use std::collections::{BTreeMap, HashMap, HashSet};

use anyhow::{Result, bail};
use kube::Client;
use kube::api::DynamicObject;
use serde::{Deserialize, Serialize};

use crate::kube::resource::ResourceId;
use crate::teardown::journal::{AuditContext, ResidualStatus, RunJournal};
use crate::teardown::plan::{OperatorGenerationIdentity, OperatorIdentitySnapshot};
use crate::teardown::planner::Action;

// ──────────────────────────────────────────────────────────────
//  Operator generation check
// ──────────────────────────────────────────────────────────────

#[derive(Clone, Debug)]
pub enum OperatorGenerationState {
    Absent,
    SameGeneration,
    Reappeared,
    Unknown(String),
}

/// LIST through planner (if provided) or raw kube API.
/// Used by check_operator_generation to route all LISTs through the shared planner.
async fn gen_list(
    client: &Client,
    group: &str,
    version: &str,
    plural: &str,
    namespace: Option<&str>,
    planner: &crate::kube::scanner::SharedPlanner,
) -> std::result::Result<Vec<DynamicObject>, String> {
    match planner
        .list_all(
            client,
            group,
            version,
            plural,
            namespace,
            crate::kube::resource::QueryRequirement::Required,
        )
        .await
    {
        Ok(items) => Ok((*items).clone()),
        Err(w) => Err(format!("{:?}", w)),
    }
}

/// GET through planner (if provided) or raw kube API.
/// Returns Ok(Some(obj)) if found, Ok(None) if 404, Err on other failures.
async fn gen_get(
    client: &Client,
    group: &str,
    version: &str,
    plural: &str,
    namespace: Option<&str>,
    name: &str,
    planner: &crate::kube::scanner::SharedPlanner,
) -> std::result::Result<Option<DynamicObject>, String> {
    match planner
        .get(
            client,
            group,
            version,
            plural,
            namespace,
            name,
            crate::kube::resource::QueryRequirement::Required,
        )
        .await
    {
        Ok(obj) => Ok(Some(obj)),
        Err(crate::kube::resource::ScanWarning::NotFound { .. }) => {
            // GET 404: verify endpoint exists via LIST to distinguish
            // resource absence from endpoint absence (e.g. CRD removed).
            match planner
                .list_all(
                    client,
                    group,
                    version,
                    plural,
                    namespace,
                    crate::kube::resource::QueryRequirement::Required,
                )
                .await
            {
                Ok(_) => Ok(None),
                Err(w) => Err(format!("GET 404 but endpoint verification failed: {:?}", w)),
            }
        }
        Err(w) => Err(format!("{:?}", w)),
    }
}

pub async fn check_operator_generation(
    client: &Client,
    snapshot: &OperatorIdentitySnapshot,
    csv_baseline: &Option<Vec<crate::teardown::journal::CsvBaselineEntry>>,
    planner: &crate::kube::scanner::SharedPlanner,
) -> OperatorGenerationState {
    let (package_name, install_namespace) = match &snapshot.generation_identity {
        OperatorGenerationIdentity::Unverifiable { reason } => {
            return OperatorGenerationState::Unknown(format!(
                "generation identity unverifiable: {}",
                reason
            ));
        }
        OperatorGenerationIdentity::OlmPackage {
            package_name,
            install_namespace,
        } => (package_name.clone(), install_namespace.clone()),
    };

    // Step 1: LIST Subscriptions in install namespace, find spec.name == package_name
    let sub_list = match gen_list(
        client,
        "operators.coreos.com",
        "v1alpha1",
        "subscriptions",
        Some(&install_namespace),
        planner,
    )
    .await
    {
        Ok(items) => items,
        Err(e) => {
            return OperatorGenerationState::Unknown(format!(
                "failed to LIST Subscriptions in {}: {}",
                install_namespace, e
            ));
        }
    };

    // Check for semantic drift: saved-UID subscription with changed spec.name
    for saved_sub in &snapshot.subscriptions {
        if let Some(live_sub) = sub_list
            .iter()
            .find(|s| s.metadata.uid.as_deref().unwrap_or("") == saved_sub.uid)
        {
            let live_spec_name = live_sub
                .data
                .get("spec")
                .and_then(|s| s.get("name"))
                .and_then(|n| n.as_str())
                .unwrap_or("");
            if live_spec_name != package_name.as_str() {
                return OperatorGenerationState::Unknown(format!(
                    "saved Subscription UID {} still exists but spec.name changed \
                     from '{}' to '{}' — semantic identity drift",
                    saved_sub.uid, package_name, live_spec_name
                ));
            }
        }
    }

    for sub in &sub_list {
        let spec_name = sub
            .data
            .get("spec")
            .and_then(|s| s.get("name"))
            .and_then(|n| n.as_str());

        if spec_name == Some(package_name.as_str()) {
            let live_uid = sub.metadata.uid.as_deref().unwrap_or("");
            let saved_matches = snapshot.subscriptions.iter().any(|s| s.uid == live_uid);

            return if saved_matches {
                OperatorGenerationState::SameGeneration
            } else {
                OperatorGenerationState::Reappeared
            };
        }
    }

    // Step 2: No matching subscription — check CSV
    match gen_get(
        client,
        "operators.coreos.com",
        "v1alpha1",
        "clusterserviceversions",
        Some(&install_namespace),
        &snapshot.csv_name,
        planner,
    )
    .await
    {
        Ok(Some(csv_obj)) => {
            let live_uid = csv_obj.metadata.uid.as_deref().unwrap_or("");
            return if snapshot.csv.uid == live_uid {
                OperatorGenerationState::SameGeneration
            } else {
                OperatorGenerationState::Reappeared
            };
        }
        Ok(None) => {
            // CSV genuinely gone — continue to deployment check
        }
        Err(e) => {
            return OperatorGenerationState::Unknown(format!(
                "failed to check CSV {}: {}",
                snapshot.csv_name, e
            ));
        }
    }

    // Step 3: Check controller deployments
    for saved_dep in &snapshot.controller_deployments {
        match gen_get(
            client,
            "apps",
            "v1",
            "deployments",
            Some(&install_namespace),
            &saved_dep.resource.name,
            planner,
        )
        .await
        {
            Ok(Some(dep_obj)) => {
                let live_uid = dep_obj.metadata.uid.as_deref().unwrap_or("");
                return if saved_dep.uid == live_uid {
                    OperatorGenerationState::SameGeneration
                } else {
                    OperatorGenerationState::Reappeared
                };
            }
            Ok(None) => {
                // Deployment genuinely gone — continue
            }
            Err(e) => {
                return OperatorGenerationState::Unknown(format!(
                    "failed to check Deployment {}: {}",
                    saved_dep.resource.name, e
                ));
            }
        }
    }

    // Step 4: All saved identities are gone. Check if any new CSVs appeared
    // since plan time by comparing against the pre-execution CSV baseline.
    // Also check if any surviving baseline CSVs cannot be attributed to a
    // different package — they could be the same package under a different name.
    match csv_baseline {
        None => {
            // No baseline captured — cannot safely verify absence
            return OperatorGenerationState::Unknown(
                "No CSV baseline captured at plan time; cannot verify \
                 that no new operator generation has been installed"
                    .to_string(),
            );
        }
        Some(baseline) => {
            // Build map: csv_name → set of package names from live Subscriptions.
            // Multiple Subs can point to the same CSV with different packages.
            let mut sub_csv_to_pkgs: HashMap<String, HashSet<String>> = HashMap::new();
            for sub in &sub_list {
                let csv = sub.data.get("status").and_then(|s| {
                    s.get("installedCSV")
                        .and_then(|v| v.as_str())
                        .filter(|s| !s.is_empty())
                        .or_else(|| {
                            s.get("currentCSV")
                                .and_then(|v| v.as_str())
                                .filter(|s| !s.is_empty())
                        })
                });
                let pkg = sub
                    .data
                    .get("spec")
                    .and_then(|s| s.get("name"))
                    .and_then(|n| n.as_str());
                if let (Some(csv), Some(pkg)) = (csv, pkg) {
                    sub_csv_to_pkgs
                        .entry(csv.to_string())
                        .or_default()
                        .insert(pkg.to_string());
                }
            }

            match gen_list(
                client,
                "operators.coreos.com",
                "v1alpha1",
                "clusterserviceversions",
                Some(&install_namespace),
                planner,
            )
            .await
            {
                Ok(csv_list_items) => {
                    let csv_list_items_ref = &csv_list_items;
                    // Pass 1: Check for new CSVs not in baseline
                    for csv_obj in csv_list_items_ref {
                        let name = csv_obj.metadata.name.as_deref().unwrap_or("");
                        let uid = csv_obj.metadata.uid.as_deref().unwrap_or("");

                        // Missing identity on a live CSV → cannot verify
                        if name.is_empty() || uid.is_empty() {
                            return OperatorGenerationState::Unknown(format!(
                                "CSV in {} has missing name or UID — cannot verify generation",
                                install_namespace
                            ));
                        }

                        // Check if this CSV was in baseline (same name AND same UID)
                        let in_baseline = baseline.iter().any(|b| b.name == name && b.uid == uid);

                        if !in_baseline {
                            // New CSV or recreated CSV not in baseline
                            return OperatorGenerationState::Unknown(format!(
                                "CSV '{}' (uid: {}) in {} was not present at plan time — \
                                 possible new operator generation",
                                name, uid, install_namespace
                            ));
                        }
                    }

                    // Pass 2: Check surviving baseline CSVs (other than our saved CSV).
                    // If any CSV remains that cannot be attributed to a different package,
                    // it could be a same-package generation with a different CSV name.
                    // Attribution uses both Subscription status→CSV mapping AND CSV labels
                    // (operators.coreos.com/<package>.<namespace>).
                    for csv_obj in csv_list_items_ref {
                        let name = csv_obj.metadata.name.as_deref().unwrap_or("");
                        let uid = csv_obj.metadata.uid.as_deref().unwrap_or("");

                        // Skip our own saved CSV
                        if name == snapshot.csv_name {
                            continue;
                        }

                        // Collect all package evidence from labels + annotations
                        let csv_ns = csv_obj
                            .metadata
                            .namespace
                            .as_deref()
                            .unwrap_or(&install_namespace);

                        let mut evidence_packages: HashSet<String> = HashSet::new();

                        // From Subscription status (all packages, not just last)
                        if let Some(pkgs) = sub_csv_to_pkgs.get(name) {
                            evidence_packages.extend(pkgs.iter().cloned());
                        }

                        // From CSV labels (operators.coreos.com/<package>.<namespace>)
                        if let Some(labels) = &csv_obj.metadata.labels {
                            let suffix = format!(".{}", csv_ns);
                            for key in labels.keys() {
                                if let Some(rest) = key.strip_prefix("operators.coreos.com/")
                                    && let Some(pkg) = rest.strip_suffix(&suffix)
                                    && !pkg.is_empty()
                                {
                                    evidence_packages.insert(pkg.to_string());
                                }
                            }
                        }

                        // From annotations (olm.package in operatorframework.io/properties)
                        for pkg in csv_packages_from_annotations(csv_obj) {
                            evidence_packages.insert(pkg);
                        }

                        if !is_exclusively_other_package(&evidence_packages, &package_name) {
                            return OperatorGenerationState::Unknown(format!(
                                "CSV '{}' (uid: {}) in {} survived teardown and cannot be \
                                 attributed to a different package — possible same-package \
                                 generation",
                                name, uid, install_namespace
                            ));
                        }
                    }
                }
                Err(e) => {
                    return OperatorGenerationState::Unknown(format!(
                        "failed to LIST CSVs in {} for baseline comparison: {}",
                        install_namespace, e
                    ));
                }
            }
        }
    }

    // All checks succeeded: saved identities gone, no new/unattributed CSVs
    OperatorGenerationState::Absent
}

/// Check if a CSV's OLM labels attribute it to a package other than `our_package`.
/// OLM copies carry labels like `operators.coreos.com/<package>.<namespace>`.
/// Returns true if the CSV is conclusively attributed to a DIFFERENT package.
/// Returns true only if the CSV is EXCLUSIVELY attributable to a different package.
/// Conflicting labels (both our package and another) → ambiguous → false.
/// Determine if evidence_packages exclusively points to a single non-target package.
/// Returns true only when exactly one package is present and it's not the target.
/// Empty, target-containing, or multi-package evidence → false (Unknown).
pub fn is_exclusively_other_package(
    evidence_packages: &HashSet<String>,
    target_package: &str,
) -> bool {
    if evidence_packages.is_empty() {
        return false;
    }
    let has_target = evidence_packages.contains(target_package);
    let other_count = evidence_packages
        .iter()
        .filter(|p| p.as_str() != target_package)
        .count();
    !has_target && other_count == 1
}

#[allow(dead_code)]
fn csv_label_attributes_to_other_package(
    labels: &std::collections::BTreeMap<String, String>,
    csv_namespace: &str,
    our_package: &str,
) -> bool {
    let suffix = format!(".{}", csv_namespace);
    let mut has_our_package = false;
    let mut has_other_package = false;

    for key in labels.keys() {
        if let Some(rest) = key.strip_prefix("operators.coreos.com/")
            && let Some(pkg) = rest.strip_suffix(&suffix)
            && !pkg.is_empty()
        {
            if pkg == our_package {
                has_our_package = true;
            } else {
                has_other_package = true;
            }
        }
    }

    // Only attributable to other if exclusively other-package labels.
    // Conflicting evidence → not safe to exclude → returns false → triggers Unknown.
    has_other_package && !has_our_package
}

/// Extract package name from CSV annotations (olm.package in operatorframework.io/properties).
/// Used for CSV copies that may lack operators.coreos.com/* labels but have annotation evidence.
/// Extract ALL package names from olm.package annotations.
/// Returns all unique package names found (not just the first).
fn csv_packages_from_annotations(csv: &DynamicObject) -> Vec<String> {
    let mut packages = Vec::new();
    let annotations = match csv.metadata.annotations.as_ref() {
        Some(a) => a,
        None => return packages,
    };

    if let Some(props_str) = annotations.get("operatorframework.io/properties") {
        // Real OLM format can be either:
        // - A JSON array: [{"type":"olm.package","value":...}, ...]
        // - A JSON object: {"properties":[{"type":"olm.package","value":...}, ...]}
        let props: Vec<serde_json::Value> =
            if let Ok(arr) = serde_json::from_str::<Vec<serde_json::Value>>(props_str) {
                arr
            } else if let Ok(obj) = serde_json::from_str::<serde_json::Value>(props_str) {
                obj.get("properties")
                    .and_then(|p| p.as_array())
                    .cloned()
                    .unwrap_or_default()
            } else {
                Vec::new()
            };

        for prop in &props {
            if prop.get("type").and_then(|t| t.as_str()) == Some("olm.package")
                && let Some(value) = prop.get("value")
            {
                let pkg_value = if let Some(s) = value.as_str() {
                    serde_json::from_str::<serde_json::Value>(s).ok()
                } else {
                    Some(value.clone())
                };
                if let Some(pkg_info) = pkg_value
                    && let Some(name) = pkg_info.get("packageName").and_then(|n| n.as_str())
                    && !packages.contains(&name.to_string())
                {
                    packages.push(name.to_string());
                }
            }
        }
    }

    packages
}

// ──────────────────────────────────────────────────────────────
//  Residual audit types
// ──────────────────────────────────────────────────────────────

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ResidualAudit {
    pub planned_delete_still_present: Vec<ResidualItem>,
    pub planned_expect_still_present: Vec<ResidualItem>,
    pub expected_preserved: Vec<PreservedItem>,
    pub likely_operator_residual: Vec<AttributedResidual>,
    pub unattributed: Vec<AttributedResidual>,
    pub coverage: AuditCoverage,
    pub scan_errors: Vec<AuditScanError>,
    #[serde(default)]
    pub target_operators_absent: bool,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub residual_workloads: Vec<ResidualWorkload>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub incomplete_scopes: Vec<IncompleteScopeEntry>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct ResidualWorkload {
    pub resource: ResourceId,
    pub uid: Option<String>,
    pub owner_chain: Vec<OwnerChainEntry>,
    pub classification: ResidualClassification,
    pub evidence: ResidualEvidence,
    pub scope_provenance: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct OwnerChainEntry {
    pub group: String,
    pub version: String,
    pub kind: String,
    pub name: String,
    pub uid: String,
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum ResidualClassification {
    Attributed,
    Unattributed,
    Preserved,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct IncompleteScopeEntry {
    pub namespace: String,
    pub resource_type: String,
    pub error: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ResidualItem {
    pub resource: ResourceId,
    pub planned_action: String,
    #[serde(default)]
    pub live_uid: Option<String>,
    #[serde(default = "RecreationState::default_unknown")]
    pub recreation: RecreationState,
}

/// Recreation state cannot default to SameResource (false safety).
/// Default is Unknown — which triggers AuditIncomplete, blocking cleanup.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub enum RecreationState {
    SameResource,
    Recreated,
    Unknown,
}

impl RecreationState {
    fn default_unknown() -> Self {
        RecreationState::Unknown
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PreservedItem {
    pub resource: ResourceId,
    pub reason: String,
    pub confirmed_descendants: usize,
    pub associated_active_workloads: usize,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AttributedResidual {
    pub resource: ResourceId,
    pub evidence: ResidualEvidence,
    pub confidence: ResidualConfidence,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResidualEvidence {
    /// Added in schema v3. Defaults to false for v2 journals so that
    /// deserialization succeeds before migration discards the old audit.
    #[serde(default)]
    pub owner_ref_match: bool,
    pub matching_labels: Vec<(String, String)>,
    pub matching_managers: Vec<String>,
    pub namespace_affinity: bool,
    pub service_account_match: bool,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub enum ResidualConfidence {
    High,
    Medium,
    Low,
    None,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AuditCoverage {
    pub requested_probes: usize,
    pub succeeded_probes: usize,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct AuditScanError {
    pub resource_type: String,
    pub namespace: String,
    pub error: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub missing_owner_ref: Option<Box<ResourceId>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dependent_uid: Option<String>,
    #[serde(default)]
    pub dependent_is_terminating: bool,
    #[serde(default)]
    pub dependent_has_target_evidence: bool,
}

// ──────────────────────────────────────────────────────────────
//  MVP scan targets
// ──────────────────────────────────────────────────────────────

struct ScanTarget {
    group: &'static str,
    version: &'static str,
    kind: &'static str,
    plural: &'static str,
}

const WORKLOAD_TARGETS: &[ScanTarget] = &[
    ScanTarget {
        group: "apps",
        version: "v1",
        kind: "Deployment",
        plural: "deployments",
    },
    ScanTarget {
        group: "apps",
        version: "v1",
        kind: "StatefulSet",
        plural: "statefulsets",
    },
    ScanTarget {
        group: "apps",
        version: "v1",
        kind: "DaemonSet",
        plural: "daemonsets",
    },
    ScanTarget {
        group: "batch",
        version: "v1",
        kind: "Job",
        plural: "jobs",
    },
    ScanTarget {
        group: "batch",
        version: "v1",
        kind: "CronJob",
        plural: "cronjobs",
    },
];

const RELATED_TARGETS: &[ScanTarget] = &[ScanTarget {
    group: "",
    version: "v1",
    kind: "Service",
    plural: "services",
}];

const POD_NORMALIZATION_TARGETS: &[ScanTarget] = &[
    ScanTarget {
        group: "",
        version: "v1",
        kind: "Pod",
        plural: "pods",
    },
    ScanTarget {
        group: "apps",
        version: "v1",
        kind: "ReplicaSet",
        plural: "replicasets",
    },
];

const OPENSHIFT_TARGETS: &[ScanTarget] = &[
    ScanTarget {
        group: "route.openshift.io",
        version: "v1",
        kind: "Route",
        plural: "routes",
    },
    ScanTarget {
        group: "image.openshift.io",
        version: "v1",
        kind: "ImageStream",
        plural: "imagestreams",
    },
];

const OLM_TARGETS: &[ScanTarget] = &[
    ScanTarget {
        group: "operators.coreos.com",
        version: "v1alpha1",
        kind: "Subscription",
        plural: "subscriptions",
    },
    ScanTarget {
        group: "operators.coreos.com",
        version: "v1alpha1",
        kind: "ClusterServiceVersion",
        plural: "clusterserviceversions",
    },
];

// ──────────────────────────────────────────────────────────────
//  Live residual audit
// ──────────────────────────────────────────────────────────────

/// Result of one complete audit observation cycle.
pub struct AuditObservation {
    pub generation: OperatorGenerationState,
    pub audit: Option<ResidualAudit>,
}

/// Public entry point: one fresh planner for generation check + residual audit.
/// Creates a new planner per call — never reuses pre-mutation cache.
pub async fn observe_residual_state(
    client: &Client,
    journal: &RunJournal,
) -> Result<AuditObservation> {
    use crate::kube::planner::QueryPlanner;
    use crate::kube::scanner::DEFAULT_API_CONCURRENCY;
    let planner = QueryPlanner::new(Some(std::sync::Arc::new(tokio::sync::Semaphore::new(
        DEFAULT_API_CONCURRENCY,
    ))));
    let generation = check_operator_generation(
        client,
        &journal.operator,
        &journal.audit_context.csv_baseline,
        &planner,
    )
    .await;
    let audit = if matches!(generation, OperatorGenerationState::Absent) {
        Some(run_residual_audit(client, journal, &generation, &planner).await?)
    } else {
        None
    };
    Ok(AuditObservation { generation, audit })
}

/// Result of a bounded settled observation.
pub struct SettledAudit {
    pub observation: AuditObservation,
    pub attempts: u32,
    pub duration_ms: u64,
    #[allow(dead_code)]
    pub last_transient_blockers: Vec<ResourceId>,
}

/// Classify a scan error as transient (post-delete pod termination) or persistent.
/// Uses typed `missing_owner_ref` identity when available, matching by exact
/// group/version/kind/namespace/name/UID against `execution.deleted`.
/// Fails closed: missing or empty UID on either side is never transient.
fn is_transient_scan_error(error: &AuditScanError, deleted_resources: &[ResourceId]) -> bool {
    let missing = match &error.missing_owner_ref {
        Some(id) => id,
        None => return false,
    };
    let Some(missing_uid) = missing.uid.as_deref().filter(|u| !u.is_empty()) else {
        return false;
    };

    // Path 1: Exact deleted-parent match (owner was explicitly deleted by the plan)
    let exact_match = deleted_resources.iter().any(|d| {
        let Some(del_uid) = d.uid.as_deref().filter(|u| !u.is_empty()) else {
            return false;
        };
        d.kind == missing.kind
            && d.name == missing.name
            && d.namespace == missing.namespace
            && d.group == missing.group
            && d.version == missing.version
            && del_uid == missing_uid
    });
    if exact_match {
        return true;
    }

    // Path 2: Orphaned dependent with target evidence — retry eligible
    // Owner is a supported workload type (absent from native scan, not in plan).
    // The dependent Pod has a UID and positive target evidence. The settle loop
    // will re-observe; if the Pod persists past deadline, result is AuditIncomplete.
    let is_supported_owner = matches!(
        (
            missing.group.as_str(),
            missing.version.as_str(),
            missing.kind.as_str()
        ),
        (
            "apps",
            "v1",
            "DaemonSet" | "Deployment" | "StatefulSet" | "ReplicaSet"
        ) | ("batch", "v1", "Job")
    );
    is_supported_owner
        && error.dependent_uid.as_ref().is_some_and(|u| !u.is_empty())
        && error.dependent_has_target_evidence
}

/// Core settling loop: retry transient post-delete blockers, fail immediately on persistent errors.
/// `observe_fn` is called each iteration to produce an observation.
async fn settle_loop<F, Fut>(
    observe_fn: F,
    deleted_resources: &[ResourceId],
    deadline: std::time::Duration,
    cancel: &tokio_util::sync::CancellationToken,
) -> Result<SettledAudit>
where
    F: Fn() -> Fut,
    Fut: std::future::Future<Output = Result<AuditObservation>>,
{
    let start = tokio::time::Instant::now();
    let mut attempts = 0u32;
    let mut last_transient_blockers = Vec::new();

    loop {
        if cancel.is_cancelled() {
            let obs = AuditObservation {
                generation: OperatorGenerationState::Unknown("cancelled".to_string()),
                audit: None,
            };
            return Ok(SettledAudit {
                observation: obs,
                attempts,
                duration_ms: start.elapsed().as_millis() as u64,
                last_transient_blockers,
            });
        }

        attempts += 1;
        let obs = observe_fn().await?;

        if !matches!(obs.generation, OperatorGenerationState::Absent) {
            return Ok(SettledAudit {
                observation: obs,
                attempts,
                duration_ms: start.elapsed().as_millis() as u64,
                last_transient_blockers,
            });
        }

        if let Some(ref audit) = obs.audit {
            if audit.scan_errors.is_empty() {
                return Ok(SettledAudit {
                    observation: obs,
                    attempts,
                    duration_ms: start.elapsed().as_millis() as u64,
                    last_transient_blockers: vec![],
                });
            }

            let mut all_transient = true;
            let mut transient_ids = Vec::new();
            for err in &audit.scan_errors {
                if is_transient_scan_error(err, deleted_resources) {
                    if let Some(ref id) = err.missing_owner_ref {
                        transient_ids.push((**id).clone());
                    }
                } else {
                    all_transient = false;
                    break;
                }
            }

            if !all_transient {
                return Ok(SettledAudit {
                    observation: obs,
                    attempts,
                    duration_ms: start.elapsed().as_millis() as u64,
                    last_transient_blockers: transient_ids,
                });
            }

            last_transient_blockers = transient_ids;
        } else {
            return Ok(SettledAudit {
                observation: obs,
                attempts,
                duration_ms: start.elapsed().as_millis() as u64,
                last_transient_blockers,
            });
        }

        if start.elapsed() >= deadline {
            return Ok(SettledAudit {
                observation: obs,
                attempts,
                duration_ms: start.elapsed().as_millis() as u64,
                last_transient_blockers,
            });
        }

        tokio::select! {
            _ = tokio::time::sleep(std::time::Duration::from_secs(3)) => {},
            _ = cancel.cancelled() => {
                return Ok(SettledAudit {
                    observation: obs,
                    attempts,
                    duration_ms: start.elapsed().as_millis() as u64,
                    last_transient_blockers,
                });
            }
        }
    }
}

/// Observe residual state with bounded retry for transient post-delete blockers.
/// Re-runs a fresh observation every ~3s up to `deadline`. Transient blockers
/// (just-deleted controller Pods not yet terminated) are retried; persistent
/// errors (Forbidden, 500, identity ambiguity) fail immediately.
pub async fn observe_residual_state_until_settled(
    client: &Client,
    journal: &RunJournal,
    deadline: std::time::Duration,
    cancel: &tokio_util::sync::CancellationToken,
) -> Result<SettledAudit> {
    let deleted_resources = &journal.execution.deleted;
    settle_loop(
        || observe_residual_state(client, journal),
        deleted_resources,
        deadline,
        cancel,
    )
    .await
}

/// Fresh generation-only check with its own planner.
/// Use after mutations/permits where only generation state is needed.
pub async fn check_operator_generation_fresh(
    client: &Client,
    snapshot: &OperatorIdentitySnapshot,
    csv_baseline: &Option<Vec<crate::teardown::journal::CsvBaselineEntry>>,
) -> OperatorGenerationState {
    use crate::kube::planner::QueryPlanner;
    use crate::kube::scanner::DEFAULT_API_CONCURRENCY;
    let planner = QueryPlanner::new(Some(std::sync::Arc::new(tokio::sync::Semaphore::new(
        DEFAULT_API_CONCURRENCY,
    ))));
    check_operator_generation(client, snapshot, csv_baseline, &planner).await
}

/// Single-shot observation: one fresh planner, one observation, no settling.
/// Used by teardown journal, pre-mutation checks, and read-only audit paths.
pub async fn run_observed_audit(client: &Client, journal: &RunJournal) -> Result<ResidualAudit> {
    let obs = observe_residual_state(client, journal).await?;
    match obs.audit {
        Some(audit) => Ok(audit),
        None => bail!(
            "Operator generation is {:?} — residual audit not available",
            obs.generation
        ),
    }
}

/// Post-mutation audit with bounded settling. Used ONLY after apply/cleanup mutations.
/// Retries transient post-delete blockers (just-deleted controller Pods not yet terminated).
pub async fn run_post_mutation_audit_until_settled(
    client: &Client,
    journal: &RunJournal,
    deadline: std::time::Duration,
    cancel: &tokio_util::sync::CancellationToken,
) -> Result<ResidualAudit> {
    let settled = observe_residual_state_until_settled(client, journal, deadline, cancel).await?;
    if settled.attempts > 1 {
        eprintln!(
            "  Residual audit settled after {} attempt(s) ({:.1}s)",
            settled.attempts,
            settled.duration_ms as f64 / 1000.0
        );
    }
    match settled.observation.audit {
        Some(audit) => Ok(audit),
        None => bail!(
            "Operator generation is {:?} — residual audit not available",
            settled.observation.generation
        ),
    }
}

/// Convenience wrapper for post-mutation audit with default 120s deadline.
/// Used by apply/cleanup paths that need settling for transient post-delete blockers.
pub async fn run_post_mutation_audit(
    client: &Client,
    journal: &RunJournal,
) -> Result<ResidualAudit> {
    let cancel = tokio_util::sync::CancellationToken::new();
    run_post_mutation_audit_until_settled(
        client,
        journal,
        std::time::Duration::from_secs(120),
        &cancel,
    )
    .await
}

/// WorkloadKey: full physical identity including UID.
type WorkloadKey = (String, String, String, String, String, String);

pub async fn run_residual_audit(
    client: &Client,
    journal: &RunJournal,
    generation_state: &OperatorGenerationState,
    planner: &crate::kube::scanner::SharedPlanner,
) -> Result<ResidualAudit> {
    let ctx = &journal.audit_context;
    let plan = &journal.plan_snapshot;

    let mut audit = ResidualAudit {
        planned_delete_still_present: Vec::new(),
        planned_expect_still_present: Vec::new(),
        expected_preserved: Vec::new(),
        likely_operator_residual: Vec::new(),
        unattributed: Vec::new(),
        coverage: AuditCoverage {
            requested_probes: 0,
            succeeded_probes: 0,
        },
        scan_errors: Vec::new(),
        target_operators_absent: matches!(generation_state, OperatorGenerationState::Absent),
        residual_workloads: Vec::new(),
        incomplete_scopes: Vec::new(),
    };

    // Derive effective namespaces from namespace_scope (always present in v12+).
    let effective_namespaces: HashSet<String> = ctx
        .namespace_scope
        .as_ref()
        .map(|scope| scope.iter().map(|e| e.namespace.clone()).collect())
        .unwrap_or_default();

    // Collect DELETE/EXPECT/WAIT plan resource identities for exclusion during namespace scan.
    // KEEP/REVIEW resources are NOT excluded — they appear as Preserved residual workloads.
    let mut plan_resources: HashSet<(String, String, Option<String>, String)> = HashSet::new();
    for phase in &plan.phases {
        for action in &phase.actions {
            match action {
                Action::Delete { resource, .. }
                | Action::ExpectGone { resource, .. }
                | Action::WaitGone { resource } => {
                    plan_resources.insert((
                        resource.group.clone(),
                        resource.kind.clone(),
                        resource.namespace.clone(),
                        resource.name.clone(),
                    ));
                }
                Action::Keep { .. } | Action::Review { .. } => {
                    // Not excluded — classified as Preserved during live scan
                }
            }
        }
    }

    // Collect target operator identity UIDs for ownerRef→HIGH attribution.
    // Includes operator control-plane UIDs AND plan DELETE/EXPECT resource UIDs
    // so that descendants of approved root CRs are classified HIGH, not UNATTRIBUTED.
    // Note: attribution != DELETE authority — this is for classification only.
    let mut target_uids: HashSet<String> = HashSet::new();
    target_uids.insert(journal.operator.csv.uid.clone());
    for sub in &journal.operator.subscriptions {
        target_uids.insert(sub.uid.clone());
    }
    for dep in &journal.operator.controller_deployments {
        target_uids.insert(dep.uid.clone());
    }
    for sa in &journal.operator.service_accounts {
        target_uids.insert(sa.uid.clone());
    }
    for phase in &plan.phases {
        for action in &phase.actions {
            match action {
                Action::Delete { resource, .. } | Action::ExpectGone { resource, .. } => {
                    if let Some(uid) = &resource.uid {
                        target_uids.insert(uid.clone());
                    }
                }
                _ => {}
            }
        }
    }

    // Phase A: Check planned DELETE/EXPECT resources (exact GET probes)
    for phase in &plan.phases {
        for action in &phase.actions {
            match action {
                Action::Delete { resource, .. } => {
                    audit.coverage.requested_probes += 1;
                    match probe_resource(client, resource, &ctx.known_gvrs, planner).await {
                        ProbeResult::Present { uid } => {
                            audit.coverage.succeeded_probes += 1;
                            let recreation = check_recreation(resource, &uid);
                            audit.planned_delete_still_present.push(ResidualItem {
                                resource: resource.clone(),
                                planned_action: "DELETE".to_string(),
                                live_uid: uid,
                                recreation,
                            });
                        }
                        ProbeResult::Gone => {
                            audit.coverage.succeeded_probes += 1;
                        }
                        ProbeResult::Error(e) => {
                            audit.scan_errors.push(AuditScanError {
                                resource_type: resource.kind.clone(),
                                namespace: resource
                                    .namespace
                                    .clone()
                                    .unwrap_or_else(|| "cluster".to_string()),
                                error: e,
                                missing_owner_ref: None,
                                ..Default::default()
                            });
                        }
                    }
                }
                Action::ExpectGone { resource, .. } => {
                    audit.coverage.requested_probes += 1;
                    match probe_resource(client, resource, &ctx.known_gvrs, planner).await {
                        ProbeResult::Present { uid } => {
                            audit.coverage.succeeded_probes += 1;
                            let recreation = check_recreation(resource, &uid);
                            audit.planned_expect_still_present.push(ResidualItem {
                                resource: resource.clone(),
                                planned_action: "EXPECT-GONE".to_string(),
                                live_uid: uid,
                                recreation,
                            });
                        }
                        ProbeResult::Gone => {
                            audit.coverage.succeeded_probes += 1;
                        }
                        ProbeResult::Error(e) => {
                            audit.scan_errors.push(AuditScanError {
                                resource_type: resource.kind.clone(),
                                namespace: resource
                                    .namespace
                                    .clone()
                                    .unwrap_or_else(|| "cluster".to_string()),
                                error: e,
                                missing_owner_ref: None,
                                ..Default::default()
                            });
                        }
                    }
                }
                Action::Keep {
                    resource, reason, ..
                } => {
                    audit.expected_preserved.push(PreservedItem {
                        resource: resource.clone(),
                        reason: reason.clone(),
                        confirmed_descendants: 0,
                        associated_active_workloads: 0,
                    });
                }
                Action::Review {
                    resource,
                    reason,
                    metadata,
                    ..
                } => {
                    // RelatedLabelOnly items are probed in Phase A2 and
                    // may appear as unattributed residuals — skip here
                    let is_related_label_only = metadata.as_ref().is_some_and(|m| {
                        matches!(
                            m.discovery_source,
                            Some(crate::teardown::plan::DiscoverySourceSer::RelatedLabelOnly)
                        )
                    });
                    if is_related_label_only {
                        continue;
                    }
                    audit.expected_preserved.push(PreservedItem {
                        resource: resource.clone(),
                        reason: reason.clone(),
                        confirmed_descendants: 0,
                        associated_active_workloads: 0,
                    });
                }
                _ => {}
            }
        }
    }

    // Phase A2: Probe RelatedLabelOnly REVIEW roots — these are non-blocking
    // but need live state for Residual Cleanup. If present → unattributed residual.
    // If 404 + LIST OK → gone (no residual entry). If error → AuditIncomplete.
    for phase in &plan.phases {
        for action in &phase.actions {
            if let Action::Review {
                resource, metadata, ..
            } = action
            {
                let is_related_label_only = metadata.as_ref().is_some_and(|m| {
                    matches!(
                        m.discovery_source,
                        Some(crate::teardown::plan::DiscoverySourceSer::RelatedLabelOnly)
                    )
                });
                if !is_related_label_only {
                    continue;
                }
                audit.coverage.requested_probes += 1;
                match probe_resource(client, resource, &ctx.known_gvrs, planner).await {
                    ProbeResult::Present { uid } => {
                        audit.coverage.succeeded_probes += 1;
                        match uid {
                            Some(live_uid) => {
                                let mut live_resource = resource.clone();
                                live_resource.uid = Some(live_uid);
                                audit.unattributed.push(AttributedResidual {
                                    resource: live_resource,
                                    evidence: ResidualEvidence {
                                        owner_ref_match: false,
                                        matching_labels: vec![],
                                        matching_managers: vec![],
                                        namespace_affinity: false,
                                        service_account_match: false,
                                    },
                                    confidence: ResidualConfidence::None,
                                });
                            }
                            None => {
                                audit.scan_errors.push(AuditScanError {
                                    resource_type: format!("{}/{}", resource.kind, resource.name),
                                    namespace: resource
                                        .namespace
                                        .clone()
                                        .unwrap_or_else(|| "cluster".to_string()),
                                    error: "RelatedLabelOnly resource present but has no UID"
                                        .to_string(),
                                    missing_owner_ref: None,
                                    ..Default::default()
                                });
                            }
                        }
                    }
                    ProbeResult::Gone => {
                        audit.coverage.succeeded_probes += 1;
                    }
                    ProbeResult::Error(err) => {
                        audit.scan_errors.push(AuditScanError {
                            resource_type: format!("{}/{}", resource.kind, resource.name),
                            namespace: resource
                                .namespace
                                .clone()
                                .unwrap_or_else(|| "cluster".to_string()),
                            error: err,
                            missing_owner_ref: None,
                            ..Default::default()
                        });
                    }
                }
            }
        }
    }

    // Phase B: Scan workload targets (Deployment/StatefulSet/DaemonSet/Job) into canonical map.
    // Phase C: Scan related targets (Service, OLM, OpenShift) into old classification lists only.
    // Both direct LIST and Pod normalization feed into this single map.

    let mut workload_map: BTreeMap<WorkloadKey, ResidualWorkload> = BTreeMap::new();
    // Native workload DynamicObjects for Pod owner UID verification.
    let mut native_workload_objects: HashMap<(String, String, String), DynamicObject> =
        HashMap::new();

    // Build plan classification index for KEEP/REVIEW.
    // Used during live scan to classify Preserved workloads.
    let mut plan_preserved: HashMap<(String, String, String, String, String), Option<String>> =
        HashMap::new();
    for phase in &plan.phases {
        for action in &phase.actions {
            let (resource, is_preserved) = match action {
                Action::Keep { resource, .. } => (resource, true),
                Action::Review { resource, .. } => (resource, true),
                _ => continue,
            };
            if !is_preserved {
                continue;
            }
            if !matches!(
                resource.kind.as_str(),
                "Deployment" | "StatefulSet" | "DaemonSet" | "Job" | "CronJob" | "Pod"
            ) {
                continue;
            }
            let key = (
                resource.group.clone(),
                resource.version.clone(),
                resource.kind.clone(),
                resource.namespace.clone().unwrap_or_default(),
                resource.name.clone(),
            );
            plan_preserved.insert(key, resource.uid.clone());
        }
    }

    // Phase B: Scan workload targets (Deployment/StatefulSet/DaemonSet/Job) into canonical map.
    // Phase C: Scan related targets (Service, OLM, OpenShift) into old classification lists only.
    let related_targets: Vec<&ScanTarget> = RELATED_TARGETS
        .iter()
        .chain(OLM_TARGETS.iter())
        .chain(OPENSHIFT_TARGETS.iter())
        .collect();

    for ns in &effective_namespaces {
        // Workload targets → workload_map + native_workload_objects
        for target in WORKLOAD_TARGETS {
            audit.coverage.requested_probes += 1;
            match audit_list(
                client,
                target.group,
                target.version,
                target.kind,
                target.plural,
                Some(ns),
                crate::kube::resource::QueryRequirement::Required,
                planner,
            )
            .await
            {
                Ok(items) => {
                    audit.coverage.succeeded_probes += 1;
                    for obj in items {
                        let name = match obj.metadata.name.as_deref() {
                            Some(n) => n.to_string(),
                            None => {
                                audit.scan_errors.push(AuditScanError {
                                    resource_type: target.kind.to_string(),
                                    namespace: ns.clone(),
                                    error: "Object without metadata.name".to_string(),
                                    missing_owner_ref: None,
                                    ..Default::default()
                                });
                                continue;
                            }
                        };
                        let uid_str = match non_empty_uid(&obj, target.kind, &name) {
                            Ok(u) => u,
                            Err(err) => {
                                audit.scan_errors.push(AuditScanError {
                                    resource_type: target.kind.to_string(),
                                    namespace: ns.clone(),
                                    error: err,
                                    missing_owner_ref: None,
                                    ..Default::default()
                                });
                                continue;
                            }
                        };
                        let key = (
                            target.group.to_string(),
                            target.kind.to_string(),
                            Some(ns.clone()),
                            name.clone(),
                        );
                        if plan_resources.contains(&key) {
                            continue;
                        }
                        native_workload_objects.insert(
                            (ns.clone(), target.kind.to_string(), name.clone()),
                            obj.clone(),
                        );
                        let evidence = classify_evidence(&obj, ctx, &target_uids);
                        let _confidence = compute_confidence(&evidence);
                        // In broad-only namespaces, skip objects with no target evidence
                        if !has_positive_target_evidence(&evidence) {
                            continue; // No positive target evidence → scope-out
                        }
                        let pkey = (
                            target.group.to_string(),
                            target.version.to_string(),
                            target.kind.to_string(),
                            ns.clone(),
                            name.clone(),
                        );
                        let classification = if let Some(plan_uid) = plan_preserved.get(&pkey) {
                            match plan_uid {
                                Some(pu) if !pu.is_empty() && pu == &uid_str => {
                                    ResidualClassification::Preserved
                                }
                                Some(_) => {
                                    audit.scan_errors.push(AuditScanError {
                                        resource_type: target.kind.to_string(),
                                        namespace: ns.clone(),
                                        error: format!(
                                            "KEEP/REVIEW {}/{} UID changed — recreated, incomplete",
                                            target.kind, name
                                        ),
                                        missing_owner_ref: None,
                                        ..Default::default()
                                    });
                                    ResidualClassification::Unattributed
                                }
                                None => {
                                    audit.scan_errors.push(AuditScanError {
                                        resource_type: target.kind.to_string(),
                                        namespace: ns.clone(),
                                        error: format!(
                                            "KEEP/REVIEW {}/{} has no plan UID — incomplete",
                                            target.kind, name
                                        ),
                                        missing_owner_ref: None,
                                        ..Default::default()
                                    });
                                    ResidualClassification::Unattributed
                                }
                            }
                        } else {
                            // Positive target evidence confirmed by initial filter
                            ResidualClassification::Attributed
                        };
                        let scope_prov = scope_provenance_str(ctx, ns);
                        let wk: WorkloadKey = (
                            target.group.to_string(),
                            target.version.to_string(),
                            target.kind.to_string(),
                            ns.clone(),
                            name.clone(),
                            uid_str.clone(),
                        );
                        let rid = ResourceId {
                            group: target.group.to_string(),
                            version: target.version.to_string(),
                            kind: target.kind.to_string(),
                            namespace: Some(ns.clone()),
                            name,
                            uid: Some(uid_str.clone()),
                        };
                        workload_map.entry(wk).or_insert(ResidualWorkload {
                            resource: rid,
                            uid: Some(uid_str),
                            owner_chain: vec![],
                            classification,
                            evidence,
                            scope_provenance: scope_prov,
                        });
                    }
                }
                Err(e) => {
                    audit.scan_errors.push(e);
                }
            }
        }
        // Related targets → old classification lists only (not workloads)
        for target in &related_targets {
            let req = if matches!(target.group, "route.openshift.io" | "image.openshift.io") {
                crate::kube::resource::QueryRequirement::Optional
            } else {
                crate::kube::resource::QueryRequirement::Required
            };
            scan_namespace_for_target(
                client,
                target.group,
                target.version,
                target.kind,
                target.plural,
                ns,
                ctx,
                &target_uids,
                &plan_resources,
                &mut audit,
                req,
                planner,
            )
            .await;
        }
    }

    // Phase D: Owned CR API scan using owned_cr_gvrs (NOT known_gvrs which
    // includes Namespace/CRD/APIService etc. from plan KEEP actions)
    match &ctx.owned_cr_gvrs {
        None => {
            // Old journal without owned_cr_gvrs — mark incomplete if operator owns CRDs
            if !journal.operator.owned_crds.is_empty() {
                audit.scan_errors.push(AuditScanError {
                    resource_type: "(owned CR APIs)".to_string(),
                    namespace: "(all)".to_string(),
                    error: "Journal lacks owned CR GVR metadata. \
                            Residual CRs beyond plan resources are not covered."
                        .to_string(),
                    missing_owner_ref: None,
                    ..Default::default()
                });
            }
        }
        Some(gvrs) => {
            for gvr in gvrs {
                // Check if this GVR's governing CRD was approved for deletion
                // and confirmed Gone (GoneByCrdRemoval exception for --prune-crds)
                let crd_name = format!("{}.{}", gvr.plural, gvr.group);
                let crd_approved_delete = plan.phases.iter().flat_map(|p| &p.actions).any(|a| {
                    matches!(a, Action::Delete { resource, .. }
                            if resource.kind == "CustomResourceDefinition"
                                && resource.name == crd_name)
                });

                if crd_approved_delete {
                    let crd_still_present = audit.planned_delete_still_present.iter().any(|item| {
                        item.resource.kind == "CustomResourceDefinition"
                            && item.resource.name == crd_name
                    });

                    if !crd_still_present {
                        // CRD was approved for delete and appears gone in Phase A.
                        // However, we cannot prove the original CRD UID is gone
                        // or that a replacement CRD hasn't been created between
                        // Phase A and Phase D. Mark as incomplete rather than
                        // claiming probe success.
                        audit.scan_errors.push(AuditScanError {
                            resource_type: format!("{} (CRD pruned)", gvr.kind),
                            namespace: "(all)".to_string(),
                            error: format!(
                                "CRD '{}' was approved for deletion and appears gone, \
                                 but CR API probe is skipped — CRD UID verification \
                                 not yet implemented",
                                crd_name
                            ),
                            missing_owner_ref: None,
                            ..Default::default()
                        });
                        continue;
                    }
                }

                match gvr.scope {
                    crate::teardown::journal::GvrScope::Namespaced => {
                        for ns in &effective_namespaces {
                            scan_namespace_for_target(
                                client,
                                &gvr.group,
                                &gvr.version,
                                &gvr.kind,
                                &gvr.plural,
                                ns,
                                ctx,
                                &target_uids,
                                &plan_resources,
                                &mut audit,
                                crate::kube::resource::QueryRequirement::Required,
                                planner,
                            )
                            .await;
                        }
                    }
                    crate::teardown::journal::GvrScope::Cluster => {
                        audit.coverage.requested_probes += 1;
                        match audit_list(
                            client,
                            &gvr.group,
                            &gvr.version,
                            &gvr.kind,
                            &gvr.plural,
                            None,
                            crate::kube::resource::QueryRequirement::Required,
                            planner,
                        )
                        .await
                        {
                            Ok(items) => {
                                audit.coverage.succeeded_probes += 1;
                                classify_list_results(
                                    items,
                                    &gvr.kind,
                                    &gvr.group,
                                    &gvr.version,
                                    "cluster",
                                    ctx,
                                    &target_uids,
                                    &plan_resources,
                                    &mut audit,
                                );
                            }
                            Err(e) => {
                                audit.scan_errors.push(e);
                            }
                        }
                    }
                }
            }
        }
    }

    // Unresolved CRDs from plan time → cannot scan for their CR instances
    match &ctx.unresolved_crds {
        None => {
            // Old journal without unresolved_crds info
            if !journal.operator.owned_crds.is_empty() {
                audit.scan_errors.push(AuditScanError {
                    resource_type: "(owned CRD resolution)".to_string(),
                    namespace: "(all)".to_string(),
                    error: "Journal lacks CRD resolution metadata. \
                            Cannot verify owned CRD coverage completeness."
                        .to_string(),
                    missing_owner_ref: None,
                    ..Default::default()
                });
            }
        }
        Some(unresolved) => {
            for crd_name in unresolved {
                audit.scan_errors.push(AuditScanError {
                    resource_type: crd_name.clone(),
                    namespace: "(all)".to_string(),
                    error: format!(
                        "Owned CRD '{}' could not be resolved via API discovery at plan time. \
                         Residual CR instances of this type are not covered.",
                        crd_name
                    ),
                    missing_owner_ref: None,
                    ..Default::default()
                });
            }
        }
    }

    // Unresolved plan GVKs → cannot probe those plan resources
    match &ctx.unresolved_gvks {
        None => {
            // Old journal without GVK resolution metadata → AuditIncomplete
            audit.scan_errors.push(AuditScanError {
                resource_type: "(plan GVK resolution)".to_string(),
                namespace: "(all)".to_string(),
                error: "Journal lacks plan GVK resolution metadata. \
                        Cannot verify exact-GET probe coverage."
                    .to_string(),
                missing_owner_ref: None,
                ..Default::default()
            });
        }
        Some(unresolved) => {
            for (g, v, k) in unresolved {
                audit.scan_errors.push(AuditScanError {
                    resource_type: format!("{}/{}/{}", g, v, k),
                    namespace: "(all)".to_string(),
                    error: format!(
                        "Plan GVK {}/{} '{}' could not be resolved via API discovery. \
                         Exact-GET probes for this type are not possible.",
                        g, v, k
                    ),
                    missing_owner_ref: None,
                    ..Default::default()
                });
            }
        }
    }

    normalize_jobs_to_cronjobs(
        &mut workload_map,
        &native_workload_objects,
        &mut audit,
        ctx,
        &target_uids,
        &plan_preserved,
    );

    // Phase E: Pod→top-level owner normalization.
    // Scan Pods and ReplicaSets, walk ownerRef chains to top-level controllers.
    // Merge results into workload_map (upserts chain if entry exists).
    let mut pod_items: HashMap<String, Vec<DynamicObject>> = HashMap::new();
    let mut rs_items: HashMap<String, Vec<DynamicObject>> = HashMap::new();

    for ns in &effective_namespaces {
        for target in POD_NORMALIZATION_TARGETS {
            audit.coverage.requested_probes += 1;
            match audit_list(
                client,
                target.group,
                target.version,
                target.kind,
                target.plural,
                Some(ns),
                crate::kube::resource::QueryRequirement::Required,
                planner,
            )
            .await
            {
                Ok(items) => {
                    audit.coverage.succeeded_probes += 1;
                    match target.kind {
                        "Pod" => pod_items.entry(ns.clone()).or_default().extend(items),
                        "ReplicaSet" => {
                            for rs in &items {
                                if let (Some(rs_ns), Some(rs_name)) = (
                                    rs.metadata.namespace.as_deref(),
                                    rs.metadata.name.as_deref(),
                                ) {
                                    native_workload_objects.insert(
                                        (
                                            rs_ns.to_string(),
                                            "ReplicaSet".to_string(),
                                            rs_name.to_string(),
                                        ),
                                        rs.clone(),
                                    );
                                }
                            }
                            rs_items.entry(ns.clone()).or_default().extend(items);
                        }
                        _ => {}
                    }
                }
                Err(e) => {
                    audit.scan_errors.push(e);
                }
            }
        }
    }

    let rs_lookup: HashMap<(String, String), &DynamicObject> = rs_items
        .values()
        .flat_map(|items| items.iter())
        .filter_map(|rs| {
            let ns = rs.metadata.namespace.as_deref()?.to_string();
            let name = rs.metadata.name.as_deref()?.to_string();
            Some(((ns, name), rs))
        })
        .collect();

    for (ns, pods) in &pod_items {
        for pod in pods {
            let pod_name = match pod.metadata.name.as_deref() {
                Some(n) => n,
                None => continue,
            };
            let pod_key = (
                "".to_string(),
                "Pod".to_string(),
                Some(ns.clone()),
                pod_name.to_string(),
            );
            if plan_resources.contains(&pod_key) {
                continue;
            }

            let owner_refs = match &pod.metadata.owner_references {
                Some(refs) if !refs.is_empty() => refs,
                _ => {
                    // Ownerless Pod: insert as workload
                    let uid = pod.metadata.uid.clone();
                    let evidence = classify_evidence(pod, ctx, &target_uids);
                    let _confidence = compute_confidence(&evidence);
                    if !has_positive_target_evidence(&evidence) {
                        continue; // No positive target evidence → scope-out
                    }
                    let classification = ResidualClassification::Attributed;
                    let pod_uid = match non_empty_uid(pod, "Pod", pod_name) {
                        Ok(u) => u,
                        Err(err) => {
                            audit.scan_errors.push(AuditScanError {
                                resource_type: format!("Pod/{}", pod_name),
                                namespace: ns.clone(),
                                error: err,
                                missing_owner_ref: None,
                                ..Default::default()
                            });
                            continue;
                        }
                    };
                    let wk: WorkloadKey = (
                        "".to_string(),
                        "v1".to_string(),
                        "Pod".to_string(),
                        ns.clone(),
                        pod_name.to_string(),
                        pod_uid,
                    );
                    workload_map.entry(wk).or_insert(ResidualWorkload {
                        resource: ResourceId {
                            group: String::new(),
                            version: "v1".to_string(),
                            kind: "Pod".to_string(),
                            namespace: Some(ns.clone()),
                            name: pod_name.to_string(),
                            uid: uid.clone(),
                        },
                        uid,
                        owner_chain: vec![],
                        classification,
                        evidence,
                        scope_provenance: scope_provenance_str(ctx, ns),
                    });
                    continue;
                }
            };

            let controllers: Vec<_> = owner_refs
                .iter()
                .filter(|r| r.controller.unwrap_or(false))
                .collect();
            if controllers.len() > 1 {
                audit.scan_errors.push(AuditScanError {
                    resource_type: format!("Pod/{}", pod_name),
                    namespace: ns.clone(),
                    error: format!(
                        "Pod has {} controller ownerRefs — multi-owner fail closed",
                        controllers.len()
                    ),
                    missing_owner_ref: None,
                    ..Default::default()
                });
                continue;
            }

            let owner = if controllers.len() == 1 {
                controllers[0]
            } else if owner_refs.len() == 1 {
                &owner_refs[0]
            } else {
                audit.scan_errors.push(AuditScanError {
                    resource_type: format!("Pod/{}", pod_name),
                    namespace: ns.clone(),
                    error: format!(
                        "Pod has {} non-controller ownerRefs — ambiguous fail closed",
                        owner_refs.len()
                    ),
                    missing_owner_ref: None,
                    ..Default::default()
                });
                continue;
            };

            let (top_kind, top_group, top_version, top_name, top_uid, owner_chain) =
                match normalize_pod_owner(owner, ns, &rs_lookup, &native_workload_objects) {
                    OwnerNormalization::Resolved(result) => result,
                    OwnerNormalization::Foreign { owner_gvk } => {
                        let evidence = classify_evidence(pod, ctx, &target_uids);
                        let has_target = has_positive_target_evidence(&evidence);
                        let _broad = is_broad_only_namespace(ctx, ns);
                        match decide_foreign(has_target, &owner_gvk) {
                            ScopeDecision::ScopeOut => {
                                continue;
                            }
                            ScopeDecision::FailClosed(reason) => {
                                audit.scan_errors.push(AuditScanError {
                                    resource_type: format!("Pod/{}", pod_name),
                                    namespace: ns.clone(),
                                    error: reason,
                                    missing_owner_ref: None,
                                    ..Default::default()
                                });
                                continue;
                            }
                        }
                    }
                    OwnerNormalization::Incomplete {
                        reason,
                        missing_ref,
                    } => {
                        let evidence = classify_evidence(pod, ctx, &target_uids);
                        let has_evidence = has_positive_target_evidence(&evidence);
                        if !has_evidence && is_broad_only_namespace(ctx, ns) {
                            continue;
                        }
                        audit.scan_errors.push(AuditScanError {
                            resource_type: format!("Pod/{}", pod_name),
                            namespace: ns.clone(),
                            error: reason,
                            missing_owner_ref: missing_ref.map(Box::new),
                            dependent_uid: pod.metadata.uid.clone(),
                            dependent_is_terminating: pod.metadata.deletion_timestamp.is_some(),
                            dependent_has_target_evidence: has_evidence,
                        });
                        continue;
                    }
                };

            // Merge into workload_map
            let wk: WorkloadKey = (
                top_group.clone(),
                top_version.clone(),
                top_kind.clone(),
                ns.clone(),
                top_name.clone(),
                top_uid.clone(),
            );
            let top_obj_key = (ns.clone(), top_kind.clone(), top_name.clone());
            let top_obj = native_workload_objects.get(&top_obj_key);
            let evidence = if let Some(obj) = top_obj {
                classify_evidence(obj, ctx, &target_uids)
            } else {
                classify_evidence(pod, ctx, &target_uids)
            };
            let _confidence = compute_confidence(&evidence);
            if !has_positive_target_evidence(&evidence) {
                continue; // No positive target evidence → scope-out
            }
            let classification = ResidualClassification::Attributed;

            workload_map
                .entry(wk)
                .and_modify(|existing| {
                    if existing.owner_chain.is_empty() && !owner_chain.is_empty() {
                        existing.owner_chain.clone_from(&owner_chain);
                    }
                })
                .or_insert_with(|| ResidualWorkload {
                    resource: ResourceId {
                        group: top_group,
                        version: top_version,
                        kind: top_kind,
                        namespace: Some(ns.clone()),
                        name: top_name,
                        uid: Some(top_uid),
                    },
                    uid: top_obj.and_then(|o| o.metadata.uid.clone()),
                    owner_chain,
                    classification,
                    evidence,
                    scope_provenance: scope_provenance_str(ctx, ns),
                });
        }
    }

    // Derive classification views from canonical workload_map
    audit.residual_workloads = workload_map.into_values().collect();
    audit.residual_workloads.sort_by(|a, b| {
        a.resource
            .group
            .cmp(&b.resource.group)
            .then(a.resource.kind.cmp(&b.resource.kind))
            .then(a.resource.namespace.cmp(&b.resource.namespace))
            .then(a.resource.name.cmp(&b.resource.name))
    });

    for wl in &audit.residual_workloads {
        let residual = AttributedResidual {
            resource: wl.resource.clone(),
            evidence: wl.evidence.clone(),
            confidence: compute_confidence(&wl.evidence),
        };
        match wl.classification {
            ResidualClassification::Unattributed => audit.unattributed.push(residual),
            ResidualClassification::Attributed => audit.likely_operator_residual.push(residual),
            _ => {}
        }
    }

    // Sort scan_errors for deterministic JSON output
    audit.scan_errors.sort_by(|a, b| {
        a.namespace
            .cmp(&b.namespace)
            .then(a.resource_type.cmp(&b.resource_type))
            .then(a.error.cmp(&b.error))
    });

    // Build incomplete_scopes from scan_errors (sorted, deduped)
    for err in &audit.scan_errors {
        audit.incomplete_scopes.push(IncompleteScopeEntry {
            namespace: err.namespace.clone(),
            resource_type: err.resource_type.clone(),
            error: err.error.clone(),
        });
    }
    audit.incomplete_scopes.sort_by(|a, b| {
        a.namespace
            .cmp(&b.namespace)
            .then(a.resource_type.cmp(&b.resource_type))
    });
    audit.incomplete_scopes.dedup_by(|a, b| {
        a.namespace == b.namespace && a.resource_type == b.resource_type && a.error == b.error
    });

    let sort_residual = |a: &AttributedResidual, b: &AttributedResidual| {
        a.resource
            .group
            .cmp(&b.resource.group)
            .then(a.resource.kind.cmp(&b.resource.kind))
            .then(a.resource.namespace.cmp(&b.resource.namespace))
            .then(a.resource.name.cmp(&b.resource.name))
    };
    audit.likely_operator_residual.sort_by(sort_residual);
    audit.unattributed.sort_by(sort_residual);

    Ok(audit)
}

/// Direct Job→CronJob normalization (independent of Pods).
/// For every Job in workload_map, inspect its ownerRefs:
/// - None/empty → Job is top-level (keep).
/// - Nonempty → select sole owner, require exact batch/v1/CronJob,
///   verify full identity, build Job→CronJob chain, upsert CronJob, remove Job.
/// - Missing/stale/ambiguous/unsupported → scan_error, remove Job.
#[allow(clippy::too_many_arguments)]
fn normalize_jobs_to_cronjobs(
    workload_map: &mut BTreeMap<WorkloadKey, ResidualWorkload>,
    native_workload_objects: &HashMap<(String, String, String), DynamicObject>,
    audit: &mut ResidualAudit,
    ctx: &crate::teardown::journal::AuditContext,
    target_uids: &HashSet<String>,
    plan_preserved: &HashMap<(String, String, String, String, String), Option<String>>,
) {
    let job_keys: Vec<WorkloadKey> = workload_map
        .keys()
        .filter(|k| k.2 == "Job")
        .cloned()
        .collect();
    for job_key in job_keys {
        let job_ns = job_key.3.clone();
        let job_name = job_key.4.clone();
        let job_uid = job_key.5.clone();
        let job_obj_key = (job_ns.clone(), "Job".to_string(), job_name.clone());
        let job_obj = match native_workload_objects.get(&job_obj_key) {
            Some(obj) => obj,
            None => continue,
        };
        let job_owners = match &job_obj.metadata.owner_references {
            Some(refs) if !refs.is_empty() => refs,
            _ => continue, // No ownerRefs — Job is top-level
        };
        match select_sole_owner(job_owners, &format!("Job/{}", job_name)) {
            Ok(cj_ref) => {
                let cj_group = api_version_to_group(&cj_ref.api_version);
                let cj_version = api_version_to_version(&cj_ref.api_version);
                if cj_group != "batch" || cj_version != "v1" || cj_ref.kind != "CronJob" {
                    let job_evidence = classify_evidence(job_obj, ctx, target_uids);
                    let has_target = has_positive_target_evidence(&job_evidence);
                    let _broad = is_broad_only_namespace(ctx, &job_ns);
                    let owner_desc = format!("{}/{}/{}", cj_group, cj_version, cj_ref.kind);
                    match decide_foreign(has_target, &owner_desc) {
                        ScopeDecision::ScopeOut => {
                            workload_map.remove(&job_key);
                        }
                        ScopeDecision::FailClosed(reason) => {
                            audit.scan_errors.push(AuditScanError {
                                resource_type: format!("Job/{}", job_name),
                                namespace: job_ns.clone(),
                                error: reason,
                                missing_owner_ref: None,
                                ..Default::default()
                            });
                            workload_map.remove(&job_key);
                        }
                    }
                    continue;
                }

                let cj_obj_key = (job_ns.clone(), "CronJob".to_string(), cj_ref.name.clone());
                match native_workload_objects.get(&cj_obj_key) {
                    Some(cj_obj) => {
                        if let Err(err) = verify_owner_identity(
                            cj_obj,
                            &cj_group,
                            &cj_version,
                            "CronJob",
                            &job_ns,
                            &cj_ref.name,
                            &cj_ref.uid,
                        ) {
                            audit.scan_errors.push(AuditScanError {
                                resource_type: format!("Job/{}", job_name),
                                namespace: job_ns.clone(),
                                error: format!("Job→CronJob identity verification failed: {}", err),
                                missing_owner_ref: None,
                                ..Default::default()
                            });
                            workload_map.remove(&job_key);
                            continue;
                        }
                        let cj_uid_str = match non_empty_uid(cj_obj, "CronJob", &cj_ref.name) {
                            Ok(u) => u,
                            Err(err) => {
                                audit.scan_errors.push(AuditScanError {
                                    resource_type: format!("Job/{}", job_name),
                                    namespace: job_ns.clone(),
                                    error: err,
                                    missing_owner_ref: None,
                                    ..Default::default()
                                });
                                workload_map.remove(&job_key);
                                continue;
                            }
                        };
                        let chain = vec![
                            OwnerChainEntry {
                                group: "batch".to_string(),
                                version: "v1".to_string(),
                                kind: "Job".to_string(),
                                name: job_name.clone(),
                                uid: job_uid.clone(),
                            },
                            OwnerChainEntry {
                                group: cj_group.clone(),
                                version: cj_version.clone(),
                                kind: "CronJob".to_string(),
                                name: cj_ref.name.clone(),
                                uid: cj_ref.uid.clone(),
                            },
                        ];
                        let cj_wk: WorkloadKey = (
                            cj_group.clone(),
                            cj_version.clone(),
                            "CronJob".to_string(),
                            job_ns.clone(),
                            cj_ref.name.clone(),
                            cj_uid_str.clone(),
                        );
                        let cj_evidence = classify_evidence(cj_obj, ctx, target_uids);
                        let _cj_confidence = compute_confidence(&cj_evidence);
                        let cj_classification = if let Some(plan_uid) = plan_preserved.get(&(
                            cj_group.clone(),
                            cj_version.clone(),
                            "CronJob".to_string(),
                            job_ns.clone(),
                            cj_ref.name.clone(),
                        )) {
                            match plan_uid {
                                Some(pu) if !pu.is_empty() && pu == &cj_uid_str => {
                                    ResidualClassification::Preserved
                                }
                                _ => {
                                    if has_positive_target_evidence(&cj_evidence) {
                                        ResidualClassification::Attributed
                                    } else {
                                        ResidualClassification::Unattributed
                                    }
                                }
                            }
                        } else if has_positive_target_evidence(&cj_evidence) {
                            ResidualClassification::Attributed
                        } else {
                            ResidualClassification::Unattributed
                        };
                        workload_map
                            .entry(cj_wk)
                            .and_modify(|existing| {
                                if existing.owner_chain.is_empty() {
                                    existing.owner_chain.clone_from(&chain);
                                }
                            })
                            .or_insert(ResidualWorkload {
                                resource: ResourceId {
                                    group: cj_group,
                                    version: cj_version,
                                    kind: "CronJob".to_string(),
                                    namespace: Some(job_ns.clone()),
                                    name: cj_ref.name.clone(),
                                    uid: Some(cj_uid_str),
                                },
                                uid: cj_obj.metadata.uid.clone(),
                                owner_chain: chain,
                                classification: cj_classification,
                                evidence: cj_evidence,
                                scope_provenance: scope_provenance_str(ctx, &job_ns),
                            });
                        workload_map.remove(&job_key);
                    }
                    None => {
                        let job_evidence = classify_evidence(job_obj, ctx, target_uids);
                        if !has_positive_target_evidence(&job_evidence)
                            && is_broad_only_namespace(ctx, &job_ns)
                        {
                            workload_map.remove(&job_key);
                            continue;
                        }
                        audit.scan_errors.push(AuditScanError {
                            resource_type: format!("Job/{}", job_name),
                            namespace: job_ns.clone(),
                            error: format!(
                                "CronJob {} not found in native workload scan",
                                cj_ref.name
                            ),
                            missing_owner_ref: Some(Box::new(ResourceId {
                                group: cj_group.clone(),
                                version: cj_version.clone(),
                                kind: "CronJob".to_string(),
                                namespace: Some(job_ns),
                                name: cj_ref.name.clone(),
                                uid: Some(cj_ref.uid.clone()),
                            })),
                            ..Default::default()
                        });
                        workload_map.remove(&job_key);
                    }
                }
            }
            Err(err) => {
                audit.scan_errors.push(AuditScanError {
                    resource_type: format!("Job/{}", job_name),
                    namespace: job_ns,
                    error: err,
                    missing_owner_ref: None,
                    ..Default::default()
                });
                workload_map.remove(&job_key);
            }
        }
    }
}

fn scope_provenance_str(
    ctx: &crate::teardown::journal::AuditContext,
    namespace: &str,
) -> Option<String> {
    ctx.namespace_scope
        .as_ref()
        .and_then(|scope| scope.iter().find(|e| e.namespace == namespace))
        .map(|e| {
            e.evidence
                .iter()
                .map(|ev| format!("{:?}", ev))
                .collect::<Vec<_>>()
                .join(", ")
        })
}

/// LIST resources through the shared planner (retry/timeout/dedup).
/// Returns Ok(items) or maps ScanWarning to AuditScanError.
#[allow(clippy::too_many_arguments)]
async fn audit_list(
    client: &Client,
    group: &str,
    version: &str,
    kind: &str,
    plural: &str,
    namespace: Option<&str>,
    requirement: crate::kube::resource::QueryRequirement,
    planner: &crate::kube::scanner::SharedPlanner,
) -> std::result::Result<Vec<DynamicObject>, AuditScanError> {
    use crate::kube::resource::QueryRequirement;

    match planner
        .list_all(client, group, version, plural, namespace, requirement)
        .await
    {
        Ok(items) => {
            let expected_api_version = if group.is_empty() {
                version.to_string()
            } else {
                format!("{group}/{version}")
            };
            let mut objects = (*items).clone();
            for obj in &mut objects {
                match obj.types.as_ref() {
                    Some(t) if t.api_version != expected_api_version || t.kind != kind => {
                        return Err(AuditScanError {
                            resource_type: kind.to_string(),
                            namespace: namespace.unwrap_or("cluster").to_string(),
                            error: format!(
                                "LIST item TypeMeta mismatch: expected {}/{}, got {}/{}",
                                expected_api_version, kind, t.api_version, t.kind
                            ),
                            missing_owner_ref: None,
                            ..Default::default()
                        });
                    }
                    Some(_) => {}
                    None => {
                        obj.types = Some(kube::api::TypeMeta {
                            api_version: expected_api_version.clone(),
                            kind: kind.to_string(),
                        });
                    }
                }
            }
            Ok(objects)
        }
        Err(warning) => {
            if requirement == QueryRequirement::Optional
                && matches!(warning, crate::kube::resource::ScanWarning::NotFound { .. })
            {
                return Ok(vec![]);
            }
            Err(AuditScanError {
                resource_type: kind.to_string(),
                namespace: namespace.unwrap_or("cluster").to_string(),
                error: format!("{:?}", warning),
                missing_owner_ref: None,
                ..Default::default()
            })
        }
    }
}

/// Extract a non-empty UID from a DynamicObject, or return an error.
/// Missing and empty UID both fail — they must never create a residual identity.
fn non_empty_uid(
    obj: &DynamicObject,
    kind: &str,
    name: &str,
) -> std::result::Result<String, String> {
    match obj.metadata.uid.as_deref() {
        Some(u) if !u.is_empty() => Ok(u.to_string()),
        _ => Err(format!(
            "{}/{} has no UID or empty UID — identity unverifiable",
            kind, name
        )),
    }
}

/// Verify a live object matches the expected ownerRef identity.
/// Checks apiVersion (group+version), kind, namespace, name, and UID.
fn verify_owner_identity(
    live_obj: &DynamicObject,
    expected_group: &str,
    expected_version: &str,
    expected_kind: &str,
    expected_ns: &str,
    expected_name: &str,
    expected_uid: &str,
) -> std::result::Result<(), String> {
    if expected_uid.is_empty() {
        return Err(format!(
            "{}/{} expected UID is empty — identity unverifiable",
            expected_kind, expected_name
        ));
    }
    let live_uid = match live_obj.metadata.uid.as_deref() {
        Some(u) if !u.is_empty() => u,
        _ => {
            return Err(format!(
                "{}/{} live UID is missing or empty — identity unverifiable",
                expected_kind, expected_name
            ));
        }
    };
    if live_uid != expected_uid {
        return Err(format!(
            "{}/{} UID {} does not match live UID {} — stale identity",
            expected_kind, expected_name, expected_uid, live_uid
        ));
    }
    let live_name = live_obj.metadata.name.as_deref().unwrap_or("");
    if live_name != expected_name {
        return Err(format!(
            "{} name mismatch: expected {}, live {}",
            expected_kind, expected_name, live_name
        ));
    }
    let live_ns = live_obj.metadata.namespace.as_deref().unwrap_or("");
    if live_ns != expected_ns {
        return Err(format!(
            "{}/{} namespace mismatch: expected {}, live {}",
            expected_kind, expected_name, expected_ns, live_ns
        ));
    }
    // Verify apiVersion and kind — TypeMeta must be present
    let types = live_obj.types.as_ref().ok_or_else(|| {
        format!(
            "{}/{} missing TypeMeta — cannot verify apiVersion/kind",
            expected_kind, expected_name
        )
    })?;
    if types.kind != expected_kind {
        return Err(format!(
            "{}/{} kind mismatch: expected {}, live {}",
            expected_kind, expected_name, expected_kind, types.kind
        ));
    }
    let live_group = api_version_to_group(&types.api_version);
    let live_version = api_version_to_version(&types.api_version);
    if live_group != expected_group || live_version != expected_version {
        return Err(format!(
            "{}/{} apiVersion mismatch: expected {}/{}, live {}/{}",
            expected_kind,
            expected_name,
            expected_group,
            expected_version,
            live_group,
            live_version
        ));
    }
    Ok(())
}

/// Select exactly one owner from ownerRefs.
/// One controller → that one. No controllers, exactly one ref → that one.
/// Zero/multiple → fail closed.
fn select_sole_owner<'a>(
    owner_refs: &'a [k8s_openapi::apimachinery::pkg::apis::meta::v1::OwnerReference],
    resource_desc: &str,
) -> std::result::Result<&'a k8s_openapi::apimachinery::pkg::apis::meta::v1::OwnerReference, String>
{
    let controllers: Vec<_> = owner_refs
        .iter()
        .filter(|r| r.controller.unwrap_or(false))
        .collect();
    if controllers.len() == 1 {
        return Ok(controllers[0]);
    }
    if controllers.len() > 1 {
        return Err(format!(
            "{} has {} controller ownerRefs — multi-owner fail closed",
            resource_desc,
            controllers.len()
        ));
    }
    // No controller refs
    if owner_refs.len() == 1 {
        return Ok(&owner_refs[0]);
    }
    Err(format!(
        "{} has {} non-controller ownerRefs and no controller — ambiguous fail closed",
        resource_desc,
        owner_refs.len()
    ))
}

/// Normalize a Pod's ownerRef to its top-level controller.
/// Returns (kind, group, version, name, uid, owner_chain) or error string.
/// Verifies full identity (group/version/kind/namespace/name/UID) at every hop.
/// Walks: Pod→RS→Deployment, Pod→StatefulSet, Pod→DaemonSet, Pod→Job→CronJob.
type NormalizedOwner = (String, String, String, String, String, Vec<OwnerChainEntry>);

/// Result of Pod/Job owner normalization.
#[derive(Debug)]
enum OwnerNormalization {
    /// Successfully resolved to a top-level workload controller.
    Resolved(NormalizedOwner),
    /// Owner GVK is outside the supported workload chain (e.g. CatalogSource, ConfigMap).
    /// Not a verification failure — the object is simply foreign to teardown scope.
    Foreign { owner_gvk: String },
    /// Owner identity could not be verified (stale UID, missing object, cycle, multi-owner).
    Incomplete {
        reason: String,
        missing_ref: Option<ResourceId>,
    },
}

#[cfg(test)]
impl OwnerNormalization {
    fn unwrap(self) -> NormalizedOwner {
        match self {
            OwnerNormalization::Resolved(r) => r,
            OwnerNormalization::Foreign { owner_gvk } => {
                panic!("expected Resolved, got Foreign({})", owner_gvk)
            }
            OwnerNormalization::Incomplete { reason, .. } => {
                panic!("expected Resolved, got Incomplete({})", reason)
            }
        }
    }
    fn unwrap_err(self) -> String {
        match self {
            OwnerNormalization::Incomplete { reason, .. } => reason,
            OwnerNormalization::Foreign { owner_gvk } => {
                format!("FOREIGN: {}", owner_gvk)
            }
            OwnerNormalization::Resolved(_) => {
                panic!("expected error, got Resolved")
            }
        }
    }
    fn is_ok(&self) -> bool {
        matches!(self, OwnerNormalization::Resolved(_))
    }
    fn is_err(&self) -> bool {
        !self.is_ok()
    }
    fn is_foreign(&self) -> bool {
        matches!(self, OwnerNormalization::Foreign { .. })
    }
}

/// Returns true if a namespace is in scope only because of AllNamespaces OG.
/// In such namespaces, objects with no target evidence are scope-out (not residuals).
/// Decision for foreign-owned objects based on namespace scope and target evidence.
enum ScopeDecision {
    ScopeOut,
    FailClosed(String),
}

fn decide_foreign(has_target_evidence: bool, owner_gvk: &str) -> ScopeDecision {
    if has_target_evidence {
        ScopeDecision::FailClosed(format!(
            "Foreign owner {} with target evidence — fail closed",
            owner_gvk
        ))
    } else {
        ScopeDecision::ScopeOut
    }
}

fn is_broad_only_namespace(ctx: &crate::teardown::journal::AuditContext, namespace: &str) -> bool {
    use crate::teardown::journal::NamespaceScopeEvidence;
    ctx.namespace_scope.as_ref().is_some_and(|scope| {
        scope
            .iter()
            .find(|e| e.namespace == namespace)
            .is_some_and(|entry| {
                !entry.evidence.is_empty()
                    && entry
                        .evidence
                        .iter()
                        .all(|ev| matches!(ev, NamespaceScopeEvidence::OperatorGroupAllNamespaces))
            })
    })
}

/// Normalize a Pod's ownerRef to its top-level controller.
/// Returns OwnerNormalization: Resolved, Foreign, or Incomplete.
/// Verifies full identity (group/version/kind/namespace/name/UID) at every hop.
/// Walks: Pod→RS→Deployment, Pod→StatefulSet, Pod→DaemonSet, Pod→Job→CronJob.
fn normalize_pod_owner(
    owner: &k8s_openapi::apimachinery::pkg::apis::meta::v1::OwnerReference,
    namespace: &str,
    rs_lookup: &HashMap<(String, String), &DynamicObject>,
    native_workload_objects: &HashMap<(String, String, String), DynamicObject>,
) -> OwnerNormalization {
    let owner_group = api_version_to_group(&owner.api_version);
    let owner_version = api_version_to_version(&owner.api_version);
    let mut visited_uids: HashSet<String> = HashSet::new();
    visited_uids.insert(owner.uid.clone());

    let mut chain = vec![OwnerChainEntry {
        group: owner_group.clone(),
        version: owner_version.clone(),
        kind: owner.kind.clone(),
        name: owner.name.clone(),
        uid: owner.uid.clone(),
    }];

    // Anchor supported Pod owner GVK
    let supported = matches!(
        (
            owner_group.as_str(),
            owner_version.as_str(),
            owner.kind.as_str()
        ),
        ("apps", "v1", "ReplicaSet")
            | ("apps", "v1", "StatefulSet")
            | ("apps", "v1", "DaemonSet")
            | ("batch", "v1", "Job")
    );
    if !supported {
        return OwnerNormalization::Foreign {
            owner_gvk: format!("{}/{}/{}", owner_group, owner_version, owner.kind),
        };
    }

    match owner.kind.as_str() {
        "ReplicaSet" => {
            let rs_key = (namespace.to_string(), owner.name.clone());
            let rs = match rs_lookup.get(&rs_key) {
                Some(rs) => rs,
                None => {
                    return OwnerNormalization::Incomplete {
                        reason: format!(
                            "ReplicaSet {} not found in LIST results — cannot verify identity",
                            owner.name
                        ),
                        missing_ref: None,
                    };
                }
            };
            if let Err(e) = verify_owner_identity(
                rs,
                &owner_group,
                &owner_version,
                "ReplicaSet",
                namespace,
                &owner.name,
                &owner.uid,
            ) {
                return OwnerNormalization::Incomplete {
                    reason: e,
                    missing_ref: None,
                };
            }
            if let Some(rs_owners) = &rs.metadata.owner_references {
                let dep_owner =
                    match select_sole_owner(rs_owners, &format!("ReplicaSet/{}", owner.name)) {
                        Ok(o) => o,
                        Err(e) => {
                            return OwnerNormalization::Incomplete {
                                reason: e,
                                missing_ref: None,
                            };
                        }
                    };
                let dep_group = api_version_to_group(&dep_owner.api_version);
                let dep_version = api_version_to_version(&dep_owner.api_version);
                if dep_group != "apps" || dep_version != "v1" || dep_owner.kind != "Deployment" {
                    return OwnerNormalization::Incomplete {
                        reason: format!(
                            "ReplicaSet {} owned by unsupported GVK {}/{}/{} — expected apps/v1/Deployment",
                            owner.name, dep_group, dep_version, dep_owner.kind
                        ),
                        missing_ref: None,
                    };
                }
                if !visited_uids.insert(dep_owner.uid.clone()) {
                    return OwnerNormalization::Incomplete {
                        reason: format!(
                            "ownerRef cycle at ReplicaSet {} → Deployment {}",
                            owner.name, dep_owner.name
                        ),
                        missing_ref: None,
                    };
                }
                let dep_key = (
                    namespace.to_string(),
                    "Deployment".to_string(),
                    dep_owner.name.clone(),
                );
                let dep_obj = match native_workload_objects.get(&dep_key) {
                    Some(o) => o,
                    None => {
                        return OwnerNormalization::Incomplete {
                            reason: format!(
                                "Deployment {} not found in native workload scan — cannot verify identity",
                                dep_owner.name
                            ),
                            missing_ref: Some(ResourceId {
                                group: dep_group.clone(),
                                version: dep_version.clone(),
                                kind: "Deployment".to_string(),
                                namespace: Some(namespace.to_string()),
                                name: dep_owner.name.clone(),
                                uid: Some(dep_owner.uid.clone()),
                            }),
                        };
                    }
                };
                if let Err(e) = verify_owner_identity(
                    dep_obj,
                    &dep_group,
                    &dep_version,
                    "Deployment",
                    namespace,
                    &dep_owner.name,
                    &dep_owner.uid,
                ) {
                    return OwnerNormalization::Incomplete {
                        reason: e,
                        missing_ref: None,
                    };
                }
                chain.push(OwnerChainEntry {
                    group: dep_group.clone(),
                    version: dep_version.clone(),
                    kind: "Deployment".to_string(),
                    name: dep_owner.name.clone(),
                    uid: dep_owner.uid.clone(),
                });
                return OwnerNormalization::Resolved((
                    "Deployment".to_string(),
                    dep_group,
                    dep_version,
                    dep_owner.name.clone(),
                    dep_owner.uid.clone(),
                    chain,
                ));
            }
            // RS has no ownerRefs — RS is top-level
            OwnerNormalization::Resolved((
                "ReplicaSet".to_string(),
                owner_group,
                owner_version,
                owner.name.clone(),
                owner.uid.clone(),
                chain,
            ))
        }
        "StatefulSet" | "DaemonSet" => {
            let obj_key = (
                namespace.to_string(),
                owner.kind.clone(),
                owner.name.clone(),
            );
            let live_obj = match native_workload_objects.get(&obj_key) {
                Some(o) => o,
                None => {
                    return OwnerNormalization::Incomplete {
                        reason: format!(
                            "{} {} not found in native workload scan — cannot verify identity",
                            owner.kind, owner.name
                        ),
                        missing_ref: Some(ResourceId {
                            group: owner_group.clone(),
                            version: owner_version.clone(),
                            kind: owner.kind.clone(),
                            namespace: Some(namespace.to_string()),
                            name: owner.name.clone(),
                            uid: Some(owner.uid.clone()),
                        }),
                    };
                }
            };
            if let Err(e) = verify_owner_identity(
                live_obj,
                &owner_group,
                &owner_version,
                &owner.kind,
                namespace,
                &owner.name,
                &owner.uid,
            ) {
                return OwnerNormalization::Incomplete {
                    reason: e,
                    missing_ref: None,
                };
            }
            OwnerNormalization::Resolved((
                owner.kind.clone(),
                owner_group,
                owner_version,
                owner.name.clone(),
                owner.uid.clone(),
                chain,
            ))
        }
        "Job" => {
            let job_key = (namespace.to_string(), "Job".to_string(), owner.name.clone());
            let job_obj = match native_workload_objects.get(&job_key) {
                Some(o) => o,
                None => {
                    return OwnerNormalization::Incomplete {
                        reason: format!(
                            "Job {} not found in native workload scan — cannot verify identity",
                            owner.name
                        ),
                        missing_ref: Some(ResourceId {
                            group: owner_group.clone(),
                            version: owner_version.clone(),
                            kind: "Job".to_string(),
                            namespace: Some(namespace.to_string()),
                            name: owner.name.clone(),
                            uid: Some(owner.uid.clone()),
                        }),
                    };
                }
            };
            if let Err(e) = verify_owner_identity(
                job_obj,
                &owner_group,
                &owner_version,
                "Job",
                namespace,
                &owner.name,
                &owner.uid,
            ) {
                return OwnerNormalization::Incomplete {
                    reason: e,
                    missing_ref: None,
                };
            }
            // Walk Job → CronJob
            if let Some(job_owners) = &job_obj.metadata.owner_references
                && !job_owners.is_empty()
            {
                let cj_owner = match select_sole_owner(job_owners, &format!("Job/{}", owner.name)) {
                    Ok(o) => o,
                    Err(e) => {
                        return OwnerNormalization::Incomplete {
                            reason: e,
                            missing_ref: None,
                        };
                    }
                };
                let cj_group_p = api_version_to_group(&cj_owner.api_version);
                let cj_version_p = api_version_to_version(&cj_owner.api_version);
                if cj_group_p != "batch" || cj_version_p != "v1" || cj_owner.kind != "CronJob" {
                    return OwnerNormalization::Foreign {
                        owner_gvk: format!("{}/{}/{}", cj_group_p, cj_version_p, cj_owner.kind),
                    };
                }
                if !visited_uids.insert(cj_owner.uid.clone()) {
                    return OwnerNormalization::Incomplete {
                        reason: format!(
                            "ownerRef cycle at Job {} → CronJob {}",
                            owner.name, cj_owner.name
                        ),
                        missing_ref: None,
                    };
                }
                let cj_key = (
                    namespace.to_string(),
                    "CronJob".to_string(),
                    cj_owner.name.clone(),
                );
                let cj_obj = match native_workload_objects.get(&cj_key) {
                    Some(o) => o,
                    None => {
                        return OwnerNormalization::Incomplete {
                            reason: format!(
                                "CronJob {} not found in native workload scan — cannot verify identity",
                                cj_owner.name
                            ),
                            missing_ref: Some(ResourceId {
                                group: cj_group_p.clone(),
                                version: cj_version_p.clone(),
                                kind: "CronJob".to_string(),
                                namespace: Some(namespace.to_string()),
                                name: cj_owner.name.clone(),
                                uid: Some(cj_owner.uid.clone()),
                            }),
                        };
                    }
                };
                if let Err(e) = verify_owner_identity(
                    cj_obj,
                    &cj_group_p,
                    &cj_version_p,
                    "CronJob",
                    namespace,
                    &cj_owner.name,
                    &cj_owner.uid,
                ) {
                    return OwnerNormalization::Incomplete {
                        reason: e,
                        missing_ref: None,
                    };
                }
                chain.push(OwnerChainEntry {
                    group: cj_group_p.clone(),
                    version: cj_version_p.clone(),
                    kind: "CronJob".to_string(),
                    name: cj_owner.name.clone(),
                    uid: cj_owner.uid.clone(),
                });
                return OwnerNormalization::Resolved((
                    "CronJob".to_string(),
                    cj_group_p,
                    cj_version_p,
                    cj_owner.name.clone(),
                    cj_owner.uid.clone(),
                    chain,
                ));
            }
            // Job has no CronJob owner — Job is top-level
            OwnerNormalization::Resolved((
                "Job".to_string(),
                owner_group,
                owner_version,
                owner.name.clone(),
                owner.uid.clone(),
                chain,
            ))
        }
        _ => unreachable!("GVK was validated above"),
    }
}

fn api_version_to_group(api_version: &str) -> String {
    if let Some((group, _)) = api_version.rsplit_once('/') {
        group.to_string()
    } else {
        String::new()
    }
}

fn api_version_to_version(api_version: &str) -> String {
    if let Some((_, version)) = api_version.rsplit_once('/') {
        version.to_string()
    } else {
        api_version.to_string()
    }
}

/// Scan a single GVR in a namespace for residual resources.
/// All LIST failures (404/403/timeout) are scan errors → AuditIncomplete.
#[allow(clippy::too_many_arguments)]
async fn scan_namespace_for_target(
    client: &Client,
    group: &str,
    version: &str,
    kind: &str,
    plural: &str,
    namespace: &str,
    ctx: &AuditContext,
    target_uids: &HashSet<String>,
    plan_resources: &HashSet<(String, String, Option<String>, String)>,
    audit: &mut ResidualAudit,
    requirement: crate::kube::resource::QueryRequirement,
    planner: &crate::kube::scanner::SharedPlanner,
) {
    audit.coverage.requested_probes += 1;

    match audit_list(
        client,
        group,
        version,
        kind,
        plural,
        Some(namespace),
        requirement,
        planner,
    )
    .await
    {
        Ok(items) => {
            audit.coverage.succeeded_probes += 1;
            classify_list_results(
                items,
                kind,
                group,
                version,
                namespace,
                ctx,
                target_uids,
                plan_resources,
                audit,
            );
        }
        Err(e) => {
            audit.scan_errors.push(e);
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn classify_list_results(
    items: Vec<DynamicObject>,
    kind: &str,
    group: &str,
    version: &str,
    namespace: &str,
    ctx: &AuditContext,
    target_uids: &HashSet<String>,
    plan_resources: &HashSet<(String, String, Option<String>, String)>,
    audit: &mut ResidualAudit,
) {
    for obj in items {
        let name = match &obj.metadata.name {
            Some(n) => n.clone(),
            None => {
                audit.scan_errors.push(AuditScanError {
                    resource_type: kind.to_string(),
                    namespace: namespace.to_string(),
                    error: "Object found without metadata.name — identity unknown".to_string(),
                    missing_owner_ref: None,
                    ..Default::default()
                });
                continue;
            }
        };

        let uid = match non_empty_uid(&obj, kind, &name) {
            Ok(u) => u,
            Err(err) => {
                audit.scan_errors.push(AuditScanError {
                    resource_type: kind.to_string(),
                    namespace: namespace.to_string(),
                    error: err,
                    missing_owner_ref: None,
                    ..Default::default()
                });
                continue;
            }
        };

        let obj_ns = obj.metadata.namespace.clone();
        let key = (
            group.to_string(),
            kind.to_string(),
            obj_ns.clone(),
            name.clone(),
        );
        if plan_resources.contains(&key) {
            continue;
        }

        let rid = ResourceId {
            group: group.to_string(),
            version: version.to_string(),
            kind: kind.to_string(),
            namespace: obj_ns,
            name,
            uid: Some(uid),
        };

        let evidence = classify_evidence(&obj, ctx, target_uids);
        let confidence = compute_confidence(&evidence);
        // In broad-only namespaces, skip related resources with no target evidence
        if !has_positive_target_evidence(&evidence) {
            continue; // No positive target evidence → scope-out
        }
        let classification = ResidualClassification::Attributed;

        let scope_prov = ctx
            .namespace_scope
            .as_ref()
            .and_then(|scope| scope.iter().find(|e| e.namespace == namespace))
            .map(|e| {
                e.evidence
                    .iter()
                    .map(|ev| format!("{:?}", ev))
                    .collect::<Vec<_>>()
                    .join(", ")
            });

        if matches!(
            kind,
            "Deployment"
                | "StatefulSet"
                | "DaemonSet"
                | "Service"
                | "Route"
                | "ImageStream"
                | "Subscription"
                | "ClusterServiceVersion"
        ) {
            audit.residual_workloads.push(ResidualWorkload {
                resource: rid.clone(),
                uid: rid.uid.clone(),
                owner_chain: vec![],
                classification: classification.clone(),
                evidence: evidence.clone(),
                scope_provenance: scope_prov,
            });
        }

        let residual = AttributedResidual {
            resource: rid,
            evidence,
            confidence: confidence.clone(),
        };

        if confidence == ResidualConfidence::None {
            audit.unattributed.push(residual);
        } else {
            audit.likely_operator_residual.push(residual);
        }
    }
}

// ──────────────────────────────────────────────────────────────
//  Attribution classification
// ──────────────────────────────────────────────────────────────

fn classify_evidence(
    obj: &DynamicObject,
    ctx: &AuditContext,
    target_uids: &HashSet<String>,
) -> ResidualEvidence {
    let mut owner_ref_match = false;
    let mut matching_labels = Vec::new();
    let mut matching_managers = Vec::new();
    let mut service_account_match = false;

    // Check ownerRefs against target operator identity UIDs
    if let Some(owner_refs) = &obj.metadata.owner_references {
        for oref in owner_refs {
            if target_uids.contains(&oref.uid) {
                owner_ref_match = true;
                break;
            }
        }
    }

    // Check labels
    if let Some(labels) = &obj.metadata.labels {
        for csv_name in &ctx.csv_names {
            let prefix = csv_name.split('.').next().unwrap_or(csv_name);
            for (k, v) in labels {
                if k.contains(prefix) || v.contains(prefix) {
                    matching_labels.push((k.clone(), v.clone()));
                }
            }
        }
    }

    // Check managedFields managers
    if let Some(managed_fields) = &obj.metadata.managed_fields {
        for mf in managed_fields {
            if let Some(manager) = &mf.manager {
                for dep_name in &ctx.controller_deployment_names {
                    if manager.contains(dep_name.as_str()) {
                        matching_managers.push(manager.clone());
                    }
                }
                for csv_name in &ctx.csv_names {
                    let prefix = csv_name.split('.').next().unwrap_or(csv_name);
                    if manager.contains(prefix) && !matching_managers.contains(manager) {
                        matching_managers.push(manager.clone());
                    }
                }
            }
        }
    }

    // Check serviceAccountName in spec (for Pods/Deployments)
    if let Some(spec) = obj.data.get("spec") {
        let sa_name = spec
            .get("template")
            .and_then(|t| t.get("spec"))
            .and_then(|s| s.get("serviceAccountName"))
            .and_then(|n| n.as_str())
            .or_else(|| spec.get("serviceAccountName").and_then(|n| n.as_str()));

        if let Some(sa) = sa_name
            && ctx.service_account_names.contains(sa)
        {
            service_account_match = true;
        }
    }

    // namespace_affinity is always true since we only scan footprint namespaces
    // but it's a supplementary signal, not classification-driving
    ResidualEvidence {
        owner_ref_match,
        matching_labels,
        matching_managers,
        namespace_affinity: true,
        service_account_match,
    }
}

/// Deterministic confidence rules:
/// HIGH: ownerRef UID matches target operator identity, OR SA match + matching manager
/// MEDIUM: matching manager + matching label
/// LOW: matching label only OR matching manager only
/// NONE: namespace affinity only / no evidence
///
/// Attribution confidence is NOT deletion authority.
fn compute_confidence(evidence: &ResidualEvidence) -> ResidualConfidence {
    if evidence.owner_ref_match {
        return ResidualConfidence::High;
    }

    let has_managers = !evidence.matching_managers.is_empty();
    let has_labels = !evidence.matching_labels.is_empty();
    let has_sa = evidence.service_account_match;

    if has_sa && has_managers {
        ResidualConfidence::High
    } else if has_managers && has_labels {
        ResidualConfidence::Medium
    } else if has_managers || has_labels {
        ResidualConfidence::Low
    } else {
        // namespace_affinity alone is NOT sufficient for LIKELY classification
        ResidualConfidence::None
    }
}

/// Positive target evidence: authoritative signals or corroborated hints.
/// Single-signal substring matches (label-only or manager-only) are display
/// hints, not safety-decision evidence.
fn has_positive_target_evidence(evidence: &ResidualEvidence) -> bool {
    evidence.owner_ref_match
        || evidence.service_account_match
        || (!evidence.matching_managers.is_empty() && !evidence.matching_labels.is_empty())
}

// ──────────────────────────────────────────────────────────────
//  Resource probing
// ──────────────────────────────────────────────────────────────

enum ProbeResult {
    Present { uid: Option<String> },
    Gone,
    Error(String),
}

/// Map well-known Kinds to their API plural. Returns None for unknown types
/// where guessing would produce false Gone results.
/// Resolve plural for a known (group, kind) pair.
/// Uses both group and kind to avoid cross-group collisions.
fn known_plural_for_gvk(group: &str, kind: &str) -> Option<&'static str> {
    match (group, kind) {
        ("", "Service") => Some("services"),
        ("", "Namespace") => Some("namespaces"),
        ("", "ConfigMap") => Some("configmaps"),
        ("", "ServiceAccount") => Some("serviceaccounts"),
        ("", "Pod") => Some("pods"),
        ("", "Secret") => Some("secrets"),
        ("apps", "Deployment") => Some("deployments"),
        ("apps", "StatefulSet") => Some("statefulsets"),
        ("apps", "DaemonSet") => Some("daemonsets"),
        ("apps", "ReplicaSet") => Some("replicasets"),
        ("route.openshift.io", "Route") => Some("routes"),
        ("image.openshift.io", "ImageStream") => Some("imagestreams"),
        ("operators.coreos.com", "Subscription") => Some("subscriptions"),
        ("operators.coreos.com", "ClusterServiceVersion") => Some("clusterserviceversions"),
        ("operators.coreos.com", "InstallPlan") => Some("installplans"),
        ("operators.coreos.com", "OperatorGroup") => Some("operatorgroups"),
        ("apiextensions.k8s.io", "CustomResourceDefinition") => Some("customresourcedefinitions"),
        _ => None,
    }
}

/// Probe a single resource by exact GET.
/// Uses discovery-derived GVR from known_gvrs, falling back to static allowlist.
/// GET 404 verifies endpoint existence via LIST — endpoint absence is not Gone.
async fn probe_resource(
    client: &Client,
    resource: &ResourceId,
    known_gvrs: &Option<Vec<crate::teardown::journal::KnownGvr>>,
    planner: &crate::kube::scanner::SharedPlanner,
) -> ProbeResult {
    // First try discovery-derived GVR (accurate plural + scope)
    let plural = if let Some(gvrs) = known_gvrs {
        gvrs.iter()
            .find(|g| g.group == resource.group && g.kind == resource.kind)
            .map(|g| g.plural.clone())
    } else {
        None
    };

    // Fall back to static allowlist for well-known types
    let plural =
        plural.or_else(|| known_plural_for_gvk(&resource.group, &resource.kind).map(String::from));

    let plural = match plural {
        Some(p) => p,
        None => {
            return ProbeResult::Error(format!(
                "Unknown GVR for {}/{} '{}' — no discovery metadata and not in static allowlist",
                resource.group, resource.kind, resource.name
            ));
        }
    };

    match gen_get(
        client,
        &resource.group,
        &resource.version,
        &plural,
        resource.namespace.as_deref(),
        &resource.name,
        planner,
    )
    .await
    {
        Ok(Some(obj)) => ProbeResult::Present {
            uid: obj.metadata.uid,
        },
        Ok(None) => ProbeResult::Gone,
        Err(e) => ProbeResult::Error(e),
    }
}

/// Compare plan UID with live UID to detect recreation.
/// Returns Unknown when either UID is missing — never assumes same resource.
fn check_recreation(plan_resource: &ResourceId, live_uid: &Option<String>) -> RecreationState {
    match (&plan_resource.uid, live_uid) {
        (Some(plan_uid), Some(live)) => {
            if plan_uid == live {
                RecreationState::SameResource
            } else {
                RecreationState::Recreated
            }
        }
        _ => RecreationState::Unknown,
    }
}

#[allow(dead_code)]
fn action_resource(action: &Action) -> &ResourceId {
    match action {
        Action::Delete { resource, .. }
        | Action::ExpectGone { resource, .. }
        | Action::WaitGone { resource }
        | Action::Keep { resource, .. }
        | Action::Review { resource, .. } => resource,
    }
}

// ──────────────────────────────────────────────────────────────
//  Display
// ──────────────────────────────────────────────────────────────

#[allow(dead_code)]
fn print_residual_item(item: &ResidualItem) {
    let suffix = ns_suffix(&item.resource);
    match item.recreation {
        RecreationState::Recreated => {
            eprintln!(
                "  {}/{}{} \x1b[33m(RECREATED — different UID)\x1b[0m",
                item.resource.kind, item.resource.name, suffix
            );
        }
        RecreationState::Unknown => {
            eprintln!(
                "  {}/{}{} \x1b[33m(UID unknown — cannot verify identity)\x1b[0m",
                item.resource.kind, item.resource.name, suffix
            );
        }
        RecreationState::SameResource => {
            eprintln!("  {}/{}{}", item.resource.kind, item.resource.name, suffix);
        }
    }
}

/// Deterministic camelCase summary for JSON output.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ResidualAuditSummary {
    pub target_operators_absent: bool,
    pub residual_workloads: Vec<ResidualWorkload>,
    pub attributed_residuals: Vec<AttributedResidual>,
    pub unattributed_residuals: Vec<AttributedResidual>,
    pub preserved_residuals: Vec<ResidualWorkload>,
    pub incomplete_scopes: Vec<IncompleteScopeEntry>,
}

impl ResidualAuditSummary {
    pub fn from_audit(audit: &ResidualAudit) -> Self {
        Self {
            target_operators_absent: audit.target_operators_absent,
            residual_workloads: audit.residual_workloads.clone(),
            attributed_residuals: audit.likely_operator_residual.clone(),
            unattributed_residuals: audit.unattributed.clone(),
            preserved_residuals: audit
                .residual_workloads
                .iter()
                .filter(|w| w.classification == ResidualClassification::Preserved)
                .cloned()
                .collect(),
            incomplete_scopes: audit.incomplete_scopes.clone(),
        }
    }
}

pub fn format_residual_audit_json(audit: &ResidualAudit) -> String {
    let summary = ResidualAuditSummary::from_audit(audit);
    serde_json::to_string_pretty(&summary).unwrap_or_else(|e| e.to_string())
}

/// Render a resource identity line for tree/table output.
fn render_resource_line(rid: &ResourceId, _ansi: bool) -> String {
    let uid = rid.uid.as_deref().unwrap_or("?");
    let ns = rid.namespace.as_deref().unwrap_or("cluster");
    format!(
        "{}.{}/{}/{}  ({})  [uid:{}]",
        rid.group, rid.version, rid.kind, rid.name, ns, uid
    )
}

/// Build a deduplication set from residual_workloads to avoid double-printing
/// resources that appear in both workloads and attributed/unattributed lists.
fn workload_identity_set(
    audit: &ResidualAudit,
) -> HashSet<(String, String, String, String, String)> {
    audit
        .residual_workloads
        .iter()
        .map(|w| {
            (
                w.resource.group.clone(),
                w.resource.kind.clone(),
                w.resource.namespace.clone().unwrap_or_default(),
                w.resource.name.clone(),
                w.resource.uid.clone().unwrap_or_default(),
            )
        })
        .collect()
}

/// Pure renderer for tree output. Returns a complete string.
pub fn render_residual_audit_tree(
    audit: &ResidualAudit,
    journal: &RunJournal,
    ansi: bool,
) -> String {
    let mut out = String::new();
    let bold = |s: &str| {
        if ansi {
            format!("\x1b[1m{}\x1b[0m", s)
        } else {
            s.to_string()
        }
    };
    let colored = |s: &str, c: &str| {
        if ansi {
            format!("\x1b[1;{}m{}\x1b[0m", c, s)
        } else {
            s.to_string()
        }
    };

    out.push_str(&format!(
        "\n{}: {}\n",
        bold("Teardown Residual Audit"),
        journal.operator.csv_name
    ));
    out.push_str(&format!("Session: {}\n", journal.run_id));
    out.push_str(&format!(
        "Target operator absent: {}\n",
        if audit.target_operators_absent {
            "yes"
        } else {
            "no"
        }
    ));
    out.push_str(&format!(
        "Execution: {:?} ({}/{} phases)\n\n",
        journal.state, journal.execution.phases_completed, journal.execution.phases_total,
    ));

    // Planned DELETE/EXPECT still present
    if !audit.planned_delete_still_present.is_empty() {
        out.push_str(&format!(
            "{} ({})\n",
            colored("PLANNED DELETE STILL PRESENT", "31"),
            audit.planned_delete_still_present.len()
        ));
        for item in &audit.planned_delete_still_present {
            out.push_str(&format!(
                "  {}/{}  [{}]\n",
                item.resource.kind, item.resource.name, item.planned_action
            ));
        }
        out.push('\n');
    }
    if !audit.planned_expect_still_present.is_empty() {
        out.push_str(&format!(
            "{} ({})\n",
            colored("PLANNED EXPECT-GONE STILL PRESENT", "33"),
            audit.planned_expect_still_present.len()
        ));
        for item in &audit.planned_expect_still_present {
            out.push_str(&format!(
                "  {}/{}  [{}]\n",
                item.resource.kind, item.resource.name, item.planned_action
            ));
        }
        out.push('\n');
    }

    // Residual workloads by classification
    let wl_ids = workload_identity_set(audit);
    for (label, color, class) in [
        (
            "ATTRIBUTED WORKLOADS",
            "35",
            ResidualClassification::Attributed,
        ),
        (
            "UNATTRIBUTED WORKLOADS",
            "0",
            ResidualClassification::Unattributed,
        ),
        (
            "PRESERVED WORKLOADS",
            "36",
            ResidualClassification::Preserved,
        ),
    ] {
        let items: Vec<_> = audit
            .residual_workloads
            .iter()
            .filter(|w| w.classification == class)
            .collect();
        if !items.is_empty() {
            out.push_str(&format!("{} ({})\n", colored(label, color), items.len()));
            for wl in &items {
                out.push_str(&format!("  {}\n", render_resource_line(&wl.resource, ansi)));
                if !wl.owner_chain.is_empty() {
                    let chain_str: Vec<String> = wl
                        .owner_chain
                        .iter()
                        .map(|c| format!("{}/{}", c.kind, c.name))
                        .collect();
                    out.push_str(&format!("    chain: {}\n", chain_str.join(" -> ")));
                }
                let ev = format_evidence(&wl.evidence);
                if !ev.is_empty() {
                    out.push_str(&format!("    evidence: {}\n", ev));
                }
                if let Some(prov) = &wl.scope_provenance {
                    out.push_str(&format!("    scope: {}\n", prov));
                }
            }
            out.push('\n');
        }
    }

    // Non-workload attributed residuals (e.g. Route, Service)
    let non_wl_attributed: Vec<_> = audit
        .likely_operator_residual
        .iter()
        .filter(|r| {
            let key = (
                r.resource.group.clone(),
                r.resource.kind.clone(),
                r.resource.namespace.clone().unwrap_or_default(),
                r.resource.name.clone(),
                r.resource.uid.clone().unwrap_or_default(),
            );
            !wl_ids.contains(&key)
        })
        .collect();
    if !non_wl_attributed.is_empty() {
        out.push_str(&format!(
            "{} ({})\n",
            colored("ATTRIBUTED RELATED RESOURCES", "35"),
            non_wl_attributed.len()
        ));
        for item in &non_wl_attributed {
            out.push_str(&format!(
                "  {}\n",
                render_resource_line(&item.resource, ansi)
            ));
            let ev = format_evidence(&item.evidence);
            if !ev.is_empty() {
                out.push_str(&format!("    evidence: {}\n", ev));
            }
        }
        out.push('\n');
    }

    // Non-workload unattributed residuals
    let non_wl_unattributed: Vec<_> = audit
        .unattributed
        .iter()
        .filter(|r| {
            let key = (
                r.resource.group.clone(),
                r.resource.kind.clone(),
                r.resource.namespace.clone().unwrap_or_default(),
                r.resource.name.clone(),
                r.resource.uid.clone().unwrap_or_default(),
            );
            !wl_ids.contains(&key)
        })
        .collect();
    if !non_wl_unattributed.is_empty() {
        out.push_str(&format!(
            "{} ({})\n",
            colored("UNATTRIBUTED RELATED RESOURCES", "0"),
            non_wl_unattributed.len()
        ));
        for item in &non_wl_unattributed {
            out.push_str(&format!(
                "  {}\n",
                render_resource_line(&item.resource, ansi)
            ));
        }
        out.push('\n');
    }

    // Expected preserved (plan-level)
    if !audit.expected_preserved.is_empty() {
        out.push_str(&format!(
            "{} ({})\n",
            bold("EXPECTED PRESERVED"),
            audit.expected_preserved.len()
        ));
        for item in &audit.expected_preserved {
            out.push_str(&format!(
                "  {}/{}  ({})\n",
                item.resource.kind,
                item.resource.name,
                item.resource.namespace.as_deref().unwrap_or("cluster")
            ));
            out.push_str(&format!("    {}\n", item.reason));
        }
        out.push('\n');
    }

    // Coverage
    out.push_str(&format!(
        "Audit coverage: {}/{} probes succeeded\n",
        audit.coverage.succeeded_probes, audit.coverage.requested_probes,
    ));

    // Incomplete scopes
    if !audit.incomplete_scopes.is_empty() {
        out.push_str(&format!(
            "{} ({})\n",
            colored("INCOMPLETE SCOPES", "33"),
            audit.incomplete_scopes.len()
        ));
        for inc in &audit.incomplete_scopes {
            out.push_str(&format!(
                "  {}/{}: {}\n",
                inc.resource_type, inc.namespace, inc.error
            ));
        }
    }

    out
}

/// Pure renderer for table output. Returns a complete string.
/// Pure renderer for table output using comfy_table. Returns a complete string.
pub fn render_residual_audit_table(
    audit: &ResidualAudit,
    journal: &RunJournal,
    _ansi: bool,
) -> String {
    use comfy_table::{ContentArrangement, Table};

    let mut out = String::new();
    out.push_str(&format!(
        "Teardown Residual Audit: {}\nSession: {}\nTarget operator absent: {}\n\n",
        journal.operator.csv_name,
        journal.run_id,
        if audit.target_operators_absent {
            "yes"
        } else {
            "no"
        },
    ));

    let wl_ids = workload_identity_set(audit);

    // Collect all rows: workloads + non-workload residuals
    struct Row {
        classification: String,
        resource: String,
        namespace: String,
        name: String,
        uid: String,
        evidence: String,
        chain: String,
        scope: String,
    }
    let mut rows: Vec<Row> = Vec::new();

    for wl in &audit.residual_workloads {
        let chain_str = if wl.owner_chain.is_empty() {
            String::new()
        } else {
            wl.owner_chain
                .iter()
                .map(|c| format!("{}/{}", c.kind, c.name))
                .collect::<Vec<_>>()
                .join(" -> ")
        };
        rows.push(Row {
            classification: format!("{:?}", wl.classification),
            resource: format!(
                "{}.{}/{}",
                wl.resource.group, wl.resource.version, wl.resource.kind
            ),
            namespace: wl
                .resource
                .namespace
                .clone()
                .unwrap_or_else(|| "cluster".into()),
            name: wl.resource.name.clone(),
            uid: wl.uid.as_deref().unwrap_or("?").to_string(),
            evidence: format_evidence(&wl.evidence),
            chain: chain_str,
            scope: wl.scope_provenance.clone().unwrap_or_default(),
        });
    }

    // Non-workload attributed
    for item in &audit.likely_operator_residual {
        let key = (
            item.resource.group.clone(),
            item.resource.kind.clone(),
            item.resource.namespace.clone().unwrap_or_default(),
            item.resource.name.clone(),
            item.resource.uid.clone().unwrap_or_default(),
        );
        if wl_ids.contains(&key) {
            continue;
        }
        rows.push(Row {
            classification: "Attributed".into(),
            resource: format!(
                "{}.{}/{}",
                item.resource.group, item.resource.version, item.resource.kind
            ),
            namespace: item
                .resource
                .namespace
                .clone()
                .unwrap_or_else(|| "cluster".into()),
            name: item.resource.name.clone(),
            uid: item.resource.uid.as_deref().unwrap_or("?").to_string(),
            evidence: format_evidence(&item.evidence),
            chain: String::new(),
            scope: String::new(),
        });
    }

    // Non-workload unattributed
    for item in &audit.unattributed {
        let key = (
            item.resource.group.clone(),
            item.resource.kind.clone(),
            item.resource.namespace.clone().unwrap_or_default(),
            item.resource.name.clone(),
            item.resource.uid.clone().unwrap_or_default(),
        );
        if wl_ids.contains(&key) {
            continue;
        }
        rows.push(Row {
            classification: "Unattributed".into(),
            resource: format!(
                "{}.{}/{}",
                item.resource.group, item.resource.version, item.resource.kind
            ),
            namespace: item
                .resource
                .namespace
                .clone()
                .unwrap_or_else(|| "cluster".into()),
            name: item.resource.name.clone(),
            uid: item.resource.uid.as_deref().unwrap_or("?").to_string(),
            evidence: format_evidence(&item.evidence),
            chain: String::new(),
            scope: String::new(),
        });
    }

    if !rows.is_empty() {
        let mut table = Table::new();
        table.set_content_arrangement(ContentArrangement::Dynamic);
        table.set_header(vec![
            "Classification",
            "Resource",
            "Namespace",
            "Name",
            "UID",
            "Evidence",
            "Chain",
            "Scope",
        ]);
        for row in &rows {
            table.add_row(vec![
                &row.classification,
                &row.resource,
                &row.namespace,
                &row.name,
                &row.uid,
                &row.evidence,
                &row.chain,
                &row.scope,
            ]);
        }
        out.push_str(&table.to_string());
        out.push('\n');
    }

    // Incomplete scopes
    if !audit.incomplete_scopes.is_empty() {
        out.push_str(&format!(
            "\nINCOMPLETE SCOPES ({})\n",
            audit.incomplete_scopes.len()
        ));
        for inc in &audit.incomplete_scopes {
            out.push_str(&format!(
                "  {}/{}: {}\n",
                inc.resource_type, inc.namespace, inc.error
            ));
        }
    }

    out
}

/// Print tree view to stderr (thin wrapper, TTY-aware ANSI).
pub fn print_residual_audit(audit: &ResidualAudit, journal: &RunJournal) {
    use std::io::IsTerminal;
    let ansi = std::io::stderr().is_terminal();
    eprint!("{}", render_residual_audit_tree(audit, journal, ansi));
}

/// Print table view to stderr (thin wrapper, TTY-aware ANSI).
pub fn format_residual_audit_table(audit: &ResidualAudit, journal: &RunJournal) {
    use std::io::IsTerminal;
    let ansi = std::io::stderr().is_terminal();
    eprint!("{}", render_residual_audit_table(audit, journal, ansi));
}

#[allow(dead_code)]
fn ns_suffix(resource: &ResourceId) -> String {
    resource
        .namespace
        .as_ref()
        .map(|ns| format!(" ({})", ns))
        .unwrap_or_default()
}

fn format_evidence(evidence: &ResidualEvidence) -> String {
    let mut parts = Vec::new();
    if evidence.owner_ref_match {
        parts.push("ownerRef matches operator identity".to_string());
    }
    if !evidence.matching_managers.is_empty() {
        parts.push(format!(
            "managedFields manager: {}",
            evidence.matching_managers.join(", ")
        ));
    }
    if !evidence.matching_labels.is_empty() {
        let label_strs: Vec<String> = evidence
            .matching_labels
            .iter()
            .map(|(k, v)| format!("{}={}", k, v))
            .collect();
        parts.push(format!("matching labels: {}", label_strs.join(", ")));
    }
    if evidence.service_account_match {
        parts.push("service account match".to_string());
    }
    parts.join(", ")
}

pub fn residual_status_from_audit(audit: &ResidualAudit) -> ResidualStatus {
    if !audit.scan_errors.is_empty() {
        return ResidualStatus::AuditIncomplete;
    }

    // UID-unknown probes are coverage failures — cannot verify identity
    let has_uid_unknown = audit
        .planned_delete_still_present
        .iter()
        .chain(audit.planned_expect_still_present.iter())
        .any(|item| item.recreation == RecreationState::Unknown);
    if has_uid_unknown {
        return ResidualStatus::AuditIncomplete;
    }

    let total = audit.planned_delete_still_present.len()
        + audit.planned_expect_still_present.len()
        + audit.likely_operator_residual.len()
        + audit.unattributed.len();

    if total == 0 {
        ResidualStatus::NoneObservedInScope
    } else {
        ResidualStatus::ResidualsObserved { count: total }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use kube::api::ApiResource;

    fn make_rid(
        group: &str,
        kind: &str,
        ns: Option<&str>,
        name: &str,
        uid: Option<&str>,
    ) -> ResourceId {
        ResourceId {
            group: group.to_string(),
            version: "v1".to_string(),
            kind: kind.to_string(),
            namespace: ns.map(String::from),
            name: name.to_string(),
            uid: uid.map(String::from),
        }
    }

    // ── RecreationState tests ──

    #[test]
    fn test_recreation_uid_match_is_same_resource() {
        let rid = make_rid("apps", "Deployment", Some("ns"), "foo", Some("uid-aaa"));
        let live = Some("uid-aaa".to_string());
        assert_eq!(check_recreation(&rid, &live), RecreationState::SameResource);
    }

    #[test]
    fn test_recreation_uid_mismatch_is_recreated() {
        let rid = make_rid("apps", "Deployment", Some("ns"), "foo", Some("uid-aaa"));
        let live = Some("uid-bbb".to_string());
        assert_eq!(check_recreation(&rid, &live), RecreationState::Recreated);
    }

    #[test]
    fn test_recreation_plan_uid_missing_is_unknown() {
        let rid = make_rid("apps", "Deployment", Some("ns"), "foo", None);
        let live = Some("uid-aaa".to_string());
        assert_eq!(check_recreation(&rid, &live), RecreationState::Unknown);
    }

    #[test]
    fn test_recreation_live_uid_missing_is_unknown() {
        let rid = make_rid("apps", "Deployment", Some("ns"), "foo", Some("uid-aaa"));
        let live: Option<String> = None;
        assert_eq!(check_recreation(&rid, &live), RecreationState::Unknown);
    }

    #[test]
    fn test_recreation_both_uid_missing_is_unknown() {
        let rid = make_rid("apps", "Deployment", Some("ns"), "foo", None);
        let live: Option<String> = None;
        assert_eq!(check_recreation(&rid, &live), RecreationState::Unknown);
    }

    // ── residual_status_from_audit tests ──

    #[test]
    fn test_residual_status_scan_error_is_incomplete() {
        let mut audit = empty_audit();
        audit.scan_errors.push(AuditScanError {
            resource_type: "Route".to_string(),
            namespace: "ns".to_string(),
            error: "403 Forbidden".to_string(),
            missing_owner_ref: None,
            ..Default::default()
        });
        assert!(matches!(
            residual_status_from_audit(&audit),
            ResidualStatus::AuditIncomplete
        ));
    }

    #[test]
    fn test_residual_status_uid_unknown_is_incomplete() {
        let mut audit = empty_audit();
        audit.planned_delete_still_present.push(ResidualItem {
            resource: make_rid("apps", "Deployment", Some("ns"), "foo", Some("uid-a")),
            planned_action: "DELETE".to_string(),
            live_uid: None,
            recreation: RecreationState::Unknown,
        });
        assert!(matches!(
            residual_status_from_audit(&audit),
            ResidualStatus::AuditIncomplete
        ));
    }

    #[test]
    fn test_residual_status_no_residuals_is_none_observed() {
        let audit = empty_audit();
        assert!(matches!(
            residual_status_from_audit(&audit),
            ResidualStatus::NoneObservedInScope
        ));
    }

    #[test]
    fn test_residual_status_with_residuals_is_observed() {
        let mut audit = empty_audit();
        audit.unattributed.push(AttributedResidual {
            resource: make_rid("", "Service", Some("ns"), "svc", None),
            evidence: empty_evidence(),
            confidence: ResidualConfidence::None,
        });
        match residual_status_from_audit(&audit) {
            ResidualStatus::ResidualsObserved { count } => assert_eq!(count, 1),
            other => panic!("expected ResidualsObserved, got {:?}", other),
        }
    }

    // ── compute_confidence tests ──

    #[test]
    fn test_confidence_owner_ref_is_high() {
        let evidence = ResidualEvidence {
            owner_ref_match: true,
            matching_labels: vec![],
            matching_managers: vec![],
            namespace_affinity: true,
            service_account_match: false,
        };
        assert_eq!(compute_confidence(&evidence), ResidualConfidence::High);
    }

    #[test]
    fn test_confidence_sa_and_manager_is_high() {
        let evidence = ResidualEvidence {
            owner_ref_match: false,
            matching_labels: vec![],
            matching_managers: vec!["controller".to_string()],
            namespace_affinity: true,
            service_account_match: true,
        };
        assert_eq!(compute_confidence(&evidence), ResidualConfidence::High);
    }

    #[test]
    fn test_confidence_manager_and_label_is_medium() {
        let evidence = ResidualEvidence {
            owner_ref_match: false,
            matching_labels: vec![("app".to_string(), "test".to_string())],
            matching_managers: vec!["controller".to_string()],
            namespace_affinity: true,
            service_account_match: false,
        };
        assert_eq!(compute_confidence(&evidence), ResidualConfidence::Medium);
    }

    #[test]
    fn test_confidence_manager_only_is_low() {
        let evidence = ResidualEvidence {
            owner_ref_match: false,
            matching_labels: vec![],
            matching_managers: vec!["controller".to_string()],
            namespace_affinity: true,
            service_account_match: false,
        };
        assert_eq!(compute_confidence(&evidence), ResidualConfidence::Low);
    }

    #[test]
    fn test_confidence_label_only_is_low() {
        let evidence = ResidualEvidence {
            owner_ref_match: false,
            matching_labels: vec![("app".to_string(), "test".to_string())],
            matching_managers: vec![],
            namespace_affinity: true,
            service_account_match: false,
        };
        assert_eq!(compute_confidence(&evidence), ResidualConfidence::Low);
    }

    #[test]
    fn test_confidence_namespace_only_is_none() {
        let evidence = ResidualEvidence {
            owner_ref_match: false,
            matching_labels: vec![],
            matching_managers: vec![],
            namespace_affinity: true,
            service_account_match: false,
        };
        assert_eq!(compute_confidence(&evidence), ResidualConfidence::None);
    }

    #[test]
    fn test_confidence_no_evidence_is_none() {
        let evidence = empty_evidence();
        assert_eq!(compute_confidence(&evidence), ResidualConfidence::None);
    }

    // ── known_plural_for_gvk tests ──

    #[test]
    fn test_known_plural_apps_deployment() {
        assert_eq!(
            known_plural_for_gvk("apps", "Deployment"),
            Some("deployments")
        );
    }

    #[test]
    fn test_known_plural_group_mismatch_returns_none() {
        // A custom "Deployment" Kind in a different API group must NOT resolve to "deployments"
        assert_eq!(known_plural_for_gvk("foo.io", "Deployment"), None);
    }

    #[test]
    fn test_known_plural_olm_subscription() {
        assert_eq!(
            known_plural_for_gvk("operators.coreos.com", "Subscription"),
            Some("subscriptions")
        );
    }

    #[test]
    fn test_known_plural_unknown_kind() {
        assert_eq!(known_plural_for_gvk("custom.io", "Widget"), None);
    }

    // ── plan_resources group exclusion tests ──

    #[test]
    fn test_plan_resources_excludes_same_group() {
        let mut plan_resources: HashSet<(String, String, Option<String>, String)> = HashSet::new();
        plan_resources.insert((
            "apps".into(),
            "Deployment".into(),
            Some("ns".into()),
            "foo".into(),
        ));

        // Same group+kind+ns+name → excluded
        let key = (
            "apps".to_string(),
            "Deployment".to_string(),
            Some("ns".to_string()),
            "foo".to_string(),
        );
        assert!(plan_resources.contains(&key));
    }

    #[test]
    fn test_plan_resources_does_not_exclude_different_group() {
        let mut plan_resources: HashSet<(String, String, Option<String>, String)> = HashSet::new();
        plan_resources.insert((
            "apps".into(),
            "Deployment".into(),
            Some("ns".into()),
            "foo".into(),
        ));

        // Different group with same Kind/name → NOT excluded
        let key = (
            "custom.io".to_string(),
            "Deployment".to_string(),
            Some("ns".to_string()),
            "foo".to_string(),
        );
        assert!(!plan_resources.contains(&key));
    }

    // ── Schema migration / RecreationState default tests ──

    #[test]
    fn test_recreation_state_default_is_unknown() {
        assert_eq!(RecreationState::default_unknown(), RecreationState::Unknown);
    }

    #[test]
    fn test_residual_item_deserialize_without_recreation_defaults_to_unknown() {
        let json = r#"{
            "resource": {"group":"apps","version":"v1","kind":"Deployment","namespace":"ns","name":"foo","uid":"abc"},
            "planned_action": "DELETE"
        }"#;
        let item: ResidualItem = serde_json::from_str(json).unwrap();
        assert_eq!(item.recreation, RecreationState::Unknown);
        assert!(item.live_uid.is_none());
    }

    // ── Helpers ──

    fn empty_audit() -> ResidualAudit {
        ResidualAudit {
            planned_delete_still_present: Vec::new(),
            planned_expect_still_present: Vec::new(),
            expected_preserved: Vec::new(),
            likely_operator_residual: Vec::new(),
            unattributed: Vec::new(),
            coverage: AuditCoverage {
                requested_probes: 0,
                succeeded_probes: 0,
            },
            scan_errors: Vec::new(),
            target_operators_absent: false,
            residual_workloads: Vec::new(),
            incomplete_scopes: Vec::new(),
        }
    }

    fn make_dynamic_object(name: &str) -> kube::api::DynamicObject {
        let mut obj = kube::api::DynamicObject {
            types: None,
            metadata: Default::default(),
            data: serde_json::json!({}),
        };
        obj.metadata.name = Some(name.to_string());
        obj
    }

    fn empty_evidence() -> ResidualEvidence {
        ResidualEvidence {
            owner_ref_match: false,
            matching_labels: vec![],
            matching_managers: vec![],
            namespace_affinity: false,
            service_account_match: false,
        }
    }

    fn make_native_workload(
        ns: &str,
        kind: &str,
        name: &str,
        uid: &str,
    ) -> ((String, String, String), DynamicObject) {
        let group = match kind {
            "Job" | "CronJob" => "batch",
            _ => "apps",
        };
        let api_version = if group.is_empty() {
            "v1".to_string()
        } else {
            format!("{}/v1", group)
        };
        let mut obj = DynamicObject {
            types: Some(kube::api::TypeMeta {
                api_version,
                kind: kind.to_string(),
            }),
            metadata: Default::default(),
            data: serde_json::json!({}),
        };
        obj.metadata.name = Some(name.to_string());
        obj.metadata.namespace = Some(ns.to_string());
        obj.metadata.uid = Some(uid.to_string());
        ((ns.to_string(), kind.to_string(), name.to_string()), obj)
    }

    #[test]
    fn test_v2_residual_evidence_deserialize_without_owner_ref_match() {
        // v2 journals have ResidualEvidence without owner_ref_match.
        // serde(default) must allow deserialization so migration can proceed.
        let json = r#"{
            "matching_labels": [["app", "test"]],
            "matching_managers": ["controller"],
            "namespace_affinity": true,
            "service_account_match": false
        }"#;
        let evidence: ResidualEvidence = serde_json::from_str(json).unwrap();
        assert!(!evidence.owner_ref_match);
        assert!(evidence.namespace_affinity);
        assert_eq!(evidence.matching_labels.len(), 1);
    }

    #[test]
    fn test_v2_attributed_residual_deserialize() {
        // Full AttributedResidual from a v2 journal (no owner_ref_match in evidence)
        let json = r#"{
            "resource": {
                "group": "apps", "version": "v1", "kind": "Deployment",
                "namespace": "test-ns", "name": "test-dep", "uid": "uid-123"
            },
            "evidence": {
                "matching_labels": [],
                "matching_managers": ["mgr"],
                "namespace_affinity": false,
                "service_account_match": false
            },
            "confidence": "Low"
        }"#;
        let residual: AttributedResidual = serde_json::from_str(json).unwrap();
        assert!(!residual.evidence.owner_ref_match);
        assert_eq!(residual.confidence, ResidualConfidence::Low);
    }

    #[test]
    fn test_v2_residual_audit_deserialize() {
        // A complete ResidualAudit from v2 (no owner_ref_match, no recreation, no live_uid)
        let json = r#"{
            "planned_delete_still_present": [{
                "resource": {
                    "group": "", "version": "v1", "kind": "Service",
                    "namespace": "ns", "name": "svc", "uid": "uid-1"
                },
                "planned_action": "DELETE"
            }],
            "planned_expect_still_present": [],
            "expected_preserved": [],
            "likely_operator_residual": [{
                "resource": {
                    "group": "apps", "version": "v1", "kind": "Deployment",
                    "namespace": "ns", "name": "dep", "uid": "uid-2"
                },
                "evidence": {
                    "matching_labels": [],
                    "matching_managers": [],
                    "namespace_affinity": true,
                    "service_account_match": false
                },
                "confidence": "None"
            }],
            "unattributed": [],
            "coverage": { "requested_probes": 10, "succeeded_probes": 10 },
            "scan_errors": []
        }"#;
        let audit: ResidualAudit = serde_json::from_str(json).unwrap();
        // ResidualItem defaults: recreation=Unknown, live_uid=None
        assert_eq!(
            audit.planned_delete_still_present[0].recreation,
            RecreationState::Unknown
        );
        assert!(audit.planned_delete_still_present[0].live_uid.is_none());
        // ResidualEvidence defaults: owner_ref_match=false
        assert!(!audit.likely_operator_residual[0].evidence.owner_ref_match);
    }

    #[test]
    fn test_residual_status_unresolved_gvks_none_is_incomplete() {
        // If unresolved_gvks is None (old journal), audit scan pushes a
        // scan_error for plan GVK resolution → AuditIncomplete
        let audit = ResidualAudit {
            planned_delete_still_present: vec![],
            planned_expect_still_present: vec![],
            expected_preserved: vec![],
            likely_operator_residual: vec![],
            unattributed: vec![],
            coverage: AuditCoverage {
                requested_probes: 5,
                succeeded_probes: 5,
            },
            scan_errors: vec![AuditScanError {
                resource_type: "(plan GVK resolution)".to_string(),
                namespace: "(all)".to_string(),
                error: "Journal lacks plan GVK resolution metadata.".to_string(),
                missing_owner_ref: None,
                ..Default::default()
            }],
            target_operators_absent: false,
            residual_workloads: Vec::new(),
            incomplete_scopes: Vec::new(),
        };
        let status = residual_status_from_audit(&audit);
        assert!(matches!(status, ResidualStatus::AuditIncomplete));
    }

    #[test]
    fn test_plan_resources_different_group_not_excluded() {
        // Verify that resources from different API groups with same Kind/name
        // are NOT excluded from scan results
        let plan_resources: HashSet<(String, String, Option<String>, String)> = [(
            "apps".to_string(),
            "Deployment".to_string(),
            Some("ns".to_string()),
            "my-dep".to_string(),
        )]
        .into_iter()
        .collect();

        // Same kind/name but different group should NOT be excluded
        let key = (
            "custom.io".to_string(),
            "Deployment".to_string(),
            Some("ns".to_string()),
            "my-dep".to_string(),
        );
        assert!(!plan_resources.contains(&key));

        // Same group/kind/name SHOULD be excluded
        let key2 = (
            "apps".to_string(),
            "Deployment".to_string(),
            Some("ns".to_string()),
            "my-dep".to_string(),
        );
        assert!(plan_resources.contains(&key2));
    }

    #[test]
    fn test_classify_list_results_uid_none_creates_error_no_residual() {
        use crate::teardown::journal::AuditContext;
        let mut audit = empty_audit();
        let ctx = AuditContext::default();
        let target_uids = HashSet::new();
        let plan_resources = HashSet::new();

        let mut obj = DynamicObject::new(
            "no-uid-obj",
            &ApiResource::erase::<k8s_openapi::api::core::v1::Service>(&()),
        );
        obj.metadata.namespace = Some("ns".to_string());
        obj.metadata.uid = None;

        classify_list_results(
            vec![obj],
            "Service",
            "",
            "v1",
            "ns",
            &ctx,
            &target_uids,
            &plan_resources,
            &mut audit,
        );
        assert_eq!(audit.scan_errors.len(), 1);
        assert!(audit.scan_errors[0].error.contains("UID"));
        assert_eq!(
            audit.unattributed.len(),
            0,
            "None UID must not create residual"
        );
        assert_eq!(audit.likely_operator_residual.len(), 0);
    }

    #[test]
    fn test_classify_list_results_uid_empty_creates_error_no_residual() {
        use crate::teardown::journal::AuditContext;
        let mut audit = empty_audit();
        let ctx = AuditContext::default();
        let target_uids = HashSet::new();
        let plan_resources = HashSet::new();

        let mut obj = DynamicObject::new(
            "empty-uid-obj",
            &ApiResource::erase::<k8s_openapi::api::core::v1::Service>(&()),
        );
        obj.metadata.namespace = Some("ns".to_string());
        obj.metadata.uid = Some(String::new());

        classify_list_results(
            vec![obj],
            "Service",
            "",
            "v1",
            "ns",
            &ctx,
            &target_uids,
            &plan_resources,
            &mut audit,
        );
        assert_eq!(audit.scan_errors.len(), 1);
        assert!(
            audit.scan_errors[0].error.contains("UID")
                || audit.scan_errors[0].error.contains("empty")
        );
        assert_eq!(
            audit.unattributed.len(),
            0,
            "empty UID must not create residual"
        );
    }

    #[test]
    fn test_classify_list_results_valid_uid_creates_residual() {
        use crate::teardown::journal::AuditContext;
        let mut audit = empty_audit();
        let ctx = AuditContext::default();
        let target_uids = HashSet::new();
        let plan_resources = HashSet::new();

        let mut obj = DynamicObject::new(
            "valid-obj",
            &ApiResource::erase::<k8s_openapi::api::core::v1::Service>(&()),
        );
        obj.metadata.namespace = Some("ns".to_string());
        obj.metadata.uid = Some("valid-uid-123".to_string());

        classify_list_results(
            vec![obj],
            "Service",
            "",
            "v1",
            "ns",
            &ctx,
            &target_uids,
            &plan_resources,
            &mut audit,
        );
        assert!(audit.scan_errors.is_empty());
        // No target evidence → scope-out (not unattributed)
        assert_eq!(audit.unattributed.len(), 0);
    }

    #[test]
    fn test_residual_status_crd_pruned_is_incomplete() {
        // GoneByCrdRemoval should produce AuditIncomplete via scan_error,
        // not a false probe-success
        let audit = ResidualAudit {
            planned_delete_still_present: vec![],
            planned_expect_still_present: vec![],
            expected_preserved: vec![],
            likely_operator_residual: vec![],
            unattributed: vec![],
            coverage: AuditCoverage {
                requested_probes: 5,
                succeeded_probes: 5,
            },
            scan_errors: vec![AuditScanError {
                resource_type: "Foo (CRD pruned)".to_string(),
                namespace: "(all)".to_string(),
                error: "CRD pruned, UID verification not implemented".to_string(),
                missing_owner_ref: None,
                ..Default::default()
            }],
            target_operators_absent: false,
            residual_workloads: Vec::new(),
            incomplete_scopes: Vec::new(),
        };

        let status = residual_status_from_audit(&audit);
        assert!(
            matches!(status, ResidualStatus::AuditIncomplete),
            "CRD pruned scan_error should make audit incomplete"
        );
    }

    #[test]
    fn test_target_uids_includes_plan_delete_resources() {
        // target_uids should include UIDs from plan DELETE/EXPECT actions
        // so ownerRef descendants of approved root CRs are classified HIGH
        use crate::kube::resource::ResourceId;
        use crate::teardown::planner::{Action, PlanPhase, Preflight, TeardownPlan};

        let plan = TeardownPlan {
            targets: vec![],
            preflight: Preflight { checks: vec![] },
            phases: vec![PlanPhase {
                name: "test".to_string(),
                description: "test".to_string(),
                actions: vec![
                    Action::Delete {
                        resource: ResourceId {
                            group: "example.com".to_string(),
                            version: "v1".to_string(),
                            kind: "Foo".to_string(),
                            namespace: Some("ns".to_string()),
                            name: "root-cr".to_string(),
                            uid: Some("root-uid-123".to_string()),
                        },
                        reason: "test".to_string(),
                    },
                    Action::ExpectGone {
                        resource: ResourceId {
                            group: "example.com".to_string(),
                            version: "v1".to_string(),
                            kind: "Bar".to_string(),
                            namespace: Some("ns".to_string()),
                            name: "descendant".to_string(),
                            uid: Some("desc-uid-456".to_string()),
                        },
                        reason: "test".to_string(),
                    },
                    Action::Keep {
                        resource: ResourceId {
                            group: "".to_string(),
                            version: "v1".to_string(),
                            kind: "Namespace".to_string(),
                            namespace: None,
                            name: "ns".to_string(),
                            uid: Some("keep-uid-789".to_string()),
                        },
                        reason: "test".to_string(),
                    },
                ],
                barrier: None,
            }],
            blockers: vec![],
            warnings: vec![],
            snapshot_taken_at: "test".to_string(),
            dependency_edges: vec![],
            operator_inventory: vec![],
            explicit_decisions: vec![],
            explicit_deletes: vec![],
        };

        let mut target_uids: HashSet<String> = HashSet::new();
        // Simulate what run_residual_audit does
        for phase in &plan.phases {
            for action in &phase.actions {
                match action {
                    Action::Delete { resource, .. } | Action::ExpectGone { resource, .. } => {
                        if let Some(uid) = &resource.uid {
                            target_uids.insert(uid.clone());
                        }
                    }
                    _ => {}
                }
            }
        }

        assert!(target_uids.contains("root-uid-123"));
        assert!(target_uids.contains("desc-uid-456"));
        // KEEP actions should NOT be in target_uids
        assert!(!target_uids.contains("keep-uid-789"));
    }

    #[test]
    fn test_ownerref_to_plan_root_cr_is_high() {
        // An object whose ownerRef points to a plan DELETE resource's UID
        // should be classified HIGH (not UNATTRIBUTED)
        let mut target_uids = HashSet::new();
        target_uids.insert("root-cr-uid-123".to_string());

        let evidence = ResidualEvidence {
            owner_ref_match: true, // matches root-cr-uid-123
            matching_labels: vec![],
            matching_managers: vec![],
            namespace_affinity: false,
            service_account_match: false,
        };

        let confidence = compute_confidence(&evidence);
        assert_eq!(confidence, ResidualConfidence::High);
    }

    // ── CSV label attribution tests ──

    #[test]
    fn test_csv_label_other_package() {
        let mut labels = std::collections::BTreeMap::new();
        labels.insert(
            "operators.coreos.com/other-operator.my-ns".to_string(),
            String::new(),
        );
        assert!(csv_label_attributes_to_other_package(
            &labels,
            "my-ns",
            "rhods-operator"
        ));
    }

    #[test]
    fn test_csv_label_same_package_not_other() {
        let mut labels = std::collections::BTreeMap::new();
        labels.insert(
            "operators.coreos.com/rhods-operator.my-ns".to_string(),
            String::new(),
        );
        // Same package → should NOT be attributed to "other"
        assert!(!csv_label_attributes_to_other_package(
            &labels,
            "my-ns",
            "rhods-operator"
        ));
    }

    #[test]
    fn test_csv_label_no_olm_label() {
        let mut labels = std::collections::BTreeMap::new();
        labels.insert("app".to_string(), "test".to_string());
        // No OLM label → not attributed
        assert!(!csv_label_attributes_to_other_package(
            &labels,
            "my-ns",
            "rhods-operator"
        ));
    }

    #[test]
    fn test_csv_label_wrong_namespace_suffix() {
        let mut labels = std::collections::BTreeMap::new();
        labels.insert(
            "operators.coreos.com/other-op.different-ns".to_string(),
            String::new(),
        );
        // Namespace doesn't match → not attributed (label is for a different namespace)
        assert!(!csv_label_attributes_to_other_package(
            &labels,
            "my-ns",
            "rhods-operator"
        ));
    }

    #[test]
    fn test_csv_label_empty_package() {
        let mut labels = std::collections::BTreeMap::new();
        // Edge case: label key = "operators.coreos.com/.my-ns" → empty package
        labels.insert("operators.coreos.com/.my-ns".to_string(), String::new());
        assert!(!csv_label_attributes_to_other_package(
            &labels,
            "my-ns",
            "rhods-operator"
        ));
    }

    #[test]
    fn test_conflicting_csv_labels_is_ambiguous() {
        // CSV has labels for BOTH our package and another package → ambiguous
        let mut labels = std::collections::BTreeMap::new();
        labels.insert(
            "operators.coreos.com/rhods-operator.redhat-ods-operator".to_string(),
            String::new(),
        );
        labels.insert(
            "operators.coreos.com/other-operator.redhat-ods-operator".to_string(),
            String::new(),
        );
        // Conflicting → NOT attributable to other → should return false
        assert!(!csv_label_attributes_to_other_package(
            &labels,
            "redhat-ods-operator",
            "rhods-operator"
        ));
    }

    #[test]
    fn test_csv_copy_olm_package_annotation_other_package() {
        let mut csv = make_dynamic_object("authorino-operator.v1.0.2");
        csv.metadata.annotations = Some(std::collections::BTreeMap::from([(
            "operatorframework.io/properties".to_string(),
            r#"[{"type":"olm.package","value":"{\"packageName\":\"authorino-operator\",\"version\":\"1.0.2\"}"}]"#.to_string(),
        )]));

        let pkgs = csv_packages_from_annotations(&csv);
        assert_eq!(pkgs, vec!["authorino-operator"]);
    }

    #[test]
    fn test_csv_copy_olm_package_annotation_same_package() {
        let mut csv = make_dynamic_object("rhods-operator.3.5.0");
        csv.metadata.annotations = Some(std::collections::BTreeMap::from([(
            "operatorframework.io/properties".to_string(),
            r#"[{"type":"olm.package","value":"{\"packageName\":\"rhods-operator\",\"version\":\"3.5.0\"}"}]"#.to_string(),
        )]));

        let pkgs = csv_packages_from_annotations(&csv);
        assert_eq!(pkgs, vec!["rhods-operator"]);
    }

    #[test]
    fn test_csv_copy_olm_package_annotation_object_format() {
        // Real OLM format on some clusters: {"properties":[...]} instead of [...]
        let mut csv = make_dynamic_object("authorino-operator.v1.0.2");
        csv.metadata.annotations = Some(std::collections::BTreeMap::from([(
            "operatorframework.io/properties".to_string(),
            r#"{"properties":[{"type":"olm.package","value":"{\"packageName\":\"authorino-operator\",\"version\":\"1.0.2\"}"}]}"#.to_string(),
        )]));

        let pkgs = csv_packages_from_annotations(&csv);
        assert_eq!(pkgs, vec!["authorino-operator"]);
    }

    #[test]
    fn test_csv_copy_olm_package_annotation_multiple_packages() {
        // CSV with two different olm.package entries → evidence_packages gets both
        let mut csv = make_dynamic_object("conflict-csv.v1.0");
        csv.metadata.annotations = Some(std::collections::BTreeMap::from([(
            "operatorframework.io/properties".to_string(),
            r#"[
                {"type":"olm.package","value":"{\"packageName\":\"pkg-a\",\"version\":\"1.0\"}"},
                {"type":"olm.package","value":"{\"packageName\":\"pkg-b\",\"version\":\"2.0\"}"}
            ]"#
            .to_string(),
        )]));

        let pkgs = csv_packages_from_annotations(&csv);
        assert_eq!(pkgs.len(), 2);
        assert!(pkgs.contains(&"pkg-a".to_string()));
        assert!(pkgs.contains(&"pkg-b".to_string()));
    }

    #[test]
    fn test_csv_copy_no_labels_or_annotations() {
        let csv = make_dynamic_object("mystery-csv.v1.0");
        // No labels, no annotations
        let pkgs = csv_packages_from_annotations(&csv);
        assert!(pkgs.is_empty());
        // No labels → csv_label_attributes_to_other_package returns false
        assert!(!csv_label_attributes_to_other_package(
            &std::collections::BTreeMap::new(),
            "ns",
            "our-pkg"
        ));
    }

    #[test]
    fn test_explain_action_label() {
        // Verify the action_resource and action label mapping logic.
        // The actual explain output is tested via the function, but here we
        // verify the match arms produce correct labels.
        let review_action = Action::Review {
            resource: ResourceId {
                group: String::new(),
                version: "v1".to_string(),
                kind: "Limitador".to_string(),
                namespace: Some("ns".to_string()),
                name: "limitador".to_string(),
                uid: None,
            },
            reason: "test".to_string(),
            metadata: None,
        };
        // In explain.rs, REVIEW → "marked for review", not "deleted"
        let label = match &review_action {
            Action::Delete { .. } => "deleted",
            Action::ExpectGone { .. } => "expected to be removed by controller",
            Action::Keep { .. } => "kept",
            Action::Review { .. } => "marked for review",
            Action::WaitGone { .. } => "waiting for deletion",
        };
        assert_eq!(label, "marked for review");
    }

    // ── csv_package_evidence_is_exclusive tests (olm.rs safety predicate) ──

    #[test]
    fn test_evidence_exclusive_label_only_target() {
        let mut csv = make_dynamic_object("csv.v1");
        let mut labels = std::collections::BTreeMap::new();
        labels.insert("operators.coreos.com/pkg-a.ns".to_string(), String::new());
        csv.metadata.labels = Some(labels);
        csv.metadata.namespace = Some("ns".to_string());
        assert!(crate::analyzers::olm::csv_package_evidence_is_exclusive(
            &csv, "pkg-a", "ns"
        ));
    }

    #[test]
    fn test_evidence_exclusive_label_other_rejects() {
        let mut csv = make_dynamic_object("csv.v1");
        let mut labels = std::collections::BTreeMap::new();
        labels.insert("operators.coreos.com/pkg-b.ns".to_string(), String::new());
        csv.metadata.labels = Some(labels);
        csv.metadata.namespace = Some("ns".to_string());
        assert!(!crate::analyzers::olm::csv_package_evidence_is_exclusive(
            &csv, "pkg-a", "ns"
        ));
    }

    #[test]
    fn test_evidence_exclusive_conflicting_labels_rejects() {
        let mut csv = make_dynamic_object("csv.v1");
        let mut labels = std::collections::BTreeMap::new();
        labels.insert("operators.coreos.com/pkg-a.ns".to_string(), String::new());
        labels.insert("operators.coreos.com/pkg-b.ns".to_string(), String::new());
        csv.metadata.labels = Some(labels);
        csv.metadata.namespace = Some("ns".to_string());
        // Two packages → not exclusive for either
        assert!(!crate::analyzers::olm::csv_package_evidence_is_exclusive(
            &csv, "pkg-a", "ns"
        ));
    }

    #[test]
    fn test_evidence_exclusive_annotation_contradicts_label() {
        let mut csv = make_dynamic_object("csv.v1");
        let mut labels = std::collections::BTreeMap::new();
        labels.insert("operators.coreos.com/pkg-a.ns".to_string(), String::new());
        csv.metadata.labels = Some(labels);
        csv.metadata.annotations = Some(std::collections::BTreeMap::from([(
            "operatorframework.io/properties".to_string(),
            r#"[{"type":"olm.package","value":"{\"packageName\":\"pkg-b\",\"version\":\"1.0\"}"}]"#
                .to_string(),
        )]));
        csv.metadata.namespace = Some("ns".to_string());
        // label=pkg-a, annotation=pkg-b → conflicting → not exclusive
        assert!(!crate::analyzers::olm::csv_package_evidence_is_exclusive(
            &csv, "pkg-a", "ns"
        ));
    }

    #[test]
    fn test_evidence_exclusive_no_labels_annotation_other_rejects() {
        let mut csv = make_dynamic_object("csv.v1");
        csv.metadata.labels = None;
        csv.metadata.annotations = Some(std::collections::BTreeMap::from([(
            "operatorframework.io/properties".to_string(),
            r#"[{"type":"olm.package","value":"{\"packageName\":\"other-pkg\",\"version\":\"1.0\"}"}]"#
                .to_string(),
        )]));
        csv.metadata.namespace = Some("ns".to_string());
        assert!(!crate::analyzers::olm::csv_package_evidence_is_exclusive(
            &csv, "my-pkg", "ns"
        ));
    }

    #[test]
    fn test_evidence_exclusive_no_evidence_trusts_status() {
        let csv = make_dynamic_object("csv.v1");
        assert!(crate::analyzers::olm::csv_package_evidence_is_exclusive(
            &csv, "any", "ns"
        ));
    }

    #[test]
    fn test_evidence_exclusive_annotation_confirms_target() {
        let mut csv = make_dynamic_object("csv.v1");
        csv.metadata.labels = None;
        csv.metadata.annotations = Some(std::collections::BTreeMap::from([(
            "operatorframework.io/properties".to_string(),
            r#"[{"type":"olm.package","value":"{\"packageName\":\"my-pkg\",\"version\":\"1.0\"}"}]"#
                .to_string(),
        )]));
        csv.metadata.namespace = Some("ns".to_string());
        assert!(crate::analyzers::olm::csv_package_evidence_is_exclusive(
            &csv, "my-pkg", "ns"
        ));
    }

    // ── olm.rs linkage edge cases ──

    #[test]
    fn test_annotation_contradicts_label_different_package() {
        // CSV has label for pkg-a but annotation says pkg-b
        // → both should appear in evidence_packages
        // → if our package is pkg-a, evidence has our package → Unknown
        let mut csv = make_dynamic_object("test-csv.v1");
        let mut labels = std::collections::BTreeMap::new();
        labels.insert(
            "operators.coreos.com/pkg-a.test-ns".to_string(),
            String::new(),
        );
        csv.metadata.labels = Some(labels);
        csv.metadata.annotations = Some(std::collections::BTreeMap::from([(
            "operatorframework.io/properties".to_string(),
            r#"[{"type":"olm.package","value":"{\"packageName\":\"pkg-b\",\"version\":\"1.0\"}"}]"#
                .to_string(),
        )]));
        csv.metadata.namespace = Some("test-ns".to_string());

        // Label evidence
        let label_attrs = csv_label_attributes_to_other_package(
            csv.metadata.labels.as_ref().unwrap(),
            "test-ns",
            "pkg-a",
        );
        // label has pkg-a (our package) → not "other only"
        assert!(!label_attrs);

        // Annotation evidence
        let ann_pkgs = csv_packages_from_annotations(&csv);
        assert_eq!(ann_pkgs, vec!["pkg-b"]);

        // Combined: evidence_packages = {pkg-a, pkg-b}, has_our = true → Unknown
    }

    #[test]
    fn test_no_label_annotation_says_other_package() {
        // CSV with NO labels, annotation says different package
        // In olm.rs status linkage: labels=None → was trusting status
        // Now annotation contradiction should reject
        let mut csv = make_dynamic_object("other-csv.v1");
        csv.metadata.labels = None;
        csv.metadata.annotations = Some(std::collections::BTreeMap::from([(
            "operatorframework.io/properties".to_string(),
            r#"[{"type":"olm.package","value":"{\"packageName\":\"other-operator\",\"version\":\"1.0\"}"}]"#
                .to_string(),
        )]));

        let ann_pkgs = csv_packages_from_annotations(&csv);
        assert_eq!(ann_pkgs, vec!["other-operator"]);
        // In olm.rs, extract_annotation_packages returns ["other-operator"]
        // If Sub pkg is "my-operator", annotation_contradicts → reject status link
    }

    // ── Preflight safety predicate tests (calls real check_subscription_safety) ──

    fn make_test_operator(
        sub: Option<&str>,
        has_unlinked: bool,
    ) -> crate::analyzers::olm::OperatorInstance {
        crate::analyzers::olm::OperatorInstance {
            subscription: sub.map(|name| crate::kube::resource::ResourceId {
                group: "operators.coreos.com".to_string(),
                version: "v1alpha1".to_string(),
                kind: "Subscription".to_string(),
                namespace: Some("test-ns".to_string()),
                name: name.to_string(),
                uid: Some("uid-1".to_string()),
            }),
            package_name: Some("test-pkg".to_string()),
            csv: crate::kube::resource::ResourceId {
                group: "operators.coreos.com".to_string(),
                version: "v1alpha1".to_string(),
                kind: "ClusterServiceVersion".to_string(),
                namespace: Some("test-ns".to_string()),
                name: "test-pkg.v1.0".to_string(),
                uid: Some("csv-uid".to_string()),
            },
            csv_phase: "Succeeded".to_string(),
            owned_crds: vec![],
            required_crds: vec![],
            owned_api_service_defs: vec![],
            required_api_service_defs: vec![],
            deployments: vec![],
            service_accounts: vec![],
            install_namespace: "test-ns".to_string(),
            has_unlinked_subscriptions: has_unlinked,
        }
    }

    #[test]
    fn test_preflight_linked_sub_no_unlinked_passes() {
        let op = make_test_operator(Some("sub-a"), false);
        let (passed, severity, _) = crate::teardown::planner::check_subscription_safety(&op);
        assert!(passed);
        assert_eq!(
            severity,
            crate::teardown::planner::PreflightSeverity::Warning
        );
    }

    #[test]
    fn test_preflight_has_unlinked_with_linked_sub_is_critical() {
        // subscription=Some + has_unlinked=true → Critical (not passed)
        let op = make_test_operator(Some("sub-a"), true);
        let (passed, severity, _) = crate::teardown::planner::check_subscription_safety(&op);
        assert!(
            !passed,
            "has_unlinked_subscriptions should block even with linked Sub"
        );
        assert_eq!(
            severity,
            crate::teardown::planner::PreflightSeverity::Critical
        );
    }

    #[test]
    fn test_preflight_no_sub_no_unlinked_passes() {
        // No subscription, no unlinked → frozen/manual → OK
        let op = make_test_operator(None, false);
        let (passed, severity, _) = crate::teardown::planner::check_subscription_safety(&op);
        assert!(passed);
        assert_eq!(
            severity,
            crate::teardown::planner::PreflightSeverity::Warning
        );
    }

    #[test]
    fn test_preflight_no_sub_has_unlinked_is_critical() {
        // No linked subscription but unlinked exist → Critical
        let op = make_test_operator(None, true);
        let (passed, severity, _) = crate::teardown::planner::check_subscription_safety(&op);
        assert!(!passed);
        assert_eq!(
            severity,
            crate::teardown::planner::PreflightSeverity::Critical
        );
    }

    // ── Generation Step 4 evidence conflict tests ──

    // ── is_exclusively_other_package tests (calls real function) ──

    #[test]
    fn test_exclusively_other_one_non_target_is_safe() {
        let mut evidence = HashSet::new();
        evidence.insert("pkg-b".to_string());
        assert!(is_exclusively_other_package(&evidence, "pkg-a"));
    }

    #[test]
    fn test_exclusively_other_two_non_target_is_unknown() {
        // B+C conflicting non-target → not exclusively one other
        let mut evidence = HashSet::new();
        evidence.insert("pkg-b".to_string());
        evidence.insert("pkg-c".to_string());
        assert!(!is_exclusively_other_package(&evidence, "pkg-a"));
    }

    #[test]
    fn test_exclusively_other_target_present_is_unknown() {
        let mut evidence = HashSet::new();
        evidence.insert("pkg-a".to_string());
        evidence.insert("pkg-b".to_string());
        assert!(!is_exclusively_other_package(&evidence, "pkg-a"));
    }

    #[test]
    fn test_exclusively_other_empty_is_unknown() {
        let evidence = HashSet::new();
        assert!(!is_exclusively_other_package(&evidence, "pkg-a"));
    }

    #[test]
    fn test_exclusively_other_only_target_is_unknown() {
        let mut evidence = HashSet::new();
        evidence.insert("pkg-a".to_string());
        assert!(!is_exclusively_other_package(&evidence, "pkg-a"));
    }

    // ── Status CSV extraction fallback test ──

    #[test]
    fn test_sub_status_empty_installed_csv_falls_through_to_current() {
        // Simulates the same extraction logic as sub_csv_to_pkgs builder:
        // installedCSV="" should fall through to currentCSV="csv-x"
        let status = serde_json::json!({
            "installedCSV": "",
            "currentCSV": "csv-x"
        });

        let csv_name = status
            .get("installedCSV")
            .and_then(|v| v.as_str())
            .filter(|s| !s.is_empty())
            .or_else(|| {
                status
                    .get("currentCSV")
                    .and_then(|v| v.as_str())
                    .filter(|s| !s.is_empty())
            });

        assert_eq!(
            csv_name,
            Some("csv-x"),
            "empty installedCSV must fall through to currentCSV"
        );
    }

    #[test]
    fn test_sub_status_both_empty_is_none() {
        let status = serde_json::json!({
            "installedCSV": "",
            "currentCSV": ""
        });

        let csv_name = status
            .get("installedCSV")
            .and_then(|v| v.as_str())
            .filter(|s| !s.is_empty())
            .or_else(|| {
                status
                    .get("currentCSV")
                    .and_then(|v| v.as_str())
                    .filter(|s| !s.is_empty())
            });

        assert!(csv_name.is_none());
    }

    // ── Phase B: Pod→top-level owner normalization ──

    #[test]
    fn test_normalize_pod_to_deployment_via_replicaset() {
        let rs_name = "my-deploy-abc123";
        let deploy_name = "my-deploy";
        let rs_uid = "rs-uid-111";
        let deploy_uid = "dep-uid-222";

        let mut rs = DynamicObject::new(
            rs_name,
            &ApiResource::erase::<k8s_openapi::api::apps::v1::ReplicaSet>(&()),
        );
        rs.metadata.namespace = Some("ns".to_string());
        rs.metadata.uid = Some(rs_uid.to_string());
        rs.metadata.owner_references = Some(vec![
            k8s_openapi::apimachinery::pkg::apis::meta::v1::OwnerReference {
                api_version: "apps/v1".to_string(),
                kind: "Deployment".to_string(),
                name: deploy_name.to_string(),
                uid: deploy_uid.to_string(),
                controller: Some(true),
                block_owner_deletion: None,
            },
        ]);

        let rs_lookup: HashMap<(String, String), &DynamicObject> =
            [(("ns".to_string(), rs_name.to_string()), &rs)]
                .into_iter()
                .collect();

        let owner = k8s_openapi::apimachinery::pkg::apis::meta::v1::OwnerReference {
            api_version: "apps/v1".to_string(),
            kind: "ReplicaSet".to_string(),
            name: rs_name.to_string(),
            uid: rs_uid.to_string(),
            controller: Some(true),
            block_owner_deletion: None,
        };

        let native = HashMap::from([make_native_workload(
            "ns",
            "Deployment",
            deploy_name,
            deploy_uid,
        )]);
        let result = normalize_pod_owner(&owner, "ns", &rs_lookup, &native);
        assert!(result.is_ok(), "should succeed: {:?}", result);
        let (kind, group, _version, name, uid, chain) = result.unwrap();
        assert_eq!(kind, "Deployment");
        assert_eq!(group, "apps");
        assert_eq!(name, deploy_name);
        assert_eq!(uid, deploy_uid);
        assert_eq!(chain.len(), 2);
        assert_eq!(chain[0].kind, "ReplicaSet");
        assert_eq!(chain[1].kind, "Deployment");
    }

    #[test]
    fn test_normalize_pod_to_statefulset() {
        let owner = k8s_openapi::apimachinery::pkg::apis::meta::v1::OwnerReference {
            api_version: "apps/v1".to_string(),
            kind: "StatefulSet".to_string(),
            name: "postgres".to_string(),
            uid: "sts-uid-333".to_string(),
            controller: Some(true),
            block_owner_deletion: None,
        };
        let rs_lookup: HashMap<(String, String), &DynamicObject> = HashMap::new();

        let native = HashMap::from([make_native_workload(
            "ns",
            "StatefulSet",
            "postgres",
            "sts-uid-333",
        )]);
        let result = normalize_pod_owner(&owner, "ns", &rs_lookup, &native);
        assert!(result.is_ok());
        let (kind, group, _, name, uid, chain) = result.unwrap();
        assert_eq!(kind, "StatefulSet");
        assert_eq!(group, "apps");
        assert_eq!(name, "postgres");
        assert_eq!(uid, "sts-uid-333");
        assert_eq!(chain.len(), 1);
    }

    #[test]
    fn test_normalize_stale_rs_uid_fail_closed() {
        let rs_name = "my-deploy-abc";
        let mut rs = DynamicObject::new(
            rs_name,
            &ApiResource::erase::<k8s_openapi::api::apps::v1::ReplicaSet>(&()),
        );
        rs.metadata.namespace = Some("ns".to_string());
        rs.metadata.uid = Some("actual-rs-uid".to_string());

        let rs_lookup: HashMap<(String, String), &DynamicObject> =
            [(("ns".to_string(), rs_name.to_string()), &rs)]
                .into_iter()
                .collect();

        let owner = k8s_openapi::apimachinery::pkg::apis::meta::v1::OwnerReference {
            api_version: "apps/v1".to_string(),
            kind: "ReplicaSet".to_string(),
            name: rs_name.to_string(),
            uid: "stale-wrong-uid".to_string(),
            controller: Some(true),
            block_owner_deletion: None,
        };

        let result = normalize_pod_owner(&owner, "ns", &rs_lookup, &HashMap::new());
        assert!(result.is_err(), "stale UID must fail closed");
        assert!(
            result.unwrap_err().contains("stale identity"),
            "error should mention stale identity"
        );
    }

    #[test]
    fn test_normalize_rs_not_found_fail_closed() {
        let rs_lookup: HashMap<(String, String), &DynamicObject> = HashMap::new();

        let owner = k8s_openapi::apimachinery::pkg::apis::meta::v1::OwnerReference {
            api_version: "apps/v1".to_string(),
            kind: "ReplicaSet".to_string(),
            name: "missing-rs".to_string(),
            uid: "uid-x".to_string(),
            controller: Some(true),
            block_owner_deletion: None,
        };

        let result = normalize_pod_owner(&owner, "ns", &rs_lookup, &HashMap::new());
        assert!(result.is_err(), "missing RS must fail closed");
    }

    #[test]
    fn test_normalize_multi_owner_rs_fail_closed() {
        let rs_name = "multi-owner-rs";
        let mut rs = DynamicObject::new(
            rs_name,
            &ApiResource::erase::<k8s_openapi::api::apps::v1::ReplicaSet>(&()),
        );
        rs.metadata.namespace = Some("ns".to_string());
        rs.metadata.uid = Some("rs-uid".to_string());
        rs.metadata.owner_references = Some(vec![
            k8s_openapi::apimachinery::pkg::apis::meta::v1::OwnerReference {
                api_version: "apps/v1".to_string(),
                kind: "Deployment".to_string(),
                name: "dep-a".to_string(),
                uid: "dep-a-uid".to_string(),
                controller: Some(true),
                block_owner_deletion: None,
            },
            k8s_openapi::apimachinery::pkg::apis::meta::v1::OwnerReference {
                api_version: "apps/v1".to_string(),
                kind: "Deployment".to_string(),
                name: "dep-b".to_string(),
                uid: "dep-b-uid".to_string(),
                controller: Some(true),
                block_owner_deletion: None,
            },
        ]);

        let rs_lookup: HashMap<(String, String), &DynamicObject> =
            [(("ns".to_string(), rs_name.to_string()), &rs)]
                .into_iter()
                .collect();

        let owner = k8s_openapi::apimachinery::pkg::apis::meta::v1::OwnerReference {
            api_version: "apps/v1".to_string(),
            kind: "ReplicaSet".to_string(),
            name: rs_name.to_string(),
            uid: "rs-uid".to_string(),
            controller: Some(true),
            block_owner_deletion: None,
        };

        let result = normalize_pod_owner(&owner, "ns", &rs_lookup, &HashMap::new());
        assert!(result.is_err(), "multi-owner RS must fail closed");
        assert!(result.unwrap_err().contains("multi-owner"));
    }

    // ── Phase B: namespace_scope and residual classification ──

    #[test]
    fn test_namespace_scope_entry_roundtrip() {
        use crate::teardown::journal::{NamespaceScopeEntry, NamespaceScopeEvidence};

        let entry = NamespaceScopeEntry {
            namespace: "rhoai-model-registries".to_string(),
            evidence: vec![
                NamespaceScopeEvidence::SpecNamespaceRef {
                    source_kind: "DSCInitialization".to_string(),
                    source_name: "default".to_string(),
                    field: "registriesNamespace".to_string(),
                },
                NamespaceScopeEvidence::PlanActionNamespace,
            ],
        };

        let json = serde_json::to_string(&entry).unwrap();
        let rt: NamespaceScopeEntry = serde_json::from_str(&json).unwrap();
        assert_eq!(rt, entry);
    }

    #[test]
    fn test_residual_workload_classification_unattributed() {
        let rw = ResidualWorkload {
            resource: make_rid(
                "apps",
                "Deployment",
                Some("keycloak"),
                "postgres",
                Some("uid-x"),
            ),
            uid: Some("uid-x".to_string()),
            owner_chain: vec![],
            classification: ResidualClassification::Unattributed,
            evidence: empty_evidence(),
            scope_provenance: Some("InstallNamespace".to_string()),
        };
        assert_eq!(rw.classification, ResidualClassification::Unattributed);
    }

    #[test]
    fn test_label_evidence_does_not_grant_delete_authority() {
        let evidence = ResidualEvidence {
            owner_ref_match: false,
            matching_labels: vec![("app".to_string(), "rhods".to_string())],
            matching_managers: vec![],
            namespace_affinity: true,
            service_account_match: false,
        };
        let confidence = compute_confidence(&evidence);
        assert_eq!(confidence, ResidualConfidence::Low);
        // Low confidence → attributed residual, NOT a delete action
        // This verifies 必須4: labels alone don't create DELETE authority
    }

    #[allow(clippy::useless_vec)]
    #[test]
    fn test_residual_workload_deterministic_sort() {
        let mut workloads = vec![
            ResidualWorkload {
                resource: make_rid("apps", "StatefulSet", Some("ns-b"), "zzz", None),
                uid: None,
                owner_chain: vec![],
                classification: ResidualClassification::Unattributed,
                evidence: empty_evidence(),
                scope_provenance: None,
            },
            ResidualWorkload {
                resource: make_rid("apps", "Deployment", Some("ns-a"), "aaa", None),
                uid: None,
                owner_chain: vec![],
                classification: ResidualClassification::Unattributed,
                evidence: empty_evidence(),
                scope_provenance: None,
            },
            ResidualWorkload {
                resource: make_rid("apps", "Deployment", Some("ns-a"), "bbb", None),
                uid: None,
                owner_chain: vec![],
                classification: ResidualClassification::Attributed,
                evidence: empty_evidence(),
                scope_provenance: None,
            },
        ];
        workloads.sort_by(|a, b| {
            a.resource
                .kind
                .cmp(&b.resource.kind)
                .then(a.resource.namespace.cmp(&b.resource.namespace))
                .then(a.resource.name.cmp(&b.resource.name))
        });
        assert_eq!(workloads[0].resource.name, "aaa");
        assert_eq!(workloads[1].resource.name, "bbb");
        assert_eq!(workloads[2].resource.kind, "StatefulSet");
    }

    #[test]
    fn test_incomplete_scope_from_scan_error() {
        let audit = ResidualAudit {
            scan_errors: vec![AuditScanError {
                resource_type: "Deployment".to_string(),
                namespace: "ns-a".to_string(),
                error: "403 Forbidden".to_string(),
                missing_owner_ref: None,
                ..Default::default()
            }],
            ..empty_audit()
        };
        assert!(matches!(
            residual_status_from_audit(&audit),
            ResidualStatus::AuditIncomplete
        ));
    }

    #[test]
    fn test_api_version_parsing() {
        assert_eq!(api_version_to_group("apps/v1"), "apps");
        assert_eq!(api_version_to_version("apps/v1"), "v1");
        assert_eq!(api_version_to_group("v1"), "");
        assert_eq!(api_version_to_version("v1"), "v1");
        assert_eq!(api_version_to_group("batch/v1"), "batch");
    }

    #[test]
    fn test_recreated_uid_not_plan_identity() {
        let plan_rid = make_rid(
            "apps",
            "Deployment",
            Some("ns"),
            "dep",
            Some("original-uid"),
        );
        let live_uid = Some("recreated-uid".to_string());
        assert_eq!(
            check_recreation(&plan_rid, &live_uid),
            RecreationState::Recreated
        );
    }

    // ══════════════════════════════════════════════════════════════
    //  Phase B: Residual Inventory Completion tests
    // ══════════════════════════════════════════════════════════════

    // ── Test 3: OperatorGroup target + explicit cleanup namespace saved ──

    #[test]
    fn test_namespace_scope_entry_og_target_saved() {
        use crate::teardown::journal::{NamespaceScopeEntry, NamespaceScopeEvidence};
        let entry = NamespaceScopeEntry {
            namespace: "target-ns".to_string(),
            evidence: vec![NamespaceScopeEvidence::OperatorGroupTarget],
        };
        let json = serde_json::to_string(&entry).unwrap();
        let rt: NamespaceScopeEntry = serde_json::from_str(&json).unwrap();
        assert_eq!(rt.namespace, "target-ns");
        assert_eq!(rt.evidence.len(), 1);
        assert_eq!(rt.evidence[0], NamespaceScopeEvidence::OperatorGroupTarget);
    }

    #[test]
    fn test_namespace_scope_entry_explicit_cleanup_saved() {
        use crate::teardown::journal::{NamespaceScopeEntry, NamespaceScopeEvidence};
        let entry = NamespaceScopeEntry {
            namespace: "keycloak".to_string(),
            evidence: vec![NamespaceScopeEvidence::ExplicitCleanupTarget],
        };
        let json = serde_json::to_string(&entry).unwrap();
        let rt: NamespaceScopeEntry = serde_json::from_str(&json).unwrap();
        assert_eq!(
            rt.evidence[0],
            NamespaceScopeEvidence::ExplicitCleanupTarget
        );
    }

    // ── Test 4: Pod→RS→Deployment normalization ──

    fn make_rs_dynamic(name: &str, uid: &str, dep_name: &str, dep_uid: &str) -> DynamicObject {
        let mut obj = DynamicObject::new(
            name,
            &ApiResource::erase::<k8s_openapi::api::apps::v1::ReplicaSet>(&()),
        );
        obj.metadata.namespace = Some("ns".to_string());
        obj.metadata.uid = Some(uid.to_string());
        obj.metadata.owner_references = Some(vec![
            k8s_openapi::apimachinery::pkg::apis::meta::v1::OwnerReference {
                api_version: "apps/v1".to_string(),
                kind: "Deployment".to_string(),
                name: dep_name.to_string(),
                uid: dep_uid.to_string(),
                controller: Some(true),
                block_owner_deletion: None,
            },
        ]);
        obj
    }

    #[test]
    fn test_normalize_pod_rs_deployment() {
        let rs = make_rs_dynamic("my-rs-abc", "rs-uid-1", "my-dep", "dep-uid-1");
        let lookup: HashMap<(String, String), &DynamicObject> =
            [(("ns".to_string(), "my-rs-abc".to_string()), &rs)]
                .into_iter()
                .collect();

        let owner = k8s_openapi::apimachinery::pkg::apis::meta::v1::OwnerReference {
            api_version: "apps/v1".to_string(),
            kind: "ReplicaSet".to_string(),
            name: "my-rs-abc".to_string(),
            uid: "rs-uid-1".to_string(),
            controller: Some(true),
            block_owner_deletion: None,
        };
        let native = HashMap::from([make_native_workload(
            "ns",
            "Deployment",
            "my-dep",
            "dep-uid-1",
        )]);
        let result = normalize_pod_owner(&owner, "ns", &lookup, &native).unwrap();
        assert_eq!(result.0, "Deployment");
        assert_eq!(result.3, "my-dep");
        assert_eq!(result.4, "dep-uid-1");
        assert_eq!(result.5.len(), 2); // RS + Deployment in chain
    }

    #[test]
    fn test_normalize_pod_statefulset() {
        let lookup: HashMap<(String, String), &DynamicObject> = HashMap::new();
        let owner = k8s_openapi::apimachinery::pkg::apis::meta::v1::OwnerReference {
            api_version: "apps/v1".to_string(),
            kind: "StatefulSet".to_string(),
            name: "my-sts".to_string(),
            uid: "sts-uid-1".to_string(),
            controller: Some(true),
            block_owner_deletion: None,
        };
        let native = HashMap::from([make_native_workload(
            "ns",
            "StatefulSet",
            "my-sts",
            "sts-uid-1",
        )]);
        let result = normalize_pod_owner(&owner, "ns", &lookup, &native).unwrap();
        assert_eq!(result.0, "StatefulSet");
        assert_eq!(result.3, "my-sts");
        assert_eq!(result.4, "sts-uid-1");
        assert_eq!(result.5.len(), 1); // Only StatefulSet in chain
    }

    // ── Test 5: stale owner identity, cycle, multi-owner, dedup ──

    #[test]
    fn test_normalize_pod_stale_rs_uid_fails() {
        let rs = make_rs_dynamic("my-rs", "rs-uid-WRONG", "dep", "dep-uid");
        let lookup: HashMap<(String, String), &DynamicObject> =
            [(("ns".to_string(), "my-rs".to_string()), &rs)]
                .into_iter()
                .collect();

        let owner = k8s_openapi::apimachinery::pkg::apis::meta::v1::OwnerReference {
            api_version: "apps/v1".to_string(),
            kind: "ReplicaSet".to_string(),
            name: "my-rs".to_string(),
            uid: "rs-uid-EXPECTED".to_string(),
            controller: Some(true),
            block_owner_deletion: None,
        };
        let err = normalize_pod_owner(&owner, "ns", &lookup, &HashMap::new()).unwrap_err();
        assert!(
            err.contains("stale identity"),
            "expected stale identity error, got: {}",
            err
        );
    }

    #[test]
    fn test_normalize_pod_cycle_fails() {
        // RS owned by Deployment, but Deployment UID = same as RS UID (cycle)
        let rs = make_rs_dynamic("my-rs", "cycle-uid", "dep", "cycle-uid");
        let lookup: HashMap<(String, String), &DynamicObject> =
            [(("ns".to_string(), "my-rs".to_string()), &rs)]
                .into_iter()
                .collect();

        let owner = k8s_openapi::apimachinery::pkg::apis::meta::v1::OwnerReference {
            api_version: "apps/v1".to_string(),
            kind: "ReplicaSet".to_string(),
            name: "my-rs".to_string(),
            uid: "cycle-uid".to_string(),
            controller: Some(true),
            block_owner_deletion: None,
        };
        let err = normalize_pod_owner(&owner, "ns", &lookup, &HashMap::new()).unwrap_err();
        assert!(err.contains("cycle"), "expected cycle error, got: {}", err);
    }

    #[test]
    fn test_normalize_pod_rs_multi_owner_fails() {
        let mut rs = make_rs_dynamic("my-rs", "rs-uid", "dep1", "dep1-uid");
        // Add second controller ownerRef
        rs.metadata.owner_references.as_mut().unwrap().push(
            k8s_openapi::apimachinery::pkg::apis::meta::v1::OwnerReference {
                api_version: "apps/v1".to_string(),
                kind: "Deployment".to_string(),
                name: "dep2".to_string(),
                uid: "dep2-uid".to_string(),
                controller: Some(true),
                block_owner_deletion: None,
            },
        );
        let lookup: HashMap<(String, String), &DynamicObject> =
            [(("ns".to_string(), "my-rs".to_string()), &rs)]
                .into_iter()
                .collect();

        let owner = k8s_openapi::apimachinery::pkg::apis::meta::v1::OwnerReference {
            api_version: "apps/v1".to_string(),
            kind: "ReplicaSet".to_string(),
            name: "my-rs".to_string(),
            uid: "rs-uid".to_string(),
            controller: Some(true),
            block_owner_deletion: None,
        };
        let err = normalize_pod_owner(&owner, "ns", &lookup, &HashMap::new()).unwrap_err();
        assert!(
            err.contains("multi-owner"),
            "expected multi-owner error, got: {}",
            err
        );
    }

    #[test]
    fn test_normalize_pod_rs_not_found_fails() {
        let lookup: HashMap<(String, String), &DynamicObject> = HashMap::new();
        let owner = k8s_openapi::apimachinery::pkg::apis::meta::v1::OwnerReference {
            api_version: "apps/v1".to_string(),
            kind: "ReplicaSet".to_string(),
            name: "missing-rs".to_string(),
            uid: "rs-uid".to_string(),
            controller: Some(true),
            block_owner_deletion: None,
        };
        let err = normalize_pod_owner(&owner, "ns", &lookup, &HashMap::new()).unwrap_err();
        assert!(
            err.contains("not found"),
            "expected not found error, got: {}",
            err
        );
    }

    // ── Test 6: ownerRefなしDeployment/StatefulSet in scope = unattributed ──

    #[test]
    fn test_classify_no_evidence_is_unattributed() {
        let ctx = AuditContext::default();
        let target_uids = HashSet::new();
        let obj = make_dynamic_object("orphan-dep");
        let evidence = classify_evidence(&obj, &ctx, &target_uids);
        let confidence = compute_confidence(&evidence);
        assert_eq!(confidence, ResidualConfidence::None);
        // None confidence → unattributed in classify_list_results
    }

    // ── Test 7: LIST 403/timeout = incomplete ──

    #[test]
    fn test_scan_error_403_is_incomplete() {
        let mut audit = empty_audit();
        audit.scan_errors.push(AuditScanError {
            resource_type: "Deployment".to_string(),
            namespace: "ns".to_string(),
            error: "403 Forbidden".to_string(),
            missing_owner_ref: None,
            ..Default::default()
        });
        assert!(matches!(
            residual_status_from_audit(&audit),
            ResidualStatus::AuditIncomplete
        ));
    }

    #[test]
    fn test_scan_error_timeout_is_incomplete() {
        let mut audit = empty_audit();
        audit.scan_errors.push(AuditScanError {
            resource_type: "StatefulSet".to_string(),
            namespace: "ns".to_string(),
            error: "request timeout after 30s".to_string(),
            missing_owner_ref: None,
            ..Default::default()
        });
        assert!(matches!(
            residual_status_from_audit(&audit),
            ResidualStatus::AuditIncomplete
        ));
    }

    #[test]
    fn test_scan_error_500_is_incomplete() {
        let mut audit = empty_audit();
        audit.scan_errors.push(AuditScanError {
            resource_type: "DaemonSet".to_string(),
            namespace: "ns".to_string(),
            error: "500 Internal Server Error".to_string(),
            missing_owner_ref: None,
            ..Default::default()
        });
        assert!(matches!(
            residual_status_from_audit(&audit),
            ResidualStatus::AuditIncomplete
        ));
    }

    // ── Test 8: recreated UID not treated as old plan identity ──

    #[test]
    fn test_recreated_uid_not_same_resource() {
        let rid = make_rid(
            "apps",
            "Deployment",
            Some("ns"),
            "foo",
            Some("uid-original"),
        );
        let live = Some("uid-recreated".to_string());
        assert_eq!(check_recreation(&rid, &live), RecreationState::Recreated);
    }

    // ── Test 9: label evidence does not grant DELETE authority ──

    #[test]
    fn test_label_evidence_is_low_confidence_not_delete_authority() {
        let evidence = ResidualEvidence {
            owner_ref_match: false,
            matching_labels: vec![("app".to_string(), "operator-name".to_string())],
            matching_managers: vec![],
            namespace_affinity: true,
            service_account_match: false,
        };
        let confidence = compute_confidence(&evidence);
        // Label-only → Low confidence, NOT High. Low never grants DELETE authority.
        assert_eq!(confidence, ResidualConfidence::Low);
    }

    // ── Test 10: deterministic order ──

    #[allow(clippy::useless_vec)]
    #[test]
    fn test_residual_workloads_sorted_deterministically() {
        let mut workloads = vec![
            ResidualWorkload {
                resource: make_rid("apps", "StatefulSet", Some("ns-b"), "sts-2", Some("uid-2")),
                uid: Some("uid-2".to_string()),
                owner_chain: vec![],
                classification: ResidualClassification::Unattributed,
                evidence: empty_evidence(),
                scope_provenance: None,
            },
            ResidualWorkload {
                resource: make_rid("apps", "Deployment", Some("ns-a"), "dep-1", Some("uid-1")),
                uid: Some("uid-1".to_string()),
                owner_chain: vec![],
                classification: ResidualClassification::Attributed,
                evidence: empty_evidence(),
                scope_provenance: None,
            },
        ];
        workloads.sort_by(|a, b| {
            a.resource
                .kind
                .cmp(&b.resource.kind)
                .then(a.resource.namespace.cmp(&b.resource.namespace))
                .then(a.resource.name.cmp(&b.resource.name))
        });
        assert_eq!(workloads[0].resource.kind, "Deployment");
        assert_eq!(workloads[1].resource.kind, "StatefulSet");
    }

    // ── Test: namespace_scope None (old journal) → incomplete ──

    // ── Test: api_version_to_group / api_version_to_version helpers ──

    #[test]
    fn test_api_version_to_group_with_group() {
        assert_eq!(api_version_to_group("apps/v1"), "apps");
    }

    #[test]
    fn test_api_version_to_group_core() {
        assert_eq!(api_version_to_group("v1"), "");
    }

    #[test]
    fn test_api_version_to_version_with_group() {
        assert_eq!(api_version_to_version("apps/v1"), "v1");
    }

    #[test]
    fn test_api_version_to_version_core() {
        assert_eq!(api_version_to_version("v1"), "v1");
    }

    // ── Test: DaemonSet and Job normalization ──

    #[test]
    fn test_normalize_pod_daemonset() {
        let lookup: HashMap<(String, String), &DynamicObject> = HashMap::new();
        let owner = k8s_openapi::apimachinery::pkg::apis::meta::v1::OwnerReference {
            api_version: "apps/v1".to_string(),
            kind: "DaemonSet".to_string(),
            name: "my-ds".to_string(),
            uid: "ds-uid".to_string(),
            controller: Some(true),
            block_owner_deletion: None,
        };
        let native = HashMap::from([make_native_workload("ns", "DaemonSet", "my-ds", "ds-uid")]);
        let result = normalize_pod_owner(&owner, "ns", &lookup, &native).unwrap();
        assert_eq!(result.0, "DaemonSet");
        assert_eq!(result.1, "apps");
    }

    #[test]
    fn test_normalize_pod_job() {
        let lookup: HashMap<(String, String), &DynamicObject> = HashMap::new();
        let owner = k8s_openapi::apimachinery::pkg::apis::meta::v1::OwnerReference {
            api_version: "batch/v1".to_string(),
            kind: "Job".to_string(),
            name: "my-job".to_string(),
            uid: "job-uid".to_string(),
            controller: Some(true),
            block_owner_deletion: None,
        };
        let native = HashMap::from([make_native_workload("ns", "Job", "my-job", "job-uid")]);
        let result = normalize_pod_owner(&owner, "ns", &lookup, &native).unwrap();
        assert_eq!(result.0, "Job");
        assert_eq!(result.1, "batch");
    }

    // ── Test: OwnerChainEntry serialization roundtrip ──

    #[test]
    fn test_owner_chain_entry_roundtrip() {
        let entry = OwnerChainEntry {
            group: "apps".to_string(),
            version: "v1".to_string(),
            kind: "ReplicaSet".to_string(),
            name: "my-rs".to_string(),
            uid: "rs-uid".to_string(),
        };
        let json = serde_json::to_string(&entry).unwrap();
        let rt: OwnerChainEntry = serde_json::from_str(&json).unwrap();
        assert_eq!(rt, entry);
    }

    // ── Test: ResidualWorkload serialization roundtrip ──

    #[test]
    fn test_residual_workload_roundtrip() {
        let wl = ResidualWorkload {
            resource: make_rid("apps", "Deployment", Some("ns"), "dep", Some("uid-1")),
            uid: Some("uid-1".to_string()),
            owner_chain: vec![OwnerChainEntry {
                group: "apps".to_string(),
                version: "v1".to_string(),
                kind: "ReplicaSet".to_string(),
                name: "dep-rs".to_string(),
                uid: "rs-uid".to_string(),
            }],
            classification: ResidualClassification::Unattributed,
            evidence: ResidualEvidence {
                owner_ref_match: false,
                matching_labels: vec![],
                matching_managers: vec![],
                namespace_affinity: true,
                service_account_match: false,
            },
            scope_provenance: Some("InstallNamespace".to_string()),
        };
        let json = serde_json::to_string(&wl).unwrap();
        let rt: ResidualWorkload = serde_json::from_str(&json).unwrap();
        assert_eq!(rt, wl);
    }

    // ── Test: IncompleteScopeEntry from scan_error ──

    // ── Test: ResidualClassification ordering ──

    #[allow(clippy::useless_vec)]
    #[test]
    fn test_residual_classification_ordering() {
        let mut classes = vec![
            ResidualClassification::Unattributed,
            ResidualClassification::Preserved,
            ResidualClassification::Attributed,
        ];
        classes.sort();
        assert_eq!(classes[0], ResidualClassification::Attributed);
        assert_eq!(classes[1], ResidualClassification::Unattributed);
    }

    // ── Test: unattributed or incomplete → not complete clean ──

    #[test]
    fn test_unattributed_residuals_not_clean() {
        let mut audit = empty_audit();
        audit.unattributed.push(AttributedResidual {
            resource: make_rid("apps", "Deployment", Some("ns"), "orphan", None),
            evidence: empty_evidence(),
            confidence: ResidualConfidence::None,
        });
        match residual_status_from_audit(&audit) {
            ResidualStatus::ResidualsObserved { count } => assert_eq!(count, 1),
            other => panic!("expected ResidualsObserved, got {:?}", other),
        }
    }

    #[test]
    fn test_incomplete_scope_not_clean() {
        let mut audit = empty_audit();
        audit.scan_errors.push(AuditScanError {
            resource_type: "Pod".to_string(),
            namespace: "ns".to_string(),
            error: "503 Service Unavailable".to_string(),
            missing_owner_ref: None,
            ..Default::default()
        });
        assert!(matches!(
            residual_status_from_audit(&audit),
            ResidualStatus::AuditIncomplete
        ));
    }

    // ══════════════════════════════════════════════════════════════
    //  Phase B v4: New production-path tests
    // ══════════════════════════════════════════════════════════════

    // ── target_operators_absent from generation state ──

    #[test]
    fn test_target_operators_absent_from_generation_absent() {
        let absent = OperatorGenerationState::Absent;
        assert!(matches!(absent, OperatorGenerationState::Absent));
        // In run_residual_audit: target_operators_absent = matches!(gen, Absent)
        let is_absent = matches!(&absent, OperatorGenerationState::Absent);
        assert!(is_absent);
    }

    #[test]
    fn test_target_operators_absent_not_from_same_generation() {
        let state = OperatorGenerationState::SameGeneration;
        let is_absent = matches!(&state, OperatorGenerationState::Absent);
        assert!(!is_absent);
    }

    // ── ResidualAuditSummary JSON ──

    #[test]
    fn test_residual_audit_summary_json_camel_case_all_fields() {
        let audit = ResidualAudit {
            planned_delete_still_present: vec![],
            planned_expect_still_present: vec![],
            expected_preserved: vec![],
            likely_operator_residual: vec![],
            unattributed: vec![],
            coverage: AuditCoverage {
                requested_probes: 0,
                succeeded_probes: 0,
            },
            scan_errors: vec![],
            target_operators_absent: true,
            residual_workloads: vec![],
            incomplete_scopes: vec![],
        };
        let summary = super::ResidualAuditSummary::from_audit(&audit);
        let json = serde_json::to_string_pretty(&summary).unwrap();
        // Verify camelCase field names
        assert!(json.contains("targetOperatorsAbsent"));
        assert!(json.contains("residualWorkloads"));
        assert!(json.contains("attributedResiduals"));
        assert!(json.contains("unattributedResiduals"));
        assert!(json.contains("preservedResiduals"));
        assert!(json.contains("incompleteScopes"));
        // Verify empty arrays present
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed["residualWorkloads"].as_array().unwrap().len(), 0);
        assert_eq!(parsed["targetOperatorsAbsent"].as_bool(), Some(true));
    }

    #[test]
    fn test_residual_audit_summary_roundtrip() {
        let audit = ResidualAudit {
            planned_delete_still_present: vec![],
            planned_expect_still_present: vec![],
            expected_preserved: vec![],
            likely_operator_residual: vec![AttributedResidual {
                resource: make_rid("apps", "Deployment", Some("ns"), "dep", Some("uid-1")),
                evidence: ResidualEvidence {
                    owner_ref_match: true,
                    matching_labels: vec![],
                    matching_managers: vec![],
                    namespace_affinity: true,
                    service_account_match: false,
                },
                confidence: ResidualConfidence::High,
            }],
            unattributed: vec![],
            coverage: AuditCoverage {
                requested_probes: 5,
                succeeded_probes: 5,
            },
            scan_errors: vec![],
            target_operators_absent: true,
            residual_workloads: vec![ResidualWorkload {
                resource: make_rid("apps", "Deployment", Some("ns"), "dep", Some("uid-1")),
                uid: Some("uid-1".to_string()),
                owner_chain: vec![],
                classification: ResidualClassification::Attributed,
                evidence: ResidualEvidence {
                    owner_ref_match: true,
                    matching_labels: vec![],
                    matching_managers: vec![],
                    namespace_affinity: true,
                    service_account_match: false,
                },
                scope_provenance: None,
            }],
            incomplete_scopes: vec![],
        };
        let summary = super::ResidualAuditSummary::from_audit(&audit);
        let json = serde_json::to_string(&summary).unwrap();
        let rt: super::ResidualAuditSummary = serde_json::from_str(&json).unwrap();
        assert_eq!(rt.attributed_residuals.len(), 1);
        assert_eq!(rt.residual_workloads.len(), 1);
        assert!(rt.target_operators_absent);
    }

    // ── Preserved from live classification ──

    #[test]
    fn test_preserved_classification_same_uid() {
        // Simulate plan_preserved lookup with matching UID
        let plan_uid: Option<String> = Some("uid-1".to_string());
        let live_uid: Option<&str> = Some("uid-1");
        let is_preserved = matches!(&plan_uid, Some(pu) if Some(pu.as_str()) == live_uid);
        assert!(is_preserved);
    }

    #[test]
    fn test_preserved_classification_different_uid_is_not_preserved() {
        let plan_uid: Option<String> = Some("uid-original".to_string());
        let live_uid: Option<&str> = Some("uid-recreated");
        let is_preserved = matches!(&plan_uid, Some(pu) if Some(pu.as_str()) == live_uid);
        assert!(!is_preserved, "recreated UID should not be Preserved");
    }

    // ── WorkloadKey with UID ──

    #[test]
    fn test_workload_key_different_uid_separate_entries() {
        type WK = (String, String, String, String, String, String);
        let mut map: std::collections::BTreeMap<WK, &str> = std::collections::BTreeMap::new();
        let k1: WK = (
            "apps".into(),
            "v1".into(),
            "Deployment".into(),
            "ns".into(),
            "dep".into(),
            "uid-aaa".into(),
        );
        let k2: WK = (
            "apps".into(),
            "v1".into(),
            "Deployment".into(),
            "ns".into(),
            "dep".into(),
            "uid-bbb".into(),
        );
        map.insert(k1, "original");
        map.insert(k2, "recreated");
        assert_eq!(map.len(), 2, "different UIDs must produce separate entries");
    }

    // ── Deterministic sort with reversed input ──

    #[test]
    fn test_deterministic_sort_reversed_input() {
        let wl_a = ResidualWorkload {
            resource: make_rid("apps", "Deployment", Some("ns-a"), "aaa", Some("uid-1")),
            uid: Some("uid-1".to_string()),
            owner_chain: vec![],
            classification: ResidualClassification::Attributed,
            evidence: empty_evidence(),
            scope_provenance: None,
        };
        let wl_b = ResidualWorkload {
            resource: make_rid("apps", "Deployment", Some("ns-b"), "bbb", Some("uid-2")),
            uid: Some("uid-2".to_string()),
            owner_chain: vec![],
            classification: ResidualClassification::Unattributed,
            evidence: empty_evidence(),
            scope_provenance: None,
        };

        // Forward order
        let mut fwd = vec![wl_a.clone(), wl_b.clone()];
        fwd.sort_by(|a, b| {
            a.resource
                .group
                .cmp(&b.resource.group)
                .then(a.resource.kind.cmp(&b.resource.kind))
                .then(a.resource.namespace.cmp(&b.resource.namespace))
                .then(a.resource.name.cmp(&b.resource.name))
        });

        // Reversed input
        let mut rev = vec![wl_b.clone(), wl_a.clone()];
        rev.sort_by(|a, b| {
            a.resource
                .group
                .cmp(&b.resource.group)
                .then(a.resource.kind.cmp(&b.resource.kind))
                .then(a.resource.namespace.cmp(&b.resource.namespace))
                .then(a.resource.name.cmp(&b.resource.name))
        });

        let fwd_json = serde_json::to_string(&fwd).unwrap();
        let rev_json = serde_json::to_string(&rev).unwrap();
        assert_eq!(
            fwd_json, rev_json,
            "reversed input must produce byte-identical JSON"
        );
    }

    // ── OperatorGroupAllNamespaces evidence ──

    #[test]
    fn test_og_all_namespaces_evidence_roundtrip() {
        use crate::teardown::journal::{NamespaceScopeEntry, NamespaceScopeEvidence};
        let entry = NamespaceScopeEntry {
            namespace: "any-ns".to_string(),
            evidence: vec![NamespaceScopeEvidence::OperatorGroupAllNamespaces],
        };
        let json = serde_json::to_string(&entry).unwrap();
        let rt: NamespaceScopeEntry = serde_json::from_str(&json).unwrap();
        assert_eq!(
            rt.evidence[0],
            NamespaceScopeEvidence::OperatorGroupAllNamespaces
        );
    }

    // ── scan_errors sorted ──

    #[test]
    fn test_scan_errors_sorted_deterministically() {
        let mut errors = [
            AuditScanError {
                resource_type: "StatefulSet".to_string(),
                namespace: "ns-b".to_string(),
                error: "403 Forbidden".to_string(),
                missing_owner_ref: None,
                ..Default::default()
            },
            AuditScanError {
                resource_type: "Deployment".to_string(),
                namespace: "ns-a".to_string(),
                error: "timeout".to_string(),
                missing_owner_ref: None,
                ..Default::default()
            },
        ];
        errors.sort_by(|a, b| {
            a.namespace
                .cmp(&b.namespace)
                .then(a.resource_type.cmp(&b.resource_type))
                .then(a.error.cmp(&b.error))
        });
        assert_eq!(errors[0].namespace, "ns-a");
        assert_eq!(errors[1].namespace, "ns-b");
    }

    // ── incomplete_scopes dedup ──

    #[test]
    fn test_incomplete_scopes_deduped() {
        let mut scopes = vec![
            IncompleteScopeEntry {
                namespace: "ns".to_string(),
                resource_type: "Deployment".to_string(),
                error: "403".to_string(),
            },
            IncompleteScopeEntry {
                namespace: "ns".to_string(),
                resource_type: "Deployment".to_string(),
                error: "403".to_string(),
            },
        ];
        scopes.sort_by(|a, b| {
            a.namespace
                .cmp(&b.namespace)
                .then(a.resource_type.cmp(&b.resource_type))
        });
        scopes.dedup_by(|a, b| {
            a.namespace == b.namespace && a.resource_type == b.resource_type && a.error == b.error
        });
        assert_eq!(scopes.len(), 1);
    }

    // ── AllNamespaces malformed namespace fail closed ──

    #[test]
    fn test_invalid_namespace_rejected() {
        use crate::analyzers::namespace_scope::is_valid_k8s_namespace;
        assert!(!is_valid_k8s_namespace(""));
        assert!(!is_valid_k8s_namespace("Has-Upper"));
        assert!(!is_valid_k8s_namespace("has_underscore"));
        assert!(!is_valid_k8s_namespace("has/slash"));
        assert!(!is_valid_k8s_namespace("-starts-with-dash"));
        assert!(is_valid_k8s_namespace("valid-namespace"));
        assert!(is_valid_k8s_namespace("kube-system"));
    }

    // ══════════════════════════════════════════════════════════════
    //  Phase B v6: P0 owner verification + aggregation tests
    // ══════════════════════════════════════════════════════════════

    // ── verify_owner_identity ──

    #[test]
    fn test_verify_missing_typemeta_fails() {
        let mut obj = DynamicObject {
            types: None,
            metadata: Default::default(),
            data: serde_json::json!({}),
        };
        obj.metadata.name = Some("dep".to_string());
        obj.metadata.namespace = Some("ns".to_string());
        obj.metadata.uid = Some("uid".to_string());
        let err = verify_owner_identity(&obj, "apps", "v1", "Deployment", "ns", "dep", "uid")
            .unwrap_err();
        assert!(err.contains("missing TypeMeta"), "got: {err}");
    }

    #[test]
    fn test_verify_wrong_kind_fails() {
        let obj = DynamicObject {
            types: Some(kube::api::TypeMeta {
                api_version: "apps/v1".to_string(),
                kind: "StatefulSet".to_string(),
            }),
            metadata: kube::api::ObjectMeta {
                name: Some("dep".to_string()),
                namespace: Some("ns".to_string()),
                uid: Some("uid".to_string()),
                ..Default::default()
            },
            data: serde_json::json!({}),
        };
        let err = verify_owner_identity(&obj, "apps", "v1", "Deployment", "ns", "dep", "uid")
            .unwrap_err();
        assert!(err.contains("kind mismatch"), "got: {err}");
    }

    #[test]
    fn test_verify_wrong_group_version_same_uid_fails() {
        let obj = DynamicObject {
            types: Some(kube::api::TypeMeta {
                api_version: "extensions/v1beta1".to_string(),
                kind: "Deployment".to_string(),
            }),
            metadata: kube::api::ObjectMeta {
                name: Some("dep".to_string()),
                namespace: Some("ns".to_string()),
                uid: Some("uid".to_string()),
                ..Default::default()
            },
            data: serde_json::json!({}),
        };
        let err = verify_owner_identity(&obj, "apps", "v1", "Deployment", "ns", "dep", "uid")
            .unwrap_err();
        assert!(err.contains("apiVersion mismatch"), "got: {err}");
    }

    #[test]
    fn test_verify_correct_identity_passes() {
        let obj = DynamicObject {
            types: Some(kube::api::TypeMeta {
                api_version: "apps/v1".to_string(),
                kind: "Deployment".to_string(),
            }),
            metadata: kube::api::ObjectMeta {
                name: Some("dep".to_string()),
                namespace: Some("ns".to_string()),
                uid: Some("uid".to_string()),
                ..Default::default()
            },
            data: serde_json::json!({}),
        };
        assert!(
            verify_owner_identity(&obj, "apps", "v1", "Deployment", "ns", "dep", "uid").is_ok()
        );
    }

    // ── Job owner verification ──

    #[test]
    fn test_job_stale_uid_fails() {
        let lookup: HashMap<(String, String), &DynamicObject> = HashMap::new();
        let native = HashMap::from([make_native_workload("ns", "Job", "my-job", "wrong-uid")]);
        let owner = k8s_openapi::apimachinery::pkg::apis::meta::v1::OwnerReference {
            api_version: "batch/v1".to_string(),
            kind: "Job".to_string(),
            name: "my-job".to_string(),
            uid: "expected-uid".to_string(),
            controller: Some(true),
            block_owner_deletion: None,
        };
        let err = normalize_pod_owner(&owner, "ns", &lookup, &native).unwrap_err();
        assert!(
            err.contains("stale identity") || err.contains("UID"),
            "got: {err}"
        );
    }

    #[test]
    fn test_job_missing_from_scan_fails() {
        let lookup: HashMap<(String, String), &DynamicObject> = HashMap::new();
        let owner = k8s_openapi::apimachinery::pkg::apis::meta::v1::OwnerReference {
            api_version: "batch/v1".to_string(),
            kind: "Job".to_string(),
            name: "missing-job".to_string(),
            uid: "uid".to_string(),
            controller: Some(true),
            block_owner_deletion: None,
        };
        let err = normalize_pod_owner(&owner, "ns", &lookup, &HashMap::new()).unwrap_err();
        assert!(err.contains("not found"), "got: {err}");
    }

    // ── RS sole non-Deployment owner → Err ──

    #[test]
    fn test_rs_sole_non_deployment_owner_fails() {
        let mut rs = DynamicObject {
            types: Some(kube::api::TypeMeta {
                api_version: "apps/v1".to_string(),
                kind: "ReplicaSet".to_string(),
            }),
            metadata: Default::default(),
            data: serde_json::json!({}),
        };
        rs.metadata.name = Some("my-rs".to_string());
        rs.metadata.namespace = Some("ns".to_string());
        rs.metadata.uid = Some("rs-uid".to_string());
        rs.metadata.owner_references = Some(vec![
            k8s_openapi::apimachinery::pkg::apis::meta::v1::OwnerReference {
                api_version: "custom.io/v1".to_string(),
                kind: "CustomController".to_string(),
                name: "ctrl".to_string(),
                uid: "ctrl-uid".to_string(),
                controller: Some(true),
                block_owner_deletion: None,
            },
        ]);
        let rs_lookup: HashMap<(String, String), &DynamicObject> =
            [(("ns".to_string(), "my-rs".to_string()), &rs)]
                .into_iter()
                .collect();
        let owner = k8s_openapi::apimachinery::pkg::apis::meta::v1::OwnerReference {
            api_version: "apps/v1".to_string(),
            kind: "ReplicaSet".to_string(),
            name: "my-rs".to_string(),
            uid: "rs-uid".to_string(),
            controller: Some(true),
            block_owner_deletion: None,
        };
        let err = normalize_pod_owner(&owner, "ns", &rs_lookup, &HashMap::new()).unwrap_err();
        assert!(
            err.contains("unsupported type") || err.contains("CustomController"),
            "got: {err}"
        );
    }

    // ── Job sole non-CronJob owner → Err ──

    #[test]
    fn test_job_sole_non_cronjob_owner_fails() {
        let (key, mut job) = make_native_workload("ns", "Job", "my-job", "job-uid");
        job.metadata.owner_references = Some(vec![
            k8s_openapi::apimachinery::pkg::apis::meta::v1::OwnerReference {
                api_version: "custom.io/v1".to_string(),
                kind: "WorkflowStep".to_string(),
                name: "step".to_string(),
                uid: "step-uid".to_string(),
                controller: Some(true),
                block_owner_deletion: None,
            },
        ]);
        let lookup: HashMap<(String, String), &DynamicObject> = HashMap::new();
        let native = HashMap::from([(key, job)]);
        let owner = k8s_openapi::apimachinery::pkg::apis::meta::v1::OwnerReference {
            api_version: "batch/v1".to_string(),
            kind: "Job".to_string(),
            name: "my-job".to_string(),
            uid: "job-uid".to_string(),
            controller: Some(true),
            block_owner_deletion: None,
        };
        let err = normalize_pod_owner(&owner, "ns", &lookup, &native).unwrap_err();
        assert!(
            err.contains("unsupported type") || err.contains("WorkflowStep"),
            "got: {err}"
        );
    }

    // ── select_sole_owner ──

    #[test]
    fn test_select_sole_owner_zero_refs_fails() {
        let refs: Vec<k8s_openapi::apimachinery::pkg::apis::meta::v1::OwnerReference> = vec![];
        let err = select_sole_owner(&refs, "test").unwrap_err();
        assert!(
            err.contains("0 non-controller") || err.contains("ambiguous"),
            "got: {err}"
        );
    }

    #[test]
    fn test_select_sole_owner_multiple_non_controller_fails() {
        let refs = vec![
            k8s_openapi::apimachinery::pkg::apis::meta::v1::OwnerReference {
                api_version: "v1".to_string(),
                kind: "A".to_string(),
                name: "a".to_string(),
                uid: "1".to_string(),
                controller: None,
                block_owner_deletion: None,
            },
            k8s_openapi::apimachinery::pkg::apis::meta::v1::OwnerReference {
                api_version: "v1".to_string(),
                kind: "B".to_string(),
                name: "b".to_string(),
                uid: "2".to_string(),
                controller: None,
                block_owner_deletion: None,
            },
        ];
        let err = select_sole_owner(&refs, "test").unwrap_err();
        assert!(err.contains("2 non-controller"), "got: {err}");
    }

    // ── Owned Job dedup ──

    // ── Direct Job→CronJob normalization tests ──

    #[test]
    fn test_direct_job_cronjob_no_pods() {
        let (cj_key, cj_obj) = make_native_workload("ns", "CronJob", "my-cron", "cj-uid");
        let (job_key, mut job_obj) = make_native_workload("ns", "Job", "my-job", "job-uid");
        job_obj.metadata.owner_references = Some(vec![
            k8s_openapi::apimachinery::pkg::apis::meta::v1::OwnerReference {
                api_version: "batch/v1".to_string(),
                kind: "CronJob".to_string(),
                name: "my-cron".to_string(),
                uid: "cj-uid".to_string(),
                controller: Some(true),
                block_owner_deletion: None,
            },
        ]);
        let native = HashMap::from([(cj_key, cj_obj), (job_key, job_obj)]);

        // Simulate the direct normalization: Job has CronJob parent
        let job_owners = native
            .get(&("ns".into(), "Job".into(), "my-job".into()))
            .unwrap()
            .metadata
            .owner_references
            .as_ref()
            .unwrap();
        let cj_ref = select_sole_owner(job_owners, "Job/my-job").unwrap();
        assert_eq!(cj_ref.kind, "CronJob");
        assert_eq!(cj_ref.name, "my-cron");
        // Verify CronJob identity
        let cj_live = native
            .get(&("ns".into(), "CronJob".into(), "my-cron".into()))
            .unwrap();
        assert!(
            verify_owner_identity(cj_live, "batch", "v1", "CronJob", "ns", "my-cron", "cj-uid")
                .is_ok()
        );
    }

    #[test]
    fn test_job_stale_cronjob_uid_fails_verification() {
        let (_cj_key, cj_obj) = make_native_workload("ns", "CronJob", "cron", "cj-uid-live");
        let err = verify_owner_identity(
            &cj_obj,
            "batch",
            "v1",
            "CronJob",
            "ns",
            "cron",
            "cj-uid-stale",
        )
        .unwrap_err();
        assert!(
            err.contains("stale identity") || err.contains("UID"),
            "got: {err}"
        );
    }

    #[test]
    fn test_job_unsupported_owner_type_detected() {
        let job_refs = vec![
            k8s_openapi::apimachinery::pkg::apis::meta::v1::OwnerReference {
                api_version: "custom.io/v1".to_string(),
                kind: "Pipeline".to_string(),
                name: "pipe".to_string(),
                uid: "pipe-uid".to_string(),
                controller: Some(true),
                block_owner_deletion: None,
            },
        ];
        let result = select_sole_owner(&job_refs, "Job/job");
        assert!(result.is_ok());
        assert_ne!(result.unwrap().kind, "CronJob");
    }

    #[test]
    fn test_job_multiple_owners_fails_closed() {
        let job_refs = vec![
            k8s_openapi::apimachinery::pkg::apis::meta::v1::OwnerReference {
                api_version: "batch/v1".to_string(),
                kind: "CronJob".to_string(),
                name: "cron-a".to_string(),
                uid: "uid-a".to_string(),
                controller: None,
                block_owner_deletion: None,
            },
            k8s_openapi::apimachinery::pkg::apis::meta::v1::OwnerReference {
                api_version: "batch/v1".to_string(),
                kind: "CronJob".to_string(),
                name: "cron-b".to_string(),
                uid: "uid-b".to_string(),
                controller: None,
                block_owner_deletion: None,
            },
        ];
        let err = select_sole_owner(&job_refs, "Job/job").unwrap_err();
        assert!(
            err.contains("2 non-controller") || err.contains("ambiguous"),
            "got: {err}"
        );
    }

    // ── P0-v8: Anchored GVK and empty UID tests ──

    #[test]
    fn test_wrong_group_same_kind_cronjob_rejected_by_pod_owner() {
        // custom.io/v1 CronJob should be rejected at Pod→Job stage
        let lookup: HashMap<(String, String), &DynamicObject> = HashMap::new();
        let native = HashMap::from([make_native_workload("ns", "Job", "j", "j-uid")]);
        let owner = k8s_openapi::apimachinery::pkg::apis::meta::v1::OwnerReference {
            api_version: "custom.io/v1".to_string(), // Wrong group
            kind: "Job".to_string(),
            name: "j".to_string(),
            uid: "j-uid".to_string(),
            controller: Some(true),
            block_owner_deletion: None,
        };
        let err = normalize_pod_owner(&owner, "ns", &lookup, &native).unwrap_err();
        assert!(
            err.contains("FOREIGN") || err.contains("unsupported"),
            "got: {err}"
        );
    }

    #[test]
    fn test_wrong_group_same_kind_deployment_rejected_by_rs() {
        // RS owned by extensions/v1beta1 Deployment should be rejected
        let mut rs = DynamicObject {
            types: Some(kube::api::TypeMeta {
                api_version: "apps/v1".to_string(),
                kind: "ReplicaSet".to_string(),
            }),
            metadata: kube::api::ObjectMeta {
                name: Some("rs".to_string()),
                namespace: Some("ns".to_string()),
                uid: Some("rs-uid".to_string()),
                ..Default::default()
            },
            data: serde_json::json!({}),
        };
        rs.metadata.owner_references = Some(vec![
            k8s_openapi::apimachinery::pkg::apis::meta::v1::OwnerReference {
                api_version: "extensions/v1beta1".to_string(), // Wrong group/version
                kind: "Deployment".to_string(),
                name: "dep".to_string(),
                uid: "dep-uid".to_string(),
                controller: Some(true),
                block_owner_deletion: None,
            },
        ]);
        let rs_lookup: HashMap<(String, String), &DynamicObject> =
            [(("ns".to_string(), "rs".to_string()), &rs)]
                .into_iter()
                .collect();
        let owner = k8s_openapi::apimachinery::pkg::apis::meta::v1::OwnerReference {
            api_version: "apps/v1".to_string(),
            kind: "ReplicaSet".to_string(),
            name: "rs".to_string(),
            uid: "rs-uid".to_string(),
            controller: Some(true),
            block_owner_deletion: None,
        };
        let err = normalize_pod_owner(&owner, "ns", &rs_lookup, &HashMap::new()).unwrap_err();
        assert!(
            err.contains("unsupported GVK") || err.contains("extensions"),
            "got: {err}"
        );
    }

    #[test]
    fn test_empty_uid_fails_verification() {
        let obj = DynamicObject {
            types: Some(kube::api::TypeMeta {
                api_version: "apps/v1".to_string(),
                kind: "Deployment".to_string(),
            }),
            metadata: kube::api::ObjectMeta {
                name: Some("dep".to_string()),
                namespace: Some("ns".to_string()),
                uid: Some(String::new()), // Empty UID
                ..Default::default()
            },
            data: serde_json::json!({}),
        };
        let err = verify_owner_identity(&obj, "apps", "v1", "Deployment", "ns", "dep", "uid")
            .unwrap_err();
        assert!(
            err.contains("empty") || err.contains("unverifiable"),
            "got: {err}"
        );
    }

    #[test]
    fn test_empty_expected_uid_fails_verification() {
        let obj = DynamicObject {
            types: Some(kube::api::TypeMeta {
                api_version: "apps/v1".to_string(),
                kind: "Deployment".to_string(),
            }),
            metadata: kube::api::ObjectMeta {
                name: Some("dep".to_string()),
                namespace: Some("ns".to_string()),
                uid: Some("uid".to_string()),
                ..Default::default()
            },
            data: serde_json::json!({}),
        };
        let err =
            verify_owner_identity(&obj, "apps", "v1", "Deployment", "ns", "dep", "").unwrap_err();
        assert!(
            err.contains("empty") || err.contains("unverifiable"),
            "got: {err}"
        );
    }

    #[test]
    fn test_pod_owner_wrong_group_statefulset_rejected() {
        let lookup: HashMap<(String, String), &DynamicObject> = HashMap::new();
        let owner = k8s_openapi::apimachinery::pkg::apis::meta::v1::OwnerReference {
            api_version: "custom.io/v1".to_string(),
            kind: "StatefulSet".to_string(),
            name: "sts".to_string(),
            uid: "uid".to_string(),
            controller: Some(true),
            block_owner_deletion: None,
        };
        let err = normalize_pod_owner(&owner, "ns", &lookup, &HashMap::new()).unwrap_err();
        assert!(
            err.contains("FOREIGN") || err.contains("unsupported"),
            "got: {err}"
        );
    }

    // ── Production-path tests calling normalize_jobs_to_cronjobs ──

    #[test]
    fn test_normalize_jobs_helper_no_pods_one_cronjob() {
        use crate::teardown::journal::AuditContext;
        let (cj_key, cj_obj) = make_native_workload("ns", "CronJob", "cron", "cj-uid");
        let (job_key, mut job_obj) = make_native_workload("ns", "Job", "job", "job-uid");
        job_obj.metadata.owner_references = Some(vec![
            k8s_openapi::apimachinery::pkg::apis::meta::v1::OwnerReference {
                api_version: "batch/v1".to_string(),
                kind: "CronJob".to_string(),
                name: "cron".to_string(),
                uid: "cj-uid".to_string(),
                controller: Some(true),
                block_owner_deletion: None,
            },
        ]);
        let native = HashMap::from([(cj_key, cj_obj), (job_key, job_obj)]);
        let mut wmap: BTreeMap<WorkloadKey, ResidualWorkload> = BTreeMap::new();
        wmap.insert(
            (
                "batch".into(),
                "v1".into(),
                "Job".into(),
                "ns".into(),
                "job".into(),
                "job-uid".into(),
            ),
            ResidualWorkload {
                resource: make_rid("batch", "Job", Some("ns"), "job", Some("job-uid")),
                uid: Some("job-uid".into()),
                owner_chain: vec![],
                classification: ResidualClassification::Unattributed,
                evidence: empty_evidence(),
                scope_provenance: None,
            },
        );
        wmap.insert(
            (
                "batch".into(),
                "v1".into(),
                "CronJob".into(),
                "ns".into(),
                "cron".into(),
                "cj-uid".into(),
            ),
            ResidualWorkload {
                resource: make_rid("batch", "CronJob", Some("ns"), "cron", Some("cj-uid")),
                uid: Some("cj-uid".into()),
                owner_chain: vec![],
                classification: ResidualClassification::Unattributed,
                evidence: empty_evidence(),
                scope_provenance: None,
            },
        );
        let mut audit = empty_audit();
        normalize_jobs_to_cronjobs(
            &mut wmap,
            &native,
            &mut audit,
            &AuditContext::default(),
            &HashSet::new(),
            &HashMap::new(),
        );
        assert_eq!(
            wmap.len(),
            1,
            "only CronJob: {:?}",
            wmap.keys().collect::<Vec<_>>()
        );
        let wl = wmap.values().next().unwrap();
        assert_eq!(wl.resource.kind, "CronJob");
        assert_eq!(wl.owner_chain.len(), 2);
        assert_eq!(wl.owner_chain[0].kind, "Job");
        assert!(audit.scan_errors.is_empty());
    }

    #[test]
    fn test_normalize_jobs_helper_invalid_parent_incomplete() {
        use crate::teardown::journal::AuditContext;
        let (job_key, mut job_obj) = make_native_workload("ns", "Job", "j", "j-uid");
        job_obj.metadata.owner_references = Some(vec![
            k8s_openapi::apimachinery::pkg::apis::meta::v1::OwnerReference {
                api_version: "custom.io/v1".to_string(),
                kind: "Pipeline".to_string(),
                name: "p".to_string(),
                uid: "p-uid".to_string(),
                controller: Some(true),
                block_owner_deletion: None,
            },
        ]);
        let native = HashMap::from([(job_key, job_obj)]);
        let mut wmap: BTreeMap<WorkloadKey, ResidualWorkload> = BTreeMap::new();
        wmap.insert(
            (
                "batch".into(),
                "v1".into(),
                "Job".into(),
                "ns".into(),
                "j".into(),
                "j-uid".into(),
            ),
            ResidualWorkload {
                resource: make_rid("batch", "Job", Some("ns"), "j", Some("j-uid")),
                uid: Some("j-uid".into()),
                owner_chain: vec![],
                classification: ResidualClassification::Unattributed,
                evidence: empty_evidence(),
                scope_provenance: None,
            },
        );
        let mut audit = empty_audit();
        normalize_jobs_to_cronjobs(
            &mut wmap,
            &native,
            &mut audit,
            &AuditContext::default(),
            &HashSet::new(),
            &HashMap::new(),
        );
        // No target evidence → ScopeOut → Job removed
        assert!(wmap.is_empty(), "foreign-owner Job scope-out (removed)");
        assert!(
            audit.scan_errors.is_empty(),
            "no scan_error: {:?}",
            audit.scan_errors
        );
    }

    #[test]
    fn test_non_empty_uid_rejects_empty_string() {
        let obj = DynamicObject {
            types: Some(kube::api::TypeMeta {
                api_version: "apps/v1".to_string(),
                kind: "Deployment".to_string(),
            }),
            metadata: kube::api::ObjectMeta {
                name: Some("dep".to_string()),
                uid: Some(String::new()),
                ..Default::default()
            },
            data: serde_json::json!({}),
        };
        assert!(non_empty_uid(&obj, "Deployment", "dep").is_err());
    }

    #[test]
    fn test_non_empty_uid_rejects_none() {
        let obj = DynamicObject {
            types: None,
            metadata: kube::api::ObjectMeta {
                name: Some("dep".to_string()),
                uid: None,
                ..Default::default()
            },
            data: serde_json::json!({}),
        };
        assert!(non_empty_uid(&obj, "Deployment", "dep").is_err());
    }

    #[test]
    fn test_non_empty_uid_accepts_valid() {
        let obj = DynamicObject {
            types: None,
            metadata: kube::api::ObjectMeta {
                name: Some("dep".to_string()),
                uid: Some("abc-123".to_string()),
                ..Default::default()
            },
            data: serde_json::json!({}),
        };
        assert_eq!(non_empty_uid(&obj, "Deployment", "dep").unwrap(), "abc-123");
    }

    // ── P1: Formatter and output tests ──

    #[test]
    fn test_format_residual_audit_json_no_scope_out() {
        let audit = empty_audit();
        let json = super::format_residual_audit_json(&audit);
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
        // ScopeOut removed from Phase B schema
        assert!(parsed.get("scopeOutResiduals").is_none());
        // Required fields present
        assert!(parsed.get("targetOperatorsAbsent").is_some());
        assert!(parsed.get("residualWorkloads").is_some());
        assert!(parsed.get("attributedResiduals").is_some());
        assert!(parsed.get("unattributedResiduals").is_some());
        assert!(parsed.get("preservedResiduals").is_some());
        assert!(parsed.get("incompleteScopes").is_some());
    }

    #[test]
    fn test_format_json_nonempty_attributed() {
        let mut audit = empty_audit();
        audit.target_operators_absent = true;
        audit.residual_workloads.push(ResidualWorkload {
            resource: make_rid("apps", "Deployment", Some("ns"), "dep", Some("uid-1")),
            uid: Some("uid-1".to_string()),
            owner_chain: vec![],
            classification: ResidualClassification::Attributed,
            evidence: ResidualEvidence {
                owner_ref_match: true,
                matching_labels: vec![],
                matching_managers: vec![],
                namespace_affinity: true,
                service_account_match: false,
            },
            scope_provenance: Some("InstallNamespace".to_string()),
        });
        audit.likely_operator_residual.push(AttributedResidual {
            resource: make_rid("apps", "Deployment", Some("ns"), "dep", Some("uid-1")),
            evidence: ResidualEvidence {
                owner_ref_match: true,
                matching_labels: vec![],
                matching_managers: vec![],
                namespace_affinity: true,
                service_account_match: false,
            },
            confidence: ResidualConfidence::High,
        });
        let json = super::format_residual_audit_json(&audit);
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed["targetOperatorsAbsent"].as_bool(), Some(true));
        assert_eq!(parsed["residualWorkloads"].as_array().unwrap().len(), 1);
        assert_eq!(parsed["attributedResiduals"].as_array().unwrap().len(), 1);
        assert_eq!(parsed["unattributedResiduals"].as_array().unwrap().len(), 0);
        assert_eq!(parsed["preservedResiduals"].as_array().unwrap().len(), 0);
        let wl = &parsed["residualWorkloads"][0];
        assert_eq!(wl["scope_provenance"].as_str(), Some("InstallNamespace"));
    }

    #[test]
    fn test_format_json_nonempty_preserved() {
        let mut audit = empty_audit();
        audit.residual_workloads.push(ResidualWorkload {
            resource: make_rid("apps", "StatefulSet", Some("ns"), "sts", Some("uid-2")),
            uid: Some("uid-2".to_string()),
            owner_chain: vec![],
            classification: ResidualClassification::Preserved,
            evidence: empty_evidence(),
            scope_provenance: None,
        });
        let json = super::format_residual_audit_json(&audit);
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed["preservedResiduals"].as_array().unwrap().len(), 1);
    }

    #[test]
    fn test_format_json_nonempty_incomplete() {
        let mut audit = empty_audit();
        audit.incomplete_scopes.push(IncompleteScopeEntry {
            namespace: "ns".to_string(),
            resource_type: "Deployment".to_string(),
            error: "403 Forbidden".to_string(),
        });
        let json = super::format_residual_audit_json(&audit);
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed["incompleteScopes"].as_array().unwrap().len(), 1);
    }

    #[test]
    fn test_classify_uid_none_no_residual() {
        let mut audit = empty_audit();
        let ctx = crate::teardown::journal::AuditContext::default();
        let obj = DynamicObject {
            types: None,
            metadata: kube::api::ObjectMeta {
                name: Some("x".to_string()),
                namespace: Some("ns".to_string()),
                uid: None,
                ..Default::default()
            },
            data: serde_json::json!({}),
        };
        classify_list_results(
            vec![obj],
            "Service",
            "",
            "v1",
            "ns",
            &ctx,
            &HashSet::new(),
            &HashSet::new(),
            &mut audit,
        );
        assert_eq!(audit.scan_errors.len(), 1);
        assert_eq!(audit.unattributed.len(), 0);
    }

    #[test]
    fn test_classify_uid_empty_no_residual() {
        let mut audit = empty_audit();
        let ctx = crate::teardown::journal::AuditContext::default();
        let obj = DynamicObject {
            types: None,
            metadata: kube::api::ObjectMeta {
                name: Some("y".to_string()),
                namespace: Some("ns".to_string()),
                uid: Some(String::new()),
                ..Default::default()
            },
            data: serde_json::json!({}),
        };
        classify_list_results(
            vec![obj],
            "Service",
            "",
            "v1",
            "ns",
            &ctx,
            &HashSet::new(),
            &HashSet::new(),
            &mut audit,
        );
        assert_eq!(audit.scan_errors.len(), 1);
        assert_eq!(audit.unattributed.len(), 0);
    }

    // ── P1: Pure renderer tests ──

    #[test]
    fn test_tree_renderer_all_classifications() {
        let mut audit = empty_audit();
        audit.target_operators_absent = true;
        // Attributed workload with chain and scope
        audit.residual_workloads.push(ResidualWorkload {
            resource: make_rid("apps", "Deployment", Some("ns"), "my-dep", Some("uid-1")),
            uid: Some("uid-1".into()),
            owner_chain: vec![OwnerChainEntry {
                group: "apps".into(),
                version: "v1".into(),
                kind: "ReplicaSet".into(),
                name: "my-dep-rs".into(),
                uid: "rs-uid".into(),
            }],
            classification: ResidualClassification::Attributed,
            evidence: ResidualEvidence {
                owner_ref_match: true,
                matching_labels: vec![],
                matching_managers: vec!["controller".into()],
                namespace_affinity: true,
                service_account_match: false,
            },
            scope_provenance: Some("InstallNamespace".into()),
        });
        // Unattributed workload
        audit.residual_workloads.push(ResidualWorkload {
            resource: make_rid("apps", "StatefulSet", Some("ns"), "sts", Some("uid-2")),
            uid: Some("uid-2".into()),
            owner_chain: vec![],
            classification: ResidualClassification::Unattributed,
            evidence: empty_evidence(),
            scope_provenance: None,
        });
        // Preserved workload
        audit.residual_workloads.push(ResidualWorkload {
            resource: make_rid("apps", "Deployment", Some("ns"), "kept", Some("uid-3")),
            uid: Some("uid-3".into()),
            owner_chain: vec![],
            classification: ResidualClassification::Preserved,
            evidence: empty_evidence(),
            scope_provenance: None,
        });
        // Non-workload attributed (Route)
        audit.likely_operator_residual.push(AttributedResidual {
            resource: make_rid(
                "route.openshift.io",
                "Route",
                Some("ns"),
                "my-route",
                Some("uid-r"),
            ),
            evidence: ResidualEvidence {
                owner_ref_match: false,
                matching_labels: vec![("app".into(), "test".into())],
                matching_managers: vec![],
                namespace_affinity: true,
                service_account_match: false,
            },
            confidence: ResidualConfidence::Low,
        });
        // Non-workload unattributed
        audit.unattributed.push(AttributedResidual {
            resource: make_rid("", "Service", Some("ns"), "orphan-svc", Some("uid-s")),
            evidence: empty_evidence(),
            confidence: ResidualConfidence::None,
        });
        // Incomplete scope
        audit.incomplete_scopes.push(IncompleteScopeEntry {
            namespace: "ns".into(),
            resource_type: "ImageStream".into(),
            error: "403 Forbidden".into(),
        });

        // Build a minimal journal for rendering
        let csv_rid = make_rid(
            "operators.coreos.com",
            "ClusterServiceVersion",
            Some("ns"),
            "test-op.v1",
            Some("csv-uid"),
        );
        let journal = crate::teardown::journal::RunJournal {
            run_id: "test-run".to_string(),
            schema_version: 12,
            oc_deps_version: "0.1.0".to_string(),
            journal_revision: 0,
            cluster_identity: crate::teardown::plan::ClusterIdentity {
                api_server: "test".to_string(),
                kube_system_uid: "test".to_string(),
            },
            operator: crate::teardown::plan::OperatorIdentitySnapshot {
                generation_identity:
                    crate::teardown::plan::OperatorGenerationIdentity::Unverifiable {
                        reason: "test".to_string(),
                    },
                operator_id: crate::analyzers::olm::OperatorId {
                    csv_name: "test-op.v1".to_string(),
                    namespace: "ns".to_string(),
                },
                csv_name: "test-op.v1".to_string(),
                csv: crate::teardown::plan::ObservedResourceIdentity {
                    resource: csv_rid,
                    uid: "csv-uid".to_string(),
                },
                subscriptions: vec![],
                controller_deployments: vec![],
                service_accounts: vec![],
                owned_crds: vec![],
                required_crds: vec![],
            },
            created_at: "2024-01-01T00:00:00Z".to_string(),
            updated_at: "2024-01-01T00:00:00Z".to_string(),
            state: crate::teardown::journal::RunState::ApplyCompleted,
            residual_status: crate::teardown::journal::ResidualStatus::NotAudited,
            audit_revision: 0,
            audit_context: crate::teardown::journal::AuditContext::default(),
            plan_snapshot: crate::teardown::planner::TeardownPlan {
                targets: vec![],
                preflight: crate::teardown::planner::Preflight { checks: vec![] },
                phases: vec![],
                blockers: vec![],
                warnings: vec![],
                snapshot_taken_at: String::new(),
                dependency_edges: vec![],
                operator_inventory: vec![],
                explicit_decisions: vec![],
                explicit_deletes: vec![],
            },
            execution: crate::teardown::journal::ExecutionRecord {
                phases_completed: 7,
                phases_total: 7,
                ..Default::default()
            },
            last_residual_audit: None,
            cleanup_decisions: vec![],
            finalizer_recovery_approved: false,
            finalizer_recoveries: vec![],
            backup_receipts: vec![],
        };

        let tree = super::render_residual_audit_tree(&audit, &journal, false);
        // Check all sections present
        assert!(tree.contains("Target operator absent: yes"), "tree: {tree}");
        assert!(tree.contains("ATTRIBUTED WORKLOADS"), "tree: {tree}");
        assert!(tree.contains("my-dep"), "tree: {tree}");
        assert!(tree.contains("ReplicaSet/my-dep-rs"), "tree: {tree}");
        assert!(tree.contains("InstallNamespace"), "tree: {tree}");
        assert!(tree.contains("UNATTRIBUTED WORKLOADS"), "tree: {tree}");
        assert!(tree.contains("sts"), "tree: {tree}");
        assert!(tree.contains("PRESERVED WORKLOADS"), "tree: {tree}");
        assert!(tree.contains("kept"), "tree: {tree}");
        assert!(tree.contains("ATTRIBUTED RELATED"), "tree: {tree}");
        assert!(tree.contains("my-route"), "tree: {tree}");
        assert!(tree.contains("UNATTRIBUTED RELATED"), "tree: {tree}");
        assert!(tree.contains("orphan-svc"), "tree: {tree}");
        assert!(tree.contains("INCOMPLETE SCOPES"), "tree: {tree}");
        assert!(tree.contains("ImageStream"), "tree: {tree}");
        // Each identity appears exactly once
        assert_eq!(tree.matches("uid-1").count(), 1, "uid-1 should appear once");
        assert_eq!(tree.matches("uid-2").count(), 1, "uid-2 should appear once");
    }

    // ── Table renderer test ──

    #[test]
    fn test_table_renderer_all_classifications() {
        let mut audit = empty_audit();
        audit.target_operators_absent = true;
        audit.residual_workloads.push(ResidualWorkload {
            resource: make_rid("apps", "Deployment", Some("ns"), "my-dep", Some("uid-1")),
            uid: Some("uid-1".into()),
            owner_chain: vec![OwnerChainEntry {
                group: "apps".into(),
                version: "v1".into(),
                kind: "ReplicaSet".into(),
                name: "my-dep-rs".into(),
                uid: "rs-uid".into(),
            }],
            classification: ResidualClassification::Attributed,
            evidence: ResidualEvidence {
                owner_ref_match: true,
                matching_labels: vec![],
                matching_managers: vec!["controller".into()],
                namespace_affinity: true,
                service_account_match: false,
            },
            scope_provenance: Some("InstallNamespace".into()),
        });
        audit.residual_workloads.push(ResidualWorkload {
            resource: make_rid("apps", "StatefulSet", Some("ns"), "sts", Some("uid-2")),
            uid: Some("uid-2".into()),
            owner_chain: vec![],
            classification: ResidualClassification::Unattributed,
            evidence: empty_evidence(),
            scope_provenance: None,
        });
        audit.residual_workloads.push(ResidualWorkload {
            resource: make_rid("apps", "Deployment", Some("ns"), "kept", Some("uid-3")),
            uid: Some("uid-3".into()),
            owner_chain: vec![],
            classification: ResidualClassification::Preserved,
            evidence: empty_evidence(),
            scope_provenance: None,
        });
        audit.likely_operator_residual.push(AttributedResidual {
            resource: make_rid(
                "route.openshift.io",
                "Route",
                Some("ns"),
                "my-route",
                Some("uid-r"),
            ),
            evidence: ResidualEvidence {
                owner_ref_match: false,
                matching_labels: vec![("app".into(), "test".into())],
                matching_managers: vec![],
                namespace_affinity: true,
                service_account_match: false,
            },
            confidence: ResidualConfidence::Low,
        });
        audit.unattributed.push(AttributedResidual {
            resource: make_rid("", "Service", Some("ns"), "orphan-svc", Some("uid-s")),
            evidence: empty_evidence(),
            confidence: ResidualConfidence::None,
        });
        audit.incomplete_scopes.push(IncompleteScopeEntry {
            namespace: "ns".into(),
            resource_type: "ImageStream".into(),
            error: "403 Forbidden".into(),
        });

        let csv_rid = make_rid(
            "operators.coreos.com",
            "ClusterServiceVersion",
            Some("ns"),
            "test-op.v1",
            Some("csv-uid"),
        );
        let journal = crate::teardown::journal::RunJournal {
            run_id: "test-run".to_string(),
            schema_version: 12,
            oc_deps_version: "0.1.0".to_string(),
            journal_revision: 0,
            cluster_identity: crate::teardown::plan::ClusterIdentity {
                api_server: "test".to_string(),
                kube_system_uid: "test".to_string(),
            },
            operator: crate::teardown::plan::OperatorIdentitySnapshot {
                generation_identity:
                    crate::teardown::plan::OperatorGenerationIdentity::Unverifiable {
                        reason: "test".to_string(),
                    },
                operator_id: crate::analyzers::olm::OperatorId {
                    csv_name: "test-op.v1".to_string(),
                    namespace: "ns".to_string(),
                },
                csv_name: "test-op.v1".to_string(),
                csv: crate::teardown::plan::ObservedResourceIdentity {
                    resource: csv_rid,
                    uid: "csv-uid".to_string(),
                },
                subscriptions: vec![],
                controller_deployments: vec![],
                service_accounts: vec![],
                owned_crds: vec![],
                required_crds: vec![],
            },
            created_at: "2024-01-01T00:00:00Z".to_string(),
            updated_at: "2024-01-01T00:00:00Z".to_string(),
            state: crate::teardown::journal::RunState::ApplyCompleted,
            residual_status: crate::teardown::journal::ResidualStatus::NotAudited,
            audit_revision: 0,
            audit_context: crate::teardown::journal::AuditContext::default(),
            plan_snapshot: crate::teardown::planner::TeardownPlan {
                targets: vec![],
                preflight: crate::teardown::planner::Preflight { checks: vec![] },
                phases: vec![],
                blockers: vec![],
                warnings: vec![],
                snapshot_taken_at: String::new(),
                dependency_edges: vec![],
                operator_inventory: vec![],
                explicit_decisions: vec![],
                explicit_deletes: vec![],
            },
            execution: crate::teardown::journal::ExecutionRecord {
                phases_completed: 7,
                phases_total: 7,
                ..Default::default()
            },
            last_residual_audit: None,
            cleanup_decisions: vec![],
            finalizer_recovery_approved: false,
            finalizer_recoveries: vec![],
            backup_receipts: vec![],
        };

        let table = super::render_residual_audit_table(&audit, &journal, false);
        // Header row
        assert!(table.contains("Classification"), "table: {table}");
        assert!(table.contains("Resource"), "table: {table}");
        assert!(table.contains("Namespace"), "table: {table}");
        assert!(table.contains("UID"), "table: {table}");
        assert!(table.contains("Evidence"), "table: {table}");
        assert!(table.contains("Chain"), "table: {table}");
        assert!(table.contains("Scope"), "table: {table}");
        // All fixture rows
        assert!(table.contains("my-dep"), "table: {table}");
        assert!(table.contains("uid-1"), "table: {table}");
        assert!(table.contains("ReplicaSet/my-dep-rs"), "table: {table}");
        assert!(table.contains("InstallNamespace"), "table: {table}");
        assert!(table.contains("sts"), "table: {table}");
        assert!(table.contains("uid-2"), "table: {table}");
        assert!(table.contains("kept"), "table: {table}");
        assert!(table.contains("uid-3"), "table: {table}");
        assert!(table.contains("my-route"), "table: {table}");
        assert!(table.contains("uid-r"), "table: {table}");
        assert!(table.contains("orphan-svc"), "table: {table}");
        assert!(table.contains("uid-s"), "table: {table}");
        // Incomplete scope
        assert!(table.contains("ImageStream"), "table: {table}");
        assert!(table.contains("403 Forbidden"), "table: {table}");
        // Evidence
        assert!(table.contains("ownerRef"), "table: {table}");
        // Each identity once
        assert_eq!(table.matches("uid-1").count(), 1, "uid-1 once");
        assert_eq!(table.matches("uid-2").count(), 1, "uid-2 once");
        assert_eq!(table.matches("uid-r").count(), 1, "uid-r once");
        assert_eq!(table.matches("uid-s").count(), 1, "uid-s once");
        // Target absent
        assert!(
            table.contains("Target operator absent: yes"),
            "table: {table}"
        );
    }

    // ── No-ANSI test ──

    #[test]
    fn test_renderer_no_ansi() {
        let mut audit = empty_audit();
        audit.residual_workloads.push(ResidualWorkload {
            resource: make_rid("apps", "Deployment", Some("ns"), "dep", Some("uid-1")),
            uid: Some("uid-1".into()),
            owner_chain: vec![],
            classification: ResidualClassification::Attributed,
            evidence: empty_evidence(),
            scope_provenance: None,
        });
        audit.incomplete_scopes.push(IncompleteScopeEntry {
            namespace: "ns".into(),
            resource_type: "Route".into(),
            error: "403".into(),
        });

        let csv_rid = make_rid(
            "operators.coreos.com",
            "ClusterServiceVersion",
            Some("ns"),
            "op.v1",
            Some("uid"),
        );
        let journal = crate::teardown::journal::RunJournal {
            run_id: "r".to_string(),
            schema_version: 12,
            oc_deps_version: "0.1.0".to_string(),
            journal_revision: 0,
            cluster_identity: crate::teardown::plan::ClusterIdentity {
                api_server: "t".to_string(),
                kube_system_uid: "t".to_string(),
            },
            operator: crate::teardown::plan::OperatorIdentitySnapshot {
                generation_identity:
                    crate::teardown::plan::OperatorGenerationIdentity::Unverifiable {
                        reason: "t".to_string(),
                    },
                operator_id: crate::analyzers::olm::OperatorId {
                    csv_name: "op.v1".to_string(),
                    namespace: "ns".to_string(),
                },
                csv_name: "op.v1".to_string(),
                csv: crate::teardown::plan::ObservedResourceIdentity {
                    resource: csv_rid,
                    uid: "uid".to_string(),
                },
                subscriptions: vec![],
                controller_deployments: vec![],
                service_accounts: vec![],
                owned_crds: vec![],
                required_crds: vec![],
            },
            created_at: "t".to_string(),
            updated_at: "t".to_string(),
            state: crate::teardown::journal::RunState::ApplyCompleted,
            residual_status: crate::teardown::journal::ResidualStatus::NotAudited,
            audit_revision: 0,
            audit_context: crate::teardown::journal::AuditContext::default(),
            plan_snapshot: crate::teardown::planner::TeardownPlan {
                targets: vec![],
                preflight: crate::teardown::planner::Preflight { checks: vec![] },
                phases: vec![],
                blockers: vec![],
                warnings: vec![],
                snapshot_taken_at: String::new(),
                dependency_edges: vec![],
                operator_inventory: vec![],
                explicit_decisions: vec![],
                explicit_deletes: vec![],
            },
            execution: crate::teardown::journal::ExecutionRecord::default(),
            last_residual_audit: None,
            cleanup_decisions: vec![],
            finalizer_recovery_approved: false,
            finalizer_recoveries: vec![],
            backup_receipts: vec![],
        };

        let tree = super::render_residual_audit_tree(&audit, &journal, false);
        assert!(
            !tree.contains("\x1b"),
            "no-ANSI tree must not contain escape sequences; got: {tree}"
        );
        assert!(tree.contains("ATTRIBUTED WORKLOADS"), "tree: {tree}");
        assert!(tree.contains("dep"), "tree: {tree}");
    }

    // ══════════════════════════════════════════════════════════════
    //  Tower production tests through observe_residual_state
    // ══════════════════════════════════════════════════════════════

    fn tower_json_response(json: serde_json::Value) -> http::Response<kube::client::Body> {
        http::Response::builder()
            .status(200)
            .body(kube::client::Body::from(serde_json::to_vec(&json).unwrap()))
            .unwrap()
    }

    fn tower_status_response(code: u16) -> http::Response<kube::client::Body> {
        let body = serde_json::json!({
            "kind": "Status", "apiVersion": "v1", "metadata": {},
            "status": "Failure", "message": "error", "reason": "error", "code": code
        });
        http::Response::builder()
            .status(code)
            .body(kube::client::Body::from(serde_json::to_vec(&body).unwrap()))
            .unwrap()
    }

    fn tower_empty_list() -> http::Response<kube::client::Body> {
        tower_json_response(serde_json::json!({
            "apiVersion": "v1", "kind": "List",
            "metadata": {"resourceVersion": "1"},
            "items": []
        }))
    }

    #[allow(clippy::field_reassign_with_default)]
    fn make_tower_journal() -> crate::teardown::journal::RunJournal {
        let csv_rid = make_rid(
            "operators.coreos.com",
            "ClusterServiceVersion",
            Some("test-ns"),
            "test-pkg.v1",
            Some("csv-uid-1"),
        );
        let dep_rid = make_rid(
            "apps",
            "Deployment",
            Some("test-ns"),
            "test-dep",
            Some("dep-uid-1"),
        );
        crate::teardown::journal::RunJournal {
            run_id: "tower-test-run".to_string(),
            schema_version: 12,
            oc_deps_version: "0.1.0".to_string(),
            journal_revision: 0,
            cluster_identity: crate::teardown::plan::ClusterIdentity {
                api_server: "test".to_string(),
                kube_system_uid: "test".to_string(),
            },
            operator: crate::teardown::plan::OperatorIdentitySnapshot {
                generation_identity:
                    crate::teardown::plan::OperatorGenerationIdentity::OlmPackage {
                        package_name: "test-pkg".to_string(),
                        install_namespace: "test-ns".to_string(),
                    },
                operator_id: crate::analyzers::olm::OperatorId {
                    csv_name: "test-pkg.v1".to_string(),
                    namespace: "test-ns".to_string(),
                },
                csv_name: "test-pkg.v1".to_string(),
                csv: crate::teardown::plan::ObservedResourceIdentity {
                    resource: csv_rid,
                    uid: "csv-uid-1".to_string(),
                },
                subscriptions: vec![],
                controller_deployments: vec![],
                service_accounts: vec![],
                owned_crds: vec![],
                required_crds: vec![],
            },
            created_at: "2024-01-01T00:00:00Z".to_string(),
            updated_at: "2024-01-01T00:00:00Z".to_string(),
            state: crate::teardown::journal::RunState::ApplyCompleted,
            residual_status: crate::teardown::journal::ResidualStatus::NotAudited,
            audit_revision: 0,
            audit_context: {
                let mut ctx = crate::teardown::journal::AuditContext::default();
                ctx.namespace_scope = Some(vec![crate::teardown::journal::NamespaceScopeEntry {
                    namespace: "test-ns".to_string(),
                    evidence: vec![
                        crate::teardown::journal::NamespaceScopeEvidence::InstallNamespace,
                    ],
                }]);
                ctx.footprint_namespaces.insert("test-ns".to_string());
                ctx.csv_baseline = Some(vec![crate::teardown::journal::CsvBaselineEntry {
                    name: "test-pkg.v1".to_string(),
                    uid: "csv-uid-1".to_string(),
                }]);
                ctx.known_gvrs = Some(vec![]);
                ctx.unresolved_crds = Some(vec![]);
                ctx.unresolved_gvks = Some(vec![]);
                ctx.owned_cr_gvrs = Some(vec![]);
                ctx
            },
            plan_snapshot: crate::teardown::planner::TeardownPlan {
                targets: vec![],
                preflight: crate::teardown::planner::Preflight { checks: vec![] },
                phases: vec![crate::teardown::planner::PlanPhase {
                    name: "test".to_string(),
                    description: "test".to_string(),
                    actions: vec![crate::teardown::planner::Action::Delete {
                        resource: dep_rid,
                        reason: "test".to_string(),
                    }],
                    barrier: None,
                }],
                blockers: vec![],
                warnings: vec![],
                snapshot_taken_at: String::new(),
                dependency_edges: vec![],
                operator_inventory: vec![],
                explicit_decisions: vec![],
                explicit_deletes: vec![],
            },
            execution: crate::teardown::journal::ExecutionRecord {
                phases_completed: 1,
                phases_total: 1,
                ..Default::default()
            },
            last_residual_audit: None,
            cleanup_decisions: vec![],
            finalizer_recovery_approved: false,
            finalizer_recoveries: vec![],
            backup_receipts: vec![],
        }
    }

    /// Handle generation-check baseline that reaches Absent:
    /// Sub LIST → empty, CSV GET → 404 (endpoint LIST → success), CSV baseline LIST → empty.
    // Exact Kubernetes API paths for test assertions
    const SUB_LIST: &str = "/apis/operators.coreos.com/v1alpha1/namespaces/test-ns/subscriptions";
    const CSV_GET: &str =
        "/apis/operators.coreos.com/v1alpha1/namespaces/test-ns/clusterserviceversions/test-pkg.v1";
    const CSV_LIST: &str =
        "/apis/operators.coreos.com/v1alpha1/namespaces/test-ns/clusterserviceversions";
    const DEP_LIST: &str = "/apis/apps/v1/namespaces/test-ns/deployments";
    const DEP_GET: &str = "/apis/apps/v1/namespaces/test-ns/deployments/test-dep";
    const STS_LIST: &str = "/apis/apps/v1/namespaces/test-ns/statefulsets";
    const DS_LIST: &str = "/apis/apps/v1/namespaces/test-ns/daemonsets";
    const JOB_LIST: &str = "/apis/batch/v1/namespaces/test-ns/jobs";
    const CJ_LIST: &str = "/apis/batch/v1/namespaces/test-ns/cronjobs";
    const POD_LIST: &str = "/api/v1/namespaces/test-ns/pods";
    const RS_LIST: &str = "/apis/apps/v1/namespaces/test-ns/replicasets";
    const SVC_LIST: &str = "/api/v1/namespaces/test-ns/services";
    const ROUTE_LIST: &str = "/apis/route.openshift.io/v1/namespaces/test-ns/routes";
    const IS_LIST: &str = "/apis/image.openshift.io/v1/namespaces/test-ns/imagestreams";

    fn handle_generation_absent(path: &str) -> Option<http::Response<kube::client::Body>> {
        match path {
            SUB_LIST => Some(tower_empty_list()),
            CSV_GET => Some(tower_status_response(404)),
            CSV_LIST => Some(tower_empty_list()),
            _ => None,
        }
    }

    /// Handle residual audit scan requests with empty success for all workload/related types.
    fn handle_audit_scan_default(path: &str) -> Option<http::Response<kube::client::Body>> {
        match path {
            DEP_LIST | STS_LIST | DS_LIST | JOB_LIST | CJ_LIST | POD_LIST | RS_LIST | SVC_LIST
            | SUB_LIST | CSV_LIST => Some(tower_empty_list()),
            DEP_GET => Some(tower_status_response(404)),
            ROUTE_LIST | IS_LIST => Some(tower_status_response(404)),
            _ => None,
        }
    }

    #[tokio::test]
    async fn test_observe_403_generation_list() {
        use std::pin::pin;
        use std::sync::atomic::{AtomicUsize, Ordering};

        let (mock_service, handle) = tower_test::mock::pair::<
            http::Request<kube::client::Body>,
            http::Response<kube::client::Body>,
        >();
        let client = kube::Client::new(mock_service, "default");
        let journal = make_tower_journal();
        let request_count = std::sync::Arc::new(AtomicUsize::new(0));
        let rc = request_count.clone();

        let spawned = tokio::spawn(async move {
            let mut handle = pin!(handle);
            while let Some((req, send)) = handle.next_request().await {
                rc.fetch_add(1, Ordering::SeqCst);
                let path = req.uri().path().to_string();
                if path == SUB_LIST {
                    send.send_response(tower_status_response(403));
                } else {
                    panic!("test_observe_403: unexpected request path: {}", path);
                }
            }
        });

        let result = super::observe_residual_state(&client, &journal).await;
        drop(client);
        spawned.await.unwrap();

        let obs = result.unwrap();
        assert!(
            matches!(obs.generation, OperatorGenerationState::Unknown(_)),
            "403 should produce Unknown, got {:?}",
            obs.generation
        );
        assert!(
            obs.audit.is_none(),
            "Unknown generation should not run audit"
        );
        assert_eq!(
            request_count.load(Ordering::SeqCst),
            1,
            "403 should produce exactly 1 request"
        );
    }

    #[tokio::test]
    async fn test_observe_500_generation_list() {
        use std::pin::pin;
        use std::sync::atomic::{AtomicUsize, Ordering};

        let (mock_service, handle) = tower_test::mock::pair::<
            http::Request<kube::client::Body>,
            http::Response<kube::client::Body>,
        >();
        let client = kube::Client::new(mock_service, "default");
        let journal = make_tower_journal();
        let request_count = std::sync::Arc::new(AtomicUsize::new(0));
        let rc = request_count.clone();

        let spawned = tokio::spawn(async move {
            let mut handle = pin!(handle);
            while let Some((_req, send)) = handle.next_request().await {
                rc.fetch_add(1, Ordering::SeqCst);
                // All requests get 500
                send.send_response(tower_status_response(500));
            }
        });

        let result = super::observe_residual_state(&client, &journal).await;
        drop(client);
        spawned.await.unwrap();

        let obs = result.unwrap();
        assert!(
            matches!(obs.generation, OperatorGenerationState::Unknown(_)),
            "persistent 500 should produce Unknown"
        );
        // MAX_RETRIES=2 means 3 total attempts
        assert_eq!(
            request_count.load(Ordering::SeqCst),
            3,
            "persistent 500 should produce exactly 3 requests (initial + 2 retries)"
        );
    }

    #[tokio::test]
    async fn test_observe_absent_baseline() {
        use std::pin::pin;
        use std::sync::atomic::{AtomicUsize, Ordering};

        let (mock_service, handle) = tower_test::mock::pair::<
            http::Request<kube::client::Body>,
            http::Response<kube::client::Body>,
        >();
        let client = kube::Client::new(mock_service, "default");
        let journal = make_tower_journal();
        let request_count = std::sync::Arc::new(AtomicUsize::new(0));
        let rc = request_count.clone();

        let spawned = tokio::spawn(async move {
            let mut handle = pin!(handle);
            while let Some((req, send)) = handle.next_request().await {
                rc.fetch_add(1, Ordering::SeqCst);
                let path = req.uri().path().to_string();
                if let Some(resp) = handle_generation_absent(&path) {
                    send.send_response(resp);
                } else if let Some(resp) = handle_audit_scan_default(&path) {
                    send.send_response(resp);
                } else {
                    panic!("test_observe_absent_baseline: unexpected request: {}", path);
                }
            }
        });

        let result = super::observe_residual_state(&client, &journal).await;
        drop(client);
        spawned.await.unwrap();

        let obs = result.unwrap();
        assert!(
            matches!(obs.generation, OperatorGenerationState::Absent),
            "baseline should be Absent, got {:?}",
            obs.generation
        );
        assert!(obs.audit.is_some(), "Absent should produce audit");
        let audit = obs.audit.unwrap();
        assert!(
            audit.scan_errors.is_empty(),
            "baseline should have no scan errors, got {:?}",
            audit.scan_errors
        );
        assert!(
            request_count.load(Ordering::SeqCst) > 0,
            "should have made network requests"
        );
    }

    #[tokio::test]
    async fn test_observe_planned_get_404_endpoint_success() {
        use std::pin::pin;
        #[allow(unused_imports)]
        use std::sync::atomic::{AtomicUsize, Ordering};

        let (mock_service, handle) = tower_test::mock::pair::<
            http::Request<kube::client::Body>,
            http::Response<kube::client::Body>,
        >();
        let client = kube::Client::new(mock_service, "default");
        let journal = make_tower_journal();
        let request_paths = std::sync::Arc::new(std::sync::Mutex::new(Vec::<String>::new()));
        let rp = request_paths.clone();

        let spawned = tokio::spawn(async move {
            let mut handle = pin!(handle);
            while let Some((req, send)) = handle.next_request().await {
                let path = req.uri().path().to_string();
                rp.lock().unwrap().push(path.clone());
                if let Some(resp) = handle_generation_absent(&path) {
                    send.send_response(resp);
                } else if path == "/apis/apps/v1/namespaces/test-ns/deployments/test-dep" {
                    // Planned DELETE GET → 404
                    send.send_response(tower_status_response(404));
                } else if let Some(resp) = handle_audit_scan_default(&path) {
                    send.send_response(resp);
                } else {
                    panic!(
                        "test_observe_planned_get_404_endpoint_success: unexpected request: {}",
                        path
                    );
                }
            }
        });

        let result = super::observe_residual_state(&client, &journal).await;
        drop(client);
        spawned.await.unwrap();

        let obs = result.unwrap();
        let audit = obs.audit.unwrap();
        // The planned DELETE should be Gone (not in still_present)
        assert!(
            audit.planned_delete_still_present.is_empty(),
            "GET 404 + endpoint LIST success → resource Gone"
        );
        // Verify both request paths were made
        let paths = request_paths.lock().unwrap();
        assert!(
            paths.contains(&DEP_GET.to_string()),
            "should have GET for planned DELETE resource"
        );
        assert!(
            paths.contains(&DEP_LIST.to_string()),
            "should have endpoint verification LIST"
        );
    }

    #[tokio::test]
    async fn test_observe_planned_get_404_endpoint_404() {
        use std::pin::pin;

        let (mock_service, handle) = tower_test::mock::pair::<
            http::Request<kube::client::Body>,
            http::Response<kube::client::Body>,
        >();
        let client = kube::Client::new(mock_service, "default");
        let journal = make_tower_journal();

        let spawned = tokio::spawn(async move {
            let mut handle = pin!(handle);
            while let Some((req, send)) = handle.next_request().await {
                let path = req.uri().path().to_string();
                if let Some(resp) = handle_generation_absent(&path) {
                    send.send_response(resp);
                } else if path == DEP_GET {
                    // Planned GET → 404
                    send.send_response(tower_status_response(404));
                } else if path == DEP_LIST {
                    // Endpoint LIST also 404 (only for the verification LIST after GET 404)
                    send.send_response(tower_status_response(404));
                } else if let Some(resp) = handle_audit_scan_default(&path) {
                    send.send_response(resp);
                } else {
                    panic!(
                        "test_observe_planned_get_404_endpoint_404: unexpected request: {}",
                        path
                    );
                }
            }
        });

        let result = super::observe_residual_state(&client, &journal).await;
        drop(client);
        spawned.await.unwrap();

        let obs = result.unwrap();
        let audit = obs.audit.unwrap();
        // Should have scan error — endpoint verification failed
        assert!(
            !audit.scan_errors.is_empty(),
            "GET 404 + endpoint LIST 404 should produce scan error"
        );
        // Should NOT be in Gone
        assert!(
            audit.planned_delete_still_present.is_empty(),
            "resource should not be marked as still-present either"
        );
    }

    #[tokio::test]
    async fn test_observe_planned_get_404_endpoint_403() {
        use std::pin::pin;

        let (mock_service, handle) = tower_test::mock::pair::<
            http::Request<kube::client::Body>,
            http::Response<kube::client::Body>,
        >();
        let client = kube::Client::new(mock_service, "default");
        let journal = make_tower_journal();

        let spawned = tokio::spawn(async move {
            let mut handle = pin!(handle);
            while let Some((req, send)) = handle.next_request().await {
                let path = req.uri().path().to_string();
                if let Some(resp) = handle_generation_absent(&path) {
                    send.send_response(resp);
                } else if path == DEP_GET {
                    send.send_response(tower_status_response(404));
                } else if path == DEP_LIST {
                    // Endpoint LIST 403
                    send.send_response(tower_status_response(403));
                } else if let Some(resp) = handle_audit_scan_default(&path) {
                    send.send_response(resp);
                } else {
                    panic!(
                        "test_observe_planned_get_404_endpoint_403: unexpected request: {}",
                        path
                    );
                }
            }
        });

        let result = super::observe_residual_state(&client, &journal).await;
        drop(client);
        spawned.await.unwrap();

        let obs = result.unwrap();
        let audit = obs.audit.unwrap();
        assert!(
            !audit.scan_errors.is_empty(),
            "GET 404 + endpoint LIST 403 should produce scan error (incomplete)"
        );
    }

    #[tokio::test]
    async fn test_observe_optional_route_404_complete() {
        use std::pin::pin;

        let (mock_service, handle) = tower_test::mock::pair::<
            http::Request<kube::client::Body>,
            http::Response<kube::client::Body>,
        >();
        let client = kube::Client::new(mock_service, "default");
        let journal = make_tower_journal();

        let spawned = tokio::spawn(async move {
            let mut handle = pin!(handle);
            while let Some((req, send)) = handle.next_request().await {
                let path = req.uri().path().to_string();
                if let Some(resp) = handle_generation_absent(&path) {
                    send.send_response(resp);
                } else if path == ROUTE_LIST {
                    // Optional Route LIST → 404 (API not available)
                    send.send_response(tower_status_response(404));
                } else if let Some(resp) = handle_audit_scan_default(&path) {
                    send.send_response(resp);
                } else {
                    panic!(
                        "test_observe_optional_route_404_complete: unexpected request: {}",
                        path
                    );
                }
            }
        });

        let result = super::observe_residual_state(&client, &journal).await;
        drop(client);
        spawned.await.unwrap();

        let obs = result.unwrap();
        let audit = obs.audit.unwrap();
        // Route 404 should NOT produce scan error (Optional)
        let route_errors: Vec<_> = audit
            .scan_errors
            .iter()
            .filter(|e| e.resource_type.contains("Route"))
            .collect();
        assert!(
            route_errors.is_empty(),
            "Optional Route LIST 404 should be complete, not incomplete: {:?}",
            route_errors
        );
    }

    #[tokio::test]
    async fn test_observe_required_workload_404_incomplete() {
        use std::pin::pin;

        let (mock_service, handle) = tower_test::mock::pair::<
            http::Request<kube::client::Body>,
            http::Response<kube::client::Body>,
        >();
        let client = kube::Client::new(mock_service, "default");
        let journal = make_tower_journal();

        let spawned = tokio::spawn(async move {
            let mut handle = pin!(handle);
            while let Some((req, send)) = handle.next_request().await {
                let path = req.uri().path().to_string();
                if let Some(resp) = handle_generation_absent(&path) {
                    send.send_response(resp);
                } else if path == DEP_LIST {
                    // Required Deployment LIST → 404 (should be incomplete)
                    send.send_response(tower_status_response(404));
                } else if let Some(resp) = handle_audit_scan_default(&path) {
                    send.send_response(resp);
                } else {
                    panic!(
                        "test_observe_required_workload_404_incomplete: unexpected request: {}",
                        path
                    );
                }
            }
        });

        let result = super::observe_residual_state(&client, &journal).await;
        drop(client);
        spawned.await.unwrap();

        let obs = result.unwrap();
        let audit = obs.audit.unwrap();
        // Required Deployment LIST 404 should produce scan error → incomplete
        let dep_errors: Vec<_> = audit
            .scan_errors
            .iter()
            .filter(|e| e.resource_type.contains("Deployment"))
            .collect();
        assert!(
            !dep_errors.is_empty(),
            "Required Deployment LIST 404 should be incomplete"
        );
    }

    #[tokio::test]
    async fn test_observe_nonzero_network_queries() {
        use std::pin::pin;
        use std::sync::atomic::{AtomicUsize, Ordering};

        let (mock_service, handle) = tower_test::mock::pair::<
            http::Request<kube::client::Body>,
            http::Response<kube::client::Body>,
        >();
        let client = kube::Client::new(mock_service, "default");
        let journal = make_tower_journal();
        let request_count = std::sync::Arc::new(AtomicUsize::new(0));
        let rc = request_count.clone();

        let spawned = tokio::spawn(async move {
            let mut handle = pin!(handle);
            while let Some((req, send)) = handle.next_request().await {
                rc.fetch_add(1, Ordering::SeqCst);
                let path = req.uri().path().to_string();
                if let Some(resp) = handle_generation_absent(&path) {
                    send.send_response(resp);
                } else if let Some(resp) = handle_audit_scan_default(&path) {
                    send.send_response(resp);
                } else {
                    panic!("test_observe_absent_baseline: unexpected request: {}", path);
                }
            }
        });

        let result = super::observe_residual_state(&client, &journal).await;
        drop(client);
        spawned.await.unwrap();

        let obs = result.unwrap();
        assert!(
            matches!(obs.generation, OperatorGenerationState::Absent),
            "baseline should be Absent, got {:?}",
            obs.generation
        );
        assert!(obs.audit.is_some(), "Absent should produce audit");
        let audit = obs.audit.unwrap();
        assert!(
            audit.scan_errors.is_empty(),
            "baseline should have no scan errors, got: {:?}",
            audit.scan_errors
        );
        let count = request_count.load(Ordering::SeqCst);
        assert!(
            count > 0,
            "must have nonzero network queries — no raw fallback"
        );
    }
    #[tokio::test(start_paused = true)]
    async fn test_observe_timeout_generation() {
        use std::pin::pin;
        use std::sync::atomic::{AtomicUsize, Ordering};

        let (mock_service, handle) = tower_test::mock::pair::<
            http::Request<kube::client::Body>,
            http::Response<kube::client::Body>,
        >();
        let client = kube::Client::new(mock_service, "default");
        let journal = make_tower_journal();
        let request_count = std::sync::Arc::new(AtomicUsize::new(0));
        let rc = request_count.clone();
        let paths = std::sync::Arc::new(std::sync::Mutex::new(Vec::<String>::new()));
        let pp = paths.clone();

        // Hold response handles so the connection stays open but never responds.
        // With start_paused=true, Tokio advances time past the 30s timeout
        // without real wall-clock delay. Planner retries up to MAX_RETRIES.
        let spawned = tokio::spawn(async move {
            let mut handle = pin!(handle);
            let mut held_senders = Vec::new();
            while let Some((req, send)) = handle.next_request().await {
                rc.fetch_add(1, Ordering::SeqCst);
                let path = req.uri().path().to_string();
                pp.lock().unwrap().push(path.clone());
                if path == SUB_LIST {
                    held_senders.push(send);
                } else {
                    panic!(
                        "test_observe_timeout_generation: unexpected request: {}",
                        path
                    );
                }
            }
            drop(held_senders);
        });

        let result = super::observe_residual_state(&client, &journal).await;
        drop(client);
        let _ = spawned.await;

        let obs = result.unwrap();
        assert!(
            matches!(obs.generation, OperatorGenerationState::Unknown(_)),
            "timeout should produce Unknown, got {:?}",
            obs.generation
        );
        assert!(
            obs.audit.is_none(),
            "Unknown generation should not run audit"
        );
        let count = request_count.load(Ordering::SeqCst);
        assert_eq!(
            count, 3,
            "planner retries 3 times (MAX_RETRIES+1), got {}",
            count
        );
        let recorded = paths.lock().unwrap();
        assert!(
            recorded.iter().all(|p| p.contains("/subscriptions")),
            "all requests should be subscription LIST: {:?}",
            *recorded
        );
    }

    // ── TypeMeta normalization production-boundary tower tests ──

    #[tokio::test]
    async fn test_audit_list_normalizes_missing_typemeta() {
        use std::pin::pin;
        use std::sync::atomic::{AtomicUsize, Ordering};

        let (mock_service, handle) = tower_test::mock::pair::<
            http::Request<kube::client::Body>,
            http::Response<kube::client::Body>,
        >();
        let client = kube::Client::new(mock_service, "default");
        let planner = crate::kube::planner::QueryPlanner::new(Some(std::sync::Arc::new(
            tokio::sync::Semaphore::new(50),
        )));
        let request_count = std::sync::Arc::new(AtomicUsize::new(0));
        let rc = request_count.clone();
        let paths = std::sync::Arc::new(std::sync::Mutex::new(Vec::<String>::new()));
        let pp = paths.clone();

        let spawned = tokio::spawn(async move {
            let mut handle = pin!(handle);
            while let Some((req, send)) = handle.next_request().await {
                rc.fetch_add(1, Ordering::SeqCst);
                let path = req.uri().path().to_string();
                pp.lock().unwrap().push(path.clone());
                // Return CronJob LIST item WITHOUT apiVersion/kind (missing TypeMeta)
                send.send_response(tower_json_response(serde_json::json!({
                    "apiVersion": "v1", "kind": "List",
                    "metadata": {"resourceVersion": "1"},
                    "items": [{
                        "metadata": {
                            "name": "image-pruner",
                            "namespace": "openshift-image-registry",
                            "uid": "cron-uid-1"
                        }
                    }]
                })));
            }
        });

        let result = audit_list(
            &client,
            "batch",
            "v1",
            "CronJob",
            "cronjobs",
            Some("openshift-image-registry"),
            crate::kube::resource::QueryRequirement::Required,
            &planner,
        )
        .await;
        drop(client);
        let _ = spawned.await;

        let items = result.expect("audit_list should succeed with normalized TypeMeta");
        assert_eq!(items.len(), 1);
        // TypeMeta should be filled in by audit_list
        let t = items[0].types.as_ref().expect("TypeMeta should be present");
        assert_eq!(t.api_version, "batch/v1");
        assert_eq!(t.kind, "CronJob");
        assert_eq!(request_count.load(Ordering::SeqCst), 1);
        let recorded = paths.lock().unwrap();
        assert_eq!(
            recorded[0],
            "/apis/batch/v1/namespaces/openshift-image-registry/cronjobs"
        );
    }

    #[tokio::test]
    async fn test_audit_list_rejects_wrong_typemeta() {
        use std::pin::pin;
        use std::sync::atomic::{AtomicUsize, Ordering};

        let (mock_service, handle) = tower_test::mock::pair::<
            http::Request<kube::client::Body>,
            http::Response<kube::client::Body>,
        >();
        let client = kube::Client::new(mock_service, "default");
        let planner = crate::kube::planner::QueryPlanner::new(Some(std::sync::Arc::new(
            tokio::sync::Semaphore::new(50),
        )));
        let request_count = std::sync::Arc::new(AtomicUsize::new(0));
        let rc = request_count.clone();

        let spawned = tokio::spawn(async move {
            let mut handle = pin!(handle);
            while let Some((_req, send)) = handle.next_request().await {
                rc.fetch_add(1, Ordering::SeqCst);
                // Return item with WRONG apiVersion/kind
                send.send_response(tower_json_response(serde_json::json!({
                    "apiVersion": "v1", "kind": "List",
                    "metadata": {"resourceVersion": "1"},
                    "items": [{
                        "apiVersion": "apps/v1",
                        "kind": "Deployment",
                        "metadata": {
                            "name": "wrong-type",
                            "namespace": "ns",
                            "uid": "uid-wrong"
                        }
                    }]
                })));
            }
        });

        let result = audit_list(
            &client,
            "batch",
            "v1",
            "CronJob",
            "cronjobs",
            Some("ns"),
            crate::kube::resource::QueryRequirement::Required,
            &planner,
        )
        .await;
        drop(client);
        let _ = spawned.await;

        assert!(result.is_err(), "wrong TypeMeta should fail");
        let err = result.unwrap_err();
        assert!(
            err.error.contains("TypeMeta mismatch"),
            "error should mention mismatch: {}",
            err.error
        );
        assert_eq!(request_count.load(Ordering::SeqCst), 1);
    }

    // ── Foreign-owned classification tests ──

    #[test]
    fn test_foreign_pod_catalogsource_no_evidence_skipped() {
        // Pod owned by CatalogSource with no target evidence → skip, no scan_error
        let lookup: HashMap<(String, String), &DynamicObject> = HashMap::new();
        let owner = k8s_openapi::apimachinery::pkg::apis::meta::v1::OwnerReference {
            api_version: "operators.coreos.com/v1alpha1".to_string(),
            kind: "CatalogSource".to_string(),
            name: "redhat-operators".to_string(),
            uid: "cat-uid".to_string(),
            controller: Some(true),
            block_owner_deletion: None,
        };
        let result = normalize_pod_owner(&owner, "ns", &lookup, &HashMap::new());
        assert!(result.is_foreign(), "CatalogSource owner should be Foreign");
    }

    #[test]
    fn test_foreign_job_configmap_owner_detected() {
        // Job owned by ConfigMap → FOREIGN_OWNER if no target evidence
        let (key, mut job) = make_native_workload("ns", "Job", "unpack-job", "job-uid");
        job.metadata.owner_references = Some(vec![
            k8s_openapi::apimachinery::pkg::apis::meta::v1::OwnerReference {
                api_version: "v1".to_string(),
                kind: "ConfigMap".to_string(),
                name: "catalog-config".to_string(),
                uid: "cm-uid".to_string(),
                controller: Some(true),
                block_owner_deletion: None,
            },
        ]);
        let native = HashMap::from([(key, job.clone())]);
        let mut wmap: BTreeMap<WorkloadKey, ResidualWorkload> = BTreeMap::new();
        wmap.insert(
            (
                "batch".into(),
                "v1".into(),
                "Job".into(),
                "ns".into(),
                "unpack-job".into(),
                "job-uid".into(),
            ),
            ResidualWorkload {
                resource: make_rid("batch", "Job", Some("ns"), "unpack-job", Some("job-uid")),
                uid: Some("job-uid".into()),
                owner_chain: vec![],
                classification: ResidualClassification::Unattributed,
                evidence: empty_evidence(),
                scope_provenance: None,
            },
        );
        let mut audit = empty_audit();
        let ctx = crate::teardown::journal::AuditContext::default();
        normalize_jobs_to_cronjobs(
            &mut wmap,
            &native,
            &mut audit,
            &ctx,
            &HashSet::new(),
            &HashMap::new(),
        );
        // No target evidence → ScopeOut → Job removed
        assert!(wmap.is_empty(), "foreign Job should be scope-out (removed)");
        assert!(
            audit.scan_errors.is_empty(),
            "no scan_error: {:?}",
            audit.scan_errors
        );
    }

    #[test]
    fn test_foreign_pod_with_target_evidence_retained() {
        // Pod owned by CatalogSource but WITH target evidence → fail closed (scan_error)
        let lookup: HashMap<(String, String), &DynamicObject> = HashMap::new();
        let owner = k8s_openapi::apimachinery::pkg::apis::meta::v1::OwnerReference {
            api_version: "operators.coreos.com/v1alpha1".to_string(),
            kind: "CatalogSource".to_string(),
            name: "custom-catalog".to_string(),
            uid: "cat-uid".to_string(),
            controller: Some(true),
            block_owner_deletion: None,
        };
        let result = normalize_pod_owner(&owner, "ns", &lookup, &HashMap::new());
        assert!(
            result.is_foreign(),
            "foreign owner should be Foreign variant"
        );
        // If the caller finds target evidence, it should add scan_error (tested at caller level)
    }

    // ── Broad-only namespace and OwnerNormalization tests ──

    #[test]
    fn test_broad_only_namespace_detection() {
        use crate::teardown::journal::{AuditContext, NamespaceScopeEntry, NamespaceScopeEvidence};

        // AllNamespaces only → broad
        let ctx = AuditContext {
            namespace_scope: Some(vec![NamespaceScopeEntry {
                namespace: "openshift-marketplace".to_string(),
                evidence: vec![NamespaceScopeEvidence::OperatorGroupAllNamespaces],
            }]),
            ..Default::default()
        };
        assert!(is_broad_only_namespace(&ctx, "openshift-marketplace"));

        // Install namespace → not broad
        let ctx2 = AuditContext {
            namespace_scope: Some(vec![NamespaceScopeEntry {
                namespace: "install-ns".to_string(),
                evidence: vec![NamespaceScopeEvidence::InstallNamespace],
            }]),
            ..Default::default()
        };
        assert!(!is_broad_only_namespace(&ctx2, "install-ns"));

        // Mixed evidence → not broad
        let ctx3 = AuditContext {
            namespace_scope: Some(vec![NamespaceScopeEntry {
                namespace: "mixed-ns".to_string(),
                evidence: vec![
                    NamespaceScopeEvidence::OperatorGroupAllNamespaces,
                    NamespaceScopeEvidence::PlanActionNamespace,
                ],
            }]),
            ..Default::default()
        };
        assert!(!is_broad_only_namespace(&ctx3, "mixed-ns"));

        // Unknown namespace → not broad
        assert!(!is_broad_only_namespace(&ctx3, "unknown-ns"));

        // Empty evidence → not broad
        let ctx4 = AuditContext {
            namespace_scope: Some(vec![NamespaceScopeEntry {
                namespace: "empty".to_string(),
                evidence: vec![],
            }]),
            ..Default::default()
        };
        assert!(!is_broad_only_namespace(&ctx4, "empty"));
    }

    #[test]
    fn test_broad_only_foreign_pod_skipped() {
        // CatalogSource Pod in AllNamespaces-only namespace → Foreign, skipped
        let owner = k8s_openapi::apimachinery::pkg::apis::meta::v1::OwnerReference {
            api_version: "operators.coreos.com/v1alpha1".to_string(),
            kind: "CatalogSource".to_string(),
            name: "redhat-operators".to_string(),
            uid: "cat-uid".to_string(),
            controller: Some(true),
            block_owner_deletion: None,
        };
        let result = normalize_pod_owner(
            &owner,
            "openshift-marketplace",
            &HashMap::new(),
            &HashMap::new(),
        );
        assert!(
            result.is_foreign(),
            "CatalogSource should be Foreign: {:?}",
            result
        );
    }

    #[test]
    fn test_broad_only_target_residual_found() {
        // Genuine target Deployment in AllNamespaces-only namespace with target evidence
        // → should still be found as attributed
        use crate::teardown::journal::{AuditContext, NamespaceScopeEntry, NamespaceScopeEvidence};

        let ctx = AuditContext {
            namespace_scope: Some(vec![NamespaceScopeEntry {
                namespace: "broad-ns".to_string(),
                evidence: vec![NamespaceScopeEvidence::OperatorGroupAllNamespaces],
            }]),
            ..Default::default()
        };

        assert!(is_broad_only_namespace(&ctx, "broad-ns"));

        // Target evidence (ownerRef match) should NOT be filtered
        let evidence = ResidualEvidence {
            owner_ref_match: true,
            matching_labels: vec![],
            matching_managers: vec![],
            namespace_affinity: true,
            service_account_match: false,
        };
        let confidence = compute_confidence(&evidence);
        assert_ne!(
            confidence,
            ResidualConfidence::None,
            "target evidence should produce non-None confidence"
        );
        // Non-None confidence is NOT skipped even in broad-only namespace
    }

    #[test]
    fn test_strong_namespace_foreign_pod_with_evidence_fails_closed() {
        // In a strongly evidenced namespace, foreign owner with target evidence → fail closed
        use crate::teardown::journal::{AuditContext, NamespaceScopeEntry, NamespaceScopeEvidence};

        let ctx = AuditContext {
            namespace_scope: Some(vec![NamespaceScopeEntry {
                namespace: "install-ns".to_string(),
                evidence: vec![NamespaceScopeEvidence::InstallNamespace],
            }]),
            ..Default::default()
        };

        // Not broad-only
        assert!(!is_broad_only_namespace(&ctx, "install-ns"));

        // Foreign owner with target evidence → should be scan_error, not skipped
        // (This is tested at the caller level, here we verify the conditions)
        let evidence = ResidualEvidence {
            owner_ref_match: true,
            matching_labels: vec![],
            matching_managers: vec![],
            namespace_affinity: true,
            service_account_match: false,
        };
        let confidence = compute_confidence(&evidence);
        assert_ne!(confidence, ResidualConfidence::None);
        // In strong namespace + target evidence + foreign owner → fail closed
    }

    #[test]
    fn test_normalize_pod_owner_returns_foreign_enum() {
        let owner = k8s_openapi::apimachinery::pkg::apis::meta::v1::OwnerReference {
            api_version: "v1".to_string(),
            kind: "ConfigMap".to_string(),
            name: "cm".to_string(),
            uid: "uid".to_string(),
            controller: Some(true),
            block_owner_deletion: None,
        };
        let result = normalize_pod_owner(&owner, "ns", &HashMap::new(), &HashMap::new());
        match result {
            OwnerNormalization::Foreign { owner_gvk } => {
                assert!(owner_gvk.contains("ConfigMap"), "got: {}", owner_gvk);
            }
            other => panic!("expected Foreign, got: {:?}", other),
        }
    }

    #[test]
    fn test_normalize_pod_owner_returns_incomplete_for_missing() {
        let native = HashMap::from([make_native_workload(
            "ns",
            "StatefulSet",
            "other-sts",
            "other-uid",
        )]);
        let owner = k8s_openapi::apimachinery::pkg::apis::meta::v1::OwnerReference {
            api_version: "apps/v1".to_string(),
            kind: "StatefulSet".to_string(),
            name: "missing-sts".to_string(),
            uid: "uid".to_string(),
            controller: Some(true),
            block_owner_deletion: None,
        };
        let result = normalize_pod_owner(&owner, "ns", &HashMap::new(), &native);
        match result {
            OwnerNormalization::Incomplete {
                reason,
                missing_ref,
            } => {
                assert!(reason.contains("not found"), "got: {}", reason);
                let mref = missing_ref.expect("missing_ref should be set for 'not found' errors");
                assert_eq!(mref.kind, "StatefulSet");
                assert_eq!(mref.name, "missing-sts");
                assert_eq!(mref.namespace, Some("ns".to_string()));
            }
            other => panic!("expected Incomplete, got: {:?}", other),
        }
    }

    // ── Settled observation tests ──

    #[test]
    fn test_is_transient_matched_deleted_exact_identity() {
        let deleted = vec![make_rid(
            "apps",
            "DaemonSet",
            Some("ns"),
            "my-daemonset",
            Some("uid-1"),
        )];
        let err = AuditScanError {
            resource_type: "Pod/my-pod".to_string(),
            namespace: "ns".to_string(),
            error: "DaemonSet my-daemonset not found in native workload scan".to_string(),
            missing_owner_ref: Some(Box::new(ResourceId {
                group: "apps".to_string(),
                version: "v1".to_string(),
                kind: "DaemonSet".to_string(),
                namespace: Some("ns".to_string()),
                name: "my-daemonset".to_string(),
                uid: Some("uid-1".to_string()),
            })),
            ..Default::default()
        };
        assert!(is_transient_scan_error(&err, &deleted));
    }

    #[test]
    fn test_is_transient_wrong_kind_immediate() {
        let deleted = vec![make_rid(
            "apps",
            "DaemonSet",
            Some("ns"),
            "my-daemonset",
            Some("uid-1"),
        )];
        let err = AuditScanError {
            resource_type: "Pod/my-pod".to_string(),
            namespace: "ns".to_string(),
            error: "Deployment my-daemonset not found".to_string(),
            missing_owner_ref: Some(Box::new(ResourceId {
                group: "apps".to_string(),
                version: "v1".to_string(),
                kind: "Deployment".to_string(),
                namespace: Some("ns".to_string()),
                name: "my-daemonset".to_string(),
                uid: Some("uid-1".to_string()),
            })),
            ..Default::default()
        };
        assert!(
            !is_transient_scan_error(&err, &deleted),
            "wrong kind must be persistent"
        );
    }

    #[test]
    fn test_is_transient_wrong_namespace_immediate() {
        let deleted = vec![make_rid(
            "apps",
            "DaemonSet",
            Some("ns"),
            "my-daemonset",
            Some("uid-1"),
        )];
        let err = AuditScanError {
            resource_type: "Pod/my-pod".to_string(),
            namespace: "other-ns".to_string(),
            error: "DaemonSet my-daemonset not found".to_string(),
            missing_owner_ref: Some(Box::new(ResourceId {
                group: "apps".to_string(),
                version: "v1".to_string(),
                kind: "DaemonSet".to_string(),
                namespace: Some("other-ns".to_string()),
                name: "my-daemonset".to_string(),
                uid: Some("uid-1".to_string()),
            })),
            ..Default::default()
        };
        assert!(
            !is_transient_scan_error(&err, &deleted),
            "wrong namespace must be persistent"
        );
    }

    #[test]
    fn test_is_transient_wrong_uid_immediate() {
        let deleted = vec![make_rid(
            "apps",
            "DaemonSet",
            Some("ns"),
            "my-daemonset",
            Some("uid-1"),
        )];
        let err = AuditScanError {
            resource_type: "Pod/my-pod".to_string(),
            namespace: "ns".to_string(),
            error: "DaemonSet my-daemonset not found".to_string(),
            missing_owner_ref: Some(Box::new(ResourceId {
                group: "apps".to_string(),
                version: "v1".to_string(),
                kind: "DaemonSet".to_string(),
                namespace: Some("ns".to_string()),
                name: "my-daemonset".to_string(),
                uid: Some("uid-wrong".to_string()),
            })),
            ..Default::default()
        };
        assert!(
            !is_transient_scan_error(&err, &deleted),
            "wrong UID must be persistent"
        );
    }

    #[test]
    fn test_is_transient_unmatched_name_is_persistent() {
        let deleted = vec![make_rid(
            "apps",
            "DaemonSet",
            Some("ns"),
            "other-ds",
            Some("uid-2"),
        )];
        let err = AuditScanError {
            resource_type: "Pod/my-pod".to_string(),
            namespace: "ns".to_string(),
            error: "DaemonSet my-daemonset not found in native workload scan".to_string(),
            missing_owner_ref: Some(Box::new(ResourceId {
                group: "apps".to_string(),
                version: "v1".to_string(),
                kind: "DaemonSet".to_string(),
                namespace: Some("ns".to_string()),
                name: "my-daemonset".to_string(),
                uid: Some("uid-1".to_string()),
            })),
            ..Default::default()
        };
        assert!(
            !is_transient_scan_error(&err, &deleted),
            "unmatched name must be persistent"
        );
    }

    #[test]
    fn test_is_transient_no_missing_ref_is_persistent() {
        let deleted = vec![make_rid(
            "apps",
            "DaemonSet",
            Some("ns"),
            "my-daemonset",
            Some("uid-1"),
        )];
        let err = AuditScanError {
            resource_type: "Pod/my-pod".to_string(),
            namespace: "ns".to_string(),
            error: "some error".to_string(),
            missing_owner_ref: None,
            ..Default::default()
        };
        assert!(
            !is_transient_scan_error(&err, &deleted),
            "no missing_owner_ref must be persistent"
        );
    }

    #[test]
    fn test_is_transient_missing_uid_none_is_persistent() {
        let deleted = vec![make_rid(
            "apps",
            "DaemonSet",
            Some("ns"),
            "my-ds",
            Some("uid-1"),
        )];
        let err = AuditScanError {
            resource_type: "Pod/my-pod".to_string(),
            namespace: "ns".to_string(),
            error: "DaemonSet my-ds not found".to_string(),
            missing_owner_ref: Some(Box::new(ResourceId {
                group: "apps".to_string(),
                version: "v1".to_string(),
                kind: "DaemonSet".to_string(),
                namespace: Some("ns".to_string()),
                name: "my-ds".to_string(),
                uid: None,
            })),
            ..Default::default()
        };
        assert!(
            !is_transient_scan_error(&err, &deleted),
            "missing_owner_ref with uid=None must be persistent"
        );
    }

    #[test]
    fn test_is_transient_missing_uid_empty_is_persistent() {
        let deleted = vec![make_rid(
            "apps",
            "DaemonSet",
            Some("ns"),
            "my-ds",
            Some("uid-1"),
        )];
        let err = AuditScanError {
            resource_type: "Pod/my-pod".to_string(),
            namespace: "ns".to_string(),
            error: "DaemonSet my-ds not found".to_string(),
            missing_owner_ref: Some(Box::new(ResourceId {
                group: "apps".to_string(),
                version: "v1".to_string(),
                kind: "DaemonSet".to_string(),
                namespace: Some("ns".to_string()),
                name: "my-ds".to_string(),
                uid: Some("".to_string()),
            })),
            ..Default::default()
        };
        assert!(
            !is_transient_scan_error(&err, &deleted),
            "missing_owner_ref with uid=empty must be persistent"
        );
    }

    #[test]
    fn test_is_transient_deleted_uid_none_is_persistent() {
        let deleted = vec![make_rid("apps", "DaemonSet", Some("ns"), "my-ds", None)];
        let err = AuditScanError {
            resource_type: "Pod/my-pod".to_string(),
            namespace: "ns".to_string(),
            error: "DaemonSet my-ds not found".to_string(),
            missing_owner_ref: Some(Box::new(ResourceId {
                group: "apps".to_string(),
                version: "v1".to_string(),
                kind: "DaemonSet".to_string(),
                namespace: Some("ns".to_string()),
                name: "my-ds".to_string(),
                uid: Some("uid-1".to_string()),
            })),
            ..Default::default()
        };
        assert!(
            !is_transient_scan_error(&err, &deleted),
            "deleted resource with uid=None must be persistent"
        );
    }

    #[test]
    fn test_is_transient_deleted_uid_empty_is_persistent() {
        let deleted = vec![make_rid("apps", "DaemonSet", Some("ns"), "my-ds", Some(""))];
        let err = AuditScanError {
            resource_type: "Pod/my-pod".to_string(),
            namespace: "ns".to_string(),
            error: "DaemonSet my-ds not found".to_string(),
            missing_owner_ref: Some(Box::new(ResourceId {
                group: "apps".to_string(),
                version: "v1".to_string(),
                kind: "DaemonSet".to_string(),
                namespace: Some("ns".to_string()),
                name: "my-ds".to_string(),
                uid: Some("uid-1".to_string()),
            })),
            ..Default::default()
        };
        assert!(
            !is_transient_scan_error(&err, &deleted),
            "deleted resource with uid=empty must be persistent"
        );
    }

    #[test]
    fn test_is_persistent_scan_error_forbidden() {
        let err = AuditScanError {
            resource_type: "Deployment".to_string(),
            namespace: "ns".to_string(),
            error: "Forbidden: 403".to_string(),
            missing_owner_ref: None,
            ..Default::default()
        };
        assert!(!is_transient_scan_error(&err, &[]));
    }

    #[test]
    fn test_is_persistent_scan_error_timeout() {
        let err = AuditScanError {
            resource_type: "Pod".to_string(),
            namespace: "ns".to_string(),
            error: "request timeout after 30s".to_string(),
            missing_owner_ref: None,
            ..Default::default()
        };
        assert!(!is_transient_scan_error(&err, &[]));
    }

    #[test]
    fn test_is_persistent_scan_error_ambiguous() {
        let err = AuditScanError {
            resource_type: "Pod/x".to_string(),
            namespace: "ns".to_string(),
            error: "ambiguous multi-owner fail closed".to_string(),
            missing_owner_ref: None,
            ..Default::default()
        };
        assert!(!is_transient_scan_error(&err, &[]));
    }

    #[test]
    fn test_is_persistent_scan_error_typemeta_mismatch() {
        let err = AuditScanError {
            resource_type: "CronJob".to_string(),
            namespace: "ns".to_string(),
            error: "LIST item TypeMeta mismatch: expected batch/v1/CronJob".to_string(),
            missing_owner_ref: None,
            ..Default::default()
        };
        assert!(!is_transient_scan_error(&err, &[]));
    }

    #[test]
    fn test_is_persistent_unknown_error() {
        let err = AuditScanError {
            resource_type: "X".to_string(),
            namespace: "ns".to_string(),
            error: "some completely unknown error".to_string(),
            missing_owner_ref: None,
            ..Default::default()
        };
        assert!(!is_transient_scan_error(&err, &[]));
    }

    #[test]
    fn test_is_persistent_deletion_timestamp_not_transient() {
        // deletionTimestamp alone is not transient — requires matched deleted name
        let err = AuditScanError {
            resource_type: "Pod/x".to_string(),
            namespace: "ns".to_string(),
            error: "resource has deletionTimestamp set".to_string(),
            missing_owner_ref: None,
            ..Default::default()
        };
        assert!(
            !is_transient_scan_error(&err, &[]),
            "deletionTimestamp without name match is persistent"
        );
    }

    // ── Terminating-dependent transient tests ──

    #[test]
    fn terminating_target_evidenced_pod_settles() {
        let err = AuditScanError {
            resource_type: "Pod/gpu-pod".to_string(),
            namespace: "ns".to_string(),
            error: "DaemonSet nvidia-ds not found in native workload scan".to_string(),
            missing_owner_ref: Some(Box::new(ResourceId {
                group: "apps".to_string(),
                version: "v1".to_string(),
                kind: "DaemonSet".to_string(),
                namespace: Some("ns".to_string()),
                name: "nvidia-ds".to_string(),
                uid: Some("ds-uid-99".to_string()),
            })),
            dependent_uid: Some("pod-uid-1".to_string()),
            dependent_is_terminating: true,
            dependent_has_target_evidence: true,
        };
        assert!(
            is_transient_scan_error(&err, &[]),
            "terminating pod with target evidence and supported owner should be transient"
        );
    }

    #[test]
    fn non_terminating_orphan_with_evidence_is_transient() {
        let err = AuditScanError {
            resource_type: "Pod/gpu-pod".to_string(),
            namespace: "ns".to_string(),
            error: "DaemonSet nvidia-ds not found".to_string(),
            missing_owner_ref: Some(Box::new(ResourceId {
                group: "apps".to_string(),
                version: "v1".to_string(),
                kind: "DaemonSet".to_string(),
                namespace: Some("ns".to_string()),
                name: "nvidia-ds".to_string(),
                uid: Some("ds-uid-99".to_string()),
            })),
            dependent_uid: Some("pod-uid-1".to_string()),
            dependent_is_terminating: false,
            dependent_has_target_evidence: true,
        };
        assert!(
            is_transient_scan_error(&err, &[]),
            "orphan pod with UID + evidence + supported GVK is retry-eligible"
        );
    }

    #[test]
    fn missing_pod_uid_not_transient() {
        let err = AuditScanError {
            resource_type: "Pod/gpu-pod".to_string(),
            namespace: "ns".to_string(),
            error: "DaemonSet nvidia-ds not found".to_string(),
            missing_owner_ref: Some(Box::new(ResourceId {
                group: "apps".to_string(),
                version: "v1".to_string(),
                kind: "DaemonSet".to_string(),
                namespace: Some("ns".to_string()),
                name: "nvidia-ds".to_string(),
                uid: Some("ds-uid-99".to_string()),
            })),
            dependent_uid: None,
            dependent_is_terminating: true,
            dependent_has_target_evidence: true,
        };
        assert!(
            !is_transient_scan_error(&err, &[]),
            "pod without UID must not be transient"
        );
    }

    #[test]
    fn no_evidence_pod_not_transient() {
        let err = AuditScanError {
            resource_type: "Pod/gpu-pod".to_string(),
            namespace: "ns".to_string(),
            error: "DaemonSet nvidia-ds not found".to_string(),
            missing_owner_ref: Some(Box::new(ResourceId {
                group: "apps".to_string(),
                version: "v1".to_string(),
                kind: "DaemonSet".to_string(),
                namespace: Some("ns".to_string()),
                name: "nvidia-ds".to_string(),
                uid: Some("ds-uid-99".to_string()),
            })),
            dependent_uid: Some("pod-uid-1".to_string()),
            dependent_is_terminating: true,
            dependent_has_target_evidence: false,
        };
        assert!(
            !is_transient_scan_error(&err, &[]),
            "pod without target evidence must not be transient"
        );
    }

    #[test]
    fn exact_deleted_parent_still_works() {
        let deleted = vec![make_rid(
            "apps",
            "DaemonSet",
            Some("ns"),
            "my-ds",
            Some("uid-1"),
        )];
        let err = AuditScanError {
            resource_type: "Pod/my-pod".to_string(),
            namespace: "ns".to_string(),
            error: "DaemonSet my-ds not found".to_string(),
            missing_owner_ref: Some(Box::new(ResourceId {
                group: "apps".to_string(),
                version: "v1".to_string(),
                kind: "DaemonSet".to_string(),
                namespace: Some("ns".to_string()),
                name: "my-ds".to_string(),
                uid: Some("uid-1".to_string()),
            })),
            ..Default::default()
        };
        assert!(
            is_transient_scan_error(&err, &deleted),
            "exact deleted-parent match (path 1) must still work"
        );
    }

    #[test]
    fn custom_group_daemonset_not_transient() {
        let err = AuditScanError {
            resource_type: "Pod/custom-pod".to_string(),
            namespace: "ns".to_string(),
            error: "DaemonSet custom-ds not found".to_string(),
            missing_owner_ref: Some(Box::new(ResourceId {
                group: "custom.io".to_string(),
                version: "v1".to_string(),
                kind: "DaemonSet".to_string(),
                namespace: Some("ns".to_string()),
                name: "custom-ds".to_string(),
                uid: Some("ds-uid-custom".to_string()),
            })),
            dependent_uid: Some("pod-uid-1".to_string()),
            dependent_is_terminating: true,
            dependent_has_target_evidence: true,
        };
        assert!(
            !is_transient_scan_error(&err, &[]),
            "custom.io/v1/DaemonSet must not be treated as supported workload"
        );
    }

    #[test]
    fn wrong_version_daemonset_not_transient() {
        let err = AuditScanError {
            resource_type: "Pod/v2-pod".to_string(),
            namespace: "ns".to_string(),
            error: "DaemonSet v2-ds not found".to_string(),
            missing_owner_ref: Some(Box::new(ResourceId {
                group: "apps".to_string(),
                version: "v2".to_string(),
                kind: "DaemonSet".to_string(),
                namespace: Some("ns".to_string()),
                name: "v2-ds".to_string(),
                uid: Some("ds-uid-v2".to_string()),
            })),
            dependent_uid: Some("pod-uid-1".to_string()),
            dependent_is_terminating: true,
            dependent_has_target_evidence: true,
        };
        assert!(
            !is_transient_scan_error(&err, &[]),
            "apps/v2/DaemonSet must not be treated as supported workload"
        );
    }

    // ── settle_loop tests ──

    fn make_empty_audit() -> ResidualAudit {
        ResidualAudit {
            planned_delete_still_present: vec![],
            planned_expect_still_present: vec![],
            expected_preserved: vec![],
            likely_operator_residual: vec![],
            unattributed: vec![],
            coverage: AuditCoverage {
                requested_probes: 0,
                succeeded_probes: 0,
            },
            scan_errors: vec![],
            target_operators_absent: true,
            residual_workloads: vec![],
            incomplete_scopes: vec![],
        }
    }

    fn make_transient_error(rid: &ResourceId) -> AuditScanError {
        AuditScanError {
            resource_type: "Pod/test-pod".to_string(),
            namespace: rid.namespace.clone().unwrap_or_default(),
            error: format!(
                "{} {} not found in native workload scan",
                rid.kind, rid.name
            ),
            missing_owner_ref: Some(Box::new(rid.clone())),
            ..Default::default()
        }
    }

    fn make_obs_with_errors(errors: Vec<AuditScanError>) -> AuditObservation {
        let mut audit = make_empty_audit();
        audit.scan_errors = errors;
        AuditObservation {
            generation: OperatorGenerationState::Absent,
            audit: Some(audit),
        }
    }

    fn make_clean_obs() -> AuditObservation {
        AuditObservation {
            generation: OperatorGenerationState::Absent,
            audit: Some(make_empty_audit()),
        }
    }

    #[tokio::test(start_paused = true)]
    async fn test_settle_poll1_2_present_poll3_gone() {
        let rid = make_rid("apps", "DaemonSet", Some("ns"), "my-ds", Some("uid-1"));
        let deleted = vec![rid.clone()];
        let call_count = std::sync::Arc::new(std::sync::atomic::AtomicU32::new(0));
        let cc = call_count.clone();

        let cancel = tokio_util::sync::CancellationToken::new();
        let result = settle_loop(
            || {
                let n = cc.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                let rid = rid.clone();
                async move {
                    if n < 2 {
                        Ok(make_obs_with_errors(vec![make_transient_error(&rid)]))
                    } else {
                        Ok(make_clean_obs())
                    }
                }
            },
            &deleted,
            std::time::Duration::from_secs(120),
            &cancel,
        )
        .await
        .unwrap();

        assert_eq!(result.attempts, 3);
        assert!(result.last_transient_blockers.is_empty());
        assert!(result.observation.audit.unwrap().scan_errors.is_empty());
        assert_eq!(
            call_count.load(std::sync::atomic::Ordering::SeqCst),
            3,
            "fresh request count"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn test_settle_persistent_error_immediate() {
        let call_count = std::sync::Arc::new(std::sync::atomic::AtomicU32::new(0));
        let cc = call_count.clone();

        let cancel = tokio_util::sync::CancellationToken::new();
        let result = settle_loop(
            || {
                cc.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                async {
                    let mut audit = make_empty_audit();
                    audit.scan_errors.push(AuditScanError {
                        resource_type: "Deployment".to_string(),
                        namespace: "ns".to_string(),
                        error: "Forbidden: 403".to_string(),
                        missing_owner_ref: None,
                        ..Default::default()
                    });
                    Ok(AuditObservation {
                        generation: OperatorGenerationState::Absent,
                        audit: Some(audit),
                    })
                }
            },
            &[],
            std::time::Duration::from_secs(120),
            &cancel,
        )
        .await
        .unwrap();

        assert_eq!(result.attempts, 1, "persistent error returns immediately");
        assert_eq!(
            call_count.load(std::sync::atomic::Ordering::SeqCst),
            1,
            "only one request for persistent error"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn test_settle_500_immediate() {
        let cancel = tokio_util::sync::CancellationToken::new();
        let call_count = std::sync::Arc::new(std::sync::atomic::AtomicU32::new(0));
        let cc = call_count.clone();

        let result = settle_loop(
            || {
                cc.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                async {
                    let mut audit = make_empty_audit();
                    audit.scan_errors.push(AuditScanError {
                        resource_type: "Pod".to_string(),
                        namespace: "ns".to_string(),
                        error: "Internal Server Error: 500".to_string(),
                        missing_owner_ref: None,
                        ..Default::default()
                    });
                    Ok(AuditObservation {
                        generation: OperatorGenerationState::Absent,
                        audit: Some(audit),
                    })
                }
            },
            &[],
            std::time::Duration::from_secs(120),
            &cancel,
        )
        .await
        .unwrap();

        assert_eq!(result.attempts, 1, "500 error returns immediately");
    }

    #[tokio::test(start_paused = true)]
    async fn test_settle_never_gone_deadline() {
        let rid = make_rid("apps", "DaemonSet", Some("ns"), "my-ds", Some("uid-1"));
        let deleted = vec![rid.clone()];

        let cancel = tokio_util::sync::CancellationToken::new();
        let call_count = std::sync::Arc::new(std::sync::atomic::AtomicU32::new(0));
        let cc = call_count.clone();

        let result = settle_loop(
            || {
                cc.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                let rid = rid.clone();
                async move { Ok(make_obs_with_errors(vec![make_transient_error(&rid)])) }
            },
            &deleted,
            std::time::Duration::from_secs(9),
            &cancel,
        )
        .await
        .unwrap();

        assert!(
            result.attempts >= 2,
            "should retry until deadline, got {} attempts",
            result.attempts
        );
        assert!(
            !result.last_transient_blockers.is_empty(),
            "transient blockers remain at deadline"
        );
        assert!(
            !result.observation.audit.unwrap().scan_errors.is_empty(),
            "scan errors still present"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn test_settle_cancellation() {
        let rid = make_rid("apps", "DaemonSet", Some("ns"), "my-ds", Some("uid-1"));
        let deleted = vec![rid.clone()];

        let cancel = tokio_util::sync::CancellationToken::new();
        let cancel_clone = cancel.clone();

        let call_count = std::sync::Arc::new(std::sync::atomic::AtomicU32::new(0));
        let cc = call_count.clone();

        let handle = tokio::spawn(async move {
            settle_loop(
                || {
                    let n = cc.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                    let rid = rid.clone();
                    let cancel_inner = cancel_clone.clone();
                    async move {
                        if n == 1 {
                            cancel_inner.cancel();
                        }
                        Ok(make_obs_with_errors(vec![make_transient_error(&rid)]))
                    }
                },
                &deleted,
                std::time::Duration::from_secs(120),
                &cancel,
            )
            .await
        });

        let result = handle.await.unwrap().unwrap();
        assert!(
            result.attempts <= 3,
            "should stop after cancellation, got {} attempts",
            result.attempts
        );
    }

    #[tokio::test(start_paused = true)]
    async fn test_settle_wrong_kind_immediate_no_retry() {
        let deleted = vec![make_rid(
            "apps",
            "DaemonSet",
            Some("ns"),
            "my-ds",
            Some("uid-1"),
        )];

        let cancel = tokio_util::sync::CancellationToken::new();
        let call_count = std::sync::Arc::new(std::sync::atomic::AtomicU32::new(0));
        let cc = call_count.clone();

        let result = settle_loop(
            || {
                cc.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                async {
                    let mut audit = make_empty_audit();
                    audit.scan_errors.push(AuditScanError {
                        resource_type: "Pod/test".to_string(),
                        namespace: "ns".to_string(),
                        error: "Deployment my-ds not found".to_string(),
                        missing_owner_ref: Some(Box::new(ResourceId {
                            group: "apps".to_string(),
                            version: "v1".to_string(),
                            kind: "Deployment".to_string(),
                            namespace: Some("ns".to_string()),
                            name: "my-ds".to_string(),
                            uid: Some("uid-1".to_string()),
                        })),
                        ..Default::default()
                    });
                    Ok(AuditObservation {
                        generation: OperatorGenerationState::Absent,
                        audit: Some(audit),
                    })
                }
            },
            &deleted,
            std::time::Duration::from_secs(120),
            &cancel,
        )
        .await
        .unwrap();

        assert_eq!(result.attempts, 1, "wrong kind should not retry");
    }

    // ── Tower production test: observe_residual_state_until_settled ──

    #[tokio::test(start_paused = true)]
    async fn test_tower_settle_poll1_2_blocker_poll3_clean() {
        use std::pin::pin;
        use std::sync::atomic::{AtomicUsize, Ordering};

        let ds_rid = make_rid(
            "apps",
            "DaemonSet",
            Some("test-ns"),
            "my-ds",
            Some("ds-uid-1"),
        );

        let mut journal = make_tower_journal();
        journal.execution.deleted.push(ds_rid);

        let request_count = std::sync::Arc::new(AtomicUsize::new(0));
        let rc = request_count.clone();
        let poll_number = std::sync::Arc::new(AtomicUsize::new(0));
        let pn = poll_number.clone();

        let (mock_service, handle) = tower_test::mock::pair::<
            http::Request<kube::client::Body>,
            http::Response<kube::client::Body>,
        >();
        let client = kube::Client::new(mock_service, "default");

        let spawned = tokio::spawn(async move {
            let mut handle = pin!(handle);
            let mut seen_sub_list_count = 0usize;
            while let Some((req, send)) = handle.next_request().await {
                rc.fetch_add(1, Ordering::SeqCst);
                let path = req.uri().path().to_string();

                if path == SUB_LIST {
                    seen_sub_list_count += 1;
                    pn.store(seen_sub_list_count, Ordering::SeqCst);
                }

                if let Some(resp) = handle_generation_absent(&path) {
                    send.send_response(resp);
                } else if path == POD_LIST {
                    let current_poll = pn.load(Ordering::SeqCst);
                    if current_poll <= 2 {
                        // Polls 1-2: return a pod owned by deleted DaemonSet
                        send.send_response(tower_json_response(serde_json::json!({
                            "apiVersion": "v1", "kind": "PodList",
                            "metadata": {"resourceVersion": "1"},
                            "items": [{
                                "apiVersion": "v1", "kind": "Pod",
                                "metadata": {
                                    "name": "my-ds-pod",
                                    "namespace": "test-ns",
                                    "uid": "pod-uid-1",
                                    "ownerReferences": [{
                                        "apiVersion": "apps/v1",
                                        "kind": "DaemonSet",
                                        "name": "my-ds",
                                        "uid": "ds-uid-1",
                                        "controller": true
                                    }]
                                }
                            }]
                        })));
                    } else {
                        // Poll 3: pod is gone
                        send.send_response(tower_empty_list());
                    }
                } else if let Some(resp) = handle_audit_scan_default(&path) {
                    send.send_response(resp);
                } else {
                    panic!(
                        "test_tower_settle: unexpected request: {} (poll {})",
                        path,
                        pn.load(Ordering::SeqCst)
                    );
                }
            }
        });

        let cancel = tokio_util::sync::CancellationToken::new();
        let result = super::observe_residual_state_until_settled(
            &client,
            &journal,
            std::time::Duration::from_secs(120),
            &cancel,
        )
        .await;
        drop(client);
        spawned.await.unwrap();

        let settled = result.unwrap();
        assert_eq!(settled.attempts, 3, "should settle on 3rd attempt");
        assert!(
            settled.last_transient_blockers.is_empty(),
            "settled audit should have no transient blockers"
        );
        let audit = settled
            .observation
            .audit
            .expect("settled should have audit");
        assert!(
            audit.scan_errors.is_empty(),
            "settled audit should have no scan errors, got: {:?}",
            audit.scan_errors
        );

        let total_requests = request_count.load(Ordering::SeqCst);
        let requests_per_poll = total_requests / 3;
        assert!(
            requests_per_poll > 1,
            "each poll should make multiple fresh requests (fresh planner), got {} total for 3 polls",
            total_requests
        );
    }

    // ── Tower test: terminating GPU pod settle ──

    #[tokio::test(start_paused = true)]
    async fn settle_loop_resolves_orphaned_gpu_pods() {
        use std::pin::pin;
        use std::sync::atomic::{AtomicUsize, Ordering};

        // No deleted resources in the plan — DaemonSets were side-effect deletions
        let mut journal = make_tower_journal();
        // Populate csv_names so label evidence matching works
        journal
            .audit_context
            .csv_names
            .insert("test-pkg.v1".to_string());

        let request_count = std::sync::Arc::new(AtomicUsize::new(0));
        let rc = request_count.clone();
        let poll_number = std::sync::Arc::new(AtomicUsize::new(0));
        let pn = poll_number.clone();

        let (mock_service, handle) = tower_test::mock::pair::<
            http::Request<kube::client::Body>,
            http::Response<kube::client::Body>,
        >();
        let client = kube::Client::new(mock_service, "default");

        let spawned = tokio::spawn(async move {
            let mut handle = pin!(handle);
            let mut seen_sub_list_count = 0usize;
            while let Some((req, send)) = handle.next_request().await {
                rc.fetch_add(1, Ordering::SeqCst);
                let path = req.uri().path().to_string();

                if path == SUB_LIST {
                    seen_sub_list_count += 1;
                    pn.store(seen_sub_list_count, Ordering::SeqCst);
                }

                if let Some(resp) = handle_generation_absent(&path) {
                    send.send_response(resp);
                } else if path == POD_LIST {
                    let current_poll = pn.load(Ordering::SeqCst);
                    if current_poll <= 2 {
                        // Polls 1-2: orphan pod owned by side-effect-deleted DaemonSet
                        // Pod has target labels (olm.owner) but NO deletionTimestamp
                        // (GC hasn't processed orphan yet)
                        send.send_response(tower_json_response(serde_json::json!({
                            "apiVersion": "v1", "kind": "PodList",
                            "metadata": {"resourceVersion": "1"},
                            "items": [{
                                "apiVersion": "v1", "kind": "Pod",
                                "metadata": {
                                    "name": "nvidia-dcgm-exporter-abc",
                                    "namespace": "test-ns",
                                    "uid": "gpu-pod-uid-1",
                                    "labels": {
                                        "olm.owner": "test-pkg.v1",
                                        "app": "nvidia-dcgm-exporter"
                                    },
                                    "managedFields": [{
                                        "manager": "test-pkg-controller",
                                        "operation": "Apply"
                                    }],
                                    "ownerReferences": [{
                                        "apiVersion": "apps/v1",
                                        "kind": "DaemonSet",
                                        "name": "nvidia-dcgm-exporter",
                                        "uid": "gpu-ds-uid-1",
                                        "controller": true
                                    }]
                                }
                            }]
                        })));
                    } else {
                        // Poll 3: pod is gone
                        send.send_response(tower_empty_list());
                    }
                } else if path == DS_LIST {
                    // DaemonSet was deleted as side effect — always empty
                    send.send_response(tower_empty_list());
                } else if let Some(resp) = handle_audit_scan_default(&path) {
                    send.send_response(resp);
                } else {
                    panic!(
                        "settle_loop_resolves_terminating_gpu_pods: unexpected request: {} (poll {})",
                        path,
                        pn.load(Ordering::SeqCst)
                    );
                }
            }
        });

        let cancel = tokio_util::sync::CancellationToken::new();
        let result = super::observe_residual_state_until_settled(
            &client,
            &journal,
            std::time::Duration::from_secs(120),
            &cancel,
        )
        .await;
        drop(client);
        spawned.await.unwrap();

        let settled = result.unwrap();
        assert_eq!(settled.attempts, 3, "should settle on 3rd attempt");
        assert!(
            settled.last_transient_blockers.is_empty(),
            "settled audit should have no transient blockers"
        );
        let audit = settled
            .observation
            .audit
            .expect("settled should have audit");
        assert!(
            audit.scan_errors.is_empty(),
            "settled audit should have no scan errors, got: {:?}",
            audit.scan_errors
        );
    }

    #[tokio::test]
    async fn settle_loop_deadline_orphan_persists_incomplete() {
        let err = AuditScanError {
            resource_type: "Pod/nvidia-dcgm-exporter-abc".to_string(),
            namespace: "ns".to_string(),
            error: "DaemonSet nvidia-dcgm-exporter not found".to_string(),
            missing_owner_ref: Some(Box::new(ResourceId {
                group: "apps".to_string(),
                version: "v1".to_string(),
                kind: "DaemonSet".to_string(),
                namespace: Some("ns".to_string()),
                name: "nvidia-dcgm-exporter".to_string(),
                uid: Some("ds-uid-1".to_string()),
            })),
            dependent_uid: Some("pod-uid-1".to_string()),
            dependent_is_terminating: false,
            dependent_has_target_evidence: true,
        };
        assert!(
            is_transient_scan_error(&err, &[]),
            "orphan with evidence is retry-eligible"
        );

        let cancel = tokio_util::sync::CancellationToken::new();
        let settled = super::settle_loop(
            || async {
                let mut audit = make_empty_audit();
                audit.scan_errors.push(AuditScanError {
                    resource_type: "Pod/nvidia-dcgm-exporter-abc".to_string(),
                    namespace: "ns".to_string(),
                    error: "DaemonSet nvidia-dcgm-exporter not found".to_string(),
                    missing_owner_ref: Some(Box::new(ResourceId {
                        group: "apps".to_string(),
                        version: "v1".to_string(),
                        kind: "DaemonSet".to_string(),
                        namespace: Some("ns".to_string()),
                        name: "nvidia-dcgm-exporter".to_string(),
                        uid: Some("ds-uid-1".to_string()),
                    })),
                    dependent_uid: Some("pod-uid-1".to_string()),
                    dependent_is_terminating: false,
                    dependent_has_target_evidence: true,
                });
                Ok(AuditObservation {
                    generation: OperatorGenerationState::Absent,
                    audit: Some(audit),
                })
            },
            &[],
            std::time::Duration::from_millis(50),
            &cancel,
        )
        .await
        .unwrap();

        assert!(
            settled.attempts >= 2,
            "should have retried at least once, got {} attempts",
            settled.attempts
        );
        let audit = settled.observation.audit.expect("should have audit");
        assert!(
            !audit.scan_errors.is_empty(),
            "persistent orphan should leave scan errors"
        );
        assert!(
            !settled.last_transient_blockers.is_empty(),
            "should report transient blockers at deadline"
        );
    }

    // ── has_positive_target_evidence tests ──

    #[test]
    fn test_positive_evidence_owner_ref() {
        let e = ResidualEvidence {
            owner_ref_match: true,
            ..empty_evidence()
        };
        assert!(has_positive_target_evidence(&e));
    }

    #[test]
    fn test_positive_evidence_sa_match() {
        let e = ResidualEvidence {
            service_account_match: true,
            ..empty_evidence()
        };
        assert!(has_positive_target_evidence(&e));
    }

    #[test]
    fn test_positive_evidence_manager_plus_label() {
        let e = ResidualEvidence {
            matching_managers: vec!["controller".to_string()],
            matching_labels: vec![("app".to_string(), "test".to_string())],
            ..empty_evidence()
        };
        assert!(has_positive_target_evidence(&e));
    }

    #[test]
    fn test_not_positive_label_only() {
        let e = ResidualEvidence {
            matching_labels: vec![("app".to_string(), "test".to_string())],
            ..empty_evidence()
        };
        assert!(!has_positive_target_evidence(&e));
    }

    #[test]
    fn test_not_positive_manager_only() {
        let e = ResidualEvidence {
            matching_managers: vec!["controller".to_string()],
            ..empty_evidence()
        };
        assert!(!has_positive_target_evidence(&e));
    }

    #[test]
    fn test_not_positive_namespace_only() {
        let e = ResidualEvidence {
            namespace_affinity: true,
            ..empty_evidence()
        };
        assert!(!has_positive_target_evidence(&e));
    }

    #[tokio::test]
    async fn generation_transport_recovery_reaches_absent() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        let call_count = std::sync::Arc::new(AtomicUsize::new(0));
        let cc = call_count.clone();

        let svc = tower::service_fn(move |req: http::Request<kube::client::Body>| {
            let call = cc.fetch_add(1, Ordering::SeqCst);
            let path = req.uri().path().to_string();
            async move {
                if path.contains("/subscriptions") && call < 2 {
                    return Err(Box::new(std::io::Error::new(
                        std::io::ErrorKind::ConnectionRefused,
                        "connection refused",
                    ))
                        as Box<dyn std::error::Error + Send + Sync>);
                }
                if path.contains("/subscriptions") {
                    let body = serde_json::to_vec(&serde_json::json!({
                        "apiVersion": "operators.coreos.com/v1alpha1",
                        "kind": "SubscriptionList",
                        "metadata": {"resourceVersion": "1"},
                        "items": []
                    }))
                    .unwrap();
                    return Ok(http::Response::builder()
                        .status(200)
                        .body(kube::client::Body::from(body))
                        .unwrap());
                }
                if path.contains("/clusterserviceversions/") {
                    let body = serde_json::to_vec(&serde_json::json!({
                        "kind": "Status", "apiVersion": "v1", "metadata": {},
                        "status": "Failure", "message": "not found", "code": 404
                    }))
                    .unwrap();
                    return Ok(http::Response::builder()
                        .status(404)
                        .body(kube::client::Body::from(body))
                        .unwrap());
                }
                if path.contains("/deployments/") {
                    let body = serde_json::to_vec(&serde_json::json!({
                        "kind": "Status", "apiVersion": "v1", "metadata": {},
                        "status": "Failure", "message": "not found", "code": 404
                    }))
                    .unwrap();
                    return Ok(http::Response::builder()
                        .status(404)
                        .body(kube::client::Body::from(body))
                        .unwrap());
                }
                let body = serde_json::to_vec(&serde_json::json!({
                    "apiVersion": "v1", "kind": "List",
                    "metadata": {"resourceVersion": "1"}, "items": []
                }))
                .unwrap();
                Ok(http::Response::builder()
                    .status(200)
                    .body(kube::client::Body::from(body))
                    .unwrap())
            }
        });

        let client = kube::Client::new(svc, "test-ns");

        let csv_rid = make_rid(
            "operators.coreos.com",
            "ClusterServiceVersion",
            Some("test-ns"),
            "test-pkg.v1",
            Some("csv-uid-1"),
        );
        let snapshot = crate::teardown::plan::OperatorIdentitySnapshot {
            generation_identity: crate::teardown::plan::OperatorGenerationIdentity::OlmPackage {
                package_name: "test-pkg".to_string(),
                install_namespace: "test-ns".to_string(),
            },
            operator_id: crate::analyzers::olm::OperatorId {
                csv_name: "test-pkg.v1".to_string(),
                namespace: "test-ns".to_string(),
            },
            csv_name: "test-pkg.v1".to_string(),
            csv: crate::teardown::plan::ObservedResourceIdentity {
                resource: csv_rid,
                uid: "csv-uid-1".to_string(),
            },
            subscriptions: vec![],
            controller_deployments: vec![],
            service_accounts: vec![],
            owned_crds: vec![],
            required_crds: vec![],
        };

        let baseline = Some(vec![]);
        let result = super::check_operator_generation_fresh(&client, &snapshot, &baseline).await;
        assert!(
            matches!(result, OperatorGenerationState::Absent),
            "transport recovery should reach Absent, got {:?}",
            result
        );
        assert!(
            call_count.load(Ordering::SeqCst) >= 3,
            "should have retried: {} calls",
            call_count.load(Ordering::SeqCst)
        );
    }

    #[tokio::test]
    async fn generation_transport_exhausted_remains_unknown() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        let call_count = std::sync::Arc::new(AtomicUsize::new(0));
        let cc = call_count.clone();

        let svc = tower::service_fn(move |_req: http::Request<kube::client::Body>| {
            cc.fetch_add(1, Ordering::SeqCst);
            async move {
                Err::<http::Response<kube::client::Body>, _>(Box::new(std::io::Error::new(
                    std::io::ErrorKind::ConnectionRefused,
                    "connection refused",
                ))
                    as Box<dyn std::error::Error + Send + Sync>)
            }
        });

        let client = kube::Client::new(svc, "test-ns");

        let csv_rid = make_rid(
            "operators.coreos.com",
            "ClusterServiceVersion",
            Some("test-ns"),
            "test-pkg.v1",
            Some("csv-uid-1"),
        );
        let snapshot = crate::teardown::plan::OperatorIdentitySnapshot {
            generation_identity: crate::teardown::plan::OperatorGenerationIdentity::OlmPackage {
                package_name: "test-pkg".to_string(),
                install_namespace: "test-ns".to_string(),
            },
            operator_id: crate::analyzers::olm::OperatorId {
                csv_name: "test-pkg.v1".to_string(),
                namespace: "test-ns".to_string(),
            },
            csv_name: "test-pkg.v1".to_string(),
            csv: crate::teardown::plan::ObservedResourceIdentity {
                resource: csv_rid,
                uid: "csv-uid-1".to_string(),
            },
            subscriptions: vec![],
            controller_deployments: vec![],
            service_accounts: vec![],
            owned_crds: vec![],
            required_crds: vec![],
        };

        let result = super::check_operator_generation_fresh(&client, &snapshot, &None).await;
        assert!(
            matches!(result, OperatorGenerationState::Unknown(_)),
            "exhausted transport should be Unknown, got {:?}",
            result
        );
        assert_eq!(
            call_count.load(Ordering::SeqCst),
            3,
            "initial + 2 retries = 3 requests"
        );
    }
}
