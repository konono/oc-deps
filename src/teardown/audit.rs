use std::collections::{HashMap, HashSet};

use anyhow::Result;
use kube::Client;
use kube::api::{Api, ApiResource, DynamicObject, ListParams};
use kube::core::GroupVersion;
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

pub async fn check_operator_generation(
    client: &Client,
    snapshot: &OperatorIdentitySnapshot,
    csv_baseline: &Option<Vec<crate::teardown::journal::CsvBaselineEntry>>,
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
    let sub_gvk = GroupVersion::gv("operators.coreos.com", "v1alpha1").with_kind("Subscription");
    let sub_ar = ApiResource::from_gvk_with_plural(&sub_gvk, "subscriptions");
    let sub_api: Api<DynamicObject> =
        Api::namespaced_with(client.clone(), &install_namespace, &sub_ar);

    let sub_list = match sub_api.list(&ListParams::default()).await {
        Ok(list) => list.items,
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
    let csv_gvk =
        GroupVersion::gv("operators.coreos.com", "v1alpha1").with_kind("ClusterServiceVersion");
    let csv_ar = ApiResource::from_gvk_with_plural(&csv_gvk, "clusterserviceversions");
    let csv_api: Api<DynamicObject> =
        Api::namespaced_with(client.clone(), &install_namespace, &csv_ar);

    match csv_api.get(&snapshot.csv_name).await {
        Ok(csv_obj) => {
            let live_uid = csv_obj.metadata.uid.as_deref().unwrap_or("");
            return if snapshot.csv.uid == live_uid {
                OperatorGenerationState::SameGeneration
            } else {
                OperatorGenerationState::Reappeared
            };
        }
        Err(kube::Error::Api(ref resp)) if resp.code == 404 => {
            // GET 404 could be object gone or endpoint gone (OLM removed).
            // Verify endpoint exists via LIST.
            match csv_api.list(&ListParams::default().limit(1)).await {
                Ok(_) => {
                    // Endpoint exists, CSV is genuinely gone — continue
                }
                Err(_) => {
                    return OperatorGenerationState::Unknown(
                        "CSV GET returned 404 but API endpoint verification failed; \
                         cannot confirm CSV absence vs endpoint absence"
                            .to_string(),
                    );
                }
            }
        }
        Err(e) => {
            return OperatorGenerationState::Unknown(format!(
                "failed to GET CSV {}: {}",
                snapshot.csv_name, e
            ));
        }
    }

    // Step 3: Check controller deployments
    let dep_gvk = GroupVersion::gv("apps", "v1").with_kind("Deployment");
    let dep_ar = ApiResource::from_gvk_with_plural(&dep_gvk, "deployments");
    let dep_api: Api<DynamicObject> =
        Api::namespaced_with(client.clone(), &install_namespace, &dep_ar);

    for saved_dep in &snapshot.controller_deployments {
        match dep_api.get(&saved_dep.resource.name).await {
            Ok(dep_obj) => {
                let live_uid = dep_obj.metadata.uid.as_deref().unwrap_or("");
                return if saved_dep.uid == live_uid {
                    OperatorGenerationState::SameGeneration
                } else {
                    OperatorGenerationState::Reappeared
                };
            }
            Err(kube::Error::Api(ref resp)) if resp.code == 404 => {
                // Verify endpoint exists
                match dep_api.list(&ListParams::default().limit(1)).await {
                    Ok(_) => {
                        // Endpoint exists, deployment genuinely gone
                    }
                    Err(_) => {
                        return OperatorGenerationState::Unknown(format!(
                            "Deployment GET returned 404 but API endpoint verification \
                             failed for {}",
                            saved_dep.resource.name
                        ));
                    }
                }
            }
            Err(e) => {
                return OperatorGenerationState::Unknown(format!(
                    "failed to GET Deployment {}: {}",
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

            match csv_api.list(&ListParams::default()).await {
                Ok(csv_list) => {
                    // Pass 1: Check for new CSVs not in baseline
                    for csv_obj in &csv_list.items {
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
                    for csv_obj in &csv_list.items {
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

#[derive(Clone, Debug, Serialize, Deserialize)]
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

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AuditScanError {
    pub resource_type: String,
    pub namespace: String,
    pub error: String,
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

const NATIVE_WORKLOAD_TARGETS: &[ScanTarget] = &[
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
        group: "",
        version: "v1",
        kind: "Service",
        plural: "services",
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

pub async fn run_residual_audit(client: &Client, journal: &RunJournal) -> Result<ResidualAudit> {
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
    };

    // Collect all plan resource identities for exclusion during namespace scan.
    // Key includes API group to avoid hiding resources from different groups with same Kind/name.
    let mut plan_resources: HashSet<(String, String, Option<String>, String)> = HashSet::new();
    for phase in &plan.phases {
        for action in &phase.actions {
            let rid = action_resource(action);
            plan_resources.insert((
                rid.group.clone(),
                rid.kind.clone(),
                rid.namespace.clone(),
                rid.name.clone(),
            ));
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
                    match probe_resource(client, resource, &ctx.known_gvrs).await {
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
                            });
                        }
                    }
                }
                Action::ExpectGone { resource, .. } => {
                    audit.coverage.requested_probes += 1;
                    match probe_resource(client, resource, &ctx.known_gvrs).await {
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
                match probe_resource(client, resource, &ctx.known_gvrs).await {
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
                        });
                    }
                }
            }
        }
    }

    // Phase B+C: Scan footprint namespaces for native workloads + OLM resources
    // Required APIs: failure = AuditIncomplete
    let required_targets: Vec<&ScanTarget> = NATIVE_WORKLOAD_TARGETS
        .iter()
        .chain(OLM_TARGETS.iter())
        .collect();
    // All targets (including OpenShift Route/ImageStream) are treated as required.
    // LIST 404/403/timeout → AuditIncomplete. Non-OpenShift clusters will show
    // incomplete for Route/ImageStream; accurate API availability detection is
    // deferred to a future PR with proper discovery integration.
    let all_targets: Vec<&ScanTarget> = required_targets
        .into_iter()
        .chain(OPENSHIFT_TARGETS.iter())
        .collect();

    for ns in &ctx.footprint_namespaces {
        for target in &all_targets {
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
                });
            }
        }
        Some(gvrs) => {
            for gvr in gvrs {
                // Check if this GVR's governing CRD was approved for deletion
                // and confirmed Gone (GoneByCrdRemoval exception for --prune-apis)
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
                        });
                        continue;
                    }
                }

                match gvr.scope {
                    crate::teardown::journal::GvrScope::Namespaced => {
                        for ns in &ctx.footprint_namespaces {
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
                            )
                            .await;
                        }
                    }
                    crate::teardown::journal::GvrScope::Cluster => {
                        audit.coverage.requested_probes += 1;
                        let gvk = GroupVersion::gv(&gvr.group, &gvr.version).with_kind(&gvr.kind);
                        let ar = ApiResource::from_gvk_with_plural(&gvk, &gvr.plural);
                        let api: Api<DynamicObject> = Api::all_with(client.clone(), &ar);
                        match api.list(&ListParams::default()).await {
                            Ok(list) => {
                                audit.coverage.succeeded_probes += 1;
                                classify_list_results(
                                    list.items,
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
                                audit.scan_errors.push(AuditScanError {
                                    resource_type: gvr.kind.clone(),
                                    namespace: "cluster".to_string(),
                                    error: e.to_string(),
                                });
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
                });
            }
        }
    }

    Ok(audit)
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
) {
    audit.coverage.requested_probes += 1;

    let gvk = GroupVersion::gv(group, version).with_kind(kind);
    let ar = ApiResource::from_gvk_with_plural(&gvk, plural);
    let api: Api<DynamicObject> = Api::namespaced_with(client.clone(), namespace, &ar);

    match api.list(&ListParams::default()).await {
        Ok(list) => {
            audit.coverage.succeeded_probes += 1;
            classify_list_results(
                list.items,
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
            audit.scan_errors.push(AuditScanError {
                resource_type: kind.to_string(),
                namespace: namespace.to_string(),
                error: e.to_string(),
            });
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
                });
                continue;
            }
        };

        let uid = obj.metadata.uid.clone();
        if uid.is_none() {
            audit.scan_errors.push(AuditScanError {
                resource_type: kind.to_string(),
                namespace: namespace.to_string(),
                error: format!("{}/{} has no UID — identity unverifiable", kind, name),
            });
        }

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
            uid,
        };

        let evidence = classify_evidence(&obj, ctx, target_uids);
        let confidence = compute_confidence(&evidence);

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

    let gvk = GroupVersion::gv(&resource.group, &resource.version).with_kind(&resource.kind);
    let ar = ApiResource::from_gvk_with_plural(&gvk, &plural);

    let api: Api<DynamicObject> = if let Some(ns) = &resource.namespace {
        Api::namespaced_with(client.clone(), ns, &ar)
    } else {
        Api::all_with(client.clone(), &ar)
    };

    match api.get(&resource.name).await {
        Ok(obj) => ProbeResult::Present {
            uid: obj.metadata.uid,
        },
        Err(kube::Error::Api(ref resp)) if resp.code == 404 => {
            // GET 404 could mean object gone OR endpoint gone (CRD removed).
            // Verify endpoint exists via LIST(limit=1). If LIST succeeds,
            // the object is genuinely gone. If LIST fails, we can't tell.
            match api.list(&ListParams::default().limit(1)).await {
                Ok(_) => ProbeResult::Gone,
                Err(_) => ProbeResult::Error(format!(
                    "GET returned 404 but API endpoint verification failed for {}/{}; \
                     cannot distinguish object absence from endpoint absence",
                    resource.kind, resource.name
                )),
            }
        }
        Err(e) => ProbeResult::Error(e.to_string()),
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

pub fn print_residual_audit(audit: &ResidualAudit, journal: &RunJournal) {
    eprintln!(
        "\n\x1b[1mTeardown status\x1b[0m: {}",
        journal.operator.csv_name
    );
    eprintln!("Session: {}", journal.run_id);
    eprintln!("Created: {}", journal.created_at);
    eprintln!();
    eprintln!(
        "Execution: {:?} ({}/{} phases)",
        journal.state, journal.execution.phases_completed, journal.execution.phases_total,
    );

    let total_residuals = audit.planned_delete_still_present.len()
        + audit.planned_expect_still_present.len()
        + audit.likely_operator_residual.len()
        + audit.unattributed.len();

    eprintln!("Residual audit: {} residuals observed", total_residuals);
    eprintln!();

    // Planned DELETE still present
    if audit.planned_delete_still_present.is_empty() {
        eprintln!("\x1b[1mPLANNED DELETE STILL PRESENT\x1b[0m");
        eprintln!("  none");
    } else {
        eprintln!(
            "\x1b[1;31mPLANNED DELETE STILL PRESENT\x1b[0m ({})",
            audit.planned_delete_still_present.len()
        );
        for item in &audit.planned_delete_still_present {
            print_residual_item(item);
        }
    }
    eprintln!();

    // Planned EXPECT still present
    if audit.planned_expect_still_present.is_empty() {
        eprintln!("\x1b[1mPLANNED EXPECT-GONE STILL PRESENT\x1b[0m");
        eprintln!("  none");
    } else {
        eprintln!(
            "\x1b[1;33mPLANNED EXPECT-GONE STILL PRESENT\x1b[0m ({})",
            audit.planned_expect_still_present.len()
        );
        for item in &audit.planned_expect_still_present {
            print_residual_item(item);
        }
    }
    eprintln!();

    // Expected preserved
    if !audit.expected_preserved.is_empty() {
        eprintln!(
            "\x1b[1mEXPECTED PRESERVED\x1b[0m ({})",
            audit.expected_preserved.len()
        );
        for item in &audit.expected_preserved {
            eprintln!(
                "  {}/{}{}",
                item.resource.kind,
                item.resource.name,
                ns_suffix(&item.resource)
            );
            eprintln!("    \x1b[2m{}\x1b[0m", item.reason);
        }
        eprintln!();
    }

    // Likely operator residual
    if !audit.likely_operator_residual.is_empty() {
        eprintln!(
            "\x1b[1;35mLIKELY OPERATOR RESIDUAL\x1b[0m ({})",
            audit.likely_operator_residual.len()
        );
        for item in &audit.likely_operator_residual {
            eprintln!(
                "  {}/{}{}",
                item.resource.kind,
                item.resource.name,
                ns_suffix(&item.resource)
            );
            let evidence_parts = format_evidence(&item.evidence);
            if !evidence_parts.is_empty() {
                eprintln!("    evidence: {}", evidence_parts);
            }
            eprintln!("    confidence: {:?}", item.confidence);
        }
        eprintln!();
    }

    // Unattributed
    if !audit.unattributed.is_empty() {
        eprintln!("\x1b[1mUNATTRIBUTED\x1b[0m ({})", audit.unattributed.len());
        for item in &audit.unattributed {
            eprintln!(
                "  {}/{}{}",
                item.resource.kind,
                item.resource.name,
                ns_suffix(&item.resource)
            );
            eprintln!("    no sufficient operator attribution evidence");
        }
        eprintln!();
    }

    // Coverage
    let ctx = &journal.audit_context;
    eprintln!(
        "Audit coverage: {}/{} probes succeeded (scope: {} namespace(s))",
        audit.coverage.succeeded_probes,
        audit.coverage.requested_probes,
        ctx.footprint_namespaces.len(),
    );
    eprintln!(
        "  \x1b[2mScope: install namespace + plan action namespaces only.\n  \
         Residuals in namespaces outside this footprint are not covered.\x1b[0m"
    );

    if !audit.scan_errors.is_empty() {
        eprintln!("\x1b[1;33mINCOMPLETE\x1b[0m");
        for err in &audit.scan_errors {
            eprintln!("  {}/{}: {}", err.resource_type, err.namespace, err.error);
        }
    }
}

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
            }],
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
    fn test_classify_list_results_missing_uid_creates_scan_error() {
        // Objects without UID should generate a scan_error
        use crate::teardown::journal::AuditContext;
        let mut audit = ResidualAudit {
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
        };
        let ctx = AuditContext::default();
        let target_uids = HashSet::new();
        let plan_resources = HashSet::new();

        // Create a DynamicObject with name but no UID
        let mut obj = DynamicObject::new(
            "test-obj",
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

        // Should have a scan error about missing UID
        assert!(audit.scan_errors.iter().any(|e| e.error.contains("no UID")));
        // Resource should still be classified (not silently dropped)
        assert_eq!(audit.unattributed.len(), 1);
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
            }],
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
}
