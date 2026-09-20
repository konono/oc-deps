use std::collections::{HashMap, HashSet};

use anyhow::{Result, bail};
use kube::Client;
use kube::api::{Api, ApiResource, DynamicObject, ListParams};
use kube::core::GroupVersion;
use serde::{Deserialize, Serialize};

use crate::kube::resource::ResourceId;
use crate::teardown::journal::{AuditContext, RunJournal, ResidualStatus};
use crate::teardown::plan::{
    OperatorGenerationIdentity, OperatorIdentitySnapshot,
};
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
    let sub_gvk =
        GroupVersion::gv("operators.coreos.com", "v1alpha1").with_kind("Subscription");
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

    for sub in &sub_list {
        let spec_name = sub
            .data
            .get("spec")
            .and_then(|s| s.get("name"))
            .and_then(|n| n.as_str());

        if spec_name == Some(package_name.as_str()) {
            let live_uid = sub.metadata.uid.as_deref().unwrap_or("");
            let saved_matches = snapshot
                .subscriptions
                .iter()
                .any(|s| s.uid == live_uid);

            return if saved_matches {
                OperatorGenerationState::SameGeneration
            } else {
                OperatorGenerationState::Reappeared
            };
        }
    }

    // Step 2: No matching subscription — check CSV
    let csv_gvk = GroupVersion::gv("operators.coreos.com", "v1alpha1")
        .with_kind("ClusterServiceVersion");
    let csv_ar =
        ApiResource::from_gvk_with_plural(&csv_gvk, "clusterserviceversions");
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

    // All checks succeeded with verified endpoint existence, nothing found
    OperatorGenerationState::Absent
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
    ScanTarget { group: "apps", version: "v1", kind: "Deployment", plural: "deployments" },
    ScanTarget { group: "apps", version: "v1", kind: "StatefulSet", plural: "statefulsets" },
    ScanTarget { group: "apps", version: "v1", kind: "DaemonSet", plural: "daemonsets" },
    ScanTarget { group: "", version: "v1", kind: "Service", plural: "services" },
];

const OPENSHIFT_TARGETS: &[ScanTarget] = &[
    ScanTarget { group: "route.openshift.io", version: "v1", kind: "Route", plural: "routes" },
    ScanTarget { group: "image.openshift.io", version: "v1", kind: "ImageStream", plural: "imagestreams" },
];

const OLM_TARGETS: &[ScanTarget] = &[
    ScanTarget { group: "operators.coreos.com", version: "v1alpha1", kind: "Subscription", plural: "subscriptions" },
    ScanTarget { group: "operators.coreos.com", version: "v1alpha1", kind: "ClusterServiceVersion", plural: "clusterserviceversions" },
];

// ──────────────────────────────────────────────────────────────
//  Live residual audit
// ──────────────────────────────────────────────────────────────

pub async fn run_residual_audit(
    client: &Client,
    journal: &RunJournal,
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
    };

    // Collect all plan resource identities for exclusion during namespace scan
    let mut plan_resources: HashSet<(String, Option<String>, String)> = HashSet::new();
    for phase in &plan.phases {
        for action in &phase.actions {
            let rid = action_resource(action);
            plan_resources.insert((
                rid.kind.clone(),
                rid.namespace.clone(),
                rid.name.clone(),
            ));
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
                Action::Keep { resource, reason, .. } => {
                    audit.expected_preserved.push(PreservedItem {
                        resource: resource.clone(),
                        reason: reason.clone(),
                        confirmed_descendants: 0,
                        associated_active_workloads: 0,
                    });
                }
                Action::Review { resource, reason, .. } => {
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
                client, target.group, target.version, target.kind, target.plural,
                ns, ctx, &plan_resources, &mut audit,
            ).await;
        }
    }

    // Known CR API scan requires pre-execution GVR/scope metadata not yet captured at plan time.
    // Only mark incomplete if the operator actually owns CRDs that we can't scan.
    if !journal.operator.owned_crds.is_empty() {
        audit.scan_errors.push(AuditScanError {
            resource_type: "(known CR APIs)".to_string(),
            namespace: "(all)".to_string(),
            error: format!(
                "Operator owns {} CRD(s) but GVR/scope metadata is not yet captured at plan time. \
                 Residual CRs beyond plan resources are not covered.",
                journal.operator.owned_crds.len()
            ),
        });
    }

    Ok(audit)
}

/// Scan a single GVR in a namespace for residual resources.
/// All LIST failures (404/403/timeout) are scan errors → AuditIncomplete.
async fn scan_namespace_for_target(
    client: &Client,
    group: &str,
    version: &str,
    kind: &str,
    plural: &str,
    namespace: &str,
    ctx: &AuditContext,
    plan_resources: &HashSet<(String, Option<String>, String)>,
    audit: &mut ResidualAudit,
) {
    audit.coverage.requested_probes += 1;

    let gvk = GroupVersion::gv(group, version).with_kind(kind);
    let ar = ApiResource::from_gvk_with_plural(&gvk, plural);
    let api: Api<DynamicObject> = Api::namespaced_with(client.clone(), namespace, &ar);

    match api.list(&ListParams::default()).await {
        Ok(list) => {
            audit.coverage.succeeded_probes += 1;
            classify_list_results(list.items, kind, group, version, namespace, ctx, plan_resources, audit);
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

fn classify_list_results(
    items: Vec<DynamicObject>,
    kind: &str,
    group: &str,
    version: &str,
    namespace: &str,
    ctx: &AuditContext,
    plan_resources: &HashSet<(String, Option<String>, String)>,
    audit: &mut ResidualAudit,
) {
    for obj in items {
        let name = match &obj.metadata.name {
            Some(n) => n.clone(),
            None => continue,
        };

        let obj_ns = obj.metadata.namespace.clone();
        let key = (kind.to_string(), obj_ns.clone(), name.clone());
        if plan_resources.contains(&key) {
            continue;
        }

        let rid = ResourceId {
            group: group.to_string(),
            version: version.to_string(),
            kind: kind.to_string(),
            namespace: obj_ns,
            name,
            uid: obj.metadata.uid.clone(),
        };

        let evidence = classify_evidence(&obj, ctx, namespace);
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
    _namespace: &str,
) -> ResidualEvidence {
    let mut matching_labels = Vec::new();
    let mut matching_managers = Vec::new();
    let mut service_account_match = false;

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
                    if manager.contains(prefix) {
                        if !matching_managers.contains(manager) {
                            matching_managers.push(manager.clone());
                        }
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

        if let Some(sa) = sa_name {
            if ctx.service_account_names.contains(sa) {
                service_account_match = true;
            }
        }
    }

    // namespace_affinity is always true since we only scan footprint namespaces
    // but it's a supplementary signal, not classification-driving
    ResidualEvidence {
        matching_labels,
        matching_managers,
        namespace_affinity: true,
        service_account_match,
    }
}

/// Deterministic confidence rules:
/// HIGH: SA match + matching manager
/// MEDIUM: matching manager + matching label
/// LOW: matching label only OR matching manager only
/// NONE: namespace affinity only / no evidence
fn compute_confidence(evidence: &ResidualEvidence) -> ResidualConfidence {
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
    let plural = plural
        .or_else(|| known_plural_for_gvk(&resource.group, &resource.kind).map(String::from));

    let plural = match plural {
        Some(p) => p,
        None => {
            return ProbeResult::Error(format!(
                "Unknown GVR for {}/{} '{}' — no discovery metadata and not in static allowlist",
                resource.group, resource.kind, resource.name
            ));
        }
    };

    let gvk = GroupVersion::gv(&resource.group, &resource.version)
        .with_kind(&resource.kind);
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
        journal.state,
        journal.execution.phases_completed,
        journal.execution.phases_total,
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
                item.resource.kind, item.resource.name, ns_suffix(&item.resource)
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
                item.resource.kind, item.resource.name, ns_suffix(&item.resource)
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
        eprintln!(
            "\x1b[1mUNATTRIBUTED\x1b[0m ({})",
            audit.unattributed.len()
        );
        for item in &audit.unattributed {
            eprintln!(
                "  {}/{}{}",
                item.resource.kind, item.resource.name, ns_suffix(&item.resource)
            );
            eprintln!("    no sufficient operator attribution evidence");
        }
        eprintln!();
    }

    // Coverage
    eprintln!(
        "Audit coverage: {}/{} probes succeeded",
        audit.coverage.succeeded_probes,
        audit.coverage.requested_probes,
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
