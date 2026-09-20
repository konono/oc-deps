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
            // CSV gone — continue checking controllers
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
                // Controller gone — continue
            }
            Err(e) => {
                return OperatorGenerationState::Unknown(format!(
                    "failed to GET Deployment {}: {}",
                    saved_dep.resource.name, e
                ));
            }
        }
    }

    // All checks succeeded, nothing found
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
                    match probe_resource(client, resource).await {
                        ProbeResult::Present => {
                            audit.coverage.succeeded_probes += 1;
                            audit.planned_delete_still_present.push(ResidualItem {
                                resource: resource.clone(),
                                planned_action: "DELETE".to_string(),
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
                    match probe_resource(client, resource).await {
                        ProbeResult::Present => {
                            audit.coverage.succeeded_probes += 1;
                            audit.planned_expect_still_present.push(ResidualItem {
                                resource: resource.clone(),
                                planned_action: "EXPECT-GONE".to_string(),
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
    let all_targets: Vec<&ScanTarget> = NATIVE_WORKLOAD_TARGETS
        .iter()
        .chain(OLM_TARGETS.iter())
        .chain(OPENSHIFT_TARGETS.iter())
        .collect();

    for ns in &ctx.footprint_namespaces {
        for target in &all_targets {
            audit.coverage.requested_probes += 1;

            let gvk = GroupVersion::gv(target.group, target.version)
                .with_kind(target.kind);
            let ar = ApiResource::from_gvk_with_plural(&gvk, target.plural);
            let api: Api<DynamicObject> =
                Api::namespaced_with(client.clone(), ns, &ar);

            match api.list(&ListParams::default()).await {
                Ok(list) => {
                    audit.coverage.succeeded_probes += 1;

                    for obj in list.items {
                        let name = match &obj.metadata.name {
                            Some(n) => n.clone(),
                            None => continue,
                        };

                        // Skip resources already in the plan
                        let key = (
                            target.kind.to_string(),
                            Some(ns.clone()),
                            name.clone(),
                        );
                        if plan_resources.contains(&key) {
                            continue;
                        }

                        let rid = ResourceId {
                            group: target.group.to_string(),
                            version: target.version.to_string(),
                            kind: target.kind.to_string(),
                            namespace: Some(ns.clone()),
                            name,
                            uid: obj.metadata.uid.clone(),
                        };

                        let evidence = classify_evidence(&obj, ctx, ns);
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
                Err(kube::Error::Api(ref resp)) if resp.code == 404 => {
                    // API not available on this cluster (e.g. Route on non-OpenShift)
                    audit.coverage.succeeded_probes += 1;
                }
                Err(e) => {
                    audit.scan_errors.push(AuditScanError {
                        resource_type: target.kind.to_string(),
                        namespace: ns.clone(),
                        error: e.to_string(),
                    });
                }
            }
        }
    }

    Ok(audit)
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
    Present,
    Gone,
    Error(String),
}

async fn probe_resource(client: &Client, resource: &ResourceId) -> ProbeResult {
    let gvk = GroupVersion::gv(&resource.group, &resource.version)
        .with_kind(&resource.kind);

    // Guess plural (simple heuristic)
    let plural = guess_plural(&resource.kind);
    let ar = ApiResource::from_gvk_with_plural(&gvk, &plural);

    let api: Api<DynamicObject> = if let Some(ns) = &resource.namespace {
        Api::namespaced_with(client.clone(), ns, &ar)
    } else {
        Api::all_with(client.clone(), &ar)
    };

    match api.get(&resource.name).await {
        Ok(_) => ProbeResult::Present,
        Err(kube::Error::Api(ref resp)) if resp.code == 404 => ProbeResult::Gone,
        Err(e) => ProbeResult::Error(e.to_string()),
    }
}

fn guess_plural(kind: &str) -> String {
    let lower = kind.to_lowercase();
    if lower.ends_with("ss") || lower.ends_with("sh") || lower.ends_with("ch") || lower.ends_with("x") {
        format!("{}es", lower)
    } else if lower.ends_with('s') {
        lower
    } else if lower.ends_with('y') && !lower.ends_with("ey") && !lower.ends_with("ay") {
        format!("{}ies", &lower[..lower.len() - 1])
    } else {
        format!("{}s", lower)
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
            eprintln!("  {}/{}{}", item.resource.kind, item.resource.name, ns_suffix(&item.resource));
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
            eprintln!("  {}/{}{}", item.resource.kind, item.resource.name, ns_suffix(&item.resource));
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
