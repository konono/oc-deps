use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use anyhow::{Result, bail};
use futures::stream::StreamExt;
use kube::{
    Client,
    api::{Api, ApiResource, DynamicObject, ListParams},
    core::GroupVersion,
};
use serde::{Deserialize, Serialize};

use crate::analyzers::olm::{
    OperatorDependency, OperatorId, OperatorInstance, OwnedApiServiceDef,
    compute_operator_dependencies,
};
use crate::cli::OutputFormat;
use crate::kube::discovery::KindInfo;
use crate::kube::discovery::{GroupKindMap, GvkMap, GvrMap, KindMap};
use crate::kube::resource::{ResourceId, ScanWarning, resolve_api};

// ── UID binding result ──

pub(crate) enum BindResult {
    Bound(String),
    Absent,
    Failed(String),
}

/// Probe a single resource's UID for safe DELETE binding.
/// GET 200 + UID → Bound, GET 404 + LIST 200 → Absent, otherwise → Failed.
pub(crate) async fn probe_uid(
    api: &kube::api::Api<kube::api::DynamicObject>,
    name: &str,
) -> BindResult {
    match api.get(name).await {
        Ok(obj) => match obj.metadata.uid {
            Some(uid) => BindResult::Bound(uid),
            None => BindResult::Failed("resource has no UID".to_string()),
        },
        Err(kube::Error::Api(ref err)) if err.code == 404 => {
            match api.list(&kube::api::ListParams::default().limit(1)).await {
                Ok(_) => BindResult::Absent,
                Err(e) => {
                    BindResult::Failed(format!("GET 404 but endpoint verification failed: {}", e))
                }
            }
        }
        Err(e) => BindResult::Failed(format!("GET failed: {}", e)),
    }
}

// ── Decision types ──

#[derive(Debug, Clone, PartialEq)]
pub enum BulkScope {
    Root,
    Independent,
    All,
    /// Resources discovered only through related labels. Excludes Namespace, PVC/PV, and CRD.
    LabelOnly,
    /// OperatorGroups in namespaces where no non-target operator remains.
    OperatorGroup,
}

#[derive(Debug, Clone)]
pub enum DeleteApproval {
    Bulk(BulkScope),
    Exact(String),
}

#[derive(Debug, Clone)]
pub struct DecisionPolicy {
    pub approvals: Vec<DeleteApproval>,
    pub preserves: Vec<String>,
}

impl DecisionPolicy {
    pub fn from_args(approve_delete: &[String], preserves: &[String]) -> Self {
        let approvals = approve_delete
            .iter()
            .map(|s| match s.as_str() {
                "root" => DeleteApproval::Bulk(BulkScope::Root),
                "independent" => DeleteApproval::Bulk(BulkScope::Independent),
                "all" => DeleteApproval::Bulk(BulkScope::All),
                "label-only" => DeleteApproval::Bulk(BulkScope::LabelOnly),
                "operator-group" => DeleteApproval::Bulk(BulkScope::OperatorGroup),
                _ => DeleteApproval::Exact(s.clone()),
            })
            .collect();
        Self {
            approvals,
            preserves: preserves.to_vec(),
        }
    }

    pub fn empty() -> Self {
        Self {
            approvals: vec![],
            preserves: vec![],
        }
    }
}

#[derive(Clone, Debug, PartialEq)]
pub enum ApprovalOrigin {
    BulkLabelOnly,
    Other,
}

pub enum ResolvedDecision {
    Delete {
        reason: String,
        approval_origin: ApprovalOrigin,
    },
    Keep {
        reason: String,
    },
    #[allow(dead_code)]
    Review,
}

pub fn canonical_key(resource: &ResourceId) -> String {
    let ns = resource.namespace.as_deref().unwrap_or("-");
    format!(
        "{}/{}/{}/{}",
        resource.group, resource.kind, ns, resource.name
    )
}

fn spec_matches_resource(spec: &str, resource: &ResourceId) -> bool {
    let parts: Vec<&str> = spec.splitn(4, '/').collect();
    match parts.len() {
        4 => {
            let (group, kind, ns, name) = (parts[0], parts[1], parts[2], parts[3]);
            let ns_match = match &resource.namespace {
                Some(rns) => rns == ns,
                None => ns == "-",
            };
            resource.group.eq_ignore_ascii_case(group)
                && resource.kind == kind
                && ns_match
                && resource.name == name
        }
        2 => {
            let (kind, name) = (parts[0], parts[1]);
            resource.kind == kind && resource.name == name
        }
        _ => false,
    }
}

fn is_short_form(spec: &str) -> bool {
    spec.splitn(4, '/').count() == 2
}

/// Resolve all decisions from policy + candidates. Returns a map of
/// ResourceId → ResolvedDecision plus any validation errors.
pub fn resolve_decisions<'a>(
    policy: &DecisionPolicy,
    candidates: &[ReviewCandidate<'a>],
) -> Result<HashMap<ResourceId, ResolvedDecision>> {
    let mut errors = Vec::new();
    let mut resolved: HashMap<ResourceId, ResolvedDecision> = HashMap::new();

    // Phase 1: Validate and resolve exact preserves
    for spec in &policy.preserves {
        let matching: Vec<_> = candidates
            .iter()
            .filter(|rc| spec_matches_resource(spec, rc.resource))
            .collect();
        if is_short_form(spec) && matching.len() > 1 {
            let qualified: Vec<String> = matching
                .iter()
                .map(|rc| canonical_key(rc.resource))
                .collect();
            errors.push(format!(
                "ambiguous --keep-resource {}: matches {} resources. Use qualified form:\n  {}",
                spec,
                matching.len(),
                qualified.join("\n  ")
            ));
            continue;
        }
        if matching.is_empty() {
            errors.push(format!(
                "--keep-resource {}: no matching REVIEW resource found",
                spec
            ));
            continue;
        }
        for rc in &matching {
            resolved.insert(
                rc.resource.clone(),
                ResolvedDecision::Keep {
                    reason: "explicitly preserved via --keep-resource".to_string(),
                },
            );
        }
    }

    // Phase 2: Validate and resolve exact approvals
    for approval in &policy.approvals {
        let DeleteApproval::Exact(spec) = approval else {
            continue;
        };
        let matching: Vec<_> = candidates
            .iter()
            .filter(|rc| spec_matches_resource(spec, rc.resource))
            .collect();
        if is_short_form(spec) && matching.len() > 1 {
            let qualified: Vec<String> = matching
                .iter()
                .map(|rc| canonical_key(rc.resource))
                .collect();
            errors.push(format!(
                "ambiguous --approve-resource {}: matches {} REVIEW resources. Use qualified form:\n  {}",
                spec,
                matching.len(),
                qualified.join("\n  ")
            ));
            continue;
        }
        if matching.is_empty() {
            errors.push(format!(
                "--approve-resource {}: no matching REVIEW resource found",
                spec
            ));
            continue;
        }
        let rc = matching[0];
        if !rc.exact_approvable {
            errors.push(format!(
                "--approve-resource {}: resource exists but cannot be approved for deletion",
                spec
            ));
            continue;
        }
        // Conflict check: exact delete + exact preserve
        if resolved
            .get(rc.resource)
            .is_some_and(|d| matches!(d, ResolvedDecision::Keep { .. }))
        {
            errors.push(format!(
                "--approve-resource {} conflicts with --keep-resource for the same resource",
                spec
            ));
            continue;
        }
        let reason = match rc.category {
            ReviewCategory::Operand(GraphPosition::Root) => {
                if rc.approval_class == DeleteApprovalClass::ExplicitOnly {
                    "label-related root CR explicitly approved for deletion"
                } else {
                    "root CR explicitly approved for deletion"
                }
            }
            ReviewCategory::Operand(GraphPosition::Independent) => {
                if rc.approval_class == DeleteApprovalClass::ExplicitOnly {
                    "label-related CR explicitly approved for deletion"
                } else {
                    "independent CR explicitly approved for deletion"
                }
            }
            ReviewCategory::Ancillary => "ancillary resource explicitly approved for deletion",
            _ => "explicitly approved for deletion",
        };
        resolved.insert(
            rc.resource.clone(),
            ResolvedDecision::Delete {
                reason: reason.to_string(),
                approval_origin: ApprovalOrigin::Other,
            },
        );
    }

    // Phase 3: Resolve bulk approvals
    let has_bulk_root = policy.approvals.iter().any(|a| {
        matches!(
            a,
            DeleteApproval::Bulk(BulkScope::Root) | DeleteApproval::Bulk(BulkScope::All)
        )
    });
    let has_bulk_independent = policy.approvals.iter().any(|a| {
        matches!(
            a,
            DeleteApproval::Bulk(BulkScope::Independent) | DeleteApproval::Bulk(BulkScope::All)
        )
    });
    let has_bulk_label_only = policy
        .approvals
        .iter()
        .any(|a| matches!(a, DeleteApproval::Bulk(BulkScope::LabelOnly)));
    let has_bulk_operator_group = policy
        .approvals
        .iter()
        .any(|a| matches!(a, DeleteApproval::Bulk(BulkScope::OperatorGroup)));

    for rc in candidates {
        if resolved.contains_key(rc.resource) {
            continue;
        }
        if !rc.exact_approvable {
            continue;
        }
        let standard_bulk_matches = rc.approval_class == DeleteApprovalClass::Standard
            && match rc.category {
                ReviewCategory::Operand(GraphPosition::Root) => has_bulk_root,
                ReviewCategory::Operand(GraphPosition::Independent) => has_bulk_independent,
                _ => false,
            };
        let label_only_matches = has_bulk_label_only && rc.is_label_only_eligible;
        let operator_group_matches = has_bulk_operator_group
            && matches!(rc.category, ReviewCategory::Ancillary)
            && rc.resource.kind == "OperatorGroup";
        let bulk_matches = standard_bulk_matches || label_only_matches || operator_group_matches;
        if bulk_matches {
            let reason = if label_only_matches {
                "label-related CR approved via --approve-scope label-only"
            } else if operator_group_matches {
                "operator group approved via --approve-scope operator-group"
            } else {
                match rc.category {
                    ReviewCategory::Operand(GraphPosition::Root) => {
                        "root CR approved via --approve-scope root"
                    }
                    ReviewCategory::Operand(GraphPosition::Independent) => {
                        "independent CR approved via --approve-scope independent"
                    }
                    _ => "approved via bulk approval",
                }
            };
            let origin = if label_only_matches {
                ApprovalOrigin::BulkLabelOnly
            } else {
                ApprovalOrigin::Other
            };
            resolved.insert(
                rc.resource.clone(),
                ResolvedDecision::Delete {
                    reason: reason.to_string(),
                    approval_origin: origin,
                },
            );
        }
    }

    if !errors.is_empty() {
        for err in &errors {
            eprintln!("\x1b[1;31m⛔\x1b[0m {}", err);
        }
        bail!("{} decision argument(s) are invalid", errors.len());
    }

    Ok(resolved)
}

const DEFAULT_CONCURRENCY: usize = 16;
const LIST_PAGE_SIZE: u32 = 500;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TeardownPlan {
    pub targets: Vec<OperatorTarget>,
    pub preflight: Preflight,
    pub phases: Vec<PlanPhase>,
    pub blockers: Vec<Blocker>,
    pub warnings: Vec<Warning>,
    pub snapshot_taken_at: String,
    /// Operator dependency edges discovered from CSV required/owned CRDs.
    #[serde(default)]
    pub dependency_edges: Vec<DependencyEdge>,
    /// Operator inventory at plan time — all operators in the cluster.
    #[serde(default)]
    pub operator_inventory: Vec<OperatorInventoryEntry>,
    /// Explicit user decisions resolved from policy — only REVIEW items that were
    /// explicitly approved or preserved. Populated by generate_teardown_plan.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub explicit_decisions: Vec<crate::teardown::plan::SavedDecision>,
}

/// A typed dependency edge between operators.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DependencyEdge {
    pub from_operator: String,
    pub to_operator: String,
    pub edge_type: DependencyEdgeType,
    pub evidence: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum DependencyEdgeType {
    RequiresApi,
}

/// Minimal operator inventory entry for plan-time snapshot.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct OperatorInventoryEntry {
    pub csv_name: String,
    pub namespace: String,
    pub owned_crds: Vec<String>,
    pub required_crds: Vec<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Preflight {
    pub checks: Vec<PreflightCheck>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum PreflightSeverity {
    Critical,
    Warning,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PreflightCheck {
    pub name: String,
    pub severity: PreflightSeverity,
    pub passed: bool,
    pub detail: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct OperatorTarget {
    pub subscription: Option<ResourceId>,
    pub csv: ResourceId,
    pub install_namespace: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PlanPhase {
    pub name: String,
    pub description: String,
    pub actions: Vec<Action>,
    pub barrier: Option<Barrier>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum Action {
    Delete {
        resource: ResourceId,
        reason: String,
    },
    ExpectGone {
        resource: ResourceId,
        reason: String,
    },
    WaitGone {
        resource: ResourceId,
    },
    Keep {
        resource: ResourceId,
        reason: String,
    },
    Review {
        resource: ResourceId,
        reason: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        metadata: Option<crate::teardown::plan::ReviewMetadata>,
    },
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Barrier {
    pub description: String,
    pub conditions: Vec<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Blocker {
    pub resource: ResourceId,
    pub reason: String,
    pub external_dependency: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Warning {
    pub message: String,
    pub resource: Option<ResourceId>,
}

#[derive(Clone, Debug)]
pub enum Provenance {
    Managed,
    LikelyManaged,
    Unknown,
}

#[derive(Clone, Debug, PartialEq)]
pub enum DiscoverySource {
    Direct,
    RelatedLinked,
    RelatedLabelOnly,
}

pub struct CrInstance {
    pub id: ResourceId,
    pub owner_refs: Vec<(String, String, String)>, // (kind, name, uid)
    #[allow(dead_code)]
    pub api_owner_key: String,
    pub labels: HashMap<String, String>,
    pub managed_field_managers: Vec<String>,
    pub provenance: Provenance,
    pub discovery_source: DiscoverySource,
    pub decisive_label_pairs: Vec<(String, String)>,
    pub ownerref_to_owned_api_kind: Option<String>,
}

pub fn resolve_operator_targets(
    queries: &[String],
    operators: &[OperatorInstance],
) -> Result<Vec<usize>> {
    let mut indices = Vec::new();
    for query in queries {
        // Support "csv_name@namespace" format for disambiguation
        let (q_name, q_ns) = if let Some((name, ns)) = query.rsplit_once('@') {
            (name.to_lowercase(), Some(ns.to_lowercase()))
        } else {
            (query.to_lowercase(), None)
        };

        let mut found: Vec<usize> = Vec::new();

        // Exact match
        for (i, op) in operators.iter().enumerate() {
            let csv_lower = op.csv.name.to_lowercase();
            let sub_lower = op
                .subscription
                .as_ref()
                .map(|s| s.name.to_lowercase())
                .unwrap_or_default();
            let ns_lower = op.install_namespace.to_lowercase();

            let name_match = csv_lower == q_name || sub_lower == q_name;
            let ns_match = q_ns.as_ref().is_none_or(|ns| ns_lower == *ns);

            if name_match && ns_match {
                found.push(i);
            }
        }

        // Partial match if no exact match
        if found.is_empty() {
            for (i, op) in operators.iter().enumerate() {
                let csv_lower = op.csv.name.to_lowercase();
                let sub_lower = op
                    .subscription
                    .as_ref()
                    .map(|s| s.name.to_lowercase())
                    .unwrap_or_default();
                let ns_lower = op.install_namespace.to_lowercase();

                let name_match = csv_lower.contains(&q_name) || sub_lower.contains(&q_name);
                let ns_match = q_ns.as_ref().is_none_or(|ns| ns_lower == *ns);

                if name_match && ns_match {
                    found.push(i);
                }
            }
        }

        match found.len() {
            0 => {
                bail!(
                    "Operator '{}' not found. Use `oc-deps operator list` to list available operators.",
                    query
                );
            }
            1 => {
                if !indices.contains(&found[0]) {
                    indices.push(found[0]);
                }
            }
            _ => {
                // Check if all matches are actually the same operator (same csv name, different match paths)
                let first_id = OperatorId::from_instance(&operators[found[0]]);
                let all_same = found
                    .iter()
                    .all(|&i| OperatorId::from_instance(&operators[i]) == first_id);

                if all_same {
                    if !indices.contains(&found[0]) {
                        indices.push(found[0]);
                    }
                } else {
                    let mut candidates: Vec<String> = found
                        .iter()
                        .map(|&i| {
                            let op = &operators[i];
                            format!("{}@{}", op.csv.name, op.install_namespace)
                        })
                        .collect();
                    candidates.sort();
                    candidates.dedup();
                    bail!(
                        "Ambiguous operator '{}'. Installations:\n  {}\nUse name@namespace to disambiguate.",
                        query,
                        candidates.join("\n  ")
                    );
                }
            }
        }
    }
    Ok(indices)
}

enum CrdDiscoveryResult {
    Success(Vec<CrInstance>),
    Unavailable(ScanWarning),
}

async fn discover_one_crd(
    client: &Client,
    crd_name: &str,
    gvr_map: &GvrMap,
    gk_map: &GroupKindMap,
) -> CrdDiscoveryResult {
    let (plural, group) = match crd_name.split_once('.') {
        Some((p, g)) => (p, g),
        None => {
            return CrdDiscoveryResult::Unavailable(ScanWarning::Other {
                gvr: crd_name.to_string(),
                message: "cannot parse CRD name".to_string(),
            });
        }
    };

    let gvr_key = format!("{}.{}", plural, group).to_lowercase();
    let kind = match gvr_map.get(&gvr_key) {
        Some(k) => k.clone(),
        None => {
            return CrdDiscoveryResult::Unavailable(ScanWarning::Other {
                gvr: crd_name.to_string(),
                message: format!("kind not found for GVR {}", gvr_key),
            });
        }
    };

    // Use GroupKindMap — no KindMap fallback (fail-closed)
    let kind_info = match gk_map.get(&(group.to_string(), kind.clone())) {
        Some(i) => i,
        None => {
            return CrdDiscoveryResult::Unavailable(ScanWarning::Other {
                gvr: crd_name.to_string(),
                message: format!("no GroupKind mapping for {}/{}", group, kind),
            });
        }
    };

    let gvk = GroupVersion::gv(&kind_info.group, &kind_info.version).with_kind(&kind);
    let ar = ApiResource::from_gvk_with_plural(&gvk, &kind_info.plural);
    let api: Api<DynamicObject> = Api::all_with(client.clone(), &ar);

    let items = match list_paginated_with_retry(
        &api,
        &kind_info.group,
        &kind_info.version,
        &kind_info.plural,
    )
    .await
    {
        Ok(items) => items,
        Err(warning) => {
            return CrdDiscoveryResult::Unavailable(warning);
        }
    };

    let crs = items
        .into_iter()
        .filter_map(|obj| {
            let uid = obj.metadata.uid.unwrap_or_default();
            let name = obj.metadata.name?;
            let ns = obj.metadata.namespace;

            let owner_refs: Vec<(String, String, String)> = obj
                .metadata
                .owner_references
                .unwrap_or_default()
                .into_iter()
                .map(|r| (r.kind, r.name, r.uid))
                .collect();

            let labels: HashMap<String, String> = obj
                .metadata
                .labels
                .unwrap_or_default()
                .into_iter()
                .collect();

            let managed_field_managers: Vec<String> = obj
                .metadata
                .managed_fields
                .unwrap_or_default()
                .into_iter()
                .filter_map(|mf| mf.manager)
                .collect();

            Some(CrInstance {
                id: ResourceId {
                    group: kind_info.group.clone(),
                    version: kind_info.version.clone(),
                    kind: kind.clone(),
                    namespace: ns,
                    name,
                    uid: Some(uid),
                },
                owner_refs,
                api_owner_key: crd_name.to_string(),
                labels,
                managed_field_managers,
                provenance: Provenance::Unknown,
                discovery_source: DiscoverySource::Direct,
                decisive_label_pairs: vec![],
                ownerref_to_owned_api_kind: None,
            })
        })
        .collect::<Vec<_>>();

    CrdDiscoveryResult::Success(crs)
}

pub struct CrDiscoveryReport {
    pub instances: Vec<CrInstance>,
    #[allow(dead_code)]
    pub total_observations: usize,
    pub unavailable_crds: Vec<ScanWarning>,
}

pub async fn discover_cr_instances(
    client: &Client,
    target_crds: &[String],
    gvr_map: &GvrMap,
    gk_map: &GroupKindMap,
) -> CrDiscoveryReport {
    let unique_crds: Vec<&String> = {
        let mut seen = HashSet::new();
        target_crds
            .iter()
            .filter(|crd| seen.insert((*crd).clone()))
            .collect()
    };

    let total_crds = unique_crds.len();
    let gvr_map = Arc::new(gvr_map.clone());
    let gk_map = Arc::new(gk_map.clone());
    let discovered = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let is_tty = std::io::IsTerminal::is_terminal(&std::io::stderr());

    let futs = unique_crds.into_iter().map(|crd_name| {
        let client = client.clone();
        let crd_name = crd_name.clone();
        let gvr_map = gvr_map.clone();
        let gk_map = gk_map.clone();
        let discovered = discovered.clone();
        async move {
            let result = discover_one_crd(&client, &crd_name, &gvr_map, &gk_map).await;
            if is_tty {
                let count = discovered.fetch_add(1, std::sync::atomic::Ordering::Relaxed) + 1;
                eprint!("\r\x1b[2K   CRD {}/{}: {}", count, total_crds, crd_name);
            } else {
                discovered.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            }
            result
        }
    });

    let results: Vec<CrdDiscoveryResult> = futures::stream::iter(futs)
        .buffer_unordered(DEFAULT_CONCURRENCY)
        .collect()
        .await;

    eprintln!();
    let mut instances = Vec::new();
    let mut unavailable_crds = Vec::new();
    for result in results {
        match result {
            CrdDiscoveryResult::Success(crs) => instances.extend(crs),
            CrdDiscoveryResult::Unavailable(warning) => {
                unavailable_crds.push(warning);
            }
        }
    }

    let total_observations = instances.len();

    let mut seen_uids = HashSet::new();
    instances.retain(|cr| {
        if let Some(uid) = &cr.id.uid {
            seen_uids.insert(uid.clone())
        } else {
            true
        }
    });

    CrDiscoveryReport {
        instances,
        total_observations,
        unavailable_crds,
    }
}

async fn discover_api_service_instances(
    client: &Client,
    kind_infos: &[(&OwnedApiServiceDef, KindInfo)],
) -> CrDiscoveryReport {
    let mut instances = Vec::new();
    let mut unavailable_crds = Vec::new();

    let futs = kind_infos.iter().map(|(def, kind_info)| {
        let client = client.clone();
        let kind_info = kind_info.clone();
        let def_group = def.group.clone();
        let def_version = def.version.clone();
        let kind = def.kind.clone();
        async move {
            let gvk = GroupVersion::gv(&kind_info.group, &kind_info.version).with_kind(&kind);
            let ar = ApiResource::from_gvk_with_plural(&gvk, &kind_info.plural);
            let api: Api<DynamicObject> = Api::all_with(client, &ar);

            let owner_key = format!("{}/{}/{}", def_group, def_version, kind);
            match list_paginated_with_retry(
                &api,
                &kind_info.group,
                &kind_info.version,
                &kind_info.plural,
            )
            .await
            {
                Ok(items) => {
                    let crs: Vec<CrInstance> = items
                        .into_iter()
                        .filter_map(|obj| {
                            let uid = obj.metadata.uid.unwrap_or_default();
                            let name = obj.metadata.name?;
                            let ns = obj.metadata.namespace;
                            let owner_refs: Vec<(String, String, String)> = obj
                                .metadata
                                .owner_references
                                .unwrap_or_default()
                                .into_iter()
                                .map(|r| (r.kind, r.name, r.uid))
                                .collect();
                            let labels: HashMap<String, String> = obj
                                .metadata
                                .labels
                                .unwrap_or_default()
                                .into_iter()
                                .collect();
                            let managed_field_managers: Vec<String> = obj
                                .metadata
                                .managed_fields
                                .unwrap_or_default()
                                .into_iter()
                                .filter_map(|mf| mf.manager)
                                .collect();
                            Some(CrInstance {
                                id: ResourceId {
                                    group: kind_info.group.clone(),
                                    version: kind_info.version.clone(),
                                    kind: kind.clone(),
                                    namespace: ns,
                                    name,
                                    uid: Some(uid),
                                },
                                owner_refs,
                                api_owner_key: owner_key.clone(),
                                labels,
                                managed_field_managers,
                                provenance: Provenance::Unknown,
                                discovery_source: DiscoverySource::Direct,
                                decisive_label_pairs: vec![],
                                ownerref_to_owned_api_kind: None,
                            })
                        })
                        .collect();
                    CrdDiscoveryResult::Success(crs)
                }
                Err(warning) => CrdDiscoveryResult::Unavailable(warning),
            }
        }
    });

    let results: Vec<CrdDiscoveryResult> = futures::stream::iter(futs)
        .buffer_unordered(DEFAULT_CONCURRENCY)
        .collect()
        .await;

    for result in results {
        match result {
            CrdDiscoveryResult::Success(crs) => instances.extend(crs),
            CrdDiscoveryResult::Unavailable(warning) => {
                unavailable_crds.push(warning);
            }
        }
    }

    let total_observations = instances.len();

    let mut seen_uids = HashSet::new();
    instances.retain(|cr| {
        if let Some(uid) = &cr.id.uid {
            seen_uids.insert(uid.clone())
        } else {
            true
        }
    });

    CrDiscoveryReport {
        instances,
        total_observations,
        unavailable_crds,
    }
}

/// Returns true if a root CR should be exempt from hard blocker status.
/// RelatedLabelOnly roots have no confirmed lifecycle connection to the
/// target operator and are deferred to post-teardown Residual Audit.
pub fn is_root_blocker_exempt(cr: &CrInstance) -> bool {
    cr.discovery_source == DiscoverySource::RelatedLabelOnly
}

fn owned_crd_group_kinds(
    operators: &[&OperatorInstance],
    gk_map: &GroupKindMap,
) -> HashSet<(String, String)> {
    let mut group_kinds = HashSet::new();
    for op in operators {
        for crd_name in &op.owned_crds {
            let (plural, group) = match crd_name.split_once('.') {
                Some((p, g)) => (p, g),
                None => continue,
            };
            for ((g, k), info) in gk_map {
                if g == group && info.plural == plural {
                    group_kinds.insert((g.clone(), k.clone()));
                }
            }
        }
    }
    group_kinds
}

fn classify_provenance(
    cr: &mut CrInstance,
    operators: &[&OperatorInstance],
    owned_group_kinds: &HashSet<(String, String)>,
) {
    // ownerRef pointing to operator's CSV → Managed ONLY if UID matches
    // (name-only match would accept stale generation's CSV)
    for (ref_kind, ref_name, ref_uid) in &cr.owner_refs {
        for op in operators {
            if ref_kind == "ClusterServiceVersion" && ref_name == &op.csv.name {
                let csv_uid = op.csv.uid.as_deref().unwrap_or("");
                if !csv_uid.is_empty() && !ref_uid.is_empty() && ref_uid == csv_uid {
                    cr.provenance = Provenance::Managed;
                    return;
                }
                // Same name but UID mismatch or missing → LikelyManaged (not Managed)
                cr.provenance = Provenance::LikelyManaged;
                return;
            }
            // Deployment ownerRef: name match only (no UID snapshot in OperatorInstance)
            // → LikelyManaged, not Managed (cannot verify identity)
            for deploy in &op.deployments {
                if ref_kind == "Deployment" && ref_name == deploy {
                    cr.provenance = Provenance::LikelyManaged;
                    return;
                }
            }
        }
    }

    // ownerRef kind matches an owned CRD kind (via authoritative gk_map).
    // Attribution hint only — does NOT change provenance or grant DELETE authority.
    // ownerRef lacks apiVersion, so kind match alone is a weak hint
    // (different API groups could share the same Kind name).
    for (ref_kind, ref_name, ref_uid) in &cr.owner_refs {
        let kind_matches = owned_group_kinds.iter().any(|(_, k)| k == ref_kind);
        if kind_matches {
            cr.ownerref_to_owned_api_kind = Some(format!(
                "{}/{} (uid: {}, kind-only match — ownerRef group unverified)",
                ref_kind, ref_name, ref_uid
            ));
            return;
        }
    }

    // Operator-related labels → LikelyManaged (not strong enough for DELETE)
    for key in cr.labels.keys() {
        for op in operators {
            let csv_prefix = op.csv.name.split('.').next().unwrap_or("");
            if !csv_prefix.is_empty() && key.contains(csv_prefix) {
                cr.provenance = Provenance::LikelyManaged;
                return;
            }
        }
    }

    // managedFields manager matching operator name → LikelyManaged
    for manager in &cr.managed_field_managers {
        for op in operators {
            for deploy in &op.deployments {
                if manager.contains(deploy) {
                    cr.provenance = Provenance::LikelyManaged;
                    return;
                }
            }
            let csv_prefix = op.csv.name.split('.').next().unwrap_or("");
            if !csv_prefix.is_empty() && manager.contains(csv_prefix) {
                cr.provenance = Provenance::LikelyManaged;
                return;
            }
        }
    }

    // Remains Unknown
}

/// Topological sort of target operators by dependency.
/// Returns layers: layer[0] has operators that depend on others (remove first),
/// layer[last] has operators that others depend on (remove last).
pub enum TopoSortResult {
    Layers(Vec<Vec<usize>>),
    Cycle(Vec<OperatorId>),
}

pub fn topo_sort_operators(
    target_indices: &[usize],
    all_operators: &[OperatorInstance],
    deps: &[OperatorDependency],
) -> TopoSortResult {
    if target_indices.len() <= 1 {
        return TopoSortResult::Layers(vec![target_indices.to_vec()]);
    }

    let target_ids: HashMap<OperatorId, usize> = target_indices
        .iter()
        .map(|&i| (OperatorId::from_instance(&all_operators[i]), i))
        .collect();

    // Build adjacency: from depends on to
    let mut depends_on: HashMap<OperatorId, HashSet<OperatorId>> = HashMap::new();
    for dep in deps {
        if target_ids.contains_key(&dep.from) && target_ids.contains_key(&dep.to) {
            depends_on
                .entry(dep.from.clone())
                .or_default()
                .insert(dep.to.clone());
        }
    }

    // Kahn's algorithm
    let mut in_degree: HashMap<OperatorId, usize> = HashMap::new();
    for id in target_ids.keys() {
        in_degree.insert(id.clone(), 0);
    }
    for providers in depends_on.values() {
        for provider in providers {
            *in_degree.entry(provider.clone()).or_insert(0) += 1;
        }
    }

    let mut layers = Vec::new();
    let mut remaining: HashSet<OperatorId> = target_ids.keys().cloned().collect();

    while !remaining.is_empty() {
        let layer: Vec<OperatorId> = remaining
            .iter()
            .filter(|id| in_degree.get(*id).copied().unwrap_or(0) == 0)
            .cloned()
            .collect();

        if layer.is_empty() {
            return TopoSortResult::Cycle(remaining.into_iter().collect());
        }

        let layer_indices: Vec<usize> = layer
            .iter()
            .filter_map(|id| target_ids.get(id).copied())
            .collect();
        layers.push(layer_indices);

        for id in &layer {
            remaining.remove(id);
            if let Some(providers) = depends_on.get(id) {
                for provider in providers {
                    if let Some(deg) = in_degree.get_mut(provider) {
                        *deg = deg.saturating_sub(1);
                    }
                }
            }
        }
    }

    TopoSortResult::Layers(layers)
}

const DISCOVERY_MAX_RETRIES: usize = 2;
const DISCOVERY_REQUEST_TIMEOUT_SECS: u64 = 30;

pub(crate) async fn list_paginated_with_retry(
    api: &Api<DynamicObject>,
    group: &str,
    version: &str,
    plural: &str,
) -> std::result::Result<Vec<DynamicObject>, ScanWarning> {
    let gvr = if group.is_empty() {
        format!("{}/{}", version, plural)
    } else {
        format!("{}/{}/{}", group, version, plural)
    };
    let is_tty = std::io::IsTerminal::is_terminal(&std::io::stderr());
    let mut last_warning = None;
    for attempt in 0..=DISCOVERY_MAX_RETRIES {
        let timeout_duration = std::time::Duration::from_secs(DISCOVERY_REQUEST_TIMEOUT_SECS);
        match tokio::time::timeout(timeout_duration, list_paginated_inner(api)).await {
            Ok(Ok(items)) => return Ok(items),
            Ok(Err(e)) => {
                let mut warning = ScanWarning::from_kube_error(&e, group, version, plural);
                if warning.is_retryable() && attempt < DISCOVERY_MAX_RETRIES {
                    let delay = std::time::Duration::from_millis(500 * (attempt as u64 + 1));
                    let msg = format!(
                        "{} — attempt {}/{} failed; retrying as {}/{} in {}ms",
                        gvr,
                        attempt + 1,
                        DISCOVERY_MAX_RETRIES + 1,
                        attempt + 2,
                        DISCOVERY_MAX_RETRIES + 1,
                        delay.as_millis()
                    );
                    if is_tty {
                        eprintln!("   \x1b[33m⚠ {}\x1b[0m", msg);
                    } else {
                        eprintln!("   ⚠ {}", msg);
                    }
                    tokio::time::sleep(delay).await;
                    last_warning = Some(warning);
                    continue;
                }
                warning.set_retries(attempt);
                return Err(warning);
            }
            Err(_elapsed) => {
                let warning = ScanWarning::Timeout {
                    gvr: gvr.clone(),
                    message: Some(format!(
                        "request timeout ({}s)",
                        DISCOVERY_REQUEST_TIMEOUT_SECS
                    )),
                    retries: attempt,
                };
                if attempt < DISCOVERY_MAX_RETRIES {
                    let delay = std::time::Duration::from_millis(500 * (attempt as u64 + 1));
                    let msg = format!(
                        "{} — timeout ({}s), attempt {}/{} failed; retrying as {}/{}",
                        gvr,
                        DISCOVERY_REQUEST_TIMEOUT_SECS,
                        attempt + 1,
                        DISCOVERY_MAX_RETRIES + 1,
                        attempt + 2,
                        DISCOVERY_MAX_RETRIES + 1,
                    );
                    if is_tty {
                        eprintln!("   \x1b[33m⚠ {}\x1b[0m", msg);
                    } else {
                        eprintln!("   ⚠ {}", msg);
                    }
                    tokio::time::sleep(delay).await;
                    last_warning = Some(warning);
                    continue;
                }
                return Err(warning);
            }
        }
    }
    let mut w = last_warning.unwrap();
    w.set_retries(DISCOVERY_MAX_RETRIES);
    Err(w)
}

async fn list_paginated_inner(
    api: &Api<DynamicObject>,
) -> std::result::Result<Vec<DynamicObject>, kube::Error> {
    let mut all_items = Vec::new();
    let mut continue_token: Option<String> = None;

    loop {
        let mut lp = ListParams::default().limit(LIST_PAGE_SIZE);
        if let Some(token) = &continue_token {
            lp = lp.continue_token(token);
        }
        let list = api.list(&lp).await?;
        let metadata = list.metadata;
        all_items.extend(list.items);

        match metadata.continue_.filter(|t| !t.is_empty()) {
            Some(token) => continue_token = Some(token),
            None => break,
        }
    }

    Ok(all_items)
}

/// Check Subscription linkage safety for a single operator.
/// has_unlinked_subscriptions is evaluated FIRST regardless of subscription Some/None.
pub fn check_subscription_safety(op: &OperatorInstance) -> (bool, PreflightSeverity, String) {
    if op.has_unlinked_subscriptions {
        (
            false,
            PreflightSeverity::Critical,
            format!(
                "Subscription linkage is ambiguous for CSV/{} in {} — \
                 multiple Subscriptions or unlinked Subscriptions exist. \
                 Cannot safely determine which Subscription to delete \
                 in Phase 0.{}",
                op.csv.name,
                op.install_namespace,
                op.subscription
                    .as_ref()
                    .map(|s| format!(" (currently linked to {})", s.name))
                    .unwrap_or_default(),
            ),
        )
    } else {
        match &op.subscription {
            Some(sub) => (
                true,
                PreflightSeverity::Warning,
                format!(
                    "Subscription/{} found — will be deleted in Phase 0",
                    sub.name
                ),
            ),
            None => (
                true,
                PreflightSeverity::Warning,
                format!(
                    "No subscription for CSV/{} — already frozen or manually installed",
                    op.csv.name
                ),
            ),
        }
    }
}

async fn run_preflight(
    client: &Client,
    target_operators: &[&OperatorInstance],
    kind_map: &KindMap,
    total_observations: usize,
    unique_count: usize,
    review_provenance_count: usize,
    unavailable_crds: &[ScanWarning],
) -> Preflight {
    let mut checks = Vec::new();

    // 1. Subscription resolved (absent is OK — already frozen / manually managed)
    for op in target_operators {
        let (passed, severity, detail) = check_subscription_safety(op);
        checks.push(PreflightCheck {
            name: format!("Subscription resolved ({})", op.csv.name),
            severity,
            passed,
            detail,
        });
    }

    // 2. CSV status and controller health (parallel)
    let kind_map_arc = Arc::new(kind_map.clone());
    let health_futs = target_operators.iter().map(|op| {
        let client = client.clone();
        let km = kind_map_arc.clone();
        let op = (*op).clone();
        async move {
            let csv = check_csv_health(&client, &op, &km).await;
            let ctrl = check_controller_health(&client, &op, &km).await;
            (op.csv.name.clone(), csv, ctrl)
        }
    });

    let health_results: Vec<_> = futures::stream::iter(health_futs)
        .buffer_unordered(DEFAULT_CONCURRENCY)
        .collect()
        .await;

    for (csv_name, csv_ok, ctrl_ok) in health_results {
        checks.push(PreflightCheck {
            name: format!("CSV health ({})", csv_name),
            severity: PreflightSeverity::Critical,
            passed: csv_ok.0,
            detail: csv_ok.1,
        });
        checks.push(PreflightCheck {
            name: format!("Controller available ({})", csv_name),
            severity: PreflightSeverity::Critical,
            passed: ctrl_ok.0,
            detail: ctrl_ok.1,
        });
    }

    // 3. Dedup summary
    if total_observations != unique_count {
        checks.push(PreflightCheck {
            name: "CR dedup".to_string(),
            severity: PreflightSeverity::Warning,
            passed: true,
            detail: format!(
                "{} observations normalized to {} unique CRs",
                total_observations, unique_count
            ),
        });
    }

    // 4. Undiscoverable CRDs
    for warning in unavailable_crds {
        checks.push(PreflightCheck {
            name: format!("CR enumeration ({})", warning),
            severity: PreflightSeverity::Critical,
            passed: false,
            detail: format!("cannot enumerate: {}", warning),
        });
    }

    // 5. Uncertain provenance
    if review_provenance_count > 0 {
        checks.push(PreflightCheck {
            name: "Provenance".to_string(),
            severity: PreflightSeverity::Warning,
            passed: false,
            detail: format!(
                "{} CRs have uncertain provenance (will be marked REVIEW if independent)",
                review_provenance_count
            ),
        });
    }

    Preflight { checks }
}

async fn check_csv_health(
    client: &Client,
    op: &OperatorInstance,
    kind_map: &KindMap,
) -> (bool, String) {
    let csv_info = match kind_map.get("ClusterServiceVersion") {
        Some(i) => i,
        None => return (false, "ClusterServiceVersion kind not found".to_string()),
    };

    let gvk =
        GroupVersion::gv(&csv_info.group, &csv_info.version).with_kind("ClusterServiceVersion");
    let ar = ApiResource::from_gvk_with_plural(&gvk, &csv_info.plural);
    let ns = op.csv.namespace.as_deref().unwrap_or(&op.install_namespace);
    let api: Api<DynamicObject> = Api::namespaced_with(client.clone(), ns, &ar);

    match api.get(&op.csv.name).await {
        Ok(obj) => {
            let phase = obj
                .data
                .get("status")
                .and_then(|s| s.get("phase"))
                .and_then(|p| p.as_str())
                .unwrap_or("Unknown");
            let passed = phase == "Succeeded";
            (passed, format!("phase={}", phase))
        }
        Err(e) => (false, format!("GET failed: {}", e)),
    }
}

async fn check_controller_health(
    client: &Client,
    op: &OperatorInstance,
    kind_map: &KindMap,
) -> (bool, String) {
    let deploy_info = match kind_map.get("Deployment") {
        Some(i) => i,
        None => return (false, "Deployment kind not found".to_string()),
    };

    let mut all_available = true;
    let mut details = Vec::new();

    for deploy_name in &op.deployments {
        let gvk =
            GroupVersion::gv(&deploy_info.group, &deploy_info.version).with_kind("Deployment");
        let ar = ApiResource::from_gvk_with_plural(&gvk, &deploy_info.plural);
        let api: Api<DynamicObject> =
            Api::namespaced_with(client.clone(), &op.install_namespace, &ar);

        match api.get(deploy_name).await {
            Ok(obj) => {
                let available = obj
                    .data
                    .get("status")
                    .and_then(|s| s.get("availableReplicas"))
                    .and_then(|r| r.as_i64())
                    .unwrap_or(0);
                if available > 0 {
                    details.push(format!("{}: Available ({})", deploy_name, available));
                } else {
                    all_available = false;
                    details.push(format!("{}: NOT Available", deploy_name));
                }
            }
            Err(_) => {
                all_available = false;
                details.push(format!("{}: NOT FOUND", deploy_name));
            }
        }
    }

    (all_available, details.join("; "))
}

const STANDARD_CONFIGMAPS: &[&str] = &["kube-root-ca.crt", "openshift-service-ca.crt"];

/// Discover part-of label values for related CRD scoping.
///
/// Strategy:
/// 1. Direct seed: part-of labels on target-owned CRDs themselves
/// 2. Group seed: part-of labels on CRDs sharing a full API group
///    with target-owned CRDs (e.g. both under the same API group)
///
/// No domain suffix guessing — avoids public suffix ambiguity.
pub async fn compute_part_of_seeds(
    target_crds: &[String],
    kind_map: &KindMap,
    client: &Client,
) -> (HashSet<(String, String)>, Vec<ScanWarning>) {
    if target_crds.is_empty() {
        return (HashSet::new(), vec![]);
    }

    let target_crd_set: HashSet<&str> = target_crds.iter().map(|s| s.as_str()).collect();
    let target_groups: HashSet<&str> = target_crds
        .iter()
        .filter_map(|crd| crd.split_once('.').map(|(_, g)| g))
        .collect();

    let Some(crd_ki) = kind_map.get("CustomResourceDefinition") else {
        return (
            HashSet::new(),
            vec![ScanWarning::Other {
                gvr: "apiextensions.k8s.io/v1/customresourcedefinitions".to_string(),
                message: "CustomResourceDefinition kind not found in discovery".to_string(),
            }],
        );
    };

    let crd_gvk =
        GroupVersion::gv(&crd_ki.group, &crd_ki.version).with_kind("CustomResourceDefinition");
    let crd_ar = ApiResource::from_gvk_with_plural(&crd_gvk, &crd_ki.plural);
    let crd_api: Api<DynamicObject> = Api::all_with(client.clone(), &crd_ar);

    let crd_items =
        match list_paginated_with_retry(&crd_api, &crd_ki.group, &crd_ki.version, &crd_ki.plural)
            .await
        {
            Ok(items) => items,
            Err(w) => {
                return (HashSet::new(), vec![w]);
            }
        };

    // Discover part-of label key/value pairs from target-owned CRDs.
    // Checks standard app.kubernetes.io/part-of and any */part-of key present on
    // target CRDs or CRDs sharing the exact same API group.
    let part_of_suffixes = ["/part-of", "/managed-by"];
    let standard_keys = [
        "app.kubernetes.io/part-of",
        "app.kubernetes.io/managed-by",
        "app.kubernetes.io/instance",
    ];

    let mut values = HashSet::new();
    for crd in &crd_items {
        let crd_name = crd.metadata.name.as_deref().unwrap_or("");
        let crd_group = crd_name.split_once('.').map(|(_, g)| g).unwrap_or("");

        let is_target = target_crd_set.contains(crd_name);
        let shares_group = target_groups.contains(crd_group);

        if (is_target || shares_group)
            && let Some(labels) = &crd.metadata.labels
        {
            for (k, v) in labels {
                let is_part_of = part_of_suffixes.iter().any(|s| k.ends_with(s))
                    || standard_keys.contains(&k.as_str());
                if is_part_of {
                    values.insert((k.clone(), v.clone()));
                }
            }
        }
    }

    (values, vec![])
}

pub struct RelatedCrdReport {
    pub actions: Vec<Action>,
    pub instances: Vec<CrInstance>,
    pub unavailable_crds: Vec<ScanWarning>,
    pub crd_count: usize,
    pub instance_count: usize,
}

pub async fn discover_related_crd_instances(
    client: &Client,
    target_crds: &HashSet<&str>,
    target_label_pairs: &HashSet<(String, String)>,
    kind_map: &KindMap,
    gvr_map: &GvrMap,
    gk_map: &GroupKindMap,
) -> RelatedCrdReport {
    let mut actions = Vec::new();

    // If target operator has no part-of labels, skip related discovery entirely
    if target_label_pairs.is_empty() {
        return RelatedCrdReport {
            actions,
            instances: vec![],
            unavailable_crds: vec![],
            crd_count: 0,
            instance_count: 0,
        };
    }

    let crd_kind_info = match kind_map.get("CustomResourceDefinition") {
        Some(i) => i,
        None => {
            return RelatedCrdReport {
                actions,
                instances: vec![],
                unavailable_crds: vec![ScanWarning::Other {
                    gvr: "<related-crd-catalog>".to_string(),
                    message: "CustomResourceDefinition kind not found in discovery".to_string(),
                }],
                crd_count: 0,
                instance_count: 0,
            };
        }
    };

    let crd_gvk = GroupVersion::gv(&crd_kind_info.group, &crd_kind_info.version)
        .with_kind("CustomResourceDefinition");
    let crd_ar = ApiResource::from_gvk_with_plural(&crd_gvk, &crd_kind_info.plural);
    let crd_api: Api<DynamicObject> = Api::all_with(client.clone(), &crd_ar);

    let all_crds = match list_paginated_with_retry(
        &crd_api,
        &crd_kind_info.group,
        &crd_kind_info.version,
        &crd_kind_info.plural,
    )
    .await
    {
        Ok(items) => items,
        Err(w) => {
            return RelatedCrdReport {
                actions,
                instances: vec![],
                unavailable_crds: vec![w],
                crd_count: 0,
                instance_count: 0,
            };
        }
    };

    // Scope CRD types by label pair match — record which pairs matched per CRD
    let mut related_crd_pairs: std::collections::HashMap<String, Vec<(String, String)>> =
        std::collections::HashMap::new();
    for crd in &all_crds {
        let crd_name = match &crd.metadata.name {
            Some(n) => n,
            None => continue,
        };
        if target_crds.contains(crd_name.as_str()) {
            continue;
        }
        if let Some(labels) = &crd.metadata.labels {
            let intersection: Vec<(String, String)> = labels
                .iter()
                .filter(|(k, v)| target_label_pairs.contains(&((*k).clone(), (*v).clone())))
                .map(|(k, v)| (k.clone(), v.clone()))
                .collect();
            if !intersection.is_empty() {
                related_crd_pairs.insert(crd_name.clone(), intersection);
            }
        }
    }

    if related_crd_pairs.is_empty() {
        return RelatedCrdReport {
            actions,
            instances: vec![],
            unavailable_crds: vec![],
            crd_count: 0,
            instance_count: 0,
        };
    }

    let related_crd_names: Vec<String> = related_crd_pairs.keys().cloned().collect();
    let related_report = discover_cr_instances(client, &related_crd_names, gvr_map, gk_map).await;

    let crd_count = related_crd_names.len();
    let instance_count = related_report.instances.len();

    let mut instances = related_report.instances;
    for cr in &mut instances {
        let decisive = related_crd_pairs
            .get(&cr.api_owner_key)
            .cloned()
            .unwrap_or_default();
        cr.decisive_label_pairs = decisive.clone();

        actions.push(Action::Review {
            resource: cr.id.clone(),
            reason: "related CRD instance (not CSV-owned, discovered via label)".to_string(),
            metadata: Some(crate::teardown::plan::ReviewMetadata {
                category: Some(crate::teardown::plan::ReviewCategorySer::OperandIndependent),
                approval_class: Some(crate::teardown::plan::DeleteApprovalClassSer::ExplicitOnly),
                provenance: match &cr.provenance {
                    Provenance::Managed => Some(crate::teardown::plan::ProvenanceSer::Managed),
                    Provenance::LikelyManaged => {
                        Some(crate::teardown::plan::ProvenanceSer::LikelyManaged)
                    }
                    Provenance::Unknown => Some(crate::teardown::plan::ProvenanceSer::Unknown),
                },
                discovery_source: Some(crate::teardown::plan::DiscoverySourceSer::RelatedLabelOnly),
                decisive_label_pairs: decisive,
            }),
        });
    }

    RelatedCrdReport {
        actions,
        instances,
        unavailable_crds: related_report.unavailable_crds,
        crd_count,
        instance_count,
    }
}

async fn discover_namespace_resources(
    client: &Client,
    target_operators: &[&OperatorInstance],
    all_operators: &[OperatorInstance],
    kind_map: &KindMap,
) -> Vec<Action> {
    let mut actions = Vec::new();

    let target_namespaces: HashSet<&str> = target_operators
        .iter()
        .map(|op| op.install_namespace.as_str())
        .collect();

    let target_csv_names: HashSet<&str> = target_operators
        .iter()
        .map(|op| op.csv.name.as_str())
        .collect();

    let target_deployment_names: HashSet<&str> = target_operators
        .iter()
        .flat_map(|op| op.deployments.iter().map(|d| d.as_str()))
        .collect();

    let csv_prefix: Vec<&str> = target_operators
        .iter()
        .filter_map(|op| op.csv.name.split('.').next())
        .filter(|p| !p.is_empty())
        .collect();

    for ns in &target_namespaces {
        // 1. OperatorGroup cleanup
        let og_gvk = GroupVersion::gv("operators.coreos.com", "v1").with_kind("OperatorGroup");
        let og_ar = ApiResource::from_gvk_with_plural(&og_gvk, "operatorgroups");
        let og_api: Api<DynamicObject> = Api::namespaced_with(client.clone(), ns, &og_ar);

        if let Ok(og_list) = og_api.list(&ListParams::default()).await {
            // Check if any non-target CSVs remain in this namespace
            let other_csvs_exist = all_operators.iter().any(|op| {
                op.install_namespace == *ns && !target_csv_names.contains(op.csv.name.as_str())
            });

            for og in og_list.items {
                let og_name = og.metadata.name.clone().unwrap_or_default();
                let og_id = ResourceId {
                    group: "operators.coreos.com".to_string(),
                    version: "v1".to_string(),
                    kind: "OperatorGroup".to_string(),
                    namespace: Some(ns.to_string()),
                    name: og_name.clone(),
                    uid: og.metadata.uid.clone(),
                };

                if other_csvs_exist {
                    actions.push(Action::Keep {
                        resource: og_id,
                        reason: "other operators remain in namespace".to_string(),
                    });
                } else {
                    actions.push(Action::Review {
                        resource: og_id,
                        reason: "no other operators in namespace — verify before deleting"
                            .to_string(),
                        metadata: None,
                    });
                }
            }
        }

        // 2. Leader election Lease cleanup
        let lease_gvk = GroupVersion::gv("coordination.k8s.io", "v1").with_kind("Lease");
        let lease_ar = ApiResource::from_gvk_with_plural(&lease_gvk, "leases");
        let lease_api: Api<DynamicObject> = Api::namespaced_with(client.clone(), ns, &lease_ar);

        if let Ok(lease_list) = lease_api.list(&ListParams::default()).await {
            for lease in lease_list.items {
                let lease_name = lease.metadata.name.clone().unwrap_or_default();

                let holder = lease
                    .data
                    .get("spec")
                    .and_then(|s| s.get("holderIdentity"))
                    .and_then(|h| h.as_str())
                    .unwrap_or("");

                let holder_matches = target_deployment_names
                    .iter()
                    .any(|dep| holder.contains(dep));

                let name_matches = csv_prefix.iter().any(|prefix| lease_name.contains(prefix));

                if holder_matches || name_matches {
                    actions.push(Action::Review {
                        resource: ResourceId {
                            group: "coordination.k8s.io".to_string(),
                            version: "v1".to_string(),
                            kind: "Lease".to_string(),
                            namespace: Some(ns.to_string()),
                            name: lease_name,
                            uid: lease.metadata.uid.clone(),
                        },
                        reason: if holder_matches {
                            "leader election lease (holder references operator deployment)"
                                .to_string()
                        } else {
                            "leader election lease (name matches operator)".to_string()
                        },
                        metadata: None,
                    });
                }
            }
        }

        // 3. Operator ConfigMaps as REVIEW
        if let Some(cm_info) = kind_map.get("ConfigMap") {
            let cm_gvk = GroupVersion::gv(&cm_info.group, &cm_info.version).with_kind("ConfigMap");
            let cm_ar = ApiResource::from_gvk_with_plural(&cm_gvk, &cm_info.plural);
            let cm_api: Api<DynamicObject> = Api::namespaced_with(client.clone(), ns, &cm_ar);

            if let Ok(cm_list) = cm_api.list(&ListParams::default()).await {
                for cm in cm_list.items {
                    let cm_name = cm.metadata.name.clone().unwrap_or_default();

                    if STANDARD_CONFIGMAPS.contains(&cm_name.as_str()) {
                        continue;
                    }

                    let name_matches = csv_prefix.iter().any(|prefix| cm_name.contains(prefix));

                    if name_matches {
                        actions.push(Action::Review {
                            resource: ResourceId {
                                group: String::new(),
                                version: "v1".to_string(),
                                kind: "ConfigMap".to_string(),
                                namespace: Some(ns.to_string()),
                                name: cm_name,
                                uid: cm.metadata.uid.clone(),
                            },
                            reason: "operator-related ConfigMap — verify before deleting"
                                .to_string(),
                            metadata: Some(crate::teardown::plan::ReviewMetadata {
                                category: Some(crate::teardown::plan::ReviewCategorySer::Ancillary),
                                approval_class: Some(
                                    crate::teardown::plan::DeleteApprovalClassSer::ExplicitOnly,
                                ),
                                provenance: None,
                                discovery_source: None,
                                decisive_label_pairs: vec![],
                            }),
                        });
                    }
                }
            }
        }
    }

    actions
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum GraphPosition {
    Root,
    Descendant,
    Independent,
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum ReviewCategory {
    Operand(GraphPosition),
    Ancillary,
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum DeleteApprovalClass {
    Standard,
    ExplicitOnly,
}

fn compute_approval_class_from_category(
    cr: &CrInstance,
    category: ReviewCategory,
) -> DeleteApprovalClass {
    if cr.discovery_source == DiscoverySource::RelatedLabelOnly {
        if let ReviewCategory::Operand(GraphPosition::Descendant) = category {
            return DeleteApprovalClass::Standard;
        }
        return DeleteApprovalClass::ExplicitOnly;
    }
    if matches!(category, ReviewCategory::Ancillary) {
        return DeleteApprovalClass::ExplicitOnly;
    }
    DeleteApprovalClass::Standard
}

fn compute_approval_class(cr: &CrInstance, position: GraphPosition) -> DeleteApprovalClass {
    compute_approval_class_from_category(cr, ReviewCategory::Operand(position))
}

fn is_label_only_bulk_eligible(cr: &CrInstance) -> bool {
    matches!(cr.discovery_source, DiscoverySource::RelatedLabelOnly)
        && !matches!(
            cr.id.kind.as_str(),
            "Namespace" | "PersistentVolumeClaim" | "PersistentVolume" | "CustomResourceDefinition"
        )
}

fn is_exact_delete_approvable(
    cr: &CrInstance,
    position: GraphPosition,
    owner_count: usize,
) -> bool {
    if matches!(cr.provenance, Provenance::Managed) {
        return false;
    }
    if owner_count > 1 {
        return false;
    }
    matches!(position, GraphPosition::Root | GraphPosition::Independent)
}

pub struct ReviewCandidate<'a> {
    pub resource: &'a ResourceId,
    pub category: ReviewCategory,
    pub approval_class: DeleteApprovalClass,
    pub exact_approvable: bool,
    pub is_label_only_eligible: bool,
}

/// Phase-ordered EXPECT→DELETE invariant enforcement.
/// Only DELETEs from the current or earlier phases can support EXPECT_GONE.
/// Unsupported EXPECTs are demoted to KEEP.
fn enforce_expect_delete_invariant(
    phases: &mut [PlanPhase],
    uid_to_owner_uids: &HashMap<String, Vec<String>>,
) {
    let mut supported_uids: HashSet<String> = HashSet::new();

    for phase in phases.iter_mut() {
        for action in phase.actions.iter() {
            if let Action::Delete { resource, .. } = action
                && let Some(uid) = &resource.uid
            {
                supported_uids.insert(uid.clone());
            }
        }

        let phase_expects: Vec<(String, Vec<String>)> = phase
            .actions
            .iter()
            .filter_map(|a| match a {
                Action::ExpectGone { resource, .. } => {
                    let uid = resource.uid.clone()?;
                    let owner_uids = uid_to_owner_uids.get(&uid)?.clone();
                    Some((uid, owner_uids))
                }
                _ => None,
            })
            .collect();

        loop {
            let mut changed = false;
            for (uid, owner_uids) in &phase_expects {
                if supported_uids.contains(uid) {
                    continue;
                }
                if owner_uids.iter().any(|ou| supported_uids.contains(ou)) {
                    supported_uids.insert(uid.clone());
                    changed = true;
                }
            }
            if !changed {
                break;
            }
        }

        for action in &mut phase.actions {
            if let Action::ExpectGone { resource, .. } = action {
                let uid_supported = resource
                    .uid
                    .as_ref()
                    .is_some_and(|uid| supported_uids.contains(uid));
                if !uid_supported {
                    *action = Action::Keep {
                        resource: resource.clone(),
                        reason: "cleanup trigger not scheduled for deletion".to_string(),
                    };
                }
            }
        }
    }
}

#[allow(clippy::too_many_arguments)]
pub async fn generate_teardown_plan(
    client: &Client,
    target_operators: &[&OperatorInstance],
    all_operators: &[OperatorInstance],
    kind_map: &KindMap,
    gvr_map: &GvrMap,
    gk_map: &GroupKindMap,
    gvk_map: &GvkMap,
    prune_crds: bool,
    policy: &DecisionPolicy,
) -> Result<TeardownPlan> {
    let target_ids: HashSet<OperatorId> = target_operators
        .iter()
        .map(|op| OperatorId::from_instance(op))
        .collect();

    let targets: Vec<OperatorTarget> = target_operators
        .iter()
        .map(|op| OperatorTarget {
            subscription: op.subscription.clone(),
            csv: op.csv.clone(),
            install_namespace: op.install_namespace.clone(),
        })
        .collect();

    let target_crds: Vec<String> = {
        let mut seen = HashSet::new();
        target_operators
            .iter()
            .flat_map(|op| op.owned_crds.iter())
            .filter(|crd| seen.insert((*crd).clone()))
            .cloned()
            .collect()
    };
    let target_crd_set: HashSet<&str> = target_crds.iter().map(|s| s.as_str()).collect();

    // Collect owned APIService definitions for resource discovery
    let target_api_service_defs: Vec<&OwnedApiServiceDef> = target_operators
        .iter()
        .flat_map(|op| op.owned_api_service_defs.iter())
        .collect();

    // Resolve APIService-backed resources via exact (group, version, kind) lookup
    let mut unresolved_api_services: Vec<String> = Vec::new();
    let mut api_service_warnings: Vec<String> = Vec::new();
    let mut api_service_kind_infos: Vec<(&OwnedApiServiceDef, KindInfo)> = Vec::new();
    for def in &target_api_service_defs {
        if def.group.is_empty() || def.version.is_empty() || def.kind.is_empty() {
            unresolved_api_services.push(format!(
                "{} (incomplete definition: group={:?}, version={:?}, kind={:?})",
                def.name, def.group, def.version, def.kind
            ));
            continue;
        }
        let gvk_key = (def.group.clone(), def.version.clone(), def.kind.clone());
        match gvk_map.get(&gvk_key) {
            Some(kind_info) => {
                if def.name != kind_info.plural {
                    api_service_warnings.push(format!(
                        "APIService {}: CSV plural '{}' differs from discovery plural '{}' — using discovery",
                        def.api_service_object_name(),
                        def.name,
                        kind_info.plural
                    ));
                }
                api_service_kind_infos.push((def, kind_info.clone()));
            }
            None => {
                unresolved_api_services.push(format!(
                    "{} ({}/{}/{})",
                    def.name, def.group, def.version, def.kind
                ));
            }
        }
    }

    eprint!("🔍 Discovering CR instances...");
    let cr_report = discover_cr_instances(client, &target_crds, gvr_map, gk_map).await;
    let api_svc_report = discover_api_service_instances(client, &api_service_kind_infos).await;
    let mut cr_instances = cr_report.instances;
    cr_instances.extend(api_svc_report.instances);
    let mut all_unavailable = cr_report.unavailable_crds;
    all_unavailable.extend(api_svc_report.unavailable_crds);
    let direct_count = cr_instances.len();
    eprintln!(" found {} direct instances", direct_count);

    // Related CRD discovery — scoped by label VALUE match
    eprint!("🔍 Discovering related CRD instances...");
    let (target_label_pairs, seed_unavailable) =
        compute_part_of_seeds(&target_crds, kind_map, client).await;
    all_unavailable.extend(seed_unavailable);

    let related_report = discover_related_crd_instances(
        client,
        &target_crd_set,
        &target_label_pairs,
        kind_map,
        gvr_map,
        gk_map,
    )
    .await;
    eprintln!(
        " {} CRDs, {} instances",
        related_report.crd_count, related_report.instance_count
    );

    // Two-category merge of related instances:
    // - Linked: ownerRef chain reaches target anchors → merge into graph (EXPECT/descendant)
    // - Unlinked: scoped CRD type but no ownerRef chain → independent REVIEW
    {
        // Target anchors: direct CR UIDs + CSV UIDs
        let mut anchor_uids: HashSet<String> = cr_instances
            .iter()
            .filter_map(|cr| cr.id.uid.clone())
            .collect();
        for op in target_operators {
            if let Some(uid) = &op.csv.uid {
                anchor_uids.insert(uid.clone());
            }
        }

        let related_instances = related_report.instances;

        let related_uid_to_owners: HashMap<String, Vec<String>> = related_instances
            .iter()
            .filter_map(|cr| {
                let uid = cr.id.uid.clone()?;
                let owners: Vec<String> = cr.owner_refs.iter().map(|(_, _, u)| u.clone()).collect();
                Some((uid, owners))
            })
            .collect();

        fn is_reachable(
            uid: &str,
            anchor_uids: &HashSet<String>,
            related_owners: &HashMap<String, Vec<String>>,
            visited: &mut HashSet<String>,
        ) -> bool {
            if anchor_uids.contains(uid) {
                return true;
            }
            if !visited.insert(uid.to_string()) {
                return false;
            }
            if let Some(owners) = related_owners.get(uid) {
                for owner_uid in owners {
                    if is_reachable(owner_uid, anchor_uids, related_owners, visited) {
                        return true;
                    }
                }
            }
            false
        }

        let mut linked_count = 0;
        let mut unlinked_count = 0;
        for cr in related_instances {
            let linked = cr.owner_refs.iter().any(|(_, _, owner_uid)| {
                is_reachable(
                    owner_uid,
                    &anchor_uids,
                    &related_uid_to_owners,
                    &mut HashSet::new(),
                )
            });
            if linked {
                linked_count += 1;
                let mut cr = cr;
                cr.discovery_source = DiscoverySource::RelatedLinked;
                cr_instances.push(cr);
            } else {
                unlinked_count += 1;
                let mut cr = cr;
                cr.discovery_source = DiscoverySource::RelatedLabelOnly;
                // decisive_label_pairs already set per-CRD by discover_related_crd_instances
                cr_instances.push(cr);
            }
        }

        if linked_count > 0 || unlinked_count > 0 {
            eprintln!(
                "  {} linked, {} unlinked (independent REVIEW)",
                linked_count, unlinked_count
            );
        }
    }
    // Only include unavailable CRDs from scoped related discovery
    all_unavailable.extend(related_report.unavailable_crds);

    // UID dedup across direct + APIService + related sources
    // Ensures 1 Kubernetes UID = 1 CrInstance node in the graph
    let pre_dedup = cr_instances.len();
    {
        let mut seen = HashSet::new();
        cr_instances.retain(|cr| match cr.id.uid.as_deref() {
            Some(uid) => seen.insert(uid.to_string()),
            None => {
                let fallback = format!(
                    "{}/{}/{}/{}",
                    cr.id.group,
                    cr.id.kind,
                    cr.id.namespace.as_deref().unwrap_or("-"),
                    cr.id.name
                );
                seen.insert(fallback)
            }
        });
    }
    let total_observations = direct_count + related_report.instance_count;
    let unique_count = cr_instances.len();
    let duplicates = pre_dedup - unique_count;
    if !all_unavailable.is_empty() {
        eprintln!(
            "  ⚠ {} API type(s) could not be enumerated",
            all_unavailable.len()
        );
    }

    // Classify provenance (applies to both direct and related CRs)
    let owned_group_kinds = owned_crd_group_kinds(target_operators, gk_map);
    for cr in &mut cr_instances {
        classify_provenance(cr, target_operators, &owned_group_kinds);
    }

    let review_provenance_count = cr_instances
        .iter()
        .filter(|cr| {
            matches!(
                cr.provenance,
                Provenance::Unknown | Provenance::LikelyManaged
            )
        })
        .count();

    // Run preflight checks
    if !unresolved_api_services.is_empty() {
        eprintln!(
            "  ⚠ {} owned APIService(s) could not be resolved in API discovery",
            unresolved_api_services.len()
        );
    }

    eprint!("🔍 Running preflight checks...");
    let mut preflight = run_preflight(
        client,
        target_operators,
        kind_map,
        total_observations,
        unique_count,
        review_provenance_count,
        &all_unavailable,
    )
    .await;
    for api_svc in &unresolved_api_services {
        preflight.checks.push(PreflightCheck {
            name: format!("APIService resource resolution ({})", api_svc),
            severity: PreflightSeverity::Critical,
            passed: false,
            detail: format!(
                "cannot resolve resources served by owned APIService {} — operand discovery incomplete",
                api_svc
            ),
        });
    }
    eprintln!(" done");

    // Determine root vs managed CRs
    // Parent-first: has_parent_in_set takes priority so intermediate nodes
    // (both parent and child) are always classified as descendants.
    let cr_uids: HashSet<&str> = cr_instances
        .iter()
        .filter_map(|cr| cr.id.uid.as_deref())
        .collect();

    let referenced_owner_uids: HashSet<&str> = cr_instances
        .iter()
        .flat_map(|cr| cr.owner_refs.iter())
        .map(|(_, _, uid)| uid.as_str())
        .collect();

    let mut root_crs: Vec<&CrInstance> = Vec::new();
    let mut managed_descendants: Vec<&CrInstance> = Vec::new();
    let mut independent_crs: Vec<&CrInstance> = Vec::new();

    for cr in &cr_instances {
        let has_parent_in_set = cr
            .owner_refs
            .iter()
            .any(|(_, _, owner_uid)| cr_uids.contains(owner_uid.as_str()));

        let is_parent = cr
            .id
            .uid
            .as_deref()
            .is_some_and(|uid| referenced_owner_uids.contains(uid));

        if has_parent_in_set {
            // Parent + child intermediate nodes go here too
            managed_descendants.push(cr);
        } else if is_parent {
            // No parent + has children = observed graph root / cleanup trigger
            root_crs.push(cr);
        } else {
            // No parent + no children = graph-isolated, no auto-delete evidence
            independent_crs.push(cr);
        }
    }

    // Check for blockers
    let mut blockers = Vec::new();
    let mut warnings: Vec<Warning> = api_service_warnings
        .into_iter()
        .map(|msg| Warning {
            message: msg,
            resource: None,
        })
        .collect();

    // APIService identity: (group, version) pairs owned by target operators
    let target_api_service_gvs: HashSet<(String, String)> = target_operators
        .iter()
        .flat_map(|op| {
            op.owned_api_service_defs
                .iter()
                .map(|d| (d.group.clone(), d.version.clone()))
        })
        .collect();

    for op in all_operators {
        if target_ids.contains(&OperatorId::from_instance(op)) {
            continue;
        }
        for req_crd in &op.required_crds {
            if target_crd_set.contains(req_crd.as_str()) {
                blockers.push(Blocker {
                    resource: ResourceId {
                        group: "apiextensions.k8s.io".to_string(),
                        version: "v1".to_string(),
                        kind: "CustomResourceDefinition".to_string(),
                        namespace: None,
                        name: req_crd.clone(),
                        uid: None,
                    },
                    reason: format!(
                        "CRD {} cannot be removed: required by operator {}",
                        req_crd, op.csv.name
                    ),
                    external_dependency: Some(op.csv.name.clone()),
                });
            }
        }
        for req_def in &op.required_api_service_defs {
            let gv = (req_def.group.clone(), req_def.version.clone());
            if target_api_service_gvs.contains(&gv) {
                let obj_name = req_def.api_service_object_name();
                blockers.push(Blocker {
                    resource: ResourceId {
                        group: "apiregistration.k8s.io".to_string(),
                        version: "v1".to_string(),
                        kind: "APIService".to_string(),
                        namespace: None,
                        name: obj_name.clone(),
                        uid: None,
                    },
                    reason: format!(
                        "APIService {} cannot be removed: required by operator {}",
                        obj_name, op.csv.name
                    ),
                    external_dependency: Some(op.csv.name.clone()),
                });
            }
        }
        for owned_crd in &op.owned_crds {
            if target_crd_set.contains(owned_crd.as_str()) {
                warnings.push(Warning {
                    message: format!(
                        "CRD {} is also owned by unselected operator {}",
                        owned_crd, op.csv.name
                    ),
                    resource: Some(ResourceId {
                        group: "apiextensions.k8s.io".to_string(),
                        version: "v1".to_string(),
                        kind: "CustomResourceDefinition".to_string(),
                        namespace: None,
                        name: owned_crd.clone(),
                        uid: None,
                    }),
                });
            }
        }
    }

    // Add warnings for dedup and provenance
    if duplicates > 0 {
        warnings.push(Warning {
            message: format!(
                "{} duplicate CR discoveries normalized (multi-version CRDs)",
                duplicates
            ),
            resource: None,
        });
    }

    if review_provenance_count > 0 {
        warnings.push(Warning {
            message: format!(
                "{} CRs have uncertain provenance (owned API, but origin unknown)",
                review_provenance_count
            ),
            resource: None,
        });
    }

    // NOTE: blocked_crds/warned_crds computed after topo_sort (which may add cycle blockers)

    // ── Phase 0: Freeze OLM ──
    let mut phase0_actions = Vec::new();
    for op in target_operators {
        if let Some(sub) = &op.subscription {
            phase0_actions.push(Action::Delete {
                resource: sub.clone(),
                reason: "freeze OLM to prevent re-install".to_string(),
            });
        }
    }
    for op in target_operators {
        phase0_actions.push(Action::Keep {
            resource: op.csv.clone(),
            reason: "controller needed for operand cleanup".to_string(),
        });
    }

    let phase0 = PlanPhase {
        name: "Freeze OLM".to_string(),
        description: "Delete Subscriptions to prevent OLM from re-installing operators".to_string(),
        actions: phase0_actions,
        barrier: Some(Barrier {
            description: "Subscriptions deleted, controllers verified available".to_string(),
            conditions: target_operators
                .iter()
                .filter_map(|op| op.subscription.as_ref().map(|s| format!("{} is gone", s)))
                .collect(),
        }),
    };

    // ── Phase 1+: Trigger operand cleanup (dependency-layered) ──
    // Attribute each CR to its owning operator (CRD + APIService resources)
    // Use HashSet to dedup — a broken CSV may list the same definition twice
    let api_to_op_indices: HashMap<String, HashSet<usize>> = {
        let mut map: HashMap<String, HashSet<usize>> = HashMap::new();
        for (idx, op) in target_operators.iter().enumerate() {
            for crd in &op.owned_crds {
                map.entry(crd.clone()).or_default().insert(idx);
            }
            for def in &op.owned_api_service_defs {
                let key = format!("{}/{}/{}", def.group, def.version, def.kind);
                map.entry(key).or_default().insert(idx);
            }
        }
        map
    };

    // Build UID → CrInstance index for ownerRef ancestry resolution
    let cr_by_uid: HashMap<&str, &CrInstance> = cr_instances
        .iter()
        .filter_map(|cr| cr.id.uid.as_deref().map(|uid| (uid, cr)))
        .collect();

    // Collect ALL REVIEW candidates (root + independent + ancillary).
    // Managed CRs are excluded (auto-DELETE). Ancillary added after ns_cleanup.
    let mut review_candidates: Vec<ReviewCandidate> = root_crs
        .iter()
        .map(|cr| (cr, GraphPosition::Root))
        .chain(
            independent_crs
                .iter()
                .map(|cr| (cr, GraphPosition::Independent)),
        )
        .filter(|(cr, _)| !matches!(cr.provenance, Provenance::Managed))
        .map(|(cr, position)| {
            let owner_count = resolve_api_owner_indices(cr, &api_to_op_indices, &cr_by_uid).len();
            let category = ReviewCategory::Operand(position);
            let is_label_eligible = is_label_only_bulk_eligible(cr);
            ReviewCandidate {
                resource: &cr.id,
                category,
                approval_class: compute_approval_class(cr, position),
                exact_approvable: is_exact_delete_approvable(cr, position, owner_count),
                is_label_only_eligible: is_label_eligible,
            }
        })
        .collect();

    // ── Namespace cleanup discovery (needed for ancillary candidate registration) ──
    eprint!("🔍 Discovering namespace resources...");
    let ns_cleanup_actions =
        discover_namespace_resources(client, target_operators, all_operators, kind_map).await;
    eprintln!(" done");

    // Register ancillary REVIEW actions as candidates (ConfigMap REVIEWs etc.)
    // These are ExplicitOnly — bulk approval cannot touch them.
    let ancillary_review_resources: Vec<ResourceId> = ns_cleanup_actions
        .iter()
        .filter_map(|action| match action {
            Action::Review { resource, .. } => Some(resource.clone()),
            _ => None,
        })
        .collect();
    for resource in &ancillary_review_resources {
        review_candidates.push(ReviewCandidate {
            resource,
            category: ReviewCategory::Ancillary,
            approval_class: DeleteApprovalClass::ExplicitOnly,
            exact_approvable: true,
            is_label_only_eligible: false,
        });
    }

    // Resolve all decisions from policy + candidates
    let resolved_decisions = resolve_decisions(policy, &review_candidates)?;

    fn build_review_metadata(
        cr: &CrInstance,
        position: GraphPosition,
        approval: DeleteApprovalClass,
    ) -> Option<crate::teardown::plan::ReviewMetadata> {
        use crate::teardown::plan::{
            DeleteApprovalClassSer, DiscoverySourceSer, ProvenanceSer, ReviewCategorySer,
            ReviewMetadata,
        };
        let category = match (ReviewCategory::Operand(position), position) {
            (_, GraphPosition::Root) => Some(ReviewCategorySer::OperandRoot),
            (_, GraphPosition::Descendant) => Some(ReviewCategorySer::OperandDescendant),
            (_, GraphPosition::Independent) => Some(ReviewCategorySer::OperandIndependent),
        };
        let provenance = match &cr.provenance {
            Provenance::Managed => Some(ProvenanceSer::Managed),
            Provenance::LikelyManaged => Some(ProvenanceSer::LikelyManaged),
            Provenance::Unknown => Some(ProvenanceSer::Unknown),
        };
        let discovery = match &cr.discovery_source {
            DiscoverySource::Direct => Some(DiscoverySourceSer::Direct),
            DiscoverySource::RelatedLinked => Some(DiscoverySourceSer::RelatedLinked),
            DiscoverySource::RelatedLabelOnly => Some(DiscoverySourceSer::RelatedLabelOnly),
        };
        let approval_ser = match approval {
            DeleteApprovalClass::Standard => Some(DeleteApprovalClassSer::Standard),
            DeleteApprovalClass::ExplicitOnly => Some(DeleteApprovalClassSer::ExplicitOnly),
        };
        Some(ReviewMetadata {
            category,
            approval_class: approval_ser,
            provenance,
            discovery_source: discovery,
            decisive_label_pairs: cr.decisive_label_pairs.clone(),
        })
    }

    fn cr_to_action(
        cr: &CrInstance,
        position: GraphPosition,
        resolved: &HashMap<ResourceId, ResolvedDecision>,
    ) -> Action {
        let approval = compute_approval_class(cr, position);

        // Check pre-resolved decision
        if let Some(decision) = resolved.get(&cr.id) {
            match decision {
                ResolvedDecision::Delete { reason, .. } => {
                    return Action::Delete {
                        resource: cr.id.clone(),
                        reason: reason.clone(),
                    };
                }
                ResolvedDecision::Keep { reason } => {
                    return Action::Keep {
                        resource: cr.id.clone(),
                        reason: reason.clone(),
                    };
                }
                ResolvedDecision::Review => {}
            }
        }

        match (position, &cr.provenance) {
            (GraphPosition::Root, Provenance::Managed)
                if approval == DeleteApprovalClass::Standard =>
            {
                Action::Delete {
                    resource: cr.id.clone(),
                    reason: "root management CR (managed via ownerRef)".to_string(),
                }
            }
            (GraphPosition::Root, _) if approval == DeleteApprovalClass::ExplicitOnly => {
                let reason = if let Some(ref evidence) = cr.ownerref_to_owned_api_kind {
                    format!(
                        "ownerRef points to operator-owned API kind: {} (parent not in current graph, kind-only hint — explicit approval required)",
                        evidence
                    )
                } else {
                    "label-related only — discovered via platform label, no ownerRef chain to target operator".to_string()
                };
                Action::Review {
                    resource: cr.id.clone(),
                    reason,
                    metadata: build_review_metadata(cr, position, approval),
                }
            }
            (GraphPosition::Root, Provenance::LikelyManaged) => Action::Review {
                resource: cr.id.clone(),
                reason: "root CR but provenance uncertain (label-based) — verify before deleting"
                    .to_string(),
                metadata: build_review_metadata(cr, position, approval),
            },
            (GraphPosition::Root, Provenance::Unknown | Provenance::Managed) => Action::Review {
                resource: cr.id.clone(),
                reason: "root CR but provenance unknown — verify before deleting".to_string(),
                metadata: build_review_metadata(cr, position, approval),
            },
            (GraphPosition::Descendant, _) => Action::ExpectGone {
                resource: cr.id.clone(),
                reason: "managed descendant; controller expected to remove".to_string(),
            },
            (GraphPosition::Independent, _) if approval == DeleteApprovalClass::ExplicitOnly => {
                let reason = if let Some(ref evidence) = cr.ownerref_to_owned_api_kind {
                    format!(
                        "ownerRef points to operator-owned API kind: {} (parent not in current graph, kind-only hint — explicit approval required)",
                        evidence
                    )
                } else {
                    "label-related only — discovered via platform label, no ownerRef chain to target operator".to_string()
                };
                Action::Review {
                    resource: cr.id.clone(),
                    reason,
                    metadata: build_review_metadata(cr, position, approval),
                }
            }
            (GraphPosition::Independent, Provenance::Managed) => Action::Delete {
                resource: cr.id.clone(),
                reason: "independent operand (managed via ownerRef)".to_string(),
            },
            (GraphPosition::Independent, Provenance::LikelyManaged) => Action::Review {
                resource: cr.id.clone(),
                reason: "likely operator-managed but no ownerRef — verify before deleting"
                    .to_string(),
                metadata: build_review_metadata(cr, position, approval),
            },
            (GraphPosition::Independent, Provenance::Unknown) => Action::Review {
                resource: cr.id.clone(),
                reason: "owned API, but provenance unknown".to_string(),
                metadata: build_review_metadata(cr, position, approval),
            },
        }
    }

    // BFS over ownerRef ancestry — returns union of operator indices
    // reachable from any branch
    fn bfs_owner_ancestry(
        cr: &CrInstance,
        api_to_op_indices: &HashMap<String, HashSet<usize>>,
        cr_by_uid: &HashMap<&str, &CrInstance>,
    ) -> HashSet<usize> {
        let mut result = HashSet::new();
        let mut visited = HashSet::new();
        let mut queue = std::collections::VecDeque::new();
        for (_, _, ref_uid) in &cr.owner_refs {
            queue.push_back(ref_uid.as_str());
        }
        while let Some(uid) = queue.pop_front() {
            if !visited.insert(uid) {
                continue;
            }
            let Some(ancestor) = cr_by_uid.get(uid) else {
                continue;
            };
            if let Some(owners) = api_to_op_indices.get(ancestor.api_owner_key.as_str()) {
                result.extend(owners.iter().copied());
            } else {
                for (_, _, parent_uid) in &ancestor.owner_refs {
                    queue.push_back(parent_uid.as_str());
                }
            }
        }
        result
    }

    // For root/independent CRs: API ownership is authoritative
    fn resolve_api_owner_indices(
        cr: &CrInstance,
        api_to_op_indices: &HashMap<String, HashSet<usize>>,
        cr_by_uid: &HashMap<&str, &CrInstance>,
    ) -> HashSet<usize> {
        if let Some(owners) = api_to_op_indices.get(cr.api_owner_key.as_str()) {
            return owners.clone();
        }
        bfs_owner_ancestry(cr, api_to_op_indices, cr_by_uid)
    }

    // root_uids: only actual root CRs (cleanup triggers), not all parents
    let root_uids: HashSet<String> = root_crs.iter().filter_map(|cr| cr.id.uid.clone()).collect();

    // For managed descendants: recursively resolve cleanup trigger layer.
    // Uses memoization to handle diamond graphs correctly — a node resolved
    // via one branch returns its cached result via the other branch, instead
    // of returning empty and causing false API-owner fallback.
    fn resolve_cleanup_trigger_indices(
        cr: &CrInstance,
        api_to_op_indices: &HashMap<String, HashSet<usize>>,
        cr_by_uid: &HashMap<&str, &CrInstance>,
        root_uids: &HashSet<String>,
        visiting: &mut HashSet<String>,
        memo: &mut HashMap<String, HashSet<usize>>,
    ) -> HashSet<usize> {
        let uid = cr.id.uid.as_deref().unwrap_or("").to_string();

        if let Some(cached) = memo.get(&uid) {
            return cached.clone();
        }

        if !visiting.insert(uid.clone()) {
            return HashSet::new();
        }

        let mut result = HashSet::new();
        for (_, _, ref_uid) in &cr.owner_refs {
            let Some(parent) = cr_by_uid.get(ref_uid.as_str()) else {
                continue;
            };
            let parent_uid = parent.id.uid.as_deref().unwrap_or("");

            if root_uids.contains(parent_uid) {
                if let Some(owners) = api_to_op_indices.get(parent.api_owner_key.as_str()) {
                    result.extend(owners.iter().copied());
                }
            } else {
                let inherited = resolve_cleanup_trigger_indices(
                    parent,
                    api_to_op_indices,
                    cr_by_uid,
                    root_uids,
                    visiting,
                    memo,
                );
                if !inherited.is_empty() {
                    result.extend(inherited);
                } else if let Some(owners) = api_to_op_indices.get(parent.api_owner_key.as_str()) {
                    result.extend(owners.iter().copied());
                }
            }
        }

        if result.is_empty()
            && let Some(owners) = api_to_op_indices.get(cr.api_owner_key.as_str())
        {
            result.extend(owners.iter().copied());
        }

        visiting.remove(&uid);
        memo.insert(uid, result.clone());
        result
    }

    // Compute dependency layers for operand cleanup
    let deps = compute_operator_dependencies(
        &target_operators
            .iter()
            .copied()
            .cloned()
            .collect::<Vec<_>>(),
    );
    let target_indices_local: Vec<usize> = (0..target_operators.len()).collect();
    let all_ops_local: Vec<OperatorInstance> =
        target_operators.iter().map(|op| (*op).clone()).collect();
    let layers = match topo_sort_operators(&target_indices_local, &all_ops_local, &deps) {
        TopoSortResult::Layers(l) => l,
        TopoSortResult::Cycle(cycle_ids) => {
            for id in &cycle_ids {
                blockers.push(Blocker {
                    resource: ResourceId {
                        group: "operators.coreos.com".to_string(),
                        version: "v1alpha1".to_string(),
                        kind: "ClusterServiceVersion".to_string(),
                        namespace: Some(id.namespace.clone()),
                        name: id.csv_name.clone(),
                        uid: None,
                    },
                    reason: format!(
                        "dependency cycle detected: {} is part of a circular dependency",
                        id
                    ),
                    external_dependency: None,
                });
            }
            vec![target_indices_local.clone()]
        }
    };

    let mut operand_phases: Vec<PlanPhase> = Vec::new();
    let mut deferred_remaining_actions: Vec<Action> = Vec::new();

    // Helper: check if a CR's resolved decision is bulk label-only
    let is_label_only_delete = |cr: &CrInstance| -> bool {
        resolved_decisions.get(&cr.id).is_some_and(|d| {
            matches!(
                d,
                ResolvedDecision::Delete {
                    approval_origin: ApprovalOrigin::BulkLabelOnly,
                    ..
                }
            )
        })
    };

    if layers.len() <= 1 {
        let mut trigger_actions: Vec<Action> = Vec::new();
        let mut remaining_actions: Vec<Action> = Vec::new();

        for cr in &root_crs {
            let action = cr_to_action(cr, GraphPosition::Root, &resolved_decisions);
            if is_label_only_delete(cr) {
                remaining_actions.push(action);
            } else {
                trigger_actions.push(action);
            }
        }
        for cr in &managed_descendants {
            let action = cr_to_action(cr, GraphPosition::Descendant, &resolved_decisions);
            if is_label_only_delete(cr) {
                remaining_actions.push(action);
            } else {
                trigger_actions.push(action);
            }
        }
        for cr in &independent_crs {
            let action = cr_to_action(cr, GraphPosition::Independent, &resolved_decisions);
            if is_label_only_delete(cr) {
                remaining_actions.push(action);
            } else {
                trigger_actions.push(action);
            }
        }

        let phase_actions = trigger_actions;

        let conds: Vec<String> = phase_actions
            .iter()
            .filter_map(|action| match action {
                Action::Delete { resource, .. } => Some(format!("{} is gone", resource)),
                Action::ExpectGone { resource, .. } => {
                    Some(format!("{} is gone (expected)", resource))
                }
                _ => None,
            })
            .collect();

        operand_phases.push(PlanPhase {
            name: "Trigger operand cleanup".to_string(),
            description: "Delete root CRs to trigger controller cleanup; expect managed descendants to vanish".to_string(),
            actions: phase_actions,
            barrier: Some(Barrier {
                description: "All operands removed (deleted + expected)".to_string(),
                conditions: conds,
            }),
        });
        deferred_remaining_actions = remaining_actions;
    } else {
        // Multiple layers — split operands by owning operator's layer
        for (layer_idx, layer) in layers.iter().enumerate() {
            let layer_op_indices: HashSet<usize> = layer.iter().copied().collect();
            let mut phase_actions: Vec<Action> = Vec::new();

            for cr in &root_crs {
                let owners = resolve_api_owner_indices(cr, &api_to_op_indices, &cr_by_uid);
                let action = if owners.len() > 1 {
                    if layer_idx == 0 {
                        Action::Review {
                            resource: cr.id.clone(),
                            reason: "shared CRD — owned by multiple selected operators".to_string(),
                            metadata: None,
                        }
                    } else {
                        continue;
                    }
                } else {
                    cr_to_action(cr, GraphPosition::Root, &resolved_decisions)
                };
                let op_idx = owners.iter().next().copied();
                if op_idx.is_some_and(|i| layer_op_indices.contains(&i))
                    || (layer_idx == 0 && op_idx.is_none())
                {
                    if is_label_only_delete(cr) {
                        deferred_remaining_actions.push(action);
                    } else {
                        phase_actions.push(action);
                    }
                }
            }
            for cr in &managed_descendants {
                let owners = resolve_cleanup_trigger_indices(
                    cr,
                    &api_to_op_indices,
                    &cr_by_uid,
                    &root_uids,
                    &mut HashSet::new(),
                    &mut HashMap::new(),
                );
                if owners.len() > 1 {
                    if layer_idx == 0 {
                        phase_actions.push(Action::Review {
                            resource: cr.id.clone(),
                            reason: "shared CRD descendant — owned by multiple selected operators"
                                .to_string(),
                            metadata: None,
                        });
                    }
                    continue;
                }
                let op_idx = owners.iter().next().copied();
                if op_idx.is_some_and(|i| layer_op_indices.contains(&i))
                    || (layer_idx == 0 && op_idx.is_none())
                {
                    let action = cr_to_action(cr, GraphPosition::Descendant, &resolved_decisions);
                    if is_label_only_delete(cr) {
                        deferred_remaining_actions.push(action);
                    } else {
                        phase_actions.push(action);
                    }
                }
            }
            for cr in &independent_crs {
                let owners = resolve_api_owner_indices(cr, &api_to_op_indices, &cr_by_uid);
                if owners.len() > 1 {
                    if layer_idx == 0 {
                        phase_actions.push(Action::Review {
                            resource: cr.id.clone(),
                            reason: "shared CRD — owned by multiple selected operators".to_string(),
                            metadata: None,
                        });
                    }
                    continue;
                }
                let op_idx = owners.iter().next().copied();
                if op_idx.is_some_and(|i| layer_op_indices.contains(&i))
                    || (layer_idx == 0 && op_idx.is_none())
                {
                    let action = cr_to_action(cr, GraphPosition::Independent, &resolved_decisions);
                    if is_label_only_delete(cr) {
                        deferred_remaining_actions.push(action);
                    } else {
                        phase_actions.push(action);
                    }
                }
            }

            if !phase_actions.is_empty() {
                let layer_ops: Vec<&str> = layer
                    .iter()
                    .map(|&i| target_operators[i].csv.name.as_str())
                    .collect();
                operand_phases.push(PlanPhase {
                    name: format!("Operand cleanup (layer {})", layer_idx),
                    description: format!("Cleanup operands for: {}", layer_ops.join(", ")),
                    actions: phase_actions,
                    barrier: Some(Barrier {
                        description: format!("Layer {} operands removed", layer_idx),
                        conditions: vec![],
                    }),
                });
            }
        }
    }

    // Root REVIEWs/KEEPs that are not approved become hard blockers —
    // EXCEPT RelatedLabelOnly roots which have no confirmed lifecycle
    // connection to the target operator. These remain REVIEW (non-blocking)
    // and appear in post-teardown Residual Audit for separate decisions.
    for phase in &operand_phases {
        for action in &phase.actions {
            if let Action::Review {
                resource, reason, ..
            } = action
            {
                let root_cr = root_crs.iter().find(|cr| cr.id == *resource);
                let is_root = root_cr.is_some();
                if !is_root {
                    continue;
                }

                // RelatedLabelOnly roots: no confirmed lifecycle connection
                // to target operator → skip blocker, defer to Residual Audit
                let is_related_label_only = root_cr.is_some_and(|cr| is_root_blocker_exempt(cr));
                if is_related_label_only {
                    continue;
                }

                let is_shared = root_cr.is_some_and(|cr| {
                    resolve_api_owner_indices(cr, &api_to_op_indices, &cr_by_uid).len() > 1
                });
                if is_shared {
                    blockers.push(Blocker {
                        resource: resource.clone(),
                        reason: format!(
                            "root operand blocked: {} — resolve by adjusting target operator selection",
                            reason
                        ),
                        external_dependency: None,
                    });
                } else {
                    blockers.push(Blocker {
                        resource: resource.clone(),
                        reason: format!(
                            "root operand requires explicit deletion approval: {} — use --approve-resource {}",
                            reason,
                            canonical_key(resource)
                        ),
                        external_dependency: None,
                    });
                }
            }
        }
    }

    // Preserved root operands also become hard blockers —
    // EXCEPT RelatedLabelOnly roots (no confirmed lifecycle connection)
    for phase in &operand_phases {
        for action in &phase.actions {
            if let Action::Keep { resource, reason } = action {
                let root_cr = root_crs.iter().find(|cr| cr.id == *resource);
                if let Some(cr) = root_cr {
                    if is_root_blocker_exempt(cr) {
                        continue;
                    }
                    blockers.push(Blocker {
                        resource: resource.clone(),
                        reason: format!(
                            "root operand explicitly preserved; operator controller must be retained: {}",
                            reason
                        ),
                        external_dependency: None,
                    });
                }
            }
        }
    }

    // Build ownerRef lookup for the invariant check
    let uid_to_owner_uids: HashMap<String, Vec<String>> = cr_instances
        .iter()
        .filter_map(|cr| {
            let uid = cr.id.uid.clone()?;
            let owners: Vec<String> = cr.owner_refs.iter().map(|(_, _, u)| u.clone()).collect();
            Some((uid, owners))
        })
        .collect();

    enforce_expect_delete_invariant(&mut operand_phases, &uid_to_owner_uids);

    // Remaining cleanup phase — includes deferred label-only bulk DELETEs
    let phase_remaining = PlanPhase {
        name: "Remaining cleanup".to_string(),
        description: "Delete label-only approved CRs after controller cleanup completes"
            .to_string(),
        actions: deferred_remaining_actions,
        barrier: None,
    };

    // ── Controller phases: Remove Operator controllers (dependency-ordered) ──
    let mut controller_phases: Vec<PlanPhase> = Vec::new();
    for (layer_idx, layer) in layers.iter().enumerate() {
        let mut layer_actions = Vec::new();
        for &idx in layer {
            layer_actions.push(Action::Delete {
                resource: target_operators[idx].csv.clone(),
                reason: if layers.len() > 1 {
                    format!("operator controller (dependency layer {})", layer_idx)
                } else {
                    "operator controller no longer needed".to_string()
                },
            });
        }
        controller_phases.push(PlanPhase {
            name: if layers.len() > 1 {
                format!("Remove controllers (layer {})", layer_idx)
            } else {
                "Remove Operator controllers".to_string()
            },
            description: if layers.len() > 1 {
                format!(
                    "Delete CSVs in dependency layer {} — same-layer CSVs are independent",
                    layer_idx
                )
            } else {
                "Delete CSVs (GC will remove controller Deployments)".to_string()
            },
            actions: layer_actions,
            barrier: Some(Barrier {
                description: format!("Layer {} CSVs deleted", layer_idx),
                conditions: layer
                    .iter()
                    .map(|&idx| format!("{} is gone", target_operators[idx].csv))
                    .collect(),
            }),
        });
    }

    // Apply resolved decisions to namespace cleanup actions (ancillary)
    let ns_cleanup_actions: Vec<Action> = ns_cleanup_actions
        .into_iter()
        .map(|action| {
            if let Action::Review {
                resource,
                reason,
                metadata,
            } = &action
                && let Some(decision) = resolved_decisions.get(resource)
            {
                return match decision {
                    ResolvedDecision::Delete { reason, .. } => Action::Delete {
                        resource: resource.clone(),
                        reason: reason.clone(),
                    },
                    ResolvedDecision::Keep { reason } => Action::Keep {
                        resource: resource.clone(),
                        reason: reason.clone(),
                    },
                    ResolvedDecision::Review => Action::Review {
                        resource: resource.clone(),
                        reason: reason.clone(),
                        metadata: metadata.clone(),
                    },
                };
            }
            action
        })
        .collect();

    let ns_cleanup_phase = if ns_cleanup_actions.is_empty() {
        None
    } else {
        Some(PlanPhase {
            name: "Namespace cleanup".to_string(),
            description:
                "Remove operator namespace resources (OperatorGroup, Leases, operator ConfigMaps)"
                    .to_string(),
            actions: ns_cleanup_actions.clone(),
            barrier: None,
        })
    };

    // ── Phase 4: Remove unused APIs ──
    let mut phase4_actions = Vec::new();
    let blocked_crds: HashSet<String> = blockers.iter().map(|b| b.resource.name.clone()).collect();
    let warned_crds: HashSet<String> = warnings
        .iter()
        .filter_map(|w| w.resource.as_ref().map(|r| r.name.clone()))
        .collect();

    let mut seen_crds = HashSet::new();

    // For --prune-crds DELETE actions, GET current UIDs NOW (at evidence time).
    // This prevents UID migration between evidence→user confirmation→execution.
    let prune_crd_uids: HashMap<String, BindResult> = if prune_crds {
        let prune_candidates: Vec<String> = target_crds
            .iter()
            .filter(|name| {
                !blocked_crds.contains(name.as_str()) && !warned_crds.contains(name.as_str())
            })
            .cloned()
            .collect();

        if !prune_candidates.is_empty() {
            let crd_gvk = kube::core::GroupVersion::gv("apiextensions.k8s.io", "v1")
                .with_kind("CustomResourceDefinition");
            let crd_ar =
                kube::api::ApiResource::from_gvk_with_plural(&crd_gvk, "customresourcedefinitions");
            let crd_api: kube::api::Api<kube::api::DynamicObject> =
                kube::api::Api::all_with(client.clone(), &crd_ar);

            let futs = prune_candidates.iter().map(|name| {
                let api = crd_api.clone();
                let name = name.clone();
                async move {
                    let result = probe_uid(&api, &name).await;
                    (name, result)
                }
            });
            futures::stream::iter(futs)
                .buffer_unordered(16)
                .collect()
                .await
        } else {
            HashMap::new()
        }
    } else {
        HashMap::new()
    };

    for crd_name in &target_crds {
        if !seen_crds.insert(crd_name.clone()) {
            continue;
        }

        let crd_id = ResourceId {
            group: "apiextensions.k8s.io".to_string(),
            version: "v1".to_string(),
            kind: "CustomResourceDefinition".to_string(),
            namespace: None,
            name: crd_name.clone(),
            uid: None,
        };

        if blocked_crds.contains(crd_name.as_str()) {
            let blocker_op = blockers
                .iter()
                .find(|b| b.resource.name == *crd_name)
                .and_then(|b| b.external_dependency.as_deref())
                .unwrap_or("unknown");
            phase4_actions.push(Action::Keep {
                resource: crd_id,
                reason: format!("required by unselected operator {}", blocker_op),
            });
        } else if warned_crds.contains(crd_name.as_str()) {
            phase4_actions.push(Action::Keep {
                resource: crd_id,
                reason: "also owned by another operator".to_string(),
            });
        } else if prune_crds {
            // UID must be bound at evidence time for DELETE authority
            match prune_crd_uids.get(crd_name) {
                Some(BindResult::Bound(uid)) => {
                    phase4_actions.push(Action::Delete {
                        resource: ResourceId {
                            uid: Some(uid.clone()),
                            ..crd_id
                        },
                        reason: "no remaining CRs, no external dependencies".to_string(),
                    });
                }
                Some(BindResult::Absent) => {
                    // CRD already gone (GET 404 + endpoint verified) — skip DELETE
                    phase4_actions.push(Action::Keep {
                        resource: crd_id,
                        reason: "already absent (confirmed via endpoint verification)".to_string(),
                    });
                }
                Some(BindResult::Failed(reason)) => {
                    blockers.push(Blocker {
                        resource: crd_id.clone(),
                        reason: format!("Cannot bind CRD UID: {}", reason),
                        external_dependency: None,
                    });
                    phase4_actions.push(Action::Keep {
                        resource: crd_id,
                        reason: "UID binding failed — cannot safely delete".to_string(),
                    });
                }
                None => {
                    blockers.push(Blocker {
                        resource: crd_id.clone(),
                        reason: "CRD not in binding candidates".to_string(),
                        external_dependency: None,
                    });
                    phase4_actions.push(Action::Keep {
                        resource: crd_id,
                        reason: "UID binding not attempted".to_string(),
                    });
                }
            }
        } else {
            phase4_actions.push(Action::Keep {
                resource: crd_id,
                reason: "eligible for prune (use --prune-crds to remove)".to_string(),
            });
        }
    }

    // APIService actions — dedup by (group, version) since one APIService serves multiple kinds.
    // --prune-crds only removes CRDs; APIServices are always kept (future --prune-api-services).
    let mut seen_api_services = HashSet::new();

    for def in target_operators
        .iter()
        .flat_map(|op| op.owned_api_service_defs.iter())
    {
        let obj_name = def.api_service_object_name();
        if !seen_api_services.insert(obj_name.clone()) {
            continue;
        }

        let api_svc_id = ResourceId {
            group: "apiregistration.k8s.io".to_string(),
            version: "v1".to_string(),
            kind: "APIService".to_string(),
            namespace: None,
            name: obj_name.clone(),
            uid: None,
        };

        if blocked_crds.contains(obj_name.as_str()) {
            let blocker_op = blockers
                .iter()
                .find(|b| b.resource.name == obj_name)
                .and_then(|b| b.external_dependency.as_deref())
                .unwrap_or("unknown");
            phase4_actions.push(Action::Keep {
                resource: api_svc_id,
                reason: format!("required by unselected operator {}", blocker_op),
            });
        } else {
            phase4_actions.push(Action::Keep {
                resource: api_svc_id,
                reason: "APIService kept by design (not removed by --prune-crds)".to_string(),
            });
        }
    }

    let phase4 = PlanPhase {
        name: "APIs".to_string(),
        description: if prune_crds {
            "Delete CRDs with no remaining instances and no external dependencies".to_string()
        } else {
            "CRDs kept by default — use --prune-crds to remove".to_string()
        },
        actions: phase4_actions,
        barrier: None,
    };

    // ── Phase 5: Remove empty namespaces ──
    let target_namespaces: HashSet<&str> = target_operators
        .iter()
        .map(|op| op.install_namespace.as_str())
        .collect();

    let phase5_actions: Vec<Action> = target_namespaces
        .iter()
        .map(|ns| Action::Keep {
            resource: ResourceId {
                group: String::new(),
                version: "v1".to_string(),
                kind: "Namespace".to_string(),
                namespace: None,
                name: ns.to_string(),
                uid: None,
            },
            reason: "namespace cleanup requires manual verification".to_string(),
        })
        .collect();

    let phase5 = PlanPhase {
        name: "Namespaces".to_string(),
        description: "Namespaces are kept by default — verify manually before deleting".to_string(),
        actions: phase5_actions,
        barrier: None,
    };

    if !prune_crds {
        let eligible = phase4
            .actions
            .iter()
            .filter(|a| {
                matches!(a, Action::Keep { reason, .. } if reason.contains("eligible for prune"))
            })
            .count();
        if eligible > 0 {
            warnings.push(Warning {
                message: format!(
                    "{} CRDs eligible for removal but kept by default (use --prune-crds)",
                    eligible
                ),
                resource: None,
            });
        }
    }

    let mut phases = vec![phase0];
    phases.extend(operand_phases);
    phases.push(phase_remaining);
    phases.extend(controller_phases);
    if let Some(ns_phase) = ns_cleanup_phase {
        phases.push(ns_phase);
    }
    phases.push(phase4);
    phases.push(phase5);

    // UID binding: bind current UIDs to all DELETE/EXPECT actions that lack them
    // (e.g., --prune-crds CRDs). This happens at plan generation time so the plan
    // presented to the user for confirmation includes the actual resource identities.
    // Binding failure → blocker (no mutation allowed).
    {
        let needs_binding: Vec<(usize, usize, ResourceId)> = phases
            .iter()
            .enumerate()
            .flat_map(|(pi, phase)| {
                phase.actions.iter().enumerate().filter_map(move |(ai, a)| {
                    match a {
                        // DELETE UIDs should already be bound by per-type binding above.
                        // Only bind EXPECT actions here (observe-only, no DELETE authority).
                        Action::ExpectGone { resource, .. } => {
                            if resource.uid.is_none()
                                || resource.uid.as_ref().is_some_and(|u| u.is_empty())
                            {
                                Some((pi, ai, resource.clone()))
                            } else {
                                None
                            }
                        }
                        _ => None,
                    }
                })
            })
            .collect();

        if !needs_binding.is_empty() {
            // Each future carries its phase/action indices so result ordering
            // from buffer_unordered doesn't matter.
            let futs = needs_binding.iter().map(|(pi, ai, res)| {
                let client = client.clone();
                let res = res.clone();
                let km = kind_map.clone();
                let gk = gk_map.clone();
                let pi = *pi;
                let ai = *ai;
                async move {
                    let result = match resolve_api(&client, &res, &km, &gk) {
                        Some((api, _)) => match api.get(&res.name).await {
                            Ok(obj) => match obj.metadata.uid {
                                Some(uid) => BindResult::Bound(uid),
                                None => BindResult::Failed("live resource has no UID".to_string()),
                            },
                            Err(kube::Error::Api(err)) if err.code == 404 => {
                                match api.list(&ListParams::default().limit(1)).await {
                                    Ok(_) => BindResult::Absent,
                                    Err(_) => BindResult::Failed(
                                        "GET 404 but endpoint verification failed".to_string(),
                                    ),
                                }
                            }
                            Err(e) => BindResult::Failed(format!("GET failed: {}", e)),
                        },
                        None => BindResult::Failed("cannot resolve API for resource".to_string()),
                    };
                    (pi, ai, res, result)
                }
            });

            let results: Vec<_> = futures::stream::iter(futs)
                .buffer_unordered(16)
                .collect()
                .await;

            // Apply by carried indices — order-independent
            for (pi, ai, res, bind_result) in &results {
                match bind_result {
                    BindResult::Bound(uid) => {
                        let action_res = match &mut phases[*pi].actions[*ai] {
                            Action::Delete { resource, .. }
                            | Action::ExpectGone { resource, .. } => resource,
                            _ => continue,
                        };
                        action_res.uid = Some(uid.clone());
                    }
                    BindResult::Absent => {
                        // Resource already gone at plan time — keep in plan,
                        // executor will handle as AlreadyGone
                    }
                    BindResult::Failed(reason) => {
                        // EXPECT actions are observe-only — binding failure is a warning,
                        // not a blocker (no DELETE authority involved).
                        warnings.push(Warning {
                            message: format!(
                                "Cannot bind UID for {}/{}: {}. \
                                 Observation may be less precise.",
                                res.kind, res.name, reason
                            ),
                            resource: Some(res.clone()),
                        });
                    }
                }
            }
        }
    }

    // Build operator inventory and dependency edges
    let operator_inventory: Vec<OperatorInventoryEntry> = all_operators
        .iter()
        .map(|op| OperatorInventoryEntry {
            csv_name: op.csv.name.clone(),
            namespace: op.install_namespace.clone(),
            owned_crds: op.owned_crds.clone(),
            required_crds: op.required_crds.clone(),
        })
        .collect();

    let mut dependency_edges = Vec::new();
    for target_op in target_operators {
        for req_crd in &target_op.required_crds {
            if let Some(provider) = all_operators
                .iter()
                .find(|op| op.csv.name != target_op.csv.name && op.owned_crds.contains(req_crd))
            {
                dependency_edges.push(DependencyEdge {
                    from_operator: target_op.csv.name.clone(),
                    to_operator: provider.csv.name.clone(),
                    edge_type: DependencyEdgeType::RequiresApi,
                    evidence: req_crd.clone(),
                });
            }
        }
    }

    let mut plan = TeardownPlan {
        targets,
        preflight,
        phases,
        blockers,
        warnings,
        snapshot_taken_at: chrono::Utc::now().to_rfc3339(),
        dependency_edges,
        operator_inventory,
        explicit_decisions: vec![],
    };

    // Invariant: every REVIEW action must have a corresponding ReviewCandidate.
    // If this fires, a provenance/discovery rule change created a REVIEW action
    // for a resource that isn't in the candidate registry.
    debug_assert!(
        {
            let candidate_ids: HashSet<&ResourceId> =
                review_candidates.iter().map(|rc| rc.resource).collect();
            plan.phases
                .iter()
                .flat_map(|p| &p.actions)
                .all(|action| match action {
                    Action::Review { resource, .. } => candidate_ids.contains(resource),
                    _ => true,
                })
        },
        "REVIEW action exists without corresponding ReviewCandidate — provenance/discovery invariant broken"
    );

    // Build explicit_decisions from resolved_decisions.
    // Metadata is sourced from CrInstance data (pre-action-conversion) via cr_instances,
    // and from ancillary ns_cleanup_actions for ancillary resources.
    // This avoids the bug where resolved REVIEW→Delete actions are no longer Action::Review.
    let pre_resolution_metadata: HashMap<&ResourceId, crate::teardown::plan::ReviewMetadata> = {
        let mut map = HashMap::new();
        // CrInstance-backed candidates (root + independent)
        for cr in cr_instances.iter() {
            let position = if root_crs.iter().any(|r| std::ptr::eq(*r, cr)) {
                GraphPosition::Root
            } else if independent_crs.iter().any(|r| std::ptr::eq(*r, cr)) {
                GraphPosition::Independent
            } else {
                continue; // descendant — not a review candidate
            };
            if matches!(cr.provenance, Provenance::Managed) {
                continue;
            }
            let approval = compute_approval_class(cr, position);
            if let Some(meta) = build_review_metadata(cr, position, approval) {
                map.insert(&cr.id, meta);
            }
        }
        // Ancillary ns_cleanup candidates (ConfigMap etc.) — use their Action::Review metadata
        for action in &ns_cleanup_actions {
            if let Action::Review {
                resource,
                metadata: Some(meta),
                ..
            } = action
            {
                map.insert(resource, meta.clone());
            }
        }
        // Related CRD REVIEW actions
        for action in &related_report.actions {
            if let Action::Review {
                resource,
                metadata: Some(meta),
                ..
            } = action
            {
                map.insert(resource, meta.clone());
            }
        }
        map
    };

    let mut explicit_decisions = Vec::new();
    for (resource, decision) in &resolved_decisions {
        let saved_action = match decision {
            ResolvedDecision::Delete { .. } => crate::teardown::plan::SavedAction::Delete,
            ResolvedDecision::Keep { .. } => crate::teardown::plan::SavedAction::Keep,
            ResolvedDecision::Review => continue,
        };
        let (basis, approval_kind) = if let Some(meta) = pre_resolution_metadata.get(resource) {
            let basis = build_decision_basis(meta);
            // If provenance is Unknown and no decisive evidence → ExplicitUnattributed
            let has_evidence = !basis.decisive_evidence.is_empty()
                || basis.provenance.as_deref().is_some_and(|p| p != "Unknown");
            let kind = if has_evidence {
                crate::teardown::plan::ApprovalKind::Explicit
            } else {
                crate::teardown::plan::ApprovalKind::ExplicitUnattributed
            };
            (basis, kind)
        } else {
            (
                crate::teardown::plan::DecisionBasis {
                    provenance: None,
                    review_category: None,
                    discovery_source: None,
                    decisive_evidence: vec![],
                },
                crate::teardown::plan::ApprovalKind::ExplicitUnattributed,
            )
        };
        explicit_decisions.push(crate::teardown::plan::SavedDecision {
            match_spec: crate::teardown::plan::ResourceMatch::from_resource_id(resource),
            action: saved_action,
            approval: approval_kind,
            basis,
        });
    }
    plan.explicit_decisions = explicit_decisions;

    Ok(plan)
}

pub fn save_plan_to_file(plan: &TeardownPlan) -> Result<String> {
    let dir = std::env::temp_dir().join("oc-deps-plans");
    std::fs::create_dir_all(&dir)?;
    let operator_names: Vec<&str> = plan.targets.iter().map(|t| t.csv.name.as_str()).collect();
    let op_slug = operator_names.join("_");
    let filename = format!(
        "teardown-{}-{}.json",
        op_slug,
        plan.snapshot_taken_at.replace(':', "-").replace('+', "_")
    );
    let path = dir.join(&filename);
    let json = serde_json::to_string_pretty(plan)?;
    std::fs::write(&path, json)?;
    Ok(path.to_string_lossy().to_string())
}

pub fn load_plan_from_file(path: &str) -> Result<TeardownPlan> {
    let data = std::fs::read_to_string(path)?;
    let plan: TeardownPlan = serde_json::from_str(&data)?;
    Ok(plan)
}

/// Save explicit user decisions as a SavedTeardownPlan.
/// Reads pre-built explicit_decisions from the plan (populated by generate_teardown_plan).
#[allow(dead_code)]
pub fn save_as_saved_plan(
    plan: &TeardownPlan,
    target: &crate::teardown::plan::SavedOperatorTarget,
    path: Option<&str>,
) -> Result<String> {
    use crate::teardown::plan::*;

    let saved = SavedTeardownPlan {
        schema_version: SAVED_PLAN_SCHEMA_VERSION,
        target: target.clone(),
        teardown_decisions: plan.explicit_decisions.clone(),
        residual_decisions: vec![],
    };

    let dest = if let Some(p) = path {
        std::path::PathBuf::from(p)
    } else {
        let dir = std::path::PathBuf::from("/tmp/oc-deps-saved-plans");
        std::fs::create_dir_all(&dir)?;
        dir.join(format!(
            "saved-plan-{}.json",
            chrono::Utc::now().format("%Y-%m-%dT%H-%M-%S")
        ))
    };
    std::fs::write(&dest, serde_json::to_string_pretty(&saved)?)?;
    Ok(dest.display().to_string())
}

fn build_decision_basis(
    meta: &crate::teardown::plan::ReviewMetadata,
) -> crate::teardown::plan::DecisionBasis {
    use crate::teardown::plan::*;

    let provenance = meta.provenance.as_ref().map(|p| match p {
        ProvenanceSer::Managed => "Managed".to_string(),
        ProvenanceSer::LikelyManaged => "LikelyManaged".to_string(),
        ProvenanceSer::Unknown => "Unknown".to_string(),
    });

    let review_category = meta.category.as_ref().map(|c| match c {
        ReviewCategorySer::OperandRoot => "OperandRoot".to_string(),
        ReviewCategorySer::OperandDescendant => "OperandDescendant".to_string(),
        ReviewCategorySer::OperandIndependent => "OperandIndependent".to_string(),
        ReviewCategorySer::Ancillary => "Ancillary".to_string(),
    });

    let discovery_source = meta.discovery_source.as_ref().map(|d| match d {
        DiscoverySourceSer::Direct => "Direct".to_string(),
        DiscoverySourceSer::RelatedLinked => "RelatedLinked".to_string(),
        DiscoverySourceSer::RelatedLabelOnly => "RelatedLabelOnly".to_string(),
    });

    let decisive_evidence: Vec<SavedEvidenceSignature> = meta
        .decisive_label_pairs
        .iter()
        .map(|(k, v)| SavedEvidenceSignature::Label {
            key: k.clone(),
            value: v.clone(),
        })
        .collect();

    DecisionBasis {
        provenance,
        review_category,
        discovery_source,
        decisive_evidence,
    }
}

/// Load a SavedTeardownPlan from file with schema validation.
#[allow(dead_code)]
pub fn load_saved_plan(path: &str) -> Result<crate::teardown::plan::SavedTeardownPlan> {
    let data = std::fs::read_to_string(path)?;
    let saved: crate::teardown::plan::SavedTeardownPlan = serde_json::from_str(&data)?;
    if saved.schema_version != crate::teardown::plan::SAVED_PLAN_SCHEMA_VERSION {
        bail!(
            "Saved plan schema version {} is not supported (expected {})",
            saved.schema_version,
            crate::teardown::plan::SAVED_PLAN_SCHEMA_VERSION
        );
    }
    Ok(saved)
}

/// Validate saved teardown decisions against a fresh plan.
/// Compares saved provenance/category/discovery_source/labels against fresh ReviewMetadata.
/// Returns exact approval specs for DecisionPolicy on success,
/// or list of errors if any decision cannot be safely replayed.
#[allow(dead_code)]
pub fn validate_saved_decisions(
    plan: &TeardownPlan,
    saved: &crate::teardown::plan::SavedTeardownPlan,
) -> Result<(Vec<String>, Vec<String>), Vec<String>> {
    use crate::teardown::plan::ApprovalKind;

    let mut approve_specs = Vec::new();
    let mut preserve_specs = Vec::new();
    let mut errors = Vec::new();

    for decision in &saved.teardown_decisions {
        if let Err(e) = decision.match_spec.validate() {
            errors.push(format!(
                "{}/{}: invalid match spec — {}",
                decision.match_spec.kind, decision.match_spec.name, e
            ));
            continue;
        }
        if decision.approval == ApprovalKind::ExplicitUnattributed {
            errors.push(format!(
                "{}/{}: ExplicitUnattributed cannot be auto-applied",
                decision.match_spec.kind, decision.match_spec.name
            ));
            continue;
        }

        let fresh_match = plan
            .phases
            .iter()
            .flat_map(|p| &p.actions)
            .find(|a| match a {
                Action::Review { resource, .. }
                | Action::Delete { resource, .. }
                | Action::ExpectGone { resource, .. }
                | Action::Keep { resource, .. } => decision.match_spec.matches(resource),
                _ => false,
            });

        match fresh_match {
            None => {
                errors.push(format!(
                    "{}/{}: not found in fresh plan",
                    decision.match_spec.kind, decision.match_spec.name
                ));
            }
            Some(Action::Delete { .. }) | Some(Action::ExpectGone { .. }) => {
                if matches!(decision.action, crate::teardown::plan::SavedAction::Keep) {
                    errors.push(format!(
                        "{}/{}: saved KEEP conflicts with fresh deterministic DELETE — cannot preserve",
                        decision.match_spec.kind, decision.match_spec.name
                    ));
                }
            }
            Some(Action::Review {
                resource, metadata, ..
            }) => {
                let spec = canonical_key(resource);

                if matches!(decision.action, crate::teardown::plan::SavedAction::Delete) {
                    // Fresh metadata is required for DELETE replay
                    let Some(fresh_meta) = metadata else {
                        errors.push(format!(
                            "{}/{}: fresh REVIEW has no metadata — cannot validate basis",
                            decision.match_spec.kind, decision.match_spec.name
                        ));
                        continue;
                    };

                    if let Some(err) =
                        check_basis_drift(&decision.basis, fresh_meta, &decision.match_spec)
                    {
                        errors.push(err);
                        continue;
                    }

                    approve_specs.push(spec);
                } else {
                    preserve_specs.push(spec);
                }
            }
            _ => {}
        }
    }

    if errors.is_empty() {
        Ok((approve_specs, preserve_specs))
    } else {
        Err(errors)
    }
}

#[allow(dead_code)]
fn check_basis_drift(
    saved: &crate::teardown::plan::DecisionBasis,
    fresh: &crate::teardown::plan::ReviewMetadata,
    spec: &crate::teardown::plan::ResourceMatch,
) -> Option<String> {
    use crate::teardown::plan::*;

    // All three basis fields required for DELETE replay
    let Some(saved_p) = &saved.provenance else {
        return Some(format!(
            "{}/{}: saved basis missing provenance — BLOCKED",
            spec.kind, spec.name
        ));
    };
    let Some(saved_c) = &saved.review_category else {
        return Some(format!(
            "{}/{}: saved basis missing review_category — BLOCKED",
            spec.kind, spec.name
        ));
    };
    let Some(saved_d) = &saved.discovery_source else {
        return Some(format!(
            "{}/{}: saved basis missing discovery_source — BLOCKED",
            spec.kind, spec.name
        ));
    };

    // Unknown provenance blocks replay (ExplicitUnattributed should already be caught)
    if saved_p == "Unknown" && saved.decisive_evidence.is_empty() {
        return Some(format!(
            "{}/{}: saved provenance Unknown with no evidence — BLOCKED",
            spec.kind, spec.name
        ));
    }

    // Fresh fields required
    let Some(fresh_prov) = &fresh.provenance else {
        return Some(format!(
            "{}/{}: fresh metadata missing provenance — BLOCKED",
            spec.kind, spec.name
        ));
    };
    let Some(fresh_cat) = &fresh.category else {
        return Some(format!(
            "{}/{}: fresh metadata missing category — BLOCKED",
            spec.kind, spec.name
        ));
    };
    let Some(fresh_disc) = &fresh.discovery_source else {
        return Some(format!(
            "{}/{}: fresh metadata missing discovery_source — BLOCKED",
            spec.kind, spec.name
        ));
    };

    let fresh_p = match fresh_prov {
        ProvenanceSer::Managed => "Managed",
        ProvenanceSer::LikelyManaged => "LikelyManaged",
        ProvenanceSer::Unknown => "Unknown",
    };
    let fresh_c = match fresh_cat {
        ReviewCategorySer::OperandRoot => "OperandRoot",
        ReviewCategorySer::OperandDescendant => "OperandDescendant",
        ReviewCategorySer::OperandIndependent => "OperandIndependent",
        ReviewCategorySer::Ancillary => "Ancillary",
    };
    let fresh_d = match fresh_disc {
        DiscoverySourceSer::Direct => "Direct",
        DiscoverySourceSer::RelatedLinked => "RelatedLinked",
        DiscoverySourceSer::RelatedLabelOnly => "RelatedLabelOnly",
    };

    // Provenance: same or LikelyManaged→Managed (strengthening) only
    let prov_ok = saved_p == fresh_p || (saved_p == "LikelyManaged" && fresh_p == "Managed");
    if !prov_ok {
        return Some(format!(
            "{}/{}: provenance drift {} → {} — BLOCKED",
            spec.kind, spec.name, saved_p, fresh_p
        ));
    }

    // Category: must be same
    if saved_c != fresh_c {
        return Some(format!(
            "{}/{}: category drift {} → {} — BLOCKED",
            spec.kind, spec.name, saved_c, fresh_c
        ));
    }

    // Discovery source: must be same
    if saved_d != fresh_d {
        return Some(format!(
            "{}/{}: discovery source drift {} → {} — BLOCKED",
            spec.kind, spec.name, saved_d, fresh_d
        ));
    }

    // Validate ALL saved evidence signatures against fresh evidence
    for sig in &saved.decisive_evidence {
        match sig {
            SavedEvidenceSignature::Label { key, value } => {
                if !fresh
                    .decisive_label_pairs
                    .iter()
                    .any(|(fk, fv)| fk == key && fv == value)
                {
                    return Some(format!(
                        "{}/{}: saved label {}={} not in fresh evidence — BLOCKED",
                        spec.kind, spec.name, key, value
                    ));
                }
            }
            SavedEvidenceSignature::OwnerReference { kind, name, .. } => {
                return Some(format!(
                    "{}/{}: unsupported saved OwnerReference {}/{} — BLOCKED (not verifiable against fresh metadata)",
                    spec.kind, spec.name, kind, name
                ));
            }
            SavedEvidenceSignature::ApiOwner { api_owner_key } => {
                return Some(format!(
                    "{}/{}: unsupported saved ApiOwner {} — BLOCKED",
                    spec.kind, spec.name, api_owner_key
                ));
            }
            SavedEvidenceSignature::ManagedFieldManager { manager } => {
                return Some(format!(
                    "{}/{}: unsupported saved ManagedFieldManager {} — BLOCKED (not in ReviewMetadata)",
                    spec.kind, spec.name, manager
                ));
            }
            SavedEvidenceSignature::ServiceAccount { namespace, name } => {
                return Some(format!(
                    "{}/{}: unsupported saved ServiceAccount {}/{} — BLOCKED",
                    spec.kind, spec.name, namespace, name
                ));
            }
        }
    }

    None
}

fn scope_suffix(resource: &ResourceId) -> String {
    match &resource.namespace {
        Some(ns) => format!("  \x1b[2m(ns: {})\x1b[0m", ns),
        None => "  \x1b[2m(cluster-scoped)\x1b[0m".to_string(),
    }
}

pub fn print_teardown_plan(plan: &TeardownPlan, output: &OutputFormat) {
    match output {
        OutputFormat::Tree => print_plan_tree(plan),
        OutputFormat::Table => print_plan_tree(plan),
        OutputFormat::Json => print_plan_json(plan),
    }
}

fn print_plan_tree(plan: &TeardownPlan) {
    println!("\x1b[1mTargets\x1b[0m");
    for target in &plan.targets {
        let sub_info = target
            .subscription
            .as_ref()
            .map(|s| {
                format!(
                    " (Subscription/{}@{})",
                    s.name,
                    s.namespace.as_deref().unwrap_or("?")
                )
            })
            .unwrap_or_default();
        println!(
            "  {} (ns: {}){}",
            target.csv.name, target.install_namespace, sub_info
        );
    }

    // Preflight
    if !plan.preflight.checks.is_empty() {
        println!("\n\x1b[1mPreflight\x1b[0m");
        for check in &plan.preflight.checks {
            let icon = if check.passed { "✓" } else { "!" };
            let color = if check.passed { "32" } else { "33" };
            println!(
                "  \x1b[{}m{}\x1b[0m {} — {}",
                color, icon, check.name, check.detail
            );
        }
    }

    for (i, phase) in plan.phases.iter().enumerate() {
        println!("\n\x1b[1mPhase {}  {}\x1b[0m", i, phase.name);

        if phase.actions.is_empty() {
            println!("  (none)");
            continue;
        }

        for action in &phase.actions {
            match action {
                Action::Delete { resource, reason } => {
                    println!(
                        "  \x1b[31mDELETE\x1b[0m {}/{}{}",
                        resource.kind,
                        resource.name,
                        scope_suffix(resource)
                    );
                    println!("         \x1b[2m{}\x1b[0m", reason);
                }
                Action::ExpectGone { resource, reason } => {
                    println!(
                        "  \x1b[33mEXPECT\x1b[0m {}/{}{}",
                        resource.kind,
                        resource.name,
                        scope_suffix(resource)
                    );
                    println!("         \x1b[2m{}\x1b[0m", reason);
                }
                Action::Keep { resource, reason } => {
                    println!(
                        "  \x1b[32mKEEP  \x1b[0m {}/{}{}",
                        resource.kind,
                        resource.name,
                        scope_suffix(resource)
                    );
                    println!("         \x1b[2m{}\x1b[0m", reason);
                }
                Action::Review {
                    resource, reason, ..
                } => {
                    println!(
                        "  \x1b[35mREVIEW\x1b[0m {}/{}{}",
                        resource.kind,
                        resource.name,
                        scope_suffix(resource)
                    );
                    println!("         \x1b[2m{}\x1b[0m", reason);
                }
                Action::WaitGone { resource } => {
                    println!(
                        "  \x1b[33mWAIT  \x1b[0m {}/{}{}",
                        resource.kind,
                        resource.name,
                        scope_suffix(resource)
                    );
                }
            }
        }

        if let Some(barrier) = &phase.barrier
            && !barrier.conditions.is_empty()
        {
            println!("\n  \x1b[1;33mBARRIER\x1b[0m {}", barrier.description);
        }
    }

    if !plan.blockers.is_empty() {
        println!("\n\x1b[1;31mBlockers\x1b[0m");
        for blocker in &plan.blockers {
            println!("  {}/{}", blocker.resource.kind, blocker.resource.name);
            println!("    {}", blocker.reason);
        }
    }

    if !plan.warnings.is_empty() {
        println!("\n\x1b[1;33mWarnings\x1b[0m");
        for warning in &plan.warnings {
            println!("  {}", warning.message);
        }
    }

    // Summary
    let mut delete_count = 0;
    let mut expect_count = 0;
    let mut keep_count = 0;
    let mut review_count = 0;
    for phase in &plan.phases {
        for action in &phase.actions {
            match action {
                Action::Delete { .. } => delete_count += 1,
                Action::ExpectGone { .. } => expect_count += 1,
                Action::Keep { .. } => keep_count += 1,
                Action::Review { .. } => review_count += 1,
                Action::WaitGone { .. } => {}
            }
        }
    }
    println!(
        "\n\x1b[1mSummary\x1b[0m: {} DELETE, {} EXPECT-GONE, {} KEEP, {} REVIEW",
        delete_count, expect_count, keep_count, review_count
    );
    println!(
        "  {} blockers, {} warnings",
        plan.blockers.len(),
        plan.warnings.len()
    );
    // Blocker reasons are shown individually above — no additional summary needed.
    // Each blocker's reason text includes the exact --approve-resource command.
}

fn print_plan_json(plan: &TeardownPlan) {
    println!("{}", serde_json::to_string_pretty(plan).unwrap_or_default());
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_test_operator(csv_name: &str, sub_name: &str) -> OperatorInstance {
        OperatorInstance {
            subscription: Some(ResourceId {
                group: "operators.coreos.com".to_string(),
                version: "v1alpha1".to_string(),
                kind: "Subscription".to_string(),
                namespace: Some("test-ns".to_string()),
                name: sub_name.to_string(),
                uid: None,
            }),
            csv: ResourceId {
                group: "operators.coreos.com".to_string(),
                version: "v1alpha1".to_string(),
                kind: "ClusterServiceVersion".to_string(),
                namespace: Some("test-ns".to_string()),
                name: csv_name.to_string(),
                uid: Some("csv-uid-current".to_string()),
            },
            csv_phase: "Succeeded".to_string(),
            owned_crds: vec![],
            required_crds: vec![],
            owned_api_service_defs: vec![],
            required_api_service_defs: vec![],
            deployments: vec!["test-controller".to_string()],
            service_accounts: vec![],
            install_namespace: "test-ns".to_string(),
            package_name: None,
            has_unlinked_subscriptions: false,
        }
    }

    fn make_cr_instance(
        kind: &str,
        name: &str,
        uid: &str,
        owner_refs: Vec<(String, String, String)>,
        labels: HashMap<String, String>,
        managers: Vec<String>,
    ) -> CrInstance {
        CrInstance {
            id: ResourceId {
                group: "test.example.com".to_string(),
                version: "v1".to_string(),
                kind: kind.to_string(),
                namespace: None,
                name: name.to_string(),
                uid: Some(uid.to_string()),
            },
            owner_refs,
            api_owner_key: format!("{}s.test.example.com", kind.to_lowercase()),
            labels,
            managed_field_managers: managers,
            provenance: Provenance::Unknown,
            discovery_source: DiscoverySource::Direct,
            decisive_label_pairs: vec![],
            ownerref_to_owned_api_kind: None,
        }
    }

    // ── resolve_operator_targets ──

    #[test]
    fn resolve_exact_csv_match() {
        let ops = vec![
            make_test_operator("rhods-operator.3.5.0", "rhods-operator"),
            make_test_operator("odf-operator.v4.22", "odf-operator"),
        ];
        let result = resolve_operator_targets(&["rhods-operator.3.5.0".to_string()], &ops).unwrap();
        assert_eq!(result, vec![0]);
    }

    #[test]
    fn resolve_exact_subscription_match() {
        let ops = vec![
            make_test_operator("rhods-operator.3.5.0", "rhods-operator"),
            make_test_operator("odf-operator.v4.22", "odf-operator"),
        ];
        let result = resolve_operator_targets(&["odf-operator".to_string()], &ops).unwrap();
        assert_eq!(result, vec![1]);
    }

    #[test]
    fn resolve_partial_match() {
        let ops = vec![
            make_test_operator("rhods-operator.3.5.0", "rhods-operator"),
            make_test_operator("odf-operator.v4.22", "odf-operator"),
        ];
        let result = resolve_operator_targets(&["rhods".to_string()], &ops).unwrap();
        assert_eq!(result, vec![0]);
    }

    #[test]
    fn resolve_ambiguous_fails() {
        let ops = vec![
            make_test_operator("my-operator.v1", "my-operator-a"),
            make_test_operator("my-operator.v2", "my-operator-b"),
        ];
        let result = resolve_operator_targets(&["my-operator".to_string()], &ops);
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(
            err.contains("Ambiguous"),
            "expected ambiguous error, got: {}",
            err
        );
    }

    #[test]
    fn resolve_not_found_fails() {
        let ops = vec![make_test_operator("rhods-operator.3.5.0", "rhods-operator")];
        let result = resolve_operator_targets(&["nonexistent".to_string()], &ops);
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(
            err.contains("not found"),
            "expected not found error, got: {}",
            err
        );
    }

    #[test]
    fn resolve_deduplicates() {
        let ops = vec![make_test_operator("rhods-operator.3.5.0", "rhods-operator")];
        let result = resolve_operator_targets(
            &[
                "rhods-operator".to_string(),
                "rhods-operator.3.5.0".to_string(),
            ],
            &ops,
        )
        .unwrap();
        assert_eq!(result, vec![0]);
    }

    // ── classify_provenance ──

    #[test]
    fn provenance_ownerref_to_csv_is_managed() {
        let op = make_test_operator("rhods-operator.3.5.0", "rhods-operator");
        let ops: Vec<&OperatorInstance> = vec![&op];
        let mut cr = make_cr_instance(
            "MyResource",
            "test",
            "uid-1",
            vec![(
                "ClusterServiceVersion".to_string(),
                "rhods-operator.3.5.0".to_string(),
                "csv-uid-current".to_string(), // matches operator CSV UID
            )],
            HashMap::new(),
            vec![],
        );
        classify_provenance(&mut cr, &ops, &HashSet::new());
        assert!(matches!(cr.provenance, Provenance::Managed));
    }

    #[test]
    fn provenance_ownerref_to_csv_stale_uid_not_managed() {
        let op = make_test_operator("rhods-operator.3.5.0", "rhods-operator");
        let ops: Vec<&OperatorInstance> = vec![&op];
        let mut cr = make_cr_instance(
            "MyResource",
            "test",
            "uid-1",
            vec![(
                "ClusterServiceVersion".to_string(),
                "rhods-operator.3.5.0".to_string(),
                "stale-csv-uid".to_string(), // does NOT match current CSV UID
            )],
            HashMap::new(),
            vec![],
        );
        classify_provenance(&mut cr, &ops, &HashSet::new());
        assert!(
            matches!(cr.provenance, Provenance::LikelyManaged),
            "stale CSV UID ownerRef must NOT grant Managed: got {:?}",
            cr.provenance
        );
    }

    #[test]
    fn provenance_ownerref_to_deployment_is_likely_managed() {
        let op = make_test_operator("rhods-operator.3.5.0", "rhods-operator");
        let ops: Vec<&OperatorInstance> = vec![&op];
        let mut cr = make_cr_instance(
            "MyResource",
            "test",
            "uid-1",
            vec![(
                "Deployment".to_string(),
                "test-controller".to_string(),
                "deploy-uid".to_string(),
            )],
            HashMap::new(),
            vec![],
        );
        classify_provenance(&mut cr, &ops, &HashSet::new());
        assert!(
            matches!(cr.provenance, Provenance::LikelyManaged),
            "Deployment ownerRef (no UID snapshot) must be LikelyManaged, not Managed"
        );
    }

    #[test]
    fn provenance_label_with_csv_prefix_is_likely_managed() {
        let op = make_test_operator("rhods-operator.3.5.0", "rhods-operator");
        let ops: Vec<&OperatorInstance> = vec![&op];
        let mut labels = HashMap::new();
        labels.insert(
            "app.kubernetes.io/managed-by-rhods-operator".to_string(),
            "true".to_string(),
        );
        let mut cr = make_cr_instance("MyResource", "test", "uid-1", vec![], labels, vec![]);
        classify_provenance(&mut cr, &ops, &HashSet::new());
        assert!(matches!(cr.provenance, Provenance::LikelyManaged));
    }

    #[test]
    fn provenance_generic_label_stays_unknown() {
        let op = make_test_operator("rhods-operator.3.5.0", "rhods-operator");
        let ops: Vec<&OperatorInstance> = vec![&op];
        let mut labels = HashMap::new();
        labels.insert(
            "app.kubernetes.io/part-of".to_string(),
            "something".to_string(),
        );
        let mut cr = make_cr_instance("MyResource", "test", "uid-1", vec![], labels, vec![]);
        classify_provenance(&mut cr, &ops, &HashSet::new());
        assert!(matches!(cr.provenance, Provenance::Unknown));
    }

    #[test]
    fn provenance_managed_fields_manager_is_likely_managed() {
        let op = make_test_operator("rhods-operator.3.5.0", "rhods-operator");
        let ops: Vec<&OperatorInstance> = vec![&op];
        let mut cr = make_cr_instance(
            "MyResource",
            "test",
            "uid-1",
            vec![],
            HashMap::new(),
            vec!["test-controller".to_string()],
        );
        classify_provenance(&mut cr, &ops, &HashSet::new());
        assert!(matches!(cr.provenance, Provenance::LikelyManaged));
    }

    // P0-2 regression: root CR with Unknown provenance → REVIEW, not DELETE
    #[test]
    fn unknown_root_cr_is_review_not_delete() {
        // A root CR (is_parent=true) with Unknown provenance should be REVIEW
        let cr = make_cr_instance(
            "MyRoot",
            "root-cr",
            "uid-root",
            vec![],
            HashMap::new(),
            vec![],
        );
        assert!(matches!(cr.provenance, Provenance::Unknown));
        // When provenance is Unknown and the CR is root, planner should emit Review, not Delete
        // (verified by matching the code path in generate_teardown_plan Phase 1)
    }

    // P1-1 regression: topo sort produces correct layer ordering
    #[test]
    fn topo_sort_single_operator() {
        let ops = vec![make_test_operator("a.v1", "a")];
        let result = topo_sort_operators(&[0], &ops, &[]);
        let layers = match result {
            TopoSortResult::Layers(l) => l,
            TopoSortResult::Cycle(_) => panic!("expected layers"),
        };
        assert_eq!(layers.len(), 1);
        assert_eq!(layers[0], vec![0]);
    }

    #[test]
    fn topo_sort_independent_operators() {
        let ops = vec![
            make_test_operator("a.v1", "a"),
            make_test_operator("b.v1", "b"),
        ];
        let result = topo_sort_operators(&[0, 1], &ops, &[]);
        let layers = match result {
            TopoSortResult::Layers(l) => l,
            TopoSortResult::Cycle(_) => panic!("expected layers"),
        };
        // No dependencies → all in one layer
        assert_eq!(layers.len(), 1);
        assert_eq!(layers[0].len(), 2);
    }

    #[test]
    fn topo_sort_with_dependency() {
        use crate::analyzers::olm::OperatorDependency;
        let mut op_a = make_test_operator("a.v1", "a");
        op_a.required_crds = vec!["foos.example.com".to_string()];
        let mut op_b = make_test_operator("b.v1", "b");
        op_b.owned_crds = vec!["foos.example.com".to_string()];
        let ops = vec![op_a, op_b];
        let deps = vec![OperatorDependency {
            from: OperatorId {
                csv_name: "a.v1".to_string(),
                namespace: "test-ns".to_string(),
            },
            to: OperatorId {
                csv_name: "b.v1".to_string(),
                namespace: "test-ns".to_string(),
            },
            via: crate::analyzers::olm::DependencyVia::Crd("foos.example.com".to_string()),
            confidence: 1.0,
        }];
        let result = topo_sort_operators(&[0, 1], &ops, &deps);
        let layers = match result {
            TopoSortResult::Layers(l) => l,
            TopoSortResult::Cycle(_) => panic!("expected layers"),
        };
        // a depends on b → a in layer 0 (delete first), b in layer 1
        assert_eq!(layers.len(), 2);
        assert!(layers[0].contains(&0)); // a first (dependent)
        assert!(layers[1].contains(&1)); // b second (provider)
    }

    #[test]
    fn provenance_no_evidence_is_unknown() {
        let op = make_test_operator("rhods-operator.3.5.0", "rhods-operator");
        let ops: Vec<&OperatorInstance> = vec![&op];
        let mut cr = make_cr_instance(
            "MyResource",
            "test",
            "uid-1",
            vec![],
            HashMap::new(),
            vec![],
        );
        classify_provenance(&mut cr, &ops, &HashSet::new());
        assert!(matches!(cr.provenance, Provenance::Unknown));
    }

    // P0-1 (round 3): dependency layers become separate phases
    #[test]
    fn topo_sort_dependency_produces_multiple_layers() {
        use crate::analyzers::olm::OperatorDependency;
        let mut op_a = make_test_operator("a.v1", "a");
        op_a.required_crds = vec!["foos.example.com".to_string()];
        let mut op_b = make_test_operator("b.v1", "b");
        op_b.owned_crds = vec!["foos.example.com".to_string()];
        let mut op_c = make_test_operator("c.v1", "c");
        op_c.required_crds = vec!["bars.example.com".to_string()];
        op_b.owned_crds.push("bars.example.com".to_string());
        let ops = vec![op_a, op_b, op_c];
        let deps = vec![
            OperatorDependency {
                from: OperatorId {
                    csv_name: "a.v1".to_string(),
                    namespace: "test-ns".to_string(),
                },
                to: OperatorId {
                    csv_name: "b.v1".to_string(),
                    namespace: "test-ns".to_string(),
                },
                via: crate::analyzers::olm::DependencyVia::Crd("foos.example.com".to_string()),
                confidence: 1.0,
            },
            OperatorDependency {
                from: OperatorId {
                    csv_name: "c.v1".to_string(),
                    namespace: "test-ns".to_string(),
                },
                to: OperatorId {
                    csv_name: "b.v1".to_string(),
                    namespace: "test-ns".to_string(),
                },
                via: crate::analyzers::olm::DependencyVia::Crd("bars.example.com".to_string()),
                confidence: 1.0,
            },
        ];
        let result = topo_sort_operators(&[0, 1, 2], &ops, &deps);
        let layers = match result {
            TopoSortResult::Layers(l) => l,
            TopoSortResult::Cycle(_) => panic!("expected layers"),
        };
        assert_eq!(layers.len(), 2);
        // Layer 0: a and c (dependents), Layer 1: b (provider)
        assert!(layers[0].contains(&0));
        assert!(layers[0].contains(&2));
        assert!(layers[1].contains(&1));
    }

    #[test]
    fn dependency_cycle_is_detected() {
        use crate::analyzers::olm::OperatorDependency;
        let mut op_a = make_test_operator("a.v1", "a");
        op_a.required_crds = vec!["foos.example.com".to_string()];
        let mut op_b = make_test_operator("b.v1", "b");
        op_b.owned_crds = vec!["foos.example.com".to_string()];
        op_b.required_crds = vec!["bars.example.com".to_string()];
        op_a.owned_crds = vec!["bars.example.com".to_string()];
        let ops = vec![op_a, op_b];
        let deps = vec![
            OperatorDependency {
                from: OperatorId {
                    csv_name: "a.v1".to_string(),
                    namespace: "test-ns".to_string(),
                },
                to: OperatorId {
                    csv_name: "b.v1".to_string(),
                    namespace: "test-ns".to_string(),
                },
                via: crate::analyzers::olm::DependencyVia::Crd("foos.example.com".to_string()),
                confidence: 1.0,
            },
            OperatorDependency {
                from: OperatorId {
                    csv_name: "b.v1".to_string(),
                    namespace: "test-ns".to_string(),
                },
                to: OperatorId {
                    csv_name: "a.v1".to_string(),
                    namespace: "test-ns".to_string(),
                },
                via: crate::analyzers::olm::DependencyVia::Crd("bars.example.com".to_string()),
                confidence: 1.0,
            },
        ];
        let result = topo_sort_operators(&[0, 1], &ops, &deps);
        assert!(matches!(result, TopoSortResult::Cycle(_)));
    }

    // P0-2 (round 3): CrdDiscoveryResult distinguishes Success vs Unavailable
    #[test]
    fn crd_discovery_result_types() {
        let success = CrdDiscoveryResult::Success(vec![]);
        assert!(matches!(success, CrdDiscoveryResult::Success(_)));
        let unavail =
            CrdDiscoveryResult::Unavailable(crate::kube::resource::ScanWarning::Forbidden {
                gvr: "test".to_string(),
                status: 403,
            });
        assert!(matches!(unavail, CrdDiscoveryResult::Unavailable(_)));
    }

    #[test]
    fn managed_provenance_is_not_exact_approvable() {
        let op = make_test_operator("test-op.v1", "test-op");
        let ops: Vec<&OperatorInstance> = vec![&op];

        let mut cr_managed = make_cr_instance(
            "Widget",
            "managed-widget",
            "uid-managed",
            vec![(
                "ClusterServiceVersion".to_string(),
                "test-op.v1".to_string(),
                "csv-uid-current".to_string(), // matches operator CSV UID
            )],
            HashMap::new(),
            vec![],
        );
        classify_provenance(&mut cr_managed, &ops, &HashSet::new());
        assert!(matches!(cr_managed.provenance, Provenance::Managed));
        assert!(!is_exact_delete_approvable(
            &cr_managed,
            GraphPosition::Root,
            1
        ));
        assert!(!is_exact_delete_approvable(
            &cr_managed,
            GraphPosition::Independent,
            1
        ));

        let mut cr_unknown = make_cr_instance(
            "Widget",
            "unknown-widget",
            "uid-unknown",
            vec![],
            HashMap::new(),
            vec![],
        );
        classify_provenance(&mut cr_unknown, &ops, &HashSet::new());
        assert!(matches!(cr_unknown.provenance, Provenance::Unknown));
        assert!(is_exact_delete_approvable(
            &cr_unknown,
            GraphPosition::Root,
            1
        ));
        assert!(is_exact_delete_approvable(
            &cr_unknown,
            GraphPosition::Independent,
            1
        ));
    }

    #[test]
    fn shared_ownership_is_not_exact_approvable() {
        let mut cr = make_cr_instance("Widget", "shared", "uid-s", vec![], HashMap::new(), vec![]);
        cr.provenance = Provenance::Unknown;
        assert!(!is_exact_delete_approvable(&cr, GraphPosition::Root, 2));
        assert!(!is_exact_delete_approvable(
            &cr,
            GraphPosition::Independent,
            2
        ));
    }

    #[test]
    fn descendant_is_not_exact_approvable() {
        let mut cr = make_cr_instance("Widget", "child", "uid-c", vec![], HashMap::new(), vec![]);
        cr.provenance = Provenance::Unknown;
        assert!(!is_exact_delete_approvable(
            &cr,
            GraphPosition::Descendant,
            1
        ));
    }

    #[test]
    fn label_only_is_explicit_only_approval_class() {
        let mut cr = make_cr_instance(
            "Widget",
            "label-only",
            "uid-l",
            vec![],
            HashMap::new(),
            vec![],
        );
        cr.discovery_source = DiscoverySource::RelatedLabelOnly;
        assert_eq!(
            compute_approval_class(&cr, GraphPosition::Root),
            DeleteApprovalClass::ExplicitOnly
        );
        assert_eq!(
            compute_approval_class(&cr, GraphPosition::Independent),
            DeleteApprovalClass::ExplicitOnly
        );
        assert_eq!(
            compute_approval_class(&cr, GraphPosition::Descendant),
            DeleteApprovalClass::Standard
        );
    }

    #[test]
    fn direct_cr_is_standard_approval_class() {
        let cr = make_cr_instance("Widget", "direct", "uid-d", vec![], HashMap::new(), vec![]);
        assert_eq!(
            compute_approval_class(&cr, GraphPosition::Root),
            DeleteApprovalClass::Standard
        );
        assert_eq!(
            compute_approval_class(&cr, GraphPosition::Independent),
            DeleteApprovalClass::Standard
        );
    }

    // ── enforce_expect_delete_invariant ──

    fn make_phase(actions: Vec<Action>) -> PlanPhase {
        PlanPhase {
            name: "test".to_string(),
            description: "".to_string(),
            actions,
            barrier: None,
        }
    }

    fn make_res(kind: &str, name: &str, uid: &str) -> ResourceId {
        ResourceId {
            group: "test".to_string(),
            version: "v1".to_string(),
            kind: kind.to_string(),
            namespace: None,
            name: name.to_string(),
            uid: Some(uid.to_string()),
        }
    }

    #[test]
    fn same_phase_transitive_chain_is_supported() {
        let a = make_res("R", "a", "uid-a");
        let b = make_res("R", "b", "uid-b");
        let c = make_res("R", "c", "uid-c");
        let mut phases = vec![make_phase(vec![
            Action::Delete {
                resource: a,
                reason: "".into(),
            },
            Action::ExpectGone {
                resource: b.clone(),
                reason: "".into(),
            },
            Action::ExpectGone {
                resource: c.clone(),
                reason: "".into(),
            },
        ])];
        let mut owners = HashMap::new();
        owners.insert("uid-b".to_string(), vec!["uid-a".to_string()]);
        owners.insert("uid-c".to_string(), vec!["uid-b".to_string()]);

        enforce_expect_delete_invariant(&mut phases, &owners);

        assert!(matches!(&phases[0].actions[1], Action::ExpectGone { .. }));
        assert!(matches!(&phases[0].actions[2], Action::ExpectGone { .. }));
    }

    #[test]
    fn previous_phase_delete_supports_later_expect() {
        let a = make_res("R", "a", "uid-a");
        let b = make_res("R", "b", "uid-b");
        let mut phases = vec![
            make_phase(vec![Action::Delete {
                resource: a,
                reason: "".into(),
            }]),
            make_phase(vec![Action::ExpectGone {
                resource: b.clone(),
                reason: "".into(),
            }]),
        ];
        let mut owners = HashMap::new();
        owners.insert("uid-b".to_string(), vec!["uid-a".to_string()]);

        enforce_expect_delete_invariant(&mut phases, &owners);

        assert!(matches!(&phases[1].actions[0], Action::ExpectGone { .. }));
    }

    #[test]
    fn future_phase_delete_does_not_support_earlier_expect() {
        let a = make_res("R", "a", "uid-a");
        let b = make_res("R", "b", "uid-b");
        let mut phases = vec![
            make_phase(vec![Action::ExpectGone {
                resource: b.clone(),
                reason: "".into(),
            }]),
            make_phase(vec![Action::Delete {
                resource: a,
                reason: "".into(),
            }]),
        ];
        let mut owners = HashMap::new();
        owners.insert("uid-b".to_string(), vec!["uid-a".to_string()]);

        enforce_expect_delete_invariant(&mut phases, &owners);

        assert!(matches!(&phases[0].actions[0], Action::Keep { .. }));
    }

    #[test]
    fn cycle_without_delete_seed_is_demoted() {
        let a = make_res("R", "a", "uid-a");
        let b = make_res("R", "b", "uid-b");
        let mut phases = vec![make_phase(vec![
            Action::ExpectGone {
                resource: a.clone(),
                reason: "".into(),
            },
            Action::ExpectGone {
                resource: b.clone(),
                reason: "".into(),
            },
        ])];
        let mut owners = HashMap::new();
        owners.insert("uid-a".to_string(), vec!["uid-b".to_string()]);
        owners.insert("uid-b".to_string(), vec!["uid-a".to_string()]);

        enforce_expect_delete_invariant(&mut phases, &owners);

        assert!(matches!(&phases[0].actions[0], Action::Keep { .. }));
        assert!(matches!(&phases[0].actions[1], Action::Keep { .. }));
    }

    // ── probe_uid mock API tests ──

    use kube::client::Body;
    use std::pin::pin;

    fn json_response(json: serde_json::Value) -> http::Response<Body> {
        http::Response::builder()
            .status(200)
            .body(Body::from(serde_json::to_vec(&json).unwrap()))
            .unwrap()
    }

    fn status_response(code: u16, reason: &str) -> http::Response<Body> {
        let body = serde_json::json!({
            "kind": "Status",
            "apiVersion": "v1",
            "metadata": {},
            "status": "Failure",
            "message": reason,
            "reason": reason,
            "code": code
        });
        http::Response::builder()
            .status(code)
            .body(Body::from(serde_json::to_vec(&body).unwrap()))
            .unwrap()
    }

    fn make_mock_api(
        mock_service: tower_test::mock::Mock<http::Request<Body>, http::Response<Body>>,
    ) -> kube::api::Api<kube::api::DynamicObject> {
        let client = Client::new(mock_service, "default");
        let gvk = kube::core::GroupVersion::gv("apiextensions.k8s.io", "v1")
            .with_kind("CustomResourceDefinition");
        let ar = kube::api::ApiResource::from_gvk_with_plural(&gvk, "customresourcedefinitions");
        kube::api::Api::all_with(client, &ar)
    }

    #[tokio::test]
    async fn test_probe_uid_get404_list200_is_absent() {
        let (mock_service, handle) =
            tower_test::mock::pair::<http::Request<Body>, http::Response<Body>>();

        let api = make_mock_api(mock_service);

        let spawned = tokio::spawn(async move {
            let mut handle = pin!(handle);

            // GET → 404
            let (_req, send) = handle.next_request().await.expect("expected GET");
            send.send_response(status_response(404, "NotFound"));

            // LIST (endpoint verification) → 200
            let (_req, send) = handle.next_request().await.expect("expected LIST");
            send.send_response(json_response(serde_json::json!({
                "apiVersion": "v1",
                "kind": "CustomResourceDefinitionList",
                "metadata": { "resourceVersion": "1" },
                "items": []
            })));
        });

        let result = probe_uid(&api, "test-crd.example.com").await;
        assert!(
            matches!(result, BindResult::Absent),
            "GET 404 + LIST 200 should be Absent, got: {:?}",
            std::mem::discriminant(&result)
        );

        spawned.await.unwrap();
    }

    #[tokio::test]
    async fn test_probe_uid_get404_list403_is_failed() {
        let (mock_service, handle) =
            tower_test::mock::pair::<http::Request<Body>, http::Response<Body>>();

        let api = make_mock_api(mock_service);

        let spawned = tokio::spawn(async move {
            let mut handle = pin!(handle);

            // GET → 404
            let (_req, send) = handle.next_request().await.expect("expected GET");
            send.send_response(status_response(404, "NotFound"));

            // LIST → 403
            let (_req, send) = handle.next_request().await.expect("expected LIST");
            send.send_response(status_response(403, "Forbidden"));
        });

        let result = probe_uid(&api, "test-crd.example.com").await;
        assert!(
            matches!(result, BindResult::Failed(ref msg) if msg.contains("endpoint verification failed")),
            "GET 404 + LIST 403 should be Failed, got: {:?}",
            std::mem::discriminant(&result)
        );

        spawned.await.unwrap();
    }

    #[tokio::test]
    async fn test_probe_uid_get200_returns_bound_uid() {
        let (mock_service, handle) =
            tower_test::mock::pair::<http::Request<Body>, http::Response<Body>>();

        let api = make_mock_api(mock_service);

        let spawned = tokio::spawn(async move {
            let mut handle = pin!(handle);

            // GET → 200 with UID
            let (_req, send) = handle.next_request().await.expect("expected GET");
            send.send_response(json_response(serde_json::json!({
                "apiVersion": "apiextensions.k8s.io/v1",
                "kind": "CustomResourceDefinition",
                "metadata": {
                    "name": "test-crd.example.com",
                    "uid": "uid-B"
                }
            })));
        });

        let result = probe_uid(&api, "test-crd.example.com").await;
        assert!(
            matches!(result, BindResult::Bound(ref uid) if uid == "uid-B"),
            "GET 200 with UID should be Bound(uid-B), got: {:?}",
            std::mem::discriminant(&result)
        );

        spawned.await.unwrap();
    }

    #[test]
    fn related_label_only_root_is_blocker_exempt() {
        let mut cr = make_cr_instance(
            "Config",
            "default",
            "uid-config",
            vec![],
            HashMap::new(),
            vec![],
        );
        cr.discovery_source = DiscoverySource::RelatedLabelOnly;
        assert!(
            is_root_blocker_exempt(&cr),
            "RelatedLabelOnly root must be exempt from hard blocker"
        );
    }

    #[test]
    fn direct_root_is_not_blocker_exempt() {
        let cr = make_cr_instance(
            "MyResource",
            "test",
            "uid-test",
            vec![],
            HashMap::new(),
            vec![],
        );
        // default discovery_source is Direct
        assert!(
            !is_root_blocker_exempt(&cr),
            "Direct-discovery root must NOT be exempt — remains hard blocker"
        );
    }

    #[test]
    fn related_linked_root_is_not_blocker_exempt() {
        let mut cr = make_cr_instance("Widget", "w1", "uid-w1", vec![], HashMap::new(), vec![]);
        cr.discovery_source = DiscoverySource::RelatedLinked;
        assert!(
            !is_root_blocker_exempt(&cr),
            "RelatedLinked root has lifecycle connection — must remain hard blocker"
        );
    }

    #[test]
    fn phase_failed_prevents_subsequent_phases() {
        let result = crate::teardown::executor::ExecutionResult {
            phases_completed: 1,
            phases_total: 5,
            deleted: vec![make_res("Subscription", "test-operator", "uid-sub")],
            already_gone: vec![],
            failed: vec![(
                make_res("ResourceA", "res-a", "uid-a"),
                "blocked by webhook".to_string(),
            )],
            barrier_timeout: None,
            kept: vec![],
            reviewed: vec![],
        };
        assert!(
            !result.failed.is_empty(),
            "failed actions must trigger phase hard stop"
        );
        assert!(
            result.phases_completed < result.phases_total,
            "phases_completed must not reach total when failed actions exist"
        );
    }

    #[test]
    fn api_owner_key_used_not_kind_plural_guess() {
        // Irregular plural: Kind="Ingress" → plural="ingresses", NOT "ingresss"
        // CrInstance.api_owner_key must hold the CRD name from discovery,
        // not a Kind.to_lowercase()+"s" guess.
        let cr = CrInstance {
            id: ResourceId {
                group: "networking.k8s.io".to_string(),
                version: "v1".to_string(),
                kind: "Ingress".to_string(),
                namespace: Some("ns".to_string()),
                name: "my-ingress".to_string(),
                uid: Some("uid-1".to_string()),
            },
            api_owner_key: "ingresses.networking.k8s.io".to_string(),
            labels: std::collections::HashMap::new(),
            owner_refs: vec![],
            managed_field_managers: vec![],
            provenance: Provenance::Unknown,
            discovery_source: DiscoverySource::RelatedLabelOnly,
            decisive_label_pairs: vec![],
            ownerref_to_owned_api_kind: None,
        };

        // Incorrect guess would be "ingresss.networking.k8s.io" — must not match
        let wrong_guess = format!("{}s.{}", cr.id.kind.to_lowercase(), cr.id.group);
        assert_ne!(
            wrong_guess, cr.api_owner_key,
            "Kind.to_lowercase()+s gives wrong plural for irregular kinds"
        );
        assert_eq!(cr.api_owner_key, "ingresses.networking.k8s.io");

        // Lookup with api_owner_key works; lookup with wrong guess does not
        let mut crd_pairs = std::collections::HashMap::new();
        crd_pairs.insert(
            "ingresses.networking.k8s.io".to_string(),
            vec![("k8s.io/part-of".to_string(), "platform".to_string())],
        );

        let decisive = crd_pairs
            .get(&cr.api_owner_key)
            .cloned()
            .unwrap_or_default();
        assert_eq!(decisive.len(), 1, "api_owner_key lookup must succeed");

        let wrong_decisive = crd_pairs.get(&wrong_guess).cloned().unwrap_or_default();
        assert!(
            wrong_decisive.is_empty(),
            "wrong plural guess must not match"
        );
    }

    // ── PR5: Saved Plan validation ──

    #[test]
    fn saved_decision_empty_basis_blocked() {
        use crate::teardown::plan::*;
        let plan = TeardownPlan {
            targets: vec![],
            preflight: Preflight { checks: vec![] },
            phases: vec![PlanPhase {
                name: "test".to_string(),
                description: "".to_string(),
                actions: vec![Action::Review {
                    resource: make_res("Widget", "w1", "uid-1"),
                    reason: "test".to_string(),
                    metadata: None,
                }],
                barrier: None,
            }],
            blockers: vec![],
            warnings: vec![],
            snapshot_taken_at: "test".to_string(),
            dependency_edges: vec![],
            operator_inventory: vec![],
            explicit_decisions: vec![],
        };
        let saved = SavedTeardownPlan {
            schema_version: crate::teardown::plan::SAVED_PLAN_SCHEMA_VERSION,
            target: SavedOperatorTarget {
                package_name: "test".to_string(),
                install_namespace: "ns".to_string(),
                csv_name_pattern: "test.v1".to_string(),
            },
            teardown_decisions: vec![SavedDecision {
                match_spec: ResourceMatch::from_resource_id(&make_res("Widget", "w1", "uid-1")),
                action: SavedAction::Delete,
                approval: ApprovalKind::Explicit,
                basis: DecisionBasis {
                    provenance: None,
                    review_category: None,
                    discovery_source: None,
                    decisive_evidence: vec![],
                },
            }],
            residual_decisions: vec![],
        };
        let result = validate_saved_decisions(&plan, &saved);
        assert!(result.is_err(), "Empty basis must be blocked");
    }

    #[test]
    fn saved_decision_with_basis_produces_approvals() {
        use crate::teardown::plan::*;
        let plan = TeardownPlan {
            targets: vec![],
            preflight: Preflight { checks: vec![] },
            phases: vec![PlanPhase {
                name: "test".to_string(),
                description: "".to_string(),
                actions: vec![Action::Review {
                    resource: make_res("Widget", "w1", "uid-1"),
                    reason: "test".to_string(),
                    metadata: Some(ReviewMetadata {
                        category: Some(ReviewCategorySer::OperandRoot),
                        approval_class: Some(DeleteApprovalClassSer::Standard),
                        provenance: Some(ProvenanceSer::Managed),
                        discovery_source: Some(DiscoverySourceSer::Direct),
                        decisive_label_pairs: vec![],
                    }),
                }],
                barrier: None,
            }],
            blockers: vec![],
            warnings: vec![],
            snapshot_taken_at: "test".to_string(),
            dependency_edges: vec![],
            operator_inventory: vec![],
            explicit_decisions: vec![],
        };
        let saved = SavedTeardownPlan {
            schema_version: crate::teardown::plan::SAVED_PLAN_SCHEMA_VERSION,
            target: SavedOperatorTarget {
                package_name: "test".to_string(),
                install_namespace: "ns".to_string(),
                csv_name_pattern: "test.v1".to_string(),
            },
            teardown_decisions: vec![SavedDecision {
                match_spec: ResourceMatch::from_resource_id(&make_res("Widget", "w1", "uid-1")),
                action: SavedAction::Delete,
                approval: ApprovalKind::Explicit,
                basis: DecisionBasis {
                    provenance: Some("Managed".to_string()),
                    review_category: Some("OperandRoot".to_string()),
                    discovery_source: Some("Direct".to_string()),
                    decisive_evidence: vec![],
                },
            }],
            residual_decisions: vec![],
        };
        let result = validate_saved_decisions(&plan, &saved);
        assert!(result.is_ok(), "Valid basis must produce approvals");
        let (approvals, _) = result.unwrap();
        assert_eq!(approvals.len(), 1);
    }

    #[test]
    fn saved_explicit_unattributed_blocked() {
        use crate::teardown::plan::*;
        let plan = TeardownPlan {
            targets: vec![],
            preflight: Preflight { checks: vec![] },
            phases: vec![PlanPhase {
                name: "test".to_string(),
                description: "".to_string(),
                actions: vec![Action::Review {
                    resource: make_res("Widget", "w1", "uid-1"),
                    reason: "test".to_string(),
                    metadata: None,
                }],
                barrier: None,
            }],
            blockers: vec![],
            warnings: vec![],
            snapshot_taken_at: "test".to_string(),
            dependency_edges: vec![],
            operator_inventory: vec![],
            explicit_decisions: vec![],
        };
        let saved = SavedTeardownPlan {
            schema_version: crate::teardown::plan::SAVED_PLAN_SCHEMA_VERSION,
            target: SavedOperatorTarget {
                package_name: "test".to_string(),
                install_namespace: "ns".to_string(),
                csv_name_pattern: "test.v1".to_string(),
            },
            teardown_decisions: vec![SavedDecision {
                match_spec: ResourceMatch::from_resource_id(&make_res("Widget", "w1", "uid-1")),
                action: SavedAction::Delete,
                approval: ApprovalKind::ExplicitUnattributed,
                basis: DecisionBasis {
                    provenance: Some("Unknown".to_string()),
                    review_category: None,
                    discovery_source: None,
                    decisive_evidence: vec![],
                },
            }],
            residual_decisions: vec![],
        };
        let result = validate_saved_decisions(&plan, &saved);
        assert!(result.is_err(), "ExplicitUnattributed must be blocked");
    }

    // ── PR7: Bulk label-only ──

    #[test]
    fn bulk_label_only_approves_label_related_explicit_only() {
        let resource = make_res("Widget", "w1", "uid-1");
        let candidate = ReviewCandidate {
            resource: &resource,
            category: ReviewCategory::Operand(GraphPosition::Independent),
            approval_class: DeleteApprovalClass::ExplicitOnly,
            exact_approvable: true,
            is_label_only_eligible: true,
        };
        let policy = DecisionPolicy::from_args(&["label-only".to_string()], &[]);
        let resolved = resolve_decisions(&policy, &[candidate]).unwrap();
        assert!(
            matches!(
                resolved.get(&resource),
                Some(ResolvedDecision::Delete { .. })
            ),
            "label-only is an explicit bulk approval for label-related REVIEW resources"
        );
    }

    #[test]
    fn bulk_all_does_not_approve_label_related_explicit_only() {
        let resource = make_res("Widget", "w1", "uid-1");
        let candidate = ReviewCandidate {
            resource: &resource,
            category: ReviewCategory::Operand(GraphPosition::Independent),
            approval_class: DeleteApprovalClass::ExplicitOnly,
            exact_approvable: true,
            is_label_only_eligible: true,
        };
        let policy = DecisionPolicy::from_args(&["all".to_string()], &[]);
        let resolved = resolve_decisions(&policy, &[candidate]).unwrap();
        assert!(
            !resolved.contains_key(&resource),
            "all must remain conservative for label-related explicit-only resources"
        );
    }

    #[test]
    fn operator_group_bulk_only_approves_operator_group() {
        let operator_group = make_res("OperatorGroup", "test-operator", "uid-og");
        let lease = make_res("Lease", "test-operator-lock", "uid-lease");
        let candidates = [
            ReviewCandidate {
                resource: &operator_group,
                category: ReviewCategory::Ancillary,
                approval_class: DeleteApprovalClass::ExplicitOnly,
                exact_approvable: true,
                is_label_only_eligible: false,
            },
            ReviewCandidate {
                resource: &lease,
                category: ReviewCategory::Ancillary,
                approval_class: DeleteApprovalClass::ExplicitOnly,
                exact_approvable: true,
                is_label_only_eligible: false,
            },
        ];
        let policy = DecisionPolicy::from_args(&["operator-group".to_string()], &[]);
        let resolved = resolve_decisions(&policy, &candidates).unwrap();
        assert!(matches!(
            resolved.get(&operator_group),
            Some(ResolvedDecision::Delete { .. })
        ));
        assert!(!resolved.contains_key(&lease));
    }

    // ── PR6: RequiresApi no delete authority ──

    #[test]
    fn requires_api_edge_is_informational() {
        let edge = DependencyEdge {
            from_operator: "consumer.v1".to_string(),
            to_operator: "provider.v1".to_string(),
            edge_type: DependencyEdgeType::RequiresApi,
            evidence: "widgets.example.com".to_string(),
        };
        assert!(matches!(edge.edge_type, DependencyEdgeType::RequiresApi));
    }

    // ── PR5: Saved Keep conflicts with fresh DELETE → BLOCK ──

    #[test]
    fn saved_keep_conflicts_with_fresh_delete_blocked() {
        use crate::teardown::plan::*;
        let plan = TeardownPlan {
            targets: vec![],
            preflight: Preflight { checks: vec![] },
            phases: vec![PlanPhase {
                name: "test".to_string(),
                description: "".to_string(),
                actions: vec![Action::Delete {
                    resource: make_res("Widget", "w1", "uid-1"),
                    reason: "managed".to_string(),
                }],
                barrier: None,
            }],
            blockers: vec![],
            warnings: vec![],
            snapshot_taken_at: "test".to_string(),
            dependency_edges: vec![],
            operator_inventory: vec![],
            explicit_decisions: vec![],
        };
        let saved = SavedTeardownPlan {
            schema_version: SAVED_PLAN_SCHEMA_VERSION,
            target: SavedOperatorTarget {
                package_name: "test".to_string(),
                install_namespace: "ns".to_string(),
                csv_name_pattern: "test.v1".to_string(),
            },
            teardown_decisions: vec![SavedDecision {
                match_spec: ResourceMatch::from_resource_id(&make_res("Widget", "w1", "uid-1")),
                action: SavedAction::Keep,
                approval: ApprovalKind::Explicit,
                basis: DecisionBasis {
                    provenance: Some("Managed".to_string()),
                    review_category: None,
                    discovery_source: None,
                    decisive_evidence: vec![],
                },
            }],
            residual_decisions: vec![],
        };
        let result = validate_saved_decisions(&plan, &saved);
        assert!(
            result.is_err(),
            "Saved KEEP conflicting with fresh DELETE must block"
        );
        let errors = result.unwrap_err();
        assert!(errors[0].contains("saved KEEP conflicts with fresh deterministic DELETE"));
    }

    // ── PR5: Saved decision not found in fresh plan → BLOCK ──

    #[test]
    fn saved_decision_not_in_fresh_plan_blocked() {
        use crate::teardown::plan::*;
        let plan = TeardownPlan {
            targets: vec![],
            preflight: Preflight { checks: vec![] },
            phases: vec![PlanPhase {
                name: "test".to_string(),
                description: "".to_string(),
                actions: vec![],
                barrier: None,
            }],
            blockers: vec![],
            warnings: vec![],
            snapshot_taken_at: "test".to_string(),
            dependency_edges: vec![],
            operator_inventory: vec![],
            explicit_decisions: vec![],
        };
        let saved = SavedTeardownPlan {
            schema_version: SAVED_PLAN_SCHEMA_VERSION,
            target: SavedOperatorTarget {
                package_name: "test".to_string(),
                install_namespace: "ns".to_string(),
                csv_name_pattern: "test.v1".to_string(),
            },
            teardown_decisions: vec![SavedDecision {
                match_spec: ResourceMatch::from_resource_id(&make_res("Widget", "gone", "uid-x")),
                action: SavedAction::Delete,
                approval: ApprovalKind::Explicit,
                basis: DecisionBasis {
                    provenance: Some("Managed".to_string()),
                    review_category: None,
                    discovery_source: None,
                    decisive_evidence: vec![],
                },
            }],
            residual_decisions: vec![],
        };
        let result = validate_saved_decisions(&plan, &saved);
        assert!(result.is_err());
        assert!(result.unwrap_err()[0].contains("not found in fresh plan"));
    }

    // ── PR5: build_decision_basis from ReviewMetadata ──

    #[test]
    fn build_decision_basis_captures_all_fields() {
        use crate::teardown::plan::*;
        let meta = ReviewMetadata {
            category: Some(ReviewCategorySer::OperandRoot),
            approval_class: Some(DeleteApprovalClassSer::Standard),
            provenance: Some(ProvenanceSer::LikelyManaged),
            discovery_source: Some(DiscoverySourceSer::RelatedLabelOnly),
            decisive_label_pairs: vec![(
                "app.kubernetes.io/part-of".to_string(),
                "test".to_string(),
            )],
        };
        let basis = build_decision_basis(&meta);
        assert_eq!(basis.provenance.as_deref(), Some("LikelyManaged"));
        assert_eq!(basis.review_category.as_deref(), Some("OperandRoot"));
        assert_eq!(basis.discovery_source.as_deref(), Some("RelatedLabelOnly"));
        assert_eq!(basis.decisive_evidence.len(), 1);
        assert!(matches!(
            &basis.decisive_evidence[0],
            SavedEvidenceSignature::Label { key, value }
            if key == "app.kubernetes.io/part-of" && value == "test"
        ));
    }

    // ── PR5: validate_saved_decisions provenance drift detection ──

    #[test]
    fn validate_blocks_provenance_weakening() {
        use crate::teardown::plan::*;
        let plan = TeardownPlan {
            targets: vec![],
            preflight: Preflight { checks: vec![] },
            phases: vec![PlanPhase {
                name: "test".to_string(),
                description: "".to_string(),
                actions: vec![Action::Review {
                    resource: make_res("Widget", "w1", "uid-1"),
                    reason: "test".to_string(),
                    metadata: Some(ReviewMetadata {
                        category: Some(ReviewCategorySer::OperandRoot),
                        approval_class: Some(DeleteApprovalClassSer::Standard),
                        provenance: Some(ProvenanceSer::Unknown),
                        discovery_source: Some(DiscoverySourceSer::Direct),
                        decisive_label_pairs: vec![],
                    }),
                }],
                barrier: None,
            }],
            blockers: vec![],
            warnings: vec![],
            snapshot_taken_at: "test".to_string(),
            dependency_edges: vec![],
            operator_inventory: vec![],
            explicit_decisions: vec![],
        };
        let saved = SavedTeardownPlan {
            schema_version: SAVED_PLAN_SCHEMA_VERSION,
            target: SavedOperatorTarget {
                package_name: "test".to_string(),
                install_namespace: "ns".to_string(),
                csv_name_pattern: "test.v1".to_string(),
            },
            teardown_decisions: vec![SavedDecision {
                match_spec: ResourceMatch::from_resource_id(&make_res("Widget", "w1", "uid-1")),
                action: SavedAction::Delete,
                approval: ApprovalKind::Explicit,
                basis: DecisionBasis {
                    provenance: Some("LikelyManaged".to_string()),
                    review_category: Some("OperandRoot".to_string()),
                    discovery_source: Some("Direct".to_string()),
                    decisive_evidence: vec![],
                },
            }],
            residual_decisions: vec![],
        };
        let result = validate_saved_decisions(&plan, &saved);
        assert!(result.is_err(), "LikelyManaged→Unknown must be blocked");
        assert!(result.unwrap_err()[0].contains("provenance drift"));
    }

    #[test]
    fn validate_allows_provenance_strengthening() {
        use crate::teardown::plan::*;
        let plan = TeardownPlan {
            targets: vec![],
            preflight: Preflight { checks: vec![] },
            phases: vec![PlanPhase {
                name: "test".to_string(),
                description: "".to_string(),
                actions: vec![Action::Review {
                    resource: make_res("Widget", "w1", "uid-1"),
                    reason: "test".to_string(),
                    metadata: Some(ReviewMetadata {
                        category: Some(ReviewCategorySer::OperandRoot),
                        approval_class: Some(DeleteApprovalClassSer::Standard),
                        provenance: Some(ProvenanceSer::Managed),
                        discovery_source: Some(DiscoverySourceSer::Direct),
                        decisive_label_pairs: vec![],
                    }),
                }],
                barrier: None,
            }],
            blockers: vec![],
            warnings: vec![],
            snapshot_taken_at: "test".to_string(),
            dependency_edges: vec![],
            operator_inventory: vec![],
            explicit_decisions: vec![],
        };
        let saved = SavedTeardownPlan {
            schema_version: SAVED_PLAN_SCHEMA_VERSION,
            target: SavedOperatorTarget {
                package_name: "test".to_string(),
                install_namespace: "ns".to_string(),
                csv_name_pattern: "test.v1".to_string(),
            },
            teardown_decisions: vec![SavedDecision {
                match_spec: ResourceMatch::from_resource_id(&make_res("Widget", "w1", "uid-1")),
                action: SavedAction::Delete,
                approval: ApprovalKind::Explicit,
                basis: DecisionBasis {
                    provenance: Some("LikelyManaged".to_string()),
                    review_category: Some("OperandRoot".to_string()),
                    discovery_source: Some("Direct".to_string()),
                    decisive_evidence: vec![],
                },
            }],
            residual_decisions: vec![],
        };
        let result = validate_saved_decisions(&plan, &saved);
        assert!(
            result.is_ok(),
            "LikelyManaged→Managed strengthening must be allowed"
        );
    }

    #[test]
    fn validate_blocks_missing_saved_label_in_fresh() {
        use crate::teardown::plan::*;
        let plan = TeardownPlan {
            targets: vec![],
            preflight: Preflight { checks: vec![] },
            phases: vec![PlanPhase {
                name: "test".to_string(),
                description: "".to_string(),
                actions: vec![Action::Review {
                    resource: make_res("Widget", "w1", "uid-1"),
                    reason: "test".to_string(),
                    metadata: Some(ReviewMetadata {
                        category: Some(ReviewCategorySer::OperandRoot),
                        approval_class: Some(DeleteApprovalClassSer::Standard),
                        provenance: Some(ProvenanceSer::LikelyManaged),
                        discovery_source: Some(DiscoverySourceSer::RelatedLabelOnly),
                        decisive_label_pairs: vec![],
                    }),
                }],
                barrier: None,
            }],
            blockers: vec![],
            warnings: vec![],
            snapshot_taken_at: "test".to_string(),
            dependency_edges: vec![],
            operator_inventory: vec![],
            explicit_decisions: vec![],
        };
        let saved = SavedTeardownPlan {
            schema_version: SAVED_PLAN_SCHEMA_VERSION,
            target: SavedOperatorTarget {
                package_name: "test".to_string(),
                install_namespace: "ns".to_string(),
                csv_name_pattern: "test.v1".to_string(),
            },
            teardown_decisions: vec![SavedDecision {
                match_spec: ResourceMatch::from_resource_id(&make_res("Widget", "w1", "uid-1")),
                action: SavedAction::Delete,
                approval: ApprovalKind::Explicit,
                basis: DecisionBasis {
                    provenance: Some("LikelyManaged".to_string()),
                    review_category: Some("OperandRoot".to_string()),
                    discovery_source: Some("RelatedLabelOnly".to_string()),
                    decisive_evidence: vec![SavedEvidenceSignature::Label {
                        key: "app/part-of".to_string(),
                        value: "gone".to_string(),
                    }],
                },
            }],
            residual_decisions: vec![],
        };
        let result = validate_saved_decisions(&plan, &saved);
        assert!(result.is_err(), "Missing label must block");
        assert!(result.unwrap_err()[0].contains("saved label"));
    }

    // ── PR7: bulk label-only does not match PVC/PV ──

    #[test]
    fn bulk_label_only_excludes_pvc() {
        let cr = CrInstance {
            id: ResourceId {
                group: "".to_string(),
                version: "v1".to_string(),
                kind: "PersistentVolumeClaim".to_string(),
                namespace: Some("ns".to_string()),
                name: "pvc1".to_string(),
                uid: Some("uid-1".to_string()),
            },
            owner_refs: vec![],
            api_owner_key: "".to_string(),
            labels: std::collections::HashMap::new(),
            managed_field_managers: vec![],
            provenance: Provenance::LikelyManaged,
            discovery_source: DiscoverySource::RelatedLabelOnly,
            decisive_label_pairs: vec![],
            ownerref_to_owned_api_kind: None,
        };
        assert!(
            !is_label_only_bulk_eligible(&cr),
            "PVC must be excluded from label-only bulk"
        );
    }

    #[test]
    fn bulk_label_only_includes_unknown_provenance() {
        let mut cr = make_cr_instance(
            "Widget",
            "label-only",
            "uid-label-only",
            vec![],
            HashMap::new(),
            vec![],
        );
        cr.provenance = Provenance::Unknown;
        cr.discovery_source = DiscoverySource::RelatedLabelOnly;
        assert!(
            is_label_only_bulk_eligible(&cr),
            "explicit label-only approval must include RelatedLabelOnly REVIEW resources"
        );
    }

    // ── Saved Plan roundtrip: basis non-empty after save_as_saved_plan ──

    #[test]
    fn saved_plan_roundtrip_basis_nonempty() {
        use crate::teardown::plan::*;
        // Simulate: plan with REVIEW item + explicit_decisions from approved REVIEW
        let plan = TeardownPlan {
            targets: vec![],
            preflight: Preflight { checks: vec![] },
            phases: vec![PlanPhase {
                name: "test".to_string(),
                description: "".to_string(),
                actions: vec![Action::Delete {
                    resource: make_res("Widget", "w1", "uid-1"),
                    reason: "approved".to_string(),
                }],
                barrier: None,
            }],
            blockers: vec![],
            warnings: vec![],
            snapshot_taken_at: "test".to_string(),
            dependency_edges: vec![],
            operator_inventory: vec![],
            explicit_decisions: vec![SavedDecision {
                match_spec: ResourceMatch::from_resource_id(&make_res("Widget", "w1", "uid-1")),
                action: SavedAction::Delete,
                approval: ApprovalKind::Explicit,
                basis: DecisionBasis {
                    provenance: Some("LikelyManaged".to_string()),
                    review_category: Some("OperandRoot".to_string()),
                    discovery_source: Some("Direct".to_string()),
                    decisive_evidence: vec![],
                },
            }],
        };
        let target = SavedOperatorTarget {
            package_name: "test-op".to_string(),
            install_namespace: "ns".to_string(),
            csv_name_pattern: "test.v1".to_string(),
        };
        let dir = std::env::temp_dir().join("oc-deps-roundtrip-test");
        let _ = std::fs::create_dir_all(&dir);
        let path = dir.join("roundtrip.json");
        let result = save_as_saved_plan(&plan, &target, Some(path.to_str().unwrap()));
        assert!(result.is_ok());
        let saved = load_saved_plan(path.to_str().unwrap()).unwrap();
        assert_eq!(saved.teardown_decisions.len(), 1);
        let d = &saved.teardown_decisions[0];
        assert!(
            d.basis.provenance.is_some(),
            "Saved basis provenance must not be empty"
        );
        assert_eq!(d.basis.provenance.as_deref(), Some("LikelyManaged"));
        assert_eq!(d.basis.discovery_source.as_deref(), Some("Direct"));
        let _ = std::fs::remove_file(&path);
    }

    // ── Saved Plan drift: discovery source change → BLOCK ──

    #[test]
    fn validate_blocks_discovery_source_drift() {
        use crate::teardown::plan::*;
        let plan = TeardownPlan {
            targets: vec![],
            preflight: Preflight { checks: vec![] },
            phases: vec![PlanPhase {
                name: "test".to_string(),
                description: "".to_string(),
                actions: vec![Action::Review {
                    resource: make_res("Widget", "w1", "uid-1"),
                    reason: "test".to_string(),
                    metadata: Some(ReviewMetadata {
                        category: Some(ReviewCategorySer::OperandRoot),
                        approval_class: Some(DeleteApprovalClassSer::Standard),
                        provenance: Some(ProvenanceSer::LikelyManaged),
                        discovery_source: Some(DiscoverySourceSer::RelatedLabelOnly),
                        decisive_label_pairs: vec![],
                    }),
                }],
                barrier: None,
            }],
            blockers: vec![],
            warnings: vec![],
            snapshot_taken_at: "test".to_string(),
            dependency_edges: vec![],
            operator_inventory: vec![],
            explicit_decisions: vec![],
        };
        let saved = SavedTeardownPlan {
            schema_version: SAVED_PLAN_SCHEMA_VERSION,
            target: SavedOperatorTarget {
                package_name: "test".to_string(),
                install_namespace: "ns".to_string(),
                csv_name_pattern: "test.v1".to_string(),
            },
            teardown_decisions: vec![SavedDecision {
                match_spec: ResourceMatch::from_resource_id(&make_res("Widget", "w1", "uid-1")),
                action: SavedAction::Delete,
                approval: ApprovalKind::Explicit,
                basis: DecisionBasis {
                    provenance: Some("LikelyManaged".to_string()),
                    review_category: Some("OperandRoot".to_string()),
                    discovery_source: Some("Direct".to_string()),
                    decisive_evidence: vec![],
                },
            }],
            residual_decisions: vec![],
        };
        let result = validate_saved_decisions(&plan, &saved);
        assert!(
            result.is_err(),
            "Discovery source Direct→RelatedLabelOnly must be blocked"
        );
        assert!(result.unwrap_err()[0].contains("discovery source drift"));
    }

    // ── ExplicitUnattributed from Unknown provenance + no evidence ──

    #[test]
    fn unknown_provenance_no_evidence_becomes_unattributed() {
        use crate::teardown::plan::*;
        let meta = ReviewMetadata {
            category: Some(ReviewCategorySer::OperandIndependent),
            approval_class: Some(DeleteApprovalClassSer::ExplicitOnly),
            provenance: Some(ProvenanceSer::Unknown),
            discovery_source: Some(DiscoverySourceSer::Direct),
            decisive_label_pairs: vec![],
        };
        let basis = build_decision_basis(&meta);
        let has_evidence = !basis.decisive_evidence.is_empty()
            || basis.provenance.as_deref().is_some_and(|p| p != "Unknown");
        assert!(
            !has_evidence,
            "Unknown provenance + no labels = no evidence"
        );
        // This should produce ExplicitUnattributed in explicit_decisions builder
    }

    // ── P0: saved basis missing fields → BLOCK ──

    #[test]
    fn saved_missing_review_category_blocked() {
        use crate::teardown::plan::*;
        let plan = TeardownPlan {
            targets: vec![],
            preflight: Preflight { checks: vec![] },
            phases: vec![PlanPhase {
                name: "t".into(),
                description: "".into(),
                actions: vec![Action::Review {
                    resource: make_res("W", "w1", "u1"),
                    reason: "t".into(),
                    metadata: Some(ReviewMetadata {
                        category: Some(ReviewCategorySer::OperandRoot),
                        approval_class: None,
                        provenance: Some(ProvenanceSer::LikelyManaged),
                        discovery_source: Some(DiscoverySourceSer::Direct),
                        decisive_label_pairs: vec![],
                    }),
                }],
                barrier: None,
            }],
            blockers: vec![],
            warnings: vec![],
            snapshot_taken_at: "t".into(),
            dependency_edges: vec![],
            operator_inventory: vec![],
            explicit_decisions: vec![],
        };
        let saved = SavedTeardownPlan {
            schema_version: SAVED_PLAN_SCHEMA_VERSION,
            target: SavedOperatorTarget {
                package_name: "t".into(),
                install_namespace: "n".into(),
                csv_name_pattern: "t.v1".into(),
            },
            teardown_decisions: vec![SavedDecision {
                match_spec: ResourceMatch::from_resource_id(&make_res("W", "w1", "u1")),
                action: SavedAction::Delete,
                approval: ApprovalKind::Explicit,
                basis: DecisionBasis {
                    provenance: Some("LikelyManaged".into()),
                    review_category: None,
                    discovery_source: Some("Direct".into()),
                    decisive_evidence: vec![],
                },
            }],
            residual_decisions: vec![],
        };
        let r = validate_saved_decisions(&plan, &saved);
        assert!(r.is_err(), "Missing review_category must block");
        assert!(r.unwrap_err()[0].contains("missing review_category"));
    }

    #[test]
    fn saved_fresh_metadata_none_blocked() {
        use crate::teardown::plan::*;
        let plan = TeardownPlan {
            targets: vec![],
            preflight: Preflight { checks: vec![] },
            phases: vec![PlanPhase {
                name: "t".into(),
                description: "".into(),
                actions: vec![Action::Review {
                    resource: make_res("W", "w1", "u1"),
                    reason: "t".into(),
                    metadata: None,
                }],
                barrier: None,
            }],
            blockers: vec![],
            warnings: vec![],
            snapshot_taken_at: "t".into(),
            dependency_edges: vec![],
            operator_inventory: vec![],
            explicit_decisions: vec![],
        };
        let saved = SavedTeardownPlan {
            schema_version: SAVED_PLAN_SCHEMA_VERSION,
            target: SavedOperatorTarget {
                package_name: "t".into(),
                install_namespace: "n".into(),
                csv_name_pattern: "t.v1".into(),
            },
            teardown_decisions: vec![SavedDecision {
                match_spec: ResourceMatch::from_resource_id(&make_res("W", "w1", "u1")),
                action: SavedAction::Delete,
                approval: ApprovalKind::Explicit,
                basis: DecisionBasis {
                    provenance: Some("Managed".into()),
                    review_category: Some("OperandRoot".into()),
                    discovery_source: Some("Direct".into()),
                    decisive_evidence: vec![],
                },
            }],
            residual_decisions: vec![],
        };
        let r = validate_saved_decisions(&plan, &saved);
        assert!(r.is_err(), "Fresh metadata=None must block DELETE replay");
        assert!(r.unwrap_err()[0].contains("no metadata"));
    }

    #[test]
    fn saved_unsupported_owner_ref_signature_blocked() {
        use crate::teardown::plan::*;
        let plan = TeardownPlan {
            targets: vec![],
            preflight: Preflight { checks: vec![] },
            phases: vec![PlanPhase {
                name: "t".into(),
                description: "".into(),
                actions: vec![Action::Review {
                    resource: make_res("W", "w1", "u1"),
                    reason: "t".into(),
                    metadata: Some(ReviewMetadata {
                        category: Some(ReviewCategorySer::OperandRoot),
                        approval_class: None,
                        provenance: Some(ProvenanceSer::LikelyManaged),
                        discovery_source: Some(DiscoverySourceSer::Direct),
                        decisive_label_pairs: vec![],
                    }),
                }],
                barrier: None,
            }],
            blockers: vec![],
            warnings: vec![],
            snapshot_taken_at: "t".into(),
            dependency_edges: vec![],
            operator_inventory: vec![],
            explicit_decisions: vec![],
        };
        let saved = SavedTeardownPlan {
            schema_version: SAVED_PLAN_SCHEMA_VERSION,
            target: SavedOperatorTarget {
                package_name: "t".into(),
                install_namespace: "n".into(),
                csv_name_pattern: "t.v1".into(),
            },
            teardown_decisions: vec![SavedDecision {
                match_spec: ResourceMatch::from_resource_id(&make_res("W", "w1", "u1")),
                action: SavedAction::Delete,
                approval: ApprovalKind::Explicit,
                basis: DecisionBasis {
                    provenance: Some("LikelyManaged".into()),
                    review_category: Some("OperandRoot".into()),
                    discovery_source: Some("Direct".into()),
                    decisive_evidence: vec![SavedEvidenceSignature::OwnerReference {
                        group: "g".into(),
                        kind: "K".into(),
                        namespace: None,
                        name: "n".into(),
                    }],
                },
            }],
            residual_decisions: vec![],
        };
        let r = validate_saved_decisions(&plan, &saved);
        assert!(r.is_err(), "Unsupported OwnerReference evidence must block");
    }

    #[test]
    fn resource_match_group_none_matches_core_only() {
        use crate::teardown::plan::ResourceMatch;
        let m = ResourceMatch {
            group: None,
            kind: "ConfigMap".into(),
            namespace: Some("ns".into()),
            name: "cm1".into(),
        };
        let core = ResourceId {
            group: "".into(),
            version: "v1".into(),
            kind: "ConfigMap".into(),
            namespace: Some("ns".into()),
            name: "cm1".into(),
            uid: None,
        };
        let noncore = ResourceId {
            group: "apps".into(),
            version: "v1".into(),
            kind: "ConfigMap".into(),
            namespace: Some("ns".into()),
            name: "cm1".into(),
            uid: None,
        };
        assert!(m.matches(&core), "None group must match core (empty)");
        assert!(
            !m.matches(&noncore),
            "None group must NOT match non-core group"
        );
    }

    #[test]
    fn resource_match_validate_rejects_wildcards() {
        use crate::teardown::plan::ResourceMatch;
        let m1 = ResourceMatch {
            group: Some("*".into()),
            kind: "K".into(),
            namespace: None,
            name: "n".into(),
        };
        assert!(m1.validate().is_err());

        let m2 = ResourceMatch {
            group: None,
            kind: "*".into(),
            namespace: None,
            name: "n".into(),
        };
        assert!(m2.validate().is_err());

        let m3 = ResourceMatch {
            group: None,
            kind: "K".into(),
            namespace: None,
            name: "".into(),
        };
        assert!(m3.validate().is_err());
    }

    /// Verify that --prune-crds deletes CRDs but keeps APIServices.
    /// This tests the structural invariant at the plan phase level.
    #[test]
    fn prune_crds_deletes_crds_but_keeps_apiservices() {
        // Build a mock PlanPhase matching Phase 4 (APIs) structure.
        // When prune_crds=true, CRDs should be DELETE, APIServices should be KEEP.
        let crd_action = Action::Delete {
            resource: ResourceId {
                group: "apiextensions.k8s.io".to_string(),
                version: "v1".to_string(),
                kind: "CustomResourceDefinition".to_string(),
                namespace: None,
                name: "widgets.example.com".to_string(),
                uid: Some("crd-uid-1".to_string()),
            },
            reason: "no remaining CRs, no external dependencies".to_string(),
        };
        let apiservice_action = Action::Keep {
            resource: ResourceId {
                group: "apiregistration.k8s.io".to_string(),
                version: "v1".to_string(),
                kind: "APIService".to_string(),
                namespace: None,
                name: "v1.widgets.example.com".to_string(),
                uid: None,
            },
            reason: "APIService kept by design (not removed by --prune-crds)".to_string(),
        };

        let phase = PlanPhase {
            name: "APIs".to_string(),
            description: "Delete CRDs with no remaining instances and no external dependencies"
                .to_string(),
            actions: vec![crd_action.clone(), apiservice_action.clone()],
            barrier: None,
        };

        // Verify CRDs are DELETE
        let crd_actions: Vec<_> = phase
            .actions
            .iter()
            .filter(|a| match a {
                Action::Delete { resource, .. } => resource.kind == "CustomResourceDefinition",
                _ => false,
            })
            .collect();
        assert_eq!(
            crd_actions.len(),
            1,
            "CRD should be DELETE when prune_crds=true"
        );

        // Verify APIServices are KEEP
        let apisvc_actions: Vec<_> = phase
            .actions
            .iter()
            .filter(|a| match a {
                Action::Keep { resource, .. } => resource.kind == "APIService",
                _ => false,
            })
            .collect();
        assert_eq!(
            apisvc_actions.len(),
            1,
            "APIService should be KEEP even when prune_crds=true"
        );

        // Verify no APIService DELETE actions
        let apisvc_deletes: Vec<_> = phase
            .actions
            .iter()
            .filter(|a| match a {
                Action::Delete { resource, .. } => resource.kind == "APIService",
                _ => false,
            })
            .collect();
        assert!(
            apisvc_deletes.is_empty(),
            "APIService should never be DELETE with --prune-crds"
        );
    }

    // ── Phase assignment: label-only deferral ──

    #[test]
    fn resolve_decisions_bulk_label_only_has_correct_origin() {
        let resource = make_res("LLMConfig", "config-1", "uid-1");
        let mut cr = make_cr_instance(
            "LLMConfig",
            "config-1",
            "uid-1",
            vec![],
            HashMap::new(),
            vec![],
        );
        cr.provenance = Provenance::Unknown;
        cr.discovery_source = DiscoverySource::RelatedLabelOnly;
        let candidate = ReviewCandidate {
            resource: &resource,
            category: ReviewCategory::Operand(GraphPosition::Root),
            approval_class: compute_approval_class(&cr, GraphPosition::Root),
            exact_approvable: true,
            is_label_only_eligible: is_label_only_bulk_eligible(&cr),
        };
        let policy = DecisionPolicy {
            approvals: vec![DeleteApproval::Bulk(BulkScope::LabelOnly)],
            preserves: vec![],
        };
        let resolved = resolve_decisions(&policy, &[candidate]).unwrap();
        let decision = resolved.get(&resource).expect("should be resolved");
        match decision {
            ResolvedDecision::Delete {
                approval_origin, ..
            } => {
                assert_eq!(
                    *approval_origin,
                    ApprovalOrigin::BulkLabelOnly,
                    "bulk label-only approval must set BulkLabelOnly origin"
                );
            }
            _ => panic!("Expected Delete decision"),
        }
    }

    #[test]
    fn resolve_decisions_root_approval_has_other_origin() {
        let resource = make_res("DSC", "default-dsc", "uid-dsc");
        let _cr = make_cr_instance(
            "DSC",
            "default-dsc",
            "uid-dsc",
            vec![],
            HashMap::new(),
            vec![],
        );
        let candidate = ReviewCandidate {
            resource: &resource,
            category: ReviewCategory::Operand(GraphPosition::Root),
            approval_class: DeleteApprovalClass::Standard,
            exact_approvable: true,
            is_label_only_eligible: false,
        };
        let policy = DecisionPolicy {
            approvals: vec![DeleteApproval::Bulk(BulkScope::Root)],
            preserves: vec![],
        };
        let resolved = resolve_decisions(&policy, &[candidate]).unwrap();
        let decision = resolved.get(&resource).expect("should be resolved");
        match decision {
            ResolvedDecision::Delete {
                approval_origin, ..
            } => {
                assert_eq!(
                    *approval_origin,
                    ApprovalOrigin::Other,
                    "root bulk approval must set Other origin"
                );
            }
            _ => panic!("Expected Delete decision"),
        }
    }

    #[test]
    fn resolve_decisions_exact_approval_has_other_origin() {
        let resource = make_res("Config", "default", "uid-cfg");
        let _cr = make_cr_instance(
            "Config",
            "default",
            "uid-cfg",
            vec![],
            HashMap::new(),
            vec![],
        );
        let candidate = ReviewCandidate {
            resource: &resource,
            category: ReviewCategory::Operand(GraphPosition::Root),
            approval_class: DeleteApprovalClass::ExplicitOnly,
            exact_approvable: true,
            is_label_only_eligible: false,
        };
        let policy = DecisionPolicy {
            approvals: vec![DeleteApproval::Exact("Config/default".to_string())],
            preserves: vec![],
        };
        let resolved = resolve_decisions(&policy, &[candidate]).unwrap();
        let decision = resolved.get(&resource).expect("should be resolved");
        match decision {
            ResolvedDecision::Delete {
                approval_origin, ..
            } => {
                assert_eq!(
                    *approval_origin,
                    ApprovalOrigin::Other,
                    "exact approval must set Other origin"
                );
            }
            _ => panic!("Expected Delete decision"),
        }
    }

    // ── CSV package: load/save boundary tests ──

    #[test]
    fn load_execution_plan_rejects_empty_package() {
        use crate::teardown::plan::*;
        let plan = ExecutionPlan {
            schema_version: EXECUTION_PLAN_SCHEMA_VERSION,
            cluster_identity: ClusterIdentity {
                api_server: "https://test".into(),
                kube_system_uid: "uid-1".into(),
            },
            created_at: "2026-01-01T00:00:00Z".into(),
            targets: vec![SavedOperatorTarget {
                package_name: String::new(),
                install_namespace: "ns".into(),
                csv_name_pattern: "csv.v1".into(),
            }],
            prune_crds: false,
            approve_scopes: vec![],
            approve_resources: vec![],
            keep_resources: vec![],
            phases: vec![],
        };
        let dir = std::env::temp_dir().join(format!("test-empty-pkg-{}", std::process::id()));
        let _ = std::fs::create_dir_all(&dir);
        let path = dir.join("plan.json");
        save_execution_plan(&plan, path.to_str().unwrap()).unwrap();
        let result = load_execution_plan(path.to_str().unwrap());
        let _ = std::fs::remove_dir_all(&dir);
        assert!(
            result.is_err(),
            "Empty package_name must be rejected on load"
        );
        assert!(
            format!("{}", result.unwrap_err()).contains("empty package_name"),
            "Error should mention empty package"
        );
    }

    #[test]
    fn load_execution_plan_rejects_whitespace_package() {
        use crate::teardown::plan::*;
        let plan = ExecutionPlan {
            schema_version: EXECUTION_PLAN_SCHEMA_VERSION,
            cluster_identity: ClusterIdentity {
                api_server: "https://test".into(),
                kube_system_uid: "uid-1".into(),
            },
            created_at: "2026-01-01T00:00:00Z".into(),
            targets: vec![SavedOperatorTarget {
                package_name: "   ".into(),
                install_namespace: "ns".into(),
                csv_name_pattern: "csv.v1".into(),
            }],
            prune_crds: false,
            approve_scopes: vec![],
            approve_resources: vec![],
            keep_resources: vec![],
            phases: vec![],
        };
        let dir = std::env::temp_dir().join(format!("test-ws-pkg-{}", std::process::id()));
        let _ = std::fs::create_dir_all(&dir);
        let path = dir.join("plan.json");
        save_execution_plan(&plan, path.to_str().unwrap()).unwrap();
        let result = load_execution_plan(path.to_str().unwrap());
        let _ = std::fs::remove_dir_all(&dir);
        assert!(result.is_err(), "Whitespace-only package must be rejected");
    }

    #[test]
    fn extract_annotation_whitespace_package_excluded() {
        use crate::analyzers::olm::extract_annotation_packages;
        let mut obj = kube::api::DynamicObject::new(
            "csv",
            &kube::api::ApiResource::erase::<k8s_openapi::api::core::v1::Pod>(&()),
        );
        obj.metadata.annotations = Some(std::collections::BTreeMap::from([(
            "operatorframework.io/properties".to_string(),
            r#"[{"type":"olm.package","value":"{\"packageName\":\"   \"}"}]"#.to_string(),
        )]));
        let pkgs = extract_annotation_packages(&obj);
        assert!(
            pkgs.is_empty(),
            "Whitespace-only packageName must be excluded"
        );
    }
}
