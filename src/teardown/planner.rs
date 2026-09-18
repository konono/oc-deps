use std::collections::{HashMap, HashSet};

use anyhow::{Result, bail};
use kube::{
    Client,
    api::{Api, ApiResource, DynamicObject, ListParams},
    core::GroupVersion,
};
use serde::{Deserialize, Serialize};

use crate::analyzers::olm::OperatorInstance;
use crate::cli::OutputFormat;
use crate::kube::discovery::{GvrMap, KindMap};
use crate::kube::resource::ResourceId;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TeardownPlan {
    pub targets: Vec<OperatorTarget>,
    pub preflight: Preflight,
    pub phases: Vec<PlanPhase>,
    pub blockers: Vec<Blocker>,
    pub warnings: Vec<Warning>,
    pub snapshot_taken_at: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Preflight {
    pub checks: Vec<PreflightCheck>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PreflightCheck {
    pub name: String,
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
enum Provenance {
    Managed,
    LikelyManaged,
    Unknown,
}

struct CrInstance {
    id: ResourceId,
    owner_refs: Vec<(String, String, String)>, // (kind, name, uid)
    #[allow(dead_code)]
    crd_name: String,
    labels: HashMap<String, String>,
    managed_field_managers: Vec<String>,
    provenance: Provenance,
}

pub fn resolve_operator_targets(
    queries: &[String],
    operators: &[OperatorInstance],
) -> Result<Vec<usize>> {
    let mut indices = Vec::new();
    for query in queries {
        let q = query.to_lowercase();
        let mut found = None;
        for (i, op) in operators.iter().enumerate() {
            let csv_lower = op.csv.name.to_lowercase();
            let sub_lower = op
                .subscription
                .as_ref()
                .map(|s| s.name.to_lowercase())
                .unwrap_or_default();
            if csv_lower == q || sub_lower == q {
                found = Some(i);
                break;
            }
        }
        if found.is_none() {
            for (i, op) in operators.iter().enumerate() {
                let csv_lower = op.csv.name.to_lowercase();
                let sub_lower = op
                    .subscription
                    .as_ref()
                    .map(|s| s.name.to_lowercase())
                    .unwrap_or_default();
                if csv_lower.contains(&q) || sub_lower.contains(&q) {
                    if found.is_some() {
                        let mut candidates: Vec<String> = operators
                            .iter()
                            .filter(|o| {
                                let c = o.csv.name.to_lowercase();
                                let s = o
                                    .subscription
                                    .as_ref()
                                    .map(|s| s.name.to_lowercase())
                                    .unwrap_or_default();
                                c.contains(&q) || s.contains(&q)
                            })
                            .map(|o| o.csv.name.clone())
                            .collect();
                        candidates.sort();
                        bail!(
                            "Ambiguous operator '{}'. Candidates: {}",
                            query,
                            candidates.join(", ")
                        );
                    }
                    found = Some(i);
                }
            }
        }
        match found {
            Some(i) => {
                if !indices.contains(&i) {
                    indices.push(i);
                }
            }
            None => {
                bail!(
                    "Operator '{}' not found. Use `oc-deps operators` to list available operators.",
                    query
                );
            }
        }
    }
    Ok(indices)
}

async fn discover_cr_instances(
    client: &Client,
    target_crds: &[String],
    kind_map: &KindMap,
    gvr_map: &GvrMap,
) -> (Vec<CrInstance>, usize) {
    let mut instances = Vec::new();
    let mut total_observations: usize = 0;

    for crd_name in target_crds {
        let (plural, group) = match crd_name.split_once('.') {
            Some((p, g)) => (p, g),
            None => continue,
        };

        let gvr_key = format!("{}.{}", plural, group).to_lowercase();
        let kind = match gvr_map.get(&gvr_key) {
            Some(k) => k.clone(),
            None => continue,
        };

        let kind_info = match kind_map.get(&kind) {
            Some(i) => i,
            None => continue,
        };

        let gvk = GroupVersion::gv(&kind_info.group, &kind_info.version).with_kind(&kind);
        let ar = ApiResource::from_gvk_with_plural(&gvk, &kind_info.plural);
        let api: Api<DynamicObject> = Api::all_with(client.clone(), &ar);

        let items = match list_paginated(&api).await {
            Ok(items) => items,
            Err(_) => continue,
        };

        for obj in items {
            total_observations += 1;
            let uid = obj.metadata.uid.unwrap_or_default();
            let name = match obj.metadata.name {
                Some(n) => n,
                None => continue,
            };
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

            instances.push(CrInstance {
                id: ResourceId {
                    group: kind_info.group.clone(),
                    version: kind_info.version.clone(),
                    kind: kind.clone(),
                    namespace: ns,
                    name,
                    uid: Some(uid),
                },
                owner_refs,
                crd_name: crd_name.clone(),
                labels,
                managed_field_managers,
                provenance: Provenance::Unknown, // classified later
            });
        }
    }

    // UID-based dedup
    let pre_dedup = instances.len();
    let mut seen_uids = HashSet::new();
    instances.retain(|cr| {
        if let Some(uid) = &cr.id.uid {
            seen_uids.insert(uid.clone())
        } else {
            true
        }
    });
    let duplicates = pre_dedup - instances.len();
    let _ = duplicates; // used in caller for warnings

    (instances, total_observations)
}

fn classify_provenance(cr: &mut CrInstance, operators: &[&OperatorInstance]) {
    // ownerRef pointing to operator's CSV or Deployment → Managed
    for (ref_kind, ref_name, _) in &cr.owner_refs {
        for op in operators {
            if ref_kind == "ClusterServiceVersion" && ref_name == &op.csv.name {
                cr.provenance = Provenance::Managed;
                return;
            }
            for deploy in &op.deployments {
                if ref_kind == "Deployment" && ref_name == deploy {
                    cr.provenance = Provenance::Managed;
                    return;
                }
            }
        }
    }

    // Operator-related labels → Managed
    for key in cr.labels.keys() {
        for op in operators {
            let csv_prefix = op.csv.name.split('.').next().unwrap_or("");
            if !csv_prefix.is_empty()
                && (key.contains(csv_prefix)
                    || key.contains("opendatahub")
                    || key.contains("app.kubernetes.io/part-of"))
            {
                cr.provenance = Provenance::Managed;
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

async fn list_paginated(api: &Api<DynamicObject>) -> Result<Vec<DynamicObject>> {
    let mut all_items = Vec::new();
    let mut continue_token: Option<String> = None;

    loop {
        let mut lp = ListParams::default().limit(100);
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

async fn run_preflight(
    client: &Client,
    target_operators: &[&OperatorInstance],
    kind_map: &KindMap,
    total_observations: usize,
    unique_count: usize,
    unknown_provenance_count: usize,
) -> Preflight {
    let mut checks = Vec::new();

    // 1. Subscription resolved
    for op in target_operators {
        let (passed, detail) = match &op.subscription {
            Some(sub) => (true, format!("Subscription/{} found", sub.name)),
            None => (false, format!("No subscription for CSV/{}", op.csv.name)),
        };
        checks.push(PreflightCheck {
            name: format!("Subscription resolved ({})", op.csv.name),
            passed,
            detail,
        });
    }

    // 2. CSV status and controller health
    for op in target_operators {
        let csv_ok = check_csv_health(client, op, kind_map).await;
        checks.push(PreflightCheck {
            name: format!("CSV health ({})", op.csv.name),
            passed: csv_ok.0,
            detail: csv_ok.1,
        });

        let ctrl_ok = check_controller_health(client, op, kind_map).await;
        checks.push(PreflightCheck {
            name: format!("Controller available ({})", op.csv.name),
            passed: ctrl_ok.0,
            detail: ctrl_ok.1,
        });
    }

    // 3. Dedup summary
    if total_observations != unique_count {
        checks.push(PreflightCheck {
            name: "CR dedup".to_string(),
            passed: true,
            detail: format!(
                "{} observations normalized to {} unique CRs",
                total_observations, unique_count
            ),
        });
    }

    // 4. Uncertain provenance
    if unknown_provenance_count > 0 {
        checks.push(PreflightCheck {
            name: "Provenance".to_string(),
            passed: false,
            detail: format!(
                "{} CRs have uncertain provenance (marked as REVIEW)",
                unknown_provenance_count
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

pub async fn generate_teardown_plan(
    client: &Client,
    target_operators: &[&OperatorInstance],
    all_operators: &[OperatorInstance],
    kind_map: &KindMap,
    gvr_map: &GvrMap,
    prune_apis: bool,
) -> Result<TeardownPlan> {
    let target_csv_names: HashSet<&str> = target_operators
        .iter()
        .map(|op| op.csv.name.as_str())
        .collect();

    let targets: Vec<OperatorTarget> = target_operators
        .iter()
        .map(|op| OperatorTarget {
            subscription: op.subscription.clone(),
            csv: op.csv.clone(),
            install_namespace: op.install_namespace.clone(),
        })
        .collect();

    let target_crds: Vec<String> = target_operators
        .iter()
        .flat_map(|op| op.owned_crds.iter().cloned())
        .collect();
    let target_crd_set: HashSet<&str> = target_crds.iter().map(|s| s.as_str()).collect();

    eprint!("🔍 Discovering CR instances...");
    let (mut cr_instances, total_observations) =
        discover_cr_instances(client, &target_crds, kind_map, gvr_map).await;
    let unique_count = cr_instances.len();
    let duplicates = total_observations - unique_count;
    eprintln!(
        " found {} instances ({} observations)",
        unique_count, total_observations
    );

    // Classify provenance
    for cr in &mut cr_instances {
        classify_provenance(cr, target_operators);
    }

    let unknown_provenance_count = cr_instances
        .iter()
        .filter(|cr| matches!(cr.provenance, Provenance::Unknown))
        .count();

    // Run preflight checks
    eprint!("🔍 Running preflight checks...");
    let preflight = run_preflight(
        client,
        target_operators,
        kind_map,
        total_observations,
        unique_count,
        unknown_provenance_count,
    )
    .await;
    eprintln!(" done");

    // Determine root vs managed CRs
    // Root CRs: have no ownerRef pointing to another target CR, or are ownerRef targets of other CRs
    let cr_uids: HashSet<String> = cr_instances
        .iter()
        .filter_map(|cr| cr.id.uid.clone())
        .collect();

    // UIDs that are referenced as owners by other CRs
    let parent_uids: HashSet<String> = cr_instances
        .iter()
        .flat_map(|cr| cr.owner_refs.iter().map(|(_, _, uid)| uid.clone()))
        .filter(|uid| cr_uids.contains(uid))
        .collect();

    // Root CRs: those that ARE parents of other target CRs, or have no ownerRef to target CRs
    // Managed descendants: those whose ownerRef points to a root CR
    let mut root_crs: Vec<&CrInstance> = Vec::new();
    let mut managed_descendants: Vec<&CrInstance> = Vec::new();
    let mut independent_crs: Vec<&CrInstance> = Vec::new();

    for cr in &cr_instances {
        let uid = cr.id.uid.as_deref().unwrap_or("");
        let is_parent = parent_uids.contains(uid);
        let has_parent_in_set = cr
            .owner_refs
            .iter()
            .any(|(_, _, ouid)| cr_uids.contains(ouid));

        if is_parent {
            root_crs.push(cr);
        } else if has_parent_in_set {
            managed_descendants.push(cr);
        } else {
            independent_crs.push(cr);
        }
    }

    // Check for blockers
    let mut blockers = Vec::new();
    let mut warnings = Vec::new();

    for op in all_operators {
        if target_csv_names.contains(op.csv.name.as_str()) {
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

    if unknown_provenance_count > 0 {
        warnings.push(Warning {
            message: format!(
                "{} CRs have uncertain provenance (owned API, but origin unknown)",
                unknown_provenance_count
            ),
            resource: None,
        });
    }

    let blocked_crds: HashSet<&str> = blockers.iter().map(|b| b.resource.name.as_str()).collect();
    let warned_crds: HashSet<&str> = warnings
        .iter()
        .filter_map(|w| w.resource.as_ref().map(|r| r.name.as_str()))
        .collect();

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

    // ── Phase 1: Trigger operand cleanup ──
    let mut phase1_actions: Vec<Action> = Vec::new();

    // DELETE root CRs (these trigger controller cleanup of descendants)
    for cr in &root_crs {
        phase1_actions.push(Action::Delete {
            resource: cr.id.clone(),
            reason: "root management CR".to_string(),
        });
    }

    // EXPECT_GONE for managed descendants
    for cr in &managed_descendants {
        phase1_actions.push(Action::ExpectGone {
            resource: cr.id.clone(),
            reason: "managed descendant; controller expected to remove".to_string(),
        });
    }

    // Handle independent CRs based on provenance
    for cr in &independent_crs {
        match cr.provenance {
            Provenance::Managed | Provenance::LikelyManaged => {
                phase1_actions.push(Action::Delete {
                    resource: cr.id.clone(),
                    reason: format!("independent operand (provenance: {:?})", cr.provenance),
                });
            }
            Provenance::Unknown => {
                phase1_actions.push(Action::Review {
                    resource: cr.id.clone(),
                    reason: "owned API, but provenance unknown".to_string(),
                });
            }
        }
    }

    let phase1 = PlanPhase {
        name: "Trigger operand cleanup".to_string(),
        description:
            "Delete root CRs to trigger controller cleanup; expect managed descendants to vanish"
                .to_string(),
        actions: phase1_actions,
        barrier: Some(Barrier {
            description: "All operands removed (deleted + expected)".to_string(),
            conditions: {
                let mut conds: Vec<String> = root_crs
                    .iter()
                    .map(|cr| format!("{} is gone", cr.id))
                    .collect();
                conds.extend(
                    managed_descendants
                        .iter()
                        .map(|cr| format!("{} is gone (expected)", cr.id)),
                );
                conds
            },
        }),
    };

    // ── Phase 2: Remaining roots ──
    // (empty by design — Phase 1 should handle everything, but this phase catches stragglers)
    let phase2 = PlanPhase {
        name: "Remaining cleanup".to_string(),
        description: "Delete any CRs that were not cleaned up by controller".to_string(),
        actions: vec![],
        barrier: None,
    };

    // ── Phase 3: Remove Operator controllers ──
    let phase3_actions: Vec<Action> = target_operators
        .iter()
        .map(|op| Action::Delete {
            resource: op.csv.clone(),
            reason: "operator controller no longer needed".to_string(),
        })
        .collect();

    let phase3 = PlanPhase {
        name: "Remove Operator controllers".to_string(),
        description: "Delete CSVs (GC will remove controller Deployments)".to_string(),
        actions: phase3_actions,
        barrier: Some(Barrier {
            description: "All CSVs deleted".to_string(),
            conditions: target_operators
                .iter()
                .map(|op| format!("{} is gone", op.csv))
                .collect(),
        }),
    };

    // ── Phase 4: Remove unused APIs ──
    let mut phase4_actions = Vec::new();
    let mut seen_crds = HashSet::new();

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
        } else if prune_apis {
            phase4_actions.push(Action::Delete {
                resource: crd_id,
                reason: "no remaining CRs, no external dependencies".to_string(),
            });
        } else {
            phase4_actions.push(Action::Keep {
                resource: crd_id,
                reason: "eligible for prune (use --prune-apis to remove)".to_string(),
            });
        }
    }

    let phase4 = PlanPhase {
        name: "APIs".to_string(),
        description: if prune_apis {
            "Delete CRDs with no remaining instances and no external dependencies".to_string()
        } else {
            "CRDs kept by default — use --prune-apis for complete API removal".to_string()
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

    if !prune_apis {
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
                    "{} CRDs eligible for removal but kept by default (use --prune-apis)",
                    eligible
                ),
                resource: None,
            });
        }
    }

    let plan = TeardownPlan {
        targets,
        preflight,
        phases: vec![phase0, phase1, phase2, phase3, phase4, phase5],
        blockers,
        warnings,
        snapshot_taken_at: chrono::Utc::now().to_rfc3339(),
    };

    Ok(plan)
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
                Action::Review { resource, reason } => {
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
}

fn print_plan_json(plan: &TeardownPlan) {
    println!("{}", serde_json::to_string_pretty(plan).unwrap_or_default());
}
