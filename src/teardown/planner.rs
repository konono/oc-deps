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
    pub phases: Vec<PlanPhase>,
    pub blockers: Vec<Blocker>,
    pub warnings: Vec<Warning>,
    pub snapshot_taken_at: String,
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
    WaitGone {
        resource: ResourceId,
    },
    Keep {
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

struct CrInstance {
    id: ResourceId,
    owner_refs: Vec<(String, String, String)>, // (kind, name, uid)
    crd_name: String,
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
) -> Vec<CrInstance> {
    let mut instances = Vec::new();

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
            });
        }
    }

    instances
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

pub async fn generate_teardown_plan(
    client: &Client,
    target_operators: &[&OperatorInstance],
    all_operators: &[OperatorInstance],
    kind_map: &KindMap,
    gvr_map: &GvrMap,
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

    // Collect all owned CRDs from targets
    let target_crds: Vec<String> = target_operators
        .iter()
        .flat_map(|op| op.owned_crds.iter().cloned())
        .collect();
    let target_crd_set: HashSet<&str> = target_crds.iter().map(|s| s.as_str()).collect();

    // Discover CR instances across cluster
    eprint!("🔍 Discovering CR instances...");
    let cr_instances = discover_cr_instances(client, &target_crds, kind_map, gvr_map).await;
    eprintln!(" found {} instances", cr_instances.len());

    // Build uid set of all CRs to detect parent/leaf relationships
    let cr_uids: HashSet<String> = cr_instances
        .iter()
        .filter_map(|cr| cr.id.uid.clone())
        .collect();

    // Separate CRs into leaf (no CR children own them) and parent
    // A CR is a "leaf" if no other CR has an ownerRef pointing to it
    let cr_parent_uids: HashSet<String> = cr_instances
        .iter()
        .flat_map(|cr| cr.owner_refs.iter().map(|(_, _, uid)| uid.clone()))
        .filter(|uid| cr_uids.contains(uid))
        .collect();

    let mut leaf_crs: Vec<&CrInstance> = Vec::new();
    let mut parent_crs: Vec<&CrInstance> = Vec::new();

    for cr in &cr_instances {
        if let Some(uid) = &cr.id.uid {
            if cr_parent_uids.contains(uid) {
                parent_crs.push(cr);
            } else {
                leaf_crs.push(cr);
            }
        } else {
            leaf_crs.push(cr);
        }
    }

    // Sort parents topologically: children before parents
    parent_crs.sort_by(|a, b| {
        let a_is_parent_of_b = b
            .owner_refs
            .iter()
            .any(|(_, _, uid)| a.id.uid.as_ref().is_some_and(|a_uid| a_uid == uid));
        let b_is_parent_of_a = a
            .owner_refs
            .iter()
            .any(|(_, _, uid)| b.id.uid.as_ref().is_some_and(|b_uid| b_uid == uid));
        if a_is_parent_of_b {
            std::cmp::Ordering::Greater // a after b (parent after child)
        } else if b_is_parent_of_a {
            std::cmp::Ordering::Less
        } else {
            a.id.kind.cmp(&b.id.kind).then(a.id.name.cmp(&b.id.name))
        }
    });

    // Check for blockers: unselected operators that require target CRDs
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
        // Also check if unselected operators own a target CRD
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
    // Keep CSVs alive during operand cleanup
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
            description: "All Subscriptions deleted".to_string(),
            conditions: target_operators
                .iter()
                .filter_map(|op| op.subscription.as_ref().map(|s| format!("{} is gone", s)))
                .collect(),
        }),
    };

    // ── Phase 1: Remove leaf operands ──
    let phase1_actions: Vec<Action> = leaf_crs
        .iter()
        .map(|cr| Action::Delete {
            resource: cr.id.clone(),
            reason: format!("leaf CR of CRD {}", cr.crd_name),
        })
        .collect();

    let phase1 = PlanPhase {
        name: "Remove leaf operands".to_string(),
        description: "Delete CR instances that are not parents of other CRs".to_string(),
        actions: phase1_actions,
        barrier: Some(Barrier {
            description: "All leaf operands removed".to_string(),
            conditions: leaf_crs
                .iter()
                .map(|cr| format!("{} is gone", cr.id))
                .collect(),
        }),
    };

    // ── Phase 2: Remove parent operands ──
    let phase2_actions: Vec<Action> = parent_crs
        .iter()
        .map(|cr| Action::Delete {
            resource: cr.id.clone(),
            reason: format!("parent CR of CRD {}", cr.crd_name),
        })
        .collect();

    let phase2 = PlanPhase {
        name: "Remove parent operands".to_string(),
        description: "Delete CRs that own other CRs (children first)".to_string(),
        actions: phase2_actions,
        barrier: Some(Barrier {
            description: "All parent operands removed".to_string(),
            conditions: parent_crs
                .iter()
                .map(|cr| format!("{} is gone", cr.id))
                .collect(),
        }),
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
    // Count remaining CRs per CRD (after plan execution, should be 0)
    let cr_counts: HashMap<&str, usize> =
        cr_instances.iter().fold(HashMap::new(), |mut acc, cr| {
            *acc.entry(cr.crd_name.as_str()).or_insert(0) += 1;
            acc
        });

    let mut phase4_actions = Vec::new();
    for crd_name in &target_crds {
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
            let _count = cr_counts.get(crd_name.as_str()).copied().unwrap_or(0);
            phase4_actions.push(Action::Keep {
                resource: crd_id,
                reason: "also owned by another operator".to_string(),
            });
        } else {
            phase4_actions.push(Action::Delete {
                resource: crd_id,
                reason: "no remaining CRs, no external dependencies".to_string(),
            });
        }
    }

    // Dedup CRD actions (multiple operators may own the same CRD)
    let mut seen_crds = HashSet::new();
    phase4_actions.retain(|action| {
        let name = match action {
            Action::Delete { resource, .. } => &resource.name,
            Action::Keep { resource, .. } => &resource.name,
            Action::WaitGone { resource } => &resource.name,
        };
        seen_crds.insert(name.clone())
    });

    let phase4 = PlanPhase {
        name: "Remove unused APIs".to_string(),
        description: "Delete CRDs with no remaining instances and no external dependencies"
            .to_string(),
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
        name: "Remove empty namespaces".to_string(),
        description: "Namespaces are kept by default — verify manually before deleting".to_string(),
        actions: phase5_actions,
        barrier: None,
    };

    let plan = TeardownPlan {
        targets,
        phases: vec![phase0, phase1, phase2, phase3, phase4, phase5],
        blockers,
        warnings,
        snapshot_taken_at: chrono::Utc::now().to_rfc3339(),
    };

    Ok(plan)
}

pub fn print_teardown_plan(plan: &TeardownPlan, output: &OutputFormat) {
    match output {
        OutputFormat::Tree => print_plan_tree(plan),
        OutputFormat::Table => print_plan_tree(plan), // table not particularly useful for plans
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

    for (i, phase) in plan.phases.iter().enumerate() {
        println!("\n\x1b[1mPhase {}  {}\x1b[0m", i, phase.name);

        if phase.actions.is_empty() {
            println!("  (none)");
            continue;
        }

        for action in &phase.actions {
            match action {
                Action::Delete { resource, reason } => {
                    let ns_suffix = resource
                        .namespace
                        .as_ref()
                        .map(|ns| format!("  \x1b[2m(ns: {})\x1b[0m", ns))
                        .unwrap_or_default();
                    println!(
                        "  \x1b[31mDELETE\x1b[0m {}/{}{}",
                        resource.kind, resource.name, ns_suffix
                    );
                    println!("         \x1b[2m{}\x1b[0m", reason);
                }
                Action::Keep { resource, reason } => {
                    println!(
                        "  \x1b[32mKEEP  \x1b[0m {}/{}",
                        resource.kind, resource.name
                    );
                    println!("         \x1b[2m{}\x1b[0m", reason);
                }
                Action::WaitGone { resource } => {
                    println!(
                        "  \x1b[33mWAIT  \x1b[0m {}/{}",
                        resource.kind, resource.name
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
    let delete_count = plan
        .phases
        .iter()
        .flat_map(|p| &p.actions)
        .filter(|a| matches!(a, Action::Delete { .. }))
        .count();
    let keep_count = plan
        .phases
        .iter()
        .flat_map(|p| &p.actions)
        .filter(|a| matches!(a, Action::Keep { .. }))
        .count();
    println!(
        "\n\x1b[1mSummary\x1b[0m: {} DELETE, {} KEEP, {} blockers, {} warnings",
        delete_count,
        keep_count,
        plan.blockers.len(),
        plan.warnings.len()
    );
}

fn print_plan_json(plan: &TeardownPlan) {
    println!("{}", serde_json::to_string_pretty(plan).unwrap_or_default());
}
