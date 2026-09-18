use std::collections::HashSet;

use kube::{
    Client,
    api::{Api, ApiResource, DynamicObject},
    core::GroupVersion,
};
use serde::{Deserialize, Serialize};

use crate::kube::discovery::KindMap;
use crate::kube::resource::ResourceId;
use crate::teardown::planner::{Action, TeardownPlan};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum ProgressState {
    Exists,
    HasFinalizers,
    Deleting,
    Gone,
    Unknown,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ResourceStatus {
    pub resource: ResourceId,
    pub state: ProgressState,
    pub finalizers: Vec<String>,
    pub deletion_timestamp: Option<String>,
    pub controller_available: Option<bool>,
    pub is_keep: bool,
}

pub async fn check_plan_status(
    client: &Client,
    plan: &TeardownPlan,
    kind_map: &KindMap,
) -> Vec<Vec<ResourceStatus>> {
    let mut phase_statuses = Vec::new();

    let controller_deployments: HashSet<String> =
        plan.targets.iter().map(|t| t.csv.name.clone()).collect();

    for phase in &plan.phases {
        let mut statuses = Vec::new();
        let mut seen = HashSet::new();

        for action in &phase.actions {
            let (resource, is_keep) = match action {
                Action::Delete { resource, .. } => (resource, false),
                Action::ExpectGone { resource, .. } => (resource, false),
                Action::Keep { resource, .. } => (resource, true),
                Action::Review { resource, .. } => (resource, true),
                Action::WaitGone { resource } => (resource, false),
            };

            let key = format!(
                "{}/{}@{}",
                resource.kind,
                resource.name,
                resource.namespace.as_deref().unwrap_or("-")
            );
            if !seen.insert(key) {
                continue;
            }

            let status = check_resource(client, resource, kind_map, is_keep).await;

            let status = if matches!(status.state, ProgressState::Deleting)
                && !status.finalizers.is_empty()
            {
                let controller_ok =
                    check_controller_available(client, &controller_deployments, plan, kind_map)
                        .await;
                ResourceStatus {
                    controller_available: Some(controller_ok),
                    ..status
                }
            } else {
                status
            };

            statuses.push(status);
        }

        phase_statuses.push(statuses);
    }

    phase_statuses
}

async fn check_resource(
    client: &Client,
    resource: &ResourceId,
    kind_map: &KindMap,
    is_keep: bool,
) -> ResourceStatus {
    let kind_info = match kind_map.get(&resource.kind) {
        Some(i) => i,
        None => {
            return ResourceStatus {
                resource: resource.clone(),
                state: ProgressState::Unknown,
                finalizers: vec![],
                deletion_timestamp: None,
                controller_available: None,
                is_keep,
            };
        }
    };

    let gvk = GroupVersion::gv(&kind_info.group, &kind_info.version).with_kind(&resource.kind);
    let ar = ApiResource::from_gvk_with_plural(&gvk, &kind_info.plural);
    let api: Api<DynamicObject> = if let Some(ns) = &resource.namespace {
        Api::namespaced_with(client.clone(), ns, &ar)
    } else if kind_info.namespaced {
        return ResourceStatus {
            resource: resource.clone(),
            state: ProgressState::Unknown,
            finalizers: vec![],
            deletion_timestamp: None,
            controller_available: None,
            is_keep,
        };
    } else {
        Api::all_with(client.clone(), &ar)
    };

    match api.get(&resource.name).await {
        Ok(obj) => {
            let finalizers = obj.metadata.finalizers.clone().unwrap_or_default();
            let deletion_ts = obj
                .metadata
                .deletion_timestamp
                .as_ref()
                .map(|t| t.0.to_string());

            let state = if deletion_ts.is_some() {
                ProgressState::Deleting
            } else if !finalizers.is_empty() {
                ProgressState::HasFinalizers
            } else {
                ProgressState::Exists
            };

            ResourceStatus {
                resource: resource.clone(),
                state,
                finalizers,
                deletion_timestamp: deletion_ts,
                controller_available: None,
                is_keep,
            }
        }
        Err(kube::Error::Api(err)) if err.code == 404 => ResourceStatus {
            resource: resource.clone(),
            state: ProgressState::Gone,
            finalizers: vec![],
            deletion_timestamp: None,
            controller_available: None,
            is_keep,
        },
        Err(_) => ResourceStatus {
            resource: resource.clone(),
            state: ProgressState::Unknown,
            finalizers: vec![],
            deletion_timestamp: None,
            controller_available: None,
            is_keep,
        },
    }
}

async fn check_controller_available(
    client: &Client,
    _controller_csvs: &HashSet<String>,
    plan: &TeardownPlan,
    kind_map: &KindMap,
) -> bool {
    for target in &plan.targets {
        let csv_kind_info = match kind_map.get("ClusterServiceVersion") {
            Some(i) => i,
            None => return false,
        };
        let gvk = GroupVersion::gv(&csv_kind_info.group, &csv_kind_info.version)
            .with_kind("ClusterServiceVersion");
        let ar = ApiResource::from_gvk_with_plural(&gvk, &csv_kind_info.plural);
        let ns = &target.install_namespace;
        let api: Api<DynamicObject> = Api::namespaced_with(client.clone(), ns, &ar);

        match api.get(&target.csv.name).await {
            Ok(obj) => {
                let phase = obj
                    .data
                    .get("status")
                    .and_then(|s| s.get("phase"))
                    .and_then(|p| p.as_str())
                    .unwrap_or("");
                if phase != "Succeeded" {
                    return false;
                }
            }
            Err(_) => return false,
        }
    }
    true
}

pub fn print_plan_status(plan: &TeardownPlan, phase_statuses: &[Vec<ResourceStatus>]) {
    let mut total_exist = 0usize;
    let mut total_finalizers = 0usize;
    let mut total_deleting = 0usize;
    let mut total_gone = 0usize;
    let mut total_unknown = 0usize;
    let mut controller_ok = true;

    for (i, phase) in plan.phases.iter().enumerate() {
        println!("\n\x1b[1mPhase {}  {}\x1b[0m", i, phase.name);

        let statuses = match phase_statuses.get(i) {
            Some(s) => s,
            None => {
                println!("  (no status)");
                continue;
            }
        };

        if statuses.is_empty() {
            println!("  (none)");
            continue;
        }

        for status in statuses {
            let label = format!("{}/{}", status.resource.kind, status.resource.name);
            let ns_suffix = status
                .resource
                .namespace
                .as_ref()
                .map(|ns| format!("  \x1b[2m(ns: {})\x1b[0m", ns))
                .unwrap_or_default();
            let keep_marker = if status.is_keep { " (KEEP)" } else { "" };

            match &status.state {
                ProgressState::Exists => {
                    total_exist += 1;
                    println!(
                        "  \x1b[32mEXISTS   \x1b[0m {}{}{}",
                        label, keep_marker, ns_suffix
                    );
                }
                ProgressState::HasFinalizers => {
                    total_exist += 1;
                    total_finalizers += 1;
                    println!(
                        "  \x1b[33mEXISTS   \x1b[0m {}{}{}",
                        label, keep_marker, ns_suffix
                    );
                    println!("           finalizers: [{}]", status.finalizers.join(", "));
                }
                ProgressState::Deleting => {
                    total_deleting += 1;
                    if !status.finalizers.is_empty() {
                        total_finalizers += 1;
                    }
                    println!(
                        "  \x1b[1;31mDELETING \x1b[0m {}{}{}",
                        label, keep_marker, ns_suffix
                    );
                    if !status.finalizers.is_empty() {
                        println!("           finalizers: [{}]", status.finalizers.join(", "));
                    }
                    if let Some(false) = status.controller_available {
                        controller_ok = false;
                        println!(
                            "           \x1b[1;31m⚠ Controller NOT FOUND — finalizer may be stuck\x1b[0m"
                        );
                    }
                }
                ProgressState::Gone => {
                    total_gone += 1;
                    println!(
                        "  \x1b[2mGONE     \x1b[0m {}{}{}",
                        label, keep_marker, ns_suffix
                    );
                }
                ProgressState::Unknown => {
                    total_unknown += 1;
                    println!(
                        "  \x1b[35mUNKNOWN  \x1b[0m {}{}{}",
                        label, keep_marker, ns_suffix
                    );
                }
            }
        }
    }

    println!(
        "\n\x1b[1mSummary\x1b[0m: {} exist, {} deleting, {} gone, {} unknown",
        total_exist, total_deleting, total_gone, total_unknown
    );
    if total_finalizers > 0 {
        let ctrl_status = if controller_ok {
            "controller available"
        } else {
            "controller NOT available"
        };
        println!(
            "  {} resources have finalizers ({})",
            total_finalizers, ctrl_status
        );
    }
}
