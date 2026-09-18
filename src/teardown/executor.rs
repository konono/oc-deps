use std::io::Write;
use std::time::Instant;

use anyhow::Result;
use kube::{
    Client,
    api::{Api, ApiResource, DeleteParams, DynamicObject},
    core::GroupVersion,
};

use crate::kube::discovery::KindMap;
use crate::kube::resource::ResourceId;
use crate::teardown::planner::{Action, TeardownPlan};

#[derive(Debug)]
enum DeleteResult {
    Deleted,
    AlreadyGone,
    Failed(String),
}

pub struct ExecutionResult {
    pub phases_completed: usize,
    pub phases_total: usize,
    pub deleted: Vec<ResourceId>,
    pub already_gone: Vec<ResourceId>,
    pub failed: Vec<(ResourceId, String)>,
    pub barrier_timeout: Option<BarrierTimeout>,
}

pub struct BarrierTimeout {
    pub phase: String,
    pub remaining: Vec<ResourceId>,
    pub finalizers: Vec<(ResourceId, Vec<String>)>,
}

fn count_actions(plan: &TeardownPlan) -> (usize, usize, usize, usize) {
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
    (delete_count, expect_count, keep_count, review_count)
}

fn scope_suffix(resource: &ResourceId) -> String {
    match &resource.namespace {
        Some(ns) => format!("  \x1b[2m(ns: {})\x1b[0m", ns),
        None => "  \x1b[2m(cluster-scoped)\x1b[0m".to_string(),
    }
}

fn confirm_execution(plan: &TeardownPlan) -> bool {
    let (total_delete, total_expect, _total_keep, _total_review) = count_actions(plan);

    eprintln!(
        "\n\x1b[1;33m⚠ This will DELETE {} resources ({} expected to auto-remove) across {} phases.\x1b[0m\n",
        total_delete,
        total_expect,
        plan.phases.len()
    );

    let target_names: Vec<&str> = plan.targets.iter().map(|t| t.csv.name.as_str()).collect();
    eprintln!("  Targets: {}", target_names.join(", "));
    eprintln!();

    for (i, phase) in plan.phases.iter().enumerate() {
        let del = phase
            .actions
            .iter()
            .filter(|a| matches!(a, Action::Delete { .. }))
            .count();
        let expect = phase
            .actions
            .iter()
            .filter(|a| matches!(a, Action::ExpectGone { .. }))
            .count();
        let keep = phase
            .actions
            .iter()
            .filter(|a| matches!(a, Action::Keep { .. }))
            .count();
        let review = phase
            .actions
            .iter()
            .filter(|a| matches!(a, Action::Review { .. }))
            .count();
        if del > 0 || expect > 0 || keep > 0 || review > 0 {
            let mut parts = Vec::new();
            if del > 0 {
                parts.push(format!("{} DELETE", del));
            }
            if expect > 0 {
                parts.push(format!("{} EXPECT", expect));
            }
            if keep > 0 {
                parts.push(format!("{} KEEP", keep));
            }
            if review > 0 {
                parts.push(format!("{} REVIEW", review));
            }
            eprintln!("  Phase {}: {}", i, parts.join(", "));
        }
    }

    eprint!("\nProceed? [y/N] ");
    std::io::stderr().flush().ok();

    let mut input = String::new();
    if std::io::stdin().read_line(&mut input).is_err() {
        return false;
    }
    matches!(input.trim().to_lowercase().as_str(), "y" | "yes")
}

pub async fn execute_plan(
    client: &Client,
    plan: &TeardownPlan,
    kind_map: &KindMap,
    dry_run: bool,
) -> Result<ExecutionResult> {
    if dry_run {
        eprintln!("\x1b[1;36m── DRY RUN ──\x1b[0m\n");
    } else if !confirm_execution(plan) {
        eprintln!("\nAborted.");
        return Ok(ExecutionResult {
            phases_completed: 0,
            phases_total: plan.phases.len(),
            deleted: vec![],
            already_gone: vec![],
            failed: vec![],
            barrier_timeout: None,
        });
    }

    let mut result = ExecutionResult {
        phases_completed: 0,
        phases_total: plan.phases.len(),
        deleted: vec![],
        already_gone: vec![],
        failed: vec![],
        barrier_timeout: None,
    };

    for (i, phase) in plan.phases.iter().enumerate() {
        eprintln!("\n\x1b[1mPhase {}  {}\x1b[0m", i, phase.name);

        if phase.actions.is_empty() {
            eprintln!("  (none)");
            result.phases_completed += 1;
            continue;
        }

        let mut phase_wait_targets: Vec<ResourceId> = Vec::new();

        for action in &phase.actions {
            match action {
                Action::Delete { resource, reason } => {
                    if dry_run {
                        eprintln!(
                            "  \x1b[36mDRY-DELETE\x1b[0m {}/{}{}",
                            resource.kind,
                            resource.name,
                            scope_suffix(resource)
                        );
                        eprintln!("             \x1b[2m{}\x1b[0m", reason);
                        phase_wait_targets.push(resource.clone());
                    } else {
                        match delete_resource(client, resource, kind_map).await {
                            DeleteResult::Deleted => {
                                eprintln!(
                                    "  \x1b[31mDELETED\x1b[0m  {}/{}{}",
                                    resource.kind,
                                    resource.name,
                                    scope_suffix(resource)
                                );
                                result.deleted.push(resource.clone());
                                phase_wait_targets.push(resource.clone());
                            }
                            DeleteResult::AlreadyGone => {
                                eprintln!(
                                    "  \x1b[2mSKIPPED\x1b[0m  {}/{} (already gone){}",
                                    resource.kind,
                                    resource.name,
                                    scope_suffix(resource)
                                );
                                result.already_gone.push(resource.clone());
                            }
                            DeleteResult::Failed(err) => {
                                eprintln!(
                                    "  \x1b[1;31mFAILED\x1b[0m   {}/{}: {}{}",
                                    resource.kind,
                                    resource.name,
                                    err,
                                    scope_suffix(resource)
                                );
                                result.failed.push((resource.clone(), err));
                                phase_wait_targets.push(resource.clone());
                            }
                        }
                    }
                }
                Action::ExpectGone { resource, reason } => {
                    if dry_run {
                        eprintln!(
                            "  \x1b[33mDRY-EXPECT\x1b[0m {}/{}{}",
                            resource.kind,
                            resource.name,
                            scope_suffix(resource)
                        );
                        eprintln!("             \x1b[2m{}\x1b[0m", reason);
                    } else {
                        eprintln!(
                            "  \x1b[33mEXPECT\x1b[0m   {}/{}{}",
                            resource.kind,
                            resource.name,
                            scope_suffix(resource)
                        );
                        eprintln!("             \x1b[2m{}\x1b[0m", reason);
                    }
                    phase_wait_targets.push(resource.clone());
                }
                Action::Keep { resource, reason } => {
                    eprintln!(
                        "  \x1b[32mKEEP\x1b[0m     {}/{}{}",
                        resource.kind,
                        resource.name,
                        scope_suffix(resource)
                    );
                    eprintln!("             \x1b[2m{}\x1b[0m", reason);
                }
                Action::Review { resource, reason } => {
                    eprintln!(
                        "  \x1b[35mREVIEW\x1b[0m   {}/{}{}",
                        resource.kind,
                        resource.name,
                        scope_suffix(resource)
                    );
                    eprintln!("             \x1b[2m{}\x1b[0m", reason);
                }
                Action::WaitGone { resource } => {
                    eprintln!(
                        "  \x1b[33mWAIT\x1b[0m     {}/{}{}",
                        resource.kind,
                        resource.name,
                        scope_suffix(resource)
                    );
                    phase_wait_targets.push(resource.clone());
                }
            }
        }

        if phase.barrier.is_some() && !phase_wait_targets.is_empty() {
            if dry_run {
                eprintln!("\n  \x1b[1;33mBARRIER\x1b[0m (skipped in dry-run)");
            } else {
                eprintln!();
                match wait_for_barrier(client, &phase_wait_targets, kind_map, 300).await {
                    BarrierResult::Passed => {
                        eprintln!("  \x1b[32m✅ Barrier passed\x1b[0m");
                    }
                    BarrierResult::Timeout {
                        remaining,
                        finalizers,
                    } => {
                        eprintln!(
                            "  \x1b[1;31m⚠ Barrier timeout — {} resources remain\x1b[0m",
                            remaining.len()
                        );
                        for res in &remaining {
                            let fins: Vec<&str> = finalizers
                                .iter()
                                .filter(|(r, _)| r == res)
                                .flat_map(|(_, f)| f.iter().map(|s| s.as_str()))
                                .collect();
                            if fins.is_empty() {
                                eprintln!("    {}/{}", res.kind, res.name);
                            } else {
                                eprintln!(
                                    "    {}/{} (finalizers: [{}])",
                                    res.kind,
                                    res.name,
                                    fins.join(", ")
                                );
                            }
                        }
                        result.barrier_timeout = Some(BarrierTimeout {
                            phase: phase.name.clone(),
                            remaining: remaining.clone(),
                            finalizers,
                        });
                        break;
                    }
                }
            }
        }

        result.phases_completed += 1;
    }

    Ok(result)
}

async fn delete_resource(
    client: &Client,
    resource: &ResourceId,
    kind_map: &KindMap,
) -> DeleteResult {
    let kind_info = match kind_map.get(&resource.kind) {
        Some(i) => i,
        None => return DeleteResult::Failed(format!("unknown kind: {}", resource.kind)),
    };

    let gvk = GroupVersion::gv(&kind_info.group, &kind_info.version).with_kind(&resource.kind);
    let ar = ApiResource::from_gvk_with_plural(&gvk, &kind_info.plural);
    let api: Api<DynamicObject> = if let Some(ns) = &resource.namespace {
        Api::namespaced_with(client.clone(), ns, &ar)
    } else if kind_info.namespaced {
        return DeleteResult::Failed("namespaced resource without namespace".to_string());
    } else {
        Api::all_with(client.clone(), &ar)
    };

    match api.delete(&resource.name, &DeleteParams::default()).await {
        Ok(_) => DeleteResult::Deleted,
        Err(kube::Error::Api(err)) if err.code == 404 => DeleteResult::AlreadyGone,
        Err(e) => DeleteResult::Failed(e.to_string()),
    }
}

enum BarrierResult {
    Passed,
    Timeout {
        remaining: Vec<ResourceId>,
        finalizers: Vec<(ResourceId, Vec<String>)>,
    },
}

async fn wait_for_barrier(
    client: &Client,
    resources: &[ResourceId],
    kind_map: &KindMap,
    timeout_secs: u64,
) -> BarrierResult {
    let start = Instant::now();
    let total = resources.len();

    loop {
        let elapsed = start.elapsed().as_secs();
        if elapsed >= timeout_secs {
            let mut remaining = Vec::new();
            let mut finalizers = Vec::new();
            for res in resources {
                if !is_gone(client, res, kind_map).await {
                    let fins = get_finalizers(client, res, kind_map).await;
                    if !fins.is_empty() {
                        finalizers.push((res.clone(), fins));
                    }
                    remaining.push(res.clone());
                }
            }
            return BarrierResult::Timeout {
                remaining,
                finalizers,
            };
        }

        let mut gone_count = 0;
        for res in resources {
            if is_gone(client, res, kind_map).await {
                gone_count += 1;
            }
        }

        eprint!(
            "\r\x1b[2K  ⏳ Waiting... {}/{} gone (elapsed: {}s)",
            gone_count, total, elapsed
        );
        std::io::stderr().flush().ok();

        if gone_count == total {
            eprintln!();
            return BarrierResult::Passed;
        }

        tokio::time::sleep(std::time::Duration::from_secs(5)).await;
    }
}

async fn is_gone(client: &Client, resource: &ResourceId, kind_map: &KindMap) -> bool {
    let kind_info = match kind_map.get(&resource.kind) {
        Some(i) => i,
        None => return true,
    };

    let gvk = GroupVersion::gv(&kind_info.group, &kind_info.version).with_kind(&resource.kind);
    let ar = ApiResource::from_gvk_with_plural(&gvk, &kind_info.plural);
    let api: Api<DynamicObject> = if let Some(ns) = &resource.namespace {
        Api::namespaced_with(client.clone(), ns, &ar)
    } else if kind_info.namespaced {
        return true;
    } else {
        Api::all_with(client.clone(), &ar)
    };

    matches!(
        api.get(&resource.name).await,
        Err(kube::Error::Api(err)) if err.code == 404
    )
}

async fn get_finalizers(client: &Client, resource: &ResourceId, kind_map: &KindMap) -> Vec<String> {
    let kind_info = match kind_map.get(&resource.kind) {
        Some(i) => i,
        None => return vec![],
    };

    let gvk = GroupVersion::gv(&kind_info.group, &kind_info.version).with_kind(&resource.kind);
    let ar = ApiResource::from_gvk_with_plural(&gvk, &kind_info.plural);
    let api: Api<DynamicObject> = if let Some(ns) = &resource.namespace {
        Api::namespaced_with(client.clone(), ns, &ar)
    } else if kind_info.namespaced {
        return vec![];
    } else {
        Api::all_with(client.clone(), &ar)
    };

    match api.get(&resource.name).await {
        Ok(obj) => obj.metadata.finalizers.unwrap_or_default(),
        Err(_) => vec![],
    }
}

pub fn print_execution_result(result: &ExecutionResult) {
    eprintln!(
        "\n\x1b[1mExecution Summary\x1b[0m: {}/{} phases completed",
        result.phases_completed, result.phases_total
    );
    eprintln!(
        "  {} deleted, {} already gone, {} failed",
        result.deleted.len(),
        result.already_gone.len(),
        result.failed.len()
    );

    if !result.failed.is_empty() {
        eprintln!("\n\x1b[1;31mFailed:\x1b[0m");
        for (res, err) in &result.failed {
            eprintln!("  {}/{}: {}", res.kind, res.name, err);
        }
    }

    if let Some(timeout) = &result.barrier_timeout {
        eprintln!(
            "\n\x1b[1;33mBarrier timeout in phase '{}'\x1b[0m — {} resources remain:",
            timeout.phase,
            timeout.remaining.len()
        );
        for res in &timeout.remaining {
            let fins: Vec<&str> = timeout
                .finalizers
                .iter()
                .filter(|(r, _)| r == res)
                .flat_map(|(_, f)| f.iter().map(|s| s.as_str()))
                .collect();
            if fins.is_empty() {
                eprintln!("  {}/{}", res.kind, res.name);
            } else {
                eprintln!(
                    "  {}/{} (finalizers: [{}])",
                    res.kind,
                    res.name,
                    fins.join(", ")
                );
            }
        }
    }
}
