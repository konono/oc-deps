use std::io::Write;
use std::time::Instant;

use anyhow::{Result, bail};
use kube::{Client, api::DeleteParams};

use crate::kube::discovery::KindMap;
use crate::kube::resource::{ResourceId, resolve_api};
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
    if !plan.blockers.is_empty() && !dry_run {
        eprintln!(
            "\x1b[1;31m⛔ Plan has {} blocker(s) — cannot execute:\x1b[0m",
            plan.blockers.len()
        );
        for blocker in &plan.blockers {
            eprintln!(
                "  {}/{}: {}",
                blocker.resource.kind, blocker.resource.name, blocker.reason
            );
        }
        bail!("Plan has blockers. Resolve external dependencies before applying.");
    }

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
                    BarrierResult::Stalled {
                        remaining,
                        finalizers,
                        reason,
                    } => {
                        eprintln!(
                            "  \x1b[1;31m⚠ Barrier stalled — {} resources remain ({})\x1b[0m",
                            remaining.len(),
                            reason
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
    let (api, _) = match resolve_api(client, resource, kind_map) {
        Some(r) => r,
        None => {
            return DeleteResult::Failed(format!(
                "cannot resolve API for {}/{}",
                resource.kind, resource.name
            ));
        }
    };

    match api.delete(&resource.name, &DeleteParams::default()).await {
        Ok(_) => DeleteResult::Deleted,
        Err(kube::Error::Api(err)) if err.code == 404 => DeleteResult::AlreadyGone,
        Err(e) => DeleteResult::Failed(e.to_string()),
    }
}

enum BarrierResult {
    Passed,
    Stalled {
        remaining: Vec<ResourceId>,
        finalizers: Vec<(ResourceId, Vec<String>)>,
        reason: String,
    },
}

struct ResourceState {
    gone: bool,
    finalizer_count: usize,
    has_deletion_timestamp: bool,
}

async fn check_resource_state(
    client: &Client,
    resource: &ResourceId,
    kind_map: &KindMap,
) -> ResourceState {
    let (api, _) = match resolve_api(client, resource, kind_map) {
        Some(r) => r,
        None => {
            return ResourceState {
                gone: true,
                finalizer_count: 0,
                has_deletion_timestamp: false,
            };
        }
    };

    match api.get(&resource.name).await {
        Ok(obj) => {
            let finalizers = obj
                .metadata
                .finalizers
                .as_ref()
                .map(|f| f.len())
                .unwrap_or(0);
            let has_dt = obj.metadata.deletion_timestamp.is_some();
            ResourceState {
                gone: false,
                finalizer_count: finalizers,
                has_deletion_timestamp: has_dt,
            }
        }
        Err(kube::Error::Api(err)) if err.code == 404 => ResourceState {
            gone: true,
            finalizer_count: 0,
            has_deletion_timestamp: false,
        },
        Err(_) => ResourceState {
            gone: false,
            finalizer_count: 0,
            has_deletion_timestamp: false,
        },
    }
}

async fn wait_for_barrier(
    client: &Client,
    resources: &[ResourceId],
    kind_map: &KindMap,
    timeout_secs: u64,
) -> BarrierResult {
    let start = Instant::now();
    let total = resources.len();

    let mut prev_gone = 0usize;
    let mut prev_total_finalizers = usize::MAX;
    let mut last_progress = Instant::now();
    let stall_threshold_secs = 120;

    loop {
        let elapsed = start.elapsed().as_secs();

        let mut gone_count = 0;
        let mut deleting_count = 0;
        let mut total_finalizers = 0;
        let mut remaining = Vec::new();
        let mut remaining_finalizers = Vec::new();

        for res in resources {
            let state = check_resource_state(client, res, kind_map).await;
            if state.gone {
                gone_count += 1;
            } else {
                remaining.push(res.clone());
                total_finalizers += state.finalizer_count;
                if state.has_deletion_timestamp {
                    deleting_count += 1;
                }
                if state.finalizer_count > 0 {
                    let fins = get_finalizers(client, res, kind_map).await;
                    remaining_finalizers.push((res.clone(), fins));
                }
            }
        }

        let made_progress = gone_count > prev_gone || total_finalizers < prev_total_finalizers;

        if made_progress {
            last_progress = Instant::now();
            prev_gone = gone_count;
            prev_total_finalizers = total_finalizers;
        }

        eprint!(
            "\r\x1b[2K  ⏳ {}/{} gone, {} deleting, {} finalizers ({}s)",
            gone_count, total, deleting_count, total_finalizers, elapsed
        );
        std::io::stderr().flush().ok();

        if gone_count == total {
            eprintln!();
            return BarrierResult::Passed;
        }

        let stall_duration = last_progress.elapsed().as_secs();
        if elapsed >= timeout_secs {
            eprintln!();
            return BarrierResult::Stalled {
                remaining,
                finalizers: remaining_finalizers,
                reason: format!("timeout after {}s", elapsed),
            };
        }

        if stall_duration >= stall_threshold_secs && deleting_count > 0 {
            eprintln!();
            return BarrierResult::Stalled {
                remaining,
                finalizers: remaining_finalizers,
                reason: format!(
                    "no progress for {}s — {} resources stuck in Deleting with finalizers",
                    stall_duration, deleting_count
                ),
            };
        }

        tokio::time::sleep(std::time::Duration::from_secs(5)).await;
    }
}

async fn get_finalizers(client: &Client, resource: &ResourceId, kind_map: &KindMap) -> Vec<String> {
    let (api, _) = match resolve_api(client, resource, kind_map) {
        Some(r) => r,
        None => return vec![],
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
            "\n\x1b[1;33mBarrier stalled in phase '{}'\x1b[0m — {} resources remain:",
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
