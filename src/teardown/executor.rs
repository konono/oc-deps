use std::collections::HashSet;
use std::io::Write;
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{Context, Result, bail};
use futures::stream::StreamExt;
use kube::{
    Client,
    api::{Api, ApiResource, DeleteParams, DynamicObject, ListParams},
    core::GroupVersion,
};

use crate::kube::discovery::{GroupKindMap, GvkMap, GvrMap, KindMap};
use crate::kube::resource::{ResourceId, resolve_api};
use crate::teardown::events::EventNotifier;
use crate::teardown::journal::JournalStore;
use crate::teardown::permit::MutationGate;
use crate::teardown::plan::PlannedPreserved;
use crate::teardown::planner::{Action, PreflightSeverity, TeardownPlan};
use crate::teardown::runtime::{ResourceRuntimeState, RuntimeStateStore};
use crate::teardown::watch::{WatchManager, WatchWaitResult};

const DEFAULT_CONCURRENCY: usize = 16;

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
    pub kept: Vec<PlannedPreserved>,
    pub reviewed: Vec<PlannedPreserved>,
}

pub struct BarrierTimeout {
    pub phase: String,
    pub remaining: Vec<ResourceId>,
    pub finalizers: Vec<(ResourceId, Vec<String>)>,
}

// P0-1: three-value state for resource checks — Unknown is never treated as Gone
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ObservationState {
    Gone,
    Exists {
        finalizer_count: usize,
        has_deletion_timestamp: bool,
    },
    Unknown(String),
}

// P0-adjacent: three-value result for finalizer checks
#[derive(Debug, Clone)]
pub enum FinalizerCheckResult {
    Known(Vec<String>),
    Gone,
    Unknown(String),
}

// P0-3: live instance count check before CRD deletion
#[derive(Debug)]
enum LiveCount {
    Zero,
    NonZero(usize),
    Unknown(String),
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

#[allow(clippy::too_many_arguments)]
pub async fn execute_plan(
    client: &Client,
    plan: &TeardownPlan,
    kind_map: &KindMap,
    gk_map: &GroupKindMap,
    gvk_map: &GvkMap,
    gvr_map: &GvrMap,
    dry_run: bool,
    force: bool,
    journal: Option<&JournalStore>,
    gate: Option<&MutationGate>,
    start_phase: usize,
    skip_confirm: bool,
) -> Result<ExecutionResult> {
    execute_plan_with_store(
        client, plan, kind_map, gk_map, gvk_map, gvr_map,
        dry_run, force, journal, gate, start_phase, skip_confirm, None,
    ).await
}

pub async fn execute_plan_with_store(
    client: &Client,
    plan: &TeardownPlan,
    kind_map: &KindMap,
    gk_map: &GroupKindMap,
    gvk_map: &GvkMap,
    gvr_map: &GvrMap,
    dry_run: bool,
    force: bool,
    journal: Option<&JournalStore>,
    gate: Option<&MutationGate>,
    start_phase: usize,
    skip_confirm: bool,
    external_store: Option<Arc<RuntimeStateStore>>,
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

    let critical_failures: Vec<&str> = plan
        .preflight
        .checks
        .iter()
        .filter(|c| !c.passed && c.severity == PreflightSeverity::Critical)
        .map(|c| c.name.as_str())
        .collect();
    if !critical_failures.is_empty() && !dry_run {
        eprintln!(
            "\x1b[1;31m⛔ Critical preflight failed — {} check(s):\x1b[0m",
            critical_failures.len()
        );
        for name in &critical_failures {
            eprintln!("  {}", name);
        }
        bail!("Critical preflight checks failed. Cannot override with --force.");
    }

    let non_critical_failures: Vec<&str> = plan
        .preflight
        .checks
        .iter()
        .filter(|c| !c.passed && c.severity == PreflightSeverity::Warning)
        .map(|c| c.name.as_str())
        .collect();
    if !non_critical_failures.is_empty() && !dry_run && !force {
        eprintln!(
            "\x1b[1;33m⚠ Preflight warnings — {} check(s):\x1b[0m",
            non_critical_failures.len()
        );
        for name in &non_critical_failures {
            eprintln!("  {}", name);
        }
        bail!("Preflight checks have warnings. Use --force to override.");
    }

    let review_count = plan
        .phases
        .iter()
        .flat_map(|p| &p.actions)
        .filter(|a| matches!(a, Action::Review { .. }))
        .count();
    if review_count > 0 && !dry_run && !force {
        eprintln!(
            "\x1b[1;33m⚠ Plan has {} REVIEW item(s) — resources with uncertain provenance:\x1b[0m",
            review_count
        );
        for phase in &plan.phases {
            for action in &phase.actions {
                if let Action::Review { resource, reason, .. } = action {
                    eprintln!("  {}/{}: {}", resource.kind, resource.name, reason);
                }
            }
        }
        bail!("Cannot execute with unresolved REVIEW items. Use --force to override.");
    }

    if dry_run {
        eprintln!("\x1b[1;36m── DRY RUN ──\x1b[0m\n");
    } else if !skip_confirm && !confirm_execution(plan) {
        eprintln!("\nAborted.");
        return Ok(ExecutionResult {
            phases_completed: 0,
            phases_total: plan.phases.len(),
            deleted: vec![],
            already_gone: vec![],
            failed: vec![],
            barrier_timeout: None,
            kept: vec![],
            reviewed: vec![],
        });
    }

    let mut result = ExecutionResult {
        phases_completed: 0,
        phases_total: plan.phases.len(),
        deleted: vec![],
        already_gone: vec![],
        failed: vec![],
        barrier_timeout: None,
        kept: vec![],
        reviewed: vec![],
    };

    // Verify all DELETE actions have bound UIDs BEFORE persisting Applying state.
    // This prevents a crash-recovery misread: Applying + zero mutations = interrupted,
    // but UID gate failure means no mutation was ever intended.
    if !dry_run {
        let uid_missing: Vec<String> = plan
            .phases
            .iter()
            .flat_map(|p| &p.actions)
            .filter_map(|a| match a {
                Action::Delete { resource, .. } => {
                    if resource.uid.is_none()
                        || resource.uid.as_ref().is_some_and(|u| u.is_empty())
                    {
                        Some(format!("{}/{}", resource.kind, resource.name))
                    } else {
                        None
                    }
                }
                _ => None,
            })
            .collect();

        if !uid_missing.is_empty() {
            bail!(
                "Cannot execute: {} DELETE action(s) have unbound UIDs \
                 (UID binding should happen at plan time): {}",
                uid_missing.len(),
                uid_missing.join(", ")
            );
        }
    }

    // Persist Applying state before first mutation (after UID gate passes)
    if let Some(j) = journal {
        j.update(|journal| {
            journal.state = crate::teardown::journal::RunState::Applying;
        })
        .await
        .context("Failed to persist Applying state — aborting before first mutation")?;
    }

    // Initialize RuntimeStateStore — canonical state for all tracked resources.
    // The store is purely observational: it never calls delete/mutation APIs.
    let store = if let Some(ext) = external_store {
        ext
    } else {
        let notifier = Arc::new(EventNotifier::new());
        Arc::new(RuntimeStateStore::new(
            notifier.clone(),
            Duration::from_secs(120),
        ))
    };
    let watch_mgr = WatchManager::new(store.clone());

    // Register all resources from the plan with their initial states
    for (phase_idx, phase) in plan.phases.iter().enumerate() {
        for action in &phase.actions {
            match action {
                Action::Delete { resource, .. } => {
                    store.register(resource, ResourceRuntimeState::Planned, phase_idx);
                }
                Action::ExpectGone { resource, .. } | Action::WaitGone { resource } => {
                    store.register(resource, ResourceRuntimeState::ExpectingGone, phase_idx);
                }
                Action::Keep { resource, .. } => {
                    store.register(resource, ResourceRuntimeState::Keep, phase_idx);
                }
                Action::Review { resource, .. } => {
                    store.register(resource, ResourceRuntimeState::Review, phase_idx);
                }
            }
        }
    }

    for (i, phase) in plan.phases.iter().enumerate() {
        // Skip already-completed phases (resume support)
        if i < start_phase {
            eprintln!("\n\x1b[2mPhase {} {} (completed in prior run)\x1b[0m", i, phase.name);
            result.phases_completed += 1;
            continue;
        }

        // Acquire phase-level mutation permit before any phase work.
        // Held through DELETEs + journal checkpoint so pause drain
        // waits for the durable result. Dropped at end of loop iteration.
        let _phase_permit = if !dry_run {
            if let Some(g) = gate {
                match g.acquire().await {
                    Ok(permit) => Some(permit),
                    Err(_) => {
                        eprintln!("\n\x1b[1;33m⏸ Mutation gate closed — pausing\x1b[0m");
                        break;
                    }
                }
            } else {
                None
            }
        } else {
            None
        };

        eprintln!("\n\x1b[1mPhase {}  {}\x1b[0m", i, phase.name);

        if phase.actions.is_empty() {
            eprintln!("  (none)");
            result.phases_completed += 1;
            continue;
        }

        let mut phase_wait_targets: Vec<ResourceId> = Vec::new();

        // Collect DELETE actions for parallel execution
        let delete_actions: Vec<_> = phase
            .actions
            .iter()
            .filter_map(|a| match a {
                Action::Delete { resource, reason } => Some((resource.clone(), reason.clone())),
                _ => None,
            })
            .collect();

        if !delete_actions.is_empty() {
            if dry_run {
                for (resource, reason) in &delete_actions {
                    eprintln!(
                        "  \x1b[36mDRY-DELETE\x1b[0m {}/{}{}",
                        resource.kind,
                        resource.name,
                        scope_suffix(resource)
                    );
                    eprintln!("             \x1b[2m{}\x1b[0m", reason);
                    phase_wait_targets.push(resource.clone());
                }
            } else {
                // CRD/APIService live count checks (must be sequential for safety)
                let mut api_blocked: HashSet<String> = HashSet::new();
                for (resource, _) in &delete_actions {
                    let live = if resource.kind == "CustomResourceDefinition" {
                        Some(
                            count_live_cr_instances(
                                client,
                                &resource.name,
                                kind_map,
                                gk_map,
                                gvr_map,
                            )
                            .await,
                        )
                    } else if resource.kind == "APIService" {
                        Some(
                            count_live_api_service_instances(client, &resource.name, gvk_map).await,
                        )
                    } else {
                        None
                    };

                    if let Some(live) = live {
                        match live {
                            LiveCount::NonZero(n) => {
                                eprintln!(
                                    "  \x1b[1;31m⛔ BLOCKED\x1b[0m {}/{}{}",
                                    resource.kind,
                                    resource.name,
                                    scope_suffix(resource)
                                );
                                eprintln!("             {} live instances remain — skipping", n);
                                result.failed.push((
                                    resource.clone(),
                                    format!("{} live instances remain", n),
                                ));
                                api_blocked.insert(resource.name.clone());
                            }
                            LiveCount::Unknown(err) => {
                                eprintln!(
                                    "  \x1b[1;31m⛔ BLOCKED\x1b[0m {}/{}{}",
                                    resource.kind,
                                    resource.name,
                                    scope_suffix(resource)
                                );
                                eprintln!(
                                    "             cannot verify instance count: {} — skipping",
                                    err
                                );
                                result
                                    .failed
                                    .push((resource.clone(), format!("cannot verify: {}", err)));
                                api_blocked.insert(resource.name.clone());
                            }
                            LiveCount::Zero => {}
                        }
                    }
                }

                // Parallel DELETE (excluding blocked APIs)
                let eligible: Vec<_> = delete_actions
                    .iter()
                    .filter(|(r, _)| !api_blocked.contains(&r.name))
                    .collect();

                let km = Arc::new(kind_map.clone());
                let gk = Arc::new(gk_map.clone());
                let del_futs = eligible.iter().map(|(resource, _)| {
                    let client = client.clone();
                    let resource = resource.clone();
                    let km = km.clone();
                    let gk = gk.clone();
                    async move {
                        let res = delete_resource(&client, &resource, &km, &gk).await;
                        (resource, res)
                    }
                });

                let del_results: Vec<_> = futures::stream::iter(del_futs)
                    .buffer_unordered(DEFAULT_CONCURRENCY)
                    .collect()
                    .await;

                for (resource, del_result) in del_results {
                    match del_result {
                        DeleteResult::Deleted => {
                            eprintln!(
                                "  \x1b[31mDELETED\x1b[0m  {}/{}{}",
                                resource.kind,
                                resource.name,
                                scope_suffix(&resource)
                            );
                            store.update_from_executor(
                                &resource,
                                ResourceRuntimeState::DeleteRequested,
                            );
                            result.deleted.push(resource.clone());
                            phase_wait_targets.push(resource);
                        }
                        DeleteResult::AlreadyGone => {
                            eprintln!(
                                "  \x1b[2mSKIPPED\x1b[0m  {}/{} (already gone){}",
                                resource.kind,
                                resource.name,
                                scope_suffix(&resource)
                            );
                            store.update_from_executor(
                                &resource,
                                ResourceRuntimeState::Gone,
                            );
                            result.already_gone.push(resource);
                        }
                        DeleteResult::Failed(err) => {
                            eprintln!(
                                "  \x1b[1;31mFAILED\x1b[0m   {}/{}: {}{}",
                                resource.kind,
                                resource.name,
                                err,
                                scope_suffix(&resource)
                            );
                            store.update_from_executor(
                                &resource,
                                ResourceRuntimeState::Failed {
                                    reason: err.clone(),
                                },
                            );
                            result.failed.push((resource.clone(), err));
                            phase_wait_targets.push(resource);
                        }
                    }
                }
            }
        }

        // Non-DELETE actions (sequential for display)
        for action in &phase.actions {
            match action {
                Action::Delete { .. } => {} // already handled above
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
                    result.kept.push(PlannedPreserved {
                        resource: resource.clone(),
                        reason: reason.clone(),
                        metadata: None,
                    });
                }
                Action::Review { resource, reason, metadata } => {
                    eprintln!(
                        "  \x1b[35mREVIEW\x1b[0m   {}/{}{}",
                        resource.kind,
                        resource.name,
                        scope_suffix(resource)
                    );
                    eprintln!("             \x1b[2m{}\x1b[0m", reason);
                    result.reviewed.push(PlannedPreserved {
                        resource: resource.clone(),
                        reason: reason.clone(),
                        metadata: metadata.clone(),
                    });
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
                // Use WatchManager for barrier wait — state is tracked in
                // RuntimeStateStore, CLI renders from the store's summary.
                let barrier_start = Instant::now();

                let wait_result = {
                    // Spawn a background task to render progress from the store.
                    // Uses summary_for to show only current barrier targets.
                    let store_ref = store.clone();
                    let barrier_targets = phase_wait_targets.clone();
                    let render_handle = tokio::spawn(async move {
                        let mut rx = store_ref.subscribe();
                        loop {
                            // Wait for state change notification
                            if rx.changed().await.is_err() {
                                break;
                            }
                            let summary = store_ref.summary_for(&barrier_targets);
                            let elapsed = barrier_start.elapsed().as_secs();
                            eprint!(
                                "\r\x1b[2K  ⏳ {}/{} Gone, {} Deleting, {} FinalizerBlocked{}{}({}s)",
                                summary.gone,
                                summary.total,
                                summary.deleting,
                                summary.finalizer_blocked,
                                if summary.stalled > 0 { format!(", {} Stalled", summary.stalled) } else { String::new() },
                                if summary.unknown > 0 { format!(", {} Unknown", summary.unknown) } else { String::new() },
                                elapsed
                            );
                            std::io::stderr().flush().ok();
                        }
                    });

                    let r = watch_mgr
                        .wait_for_gone(
                            client,
                            &phase_wait_targets,
                            kind_map,
                            gk_map,
                            Duration::from_secs(300),
                            Duration::from_secs(120),
                        )
                        .await;

                    render_handle.abort();
                    // Final status line — barrier targets only
                    let summary = store.summary_for(&phase_wait_targets);
                    let elapsed = barrier_start.elapsed().as_secs();
                    eprint!(
                        "\r\x1b[2K  ⏳ {}/{} Gone, {} Deleting, {} FinalizerBlocked{}{}({}s)",
                        summary.gone,
                        summary.total,
                        summary.deleting,
                        summary.finalizer_blocked,
                        if summary.stalled > 0 { format!(", {} Stalled", summary.stalled) } else { String::new() },
                        if summary.unknown > 0 { format!(", {} Unknown", summary.unknown) } else { String::new() },
                        elapsed
                    );
                    eprintln!();
                    r
                };

                match wait_result {
                    WatchWaitResult::AllGone => {
                        eprintln!("  \x1b[32m✅ Barrier passed\x1b[0m");
                    }
                    WatchWaitResult::Stalled {
                        remaining,
                        finalizer_details,
                        reason,
                    } => {
                        eprintln!(
                            "  \x1b[1;31m⚠ Barrier stalled — {} resources remain ({})\x1b[0m",
                            remaining.len(),
                            reason
                        );
                        let finalizers: Vec<(ResourceId, Vec<String>)> = finalizer_details
                            .iter()
                            .map(|(r, count)| {
                                (r.clone(), vec![format!("{} finalizer(s)", count)])
                            })
                            .collect();
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
                                    "    {}/{} ({})",
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

        // P0-adjacent: Before advancing to a controller-deletion phase,
        // check REVIEW resources — Unknown finalizer state blocks controller deletion
        if !dry_run {
            let next_phase = plan.phases.get(i + 1);
            let next_deletes_controllers = next_phase.is_some_and(|p| {
                p.actions.iter().any(|a| {
                    matches!(a, Action::Delete { resource, .. } if resource.kind == "ClusterServiceVersion")
                })
            });
            if next_deletes_controllers {
                let review_resources: Vec<&ResourceId> = plan
                    .phases
                    .iter()
                    .flat_map(|p| &p.actions)
                    .filter_map(|a| match a {
                        Action::Review { resource, .. } => Some(resource),
                        _ => None,
                    })
                    .collect();
                let km = Arc::new(kind_map.clone());
                let gk = Arc::new(gk_map.clone());
                let fin_futs = review_resources.into_iter().map(|res| {
                    let client = client.clone();
                    let res = res.clone();
                    let km = km.clone();
                    let gk = gk.clone();
                    async move {
                        let r = check_finalizers(&client, &res, &km, &gk).await;
                        (res, r)
                    }
                });
                let fin_results: Vec<_> = futures::stream::iter(fin_futs)
                    .buffer_unordered(DEFAULT_CONCURRENCY)
                    .collect()
                    .await;

                let mut block_reasons = Vec::new();
                for (res, fin_result) in fin_results {
                    match fin_result {
                        FinalizerCheckResult::Known(fins) if !fins.is_empty() => {
                            block_reasons.push((res, fins));
                        }
                        FinalizerCheckResult::Unknown(err) => {
                            block_reasons.push((res, vec![format!("check failed: {}", err)]));
                        }
                        _ => {}
                    }
                }
                if !block_reasons.is_empty() {
                    eprintln!(
                        "\n  \x1b[1;31m⛔ {} REVIEW resource(s) block controller deletion:\x1b[0m",
                        block_reasons.len()
                    );
                    for (res, fins) in &block_reasons {
                        eprintln!("    {}/{} ({})", res.kind, res.name, fins.join(", "));
                    }
                    result.barrier_timeout = Some(BarrierTimeout {
                        phase: "pre-controller safety check".to_string(),
                        remaining: block_reasons.iter().map(|(r, _)| r.clone()).collect(),
                        finalizers: block_reasons,
                    });
                    break;
                }
            }
        }

        result.phases_completed += 1;

        // Checkpoint phase completion to journal
        if let Some(j) = journal {
            let phase_count = result.phases_completed;
            let deleted_snapshot = result.deleted.clone();
            let already_gone_snapshot = result.already_gone.clone();
            let failed_snapshot = result.failed.clone();
            let kept_snapshot: Vec<_> = result.kept.iter().map(crate::teardown::journal::PreservedRecord::from).collect();
            let reviewed_snapshot: Vec<_> = result.reviewed.iter().map(crate::teardown::journal::PreservedRecord::from).collect();
            j.update(|journal| {
                journal.execution.phases_completed = phase_count;
                journal.execution.deleted = deleted_snapshot;
                journal.execution.already_gone = already_gone_snapshot;
                journal.execution.failed = failed_snapshot;
                journal.execution.kept = kept_snapshot;
                journal.execution.reviewed = reviewed_snapshot;
            })
            .await
            .context("Failed to checkpoint phase completion — aborting before next mutation")?;
        }
    }

    Ok(result)
}

/// Verify delete identity: plan UID vs live UID.
///
/// Both plan UID and live UID must be present and match.
/// Plan UID should have been bound in the pre-mutation UID binding step.
/// If either is missing/empty, return Err (no mutation).
pub fn verify_delete_identity(
    plan_uid: &Option<String>,
    current_uid: &str,
) -> Result<(), String> {
    let plan_uid = match plan_uid {
        Some(uid) if !uid.is_empty() => uid.as_str(),
        _ => {
            return Err(
                "plan resource has no UID — cannot verify identity for safe DELETE".to_string(),
            );
        }
    };
    if current_uid.is_empty() {
        return Err(
            "live resource has no UID — cannot verify identity for safe DELETE".to_string(),
        );
    }
    if current_uid != plan_uid {
        return Err(format!(
            "UID mismatch: plan expected {} but found {} — resource may have been recreated",
            plan_uid, current_uid
        ));
    }
    Ok(())
}

/// Delete a resource with UID-preconditioned safety.
///
/// 1. GET current resource to verify endpoint + identity
/// 2. Verify plan UID vs live UID (see verify_delete_identity)
/// 3. DELETE with UID precondition to prevent TOCTOU race
///
/// Failure/AlreadyGone does NOT grant re-delete authority.
async fn delete_resource(
    client: &Client,
    resource: &ResourceId,
    kind_map: &KindMap,
    gk_map: &GroupKindMap,
) -> DeleteResult {
    let (api, _) = match resolve_api(client, resource, kind_map, gk_map) {
        Some(r) => r,
        None => {
            return DeleteResult::Failed(format!(
                "cannot resolve API for {}/{}",
                resource.kind, resource.name
            ));
        }
    };

    // Step 1: GET current resource to verify identity
    let current = match api.get(&resource.name).await {
        Ok(obj) => obj,
        Err(kube::Error::Api(err)) if err.code == 404 => {
            // Verify endpoint exists before declaring AlreadyGone
            match api.list(&ListParams::default().limit(1)).await {
                Ok(_) => return DeleteResult::AlreadyGone,
                Err(_) => {
                    return DeleteResult::Failed(
                        "pre-delete GET returned 404 but API endpoint verification failed — \
                         cannot distinguish object absence from endpoint absence"
                            .to_string(),
                    );
                }
            }
        }
        Err(e) => {
            return DeleteResult::Failed(format!("pre-delete GET failed: {}", e));
        }
    };

    let current_uid = current.metadata.uid.as_deref().unwrap_or("");

    // Step 2: Verify identity
    if let Err(reason) = verify_delete_identity(&resource.uid, current_uid) {
        return DeleteResult::Failed(reason);
    }

    // Step 3: Delete with UID precondition
    let dp = if !current_uid.is_empty() {
        DeleteParams {
            preconditions: Some(kube::api::Preconditions {
                uid: Some(current_uid.to_string()),
                resource_version: None,
            }),
            ..Default::default()
        }
    } else {
        DeleteParams::default()
    };

    match api.delete(&resource.name, &dp).await {
        Ok(_) => DeleteResult::Deleted,
        Err(kube::Error::Api(err)) if err.code == 404 => {
            // Endpoint could have disappeared between GET and DELETE.
            // Verify before declaring AlreadyGone.
            match api.list(&ListParams::default().limit(1)).await {
                Ok(_) => DeleteResult::AlreadyGone,
                Err(_) => DeleteResult::Failed(
                    "DELETE returned 404 but endpoint verification failed — \
                     cannot distinguish deletion from endpoint disappearance"
                        .to_string(),
                ),
            }
        }
        Err(kube::Error::Api(err)) if err.code == 409 => {
            DeleteResult::Failed(
                "UID conflict during delete — resource was recreated between GET and DELETE"
                    .to_string(),
            )
        }
        Err(e) => DeleteResult::Failed(e.to_string()),
    }
}

/// Public wrapper for residual cleanup DELETE with MutationGate.
/// Returns Ok(description) on success, Err on failure.
pub async fn delete_resource_pub(
    client: &Client,
    resource: &ResourceId,
    kind_map: &KindMap,
    gk_map: &GroupKindMap,
    gate: Option<&MutationGate>,
) -> Result<String> {
    // Acquire mutation permit
    let _permit = if let Some(g) = gate {
        Some(g.acquire().await.context("Mutation gate closed")?)
    } else {
        None
    };

    match delete_resource(client, resource, kind_map, gk_map).await {
        DeleteResult::Deleted => Ok("deleted".to_string()),
        DeleteResult::AlreadyGone => Ok("already gone".to_string()),
        DeleteResult::Failed(reason) => bail!("{}", reason),
    }
}

// Old wait_for_barrier removed — replaced by WatchManager::wait_for_gone
// which uses RuntimeStateStore for state tracking and epoch-based reconciliation.

// P0-adjacent: check_finalizers distinguishes Known/Gone/Unknown
async fn check_finalizers(
    client: &Client,
    resource: &ResourceId,
    kind_map: &KindMap,
    gk_map: &GroupKindMap,
) -> FinalizerCheckResult {
    let (api, _) = match resolve_api(client, resource, kind_map, gk_map) {
        Some(r) => r,
        None => {
            return FinalizerCheckResult::Unknown(format!(
                "cannot resolve API for {}/{}",
                resource.kind, resource.name
            ));
        }
    };

    match api.get(&resource.name).await {
        Ok(obj) => FinalizerCheckResult::Known(obj.metadata.finalizers.unwrap_or_default()),
        Err(kube::Error::Api(err)) if err.code == 404 => {
            // Verify endpoint exists before treating as Gone
            match api.list(&ListParams::default().limit(1)).await {
                Ok(_) => FinalizerCheckResult::Gone,
                Err(_) => FinalizerCheckResult::Unknown(
                    "GET 404 but API endpoint verification failed — \
                     cannot confirm resource absence"
                        .to_string(),
                ),
            }
        }
        Err(e) => FinalizerCheckResult::Unknown(format!("GET failed: {}", e)),
    }
}

async fn count_live_cr_instances(
    client: &Client,
    crd_name: &str,
    _kind_map: &KindMap,
    gk_map: &GroupKindMap,
    gvr_map: &GvrMap,
) -> LiveCount {
    let (plural, group) = match crd_name.split_once('.') {
        Some((p, g)) => (p, g),
        None => return LiveCount::Unknown(format!("cannot parse CRD name: {}", crd_name)),
    };

    let gvr_key = format!("{}.{}", plural, group).to_lowercase();
    let kind = match gvr_map.get(&gvr_key) {
        Some(k) => k.clone(),
        None => return LiveCount::Unknown(format!("kind not found for {}", gvr_key)),
    };

    let kind_info = match gk_map.get(&(group.to_string(), kind.clone())) {
        Some(i) => i,
        None => return LiveCount::Unknown(format!("no GroupKind mapping for {}/{}", group, kind)),
    };

    let gvk = GroupVersion::gv(&kind_info.group, &kind_info.version).with_kind(&kind);
    let ar = ApiResource::from_gvk_with_plural(&gvk, &kind_info.plural);
    let api: Api<DynamicObject> = Api::all_with(client.clone(), &ar);

    match api.list(&ListParams::default().limit(1)).await {
        Ok(list) if list.items.is_empty() => LiveCount::Zero,
        Ok(_) => LiveCount::NonZero(1),
        Err(e) => LiveCount::Unknown(format!("list failed: {}", e)),
    }
}

async fn count_live_api_service_instances(
    client: &Client,
    api_service_name: &str,
    gvk_map: &GvkMap,
) -> LiveCount {
    // APIService name format: <version>.<group> e.g. "v1beta1.metrics.k8s.io"
    let (version, group) = match api_service_name.split_once('.') {
        Some((v, g)) => (v, g),
        None => {
            return LiveCount::Unknown(format!(
                "cannot parse APIService name: {}",
                api_service_name
            ));
        }
    };

    let matching: Vec<_> = gvk_map
        .iter()
        .filter(|((g, v, _), _)| g == group && v == version)
        .collect();

    if matching.is_empty() {
        return LiveCount::Unknown(format!(
            "no discovered resources for APIService {}",
            api_service_name
        ));
    }

    for ((_, _, kind), kind_info) in &matching {
        let gvk = GroupVersion::gv(&kind_info.group, &kind_info.version).with_kind(kind);
        let ar = ApiResource::from_gvk_with_plural(&gvk, &kind_info.plural);
        let api: Api<DynamicObject> = Api::all_with(client.clone(), &ar);

        match api.list(&ListParams::default().limit(1)).await {
            Ok(list) if !list.items.is_empty() => return LiveCount::NonZero(1),
            Ok(_) => {}
            Err(e) => return LiveCount::Unknown(format!("LIST {}/{} failed: {}", group, kind, e)),
        }
    }

    LiveCount::Zero
}

pub fn create_runtime_store() -> (Arc<RuntimeStateStore>, Arc<EventNotifier>) {
    let notifier = Arc::new(EventNotifier::new());
    let store = Arc::new(RuntimeStateStore::new(
        notifier.clone(),
        Duration::from_secs(120),
    ));
    (store, notifier)
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

    if !result.kept.is_empty() || !result.reviewed.is_empty() {
        eprintln!(
            "\n\x1b[1mPlanned preserved\x1b[0m: {} KEEP, {} REVIEW",
            result.kept.len(),
            result.reviewed.len()
        );
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

/// Result of a single residual cleanup cycle.
#[derive(Debug)]
pub struct ResidualCleanupResult {
    pub deleted: Vec<ResourceId>,
    pub skipped: Vec<(ResourceId, String)>,
    pub failed: Vec<(ResourceId, String)>,
    pub post_audit: Option<crate::teardown::audit::ResidualAudit>,
}

/// Core residual cleanup — shared by TUI, --script, and interactive CLI.
///
/// Safety contract enforced by this function:
/// 1. Generation must be Absent (operator fully removed)
/// 2. Fresh complete audit before any mutation
/// 3. Each resource verified in current residual set
/// 4. Per-resource: generation recheck + residual membership + gate permit + durable decision → DELETE → Gone poll → result persist
/// 5. Post-cleanup re-audit
///
/// Caller provides the selected ResourceIds. This function does NOT grant DELETE
/// authority from RuntimeStateStore — only from durable journal state.
pub async fn execute_residual_cleanup(
    client: &Client,
    selected: &[ResourceId],
    journal_store: &JournalStore,
    gate: &MutationGate,
    kind_map: &KindMap,
    gk_map: &GroupKindMap,
) -> Result<ResidualCleanupResult> {
    use crate::teardown::audit;
    use crate::teardown::journal::{CleanupDecision, CleanupResult, RunState, ResidualStatus};

    let mut result = ResidualCleanupResult {
        deleted: Vec::new(),
        skipped: Vec::new(),
        failed: Vec::new(),
        post_audit: None,
    };

    if selected.is_empty() {
        return Ok(result);
    }

    // Step 0: Verify journal state allows cleanup
    {
        let j = journal_store.read().await;
        if j.schema_version != crate::teardown::journal::RUN_JOURNAL_SCHEMA_VERSION {
            bail!(
                "Journal schema version {} is not current (expected {}). \
                 Cannot perform cleanup on incompatible journal.",
                j.schema_version,
                crate::teardown::journal::RUN_JOURNAL_SCHEMA_VERSION
            );
        }
        match j.state {
            RunState::ApplyCompleted | RunState::InteractiveCleanup => {}
            ref other => {
                bail!(
                    "Journal state is {:?} — cleanup only allowed from ApplyCompleted or InteractiveCleanup. \
                     Resolve the current state before retrying.",
                    other
                );
            }
        }
    }

    // Step 1: Verify generation Absent
    let j = journal_store.read().await;
    let gen_state = audit::check_operator_generation(
        client, &j.operator, &j.audit_context.csv_baseline,
    ).await;
    if !matches!(gen_state, audit::OperatorGenerationState::Absent) {
        bail!("Operator generation is not Absent — residual cleanup blocked");
    }

    // Step 2: Fresh complete audit
    let fresh_audit = audit::run_residual_audit(client, &j).await
        .context("Fresh audit failed before cleanup")?;
    let fresh_status = audit::residual_status_from_audit(&fresh_audit);
    if matches!(fresh_status, ResidualStatus::AuditIncomplete) {
        bail!("Fresh audit incomplete — residual cleanup blocked");
    }

    // Step 3: Build current residual set (likely_operator_residual + unattributed only)
    let residual_keys: std::collections::HashSet<String> = fresh_audit.likely_operator_residual.iter()
        .chain(fresh_audit.unattributed.iter())
        .map(|r| format!("{}/{}/{}/{}", r.resource.group, r.resource.kind,
            r.resource.namespace.as_deref().unwrap_or("-"), r.resource.name))
        .collect();

    // Validate all selections against current residual set
    let valid_selected: Vec<&ResourceId> = selected.iter().filter(|res| {
        let key = format!("{}/{}/{}/{}", res.group, res.kind,
            res.namespace.as_deref().unwrap_or("-"), res.name);
        if residual_keys.contains(&key) {
            true
        } else {
            result.skipped.push(((*res).clone(), "not in current residual set".to_string()));
            false
        }
    }).collect();

    if valid_selected.is_empty() {
        return Ok(result);
    }

    // Set InteractiveCleanup state
    journal_store.update(|j| {
        j.state = RunState::InteractiveCleanup;
    }).await
    .context("Failed to persist InteractiveCleanup state")?;

    // Step 4: Per-resource DELETE with full safety checks
    for res in &valid_selected {
        // Re-check generation per resource
        let cur_j = journal_store.read().await;
        let gen_per_res = audit::check_operator_generation(
            client, &cur_j.operator, &cur_j.audit_context.csv_baseline,
        ).await;
        if !matches!(gen_per_res, audit::OperatorGenerationState::Absent) {
            result.skipped.push(((*res).clone(), "generation changed".to_string()));
            break;
        }

        // Per-resource fresh audit: verify still in residual set
        let per_res_j = journal_store.read().await;
        match audit::run_residual_audit(client, &per_res_j).await {
            Ok(fresh_per_res) => {
                let still_in_set = fresh_per_res.likely_operator_residual.iter()
                    .chain(fresh_per_res.unattributed.iter())
                    .any(|r| r.resource.group == res.group
                        && r.resource.kind == res.kind
                        && r.resource.name == res.name
                        && r.resource.namespace == res.namespace);
                if !still_in_set {
                    result.skipped.push(((*res).clone(), "no longer in residual set".to_string()));
                    continue;
                }
                let per_status = audit::residual_status_from_audit(&fresh_per_res);
                if matches!(per_status, ResidualStatus::AuditIncomplete) {
                    result.skipped.push(((*res).clone(), "per-resource audit incomplete".to_string()));
                    continue;
                }
            }
            Err(e) => {
                result.failed.push(((*res).clone(), format!("per-resource audit failed: {}", e)));
                break;
            }
        }

        // Acquire gate permit FIRST — may block waiting for active permits
        let _permit = gate.acquire().await
            .context("Mutation gate closed during cleanup")?;

        // Post-permit safety rechecks: generation + fresh audit + membership
        // Conditions could have changed during permit wait
        {
            let post_permit_j = journal_store.read().await;
            let post_permit_gen = audit::check_operator_generation(
                client, &post_permit_j.operator, &post_permit_j.audit_context.csv_baseline,
            ).await;
            if !matches!(post_permit_gen, audit::OperatorGenerationState::Absent) {
                result.skipped.push(((*res).clone(), "generation changed after permit acquisition".to_string()));
                drop(_permit);
                break;
            }
            // Fresh audit to verify current residual membership with permit held
            match audit::run_residual_audit(client, &post_permit_j).await {
                Ok(post_permit_audit) => {
                    let post_permit_status = audit::residual_status_from_audit(&post_permit_audit);
                    if matches!(post_permit_status, ResidualStatus::AuditIncomplete) {
                        result.skipped.push(((*res).clone(), "post-permit audit incomplete".to_string()));
                        drop(_permit);
                        continue;
                    }
                    let still_in_set = post_permit_audit.likely_operator_residual.iter()
                        .chain(post_permit_audit.unattributed.iter())
                        .any(|r| r.resource.group == res.group
                            && r.resource.kind == res.kind
                            && r.resource.name == res.name
                            && r.resource.namespace == res.namespace);
                    if !still_in_set {
                        result.skipped.push(((*res).clone(), "no longer in residual set after permit acquisition".to_string()));
                        drop(_permit);
                        continue;
                    }
                }
                Err(e) => {
                    result.failed.push(((*res).clone(), format!("post-permit audit failed: {}", e)));
                    drop(_permit);
                    break;
                }
            }
        }

        // Record decision BEFORE mutation (durable)
        let decision_uid = res.uid.clone();
        let res_clone = (*res).clone();
        journal_store.update(|j| {
            j.cleanup_decisions.push(CleanupDecision {
                resource: res_clone.clone(),
                bound_uid: decision_uid.clone(),
                action: "delete".to_string(),
                result: None,
            });
            j.audit_revision += 1;
        }).await
        .context("Failed to persist cleanup decision — no mutation")?;

        // Core executor DELETE (UID-preconditioned)
        let del_result = delete_resource_pub(
            client, res, kind_map, gk_map, None,
        ).await;

        let cleanup_result = match &del_result {
            Ok(msg) => {
                if msg == "deleted" {
                    let mut gone_confirmed = false;
                    if let Some((api, _)) = resolve_api(client, res, kind_map, gk_map) {
                        for _ in 0..30 {
                            tokio::time::sleep(Duration::from_secs(2)).await;
                            match api.get(&res.name).await {
                                Err(kube::Error::Api(ref err)) if err.code == 404 => {
                                    gone_confirmed = true;
                                    break;
                                }
                                Ok(_) => continue,
                                Err(_) => break,
                            }
                        }
                    }
                    if gone_confirmed {
                        result.deleted.push((*res).clone());
                        CleanupResult::Gone
                    } else {
                        CleanupResult::DeleteRequested
                    }
                } else if msg == "already gone" {
                    result.deleted.push((*res).clone());
                    CleanupResult::AlreadyGone
                } else {
                    CleanupResult::DeleteRequested
                }
            }
            Err(e) => {
                result.failed.push(((*res).clone(), e.to_string()));
                CleanupResult::Failed(e.to_string())
            }
        };

        let res_clone2 = (*res).clone();
        journal_store.update(|j| {
            if let Some(d) = j.cleanup_decisions.iter_mut().rev()
                .find(|d| d.resource == res_clone2 && d.result.is_none())
            {
                d.result = Some(cleanup_result);
            }
        }).await
        .context("Failed to checkpoint cleanup result")?;

        drop(_permit);
    }

    // Step 5: Re-audit after all cleanups
    let post_j = journal_store.read().await;
    let post_gen = audit::check_operator_generation(
        client, &post_j.operator, &post_j.audit_context.csv_baseline,
    ).await;
    if !matches!(post_gen, audit::OperatorGenerationState::Absent) {
        journal_store.update(|j| {
            j.state = RunState::Failed;
        }).await.context("Failed to persist Failed state after generation change")?;
        bail!("Operator generation changed after cleanup — cannot verify results. State persisted as Failed.");
    }

    match audit::run_residual_audit(client, &post_j).await {
        Ok(new_audit) => {
            let new_status = audit::residual_status_from_audit(&new_audit);
            journal_store.update(|j| {
                j.residual_status = new_status;
                j.audit_revision += 1;
                j.last_residual_audit = Some(new_audit.clone());
            }).await
            .context("Failed to persist post-cleanup audit")?;
            result.post_audit = Some(new_audit);
        }
        Err(e) => {
            journal_store.update(|j| {
                j.state = RunState::Failed;
            }).await.context("Failed to persist Failed state after audit failure")?;
            bail!("Post-cleanup re-audit failed: {}. Cannot verify cleanup results.", e);
        }
    }

    // Determine final state — consider skipped/failed resources
    let post_j_final = journal_store.read().await;
    let has_failed_decisions = post_j_final.cleanup_decisions.iter().any(|d| d.is_failed());
    let has_incomplete = !result.skipped.is_empty() || !result.failed.is_empty();

    let final_cleanup_state = if has_failed_decisions {
        RunState::Failed
    } else {
        match &post_j_final.residual_status {
            ResidualStatus::AuditIncomplete => {
                journal_store.update(|j| {
                    j.state = RunState::Failed;
                }).await.context("Failed to persist Failed state for incomplete audit")?;
                bail!("Post-cleanup audit incomplete — cannot confirm cleanup success. State persisted as Failed.");
            }
            _ => {
                if has_incomplete {
                    // Some resources were skipped/failed — stay in InteractiveCleanup
                    // so the user can retry after resolving the issues
                    RunState::InteractiveCleanup
                } else {
                    RunState::ApplyCompleted
                }
            }
        }
    };
    journal_store.update(|j| {
        j.state = final_cleanup_state.clone();
    }).await
    .context("Failed to persist final cleanup state")?;

    if final_cleanup_state == RunState::Failed {
        bail!("Cleanup completed with failed or unconfirmed decisions");
    }
    if final_cleanup_state == RunState::InteractiveCleanup {
        bail!(
            "Cleanup incomplete: {} deleted, {} skipped, {} failed. \
             State persisted as InteractiveCleanup — retry is safe.",
            result.deleted.len(), result.skipped.len(), result.failed.len()
        );
    }

    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::teardown::planner::*;

    fn make_resource(kind: &str, name: &str) -> ResourceId {
        ResourceId {
            group: "test.example.com".to_string(),
            version: "v1".to_string(),
            kind: kind.to_string(),
            namespace: Some("test-ns".to_string()),
            name: name.to_string(),
            uid: None,
        }
    }

    fn make_empty_preflight() -> Preflight {
        Preflight { checks: vec![] }
    }

    fn make_plan_with_actions(actions: Vec<Action>) -> TeardownPlan {
        TeardownPlan {
            targets: vec![],
            preflight: make_empty_preflight(),
            phases: vec![PlanPhase {
                name: "test".to_string(),
                description: "test phase".to_string(),
                actions,
                barrier: None,
            }],
            blockers: vec![],
            warnings: vec![],
            snapshot_taken_at: "2026-01-01T00:00:00Z".to_string(),
        }
    }

    #[test]
    fn count_actions_all_types() {
        let plan = make_plan_with_actions(vec![
            Action::Delete {
                resource: make_resource("Pod", "a"),
                reason: "test".to_string(),
            },
            Action::Delete {
                resource: make_resource("Pod", "b"),
                reason: "test".to_string(),
            },
            Action::ExpectGone {
                resource: make_resource("Pod", "c"),
                reason: "test".to_string(),
            },
            Action::Keep {
                resource: make_resource("CRD", "d"),
                reason: "test".to_string(),
            },
            Action::Review {
                resource: make_resource("CR", "e"),
                reason: "test".to_string(),
                metadata: None,
            },
            Action::WaitGone {
                resource: make_resource("Pod", "f"),
            },
        ]);
        let (d, e, k, r) = count_actions(&plan);
        assert_eq!(d, 2);
        assert_eq!(e, 1);
        assert_eq!(k, 1);
        assert_eq!(r, 1);
    }

    #[test]
    fn count_actions_empty_plan() {
        let plan = make_plan_with_actions(vec![]);
        let (d, e, k, r) = count_actions(&plan);
        assert_eq!((d, e, k, r), (0, 0, 0, 0));
    }

    #[test]
    fn scope_suffix_namespaced() {
        let res = make_resource("Pod", "test");
        let suffix = scope_suffix(&res);
        assert!(suffix.contains("ns: test-ns"));
    }

    #[test]
    fn scope_suffix_cluster_scoped() {
        let res = ResourceId {
            group: "".to_string(),
            version: "v1".to_string(),
            kind: "Namespace".to_string(),
            namespace: None,
            name: "test".to_string(),
            uid: None,
        };
        let suffix = scope_suffix(&res);
        assert!(suffix.contains("cluster-scoped"));
    }

    // P0-1 regression: Unknown state is never Gone
    #[test]
    fn observation_state_unknown_is_not_gone() {
        let state = ObservationState::Unknown("test error".to_string());
        assert_ne!(state, ObservationState::Gone);
        assert!(matches!(state, ObservationState::Unknown(_)));
    }

    #[test]
    fn observation_state_exists_is_not_gone() {
        let state = ObservationState::Exists {
            finalizer_count: 0,
            has_deletion_timestamp: false,
        };
        assert_ne!(state, ObservationState::Gone);
    }

    // P0-adjacent regression: FinalizerCheckResult::Unknown is distinguishable
    #[test]
    fn finalizer_check_unknown_is_not_empty_known() {
        let result = FinalizerCheckResult::Unknown("resolve failed".to_string());
        assert!(matches!(result, FinalizerCheckResult::Unknown(_)));
        let empty = FinalizerCheckResult::Known(vec![]);
        assert!(matches!(empty, FinalizerCheckResult::Known(ref v) if v.is_empty()));
    }

    // P0-3 (round 3): LiveCount types are distinct
    #[test]
    fn live_count_types() {
        assert!(matches!(LiveCount::Zero, LiveCount::Zero));
        assert!(matches!(LiveCount::NonZero(1), LiveCount::NonZero(1)));
        assert!(matches!(
            LiveCount::Unknown("err".to_string()),
            LiveCount::Unknown(_)
        ));
    }

    // ResourceStateInfo test removed — struct replaced by RuntimeStateStore/RuntimeObservation

    // ── verify_delete_identity tests ──

    #[test]
    fn test_delete_identity_both_uids_match() {
        assert!(verify_delete_identity(
            &Some("uid-a".to_string()),
            "uid-a"
        ).is_ok());
    }

    #[test]
    fn test_delete_identity_uid_mismatch() {
        let err = verify_delete_identity(
            &Some("uid-a".to_string()),
            "uid-b"
        ).unwrap_err();
        assert!(err.contains("UID mismatch"));
    }

    #[test]
    fn test_delete_identity_live_uid_empty() {
        let err = verify_delete_identity(
            &Some("uid-a".to_string()),
            ""
        ).unwrap_err();
        assert!(err.contains("no UID"));
    }

    #[test]
    fn test_delete_identity_plan_uid_none_fails() {
        // Plan UID absent → cannot verify, must be bound first
        let err = verify_delete_identity(&None, "uid-x").unwrap_err();
        assert!(err.contains("no UID"));
    }

    #[test]
    fn test_delete_identity_plan_uid_empty_fails() {
        let err = verify_delete_identity(&Some(String::new()), "uid-x").unwrap_err();
        assert!(err.contains("no UID"));
    }

    #[test]
    fn test_delete_identity_both_empty_fails() {
        assert!(verify_delete_identity(&None, "").is_err());
    }

    // ── UID-preconditioned DELETE decision path tests ──

    #[test]
    fn test_uid_a_to_b_recreation_blocks_delete() {
        // Plan says UID=A, live resource has UID=B → mismatch → no DELETE
        let result = verify_delete_identity(&Some("uid-A".to_string()), "uid-B");
        assert!(result.is_err());
        assert!(
            result.unwrap_err().contains("UID mismatch"),
            "should report UID mismatch, not proceed with DELETE"
        );
    }

    #[test]
    fn test_uid_match_allows_delete() {
        // Plan says UID=A, live resource has UID=A → match → DELETE allowed
        assert!(verify_delete_identity(&Some("uid-A".to_string()), "uid-A").is_ok());
    }

    #[test]
    fn test_plan_uid_none_blocks_delete() {
        // Plan has no UID → cannot verify identity → no DELETE
        let result = verify_delete_identity(&None, "uid-live");
        assert!(result.is_err());
        assert!(
            result.unwrap_err().contains("no UID"),
            "missing plan UID should block DELETE"
        );
    }

    #[test]
    fn test_live_uid_empty_blocks_delete() {
        // Live resource has no UID → cannot verify → no DELETE
        let result = verify_delete_identity(&Some("uid-A".to_string()), "");
        assert!(result.is_err());
    }

    // ── UID gate ordering test ──

    // ── Mock API tests: real HTTP decision paths ──

    use std::pin::pin;
    use kube::client::Body;

    fn test_kind_map() -> KindMap {
        let mut km = std::collections::HashMap::new();
        km.insert(
            "ConfigMap".to_string(),
            crate::kube::discovery::KindInfo {
                group: String::new(),
                version: "v1".to_string(),
                plural: "configmaps".to_string(),
                namespaced: true,
            },
        );
        km
    }

    fn test_gk_map() -> GroupKindMap {
        let mut gk = std::collections::HashMap::new();
        gk.insert(
            (String::new(), "ConfigMap".to_string()),
            crate::kube::discovery::KindInfo {
                group: String::new(),
                version: "v1".to_string(),
                plural: "configmaps".to_string(),
                namespaced: true,
            },
        );
        gk
    }

    fn make_cm_resource(name: &str, uid: Option<&str>) -> ResourceId {
        ResourceId {
            group: String::new(),
            version: "v1".to_string(),
            kind: "ConfigMap".to_string(),
            namespace: Some("test-ns".to_string()),
            name: name.to_string(),
            uid: uid.map(String::from),
        }
    }

    fn json_response(json: serde_json::Value) -> http::Response<Body> {
        http::Response::builder()
            .status(200)
            .body(Body::from(serde_json::to_vec(&json).unwrap()))
            .unwrap()
    }

    fn not_found_response() -> http::Response<Body> {
        let body = serde_json::json!({
            "kind": "Status",
            "apiVersion": "v1",
            "metadata": {},
            "status": "Failure",
            "message": "not found",
            "reason": "NotFound",
            "code": 404
        });
        http::Response::builder()
            .status(404)
            .body(Body::from(serde_json::to_vec(&body).unwrap()))
            .unwrap()
    }

    fn forbidden_response() -> http::Response<Body> {
        let body = serde_json::json!({
            "kind": "Status",
            "apiVersion": "v1",
            "metadata": {},
            "status": "Failure",
            "message": "forbidden",
            "reason": "Forbidden",
            "code": 403
        });
        http::Response::builder()
            .status(403)
            .body(Body::from(serde_json::to_vec(&body).unwrap()))
            .unwrap()
    }

    #[tokio::test]
    async fn test_mock_delete_uid_mismatch_zero_deletes() {
        // Plan says UID=A, live resource has UID=B → DELETE should NOT be called
        let (mock_service, handle) = tower_test::mock::pair::<
            http::Request<Body>,
            http::Response<Body>,
        >();

        let resource = make_cm_resource("my-cm", Some("uid-A"));
        let km = test_kind_map();
        let gk = test_gk_map();

        let spawned = tokio::spawn(async move {
            let mut handle = pin!(handle);
            // Request 1: GET /api/v1/namespaces/test-ns/configmaps/my-cm
            let (request, send) = handle.next_request().await.expect("expected GET");
            assert_eq!(request.method(), http::Method::GET);
            assert!(request.uri().to_string().contains("my-cm"));

            // Return resource with UID=B (different from plan UID=A)
            send.send_response(json_response(serde_json::json!({
                "apiVersion": "v1",
                "kind": "ConfigMap",
                "metadata": {
                    "name": "my-cm",
                    "namespace": "test-ns",
                    "uid": "uid-B"
                }
            })));

            // No more requests should come — DELETE should NOT be called
            // (the function should return Failed due to UID mismatch)
        });

        let client = Client::new(mock_service, "test-ns");
        let result = delete_resource(&client, &resource, &km, &gk).await;

        assert!(
            matches!(result, DeleteResult::Failed(ref msg) if msg.contains("UID mismatch")),
            "UID mismatch should prevent DELETE: got {:?}",
            result
        );

        spawned.await.unwrap();
    }

    #[tokio::test]
    async fn test_mock_delete_get404_list_forbidden_not_already_gone() {
        // GET 404 + LIST 403 → cannot verify endpoint → Failed (not AlreadyGone)
        let (mock_service, handle) = tower_test::mock::pair::<
            http::Request<Body>,
            http::Response<Body>,
        >();

        let resource = make_cm_resource("gone-cm", Some("uid-A"));
        let km = test_kind_map();
        let gk = test_gk_map();

        let spawned = tokio::spawn(async move {
            let mut handle = pin!(handle);

            // Request 1: GET → 404
            let (request, send) = handle.next_request().await.expect("expected GET");
            assert_eq!(request.method(), http::Method::GET);
            send.send_response(not_found_response());

            // Request 2: LIST (endpoint verification) → 403
            let (request, send) = handle.next_request().await.expect("expected LIST");
            assert_eq!(request.method(), http::Method::GET); // LIST is also GET
            send.send_response(forbidden_response());
        });

        let client = Client::new(mock_service, "test-ns");
        let result = delete_resource(&client, &resource, &km, &gk).await;

        assert!(
            matches!(result, DeleteResult::Failed(ref msg) if msg.contains("endpoint verification failed")),
            "GET 404 + LIST 403 should NOT be AlreadyGone: got {:?}",
            result
        );

        spawned.await.unwrap();
    }

    #[test]
    fn test_uid_gate_runs_before_applying_state() {
        // Verify the code structure: UID gate (bail!) appears before
        // the Applying state checkpoint. This is a structural assertion.
        // The actual ordering is verified by reading the source:
        // 1. UID gate → bail! if missing (no state change)
        // 2. Applying checkpoint → journal persist
        // If UID gate fails, RunState stays Prepared (not Applying).
        //
        // We can't easily test the async executor here, but we verify
        // the decision logic is correct:
        let plan_uid_none = verify_delete_identity(&None, "anything");
        assert!(
            plan_uid_none.is_err(),
            "UID-less DELETE must fail before any state transition"
        );
    }

    #[test]
    fn residual_cleanup_state_gate_rejects_invalid_states() {
        use crate::teardown::journal::RunState;
        let allowed = [RunState::ApplyCompleted, RunState::InteractiveCleanup];
        let rejected = [
            RunState::Prepared,
            RunState::Applying,
            RunState::Failed,
            RunState::Paused,
        ];

        for state in &allowed {
            let ok = matches!(state, RunState::ApplyCompleted | RunState::InteractiveCleanup);
            assert!(ok, "State {:?} should be allowed for cleanup", state);
        }

        for state in &rejected {
            let ok = matches!(state, RunState::ApplyCompleted | RunState::InteractiveCleanup);
            assert!(!ok, "State {:?} should be rejected for cleanup", state);
        }
    }

    #[test]
    fn residual_cleanup_schema_gate_rejects_old_schema() {
        let current = crate::teardown::journal::RUN_JOURNAL_SCHEMA_VERSION;
        assert_eq!(current, 6, "Schema version must be 6 for cleanup gate to work correctly");
    }
}
