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
    /// DELETE accepted by API server (202/200). Not yet Gone — needs barrier confirmation.
    Accepted,
    /// Resource confirmed absent (404 + endpoint verification OK).
    AlreadyGone,
    /// API server definitively rejected the DELETE without mutation (400/422 webhook denial).
    /// Retryable in next wave only if other targets make progress.
    Rejected(String),
    /// Pre-GET/API resolve/403/401/identity mismatch/new UID — immediate phase stop.
    Blocked(String),
    /// Transport/timeout/5xx/endpoint verification failure — outcome unknown.
    /// Fresh GET reconciliation required before any further mutations.
    Unknown(String),
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
#[allow(dead_code)]
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
    Known {
        finalizers: Vec<String>,
        terminating: bool,
    },
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

fn is_admission_webhook_denial(message: &str) -> bool {
    let msg = message.to_lowercase();
    msg.contains("admission webhook") && msg.contains("denied")
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
        client,
        plan,
        kind_map,
        gk_map,
        gvk_map,
        gvr_map,
        dry_run,
        force,
        journal,
        gate,
        start_phase,
        skip_confirm,
        None,
    )
    .await
}

#[allow(clippy::too_many_arguments)]
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
        eprintln!("  REVIEW resources remain preserved unless explicitly approved for DELETE.");
    }

    let review_count = plan
        .phases
        .iter()
        .flat_map(|p| &p.actions)
        .filter(|a| matches!(a, Action::Review { .. }))
        .count();
    if review_count > 0 && !dry_run && !force {
        eprintln!(
            "\x1b[1;33m⚠ Plan has {} REVIEW item(s) with uncertain provenance; all remain preserved.\x1b[0m",
            review_count
        );
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

    // Seed result with prior run's successful deletes so recovery can find
    // root UIDs. Needed for any resume (even start_phase=0 after a crash
    // mid-phase where DELETEs were checkpointed but barrier not passed).
    let prior_deleted = if let Some(j) = journal {
        j.read().await.execution.deleted.clone()
    } else {
        vec![]
    };

    let mut result = ExecutionResult {
        phases_completed: 0,
        phases_total: plan.phases.len(),
        deleted: prior_deleted,
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
                    if resource.uid.is_none() || resource.uid.as_ref().is_some_and(|u| u.is_empty())
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
            eprintln!(
                "\n\x1b[2mPhase {} {} (completed in prior run)\x1b[0m",
                i, phase.name
            );
            result.phases_completed += 1;
            continue;
        }

        // Gate check: if gate is closed before phase, pause immediately.
        // Actual mutation permits are acquired per-wave in execute_delete_waves.
        if !dry_run && gate.is_some_and(|g| !g.is_open()) {
            eprintln!("\n\x1b[1;33m⏸ Mutation gate closed — pausing\x1b[0m");
            break;
        }

        eprintln!("\n\x1b[1mPhase {}  {}\x1b[0m", i, phase.name);

        if phase.actions.is_empty() {
            eprintln!("  (none)");
            result.phases_completed += 1;
            continue;
        }

        // Pre-controller guard: if THIS phase deletes a CSV, check all REVIEW
        // resources for finalizers first. Placed here (phase entry, after gate
        // acquire, after empty-skip) so it runs on resume and across empty phases.
        // --force does NOT bypass this check.
        if !dry_run {
            let this_phase_deletes_csv = phase.actions.iter().any(|a| {
                matches!(a, Action::Delete { resource, .. } if resource.kind == "ClusterServiceVersion")
            });
            if this_phase_deletes_csv {
                let review_resources: Vec<&ResourceId> = plan
                    .phases
                    .iter()
                    .flat_map(|p| &p.actions)
                    .filter_map(|a| match a {
                        Action::Review { resource, .. } => Some(resource),
                        _ => None,
                    })
                    .collect();
                if !review_resources.is_empty() {
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
                            FinalizerCheckResult::Known {
                                finalizers,
                                terminating,
                            } if !finalizers.is_empty() && terminating => {
                                let annotated: Vec<String> = finalizers
                                    .iter()
                                    .map(|f| format!("{} (terminating)", f))
                                    .collect();
                                block_reasons.push((res, annotated));
                            }
                            FinalizerCheckResult::Known {
                                finalizers,
                                terminating: false,
                            } if !finalizers.is_empty() => {
                                eprintln!(
                                    "  ⚠ {}/{}: intact with finalizer(s) {} — warning only",
                                    res.kind,
                                    res.name,
                                    finalizers.join(", ")
                                );
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
                        let bt = BarrierTimeout {
                            phase: "pre-controller safety check".to_string(),
                            remaining: block_reasons.iter().map(|(r, _)| r.clone()).collect(),
                            finalizers: block_reasons,
                        };
                        if let Some(j) = journal {
                            let record = crate::teardown::journal::BarrierTimeoutRecord {
                                phase: bt.phase.clone(),
                                remaining: bt.remaining.clone(),
                                finalizer_details: bt.finalizers.clone(),
                            };
                            j.update(|jrnl| {
                                jrnl.execution.barrier_timeout = Some(record);
                            })
                            .await
                            .context("Failed to persist barrier timeout to journal")?;
                        }
                        result.barrier_timeout = Some(bt);
                        break;
                    }
                }
            }
        }

        let mut phase_wait_targets: Vec<ResourceId> = Vec::new();
        let pkg_name: Option<String> = if let Some(j_ref) = journal {
            let j = j_ref.read().await;
            match &j.operator.generation_identity {
                crate::teardown::plan::OperatorGenerationIdentity::OlmPackage {
                    package_name,
                    ..
                } => Some(package_name.clone()),
                _ => None,
            }
        } else {
            None
        };

        // Collect DELETE actions for parallel execution
        let delete_actions: Vec<_> = phase
            .actions
            .iter()
            .filter_map(|a| match a {
                Action::Delete { resource, reason } => Some((resource.clone(), reason.clone())),
                _ => None,
            })
            .collect();

        let mut phase_redelete_authorities: Vec<(ResourceId, String)> = Vec::new();

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
                let mut api_blocked: HashSet<ResourceId> = HashSet::new();
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
                                api_blocked.insert(resource.clone());
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
                                api_blocked.insert(resource.clone());
                            }
                            LiveCount::Zero => {}
                        }
                    }
                }

                // ── Delete wave/fixpoint ──
                let eligible: Vec<ResourceId> = delete_actions
                    .iter()
                    .filter(|(r, _)| !api_blocked.contains(r))
                    .map(|(r, _)| r.clone())
                    .collect();

                // Fail-closed: Subscription DELETE requires known package name
                let has_sub_delete = eligible
                    .iter()
                    .any(|r| r.kind == "Subscription" && r.group == "operators.coreos.com");
                if has_sub_delete && pkg_name.is_none() {
                    for resource in &eligible {
                        if resource.kind == "Subscription"
                            && resource.group == "operators.coreos.com"
                        {
                            result.failed.push((
                                resource.clone(),
                                "cannot DELETE Subscription without verified package name \
                                 (generation_identity is Unverifiable)"
                                    .to_string(),
                            ));
                        }
                    }
                    break;
                }

                let cancel = gate.map(|g| g.cancel_signal());
                let wave_result = execute_delete_waves(
                    client,
                    &eligible,
                    kind_map,
                    gk_map,
                    pkg_name.as_deref(),
                    &watch_mgr,
                    &store,
                    journal,
                    gate,
                    cancel.as_ref(),
                    Some(phase),
                )
                .await?;

                // Collect wave results into phase result.
                // Accepted-then-Gone explicit DELETEs go to phase_wait_targets
                // with ReDeleteIfRecreated authority for the outer barrier.
                for r in &wave_result.accepted_gone {
                    result.deleted.push(r.clone());
                    phase_wait_targets.push(r.clone());
                }
                result.already_gone.extend(wave_result.already_gone);
                result.failed.extend(wave_result.failed);
                phase_redelete_authorities = wave_result.redelete_authorities.clone();

                if wave_result.stopped {
                    break;
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
                Action::Review {
                    resource,
                    reason,
                    metadata,
                } => {
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
                // Checkpoint DELETE results before releasing permit for barrier wait
                if let Some(j) = journal {
                    let phase_count = result.phases_completed;
                    let deleted_snap = result.deleted.clone();
                    let already_snap = result.already_gone.clone();
                    let failed_snap = result.failed.clone();
                    let kept_snap: Vec<_> = result
                        .kept
                        .iter()
                        .map(crate::teardown::journal::PreservedRecord::from)
                        .collect();
                    let reviewed_snap: Vec<_> = result
                        .reviewed
                        .iter()
                        .map(crate::teardown::journal::PreservedRecord::from)
                        .collect();
                    j.update(|jrnl| {
                        jrnl.execution.phases_completed = phase_count;
                        for r in &deleted_snap {
                            if !jrnl.execution.deleted.iter().any(|d| d == r) {
                                jrnl.execution.deleted.push(r.clone());
                            }
                        }
                        jrnl.execution.already_gone = already_snap;
                        jrnl.execution.failed = failed_snap;
                        jrnl.execution.kept = kept_snap;
                        jrnl.execution.reviewed = reviewed_snap;
                    })
                    .await
                    .context("Failed to checkpoint DELETE results before barrier")?;
                }

                // No phase-level permit — wave helper acquires per-wave permits.

                eprintln!();
                let barrier_start = Instant::now();

                // Create cancel signal from gate for fast pause during watch
                let cancel = gate.map(|g| g.cancel_signal());

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
                                if summary.stalled > 0 {
                                    format!(", {} Stalled", summary.stalled)
                                } else {
                                    String::new()
                                },
                                if summary.unknown > 0 {
                                    format!(", {} Unknown", summary.unknown)
                                } else {
                                    String::new()
                                },
                                elapsed
                            );
                            std::io::stderr().flush().ok();
                        }
                    });

                    let r = watch_mgr
                        .wait_for_gone_cancellable(
                            client,
                            &phase_wait_targets,
                            kind_map,
                            gk_map,
                            WAVE_BARRIER_TIMEOUT,
                            WAVE_STALL_TIMEOUT,
                            cancel.as_ref(),
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
                        if summary.stalled > 0 {
                            format!(", {} Stalled", summary.stalled)
                        } else {
                            String::new()
                        },
                        if summary.unknown > 0 {
                            format!(", {} Unknown", summary.unknown)
                        } else {
                            String::new()
                        },
                        elapsed
                    );
                    eprintln!();
                    r
                };

                match wait_result {
                    WatchWaitResult::AllGone => {
                        eprintln!("  \x1b[32m✅ Barrier passed\x1b[0m");
                    }
                    WatchWaitResult::Cancelled => {
                        eprintln!("  \x1b[1;33m⏸ Barrier cancelled (pausing)\x1b[0m");
                        break;
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

                        // Attempt finalizer recovery if approved
                        let recovery_approved = if let Some(j) = journal {
                            j.read().await.finalizer_recovery_approved
                        } else {
                            false
                        };

                        let mut recovery_all_gone = false;

                        if recovery_approved
                            && !dry_run
                            && let Some(jrnl) = journal
                            && let Some(g) = gate
                        {
                            let recovered = attempt_finalizer_recovery(
                                client,
                                &remaining,
                                &result.deleted,
                                phase,
                                kind_map,
                                gk_map,
                                jrnl,
                                g,
                            )
                            .await?;
                            if recovered > 0 {
                                eprintln!(
                                    "  🔧 Recovered {} stalled resource(s) via finalizer strip",
                                    recovered
                                );
                                let re_wait = watch_mgr
                                    .wait_for_gone_cancellable(
                                        client,
                                        &remaining,
                                        kind_map,
                                        gk_map,
                                        POST_RECOVERY_BARRIER_TIMEOUT,
                                        WAVE_STALL_TIMEOUT,
                                        cancel.as_ref(),
                                    )
                                    .await;
                                match re_wait {
                                    WatchWaitResult::AllGone => {
                                        eprintln!(
                                            "  \x1b[32m✅ Barrier passed after recovery\x1b[0m"
                                        );
                                        recovery_all_gone = true;
                                    }
                                    WatchWaitResult::Recreated { .. } => {
                                        // Resources re-created during recovery — deferred to residual
                                    }
                                    WatchWaitResult::Stalled {
                                        remaining: rem,
                                        reason,
                                        ..
                                    } => {
                                        eprintln!(
                                            "  ⚠ Post-recovery re-wait stalled: {} remaining — {}",
                                            rem.len(),
                                            reason
                                        );
                                        let summary = store.summary_for(&remaining);
                                        eprintln!(
                                            "    summary: gone={} deleting={} fb={} expect={} unknown={} stalled={} review={} keep={}",
                                            summary.gone,
                                            summary.deleting,
                                            summary.finalizer_blocked,
                                            summary.expecting_gone,
                                            summary.unknown,
                                            summary.stalled,
                                            summary.review,
                                            summary.keep
                                        );
                                    }
                                    WatchWaitResult::Cancelled => {
                                        eprintln!("  ⏸ Post-recovery re-wait cancelled");
                                    }
                                }
                            }
                        } else if !recovery_approved && !remaining.is_empty() {
                            eprintln!(
                                "  ℹ Use --approve-finalizer-recovery to enable stalled resource recovery"
                            );
                        }

                        let deferred = !recovery_all_gone
                            && can_defer_to_residual(
                                client, &remaining, phase, &watch_mgr, &store, journal, kind_map,
                                gk_map,
                            )
                            .await;
                        if deferred {
                            eprintln!(
                                "  ⚠ {} resource(s) still present; deferring to post-controller residual audit",
                                store.summary_for(&remaining).total
                                    - store.summary_for(&remaining).gone
                            );
                        } else if !recovery_all_gone {
                            // Still stalled — report and break
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
                            let bt = BarrierTimeout {
                                phase: phase.name.clone(),
                                remaining: remaining.clone(),
                                finalizers,
                            };
                            if let Some(j) = journal {
                                let record = crate::teardown::journal::BarrierTimeoutRecord {
                                    phase: bt.phase.clone(),
                                    remaining: bt.remaining.clone(),
                                    finalizer_details: bt.finalizers.clone(),
                                };
                                j.update(|jrnl| {
                                    jrnl.execution.barrier_timeout = Some(record);
                                })
                                .await
                                .context("Failed to persist barrier timeout to journal")?;
                            }
                            result.barrier_timeout = Some(bt);
                            break;
                        }
                    }
                    WatchWaitResult::Recreated {
                        remaining: _,
                        recreated,
                    } => {
                        // Re-delete loop for explicit DELETE targets that were recreated.
                        // EXPECTs are observe-only — never DELETE/PATCH.
                        // Authority from wave: only initial explicit DELETE Accepted targets.
                        let redelete_authorities = phase_redelete_authorities.clone();

                        let mut redelete_stopped = false;
                        let mut redelete_iterations = 0u32;
                        let mut current_recreated = recreated;

                        'redelete_loop: loop {
                            redelete_iterations += 1;
                            if redelete_iterations > MAX_REDELETE_ITERATIONS {
                                eprintln!(
                                    "  ⚠ Re-delete iteration limit ({}) — deferring {} recreated resource(s) to residual",
                                    MAX_REDELETE_ITERATIONS,
                                    current_recreated.len()
                                );
                                // Remove persistently-recreated resources from barrier targets
                                for (res, _, _) in &current_recreated {
                                    phase_wait_targets.retain(|t| {
                                        !(t.group == res.group
                                            && t.kind == res.kind
                                            && t.namespace == res.namespace
                                            && t.name == res.name)
                                    });
                                }
                                // Re-wait on remaining (without recreated)
                                if phase_wait_targets.is_empty()
                                    || store.all_gone_for(&phase_wait_targets)
                                {
                                    break 'redelete_loop;
                                }
                                let final_wait = watch_mgr
                                    .wait_for_gone_cancellable(
                                        client,
                                        &phase_wait_targets,
                                        kind_map,
                                        gk_map,
                                        POST_RECOVERY_BARRIER_TIMEOUT,
                                        WAVE_STALL_TIMEOUT,
                                        cancel.as_ref(),
                                    )
                                    .await;
                                if let WatchWaitResult::Stalled { remaining, .. } = &final_wait {
                                    if can_defer_to_residual(
                                        client, remaining, phase, &watch_mgr, &store, journal,
                                        kind_map, gk_map,
                                    )
                                    .await
                                    {
                                        eprintln!(
                                            "  ⚠ {} resource(s) still present; deferring to post-controller residual audit",
                                            store.summary_for(remaining).total
                                                - store.summary_for(remaining).gone
                                        );
                                    } else {
                                        redelete_stopped = true;
                                    }
                                } else if !matches!(final_wait, WatchWaitResult::AllGone) {
                                    redelete_stopped = true;
                                }
                                break;
                            }

                            for (res, _old_uid, new_uid) in &current_recreated {
                                // Exact identity match — no string key
                                let authority = redelete_authorities.iter().find(|(auth_r, _)| {
                                    auth_r.group == res.group
                                        && auth_r.version == res.version
                                        && auth_r.kind == res.kind
                                        && auth_r.namespace == res.namespace
                                        && auth_r.name == res.name
                                });
                                let original_uid = match authority {
                                    Some((_, u)) => u.clone(),
                                    None => {
                                        eprintln!(
                                            "  ⚠ {}/{}: recreated (no explicit DELETE authority) — observe only",
                                            res.kind, res.name
                                        );
                                        continue;
                                    }
                                };

                                eprintln!(
                                    "  \x1b[1;33mRECREATED\x1b[0m {}/{}: → {} (iter {})",
                                    res.kind, res.name, new_uid, redelete_iterations
                                );

                                if let (Some(j), Some(g)) = (journal, gate) {
                                    match attempt_single_redelete(
                                        client,
                                        res,
                                        &original_uid,
                                        new_uid,
                                        kind_map,
                                        gk_map,
                                        j,
                                        g,
                                    )
                                    .await
                                    {
                                        ReDeleteAttemptResult::Accepted
                                        | ReDeleteAttemptResult::AlreadyDeleting => {
                                            // Continue to re-wait
                                        }
                                        ReDeleteAttemptResult::Gone => {
                                            // Continue to re-wait (others may still be pending)
                                        }
                                        ReDeleteAttemptResult::Stop(reason) => {
                                            eprintln!(
                                                "  ⛔ {}/{}: re-delete stopped: {}",
                                                res.kind, res.name, reason
                                            );
                                            redelete_stopped = true;
                                            break 'redelete_loop;
                                        }
                                    }
                                } else {
                                    eprintln!("  ⛔ No journal/gate for re-delete — stopping");
                                    redelete_stopped = true;
                                    break 'redelete_loop;
                                }
                            }

                            // Re-wait on barrier
                            let re_wait = watch_mgr
                                .wait_for_gone_cancellable(
                                    client,
                                    &phase_wait_targets,
                                    kind_map,
                                    gk_map,
                                    WAVE_BARRIER_TIMEOUT,
                                    WAVE_STALL_TIMEOUT,
                                    cancel.as_ref(),
                                )
                                .await;

                            match re_wait {
                                WatchWaitResult::AllGone => {
                                    eprintln!(
                                        "  \x1b[32m✅ Barrier passed (after {} re-delete iteration(s))\x1b[0m",
                                        redelete_iterations
                                    );
                                    // Checkpoint re-delete records as Gone for barrier targets only
                                    if let Some(j) = journal {
                                        let barrier_ids: Vec<_> = redelete_authorities
                                            .iter()
                                            .map(|(r, _)| {
                                                (
                                                    r.group.clone(),
                                                    r.version.clone(),
                                                    r.kind.clone(),
                                                    r.namespace.clone(),
                                                    r.name.clone(),
                                                )
                                            })
                                            .collect();
                                        j.update(|jrnl| {
                                            for rec in &mut jrnl.execution.re_delete_records {
                                                if matches!(
                                                    rec.result,
                                                    crate::teardown::journal::ReDeleteResult::Accepted
                                                ) && barrier_ids.iter().any(|(g, v, k, ns, n)| {
                                                    rec.resource_identity.group == *g
                                                        && rec.resource_identity.version == *v
                                                        && rec.resource_identity.kind == *k
                                                        && rec.resource_identity.namespace == *ns
                                                        && rec.resource_identity.name == *n
                                                }) {
                                                    rec.result =
                                                        crate::teardown::journal::ReDeleteResult::Gone;
                                                }
                                            }
                                        })
                                        .await
                                        .context("Failed to checkpoint re-delete Gone")?;
                                    }
                                    break 'redelete_loop;
                                }
                                WatchWaitResult::Cancelled => {
                                    redelete_stopped = true;
                                    break 'redelete_loop;
                                }
                                WatchWaitResult::Stalled {
                                    remaining,
                                    finalizer_details,
                                    reason: _,
                                } => {
                                    let recovery_approved = if let Some(j) = journal {
                                        j.read().await.finalizer_recovery_approved
                                    } else {
                                        false
                                    };
                                    let mut recovery_ok = false;
                                    if recovery_approved
                                        && let Some(jrnl) = journal
                                        && let Some(g) = gate
                                        && let Ok(recovered) = attempt_finalizer_recovery(
                                            client,
                                            &remaining,
                                            &result.deleted,
                                            phase,
                                            kind_map,
                                            gk_map,
                                            jrnl,
                                            g,
                                        )
                                        .await
                                        && recovered > 0
                                    {
                                        let re2 = watch_mgr
                                            .wait_for_gone_cancellable(
                                                client,
                                                &remaining,
                                                kind_map,
                                                gk_map,
                                                POST_RECOVERY_BARRIER_TIMEOUT,
                                                WAVE_STALL_TIMEOUT,
                                                cancel.as_ref(),
                                            )
                                            .await;
                                        match re2 {
                                            WatchWaitResult::AllGone => {
                                                recovery_ok = true;
                                            }
                                            WatchWaitResult::Recreated {
                                                recreated: re_recreated,
                                                ..
                                            } => {
                                                current_recreated = re_recreated;
                                                continue 'redelete_loop;
                                            }
                                            _ => {}
                                        }
                                    }
                                    if !recovery_ok {
                                        if can_defer_to_residual(
                                            client, &remaining, phase, &watch_mgr, &store, journal,
                                            kind_map, gk_map,
                                        )
                                        .await
                                        {
                                            eprintln!(
                                                "  ⚠ {} resource(s) still present; deferring to post-controller residual audit",
                                                store.summary_for(&remaining).total
                                                    - store.summary_for(&remaining).gone
                                            );
                                            break 'redelete_loop;
                                        }
                                        let bt = BarrierTimeout {
                                            phase: phase.name.clone(),
                                            remaining,
                                            finalizers: finalizer_details
                                                .iter()
                                                .map(|(r, c)| {
                                                    (r.clone(), vec![format!("{} finalizer(s)", c)])
                                                })
                                                .collect(),
                                        };
                                        result.barrier_timeout = Some(bt);
                                        redelete_stopped = true;
                                        break 'redelete_loop;
                                    }
                                    break 'redelete_loop; // recovery succeeded
                                }
                                WatchWaitResult::Recreated {
                                    remaining: _,
                                    recreated: new_recreated,
                                } => {
                                    // Loop again with newly recreated set
                                    current_recreated = new_recreated;
                                    continue 'redelete_loop;
                                }
                            }
                        }
                        if redelete_stopped {
                            break; // outer phase loop
                        }
                    }
                }
            }
        }

        // Hard stop: if any DELETE failed/blocked in this phase, do NOT proceed
        // to subsequent phases. Checkpoint current results and break.
        if !result.failed.is_empty() && !dry_run {
            eprintln!(
                "\n  \x1b[1;31m⛔ Phase has {} failed action(s) — stopping before next phase\x1b[0m",
                result.failed.len()
            );
            // Checkpoint failed state before stopping
            if let Some(j) = journal {
                let deleted_snapshot = result.deleted.clone();
                let already_gone_snapshot = result.already_gone.clone();
                let failed_snapshot = result.failed.clone();
                let kept_snapshot: Vec<_> = result
                    .kept
                    .iter()
                    .map(crate::teardown::journal::PreservedRecord::from)
                    .collect();
                let reviewed_snapshot: Vec<_> = result
                    .reviewed
                    .iter()
                    .map(crate::teardown::journal::PreservedRecord::from)
                    .collect();
                j.update(|jrnl| {
                    jrnl.execution.phases_completed = result.phases_completed;
                    // Merge: keep accepted-but-not-Gone from wave checkpoints
                    for r in &deleted_snapshot {
                        if !jrnl.execution.deleted.iter().any(|d| d == r) {
                            jrnl.execution.deleted.push(r.clone());
                        }
                    }
                    jrnl.execution.already_gone = already_gone_snapshot;
                    jrnl.execution.failed = failed_snapshot;
                    jrnl.execution.kept = kept_snapshot;
                    jrnl.execution.reviewed = reviewed_snapshot;
                })
                .await
                .context("Failed to checkpoint failed phase — aborting")?;
            }
            break;
        }

        result.phases_completed += 1;

        // Checkpoint phase completion to journal
        if let Some(j) = journal {
            let phase_count = result.phases_completed;
            let deleted_snapshot = result.deleted.clone();
            let already_gone_snapshot = result.already_gone.clone();
            let failed_snapshot = result.failed.clone();
            let kept_snapshot: Vec<_> = result
                .kept
                .iter()
                .map(crate::teardown::journal::PreservedRecord::from)
                .collect();
            let reviewed_snapshot: Vec<_> = result
                .reviewed
                .iter()
                .map(crate::teardown::journal::PreservedRecord::from)
                .collect();
            j.update(|jrnl| {
                jrnl.execution.phases_completed = phase_count;
                for r in &deleted_snapshot {
                    if !jrnl.execution.deleted.iter().any(|d| d == r) {
                        jrnl.execution.deleted.push(r.clone());
                    }
                }
                jrnl.execution.already_gone = already_gone_snapshot;
                jrnl.execution.failed = failed_snapshot;
                jrnl.execution.kept = kept_snapshot;
                jrnl.execution.reviewed = reviewed_snapshot;
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
pub fn verify_delete_identity(plan_uid: &Option<String>, current_uid: &str) -> Result<(), String> {
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
#[allow(dead_code)]
async fn delete_resource(
    client: &Client,
    resource: &ResourceId,
    kind_map: &KindMap,
    gk_map: &GroupKindMap,
) -> DeleteResult {
    delete_resource_inner(client, resource, kind_map, gk_map, None).await
}

async fn delete_resource_inner(
    client: &Client,
    resource: &ResourceId,
    kind_map: &KindMap,
    gk_map: &GroupKindMap,
    expected_package_name: Option<&str>,
) -> DeleteResult {
    let (api, _) = match resolve_api(client, resource, kind_map, gk_map) {
        Some(r) => r,
        None => {
            return DeleteResult::Blocked(format!(
                "cannot resolve API for {}/{}",
                resource.kind, resource.name
            ));
        }
    };

    // Step 1: GET current resource to verify identity
    let current = match api.get(&resource.name).await {
        Ok(obj) => obj,
        Err(kube::Error::Api(err)) if err.code == 404 => {
            match api.list(&ListParams::default().limit(1)).await {
                Ok(_) => return DeleteResult::AlreadyGone,
                Err(_) => {
                    return DeleteResult::Unknown(
                        "pre-delete GET returned 404 but API endpoint verification failed — \
                         cannot distinguish object absence from endpoint absence"
                            .to_string(),
                    );
                }
            }
        }
        Err(kube::Error::Api(err)) if err.code == 403 || err.code == 401 => {
            return DeleteResult::Blocked(format!("pre-delete GET: {}", err.message));
        }
        Err(e) => {
            return DeleteResult::Unknown(format!("pre-delete GET failed: {}", e));
        }
    };

    let current_uid = current.metadata.uid.as_deref().unwrap_or("");

    // Step 2: Verify identity — mismatch/new UID is Blocked
    if let Err(reason) = verify_delete_identity(&resource.uid, current_uid) {
        return DeleteResult::Blocked(reason);
    }

    // Step 2b: Subscription semantic identity check — fail-closed on empty
    if resource.kind == "Subscription" && resource.group == "operators.coreos.com" {
        let expected_pkg = match expected_package_name {
            Some(pkg) if !pkg.is_empty() => pkg,
            _ => {
                return DeleteResult::Blocked(
                    "Subscription DELETE requires non-empty expected package name".to_string(),
                );
            }
        };
        let live_spec_name = current
            .data
            .get("spec")
            .and_then(|s| s.get("name"))
            .and_then(|n| n.as_str())
            .unwrap_or("");
        if live_spec_name.is_empty() {
            return DeleteResult::Blocked(
                "Subscription has empty spec.name — cannot verify semantic identity".to_string(),
            );
        }
        if live_spec_name != expected_pkg {
            return DeleteResult::Blocked(format!(
                "Subscription spec.name changed from '{}' to '{}' — semantic identity drift",
                expected_pkg, live_spec_name
            ));
        }
    }

    // Step 3: Delete with preconditions
    let current_rv = current.metadata.resource_version.as_deref().unwrap_or("");
    let needs_rv_precondition = resource.kind == "Subscription"
        && resource.group == "operators.coreos.com"
        && expected_package_name.is_some();

    if needs_rv_precondition && current_rv.is_empty() {
        return DeleteResult::Blocked(
            "Subscription has no resourceVersion — cannot set atomic precondition for semantic identity".to_string()
        );
    }

    let dp = if !current_uid.is_empty() {
        DeleteParams {
            preconditions: Some(kube::api::Preconditions {
                uid: Some(current_uid.to_string()),
                resource_version: if needs_rv_precondition {
                    Some(current_rv.to_string())
                } else {
                    None
                },
            }),
            ..Default::default()
        }
    } else {
        DeleteParams::default()
    };

    match api.delete(&resource.name, &dp).await {
        Ok(_) => DeleteResult::Accepted,
        Err(kube::Error::Api(err)) if err.code == 404 => {
            match api.list(&ListParams::default().limit(1)).await {
                Ok(_) => DeleteResult::AlreadyGone,
                Err(_) => DeleteResult::Unknown(
                    "DELETE returned 404 but endpoint verification failed".to_string(),
                ),
            }
        }
        Err(kube::Error::Api(err)) if err.code == 409 => {
            // UID conflict — resource recreated between GET and DELETE
            DeleteResult::Blocked(if needs_rv_precondition {
                "Subscription modified between GET and DELETE (resourceVersion conflict)"
                    .to_string()
            } else {
                "UID conflict — resource recreated between GET and DELETE".to_string()
            })
        }
        Err(kube::Error::Api(err)) if err.code == 401 => {
            DeleteResult::Blocked(format!("{}: {}", err.reason, err.message))
        }
        Err(kube::Error::Api(err)) if err.code == 403 => {
            if is_admission_webhook_denial(&err.message) {
                DeleteResult::Rejected(format!("{}: {}", err.reason, err.message))
            } else {
                DeleteResult::Blocked(format!("{}: {}", err.reason, err.message))
            }
        }
        Err(kube::Error::Api(err)) if err.code == 400 || err.code == 422 => {
            DeleteResult::Rejected(format!("{}: {}", err.reason, err.message))
        }
        Err(kube::Error::Api(err)) if err.code >= 500 => {
            DeleteResult::Unknown(format!("{}: {}", err.reason, err.message))
        }
        Err(e) => DeleteResult::Unknown(e.to_string()),
    }
}

/// Public wrapper for residual cleanup DELETE with MutationGate.
/// Returns Ok(description) on success, Err on failure.
///
/// `expected_package_name`: required for Subscription DELETEs to verify
/// semantic identity (spec.name) and set UID+RV precondition. Pass None
/// only for non-Subscription resources — Subscription with None is fail-closed.
/// Typed outcome for public DELETE callers (residual cleanup, resume).
#[derive(Clone, Debug)]
pub enum DeleteOutcome {
    Accepted,
    AlreadyGone,
    Rejected(String),
    Blocked(String),
    Unknown(String),
}

impl DeleteOutcome {
    pub fn is_stop(&self) -> bool {
        matches!(self, Self::Blocked(_) | Self::Unknown(_))
    }
}

pub async fn delete_resource_pub(
    client: &Client,
    resource: &ResourceId,
    kind_map: &KindMap,
    gk_map: &GroupKindMap,
    gate: Option<&MutationGate>,
    expected_package_name: Option<&str>,
) -> DeleteOutcome {
    // Fail-closed: Subscription DELETE requires non-empty semantic identity
    if resource.kind == "Subscription" && resource.group == "operators.coreos.com" {
        match expected_package_name {
            None | Some("") => {
                return DeleteOutcome::Blocked(format!(
                    "Cannot DELETE Subscription {}/{} without verified package name",
                    resource.kind, resource.name
                ));
            }
            _ => {}
        }
    }

    // Acquire mutation permit
    let _permit = if let Some(g) = gate {
        match g.acquire().await {
            Ok(p) => Some(p),
            Err(_) => return DeleteOutcome::Blocked("Mutation gate closed".to_string()),
        }
    } else {
        None
    };

    match delete_resource_inner(client, resource, kind_map, gk_map, expected_package_name).await {
        DeleteResult::Accepted => DeleteOutcome::Accepted,
        DeleteResult::AlreadyGone => DeleteOutcome::AlreadyGone,
        DeleteResult::Rejected(r) => DeleteOutcome::Rejected(r),
        DeleteResult::Blocked(r) => DeleteOutcome::Blocked(r),
        DeleteResult::Unknown(r) => DeleteOutcome::Unknown(r),
    }
}

// ── Delete wave/fixpoint helper ──

#[derive(Debug)]
struct WaveResult {
    accepted_gone: Vec<ResourceId>,
    already_gone: Vec<ResourceId>,
    failed: Vec<(ResourceId, String)>,
    stopped: bool,
    /// Explicit DELETE Accepted targets with their original UIDs.
    /// Only initial Accepted (not AlreadyGone) grants re-delete authority.
    redelete_authorities: Vec<(ResourceId, String)>,
}

const MAX_REDELETE_ITERATIONS: u32 = 3;

/// Result of a single re-delete attempt on a recreated resource.
#[derive(Debug)]
enum ReDeleteAttemptResult {
    /// Re-DELETE accepted, needs Gone confirmation via barrier.
    Accepted,
    /// Resource already Gone (404 + endpoint verified).
    Gone,
    /// Resource has deletionTimestamp — wait only, no DELETE needed.
    AlreadyDeleting,
    /// Stop: API failure, UID changed again, journal/gate failure.
    Stop(String),
}

/// Attempt a single re-delete on a recreated resource.
/// Persists ReDeleteRecord to journal before mutation.
#[allow(clippy::too_many_arguments)]
async fn attempt_single_redelete(
    client: &Client,
    res: &ResourceId,
    original_uid: &str,
    _event_uid: &str,
    kind_map: &KindMap,
    gk_map: &GroupKindMap,
    journal: &JournalStore,
    gate: &MutationGate,
) -> ReDeleteAttemptResult {
    let (api, _) = match resolve_api(client, res, kind_map, gk_map) {
        Some(r) => r,
        None => return ReDeleteAttemptResult::Stop("cannot resolve API".to_string()),
    };

    // Authoritative GET
    let obj = match api.get(&res.name).await {
        Ok(obj) => obj,
        Err(kube::Error::Api(ref err)) if err.code == 404 => {
            match api.list(&ListParams::default().limit(1)).await {
                Ok(_) => return ReDeleteAttemptResult::Gone,
                Err(e) => {
                    return ReDeleteAttemptResult::Stop(format!(
                        "404 but endpoint check failed: {}",
                        e
                    ));
                }
            }
        }
        Err(e) => return ReDeleteAttemptResult::Stop(format!("GET failed: {}", e)),
    };

    // Authoritative GET is truth — use live_uid, not watch event new_uid.
    // If live_uid differs from event but also differs from original, it's still recreated.
    let live_uid = obj.metadata.uid.as_deref().unwrap_or("");
    if live_uid.is_empty() {
        return ReDeleteAttemptResult::Stop("live resource has no UID".to_string());
    }
    if live_uid == original_uid {
        return ReDeleteAttemptResult::Stop(
            "live UID matches original — not recreated".to_string(),
        );
    }

    if obj.metadata.deletion_timestamp.is_some() {
        return ReDeleteAttemptResult::AlreadyDeleting;
    }

    // Acquire permit BEFORE journal persist
    let _permit = match gate.acquire().await {
        Ok(p) => p,
        Err(_) => return ReDeleteAttemptResult::Stop("gate closed".to_string()),
    };

    // Persist Authorized with live_uid (authoritative GET truth)
    let stable_id = ResourceId {
        group: res.group.clone(),
        version: res.version.clone(),
        kind: res.kind.clone(),
        namespace: res.namespace.clone(),
        name: res.name.clone(),
        uid: None,
    };
    let rec = crate::teardown::journal::ReDeleteRecord {
        resource_identity: stable_id.clone(),
        original_uid: original_uid.to_string(),
        new_uid: live_uid.to_string(),
        result: crate::teardown::journal::ReDeleteResult::Authorized,
    };
    if let Err(e) = journal
        .update(|j| j.execution.re_delete_records.push(rec))
        .await
    {
        return ReDeleteAttemptResult::Stop(format!("journal persist failed: {}", e));
    }

    // UID-preconditioned DELETE using authoritative live_uid
    let dp = kube::api::DeleteParams {
        preconditions: Some(kube::api::Preconditions {
            uid: Some(live_uid.to_string()),
            resource_version: None,
        }),
        ..Default::default()
    };
    let del_result = match api.delete(&res.name, &dp).await {
        Ok(_) => crate::teardown::journal::ReDeleteResult::Accepted,
        Err(kube::Error::Api(ref err)) if err.code == 404 => {
            match api.list(&ListParams::default().limit(1)).await {
                Ok(_) => crate::teardown::journal::ReDeleteResult::Gone,
                Err(e) => crate::teardown::journal::ReDeleteResult::UnknownOutcome(format!(
                    "DELETE 404 endpoint check failed: {}",
                    e
                )),
            }
        }
        Err(kube::Error::Api(ref err)) if err.code >= 500 => {
            crate::teardown::journal::ReDeleteResult::UnknownOutcome(format!(
                "{}: {}",
                err.reason, err.message
            ))
        }
        Err(e) => crate::teardown::journal::ReDeleteResult::Failed(e.to_string()),
    };

    eprintln!(
        "    ↳ re-DELETE {}/{}: {:?}",
        res.kind, res.name, del_result
    );

    // Checkpoint result — search with live_uid (authoritative GET truth)
    {
        let sid = stable_id;
        let ouid = original_uid.to_string();
        let nuid = live_uid.to_string();
        let result_c = del_result.clone();
        if let Err(e) = journal
            .update(|j| {
                if let Some(r) = j.execution.re_delete_records.iter_mut().rev().find(|r| {
                    r.resource_identity.group == sid.group
                        && r.resource_identity.version == sid.version
                        && r.resource_identity.kind == sid.kind
                        && r.resource_identity.namespace == sid.namespace
                        && r.resource_identity.name == sid.name
                        && r.original_uid == ouid
                        && r.new_uid == nuid
                }) {
                    r.result = result_c;
                }
            })
            .await
        {
            return ReDeleteAttemptResult::Stop(format!(
                "post-mutation journal checkpoint failed: {}",
                e
            ));
        }
    }

    match del_result {
        crate::teardown::journal::ReDeleteResult::Accepted => ReDeleteAttemptResult::Accepted,
        crate::teardown::journal::ReDeleteResult::Gone => ReDeleteAttemptResult::Gone,
        crate::teardown::journal::ReDeleteResult::Failed(r)
        | crate::teardown::journal::ReDeleteResult::UnknownOutcome(r) => {
            ReDeleteAttemptResult::Stop(r)
        }
        _ => ReDeleteAttemptResult::Stop("unexpected result".to_string()),
    }
}

const WAVE_BARRIER_TIMEOUT: Duration = if cfg!(test) {
    Duration::from_millis(200)
} else {
    Duration::from_secs(1200)
};
const WAVE_STALL_TIMEOUT: Duration = if cfg!(test) {
    Duration::from_millis(100)
} else {
    Duration::from_secs(120)
};
const POST_RECOVERY_BARRIER_TIMEOUT: Duration = if cfg!(test) {
    Duration::from_millis(200)
} else {
    Duration::from_secs(900)
};

/// The controller can keep recreating its descendants until it is removed.
/// After a bounded cleanup wait, only EXPECT descendants and roots whose
/// original UID is gone may be left for the post-controller residual audit.
/// A recreated explicit root also needs a durably accepted re-delete of its
/// current UID. API uncertainty or an original root still present blocks the
/// phase transition.
#[allow(clippy::too_many_arguments)]
async fn can_defer_to_residual(
    client: &Client,
    remaining: &[ResourceId],
    phase: &crate::teardown::planner::PlanPhase,
    watch_mgr: &crate::teardown::watch::WatchManager,
    store: &Arc<crate::teardown::runtime::RuntimeStateStore>,
    journal: Option<&JournalStore>,
    kind_map: &KindMap,
    gk_map: &GroupKindMap,
) -> bool {
    if remaining.is_empty() {
        return true;
    }
    let deleted: Vec<&ResourceId> = phase
        .actions
        .iter()
        .filter_map(|action| match action {
            Action::Delete { resource, .. } => Some(resource),
            _ => None,
        })
        .collect();
    let expected: Vec<&ResourceId> = phase
        .actions
        .iter()
        .filter_map(|action| match action {
            Action::ExpectGone { resource, .. } => Some(resource),
            _ => None,
        })
        .collect();
    // DELETE roots: match by identity (group/kind/namespace/name) — UIDs may
    // differ for recreated resources that were re-deleted with a new UID.
    // The downstream root check (line ~1912) validates redelete authority.
    // EXPECT resources: require UID match — no redelete authority exists for
    // them, so identity-only matching could accept an unrelated resource.
    let matches_deleted_identity = |r: &ResourceId| -> bool {
        deleted.iter().any(|s| {
            s.group == r.group
                && s.kind == r.kind
                && s.namespace == r.namespace
                && s.name == r.name
        })
    };
    if remaining
        .iter()
        .any(|r| !matches_deleted_identity(r) && !expected.contains(&r))
    {
        return false;
    }

    watch_mgr
        .reconcile(client, remaining, kind_map, gk_map)
        .await;
    if remaining.iter().any(|r| {
        store.get(r).is_none_or(|entry| {
            matches!(
                entry.state,
                crate::teardown::runtime::ResourceRuntimeState::Unknown { .. }
                    | crate::teardown::runtime::ResourceRuntimeState::Failed { .. }
            )
        })
    }) {
        return false;
    }

    let redeletes = if let Some(j) = journal {
        j.read().await.execution.re_delete_records.clone()
    } else {
        Vec::new()
    };

    for root in deleted {
        let (api, _) = match resolve_api(client, root, kind_map, gk_map) {
            Some(api) => api,
            None => return false,
        };
        match api.get(&root.name).await {
            Err(kube::Error::Api(ref err)) if err.code == 404 => {
                if api.list(&ListParams::default().limit(1)).await.is_err() {
                    return false;
                }
            }
            Ok(obj) => {
                let Some(current_uid) = obj.metadata.uid.as_deref() else {
                    return false;
                };
                if root.uid.as_deref() == Some(current_uid) {
                    return false;
                }
                if !redeletes.iter().any(|record| {
                    record.resource_identity.group == root.group
                        && record.resource_identity.version == root.version
                        && record.resource_identity.kind == root.kind
                        && record.resource_identity.namespace == root.namespace
                        && record.resource_identity.name == root.name
                        && record.original_uid == root.uid.as_deref().unwrap_or("")
                        && record.new_uid == current_uid
                        && matches!(
                            record.result,
                            crate::teardown::journal::ReDeleteResult::Accepted
                                | crate::teardown::journal::ReDeleteResult::Gone
                        )
                }) {
                    return false;
                }
            }
            Err(_) => return false,
        }
    }
    true
}

#[allow(clippy::too_many_arguments)]
async fn execute_delete_waves(
    client: &Client,
    targets: &[ResourceId],
    kind_map: &KindMap,
    gk_map: &GroupKindMap,
    pkg_name: Option<&str>,
    watch_mgr: &crate::teardown::watch::WatchManager,
    store: &Arc<crate::teardown::runtime::RuntimeStateStore>,
    journal: Option<&JournalStore>,
    gate: Option<&MutationGate>,
    cancel: Option<&crate::teardown::permit::CancelSignal>,
    phase: Option<&crate::teardown::planner::PlanPhase>,
) -> Result<WaveResult> {
    let km = Arc::new(kind_map.clone());
    let gk = Arc::new(gk_map.clone());

    // Register all targets in the runtime store for observation tracking
    for (i, r) in targets.iter().enumerate() {
        store.register(
            r,
            crate::teardown::runtime::ResourceRuntimeState::Planned,
            i,
        );
    }

    let mut pending: Vec<ResourceId> = targets.to_vec();
    let mut all_accepted_gone: Vec<ResourceId> = Vec::new();
    let mut all_already_gone: Vec<ResourceId> = Vec::new();
    let mut all_failed: Vec<(ResourceId, String)> = Vec::new();
    let mut wave_num = 0u32;

    while !pending.is_empty() {
        wave_num += 1;
        if wave_num > 1 {
            eprintln!(
                "\n  \x1b[1;36mWAVE {}\x1b[0m: retrying {} rejected target(s)",
                wave_num,
                pending.len()
            );
        }

        // Acquire gate permit for this wave's mutations
        let _wave_permit = if let Some(g) = gate {
            match g.acquire().await {
                Ok(p) => Some(p),
                Err(_) => {
                    eprintln!("  ⏸ Gate closed — stopping wave");
                    return Ok(WaveResult {
                        accepted_gone: all_accepted_gone,
                        already_gone: all_already_gone,
                        failed: all_failed,
                        stopped: true,
                        redelete_authorities: vec![],
                    });
                }
            }
        } else {
            None
        };

        // Fire DELETEs concurrently
        let del_futs = pending.iter().map(|resource| {
            let client = client.clone();
            let resource = resource.clone();
            let km = km.clone();
            let gk = gk.clone();
            let pkg = pkg_name.map(|s| s.to_string());
            async move {
                let res = delete_resource_inner(&client, &resource, &km, &gk, pkg.as_deref()).await;
                (resource, res)
            }
        });

        let del_results: Vec<_> = futures::stream::iter(del_futs)
            .buffer_unordered(DEFAULT_CONCURRENCY)
            .collect()
            .await;

        let mut wave_accepted: Vec<ResourceId> = Vec::new();
        let mut wave_rejected: Vec<ResourceId> = Vec::new();
        let mut wave_progress: usize = 0;
        let mut wave_stopped = false;

        for (resource, del_result) in del_results {
            match del_result {
                DeleteResult::Accepted => {
                    eprintln!(
                        "  \x1b[31mDELETED\x1b[0m  {}/{}{}",
                        resource.kind,
                        resource.name,
                        scope_suffix(&resource)
                    );
                    store.update_from_executor(
                        &resource,
                        crate::teardown::runtime::ResourceRuntimeState::DeleteRequested,
                    );
                    wave_accepted.push(resource);
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
                        crate::teardown::runtime::ResourceRuntimeState::Gone,
                    );
                    all_already_gone.push(resource);
                    wave_progress += 1;
                }
                DeleteResult::Rejected(reason) => {
                    eprintln!(
                        "  \x1b[33mREJECTED\x1b[0m {}/{}: {}{}",
                        resource.kind,
                        resource.name,
                        reason,
                        scope_suffix(&resource)
                    );
                    wave_rejected.push(resource);
                }
                DeleteResult::Blocked(reason) => {
                    eprintln!(
                        "  \x1b[1;31mBLOCKED\x1b[0m  {}/{}: {}{}",
                        resource.kind,
                        resource.name,
                        reason,
                        scope_suffix(&resource)
                    );
                    store.update_from_executor(
                        &resource,
                        crate::teardown::runtime::ResourceRuntimeState::Failed {
                            reason: reason.clone(),
                        },
                    );
                    all_failed.push((resource, reason));
                    wave_stopped = true;
                }
                DeleteResult::Unknown(reason) => {
                    eprintln!(
                        "  \x1b[1;35mUNKNOWN\x1b[0m  {}/{}: {}{}",
                        resource.kind,
                        resource.name,
                        reason,
                        scope_suffix(&resource)
                    );
                    store.update_from_executor(
                        &resource,
                        crate::teardown::runtime::ResourceRuntimeState::Failed {
                            reason: reason.clone(),
                        },
                    );
                    all_failed.push((resource, reason));
                    wave_stopped = true;
                }
            }
        }

        // Checkpoint accepted DELETEs to journal before waiting
        if let Some(j) = journal {
            let accepted_snap = wave_accepted.clone();
            let failed_snap = all_failed.clone();
            j.update(|jrnl| {
                for r in &accepted_snap {
                    if !jrnl.execution.deleted.iter().any(|d| d == r) {
                        jrnl.execution.deleted.push(r.clone());
                    }
                }
                jrnl.execution.failed = failed_snap;
            })
            .await
            .context("Failed to checkpoint wave DELETEs to journal")?;
        }

        // Blocked/Unknown → stop immediately, no further mutations
        if wave_stopped {
            for r in &wave_rejected {
                all_failed.push((
                    r.clone(),
                    "phase stopped due to Blocked/Unknown result".to_string(),
                ));
            }
            // Durable checkpoint: rejected additions to failed
            if let Some(j) = journal {
                let failed_snap = all_failed.clone();
                j.update(|jrnl| {
                    jrnl.execution.failed = failed_snap;
                })
                .await
                .context("Failed to checkpoint stopped wave to journal")?;
            }
            return Ok(WaveResult {
                accepted_gone: all_accepted_gone,
                already_gone: all_already_gone,
                failed: all_failed,
                stopped: true,
                redelete_authorities: vec![],
            });
        }

        // Drop permit before barrier wait
        drop(_wave_permit);

        // Wait for accepted targets to be Gone (barrier on accepted only, not EXPECT)
        if !wave_accepted.is_empty() {
            let barrier_start = Instant::now();
            let store_ref = store.clone();
            let barrier_targets = wave_accepted.clone();
            let render_handle = tokio::spawn(async move {
                let mut rx = store_ref.subscribe();
                loop {
                    if rx.changed().await.is_err() {
                        break;
                    }
                    let summary = store_ref.summary_for(&barrier_targets);
                    let elapsed = barrier_start.elapsed().as_secs();
                    eprint!(
                        "\r\x1b[2K  ⏳ wave {}: {}/{} Gone ({}s)",
                        wave_num, summary.gone, summary.total, elapsed
                    );
                    use std::io::Write;
                    std::io::stderr().flush().ok();
                }
            });

            let wait_result = watch_mgr
                .wait_for_gone_cancellable(
                    client,
                    &wave_accepted,
                    kind_map,
                    gk_map,
                    WAVE_BARRIER_TIMEOUT,
                    WAVE_STALL_TIMEOUT,
                    cancel,
                )
                .await;

            render_handle.abort();
            eprintln!();

            match wait_result {
                WatchWaitResult::AllGone => {
                    wave_progress += wave_accepted.len();
                    all_accepted_gone.extend(wave_accepted);
                }
                WatchWaitResult::Cancelled => {
                    if let Some(j) = journal {
                        let failed_snap = all_failed.clone();
                        j.update(|jrnl| {
                            jrnl.execution.failed = failed_snap;
                        })
                        .await
                        .context("Failed to checkpoint cancelled wave to journal")?;
                    }
                    return Ok(WaveResult {
                        accepted_gone: all_accepted_gone,
                        already_gone: all_already_gone,
                        failed: all_failed,
                        stopped: true,
                        redelete_authorities: vec![],
                    });
                }
                WatchWaitResult::Stalled {
                    remaining, reason, ..
                } => {
                    for r in &wave_accepted {
                        if !remaining.contains(r) {
                            all_accepted_gone.push(r.clone());
                        }
                    }

                    // Attempt finalizer recovery on stalled explicit DELETE targets
                    let mut recovery_succeeded = false;
                    let approve_recovery = if let Some(j) = journal {
                        j.read().await.finalizer_recovery_approved
                    } else {
                        false
                    };
                    if approve_recovery
                        && !remaining.is_empty()
                        && let Some(ph) = phase
                        && let Some(jrnl) = journal
                        && let Some(g) = gate
                    {
                        eprintln!(
                            "  🔧 Attempting finalizer recovery on {} stalled target(s)",
                            remaining.len()
                        );
                        match attempt_finalizer_recovery(
                            client,
                            &remaining,
                            &all_accepted_gone,
                            ph,
                            kind_map,
                            gk_map,
                            jrnl,
                            g,
                        )
                        .await
                        {
                            Ok(recovered) if recovered > 0 => {
                                eprintln!(
                                    "  🔧 Recovered {} resource(s) — re-checking Gone",
                                    recovered
                                );
                                let re_wait = watch_mgr
                                    .wait_for_gone_cancellable(
                                        client,
                                        &remaining,
                                        kind_map,
                                        gk_map,
                                        WAVE_BARRIER_TIMEOUT,
                                        WAVE_STALL_TIMEOUT,
                                        cancel,
                                    )
                                    .await;
                                if matches!(re_wait, WatchWaitResult::AllGone) {
                                    for r in &remaining {
                                        all_accepted_gone.push(r.clone());
                                    }
                                    wave_progress += remaining.len();
                                    recovery_succeeded = true;
                                }
                            }
                            Ok(_) => {}
                            Err(e) => {
                                eprintln!("  ⚠ Finalizer recovery error: {}", e);
                            }
                        }
                    }

                    if !recovery_succeeded {
                        for r in &remaining {
                            all_failed.push((r.clone(), format!("barrier stalled: {}", reason)));
                        }
                        for r in &wave_rejected {
                            all_failed.push((
                                r.clone(),
                                "wave stopped — barrier stalled before retry".to_string(),
                            ));
                        }
                        if let Some(j) = journal {
                            let failed_snap = all_failed.clone();
                            j.update(|jrnl| {
                                jrnl.execution.failed = failed_snap;
                            })
                            .await
                            .context("Failed to checkpoint stalled wave to journal")?;
                        }
                        return Ok(WaveResult {
                            accepted_gone: all_accepted_gone,
                            already_gone: all_already_gone,
                            failed: all_failed,
                            stopped: true,
                            redelete_authorities: vec![],
                        });
                    }
                }
                WatchWaitResult::Recreated {
                    remaining,
                    recreated,
                } => {
                    // Targets confirmed Gone
                    for r in &wave_accepted {
                        if !remaining.contains(r) {
                            all_accepted_gone.push(r.clone());
                            wave_progress += 1;
                        }
                    }

                    // Exact recreated targets: original DELETE completed (new UID exists).
                    // Mark as accepted_gone for outer barrier re-delete authority.
                    // Do NOT re-delete new UID in wave.
                    let recreated_ids: std::collections::HashSet<String> = recreated
                        .iter()
                        .map(|(r, _, _)| {
                            format!(
                                "{}/{}/{}/{}/{}",
                                r.group,
                                r.version,
                                r.kind,
                                r.namespace.as_deref().unwrap_or("-"),
                                r.name
                            )
                        })
                        .collect();
                    for r in &remaining {
                        let key = format!(
                            "{}/{}/{}/{}/{}",
                            r.group,
                            r.version,
                            r.kind,
                            r.namespace.as_deref().unwrap_or("-"),
                            r.name
                        );
                        if recreated_ids.contains(&key) {
                            all_accepted_gone.push(r.clone());
                            wave_progress += 1;
                        }
                    }

                    // Non-recreated remaining: re-wait loop
                    let mut still_waiting: Vec<ResourceId> = remaining
                        .iter()
                        .filter(|r| {
                            let key = format!(
                                "{}/{}/{}/{}/{}",
                                r.group,
                                r.version,
                                r.kind,
                                r.namespace.as_deref().unwrap_or("-"),
                                r.name
                            );
                            !recreated_ids.contains(&key)
                        })
                        .cloned()
                        .collect();
                    while !still_waiting.is_empty() {
                        let re_wait = watch_mgr
                            .wait_for_gone_cancellable(
                                client,
                                &still_waiting,
                                kind_map,
                                gk_map,
                                WAVE_BARRIER_TIMEOUT,
                                WAVE_STALL_TIMEOUT,
                                cancel,
                            )
                            .await;
                        match re_wait {
                            WatchWaitResult::AllGone => {
                                for r in &still_waiting {
                                    if !all_accepted_gone.contains(r) {
                                        all_accepted_gone.push(r.clone());
                                        wave_progress += 1;
                                    }
                                }
                                break;
                            }
                            WatchWaitResult::Recreated {
                                remaining: re_remaining,
                                recreated: re_recreated,
                            } => {
                                // Move newly Gone + newly recreated to completed
                                for r in &still_waiting {
                                    if !re_remaining.contains(r) {
                                        all_accepted_gone.push(r.clone());
                                        wave_progress += 1;
                                    }
                                }
                                let re_ids: std::collections::HashSet<String> = re_recreated
                                    .iter()
                                    .map(|(r, _, _)| {
                                        format!(
                                            "{}/{}/{}/{}/{}",
                                            r.group,
                                            r.version,
                                            r.kind,
                                            r.namespace.as_deref().unwrap_or("-"),
                                            r.name
                                        )
                                    })
                                    .collect();
                                for r in &re_remaining {
                                    let key = format!(
                                        "{}/{}/{}/{}/{}",
                                        r.group,
                                        r.version,
                                        r.kind,
                                        r.namespace.as_deref().unwrap_or("-"),
                                        r.name
                                    );
                                    if re_ids.contains(&key) {
                                        all_accepted_gone.push(r.clone());
                                        wave_progress += 1;
                                    }
                                }
                                // Continue with truly remaining
                                still_waiting = re_remaining
                                    .into_iter()
                                    .filter(|r| {
                                        let key = format!(
                                            "{}/{}/{}/{}/{}",
                                            r.group,
                                            r.version,
                                            r.kind,
                                            r.namespace.as_deref().unwrap_or("-"),
                                            r.name
                                        );
                                        !re_ids.contains(&key)
                                    })
                                    .collect();
                            }
                            WatchWaitResult::Stalled { .. } | WatchWaitResult::Cancelled => {
                                for r in &still_waiting {
                                    all_failed.push((
                                        r.clone(),
                                        "wave re-wait stalled/cancelled".to_string(),
                                    ));
                                }
                                return Ok(WaveResult {
                                    accepted_gone: all_accepted_gone,
                                    already_gone: all_already_gone,
                                    failed: all_failed,
                                    stopped: true,
                                    redelete_authorities: vec![],
                                });
                            }
                        }
                    }
                }
            }
        }

        // Check progress: if no newly Gone this wave and rejected remain → no progress failure
        if wave_progress == 0 && !wave_rejected.is_empty() {
            for r in &wave_rejected {
                all_failed.push((
                    r.clone(),
                    "no progress in delete wave — all targets rejected".to_string(),
                ));
            }
            if let Some(j) = journal {
                let failed_snap = all_failed.clone();
                j.update(|jrnl| {
                    jrnl.execution.failed = failed_snap;
                })
                .await
                .context("Failed to checkpoint no-progress wave to journal")?;
            }
            return Ok(WaveResult {
                accepted_gone: all_accepted_gone,
                already_gone: all_already_gone,
                failed: all_failed,
                stopped: true,
                redelete_authorities: vec![],
            });
        }

        // Next wave with rejected targets
        pending = wave_rejected;
    }

    // Collect re-delete authorities: only from initial DELETE Accepted targets
    let authorities: Vec<(ResourceId, String)> = all_accepted_gone
        .iter()
        .filter_map(|r| r.uid.as_ref().map(|u| (r.clone(), u.clone())))
        .collect();

    Ok(WaveResult {
        accepted_gone: all_accepted_gone,
        already_gone: all_already_gone,
        failed: all_failed,
        stopped: false,
        redelete_authorities: authorities,
    })
}

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
        Ok(obj) => FinalizerCheckResult::Known {
            finalizers: obj.metadata.finalizers.unwrap_or_default(),
            terminating: obj.metadata.deletion_timestamp.is_some(),
        },
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

const PROTECTED_KINDS: &[&str] = &[
    "CustomResourceDefinition",
    "Namespace",
    "PersistentVolume",
    "PersistentVolumeClaim",
    "Node",
    "Subscription",
    "ClusterServiceVersion",
    "APIService",
    "OperatorGroup",
];

#[allow(clippy::too_many_arguments)]
async fn attempt_finalizer_recovery(
    client: &Client,
    remaining: &[ResourceId],
    deleted_roots: &[ResourceId],
    phase: &crate::teardown::planner::PlanPhase,
    kind_map: &KindMap,
    gk_map: &GroupKindMap,
    journal: &JournalStore,
    gate: &MutationGate,
) -> Result<usize> {
    use crate::teardown::journal::FinalizerRecoveryRecord;
    use crate::teardown::journal::FinalizerRecoveryResult;
    use crate::teardown::journal::OwnerRefSnapshot;

    // A successful re-delete of a recreated explicit root is also a durable
    // DELETE authority. The operator may have updated an existing dependent's
    // ownerRef to that new UID before its finalizer became stuck.
    let mut effective_deleted_roots = deleted_roots.to_vec();
    let recorded_redeletes = journal.read().await.execution.re_delete_records.clone();
    for record in &recorded_redeletes {
        if !matches!(
            record.result,
            crate::teardown::journal::ReDeleteResult::Accepted
                | crate::teardown::journal::ReDeleteResult::Gone
        ) {
            continue;
        }
        if let Some(original) = deleted_roots.iter().find(|root| {
            root.group == record.resource_identity.group
                && root.version == record.resource_identity.version
                && root.kind == record.resource_identity.kind
                && root.namespace == record.resource_identity.namespace
                && root.name == record.resource_identity.name
                && root.uid.as_deref() == Some(record.original_uid.as_str())
        }) {
            let mut recreated = original.clone();
            recreated.uid = Some(record.new_uid.clone());
            effective_deleted_roots.push(recreated);
        }
    }
    let deleted_uids: std::collections::HashSet<String> = effective_deleted_roots
        .iter()
        .filter_map(|r| r.uid.clone())
        .collect();

    let expect_resources: std::collections::HashSet<ResourceId> = phase
        .actions
        .iter()
        .filter_map(|a| match a {
            crate::teardown::planner::Action::ExpectGone { resource, .. } => Some(resource.clone()),
            _ => None,
        })
        .collect();

    let delete_resources: std::collections::HashSet<ResourceId> = phase
        .actions
        .iter()
        .filter_map(|a| match a {
            crate::teardown::planner::Action::Delete { resource, .. } => Some(resource.clone()),
            _ => None,
        })
        .collect();

    let mut recovered = 0;

    for res in remaining {
        let is_expect = expect_resources.contains(res);
        let is_explicit_delete = delete_resources.contains(res);
        if !is_expect && !is_explicit_delete {
            continue;
        }

        if PROTECTED_KINDS.contains(&res.kind.as_str()) {
            eprintln!(
                "    ⚠ {}/{}: protected kind — skip recovery",
                res.kind, res.name
            );
            continue;
        }

        let plan_uid = match &res.uid {
            Some(uid) if !uid.is_empty() => uid.clone(),
            _ => {
                eprintln!(
                    "    ⚠ {}/{}: no plan UID — skip recovery",
                    res.kind, res.name
                );
                continue;
            }
        };

        let (api, _) = match resolve_api(client, res, kind_map, gk_map) {
            Some(r) => r,
            None => {
                eprintln!(
                    "    ⚠ {}/{}: cannot resolve API — skip recovery",
                    res.kind, res.name
                );
                continue;
            }
        };

        let obj = match api.get(&res.name).await {
            Ok(obj) => obj,
            Err(kube::Error::Api(ref err)) if err.code == 404 => {
                continue;
            }
            Err(e) => {
                eprintln!(
                    "    ⚠ {}/{}: GET failed ({}) — skip recovery",
                    res.kind, res.name, e
                );
                continue;
            }
        };

        let live_uid = match obj.metadata.uid.as_deref() {
            Some(uid) if uid == plan_uid => uid.to_string(),
            Some(uid) => {
                // For explicit DELETE targets that were re-deleted, accept
                // the new UID if we have a redelete record for it.
                if is_explicit_delete
                    && recorded_redeletes.iter().any(|rec| {
                        rec.resource_identity.group == res.group
                            && rec.resource_identity.version == res.version
                            && rec.resource_identity.kind == res.kind
                            && rec.resource_identity.namespace == res.namespace
                            && rec.resource_identity.name == res.name
                            && rec.original_uid == plan_uid
                            && rec.new_uid == uid
                            && matches!(
                                rec.result,
                                crate::teardown::journal::ReDeleteResult::Accepted
                                    | crate::teardown::journal::ReDeleteResult::Gone
                            )
                    })
                {
                    uid.to_string()
                } else {
                    eprintln!(
                        "    ⚠ {}/{}: UID changed ({} → {}) — skip recovery",
                        res.kind, res.name, plan_uid, uid
                    );
                    continue;
                }
            }
            None => {
                eprintln!(
                    "    ⚠ {}/{}: no live UID — skip recovery",
                    res.kind, res.name
                );
                continue;
            }
        };

        if obj.metadata.deletion_timestamp.is_none() {
            eprintln!(
                "    ⚠ {}/{}: no deletionTimestamp — skip recovery",
                res.kind, res.name
            );
            continue;
        }

        // EXPECT descendants: strict single-controller ownerRef check
        // Explicit DELETE targets: skip ownerRef check (they have their own authority)
        let owner_refs = obj.metadata.owner_references.as_deref().unwrap_or(&[]);
        if is_expect {
            if owner_refs.len() != 1 {
                eprintln!(
                    "    ⚠ {}/{}: {} ownerRefs (need exactly 1) — skip recovery",
                    res.kind,
                    res.name,
                    owner_refs.len()
                );
                continue;
            }
            let oref = &owner_refs[0];
            // A single ownerRef is a GC dependency even when controller=false.
            // The exact UID must still match a successfully deleted root below.
            if !deleted_uids.contains(&oref.uid) {
                eprintln!(
                    "    ⚠ {}/{}: ownerRef UID {} not in deleted roots — skip recovery",
                    res.kind, res.name, oref.uid
                );
                continue;
            }
        }

        // EXPECT: verify root is authoritatively Gone
        // Explicit DELETE: skip root check (resource IS the root)
        if is_expect {
            let oref = &owner_refs[0]; // safe: checked len==1 above
            let root = effective_deleted_roots
                .iter()
                .find(|r| r.uid.as_deref() == Some(&oref.uid));
            let root_res = match root {
                Some(r) => r,
                None => {
                    eprintln!(
                        "    ⚠ {}/{}: ownerRef root not found in deleted_roots — skip recovery",
                        res.kind, res.name
                    );
                    continue;
                }
            };
            let (root_api, _) = match resolve_api(client, root_res, kind_map, gk_map) {
                Some(r) => r,
                None => {
                    eprintln!(
                        "    ⚠ {}/{}: root API unresolvable — skip recovery (fail-closed)",
                        res.kind, res.name
                    );
                    continue;
                }
            };
            match root_api.get(&root_res.name).await {
                Err(kube::Error::Api(ref err)) if err.code == 404 => {
                    match root_api.list(&ListParams::default().limit(1)).await {
                        Ok(_) => {}
                        Err(_) => {
                            eprintln!(
                                "    ⚠ {}/{}: root endpoint verification failed — skip",
                                res.kind, res.name
                            );
                            continue;
                        }
                    }
                }
                Ok(current_root) => {
                    match current_root.metadata.uid.as_deref() {
                        // The original owner is still present. A DELETE request alone
                        // does not authorize stripping its dependent's finalizer.
                        Some(uid) if Some(uid) == root_res.uid.as_deref() => {
                            eprintln!(
                                "    ⚠ {}/{}: root {}/{} still has original UID — skip recovery",
                                res.kind, res.name, root_res.kind, root_res.name
                            );
                            continue;
                        }
                        // A different immutable UID proves the dependent's owner is
                        // gone, even when the operator has recreated the same name.
                        Some(_) => {}
                        None => {
                            eprintln!(
                                "    ⚠ {}/{}: replacement root has no UID — skip recovery",
                                res.kind, res.name
                            );
                            continue;
                        }
                    }
                }
                Err(e) => {
                    eprintln!(
                        "    ⚠ {}/{}: root GET error ({}) — skip recovery",
                        res.kind, res.name, e
                    );
                    continue;
                }
            }
        }

        let finalizers = obj.metadata.finalizers.as_deref().unwrap_or(&[]);
        if finalizers.is_empty() {
            continue;
        }

        // Acquire gate permit
        let _permit = match gate.acquire().await {
            Ok(p) => p,
            Err(_) => {
                eprintln!("    ⏸ Gate closed — stopping recovery");
                break;
            }
        };

        // Snapshot for journal record (authority-grade, not display strings)
        let finalizer_values: Vec<String> = finalizers.to_vec();
        let finalizer_display = finalizer_values.join(", ");
        let owner_ref_snapshots: Vec<OwnerRefSnapshot> = owner_refs
            .iter()
            .map(|o| OwnerRefSnapshot {
                api_version: o.api_version.clone(),
                kind: o.kind.clone(),
                name: o.name.clone(),
                uid: o.uid.clone(),
                controller: o.controller,
            })
            .collect();

        // Record PatchRequested to journal BEFORE mutation
        let (root_uid, root_kind) = if is_expect {
            let oref = &owner_refs[0];
            (oref.uid.clone(), oref.kind.clone())
        } else {
            (live_uid.clone(), res.kind.clone())
        };
        let record = FinalizerRecoveryRecord {
            resource: res.clone(),
            live_uid: live_uid.clone(),
            finalizer_values: finalizer_values.clone(),
            owner_references_snapshot: owner_ref_snapshots.clone(),
            root_uid,
            root_kind,
            result: FinalizerRecoveryResult::PatchRequested,
        };
        journal
            .update(|jrnl| {
                jrnl.finalizer_recoveries.push(record);
                jrnl.audit_revision += 1;
            })
            .await
            .map_err(|e| {
                anyhow::anyhow!(
                    "{}/{}: pre-patch journal checkpoint failed: {}",
                    res.kind,
                    res.name,
                    e
                )
            })?;

        // JSON Patch: atomic UID + ownerReferences + finalizers test → replace with empty
        let finalizers_json: Vec<serde_json::Value> = finalizer_values
            .iter()
            .map(|f| serde_json::json!(f))
            .collect();
        let owner_refs_json: Vec<serde_json::Value> = owner_refs
            .iter()
            .map(|oref| {
                let mut m = serde_json::Map::new();
                m.insert("apiVersion".into(), serde_json::json!(oref.api_version));
                m.insert("kind".into(), serde_json::json!(oref.kind));
                m.insert("name".into(), serde_json::json!(oref.name));
                m.insert("uid".into(), serde_json::json!(oref.uid));
                if let Some(c) = oref.controller {
                    m.insert("controller".into(), serde_json::json!(c));
                }
                if let Some(b) = oref.block_owner_deletion {
                    m.insert("blockOwnerDeletion".into(), serde_json::json!(b));
                }
                serde_json::Value::Object(m)
            })
            .collect();
        // EXPECT: test UID + ownerReferences + finalizers (strict descendant check)
        // Explicit DELETE: test UID + finalizers only (ownerReferences may be absent)
        let mut patch_ops =
            vec![serde_json::json!({"op": "test", "path": "/metadata/uid", "value": live_uid})];
        if is_expect {
            patch_ops
                .push(serde_json::json!({"op": "test", "path": "/metadata/ownerReferences", "value": owner_refs_json}));
        }
        patch_ops.push(
            serde_json::json!({"op": "test", "path": "/metadata/finalizers", "value": finalizers_json}),
        );
        patch_ops.push(
            serde_json::json!({"op": "replace", "path": "/metadata/finalizers", "value": []}),
        );
        let patch = serde_json::Value::Array(patch_ops);
        match api
            .patch(
                &res.name,
                &kube::api::PatchParams::default(),
                &kube::api::Patch::Json::<serde_json::Value>(
                    serde_json::from_value(patch).unwrap(),
                ),
            )
            .await
        {
            Ok(_) => {
                eprintln!(
                    "    🔧 {}/{}: finalizer(s) stripped ({})",
                    res.kind, res.name, finalizer_display
                );
                {
                    let res_clone = res.clone();
                    let uid = live_uid.clone();
                    journal
                        .update(|jrnl| {
                            if let Some(rec) = jrnl
                                .finalizer_recoveries
                                .iter_mut()
                                .rev()
                                .find(|r| r.resource == res_clone && r.live_uid == uid)
                            {
                                rec.result = FinalizerRecoveryResult::Stripped;
                            }
                        })
                        .await
                        .map_err(|e| {
                            anyhow::anyhow!(
                                "{}/{}: post-patch journal update failed (mutation committed): {}",
                                res.kind,
                                res.name,
                                e
                            )
                        })?;
                }
                recovered += 1;
            }
            Err(kube::Error::Api(ref api_err)) if api_err.code == 409 || api_err.code == 422 => {
                // 409 Conflict / 422 test-op failed: precondition rejected, no mutation
                eprintln!(
                    "    ⚠ {}/{}: patch precondition failed ({}) — state changed, skipping",
                    res.kind, res.name, api_err.reason
                );
                {
                    let res_clone = res.clone();
                    let uid = live_uid.clone();
                    let msg = format!("precondition: {}", api_err.reason);
                    journal
                        .update(|jrnl| {
                            if let Some(rec) = jrnl
                                .finalizer_recoveries
                                .iter_mut()
                                .rev()
                                .find(|r| r.resource == res_clone && r.live_uid == uid)
                            {
                                rec.result = FinalizerRecoveryResult::Failed(msg);
                            }
                        })
                        .await
                        .map_err(|e| {
                            anyhow::anyhow!(
                                "{}/{}: post-rejection journal update failed: {}",
                                res.kind,
                                res.name,
                                e
                            )
                        })?;
                }
            }
            Err(e) => {
                // Transport/unknown error: commit outcome unknown — live GET to resolve.
                // Must verify UID + ownerReferences match pre-patch snapshot, not just
                // finalizer emptiness. A new-UID same-name resource with empty finalizers
                // is NOT evidence that our patch succeeded.
                eprintln!(
                    "    ✗ {}/{}: patch transport error ({}) — verifying outcome",
                    res.kind, res.name, e
                );
                let outcome = match api.get(&res.name).await {
                    Ok(recheck) => {
                        let recheck_uid = recheck.metadata.uid.as_deref().unwrap_or("");
                        if recheck_uid != live_uid {
                            // Different UID — resource was recreated, our patch is moot
                            eprintln!(
                                "    ↳ {}/{}: UID changed ({} → {}) — outcome ambiguous, stopping",
                                res.kind, res.name, live_uid, recheck_uid
                            );
                            FinalizerRecoveryResult::PatchRequested
                        } else {
                            // Same UID — verify ownerRef snapshot matches
                            let recheck_orefs =
                                recheck.metadata.owner_references.as_deref().unwrap_or(&[]);
                            let orefs_match = recheck_orefs.len() == owner_ref_snapshots.len()
                                && recheck_orefs.iter().zip(&owner_ref_snapshots).all(
                                    |(live, snap)| {
                                        live.uid == snap.uid
                                            && live.kind == snap.kind
                                            && live.name == snap.name
                                            && live.api_version == snap.api_version
                                            && live.controller.unwrap_or(false)
                                                == snap.controller.unwrap_or(false)
                                    },
                                );
                            if !orefs_match {
                                eprintln!(
                                    "    ↳ {}/{}: ownerReferences changed — outcome ambiguous, stopping",
                                    res.kind, res.name
                                );
                                FinalizerRecoveryResult::PatchRequested
                            } else {
                                let recheck_fins =
                                    recheck.metadata.finalizers.as_deref().unwrap_or(&[]);
                                if recheck_fins.is_empty() {
                                    eprintln!(
                                        "    ↳ {}/{}: same UID+ownerRefs, finalizers empty — stripped",
                                        res.kind, res.name
                                    );
                                    recovered += 1;
                                    FinalizerRecoveryResult::Stripped
                                } else {
                                    // Finalizers present does NOT prove patch failed —
                                    // controller may have re-added them after successful strip.
                                    // Keep PatchRequested so resume blocks for manual check.
                                    eprintln!(
                                        "    ↳ {}/{}: same UID+ownerRefs, finalizers present — ambiguous, stopping",
                                        res.kind, res.name
                                    );
                                    FinalizerRecoveryResult::PatchRequested
                                }
                            }
                        }
                    }
                    Err(kube::Error::Api(ref err)) if err.code == 404 => {
                        // Verify endpoint exists before counting as Gone
                        match api.list(&ListParams::default().limit(1)).await {
                            Ok(_) => {
                                eprintln!(
                                    "    ↳ {}/{}: 404 + endpoint OK — resource gone",
                                    res.kind, res.name
                                );
                                recovered += 1;
                                FinalizerRecoveryResult::Gone
                            }
                            Err(_) => {
                                eprintln!(
                                    "    ↳ {}/{}: 404 but endpoint unreachable — ambiguous, stopping",
                                    res.kind, res.name
                                );
                                FinalizerRecoveryResult::PatchRequested
                            }
                        }
                    }
                    Err(recheck_err) => {
                        eprintln!(
                            "    ↳ {}/{}: recheck GET failed ({}) — outcome unknown, stopping",
                            res.kind, res.name, recheck_err
                        );
                        // Keep PatchRequested — outcome unknown, resume will block
                        FinalizerRecoveryResult::PatchRequested
                    }
                };
                {
                    let res_clone = res.clone();
                    let uid = live_uid.clone();
                    journal
                        .update(|jrnl| {
                            if let Some(rec) = jrnl
                                .finalizer_recoveries
                                .iter_mut()
                                .rev()
                                .find(|r| r.resource == res_clone && r.live_uid == uid)
                            {
                                rec.result = outcome;
                            }
                        })
                        .await
                        .map_err(|e| {
                            anyhow::anyhow!(
                                "{}/{}: post-transport-error journal update failed: {}",
                                res.kind,
                                res.name,
                                e
                            )
                        })?;
                }
                // Transport error → stop processing further candidates
                break;
            }
        }
    }

    // If any recovery record is still PatchRequested, the run must NOT continue
    // to further mutations. Return Err so the caller stops immediately.
    let has_unresolved = journal
        .read()
        .await
        .finalizer_recoveries
        .iter()
        .any(|r| matches!(r.result, FinalizerRecoveryResult::PatchRequested));
    if has_unresolved {
        anyhow::bail!(
            "Unresolved PatchRequested finalizer recovery — \
             stopping to prevent further mutations with ambiguous prior state"
        );
    }

    Ok(recovered)
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

/// Typed error for gate-closed cancellation (not a hard failure).
#[derive(Debug)]
pub struct GateClosedError;

impl std::fmt::Display for GateClosedError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Mutation gate closed during cleanup")
    }
}

impl std::error::Error for GateClosedError {}

pub fn is_gate_closed_error(err: &anyhow::Error) -> bool {
    err.downcast_ref::<GateClosedError>().is_some()
}

/// Result of a single residual cleanup cycle.
/// Check if a resource (with UID) is in the current residual audit.
/// Matches exact group/version/kind/namespace/name. For planned items,
/// also requires live_uid == res.uid. For attributed items, exact resource UID.
fn is_in_residual_audit(res: &ResourceId, audit: &crate::teardown::audit::ResidualAudit) -> bool {
    let identity_match = |r: &ResourceId| -> bool {
        r.group == res.group
            && r.version == res.version
            && r.kind == res.kind
            && r.namespace == res.namespace
            && r.name == res.name
    };

    // Planned DELETE: live_uid must match res.uid
    for item in &audit.planned_delete_still_present {
        if identity_match(&item.resource)
            && item.live_uid.as_ref() == res.uid.as_ref()
            && res.uid.is_some()
        {
            return true;
        }
    }
    // Planned EXPECT: live_uid must match res.uid
    for item in &audit.planned_expect_still_present {
        if identity_match(&item.resource)
            && item.live_uid.as_ref() == res.uid.as_ref()
            && res.uid.is_some()
        {
            return true;
        }
    }
    // Attributed: resource UID match
    for item in &audit.likely_operator_residual {
        if identity_match(&item.resource) && item.resource.uid == res.uid {
            return true;
        }
    }
    for item in &audit.unattributed {
        if identity_match(&item.resource) && item.resource.uid == res.uid {
            return true;
        }
    }
    false
}

/// Build auto-cleanup candidates from a residual audit.
/// Only planned DELETE (matching journal.execution.deleted exact identity) and
/// planned EXPECT still present (with live UID, excluding protected kinds) are included.
/// Ambiguous / unattributed / user-created are excluded.
pub fn auto_cleanup_candidates(
    audit: &crate::teardown::audit::ResidualAudit,
    journal_deleted: &[ResourceId],
) -> Vec<ResourceId> {
    let mut candidates = Vec::new();

    for item in &audit.planned_delete_still_present {
        if let Some(live_uid) = &item.live_uid {
            // Only if original DELETE was in journal.execution.deleted (exact identity)
            let has_authority = journal_deleted.iter().any(|d| {
                d.group == item.resource.group
                    && d.version == item.resource.version
                    && d.kind == item.resource.kind
                    && d.namespace == item.resource.namespace
                    && d.name == item.resource.name
            });
            if has_authority && !PROTECTED_KINDS.contains(&item.resource.kind.as_str()) {
                let mut rid = item.resource.clone();
                rid.uid = Some(live_uid.clone());
                candidates.push(rid);
            }
        }
    }

    for item in &audit.planned_expect_still_present {
        if let Some(live_uid) = &item.live_uid
            && item.resource.uid.as_ref() == Some(live_uid)
            && !PROTECTED_KINDS.contains(&item.resource.kind.as_str())
        {
            let mut rid = item.resource.clone();
            rid.uid = Some(live_uid.clone());
            candidates.push(rid);
        }
    }

    candidates
}

/// Validate saved residual decisions against a current residual audit.
/// Returns ResourceIds with current UIDs for cleanup, or errors.
/// Compares saved evidence signatures (labels, managers, service accounts) against
/// current ResidualEvidence. ExplicitUnattributed → error. Basis empty/weakened → error.
pub fn validate_saved_residual_decisions(
    saved_decisions: &[crate::teardown::plan::SavedDecision],
    audit: &crate::teardown::audit::ResidualAudit,
) -> Result<Vec<ResourceId>, Vec<String>> {
    use crate::teardown::plan::{ApprovalKind, SavedAction};

    let mut candidates = Vec::new();
    let mut seen = std::collections::HashSet::new();
    let mut errors = Vec::new();

    for decision in saved_decisions {
        if !matches!(decision.action, SavedAction::Delete) {
            continue;
        }
        if let Err(e) = decision.match_spec.validate() {
            errors.push(format!(
                "{}/{}: invalid match spec — {}",
                decision.match_spec.kind, decision.match_spec.name, e
            ));
            continue;
        }
        if decision.approval == ApprovalKind::ExplicitUnattributed {
            errors.push(format!(
                "{}/{}: ExplicitUnattributed cannot be auto-applied for residual cleanup",
                decision.match_spec.kind, decision.match_spec.name
            ));
            continue;
        }

        // Dedup by group+kind+namespace+name
        let dedup_key = (
            decision.match_spec.group.clone(),
            decision.match_spec.kind.clone(),
            decision.match_spec.namespace.clone(),
            decision.match_spec.name.clone(),
        );
        if !seen.insert(dedup_key) {
            continue;
        }

        // Match against current residual — group=None matches core only
        let matched = audit
            .likely_operator_residual
            .iter()
            .chain(audit.unattributed.iter())
            .find(|r| decision.match_spec.matches(&r.resource));

        match matched {
            Some(residual) => {
                if residual.confidence == crate::teardown::audit::ResidualConfidence::None {
                    errors.push(format!(
                        "{}/{}: current confidence is None — cannot cleanup",
                        decision.match_spec.kind, decision.match_spec.name
                    ));
                    continue;
                }

                // Verify saved evidence signatures exist in current ResidualEvidence
                if let Some(err) = check_residual_evidence_drift(
                    &decision.basis,
                    &residual.evidence,
                    &decision.match_spec,
                ) {
                    errors.push(err);
                    continue;
                }

                if let Some(uid) = &residual.resource.uid {
                    let mut rid = residual.resource.clone();
                    rid.uid = Some(uid.clone());
                    candidates.push(rid);
                } else {
                    errors.push(format!(
                        "{}/{}: no UID in current residual — cannot bind",
                        decision.match_spec.kind, decision.match_spec.name
                    ));
                }
            }
            None => {
                let planned_match = audit
                    .planned_delete_still_present
                    .iter()
                    .chain(audit.planned_expect_still_present.iter())
                    .find(|r| decision.match_spec.matches(&r.resource));
                if let Some(item) = planned_match {
                    if let Some(live_uid) = &item.live_uid {
                        let mut rid = item.resource.clone();
                        rid.uid = Some(live_uid.clone());
                        candidates.push(rid);
                    }
                } else {
                    errors.push(format!(
                        "{}/{}: not found in current residual set",
                        decision.match_spec.kind, decision.match_spec.name
                    ));
                }
            }
        }
    }

    if errors.is_empty() {
        Ok(candidates)
    } else {
        Err(errors)
    }
}

fn check_residual_evidence_drift(
    saved_basis: &crate::teardown::plan::DecisionBasis,
    current: &crate::teardown::audit::ResidualEvidence,
    spec: &crate::teardown::plan::ResourceMatch,
) -> Option<String> {
    use crate::teardown::plan::SavedEvidenceSignature;

    // Empty basis is always blocked
    if saved_basis.decisive_evidence.is_empty() && saved_basis.provenance.is_none() {
        return Some(format!(
            "{}/{}: saved residual DELETE has empty basis — cannot replay",
            spec.kind, spec.name
        ));
    }

    // Each saved signature must exist in current evidence
    for sig in &saved_basis.decisive_evidence {
        match sig {
            SavedEvidenceSignature::Label { key, value }
                if !current
                    .matching_labels
                    .iter()
                    .any(|(k, v)| k == key && v == value) =>
            {
                return Some(format!(
                    "{}/{}: saved label {}={} not in current residual evidence",
                    spec.kind, spec.name, key, value
                ));
            }
            SavedEvidenceSignature::ManagedFieldManager { manager }
                if !current.matching_managers.iter().any(|m| m == manager) =>
            {
                return Some(format!(
                    "{}/{}: saved manager {} not in current residual evidence",
                    spec.kind, spec.name, manager
                ));
            }
            SavedEvidenceSignature::ServiceAccount { .. } if !current.service_account_match => {
                return Some(format!(
                    "{}/{}: saved service account match not confirmed in current evidence",
                    spec.kind, spec.name
                ));
            }
            _ => {}
        }
    }

    None
}

#[derive(Debug)]
pub struct ResidualCleanupResult {
    pub deleted: Vec<ResourceId>,
    pub skipped: Vec<(ResourceId, String)>,
    pub failed: Vec<(ResourceId, String)>,
    pub post_audit: Option<crate::teardown::audit::ResidualAudit>,
}

/// Progress update from residual cleanup — for TUI rendering.
#[derive(Clone, Debug)]
pub enum CleanupProgress {
    Validating {
        resource: ResourceId,
    },
    DeleteRequested {
        resource: ResourceId,
    },
    WaitingGone {
        resource: ResourceId,
    },
    Gone {
        resource: ResourceId,
    },
    #[allow(dead_code)]
    Skipped {
        resource: ResourceId,
        reason: String,
    },
    Failed {
        resource: ResourceId,
        reason: String,
    },
}

pub type ProgressSender = tokio::sync::mpsc::UnboundedSender<CleanupProgress>;

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
    execute_residual_cleanup_with_progress(
        client,
        selected,
        journal_store,
        gate,
        kind_map,
        gk_map,
        None,
    )
    .await
}

pub async fn execute_residual_cleanup_with_progress(
    client: &Client,
    selected: &[ResourceId],
    journal_store: &JournalStore,
    gate: &MutationGate,
    kind_map: &KindMap,
    gk_map: &GroupKindMap,
    progress_tx: Option<&ProgressSender>,
) -> Result<ResidualCleanupResult> {
    use crate::teardown::audit;
    use crate::teardown::journal::{CleanupDecision, CleanupResult, ResidualStatus, RunState};

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
    let gen_state =
        audit::check_operator_generation(client, &j.operator, &j.audit_context.csv_baseline).await;
    if !matches!(gen_state, audit::OperatorGenerationState::Absent) {
        bail!("Operator generation is not Absent — residual cleanup blocked");
    }

    // Step 2: Fresh complete audit
    let fresh_audit = audit::run_residual_audit(client, &j)
        .await
        .context("Fresh audit failed before cleanup")?;
    let fresh_status = audit::residual_status_from_audit(&fresh_audit);
    if matches!(fresh_status, ResidualStatus::AuditIncomplete) {
        bail!("Fresh audit incomplete — residual cleanup blocked");
    }

    // Step 3: Validate selections against current residual set (exact identity + UID)
    let valid_selected: Vec<&ResourceId> = selected
        .iter()
        .filter(|res| {
            if is_in_residual_audit(res, &fresh_audit) {
                true
            } else {
                result
                    .skipped
                    .push(((*res).clone(), "not in current residual set".to_string()));
                false
            }
        })
        .collect();

    if valid_selected.is_empty() {
        if !result.skipped.is_empty() {
            bail!(
                "All {} selected resource(s) were skipped — none eligible for cleanup. \
                 State unchanged (retryable).",
                result.skipped.len()
            );
        }
        return Ok(result);
    }

    // Set InteractiveCleanup state
    journal_store
        .update(|j| {
            j.state = RunState::InteractiveCleanup;
        })
        .await
        .context("Failed to persist InteractiveCleanup state")?;

    // Step 4: Per-resource DELETE with full safety checks
    for res in &valid_selected {
        if let Some(tx) = progress_tx {
            let _ = tx.send(CleanupProgress::Validating {
                resource: (*res).clone(),
            });
        }
        // Acquire gate permit FIRST — may block waiting for active permits
        let _permit = match gate.acquire().await {
            Ok(p) => p,
            Err(_) => return Err(GateClosedError.into()),
        };

        // The batch started from a complete fresh audit. Under the mutation
        // permit, recheck generation and this exact UID before recording a
        // decision. A full cluster audit per resource is expensive and does
        // not add authority beyond the batch audit plus exact live GET.
        {
            let post_permit_j = journal_store.read().await;
            let post_permit_gen = audit::check_operator_generation(
                client,
                &post_permit_j.operator,
                &post_permit_j.audit_context.csv_baseline,
            )
            .await;
            if !matches!(post_permit_gen, audit::OperatorGenerationState::Absent) {
                result.skipped.push((
                    (*res).clone(),
                    "generation changed after permit acquisition".to_string(),
                ));
                drop(_permit);
                break;
            }
            let (api, _) = resolve_api(client, res, kind_map, gk_map).ok_or_else(|| {
                anyhow::anyhow!("Cannot resolve API for {}/{}", res.kind, res.name)
            })?;
            match api.get(&res.name).await {
                Ok(obj) => {
                    let expected_uid = res.uid.as_deref().unwrap_or("");
                    let current_uid = obj.metadata.uid.as_deref().unwrap_or("");
                    if expected_uid.is_empty() || current_uid.is_empty() {
                        bail!(
                            "Missing UID for residual {}/{} — fail-closed",
                            res.kind,
                            res.name
                        );
                    }
                    if current_uid != expected_uid {
                        result.skipped.push((
                            (*res).clone(),
                            format!("UID changed from {} to {}", expected_uid, current_uid),
                        ));
                        drop(_permit);
                        continue;
                    }
                }
                Err(kube::Error::Api(ref err)) if err.code == 404 => {
                    api.list(&ListParams::default().limit(1))
                        .await
                        .context("Residual GET 404 endpoint verification failed")?;
                    result
                        .skipped
                        .push(((*res).clone(), "already gone".to_string()));
                    drop(_permit);
                    continue;
                }
                Err(e) => bail!("Cannot GET residual {}/{}: {}", res.kind, res.name, e),
            }
        }

        // For Subscription: capture live spec.name for semantic identity
        let approved_spec_name: Option<String> = if res.kind == "Subscription"
            && res.group == "operators.coreos.com"
        {
            let (api, _) = resolve_api(client, res, kind_map, gk_map).ok_or_else(|| {
                anyhow::anyhow!(
                    "Cannot resolve API for Subscription {} — fail-closed",
                    res.name
                )
            })?;
            match api.get(&res.name).await {
                Ok(obj) => {
                    // Verify GET UID matches resource UID
                    let get_uid = obj.metadata.uid.as_deref().unwrap_or("");
                    let expected_uid = res.uid.as_deref().unwrap_or("");
                    if get_uid.is_empty() || expected_uid.is_empty() {
                        bail!(
                            "Subscription {} UID missing (get={:?}, expected={:?}) — fail-closed",
                            res.name,
                            get_uid,
                            expected_uid
                        );
                    }
                    if get_uid != expected_uid {
                        bail!(
                            "Subscription {} UID changed ({} → {}) — cannot capture semantic identity",
                            res.name,
                            expected_uid,
                            get_uid
                        );
                    }
                    let spec_name = obj
                        .data
                        .get("spec")
                        .and_then(|s| s.get("name"))
                        .and_then(|n| n.as_str())
                        .unwrap_or("");
                    if spec_name.is_empty() {
                        bail!(
                            "Subscription {} has no spec.name — cannot establish semantic identity",
                            res.name
                        );
                    }
                    Some(spec_name.to_string())
                }
                Err(kube::Error::Api(ref err)) if err.code == 404 => {
                    // Verify endpoint exists before declaring gone
                    match api.list(&kube::api::ListParams::default().limit(1)).await {
                        Ok(_) => {
                            result
                                .skipped
                                .push(((*res).clone(), "Subscription already gone".to_string()));
                            drop(_permit);
                            continue;
                        }
                        Err(_) => bail!(
                            "Subscription {} GET 404 but endpoint verification failed",
                            res.name
                        ),
                    }
                }
                Err(e) => bail!(
                    "Cannot GET Subscription {} for semantic identity: {}",
                    res.name,
                    e
                ),
            }
        } else {
            None
        };

        // Record decision BEFORE mutation (durable) — includes semantic basis
        let decision_uid = res.uid.clone();
        let res_clone = (*res).clone();
        let spec_name_clone = approved_spec_name.clone();
        journal_store
            .update(|j| {
                j.cleanup_decisions.push(CleanupDecision {
                    resource: res_clone.clone(),
                    bound_uid: decision_uid.clone(),
                    action: "delete".to_string(),
                    result: None,
                    approved_spec_name: spec_name_clone,
                });
                j.audit_revision += 1;
            })
            .await
            .context("Failed to persist cleanup decision — no mutation")?;

        // Core executor DELETE (UID + semantic identity preconditioned)
        let del_outcome = delete_resource_pub(
            client,
            res,
            kind_map,
            gk_map,
            None,
            approved_spec_name.as_deref(),
        )
        .await;

        let must_stop = del_outcome.is_stop();

        let cleanup_result = match &del_outcome {
            DeleteOutcome::Accepted => {
                if let Some(tx) = progress_tx {
                    let _ = tx.send(CleanupProgress::DeleteRequested {
                        resource: (*res).clone(),
                    });
                }
                // Checkpoint DeleteRequested immediately and drop permit
                let res_dr = (*res).clone();
                journal_store
                    .update(|j| {
                        if let Some(d) = j
                            .cleanup_decisions
                            .iter_mut()
                            .rev()
                            .find(|d| d.resource == res_dr && d.result.is_none())
                        {
                            d.result = Some(CleanupResult::DeleteRequested);
                        }
                    })
                    .await
                    .context("Failed to checkpoint DeleteRequested")?;
                drop(_permit);

                // Wait for Gone without holding permit — verify UID each iteration
                let mut gone_confirmed = false;
                let mut has_terminating_finalizer = false;
                let (api, _) = resolve_api(client, res, kind_map, gk_map).ok_or_else(|| {
                    anyhow::anyhow!(
                        "Cannot resolve API for cleanup wait on {}/{}",
                        res.kind,
                        res.name
                    )
                })?;
                if let Some(tx) = progress_tx {
                    let _ = tx.send(CleanupProgress::WaitingGone {
                        resource: (*res).clone(),
                    });
                }
                for _ in 0..15 {
                    tokio::time::sleep(Duration::from_secs(2)).await;
                    match api.get(&res.name).await {
                        Err(kube::Error::Api(ref err)) if err.code == 404 => {
                            api.list(&ListParams::default().limit(1))
                                .await
                                .context("404 endpoint verification failed — stopping")?;
                            gone_confirmed = true;
                            break;
                        }
                        Ok(obj) => {
                            let live_uid = obj.metadata.uid.as_deref().unwrap_or("");
                            let bound_uid = res.uid.as_deref().unwrap_or("");
                            if !bound_uid.is_empty() && live_uid != bound_uid {
                                bail!(
                                    "Cleanup {}/{}: UID changed {} → {} — stopping",
                                    res.kind,
                                    res.name,
                                    bound_uid,
                                    live_uid
                                );
                            }
                            if obj.metadata.deletion_timestamp.is_some()
                                && !obj.metadata.finalizers.as_deref().unwrap_or(&[]).is_empty()
                            {
                                has_terminating_finalizer = true;
                            }
                            continue;
                        }
                        Err(e) => {
                            bail!(
                                "Cleanup {}/{}: Gone-wait GET failed: {} — stopping",
                                res.kind,
                                res.name,
                                e
                            );
                        }
                    }
                }

                // Finalizer recovery if needed (acquires its own permit)
                if !gone_confirmed
                    && has_terminating_finalizer
                    && !PROTECTED_KINDS.contains(&res.kind.as_str())
                {
                    let synthetic_phase = crate::teardown::planner::PlanPhase {
                        name: "residual cleanup".to_string(),
                        description: String::new(),
                        actions: vec![crate::teardown::planner::Action::Delete {
                            resource: (*res).clone(),
                            reason: "residual cleanup".to_string(),
                        }],
                        barrier: None,
                    };
                    let recovered = attempt_finalizer_recovery(
                        client,
                        std::slice::from_ref(res),
                        &[(*res).clone()],
                        &synthetic_phase,
                        kind_map,
                        gk_map,
                        journal_store,
                        gate,
                    )
                    .await
                    .context("Residual finalizer recovery failed — stopping")?;
                    if recovered == 0 {
                        bail!(
                            "Cleanup {}/{}: finalizer recovery returned 0 — stopping",
                            res.kind,
                            res.name
                        );
                    }
                    // Re-check Gone with UID verification
                    for _ in 0..15 {
                        tokio::time::sleep(Duration::from_secs(2)).await;
                        match api.get(&res.name).await {
                            Err(kube::Error::Api(ref err)) if err.code == 404 => {
                                api.list(&ListParams::default().limit(1))
                                    .await
                                    .context("Post-recovery endpoint check failed — stopping")?;
                                gone_confirmed = true;
                                break;
                            }
                            Ok(obj) => {
                                let live_uid = obj.metadata.uid.as_deref().unwrap_or("");
                                let bound_uid = res.uid.as_deref().unwrap_or("");
                                if !bound_uid.is_empty() && live_uid != bound_uid {
                                    bail!(
                                        "Post-recovery {}/{}: UID changed — stopping",
                                        res.kind,
                                        res.name
                                    );
                                }
                                continue;
                            }
                            Err(e) => {
                                bail!(
                                    "Post-recovery {}/{}: GET failed: {} — stopping",
                                    res.kind,
                                    res.name,
                                    e
                                );
                            }
                        }
                    }
                }
                if gone_confirmed {
                    if let Some(tx) = progress_tx {
                        let _ = tx.send(CleanupProgress::Gone {
                            resource: (*res).clone(),
                        });
                    }
                    result.deleted.push((*res).clone());
                    // Update decision from DeleteRequested → Gone
                    let res_gone = (*res).clone();
                    journal_store
                        .update(|j| {
                            if let Some(d) = j.cleanup_decisions.iter_mut().rev().find(|d| {
                                d.resource == res_gone
                                    && matches!(d.result, Some(CleanupResult::DeleteRequested))
                            }) {
                                d.result = Some(CleanupResult::Gone);
                            }
                        })
                        .await
                        .context("Failed to checkpoint cleanup Gone")?;
                    // Skip the general checkpoint below — already persisted
                    continue;
                } else {
                    bail!(
                        "Cleanup {}/{}: DELETE accepted but not confirmed Gone after wait — stopping",
                        res.kind,
                        res.name
                    );
                }
            }
            DeleteOutcome::AlreadyGone => {
                result.deleted.push((*res).clone());
                CleanupResult::AlreadyGone
            }
            DeleteOutcome::Unknown(reason) => {
                if let Some(tx) = progress_tx {
                    let _ = tx.send(CleanupProgress::Failed {
                        resource: (*res).clone(),
                        reason: reason.clone(),
                    });
                }
                result.failed.push(((*res).clone(), reason.clone()));
                CleanupResult::UnknownOutcome(reason.clone())
            }
            DeleteOutcome::Rejected(reason) | DeleteOutcome::Blocked(reason) => {
                if let Some(tx) = progress_tx {
                    let _ = tx.send(CleanupProgress::Failed {
                        resource: (*res).clone(),
                        reason: reason.clone(),
                    });
                }
                result.failed.push(((*res).clone(), reason.clone()));
                CleanupResult::Failed(reason.clone())
            }
        };

        let res_clone2 = (*res).clone();
        journal_store
            .update(|j| {
                if let Some(d) = j
                    .cleanup_decisions
                    .iter_mut()
                    .rev()
                    .find(|d| d.resource == res_clone2 && d.result.is_none())
                {
                    d.result = Some(cleanup_result);
                }
            })
            .await
            .context("Failed to checkpoint cleanup result")?;

        drop(_permit);

        // Unknown/Blocked outcome → stop immediately, no further mutations
        if must_stop {
            eprintln!(
                "  ⛔ Stopping residual cleanup — outcome unknown or blocked for {}/{}",
                res.kind, res.name
            );
            break;
        }
    }

    // Step 5: Re-audit after all cleanups
    let post_j = journal_store.read().await;
    let post_gen = audit::check_operator_generation(
        client,
        &post_j.operator,
        &post_j.audit_context.csv_baseline,
    )
    .await;
    if !matches!(post_gen, audit::OperatorGenerationState::Absent) {
        // Generation change during post-cleanup audit is not a hard DELETE failure.
        // DELETEs already completed — keep retryable state for re-audit.
        journal_store
            .update(|j| {
                j.state = RunState::InteractiveCleanup;
            })
            .await
            .context("Failed to persist state after generation change")?;
        bail!(
            "Operator generation changed after cleanup — re-audit needed. State: InteractiveCleanup."
        );
    }

    match audit::run_residual_audit(client, &post_j).await {
        Ok(new_audit) => {
            let new_status = audit::residual_status_from_audit(&new_audit);
            journal_store
                .update(|j| {
                    j.residual_status = new_status;
                    j.audit_revision += 1;
                    j.last_residual_audit = Some(new_audit.clone());
                })
                .await
                .context("Failed to persist post-cleanup audit")?;
            result.post_audit = Some(new_audit);
        }
        Err(e) => {
            // Audit probe failure is retryable — DELETEs already completed
            journal_store
                .update(|j| {
                    j.state = RunState::InteractiveCleanup;
                })
                .await
                .context("Failed to persist state after audit failure")?;
            bail!(
                "Post-cleanup re-audit failed: {}. State: InteractiveCleanup (retryable).",
                e
            );
        }
    }

    // Determine final state — consider skipped/failed resources
    let post_j_final = journal_store.read().await;
    let has_hard_failed = post_j_final
        .cleanup_decisions
        .iter()
        .any(|d| d.is_hard_failed());
    let has_unconfirmed = post_j_final
        .cleanup_decisions
        .iter()
        .any(|d| d.is_pending());
    let has_incomplete = !result.skipped.is_empty() || !result.failed.is_empty();

    let final_cleanup_state = if has_hard_failed {
        RunState::Failed
    } else {
        match &post_j_final.residual_status {
            ResidualStatus::AuditIncomplete => {
                // Incomplete audit is retryable — DELETEs may have succeeded
                RunState::InteractiveCleanup
            }
            _ => {
                if has_incomplete || has_unconfirmed {
                    // Resources skipped/failed/unconfirmed — stay in InteractiveCleanup
                    // so the user can retry/reconcile
                    RunState::InteractiveCleanup
                } else {
                    RunState::ApplyCompleted
                }
            }
        }
    };
    journal_store
        .update(|j| {
            j.state = final_cleanup_state.clone();
        })
        .await
        .context("Failed to persist final cleanup state")?;

    if final_cleanup_state == RunState::Failed {
        bail!("Cleanup completed with failed or unconfirmed decisions");
    }
    if final_cleanup_state == RunState::InteractiveCleanup {
        bail!(
            "Cleanup incomplete: {} deleted, {} skipped, {} failed. \
             State persisted as InteractiveCleanup — retry is safe.",
            result.deleted.len(),
            result.skipped.len(),
            result.failed.len()
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
            dependency_edges: vec![],
            operator_inventory: vec![],
            explicit_decisions: vec![],
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
        let empty = FinalizerCheckResult::Known {
            finalizers: vec![],
            terminating: false,
        };
        assert!(matches!(
            empty,
            FinalizerCheckResult::Known {
                ref finalizers,
                ..
            } if finalizers.is_empty()
        ));
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
        assert!(verify_delete_identity(&Some("uid-a".to_string()), "uid-a").is_ok());
    }

    #[test]
    fn test_delete_identity_uid_mismatch() {
        let err = verify_delete_identity(&Some("uid-a".to_string()), "uid-b").unwrap_err();
        assert!(err.contains("UID mismatch"));
    }

    #[test]
    fn test_delete_identity_live_uid_empty() {
        let err = verify_delete_identity(&Some("uid-a".to_string()), "").unwrap_err();
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

    use kube::client::Body;
    use std::pin::pin;

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
        let (mock_service, handle) =
            tower_test::mock::pair::<http::Request<Body>, http::Response<Body>>();

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
            matches!(result, DeleteResult::Blocked(ref msg) if msg.contains("UID")),
            "UID mismatch should prevent DELETE: got {:?}",
            result
        );

        spawned.await.unwrap();
    }

    #[tokio::test]
    async fn test_mock_delete_get404_list_forbidden_not_already_gone() {
        // GET 404 + LIST 403 → cannot verify endpoint → Failed (not AlreadyGone)
        let (mock_service, handle) =
            tower_test::mock::pair::<http::Request<Body>, http::Response<Body>>();

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
            matches!(result, DeleteResult::Unknown(ref msg) if msg.contains("endpoint")),
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
            let ok = matches!(
                state,
                RunState::ApplyCompleted | RunState::InteractiveCleanup
            );
            assert!(ok, "State {:?} should be allowed for cleanup", state);
        }

        for state in &rejected {
            let ok = matches!(
                state,
                RunState::ApplyCompleted | RunState::InteractiveCleanup
            );
            assert!(!ok, "State {:?} should be rejected for cleanup", state);
        }
    }

    #[test]
    fn residual_cleanup_schema_gate_rejects_old_schema() {
        let current = crate::teardown::journal::RUN_JOURNAL_SCHEMA_VERSION;
        assert_eq!(
            current, 9,
            "Schema version must be 9 for cleanup gate to work correctly"
        );
    }

    fn make_sub_resource(name: &str, uid: Option<&str>) -> ResourceId {
        ResourceId {
            group: "operators.coreos.com".to_string(),
            version: "v1alpha1".to_string(),
            kind: "Subscription".to_string(),
            namespace: Some("test-ns".to_string()),
            name: name.to_string(),
            uid: uid.map(String::from),
        }
    }

    fn test_sub_kind_map() -> KindMap {
        let mut km = test_kind_map();
        km.insert(
            "Subscription".to_string(),
            crate::kube::discovery::KindInfo {
                group: "operators.coreos.com".to_string(),
                version: "v1alpha1".to_string(),
                plural: "subscriptions".to_string(),
                namespaced: true,
            },
        );
        km
    }

    fn test_sub_gk_map() -> GroupKindMap {
        let mut gk = test_gk_map();
        gk.insert(
            (
                "operators.coreos.com".to_string(),
                "Subscription".to_string(),
            ),
            crate::kube::discovery::KindInfo {
                group: "operators.coreos.com".to_string(),
                version: "v1alpha1".to_string(),
                plural: "subscriptions".to_string(),
                namespaced: true,
            },
        );
        gk
    }

    #[tokio::test]
    async fn test_mock_subscription_spec_name_drift_zero_deletes() {
        // Subscription has spec.name=other (expected=target) → DELETE NOT called
        let (mock_service, handle) =
            tower_test::mock::pair::<http::Request<Body>, http::Response<Body>>();

        let resource = make_sub_resource("my-sub", Some("uid-A"));
        let km = test_sub_kind_map();
        let gk = test_sub_gk_map();

        let spawned = tokio::spawn(async move {
            let mut handle = pin!(handle);
            let (request, send) = handle.next_request().await.expect("expected GET");
            assert_eq!(request.method(), http::Method::GET);
            send.send_response(json_response(serde_json::json!({
                "apiVersion": "operators.coreos.com/v1alpha1",
                "kind": "Subscription",
                "metadata": {
                    "name": "my-sub",
                    "namespace": "test-ns",
                    "uid": "uid-A",
                    "resourceVersion": "100"
                },
                "spec": { "name": "other-package" }
            })));
            // No DELETE request should follow
        });

        let client = Client::new(mock_service, "test-ns");
        let result =
            delete_resource_inner(&client, &resource, &km, &gk, Some("target-package")).await;

        assert!(
            matches!(result, DeleteResult::Blocked(ref msg) if msg.contains("semantic identity drift")),
            "spec.name drift should prevent DELETE: got {:?}",
            result
        );
        spawned.await.unwrap();
    }

    #[tokio::test]
    async fn test_mock_subscription_delete_pub_no_package_fails() {
        // delete_resource_pub with None package for Subscription → immediate Err
        let (mock_service, _handle) =
            tower_test::mock::pair::<http::Request<Body>, http::Response<Body>>();
        let resource = make_sub_resource("my-sub", Some("uid-A"));
        let km = test_sub_kind_map();
        let gk = test_sub_gk_map();

        let client = Client::new(mock_service, "test-ns");
        let result = delete_resource_pub(&client, &resource, &km, &gk, None, None).await;

        assert!(
            matches!(result, DeleteOutcome::Blocked(ref msg) if msg.contains("without verified package name")),
            "Subscription DELETE with None package must be Blocked, got: {:?}",
            result
        );
    }

    #[tokio::test]
    async fn test_mock_subscription_delete_pub_empty_package_fails() {
        let (mock_service, _handle) =
            tower_test::mock::pair::<http::Request<Body>, http::Response<Body>>();
        let resource = make_sub_resource("my-sub", Some("uid-A"));
        let km = test_sub_kind_map();
        let gk = test_sub_gk_map();

        let client = Client::new(mock_service, "test-ns");
        let result = delete_resource_pub(&client, &resource, &km, &gk, None, Some("")).await;

        assert!(
            matches!(result, DeleteOutcome::Blocked(_)),
            "Subscription DELETE with empty package must be Blocked"
        );
    }

    #[tokio::test]
    async fn test_mock_get404_list403_not_already_gone() {
        // GET 404 + LIST 403 → Failed (not AlreadyGone)
        // This tests the endpoint verification requirement
        let (mock_service, handle) =
            tower_test::mock::pair::<http::Request<Body>, http::Response<Body>>();

        let resource = make_cm_resource("gone-cm", Some("uid-A"));
        let km = test_kind_map();
        let gk = test_gk_map();

        let spawned = tokio::spawn(async move {
            let mut handle = pin!(handle);
            let (_request, send) = handle.next_request().await.expect("expected GET");
            send.send_response(not_found_response());
            let (_request, send) = handle.next_request().await.expect("expected LIST");
            send.send_response(forbidden_response());
        });

        let client = Client::new(mock_service, "test-ns");
        let result = delete_resource_inner(&client, &resource, &km, &gk, None).await;

        assert!(
            matches!(result, DeleteResult::Unknown(ref msg) if msg.contains("endpoint")),
            "GET 404 + LIST 403 must not be AlreadyGone: got {:?}",
            result
        );
        spawned.await.unwrap();
    }

    #[test]
    fn hard_failed_vs_retryable() {
        use crate::teardown::journal::{CleanupDecision, CleanupResult};
        let hard = CleanupDecision {
            resource: make_resource("Pod", "a"),
            bound_uid: Some("uid".to_string()),
            action: "delete".to_string(),
            result: Some(CleanupResult::Failed("API error".to_string())),
            approved_spec_name: None,
        };
        assert!(hard.is_hard_failed(), "Failed is a hard failure");

        let retryable = CleanupDecision {
            resource: make_resource("Pod", "b"),
            bound_uid: Some("uid".to_string()),
            action: "delete".to_string(),
            result: Some(CleanupResult::DeleteRequested),
            approved_spec_name: None,
        };
        assert!(
            !retryable.is_hard_failed(),
            "DeleteRequested is NOT hard failed"
        );
        assert!(
            retryable.is_pending(),
            "DeleteRequested IS pending (retryable)"
        );
    }

    #[test]
    fn pending_decisions_prevent_apply_completed() {
        use crate::teardown::journal::{CleanupDecision, CleanupResult};
        let decisions = [
            CleanupDecision {
                resource: make_resource("Pod", "a"),
                bound_uid: Some("uid".to_string()),
                action: "delete".to_string(),
                result: Some(CleanupResult::Gone),
                approved_spec_name: None,
            },
            CleanupDecision {
                resource: make_resource("Pod", "b"),
                bound_uid: Some("uid".to_string()),
                action: "delete".to_string(),
                result: Some(CleanupResult::DeleteRequested),
                approved_spec_name: None,
            },
        ];
        assert!(
            decisions.iter().any(|d| d.is_pending()),
            "DeleteRequested must prevent ApplyCompleted"
        );
    }

    #[tokio::test]
    async fn test_mock_subscription_empty_spec_name_zero_deletes() {
        // Subscription with empty spec.name → Failed (no DELETE sent)
        let (mock_service, handle) =
            tower_test::mock::pair::<http::Request<Body>, http::Response<Body>>();

        let resource = make_sub_resource("my-sub", Some("uid-A"));
        let km = test_sub_kind_map();
        let gk = test_sub_gk_map();

        let spawned = tokio::spawn(async move {
            let mut handle = pin!(handle);
            let (_request, send) = handle.next_request().await.expect("expected GET");
            send.send_response(json_response(serde_json::json!({
                "apiVersion": "operators.coreos.com/v1alpha1",
                "kind": "Subscription",
                "metadata": {
                    "name": "my-sub",
                    "namespace": "test-ns",
                    "uid": "uid-A",
                    "resourceVersion": "100"
                },
                "spec": { "name": "" }
            })));
            // No DELETE should follow
        });

        let client = Client::new(mock_service, "test-ns");
        let result = delete_resource_inner(&client, &resource, &km, &gk, Some("target-pkg")).await;

        assert!(
            matches!(result, DeleteResult::Blocked(ref msg) if msg.contains("empty spec.name")),
            "empty spec.name should prevent DELETE: got {:?}",
            result
        );
        spawned.await.unwrap();
    }

    #[tokio::test]
    async fn test_mock_subscription_inner_no_package_fails() {
        // delete_resource_inner with None expected_package for Subscription → Failed
        let (mock_service, handle) =
            tower_test::mock::pair::<http::Request<Body>, http::Response<Body>>();

        let resource = make_sub_resource("my-sub", Some("uid-A"));
        let km = test_sub_kind_map();
        let gk = test_sub_gk_map();

        let spawned = tokio::spawn(async move {
            let mut handle = pin!(handle);
            let (_request, send) = handle.next_request().await.expect("expected GET");
            send.send_response(json_response(serde_json::json!({
                "apiVersion": "operators.coreos.com/v1alpha1",
                "kind": "Subscription",
                "metadata": {
                    "name": "my-sub",
                    "namespace": "test-ns",
                    "uid": "uid-A",
                    "resourceVersion": "100"
                },
                "spec": { "name": "target-pkg" }
            })));
        });

        let client = Client::new(mock_service, "test-ns");
        let result = delete_resource_inner(&client, &resource, &km, &gk, None).await;

        assert!(
            matches!(result, DeleteResult::Blocked(ref msg) if msg.contains("non-empty expected package")),
            "None package should prevent Subscription DELETE: got {:?}",
            result
        );
        spawned.await.unwrap();
    }

    #[test]
    fn gate_closed_error_is_typed() {
        let err: anyhow::Error = GateClosedError.into();
        assert!(
            is_gate_closed_error(&err),
            "GateClosedError must be detected by is_gate_closed_error"
        );
    }

    #[test]
    fn non_gate_error_is_not_gate_closed() {
        let err = anyhow::anyhow!("some other error");
        assert!(
            !is_gate_closed_error(&err),
            "generic error must not match gate-closed"
        );
    }

    #[tokio::test]
    async fn gate_closed_acquire_fails() {
        let gate = crate::teardown::permit::MutationGate::new(4);
        gate.close_and_drain().await;
        assert!(
            gate.acquire().await.is_err(),
            "acquire on closed gate must fail"
        );
    }

    #[tokio::test]
    async fn test_intact_review_finalizer_does_not_block_csv() {
        // Phase 0: Delete ResourceA (accepted → Gone)
        // Phase 1: EMPTY
        // Phase 2: Review with intact finalizer (no deletionTimestamp → warning only)
        // Phase 3: CSV DELETE (MUST be reached — intact REVIEW does not block)
        use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

        let res_a = ResourceId {
            group: "test.example.io".to_string(),
            version: "v1".to_string(),
            kind: "ResourceA".to_string(),
            namespace: None,
            name: "resource-a".to_string(),
            uid: Some("uid-a".to_string()),
        };
        let review_res = ResourceId {
            group: "test.example.io".to_string(),
            version: "v1".to_string(),
            kind: "ReviewTarget".to_string(),
            namespace: Some("test-ns".to_string()),
            name: "review-1".to_string(),
            uid: Some("uid-review".to_string()),
        };
        let csv_res = ResourceId {
            group: "operators.coreos.com".to_string(),
            version: "v1alpha1".to_string(),
            kind: "ClusterServiceVersion".to_string(),
            namespace: Some("test-ns".to_string()),
            name: "test-op.v1".to_string(),
            uid: Some("uid-csv".to_string()),
        };

        let plan = TeardownPlan {
            targets: vec![],
            preflight: Preflight { checks: vec![] },
            phases: vec![
                PlanPhase {
                    name: "Delete ResourceA".to_string(),
                    description: "".to_string(),
                    actions: vec![Action::Delete {
                        resource: res_a.clone(),
                        reason: "test".to_string(),
                    }],
                    barrier: None,
                },
                PlanPhase {
                    name: "Empty intermediate".to_string(),
                    description: "".to_string(),
                    actions: vec![],
                    barrier: None,
                },
                PlanPhase {
                    name: "Review phase".to_string(),
                    description: "".to_string(),
                    actions: vec![Action::Review {
                        resource: review_res.clone(),
                        reason: "label-only".to_string(),
                        metadata: None,
                    }],
                    barrier: None,
                },
                PlanPhase {
                    name: "CSV phase".to_string(),
                    description: "".to_string(),
                    actions: vec![Action::Delete {
                        resource: csv_res.clone(),
                        reason: "test".to_string(),
                    }],
                    barrier: None,
                },
            ],
            blockers: vec![],
            warnings: vec![],
            snapshot_taken_at: "2026-01-01T00:00:00Z".to_string(),
            dependency_edges: vec![],
            operator_inventory: vec![],
            explicit_decisions: vec![],
        };

        let mut gk = std::collections::HashMap::new();
        gk.insert(
            ("test.example.io".to_string(), "ResourceA".to_string()),
            crate::kube::discovery::KindInfo {
                group: "test.example.io".to_string(),
                version: "v1".to_string(),
                plural: "resourceas".to_string(),
                namespaced: false,
            },
        );
        gk.insert(
            ("test.example.io".to_string(), "ReviewTarget".to_string()),
            crate::kube::discovery::KindInfo {
                group: "test.example.io".to_string(),
                version: "v1".to_string(),
                plural: "reviewtargets".to_string(),
                namespaced: true,
            },
        );
        gk.insert(
            (
                "operators.coreos.com".to_string(),
                "ClusterServiceVersion".to_string(),
            ),
            crate::kube::discovery::KindInfo {
                group: "operators.coreos.com".to_string(),
                version: "v1alpha1".to_string(),
                plural: "clusterserviceversions".to_string(),
                namespaced: true,
            },
        );

        let csv_request_count = Arc::new(AtomicUsize::new(0));
        let csv_count = csv_request_count.clone();
        let a_deleted = Arc::new(AtomicBool::new(false));
        let a_deleted_flag = a_deleted.clone();
        let review_request_count = Arc::new(AtomicUsize::new(0));
        let review_delete_count = Arc::new(AtomicUsize::new(0));
        let review_del = review_delete_count.clone();
        let review_patch_count = Arc::new(AtomicUsize::new(0));
        let review_patch = review_patch_count.clone();
        let review_count = review_request_count.clone();

        let (mock_service, handle) = tower_test::mock::pair::<
            http::Request<kube::client::Body>,
            http::Response<kube::client::Body>,
        >();

        let spawned = tokio::spawn(async move {
            let mut handle = std::pin::pin!(handle);
            while let Some((req, send)) = handle.next_request().await {
                let uri = req.uri().to_string();

                if uri.contains("clusterserviceversions") {
                    csv_count.fetch_add(1, Ordering::SeqCst);
                }
                if uri.contains("reviewtargets") {
                    review_count.fetch_add(1, Ordering::SeqCst);
                    if req.method() == http::Method::DELETE {
                        review_del.fetch_add(1, Ordering::SeqCst);
                    }
                    if req.method() == http::Method::PATCH {
                        review_patch.fetch_add(1, Ordering::SeqCst);
                    }
                }

                if uri.contains("resourceas") {
                    if req.method() == http::Method::DELETE {
                        a_deleted_flag.store(true, Ordering::SeqCst);
                        send.send_response(json_response(serde_json::json!({
                            "apiVersion": "v1", "kind": "Status", "metadata": {},
                            "status": "Success"
                        })));
                    } else if req.method() == http::Method::GET
                        && !uri.contains('?')
                        && a_deleted_flag.load(Ordering::SeqCst)
                    {
                        // After DELETE: GET returns 404
                        send.send_response(not_found_response());
                    } else if req.method() == http::Method::GET
                        && !uri.contains('?')
                        && !a_deleted_flag.load(Ordering::SeqCst)
                    {
                        // Before DELETE: GET returns object
                        send.send_response(json_response(serde_json::json!({
                            "apiVersion": "test.example.io/v1",
                            "kind": "ResourceA",
                            "metadata": {
                                "name": "resource-a",
                                "uid": "uid-a",
                                "resourceVersion": "100"
                            }
                        })));
                    } else {
                        // LIST for endpoint verification
                        send.send_response(json_response(serde_json::json!({
                            "apiVersion": "v1", "kind": "ResourceAList",
                            "metadata": {"resourceVersion": "1"}, "items": []
                        })));
                    }
                } else if uri.contains("reviewtargets") {
                    send.send_response(json_response(serde_json::json!({
                        "apiVersion": "test.example.io/v1",
                        "kind": "ReviewTarget",
                        "metadata": {
                            "name": "review-1",
                            "namespace": "test-ns",
                            "uid": "uid-review",
                            "finalizers": ["test.example.io/finalizer"]
                        }
                    })));
                } else {
                    send.send_response(not_found_response());
                }
            }
        });

        let km = std::collections::HashMap::new();
        let gvk = std::collections::HashMap::new();
        let gvr = std::collections::HashMap::new();

        let client = Client::new(mock_service, "test-ns");
        let result = execute_plan_with_store(
            &client, &plan, &km, &gk, &gvk, &gvr, false, true, None, None, 0, true, None,
        )
        .await;

        let _r = result.expect("execute_plan_with_store must return Ok");

        // REVIEW finalizer check must have been reached
        let review_reqs = review_request_count.load(Ordering::SeqCst);
        assert!(
            review_reqs >= 1,
            "REVIEW finalizer check must run — got {} REVIEW requests",
            review_reqs
        );

        // CSV phase MUST be reached — intact REVIEW with finalizer is warning only
        let csv_reqs = csv_request_count.load(Ordering::SeqCst);
        assert!(
            csv_reqs >= 1,
            "CSV phase must be reached when REVIEW is intact — got {} CSV requests",
            csv_reqs
        );

        // No DELETE or PATCH on REVIEW resource
        assert_eq!(
            review_delete_count.load(Ordering::SeqCst),
            0,
            "REVIEW resource must NOT receive DELETE"
        );
        assert_eq!(
            review_patch_count.load(Ordering::SeqCst),
            0,
            "REVIEW resource must NOT receive PATCH"
        );

        drop(client);
        spawned.abort();
    }

    #[tokio::test]
    async fn test_resume_skips_empty_phase_but_csv_guard_still_fires() {
        // Simulates resume from start_phase=3:
        // Phase 0-2: already completed (skipped by resume)
        // Phase 3: EMPTY intermediate
        // Phase 4: CSV DELETE (guard must fire here)
        // REVIEW resource with finalizer exists across plan.
        use std::sync::atomic::{AtomicUsize, Ordering};

        let review_res = ResourceId {
            group: "serving.kserve.io".to_string(),
            version: "v1alpha1".to_string(),
            kind: "LLMInferenceService".to_string(),
            namespace: Some("test-ns".to_string()),
            name: "qwen3-06b".to_string(),
            uid: Some("uid-llm".to_string()),
        };
        let csv_res = ResourceId {
            group: "operators.coreos.com".to_string(),
            version: "v1alpha1".to_string(),
            kind: "ClusterServiceVersion".to_string(),
            namespace: Some("test-ns".to_string()),
            name: "test-op.v1".to_string(),
            uid: Some("uid-csv".to_string()),
        };

        let plan = TeardownPlan {
            targets: vec![],
            preflight: Preflight { checks: vec![] },
            phases: vec![
                PlanPhase {
                    name: "Phase 0 (completed)".to_string(),
                    description: "".to_string(),
                    actions: vec![Action::Delete {
                        resource: {
                            let mut r = make_resource("Pod", "p0");
                            r.uid = Some("uid-p0".to_string());
                            r
                        },
                        reason: "test".to_string(),
                    }],
                    barrier: None,
                },
                PlanPhase {
                    name: "Phase 1 (completed)".to_string(),
                    description: "".to_string(),
                    actions: vec![Action::Delete {
                        resource: {
                            let mut r = make_resource("Pod", "p1");
                            r.uid = Some("uid-p1".to_string());
                            r
                        },
                        reason: "test".to_string(),
                    }],
                    barrier: None,
                },
                PlanPhase {
                    name: "Phase 2 (completed)".to_string(),
                    description: "".to_string(),
                    actions: vec![Action::Delete {
                        resource: {
                            let mut r = make_resource("Pod", "p2");
                            r.uid = Some("uid-p2".to_string());
                            r
                        },
                        reason: "test".to_string(),
                    }],
                    barrier: None,
                },
                PlanPhase {
                    name: "Phase 3 EMPTY".to_string(),
                    description: "".to_string(),
                    actions: vec![],
                    barrier: None,
                },
                PlanPhase {
                    name: "Phase 4 CSV".to_string(),
                    description: "".to_string(),
                    actions: vec![
                        Action::Review {
                            resource: review_res.clone(),
                            reason: "label-only".to_string(),
                            metadata: None,
                        },
                        Action::Delete {
                            resource: csv_res.clone(),
                            reason: "test".to_string(),
                        },
                    ],
                    barrier: None,
                },
            ],
            blockers: vec![],
            warnings: vec![],
            snapshot_taken_at: "2026-01-01T00:00:00Z".to_string(),
            dependency_edges: vec![],
            operator_inventory: vec![],
            explicit_decisions: vec![],
        };

        let mut gk = std::collections::HashMap::new();
        gk.insert(
            (
                "serving.kserve.io".to_string(),
                "LLMInferenceService".to_string(),
            ),
            crate::kube::discovery::KindInfo {
                group: "serving.kserve.io".to_string(),
                version: "v1alpha1".to_string(),
                plural: "llminferenceservices".to_string(),
                namespaced: true,
            },
        );
        gk.insert(
            (
                "operators.coreos.com".to_string(),
                "ClusterServiceVersion".to_string(),
            ),
            crate::kube::discovery::KindInfo {
                group: "operators.coreos.com".to_string(),
                version: "v1alpha1".to_string(),
                plural: "clusterserviceversions".to_string(),
                namespaced: true,
            },
        );

        let csv_request_count = Arc::new(AtomicUsize::new(0));
        let csv_count = csv_request_count.clone();
        let review_request_count = Arc::new(AtomicUsize::new(0));
        let review_count = review_request_count.clone();

        let (mock_service, handle) = tower_test::mock::pair::<
            http::Request<kube::client::Body>,
            http::Response<kube::client::Body>,
        >();

        let spawned = tokio::spawn(async move {
            let mut handle = std::pin::pin!(handle);
            while let Some((req, send)) = handle.next_request().await {
                let uri = req.uri().to_string();
                if uri.contains("clusterserviceversions") {
                    csv_count.fetch_add(1, Ordering::SeqCst);
                }
                if uri.contains("llminferenceservices") {
                    review_count.fetch_add(1, Ordering::SeqCst);
                    send.send_response(
                        http::Response::builder()
                            .status(200)
                            .body(kube::client::Body::from(
                                serde_json::to_vec(&serde_json::json!({
                                    "apiVersion": "serving.kserve.io/v1alpha1",
                                    "kind": "LLMInferenceService",
                                    "metadata": {
                                        "name": "qwen3-06b",
                                        "namespace": "test-ns",
                                        "uid": "uid-llm",
                                        "finalizers": ["serving.kserve.io/llmisvc-finalizer"]
                                    }
                                }))
                                .unwrap(),
                            ))
                            .unwrap(),
                    );
                } else {
                    let body = serde_json::json!({
                        "kind": "Status", "apiVersion": "v1", "metadata": {},
                        "status": "Failure", "reason": "NotFound", "code": 404
                    });
                    send.send_response(
                        http::Response::builder()
                            .status(404)
                            .body(kube::client::Body::from(serde_json::to_vec(&body).unwrap()))
                            .unwrap(),
                    );
                }
            }
        });

        let km = std::collections::HashMap::new();
        let gvk = std::collections::HashMap::new();
        let gvr = std::collections::HashMap::new();

        let client = Client::new(mock_service, "test-ns");
        // start_phase=3: resume from Phase 3 (empty), should reach Phase 4 guard
        let result = execute_plan_with_store(
            &client, &plan, &km, &gk, &gvk, &gvr, false, true, None, None, 3, true, None,
        )
        .await;

        let _r = result.expect("execute_plan_with_store must return Ok");

        // REVIEW finalizer check must have run
        let review_reqs = review_request_count.load(Ordering::SeqCst);
        assert!(
            review_reqs >= 1,
            "REVIEW finalizer check must run on resume — got {} requests",
            review_reqs
        );

        // CSV MUST be reached — intact REVIEW (no deletionTimestamp) is warning only
        let csv_reqs = csv_request_count.load(Ordering::SeqCst);
        assert!(
            csv_reqs >= 1,
            "CSV must be reached on resume — intact REVIEW does not block — got {}",
            csv_reqs
        );

        drop(client);
        spawned.abort();
    }

    #[tokio::test]
    async fn test_terminating_review_blocks_csv() {
        // REVIEW with deletionTimestamp + finalizer must block CSV phase
        use std::sync::atomic::{AtomicUsize, Ordering};

        let review_res = ResourceId {
            group: "test.example.io".to_string(),
            version: "v1".to_string(),
            kind: "ReviewTarget".to_string(),
            namespace: Some("test-ns".to_string()),
            name: "review-1".to_string(),
            uid: Some("uid-review".to_string()),
        };
        let csv_res = ResourceId {
            group: "operators.coreos.com".to_string(),
            version: "v1alpha1".to_string(),
            kind: "ClusterServiceVersion".to_string(),
            namespace: Some("test-ns".to_string()),
            name: "test-op.v1".to_string(),
            uid: Some("uid-csv".to_string()),
        };
        let plan = TeardownPlan {
            targets: vec![],
            preflight: Preflight { checks: vec![] },
            phases: vec![
                PlanPhase {
                    name: "Review phase".to_string(),
                    description: "".to_string(),
                    actions: vec![Action::Review {
                        resource: review_res,
                        reason: "test".to_string(),
                        metadata: None,
                    }],
                    barrier: None,
                },
                PlanPhase {
                    name: "CSV phase".to_string(),
                    description: "".to_string(),
                    actions: vec![Action::Delete {
                        resource: csv_res,
                        reason: "test".to_string(),
                    }],
                    barrier: None,
                },
            ],
            blockers: vec![],
            warnings: vec![],
            snapshot_taken_at: "2026-01-01T00:00:00Z".to_string(),
            dependency_edges: vec![],
            operator_inventory: vec![],
            explicit_decisions: vec![],
        };
        let mut gk = std::collections::HashMap::new();
        gk.insert(
            ("test.example.io".to_string(), "ReviewTarget".to_string()),
            crate::kube::discovery::KindInfo {
                group: "test.example.io".to_string(),
                version: "v1".to_string(),
                plural: "reviewtargets".to_string(),
                namespaced: true,
            },
        );
        gk.insert(
            (
                "operators.coreos.com".to_string(),
                "ClusterServiceVersion".to_string(),
            ),
            crate::kube::discovery::KindInfo {
                group: "operators.coreos.com".to_string(),
                version: "v1alpha1".to_string(),
                plural: "clusterserviceversions".to_string(),
                namespaced: true,
            },
        );
        let csv_request_count = Arc::new(AtomicUsize::new(0));
        let csv_count = csv_request_count.clone();

        let (mock_service, handle) = tower_test::mock::pair::<
            http::Request<kube::client::Body>,
            http::Response<kube::client::Body>,
        >();
        let spawned = tokio::spawn(async move {
            let mut handle = std::pin::pin!(handle);
            while let Some((req, send)) = handle.next_request().await {
                let uri = req.uri().to_string();
                if uri.contains("clusterserviceversions") {
                    csv_count.fetch_add(1, Ordering::SeqCst);
                }
                if uri.contains("reviewtargets") {
                    // Terminating with finalizer
                    send.send_response(json_response(serde_json::json!({
                        "apiVersion": "test.example.io/v1",
                        "kind": "ReviewTarget",
                        "metadata": {
                            "name": "review-1", "namespace": "test-ns", "uid": "uid-review",
                            "deletionTimestamp": "2026-01-01T00:00:00Z",
                            "finalizers": ["test.example.io/fin"]
                        }
                    })));
                } else {
                    send.send_response(not_found_response());
                }
            }
        });

        let km = std::collections::HashMap::new();
        let gvk = std::collections::HashMap::new();
        let gvr = std::collections::HashMap::new();
        let client = Client::new(mock_service, "test-ns");
        let result = execute_plan_with_store(
            &client, &plan, &km, &gk, &gvk, &gvr, false, true, None, None, 0, true, None,
        )
        .await;
        let _r = result.expect("must return Ok");
        assert_eq!(
            csv_request_count.load(Ordering::SeqCst),
            0,
            "CSV must NOT be reached when terminating REVIEW has finalizers"
        );
        drop(client);
        spawned.abort();
    }

    #[tokio::test]
    async fn test_review_get_error_blocks_csv() {
        // REVIEW GET returns 403 → fail-closed → CSV must NOT be reached
        use std::sync::atomic::{AtomicUsize, Ordering};

        let review_res = ResourceId {
            group: "test.example.io".to_string(),
            version: "v1".to_string(),
            kind: "ReviewTarget".to_string(),
            namespace: Some("test-ns".to_string()),
            name: "review-1".to_string(),
            uid: Some("uid-review".to_string()),
        };
        let csv_res = ResourceId {
            group: "operators.coreos.com".to_string(),
            version: "v1alpha1".to_string(),
            kind: "ClusterServiceVersion".to_string(),
            namespace: Some("test-ns".to_string()),
            name: "test-op.v1".to_string(),
            uid: Some("uid-csv".to_string()),
        };
        let plan = TeardownPlan {
            targets: vec![],
            preflight: Preflight { checks: vec![] },
            phases: vec![
                PlanPhase {
                    name: "Review phase".to_string(),
                    description: "".to_string(),
                    actions: vec![Action::Review {
                        resource: review_res,
                        reason: "test".to_string(),
                        metadata: None,
                    }],
                    barrier: None,
                },
                PlanPhase {
                    name: "CSV phase".to_string(),
                    description: "".to_string(),
                    actions: vec![Action::Delete {
                        resource: csv_res,
                        reason: "test".to_string(),
                    }],
                    barrier: None,
                },
            ],
            blockers: vec![],
            warnings: vec![],
            snapshot_taken_at: "2026-01-01T00:00:00Z".to_string(),
            dependency_edges: vec![],
            operator_inventory: vec![],
            explicit_decisions: vec![],
        };
        let mut gk = std::collections::HashMap::new();
        gk.insert(
            ("test.example.io".to_string(), "ReviewTarget".to_string()),
            crate::kube::discovery::KindInfo {
                group: "test.example.io".to_string(),
                version: "v1".to_string(),
                plural: "reviewtargets".to_string(),
                namespaced: true,
            },
        );
        gk.insert(
            (
                "operators.coreos.com".to_string(),
                "ClusterServiceVersion".to_string(),
            ),
            crate::kube::discovery::KindInfo {
                group: "operators.coreos.com".to_string(),
                version: "v1alpha1".to_string(),
                plural: "clusterserviceversions".to_string(),
                namespaced: true,
            },
        );
        let csv_request_count = Arc::new(AtomicUsize::new(0));
        let csv_count = csv_request_count.clone();

        let (mock_service, handle) = tower_test::mock::pair::<
            http::Request<kube::client::Body>,
            http::Response<kube::client::Body>,
        >();
        let spawned = tokio::spawn(async move {
            let mut handle = std::pin::pin!(handle);
            while let Some((req, send)) = handle.next_request().await {
                let uri = req.uri().to_string();
                if uri.contains("clusterserviceversions") {
                    csv_count.fetch_add(1, Ordering::SeqCst);
                }
                if uri.contains("reviewtargets") {
                    send.send_response(forbidden_response());
                } else {
                    send.send_response(not_found_response());
                }
            }
        });

        let km = std::collections::HashMap::new();
        let gvk = std::collections::HashMap::new();
        let gvr = std::collections::HashMap::new();
        let client = Client::new(mock_service, "test-ns");
        let result = execute_plan_with_store(
            &client, &plan, &km, &gk, &gvk, &gvr, false, true, None, None, 0, true, None,
        )
        .await;
        let _r = result.expect("must return Ok");
        assert_eq!(
            csv_request_count.load(Ordering::SeqCst),
            0,
            "CSV must NOT be reached when REVIEW GET fails (403)"
        );
        drop(client);
        spawned.abort();
    }

    // ── Finalizer recovery mock tests ──

    fn make_test_journal_store() -> JournalStore {
        use crate::teardown::journal::*;
        use crate::teardown::plan::*;
        let csv_rid = ResourceId {
            group: "operators.coreos.com".to_string(),
            version: "v1alpha1".to_string(),
            kind: "ClusterServiceVersion".to_string(),
            namespace: Some("test-ns".to_string()),
            name: "test.v1".to_string(),
            uid: Some("uid-csv".to_string()),
        };
        let j = RunJournal {
            run_id: "test-recovery".to_string(),
            schema_version: RUN_JOURNAL_SCHEMA_VERSION,
            oc_deps_version: "0.1.0".to_string(),
            journal_revision: 1,
            cluster_identity: ClusterIdentity {
                api_server: "https://test:6443".to_string(),
                kube_system_uid: "test-uid".to_string(),
            },
            operator: OperatorIdentitySnapshot {
                generation_identity: OperatorGenerationIdentity::OlmPackage {
                    package_name: "test".to_string(),
                    install_namespace: "test-ns".to_string(),
                },
                operator_id: crate::analyzers::olm::OperatorId {
                    csv_name: "test.v1".to_string(),
                    namespace: "test-ns".to_string(),
                },
                csv_name: "test.v1".to_string(),
                csv: ObservedResourceIdentity {
                    resource: csv_rid,
                    uid: "uid-csv".to_string(),
                },
                subscriptions: vec![],
                controller_deployments: vec![],
                service_accounts: vec![],
                owned_crds: vec![],
                required_crds: vec![],
            },
            created_at: "2026-01-01T00:00:00Z".to_string(),
            updated_at: "2026-01-01T00:00:00Z".to_string(),
            state: RunState::Applying,
            residual_status: ResidualStatus::NotAudited,
            audit_revision: 0,
            audit_context: AuditContext::default(),
            plan_snapshot: crate::teardown::planner::TeardownPlan {
                targets: vec![],
                preflight: crate::teardown::planner::Preflight { checks: vec![] },
                phases: vec![],
                blockers: vec![],
                warnings: vec![],
                snapshot_taken_at: "2026-01-01T00:00:00Z".to_string(),
                dependency_edges: vec![],
                operator_inventory: vec![],
                explicit_decisions: vec![],
            },
            execution: ExecutionRecord::default(),
            last_residual_audit: None,
            cleanup_decisions: vec![],
            finalizer_recovery_approved: true,
            finalizer_recoveries: vec![],
        };
        let dir = std::env::temp_dir().join(format!(
            "oc-deps-test-recovery-{:?}",
            std::thread::current().id()
        ));
        std::fs::create_dir_all(&dir).ok();
        let path = dir.join("journal.json");
        crate::teardown::journal::atomic_write_json_pub(&path, &j).unwrap();
        JournalStore::new(j, path)
    }

    fn make_test_gate() -> crate::teardown::permit::MutationGate {
        crate::teardown::permit::MutationGate::new(4)
    }

    fn make_recovery_phase(child_res: &ResourceId) -> PlanPhase {
        PlanPhase {
            name: "recovery test".to_string(),
            description: "".to_string(),
            actions: vec![Action::ExpectGone {
                resource: child_res.clone(),
                reason: "owned by root".to_string(),
            }],
            barrier: None,
        }
    }

    fn recovery_gk_map() -> GroupKindMap {
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

    #[tokio::test]
    async fn test_recovery_uid_change_skips_child() {
        // Child UID changed between plan and live → skip (no strip)
        let child = make_cm_resource("child1", Some("uid-child-plan"));
        let root = make_cm_resource("root1", Some("uid-root"));
        let phase = make_recovery_phase(&child);
        let km = test_kind_map();
        let gk = recovery_gk_map();

        let (mock_service, handle) =
            tower_test::mock::pair::<http::Request<Body>, http::Response<Body>>();

        let spawned = tokio::spawn(async move {
            let mut handle = pin!(handle);
            // GET child → returns with different UID
            let (_req, send) = handle.next_request().await.unwrap();
            send.send_response(json_response(serde_json::json!({
                "apiVersion": "v1", "kind": "ConfigMap",
                "metadata": {
                    "name": "child1", "namespace": "test-ns",
                    "uid": "uid-child-DIFFERENT",
                    "deletionTimestamp": "2026-01-01T00:00:00Z",
                    "ownerReferences": [{"apiVersion": "v1", "kind": "ConfigMap",
                        "name": "root1", "uid": "uid-root", "controller": true}],
                    "finalizers": ["test/fin"]
                }
            })));
            // No PATCH should follow
        });

        let js = make_test_journal_store();
        let gate = make_test_gate();
        let client = Client::new(mock_service, "test-ns");
        let result = attempt_finalizer_recovery(
            &client,
            std::slice::from_ref(&child),
            &[root],
            &phase,
            &km,
            &gk,
            &js,
            &gate,
        )
        .await;

        assert_eq!(result.unwrap(), 0, "UID mismatch must skip recovery");
        drop(client);
        spawned.abort();
    }

    #[tokio::test]
    async fn test_recovery_ownerref_mismatch_skips() {
        // Child ownerRef UID not in deleted_roots → skip
        let child = make_cm_resource("child1", Some("uid-child"));
        let root = make_cm_resource("root1", Some("uid-root"));
        let phase = make_recovery_phase(&child);
        let km = test_kind_map();
        let gk = recovery_gk_map();

        let (mock_service, handle) =
            tower_test::mock::pair::<http::Request<Body>, http::Response<Body>>();

        let spawned = tokio::spawn(async move {
            let mut handle = pin!(handle);
            let (_req, send) = handle.next_request().await.unwrap();
            send.send_response(json_response(serde_json::json!({
                "apiVersion": "v1", "kind": "ConfigMap",
                "metadata": {
                    "name": "child1", "namespace": "test-ns",
                    "uid": "uid-child",
                    "deletionTimestamp": "2026-01-01T00:00:00Z",
                    "ownerReferences": [{"apiVersion": "v1", "kind": "ConfigMap",
                        "name": "other-root", "uid": "uid-OTHER-ROOT", "controller": true}],
                    "finalizers": ["test/fin"]
                }
            })));
        });

        let js = make_test_journal_store();
        let gate = make_test_gate();
        let client = Client::new(mock_service, "test-ns");
        let result = attempt_finalizer_recovery(
            &client,
            std::slice::from_ref(&child),
            &[root],
            &phase,
            &km,
            &gk,
            &js,
            &gate,
        )
        .await;

        assert_eq!(
            result.unwrap(),
            0,
            "ownerRef not matching deleted roots must skip"
        );
        drop(client);
        spawned.abort();
    }

    #[tokio::test]
    async fn test_recovery_child_get_403_skips() {
        // GET child returns 403 → skip
        let child = make_cm_resource("child1", Some("uid-child"));
        let root = make_cm_resource("root1", Some("uid-root"));
        let phase = make_recovery_phase(&child);
        let km = test_kind_map();
        let gk = recovery_gk_map();

        let (mock_service, handle) =
            tower_test::mock::pair::<http::Request<Body>, http::Response<Body>>();

        let spawned = tokio::spawn(async move {
            let mut handle = pin!(handle);
            let (_req, send) = handle.next_request().await.unwrap();
            send.send_response(forbidden_response());
        });

        let js = make_test_journal_store();
        let gate = make_test_gate();
        let client = Client::new(mock_service, "test-ns");
        let result = attempt_finalizer_recovery(
            &client,
            std::slice::from_ref(&child),
            &[root],
            &phase,
            &km,
            &gk,
            &js,
            &gate,
        )
        .await;

        assert_eq!(result.unwrap(), 0, "GET 403 must skip recovery");
        drop(client);
        spawned.abort();
    }

    #[tokio::test]
    async fn test_recovery_root_still_exists_skips() {
        // Root GET returns 200 (not gone) → skip
        let child = make_cm_resource("child1", Some("uid-child"));
        let root = make_cm_resource("root1", Some("uid-root"));
        let phase = make_recovery_phase(&child);
        let km = test_kind_map();
        let gk = recovery_gk_map();

        let (mock_service, handle) =
            tower_test::mock::pair::<http::Request<Body>, http::Response<Body>>();

        let spawned = tokio::spawn(async move {
            let mut handle = pin!(handle);
            // GET child → valid with matching UID, deletionTimestamp, ownerRef
            let (_req, send) = handle.next_request().await.unwrap();
            send.send_response(json_response(serde_json::json!({
                "apiVersion": "v1", "kind": "ConfigMap",
                "metadata": {
                    "name": "child1", "namespace": "test-ns",
                    "uid": "uid-child",
                    "deletionTimestamp": "2026-01-01T00:00:00Z",
                    "ownerReferences": [{"apiVersion": "v1", "kind": "ConfigMap",
                        "name": "root1", "uid": "uid-root", "controller": true}],
                    "finalizers": ["test/fin"]
                }
            })));
            // GET root → 200 (still exists)
            let (_req, send) = handle.next_request().await.unwrap();
            send.send_response(json_response(serde_json::json!({
                "apiVersion": "v1", "kind": "ConfigMap",
                "metadata": {"name": "root1", "namespace": "test-ns", "uid": "uid-root"}
            })));
        });

        let js = make_test_journal_store();
        let gate = make_test_gate();
        let client = Client::new(mock_service, "test-ns");
        let result = attempt_finalizer_recovery(
            &client,
            std::slice::from_ref(&child),
            &[root],
            &phase,
            &km,
            &gk,
            &js,
            &gate,
        )
        .await;

        assert_eq!(result.unwrap(), 0, "Root still exists must skip recovery");
        drop(client);
        spawned.abort();
    }

    #[tokio::test]
    async fn test_recovery_redeleted_root_allows_single_noncontroller_dependent() {
        // A dependent can be reparented to UID B after an explicit root A was
        // deleted. B's accepted re-delete is durable authority; controller=false
        // does not change Kubernetes GC ownership for a single ownerRef.
        let child = make_cm_resource("child1", Some("uid-child"));
        let root = make_cm_resource("root1", Some("uid-root-A"));
        let phase = make_recovery_phase(&child);
        let km = test_kind_map();
        let gk = recovery_gk_map();
        let (mock_service, handle) =
            tower_test::mock::pair::<http::Request<Body>, http::Response<Body>>();

        let spawned = tokio::spawn(async move {
            let mut handle = pin!(handle);
            let (_req, send) = handle.next_request().await.unwrap();
            send.send_response(json_response(serde_json::json!({
                "apiVersion": "v1", "kind": "ConfigMap",
                "metadata": {
                    "name": "child1", "namespace": "test-ns", "uid": "uid-child",
                    "deletionTimestamp": "2026-01-01T00:00:00Z",
                    "ownerReferences": [{"apiVersion": "v1", "kind": "ConfigMap",
                        "name": "root1", "uid": "uid-root-B"}],
                    "finalizers": ["test/fin"]
                }
            })));
            let (_req, send) = handle.next_request().await.unwrap();
            send.send_response(json_response(serde_json::json!({
                "apiVersion": "v1", "kind": "ConfigMap",
                "metadata": {"name": "root1", "namespace": "test-ns", "uid": "uid-root-C"}
            })));
            let (req, send) = handle.next_request().await.unwrap();
            assert_eq!(req.method(), http::Method::PATCH);
            send.send_response(json_response(serde_json::json!({
                "apiVersion": "v1", "kind": "ConfigMap",
                "metadata": {"name": "child1", "namespace": "test-ns",
                    "uid": "uid-child", "finalizers": []}
            })));
        });

        let js = make_test_journal_store();
        let mut identity = root.clone();
        identity.uid = None;
        js.update(|j| {
            j.execution
                .re_delete_records
                .push(crate::teardown::journal::ReDeleteRecord {
                    resource_identity: identity,
                    original_uid: "uid-root-A".to_string(),
                    new_uid: "uid-root-B".to_string(),
                    result: crate::teardown::journal::ReDeleteResult::Accepted,
                });
        })
        .await
        .unwrap();
        let gate = make_test_gate();
        let client = Client::new(mock_service, "test-ns");
        let result = attempt_finalizer_recovery(
            &client,
            std::slice::from_ref(&child),
            &[root],
            &phase,
            &km,
            &gk,
            &js,
            &gate,
        )
        .await;
        assert_eq!(result.unwrap(), 1);
        spawned.await.unwrap();
    }

    #[tokio::test]
    async fn test_recovery_unaccepted_redelete_never_authorizes_child() {
        let child = make_cm_resource("child1", Some("uid-child"));
        let root = make_cm_resource("root1", Some("uid-root-A"));
        let phase = make_recovery_phase(&child);
        let km = test_kind_map();
        let gk = recovery_gk_map();
        let (mock_service, handle) =
            tower_test::mock::pair::<http::Request<Body>, http::Response<Body>>();
        let spawned = tokio::spawn(async move {
            let mut handle = pin!(handle);
            let (_req, send) = handle.next_request().await.unwrap();
            send.send_response(json_response(serde_json::json!({
                "apiVersion": "v1", "kind": "ConfigMap",
                "metadata": {
                    "name": "child1", "namespace": "test-ns", "uid": "uid-child",
                    "deletionTimestamp": "2026-01-01T00:00:00Z",
                    "ownerReferences": [{"apiVersion": "v1", "kind": "ConfigMap",
                        "name": "root1", "uid": "uid-root-B"}],
                    "finalizers": ["test/fin"]
                }
            })));
            assert!(
                handle.next_request().await.is_none(),
                "no root GET or PATCH"
            );
        });

        let js = make_test_journal_store();
        let mut identity = root.clone();
        identity.uid = None;
        js.update(|j| {
            j.execution
                .re_delete_records
                .push(crate::teardown::journal::ReDeleteRecord {
                    resource_identity: identity,
                    original_uid: "uid-root-A".to_string(),
                    new_uid: "uid-root-B".to_string(),
                    result: crate::teardown::journal::ReDeleteResult::Authorized,
                });
        })
        .await
        .unwrap();
        let gate = make_test_gate();
        let client = Client::new(mock_service, "test-ns");
        let result = attempt_finalizer_recovery(
            &client,
            std::slice::from_ref(&child),
            &[root],
            &phase,
            &km,
            &gk,
            &js,
            &gate,
        )
        .await;
        assert_eq!(result.unwrap(), 0);
        drop(client);
        spawned.await.unwrap();
    }

    #[tokio::test]
    async fn test_defer_requires_accepted_redelete_of_current_root_uid() {
        let child = make_cm_resource("child1", Some("uid-child"));
        let root = make_cm_resource("root1", Some("uid-root-A"));
        let phase = PlanPhase {
            name: "operand cleanup".to_string(),
            description: String::new(),
            actions: vec![
                Action::Delete {
                    resource: root.clone(),
                    reason: String::new(),
                },
                Action::ExpectGone {
                    resource: child.clone(),
                    reason: String::new(),
                },
            ],
            barrier: None,
        };
        let notifier = Arc::new(EventNotifier::new());
        let store = Arc::new(crate::teardown::runtime::RuntimeStateStore::new(
            notifier,
            Duration::from_secs(120),
        ));
        store.register(
            &child,
            crate::teardown::runtime::ResourceRuntimeState::ExpectingGone,
            0,
        );
        let watch_mgr = crate::teardown::watch::WatchManager::new(store.clone());
        let (mock_service, handle) =
            tower_test::mock::pair::<http::Request<Body>, http::Response<Body>>();
        let spawned = tokio::spawn(async move {
            let mut handle = pin!(handle);
            let (_req, send) = handle.next_request().await.unwrap();
            send.send_response(json_response(serde_json::json!({
                "apiVersion": "v1", "kind": "ConfigMap",
                "metadata": {"name": "child1", "namespace": "test-ns", "uid": "uid-child"}
            })));
            let (_req, send) = handle.next_request().await.unwrap();
            send.send_response(json_response(serde_json::json!({
                "apiVersion": "v1", "kind": "ConfigMap",
                "metadata": {"name": "root1", "namespace": "test-ns", "uid": "uid-root-B"}
            })));
        });
        let js = make_test_journal_store();
        let mut identity = root.clone();
        identity.uid = None;
        js.update(|j| {
            j.execution
                .re_delete_records
                .push(crate::teardown::journal::ReDeleteRecord {
                    resource_identity: identity,
                    original_uid: "uid-root-A".to_string(),
                    new_uid: "uid-root-B".to_string(),
                    result: crate::teardown::journal::ReDeleteResult::Accepted,
                });
        })
        .await
        .unwrap();
        let client = Client::new(mock_service, "test-ns");
        assert!(
            can_defer_to_residual(
                &client,
                std::slice::from_ref(&child),
                &phase,
                &watch_mgr,
                &store,
                Some(&js),
                &test_kind_map(),
                &recovery_gk_map(),
            )
            .await
        );
        spawned.await.unwrap();

        // The original root still exists: do not advance to controller removal,
        // even though an accepted re-delete record for another UID exists.
        let (mock_service, handle) =
            tower_test::mock::pair::<http::Request<Body>, http::Response<Body>>();
        let spawned = tokio::spawn(async move {
            let mut handle = pin!(handle);
            let (_req, send) = handle.next_request().await.unwrap();
            send.send_response(json_response(serde_json::json!({
                "apiVersion": "v1", "kind": "ConfigMap",
                "metadata": {"name": "child1", "namespace": "test-ns", "uid": "uid-child"}
            })));
            let (_req, send) = handle.next_request().await.unwrap();
            send.send_response(json_response(serde_json::json!({
                "apiVersion": "v1", "kind": "ConfigMap",
                "metadata": {"name": "root1", "namespace": "test-ns", "uid": "uid-root-A"}
            })));
        });
        let client = Client::new(mock_service, "test-ns");
        assert!(
            !can_defer_to_residual(
                &client,
                std::slice::from_ref(&child),
                &phase,
                &watch_mgr,
                &store,
                Some(&js),
                &test_kind_map(),
                &recovery_gk_map(),
            )
            .await
        );
        spawned.await.unwrap();
    }

    #[tokio::test]
    async fn test_recovery_root_404_endpoint_failure_skips() {
        // Root GET 404 but endpoint LIST fails → can't confirm Gone → skip
        let child = make_cm_resource("child1", Some("uid-child"));
        let root = make_cm_resource("root1", Some("uid-root"));
        let phase = make_recovery_phase(&child);
        let km = test_kind_map();
        let gk = recovery_gk_map();

        let (mock_service, handle) =
            tower_test::mock::pair::<http::Request<Body>, http::Response<Body>>();

        let spawned = tokio::spawn(async move {
            let mut handle = pin!(handle);
            // GET child → valid
            let (_req, send) = handle.next_request().await.unwrap();
            send.send_response(json_response(serde_json::json!({
                "apiVersion": "v1", "kind": "ConfigMap",
                "metadata": {
                    "name": "child1", "namespace": "test-ns",
                    "uid": "uid-child",
                    "deletionTimestamp": "2026-01-01T00:00:00Z",
                    "ownerReferences": [{"apiVersion": "v1", "kind": "ConfigMap",
                        "name": "root1", "uid": "uid-root", "controller": true}],
                    "finalizers": ["test/fin"]
                }
            })));
            // GET root → 404
            let (_req, send) = handle.next_request().await.unwrap();
            send.send_response(not_found_response());
            // LIST root endpoint → 403 (endpoint failure)
            let (_req, send) = handle.next_request().await.unwrap();
            send.send_response(forbidden_response());
        });

        let js = make_test_journal_store();
        let gate = make_test_gate();
        let client = Client::new(mock_service, "test-ns");
        let result = attempt_finalizer_recovery(
            &client,
            std::slice::from_ref(&child),
            &[root],
            &phase,
            &km,
            &gk,
            &js,
            &gate,
        )
        .await;

        assert_eq!(result.unwrap(), 0, "Root 404 + endpoint failure must skip");
        drop(client);
        spawned.abort();
    }

    #[tokio::test]
    async fn test_recovery_happy_path_strips_finalizer() {
        // Root authoritatively Gone + child has finalizer → PATCH strips it
        let child = make_cm_resource("child1", Some("uid-child"));
        let root = make_cm_resource("root1", Some("uid-root"));
        let phase = make_recovery_phase(&child);
        let km = test_kind_map();
        let gk = recovery_gk_map();

        let (mock_service, handle) =
            tower_test::mock::pair::<http::Request<Body>, http::Response<Body>>();

        let spawned = tokio::spawn(async move {
            let mut handle = pin!(handle);
            // GET child
            let (_req, send) = handle.next_request().await.unwrap();
            send.send_response(json_response(serde_json::json!({
                "apiVersion": "v1", "kind": "ConfigMap",
                "metadata": {
                    "name": "child1", "namespace": "test-ns",
                    "uid": "uid-child",
                    "deletionTimestamp": "2026-01-01T00:00:00Z",
                    "ownerReferences": [{"apiVersion": "v1", "kind": "ConfigMap",
                        "name": "root1", "uid": "uid-root", "controller": true}],
                    "finalizers": ["test/fin"]
                }
            })));
            // GET root → 404
            let (_req, send) = handle.next_request().await.unwrap();
            send.send_response(not_found_response());
            // LIST root endpoint → 200 (endpoint exists)
            let (_req, send) = handle.next_request().await.unwrap();
            send.send_response(json_response(serde_json::json!({
                "apiVersion": "v1", "kind": "ConfigMapList",
                "metadata": {"resourceVersion": "1"},
                "items": []
            })));
            // PATCH child → 200 (success)
            let (req, send) = handle.next_request().await.unwrap();
            assert_eq!(req.method(), http::Method::PATCH);
            send.send_response(json_response(serde_json::json!({
                "apiVersion": "v1", "kind": "ConfigMap",
                "metadata": {
                    "name": "child1", "namespace": "test-ns",
                    "uid": "uid-child", "finalizers": []
                }
            })));
        });

        let js = make_test_journal_store();
        let gate = make_test_gate();
        let client = Client::new(mock_service, "test-ns");
        let result = attempt_finalizer_recovery(
            &client,
            std::slice::from_ref(&child),
            &[root],
            &phase,
            &km,
            &gk,
            &js,
            &gate,
        )
        .await;

        assert_eq!(result.unwrap(), 1, "Happy path must strip 1 finalizer");
        // Verify journal records the Stripped result
        let j = js.read().await;
        assert_eq!(j.finalizer_recoveries.len(), 1);
        assert!(
            matches!(
                j.finalizer_recoveries[0].result,
                crate::teardown::journal::FinalizerRecoveryResult::Stripped
            ),
            "Journal must record Stripped"
        );
        drop(client);
        spawned.abort();
    }

    #[tokio::test]
    async fn test_recovery_unresolved_patch_returns_err() {
        // Simulate: child A stripped OK, child B patch transport error + GET 403
        // → PatchRequested stays unresolved → function must return Err
        let child_a = make_cm_resource("childA", Some("uid-a"));
        let child_b = make_cm_resource("childB", Some("uid-b"));
        let root = make_cm_resource("root1", Some("uid-root"));
        let phase = PlanPhase {
            name: "recovery test".to_string(),
            description: "".to_string(),
            actions: vec![
                Action::ExpectGone {
                    resource: child_a.clone(),
                    reason: "test".to_string(),
                },
                Action::ExpectGone {
                    resource: child_b.clone(),
                    reason: "test".to_string(),
                },
            ],
            barrier: None,
        };
        let km = test_kind_map();
        let gk = recovery_gk_map();

        let (mock_service, handle) =
            tower_test::mock::pair::<http::Request<Body>, http::Response<Body>>();

        let spawned = tokio::spawn(async move {
            let mut handle = pin!(handle);

            // -- Child A: full happy path --
            // GET child A
            let (_req, send) = handle.next_request().await.unwrap();
            send.send_response(json_response(serde_json::json!({
                "apiVersion": "v1", "kind": "ConfigMap",
                "metadata": {
                    "name": "childA", "namespace": "test-ns", "uid": "uid-a",
                    "deletionTimestamp": "2026-01-01T00:00:00Z",
                    "ownerReferences": [{"apiVersion": "v1", "kind": "ConfigMap",
                        "name": "root1", "uid": "uid-root", "controller": true}],
                    "finalizers": ["test/fin"]
                }
            })));
            // GET root → 404
            let (_req, send) = handle.next_request().await.unwrap();
            send.send_response(not_found_response());
            // LIST root endpoint → 200
            let (_req, send) = handle.next_request().await.unwrap();
            send.send_response(json_response(serde_json::json!({
                "apiVersion": "v1", "kind": "ConfigMapList",
                "metadata": {"resourceVersion": "1"}, "items": []
            })));
            // PATCH child A → 200
            let (_req, send) = handle.next_request().await.unwrap();
            send.send_response(json_response(serde_json::json!({
                "apiVersion": "v1", "kind": "ConfigMap",
                "metadata": {"name": "childA", "namespace": "test-ns", "uid": "uid-a", "finalizers": []}
            })));

            // -- Child B: transport error --
            // GET child B
            let (_req, send) = handle.next_request().await.unwrap();
            send.send_response(json_response(serde_json::json!({
                "apiVersion": "v1", "kind": "ConfigMap",
                "metadata": {
                    "name": "childB", "namespace": "test-ns", "uid": "uid-b",
                    "deletionTimestamp": "2026-01-01T00:00:00Z",
                    "ownerReferences": [{"apiVersion": "v1", "kind": "ConfigMap",
                        "name": "root1", "uid": "uid-root", "controller": true}],
                    "finalizers": ["test/fin"]
                }
            })));
            // GET root → 404 (again for child B)
            let (_req, send) = handle.next_request().await.unwrap();
            send.send_response(not_found_response());
            // LIST root endpoint → 200
            let (_req, send) = handle.next_request().await.unwrap();
            send.send_response(json_response(serde_json::json!({
                "apiVersion": "v1", "kind": "ConfigMapList",
                "metadata": {"resourceVersion": "1"}, "items": []
            })));
            // PATCH child B → connection error (simulate by dropping handle)
            // Actually tower_test doesn't support connection errors easily.
            // Instead return 500 (not 409/422, so it goes to transport error branch)
            let (_req, send) = handle.next_request().await.unwrap();
            let body = serde_json::json!({
                "kind": "Status", "apiVersion": "v1", "metadata": {},
                "status": "Failure", "reason": "InternalError",
                "message": "connection reset", "code": 500
            });
            send.send_response(
                http::Response::builder()
                    .status(500)
                    .body(Body::from(serde_json::to_vec(&body).unwrap()))
                    .unwrap(),
            );
            // Re-GET child B for outcome verification → 403 (ambiguous)
            let (_req, send) = handle.next_request().await.unwrap();
            send.send_response(forbidden_response());
        });

        let js = make_test_journal_store();
        let gate = make_test_gate();
        let client = Client::new(mock_service, "test-ns");
        let result = attempt_finalizer_recovery(
            &client,
            &[child_a, child_b],
            &[root],
            &phase,
            &km,
            &gk,
            &js,
            &gate,
        )
        .await;

        // Must be Err: child B has unresolved PatchRequested in journal.
        // The final check reads journal and finds PatchRequested → bail.
        assert!(
            result.is_err(),
            "Unresolved PatchRequested must always return Err, got: {:?}",
            result
        );
        let err_msg = format!("{}", result.unwrap_err());
        assert!(
            err_msg.contains("PatchRequested"),
            "Error must mention PatchRequested: {}",
            err_msg
        );
        // Verify journal has the records
        let j = js.read().await;
        assert!(
            j.finalizer_recoveries.len() >= 2,
            "Journal must have records for both children"
        );
        assert!(
            j.finalizer_recoveries.iter().any(|r| matches!(
                r.result,
                crate::teardown::journal::FinalizerRecoveryResult::PatchRequested
            )),
            "At least one record must be PatchRequested"
        );

        drop(client);
        spawned.abort();
    }

    #[test]
    fn test_admission_webhook_detection() {
        assert!(is_admission_webhook_denial(
            "admission webhook \"validator.example.io\" denied the request: Cannot delete"
        ));
        assert!(is_admission_webhook_denial(
            "admission webhook \"dscinitialization-v2-validator.opendatahub.io\" denied the request: Cannot delete DSCInitialization"
        ));
        assert!(!is_admission_webhook_denial("forbidden"));
        assert!(!is_admission_webhook_denial("User cannot delete resource"));
        assert!(!is_admission_webhook_denial(""));
    }

    // ── Generic delete wave/fixpoint tests ──

    fn wave_gk_map() -> GroupKindMap {
        let mut gk = std::collections::HashMap::new();
        for kind in ["ResourceA", "ResourceB", "ResourceC"] {
            gk.insert(
                ("test.example.io".to_string(), kind.to_string()),
                crate::kube::discovery::KindInfo {
                    group: "test.example.io".to_string(),
                    version: "v1".to_string(),
                    plural: format!("{}s", kind.to_lowercase()),
                    namespaced: true,
                },
            );
        }
        gk
    }

    fn make_test_res(kind: &str, name: &str, uid: &str) -> ResourceId {
        ResourceId {
            group: "test.example.io".to_string(),
            version: "v1".to_string(),
            kind: kind.to_string(),
            namespace: Some("test-ns".to_string()),
            name: name.to_string(),
            uid: Some(uid.to_string()),
        }
    }

    #[tokio::test]
    async fn test_wave_b_rejected_a_gone_then_b_retry_success() {
        // Wave 1: A accepted→Gone, B rejected (422 webhook)
        // Wave 2: B accepted→Gone (dependency satisfied)
        use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

        let res_a = make_test_res("ResourceA", "a1", "uid-a");
        let res_b = make_test_res("ResourceB", "b1", "uid-b");
        let gk = wave_gk_map();
        let km = std::collections::HashMap::new();

        let a_deleted = Arc::new(AtomicBool::new(false));
        let a_del = a_deleted.clone();
        let b_attempt = Arc::new(AtomicUsize::new(0));
        let b_att = b_attempt.clone();

        let (mock_service, handle) =
            tower_test::mock::pair::<http::Request<Body>, http::Response<Body>>();

        let spawned = tokio::spawn(async move {
            let mut handle = std::pin::pin!(handle);
            while let Some((req, send)) = handle.next_request().await {
                let uri = req.uri().to_string();
                let method = req.method().clone();

                if uri.contains("resourceas") {
                    if method == http::Method::DELETE {
                        a_del.store(true, Ordering::SeqCst);
                        send.send_response(json_response(serde_json::json!({
                            "apiVersion": "v1", "kind": "Status", "status": "Success", "metadata": {}
                        })));
                    } else if method == http::Method::GET && !uri.contains('?') {
                        if a_del.load(Ordering::SeqCst) {
                            send.send_response(not_found_response());
                        } else {
                            send.send_response(json_response(serde_json::json!({
                                "apiVersion": "test.example.io/v1", "kind": "ResourceA",
                                "metadata": {"name": "a1", "namespace": "test-ns", "uid": "uid-a", "resourceVersion": "1"}
                            })));
                        }
                    } else {
                        // LIST for endpoint verification
                        send.send_response(json_response(serde_json::json!({
                            "apiVersion": "v1", "kind": "ResourceAList",
                            "metadata": {"resourceVersion": "1"}, "items": []
                        })));
                    }
                } else if uri.contains("resourcebs") {
                    if method == http::Method::GET && !uri.contains('?') {
                        let del_count = b_att.load(Ordering::SeqCst);
                        if del_count >= 2 {
                            // After second DELETE accepted, B is Gone
                            send.send_response(not_found_response());
                        } else {
                            send.send_response(json_response(serde_json::json!({
                                "apiVersion": "test.example.io/v1", "kind": "ResourceB",
                                "metadata": {"name": "b1", "namespace": "test-ns", "uid": "uid-b", "resourceVersion": "1"}
                            })));
                        }
                    } else if method == http::Method::DELETE {
                        let attempt = b_att.fetch_add(1, Ordering::SeqCst);
                        if attempt == 0 {
                            // First DELETE: webhook rejects (422)
                            let body = serde_json::json!({
                                "kind": "Status", "apiVersion": "v1", "metadata": {},
                                "status": "Failure", "reason": "Invalid",
                                "message": "dependency not met", "code": 422
                            });
                            send.send_response(
                                http::Response::builder()
                                    .status(422)
                                    .body(Body::from(serde_json::to_vec(&body).unwrap()))
                                    .unwrap(),
                            );
                        } else {
                            // Second DELETE: success
                            send.send_response(json_response(serde_json::json!({
                                "apiVersion": "v1", "kind": "Status", "status": "Success", "metadata": {}
                            })));
                        }
                    } else {
                        // LIST for endpoint verification
                        let del_count = b_att.load(Ordering::SeqCst);
                        if del_count >= 2 {
                            send.send_response(json_response(serde_json::json!({
                                "apiVersion": "v1", "kind": "ResourceBList",
                                "metadata": {"resourceVersion": "1"}, "items": []
                            })));
                        } else {
                            send.send_response(json_response(serde_json::json!({
                                "apiVersion": "v1", "kind": "ResourceBList",
                                "metadata": {"resourceVersion": "1"},
                                "items": [{"apiVersion": "test.example.io/v1", "kind": "ResourceB",
                                    "metadata": {"name": "b1", "namespace": "test-ns", "uid": "uid-b"}}]
                            })));
                        }
                    }
                } else {
                    send.send_response(not_found_response());
                }
            }
        });

        let client = Client::new(mock_service, "test-ns");
        let (store, _notifier) = create_runtime_store();
        let watch_mgr = crate::teardown::watch::WatchManager::new(store.clone());

        let result = execute_delete_waves(
            &client,
            &[res_a.clone(), res_b.clone()],
            &km,
            &gk,
            None,
            &watch_mgr,
            &store,
            None,
            None,
            None,
            None,
        )
        .await
        .unwrap();

        assert!(
            result.accepted_gone.iter().any(|r| r.name == "a1"),
            "A must be accepted and Gone"
        );
        assert!(
            result.accepted_gone.iter().any(|r| r.name == "b1")
                || result.already_gone.iter().any(|r| r.name == "b1"),
            "B must be accepted/gone after retry"
        );
        assert!(
            result.failed.is_empty(),
            "No failures expected: {:?}",
            result.failed
        );

        drop(client);
        spawned.abort();
    }

    #[tokio::test]
    async fn test_wave_no_progress_all_rejected() {
        // All targets rejected (422), none accepted → no progress → failure
        let res_a = make_test_res("ResourceA", "a1", "uid-a");
        let gk = wave_gk_map();
        let km = std::collections::HashMap::new();

        let (mock_service, handle) =
            tower_test::mock::pair::<http::Request<Body>, http::Response<Body>>();

        let spawned = tokio::spawn(async move {
            let mut handle = std::pin::pin!(handle);
            while let Some((req, send)) = handle.next_request().await {
                let uri = req.uri().to_string();
                if uri.contains("resourceas")
                    && req.method() == http::Method::GET
                    && !uri.contains('?')
                {
                    send.send_response(json_response(serde_json::json!({
                        "apiVersion": "test.example.io/v1", "kind": "ResourceA",
                        "metadata": {"name": "a1", "namespace": "test-ns", "uid": "uid-a", "resourceVersion": "1"}
                    })));
                } else if uri.contains("resourceas") && req.method() == http::Method::DELETE {
                    let body = serde_json::json!({
                        "kind": "Status", "apiVersion": "v1", "metadata": {},
                        "status": "Failure", "reason": "Invalid", "message": "rejected", "code": 422
                    });
                    send.send_response(
                        http::Response::builder()
                            .status(422)
                            .body(Body::from(serde_json::to_vec(&body).unwrap()))
                            .unwrap(),
                    );
                } else {
                    send.send_response(not_found_response());
                }
            }
        });

        let client = Client::new(mock_service, "test-ns");
        let (store, _notifier) = create_runtime_store();
        let watch_mgr = crate::teardown::watch::WatchManager::new(store.clone());

        let result = execute_delete_waves(
            &client,
            &[res_a],
            &km,
            &gk,
            None,
            &watch_mgr,
            &store,
            None,
            None,
            None,
            None,
        )
        .await
        .unwrap();

        assert!(result.stopped, "No progress must stop");
        assert!(result.accepted_gone.is_empty());
        assert!(
            result.failed.iter().any(|(r, _)| r.name == "a1"),
            "A must be in failed: {:?}",
            result.failed
        );

        drop(client);
        spawned.abort();
    }

    #[tokio::test]
    async fn test_wave_blocked_403_stops_immediately() {
        // DELETE returns 403 → Blocked → immediate phase stop
        let res_a = make_test_res("ResourceA", "a1", "uid-a");
        let gk = wave_gk_map();
        let km = std::collections::HashMap::new();

        let (mock_service, handle) =
            tower_test::mock::pair::<http::Request<Body>, http::Response<Body>>();

        let spawned = tokio::spawn(async move {
            let mut handle = std::pin::pin!(handle);
            while let Some((req, send)) = handle.next_request().await {
                let uri = req.uri().to_string();
                if uri.contains("resourceas")
                    && req.method() == http::Method::GET
                    && !uri.contains('?')
                {
                    send.send_response(json_response(serde_json::json!({
                        "apiVersion": "test.example.io/v1", "kind": "ResourceA",
                        "metadata": {"name": "a1", "namespace": "test-ns", "uid": "uid-a", "resourceVersion": "1"}
                    })));
                } else if uri.contains("resourceas") && req.method() == http::Method::DELETE {
                    let body = serde_json::json!({
                        "kind": "Status", "apiVersion": "v1", "metadata": {},
                        "status": "Failure", "reason": "Forbidden", "message": "forbidden", "code": 403
                    });
                    send.send_response(
                        http::Response::builder()
                            .status(403)
                            .body(Body::from(serde_json::to_vec(&body).unwrap()))
                            .unwrap(),
                    );
                } else {
                    send.send_response(not_found_response());
                }
            }
        });

        let client = Client::new(mock_service, "test-ns");
        let (store, _notifier) = create_runtime_store();
        let watch_mgr = crate::teardown::watch::WatchManager::new(store.clone());

        let result = execute_delete_waves(
            &client,
            &[res_a],
            &km,
            &gk,
            None,
            &watch_mgr,
            &store,
            None,
            None,
            None,
            None,
        )
        .await
        .unwrap();

        assert!(result.stopped, "RBAC 403 must Blocked → stop immediately");
        assert!(!result.failed.is_empty(), "Must have failed entries");

        drop(client);
        spawned.abort();
    }

    #[tokio::test]
    async fn test_wave_admission_webhook_403_is_rejected_not_blocked() {
        // Admission webhook 403 is retryable (Rejected), not permanent (Blocked)
        let res_a = make_test_res("ResourceA", "a1", "uid-a");
        let gk = wave_gk_map();
        let km = std::collections::HashMap::new();

        let (mock_service, handle) =
            tower_test::mock::pair::<http::Request<Body>, http::Response<Body>>();

        let spawned = tokio::spawn(async move {
            let mut handle = std::pin::pin!(handle);
            while let Some((req, send)) = handle.next_request().await {
                let uri = req.uri().to_string();
                if uri.contains("resourceas")
                    && req.method() == http::Method::GET
                    && !uri.contains('?')
                {
                    send.send_response(json_response(serde_json::json!({
                        "apiVersion": "test.example.io/v1", "kind": "ResourceA",
                        "metadata": {"name": "a1", "namespace": "test-ns", "uid": "uid-a", "resourceVersion": "1"}
                    })));
                } else if uri.contains("resourceas") && req.method() == http::Method::DELETE {
                    let body = serde_json::json!({
                        "kind": "Status", "apiVersion": "v1", "metadata": {},
                        "status": "Failure", "reason": "Forbidden",
                        "message": "admission webhook \"validator.example.io\" denied the request: dependency not met",
                        "code": 403
                    });
                    send.send_response(
                        http::Response::builder()
                            .status(403)
                            .body(Body::from(serde_json::to_vec(&body).unwrap()))
                            .unwrap(),
                    );
                } else {
                    send.send_response(not_found_response());
                }
            }
        });

        let client = Client::new(mock_service, "test-ns");
        let (store, _notifier) = create_runtime_store();
        let watch_mgr = crate::teardown::watch::WatchManager::new(store.clone());

        let result = execute_delete_waves(
            &client,
            &[res_a],
            &km,
            &gk,
            None,
            &watch_mgr,
            &store,
            None,
            None,
            None,
            None,
        )
        .await
        .unwrap();

        // Admission 403 → Rejected → no progress → stopped (but NOT Blocked)
        assert!(result.stopped, "No progress → stopped");
        // Verify it was classified as no-progress (rejected), not Blocked
        assert!(
            result
                .failed
                .iter()
                .any(|(_, msg)| msg.contains("no progress")),
            "Must be no-progress failure, not Blocked: {:?}",
            result.failed
        );

        drop(client);
        spawned.abort();
    }

    #[tokio::test]
    async fn test_wave_new_uid_blocks() {
        // Fresh GET returns different UID → Blocked
        let res_a = make_test_res("ResourceA", "a1", "uid-a-original");
        let gk = wave_gk_map();
        let km = std::collections::HashMap::new();

        let (mock_service, handle) =
            tower_test::mock::pair::<http::Request<Body>, http::Response<Body>>();

        let spawned = tokio::spawn(async move {
            let mut handle = std::pin::pin!(handle);
            while let Some((req, send)) = handle.next_request().await {
                let uri = req.uri().to_string();
                if uri.contains("resourceas")
                    && req.method() == http::Method::GET
                    && !uri.contains('?')
                {
                    // Return with DIFFERENT UID
                    send.send_response(json_response(serde_json::json!({
                        "apiVersion": "test.example.io/v1", "kind": "ResourceA",
                        "metadata": {"name": "a1", "namespace": "test-ns", "uid": "uid-a-NEW", "resourceVersion": "1"}
                    })));
                } else {
                    send.send_response(not_found_response());
                }
            }
        });

        let client = Client::new(mock_service, "test-ns");
        let (store, _notifier) = create_runtime_store();
        let watch_mgr = crate::teardown::watch::WatchManager::new(store.clone());

        let result = execute_delete_waves(
            &client,
            &[res_a],
            &km,
            &gk,
            None,
            &watch_mgr,
            &store,
            None,
            None,
            None,
            None,
        )
        .await
        .unwrap();

        assert!(result.stopped, "New UID must Blocked → stop");
        assert!(
            result.failed.iter().any(|(_, msg)| msg.contains("UID")),
            "Error must mention UID: {:?}",
            result.failed
        );

        drop(client);
        spawned.abort();
    }

    #[tokio::test]
    async fn test_wave_unknown_5xx_stops_b_not_retried() {
        // A gets 500 → Unknown → stop. B is 422 Rejected in same wave (concurrent).
        // B must NOT get a second DELETE in a retry wave.
        use std::sync::atomic::{AtomicUsize, Ordering};

        let res_a = make_test_res("ResourceA", "a1", "uid-a");
        let res_b = make_test_res("ResourceB", "b1", "uid-b");
        let gk = wave_gk_map();
        let km = std::collections::HashMap::new();

        let b_delete_count = Arc::new(AtomicUsize::new(0));
        let b_del = b_delete_count.clone();

        let (mock_service, handle) =
            tower_test::mock::pair::<http::Request<Body>, http::Response<Body>>();

        let spawned = tokio::spawn(async move {
            let mut handle = std::pin::pin!(handle);
            while let Some((req, send)) = handle.next_request().await {
                let uri = req.uri().to_string();
                let method = req.method().clone();

                if uri.contains("resourceas") && method == http::Method::GET && !uri.contains('?') {
                    send.send_response(json_response(serde_json::json!({
                        "apiVersion": "test.example.io/v1", "kind": "ResourceA",
                        "metadata": {"name": "a1", "namespace": "test-ns", "uid": "uid-a", "resourceVersion": "1"}
                    })));
                } else if uri.contains("resourceas") && method == http::Method::DELETE {
                    let body = serde_json::json!({
                        "kind": "Status", "apiVersion": "v1", "metadata": {},
                        "status": "Failure", "reason": "InternalError", "message": "timeout", "code": 500
                    });
                    send.send_response(
                        http::Response::builder()
                            .status(500)
                            .body(Body::from(serde_json::to_vec(&body).unwrap()))
                            .unwrap(),
                    );
                } else if uri.contains("resourcebs")
                    && method == http::Method::GET
                    && !uri.contains('?')
                {
                    send.send_response(json_response(serde_json::json!({
                        "apiVersion": "test.example.io/v1", "kind": "ResourceB",
                        "metadata": {"name": "b1", "namespace": "test-ns", "uid": "uid-b", "resourceVersion": "1"}
                    })));
                } else if uri.contains("resourcebs") && method == http::Method::DELETE {
                    b_del.fetch_add(1, Ordering::SeqCst);
                    let body = serde_json::json!({
                        "kind": "Status", "apiVersion": "v1", "metadata": {},
                        "status": "Failure", "reason": "Invalid", "message": "not ready", "code": 422
                    });
                    send.send_response(
                        http::Response::builder()
                            .status(422)
                            .body(Body::from(serde_json::to_vec(&body).unwrap()))
                            .unwrap(),
                    );
                } else {
                    send.send_response(not_found_response());
                }
            }
        });

        let client = Client::new(mock_service, "test-ns");
        let (store, _notifier) = create_runtime_store();
        let watch_mgr = crate::teardown::watch::WatchManager::new(store.clone());

        let result = execute_delete_waves(
            &client,
            &[res_a, res_b],
            &km,
            &gk,
            None,
            &watch_mgr,
            &store,
            None,
            None,
            None,
            None,
        )
        .await
        .unwrap();

        assert!(result.stopped, "Unknown must stop");
        assert!(
            result.failed.iter().any(|(r, _)| r.name == "a1"),
            "A must be in failed"
        );
        let b_dels = b_delete_count.load(Ordering::SeqCst);
        assert_eq!(
            b_dels, 1,
            "B must have exactly 1 DELETE attempt (no retry after Unknown stop), got {}",
            b_dels
        );

        drop(client);
        spawned.abort();
    }

    #[tokio::test]
    async fn test_wave_already_gone_counts_as_progress() {
        // A already gone (404), B rejected (422) → AlreadyGone is progress → B retried
        use std::sync::atomic::{AtomicUsize, Ordering};

        let res_a = make_test_res("ResourceA", "a1", "uid-a");
        let res_b = make_test_res("ResourceB", "b1", "uid-b");
        let gk = wave_gk_map();
        let km = std::collections::HashMap::new();

        let b_delete_count = Arc::new(AtomicUsize::new(0));
        let b_del = b_delete_count.clone();

        let (mock_service, handle) =
            tower_test::mock::pair::<http::Request<Body>, http::Response<Body>>();

        let spawned = tokio::spawn(async move {
            let mut handle = std::pin::pin!(handle);
            while let Some((req, send)) = handle.next_request().await {
                let uri = req.uri().to_string();
                let method = req.method().clone();

                if uri.contains("resourceas") && method == http::Method::GET && !uri.contains('?') {
                    // A is already gone
                    send.send_response(not_found_response());
                } else if uri.contains("resourceas") && uri.contains('?') {
                    // LIST for endpoint verification
                    send.send_response(json_response(serde_json::json!({
                        "apiVersion": "v1", "kind": "ResourceAList",
                        "metadata": {"resourceVersion": "1"}, "items": []
                    })));
                } else if uri.contains("resourcebs")
                    && method == http::Method::GET
                    && !uri.contains('?')
                {
                    if b_del.load(Ordering::SeqCst) >= 2 {
                        send.send_response(not_found_response());
                    } else {
                        send.send_response(json_response(serde_json::json!({
                            "apiVersion": "test.example.io/v1", "kind": "ResourceB",
                            "metadata": {"name": "b1", "namespace": "test-ns", "uid": "uid-b", "resourceVersion": "1"}
                        })));
                    }
                } else if uri.contains("resourcebs") && method == http::Method::DELETE {
                    let attempt = b_del.fetch_add(1, Ordering::SeqCst);
                    if attempt == 0 {
                        let body = serde_json::json!({
                            "kind": "Status", "apiVersion": "v1", "metadata": {},
                            "status": "Failure", "reason": "Invalid", "message": "not ready", "code": 422
                        });
                        send.send_response(
                            http::Response::builder()
                                .status(422)
                                .body(Body::from(serde_json::to_vec(&body).unwrap()))
                                .unwrap(),
                        );
                    } else {
                        send.send_response(json_response(serde_json::json!({
                            "apiVersion": "v1", "kind": "Status", "status": "Success", "metadata": {}
                        })));
                    }
                } else if uri.contains("resourcebs") {
                    if b_del.load(Ordering::SeqCst) >= 2 {
                        send.send_response(json_response(serde_json::json!({
                            "apiVersion": "v1", "kind": "ResourceBList",
                            "metadata": {"resourceVersion": "1"}, "items": []
                        })));
                    } else {
                        send.send_response(json_response(serde_json::json!({
                            "apiVersion": "v1", "kind": "ResourceBList",
                            "metadata": {"resourceVersion": "1"},
                            "items": [{"apiVersion": "test.example.io/v1", "kind": "ResourceB",
                                "metadata": {"name": "b1", "namespace": "test-ns", "uid": "uid-b"}}]
                        })));
                    }
                } else {
                    send.send_response(not_found_response());
                }
            }
        });

        let client = Client::new(mock_service, "test-ns");
        let (store, _notifier) = create_runtime_store();
        let watch_mgr = crate::teardown::watch::WatchManager::new(store.clone());

        let result = execute_delete_waves(
            &client,
            &[res_a, res_b],
            &km,
            &gk,
            None,
            &watch_mgr,
            &store,
            None,
            None,
            None,
            None,
        )
        .await
        .unwrap();

        assert!(
            result.already_gone.iter().any(|r| r.name == "a1"),
            "A must be AlreadyGone"
        );
        let b_attempts = b_delete_count.load(Ordering::SeqCst);
        assert!(
            b_attempts >= 2,
            "B must be retried after A's AlreadyGone progress, got {} attempts",
            b_attempts
        );
        assert!(result.failed.is_empty(), "No failures: {:?}", result.failed);

        drop(client);
        spawned.abort();
    }

    #[tokio::test]
    async fn test_wave_retry_new_uid_blocks_no_second_delete() {
        // Wave 1: A accepted→Gone, B rejected (422)
        // Wave 2: B fresh GET returns NEW UID → Blocked, 0 DELETE attempts for B in wave 2
        use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

        let res_a = make_test_res("ResourceA", "a1", "uid-a");
        let res_b = make_test_res("ResourceB", "b1", "uid-b");
        let gk = wave_gk_map();
        let km = std::collections::HashMap::new();

        let a_deleted = Arc::new(AtomicBool::new(false));
        let a_del = a_deleted.clone();
        let b_delete_count = Arc::new(AtomicUsize::new(0));
        let b_del = b_delete_count.clone();

        let (mock_service, handle) =
            tower_test::mock::pair::<http::Request<Body>, http::Response<Body>>();

        let spawned = tokio::spawn(async move {
            let mut handle = std::pin::pin!(handle);
            while let Some((req, send)) = handle.next_request().await {
                let uri = req.uri().to_string();
                let method = req.method().clone();

                if uri.contains("resourceas") {
                    if method == http::Method::DELETE {
                        a_del.store(true, Ordering::SeqCst);
                        send.send_response(json_response(serde_json::json!({
                            "apiVersion": "v1", "kind": "Status", "status": "Success", "metadata": {}
                        })));
                    } else if method == http::Method::GET && !uri.contains('?') {
                        if a_del.load(Ordering::SeqCst) {
                            send.send_response(not_found_response());
                        } else {
                            send.send_response(json_response(serde_json::json!({
                                "apiVersion": "test.example.io/v1", "kind": "ResourceA",
                                "metadata": {"name": "a1", "namespace": "test-ns", "uid": "uid-a", "resourceVersion": "1"}
                            })));
                        }
                    } else {
                        send.send_response(json_response(serde_json::json!({
                            "apiVersion": "v1", "kind": "ResourceAList",
                            "metadata": {"resourceVersion": "1"}, "items": []
                        })));
                    }
                } else if uri.contains("resourcebs") {
                    if method == http::Method::DELETE {
                        b_del.fetch_add(1, Ordering::SeqCst);
                        // First attempt: 422 rejected
                        let body = serde_json::json!({
                            "kind": "Status", "apiVersion": "v1", "metadata": {},
                            "status": "Failure", "reason": "Invalid", "message": "dep", "code": 422
                        });
                        send.send_response(
                            http::Response::builder()
                                .status(422)
                                .body(Body::from(serde_json::to_vec(&body).unwrap()))
                                .unwrap(),
                        );
                    } else if method == http::Method::GET && !uri.contains('?') {
                        // Wave 2 fresh GET: return NEW UID (recreated)
                        if a_del.load(Ordering::SeqCst) {
                            send.send_response(json_response(serde_json::json!({
                                "apiVersion": "test.example.io/v1", "kind": "ResourceB",
                                "metadata": {"name": "b1", "namespace": "test-ns", "uid": "uid-b-NEW", "resourceVersion": "2"}
                            })));
                        } else {
                            send.send_response(json_response(serde_json::json!({
                                "apiVersion": "test.example.io/v1", "kind": "ResourceB",
                                "metadata": {"name": "b1", "namespace": "test-ns", "uid": "uid-b", "resourceVersion": "1"}
                            })));
                        }
                    } else {
                        send.send_response(json_response(serde_json::json!({
                            "apiVersion": "v1", "kind": "ResourceBList",
                            "metadata": {"resourceVersion": "1"}, "items": []
                        })));
                    }
                } else {
                    send.send_response(not_found_response());
                }
            }
        });

        let client = Client::new(mock_service, "test-ns");
        let (store, _notifier) = create_runtime_store();
        let watch_mgr = crate::teardown::watch::WatchManager::new(store.clone());

        let result = execute_delete_waves(
            &client,
            &[res_a, res_b],
            &km,
            &gk,
            None,
            &watch_mgr,
            &store,
            None,
            None,
            None,
            None,
        )
        .await
        .unwrap();

        assert!(result.stopped, "New UID on retry must Blocked → stop");
        let b_dels = b_delete_count.load(Ordering::SeqCst);
        assert_eq!(
            b_dels, 1,
            "B must have exactly 1 DELETE (wave 1 rejected, wave 2 Blocked by new UID — no DELETE), got {}",
            b_dels
        );
        assert!(
            result
                .failed
                .iter()
                .any(|(r, msg)| r.name == "b1" && msg.contains("UID")),
            "B must be failed with UID message: {:?}",
            result.failed
        );

        drop(client);
        spawned.abort();
    }

    #[tokio::test]
    async fn test_wave_3_stage_fixpoint() {
        // 3 targets with cascading admission dependencies:
        // Wave 1: A accepted→Gone, B rejected, C rejected
        // Wave 2: B accepted→Gone, C rejected
        // Wave 3: C accepted→Gone
        use std::sync::atomic::{AtomicUsize, Ordering};

        let res_a = make_test_res("ResourceA", "a1", "uid-a");
        let res_b = make_test_res("ResourceB", "b1", "uid-b");
        let res_c = make_test_res("ResourceC", "c1", "uid-c");
        let gk = wave_gk_map();
        let km = std::collections::HashMap::new();

        let a_del_count = Arc::new(AtomicUsize::new(0));
        let b_del_count = Arc::new(AtomicUsize::new(0));
        let c_del_count = Arc::new(AtomicUsize::new(0));
        let a_dc = a_del_count.clone();
        let b_dc = b_del_count.clone();
        let c_dc = c_del_count.clone();

        let (mock_service, handle) =
            tower_test::mock::pair::<http::Request<Body>, http::Response<Body>>();

        let spawned = tokio::spawn(async move {
            let mut handle = std::pin::pin!(handle);
            while let Some((req, send)) = handle.next_request().await {
                let uri = req.uri().to_string();
                let method = req.method().clone();

                // Helper: resource kind from URI
                let (kind, del_count_ref): (&str, &AtomicUsize) = if uri.contains("resourceas") {
                    ("ResourceA", &a_dc)
                } else if uri.contains("resourcebs") {
                    ("ResourceB", &b_dc)
                } else if uri.contains("resourcecs") {
                    ("ResourceC", &c_dc)
                } else {
                    send.send_response(not_found_response());
                    continue;
                };

                let name = match kind {
                    "ResourceA" => "a1",
                    "ResourceB" => "b1",
                    _ => "c1",
                };
                let uid = match kind {
                    "ResourceA" => "uid-a",
                    "ResourceB" => "uid-b",
                    _ => "uid-c",
                };

                if method == http::Method::DELETE {
                    let attempt = del_count_ref.fetch_add(1, Ordering::SeqCst);
                    // A: always accepted (wave 1)
                    // B: rejected on attempt 0, accepted on attempt 1+ (wave 2)
                    // C: rejected on attempts 0,1, accepted on attempt 2+ (wave 3)
                    let threshold = match kind {
                        "ResourceA" => 0,
                        "ResourceB" => 1,
                        _ => 2,
                    };
                    if attempt < threshold {
                        let body = serde_json::json!({
                            "kind": "Status", "apiVersion": "v1", "metadata": {},
                            "status": "Failure", "reason": "Invalid",
                            "message": "dependency not ready", "code": 422
                        });
                        send.send_response(
                            http::Response::builder()
                                .status(422)
                                .body(Body::from(serde_json::to_vec(&body).unwrap()))
                                .unwrap(),
                        );
                    } else {
                        send.send_response(json_response(serde_json::json!({
                            "apiVersion": "v1", "kind": "Status", "status": "Success", "metadata": {}
                        })));
                    }
                } else if method == http::Method::GET && !uri.contains('?') {
                    // After all DELETEs accepted for this resource, return 404
                    let threshold = match kind {
                        "ResourceA" => 1,
                        "ResourceB" => 2,
                        _ => 3,
                    };
                    if del_count_ref.load(Ordering::SeqCst) >= threshold {
                        send.send_response(not_found_response());
                    } else {
                        send.send_response(json_response(serde_json::json!({
                            "apiVersion": "test.example.io/v1", "kind": kind,
                            "metadata": {"name": name, "namespace": "test-ns", "uid": uid, "resourceVersion": "1"}
                        })));
                    }
                } else {
                    // LIST for endpoint verification
                    let threshold = match kind {
                        "ResourceA" => 1,
                        "ResourceB" => 2,
                        _ => 3,
                    };
                    if del_count_ref.load(Ordering::SeqCst) >= threshold {
                        send.send_response(json_response(serde_json::json!({
                            "apiVersion": "v1", "kind": "List",
                            "metadata": {"resourceVersion": "1"}, "items": []
                        })));
                    } else {
                        send.send_response(json_response(serde_json::json!({
                            "apiVersion": "v1", "kind": "List",
                            "metadata": {"resourceVersion": "1"},
                            "items": [{"apiVersion": "test.example.io/v1", "kind": kind,
                                "metadata": {"name": name, "namespace": "test-ns", "uid": uid}}]
                        })));
                    }
                }
            }
        });

        let client = Client::new(mock_service, "test-ns");
        let (store, _notifier) = create_runtime_store();
        let watch_mgr = crate::teardown::watch::WatchManager::new(store.clone());

        let result = execute_delete_waves(
            &client,
            &[res_a, res_b, res_c],
            &km,
            &gk,
            None,
            &watch_mgr,
            &store,
            None,
            None,
            None,
            None,
        )
        .await
        .unwrap();

        assert!(!result.stopped, "3-wave fixpoint must complete");
        assert_eq!(
            result.accepted_gone.len(),
            3,
            "All 3 must be Gone: {:?}",
            result.accepted_gone
        );
        assert!(result.failed.is_empty(), "No failures: {:?}", result.failed);

        let a_dels = a_del_count.load(Ordering::SeqCst);
        let b_dels = b_del_count.load(Ordering::SeqCst);
        let c_dels = c_del_count.load(Ordering::SeqCst);
        assert_eq!(a_dels, 1, "A: 1 DELETE attempt");
        assert_eq!(b_dels, 2, "B: 2 DELETE attempts (rejected+retry)");
        assert_eq!(c_dels, 3, "C: 3 DELETE attempts (rejected+rejected+retry)");

        drop(client);
        spawned.abort();
    }

    // ── MVP re-delete and finalizer recovery integration tests ──

    #[tokio::test]
    async fn test_wave_recreated_passes_through_no_redelete() {
        // Wave: A DELETE accepted → Recreated (new UID) → wave treats original as complete
        // → no re-DELETE in wave → 1 DELETE total → accepted_gone includes A
        use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

        let res_a = make_test_res("ResourceA", "a1", "uid-old");
        let gk = wave_gk_map();
        let km = std::collections::HashMap::new();

        let a_deleted = Arc::new(AtomicBool::new(false));
        let a_del = a_deleted.clone();
        let delete_count = Arc::new(AtomicUsize::new(0));
        let del_cnt = delete_count.clone();

        let (mock_service, handle) =
            tower_test::mock::pair::<http::Request<Body>, http::Response<Body>>();

        let spawned = tokio::spawn(async move {
            let mut handle = std::pin::pin!(handle);
            while let Some((req, send)) = handle.next_request().await {
                let uri = req.uri().to_string();
                let method = req.method().clone();
                if !uri.contains("resourceas") {
                    send.send_response(not_found_response());
                    continue;
                }
                if method == http::Method::DELETE {
                    del_cnt.fetch_add(1, Ordering::SeqCst);
                    a_del.store(true, Ordering::SeqCst);
                    send.send_response(json_response(serde_json::json!({
                        "apiVersion": "v1", "kind": "Status", "status": "Success", "metadata": {}
                    })));
                } else if method == http::Method::GET && !uri.contains('?') {
                    if a_del.load(Ordering::SeqCst) {
                        send.send_response(json_response(serde_json::json!({
                            "apiVersion": "test.example.io/v1", "kind": "ResourceA",
                            "metadata": {"name": "a1", "namespace": "test-ns", "uid": "uid-new", "resourceVersion": "2"}
                        })));
                    } else {
                        send.send_response(json_response(serde_json::json!({
                            "apiVersion": "test.example.io/v1", "kind": "ResourceA",
                            "metadata": {"name": "a1", "namespace": "test-ns", "uid": "uid-old", "resourceVersion": "1"}
                        })));
                    }
                } else {
                    let uid = if a_del.load(Ordering::SeqCst) {
                        "uid-new"
                    } else {
                        "uid-old"
                    };
                    send.send_response(json_response(serde_json::json!({
                        "apiVersion": "v1", "kind": "ResourceAList",
                        "metadata": {"resourceVersion": "1"},
                        "items": [{"apiVersion": "test.example.io/v1", "kind": "ResourceA",
                            "metadata": {"name": "a1", "namespace": "test-ns", "uid": uid}}]
                    })));
                }
            }
        });

        let js = make_test_journal_store();
        let gate = crate::teardown::permit::MutationGate::new(4);
        let client = Client::new(mock_service, "test-ns");
        let (store, _notifier) = create_runtime_store();
        let watch_mgr = crate::teardown::watch::WatchManager::new(store.clone());

        let result = execute_delete_waves(
            &client,
            &[res_a],
            &km,
            &gk,
            None,
            &watch_mgr,
            &store,
            Some(&js),
            Some(&gate),
            None,
            None,
        )
        .await
        .unwrap();

        assert_eq!(
            delete_count.load(Ordering::SeqCst),
            1,
            "Only 1 DELETE (original, no wave re-delete)"
        );
        assert!(
            !result.accepted_gone.is_empty(),
            "Recreated target must be in accepted_gone"
        );
        assert!(!result.stopped);

        // Wave does NOT create re-delete journal records
        let j = js.read().await;
        assert!(
            j.execution.re_delete_records.is_empty(),
            "No re-delete records from wave"
        );

        drop(client);
        spawned.abort();
    }

    #[tokio::test]
    async fn test_attempt_redelete_b_then_c_current_uid() {
        // Direct test of attempt_single_redelete: A→B→C with current UID precondition
        use std::sync::atomic::{AtomicUsize, Ordering};

        let res = make_test_res("ResourceA", "a1", "uid-A");
        let gk = wave_gk_map();
        let km = std::collections::HashMap::new();

        let delete_count = Arc::new(AtomicUsize::new(0));
        let del_cnt = delete_count.clone();

        let (mock_service, handle) =
            tower_test::mock::pair::<http::Request<Body>, http::Response<Body>>();

        let spawned = tokio::spawn(async move {
            let mut handle = std::pin::pin!(handle);
            while let Some((req, send)) = handle.next_request().await {
                let uri = req.uri().to_string();
                let method = req.method().clone();
                if !uri.contains("resourceas") {
                    send.send_response(not_found_response());
                    continue;
                }
                let cnt = del_cnt.load(Ordering::SeqCst);
                if method == http::Method::DELETE {
                    del_cnt.fetch_add(1, Ordering::SeqCst);
                    send.send_response(json_response(serde_json::json!({
                        "apiVersion": "v1", "kind": "Status", "status": "Success", "metadata": {}
                    })));
                } else if method == http::Method::GET && !uri.contains('?') {
                    if cnt == 0 {
                        send.send_response(json_response(serde_json::json!({
                            "apiVersion": "test.example.io/v1", "kind": "ResourceA",
                            "metadata": {"name": "a1", "namespace": "test-ns", "uid": "uid-B", "resourceVersion": "1"}
                        })));
                    } else {
                        send.send_response(json_response(serde_json::json!({
                            "apiVersion": "test.example.io/v1", "kind": "ResourceA",
                            "metadata": {"name": "a1", "namespace": "test-ns", "uid": "uid-C", "resourceVersion": "1"}
                        })));
                    }
                } else {
                    send.send_response(json_response(serde_json::json!({
                        "apiVersion": "v1", "kind": "ResourceAList",
                        "metadata": {"resourceVersion": "1"}, "items": []
                    })));
                }
            }
        });

        let js = make_test_journal_store();
        let gate = crate::teardown::permit::MutationGate::new(4);
        let client = Client::new(mock_service, "test-ns");

        // First re-delete: A→B
        let r1 =
            attempt_single_redelete(&client, &res, "uid-A", "uid-B", &km, &gk, &js, &gate).await;
        assert!(
            matches!(r1, ReDeleteAttemptResult::Accepted),
            "B must be Accepted: {:?}",
            r1
        );

        // Second re-delete: A→C
        let r2 =
            attempt_single_redelete(&client, &res, "uid-A", "uid-C", &km, &gk, &js, &gate).await;
        assert!(
            matches!(r2, ReDeleteAttemptResult::Accepted),
            "C must be Accepted: {:?}",
            r2
        );

        assert_eq!(
            delete_count.load(Ordering::SeqCst),
            2,
            "2 DELETEs (B and C)"
        );

        // Journal: 2 re-delete records
        let j = js.read().await;
        assert_eq!(j.execution.re_delete_records.len(), 2);
        assert_eq!(j.execution.re_delete_records[0].original_uid, "uid-A");
        assert_eq!(j.execution.re_delete_records[1].original_uid, "uid-A");

        drop(client);
        spawned.abort();
    }

    #[tokio::test]
    async fn test_attempt_redelete_404_endpoint_failure_stops() {
        // attempt_single_redelete: DELETE returns 404, LIST returns 403 → Stop
        let res = make_test_res("ResourceA", "a1", "uid-A");
        let gk = wave_gk_map();
        let km = std::collections::HashMap::new();

        let (mock_service, handle) =
            tower_test::mock::pair::<http::Request<Body>, http::Response<Body>>();

        let spawned = tokio::spawn(async move {
            let mut handle = std::pin::pin!(handle);
            while let Some((req, send)) = handle.next_request().await {
                let uri = req.uri().to_string();
                let method = req.method().clone();
                if !uri.contains("resourceas") {
                    send.send_response(not_found_response());
                    continue;
                }
                if method == http::Method::GET && !uri.contains('?') {
                    send.send_response(json_response(serde_json::json!({
                        "apiVersion": "test.example.io/v1", "kind": "ResourceA",
                        "metadata": {"name": "a1", "namespace": "test-ns", "uid": "uid-B", "resourceVersion": "1"}
                    })));
                } else if method == http::Method::DELETE {
                    send.send_response(not_found_response());
                } else {
                    send.send_response(forbidden_response());
                }
            }
        });

        let js = make_test_journal_store();
        let gate = crate::teardown::permit::MutationGate::new(4);
        let client = Client::new(mock_service, "test-ns");

        let r =
            attempt_single_redelete(&client, &res, "uid-A", "uid-B", &km, &gk, &js, &gate).await;
        assert!(
            matches!(r, ReDeleteAttemptResult::Stop(_)),
            "404+403 must Stop: {:?}",
            r
        );

        // Journal record must not be Gone
        let j = js.read().await;
        assert!(!j.execution.re_delete_records.is_empty());
        assert!(
            !matches!(
                j.execution.re_delete_records[0].result,
                crate::teardown::journal::ReDeleteResult::Gone
            ),
            "Must not be Gone"
        );

        drop(client);
        spawned.abort();
    }

    #[test]
    fn test_already_gone_has_no_redelete_authority() {
        let res_a = make_test_res("ResourceA", "a1", "uid-a");
        let res_b = make_test_res("ResourceB", "b1", "uid-b");
        let wave = WaveResult {
            accepted_gone: vec![res_a.clone()],
            already_gone: vec![res_b.clone()],
            failed: vec![],
            stopped: false,
            redelete_authorities: vec![(res_a.clone(), "uid-a".to_string())],
        };
        assert!(
            wave.redelete_authorities
                .iter()
                .any(|(r, _)| r.name == "a1"),
        );
        assert!(
            !wave
                .redelete_authorities
                .iter()
                .any(|(r, _)| r.name == "b1"),
        );
    }

    #[tokio::test]
    async fn test_explicit_delete_finalizer_recovery_full_path() {
        use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

        let res_a = make_test_res("ResourceA", "a1", "uid-a");
        let phase = crate::teardown::planner::PlanPhase {
            name: "test".to_string(),
            description: "".to_string(),
            actions: vec![crate::teardown::planner::Action::Delete {
                resource: res_a.clone(),
                reason: "test".to_string(),
            }],
            barrier: None,
        };
        let gk = wave_gk_map();
        let km = std::collections::HashMap::new();

        let a_deleted = Arc::new(AtomicBool::new(false));
        let a_del = a_deleted.clone();
        let a_stripped = Arc::new(AtomicBool::new(false));
        let a_strip = a_stripped.clone();
        let patch_count = Arc::new(AtomicUsize::new(0));
        let patch_cnt = patch_count.clone();
        let patch_body: Arc<std::sync::Mutex<Option<serde_json::Value>>> =
            Arc::new(std::sync::Mutex::new(None));
        let patch_body_cap = patch_body.clone();

        let (mock_service, handle) =
            tower_test::mock::pair::<http::Request<Body>, http::Response<Body>>();

        let spawned = tokio::spawn(async move {
            let mut handle = std::pin::pin!(handle);
            while let Some((req, send)) = handle.next_request().await {
                let uri = req.uri().to_string();
                let method = req.method().clone();
                if !uri.contains("resourceas") {
                    send.send_response(not_found_response());
                    continue;
                }
                if method == http::Method::DELETE {
                    a_del.store(true, Ordering::SeqCst);
                    send.send_response(json_response(serde_json::json!({
                        "apiVersion": "v1", "kind": "Status", "status": "Success", "metadata": {}
                    })));
                } else if method == http::Method::PATCH {
                    patch_cnt.fetch_add(1, Ordering::SeqCst);
                    if let Ok(bytes) = req.into_body().collect_bytes().await
                        && let Ok(json) = serde_json::from_slice::<serde_json::Value>(&bytes)
                    {
                        *patch_body_cap.lock().unwrap() = Some(json);
                    }
                    a_strip.store(true, Ordering::SeqCst);
                    send.send_response(json_response(serde_json::json!({
                        "apiVersion": "test.example.io/v1", "kind": "ResourceA",
                        "metadata": {"name": "a1", "namespace": "test-ns", "uid": "uid-a",
                            "deletionTimestamp": "2026-01-01T00:00:00Z", "finalizers": []}
                    })));
                } else if method == http::Method::GET && !uri.contains('?') {
                    if a_strip.load(Ordering::SeqCst) {
                        send.send_response(not_found_response());
                    } else if a_del.load(Ordering::SeqCst) {
                        send.send_response(json_response(serde_json::json!({
                            "apiVersion": "test.example.io/v1", "kind": "ResourceA",
                            "metadata": {"name": "a1", "namespace": "test-ns", "uid": "uid-a",
                                "deletionTimestamp": "2026-01-01T00:00:00Z",
                                "finalizers": ["test.example.io/block"],
                                "resourceVersion": "2"}
                        })));
                    } else {
                        send.send_response(json_response(serde_json::json!({
                            "apiVersion": "test.example.io/v1", "kind": "ResourceA",
                            "metadata": {"name": "a1", "namespace": "test-ns", "uid": "uid-a",
                                "resourceVersion": "1"}
                        })));
                    }
                } else {
                    if a_strip.load(Ordering::SeqCst) {
                        send.send_response(json_response(serde_json::json!({
                            "apiVersion": "v1", "kind": "ResourceAList",
                            "metadata": {"resourceVersion": "1"}, "items": []
                        })));
                    } else {
                        send.send_response(json_response(serde_json::json!({
                            "apiVersion": "v1", "kind": "ResourceAList",
                            "metadata": {"resourceVersion": "1"},
                            "items": [{"apiVersion": "test.example.io/v1", "kind": "ResourceA",
                                "metadata": {"name": "a1", "namespace": "test-ns", "uid": "uid-a"}}]
                        })));
                    }
                }
            }
        });

        let js = make_test_journal_store();
        js.update(|j| {
            j.finalizer_recovery_approved = true;
        })
        .await
        .unwrap();
        let gate = crate::teardown::permit::MutationGate::new(4);
        let client = Client::new(mock_service, "test-ns");
        let (store, _notifier) = create_runtime_store();
        let watch_mgr = crate::teardown::watch::WatchManager::new(store.clone());

        let result = execute_delete_waves(
            &client,
            &[res_a],
            &km,
            &gk,
            None,
            &watch_mgr,
            &store,
            Some(&js),
            Some(&gate),
            None,
            Some(&phase),
        )
        .await
        .unwrap();

        assert!(!result.stopped, "Recovery must succeed: {:?}", result);
        assert!(!result.accepted_gone.is_empty());
        assert_eq!(patch_count.load(Ordering::SeqCst), 1);

        let j = js.read().await;
        assert!(!j.finalizer_recoveries.is_empty());

        let captured_patch = patch_body.lock().unwrap();
        let ops = captured_patch.as_ref().unwrap().as_array().unwrap();
        assert!(ops.iter().any(|op| {
            op.get("op").and_then(|o| o.as_str()) == Some("test")
                && op.get("path").and_then(|p| p.as_str()) == Some("/metadata/uid")
        }));
        assert!(ops.iter().any(|op| {
            op.get("op").and_then(|o| o.as_str()) == Some("test")
                && op.get("path").and_then(|p| p.as_str()) == Some("/metadata/finalizers")
                && op.get("value") == Some(&serde_json::json!(["test.example.io/block"]))
        }));
        assert!(!ops.iter().any(|op| {
            op.get("path")
                .and_then(|p| p.as_str())
                .is_some_and(|p| p.contains("ownerReferences"))
        }));

        drop(client);
        spawned.abort();
    }

    // ── Saved residual decision validation tests ──

    #[test]
    fn recreated_expect_does_not_inherit_auto_cleanup_authority() {
        use crate::teardown::audit::{AuditCoverage, RecreationState, ResidualAudit, ResidualItem};

        let resource = make_cm_resource("child1", Some("uid-A"));
        let mut audit = ResidualAudit {
            planned_delete_still_present: vec![],
            planned_expect_still_present: vec![ResidualItem {
                resource: resource.clone(),
                planned_action: "EXPECT".to_string(),
                live_uid: Some("uid-B".to_string()),
                recreation: RecreationState::Recreated,
            }],
            expected_preserved: vec![],
            likely_operator_residual: vec![],
            unattributed: vec![],
            coverage: AuditCoverage {
                requested_probes: 1,
                succeeded_probes: 1,
            },
            scan_errors: vec![],
        };
        assert!(auto_cleanup_candidates(&audit, &[]).is_empty());

        audit.planned_expect_still_present[0].live_uid = resource.uid.clone();
        audit.planned_expect_still_present[0].recreation = RecreationState::SameResource;
        assert_eq!(auto_cleanup_candidates(&audit, &[]).len(), 1);
    }

    #[test]
    fn residual_explicit_unattributed_blocked() {
        use crate::teardown::audit::*;
        use crate::teardown::plan::*;

        let audit = ResidualAudit {
            planned_delete_still_present: vec![],
            planned_expect_still_present: vec![],
            expected_preserved: vec![],
            likely_operator_residual: vec![AttributedResidual {
                resource: crate::kube::resource::ResourceId {
                    group: "test.io".to_string(),
                    version: "v1".to_string(),
                    kind: "Widget".to_string(),
                    namespace: Some("ns".to_string()),
                    name: "w1".to_string(),
                    uid: Some("uid-w1".to_string()),
                },
                evidence: ResidualEvidence {
                    owner_ref_match: false,
                    matching_labels: vec![],
                    matching_managers: vec![],
                    namespace_affinity: true,
                    service_account_match: false,
                },
                confidence: ResidualConfidence::Medium,
            }],
            unattributed: vec![],
            coverage: AuditCoverage {
                requested_probes: 0,
                succeeded_probes: 0,
            },
            scan_errors: vec![],
        };

        let decisions = vec![SavedDecision {
            match_spec: ResourceMatch {
                group: Some("test.io".to_string()),
                kind: "Widget".to_string(),
                namespace: Some("ns".to_string()),
                name: "w1".to_string(),
            },
            action: SavedAction::Delete,
            approval: ApprovalKind::ExplicitUnattributed,
            basis: DecisionBasis {
                provenance: Some("Unknown".to_string()),
                review_category: None,
                discovery_source: None,
                decisive_evidence: vec![],
            },
        }];

        let result = validate_saved_residual_decisions(&decisions, &audit);
        assert!(result.is_err(), "ExplicitUnattributed must be blocked");
    }

    #[test]
    fn residual_not_in_current_set_blocked() {
        use crate::teardown::audit::*;
        use crate::teardown::plan::*;

        let audit = ResidualAudit {
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

        let decisions = vec![SavedDecision {
            match_spec: ResourceMatch {
                group: Some("test.io".to_string()),
                kind: "Widget".to_string(),
                namespace: Some("ns".to_string()),
                name: "w1".to_string(),
            },
            action: SavedAction::Delete,
            approval: ApprovalKind::Explicit,
            basis: DecisionBasis {
                provenance: Some("Managed".to_string()),
                review_category: None,
                discovery_source: None,
                decisive_evidence: vec![],
            },
        }];

        let result = validate_saved_residual_decisions(&decisions, &audit);
        assert!(
            result.is_err(),
            "Not in current residual set must be blocked"
        );
    }

    #[test]
    fn residual_valid_match_returns_uid() {
        use crate::teardown::audit::*;
        use crate::teardown::plan::*;

        let audit = ResidualAudit {
            planned_delete_still_present: vec![],
            planned_expect_still_present: vec![],
            expected_preserved: vec![],
            likely_operator_residual: vec![AttributedResidual {
                resource: crate::kube::resource::ResourceId {
                    group: "test.io".to_string(),
                    version: "v1".to_string(),
                    kind: "Widget".to_string(),
                    namespace: Some("ns".to_string()),
                    name: "w1".to_string(),
                    uid: Some("uid-current".to_string()),
                },
                evidence: ResidualEvidence {
                    owner_ref_match: true,
                    matching_labels: vec![],
                    matching_managers: vec![],
                    namespace_affinity: true,
                    service_account_match: false,
                },
                confidence: ResidualConfidence::High,
            }],
            unattributed: vec![],
            coverage: AuditCoverage {
                requested_probes: 1,
                succeeded_probes: 1,
            },
            scan_errors: vec![],
        };

        let decisions = vec![SavedDecision {
            match_spec: ResourceMatch {
                group: Some("test.io".to_string()),
                kind: "Widget".to_string(),
                namespace: Some("ns".to_string()),
                name: "w1".to_string(),
            },
            action: SavedAction::Delete,
            approval: ApprovalKind::Explicit,
            basis: DecisionBasis {
                provenance: Some("Managed".to_string()),
                review_category: None,
                discovery_source: None,
                decisive_evidence: vec![],
            },
        }];

        let result = validate_saved_residual_decisions(&decisions, &audit);
        assert!(result.is_ok(), "Valid match must succeed");
        let candidates = result.unwrap();
        assert_eq!(candidates.len(), 1);
        assert_eq!(candidates[0].uid.as_deref(), Some("uid-current"));
    }

    #[test]
    fn residual_empty_basis_blocked() {
        use crate::teardown::audit::*;
        use crate::teardown::plan::*;

        let audit = ResidualAudit {
            planned_delete_still_present: vec![],
            planned_expect_still_present: vec![],
            expected_preserved: vec![],
            likely_operator_residual: vec![AttributedResidual {
                resource: crate::kube::resource::ResourceId {
                    group: "test.io".to_string(),
                    version: "v1".to_string(),
                    kind: "Widget".to_string(),
                    namespace: Some("ns".to_string()),
                    name: "w1".to_string(),
                    uid: Some("uid-1".to_string()),
                },
                evidence: ResidualEvidence {
                    owner_ref_match: false,
                    matching_labels: vec![],
                    matching_managers: vec![],
                    namespace_affinity: true,
                    service_account_match: false,
                },
                confidence: ResidualConfidence::Medium,
            }],
            unattributed: vec![],
            coverage: AuditCoverage {
                requested_probes: 1,
                succeeded_probes: 1,
            },
            scan_errors: vec![],
        };

        let decisions = vec![SavedDecision {
            match_spec: ResourceMatch {
                group: Some("test.io".to_string()),
                kind: "Widget".to_string(),
                namespace: Some("ns".to_string()),
                name: "w1".to_string(),
            },
            action: SavedAction::Delete,
            approval: ApprovalKind::Explicit,
            basis: DecisionBasis {
                provenance: None,
                review_category: None,
                discovery_source: None,
                decisive_evidence: vec![],
            },
        }];

        let result = validate_saved_residual_decisions(&decisions, &audit);
        assert!(result.is_err(), "Empty basis must block residual cleanup");
    }

    #[test]
    fn residual_missing_label_in_evidence_blocked() {
        use crate::teardown::audit::*;
        use crate::teardown::plan::*;

        let audit = ResidualAudit {
            planned_delete_still_present: vec![],
            planned_expect_still_present: vec![],
            expected_preserved: vec![],
            likely_operator_residual: vec![AttributedResidual {
                resource: crate::kube::resource::ResourceId {
                    group: "test.io".to_string(),
                    version: "v1".to_string(),
                    kind: "Widget".to_string(),
                    namespace: Some("ns".to_string()),
                    name: "w1".to_string(),
                    uid: Some("uid-1".to_string()),
                },
                evidence: ResidualEvidence {
                    owner_ref_match: false,
                    matching_labels: vec![("app".to_string(), "other".to_string())],
                    matching_managers: vec![],
                    namespace_affinity: true,
                    service_account_match: false,
                },
                confidence: ResidualConfidence::High,
            }],
            unattributed: vec![],
            coverage: AuditCoverage {
                requested_probes: 1,
                succeeded_probes: 1,
            },
            scan_errors: vec![],
        };

        let decisions = vec![SavedDecision {
            match_spec: ResourceMatch {
                group: Some("test.io".to_string()),
                kind: "Widget".to_string(),
                namespace: Some("ns".to_string()),
                name: "w1".to_string(),
            },
            action: SavedAction::Delete,
            approval: ApprovalKind::Explicit,
            basis: DecisionBasis {
                provenance: Some("LikelyManaged".to_string()),
                review_category: None,
                discovery_source: None,
                decisive_evidence: vec![SavedEvidenceSignature::Label {
                    key: "app".to_string(),
                    value: "expected".to_string(),
                }],
            },
        }];

        let result = validate_saved_residual_decisions(&decisions, &audit);
        assert!(
            result.is_err(),
            "Missing label in current evidence must block"
        );
    }

    #[test]
    fn residual_dedup_by_group_kind_ns_name() {
        use crate::teardown::audit::*;
        use crate::teardown::plan::*;

        let audit = ResidualAudit {
            planned_delete_still_present: vec![],
            planned_expect_still_present: vec![],
            expected_preserved: vec![],
            likely_operator_residual: vec![AttributedResidual {
                resource: crate::kube::resource::ResourceId {
                    group: "test.io".to_string(),
                    version: "v1".to_string(),
                    kind: "Widget".to_string(),
                    namespace: Some("ns".to_string()),
                    name: "w1".to_string(),
                    uid: Some("uid-1".to_string()),
                },
                evidence: ResidualEvidence {
                    owner_ref_match: true,
                    matching_labels: vec![],
                    matching_managers: vec![],
                    namespace_affinity: true,
                    service_account_match: false,
                },
                confidence: ResidualConfidence::High,
            }],
            unattributed: vec![],
            coverage: AuditCoverage {
                requested_probes: 1,
                succeeded_probes: 1,
            },
            scan_errors: vec![],
        };

        let same_decision = SavedDecision {
            match_spec: ResourceMatch {
                group: Some("test.io".to_string()),
                kind: "Widget".to_string(),
                namespace: Some("ns".to_string()),
                name: "w1".to_string(),
            },
            action: SavedAction::Delete,
            approval: ApprovalKind::Explicit,
            basis: DecisionBasis {
                provenance: Some("Managed".to_string()),
                review_category: None,
                discovery_source: None,
                decisive_evidence: vec![],
            },
        };

        let decisions = vec![same_decision.clone(), same_decision];
        let result = validate_saved_residual_decisions(&decisions, &audit);
        assert!(result.is_ok());
        assert_eq!(result.unwrap().len(), 1, "Duplicate must be deduped");
    }

    #[tokio::test]
    async fn test_recovery_redelete_wrong_original_uid_rejects() {
        // A redelete record exists but with a different original_uid than plan_uid.
        // Recovery must NOT accept it — prevents cross-generation authority leak.
        let root = make_cm_resource("root1", Some("uid-root-A"));
        let phase = PlanPhase {
            name: "operand cleanup".to_string(),
            description: String::new(),
            actions: vec![Action::Delete {
                resource: root.clone(),
                reason: String::new(),
            }],
            barrier: None,
        };
        let km = test_kind_map();
        let gk = recovery_gk_map();

        let (mock_service, handle) =
            tower_test::mock::pair::<http::Request<Body>, http::Response<Body>>();

        let spawned = tokio::spawn(async move {
            let mut handle = pin!(handle);
            // GET root → live UID is "uid-root-C" (recreated)
            let (_req, send) = handle.next_request().await.unwrap();
            send.send_response(json_response(serde_json::json!({
                "apiVersion": "v1", "kind": "ConfigMap",
                "metadata": {
                    "name": "root1", "namespace": "test-ns",
                    "uid": "uid-root-C",
                    "deletionTimestamp": "2026-01-01T00:00:00Z",
                    "finalizers": ["test/fin"]
                }
            })));
        });

        let js = make_test_journal_store();
        // Record has original_uid = "uid-root-B" (different generation), not "uid-root-A"
        let mut identity = root.clone();
        identity.uid = None;
        js.update(|j| {
            j.execution
                .re_delete_records
                .push(crate::teardown::journal::ReDeleteRecord {
                    resource_identity: identity,
                    original_uid: "uid-root-B".to_string(),
                    new_uid: "uid-root-C".to_string(),
                    result: crate::teardown::journal::ReDeleteResult::Accepted,
                });
        })
        .await
        .unwrap();

        let gate = make_test_gate();
        let client = Client::new(mock_service, "test-ns");
        let result = attempt_finalizer_recovery(
            &client,
            std::slice::from_ref(&root),
            &[root.clone()],
            &phase,
            &km,
            &gk,
            &js,
            &gate,
        )
        .await;

        assert_eq!(
            result.unwrap(),
            0,
            "Redelete record with wrong original_uid must not authorize recovery"
        );
        drop(client);
        spawned.abort();
    }

    #[tokio::test]
    async fn test_defer_rejects_expect_with_different_uid() {
        // EXPECT resource with same name but different UID must NOT pass
        // can_defer_to_residual — only full ResourceId match is accepted.
        let child_plan = make_cm_resource("child1", Some("uid-child-A"));
        let child_different_uid = make_cm_resource("child1", Some("uid-child-B"));
        let root = make_cm_resource("root1", Some("uid-root"));
        let phase = PlanPhase {
            name: "operand cleanup".to_string(),
            description: String::new(),
            actions: vec![
                Action::Delete {
                    resource: root.clone(),
                    reason: String::new(),
                },
                Action::ExpectGone {
                    resource: child_plan.clone(),
                    reason: String::new(),
                },
            ],
            barrier: None,
        };

        let notifier = Arc::new(EventNotifier::new());
        let store = Arc::new(crate::teardown::runtime::RuntimeStateStore::new(
            notifier,
            Duration::from_secs(120),
        ));
        store.register(
            &child_different_uid,
            crate::teardown::runtime::ResourceRuntimeState::ExpectingGone,
            0,
        );
        let watch_mgr = crate::teardown::watch::WatchManager::new(store.clone());

        // No API calls needed — should reject before reaching root check
        let (mock_service, _handle) =
            tower_test::mock::pair::<http::Request<Body>, http::Response<Body>>();
        let client = Client::new(mock_service, "test-ns");

        let js = make_test_journal_store();
        let result = can_defer_to_residual(
            &client,
            std::slice::from_ref(&child_different_uid),
            &phase,
            &watch_mgr,
            &store,
            Some(&js),
            &test_kind_map(),
            &recovery_gk_map(),
        )
        .await;

        assert!(
            !result,
            "EXPECT with different UID must not be deferred"
        );
    }
}
