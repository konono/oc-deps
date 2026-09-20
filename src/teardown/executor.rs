use std::collections::HashSet;
use std::io::Write;
use std::sync::Arc;
use std::time::Instant;

use anyhow::{Result, bail};
use futures::stream::StreamExt;
use kube::{
    Client,
    api::{Api, ApiResource, DeleteParams, DynamicObject, ListParams, Patch, PatchParams},
    core::GroupVersion,
};

use crate::kube::discovery::{GroupKindMap, GvkMap, GvrMap, KindMap};
use crate::kube::resource::{ResourceId, resolve_api};
use crate::teardown::finalizers::{FinalizerCheck, check_finalizers_batch, requires_serialization};
use crate::teardown::planner::{Action, PreflightSeverity, TeardownPlan};

const DEFAULT_CONCURRENCY: usize = 16;

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

// ── Delete result ──

#[derive(Debug)]
enum DeleteResult {
    Deleted { uid: String },
    AlreadyGone,
    Failed(String),
}

// ── Barrier target: separates "observe" from "authorized to re-DELETE" ──

#[derive(Debug, Clone)]
enum BarrierMode {
    ObserveOnly,
    ReDeleteIfRecreated { original_uid: String },
}

#[derive(Debug, Clone)]
struct BarrierTarget {
    resource: ResourceId,
    mode: BarrierMode,
}

fn should_redelete(
    target: &BarrierTarget,
    current_uid: Option<&str>,
    has_deletion_timestamp: bool,
) -> bool {
    if has_deletion_timestamp {
        return false;
    }
    match &target.mode {
        BarrierMode::ObserveOnly => false,
        BarrierMode::ReDeleteIfRecreated { original_uid } => {
            current_uid.is_some_and(|uid| uid != original_uid)
        }
    }
}

// ── Public result types ──

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
    strip_finalizers: bool,
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
                if let Action::Review { resource, reason } = action {
                    eprintln!("  {}/{}: {}", resource.kind, resource.name, reason);
                }
            }
        }
        bail!("Cannot execute with unresolved REVIEW items. Use --force to override.");
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

    // Collect all plan-level DELETE/EXPECT resource IDs for strip safety checks
    let plan_operand_resources: HashSet<ResourceId> = plan
        .phases
        .iter()
        .flat_map(|p| &p.actions)
        .filter_map(|a| match a {
            Action::Delete { resource, .. } | Action::ExpectGone { resource, .. } => {
                Some(resource.clone())
            }
            _ => None,
        })
        .collect();

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

        let mut phase_wait_targets: Vec<BarrierTarget> = Vec::new();

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
                    phase_wait_targets.push(BarrierTarget {
                        resource: resource.clone(),
                        mode: BarrierMode::ObserveOnly,
                    });
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

                // Eligible DELETEs (excluding blocked APIs)
                let eligible: Vec<_> = delete_actions
                    .iter()
                    .filter(|(r, _)| !api_blocked.contains(&r.name))
                    .collect();
                let eligible_resources: Vec<ResourceId> =
                    eligible.iter().map(|(r, _)| r.clone()).collect();

                // Pre-flight: check if EXPECT targets in this phase have finalizers.
                // If so, serialize root CR deletions to let the controller process
                // finalizers while other root CRs still exist.
                let expect_targets: Vec<&ResourceId> = phase
                    .actions
                    .iter()
                    .filter_map(|a| match a {
                        Action::ExpectGone { resource, .. } => Some(resource),
                        _ => None,
                    })
                    .collect();

                let has_finalized_descendants = if !expect_targets.is_empty()
                    && eligible_resources.len() > 1
                    && phase.barrier.is_some()
                {
                    let expect_owned: Vec<ResourceId> =
                        expect_targets.iter().map(|r| (*r).clone()).collect();
                    let fin_results = check_finalizers_batch(
                        client,
                        &expect_owned,
                        kind_map,
                        gk_map,
                        DEFAULT_CONCURRENCY,
                    )
                    .await;
                    let should_serialize = requires_serialization(&fin_results);
                    if should_serialize {
                        let finalized_count = fin_results
                            .iter()
                            .filter(|(_, r)| matches!(r, FinalizerCheck::KnownFinalizers(_)))
                            .count();
                        let unknown_count = fin_results
                            .iter()
                            .filter(|(_, r)| matches!(r, FinalizerCheck::Unknown(_)))
                            .count();
                        if unknown_count > 0 {
                            eprintln!(
                                "  \x1b[33m⚠ {} EXPECT target(s) have finalizers, {} unknown — serializing root CR deletions conservatively\x1b[0m",
                                finalized_count, unknown_count
                            );
                        } else {
                            eprintln!(
                                "  \x1b[33m⚠ {} EXPECT target(s) have finalizers — serializing root CR deletions\x1b[0m",
                                finalized_count
                            );
                        }
                    }
                    should_serialize
                } else {
                    false
                };

                if has_finalized_descendants {
                    // Collect all EXPECT + WaitGone targets upfront so intermediate
                    // barriers can wait for descendant finalizer processing
                    let all_expect_targets: Vec<BarrierTarget> = phase
                        .actions
                        .iter()
                        .filter_map(|a| match a {
                            Action::ExpectGone { resource, .. } => Some(BarrierTarget {
                                resource: resource.clone(),
                                mode: BarrierMode::ObserveOnly,
                            }),
                            Action::WaitGone { resource } => Some(BarrierTarget {
                                resource: resource.clone(),
                                mode: BarrierMode::ObserveOnly,
                            }),
                            _ => None,
                        })
                        .collect();

                    // Track stalled resource sets to detect repeated stalls:
                    // if consecutive intermediate barriers stall on the same set,
                    // skip remaining barriers (deleting more root CRs won't help)
                    let mut prev_stall_set: Option<HashSet<ResourceId>> = None;
                    let mut skip_repeated_stall = false;

                    // Sequential deletion: delete one root CR at a time, barrier between each
                    for (seq_idx, resource) in eligible_resources.iter().enumerate() {
                        let (s, d, last_err) = execute_delete_batch(
                            client,
                            std::slice::from_ref(resource),
                            kind_map,
                            gk_map,
                            &mut result,
                            None,
                        )
                        .await;

                        // Retry if webhook rejected
                        let mut d = d;
                        let mut last_err = last_err;
                        for attempt in 0..2u64 {
                            if d.is_empty() {
                                break;
                            }
                            let delay = std::time::Duration::from_secs(2 * (attempt + 1));
                            eprintln!("  \x1b[33m⟳ Retrying in {}s...\x1b[0m", delay.as_secs());
                            tokio::time::sleep(delay).await;
                            let (s2, d2, e2) = execute_delete_batch(
                                client,
                                &d,
                                kind_map,
                                gk_map,
                                &mut result,
                                Some(attempt + 1),
                            )
                            .await;
                            phase_wait_targets.extend(s2);
                            d = d2;
                            if e2.is_some() {
                                last_err = e2;
                            }
                        }

                        phase_wait_targets.extend(s);
                        if !d.is_empty() {
                            let err_msg =
                                last_err.unwrap_or_else(|| "failed after retries".to_string());
                            for r in &d {
                                result.failed.push((r.clone(), err_msg.clone()));
                            }
                        }

                        // Intermediate barrier: wait for this root CR AND all EXPECT
                        // descendants before deleting the next root CR.
                        // Skip for the last root CR — main barrier handles it.
                        // Skip if previous barrier stalled on the same set (repeated stall).
                        if seq_idx < eligible_resources.len() - 1 && phase.barrier.is_some() {
                            if skip_repeated_stall {
                                eprintln!(
                                    "\n  \x1b[2m⏭ Skipping intermediate barrier (repeated stall — same resources stalled)\x1b[0m"
                                );
                            } else {
                                let mut inter_wait = phase_wait_targets.clone();
                                for et in &all_expect_targets {
                                    if !inter_wait.iter().any(|t| t.resource == et.resource) {
                                        inter_wait.push(et.clone());
                                    }
                                }
                                if !inter_wait.is_empty() {
                                    eprintln!(
                                        "\n  \x1b[33m⏳ Intermediate barrier: waiting for {}/{} + {} descendants before next root CR\x1b[0m",
                                        resource.kind,
                                        resource.name,
                                        all_expect_targets.len()
                                    );
                                    match wait_for_barrier(
                                        client,
                                        &inter_wait,
                                        kind_map,
                                        gk_map,
                                        300,
                                    )
                                    .await
                                    {
                                        BarrierResult::Passed => {
                                            eprintln!(
                                                "  \x1b[32m✅ Intermediate barrier passed\x1b[0m"
                                            );
                                            phase_wait_targets.clear();
                                            prev_stall_set = None;
                                        }
                                        BarrierResult::Stalled {
                                            remaining,
                                            finalizers,
                                            reason,
                                        } => {
                                            let current_stall: HashSet<ResourceId> = remaining
                                                .iter()
                                                .map(|t| t.resource.clone())
                                                .collect();
                                            if let Some(prev) = &prev_stall_set {
                                                if *prev == current_stall {
                                                    eprintln!(
                                                        "  \x1b[1;33m⚠ Intermediate barrier stalled on same {} resources — skipping remaining intermediate barriers\x1b[0m",
                                                        current_stall.len()
                                                    );
                                                    skip_repeated_stall = true;
                                                } else {
                                                    eprintln!(
                                                        "  \x1b[1;33m⚠ Intermediate barrier stalled ({}) — continuing with next root CR\x1b[0m",
                                                        reason
                                                    );
                                                }
                                            } else {
                                                eprintln!(
                                                    "  \x1b[1;33m⚠ Intermediate barrier stalled ({}) — continuing with next root CR\x1b[0m",
                                                    reason
                                                );
                                            }
                                            prev_stall_set = Some(current_stall);
                                            // Preserve remaining with their original modes
                                            phase_wait_targets = remaining;
                                            for (r, f) in &finalizers {
                                                if !f.is_empty()
                                                    && !phase_wait_targets
                                                        .iter()
                                                        .any(|t| t.resource == *r)
                                                {
                                                    phase_wait_targets.push(BarrierTarget {
                                                        resource: r.clone(),
                                                        mode: BarrierMode::ObserveOnly,
                                                    });
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                } else {
                    // Standard parallel DELETE
                    let (mut succeeded, mut deferred, mut last_err) = execute_delete_batch(
                        client,
                        &eligible_resources,
                        kind_map,
                        gk_map,
                        &mut result,
                        None,
                    )
                    .await;

                    // Quick retry with backoff for webhook ordering races
                    for attempt in 0..2u64 {
                        if deferred.is_empty() {
                            break;
                        }
                        let delay = std::time::Duration::from_secs(2 * (attempt + 1));
                        eprintln!(
                            "  \x1b[33m⟳ Retrying {} failed DELETE(s) in {}s...\x1b[0m",
                            deferred.len(),
                            delay.as_secs()
                        );
                        tokio::time::sleep(delay).await;

                        let (s, d, e) = execute_delete_batch(
                            client,
                            &deferred,
                            kind_map,
                            gk_map,
                            &mut result,
                            Some(attempt + 1),
                        )
                        .await;
                        succeeded.extend(s);
                        deferred = d;
                        if e.is_some() {
                            last_err = e;
                        }
                    }

                    phase_wait_targets.extend(succeeded);
                    if !deferred.is_empty() {
                        let err_msg =
                            last_err.unwrap_or_else(|| "failed after retries".to_string());
                        for r in &deferred {
                            result.failed.push((r.clone(), err_msg.clone()));
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
                    phase_wait_targets.push(BarrierTarget {
                        resource: resource.clone(),
                        mode: BarrierMode::ObserveOnly,
                    });
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
                    phase_wait_targets.push(BarrierTarget {
                        resource: resource.clone(),
                        mode: BarrierMode::ObserveOnly,
                    });
                }
            }
        }

        if phase.barrier.is_some() && !phase_wait_targets.is_empty() {
            if dry_run {
                eprintln!("\n  \x1b[1;33mBARRIER\x1b[0m (skipped in dry-run)");
            } else {
                eprintln!();
                match wait_for_barrier(client, &phase_wait_targets, kind_map, gk_map, 300).await {
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
                        for target in &remaining {
                            let res = &target.resource;
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

                        let stuck_with_finalizers: Vec<_> =
                            finalizers.iter().filter(|(_, f)| !f.is_empty()).collect();

                        if strip_finalizers && !stuck_with_finalizers.is_empty() {
                            eprintln!(
                                "\n  \x1b[1;33m⚠ --strip-finalizers: removing finalizers from {} resource(s)\x1b[0m",
                                stuck_with_finalizers.len()
                            );
                            // Collect observed UIDs for strip safety
                            let km = Arc::new(kind_map.clone());
                            let gk = Arc::new(gk_map.clone());
                            for (res, fins) in &stuck_with_finalizers {
                                // Safety guards
                                if PROTECTED_KINDS.contains(&res.kind.as_str()) {
                                    eprintln!(
                                        "  \x1b[2mSKIPPED\x1b[0m  strip {}/{}: protected resource kind",
                                        res.kind, res.name
                                    );
                                    continue;
                                }
                                if !plan_operand_resources.contains(res) {
                                    eprintln!(
                                        "  \x1b[2mSKIPPED\x1b[0m  strip {}/{}: not in plan DELETE/EXPECT",
                                        res.kind, res.name
                                    );
                                    continue;
                                }

                                // Get observed UID for strip race protection
                                let state_info =
                                    check_resource_state_full(client, res, &km, &gk).await;
                                let is_deleting = matches!(
                                    state_info.state,
                                    ObservationState::Exists {
                                        has_deletion_timestamp: true,
                                        ..
                                    }
                                );
                                if !is_deleting {
                                    eprintln!(
                                        "  \x1b[2mSKIPPED\x1b[0m  strip {}/{}: not in Deleting state",
                                        res.kind, res.name
                                    );
                                    continue;
                                }

                                let observed_uid = match &state_info.uid {
                                    Some(uid) => uid.clone(),
                                    None => {
                                        eprintln!(
                                            "  \x1b[2mSKIPPED\x1b[0m  strip {}/{}: cannot determine UID",
                                            res.kind, res.name
                                        );
                                        continue;
                                    }
                                };

                                match strip_resource_finalizers(
                                    client,
                                    res,
                                    kind_map,
                                    gk_map,
                                    &observed_uid,
                                    fins,
                                )
                                .await
                                {
                                    Ok(()) => {
                                        eprintln!(
                                            "  \x1b[33mSTRIPPED\x1b[0m {}/{} (was: [{}])",
                                            res.kind,
                                            res.name,
                                            fins.join(", ")
                                        );
                                    }
                                    Err(e) => {
                                        eprintln!(
                                            "  \x1b[1;31mFAILED\x1b[0m   strip {}/{}: {}",
                                            res.kind, res.name, e
                                        );
                                    }
                                }
                            }
                            eprintln!(
                                "  \x1b[33m⟳ Re-entering barrier after finalizer strip...\x1b[0m\n"
                            );
                            // Re-enter barrier — remaining already carries modes
                            match wait_for_barrier(client, &remaining, kind_map, gk_map, 120).await
                            {
                                BarrierResult::Passed => {
                                    eprintln!(
                                        "  \x1b[32m✅ Barrier passed (after finalizer strip)\x1b[0m"
                                    );
                                }
                                BarrierResult::Stalled {
                                    remaining: remaining2,
                                    finalizers: finalizers2,
                                    reason: reason2,
                                } => {
                                    eprintln!(
                                        "  \x1b[1;31m⚠ Barrier still stalled after strip — {} resources remain ({})\x1b[0m",
                                        remaining2.len(),
                                        reason2
                                    );
                                    result.barrier_timeout = Some(BarrierTimeout {
                                        phase: phase.name.clone(),
                                        remaining: remaining2
                                            .iter()
                                            .map(|t| t.resource.clone())
                                            .collect(),
                                        finalizers: finalizers2,
                                    });
                                    break;
                                }
                            }
                        } else {
                            if !stuck_with_finalizers.is_empty() && !strip_finalizers {
                                eprintln!(
                                    "\n  \x1b[2mHint: use --strip-finalizers to remove finalizers and continue\x1b[0m"
                                );
                            }
                            result.barrier_timeout = Some(BarrierTimeout {
                                phase: phase.name.clone(),
                                remaining: remaining.iter().map(|t| t.resource.clone()).collect(),
                                finalizers,
                            });
                            break;
                        }
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
                let review_resources: Vec<ResourceId> = plan
                    .phases
                    .iter()
                    .flat_map(|p| &p.actions)
                    .filter_map(|a| match a {
                        Action::Review { resource, .. } => Some(resource.clone()),
                        _ => None,
                    })
                    .collect();
                let fin_results = check_finalizers_batch(
                    client,
                    &review_resources,
                    kind_map,
                    gk_map,
                    DEFAULT_CONCURRENCY,
                )
                .await;

                let mut block_reasons = Vec::new();
                for (res, fin_result) in fin_results {
                    match fin_result {
                        FinalizerCheck::KnownFinalizers(fins) => {
                            block_reasons.push((res, fins));
                        }
                        FinalizerCheck::Unknown(err) => {
                            block_reasons.push((res, vec![format!("check failed: {}", err)]));
                        }
                        FinalizerCheck::KnownEmpty => {}
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
    }

    Ok(result)
}

// ── Delete batch: returns BarrierTargets for succeeded, ResourceIds for deferred ──

async fn execute_delete_batch(
    client: &Client,
    targets: &[ResourceId],
    kind_map: &KindMap,
    gk_map: &GroupKindMap,
    result: &mut ExecutionResult,
    retry_num: Option<u64>,
) -> (Vec<BarrierTarget>, Vec<ResourceId>, Option<String>) {
    let km = Arc::new(kind_map.clone());
    let gk = Arc::new(gk_map.clone());
    let del_futs = targets.iter().map(|resource| {
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

    let retry_suffix = match retry_num {
        Some(n) => format!(" (retry {})", n),
        None => String::new(),
    };

    let mut succeeded = Vec::new();
    let mut deferred = Vec::new();
    let mut last_error: Option<String> = None;

    for (resource, del_result) in del_results {
        match del_result {
            DeleteResult::Deleted { uid } => {
                eprintln!(
                    "  \x1b[31mDELETED\x1b[0m  {}/{}{}{}",
                    resource.kind,
                    resource.name,
                    retry_suffix,
                    scope_suffix(&resource)
                );
                result.deleted.push(resource.clone());
                succeeded.push(BarrierTarget {
                    resource,
                    mode: BarrierMode::ReDeleteIfRecreated { original_uid: uid },
                });
            }
            DeleteResult::AlreadyGone => {
                eprintln!(
                    "  \x1b[2mSKIPPED\x1b[0m  {}/{} (already gone){}",
                    resource.kind,
                    resource.name,
                    scope_suffix(&resource)
                );
                result.already_gone.push(resource);
            }
            DeleteResult::Failed(err) => {
                eprintln!(
                    "  \x1b[1;31mFAILED\x1b[0m   {}/{}: {}{}{}",
                    resource.kind,
                    resource.name,
                    err,
                    retry_suffix,
                    scope_suffix(&resource)
                );
                last_error = Some(err);
                deferred.push(resource);
            }
        }
    }

    (succeeded, deferred, last_error)
}

// ── UID-bound DELETE: GET → resolve UID → preconditioned DELETE ──

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

    // Fail-closed: GET current UID before DELETE
    let current_uid = match api.get(&resource.name).await {
        Ok(obj) => match obj.metadata.uid {
            Some(uid) => uid,
            None => {
                return DeleteResult::Failed(format!(
                    "cannot resolve UID for {}/{}",
                    resource.kind, resource.name
                ));
            }
        },
        Err(kube::Error::Api(err)) if err.code == 404 => {
            return DeleteResult::AlreadyGone;
        }
        Err(e) => {
            return DeleteResult::Failed(format!(
                "GET failed for {}/{}: {}",
                resource.kind, resource.name, e
            ));
        }
    };

    // UID-preconditioned DELETE
    let dp = DeleteParams {
        preconditions: Some(kube::api::Preconditions {
            uid: Some(current_uid.clone()),
            resource_version: None,
        }),
        ..Default::default()
    };

    match api.delete(&resource.name, &dp).await {
        Ok(_) => DeleteResult::Deleted { uid: current_uid },
        Err(kube::Error::Api(err)) if err.code == 404 => DeleteResult::AlreadyGone,
        Err(e) => DeleteResult::Failed(e.to_string()),
    }
}

// ── Barrier ──

enum BarrierResult {
    Passed,
    Stalled {
        remaining: Vec<BarrierTarget>,
        finalizers: Vec<(ResourceId, Vec<String>)>,
        reason: String,
    },
}

struct ResourceStateInfo {
    state: ObservationState,
    finalizers: Vec<String>,
    uid: Option<String>,
}

async fn strip_resource_finalizers(
    client: &Client,
    resource: &ResourceId,
    kind_map: &KindMap,
    gk_map: &GroupKindMap,
    observed_uid: &str,
    observed_finalizers: &[String],
) -> Result<()> {
    let (api, _) = resolve_api(client, resource, kind_map, gk_map).ok_or_else(|| {
        anyhow::anyhow!("cannot resolve API for {}/{}", resource.kind, resource.name)
    })?;

    // Atomic compare-and-swap via JSON Patch test operations:
    // verify UID and finalizer set haven't changed before stripping.
    // If either changed (recreation or concurrent finalizer addition),
    // the patch itself fails at the API server level — no TOCTOU race.
    let patch_value = serde_json::json!([
        { "op": "test", "path": "/metadata/uid", "value": observed_uid },
        { "op": "test", "path": "/metadata/finalizers", "value": observed_finalizers },
        { "op": "replace", "path": "/metadata/finalizers", "value": [] }
    ]);
    let json_patch: kube::core::params::Patch<serde_json::Value> =
        Patch::Json(serde_json::from_value(patch_value)?);
    api.patch(&resource.name, &PatchParams::default(), &json_patch)
        .await?;
    Ok(())
}

async fn check_resource_state_full(
    client: &Client,
    resource: &ResourceId,
    kind_map: &KindMap,
    gk_map: &GroupKindMap,
) -> ResourceStateInfo {
    let (api, _) = match resolve_api(client, resource, kind_map, gk_map) {
        Some(r) => r,
        None => {
            return ResourceStateInfo {
                state: ObservationState::Unknown(format!(
                    "cannot resolve API for {}/{}",
                    resource.kind, resource.name
                )),
                finalizers: vec![],
                uid: None,
            };
        }
    };

    match api.get(&resource.name).await {
        Ok(obj) => {
            let finalizers = obj.metadata.finalizers.clone().unwrap_or_default();
            let has_dt = obj.metadata.deletion_timestamp.is_some();
            let uid = obj.metadata.uid.clone();
            ResourceStateInfo {
                state: ObservationState::Exists {
                    finalizer_count: finalizers.len(),
                    has_deletion_timestamp: has_dt,
                },
                finalizers,
                uid,
            }
        }
        Err(kube::Error::Api(err)) if err.code == 404 => ResourceStateInfo {
            state: ObservationState::Gone,
            finalizers: vec![],
            uid: None,
        },
        Err(e) => ResourceStateInfo {
            state: ObservationState::Unknown(format!("GET failed: {}", e)),
            finalizers: vec![],
            uid: None,
        },
    }
}

async fn wait_for_barrier(
    client: &Client,
    targets: &[BarrierTarget],
    kind_map: &KindMap,
    gk_map: &GroupKindMap,
    timeout_secs: u64,
) -> BarrierResult {
    let start = Instant::now();
    let total = targets.len();

    let mut prev_gone = 0usize;
    let mut prev_total_finalizers = usize::MAX;
    let mut last_progress = Instant::now();
    let stall_threshold_secs = 120;
    let mut consecutive_unknown_cycles = 0u32;
    const MAX_UNKNOWN_RETRIES: u32 = 3;

    let kind_map = Arc::new(kind_map.clone());
    let gk_map = Arc::new(gk_map.clone());

    loop {
        let elapsed = start.elapsed().as_secs();

        // Parallel state check — carry BarrierTarget through the future
        // so completion order from buffer_unordered cannot misattribute modes
        let check_futs = targets.iter().cloned().map(|target| {
            let client = client.clone();
            let km = kind_map.clone();
            let gk = gk_map.clone();
            async move {
                let info = check_resource_state_full(&client, &target.resource, &km, &gk).await;
                (target, info)
            }
        });

        let states: Vec<(BarrierTarget, ResourceStateInfo)> = futures::stream::iter(check_futs)
            .buffer_unordered(DEFAULT_CONCURRENCY)
            .collect()
            .await;

        let mut gone_count = 0;
        let mut unknown_count = 0;
        let mut deleting_count = 0;
        let mut total_finalizers = 0;
        let mut remaining: Vec<BarrierTarget> = Vec::new();
        let mut remaining_finalizers = Vec::new();
        let mut unknown_reasons = Vec::new();

        for (target, info) in &states {
            let res = &target.resource;
            match &info.state {
                ObservationState::Gone => {
                    gone_count += 1;
                }
                ObservationState::Exists {
                    finalizer_count,
                    has_deletion_timestamp,
                } => {
                    remaining.push(target.clone());
                    total_finalizers += finalizer_count;
                    if *has_deletion_timestamp {
                        deleting_count += 1;
                    }
                    if !info.finalizers.is_empty() {
                        remaining_finalizers.push((res.clone(), info.finalizers.clone()));
                    }
                }
                ObservationState::Unknown(reason) => {
                    unknown_count += 1;
                    remaining.push(target.clone());
                    unknown_reasons.push(format!("{}/{}: {}", res.kind, res.name, reason));
                }
            }
        }

        if unknown_count > 0 {
            consecutive_unknown_cycles += 1;
            if consecutive_unknown_cycles >= MAX_UNKNOWN_RETRIES {
                eprintln!();
                return BarrierResult::Stalled {
                    remaining,
                    finalizers: remaining_finalizers,
                    reason: format!(
                        "{} resource(s) could not be observed after {} retries: {}",
                        unknown_count,
                        MAX_UNKNOWN_RETRIES,
                        unknown_reasons.first().unwrap_or(&String::new())
                    ),
                };
            }
            eprint!(
                "\r\x1b[2K  ⚠ {} resource(s) unknown (retry {}/{}), waiting...",
                unknown_count, consecutive_unknown_cycles, MAX_UNKNOWN_RETRIES
            );
            std::io::stderr().flush().ok();
            tokio::time::sleep(std::time::Duration::from_secs(5)).await;
            continue;
        }
        consecutive_unknown_cycles = 0;

        // Re-DELETE only resources authorized via ReDeleteIfRecreated and
        // confirmed to have a different UID (recreated by controller)
        let mut redeleted = false;
        for (target, info) in &states {
            let res = &target.resource;
            let has_dt = matches!(
                info.state,
                ObservationState::Exists {
                    has_deletion_timestamp: true,
                    ..
                }
            );
            let current_uid = info.uid.as_deref();
            if should_redelete(target, current_uid, has_dt) {
                let original_uid = match &target.mode {
                    BarrierMode::ReDeleteIfRecreated { original_uid } => original_uid.as_str(),
                    _ => continue,
                };
                // Re-DELETE with current UID precondition
                if let Some(cur_uid) = current_uid {
                    let (api, _) = match resolve_api(client, res, &kind_map, &gk_map) {
                        Some(r) => r,
                        None => continue,
                    };
                    let dp = DeleteParams {
                        preconditions: Some(kube::api::Preconditions {
                            uid: Some(cur_uid.to_string()),
                            resource_version: None,
                        }),
                        ..Default::default()
                    };
                    match api.delete(&res.name, &dp).await {
                        Ok(_) => {
                            eprint!(
                                "\r\x1b[2K  \x1b[33m♻ RE-DELETE\x1b[0m {}/{} (recreated: uid {}→{})\n",
                                res.kind,
                                res.name,
                                &original_uid[..8.min(original_uid.len())],
                                &cur_uid[..8.min(cur_uid.len())]
                            );
                            redeleted = true;
                        }
                        Err(kube::Error::Api(err)) if err.code == 404 => {}
                        Err(err) => {
                            eprint!(
                                "\r\x1b[2K  \x1b[2m♻ re-delete {}/{} failed: {}\x1b[0m\n",
                                res.kind, res.name, err
                            );
                        }
                    }
                }
            }
        }
        if redeleted {
            std::io::stderr().flush().ok();
        }

        // re-DELETE is NOT progress — stall timer must not reset from it
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

    // FinalizerCheck (shared helper) regression: Unknown is distinguishable
    #[test]
    fn finalizer_check_unknown_is_not_empty_known() {
        use crate::teardown::finalizers::FinalizerCheck;
        let result = FinalizerCheck::Unknown("resolve failed".to_string());
        assert!(matches!(result, FinalizerCheck::Unknown(_)));
        let empty = FinalizerCheck::KnownEmpty;
        assert!(matches!(empty, FinalizerCheck::KnownEmpty));
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

    // ResourceStateInfo carries finalizers and UID in single GET
    #[test]
    fn resource_state_info_carries_finalizers() {
        let info = ResourceStateInfo {
            state: ObservationState::Exists {
                finalizer_count: 2,
                has_deletion_timestamp: false,
            },
            finalizers: vec!["a".to_string(), "b".to_string()],
            uid: Some("test-uid".to_string()),
        };
        assert_eq!(info.finalizers.len(), 2);
        assert_eq!(info.uid.as_deref(), Some("test-uid"));
        assert!(matches!(
            info.state,
            ObservationState::Exists {
                finalizer_count: 2,
                ..
            }
        ));
    }

    // ── should_redelete state machine tests ──

    #[test]
    fn expect_target_is_never_redeleted() {
        let target = BarrierTarget {
            resource: make_resource("Pod", "a"),
            mode: BarrierMode::ObserveOnly,
        };
        assert!(!should_redelete(&target, Some("uid-B"), false));
        assert!(!should_redelete(&target, Some("uid-B"), true));
        assert!(!should_redelete(&target, None, false));
    }

    #[test]
    fn explicit_delete_recreated_with_new_uid_is_redeleted() {
        let target = BarrierTarget {
            resource: make_resource("Pod", "a"),
            mode: BarrierMode::ReDeleteIfRecreated {
                original_uid: "uid-A".to_string(),
            },
        };
        assert!(should_redelete(&target, Some("uid-B"), false));
    }

    #[test]
    fn same_uid_without_deletion_timestamp_is_not_redeleted() {
        let target = BarrierTarget {
            resource: make_resource("Pod", "a"),
            mode: BarrierMode::ReDeleteIfRecreated {
                original_uid: "uid-A".to_string(),
            },
        };
        assert!(!should_redelete(&target, Some("uid-A"), false));
    }

    #[test]
    fn recreated_new_uid_already_deleting_is_not_redeleted() {
        let target = BarrierTarget {
            resource: make_resource("Pod", "a"),
            mode: BarrierMode::ReDeleteIfRecreated {
                original_uid: "uid-A".to_string(),
            },
        };
        // New UID but already being deleted → just wait
        assert!(!should_redelete(&target, Some("uid-B"), true));
    }

    #[test]
    fn redelete_with_unknown_uid_is_safe() {
        let target = BarrierTarget {
            resource: make_resource("Pod", "a"),
            mode: BarrierMode::ReDeleteIfRecreated {
                original_uid: "uid-A".to_string(),
            },
        };
        // UID unknown → safe side, don't re-delete
        assert!(!should_redelete(&target, None, false));
    }

    #[test]
    fn redelete_does_not_apply_to_observe_only() {
        // Even with mismatched UIDs, ObserveOnly never re-deletes
        let target = BarrierTarget {
            resource: make_resource("Pod", "a"),
            mode: BarrierMode::ObserveOnly,
        };
        assert!(!should_redelete(&target, Some("different-uid"), false));
    }

    // ── BarrierTarget construction invariants ──

    #[test]
    fn barrier_target_from_delete_success_is_redelete_mode() {
        let res = make_resource("Pod", "a");
        let target = BarrierTarget {
            resource: res.clone(),
            mode: BarrierMode::ReDeleteIfRecreated {
                original_uid: "uid-A".to_string(),
            },
        };
        assert!(matches!(
            target.mode,
            BarrierMode::ReDeleteIfRecreated { .. }
        ));
    }

    #[test]
    fn barrier_target_from_expect_is_observe_only() {
        let res = make_resource("Pod", "a");
        let target = BarrierTarget {
            resource: res,
            mode: BarrierMode::ObserveOnly,
        };
        assert!(matches!(target.mode, BarrierMode::ObserveOnly));
    }

    // Protected kinds are not stripped
    #[test]
    fn protected_kinds_includes_critical_resources() {
        assert!(PROTECTED_KINDS.contains(&"CustomResourceDefinition"));
        assert!(PROTECTED_KINDS.contains(&"Namespace"));
        assert!(PROTECTED_KINDS.contains(&"PersistentVolume"));
        assert!(PROTECTED_KINDS.contains(&"PersistentVolumeClaim"));
        assert!(PROTECTED_KINDS.contains(&"Node"));
        assert!(!PROTECTED_KINDS.contains(&"Dashboard"));
    }

    // OLM/API infrastructure kinds are also protected from strip
    #[test]
    fn protected_kinds_includes_olm_infrastructure() {
        assert!(PROTECTED_KINDS.contains(&"Subscription"));
        assert!(PROTECTED_KINDS.contains(&"ClusterServiceVersion"));
        assert!(PROTECTED_KINDS.contains(&"APIService"));
        assert!(PROTECTED_KINDS.contains(&"OperatorGroup"));
    }

    // buffer_unordered completion order cannot misattribute barrier modes
    #[test]
    fn unordered_barrier_results_preserve_target_mode() {
        let target_a = BarrierTarget {
            resource: make_resource("Auth", "auth"),
            mode: BarrierMode::ReDeleteIfRecreated {
                original_uid: "uid-a".to_string(),
            },
        };
        let target_b = BarrierTarget {
            resource: make_resource("Ray", "default-ray"),
            mode: BarrierMode::ObserveOnly,
        };

        // Simulate buffer_unordered returning results in reversed order
        let results_reversed = vec![
            (target_b.clone(), "uid-b-new".to_string(), false),
            (target_a.clone(), "uid-a-new".to_string(), false),
        ];

        for (target, uid, has_dt) in &results_reversed {
            let should = should_redelete(target, Some(uid.as_str()), *has_dt);
            match &target.mode {
                BarrierMode::ObserveOnly => {
                    assert!(!should, "ObserveOnly must never re-delete");
                }
                BarrierMode::ReDeleteIfRecreated { original_uid } => {
                    // uid changed, so re-delete is correct for this target
                    assert!(uid != original_uid);
                    assert!(should, "ReDelete with changed UID should re-delete");
                }
            }
        }
    }
}
