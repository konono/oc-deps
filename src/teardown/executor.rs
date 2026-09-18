use std::collections::HashSet;
use std::io::Write;
use std::sync::Arc;
use std::time::Instant;

use anyhow::{Result, bail};
use futures::stream::StreamExt;
use kube::{
    Client,
    api::{Api, ApiResource, DeleteParams, DynamicObject, ListParams},
    core::GroupVersion,
};

use crate::kube::discovery::{GroupKindMap, GvrMap, KindMap};
use crate::kube::resource::{ResourceId, resolve_api};
use crate::teardown::planner::{Action, PreflightSeverity, TeardownPlan};

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

pub async fn execute_plan(
    client: &Client,
    plan: &TeardownPlan,
    kind_map: &KindMap,
    gk_map: &GroupKindMap,
    gvr_map: &GvrMap,
    dry_run: bool,
    force: bool,
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
                // CRD live count checks (must be sequential per CRD for safety)
                let mut crd_blocked: HashSet<String> = HashSet::new();
                for (resource, _) in &delete_actions {
                    if resource.kind == "CustomResourceDefinition" {
                        let live =
                            count_live_cr_instances(client, &resource.name, kind_map, gvr_map)
                                .await;
                        match live {
                            LiveCount::NonZero(n) => {
                                eprintln!(
                                    "  \x1b[1;31m⛔ BLOCKED\x1b[0m {}/{}{}",
                                    resource.kind,
                                    resource.name,
                                    scope_suffix(resource)
                                );
                                eprintln!("             {} live CR instances remain — skipping", n);
                                result.failed.push((
                                    resource.clone(),
                                    format!("{} live CR instances remain", n),
                                ));
                                crd_blocked.insert(resource.name.clone());
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
                                crd_blocked.insert(resource.name.clone());
                            }
                            LiveCount::Zero => {}
                        }
                    }
                }

                // Parallel DELETE (excluding blocked CRDs)
                let eligible: Vec<_> = delete_actions
                    .iter()
                    .filter(|(r, _)| {
                        !(r.kind == "CustomResourceDefinition" && crd_blocked.contains(&r.name))
                    })
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
    }

    Ok(result)
}

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

struct ResourceStateInfo {
    state: ObservationState,
    finalizers: Vec<String>,
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
            };
        }
    };

    match api.get(&resource.name).await {
        Ok(obj) => {
            let finalizers = obj.metadata.finalizers.clone().unwrap_or_default();
            let has_dt = obj.metadata.deletion_timestamp.is_some();
            ResourceStateInfo {
                state: ObservationState::Exists {
                    finalizer_count: finalizers.len(),
                    has_deletion_timestamp: has_dt,
                },
                finalizers,
            }
        }
        Err(kube::Error::Api(err)) if err.code == 404 => ResourceStateInfo {
            state: ObservationState::Gone,
            finalizers: vec![],
        },
        Err(e) => ResourceStateInfo {
            state: ObservationState::Unknown(format!("GET failed: {}", e)),
            finalizers: vec![],
        },
    }
}

async fn wait_for_barrier(
    client: &Client,
    resources: &[ResourceId],
    kind_map: &KindMap,
    gk_map: &GroupKindMap,
    timeout_secs: u64,
) -> BarrierResult {
    let start = Instant::now();
    let total = resources.len();

    let mut prev_gone = 0usize;
    let mut prev_total_finalizers = usize::MAX;
    let mut last_progress = Instant::now();
    let stall_threshold_secs = 120;

    let kind_map = Arc::new(kind_map.clone());
    let gk_map = Arc::new(gk_map.clone());

    loop {
        let elapsed = start.elapsed().as_secs();

        // Parallel state check for all resources — single GET per resource
        let check_futs = resources.iter().map(|res| {
            let client = client.clone();
            let res = res.clone();
            let km = kind_map.clone();
            let gk = gk_map.clone();
            async move {
                let r = check_resource_state_full(&client, &res, &km, &gk).await;
                (res, r)
            }
        });

        let states: Vec<_> = futures::stream::iter(check_futs)
            .buffer_unordered(DEFAULT_CONCURRENCY)
            .collect()
            .await;

        let mut gone_count = 0;
        let mut unknown_count = 0;
        let mut deleting_count = 0;
        let mut total_finalizers = 0;
        let mut remaining = Vec::new();
        let mut remaining_finalizers = Vec::new();
        let mut unknown_reasons = Vec::new();

        for (res, info) in &states {
            match &info.state {
                ObservationState::Gone => {
                    gone_count += 1;
                }
                ObservationState::Exists {
                    finalizer_count,
                    has_deletion_timestamp,
                } => {
                    remaining.push(res.clone());
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
                    remaining.push(res.clone());
                    unknown_reasons.push(format!("{}/{}: {}", res.kind, res.name, reason));
                }
            }
        }

        if unknown_count > 0 {
            eprintln!();
            return BarrierResult::Stalled {
                remaining,
                finalizers: remaining_finalizers,
                reason: format!(
                    "{} resource(s) could not be observed: {}",
                    unknown_count,
                    unknown_reasons.join("; ")
                ),
            };
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
        Err(kube::Error::Api(err)) if err.code == 404 => FinalizerCheckResult::Gone,
        Err(e) => FinalizerCheckResult::Unknown(format!("GET failed: {}", e)),
    }
}

// P0-3: verify no live CR instances exist before CRD deletion
async fn count_live_cr_instances(
    client: &Client,
    crd_name: &str,
    kind_map: &KindMap,
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

    let kind_info = match kind_map.get(&kind) {
        Some(i) => i,
        None => return LiveCount::Unknown(format!("no KindInfo for {}", kind)),
    };

    let gvk = GroupVersion::gv(&kind_info.group, &kind_info.version).with_kind(&kind);
    let ar = ApiResource::from_gvk_with_plural(&gvk, &kind_info.plural);
    let api: Api<DynamicObject> = Api::all_with(client.clone(), &ar);

    match api.list(&ListParams::default().limit(1)).await {
        Ok(list) => {
            let count = list.items.len();
            if count == 0 {
                LiveCount::Zero
            } else {
                // There may be more — list with limit=1 just tells us non-empty
                match api.list(&ListParams::default()).await {
                    Ok(full) => {
                        if full.items.is_empty() {
                            LiveCount::Zero
                        } else {
                            LiveCount::NonZero(full.items.len())
                        }
                    }
                    Err(e) => LiveCount::Unknown(format!("full list failed: {}", e)),
                }
            }
        }
        Err(e) => LiveCount::Unknown(format!("list failed: {}", e)),
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

    // P0-adjacent regression: FinalizerCheckResult::Unknown is distinguishable
    #[test]
    fn finalizer_check_unknown_is_not_empty_known() {
        let result = FinalizerCheckResult::Unknown("resolve failed".to_string());
        assert!(matches!(result, FinalizerCheckResult::Unknown(_)));
        // Known with empty vec is a different state
        let empty = FinalizerCheckResult::Known(vec![]);
        assert!(matches!(empty, FinalizerCheckResult::Known(ref v) if v.is_empty()));
    }
}
