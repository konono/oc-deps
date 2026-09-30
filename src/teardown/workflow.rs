use std::sync::Arc;

use anyhow::{Context, bail};

use crate::kube::discovery::{GroupKindMap, GvkMap, GvrMap, KindMap};
use crate::teardown::audit::{self, OperatorGenerationState};
use crate::teardown::executor::{self, ExecutionResult, print_execution_result};
use crate::teardown::journal::{self, CleanupResult, JournalStore, RunState};
use crate::teardown::permit::MutationGate;
use crate::teardown::planner::TeardownPlan;

pub struct WorkflowContext<'a> {
    pub client: &'a kube::Client,
    pub plan: &'a TeardownPlan,
    pub kind_map: &'a KindMap,
    pub gk_map: &'a GroupKindMap,
    pub gvk_map: &'a GvkMap,
    pub gvr_map: &'a GvrMap,
}

pub struct WorkflowOptions {
    pub dry_run: bool,
    /// Suppress preflight/REVIEW warnings. Fresh=false, Resume=true.
    pub force: bool,
    pub skip_confirm: bool,
    pub start_phase: usize,
}

pub struct WorkflowOutcome {
    pub final_state: RunState,
    pub result: ExecutionResult,
    pub cleanup_failure: Option<String>,
}

/// Single production entry point for the execute → state → audit → cleanup pipeline.
///
/// Both fresh apply and resume call this after their respective preparation
/// (validation, backup, journal creation/lock). The MutationGate and Ctrl-C
/// handler are set up by the caller and passed in.
///
/// Stages:
/// 1. execute_plan — single call site
/// 2. Final state determination (Paused / ApplyCompleted / Failed)
/// 3. Persist final state to journal
/// 4. Post-execution audit (if ApplyCompleted + operator Absent)
/// 5. Auto residual cleanup (if audit found actionable residuals)
/// 6. Return outcome
pub async fn run_teardown_workflow(
    ctx: &WorkflowContext<'_>,
    journal_store: Option<&Arc<JournalStore>>,
    gate: &Arc<MutationGate>,
    options: &WorkflowOptions,
) -> anyhow::Result<WorkflowOutcome> {
    let exec_result = executor::execute_plan(
        ctx.client,
        ctx.plan,
        ctx.kind_map,
        ctx.gk_map,
        ctx.gvk_map,
        ctx.gvr_map,
        options.dry_run,
        options.force,
        journal_store.map(|s| s.as_ref() as &JournalStore),
        Some(gate.as_ref()),
        options.start_phase,
        options.skip_confirm,
    )
    .await;

    match exec_result {
        Ok(result) => {
            let final_state = determine_final_state(&result, gate);

            if let Some(store) = journal_store {
                store
                    .update(|j| {
                        j.state = final_state.clone();
                        j.execution.phases_total = result.phases_total;
                    })
                    .await
                    .context("Failed to persist final execution state")?;
            }

            if final_state == RunState::Paused {
                eprintln!(
                    "\n⏸ Paused at phase {}/{}. Use 'teardown resume' to continue.",
                    result.phases_completed, result.phases_total
                );
            }

            print_execution_result(&result);

            let cleanup_failure = if let Some(store) = journal_store
                && !options.dry_run
                && final_state == RunState::ApplyCompleted
            {
                run_post_execution_audit(ctx, store, gate).await
            } else {
                None
            };

            Ok(WorkflowOutcome {
                final_state,
                result,
                cleanup_failure,
            })
        }
        Err(e) => {
            if let Some(store) = journal_store
                && store
                    .update(|j| {
                        journal::mark_failed_preserving_retryable(j);
                    })
                    .await
                    .is_err()
            {
                eprintln!("⚠ Additionally, failed to persist Failed state to journal");
            }
            Err(e)
        }
    }
}

fn determine_final_state(result: &ExecutionResult, gate: &MutationGate) -> RunState {
    if !gate.is_open() {
        RunState::Paused
    } else if result.failed.is_empty()
        && result.barrier_timeout.is_none()
        && result.phases_completed == result.phases_total
    {
        RunState::ApplyCompleted
    } else {
        RunState::Failed
    }
}

async fn run_post_execution_audit(
    ctx: &WorkflowContext<'_>,
    store: &Arc<JournalStore>,
    gate: &MutationGate,
) -> Option<String> {
    let j = store.read().await;
    let gen_state = audit::check_operator_generation_fresh(
        ctx.client,
        &j.operator,
        &j.audit_context.csv_baseline,
    )
    .await;

    match gen_state {
        OperatorGenerationState::Absent => {
            eprintln!("\n🔍 Running post-execution residual audit...");
            match audit::run_post_mutation_audit(ctx.client, &j).await {
                Ok(audit_result) => {
                    let status = audit::residual_status_from_audit(&audit_result);
                    audit::print_residual_audit(&audit_result, &j);

                    let auto_candidates =
                        executor::auto_cleanup_candidates(&audit_result, &j.execution.deleted);

                    let gen_recheck = audit::check_operator_generation_fresh(
                        ctx.client,
                        &j.operator,
                        &j.audit_context.csv_baseline,
                    )
                    .await;

                    if !matches!(gen_recheck, OperatorGenerationState::Absent) {
                        eprintln!("⚠ Operator generation changed during audit; discarding results");
                        return Some("Operator generation changed during audit".to_string());
                    }

                    match store
                        .update(|j| {
                            j.residual_status = status;
                            j.audit_revision += 1;
                            j.last_residual_audit = Some(audit_result.clone());
                        })
                        .await
                    {
                        Ok(()) => {
                            if matches!(
                                audit::residual_status_from_audit(&audit_result),
                                journal::ResidualStatus::AuditIncomplete
                            ) {
                                return Some("Residual audit incomplete".to_string());
                            }

                            if !auto_candidates.is_empty() {
                                eprintln!(
                                    "\n🧹 Cleaning {} planned residual(s)...",
                                    auto_candidates.len()
                                );
                                match executor::execute_residual_cleanup(
                                    ctx.client,
                                    &auto_candidates,
                                    store.as_ref(),
                                    gate,
                                    ctx.kind_map,
                                    ctx.gk_map,
                                )
                                .await
                                {
                                    Ok(cleanup) => {
                                        eprintln!(
                                            "  {} Gone, {} skipped, {} failed",
                                            cleanup.deleted.len(),
                                            cleanup.skipped.len(),
                                            cleanup.failed.len()
                                        );
                                        if !cleanup.skipped.is_empty() || !cleanup.failed.is_empty()
                                        {
                                            return Some("Residual cleanup incomplete".to_string());
                                        }
                                        if let Some(post) = cleanup.post_audit
                                            && (!post.planned_delete_still_present.is_empty()
                                                || !post.planned_expect_still_present.is_empty())
                                        {
                                            return Some(format!(
                                                "{} planned DELETE/EXPECT resources remain after cleanup",
                                                post.planned_delete_still_present.len()
                                                    + post.planned_expect_still_present.len()
                                            ));
                                        }
                                    }
                                    Err(e) => {
                                        return Some(format!("Residual cleanup failed: {:#}", e));
                                    }
                                }
                            }

                            None
                        }
                        Err(e) => {
                            eprintln!("⚠ Failed to persist audit results: {}", e);
                            Some(format!("Residual audit persistence failed: {}", e))
                        }
                    }
                }
                Err(e) => {
                    eprintln!("⚠ Post-execution residual audit failed: {}", e);
                    Some(format!("Post-execution residual audit failed: {}", e))
                }
            }
        }
        _ => {
            eprintln!("\nSkipping post-execution residual audit: operator generation not absent");
            Some("Operator generation not absent".to_string())
        }
    }
}

/// Resume cleanup stage — handles pending cleanup decisions from a prior run.
/// This is a workflow stage, not a standalone function — it uses the same
/// MutationGate and journal authority as run_teardown_workflow.
pub async fn run_resume_cleanup(
    ctx: &WorkflowContext<'_>,
    store: &Arc<JournalStore>,
    gate: &Arc<MutationGate>,
    j: &journal::RunJournal,
    main_complete: bool,
    paused_from_residual: bool,
) -> anyhow::Result<()> {
    // Schema gate: v5 journals cannot gain resume authority
    if j.schema_version != journal::RUN_JOURNAL_SCHEMA_VERSION {
        bail!(
            "Journal schema v{} does not match current v{}. \
                     Cannot resume cleanup on incompatible journal.",
            j.schema_version,
            journal::RUN_JOURNAL_SCHEMA_VERSION
        );
    }

    if j.cleanup_decisions.iter().any(|d| d.is_hard_failed()) {
        store
            .update(|j| {
                j.state = RunState::Failed;
            })
            .await?;
        bail!(
            "Journal contains hard-failed cleanup decisions from a prior run. \
                     Cannot resume — create a new teardown plan."
        );
    }

    // Write InteractiveCleanup state for crash safety
    if j.state != RunState::InteractiveCleanup {
        store
            .update(|j| {
                j.state = RunState::InteractiveCleanup;
            })
            .await?;
    }
    let pending: Vec<journal::CleanupDecision> = j
        .cleanup_decisions
        .iter()
        .filter(|d| d.is_pending())
        .cloned()
        .collect();

    let mut any_hard_failed = false;
    let mut any_retryable = false;
    let is_residual_reentry = paused_from_residual
        || (j.state == RunState::ApplyCompleted && main_complete)
        || (j.state == RunState::InteractiveCleanup && main_complete);

    if pending.is_empty() {
        if is_residual_reentry {
            eprintln!("Resuming Residual Cleanup stage.");
            let gen_check = audit::check_operator_generation_fresh(
                ctx.client,
                &j.operator,
                &j.audit_context.csv_baseline,
            )
            .await;
            if !matches!(gen_check, OperatorGenerationState::Absent) {
                bail!(
                    "Operator generation not Absent on Residual resume — \
                               create a new teardown plan."
                );
            }
        } else {
            eprintln!("No pending cleanup decisions to resume.");
        }
    } else {
        eprintln!("Resuming {} pending cleanup decision(s)...", pending.len());
        for decision in &pending {
            if crate::teardown::runtime::persist_paused_if_closed(store, gate).await? {
                eprintln!("⏸ Gate closed — stopping cleanup resume");
                break;
            }

            // Handle delete_requested: DELETE was sent but Gone
            // was not confirmed. Reconcile via live GET — do NOT
            // re-send DELETE (authority already used).
            if matches!(decision.result, Some(CleanupResult::DeleteRequested)) {
                let (api, _) = crate::kube::resource::resolve_api(
                    ctx.client,
                    &decision.resource,
                    ctx.kind_map,
                    ctx.gk_map,
                )
                .ok_or_else(|| {
                    anyhow::anyhow!(
                        "Cannot resolve API for {}/{}",
                        decision.resource.kind,
                        decision.resource.name
                    )
                })?;
                match api.get(&decision.resource.name).await {
                    Err(::kube::Error::Api(ref err)) if err.code == 404 => {
                        // Verify endpoint exists (404 could be endpoint gone, not object gone)
                        match api.list(&::kube::api::ListParams::default().limit(1)).await {
                            Ok(_) => {
                                let res_up = decision.resource.clone();
                                store
                                    .update(|j| {
                                        if let Some(d) =
                                            j.cleanup_decisions.iter_mut().rev().find(|d| {
                                                d.resource == res_up
                                                    && matches!(
                                                        d.result,
                                                        Some(CleanupResult::DeleteRequested)
                                                    )
                                            })
                                        {
                                            d.result = Some(CleanupResult::Gone);
                                        }
                                    })
                                    .await?;
                                eprintln!(
                                    "  {}/{}: gone (confirmed on resume)",
                                    decision.resource.kind, decision.resource.name
                                );
                            }
                            Err(_) => {
                                eprintln!(
                                    "  ⚠ {}/{}: GET 404 but endpoint verification failed — cannot confirm Gone",
                                    decision.resource.kind, decision.resource.name
                                );
                                any_retryable = true;
                            }
                        }
                    }
                    Ok(obj) => {
                        let live_uid = obj.metadata.uid.as_deref().unwrap_or("");
                        let bound = decision.bound_uid.as_deref().unwrap_or("");
                        if bound.is_empty() || live_uid.is_empty() {
                            bail!(
                                "Cannot verify {}/{}: UID missing (bound={:?}, live={:?})",
                                decision.resource.kind,
                                decision.resource.name,
                                bound,
                                live_uid
                            );
                        }
                        if live_uid != bound {
                            let res_up = decision.resource.clone();
                            store
                                .update(|j| {
                                    if let Some(d) =
                                        j.cleanup_decisions.iter_mut().rev().find(|d| {
                                            d.resource == res_up
                                                && matches!(
                                                    d.result,
                                                    Some(CleanupResult::DeleteRequested)
                                                )
                                        })
                                    {
                                        d.result = Some(CleanupResult::Gone);
                                    }
                                })
                                .await?;
                            eprintln!(
                                "  {}/{}: old UID gone (new UID {} = recreated)",
                                decision.resource.kind, decision.resource.name, live_uid
                            );
                            continue;
                        }
                        // Same UID — check if deleting
                        if obj.metadata.deletion_timestamp.is_some() {
                            let mut gone = false;
                            for _ in 0..30 {
                                tokio::time::sleep(std::time::Duration::from_secs(2)).await;
                                match api.get(&decision.resource.name).await {
                                    Err(::kube::Error::Api(ref err)) if err.code == 404 => {
                                        // Verify endpoint for wait-loop 404 too
                                        match api
                                            .list(&::kube::api::ListParams::default().limit(1))
                                            .await
                                        {
                                            Ok(_) => {
                                                gone = true;
                                                break;
                                            }
                                            Err(_) => break,
                                        }
                                    }
                                    Ok(_) => continue,
                                    Err(_) => break,
                                }
                            }
                            if gone {
                                let res_up = decision.resource.clone();
                                store
                                    .update(|j| {
                                        if let Some(d) =
                                            j.cleanup_decisions.iter_mut().rev().find(|d| {
                                                d.resource == res_up
                                                    && matches!(
                                                        d.result,
                                                        Some(CleanupResult::DeleteRequested)
                                                    )
                                            })
                                        {
                                            d.result = Some(CleanupResult::Gone);
                                        }
                                    })
                                    .await?;
                                eprintln!(
                                    "  {}/{}: gone (waited on resume)",
                                    decision.resource.kind, decision.resource.name
                                );
                            } else {
                                eprintln!(
                                    "  ⚠ {}/{}: still not Gone after wait",
                                    decision.resource.kind, decision.resource.name
                                );
                                any_retryable = true;
                            }
                        } else {
                            // No deletionTimestamp — UID-bound authority exists.
                            // Re-DELETE requires same safety checks as fresh DELETE.
                            eprintln!(
                                "  {}/{}: exists without deletionTimestamp — verifying for re-DELETE",
                                decision.resource.kind, decision.resource.name
                            );

                            // Acquire permit first
                            let _re_permit = gate
                                .acquire()
                                .await
                                .context("Mutation gate closed during re-DELETE")?;

                            // Post-permit: generation + audit + membership
                            let re_j = store.read().await;
                            let re_gen = audit::check_operator_generation_fresh(
                                ctx.client,
                                &re_j.operator,
                                &re_j.audit_context.csv_baseline,
                            )
                            .await;
                            if !matches!(re_gen, OperatorGenerationState::Absent) {
                                eprintln!("    ⚠ Generation not Absent for re-DELETE — skipping");
                                any_retryable = true;
                                drop(_re_permit);
                            } else {
                                match crate::teardown::audit::run_observed_audit(ctx.client, &re_j)
                                    .await
                                {
                                    Ok(re_audit) => {
                                        let re_status =
                                            audit::residual_status_from_audit(&re_audit);
                                        let re_in_set = !matches!(
                                            re_status,
                                            journal::ResidualStatus::AuditIncomplete
                                        ) && re_audit
                                            .likely_operator_residual
                                            .iter()
                                            .chain(re_audit.unattributed.iter())
                                            .any(|r| r.resource == decision.resource);
                                        if !re_in_set {
                                            eprintln!(
                                                "    ⚠ Not in current residual set for re-DELETE — skipping"
                                            );
                                            any_retryable = true;
                                            drop(_re_permit);
                                        } else {
                                            // Post-audit generation recheck before mutation
                                            let re_gen2 = audit::check_operator_generation_fresh(
                                                ctx.client,
                                                &re_j.operator,
                                                &re_j.audit_context.csv_baseline,
                                            )
                                            .await;
                                            if !matches!(re_gen2, OperatorGenerationState::Absent) {
                                                eprintln!(
                                                    "    ⚠ Generation changed during re-DELETE audit — skipping"
                                                );
                                                any_retryable = true;
                                                drop(_re_permit);
                                                continue;
                                            }
                                            use executor::DeleteOutcome;
                                            let re_del = executor::delete_resource_pub(
                                                ctx.client,
                                                &decision.resource,
                                                ctx.kind_map,
                                                ctx.gk_map,
                                                None, // permit already held
                                                decision.approved_spec_name.as_deref(),
                                            )
                                            .await;
                                            match re_del {
                                                DeleteOutcome::Accepted => {
                                                    eprintln!(
                                                        "    {}/{}: re-DELETE accepted",
                                                        decision.resource.kind,
                                                        decision.resource.name,
                                                    );
                                                    let mut re_gone = false;
                                                    for _ in 0..30 {
                                                        tokio::time::sleep(
                                                            std::time::Duration::from_secs(2),
                                                        )
                                                        .await;
                                                        match api.get(&decision.resource.name).await {
                                                            Err(::kube::Error::Api(ref err)) if err.code == 404 => {
                                                                match api.list(&::kube::api::ListParams::default().limit(1)).await {
                                                                    Ok(_) => { re_gone = true; break; }
                                                                    Err(_) => break,
                                                                }
                                                            }
                                                            Ok(_) => continue,
                                                            Err(_) => break,
                                                        }
                                                    }
                                                    let re_result = if re_gone {
                                                        CleanupResult::Gone
                                                    } else {
                                                        CleanupResult::DeleteRequested
                                                    };
                                                    let res_up = decision.resource.clone();
                                                    let re_result_clone = re_result.clone();
                                                    store.update(|j| {
                                                        if let Some(d) = j.cleanup_decisions.iter_mut().rev()
                                                            .find(|d| d.resource == res_up && matches!(d.result, Some(CleanupResult::DeleteRequested) | Some(CleanupResult::UnknownOutcome(_))))
                                                        { d.result = Some(re_result_clone); }
                                                    }).await
                                                    .context("Failed to checkpoint re-DELETE result")?;
                                                    if !re_gone {
                                                        any_retryable = true;
                                                    }
                                                }
                                                DeleteOutcome::AlreadyGone => {
                                                    eprintln!(
                                                        "    {}/{}: already gone",
                                                        decision.resource.kind,
                                                        decision.resource.name,
                                                    );
                                                    let res_up = decision.resource.clone();
                                                    store.update(|j| {
                                                        if let Some(d) = j.cleanup_decisions.iter_mut().rev()
                                                            .find(|d| d.resource == res_up && matches!(d.result, Some(CleanupResult::DeleteRequested) | Some(CleanupResult::UnknownOutcome(_))))
                                                        { d.result = Some(CleanupResult::Gone); }
                                                    }).await
                                                    .context("Failed to checkpoint re-DELETE already gone")?;
                                                }
                                                DeleteOutcome::Unknown(reason) => {
                                                    eprintln!(
                                                        "    ⚠ {}/{}: unknown outcome: {} — stopping (resumable)",
                                                        decision.resource.kind,
                                                        decision.resource.name,
                                                        reason
                                                    );
                                                    let res_up = decision.resource.clone();
                                                    store.update(|j| {
                                                        if let Some(d) = j.cleanup_decisions.iter_mut().rev()
                                                            .find(|d| d.resource == res_up)
                                                        { d.result = Some(CleanupResult::UnknownOutcome(reason.clone())); }
                                                    }).await
                                                    .context("Failed to checkpoint unknown re-DELETE")?;
                                                    // NOT any_hard_failed: Unknown is resumable via reconciliation
                                                    any_retryable = true;
                                                    drop(_re_permit);
                                                    break;
                                                }
                                                DeleteOutcome::Blocked(reason)
                                                | DeleteOutcome::Rejected(reason) => {
                                                    eprintln!(
                                                        "    ⚠ {}/{}: re-DELETE blocked/rejected: {}",
                                                        decision.resource.kind,
                                                        decision.resource.name,
                                                        reason
                                                    );
                                                    any_hard_failed = true;
                                                }
                                            }
                                            drop(_re_permit);
                                        }
                                    }
                                    Err(e) => {
                                        eprintln!(
                                            "    ⚠ Post-permit audit failed for re-DELETE: {}",
                                            e
                                        );
                                        any_retryable = true;
                                        drop(_re_permit);
                                    }
                                }
                            }
                        }
                    }
                    Err(e) => {
                        eprintln!(
                            "  ⚠ {}/{}: cannot verify: {}",
                            decision.resource.kind, decision.resource.name, e
                        );
                        any_retryable = true;
                    }
                }
                continue;
            }

            // Below: result.is_none() — fresh DELETE needed
            // Validate decision authority fields
            if decision.action != "delete" {
                bail!(
                    "Pending decision for {}/{} has action '{}', expected 'delete' — cannot resume",
                    decision.resource.kind,
                    decision.resource.name,
                    decision.action
                );
            }
            if decision.bound_uid.as_deref().unwrap_or("").is_empty() {
                bail!(
                    "Pending decision for {}/{} has no bound_uid — cannot verify identity for resume",
                    decision.resource.kind,
                    decision.resource.name
                );
            }

            if crate::teardown::runtime::persist_paused_if_closed(store, gate).await? {
                eprintln!("⏸ Gate closed — stopping cleanup resume");
                break;
            }

            // 1. Per-resource generation check
            let j_cur = store.read().await;
            let gen_state = audit::check_operator_generation_fresh(
                ctx.client,
                &j_cur.operator,
                &j_cur.audit_context.csv_baseline,
            )
            .await;
            if !matches!(gen_state, OperatorGenerationState::Absent) {
                bail!("Generation not Absent — cannot resume cleanup");
            }

            // 2. Fresh complete audit + membership check
            let fresh_audit = crate::teardown::audit::run_observed_audit(ctx.client, &j_cur)
                .await
                .context("Fresh audit failed during cleanup resume")?;
            let audit_status = audit::residual_status_from_audit(&fresh_audit);
            if matches!(audit_status, journal::ResidualStatus::AuditIncomplete) {
                bail!("Audit incomplete — cannot verify residual membership for resume");
            }
            let in_set = fresh_audit
                .likely_operator_residual
                .iter()
                .chain(fresh_audit.unattributed.iter())
                .any(|r| {
                    r.resource.group == decision.resource.group
                        && r.resource.kind == decision.resource.kind
                        && r.resource.name == decision.resource.name
                        && r.resource.namespace == decision.resource.namespace
                });
            if !in_set {
                // Check if already Gone
                let (api, _) = crate::kube::resource::resolve_api(
                    ctx.client,
                    &decision.resource,
                    ctx.kind_map,
                    ctx.gk_map,
                )
                .ok_or_else(|| {
                    anyhow::anyhow!(
                        "Cannot resolve API for {}/{} — aborting resume",
                        decision.resource.kind,
                        decision.resource.name
                    )
                })?;
                match api.get(&decision.resource.name).await {
                    Err(::kube::Error::Api(ref err)) if err.code == 404 => {
                        // Verify endpoint exists before declaring AlreadyGone
                        match api.list(&::kube::api::ListParams::default().limit(1)).await {
                            Ok(_) => {
                                let res_up = decision.resource.clone();
                                store
                                    .update(|j| {
                                        if let Some(d) =
                                            j.cleanup_decisions.iter_mut().rev().find(|d| {
                                                d.resource == res_up && d.result.is_none()
                                            })
                                        {
                                            d.result = Some(CleanupResult::AlreadyGone);
                                        }
                                    })
                                    .await?;
                                eprintln!(
                                    "  {}/{}: already gone",
                                    decision.resource.kind, decision.resource.name
                                );
                                continue;
                            }
                            Err(_) => {
                                bail!(
                                    "{}/{}: GET 404 but endpoint verification failed — \
                                               cannot confirm absence vs endpoint removal",
                                    decision.resource.kind,
                                    decision.resource.name
                                );
                            }
                        }
                    }
                    _ => bail!(
                        "{}/{} not in current residual set and not Gone",
                        decision.resource.kind,
                        decision.resource.name
                    ),
                }
            }

            // 3. Verify bound UID matches live
            let bound_uid = decision.bound_uid.as_deref().unwrap_or("");
            if bound_uid.is_empty() {
                bail!(
                    "Pending decision for {}/{} has no bound UID — cannot verify identity",
                    decision.resource.kind,
                    decision.resource.name
                );
            }
            let (api, _) = crate::kube::resource::resolve_api(
                ctx.client,
                &decision.resource,
                ctx.kind_map,
                ctx.gk_map,
            )
            .ok_or_else(|| {
                anyhow::anyhow!(
                    "Cannot resolve API for {}/{} — aborting resume",
                    decision.resource.kind,
                    decision.resource.name
                )
            })?;
            match api.get(&decision.resource.name).await {
                Ok(obj) => {
                    let live_uid = obj.metadata.uid.as_deref().unwrap_or("");
                    if live_uid != bound_uid {
                        bail!(
                            "Resource {}/{} UID changed ({} → {}) — cannot resume cleanup",
                            decision.resource.kind,
                            decision.resource.name,
                            bound_uid,
                            live_uid
                        );
                    }
                }
                Err(::kube::Error::Api(ref err)) if err.code == 404 => {
                    match api.list(&::kube::api::ListParams::default().limit(1)).await {
                        Ok(_) => {
                            let res_up = decision.resource.clone();
                            store
                                .update(|j| {
                                    if let Some(d) = j
                                        .cleanup_decisions
                                        .iter_mut()
                                        .rev()
                                        .find(|d| d.resource == res_up && d.result.is_none())
                                    {
                                        d.result = Some(CleanupResult::AlreadyGone);
                                    }
                                })
                                .await?;
                            eprintln!(
                                "  {}/{}: already gone",
                                decision.resource.kind, decision.resource.name
                            );
                            continue;
                        }
                        Err(_) => {
                            bail!(
                                "{}/{}: GET 404 but endpoint verification failed — \
                                           cannot confirm absence vs endpoint removal",
                                decision.resource.kind,
                                decision.resource.name
                            );
                        }
                    }
                }
                Err(e) => bail!(
                    "Cannot verify {}/{}: {} — aborting resume",
                    decision.resource.kind,
                    decision.resource.name,
                    e
                ),
            }

            // 4. DELETE with permit held through checkpoint
            let _permit = gate
                .acquire()
                .await
                .context("Mutation gate closed during cleanup resume")?;

            // Post-permit rechecks: generation + audit + membership could have changed
            {
                let pp_j = store.read().await;
                let pp_gen = audit::check_operator_generation_fresh(
                    ctx.client,
                    &pp_j.operator,
                    &pp_j.audit_context.csv_baseline,
                )
                .await;
                if !matches!(pp_gen, OperatorGenerationState::Absent) {
                    bail!("Generation changed after permit acquisition — aborting resume");
                }
                let pp_audit = crate::teardown::audit::run_observed_audit(ctx.client, &pp_j)
                    .await
                    .context("Post-permit audit failed during resume")?;
                let pp_status = audit::residual_status_from_audit(&pp_audit);
                if matches!(pp_status, journal::ResidualStatus::AuditIncomplete) {
                    bail!("Post-permit audit incomplete — aborting resume");
                }
                let pp_in_set = pp_audit
                    .likely_operator_residual
                    .iter()
                    .chain(pp_audit.unattributed.iter())
                    .any(|r| {
                        r.resource.group == decision.resource.group
                            && r.resource.kind == decision.resource.kind
                            && r.resource.name == decision.resource.name
                            && r.resource.namespace == decision.resource.namespace
                    });
                if !pp_in_set {
                    bail!(
                        "{}/{} no longer in residual set after permit acquisition",
                        decision.resource.kind,
                        decision.resource.name
                    );
                }
                // Final generation recheck after audit
                let pp_gen2 = audit::check_operator_generation_fresh(
                    ctx.client,
                    &pp_j.operator,
                    &pp_j.audit_context.csv_baseline,
                )
                .await;
                if !matches!(pp_gen2, OperatorGenerationState::Absent) {
                    bail!("Generation changed during post-permit audit — aborting resume");
                }
            }

            use executor::DeleteOutcome;
            let del = executor::delete_resource_pub(
                ctx.client,
                &decision.resource,
                ctx.kind_map,
                ctx.gk_map,
                None,
                decision.approved_spec_name.as_deref(),
            )
            .await;

            let must_stop = del.is_stop();
            let initial_result = match &del {
                DeleteOutcome::Accepted => CleanupResult::DeleteRequested,
                DeleteOutcome::AlreadyGone => CleanupResult::AlreadyGone,
                DeleteOutcome::Unknown(reason) => CleanupResult::UnknownOutcome(reason.clone()),
                DeleteOutcome::Blocked(reason) | DeleteOutcome::Rejected(reason) => {
                    any_hard_failed = true;
                    CleanupResult::Failed(reason.clone())
                }
            };
            let res_up = decision.resource.clone();
            let initial_clone = initial_result.clone();
            store
                .update(|j| {
                    if let Some(d) = j
                        .cleanup_decisions
                        .iter_mut()
                        .rev()
                        .find(|d| d.resource == res_up && d.result.is_none())
                    {
                        d.result = Some(initial_clone);
                    }
                })
                .await
                .context("Failed to checkpoint cleanup result")?;
            drop(_permit);

            // Unknown/Blocked → stop loop (Unknown is resumable)
            if must_stop {
                if matches!(initial_result, CleanupResult::UnknownOutcome(_)) {
                    any_retryable = true;
                } else {
                    any_hard_failed = true;
                }
                break;
            }

            // 5. Wait for Gone (only if DELETE was accepted)
            if matches!(initial_result, CleanupResult::DeleteRequested) {
                let mut gone = false;
                for _ in 0..30 {
                    tokio::time::sleep(std::time::Duration::from_secs(2)).await;
                    match api.get(&decision.resource.name).await {
                        Err(::kube::Error::Api(ref err)) if err.code == 404 => {
                            match api.list(&::kube::api::ListParams::default().limit(1)).await {
                                Ok(_) => {
                                    gone = true;
                                    break;
                                }
                                Err(_) => {
                                    any_retryable = true;
                                    break;
                                }
                            }
                        }
                        Ok(_) => continue,
                        Err(_) => {
                            any_retryable = true;
                            break;
                        }
                    }
                }
                if gone {
                    // Update result to "gone" (confirmed)
                    let res_up2 = decision.resource.clone();
                    store
                        .update(|j| {
                            if let Some(d) = j.cleanup_decisions.iter_mut().rev().find(|d| {
                                d.resource == res_up2
                                    && matches!(d.result, Some(CleanupResult::DeleteRequested))
                            }) {
                                d.result = Some(CleanupResult::Gone);
                            }
                        })
                        .await?;
                    eprintln!(
                        "  {}/{}: gone (confirmed)",
                        decision.resource.kind, decision.resource.name
                    );
                } else {
                    eprintln!(
                        "  ⚠ {}/{}: DELETE accepted but Gone not confirmed",
                        decision.resource.kind, decision.resource.name
                    );
                    any_retryable = true;
                }
            } else {
                eprintln!(
                    "  {}/{}: {:?}",
                    decision.resource.kind, decision.resource.name, initial_result
                );
            }
        }
    }

    // 6. Mandatory re-audit
    let j_cur = store.read().await;
    let gen_state = audit::check_operator_generation_fresh(
        ctx.client,
        &j_cur.operator,
        &j_cur.audit_context.csv_baseline,
    )
    .await;
    let final_state = if !gate.is_open() {
        RunState::Paused
    } else if any_hard_failed {
        RunState::Failed
    } else if any_retryable {
        RunState::InteractiveCleanup
    } else if matches!(gen_state, OperatorGenerationState::Absent) {
        match crate::teardown::audit::run_post_mutation_audit(ctx.client, &j_cur).await {
            Ok(re_audit) => {
                let status = audit::residual_status_from_audit(&re_audit);
                audit::print_residual_audit(&re_audit, &j_cur);
                store
                    .update(|j| {
                        j.residual_status = status.clone();
                        j.audit_revision += 1;
                        j.last_residual_audit = Some(re_audit);
                    })
                    .await?;
                if matches!(status, journal::ResidualStatus::AuditIncomplete) {
                    RunState::InteractiveCleanup
                } else {
                    let j_final = store.read().await;
                    if j_final.cleanup_decisions.iter().any(|d| d.is_hard_failed()) {
                        RunState::Failed
                    } else if j_final.cleanup_decisions.iter().any(|d| d.is_pending()) {
                        RunState::InteractiveCleanup
                    } else {
                        RunState::ApplyCompleted
                    }
                }
            }
            Err(e) => {
                eprintln!("⚠ Re-audit failed: {}", e);
                RunState::Failed
            }
        }
    } else {
        RunState::Failed
    };
    store
        .update(|j| {
            j.state = final_state.clone();
        })
        .await?;
    if final_state == RunState::Failed {
        bail!("Cleanup resume completed with hard failures");
    }
    if final_state == RunState::InteractiveCleanup {
        bail!(
            "Cleanup resume incomplete — pending decisions remain. \
                     State persisted as InteractiveCleanup (retryable)."
        );
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn determine_final_state_paused_when_gate_closed() {
        let gate = MutationGate::new(4);
        // Synchronously close for test — create a runtime to run the async drain
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(gate.close_and_drain());

        let result = ExecutionResult {
            phases_completed: 3,
            phases_total: 7,
            deleted: vec![],
            already_gone: vec![],
            failed: vec![],
            barrier_timeout: None,
            kept: vec![],
            reviewed: vec![],
        };
        assert_eq!(determine_final_state(&result, &gate), RunState::Paused);
    }

    #[test]
    fn determine_final_state_completed_when_all_phases_done() {
        let gate = MutationGate::new(4);
        let result = ExecutionResult {
            phases_completed: 7,
            phases_total: 7,
            deleted: vec![],
            already_gone: vec![],
            failed: vec![],
            barrier_timeout: None,
            kept: vec![],
            reviewed: vec![],
        };
        assert_eq!(
            determine_final_state(&result, &gate),
            RunState::ApplyCompleted
        );
    }

    #[test]
    fn determine_final_state_failed_when_failures_exist() {
        let gate = MutationGate::new(4);
        let result = ExecutionResult {
            phases_completed: 7,
            phases_total: 7,
            deleted: vec![],
            already_gone: vec![],
            failed: vec![(
                crate::kube::resource::ResourceId {
                    group: "".to_string(),
                    version: "v1".to_string(),
                    kind: "Pod".to_string(),
                    namespace: Some("ns".to_string()),
                    name: "test".to_string(),
                    uid: None,
                },
                "error".to_string(),
            )],
            barrier_timeout: None,
            kept: vec![],
            reviewed: vec![],
        };
        assert_eq!(determine_final_state(&result, &gate), RunState::Failed);
    }

    #[test]
    fn determine_final_state_failed_when_incomplete() {
        let gate = MutationGate::new(4);
        let result = ExecutionResult {
            phases_completed: 5,
            phases_total: 7,
            deleted: vec![],
            already_gone: vec![],
            failed: vec![],
            barrier_timeout: None,
            kept: vec![],
            reviewed: vec![],
        };
        assert_eq!(determine_final_state(&result, &gate), RunState::Failed);
    }
}
