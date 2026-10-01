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

pub enum WorkflowStart<'a> {
    /// Fresh apply: force=false, start_phase=0.
    Fresh { dry_run: bool, skip_confirm: bool },
    /// Normal resume from Paused/Applying: force=true, skip_confirm=true.
    ResumeExecution { start_phase: usize },
    /// Resume cleanup stage: handles pending cleanup decisions.
    ResumeCleanup {
        journal: &'a journal::RunJournal,
        main_complete: bool,
        paused_from_residual: bool,
    },
}

struct ExecuteOptions {
    dry_run: bool,
    force: bool,
    skip_confirm: bool,
    start_phase: usize,
}

pub struct WorkflowOutcome {
    pub final_state: RunState,
    pub result: ExecutionResult,
    pub cleanup_failure: Option<String>,
}

/// Single production mutation entry point for all teardown paths.
///
/// Every mutation (fresh apply, normal resume, cleanup resume) enters
/// through this function. main.rs performs read-only preparation
/// (validation, backup, journal creation/lock) then calls here.
pub async fn run_teardown_workflow(
    ctx: &WorkflowContext<'_>,
    journal_store: Option<&Arc<JournalStore>>,
    gate: &Arc<MutationGate>,
    start: WorkflowStart<'_>,
) -> anyhow::Result<WorkflowOutcome> {
    match start {
        WorkflowStart::Fresh {
            dry_run,
            skip_confirm,
        } => {
            run_execute_stage(
                ctx,
                journal_store,
                gate,
                &ExecuteOptions {
                    dry_run,
                    force: false,
                    skip_confirm,
                    start_phase: 0,
                },
            )
            .await
        }
        WorkflowStart::ResumeExecution { start_phase } => {
            run_execute_stage(
                ctx,
                journal_store,
                gate,
                &ExecuteOptions {
                    dry_run: false,
                    force: true,
                    skip_confirm: true,
                    start_phase,
                },
            )
            .await
        }
        WorkflowStart::ResumeCleanup {
            journal,
            main_complete,
            paused_from_residual,
        } => {
            let store = journal_store
                .ok_or_else(|| anyhow::anyhow!("ResumeCleanup requires a journal store"))?;
            run_resume_cleanup(
                ctx,
                store,
                gate,
                journal,
                main_complete,
                paused_from_residual,
            )
            .await?;
            let j = store.read().await;
            Ok(WorkflowOutcome {
                final_state: j.state.clone(),
                result: ExecutionResult {
                    phases_completed: j.execution.phases_completed,
                    phases_total: j.execution.phases_total,
                    deleted: vec![],
                    already_gone: vec![],
                    failed: vec![],
                    barrier_timeout: None,
                    kept: vec![],
                    reviewed: vec![],
                },
                cleanup_failure: None,
            })
        }
    }
}

async fn run_execute_stage(
    ctx: &WorkflowContext<'_>,
    journal_store: Option<&Arc<JournalStore>>,
    gate: &Arc<MutationGate>,
    options: &ExecuteOptions,
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
async fn run_resume_cleanup(
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

// ──────────────────────────────────────────────────────────────
//  Shared service functions — CLI and batch call these
// ──────────────────────────────────────────────────────────────

/// Check that a workflow outcome represents successful completion.
/// Dry-run and mutating runs use the same completion criteria; dry-run differs
/// only by performing zero mutation and creating no journal.
pub fn require_completed(outcome: &WorkflowOutcome) -> anyhow::Result<()> {
    match (&outcome.final_state, &outcome.cleanup_failure) {
        (RunState::ApplyCompleted, None) => Ok(()),
        (RunState::Paused, _) => bail!(
            "Teardown paused at phase {}/{}",
            outcome.result.phases_completed,
            outcome.result.phases_total
        ),
        (_, Some(reason)) => bail!("cleanup incomplete: {}", reason),
        (state, _) => bail!("Teardown did not complete (state: {:?})", state),
    }
}

pub struct ApplyParams<'a> {
    pub dry_run: bool,
    pub backup_dir: Option<&'a str>,
    pub skip_confirm: bool,
    pub refresh_discovery: bool,
    pub gate: &'a std::sync::Arc<MutationGate>,
}

/// Shared apply service: validates an ExecutionPlan against live cluster,
/// runs backup + journal + workflow. Used by both CLI apply and batch.
pub async fn apply_execution_plan(
    client: &::kube::Client,
    config: &::kube::config::Config,
    exec_plan: &crate::teardown::plan::ExecutionPlan,
    params: &ApplyParams<'_>,
) -> anyhow::Result<WorkflowOutcome> {
    use crate::teardown::plan::ApprovalScopeValue;
    use crate::teardown::planner::DecisionPolicy;

    let no_cache = super::planner::should_refresh_discovery(
        params.refresh_discovery,
        exec_plan.explicit_deletes.len(),
    );

    // P0: Validate cluster identity
    let current_cluster_identity = journal::fetch_cluster_identity(client).await?;
    if !current_cluster_identity.matches(&exec_plan.cluster_identity) {
        bail!(
            "Cluster identity mismatch: plan kube-system UID '{}' != current '{}'",
            exec_plan.cluster_identity.kube_system_uid,
            current_cluster_identity.kube_system_uid,
        );
    }

    let t0 = std::time::Instant::now();
    eprintln!("🔍 Discovering API resources...");
    let (kind_map, gvr_map, gk_map, gvk_map) =
        crate::kube::discovery::build_kind_lookup_cached(client, config, no_cache).await?;
    eprintln!("   Discovery: {:.1}s", t0.elapsed().as_secs_f64());

    eprint!("🔍 Discovering operators...");
    let all_operators = crate::analyzers::olm::discover_operators(client, &kind_map).await?;
    eprintln!(" found {} operators", all_operators.len());

    // P1: Resolve targets
    if exec_plan.targets.is_empty() {
        bail!("Execution plan has no operator targets");
    }
    let operator_queries: Vec<String> = exec_plan
        .targets
        .iter()
        .map(|t| t.package_name.clone())
        .filter(|s| !s.is_empty())
        .collect();
    if operator_queries.is_empty() {
        bail!("Execution plan has no valid operator targets");
    }
    let target_indices =
        crate::teardown::planner::resolve_operator_targets(&operator_queries, &all_operators)?;

    let mut validated_indices = Vec::new();
    for target in &exec_plan.targets {
        if target.package_name.is_empty() {
            continue;
        }
        let ns_matched: Vec<usize> = target_indices
            .iter()
            .copied()
            .filter(|&i| all_operators[i].install_namespace == target.install_namespace)
            .collect();
        if ns_matched.is_empty() {
            bail!(
                "Execution plan target {}/{} not found",
                target.package_name,
                target.install_namespace
            );
        }
        let csv_matched: Vec<usize> = ns_matched
            .iter()
            .copied()
            .filter(|&i| {
                crate::teardown::plan::csv_name_matches(
                    &target.csv_name_pattern,
                    &all_operators[i].csv.name,
                )
            })
            .collect();
        if csv_matched.is_empty() {
            bail!(
                "Execution plan target {}/{}: csv_name_pattern '{}' does not match",
                target.package_name,
                target.install_namespace,
                target.csv_name_pattern,
            );
        }
        for idx in csv_matched {
            if !validated_indices.contains(&idx) {
                validated_indices.push(idx);
            }
        }
    }
    if validated_indices.len()
        != exec_plan
            .targets
            .iter()
            .filter(|t| !t.package_name.is_empty())
            .count()
    {
        bail!(
            "Target count mismatch: plan {} vs resolved {}",
            exec_plan.targets.len(),
            validated_indices.len()
        );
    }

    let target_operators: Vec<&_> = validated_indices
        .iter()
        .map(|&i| &all_operators[i])
        .collect();

    // Reconstruct approval policy
    let mut approve_delete: Vec<String> = exec_plan
        .approve_scopes
        .iter()
        .map(|s| s.cli_arg().to_string())
        .collect();
    approve_delete.extend(exec_plan.approve_resources.iter().cloned());
    let preserve = exec_plan.keep_resources.clone();
    let prune_crds = exec_plan.prune_crds;

    let policy = DecisionPolicy::from_args(&approve_delete, &preserve);
    let plan = crate::teardown::planner::generate_teardown_plan(
        client,
        &target_operators,
        &all_operators,
        &kind_map,
        &gvr_map,
        &gk_map,
        &gvk_map,
        prune_crds,
        &policy,
        None,
    )
    .await?;

    // Drift detection: compare saved exec_plan vs fresh from live discovery
    {
        let approve_scope_values: Vec<crate::cli::ApprovalScope> = exec_plan
            .approve_scopes
            .iter()
            .map(|s| match s {
                ApprovalScopeValue::Root => crate::cli::ApprovalScope::Root,
                ApprovalScopeValue::Independent => crate::cli::ApprovalScope::Independent,
                ApprovalScopeValue::LabelOnly => crate::cli::ApprovalScope::LabelOnly,
                ApprovalScopeValue::OperatorGroup => crate::cli::ApprovalScope::OperatorGroup,
            })
            .collect();
        let fresh_exec = super::planner::build_execution_plan_from_teardown(
            &plan,
            &target_operators,
            &current_cluster_identity,
            prune_crds,
            &approve_scope_values,
            &exec_plan.approve_resources,
            &exec_plan.keep_resources,
        )?;
        if let Err(drift_errors) =
            crate::teardown::plan::validate_execution_plan_against_fresh(exec_plan, &fresh_exec)
        {
            eprintln!("\n⛔ Execution plan drift detected:");
            for err in &drift_errors {
                eprintln!("  - {}", err);
            }
            bail!("{} drift error(s) detected", drift_errors.len());
        }
        eprintln!("✅ Execution plan validated — no drift detected");
    }

    // Explicit target injection
    let mut plan = plan;
    if !exec_plan.explicit_deletes.is_empty() {
        let fresh_specs: Vec<super::plan::DeleteResourceSpec> = exec_plan
            .explicit_deletes
            .iter()
            .map(|t| super::plan::DeleteResourceSpec {
                group: t.group.clone(),
                kind: t.kind.clone(),
                namespace: t.namespace.clone(),
                name: t.name.clone(),
            })
            .collect();
        let fresh_targets =
            super::planner::resolve_explicit_delete_targets(client, &fresh_specs, &plan, &gk_map)
                .await?;
        if let Err(drift_errors) = crate::teardown::plan::validate_explicit_targets_authority(
            &exec_plan.explicit_deletes,
            &fresh_targets,
            &exec_plan.phases,
        ) {
            for e in &drift_errors {
                eprintln!("❌ {}", e);
            }
            bail!("{} explicit target authority error(s)", drift_errors.len());
        }
        super::planner::inject_explicit_phase_into_teardown_plan(
            &mut plan,
            &fresh_targets,
            &gk_map,
        )?;
    }

    // Backup gate
    let normal_backup_receipts = if let Some(bp) = params.backup_dir {
        let ctx = crate::teardown::backup::BackupGateContext {
            client,
            final_plan: &plan,
            target_operators: target_operators.clone(),
            cluster_identity: &current_cluster_identity,
            plan_path: "",
            kind_map: &kind_map,
            gvr_map: &gvr_map,
            gk_map: &gk_map,
            gvk_map: &gvk_map,
        };
        crate::teardown::backup::prepare_backup_gate(&ctx, std::path::Path::new(bp)).await?
    } else {
        vec![]
    };

    // Journal
    let journal_store: Option<std::sync::Arc<JournalStore>> = if !params.dry_run {
        let audit_ns = journal::discover_audit_scope(
            client,
            target_operators[0],
            &kind_map,
            &gvr_map,
            &gk_map,
        )
        .await?;
        let store = journal::create_run_journal(
            client,
            &plan,
            &target_operators,
            &gk_map,
            true,
            normal_backup_receipts,
            Some(audit_ns),
        )
        .await?;
        eprintln!("📓 Run journal: {}", store.path().display());
        let current_id = journal::fetch_cluster_identity(client).await?;
        let stored = store.read().await;
        if !current_id.matches(&stored.cluster_identity) {
            bail!("Cluster identity changed between journal creation and execution");
        }
        Some(std::sync::Arc::new(store))
    } else {
        None
    };

    // Workflow
    let workflow_ctx = WorkflowContext {
        client,
        plan: &plan,
        kind_map: &kind_map,
        gk_map: &gk_map,
        gvk_map: &gvk_map,
        gvr_map: &gvr_map,
    };
    run_teardown_workflow(
        &workflow_ctx,
        journal_store.as_ref(),
        params.gate,
        WorkflowStart::Fresh {
            dry_run: params.dry_run,
            skip_confirm: params.skip_confirm,
        },
    )
    .await
}

pub struct GeneratePlanParams<'a> {
    pub operator_name: &'a str,
    pub approve_delete: &'a [String],
    pub preserve: &'a [String],
    pub delete_resources: &'a [super::plan::DeleteResourceSpec],
    pub refresh_discovery: bool,
}

/// Generate an ExecutionPlan for an operator (plan step for batch).
pub async fn generate_execution_plan_for_operator(
    client: &::kube::Client,
    config: &::kube::config::Config,
    params: &GeneratePlanParams<'_>,
) -> anyhow::Result<crate::teardown::plan::ExecutionPlan> {
    use crate::teardown::planner::DecisionPolicy;

    let explicit_specs = params.delete_resources.to_vec();
    validate_delete_resource_specs(&explicit_specs)?;

    let no_cache =
        super::planner::should_refresh_discovery(params.refresh_discovery, explicit_specs.len());
    eprintln!("🔍 Discovering API resources...");
    let (kind_map, gvr_map, gk_map, gvk_map) =
        crate::kube::discovery::build_kind_lookup_cached(client, config, no_cache).await?;

    eprint!("🔍 Discovering operators...");
    let all_operators = crate::analyzers::olm::discover_operators(client, &kind_map).await?;
    eprintln!(" found {} operators", all_operators.len());

    let target_indices = crate::teardown::planner::resolve_operator_targets(
        &[params.operator_name.to_string()],
        &all_operators,
    )?;
    let target_operators: Vec<&_> = target_indices.iter().map(|&i| &all_operators[i]).collect();

    let policy = DecisionPolicy::from_args(params.approve_delete, params.preserve);
    let plan = crate::teardown::planner::generate_teardown_plan(
        client,
        &target_operators,
        &all_operators,
        &kind_map,
        &gvr_map,
        &gk_map,
        &gvk_map,
        false,
        &policy,
        None,
    )
    .await?;

    let mut plan = plan;
    let explicit_targets = if !explicit_specs.is_empty() {
        let targets = super::planner::resolve_explicit_delete_targets(
            client,
            &explicit_specs,
            &plan,
            &gk_map,
        )
        .await?;
        super::planner::inject_explicit_phase_into_teardown_plan(&mut plan, &targets, &gk_map)?;
        targets
    } else {
        Vec::new()
    };

    let cluster_identity = journal::fetch_cluster_identity(client).await?;
    let approve_scope: Vec<crate::cli::ApprovalScope> = params
        .approve_delete
        .iter()
        .filter_map(|s| match s.as_str() {
            "root" => Some(crate::cli::ApprovalScope::Root),
            "independent" => Some(crate::cli::ApprovalScope::Independent),
            "label-only" => Some(crate::cli::ApprovalScope::LabelOnly),
            "operator-group" => Some(crate::cli::ApprovalScope::OperatorGroup),
            _ => None,
        })
        .collect();
    let approve_resource: Vec<String> = params
        .approve_delete
        .iter()
        .filter(|s| {
            !matches!(
                s.as_str(),
                "root" | "independent" | "label-only" | "operator-group"
            )
        })
        .cloned()
        .collect();
    let mut exec_plan = super::planner::build_execution_plan_from_teardown(
        &plan,
        &target_operators,
        &cluster_identity,
        false,
        &approve_scope,
        &approve_resource,
        params.preserve,
    )?;
    exec_plan.explicit_deletes = explicit_targets;
    Ok(exec_plan)
}

/// Shared resume service: validates journal, acquires lock, runs workflow.
/// Used by both CLI resume and batch pending-explicit-cleanup.
pub async fn resume_from_journal(
    client: &::kube::Client,
    config: &::kube::config::Config,
    j: journal::RunJournal,
    journal_path: std::path::PathBuf,
    gate: &std::sync::Arc<MutationGate>,
    refresh_discovery: bool,
) -> anyhow::Result<WorkflowOutcome> {
    use crate::teardown::audit::{self as teardown_audit, OperatorGenerationState};

    let mut no_cache = refresh_discovery;
    let cluster_id = journal::fetch_cluster_identity(client).await?;

    if !j.cluster_identity.matches(&cluster_id) {
        bail!(
            "Journal cluster identity does not match current cluster \
             (journal: {}, current: {})",
            j.cluster_identity.kube_system_uid,
            cluster_id.kube_system_uid,
        );
    }

    match j.state {
        RunState::Paused
        | RunState::Applying
        | RunState::InteractiveCleanup
        | RunState::ExplicitCleanupBlocked => {}
        RunState::ApplyCompleted => {
            if j.last_residual_audit.is_none() {
                eprintln!(
                    "Run {} is ApplyCompleted but has no residual audit — running audit recovery",
                    j.run_id
                );
            } else {
                eprintln!(
                    "Run {} is ApplyCompleted — re-entering Residual Cleanup",
                    j.run_id
                );
            }
        }
        RunState::Finished => bail!("Run {} already finished", j.run_id),
        RunState::Failed => match explicit_cleanup_resume_mode(&j) {
            Ok(_) => {}
            Err(reason) => bail!(
                "Run {} has failed and is not eligible for retry: {}",
                j.run_id,
                reason
            ),
        },
        _ => bail!("Run {} is in state {:?} — cannot resume", j.run_id, j.state),
    }

    let store = std::sync::Arc::new(JournalStore::new_with_lock(j.clone(), journal_path)?);
    let mut j = store.read().await;

    // Re-verify after lock
    match j.state {
        RunState::Paused
        | RunState::Applying
        | RunState::InteractiveCleanup
        | RunState::ExplicitCleanupBlocked
        | RunState::ApplyCompleted => {}
        RunState::Finished => bail!("Run finished after lock"),
        RunState::Failed => match explicit_cleanup_resume_mode(&j) {
            Ok(_) => {}
            Err(reason) => bail!("Run failed after lock: {}", reason),
        },
        _ => bail!("Run state {:?} after lock", j.state),
    }

    if j.schema_version != journal::RUN_JOURNAL_SCHEMA_VERSION {
        bail!(
            "Journal schema v{} does not match current v{}",
            j.schema_version,
            journal::RUN_JOURNAL_SCHEMA_VERSION
        );
    }
    if !j.cluster_identity.matches(&cluster_id) {
        bail!("Cluster identity mismatch after lock");
    }
    if !j.backup_receipts.is_empty() {
        eprintln!(
            "📦 Validating {} backup receipt(s)...",
            j.backup_receipts.len()
        );
        for receipt in &j.backup_receipts {
            crate::teardown::backup::validate_receipt(receipt, &cluster_id)?;
            eprintln!("  ✅ Backup intact: {}", receipt.root);
        }
    }

    // Legacy migration
    let explicit_resume_mode = explicit_cleanup_resume_mode(&j).ok();
    if explicit_resume_mode == Some(ExplicitCleanupResumeMode::LegacyFailed) {
        store
            .update(|journal| {
                journal.state = RunState::ExplicitCleanupBlocked;
                journal.execution.explicit_cleanup_error = Some(journal::ExplicitCleanupError {
                    target: "saved Explicit cleanup phase".to_string(),
                    error_kind: journal::ExplicitCleanupErrorKind::LegacyStateMigration,
                    message: "migrated from structurally eligible legacy Failed journal"
                        .to_string(),
                });
            })
            .await
            .context("Failed to persist legacy ExplicitCleanupBlocked migration")?;
        j = store.read().await;
        eprintln!("  ✅ Migrated legacy Failed journal to ExplicitCleanupBlocked");
    }
    let is_explicit_cleanup_resume = explicit_cleanup_resume_mode(&j).is_ok();
    no_cache |= is_explicit_cleanup_resume;

    eprintln!(
        "Resuming run {} (state: {:?}, operator: {})",
        j.run_id, j.state, j.operator.csv_name
    );
    eprintln!(
        "  {}/{} phases completed, {} deleted",
        j.execution.phases_completed,
        j.execution.phases_total,
        j.execution.deleted.len(),
    );

    let t0 = std::time::Instant::now();
    eprintln!("🔍 Re-discovering API resources...");
    let (kind_map, _gvr_map, gk_map, gvk_map) =
        crate::kube::discovery::build_kind_lookup_cached(client, config, no_cache).await?;
    eprintln!("   Discovery: {:.1}s", t0.elapsed().as_secs_f64());

    let gen_state = teardown_audit::check_operator_generation_fresh(
        client,
        &j.operator,
        &j.audit_context.csv_baseline,
    )
    .await;

    if is_explicit_cleanup_resume {
        match gen_state {
            OperatorGenerationState::Absent => {
                eprintln!("  ✅ Operator absent — explicit cleanup eligible");
            }
            OperatorGenerationState::Reappeared => {
                bail!("Operator reappeared — cannot resume explicit cleanup");
            }
            _ => {
                bail!(
                    "Operator generation not absent ({:?}) — explicit cleanup blocked",
                    gen_state
                );
            }
        }
    } else {
        match gen_state {
            OperatorGenerationState::SameGeneration => {}
            OperatorGenerationState::Absent => {
                eprintln!("  Operator generation absent — teardown may have completed.");
            }
            OperatorGenerationState::Reappeared => {
                bail!("Operator reinstalled — cannot resume old teardown");
            }
            OperatorGenerationState::Unknown(reason) => {
                bail!("Cannot verify operator generation: {}", reason);
            }
        }
    }

    // Phase reconciliation
    use crate::teardown::planner::Action;
    let start_phase = {
        let completed = j.execution.phases_completed;
        let mut verified_through = completed;
        'phase_check: for (pi, phase) in j.plan_snapshot.phases.iter().take(completed).enumerate() {
            for action in &phase.actions {
                let resource = match action {
                    Action::Delete { resource, .. } | Action::ExpectGone { resource, .. } => {
                        resource
                    }
                    _ => continue,
                };
                let (api, _) = match crate::kube::resource::resolve_api(
                    client, resource, &kind_map, &gk_map,
                ) {
                    Some(r) => r,
                    None => bail!(
                        "Cannot resolve API for {}/{} — cannot verify state for resume",
                        resource.kind,
                        resource.name,
                    ),
                };
                match api.get(&resource.name).await {
                    Ok(obj) => {
                        let live_uid = obj.metadata.uid.as_deref().unwrap_or("");
                        let plan_uid = match &resource.uid {
                            Some(u) if !u.is_empty() => u.as_str(),
                            _ => bail!(
                                "Plan resource {}/{} has no UID",
                                resource.kind,
                                resource.name,
                            ),
                        };
                        if live_uid != plan_uid {
                            bail!(
                                "Resource {}/{} was recreated (plan UID {} vs live UID {})",
                                resource.kind,
                                resource.name,
                                plan_uid,
                                live_uid,
                            );
                        }
                        if obj.metadata.deletion_timestamp.is_none() {
                            eprintln!(
                                "  ⚠ {}/{} still exists — re-executing from phase {}",
                                resource.kind, resource.name, pi
                            );
                        } else {
                            eprintln!(
                                "  ⏳ {}/{} still deleting — re-executing from phase {}",
                                resource.kind, resource.name, pi
                            );
                        }
                        verified_through = pi;
                        break 'phase_check;
                    }
                    Err(::kube::Error::Api(ref err)) if err.code == 404 => {
                        match api.list(&::kube::api::ListParams::default().limit(1)).await {
                            Ok(_) => {}
                            Err(_) => {
                                bail!(
                                    "{}/{}: GET 404 but endpoint verification failed",
                                    resource.kind,
                                    resource.name
                                );
                            }
                        }
                    }
                    Err(e) => {
                        bail!(
                            "Cannot verify {}/{} state: {}",
                            resource.kind,
                            resource.name,
                            e
                        );
                    }
                }
            }
        }
        verified_through
    };

    eprintln!(
        "  Resuming from phase {}/{}",
        start_phase,
        j.plan_snapshot.phases.len()
    );

    // Re-delete reconciliation for ApplyCompleted
    if j.state == RunState::ApplyCompleted && start_phase == j.plan_snapshot.phases.len() {
        for record in j
            .execution
            .re_delete_records
            .iter()
            .filter(|r| matches!(r.result, journal::ReDeleteResult::Accepted))
        {
            let (api, _) = crate::kube::resource::resolve_api(
                client,
                &record.resource_identity,
                &kind_map,
                &gk_map,
            )
            .ok_or_else(|| {
                anyhow::anyhow!(
                    "Cannot resolve API for re-delete {}/{}",
                    record.resource_identity.kind,
                    record.resource_identity.name
                )
            })?;
            match api.get(&record.resource_identity.name).await {
                Err(::kube::Error::Api(ref err)) if err.code == 404 => {
                    api.list(&::kube::api::ListParams::default().limit(1))
                        .await
                        .with_context(|| {
                            format!(
                                "Cannot verify endpoint for re-delete {}/{}",
                                record.resource_identity.kind, record.resource_identity.name
                            )
                        })?;
                    let identity = record.resource_identity.clone();
                    let original_uid = record.original_uid.clone();
                    let new_uid = record.new_uid.clone();
                    store
                        .update(|latest| {
                            if let Some(entry) =
                                latest.execution.re_delete_records.iter_mut().find(|r| {
                                    r.resource_identity == identity
                                        && r.original_uid == original_uid
                                        && r.new_uid == new_uid
                                        && matches!(r.result, journal::ReDeleteResult::Accepted)
                                })
                            {
                                entry.result = journal::ReDeleteResult::Gone;
                            }
                        })
                        .await?;
                }
                Ok(_) => {}
                Err(e) => {
                    bail!(
                        "Cannot reconcile accepted re-delete {}/{}: {}",
                        record.resource_identity.kind,
                        record.resource_identity.name,
                        e
                    );
                }
            }
        }
    }
    let j = store.read().await;

    let resume_stage =
        classify_resume_stage(&j).map_err(|e| anyhow::anyhow!("Cannot resume: {}", e))?;
    let main_complete = j.execution.phases_completed == j.execution.phases_total;
    let paused_from_residual =
        j.state == RunState::Paused && main_complete && j.last_residual_audit.is_some();

    let workflow_ctx = WorkflowContext {
        client,
        plan: &j.plan_snapshot,
        kind_map: &kind_map,
        gk_map: &gk_map,
        gvk_map: &gvk_map,
        gvr_map: &_gvr_map,
    };

    if resume_stage == ResumeStage::Cleanup {
        return run_teardown_workflow(
            &workflow_ctx,
            Some(&store),
            gate,
            WorkflowStart::ResumeCleanup {
                journal: &j,
                main_complete,
                paused_from_residual,
            },
        )
        .await;
    }

    // Main execution resume
    store
        .update(|journal| {
            journal.state = RunState::Applying;
            journal.execution.explicit_cleanup_error = None;
        })
        .await
        .context("Failed to persist Applying state for resume")?;

    run_teardown_workflow(
        &workflow_ctx,
        Some(&store),
        gate,
        WorkflowStart::ResumeExecution { start_phase },
    )
    .await
}

/// Shared validation for delete-resource specs: per-spec validation + duplicate rejection.
/// Used by both CLI plan and batch generate_execution_plan_for_operator.
pub fn validate_delete_resource_specs(
    specs: &[super::plan::DeleteResourceSpec],
) -> anyhow::Result<()> {
    for spec in specs {
        spec.validate()?;
    }
    let mut seen = std::collections::HashSet::new();
    for spec in specs {
        let key = (
            spec.group.clone(),
            spec.kind.clone(),
            spec.namespace.clone(),
            spec.name.clone(),
        );
        if !seen.insert(key) {
            bail!("Duplicate delete-resource: {}/{}", spec.kind, spec.name);
        }
    }
    Ok(())
}

// ── Production batch types and loop ──

/// Outcome of a single batch entry.
#[derive(Clone, Debug, PartialEq)]
pub enum BatchOutcome {
    Succeeded,
    Skipped,
    Failed(i32),
    NotRun,
}

/// Classified batch entry kind for the production loop.
#[derive(Clone, Debug)]
pub enum BatchEntryKind {
    PlanAndApply,
    Skip,
    PendingResume {
        run_id: String,
    },
    DryRunResume {
        #[allow(dead_code)]
        run_id: String,
    },
}

/// Classify batch entries from baseline gate results.
/// Per-entry baseline observation from operator discovery.
#[derive(Clone, Debug)]
pub enum BaselineObservation {
    Present,
    Missing,
    PendingResume { run_id: String },
}

/// A classified batch entry with its original config index preserved.
#[derive(Clone, Debug)]
pub struct ClassifiedBatchEntry {
    pub source_index: usize,
    pub name: String,
    pub kind: BatchEntryKind,
}

/// Classify batch entries into typed kinds. Returns Err if any operator
/// is missing and skip_missing is false (baseline gate failure).
/// Preserves source_index so runners use the correct config entry.
pub fn classify_batch_entries(
    entries: &[(String, BaselineObservation)],
    skip_missing: bool,
    dry_run: bool,
) -> anyhow::Result<Vec<ClassifiedBatchEntry>> {
    let mut missing: Vec<String> = Vec::new();
    let mut classified = Vec::new();

    for (i, (name, obs)) in entries.iter().enumerate() {
        match obs {
            BaselineObservation::Present => {
                classified.push(ClassifiedBatchEntry {
                    source_index: i,
                    name: name.clone(),
                    kind: BatchEntryKind::PlanAndApply,
                });
            }
            BaselineObservation::Missing => {
                if skip_missing {
                    classified.push(ClassifiedBatchEntry {
                        source_index: i,
                        name: name.clone(),
                        kind: BatchEntryKind::Skip,
                    });
                } else {
                    missing.push(name.clone());
                }
            }
            BaselineObservation::PendingResume { run_id } => {
                if dry_run {
                    classified.push(ClassifiedBatchEntry {
                        source_index: i,
                        name: name.clone(),
                        kind: BatchEntryKind::DryRunResume {
                            run_id: run_id.clone(),
                        },
                    });
                } else {
                    classified.push(ClassifiedBatchEntry {
                        source_index: i,
                        name: name.clone(),
                        kind: BatchEntryKind::PendingResume {
                            run_id: run_id.clone(),
                        },
                    });
                }
            }
        }
    }

    if !missing.is_empty() {
        bail!(
            "Baseline gate failed: {} operator(s) not found: {}. \
             Use --skip-missing to skip absent operators.",
            missing.len(),
            missing.join(", ")
        );
    }

    Ok(classified)
}

/// Production batch entry loop. Both main.rs and tests call this.
/// plan_apply_runner receives (source_index, name) so the caller can look up
/// the correct config entry by index, not by name search.
pub async fn run_batch_entries<PlanApplyFn, PlanApplyFut, ResumeFn, ResumeFut>(
    entries: &[ClassifiedBatchEntry],
    gate: &Arc<MutationGate>,
    mut plan_apply_runner: PlanApplyFn,
    mut resume_runner: ResumeFn,
) -> Vec<(String, BatchOutcome)>
where
    PlanApplyFn: FnMut(usize, &str) -> PlanApplyFut,
    PlanApplyFut: std::future::Future<Output = anyhow::Result<WorkflowOutcome>>,
    ResumeFn: FnMut(&str) -> ResumeFut,
    ResumeFut: std::future::Future<Output = anyhow::Result<WorkflowOutcome>>,
{
    let mut outcomes = Vec::new();

    for (i, entry) in entries.iter().enumerate() {
        let name = &entry.name;
        if !gate.is_open() {
            for e in entries.iter().skip(i) {
                outcomes.push((e.name.clone(), BatchOutcome::NotRun));
            }
            break;
        }

        match &entry.kind {
            BatchEntryKind::Skip => {
                outcomes.push((name.clone(), BatchOutcome::Skipped));
            }
            BatchEntryKind::DryRunResume { .. } => {
                outcomes.push((name.clone(), BatchOutcome::Succeeded));
            }
            BatchEntryKind::PendingResume { run_id } => {
                match resume_runner(run_id).await.and_then(|o| {
                    require_completed(&o)?;
                    Ok(o)
                }) {
                    Ok(_) => {
                        outcomes.push((name.clone(), BatchOutcome::Succeeded));
                    }
                    Err(e) => {
                        eprintln!("\n⛔ {} failed: {:#}", name, e);
                        outcomes.push((name.clone(), BatchOutcome::Failed(1)));
                        for e in entries.iter().skip(i + 1) {
                            outcomes.push((e.name.clone(), BatchOutcome::NotRun));
                        }
                        break;
                    }
                }
            }
            BatchEntryKind::PlanAndApply => {
                match plan_apply_runner(entry.source_index, name)
                    .await
                    .and_then(|o| {
                        require_completed(&o)?;
                        Ok(o)
                    }) {
                    Ok(_) => {
                        outcomes.push((name.clone(), BatchOutcome::Succeeded));
                    }
                    Err(e) => {
                        eprintln!("\n⛔ {} failed: {:#}", name, e);
                        outcomes.push((name.clone(), BatchOutcome::Failed(1)));
                        for e in entries.iter().skip(i + 1) {
                            outcomes.push((e.name.clone(), BatchOutcome::NotRun));
                        }
                        break;
                    }
                }
            }
        }
    }

    outcomes
}

// ── Functions moved from commands/teardown.rs (P0-1 dependency direction fix) ──

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ExplicitCleanupResumeMode {
    TypedBlocked,
    LegacyFailed,
}

type ExplicitCleanupKey = (String, String, Option<String>, String, String);

pub fn explicit_cleanup_resume_mode(
    run: &journal::RunJournal,
) -> Result<ExplicitCleanupResumeMode, String> {
    use super::planner::Action;
    use journal::{FinalizerRecoveryResult, ReDeleteResult, RunState};

    let mode = match run.state {
        RunState::ExplicitCleanupBlocked => ExplicitCleanupResumeMode::TypedBlocked,
        RunState::Failed => ExplicitCleanupResumeMode::LegacyFailed,
        ref other => {
            return Err(format!(
                "state {:?} is not an explicit-cleanup retry state",
                other
            ));
        }
    };

    if run.schema_version != journal::RUN_JOURNAL_SCHEMA_VERSION {
        return Err(format!(
            "journal schema v{} does not match current v{}",
            run.schema_version,
            journal::RUN_JOURNAL_SCHEMA_VERSION
        ));
    }
    if run.execution.phases_total != run.plan_snapshot.phases.len() {
        return Err(format!(
            "phase count mismatch: journal={} plan={}",
            run.execution.phases_total,
            run.plan_snapshot.phases.len()
        ));
    }
    if !run.plan_snapshot.blockers.is_empty() {
        return Err("saved plan contains blockers".to_string());
    }

    let explicit_phase_indices: Vec<usize> = run
        .plan_snapshot
        .phases
        .iter()
        .enumerate()
        .filter_map(|(i, p)| (p.name == super::plan::EXPLICIT_CLEANUP_PHASE_NAME).then_some(i))
        .collect();
    if explicit_phase_indices.len() != 1 {
        return Err(format!(
            "expected exactly one Explicit cleanup phase, found {}",
            explicit_phase_indices.len()
        ));
    }
    let explicit_phase_index = explicit_phase_indices[0];
    if run.execution.phases_completed != explicit_phase_index {
        return Err(format!(
            "phases_completed {} does not point to Explicit cleanup phase {}",
            run.execution.phases_completed, explicit_phase_index
        ));
    }
    if run.plan_snapshot.explicit_deletes.is_empty() {
        return Err("saved plan has no explicit_deletes".to_string());
    }

    let mut metadata_keys: Vec<ExplicitCleanupKey> = Vec::new();
    for target in &run.plan_snapshot.explicit_deletes {
        if target.kind.trim().is_empty()
            || target.name.trim().is_empty()
            || target.uid.trim().is_empty()
            || target
                .namespace
                .as_ref()
                .is_some_and(|ns| ns.trim().is_empty())
            || !target.ref_scan_coverage.scan_complete
        {
            return Err(format!(
                "invalid explicit target {}/{} (empty identity/UID or incomplete plan-time scan)",
                target.kind, target.name
            ));
        }
        metadata_keys.push((
            target.group.clone(),
            target.kind.clone(),
            target.namespace.clone(),
            target.name.clone(),
            target.uid.clone(),
        ));
    }

    let mut action_keys: Vec<ExplicitCleanupKey> = Vec::new();
    for action in &run.plan_snapshot.phases[explicit_phase_index].actions {
        let Action::Delete { resource, .. } = action else {
            return Err("Explicit cleanup phase contains a non-DELETE action".to_string());
        };
        let uid = resource
            .uid
            .as_ref()
            .filter(|uid| !uid.trim().is_empty())
            .ok_or_else(|| {
                format!(
                    "Explicit cleanup action {}/{} has no bound UID",
                    resource.kind, resource.name
                )
            })?;
        if resource.version.trim().is_empty() {
            return Err(format!(
                "Explicit cleanup action {}/{} has no API version",
                resource.kind, resource.name
            ));
        }
        action_keys.push((
            resource.group.clone(),
            resource.kind.clone(),
            resource.namespace.clone(),
            resource.name.clone(),
            uid.clone(),
        ));
    }
    metadata_keys.sort();
    action_keys.sort();
    if metadata_keys.windows(2).any(|w| w[0] == w[1])
        || action_keys.windows(2).any(|w| w[0] == w[1])
    {
        return Err("duplicate explicit cleanup identity in saved authority".to_string());
    }
    if metadata_keys != action_keys {
        return Err("explicit_deletes do not match Explicit cleanup actions 1:1".to_string());
    }

    if run.execution.barrier_timeout.is_some() || !run.execution.failed.is_empty() {
        return Err("journal contains a failed action or barrier timeout".to_string());
    }
    let has_explicit_outcome = run
        .execution
        .deleted
        .iter()
        .chain(run.execution.already_gone.iter())
        .any(|r| {
            r.uid.as_ref().is_some_and(|uid| {
                metadata_keys
                    .iter()
                    .any(|(_, _, _, _, target_uid)| target_uid == uid)
            })
        });
    if has_explicit_outcome {
        return Err("journal already contains an explicit cleanup mutation outcome".to_string());
    }
    if !run.cleanup_decisions.is_empty() {
        return Err(
            "residual cleanup decisions exist before Explicit cleanup completed".to_string(),
        );
    }
    if run
        .finalizer_recoveries
        .iter()
        .any(|r| matches!(r.result, FinalizerRecoveryResult::PatchRequested))
    {
        return Err("unresolved finalizer recovery outcome".to_string());
    }
    if run.execution.re_delete_records.iter().any(|r| {
        matches!(
            r.result,
            ReDeleteResult::Authorized
                | ReDeleteResult::Accepted
                | ReDeleteResult::UnknownOutcome(_)
        )
    }) {
        return Err("unresolved re-delete outcome".to_string());
    }

    match mode {
        ExplicitCleanupResumeMode::TypedBlocked => {
            if run.execution.explicit_cleanup_error.is_none() {
                return Err("typed blocked state has no typed cleanup error".to_string());
            }
        }
        ExplicitCleanupResumeMode::LegacyFailed => {
            if run.execution.explicit_cleanup_error.is_some() {
                return Err(
                    "legacy Failed journal unexpectedly has a typed cleanup error".to_string(),
                );
            }
            if run.backup_receipts.is_empty() {
                return Err("legacy Failed migration requires a backup receipt".to_string());
            }
        }
    }

    Ok(mode)
}

pub fn operator_snapshot_matches_entry(
    run: &journal::RunJournal,
    operator_entry_name: &str,
) -> bool {
    let csv = &run.operator.csv_name;
    let pkg = match &run.operator.generation_identity {
        super::plan::OperatorGenerationIdentity::OlmPackage { package_name, .. } => {
            package_name.as_str()
        }
        _ => "",
    };
    csv.starts_with(&format!("{}.", operator_entry_name))
        || csv.starts_with(&format!("{}.v", operator_entry_name))
        || pkg == operator_entry_name
        || csv == operator_entry_name
}

pub fn find_pending_explicit_cleanup_journal(
    cluster_id: &super::plan::ClusterIdentity,
    operator_entry_name: &str,
) -> anyhow::Result<Option<String>> {
    let runs = journal::list_runs(cluster_id)?;
    select_pending_explicit_cleanup_journal(&runs, operator_entry_name).map_err(anyhow::Error::msg)
}

pub fn select_pending_explicit_cleanup_journal(
    runs: &[journal::RunJournal],
    operator_entry_name: &str,
) -> Result<Option<String>, String> {
    let Some(latest) = runs
        .iter()
        .filter(|run| operator_snapshot_matches_entry(run, operator_entry_name))
        .max_by(|a, b| {
            a.created_at
                .cmp(&b.created_at)
                .then_with(|| a.run_id.cmp(&b.run_id))
        })
    else {
        return Ok(None);
    };

    if matches!(
        latest.state,
        journal::RunState::ExplicitCleanupBlocked | journal::RunState::Failed
    ) && !latest.plan_snapshot.explicit_deletes.is_empty()
    {
        explicit_cleanup_resume_mode(latest).map_err(|reason| {
            format!(
                "Latest run {} for {} has pending explicit cleanup but is not safely resumable: {}",
                latest.run_id, operator_entry_name, reason
            )
        })?;
        return Ok(Some(latest.run_id.clone()));
    }

    Ok(None)
}

#[derive(Debug, PartialEq)]
pub enum ResumeStage {
    Cleanup,
    MainExecution,
}

pub fn classify_resume_stage(j: &journal::RunJournal) -> Result<ResumeStage, String> {
    // Block resume if any finalizer recovery is in PatchRequested state (crash between
    // intent record and outcome record — commit outcome unknown without live verification)
    let unresolved_patch = j
        .finalizer_recoveries
        .iter()
        .any(|r| matches!(r.result, journal::FinalizerRecoveryResult::PatchRequested));
    if unresolved_patch {
        return Err(
            "Journal contains unresolved PatchRequested finalizer recovery record(s). \
             Crash occurred between intent and outcome — manual verification required before resume."
                .to_string(),
        );
    }

    // Block resume if any re-delete record is not terminal (Gone/Failed).
    // MVP: re-delete crash recovery requires fresh plan. Stale authority not reused.
    let has_unresolved_redelete = j.execution.re_delete_records.iter().any(|r| {
        matches!(
            r.result,
            journal::ReDeleteResult::Authorized
                | journal::ReDeleteResult::Accepted
                | journal::ReDeleteResult::UnknownOutcome(_)
        )
    });
    if has_unresolved_redelete {
        return Err(
            "Journal contains unresolved re-delete record(s) (Authorized/Accepted/Unknown). \
             Re-delete crash recovery requires a fresh teardown plan."
                .to_string(),
        );
    }

    let main_complete = j.execution.phases_completed == j.execution.phases_total;

    let has_pending_cleanup =
        !j.cleanup_decisions.is_empty() && j.cleanup_decisions.iter().any(|d| d.is_pending());

    let paused_from_residual =
        j.state == journal::RunState::Paused && main_complete && j.last_residual_audit.is_some();

    // ApplyCompleted → re-enter Residual (with or without prior audit)
    let apply_completed_reentry = j.state == journal::RunState::ApplyCompleted && main_complete;

    // Inconsistent: cleanup decisions exist but main not complete
    if !j.cleanup_decisions.is_empty() && !main_complete {
        return Err(format!(
            "Journal inconsistent: {} cleanup decisions but only {}/{} phases complete",
            j.cleanup_decisions.len(),
            j.execution.phases_completed,
            j.execution.phases_total,
        ));
    }
    // Inconsistent: InteractiveCleanup but main not complete
    if j.state == journal::RunState::InteractiveCleanup && !main_complete {
        return Err(format!(
            "Journal inconsistent: InteractiveCleanup state but only {}/{} phases complete",
            j.execution.phases_completed, j.execution.phases_total,
        ));
    }
    // Inconsistent: ApplyCompleted but main not complete
    if j.state == journal::RunState::ApplyCompleted && !main_complete {
        return Err(format!(
            "Journal inconsistent: ApplyCompleted but only {}/{} phases complete",
            j.execution.phases_completed, j.execution.phases_total,
        ));
    }

    // Prepared → user quit Plan Review without pressing Start. No mutation occurred.
    if j.state == journal::RunState::Prepared {
        return Err(
            "Journal is in Prepared state — Plan Review was not completed. \
             Create a new teardown plan."
                .to_string(),
        );
    }

    // Typed and narrowly proven legacy explicit-cleanup failures both resume
    // through the saved main plan at the exact Explicit cleanup boundary.
    if matches!(
        j.state,
        journal::RunState::ExplicitCleanupBlocked | journal::RunState::Failed
    ) {
        explicit_cleanup_resume_mode(j)?;
        return Ok(ResumeStage::MainExecution);
    }

    if (j.state == journal::RunState::InteractiveCleanup && main_complete)
        || (j.state == journal::RunState::Paused && main_complete && has_pending_cleanup)
        || paused_from_residual
        || apply_completed_reentry
    {
        Ok(ResumeStage::Cleanup)
    } else {
        Ok(ResumeStage::MainExecution)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::teardown::plan::DeleteResourceSpec;

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

    use crate::teardown::planner::{Action, PlanPhase, Preflight};
    use kube::client::Body;
    use std::pin::pin;
    use std::sync::atomic::{AtomicUsize, Ordering};

    fn make_plan_with_delete(name: &str, uid: &str) -> TeardownPlan {
        let resource = crate::kube::resource::ResourceId {
            group: String::new(),
            version: "v1".to_string(),
            kind: "ConfigMap".to_string(),
            namespace: Some("test-ns".to_string()),
            name: name.to_string(),
            uid: Some(uid.to_string()),
        };
        TeardownPlan {
            targets: vec![],
            preflight: Preflight { checks: vec![] },
            phases: vec![PlanPhase {
                name: "test".to_string(),
                description: "test phase".to_string(),
                actions: vec![Action::Delete {
                    resource,
                    reason: "test".to_string(),
                }],
                barrier: None,
            }],
            blockers: vec![],
            warnings: vec![],
            snapshot_taken_at: "2026-01-01T00:00:00Z".to_string(),
            dependency_edges: vec![],
            operator_inventory: vec![],
            explicit_decisions: vec![],
            explicit_deletes: vec![],
        }
    }

    fn make_test_journal_for_workflow(
        state: RunState,
        phases_completed: usize,
        phases_total: usize,
    ) -> journal::RunJournal {
        use crate::teardown::plan::*;
        journal::RunJournal {
            run_id: "test-workflow".to_string(),
            schema_version: journal::RUN_JOURNAL_SCHEMA_VERSION,
            oc_deps_version: "test".to_string(),
            journal_revision: 0,
            cluster_identity: ClusterIdentity {
                api_server: "https://test:6443".to_string(),
                kube_system_uid: "test-uid".to_string(),
            },
            operator: OperatorIdentitySnapshot {
                generation_identity: OperatorGenerationIdentity::Unverifiable {
                    reason: "test".to_string(),
                },
                operator_id: crate::analyzers::olm::OperatorId {
                    namespace: "ns".to_string(),
                    csv_name: "test.v1".to_string(),
                },
                csv_name: "test.v1".to_string(),
                csv: ObservedResourceIdentity {
                    resource: crate::kube::resource::ResourceId {
                        group: "operators.coreos.com".to_string(),
                        version: "v1alpha1".to_string(),
                        kind: "ClusterServiceVersion".to_string(),
                        namespace: Some("ns".to_string()),
                        name: "test.v1".to_string(),
                        uid: Some("csv-uid".to_string()),
                    },
                    uid: "csv-uid".to_string(),
                },
                subscriptions: vec![],
                controller_deployments: vec![],
                service_accounts: vec![],
                owned_crds: vec![],
                required_crds: vec![],
            },
            created_at: "2026-01-01T00:00:00Z".to_string(),
            updated_at: "2026-01-01T00:00:00Z".to_string(),
            state,
            residual_status: journal::ResidualStatus::NotAudited,
            audit_revision: 0,
            audit_context: journal::AuditContext::default(),
            plan_snapshot: make_plan_with_delete("test-cm", "uid-cm"),
            execution: journal::ExecutionRecord {
                phases_completed,
                phases_total,
                ..Default::default()
            },
            last_residual_audit: None,
            cleanup_decisions: vec![],
            finalizer_recovery_approved: true,
            finalizer_recoveries: vec![],
            backup_receipts: vec![],
        }
    }

    fn make_journal_store(j: journal::RunJournal) -> (Arc<JournalStore>, std::path::PathBuf) {
        let dir = std::env::temp_dir().join(format!(
            "oc-deps-wf-test-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let _ = std::fs::create_dir_all(&dir);
        let path = dir.join("journal.json");
        journal::atomic_write_json_pub(&path, &j).unwrap();
        let store = Arc::new(JournalStore::new_with_lock(j, path).unwrap());
        (store, dir)
    }

    fn json_response(json: serde_json::Value) -> http::Response<Body> {
        http::Response::builder()
            .status(200)
            .body(Body::from(serde_json::to_vec(&json).unwrap()))
            .unwrap()
    }

    fn not_found_response() -> http::Response<Body> {
        let body = serde_json::json!({
            "kind": "Status", "apiVersion": "v1", "metadata": {},
            "status": "Failure", "message": "not found", "reason": "NotFound", "code": 404
        });
        http::Response::builder()
            .status(404)
            .body(Body::from(serde_json::to_vec(&body).unwrap()))
            .unwrap()
    }

    fn test_kind_map() -> std::collections::HashMap<String, crate::kube::discovery::KindInfo> {
        let mut km = std::collections::HashMap::new();
        km.insert(
            "ConfigMap".to_string(),
            crate::kube::discovery::KindInfo {
                group: String::new(),
                version: "v1".to_string(),
                plural: "configmaps".to_string(),
                namespaced: true,
                listable: true,
            },
        );
        km
    }

    fn test_gk_map() -> std::collections::HashMap<(String, String), crate::kube::discovery::KindInfo>
    {
        let mut gk = std::collections::HashMap::new();
        gk.insert(
            (String::new(), "ConfigMap".to_string()),
            crate::kube::discovery::KindInfo {
                group: String::new(),
                version: "v1".to_string(),
                plural: "configmaps".to_string(),
                namespaced: true,
                listable: true,
            },
        );
        gk
    }

    /// Test 1: Fresh workflow with 1 DELETE action and closed gate.
    /// Gate is closed before workflow → executor must not send DELETE.
    /// Asserts: 0 DELETE requests via tower mock, journal durably Paused.
    #[tokio::test]
    async fn workflow_fresh_closed_gate_blocks_delete() {
        let delete_count = Arc::new(AtomicUsize::new(0));
        let request_count = Arc::new(AtomicUsize::new(0));
        let dc = delete_count.clone();
        let rc = request_count.clone();

        let (mock_service, handle) =
            tower_test::mock::pair::<http::Request<Body>, http::Response<Body>>();

        let spawned = tokio::spawn(async move {
            let mut handle = pin!(handle);
            while let Some((req, send)) = handle.next_request().await {
                rc.fetch_add(1, Ordering::SeqCst);
                if req.method() == http::Method::DELETE {
                    dc.fetch_add(1, Ordering::SeqCst);
                }
                // Respond to any request with not-found (gate should prevent reaching here)
                send.send_response(not_found_response());
            }
        });

        let client = kube::Client::new(mock_service, "test-ns");
        let plan = make_plan_with_delete("target-cm", "uid-target");
        let j = make_test_journal_for_workflow(RunState::Applying, 0, 1);
        let (store, dir) = make_journal_store(j);
        let km = test_kind_map();
        let gk = test_gk_map();
        let gvk = std::collections::HashMap::new();
        let gvr = std::collections::HashMap::new();
        let gate = Arc::new(MutationGate::new(4));
        gate.close_and_drain().await;

        let ctx = WorkflowContext {
            client: &client,
            plan: &plan,
            kind_map: &km,
            gk_map: &gk,
            gvk_map: &gvk,
            gvr_map: &gvr,
        };

        let outcome = run_teardown_workflow(
            &ctx,
            Some(&store),
            &gate,
            WorkflowStart::Fresh {
                dry_run: false,
                skip_confirm: true,
            },
        )
        .await
        .unwrap();

        drop(client);
        let _ = spawned.await;

        assert_eq!(outcome.final_state, RunState::Paused, "must be Paused");
        assert_eq!(
            delete_count.load(Ordering::SeqCst),
            0,
            "0 DELETE requests with closed gate"
        );
        assert_eq!(
            request_count.load(Ordering::SeqCst),
            0,
            "0 total API requests with closed gate (no read/write reaches API)"
        );

        let j_disk = journal::load_journal(&dir.join("journal.json")).unwrap();
        assert_eq!(
            j_disk.state,
            RunState::Paused,
            "journal durably Paused on disk"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    // ExplicitCleanupBlocked preservation is covered by existing production tests:
    //   executor::tests::explicit_cleanup_incomplete_ref_scan_persists_retryable_before_delete
    //     → ref-guard failure → ExplicitCleanupBlocked → DELETE=0
    //   main::tests::mark_failed_preserving_retryable_preserves_blocked
    //     → journal.mark_failed_preserving_retryable skips ExplicitCleanupBlocked

    /// Test 2: ResumeCleanup with a pending DeleteRequested decision.
    /// Resource returns 404 on GET → confirmed Gone via endpoint LIST.
    /// Exact request recording with panic on unexpected method/path.
    #[tokio::test]
    async fn workflow_resume_cleanup_pending_decision_exact_requests() {
        let requests: Arc<std::sync::Mutex<Vec<(String, String)>>> =
            Arc::new(std::sync::Mutex::new(vec![]));
        let req_clone = requests.clone();

        let (mock_service, handle) =
            tower_test::mock::pair::<http::Request<Body>, http::Response<Body>>();

        let spawned = tokio::spawn(async move {
            let mut handle = pin!(handle);
            while let Some((req, send)) = handle.next_request().await {
                let method = req.method().to_string();
                let uri = req.uri().to_string();
                req_clone
                    .lock()
                    .unwrap()
                    .push((method.clone(), uri.clone()));

                if method == "GET" && uri == "/api/v1/namespaces/test-ns/configmaps/cleanup-cm" {
                    send.send_response(not_found_response());
                } else if method == "GET"
                    && uri.starts_with("/api/v1/namespaces/test-ns/configmaps?")
                    && uri.contains("limit=1")
                {
                    send.send_response(json_response(serde_json::json!({
                        "apiVersion": "v1", "kind": "ConfigMapList",
                        "metadata": {"resourceVersion": "1"}, "items": []
                    })));
                } else {
                    panic!(
                        "Unexpected request: {} {} (all requests so far: {:?})",
                        method,
                        uri,
                        req_clone.lock().unwrap()
                    );
                }
            }
        });

        let client = kube::Client::new(mock_service, "test-ns");
        let plan = make_plan_with_delete("cleanup-cm", "uid-cleanup");
        let mut j = make_test_journal_for_workflow(RunState::InteractiveCleanup, 1, 1);
        j.cleanup_decisions.push(journal::CleanupDecision {
            resource: crate::kube::resource::ResourceId {
                group: String::new(),
                version: "v1".to_string(),
                kind: "ConfigMap".to_string(),
                namespace: Some("test-ns".to_string()),
                name: "cleanup-cm".to_string(),
                uid: Some("uid-cleanup".to_string()),
            },
            action: "delete".to_string(),
            bound_uid: Some("uid-cleanup".to_string()),
            result: Some(CleanupResult::DeleteRequested),
            approved_spec_name: None,
        });
        let j_clone = j.clone();
        let (store, dir) = make_journal_store(j);
        let km = test_kind_map();
        let gk = test_gk_map();
        let gvk = std::collections::HashMap::new();
        let gvr = std::collections::HashMap::new();
        let gate = Arc::new(MutationGate::new(4));

        let ctx = WorkflowContext {
            client: &client,
            plan: &plan,
            kind_map: &km,
            gk_map: &gk,
            gvk_map: &gvk,
            gvr_map: &gvr,
        };

        let result = run_teardown_workflow(
            &ctx,
            Some(&store),
            &gate,
            WorkflowStart::ResumeCleanup {
                journal: &j_clone,
                main_complete: true,
                paused_from_residual: false,
            },
        )
        .await;

        drop(client);
        let _ = spawned.await;

        let recorded = requests.lock().unwrap().clone();

        // Exact request assertions
        let object_gets: Vec<_> = recorded
            .iter()
            .filter(|(m, u)| m == "GET" && u == "/api/v1/namespaces/test-ns/configmaps/cleanup-cm")
            .collect();
        assert_eq!(
            object_gets.len(),
            1,
            "exactly 1 object GET for cleanup-cm, got {}",
            object_gets.len()
        );

        let endpoint_lists: Vec<_> = recorded
            .iter()
            .filter(|(m, u)| {
                m == "GET"
                    && u.starts_with("/api/v1/namespaces/test-ns/configmaps?")
                    && u.contains("limit=1")
            })
            .collect();
        assert_eq!(
            endpoint_lists.len(),
            1,
            "exactly 1 endpoint LIST with limit=1, got {}",
            endpoint_lists.len()
        );

        let deletes: Vec<_> = recorded.iter().filter(|(m, _)| m == "DELETE").collect();
        assert_eq!(deletes.len(), 0, "0 DELETEs (resource already gone)");

        // Result: this fixture has Unverifiable generation identity,
        // so the mandatory re-audit generation check will fail with Err.
        assert!(result.is_err(), "Unverifiable generation → Err on re-audit");

        // Journal must reflect cleanup result despite re-audit error
        let j_disk = journal::load_journal(&dir.join("journal.json")).unwrap();
        let decision = j_disk.cleanup_decisions.first();
        assert!(decision.is_some(), "cleanup decision must be present");
        let d = decision.unwrap();
        assert!(
            matches!(d.result, Some(CleanupResult::Gone)),
            "cleanup decision result must be Gone after 404 reconciliation, got {:?}",
            d.result
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    // ── require_completed tests ──

    fn make_outcome(state: RunState, cleanup_failure: Option<&str>) -> WorkflowOutcome {
        WorkflowOutcome {
            final_state: state,
            result: ExecutionResult {
                phases_completed: 5,
                phases_total: 7,
                deleted: vec![],
                already_gone: vec![],
                failed: vec![],
                barrier_timeout: None,
                kept: vec![],
                reviewed: vec![],
            },
            cleanup_failure: cleanup_failure.map(String::from),
        }
    }

    #[test]
    fn require_completed_ok_for_apply_completed_no_failure() {
        let o = make_outcome(RunState::ApplyCompleted, None);
        assert!(require_completed(&o).is_ok());
    }

    #[test]
    fn require_completed_err_for_paused() {
        let o = make_outcome(RunState::Paused, None);
        let err = require_completed(&o).unwrap_err();
        assert!(
            err.to_string().contains("paused"),
            "Paused → Err mentioning paused, got: {}",
            err
        );
    }

    #[test]
    fn require_completed_err_for_failed() {
        let o = make_outcome(RunState::Failed, None);
        assert!(require_completed(&o).is_err());
    }

    #[test]
    fn require_completed_err_for_cleanup_failure() {
        let o = make_outcome(RunState::ApplyCompleted, Some("residual incomplete"));
        let err = require_completed(&o).unwrap_err();
        assert!(
            err.to_string().contains("residual incomplete"),
            "cleanup_failure → Err with reason, got: {}",
            err
        );
    }

    #[test]
    fn require_completed_rejects_paused_and_failed_in_all_modes() {
        let o_paused = make_outcome(RunState::Paused, None);
        assert!(require_completed(&o_paused).is_err(), "Paused → Err always");

        let o_failed = make_outcome(RunState::Failed, Some("error"));
        assert!(
            require_completed(&o_failed).is_err(),
            "Failed+cleanup → Err always"
        );

        let o_ok = make_outcome(RunState::ApplyCompleted, None);
        assert!(
            require_completed(&o_ok).is_ok(),
            "ApplyCompleted+None → Ok always"
        );
    }

    // ── shared gate cancellation test ──

    #[tokio::test]
    async fn shared_gate_closed_blocks_second_entry() {
        let gate = Arc::new(MutationGate::new(4));

        // Entry 1: gate open → would proceed (simulated)
        assert!(gate.is_open(), "gate must be open for first entry");

        // Simulate Ctrl-C between entries
        gate.close_and_drain().await;

        // Entry 2: gate closed → must not proceed
        assert!(!gate.is_open(), "gate must be closed for second entry");
    }

    // ── Batch production tests using run_batch_entries ──

    fn ok_outcome() -> WorkflowOutcome {
        make_outcome(RunState::ApplyCompleted, None)
    }

    #[allow(dead_code)]
    fn failed_outcome() -> WorkflowOutcome {
        make_outcome(RunState::Failed, None)
    }

    fn paused_outcome() -> WorkflowOutcome {
        make_outcome(RunState::Paused, None)
    }

    #[tokio::test]
    async fn batch_two_present_entries_success() {
        let gate = Arc::new(MutationGate::new(4));
        let mut plan_count = 0usize;
        let entries = vec![
            ClassifiedBatchEntry {
                source_index: 0,
                name: "op-a".to_string(),
                kind: BatchEntryKind::PlanAndApply,
            },
            ClassifiedBatchEntry {
                source_index: 1,
                name: "op-b".to_string(),
                kind: BatchEntryKind::PlanAndApply,
            },
        ];
        let result = run_batch_entries(
            &entries,
            &gate,
            |_idx, _name| {
                plan_count += 1;
                async { Ok(ok_outcome()) }
            },
            |_| async { Ok(ok_outcome()) },
        )
        .await;
        assert_eq!(result.len(), 2);
        assert_eq!(result[0], ("op-a".to_string(), BatchOutcome::Succeeded));
        assert_eq!(result[1], ("op-b".to_string(), BatchOutcome::Succeeded));
    }

    #[tokio::test]
    async fn batch_present_plus_missing_skip() {
        let gate = Arc::new(MutationGate::new(4));
        let mut runner_count = 0usize;
        let entries = vec![
            ClassifiedBatchEntry {
                source_index: 0,
                name: "op-a".to_string(),
                kind: BatchEntryKind::PlanAndApply,
            },
            ClassifiedBatchEntry {
                source_index: 1,
                name: "op-missing".to_string(),
                kind: BatchEntryKind::Skip,
            },
        ];
        let result = run_batch_entries(
            &entries,
            &gate,
            |_, _| {
                runner_count += 1;
                async { Ok(ok_outcome()) }
            },
            |_| async { Ok(ok_outcome()) },
        )
        .await;
        assert_eq!(result.len(), 2);
        assert_eq!(result[0].1, BatchOutcome::Succeeded);
        assert_eq!(result[1].1, BatchOutcome::Skipped);
        assert_eq!(runner_count, 1, "runner invoked only for present entry");
    }

    #[tokio::test]
    async fn batch_missing_without_skip_baseline_error() {
        let entries = vec![
            ("op-a".to_string(), BaselineObservation::Present),
            ("op-missing".to_string(), BaselineObservation::Missing),
        ];
        let classify_result = classify_batch_entries(&entries, false, false);
        assert!(
            classify_result.is_err(),
            "missing + skip_missing=false → Err before run_batch_entries"
        );
        let err = classify_result.unwrap_err().to_string();
        assert!(err.contains("op-missing"), "error names missing operator");
    }

    #[tokio::test]
    async fn batch_second_entry_failure_stops_remaining() {
        let gate = Arc::new(MutationGate::new(4));
        let mut call_count = 0usize;
        let entries = vec![
            ClassifiedBatchEntry {
                source_index: 0,
                name: "op-a".to_string(),
                kind: BatchEntryKind::PlanAndApply,
            },
            ClassifiedBatchEntry {
                source_index: 1,
                name: "op-b".to_string(),
                kind: BatchEntryKind::PlanAndApply,
            },
            ClassifiedBatchEntry {
                source_index: 2,
                name: "op-c".to_string(),
                kind: BatchEntryKind::PlanAndApply,
            },
        ];
        let result = run_batch_entries(
            &entries,
            &gate,
            |_idx, name| {
                call_count += 1;
                let fail = name == "op-b";
                async move {
                    if fail {
                        anyhow::bail!("simulated failure")
                    } else {
                        Ok(ok_outcome())
                    }
                }
            },
            |_| async { Ok(ok_outcome()) },
        )
        .await;
        assert_eq!(result.len(), 3);
        assert_eq!(result[0].1, BatchOutcome::Succeeded, "first retained");
        assert_eq!(result[1].1, BatchOutcome::Failed(1), "second failed");
        assert_eq!(result[2].1, BatchOutcome::NotRun, "third not run");
        assert_eq!(call_count, 2, "runner stopped after failure");
    }

    #[tokio::test]
    async fn batch_paused_outcome_is_failure() {
        let gate = Arc::new(MutationGate::new(4));
        let entries = vec![
            ClassifiedBatchEntry {
                source_index: 0,
                name: "op-a".to_string(),
                kind: BatchEntryKind::PlanAndApply,
            },
            ClassifiedBatchEntry {
                source_index: 1,
                name: "op-b".to_string(),
                kind: BatchEntryKind::PlanAndApply,
            },
        ];
        let result = run_batch_entries(
            &entries,
            &gate,
            |_, _| async { Ok(paused_outcome()) },
            |_| async { Ok(ok_outcome()) },
        )
        .await;
        assert_eq!(result[0].1, BatchOutcome::Failed(1), "Paused → Failed");
        assert_eq!(result[1].1, BatchOutcome::NotRun, "remaining NotRun");
    }

    #[tokio::test]
    async fn batch_pending_resume_selects_resume_runner() {
        let gate = Arc::new(MutationGate::new(4));
        let mut apply_count = 0usize;
        let mut resume_count = 0usize;
        let entries = vec![ClassifiedBatchEntry {
            source_index: 0,
            name: "op-a".to_string(),
            kind: BatchEntryKind::PendingResume {
                run_id: "run-123".to_string(),
            },
        }];
        let result = run_batch_entries(
            &entries,
            &gate,
            |_, _| {
                apply_count += 1;
                async { Ok(ok_outcome()) }
            },
            |run_id| {
                resume_count += 1;
                assert_eq!(run_id, "run-123", "correct run_id passed to resume runner");
                async { Ok(ok_outcome()) }
            },
        )
        .await;
        assert_eq!(apply_count, 0, "apply runner not called for pending resume");
        assert_eq!(resume_count, 1, "resume runner called once");
        assert_eq!(result[0].1, BatchOutcome::Succeeded);
    }

    #[tokio::test]
    async fn batch_gate_closed_after_entry1_blocks_entry2() {
        let gate = Arc::new(MutationGate::new(4));
        let gate_clone = gate.clone();
        let mut call_count = 0usize;
        let entries = vec![
            ClassifiedBatchEntry {
                source_index: 0,
                name: "op-a".to_string(),
                kind: BatchEntryKind::PlanAndApply,
            },
            ClassifiedBatchEntry {
                source_index: 1,
                name: "op-b".to_string(),
                kind: BatchEntryKind::PlanAndApply,
            },
        ];
        let result = run_batch_entries(
            &entries,
            &gate,
            |_, _| {
                call_count += 1;
                let g = gate_clone.clone();
                async move {
                    g.close_and_drain().await;
                    Ok(ok_outcome())
                }
            },
            |_| async { Ok(ok_outcome()) },
        )
        .await;
        assert_eq!(call_count, 1, "only first entry invoked");
        assert_eq!(result[0].1, BatchOutcome::Succeeded, "first completed");
        assert_eq!(
            result[1].1,
            BatchOutcome::NotRun,
            "second not run (gate closed)"
        );
    }

    #[tokio::test]
    async fn batch_same_name_entries_use_distinct_source_index() {
        let gate = Arc::new(MutationGate::new(4));
        let mut received_indices = Vec::new();
        let entries = vec![
            ClassifiedBatchEntry {
                source_index: 0,
                name: "op-a".to_string(),
                kind: BatchEntryKind::PlanAndApply,
            },
            ClassifiedBatchEntry {
                source_index: 1,
                name: "op-a".to_string(),
                kind: BatchEntryKind::PlanAndApply,
            },
        ];
        let result = run_batch_entries(
            &entries,
            &gate,
            |idx, _name| {
                received_indices.push(idx);
                async { Ok(ok_outcome()) }
            },
            |_| async { Ok(ok_outcome()) },
        )
        .await;
        assert_eq!(
            received_indices,
            vec![0, 1],
            "runner receives distinct source indices 0 and 1"
        );
        assert_eq!(result.len(), 2);
        assert_eq!(result[0].1, BatchOutcome::Succeeded);
        assert_eq!(result[1].1, BatchOutcome::Succeeded);
    }

    #[tokio::test]
    async fn batch_skip_preserves_source_index() {
        let gate = Arc::new(MutationGate::new(4));
        let mut received_indices = Vec::new();
        let entries = vec![
            ClassifiedBatchEntry {
                source_index: 0,
                name: "op-a".to_string(),
                kind: BatchEntryKind::PlanAndApply,
            },
            ClassifiedBatchEntry {
                source_index: 1,
                name: "op-skip".to_string(),
                kind: BatchEntryKind::Skip,
            },
            ClassifiedBatchEntry {
                source_index: 2,
                name: "op-c".to_string(),
                kind: BatchEntryKind::PlanAndApply,
            },
        ];
        let result = run_batch_entries(
            &entries,
            &gate,
            |idx, _name| {
                received_indices.push(idx);
                async { Ok(ok_outcome()) }
            },
            |_| async { Ok(ok_outcome()) },
        )
        .await;
        assert_eq!(
            received_indices,
            vec![0, 2],
            "skip does not shift source indices"
        );
        assert_eq!(result[1].1, BatchOutcome::Skipped);
    }

    #[test]
    fn batch_duplicate_explicit_target_rejected() {
        let specs = vec![
            DeleteResourceSpec {
                group: "test.io".to_string(),
                kind: "Widget".to_string(),
                namespace: Some("ns".to_string()),
                name: "w1".to_string(),
            },
            DeleteResourceSpec {
                group: "test.io".to_string(),
                kind: "Widget".to_string(),
                namespace: Some("ns".to_string()),
                name: "w1".to_string(),
            },
        ];
        let result = validate_delete_resource_specs(&specs);
        assert!(result.is_err(), "duplicate specs must be rejected");
        let err = result.unwrap_err().to_string();
        assert!(
            err.contains("Duplicate") && err.contains("Widget"),
            "error must mention Duplicate and kind, got: {}",
            err
        );
    }

    #[test]
    fn validate_delete_resource_specs_accepts_unique() {
        let specs = vec![
            DeleteResourceSpec {
                group: "test.io".to_string(),
                kind: "Widget".to_string(),
                namespace: Some("ns".to_string()),
                name: "w1".to_string(),
            },
            DeleteResourceSpec {
                group: "test.io".to_string(),
                kind: "Widget".to_string(),
                namespace: Some("ns".to_string()),
                name: "w2".to_string(),
            },
        ];
        assert!(validate_delete_resource_specs(&specs).is_ok());
    }

    #[test]
    fn classify_missing_without_skip_returns_err() {
        let entries = vec![
            ("op-a".to_string(), BaselineObservation::Present),
            ("op-b".to_string(), BaselineObservation::Missing),
        ];
        let result = classify_batch_entries(&entries, false, false);
        assert!(result.is_err(), "missing + skip_missing=false → Err");
        let err = result.unwrap_err().to_string();
        assert!(
            err.contains("op-b"),
            "error must name the missing operator, got: {}",
            err
        );
    }

    #[test]
    fn classify_missing_with_skip_returns_skip() {
        let entries = vec![
            ("op-a".to_string(), BaselineObservation::Present),
            ("op-b".to_string(), BaselineObservation::Missing),
        ];
        let classified = classify_batch_entries(&entries, true, false).unwrap();
        assert_eq!(classified.len(), 2);
        assert!(matches!(classified[0].kind, BatchEntryKind::PlanAndApply));
        assert_eq!(classified[0].source_index, 0);
        assert!(matches!(classified[1].kind, BatchEntryKind::Skip));
        assert_eq!(classified[1].source_index, 1);
    }

    #[test]
    fn classify_pending_resume_dry_run() {
        let entries = vec![(
            "op-a".to_string(),
            BaselineObservation::PendingResume {
                run_id: "run-1".to_string(),
            },
        )];
        let dry = classify_batch_entries(&entries, true, true).unwrap();
        assert!(
            matches!(&dry[0].kind, BatchEntryKind::DryRunResume { run_id } if run_id == "run-1")
        );
        assert_eq!(dry[0].source_index, 0);
        let live = classify_batch_entries(&entries, true, false).unwrap();
        assert!(
            matches!(&live[0].kind, BatchEntryKind::PendingResume { run_id } if run_id == "run-1")
        );
        assert_eq!(live[0].source_index, 0);
    }
}
