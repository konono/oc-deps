use std::sync::Arc;

use anyhow::Context;

use crate::kube::discovery::{GroupKindMap, GvkMap, GvrMap, KindMap};
use crate::teardown::audit::{self, OperatorGenerationState};
use crate::teardown::executor::{self, ExecutionResult, print_execution_result};
use crate::teardown::journal::{self, JournalStore, RunState};
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
        true, // force — advisory warnings always shown
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
                run_post_execution_audit(ctx, store).await
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
                                    &crate::teardown::permit::MutationGate::new(16),
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
