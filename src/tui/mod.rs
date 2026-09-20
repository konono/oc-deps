mod renderer;

use std::sync::Arc;

use anyhow::{Context, Result, bail};
use crossterm::{
    event::{self, Event, KeyCode, KeyEvent, KeyModifiers},
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
    execute,
};
use ratatui::{
    backend::CrosstermBackend,
    Terminal,
};

use crate::analyzers::olm::OperatorInstance;
use crate::kube::discovery::{GroupKindMap, GvkMap, GvrMap, KindMap};
use crate::kube::resource::ResourceId;
use crate::teardown::app::{
    AppCommand, AppScreen, AppState, DraftAction, apply_command,
};
use crate::teardown::audit::{self, OperatorGenerationState};
use crate::teardown::executor::{self, ExecutionResult};
use crate::teardown::journal::{self, JournalStore, RunState, ResidualStatus, CleanupDecision};
use crate::teardown::permit::MutationGate;
use crate::teardown::planner::{Action, TeardownPlan};
use crate::teardown::plan::ReviewMetadata;

/// Run the interactive TUI workflow: Plan Review → Execution → Residual Cleanup.
///
/// The TUI never calls Kubernetes DELETE directly — all mutations go through
/// the core executor's UID-preconditioned DELETE.
pub async fn run_tui(
    client: &::kube::Client,
    plan: &mut TeardownPlan,
    target_operators: &[&OperatorInstance],
    kind_map: &KindMap,
    gk_map: &GroupKindMap,
    gvk_map: &GvkMap,
    gvr_map: &GvrMap,
    journal_store: &Arc<JournalStore>,
    gate: &Arc<MutationGate>,
    force: bool,
) -> Result<()> {
    // Enter TUI mode
    enable_raw_mode().context("Failed to enable raw mode")?;
    let mut stdout = std::io::stdout();
    execute!(stdout, EnterAlternateScreen).context("Failed to enter alternate screen")?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend).context("Failed to create terminal")?;

    let result = run_tui_inner(
        &mut terminal, client, plan, target_operators,
        kind_map, gk_map, gvk_map, gvr_map,
        journal_store, gate, force,
    ).await;

    // Always restore terminal
    disable_raw_mode().ok();
    execute!(terminal.backend_mut(), LeaveAlternateScreen).ok();
    terminal.show_cursor().ok();

    result
}

async fn run_tui_inner(
    terminal: &mut Terminal<CrosstermBackend<std::io::Stdout>>,
    client: &::kube::Client,
    plan: &mut TeardownPlan,
    target_operators: &[&OperatorInstance],
    kind_map: &KindMap,
    gk_map: &GroupKindMap,
    gvk_map: &GvkMap,
    gvr_map: &GvrMap,
    journal_store: &Arc<JournalStore>,
    gate: &Arc<MutationGate>,
    force: bool,
) -> Result<()> {
    let mut app = AppState::new();
    let mut selected_index: usize = 0;

    // Collect REVIEW items for Plan Review navigation
    let review_items: Vec<(usize, usize, ResourceId, Option<ReviewMetadata>)> = plan
        .phases
        .iter()
        .enumerate()
        .flat_map(|(pi, phase)| {
            phase.actions.iter().enumerate().filter_map(move |(ai, action)| {
                if let Action::Review { resource, metadata, .. } = action {
                    Some((pi, ai, resource.clone(), metadata.clone()))
                } else {
                    None
                }
            })
        })
        .collect();

    // ── Screen 1: Plan Review ──
    loop {
        terminal.draw(|f| {
            renderer::draw_plan_review(f, plan, &app, &review_items, selected_index);
        })?;

        if event::poll(std::time::Duration::from_millis(100))? {
            if let Event::Key(key) = event::read()? {
                match key.code {
                    KeyCode::Char('q') | KeyCode::Esc => return Ok(()),
                    KeyCode::Char('c') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                        return Ok(());
                    }
                    KeyCode::Up | KeyCode::Char('k') if !review_items.is_empty() => {
                        selected_index = selected_index.saturating_sub(1);
                    }
                    KeyCode::Down | KeyCode::Char('j') if !review_items.is_empty() => {
                        if selected_index + 1 < review_items.len() {
                            selected_index += 1;
                        }
                    }
                    KeyCode::Char('a') if !review_items.is_empty() => {
                        let (_, _, ref res, _) = review_items[selected_index];
                        let _ = apply_command(&mut app, &AppCommand::ApproveReview {
                            resource: res.clone(),
                        });
                    }
                    KeyCode::Char('K') if !review_items.is_empty() => {
                        let (_, _, ref res, _) = review_items[selected_index];
                        let _ = apply_command(&mut app, &AppCommand::KeepReview {
                            resource: res.clone(),
                        });
                    }
                    KeyCode::Char('s') | KeyCode::Enter => {
                        break; // Proceed to execution
                    }
                    _ => {}
                }
            }
        }
    }

    // ── Fresh revalidation + UID binding for draft overrides ──
    // Temporarily leave TUI for logging
    disable_raw_mode().ok();
    execute!(terminal.backend_mut(), LeaveAlternateScreen).ok();

    if !app.draft_overrides.is_empty() {
        eprintln!("  Applying {} draft override(s) with fresh validation...", app.draft_overrides.len());
        let audit_ctx = journal::build_audit_context(plan, target_operators, gk_map);
        let j = journal_store.read().await;
        let operator_snapshot = &j.operator;

        let mut mutated = plan.clone();
        for ovr in &app.draft_overrides {
            let found = mutated.phases.iter().any(|p| {
                p.actions.iter().any(|a| {
                    if let Action::Review { resource, .. } = a {
                        resource.group == ovr.resource.group
                            && resource.version == ovr.resource.version
                            && resource.kind == ovr.resource.kind
                            && resource.name == ovr.resource.name
                            && resource.namespace == ovr.resource.namespace
                    } else {
                        false
                    }
                })
            });
            if !found {
                bail!("Override for {}/{} does not match any REVIEW action",
                    ovr.resource.kind, ovr.resource.name);
            }

            for phase in &mut mutated.phases {
                for action in &mut phase.actions {
                    if let Action::Review { resource, reason, metadata, .. } = action {
                        if resource.group == ovr.resource.group
                            && resource.version == ovr.resource.version
                            && resource.kind == ovr.resource.kind
                            && resource.name == ovr.resource.name
                            && resource.namespace == ovr.resource.namespace
                        {
                            match ovr.new_action {
                                DraftAction::Delete => {
                                    let ovr_uid = ovr.resource.uid.as_deref().unwrap_or("");
                                    let plan_uid = resource.uid.as_deref().unwrap_or("");
                                    // Interactive overrides may not carry UID — use plan UID
                                    // and verify via fresh GET
                                    if let Some((api, _)) = crate::kube::resource::resolve_api(
                                        client, resource, kind_map, gk_map,
                                    ) {
                                        match api.get(&resource.name).await {
                                            Ok(obj) => {
                                                let live_uid = obj.metadata.uid.as_deref().unwrap_or("");
                                                if live_uid.is_empty() {
                                                    bail!("Cannot apply override for {}/{}: live resource has no UID",
                                                        resource.kind, resource.name);
                                                }
                                                if !plan_uid.is_empty() && live_uid != plan_uid {
                                                    bail!("UID changed for {}/{}: plan {} vs live {}",
                                                        resource.kind, resource.name, plan_uid, live_uid);
                                                }
                                                // Basis drift validation
                                                let action_meta = metadata.clone();
                                                if let Err(reason) = crate::revalidate_review_basis(
                                                    &obj, &action_meta, &audit_ctx, operator_snapshot,
                                                ) {
                                                    bail!("BLOCKED: {}/{} — basis drift: {}",
                                                        resource.kind, resource.name, reason);
                                                }
                                                let mut bound = resource.clone();
                                                bound.uid = Some(live_uid.to_string());
                                                *action = Action::Delete {
                                                    resource: bound,
                                                    reason: format!("{} (approved in TUI)", reason),
                                                };
                                            }
                                            Err(::kube::Error::Api(ref err)) if err.code == 404 => {
                                                eprintln!("  ⚠ {}/{} no longer present — skipped", resource.kind, resource.name);
                                            }
                                            Err(e) => bail!("Cannot verify {}/{}: {}", resource.kind, resource.name, e),
                                        }
                                    }
                                }
                                DraftAction::Keep => {
                                    *action = Action::Keep {
                                        resource: resource.clone(),
                                        reason: format!("{} (kept in TUI)", reason),
                                    };
                                }
                            }
                        }
                    }
                }
            }
        }
        *plan = mutated;
    }

    let _ = apply_command(&mut app, &AppCommand::StartExecution);

    // ── Screen 2: Execution ──
    eprintln!("\n\x1b[1m▶ Starting execution...\x1b[0m\n");

    let exec_result = executor::execute_plan(
        client, plan, kind_map, gk_map, gvk_map, gvr_map,
        false, force,
        Some(journal_store.as_ref()),
        Some(gate.as_ref()),
        0,
        true, // skip_confirm — TUI already reviewed
    ).await;

    match exec_result {
        Ok(result) => {
            let final_state = if !gate.is_open() {
                RunState::Paused
            } else if result.phases_completed == result.phases_total
                && result.failed.is_empty()
                && result.barrier_timeout.is_none()
            {
                RunState::ApplyCompleted
            } else {
                RunState::Failed
            };

            journal_store.update(|j| {
                j.state = final_state.clone();
                j.execution.phases_total = result.phases_total;
            }).await.context("Failed to persist final state")?;

            executor::print_execution_result(&result);

            if final_state == RunState::Failed {
                bail!("Teardown failed");
            }
            if final_state == RunState::Paused {
                eprintln!("⏸ Paused. Use 'teardown resume' to continue.");
                return Ok(());
            }

            // ── Screen 3: Residual Cleanup ──
            run_residual_cleanup(
                client, plan, journal_store, gate,
                kind_map, gk_map,
            ).await?;
        }
        Err(e) => {
            if let Some(store) = Some(journal_store) {
                let _ = store.update(|j| { j.state = RunState::Failed; }).await;
            }
            return Err(e);
        }
    }

    Ok(())
}

/// Residual cleanup flow — shared between TUI and script paths.
pub async fn run_residual_cleanup(
    client: &::kube::Client,
    plan: &TeardownPlan,
    journal_store: &Arc<JournalStore>,
    gate: &Arc<MutationGate>,
    kind_map: &KindMap,
    gk_map: &GroupKindMap,
) -> Result<()> {
    let j = journal_store.read().await;

    // Check generation
    let gen_state = audit::check_operator_generation(
        client, &j.operator, &j.audit_context.csv_baseline,
    ).await;

    match gen_state {
        OperatorGenerationState::Absent => {
            eprintln!("\n🔍 Running post-apply residual audit...");
            match audit::run_residual_audit(client, &j).await {
                Ok(audit_result) => {
                    let status = audit::residual_status_from_audit(&audit_result);
                    audit::print_residual_audit(&audit_result, &j);

                    // Re-verify generation before saving
                    let gen_recheck = audit::check_operator_generation(
                        client, &j.operator, &j.audit_context.csv_baseline,
                    ).await;
                    if matches!(gen_recheck, OperatorGenerationState::Absent) {
                        journal_store.update(|j| {
                            j.residual_status = status;
                            j.audit_revision += 1;
                            j.last_residual_audit = Some(audit_result);
                        }).await
                        .context("Failed to persist audit results")?;
                    } else {
                        eprintln!("⚠ Operator generation changed during audit; discarding results");
                    }
                }
                Err(e) => {
                    eprintln!("⚠ Residual audit failed: {}", e);
                }
            }
        }
        OperatorGenerationState::SameGeneration => {
            eprintln!("\n⚠ Original operator generation is still active.");
            eprintln!("  Resume normal teardown instead of residual cleanup.");
        }
        OperatorGenerationState::Reappeared => {
            eprintln!("\n⚠ A newer installation of the operator exists.");
            eprintln!("  Create a new teardown plan for the current installation.");
        }
        OperatorGenerationState::Unknown(reason) => {
            eprintln!("\n⚠ Cannot verify operator generation: {}", reason);
        }
    }

    Ok(())
}
