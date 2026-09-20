mod renderer;

use std::sync::Arc;
use std::time::Instant;

use anyhow::{Context, Result, bail};
use crossterm::{
    event::{self, Event, KeyCode, KeyModifiers},
    execute,
    terminal::{EnterAlternateScreen, LeaveAlternateScreen, disable_raw_mode, enable_raw_mode},
};
use ratatui::{Terminal, backend::CrosstermBackend};

use crate::analyzers::olm::OperatorInstance;
use crate::kube::discovery::{GroupKindMap, GvkMap, GvrMap, KindMap};
use crate::kube::resource::ResourceId;
use crate::teardown::app::{AppCommand, AppState, DraftAction, apply_command};
use crate::teardown::audit::{self, OperatorGenerationState};
use crate::teardown::executor::{self, ExecutionResult};
use crate::teardown::journal::{self, JournalStore, RunState};
use crate::teardown::permit::MutationGate;
use crate::teardown::plan::ReviewMetadata;
use crate::teardown::planner::{Action, TeardownPlan};
use crate::teardown::runtime::ResourceRuntimeState;

/// Run the interactive TUI workflow: Plan Review → Execution → Residual Cleanup.
///
/// The TUI never calls Kubernetes DELETE directly — all mutations go through
/// the core executor's UID-preconditioned DELETE.
#[allow(clippy::too_many_arguments)]
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
    enable_raw_mode().context("Failed to enable raw mode")?;
    let mut stdout = std::io::stdout();
    execute!(stdout, EnterAlternateScreen).context("Failed to enter alternate screen")?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend).context("Failed to create terminal")?;

    let result = run_tui_inner(
        &mut terminal,
        client,
        plan,
        target_operators,
        kind_map,
        gk_map,
        gvk_map,
        gvr_map,
        journal_store,
        gate,
        force,
    )
    .await;

    // Always restore terminal
    disable_raw_mode().ok();
    execute!(terminal.backend_mut(), LeaveAlternateScreen).ok();
    terminal.show_cursor().ok();

    result
}

#[allow(clippy::too_many_arguments)]
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
            phase
                .actions
                .iter()
                .enumerate()
                .filter_map(move |(ai, action)| {
                    if let Action::Review {
                        resource, metadata, ..
                    } = action
                    {
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

        if event::poll(std::time::Duration::from_millis(100))?
            && let Event::Key(key) = event::read()?
        {
            match key.code {
                KeyCode::Char('q') | KeyCode::Esc => return Ok(()),
                KeyCode::Char('c') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                    return Ok(());
                }
                KeyCode::Up | KeyCode::Char('k') if !review_items.is_empty() => {
                    selected_index = selected_index.saturating_sub(1);
                }
                KeyCode::Down | KeyCode::Char('j')
                    if !review_items.is_empty() && selected_index + 1 < review_items.len() =>
                {
                    selected_index += 1;
                }
                KeyCode::Char('a') | KeyCode::Char(' ') if !review_items.is_empty() => {
                    let (_, _, ref res, _) = review_items[selected_index];
                    let _ = apply_command(
                        &mut app,
                        &AppCommand::ApproveReview {
                            resource: res.clone(),
                        },
                    );
                }
                KeyCode::Char('K') if !review_items.is_empty() => {
                    let (_, _, ref res, _) = review_items[selected_index];
                    let _ = apply_command(
                        &mut app,
                        &AppCommand::KeepReview {
                            resource: res.clone(),
                        },
                    );
                }
                KeyCode::Char('s') | KeyCode::Enter => {
                    break; // Proceed to execution
                }
                _ => {}
            }
        }
    }

    // ── Fresh revalidation + UID binding for draft overrides ──
    // Temporarily leave TUI for logging
    disable_raw_mode().ok();
    execute!(terminal.backend_mut(), LeaveAlternateScreen).ok();

    if !app.draft_overrides.is_empty() {
        eprintln!(
            "  Applying {} draft override(s) with fresh validation...",
            app.draft_overrides.len()
        );
        let audit_ctx = journal::build_audit_context(plan, target_operators, gk_map);
        let j = journal_store.read().await;
        let operator_snapshot = &j.operator;

        // Pre-fetch CRD list once for all override validations
        eprintln!("  Fetching CRD list for basis verification...");
        let crd_items = crate::fetch_crd_list(client)
            .await
            .map_err(|e| anyhow::anyhow!("CRD list fetch failed: {}", e))?;

        let mut mutated = plan.clone();
        let override_total = app.draft_overrides.len();
        for (ovr_idx, ovr) in app.draft_overrides.iter().enumerate() {
            if !gate.is_open() {
                eprintln!("  ⏸ Gate closed — stopping override validation");
                journal_store
                    .update(|j| {
                        j.state = RunState::Paused;
                    })
                    .await
                    .context("Failed to persist Paused during override validation")?;
                return Ok(());
            }
            eprintln!(
                "  [{}/{}] Validating {}/{}...",
                ovr_idx + 1,
                override_total,
                ovr.resource.kind,
                ovr.resource.name
            );
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
                bail!(
                    "Override for {}/{} does not match any REVIEW action",
                    ovr.resource.kind,
                    ovr.resource.name
                );
            }

            for phase in &mut mutated.phases {
                for action in &mut phase.actions {
                    if let Action::Review {
                        resource,
                        reason,
                        metadata,
                        ..
                    } = action
                        && resource.group == ovr.resource.group
                        && resource.version == ovr.resource.version
                        && resource.kind == ovr.resource.kind
                        && resource.name == ovr.resource.name
                        && resource.namespace == ovr.resource.namespace
                    {
                        match ovr.new_action {
                            DraftAction::Delete => {
                                let ovr_uid = ovr.resource.uid.as_deref().unwrap_or("");
                                let plan_uid = resource.uid.as_deref().unwrap_or("");
                                if plan_uid.is_empty() {
                                    bail!(
                                        "Cannot approve DELETE for {}/{}: plan resource has no UID",
                                        resource.kind,
                                        resource.name
                                    );
                                }
                                if ovr_uid.is_empty() {
                                    bail!(
                                        "Cannot approve DELETE for {}/{} without UID in approval",
                                        resource.kind,
                                        resource.name
                                    );
                                }
                                if ovr_uid != plan_uid {
                                    bail!(
                                        "Override UID {} does not match plan UID {} for {}/{}",
                                        ovr_uid,
                                        plan_uid,
                                        resource.kind,
                                        resource.name
                                    );
                                }
                                let (api, _) = crate::kube::resource::resolve_api(
                                        client, resource, kind_map, gk_map,
                                    ).ok_or_else(|| anyhow::anyhow!(
                                        "Cannot resolve API for {}/{} — refusing to skip approved DELETE override",
                                        resource.kind, resource.name
                                    ))?;
                                match api.get(&resource.name).await {
                                    Ok(obj) => {
                                        let live_uid = obj.metadata.uid.as_deref().unwrap_or("");
                                        if live_uid.is_empty() {
                                            bail!(
                                                "Cannot apply override for {}/{}: live resource has no UID",
                                                resource.kind,
                                                resource.name
                                            );
                                        }
                                        if live_uid != plan_uid {
                                            bail!(
                                                "UID changed for {}/{}: plan {} vs live {}",
                                                resource.kind,
                                                resource.name,
                                                plan_uid,
                                                live_uid
                                            );
                                        }
                                        let action_meta = metadata.clone();
                                        if let Err(drift_reason) =
                                            crate::revalidate_review_basis_cached(
                                                client,
                                                &obj,
                                                resource,
                                                &action_meta,
                                                &audit_ctx,
                                                operator_snapshot,
                                                &crd_items,
                                            )
                                            .await
                                        {
                                            bail!(
                                                "BLOCKED: {}/{} — basis drift: {}",
                                                resource.kind,
                                                resource.name,
                                                drift_reason
                                            );
                                        }
                                        let mut bound = resource.clone();
                                        bound.uid = Some(live_uid.to_string());
                                        *action = Action::Delete {
                                            resource: bound,
                                            reason: format!("{} (approved in TUI)", reason),
                                        };
                                    }
                                    Err(::kube::Error::Api(ref err)) if err.code == 404 => {
                                        eprintln!(
                                            "  ⚠ {}/{} no longer present — skipped",
                                            resource.kind, resource.name
                                        );
                                    }
                                    Err(e) => bail!(
                                        "Cannot verify {}/{}: {}",
                                        resource.kind,
                                        resource.name,
                                        e
                                    ),
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
        *plan = mutated;
    }

    // P0: Verify operator generation is still SameGeneration before Start.
    {
        let j = journal_store.read().await;
        let gen_state = crate::teardown::audit::check_operator_generation(
            client,
            &j.operator,
            &j.audit_context.csv_baseline,
        )
        .await;
        match gen_state {
            OperatorGenerationState::SameGeneration => {}
            OperatorGenerationState::Absent => {
                bail!(
                    "Operator was removed during Plan Review — cannot start execution. \
                       Create a new teardown plan."
                );
            }
            OperatorGenerationState::Reappeared => {
                bail!(
                    "Operator was reinstalled during Plan Review — approvals are invalid. \
                       Create a new teardown plan for the current generation."
                );
            }
            OperatorGenerationState::Unknown(reason) => {
                bail!(
                    "Cannot verify operator generation before Start: {}. \
                       Create a new teardown plan.",
                    reason
                );
            }
        }
    }

    // Re-verify cluster identity before Start
    {
        let j = journal_store.read().await;
        let current_id = crate::teardown::journal::fetch_cluster_identity(client).await?;
        if !current_id.matches(&j.cluster_identity) {
            bail!("Cluster identity changed during Plan Review — aborting start.");
        }
    }

    // P0: Persist Bound Plan to journal BEFORE mutation.
    let bound_snapshot = plan.clone();
    journal_store
        .update(|j| {
            j.plan_snapshot = bound_snapshot;
        })
        .await
        .context("Failed to persist Bound Plan to journal — aborting start")?;

    let _ = apply_command(&mut app, &AppCommand::StartExecution);

    // ── Screen 2: Execution (live ratatui rendering) ──
    run_execution_screen(
        terminal,
        client,
        plan,
        kind_map,
        gk_map,
        gvk_map,
        gvr_map,
        journal_store,
        gate,
        force,
    )
    .await
}

/// Execution screen: runs executor with live ratatui rendering from shared RuntimeStateStore.
///
/// Uses tokio::select! between the executor future and UI rendering ticks.
/// The executor runs in the same task (no spawn), so no 'static lifetime requirement.
///
/// Invariant: ALL exit paths (success, error, pause) perform:
///   gate.close_and_drain() → executor stops → durable state checkpoint
#[allow(clippy::too_many_arguments)]
async fn run_execution_screen(
    terminal: &mut Terminal<CrosstermBackend<std::io::Stdout>>,
    client: &::kube::Client,
    plan: &mut TeardownPlan,
    kind_map: &KindMap,
    gk_map: &GroupKindMap,
    gvk_map: &GvkMap,
    gvr_map: &GvrMap,
    journal_store: &Arc<JournalStore>,
    gate: &Arc<MutationGate>,
    force: bool,
) -> Result<()> {
    // Create shared RuntimeStateStore for rendering (display only, no DELETE authority).
    let (runtime_store, _notifier) = executor::create_runtime_store();

    // Re-enter TUI mode for execution screen
    enable_raw_mode().context("Failed to re-enable raw mode")?;
    if let Err(e) = execute!(terminal.backend_mut(), EnterAlternateScreen) {
        disable_raw_mode().ok();
        return Err(anyhow::anyhow!("Failed to enter alternate screen: {}", e));
    }

    let exec_start = Instant::now();
    let total_phases = plan.phases.len();

    // Pin the executor future so we can select! between it and UI ticks
    let mut executor_fut = Box::pin(executor::execute_plan_with_store(
        client,
        plan,
        kind_map,
        gk_map,
        gvk_map,
        gvr_map,
        false,
        force,
        Some(journal_store.as_ref()),
        Some(gate.as_ref()),
        0,
        true, // skip_confirm — TUI already reviewed
        Some(runtime_store.clone()),
    ));

    let mut event_rx = runtime_store.subscribe();
    let mut exec_result: Option<Result<ExecutionResult>> = None;
    let mut paused = false;

    loop {
        // Render current state
        let entries = runtime_store.snapshot();
        let all_resources: Vec<ResourceId> = entries.iter().map(|e| e.resource.clone()).collect();
        let summary = runtime_store.summary_for(&all_resources);
        let elapsed = exec_start.elapsed().as_secs();

        let current_phase = entries
            .iter()
            .filter(|e| {
                !matches!(
                    e.state,
                    ResourceRuntimeState::Gone
                        | ResourceRuntimeState::Keep
                        | ResourceRuntimeState::Review
                )
            })
            .map(|e| e.phase_index)
            .min()
            .unwrap_or(total_phases);

        if let Err(e) = terminal.draw(|f| {
            renderer::draw_execution(
                f,
                &entries,
                &summary,
                current_phase,
                total_phases,
                elapsed,
                paused,
                None,
            );
        }) {
            // Draw error — close gate + drain concurrently with executor
            let (_, exec_r) = tokio::join!(gate.close_and_drain(), &mut executor_fut);
            disable_raw_mode().ok();
            execute!(terminal.backend_mut(), LeaveAlternateScreen).ok();
            // If executor had a hard error (e.g. journal checkpoint failure after mutation),
            // persist Failed and propagate that error — don't mask it with draw error.
            if let Err(exec_err) = exec_r {
                let _ = journal_store
                    .update(|j| {
                        j.state = RunState::Failed;
                    })
                    .await;
                return Err(exec_err.context("Executor error during TUI draw failure"));
            }
            let _ = journal_store
                .update(|j| {
                    j.state = RunState::Paused;
                })
                .await;
            return Err(anyhow::anyhow!("TUI draw error: {}", e));
        }

        if exec_result.is_some() {
            break;
        }

        // Select between: executor completion, state change notification, key input
        tokio::select! {
            result = &mut executor_fut => {
                exec_result = Some(result);
                // One more render cycle to show final state, then break
            }
            _ = event_rx.changed() => {
                // State changed — redraw on next iteration
            }
            _ = tokio::time::sleep(std::time::Duration::from_millis(200)) => {
                // Check for key events (non-blocking, within async context)
                if event::poll(std::time::Duration::from_millis(0)).unwrap_or(false)
                    && let Ok(Event::Key(key)) = event::read() {
                        let should_pause = match key.code {
                            KeyCode::Char('c') if key.modifiers.contains(KeyModifiers::CONTROL) => true,
                            KeyCode::Char('q') | KeyCode::Esc | KeyCode::Char('p') => true,
                            _ => false,
                        };
                        if should_pause {
                            // Graceful shutdown: close gate + executor concurrently
                            let (_, exec_r) = tokio::join!(
                                gate.close_and_drain(),
                                &mut executor_fut
                            );
                            // If executor had a hard error, persist Failed and propagate
                            if let Err(exec_err) = exec_r {
                                let _ = journal_store.update(|j| { j.state = RunState::Failed; }).await;
                                disable_raw_mode().ok();
                                execute!(terminal.backend_mut(), LeaveAlternateScreen).ok();
                                return Err(exec_err.context(
                                    "Executor error during pause — state persisted as Failed"
                                ));
                            }
                            paused = true;
                            // Executor completed Ok — safe to persist Paused
                            journal_store.update(|j| {
                                j.state = RunState::Paused;
                            }).await
                            .context("Failed to persist Paused state after user pause")?;
                            break;
                        }
                    }
            }
        }
    }

    // Leave TUI for post-execution output
    disable_raw_mode().ok();
    execute!(terminal.backend_mut(), LeaveAlternateScreen).ok();

    if paused {
        eprintln!("⏸ Paused. Use 'teardown resume' to continue.");
        return Ok(());
    }

    match exec_result {
        Some(Ok(result)) => {
            handle_execution_completed(
                terminal,
                client,
                result,
                plan,
                journal_store,
                gate,
                kind_map,
                gk_map,
            )
            .await
        }
        Some(Err(e)) => {
            let _ = journal_store
                .update(|j| {
                    j.state = RunState::Failed;
                })
                .await;
            Err(e)
        }
        None => {
            bail!("Executor did not produce a result");
        }
    }
}

/// Handle post-execution: persist state, check residual transition conditions, enter residual screen.
#[allow(clippy::too_many_arguments)]
async fn handle_execution_completed(
    terminal: &mut Terminal<CrosstermBackend<std::io::Stdout>>,
    client: &::kube::Client,
    result: ExecutionResult,
    _plan: &TeardownPlan,
    journal_store: &Arc<JournalStore>,
    gate: &Arc<MutationGate>,
    kind_map: &KindMap,
    gk_map: &GroupKindMap,
) -> Result<()> {
    // Check if gate was closed (signal-based pause, not key-based)
    if !gate.is_open() {
        journal_store
            .update(|j| {
                j.state = RunState::Paused;
                j.execution.phases_total = result.phases_total;
            })
            .await
            .context("Failed to persist Paused state after signal pause")?;
        executor::print_execution_result(&result);
        eprintln!("⏸ Paused (signal). Use 'teardown resume' to continue.");
        return Ok(());
    }

    let final_state = if result.phases_completed == result.phases_total
        && result.failed.is_empty()
        && result.barrier_timeout.is_none()
    {
        RunState::ApplyCompleted
    } else {
        RunState::Failed
    };

    // Persist final state durably BEFORE any screen transition
    journal_store
        .update(|j| {
            j.state = final_state.clone();
            j.execution.phases_total = result.phases_total;
        })
        .await
        .context("Failed to persist final state")?;

    executor::print_execution_result(&result);

    if final_state == RunState::Failed {
        bail!("Teardown failed");
    }

    // ── Residual Cleanup transition gate ──
    // ApplyCompleted is durably persisted. Verify generation Absent before Residual.
    let gen_state = {
        let j = journal_store.read().await;
        audit::check_operator_generation(client, &j.operator, &j.audit_context.csv_baseline).await
    };
    match gen_state {
        OperatorGenerationState::Absent => {}
        OperatorGenerationState::SameGeneration => {
            eprintln!("⚠ Operator generation still active — residual cleanup blocked.");
            return Ok(());
        }
        OperatorGenerationState::Reappeared => {
            eprintln!("⚠ Operator was reinstalled — residual cleanup blocked.");
            return Ok(());
        }
        OperatorGenerationState::Unknown(reason) => {
            eprintln!(
                "⚠ Cannot verify operator generation: {} — residual cleanup blocked.",
                reason
            );
            return Ok(());
        }
    }

    // Run fresh complete audit and persist before entering residual screen
    let audit_result = {
        let j = journal_store.read().await;
        audit::run_residual_audit(client, &j)
            .await
            .context("Fresh residual audit failed")?
    };

    // Re-verify generation hasn't changed during audit
    {
        let j = journal_store.read().await;
        let gen_recheck =
            audit::check_operator_generation(client, &j.operator, &j.audit_context.csv_baseline)
                .await;
        if !matches!(gen_recheck, OperatorGenerationState::Absent) {
            eprintln!("⚠ Operator generation changed during audit — residual cleanup blocked.");
            return Ok(());
        }
    }

    // Persist audit durably
    let status = audit::residual_status_from_audit(&audit_result);
    journal_store
        .update(|j| {
            j.residual_status = status.clone();
            j.audit_revision += 1;
            j.last_residual_audit = Some(audit_result.clone());
        })
        .await
        .context("Failed to persist residual audit")?;

    // AuditIncomplete → cannot enter cleanup screen
    if matches!(status, journal::ResidualStatus::AuditIncomplete) {
        eprintln!("⚠ Residual audit incomplete — cleanup not available until audit completes.");
        return Ok(());
    }

    // Collect candidates: likely_operator_residual + unattributed only
    let residuals: Vec<(ResourceId, String)> = audit_result
        .likely_operator_residual
        .iter()
        .map(|r| (r.resource.clone(), format!("{:?} confidence", r.confidence)))
        .chain(
            audit_result
                .unattributed
                .iter()
                .map(|r| (r.resource.clone(), "unattributed".to_string())),
        )
        .collect();

    // ── Screen 3: Residual Cleanup ──
    // Enter even when empty — user needs 'f' to mark Finished
    enable_raw_mode().context("Failed to re-enable raw mode for residual")?;
    execute!(terminal.backend_mut(), EnterAlternateScreen)
        .context("Failed to re-enter alternate screen for residual")?;

    let residual_result = run_residual_screen(
        terminal,
        client,
        &residuals,
        journal_store,
        gate,
        kind_map,
        gk_map,
    )
    .await;

    disable_raw_mode().ok();
    execute!(terminal.backend_mut(), LeaveAlternateScreen).ok();

    residual_result
}

/// Residual Cleanup TUI screen — selection + delete via core execute_residual_cleanup.
async fn run_residual_screen(
    terminal: &mut Terminal<CrosstermBackend<std::io::Stdout>>,
    client: &::kube::Client,
    residuals: &[(ResourceId, String)],
    journal_store: &Arc<JournalStore>,
    gate: &Arc<MutationGate>,
    kind_map: &KindMap,
    gk_map: &GroupKindMap,
) -> Result<()> {
    let mut cursor: usize = 0;
    let mut selected: Vec<ResourceId> = Vec::new();
    let mut status_msg: Option<String> = None;
    let mut current_residuals = residuals.to_vec();
    let mut cleanup_states: std::collections::HashMap<ResourceId, renderer::ResidualResourceState> =
        std::collections::HashMap::new();

    loop {
        terminal.draw(|f| {
            renderer::draw_residual(
                f,
                &current_residuals,
                &selected,
                cursor,
                status_msg.as_deref(),
                if cleanup_states.is_empty() {
                    None
                } else {
                    Some(&cleanup_states)
                },
            );
        })?;

        // Check gate closed (signal-based pause) during idle
        if !gate.is_open() {
            journal_store
                .update(|j| {
                    j.state = RunState::Paused;
                })
                .await
                .context("Failed to persist Paused on signal in Residual screen")?;
            return Ok(());
        }

        if event::poll(std::time::Duration::from_millis(100))?
            && let Event::Key(key) = event::read()?
        {
            match key.code {
                KeyCode::Char('c') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                    return Ok(());
                }
                KeyCode::Char('q') | KeyCode::Esc => return Ok(()),
                KeyCode::Char('f') => {
                    journal_store
                        .update(|j| {
                            j.state = RunState::Finished;
                        })
                        .await
                        .context("Failed to persist Finished state")?;
                    return Ok(());
                }
                KeyCode::Up | KeyCode::Char('k') => {
                    cursor = cursor.saturating_sub(1);
                }
                KeyCode::Down | KeyCode::Char('j') if cursor + 1 < current_residuals.len() => {
                    cursor += 1;
                }
                KeyCode::Char(' ') if !current_residuals.is_empty() => {
                    let res = &current_residuals[cursor].0;
                    let already = selected.iter().position(|s| {
                        s.kind == res.kind
                            && s.name == res.name
                            && s.namespace == res.namespace
                            && s.group == res.group
                    });
                    if let Some(idx) = already {
                        selected.remove(idx);
                    } else {
                        selected.push(res.clone());
                    }
                }
                KeyCode::Char('d') if !selected.is_empty() => {
                    // Run cleanup in TUI with live rendering via progress channel
                    let selected_for_cleanup = selected.clone();
                    selected.clear();
                    status_msg = Some("Deleting...".to_string());

                    let (progress_tx, mut progress_rx) =
                        tokio::sync::mpsc::unbounded_channel::<executor::CleanupProgress>();

                    let mut cleanup_fut =
                        Box::pin(executor::execute_residual_cleanup_with_progress(
                            client,
                            &selected_for_cleanup,
                            journal_store.as_ref(),
                            gate.as_ref(),
                            kind_map,
                            gk_map,
                            Some(&progress_tx),
                        ));

                    // Render loop during cleanup — show per-resource progress.
                    // All exit paths (draw error, signal cancel, completion) must
                    // drain cleanup_fut and checkpoint before returning.
                    let cancel_signal = gate.cancel_signal();
                    let cleanup_result = loop {
                        if let Err(draw_err) = terminal.draw(|f| {
                            renderer::draw_residual(
                                f,
                                &current_residuals,
                                &selected_for_cleanup,
                                cursor,
                                status_msg.as_deref(),
                                if cleanup_states.is_empty() {
                                    None
                                } else {
                                    Some(&cleanup_states)
                                },
                            );
                        }) {
                            let (_, cleanup_r) =
                                tokio::join!(gate.close_and_drain(), &mut cleanup_fut);
                            let _ = cleanup_r;
                            return Err(anyhow::anyhow!(
                                "TUI draw error during cleanup: {}",
                                draw_err
                            ));
                        }

                        tokio::select! {
                            result = &mut cleanup_fut => {
                                break result;
                            }
                            progress = progress_rx.recv() => {
                                if let Some(p) = progress {
                                    let (key, state) = match p {
                                        executor::CleanupProgress::Validating { resource } =>
                                            (resource, renderer::ResidualResourceState::Validating),
                                        executor::CleanupProgress::DeleteRequested { resource } =>
                                            (resource, renderer::ResidualResourceState::DeleteRequested),
                                        executor::CleanupProgress::WaitingGone { resource } =>
                                            (resource, renderer::ResidualResourceState::WaitingGone),
                                        executor::CleanupProgress::Gone { resource } =>
                                            (resource, renderer::ResidualResourceState::Gone),
                                        executor::CleanupProgress::Skipped { resource, reason } =>
                                            (resource, renderer::ResidualResourceState::Skipped(reason)),
                                        executor::CleanupProgress::Failed { resource, reason } =>
                                            (resource, renderer::ResidualResourceState::Failed(reason)),
                                    };
                                    cleanup_states.insert(key, state);
                                }
                            }
                            _ = cancel_signal.cancelled() => {
                                // Signal-based pause during cleanup.
                                // Drain cleanup future — it will stop at next permit acquire.
                                let cleanup_r = (&mut cleanup_fut).await;
                                match cleanup_r {
                                    Ok(_) => {
                                        journal_store.update(|j| {
                                            j.state = RunState::Paused;
                                        }).await
                                        .context("Failed to persist Paused during cleanup signal pause")?;
                                        return Ok(());
                                    }
                                    Err(e) => {
                                        if executor::is_gate_closed_error(&e) {
                                            // Normal pause — gate closed caused core to stop
                                            journal_store.update(|j| {
                                                j.state = RunState::Paused;
                                            }).await
                                            .context("Failed to persist Paused during cleanup pause")?;
                                            return Ok(());
                                        }
                                        // Hard error — propagate
                                        return Err(e.context(
                                            "Cleanup error during signal pause — \
                                             journal reflects actual state"
                                        ));
                                    }
                                }
                            }
                            _ = tokio::time::sleep(std::time::Duration::from_millis(200)) => {
                                // Tick — redraw
                            }
                        }
                    };

                    match cleanup_result {
                        Ok(result) => {
                            // If gate was closed during cleanup (signal pause after last resource)
                            if !gate.is_open() {
                                journal_store
                                    .update(|j| {
                                        j.state = RunState::Paused;
                                    })
                                    .await
                                    .context("Failed to persist Paused after cleanup signal")?;
                                return Ok(());
                            }
                            if let Some(ref post_audit) = result.post_audit {
                                current_residuals =
                                    post_audit
                                        .likely_operator_residual
                                        .iter()
                                        .map(|r| {
                                            (
                                                r.resource.clone(),
                                                format!("{:?} confidence", r.confidence),
                                            )
                                        })
                                        .chain(post_audit.unattributed.iter().map(|r| {
                                            (r.resource.clone(), "unattributed".to_string())
                                        }))
                                        .collect();
                                cursor = cursor.min(current_residuals.len().saturating_sub(1));
                            }
                            // Clear stale cleanup states — post-audit may have new UIDs
                            cleanup_states.clear();
                            status_msg = Some(format!(
                                "{} deleted, {} skipped, {} failed",
                                result.deleted.len(),
                                result.skipped.len(),
                                result.failed.len(),
                            ));
                        }
                        Err(e) => {
                            if executor::is_gate_closed_error(&e) {
                                journal_store
                                    .update(|j| {
                                        j.state = RunState::Paused;
                                    })
                                    .await
                                    .context(
                                        "Failed to persist Paused after gate-closed cleanup",
                                    )?;
                                return Ok(());
                            }
                            gate.close_and_drain().await;
                            return Err(e.context(
                                    "Residual cleanup failed — gate closed, no further mutations allowed. \
                                     Use 'teardown journal' to inspect state before retry."
                                ));
                        }
                    }
                }
                _ => {}
            }
        }
    }
}

/// Residual cleanup flow — shared between TUI and script paths (non-TUI version).
#[allow(dead_code)]
pub async fn run_residual_cleanup(
    client: &::kube::Client,
    _plan: &TeardownPlan,
    journal_store: &Arc<JournalStore>,
    _gate: &Arc<MutationGate>,
    _kind_map: &KindMap,
    _gk_map: &GroupKindMap,
) -> Result<()> {
    let j = journal_store.read().await;

    let gen_state =
        audit::check_operator_generation(client, &j.operator, &j.audit_context.csv_baseline).await;

    match gen_state {
        OperatorGenerationState::Absent => {
            eprintln!("\n🔍 Running post-apply residual audit...");
            match audit::run_residual_audit(client, &j).await {
                Ok(audit_result) => {
                    let status = audit::residual_status_from_audit(&audit_result);
                    audit::print_residual_audit(&audit_result, &j);

                    let gen_recheck = audit::check_operator_generation(
                        client,
                        &j.operator,
                        &j.audit_context.csv_baseline,
                    )
                    .await;
                    if matches!(gen_recheck, OperatorGenerationState::Absent) {
                        journal_store
                            .update(|j| {
                                j.residual_status = status;
                                j.audit_revision += 1;
                                j.last_residual_audit = Some(audit_result);
                            })
                            .await
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

/// Check gate and persist Paused if closed. Returns true if paused.
pub async fn check_and_persist_paused(
    journal_store: &Arc<JournalStore>,
    gate: &Arc<MutationGate>,
) -> Result<bool> {
    if !gate.is_open() {
        journal_store
            .update(|j| {
                j.state = RunState::Paused;
            })
            .await
            .context("Failed to persist Paused on signal")?;
        return Ok(true);
    }
    Ok(false)
}

/// Residual-only TUI entry for resume. Performs fresh Absent + complete audit,
/// then opens the Residual Cleanup screen. Non-TTY prints audit results only.
pub async fn run_residual_only(
    client: &::kube::Client,
    journal_store: &Arc<JournalStore>,
    gate: &Arc<MutationGate>,
    kind_map: &KindMap,
    gk_map: &GroupKindMap,
) -> Result<()> {
    // Early gate check — if already closed, skip all API work
    if check_and_persist_paused(journal_store, gate).await? {
        return Ok(());
    }

    // Fresh generation Absent check
    let j = journal_store.read().await;
    let gen_state =
        audit::check_operator_generation(client, &j.operator, &j.audit_context.csv_baseline).await;
    if check_and_persist_paused(journal_store, gate).await? {
        return Ok(());
    }
    if !matches!(gen_state, OperatorGenerationState::Absent) {
        bail!("Operator generation not Absent — cannot enter Residual Cleanup");
    }

    // Fresh complete audit
    let audit_result = match audit::run_residual_audit(client, &j).await {
        Ok(a) => a,
        Err(e) => {
            if check_and_persist_paused(journal_store, gate).await? {
                return Ok(());
            }
            return Err(e.context("Fresh residual audit failed"));
        }
    };
    if check_and_persist_paused(journal_store, gate).await? {
        return Ok(());
    }

    // Post-audit generation recheck
    let gen_recheck =
        audit::check_operator_generation(client, &j.operator, &j.audit_context.csv_baseline).await;
    if check_and_persist_paused(journal_store, gate).await? {
        return Ok(());
    }
    if !matches!(gen_recheck, OperatorGenerationState::Absent) {
        bail!("Operator generation changed during audit — cannot enter Residual Cleanup");
    }

    let status = audit::residual_status_from_audit(&audit_result);
    if matches!(status, journal::ResidualStatus::AuditIncomplete) {
        if check_and_persist_paused(journal_store, gate).await? {
            return Ok(());
        }
        audit::print_residual_audit(&audit_result, &j);
        bail!("Residual audit incomplete — cannot enter cleanup screen");
    }

    // Persist audit
    journal_store
        .update(|j| {
            j.residual_status = status;
            j.audit_revision += 1;
            j.last_residual_audit = Some(audit_result.clone());
        })
        .await
        .context("Failed to persist residual audit")?;

    // Collect candidates
    let residuals: Vec<(ResourceId, String)> = audit_result
        .likely_operator_residual
        .iter()
        .map(|r| (r.resource.clone(), format!("{:?} confidence", r.confidence)))
        .chain(
            audit_result
                .unattributed
                .iter()
                .map(|r| (r.resource.clone(), "unattributed".to_string())),
        )
        .collect();

    // Non-TTY: print audit and return (no TUI available for f/Finish)
    if !std::io::IsTerminal::is_terminal(&std::io::stdin()) {
        if check_and_persist_paused(journal_store, gate).await? {
            return Ok(());
        }
        audit::print_residual_audit(&audit_result, &j);
        if residuals.is_empty() {
            eprintln!(
                "✅ No residuals. Run 'teardown resume' in a TTY and press 'f' to mark as Finished."
            );
        }
        return Ok(());
    }

    // TTY: enter TUI Residual screen
    enable_raw_mode().context("Failed to enable raw mode for Residual")?;
    let mut stdout = std::io::stdout();
    execute!(stdout, EnterAlternateScreen).context("Failed to enter alternate screen")?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend).context("Failed to create terminal")?;

    let result = run_residual_screen(
        &mut terminal,
        client,
        &residuals,
        journal_store,
        gate,
        kind_map,
        gk_map,
    )
    .await;

    disable_raw_mode().ok();
    execute!(terminal.backend_mut(), LeaveAlternateScreen).ok();
    terminal.show_cursor().ok();

    result
}
