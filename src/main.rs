mod analyzers;
mod cli;
mod graph;
mod kube;
mod output;
mod teardown;

use std::collections::HashSet;
use std::time::Instant;

use anyhow::{Context, Result, bail};
use clap::Parser;

use crate::analyzers::olm::{
    compute_operator_dependencies, discover_operators, find_crd_origin, print_crd_origin,
    print_operators,
};
use crate::analyzers::selector::get_service_selected_pods;
use crate::cli::{Args, Command, OutputFormat, TeardownAction};
use crate::graph::evidence::build_evidence_graph;
use crate::graph::tree::{TreeNode, build_child_tree, build_full_tree, build_namespace_map};
use crate::kube::discovery::{build_kind_lookup_cached, load_config_and_client, resolve_kind};
use crate::kube::scanner::{find_parents_only, resolve_missing_parents, scan_namespace};
use crate::kube::snapshot::{build_snapshot, save_snapshot};
use crate::output::json::{print_chain_json, print_json, tree_to_json};
use crate::output::table::{print_chain_table, print_table};
use crate::output::tree::{count_nodes, print_chain_tree, print_tree};
use crate::teardown::executor::{execute_plan, print_execution_result};
use crate::teardown::explain::explain_resource;
use crate::teardown::inspect::{inspect_operator, print_inspection};
use crate::teardown::permit::MutationGate;
use crate::teardown::journal::{
    self, AuditContext, ExecutionRecord, JournalStore, ResidualStatus, RunJournal, RunState,
};
use crate::teardown::planner::{
    DecisionPolicy, generate_teardown_plan, load_plan_from_file, print_teardown_plan,
    resolve_operator_targets, save_plan_to_file,
};
use crate::teardown::progress::{check_plan_status, print_plan_status};

fn display_tree(tree: &TreeNode, output: &OutputFormat, namespace: &str) {
    match output {
        OutputFormat::Tree => {
            eprintln!("\n📦 Namespace: {}\n", namespace);
            print_tree(tree, "", true, true);
        }
        OutputFormat::Table => print_table(tree),
        OutputFormat::Json => print_json(tree, namespace),
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();

    let (config, client) = load_config_and_client().await?;

    // ── Subcommand dispatch ──
    if let Some(command) = args.command {
        match command {
            Command::Snapshot {
                namespace,
                output_file,
                include_events,
                no_cache,
            } => {
                let namespace = namespace.unwrap_or_else(|| config.default_namespace.clone());
                let t0 = Instant::now();
                eprintln!("🔍 Discovering API resources...");
                let (kind_map, _, _gk_map, _) =
                    build_kind_lookup_cached(&client, &config, no_cache).await?;
                eprintln!("   Discovery: {:.1}s", t0.elapsed().as_secs_f64());

                let snapshot =
                    build_snapshot(&client, &config, &namespace, &kind_map, include_events).await?;

                let resource_count = snapshot.resources.len();
                let error_count = snapshot.scan_errors.len();
                save_snapshot(&snapshot, &output_file)?;

                eprintln!(
                    "✅ Snapshot saved to {} ({} resources, {} errors)",
                    output_file, resource_count, error_count
                );
                return Ok(());
            }
            Command::Graph {
                namespace,
                output_file,
                include_events,
                no_cache,
            } => {
                let namespace = namespace.unwrap_or_else(|| config.default_namespace.clone());
                let t0 = Instant::now();
                eprintln!("🔍 Discovering API resources...");
                let (kind_map, _, _gk_map, _) =
                    build_kind_lookup_cached(&client, &config, no_cache).await?;
                eprintln!("   Discovery: {:.1}s", t0.elapsed().as_secs_f64());

                let snapshot =
                    build_snapshot(&client, &config, &namespace, &kind_map, include_events).await?;

                eprint!("🔍 Discovering operators...");
                let operators = discover_operators(&client, &kind_map).await?;
                eprintln!(" found {} operators", operators.len());

                eprint!("🔗 Building evidence graph...");
                let graph = build_evidence_graph(&snapshot, &operators);
                eprintln!(" {} edges", graph.edges.len());

                let json = serde_json::to_string_pretty(&graph)?;
                std::fs::write(&output_file, json)?;
                eprintln!(
                    "✅ Evidence graph saved to {} ({} edges)",
                    output_file,
                    graph.edges.len()
                );
                return Ok(());
            }
            Command::Teardown { action } => {
                match action {
                    TeardownAction::Plan {
                        operators: operator_queries,
                        output,
                        no_cache,
                        prune_apis,
                        approve_delete,
                        preserve,
                    } => {
                        let t0 = Instant::now();
                        eprintln!("🔍 Discovering API resources...");
                        let (kind_map, gvr_map, gk_map, gvk_map) =
                            build_kind_lookup_cached(&client, &config, no_cache).await?;
                        let t_discovery = t0.elapsed();

                        let t_olm = Instant::now();
                        eprint!("🔍 Discovering operators...");
                        let all_operators = discover_operators(&client, &kind_map).await?;
                        eprintln!(" found {} operators", all_operators.len());
                        let t_olm = t_olm.elapsed();

                        let target_indices =
                            resolve_operator_targets(&operator_queries, &all_operators)?;
                        let target_operators: Vec<&_> =
                            target_indices.iter().map(|&i| &all_operators[i]).collect();

                        let policy = DecisionPolicy::from_args(&approve_delete, &preserve);
                        let t_plan = Instant::now();
                        let plan = generate_teardown_plan(
                            &client,
                            &target_operators,
                            &all_operators,
                            &kind_map,
                            &gvr_map,
                            &gk_map,
                            &gvk_map,
                            prune_apis,
                            &policy,
                        )
                        .await?;
                        let t_plan = t_plan.elapsed();

                        print_teardown_plan(&plan, &output);

                        eprintln!(
                            "\n⏱ Discovery: {:.1}s, OLM: {:.1}s, Plan: {:.1}s, Total: {:.1}s",
                            t_discovery.as_secs_f64(),
                            t_olm.as_secs_f64(),
                            t_plan.as_secs_f64(),
                            t0.elapsed().as_secs_f64()
                        );
                    }
                    TeardownAction::Apply {
                        operators: operator_queries,
                        no_cache,
                        dry_run,
                        prune_apis,
                        force,
                        approve_delete,
                        preserve,
                        script,
                    } => {
                        let t0 = Instant::now();
                        eprintln!("🔍 Discovering API resources...");
                        let (kind_map, gvr_map, gk_map, gvk_map) =
                            build_kind_lookup_cached(&client, &config, no_cache).await?;
                        eprintln!("   Discovery: {:.1}s", t0.elapsed().as_secs_f64());

                        eprint!("🔍 Discovering operators...");
                        let all_operators = discover_operators(&client, &kind_map).await?;
                        eprintln!(" found {} operators", all_operators.len());

                        let target_indices =
                            resolve_operator_targets(&operator_queries, &all_operators)?;
                        let target_operators: Vec<&_> =
                            target_indices.iter().map(|&i| &all_operators[i]).collect();

                        let policy = DecisionPolicy::from_args(&approve_delete, &preserve);
                        let plan = generate_teardown_plan(
                            &client,
                            &target_operators,
                            &all_operators,
                            &kind_map,
                            &gvr_map,
                            &gk_map,
                            &gvk_map,
                            prune_apis,
                            &policy,
                        )
                        .await?;

                        match save_plan_to_file(&plan) {
                            Ok(path) => eprintln!("📄 Plan saved to {}", path),
                            Err(e) => eprintln!("⚠ Could not save plan: {}", e),
                        }

                        // Headless script mode: drive AppState with JSON commands
                        if let Some(script_path) = &script {
                            use crate::teardown::app::{AppState, AppScreen, AppCommand, apply_command, AppStateSnapshot};
                            let mut app = AppState::new();

                            // Read commands from script file (one JSON per line)
                            let content = std::fs::read_to_string(script_path)
                                .with_context(|| format!("Failed to read script: {}", script_path))?;

                            let mut events = Vec::new();
                            for (i, line) in content.lines().enumerate() {
                                let line = line.trim();
                                if line.is_empty() || line.starts_with('#') {
                                    continue;
                                }
                                let cmd: AppCommand = serde_json::from_str(line)
                                    .with_context(|| format!("Invalid command on line {}: {}", i + 1, line))?;

                                let result = apply_command(&mut app, &cmd);
                                let snapshot = AppStateSnapshot::from(&app);
                                events.push(serde_json::json!({
                                    "step": i,
                                    "command": format!("{:?}", cmd),
                                    "result": match &result {
                                        Ok(()) => "ok".to_string(),
                                        Err(e) => format!("error: {}", e),
                                    },
                                    "state": snapshot,
                                }));

                                // On StartExecution, run the actual executor
                                if matches!(cmd, AppCommand::StartExecution)
                                    && result.is_ok()
                                    && app.screen == AppScreen::Executing
                                {
                                    // Run executor with the plan
                                    let journal_store: Option<std::sync::Arc<JournalStore>> = if !dry_run {
                                        let store = create_run_journal(
                                            &client, &plan, &target_operators, &gk_map,
                                        ).await?;
                                        Some(std::sync::Arc::new(store))
                                    } else {
                                        None
                                    };

                                    // Cluster identity re-check (same as normal apply path)
                                    if let Some(store) = &journal_store {
                                        let current_id = journal::fetch_cluster_identity(&client).await?;
                                        let stored = store.read().await;
                                        if !current_id.matches(&stored.cluster_identity) {
                                            bail!(
                                                "Cluster identity changed between journal creation and execution \
                                                 (expected {}, got {}). Aborting.",
                                                stored.cluster_identity.kube_system_uid,
                                                current_id.kube_system_uid,
                                            );
                                        }
                                    }

                                    let gate = std::sync::Arc::new(MutationGate::new(16));
                                    let exec_result = execute_plan(
                                        &client, &plan, &kind_map, &gk_map, &gvk_map, &gvr_map,
                                        dry_run, force,
                                        journal_store.as_deref(),
                                        Some(&gate),
                                        0,
                                        true, // skip_confirm in script mode
                                    ).await;

                                    match exec_result {
                                        Ok(ref result) => {
                                            // Determine final state using gate + all-phases check
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

                                            if let Some(store) = &journal_store {
                                                store.update(|j| {
                                                    j.state = final_state.clone();
                                                }).await
                                                .context("Failed to persist execution state")?;
                                            }

                                            if matches!(final_state, RunState::Failed) {
                                                events.push(serde_json::json!({
                                                    "execution_error": format!(
                                                        "Teardown completed with {} failed, {} barrier timeout",
                                                        result.failed.len(),
                                                        if result.barrier_timeout.is_some() { "yes" } else { "no" }
                                                    )
                                                }));
                                            }

                                            events.push(serde_json::json!({
                                                "execution": {
                                                    "phases_completed": result.phases_completed,
                                                    "phases_total": result.phases_total,
                                                    "deleted": result.deleted.len(),
                                                    "failed": result.failed.len(),
                                                }
                                            }));
                                        }
                                        Err(e) => {
                                            events.push(serde_json::json!({
                                                "execution_error": format!("{:#}", e)
                                            }));
                                        }
                                    }
                                }
                            }

                            // Output full trace as JSON
                            let has_errors = events.iter().any(|e| {
                                e.get("execution_error").is_some()
                                    || e.get("result")
                                        .and_then(|r| r.as_str())
                                        .is_some_and(|s| s.starts_with("error:"))
                            });
                            println!("{}", serde_json::to_string_pretty(&events)?);
                            if has_errors {
                                bail!("Script execution completed with errors");
                            }
                            return Ok(());
                        }

                        // Interactive Plan Review (if TTY and not dry-run/script)
                        let is_tty = std::io::IsTerminal::is_terminal(&std::io::stdin());
                        let mut plan = plan; // shadow with mutable for draft overrides
                        if is_tty && !dry_run && script.is_none() {
                            use crate::teardown::app::{AppState, AppScreen, AppCommand, DraftAction, apply_command};
                            use crate::teardown::planner::Action;
                            use crate::kube::resource::ResourceId;
                            let mut app = AppState::new();

                            // Collect REVIEW items
                            let review_items: Vec<(usize, usize, ResourceId)> = plan.phases.iter()
                                .enumerate()
                                .flat_map(|(pi, phase)| {
                                    phase.actions.iter().enumerate().filter_map(move |(ai, a)| {
                                        if let Action::Review { resource, .. } = a {
                                            Some((pi, ai, resource.clone()))
                                        } else {
                                            None
                                        }
                                    })
                                })
                                .collect();

                            if !review_items.is_empty() && !force {
                                eprintln!("\n\x1b[1m📋 Plan Review\x1b[0m: {} REVIEW item(s)\n", review_items.len());
                                for (i, (_, _, res)) in review_items.iter().enumerate() {
                                    eprintln!("  [{}] {}/{}{}",
                                        i + 1,
                                        res.kind, res.name,
                                        res.namespace.as_ref().map(|ns| format!(" ({})", ns)).unwrap_or_default()
                                    );
                                }
                                eprintln!();
                                eprintln!("  Enter item numbers to approve for DELETE (comma-separated),");
                                eprintln!("  or press Enter to keep all as REVIEW:");
                                eprint!("  > ");
                                std::io::Write::flush(&mut std::io::stderr()).ok();

                                let mut input = String::new();
                                if std::io::stdin().read_line(&mut input).is_ok() {
                                    let input = input.trim();
                                    if !input.is_empty() {
                                        for token in input.split(',') {
                                            if let Ok(idx) = token.trim().parse::<usize>() {
                                                if idx >= 1 && idx <= review_items.len() {
                                                    let (_, _, ref res) = review_items[idx - 1];
                                                    let _ = apply_command(&mut app, &AppCommand::ApproveReview {
                                                        resource: res.clone(),
                                                    });
                                                }
                                            }
                                        }
                                    }
                                }

                                // Apply draft overrides to plan
                                if !app.draft_overrides.is_empty() {
                                    let mut mutated_plan = plan.clone();
                                    for over in &app.draft_overrides {
                                        for phase in &mut mutated_plan.phases {
                                            for action in &mut phase.actions {
                                                if let Action::Review { resource, reason, metadata } = action {
                                                    if *resource == over.resource {
                                                        match over.new_action {
                                                            DraftAction::Delete => {
                                                                *action = Action::Delete {
                                                                    resource: resource.clone(),
                                                                    reason: format!("{} (approved in Plan Review)", reason),
                                                                };
                                                            }
                                                            DraftAction::Keep => {
                                                                *action = Action::Keep {
                                                                    resource: resource.clone(),
                                                                    reason: format!("{} (kept in Plan Review)", reason),
                                                                };
                                                            }
                                                        }
                                                    }
                                                }
                                            }
                                        }
                                    }
                                    eprintln!("  {} REVIEW item(s) approved for DELETE\n",
                                        app.draft_overrides.iter()
                                            .filter(|o| matches!(o.new_action, DraftAction::Delete))
                                            .count()
                                    );
                                    plan = mutated_plan;
                                }
                            }

                            // Transition to Executing — BoundPlan is frozen
                            let _ = apply_command(&mut app, &AppCommand::StartExecution);
                        }

                        // Create RunJournal before first mutation (fail-closed)
                        // Use process lock to prevent dual-writer from resume
                        let journal_store: Option<std::sync::Arc<JournalStore>> = if !dry_run {
                            let store = create_run_journal(
                                &client, &plan, &target_operators, &gk_map,
                            ).await?;
                            eprintln!("📓 Run journal: {}", store.path().display());

                            // Re-verify cluster identity before first mutation
                            let current_id = journal::fetch_cluster_identity(&client).await?;
                            let stored = store.read().await;
                            if !current_id.matches(&stored.cluster_identity) {
                                bail!(
                                    "Cluster identity changed between journal creation and execution \
                                     (expected {}, got {}). Aborting.",
                                    stored.cluster_identity.kube_system_uid,
                                    current_id.kube_system_uid,
                                );
                            }

                            Some(std::sync::Arc::new(store))
                        } else {
                            None
                        };

                        // Create MutationGate for pause/Ctrl-C support
                        let gate = std::sync::Arc::new(MutationGate::new(16));

                        // Ctrl-C handler: close gate + drain only.
                        // Does NOT write journal — main thread determines final state
                        // after execute_plan returns, using gate.is_open() + result.
                        if !dry_run {
                            let gate_for_signal = gate.clone();
                            tokio::spawn(async move {
                                if tokio::signal::ctrl_c().await.is_ok() {
                                    eprintln!(
                                        "\n⏸ Pausing... waiting for active mutations to complete..."
                                    );
                                    gate_for_signal.close_and_drain().await;
                                    // Main thread will persist Paused after execute_plan returns
                                }
                            });
                        }

                        let exec_result = execute_plan(
                            &client, &plan, &kind_map, &gk_map, &gvk_map, &gvr_map,
                            dry_run, force,
                            journal_store.as_deref(),
                            Some(&gate),
                            0,     // start from phase 0 (fresh execution)
                            false, // prompt for confirmation
                        )
                        .await;

                        match exec_result {
                            Ok(result) => {
                                // Determine final state: gate.is_open() distinguishes
                                // completion from Ctrl-C pause. Single writer (main thread).
                                let final_state = if !gate.is_open() {
                                    RunState::Paused
                                } else if result.failed.is_empty()
                                    && result.barrier_timeout.is_none()
                                    && result.phases_completed == result.phases_total
                                {
                                    RunState::ApplyCompleted
                                } else {
                                    RunState::Failed
                                };

                                if let Some(store) = &journal_store {
                                    store.update(|j| {
                                        j.state = final_state.clone();
                                        j.execution.phases_total = result.phases_total;
                                    }).await
                                    .context("Failed to persist final execution state")?;
                                }

                                if final_state == RunState::Paused {
                                    eprintln!(
                                        "\n⏸ Paused at phase {}/{}. Use 'teardown resume' to continue.",
                                        result.phases_completed, result.phases_total
                                    );
                                }

                                print_execution_result(&result);

                                // Run post-apply residual audit (only if apply succeeded and operator is Absent)
                                if let Some(store) = &journal_store {
                                    if result.failed.is_empty() && result.barrier_timeout.is_none() {
                                        use crate::teardown::audit::{self, OperatorGenerationState};
                                        let j = store.read().await;
                                        let gen_state = audit::check_operator_generation(&client, &j.operator, &j.audit_context.csv_baseline).await;
                                        match gen_state {
                                            OperatorGenerationState::Absent => {
                                                eprintln!("\n🔍 Running post-apply residual audit...");
                                                match audit::run_residual_audit(&client, &j).await {
                                                    Ok(audit_result) => {
                                                        let status = audit::residual_status_from_audit(&audit_result);
                                                        audit::print_residual_audit(&audit_result, &j);
                                                        // Re-verify generation before saving
                                                        let gen_recheck = audit::check_operator_generation(&client, &j.operator, &j.audit_context.csv_baseline).await;
                                                        if matches!(gen_recheck, OperatorGenerationState::Absent) {
                                                            match store.update(|j| {
                                                                j.residual_status = status;
                                                                j.audit_revision += 1;
                                                                j.last_residual_audit = Some(audit_result);
                                                            }).await {
                                                                Ok(()) => {}
                                                                Err(e) => {
                                                                    eprintln!("⚠ Failed to persist audit results: {}", e);
                                                                    eprintln!("  Audit results were displayed but are NOT durable.");
                                                                    eprintln!("  Do not use this audit for cleanup authority.");
                                                                }
                                                            }
                                                        } else {
                                                            eprintln!("⚠ Operator generation changed during audit; discarding results");
                                                        }
                                                    }
                                                    Err(e) => {
                                                        eprintln!("⚠ Post-apply residual audit failed: {}", e);
                                                    }
                                                }
                                            }
                                            _ => {
                                                eprintln!("\nSkipping post-apply residual audit: operator generation not absent");
                                            }
                                        }
                                    }
                                }

                                // Residual cleanup transition — only if Absent + complete audit + TTY
                                if final_state == RunState::ApplyCompleted {
                                    if let Some(store) = &journal_store {
                                        let j = store.read().await;
                                        if let Some(ref audit) = j.last_residual_audit {
                                            let rs = crate::teardown::audit::residual_status_from_audit(audit);
                                            match rs {
                                                journal::ResidualStatus::ResidualsObserved { count } => {
                                                    eprintln!(
                                                        "\n📋 {} residual(s) observed.",
                                                        count
                                                    );

                                                    // Interactive residual cleanup (TTY only)
                                                    if is_tty {
                                                        let residuals: Vec<&crate::teardown::audit::AttributedResidual> =
                                                            audit.likely_operator_residual.iter()
                                                                .chain(audit.unattributed.iter())
                                                                .collect();

                                                        if !residuals.is_empty() {
                                                        use crate::kube::resource::ResourceId;
                                                            eprintln!("\n\x1b[1mResidual Cleanup\x1b[0m:");
                                                            for (i, res) in residuals.iter().enumerate() {
                                                                eprintln!("  [{}] {:?} {}/{}{}",
                                                                    i + 1,
                                                                    res.confidence,
                                                                    res.resource.kind,
                                                                    res.resource.name,
                                                                    res.resource.namespace.as_ref()
                                                                        .map(|ns| format!(" ({})", ns))
                                                                        .unwrap_or_default()
                                                                );
                                                            }
                                                            eprintln!();
                                                            eprintln!("  Enter item numbers to DELETE (comma-separated),");
                                                            eprintln!("  or press Enter to skip cleanup:");
                                                            eprint!("  > ");
                                                            std::io::Write::flush(&mut std::io::stderr()).ok();

                                                            let mut input = String::new();
                                                            if std::io::stdin().read_line(&mut input).is_ok() {
                                                                let input = input.trim();
                                                                if !input.is_empty() {
                                                                    let mut selected: Vec<&ResourceId> = Vec::new();
                                                                    for token in input.split(',') {
                                                                        if let Ok(idx) = token.trim().parse::<usize>() {
                                                                            if idx >= 1 && idx <= residuals.len() {
                                                                                selected.push(&residuals[idx - 1].resource);
                                                                            }
                                                                        }
                                                                    }

                                                                    if !selected.is_empty() {
                                                                        eprintln!("\n  Deleting {} residual(s)...", selected.len());

                                                                        // Verify generation is still Absent
                                                                        let gen_check = crate::teardown::audit::check_operator_generation(
                                                                            &client, &j.operator, &j.audit_context.csv_baseline
                                                                        ).await;
                                                                        if !matches!(gen_check, crate::teardown::audit::OperatorGenerationState::Absent) {
                                                                            eprintln!("  ⚠ Operator generation is no longer Absent — cleanup blocked.");
                                                                        } else {
                                                                            // Record decisions in journal, then DELETE each
                                                                            for res in &selected {
                                                                                // Record decision before mutation
                                                                                store.update(|j| {
                                                                                    j.audit_revision += 1;
                                                                                }).await
                                                                                .context("Failed to record cleanup decision")?;

                                                                                // Use core executor DELETE (UID-preconditioned)
                                                                                let del_result = crate::teardown::executor::delete_resource_pub(
                                                                                    &client, res, &kind_map, &gk_map, Some(&gate),
                                                                                ).await;
                                                                                match del_result {
                                                                                    Ok(msg) => eprintln!("    ✓ {}/{}: {}", res.kind, res.name, msg),
                                                                                    Err(e) => eprintln!("    ✗ {}/{}: {}", res.kind, res.name, e),
                                                                                }
                                                                            }

                                                                            // Re-run audit after cleanup
                                                                            eprintln!("\n  🔍 Re-running residual audit...");
                                                                            if let Ok(new_audit) = crate::teardown::audit::run_residual_audit(&client, &j).await {
                                                                                crate::teardown::audit::print_residual_audit(&new_audit, &j);
                                                                                let new_status = crate::teardown::audit::residual_status_from_audit(&new_audit);
                                                                                let _ = store.update(|j| {
                                                                                    j.residual_status = new_status;
                                                                                    j.audit_revision += 1;
                                                                                    j.last_residual_audit = Some(new_audit);
                                                                                }).await;
                                                                            }
                                                                        }
                                                                    }
                                                                }
                                                            }
                                                        } else {
                                                            eprintln!("  Use 'teardown journal' to review details.");
                                                        }
                                                    } else {
                                                        eprintln!("  Use 'teardown journal' to review.");
                                                    }
                                                }
                                                journal::ResidualStatus::AuditIncomplete => {
                                                    eprintln!(
                                                        "\n⚠ Residual audit incomplete — manual cleanup is not available."
                                                    );
                                                }
                                                journal::ResidualStatus::NoneObservedInScope => {
                                                    eprintln!("\n✅ No residuals observed in scanned scope.");
                                                }
                                                _ => {}
                                            }
                                        }
                                    }
                                }

                                if !result.failed.is_empty() || result.barrier_timeout.is_some() {
                                    bail!(
                                        "Teardown completed with {} failed action(s){}",
                                        result.failed.len(),
                                        if result.barrier_timeout.is_some() { " and barrier timeout" } else { "" }
                                    );
                                }
                            }
                            Err(e) => {
                                // Best-effort: record Failed state in journal, then propagate error
                                if let Some(store) = &journal_store {
                                    if let Err(je) = store.update(|j| {
                                        j.state = RunState::Failed;
                                    }).await {
                                        eprintln!("⚠ Additionally, failed to persist Failed state to journal: {}", je);
                                    }
                                }
                                return Err(e);
                            }
                        }
                    }
                    TeardownAction::Status {
                        operators: operator_queries,
                        no_cache,
                        plan_file,
                    } => {
                        let t0 = Instant::now();
                        eprintln!("🔍 Discovering API resources...");
                        let (kind_map, _gvr_map, gk_map, _gvk_map) =
                            build_kind_lookup_cached(&client, &config, no_cache).await?;
                        eprintln!("   Discovery: {:.1}s", t0.elapsed().as_secs_f64());

                        let plan = if let Some(path) = plan_file {
                            eprintln!("📄 Loading plan from {}", path);
                            load_plan_from_file(&path)?
                        } else {
                            eprint!("🔍 Discovering operators...");
                            let all_operators = discover_operators(&client, &kind_map).await?;
                            eprintln!(" found {} operators", all_operators.len());

                            let target_indices =
                                resolve_operator_targets(&operator_queries, &all_operators)?;
                            let target_operators: Vec<&_> =
                                target_indices.iter().map(|&i| &all_operators[i]).collect();

                            generate_teardown_plan(
                                &client,
                                &target_operators,
                                &all_operators,
                                &kind_map,
                                &_gvr_map,
                                &gk_map,
                                &_gvk_map,
                                false,
                                &DecisionPolicy::empty(),
                            )
                            .await?
                        };

                        eprint!("🔍 Checking resource status...");
                        let statuses = check_plan_status(&client, &plan, &kind_map, &gk_map).await;
                        eprintln!(" done");

                        print_plan_status(&plan, &statuses);
                    }
                    TeardownAction::Inspect {
                        operator: operator_query,
                        output,
                        no_cache,
                    } => {
                        let t0 = Instant::now();
                        eprintln!("🔍 Discovering API resources...");
                        let (kind_map, gvr_map, gk_map, _) =
                            build_kind_lookup_cached(&client, &config, no_cache).await?;
                        eprintln!("   Discovery: {:.1}s", t0.elapsed().as_secs_f64());

                        eprint!("🔍 Discovering operators...");
                        let all_operators = discover_operators(&client, &kind_map).await?;
                        eprintln!(" found {} operators", all_operators.len());

                        let target_indices =
                            resolve_operator_targets(&[operator_query], &all_operators)?;
                        let target_op = &all_operators[target_indices[0]];

                        let inspection =
                            inspect_operator(&client, target_op, &kind_map, &gvr_map, &gk_map)
                                .await?;

                        print_inspection(&inspection, &output);
                    }
                    TeardownAction::Explain {
                        operators: operator_queries,
                        resource,
                        no_cache,
                    } => {
                        let t0 = Instant::now();
                        eprintln!("🔍 Discovering API resources...");
                        let (kind_map, gvr_map, gk_map, gvk_map) =
                            build_kind_lookup_cached(&client, &config, no_cache).await?;
                        eprintln!("   Discovery: {:.1}s", t0.elapsed().as_secs_f64());

                        eprint!("🔍 Discovering operators...");
                        let all_operators = discover_operators(&client, &kind_map).await?;
                        eprintln!(" found {} operators", all_operators.len());

                        let target_indices =
                            resolve_operator_targets(&operator_queries, &all_operators)?;
                        let target_operators: Vec<&_> =
                            target_indices.iter().map(|&i| &all_operators[i]).collect();

                        let plan = generate_teardown_plan(
                            &client,
                            &target_operators,
                            &all_operators,
                            &kind_map,
                            &gvr_map,
                            &gk_map,
                            &gvk_map,
                            false,
                            &DecisionPolicy::empty(),
                        )
                        .await?;

                        let namespace = target_operators
                            .first()
                            .map(|op| op.install_namespace.as_str())
                            .unwrap_or("default");

                        let snapshot =
                            build_snapshot(&client, &config, namespace, &kind_map, false).await?;

                        let evidence_graph = build_evidence_graph(&snapshot, &all_operators);

                        let explanation =
                            explain_resource(&plan, &resource, &all_operators, &evidence_graph);
                        println!("{}", explanation);
                    }
                    TeardownAction::Resume { operator, run, no_cache } => {
                        let cluster_id = journal::fetch_cluster_identity(&client).await?;

                        let found = if let Some(run_id) = run {
                            let path = journal::run_path(&cluster_id, &run_id)?;
                            Some(journal::load_journal(&path)?)
                        } else if let Some(op) = operator {
                            journal::find_latest_run(&cluster_id, &op)?
                        } else {
                            bail!("Specify an operator name or --run <run-id>");
                        };

                        let j = match found {
                            Some(j) => j,
                            None => bail!("No teardown run found to resume"),
                        };

                        // Verify cluster identity
                        if !j.cluster_identity.matches(&cluster_id) {
                            bail!(
                                "Journal cluster identity does not match current cluster \
                                 (journal: {}, current: {})",
                                j.cluster_identity.kube_system_uid,
                                cluster_id.kube_system_uid,
                            );
                        }

                        match j.state {
                            RunState::Paused | RunState::Applying => {
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

                                // Re-discover API resources
                                let t0 = Instant::now();
                                eprintln!("🔍 Re-discovering API resources...");
                                let (kind_map, _gvr_map, gk_map, gvk_map) =
                                    build_kind_lookup_cached(&client, &config, no_cache).await?;
                                eprintln!("   Discovery: {:.1}s", t0.elapsed().as_secs_f64());

                                // Re-verify operator generation
                                use crate::teardown::audit::{
                                    self, OperatorGenerationState,
                                };
                                let gen_state = audit::check_operator_generation(
                                    &client,
                                    &j.operator,
                                    &j.audit_context.csv_baseline,
                                )
                                .await;

                                match gen_state {
                                    OperatorGenerationState::SameGeneration => {
                                        // Original operator still active — can resume
                                    }
                                    OperatorGenerationState::Absent => {
                                        eprintln!(
                                            "  Operator generation absent — \
                                             teardown may have completed. Check status."
                                        );
                                    }
                                    OperatorGenerationState::Reappeared => {
                                        bail!(
                                            "Operator has been reinstalled (new generation). \
                                             Cannot resume old teardown — create a new plan."
                                        );
                                    }
                                    OperatorGenerationState::Unknown(reason) => {
                                        bail!(
                                            "Cannot verify operator generation: {}. \
                                             Cannot safely resume.",
                                            reason
                                        );
                                    }
                                }

                                // Acquire process lock — fail if another executor is active
                                let path = journal::run_path(&cluster_id, &j.run_id)?;
                                let store = JournalStore::new_with_lock(j.clone(), path)?;

                                // Reconcile completed phases via live GET.
                                // Journal = hint, live GET = truth.
                                use crate::teardown::planner::Action;
                                let start_phase = {
                                    let completed = j.execution.phases_completed;
                                    let mut verified_through = completed;
                                    'phase_check: for (pi, phase) in
                                        j.plan_snapshot.phases.iter().take(completed).enumerate()
                                    {
                                        for action in &phase.actions {
                                            let resource = match action {
                                                Action::Delete { resource, .. }
                                                | Action::ExpectGone { resource, .. } => resource,
                                                _ => continue,
                                            };
                                            let (api, _) = match crate::kube::resource::resolve_api(
                                                &client, resource, &kind_map, &gk_map,
                                            ) {
                                                Some(r) => r,
                                                None => bail!(
                                                    "Cannot resolve API for {}/{} — \
                                                     cannot verify state for resume",
                                                    resource.kind, resource.name,
                                                ),
                                            };
                                            match api.get(&resource.name).await {
                                                Ok(obj) => {
                                                    let live_uid =
                                                        obj.metadata.uid.as_deref().unwrap_or("");
                                                    // UID check
                                                    let plan_uid = match &resource.uid {
                                                        Some(u) if !u.is_empty() => u.as_str(),
                                                        _ => bail!(
                                                            "Plan resource {}/{} has no UID — \
                                                             cannot verify identity for resume",
                                                            resource.kind, resource.name,
                                                        ),
                                                    };
                                                    if live_uid != plan_uid {
                                                        bail!(
                                                            "Resource {}/{} was recreated \
                                                             (plan UID {} vs live UID {}) — \
                                                             cannot resume. Create a new plan.",
                                                            resource.kind,
                                                            resource.name,
                                                            plan_uid,
                                                            live_uid,
                                                        );
                                                    }
                                                    // Same UID, still exists
                                                    if !obj.metadata.deletion_timestamp.is_some() {
                                                        // No deletionTimestamp → DELETE didn't happen
                                                        eprintln!(
                                                            "  ⚠ {}/{} still exists — \
                                                             re-executing from phase {}",
                                                            resource.kind, resource.name, pi
                                                        );
                                                        verified_through = pi;
                                                        break 'phase_check;
                                                    }
                                                    // Has deletionTimestamp → still deleting, needs wait
                                                    eprintln!(
                                                        "  ⏳ {}/{} still deleting — \
                                                         re-executing from phase {} to wait",
                                                        resource.kind, resource.name, pi
                                                    );
                                                    verified_through = pi;
                                                    break 'phase_check;
                                                }
                                                Err(::kube::Error::Api(ref err))
                                                    if err.code == 404 =>
                                                {
                                                    // Gone — safe to skip
                                                }
                                                Err(e) => {
                                                    bail!(
                                                        "Cannot verify {}/{} state: {} — \
                                                         cannot safely resume",
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
                                    start_phase, j.plan_snapshot.phases.len()
                                );

                                store
                                    .update(|journal| {
                                        journal.state = RunState::Applying;
                                    })
                                    .await
                                    .context("Failed to persist Applying state for resume")?;

                                let gate = std::sync::Arc::new(MutationGate::new(16));

                                // Ctrl-C handler for resume (same as normal apply)
                                {
                                    let gate_for_signal = gate.clone();
                                    tokio::spawn(async move {
                                        if tokio::signal::ctrl_c().await.is_ok() {
                                            eprintln!(
                                                "\n⏸ Pausing... waiting for active mutations..."
                                            );
                                            gate_for_signal.close_and_drain().await;
                                        }
                                    });
                                }

                                let exec_result = execute_plan(
                                    &client,
                                    &j.plan_snapshot,
                                    &kind_map,
                                    &gk_map,
                                    &gvk_map,
                                    &_gvr_map,
                                    false,
                                    true, // force — already confirmed
                                    Some(&store),
                                    Some(&gate),
                                    start_phase,
                                    true, // skip_confirm — this is a resume
                                )
                                .await;

                                match exec_result {
                                    Ok(result) => {
                                        // Same final state logic as normal apply:
                                        // gate.is_open() + all-phases-completed
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

                                        store
                                            .update(|journal| {
                                                journal.state = final_state.clone();
                                                journal.execution.phases_total = result.phases_total;
                                            })
                                            .await
                                            .context("Failed to persist final state")?;

                                        if final_state == RunState::Paused {
                                            eprintln!(
                                                "\n⏸ Paused at phase {}/{}.",
                                                result.phases_completed, result.phases_total
                                            );
                                        }

                                        print_execution_result(&result);

                                        if matches!(final_state, RunState::Failed) {
                                            bail!(
                                                "Resume completed with {} failed action(s){}",
                                                result.failed.len(),
                                                if result.barrier_timeout.is_some() {
                                                    " and barrier timeout"
                                                } else {
                                                    ""
                                                }
                                            );
                                        }
                                    }
                                    Err(e) => {
                                        // Best-effort record Failed
                                        if let Err(je) = store
                                            .update(|journal| {
                                                journal.state = RunState::Failed;
                                            })
                                            .await
                                        {
                                            eprintln!(
                                                "⚠ Failed to persist Failed state: {}", je
                                            );
                                        }
                                        return Err(e);
                                    }
                                }
                            }
                            RunState::ApplyCompleted | RunState::Finished => {
                                eprintln!(
                                    "Run {} is already completed (state: {:?}). \
                                     Nothing to resume.",
                                    j.run_id, j.state
                                );
                            }
                            RunState::Failed => {
                                eprintln!(
                                    "Run {} has failed. Review the journal and create a new plan \
                                     if needed.",
                                    j.run_id
                                );
                            }
                            _ => {
                                eprintln!(
                                    "Run {} is in state {:?} — cannot resume from this state.",
                                    j.run_id, j.state
                                );
                            }
                        }
                    }
                    TeardownAction::Runs => {
                        let cluster_id = journal::fetch_cluster_identity(&client).await?;
                        let runs = journal::list_runs(&cluster_id)?;
                        if runs.is_empty() {
                            eprintln!("No teardown runs found for this cluster.");
                        } else {
                            eprintln!("Teardown runs for cluster {}:\n", cluster_id.kube_system_uid);
                            for run in &runs {
                                eprintln!(
                                    "  {} {} {:?} ({})",
                                    run.run_id,
                                    run.operator.csv_name,
                                    run.state,
                                    run.created_at,
                                );
                            }
                        }
                    }
                    TeardownAction::Journal { operator, run, no_audit } => {
                        let cluster_id = journal::fetch_cluster_identity(&client).await?;

                        let found = if let Some(run_id) = run {
                            let path = journal::run_path(&cluster_id, &run_id)?;
                            Some(journal::load_journal(&path)?)
                        } else if let Some(op) = operator {
                            journal::find_latest_run(&cluster_id, &op)?
                        } else {
                            bail!("Specify an operator name or --run <run-id>");
                        };

                        match found {
                            Some(j) => {
                                use crate::teardown::audit::{
                                    self, OperatorGenerationState,
                                    print_residual_audit,
                                };

                                print_run_journal(&j);

                                if no_audit {
                                    eprintln!("\n(audit skipped via --no-audit)");
                                } else {
                                    let gen_state =
                                        audit::check_operator_generation(&client, &j.operator, &j.audit_context.csv_baseline)
                                            .await;

                                    match gen_state {
                                        OperatorGenerationState::Absent => {
                                            eprintln!("\n🔍 Running live residual audit...");
                                            match audit::run_residual_audit(&client, &j).await {
                                                Ok(result) => {
                                                    print_residual_audit(&result, &j);
                                                    // teardown journal is read-only — audit results are
                                                    // displayed but NOT persisted to the journal file.
                                                    // Cross-process journal writes require PR3's full
                                                    // exclusive lock design.
                                                }
                                                Err(e) => {
                                                    eprintln!("\n⚠ Residual audit failed: {}", e);
                                                }
                                            }
                                        }
                                        OperatorGenerationState::SameGeneration => {
                                            eprintln!("\n⚠ Original operator generation is still active.");
                                            eprintln!("  Resume normal teardown instead of residual cleanup.");
                                        }
                                        OperatorGenerationState::Reappeared => {
                                            eprintln!("\n⚠ A newer installation of {} exists.", j.operator.csv_name);
                                            eprintln!("  This teardown session is historical.");
                                            eprintln!("  Live residual attribution is unavailable because");
                                            eprintln!("  old and new generation resources cannot be distinguished safely.");
                                            if let Some(ref last_audit) = j.last_residual_audit {
                                                eprintln!("\n  Last reliable residual audit:");
                                                print_residual_audit(last_audit, &j);
                                            }
                                        }
                                        OperatorGenerationState::Unknown(reason) => {
                                            eprintln!("\n⚠ Cannot verify operator generation: {}", reason);
                                            eprintln!("  Residual audit and cleanup are blocked.");
                                        }
                                    }
                                }
                            }
                            None => {
                                eprintln!("No teardown run found.");
                            }
                        }
                    }
                }
                return Ok(());
            }
            Command::Operators { output, no_cache } => {
                let t0 = Instant::now();
                eprintln!("🔍 Discovering API resources...");
                let (kind_map, _, _gk_map, _) =
                    build_kind_lookup_cached(&client, &config, no_cache).await?;
                eprintln!("   Discovery: {:.1}s", t0.elapsed().as_secs_f64());

                eprint!("🔍 Discovering operators...");
                let operators = discover_operators(&client, &kind_map).await?;
                let deps = compute_operator_dependencies(&operators);
                eprintln!(
                    " found {} operators, {} dependencies",
                    operators.len(),
                    deps.len()
                );

                print_operators(&operators, &deps, &output);
                return Ok(());
            }
        }
    }

    // ── Default inspect mode (backward compatible) ──
    let namespace = args
        .namespace
        .clone()
        .unwrap_or(config.default_namespace.clone());

    if args.map {
        let t0 = Instant::now();
        eprintln!("🔍 Discovering API resources...");
        let (kind_map, _, _gk_map, _) =
            build_kind_lookup_cached(&client, &config, args.no_cache).await?;
        eprintln!("   Discovery: {:.1}s", t0.elapsed().as_secs_f64());
        let mut index = scan_namespace(
            &client,
            &namespace,
            &kind_map,
            args.include_events,
            !args.no_refs,
        )
        .await?;

        let uids_with_missing_parents: Vec<String> = index
            .by_uid
            .iter()
            .filter(|(_, info)| {
                info.owner_refs
                    .iter()
                    .any(|r| !index.by_uid.contains_key(&r.uid))
            })
            .map(|(uid, _)| uid.clone())
            .collect();
        if !uids_with_missing_parents.is_empty() {
            eprint!("🔗 Resolving cluster-scoped parents...");
            for uid in &uids_with_missing_parents {
                resolve_missing_parents(&mut index, uid, &client, &namespace, &kind_map).await;
            }
            eprintln!(" done");
        }

        let trees = build_namespace_map(&index, args.depth);

        match args.output {
            OutputFormat::Tree => {
                eprintln!(
                    "\n📦 Namespace: {} ({} trees, {} resources)\n",
                    namespace,
                    trees.len(),
                    index.by_uid.len()
                );
                for (i, tree) in trees.iter().enumerate() {
                    print_tree(tree, "", true, true);
                    if i < trees.len() - 1 {
                        println!();
                    }
                }
            }
            OutputFormat::Table => {
                let mut table = comfy_table::Table::new();
                table.set_header(vec!["Root", "Kind", "Name", "Children"]);
                for tree in &trees {
                    let total = count_nodes(tree);
                    table.add_row(vec![
                        format!("{}/{}", tree.info.kind, tree.info.name),
                        tree.info.kind.clone(),
                        tree.info.name.clone(),
                        total.to_string(),
                    ]);
                }
                println!("{table}");
            }
            OutputFormat::Json => {
                let output = serde_json::json!({
                    "namespace": namespace,
                    "totalResources": index.by_uid.len(),
                    "trees": trees.iter().map(tree_to_json).collect::<Vec<_>>(),
                });
                println!(
                    "{}",
                    serde_json::to_string_pretty(&output).unwrap_or_default()
                );
            }
        }
        return Ok(());
    }

    let resource = args
        .resource
        .as_ref()
        .unwrap_or_else(|| {
            eprintln!("Error: RESOURCE is required (use --map for namespace-wide view)");
            std::process::exit(1);
        })
        .clone();

    let t0 = Instant::now();
    eprintln!("🔍 Discovering API resources...");
    let (kind_map, gvr_map, _gk_map, _) =
        build_kind_lookup_cached(&client, &config, args.no_cache).await?;
    eprintln!("   Discovery: {:.1}s", t0.elapsed().as_secs_f64());

    let (kind_input, name) = if let Some((k, n)) = resource.split_once('/') {
        (k.to_string(), n.to_string())
    } else {
        let k = args.kind.clone().unwrap_or_else(|| {
            eprintln!("Error: specify kind/name or use -k <KIND>");
            std::process::exit(1);
        });
        (k, resource)
    };

    let kind = resolve_kind(&kind_input, &kind_map, &gvr_map)?;

    if args.crd_origin {
        eprint!("🔍 Tracing CRD origin...");
        match find_crd_origin(&client, &kind, &kind_map).await {
            Some(chain) => {
                eprintln!(" done\n");
                print_crd_origin(&chain, &kind, &args.output);
            }
            None => {
                eprintln!();
                println!("{} is a built-in resource (no CRD).", kind);
            }
        }
        return Ok(());
    }

    if args.up_only {
        let chain = find_parents_only(&client, &kind, &name, &namespace, &kind_map).await?;
        if chain.is_empty() {
            println!("No resources found.");
            return Ok(());
        }
        match args.output {
            OutputFormat::Tree => {
                eprintln!("\n📦 Namespace: {}\n", namespace);
                print_chain_tree(&chain);
            }
            OutputFormat::Table => print_chain_table(&chain),
            OutputFormat::Json => print_chain_json(&chain, &namespace),
        }
        return Ok(());
    }

    let mut index = scan_namespace(
        &client,
        &namespace,
        &kind_map,
        args.include_events,
        !args.no_refs,
    )
    .await?;

    let target_uid = match index.by_kind_name.get(&(kind.to_lowercase(), name.clone())) {
        Some(uid) => uid.clone(),
        None => {
            bail!("{}/{} not found in namespace '{}'", kind, name, namespace);
        }
    };

    resolve_missing_parents(&mut index, &target_uid, &client, &namespace, &kind_map).await;

    if args.down_only {
        let mut visited = HashSet::new();
        match build_child_tree(
            &target_uid,
            &index,
            0,
            args.depth,
            &mut visited,
            &target_uid,
        ) {
            Some(tree) => display_tree(&tree, &args.output, &namespace),
            None => println!("No resources found."),
        }
    } else {
        match build_full_tree(&target_uid, &index, args.depth) {
            Some(tree) => display_tree(&tree, &args.output, &namespace),
            None => println!("No resources found."),
        }
    }

    if kind == "Service" {
        let pods = get_service_selected_pods(&client, &name, &namespace, &kind_map).await;
        if !pods.is_empty() {
            match args.output {
                OutputFormat::Json => {
                    let output = serde_json::json!({ "selectorPods": pods });
                    println!(
                        "{}",
                        serde_json::to_string_pretty(&output).unwrap_or_default()
                    );
                }
                _ => {
                    println!("\n📎 Service selector matches:");
                    for pod in &pods {
                        println!("   {}", pod);
                    }
                }
            }
        }
    }

    Ok(())
}

fn print_run_journal(j: &RunJournal) {
    eprintln!("Run:      {}", j.run_id);
    eprintln!("Operator: {}", j.operator.csv_name);
    eprintln!("State:    {:?}", j.state);
    eprintln!("Created:  {}", j.created_at);
    eprintln!("Updated:  {}", j.updated_at);
    eprintln!("Journal revision: {}", j.journal_revision);
    eprintln!("Audit revision:   {}", j.audit_revision);
    eprintln!();

    let exec = &j.execution;
    eprintln!(
        "Execution: {}/{} phases",
        exec.phases_completed, exec.phases_total
    );
    eprintln!(
        "  {} deleted, {} already gone, {} failed",
        exec.deleted.len(),
        exec.already_gone.len(),
        exec.failed.len()
    );

    if !exec.kept.is_empty() || !exec.reviewed.is_empty() {
        eprintln!(
            "\nPlanned preserved: {} KEEP, {} REVIEW",
            exec.kept.len(),
            exec.reviewed.len()
        );
    }
}

async fn create_run_journal(
    client: &::kube::Client,
    plan: &crate::teardown::planner::TeardownPlan,
    target_operators: &[&crate::analyzers::olm::OperatorInstance],
    gk_map: &crate::kube::discovery::GroupKindMap,
) -> Result<JournalStore> {
    use crate::teardown::plan::{
        ObservedResourceIdentity, OperatorGenerationIdentity,
        OperatorIdentitySnapshot,
    };

    if target_operators.len() > 1 {
        bail!(
            "Run journal currently supports single-operator teardown. \
             Use separate teardown commands for each operator."
        );
    }

    let cluster_id = journal::fetch_cluster_identity(client).await?;
    let run_id = journal::generate_run_id();

    let first_op = target_operators[0];
    let op_id = crate::analyzers::olm::OperatorId {
        namespace: first_op.install_namespace.clone(),
        csv_name: first_op.csv.name.clone(),
    };

    let generation_identity = match &first_op.package_name {
        Some(name) => OperatorGenerationIdentity::OlmPackage {
            package_name: name.clone(),
            install_namespace: first_op.install_namespace.clone(),
        },
        None => OperatorGenerationIdentity::Unverifiable {
            reason: "No subscription found; cannot establish stable package identity".to_string(),
        },
    };

    // Re-GET CSV and Subscription at journal creation time for fresh UIDs
    // (discovery may have happened minutes ago; resources could have been recreated)
    let csv_observed = {
        let fresh = fetch_observed_identities(
            client,
            &[first_op.csv.name.clone()],
            "ClusterServiceVersion",
            "operators.coreos.com/v1alpha1",
            &first_op.install_namespace,
        )
        .await?;
        fresh.into_iter().next()
            .context("CSV not found during identity snapshot; cannot establish generation identity")?
    };

    let sub_observed: Vec<ObservedResourceIdentity> = if let Some(sub) = &first_op.subscription {
        let fresh = fetch_observed_identities(
            client,
            &[sub.name.clone()],
            "Subscription",
            "operators.coreos.com/v1alpha1",
            sub.namespace.as_deref().unwrap_or(&first_op.install_namespace),
        )
        .await?;
        if fresh.is_empty() {
            bail!(
                "Subscription {} was observed during discovery but is now absent; \
                 cannot establish reliable generation identity",
                sub.name
            );
        }
        fresh
    } else {
        Vec::new()
    };

    let controller_deployments = fetch_observed_identities(
        client,
        &first_op.deployments,
        "Deployment",
        "apps/v1",
        &first_op.install_namespace,
    )
    .await?;

    let service_accounts = fetch_observed_identities(
        client,
        &first_op.service_accounts,
        "ServiceAccount",
        "v1",
        &first_op.install_namespace,
    )
    .await?;

    let operator_snapshot = OperatorIdentitySnapshot {
        generation_identity,
        operator_id: op_id,
        csv_name: first_op.csv.name.clone(),
        csv: csv_observed,
        subscriptions: sub_observed,
        controller_deployments,
        service_accounts,
        owned_crds: first_op.owned_crds.clone(),
        required_crds: first_op.required_crds.clone(),
    };

    let mut audit_context = journal::build_audit_context(plan, target_operators, &gk_map);

    // Capture CSV baseline: all CSVs in install namespace at plan time (name → uid).
    // Used by generation check to detect new CSVs not present before teardown.
    {
        use ::kube::api::{Api, DynamicObject, ApiResource, ListParams};
        use ::kube::core::GroupVersion;

        let csv_gvk = GroupVersion::gv("operators.coreos.com", "v1alpha1")
            .with_kind("ClusterServiceVersion");
        let csv_ar = ApiResource::from_gvk_with_plural(&csv_gvk, "clusterserviceversions");
        let csv_api: Api<DynamicObject> =
            Api::namespaced_with(client.clone(), &first_op.install_namespace, &csv_ar);

        audit_context.csv_baseline = match csv_api.list(&ListParams::default()).await {
            Ok(list) => {
                let mut baseline_entries = Vec::new();
                for csv in &list.items {
                    let name = csv.metadata.name.clone().ok_or_else(|| {
                        anyhow::anyhow!(
                            "CSV in install namespace has no name — cannot build baseline"
                        )
                    })?;
                    let uid = csv.metadata.uid.clone().ok_or_else(|| {
                        anyhow::anyhow!(
                            "CSV '{}' has no UID — cannot build baseline",
                            name
                        )
                    })?;
                    baseline_entries.push(journal::CsvBaselineEntry { name, uid });
                }
                Some(baseline_entries)
            }
            Err(e) => {
                bail!(
                    "Failed to capture CSV baseline for generation safety: {}. \
                     Cannot proceed without baseline.",
                    e
                );
            }
        };
    }

    let journal = RunJournal {
        run_id: run_id.clone(),
        schema_version: journal::RUN_JOURNAL_SCHEMA_VERSION,
        oc_deps_version: env!("CARGO_PKG_VERSION").to_string(),
        journal_revision: 0,
        cluster_identity: cluster_id.clone(),
        operator: operator_snapshot,
        created_at: journal::chrono_now_iso(),
        updated_at: journal::chrono_now_iso(),
        state: RunState::Prepared,
        residual_status: ResidualStatus::NotAudited,
        audit_revision: 0,
        audit_context,
        plan_snapshot: plan.clone(),
        execution: ExecutionRecord {
            phases_total: plan.phases.len(),
            ..Default::default()
        },
        last_residual_audit: None,
    };

    let path = journal::run_path(&cluster_id, &run_id)?;
    journal::atomic_write_json_pub(&path, &journal)?;

    JournalStore::new_with_lock(journal, path)
}

/// Fetch observed identities with UIDs for pre-execution snapshot.
/// 404 = resource absent (OK, skip). Any other error = fail-closed (abort journal creation).
async fn fetch_observed_identities(
    client: &::kube::Client,
    names: &[String],
    kind: &str,
    api_version: &str,
    namespace: &str,
) -> Result<Vec<crate::teardown::plan::ObservedResourceIdentity>> {
    use crate::teardown::plan::ObservedResourceIdentity;
    use ::kube::api::{Api, DynamicObject, ApiResource};
    use ::kube::core::GroupVersion;

    let (group, version) = if api_version.contains('/') {
        let parts: Vec<&str> = api_version.splitn(2, '/').collect();
        (parts[0].to_string(), parts[1].to_string())
    } else {
        (String::new(), api_version.to_string())
    };

    let gvk = GroupVersion::gv(&group, &version).with_kind(kind);
    let plural = format!("{}s", kind.to_lowercase());
    let ar = ApiResource::from_gvk_with_plural(&gvk, &plural);
    let api: Api<DynamicObject> = Api::namespaced_with(client.clone(), namespace, &ar);

    let mut results = Vec::new();
    for name in names {
        match api.get(name).await {
            Ok(obj) => {
                let rid = crate::kube::resource::ResourceId {
                    group: group.clone(),
                    version: version.clone(),
                    kind: kind.to_string(),
                    namespace: Some(namespace.to_string()),
                    name: name.clone(),
                    uid: obj.metadata.uid.clone(),
                };
                if let Some(observed) = ObservedResourceIdentity::from_resource_id(&rid) {
                    results.push(observed);
                } else {
                    bail!(
                        "Identity snapshot failed: {}/{} in {} has no UID",
                        kind, name, namespace
                    );
                }
            }
            Err(::kube::Error::Api(ref resp)) if resp.code == 404 => {
                // Resource genuinely absent — skip (not an error)
            }
            Err(e) => {
                bail!(
                    "Identity snapshot failed: cannot GET {}/{} in {}: {} \
                     (403/timeout/API errors are not safe to ignore)",
                    kind, name, namespace, e
                );
            }
        }
    }
    Ok(results)
}
