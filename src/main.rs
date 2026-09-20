mod analyzers;
mod cli;
mod graph;
mod kube;
mod output;
mod teardown;
mod tui;

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
    self, AuditContext, CleanupDecision, CleanupResult, ExecutionRecord, JournalStore,
    ResidualStatus, RunJournal, RunState,
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
                        tui: use_tui,
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

                        // TUI mode: ratatui interactive Plan Review → Execution → Residual Cleanup
                        if use_tui && !dry_run {
                            let journal_store = {
                                let store = create_run_journal(
                                    &client, &plan, &target_operators, &gk_map,
                                ).await?;
                                eprintln!("📓 Run journal: {}", store.path().display());

                                let current_id = journal::fetch_cluster_identity(&client).await?;
                                let stored = store.read().await;
                                if !current_id.matches(&stored.cluster_identity) {
                                    bail!("Cluster identity changed. Aborting.");
                                }
                                std::sync::Arc::new(store)
                            };
                            let gate = std::sync::Arc::new(MutationGate::new(16));

                            // Ctrl-C handler
                            {
                                let gate_for_signal = gate.clone();
                                tokio::spawn(async move {
                                    if tokio::signal::ctrl_c().await.is_ok() {
                                        gate_for_signal.close_and_drain().await;
                                    }
                                });
                            }

                            let mut plan = plan;
                            crate::tui::run_tui(
                                &client, &mut plan, &target_operators,
                                &kind_map, &gk_map, &gvk_map, &gvr_map,
                                &journal_store, &gate, force,
                            ).await?;
                            return Ok(());
                        }

                        // Headless script mode: drive AppState with JSON commands
                        if let Some(script_path) = &script {
                            use crate::teardown::app::{AppState, AppScreen, AppCommand, apply_command, AppStateSnapshot};
                            let mut app = AppState::new();
                            let mut plan = plan.clone();  // mutable copy for script overrides

                            // Read commands from script file (one JSON per line)
                            let content = std::fs::read_to_string(script_path)
                                .with_context(|| format!("Failed to read script: {}", script_path))?;

                            let mut events = Vec::new();
                            let mut script_journal: Option<std::sync::Arc<JournalStore>> = None;
                            let mut script_gate: Option<std::sync::Arc<MutationGate>> = None;
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
                                    // Apply draft overrides with fresh evidence revalidation
                                    // (same path as interactive Plan Review)
                                    if !app.draft_overrides.is_empty() {
                                        use crate::teardown::app::DraftAction;
                                        use crate::teardown::planner::Action;
                                        let mut mutated = plan.clone();
                                        for ovr in &app.draft_overrides {
                                            // P0: override MUST match a REVIEW action in the plan
                                            let found_review = mutated.phases.iter().any(|phase| {
                                                phase.actions.iter().any(|a| {
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
                                            if !found_review {
                                                bail!(
                                                    "Override for {}/{}/{} does not match any REVIEW action in the plan. \
                                                     Only REVIEW items can be overridden.",
                                                    ovr.resource.group, ovr.resource.kind, ovr.resource.name
                                                );
                                            }

                                            for phase in &mut mutated.phases {
                                                for action in &mut phase.actions {
                                                    if let Action::Review { resource, reason, metadata } = action {
                                                        if resource.group == ovr.resource.group
                                                            && resource.version == ovr.resource.version
                                                            && resource.kind == ovr.resource.kind
                                                            && resource.name == ovr.resource.name
                                                            && resource.namespace == ovr.resource.namespace
                                                        {
                                                            // P0: Three-way UID verification:
                                                            // 1. Override UID must be provided for DELETE
                                                            // 2. Override UID must match plan UID
                                                            // 3. Live UID must match plan UID
                                                            let ovr_uid = ovr.resource.uid.as_deref().unwrap_or("");
                                                            let plan_uid = resource.uid.as_deref().unwrap_or("");

                                                            match ovr.new_action {
                                                                DraftAction::Delete => {
                                                                    if ovr_uid.is_empty() {
                                                                        bail!(
                                                                            "Cannot approve DELETE for {}/{} without UID in approval",
                                                                            resource.kind, resource.name
                                                                        );
                                                                    }
                                                                    if plan_uid.is_empty() {
                                                                        bail!(
                                                                            "Cannot approve DELETE for {}/{}: plan resource has no UID",
                                                                            resource.kind, resource.name
                                                                        );
                                                                    }
                                                                    if ovr_uid != plan_uid {
                                                                        bail!(
                                                                            "Override UID {} does not match plan UID {} for {}/{}",
                                                                            ovr_uid, plan_uid, resource.kind, resource.name
                                                                        );
                                                                    }

                                                                    let (api, _) = crate::kube::resource::resolve_api(
                                                                        &client, resource, &kind_map, &gk_map,
                                                                    ).ok_or_else(|| anyhow::anyhow!(
                                                                        "Cannot resolve API for {}/{} — refusing to skip approved DELETE override",
                                                                        resource.kind, resource.name
                                                                    ))?;
                                                                    match api.get(&resource.name).await {
                                                                        Ok(obj) => {
                                                                            let live_uid = obj.metadata.uid.as_deref().unwrap_or("");
                                                                            if live_uid.is_empty() {
                                                                                bail!("Cannot apply override for {}/{}: live resource has no UID", resource.kind, resource.name);
                                                                            }
                                                                            if !plan_uid.is_empty() && live_uid != plan_uid {
                                                                                bail!(
                                                                                    "Cannot apply override for {}/{}: UID changed from {} to {} since plan was created.",
                                                                                    resource.kind, resource.name, plan_uid, live_uid
                                                                                );
                                                                            }
                                                                            // Basis drift: verify provenance hasn't degraded
                                                                            // Use journal's operator snapshot (has full controller deployment UIDs)
                                                                            {
                                                                                let ctx = journal::build_audit_context(&plan, &target_operators, &gk_map);
                                                                                let action_metadata = metadata.clone();
                                                                                let snap = if let Some(ref jstore) = script_journal {
                                                                                    let j = jstore.read().await;
                                                                                    j.operator.clone()
                                                                                } else {
                                                                                    build_operator_identity_snapshot(&client, &target_operators).await
                                                                                        .context("Cannot build identity snapshot for basis drift check")?
                                                                                };
                                                                                if let Err(reason) = revalidate_review_basis(&client, &obj, resource, &action_metadata, &ctx, &snap).await {
                                                                                    bail!(
                                                                                        "BLOCKED: {}/{} — basis drift: {}. Re-run 'teardown plan'.",
                                                                                        resource.kind, resource.name, reason
                                                                                    );
                                                                                }
                                                                            }
                                                                            let mut bound = resource.clone();
                                                                            bound.uid = Some(live_uid.to_string());
                                                                            *action = Action::Delete {
                                                                                resource: bound,
                                                                                reason: format!("{} (approved via script)", reason),
                                                                            };
                                                                        }
                                                                        Err(::kube::Error::Api(ref err)) if err.code == 404 => {
                                                                            eprintln!("  ⚠ {}/{} no longer present — override skipped", resource.kind, resource.name);
                                                                        }
                                                                        Err(e) => bail!("Cannot verify {}/{} for script override: {}", resource.kind, resource.name, e),
                                                                    }
                                                                }
                                                                DraftAction::Keep => {
                                                                    *action = Action::Keep {
                                                                        resource: resource.clone(),
                                                                        reason: format!("{} (kept via script)", reason),
                                                                    };
                                                                }
                                                            }
                                                        }
                                                    }
                                                }
                                            }
                                        }
                                        plan = mutated;
                                    }

                                    // Run executor with the plan
                                    script_journal = if !dry_run {
                                        let store = create_run_journal(
                                            &client, &plan, &target_operators, &gk_map,
                                        ).await?;
                                        Some(std::sync::Arc::new(store))
                                    } else {
                                        None
                                    };
                                    let journal_store = &script_journal;

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

                                    script_gate = Some(std::sync::Arc::new(MutationGate::new(16)));
                                    let gate = script_gate.as_ref().unwrap();
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
                                            // Best-effort Failed checkpoint (journal may already be in error state)
                                            if let Some(ref store) = script_journal {
                                                let _ = store.update(|j| {
                                                    j.state = RunState::Failed;
                                                }).await;
                                            }
                                            events.push(serde_json::json!({
                                                "execution_error": format!("{:#}", e)
                                            }));
                                        }
                                    }
                                }

                                // Transition to ResidualCleanup: ApplyCompleted + generation Absent + complete audit
                                if app.screen == AppScreen::Executing {
                                    if let (Some(store), true) = (&script_journal, result.is_ok()) {
                                        let j = store.read().await;
                                        if j.state == RunState::ApplyCompleted {
                                            let gen_check = crate::teardown::audit::check_operator_generation(
                                                &client, &j.operator, &j.audit_context.csv_baseline,
                                            ).await;
                                            if matches!(gen_check, crate::teardown::audit::OperatorGenerationState::Absent) {
                                                match crate::teardown::audit::run_residual_audit(&client, &j).await {
                                                    Ok(audit_result) => {
                                                        let status = crate::teardown::audit::residual_status_from_audit(&audit_result);
                                                        if matches!(status, journal::ResidualStatus::AuditIncomplete) {
                                                            events.push(serde_json::json!({
                                                                "screen_transition_blocked": "audit incomplete",
                                                            }));
                                                        } else {
                                                            // Re-verify generation after audit
                                                            let gen_recheck = crate::teardown::audit::check_operator_generation(
                                                                &client, &j.operator, &j.audit_context.csv_baseline,
                                                            ).await;
                                                            if !matches!(gen_recheck, crate::teardown::audit::OperatorGenerationState::Absent) {
                                                                events.push(serde_json::json!({
                                                                    "screen_transition_blocked": "generation changed during audit",
                                                                }));
                                                            } else {
                                                                store.update(|j| {
                                                                    j.residual_status = status;
                                                                    j.audit_revision += 1;
                                                                    j.last_residual_audit = Some(audit_result);
                                                                }).await
                                                                .context("Failed to persist residual audit for screen transition")?;
                                                                app.screen = AppScreen::ResidualCleanup;
                                                                events.push(serde_json::json!({
                                                                    "screen_transition": "ResidualCleanup",
                                                                }));
                                                            }
                                                        }
                                                    }
                                                    Err(e) => {
                                                        events.push(serde_json::json!({
                                                            "screen_transition_blocked": format!("audit failed: {}", e),
                                                        }));
                                                    }
                                                }
                                            } else {
                                                events.push(serde_json::json!({
                                                    "screen_transition_blocked": format!("generation: {:?}", gen_check),
                                                }));
                                            }
                                        } else {
                                            events.push(serde_json::json!({
                                                "screen_transition_blocked": format!("state is {:?}, not ApplyCompleted", j.state),
                                            }));
                                        }
                                    }
                                }

                                // Handle DeleteSelected: execute residual cleanup via core function
                                if matches!(cmd, AppCommand::DeleteSelected)
                                    && result.is_ok()
                                    && app.screen == AppScreen::ResidualCleanup
                                    && !app.selected_residuals.is_empty()
                                {
                                    if let (Some(store), Some(g)) = (&script_journal, &script_gate) {
                                        match crate::teardown::executor::execute_residual_cleanup(
                                            &client,
                                            &app.selected_residuals,
                                            store.as_ref(),
                                            g.as_ref(),
                                            &kind_map,
                                            &gk_map,
                                        ).await {
                                            Ok(cleanup_result) => {
                                                events.push(serde_json::json!({
                                                    "residual_cleanup": {
                                                        "status": "completed",
                                                        "deleted": cleanup_result.deleted.len(),
                                                        "skipped": cleanup_result.skipped.len(),
                                                        "failed": cleanup_result.failed.len(),
                                                        "skipped_details": cleanup_result.skipped.iter()
                                                            .map(|(r, reason)| format!("{}/{}: {}", r.kind, r.name, reason))
                                                            .collect::<Vec<_>>(),
                                                        "failed_details": cleanup_result.failed.iter()
                                                            .map(|(r, reason)| format!("{}/{}: {}", r.kind, r.name, reason))
                                                            .collect::<Vec<_>>(),
                                                    }
                                                }));
                                            }
                                            Err(e) => {
                                                // Cleanup error may include post-mutation journal failure.
                                                // Close gate to prevent further mutations and stop script.
                                                g.close_and_drain().await;
                                                events.push(serde_json::json!({
                                                    "residual_cleanup_error": format!("{:#}", e),
                                                    "gate_closed": true,
                                                    "script_stopped": true,
                                                }));
                                                // Break out of script command loop — no further mutations
                                                app.selected_residuals.clear();
                                                break;
                                            }
                                        }
                                        app.selected_residuals.clear();
                                    }
                                }
                            }

                            // Output full trace as JSON
                            let has_errors = events.iter().any(|e| {
                                e.get("execution_error").is_some()
                                    || e.get("residual_cleanup_error").is_some()
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

                                // Apply draft overrides with fresh evidence revalidation.
                                // Each REVIEW→DELETE conversion requires a live GET to
                                // verify the resource still exists with a bindable UID.
                                if !app.draft_overrides.is_empty() {
                                    let mut mutated_plan = plan.clone();
                                    let mut approved_count = 0usize;

                                    for over in &app.draft_overrides {
                                        for phase in &mut mutated_plan.phases {
                                            for action in &mut phase.actions {
                                                if let Action::Review { resource, reason, metadata } = action {
                                                    if resource.group == over.resource.group
                                                        && resource.version == over.resource.version
                                                        && resource.kind == over.resource.kind
                                                        && resource.name == over.resource.name
                                                        && resource.namespace == over.resource.namespace
                                                    {
                                                        match over.new_action {
                                                            DraftAction::Delete => {
                                                                // P0: Three-way UID check — all must be non-empty and match
                                                                let ovr_uid = over.resource.uid.as_deref().unwrap_or("");
                                                                let plan_uid = resource.uid.as_deref().unwrap_or("");
                                                                if ovr_uid.is_empty() {
                                                                    bail!(
                                                                        "Cannot approve DELETE for {}/{} without UID in approval",
                                                                        resource.kind, resource.name
                                                                    );
                                                                }
                                                                if plan_uid.is_empty() {
                                                                    bail!(
                                                                        "Cannot approve DELETE for {}/{}: plan resource has no UID",
                                                                        resource.kind, resource.name
                                                                    );
                                                                }
                                                                if ovr_uid != plan_uid {
                                                                    bail!(
                                                                        "Override UID {} does not match plan UID {} for {}/{}",
                                                                        ovr_uid, plan_uid, resource.kind, resource.name
                                                                    );
                                                                }
                                                                // Fresh GET to verify identity + bind UID + basis drift check
                                                                let verified = match crate::kube::resource::resolve_api(
                                                                    &client, resource, &kind_map, &gk_map,
                                                                ) {
                                                                    Some((api, _)) => {
                                                                        match api.get(&resource.name).await {
                                                                            Ok(obj) => {
                                                                                let live_uid = obj.metadata.uid.as_deref().unwrap_or("");
                                                                                if live_uid.is_empty() {
                                                                                    bail!("Cannot apply override for {}/{}: live resource has no UID", resource.kind, resource.name);
                                                                                }
                                                                                if !plan_uid.is_empty() && live_uid != plan_uid {
                                                                                    bail!(
                                                                                        "Cannot apply override for {}/{}: UID changed from {} to {}",
                                                                                        resource.kind, resource.name, plan_uid, live_uid
                                                                                    );
                                                                                }
                                                                                // Basis drift: verify provenance hasn't degraded
                                                                                // Use journal's operator snapshot (has full controller deployment UIDs)
                                                                                {
                                                                                    let ctx = journal::build_audit_context(&plan, &target_operators, &gk_map);
                                                                                    let action_metadata = metadata.clone();
                                                                                    let snap = build_operator_identity_snapshot(&client, &target_operators).await
                                                                                        .context("Cannot build identity snapshot for basis drift check")?;
                                                                                    if let Err(reason) = revalidate_review_basis(&client, &obj, resource, &action_metadata, &ctx, &snap).await {
                                                                                        bail!(
                                                                                            "BLOCKED: {}/{} — basis drift: {}. Re-run 'teardown plan'.",
                                                                                            resource.kind, resource.name, reason
                                                                                        );
                                                                                    }
                                                                                }
                                                                                let mut bound = resource.clone();
                                                                                bound.uid = Some(live_uid.to_string());
                                                                                *action = Action::Delete {
                                                                                    resource: bound,
                                                                                    reason: format!("{} (approved in Plan Review)", reason),
                                                                                };
                                                                                approved_count += 1;
                                                                                true
                                                                            }
                                                                            Err(::kube::Error::Api(ref err)) if err.code == 404 => {
                                                                                eprintln!("  ⚠ {}/{} no longer present — override skipped", resource.kind, resource.name);
                                                                                false
                                                                            }
                                                                            Err(e) => {
                                                                                bail!(
                                                                                    "Cannot verify {}/{} for draft override: {}",
                                                                                    resource.kind, resource.name, e
                                                                                );
                                                                            }
                                                                        }
                                                                    }
                                                                    None => {
                                                                        bail!(
                                                                            "Cannot resolve API for {}/{} — refusing to skip approved DELETE override",
                                                                            resource.kind, resource.name
                                                                        );
                                                                    }
                                                                };
                                                                let _ = verified;
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
                                    if approved_count > 0 {
                                        eprintln!("  {} REVIEW item(s) approved for DELETE (UID + evidence verified)", approved_count);
                                    }
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
                                                    // Check schema supports cleanup authority
                                                    let j_for_schema = store.read().await;
                                                    if j_for_schema.schema_version < 5 {
                                                        eprintln!(
                                                            "  ℹ Journal schema v{} does not support residual cleanup. \
                                                             Create a new teardown plan to enable cleanup.",
                                                            j_for_schema.schema_version
                                                        );
                                                    } else if is_tty {
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
                                                                        let selected_owned: Vec<crate::kube::resource::ResourceId> =
                                                                            selected.into_iter().cloned().collect();
                                                                        match crate::teardown::executor::execute_residual_cleanup(
                                                                            &client,
                                                                            &selected_owned,
                                                                            store.as_ref(),
                                                                            gate.as_ref(),
                                                                            &kind_map,
                                                                            &gk_map,
                                                                        ).await {
                                                                            Ok(cleanup_result) => {
                                                                                for res in &cleanup_result.deleted {
                                                                                    eprintln!("    ✓ {}/{}: Gone", res.kind, res.name);
                                                                                }
                                                                                for (res, reason) in &cleanup_result.skipped {
                                                                                    eprintln!("    ⚠ {}/{}: skipped — {}", res.kind, res.name, reason);
                                                                                }
                                                                                for (res, reason) in &cleanup_result.failed {
                                                                                    eprintln!("    ✗ {}/{}: {}", res.kind, res.name, reason);
                                                                                }
                                                                                if let Some(ref post_audit) = cleanup_result.post_audit {
                                                                                    let post_j = store.read().await;
                                                                                    crate::teardown::audit::print_residual_audit(post_audit, &post_j);
                                                                                }
                                                                            }
                                                                            Err(e) => {
                                                                                bail!("Residual cleanup failed: {:#}", e);
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

                                // Non-zero exit for non-ApplyCompleted states
                                match final_state {
                                    RunState::ApplyCompleted => {
                                        // Success — exit 0
                                    }
                                    RunState::Paused => {
                                        bail!(
                                            "Teardown paused at phase {}/{}",
                                            result.phases_completed, result.phases_total
                                        );
                                    }
                                    _ => {
                                        if !result.failed.is_empty() || result.barrier_timeout.is_some() {
                                            bail!(
                                                "Teardown completed with {} failed action(s){}",
                                                result.failed.len(),
                                                if result.barrier_timeout.is_some() {
                                                    " and barrier timeout"
                                                } else {
                                                    ""
                                                }
                                            );
                                        } else {
                                            bail!(
                                                "Teardown did not complete (state: {:?})",
                                                final_state
                                            );
                                        }
                                    }
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

                        // Pre-lock sanity check (non-authoritative — will re-verify after lock)
                        if !j.cluster_identity.matches(&cluster_id) {
                            bail!(
                                "Journal cluster identity does not match current cluster \
                                 (journal: {}, current: {})",
                                j.cluster_identity.kube_system_uid,
                                cluster_id.kube_system_uid,
                            );
                        }

                        match j.state {
                            RunState::Paused | RunState::Applying | RunState::InteractiveCleanup => {}
                            RunState::ApplyCompleted => {
                                if j.last_residual_audit.is_none() {
                                    // Crash between ApplyCompleted persist and audit — allow audit-only recovery
                                    eprintln!("Run {} is ApplyCompleted but has no residual audit — running audit recovery", j.run_id);
                                } else {
                                    bail!("Run {} already completed — nothing to resume", j.run_id);
                                }
                            }
                            RunState::Finished => {
                                bail!("Run {} already finished — nothing to resume", j.run_id);
                            }
                            RunState::Failed => {
                                bail!("Run {} has failed. Review the journal and create a new plan if needed.", j.run_id);
                            }
                            _ => {
                                bail!("Run {} is in state {:?} — cannot resume", j.run_id, j.state);
                            }
                        }

                                // Acquire process lock FIRST — fail if another executor is active
                                let path = journal::run_path(&cluster_id, &j.run_id)?;
                                let store = JournalStore::new_with_lock(j.clone(), path)?;

                                // Re-read from store — this is the AUTHORITATIVE state after lock.
                                // All decisions below use ONLY this `j`, not the pre-lock one.
                                let j = store.read().await;

                                // Re-verify state after lock (another process may have completed it)
                                match j.state {
                                    RunState::Paused | RunState::Applying | RunState::InteractiveCleanup => {}
                                    RunState::ApplyCompleted => {
                                        if j.last_residual_audit.is_some() {
                                            bail!("Run completed by another process — nothing to resume");
                                        }
                                        // ApplyCompleted + no audit = crash recovery allowed
                                    }
                                    RunState::Finished => {
                                        bail!("Run finished — nothing to resume");
                                    }
                                    RunState::Failed => {
                                        bail!("Run failed (possibly by another process). Create a new plan.");
                                    }
                                    _ => {
                                        bail!("Run is in state {:?} after lock — cannot resume", j.state);
                                    }
                                }

                                // Schema gate: all resume paths require current schema
                                if j.schema_version != journal::RUN_JOURNAL_SCHEMA_VERSION {
                                    bail!(
                                        "Journal schema v{} does not match current v{}. \
                                         Cannot resume on incompatible journal — create a new plan.",
                                        j.schema_version, journal::RUN_JOURNAL_SCHEMA_VERSION
                                    );
                                }

                                // Re-verify cluster identity with authoritative journal
                                if !j.cluster_identity.matches(&cluster_id) {
                                    bail!("Cluster identity mismatch after lock acquisition");
                                }

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

                                // Re-verify operator generation with AUTHORITATIVE journal
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
                                    OperatorGenerationState::SameGeneration => {}
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
                                                    // Verify endpoint exists before declaring Gone
                                                    match api.list(&::kube::api::ListParams::default().limit(1)).await {
                                                        Ok(_) => {
                                                            // Endpoint exists, resource genuinely gone
                                                        }
                                                        Err(_) => {
                                                            bail!(
                                                                "{}/{}: GET 404 but endpoint verification failed — \
                                                                 cannot confirm absence for resume",
                                                                resource.kind, resource.name
                                                            );
                                                        }
                                                    }
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

                                let gate = std::sync::Arc::new(MutationGate::new(16));

                                // Ctrl-C handler for resume
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

                                let resume_stage = classify_resume_stage(&j)
                                    .map_err(|e| anyhow::anyhow!("Cannot resume: {}", e))?;
                                let paused_from_residual = j.state == RunState::Paused
                                    && j.execution.phases_completed == j.execution.phases_total
                                    && j.last_residual_audit.is_some();

                                if resume_stage == ResumeStage::Cleanup {
                                    // Schema gate: v5 journals cannot gain resume authority
                                    if j.schema_version != journal::RUN_JOURNAL_SCHEMA_VERSION {
                                        bail!(
                                            "Journal schema v{} does not match current v{}. \
                                             Cannot resume cleanup on incompatible journal.",
                                            j.schema_version, journal::RUN_JOURNAL_SCHEMA_VERSION
                                        );
                                    }

                                    if resume_has_blocking_hard_failure(&j) {
                                        store.update(|j| { j.state = RunState::Failed; }).await?;
                                        bail!(
                                            "Journal contains hard-failed cleanup decisions from a prior run. \
                                             Cannot resume — create a new teardown plan."
                                        );
                                    }

                                    // Write InteractiveCleanup state for crash safety
                                    if j.state != RunState::InteractiveCleanup {
                                        store.update(|j| { j.state = RunState::InteractiveCleanup; }).await?;
                                    }
                                    let pending: Vec<crate::teardown::journal::CleanupDecision> =
                                        j.cleanup_decisions.iter()
                                            .filter(|d| d.is_pending())
                                            .cloned()
                                            .collect();

                                    let mut any_hard_failed = false;
                                    let mut any_retryable = false;
                                    if pending.is_empty() {
                                        if paused_from_residual {
                                            eprintln!("Resuming from Residual stage (no pending decisions).");
                                            // Re-verify generation before proceeding to re-audit
                                            let gen_check = audit::check_operator_generation(
                                                &client, &j.operator, &j.audit_context.csv_baseline,
                                            ).await;
                                            if !matches!(gen_check, OperatorGenerationState::Absent) {
                                                bail!("Operator generation not Absent on Residual resume — \
                                                       create a new teardown plan.");
                                            }
                                        } else {
                                            eprintln!("No pending cleanup decisions to resume.");
                                        }
                                    } else {
                                        eprintln!("Resuming {} pending cleanup decision(s)...", pending.len());
                                        for decision in &pending {
                                            if !gate.is_open() {
                                                eprintln!("⏸ Gate closed — stopping cleanup resume");
                                                break;
                                            }

                                            // Handle delete_requested: DELETE was sent but Gone
                                            // was not confirmed. Reconcile via live GET — do NOT
                                            // re-send DELETE (authority already used).
                                            if matches!(decision.result, Some(CleanupResult::DeleteRequested)) {
                                                let (api, _) = crate::kube::resource::resolve_api(
                                                    &client, &decision.resource, &kind_map, &gk_map,
                                                ).ok_or_else(|| anyhow::anyhow!(
                                                    "Cannot resolve API for {}/{}", decision.resource.kind, decision.resource.name
                                                ))?;
                                                match api.get(&decision.resource.name).await {
                                                    Err(::kube::Error::Api(ref err)) if err.code == 404 => {
                                                        // Verify endpoint exists (404 could be endpoint gone, not object gone)
                                                        match api.list(&::kube::api::ListParams::default().limit(1)).await {
                                                            Ok(_) => {
                                                                let res_up = decision.resource.clone();
                                                                store.update(|j| {
                                                                    if let Some(d) = j.cleanup_decisions.iter_mut().rev()
                                                                        .find(|d| d.resource == res_up && matches!(d.result, Some(CleanupResult::DeleteRequested)))
                                                                    { d.result = Some(CleanupResult::Gone); }
                                                                }).await?;
                                                                eprintln!("  {}/{}: gone (confirmed on resume)", decision.resource.kind, decision.resource.name);
                                                            }
                                                            Err(_) => {
                                                                eprintln!("  ⚠ {}/{}: GET 404 but endpoint verification failed — cannot confirm Gone",
                                                                    decision.resource.kind, decision.resource.name);
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
                                                                decision.resource.kind, decision.resource.name, bound, live_uid
                                                            );
                                                        }
                                                        if live_uid != bound {
                                                            let res_up = decision.resource.clone();
                                                            store.update(|j| {
                                                                if let Some(d) = j.cleanup_decisions.iter_mut().rev()
                                                                    .find(|d| d.resource == res_up && matches!(d.result, Some(CleanupResult::DeleteRequested)))
                                                                { d.result = Some(CleanupResult::Gone); }
                                                            }).await?;
                                                            eprintln!("  {}/{}: old UID gone (new UID {} = recreated)", decision.resource.kind, decision.resource.name, live_uid);
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
                                                                        match api.list(&::kube::api::ListParams::default().limit(1)).await {
                                                                            Ok(_) => { gone = true; break; }
                                                                            Err(_) => break,
                                                                        }
                                                                    }
                                                                    Ok(_) => continue,
                                                                    Err(_) => break,
                                                                }
                                                            }
                                                            if gone {
                                                                let res_up = decision.resource.clone();
                                                                store.update(|j| {
                                                                    if let Some(d) = j.cleanup_decisions.iter_mut().rev()
                                                                        .find(|d| d.resource == res_up && matches!(d.result, Some(CleanupResult::DeleteRequested)))
                                                                    { d.result = Some(CleanupResult::Gone); }
                                                                }).await?;
                                                                eprintln!("  {}/{}: gone (waited on resume)", decision.resource.kind, decision.resource.name);
                                                            } else {
                                                                eprintln!("  ⚠ {}/{}: still not Gone after wait", decision.resource.kind, decision.resource.name);
                                                                any_retryable = true;
                                                            }
                                                        } else {
                                                            // No deletionTimestamp — UID-bound authority exists.
                                                            // Re-DELETE requires same safety checks as fresh DELETE.
                                                            eprintln!("  {}/{}: exists without deletionTimestamp — verifying for re-DELETE", decision.resource.kind, decision.resource.name);

                                                            // Acquire permit first
                                                            let _re_permit = gate.acquire().await
                                                                .context("Mutation gate closed during re-DELETE")?;

                                                            // Post-permit: generation + audit + membership
                                                            let re_j = store.read().await;
                                                            let re_gen = audit::check_operator_generation(
                                                                &client, &re_j.operator, &re_j.audit_context.csv_baseline,
                                                            ).await;
                                                            if !matches!(re_gen, OperatorGenerationState::Absent) {
                                                                eprintln!("    ⚠ Generation not Absent for re-DELETE — skipping");
                                                                any_retryable = true;
                                                                drop(_re_permit);
                                                            } else {
                                                                match audit::run_residual_audit(&client, &re_j).await {
                                                                    Ok(re_audit) => {
                                                                        let re_status = audit::residual_status_from_audit(&re_audit);
                                                                        let re_in_set = !matches!(re_status, journal::ResidualStatus::AuditIncomplete)
                                                                            && re_audit.likely_operator_residual.iter()
                                                                                .chain(re_audit.unattributed.iter())
                                                                                .any(|r| r.resource == decision.resource);
                                                                        if !re_in_set {
                                                                            eprintln!("    ⚠ Not in current residual set for re-DELETE — skipping");
                                                                            any_retryable = true;
                                                                            drop(_re_permit);
                                                                        } else {
                                                                            // Post-audit generation recheck before mutation
                                                                            let re_gen2 = audit::check_operator_generation(
                                                                                &client, &re_j.operator, &re_j.audit_context.csv_baseline,
                                                                            ).await;
                                                                            if !matches!(re_gen2, OperatorGenerationState::Absent) {
                                                                                eprintln!("    ⚠ Generation changed during re-DELETE audit — skipping");
                                                                                any_retryable = true;
                                                                                drop(_re_permit);
                                                                                continue;
                                                                            }
                                                                            let re_del = crate::teardown::executor::delete_resource_pub(
                                                                                &client, &decision.resource, &kind_map, &gk_map,
                                                                                None, // permit already held
                                                                                decision.approved_spec_name.as_deref(),
                                                                            ).await;
                                                                            match re_del {
                                                                                Ok(msg) => {
                                                                                    eprintln!("    {}/{}: {}", decision.resource.kind, decision.resource.name, msg);
                                                                                    // Wait for Gone + checkpoint
                                                                                    if msg == "deleted" {
                                                                                        let mut re_gone = false;
                                                                                        for _ in 0..30 {
                                                                                            tokio::time::sleep(std::time::Duration::from_secs(2)).await;
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
                                                                                        let re_result = if re_gone { CleanupResult::Gone } else { CleanupResult::DeleteRequested };
                                                                                        let res_up = decision.resource.clone();
                                                                                        let re_result_clone = re_result.clone();
                                                                                        store.update(|j| {
                                                                                            if let Some(d) = j.cleanup_decisions.iter_mut().rev()
                                                                                                .find(|d| d.resource == res_up && matches!(d.result, Some(CleanupResult::DeleteRequested)))
                                                                                            { d.result = Some(re_result_clone); }
                                                                                        }).await
                                                                                        .context("Failed to checkpoint re-DELETE result")?;
                                                                                        if !re_gone {
                                                                                            any_retryable = true;
                                                                                        }
                                                                                    }
                                                                                }
                                                                                Err(e) => {
                                                                                    eprintln!("    ⚠ {}/{}: re-DELETE failed: {}", decision.resource.kind, decision.resource.name, e);
                                                                                    any_hard_failed = true;
                                                                                }
                                                                            }
                                                                            drop(_re_permit);
                                                                        }
                                                                    }
                                                                    Err(e) => {
                                                                        eprintln!("    ⚠ Post-permit audit failed for re-DELETE: {}", e);
                                                                        any_retryable = true;
                                                                        drop(_re_permit);
                                                                    }
                                                                }
                                                            }
                                                        }
                                                    }
                                                    Err(e) => {
                                                        eprintln!("  ⚠ {}/{}: cannot verify: {}", decision.resource.kind, decision.resource.name, e);
                                                        any_retryable = true;
                                                    }
                                                }
                                                continue;
                                            }

                                            // Below: result.is_none() — fresh DELETE needed
                                            // Validate decision authority fields
                                            if decision.action != "delete" {
                                                bail!("Pending decision for {}/{} has action '{}', expected 'delete' — cannot resume",
                                                    decision.resource.kind, decision.resource.name, decision.action);
                                            }
                                            if decision.bound_uid.as_deref().unwrap_or("").is_empty() {
                                                bail!("Pending decision for {}/{} has no bound_uid — cannot verify identity for resume",
                                                    decision.resource.kind, decision.resource.name);
                                            }

                                            if !gate.is_open() {
                                                eprintln!("⏸ Gate closed — stopping cleanup resume");
                                                break;
                                            }

                                            // 1. Per-resource generation check
                                            let j_cur = store.read().await;
                                            let gen_state = audit::check_operator_generation(
                                                &client, &j_cur.operator, &j_cur.audit_context.csv_baseline
                                            ).await;
                                            if !matches!(gen_state, OperatorGenerationState::Absent) {
                                                bail!("Generation not Absent — cannot resume cleanup");
                                            }

                                            // 2. Fresh complete audit + membership check
                                            let fresh_audit = audit::run_residual_audit(&client, &j_cur).await
                                                .context("Fresh audit failed during cleanup resume")?;
                                            let audit_status = audit::residual_status_from_audit(&fresh_audit);
                                            if matches!(audit_status, crate::teardown::journal::ResidualStatus::AuditIncomplete) {
                                                bail!("Audit incomplete — cannot verify residual membership for resume");
                                            }
                                            let in_set = fresh_audit.likely_operator_residual.iter()
                                                .chain(fresh_audit.unattributed.iter())
                                                .any(|r| r.resource.group == decision.resource.group
                                                    && r.resource.kind == decision.resource.kind
                                                    && r.resource.name == decision.resource.name
                                                    && r.resource.namespace == decision.resource.namespace);
                                            if !in_set {
                                                // Check if already Gone
                                                let (api, _) = crate::kube::resource::resolve_api(
                                                    &client, &decision.resource, &kind_map, &gk_map,
                                                ).ok_or_else(|| anyhow::anyhow!(
                                                    "Cannot resolve API for {}/{} — aborting resume",
                                                    decision.resource.kind, decision.resource.name
                                                ))?;
                                                match api.get(&decision.resource.name).await {
                                                    Err(::kube::Error::Api(ref err)) if err.code == 404 => {
                                                        // Verify endpoint exists before declaring AlreadyGone
                                                        match api.list(&::kube::api::ListParams::default().limit(1)).await {
                                                            Ok(_) => {
                                                                let res_up = decision.resource.clone();
                                                                store.update(|j| {
                                                                    if let Some(d) = j.cleanup_decisions.iter_mut().rev()
                                                                        .find(|d| d.resource == res_up && d.result.is_none())
                                                                    { d.result = Some(CleanupResult::AlreadyGone); }
                                                                }).await?;
                                                                eprintln!("  {}/{}: already gone", decision.resource.kind, decision.resource.name);
                                                                continue;
                                                            }
                                                            Err(_) => {
                                                                bail!("{}/{}: GET 404 but endpoint verification failed — \
                                                                       cannot confirm absence vs endpoint removal",
                                                                    decision.resource.kind, decision.resource.name);
                                                            }
                                                        }
                                                    }
                                                    _ => bail!("{}/{} not in current residual set and not Gone",
                                                        decision.resource.kind, decision.resource.name),
                                                }
                                            }

                                            // 3. Verify bound UID matches live
                                            let bound_uid = decision.bound_uid.as_deref().unwrap_or("");
                                            if bound_uid.is_empty() {
                                                bail!("Pending decision for {}/{} has no bound UID — cannot verify identity",
                                                    decision.resource.kind, decision.resource.name);
                                            }
                                            let (api, _) = crate::kube::resource::resolve_api(
                                                &client, &decision.resource, &kind_map, &gk_map,
                                            ).ok_or_else(|| anyhow::anyhow!(
                                                "Cannot resolve API for {}/{} — aborting resume",
                                                decision.resource.kind, decision.resource.name
                                            ))?;
                                            match api.get(&decision.resource.name).await {
                                                Ok(obj) => {
                                                    let live_uid = obj.metadata.uid.as_deref().unwrap_or("");
                                                    if live_uid != bound_uid {
                                                        bail!("Resource {}/{} UID changed ({} → {}) — cannot resume cleanup",
                                                            decision.resource.kind, decision.resource.name,
                                                            bound_uid, live_uid);
                                                    }
                                                }
                                                Err(::kube::Error::Api(ref err)) if err.code == 404 => {
                                                    match api.list(&::kube::api::ListParams::default().limit(1)).await {
                                                        Ok(_) => {
                                                            let res_up = decision.resource.clone();
                                                            store.update(|j| {
                                                                if let Some(d) = j.cleanup_decisions.iter_mut().rev()
                                                                    .find(|d| d.resource == res_up && d.result.is_none())
                                                                { d.result = Some(CleanupResult::AlreadyGone); }
                                                            }).await?;
                                                            eprintln!("  {}/{}: already gone", decision.resource.kind, decision.resource.name);
                                                            continue;
                                                        }
                                                        Err(_) => {
                                                            bail!("{}/{}: GET 404 but endpoint verification failed — \
                                                                   cannot confirm absence vs endpoint removal",
                                                                decision.resource.kind, decision.resource.name);
                                                        }
                                                    }
                                                }
                                                Err(e) => bail!("Cannot verify {}/{}: {} — aborting resume",
                                                    decision.resource.kind, decision.resource.name, e),
                                            }

                                            // 4. DELETE with permit held through checkpoint
                                            let _permit = gate.acquire().await
                                                .context("Mutation gate closed during cleanup resume")?;

                                            // Post-permit rechecks: generation + audit + membership could have changed
                                            {
                                                let pp_j = store.read().await;
                                                let pp_gen = audit::check_operator_generation(
                                                    &client, &pp_j.operator, &pp_j.audit_context.csv_baseline,
                                                ).await;
                                                if !matches!(pp_gen, OperatorGenerationState::Absent) {
                                                    bail!("Generation changed after permit acquisition — aborting resume");
                                                }
                                                let pp_audit = audit::run_residual_audit(&client, &pp_j).await
                                                    .context("Post-permit audit failed during resume")?;
                                                let pp_status = audit::residual_status_from_audit(&pp_audit);
                                                if matches!(pp_status, journal::ResidualStatus::AuditIncomplete) {
                                                    bail!("Post-permit audit incomplete — aborting resume");
                                                }
                                                let pp_in_set = pp_audit.likely_operator_residual.iter()
                                                    .chain(pp_audit.unattributed.iter())
                                                    .any(|r| r.resource.group == decision.resource.group
                                                        && r.resource.kind == decision.resource.kind
                                                        && r.resource.name == decision.resource.name
                                                        && r.resource.namespace == decision.resource.namespace);
                                                if !pp_in_set {
                                                    bail!("{}/{} no longer in residual set after permit acquisition",
                                                        decision.resource.kind, decision.resource.name);
                                                }
                                                // Final generation recheck after audit
                                                let pp_gen2 = audit::check_operator_generation(
                                                    &client, &pp_j.operator, &pp_j.audit_context.csv_baseline,
                                                ).await;
                                                if !matches!(pp_gen2, OperatorGenerationState::Absent) {
                                                    bail!("Generation changed during post-permit audit — aborting resume");
                                                }
                                            }

                                            let del = crate::teardown::executor::delete_resource_pub(
                                                &client, &decision.resource, &kind_map, &gk_map, None,
                                                decision.approved_spec_name.as_deref(),
                                            ).await;

                                            // Record initial result
                                            let initial_result = match &del {
                                                Ok(msg) if msg == "deleted" => CleanupResult::DeleteRequested,
                                                Ok(msg) if msg == "already_gone" => CleanupResult::AlreadyGone,
                                                Ok(_) => CleanupResult::DeleteRequested,
                                                Err(e) => { any_hard_failed = true; CleanupResult::Failed(e.to_string()) },
                                            };
                                            let res_up = decision.resource.clone();
                                            let initial_clone = initial_result.clone();
                                            store.update(|j| {
                                                if let Some(d) = j.cleanup_decisions.iter_mut().rev()
                                                    .find(|d| d.resource == res_up && d.result.is_none())
                                                { d.result = Some(initial_clone); }
                                            }).await.context("Failed to checkpoint cleanup result")?;
                                            drop(_permit);

                                            // 5. Wait for Gone (only if DELETE was accepted)
                                            if matches!(initial_result, CleanupResult::DeleteRequested) {
                                                let mut gone = false;
                                                for _ in 0..30 {
                                                    tokio::time::sleep(std::time::Duration::from_secs(2)).await;
                                                    match api.get(&decision.resource.name).await {
                                                        Err(::kube::Error::Api(ref err)) if err.code == 404 => {
                                                            match api.list(&::kube::api::ListParams::default().limit(1)).await {
                                                                Ok(_) => { gone = true; break; }
                                                                Err(_) => { any_retryable = true; break; }
                                                            }
                                                        }
                                                        Ok(_) => continue,
                                                        Err(_) => { any_retryable = true; break; }
                                                    }
                                                }
                                                if gone {
                                                    // Update result to "gone" (confirmed)
                                                    let res_up2 = decision.resource.clone();
                                                    store.update(|j| {
                                                        if let Some(d) = j.cleanup_decisions.iter_mut().rev()
                                                            .find(|d| d.resource == res_up2 && matches!(d.result, Some(CleanupResult::DeleteRequested)))
                                                        { d.result = Some(CleanupResult::Gone); }
                                                    }).await?;
                                                    eprintln!("  {}/{}: gone (confirmed)", decision.resource.kind, decision.resource.name);
                                                } else {
                                                    eprintln!("  ⚠ {}/{}: DELETE accepted but Gone not confirmed", decision.resource.kind, decision.resource.name);
                                                    any_retryable = true;
                                                }
                                            } else {
                                                eprintln!("  {}/{}: {:?}", decision.resource.kind, decision.resource.name, initial_result);
                                            }
                                        }
                                    }

                                    // 6. Mandatory re-audit
                                    let j_cur = store.read().await;
                                    let gen_state = audit::check_operator_generation(
                                        &client, &j_cur.operator, &j_cur.audit_context.csv_baseline
                                    ).await;
                                    let final_state = if !gate.is_open() {
                                        RunState::Paused
                                    } else if any_hard_failed {
                                        RunState::Failed
                                    } else if any_retryable {
                                        RunState::InteractiveCleanup
                                    } else if matches!(gen_state, OperatorGenerationState::Absent) {
                                        match audit::run_residual_audit(&client, &j_cur).await {
                                            Ok(re_audit) => {
                                                let status = audit::residual_status_from_audit(&re_audit);
                                                audit::print_residual_audit(&re_audit, &j_cur);
                                                store.update(|j| {
                                                    j.residual_status = status.clone();
                                                    j.audit_revision += 1;
                                                    j.last_residual_audit = Some(re_audit);
                                                }).await?;
                                                if matches!(status, crate::teardown::journal::ResidualStatus::AuditIncomplete) {
                                                    RunState::InteractiveCleanup
                                                } else {
                                                    let j_final = store.read().await;
                                                    if resume_has_blocking_hard_failure(&j_final) {
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
                                    store.update(|j| { j.state = final_state.clone(); }).await?;
                                    if final_state == RunState::Failed {
                                        bail!("Cleanup resume completed with hard failures");
                                    }
                                    if final_state == RunState::InteractiveCleanup {
                                        bail!(
                                            "Cleanup resume incomplete — pending decisions remain. \
                                             State persisted as InteractiveCleanup (retryable)."
                                        );
                                    }
                                    return Ok(());
                                }

                                // Main execution resume: write Applying before first mutation
                                store
                                    .update(|journal| {
                                        journal.state = RunState::Applying;
                                    })
                                    .await
                                    .context("Failed to persist Applying state for resume")?;

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

                                        // Post-resume: run residual audit (same as normal apply)
                                        if final_state == RunState::ApplyCompleted {
                                            let j_post = store.read().await;
                                            let post_gen = audit::check_operator_generation(
                                                &client, &j_post.operator, &j_post.audit_context.csv_baseline,
                                            ).await;
                                            if matches!(post_gen, OperatorGenerationState::Absent) {
                                                match audit::run_residual_audit(&client, &j_post).await {
                                                    Ok(post_audit) => {
                                                        let post_status = audit::residual_status_from_audit(&post_audit);
                                                        audit::print_residual_audit(&post_audit, &j_post);
                                                        // Re-verify generation after audit
                                                        let gen_recheck = audit::check_operator_generation(
                                                            &client, &j_post.operator, &j_post.audit_context.csv_baseline,
                                                        ).await;
                                                        if matches!(gen_recheck, OperatorGenerationState::Absent) {
                                                            store.update(|j| {
                                                                j.residual_status = post_status;
                                                                j.audit_revision += 1;
                                                                j.last_residual_audit = Some(post_audit);
                                                            }).await?;
                                                        }
                                                    }
                                                    Err(e) => {
                                                        eprintln!("⚠ Post-resume residual audit failed: {}", e);
                                                    }
                                                }
                                            }
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

    let operator_snapshot = build_operator_identity_snapshot(client, target_operators).await
        .context("Failed to build operator identity snapshot for journal")?;

    let first_op = target_operators[0];
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
        cleanup_decisions: Vec::new(),
    };

    let path = journal::run_path(&cluster_id, &run_id)?;
    journal::atomic_write_json_pub(&path, &journal)?;

    JournalStore::new_with_lock(journal, path)
}

/// Build a fresh OperatorIdentitySnapshot with live UIDs from the cluster.
/// Used for basis drift validation before journal creation.
async fn build_operator_identity_snapshot(
    client: &::kube::Client,
    target_operators: &[&crate::analyzers::olm::OperatorInstance],
) -> Result<crate::teardown::plan::OperatorIdentitySnapshot> {
    use crate::teardown::plan::{
        ObservedResourceIdentity, OperatorGenerationIdentity,
        OperatorIdentitySnapshot,
    };

    let first_op = target_operators[0];
    let op_id = crate::analyzers::olm::OperatorId {
        namespace: first_op.install_namespace.clone(),
        csv_name: first_op.csv.name.clone(),
    };

    // Fail-closed: Subscription exists but package name unknown/empty
    if first_op.subscription.is_some() {
        match &first_op.package_name {
            None => {
                bail!(
                    "Subscription exists but package name is unknown — \
                     cannot establish semantic identity for safe teardown."
                );
            }
            Some(pkg) if pkg.trim().is_empty() => {
                bail!(
                    "Subscription exists but package name is empty — \
                     cannot establish semantic identity for safe teardown."
                );
            }
            _ => {}
        }
    }

    let generation_identity = match &first_op.package_name {
        Some(name) if !name.trim().is_empty() => OperatorGenerationIdentity::OlmPackage {
            package_name: name.clone(),
            install_namespace: first_op.install_namespace.clone(),
        },
        _ => OperatorGenerationIdentity::Unverifiable {
            reason: "No subscription or empty package name".to_string(),
        },
    };

    let csv_observed = {
        let fresh = fetch_observed_identities(
            client,
            &[first_op.csv.name.clone()],
            "ClusterServiceVersion",
            "operators.coreos.com/v1alpha1",
            &first_op.install_namespace,
        ).await?;
        let obs = fresh.into_iter().next()
            .context("CSV not found during identity snapshot")?;
        // Verify discovery UID is present and matches fresh UID
        let discovery_uid = first_op.csv.uid.as_deref().unwrap_or("");
        if discovery_uid.is_empty() {
            bail!(
                "CSV {} has no UID from discovery — cannot verify identity for safe teardown",
                first_op.csv.name
            );
        }
        if obs.uid != discovery_uid {
            bail!(
                "CSV {} UID changed between discovery ({}) and snapshot ({}) — \
                 operator may have been recreated. Re-run 'teardown plan'.",
                first_op.csv.name, discovery_uid, obs.uid
            );
        }
        obs
    };

    let controller_deployments = fetch_observed_identities(
        client,
        &first_op.deployments,
        "Deployment",
        "apps/v1",
        &first_op.install_namespace,
    ).await?;

    let service_accounts = fetch_observed_identities(
        client,
        &first_op.service_accounts,
        "ServiceAccount",
        "v1",
        &first_op.install_namespace,
    ).await?;

    let sub_observed: Vec<ObservedResourceIdentity> = if let Some(sub) = &first_op.subscription {
        let fresh = fetch_observed_identities(
            client,
            &[sub.name.clone()],
            "Subscription",
            "operators.coreos.com/v1alpha1",
            sub.namespace.as_deref().unwrap_or(&first_op.install_namespace),
        ).await?;
        if fresh.is_empty() {
            bail!(
                "Subscription {} was observed during discovery but is now absent — \
                 cannot establish reliable generation identity",
                sub.name
            );
        }
        // Verify discovery UID is present and matches fresh UID
        let discovery_uid = sub.uid.as_deref().unwrap_or("");
        if discovery_uid.is_empty() {
            bail!(
                "Subscription {} has no UID from discovery — cannot verify identity",
                sub.name
            );
        }
        if let Some(obs) = fresh.first() {
            if obs.uid != discovery_uid {
                bail!(
                    "Subscription {} UID changed between discovery ({}) and snapshot ({}) — \
                     operator may have been recreated. Re-run 'teardown plan'.",
                    sub.name, discovery_uid, obs.uid
                );
            }
        }
        // Verify spec.name matches expected package
        if let Some(ref expected_package) = first_op.package_name {
            let sub_gvk = ::kube::core::GroupVersion::gv("operators.coreos.com", "v1alpha1")
                .with_kind("Subscription");
            let sub_ar = ::kube::api::ApiResource::from_gvk_with_plural(&sub_gvk, "subscriptions");
            let sub_api: ::kube::api::Api<::kube::api::DynamicObject> = ::kube::api::Api::namespaced_with(
                client.clone(),
                sub.namespace.as_deref().unwrap_or(&first_op.install_namespace),
                &sub_ar,
            );
            match sub_api.get(&sub.name).await {
                Ok(live_sub) => {
                    let live_spec_name = live_sub.data
                        .get("spec")
                        .and_then(|s| s.get("name"))
                        .and_then(|n| n.as_str())
                        .unwrap_or("");
                    if live_spec_name != expected_package.as_str() {
                        bail!(
                            "Subscription {} spec.name changed from '{}' to '{}' — \
                             semantic identity drift. Re-run 'teardown plan'.",
                            sub.name, expected_package, live_spec_name
                        );
                    }
                }
                Err(e) => {
                    bail!("Cannot verify Subscription {} spec.name: {}", sub.name, e);
                }
            }
        }
        fresh
    } else {
        Vec::new()
    };

    Ok(OperatorIdentitySnapshot {
        generation_identity,
        operator_id: op_id,
        csv_name: first_op.csv.name.clone(),
        csv: csv_observed,
        subscriptions: sub_observed,
        controller_deployments,
        service_accounts,
        owned_crds: first_op.owned_crds.clone(),
        required_crds: first_op.required_crds.clone(),
    })
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

/// Check if a resource still has evidence linking to the TARGET operator.
/// Evidence rules (matching audit.rs compute_confidence):
/// - ownerRef to target operator identity → sufficient
/// - target manager + target label → sufficient
/// - target label alone → insufficient for DELETE authority
/// - target manager alone → insufficient for DELETE authority
/// - arbitrary ownerRef without target match → insufficient
/// Re-classify fresh provenance from a live GET result using UID-based identity.
pub fn classify_fresh_provenance(
    obj: &::kube::api::DynamicObject,
    audit_ctx: &crate::teardown::journal::AuditContext,
    operator_snapshot: &crate::teardown::plan::OperatorIdentitySnapshot,
) -> crate::teardown::plan::ProvenanceSer {
    use crate::teardown::plan::ProvenanceSer;

    // ownerRef → Managed ONLY if ownerRef UID matches saved CSV/controller UID
    if let Some(owner_refs) = &obj.metadata.owner_references {
        for oref in owner_refs {
            let oref_uid = &oref.uid;
            if !oref_uid.is_empty() {
                if *oref_uid == operator_snapshot.csv.uid {
                    return ProvenanceSer::Managed;
                }
                for dep in &operator_snapshot.controller_deployments {
                    if *oref_uid == dep.uid {
                        return ProvenanceSer::Managed;
                    }
                }
            }
        }
    }

    let has_label = obj.metadata.labels.as_ref().map(|labels| {
        audit_ctx.csv_names.iter().any(|csv| {
            let prefix = csv.split('.').next().unwrap_or(csv);
            !prefix.is_empty()
                && labels
                    .keys()
                    .any(|k| k.starts_with(&format!("operators.coreos.com/{}", prefix)))
        })
    }).unwrap_or(false);

    let has_manager = obj.metadata.managed_fields.as_ref().map(|mfs| {
        mfs.iter().any(|mf| {
            mf.manager
                .as_ref()
                .is_some_and(|m| audit_ctx.controller_deployment_names.iter().any(|d| m.contains(d.as_str())))
        })
    }).unwrap_or(false);

    // LikelyManaged requires BOTH label AND manager
    if has_label && has_manager {
        ProvenanceSer::LikelyManaged
    } else {
        ProvenanceSer::Unknown
    }
}

/// Validate that fresh provenance hasn't degraded from the stored review metadata.
/// Provenance downgrade → BLOCK (basis drift detected).
///
/// For RelatedLabelOnly resources (Unknown provenance from CRD-based discovery),
/// performs a fresh GET on the governing CRD to verify the label still links to
/// the target operator's part-of set.
pub async fn revalidate_review_basis(
    client: &::kube::Client,
    obj: &::kube::api::DynamicObject,
    resource: &crate::kube::resource::ResourceId,
    metadata: &Option<crate::teardown::plan::ReviewMetadata>,
    audit_ctx: &crate::teardown::journal::AuditContext,
    operator_snapshot: &crate::teardown::plan::OperatorIdentitySnapshot,
) -> Result<(), String> {
    revalidate_review_basis_inner(client, obj, resource, metadata, audit_ctx, operator_snapshot).await
}

async fn revalidate_review_basis_inner(
    client: &::kube::Client,
    obj: &::kube::api::DynamicObject,
    resource: &crate::kube::resource::ResourceId,
    metadata: &Option<crate::teardown::plan::ReviewMetadata>,
    audit_ctx: &crate::teardown::journal::AuditContext,
    operator_snapshot: &crate::teardown::plan::OperatorIdentitySnapshot,
) -> Result<(), String> {
    let fresh = classify_fresh_provenance(obj, audit_ctx, operator_snapshot);
    match check_provenance_drift(metadata, &fresh) {
        ProvenanceDriftResult::Ok => Ok(()),
        ProvenanceDriftResult::Blocked(reason) => Err(reason),
        ProvenanceDriftResult::NeedsCrdVerification => {
            let saved_seeds: std::collections::HashSet<String> = metadata
                .as_ref()
                .map(|m| m.decisive_part_of_seeds.iter().cloned().collect())
                .unwrap_or_default();
            if saved_seeds.is_empty() {
                return Err("RelatedLabelOnly resource has no saved part-of seeds — \
                            cannot verify CRD-based evidence".to_string());
            }
            if saved_seeds.len() > 1 {
                return Err(format!(
                    "RelatedLabelOnly resource has {} part-of seed values {:?} — \
                     multi-value seed verification not yet supported (BLOCKED)",
                    saved_seeds.len(), saved_seeds
                ));
            }
            verify_governing_crd_label(client, resource, &saved_seeds).await
        }
    }
}

enum ProvenanceDriftResult {
    Ok,
    Blocked(String),
    NeedsCrdVerification,
}

/// Pure sync provenance drift check — testable without cluster.
fn check_provenance_drift(
    metadata: &Option<crate::teardown::plan::ReviewMetadata>,
    fresh: &crate::teardown::plan::ProvenanceSer,
) -> ProvenanceDriftResult {
    use crate::teardown::plan::{ProvenanceSer, DiscoverySourceSer};

    let stored_provenance = metadata
        .as_ref()
        .and_then(|m| m.provenance.as_ref());

    match (stored_provenance, fresh) {
        (Some(ProvenanceSer::Managed), ProvenanceSer::Managed) => ProvenanceDriftResult::Ok,
        (Some(ProvenanceSer::Managed), _) => {
            ProvenanceDriftResult::Blocked("provenance downgraded from Managed".to_string())
        }
        (Some(ProvenanceSer::LikelyManaged), ProvenanceSer::Managed | ProvenanceSer::LikelyManaged) => ProvenanceDriftResult::Ok,
        (Some(ProvenanceSer::LikelyManaged), ProvenanceSer::Unknown) => {
            ProvenanceDriftResult::Blocked("provenance downgraded from LikelyManaged to Unknown".to_string())
        }
        (Some(ProvenanceSer::Unknown), _) => {
            let discovery_source = metadata.as_ref().and_then(|m| m.discovery_source.as_ref());
            match discovery_source {
                Some(DiscoverySourceSer::RelatedLabelOnly) => {
                    ProvenanceDriftResult::NeedsCrdVerification
                }
                _ => {
                    ProvenanceDriftResult::Blocked(
                        "stored provenance was Unknown with no verifiable discovery source — \
                         cannot verify approval basis".to_string()
                    )
                }
            }
        }
        (None, _) => {
            ProvenanceDriftResult::Blocked("no stored provenance to verify against".to_string())
        }
    }
}

/// Pure sync CRD label value verification — testable without cluster.
/// Checks if a CRD label value is in the target-owned seed set.
fn verify_crd_label_value_in_seeds(
    crd_label_value: Option<&str>,
    seed_values: &std::collections::HashSet<String>,
    resource_group: &str,
    resource_kind: &str,
) -> Result<(), String> {
    let label_key = "platform.opendatahub.io/part-of";
    if seed_values.is_empty() {
        return Err("no part-of label seeds found on owned CRDs — cannot verify CRD-based evidence".to_string());
    }
    match crd_label_value {
        Some(value) => {
            if seed_values.contains(value) {
                Ok(())
            } else {
                Err(format!(
                    "governing CRD has '{}={}' but value not in target seed set {:?} — evidence invalidated",
                    label_key, value, seed_values
                ))
            }
        }
        None => {
            Err(format!(
                "governing CRD for {}/{} no longer has '{}' label — CRD-based evidence invalidated",
                resource_group, resource_kind, label_key
            ))
        }
    }
}

/// Verify the governing CRD for a resource still has a part-of label linking to the target operator.
///
/// Uses operator_snapshot.owned_crds to compute fresh part-of seeds and verifies
/// the governing CRD's label value is in that set.
/// Verify the governing CRD for a resource still has a part-of label value
/// matching the seeds saved at plan time.
async fn verify_governing_crd_label(
    client: &::kube::Client,
    resource: &crate::kube::resource::ResourceId,
    saved_seeds: &std::collections::HashSet<String>,
) -> Result<(), String> {
    use ::kube::api::{Api, DynamicObject, ApiResource};
    use ::kube::core::GroupVersion;

    let label_key = "platform.opendatahub.io/part-of";

    if resource.group.is_empty() {
        return Err("resource has no API group — cannot determine governing CRD".to_string());
    }

    // Find governing CRD by matching API group + kind
    let crd_gvk = GroupVersion::gv("apiextensions.k8s.io", "v1")
        .with_kind("CustomResourceDefinition");
    let crd_ar = ApiResource::from_gvk_with_plural(&crd_gvk, "customresourcedefinitions");
    let crd_api: Api<DynamicObject> = Api::all_with(client.clone(), &crd_ar);

    let crd_list = crd_api.list(&::kube::api::ListParams::default()).await
        .map_err(|e| format!("cannot list CRDs: {} — BLOCKED", e))?;

    let governing_crd = crd_list.items.iter().find(|crd| {
        let crd_name = crd.metadata.name.as_deref().unwrap_or("");
        crd_name.split_once('.').map(|(_, g)| g == resource.group).unwrap_or(false)
            && crd.data.get("spec")
                .and_then(|s| s.get("names"))
                .and_then(|n| n.get("kind"))
                .and_then(|k| k.as_str())
                .is_some_and(|k| k == resource.kind)
    });

    let crd = match governing_crd {
        Some(c) => c,
        None => {
            return Err(format!(
                "governing CRD for {}/{} not found — cannot verify label basis",
                resource.group, resource.kind
            ));
        }
    };

    // Verify CRD's label value is in the plan-time saved seed set
    let crd_labels = crd.metadata.labels.as_ref();
    let crd_part_of = crd_labels.and_then(|labels| labels.get(label_key));
    verify_crd_label_value_in_seeds(
        crd_part_of.map(|s| s.as_str()),
        saved_seeds,
        &resource.group,
        &resource.kind,
    )
}

// ── Resume classification (extracted for testability) ──

#[derive(Debug, PartialEq)]
pub enum ResumeStage {
    Cleanup,
    MainExecution,
}

pub fn classify_resume_stage(j: &journal::RunJournal) -> Result<ResumeStage, String> {
    let main_complete = j.execution.phases_completed == j.execution.phases_total;

    let has_pending_cleanup = !j.cleanup_decisions.is_empty()
        && j.cleanup_decisions.iter().any(|d| d.is_pending());

    let paused_from_residual = j.state == journal::RunState::Paused
        && main_complete
        && j.last_residual_audit.is_some();

    let needs_audit_recovery = j.state == journal::RunState::ApplyCompleted
        && j.last_residual_audit.is_none();

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
            j.execution.phases_completed,
            j.execution.phases_total,
        ));
    }
    // Inconsistent: ApplyCompleted but main not complete
    if j.state == journal::RunState::ApplyCompleted && !main_complete {
        return Err(format!(
            "Journal inconsistent: ApplyCompleted but only {}/{} phases complete",
            j.execution.phases_completed,
            j.execution.phases_total,
        ));
    }

    if (j.state == journal::RunState::InteractiveCleanup && main_complete)
        || (j.state == journal::RunState::Paused && main_complete && has_pending_cleanup)
        || paused_from_residual
        || needs_audit_recovery
    {
        Ok(ResumeStage::Cleanup)
    } else {
        Ok(ResumeStage::MainExecution)
    }
}

pub fn resume_has_blocking_hard_failure(j: &journal::RunJournal) -> bool {
    j.cleanup_decisions.iter().any(|d| d.is_hard_failed())
}

#[cfg(test)]
mod basis_drift_tests {
    use super::*;
    use crate::teardown::plan::*;
    use std::collections::HashSet;

    fn make_metadata(
        provenance: Option<ProvenanceSer>,
        discovery_source: Option<DiscoverySourceSer>,
    ) -> Option<ReviewMetadata> {
        Some(ReviewMetadata {
            category: None,
            approval_class: None,
            provenance,
            discovery_source,
            decisive_part_of_seeds: vec![],
        })
    }

    // ── check_provenance_drift ──

    #[test]
    fn managed_to_managed_ok() {
        let meta = make_metadata(Some(ProvenanceSer::Managed), None);
        assert!(matches!(
            check_provenance_drift(&meta, &ProvenanceSer::Managed),
            ProvenanceDriftResult::Ok
        ));
    }

    #[test]
    fn managed_downgrade_blocked() {
        let meta = make_metadata(Some(ProvenanceSer::Managed), None);
        assert!(matches!(
            check_provenance_drift(&meta, &ProvenanceSer::Unknown),
            ProvenanceDriftResult::Blocked(_)
        ));
    }

    #[test]
    fn likely_to_unknown_blocked() {
        let meta = make_metadata(Some(ProvenanceSer::LikelyManaged), None);
        assert!(matches!(
            check_provenance_drift(&meta, &ProvenanceSer::Unknown),
            ProvenanceDriftResult::Blocked(_)
        ));
    }

    #[test]
    fn unknown_no_discovery_source_blocked() {
        let meta = make_metadata(Some(ProvenanceSer::Unknown), None);
        assert!(matches!(
            check_provenance_drift(&meta, &ProvenanceSer::Unknown),
            ProvenanceDriftResult::Blocked(_)
        ));
    }

    #[test]
    fn unknown_direct_source_blocked() {
        let meta = make_metadata(
            Some(ProvenanceSer::Unknown),
            Some(DiscoverySourceSer::Direct),
        );
        assert!(matches!(
            check_provenance_drift(&meta, &ProvenanceSer::Unknown),
            ProvenanceDriftResult::Blocked(_)
        ));
    }

    #[test]
    fn unknown_related_label_only_needs_crd_verification() {
        let meta = make_metadata(
            Some(ProvenanceSer::Unknown),
            Some(DiscoverySourceSer::RelatedLabelOnly),
        );
        assert!(matches!(
            check_provenance_drift(&meta, &ProvenanceSer::Unknown),
            ProvenanceDriftResult::NeedsCrdVerification
        ));
    }

    #[test]
    fn no_stored_provenance_blocked() {
        let meta = make_metadata(None, None);
        assert!(matches!(
            check_provenance_drift(&meta, &ProvenanceSer::Managed),
            ProvenanceDriftResult::Blocked(_)
        ));
    }

    #[test]
    fn no_metadata_blocked() {
        assert!(matches!(
            check_provenance_drift(&None, &ProvenanceSer::Managed),
            ProvenanceDriftResult::Blocked(_)
        ));
    }

    // ── verify_crd_label_value_in_seeds ──

    #[test]
    fn crd_label_matches_seed_ok() {
        let seeds: HashSet<String> = ["platform"].iter().map(|s| s.to_string()).collect();
        assert!(verify_crd_label_value_in_seeds(
            Some("platform"), &seeds, "maas.opendatahub.io", "Config"
        ).is_ok());
    }

    #[test]
    fn crd_label_value_not_in_seeds_blocked() {
        let seeds: HashSet<String> = ["platform"].iter().map(|s| s.to_string()).collect();
        let result = verify_crd_label_value_in_seeds(
            Some("other-project"), &seeds, "maas.opendatahub.io", "Config"
        );
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("not in target seed set"));
    }

    #[test]
    fn crd_label_missing_blocked() {
        let seeds: HashSet<String> = ["platform"].iter().map(|s| s.to_string()).collect();
        let result = verify_crd_label_value_in_seeds(
            None, &seeds, "maas.opendatahub.io", "Config"
        );
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("no longer has"));
    }

    #[test]
    fn empty_seeds_blocked() {
        let seeds: HashSet<String> = HashSet::new();
        let result = verify_crd_label_value_in_seeds(
            Some("platform"), &seeds, "maas.opendatahub.io", "Config"
        );
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("no part-of label seeds"));
    }

    #[test]
    fn candidate_self_label_does_not_seed() {
        // Candidate CRD has label value "other" but target-owned CRDs only have "platform".
        // Candidate's own value must NOT appear in seeds (seeds come from owned CRDs only).
        let seeds: HashSet<String> = ["platform"].iter().map(|s| s.to_string()).collect();
        let result = verify_crd_label_value_in_seeds(
            Some("other"), &seeds, "components.platform.opendatahub.io", "Dashboard"
        );
        assert!(result.is_err(), "candidate's own label value must not match target seeds");
    }

    #[test]
    fn multiple_seeds_match_any() {
        let seeds: HashSet<String> = ["platform", "workbenches"]
            .iter().map(|s| s.to_string()).collect();
        assert!(verify_crd_label_value_in_seeds(
            Some("workbenches"), &seeds, "x.opendatahub.io", "Notebook"
        ).is_ok());
    }

    // ── Multi-seed MVP restriction ──

    #[test]
    fn multi_seed_blocked_in_provenance_drift() {
        let meta = Some(ReviewMetadata {
            category: None,
            approval_class: None,
            provenance: Some(ProvenanceSer::Unknown),
            discovery_source: Some(DiscoverySourceSer::RelatedLabelOnly),
            decisive_part_of_seeds: vec!["platform".to_string(), "workbenches".to_string()],
        });
        // Multi-seed → NeedsCrdVerification, but caller blocks at len() > 1
        assert!(matches!(
            check_provenance_drift(&meta, &ProvenanceSer::Unknown),
            ProvenanceDriftResult::NeedsCrdVerification
        ));
        // Verify the caller-side restriction
        let seeds: HashSet<String> = meta.as_ref().unwrap()
            .decisive_part_of_seeds.iter().cloned().collect();
        assert!(seeds.len() > 1, "multi-seed set must be blocked by caller");
    }

    #[test]
    fn single_seed_allows_crd_verification() {
        let meta = Some(ReviewMetadata {
            category: None,
            approval_class: None,
            provenance: Some(ProvenanceSer::Unknown),
            discovery_source: Some(DiscoverySourceSer::RelatedLabelOnly),
            decisive_part_of_seeds: vec!["platform".to_string()],
        });
        assert!(matches!(
            check_provenance_drift(&meta, &ProvenanceSer::Unknown),
            ProvenanceDriftResult::NeedsCrdVerification
        ));
        let seeds: HashSet<String> = meta.as_ref().unwrap()
            .decisive_part_of_seeds.iter().cloned().collect();
        assert_eq!(seeds.len(), 1, "single seed passes caller restriction");
    }

    #[test]
    fn empty_seeds_in_metadata_blocked_at_caller() {
        let meta = Some(ReviewMetadata {
            category: None,
            approval_class: None,
            provenance: Some(ProvenanceSer::Unknown),
            discovery_source: Some(DiscoverySourceSer::RelatedLabelOnly),
            decisive_part_of_seeds: vec![],
        });
        assert!(matches!(
            check_provenance_drift(&meta, &ProvenanceSer::Unknown),
            ProvenanceDriftResult::NeedsCrdVerification
        ));
        let seeds: HashSet<String> = meta.as_ref().unwrap()
            .decisive_part_of_seeds.iter().cloned().collect();
        assert!(seeds.is_empty(), "empty seeds blocked by caller");
    }

    // ── Resume stage + crash recovery tests (call extracted functions) ──

    fn make_test_journal(
        state: crate::teardown::journal::RunState,
        phases_completed: usize,
        phases_total: usize,
        has_audit: bool,
        decisions: Vec<crate::teardown::journal::CleanupDecision>,
    ) -> crate::teardown::journal::RunJournal {
        use crate::teardown::journal::*;
        use crate::teardown::plan::*;
        use crate::teardown::planner::*;
        RunJournal {
            run_id: "test-run".to_string(),
            schema_version: RUN_JOURNAL_SCHEMA_VERSION,
            oc_deps_version: "0.1.0".to_string(),
            journal_revision: 0,
            cluster_identity: ClusterIdentity {
                api_server: "https://test:6443".to_string(),
                kube_system_uid: "test-uid".to_string(),
            },
            operator: OperatorIdentitySnapshot {
                generation_identity: OperatorGenerationIdentity::Unverifiable { reason: "test".to_string() },
                operator_id: crate::analyzers::olm::OperatorId { namespace: "ns".to_string(), csv_name: "test.1.0".to_string() },
                csv_name: "test.1.0".to_string(),
                csv: ObservedResourceIdentity { resource: crate::kube::resource::ResourceId { group: "operators.coreos.com".to_string(), version: "v1alpha1".to_string(), kind: "ClusterServiceVersion".to_string(), namespace: Some("ns".to_string()), name: "test.1.0".to_string(), uid: Some("csv-uid".to_string()) }, uid: "csv-uid".to_string() },
                subscriptions: vec![], controller_deployments: vec![], service_accounts: vec![], owned_crds: vec![], required_crds: vec![],
            },
            created_at: "2026-01-01T00:00:00Z".to_string(),
            updated_at: "2026-01-01T00:00:00Z".to_string(),
            state,
            residual_status: ResidualStatus::NotAudited,
            audit_revision: 0,
            audit_context: AuditContext::default(),
            plan_snapshot: TeardownPlan { targets: vec![], preflight: Preflight { checks: vec![] }, phases: vec![], blockers: vec![], warnings: vec![], snapshot_taken_at: "2026-01-01T00:00:00Z".to_string() },
            execution: ExecutionRecord { phases_completed, phases_total, ..Default::default() },
            last_residual_audit: if has_audit { Some(crate::teardown::audit::ResidualAudit { planned_delete_still_present: vec![], planned_expect_still_present: vec![], expected_preserved: vec![], likely_operator_residual: vec![], unattributed: vec![], coverage: crate::teardown::audit::AuditCoverage { requested_probes: 0, succeeded_probes: 0 }, scan_errors: vec![] }) } else { None },
            cleanup_decisions: decisions,
        }
    }

    fn make_decision(name: &str, result: Option<crate::teardown::journal::CleanupResult>) -> crate::teardown::journal::CleanupDecision {
        crate::teardown::journal::CleanupDecision {
            resource: crate::kube::resource::ResourceId { group: "apps".to_string(), version: "v1".to_string(), kind: "Deployment".to_string(), namespace: Some("ns".to_string()), name: name.to_string(), uid: Some(format!("uid-{}", name)) },
            bound_uid: Some(format!("uid-{}", name)),
            action: "delete".to_string(),
            result,
            approved_spec_name: None,
        }
    }

    #[test]
    fn classify_resume_paused_from_residual_routes_to_cleanup() {
        use crate::teardown::journal::RunState;
        let j = make_test_journal(RunState::Paused, 7, 7, true, vec![]);
        assert_eq!(classify_resume_stage(&j).unwrap(), ResumeStage::Cleanup);
    }

    #[test]
    fn classify_resume_paused_from_main_routes_to_execution() {
        use crate::teardown::journal::RunState;
        let j = make_test_journal(RunState::Paused, 3, 7, false, vec![]);
        assert_eq!(classify_resume_stage(&j).unwrap(), ResumeStage::MainExecution);
    }

    #[test]
    fn classify_resume_interactive_cleanup_routes_to_cleanup() {
        use crate::teardown::journal::RunState;
        let j = make_test_journal(RunState::InteractiveCleanup, 7, 7, true, vec![]);
        assert_eq!(classify_resume_stage(&j).unwrap(), ResumeStage::Cleanup);
    }

    #[test]
    fn classify_resume_paused_with_pending_complete_routes_to_cleanup() {
        use crate::teardown::journal::{RunState, CleanupResult};
        let j = make_test_journal(RunState::Paused, 7, 7, false, vec![
            make_decision("a", None),
        ]);
        assert_eq!(classify_resume_stage(&j).unwrap(), ResumeStage::Cleanup);
    }

    #[test]
    fn classify_resume_pending_with_incomplete_phases_is_error() {
        use crate::teardown::journal::{RunState, CleanupResult};
        let j = make_test_journal(RunState::Paused, 5, 7, false, vec![
            make_decision("a", None),
        ]);
        assert!(classify_resume_stage(&j).is_err(),
            "Pending cleanup with incomplete main phases = inconsistent journal");
    }

    #[test]
    fn classify_resume_interactive_cleanup_incomplete_phases_is_error() {
        use crate::teardown::journal::RunState;
        let j = make_test_journal(RunState::InteractiveCleanup, 3, 7, true, vec![]);
        assert!(classify_resume_stage(&j).is_err(),
            "InteractiveCleanup with incomplete phases = inconsistent journal");
    }

    #[test]
    fn hard_failure_blocks_resume() {
        use crate::teardown::journal::{RunState, CleanupResult};
        let j = make_test_journal(RunState::InteractiveCleanup, 7, 7, true, vec![
            make_decision("failed", Some(CleanupResult::Failed("err".to_string()))),
            make_decision("pending", None),
        ]);
        assert!(resume_has_blocking_hard_failure(&j),
            "hard failure must block resume before pending is processed");
    }

    #[test]
    fn classify_resume_apply_completed_no_audit_routes_to_cleanup() {
        use crate::teardown::journal::RunState;
        let j = make_test_journal(RunState::ApplyCompleted, 7, 7, false, vec![]);
        assert_eq!(classify_resume_stage(&j).unwrap(), ResumeStage::Cleanup,
            "ApplyCompleted with no audit = crash recovery → cleanup branch");
    }

    #[test]
    fn classify_resume_apply_completed_with_audit_goes_to_main() {
        use crate::teardown::journal::RunState;
        let j = make_test_journal(RunState::ApplyCompleted, 7, 7, true, vec![]);
        assert_eq!(classify_resume_stage(&j).unwrap(), ResumeStage::MainExecution,
            "ApplyCompleted + has audit = fully completed (gate would bail first)");
    }

    #[test]
    fn no_hard_failure_allows_resume() {
        use crate::teardown::journal::{RunState, CleanupResult};
        let j = make_test_journal(RunState::InteractiveCleanup, 7, 7, true, vec![
            make_decision("gone", Some(CleanupResult::Gone)),
            make_decision("pending", Some(CleanupResult::DeleteRequested)),
        ]);
        assert!(!resume_has_blocking_hard_failure(&j),
            "DeleteRequested is retryable, not hard failure");
    }
}
