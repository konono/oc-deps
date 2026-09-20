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

                        // Create RunJournal before first mutation (fail-closed)
                        let journal_store = if !dry_run {
                            let store = create_run_journal(
                                &client, &plan, &target_operators,
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

                            Some(store)
                        } else {
                            None
                        };

                        let exec_result = execute_plan(
                            &client, &plan, &kind_map, &gk_map, &gvk_map, &gvr_map,
                            dry_run, force, journal_store.as_ref(),
                        )
                        .await;

                        match exec_result {
                            Ok(result) => {
                                if let Some(store) = &journal_store {
                                    store.update(|j| {
                                        j.state = if result.failed.is_empty() && result.barrier_timeout.is_none() {
                                            RunState::ApplyCompleted
                                        } else {
                                            RunState::Failed
                                        };
                                        j.execution.phases_total = result.phases_total;
                                    }).await
                                    .context("Failed to persist final execution state")?;
                                }
                                print_execution_result(&result);

                                // Run post-apply residual audit
                                if let Some(store) = &journal_store {
                                    if result.failed.is_empty() && result.barrier_timeout.is_none() {
                                        eprintln!("\n🔍 Running post-apply residual audit...");
                                        let j = store.read().await;
                                        match crate::teardown::audit::run_residual_audit(&client, &j).await {
                                            Ok(audit_result) => {
                                                let status = crate::teardown::audit::residual_status_from_audit(&audit_result);
                                                crate::teardown::audit::print_residual_audit(&audit_result, &j);
                                                let _ = store.update(|j| {
                                                    j.residual_status = status;
                                                    j.audit_revision += 1;
                                                    j.last_residual_audit = Some(audit_result);
                                                }).await;
                                            }
                                            Err(e) => {
                                                eprintln!("⚠ Post-apply residual audit failed: {}", e);
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
                                    let _ = store.update(|j| {
                                        j.state = RunState::Failed;
                                    }).await;
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
                                    print_residual_audit, residual_status_from_audit,
                                };

                                print_run_journal(&j);

                                if no_audit {
                                    eprintln!("\n(audit skipped via --no-audit)");
                                } else {
                                    let gen_state =
                                        audit::check_operator_generation(&client, &j.operator)
                                            .await;

                                    match gen_state {
                                        OperatorGenerationState::Absent => {
                                            eprintln!("\n🔍 Running live residual audit...");
                                            match audit::run_residual_audit(&client, &j).await {
                                                Ok(result) => {
                                                    let status = residual_status_from_audit(&result);
                                                    print_residual_audit(&result, &j);

                                                    // Best-effort: update journal with audit results
                                                    let path = journal::run_path(&cluster_id, &j.run_id)?;
                                                    if let Ok(mut updated) = journal::load_journal(&path) {
                                                        updated.residual_status = status;
                                                        updated.audit_revision += 1;
                                                        updated.last_residual_audit = Some(result);
                                                        let _ = journal::atomic_write_json_pub(&path, &updated);
                                                    }
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

    let audit_context = journal::build_audit_context(plan, target_operators);

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

    Ok(JournalStore::new(journal, path))
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
