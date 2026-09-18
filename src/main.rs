mod analyzers;
mod cli;
mod graph;
mod kube;
mod output;
mod teardown;

use std::collections::HashSet;
use std::time::Instant;

use anyhow::{Result, bail};
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
use crate::teardown::planner::{
    generate_teardown_plan, print_teardown_plan, resolve_operator_targets,
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
                            prune_apis,
                        )
                        .await?;

                        let result = execute_plan(
                            &client, &plan, &kind_map, &gk_map, &gvr_map, dry_run, force,
                        )
                        .await?;

                        print_execution_result(&result);
                    }
                    TeardownAction::Status {
                        operators: operator_queries,
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
                        )
                        .await?;

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
                        let (kind_map, gvr_map, _gk_map, _) =
                            build_kind_lookup_cached(&client, &config, no_cache).await?;
                        eprintln!("   Discovery: {:.1}s", t0.elapsed().as_secs_f64());

                        eprint!("🔍 Discovering operators...");
                        let all_operators = discover_operators(&client, &kind_map).await?;
                        eprintln!(" found {} operators", all_operators.len());

                        let target_indices =
                            resolve_operator_targets(&[operator_query], &all_operators)?;
                        let target_op = &all_operators[target_indices[0]];

                        let inspection =
                            inspect_operator(&client, target_op, &kind_map, &gvr_map).await?;

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
