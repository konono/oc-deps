mod analyzers;
mod cli;
mod graph;
mod kube;
mod output;

use std::collections::HashSet;
use std::time::Instant;

use anyhow::{Result, bail};
use clap::Parser;

use crate::analyzers::olm::{find_crd_origin, print_crd_origin};
use crate::analyzers::selector::get_service_selected_pods;
use crate::cli::{Args, Command, OutputFormat};
use crate::graph::tree::{TreeNode, build_child_tree, build_full_tree, build_namespace_map};
use crate::kube::discovery::{build_kind_lookup_cached, load_config_and_client, resolve_kind};
use crate::kube::scanner::{find_parents_only, resolve_missing_parents, scan_namespace};
use crate::kube::snapshot::{build_snapshot, save_snapshot};
use crate::output::json::{print_chain_json, print_json, tree_to_json};
use crate::output::table::{print_chain_table, print_table};
use crate::output::tree::{count_nodes, print_chain_tree, print_tree};

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
                let (kind_map, _) = build_kind_lookup_cached(&client, &config, no_cache).await?;
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
        let (kind_map, _) = build_kind_lookup_cached(&client, &config, args.no_cache).await?;
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
    let (kind_map, gvr_map) = build_kind_lookup_cached(&client, &config, args.no_cache).await?;
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
