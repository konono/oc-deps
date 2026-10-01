use crate::analyzers::selector::get_service_selected_pods;
use crate::cli::{Direction, OutputFormat, ShowField};
use crate::graph::tree::{TreeNode, build_child_tree, build_full_tree};
use crate::kube::discovery::{build_kind_lookup_cached, resolve_kind_with_group};
use crate::kube::resource::format_scan_warnings;
use crate::kube::scanner::{resolve_missing_parents, scan_namespace_with_extra_apis};
use crate::output::json::{print_chain_json, print_json, tree_to_json};
use crate::output::table::{print_chain_table, print_table};
use crate::output::tree::{TreeDisplayOpts, print_chain_tree, print_tree};
use anyhow::{Result, bail};
use std::collections::HashSet;

pub(crate) fn show_fields_to_tree_opts(show: &[ShowField]) -> TreeDisplayOpts {
    TreeDisplayOpts {
        show_labels: show.contains(&ShowField::Labels),
        show_annotations: show.contains(&ShowField::Annotations),
        show_spec: show.contains(&ShowField::PodResources),
    }
}

pub(crate) fn find_descendant_pods(
    root_uid: &str,
    index: &crate::kube::resource::NamespaceIndex,
) -> Vec<(String, String, std::collections::HashMap<String, String>)> {
    let mut pods = Vec::new();
    let mut stack = vec![root_uid.to_string()];
    let mut visited = std::collections::HashSet::new();
    while let Some(uid) = stack.pop() {
        if !visited.insert(uid.clone()) {
            continue;
        }
        if let Some(info) = index.by_uid.get(&uid)
            && info.kind == "Pod"
        {
            pods.push((info.name.clone(), info.uid.clone(), info.labels.clone()));
        }
        if let Some(children) = index.children_of.get(&uid) {
            stack.extend(children.iter().cloned());
        }
    }
    pods
}

pub(crate) fn display_tree(
    tree: &TreeNode,
    output: &OutputFormat,
    namespace: &str,
    opts: &TreeDisplayOpts,
) {
    match output {
        OutputFormat::Tree => {
            println!("\n📦 Namespace: {}\n", namespace);
            print_tree(tree, "", true, true, opts);
        }
        OutputFormat::Table => print_table(tree, opts.show_spec),
        OutputFormat::Json => print_json(tree, namespace, opts.show_annotations, opts.show_spec),
    }
}

#[allow(clippy::too_many_arguments)]
pub(crate) async fn handle_tree(
    client: &::kube::Client,
    config: &::kube::config::Config,
    resource: String,
    online: crate::cli::OnlineOpts,
    direction: Direction,
    depth: usize,
    no_refs: bool,
    include_events: bool,
    show: Vec<ShowField>,
) -> Result<()> {
    let namespace = online
        .namespace
        .unwrap_or_else(|| config.default_namespace.clone());
    let tree_opts = show_fields_to_tree_opts(&show);
    let show_spec = show.contains(&ShowField::PodResources);

    let (kind_input, name) = if let Some((k, n)) = resource.split_once('/') {
        (k.to_string(), n.to_string())
    } else {
        bail!("Resource must be in kind/name format (e.g. deployment/nginx)");
    };

    let t0 = std::time::Instant::now();
    eprintln!("🔍 Discovering API resources...");
    let (kind_map, gvr_map, gk_map, _) =
        build_kind_lookup_cached(client, config, online.refresh_discovery).await?;
    eprintln!("   Discovery: {:.1}s", t0.elapsed().as_secs_f64());

    let (kind, target_group) = resolve_kind_with_group(&kind_input, &kind_map, &gvr_map)?;

    if matches!(direction, Direction::Parents) {
        let (chain, parent_warnings) = crate::kube::scanner::find_parents_only(
            client,
            &target_group,
            &kind,
            &name,
            &namespace,
            &kind_map,
            &gk_map,
            show_spec,
            !no_refs,
        )
        .await?;
        if !parent_warnings.is_empty() {
            format_scan_warnings(&parent_warnings, online.verbose);
        }
        if chain.is_empty() {
            println!("No resources found.");
            return Ok(());
        }
        match online.output {
            OutputFormat::Tree => {
                println!("\n📦 Namespace: {}\n", namespace);
                print_chain_tree(&chain, &tree_opts);
            }
            OutputFormat::Table => print_chain_table(&chain, show_spec),
            OutputFormat::Json => print_chain_json(
                &chain,
                &namespace,
                tree_opts.show_annotations,
                show_spec,
                &parent_warnings,
            ),
        }
        if online.strict && !parent_warnings.is_empty() {
            std::process::exit(2);
        }
        return Ok(());
    }

    let (mut index, mut scan_warnings) = scan_namespace_with_extra_apis(
        client,
        &namespace,
        &kind_map,
        &gk_map,
        &target_group,
        &kind,
        include_events,
        !no_refs,
        show_spec,
    )
    .await?;

    format_scan_warnings(&scan_warnings, online.verbose);

    let group_for_lookup = Some(target_group.as_str()).filter(|g| !g.is_empty());
    let target_uid =
        match index.lookup_by_kind_name(group_for_lookup, &kind, &name, Some(&namespace)) {
            Some(uid) => uid.clone(),
            None => {
                if online.strict && !scan_warnings.is_empty() {
                    eprintln!(
                        "Error: {}/{} not found in namespace '{}' (scan was incomplete)",
                        kind, name, namespace
                    );
                    std::process::exit(2);
                }
                bail!("{}/{} not found in namespace '{}'", kind, name, namespace);
            }
        };

    let parent_warnings = resolve_missing_parents(
        &mut index,
        &target_uid,
        client,
        &namespace,
        &kind_map,
        &gk_map,
        show.contains(&ShowField::PodResources),
    )
    .await;
    scan_warnings.extend(parent_warnings);

    let tree = match direction {
        Direction::Children => {
            let mut visited = HashSet::new();
            build_child_tree(&target_uid, &index, 0, depth, &mut visited, &target_uid)
        }
        _ => build_full_tree(&target_uid, &index, depth),
    };

    let mut extra_json = serde_json::Map::new();

    if kind == "Service" {
        let pods = get_service_selected_pods(client, &name, &namespace, &kind_map).await;
        if !pods.is_empty() {
            match online.output {
                OutputFormat::Json => {
                    extra_json.insert("selectorPods".into(), serde_json::json!(pods));
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

    match tree {
        Some(t) => {
            if matches!(online.output, OutputFormat::Json) {
                let target = format!("{}/{}", kind, name);
                let json_warnings: Vec<serde_json::Value> = scan_warnings
                    .iter()
                    .map(|w| {
                        serde_json::to_value(w).unwrap_or_else(|_| serde_json::json!(w.to_string()))
                    })
                    .collect();
                let mut output = serde_json::json!({
                    "namespace": namespace,
                    "target": target,
                    "scope": "namespace",
                    "tree": tree_to_json(&t, tree_opts.show_annotations, show_spec),
                    "warnings": json_warnings,
                    "scanWarningCount": scan_warnings.len(),
                });
                for (k, v) in extra_json {
                    output[k] = v;
                }
                println!(
                    "{}",
                    serde_json::to_string_pretty(&output).unwrap_or_default()
                );
            } else {
                display_tree(&t, &online.output, &namespace, &tree_opts);
            }
        }
        None => println!("No resources found."),
    }

    if online.strict && !scan_warnings.is_empty() {
        std::process::exit(2);
    }
    Ok(())
}
