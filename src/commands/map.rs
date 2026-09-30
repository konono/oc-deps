use crate::cli::{OutputFormat, ShowField};
use crate::graph::tree::{TreeNode, apply_filters, build_namespace_map};
use crate::kube::discovery::build_kind_lookup_cached;
use crate::kube::resource::format_scan_warnings;
use crate::kube::scanner::{resolve_missing_parents, scan_namespace};
use crate::output::json::tree_to_json;
use crate::output::tree::{TreeDisplayOpts, count_nodes, format_container_resources, print_tree};
use anyhow::{Result, bail};
use std::time::Instant;

use super::tree::show_fields_to_tree_opts;

pub(crate) const MAX_NAMESPACE_CONCURRENCY: usize = 5;

pub(crate) const SYSTEM_NAMESPACE_PREFIXES: &[&str] = &["openshift-", "kube-"];
pub(crate) const SYSTEM_NAMESPACE_EXACT: &[&str] = &["default"];

pub(crate) fn is_system_namespace(name: &str) -> bool {
    SYSTEM_NAMESPACE_PREFIXES
        .iter()
        .any(|p| name.starts_with(p))
        || SYSTEM_NAMESPACE_EXACT.contains(&name)
}

pub(crate) fn matches_glob(pattern: &str, name: &str) -> bool {
    if let Some(prefix) = pattern.strip_suffix('*') {
        name.starts_with(prefix)
    } else if let Some(suffix) = pattern.strip_prefix('*') {
        name.ends_with(suffix)
    } else {
        name == pattern
    }
}

pub(crate) fn filter_namespaces(
    namespaces: Vec<(String, std::collections::HashMap<String, String>)>,
    selectors: &[String],
    excludes: &[String],
    exclude_system: bool,
) -> Vec<String> {
    namespaces
        .into_iter()
        .filter(|(name, labels)| {
            if exclude_system && is_system_namespace(name) {
                return false;
            }
            for pattern in excludes {
                if matches_glob(pattern, name) {
                    return false;
                }
            }
            for sel in selectors {
                if let Some((key, value)) = sel.split_once('=')
                    && labels.get(key) != Some(&value.to_string())
                {
                    return false;
                }
            }
            true
        })
        .map(|(name, _)| name)
        .collect()
}

pub(crate) struct NamespaceScanResult {
    namespace: String,
    trees: Vec<TreeNode>,
    total_trees: usize,
    resource_count: usize,
    warnings: Vec<crate::kube::resource::ScanWarning>,
    error: Option<String>,
}

impl NamespaceScanResult {
    fn is_incomplete(&self) -> bool {
        self.error.is_some() || !self.warnings.is_empty()
    }
}

/// Parameters for cluster-wide map scan (extracted from Args for CLI v2).
pub(crate) struct ClusterWideMapParams<'a> {
    pub(crate) namespace_selector: &'a [String],
    pub(crate) exclude_namespace: &'a [String],
    pub(crate) exclude_system_namespaces: bool,
    pub(crate) include_events: bool,
    pub(crate) no_refs: bool,
    pub(crate) show_spec: bool,
    pub(crate) depth: usize,
    pub(crate) output: &'a OutputFormat,
    pub(crate) verbose: bool,
    pub(crate) strict: bool,
    pub(crate) show_annotations: bool,
}

pub(crate) async fn cluster_wide_map(
    client: &::kube::Client,
    kind_map: &crate::kube::discovery::KindMap,
    gk_map: &crate::kube::discovery::GroupKindMap,
    params: &ClusterWideMapParams<'_>,
    tree_opts: &TreeDisplayOpts,
    map_filters: &[crate::graph::tree::MapFilter],
    t0: Instant,
) -> Result<()> {
    use crate::kube::scanner::{
        DEFAULT_API_CONCURRENCY, list_namespaces_with_retry, scan_namespace_with_semaphore,
    };
    use futures::stream::StreamExt;

    let all_ns = list_namespaces_with_retry(client).await?;

    let target_namespaces = filter_namespaces(
        all_ns,
        params.namespace_selector,
        params.exclude_namespace,
        params.exclude_system_namespaces,
    );

    if target_namespaces.is_empty() {
        bail!("No namespaces matched the given selectors/filters");
    }

    let total_ns = target_namespaces.len();
    let is_tty = std::io::IsTerminal::is_terminal(&std::io::stderr());
    eprintln!(
        "📦 Scanning {} namespace{}...",
        total_ns,
        if total_ns == 1 { "" } else { "s" }
    );

    let api_semaphore = std::sync::Arc::new(tokio::sync::Semaphore::new(DEFAULT_API_CONCURRENCY));
    let scanned_count = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));

    let futs = target_namespaces.into_iter().map(|ns| {
        let client = client.clone();
        let kind_map = kind_map.clone();
        let gk_map = gk_map.clone();
        let include_events = params.include_events;
        let refs = !params.no_refs;
        let show_spec = params.show_spec;
        let depth = params.depth;
        let map_filters = map_filters.to_vec();
        let scanned = scanned_count.clone();
        let sem = api_semaphore.clone();

        async move {
            let ns_start = Instant::now();
            let scan_result = scan_namespace_with_semaphore(
                &client,
                &ns,
                &kind_map,
                include_events,
                refs,
                show_spec,
                Some(sem),
                &[],
                None,
                None,
            )
            .await;

            let count = scanned.fetch_add(1, std::sync::atomic::Ordering::Relaxed) + 1;
            let elapsed = ns_start.elapsed().as_secs_f64();

            match scan_result {
                Ok((mut index, mut warnings)) => {
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
                    for uid in &uids_with_missing_parents {
                        let parent_warnings = resolve_missing_parents(
                            &mut index, uid, &client, &ns, &kind_map, &gk_map, show_spec,
                        )
                        .await;
                        warnings.extend(parent_warnings);
                    }

                    let resource_count = index.by_uid.len();
                    let all_trees = build_namespace_map(&index, depth);
                    let total_trees = all_trees.len();
                    let trees = apply_filters(all_trees, &map_filters);

                    if is_tty {
                        eprint!(
                            "\r\x1b[2K   [{}/{}] {} — {} resources, {:.1}s",
                            count, total_ns, ns, resource_count, elapsed
                        );
                    } else {
                        eprintln!(
                            "   [{}/{}] {} — {} resources, {:.1}s",
                            count, total_ns, ns, resource_count, elapsed
                        );
                    }

                    NamespaceScanResult {
                        namespace: ns,
                        trees,
                        total_trees,
                        resource_count,
                        warnings,
                        error: None,
                    }
                }
                Err(e) => {
                    if is_tty {
                        eprint!(
                            "\r\x1b[2K   [{}/{}] {} — ERROR: {}, {:.1}s",
                            count, total_ns, ns, e, elapsed
                        );
                    } else {
                        eprintln!(
                            "   [{}/{}] {} — ERROR: {}, {:.1}s",
                            count, total_ns, ns, e, elapsed
                        );
                    }
                    NamespaceScanResult {
                        namespace: ns,
                        trees: vec![],
                        total_trees: 0,
                        resource_count: 0,
                        warnings: vec![],
                        error: Some(e.to_string()),
                    }
                }
            }
        }
    });

    let mut results: Vec<NamespaceScanResult> = futures::stream::iter(futs)
        .buffer_unordered(MAX_NAMESPACE_CONCURRENCY)
        .collect()
        .await;

    results.sort_by(|a, b| a.namespace.cmp(&b.namespace));

    if is_tty {
        eprintln!();
    }

    let total_resources: usize = results.iter().map(|r| r.resource_count).sum();
    let total_trees: usize = results.iter().map(|r| r.trees.len()).sum();
    let complete_count = results.iter().filter(|r| !r.is_incomplete()).count();
    let incomplete_count = results.iter().filter(|r| r.is_incomplete()).count();

    eprintln!(
        "✅ Cluster-wide scan: {} complete, {} incomplete, {} resources, {} trees in {:.1}s",
        complete_count,
        incomplete_count,
        total_resources,
        total_trees,
        t0.elapsed().as_secs_f64()
    );

    for r in &results {
        if r.error.is_some() {
            eprintln!("⚠ {} — ERROR: {}", r.namespace, r.error.as_deref().unwrap());
        }
    }
    for r in &results {
        if !r.warnings.is_empty() {
            eprintln!("\n⚠ Warnings for namespace '{}':", r.namespace);
            format_scan_warnings(&r.warnings, params.verbose);
        }
    }

    match params.output {
        OutputFormat::Tree => {
            for r in &results {
                if r.trees.is_empty() {
                    continue;
                }
                println!(
                    "\n📦 Namespace: {} ({} trees, {} resources)\n",
                    r.namespace,
                    r.trees.len(),
                    r.resource_count
                );
                for (i, tree) in r.trees.iter().enumerate() {
                    print_tree(tree, "", true, true, tree_opts);
                    if i < r.trees.len() - 1 {
                        println!();
                    }
                }
            }
        }
        OutputFormat::Table => {
            let mut table = comfy_table::Table::new();
            if params.show_spec {
                table.set_header(vec![
                    "Namespace",
                    "Root",
                    "Kind",
                    "Name",
                    "Children",
                    "Containers",
                ]);
                for r in &results {
                    for tree in &r.trees {
                        let total = count_nodes(tree);
                        let containers = if let Some(pt) = &tree.info.pod_template {
                            let mut parts = Vec::new();
                            for c in &pt.containers {
                                parts.push(format_container_resources(c, ""));
                            }
                            for c in &pt.init_containers {
                                parts.push(format_container_resources(c, "init:"));
                            }
                            parts.join("; ")
                        } else {
                            String::new()
                        };
                        table.add_row(vec![
                            r.namespace.as_str(),
                            &format!("{}/{}", tree.info.kind, tree.info.name),
                            tree.info.kind.as_str(),
                            tree.info.name.as_str(),
                            &total.to_string(),
                            &containers,
                        ]);
                    }
                }
            } else {
                table.set_header(vec!["Namespace", "Root", "Kind", "Name", "Children"]);
                for r in &results {
                    for tree in &r.trees {
                        let total = count_nodes(tree);
                        table.add_row(vec![
                            r.namespace.as_str(),
                            &format!("{}/{}", tree.info.kind, tree.info.name),
                            tree.info.kind.as_str(),
                            tree.info.name.as_str(),
                            &total.to_string(),
                        ]);
                    }
                }
            }
            println!("{table}");
        }
        OutputFormat::Json => {
            let output = build_cluster_wide_json(
                &results,
                total_ns,
                params.show_annotations,
                params.show_spec,
                params.namespace_selector,
                params.exclude_namespace,
                params.exclude_system_namespaces,
            );
            println!(
                "{}",
                serde_json::to_string_pretty(&output).unwrap_or_default()
            );
        }
    }

    if params.strict && incomplete_count > 0 {
        std::process::exit(2);
    }
    Ok(())
}

pub(crate) fn build_cluster_wide_json(
    results: &[NamespaceScanResult],
    total_ns: usize,
    include_annotations: bool,
    show_spec: bool,
    namespace_selectors: &[String],
    exclude_namespaces: &[String],
    exclude_system: bool,
) -> serde_json::Value {
    let complete_count = results.iter().filter(|r| !r.is_incomplete()).count();
    let incomplete_count = results.iter().filter(|r| r.is_incomplete()).count();
    let total_resources: usize = results.iter().map(|r| r.resource_count).sum();
    let total_trees: usize = results.iter().map(|r| r.trees.len()).sum();

    let ns_results: Vec<serde_json::Value> = results
        .iter()
        .filter(|r| r.error.is_none())
        .map(|r| {
            let mut ns_obj = serde_json::json!({
                "namespace": r.namespace,
                "totalResources": r.resource_count,
                "totalTrees": r.total_trees,
                "matchedTrees": r.trees.len(),
                "trees": r.trees.iter().map(|t| tree_to_json(t, include_annotations, show_spec)).collect::<Vec<_>>(),
            });
            if !r.warnings.is_empty() {
                ns_obj["warnings"] = serde_json::json!(&r.warnings);
            }
            ns_obj
        })
        .collect();

    let incomplete: Vec<serde_json::Value> = results
        .iter()
        .filter(|r| r.is_incomplete())
        .map(|r| {
            let mut entry = serde_json::json!({
                "namespace": r.namespace,
            });
            if let Some(err) = &r.error {
                entry["error"] = serde_json::json!(err);
            }
            if !r.warnings.is_empty() {
                entry["warnings"] = serde_json::json!(&r.warnings);
            }
            entry
        })
        .collect();

    let mut output = serde_json::json!({
        "scope": "cluster-wide",
        "totalNamespaces": total_ns,
        "completeNamespaceCount": complete_count,
        "incompleteNamespaceCount": incomplete_count,
        "totalResources": total_resources,
        "totalTrees": total_trees,
        "namespaces": ns_results,
    });
    if !namespace_selectors.is_empty() {
        output["namespaceSelectors"] = serde_json::json!(namespace_selectors);
    }
    if !exclude_namespaces.is_empty() {
        output["excludeNamespaces"] = serde_json::json!(exclude_namespaces);
    }
    if exclude_system {
        output["excludeSystemNamespaces"] = serde_json::json!(true);
    }
    if !incomplete.is_empty() {
        output["incompleteNamespaces"] = serde_json::json!(incomplete);
    }
    output
}

pub(crate) fn validate_map_args(
    all_namespaces: bool,
    namespace_selector: &[String],
    exclude_namespace: &[String],
    exclude_system_namespaces: bool,
) -> Result<()> {
    // -A and -n conflict is handled by clap conflicts_with
    if (!namespace_selector.is_empty()
        || !exclude_namespace.is_empty()
        || exclude_system_namespaces)
        && !all_namespaces
    {
        bail!(
            "--namespace-selector, --exclude-namespace, and --exclude-system-namespaces require -A/--all-namespaces"
        );
    }
    for sel in namespace_selector {
        if !sel.contains('=') || sel.starts_with('=') || sel.ends_with('=') {
            bail!(
                "Invalid --namespace-selector '{}': expected key=value format",
                sel
            );
        }
    }
    for pat in exclude_namespace {
        let star_count = pat.chars().filter(|c| *c == '*').count();
        if star_count > 1 {
            bail!(
                "Invalid --exclude-namespace '{}': only prefix* or *suffix patterns are supported",
                pat
            );
        }
        if star_count == 1 && !pat.starts_with('*') && !pat.ends_with('*') {
            bail!(
                "Invalid --exclude-namespace '{}': * must be at the start or end",
                pat
            );
        }
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
pub(crate) async fn handle_map(
    client: &::kube::Client,
    config: &::kube::config::Config,
    online: crate::cli::OnlineOpts,
    all_namespaces: bool,
    namespace_selector: Vec<String>,
    exclude_namespace: Vec<String>,
    exclude_system_namespaces: bool,
    no_refs: bool,
    include_events: bool,
    show: Vec<ShowField>,
    depth: usize,
    root_kind: Vec<String>,
    root_label: Vec<String>,
) -> Result<()> {
    let tree_opts = show_fields_to_tree_opts(&show);
    let show_spec = show.contains(&ShowField::PodResources);
    let show_annotations = show.contains(&ShowField::Annotations);

    let mut map_filters: Vec<crate::graph::tree::MapFilter> = Vec::new();
    for k in &root_kind {
        map_filters.push(crate::graph::tree::MapFilter::Kind(k.clone()));
    }
    for label in &root_label {
        let (key, value) = label.split_once('=').ok_or_else(|| {
            anyhow::anyhow!(
                "Invalid --root-label '{}': expected key=value format",
                label
            )
        })?;
        if key.is_empty() || value.is_empty() {
            bail!("Invalid --root-label '{}': empty key or value", label);
        }
        map_filters.push(crate::graph::tree::MapFilter::Label {
            key: key.to_string(),
            value: value.to_string(),
        });
    }

    let t0 = Instant::now();
    eprintln!("🔍 Discovering API resources...");
    let (kind_map, _, gk_map, _) =
        build_kind_lookup_cached(client, config, online.refresh_discovery).await?;
    eprintln!("   Discovery: {:.1}s", t0.elapsed().as_secs_f64());

    if all_namespaces {
        let params = ClusterWideMapParams {
            namespace_selector: &namespace_selector,
            exclude_namespace: &exclude_namespace,
            exclude_system_namespaces,
            include_events,
            no_refs,
            show_spec,
            depth,
            output: &online.output,
            verbose: online.verbose,
            strict: online.strict,
            show_annotations,
        };
        return cluster_wide_map(
            client,
            &kind_map,
            &gk_map,
            &params,
            &tree_opts,
            &map_filters,
            t0,
        )
        .await;
    }

    let namespace = online
        .namespace
        .unwrap_or_else(|| config.default_namespace.clone());

    let (mut index, mut scan_warnings) = scan_namespace(
        client,
        &namespace,
        &kind_map,
        include_events,
        !no_refs,
        show_spec,
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
            let parent_warnings = resolve_missing_parents(
                &mut index, uid, client, &namespace, &kind_map, &gk_map, show_spec,
            )
            .await;
            scan_warnings.extend(parent_warnings);
        }
        eprintln!(" done");
    }

    format_scan_warnings(&scan_warnings, online.verbose);

    let all_trees = build_namespace_map(&index, depth);
    let total_trees = all_trees.len();
    let trees = apply_filters(all_trees, &map_filters);

    match online.output {
        OutputFormat::Tree => {
            if map_filters.is_empty() {
                println!(
                    "\n📦 Namespace: {} ({} trees, {} resources)\n",
                    namespace,
                    trees.len(),
                    index.by_uid.len()
                );
            } else {
                println!(
                    "\n📦 Namespace: {} ({}/{} trees matched, {} resources scanned)\n",
                    namespace,
                    trees.len(),
                    total_trees,
                    index.by_uid.len()
                );
            }
            for (i, tree) in trees.iter().enumerate() {
                print_tree(tree, "", true, true, &tree_opts);
                if i < trees.len() - 1 {
                    println!();
                }
            }
        }
        OutputFormat::Table => {
            let mut table = comfy_table::Table::new();
            if show_spec {
                table.set_header(vec!["Root", "Kind", "Name", "Children", "Containers"]);
                for tree in &trees {
                    let total = count_nodes(tree);
                    let containers = if let Some(pt) = &tree.info.pod_template {
                        let mut parts = Vec::new();
                        for c in &pt.containers {
                            parts.push(format_container_resources(c, ""));
                        }
                        for c in &pt.init_containers {
                            parts.push(format_container_resources(c, "init:"));
                        }
                        parts.join("; ")
                    } else {
                        String::new()
                    };
                    table.add_row(vec![
                        format!("{}/{}", tree.info.kind, tree.info.name),
                        tree.info.kind.clone(),
                        tree.info.name.clone(),
                        total.to_string(),
                        containers,
                    ]);
                }
            } else {
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
            }
            println!("{table}");
        }
        OutputFormat::Json => {
            let json_warnings: Vec<serde_json::Value> = scan_warnings
                .iter()
                .map(|w| {
                    serde_json::to_value(w).unwrap_or_else(|_| serde_json::json!(w.to_string()))
                })
                .collect();
            let mut output = serde_json::json!({
                "namespace": namespace,
                "scope": "namespace",
                "totalResources": index.by_uid.len(),
                "matchedTrees": trees.len(),
                "trees": trees.iter().map(|t| tree_to_json(t, show_annotations, show_spec)).collect::<Vec<_>>(),
                "warnings": json_warnings,
                "scanWarningCount": scan_warnings.len(),
            });
            if !map_filters.is_empty() {
                output["totalTrees"] = serde_json::json!(total_trees);
            }
            println!(
                "{}",
                serde_json::to_string_pretty(&output).unwrap_or_default()
            );
        }
    }
    if online.strict && !scan_warnings.is_empty() {
        std::process::exit(2);
    }
    Ok(())
}

#[cfg(test)]
mod cluster_wide_map_tests {
    use super::*;
    use crate::cli::{Args, Command};
    use clap::Parser;
    use std::collections::HashMap;

    #[test]
    fn is_system_namespace_matches() {
        assert!(is_system_namespace("openshift-monitoring"));
        assert!(is_system_namespace("openshift-dns"));
        assert!(is_system_namespace("kube-system"));
        assert!(is_system_namespace("kube-public"));
        assert!(is_system_namespace("default"));
        assert!(!is_system_namespace("my-app"));
        assert!(!is_system_namespace("redhat-ods-applications"));
    }

    #[test]
    fn matches_glob_prefix() {
        assert!(matches_glob("openshift-*", "openshift-monitoring"));
        assert!(!matches_glob("openshift-*", "kube-system"));
    }

    #[test]
    fn matches_glob_suffix() {
        assert!(matches_glob("*-system", "kube-system"));
        assert!(!matches_glob("*-system", "kube-public"));
    }

    #[test]
    fn matches_glob_exact() {
        assert!(matches_glob("default", "default"));
        assert!(!matches_glob("default", "my-default"));
    }

    fn make_ns(name: &str, labels: Vec<(&str, &str)>) -> (String, HashMap<String, String>) {
        (
            name.to_string(),
            labels
                .into_iter()
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect(),
        )
    }

    #[test]
    fn filter_namespaces_exclude_system() {
        let ns = vec![
            make_ns("my-app", vec![]),
            make_ns("openshift-monitoring", vec![]),
            make_ns("kube-system", vec![]),
            make_ns("default", vec![]),
        ];
        let result = filter_namespaces(ns, &[], &[], true);
        assert_eq!(result, vec!["my-app"]);
    }

    #[test]
    fn filter_namespaces_selector_and() {
        let ns = vec![
            make_ns("ns-a", vec![("env", "prod"), ("team", "platform")]),
            make_ns("ns-b", vec![("env", "prod")]),
            make_ns("ns-c", vec![("env", "dev"), ("team", "platform")]),
        ];
        let selectors = vec!["env=prod".to_string(), "team=platform".to_string()];
        let result = filter_namespaces(ns, &selectors, &[], false);
        assert_eq!(result, vec!["ns-a"]);
    }

    #[test]
    fn filter_namespaces_exclude_pattern() {
        let ns = vec![
            make_ns("my-app", vec![]),
            make_ns("temp-test-1", vec![]),
            make_ns("temp-test-2", vec![]),
        ];
        let excludes = vec!["temp-*".to_string()];
        let result = filter_namespaces(ns, &[], &excludes, false);
        assert_eq!(result, vec!["my-app"]);
    }

    #[test]
    fn filter_namespaces_all_combined() {
        let ns = vec![
            make_ns("my-app", vec![("env", "prod")]),
            make_ns("openshift-dns", vec![("env", "prod")]),
            make_ns("temp-test", vec![("env", "prod")]),
            make_ns("other", vec![("env", "dev")]),
        ];
        let selectors = vec!["env=prod".to_string()];
        let excludes = vec!["temp-*".to_string()];
        let result = filter_namespaces(ns, &selectors, &excludes, true);
        assert_eq!(result, vec!["my-app"]);
    }

    #[test]
    fn filter_namespaces_no_filters_returns_all() {
        let ns = vec![
            make_ns("a", vec![]),
            make_ns("b", vec![]),
            make_ns("openshift-x", vec![]),
        ];
        let result = filter_namespaces(ns, &[], &[], false);
        assert_eq!(result.len(), 3);
    }

    #[test]
    fn max_namespace_concurrency_is_bounded() {
        let c = MAX_NAMESPACE_CONCURRENCY;
        assert!(c <= 10, "namespace concurrency should be bounded");
        assert!(c >= 1, "namespace concurrency must be at least 1");
    }

    #[test]
    fn cli_map_a_and_n_mutually_exclusive() {
        let result = Args::try_parse_from(["oc-deps", "map", "-A", "-n", "test"]);
        // clap conflicts_with enforces mutual exclusion
        assert!(result.is_err());
    }

    #[test]
    fn cli_namespace_selector_repeatable() {
        let result = Args::try_parse_from([
            "oc-deps",
            "map",
            "-A",
            "--namespace-selector",
            "env=prod",
            "--namespace-selector",
            "team=platform",
        ]);
        assert!(result.is_ok());
        match result.unwrap().command {
            Command::Map {
                namespace_selector, ..
            } => {
                assert_eq!(namespace_selector.len(), 2);
            }
            _ => panic!("Expected Command::Map"),
        }
    }

    #[test]
    fn cli_exclude_namespace_repeatable() {
        let result = Args::try_parse_from([
            "oc-deps",
            "map",
            "-A",
            "--exclude-namespace",
            "temp-*",
            "--exclude-namespace",
            "test-*",
        ]);
        assert!(result.is_ok());
        match result.unwrap().command {
            Command::Map {
                exclude_namespace, ..
            } => {
                assert_eq!(exclude_namespace.len(), 2);
            }
            _ => panic!("Expected Command::Map"),
        }
    }

    #[test]
    fn matches_glob_mid_star_no_match() {
        assert!(!matches_glob("foo*bar", "fooXbar"));
    }

    #[test]
    fn api_concurrency_constant_bounded() {
        use crate::kube::scanner::DEFAULT_API_CONCURRENCY;
        let c = DEFAULT_API_CONCURRENCY;
        assert!(
            (10..=100).contains(&c),
            "API concurrency should be 10-100, got {}",
            c
        );
    }

    fn validate_map(args_str: &[&str]) -> std::result::Result<(), String> {
        let args = Args::try_parse_from(args_str).map_err(|e| e.to_string())?;
        match args.command {
            Command::Map {
                all_namespaces,
                ref namespace_selector,
                ref exclude_namespace,
                exclude_system_namespaces,
                ..
            } => validate_map_args(
                all_namespaces,
                namespace_selector,
                exclude_namespace,
                exclude_system_namespaces,
            )
            .map_err(|e| e.to_string()),
            _ => Ok(()),
        }
    }

    #[test]
    fn validate_map_a_and_n_rejects() {
        // clap conflicts_with handles this
        let result = Args::try_parse_from(["oc-deps", "map", "-A", "-n", "test"]);
        assert!(result.is_err());
    }

    #[test]
    fn validate_selector_without_a_rejects() {
        let err = validate_map(&["oc-deps", "map", "--namespace-selector", "k=v"]).unwrap_err();
        assert!(err.contains("require -A"), "{}", err);
    }

    #[test]
    fn validate_invalid_selector_rejects() {
        let err =
            validate_map(&["oc-deps", "map", "-A", "--namespace-selector", "bad"]).unwrap_err();
        assert!(err.contains("key=value"), "{}", err);
    }

    #[test]
    fn validate_invalid_glob_mid_star_rejects() {
        let err =
            validate_map(&["oc-deps", "map", "-A", "--exclude-namespace", "foo*bar"]).unwrap_err();
        assert!(err.contains("start or end"), "{}", err);
    }

    #[test]
    fn validate_invalid_glob_multi_star_rejects() {
        let err =
            validate_map(&["oc-deps", "map", "-A", "--exclude-namespace", "*foo*"]).unwrap_err();
        assert!(err.contains("prefix*"), "{}", err);
    }

    #[test]
    fn validate_valid_glob_prefix_accepts() {
        assert!(
            validate_map(&["oc-deps", "map", "-A", "--exclude-namespace", "openshift-*"]).is_ok()
        );
    }

    #[test]
    fn validate_valid_glob_suffix_accepts() {
        assert!(validate_map(&["oc-deps", "map", "-A", "--exclude-namespace", "*-system"]).is_ok());
    }

    #[test]
    fn validate_valid_glob_exact_accepts() {
        assert!(validate_map(&["oc-deps", "map", "-A", "--exclude-namespace", "default"]).is_ok());
    }

    #[test]
    fn json_schema_warning_namespace_is_incomplete() {
        use crate::kube::resource::ScanWarning;

        let results = vec![
            NamespaceScanResult {
                namespace: "ns-ok".to_string(),
                trees: vec![],
                total_trees: 0,
                resource_count: 5,
                warnings: vec![],
                error: None,
            },
            NamespaceScanResult {
                namespace: "ns-warn".to_string(),
                trees: vec![],
                total_trees: 2,
                resource_count: 10,
                warnings: vec![ScanWarning::Forbidden {
                    gvr: "apps/v1/deployments".to_string(),
                    status: 403,
                }],
                error: None,
            },
        ];

        let json = build_cluster_wide_json(&results, 2, false, false, &[], &[], false);

        assert_eq!(json["totalNamespaces"], 2);
        assert_eq!(json["completeNamespaceCount"], 1);
        assert_eq!(json["incompleteNamespaceCount"], 1);
        assert_eq!(json["totalResources"], 15);

        let incomplete = json["incompleteNamespaces"].as_array().unwrap();
        assert_eq!(incomplete.len(), 1);
        assert_eq!(incomplete[0]["namespace"], "ns-warn");
        let warnings = incomplete[0]["warnings"].as_array().unwrap();
        assert_eq!(warnings[0]["type"], "Forbidden");
        assert_eq!(warnings[0]["gvr"], "apps/v1/deployments");
        assert_eq!(warnings[0]["status"], 403);

        let namespaces = json["namespaces"].as_array().unwrap();
        assert_eq!(
            namespaces.len(),
            2,
            "warning ns should still be in namespaces (partial data)"
        );
        assert!(
            namespaces
                .iter()
                .any(|n| n["namespace"] == "ns-warn" && n["totalResources"] == 10)
        );
    }

    #[test]
    fn json_schema_error_namespace_not_in_namespaces() {
        let results = vec![
            NamespaceScanResult {
                namespace: "ns-ok".to_string(),
                trees: vec![],
                total_trees: 0,
                resource_count: 5,
                warnings: vec![],
                error: None,
            },
            NamespaceScanResult {
                namespace: "ns-fail".to_string(),
                trees: vec![],
                total_trees: 0,
                resource_count: 0,
                warnings: vec![],
                error: Some("connection refused".to_string()),
            },
        ];

        let json = build_cluster_wide_json(&results, 2, false, false, &[], &[], false);
        assert_eq!(json["completeNamespaceCount"], 1);
        assert_eq!(json["incompleteNamespaceCount"], 1);

        let namespaces = json["namespaces"].as_array().unwrap();
        assert_eq!(
            namespaces.len(),
            1,
            "errored ns should not be in namespaces"
        );

        let incomplete = json["incompleteNamespaces"].as_array().unwrap();
        assert_eq!(incomplete[0]["namespace"], "ns-fail");
        assert_eq!(incomplete[0]["error"], "connection refused");
    }

    #[test]
    fn validate_map_selector_without_a_via_fn() {
        let err = validate_map_args(false, &["k=v".to_string()], &[], false)
            .unwrap_err()
            .to_string();
        assert!(err.contains("require -A"), "{}", err);
    }
}
