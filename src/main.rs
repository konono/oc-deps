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

use crate::analyzers::inspect::{
    inspect_operator_with_options, print_inspection as print_inspection_top,
};
use crate::analyzers::namespace_scope::{discover_operator_namespaces, scan_candidate_namespaces};
use crate::analyzers::olm::{
    WhoManagesInput, compute_operator_dependencies, discover_operators, print_operators,
    print_who_manages, who_manages,
};
use crate::analyzers::selector::{
    build_network_inventory, evaluate_network_postures, find_network_paths,
    get_service_selected_pods,
};
use crate::analyzers::trace::{print_trace, trace_resource};
use crate::cli::{Args, Command, Direction, OutputFormat, Scope, ShowField, TeardownAction};
use crate::graph::evidence::build_evidence_graph;
use crate::graph::tree::{
    TreeNode, apply_filters, build_child_tree, build_full_tree, build_namespace_map,
};
use crate::kube::discovery::{
    APPLY_SET_REUSE_CACHE_ENV, build_kind_lookup_cached, load_config_and_client,
    resolve_kind_with_group,
};
use crate::kube::resource::format_scan_warnings;
use crate::kube::scanner::{find_parents_only, resolve_missing_parents, scan_namespace};
use crate::kube::snapshot::{
    build_snapshot, diff_snapshots, load_snapshot, print_diff_table, print_diff_tree, save_snapshot,
};
use crate::output::json::{print_chain_json, print_json, tree_to_json};
use crate::output::table::{print_chain_table, print_table};
use crate::output::tree::{
    TreeDisplayOpts, count_nodes, format_container_resources, print_chain_tree, print_tree,
};
use crate::teardown::executor::{execute_plan, print_execution_result};
use crate::teardown::explain::explain_resource;
use crate::teardown::journal::{
    self, CleanupResult, ExecutionRecord, JournalStore, ResidualStatus, RunJournal, RunState,
};
use crate::teardown::permit::MutationGate;
use crate::teardown::planner::{
    DecisionPolicy, generate_teardown_plan, load_plan_from_file, print_teardown_plan,
    resolve_operator_targets, save_as_saved_plan, save_plan_to_file,
};
use crate::teardown::progress::{check_plan_status, print_plan_status};

fn apply_set_child_bypasses_cache(no_cache: bool, entry_index: usize) -> bool {
    no_cache && entry_index == 0
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct ApplySetConfig {
    #[allow(dead_code)]
    description: Option<String>,
    #[serde(default)]
    defaults: ApplySetDefaults,
    operators: Vec<ApplySetEntry>,
}

#[derive(Default, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct ApplySetDefaults {
    #[serde(default)]
    approve_delete: ApplySetDeleteApprovals,
    #[serde(default)]
    preserve: Vec<String>,
    #[serde(default)]
    force: bool,
    #[serde(default)]
    non_interactive: bool,
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct ApplySetEntry {
    name: String,
    #[serde(default)]
    approve_delete: ApplySetDeleteApprovals,
    #[serde(default)]
    preserve: Vec<String>,
    #[serde(default)]
    force: Option<bool>,
    #[serde(default)]
    non_interactive: Option<bool>,
}

struct EffectiveApplySetOptions {
    approve_delete: Vec<String>,
    preserve: Vec<String>,
    force: bool,
    non_interactive: bool,
}

impl ApplySetEntry {
    fn effective_options(&self, defaults: &ApplySetDefaults) -> EffectiveApplySetOptions {
        let mut approve_delete = defaults.approve_delete.cli_args();
        approve_delete.extend(self.approve_delete.cli_args());
        let mut seen_approvals = HashSet::new();
        approve_delete.retain(|value| seen_approvals.insert(value.clone()));

        let mut preserve = defaults.preserve.clone();
        preserve.extend(self.preserve.iter().cloned());
        let mut seen_preserves = HashSet::new();
        preserve.retain(|value| seen_preserves.insert(value.clone()));

        EffectiveApplySetOptions {
            approve_delete,
            preserve,
            force: self.force.unwrap_or(defaults.force),
            non_interactive: self.non_interactive.unwrap_or(defaults.non_interactive),
        }
    }
}

#[derive(serde::Deserialize)]
#[serde(untagged)]
enum ApplySetDeleteApprovals {
    Structured(StructuredDeleteApprovals),
    Legacy(Vec<String>),
}

impl Default for ApplySetDeleteApprovals {
    fn default() -> Self {
        Self::Structured(StructuredDeleteApprovals::default())
    }
}

impl ApplySetDeleteApprovals {
    fn cli_args(&self) -> Vec<String> {
        match self {
            Self::Structured(approvals) => approvals
                .scopes
                .iter()
                .map(|scope| scope.cli_arg().to_string())
                .chain(approvals.resources.iter().cloned())
                .collect(),
            Self::Legacy(approvals) => approvals.clone(),
        }
    }
}

#[derive(Default, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct StructuredDeleteApprovals {
    #[serde(default)]
    scopes: Vec<ApplySetApprovalScope>,
    #[serde(default)]
    resources: Vec<String>,
}

#[derive(serde::Deserialize)]
#[serde(rename_all = "kebab-case")]
enum ApplySetApprovalScope {
    Root,
    Independent,
    LabelOnly,
    OperatorGroup,
}

impl ApplySetApprovalScope {
    fn cli_arg(&self) -> &'static str {
        match self {
            Self::Root => "root",
            Self::Independent => "independent",
            Self::LabelOnly => "label-only",
            Self::OperatorGroup => "operator-group",
        }
    }
}

fn find_descendant_pods(
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

fn display_tree(tree: &TreeNode, output: &OutputFormat, namespace: &str, opts: &TreeDisplayOpts) {
    match output {
        OutputFormat::Tree => {
            println!("\n📦 Namespace: {}\n", namespace);
            print_tree(tree, "", true, true, opts);
        }
        OutputFormat::Table => print_table(tree, opts.show_spec),
        OutputFormat::Json => print_json(tree, namespace, opts.show_annotations, opts.show_spec),
    }
}

const MAX_NAMESPACE_CONCURRENCY: usize = 5;

const SYSTEM_NAMESPACE_PREFIXES: &[&str] = &["openshift-", "kube-"];
const SYSTEM_NAMESPACE_EXACT: &[&str] = &["default"];

fn is_system_namespace(name: &str) -> bool {
    SYSTEM_NAMESPACE_PREFIXES
        .iter()
        .any(|p| name.starts_with(p))
        || SYSTEM_NAMESPACE_EXACT.contains(&name)
}

fn matches_glob(pattern: &str, name: &str) -> bool {
    if let Some(prefix) = pattern.strip_suffix('*') {
        name.starts_with(prefix)
    } else if let Some(suffix) = pattern.strip_prefix('*') {
        name.ends_with(suffix)
    } else {
        name == pattern
    }
}

fn filter_namespaces(
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

struct NamespaceScanResult {
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
struct ClusterWideMapParams<'a> {
    namespace_selector: &'a [String],
    exclude_namespace: &'a [String],
    exclude_system_namespaces: bool,
    include_events: bool,
    no_refs: bool,
    show_spec: bool,
    depth: usize,
    output: &'a OutputFormat,
    verbose: bool,
    strict: bool,
    show_annotations: bool,
}

async fn cluster_wide_map(
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

fn build_cluster_wide_json(
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

fn validate_map_args(
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

/// Helper to convert ShowField vec to TreeDisplayOpts
fn show_fields_to_tree_opts(show: &[ShowField]) -> TreeDisplayOpts {
    TreeDisplayOpts {
        show_labels: show.contains(&ShowField::Labels),
        show_annotations: show.contains(&ShowField::Annotations),
        show_spec: show.contains(&ShowField::PodResources),
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();

    // ── Offline subcommands (dispatch before client init) ──
    if let Command::Diff {
        ref before,
        ref after,
        ref format,
    } = args.command
    {
        let before_snap = load_snapshot(before)?;
        let after_snap = load_snapshot(after)?;
        let result = diff_snapshots(&before_snap, &after_snap)?;
        match format {
            OutputFormat::Tree => print_diff_tree(&result),
            OutputFormat::Table => print_diff_table(&result),
            OutputFormat::Json => {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&result).unwrap_or_default()
                );
            }
        }
        return Ok(());
    }

    // ── Early validation for Snapshot ──
    if let Command::Snapshot {
        all_namespaces,
        ref namespace,
        ref namespace_selector,
        ref exclude_namespace,
        exclude_system_namespaces,
        ..
    } = args.command
    {
        if all_namespaces && namespace.is_some() {
            bail!("-A/--all-namespaces and -n/--namespace are mutually exclusive");
        }
        if (!namespace_selector.is_empty()
            || !exclude_namespace.is_empty()
            || exclude_system_namespaces)
            && !all_namespaces
        {
            bail!(
                "--namespace-selector, --exclude-namespace, and --exclude-system-namespaces require -A"
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
    }

    // ── Early validation for Map ──
    if let Command::Map {
        all_namespaces,
        ref namespace_selector,
        ref exclude_namespace,
        exclude_system_namespaces,
        ref root_label,
        ..
    } = args.command
    {
        validate_map_args(
            all_namespaces,
            namespace_selector,
            exclude_namespace,
            exclude_system_namespaces,
        )?;
        for label in root_label {
            let (key, value) = label.split_once('=').ok_or_else(|| {
                anyhow::anyhow!(
                    "Invalid --root-label '{}': expected key=value format",
                    label
                )
            })?;
            if key.is_empty() || value.is_empty() {
                bail!("Invalid --root-label '{}': empty key or value", label);
            }
        }
    }

    // ── Resource format validation (before client init) ──
    let resource_arg = match &args.command {
        Command::Tree { resource, .. }
        | Command::Network { resource, .. }
        | Command::Trace { resource, .. }
        | Command::WhoManages { resource, .. } => Some(resource.as_str()),
        _ => None,
    };
    if let Some(res) = resource_arg
        && !res.contains('/')
    {
        bail!(
            "Resource must be in kind/name format (e.g. deployment/nginx), got '{}'",
            res
        );
    }

    let (config, client) = load_config_and_client().await?;

    // ── Subcommand dispatch ──
    match args.command {
        Command::Snapshot {
            namespace,
            output_file,
            include_events,
            no_cache,
            all_namespaces,
            namespace_selector,
            exclude_namespace,
            exclude_system_namespaces,
            strict,
        } => {
            let snapshot_strict = strict;
            let t0 = Instant::now();
            eprintln!("🔍 Discovering API resources...");
            let (kind_map, _, _gk_map, _) =
                build_kind_lookup_cached(&client, &config, no_cache).await?;
            eprintln!("   Discovery: {:.1}s", t0.elapsed().as_secs_f64());

            if all_namespaces {
                // ── Cluster-wide snapshot ──
                use crate::kube::resource::{
                    ClusterSnapshot, IncompleteNamespace, SNAPSHOT_SCHEMA_VERSION, SnapshotScope,
                };
                use crate::kube::scanner::list_namespaces_with_retry;

                let all_ns = list_namespaces_with_retry(&client).await?;
                let target_namespaces = filter_namespaces(
                    all_ns,
                    &namespace_selector,
                    &exclude_namespace,
                    exclude_system_namespaces,
                );

                if target_namespaces.is_empty() {
                    bail!("No namespaces matched the given selectors/filters");
                }

                let requested_namespaces = target_namespaces.clone();
                let total_ns = target_namespaces.len();
                eprintln!(
                    "📦 Scanning {} namespace{}...",
                    total_ns,
                    if total_ns == 1 { "" } else { "s" }
                );

                let scanned_count = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
                let cancel_token = tokio_util::sync::CancellationToken::new();
                let cancel_for_handler = cancel_token.clone();
                let tmp_path = format!("{}.{}.tmp", output_file, std::process::id());
                let tmp_path_cleanup = tmp_path.clone();

                // Ctrl-C handler
                tokio::spawn(async move {
                    if tokio::signal::ctrl_c().await.is_ok() {
                        eprintln!("\n⚠ Interrupted — cleaning up...");
                        cancel_for_handler.cancel();
                    }
                });

                let mut all_resources =
                    std::collections::HashMap::<String, crate::kube::resource::ResourceEntry>::new(
                    );
                let mut all_warnings = Vec::new();
                let mut complete_namespaces = Vec::new();
                let mut incomplete_namespaces = Vec::new();
                let mut scanned_ns_list = Vec::new();

                let api_semaphore = std::sync::Arc::new(tokio::sync::Semaphore::new(
                    crate::kube::scanner::DEFAULT_API_CONCURRENCY,
                ));

                let futs = target_namespaces.iter().map(|ns| {
                    let client = client.clone();
                    let config_clone = config.clone();
                    let kind_map = kind_map.clone();
                    let scanned = scanned_count.clone();
                    let ns = ns.clone();
                    let sem = api_semaphore.clone();

                    async move {
                        let ns_start = Instant::now();
                        let result = crate::kube::snapshot::build_snapshot_with_semaphore(
                            &client,
                            &config_clone,
                            &ns,
                            &kind_map,
                            include_events,
                            sem,
                        )
                        .await;
                        let count = scanned.fetch_add(1, std::sync::atomic::Ordering::Relaxed) + 1;
                        let elapsed = ns_start.elapsed().as_secs_f64();
                        (ns, result, count, elapsed)
                    }
                });

                use futures::stream::StreamExt as _;
                let mut stream = futures::stream::iter(futs)
                    .buffer_unordered(MAX_NAMESPACE_CONCURRENCY)
                    .boxed();

                while let Some((ns, result, count, elapsed)) = tokio::select! {
                    item = stream.next() => item,
                    _ = cancel_token.cancelled() => None,
                } {
                    match result {
                        Ok(ns_snapshot) => {
                            let resource_count = ns_snapshot.resources.len();
                            let is_tty = std::io::IsTerminal::is_terminal(&std::io::stderr());
                            if is_tty {
                                eprint!(
                                    "\r\x1b[2K  [{}/{}] {} — {} resources, {:.1}s",
                                    count, total_ns, ns, resource_count, elapsed
                                );
                            } else {
                                eprintln!(
                                    "  [{}/{}] {} — {} resources, {:.1}s",
                                    count, total_ns, ns, resource_count, elapsed
                                );
                            }

                            if ns_snapshot.scan_warnings.is_empty() {
                                complete_namespaces.push(ns.clone());
                            } else {
                                incomplete_namespaces.push(IncompleteNamespace {
                                    namespace: ns.clone(),
                                    warnings: ns_snapshot.scan_warnings.clone(),
                                    error: None,
                                });
                                all_warnings.extend(ns_snapshot.scan_warnings);
                            }

                            all_resources.extend(ns_snapshot.resources);
                        }
                        Err(e) => {
                            let is_tty = std::io::IsTerminal::is_terminal(&std::io::stderr());
                            if is_tty {
                                eprint!(
                                    "\r\x1b[2K  [{}/{}] {} — ERROR: {}",
                                    count, total_ns, ns, e
                                );
                            } else {
                                eprintln!("  [{}/{}] {} — ERROR: {}", count, total_ns, ns, e);
                            }
                            incomplete_namespaces.push(IncompleteNamespace {
                                namespace: ns.clone(),
                                warnings: vec![],
                                error: Some(e.to_string()),
                            });
                        }
                    }
                    scanned_ns_list.push(ns);
                }

                if cancel_token.is_cancelled() {
                    let _ = std::fs::remove_file(&tmp_path_cleanup);
                    eprintln!("\n⚠ Snapshot cancelled.");
                    std::process::exit(130);
                }

                let is_tty = std::io::IsTerminal::is_terminal(&std::io::stderr());
                if is_tty {
                    eprintln!(
                        "\r\x1b[2K✅ Scanned {} namespaces in {:.1}s",
                        total_ns,
                        t0.elapsed().as_secs_f64()
                    );
                } else {
                    eprintln!(
                        "✅ Scanned {} namespaces in {:.1}s",
                        total_ns,
                        t0.elapsed().as_secs_f64()
                    );
                }

                let scope_mode = if namespace_selector.is_empty()
                    && exclude_namespace.is_empty()
                    && !exclude_system_namespaces
                {
                    "all-namespaces"
                } else {
                    "filtered"
                };

                let mut requested_ns = requested_namespaces.clone();
                requested_ns.sort();
                scanned_ns_list.sort();
                complete_namespaces.sort();
                incomplete_namespaces.sort_by(|a, b| a.namespace.cmp(&b.namespace));

                let snapshot = ClusterSnapshot {
                    schema_version: Some(SNAPSHOT_SCHEMA_VERSION),
                    resources: all_resources,
                    scan_warnings: all_warnings.clone(),
                    cluster_url: config.cluster_url.to_string(),
                    taken_at: chrono::Utc::now().to_rfc3339(),
                    namespaces: scanned_ns_list,
                    scope: Some(SnapshotScope {
                        mode: scope_mode.to_string(),
                        namespace_selectors: namespace_selector,
                        exclude_namespaces: exclude_namespace,
                        exclude_system_namespaces,
                        requested_namespaces: requested_ns,
                        complete_namespaces,
                        incomplete_namespaces,
                    }),
                };

                let resource_count = snapshot.resources.len();
                format_scan_warnings(&snapshot.scan_warnings, false);
                save_snapshot(&snapshot, &output_file)?;

                let scope = snapshot.scope.as_ref().unwrap();
                eprintln!(
                    "✅ Snapshot saved to {} ({} resources, {} requested, {} complete, {} incomplete)",
                    output_file,
                    resource_count,
                    scope.requested_namespaces.len(),
                    scope.complete_namespaces.len(),
                    scope.incomplete_namespaces.len(),
                );
                if snapshot_strict
                    && (!scope.incomplete_namespaces.is_empty()
                        || !snapshot.scan_warnings.is_empty())
                {
                    std::process::exit(2);
                }
            } else {
                // ── Single-namespace snapshot ──
                let namespace = namespace.unwrap_or_else(|| config.default_namespace.clone());
                let snapshot =
                    build_snapshot(&client, &config, &namespace, &kind_map, include_events).await?;

                let resource_count = snapshot.resources.len();
                format_scan_warnings(&snapshot.scan_warnings, false);
                save_snapshot(&snapshot, &output_file)?;

                eprintln!(
                    "✅ Snapshot saved to {} ({} resources, {} scan warnings)",
                    output_file,
                    resource_count,
                    snapshot.scan_warnings.len()
                );
                if snapshot_strict && !snapshot.scan_warnings.is_empty() {
                    std::process::exit(2);
                }
            }
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

            format_scan_warnings(&snapshot.scan_warnings, false);

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
                    save_plan_path,
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

                    // Save as runtime plan (debug)
                    match save_plan_to_file(&plan) {
                        Ok(path) => eprintln!("📄 Plan saved to {}", path),
                        Err(e) => eprintln!("⚠ Could not save plan: {}", e),
                    }

                    // Save as SavedTeardownPlan (for --plan replay)
                    if !target_operators.is_empty() {
                        let pkg_name = match &target_operators[0].package_name {
                            Some(n) => n.clone(),
                            None => {
                                if save_plan_path.is_some() {
                                    bail!(
                                        "Cannot save plan: operator has no package_name (Subscription required)"
                                    );
                                }
                                eprintln!("⚠ Cannot save replay plan: no package_name");
                                String::new()
                            }
                        };
                        if !pkg_name.is_empty() {
                            let target = crate::teardown::plan::SavedOperatorTarget {
                                package_name: pkg_name.to_string(),
                                install_namespace: target_operators[0].install_namespace.clone(),
                                csv_name_pattern: target_operators[0].csv.name.clone(),
                            };
                            match save_as_saved_plan(&plan, &target, save_plan_path.as_deref()) {
                                Ok(path) => eprintln!("📄 Saved plan for replay: {}", path),
                                Err(e) => eprintln!("⚠ Could not save replay plan: {}", e),
                            }
                        }
                    }

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
                    plan: plan_file,
                    no_cache,
                    dry_run,
                    prune_apis,
                    force,
                    approve_delete,
                    preserve,
                    approve_finalizer_recovery,
                    non_interactive,
                    script,
                    tui: use_tui,
                    save_plan_path,
                } => {
                    // Validate: --plan and positional operators are mutually exclusive
                    if plan_file.is_some() && !operator_queries.is_empty() {
                        bail!(
                            "--plan and positional operator arguments cannot be combined. \
                                 Use --plan alone to replay a saved plan."
                        );
                    }

                    let t0 = Instant::now();
                    eprintln!("🔍 Discovering API resources...");
                    let (kind_map, gvr_map, gk_map, gvk_map) =
                        build_kind_lookup_cached(&client, &config, no_cache).await?;
                    eprintln!("   Discovery: {:.1}s", t0.elapsed().as_secs_f64());

                    eprint!("🔍 Discovering operators...");
                    let all_operators = discover_operators(&client, &kind_map).await?;
                    eprintln!(" found {} operators", all_operators.len());

                    // Resolve targets: from --plan or from positional args
                    let (target_indices, _saved_plan) = if let Some(ref pf) = plan_file {
                        let saved = crate::teardown::planner::load_saved_plan(pf)?;
                        eprintln!("📄 Loaded saved plan from {}", pf);
                        // Resolve via package_name + install_namespace (both required)
                        let target_query = saved.target.package_name.clone();
                        let indices = resolve_operator_targets(&[target_query], &all_operators)?;
                        // Filter by install_namespace
                        let ns_filtered: Vec<usize> = indices
                            .iter()
                            .copied()
                            .filter(|&i| {
                                all_operators[i].install_namespace == saved.target.install_namespace
                            })
                            .collect();
                        if ns_filtered.is_empty() {
                            bail!(
                                "Saved plan target {}/{} not found in current cluster",
                                saved.target.package_name,
                                saved.target.install_namespace
                            );
                        }
                        if ns_filtered.len() > 1 {
                            bail!(
                                "Saved plan target {}/{} matches {} operators — ambiguous",
                                saved.target.package_name,
                                saved.target.install_namespace,
                                ns_filtered.len()
                            );
                        }
                        (ns_filtered, Some(saved))
                    } else {
                        let indices = resolve_operator_targets(&operator_queries, &all_operators)?;
                        (indices, None)
                    };

                    let target_operators: Vec<&_> =
                        target_indices.iter().map(|&i| &all_operators[i]).collect();

                    let policy = DecisionPolicy::from_args(&approve_delete, &preserve);
                    let mut plan = generate_teardown_plan(
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

                    // Apply saved plan decisions via DecisionPolicy
                    if let Some(ref saved) = _saved_plan {
                        use crate::teardown::planner::validate_saved_decisions;
                        match validate_saved_decisions(&plan, saved) {
                            Ok((extra_approvals, extra_preserves)) => {
                                if !extra_approvals.is_empty() || !extra_preserves.is_empty() {
                                    let mut all_approvals = approve_delete.clone();
                                    all_approvals.extend(extra_approvals);
                                    let mut all_preserves = preserve.clone();
                                    all_preserves.extend(extra_preserves);
                                    let saved_policy =
                                        DecisionPolicy::from_args(&all_approvals, &all_preserves);
                                    plan = generate_teardown_plan(
                                        &client,
                                        &target_operators,
                                        &all_operators,
                                        &kind_map,
                                        &gvr_map,
                                        &gk_map,
                                        &gvk_map,
                                        prune_apis,
                                        &saved_policy,
                                    )
                                    .await?;
                                    eprintln!(
                                        "📄 Saved plan replayed with {} approval(s)",
                                        all_approvals.len()
                                    );
                                }
                            }
                            Err(errors) => {
                                for err in &errors {
                                    eprintln!("  ⚠ Saved plan drift: {}", err);
                                }
                                bail!(
                                    "Saved plan has {} validation error(s) — cannot replay",
                                    errors.len()
                                );
                            }
                        }
                    }

                    // Non-interactive: bail if unresolved REVIEW items remain
                    if non_interactive {
                        let review_count = plan
                            .phases
                            .iter()
                            .flat_map(|p| &p.actions)
                            .filter(|a| {
                                matches!(a, crate::teardown::planner::Action::Review { .. })
                            })
                            .count();
                        if review_count > 0 {
                            bail!(
                                "{} unresolved REVIEW item(s) — cannot proceed in non-interactive mode",
                                review_count
                            );
                        }
                    }

                    match save_plan_to_file(&plan) {
                        Ok(path) => eprintln!("📄 Plan saved to {}", path),
                        Err(e) => eprintln!("⚠ Could not save plan: {}", e),
                    }

                    // TUI mode: ratatui interactive Plan Review → Execution → Residual Cleanup
                    if use_tui && !dry_run {
                        let journal_store = {
                            let store = create_run_journal(
                                &client,
                                &plan,
                                &target_operators,
                                &gk_map,
                                approve_finalizer_recovery,
                            )
                            .await?;
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
                            &client,
                            &mut plan,
                            &target_operators,
                            &kind_map,
                            &gk_map,
                            &gvk_map,
                            &gvr_map,
                            &journal_store,
                            &gate,
                            force,
                        )
                        .await?;
                        return Ok(());
                    }

                    // Headless script mode: drive AppState with JSON commands
                    if let Some(script_path) = &script {
                        use crate::teardown::app::{
                            AppCommand, AppScreen, AppState, AppStateSnapshot, apply_command,
                        };
                        let mut app = AppState::new(approve_finalizer_recovery);
                        let mut plan = plan.clone(); // mutable copy for script overrides

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
                            let cmd: AppCommand =
                                serde_json::from_str(line).with_context(|| {
                                    format!("Invalid command on line {}: {}", i + 1, line)
                                })?;

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
                                                        && resource.namespace
                                                            == ovr.resource.namespace
                                                } else {
                                                    false
                                                }
                                            })
                                        });
                                        if !found_review {
                                            bail!(
                                                "Override for {}/{}/{} does not match any REVIEW action in the plan. \
                                                     Only REVIEW items can be overridden.",
                                                ovr.resource.group,
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
                                                } = action
                                                    && resource.group == ovr.resource.group
                                                    && resource.version == ovr.resource.version
                                                    && resource.kind == ovr.resource.kind
                                                    && resource.name == ovr.resource.name
                                                    && resource.namespace == ovr.resource.namespace
                                                {
                                                    // P0: Three-way UID verification:
                                                    // 1. Override UID must be provided for DELETE
                                                    // 2. Override UID must match plan UID
                                                    // 3. Live UID must match plan UID
                                                    let ovr_uid =
                                                        ovr.resource.uid.as_deref().unwrap_or("");
                                                    let plan_uid =
                                                        resource.uid.as_deref().unwrap_or("");

                                                    match ovr.new_action {
                                                        DraftAction::Delete => {
                                                            if ovr_uid.is_empty() {
                                                                bail!(
                                                                    "Cannot approve DELETE for {}/{} without UID in approval",
                                                                    resource.kind,
                                                                    resource.name
                                                                );
                                                            }
                                                            if plan_uid.is_empty() {
                                                                bail!(
                                                                    "Cannot approve DELETE for {}/{}: plan resource has no UID",
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
                                                                        &client, resource, &kind_map, &gk_map,
                                                                    ).ok_or_else(|| anyhow::anyhow!(
                                                                        "Cannot resolve API for {}/{} — refusing to skip approved DELETE override",
                                                                        resource.kind, resource.name
                                                                    ))?;
                                                            match api.get(&resource.name).await {
                                                                Ok(obj) => {
                                                                    let live_uid = obj
                                                                        .metadata
                                                                        .uid
                                                                        .as_deref()
                                                                        .unwrap_or("");
                                                                    if live_uid.is_empty() {
                                                                        bail!(
                                                                            "Cannot apply override for {}/{}: live resource has no UID",
                                                                            resource.kind,
                                                                            resource.name
                                                                        );
                                                                    }
                                                                    if !plan_uid.is_empty()
                                                                        && live_uid != plan_uid
                                                                    {
                                                                        bail!(
                                                                            "Cannot apply override for {}/{}: UID changed from {} to {} since plan was created.",
                                                                            resource.kind,
                                                                            resource.name,
                                                                            plan_uid,
                                                                            live_uid
                                                                        );
                                                                    }
                                                                    // Basis drift: verify provenance hasn't degraded
                                                                    // Use journal's operator snapshot (has full controller deployment UIDs)
                                                                    {
                                                                        let ctx = journal::build_audit_context(&plan, &target_operators, &gk_map);
                                                                        let action_metadata =
                                                                            metadata.clone();
                                                                        let snap = if let Some(
                                                                            ref jstore,
                                                                        ) =
                                                                            script_journal
                                                                        {
                                                                            let j =
                                                                                jstore.read().await;
                                                                            j.operator.clone()
                                                                        } else {
                                                                            build_operator_identity_snapshot(&client, &target_operators).await
                                                                                        .context("Cannot build identity snapshot for basis drift check")?
                                                                        };
                                                                        if let Err(reason) =
                                                                            revalidate_review_basis(
                                                                                &client,
                                                                                &obj,
                                                                                resource,
                                                                                &action_metadata,
                                                                                &ctx,
                                                                                &snap,
                                                                            )
                                                                            .await
                                                                        {
                                                                            bail!(
                                                                                "BLOCKED: {}/{} — basis drift: {}. Re-run 'teardown plan'.",
                                                                                resource.kind,
                                                                                resource.name,
                                                                                reason
                                                                            );
                                                                        }
                                                                    }
                                                                    let mut bound =
                                                                        resource.clone();
                                                                    bound.uid =
                                                                        Some(live_uid.to_string());
                                                                    *action = Action::Delete {
                                                                        resource: bound,
                                                                        reason: format!(
                                                                            "{} (approved via script)",
                                                                            reason
                                                                        ),
                                                                    };
                                                                }
                                                                Err(::kube::Error::Api(
                                                                    ref err,
                                                                )) if err.code == 404 => {
                                                                    eprintln!(
                                                                        "  ⚠ {}/{} no longer present — override skipped",
                                                                        resource.kind,
                                                                        resource.name
                                                                    );
                                                                }
                                                                Err(e) => bail!(
                                                                    "Cannot verify {}/{} for script override: {}",
                                                                    resource.kind,
                                                                    resource.name,
                                                                    e
                                                                ),
                                                            }
                                                        }
                                                        DraftAction::Keep => {
                                                            *action = Action::Keep {
                                                                resource: resource.clone(),
                                                                reason: format!(
                                                                    "{} (kept via script)",
                                                                    reason
                                                                ),
                                                            };
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
                                        &client,
                                        &plan,
                                        &target_operators,
                                        &gk_map,
                                        app.finalizer_recovery_approved,
                                    )
                                    .await?;
                                    Some(std::sync::Arc::new(store))
                                } else {
                                    None
                                };
                                let journal_store = &script_journal;

                                // Cluster identity re-check (same as normal apply path)
                                if let Some(store) = &journal_store {
                                    let current_id =
                                        journal::fetch_cluster_identity(&client).await?;
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
                                    &client,
                                    &plan,
                                    &kind_map,
                                    &gk_map,
                                    &gvk_map,
                                    &gvr_map,
                                    dry_run,
                                    force,
                                    journal_store.as_deref(),
                                    Some(gate),
                                    0,
                                    true, // skip_confirm in script mode
                                )
                                .await;

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
                                            store
                                                .update(|j| {
                                                    j.state = final_state.clone();
                                                })
                                                .await
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
                                            let _ = store
                                                .update(|j| {
                                                    j.state = RunState::Failed;
                                                })
                                                .await;
                                        }
                                        events.push(serde_json::json!({
                                            "execution_error": format!("{:#}", e)
                                        }));
                                    }
                                }
                            }

                            // Transition to ResidualCleanup: ApplyCompleted + generation Absent + complete audit
                            if app.screen == AppScreen::Executing
                                && let (Some(store), true) = (&script_journal, result.is_ok())
                            {
                                let j = store.read().await;
                                if j.state == RunState::ApplyCompleted {
                                    let gen_check =
                                        crate::teardown::audit::check_operator_generation(
                                            &client,
                                            &j.operator,
                                            &j.audit_context.csv_baseline,
                                        )
                                        .await;
                                    if matches!(
                                        gen_check,
                                        crate::teardown::audit::OperatorGenerationState::Absent
                                    ) {
                                        match crate::teardown::audit::run_residual_audit(
                                            &client, &j,
                                        )
                                        .await
                                        {
                                            Ok(audit_result) => {
                                                let status = crate::teardown::audit::residual_status_from_audit(&audit_result);
                                                if matches!(
                                                    status,
                                                    journal::ResidualStatus::AuditIncomplete
                                                ) {
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
                                                                // Compute auto candidates BEFORE audit_result is moved
                                                                let mut auto_candidates = crate::teardown::executor::auto_cleanup_candidates(
                                                                    &audit_result,
                                                                    &j.execution.deleted,
                                                                );

                                                                // Apply saved residual decisions via validated function
                                                                if let Some(ref saved) = _saved_plan
                                                                    && !saved.residual_decisions.is_empty()
                                                                {
                                                                        match crate::teardown::executor::validate_saved_residual_decisions(
                                                                            &saved.residual_decisions,
                                                                            &audit_result,
                                                                        ) {
                                                                            Ok(extra) => {
                                                                                auto_candidates.extend(extra);
                                                                            }
                                                                            Err(errors) => {
                                                                                for e in &errors {
                                                                                    eprintln!("  ⚠ Residual decision error: {}", e);
                                                                                }
                                                                                // Block residual mutation
                                                                                auto_candidates.clear();
                                                                                events.push(serde_json::json!({"auto_cleanup_error": "residual decision validation failed", "blocked": true}));
                                                                            }
                                                                        }
                                                                    }
                                                                let residual_validation_failed = auto_candidates.is_empty()
                                                                    && events.iter().any(|e| e.get("auto_cleanup_error").is_some());
                                                                drop(j);

                                                                store.update(|j| {
                                                                    j.residual_status = status;
                                                                    j.audit_revision += 1;
                                                                    j.last_residual_audit = Some(audit_result);
                                                                }).await
                                                                .context("Failed to persist residual audit for screen transition")?;

                                                                // Auto cleanup planned DELETE/EXPECT still present
                                                                let mut cleanup_ok = !residual_validation_failed;
                                                                if !auto_candidates.is_empty() {
                                                                    events.push(serde_json::json!({
                                                                        "auto_selected_residuals": auto_candidates.len(),
                                                                    }));
                                                                    let g = match &script_gate {
                                                                        Some(g) => g.as_ref(),
                                                                        None => {
                                                                            events.push(serde_json::json!({"auto_cleanup_error": "no mutation gate"}));
                                                                            continue;
                                                                        }
                                                                    };
                                                                    match crate::teardown::executor::execute_residual_cleanup(
                                                                        &client, &auto_candidates, store.as_ref(), g, &kind_map, &gk_map,
                                                                    ).await {
                                                                        Ok(cr) => {
                                                                            let complete = cr.failed.is_empty() && cr.skipped.is_empty();
                                                                            events.push(serde_json::json!({
                                                                                "auto_cleanup": {
                                                                                    "deleted": cr.deleted.len(),
                                                                                    "skipped": cr.skipped.len(),
                                                                                    "failed": cr.failed.len(),
                                                                                    "complete": complete,
                                                                                }
                                                                            }));
                                                                            if !complete { cleanup_ok = false; }
                                                                        }
                                                                        Err(e) => {
                                                                            events.push(serde_json::json!({"auto_cleanup_error": format!("{:#}", e)}));
                                                                            cleanup_ok = false;
                                                                        }
                                                                    }
                                                                }

                                                                if cleanup_ok {
                                                                    app.screen = AppScreen::ResidualCleanup;
                                                                    events.push(serde_json::json!({"screen_transition": "ResidualCleanup"}));
                                                                } else {
                                                                    events.push(serde_json::json!({"screen_transition_blocked": "auto cleanup incomplete or failed"}));
                                                                }
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

                            // Handle DeleteSelected: execute residual cleanup via core function
                            if matches!(cmd, AppCommand::DeleteSelected)
                                && result.is_ok()
                                && app.screen == AppScreen::ResidualCleanup
                                && !app.selected_residuals.is_empty()
                                && let (Some(store), Some(g)) = (&script_journal, &script_gate)
                            {
                                match crate::teardown::executor::execute_residual_cleanup(
                                    &client,
                                    &app.selected_residuals,
                                    store.as_ref(),
                                    g.as_ref(),
                                    &kind_map,
                                    &gk_map,
                                )
                                .await
                                {
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

                            // Handle Finish: durable persist with guards
                            if matches!(cmd, AppCommand::Finish)
                                && result.is_ok()
                                && app.screen == AppScreen::Finished
                                && let Some(store) = &script_journal
                            {
                                let j = store.read().await;
                                if let Err(reason) = can_finish_run(&j) {
                                    events.push(serde_json::json!({
                                        "finish_error": reason,
                                    }));
                                } else {
                                    // Final generation check before Finished persist
                                    let fin_gen =
                                        crate::teardown::audit::check_operator_generation(
                                            &client,
                                            &j.operator,
                                            &j.audit_context.csv_baseline,
                                        )
                                        .await;
                                    if matches!(
                                        fin_gen,
                                        crate::teardown::audit::OperatorGenerationState::Absent
                                    ) {
                                        store
                                            .update(|j| {
                                                j.state = RunState::Finished;
                                            })
                                            .await
                                            .context("Failed to persist Finished state")?;
                                        events.push(serde_json::json!({
                                            "finish": "persisted",
                                        }));
                                    } else {
                                        events.push(serde_json::json!({
                                            "finish_error": "generation not Absent at Finish time",
                                        }));
                                    }
                                }
                            }
                        }

                        // Output full trace as JSON
                        let has_errors = events.iter().any(|e| {
                            e.get("execution_error").is_some()
                                || e.get("residual_cleanup_error").is_some()
                                || e.get("finish_error").is_some()
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

                    // CLI uses the approved plan directly. REVIEW actions stay
                    // preserved; users can approve exact resources with
                    // --approve-delete or choose them in the TUI.
                    let is_tty = std::io::IsTerminal::is_terminal(&std::io::stdin());
                    let effective_finalizer_recovery = approve_finalizer_recovery;

                    // Create RunJournal before first mutation (fail-closed)
                    // Use process lock to prevent dual-writer from resume
                    let journal_store: Option<std::sync::Arc<JournalStore>> = if !dry_run {
                        let store = create_run_journal(
                            &client,
                            &plan,
                            &target_operators,
                            &gk_map,
                            effective_finalizer_recovery,
                        )
                        .await?;
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
                        &client,
                        &plan,
                        &kind_map,
                        &gk_map,
                        &gvk_map,
                        &gvr_map,
                        dry_run,
                        force,
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
                            let mut cleanup_failure: Option<String> = None;

                            // Run post-apply residual audit (only if apply succeeded and operator is Absent)
                            if let Some(store) = &journal_store
                                && result.failed.is_empty()
                                && result.barrier_timeout.is_none()
                            {
                                use crate::teardown::audit::{self, OperatorGenerationState};
                                let j = store.read().await;
                                let gen_state = audit::check_operator_generation(
                                    &client,
                                    &j.operator,
                                    &j.audit_context.csv_baseline,
                                )
                                .await;
                                match gen_state {
                                    OperatorGenerationState::Absent => {
                                        eprintln!("\n🔍 Running post-apply residual audit...");
                                        match audit::run_residual_audit(&client, &j).await {
                                            Ok(audit_result) => {
                                                let status = audit::residual_status_from_audit(
                                                    &audit_result,
                                                );
                                                audit::print_residual_audit(&audit_result, &j);
                                                let mut auto_candidates =
                                                        crate::teardown::executor::auto_cleanup_candidates(
                                                            &audit_result,
                                                            &j.execution.deleted,
                                                        );
                                                if let Some(ref saved) = _saved_plan {
                                                    match crate::teardown::executor::validate_saved_residual_decisions(
                                                            &saved.residual_decisions,
                                                            &audit_result,
                                                        ) {
                                                            Ok(extra) => auto_candidates.extend(extra),
                                                            Err(errors) => {
                                                                cleanup_failure = Some(format!(
                                                                    "Saved residual decisions require review: {}",
                                                                    errors.join("; ")
                                                                ));
                                                            }
                                                        }
                                                }
                                                let mut seen = std::collections::HashSet::new();
                                                auto_candidates.retain(|r| {
                                                    seen.insert((
                                                        r.group.clone(),
                                                        r.version.clone(),
                                                        r.kind.clone(),
                                                        r.namespace.clone(),
                                                        r.name.clone(),
                                                        r.uid.clone(),
                                                    ))
                                                });
                                                // Re-verify generation before saving
                                                let gen_recheck = audit::check_operator_generation(
                                                    &client,
                                                    &j.operator,
                                                    &j.audit_context.csv_baseline,
                                                )
                                                .await;
                                                if matches!(
                                                    gen_recheck,
                                                    OperatorGenerationState::Absent
                                                ) {
                                                    let audit_persisted = match store
                                                        .update(|j| {
                                                            j.residual_status = status;
                                                            j.audit_revision += 1;
                                                            j.last_residual_audit =
                                                                Some(audit_result.clone());
                                                        })
                                                        .await
                                                    {
                                                        Ok(()) => true,
                                                        Err(e) => {
                                                            eprintln!(
                                                                "⚠ Failed to persist audit results: {}",
                                                                e
                                                            );
                                                            eprintln!(
                                                                "  Audit results were displayed but are NOT durable."
                                                            );
                                                            eprintln!(
                                                                "  Do not use this audit for cleanup authority."
                                                            );
                                                            cleanup_failure = Some(format!(
                                                                "Residual audit persistence failed: {}",
                                                                e
                                                            ));
                                                            false
                                                        }
                                                    };
                                                    if audit_persisted {
                                                        if matches!(
                                                                audit::residual_status_from_audit(&audit_result),
                                                                journal::ResidualStatus::AuditIncomplete
                                                            ) {
                                                                cleanup_failure = Some(
                                                                    "Residual audit incomplete".to_string(),
                                                                );
                                                            } else if cleanup_failure.is_none() {
                                                                if !auto_candidates.is_empty() {
                                                                    eprintln!(
                                                                        "\n🧹 Cleaning {} planned/saved residual(s)...",
                                                                        auto_candidates.len()
                                                                    );
                                                                    match crate::teardown::executor::execute_residual_cleanup(
                                                                        &client,
                                                                        &auto_candidates,
                                                                        store.as_ref(),
                                                                        gate.as_ref(),
                                                                        &kind_map,
                                                                        &gk_map,
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
                                                                            if !cleanup.skipped.is_empty()
                                                                                || !cleanup.failed.is_empty()
                                                                            {
                                                                                cleanup_failure = Some(
                                                                                    "Residual cleanup incomplete".to_string(),
                                                                                );
                                                                            }
                                                                            if let Some(post) = cleanup.post_audit
                                                                                && (!post.planned_delete_still_present.is_empty()
                                                                                    || !post.planned_expect_still_present.is_empty())
                                                                            {
                                                                                cleanup_failure = Some(format!(
                                                                                    "{} planned DELETE/EXPECT resources remain after cleanup",
                                                                                    post.planned_delete_still_present.len()
                                                                                        + post.planned_expect_still_present.len()
                                                                                ));
                                                                            }
                                                                        }
                                                                        Err(e) => {
                                                                            cleanup_failure = Some(format!(
                                                                                "Residual cleanup failed: {:#}", e
                                                                            ));
                                                                        }
                                                                    }
                                                                } else if !audit_result
                                                                    .planned_delete_still_present
                                                                    .is_empty()
                                                                    || !audit_result
                                                                        .planned_expect_still_present
                                                                        .is_empty()
                                                                {
                                                                    cleanup_failure = Some(
                                                                        "Planned residuals require review before cleanup"
                                                                            .to_string(),
                                                                    );
                                                                }
                                                            }
                                                    }
                                                } else {
                                                    eprintln!(
                                                        "⚠ Operator generation changed during audit; discarding results"
                                                    );
                                                    cleanup_failure = Some(
                                                        "Operator generation changed during audit"
                                                            .to_string(),
                                                    );
                                                }
                                            }
                                            Err(e) => {
                                                eprintln!(
                                                    "⚠ Post-apply residual audit failed: {}",
                                                    e
                                                );
                                                cleanup_failure = Some(format!(
                                                    "Post-apply residual audit failed: {}",
                                                    e
                                                ));
                                            }
                                        }
                                    }
                                    _ => {
                                        eprintln!(
                                            "\nSkipping post-apply residual audit: operator generation not absent"
                                        );
                                        cleanup_failure =
                                            Some("Operator generation not absent".to_string());
                                    }
                                }
                            }

                            // Residual cleanup transition — only if Absent + complete audit + TTY
                            if final_state == RunState::ApplyCompleted
                                && let Some(store) = &journal_store
                            {
                                let j = store.read().await;
                                if let Some(ref audit) = j.last_residual_audit {
                                    let rs =
                                        crate::teardown::audit::residual_status_from_audit(audit);
                                    match rs {
                                        journal::ResidualStatus::ResidualsObserved { count } => {
                                            eprintln!("\n📋 {} residual(s) observed.", count);

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
                                                let residuals: Vec<
                                                    &crate::teardown::audit::AttributedResidual,
                                                > = audit
                                                    .likely_operator_residual
                                                    .iter()
                                                    .chain(audit.unattributed.iter())
                                                    .collect();

                                                if !residuals.is_empty() {
                                                    use crate::kube::resource::ResourceId;
                                                    eprintln!("\n\x1b[1mResidual Cleanup\x1b[0m:");
                                                    for (i, res) in residuals.iter().enumerate() {
                                                        eprintln!(
                                                            "  [{}] {:?} {}/{}{}",
                                                            i + 1,
                                                            res.confidence,
                                                            res.resource.kind,
                                                            res.resource.name,
                                                            res.resource
                                                                .namespace
                                                                .as_ref()
                                                                .map(|ns| format!(" ({})", ns))
                                                                .unwrap_or_default()
                                                        );
                                                    }
                                                    eprintln!();
                                                    eprintln!(
                                                        "  Enter item numbers to DELETE (comma-separated),"
                                                    );
                                                    eprintln!("  or press Enter to skip cleanup:");
                                                    eprint!("  > ");
                                                    std::io::Write::flush(&mut std::io::stderr())
                                                        .ok();

                                                    let mut input = String::new();
                                                    if std::io::stdin()
                                                        .read_line(&mut input)
                                                        .is_ok()
                                                    {
                                                        let input = input.trim();
                                                        if !input.is_empty() {
                                                            let mut selected: Vec<&ResourceId> =
                                                                Vec::new();
                                                            for token in input.split(',') {
                                                                if let Ok(idx) =
                                                                    token.trim().parse::<usize>()
                                                                    && idx >= 1
                                                                    && idx <= residuals.len()
                                                                {
                                                                    selected.push(
                                                                        &residuals[idx - 1]
                                                                            .resource,
                                                                    );
                                                                }
                                                            }

                                                            if !selected.is_empty() {
                                                                eprintln!(
                                                                    "\n  Deleting {} residual(s)...",
                                                                    selected.len()
                                                                );
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
                                                    eprintln!(
                                                        "  Use 'teardown journal' to review details."
                                                    );
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
                                            eprintln!(
                                                "\n✅ No residuals observed in scanned scope."
                                            );
                                        }
                                        _ => {}
                                    }
                                }
                            }

                            // Save plan with residual decisions if --save-plan provided
                            if let Some(ref save_path) = save_plan_path
                                && final_state == RunState::ApplyCompleted
                                && !target_operators.is_empty()
                                && let Some(store) = &journal_store
                            {
                                let j = store.read().await;
                                let mut residual_decisions = Vec::new();
                                // Build from cleanup_decisions + last_residual_audit
                                let mut seen_residual = std::collections::HashSet::new();
                                for cd in &j.cleanup_decisions {
                                    let dedup_key = (
                                        cd.resource.group.clone(),
                                        cd.resource.kind.clone(),
                                        cd.resource.namespace.clone(),
                                        cd.resource.name.clone(),
                                    );
                                    if !seen_residual.insert(dedup_key) {
                                        continue;
                                    }
                                    let evidence = build_residual_evidence(
                                        &cd.resource,
                                        &j.last_residual_audit,
                                    );
                                    let approval = if evidence.is_empty() {
                                        crate::teardown::plan::ApprovalKind::ExplicitUnattributed
                                    } else {
                                        crate::teardown::plan::ApprovalKind::Explicit
                                    };
                                    residual_decisions.push(crate::teardown::plan::SavedDecision {
                                        match_spec:
                                            crate::teardown::plan::ResourceMatch::from_resource_id(
                                                &cd.resource,
                                            ),
                                        action: crate::teardown::plan::SavedAction::Delete,
                                        approval,
                                        basis: crate::teardown::plan::DecisionBasis {
                                            provenance: None,
                                            review_category: None,
                                            discovery_source: None,
                                            decisive_evidence: evidence,
                                        },
                                    });
                                }
                                drop(j);

                                let pkg_name =
                                    target_operators[0].package_name.as_deref().unwrap_or("");
                                if !pkg_name.is_empty() {
                                    let target = crate::teardown::plan::SavedOperatorTarget {
                                        package_name: pkg_name.to_string(),
                                        install_namespace: target_operators[0]
                                            .install_namespace
                                            .clone(),
                                        csv_name_pattern: target_operators[0].csv.name.clone(),
                                    };
                                    let saved_plan = plan.clone();
                                    // Merge residual decisions from cleanup into saved plan
                                    match save_as_saved_plan(&saved_plan, &target, Some(save_path))
                                    {
                                        Ok(path) => {
                                            if !residual_decisions.is_empty()
                                                && let Ok(data) = std::fs::read_to_string(&path)
                                                && let Ok(mut sp) = serde_json::from_str::<
                                                    crate::teardown::plan::SavedTeardownPlan,
                                                >(
                                                    &data
                                                )
                                            {
                                                sp.residual_decisions = residual_decisions;
                                                let _ = std::fs::write(
                                                    &path,
                                                    serde_json::to_string_pretty(&sp)
                                                        .unwrap_or_default(),
                                                );
                                            }
                                            eprintln!(
                                                "📄 Saved plan with residual decisions: {}",
                                                path
                                            );
                                        }
                                        Err(e) => eprintln!("⚠ Could not save plan: {}", e),
                                    }
                                }
                            }

                            // Non-zero exit for non-ApplyCompleted states
                            match final_state {
                                RunState::ApplyCompleted => {
                                    if let Some(reason) = cleanup_failure {
                                        bail!(
                                            "Main teardown completed, but cleanup is incomplete: {}",
                                            reason
                                        );
                                    }
                                }
                                RunState::Paused => {
                                    bail!(
                                        "Teardown paused at phase {}/{}",
                                        result.phases_completed,
                                        result.phases_total
                                    );
                                }
                                _ => {
                                    if !result.failed.is_empty() || result.barrier_timeout.is_some()
                                    {
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
                            if let Some(store) = &journal_store
                                && let Err(je) = store
                                    .update(|j| {
                                        j.state = RunState::Failed;
                                    })
                                    .await
                            {
                                eprintln!(
                                    "⚠ Additionally, failed to persist Failed state to journal: {}",
                                    je
                                );
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
                TeardownAction::Coverage {
                    operators: operator_queries,
                    output,
                    no_cache,
                } => {
                    let (kind_map, gvr_map, gk_map, gvk_map) =
                        build_kind_lookup_cached(&client, &config, no_cache).await?;
                    let all_operators = discover_operators(&client, &kind_map).await?;
                    let target_indices =
                        resolve_operator_targets(&operator_queries, &all_operators)?;
                    let target_operators: Vec<&_> =
                        target_indices.iter().map(|&i| &all_operators[i]).collect();

                    let policy = DecisionPolicy::from_args(&[], &[]);
                    let plan = generate_teardown_plan(
                        &client,
                        &target_operators,
                        &all_operators,
                        &kind_map,
                        &gvr_map,
                        &gk_map,
                        &gvk_map,
                        false,
                        &policy,
                    )
                    .await?;

                    // Categorize plan actions
                    let mut covered = Vec::new();
                    let mut preserved = Vec::new();
                    let mut not_covered = Vec::new();

                    for phase in &plan.phases {
                        for action in &phase.actions {
                            match action {
                                crate::teardown::planner::Action::Delete { resource, .. }
                                | crate::teardown::planner::Action::ExpectGone {
                                    resource, ..
                                } => {
                                    covered.push(resource.clone());
                                }
                                crate::teardown::planner::Action::Keep { resource, .. } => {
                                    preserved.push(resource.clone());
                                }
                                crate::teardown::planner::Action::Review { resource, .. } => {
                                    not_covered.push(resource.clone());
                                }
                                _ => {}
                            }
                        }
                    }

                    match output {
                        OutputFormat::Json => {
                            let json = serde_json::json!({
                                "coverage_scope": "plan-known-footprint",
                                "complete": false,
                                "note": "Coverage is limited to resources discovered by the plan. Resources outside operator-owned APIs, related CRDs, and namespace discovery are not included.",
                                "covered_by_plan": covered.len(),
                                "intentionally_preserved": preserved.len(),
                                "not_covered": not_covered.len(),
                                "covered": covered,
                                "preserved": preserved,
                                "not_covered_resources": not_covered,
                            });
                            println!("{}", serde_json::to_string_pretty(&json)?);
                        }
                        _ => {
                            eprintln!(
                                "\n\x1b[1mCoverage\x1b[0m: {} covered, {} preserved, {} not covered",
                                covered.len(),
                                preserved.len(),
                                not_covered.len()
                            );
                            if !not_covered.is_empty() {
                                eprintln!("\n\x1b[33mNOT COVERED (REVIEW):\x1b[0m");
                                for r in &not_covered {
                                    eprintln!(
                                        "  {}/{}{}",
                                        r.kind,
                                        r.name,
                                        r.namespace
                                            .as_ref()
                                            .map(|ns| format!(" ({})", ns))
                                            .unwrap_or_default()
                                    );
                                }
                            }
                        }
                    }
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

                    let inspection = inspect_operator_with_options(
                        &client, target_op, &kind_map, &gvr_map, &gk_map, false,
                    )
                    .await?;

                    print_inspection_top(&inspection, &output, false);
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
                TeardownAction::Resume {
                    operator,
                    run,
                    no_cache,
                } => {
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
                                eprintln!(
                                    "Run {} is ApplyCompleted but has no residual audit — running audit recovery",
                                    j.run_id
                                );
                            } else {
                                eprintln!(
                                    "Run {} is ApplyCompleted — re-entering Residual Cleanup",
                                    j.run_id
                                );
                            }
                        }
                        RunState::Finished => {
                            bail!("Run {} already finished — nothing to resume", j.run_id);
                        }
                        RunState::Failed => {
                            bail!(
                                "Run {} has failed. Review the journal and create a new plan if needed.",
                                j.run_id
                            );
                        }
                        _ => {
                            bail!("Run {} is in state {:?} — cannot resume", j.run_id, j.state);
                        }
                    }

                    // Acquire process lock FIRST — fail if another executor is active
                    let path = journal::run_path(&cluster_id, &j.run_id)?;
                    let store = std::sync::Arc::new(JournalStore::new_with_lock(j.clone(), path)?);

                    // Re-read from store — this is the AUTHORITATIVE state after lock.
                    // All decisions below use ONLY this `j`, not the pre-lock one.
                    let j = store.read().await;

                    // Re-verify state after lock (another process may have completed it)
                    match j.state {
                        RunState::Paused | RunState::Applying | RunState::InteractiveCleanup => {}
                        // A completed main apply can re-enter residual cleanup.
                        // The process lock, not the presence of a prior audit,
                        // prevents concurrent resume writers.
                        RunState::ApplyCompleted => {}
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
                            j.schema_version,
                            journal::RUN_JOURNAL_SCHEMA_VERSION
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
                    use crate::teardown::audit::{self, OperatorGenerationState};
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
                                        resource.kind,
                                        resource.name,
                                    ),
                                };
                                match api.get(&resource.name).await {
                                    Ok(obj) => {
                                        let live_uid = obj.metadata.uid.as_deref().unwrap_or("");
                                        // UID check
                                        let plan_uid = match &resource.uid {
                                            Some(u) if !u.is_empty() => u.as_str(),
                                            _ => bail!(
                                                "Plan resource {}/{} has no UID — \
                                                             cannot verify identity for resume",
                                                resource.kind,
                                                resource.name,
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
                                        if obj.metadata.deletion_timestamp.is_none() {
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
                                    Err(::kube::Error::Api(ref err)) if err.code == 404 => {
                                        // Verify endpoint exists before declaring Gone
                                        match api
                                            .list(&::kube::api::ListParams::default().limit(1))
                                            .await
                                        {
                                            Ok(_) => {
                                                // Endpoint exists, resource genuinely gone
                                            }
                                            Err(_) => {
                                                bail!(
                                                    "{}/{}: GET 404 but endpoint verification failed — \
                                                                 cannot confirm absence for resume",
                                                    resource.kind,
                                                    resource.name
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
                        start_phase,
                        j.plan_snapshot.phases.len()
                    );

                    // An accepted re-delete may have become Gone after the
                    // last checkpoint. Reconcile it before classifying a
                    // completed main run for residual re-entry. An intent
                    // without an accepted DELETE never gains authority here.
                    if j.state == RunState::ApplyCompleted
                        && start_phase == j.plan_snapshot.phases.len()
                    {
                        for record in j
                            .execution
                            .re_delete_records
                            .iter()
                            .filter(|r| matches!(r.result, journal::ReDeleteResult::Accepted))
                        {
                            let (api, _) = crate::kube::resource::resolve_api(
                                &client,
                                &record.resource_identity,
                                &kind_map,
                                &gk_map,
                            )
                            .ok_or_else(|| {
                                anyhow::anyhow!(
                                    "Cannot resolve API for accepted re-delete {}/{}",
                                    record.resource_identity.kind,
                                    record.resource_identity.name
                                )
                            })?;
                            match api.get(&record.resource_identity.name).await {
                                Err(::kube::Error::Api(ref err)) if err.code == 404 => {
                                    api.list(&::kube::api::ListParams::default().limit(1))
                                        .await
                                        .with_context(|| {
                                            format!(
                                                "Cannot verify endpoint for re-delete {}/{}",
                                                record.resource_identity.kind,
                                                record.resource_identity.name
                                            )
                                        })?;
                                    let identity = record.resource_identity.clone();
                                    let original_uid = record.original_uid.clone();
                                    let new_uid = record.new_uid.clone();
                                    store
                                        .update(|latest| {
                                            if let Some(entry) =
                                                latest.execution.re_delete_records.iter_mut().find(
                                                    |r| {
                                                        r.resource_identity == identity
                                                            && r.original_uid == original_uid
                                                            && r.new_uid == new_uid
                                                            && matches!(
                                                                r.result,
                                                                journal::ReDeleteResult::Accepted
                                                            )
                                                    },
                                                )
                                            {
                                                entry.result = journal::ReDeleteResult::Gone;
                                            }
                                        })
                                        .await?;
                                }
                                Ok(_) => {}
                                Err(e) => {
                                    bail!(
                                        "Cannot reconcile accepted re-delete {}/{}: {}",
                                        record.resource_identity.kind,
                                        record.resource_identity.name,
                                        e
                                    );
                                }
                            }
                        }
                    }
                    let j = store.read().await;

                    let gate = std::sync::Arc::new(MutationGate::new(16));

                    // Ctrl-C handler for resume
                    {
                        let gate_for_signal = gate.clone();
                        tokio::spawn(async move {
                            if tokio::signal::ctrl_c().await.is_ok() {
                                eprintln!("\n⏸ Pausing... waiting for active mutations...");
                                gate_for_signal.close_and_drain().await;
                            }
                        });
                    }

                    let resume_stage = classify_resume_stage(&j)
                        .map_err(|e| anyhow::anyhow!("Cannot resume: {}", e))?;
                    let main_complete = j.execution.phases_completed == j.execution.phases_total;
                    let paused_from_residual = j.state == RunState::Paused
                        && main_complete
                        && j.last_residual_audit.is_some();

                    if resume_stage == ResumeStage::Cleanup {
                        // Schema gate: v5 journals cannot gain resume authority
                        if j.schema_version != journal::RUN_JOURNAL_SCHEMA_VERSION {
                            bail!(
                                "Journal schema v{} does not match current v{}. \
                                             Cannot resume cleanup on incompatible journal.",
                                j.schema_version,
                                journal::RUN_JOURNAL_SCHEMA_VERSION
                            );
                        }

                        if resume_has_blocking_hard_failure(&j) {
                            store
                                .update(|j| {
                                    j.state = RunState::Failed;
                                })
                                .await?;
                            bail!(
                                "Journal contains hard-failed cleanup decisions from a prior run. \
                                             Cannot resume — create a new teardown plan."
                            );
                        }

                        // Write InteractiveCleanup state for crash safety
                        if j.state != RunState::InteractiveCleanup {
                            store
                                .update(|j| {
                                    j.state = RunState::InteractiveCleanup;
                                })
                                .await?;
                        }
                        let pending: Vec<crate::teardown::journal::CleanupDecision> = j
                            .cleanup_decisions
                            .iter()
                            .filter(|d| d.is_pending())
                            .cloned()
                            .collect();

                        let mut any_hard_failed = false;
                        let mut any_retryable = false;
                        let is_residual_reentry = paused_from_residual
                            || (j.state == RunState::ApplyCompleted && main_complete)
                            || (j.state == RunState::InteractiveCleanup && main_complete);

                        if pending.is_empty() {
                            if is_residual_reentry {
                                eprintln!("Resuming Residual Cleanup stage.");
                                let gen_check = audit::check_operator_generation(
                                    &client,
                                    &j.operator,
                                    &j.audit_context.csv_baseline,
                                )
                                .await;
                                if !matches!(gen_check, OperatorGenerationState::Absent) {
                                    bail!(
                                        "Operator generation not Absent on Residual resume — \
                                                       create a new teardown plan."
                                    );
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
                                        &client,
                                        &decision.resource,
                                        &kind_map,
                                        &gk_map,
                                    )
                                    .ok_or_else(|| {
                                        anyhow::anyhow!(
                                            "Cannot resolve API for {}/{}",
                                            decision.resource.kind,
                                            decision.resource.name
                                        )
                                    })?;
                                    match api.get(&decision.resource.name).await {
                                        Err(::kube::Error::Api(ref err)) if err.code == 404 => {
                                            // Verify endpoint exists (404 could be endpoint gone, not object gone)
                                            match api
                                                .list(&::kube::api::ListParams::default().limit(1))
                                                .await
                                            {
                                                Ok(_) => {
                                                    let res_up = decision.resource.clone();
                                                    store.update(|j| {
                                                                    if let Some(d) = j.cleanup_decisions.iter_mut().rev()
                                                                        .find(|d| d.resource == res_up && matches!(d.result, Some(CleanupResult::DeleteRequested)))
                                                                    { d.result = Some(CleanupResult::Gone); }
                                                                }).await?;
                                                    eprintln!(
                                                        "  {}/{}: gone (confirmed on resume)",
                                                        decision.resource.kind,
                                                        decision.resource.name
                                                    );
                                                }
                                                Err(_) => {
                                                    eprintln!(
                                                        "  ⚠ {}/{}: GET 404 but endpoint verification failed — cannot confirm Gone",
                                                        decision.resource.kind,
                                                        decision.resource.name
                                                    );
                                                    any_retryable = true;
                                                }
                                            }
                                        }
                                        Ok(obj) => {
                                            let live_uid =
                                                obj.metadata.uid.as_deref().unwrap_or("");
                                            let bound = decision.bound_uid.as_deref().unwrap_or("");
                                            if bound.is_empty() || live_uid.is_empty() {
                                                bail!(
                                                    "Cannot verify {}/{}: UID missing (bound={:?}, live={:?})",
                                                    decision.resource.kind,
                                                    decision.resource.name,
                                                    bound,
                                                    live_uid
                                                );
                                            }
                                            if live_uid != bound {
                                                let res_up = decision.resource.clone();
                                                store.update(|j| {
                                                                if let Some(d) = j.cleanup_decisions.iter_mut().rev()
                                                                    .find(|d| d.resource == res_up && matches!(d.result, Some(CleanupResult::DeleteRequested)))
                                                                { d.result = Some(CleanupResult::Gone); }
                                                            }).await?;
                                                eprintln!(
                                                    "  {}/{}: old UID gone (new UID {} = recreated)",
                                                    decision.resource.kind,
                                                    decision.resource.name,
                                                    live_uid
                                                );
                                                continue;
                                            }
                                            // Same UID — check if deleting
                                            if obj.metadata.deletion_timestamp.is_some() {
                                                let mut gone = false;
                                                for _ in 0..30 {
                                                    tokio::time::sleep(
                                                        std::time::Duration::from_secs(2),
                                                    )
                                                    .await;
                                                    match api.get(&decision.resource.name).await {
                                                        Err(::kube::Error::Api(ref err))
                                                            if err.code == 404 =>
                                                        {
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
                                                    eprintln!(
                                                        "  {}/{}: gone (waited on resume)",
                                                        decision.resource.kind,
                                                        decision.resource.name
                                                    );
                                                } else {
                                                    eprintln!(
                                                        "  ⚠ {}/{}: still not Gone after wait",
                                                        decision.resource.kind,
                                                        decision.resource.name
                                                    );
                                                    any_retryable = true;
                                                }
                                            } else {
                                                // No deletionTimestamp — UID-bound authority exists.
                                                // Re-DELETE requires same safety checks as fresh DELETE.
                                                eprintln!(
                                                    "  {}/{}: exists without deletionTimestamp — verifying for re-DELETE",
                                                    decision.resource.kind, decision.resource.name
                                                );

                                                // Acquire permit first
                                                let _re_permit = gate.acquire().await.context(
                                                    "Mutation gate closed during re-DELETE",
                                                )?;

                                                // Post-permit: generation + audit + membership
                                                let re_j = store.read().await;
                                                let re_gen = audit::check_operator_generation(
                                                    &client,
                                                    &re_j.operator,
                                                    &re_j.audit_context.csv_baseline,
                                                )
                                                .await;
                                                if !matches!(
                                                    re_gen,
                                                    OperatorGenerationState::Absent
                                                ) {
                                                    eprintln!(
                                                        "    ⚠ Generation not Absent for re-DELETE — skipping"
                                                    );
                                                    any_retryable = true;
                                                    drop(_re_permit);
                                                } else {
                                                    match audit::run_residual_audit(&client, &re_j)
                                                        .await
                                                    {
                                                        Ok(re_audit) => {
                                                            let re_status =
                                                                audit::residual_status_from_audit(
                                                                    &re_audit,
                                                                );
                                                            let re_in_set = !matches!(re_status, journal::ResidualStatus::AuditIncomplete)
                                                                            && re_audit.likely_operator_residual.iter()
                                                                                .chain(re_audit.unattributed.iter())
                                                                                .any(|r| r.resource == decision.resource);
                                                            if !re_in_set {
                                                                eprintln!(
                                                                    "    ⚠ Not in current residual set for re-DELETE — skipping"
                                                                );
                                                                any_retryable = true;
                                                                drop(_re_permit);
                                                            } else {
                                                                // Post-audit generation recheck before mutation
                                                                let re_gen2 = audit::check_operator_generation(
                                                                                &client, &re_j.operator, &re_j.audit_context.csv_baseline,
                                                                            ).await;
                                                                if !matches!(
                                                                    re_gen2,
                                                                    OperatorGenerationState::Absent
                                                                ) {
                                                                    eprintln!(
                                                                        "    ⚠ Generation changed during re-DELETE audit — skipping"
                                                                    );
                                                                    any_retryable = true;
                                                                    drop(_re_permit);
                                                                    continue;
                                                                }
                                                                use crate::teardown::executor::DeleteOutcome;
                                                                let re_del = crate::teardown::executor::delete_resource_pub(
                                                                                &client, &decision.resource, &kind_map, &gk_map,
                                                                                None, // permit already held
                                                                                decision.approved_spec_name.as_deref(),
                                                                            ).await;
                                                                match re_del {
                                                                    DeleteOutcome::Accepted => {
                                                                        eprintln!(
                                                                            "    {}/{}: re-DELETE accepted",
                                                                            decision.resource.kind,
                                                                            decision.resource.name,
                                                                        );
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
                                                                        let re_result = if re_gone {
                                                                            CleanupResult::Gone
                                                                        } else {
                                                                            CleanupResult::DeleteRequested
                                                                        };
                                                                        let res_up = decision
                                                                            .resource
                                                                            .clone();
                                                                        let re_result_clone =
                                                                            re_result.clone();
                                                                        store.update(|j| {
                                                                                if let Some(d) = j.cleanup_decisions.iter_mut().rev()
                                                                                    .find(|d| d.resource == res_up && matches!(d.result, Some(CleanupResult::DeleteRequested) | Some(CleanupResult::UnknownOutcome(_))))
                                                                                { d.result = Some(re_result_clone); }
                                                                            }).await
                                                                            .context("Failed to checkpoint re-DELETE result")?;
                                                                        if !re_gone {
                                                                            any_retryable = true;
                                                                        }
                                                                    }
                                                                    DeleteOutcome::AlreadyGone => {
                                                                        eprintln!(
                                                                            "    {}/{}: already gone",
                                                                            decision.resource.kind,
                                                                            decision.resource.name,
                                                                        );
                                                                        let res_up = decision
                                                                            .resource
                                                                            .clone();
                                                                        store.update(|j| {
                                                                                if let Some(d) = j.cleanup_decisions.iter_mut().rev()
                                                                                    .find(|d| d.resource == res_up && matches!(d.result, Some(CleanupResult::DeleteRequested) | Some(CleanupResult::UnknownOutcome(_))))
                                                                                { d.result = Some(CleanupResult::Gone); }
                                                                            }).await
                                                                            .context("Failed to checkpoint re-DELETE already gone")?;
                                                                    }
                                                                    DeleteOutcome::Unknown(
                                                                        reason,
                                                                    ) => {
                                                                        eprintln!(
                                                                            "    ⚠ {}/{}: unknown outcome: {} — stopping (resumable)",
                                                                            decision.resource.kind,
                                                                            decision.resource.name,
                                                                            reason
                                                                        );
                                                                        let res_up = decision
                                                                            .resource
                                                                            .clone();
                                                                        store.update(|j| {
                                                                                if let Some(d) = j.cleanup_decisions.iter_mut().rev()
                                                                                    .find(|d| d.resource == res_up)
                                                                                { d.result = Some(CleanupResult::UnknownOutcome(reason.clone())); }
                                                                            }).await
                                                                            .context("Failed to checkpoint unknown re-DELETE")?;
                                                                        // NOT any_hard_failed: Unknown is resumable via reconciliation
                                                                        any_retryable = true;
                                                                        drop(_re_permit);
                                                                        break;
                                                                    }
                                                                    DeleteOutcome::Blocked(
                                                                        reason,
                                                                    )
                                                                    | DeleteOutcome::Rejected(
                                                                        reason,
                                                                    ) => {
                                                                        eprintln!(
                                                                            "    ⚠ {}/{}: re-DELETE blocked/rejected: {}",
                                                                            decision.resource.kind,
                                                                            decision.resource.name,
                                                                            reason
                                                                        );
                                                                        any_hard_failed = true;
                                                                    }
                                                                }
                                                                drop(_re_permit);
                                                            }
                                                        }
                                                        Err(e) => {
                                                            eprintln!(
                                                                "    ⚠ Post-permit audit failed for re-DELETE: {}",
                                                                e
                                                            );
                                                            any_retryable = true;
                                                            drop(_re_permit);
                                                        }
                                                    }
                                                }
                                            }
                                        }
                                        Err(e) => {
                                            eprintln!(
                                                "  ⚠ {}/{}: cannot verify: {}",
                                                decision.resource.kind, decision.resource.name, e
                                            );
                                            any_retryable = true;
                                        }
                                    }
                                    continue;
                                }

                                // Below: result.is_none() — fresh DELETE needed
                                // Validate decision authority fields
                                if decision.action != "delete" {
                                    bail!(
                                        "Pending decision for {}/{} has action '{}', expected 'delete' — cannot resume",
                                        decision.resource.kind,
                                        decision.resource.name,
                                        decision.action
                                    );
                                }
                                if decision.bound_uid.as_deref().unwrap_or("").is_empty() {
                                    bail!(
                                        "Pending decision for {}/{} has no bound_uid — cannot verify identity for resume",
                                        decision.resource.kind,
                                        decision.resource.name
                                    );
                                }

                                if !gate.is_open() {
                                    eprintln!("⏸ Gate closed — stopping cleanup resume");
                                    break;
                                }

                                // 1. Per-resource generation check
                                let j_cur = store.read().await;
                                let gen_state = audit::check_operator_generation(
                                    &client,
                                    &j_cur.operator,
                                    &j_cur.audit_context.csv_baseline,
                                )
                                .await;
                                if !matches!(gen_state, OperatorGenerationState::Absent) {
                                    bail!("Generation not Absent — cannot resume cleanup");
                                }

                                // 2. Fresh complete audit + membership check
                                let fresh_audit = audit::run_residual_audit(&client, &j_cur)
                                    .await
                                    .context("Fresh audit failed during cleanup resume")?;
                                let audit_status = audit::residual_status_from_audit(&fresh_audit);
                                if matches!(
                                    audit_status,
                                    crate::teardown::journal::ResidualStatus::AuditIncomplete
                                ) {
                                    bail!(
                                        "Audit incomplete — cannot verify residual membership for resume"
                                    );
                                }
                                let in_set = fresh_audit
                                    .likely_operator_residual
                                    .iter()
                                    .chain(fresh_audit.unattributed.iter())
                                    .any(|r| {
                                        r.resource.group == decision.resource.group
                                            && r.resource.kind == decision.resource.kind
                                            && r.resource.name == decision.resource.name
                                            && r.resource.namespace == decision.resource.namespace
                                    });
                                if !in_set {
                                    // Check if already Gone
                                    let (api, _) = crate::kube::resource::resolve_api(
                                        &client,
                                        &decision.resource,
                                        &kind_map,
                                        &gk_map,
                                    )
                                    .ok_or_else(|| {
                                        anyhow::anyhow!(
                                            "Cannot resolve API for {}/{} — aborting resume",
                                            decision.resource.kind,
                                            decision.resource.name
                                        )
                                    })?;
                                    match api.get(&decision.resource.name).await {
                                        Err(::kube::Error::Api(ref err)) if err.code == 404 => {
                                            // Verify endpoint exists before declaring AlreadyGone
                                            match api
                                                .list(&::kube::api::ListParams::default().limit(1))
                                                .await
                                            {
                                                Ok(_) => {
                                                    let res_up = decision.resource.clone();
                                                    store
                                                        .update(|j| {
                                                            if let Some(d) = j
                                                                .cleanup_decisions
                                                                .iter_mut()
                                                                .rev()
                                                                .find(|d| {
                                                                    d.resource == res_up
                                                                        && d.result.is_none()
                                                                })
                                                            {
                                                                d.result = Some(
                                                                    CleanupResult::AlreadyGone,
                                                                );
                                                            }
                                                        })
                                                        .await?;
                                                    eprintln!(
                                                        "  {}/{}: already gone",
                                                        decision.resource.kind,
                                                        decision.resource.name
                                                    );
                                                    continue;
                                                }
                                                Err(_) => {
                                                    bail!(
                                                        "{}/{}: GET 404 but endpoint verification failed — \
                                                                       cannot confirm absence vs endpoint removal",
                                                        decision.resource.kind,
                                                        decision.resource.name
                                                    );
                                                }
                                            }
                                        }
                                        _ => bail!(
                                            "{}/{} not in current residual set and not Gone",
                                            decision.resource.kind,
                                            decision.resource.name
                                        ),
                                    }
                                }

                                // 3. Verify bound UID matches live
                                let bound_uid = decision.bound_uid.as_deref().unwrap_or("");
                                if bound_uid.is_empty() {
                                    bail!(
                                        "Pending decision for {}/{} has no bound UID — cannot verify identity",
                                        decision.resource.kind,
                                        decision.resource.name
                                    );
                                }
                                let (api, _) = crate::kube::resource::resolve_api(
                                    &client,
                                    &decision.resource,
                                    &kind_map,
                                    &gk_map,
                                )
                                .ok_or_else(|| {
                                    anyhow::anyhow!(
                                        "Cannot resolve API for {}/{} — aborting resume",
                                        decision.resource.kind,
                                        decision.resource.name
                                    )
                                })?;
                                match api.get(&decision.resource.name).await {
                                    Ok(obj) => {
                                        let live_uid = obj.metadata.uid.as_deref().unwrap_or("");
                                        if live_uid != bound_uid {
                                            bail!(
                                                "Resource {}/{} UID changed ({} → {}) — cannot resume cleanup",
                                                decision.resource.kind,
                                                decision.resource.name,
                                                bound_uid,
                                                live_uid
                                            );
                                        }
                                    }
                                    Err(::kube::Error::Api(ref err)) if err.code == 404 => {
                                        match api
                                            .list(&::kube::api::ListParams::default().limit(1))
                                            .await
                                        {
                                            Ok(_) => {
                                                let res_up = decision.resource.clone();
                                                store
                                                    .update(|j| {
                                                        if let Some(d) = j
                                                            .cleanup_decisions
                                                            .iter_mut()
                                                            .rev()
                                                            .find(|d| {
                                                                d.resource == res_up
                                                                    && d.result.is_none()
                                                            })
                                                        {
                                                            d.result =
                                                                Some(CleanupResult::AlreadyGone);
                                                        }
                                                    })
                                                    .await?;
                                                eprintln!(
                                                    "  {}/{}: already gone",
                                                    decision.resource.kind, decision.resource.name
                                                );
                                                continue;
                                            }
                                            Err(_) => {
                                                bail!(
                                                    "{}/{}: GET 404 but endpoint verification failed — \
                                                                   cannot confirm absence vs endpoint removal",
                                                    decision.resource.kind,
                                                    decision.resource.name
                                                );
                                            }
                                        }
                                    }
                                    Err(e) => bail!(
                                        "Cannot verify {}/{}: {} — aborting resume",
                                        decision.resource.kind,
                                        decision.resource.name,
                                        e
                                    ),
                                }

                                // 4. DELETE with permit held through checkpoint
                                let _permit = gate
                                    .acquire()
                                    .await
                                    .context("Mutation gate closed during cleanup resume")?;

                                // Post-permit rechecks: generation + audit + membership could have changed
                                {
                                    let pp_j = store.read().await;
                                    let pp_gen = audit::check_operator_generation(
                                        &client,
                                        &pp_j.operator,
                                        &pp_j.audit_context.csv_baseline,
                                    )
                                    .await;
                                    if !matches!(pp_gen, OperatorGenerationState::Absent) {
                                        bail!(
                                            "Generation changed after permit acquisition — aborting resume"
                                        );
                                    }
                                    let pp_audit = audit::run_residual_audit(&client, &pp_j)
                                        .await
                                        .context("Post-permit audit failed during resume")?;
                                    let pp_status = audit::residual_status_from_audit(&pp_audit);
                                    if matches!(pp_status, journal::ResidualStatus::AuditIncomplete)
                                    {
                                        bail!("Post-permit audit incomplete — aborting resume");
                                    }
                                    let pp_in_set = pp_audit
                                        .likely_operator_residual
                                        .iter()
                                        .chain(pp_audit.unattributed.iter())
                                        .any(|r| {
                                            r.resource.group == decision.resource.group
                                                && r.resource.kind == decision.resource.kind
                                                && r.resource.name == decision.resource.name
                                                && r.resource.namespace
                                                    == decision.resource.namespace
                                        });
                                    if !pp_in_set {
                                        bail!(
                                            "{}/{} no longer in residual set after permit acquisition",
                                            decision.resource.kind,
                                            decision.resource.name
                                        );
                                    }
                                    // Final generation recheck after audit
                                    let pp_gen2 = audit::check_operator_generation(
                                        &client,
                                        &pp_j.operator,
                                        &pp_j.audit_context.csv_baseline,
                                    )
                                    .await;
                                    if !matches!(pp_gen2, OperatorGenerationState::Absent) {
                                        bail!(
                                            "Generation changed during post-permit audit — aborting resume"
                                        );
                                    }
                                }

                                use crate::teardown::executor::DeleteOutcome;
                                let del = crate::teardown::executor::delete_resource_pub(
                                    &client,
                                    &decision.resource,
                                    &kind_map,
                                    &gk_map,
                                    None,
                                    decision.approved_spec_name.as_deref(),
                                )
                                .await;

                                let must_stop = del.is_stop();
                                let initial_result = match &del {
                                    DeleteOutcome::Accepted => CleanupResult::DeleteRequested,
                                    DeleteOutcome::AlreadyGone => CleanupResult::AlreadyGone,
                                    DeleteOutcome::Unknown(reason) => {
                                        CleanupResult::UnknownOutcome(reason.clone())
                                    }
                                    DeleteOutcome::Blocked(reason)
                                    | DeleteOutcome::Rejected(reason) => {
                                        any_hard_failed = true;
                                        CleanupResult::Failed(reason.clone())
                                    }
                                };
                                let res_up = decision.resource.clone();
                                let initial_clone = initial_result.clone();
                                store
                                    .update(|j| {
                                        if let Some(d) =
                                            j.cleanup_decisions.iter_mut().rev().find(|d| {
                                                d.resource == res_up && d.result.is_none()
                                            })
                                        {
                                            d.result = Some(initial_clone);
                                        }
                                    })
                                    .await
                                    .context("Failed to checkpoint cleanup result")?;
                                drop(_permit);

                                // Unknown/Blocked → stop loop (Unknown is resumable)
                                if must_stop {
                                    if matches!(initial_result, CleanupResult::UnknownOutcome(_)) {
                                        any_retryable = true;
                                    } else {
                                        any_hard_failed = true;
                                    }
                                    break;
                                }

                                // 5. Wait for Gone (only if DELETE was accepted)
                                if matches!(initial_result, CleanupResult::DeleteRequested) {
                                    let mut gone = false;
                                    for _ in 0..30 {
                                        tokio::time::sleep(std::time::Duration::from_secs(2)).await;
                                        match api.get(&decision.resource.name).await {
                                            Err(::kube::Error::Api(ref err)) if err.code == 404 => {
                                                match api
                                                    .list(
                                                        &::kube::api::ListParams::default()
                                                            .limit(1),
                                                    )
                                                    .await
                                                {
                                                    Ok(_) => {
                                                        gone = true;
                                                        break;
                                                    }
                                                    Err(_) => {
                                                        any_retryable = true;
                                                        break;
                                                    }
                                                }
                                            }
                                            Ok(_) => continue,
                                            Err(_) => {
                                                any_retryable = true;
                                                break;
                                            }
                                        }
                                    }
                                    if gone {
                                        // Update result to "gone" (confirmed)
                                        let res_up2 = decision.resource.clone();
                                        store
                                            .update(|j| {
                                                if let Some(d) =
                                                    j.cleanup_decisions.iter_mut().rev().find(|d| {
                                                        d.resource == res_up2
                                                            && matches!(
                                                                d.result,
                                                                Some(
                                                                    CleanupResult::DeleteRequested
                                                                )
                                                            )
                                                    })
                                                {
                                                    d.result = Some(CleanupResult::Gone);
                                                }
                                            })
                                            .await?;
                                        eprintln!(
                                            "  {}/{}: gone (confirmed)",
                                            decision.resource.kind, decision.resource.name
                                        );
                                    } else {
                                        eprintln!(
                                            "  ⚠ {}/{}: DELETE accepted but Gone not confirmed",
                                            decision.resource.kind, decision.resource.name
                                        );
                                        any_retryable = true;
                                    }
                                } else {
                                    eprintln!(
                                        "  {}/{}: {:?}",
                                        decision.resource.kind,
                                        decision.resource.name,
                                        initial_result
                                    );
                                }
                            }
                        }

                        // 6. Mandatory re-audit
                        let j_cur = store.read().await;
                        let gen_state = audit::check_operator_generation(
                            &client,
                            &j_cur.operator,
                            &j_cur.audit_context.csv_baseline,
                        )
                        .await;
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
                                    store
                                        .update(|j| {
                                            j.residual_status = status.clone();
                                            j.audit_revision += 1;
                                            j.last_residual_audit = Some(re_audit);
                                        })
                                        .await?;
                                    if matches!(
                                        status,
                                        crate::teardown::journal::ResidualStatus::AuditIncomplete
                                    ) {
                                        RunState::InteractiveCleanup
                                    } else {
                                        let j_final = store.read().await;
                                        if resume_has_blocking_hard_failure(&j_final) {
                                            RunState::Failed
                                        } else if j_final
                                            .cleanup_decisions
                                            .iter()
                                            .any(|d| d.is_pending())
                                        {
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
                        store
                            .update(|j| {
                                j.state = final_state.clone();
                            })
                            .await?;
                        if final_state == RunState::Failed {
                            bail!("Cleanup resume completed with hard failures");
                        }
                        if final_state == RunState::InteractiveCleanup {
                            bail!(
                                "Cleanup resume incomplete — pending decisions remain. \
                                             State persisted as InteractiveCleanup (retryable)."
                            );
                        }

                        // Residual re-entry: use TUI Residual screen
                        if is_residual_reentry && final_state == RunState::ApplyCompleted {
                            crate::tui::run_residual_only(
                                &client, &store, &gate, &kind_map, &gk_map,
                            )
                            .await?;
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
                                    &client,
                                    &j_post.operator,
                                    &j_post.audit_context.csv_baseline,
                                )
                                .await;
                                if matches!(post_gen, OperatorGenerationState::Absent) {
                                    match audit::run_residual_audit(&client, &j_post).await {
                                        Ok(post_audit) => {
                                            let post_status =
                                                audit::residual_status_from_audit(&post_audit);
                                            audit::print_residual_audit(&post_audit, &j_post);
                                            // Re-verify generation after audit
                                            let gen_recheck = audit::check_operator_generation(
                                                &client,
                                                &j_post.operator,
                                                &j_post.audit_context.csv_baseline,
                                            )
                                            .await;
                                            if matches!(
                                                gen_recheck,
                                                OperatorGenerationState::Absent
                                            ) {
                                                store
                                                    .update(|j| {
                                                        j.residual_status = post_status;
                                                        j.audit_revision += 1;
                                                        j.last_residual_audit = Some(post_audit);
                                                    })
                                                    .await?;
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
                                eprintln!("⚠ Failed to persist Failed state: {}", je);
                            }
                            return Err(e);
                        }
                    }
                }
                TeardownAction::ApplySet {
                    config,
                    no_cache,
                    dry_run,
                } => {
                    let config_content = std::fs::read_to_string(&config)
                        .with_context(|| format!("Failed to read config: {}", config))?;
                    let parsed: ApplySetConfig = serde_json::from_str(&config_content)
                        .with_context(|| format!("Invalid config: {}", config))?;
                    let defaults = parsed.defaults;
                    let entries = parsed.operators;

                    if entries.is_empty() {
                        bail!("Config has no operators");
                    }
                    for (i, entry) in entries.iter().enumerate() {
                        if entry.name.is_empty() {
                            bail!("Operator entry {} has empty name", i);
                        }
                    }

                    eprintln!(
                        "📋 Apply-set: {} operator(s) from {}",
                        entries.len(),
                        config
                    );
                    for (i, entry) in entries.iter().enumerate() {
                        eprintln!("  {}: {}", i + 1, entry.name);
                    }
                    eprintln!();
                    if no_cache {
                        eprintln!(
                            "🔄 API discovery: refresh once, then reuse within this apply-set\n"
                        );
                    }

                    let exe = std::env::current_exe()
                        .context("Cannot determine current executable path")?;

                    let mut results: Vec<(String, i32)> = Vec::new();

                    let entry_count = entries.len();
                    for (i, entry) in entries.iter().enumerate() {
                        let op_name = &entry.name;
                        let options = entry.effective_options(&defaults);
                        eprintln!(
                            "\n{}\n  [{}/{}] {} {}\n{}",
                            "=".repeat(60),
                            i + 1,
                            entry_count,
                            if dry_run { "DRY-RUN" } else { "TEARDOWN" },
                            op_name,
                            "=".repeat(60),
                        );

                        let mut cmd = std::process::Command::new(&exe);
                        cmd.arg("teardown").arg("apply").arg(op_name);

                        if apply_set_child_bypasses_cache(no_cache, i) {
                            cmd.arg("--no-cache");
                        }
                        if no_cache {
                            cmd.env(APPLY_SET_REUSE_CACHE_ENV, "1");
                        }
                        if dry_run {
                            cmd.arg("--dry-run");
                        }
                        if options.force {
                            cmd.arg("--force");
                        }
                        if options.non_interactive {
                            cmd.arg("--non-interactive");
                        }
                        for approval in options.approve_delete {
                            cmd.arg("--approve-delete").arg(approval);
                        }
                        for p in options.preserve {
                            cmd.arg("--preserve").arg(p);
                        }

                        // Pipe "y" to stdin for confirmation prompt
                        cmd.stdin(std::process::Stdio::piped());
                        cmd.stdout(std::process::Stdio::inherit());
                        cmd.stderr(std::process::Stdio::inherit());

                        // Forward KUBECONFIG
                        if let Ok(kc) = std::env::var("KUBECONFIG") {
                            cmd.env("KUBECONFIG", kc);
                        }

                        let mut child = cmd
                            .spawn()
                            .with_context(|| format!("Failed to spawn teardown for {}", op_name))?;

                        // Write "y\n" to stdin for confirmation
                        if let Some(mut stdin) = child.stdin.take() {
                            use std::io::Write;
                            let _ = stdin.write_all(b"y\n");
                        }

                        let status = child.wait().with_context(|| {
                            format!("Failed to wait for teardown of {}", op_name)
                        })?;

                        let exit_code = status.code().unwrap_or(1);
                        results.push((op_name.to_string(), exit_code));

                        if exit_code != 0 {
                            eprintln!(
                                "\n⛔ {} failed (exit {}). Stopping apply-set.",
                                op_name, exit_code
                            );
                            break;
                        }
                        eprintln!("  ✅ {} completed", op_name);
                    }

                    // Summary
                    eprintln!("\n📊 Apply-set results:");
                    let mut any_failed = false;
                    for (name, code) in &results {
                        let status = if *code == 0 { "✅" } else { "⛔" };
                        eprintln!("  {} {} (exit {})", status, name, code);
                        if *code != 0 {
                            any_failed = true;
                        }
                    }
                    let not_run = entry_count - results.len();
                    if not_run > 0 {
                        eprintln!("  ⏭ {} operator(s) not run (stopped on failure)", not_run);
                    }

                    if any_failed {
                        std::process::exit(1);
                    }
                }
                TeardownAction::Runs => {
                    let cluster_id = journal::fetch_cluster_identity(&client).await?;
                    let runs = journal::list_runs(&cluster_id)?;
                    if runs.is_empty() {
                        eprintln!("No teardown runs found for this cluster.");
                    } else {
                        eprintln!(
                            "Teardown runs for cluster {}:\n",
                            cluster_id.kube_system_uid
                        );
                        for run in &runs {
                            eprintln!(
                                "  {} {} {:?} ({})",
                                run.run_id, run.operator.csv_name, run.state, run.created_at,
                            );
                        }
                    }
                }
                TeardownAction::Journal {
                    operator,
                    run,
                    no_audit,
                } => {
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
                                self, OperatorGenerationState, print_residual_audit,
                            };

                            print_run_journal(&j);

                            if no_audit {
                                eprintln!("\n(audit skipped via --no-audit)");
                            } else {
                                let gen_state = audit::check_operator_generation(
                                    &client,
                                    &j.operator,
                                    &j.audit_context.csv_baseline,
                                )
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
                                        eprintln!(
                                            "\n⚠ Original operator generation is still active."
                                        );
                                        eprintln!(
                                            "  Resume normal teardown instead of residual cleanup."
                                        );
                                    }
                                    OperatorGenerationState::Reappeared => {
                                        eprintln!(
                                            "\n⚠ A newer installation of {} exists.",
                                            j.operator.csv_name
                                        );
                                        eprintln!("  This teardown session is historical.");
                                        eprintln!(
                                            "  Live residual attribution is unavailable because"
                                        );
                                        eprintln!(
                                            "  old and new generation resources cannot be distinguished safely."
                                        );
                                        if let Some(ref last_audit) = j.last_residual_audit {
                                            eprintln!("\n  Last reliable residual audit:");
                                            print_residual_audit(last_audit, &j);
                                        }
                                    }
                                    OperatorGenerationState::Unknown(reason) => {
                                        eprintln!(
                                            "\n⚠ Cannot verify operator generation: {}",
                                            reason
                                        );
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
        Command::Inspect {
            operator: operator_query,
            output,
            no_cache,
            cross_namespace,
            verbose,
            strict,
        } => {
            let t0 = Instant::now();
            eprintln!("🔍 Discovering API resources...");
            let (kind_map, gvr_map, gk_map, _) =
                build_kind_lookup_cached(&client, &config, no_cache).await?;
            eprintln!("   Discovery: {:.1}s", t0.elapsed().as_secs_f64());

            eprint!("🔍 Discovering operators...");
            let all_operators = discover_operators(&client, &kind_map).await?;
            eprintln!(" found {} operators", all_operators.len());

            let target_indices = resolve_operator_targets(&[operator_query], &all_operators)?;
            let target_op = &all_operators[target_indices[0]];

            let inspection = inspect_operator_with_options(
                &client,
                target_op,
                &kind_map,
                &gvr_map,
                &gk_map,
                cross_namespace,
            )
            .await?;

            print_inspection_top(&inspection, &output, verbose);
            if strict && inspection.scan_warning_count > 0 {
                std::process::exit(2);
            }
            return Ok(());
        }
        Command::Trace {
            resource,
            online,
            depth,
            scope,
        } => {
            let cross_namespace = matches!(scope, Scope::Related);
            let verbose = online.verbose;
            let strict = online.strict;
            let output = online.output;
            let no_cache = online.refresh_discovery;
            let namespace = online
                .namespace
                .unwrap_or_else(|| config.default_namespace.clone());
            let (kind_input, name) = if let Some((k, n)) = resource.split_once('/') {
                (k.to_string(), n.to_string())
            } else {
                bail!("Resource must be in kind/name format (e.g. datasciencecluster/default)");
            };

            let t0 = Instant::now();
            eprintln!("🔍 Discovering API resources...");
            let (kind_map, gvr_map, gk_map_trace, _) =
                build_kind_lookup_cached(&client, &config, no_cache).await?;
            eprintln!("   Discovery: {:.1}s", t0.elapsed().as_secs_f64());

            let (kind, target_group) = resolve_kind_with_group(&kind_input, &kind_map, &gvr_map)?;
            let kind_info = if !target_group.is_empty() {
                gk_map_trace.get(&(target_group.clone(), kind.clone()))
            } else {
                kind_map.get(&kind)
            }
            .ok_or_else(|| {
                if !target_group.is_empty() {
                    anyhow::anyhow!(
                        "Kind {}/{} not found in discovery (group may be incorrect)",
                        target_group,
                        kind
                    )
                } else {
                    anyhow::anyhow!("Kind {} not found in discovery", kind)
                }
            })?;

            let (mut index, mut scan_warnings) = if kind_info.namespaced {
                scan_namespace(&client, &namespace, &kind_map, false, true, false).await?
            } else {
                // For cluster-scoped targets, scan the namespace for children
                // but also fetch the target itself
                let (idx, warnings) =
                    scan_namespace(&client, &namespace, &kind_map, false, true, false).await?;
                (idx, warnings)
            };
            // For cluster-scoped targets, fetch the target via exact GET and insert
            if !kind_info.namespaced {
                eprint!("🔍 Fetching cluster-scoped target...");
                let gvk = ::kube::core::GroupVersion::gv(&kind_info.group, &kind_info.version)
                    .with_kind(&kind);
                let ar = ::kube::api::ApiResource::from_gvk_with_plural(&gvk, &kind_info.plural);
                let api: ::kube::Api<::kube::api::DynamicObject> =
                    ::kube::Api::all_with(client.clone(), &ar);
                match crate::kube::scanner::get_with_retry(
                    &api,
                    &name,
                    &kind_info.group,
                    &kind_info.version,
                    &kind_info.plural,
                )
                .await
                {
                    Ok(obj) => {
                        let uid = obj.metadata.uid.clone().unwrap_or_default();
                        let labels = obj
                            .metadata
                            .labels
                            .clone()
                            .unwrap_or_default()
                            .into_iter()
                            .collect();
                        let annotations = obj
                            .metadata
                            .annotations
                            .clone()
                            .unwrap_or_default()
                            .into_iter()
                            .collect();
                        let info = crate::kube::resource::ResourceInfo {
                            group: kind_info.group.clone(),
                            kind: kind.clone(),
                            name: name.clone(),
                            namespace: None,
                            uid,
                            owner_refs: vec![],
                            labels,
                            annotations,
                            pod_template: None,
                        };
                        index.insert(info);
                        eprintln!(" done");
                    }
                    Err(w) => {
                        scan_warnings.push(w.clone());
                        bail!("Failed to fetch {}/{}: {}", kind, name, w);
                    }
                }
            }

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
                        &mut index,
                        uid,
                        &client,
                        &namespace,
                        &kind_map,
                        &gk_map_trace,
                        false,
                    )
                    .await;
                    scan_warnings.extend(parent_warnings);
                }
                eprintln!(" done");
            }

            // Determine managing operator via who-manages (for same-operator CRD + cross-ns)
            let mut confirmed_csv: Option<String> = None;
            eprint!("🔍 Tracing ownership...");
            let wm_result = who_manages(&WhoManagesInput {
                client: &client,
                kind: &kind,
                group: &target_group,
                name: &name,
                namespace: &namespace,
                kind_map: &kind_map,
                gk_map: &gk_map_trace,
            })
            .await;
            match wm_result {
                Ok(wm) => {
                    confirmed_csv = wm
                        .chain
                        .iter()
                        .find(|s| s.kind == "ClusterServiceVersion")
                        .map(|s| s.name.clone());
                    scan_warnings.extend(wm.scan_failures);
                    eprintln!(" {}", confirmed_csv.as_deref().unwrap_or("unattributed"));
                }
                Err(e) => {
                    eprintln!(" failed: {}", e);
                    if let Some(w) = e.scan_failure {
                        scan_warnings.push(w);
                    } else {
                        scan_warnings.push(crate::kube::resource::ScanWarning::Other {
                            gvr: format!("{}/{}", kind, name),
                            message: format!("who-manages failed: {}", e.message),
                        });
                    }
                }
            }

            // Cross-namespace scan using confirmed operator
            if cross_namespace && let Some(csv_name) = &confirmed_csv {
                let operators = discover_operators(&client, &kind_map).await?;
                let csv_query = csv_name.to_string();
                if let Ok(indices) = resolve_operator_targets(&[csv_query], &operators)
                    && let Some(&idx) = indices.first()
                {
                    let target_op = &operators[idx];
                    let scope_result = discover_operator_namespaces(
                        &client,
                        target_op,
                        &kind_map,
                        &gvr_map,
                        &gk_map_trace,
                    )
                    .await?;
                    let is_tty = std::io::IsTerminal::is_terminal(&std::io::stderr());
                    for msg in &scope_result.info_messages {
                        if is_tty {
                            eprintln!("  \x1b[33m⚠ {}\x1b[0m", msg);
                        } else {
                            eprintln!("  ⚠ {}", msg);
                        }
                    }
                    scan_warnings.extend(scope_result.scan_failures);
                    let ns_scan = scan_candidate_namespaces(
                        &client,
                        &scope_result.candidates,
                        &kind_map,
                        Some(&namespace),
                    )
                    .await;
                    for w in &ns_scan.namespace_warnings {
                        scan_warnings.push(crate::kube::resource::ScanWarning::Other {
                            gvr: "cross-namespace".to_string(),
                            message: w.clone(),
                        });
                    }
                    scan_warnings.extend(ns_scan.scan_warnings);
                    index.merge(ns_scan.index);
                }
            }

            let mut result = trace_resource(
                &client,
                &kind,
                &name,
                &namespace,
                &target_group,
                &index,
                &kind_map,
                &gvr_map,
                &gk_map_trace,
                depth,
                confirmed_csv.as_deref(),
            )
            .await?;

            // Merge trace-internal typed warnings into scan_warnings for strict + display
            scan_warnings.extend(std::mem::take(&mut result.scan_failures));
            // Put unified warnings back for JSON output
            result.scan_failures = scan_warnings.clone();

            format_scan_warnings(&scan_warnings, verbose);
            let scope_str = if cross_namespace {
                "related"
            } else {
                "namespace"
            };
            print_trace(&result, &output, scope_str);

            // strict: exit 2 only for actual scan failures (not scope info messages)
            let has_scan_failures = scan_warnings.iter().any(|w| {
                !matches!(
                    w,
                    crate::kube::resource::ScanWarning::Other { message, .. }
                        if message.starts_with("AllNamespaces operator")
                )
            });
            if strict && has_scan_failures {
                std::process::exit(2);
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
        Command::WhoManages {
            resource,
            namespace,
            output,
            no_cache,
        } => {
            let namespace = namespace.unwrap_or_else(|| config.default_namespace.clone());
            let t0 = Instant::now();
            eprintln!("🔍 Discovering API resources...");
            let (kind_map, gvr_map, gk_map_wm, _) =
                build_kind_lookup_cached(&client, &config, no_cache).await?;
            eprintln!("   Discovery: {:.1}s", t0.elapsed().as_secs_f64());

            let (kind_input, name) = if let Some((k, n)) = resource.split_once('/') {
                (k.to_string(), n.to_string())
            } else {
                bail!("Resource must be in kind/name format (e.g. pod/my-pod)");
            };
            let (kind, target_group) = resolve_kind_with_group(&kind_input, &kind_map, &gvr_map)?;

            eprint!("🔍 Tracing ownership...");
            let result = match who_manages(&WhoManagesInput {
                client: &client,
                kind: &kind,
                group: &target_group,
                name: &name,
                namespace: &namespace,
                kind_map: &kind_map,
                gk_map: &gk_map_wm,
            })
            .await
            {
                Ok(r) => r,
                Err(e) => {
                    eprintln!(" failed\n");
                    bail!("{}", e.message);
                }
            };
            eprintln!(" done\n");

            print_who_manages(&result, &output);
            return Ok(());
        }
        Command::Diff { .. } => unreachable!("handled before client init"),

        // ── Tree subcommand ──
        Command::Tree {
            resource,
            online,
            direction,
            depth,
            no_refs,
            include_events,
            show,
        } => {
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

            let t0 = Instant::now();
            eprintln!("🔍 Discovering API resources...");
            let (kind_map, gvr_map, gk_map, _) =
                build_kind_lookup_cached(&client, &config, online.refresh_discovery).await?;
            eprintln!("   Discovery: {:.1}s", t0.elapsed().as_secs_f64());

            let (kind, target_group) = resolve_kind_with_group(&kind_input, &kind_map, &gvr_map)?;

            // Direction::Parents — fast path, no namespace scan
            if matches!(direction, Direction::Parents) {
                let chain = find_parents_only(
                    &client,
                    &target_group,
                    &kind,
                    &name,
                    &namespace,
                    &kind_map,
                    show_spec,
                    !no_refs,
                )
                .await?;
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
                    OutputFormat::Json => {
                        print_chain_json(&chain, &namespace, tree_opts.show_annotations, show_spec)
                    }
                }
                return Ok(());
            }

            // Full scan path
            let (mut index, mut scan_warnings) = scan_namespace(
                &client,
                &namespace,
                &kind_map,
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
                &client,
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
                let pods = get_service_selected_pods(&client, &name, &namespace, &kind_map).await;
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
                        let warning_strs: Vec<String> =
                            scan_warnings.iter().map(|w| format!("{}", w)).collect();
                        let mut output = serde_json::json!({
                            "namespace": namespace,
                            "target": target,
                            "scope": "namespace",
                            "tree": tree_to_json(&t, tree_opts.show_annotations, show_spec),
                            "warnings": warning_strs,
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
            return Ok(());
        }

        // ── Map subcommand ──
        Command::Map {
            online,
            all_namespaces,
            namespace_selector,
            exclude_namespace,
            exclude_system_namespaces,
            no_refs,
            include_events,
            show,
            depth,
            root_kind,
            root_label,
        } => {
            let tree_opts = show_fields_to_tree_opts(&show);
            let show_spec = show.contains(&ShowField::PodResources);
            let show_annotations = show.contains(&ShowField::Annotations);

            // Convert root_kind/root_label to MapFilter
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
                build_kind_lookup_cached(&client, &config, online.refresh_discovery).await?;
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
                    &client,
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
                &client,
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
                        &mut index, uid, &client, &namespace, &kind_map, &gk_map, show_spec,
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
                        eprintln!(
                            "\n📦 Namespace: {} ({} trees, {} resources)\n",
                            namespace,
                            trees.len(),
                            index.by_uid.len()
                        );
                    } else {
                        eprintln!(
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
                    let warning_strs: Vec<String> =
                        scan_warnings.iter().map(|w| format!("{}", w)).collect();
                    let mut output = serde_json::json!({
                        "namespace": namespace,
                        "scope": "namespace",
                        "totalResources": index.by_uid.len(),
                        "matchedTrees": trees.len(),
                        "trees": trees.iter().map(|t| tree_to_json(t, show_annotations, show_spec)).collect::<Vec<_>>(),
                        "warnings": warning_strs,
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
            return Ok(());
        }

        // ── Network subcommand ──
        Command::Network { resource, online } => {
            let namespace = online
                .namespace
                .unwrap_or_else(|| config.default_namespace.clone());

            let (kind_input, name) = if let Some((k, n)) = resource.split_once('/') {
                (k.to_string(), n.to_string())
            } else {
                bail!("Resource must be in kind/name format (e.g. deployment/nginx)");
            };

            let t0 = Instant::now();
            eprintln!("🔍 Discovering API resources...");
            let (kind_map, gvr_map, gk_map, _) =
                build_kind_lookup_cached(&client, &config, online.refresh_discovery).await?;
            eprintln!("   Discovery: {:.1}s", t0.elapsed().as_secs_f64());

            let (kind, target_group) = resolve_kind_with_group(&kind_input, &kind_map, &gvr_map)?;

            const NETWORK_SUPPORTED_KINDS: &[&str] = &[
                "Pod",
                "Deployment",
                "ReplicaSet",
                "StatefulSet",
                "DaemonSet",
                "Service",
            ];
            if !NETWORK_SUPPORTED_KINDS.iter().any(|k| *k == kind) {
                bail!(
                    "network subcommand requires Pod, Deployment, ReplicaSet, StatefulSet, DaemonSet, or Service, got {}",
                    kind
                );
            }

            let (index, mut scan_warnings) =
                scan_namespace(&client, &namespace, &kind_map, false, true, false).await?;

            format_scan_warnings(&scan_warnings, online.verbose);

            let inventory = build_network_inventory(&client, &namespace, &kind_map, &gk_map).await;

            let group_for_lookup = Some(target_group.as_str()).filter(|g| !g.is_empty());

            // For Service target: find the service directly in inventory
            let (all_paths, postures): (Vec<(String, _)>, Vec<_>) = if kind == "Service" {
                let svc_paths: Vec<_> = inventory
                    .services
                    .iter()
                    .filter(|s| s.name == name)
                    .cloned()
                    .collect();
                if svc_paths.is_empty() {
                    bail!("Service/{} not found in namespace '{}'", name, namespace);
                }
                let mut actual_pod_labels = Vec::new();
                for svc in &svc_paths {
                    if svc.has_selector {
                        for ep_slice in &inventory.endpoint_slices {
                            if ep_slice.service_name.as_deref() == Some(&name) {
                                for ep in &ep_slice.endpoints {
                                    if let Some(tr) = &ep.target_ref
                                        && let Some(pod_name) = &tr.name
                                        && tr.kind.as_deref() == Some("Pod")
                                        && let Some(uid) = index.lookup_by_kind_name(
                                            Some(""),
                                            "Pod",
                                            pod_name,
                                            Some(&namespace),
                                        )
                                        && let Some(info) = index.by_uid.get(uid)
                                    {
                                        actual_pod_labels.push((
                                            pod_name.clone(),
                                            uid.clone(),
                                            info.labels.clone(),
                                        ));
                                    }
                                }
                            }
                        }
                    }
                }
                let actual_paths = find_network_paths(&actual_pod_labels, &namespace, &inventory);
                let actual_postures = evaluate_network_postures(
                    &actual_pod_labels,
                    &inventory.network_policies,
                    &inventory.np_availability,
                );
                let result_paths: Vec<_> = actual_paths
                    .into_iter()
                    .map(|p| (String::new(), p))
                    .collect();
                (result_paths, actual_postures)
            } else {
                // For workload targets: find target uid and descendant pods
                let target_uid = match index.lookup_by_kind_name(
                    group_for_lookup,
                    &kind,
                    &name,
                    Some(&namespace),
                ) {
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

                let pod_labels_list = if kind == "Pod" {
                    vec![(
                        name.clone(),
                        target_uid.clone(),
                        index
                            .by_uid
                            .get(&target_uid)
                            .map(|info| info.labels.clone())
                            .unwrap_or_default(),
                    )]
                } else {
                    find_descendant_pods(&target_uid, &index)
                };

                let paths = find_network_paths(&pod_labels_list, &namespace, &inventory);
                let postures = evaluate_network_postures(
                    &pod_labels_list,
                    &inventory.network_policies,
                    &inventory.np_availability,
                );
                let result_paths: Vec<_> = paths.into_iter().map(|p| (String::new(), p)).collect();
                (result_paths, postures)
            };

            // Merge inventory warnings
            let existing_keys: std::collections::HashSet<String> =
                scan_warnings.iter().map(|w| format!("{}", w)).collect();
            for w in &inventory.warnings {
                if !existing_keys.contains(&format!("{}", w)) {
                    scan_warnings.push(w.clone());
                }
            }

            match online.output {
                OutputFormat::Json => {
                    let json_paths = network_paths_to_json(&all_paths);
                    let json_postures = network_postures_to_json(&postures);
                    let warning_strs: Vec<String> =
                        scan_warnings.iter().map(|w| format!("{}", w)).collect();
                    let output = serde_json::json!({
                        "namespace": namespace,
                        "target": format!("{}/{}", kind, name),
                        "scope": "namespace",
                        "networkPaths": json_paths,
                        "networkPolicyPostures": json_postures,
                        "warnings": warning_strs,
                        "scanWarningCount": scan_warnings.len(),
                    });
                    println!(
                        "{}",
                        serde_json::to_string_pretty(&output).unwrap_or_default()
                    );
                }
                OutputFormat::Table => {
                    let mut table = comfy_table::Table::new();
                    table.set_header(vec![
                        "Service",
                        "Type",
                        "ClusterIP",
                        "Ports",
                        "Endpoints",
                        "Ingress/Route",
                    ]);
                    let mut seen_svcs = std::collections::HashSet::new();
                    for (_, path) in &all_paths {
                        if !seen_svcs.insert(path.service.name.clone()) {
                            continue;
                        }
                        let svc = &path.service;
                        let ports_str: String = svc
                            .ports
                            .iter()
                            .map(|sp| {
                                if let Some(np) = sp.node_port {
                                    format!("{}/{} (np:{})", sp.port, sp.protocol, np)
                                } else {
                                    format!("{}/{}", sp.port, sp.protocol)
                                }
                            })
                            .collect::<Vec<_>>()
                            .join(", ");
                        let es = &path.endpoint_summary;
                        let eps_str =
                            format!("{} ready, {} not-ready", es.effective_ready, es.not_ready);
                        let ing_str: String = path
                            .ingresses
                            .iter()
                            .map(|i| format!("{}/{}", i.kind, i.name))
                            .collect::<Vec<_>>()
                            .join(", ");
                        table.add_row(vec![
                            format!("Service/{}", svc.name),
                            svc.svc_type.clone(),
                            svc.cluster_ip.clone(),
                            ports_str,
                            eps_str,
                            ing_str,
                        ]);
                    }
                    println!("{table}");

                    if !postures.is_empty() {
                        println!();
                        let mut np_table = comfy_table::Table::new();
                        np_table.set_header(vec!["Pod", "Ingress", "Egress", "Policies"]);
                        for p in &postures {
                            let policies: String = p
                                .applicable_policies
                                .iter()
                                .map(|ap| ap.name.clone())
                                .collect::<Vec<_>>()
                                .join(", ");
                            np_table.add_row(vec![
                                format!("Pod/{}", p.pod_name),
                                p.ingress_isolation.clone(),
                                p.egress_isolation.clone(),
                                policies,
                            ]);
                        }
                        println!("{np_table}");
                    }
                }
                OutputFormat::Tree => {
                    print_network_tree(&kind, &name, &all_paths, &postures);
                }
            }

            format_scan_warnings(&scan_warnings, online.verbose);

            if online.strict && !scan_warnings.is_empty() {
                std::process::exit(2);
            }
            return Ok(());
        }
    }
}

fn selector_to_json(sel: &crate::analyzers::selector::PodSelector) -> serde_json::Value {
    let mut obj = serde_json::json!({});
    if !sel.match_labels.is_empty() {
        obj["matchLabels"] = serde_json::json!(sel.match_labels);
    }
    if !sel.match_expressions.is_empty() {
        let exprs: Vec<_> = sel
            .match_expressions
            .iter()
            .map(|e| {
                serde_json::json!({
                    "key": e.key,
                    "operator": e.operator,
                    "values": e.values,
                })
            })
            .collect();
        obj["matchExpressions"] = serde_json::json!(exprs);
    }
    obj
}

fn format_selector(sel: &crate::analyzers::selector::PodSelector) -> String {
    let mut parts = Vec::new();
    for (k, v) in &sel.match_labels {
        parts.push(format!("{}={}", k, v));
    }
    for expr in &sel.match_expressions {
        match expr.operator.as_str() {
            "In" => parts.push(format!("{} in ({})", expr.key, expr.values.join(","))),
            "NotIn" => parts.push(format!("{} notin ({})", expr.key, expr.values.join(","))),
            "Exists" => parts.push(expr.key.clone()),
            "DoesNotExist" => parts.push(format!("!{}", expr.key)),
            _ => parts.push(format!("{}?{}", expr.key, expr.operator)),
        }
    }
    if parts.is_empty() {
        "*".to_string()
    } else {
        parts.join(",")
    }
}

fn format_policy_peers(peers: &[crate::analyzers::selector::NetworkPolicyPeer]) -> String {
    if peers.is_empty() {
        return String::new();
    }
    peers
        .iter()
        .map(|peer| {
            let mut parts = Vec::new();
            if let Some(ns) = &peer.namespace_selector {
                parts.push(format!("namespaceSelector{{{}}}", format_selector(ns)));
            }
            if let Some(ps) = &peer.pod_selector {
                parts.push(format!("podSelector{{{}}}", format_selector(ps)));
            }
            if let Some(ib) = &peer.ip_block {
                let mut s = format!("ipBlock:{}", ib.cidr);
                if !ib.except.is_empty() {
                    s.push_str(&format!(" except [{}]", ib.except.join(",")));
                }
                parts.push(s);
            }
            parts.join(" ")
        })
        .collect::<Vec<_>>()
        .join("; ")
}

fn format_policy_ports(ports: &[crate::analyzers::selector::NetworkPolicyPort]) -> String {
    if ports.is_empty() {
        return String::new();
    }
    ports
        .iter()
        .map(|p| {
            let proto = p.protocol.as_deref().unwrap_or("TCP");
            let port = match &p.port {
                Some(crate::analyzers::selector::IntOrString::Int(n)) => n.to_string(),
                Some(crate::analyzers::selector::IntOrString::String(s)) => s.clone(),
                None => "*".to_string(),
            };
            if let Some(ep) = p.end_port {
                format!("{}/{}-{}", proto, port, ep)
            } else {
                format!("{}/{}", proto, port)
            }
        })
        .collect::<Vec<_>>()
        .join(", ")
}

fn network_paths_to_json(
    paths: &[(String, crate::analyzers::selector::NetworkPath)],
) -> Vec<serde_json::Value> {
    let mut seen_svcs = std::collections::HashSet::new();
    paths
        .iter()
        .filter(|(_, p)| seen_svcs.insert(p.service.name.clone()))
        .map(|(_, p)| {
            let ports: Vec<_> = p
                .service
                .ports
                .iter()
                .map(|sp| {
                    let mut port_obj = serde_json::json!({
                        "port": sp.port,
                        "targetPort": sp.target_port,
                        "protocol": sp.protocol,
                    });
                    if let Some(np) = sp.node_port {
                        port_obj["nodePort"] = serde_json::json!(np);
                    }
                    port_obj
                })
                .collect();
            let ingresses: Vec<_> = p
                .ingresses
                .iter()
                .map(|i| {
                    let mut obj = serde_json::json!({"kind": i.kind, "name": i.name});
                    if let Some(h) = &i.host {
                        obj["host"] = serde_json::json!(h);
                    }
                    if let Some(pa) = &i.path {
                        obj["path"] = serde_json::json!(pa);
                    }
                    if let Some(t) = &i.tls {
                        obj["tls"] = serde_json::json!(t);
                    }
                    obj
                })
                .collect();
            let endpoint_slices_json: Vec<_> = p
                .endpoint_slices
                .iter()
                .map(|es| {
                    let eps: Vec<_> = es
                        .endpoints
                        .iter()
                        .map(|ep| {
                            let mut obj = serde_json::json!({
                                "addresses": ep.addresses,
                                "ready": ep.conditions_ready,
                                "serving": ep.conditions_serving,
                                "terminating": ep.conditions_terminating,
                            });
                            if let Some(h) = &ep.hostname {
                                obj["hostname"] = serde_json::json!(h);
                            }
                            if let Some(n) = &ep.node_name {
                                obj["nodeName"] = serde_json::json!(n);
                            }
                            if let Some(z) = &ep.zone {
                                obj["zone"] = serde_json::json!(z);
                            }
                            if let Some(tr) = &ep.target_ref {
                                let mut tr_obj = serde_json::Map::new();
                                if let Some(v) = &tr.api_version {
                                    tr_obj.insert("apiVersion".into(), serde_json::json!(v));
                                }
                                if let Some(v) = &tr.kind {
                                    tr_obj.insert("kind".into(), serde_json::json!(v));
                                }
                                if let Some(v) = &tr.name {
                                    tr_obj.insert("name".into(), serde_json::json!(v));
                                }
                                if let Some(v) = &tr.namespace {
                                    tr_obj.insert("namespace".into(), serde_json::json!(v));
                                }
                                if let Some(v) = &tr.uid {
                                    tr_obj.insert("uid".into(), serde_json::json!(v));
                                }
                                obj["targetRef"] = serde_json::Value::Object(tr_obj);
                            }
                            if let Some(hints) = &ep.hints {
                                obj["hints"] = serde_json::json!(hints);
                            }
                            obj
                        })
                        .collect();
                    let es_ports: Vec<_> = es
                        .ports
                        .iter()
                        .map(|port| {
                            let mut obj =
                                serde_json::json!({"port": port.port, "protocol": port.protocol});
                            if let Some(n) = &port.name {
                                obj["name"] = serde_json::json!(n);
                            }
                            if let Some(ap) = &port.app_protocol {
                                obj["appProtocol"] = serde_json::json!(ap);
                            }
                            obj
                        })
                        .collect();
                    serde_json::json!({
                        "name": es.name,
                        "addressType": es.address_type,
                        "ports": es_ports,
                        "endpoints": eps,
                    })
                })
                .collect();
            let es = &p.endpoint_summary;
            let svc = &p.service;
            let mut config = serde_json::json!({
                "type": svc.svc_type,
                "clusterIP": svc.cluster_ip,
                "ports": ports,
                "selector": svc.selector,
                "hasSelector": svc.has_selector,
            });
            if !svc.external_ips.is_empty() {
                config["externalIPs"] = serde_json::json!(svc.external_ips);
            }
            if !svc.ip_families.is_empty() {
                config["ipFamilies"] = serde_json::json!(svc.ip_families);
            }
            if let Some(v) = &svc.external_traffic_policy {
                config["externalTrafficPolicy"] = serde_json::json!(v);
            }
            if let Some(v) = &svc.internal_traffic_policy {
                config["internalTrafficPolicy"] = serde_json::json!(v);
            }
            if let Some(v) = &svc.ip_family_policy {
                config["ipFamilyPolicy"] = serde_json::json!(v);
            }
            if let Some(v) = svc.health_check_node_port {
                config["healthCheckNodePort"] = serde_json::json!(v);
            }
            if let Some(v) = &svc.load_balancer_class {
                config["loadBalancerClass"] = serde_json::json!(v);
            }
            if let Some(v) = svc.allocate_lb_node_ports {
                config["allocateLoadBalancerNodePorts"] = serde_json::json!(v);
            }
            let mut status = serde_json::json!({});
            if !svc.lb_ingress.is_empty() {
                let lb: Vec<_> = svc
                    .lb_ingress
                    .iter()
                    .map(|lbi| {
                        let mut obj = serde_json::Map::new();
                        if let Some(ip) = &lbi.ip {
                            obj.insert("ip".into(), serde_json::json!(ip));
                        }
                        if let Some(h) = &lbi.hostname {
                            obj.insert("hostname".into(), serde_json::json!(h));
                        }
                        if let Some(m) = &lbi.ip_mode {
                            obj.insert("ipMode".into(), serde_json::json!(m));
                        }
                        serde_json::Value::Object(obj)
                    })
                    .collect();
                status["loadBalancerIngress"] = serde_json::json!(lb);
            }
            serde_json::json!({
                "service": {"name": svc.name, "config": config, "status": status},
                "ingresses": ingresses,
                "endpointSlices": endpoint_slices_json,
                "endpointSummary": {"ready": es.ready, "notReady": es.not_ready, "unknown": es.unknown, "effectiveReady": es.effective_ready, "serving": es.serving, "terminating": es.terminating},
                "selectorMatchedPods": p.selector_matched_pods,
                "targetRefMatchedPods": p.target_ref_matched_pods,
            })
        })
        .collect()
}

fn network_postures_to_json(
    postures: &[crate::analyzers::selector::PodNetworkPosture],
) -> Vec<serde_json::Value> {
    postures
        .iter()
        .map(|p| {
            let policies: Vec<_> = p
                .applicable_policies
                .iter()
                .map(|ap| {
                    let mk_rules = |rules: &[crate::analyzers::selector::NetworkPolicyRule]| {
                        rules
                            .iter()
                            .map(|r| {
                                serde_json::json!({
                                    "peers": r.peers.iter().map(|peer| {
                                        let mut obj = serde_json::Map::new();
                                        if let Some(ps) = &peer.pod_selector { obj.insert("podSelector".into(), selector_to_json(ps)); }
                                        if let Some(ns) = &peer.namespace_selector { obj.insert("namespaceSelector".into(), selector_to_json(ns)); }
                                        if let Some(ib) = &peer.ip_block { obj.insert("ipBlock".into(), serde_json::json!({"cidr": ib.cidr, "except": ib.except})); }
                                        serde_json::Value::Object(obj)
                                    }).collect::<Vec<_>>(),
                                    "ports": r.ports.iter().map(|port| {
                                        let mut obj = serde_json::Map::new();
                                        if let Some(proto) = &port.protocol { obj.insert("protocol".into(), serde_json::json!(proto)); }
                                        if let Some(p) = &port.port {
                                            match p {
                                                crate::analyzers::selector::IntOrString::Int(n) => { obj.insert("port".into(), serde_json::json!(n)); }
                                                crate::analyzers::selector::IntOrString::String(s) => { obj.insert("port".into(), serde_json::json!(s)); }
                                            }
                                        }
                                        if let Some(ep) = port.end_port { obj.insert("endPort".into(), serde_json::json!(ep)); }
                                        serde_json::Value::Object(obj)
                                    }).collect::<Vec<_>>(),
                                })
                            })
                            .collect::<Vec<_>>()
                    };
                    serde_json::json!({
                        "name": ap.name,
                        "podSelector": selector_to_json(&ap.pod_selector),
                        "policyTypes": ap.policy_types,
                        "isolatesIngress": ap.isolates_ingress,
                        "isolatesEgress": ap.isolates_egress,
                        "ingressRules": mk_rules(&ap.ingress_rules),
                        "egressRules": mk_rules(&ap.egress_rules),
                    })
                })
                .collect();
            serde_json::json!({
                "podName": p.pod_name,
                "podUid": p.pod_uid,
                "ingressIsolation": p.ingress_isolation,
                "egressIsolation": p.egress_isolation,
                "applicablePolicies": policies,
            })
        })
        .collect()
}

fn print_network_tree(
    kind: &str,
    name: &str,
    paths: &[(String, crate::analyzers::selector::NetworkPath)],
    postures: &[crate::analyzers::selector::PodNetworkPosture],
) {
    let stdout_tty = std::io::IsTerminal::is_terminal(&std::io::stdout());
    if paths.is_empty() {
        println!("No Services select Pods under {}/{}", kind, name);
        return;
    }
    println!("Network paths for {}/{}:\n", kind, name);
    let mut seen_svcs = std::collections::HashSet::new();
    for (_, path) in paths {
        if !seen_svcs.insert(path.service.name.clone()) {
            continue;
        }
        let svc = &path.service;
        if stdout_tty {
            println!("  \x1b[1mService/{}\x1b[0m", svc.name);
        } else {
            println!("  Service/{}", svc.name);
        }
        println!("    Type:      {}", svc.svc_type);
        println!("    ClusterIP: {}", svc.cluster_ip);
        for sp in &svc.ports {
            if let Some(np) = sp.node_port {
                println!(
                    "    Port:      {}/{} \u{2192} {} (nodePort: {})",
                    sp.port, sp.protocol, sp.target_port, np
                );
            } else {
                println!(
                    "    Port:      {}/{} \u{2192} {}",
                    sp.port, sp.protocol, sp.target_port
                );
            }
        }
        if !svc.external_ips.is_empty() {
            println!("    ExternalIPs: {}", svc.external_ips.join(", "));
        }
        if !svc.ip_families.is_empty() {
            println!("    IPFamilies: {}", svc.ip_families.join(", "));
        }
        let sel = svc
            .selector
            .iter()
            .map(|(k, v)| format!("{}={}", k, v))
            .collect::<Vec<_>>()
            .join(", ");
        println!("    Selector:  {}", sel);
        if let Some(v) = &svc.internal_traffic_policy {
            println!("    InternalTrafficPolicy: {}", v);
        }
        if let Some(v) = &svc.external_traffic_policy {
            println!("    ExternalTrafficPolicy: {}", v);
        }
        if let Some(v) = &svc.ip_family_policy {
            println!("    IPFamilyPolicy:        {}", v);
        }
        if let Some(v) = svc.health_check_node_port {
            println!("    HealthCheckNodePort:   {}", v);
        }
        if let Some(v) = &svc.load_balancer_class {
            println!("    LoadBalancerClass:     {}", v);
        }
        if let Some(v) = svc.allocate_lb_node_ports {
            println!("    AllocateLBNodePorts:   {}", v);
        }
        for lbi in &svc.lb_ingress {
            let mut parts = Vec::new();
            if let Some(ip) = &lbi.ip {
                parts.push(ip.clone());
            }
            if let Some(h) = &lbi.hostname {
                parts.push(h.clone());
            }
            let addr = if parts.is_empty() {
                "?".to_string()
            } else {
                parts.join(" / ")
            };
            let mode = lbi
                .ip_mode
                .as_deref()
                .map(|m| format!(" (ipMode: {})", m))
                .unwrap_or_default();
            println!("    LB Ingress: {}{}", addr, mode);
        }
        println!(
            "    SelectorPods:  {}",
            path.selector_matched_pods.join(", ")
        );
        if !path.target_ref_matched_pods.is_empty() {
            println!(
                "    TargetRefPods: {}",
                path.target_ref_matched_pods.join(", ")
            );
        }
        let es = &path.endpoint_summary;
        let unknown_note = if es.unknown > 0 {
            format!(" ({} unknown)", es.unknown)
        } else {
            String::new()
        };
        println!(
            "    Endpoints: {} ready{}, {} not-ready, {} terminating, {} serving",
            es.effective_ready, unknown_note, es.not_ready, es.terminating, es.serving
        );
        for es_info in &path.endpoint_slices {
            println!();
            if stdout_tty {
                println!(
                    "    \x1b[1mEndpointSlice/{}\x1b[0m ({})",
                    es_info.name, es_info.address_type
                );
            } else {
                println!(
                    "    EndpointSlice/{} ({})",
                    es_info.name, es_info.address_type
                );
            }
            for ep_port in &es_info.ports {
                let port_str = ep_port.port.map(|p| p.to_string()).unwrap_or("?".into());
                let name_str = ep_port.name.as_deref().unwrap_or("");
                let app_proto = ep_port
                    .app_protocol
                    .as_deref()
                    .map(|a| format!(" appProtocol={}", a))
                    .unwrap_or_default();
                if name_str.is_empty() {
                    println!("      Port: {}/{}{}", port_str, ep_port.protocol, app_proto);
                } else {
                    println!(
                        "      Port: {} {}/{}{}",
                        name_str, port_str, ep_port.protocol, app_proto
                    );
                }
            }
            for ep in &es_info.endpoints {
                let addrs = ep.addresses.join(", ");
                let ready_str = match ep.conditions_ready {
                    Some(true) => "ready",
                    Some(false) => "not-ready",
                    None => "unknown(ready)",
                };
                let serving_str = match ep.conditions_serving {
                    Some(true) => " serving",
                    Some(false) => " not-serving",
                    None => "",
                };
                let term_str = match ep.conditions_terminating {
                    Some(true) => " terminating",
                    _ => "",
                };
                let target = ep
                    .target_ref
                    .as_ref()
                    .map(|tr| {
                        let kind = tr.kind.as_deref().unwrap_or("?");
                        let name = tr.name.as_deref().unwrap_or("?");
                        format!(" \u{2192} {}/{}", kind, name)
                    })
                    .unwrap_or_default();
                let mut meta_parts = Vec::new();
                if let Some(h) = &ep.hostname {
                    meta_parts.push(format!("host={}", h));
                }
                if let Some(n) = &ep.node_name {
                    meta_parts.push(format!("node={}", n));
                }
                if let Some(z) = &ep.zone {
                    meta_parts.push(format!("zone={}", z));
                }
                let meta_str = if meta_parts.is_empty() {
                    String::new()
                } else {
                    format!(" {}", meta_parts.join(" "))
                };
                let hints_str = ep
                    .hints
                    .as_ref()
                    .map(|h| {
                        if h.is_empty() {
                            String::new()
                        } else {
                            format!(" zones={}", h.join(","))
                        }
                    })
                    .unwrap_or_default();
                println!(
                    "      {} [{}{}{}]{}{}{}",
                    addrs, ready_str, serving_str, term_str, target, meta_str, hints_str
                );
            }
        }
        for ing in &path.ingresses {
            println!();
            if stdout_tty {
                println!(
                    "    \x1b[1m{}/{}\x1b[0m \u{2192} Service/{}",
                    ing.kind, ing.name, svc.name
                );
            } else {
                println!(
                    "    {}/{} \u{2192} Service/{}",
                    ing.kind, ing.name, svc.name
                );
            }
            if let Some(host) = &ing.host {
                println!("      Host: {}", host);
            }
            if let Some(p) = &ing.path {
                println!("      Path: {}", p);
            }
            if let Some(tls) = &ing.tls {
                println!("      TLS:  {}", tls);
            }
        }
        println!();
    }
    if !postures.is_empty() {
        println!("Network Policy posture for {}/{}:\n", kind, name);
        for posture in postures {
            if stdout_tty {
                println!("  \x1b[1mPod/{}\x1b[0m", posture.pod_name);
            } else {
                println!("  Pod/{}", posture.pod_name);
            }
            println!("    Ingress: {}", posture.ingress_isolation);
            println!("    Egress:  {}", posture.egress_isolation);
            for ap in &posture.applicable_policies {
                if stdout_tty {
                    println!("    \x1b[1mNetworkPolicy/{}\x1b[0m", ap.name);
                } else {
                    println!("    NetworkPolicy/{}", ap.name);
                }
                println!("      Types: {}", ap.policy_types.join(", "));
                println!("      Selector: {}", format_selector(&ap.pod_selector));
                let mut effects = Vec::new();
                if ap.isolates_ingress {
                    effects.push("isolates ingress");
                }
                if ap.isolates_egress {
                    effects.push("isolates egress");
                }
                println!("      Effect: {}", effects.join("; "));
                for rule in &ap.ingress_rules {
                    let peers_str = format_policy_peers(&rule.peers);
                    let ports_str = format_policy_ports(&rule.ports);
                    print!("      Allows ingress:");
                    if !peers_str.is_empty() {
                        print!(" from: {}", peers_str);
                    }
                    if !ports_str.is_empty() {
                        print!(" ports: {}", ports_str);
                    }
                    if peers_str.is_empty() && ports_str.is_empty() {
                        print!(" (all)");
                    }
                    println!();
                }
                for rule in &ap.egress_rules {
                    let peers_str = format_policy_peers(&rule.peers);
                    let ports_str = format_policy_ports(&rule.ports);
                    print!("      Allows egress:");
                    if !peers_str.is_empty() {
                        print!(" to: {}", peers_str);
                    }
                    if !ports_str.is_empty() {
                        print!(" ports: {}", ports_str);
                    }
                    if peers_str.is_empty() && ports_str.is_empty() {
                        print!(" (all)");
                    }
                    println!();
                }
                if ap.isolates_ingress && ap.ingress_rules.is_empty() {
                    println!("      (no ingress allow rules \u{2192} deny all ingress)");
                }
                if ap.isolates_egress && ap.egress_rules.is_empty() {
                    println!("      (no egress allow rules \u{2192} deny all egress)");
                }
            }
        }
        println!();
    }
}

fn build_residual_evidence(
    rid: &crate::kube::resource::ResourceId,
    audit: &Option<crate::teardown::audit::ResidualAudit>,
) -> Vec<crate::teardown::plan::SavedEvidenceSignature> {
    let Some(audit) = audit else {
        return vec![];
    };
    let matched = audit
        .likely_operator_residual
        .iter()
        .chain(audit.unattributed.iter())
        .find(|r| {
            r.resource.group == rid.group
                && r.resource.kind == rid.kind
                && r.resource.name == rid.name
                && r.resource.namespace == rid.namespace
        });
    let Some(res) = matched else {
        return vec![];
    };
    let mut evidence = Vec::new();
    for (k, v) in &res.evidence.matching_labels {
        evidence.push(crate::teardown::plan::SavedEvidenceSignature::Label {
            key: k.clone(),
            value: v.clone(),
        });
    }
    for mgr in &res.evidence.matching_managers {
        evidence.push(
            crate::teardown::plan::SavedEvidenceSignature::ManagedFieldManager {
                manager: mgr.clone(),
            },
        );
    }
    if res.evidence.service_account_match {
        evidence.push(
            crate::teardown::plan::SavedEvidenceSignature::ServiceAccount {
                namespace: rid.namespace.clone().unwrap_or_default(),
                name: String::new(),
            },
        );
    }
    evidence
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
    _finalizer_recovery_approved: bool,
) -> Result<JournalStore> {
    if target_operators.len() > 1 {
        bail!(
            "Run journal currently supports single-operator teardown. \
             Use separate teardown commands for each operator."
        );
    }

    let cluster_id = journal::fetch_cluster_identity(client).await?;
    let run_id = journal::generate_run_id();

    let operator_snapshot = build_operator_identity_snapshot(client, target_operators)
        .await
        .context("Failed to build operator identity snapshot for journal")?;

    let first_op = target_operators[0];
    let mut audit_context = journal::build_audit_context(plan, target_operators, gk_map);

    // Capture CSV baseline: all CSVs in install namespace at plan time (name → uid).
    // Used by generation check to detect new CSVs not present before teardown.
    {
        use ::kube::api::{Api, ApiResource, DynamicObject, ListParams};
        use ::kube::core::GroupVersion;

        let csv_gvk =
            GroupVersion::gv("operators.coreos.com", "v1alpha1").with_kind("ClusterServiceVersion");
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
                        anyhow::anyhow!("CSV '{}' has no UID — cannot build baseline", name)
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
        finalizer_recovery_approved: true,
        finalizer_recoveries: Vec::new(),
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
        ObservedResourceIdentity, OperatorGenerationIdentity, OperatorIdentitySnapshot,
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
            std::slice::from_ref(&first_op.csv.name),
            "ClusterServiceVersion",
            "operators.coreos.com/v1alpha1",
            &first_op.install_namespace,
        )
        .await?;
        let obs = fresh
            .into_iter()
            .next()
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
                first_op.csv.name,
                discovery_uid,
                obs.uid
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

    let sub_observed: Vec<ObservedResourceIdentity> = if let Some(sub) = &first_op.subscription {
        let fresh = fetch_observed_identities(
            client,
            std::slice::from_ref(&sub.name),
            "Subscription",
            "operators.coreos.com/v1alpha1",
            sub.namespace
                .as_deref()
                .unwrap_or(&first_op.install_namespace),
        )
        .await?;
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
        if let Some(obs) = fresh.first()
            && obs.uid != discovery_uid
        {
            bail!(
                "Subscription {} UID changed between discovery ({}) and snapshot ({}) — \
                     operator may have been recreated. Re-run 'teardown plan'.",
                sub.name,
                discovery_uid,
                obs.uid
            );
        }
        // Verify spec.name matches expected package
        if let Some(ref expected_package) = first_op.package_name {
            let sub_gvk = ::kube::core::GroupVersion::gv("operators.coreos.com", "v1alpha1")
                .with_kind("Subscription");
            let sub_ar = ::kube::api::ApiResource::from_gvk_with_plural(&sub_gvk, "subscriptions");
            let sub_api: ::kube::api::Api<::kube::api::DynamicObject> =
                ::kube::api::Api::namespaced_with(
                    client.clone(),
                    sub.namespace
                        .as_deref()
                        .unwrap_or(&first_op.install_namespace),
                    &sub_ar,
                );
            match sub_api.get(&sub.name).await {
                Ok(live_sub) => {
                    let live_spec_name = live_sub
                        .data
                        .get("spec")
                        .and_then(|s| s.get("name"))
                        .and_then(|n| n.as_str())
                        .unwrap_or("");
                    if live_spec_name != expected_package.as_str() {
                        bail!(
                            "Subscription {} spec.name changed from '{}' to '{}' — \
                             semantic identity drift. Re-run 'teardown plan'.",
                            sub.name,
                            expected_package,
                            live_spec_name
                        );
                    }
                }
                Err(::kube::Error::Api(ref api_err)) if api_err.code == 404 => {
                    // Subscription already deleted (previous teardown or manual).
                    // This is safe — operator is frozen.
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
    use ::kube::api::{Api, ApiResource, DynamicObject};
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
                        kind,
                        name,
                        namespace
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
                    kind,
                    name,
                    namespace,
                    e
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
///
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

    let has_label = obj
        .metadata
        .labels
        .as_ref()
        .map(|labels| {
            audit_ctx.csv_names.iter().any(|csv| {
                let prefix = csv.split('.').next().unwrap_or(csv);
                !prefix.is_empty()
                    && labels
                        .keys()
                        .any(|k| k.starts_with(&format!("operators.coreos.com/{}", prefix)))
            })
        })
        .unwrap_or(false);

    let has_manager = obj
        .metadata
        .managed_fields
        .as_ref()
        .map(|mfs| {
            mfs.iter().any(|mf| {
                mf.manager.as_ref().is_some_and(|m| {
                    audit_ctx
                        .controller_deployment_names
                        .iter()
                        .any(|d| m.contains(d.as_str()))
                })
            })
        })
        .unwrap_or(false);

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
    revalidate_review_basis_inner(
        client,
        obj,
        resource,
        metadata,
        audit_ctx,
        operator_snapshot,
        None,
    )
    .await
}

pub async fn revalidate_review_basis_cached(
    client: &::kube::Client,
    obj: &::kube::api::DynamicObject,
    resource: &crate::kube::resource::ResourceId,
    metadata: &Option<crate::teardown::plan::ReviewMetadata>,
    audit_ctx: &crate::teardown::journal::AuditContext,
    operator_snapshot: &crate::teardown::plan::OperatorIdentitySnapshot,
    crd_items: &[::kube::api::DynamicObject],
) -> Result<(), String> {
    revalidate_review_basis_inner(
        client,
        obj,
        resource,
        metadata,
        audit_ctx,
        operator_snapshot,
        Some(crd_items),
    )
    .await
}

async fn revalidate_review_basis_inner(
    client: &::kube::Client,
    obj: &::kube::api::DynamicObject,
    resource: &crate::kube::resource::ResourceId,
    metadata: &Option<crate::teardown::plan::ReviewMetadata>,
    audit_ctx: &crate::teardown::journal::AuditContext,
    operator_snapshot: &crate::teardown::plan::OperatorIdentitySnapshot,
    cached_crd_items: Option<&[::kube::api::DynamicObject]>,
) -> Result<(), String> {
    let fresh = classify_fresh_provenance(obj, audit_ctx, operator_snapshot);
    match check_provenance_drift(metadata, &fresh) {
        ProvenanceDriftResult::Ok => Ok(()),
        ProvenanceDriftResult::Blocked(reason) => Err(reason),
        ProvenanceDriftResult::NeedsCrdVerification => {
            let saved_pairs: std::collections::HashSet<(String, String)> = metadata
                .as_ref()
                .map(|m| m.decisive_label_pairs.iter().cloned().collect())
                .unwrap_or_default();
            if saved_pairs.is_empty() {
                return Err("RelatedLabelOnly resource has no saved label pairs — \
                            cannot verify CRD-based evidence"
                    .to_string());
            }
            let crd_items = match cached_crd_items {
                Some(items) => items.to_vec(),
                None => fetch_crd_list(client).await?,
            };
            verify_governing_crd_label(resource, &saved_pairs, &crd_items)
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
    use crate::teardown::plan::{DiscoverySourceSer, ProvenanceSer};

    let stored_provenance = metadata.as_ref().and_then(|m| m.provenance.as_ref());

    match (stored_provenance, fresh) {
        (Some(ProvenanceSer::Managed), ProvenanceSer::Managed) => ProvenanceDriftResult::Ok,
        (Some(ProvenanceSer::Managed), _) => {
            ProvenanceDriftResult::Blocked("provenance downgraded from Managed".to_string())
        }
        (
            Some(ProvenanceSer::LikelyManaged),
            ProvenanceSer::Managed | ProvenanceSer::LikelyManaged,
        ) => ProvenanceDriftResult::Ok,
        (Some(ProvenanceSer::LikelyManaged), ProvenanceSer::Unknown) => {
            ProvenanceDriftResult::Blocked(
                "provenance downgraded from LikelyManaged to Unknown".to_string(),
            )
        }
        (Some(ProvenanceSer::Unknown), _) => {
            let discovery_source = metadata.as_ref().and_then(|m| m.discovery_source.as_ref());
            match discovery_source {
                Some(DiscoverySourceSer::RelatedLabelOnly) => {
                    ProvenanceDriftResult::NeedsCrdVerification
                }
                _ => ProvenanceDriftResult::Blocked(
                    "stored provenance was Unknown with no verifiable discovery source — \
                         cannot verify approval basis"
                        .to_string(),
                ),
            }
        }
        (None, _) => {
            ProvenanceDriftResult::Blocked("no stored provenance to verify against".to_string())
        }
    }
}

/// Pure sync CRD label verification — testable without cluster.
/// Checks if any label (key, value) pair on the CRD matches the saved exact pairs.
fn verify_crd_label_pairs(
    crd_labels: Option<&std::collections::BTreeMap<String, String>>,
    saved_pairs: &std::collections::HashSet<(String, String)>,
    resource_group: &str,
    resource_kind: &str,
) -> Result<(), String> {
    if saved_pairs.is_empty() {
        return Err(
            "no label pairs found on owned CRDs — cannot verify CRD-based evidence".to_string(),
        );
    }
    let has_match = crd_labels.is_some_and(|labels| {
        labels
            .iter()
            .any(|(k, v)| saved_pairs.contains(&(k.clone(), v.clone())))
    });
    if has_match {
        Ok(())
    } else {
        Err(format!(
            "governing CRD for {}/{} has no label matching saved pairs {:?}",
            resource_group, resource_kind, saved_pairs
        ))
    }
}

/// Verify the governing CRD for a resource still has a part-of label linking to the target operator.
///
/// Uses operator_snapshot.owned_crds to compute fresh part-of seeds and verifies
/// the governing CRD's label value is in that set.
/// Verify the governing CRD for a resource still has a part-of label value
/// matching the seeds saved at plan time.
/// Fetch CRD list once for reuse across multiple verify_governing_crd_label calls.
async fn fetch_crd_list(
    client: &::kube::Client,
) -> Result<Vec<::kube::api::DynamicObject>, String> {
    use ::kube::api::{Api, ApiResource, DynamicObject};
    use ::kube::core::GroupVersion;

    let crd_gvk =
        GroupVersion::gv("apiextensions.k8s.io", "v1").with_kind("CustomResourceDefinition");
    let crd_ar = ApiResource::from_gvk_with_plural(&crd_gvk, "customresourcedefinitions");
    let crd_api: Api<DynamicObject> = Api::all_with(client.clone(), &crd_ar);

    crd_api
        .list(&::kube::api::ListParams::default())
        .await
        .map(|list| list.items)
        .map_err(|e| format!("cannot list CRDs: {} — BLOCKED", e))
}

fn verify_governing_crd_label(
    resource: &crate::kube::resource::ResourceId,
    saved_pairs: &std::collections::HashSet<(String, String)>,
    crd_items: &[::kube::api::DynamicObject],
) -> Result<(), String> {
    if resource.group.is_empty() {
        return Err("resource has no API group — cannot determine governing CRD".to_string());
    }

    let governing_crd = crd_items.iter().find(|crd| {
        let crd_name = crd.metadata.name.as_deref().unwrap_or("");
        crd_name
            .split_once('.')
            .map(|(_, g)| g == resource.group)
            .unwrap_or(false)
            && crd
                .data
                .get("spec")
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

    verify_crd_label_pairs(
        crd.metadata.labels.as_ref(),
        saved_pairs,
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
    // Block resume if any finalizer recovery is in PatchRequested state (crash between
    // intent record and outcome record — commit outcome unknown without live verification)
    let unresolved_patch = j
        .finalizer_recoveries
        .iter()
        .any(|r| matches!(r.result, journal::FinalizerRecoveryResult::PatchRequested));
    if unresolved_patch {
        return Err(
            "Journal contains unresolved PatchRequested finalizer recovery record(s). \
             Crash occurred between intent and outcome — manual verification required before resume."
                .to_string(),
        );
    }

    // Block resume if any re-delete record is not terminal (Gone/Failed).
    // MVP: re-delete crash recovery requires fresh plan. Stale authority not reused.
    let has_unresolved_redelete = j.execution.re_delete_records.iter().any(|r| {
        matches!(
            r.result,
            journal::ReDeleteResult::Authorized
                | journal::ReDeleteResult::Accepted
                | journal::ReDeleteResult::UnknownOutcome(_)
        )
    });
    if has_unresolved_redelete {
        return Err(
            "Journal contains unresolved re-delete record(s) (Authorized/Accepted/Unknown). \
             Re-delete crash recovery requires a fresh teardown plan."
                .to_string(),
        );
    }

    let main_complete = j.execution.phases_completed == j.execution.phases_total;

    let has_pending_cleanup =
        !j.cleanup_decisions.is_empty() && j.cleanup_decisions.iter().any(|d| d.is_pending());

    let paused_from_residual =
        j.state == journal::RunState::Paused && main_complete && j.last_residual_audit.is_some();

    // ApplyCompleted → re-enter Residual (with or without prior audit)
    let apply_completed_reentry = j.state == journal::RunState::ApplyCompleted && main_complete;

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
            j.execution.phases_completed, j.execution.phases_total,
        ));
    }
    // Inconsistent: ApplyCompleted but main not complete
    if j.state == journal::RunState::ApplyCompleted && !main_complete {
        return Err(format!(
            "Journal inconsistent: ApplyCompleted but only {}/{} phases complete",
            j.execution.phases_completed, j.execution.phases_total,
        ));
    }

    // Prepared → user quit Plan Review without pressing Start. No mutation occurred.
    if j.state == journal::RunState::Prepared {
        return Err(
            "Journal is in Prepared state — Plan Review was not completed. \
             Create a new teardown plan."
                .to_string(),
        );
    }

    if (j.state == journal::RunState::InteractiveCleanup && main_complete)
        || (j.state == journal::RunState::Paused && main_complete && has_pending_cleanup)
        || paused_from_residual
        || apply_completed_reentry
    {
        Ok(ResumeStage::Cleanup)
    } else {
        Ok(ResumeStage::MainExecution)
    }
}

pub fn resume_has_blocking_hard_failure(j: &journal::RunJournal) -> bool {
    j.cleanup_decisions.iter().any(|d| d.is_hard_failed())
}

pub fn can_finish_run(j: &journal::RunJournal) -> Result<(), String> {
    if !matches!(
        j.state,
        journal::RunState::ApplyCompleted | journal::RunState::InteractiveCleanup
    ) {
        return Err(format!("state {:?} does not allow Finish", j.state));
    }
    if j.execution.phases_completed != j.execution.phases_total {
        return Err(format!(
            "main execution incomplete ({}/{} phases)",
            j.execution.phases_completed, j.execution.phases_total
        ));
    }
    if j.last_residual_audit.is_none() {
        return Err("no residual audit — cannot confirm cleanup status".to_string());
    }
    match j.residual_status {
        journal::ResidualStatus::ResidualsObserved { .. }
        | journal::ResidualStatus::NoneObservedInScope => {}
        journal::ResidualStatus::AuditIncomplete => {
            return Err("audit incomplete — cannot confirm cleanup status".to_string());
        }
        ref other => {
            return Err(format!(
                "residual status {:?} does not confirm audit complete",
                other
            ));
        }
    }
    if j.cleanup_decisions.iter().any(|d| d.is_hard_failed()) {
        return Err("hard-failed cleanup decisions exist".to_string());
    }
    if j.cleanup_decisions.iter().any(|d| d.is_pending()) {
        return Err(
            "pending cleanup decisions exist (UnknownOutcome or DeleteRequested)".to_string(),
        );
    }
    Ok(())
}

#[cfg(test)]
mod cluster_wide_map_tests {
    use super::*;
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

#[cfg(test)]
mod basis_drift_tests {
    use super::*;
    use crate::teardown::plan::*;
    use std::collections::HashSet;

    #[test]
    fn apply_set_no_cache_only_refreshes_first_entry() {
        assert!(apply_set_child_bypasses_cache(true, 0));
        assert!(!apply_set_child_bypasses_cache(true, 1));
        assert!(!apply_set_child_bypasses_cache(false, 0));
    }

    #[test]
    fn structured_apply_set_approvals_separate_scopes_and_resources() {
        let config: ApplySetConfig = serde_json::from_str(
            r#"{
                "operators": [{
                    "name": "example-operator",
                    "approve_delete": {
                        "scopes": ["root", "independent", "label-only", "operator-group"],
                        "resources": ["example.io/Widget/ns/example"]
                    }
                }]
            }"#,
        )
        .unwrap();

        assert_eq!(
            config.operators[0].approve_delete.cli_args(),
            vec![
                "root",
                "independent",
                "label-only",
                "operator-group",
                "example.io/Widget/ns/example",
            ]
        );
    }

    #[test]
    fn apply_set_defaults_are_merged_with_operator_exceptions() {
        let config: ApplySetConfig = serde_json::from_str(
            r#"{
                "defaults": {
                    "approve_delete": {
                        "scopes": ["root", "independent", "label-only", "operator-group"]
                    },
                    "force": true
                },
                "operators": [{
                    "name": "example-operator",
                    "approve_delete": {
                        "resources": ["example.io/Widget/ns/example"]
                    },
                    "force": false
                }]
            }"#,
        )
        .unwrap();

        let options = config.operators[0].effective_options(&config.defaults);
        assert_eq!(
            options.approve_delete,
            vec![
                "root",
                "independent",
                "label-only",
                "operator-group",
                "example.io/Widget/ns/example",
            ]
        );
        assert!(!options.force, "operator value must override the default");
        assert!(!options.non_interactive);
    }

    #[test]
    fn structured_apply_set_approvals_reject_all_scope() {
        let result = serde_json::from_str::<ApplySetConfig>(
            r#"{
                "operators": [{
                    "name": "example-operator",
                    "approve_delete": { "scopes": ["all"] }
                }]
            }"#,
        );
        assert!(result.is_err(), "structured scopes must be explicit");
    }

    #[test]
    fn legacy_apply_set_approval_array_remains_supported() {
        let config: ApplySetConfig = serde_json::from_str(
            r#"{
                "operators": [{
                    "name": "example-operator",
                    "approve_delete": ["all", "Widget/example"]
                }]
            }"#,
        )
        .unwrap();

        assert_eq!(
            config.operators[0].approve_delete.cli_args(),
            vec!["all", "Widget/example"]
        );
    }

    fn make_metadata(
        provenance: Option<ProvenanceSer>,
        discovery_source: Option<DiscoverySourceSer>,
    ) -> Option<ReviewMetadata> {
        Some(ReviewMetadata {
            category: None,
            approval_class: None,
            provenance,
            discovery_source,
            decisive_label_pairs: vec![],
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

    // ── verify_crd_label_pairs ──

    fn make_labels(pairs: &[(&str, &str)]) -> Option<std::collections::BTreeMap<String, String>> {
        if pairs.is_empty() {
            None
        } else {
            Some(
                pairs
                    .iter()
                    .map(|(k, v)| (k.to_string(), v.to_string()))
                    .collect(),
            )
        }
    }

    fn make_seed_pairs(pairs: &[(&str, &str)]) -> HashSet<(String, String)> {
        pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect()
    }

    #[test]
    fn crd_label_exact_pair_matches() {
        let pairs = make_seed_pairs(&[("example.io/part-of", "platform")]);
        let labels = make_labels(&[("example.io/part-of", "platform")]);
        assert!(verify_crd_label_pairs(labels.as_ref(), &pairs, "test.io", "Foo").is_ok());
    }

    #[test]
    fn crd_label_wrong_value_blocked() {
        let pairs = make_seed_pairs(&[("example.io/part-of", "platform")]);
        let labels = make_labels(&[("example.io/part-of", "other")]);
        assert!(verify_crd_label_pairs(labels.as_ref(), &pairs, "test.io", "Foo").is_err());
    }

    #[test]
    fn crd_label_wrong_key_blocked() {
        let pairs = make_seed_pairs(&[("example.io/part-of", "platform")]);
        let labels = make_labels(&[("other.io/part-of", "platform")]);
        assert!(verify_crd_label_pairs(labels.as_ref(), &pairs, "test.io", "Foo").is_err());
    }

    #[test]
    fn crd_label_missing_blocked() {
        let pairs = make_seed_pairs(&[("example.io/part-of", "platform")]);
        assert!(verify_crd_label_pairs(None, &pairs, "test.io", "Foo").is_err());
    }

    #[test]
    fn empty_pairs_blocked() {
        let pairs: HashSet<(String, String)> = HashSet::new();
        let labels = make_labels(&[("example.io/part-of", "platform")]);
        let result = verify_crd_label_pairs(labels.as_ref(), &pairs, "test.io", "Foo");
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("no label pairs"));
    }

    #[test]
    fn multiple_pairs_match_any() {
        let pairs = make_seed_pairs(&[
            ("example.io/part-of", "platform"),
            ("app.kubernetes.io/managed-by", "operator-x"),
        ]);
        let labels = make_labels(&[("app.kubernetes.io/managed-by", "operator-x")]);
        assert!(verify_crd_label_pairs(labels.as_ref(), &pairs, "test.io", "Foo").is_ok());
    }

    #[test]
    fn basis_drift_pair_a_removed_pair_b_only_blocked() {
        // Seed has pairs A and B. CRD was discovered via pair A.
        // decisive_label_pairs stores only [A] (the intersection).
        // On revalidation, CRD now only has pair B (A removed) → BLOCKED.
        let saved = make_seed_pairs(&[("vendor.io/part-of", "platform-a")]);
        let live_labels = make_labels(&[("other.io/part-of", "platform-b")]);
        let result = verify_crd_label_pairs(live_labels.as_ref(), &saved, "vendor.io", "Widget");
        assert!(
            result.is_err(),
            "pair A removed, only B present → must block"
        );
    }

    #[test]
    fn basis_drift_pair_a_maintained_ok() {
        let saved = make_seed_pairs(&[("vendor.io/part-of", "platform-a")]);
        let live_labels = make_labels(&[
            ("vendor.io/part-of", "platform-a"),
            ("other.io/part-of", "platform-b"),
        ]);
        assert!(
            verify_crd_label_pairs(live_labels.as_ref(), &saved, "vendor.io", "Widget").is_ok()
        );
    }

    // ── Multi-seed MVP restriction ──

    #[test]
    fn multi_pair_allows_crd_verification() {
        let meta = Some(ReviewMetadata {
            category: None,
            approval_class: None,
            provenance: Some(ProvenanceSer::Unknown),
            discovery_source: Some(DiscoverySourceSer::RelatedLabelOnly),
            decisive_label_pairs: vec![
                ("x.io/part-of".to_string(), "platform".to_string()),
                ("x.io/managed-by".to_string(), "operator-a".to_string()),
            ],
        });
        assert!(matches!(
            check_provenance_drift(&meta, &ProvenanceSer::Unknown),
            ProvenanceDriftResult::NeedsCrdVerification
        ));
    }

    #[test]
    fn single_pair_allows_crd_verification() {
        let meta = Some(ReviewMetadata {
            category: None,
            approval_class: None,
            provenance: Some(ProvenanceSer::Unknown),
            discovery_source: Some(DiscoverySourceSer::RelatedLabelOnly),
            decisive_label_pairs: vec![("x.io/part-of".to_string(), "platform".to_string())],
        });
        assert!(matches!(
            check_provenance_drift(&meta, &ProvenanceSer::Unknown),
            ProvenanceDriftResult::NeedsCrdVerification
        ));
    }

    #[test]
    fn empty_pairs_in_metadata_blocked_at_caller() {
        let meta = Some(ReviewMetadata {
            category: None,
            approval_class: None,
            provenance: Some(ProvenanceSer::Unknown),
            discovery_source: Some(DiscoverySourceSer::RelatedLabelOnly),
            decisive_label_pairs: vec![],
        });
        assert!(matches!(
            check_provenance_drift(&meta, &ProvenanceSer::Unknown),
            ProvenanceDriftResult::NeedsCrdVerification
        ));
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
                generation_identity: OperatorGenerationIdentity::Unverifiable {
                    reason: "test".to_string(),
                },
                operator_id: crate::analyzers::olm::OperatorId {
                    namespace: "ns".to_string(),
                    csv_name: "test.1.0".to_string(),
                },
                csv_name: "test.1.0".to_string(),
                csv: ObservedResourceIdentity {
                    resource: crate::kube::resource::ResourceId {
                        group: "operators.coreos.com".to_string(),
                        version: "v1alpha1".to_string(),
                        kind: "ClusterServiceVersion".to_string(),
                        namespace: Some("ns".to_string()),
                        name: "test.1.0".to_string(),
                        uid: Some("csv-uid".to_string()),
                    },
                    uid: "csv-uid".to_string(),
                },
                subscriptions: vec![],
                controller_deployments: vec![],
                service_accounts: vec![],
                owned_crds: vec![],
                required_crds: vec![],
            },
            created_at: "2026-01-01T00:00:00Z".to_string(),
            updated_at: "2026-01-01T00:00:00Z".to_string(),
            state,
            residual_status: if has_audit {
                ResidualStatus::NoneObservedInScope
            } else {
                ResidualStatus::NotAudited
            },
            audit_revision: 0,
            audit_context: AuditContext::default(),
            plan_snapshot: TeardownPlan {
                targets: vec![],
                preflight: Preflight { checks: vec![] },
                phases: vec![],
                blockers: vec![],
                warnings: vec![],
                snapshot_taken_at: "2026-01-01T00:00:00Z".to_string(),
                dependency_edges: vec![],
                operator_inventory: vec![],
                explicit_decisions: vec![],
            },
            execution: ExecutionRecord {
                phases_completed,
                phases_total,
                ..Default::default()
            },
            last_residual_audit: if has_audit {
                Some(crate::teardown::audit::ResidualAudit {
                    planned_delete_still_present: vec![],
                    planned_expect_still_present: vec![],
                    expected_preserved: vec![],
                    likely_operator_residual: vec![],
                    unattributed: vec![],
                    coverage: crate::teardown::audit::AuditCoverage {
                        requested_probes: 0,
                        succeeded_probes: 0,
                    },
                    scan_errors: vec![],
                })
            } else {
                None
            },
            cleanup_decisions: decisions,
            finalizer_recovery_approved: false,
            finalizer_recoveries: Vec::new(),
        }
    }

    fn make_decision(
        name: &str,
        result: Option<crate::teardown::journal::CleanupResult>,
    ) -> crate::teardown::journal::CleanupDecision {
        crate::teardown::journal::CleanupDecision {
            resource: crate::kube::resource::ResourceId {
                group: "apps".to_string(),
                version: "v1".to_string(),
                kind: "Deployment".to_string(),
                namespace: Some("ns".to_string()),
                name: name.to_string(),
                uid: Some(format!("uid-{}", name)),
            },
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
        assert_eq!(
            classify_resume_stage(&j).unwrap(),
            ResumeStage::MainExecution
        );
    }

    #[test]
    fn classify_resume_interactive_cleanup_routes_to_cleanup() {
        use crate::teardown::journal::RunState;
        let j = make_test_journal(RunState::InteractiveCleanup, 7, 7, true, vec![]);
        assert_eq!(classify_resume_stage(&j).unwrap(), ResumeStage::Cleanup);
    }

    #[test]
    fn classify_resume_paused_with_pending_complete_routes_to_cleanup() {
        use crate::teardown::journal::RunState;
        let j = make_test_journal(
            RunState::Paused,
            7,
            7,
            false,
            vec![make_decision("a", None)],
        );
        assert_eq!(classify_resume_stage(&j).unwrap(), ResumeStage::Cleanup);
    }

    #[test]
    fn classify_resume_pending_with_incomplete_phases_is_error() {
        use crate::teardown::journal::RunState;
        let j = make_test_journal(
            RunState::Paused,
            5,
            7,
            false,
            vec![make_decision("a", None)],
        );
        assert!(
            classify_resume_stage(&j).is_err(),
            "Pending cleanup with incomplete main phases = inconsistent journal"
        );
    }

    #[test]
    fn classify_resume_interactive_cleanup_incomplete_phases_is_error() {
        use crate::teardown::journal::RunState;
        let j = make_test_journal(RunState::InteractiveCleanup, 3, 7, true, vec![]);
        assert!(
            classify_resume_stage(&j).is_err(),
            "InteractiveCleanup with incomplete phases = inconsistent journal"
        );
    }

    #[test]
    fn hard_failure_blocks_resume() {
        use crate::teardown::journal::{CleanupResult, RunState};
        let j = make_test_journal(
            RunState::InteractiveCleanup,
            7,
            7,
            true,
            vec![
                make_decision("failed", Some(CleanupResult::Failed("err".to_string()))),
                make_decision("pending", None),
            ],
        );
        assert!(
            resume_has_blocking_hard_failure(&j),
            "hard failure must block resume before pending is processed"
        );
    }

    #[test]
    fn classify_resume_apply_completed_no_audit_routes_to_cleanup() {
        use crate::teardown::journal::RunState;
        let j = make_test_journal(RunState::ApplyCompleted, 7, 7, false, vec![]);
        assert_eq!(
            classify_resume_stage(&j).unwrap(),
            ResumeStage::Cleanup,
            "ApplyCompleted with no audit = crash recovery → cleanup branch"
        );
    }

    #[test]
    fn classify_resume_apply_completed_with_audit_routes_to_cleanup() {
        use crate::teardown::journal::RunState;
        let j = make_test_journal(RunState::ApplyCompleted, 7, 7, true, vec![]);
        assert_eq!(
            classify_resume_stage(&j).unwrap(),
            ResumeStage::Cleanup,
            "ApplyCompleted + audit + complete = Residual re-entry"
        );
    }

    #[test]
    fn no_hard_failure_allows_resume() {
        use crate::teardown::journal::{CleanupResult, RunState};
        let j = make_test_journal(
            RunState::InteractiveCleanup,
            7,
            7,
            true,
            vec![
                make_decision("gone", Some(CleanupResult::Gone)),
                make_decision("pending", Some(CleanupResult::DeleteRequested)),
            ],
        );
        assert!(
            !resume_has_blocking_hard_failure(&j),
            "DeleteRequested is retryable, not hard failure"
        );
    }

    // ── PatchRequested resume block ──

    #[test]
    fn classify_resume_blocks_on_unresolved_patch_requested() {
        use crate::teardown::journal::{
            FinalizerRecoveryRecord, FinalizerRecoveryResult, OwnerRefSnapshot, RunState,
        };
        let mut j = make_test_journal(RunState::Paused, 3, 7, false, vec![]);
        j.finalizer_recoveries.push(FinalizerRecoveryRecord {
            resource: crate::kube::resource::ResourceId {
                group: "test".to_string(),
                version: "v1".to_string(),
                kind: "Widget".to_string(),
                namespace: Some("ns".to_string()),
                name: "w1".to_string(),
                uid: Some("uid-w1".to_string()),
            },
            live_uid: "uid-w1".to_string(),
            finalizer_values: vec!["test/fin".to_string()],
            owner_references_snapshot: vec![OwnerRefSnapshot {
                api_version: "v1".to_string(),
                kind: "Parent".to_string(),
                name: "p1".to_string(),
                uid: "uid-p1".to_string(),
                controller: Some(true),
            }],
            root_uid: "uid-p1".to_string(),
            root_kind: "Parent".to_string(),
            result: FinalizerRecoveryResult::PatchRequested,
        });
        let err = classify_resume_stage(&j).unwrap_err();
        assert!(
            err.contains("PatchRequested"),
            "Should block on PatchRequested: {}",
            err
        );
    }

    #[test]
    fn classify_resume_allows_resolved_recovery() {
        use crate::teardown::journal::{
            FinalizerRecoveryRecord, FinalizerRecoveryResult, OwnerRefSnapshot, RunState,
        };
        let mut j = make_test_journal(RunState::Paused, 3, 7, false, vec![]);
        j.finalizer_recoveries.push(FinalizerRecoveryRecord {
            resource: crate::kube::resource::ResourceId {
                group: "test".to_string(),
                version: "v1".to_string(),
                kind: "Widget".to_string(),
                namespace: Some("ns".to_string()),
                name: "w1".to_string(),
                uid: Some("uid-w1".to_string()),
            },
            live_uid: "uid-w1".to_string(),
            finalizer_values: vec!["test/fin".to_string()],
            owner_references_snapshot: vec![OwnerRefSnapshot {
                api_version: "v1".to_string(),
                kind: "Parent".to_string(),
                name: "p1".to_string(),
                uid: "uid-p1".to_string(),
                controller: Some(true),
            }],
            root_uid: "uid-p1".to_string(),
            root_kind: "Parent".to_string(),
            result: FinalizerRecoveryResult::Stripped,
        });
        assert!(
            classify_resume_stage(&j).is_ok(),
            "Resolved recovery (Stripped) should not block resume"
        );
    }

    // ── can_finish_run tests ──

    #[test]
    fn can_finish_apply_completed_with_audit() {
        use crate::teardown::journal::RunState;
        let j = make_test_journal(RunState::ApplyCompleted, 7, 7, true, vec![]);
        assert!(can_finish_run(&j).is_ok());
    }

    #[test]
    fn cannot_finish_without_audit() {
        use crate::teardown::journal::RunState;
        let j = make_test_journal(RunState::ApplyCompleted, 7, 7, false, vec![]);
        let err = can_finish_run(&j).unwrap_err();
        assert!(err.contains("no residual audit"));
    }

    #[test]
    fn cannot_finish_with_incomplete_audit() {
        use crate::teardown::journal::RunState;
        let mut j = make_test_journal(RunState::ApplyCompleted, 7, 7, true, vec![]);
        j.residual_status = crate::teardown::journal::ResidualStatus::AuditIncomplete;
        let err = can_finish_run(&j).unwrap_err();
        assert!(err.contains("audit incomplete"));
    }

    #[test]
    fn cannot_finish_with_hard_failed_decision() {
        use crate::teardown::journal::{CleanupResult, RunState};
        let j = make_test_journal(
            RunState::ApplyCompleted,
            7,
            7,
            true,
            vec![make_decision(
                "failed",
                Some(CleanupResult::Failed("err".to_string())),
            )],
        );
        let err = can_finish_run(&j).unwrap_err();
        assert!(err.contains("hard-failed"));
    }

    #[test]
    fn cannot_finish_with_not_audited_status() {
        use crate::teardown::journal::RunState;
        let mut j = make_test_journal(RunState::ApplyCompleted, 7, 7, true, vec![]);
        j.residual_status = crate::teardown::journal::ResidualStatus::NotAudited;
        let err = can_finish_run(&j).unwrap_err();
        assert!(err.contains("does not confirm audit complete"));
    }

    #[test]
    fn cannot_finish_with_incomplete_phases() {
        use crate::teardown::journal::RunState;
        let j = make_test_journal(RunState::ApplyCompleted, 5, 7, true, vec![]);
        let err = can_finish_run(&j).unwrap_err();
        assert!(err.contains("incomplete"));
    }

    #[test]
    fn cannot_finish_from_paused_state() {
        use crate::teardown::journal::RunState;
        let j = make_test_journal(RunState::Paused, 7, 7, true, vec![]);
        let err = can_finish_run(&j).unwrap_err();
        assert!(err.contains("does not allow Finish"));
    }

    #[tokio::test]
    async fn check_and_persist_paused_with_closed_gate() {
        use crate::teardown::journal::*;
        use crate::teardown::permit::MutationGate;

        let j = make_test_journal(RunState::ApplyCompleted, 7, 7, true, vec![]);

        let dir = std::env::temp_dir().join(format!(
            "oc-deps-test-pause-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let _ = std::fs::create_dir_all(&dir);
        let path = dir.join("journal.json");
        crate::teardown::journal::atomic_write_json_pub(&path, &j).unwrap();

        let store = std::sync::Arc::new(JournalStore::new_with_lock(j, path.clone()).unwrap());
        let gate = std::sync::Arc::new(MutationGate::new(4));

        // Gate open → not paused
        let paused = crate::tui::check_and_persist_paused(&store, &gate)
            .await
            .unwrap();
        assert!(!paused, "open gate must not trigger pause");

        // Close gate → paused + journal state durably updated on disk
        gate.close_and_drain().await;
        let paused = crate::tui::check_and_persist_paused(&store, &gate)
            .await
            .unwrap();
        assert!(paused, "closed gate must trigger pause");

        // Verify durable state on disk (not just in-memory)
        let j_disk = load_journal(&path).unwrap();
        assert_eq!(
            j_disk.state,
            RunState::Paused,
            "journal on disk must be Paused after gate-closed persist"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    // ── MVP safety boundary tests ──

    #[test]
    fn prepared_journal_rejects_resume_mutation() {
        use crate::teardown::journal::RunState;
        let j = make_test_journal(RunState::Prepared, 0, 7, false, vec![]);
        let result = classify_resume_stage(&j);
        assert!(result.is_err(), "Prepared journal must reject resume");
        assert!(
            result.unwrap_err().contains("Prepared"),
            "Error must mention Prepared state"
        );
    }

    #[test]
    fn expect_resources_do_not_create_re_delete_authority() {
        use crate::teardown::journal::{ReDeleteRecord, ReDeleteResult, RunState};
        let mut j = make_test_journal(RunState::Applying, 3, 7, false, vec![]);
        // Simulate: EXPECT descendant was observed as Gone, no re-delete authority
        // Re-delete authority can only come from explicit DELETE accepted+Gone+Recreated
        assert!(
            j.execution.re_delete_records.is_empty(),
            "Fresh journal must have no re-delete authority"
        );
        // Manually adding a record simulates executor behavior
        j.execution.re_delete_records.push(ReDeleteRecord {
            resource_identity: crate::kube::resource::ResourceId {
                group: "test".to_string(),
                version: "v1".to_string(),
                kind: "Widget".to_string(),
                namespace: Some("ns".to_string()),
                name: "w1".to_string(),
                uid: None,
            },
            original_uid: "uid-orig".to_string(),
            new_uid: "uid-new".to_string(),
            result: ReDeleteResult::Authorized,
        });
        // Authority exists — this is valid only if original DELETE was accepted+Gone
        assert_eq!(j.execution.re_delete_records.len(), 1);
        assert_eq!(
            j.execution.re_delete_records[0].result,
            ReDeleteResult::Authorized
        );
    }

    #[test]
    fn unresolved_redelete_blocks_resume() {
        use crate::teardown::journal::{ReDeleteRecord, ReDeleteResult, RunState};
        // MVP: any Authorized/Accepted/Unknown re-delete blocks resume
        for (variant, label) in [
            (ReDeleteResult::Authorized, "Authorized must block resume"),
            (ReDeleteResult::Accepted, "Accepted must block resume"),
            (
                ReDeleteResult::UnknownOutcome("500".to_string()),
                "Unknown must block resume",
            ),
        ] {
            let mut j = make_test_journal(RunState::Paused, 3, 7, false, vec![]);
            j.execution.re_delete_records.push(ReDeleteRecord {
                resource_identity: crate::kube::resource::ResourceId {
                    group: "test".to_string(),
                    version: "v1".to_string(),
                    kind: "Widget".to_string(),
                    namespace: None,
                    name: "w1".to_string(),
                    uid: None,
                },
                original_uid: "uid-old".to_string(),
                new_uid: "uid-new".to_string(),
                result: variant,
            });
            let result = classify_resume_stage(&j);
            assert!(result.is_err(), "{}", label);
            assert!(
                result.unwrap_err().contains("re-delete"),
                "Error must mention re-delete"
            );
        }
    }

    #[test]
    fn resolved_redelete_allows_resume() {
        use crate::teardown::journal::{ReDeleteRecord, ReDeleteResult, RunState};
        let mut j = make_test_journal(RunState::Paused, 3, 7, false, vec![]);
        j.execution.re_delete_records.push(ReDeleteRecord {
            resource_identity: crate::kube::resource::ResourceId {
                group: "test".to_string(),
                version: "v1".to_string(),
                kind: "Widget".to_string(),
                namespace: None,
                name: "w1".to_string(),
                uid: None,
            },
            original_uid: "uid-old".to_string(),
            new_uid: "uid-new".to_string(),
            result: ReDeleteResult::Gone,
        });
        assert!(
            classify_resume_stage(&j).is_ok(),
            "Gone re-delete must allow resume"
        );
    }

    #[test]
    fn re_delete_record_roundtrip() {
        use crate::teardown::journal::{ReDeleteRecord, ReDeleteResult, RunState};
        let mut j = make_test_journal(RunState::Applying, 3, 7, false, vec![]);
        j.execution.re_delete_records.push(ReDeleteRecord {
            resource_identity: crate::kube::resource::ResourceId {
                group: "test".to_string(),
                version: "v1".to_string(),
                kind: "Auth".to_string(),
                namespace: None,
                name: "auth".to_string(),
                uid: None,
            },
            original_uid: "uid-orig".to_string(),
            new_uid: "uid-new".to_string(),
            result: ReDeleteResult::Gone,
        });
        let serialized = serde_json::to_string(&j).unwrap();
        let deser: crate::teardown::journal::RunJournal =
            serde_json::from_str(&serialized).unwrap();
        assert_eq!(deser.execution.re_delete_records.len(), 1);
        assert_eq!(
            deser.execution.re_delete_records[0].original_uid,
            "uid-orig"
        );
        assert_eq!(deser.execution.re_delete_records[0].new_uid, "uid-new");
        assert!(
            deser.execution.re_delete_records[0]
                .resource_identity
                .uid
                .is_none()
        );
    }

    #[test]
    fn pending_cleanup_blocks_finish() {
        use crate::teardown::journal::{CleanupDecision, CleanupResult, RunState};
        let mut j = make_test_journal(RunState::InteractiveCleanup, 7, 7, true, vec![]);
        j.residual_status = crate::teardown::journal::ResidualStatus::NoneObservedInScope;
        j.cleanup_decisions.push(CleanupDecision {
            resource: crate::kube::resource::ResourceId {
                group: "test".to_string(),
                version: "v1".to_string(),
                kind: "Widget".to_string(),
                namespace: None,
                name: "w1".to_string(),
                uid: Some("uid-w1".to_string()),
            },
            bound_uid: Some("uid-w1".to_string()),
            action: "delete".to_string(),
            result: Some(CleanupResult::UnknownOutcome("500".to_string())),
            approved_spec_name: None,
        });
        let result = can_finish_run(&j);
        assert!(
            result.is_err(),
            "Pending cleanup (UnknownOutcome) must block Finish"
        );
        assert!(
            result.unwrap_err().contains("pending"),
            "Error must mention pending"
        );
    }
}
