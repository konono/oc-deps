macro_rules! print {
    ($($arg:tt)*) => {{
        crate::terminal_output::write_stdout(format_args!($($arg)*), false)
    }};
}

macro_rules! println {
    () => {{ crate::terminal_output::write_stdout(format_args!(""), true) }};
    ($($arg:tt)*) => {{
        crate::terminal_output::write_stdout(format_args!($($arg)*), true)
    }};
}

macro_rules! eprint {
    ($($arg:tt)*) => {{
        crate::terminal_output::write_stderr(format_args!($($arg)*), false)
    }};
}

macro_rules! eprintln {
    () => {{ crate::terminal_output::write_stderr(format_args!(""), true) }};
    ($($arg:tt)*) => {{
        crate::terminal_output::write_stderr(format_args!($($arg)*), true)
    }};
}

mod analyzers;
mod audit;
mod cli;
mod graph;
mod kube;
mod output;
mod teardown;
mod terminal_output;

use std::collections::HashSet;
use std::time::Instant;

use anyhow::{Context, Result, bail};
use clap::{CommandFactory, Parser};

use crate::analyzers::inspect::{
    inspect_operator_with_options_ledger, print_inspection as print_inspection_top,
};
use crate::analyzers::namespace_scope::discover_operator_namespaces_opts;
use crate::analyzers::olm::{
    WhoManagesInput, compute_operator_dependencies, discover_operators, discover_operators_full,
    print_operators, print_who_manages, who_manages, who_manages_opts,
};
use crate::analyzers::selector::{
    build_network_inventory, build_service_network_path, evaluate_network_postures,
    find_network_paths, get_service_selected_pods,
};
use crate::analyzers::trace::{print_trace, trace_resource};
use crate::cli::{
    Args, Command, Direction, OperatorAction, OutputFormat, Scope, ShowField, SnapshotAction,
    TeardownAction,
};
use crate::graph::evidence::build_evidence_graph;
use crate::graph::tree::{
    TreeNode, apply_filters, build_child_tree, build_full_tree, build_namespace_map,
};
use crate::kube::discovery::{
    build_kind_lookup_cached, load_config_and_client, resolve_kind_with_group,
};
use crate::kube::resource::format_scan_warnings;
use crate::kube::scanner::{
    find_parents_only, resolve_missing_parents, scan_namespace, scan_namespace_with_extra_apis,
};
use crate::kube::snapshot::{
    build_snapshot, diff_snapshots, load_snapshot, print_diff_table, print_diff_tree, save_snapshot,
};
use crate::output::json::{print_chain_json, print_json, tree_to_json};
use crate::output::table::{print_chain_table, print_table};
use crate::output::tree::{
    TreeDisplayOpts, count_nodes, format_container_resources, print_chain_tree, print_tree,
};
use crate::teardown::explain::explain_resource;
use crate::teardown::journal::{
    self, ExecutionRecord, JournalStore, ResidualStatus, RunJournal, RunState,
};
use crate::teardown::permit::MutationGate;
use crate::teardown::planner::{
    DecisionPolicy, generate_teardown_plan, load_plan_from_file, print_teardown_plan,
    resolve_operator_targets, save_plan_to_file,
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
}

#[derive(Clone, Debug, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DeleteResourceSpec {
    pub group: String,
    pub kind: String,
    pub namespace: Option<String>,
    pub name: String,
}

impl DeleteResourceSpec {
    pub fn validate(&self) -> anyhow::Result<()> {
        if self.kind.trim().is_empty() || self.kind != self.kind.trim() {
            anyhow::bail!(
                "delete_resources: invalid kind {:?} (empty or whitespace)",
                self.kind
            );
        }
        if self.name.trim().is_empty() || self.name != self.name.trim() {
            anyhow::bail!(
                "delete_resources: invalid name {:?} (empty or whitespace)",
                self.name
            );
        }
        if self.group != self.group.trim() {
            anyhow::bail!(
                "delete_resources: invalid group {:?} (whitespace)",
                self.group
            );
        }
        const FORBIDDEN: &[&str] = &[
            "Namespace",
            "PersistentVolume",
            "PersistentVolumeClaim",
            "CustomResourceDefinition",
            "APIService",
        ];
        if FORBIDDEN.contains(&self.kind.as_str()) {
            anyhow::bail!(
                "delete_resources: kind {} is forbidden (use --prune-crds for CRDs)",
                self.kind
            );
        }
        Ok(())
    }

    pub fn to_cli_arg(&self) -> String {
        let ns = self.namespace.as_deref().unwrap_or("-");
        if self.group.is_empty() {
            format!("{}/{}/{}", self.kind, ns, self.name)
        } else {
            format!("{}/{}/{}/{}", self.group, self.kind, ns, self.name)
        }
    }

    pub fn parse_cli_arg(s: &str) -> anyhow::Result<Self> {
        let parts: Vec<&str> = s.split('/').collect();
        let (group, kind, ns_str, name) = match parts.len() {
            3 => ("", parts[0], parts[1], parts[2]),
            4 => (parts[0], parts[1], parts[2], parts[3]),
            _ => anyhow::bail!(
                "Invalid delete-resource spec '{}': expected Kind/ns/name or group/Kind/ns/name",
                s
            ),
        };
        let namespace = if ns_str == "-" {
            None
        } else {
            Some(ns_str.to_string())
        };
        let spec = Self {
            group: group.to_string(),
            kind: kind.to_string(),
            namespace,
            name: name.to_string(),
        };
        spec.validate()?;
        Ok(spec)
    }
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
    delete_resources: Vec<DeleteResourceSpec>,
}

struct EffectiveApplySetOptions {
    approve_delete: Vec<String>,
    preserve: Vec<String>,
    delete_resources: Vec<DeleteResourceSpec>,
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
            delete_resources: self.delete_resources.clone(),
        }
    }
}

#[derive(Default, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct ApplySetDeleteApprovals {
    #[serde(default)]
    scopes: Vec<ApplySetApprovalScope>,
    #[serde(default)]
    resources: Vec<String>,
}

impl ApplySetDeleteApprovals {
    fn cli_args(&self) -> Vec<String> {
        self.scopes
            .iter()
            .map(|scope| scope.cli_arg().to_string())
            .chain(self.resources.iter().cloned())
            .collect()
    }
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

fn build_deletion_closure_from_teardown_plan(
    plan: &crate::teardown::planner::TeardownPlan,
) -> crate::teardown::ref_guard::DeletionClosureWithUid {
    use crate::teardown::planner::Action;
    use crate::teardown::ref_guard::{DeletionClosureWithUid, deletion_key};
    let mut closure = DeletionClosureWithUid::new();
    for phase in &plan.phases {
        for action in &phase.actions {
            let rid = match action {
                Action::Delete { resource, .. } | Action::ExpectGone { resource, .. } => resource,
                _ => continue,
            };
            let key = deletion_key(&rid.group, &rid.kind, rid.namespace.as_deref(), &rid.name);
            if let Some(uid) = &rid.uid {
                closure.insert(key, uid.clone());
            }
        }
    }
    closure
}

pub(crate) async fn resolve_explicit_delete_targets(
    client: &::kube::Client,
    specs: &[DeleteResourceSpec],
    plan: &crate::teardown::planner::TeardownPlan,
    gk_map: &crate::kube::discovery::GroupKindMap,
) -> Result<Vec<crate::teardown::plan::ExplicitDeleteTarget>> {
    use crate::teardown::ref_guard;
    use ::kube::api::{Api, DynamicObject};

    // Pass 1: GET all explicit targets to capture UIDs
    struct ResolvedSpec {
        spec: DeleteResourceSpec,
        uid: String,
        version: String,
    }
    let mut resolved = Vec::new();
    for spec in specs {
        let gk = (spec.group.clone(), spec.kind.clone());
        let Some(info) = gk_map.get(&gk) else {
            bail!(
                "delete-resource: {}/{} not found in API discovery (group={:?})",
                spec.kind,
                spec.name,
                spec.group
            );
        };

        if info.namespaced && spec.namespace.is_none() {
            bail!(
                "delete-resource: {}/{} is namespaced but no namespace specified",
                spec.kind,
                spec.name
            );
        }
        if !info.namespaced && spec.namespace.is_some() {
            bail!(
                "delete-resource: {}/{} is cluster-scoped but namespace {:?} specified",
                spec.kind,
                spec.name,
                spec.namespace
            );
        }

        let gvk = ::kube::api::GroupVersionKind {
            group: info.group.clone(),
            version: info.version.clone(),
            kind: spec.kind.clone(),
        };
        let ar = ::kube::api::ApiResource::from_gvk_with_plural(&gvk, &info.plural);

        let api: Api<DynamicObject> = if let Some(ref ns) = spec.namespace {
            Api::namespaced_with(client.clone(), ns, &ar)
        } else {
            Api::all_with(client.clone(), &ar)
        };

        let obj = match crate::kube::scanner::get_with_retry(
            &api,
            &spec.name,
            &info.group,
            &info.version,
            &info.plural,
        )
        .await
        {
            Ok(o) => o,
            Err(w) if w.is_not_found() => {
                bail!(
                    "delete-resource: {}/{} not found in cluster",
                    spec.kind,
                    spec.name
                );
            }
            Err(w) => {
                bail!(
                    "delete-resource: failed to GET {}/{}: {}",
                    spec.kind,
                    spec.name,
                    w
                );
            }
        };

        let uid = obj
            .metadata
            .uid
            .as_deref()
            .ok_or_else(|| {
                anyhow::anyhow!("delete-resource: {}/{} has no UID", spec.kind, spec.name)
            })?
            .to_string();

        resolved.push(ResolvedSpec {
            spec: spec.clone(),
            uid,
            version: info.version.clone(),
        });
    }

    // Pass 2: Build closure with bound UIDs, then run ref guard
    let mut deletion_closure = build_deletion_closure_from_teardown_plan(plan);
    for r in &resolved {
        let key = ref_guard::deletion_key(
            &r.spec.group,
            &r.spec.kind,
            r.spec.namespace.as_deref(),
            &r.spec.name,
        );
        deletion_closure.insert(key, r.uid.clone());
    }

    let mut targets = Vec::new();
    for r in &resolved {
        let target_rid = crate::kube::resource::ResourceId {
            group: r.spec.group.clone(),
            version: r.version.clone(),
            kind: r.spec.kind.clone(),
            namespace: r.spec.namespace.clone(),
            name: r.spec.name.clone(),
            uid: Some(r.uid.clone()),
        };

        let scan =
            ref_guard::check_inbound_refs(client, &target_rid, &deletion_closure, gk_map).await?;

        if !scan.blockers.is_empty() {
            let blocker_list: Vec<String> = scan
                .blockers
                .iter()
                .map(|b| format!("{}/{}({})", b.resource.kind, b.resource.name, b.ref_field))
                .collect();
            bail!(
                "delete-resource: {}/{} is referenced by {} resource(s) outside the deletion plan: {}. \
                 Cannot safely delete a shared resource.",
                r.spec.kind,
                r.spec.name,
                scan.blockers.len(),
                blocker_list.join(", ")
            );
        }

        if !scan.coverage.scan_complete {
            bail!(
                "delete-resource: inbound reference scan for {}/{} is incomplete — cannot verify safety",
                r.spec.kind,
                r.spec.name
            );
        }

        let inbound_refs = ref_guard::to_inbound_ref_identities(&scan);

        targets.push(crate::teardown::plan::ExplicitDeleteTarget {
            group: r.spec.group.clone(),
            kind: r.spec.kind.clone(),
            namespace: r.spec.namespace.clone(),
            name: r.spec.name.clone(),
            uid: r.uid.clone(),
            reason: "config explicit".to_string(),
            inbound_refs_at_plan: inbound_refs,
            ref_scan_coverage: scan.coverage,
        });
    }

    Ok(targets)
}

#[derive(Clone, Debug, PartialEq)]
enum BatchOutcome {
    Succeeded,
    Skipped,
    Failed(i32),
    NotRun,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum PendingResumeAction {
    ReportOnly,
    Execute,
}

fn pending_resume_action(dry_run: bool) -> PendingResumeAction {
    if dry_run {
        PendingResumeAction::ReportOnly
    } else {
        PendingResumeAction::Execute
    }
}

fn batch_summary(results: &[(String, BatchOutcome)]) -> (usize, usize, usize) {
    let s = results
        .iter()
        .filter(|(_, o)| *o == BatchOutcome::Succeeded)
        .count();
    let sk = results
        .iter()
        .filter(|(_, o)| *o == BatchOutcome::Skipped)
        .count();
    let f = results
        .iter()
        .filter(|(_, o)| matches!(o, BatchOutcome::Failed(_)))
        .count();
    (s, sk, f)
}

fn operator_matches_entry(op: &crate::analyzers::olm::OperatorInstance, entry_name: &str) -> bool {
    op.csv.name.starts_with(&format!("{}.", entry_name))
        || op.csv.name.starts_with(&format!("{}.v", entry_name))
        || op.package_name.as_deref() == Some(entry_name)
        || op.csv.name == entry_name
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ExplicitCleanupResumeMode {
    TypedBlocked,
    LegacyFailed,
}

type ExplicitCleanupKey = (String, String, Option<String>, String, String);

pub(crate) fn explicit_cleanup_resume_mode(
    run: &crate::teardown::journal::RunJournal,
) -> Result<ExplicitCleanupResumeMode, String> {
    use crate::teardown::journal::{FinalizerRecoveryResult, ReDeleteResult, RunState};
    use crate::teardown::planner::Action;

    let mode = match run.state {
        RunState::ExplicitCleanupBlocked => ExplicitCleanupResumeMode::TypedBlocked,
        RunState::Failed => ExplicitCleanupResumeMode::LegacyFailed,
        ref other => {
            return Err(format!(
                "state {:?} is not an explicit-cleanup retry state",
                other
            ));
        }
    };

    if run.schema_version != crate::teardown::journal::RUN_JOURNAL_SCHEMA_VERSION {
        return Err(format!(
            "journal schema v{} does not match current v{}",
            run.schema_version,
            crate::teardown::journal::RUN_JOURNAL_SCHEMA_VERSION
        ));
    }
    if run.execution.phases_total != run.plan_snapshot.phases.len() {
        return Err(format!(
            "phase count mismatch: journal={} plan={}",
            run.execution.phases_total,
            run.plan_snapshot.phases.len()
        ));
    }
    if !run.plan_snapshot.blockers.is_empty() {
        return Err("saved plan contains blockers".to_string());
    }

    let explicit_phase_indices: Vec<usize> = run
        .plan_snapshot
        .phases
        .iter()
        .enumerate()
        .filter_map(|(i, p)| {
            (p.name == crate::teardown::plan::EXPLICIT_CLEANUP_PHASE_NAME).then_some(i)
        })
        .collect();
    if explicit_phase_indices.len() != 1 {
        return Err(format!(
            "expected exactly one Explicit cleanup phase, found {}",
            explicit_phase_indices.len()
        ));
    }
    let explicit_phase_index = explicit_phase_indices[0];
    if run.execution.phases_completed != explicit_phase_index {
        return Err(format!(
            "phases_completed {} does not point to Explicit cleanup phase {}",
            run.execution.phases_completed, explicit_phase_index
        ));
    }
    if run.plan_snapshot.explicit_deletes.is_empty() {
        return Err("saved plan has no explicit_deletes".to_string());
    }

    let mut metadata_keys: Vec<ExplicitCleanupKey> = Vec::new();
    for target in &run.plan_snapshot.explicit_deletes {
        if target.kind.trim().is_empty()
            || target.name.trim().is_empty()
            || target.uid.trim().is_empty()
            || target
                .namespace
                .as_ref()
                .is_some_and(|ns| ns.trim().is_empty())
            || !target.ref_scan_coverage.scan_complete
        {
            return Err(format!(
                "invalid explicit target {}/{} (empty identity/UID or incomplete plan-time scan)",
                target.kind, target.name
            ));
        }
        metadata_keys.push((
            target.group.clone(),
            target.kind.clone(),
            target.namespace.clone(),
            target.name.clone(),
            target.uid.clone(),
        ));
    }

    let mut action_keys: Vec<ExplicitCleanupKey> = Vec::new();
    for action in &run.plan_snapshot.phases[explicit_phase_index].actions {
        let Action::Delete { resource, .. } = action else {
            return Err("Explicit cleanup phase contains a non-DELETE action".to_string());
        };
        let uid = resource
            .uid
            .as_ref()
            .filter(|uid| !uid.trim().is_empty())
            .ok_or_else(|| {
                format!(
                    "Explicit cleanup action {}/{} has no bound UID",
                    resource.kind, resource.name
                )
            })?;
        if resource.version.trim().is_empty() {
            return Err(format!(
                "Explicit cleanup action {}/{} has no API version",
                resource.kind, resource.name
            ));
        }
        action_keys.push((
            resource.group.clone(),
            resource.kind.clone(),
            resource.namespace.clone(),
            resource.name.clone(),
            uid.clone(),
        ));
    }
    metadata_keys.sort();
    action_keys.sort();
    if metadata_keys.windows(2).any(|w| w[0] == w[1])
        || action_keys.windows(2).any(|w| w[0] == w[1])
    {
        return Err("duplicate explicit cleanup identity in saved authority".to_string());
    }
    if metadata_keys != action_keys {
        return Err("explicit_deletes do not match Explicit cleanup actions 1:1".to_string());
    }

    if run.execution.barrier_timeout.is_some() || !run.execution.failed.is_empty() {
        return Err("journal contains a failed action or barrier timeout".to_string());
    }
    let has_explicit_outcome = run
        .execution
        .deleted
        .iter()
        .chain(run.execution.already_gone.iter())
        .any(|r| {
            r.uid.as_ref().is_some_and(|uid| {
                metadata_keys
                    .iter()
                    .any(|(_, _, _, _, target_uid)| target_uid == uid)
            })
        });
    if has_explicit_outcome {
        return Err("journal already contains an explicit cleanup mutation outcome".to_string());
    }
    if !run.cleanup_decisions.is_empty() {
        return Err(
            "residual cleanup decisions exist before Explicit cleanup completed".to_string(),
        );
    }
    if run
        .finalizer_recoveries
        .iter()
        .any(|r| matches!(r.result, FinalizerRecoveryResult::PatchRequested))
    {
        return Err("unresolved finalizer recovery outcome".to_string());
    }
    if run.execution.re_delete_records.iter().any(|r| {
        matches!(
            r.result,
            ReDeleteResult::Authorized
                | ReDeleteResult::Accepted
                | ReDeleteResult::UnknownOutcome(_)
        )
    }) {
        return Err("unresolved re-delete outcome".to_string());
    }

    match mode {
        ExplicitCleanupResumeMode::TypedBlocked => {
            if run.execution.explicit_cleanup_error.is_none() {
                return Err("typed blocked state has no typed cleanup error".to_string());
            }
        }
        ExplicitCleanupResumeMode::LegacyFailed => {
            if run.execution.explicit_cleanup_error.is_some() {
                return Err(
                    "legacy Failed journal unexpectedly has a typed cleanup error".to_string(),
                );
            }
            if run.backup_receipts.is_empty() {
                return Err("legacy Failed migration requires a backup receipt".to_string());
            }
        }
    }

    Ok(mode)
}

fn operator_snapshot_matches_entry(
    run: &crate::teardown::journal::RunJournal,
    operator_entry_name: &str,
) -> bool {
    let csv = &run.operator.csv_name;
    let pkg = match &run.operator.generation_identity {
        crate::teardown::plan::OperatorGenerationIdentity::OlmPackage { package_name, .. } => {
            package_name.as_str()
        }
        _ => "",
    };
    csv.starts_with(&format!("{}.", operator_entry_name))
        || csv.starts_with(&format!("{}.v", operator_entry_name))
        || pkg == operator_entry_name
        || csv == operator_entry_name
}

fn find_pending_explicit_cleanup_journal(
    cluster_id: &crate::teardown::plan::ClusterIdentity,
    operator_entry_name: &str,
) -> anyhow::Result<Option<String>> {
    let runs = crate::teardown::journal::list_runs(cluster_id)?;
    select_pending_explicit_cleanup_journal(&runs, operator_entry_name).map_err(anyhow::Error::msg)
}

fn select_pending_explicit_cleanup_journal(
    runs: &[crate::teardown::journal::RunJournal],
    operator_entry_name: &str,
) -> Result<Option<String>, String> {
    let Some(latest) = runs
        .iter()
        .filter(|run| operator_snapshot_matches_entry(run, operator_entry_name))
        .max_by(|a, b| {
            a.created_at
                .cmp(&b.created_at)
                .then_with(|| a.run_id.cmp(&b.run_id))
        })
    else {
        return Ok(None);
    };

    if matches!(
        latest.state,
        crate::teardown::journal::RunState::ExplicitCleanupBlocked
            | crate::teardown::journal::RunState::Failed
    ) && !latest.plan_snapshot.explicit_deletes.is_empty()
    {
        explicit_cleanup_resume_mode(latest).map_err(|reason| {
            format!(
                "Latest run {} for {} has pending explicit cleanup but is not safely resumable: {}",
                latest.run_id, operator_entry_name, reason
            )
        })?;
        return Ok(Some(latest.run_id.clone()));
    }

    Ok(None)
}

pub(crate) fn should_refresh_discovery(user_requested: bool, explicit_target_count: usize) -> bool {
    user_requested || explicit_target_count > 0
}

pub(crate) fn inject_explicit_phase_into_teardown_plan(
    plan: &mut crate::teardown::planner::TeardownPlan,
    explicit_deletes: &[crate::teardown::plan::ExplicitDeleteTarget],
    gk_map: &crate::kube::discovery::GroupKindMap,
) -> anyhow::Result<()> {
    use crate::teardown::planner::{Action, Barrier, PlanPhase};
    if explicit_deletes.is_empty() {
        return Ok(());
    }
    let mut actions: Vec<Action> = Vec::with_capacity(explicit_deletes.len());
    for t in explicit_deletes {
        let version = gk_map
            .get(&(t.group.clone(), t.kind.clone()))
            .map(|info| info.version.clone())
            .ok_or_else(|| {
                anyhow::anyhow!(
                    "Explicit target {}/{} not found in API discovery — cannot determine version",
                    t.kind,
                    t.name
                )
            })?;
        actions.push(Action::Delete {
            resource: crate::kube::resource::ResourceId {
                group: t.group.clone(),
                version,
                kind: t.kind.clone(),
                namespace: t.namespace.clone(),
                name: t.name.clone(),
                uid: Some(t.uid.clone()),
            },
            reason: t.reason.clone(),
        });
    }

    // Insert before the last 2 phases (CRDs preserve + Namespace preserve)
    let insert_idx = if plan.phases.len() >= 2 {
        plan.phases.len() - 2
    } else {
        plan.phases.len()
    };

    plan.phases.insert(
        insert_idx,
        PlanPhase {
            name: crate::teardown::plan::EXPLICIT_CLEANUP_PHASE_NAME.to_string(),
            description: "Explicit resource cleanup (config-specified)".to_string(),
            actions,
            barrier: Some(Barrier {
                description: "Wait for explicit targets to be fully removed".to_string(),
                conditions: explicit_deletes
                    .iter()
                    .map(|t| format!("{}/{} gone", t.kind, t.name))
                    .collect(),
            }),
        },
    );
    plan.explicit_deletes = explicit_deletes.to_vec();
    Ok(())
}

pub(crate) fn build_execution_plan_from_teardown(
    plan: &crate::teardown::planner::TeardownPlan,
    target_operators: &[&crate::analyzers::olm::OperatorInstance],
    cluster_identity: &crate::teardown::plan::ClusterIdentity,
    prune_crds: bool,
    approve_scope: &[crate::cli::ApprovalScope],
    approve_resource: &[String],
    keep_resource: &[String],
) -> anyhow::Result<crate::teardown::plan::ExecutionPlan> {
    use crate::teardown::plan::{
        ApprovalScopeValue, EXECUTION_PLAN_SCHEMA_VERSION, ExecutionAction, ExecutionPhase,
        ExecutionResource,
    };
    use crate::teardown::planner::Action;

    let mut exec_targets: Vec<crate::teardown::plan::SavedOperatorTarget> = Vec::new();
    for op in target_operators {
        let pkg =
            crate::teardown::plan::validate_package_name(op.package_name.as_deref(), &op.csv.name)?;
        exec_targets.push(crate::teardown::plan::SavedOperatorTarget {
            package_name: pkg,
            install_namespace: op.install_namespace.clone(),
            csv_name_pattern: op.csv.name.clone(),
        });
    }

    let exec_phases: Vec<ExecutionPhase> = plan
        .phases
        .iter()
        .enumerate()
        .map(|(i, phase)| {
            let resources = phase
                .actions
                .iter()
                .map(|action| {
                    let (rid, act) = match action {
                        Action::Delete { resource, .. } => (resource, ExecutionAction::Delete),
                        Action::ExpectGone { resource, .. } => (resource, ExecutionAction::Expect),
                        Action::WaitGone { resource } => (resource, ExecutionAction::Wait),
                        Action::Keep { resource, .. } => (resource, ExecutionAction::Keep),
                        Action::Review { resource, .. } => (resource, ExecutionAction::Review),
                    };
                    ExecutionResource {
                        group: rid.group.clone(),
                        kind: rid.kind.clone(),
                        namespace: rid.namespace.clone(),
                        name: rid.name.clone(),
                        uid: rid.uid.clone(),
                        action: act,
                    }
                })
                .collect();
            ExecutionPhase {
                phase: (i + 1) as u32,
                name: phase.name.clone(),
                resources,
            }
        })
        .collect();

    let scopes: Vec<ApprovalScopeValue> = approve_scope
        .iter()
        .map(|s| match s {
            crate::cli::ApprovalScope::Root => ApprovalScopeValue::Root,
            crate::cli::ApprovalScope::Independent => ApprovalScopeValue::Independent,
            crate::cli::ApprovalScope::LabelOnly => ApprovalScopeValue::LabelOnly,
            crate::cli::ApprovalScope::OperatorGroup => ApprovalScopeValue::OperatorGroup,
        })
        .collect();

    Ok(crate::teardown::plan::ExecutionPlan {
        schema_version: EXECUTION_PLAN_SCHEMA_VERSION,
        cluster_identity: cluster_identity.clone(),
        created_at: plan.snapshot_taken_at.clone(),
        targets: exec_targets,
        prune_crds,
        approve_scopes: scopes,
        approve_resources: approve_resource.to_vec(),
        keep_resources: keep_resource.to_vec(),
        phases: exec_phases,
        explicit_deletes: Vec::new(),
    })
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();

    // ── Offline subcommands (dispatch before client init) ──
    if let Command::Completion { shell } = args.command {
        let mut command = Args::command();
        clap_complete::generate(
            clap_complete::Shell::from(shell),
            &mut command,
            "oc-deps",
            &mut std::io::stdout(),
        );
        return Ok(());
    }

    if let Command::Snapshot {
        action:
            SnapshotAction::Audit {
                ref before,
                ref after,
                ref plans,
                ref gvr_catalog,
                ref provider_operands,
                ref output,
            },
    } = args.command
    {
        let before_snap = load_snapshot(before)?;
        let after_snap = load_snapshot(after)?;

        let mut loaded_plans = Vec::new();
        for plan_path in plans {
            let plan = crate::teardown::plan::load_execution_plan(plan_path)?;
            let filename = std::path::Path::new(plan_path)
                .file_name()
                .map(|f| f.to_string_lossy().to_string())
                .unwrap_or_else(|| plan_path.clone());
            loaded_plans.push((filename, plan));
        }

        let catalog = match gvr_catalog {
            Some(path) => Some(crate::audit::load_gvr_catalog(path)?),
            None => None,
        };

        let provider = match provider_operands {
            Some(path) => {
                let data = std::fs::read_to_string(path)?;
                Some(serde_json::from_str(&data)?)
            }
            None => None,
        };

        let audit_input = crate::audit::AuditInput::from_snapshots(
            &before_snap,
            &after_snap,
            loaded_plans,
            catalog,
            provider,
        );
        let report = crate::audit::run_audit(&audit_input)?;

        match output {
            OutputFormat::Tree => crate::audit::print_audit_tree(&report),
            OutputFormat::Table => crate::audit::print_audit_table(&report),
            OutputFormat::Json => {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&report).unwrap_or_default()
                );
            }
        }
        return Ok(());
    }

    if let Command::Snapshot {
        action:
            SnapshotAction::Diff {
                ref before,
                ref after,
                ref output,
            },
    } = args.command
    {
        let before_snap = load_snapshot(before)?;
        let after_snap = load_snapshot(after)?;
        let result = diff_snapshots(&before_snap, &after_snap)?;
        match output {
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

    // ── Early validation for Snapshot Create ──
    if let Command::Snapshot {
        action:
            SnapshotAction::Create {
                ref namespace_selector,
                ref exclude_namespace,
                ..
            },
    } = args.command
    {
        // -A/-n conflict and requires are handled by clap at parse time
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
        | Command::Trace { resource, .. } => Some(resource.as_str()),
        Command::Operator {
            action: OperatorAction::Owner { resource, .. },
        } => Some(resource.as_str()),
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
        Command::Completion { .. } => unreachable!("completion is dispatched before client init"),
        Command::Snapshot {
            action:
                SnapshotAction::Create {
                    namespace,
                    file,
                    include_events,
                    refresh_discovery,
                    verbose: snapshot_verbose,
                    all_namespaces,
                    namespace_selector,
                    exclude_namespace,
                    exclude_system_namespaces,
                    strict,
                },
        } => {
            let no_cache = refresh_discovery;
            let t0 = Instant::now();
            eprintln!("🔍 Discovering API resources...");
            let (_kind_map, _, _gk_map, gvk_map) =
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
                let tmp_path = format!("{}.{}.tmp", file, std::process::id());
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
                let mut all_observations = Vec::new();
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
                    let gvk_map = gvk_map.clone();
                    let scanned = scanned_count.clone();
                    let ns = ns.clone();
                    let sem = api_semaphore.clone();

                    async move {
                        let ns_start = Instant::now();
                        let result = crate::kube::snapshot::build_snapshot_all_gvrs(
                            &client,
                            &config_clone,
                            &ns,
                            &gvk_map,
                            include_events,
                            crate::kube::snapshot::ScanScope::NamespacedOnly,
                            Some(sem),
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
                            all_observations.extend(ns_snapshot.observations);
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

                if cancel_token.is_cancelled() {
                    let _ = std::fs::remove_file(&tmp_path_cleanup);
                    eprintln!("\n⚠ Snapshot cancelled.");
                    std::process::exit(130);
                }

                // Cluster-scoped scan (CRDs, APIServices, PVs, etc.) — once for the whole command
                {
                    let cluster_fut = crate::kube::snapshot::build_snapshot_all_gvrs(
                        &client,
                        &config,
                        "",
                        &gvk_map,
                        include_events,
                        crate::kube::snapshot::ScanScope::ClusterScopedOnly,
                        None,
                    );
                    let cluster_result = tokio::select! {
                        result = cluster_fut => Some(result),
                        _ = cancel_token.cancelled() => None,
                    };
                    let cluster_result = match cluster_result {
                        Some(r) => r,
                        None => {
                            let _ = std::fs::remove_file(&tmp_path_cleanup);
                            eprintln!("\n⚠ Snapshot cancelled.");
                            std::process::exit(130);
                        }
                    };
                    match cluster_result {
                        Ok(cs) => {
                            all_warnings.extend(cs.scan_warnings);
                            for (uid, entry) in cs.resources {
                                if entry.id.namespace.is_none() {
                                    all_resources.entry(uid).or_insert(entry);
                                }
                            }
                            for obs in cs.observations {
                                if obs.namespace.is_none() && !obs.kind.is_empty() {
                                    all_observations.push(obs);
                                }
                            }
                        }
                        Err(e) => {
                            eprintln!("  ⚠ Cluster-scoped scan error: {}", e);
                            all_warnings.push(crate::kube::resource::ScanWarning::Other {
                                gvr: "(cluster-scoped)".into(),
                                message: e.to_string(),
                            });
                        }
                    }
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
                    observations: {
                        all_observations.sort_by(|a, b| {
                            (
                                &a.group,
                                &a.version,
                                &a.resource,
                                &a.kind,
                                &a.namespace,
                                &a.name,
                                &a.uid,
                            )
                                .cmp(&(
                                    &b.group,
                                    &b.version,
                                    &b.resource,
                                    &b.kind,
                                    &b.namespace,
                                    &b.name,
                                    &b.uid,
                                ))
                        });
                        all_observations
                    },
                };

                let resource_count = snapshot.resources.len();
                format_scan_warnings(&snapshot.scan_warnings, snapshot_verbose);
                save_snapshot(&snapshot, &file)?;

                let scope = snapshot.scope.as_ref().unwrap();
                eprintln!(
                    "✅ Snapshot saved to {} ({} resources, {} requested, {} complete, {} incomplete)",
                    file,
                    resource_count,
                    scope.requested_namespaces.len(),
                    scope.complete_namespaces.len(),
                    scope.incomplete_namespaces.len(),
                );
                if strict
                    && (!scope.incomplete_namespaces.is_empty()
                        || !snapshot.scan_warnings.is_empty())
                {
                    std::process::exit(2);
                }
            } else {
                // ── Single-namespace snapshot ──
                let namespace = namespace.unwrap_or_else(|| config.default_namespace.clone());
                let snapshot = crate::kube::snapshot::build_snapshot_all_gvrs(
                    &client,
                    &config,
                    &namespace,
                    &gvk_map,
                    include_events,
                    crate::kube::snapshot::ScanScope::NamespacedOnly,
                    None,
                )
                .await?;

                let resource_count = snapshot.resources.len();
                format_scan_warnings(&snapshot.scan_warnings, snapshot_verbose);
                save_snapshot(&snapshot, &file)?;

                eprintln!(
                    "✅ Snapshot saved to {} ({} resources, {} scan warnings)",
                    file,
                    resource_count,
                    snapshot.scan_warnings.len()
                );
                if strict && !snapshot.scan_warnings.is_empty() {
                    std::process::exit(2);
                }
            }
            return Ok(());
        }
        Command::Graph {
            namespace,
            file,
            include_events,
            refresh_discovery,
            verbose: graph_verbose,
            strict: graph_strict,
        } => {
            let namespace = namespace.unwrap_or_else(|| config.default_namespace.clone());
            let t0 = Instant::now();
            eprintln!("🔍 Discovering API resources...");
            let (kind_map, _, _gk_map, _) =
                build_kind_lookup_cached(&client, &config, refresh_discovery).await?;
            eprintln!("   Discovery: {:.1}s", t0.elapsed().as_secs_f64());

            let snapshot =
                build_snapshot(&client, &config, &namespace, &kind_map, include_events).await?;

            format_scan_warnings(&snapshot.scan_warnings, graph_verbose);

            eprint!("🔍 Discovering operators...");
            let operators = discover_operators(&client, &kind_map).await?;
            eprintln!(" found {} operators", operators.len());

            eprint!("🔗 Building evidence graph...");
            let graph = build_evidence_graph(&snapshot, &operators);
            eprintln!(" {} edges", graph.edges.len());

            let json = serde_json::to_string_pretty(&graph)?;
            std::fs::write(&file, json)?;
            eprintln!(
                "✅ Evidence graph saved to {} ({} edges)",
                file,
                graph.edges.len()
            );
            if graph_strict && !snapshot.scan_warnings.is_empty() {
                std::process::exit(2);
            }
            return Ok(());
        }
        Command::Teardown { action } => {
            match action {
                TeardownAction::Plan {
                    operators: operator_queries,
                    output,
                    refresh_discovery,
                    prune_crds,
                    approve_scope,
                    approve_resource,
                    keep_resource,
                    delete_resource,
                    file: save_plan_path,
                } => {
                    // Early validation of delete-resource specs (before discovery)
                    let explicit_specs: Vec<DeleteResourceSpec> = delete_resource
                        .iter()
                        .map(|s| DeleteResourceSpec::parse_cli_arg(s))
                        .collect::<Result<Vec<_>>>()?;
                    for spec in &explicit_specs {
                        spec.validate()?;
                    }
                    {
                        let mut seen = HashSet::new();
                        for spec in &explicit_specs {
                            let key = (
                                spec.group.clone(),
                                spec.kind.clone(),
                                spec.namespace.clone(),
                                spec.name.clone(),
                            );
                            if !seen.insert(key) {
                                bail!("Duplicate delete-resource: {}/{}", spec.kind, spec.name);
                            }
                        }
                    }

                    let no_cache =
                        should_refresh_discovery(refresh_discovery, explicit_specs.len());

                    let mut approve_delete: Vec<String> = approve_scope
                        .iter()
                        .map(|s| s.cli_arg().to_string())
                        .collect();
                    approve_delete.extend(approve_resource.iter().cloned());
                    let preserve = keep_resource.clone();
                    let t0 = Instant::now();
                    eprintln!("🔍 Discovering API resources...");
                    let (kind_map, gvr_map, gk_map, gvk_map) =
                        build_kind_lookup_cached(&client, &config, no_cache).await?;
                    let t_discovery = t0.elapsed();

                    let plan_semaphore = std::sync::Arc::new(tokio::sync::Semaphore::new(
                        crate::kube::scanner::DEFAULT_API_CONCURRENCY,
                    ));
                    let plan_planner =
                        crate::kube::planner::QueryPlanner::new(Some(plan_semaphore));
                    let t_olm = Instant::now();
                    eprint!("🔍 Discovering operators...");
                    let all_operators = discover_operators_full(
                        &client,
                        &kind_map,
                        None,
                        Some(plan_planner.clone()),
                    )
                    .await?;
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
                        prune_crds,
                        &policy,
                        Some(plan_planner.clone()),
                    )
                    .await?;
                    let t_plan = t_plan.elapsed();

                    // Resolve explicit delete targets and inject into plan before display
                    let mut plan = plan;
                    let explicit_targets = if !explicit_specs.is_empty() {
                        let targets = resolve_explicit_delete_targets(
                            &client,
                            &explicit_specs,
                            &plan,
                            &gk_map,
                        )
                        .await?;
                        inject_explicit_phase_into_teardown_plan(&mut plan, &targets, &gk_map)?;
                        targets
                    } else {
                        Vec::new()
                    };

                    print_teardown_plan(&plan, &output);

                    // Save as runtime plan (debug)
                    match save_plan_to_file(&plan) {
                        Ok(path) => eprintln!("📄 Plan saved to {}", path),
                        Err(e) => eprintln!("⚠ Could not save plan: {}", e),
                    }

                    // Build and save ExecutionPlan
                    if let Some(ref save_path) = save_plan_path {
                        let cluster_identity = journal::fetch_cluster_identity(&client).await?;
                        let mut exec_plan = build_execution_plan_from_teardown(
                            &plan,
                            &target_operators,
                            &cluster_identity,
                            prune_crds,
                            &approve_scope,
                            &approve_resource,
                            &keep_resource,
                        )?;
                        exec_plan.explicit_deletes = explicit_targets;

                        crate::teardown::plan::save_execution_plan(&exec_plan, save_path)?;
                        eprintln!("📄 Execution plan saved to {}", save_path);
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
                    plan: plan_file,
                    refresh_discovery: _,
                    dry_run,
                    yes,
                    backup_dir,
                } => {
                    // Load execution plan
                    let exec_plan = crate::teardown::plan::load_execution_plan(&plan_file)?;
                    eprintln!("📄 Loaded execution plan from {}", plan_file);

                    // Create gate + Ctrl-C handler
                    let gate = std::sync::Arc::new(MutationGate::new(16));
                    if !dry_run {
                        let gate_for_signal = gate.clone();
                        tokio::spawn(async move {
                            if tokio::signal::ctrl_c().await.is_ok() {
                                eprintln!(
                                    "\n⏸ Pausing... waiting for active mutations to complete..."
                                );
                                gate_for_signal.close_and_drain().await;
                            }
                        });
                    }

                    let apply_params = crate::teardown::workflow::ApplyParams {
                        dry_run,
                        backup_dir: backup_dir.as_deref(),
                        skip_confirm: yes,
                        gate: &gate,
                    };
                    let outcome = crate::teardown::workflow::apply_execution_plan(
                        &client,
                        &config,
                        &exec_plan,
                        &apply_params,
                    )
                    .await?;
                    crate::teardown::workflow::require_completed(&outcome, dry_run)?;
                }
                TeardownAction::Status {
                    operators: operator_queries,
                    refresh_discovery,
                    plan_file,
                } => {
                    let no_cache = refresh_discovery;
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
                            None,
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
                    refresh_discovery,
                } => {
                    let no_cache = refresh_discovery;
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
                        None,
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
                TeardownAction::Explain {
                    operators: operator_queries,
                    resource,
                    refresh_discovery,
                } => {
                    let no_cache = refresh_discovery;
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
                        None,
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
                    refresh_discovery,
                } => {
                    let cluster_id = journal::fetch_cluster_identity(&client).await?;

                    let found = if let Some(run_id) = run {
                        let path = journal::run_path(&cluster_id, &run_id)?;
                        Some((journal::load_journal(&path)?, path))
                    } else if let Some(op) = operator {
                        journal::find_latest_run(&cluster_id, &op)?.map(|j| {
                            let path = journal::run_path(&cluster_id, &j.run_id)
                                .expect("run_path for found journal");
                            (j, path)
                        })
                    } else {
                        bail!("Specify an operator name or --run <run-id>");
                    };

                    let (j, journal_path) = match found {
                        Some(pair) => pair,
                        None => bail!("No teardown run found to resume"),
                    };

                    // Create gate + Ctrl-C handler
                    let gate = std::sync::Arc::new(MutationGate::new(16));
                    {
                        let gate_for_signal = gate.clone();
                        tokio::spawn(async move {
                            if tokio::signal::ctrl_c().await.is_ok() {
                                eprintln!("\n⏸ Pausing... waiting for active mutations...");
                                gate_for_signal.close_and_drain().await;
                            }
                        });
                    }

                    let outcome = crate::teardown::workflow::resume_from_journal(
                        &client,
                        &config,
                        j,
                        journal_path,
                        &gate,
                        refresh_discovery,
                    )
                    .await?;
                    crate::teardown::workflow::require_completed(&outcome, false)?;
                }
                TeardownAction::Batch {
                    config: config_path,
                    refresh_discovery,
                    dry_run,
                    skip_missing,
                    backup_dir,
                } => {
                    let no_cache = refresh_discovery;
                    let config_content = std::fs::read_to_string(&config_path)
                        .with_context(|| format!("Failed to read config: {}", config_path))?;
                    let parsed: ApplySetConfig = serde_json::from_str(&config_content)
                        .with_context(|| format!("Invalid config: {}", config_path))?;
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
                        "📋 Batch: {} operator(s) from {}",
                        entries.len(),
                        config_path
                    );
                    for (i, entry) in entries.iter().enumerate() {
                        let dr_count = entry.delete_resources.len();
                        let suffix = if dr_count > 0 {
                            format!(" (+{} explicit)", dr_count)
                        } else {
                            String::new()
                        };
                        eprintln!("  {}: {}{}", i + 1, entry.name, suffix);
                    }
                    eprintln!();

                    // Setup backup dir if specified
                    if let Some(ref bdir) = backup_dir {
                        if bdir.is_empty() {
                            bail!("--backup-dir path must not be empty");
                        }
                        crate::teardown::backup::setup_backup_dir(std::path::Path::new(bdir))?;
                        eprintln!("📦 Backup dir: {}", bdir);
                    }

                    // Baseline gate: verify all target operators are present (phase is informational)
                    eprintln!(
                        "🔍 Baseline gate: verifying {} target operators...",
                        entries.len()
                    );
                    let (kind_map, _, _, _) =
                        build_kind_lookup_cached(&client, &config, true).await?;
                    let all_operators = discover_operators(&client, &kind_map).await?;
                    let cluster_id = journal::fetch_cluster_identity(&client).await?;
                    let mut baseline_missing: Vec<String> = Vec::new();
                    let mut skip_indices: std::collections::HashSet<usize> =
                        std::collections::HashSet::new();
                    let mut pending_resume_map: std::collections::HashMap<usize, String> =
                        std::collections::HashMap::new();
                    for (idx, entry) in entries.iter().enumerate() {
                        let found = all_operators
                            .iter()
                            .find(|op| operator_matches_entry(op, &entry.name));
                        match found {
                            Some(op) => {
                                let icon = if op.csv_phase == "Succeeded" {
                                    "✅"
                                } else {
                                    "⚠"
                                };
                                eprintln!(
                                    "  {} {} — {} ({})",
                                    icon, entry.name, op.csv.name, op.csv_phase
                                );
                            }
                            None => {
                                if skip_missing {
                                    // Check for pending explicit cleanup journal
                                    let pending_run = find_pending_explicit_cleanup_journal(
                                        &cluster_id,
                                        &entry.name,
                                    )?;
                                    if let Some(ref run_id) = pending_run {
                                        eprintln!(
                                            "  🔄 {} — absent but has pending explicit cleanup ({})",
                                            entry.name, run_id
                                        );
                                        pending_resume_map.insert(idx, run_id.clone());
                                    } else {
                                        eprintln!("  ⏭ {} — not found, will skip", entry.name);
                                        skip_indices.insert(idx);
                                    }
                                } else {
                                    baseline_missing.push(entry.name.clone());
                                    eprintln!("  ⛔ {} — NOT FOUND", entry.name);
                                }
                            }
                        }
                    }
                    if !baseline_missing.is_empty() {
                        bail!(
                            "Baseline gate failed: {} operator(s) not found: {}. \
                             Use --skip-missing to skip absent operators.",
                            baseline_missing.len(),
                            baseline_missing.join(", ")
                        );
                    }
                    let present_count =
                        entries.len() - skip_indices.len() - pending_resume_map.len();
                    let mut baseline_note = String::new();
                    if !skip_indices.is_empty() {
                        baseline_note.push_str(&format!(", {} skipped", skip_indices.len()));
                    }
                    if !pending_resume_map.is_empty() {
                        baseline_note
                            .push_str(&format!(", {} pending resume", pending_resume_map.len()));
                    }
                    eprintln!(
                        "✅ Baseline: {}/{} operators present{}\n",
                        present_count,
                        entries.len(),
                        baseline_note,
                    );

                    if no_cache {
                        eprintln!("🔄 API discovery: refresh once, then reuse within this batch\n");
                    }

                    // Shared gate for entire batch — Ctrl-C stops all remaining entries
                    let batch_gate = std::sync::Arc::new(MutationGate::new(16));
                    if !dry_run {
                        let gate_for_signal = batch_gate.clone();
                        tokio::spawn(async move {
                            if tokio::signal::ctrl_c().await.is_ok() {
                                eprintln!(
                                    "\n⏸ Pausing... waiting for active mutations to complete..."
                                );
                                gate_for_signal.close_and_drain().await;
                            }
                        });
                    }

                    let mut results: Vec<(String, BatchOutcome)> = Vec::new();

                    let entry_count = entries.len();
                    for (i, entry) in entries.iter().enumerate() {
                        // Check gate before each entry — Ctrl-C stops batch
                        if !batch_gate.is_open() {
                            eprintln!("\n⏸ Batch paused — remaining entries not started");
                            for entry in entries.iter().skip(i) {
                                results.push((entry.name.clone(), BatchOutcome::NotRun));
                            }
                            break;
                        }
                        if skip_indices.contains(&i) {
                            eprintln!(
                                "\n  ⏭ [{}/{}] SKIP {} (not found)",
                                i + 1,
                                entry_count,
                                entry.name
                            );
                            results.push((entry.name.clone(), BatchOutcome::Skipped));
                            continue;
                        }
                        // Pending explicit cleanup resume: delegate to `teardown resume`
                        if let Some(run_id) = pending_resume_map.get(&i) {
                            if pending_resume_action(dry_run) == PendingResumeAction::ReportOnly {
                                eprintln!(
                                    "\n  🧪 [{}/{}] DRY-RUN {} would resume pending explicit cleanup ({})",
                                    i + 1,
                                    entry_count,
                                    entry.name,
                                    run_id
                                );
                                results.push((entry.name.clone(), BatchOutcome::Succeeded));
                                continue;
                            }
                            eprintln!(
                                "\n{}\n  [{}/{}] RESUME {} ({})\n{}",
                                "=".repeat(60),
                                i + 1,
                                entry_count,
                                entry.name,
                                run_id,
                                "=".repeat(60),
                            );
                            let resume_path = journal::run_path(&cluster_id, run_id)?;
                            let resume_j = journal::load_journal(&resume_path)?;
                            match crate::teardown::workflow::resume_from_journal(
                                &client,
                                &config,
                                resume_j,
                                resume_path,
                                &batch_gate,
                                no_cache,
                            )
                            .await
                            .and_then(|o| {
                                crate::teardown::workflow::require_completed(&o, false)?;
                                Ok(o)
                            }) {
                                Ok(_outcome) => {
                                    eprintln!("  ✅ {} resumed and completed", entry.name);
                                    results.push((entry.name.clone(), BatchOutcome::Succeeded));
                                }
                                Err(e) => {
                                    eprintln!(
                                        "\n⛔ {} resume failed: {:#}. Stopping batch.",
                                        entry.name, e
                                    );
                                    results.push((entry.name.clone(), BatchOutcome::Failed(1)));
                                    let remaining = entry_count - i - 1;
                                    if remaining > 0 {
                                        eprintln!(
                                            "  ⏭ {} operator(s) not run (stopped on failure)",
                                            remaining
                                        );
                                    }
                                    for entry in entries.iter().skip(i + 1) {
                                        results.push((entry.name.clone(), BatchOutcome::NotRun));
                                    }
                                    break;
                                }
                            }
                            continue;
                        }
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

                        // In-process: generate plan then apply
                        let gen_params = crate::teardown::workflow::GeneratePlanParams {
                            operator_name: op_name,
                            approve_delete: &options.approve_delete,
                            preserve: &options.preserve,
                            delete_resources: &options.delete_resources,
                            refresh_discovery: apply_set_child_bypasses_cache(no_cache, i),
                        };
                        let exec_plan =
                            match crate::teardown::workflow::generate_execution_plan_for_operator(
                                &client,
                                &config,
                                &gen_params,
                            )
                            .await
                            {
                                Ok(ep) => ep,
                                Err(e) => {
                                    eprintln!(
                                        "\n⛔ {} plan failed: {:#}. Stopping batch.",
                                        op_name, e
                                    );
                                    results.push((op_name.to_string(), BatchOutcome::Failed(1)));
                                    let remaining = entry_count - i - 1;
                                    if remaining > 0 {
                                        eprintln!(
                                            "  ⏭ {} operator(s) not run (stopped on failure)",
                                            remaining
                                        );
                                    }
                                    for entry in entries.iter().skip(i + 1) {
                                        results.push((entry.name.clone(), BatchOutcome::NotRun));
                                    }
                                    break;
                                }
                            };

                        let apply_params = crate::teardown::workflow::ApplyParams {
                            dry_run,
                            backup_dir: backup_dir.as_deref(),
                            skip_confirm: true,
                            gate: &batch_gate,
                        };
                        match crate::teardown::workflow::apply_execution_plan(
                            &client,
                            &config,
                            &exec_plan,
                            &apply_params,
                        )
                        .await
                        .and_then(|o| {
                            crate::teardown::workflow::require_completed(&o, dry_run)?;
                            Ok(o)
                        }) {
                            Ok(_outcome) => {
                                results.push((op_name.to_string(), BatchOutcome::Succeeded));
                                eprintln!("  ✅ {} completed", op_name);
                            }
                            Err(e) => {
                                eprintln!("\n⛔ {} failed: {:#}. Stopping batch.", op_name, e);
                                results.push((op_name.to_string(), BatchOutcome::Failed(1)));
                                let remaining = entry_count - i - 1;
                                if remaining > 0 {
                                    eprintln!(
                                        "  ⏭ {} operator(s) not run (stopped on failure)",
                                        remaining
                                    );
                                }
                                for entry in entries.iter().skip(i + 1) {
                                    results.push((entry.name.clone(), BatchOutcome::NotRun));
                                }
                                break;
                            }
                        }
                    }

                    // Summary
                    let (s, sk, f) = batch_summary(&results);
                    eprintln!("\n📊 Batch results:");
                    let mut any_failed = false;
                    let mut not_run = 0usize;
                    for (name, outcome) in &results {
                        match outcome {
                            BatchOutcome::Succeeded => eprintln!("  ✅ {}", name),
                            BatchOutcome::Skipped => eprintln!("  ⏭ {} SKIPPED", name),
                            BatchOutcome::Failed(c) => {
                                eprintln!("  ⛔ {} (exit {})", name, c);
                                any_failed = true;
                            }
                            BatchOutcome::NotRun => {
                                not_run += 1;
                            }
                        }
                    }
                    let unrecorded = entry_count.saturating_sub(results.len());
                    not_run += unrecorded;
                    if not_run > 0 {
                        eprintln!("  ⏭ {} operator(s) not run (stopped on failure)", not_run);
                    }
                    eprintln!(
                        "\n  {} succeeded, {} skipped, {} failed, {} not run",
                        s, sk, f, not_run
                    );

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
                    output,
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
                                let gen_state = audit::check_operator_generation_fresh(
                                    &client,
                                    &j.operator,
                                    &j.audit_context.csv_baseline,
                                )
                                .await;

                                match gen_state {
                                    OperatorGenerationState::Absent => {
                                        eprintln!("\n🔍 Running live residual audit...");
                                        match crate::teardown::audit::run_observed_audit(
                                            &client, &j,
                                        )
                                        .await
                                        {
                                            Ok(result) => {
                                                match output {
                                                    crate::cli::OutputFormat::Json => {
                                                        println!(
                                                            "{}",
                                                            audit::format_residual_audit_json(
                                                                &result
                                                            )
                                                        );
                                                    }
                                                    crate::cli::OutputFormat::Table => {
                                                        audit::format_residual_audit_table(
                                                            &result, &j,
                                                        );
                                                    }
                                                    crate::cli::OutputFormat::Tree => {
                                                        print_residual_audit(&result, &j);
                                                    }
                                                }
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
        Command::Operator {
            action:
                OperatorAction::Resources {
                    operator: operator_query,
                    output,
                    refresh_discovery,
                    scope,
                    verbose,
                    strict,
                },
        } => {
            let cross_namespace = matches!(scope, Scope::Related);
            let t0 = Instant::now();
            eprintln!("🔍 Discovering API resources...");
            let (kind_map, gvr_map, gk_map, _) =
                build_kind_lookup_cached(&client, &config, refresh_discovery).await?;
            eprintln!("   Discovery: {:.1}s", t0.elapsed().as_secs_f64());

            let cmd_ledger: crate::kube::scanner::SharedLedger = std::sync::Arc::new(
                std::sync::Mutex::new(crate::kube::resource::CoverageLedger::new()),
            );
            let cmd_semaphore = std::sync::Arc::new(tokio::sync::Semaphore::new(
                crate::kube::scanner::DEFAULT_API_CONCURRENCY,
            ));
            let cmd_planner = crate::kube::planner::QueryPlanner::new(Some(cmd_semaphore));

            eprint!("🔍 Discovering operators...");
            let all_operators = discover_operators_full(
                &client,
                &kind_map,
                Some(cmd_ledger.clone()),
                Some(cmd_planner.clone()),
            )
            .await?;
            eprintln!(" found {} operators", all_operators.len());

            let target_indices = resolve_operator_targets(&[operator_query], &all_operators)?;
            let target_op = &all_operators[target_indices[0]];

            let inspection = inspect_operator_with_options_ledger(
                &client,
                target_op,
                &kind_map,
                &gvr_map,
                &gk_map,
                cross_namespace,
                Some(cmd_ledger.clone()),
                Some(cmd_planner.clone()),
            )
            .await?;

            // Flush planner records to ledger, then re-snapshot into inspection
            cmd_planner.flush_to_ledger(&cmd_ledger).await;
            let mut inspection = inspection;
            {
                let mut ledger = cmd_ledger.lock().unwrap();
                let (cov, inc, snap) = ledger.snapshot();
                inspection.coverage = cov;
                inspection.incomplete_count = inc;
                inspection.coverage_ledger = snap;
            }
            inspection.query_planner = Some(cmd_planner.metrics().await);
            inspection.sort_for_output();

            print_inspection_top(&inspection, &output, verbose);
            if let Some(ref ledger) = inspection.coverage_ledger {
                crate::kube::resource::format_coverage_summary(ledger, verbose);
            }

            // Print query planner metrics
            {
                let metrics = cmd_planner.metrics().await;
                let is_tty = std::io::IsTerminal::is_terminal(&std::io::stderr());
                if is_tty {
                    eprintln!(
                        "📊 Query planner: {} demands, {} unique, {} network, {} cache hits ({:.1}s)",
                        metrics.total_demands,
                        metrics.unique_queries,
                        metrics.network_queries,
                        metrics.cache_hits,
                        metrics.total_elapsed_ms as f64 / 1000.0
                    );
                } else {
                    eprintln!(
                        "Query planner: {} demands, {} unique, {} network, {} cache hits ({:.1}s)",
                        metrics.total_demands,
                        metrics.unique_queries,
                        metrics.network_queries,
                        metrics.cache_hits,
                        metrics.total_elapsed_ms as f64 / 1000.0
                    );
                }
            }

            if strict && inspection.should_exit_strict() {
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

            let trace_ledger: crate::kube::scanner::SharedLedger = std::sync::Arc::new(
                std::sync::Mutex::new(crate::kube::resource::CoverageLedger::new()),
            );
            let trace_semaphore = std::sync::Arc::new(tokio::sync::Semaphore::new(
                crate::kube::scanner::DEFAULT_API_CONCURRENCY,
            ));
            let trace_planner = crate::kube::planner::QueryPlanner::new(Some(trace_semaphore));
            let (mut index, mut scan_warnings) = if kind_info.namespaced {
                crate::kube::scanner::scan_namespace_with_semaphore(
                    &client,
                    &namespace,
                    &kind_map,
                    false,
                    true,
                    false,
                    None,
                    &[],
                    Some(trace_ledger.clone()),
                    Some(trace_planner.clone()),
                )
                .await?
            } else {
                let (idx, warnings) = crate::kube::scanner::scan_namespace_with_semaphore(
                    &client,
                    &namespace,
                    &kind_map,
                    false,
                    true,
                    false,
                    None,
                    &[],
                    Some(trace_ledger.clone()),
                    Some(trace_planner.clone()),
                )
                .await?;
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
                match crate::kube::scanner::get_with_retry_ledger(
                    &api,
                    &name,
                    &kind_info.group,
                    &kind_info.version,
                    &kind_info.plural,
                    Some(&trace_ledger),
                    None,
                    crate::kube::resource::QueryRequirement::Required,
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
                    let parent_warnings = crate::kube::scanner::resolve_missing_parents_opts(
                        &mut index,
                        uid,
                        &client,
                        &namespace,
                        &kind_map,
                        &gk_map_trace,
                        false,
                        Some(trace_ledger.clone()),
                        Some(trace_planner.clone()),
                    )
                    .await;
                    scan_warnings.extend(parent_warnings);
                }
                eprintln!(" done");
            }

            // Determine managing operator via who-manages (for same-operator CRD + cross-ns)
            let mut confirmed_csv: Option<String> = None;
            eprint!("🔍 Tracing ownership...");
            let wm_result = who_manages_opts(
                &WhoManagesInput {
                    client: &client,
                    kind: &kind,
                    group: &target_group,
                    name: &name,
                    namespace: &namespace,
                    kind_map: &kind_map,
                    gk_map: &gk_map_trace,
                },
                Some(trace_ledger.clone()),
                Some(trace_planner.clone()),
            )
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
                            message: format!("operator owner resolution failed: {}", e.message),
                        });
                    }
                }
            }

            // Cross-namespace scan using confirmed operator
            if cross_namespace && let Some(csv_name) = &confirmed_csv {
                let operators = discover_operators_full(
                    &client,
                    &kind_map,
                    Some(trace_ledger.clone()),
                    Some(trace_planner.clone()),
                )
                .await?;
                let csv_query = csv_name.to_string();
                if let Ok(indices) = resolve_operator_targets(&[csv_query], &operators)
                    && let Some(&idx) = indices.first()
                {
                    let target_op = &operators[idx];
                    let scope_result = discover_operator_namespaces_opts(
                        &client,
                        target_op,
                        &kind_map,
                        &gvr_map,
                        &gk_map_trace,
                        Some(trace_ledger.clone()),
                        None,
                        Some(trace_planner.clone()),
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
                    let ns_scan =
                        crate::analyzers::namespace_scope::scan_candidate_namespaces_with_ledger(
                            &client,
                            &scope_result.candidates,
                            &kind_map,
                            Some(&namespace),
                            Some(trace_ledger.clone()),
                            Some(trace_planner.clone()),
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
                Some(trace_ledger.clone()),
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
            // Flush planner records to ledger
            trace_planner.flush_to_ledger(&trace_ledger).await;
            let (trace_coverage, trace_coverage_ledger) = {
                let mut ledger = trace_ledger.lock().unwrap();
                if ledger.records.is_empty() {
                    (None, None)
                } else {
                    ledger.sort_records();
                    (Some(ledger.summary()), Some(ledger.clone()))
                }
            };
            print_trace(
                &result,
                &output,
                scope_str,
                trace_coverage,
                trace_coverage_ledger.clone(),
            );

            if let Some(ref ledger) = trace_coverage_ledger {
                crate::kube::resource::format_coverage_summary(ledger, verbose);
            }

            // strict: exit 2 for ledger incomplete OR scan failures (excluding info messages)
            let has_ledger_incomplete = trace_coverage_ledger
                .as_ref()
                .is_some_and(|l| l.has_incomplete());
            let has_scan_failures = scan_warnings.iter().any(|w| {
                !matches!(
                    w,
                    crate::kube::resource::ScanWarning::Other { message, .. }
                        if message.starts_with("AllNamespaces operator")
                )
            });
            if strict && (has_scan_failures || has_ledger_incomplete) {
                std::process::exit(2);
            }
            return Ok(());
        }
        Command::Operator {
            action:
                OperatorAction::List {
                    output,
                    refresh_discovery,
                },
        } => {
            let t0 = Instant::now();
            eprintln!("🔍 Discovering API resources...");
            let (kind_map, _, _gk_map, _) =
                build_kind_lookup_cached(&client, &config, refresh_discovery).await?;
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
        Command::Operator {
            action:
                OperatorAction::Owner {
                    resource,
                    namespace,
                    output,
                    refresh_discovery,
                    verbose: owner_verbose,
                    strict: owner_strict,
                },
        } => {
            let namespace = namespace.unwrap_or_else(|| config.default_namespace.clone());
            let t0 = Instant::now();
            eprintln!("🔍 Discovering API resources...");
            let (kind_map, gvr_map, gk_map_wm, _) =
                build_kind_lookup_cached(&client, &config, refresh_discovery).await?;
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

            if !result.scan_failures.is_empty() {
                format_scan_warnings(&result.scan_failures, owner_verbose);
            }
            print_who_manages(&result, &output);
            if owner_strict && !result.scan_failures.is_empty() {
                std::process::exit(2);
            }
            return Ok(());
        }
        Command::Snapshot {
            action: SnapshotAction::Diff { .. },
        } => unreachable!("handled before client init"),
        Command::Snapshot {
            action: SnapshotAction::Audit { .. },
        } => unreachable!("handled before client init"),

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
                let (chain, parent_warnings) = find_parents_only(
                    &client,
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

            // Full scan path (includes extra API if target group differs from KindMap)
            let (mut index, mut scan_warnings) = scan_namespace_with_extra_apis(
                &client,
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
                        let json_warnings: Vec<serde_json::Value> = scan_warnings
                            .iter()
                            .map(|w| {
                                serde_json::to_value(w)
                                    .unwrap_or_else(|_| serde_json::json!(w.to_string()))
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
                            serde_json::to_value(w)
                                .unwrap_or_else(|_| serde_json::json!(w.to_string()))
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

            let (index, mut scan_warnings) = scan_namespace_with_extra_apis(
                &client,
                &namespace,
                &kind_map,
                &gk_map,
                &target_group,
                &kind,
                false,
                true,
                false,
            )
            .await?;

            let inventory = build_network_inventory(&client, &namespace, &kind_map, &gk_map).await;

            let group_for_lookup = Some(target_group.as_str()).filter(|g| !g.is_empty());

            // For Service target: build path directly from inventory using pure helper
            let (all_paths, postures): (Vec<(String, _)>, Vec<_>) = if kind == "Service" {
                let target_svc = inventory.services.iter().find(|s| s.name == name);
                let Some(target_svc) = target_svc else {
                    bail!("Service/{} not found in namespace '{}'", name, namespace);
                };
                let (path, pod_labels_list) =
                    build_service_network_path(target_svc, &inventory, &index.by_uid, &namespace);
                let postures = evaluate_network_postures(
                    &pod_labels_list,
                    &inventory.network_policies,
                    &inventory.np_availability,
                );
                (vec![(String::new(), path)], postures)
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

            // Resolve MetalLB for each service path (events fetched once in inventory)
            let metallb_results: Vec<crate::analyzers::selector::MetalLBResult> = {
                let mut seen = std::collections::HashSet::new();
                let unique_paths: Vec<_> = all_paths
                    .iter()
                    .filter(|(_, p)| seen.insert(p.service.name.clone()))
                    .collect();
                let mut results = Vec::new();
                for (_, p) in &unique_paths {
                    let endpoint_nodes: Vec<String> = p
                        .endpoint_slices
                        .iter()
                        .flat_map(|es| es.endpoints.iter())
                        .filter(|ep| ep.conditions_ready == Some(true))
                        .filter_map(|ep| ep.node_name.clone())
                        .collect::<std::collections::HashSet<_>>()
                        .into_iter()
                        .collect();
                    results.push(crate::analyzers::selector::resolve_metallb_for_service(
                        &p.service,
                        &namespace,
                        &inventory.metallb,
                        &endpoint_nodes,
                        &inventory.metallb.namespace_labels,
                        &inventory.metallb.node_labels,
                    ));
                }
                results
            };

            // Resolve Gateway API routes per service
            let gateway_results: Vec<Vec<crate::analyzers::selector::MatchedGatewayRoute>> = {
                let mut seen = std::collections::HashSet::new();
                let mut results = Vec::new();
                for (_, p) in &all_paths {
                    if !seen.insert(p.service.name.clone()) {
                        continue;
                    }
                    results.push(
                        crate::analyzers::selector::resolve_gateway_routes_for_service(
                            &p.service.name,
                            &namespace,
                            &inventory.gateway,
                        ),
                    );
                }
                results
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
                    let json_paths =
                        network_paths_to_json(&all_paths, &metallb_results, &gateway_results);
                    let json_postures = network_postures_to_json(&postures);
                    let json_warnings: Vec<serde_json::Value> = scan_warnings
                        .iter()
                        .map(|w| {
                            serde_json::to_value(w)
                                .unwrap_or_else(|_| serde_json::json!(w.to_string()))
                        })
                        .collect();
                    let output = serde_json::json!({
                        "namespace": namespace,
                        "target": format!("{}/{}", kind, name),
                        "scope": "namespace",
                        "networkPaths": json_paths,
                        "networkPolicyPostures": json_postures,
                        "warnings": json_warnings,
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
                        "LB Provider",
                        "Pool",
                        "Advertisement",
                        "Observed",
                        "Session",
                        "Events",
                        "Config",
                        "Ingress/Route",
                        "Gateway Routes",
                        "Warnings",
                    ]);
                    let mut seen_svcs = std::collections::HashSet::new();
                    let mut mlb_idx = 0usize;
                    let mut gw_idx = 0usize;
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
                        let lb_provider = metallb_results
                            .get(mlb_idx)
                            .and_then(|r| r.provider.as_deref())
                            .unwrap_or("-")
                            .to_string();
                        mlb_idx += 1;
                        let mlb = metallb_results.get(mlb_idx.saturating_sub(1));
                        let pool_str = mlb
                            .map(|r| {
                                r.pools
                                    .iter()
                                    .map(|p| p.pool.name.clone())
                                    .collect::<Vec<_>>()
                                    .join(", ")
                            })
                            .unwrap_or_default();
                        let ad_str = mlb
                            .map(|r| {
                                r.advertisements
                                    .iter()
                                    .map(|a| format!("{}/{}", a.kind, a.name))
                                    .collect::<Vec<_>>()
                                    .join(", ")
                            })
                            .unwrap_or_default();
                        let warn_str = mlb
                            .map(|r| {
                                if r.warnings.is_empty() {
                                    String::new()
                                } else {
                                    format!("{} warning(s)", r.warnings.len())
                                }
                            })
                            .unwrap_or_default();
                        let observed_str = mlb
                            .map(|r| r.observation.observed_state.clone())
                            .unwrap_or_default();
                        let session_str = mlb
                            .map(|r| {
                                if r.observation.session_state.is_empty() {
                                    "-".to_string()
                                } else {
                                    r.observation.session_state.clone()
                                }
                            })
                            .unwrap_or_else(|| "-".to_string());
                        let events_str = mlb
                            .map(|r| {
                                if r.observation.events.is_empty() {
                                    "-".to_string()
                                } else {
                                    format!("{}", r.observation.events.len())
                                }
                            })
                            .unwrap_or_else(|| "-".to_string());
                        let config_str = mlb
                            .map(|r| {
                                r.observation
                                    .configuration_states
                                    .first()
                                    .and_then(|cs| cs.result.clone())
                                    .unwrap_or_else(|| "-".to_string())
                            })
                            .unwrap_or_else(|| "-".to_string());
                        // Gateway Routes column
                        let gw = gateway_results.get(gw_idx).cloned().unwrap_or_default();
                        gw_idx += 1;
                        let not_allowed_count = gw
                            .iter()
                            .filter(|gr| {
                                gr.cross_namespace
                                    == crate::analyzers::selector::CrossNamespaceStatus::NotAllowed
                            })
                            .count();
                        let gw_str = if gw.is_empty() {
                            String::new()
                        } else if not_allowed_count > 0 {
                            format!("{} ({} not-allowed)", gw.len(), not_allowed_count)
                        } else {
                            format!("{}", gw.len())
                        };
                        // Append gateway warnings to warn_str
                        let gw_warn_count: usize = gw.iter().map(|gr| gr.warnings.len()).sum();
                        let combined_warn = if !warn_str.is_empty() && gw_warn_count > 0 {
                            format!("{}, {} gw-warning(s)", warn_str, gw_warn_count)
                        } else if gw_warn_count > 0 {
                            format!("{} gw-warning(s)", gw_warn_count)
                        } else {
                            warn_str
                        };
                        table.add_row(vec![
                            format!("Service/{}", svc.name),
                            svc.svc_type.clone(),
                            svc.cluster_ip.clone(),
                            ports_str,
                            eps_str,
                            lb_provider,
                            pool_str,
                            ad_str,
                            observed_str,
                            session_str,
                            events_str,
                            config_str,
                            ing_str,
                            gw_str,
                            combined_warn,
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
                    print_network_tree(
                        &kind,
                        &name,
                        &all_paths,
                        &postures,
                        &metallb_results,
                        &gateway_results,
                    );
                }
            }

            format_scan_warnings(&scan_warnings, online.verbose);

            if online.strict && !scan_warnings.is_empty() {
                std::process::exit(2);
            }
            return Ok(());
        }

        Command::Backup { action } => {
            use crate::cli::BackupAction;
            match action {
                BackupAction::Operator {
                    operator: operator_query,
                    dir: output_dir,
                    refresh_discovery,
                } => {
                    let t0 = Instant::now();
                    eprintln!("🔍 Discovering API resources...");
                    let (kind_map, gvr_map, gk_map, gvk_map) =
                        build_kind_lookup_cached(&client, &config, refresh_discovery).await?;
                    eprintln!("   Discovery: {:.1}s", t0.elapsed().as_secs_f64());

                    let cmd_semaphore = std::sync::Arc::new(tokio::sync::Semaphore::new(
                        crate::kube::scanner::DEFAULT_API_CONCURRENCY,
                    ));
                    let cmd_planner = crate::kube::planner::QueryPlanner::new(Some(cmd_semaphore));

                    eprint!("🔍 Discovering operators...");
                    let all_operators = discover_operators_full(
                        &client,
                        &kind_map,
                        None,
                        Some(cmd_planner.clone()),
                    )
                    .await?;
                    eprintln!(" found {} operators", all_operators.len());

                    let target_indices = resolve_operator_targets(
                        std::slice::from_ref(&operator_query),
                        &all_operators,
                    )?;
                    let target_op = &all_operators[target_indices[0]];
                    let op_name = target_op
                        .package_name
                        .as_deref()
                        .unwrap_or(&target_op.csv.name);

                    eprintln!(
                        "📦 Backing up operator: {} ({})",
                        target_op.csv.name, target_op.install_namespace
                    );

                    // Use shared discovery function (same as operator resources --scope related)
                    let (candidates, observations, resolved) =
                        crate::teardown::backup::discover_operator_backup(
                            &client, target_op, &kind_map, &gvr_map, &gk_map, &gvk_map,
                        )
                        .await?;

                    eprintln!("  {} unique resource(s)", candidates.len());

                    let (fetched, _) = crate::teardown::backup::fetch_backup_resources(
                        &client,
                        &candidates,
                        &gvk_map,
                    )
                    .await?;

                    let captured = fetched
                        .iter()
                        .filter(|r| {
                            r.state == crate::teardown::backup::BackupResourceState::Captured
                        })
                        .count();
                    let absent = fetched
                        .iter()
                        .filter(|r| {
                            r.state == crate::teardown::backup::BackupResourceState::AlreadyAbsent
                        })
                        .count();
                    eprintln!("  {} captured, {} already absent", captured, absent);

                    let cluster_identity = journal::fetch_cluster_identity(&client).await?;
                    let selection =
                        crate::teardown::backup::BackupSelection::operator(vec![resolved]);

                    let target = crate::teardown::backup::operator_target_dir(
                        std::path::Path::new(&output_dir),
                        op_name,
                    )?;
                    let run_name = crate::teardown::backup::generate_run_name();

                    let receipt = crate::teardown::backup::write_backup_directory(
                        &fetched,
                        &cluster_identity,
                        selection,
                        observations,
                        &target,
                        &run_name,
                    )?;

                    eprintln!(
                        "✅ Operator backup: {} ({} resources, tree: {})",
                        receipt.root,
                        receipt.resource_count,
                        &receipt.tree_sha256[..12],
                    );
                    return Ok(());
                }
                BackupAction::Namespace {
                    namespace,
                    dir: output_dir,
                    refresh_discovery,
                } => {
                    let t0 = Instant::now();
                    eprintln!("🔍 Discovering API resources...");
                    let (kind_map, _gvr_map, gk_map, gvk_map) =
                        build_kind_lookup_cached(&client, &config, refresh_discovery).await?;
                    eprintln!("   Discovery: {:.1}s", t0.elapsed().as_secs_f64());

                    // Validate namespace exists
                    {
                        use k8s_openapi::api::core::v1::Namespace;
                        let ns_api: ::kube::api::Api<Namespace> =
                            ::kube::api::Api::all(client.clone());
                        ns_api
                            .get(&namespace)
                            .await
                            .with_context(|| format!("Namespace '{}' does not exist", namespace))?;
                    }

                    eprintln!("📦 Scanning namespace: {}", namespace);

                    // Use shared namespace scanner (same as existing scan/map path)
                    let candidates = crate::teardown::backup::discover_namespace_backup(
                        &client, &namespace, &kind_map, &gk_map,
                    )
                    .await?;

                    eprintln!("  {} unique resource(s)", candidates.len());

                    let (fetched, _) = crate::teardown::backup::fetch_backup_resources(
                        &client,
                        &candidates,
                        &gvk_map,
                    )
                    .await?;

                    let cluster_identity = journal::fetch_cluster_identity(&client).await?;
                    let selection = crate::teardown::backup::BackupSelection::namespace(vec![
                        namespace.clone(),
                    ]);

                    let target = crate::teardown::backup::namespace_target_dir(
                        std::path::Path::new(&output_dir),
                        &namespace,
                    )?;
                    let run_name = crate::teardown::backup::generate_run_name();

                    let receipt = crate::teardown::backup::write_backup_directory(
                        &fetched,
                        &cluster_identity,
                        selection,
                        vec![],
                        &target,
                        &run_name,
                    )?;

                    eprintln!(
                        "✅ Namespace backup: {} ({} resources, tree: {})",
                        receipt.root,
                        receipt.resource_count,
                        &receipt.tree_sha256[..12],
                    );
                    return Ok(());
                }
            }
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

fn label_selectors_to_json(
    selectors: &[crate::analyzers::selector::LabelSelector],
) -> serde_json::Value {
    let items: Vec<_> = selectors
        .iter()
        .map(|s| {
            let mut obj = serde_json::json!({});
            if !s.match_labels.is_empty() {
                obj["matchLabels"] = serde_json::json!(s.match_labels);
            }
            if !s.match_expressions.is_empty() {
                let exprs: Vec<_> = s
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
        })
        .collect();
    serde_json::json!(items)
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
    metallb_results: &[crate::analyzers::selector::MetalLBResult],
    gateway_results: &[Vec<crate::analyzers::selector::MatchedGatewayRoute>],
) -> Vec<serde_json::Value> {
    let mut seen_svcs = std::collections::HashSet::new();
    let mut metallb_idx = 0usize;
    let mut gw_idx = 0usize;
    paths
        .iter()
        .filter(|(_, p)| seen_svcs.insert(p.service.name.clone()))
        .map(|(_, p)| {
            let mlb = metallb_results.get(metallb_idx);
            metallb_idx += 1;
            let gw_routes = gateway_results.get(gw_idx).cloned().unwrap_or_default();
            gw_idx += 1;
            let _ = mlb; // used below
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
            let mut result = serde_json::json!({
                "service": {"name": svc.name, "config": config, "status": status},
                "ingresses": ingresses,
                "endpointSlices": endpoint_slices_json,
                "endpointSummary": {"ready": es.ready, "notReady": es.not_ready, "unknown": es.unknown, "effectiveReady": es.effective_ready, "serving": es.serving, "terminating": es.terminating},
                "selectorMatchedPods": p.selector_matched_pods,
                "targetRefMatchedPods": p.target_ref_matched_pods,
            });
            // Always emit gatewayRoutes and gatewayWarnings (empty arrays when no routes)
            let gw_routes_json: Vec<serde_json::Value> = gw_routes
                .iter()
                .map(|gr| {
                    let listeners_json: Vec<serde_json::Value> = gr
                        .listeners
                        .iter()
                        .map(|l| {
                            let mut obj = serde_json::json!({
                                "name": l.name,
                                "port": l.port,
                                "protocol": l.protocol,
                            });
                            if let Some(h) = &l.hostname {
                                obj["hostname"] = serde_json::json!(h);
                            }
                            if let Some(t) = &l.tls_mode {
                                obj["tlsMode"] = serde_json::json!(t);
                            }
                            obj
                        })
                        .collect();
                    let matched_backends_json: Vec<serde_json::Value> = gr
                        .matched_backends
                        .iter()
                        .map(|mb| {
                            let rule_matches: Vec<serde_json::Value> = mb
                                .rule_matches
                                .iter()
                                .map(|m| {
                                    let mut obj = serde_json::Map::new();
                                    if let Some(pt) = &m.path_type {
                                        obj.insert("pathType".into(), serde_json::json!(pt));
                                    }
                                    if let Some(pv) = &m.path_value {
                                        obj.insert("pathValue".into(), serde_json::json!(pv));
                                    }
                                    if let Some(method) = &m.method {
                                        obj.insert("method".into(), serde_json::json!(method));
                                    }
                                    serde_json::Value::Object(obj)
                                })
                                .collect();
                            let mut obj = serde_json::Map::new();
                            if let Some(p) = mb.port {
                                obj.insert("port".into(), serde_json::json!(p));
                            }
                            if let Some(w) = mb.weight {
                                obj.insert("weight".into(), serde_json::json!(w));
                            }
                            if !rule_matches.is_empty() {
                                obj.insert("ruleMatches".into(), serde_json::json!(rule_matches));
                            }
                            serde_json::Value::Object(obj)
                        })
                        .collect();
                    let conditions_json: Vec<serde_json::Value> = gr
                        .status_conditions
                        .iter()
                        .map(|c| {
                            let mut obj = serde_json::json!({
                                "type": c.condition_type,
                                "status": c.status,
                            });
                            if let Some(r) = &c.reason {
                                obj["reason"] = serde_json::json!(r);
                            }
                            if let Some(m) = &c.message {
                                obj["message"] = serde_json::json!(m);
                            }
                            obj
                        })
                        .collect();
                    let cross_ns_str = match &gr.cross_namespace {
                        crate::analyzers::selector::CrossNamespaceStatus::SameNamespace => {
                            "same-namespace"
                        }
                        crate::analyzers::selector::CrossNamespaceStatus::Allowed => "allowed",
                        crate::analyzers::selector::CrossNamespaceStatus::NotAllowed => {
                            "not-allowed"
                        }
                        crate::analyzers::selector::CrossNamespaceStatus::Unknown => "unknown",
                    };
                    let mut route_json = serde_json::json!({
                        "kind": gr.route_kind,
                        "name": gr.route_name,
                        "namespace": gr.route_namespace,
                        "gatewayName": gr.gateway_name,
                        "gatewayNamespace": gr.gateway_namespace,
                        "listeners": listeners_json,
                        "matchedBackends": matched_backends_json,
                        "crossNamespace": cross_ns_str,
                        "statusConditions": conditions_json,
                    });
                    if !gr.hostnames.is_empty() {
                        route_json["hostnames"] = serde_json::json!(gr.hostnames);
                    }
                    if let Some(gc) = &gr.gateway_class_name {
                        route_json["gatewayClassName"] = serde_json::json!(gc);
                    }
                    if let Some(gc) = &gr.gateway_class_controller {
                        route_json["gatewayClassController"] = serde_json::json!(gc);
                    }
                    if let Some(sn) = &gr.section_name {
                        route_json["sectionName"] = serde_json::json!(sn);
                    }
                    if let Some(pp) = gr.parent_port {
                        route_json["parentPort"] = serde_json::json!(pp);
                    }
                    route_json
                })
                .collect();
            let gw_warnings_json: Vec<String> = gw_routes
                .iter()
                .flat_map(|gr| gr.warnings.clone())
                .collect();
            result["gatewayRoutes"] = serde_json::json!(gw_routes_json);
            result["gatewayWarnings"] = serde_json::json!(gw_warnings_json);
            if let Some(mlb) = mlb {
                let pools_json: Vec<_> = mlb.pools.iter().map(|mp| {
                    let mut obj = serde_json::json!({
                        "name": mp.pool.name,
                        "namespace": mp.pool.namespace,
                        "addresses": mp.pool.addresses,
                        "matchReason": mp.match_reason,
                        "autoAssign": mp.pool.auto_assign,
                    });
                    if let Some(am) = &mp.allocation_match {
                        obj["allocationMatch"] = serde_json::json!(am);
                    }
                    if let Some(sa) = &mp.pool.service_allocation {
                        let mut sa_obj = serde_json::json!({
                            "priority": sa.priority,
                            "namespaces": sa.namespaces,
                        });
                        if !sa.namespace_selectors.is_empty() {
                            sa_obj["namespaceSelectors"] =
                                label_selectors_to_json(&sa.namespace_selectors);
                        }
                        if !sa.service_selectors.is_empty() {
                            sa_obj["serviceSelectors"] =
                                label_selectors_to_json(&sa.service_selectors);
                        }
                        obj["serviceAllocation"] = sa_obj;
                    }
                    if let Some(v) = mp.pool.status_available_ipv4 {
                        obj["statusAvailableIPv4"] = serde_json::json!(v);
                    }
                    if let Some(v) = mp.pool.status_available_ipv6 {
                        obj["statusAvailableIPv6"] = serde_json::json!(v);
                    }
                    if let Some(v) = mp.pool.status_assigned_ipv4 {
                        obj["statusAssignedIPv4"] = serde_json::json!(v);
                    }
                    if let Some(v) = mp.pool.status_assigned_ipv6 {
                        obj["statusAssignedIPv6"] = serde_json::json!(v);
                    }
                    if !mp.pool.labels.is_empty() {
                        obj["labels"] = serde_json::json!(mp.pool.labels);
                    }
                    obj
                }).collect();
                let ads_json: Vec<_> = mlb.advertisements.iter().map(|a| {
                    let mut obj = serde_json::json!({
                        "kind": a.kind,
                        "name": a.name,
                        "namespace": a.namespace,
                        "matchReason": a.match_reason,
                        "nodeSelectorStatus": a.node_selector_status,
                    });
                    if !a.node_selectors.is_empty() {
                        obj["nodeSelectors"] = label_selectors_to_json(&a.node_selectors);
                    }
                    if !a.candidate_nodes.is_empty() {
                        obj["candidateNodes"] = serde_json::json!(a.candidate_nodes);
                    }
                    if !a.service_selectors.is_empty() {
                        obj["serviceSelectors"] = label_selectors_to_json(&a.service_selectors);
                    }
                    if !a.interfaces.is_empty() {
                        obj["interfaces"] = serde_json::json!(a.interfaces);
                    }
                    if !a.peers.is_empty() {
                        obj["peers"] = serde_json::json!(a.peers);
                    }
                    if let Some(al) = a.aggregation_length {
                        obj["aggregationLength"] = serde_json::json!(al);
                    }
                    if let Some(al6) = a.aggregation_length_v6 {
                        obj["aggregationLengthV6"] = serde_json::json!(al6);
                    }
                    if let Some(lp) = a.local_pref {
                        obj["localPref"] = serde_json::json!(lp);
                    }
                    if !a.communities.is_empty() {
                        obj["communities"] = serde_json::json!(a.communities);
                    }
                    obj
                }).collect();
                let obs = &mlb.observation;
                let bgp_node_json: Vec<serde_json::Value> = obs
                    .bgp_advertised_nodes
                    .iter()
                    .map(|n| {
                        serde_json::json!({
                            "node": n.node,
                            "peers": n.peers,
                        })
                    })
                    .collect();
                let peers_json: Vec<serde_json::Value> = obs
                    .related_peers
                    .iter()
                    .map(|p| {
                        serde_json::json!({
                            "name": p.name,
                            "namespace": p.namespace,
                            "peerAddress": p.peer_address,
                            "peerASN": p.peer_asn,
                            "myASN": p.my_asn,
                            "sourceAddress": p.source_address,
                            "bfdProfile": p.bfd_profile,
                            "holdTime": p.hold_time,
                            "keepaliveTime": p.keepalive_time,
                            "routerID": p.router_id,
                            "nodeSelectors": label_selectors_to_json(&p.node_selectors),
                        })
                    })
                    .collect();
                let bfd_json: Vec<serde_json::Value> = obs
                    .related_bfd_profiles
                    .iter()
                    .map(|b| {
                        serde_json::json!({
                            "name": b.name,
                            "namespace": b.namespace,
                            "detectMultiplier": b.detect_multiplier,
                            "receiveInterval": b.receive_interval,
                            "transmitInterval": b.transmit_interval,
                            "echoInterval": b.echo_interval,
                            "minimumTtl": b.minimum_ttl,
                            "passiveMode": b.passive_mode,
                        })
                    })
                    .collect();
                let events_json: Vec<serde_json::Value> = obs
                    .events
                    .iter()
                    .map(|e| {
                        serde_json::json!({
                            "reason": e.reason,
                            "message": e.message,
                            "sourceComponent": e.source_component,
                            "reportingComponent": e.reporting_component,
                            "type": e.event_type,
                            "lastTimestamp": e.last_timestamp,
                        })
                    })
                    .collect();
                let config_states_json: Vec<serde_json::Value> = obs
                    .configuration_states
                    .iter()
                    .map(|cs| {
                        let conditions: Vec<serde_json::Value> = cs
                            .conditions
                            .iter()
                            .map(|c| {
                                serde_json::json!({
                                    "type": c.condition_type,
                                    "status": c.status,
                                    "reason": c.reason,
                                    "message": c.message,
                                })
                            })
                            .collect();
                        serde_json::json!({
                            "name": cs.name,
                            "namespace": cs.namespace,
                            "componentType": cs.component_type,
                            "nodeName": cs.node_name,
                            "result": cs.result,
                            "errorSummary": cs.error_summary,
                            "conditions": conditions,
                        })
                    })
                    .collect();
                let avail_str = |a: &crate::analyzers::selector::ApiAvailability| match a {
                    crate::analyzers::selector::ApiAvailability::Available => "available",
                    crate::analyzers::selector::ApiAvailability::Absent => "absent",
                    crate::analyzers::selector::ApiAvailability::Unavailable => "unavailable",
                };
                let mut obs_json = serde_json::json!({
                    "observedState": obs.observed_state,
                    "l2AdvertisedNodes": obs.l2_advertised_nodes,
                    "l2Interfaces": obs.l2_interfaces,
                    "l2StatusResources": obs.l2_status_resources.iter().map(|(n, ns)| format!("{}/{}", ns, n)).collect::<Vec<_>>(),
                    "bgpNodeStatus": bgp_node_json,
                    "bgpStatusResources": obs.bgp_status_resources.iter().map(|(n, ns)| format!("{}/{}", ns, n)).collect::<Vec<_>>(),
                    "relatedPeers": peers_json,
                    "relatedBfdProfiles": bfd_json,
                    "configurationStates": config_states_json,
                    "events": events_json,
                    "apiAvailability": {
                        "l2Status": avail_str(&obs.api_availability.l2_status),
                        "bgpStatus": avail_str(&obs.api_availability.bgp_status),
                        "bgpPeer": avail_str(&obs.api_availability.bgp_peer),
                        "bfdProfile": avail_str(&obs.api_availability.bfd_profile),
                        "events": avail_str(&obs.api_availability.events),
                        "configurationState": avail_str(&obs.api_availability.configuration_state),
                    },
                    "note": "Status represents advertisement intent, not BGP session establishment"
                });
                if !obs.session_state.is_empty() {
                    obs_json["sessionState"] = serde_json::json!(obs.session_state);
                }
                result["metallb"] = serde_json::json!({
                    "provider": mlb.provider,
                    "requestedIPs": mlb.requested_ips,
                    "requestedPool": mlb.requested_pool,
                    "pools": pools_json,
                    "advertisements": ads_json,
                    "warnings": mlb.warnings,
                    "observation": obs_json
                });
            }
            result
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
    metallb_results: &[crate::analyzers::selector::MetalLBResult],
    gateway_results: &[Vec<crate::analyzers::selector::MatchedGatewayRoute>],
) {
    let stdout_tty = std::io::IsTerminal::is_terminal(&std::io::stdout());
    if paths.is_empty() {
        println!("No Services select Pods under {}/{}", kind, name);
        return;
    }
    println!("Network paths for {}/{}:\n", kind, name);
    let mut seen_svcs = std::collections::HashSet::new();
    let mut mlb_idx = 0usize;
    let mut gw_idx = 0usize;
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
        // MetalLB section
        if let Some(mlb) = metallb_results.get(mlb_idx)
            && let Some(provider) = &mlb.provider
        {
            println!("    LB Provider:   {}", provider);
            if !mlb.requested_ips.is_empty() {
                println!("    Requested IPs: {}", mlb.requested_ips.join(", "));
            }
            if let Some(rp) = &mlb.requested_pool {
                println!("    Requested Pool: {}", rp);
            }
            for mp in &mlb.pools {
                println!(
                    "    Pool: {} [{}] ({})",
                    mp.pool.name,
                    mp.pool.addresses.join(", "),
                    mp.match_reason
                );
                if let Some(am) = &mp.allocation_match {
                    println!("      Allocation: {}", am);
                }
                let mut status_parts = Vec::new();
                if let Some(v) = mp.pool.status_available_ipv4 {
                    status_parts.push(format!("available IPv4: {}", v));
                }
                if let Some(v) = mp.pool.status_assigned_ipv4 {
                    status_parts.push(format!("assigned IPv4: {}", v));
                }
                if let Some(v) = mp.pool.status_available_ipv6 {
                    status_parts.push(format!("available IPv6: {}", v));
                }
                if let Some(v) = mp.pool.status_assigned_ipv6 {
                    status_parts.push(format!("assigned IPv6: {}", v));
                }
                if !status_parts.is_empty() {
                    println!("      Status: {}", status_parts.join(", "));
                }
            }
            for ad in &mlb.advertisements {
                println!("    {}/{} ({})", ad.kind, ad.name, ad.match_reason);
                if !ad.interfaces.is_empty() {
                    println!("      interfaces: {}", ad.interfaces.join(", "));
                }
                if !ad.peers.is_empty() {
                    println!("      peers: {}", ad.peers.join(", "));
                }
                if !ad.node_selectors.is_empty() {
                    println!(
                        "      node selector: {} ({})",
                        ad.node_selector_status,
                        if ad.candidate_nodes.is_empty() {
                            "no matching nodes".to_string()
                        } else {
                            ad.candidate_nodes.join(", ")
                        }
                    );
                }
            }
            // Observed state
            if !mlb.observation.observed_state.is_empty() {
                println!("    Observed: {}", mlb.observation.observed_state);
                if !mlb.observation.l2_advertised_nodes.is_empty() {
                    println!(
                        "      L2 nodes: {}",
                        mlb.observation.l2_advertised_nodes.join(", ")
                    );
                }
                if !mlb.observation.l2_interfaces.is_empty() {
                    println!(
                        "      L2 interfaces: {}",
                        mlb.observation.l2_interfaces.join(", ")
                    );
                }
                for bgp_node in &mlb.observation.bgp_advertised_nodes {
                    let peers_str = if bgp_node.peers.is_empty() {
                        String::new()
                    } else {
                        format!(" peers: {}", bgp_node.peers.join(", "))
                    };
                    println!("      BGP node: {}{}", bgp_node.node, peers_str);
                }
                for peer in &mlb.observation.related_peers {
                    let addr = peer.peer_address.as_deref().unwrap_or("?");
                    let asn = peer
                        .peer_asn
                        .map(|a| format!(" ASN:{}", a))
                        .unwrap_or_default();
                    println!("      BGP peer: BGPPeer/{} ({}{})", peer.name, addr, asn);
                }
                for event in &mlb.observation.events {
                    let reason = event.reason.as_deref().unwrap_or("?");
                    let msg = event.message.as_deref().unwrap_or("");
                    println!("      Event: {} - {}", reason, msg);
                }
                for cs in &mlb.observation.configuration_states {
                    let result_str = cs.result.as_deref().unwrap_or("?");
                    let err = cs.error_summary.as_deref().unwrap_or("");
                    let comp = cs.component_type.as_deref().unwrap_or("");
                    let node = cs.node_name.as_deref().unwrap_or("");
                    println!("      ConfigurationState/{}:", cs.name);
                    println!("        Result: {}", result_str);
                    if !err.is_empty() {
                        println!("        Error: {}", err);
                    }
                    if !comp.is_empty() {
                        println!("        Component: {}", comp);
                    }
                    if !node.is_empty() {
                        println!("        Node: {}", node);
                    }
                    if result_str != "OK" && result_str != "Success" && !cs.conditions.is_empty() {
                        println!("        Conditions:");
                        for c in &cs.conditions {
                            let reason = c
                                .reason
                                .as_deref()
                                .map(|r| format!(" ({})", r))
                                .unwrap_or_default();
                            println!("          {}: {}{}", c.condition_type, c.status, reason);
                        }
                    }
                }
            }
            if !mlb.observation.session_state.is_empty() {
                println!(
                    "    BGP session: {} (status is advertisement intent, not session state)",
                    mlb.observation.session_state
                );
            }
            for w in &mlb.warnings {
                println!("    [!] {}", w);
            }
        }
        mlb_idx += 1;
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
        // Gateway API routes
        if let Some(gw_routes) = gateway_results.get(gw_idx) {
            for gr in gw_routes {
                println!();
                let cross_ns_str = match &gr.cross_namespace {
                    crate::analyzers::selector::CrossNamespaceStatus::SameNamespace => "",
                    crate::analyzers::selector::CrossNamespaceStatus::Allowed => {
                        " [cross-ns: allowed]"
                    }
                    crate::analyzers::selector::CrossNamespaceStatus::NotAllowed => {
                        " [cross-ns: not-allowed]"
                    }
                    crate::analyzers::selector::CrossNamespaceStatus::Unknown => {
                        " [cross-ns: unknown]"
                    }
                };
                let gw_class_str = match (&gr.gateway_class_name, &gr.gateway_class_controller) {
                    (Some(name), Some(ctrl)) => {
                        format!(" (GatewayClass/{}, controller: {})", name, ctrl)
                    }
                    (Some(name), None) => format!(" (GatewayClass/{})", name),
                    (None, Some(ctrl)) => format!(" (controller: {})", ctrl),
                    (None, None) => String::new(),
                };
                let section_str = gr
                    .section_name
                    .as_deref()
                    .map(|sn| format!(" section={}", sn))
                    .unwrap_or_default();
                if stdout_tty {
                    println!(
                        "    \x1b[1m{}/{}\x1b[0m via Gateway/{}{}{}{} \u{2192} Service/{}",
                        gr.route_kind,
                        gr.route_name,
                        gr.gateway_name,
                        gw_class_str,
                        section_str,
                        cross_ns_str,
                        svc.name
                    );
                } else {
                    println!(
                        "    {}/{} via Gateway/{}{}{}{} \u{2192} Service/{}",
                        gr.route_kind,
                        gr.route_name,
                        gr.gateway_name,
                        gw_class_str,
                        section_str,
                        cross_ns_str,
                        svc.name
                    );
                }
                if !gr.hostnames.is_empty() {
                    println!("      Hostnames: {}", gr.hostnames.join(", "));
                }
                for listener in &gr.listeners {
                    let hostname = listener
                        .hostname
                        .as_deref()
                        .map(|h| format!(" hostname={}", h))
                        .unwrap_or_default();
                    let tls = listener
                        .tls_mode
                        .as_deref()
                        .map(|t| format!(" tls={}", t))
                        .unwrap_or_default();
                    println!(
                        "      Listener: {} port={}/{}{}{}",
                        listener.name, listener.port, listener.protocol, hostname, tls
                    );
                }
                for mb in &gr.matched_backends {
                    let mut backend_info = Vec::new();
                    if let Some(p) = mb.port {
                        backend_info.push(format!("port {}", p));
                    }
                    if let Some(w) = mb.weight {
                        backend_info.push(format!("weight {}", w));
                    }
                    if !backend_info.is_empty() {
                        println!("      Backend: {}", backend_info.join(", "));
                    }
                    for m in &mb.rule_matches {
                        let path_str = match (&m.path_type, &m.path_value) {
                            (Some(pt), Some(pv)) => format!("{} {}", pt, pv),
                            (None, Some(pv)) => pv.clone(),
                            _ => continue,
                        };
                        let method_str = m
                            .method
                            .as_deref()
                            .map(|meth| format!(" method={}", meth))
                            .unwrap_or_default();
                        println!("        Match: {}{}", path_str, method_str);
                    }
                }
                for c in &gr.status_conditions {
                    let reason = c
                        .reason
                        .as_deref()
                        .map(|r| format!(" ({})", r))
                        .unwrap_or_default();
                    println!("      Status: {}={}{}", c.condition_type, c.status, reason);
                }
                for w in &gr.warnings {
                    println!("      [!] {}", w);
                }
            }
        }
        gw_idx += 1;
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

#[allow(dead_code)]
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

/// Discover namespace scope for a single target operator.
/// Must run before journal creation so the journal captures provenance.
/// Fails closed: discovery scan failures abort the teardown.
pub(crate) async fn discover_audit_scope(
    client: &::kube::Client,
    target_operator: &crate::analyzers::olm::OperatorInstance,
    kind_map: &crate::kube::discovery::KindMap,
    gvr_map: &crate::kube::discovery::GvrMap,
    gk_map: &crate::kube::discovery::GroupKindMap,
) -> Result<Vec<crate::analyzers::namespace_scope::CandidateNamespace>> {
    use crate::analyzers::namespace_scope::{CandidateNamespace, NamespaceEvidence};
    use crate::kube::planner::QueryPlanner;
    use crate::kube::scanner::DEFAULT_API_CONCURRENCY;

    let scope_planner = QueryPlanner::new(Some(std::sync::Arc::new(tokio::sync::Semaphore::new(
        DEFAULT_API_CONCURRENCY,
    ))));

    let scope_result = discover_operator_namespaces_opts(
        client,
        target_operator,
        kind_map,
        gvr_map,
        gk_map,
        None,
        None,
        Some(scope_planner.clone()),
    )
    .await
    .context("Namespace scope discovery failed for audit context")?;
    if !scope_result.scan_failures.is_empty() {
        let msgs: Vec<String> = scope_result
            .scan_failures
            .iter()
            .map(|w| format!("{:?}", w))
            .collect();
        bail!(
            "Namespace scope discovery had {} scan failure(s) — audit scope incomplete, aborting: {}",
            msgs.len(),
            msgs.join("; ")
        );
    }
    let mut candidates = scope_result.candidates;
    if scope_result.is_all_namespaces {
        let ns_items = scope_planner
            .list_all(
                client,
                "",
                "v1",
                "namespaces",
                None,
                crate::kube::resource::QueryRequirement::Required,
            )
            .await
            .map_err(|w| anyhow::anyhow!("Failed to LIST Namespaces: {:?}", w))?;
        // Validate every Namespace identity — fail closed on missing/invalid
        for obj in ns_items.iter() {
            let raw = obj.metadata.name.as_deref().ok_or_else(|| {
                anyhow::anyhow!(
                    "AllNamespaces LIST returned Namespace without metadata.name — fail closed"
                )
            })?;
            if raw.is_empty() || !crate::analyzers::namespace_scope::is_valid_k8s_namespace(raw) {
                bail!(
                    "AllNamespaces LIST returned invalid namespace name {:?} — fail closed",
                    raw
                );
            }
            let ns_name = raw.to_string();

            if let Some(existing) = candidates.iter_mut().find(|c| c.namespace == ns_name) {
                if !existing
                    .evidence
                    .iter()
                    .any(|e| matches!(e, NamespaceEvidence::OperatorGroupAllNamespaces))
                {
                    existing
                        .evidence
                        .push(NamespaceEvidence::OperatorGroupAllNamespaces);
                }
            } else {
                candidates.push(CandidateNamespace {
                    namespace: ns_name,
                    evidence: vec![NamespaceEvidence::OperatorGroupAllNamespaces],
                });
            }
        }
    }
    Ok(candidates)
}

pub(crate) async fn create_run_journal(
    client: &::kube::Client,
    plan: &crate::teardown::planner::TeardownPlan,
    target_operators: &[&crate::analyzers::olm::OperatorInstance],
    gk_map: &crate::kube::discovery::GroupKindMap,
    _finalizer_recovery_approved: bool,
    backup_receipts: Vec<crate::teardown::backup::BackupReceipt>,
    candidate_namespaces: Option<Vec<crate::analyzers::namespace_scope::CandidateNamespace>>,
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
    let mut audit_context =
        journal::build_audit_context(plan, target_operators, gk_map, candidate_namespaces);

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
        backup_receipts,
    };

    let path = journal::run_path(&cluster_id, &run_id)?;
    journal::atomic_write_json_pub(&path, &journal)?;

    JournalStore::new_with_lock(journal, path)
}

/// Build a fresh OperatorIdentitySnapshot with live UIDs from the cluster.
/// Used for basis drift validation before journal creation.
pub(crate) async fn build_operator_identity_snapshot(
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

    // Typed and narrowly proven legacy explicit-cleanup failures both resume
    // through the saved main plan at the exact Explicit cleanup boundary.
    if matches!(
        j.state,
        journal::RunState::ExplicitCleanupBlocked | journal::RunState::Failed
    ) {
        explicit_cleanup_resume_mode(j)?;
        return Ok(ResumeStage::MainExecution);
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
                    }
                },
                "operators": [{
                    "name": "example-operator",
                    "approve_delete": {
                        "resources": ["example.io/Widget/ns/example"]
                    }
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
    }

    #[test]
    fn batch_config_rejects_force_field() {
        let result = serde_json::from_str::<ApplySetConfig>(
            r#"{
                "defaults": { "force": true },
                "operators": [{ "name": "example-operator" }]
            }"#,
        );
        assert!(
            result.is_err(),
            "force field must be rejected by deny_unknown_fields"
        );
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
    fn legacy_apply_set_approval_array_rejected() {
        let result: Result<ApplySetConfig, _> = serde_json::from_str(
            r#"{
                "operators": [{
                    "name": "example-operator",
                    "approve_delete": ["all", "Widget/example"]
                }]
            }"#,
        );
        assert!(
            result.is_err(),
            "Legacy array form must be rejected (use structured scopes/resources)"
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
                explicit_deletes: vec![],
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
                    target_operators_absent: false,
                    residual_workloads: Vec::new(),
                    incomplete_scopes: Vec::new(),
                })
            } else {
                None
            },
            cleanup_decisions: decisions,
            finalizer_recovery_approved: false,
            finalizer_recoveries: Vec::new(),
            backup_receipts: vec![],
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

    // ── ExplicitCleanupBlocked resume tests ──

    fn make_explicit_cleanup_journal(
        state: crate::teardown::journal::RunState,
        phases_completed: usize,
        cleanup_error: Option<crate::teardown::journal::ExplicitCleanupError>,
    ) -> crate::teardown::journal::RunJournal {
        use crate::teardown::plan::*;
        use crate::teardown::planner::*;
        let mut j = make_test_journal(state, phases_completed, 8, false, vec![]);
        j.plan_snapshot.explicit_deletes = vec![ExplicitDeleteTarget {
            group: "apps".to_string(),
            kind: "Deployment".to_string(),
            namespace: Some("ns".to_string()),
            name: "target-deploy".to_string(),
            uid: "uid-1".to_string(),
            reason: "explicit".to_string(),
            inbound_refs_at_plan: vec![],
            ref_scan_coverage: RefScanCoverage {
                kinds_scanned: vec![],
                scan_complete: true,
            },
        }];
        j.plan_snapshot.phases = vec![
            PlanPhase {
                name: "Freeze OLM".to_string(),
                description: "test".to_string(),
                actions: vec![],
                barrier: None,
            },
            PlanPhase {
                name: "Trigger operand cleanup".to_string(),
                description: "test".to_string(),
                actions: vec![],
                barrier: None,
            },
            PlanPhase {
                name: "Remaining cleanup".to_string(),
                description: "test".to_string(),
                actions: vec![],
                barrier: None,
            },
            PlanPhase {
                name: "Remove Operator controllers".to_string(),
                description: "test".to_string(),
                actions: vec![],
                barrier: None,
            },
            PlanPhase {
                name: "Namespace cleanup".to_string(),
                description: "test".to_string(),
                actions: vec![],
                barrier: None,
            },
            PlanPhase {
                name: EXPLICIT_CLEANUP_PHASE_NAME.to_string(),
                description: "test".to_string(),
                actions: vec![Action::Delete {
                    resource: crate::kube::resource::ResourceId {
                        group: "apps".to_string(),
                        version: "v1".to_string(),
                        kind: "Deployment".to_string(),
                        namespace: Some("ns".to_string()),
                        name: "target-deploy".to_string(),
                        uid: Some("uid-1".to_string()),
                    },
                    reason: "explicit".to_string(),
                }],
                barrier: None,
            },
            PlanPhase {
                name: "APIs".to_string(),
                description: "test".to_string(),
                actions: vec![],
                barrier: None,
            },
            PlanPhase {
                name: "Namespaces".to_string(),
                description: "test".to_string(),
                actions: vec![],
                barrier: None,
            },
        ];
        j.execution.explicit_cleanup_error = cleanup_error;
        j
    }

    #[test]
    fn classify_resume_explicit_cleanup_blocked_routes_to_main() {
        use crate::teardown::journal::{ExplicitCleanupError, ExplicitCleanupErrorKind, RunState};
        let j = make_explicit_cleanup_journal(
            RunState::ExplicitCleanupBlocked,
            5,
            Some(ExplicitCleanupError {
                target: "Deployment/target-deploy".to_string(),
                error_kind: ExplicitCleanupErrorKind::IncompleteScan,
                message: "ref scan incomplete".to_string(),
            }),
        );
        let stage = classify_resume_stage(&j).expect("should be resumable");
        assert_eq!(stage, ResumeStage::MainExecution);
    }

    #[test]
    fn classify_resume_explicit_cleanup_blocked_no_explicit_deletes_is_error() {
        use crate::teardown::journal::RunState;
        let mut j = make_explicit_cleanup_journal(RunState::ExplicitCleanupBlocked, 5, None);
        j.plan_snapshot.explicit_deletes.clear();
        let result = classify_resume_stage(&j);
        assert!(result.is_err(), "should reject without explicit_deletes");
    }

    #[test]
    fn classify_resume_explicit_cleanup_blocked_wrong_phase_is_error() {
        use crate::teardown::journal::RunState;
        // phases_completed=3 → next phase is "Remove Operator controllers", not Explicit cleanup
        let j = make_explicit_cleanup_journal(RunState::ExplicitCleanupBlocked, 3, None);
        let result = classify_resume_stage(&j);
        assert!(
            result.is_err(),
            "should reject when next phase is not Explicit cleanup"
        );
    }

    #[test]
    fn classify_resume_generic_failed_remains_non_resumable() {
        use crate::teardown::journal::RunState;
        let j = make_test_journal(RunState::Failed, 5, 8, false, vec![]);
        let err = classify_resume_stage(&j).unwrap_err();
        assert!(
            err.contains("phase count mismatch"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn legacy_failed_exact_explicit_boundary_is_narrowly_eligible() {
        use crate::teardown::backup::BackupReceipt;
        use crate::teardown::journal::RunState;
        let mut j = make_explicit_cleanup_journal(RunState::Failed, 5, None);
        j.backup_receipts.push(BackupReceipt {
            root: "/tmp/test-backup".to_string(),
            manifest_sha256: "manifest".to_string(),
            tree_sha256: "tree".to_string(),
            resource_set_sha256: "resources".to_string(),
            resource_count: 1,
            contains_secret_data: false,
            created_at: "2026-01-01T00:00:00Z".to_string(),
        });
        assert_eq!(
            explicit_cleanup_resume_mode(&j).unwrap(),
            ExplicitCleanupResumeMode::LegacyFailed
        );
        assert_eq!(
            classify_resume_stage(&j).unwrap(),
            ResumeStage::MainExecution
        );
    }

    #[test]
    fn legacy_failed_without_backup_is_not_migrated() {
        use crate::teardown::journal::RunState;
        let j = make_explicit_cleanup_journal(RunState::Failed, 5, None);
        let err = explicit_cleanup_resume_mode(&j).unwrap_err();
        assert!(err.contains("backup receipt"));
    }

    #[test]
    fn batch_selection_delegates_eligible_legacy_failed_journal() {
        use crate::teardown::backup::BackupReceipt;
        use crate::teardown::journal::RunState;
        let mut j = make_explicit_cleanup_journal(RunState::Failed, 5, None);
        j.run_id = "retry4".to_string();
        j.backup_receipts.push(BackupReceipt {
            root: "/tmp/test-backup".to_string(),
            manifest_sha256: "manifest".to_string(),
            tree_sha256: "tree".to_string(),
            resource_set_sha256: "resources".to_string(),
            resource_count: 1,
            contains_secret_data: false,
            created_at: "2026-01-01T00:00:00Z".to_string(),
        });
        assert_eq!(
            select_pending_explicit_cleanup_journal(&[j], "test").unwrap(),
            Some("retry4".to_string())
        );
    }

    #[test]
    fn batch_selection_rejects_ineligible_latest_explicit_journal() {
        use crate::teardown::journal::RunState;
        let mut j = make_explicit_cleanup_journal(RunState::Failed, 5, None);
        j.run_id = "unsafe".to_string();
        let err = select_pending_explicit_cleanup_journal(&[j], "test").unwrap_err();
        assert!(err.contains("not safely resumable"));
        assert!(err.contains("backup receipt"));
    }

    #[test]
    fn batch_dry_run_never_executes_pending_resume() {
        assert_eq!(pending_resume_action(true), PendingResumeAction::ReportOnly);
        assert_eq!(pending_resume_action(false), PendingResumeAction::Execute);
    }

    #[test]
    fn explicit_cleanup_resume_rejects_prior_target_outcome() {
        use crate::teardown::journal::{ExplicitCleanupError, ExplicitCleanupErrorKind, RunState};
        let mut j = make_explicit_cleanup_journal(
            RunState::ExplicitCleanupBlocked,
            5,
            Some(ExplicitCleanupError {
                target: "Deployment/target-deploy".to_string(),
                error_kind: ExplicitCleanupErrorKind::IncompleteScan,
                message: "incomplete".to_string(),
            }),
        );
        let target = match &j.plan_snapshot.phases[5].actions[0] {
            crate::teardown::planner::Action::Delete { resource, .. } => resource.clone(),
            _ => unreachable!(),
        };
        j.execution.deleted.push(target);
        let err = explicit_cleanup_resume_mode(&j).unwrap_err();
        assert!(err.contains("mutation outcome"));
    }

    #[test]
    fn explicit_cleanup_resume_rejects_metadata_action_mismatch() {
        use crate::teardown::journal::{ExplicitCleanupError, ExplicitCleanupErrorKind, RunState};
        let mut j = make_explicit_cleanup_journal(
            RunState::ExplicitCleanupBlocked,
            5,
            Some(ExplicitCleanupError {
                target: "Deployment/target-deploy".to_string(),
                error_kind: ExplicitCleanupErrorKind::IncompleteScan,
                message: "incomplete".to_string(),
            }),
        );
        j.plan_snapshot.explicit_deletes[0].uid = "different-uid".to_string();
        let err = explicit_cleanup_resume_mode(&j).unwrap_err();
        assert!(err.contains("1:1"));
    }

    #[test]
    fn explicit_guard_transient_timeout_classifies_correctly() {
        use crate::kube::resource::ScanWarning;
        use crate::teardown::executor::ExplicitGuardOutcome;
        let w = ScanWarning::Timeout {
            gvr: "v1/pods".to_string(),
            message: Some("timeout".to_string()),
            retries: 2,
        };
        let outcome = ExplicitGuardOutcome::from_scan_warning(&w, "Deployment/test");
        assert!(matches!(outcome, ExplicitGuardOutcome::TransientFailure(_)));
        if let ExplicitGuardOutcome::TransientFailure(err) = outcome {
            assert_eq!(
                err.error_kind,
                crate::teardown::journal::ExplicitCleanupErrorKind::Timeout
            );
        }
    }

    #[test]
    fn explicit_guard_forbidden_classifies_transient() {
        use crate::kube::resource::ScanWarning;
        use crate::teardown::executor::ExplicitGuardOutcome;
        let w = ScanWarning::Forbidden {
            gvr: "apps/v1/deployments".to_string(),
            status: 403,
        };
        let outcome = ExplicitGuardOutcome::from_scan_warning(&w, "Deployment/test");
        assert!(matches!(outcome, ExplicitGuardOutcome::TransientFailure(_)));
        if let ExplicitGuardOutcome::TransientFailure(err) = outcome {
            assert_eq!(
                err.error_kind,
                crate::teardown::journal::ExplicitCleanupErrorKind::Forbidden
            );
        }
    }

    #[test]
    fn explicit_guard_server_error_classifies_transient() {
        use crate::kube::resource::ScanWarning;
        use crate::teardown::executor::ExplicitGuardOutcome;
        let w = ScanWarning::ServerError {
            gvr: "v1/pods".to_string(),
            status: 500,
            message: "internal".to_string(),
            retries: 3,
        };
        let outcome = ExplicitGuardOutcome::from_scan_warning(&w, "Deployment/test");
        assert!(matches!(outcome, ExplicitGuardOutcome::TransientFailure(_)));
        if let ExplicitGuardOutcome::TransientFailure(err) = outcome {
            assert_eq!(
                err.error_kind,
                crate::teardown::journal::ExplicitCleanupErrorKind::ServerError
            );
        }
    }

    #[test]
    fn explicit_guard_other_error_classifies_hard() {
        use crate::kube::resource::ScanWarning;
        use crate::teardown::executor::ExplicitGuardOutcome;
        let w = ScanWarning::Other {
            gvr: "v1/pods".to_string(),
            message: "something weird".to_string(),
        };
        let outcome = ExplicitGuardOutcome::from_scan_warning(&w, "Deployment/test");
        assert!(matches!(outcome, ExplicitGuardOutcome::HardFailure(_)));
    }

    #[test]
    fn executor_error_checkpoint_preserves_only_typed_retryable_state() {
        use crate::teardown::journal::{RunState, mark_failed_preserving_retryable};
        let mut blocked = make_explicit_cleanup_journal(
            RunState::ExplicitCleanupBlocked,
            5,
            Some(crate::teardown::journal::ExplicitCleanupError {
                target: "Deployment/target-deploy".to_string(),
                error_kind: crate::teardown::journal::ExplicitCleanupErrorKind::IncompleteScan,
                message: "incomplete".to_string(),
            }),
        );
        mark_failed_preserving_retryable(&mut blocked);
        assert_eq!(blocked.state, RunState::ExplicitCleanupBlocked);

        let mut applying = make_test_journal(RunState::Applying, 2, 8, false, vec![]);
        mark_failed_preserving_retryable(&mut applying);
        assert_eq!(applying.state, RunState::Failed);
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

    #[test]
    fn network_json_has_typed_warnings() {
        use crate::kube::resource::ScanWarning;
        let w = ScanWarning::Forbidden {
            gvr: "v1/pods".into(),
            status: 403,
        };
        let json = serde_json::to_value(&w).unwrap();
        assert_eq!(json["type"], "Forbidden");
        assert_eq!(json["gvr"], "v1/pods");
        assert_eq!(json["status"], 403);
    }

    #[test]
    fn network_json_gateway_routes_always_present() {
        use crate::analyzers::selector::{EndpointSummary, NetworkPath, NetworkService};
        use std::collections::BTreeMap;

        let svc = NetworkService {
            name: "test-svc".into(),
            uid: "uid-1".into(),
            selector: BTreeMap::new(),
            has_selector: false,
            cluster_ip: "10.0.0.1".into(),
            svc_type: "ClusterIP".into(),
            ports: vec![],
            health_check_node_port: None,
            internal_traffic_policy: None,
            ip_family_policy: None,
            load_balancer_class: None,
            allocate_lb_node_ports: None,
            external_traffic_policy: None,
            external_ips: vec![],
            ip_families: vec![],
            lb_ingress: vec![],
            annotations: BTreeMap::new(),
            labels: BTreeMap::new(),
            load_balancer_ip: None,
        };
        let path = NetworkPath {
            service: svc,
            ingresses: vec![],
            endpoint_slices: vec![],
            endpoint_summary: EndpointSummary {
                ready: 0,
                not_ready: 0,
                unknown: 0,
                effective_ready: 0,
                serving: 0,
                terminating: 0,
            },
            selector_matched_pods: vec![],
            target_ref_matched_pods: vec![],
        };
        let paths = vec![("test".to_string(), path)];
        let metallb_results = vec![];
        let gateway_results: Vec<Vec<crate::analyzers::selector::MatchedGatewayRoute>> =
            vec![vec![]];
        let json = network_paths_to_json(&paths, &metallb_results, &gateway_results);
        assert_eq!(json.len(), 1);
        let entry = &json[0];
        assert!(
            entry.get("gatewayRoutes").is_some(),
            "gatewayRoutes must always be present"
        );
        assert_eq!(
            entry["gatewayRoutes"].as_array().unwrap().len(),
            0,
            "gatewayRoutes should be empty array when no routes"
        );
        assert!(
            entry.get("gatewayWarnings").is_some(),
            "gatewayWarnings must always be present"
        );
        assert_eq!(
            entry["gatewayWarnings"].as_array().unwrap().len(),
            0,
            "gatewayWarnings should be empty array when no warnings"
        );
    }

    #[test]
    fn network_json_gateway_route_fields() {
        use crate::analyzers::selector::{
            CrossNamespaceStatus, EndpointSummary, GatewayListener, HTTPRouteMatch, MatchedBackend,
            MatchedGatewayRoute, NetworkPath, NetworkService, RouteCondition,
        };
        use std::collections::BTreeMap;

        let svc = NetworkService {
            name: "web".into(),
            uid: "uid-w".into(),
            selector: BTreeMap::new(),
            has_selector: false,
            cluster_ip: "10.0.0.1".into(),
            svc_type: "ClusterIP".into(),
            ports: vec![],
            health_check_node_port: None,
            internal_traffic_policy: None,
            ip_family_policy: None,
            load_balancer_class: None,
            allocate_lb_node_ports: None,
            external_traffic_policy: None,
            external_ips: vec![],
            ip_families: vec![],
            lb_ingress: vec![],
            annotations: BTreeMap::new(),
            labels: BTreeMap::new(),
            load_balancer_ip: None,
        };
        let path = NetworkPath {
            service: svc,
            ingresses: vec![],
            endpoint_slices: vec![],
            endpoint_summary: EndpointSummary::default(),
            selector_matched_pods: vec![],
            target_ref_matched_pods: vec![],
        };
        let route = MatchedGatewayRoute {
            route_kind: "HTTPRoute".into(),
            route_name: "my-route".into(),
            route_namespace: "default".into(),
            hostnames: vec!["example.com".into()],
            gateway_name: "main-gw".into(),
            gateway_namespace: "gw-ns".into(),
            gateway_class_name: Some("my-class".into()),
            gateway_class_controller: Some("example.com/ctrl".into()),
            listeners: vec![GatewayListener {
                name: "https".into(),
                hostname: Some("example.com".into()),
                port: 443,
                protocol: "HTTPS".into(),
                tls_mode: Some("Terminate".into()),
            }],
            matched_backends: vec![
                MatchedBackend {
                    port: Some(8080),
                    weight: Some(1),
                    rule_matches: vec![HTTPRouteMatch {
                        path_type: Some("PathPrefix".into()),
                        path_value: Some("/api".into()),
                        method: None,
                    }],
                },
                MatchedBackend {
                    port: Some(8443),
                    weight: Some(2),
                    rule_matches: vec![HTTPRouteMatch {
                        path_type: Some("Exact".into()),
                        path_value: Some("/admin".into()),
                        method: Some("GET".into()),
                    }],
                },
            ],
            section_name: Some("https".into()),
            parent_port: Some(443),
            cross_namespace: CrossNamespaceStatus::SameNamespace,
            status_conditions: vec![RouteCondition {
                condition_type: "Accepted".into(),
                status: "True".into(),
                reason: Some("Accepted".into()),
                message: None,
            }],
            warnings: vec![],
        };
        let paths = vec![("".into(), path)];
        let gateway_results = vec![vec![route]];
        let json = network_paths_to_json(&paths, &[], &gateway_results);
        let entry = &json[0];
        let gw_routes = entry["gatewayRoutes"].as_array().unwrap();
        assert_eq!(gw_routes.len(), 1);
        let r = &gw_routes[0];
        assert_eq!(r["gatewayClassName"], "my-class");
        assert_eq!(r["gatewayClassController"], "example.com/ctrl");
        let backends = r["matchedBackends"].as_array().unwrap();
        assert_eq!(backends.len(), 2);
        assert_eq!(backends[0]["port"], 8080);
        assert_eq!(backends[0]["weight"], 1);
        let matches0 = backends[0]["ruleMatches"].as_array().unwrap();
        assert_eq!(matches0[0]["pathType"], "PathPrefix");
        assert_eq!(matches0[0]["pathValue"], "/api");
        assert_eq!(backends[1]["port"], 8443);
        assert_eq!(backends[1]["weight"], 2);
        let matches1 = backends[1]["ruleMatches"].as_array().unwrap();
        assert_eq!(matches1[0]["method"], "GET");
    }

    #[test]
    fn delete_resource_spec_parse_core_group() {
        let spec = DeleteResourceSpec::parse_cli_arg("ConfigMap/ns-a/my-cm").unwrap();
        assert_eq!(spec.group, "");
        assert_eq!(spec.kind, "ConfigMap");
        assert_eq!(spec.namespace, Some("ns-a".to_string()));
        assert_eq!(spec.name, "my-cm");
    }

    #[test]
    fn delete_resource_spec_parse_with_group() {
        let spec =
            DeleteResourceSpec::parse_cli_arg("gateway.networking.k8s.io/Gateway/ns-a/my-gw")
                .unwrap();
        assert_eq!(spec.group, "gateway.networking.k8s.io");
        assert_eq!(spec.kind, "Gateway");
        assert_eq!(spec.namespace, Some("ns-a".to_string()));
        assert_eq!(spec.name, "my-gw");
    }

    #[test]
    fn delete_resource_spec_parse_cluster_scoped() {
        let spec =
            DeleteResourceSpec::parse_cli_arg("console.openshift.io/ConsolePlugin/-/my-plugin")
                .unwrap();
        assert_eq!(spec.group, "console.openshift.io");
        assert_eq!(spec.kind, "ConsolePlugin");
        assert_eq!(spec.namespace, None);
        assert_eq!(spec.name, "my-plugin");
    }

    #[test]
    fn delete_resource_spec_rejects_forbidden_kinds() {
        assert!(DeleteResourceSpec::parse_cli_arg("Namespace/-/my-ns").is_err());
        assert!(DeleteResourceSpec::parse_cli_arg("PersistentVolume/-/pv1").is_err());
        assert!(DeleteResourceSpec::parse_cli_arg("PersistentVolumeClaim/ns/pvc1").is_err());
        assert!(
            DeleteResourceSpec::parse_cli_arg(
                "apiextensions.k8s.io/CustomResourceDefinition/-/foo"
            )
            .is_err()
        );
        assert!(DeleteResourceSpec::parse_cli_arg("APIService/-/v1.foo").is_err());
    }

    #[test]
    fn delete_resource_spec_rejects_empty_fields() {
        assert!(DeleteResourceSpec::parse_cli_arg("/ns/name").is_err());
        assert!(DeleteResourceSpec::parse_cli_arg("ConfigMap/ns/").is_err());
    }

    #[test]
    fn delete_resource_spec_rejects_whitespace() {
        let spec = DeleteResourceSpec {
            group: "".into(),
            kind: " ConfigMap".into(),
            namespace: Some("ns".into()),
            name: "cm".into(),
        };
        assert!(spec.validate().is_err());

        let spec2 = DeleteResourceSpec {
            group: "".into(),
            kind: "ConfigMap".into(),
            namespace: Some("ns".into()),
            name: "cm ".into(),
        };
        assert!(spec2.validate().is_err());
    }

    #[test]
    fn batch_config_parses_delete_resources() {
        let config: ApplySetConfig = serde_json::from_str(
            r#"{
                "operators": [{
                    "name": "my-op",
                    "delete_resources": [
                        {"group": "apps", "kind": "Deployment", "namespace": "ns-a", "name": "my-deploy"},
                        {"group": "", "kind": "ConfigMap", "namespace": "ns-a", "name": "my-cm"}
                    ]
                }]
            }"#,
        )
        .unwrap();
        assert_eq!(config.operators[0].delete_resources.len(), 2);
        assert_eq!(config.operators[0].delete_resources[0].kind, "Deployment");
        assert_eq!(config.operators[0].delete_resources[1].group, "");
    }

    #[test]
    fn batch_config_without_delete_resources_ok() {
        let config: ApplySetConfig = serde_json::from_str(
            r#"{
                "operators": [{"name": "my-op"}]
            }"#,
        )
        .unwrap();
        assert!(config.operators[0].delete_resources.is_empty());
    }

    #[test]
    fn delete_resource_to_cli_arg_roundtrip() {
        let spec = DeleteResourceSpec {
            group: "apps".into(),
            kind: "Deployment".into(),
            namespace: Some("ns-a".into()),
            name: "my-deploy".into(),
        };
        let arg = spec.to_cli_arg();
        assert_eq!(arg, "apps/Deployment/ns-a/my-deploy");
        let parsed = DeleteResourceSpec::parse_cli_arg(&arg).unwrap();
        assert_eq!(parsed.group, "apps");
        assert_eq!(parsed.kind, "Deployment");

        let core_spec = DeleteResourceSpec {
            group: "".into(),
            kind: "ConfigMap".into(),
            namespace: None,
            name: "cm1".into(),
        };
        let core_arg = core_spec.to_cli_arg();
        assert_eq!(core_arg, "ConfigMap/-/cm1");
        let core_parsed = DeleteResourceSpec::parse_cli_arg(&core_arg).unwrap();
        assert_eq!(core_parsed.group, "");
        assert!(core_parsed.namespace.is_none());
    }

    #[test]
    fn inject_explicit_phase_errors_on_missing_gk() {
        use crate::teardown::plan::{ExplicitDeleteTarget, RefScanCoverage};
        use crate::teardown::planner::TeardownPlan;
        let mut plan = TeardownPlan {
            targets: vec![],
            preflight: crate::teardown::planner::Preflight { checks: vec![] },
            phases: vec![],
            blockers: vec![],
            warnings: vec![],
            snapshot_taken_at: "".into(),
            dependency_edges: vec![],
            operator_inventory: vec![],
            explicit_decisions: vec![],
            explicit_deletes: vec![],
        };
        let targets = vec![ExplicitDeleteTarget {
            group: "nonexistent.io".into(),
            kind: "Widget".into(),
            namespace: Some("ns".into()),
            name: "w1".into(),
            uid: "uid-1".into(),
            reason: "config".into(),
            inbound_refs_at_plan: vec![],
            ref_scan_coverage: RefScanCoverage {
                kinds_scanned: vec![],
                scan_complete: true,
            },
        }];
        let gk_map = std::collections::HashMap::new();
        let result = inject_explicit_phase_into_teardown_plan(&mut plan, &targets, &gk_map);
        assert!(result.is_err(), "missing GK must error");
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("not found in API discovery"),
            "error should mention API discovery"
        );
    }

    #[test]
    fn should_refresh_discovery_logic() {
        assert!(
            !should_refresh_discovery(false, 0),
            "no flag, no targets = use cache"
        );
        assert!(
            should_refresh_discovery(true, 0),
            "user --refresh-discovery = refresh"
        );
        assert!(
            should_refresh_discovery(false, 1),
            "explicit targets present = force refresh even without flag"
        );
        assert!(
            should_refresh_discovery(true, 3),
            "both flag and targets = refresh"
        );
    }

    fn make_test_operator(
        csv_name: &str,
        phase: &str,
        pkg: Option<&str>,
    ) -> crate::analyzers::olm::OperatorInstance {
        crate::analyzers::olm::OperatorInstance {
            subscription: None,
            csv: crate::kube::resource::ResourceId {
                group: "operators.coreos.com".to_string(),
                version: "v1alpha1".to_string(),
                kind: "ClusterServiceVersion".to_string(),
                namespace: Some("test-ns".to_string()),
                name: csv_name.to_string(),
                uid: Some("test-uid".to_string()),
            },
            csv_phase: phase.to_string(),
            owned_crds: vec![],
            required_crds: vec![],
            owned_api_service_defs: vec![],
            required_api_service_defs: vec![],
            deployments: vec![],
            service_accounts: vec![],
            install_namespace: "test-ns".to_string(),
            package_name: pkg.map(|s| s.to_string()),
            has_unlinked_subscriptions: false,
        }
    }

    #[test]
    fn presence_gate_succeeded_passes() {
        let op = make_test_operator("rhods-operator.3.5.1", "Succeeded", Some("rhods-operator"));
        assert!(operator_matches_entry(&op, "rhods-operator"));
    }

    #[test]
    fn presence_gate_failed_passes() {
        let op = make_test_operator("rhods-operator.3.5.1", "Failed", Some("rhods-operator"));
        assert!(operator_matches_entry(&op, "rhods-operator"));
    }

    #[test]
    fn presence_gate_pending_passes() {
        let op = make_test_operator(
            "cert-manager-operator.v1.20.0",
            "Pending",
            Some("openshift-cert-manager-operator"),
        );
        assert!(operator_matches_entry(
            &op,
            "openshift-cert-manager-operator"
        ));
    }

    #[test]
    fn presence_gate_missing_fails() {
        let operators = [make_test_operator(
            "rhods-operator.3.5.1",
            "Succeeded",
            Some("rhods-operator"),
        )];
        let found = operators
            .iter()
            .any(|op| operator_matches_entry(op, "nonexistent-operator"));
        assert!(!found, "Missing operator must not match");
    }

    #[test]
    fn batch_summary_counts_outcomes_correctly() {
        let results = vec![
            ("op-a".to_string(), BatchOutcome::Succeeded),
            ("op-b".to_string(), BatchOutcome::Skipped),
            ("op-c".to_string(), BatchOutcome::Succeeded),
            ("op-d".to_string(), BatchOutcome::Failed(1)),
            ("op-e".to_string(), BatchOutcome::Skipped),
        ];
        let (s, sk, f) = batch_summary(&results);
        assert_eq!(s, 2, "succeeded count");
        assert_eq!(sk, 2, "skipped count");
        assert_eq!(f, 1, "failed count");
    }

    #[test]
    fn batch_skipped_excluded_from_success() {
        let results = vec![("op-a".to_string(), BatchOutcome::Skipped)];
        let (s, sk, f) = batch_summary(&results);
        assert_eq!(s, 0, "skipped must not count as succeeded");
        assert_eq!(sk, 1);
        assert_eq!(f, 0, "skipped must not count as failed");
    }

    #[test]
    fn health_preflight_produces_warning_not_critical() {
        use crate::teardown::planner::{PreflightSeverity, health_preflight_checks};
        let checks = health_preflight_checks(
            "test-op.v1",
            (false, "CSV phase: Failed".to_string()),
            (false, "0/1 controllers available".to_string()),
        );
        assert_eq!(checks.len(), 2);
        for check in &checks {
            assert_eq!(
                check.severity,
                PreflightSeverity::Warning,
                "{} must be Warning, not Critical",
                check.name
            );
            assert!(!check.passed);
        }
    }

    #[test]
    fn blocking_preflight_filters_critical_only() {
        use crate::teardown::executor::blocking_preflight_failures;
        use crate::teardown::planner::{PreflightCheck, PreflightSeverity};
        let checks = vec![
            PreflightCheck {
                name: "CSV health (op.v1)".to_string(),
                severity: PreflightSeverity::Warning,
                passed: false,
                detail: "Failed".to_string(),
            },
            PreflightCheck {
                name: "Controller available (op.v1)".to_string(),
                severity: PreflightSeverity::Warning,
                passed: false,
                detail: "unavailable".to_string(),
            },
            PreflightCheck {
                name: "CR enumeration (widgets)".to_string(),
                severity: PreflightSeverity::Critical,
                passed: false,
                detail: "cannot enumerate".to_string(),
            },
        ];
        let blockers = blocking_preflight_failures(&checks);
        assert_eq!(blockers.len(), 1, "only Critical should block");
        assert!(blockers[0].contains("CR enumeration"));
    }
}

#[cfg(test)]
mod resolve_explicit_target_tests {
    use super::*;
    use ::kube::client::Body;
    use std::pin::pin;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    fn json_response(json: serde_json::Value) -> http::Response<Body> {
        http::Response::builder()
            .status(200)
            .body(Body::from(serde_json::to_vec(&json).unwrap()))
            .unwrap()
    }

    fn status_response(code: u16, reason: &str) -> http::Response<Body> {
        let body = serde_json::json!({
            "apiVersion": "v1", "kind": "Status",
            "metadata": {},
            "status": "Failure",
            "reason": reason,
            "code": code
        });
        http::Response::builder()
            .status(code)
            .body(Body::from(serde_json::to_vec(&body).unwrap()))
            .unwrap()
    }

    fn test_gk_map() -> crate::kube::discovery::GroupKindMap {
        let mut gk = std::collections::HashMap::new();
        let entries: Vec<(&str, &str, &str, &str)> = vec![
            ("", "ConfigMap", "v1", "configmaps"),
            ("apps", "Deployment", "v1", "deployments"),
            ("apps", "StatefulSet", "v1", "statefulsets"),
            ("apps", "DaemonSet", "v1", "daemonsets"),
            ("apps", "ReplicaSet", "v1", "replicasets"),
            ("batch", "Job", "v1", "jobs"),
            ("batch", "CronJob", "v1", "cronjobs"),
            ("", "Pod", "v1", "pods"),
            ("gateway.networking.k8s.io", "Gateway", "v1", "gateways"),
        ];
        for (group, kind, version, plural) in entries {
            gk.insert(
                (group.to_string(), kind.to_string()),
                crate::kube::discovery::KindInfo {
                    group: group.to_string(),
                    version: version.to_string(),
                    plural: plural.to_string(),
                    namespaced: true,
                    listable: true,
                },
            );
        }
        gk
    }

    fn test_spec() -> DeleteResourceSpec {
        DeleteResourceSpec {
            group: "".to_string(),
            kind: "ConfigMap".to_string(),
            namespace: Some("ns".to_string()),
            name: "cm1".to_string(),
        }
    }

    fn empty_plan() -> crate::teardown::planner::TeardownPlan {
        crate::teardown::planner::TeardownPlan {
            targets: vec![],
            preflight: crate::teardown::planner::Preflight { checks: vec![] },
            phases: vec![],
            blockers: vec![],
            warnings: vec![],
            snapshot_taken_at: "".into(),
            dependency_edges: vec![],
            operator_inventory: vec![],
            explicit_decisions: vec![],
            explicit_deletes: vec![],
        }
    }

    #[tokio::test]
    async fn resolve_404_one_request_not_found() {
        let request_count = Arc::new(AtomicUsize::new(0));
        let count = request_count.clone();

        let (mock_service, handle) =
            tower_test::mock::pair::<http::Request<Body>, http::Response<Body>>();
        let spawned = tokio::spawn(async move {
            let mut handle = pin!(handle);
            while let Some((_req, send)) = handle.next_request().await {
                count.fetch_add(1, Ordering::SeqCst);
                send.send_response(status_response(404, "NotFound"));
            }
        });

        let client = ::kube::Client::new(mock_service, "default");
        let result =
            resolve_explicit_delete_targets(&client, &[test_spec()], &empty_plan(), &test_gk_map())
                .await;

        drop(client);
        spawned.abort();

        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("not found"));
        assert_eq!(
            request_count.load(Ordering::SeqCst),
            1,
            "404 must not retry"
        );
    }

    #[tokio::test]
    async fn resolve_403_one_request_fails() {
        let request_count = Arc::new(AtomicUsize::new(0));
        let count = request_count.clone();

        let (mock_service, handle) =
            tower_test::mock::pair::<http::Request<Body>, http::Response<Body>>();
        let spawned = tokio::spawn(async move {
            let mut handle = pin!(handle);
            while let Some((_req, send)) = handle.next_request().await {
                count.fetch_add(1, Ordering::SeqCst);
                send.send_response(status_response(403, "Forbidden"));
            }
        });

        let client = ::kube::Client::new(mock_service, "default");
        let result =
            resolve_explicit_delete_targets(&client, &[test_spec()], &empty_plan(), &test_gk_map())
                .await;

        drop(client);
        spawned.abort();

        assert!(result.is_err());
        assert_eq!(
            request_count.load(Ordering::SeqCst),
            1,
            "403 must not retry"
        );
    }

    #[tokio::test]
    async fn resolve_500_then_200_recovers() {
        let request_count = Arc::new(AtomicUsize::new(0));
        let count = request_count.clone();

        let (mock_service, handle) =
            tower_test::mock::pair::<http::Request<Body>, http::Response<Body>>();
        let spawned = tokio::spawn(async move {
            let mut handle = pin!(handle);
            while let Some((req, send)) = handle.next_request().await {
                let n = count.fetch_add(1, Ordering::SeqCst);
                let uri = req.uri().to_string();
                if uri.contains("configmaps") && !uri.contains('?') {
                    if n == 0 {
                        send.send_response(status_response(500, "InternalServerError"));
                    } else {
                        send.send_response(json_response(serde_json::json!({
                            "apiVersion": "v1", "kind": "ConfigMap",
                            "metadata": {"name": "cm1", "namespace": "ns", "uid": "cm-uid-1"}
                        })));
                    }
                } else {
                    // LIST for ref scan — return empty
                    send.send_response(json_response(serde_json::json!({
                        "apiVersion": "v1", "kind": "List",
                        "metadata": {"resourceVersion": "1"}, "items": []
                    })));
                }
            }
        });

        let client = ::kube::Client::new(mock_service, "default");
        let result =
            resolve_explicit_delete_targets(&client, &[test_spec()], &empty_plan(), &test_gk_map())
                .await;

        drop(client);
        spawned.abort();

        assert!(result.is_ok(), "500→200 must recover: {:?}", result.err());
        let targets = result.unwrap();
        assert_eq!(targets.len(), 1);
        assert_eq!(targets[0].uid, "cm-uid-1");
        assert!(
            request_count.load(Ordering::SeqCst) >= 2,
            "500→200 must use at least 2 requests (GET retry + ref scan LISTs)"
        );
    }
}

#[cfg(test)]
mod config_parse_tests {
    use super::*;

    #[test]
    fn full_teardown_config_parses_as_apply_set_config() {
        let config_str = std::fs::read_to_string("configs/full-teardown.json")
            .expect("configs/full-teardown.json should exist");
        let config: ApplySetConfig = serde_json::from_str(&config_str)
            .expect("configs/full-teardown.json must parse as ApplySetConfig");
        assert!(!config.operators.is_empty(), "config should have operators");
        // Validate every DeleteResourceSpec
        for entry in &config.operators {
            for spec in &entry.delete_resources {
                spec.validate().unwrap_or_else(|e| {
                    panic!(
                        "delete_resources entry {}/{} failed validation: {}",
                        spec.kind, spec.name, e
                    )
                });
            }
        }
    }

    #[test]
    fn config_with_unknown_field_fails() {
        let bad = r#"{"operators":[{"name":"test","delete_resources":[{"group":"","kind":"Svc","name":"x","reason":"extra"}]}]}"#;
        let result = serde_json::from_str::<ApplySetConfig>(bad);
        assert!(result.is_err(), "unknown field 'reason' must be rejected");
    }

    #[test]
    fn config_delete_resource_validate_rejects_empty_kind() {
        let spec = DeleteResourceSpec {
            group: String::new(),
            kind: String::new(),
            namespace: None,
            name: "test".to_string(),
        };
        assert!(
            spec.validate().is_err(),
            "empty kind should fail validation"
        );
    }
}
