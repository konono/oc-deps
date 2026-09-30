pub(crate) mod teardown;

#[allow(unused_imports)]
use self::teardown::*;
use crate::analyzers::inspect::{
    inspect_operator_with_options_ledger, print_inspection as print_inspection_top,
};
use crate::analyzers::namespace_scope::discover_operator_namespaces_opts;
use crate::analyzers::olm::{
    WhoManagesInput, compute_operator_dependencies, discover_operators, discover_operators_full,
    print_operators, print_who_manages, who_manages, who_manages_opts,
};
use crate::analyzers::selector::get_service_selected_pods;
use crate::analyzers::trace::{print_trace, trace_resource};
use crate::cli::{
    Args, Command, Direction, OperatorAction, OutputFormat, Scope, ShowField, SnapshotAction,
};
use crate::graph::evidence::build_evidence_graph;
use crate::graph::tree::{apply_filters, build_child_tree, build_full_tree, build_namespace_map};
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
use crate::output::json::{print_chain_json, tree_to_json};
use crate::output::table::print_chain_table;
use crate::output::tree::{count_nodes, format_container_resources, print_chain_tree, print_tree};
use crate::teardown::planner::resolve_operator_targets;
use anyhow::{Result, bail};
use clap::CommandFactory;
#[allow(unused_imports)]
use std::collections::HashSet;
use std::time::Instant;

#[allow(clippy::needless_return)]
pub async fn run(args: Args) -> Result<()> {
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
            crate::commands::teardown::handle_teardown(&client, &config, action).await?;
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
            crate::commands::teardown::handle_network(&client, &config, resource, online).await?;
            return Ok(());
        }

        Command::Backup { action } => {
            crate::commands::teardown::handle_backup(&client, &config, action).await?;
            return Ok(());
        }
    }
}
