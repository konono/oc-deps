use crate::cli::OutputFormat;
use crate::kube::discovery::build_kind_lookup_cached;
use crate::kube::resource::format_scan_warnings;
use crate::kube::snapshot::{
    diff_snapshots, load_snapshot, print_diff_table, print_diff_tree, save_snapshot,
};
use anyhow::{Result, bail};
use std::time::Instant;

pub(crate) fn handle_snapshot_audit(
    before: &str,
    after: &str,
    plans: &[String],
    gvr_catalog: Option<&str>,
    provider_operands: Option<&str>,
    output: &OutputFormat,
) -> Result<()> {
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
    Ok(())
}

pub(crate) fn handle_snapshot_diff(before: &str, after: &str, output: &OutputFormat) -> Result<()> {
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
    Ok(())
}

pub(crate) fn validate_snapshot_create_args(
    namespace_selector: &[String],
    exclude_namespace: &[String],
) -> Result<()> {
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
pub(crate) async fn handle_snapshot_create(
    client: &::kube::Client,
    config: &::kube::config::Config,
    namespace: Option<String>,
    file: String,
    include_events: bool,
    refresh_discovery: bool,
    verbose: bool,
    all_namespaces: bool,
    namespace_selector: Vec<String>,
    exclude_namespace: Vec<String>,
    exclude_system_namespaces: bool,
    strict: bool,
) -> Result<()> {
    let no_cache = refresh_discovery;
    let t0 = Instant::now();
    eprintln!("🔍 Discovering API resources...");
    let (_kind_map, _, _gk_map, gvk_map) =
        build_kind_lookup_cached(client, config, no_cache).await?;
    eprintln!("   Discovery: {:.1}s", t0.elapsed().as_secs_f64());

    if all_namespaces {
        use crate::kube::resource::{
            ClusterSnapshot, IncompleteNamespace, SNAPSHOT_SCHEMA_VERSION, SnapshotScope,
        };
        use crate::kube::scanner::list_namespaces_with_retry;

        let all_ns = list_namespaces_with_retry(client).await?;
        let target_namespaces = super::map::filter_namespaces(
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

        tokio::spawn(async move {
            if tokio::signal::ctrl_c().await.is_ok() {
                eprintln!("\n⚠ Interrupted — cleaning up...");
                cancel_for_handler.cancel();
            }
        });

        let mut all_resources =
            std::collections::HashMap::<String, crate::kube::resource::ResourceEntry>::new();
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
            .buffer_unordered(super::map::MAX_NAMESPACE_CONCURRENCY)
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
                        eprint!("\r\x1b[2K  [{}/{}] {} — ERROR: {}", count, total_ns, ns, e);
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

        {
            let cluster_fut = crate::kube::snapshot::build_snapshot_all_gvrs(
                client,
                config,
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
        format_scan_warnings(&snapshot.scan_warnings, verbose);
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
        if strict && (!scope.incomplete_namespaces.is_empty() || !snapshot.scan_warnings.is_empty())
        {
            std::process::exit(2);
        }
    } else {
        let namespace = namespace.unwrap_or_else(|| config.default_namespace.clone());
        let snapshot = crate::kube::snapshot::build_snapshot_all_gvrs(
            client,
            config,
            &namespace,
            &gvk_map,
            include_events,
            crate::kube::snapshot::ScanScope::NamespacedOnly,
            None,
        )
        .await?;

        let resource_count = snapshot.resources.len();
        format_scan_warnings(&snapshot.scan_warnings, verbose);
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
    Ok(())
}
