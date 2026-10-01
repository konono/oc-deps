use crate::analyzers::namespace_scope::discover_operator_namespaces_opts;
use crate::analyzers::olm::{WhoManagesInput, discover_operators_full, who_manages_opts};
use crate::analyzers::trace::{print_trace, trace_resource};
use crate::cli::Scope;
use crate::kube::discovery::{build_kind_lookup_cached, resolve_kind_with_group};
use crate::kube::resource::format_scan_warnings;
use crate::teardown::planner::resolve_operator_targets;
use anyhow::{Result, bail};
use std::time::Instant;

pub(crate) async fn handle_trace(
    client: &::kube::Client,
    config: &::kube::config::Config,
    resource: String,
    online: crate::cli::OnlineOpts,
    depth: usize,
    scope: Scope,
) -> Result<()> {
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
        build_kind_lookup_cached(client, config, no_cache).await?;
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
            client,
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
            client,
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
    if !kind_info.namespaced {
        eprint!("🔍 Fetching cluster-scoped target...");
        let gvk =
            ::kube::core::GroupVersion::gv(&kind_info.group, &kind_info.version).with_kind(&kind);
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
                client,
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

    let mut confirmed_csv: Option<String> = None;
    eprint!("🔍 Tracing ownership...");
    let wm_result = who_manages_opts(
        &WhoManagesInput {
            client,
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

    if cross_namespace && let Some(csv_name) = &confirmed_csv {
        let operators = discover_operators_full(
            client,
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
                client,
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
            let ns_scan = crate::analyzers::namespace_scope::scan_candidate_namespaces_with_ledger(
                client,
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
        client,
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

    scan_warnings.extend(std::mem::take(&mut result.scan_failures));
    result.scan_failures = scan_warnings.clone();

    format_scan_warnings(&scan_warnings, verbose);
    let scope_str = if cross_namespace {
        "related"
    } else {
        "namespace"
    };
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
    Ok(())
}
