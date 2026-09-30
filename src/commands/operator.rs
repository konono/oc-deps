use crate::analyzers::inspect::{
    inspect_operator_with_options_ledger, print_inspection as print_inspection_top,
};
use crate::analyzers::olm::{
    WhoManagesInput, compute_operator_dependencies, discover_operators, discover_operators_full,
    print_operators, print_who_manages, who_manages,
};
use crate::cli::{OutputFormat, Scope};
use crate::kube::discovery::{build_kind_lookup_cached, resolve_kind_with_group};
use crate::kube::resource::format_scan_warnings;
use crate::teardown::planner::resolve_operator_targets;
use anyhow::{Result, bail};
use std::time::Instant;

#[allow(clippy::too_many_arguments)]
pub(crate) async fn handle_operator_resources(
    client: &::kube::Client,
    config: &::kube::config::Config,
    operator_query: String,
    output: OutputFormat,
    refresh_discovery: bool,
    scope: Scope,
    verbose: bool,
    strict: bool,
) -> Result<()> {
    let cross_namespace = matches!(scope, Scope::Related);
    let t0 = Instant::now();
    eprintln!("🔍 Discovering API resources...");
    let (kind_map, gvr_map, gk_map, _) =
        build_kind_lookup_cached(client, config, refresh_discovery).await?;
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
        client,
        &kind_map,
        Some(cmd_ledger.clone()),
        Some(cmd_planner.clone()),
    )
    .await?;
    eprintln!(" found {} operators", all_operators.len());

    let target_indices = resolve_operator_targets(&[operator_query], &all_operators)?;
    let target_op = &all_operators[target_indices[0]];

    let inspection = inspect_operator_with_options_ledger(
        client,
        target_op,
        &kind_map,
        &gvr_map,
        &gk_map,
        cross_namespace,
        Some(cmd_ledger.clone()),
        Some(cmd_planner.clone()),
    )
    .await?;

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
    Ok(())
}

pub(crate) async fn handle_operator_list(
    client: &::kube::Client,
    config: &::kube::config::Config,
    output: OutputFormat,
    refresh_discovery: bool,
) -> Result<()> {
    let t0 = Instant::now();
    eprintln!("🔍 Discovering API resources...");
    let (kind_map, _, _gk_map, _) =
        build_kind_lookup_cached(client, config, refresh_discovery).await?;
    eprintln!("   Discovery: {:.1}s", t0.elapsed().as_secs_f64());

    eprint!("🔍 Discovering operators...");
    let operators = discover_operators(client, &kind_map).await?;
    let deps = compute_operator_dependencies(&operators);
    eprintln!(
        " found {} operators, {} dependencies",
        operators.len(),
        deps.len()
    );

    print_operators(&operators, &deps, &output);
    Ok(())
}

#[allow(clippy::too_many_arguments)]
pub(crate) async fn handle_operator_owner(
    client: &::kube::Client,
    config: &::kube::config::Config,
    resource: String,
    namespace: Option<String>,
    output: OutputFormat,
    refresh_discovery: bool,
    verbose: bool,
    strict: bool,
) -> Result<()> {
    let namespace = namespace.unwrap_or_else(|| config.default_namespace.clone());
    let t0 = Instant::now();
    eprintln!("🔍 Discovering API resources...");
    let (kind_map, gvr_map, gk_map_wm, _) =
        build_kind_lookup_cached(client, config, refresh_discovery).await?;
    eprintln!("   Discovery: {:.1}s", t0.elapsed().as_secs_f64());

    let (kind_input, name) = if let Some((k, n)) = resource.split_once('/') {
        (k.to_string(), n.to_string())
    } else {
        bail!("Resource must be in kind/name format (e.g. pod/my-pod)");
    };
    let (kind, target_group) = resolve_kind_with_group(&kind_input, &kind_map, &gvr_map)?;

    eprint!("🔍 Tracing ownership...");
    let result = match who_manages(&WhoManagesInput {
        client,
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
        format_scan_warnings(&result.scan_failures, verbose);
    }
    print_who_manages(&result, &output);
    if strict && !result.scan_failures.is_empty() {
        std::process::exit(2);
    }
    Ok(())
}
