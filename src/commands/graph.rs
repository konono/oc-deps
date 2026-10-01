use crate::analyzers::olm::discover_operators;
use crate::graph::evidence::build_evidence_graph;
use crate::kube::discovery::build_kind_lookup_cached;
use crate::kube::resource::format_scan_warnings;
use crate::kube::snapshot::build_snapshot;
use anyhow::Result;
use std::time::Instant;

#[allow(clippy::too_many_arguments)]
pub(crate) async fn handle_graph(
    client: &::kube::Client,
    config: &::kube::config::Config,
    namespace: Option<String>,
    file: String,
    include_events: bool,
    refresh_discovery: bool,
    verbose: bool,
    strict: bool,
) -> Result<()> {
    let namespace = namespace.unwrap_or_else(|| config.default_namespace.clone());
    let t0 = Instant::now();
    eprintln!("🔍 Discovering API resources...");
    let (kind_map, _, _gk_map, _) =
        build_kind_lookup_cached(client, config, refresh_discovery).await?;
    eprintln!("   Discovery: {:.1}s", t0.elapsed().as_secs_f64());

    let snapshot = build_snapshot(client, config, &namespace, &kind_map, include_events).await?;

    format_scan_warnings(&snapshot.scan_warnings, verbose);

    eprint!("🔍 Discovering operators...");
    let operators = discover_operators(client, &kind_map).await?;
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
    if strict && !snapshot.scan_warnings.is_empty() {
        std::process::exit(2);
    }
    Ok(())
}
