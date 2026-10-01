use crate::analyzers::olm::discover_operators_full;
use crate::kube::discovery::build_kind_lookup_cached;
use crate::teardown::journal;
use crate::teardown::planner::resolve_operator_targets;
use anyhow::{Context, Result};
use std::time::Instant;

pub(crate) async fn handle_backup(
    client: &::kube::Client,
    config: &::kube::config::Config,
    action: crate::cli::BackupAction,
) -> Result<()> {
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
                build_kind_lookup_cached(client, config, refresh_discovery).await?;
            eprintln!("   Discovery: {:.1}s", t0.elapsed().as_secs_f64());

            let cmd_semaphore = std::sync::Arc::new(tokio::sync::Semaphore::new(
                crate::kube::scanner::DEFAULT_API_CONCURRENCY,
            ));
            let cmd_planner = crate::kube::planner::QueryPlanner::new(Some(cmd_semaphore));

            eprint!("🔍 Discovering operators...");
            let all_operators =
                discover_operators_full(client, &kind_map, None, Some(cmd_planner.clone())).await?;
            eprintln!(" found {} operators", all_operators.len());

            let target_indices =
                resolve_operator_targets(std::slice::from_ref(&operator_query), &all_operators)?;
            let target_op = &all_operators[target_indices[0]];
            let op_name = target_op
                .package_name
                .as_deref()
                .unwrap_or(&target_op.csv.name);

            eprintln!(
                "📦 Backing up operator: {} ({})",
                target_op.csv.name, target_op.install_namespace
            );

            let (candidates, observations, resolved) =
                crate::teardown::backup::discover_operator_backup(
                    client, target_op, &kind_map, &gvr_map, &gk_map, &gvk_map,
                )
                .await?;

            eprintln!("  {} unique resource(s)", candidates.len());

            let (fetched, _) =
                crate::teardown::backup::fetch_backup_resources(client, &candidates, &gvk_map)
                    .await?;

            let captured = fetched
                .iter()
                .filter(|r| r.state == crate::teardown::backup::BackupResourceState::Captured)
                .count();
            let absent = fetched
                .iter()
                .filter(|r| r.state == crate::teardown::backup::BackupResourceState::AlreadyAbsent)
                .count();
            eprintln!("  {} captured, {} already absent", captured, absent);

            let cluster_identity = journal::fetch_cluster_identity(client).await?;
            let selection = crate::teardown::backup::BackupSelection::operator(vec![resolved]);

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
            Ok(())
        }
        BackupAction::Namespace {
            namespace,
            dir: output_dir,
            refresh_discovery,
        } => {
            let t0 = Instant::now();
            eprintln!("🔍 Discovering API resources...");
            let (kind_map, _gvr_map, gk_map, gvk_map) =
                build_kind_lookup_cached(client, config, refresh_discovery).await?;
            eprintln!("   Discovery: {:.1}s", t0.elapsed().as_secs_f64());

            {
                use k8s_openapi::api::core::v1::Namespace;
                let ns_api: ::kube::api::Api<Namespace> = ::kube::api::Api::all(client.clone());
                ns_api
                    .get(&namespace)
                    .await
                    .with_context(|| format!("Namespace '{}' does not exist", namespace))?;
            }

            eprintln!("📦 Scanning namespace: {}", namespace);

            let candidates = crate::teardown::backup::discover_namespace_backup(
                client, &namespace, &kind_map, &gk_map,
            )
            .await?;

            eprintln!("  {} unique resource(s)", candidates.len());

            let (fetched, _) =
                crate::teardown::backup::fetch_backup_resources(client, &candidates, &gvk_map)
                    .await?;

            let cluster_identity = journal::fetch_cluster_identity(client).await?;
            let selection =
                crate::teardown::backup::BackupSelection::namespace(vec![namespace.clone()]);

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
            Ok(())
        }
    }
}
