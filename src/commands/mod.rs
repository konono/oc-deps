pub(crate) mod backup;
pub(crate) mod graph;
pub(crate) mod map;
pub(crate) mod network;
pub(crate) mod operator;
pub(crate) mod snapshot;
pub(crate) mod teardown;
pub(crate) mod trace;
pub(crate) mod tree;

use crate::cli::{Args, Command, OperatorAction, SnapshotAction};
use crate::kube::discovery::load_config_and_client;
use anyhow::{Result, bail};

pub async fn run(args: Args) -> Result<()> {
    // ── Offline subcommands (dispatch before client init) ──
    if let Command::Completion { shell } = args.command {
        use clap::CommandFactory;
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
        return snapshot::handle_snapshot_audit(
            before,
            after,
            plans,
            gvr_catalog.as_deref(),
            provider_operands.as_deref(),
            output,
        );
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
        return snapshot::handle_snapshot_diff(before, after, output);
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
        snapshot::validate_snapshot_create_args(namespace_selector, exclude_namespace)?;
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
        map::validate_map_args(
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
                    verbose,
                    all_namespaces,
                    namespace_selector,
                    exclude_namespace,
                    exclude_system_namespaces,
                    strict,
                },
        } => {
            snapshot::handle_snapshot_create(
                &client,
                &config,
                namespace,
                file,
                include_events,
                refresh_discovery,
                verbose,
                all_namespaces,
                namespace_selector,
                exclude_namespace,
                exclude_system_namespaces,
                strict,
            )
            .await
        }

        Command::Snapshot {
            action: SnapshotAction::Diff { .. },
        } => unreachable!("handled before client init"),

        Command::Snapshot {
            action: SnapshotAction::Audit { .. },
        } => unreachable!("handled before client init"),

        Command::Graph {
            namespace,
            file,
            include_events,
            refresh_discovery,
            verbose,
            strict,
        } => {
            graph::handle_graph(
                &client,
                &config,
                namespace,
                file,
                include_events,
                refresh_discovery,
                verbose,
                strict,
            )
            .await
        }

        Command::Teardown { action } => teardown::handle_teardown(&client, &config, action).await,

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
            operator::handle_operator_resources(
                &client,
                &config,
                operator_query,
                output,
                refresh_discovery,
                scope,
                verbose,
                strict,
            )
            .await
        }

        Command::Operator {
            action:
                OperatorAction::List {
                    output,
                    refresh_discovery,
                },
        } => operator::handle_operator_list(&client, &config, output, refresh_discovery).await,

        Command::Operator {
            action:
                OperatorAction::Owner {
                    resource,
                    namespace,
                    output,
                    refresh_discovery,
                    verbose,
                    strict,
                },
        } => {
            operator::handle_operator_owner(
                &client,
                &config,
                resource,
                namespace,
                output,
                refresh_discovery,
                verbose,
                strict,
            )
            .await
        }

        Command::Trace {
            resource,
            online,
            depth,
            scope,
        } => trace::handle_trace(&client, &config, resource, online, depth, scope).await,

        Command::Tree {
            resource,
            online,
            direction,
            depth,
            no_refs,
            include_events,
            show,
        } => {
            tree::handle_tree(
                &client,
                &config,
                resource,
                online,
                direction,
                depth,
                no_refs,
                include_events,
                show,
            )
            .await
        }

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
            map::handle_map(
                &client,
                &config,
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
            )
            .await
        }

        Command::Network { resource, online } => {
            network::handle_network(&client, &config, resource, online).await
        }

        Command::Backup { action } => backup::handle_backup(&client, &config, action).await,
    }
}
