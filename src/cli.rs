use clap::{Parser, Subcommand, ValueEnum};

#[derive(Parser)]
#[command(
    name = "oc-deps",
    version,
    about = "Kubernetes Resource Dependency Inspector"
)]
pub struct Args {
    #[command(subcommand)]
    pub command: Command,
}

#[derive(Clone, Debug, ValueEnum)]
pub enum Direction {
    Both,
    Parents,
    Children,
}

#[derive(Clone, Debug, PartialEq, ValueEnum)]
pub enum ShowField {
    Labels,
    Annotations,
    PodResources,
}

#[derive(Clone, Debug, ValueEnum)]
pub enum Scope {
    Namespace,
    Related,
}

/// Common options for subcommands that connect to a cluster.
#[derive(clap::Args, Clone, Debug)]
pub struct OnlineOpts {
    /// Namespace (default: kubeconfig default)
    #[arg(short = 'n', long)]
    pub namespace: Option<String>,

    /// Output format
    #[arg(short = 'o', long, value_enum, default_value = "tree")]
    pub output: OutputFormat,

    /// Refresh API discovery cache
    #[arg(long)]
    pub refresh_discovery: bool,

    /// Show detailed scan warnings
    #[arg(short = 'v', long)]
    pub verbose: bool,

    /// Exit with code 2 if scan is incomplete
    #[arg(long)]
    pub strict: bool,
}

#[derive(Subcommand)]
pub enum Command {
    /// Show dependency tree around a resource
    Tree {
        /// Resource in kind/name format
        #[arg(value_name = "RESOURCE")]
        resource: String,

        #[command(flatten)]
        online: OnlineOpts,

        /// Direction to traverse
        #[arg(long, value_enum, default_value = "both")]
        direction: Direction,

        /// Max traversal depth
        #[arg(short = 'd', long, default_value_t = 20)]
        depth: usize,

        /// Disable spec-level references (Secret, ConfigMap, CRD cross-references)
        #[arg(long)]
        no_refs: bool,

        /// Include Event resources in scan (default: skip)
        #[arg(long)]
        include_events: bool,

        /// Show additional fields
        #[arg(long, value_enum)]
        show: Vec<ShowField>,
    },

    /// Show dependency trees for a namespace or cluster
    Map {
        #[command(flatten)]
        online: OnlineOpts,

        /// Scan all namespaces
        #[arg(short = 'A', long = "all-namespaces", conflicts_with = "namespace")]
        all_namespaces: bool,

        /// Select namespaces by label (repeatable, AND). Requires -A
        #[arg(long, value_name = "KEY=VALUE")]
        namespace_selector: Vec<String>,

        /// Exclude namespaces matching glob pattern (repeatable). Requires -A
        #[arg(long, value_name = "PATTERN")]
        exclude_namespace: Vec<String>,

        /// Exclude system namespaces (openshift-*, kube-*, default). Requires -A
        #[arg(long)]
        exclude_system_namespaces: bool,

        /// Disable spec-level references
        #[arg(long)]
        no_refs: bool,

        /// Include Event resources in scan (default: skip)
        #[arg(long)]
        include_events: bool,

        /// Show additional fields
        #[arg(long, value_enum)]
        show: Vec<ShowField>,

        /// Max traversal depth
        #[arg(short = 'd', long, default_value_t = 20)]
        depth: usize,

        /// Filter by root resource kind (repeatable, OR)
        #[arg(long, value_name = "KIND")]
        root_kind: Vec<String>,

        /// Filter by root resource label (repeatable, key=value format)
        #[arg(long, value_name = "KEY=VALUE")]
        root_label: Vec<String>,
    },

    /// Diagnose how a workload is exposed and network-restricted
    Network {
        /// Resource in kind/name format (Pod, Deployment, ReplicaSet, StatefulSet, DaemonSet, Service)
        #[arg(value_name = "RESOURCE")]
        resource: String,

        #[command(flatten)]
        online: OnlineOpts,
    },

    /// Operator inspection commands (list, owner, resources)
    Operator {
        #[command(subcommand)]
        action: OperatorAction,
    },

    /// Snapshot commands (create, diff)
    Snapshot {
        #[command(subcommand)]
        action: SnapshotAction,
    },

    /// Build and export the evidence graph for a namespace
    Graph {
        /// Namespace to analyze
        #[arg(short = 'n', long)]
        namespace: Option<String>,

        /// Save to file path
        #[arg(long, default_value = "evidence-graph.json")]
        file: String,

        /// Include Event resources in scan (default: skip)
        #[arg(long)]
        include_events: bool,

        /// Refresh API discovery cache
        #[arg(long)]
        refresh_discovery: bool,

        /// Show detailed scan warnings
        #[arg(short = 'v', long)]
        verbose: bool,

        /// Exit with code 2 if scan is incomplete (partial results are output/saved first)
        #[arg(long)]
        strict: bool,
    },

    /// Teardown planning for OLM operators
    Teardown {
        #[command(subcommand)]
        action: TeardownAction,
    },

    /// Trace discovered relationships from a resource, including ownerRef descendants, spec references, same-operator resources, and label correlations
    Trace {
        /// Resource in kind/name format
        #[arg(value_name = "RESOURCE")]
        resource: String,

        #[command(flatten)]
        online: OnlineOpts,

        /// Max traversal depth
        #[arg(short = 'd', long, default_value_t = 20)]
        depth: usize,

        /// Scope: namespace (default) or related (cross-namespace via OperatorGroup, owned CRD instances, label evidence)
        #[arg(long, value_enum, default_value = "namespace")]
        scope: Scope,
    },
}

#[derive(Subcommand)]
pub enum TeardownAction {
    /// Generate a teardown plan
    Plan {
        /// Operator names (subscription or CSV name, partial match OK)
        #[arg(required = true)]
        operators: Vec<String>,

        /// Output format: tree, table, json
        #[arg(short = 'o', long, value_enum, default_value = "tree")]
        output: OutputFormat,

        /// Refresh API discovery cache
        #[arg(long)]
        refresh_discovery: bool,

        /// Remove CRDs after teardown (default: keep)
        #[arg(long)]
        prune_crds: bool,

        /// Approve bulk deletion scope: root, independent, all, label-only, operator-group (repeatable)
        #[arg(long = "approve-scope", value_name = "SCOPE")]
        approve_scope: Vec<String>,

        /// Approve deletion of a specific resource: Kind/name or group/Kind/ns/name (repeatable)
        #[arg(long = "approve-resource", value_name = "SPEC")]
        approve_resource: Vec<String>,

        /// Keep a REVIEW resource (preserve instead of delete). Kind/name or group/Kind/ns/name (repeatable)
        #[arg(long = "keep-resource", value_name = "SPEC")]
        keep_resource: Vec<String>,

        /// Save the plan as a SavedTeardownPlan to the specified path
        #[arg(long = "save-plan", value_name = "PATH")]
        save_plan_path: Option<String>,
    },

    /// Check current status of resources in a teardown plan
    Status {
        /// Operator names (subscription or CSV name, partial match OK)
        #[arg(required_unless_present = "plan_file")]
        operators: Vec<String>,

        /// Refresh API discovery cache
        #[arg(long)]
        refresh_discovery: bool,

        /// Load plan from a saved JSON file instead of re-generating
        #[arg(long = "plan-file", value_name = "PATH")]
        plan_file: Option<String>,
    },

    /// Execute a teardown plan from a saved plan file
    Apply {
        /// Path to saved plan JSON file
        #[arg(required = true)]
        plan: String,

        /// Refresh API discovery cache
        #[arg(long)]
        refresh_discovery: bool,

        /// Dry run — show what would be done without executing
        #[arg(long)]
        dry_run: bool,

        /// Non-interactive mode: unresolved REVIEW, drift, audit incomplete,
        /// ExplicitUnattributed → nonzero exit before mutation.
        #[arg(long)]
        non_interactive: bool,

        /// Headless mode: read JSON commands from script file, output JSON state traces.
        /// Uses same AppState + executor as interactive mode.
        #[arg(long, value_name = "PATH")]
        script: Option<String>,

        /// Enable ratatui TUI mode for interactive Plan Review + Execution + Residual Cleanup.
        /// Uses the same AppState + core executor as CLI and --script modes.
        #[arg(long)]
        tui: bool,

        /// Save the final plan (with residual decisions) as a SavedTeardownPlan
        #[arg(long = "save-plan", value_name = "PATH")]
        save_plan_path: Option<String>,
    },

    /// Show plan coverage: COVERED BY PLAN / INTENTIONALLY PRESERVED / NOT COVERED
    Coverage {
        /// Operator names (subscription or CSV name, partial match OK)
        #[arg(required = true)]
        operators: Vec<String>,

        /// Output format: tree, table, json
        #[arg(short = 'o', long, value_enum, default_value = "tree")]
        output: OutputFormat,

        /// Refresh API discovery cache
        #[arg(long)]
        refresh_discovery: bool,
    },

    /// Explain why a resource is scheduled at its position in the plan
    Explain {
        /// Operator names to plan teardown for
        #[arg(required = true)]
        operators: Vec<String>,

        /// Resource to explain (kind/name format)
        #[arg(long)]
        resource: String,

        /// Refresh API discovery cache
        #[arg(long)]
        refresh_discovery: bool,
    },

    /// Resume a paused or interrupted teardown run
    Resume {
        /// Operator CSV name to find latest run
        operator: Option<String>,

        /// Specific run ID
        #[arg(long)]
        run: Option<String>,

        /// Refresh API discovery cache
        #[arg(long)]
        refresh_discovery: bool,
    },

    /// List all teardown runs for the current cluster
    Runs,

    /// Execute teardown for multiple operators from a config file (sequential)
    Batch {
        /// Path to JSON config file listing operators and their flags
        #[arg(required = true)]
        config: String,

        /// Refresh API discovery cache
        #[arg(long)]
        refresh_discovery: bool,

        /// Dry run — validate config and show plan without executing
        #[arg(long)]
        dry_run: bool,
    },

    /// Show teardown run journal for an operator (with live residual audit)
    Journal {
        /// Operator CSV name to find latest run
        operator: Option<String>,

        /// Specific run ID
        #[arg(long)]
        run: Option<String>,

        /// Skip live residual audit
        #[arg(long)]
        no_audit: bool,
    },
}

#[derive(Subcommand)]
pub enum OperatorAction {
    /// List all OLM-managed operators in the cluster
    List {
        /// Output format: tree, table, json
        #[arg(short = 'o', long, value_enum, default_value = "tree")]
        output: OutputFormat,

        /// Refresh API discovery cache
        #[arg(long)]
        refresh_discovery: bool,
    },

    /// Show which Operator manages a resource (ownerRef chain → CSV → Subscription)
    Owner {
        /// Resource in kind/name format
        #[arg(value_name = "RESOURCE")]
        resource: String,

        /// Namespace (default: kubeconfig default)
        #[arg(short = 'n', long)]
        namespace: Option<String>,

        /// Output format: tree, table, json
        #[arg(short = 'o', long, value_enum, default_value = "tree")]
        output: OutputFormat,

        /// Refresh API discovery cache
        #[arg(long)]
        refresh_discovery: bool,

        /// Show detailed scan warnings
        #[arg(short = 'v', long)]
        verbose: bool,

        /// Exit with code 2 if scan is incomplete (partial results are output/saved first)
        #[arg(long)]
        strict: bool,
    },

    /// Inspect all resources managed by an operator
    Resources {
        /// Operator name (subscription or CSV name, partial match OK)
        #[arg(required = true)]
        operator: String,

        /// Output format: tree, table, json
        #[arg(short = 'o', long, value_enum, default_value = "tree")]
        output: OutputFormat,

        /// Refresh API discovery cache
        #[arg(long)]
        refresh_discovery: bool,

        /// Scope: namespace (default) or related (cross-namespace via OperatorGroup, owned CRD instances, label evidence)
        #[arg(long, value_enum, default_value = "namespace")]
        scope: Scope,

        /// Show all scan/discovery warnings (default: first 5)
        #[arg(short = 'v', long)]
        verbose: bool,

        /// Exit with code 2 if discovery/scan is incomplete (partial results are still output)
        #[arg(long)]
        strict: bool,
    },
}

#[derive(Subcommand)]
pub enum SnapshotAction {
    /// Take a cluster snapshot and save to JSON
    Create {
        /// Namespace to snapshot
        #[arg(short = 'n', long)]
        namespace: Option<String>,

        /// Save to file path
        #[arg(long, default_value = "snapshot.json")]
        file: String,

        /// Include Event resources in scan (default: skip)
        #[arg(long)]
        include_events: bool,

        /// Refresh API discovery cache
        #[arg(long)]
        refresh_discovery: bool,

        /// Show detailed scan warnings
        #[arg(short = 'v', long)]
        verbose: bool,

        /// Scan all namespaces
        #[arg(short = 'A', long = "all-namespaces", conflicts_with = "namespace")]
        all_namespaces: bool,

        /// Select namespaces by label (repeatable, AND). Requires -A
        #[arg(long, value_name = "KEY=VALUE", requires = "all_namespaces")]
        namespace_selector: Vec<String>,

        /// Exclude namespaces matching glob pattern (repeatable). Requires -A
        #[arg(long, value_name = "PATTERN", requires = "all_namespaces")]
        exclude_namespace: Vec<String>,

        /// Exclude system namespaces (openshift-*, kube-*, default). Requires -A
        #[arg(long, requires = "all_namespaces")]
        exclude_system_namespaces: bool,

        /// Exit with code 2 if any API types were skipped during scan
        #[arg(long)]
        strict: bool,
    },

    /// Compare two snapshot files (offline, no cluster connection required)
    Diff {
        /// Path to the "before" snapshot JSON
        #[arg(value_name = "BEFORE")]
        before: String,

        /// Path to the "after" snapshot JSON
        #[arg(value_name = "AFTER")]
        after: String,

        /// Output format: tree (default), json, table
        #[arg(short = 'o', long, value_enum, default_value = "tree")]
        output: OutputFormat,
    },
}

#[derive(Clone, Debug, ValueEnum)]
pub enum OutputFormat {
    Tree,
    Table,
    Json,
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;

    #[test]
    fn test_tree_subcommand_basic() {
        let args = Args::parse_from(["oc-deps", "tree", "deployment/nginx", "-n", "default"]);
        match args.command {
            Command::Tree {
                resource,
                online,
                direction,
                depth,
                ..
            } => {
                assert_eq!(resource, "deployment/nginx");
                assert_eq!(online.namespace, Some("default".to_string()));
                assert!(matches!(direction, Direction::Both));
                assert_eq!(depth, 20);
            }
            _ => panic!("Expected Command::Tree"),
        }
    }

    #[test]
    fn test_tree_direction_parents() {
        let args = Args::parse_from(["oc-deps", "tree", "pod/foo", "--direction", "parents"]);
        match args.command {
            Command::Tree { direction, .. } => {
                assert!(matches!(direction, Direction::Parents));
            }
            _ => panic!("Expected Command::Tree"),
        }
    }

    #[test]
    fn test_tree_direction_children() {
        let args = Args::parse_from(["oc-deps", "tree", "pod/foo", "--direction", "children"]);
        match args.command {
            Command::Tree { direction, .. } => {
                assert!(matches!(direction, Direction::Children));
            }
            _ => panic!("Expected Command::Tree"),
        }
    }

    #[test]
    fn test_tree_show_fields() {
        let args = Args::parse_from([
            "oc-deps",
            "tree",
            "deployment/nginx",
            "--show",
            "labels",
            "--show",
            "annotations",
            "--show",
            "pod-resources",
        ]);
        match args.command {
            Command::Tree { show, .. } => {
                assert!(show.contains(&ShowField::Labels));
                assert!(show.contains(&ShowField::Annotations));
                assert!(show.contains(&ShowField::PodResources));
            }
            _ => panic!("Expected Command::Tree"),
        }
    }

    #[test]
    fn test_tree_online_opts() {
        let args = Args::parse_from([
            "oc-deps",
            "tree",
            "pod/foo",
            "-n",
            "myns",
            "-o",
            "json",
            "--refresh-discovery",
            "-v",
            "--strict",
        ]);
        match args.command {
            Command::Tree { online, .. } => {
                assert_eq!(online.namespace, Some("myns".to_string()));
                assert!(matches!(online.output, OutputFormat::Json));
                assert!(online.refresh_discovery);
                assert!(online.verbose);
                assert!(online.strict);
            }
            _ => panic!("Expected Command::Tree"),
        }
    }

    #[test]
    fn test_map_subcommand_basic() {
        let args = Args::parse_from(["oc-deps", "map", "-n", "myns"]);
        match args.command {
            Command::Map {
                online,
                all_namespaces,
                ..
            } => {
                assert_eq!(online.namespace, Some("myns".to_string()));
                assert!(!all_namespaces);
            }
            _ => panic!("Expected Command::Map"),
        }
    }

    #[test]
    fn test_map_all_namespaces() {
        let args = Args::parse_from([
            "oc-deps",
            "map",
            "-A",
            "--namespace-selector",
            "env=prod",
            "--exclude-namespace",
            "temp-*",
            "--exclude-system-namespaces",
        ]);
        match args.command {
            Command::Map {
                all_namespaces,
                namespace_selector,
                exclude_namespace,
                exclude_system_namespaces,
                online,
                ..
            } => {
                assert!(all_namespaces);
                assert_eq!(namespace_selector, vec!["env=prod"]);
                assert_eq!(exclude_namespace, vec!["temp-*"]);
                assert!(exclude_system_namespaces);
                assert!(online.namespace.is_none());
            }
            _ => panic!("Expected Command::Map"),
        }
    }

    #[test]
    fn test_map_n_and_a_conflict() {
        let result = Args::try_parse_from(["oc-deps", "map", "-n", "ns", "-A"]);
        assert!(result.is_err(), "Expected conflict error for -n and -A");
    }

    #[test]
    fn test_map_root_filters() {
        let args = Args::parse_from([
            "oc-deps",
            "map",
            "-n",
            "default",
            "--root-kind",
            "Deployment",
            "--root-label",
            "app=nginx",
        ]);
        match args.command {
            Command::Map {
                root_kind,
                root_label,
                ..
            } => {
                assert_eq!(root_kind, vec!["Deployment"]);
                assert_eq!(root_label, vec!["app=nginx"]);
            }
            _ => panic!("Expected Command::Map"),
        }
    }

    #[test]
    fn test_network_subcommand() {
        let args = Args::parse_from(["oc-deps", "network", "deployment/nginx", "-n", "default"]);
        match args.command {
            Command::Network {
                resource, online, ..
            } => {
                assert_eq!(resource, "deployment/nginx");
                assert_eq!(online.namespace, Some("default".to_string()));
            }
            _ => panic!("Expected Command::Network"),
        }
    }

    #[test]
    fn test_trace_subcommand_with_online_opts() {
        let args = Args::parse_from([
            "oc-deps",
            "trace",
            "datasciencecluster/default",
            "-n",
            "test-ns",
            "--scope",
            "related",
            "--strict",
        ]);
        match args.command {
            Command::Trace {
                resource,
                online,
                scope,
                depth,
                ..
            } => {
                assert_eq!(resource, "datasciencecluster/default");
                assert_eq!(online.namespace, Some("test-ns".to_string()));
                assert!(matches!(scope, Scope::Related));
                assert!(online.strict);
                assert_eq!(depth, 20);
            }
            _ => panic!("Expected Command::Trace"),
        }
    }

    #[test]
    fn test_trace_scope_default_namespace() {
        let args = Args::parse_from(["oc-deps", "trace", "deployment/foo", "-n", "ns"]);
        match args.command {
            Command::Trace { scope, .. } => {
                assert!(matches!(scope, Scope::Namespace));
            }
            _ => panic!("Expected Command::Trace"),
        }
    }

    #[test]
    fn test_trace_custom_depth_and_output() {
        let args = Args::parse_from([
            "oc-deps",
            "trace",
            "deployment/foo",
            "-d",
            "5",
            "-o",
            "json",
        ]);
        match args.command {
            Command::Trace { depth, online, .. } => {
                assert_eq!(depth, 5);
                assert!(matches!(online.output, OutputFormat::Json));
            }
            _ => panic!("Expected Command::Trace"),
        }
    }

    // ── operator subcommand tests ──

    #[test]
    fn test_operator_list_parses() {
        let args = Args::parse_from(["oc-deps", "operator", "list", "-o", "json"]);
        match args.command {
            Command::Operator {
                action: OperatorAction::List { output, .. },
            } => {
                assert!(matches!(output, OutputFormat::Json));
            }
            _ => panic!("Expected Command::Operator List"),
        }
    }

    #[test]
    fn test_operator_list_refresh_discovery() {
        let args = Args::parse_from(["oc-deps", "operator", "list", "--refresh-discovery"]);
        match args.command {
            Command::Operator {
                action:
                    OperatorAction::List {
                        refresh_discovery, ..
                    },
            } => {
                assert!(refresh_discovery);
            }
            _ => panic!("Expected Command::Operator List"),
        }
    }

    #[test]
    fn test_operator_owner_parses() {
        let args = Args::parse_from([
            "oc-deps",
            "operator",
            "owner",
            "deployment/nginx",
            "-n",
            "default",
        ]);
        match args.command {
            Command::Operator {
                action:
                    OperatorAction::Owner {
                        resource,
                        namespace,
                        ..
                    },
            } => {
                assert_eq!(resource, "deployment/nginx");
                assert_eq!(namespace, Some("default".to_string()));
            }
            _ => panic!("Expected Command::Operator Owner"),
        }
    }

    #[test]
    fn test_operator_resources_scope_related() {
        let args = Args::parse_from([
            "oc-deps",
            "operator",
            "resources",
            "rhods-operator",
            "--scope",
            "related",
        ]);
        match args.command {
            Command::Operator {
                action:
                    OperatorAction::Resources {
                        operator, scope, ..
                    },
            } => {
                assert_eq!(operator, "rhods-operator");
                assert!(matches!(scope, Scope::Related));
            }
            _ => panic!("Expected Command::Operator Resources"),
        }
    }

    #[test]
    fn test_operator_resources_default_scope() {
        let args = Args::parse_from(["oc-deps", "operator", "resources", "rhods-operator"]);
        match args.command {
            Command::Operator {
                action: OperatorAction::Resources { scope, .. },
            } => {
                assert!(matches!(scope, Scope::Namespace));
            }
            _ => panic!("Expected Command::Operator Resources"),
        }
    }

    // ── snapshot subcommand tests ──

    #[test]
    fn test_snapshot_create_parses() {
        let args = Args::parse_from(["oc-deps", "snapshot", "create", "-n", "myns"]);
        match args.command {
            Command::Snapshot {
                action: SnapshotAction::Create { namespace, .. },
            } => {
                assert_eq!(namespace, Some("myns".to_string()));
            }
            _ => panic!("Expected Command::Snapshot Create"),
        }
    }

    #[test]
    fn test_snapshot_create_all_namespaces() {
        let args = Args::parse_from([
            "oc-deps",
            "snapshot",
            "create",
            "-A",
            "--namespace-selector",
            "env=prod",
            "--exclude-namespace",
            "temp-*",
            "--exclude-system-namespaces",
        ]);
        match args.command {
            Command::Snapshot {
                action:
                    SnapshotAction::Create {
                        all_namespaces,
                        namespace_selector,
                        exclude_namespace,
                        exclude_system_namespaces,
                        ..
                    },
            } => {
                assert!(all_namespaces);
                assert_eq!(namespace_selector, vec!["env=prod"]);
                assert_eq!(exclude_namespace, vec!["temp-*"]);
                assert!(exclude_system_namespaces);
            }
            _ => panic!("Expected Command::Snapshot Create"),
        }
    }

    #[test]
    fn snapshot_create_n_and_a_conflict() {
        let result = Args::try_parse_from(["oc-deps", "snapshot", "create", "-n", "ns", "-A"]);
        assert!(result.is_err());
    }

    #[test]
    fn snapshot_create_ns_selector_requires_a() {
        // --namespace-selector without -A should fail
        let result = Args::try_parse_from([
            "oc-deps",
            "snapshot",
            "create",
            "--namespace-selector",
            "env=prod",
        ]);
        assert!(result.is_err());
    }

    #[test]
    fn snapshot_create_exclude_ns_requires_a() {
        // --exclude-namespace without -A should fail
        let result = Args::try_parse_from([
            "oc-deps",
            "snapshot",
            "create",
            "--exclude-namespace",
            "temp-*",
        ]);
        assert!(result.is_err());
    }

    #[test]
    fn snapshot_create_exclude_system_requires_a() {
        // --exclude-system-namespaces without -A should fail
        let result = Args::try_parse_from([
            "oc-deps",
            "snapshot",
            "create",
            "--exclude-system-namespaces",
        ]);
        assert!(result.is_err());
    }

    #[test]
    fn test_snapshot_diff_parses() {
        let args = Args::parse_from(["oc-deps", "snapshot", "diff", "before.json", "after.json"]);
        match args.command {
            Command::Snapshot {
                action: SnapshotAction::Diff { before, after, .. },
            } => {
                assert_eq!(before, "before.json");
                assert_eq!(after, "after.json");
            }
            _ => panic!("Expected Command::Snapshot Diff"),
        }
    }

    // ── graph subcommand tests ──

    #[test]
    fn test_graph_strict_parses() {
        let args = Args::parse_from(["oc-deps", "graph", "-n", "myns", "--strict"]);
        match args.command {
            Command::Graph { strict, .. } => {
                assert!(strict);
            }
            _ => panic!("Expected Command::Graph"),
        }
    }

    #[test]
    fn test_graph_refresh_discovery() {
        let args = Args::parse_from(["oc-deps", "graph", "-n", "myns", "--refresh-discovery"]);
        match args.command {
            Command::Graph {
                refresh_discovery, ..
            } => {
                assert!(refresh_discovery);
            }
            _ => panic!("Expected Command::Graph"),
        }
    }

    #[test]
    fn test_subcommand_required() {
        let result = Args::try_parse_from(["oc-deps"]);
        assert!(result.is_err(), "Expected error when no subcommand given");
    }

    #[test]
    fn test_snapshot_create_file_succeeds() {
        let args = Args::parse_from([
            "oc-deps", "snapshot", "create", "-n", "demo", "--file", "out.json",
        ]);
        match args.command {
            Command::Snapshot {
                action: SnapshotAction::Create { file, .. },
            } => {
                assert_eq!(file, "out.json");
            }
            _ => panic!("Expected snapshot create"),
        }
    }

    #[test]
    fn test_snapshot_create_dash_o_rejected() {
        let result = Args::try_parse_from(["oc-deps", "snapshot", "create", "-o", "out.json"]);
        assert!(
            result.is_err(),
            "snapshot create -o should be rejected (use --file)"
        );
    }

    #[test]
    fn test_snapshot_diff_dash_o_succeeds() {
        let args = Args::parse_from([
            "oc-deps", "snapshot", "diff", "a.json", "b.json", "-o", "json",
        ]);
        match args.command {
            Command::Snapshot {
                action: SnapshotAction::Diff { output, .. },
            } => {
                assert!(matches!(output, OutputFormat::Json));
            }
            _ => panic!("Expected snapshot diff"),
        }
    }

    #[test]
    fn test_snapshot_diff_format_rejected() {
        let result = Args::try_parse_from([
            "oc-deps", "snapshot", "diff", "a.json", "b.json", "--format", "json",
        ]);
        assert!(
            result.is_err(),
            "snapshot diff --format should be rejected (use -o)"
        );
    }

    #[test]
    fn test_graph_file_succeeds() {
        let args = Args::parse_from(["oc-deps", "graph", "-n", "demo", "--file", "g.json"]);
        match args.command {
            Command::Graph { file, .. } => assert_eq!(file, "g.json"),
            _ => panic!("Expected graph"),
        }
    }

    #[test]
    fn test_graph_dash_o_rejected() {
        let result = Args::try_parse_from(["oc-deps", "graph", "-o", "g.json"]);
        assert!(result.is_err(), "graph -o should be rejected (use --file)");
    }

    // ── teardown CLI v2 phase 4 tests ──

    #[test]
    fn test_teardown_plan_new_flags() {
        let args = Args::parse_from([
            "oc-deps",
            "teardown",
            "plan",
            "rhods-operator",
            "--approve-scope",
            "root",
            "--approve-resource",
            "Config/default",
            "--prune-crds",
        ]);
        match args.command {
            Command::Teardown {
                action:
                    TeardownAction::Plan {
                        operators,
                        prune_crds,
                        approve_scope,
                        approve_resource,
                        ..
                    },
            } => {
                assert_eq!(operators, vec!["rhods-operator"]);
                assert!(prune_crds);
                assert_eq!(approve_scope, vec!["root"]);
                assert_eq!(approve_resource, vec!["Config/default"]);
            }
            _ => panic!("Expected TeardownAction::Plan"),
        }
    }

    #[test]
    fn test_teardown_apply_plan_file() {
        let args = Args::parse_from(["oc-deps", "teardown", "apply", "plan.json", "--dry-run"]);
        match args.command {
            Command::Teardown {
                action: TeardownAction::Apply { plan, dry_run, .. },
            } => {
                assert_eq!(plan, "plan.json");
                assert!(dry_run);
            }
            _ => panic!("Expected TeardownAction::Apply"),
        }
    }

    #[test]
    fn test_teardown_batch() {
        let args = Args::parse_from(["oc-deps", "teardown", "batch", "config.json"]);
        match args.command {
            Command::Teardown {
                action: TeardownAction::Batch { config, .. },
            } => {
                assert_eq!(config, "config.json");
            }
            _ => panic!("Expected TeardownAction::Batch"),
        }
    }

    #[test]
    fn test_teardown_old_approve_delete_rejected() {
        let result = Args::try_parse_from([
            "oc-deps",
            "teardown",
            "plan",
            "rhods-operator",
            "--approve-delete",
            "all",
        ]);
        assert!(result.is_err(), "--approve-delete should be rejected");
    }

    #[test]
    fn test_teardown_old_prune_apis_rejected() {
        let result = Args::try_parse_from([
            "oc-deps",
            "teardown",
            "plan",
            "rhods-operator",
            "--prune-apis",
        ]);
        assert!(result.is_err(), "--prune-apis should be rejected");
    }

    #[test]
    fn test_teardown_old_force_rejected() {
        let result = Args::try_parse_from(["oc-deps", "teardown", "apply", "plan.json", "--force"]);
        assert!(result.is_err(), "--force should be rejected");
    }

    #[test]
    fn test_teardown_old_apply_set_rejected() {
        let result = Args::try_parse_from(["oc-deps", "teardown", "apply-set", "config.json"]);
        assert!(result.is_err(), "apply-set should be rejected (use batch)");
    }

    #[test]
    fn test_teardown_old_inspect_rejected() {
        let result = Args::try_parse_from(["oc-deps", "teardown", "inspect", "rhods-operator"]);
        assert!(result.is_err(), "teardown inspect should be rejected");
    }

    #[test]
    fn test_teardown_apply_without_plan_file_rejected() {
        let result = Args::try_parse_from(["oc-deps", "teardown", "apply"]);
        assert!(
            result.is_err(),
            "teardown apply without plan file should fail"
        );
    }
}
