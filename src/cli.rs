use clap::{Parser, Subcommand, ValueEnum};

/// Typed bulk approval scopes for --approve-scope.
/// `All` is intentionally excluded — use explicit scopes.
#[derive(Clone, Debug, ValueEnum)]
pub enum ApprovalScope {
    Root,
    Independent,
    LabelOnly,
    OperatorGroup,
}

impl ApprovalScope {
    pub fn cli_arg(&self) -> &'static str {
        match self {
            Self::Root => "root",
            Self::Independent => "independent",
            Self::LabelOnly => "label-only",
            Self::OperatorGroup => "operator-group",
        }
    }
}

/// Reject scope tokens passed as resource specs.
fn non_empty_path(s: &str) -> Result<String, String> {
    if s.is_empty() {
        Err("path must not be empty".to_string())
    } else {
        Ok(s.to_string())
    }
}

fn validate_resource_spec(s: &str) -> Result<String, String> {
    const SCOPE_TOKENS: &[&str] = &["root", "independent", "label-only", "operator-group", "all"];
    if SCOPE_TOKENS.contains(&s) {
        Err(format!(
            "'{}' is a scope token, not a resource spec. Use --approve-scope instead.",
            s
        ))
    } else {
        Ok(s.to_string())
    }
}

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

#[derive(Clone, Copy, Debug, ValueEnum)]
pub enum CompletionShell {
    Bash,
    Elvish,
    Fish,
    PowerShell,
    Zsh,
}

impl From<CompletionShell> for clap_complete::Shell {
    fn from(value: CompletionShell) -> Self {
        match value {
            CompletionShell::Bash => Self::Bash,
            CompletionShell::Elvish => Self::Elvish,
            CompletionShell::Fish => Self::Fish,
            CompletionShell::PowerShell => Self::PowerShell,
            CompletionShell::Zsh => Self::Zsh,
        }
    }
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
    /// Generate a shell completion script (offline)
    Completion {
        /// Shell to generate completions for
        #[arg(value_enum)]
        shell: CompletionShell,
    },

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

    /// Backup operator or namespace resources (read-only, no plan required)
    Backup {
        #[command(subcommand)]
        action: BackupAction,
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
pub enum BackupAction {
    /// Backup operator-discovered resources (same identity set as `operator resources --scope related`)
    Operator {
        /// Operator name (subscription or CSV name, must resolve unambiguously)
        #[arg(required = true)]
        operator: String,

        /// Output directory root
        #[arg(long, required = true, value_name = "DIR", value_parser = non_empty_path)]
        dir: String,

        /// Refresh API discovery cache
        #[arg(long)]
        refresh_discovery: bool,
    },

    /// Backup all namespace-scoped resources in a namespace
    Namespace {
        /// Namespace name
        #[arg(required = true)]
        namespace: String,

        /// Output directory root
        #[arg(long, required = true, value_name = "DIR", value_parser = non_empty_path)]
        dir: String,

        /// Refresh API discovery cache
        #[arg(long)]
        refresh_discovery: bool,
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

        /// Include CRD deletion in plan (default: keep)
        #[arg(long)]
        prune_crds: bool,

        /// Approve deletion scope (repeatable)
        #[arg(long = "approve-scope", value_enum)]
        approve_scope: Vec<ApprovalScope>,

        /// Approve deletion of specific resource (Kind/name or group/Kind/ns/name, repeatable)
        #[arg(long = "approve-resource", value_name = "SPEC", value_parser = validate_resource_spec)]
        approve_resource: Vec<String>,

        /// Keep a resource (Kind/name or group/Kind/ns/name, repeatable)
        #[arg(long = "keep-resource", value_name = "SPEC", value_parser = validate_resource_spec)]
        keep_resource: Vec<String>,

        /// Explicitly delete a resource after operator removal.
        ///
        /// Format: group/Kind/ns/name or Kind/ns/name (core group) or Kind/-/name (cluster-scoped).
        /// Supported kinds: Gateway, ConfigMap, Service, ConsolePlugin, Deployment.
        /// Forbidden: Namespace, PersistentVolume, PersistentVolumeClaim, CRD, APIService.
        /// Safety: typed inbound ref scan must pass at plan and apply time (fail-closed).
        #[arg(long = "delete-resource", value_name = "SPEC")]
        delete_resource: Vec<String>,

        /// Save the execution plan to file
        #[arg(long, value_name = "PATH")]
        file: Option<String>,
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

    /// Execute a teardown plan (reads from execution plan file)
    Apply {
        /// Path to execution plan JSON file
        #[arg(required = true)]
        plan: String,

        /// Refresh API discovery cache
        #[arg(long)]
        refresh_discovery: bool,

        /// Dry run — show what would be done without executing
        #[arg(long)]
        dry_run: bool,

        /// Non-interactive mode
        #[arg(long)]
        non_interactive: bool,

        /// Skip confirmation prompt (auto-approve execution)
        #[arg(short = 'y', long = "yes")]
        yes: bool,

        /// Headless script mode
        #[arg(long, value_name = "PATH")]
        script: Option<String>,

        /// Enable TUI mode
        #[arg(long)]
        tui: bool,

        /// Save pre-delete backup to this directory root before executing
        #[arg(long, value_name = "DIR", value_parser = non_empty_path)]
        backup_dir: Option<String>,
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

        /// Refresh API discovery once, then reuse within this batch
        #[arg(long)]
        refresh_discovery: bool,

        /// Dry run — validate config and show plan without executing
        #[arg(long)]
        dry_run: bool,

        /// Skip operators not found in the cluster instead of failing
        #[arg(long)]
        skip_missing: bool,

        /// Save per-operator backup bundles to this directory
        #[arg(long, value_name = "DIR", value_parser = non_empty_path)]
        backup_dir: Option<String>,
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

        /// Output format: tree, table, json
        #[arg(short = 'o', long, value_enum, default_value = "tree")]
        output: OutputFormat,
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

    /// Audit pre/post snapshot changes against teardown plans (offline)
    Audit {
        /// Path to the "before" snapshot JSON
        #[arg(value_name = "BEFORE")]
        before: String,

        /// Path to the "after" snapshot JSON
        #[arg(value_name = "AFTER")]
        after: String,

        /// Path to execution plan JSON (repeatable for multi-operator)
        #[arg(long = "plan", value_name = "PATH")]
        plans: Vec<String>,

        /// Path to GVR catalog JSON (for APIService derived classification)
        #[arg(long = "gvr-catalog", value_name = "PATH")]
        gvr_catalog: Option<String>,

        /// Path to provider API operands JSON
        #[arg(long = "provider-operands", value_name = "PATH")]
        provider_operands: Option<String>,

        /// Output format: tree (default), json, table
        #[arg(short = 'o', long, value_enum, default_value = "tree")]
        output: OutputFormat,
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

    #[test]
    fn test_snapshot_audit_parses() {
        let args = Args::parse_from([
            "oc-deps",
            "snapshot",
            "audit",
            "before.json",
            "after.json",
            "--plan",
            "p1.json",
            "--plan",
            "p2.json",
            "-o",
            "json",
        ]);
        match args.command {
            Command::Snapshot {
                action:
                    SnapshotAction::Audit {
                        before,
                        after,
                        plans,
                        output,
                        ..
                    },
            } => {
                assert_eq!(before, "before.json");
                assert_eq!(after, "after.json");
                assert_eq!(plans, vec!["p1.json", "p2.json"]);
                assert!(matches!(output, OutputFormat::Json));
            }
            _ => panic!("Expected Command::Snapshot Audit"),
        }
    }

    #[test]
    fn test_snapshot_audit_no_plan_parses() {
        let args = Args::parse_from(["oc-deps", "snapshot", "audit", "before.json", "after.json"]);
        match args.command {
            Command::Snapshot {
                action: SnapshotAction::Audit { plans, .. },
            } => {
                assert!(plans.is_empty());
            }
            _ => panic!("Expected Command::Snapshot Audit"),
        }
    }

    #[test]
    fn test_snapshot_audit_no_kubeconfig_needed() {
        let args = Args::parse_from(["oc-deps", "snapshot", "audit", "before.json", "after.json"]);
        assert!(matches!(
            args.command,
            Command::Snapshot {
                action: SnapshotAction::Audit { .. }
            }
        ));
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
    fn test_completion_shells_parse() {
        for shell in ["bash", "elvish", "fish", "power-shell", "zsh"] {
            let args = Args::try_parse_from(["oc-deps", "completion", shell])
                .unwrap_or_else(|e| panic!("{shell} should parse: {e}"));
            assert!(matches!(args.command, Command::Completion { .. }));
        }
    }

    #[test]
    fn documented_cli_examples_parse() {
        let examples: &[&[&str]] = &[
            &["tree", "deployment/app", "-n", "demo"],
            &["tree", "pod/app", "-n", "demo", "--direction", "parents"],
            &["map", "-n", "demo", "--root-kind", "Deployment"],
            &["map", "-A", "--exclude-system-namespaces"],
            &[
                "trace",
                "deployment/app",
                "-n",
                "demo",
                "--scope",
                "related",
            ],
            &["network", "deployment/app", "-n", "demo", "-o", "json"],
            &["operator", "list", "-o", "table"],
            &["operator", "owner", "deployment/app", "-n", "demo"],
            &[
                "operator",
                "resources",
                "example-operator",
                "--scope",
                "related",
            ],
            &["snapshot", "create", "-n", "demo", "--file", "before.json"],
            &[
                "snapshot",
                "diff",
                "before.json",
                "after.json",
                "-o",
                "json",
            ],
            &["graph", "-n", "demo", "--file", "graph.json"],
            &[
                "teardown",
                "plan",
                "example-operator",
                "--file",
                "plan.json",
            ],
            &["teardown", "apply", "plan.json", "--dry-run"],
            &[
                "teardown",
                "batch",
                "configs/full-teardown.json",
                "--dry-run",
            ],
            &["completion", "zsh"],
        ];

        for example in examples {
            let argv = std::iter::once("oc-deps").chain(example.iter().copied());
            Args::try_parse_from(argv)
                .unwrap_or_else(|e| panic!("documented example failed to parse: {example:?}: {e}"));
        }
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

    // ── teardown CLI tests ──

    #[test]
    fn test_teardown_apply_basic_parses() {
        let args = Args::parse_from(["oc-deps", "teardown", "apply", "plan.json", "--dry-run"]);
        match args.command {
            Command::Teardown {
                action: TeardownAction::Apply { plan, dry_run, .. },
            } => {
                assert_eq!(plan, "plan.json");
                assert!(dry_run);
            }
            _ => panic!("Expected Command::Teardown Apply"),
        }
    }

    #[test]
    fn test_teardown_apply_requires_plan_file() {
        let result = Args::try_parse_from(["oc-deps", "teardown", "apply"]);
        assert!(result.is_err(), "apply without plan file should fail");
    }

    #[test]
    fn test_teardown_apply_old_approve_delete_rejected() {
        let result = Args::try_parse_from([
            "oc-deps",
            "teardown",
            "apply",
            "plan.json",
            "--approve-delete",
            "all",
        ]);
        assert!(result.is_err(), "--approve-delete should be rejected");
    }

    #[test]
    fn test_teardown_apply_old_prune_apis_rejected() {
        let result =
            Args::try_parse_from(["oc-deps", "teardown", "apply", "plan.json", "--prune-apis"]);
        assert!(
            result.is_err(),
            "--prune-apis should be rejected (use --prune-crds on plan)"
        );
    }

    #[test]
    fn test_teardown_apply_old_approve_scope_rejected() {
        let result = Args::try_parse_from([
            "oc-deps",
            "teardown",
            "apply",
            "plan.json",
            "--approve-scope",
            "root",
        ]);
        assert!(
            result.is_err(),
            "--approve-scope should be rejected on apply (set on plan)"
        );
    }

    #[test]
    fn test_teardown_plan_approve_scope_parses() {
        let args = Args::parse_from([
            "oc-deps",
            "teardown",
            "plan",
            "rhods-operator",
            "--approve-scope",
            "root",
            "--prune-crds",
        ]);
        match args.command {
            Command::Teardown {
                action:
                    TeardownAction::Plan {
                        operators,
                        prune_crds,
                        approve_scope,
                        ..
                    },
            } => {
                assert_eq!(operators, vec!["rhods-operator"]);
                assert!(prune_crds);
                assert_eq!(approve_scope.len(), 1);
                assert_eq!(approve_scope[0].cli_arg(), "root");
            }
            _ => panic!("Expected Command::Teardown Plan"),
        }
    }

    #[test]
    fn test_teardown_plan_approve_scope_invalid_rejected() {
        let result = Args::try_parse_from([
            "oc-deps",
            "teardown",
            "plan",
            "op",
            "--approve-scope",
            "invalid-value",
        ]);
        assert!(
            result.is_err(),
            "--approve-scope invalid-value should be rejected by ValueEnum"
        );
    }

    #[test]
    fn test_teardown_plan_approve_scope_all_rejected() {
        let result = Args::try_parse_from([
            "oc-deps",
            "teardown",
            "plan",
            "op",
            "--approve-scope",
            "all",
        ]);
        assert!(
            result.is_err(),
            "--approve-scope all should be rejected (not in enum)"
        );
    }

    #[test]
    fn test_teardown_plan_approve_resource_rejects_scope_tokens() {
        for token in &["root", "independent", "label-only", "operator-group", "all"] {
            let result = Args::try_parse_from([
                "oc-deps",
                "teardown",
                "plan",
                "op",
                "--approve-resource",
                token,
            ]);
            assert!(
                result.is_err(),
                "--approve-resource {} should be rejected (scope token)",
                token
            );
        }
    }

    #[test]
    fn test_teardown_plan_approve_resource_accepts_resource_spec() {
        let args = Args::parse_from([
            "oc-deps",
            "teardown",
            "plan",
            "op",
            "--approve-resource",
            "Widget/example",
            "--approve-resource",
            "maas.opendatahub.io/Config/-/default",
        ]);
        match args.command {
            Command::Teardown {
                action:
                    TeardownAction::Plan {
                        approve_resource, ..
                    },
            } => {
                assert_eq!(
                    approve_resource,
                    vec!["Widget/example", "maas.opendatahub.io/Config/-/default"]
                );
            }
            _ => panic!("Expected Command::Teardown Plan"),
        }
    }

    #[test]
    fn test_teardown_plan_keep_resource_rejects_scope_tokens() {
        let result = Args::try_parse_from([
            "oc-deps",
            "teardown",
            "plan",
            "op",
            "--keep-resource",
            "root",
        ]);
        assert!(
            result.is_err(),
            "--keep-resource root should be rejected (scope token)"
        );
    }

    #[test]
    fn test_teardown_plan_old_save_plan_rejected() {
        let result = Args::try_parse_from([
            "oc-deps",
            "teardown",
            "plan",
            "op",
            "--save-plan",
            "out.json",
        ]);
        assert!(
            result.is_err(),
            "--save-plan should be rejected (use --file)"
        );
    }

    #[test]
    fn test_teardown_plan_file_parses() {
        let args = Args::parse_from(["oc-deps", "teardown", "plan", "op", "--file", "out.json"]);
        match args.command {
            Command::Teardown {
                action: TeardownAction::Plan { file, .. },
            } => {
                assert_eq!(file, Some("out.json".to_string()));
            }
            _ => panic!("Expected Command::Teardown Plan"),
        }
    }

    #[test]
    fn test_teardown_plan_old_no_cache_rejected() {
        let result = Args::try_parse_from(["oc-deps", "teardown", "plan", "op", "--no-cache"]);
        assert!(
            result.is_err(),
            "--no-cache should be rejected (use --refresh-discovery)"
        );
    }

    #[test]
    fn test_teardown_plan_refresh_discovery_parses() {
        let args = Args::parse_from(["oc-deps", "teardown", "plan", "op", "--refresh-discovery"]);
        match args.command {
            Command::Teardown {
                action:
                    TeardownAction::Plan {
                        refresh_discovery, ..
                    },
            } => {
                assert!(refresh_discovery);
            }
            _ => panic!("Expected Command::Teardown Plan"),
        }
    }

    #[test]
    fn test_teardown_inspect_rejected() {
        let result = Args::try_parse_from(["oc-deps", "teardown", "inspect", "op"]);
        assert!(
            result.is_err(),
            "teardown inspect should be rejected (removed)"
        );
    }

    #[test]
    fn test_apply_backup_dir_parse() {
        let args = Args::parse_from([
            "oc-deps",
            "teardown",
            "apply",
            "plan.json",
            "--backup-dir",
            "/tmp/backups",
            "--dry-run",
        ]);
        match args.command {
            Command::Teardown {
                action:
                    TeardownAction::Apply {
                        backup_dir,
                        dry_run,
                        ..
                    },
            } => {
                assert_eq!(backup_dir, Some("/tmp/backups".to_string()));
                assert!(dry_run);
            }
            _ => panic!("Expected teardown apply"),
        }
    }

    #[test]
    fn test_apply_empty_backup_dir_rejected() {
        let result = Args::try_parse_from([
            "oc-deps",
            "teardown",
            "apply",
            "plan.json",
            "--backup-dir",
            "",
        ]);
        assert!(result.is_err(), "empty backup-dir path must be rejected");
    }

    #[test]
    fn test_backup_operator_parse() {
        let args = Args::parse_from([
            "oc-deps",
            "backup",
            "operator",
            "nfd",
            "--dir",
            "/tmp/backups",
        ]);
        match args.command {
            Command::Backup {
                action: BackupAction::Operator { operator, dir, .. },
            } => {
                assert_eq!(operator, "nfd");
                assert_eq!(dir, "/tmp/backups");
            }
            _ => panic!("Expected backup operator"),
        }
    }

    #[test]
    fn test_backup_namespace_parse() {
        let args = Args::parse_from([
            "oc-deps",
            "backup",
            "namespace",
            "demo",
            "--dir",
            "/tmp/backups",
        ]);
        match args.command {
            Command::Backup {
                action: BackupAction::Namespace { namespace, dir, .. },
            } => {
                assert_eq!(namespace, "demo");
                assert_eq!(dir, "/tmp/backups");
            }
            _ => panic!("Expected backup namespace"),
        }
    }

    #[test]
    fn test_backup_missing_dir_rejected() {
        let result = Args::try_parse_from(["oc-deps", "backup", "operator", "nfd"]);
        assert!(result.is_err(), "missing --dir must be rejected");
    }

    #[test]
    fn test_backup_empty_dir_rejected() {
        let result = Args::try_parse_from(["oc-deps", "backup", "operator", "nfd", "--dir", ""]);
        assert!(result.is_err(), "empty --dir must be rejected");
    }

    #[test]
    fn test_batch_backup_dir_parse() {
        let args = Args::parse_from([
            "oc-deps",
            "teardown",
            "batch",
            "config.json",
            "--backup-dir",
            "/tmp/backups",
        ]);
        match args.command {
            Command::Teardown {
                action: TeardownAction::Batch { backup_dir, .. },
            } => {
                assert_eq!(backup_dir, Some("/tmp/backups".to_string()));
            }
            _ => panic!("Expected teardown batch"),
        }
    }

    #[test]
    fn test_batch_empty_backup_dir_rejected() {
        let result = Args::try_parse_from([
            "oc-deps",
            "teardown",
            "batch",
            "config.json",
            "--backup-dir",
            "",
        ]);
        assert!(result.is_err(), "empty backup-dir path must be rejected");
    }

    #[test]
    fn test_apply_no_backup_option_unchanged() {
        let args = Args::parse_from(["oc-deps", "teardown", "apply", "plan.json"]);
        match args.command {
            Command::Teardown {
                action: TeardownAction::Apply { backup_dir, .. },
            } => {
                assert!(backup_dir.is_none());
            }
            _ => panic!("Expected teardown apply"),
        }
    }

    #[test]
    fn test_batch_no_backup_option_unchanged() {
        let args = Args::parse_from(["oc-deps", "teardown", "batch", "config.json"]);
        match args.command {
            Command::Teardown {
                action: TeardownAction::Batch { backup_dir, .. },
            } => {
                assert!(backup_dir.is_none());
            }
            _ => panic!("Expected teardown batch"),
        }
    }

    // === Phase 1 contract tests: freeze current CLI surface ===
    // These tests document the options that Phase 2 will remove (--tui, --script, --non-interactive)
    // and verify that the options that will survive continue to parse correctly.

    #[test]
    fn phase1_apply_accepts_tui_flag() {
        let args = Args::try_parse_from(["oc-deps", "teardown", "apply", "plan.json", "--tui"]);
        assert!(args.is_ok(), "--tui must be accepted pre-Phase-2");
        match args.unwrap().command {
            Command::Teardown {
                action: TeardownAction::Apply { tui, .. },
            } => assert!(tui),
            _ => panic!("Expected teardown apply"),
        }
    }

    #[test]
    fn phase1_apply_accepts_script_flag() {
        let args = Args::try_parse_from([
            "oc-deps",
            "teardown",
            "apply",
            "plan.json",
            "--script",
            "/tmp/cmds.json",
        ]);
        assert!(args.is_ok(), "--script must be accepted pre-Phase-2");
        match args.unwrap().command {
            Command::Teardown {
                action: TeardownAction::Apply { script, .. },
            } => assert_eq!(script.as_deref(), Some("/tmp/cmds.json")),
            _ => panic!("Expected teardown apply"),
        }
    }

    #[test]
    fn phase1_apply_accepts_non_interactive_flag() {
        let args = Args::try_parse_from([
            "oc-deps",
            "teardown",
            "apply",
            "plan.json",
            "--non-interactive",
        ]);
        assert!(
            args.is_ok(),
            "--non-interactive must be accepted pre-Phase-2"
        );
        match args.unwrap().command {
            Command::Teardown {
                action:
                    TeardownAction::Apply {
                        non_interactive, ..
                    },
            } => assert!(non_interactive),
            _ => panic!("Expected teardown apply"),
        }
    }

    #[test]
    fn phase1_apply_surviving_options_parse() {
        let args = Args::try_parse_from([
            "oc-deps",
            "teardown",
            "apply",
            "plan.json",
            "-y",
            "--dry-run",
            "--backup-dir",
            "/tmp/backups",
            "--refresh-discovery",
        ]);
        assert!(args.is_ok(), "surviving apply options must parse");
        match args.unwrap().command {
            Command::Teardown {
                action:
                    TeardownAction::Apply {
                        yes,
                        dry_run,
                        backup_dir,
                        refresh_discovery,
                        ..
                    },
            } => {
                assert!(yes);
                assert!(dry_run);
                assert_eq!(backup_dir.as_deref(), Some("/tmp/backups"));
                assert!(refresh_discovery);
            }
            _ => panic!("Expected teardown apply"),
        }
    }

    #[test]
    fn phase1_resume_options_parse() {
        let args = Args::try_parse_from([
            "oc-deps",
            "teardown",
            "resume",
            "my-operator",
            "--run",
            "run-123",
            "--refresh-discovery",
        ]);
        assert!(args.is_ok(), "resume options must parse");
        match args.unwrap().command {
            Command::Teardown {
                action:
                    TeardownAction::Resume {
                        operator,
                        run,
                        refresh_discovery,
                    },
            } => {
                assert_eq!(operator.as_deref(), Some("my-operator"));
                assert_eq!(run.as_deref(), Some("run-123"));
                assert!(refresh_discovery);
            }
            _ => panic!("Expected teardown resume"),
        }
    }

    #[test]
    fn phase1_batch_options_parse() {
        let args = Args::try_parse_from([
            "oc-deps",
            "teardown",
            "batch",
            "config.json",
            "--dry-run",
            "--skip-missing",
            "--backup-dir",
            "/tmp/b",
            "--refresh-discovery",
        ]);
        assert!(args.is_ok(), "batch options must parse");
        match args.unwrap().command {
            Command::Teardown {
                action:
                    TeardownAction::Batch {
                        config,
                        dry_run,
                        skip_missing,
                        backup_dir,
                        refresh_discovery,
                    },
            } => {
                assert_eq!(config, "config.json");
                assert!(dry_run);
                assert!(skip_missing);
                assert_eq!(backup_dir.as_deref(), Some("/tmp/b"));
                assert!(refresh_discovery);
            }
            _ => panic!("Expected teardown batch"),
        }
    }
}
