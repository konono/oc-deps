use clap::{Parser, Subcommand, ValueEnum};

#[derive(Parser)]
#[command(
    name = "oc-deps",
    version,
    about = "Kubernetes Resource Dependency Inspector"
)]
pub struct Args {
    #[command(subcommand)]
    pub command: Option<Command>,

    /// Namespace (default: kubeconfig の default namespace)
    #[arg(short = 'n', long)]
    pub namespace: Option<String>,

    /// Resource kind (e.g. Pod, Deployment). RESOURCE が kind/name なら不要
    #[arg(short = 'k', long)]
    pub kind: Option<String>,

    /// Output format: tree, table, json
    #[arg(short = 'o', long, value_enum, default_value = "tree")]
    pub output: OutputFormat,

    /// Max traversal depth
    #[arg(short = 'd', long, default_value_t = 20)]
    pub depth: usize,

    /// Show only parent chain (namespace scan をスキップして高速)
    #[arg(long)]
    pub up_only: bool,

    /// Show only child resources
    #[arg(long)]
    pub down_only: bool,

    /// Show ALL dependency trees in the namespace
    #[arg(long)]
    pub map: bool,

    /// Show which Operator/CSV installed the CRD for this Kind
    #[arg(long)]
    pub crd_origin: bool,

    /// Disable spec-level references (Secret, ConfigMap, CRD cross-references)
    #[arg(long)]
    pub no_refs: bool,

    /// Include Event resources in scan (default: skip)
    #[arg(long)]
    pub include_events: bool,

    /// Skip discovery cache (force fresh API discovery)
    #[arg(long)]
    pub no_cache: bool,

    /// Show detailed scan warnings and diagnostics
    #[arg(short = 'v', long)]
    pub verbose: bool,

    /// Exit with code 2 if any API types were skipped during scan
    #[arg(long)]
    pub strict: bool,

    /// Show labels on each resource in tree output
    #[arg(long)]
    pub labels: bool,

    /// Show annotations on each resource in tree output
    #[arg(long)]
    pub annotations: bool,

    /// Show network paths (Service/Ingress/Route) for Pod/Deployment/ReplicaSet/StatefulSet/DaemonSet
    #[arg(long)]
    pub network: bool,

    /// Filter --map results by root resource. Applies to root nodes only.
    /// Repeatable (AND). Requires --map.
    /// Examples: --filter kind=Deployment --filter label=app=myapp
    #[arg(long, value_name = "FILTER")]
    pub filter: Vec<String>,

    /// Target resource: kind/name or name (with -k). --map 使用時は省略可
    #[arg(value_name = "RESOURCE")]
    pub resource: Option<String>,
}

#[derive(Subcommand)]
pub enum Command {
    /// Show which Operator manages a resource (ownerRef chain → CSV → Subscription)
    WhoManages {
        /// Resource in kind/name format
        #[arg(value_name = "RESOURCE")]
        resource: String,

        /// Namespace (default: kubeconfig default)
        #[arg(short = 'n', long)]
        namespace: Option<String>,

        /// Output format: tree, json
        #[arg(short = 'o', long, value_enum, default_value = "tree")]
        output: OutputFormat,

        /// Skip discovery cache
        #[arg(long)]
        no_cache: bool,
    },

    /// Take a cluster snapshot and save to JSON
    Snapshot {
        /// Namespace to snapshot
        #[arg(short = 'n', long)]
        namespace: Option<String>,

        /// Output file path
        #[arg(short = 'o', long, default_value = "snapshot.json")]
        output_file: String,

        /// Include Event resources in scan (default: skip)
        #[arg(long)]
        include_events: bool,

        /// Skip discovery cache (force fresh API discovery)
        #[arg(long)]
        no_cache: bool,
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
        #[arg(long, value_enum, default_value = "tree")]
        format: OutputFormat,
    },

    /// Build and export the evidence graph for a namespace
    Graph {
        /// Namespace to analyze
        #[arg(short = 'n', long)]
        namespace: Option<String>,

        /// Output file path
        #[arg(short = 'o', long, default_value = "evidence-graph.json")]
        output_file: String,

        /// Include Event resources in scan (default: skip)
        #[arg(long)]
        include_events: bool,

        /// Skip discovery cache (force fresh API discovery)
        #[arg(long)]
        no_cache: bool,
    },

    /// Teardown planning for OLM operators
    Teardown {
        #[command(subcommand)]
        action: TeardownAction,
    },

    /// Inspect all resources managed by an operator
    Inspect {
        /// Operator name (subscription or CSV name, partial match OK)
        #[arg(required = true)]
        operator: String,

        /// Output format: tree, table, json
        #[arg(short = 'o', long, value_enum, default_value = "tree")]
        output: OutputFormat,

        /// Skip discovery cache
        #[arg(long)]
        no_cache: bool,

        /// Discover resources across namespaces via OperatorGroup, owned CRD instances, and label evidence
        #[arg(long)]
        cross_namespace: bool,

        /// Show all scan/discovery warnings (default: first 5)
        #[arg(short = 'v', long)]
        verbose: bool,

        /// Exit with code 2 if discovery/scan is incomplete (partial results are still output)
        #[arg(long)]
        strict: bool,
    },

    /// Trace impact radius from a root resource (ownerRef descendants, spec refs, same-operator CRDs, labels)
    Trace {
        /// Resource in kind/name format
        #[arg(value_name = "RESOURCE")]
        resource: String,

        /// Namespace (default: kubeconfig default)
        #[arg(short = 'n', long)]
        namespace: Option<String>,

        /// Output format: tree, table, json
        #[arg(short = 'o', long, value_enum, default_value = "tree")]
        output: OutputFormat,

        /// Skip discovery cache
        #[arg(long)]
        no_cache: bool,

        /// Max traversal depth
        #[arg(short = 'd', long, default_value_t = 20)]
        depth: usize,

        /// Show all scan/discovery warnings (default: first 5)
        #[arg(short = 'v', long)]
        verbose: bool,

        /// Exit with code 2 if discovery/scan is incomplete (partial results are still output)
        #[arg(long)]
        strict: bool,

        /// Discover resources across namespaces via OperatorGroup, owned CRD instances, and label evidence
        #[arg(long)]
        cross_namespace: bool,
    },

    /// List all OLM-managed operators in the cluster
    Operators {
        /// Output format: tree, table, json
        #[arg(short = 'o', long, value_enum, default_value = "tree")]
        output: OutputFormat,

        /// Skip discovery cache (force fresh API discovery)
        #[arg(long)]
        no_cache: bool,
    },
}

#[derive(Subcommand)]
pub enum TeardownAction {
    /// Generate a teardown plan
    Plan {
        /// Operator names (subscription or CSV name, partial match OK)
        #[arg(required = true)]
        operators: Vec<String>,

        /// Output format: tree, json
        #[arg(short = 'o', long, value_enum, default_value = "tree")]
        output: OutputFormat,

        /// Skip discovery cache
        #[arg(long)]
        no_cache: bool,

        /// Remove CRDs after teardown (default: keep)
        #[arg(long)]
        prune_apis: bool,

        /// Approve deletion of REVIEW resources. Bulk scopes: "root", "independent", "all",
        /// "label-only", "operator-group"; or use Kind/name or group/Kind/ns/name (repeatable)
        #[arg(long = "approve-delete", value_name = "SPEC")]
        approve_delete: Vec<String>,

        /// Preserve a REVIEW resource (keep instead of delete). Kind/name or group/Kind/ns/name (repeatable)
        #[arg(long, value_name = "SPEC")]
        preserve: Vec<String>,

        /// Save the plan as a SavedTeardownPlan to the specified path
        #[arg(long = "save-plan", value_name = "PATH")]
        save_plan_path: Option<String>,
    },

    /// Check current status of resources in a teardown plan
    Status {
        /// Operator names (subscription or CSV name, partial match OK)
        #[arg(required_unless_present = "plan_file")]
        operators: Vec<String>,

        /// Skip discovery cache
        #[arg(long)]
        no_cache: bool,

        /// Load plan from a saved JSON file instead of re-generating
        #[arg(long = "plan-file", value_name = "PATH")]
        plan_file: Option<String>,
    },

    /// Execute a teardown plan
    Apply {
        /// Operator names (subscription or CSV name, partial match OK).
        /// Not required when --plan is specified.
        #[arg(required_unless_present = "plan")]
        operators: Vec<String>,

        /// Load a saved plan JSON file. Targets come from the plan, not positional args.
        /// Cannot be combined with positional operator arguments.
        #[arg(long, value_name = "PATH")]
        plan: Option<String>,

        /// Skip discovery cache
        #[arg(long)]
        no_cache: bool,

        /// Dry run — show what would be done without executing
        #[arg(long)]
        dry_run: bool,

        /// Remove CRDs after teardown (default: keep)
        #[arg(long)]
        prune_apis: bool,

        /// Suppress advisory warning output. REVIEW resources remain preserved
        /// unless explicitly approved for DELETE.
        #[arg(long)]
        force: bool,

        /// Approve deletion of REVIEW resources. Bulk scopes: "root", "independent", "all",
        /// "label-only", "operator-group"; or use Kind/name or group/Kind/ns/name (repeatable)
        #[arg(long = "approve-delete", value_name = "SPEC")]
        approve_delete: Vec<String>,

        /// Preserve a REVIEW resource (keep instead of delete). Kind/name or group/Kind/ns/name (repeatable)
        #[arg(long, value_name = "SPEC")]
        preserve: Vec<String>,

        /// Finalizer recovery is enabled by default. This flag is accepted for
        /// compatibility but has no effect. Recovery targets EXPECT descendants
        /// (owned by Gone root) and explicit DELETE targets stuck with finalizers.
        /// Uses atomic JSON Patch with UID + finalizer array test. Protected kinds
        /// (Namespace, CRD, etc.) are excluded.
        #[arg(long, hide = true)]
        approve_finalizer_recovery: bool,

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

        /// Output format: tree, json
        #[arg(short = 'o', long, value_enum, default_value = "tree")]
        output: OutputFormat,

        /// Skip discovery cache
        #[arg(long)]
        no_cache: bool,
    },

    /// Inspect all resources belonging to an operator
    Inspect {
        /// Operator name (subscription or CSV name, partial match OK)
        #[arg(required = true)]
        operator: String,

        /// Output format: tree, json
        #[arg(short = 'o', long, value_enum, default_value = "tree")]
        output: OutputFormat,

        /// Skip discovery cache
        #[arg(long)]
        no_cache: bool,
    },

    /// Explain why a resource is scheduled at its position in the plan
    Explain {
        /// Operator names to plan teardown for
        #[arg(required = true)]
        operators: Vec<String>,

        /// Resource to explain (kind/name format)
        #[arg(long)]
        resource: String,

        /// Skip discovery cache
        #[arg(long)]
        no_cache: bool,
    },

    /// Resume a paused or interrupted teardown run
    Resume {
        /// Operator CSV name to find latest run
        operator: Option<String>,

        /// Specific run ID
        #[arg(long)]
        run: Option<String>,

        /// Skip discovery cache
        #[arg(long)]
        no_cache: bool,
    },

    /// List all teardown runs for the current cluster
    Runs,

    /// Execute teardown for multiple operators from a config file (sequential)
    ApplySet {
        /// Path to JSON config file listing operators and their flags
        #[arg(required = true)]
        config: String,

        /// Refresh API discovery once, then reuse it within this apply-set
        #[arg(long)]
        no_cache: bool,

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
    fn test_inspect_subcommand_parse() {
        let args = Args::parse_from(["oc-deps", "inspect", "rhods-operator"]);
        match args.command {
            Some(Command::Inspect {
                operator,
                cross_namespace,
                ..
            }) => {
                assert_eq!(operator, "rhods-operator");
                assert!(!cross_namespace);
            }
            _ => panic!("Expected Command::Inspect"),
        }
    }

    #[test]
    fn test_inspect_cross_namespace() {
        let args = Args::parse_from(["oc-deps", "inspect", "rhods-operator", "--cross-namespace"]);
        match args.command {
            Some(Command::Inspect {
                cross_namespace, ..
            }) => {
                assert!(cross_namespace);
            }
            _ => panic!("Expected Command::Inspect"),
        }
    }

    #[test]
    fn test_trace_subcommand_parse() {
        let args = Args::parse_from([
            "oc-deps",
            "trace",
            "datasciencecluster/default",
            "-n",
            "test-ns",
        ]);
        match args.command {
            Some(Command::Trace {
                resource,
                namespace,
                depth,
                ..
            }) => {
                assert_eq!(resource, "datasciencecluster/default");
                assert_eq!(namespace, Some("test-ns".to_string()));
                assert_eq!(depth, 20);
            }
            _ => panic!("Expected Command::Trace"),
        }
    }

    #[test]
    fn test_trace_custom_depth() {
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
            Some(Command::Trace { depth, output, .. }) => {
                assert_eq!(depth, 5);
                assert!(matches!(output, OutputFormat::Json));
            }
            _ => panic!("Expected Command::Trace"),
        }
    }

    #[test]
    fn test_trace_cross_namespace() {
        let args = Args::parse_from([
            "oc-deps",
            "trace",
            "deployment/foo",
            "-n",
            "test-ns",
            "--cross-namespace",
            "--strict",
        ]);
        match args.command {
            Some(Command::Trace {
                cross_namespace,
                strict,
                ..
            }) => {
                assert!(cross_namespace);
                assert!(strict);
            }
            _ => panic!("Expected Command::Trace"),
        }
    }

    #[test]
    fn test_inspect_verbose_strict() {
        let args = Args::parse_from([
            "oc-deps",
            "inspect",
            "rhods-operator",
            "--verbose",
            "--strict",
        ]);
        match args.command {
            Some(Command::Inspect {
                verbose, strict, ..
            }) => {
                assert!(verbose);
                assert!(strict);
            }
            _ => panic!("Expected Command::Inspect"),
        }
    }
}
