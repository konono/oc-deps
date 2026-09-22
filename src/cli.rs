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

    /// Target resource: kind/name or name (with -k). --map 使用時は省略可
    #[arg(value_name = "RESOURCE")]
    pub resource: Option<String>,
}

#[derive(Subcommand)]
pub enum Command {
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

        /// Approve deletion of REVIEW resources. Use "root", "independent", "all" for bulk,
        /// or Kind/name or group/Kind/ns/name for exact resource approval (repeatable)
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

        /// Approve deletion of REVIEW resources. Use "root", "independent", "all" for bulk,
        /// or Kind/name or group/Kind/ns/name for exact resource approval (repeatable)
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

        /// Skip discovery cache
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
