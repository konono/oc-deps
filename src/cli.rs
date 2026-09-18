use clap::{Parser, ValueEnum};

#[derive(Parser)]
#[command(
    name = "oc-deps",
    version,
    about = "Kubernetes Resource Dependency Inspector"
)]
pub struct Args {
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

#[derive(Clone, Debug, ValueEnum)]
pub enum OutputFormat {
    Tree,
    Table,
    Json,
}
