use std::collections::{BTreeMap, HashMap, HashSet};
use std::fmt;

use serde::{Deserialize, Serialize};

// ──────────────────────────────────────────────────────────────
//  Scan warning types
// ──────────────────────────────────────────────────────────────

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum ScanWarning {
    Forbidden {
        gvr: String,
        status: u16,
    },
    Timeout {
        gvr: String,
        message: Option<String>,
        retries: usize,
    },
    RateLimited {
        gvr: String,
        retries: usize,
    },
    ServerError {
        gvr: String,
        status: u16,
        message: String,
        retries: usize,
    },
    NotFound {
        gvr: String,
    },
    Other {
        gvr: String,
        message: String,
    },
}

impl ScanWarning {
    pub fn from_kube_error(err: &kube::Error, group: &str, version: &str, plural: &str) -> Self {
        let gvr = if group.is_empty() {
            format!("{}/{}", version, plural)
        } else {
            format!("{}/{}/{}", group, version, plural)
        };
        match err {
            kube::Error::Api(resp) => match resp.code {
                404 => ScanWarning::NotFound { gvr },
                401 => ScanWarning::Forbidden { gvr, status: 401 },
                403 => ScanWarning::Forbidden { gvr, status: 403 },
                408 => ScanWarning::Timeout {
                    gvr,
                    message: Some(resp.message.clone()),
                    retries: 0,
                },
                429 => ScanWarning::RateLimited { gvr, retries: 0 },
                500..=599 => ScanWarning::ServerError {
                    gvr,
                    status: resp.code,
                    message: resp.message.clone(),
                    retries: 0,
                },
                _ => ScanWarning::Other {
                    gvr,
                    message: resp.message.clone(),
                },
            },
            _ => {
                let msg = err.to_string();
                if msg.contains("timed out") || msg.contains("timeout") {
                    ScanWarning::Timeout {
                        gvr,
                        message: Some(msg),
                        retries: 0,
                    }
                } else {
                    ScanWarning::Other { gvr, message: msg }
                }
            }
        }
    }

    pub fn is_retryable(&self) -> bool {
        matches!(
            self,
            ScanWarning::Timeout { .. }
                | ScanWarning::RateLimited { .. }
                | ScanWarning::ServerError { .. }
        )
    }

    pub fn is_not_found(&self) -> bool {
        matches!(self, ScanWarning::NotFound { .. })
    }

    pub fn set_retries(&mut self, count: usize) {
        match self {
            ScanWarning::Timeout { retries, .. } => *retries = count,
            ScanWarning::RateLimited { retries, .. } => *retries = count,
            ScanWarning::ServerError { retries, .. } => *retries = count,
            _ => {}
        }
    }
}

impl fmt::Display for ScanWarning {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ScanWarning::NotFound { gvr } => write!(f, "{} (404 Not Found)", gvr),
            ScanWarning::Forbidden { gvr, status } => {
                let label = if *status == 401 {
                    "Unauthorized"
                } else {
                    "Forbidden"
                };
                write!(f, "{} ({} {})", gvr, status, label)
            }
            ScanWarning::Timeout { gvr, retries, .. } => {
                if *retries > 0 {
                    write!(f, "{} (timeout, retried {}x)", gvr, retries)
                } else {
                    write!(f, "{} (timeout)", gvr)
                }
            }
            ScanWarning::RateLimited { gvr, retries } => {
                if *retries > 0 {
                    write!(f, "{} (429 Too Many Requests, retried {}x)", gvr, retries)
                } else {
                    write!(f, "{} (429 Too Many Requests)", gvr)
                }
            }
            ScanWarning::ServerError {
                gvr,
                status,
                retries,
                ..
            } => {
                if *retries > 0 {
                    write!(f, "{} ({} Server Error, retried {}x)", gvr, status, retries)
                } else {
                    write!(f, "{} ({} Server Error)", gvr, status)
                }
            }
            ScanWarning::Other { gvr, message } => write!(f, "{} ({})", gvr, message),
        }
    }
}

const MAX_DEFAULT_WARNINGS: usize = 5;

pub fn format_scan_warnings(warnings: &[ScanWarning], verbose: bool) {
    if warnings.is_empty() {
        return;
    }
    eprintln!(
        "\n⚠ {} API type{} skipped during scan:",
        warnings.len(),
        if warnings.len() == 1 { "" } else { "s" }
    );
    let display_items: &[ScanWarning] = if verbose {
        warnings
    } else if warnings.len() > MAX_DEFAULT_WARNINGS {
        &warnings[..MAX_DEFAULT_WARNINGS]
    } else {
        warnings
    };
    for w in display_items {
        if verbose {
            match w {
                ScanWarning::ServerError {
                    gvr,
                    status,
                    message,
                    retries,
                } => {
                    eprintln!(
                        "  - {} ({}: {}, retried {}x)",
                        gvr, status, message, retries
                    );
                }
                ScanWarning::Timeout {
                    gvr,
                    message,
                    retries,
                } => {
                    let msg = message.as_deref().unwrap_or("no details");
                    eprintln!("  - {} (timeout: {}, retried {}x)", gvr, msg, retries);
                }
                ScanWarning::RateLimited { gvr, retries } => {
                    eprintln!("  - {} (429 Too Many Requests, retried {}x)", gvr, retries);
                }
                ScanWarning::Other { gvr, message } => {
                    eprintln!("  - {} ({})", gvr, message);
                }
                _ => eprintln!("  - {}", w),
            }
        } else {
            eprintln!("  - {}", w);
        }
    }
    if !verbose && warnings.len() > MAX_DEFAULT_WARNINGS {
        eprintln!(
            "  ... and {} more (use --verbose to see all)",
            warnings.len() - MAX_DEFAULT_WARNINGS
        );
    }
    eprintln!("  Results may be incomplete.");
}

// ──────────────────────────────────────────────────────────────
//  Query coverage ledger
// ──────────────────────────────────────────────────────────────

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "outcome")]
pub enum QueryOutcome {
    Success { count: usize, pages: usize },
    ApiAbsent,
    Forbidden { status: u16 },
    Timeout { retries: usize },
    RateLimited { retries: usize },
    ServerError { status: u16, retries: usize },
    ListUnsupported,
    TargetMissing,
    Unknown { message: String },
}

impl QueryOutcome {
    #[cfg(test)]
    pub fn is_failure(&self) -> bool {
        matches!(
            self,
            QueryOutcome::Forbidden { .. }
                | QueryOutcome::Timeout { .. }
                | QueryOutcome::RateLimited { .. }
                | QueryOutcome::ServerError { .. }
                | QueryOutcome::Unknown { .. }
        )
    }

    pub fn is_absent(&self) -> bool {
        matches!(self, QueryOutcome::ApiAbsent)
    }

    pub fn is_target_missing(&self) -> bool {
        matches!(self, QueryOutcome::TargetMissing)
    }

    pub fn is_incomplete(&self, requirement: &QueryRequirement) -> bool {
        match requirement {
            QueryRequirement::Required => !matches!(self, QueryOutcome::Success { .. }),
            QueryRequirement::Optional => matches!(
                self,
                QueryOutcome::Forbidden { .. }
                    | QueryOutcome::Timeout { .. }
                    | QueryOutcome::RateLimited { .. }
                    | QueryOutcome::ServerError { .. }
                    | QueryOutcome::Unknown { .. }
            ),
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub enum QueryRequirement {
    Required,
    Optional,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub enum QueryOperation {
    List,
    Get,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct QueryRecord {
    pub gvr: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub namespace: Option<String>,
    pub scope: String,
    pub operation: QueryOperation,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub target_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub label_selector: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub field_selector: Option<String>,
    pub outcome: QueryOutcome,
    pub elapsed_ms: u64,
    pub requirement: QueryRequirement,
}

pub const COVERAGE_SCHEMA_VERSION: u32 = 1;

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct CoverageLedger {
    #[serde(default)]
    pub schema_version: Option<u32>,
    pub records: Vec<QueryRecord>,
}

impl CoverageLedger {
    pub fn new() -> Self {
        Self {
            schema_version: Some(COVERAGE_SCHEMA_VERSION),
            records: Vec::new(),
        }
    }

    pub fn record(&mut self, record: QueryRecord) {
        self.records.push(record);
    }

    pub fn has_incomplete(&self) -> bool {
        self.records
            .iter()
            .any(|r| r.outcome.is_incomplete(&r.requirement))
    }

    pub fn incomplete_count(&self) -> usize {
        self.records
            .iter()
            .filter(|r| r.outcome.is_incomplete(&r.requirement))
            .count()
    }

    pub fn sort_records(&mut self) {
        self.records.sort_by(|a, b| {
            a.gvr
                .cmp(&b.gvr)
                .then(a.namespace.cmp(&b.namespace))
                .then(a.scope.cmp(&b.scope))
                .then(a.operation.cmp(&b.operation))
                .then(a.target_name.cmp(&b.target_name))
                .then(a.label_selector.cmp(&b.label_selector))
                .then(a.field_selector.cmp(&b.field_selector))
                .then(a.requirement.cmp(&b.requirement))
        });
    }

    pub fn snapshot(&mut self) -> (Option<CoverageSummary>, usize, Option<CoverageLedger>) {
        if self.records.is_empty() {
            return (None, 0, None);
        }
        let summary = self.summary();
        let incomplete = self.incomplete_count();
        self.sort_records();
        let cloned = self.clone();
        (Some(summary), incomplete, Some(cloned))
    }

    pub fn summary(&self) -> CoverageSummary {
        let total = self.records.len();
        let success = self
            .records
            .iter()
            .filter(|r| matches!(r.outcome, QueryOutcome::Success { .. }))
            .count();
        let incomplete = self.incomplete_count();
        let absent = self
            .records
            .iter()
            .filter(|r| r.outcome.is_absent())
            .count();
        let target_missing = self
            .records
            .iter()
            .filter(|r| r.outcome.is_target_missing())
            .count();
        let total_elapsed_ms: u64 = self.records.iter().map(|r| r.elapsed_ms).sum();
        CoverageSummary {
            total_queries: total,
            success,
            incomplete,
            api_absent: absent,
            target_missing,
            total_elapsed_ms,
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CoverageSummary {
    pub total_queries: usize,
    pub success: usize,
    pub incomplete: usize,
    pub api_absent: usize,
    pub target_missing: usize,
    pub total_elapsed_ms: u64,
}

pub fn format_coverage_summary(ledger: &CoverageLedger, verbose: bool) {
    let summary = ledger.summary();
    let is_tty = std::io::IsTerminal::is_terminal(&std::io::stderr());
    if is_tty {
        eprintln!(
            "\n📊 Coverage: {} queries, {} success, {} incomplete, {} absent, {} missing ({:.1}s)",
            summary.total_queries,
            summary.success,
            summary.incomplete,
            summary.api_absent,
            summary.target_missing,
            summary.total_elapsed_ms as f64 / 1000.0
        );
    } else {
        eprintln!(
            "\nCoverage: {} queries, {} success, {} incomplete, {} absent, {} missing ({:.1}s)",
            summary.total_queries,
            summary.success,
            summary.incomplete,
            summary.api_absent,
            summary.target_missing,
            summary.total_elapsed_ms as f64 / 1000.0
        );
    }
    if verbose {
        for r in &ledger.records {
            let outcome_str = match &r.outcome {
                QueryOutcome::Success { count, pages } => {
                    format!("OK ({} items, {} pages)", count, pages)
                }
                QueryOutcome::ApiAbsent => "API absent".to_string(),
                QueryOutcome::Forbidden { status } => format!("{} Forbidden", status),
                QueryOutcome::Timeout { retries } => format!("Timeout (retries: {})", retries),
                QueryOutcome::RateLimited { retries } => {
                    format!("429 Rate Limited (retries: {})", retries)
                }
                QueryOutcome::ServerError { status, retries } => {
                    format!("{} Server Error (retries: {})", status, retries)
                }
                QueryOutcome::ListUnsupported => "LIST unsupported".to_string(),
                QueryOutcome::TargetMissing => "Target missing (404)".to_string(),
                QueryOutcome::Unknown { message } => format!("Unknown ({})", message),
            };
            let op_str = match r.operation {
                QueryOperation::Get => "GET",
                QueryOperation::List => "LIST",
            };
            let target_str = r
                .target_name
                .as_ref()
                .map(|n| format!(" target={}", n))
                .unwrap_or_default();
            let scope_str = r
                .namespace
                .as_ref()
                .map(|ns| format!(" ns={}", ns))
                .unwrap_or_default();
            let selector_str = r
                .label_selector
                .as_ref()
                .map(|s| format!(" selector={}", s))
                .unwrap_or_default();
            let field_sel_str = r
                .field_selector
                .as_ref()
                .map(|s| format!(" field_selector={}", s))
                .unwrap_or_default();
            let req_str = match r.requirement {
                QueryRequirement::Required => "required",
                QueryRequirement::Optional => "optional",
            };
            eprintln!(
                "  {} {} {}{}{}{}{} {}ms [{}]",
                r.gvr,
                op_str,
                outcome_str,
                target_str,
                scope_str,
                selector_str,
                field_sel_str,
                r.elapsed_ms,
                req_str
            );
        }
    }
}

pub fn scan_warning_to_outcome_for_get(w: &ScanWarning) -> QueryOutcome {
    match w {
        ScanWarning::NotFound { .. } => QueryOutcome::TargetMissing,
        _ => scan_warning_to_outcome(w),
    }
}

pub fn scan_warning_to_outcome(w: &ScanWarning) -> QueryOutcome {
    match w {
        ScanWarning::NotFound { .. } => QueryOutcome::ApiAbsent,
        ScanWarning::Forbidden { status, .. } => QueryOutcome::Forbidden { status: *status },
        ScanWarning::Timeout { retries, .. } => QueryOutcome::Timeout { retries: *retries },
        ScanWarning::RateLimited { retries, .. } => QueryOutcome::RateLimited { retries: *retries },
        ScanWarning::ServerError {
            status, retries, ..
        } => QueryOutcome::ServerError {
            status: *status,
            retries: *retries,
        },
        ScanWarning::Other { message, .. } => QueryOutcome::Unknown {
            message: message.clone(),
        },
    }
}

// ──────────────────────────────────────────────────────────────
//  Snapshot types — serializable, designed for persistence
// ──────────────────────────────────────────────────────────────

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ResourceId {
    pub group: String,
    pub version: String,
    pub kind: String,
    pub namespace: Option<String>,
    pub name: String,
    pub uid: Option<String>,
}

impl std::fmt::Display for ResourceId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}/{}", self.kind, self.name)
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct OwnerRefEntry {
    pub api_version: String,
    pub kind: String,
    pub name: String,
    pub uid: String,
    pub controller: bool,
    #[serde(default)]
    pub block_owner_deletion: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SpecRefEntry {
    pub target_kind: String,
    pub target_name: String,
    pub field_path: String,
}

pub const SNAPSHOT_SCHEMA_VERSION: u32 = 3;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ResourceEntry {
    pub id: ResourceId,
    pub owner_refs: Vec<OwnerRefEntry>,
    pub spec_refs: Vec<SpecRefEntry>,
    pub labels: HashMap<String, String>,
    pub annotations: HashMap<String, String>,
    pub raw_spec: Option<serde_json::Value>,
    #[serde(default)]
    pub data_keys: Option<Vec<String>>,
    #[serde(default)]
    pub data_hash: Option<String>,
    #[serde(default)]
    pub secret_value_hashes: Option<HashMap<String, String>>,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct SnapshotScope {
    pub mode: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub namespace_selectors: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub exclude_namespaces: Vec<String>,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub exclude_system_namespaces: bool,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub requested_namespaces: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub complete_namespaces: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub incomplete_namespaces: Vec<IncompleteNamespace>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct IncompleteNamespace {
    pub namespace: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub warnings: Vec<ScanWarning>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ClusterSnapshot {
    #[serde(default)]
    pub schema_version: Option<u32>,
    pub resources: HashMap<String, ResourceEntry>,
    #[serde(
        default,
        alias = "scan_errors",
        deserialize_with = "deserialize_scan_warnings"
    )]
    pub scan_warnings: Vec<ScanWarning>,
    pub cluster_url: String,
    pub taken_at: String,
    pub namespaces: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scope: Option<SnapshotScope>,
}

fn deserialize_scan_warnings<'de, D>(deserializer: D) -> Result<Vec<ScanWarning>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    use serde::de;

    #[derive(Deserialize)]
    #[serde(untagged)]
    enum WarningOrString {
        Warning(ScanWarning),
        LegacyString(String),
    }

    struct WarningsVisitor;

    impl<'de> de::Visitor<'de> for WarningsVisitor {
        type Value = Vec<ScanWarning>;

        fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
            formatter.write_str("a sequence of ScanWarning or legacy string errors")
        }

        fn visit_seq<A>(self, mut seq: A) -> Result<Vec<ScanWarning>, A::Error>
        where
            A: de::SeqAccess<'de>,
        {
            let mut warnings = Vec::new();
            while let Some(item) = seq.next_element::<WarningOrString>()? {
                match item {
                    WarningOrString::Warning(w) => warnings.push(w),
                    WarningOrString::LegacyString(s) => {
                        let (gvr, message) = s.split_once(": ").unwrap_or(("unknown", &s));
                        warnings.push(ScanWarning::Other {
                            gvr: gvr.to_string(),
                            message: message.to_string(),
                        });
                    }
                }
            }
            Ok(warnings)
        }
    }

    deserializer.deserialize_seq(WarningsVisitor)
}

pub const EXCLUDED_ANNOTATION_KEYS: &[&str] = &[
    "kubectl.kubernetes.io/last-applied-configuration",
    "control-plane.alpha.kubernetes.io/leader",
];

pub fn filter_annotations(annotations: &HashMap<String, String>) -> HashMap<String, String> {
    annotations
        .iter()
        .filter(|(k, _)| !EXCLUDED_ANNOTATION_KEYS.contains(&k.as_str()))
        .map(|(k, v)| (k.clone(), v.clone()))
        .collect()
}

// ──────────────────────────────────────────────────────────────
//  Container resource spec (--show-spec)
// ──────────────────────────────────────────────────────────────

#[derive(Clone, Debug, Serialize)]
pub struct ContainerResources {
    pub name: String,
    pub requests: Option<BTreeMap<String, String>>,
    pub limits: Option<BTreeMap<String, String>>,
}

#[derive(Clone, Debug, Serialize)]
pub struct PodTemplateInfo {
    pub containers: Vec<ContainerResources>,
    pub init_containers: Vec<ContainerResources>,
}

const SHOW_SPEC_KINDS: &[&str] = &[
    "Pod",
    "Deployment",
    "StatefulSet",
    "DaemonSet",
    "Job",
    "CronJob",
    "DeploymentConfig",
];

fn parse_container_resources(container: &serde_json::Value) -> Option<ContainerResources> {
    let name = container.get("name")?.as_str()?.to_string();
    let resources = container.get("resources");

    let requests = resources
        .and_then(|r| r.get("requests"))
        .and_then(|r| r.as_object())
        .map(|m| {
            m.iter()
                .map(|(k, v)| (k.clone(), v.as_str().unwrap_or("?").to_string()))
                .collect()
        });

    let limits = resources
        .and_then(|r| r.get("limits"))
        .and_then(|r| r.as_object())
        .map(|m| {
            m.iter()
                .map(|(k, v)| (k.clone(), v.as_str().unwrap_or("?").to_string()))
                .collect()
        });

    Some(ContainerResources {
        name,
        requests,
        limits,
    })
}

fn parse_containers_from(
    pod_spec: &serde_json::Value,
) -> (Vec<ContainerResources>, Vec<ContainerResources>) {
    let containers = pod_spec
        .get("containers")
        .and_then(|v| v.as_array())
        .map(|arr| arr.iter().filter_map(parse_container_resources).collect())
        .unwrap_or_default();
    let init_containers = pod_spec
        .get("initContainers")
        .and_then(|v| v.as_array())
        .map(|arr| arr.iter().filter_map(parse_container_resources).collect())
        .unwrap_or_default();
    (containers, init_containers)
}

pub fn extract_pod_template(kind: &str, data: &serde_json::Value) -> Option<PodTemplateInfo> {
    if !SHOW_SPEC_KINDS.iter().any(|k| k.eq_ignore_ascii_case(kind)) {
        return None;
    }

    let pod_spec = match kind {
        "Pod" => data.get("spec"),
        "CronJob" => data
            .get("spec")
            .and_then(|s| s.get("jobTemplate"))
            .and_then(|j| j.get("spec"))
            .and_then(|s| s.get("template"))
            .and_then(|t| t.get("spec")),
        _ => data
            .get("spec")
            .and_then(|s| s.get("template"))
            .and_then(|t| t.get("spec")),
    }?;

    let (containers, init_containers) = parse_containers_from(pod_spec);
    if containers.is_empty() && init_containers.is_empty() {
        return None;
    }
    Some(PodTemplateInfo {
        containers,
        init_containers,
    })
}

// ──────────────────────────────────────────────────────────────
//  Runtime types — used for live tree traversal (existing)
// ──────────────────────────────────────────────────────────────

#[derive(Clone)]
pub struct ResourceInfo {
    pub group: String,
    pub kind: String,
    pub name: String,
    pub namespace: Option<String>,
    pub uid: String,
    pub owner_refs: Vec<OwnerRef>,
    pub labels: HashMap<String, String>,
    pub annotations: HashMap<String, String>,
    pub pod_template: Option<PodTemplateInfo>,
}

pub type NamespaceIndexKey = (String, String, Option<String>, String);

#[derive(Clone)]
pub struct OwnerRef {
    pub api_version: String,
    pub kind: String,
    pub name: String,
    pub uid: String,
    pub controller: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize)]
pub enum SpecRefSource {
    Typed,
    Heuristic,
}

#[derive(Clone)]
pub struct SpecRef {
    pub target_kind: String,
    pub target_name: String,
    pub field_path: String,
    pub source: SpecRefSource,
}

pub struct ChainEntry {
    pub info: ResourceInfo,
    pub spec_refs: Vec<SpecRef>,
}

#[derive(Clone)]
pub struct IncomingRef {
    pub source_kind: String,
    pub source_name: String,
    pub field_path: String,
}

pub type ScanItem = (ResourceInfo, Vec<SpecRef>, Vec<(String, String)>);
pub type RefData = (String, String, Vec<SpecRef>, Vec<(String, String)>);

pub struct NamespaceIndex {
    pub by_uid: HashMap<String, ResourceInfo>,
    pub children_of: HashMap<String, Vec<String>>,
    pub by_kind_name: HashMap<NamespaceIndexKey, String>,
    pub refs_from: HashMap<String, Vec<SpecRef>>,
    pub refs_to: HashMap<String, Vec<IncomingRef>>,
}

impl NamespaceIndex {
    pub fn new() -> Self {
        Self {
            by_uid: HashMap::new(),
            children_of: HashMap::new(),
            by_kind_name: HashMap::new(),
            refs_from: HashMap::new(),
            refs_to: HashMap::new(),
        }
    }

    pub fn insert(&mut self, info: ResourceInfo) {
        let uid = info.uid.clone();
        let key = (
            info.group.to_lowercase(),
            info.kind.to_lowercase(),
            info.namespace.clone(),
            info.name.clone(),
        );

        for oref in &info.owner_refs {
            self.children_of
                .entry(oref.uid.clone())
                .or_default()
                .push(uid.clone());
        }

        self.by_kind_name.insert(key, uid.clone());
        self.by_uid.insert(uid, info);
    }

    pub fn merge(&mut self, other: NamespaceIndex) {
        for (uid, info) in other.by_uid {
            if !self.by_uid.contains_key(&uid) {
                self.insert(info);
            }
        }
        for (uid, refs) in other.refs_from {
            self.refs_from.entry(uid).or_default().extend(refs);
        }
        for (uid, refs) in other.refs_to {
            self.refs_to.entry(uid).or_default().extend(refs);
        }
    }

    pub fn lookup_by_kind_name(
        &self,
        group: Option<&str>,
        kind: &str,
        name: &str,
        namespace: Option<&str>,
    ) -> Option<&String> {
        let kind_lower = kind.to_lowercase();
        if let Some(g) = group {
            // Exact group match only — no fallback to other groups
            return self.by_kind_name.get(&(
                g.to_lowercase(),
                kind_lower,
                namespace.map(|s| s.to_string()),
                name.to_string(),
            ));
        }
        // group=None: match any group (for spec-refs where group is unknown)
        for ((_, k, ns, n), uid) in &self.by_kind_name {
            if *k == kind_lower && *n == name && ns.as_deref() == namespace {
                return Some(uid);
            }
        }
        None
    }

    pub fn lookup_exact(
        &self,
        group: &str,
        kind: &str,
        namespace: Option<&str>,
        name: &str,
    ) -> Option<&String> {
        self.by_kind_name.get(&(
            group.to_lowercase(),
            kind.to_lowercase(),
            namespace.map(|s| s.to_string()),
            name.to_string(),
        ))
    }
}

pub fn resolve_kind_info<'a>(
    resource: &ResourceId,
    kind_map: &'a crate::kube::discovery::KindMap,
    gk_map: &'a crate::kube::discovery::GroupKindMap,
) -> Option<&'a crate::kube::discovery::KindInfo> {
    if !resource.group.is_empty() {
        gk_map.get(&(resource.group.clone(), resource.kind.clone()))
    } else {
        kind_map.get(&resource.kind)
    }
}

/// Resolve the correct API endpoint for a ResourceId.
/// Uses GroupKindMap for precise (group, kind) lookup, falls back to KindMap.
pub fn resolve_api(
    client: &kube::Client,
    resource: &ResourceId,
    kind_map: &crate::kube::discovery::KindMap,
    gk_map: &crate::kube::discovery::GroupKindMap,
) -> Option<(kube::api::Api<kube::api::DynamicObject>, bool)> {
    let kind_info = resolve_kind_info(resource, kind_map, gk_map)?;

    let (group, version) = if !resource.group.is_empty() && !resource.version.is_empty() {
        (resource.group.as_str(), resource.version.as_str())
    } else {
        (kind_info.group.as_str(), kind_info.version.as_str())
    };

    let gvk = kube::core::GroupVersion::gv(group, version).with_kind(&resource.kind);
    let ar = kube::api::ApiResource::from_gvk_with_plural(&gvk, &kind_info.plural);

    let api = if let Some(ns) = &resource.namespace {
        kube::api::Api::namespaced_with(client.clone(), ns, &ar)
    } else if kind_info.namespaced {
        return None;
    } else {
        kube::api::Api::all_with(client.clone(), &ar)
    };

    Some((api, kind_info.namespaced))
}

pub fn primary_owner(refs: &[OwnerRef]) -> Option<&OwnerRef> {
    refs.iter().find(|r| r.controller).or(refs.first())
}

pub fn dedup_spec_refs(refs: &mut Vec<SpecRef>) {
    let sa_name_entries: HashSet<(String, String, SpecRefSource)> = refs
        .iter()
        .filter(|r| {
            r.target_kind == "ServiceAccount" && r.field_path.ends_with(".serviceAccountName")
        })
        .map(|r| {
            (
                r.field_path
                    .strip_suffix(".serviceAccountName")
                    .unwrap()
                    .to_string(),
                r.target_name.clone(),
                r.source,
            )
        })
        .collect();
    refs.retain(|r| {
        if r.target_kind == "ServiceAccount" && r.field_path.ends_with(".serviceAccount") {
            let parent = r
                .field_path
                .strip_suffix(".serviceAccount")
                .unwrap_or(&r.field_path);
            !sa_name_entries.contains(&(parent.to_string(), r.target_name.clone(), r.source))
        } else {
            true
        }
    });

    let mut seen = HashSet::new();
    refs.retain(|r| {
        seen.insert((
            r.target_kind.clone(),
            r.target_name.clone(),
            r.field_path.clone(),
            r.source,
        ))
    });
    refs.sort_by(|a, b| {
        a.target_kind
            .cmp(&b.target_kind)
            .then(a.target_name.cmp(&b.target_name))
            .then(a.field_path.cmp(&b.field_path))
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::kube::discovery::{GroupKindMap, KindInfo, KindMap};

    fn make_resource_id(group: &str, kind: &str, name: &str) -> ResourceId {
        ResourceId {
            group: group.to_string(),
            version: "v1".to_string(),
            kind: kind.to_string(),
            namespace: None,
            name: name.to_string(),
            uid: None,
        }
    }

    fn make_kind_info(group: &str, plural: &str) -> KindInfo {
        KindInfo {
            group: group.to_string(),
            version: "v1".to_string(),
            plural: plural.to_string(),
            namespaced: true,
            listable: true,
        }
    }

    fn make_test_maps() -> (KindMap, GroupKindMap) {
        let mut km = KindMap::new();
        let mut gk = GroupKindMap::new();

        km.insert("Pod".to_string(), make_kind_info("", "pods"));
        gk.insert(
            ("".to_string(), "Pod".to_string()),
            make_kind_info("", "pods"),
        );

        // Subscription exists in two groups
        km.insert(
            "Subscription".to_string(),
            make_kind_info("operators.coreos.com", "subscriptions"),
        );
        gk.insert(
            (
                "operators.coreos.com".to_string(),
                "Subscription".to_string(),
            ),
            make_kind_info("operators.coreos.com", "subscriptions"),
        );
        gk.insert(
            (
                "messaging.example.com".to_string(),
                "Subscription".to_string(),
            ),
            make_kind_info("messaging.example.com", "messagingsubscriptions"),
        );

        (km, gk)
    }

    #[test]
    fn resolve_kind_info_with_group_uses_gk_map() {
        let (km, gk) = make_test_maps();
        let res = make_resource_id("operators.coreos.com", "Subscription", "test");
        let info = resolve_kind_info(&res, &km, &gk).unwrap();
        assert_eq!(info.plural, "subscriptions");
        assert_eq!(info.group, "operators.coreos.com");
    }

    #[test]
    fn resolve_kind_info_with_group_picks_correct_group() {
        let (km, gk) = make_test_maps();
        let res = make_resource_id("messaging.example.com", "Subscription", "test");
        let info = resolve_kind_info(&res, &km, &gk).unwrap();
        assert_eq!(info.plural, "messagingsubscriptions");
        assert_eq!(info.group, "messaging.example.com");
    }

    #[test]
    fn resolve_kind_info_group_mismatch_returns_none() {
        let (km, gk) = make_test_maps();
        let res = make_resource_id("nonexistent.group", "Subscription", "test");
        assert!(resolve_kind_info(&res, &km, &gk).is_none());
    }

    #[test]
    fn resolve_kind_info_without_group_uses_kind_map() {
        let (km, gk) = make_test_maps();
        let res = make_resource_id("", "Pod", "test");
        let info = resolve_kind_info(&res, &km, &gk).unwrap();
        assert_eq!(info.plural, "pods");
    }

    #[test]
    fn resolve_kind_info_unknown_kind_returns_none() {
        let (km, gk) = make_test_maps();
        let res = make_resource_id("", "NonExistentKind", "test");
        assert!(resolve_kind_info(&res, &km, &gk).is_none());
    }

    #[test]
    fn scan_warning_display_with_group() {
        let w = ScanWarning::Forbidden {
            gvr: "apps/v1/deployments".into(),
            status: 403,
        };
        assert_eq!(format!("{}", w), "apps/v1/deployments (403 Forbidden)");
    }

    #[test]
    fn scan_warning_display_core_group() {
        let w = ScanWarning::Forbidden {
            gvr: "v1/pods".into(),
            status: 403,
        };
        assert_eq!(format!("{}", w), "v1/pods (403 Forbidden)");
    }

    #[test]
    fn scan_warning_401_unauthorized() {
        let w = ScanWarning::Forbidden {
            gvr: "apps/v1/deployments".into(),
            status: 401,
        };
        let display = format!("{}", w);
        assert!(display.contains("Unauthorized"), "got: {}", display);
        assert!(!display.contains("Forbidden"), "got: {}", display);
    }

    #[test]
    fn scan_warning_retryable() {
        let timeout = ScanWarning::Timeout {
            gvr: "v1/pods".into(),
            message: None,
            retries: 0,
        };
        let rate = ScanWarning::RateLimited {
            gvr: "v1/pods".into(),
            retries: 0,
        };
        let server = ScanWarning::ServerError {
            gvr: "v1/pods".into(),
            status: 500,
            message: "err".into(),
            retries: 0,
        };
        let forbidden = ScanWarning::Forbidden {
            gvr: "v1/pods".into(),
            status: 403,
        };
        let other = ScanWarning::Other {
            gvr: "v1/pods".into(),
            message: "err".into(),
        };

        assert!(timeout.is_retryable());
        assert!(rate.is_retryable());
        assert!(server.is_retryable());
        assert!(!forbidden.is_retryable());
        assert!(!other.is_retryable());
    }

    #[test]
    fn scan_warning_set_retries_display() {
        let mut w = ScanWarning::Timeout {
            gvr: "v1/pods".into(),
            message: None,
            retries: 0,
        };
        w.set_retries(2);
        assert!(format!("{}", w).contains("retried 2x"));

        let mut w2 = ScanWarning::ServerError {
            gvr: "v1/pods".into(),
            status: 503,
            message: "unavail".into(),
            retries: 0,
        };
        w2.set_retries(1);
        assert!(format!("{}", w2).contains("retried 1x"));
    }

    #[test]
    fn scan_warning_zero_retries_no_suffix() {
        let w = ScanWarning::Timeout {
            gvr: "v1/pods".into(),
            message: None,
            retries: 0,
        };
        assert!(!format!("{}", w).contains("retried"));
    }

    #[test]
    fn scan_warning_serialization_roundtrip() {
        let w = ScanWarning::Forbidden {
            gvr: "apps/v1/deployments".into(),
            status: 403,
        };
        let json = serde_json::to_string(&w).unwrap();
        let w2: ScanWarning = serde_json::from_str(&json).unwrap();
        assert_eq!(format!("{}", w), format!("{}", w2));
    }

    #[test]
    fn scan_warning_serialization_timeout_with_retries() {
        let w = ScanWarning::Timeout {
            gvr: "v1/pods".into(),
            message: Some("conn timeout".into()),
            retries: 2,
        };
        let json = serde_json::to_string(&w).unwrap();
        let w2: ScanWarning = serde_json::from_str(&json).unwrap();
        assert!(format!("{}", w2).contains("retried 2x"));
    }

    #[test]
    fn filter_annotations_excludes_last_applied() {
        let mut anns = HashMap::new();
        anns.insert(
            "kubectl.kubernetes.io/last-applied-configuration".into(),
            "{}".into(),
        );
        anns.insert("app.kubernetes.io/name".into(), "myapp".into());
        let filtered = filter_annotations(&anns);
        assert_eq!(filtered.len(), 1);
        assert!(filtered.contains_key("app.kubernetes.io/name"));
    }

    #[test]
    fn filter_annotations_excludes_leader() {
        let mut anns = HashMap::new();
        anns.insert(
            "control-plane.alpha.kubernetes.io/leader".into(),
            "{}".into(),
        );
        let filtered = filter_annotations(&anns);
        assert!(filtered.is_empty());
    }

    #[test]
    fn filter_annotations_keeps_revision() {
        let mut anns = HashMap::new();
        anns.insert("deployment.kubernetes.io/revision".into(), "3".into());
        let filtered = filter_annotations(&anns);
        assert_eq!(filtered.len(), 1);
        assert!(filtered.contains_key("deployment.kubernetes.io/revision"));
    }

    #[test]
    fn scan_warning_gvr_format_construction() {
        let w = ScanWarning::Other {
            gvr: "apps/v1/deployments".into(),
            message: "test".into(),
        };
        assert!(format!("{}", w).starts_with("apps/v1/deployments"));

        let w2 = ScanWarning::Other {
            gvr: "v1/pods".into(),
            message: "test".into(),
        };
        assert!(format!("{}", w2).starts_with("v1/pods"));
    }

    #[test]
    fn snapshot_deserialize_legacy_scan_errors() {
        let json = serde_json::json!({
            "resources": {},
            "scan_errors": ["Pod: 403 Forbidden", "Deployment: timeout"],
            "cluster_url": "https://api.test:6443",
            "taken_at": "2026-01-01T00:00:00Z",
            "namespaces": ["default"]
        });
        let snap: ClusterSnapshot = serde_json::from_value(json).unwrap();
        assert_eq!(snap.scan_warnings.len(), 2);
        match &snap.scan_warnings[0] {
            ScanWarning::Other { gvr, message } => {
                assert_eq!(gvr, "Pod");
                assert_eq!(message, "403 Forbidden");
            }
            other => panic!("expected Other, got {:?}", other),
        }
        match &snap.scan_warnings[1] {
            ScanWarning::Other { gvr, message } => {
                assert_eq!(gvr, "Deployment");
                assert_eq!(message, "timeout");
            }
            other => panic!("expected Other, got {:?}", other),
        }
    }

    #[test]
    fn snapshot_deserialize_typed_scan_warnings() {
        let json = serde_json::json!({
            "resources": {},
            "scan_warnings": [
                {"type": "Forbidden", "gvr": "apps/v1/deployments", "status": 403},
                {"type": "Timeout", "gvr": "v1/pods", "message": null, "retries": 2}
            ],
            "cluster_url": "https://api.test:6443",
            "taken_at": "2026-01-01T00:00:00Z",
            "namespaces": ["default"]
        });
        let snap: ClusterSnapshot = serde_json::from_value(json).unwrap();
        assert_eq!(snap.scan_warnings.len(), 2);
        match &snap.scan_warnings[0] {
            ScanWarning::Forbidden { gvr, status } => {
                assert_eq!(gvr, "apps/v1/deployments");
                assert_eq!(*status, 403);
            }
            other => panic!("expected Forbidden, got {:?}", other),
        }
        match &snap.scan_warnings[1] {
            ScanWarning::Timeout { gvr, retries, .. } => {
                assert_eq!(gvr, "v1/pods");
                assert_eq!(*retries, 2);
            }
            other => panic!("expected Timeout, got {:?}", other),
        }
    }

    #[test]
    fn snapshot_deserialize_missing_warnings_field() {
        let json = serde_json::json!({
            "resources": {},
            "cluster_url": "https://api.test:6443",
            "taken_at": "2026-01-01T00:00:00Z",
            "namespaces": ["default"]
        });
        let snap: ClusterSnapshot = serde_json::from_value(json).unwrap();
        assert!(snap.scan_warnings.is_empty());
    }

    #[test]
    fn snapshot_serialize_roundtrip() {
        let snap = ClusterSnapshot {
            schema_version: Some(SNAPSHOT_SCHEMA_VERSION),
            resources: HashMap::new(),
            scan_warnings: vec![
                ScanWarning::Forbidden {
                    gvr: "v1/secrets".into(),
                    status: 403,
                },
                ScanWarning::Timeout {
                    gvr: "apps/v1/deployments".into(),
                    message: Some("conn".into()),
                    retries: 1,
                },
            ],
            cluster_url: "https://api.test:6443".into(),
            taken_at: "2026-01-01T00:00:00Z".into(),
            namespaces: vec!["default".into()],
            scope: None,
        };
        let json = serde_json::to_string(&snap).unwrap();
        let snap2: ClusterSnapshot = serde_json::from_str(&json).unwrap();
        assert_eq!(snap2.scan_warnings.len(), 2);
        assert_eq!(
            format!("{}", snap2.scan_warnings[0]),
            format!("{}", snap.scan_warnings[0])
        );
        assert_eq!(
            format!("{}", snap2.scan_warnings[1]),
            format!("{}", snap.scan_warnings[1])
        );
    }

    // ── QueryOutcome / CoverageLedger tests ──

    #[test]
    fn query_outcome_success_not_failure() {
        let o = QueryOutcome::Success { count: 5, pages: 1 };
        assert!(!o.is_failure());
        assert!(!o.is_absent());
    }

    #[test]
    fn query_outcome_forbidden_is_failure() {
        let o = QueryOutcome::Forbidden { status: 403 };
        assert!(o.is_failure());
        assert!(!o.is_absent());
    }

    #[test]
    fn query_outcome_absent_not_failure() {
        let o = QueryOutcome::ApiAbsent;
        assert!(!o.is_failure());
        assert!(o.is_absent());
    }

    #[test]
    fn query_outcome_timeout_is_failure() {
        let o = QueryOutcome::Timeout { retries: 2 };
        assert!(o.is_failure());
    }

    #[test]
    fn query_outcome_rate_limited_is_failure() {
        let o = QueryOutcome::RateLimited { retries: 1 };
        assert!(o.is_failure());
    }

    #[test]
    fn query_outcome_server_error_is_failure() {
        let o = QueryOutcome::ServerError {
            status: 500,
            retries: 2,
        };
        assert!(o.is_failure());
    }

    #[test]
    fn query_outcome_list_unsupported_not_failure() {
        let o = QueryOutcome::ListUnsupported;
        assert!(!o.is_failure());
        assert!(!o.is_absent());
    }

    #[test]
    fn coverage_ledger_summary() {
        let mut ledger = CoverageLedger::new();
        ledger.record(QueryRecord {
            gvr: "apps/v1/deployments".into(),
            namespace: Some("default".into()),
            scope: "namespaced".into(),
            operation: QueryOperation::List,
            target_name: None,
            label_selector: None,
            field_selector: None,
            outcome: QueryOutcome::Success { count: 3, pages: 1 },
            elapsed_ms: 100,
            requirement: QueryRequirement::Required,
        });
        ledger.record(QueryRecord {
            gvr: "custom.io/v1/widgets".into(),
            namespace: None,
            scope: "cluster".into(),
            operation: QueryOperation::List,
            target_name: None,
            label_selector: None,
            field_selector: None,
            outcome: QueryOutcome::ApiAbsent,
            elapsed_ms: 5,
            requirement: QueryRequirement::Optional,
        });
        ledger.record(QueryRecord {
            gvr: "v1/secrets".into(),
            namespace: Some("kube-system".into()),
            scope: "namespaced".into(),
            operation: QueryOperation::List,
            target_name: None,
            label_selector: None,
            field_selector: None,
            outcome: QueryOutcome::Forbidden { status: 403 },
            elapsed_ms: 10,
            requirement: QueryRequirement::Required,
        });
        let summary = ledger.summary();
        assert_eq!(summary.total_queries, 3);
        assert_eq!(summary.success, 1);
        assert_eq!(summary.incomplete, 1);
        assert_eq!(summary.api_absent, 1);
        assert_eq!(summary.total_elapsed_ms, 115);
    }

    #[test]
    fn target_missing_separate_from_api_absent_in_summary() {
        let mut ledger = CoverageLedger::new();
        ledger.record(QueryRecord {
            gvr: "apps/v1/deployments".into(),
            namespace: Some("default".into()),
            scope: "namespaced".into(),
            operation: QueryOperation::Get,
            target_name: Some("nonexistent".into()),
            label_selector: None,
            field_selector: None,
            outcome: QueryOutcome::TargetMissing,
            elapsed_ms: 5,
            requirement: QueryRequirement::Required,
        });
        ledger.record(QueryRecord {
            gvr: "custom/v1/widgets".into(),
            namespace: None,
            scope: "cluster".into(),
            operation: QueryOperation::List,
            target_name: None,
            label_selector: None,
            field_selector: None,
            outcome: QueryOutcome::ApiAbsent,
            elapsed_ms: 3,
            requirement: QueryRequirement::Optional,
        });
        let summary = ledger.summary();
        assert_eq!(summary.api_absent, 1, "only ApiAbsent counted");
        assert_eq!(
            summary.target_missing, 1,
            "TargetMissing counted separately"
        );
        assert_eq!(
            summary.incomplete, 1,
            "Required TargetMissing is incomplete"
        );
    }

    #[test]
    fn coverage_ledger_strict_failures() {
        let mut ledger = CoverageLedger::new();
        ledger.record(QueryRecord {
            gvr: "apps/v1/deployments".into(),
            namespace: Some("default".into()),
            scope: "namespaced".into(),
            operation: QueryOperation::List,
            target_name: None,
            label_selector: None,
            field_selector: None,
            outcome: QueryOutcome::Success { count: 5, pages: 1 },
            elapsed_ms: 50,
            requirement: QueryRequirement::Required,
        });
        assert!(!ledger.has_incomplete());
        assert_eq!(ledger.incomplete_count(), 0);

        ledger.record(QueryRecord {
            gvr: "custom.io/v1/widgets".into(),
            namespace: None,
            scope: "cluster".into(),
            operation: QueryOperation::List,
            target_name: None,
            label_selector: None,
            field_selector: None,
            outcome: QueryOutcome::ApiAbsent,
            elapsed_ms: 5,
            requirement: QueryRequirement::Optional,
        });
        assert!(
            !ledger.has_incomplete(),
            "optional ApiAbsent should not be strict failure"
        );

        ledger.record(QueryRecord {
            gvr: "v1/secrets".into(),
            namespace: Some("ns".into()),
            scope: "namespaced".into(),
            operation: QueryOperation::List,
            target_name: None,
            label_selector: None,
            field_selector: None,
            outcome: QueryOutcome::Forbidden { status: 403 },
            elapsed_ms: 10,
            requirement: QueryRequirement::Required,
        });
        assert!(ledger.has_incomplete());
        assert_eq!(ledger.incomplete_count(), 1);
    }

    #[test]
    fn coverage_ledger_optional_absent_not_strict() {
        let mut ledger = CoverageLedger::new();
        ledger.record(QueryRecord {
            gvr: "missing.io/v1/things".into(),
            namespace: None,
            scope: "cluster".into(),
            operation: QueryOperation::List,
            target_name: None,
            label_selector: None,
            field_selector: None,
            outcome: QueryOutcome::ApiAbsent,
            elapsed_ms: 2,
            requirement: QueryRequirement::Optional,
        });
        assert!(!ledger.has_incomplete());
        assert_eq!(ledger.incomplete_count(), 0);
    }

    #[test]
    fn query_outcome_unknown_is_failure() {
        let o = QueryOutcome::Unknown {
            message: "something weird".into(),
        };
        assert!(o.is_failure());
        assert!(!o.is_absent());
    }

    #[test]
    fn query_outcome_serialization_roundtrip() {
        let o = QueryOutcome::Timeout { retries: 2 };
        let json = serde_json::to_string(&o).unwrap();
        let o2: QueryOutcome = serde_json::from_str(&json).unwrap();
        assert!(o2.is_failure());
    }

    #[test]
    fn query_outcome_unknown_serialization() {
        let o = QueryOutcome::Unknown {
            message: "test error".into(),
        };
        let json = serde_json::to_string(&o).unwrap();
        assert!(json.contains("Unknown"));
        let o2: QueryOutcome = serde_json::from_str(&json).unwrap();
        assert!(o2.is_failure());
    }

    #[test]
    fn coverage_ledger_serialization_roundtrip() {
        let mut ledger = CoverageLedger::new();
        ledger.record(QueryRecord {
            gvr: "apps/v1/deployments".into(),
            namespace: Some("default".into()),
            scope: "namespaced".into(),
            operation: QueryOperation::List,
            target_name: None,
            label_selector: Some("app=test".into()),
            field_selector: None,
            outcome: QueryOutcome::Success { count: 1, pages: 1 },
            elapsed_ms: 50,
            requirement: QueryRequirement::Required,
        });
        let json = serde_json::to_string(&ledger).unwrap();
        let ledger2: CoverageLedger = serde_json::from_str(&json).unwrap();
        assert_eq!(ledger2.records.len(), 1);
        assert_eq!(ledger2.schema_version, Some(1));
    }

    #[test]
    fn scan_warning_to_outcome_conversion() {
        let w = ScanWarning::NotFound {
            gvr: "v1/pods".into(),
        };
        assert!(scan_warning_to_outcome(&w).is_absent());

        let w2 = ScanWarning::Forbidden {
            gvr: "v1/pods".into(),
            status: 403,
        };
        assert!(scan_warning_to_outcome(&w2).is_failure());

        let w3 = ScanWarning::Timeout {
            gvr: "v1/pods".into(),
            message: None,
            retries: 2,
        };
        match scan_warning_to_outcome(&w3) {
            QueryOutcome::Timeout { retries } => assert_eq!(retries, 2),
            other => panic!("expected Timeout, got {:?}", other),
        }

        let w4 = ScanWarning::Other {
            gvr: "v1/pods".into(),
            message: "something went wrong".into(),
        };
        match scan_warning_to_outcome(&w4) {
            QueryOutcome::Unknown { message } => {
                assert_eq!(message, "something went wrong");
            }
            other => panic!("expected Unknown, got {:?}", other),
        }
    }

    #[test]
    fn test_namespace_index_group_kind_ns_name_identity() {
        let mut index = NamespaceIndex::new();
        index.insert(ResourceInfo {
            group: "apps".into(),
            kind: "Deployment".into(),
            name: "myapp".into(),
            namespace: Some("ns-a".into()),
            uid: "uid-1".into(),
            owner_refs: vec![],
            labels: HashMap::new(),
            annotations: HashMap::new(),
            pod_template: None,
        });
        index.insert(ResourceInfo {
            group: "apps".into(),
            kind: "Deployment".into(),
            name: "myapp".into(),
            namespace: Some("ns-b".into()),
            uid: "uid-2".into(),
            owner_refs: vec![],
            labels: HashMap::new(),
            annotations: HashMap::new(),
            pod_template: None,
        });

        assert_eq!(
            index.lookup_exact("apps", "Deployment", Some("ns-a"), "myapp"),
            Some(&"uid-1".to_string())
        );
        assert_eq!(
            index.lookup_exact("apps", "Deployment", Some("ns-b"), "myapp"),
            Some(&"uid-2".to_string())
        );
        assert_eq!(index.by_uid.len(), 2);
    }

    #[test]
    fn test_namespace_index_merge_no_overwrite() {
        let mut index1 = NamespaceIndex::new();
        index1.insert(ResourceInfo {
            group: "apps".into(),
            kind: "Deployment".into(),
            name: "myapp".into(),
            namespace: Some("ns-a".into()),
            uid: "uid-1".into(),
            owner_refs: vec![],
            labels: HashMap::new(),
            annotations: HashMap::new(),
            pod_template: None,
        });

        let mut index2 = NamespaceIndex::new();
        index2.insert(ResourceInfo {
            group: "apps".into(),
            kind: "Deployment".into(),
            name: "myapp".into(),
            namespace: Some("ns-b".into()),
            uid: "uid-2".into(),
            owner_refs: vec![],
            labels: HashMap::new(),
            annotations: HashMap::new(),
            pod_template: None,
        });

        index1.merge(index2);
        assert_eq!(index1.by_uid.len(), 2);
        assert!(index1.by_uid.contains_key("uid-1"));
        assert!(index1.by_uid.contains_key("uid-2"));
    }

    #[test]
    fn test_lookup_by_kind_name_exact_group() {
        let mut index = NamespaceIndex::new();
        index.insert(ResourceInfo {
            group: "apps".into(),
            kind: "Deployment".into(),
            name: "myapp".into(),
            namespace: Some("default".into()),
            uid: "uid-apps".into(),
            owner_refs: vec![],
            labels: HashMap::new(),
            annotations: HashMap::new(),
            pod_template: None,
        });
        index.insert(ResourceInfo {
            group: "custom.io".into(),
            kind: "Deployment".into(),
            name: "myapp".into(),
            namespace: Some("default".into()),
            uid: "uid-custom".into(),
            owner_refs: vec![],
            labels: HashMap::new(),
            annotations: HashMap::new(),
            pod_template: None,
        });

        assert_eq!(
            index.lookup_by_kind_name(Some("apps"), "Deployment", "myapp", Some("default")),
            Some(&"uid-apps".to_string())
        );
        assert_eq!(
            index.lookup_by_kind_name(Some("custom.io"), "Deployment", "myapp", Some("default")),
            Some(&"uid-custom".to_string())
        );
    }

    #[test]
    fn test_lookup_wrong_group_returns_none() {
        let mut index = NamespaceIndex::new();
        index.insert(ResourceInfo {
            group: "apps".into(),
            kind: "Deployment".into(),
            name: "myapp".into(),
            namespace: Some("default".into()),
            uid: "uid-1".into(),
            owner_refs: vec![],
            labels: HashMap::new(),
            annotations: HashMap::new(),
            pod_template: None,
        });

        assert_eq!(
            index.lookup_by_kind_name(Some("wrong.io"), "Deployment", "myapp", Some("default")),
            None
        );
        assert_eq!(
            index.lookup_exact("wrong.io", "Deployment", Some("default"), "myapp"),
            None
        );
    }

    #[test]
    fn test_lookup_none_group_matches_any() {
        let mut index = NamespaceIndex::new();
        index.insert(ResourceInfo {
            group: "apps".into(),
            kind: "Deployment".into(),
            name: "myapp".into(),
            namespace: Some("default".into()),
            uid: "uid-1".into(),
            owner_refs: vec![],
            labels: HashMap::new(),
            annotations: HashMap::new(),
            pod_template: None,
        });

        assert_eq!(
            index.lookup_by_kind_name(None, "Deployment", "myapp", Some("default")),
            Some(&"uid-1".to_string())
        );
    }

    #[test]
    fn test_exact_group_no_fallback_to_other_group() {
        let mut index = NamespaceIndex::new();
        index.insert(ResourceInfo {
            group: "config.openshift.io".into(),
            kind: "Ingress".into(),
            name: "cluster".into(),
            namespace: None,
            uid: "uid-config".into(),
            owner_refs: vec![],
            labels: HashMap::new(),
            annotations: HashMap::new(),
            pod_template: None,
        });

        // Exact lookup for networking.k8s.io should NOT find config.openshift.io
        assert_eq!(
            index.lookup_by_kind_name(Some("networking.k8s.io"), "Ingress", "cluster", None,),
            None
        );
        assert_eq!(
            index.lookup_exact("networking.k8s.io", "Ingress", None, "cluster"),
            None
        );
        // But exact match for the correct group works
        assert_eq!(
            index.lookup_exact("config.openshift.io", "Ingress", None, "cluster"),
            Some(&"uid-config".to_string())
        );
    }

    #[test]
    fn test_bfs_descendant_does_not_include_unrelated_tree() {
        let mut index = NamespaceIndex::new();
        // CR root
        index.insert(ResourceInfo {
            group: "example.com".into(),
            kind: "Widget".into(),
            name: "root".into(),
            namespace: Some("ns-a".into()),
            uid: "uid-root".into(),
            owner_refs: vec![],
            labels: HashMap::new(),
            annotations: HashMap::new(),
            pod_template: None,
        });
        // Child of root
        index.insert(ResourceInfo {
            group: "apps".into(),
            kind: "Deployment".into(),
            name: "child".into(),
            namespace: Some("ns-a".into()),
            uid: "uid-child".into(),
            owner_refs: vec![OwnerRef {
                api_version: "example.com/v1".into(),
                kind: "Widget".into(),
                name: "root".into(),
                uid: "uid-root".into(),
                controller: true,
            }],
            labels: HashMap::new(),
            annotations: HashMap::new(),
            pod_template: None,
        });
        // Unrelated tree
        index.insert(ResourceInfo {
            group: "apps".into(),
            kind: "Deployment".into(),
            name: "unrelated".into(),
            namespace: Some("ns-a".into()),
            uid: "uid-unrelated".into(),
            owner_refs: vec![],
            labels: HashMap::new(),
            annotations: HashMap::new(),
            pod_template: None,
        });

        // BFS from root should find child but not unrelated
        let known_roots: HashSet<String> = ["uid-root".to_string()].into_iter().collect();
        let mut reachable = HashSet::new();
        let mut queue: Vec<String> = known_roots.iter().cloned().collect();
        while let Some(parent) = queue.pop() {
            if let Some(children) = index.children_of.get(&parent) {
                for child in children {
                    if reachable.insert(child.clone()) {
                        queue.push(child.clone());
                    }
                }
            }
        }
        assert!(reachable.contains("uid-child"));
        assert!(!reachable.contains("uid-unrelated"));
    }

    #[test]
    fn test_scan_warning_forbidden_no_retry() {
        let w = ScanWarning::Forbidden {
            gvr: "apps/v1/deployments".into(),
            status: 403,
        };
        assert!(!w.is_retryable());
        assert!(format!("{}", w).contains("403"));
        assert!(format!("{}", w).contains("Forbidden"));
    }

    #[test]
    fn test_scan_warning_timeout_is_retryable() {
        let mut w = ScanWarning::Timeout {
            gvr: "apps/v1/deployments".into(),
            message: Some("connection timed out".into()),
            retries: 0,
        };
        assert!(w.is_retryable());
        w.set_retries(2);
        assert!(format!("{}", w).contains("retried 2x"));
    }

    #[test]
    fn test_scan_warning_server_error_is_retryable() {
        let w = ScanWarning::ServerError {
            gvr: "apps/v1/deployments".into(),
            status: 503,
            message: "service unavailable".into(),
            retries: 1,
        };
        assert!(w.is_retryable());
        assert!(format!("{}", w).contains("503"));
    }

    #[test]
    fn test_scan_warning_canonical_gvr_format() {
        let w = ScanWarning::Forbidden {
            gvr: "datasciencecluster.opendatahub.io/v1/datascienceclusters".into(),
            status: 403,
        };
        let display = format!("{}", w);
        assert!(display.starts_with("datasciencecluster.opendatahub.io/v1/datascienceclusters"));
    }

    #[test]
    fn test_scan_warning_other_not_retryable() {
        let w = ScanWarning::Other {
            gvr: "test".into(),
            message: "unknown error".into(),
        };
        assert!(!w.is_retryable());
    }

    // ── extract_pod_template tests ──

    #[test]
    fn extract_pod_from_pod_spec() {
        let data = serde_json::json!({
            "spec": {
                "containers": [
                    {"name": "app", "resources": {"requests": {"cpu": "100m", "memory": "128Mi"}, "limits": {"cpu": "500m", "memory": "256Mi"}}}
                ]
            }
        });
        let pt = extract_pod_template("Pod", &data).unwrap();
        assert_eq!(pt.containers.len(), 1);
        assert_eq!(pt.containers[0].name, "app");
        assert_eq!(pt.containers[0].requests.as_ref().unwrap()["cpu"], "100m");
        assert_eq!(pt.containers[0].limits.as_ref().unwrap()["memory"], "256Mi");
        assert!(pt.init_containers.is_empty());
    }

    #[test]
    fn extract_pod_from_deployment_template() {
        let data = serde_json::json!({
            "spec": {"template": {"spec": {
                "containers": [{"name": "web", "resources": {"requests": {"cpu": "1"}, "limits": {"cpu": "2", "memory": "1Gi"}}}],
                "initContainers": [{"name": "init", "resources": {"requests": {"cpu": "50m"}, "limits": {"cpu": "100m"}}}]
            }}}
        });
        let pt = extract_pod_template("Deployment", &data).unwrap();
        assert_eq!(pt.containers.len(), 1);
        assert_eq!(pt.init_containers.len(), 1);
        assert_eq!(pt.init_containers[0].name, "init");
    }

    #[test]
    fn extract_pod_from_statefulset_template() {
        let data = serde_json::json!({
            "spec": {"template": {"spec": {
                "containers": [{"name": "db", "resources": {"requests": {"cpu": "500m"}}}]
            }}}
        });
        let pt = extract_pod_template("StatefulSet", &data).unwrap();
        assert_eq!(pt.containers[0].name, "db");
    }

    #[test]
    fn extract_pod_from_daemonset_template() {
        let data = serde_json::json!({
            "spec": {"template": {"spec": {
                "containers": [{"name": "agent", "resources": {}}]
            }}}
        });
        let pt = extract_pod_template("DaemonSet", &data).unwrap();
        assert_eq!(pt.containers[0].name, "agent");
        assert!(pt.containers[0].requests.is_none());
        assert!(pt.containers[0].limits.is_none());
    }

    #[test]
    fn extract_pod_from_job_template() {
        let data = serde_json::json!({
            "spec": {"template": {"spec": {
                "containers": [{"name": "worker", "resources": {"limits": {"nvidia.com/gpu": "1"}}}]
            }}}
        });
        let pt = extract_pod_template("Job", &data).unwrap();
        assert_eq!(
            pt.containers[0].limits.as_ref().unwrap()["nvidia.com/gpu"],
            "1"
        );
    }

    #[test]
    fn extract_pod_from_cronjob_job_template() {
        let data = serde_json::json!({
            "spec": {"jobTemplate": {"spec": {"template": {"spec": {
                "containers": [{"name": "cron", "resources": {"requests": {"cpu": "10m"}}}]
            }}}}}
        });
        let pt = extract_pod_template("CronJob", &data).unwrap();
        assert_eq!(pt.containers[0].name, "cron");
    }

    #[test]
    fn extract_pod_from_deploymentconfig_template() {
        let data = serde_json::json!({
            "spec": {"template": {"spec": {
                "containers": [{"name": "dc-app", "resources": {"requests": {"cpu": "200m"}}}]
            }}}
        });
        let pt = extract_pod_template("DeploymentConfig", &data).unwrap();
        assert_eq!(pt.containers[0].name, "dc-app");
    }

    #[test]
    fn extract_pod_returns_none_for_unsupported_kind() {
        let data = serde_json::json!({"spec": {"containers": [{"name": "x"}]}});
        assert!(extract_pod_template("Service", &data).is_none());
        assert!(extract_pod_template("ConfigMap", &data).is_none());
    }

    #[test]
    fn extract_pod_no_resources_field() {
        let data = serde_json::json!({
            "spec": {"containers": [{"name": "bare"}]}
        });
        let pt = extract_pod_template("Pod", &data).unwrap();
        assert_eq!(pt.containers[0].name, "bare");
        assert!(pt.containers[0].requests.is_none());
        assert!(pt.containers[0].limits.is_none());
    }

    #[test]
    fn extract_pod_empty_resources() {
        let data = serde_json::json!({
            "spec": {"containers": [{"name": "empty", "resources": {}}]}
        });
        let pt = extract_pod_template("Pod", &data).unwrap();
        assert!(pt.containers[0].requests.is_none());
        assert!(pt.containers[0].limits.is_none());
    }

    #[test]
    fn extract_pod_gpu_and_ephemeral_storage() {
        let data = serde_json::json!({
            "spec": {"containers": [{
                "name": "gpu-app",
                "resources": {
                    "requests": {"cpu": "500m", "memory": "4Gi", "nvidia.com/gpu": "1", "ephemeral-storage": "10Gi"},
                    "limits": {"cpu": "2", "memory": "8Gi", "nvidia.com/gpu": "1", "ephemeral-storage": "20Gi"}
                }
            }]}
        });
        let pt = extract_pod_template("Pod", &data).unwrap();
        let c = &pt.containers[0];
        assert_eq!(c.requests.as_ref().unwrap()["nvidia.com/gpu"], "1");
        assert_eq!(c.limits.as_ref().unwrap()["ephemeral-storage"], "20Gi");
    }

    #[test]
    fn extract_pod_btreemap_sorted_keys() {
        let data = serde_json::json!({
            "spec": {"containers": [{
                "name": "sorted",
                "resources": {"requests": {"memory": "1Gi", "cpu": "100m", "nvidia.com/gpu": "1"}}
            }]}
        });
        let pt = extract_pod_template("Pod", &data).unwrap();
        let keys: Vec<_> = pt.containers[0].requests.as_ref().unwrap().keys().collect();
        assert_eq!(keys, vec!["cpu", "memory", "nvidia.com/gpu"]);
    }

    #[test]
    fn extract_pod_init_containers_only() {
        let data = serde_json::json!({
            "spec": {"initContainers": [{"name": "init-only", "resources": {"requests": {"cpu": "10m"}}}]}
        });
        let pt = extract_pod_template("Pod", &data).unwrap();
        assert!(pt.containers.is_empty());
        assert_eq!(pt.init_containers.len(), 1);
    }

    // ── dedup_spec_refs tests ──

    #[test]
    fn dedup_preserves_different_field_paths() {
        let mut refs = vec![
            SpecRef {
                target_kind: "Secret".into(),
                target_name: "my-secret".into(),
                field_path: "spec.volumes.[0].secret.secretName".into(),
                source: SpecRefSource::Typed,
            },
            SpecRef {
                target_kind: "Secret".into(),
                target_name: "my-secret".into(),
                field_path: "spec.containers.[0].env.[0].valueFrom.secretKeyRef.name".into(),
                source: SpecRefSource::Typed,
            },
        ];
        dedup_spec_refs(&mut refs);
        assert_eq!(
            refs.len(),
            2,
            "different fieldPaths should both be preserved"
        );
    }

    #[test]
    fn dedup_removes_exact_duplicates() {
        let mut refs = vec![
            SpecRef {
                target_kind: "ConfigMap".into(),
                target_name: "my-cm".into(),
                field_path: "spec.volumes.[0].configMap.name".into(),
                source: SpecRefSource::Typed,
            },
            SpecRef {
                target_kind: "ConfigMap".into(),
                target_name: "my-cm".into(),
                field_path: "spec.volumes.[0].configMap.name".into(),
                source: SpecRefSource::Typed,
            },
        ];
        dedup_spec_refs(&mut refs);
        assert_eq!(refs.len(), 1, "exact duplicates should be deduped to 1");
    }

    #[test]
    fn dedup_sa_both_fields_keeps_service_account_name() {
        let mut refs = vec![
            SpecRef {
                target_kind: "ServiceAccount".into(),
                target_name: "my-sa".into(),
                field_path: "spec.template.spec.serviceAccount".into(),
                source: SpecRefSource::Typed,
            },
            SpecRef {
                target_kind: "ServiceAccount".into(),
                target_name: "my-sa".into(),
                field_path: "spec.template.spec.serviceAccountName".into(),
                source: SpecRefSource::Typed,
            },
        ];
        dedup_spec_refs(&mut refs);
        assert_eq!(
            refs.len(),
            1,
            "both fields present → keep serviceAccountName only"
        );
        assert!(
            refs[0].field_path.ends_with("serviceAccountName"),
            "should keep serviceAccountName, got: {}",
            refs[0].field_path
        );
    }

    #[test]
    fn dedup_sa_only_service_account_preserves_original() {
        let mut refs = vec![SpecRef {
            target_kind: "ServiceAccount".into(),
            target_name: "my-sa".into(),
            field_path: "spec.serviceAccount".into(),
            source: SpecRefSource::Typed,
        }];
        dedup_spec_refs(&mut refs);
        assert_eq!(refs.len(), 1);
        assert_eq!(
            refs[0].field_path, "spec.serviceAccount",
            "serviceAccount alone should preserve original field path"
        );
    }

    #[test]
    fn dedup_sa_different_parent_paths_independent() {
        let mut refs = vec![
            SpecRef {
                target_kind: "ServiceAccount".into(),
                target_name: "sa-a".into(),
                field_path: "spec.template.spec.serviceAccount".into(),
                source: SpecRefSource::Typed,
            },
            SpecRef {
                target_kind: "ServiceAccount".into(),
                target_name: "sa-a".into(),
                field_path: "spec.template.spec.serviceAccountName".into(),
                source: SpecRefSource::Typed,
            },
            SpecRef {
                target_kind: "ServiceAccount".into(),
                target_name: "sa-b".into(),
                field_path: "spec.serviceAccount".into(),
                source: SpecRefSource::Typed,
            },
        ];
        dedup_spec_refs(&mut refs);
        assert_eq!(
            refs.len(),
            2,
            "template pair deduped + standalone preserved"
        );
        assert!(
            refs.iter()
                .any(|r| r.field_path == "spec.template.spec.serviceAccountName")
        );
        assert!(refs.iter().any(|r| r.field_path == "spec.serviceAccount"));
    }

    #[test]
    fn dedup_sa_different_names_same_parent_both_kept() {
        let mut refs = vec![
            SpecRef {
                target_kind: "ServiceAccount".into(),
                target_name: "sa-a".into(),
                field_path: "spec.serviceAccount".into(),
                source: SpecRefSource::Typed,
            },
            SpecRef {
                target_kind: "ServiceAccount".into(),
                target_name: "sa-b".into(),
                field_path: "spec.serviceAccountName".into(),
                source: SpecRefSource::Typed,
            },
        ];
        dedup_spec_refs(&mut refs);
        assert_eq!(refs.len(), 2, "different target names → both kept");
        assert!(
            refs.iter()
                .any(|r| r.target_name == "sa-a" && r.field_path == "spec.serviceAccount")
        );
        assert!(
            refs.iter()
                .any(|r| r.target_name == "sa-b" && r.field_path == "spec.serviceAccountName")
        );
    }

    #[test]
    fn dedup_sa_different_source_same_parent_both_kept() {
        let mut refs = vec![
            SpecRef {
                target_kind: "ServiceAccount".into(),
                target_name: "my-sa".into(),
                field_path: "spec.serviceAccount".into(),
                source: SpecRefSource::Heuristic,
            },
            SpecRef {
                target_kind: "ServiceAccount".into(),
                target_name: "my-sa".into(),
                field_path: "spec.serviceAccountName".into(),
                source: SpecRefSource::Typed,
            },
        ];
        dedup_spec_refs(&mut refs);
        assert_eq!(refs.len(), 2, "different sources → both kept");
    }

    #[test]
    fn dedup_stable_sort_by_kind_name_path() {
        let mut refs = vec![
            SpecRef {
                target_kind: "Secret".into(),
                target_name: "b-secret".into(),
                field_path: "spec.volumes.[0]".into(),
                source: SpecRefSource::Typed,
            },
            SpecRef {
                target_kind: "ConfigMap".into(),
                target_name: "a-cm".into(),
                field_path: "spec.volumes.[1]".into(),
                source: SpecRefSource::Typed,
            },
            SpecRef {
                target_kind: "ConfigMap".into(),
                target_name: "a-cm".into(),
                field_path: "spec.env.[0]".into(),
                source: SpecRefSource::Typed,
            },
        ];
        dedup_spec_refs(&mut refs);
        assert_eq!(refs[0].target_kind, "ConfigMap");
        assert_eq!(refs[0].field_path, "spec.env.[0]");
        assert_eq!(refs[1].target_kind, "ConfigMap");
        assert_eq!(refs[1].field_path, "spec.volumes.[1]");
        assert_eq!(refs[2].target_kind, "Secret");
    }

    #[test]
    fn snapshot_v3_scope_roundtrip() {
        let snap = ClusterSnapshot {
            schema_version: Some(3),
            resources: HashMap::new(),
            scan_warnings: vec![],
            cluster_url: "https://api.test:6443".into(),
            taken_at: "2026-01-01T00:00:00Z".into(),
            namespaces: vec!["ns-a".into(), "ns-b".into()],
            scope: Some(SnapshotScope {
                mode: "filtered".into(),
                namespace_selectors: vec!["env=prod".into()],
                exclude_namespaces: vec!["temp-*".into()],
                exclude_system_namespaces: true,
                requested_namespaces: vec![],
                complete_namespaces: vec!["ns-a".into()],
                incomplete_namespaces: vec![IncompleteNamespace {
                    namespace: "ns-b".into(),
                    warnings: vec![ScanWarning::Forbidden {
                        gvr: "v1/secrets".into(),
                        status: 403,
                    }],
                    error: None,
                }],
            }),
        };
        let json = serde_json::to_string_pretty(&snap).unwrap();
        let snap2: ClusterSnapshot = serde_json::from_str(&json).unwrap();
        let scope = snap2.scope.unwrap();
        assert_eq!(scope.mode, "filtered");
        assert_eq!(scope.namespace_selectors, vec!["env=prod"]);
        assert_eq!(scope.exclude_namespaces, vec!["temp-*"]);
        assert!(scope.exclude_system_namespaces);
        assert_eq!(scope.complete_namespaces, vec!["ns-a"]);
        assert_eq!(scope.incomplete_namespaces.len(), 1);
        assert_eq!(scope.incomplete_namespaces[0].namespace, "ns-b");
    }

    #[test]
    fn v2_snapshot_deserializes_with_scope_none() {
        let json = serde_json::json!({
            "schema_version": 2,
            "resources": {},
            "scan_warnings": [],
            "cluster_url": "https://api.test:6443",
            "taken_at": "2026-01-01T00:00:00Z",
            "namespaces": ["default"]
        });
        let snap: ClusterSnapshot = serde_json::from_value(json).unwrap();
        assert!(snap.scope.is_none());
        assert_eq!(snap.schema_version, Some(2));
    }

    #[test]
    fn v1_snapshot_no_version_deserializes() {
        let json = serde_json::json!({
            "resources": {},
            "scan_warnings": [],
            "cluster_url": "https://api.test:6443",
            "taken_at": "2026-01-01T00:00:00Z",
            "namespaces": ["default"]
        });
        let snap: ClusterSnapshot = serde_json::from_value(json).unwrap();
        assert!(snap.schema_version.is_none());
        assert!(snap.scope.is_none());
    }

    #[test]
    fn coverage_ledger_sort_deterministic() {
        let mut ledger = CoverageLedger::new();
        ledger.record(QueryRecord {
            gvr: "zoo/v1/zebras".into(),
            namespace: Some("ns-b".into()),
            scope: "namespaced".into(),
            operation: QueryOperation::List,
            target_name: None,
            label_selector: None,
            field_selector: None,
            outcome: QueryOutcome::Success { count: 1, pages: 1 },
            elapsed_ms: 10,
            requirement: QueryRequirement::Required,
        });
        ledger.record(QueryRecord {
            gvr: "apps/v1/deployments".into(),
            namespace: Some("ns-a".into()),
            scope: "namespaced".into(),
            operation: QueryOperation::List,
            target_name: None,
            label_selector: None,
            field_selector: None,
            outcome: QueryOutcome::Success { count: 2, pages: 1 },
            elapsed_ms: 20,
            requirement: QueryRequirement::Required,
        });
        ledger.record(QueryRecord {
            gvr: "apps/v1/deployments".into(),
            namespace: None,
            scope: "cluster".into(),
            operation: QueryOperation::List,
            target_name: None,
            label_selector: None,
            field_selector: None,
            outcome: QueryOutcome::Success { count: 3, pages: 1 },
            elapsed_ms: 30,
            requirement: QueryRequirement::Required,
        });
        ledger.sort_records();
        assert_eq!(ledger.records[0].gvr, "apps/v1/deployments");
        assert_eq!(ledger.records[0].namespace, None);
        assert_eq!(ledger.records[1].gvr, "apps/v1/deployments");
        assert_eq!(ledger.records[1].namespace.as_deref(), Some("ns-a"));
        assert_eq!(ledger.records[2].gvr, "zoo/v1/zebras");

        let json1 = serde_json::to_string(&ledger).unwrap();
        ledger.sort_records();
        let json2 = serde_json::to_string(&ledger).unwrap();
        assert_eq!(json1, json2, "sort is idempotent");
    }

    #[test]
    fn strict_failure_excludes_optional_absent() {
        let mut ledger = CoverageLedger::new();
        ledger.record(QueryRecord {
            gvr: "v1/pods".into(),
            namespace: Some("default".into()),
            scope: "namespaced".into(),
            operation: QueryOperation::List,
            target_name: None,
            label_selector: None,
            field_selector: None,
            outcome: QueryOutcome::Success { count: 5, pages: 1 },
            elapsed_ms: 100,
            requirement: QueryRequirement::Required,
        });
        ledger.record(QueryRecord {
            gvr: "custom/v1/widgets".into(),
            namespace: None,
            scope: "cluster".into(),
            operation: QueryOperation::List,
            target_name: None,
            label_selector: None,
            field_selector: None,
            outcome: QueryOutcome::ApiAbsent,
            elapsed_ms: 5,
            requirement: QueryRequirement::Optional,
        });
        assert!(
            !ledger.has_incomplete(),
            "optional absent should not be a required failure"
        );
        assert_eq!(ledger.incomplete_count(), 0);
    }

    #[test]
    fn incomplete_counts_required_forbidden() {
        let mut ledger = CoverageLedger::new();
        ledger.record(QueryRecord {
            gvr: "v1/secrets".into(),
            namespace: Some("default".into()),
            scope: "namespaced".into(),
            operation: QueryOperation::List,
            target_name: None,
            label_selector: None,
            field_selector: None,
            outcome: QueryOutcome::Forbidden { status: 403 },
            elapsed_ms: 10,
            requirement: QueryRequirement::Required,
        });
        ledger.record(QueryRecord {
            gvr: "custom/v1/widgets".into(),
            namespace: None,
            scope: "cluster".into(),
            operation: QueryOperation::List,
            target_name: None,
            label_selector: None,
            field_selector: None,
            outcome: QueryOutcome::Forbidden { status: 403 },
            elapsed_ms: 10,
            requirement: QueryRequirement::Optional,
        });
        assert!(ledger.has_incomplete());
        assert_eq!(
            ledger.incomplete_count(),
            2,
            "both Required and Optional 403 are incomplete"
        );
    }

    #[test]
    fn coverage_ledger_json_includes_records() {
        let mut ledger = CoverageLedger::new();
        ledger.record(QueryRecord {
            gvr: "v1/pods".into(),
            namespace: Some("default".into()),
            scope: "namespaced".into(),
            operation: QueryOperation::List,
            target_name: None,
            label_selector: None,
            field_selector: None,
            outcome: QueryOutcome::Success { count: 3, pages: 1 },
            elapsed_ms: 50,
            requirement: QueryRequirement::Required,
        });
        let json = serde_json::to_value(&ledger).unwrap();
        let records = json["records"].as_array().unwrap();
        assert_eq!(records.len(), 1);
        assert_eq!(records[0]["gvr"], "v1/pods");
        assert_eq!(records[0]["namespace"], "default");
        assert_eq!(records[0]["scope"], "namespaced");
        assert_eq!(records[0]["outcome"]["outcome"], "Success");
        assert_eq!(records[0]["outcome"]["count"], 3);
        assert_eq!(records[0]["requirement"], "Required");
    }

    #[test]
    fn is_incomplete_truth_table() {
        let cases = vec![
            // (outcome, requirement, expected_incomplete)
            (
                QueryOutcome::Success { count: 1, pages: 1 },
                QueryRequirement::Required,
                false,
            ),
            (QueryOutcome::ApiAbsent, QueryRequirement::Required, true),
            (
                QueryOutcome::ListUnsupported,
                QueryRequirement::Required,
                true,
            ),
            (
                QueryOutcome::Forbidden { status: 403 },
                QueryRequirement::Required,
                true,
            ),
            (
                QueryOutcome::Timeout { retries: 2 },
                QueryRequirement::Required,
                true,
            ),
            (
                QueryOutcome::RateLimited { retries: 1 },
                QueryRequirement::Required,
                true,
            ),
            (
                QueryOutcome::ServerError {
                    status: 500,
                    retries: 2,
                },
                QueryRequirement::Required,
                true,
            ),
            (
                QueryOutcome::Unknown {
                    message: "err".into(),
                },
                QueryRequirement::Required,
                true,
            ),
            (
                QueryOutcome::Success { count: 0, pages: 1 },
                QueryRequirement::Optional,
                false,
            ),
            (QueryOutcome::ApiAbsent, QueryRequirement::Optional, false),
            (
                QueryOutcome::ListUnsupported,
                QueryRequirement::Optional,
                false,
            ),
            (
                QueryOutcome::Forbidden { status: 403 },
                QueryRequirement::Optional,
                true,
            ),
            (
                QueryOutcome::Timeout { retries: 2 },
                QueryRequirement::Optional,
                true,
            ),
            (
                QueryOutcome::RateLimited { retries: 1 },
                QueryRequirement::Optional,
                true,
            ),
            (
                QueryOutcome::ServerError {
                    status: 500,
                    retries: 2,
                },
                QueryRequirement::Optional,
                true,
            ),
            (
                QueryOutcome::Unknown {
                    message: "err".into(),
                },
                QueryRequirement::Optional,
                true,
            ),
            // TargetMissing: same as ApiAbsent — Required=incomplete, Optional=complete
            (
                QueryOutcome::TargetMissing,
                QueryRequirement::Required,
                true,
            ),
            (
                QueryOutcome::TargetMissing,
                QueryRequirement::Optional,
                false,
            ),
        ];
        for (i, (outcome, req, expected)) in cases.iter().enumerate() {
            assert_eq!(
                outcome.is_incomplete(req),
                *expected,
                "case {}: {:?} + {:?} should be incomplete={}",
                i,
                outcome,
                req,
                expected
            );
        }
    }

    #[test]
    fn test_snapshot_nonempty_ledger() {
        let mut ledger = CoverageLedger::new();
        ledger.record(QueryRecord {
            gvr: "apps/v1/deployments".to_string(),
            namespace: Some("default".to_string()),
            scope: "namespaced".to_string(),
            operation: QueryOperation::List,
            target_name: None,
            label_selector: None,
            field_selector: None,
            outcome: QueryOutcome::Success { count: 3, pages: 1 },
            elapsed_ms: 50,
            requirement: QueryRequirement::Required,
        });
        ledger.record(QueryRecord {
            gvr: "v1/pods".to_string(),
            namespace: Some("default".to_string()),
            scope: "namespaced".to_string(),
            operation: QueryOperation::Get,
            target_name: Some("test-pod".to_string()),
            label_selector: None,
            field_selector: None,
            outcome: QueryOutcome::Timeout { retries: 2 },
            elapsed_ms: 60000,
            requirement: QueryRequirement::Required,
        });

        let (coverage, incomplete, cloned_ledger) = ledger.snapshot();
        assert!(coverage.is_some());
        let summary = coverage.unwrap();
        assert_eq!(summary.total_queries, 2);
        assert_eq!(summary.success, 1);
        assert_eq!(summary.incomplete, 1);
        assert_eq!(incomplete, 1);
        assert!(cloned_ledger.is_some());
        let cl = cloned_ledger.unwrap();
        assert_eq!(cl.records.len(), 2);
        assert_eq!(cl.records[0].gvr, "apps/v1/deployments");
        assert_eq!(cl.records[1].gvr, "v1/pods");
    }

    #[test]
    fn test_snapshot_empty_ledger() {
        let mut ledger = CoverageLedger::new();
        let (coverage, incomplete, cloned_ledger) = ledger.snapshot();
        assert!(coverage.is_none());
        assert_eq!(incomplete, 0);
        assert!(cloned_ledger.is_none());
    }

    #[test]
    fn test_shared_ledger_snapshot_no_deadlock() {
        use std::sync::{Arc, Mutex};
        let shared: Arc<Mutex<CoverageLedger>> = Arc::new(Mutex::new(CoverageLedger::new()));
        shared.lock().unwrap().record(QueryRecord {
            gvr: "v1/services".to_string(),
            namespace: None,
            scope: "cluster".to_string(),
            operation: QueryOperation::List,
            target_name: None,
            label_selector: None,
            field_selector: None,
            outcome: QueryOutcome::Success { count: 5, pages: 1 },
            elapsed_ms: 100,
            requirement: QueryRequirement::Required,
        });
        let (cov, inc, ledger) = shared.lock().unwrap().snapshot();
        assert!(cov.is_some());
        assert_eq!(inc, 0);
        assert!(ledger.is_some());
        let json = serde_json::to_string(&ledger.unwrap()).unwrap();
        assert!(json.contains("v1/services"));
    }
}
