use std::collections::HashSet;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};
use tokio::sync::Mutex;

use crate::kube::resource::ResourceId;
use crate::teardown::plan::{
    ClusterIdentity, OperatorIdentitySnapshot, PlannedPreserved, ReviewMetadata,
};
use crate::teardown::planner::TeardownPlan;

// ──────────────────────────────────────────────────────────────
//  RunJournal — cluster-bound execution record
// ──────────────────────────────────────────────────────────────

pub const RUN_JOURNAL_SCHEMA_VERSION: u32 = 12;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RunJournal {
    pub run_id: String,
    pub schema_version: u32,
    pub oc_deps_version: String,
    pub journal_revision: u64,

    pub cluster_identity: ClusterIdentity,
    pub operator: OperatorIdentitySnapshot,

    pub created_at: String,
    pub updated_at: String,

    pub state: RunState,
    pub residual_status: ResidualStatus,
    pub audit_revision: u64,

    pub audit_context: AuditContext,
    /// Immutable snapshot of the plan as it was at mutation start.
    /// This is the discovery-derived TeardownPlan, not yet a true BoundTeardownPlan
    /// (UID-bound authority). BoundTeardownPlan will replace this in PR4/5.
    pub plan_snapshot: TeardownPlan,
    pub execution: ExecutionRecord,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_residual_audit: Option<crate::teardown::audit::ResidualAudit>,

    /// Durable record of manual residual cleanup decisions + results.
    #[serde(default)]
    pub cleanup_decisions: Vec<CleanupDecision>,

    /// Explicit opt-in for finalizer recovery on stalled EXPECT/DELETE descendants.
    /// Authority-critical: v9 required, no serde default.
    pub finalizer_recovery_approved: bool,

    /// Durable record of finalizer recovery actions.
    /// Authority-critical: v9 required, no serde default.
    pub finalizer_recoveries: Vec<FinalizerRecoveryRecord>,

    /// Pre-delete backup receipts (one per target operator).
    /// When non-empty, resume validates every receipt before allowing mutations.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub backup_receipts: Vec<crate::teardown::backup::BackupReceipt>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FinalizerRecoveryRecord {
    pub resource: ResourceId,
    pub live_uid: String,
    /// Exact finalizer set at approval time. Resume compares against live state.
    pub finalizer_values: Vec<String>,
    /// Owner references snapshot at approval time. Resume compares against live state.
    pub owner_references_snapshot: Vec<OwnerRefSnapshot>,
    pub root_uid: String,
    pub root_kind: String,
    pub result: FinalizerRecoveryResult,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct OwnerRefSnapshot {
    pub api_version: String,
    pub kind: String,
    pub name: String,
    pub uid: String,
    #[serde(default)]
    pub controller: Option<bool>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum FinalizerRecoveryResult {
    PatchRequested,
    Stripped,
    Gone,
    Failed(String),
}

/// A single residual cleanup decision with its outcome.
///
/// v5 journals stored this as a plain string ("deleted", "gone", etc.).
/// v6 uses a proper enum. The custom deserializer handles both formats.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub enum CleanupResult {
    DeleteRequested,
    Gone,
    AlreadyGone,
    Failed(String),
    /// Mutation outcome unknown (5xx/transport). Pending reconciliation on resume.
    /// is_pending=true, is_hard_failed=false — resume will fresh GET to resolve.
    UnknownOutcome(String),
}

impl<'de> serde::Deserialize<'de> for CleanupResult {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        use serde::de;

        struct CleanupResultVisitor;

        impl<'de> de::Visitor<'de> for CleanupResultVisitor {
            type Value = CleanupResult;

            fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                formatter.write_str("a CleanupResult enum variant or v5-compat string")
            }

            // v6 unit variants AND v5 plain strings
            fn visit_str<E: de::Error>(self, v: &str) -> std::result::Result<Self::Value, E> {
                match v {
                    // v6 unit variant names (serde externally tagged)
                    "DeleteRequested" => Ok(CleanupResult::DeleteRequested),
                    "Gone" => Ok(CleanupResult::Gone),
                    "AlreadyGone" => Ok(CleanupResult::AlreadyGone),
                    // v5 plain strings
                    "deleted" => Ok(CleanupResult::DeleteRequested),
                    "gone" => Ok(CleanupResult::Gone),
                    "already_gone" | "already gone" => Ok(CleanupResult::AlreadyGone),
                    s if s.starts_with("failed:") => Ok(CleanupResult::Failed(
                        s.trim_start_matches("failed:").trim().to_string(),
                    )),
                    other => Err(de::Error::unknown_variant(
                        other,
                        &[
                            "DeleteRequested",
                            "Gone",
                            "AlreadyGone",
                            "deleted",
                            "gone",
                            "already_gone",
                            "failed:*",
                        ],
                    )),
                }
            }

            // v6 format: tagged enum {"DeleteRequested": null} or {"Failed": "reason"}
            fn visit_map<A: de::MapAccess<'de>>(
                self,
                mut map: A,
            ) -> std::result::Result<Self::Value, A::Error> {
                let key: String = map
                    .next_key()?
                    .ok_or_else(|| de::Error::custom("expected enum variant key"))?;
                match key.as_str() {
                    "DeleteRequested" => {
                        let _: Option<()> = map.next_value()?;
                        Ok(CleanupResult::DeleteRequested)
                    }
                    "Gone" => {
                        let _: Option<()> = map.next_value()?;
                        Ok(CleanupResult::Gone)
                    }
                    "AlreadyGone" => {
                        let _: Option<()> = map.next_value()?;
                        Ok(CleanupResult::AlreadyGone)
                    }
                    "Failed" => {
                        let reason: String = map.next_value()?;
                        Ok(CleanupResult::Failed(reason))
                    }
                    "UnknownOutcome" => {
                        let reason: String = map.next_value()?;
                        Ok(CleanupResult::UnknownOutcome(reason))
                    }
                    other => Err(de::Error::unknown_variant(
                        other,
                        &[
                            "DeleteRequested",
                            "Gone",
                            "AlreadyGone",
                            "Failed",
                            "UnknownOutcome",
                        ],
                    )),
                }
            }
        }

        deserializer.deserialize_any(CleanupResultVisitor)
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CleanupDecision {
    pub resource: ResourceId,
    pub bound_uid: Option<String>,
    pub action: String,
    pub result: Option<CleanupResult>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub approved_spec_name: Option<String>,
}

impl CleanupDecision {
    /// Pending: needs resume action (not yet executed, DELETE sent but Gone not confirmed,
    /// or outcome unknown from previous run).
    pub fn is_pending(&self) -> bool {
        self.result.is_none()
            || matches!(
                self.result,
                Some(CleanupResult::DeleteRequested) | Some(CleanupResult::UnknownOutcome(_))
            )
    }

    /// Hard failure: DELETE definitively rejected (not retryable without new authority).
    /// UnknownOutcome is NOT hard failure — it needs reconciliation on resume.
    pub fn is_hard_failed(&self) -> bool {
        matches!(self.result, Some(CleanupResult::Failed(_)))
    }

    /// Failed or unconfirmed: includes hard failures, unconfirmed DELETEs, and unknown outcomes.
    #[allow(dead_code)]
    pub fn is_failed(&self) -> bool {
        matches!(
            self.result,
            Some(CleanupResult::DeleteRequested)
                | Some(CleanupResult::Failed(_))
                | Some(CleanupResult::UnknownOutcome(_))
        )
    }

    /// Terminal success: resource confirmed Gone
    #[allow(dead_code)]
    pub fn is_complete(&self) -> bool {
        matches!(
            self.result,
            Some(CleanupResult::Gone) | Some(CleanupResult::AlreadyGone)
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum RunState {
    Prepared,
    Applying,
    ApplyCompleted,
    AuditingResiduals,
    InteractiveCleanup,
    ExplicitCleanupBlocked,
    Paused,
    Finished,
    Failed,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum ResidualStatus {
    NotAudited,
    ResidualsObserved { count: usize },
    NoneObservedInScope,
    AuditIncomplete,
    SupersededByNewGeneration,
}

#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub struct AuditContext {
    #[serde(default)]
    pub footprint_namespaces: HashSet<String>,
    #[serde(default)]
    pub csv_names: HashSet<String>,
    #[serde(default)]
    pub controller_deployment_names: HashSet<String>,
    #[serde(default)]
    pub service_account_names: HashSet<String>,
    #[serde(default)]
    pub known_labels: Vec<(String, String)>,
    #[serde(default)]
    pub managed_field_managers: HashSet<String>,
    /// Discovery-derived GVR metadata for plan resources.
    /// None = GVR info not captured (old journal or discovery failure) → AuditIncomplete.
    /// Some(vec) = known GVRs for accurate probing.
    #[serde(default)]
    pub known_gvrs: Option<Vec<KnownGvr>>,
    /// CRD names that could not be resolved via API discovery at plan time.
    /// None = info not captured (old journal) → AuditIncomplete if owned_crds non-empty.
    /// Some([]) = all owned CRDs resolved successfully.
    /// Some([...]) = listed CRDs unresolved → AuditIncomplete.
    #[serde(default)]
    pub unresolved_crds: Option<Vec<String>>,
    /// Plan action GVKs that could not be resolved to a plural/scope via API discovery.
    /// None = info not captured (old journal) → AuditIncomplete.
    /// Some([]) = all plan GVKs resolved.
    /// Some([...]) = listed GVKs unresolved → AuditIncomplete.
    #[serde(default)]
    pub unresolved_gvks: Option<Vec<(String, String, String)>>,
    /// GVRs resolved from owned CRDs only (for Phase D LIST scan).
    /// Separate from known_gvrs to avoid scanning Namespace/CRD/APIService etc.
    #[serde(default)]
    pub owned_cr_gvrs: Option<Vec<KnownGvr>>,
    /// Pre-execution CSV inventory in install namespace (name → uid).
    /// Used by generation check to detect new CSVs not present at plan time.
    /// None = not captured (old journal) → generation check returns Unknown.
    #[serde(default)]
    pub csv_baseline: Option<Vec<CsvBaselineEntry>>,
    /// Namespace scope with provenance evidence from plan time.
    /// Always Some for v12+. Pre-v12 journals are rejected by load_journal,
    /// so a fresh teardown plan run is required after upgrade.
    #[serde(default)]
    pub namespace_scope: Option<Vec<NamespaceScopeEntry>>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CsvBaselineEntry {
    pub name: String,
    pub uid: String,
}

/// A namespace in the audit scope with provenance evidence explaining why it was included.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct NamespaceScopeEntry {
    pub namespace: String,
    pub evidence: Vec<NamespaceScopeEvidence>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub enum NamespaceScopeEvidence {
    InstallNamespace,
    OperatorGroupTarget,
    OperatorGroupStatus,
    PlanActionNamespace,
    OperatorGroupAllNamespaces,
    OwnedCrdInstance {
        crd: String,
    },
    SpecNamespaceRef {
        source_kind: String,
        source_name: String,
        field: String,
    },
    LabelEvidence {
        key: String,
        value: String,
    },
    ExplicitCleanupTarget,
}

/// A GVR resolved during plan generation via API discovery.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub struct KnownGvr {
    pub group: String,
    pub version: String,
    pub kind: String,
    pub plural: String,
    pub scope: GvrScope,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum GvrScope {
    Namespaced,
    Cluster,
}

#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub struct ExecutionRecord {
    pub phases_completed: usize,
    pub phases_total: usize,
    pub deleted: Vec<ResourceId>,
    pub already_gone: Vec<ResourceId>,
    pub failed: Vec<(ResourceId, String)>,
    pub kept: Vec<PreservedRecord>,
    pub reviewed: Vec<PreservedRecord>,
    /// Barrier/guard timeout that stopped execution. Persisted for resume diagnosis.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub barrier_timeout: Option<BarrierTimeoutRecord>,
    /// Durable re-delete authority for resources recreated after explicit DELETE.
    /// Authority-critical: v9+ required. No serde(default) — v8 journals
    /// cannot deserialize into RunJournal and are handled via raw JSON inspection.
    pub re_delete_records: Vec<ReDeleteRecord>,
    /// Typed error from transient explicit cleanup guard failure.
    /// Present only in ExplicitCleanupBlocked state. Cleared on resume.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub explicit_cleanup_error: Option<ExplicitCleanupError>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ExplicitCleanupError {
    pub target: String,
    pub error_kind: ExplicitCleanupErrorKind,
    pub message: String,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum ExplicitCleanupErrorKind {
    Timeout,
    ServerError,
    Transport,
    Forbidden,
    IncompleteScan,
    /// A v12 journal written by code predating `ExplicitCleanupBlocked` stopped
    /// at the explicit-cleanup boundary.  The resume path may set this only
    /// after the legacy journal passes the same structural authority checks as
    /// a newly typed blocked run.
    LegacyStateMigration,
}

/// Persist a terminal failure without destroying the executor's more precise
/// retryable state.  Every caller that handles an `execute_plan` error must use
/// this transition; otherwise a transient explicit-cleanup guard failure is
/// immediately overwritten with `Failed` and cannot be resumed.
pub fn mark_failed_preserving_retryable(journal: &mut RunJournal) {
    if journal.state != RunState::ExplicitCleanupBlocked {
        journal.state = RunState::Failed;
    }
}

/// Durable record of re-delete authority for a recreated resource.
///
/// Authority chain: explicit plan DELETE on `original_uid` was accepted and
/// authoritatively confirmed Gone → live GET found `new_uid` (different UID)
/// with no deletionTimestamp → Authorized persisted → UID-preconditioned DELETE
/// on `new_uid`.
///
/// `resource_identity` has NO uid field (stable identity: group/version/kind/ns/name).
/// UIDs are tracked separately to prevent confusion.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ReDeleteRecord {
    /// Stable identity (group, version, kind, namespace, name). uid=None.
    pub resource_identity: ResourceId,
    /// UID of the original explicit DELETE that was accepted + confirmed Gone.
    pub original_uid: String,
    /// UID observed on live GET after original was Gone (the recreated instance).
    pub new_uid: String,
    pub result: ReDeleteResult,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub enum ReDeleteResult {
    /// Authoritative GET confirmed new UID with no deletionTimestamp.
    /// Re-DELETE intent persisted, not yet attempted.
    Authorized,
    /// Re-DELETE accepted by API server (UID-preconditioned on new_uid).
    Accepted,
    /// Re-DELETE confirmed resource Gone.
    Gone,
    /// Re-DELETE failed (UID changed again, 403, etc.)
    Failed(String),
    /// Re-DELETE outcome unknown (5xx/transport). Resumable via fresh GET.
    UnknownOutcome(String),
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct BarrierTimeoutRecord {
    pub phase: String,
    pub remaining: Vec<ResourceId>,
    pub finalizer_details: Vec<(ResourceId, Vec<String>)>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PreservedRecord {
    pub resource: ResourceId,
    pub reason: String,
    pub metadata: Option<ReviewMetadata>,
}

impl From<&PlannedPreserved> for PreservedRecord {
    fn from(pp: &PlannedPreserved) -> Self {
        Self {
            resource: pp.resource.clone(),
            reason: pp.reason.clone(),
            metadata: pp.metadata.clone(),
        }
    }
}

// ──────────────────────────────────────────────────────────────
//  JournalStore — single-writer, revision-based CAS
// ──────────────────────────────────────────────────────────────

pub struct JournalStore {
    path: PathBuf,
    inner: Arc<Mutex<RunJournal>>,
    #[allow(dead_code)]
    lock_file: Option<std::fs::File>,
}

impl JournalStore {
    /// Create a JournalStore WITHOUT a process lock (for read-only or
    /// backward-compat use). Callers must ensure single-writer semantics.
    #[allow(dead_code)]
    pub fn new(journal: RunJournal, path: PathBuf) -> Self {
        Self {
            path,
            inner: Arc::new(Mutex::new(journal)),
            lock_file: None,
        }
    }

    /// Create a JournalStore WITH an exclusive process-level lock.
    /// Fails if another process holds the lock (active executor).
    /// The lock is held for the lifetime of this JournalStore.
    pub fn new_with_lock(_journal: RunJournal, path: PathBuf) -> Result<Self> {
        let lock_path = path.with_extension("lock");
        let lock_file = std::fs::OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(false)
            .open(&lock_path)
            .with_context(|| format!("Failed to open lock file: {}", lock_path.display()))?;

        #[cfg(unix)]
        {
            use std::os::unix::io::AsRawFd;
            let ret = unsafe { libc::flock(lock_file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) };
            if ret != 0 {
                bail!(
                    "Another process is already executing this run (lock: {}). \
                     Wait for it to complete or remove stale lock.",
                    lock_path.display()
                );
            }
        }

        // Re-load from disk AFTER acquiring lock to get the latest state.
        // Another process may have written between our initial read and lock acquisition.
        // Never fall back to the caller's stale copy — if the file is gone, bail.
        let latest = if path.exists() {
            load_journal(&path).with_context(|| {
                format!(
                    "Failed to re-load journal after lock acquisition: {}",
                    path.display()
                )
            })?
        } else {
            bail!(
                "Journal file {} no longer exists after lock acquisition. \
                 Cannot proceed without authoritative journal state.",
                path.display()
            );
        };

        Ok(Self {
            path,
            inner: Arc::new(Mutex::new(latest)),
            lock_file: Some(lock_file),
        })
    }

    /// Check whether a process lock is held on a journal path without acquiring it.
    #[allow(dead_code)]
    pub fn is_locked(journal_path: &Path) -> bool {
        let lock_path = journal_path.with_extension("lock");
        let lock_file = match std::fs::OpenOptions::new()
            .create(false)
            .read(true)
            .open(&lock_path)
        {
            Ok(f) => f,
            Err(_) => return false,
        };

        #[cfg(unix)]
        {
            use std::os::unix::io::AsRawFd;
            let ret = unsafe { libc::flock(lock_file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) };
            if ret != 0 {
                return true; // lock is held by another process
            }
            // We got the lock — release it immediately
            unsafe { libc::flock(lock_file.as_raw_fd(), libc::LOCK_UN) };
        }
        false
    }

    /// Update the journal via single-writer CAS.
    /// Uses in-process Mutex + optional process-level flock.
    pub async fn update<F>(&self, f: F) -> Result<()>
    where
        F: FnOnce(&mut RunJournal),
    {
        let mut journal = self.inner.lock().await;
        f(&mut journal);
        journal.journal_revision += 1;
        journal.updated_at = chrono_now();
        self.persist_locked(&journal)?;
        Ok(())
    }

    pub async fn read(&self) -> RunJournal {
        self.inner.lock().await.clone()
    }

    fn persist_locked(&self, journal: &RunJournal) -> Result<()> {
        atomic_write_json(&self.path, journal)
    }

    pub fn path(&self) -> &Path {
        &self.path
    }
}

// ──────────────────────────────────────────────────────────────
//  Persistence helpers
// ──────────────────────────────────────────────────────────────

fn state_dir() -> Result<PathBuf> {
    let base = dirs::state_dir()
        .or_else(dirs::data_local_dir)
        .unwrap_or_else(|| PathBuf::from("/tmp"));
    Ok(base.join("oc-deps"))
}

pub fn runs_dir(cluster_id: &ClusterIdentity) -> Result<PathBuf> {
    let dir = state_dir()?
        .join("clusters")
        .join(&cluster_id.kube_system_uid)
        .join("runs");
    fs::create_dir_all(&dir)
        .with_context(|| format!("Failed to create runs directory: {}", dir.display()))?;
    set_dir_permissions(&dir);
    Ok(dir)
}

pub fn run_path(cluster_id: &ClusterIdentity, run_id: &str) -> Result<PathBuf> {
    Ok(runs_dir(cluster_id)?.join(format!("{}.json", run_id)))
}

pub fn list_runs(cluster_id: &ClusterIdentity) -> Result<Vec<RunJournal>> {
    let dir = runs_dir(cluster_id)?;
    let mut runs = Vec::new();
    if dir.exists() {
        for entry in fs::read_dir(&dir)? {
            let entry = entry?;
            let path = entry.path();
            if path.extension().is_some_and(|e| e == "json") {
                match load_journal(&path) {
                    Ok(j) => runs.push(j),
                    Err(e) => {
                        eprintln!("  ⚠ Skipping {}: {}", path.display(), e);
                    }
                }
            }
        }
    }
    runs.sort_by(|a, b| b.created_at.cmp(&a.created_at));
    Ok(runs)
}

pub fn load_journal(path: &Path) -> Result<RunJournal> {
    let data = fs::read_to_string(path)
        .with_context(|| format!("Failed to read journal: {}", path.display()))?;

    // Pre-check schema version from raw JSON before deserializing.
    // v8 and below lack re_delete_records and cannot deserialize into RunJournal.
    let raw: serde_json::Value = serde_json::from_str(&data)
        .with_context(|| format!("Failed to parse journal JSON: {}", path.display()))?;
    let raw_version = raw
        .get("schema_version")
        .and_then(|v| v.as_u64())
        .unwrap_or(0) as u32;

    if raw_version != RUN_JOURNAL_SCHEMA_VERSION {
        bail!(
            "Unsupported journal schema version {} (expected {}). \
             Remove old local run state and create a fresh teardown plan.",
            raw_version,
            RUN_JOURNAL_SCHEMA_VERSION
        );
    }

    let journal: RunJournal = serde_json::from_str(&data)
        .with_context(|| format!("Failed to parse journal: {}", path.display()))?;

    Ok(journal)
}

pub fn find_latest_run(
    cluster_id: &ClusterIdentity,
    operator_csv_name: &str,
) -> Result<Option<RunJournal>> {
    let runs = list_runs(cluster_id)?;
    Ok(runs.into_iter().find(|r| {
        r.cluster_identity.matches(cluster_id) && r.operator.csv_name == operator_csv_name
    }))
}

pub fn atomic_write_json_pub<T: Serialize>(path: &Path, value: &T) -> Result<()> {
    atomic_write_json(path, value)
}

/// Atomic write: temp file → fsync → rename → fsync parent dir.
///
/// SAFETY: This function does NOT provide cross-process locking.
/// Callers must ensure single-writer semantics externally (e.g., via
/// JournalStore's in-process Mutex for the executor process).
/// Cross-process exclusive writes will be added in PR3.
fn atomic_write_json<T: Serialize>(path: &Path, value: &T) -> Result<()> {
    let parent = path
        .parent()
        .ok_or_else(|| anyhow::anyhow!("No parent directory for {}", path.display()))?;

    let tmp_path = parent.join(format!(".tmp_{}", uuid_v4_short()));
    let data = serde_json::to_string_pretty(value)?;

    {
        let mut f = fs::File::create(&tmp_path)
            .with_context(|| format!("Failed to create temp file: {}", tmp_path.display()))?;
        f.write_all(data.as_bytes())?;
        f.sync_all()?;
    }

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = fs::set_permissions(&tmp_path, fs::Permissions::from_mode(0o600));
    }

    fs::rename(&tmp_path, path).with_context(|| {
        format!(
            "Failed to rename {} -> {}",
            tmp_path.display(),
            path.display()
        )
    })?;

    // fsync parent directory for crash consistency
    if let Ok(dir) = fs::File::open(parent) {
        let _ = dir.sync_all();
    }

    Ok(())
}

fn set_dir_permissions(path: &Path) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = fs::set_permissions(path, fs::Permissions::from_mode(0o700));
    }
}

fn uuid_v4_short() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let ts = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    let pid = std::process::id();
    format!("{:x}_{:x}", ts, pid)
}

fn chrono_now() -> String {
    chrono_now_iso()
}

pub fn chrono_now_iso() -> String {
    chrono::Utc::now().to_rfc3339()
}

// ──────────────────────────────────────────────────────────────
//  Build helpers
// ──────────────────────────────────────────────────────────────

pub fn generate_run_id() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let ts = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    let pid = std::process::id();
    format!("run-{:x}-{:x}", ts, pid)
}

pub async fn fetch_cluster_identity(client: &kube::Client) -> Result<ClusterIdentity> {
    use k8s_openapi::api::core::v1::Namespace;
    use kube::api::Api;

    let ns_api: Api<Namespace> = Api::all(client.clone());
    let kube_system = ns_api
        .get("kube-system")
        .await
        .context("Failed to get kube-system namespace for cluster identity")?;

    let uid = kube_system
        .metadata
        .uid
        .ok_or_else(|| anyhow::anyhow!("kube-system namespace has no UID"))?;

    let api_server = match kube::Config::infer().await {
        Ok(config) => config.cluster_url.to_string(),
        Err(_) => "unknown".to_string(),
    };

    Ok(ClusterIdentity {
        api_server,
        kube_system_uid: uid,
    })
}

pub fn build_audit_context(
    plan: &TeardownPlan,
    operators: &[&crate::analyzers::olm::OperatorInstance],
    gk_map: &crate::kube::discovery::GroupKindMap,
    candidate_namespaces: Option<Vec<crate::analyzers::namespace_scope::CandidateNamespace>>,
) -> AuditContext {
    let mut ctx = AuditContext::default();

    for op in operators {
        ctx.csv_names.insert(op.csv.name.clone());
        ctx.footprint_namespaces
            .insert(op.install_namespace.clone());
        for dep in &op.deployments {
            ctx.controller_deployment_names.insert(dep.clone());
        }
        for sa in &op.service_accounts {
            ctx.service_account_names.insert(sa.clone());
        }
    }

    // Resolve GVR info from plan actions using GroupKindMap (group, kind) → KindInfo.
    // Unresolved GVKs are tracked — their presence means audit is incomplete.
    let mut seen_gvks: HashSet<(String, String)> = HashSet::new();
    let mut known_gvrs = Vec::new();
    let mut unresolved_gvks: Vec<(String, String, String)> = Vec::new();

    for phase in &plan.phases {
        for action in &phase.actions {
            let rid = match action {
                crate::teardown::planner::Action::Delete { resource, .. }
                | crate::teardown::planner::Action::ExpectGone { resource, .. }
                | crate::teardown::planner::Action::WaitGone { resource }
                | crate::teardown::planner::Action::Keep { resource, .. }
                | crate::teardown::planner::Action::Review { resource, .. } => resource,
            };
            if let Some(ns) = &rid.namespace {
                ctx.footprint_namespaces.insert(ns.clone());
            }

            let gk_key = (rid.group.clone(), rid.kind.clone());
            if seen_gvks.insert(gk_key.clone()) {
                if let Some(info) = gk_map.get(&gk_key) {
                    known_gvrs.push(KnownGvr {
                        group: info.group.clone(),
                        version: info.version.clone(),
                        kind: rid.kind.clone(),
                        plural: info.plural.clone(),
                        scope: if info.namespaced {
                            GvrScope::Namespaced
                        } else {
                            GvrScope::Cluster
                        },
                    });
                } else {
                    unresolved_gvks.push((
                        rid.group.clone(),
                        rid.version.clone(),
                        rid.kind.clone(),
                    ));
                }
            }
        }
    }

    // Also resolve owned CRDs — residual CR instances may exist outside the plan.
    // These go into owned_cr_gvrs (separate from known_gvrs) so Phase D only scans
    // owned CR APIs, not Namespace/CRD/APIService etc. from plan KEEP actions.
    // CRD name format: "pluralname.group" (e.g. "widgets.example.io")
    let mut unresolved_crds: Vec<String> = Vec::new();
    let mut owned_cr_gvrs: Vec<KnownGvr> = Vec::new();
    for op in operators {
        for crd_name in &op.owned_crds {
            let parts: Vec<&str> = crd_name.splitn(2, '.').collect();
            if parts.len() < 2 {
                unresolved_crds.push(crd_name.clone());
                continue;
            }
            let plural = parts[0];
            let group = parts[1];
            let mut found = false;
            for ((g, k), info) in gk_map.iter() {
                if g == group && info.plural == plural {
                    // Add to known_gvrs for exact-GET probe resolution
                    let gk_key = (g.clone(), k.clone());
                    if seen_gvks.insert(gk_key) {
                        known_gvrs.push(KnownGvr {
                            group: info.group.clone(),
                            version: info.version.clone(),
                            kind: k.clone(),
                            plural: info.plural.clone(),
                            scope: if info.namespaced {
                                GvrScope::Namespaced
                            } else {
                                GvrScope::Cluster
                            },
                        });
                    }
                    // Also add to owned_cr_gvrs for Phase D LIST
                    owned_cr_gvrs.push(KnownGvr {
                        group: info.group.clone(),
                        version: info.version.clone(),
                        kind: k.clone(),
                        plural: info.plural.clone(),
                        scope: if info.namespaced {
                            GvrScope::Namespaced
                        } else {
                            GvrScope::Cluster
                        },
                    });
                    found = true;
                    break;
                }
            }
            if !found {
                unresolved_crds.push(crd_name.clone());
            }
        }
    }

    if !unresolved_gvks.is_empty() || !unresolved_crds.is_empty() {
        let total = unresolved_gvks.len() + unresolved_crds.len();
        eprintln!(
            "  ⚠ {} GVK(s)/CRD(s) could not be resolved via API discovery \
             (audit will be incomplete for probes of these types)",
            total
        );
    }

    ctx.known_gvrs = Some(known_gvrs);
    ctx.unresolved_crds = Some(unresolved_crds);
    ctx.unresolved_gvks = Some(unresolved_gvks);
    ctx.owned_cr_gvrs = Some(owned_cr_gvrs);
    // csv_baseline is captured separately in create_run_journal (requires async client)

    // Build namespace_scope from footprint_namespaces with provenance evidence.
    // Install namespace and plan action namespaces are always included.
    // External CandidateNamespace data (OperatorGroup, spec refs) is merged via
    // enrich_namespace_scope_from_candidates after build.
    let mut ns_entries: std::collections::HashMap<String, Vec<NamespaceScopeEvidence>> =
        std::collections::HashMap::new();
    for op in operators {
        ns_entries
            .entry(op.install_namespace.clone())
            .or_default()
            .push(NamespaceScopeEvidence::InstallNamespace);
    }
    for phase in &plan.phases {
        for action in &phase.actions {
            let rid = match action {
                crate::teardown::planner::Action::Delete { resource, .. }
                | crate::teardown::planner::Action::ExpectGone { resource, .. }
                | crate::teardown::planner::Action::WaitGone { resource }
                | crate::teardown::planner::Action::Keep { resource, .. }
                | crate::teardown::planner::Action::Review { resource, .. } => resource,
            };
            if let Some(ns) = &rid.namespace {
                let entry = ns_entries.entry(ns.clone()).or_default();
                if !entry.contains(&NamespaceScopeEvidence::PlanActionNamespace) {
                    entry.push(NamespaceScopeEvidence::PlanActionNamespace);
                }
            }
        }
    }
    for ed in &plan.explicit_deletes {
        if let Some(ns) = &ed.namespace {
            let entry = ns_entries.entry(ns.clone()).or_default();
            if !entry.contains(&NamespaceScopeEvidence::ExplicitCleanupTarget) {
                entry.push(NamespaceScopeEvidence::ExplicitCleanupTarget);
            }
        }
    }
    let mut scope_entries: Vec<NamespaceScopeEntry> = ns_entries
        .into_iter()
        .map(|(namespace, mut evidence)| {
            evidence.sort();
            NamespaceScopeEntry {
                namespace,
                evidence,
            }
        })
        .collect();
    scope_entries.sort_by(|a, b| a.namespace.cmp(&b.namespace));
    ctx.namespace_scope = Some(scope_entries);

    if let Some(candidates) = candidate_namespaces {
        enrich_namespace_scope_from_candidates(&mut ctx, &candidates);
    }

    ctx
}

/// Enrich namespace_scope with evidence from CandidateNamespace discovery results.
/// Call after build_audit_context when namespace scope discovery data is available.
pub fn enrich_namespace_scope_from_candidates(
    ctx: &mut AuditContext,
    candidates: &[crate::analyzers::namespace_scope::CandidateNamespace],
) {
    let scope = ctx.namespace_scope.get_or_insert_with(Vec::new);
    for candidate in candidates {
        let entry = if let Some(existing) = scope
            .iter_mut()
            .find(|e| e.namespace == candidate.namespace)
        {
            existing
        } else {
            scope.push(NamespaceScopeEntry {
                namespace: candidate.namespace.clone(),
                evidence: Vec::new(),
            });
            scope.last_mut().unwrap()
        };
        for ev in &candidate.evidence {
            let converted = match ev {
                crate::analyzers::namespace_scope::NamespaceEvidence::InstallNamespace => {
                    NamespaceScopeEvidence::InstallNamespace
                }
                crate::analyzers::namespace_scope::NamespaceEvidence::OperatorGroupTarget => {
                    NamespaceScopeEvidence::OperatorGroupTarget
                }
                crate::analyzers::namespace_scope::NamespaceEvidence::OperatorGroupStatus => {
                    NamespaceScopeEvidence::OperatorGroupStatus
                }
                crate::analyzers::namespace_scope::NamespaceEvidence::OwnedCrdInstance { crd } => {
                    NamespaceScopeEvidence::OwnedCrdInstance { crd: crd.clone() }
                }
                crate::analyzers::namespace_scope::NamespaceEvidence::SpecNamespaceRef {
                    source_kind,
                    source_name,
                    field,
                    ..
                } => NamespaceScopeEvidence::SpecNamespaceRef {
                    source_kind: source_kind.clone(),
                    source_name: source_name.clone(),
                    field: field.clone(),
                },
                crate::analyzers::namespace_scope::NamespaceEvidence::LabelEvidence {
                    key,
                    value,
                } => NamespaceScopeEvidence::LabelEvidence {
                    key: key.clone(),
                    value: value.clone(),
                },
                crate::analyzers::namespace_scope::NamespaceEvidence::PlanActionNamespace => {
                    NamespaceScopeEvidence::PlanActionNamespace
                }
                crate::analyzers::namespace_scope::NamespaceEvidence::OperatorGroupAllNamespaces => {
                    NamespaceScopeEvidence::OperatorGroupAllNamespaces
                }
                crate::analyzers::namespace_scope::NamespaceEvidence::ExplicitCleanupTarget => {
                    NamespaceScopeEvidence::ExplicitCleanupTarget
                }
            };
            if !entry.evidence.contains(&converted) {
                entry.evidence.push(converted);
            }
        }
        entry.evidence.sort();
        // Also add to footprint_namespaces so audit scan covers this namespace
        ctx.footprint_namespaces.insert(candidate.namespace.clone());
    }
    scope.sort_by(|a, b| a.namespace.cmp(&b.namespace));
}

// ── Functions moved from commands/teardown.rs (P0-1 dependency direction fix) ──

/// Discover namespace scope for a single target operator.
/// Must run before journal creation so the journal captures provenance.
/// Fails closed: discovery scan failures abort the teardown.
pub async fn discover_audit_scope(
    client: &::kube::Client,
    target_operator: &crate::analyzers::olm::OperatorInstance,
    kind_map: &crate::kube::discovery::KindMap,
    gvr_map: &crate::kube::discovery::GvrMap,
    gk_map: &crate::kube::discovery::GroupKindMap,
) -> Result<Vec<crate::analyzers::namespace_scope::CandidateNamespace>> {
    use crate::analyzers::namespace_scope::{CandidateNamespace, NamespaceEvidence};
    use crate::kube::planner::QueryPlanner;
    use crate::kube::scanner::DEFAULT_API_CONCURRENCY;

    let scope_planner = QueryPlanner::new(Some(std::sync::Arc::new(tokio::sync::Semaphore::new(
        DEFAULT_API_CONCURRENCY,
    ))));

    let scope_result = crate::analyzers::namespace_scope::discover_operator_namespaces_opts(
        client,
        target_operator,
        kind_map,
        gvr_map,
        gk_map,
        None,
        None,
        Some(scope_planner.clone()),
    )
    .await
    .context("Namespace scope discovery failed for audit context")?;
    if !scope_result.scan_failures.is_empty() {
        let msgs: Vec<String> = scope_result
            .scan_failures
            .iter()
            .map(|w| format!("{:?}", w))
            .collect();
        bail!(
            "Namespace scope discovery had {} scan failure(s) — audit scope incomplete, aborting: {}",
            msgs.len(),
            msgs.join("; ")
        );
    }
    let mut candidates = scope_result.candidates;
    if scope_result.is_all_namespaces {
        let ns_items = scope_planner
            .list_all(
                client,
                "",
                "v1",
                "namespaces",
                None,
                crate::kube::resource::QueryRequirement::Required,
            )
            .await
            .map_err(|w| anyhow::anyhow!("Failed to LIST Namespaces: {:?}", w))?;
        // Validate every Namespace identity — fail closed on missing/invalid
        for obj in ns_items.iter() {
            let raw = obj.metadata.name.as_deref().ok_or_else(|| {
                anyhow::anyhow!(
                    "AllNamespaces LIST returned Namespace without metadata.name — fail closed"
                )
            })?;
            if raw.is_empty() || !crate::analyzers::namespace_scope::is_valid_k8s_namespace(raw) {
                bail!(
                    "AllNamespaces LIST returned invalid namespace name {:?} — fail closed",
                    raw
                );
            }
            let ns_name = raw.to_string();

            if let Some(existing) = candidates.iter_mut().find(|c| c.namespace == ns_name) {
                if !existing
                    .evidence
                    .iter()
                    .any(|e| matches!(e, NamespaceEvidence::OperatorGroupAllNamespaces))
                {
                    existing
                        .evidence
                        .push(NamespaceEvidence::OperatorGroupAllNamespaces);
                }
            } else {
                candidates.push(CandidateNamespace {
                    namespace: ns_name,
                    evidence: vec![NamespaceEvidence::OperatorGroupAllNamespaces],
                });
            }
        }
    }
    Ok(candidates)
}

pub async fn create_run_journal(
    client: &::kube::Client,
    plan: &crate::teardown::planner::TeardownPlan,
    target_operators: &[&crate::analyzers::olm::OperatorInstance],
    gk_map: &crate::kube::discovery::GroupKindMap,
    _finalizer_recovery_approved: bool,
    backup_receipts: Vec<crate::teardown::backup::BackupReceipt>,
    candidate_namespaces: Option<Vec<crate::analyzers::namespace_scope::CandidateNamespace>>,
) -> Result<JournalStore> {
    if target_operators.len() > 1 {
        bail!(
            "Run journal currently supports single-operator teardown. \
             Use separate teardown commands for each operator."
        );
    }

    let cluster_id = fetch_cluster_identity(client).await?;
    let run_id = generate_run_id();

    let operator_snapshot = build_operator_identity_snapshot(client, target_operators)
        .await
        .context("Failed to build operator identity snapshot for journal")?;

    let first_op = target_operators[0];
    let mut audit_context =
        build_audit_context(plan, target_operators, gk_map, candidate_namespaces);

    // Capture CSV baseline: all CSVs in install namespace at plan time (name → uid).
    // Used by generation check to detect new CSVs not present before teardown.
    {
        use ::kube::api::{Api, ApiResource, DynamicObject, ListParams};
        use ::kube::core::GroupVersion;

        let csv_gvk =
            GroupVersion::gv("operators.coreos.com", "v1alpha1").with_kind("ClusterServiceVersion");
        let csv_ar = ApiResource::from_gvk_with_plural(&csv_gvk, "clusterserviceversions");
        let csv_api: Api<DynamicObject> =
            Api::namespaced_with(client.clone(), &first_op.install_namespace, &csv_ar);

        audit_context.csv_baseline = match csv_api.list(&ListParams::default()).await {
            Ok(list) => {
                let mut baseline_entries = Vec::new();
                for csv in &list.items {
                    let name = csv.metadata.name.clone().ok_or_else(|| {
                        anyhow::anyhow!(
                            "CSV in install namespace has no name — cannot build baseline"
                        )
                    })?;
                    let uid = csv.metadata.uid.clone().ok_or_else(|| {
                        anyhow::anyhow!("CSV '{}' has no UID — cannot build baseline", name)
                    })?;
                    baseline_entries.push(CsvBaselineEntry { name, uid });
                }
                Some(baseline_entries)
            }
            Err(e) => {
                bail!(
                    "Failed to capture CSV baseline for generation safety: {}. \
                     Cannot proceed without baseline.",
                    e
                );
            }
        };
    }

    let journal = RunJournal {
        run_id: run_id.clone(),
        schema_version: RUN_JOURNAL_SCHEMA_VERSION,
        oc_deps_version: env!("CARGO_PKG_VERSION").to_string(),
        journal_revision: 0,
        cluster_identity: cluster_id.clone(),
        operator: operator_snapshot,
        created_at: chrono_now_iso(),
        updated_at: chrono_now_iso(),
        state: RunState::Prepared,
        residual_status: ResidualStatus::NotAudited,
        audit_revision: 0,
        audit_context,
        plan_snapshot: plan.clone(),
        execution: ExecutionRecord {
            phases_total: plan.phases.len(),
            ..Default::default()
        },
        last_residual_audit: None,
        cleanup_decisions: Vec::new(),
        finalizer_recovery_approved: true,
        finalizer_recoveries: Vec::new(),
        backup_receipts,
    };

    let path = run_path(&cluster_id, &run_id)?;
    atomic_write_json_pub(&path, &journal)?;

    JournalStore::new_with_lock(journal, path)
}

/// Build a fresh OperatorIdentitySnapshot with live UIDs from the cluster.
/// Used for basis drift validation before journal creation.
pub async fn build_operator_identity_snapshot(
    client: &::kube::Client,
    target_operators: &[&crate::analyzers::olm::OperatorInstance],
) -> Result<crate::teardown::plan::OperatorIdentitySnapshot> {
    use crate::teardown::plan::{
        ObservedResourceIdentity, OperatorGenerationIdentity, OperatorIdentitySnapshot,
    };

    let first_op = target_operators[0];
    let op_id = crate::analyzers::olm::OperatorId {
        namespace: first_op.install_namespace.clone(),
        csv_name: first_op.csv.name.clone(),
    };

    // Fail-closed: Subscription exists but package name unknown/empty
    if first_op.subscription.is_some() {
        match &first_op.package_name {
            None => {
                bail!(
                    "Subscription exists but package name is unknown — \
                     cannot establish semantic identity for safe teardown."
                );
            }
            Some(pkg) if pkg.trim().is_empty() => {
                bail!(
                    "Subscription exists but package name is empty — \
                     cannot establish semantic identity for safe teardown."
                );
            }
            _ => {}
        }
    }

    let generation_identity = match &first_op.package_name {
        Some(name) if !name.trim().is_empty() => OperatorGenerationIdentity::OlmPackage {
            package_name: name.clone(),
            install_namespace: first_op.install_namespace.clone(),
        },
        _ => OperatorGenerationIdentity::Unverifiable {
            reason: "No subscription or empty package name".to_string(),
        },
    };

    let csv_observed = {
        let fresh = fetch_observed_identities(
            client,
            std::slice::from_ref(&first_op.csv.name),
            "ClusterServiceVersion",
            "operators.coreos.com/v1alpha1",
            &first_op.install_namespace,
        )
        .await?;
        let obs = fresh
            .into_iter()
            .next()
            .context("CSV not found during identity snapshot")?;
        // Verify discovery UID is present and matches fresh UID
        let discovery_uid = first_op.csv.uid.as_deref().unwrap_or("");
        if discovery_uid.is_empty() {
            bail!(
                "CSV {} has no UID from discovery — cannot verify identity for safe teardown",
                first_op.csv.name
            );
        }
        if obs.uid != discovery_uid {
            bail!(
                "CSV {} UID changed between discovery ({}) and snapshot ({}) — \
                 operator may have been recreated. Re-run 'teardown plan'.",
                first_op.csv.name,
                discovery_uid,
                obs.uid
            );
        }
        obs
    };

    let controller_deployments = fetch_observed_identities(
        client,
        &first_op.deployments,
        "Deployment",
        "apps/v1",
        &first_op.install_namespace,
    )
    .await?;

    let service_accounts = fetch_observed_identities(
        client,
        &first_op.service_accounts,
        "ServiceAccount",
        "v1",
        &first_op.install_namespace,
    )
    .await?;

    let sub_observed: Vec<ObservedResourceIdentity> = if let Some(sub) = &first_op.subscription {
        let fresh = fetch_observed_identities(
            client,
            std::slice::from_ref(&sub.name),
            "Subscription",
            "operators.coreos.com/v1alpha1",
            sub.namespace
                .as_deref()
                .unwrap_or(&first_op.install_namespace),
        )
        .await?;
        if fresh.is_empty() {
            bail!(
                "Subscription {} was observed during discovery but is now absent — \
                 cannot establish reliable generation identity",
                sub.name
            );
        }
        // Verify discovery UID is present and matches fresh UID
        let discovery_uid = sub.uid.as_deref().unwrap_or("");
        if discovery_uid.is_empty() {
            bail!(
                "Subscription {} has no UID from discovery — cannot verify identity",
                sub.name
            );
        }
        if let Some(obs) = fresh.first()
            && obs.uid != discovery_uid
        {
            bail!(
                "Subscription {} UID changed between discovery ({}) and snapshot ({}) — \
                     operator may have been recreated. Re-run 'teardown plan'.",
                sub.name,
                discovery_uid,
                obs.uid
            );
        }
        // Verify spec.name matches expected package
        if let Some(ref expected_package) = first_op.package_name {
            let sub_gvk = ::kube::core::GroupVersion::gv("operators.coreos.com", "v1alpha1")
                .with_kind("Subscription");
            let sub_ar = ::kube::api::ApiResource::from_gvk_with_plural(&sub_gvk, "subscriptions");
            let sub_api: ::kube::api::Api<::kube::api::DynamicObject> =
                ::kube::api::Api::namespaced_with(
                    client.clone(),
                    sub.namespace
                        .as_deref()
                        .unwrap_or(&first_op.install_namespace),
                    &sub_ar,
                );
            match sub_api.get(&sub.name).await {
                Ok(live_sub) => {
                    let live_spec_name = live_sub
                        .data
                        .get("spec")
                        .and_then(|s| s.get("name"))
                        .and_then(|n| n.as_str())
                        .unwrap_or("");
                    if live_spec_name != expected_package.as_str() {
                        bail!(
                            "Subscription {} spec.name changed from '{}' to '{}' — \
                             semantic identity drift. Re-run 'teardown plan'.",
                            sub.name,
                            expected_package,
                            live_spec_name
                        );
                    }
                }
                Err(::kube::Error::Api(ref api_err)) if api_err.code == 404 => {
                    // Subscription already deleted (previous teardown or manual).
                    // This is safe — operator is frozen.
                }
                Err(e) => {
                    bail!("Cannot verify Subscription {} spec.name: {}", sub.name, e);
                }
            }
        }
        fresh
    } else {
        Vec::new()
    };

    Ok(OperatorIdentitySnapshot {
        generation_identity,
        operator_id: op_id,
        csv_name: first_op.csv.name.clone(),
        csv: csv_observed,
        subscriptions: sub_observed,
        controller_deployments,
        service_accounts,
        owned_crds: first_op.owned_crds.clone(),
        required_crds: first_op.required_crds.clone(),
    })
}

/// Fetch observed identities with UIDs for pre-execution snapshot.
/// 404 = resource absent (OK, skip). Any other error = fail-closed (abort journal creation).
pub async fn fetch_observed_identities(
    client: &::kube::Client,
    names: &[String],
    kind: &str,
    api_version: &str,
    namespace: &str,
) -> Result<Vec<crate::teardown::plan::ObservedResourceIdentity>> {
    use crate::teardown::plan::ObservedResourceIdentity;
    use ::kube::api::{Api, ApiResource, DynamicObject};
    use ::kube::core::GroupVersion;

    let (group, version) = if api_version.contains('/') {
        let parts: Vec<&str> = api_version.splitn(2, '/').collect();
        (parts[0].to_string(), parts[1].to_string())
    } else {
        (String::new(), api_version.to_string())
    };

    let gvk = GroupVersion::gv(&group, &version).with_kind(kind);
    let plural = format!("{}s", kind.to_lowercase());
    let ar = ApiResource::from_gvk_with_plural(&gvk, &plural);
    let api: Api<DynamicObject> = Api::namespaced_with(client.clone(), namespace, &ar);

    let mut results = Vec::new();
    for name in names {
        match api.get(name).await {
            Ok(obj) => {
                let rid = crate::kube::resource::ResourceId {
                    group: group.clone(),
                    version: version.clone(),
                    kind: kind.to_string(),
                    namespace: Some(namespace.to_string()),
                    name: name.clone(),
                    uid: obj.metadata.uid.clone(),
                };
                if let Some(observed) = ObservedResourceIdentity::from_resource_id(&rid) {
                    results.push(observed);
                } else {
                    bail!(
                        "Identity snapshot failed: {}/{} in {} has no UID",
                        kind,
                        name,
                        namespace
                    );
                }
            }
            Err(::kube::Error::Api(ref resp)) if resp.code == 404 => {
                // Resource genuinely absent — skip (not an error)
            }
            Err(e) => {
                bail!(
                    "Identity snapshot failed: cannot GET {}/{} in {}: {} \
                     (403/timeout/API errors are not safe to ignore)",
                    kind,
                    name,
                    namespace,
                    e
                );
            }
        }
    }
    Ok(results)
}

#[cfg(test)]
mod tests {
    use super::*;

    // Deleted: test_load_journal_v2_migration_discards_audit (old schema migration test)
    // Deleted: test_load_journal_v2_no_owned_crds_discards_audit_for_v4 (old schema migration test)

    #[test]
    fn test_cleanup_result_deserializes_v5_string() {
        // v5 format: plain string
        let v5_deleted: CleanupResult = serde_json::from_str(r#""deleted""#).unwrap();
        assert_eq!(v5_deleted, CleanupResult::DeleteRequested);

        let v5_gone: CleanupResult = serde_json::from_str(r#""gone""#).unwrap();
        assert_eq!(v5_gone, CleanupResult::Gone);

        let v5_already: CleanupResult = serde_json::from_str(r#""already_gone""#).unwrap();
        assert_eq!(v5_already, CleanupResult::AlreadyGone);

        let v5_already_space: CleanupResult = serde_json::from_str(r#""already gone""#).unwrap();
        assert_eq!(v5_already_space, CleanupResult::AlreadyGone);

        let v5_failed: CleanupResult =
            serde_json::from_str(r#""failed: connection refused""#).unwrap();
        assert!(matches!(v5_failed, CleanupResult::Failed(r) if r == "connection refused"));

        // Unknown strings must be rejected (not silently converted to Failed)
        let v5_unknown: Result<CleanupResult, _> = serde_json::from_str(r#""something_else""#);
        assert!(
            v5_unknown.is_err(),
            "unknown v5 string must fail deserialization"
        );
    }

    #[test]
    fn test_cleanup_result_deserializes_v6_enum() {
        // v6 format: tagged enum
        let v6_gone: CleanupResult = serde_json::from_str(r#""Gone""#).unwrap();
        assert_eq!(v6_gone, CleanupResult::Gone);

        let v6_failed: CleanupResult = serde_json::from_str(r#"{"Failed":"reason"}"#).unwrap();
        assert_eq!(v6_failed, CleanupResult::Failed("reason".to_string()));

        let v6_requested: CleanupResult = serde_json::from_str(r#""DeleteRequested""#).unwrap();
        assert_eq!(v6_requested, CleanupResult::DeleteRequested);

        let v6_already: CleanupResult = serde_json::from_str(r#""AlreadyGone""#).unwrap();
        assert_eq!(v6_already, CleanupResult::AlreadyGone);
    }

    #[test]
    fn test_unknown_outcome_roundtrip() {
        let uo: CleanupResult =
            serde_json::from_str(r#"{"UnknownOutcome":"500 timeout"}"#).unwrap();
        assert_eq!(uo, CleanupResult::UnknownOutcome("500 timeout".to_string()));

        let serialized = serde_json::to_string(&uo).unwrap();
        let rt: CleanupResult = serde_json::from_str(&serialized).unwrap();
        assert_eq!(rt, uo);
    }

    #[test]
    fn test_unknown_variant_rejected_not_silent() {
        let result: Result<CleanupResult, _> = serde_json::from_str(r#"{"FutureVariant":"data"}"#);
        assert!(
            result.is_err(),
            "unrecognized variant must fail, not silently convert"
        );
    }

    #[test]
    fn test_unknown_outcome_is_pending_not_hard_failed() {
        let decision = CleanupDecision {
            resource: crate::kube::resource::ResourceId {
                group: "test.io".to_string(),
                version: "v1".to_string(),
                kind: "Thing".to_string(),
                namespace: Some("ns".to_string()),
                name: "a".to_string(),
                uid: Some("uid-a".to_string()),
            },
            bound_uid: Some("uid-a".to_string()),
            action: "delete".to_string(),
            result: Some(CleanupResult::UnknownOutcome("500".to_string())),
            approved_spec_name: None,
        };
        assert!(
            decision.is_pending(),
            "UnknownOutcome must be pending (resumable)"
        );
        assert!(
            !decision.is_hard_failed(),
            "UnknownOutcome must NOT be hard_failed"
        );
        assert!(
            decision.is_failed(),
            "UnknownOutcome must be is_failed (needs attention)"
        );
    }

    // Deleted: test_v5_journal_cleanup_decisions_preserved (old schema migration test)
    // Deleted: test_v5_journal_no_mutation_authority (old schema migration test)

    /// Create a valid v12 journal JSON for field-removal tests.
    fn make_v12_journal_json() -> serde_json::Value {
        use crate::kube::resource::ResourceId;
        let csv_rid = ResourceId {
            group: "operators.coreos.com".to_string(),
            version: "v1alpha1".to_string(),
            kind: "ClusterServiceVersion".to_string(),
            namespace: Some("test-ns".to_string()),
            name: "test.v1".to_string(),
            uid: Some("uid-csv".to_string()),
        };
        let j = RunJournal {
            run_id: "test-v12".to_string(),
            schema_version: 12,
            oc_deps_version: "0.1.0".to_string(),
            journal_revision: 1,
            cluster_identity: crate::teardown::plan::ClusterIdentity {
                api_server: "https://test:6443".to_string(),
                kube_system_uid: "test-uid".to_string(),
            },
            operator: crate::teardown::plan::OperatorIdentitySnapshot {
                generation_identity:
                    crate::teardown::plan::OperatorGenerationIdentity::OlmPackage {
                        package_name: "test".to_string(),
                        install_namespace: "test-ns".to_string(),
                    },
                operator_id: crate::analyzers::olm::OperatorId {
                    csv_name: "test.v1".to_string(),
                    namespace: "test-ns".to_string(),
                },
                csv_name: "test.v1".to_string(),
                csv: crate::teardown::plan::ObservedResourceIdentity {
                    resource: csv_rid,
                    uid: "uid-csv".to_string(),
                },
                subscriptions: vec![],
                controller_deployments: vec![],
                service_accounts: vec![],
                owned_crds: vec![],
                required_crds: vec![],
            },
            created_at: "2026-01-01T00:00:00Z".to_string(),
            updated_at: "2026-01-01T00:00:00Z".to_string(),
            state: RunState::Applying,
            residual_status: ResidualStatus::NotAudited,
            audit_revision: 0,
            audit_context: AuditContext::default(),
            plan_snapshot: crate::teardown::planner::TeardownPlan {
                targets: vec![],
                preflight: crate::teardown::planner::Preflight { checks: vec![] },
                phases: vec![],
                blockers: vec![],
                warnings: vec![],
                snapshot_taken_at: "2026-01-01T00:00:00Z".to_string(),
                dependency_edges: vec![],
                operator_inventory: vec![],
                explicit_decisions: vec![],
                explicit_deletes: vec![],
            },
            execution: ExecutionRecord::default(),
            last_residual_audit: None,
            cleanup_decisions: vec![],
            finalizer_recovery_approved: false,
            finalizer_recoveries: vec![],
            backup_receipts: vec![],
        };
        serde_json::to_value(&j).unwrap()
    }

    fn write_json_to_file(json: &serde_json::Value, path: &std::path::Path) {
        std::fs::write(path, serde_json::to_string_pretty(json).unwrap()).unwrap();
    }

    #[test]
    fn v12_missing_re_delete_records_rejected() {
        let dir = std::env::temp_dir().join(format!("v12-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("journal.json");

        let mut json = make_v12_journal_json();
        json.pointer_mut("/execution")
            .unwrap()
            .as_object_mut()
            .unwrap()
            .remove("re_delete_records");
        write_json_to_file(&json, &path);

        let result = load_journal(&path);
        assert!(
            result.is_err(),
            "v12 journal without re_delete_records must fail parse"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn v12_missing_finalizer_fields_rejected() {
        let dir = std::env::temp_dir().join(format!("v12-fin-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("journal.json");

        let mut json = make_v12_journal_json();
        json.as_object_mut()
            .unwrap()
            .remove("finalizer_recovery_approved");
        write_json_to_file(&json, &path);
        assert!(
            load_journal(&path).is_err(),
            "v12 without finalizer_recovery_approved must fail"
        );

        let mut json2 = make_v12_journal_json();
        json2
            .as_object_mut()
            .unwrap()
            .remove("finalizer_recoveries");
        write_json_to_file(&json2, &path);
        assert!(
            load_journal(&path).is_err(),
            "v12 without finalizer_recoveries must fail"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn old_schema_version_rejected() {
        let dir = std::env::temp_dir().join(format!("old-schema-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("journal.json");

        let mut json = make_v12_journal_json();
        json["schema_version"] = serde_json::json!(11);
        write_json_to_file(&json, &path);

        let result = load_journal(&path);
        assert!(result.is_err(), "v11 journal must be rejected");
        let err = result.unwrap_err().to_string();
        assert!(
            err.contains("Unsupported journal schema version"),
            "Error must mention unsupported: {}",
            err
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn v12_roundtrip() {
        let dir = std::env::temp_dir().join(format!("v12-rt-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("journal.json");

        let json = make_v12_journal_json();
        write_json_to_file(&json, &path);
        let j = load_journal(&path).unwrap();
        assert_eq!(j.schema_version, 12);
        assert!(j.execution.re_delete_records.is_empty());
        assert!(!j.finalizer_recovery_approved);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
