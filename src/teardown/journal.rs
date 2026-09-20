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

pub const RUN_JOURNAL_SCHEMA_VERSION: u32 = 7;

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
                    other => Ok(CleanupResult::Failed(format!("unknown result: {}", other))),
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
                    other => Ok(CleanupResult::Failed(format!("unknown variant: {}", other))),
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
    /// Pending: needs resume action (not yet executed or DELETE sent but Gone not confirmed)
    pub fn is_pending(&self) -> bool {
        self.result.is_none() || matches!(self.result, Some(CleanupResult::DeleteRequested))
    }

    /// Hard failure: DELETE API error (not retryable without new authority)
    pub fn is_hard_failed(&self) -> bool {
        matches!(self.result, Some(CleanupResult::Failed(_)))
    }

    /// Failed or unconfirmed: includes both hard failures and unconfirmed DELETEs.
    /// DeleteRequested = DELETE accepted but Gone not confirmed (retryable via reconciliation).
    pub fn is_failed(&self) -> bool {
        matches!(
            self.result,
            Some(CleanupResult::DeleteRequested) | Some(CleanupResult::Failed(_))
        )
    }

    /// Terminal success: resource confirmed Gone
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
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CsvBaselineEntry {
    pub name: String,
    pub uid: String,
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
    let mut journal: RunJournal = serde_json::from_str(&data)
        .with_context(|| format!("Failed to parse journal: {}", path.display()))?;

    if journal.schema_version > RUN_JOURNAL_SCHEMA_VERSION {
        bail!(
            "Journal schema version {} is newer than supported version {}. \
             Update oc-deps to read this journal.",
            journal.schema_version,
            RUN_JOURNAL_SCHEMA_VERSION
        );
    }

    // Schema migration chain:
    // v1 → v2: discard audit (lacks UID tracking / recreation state)
    // v2 → v3: discard audit if unresolved_crds is None with owned CRDs
    // v3 → v4: discard audit if unresolved_gvks/csv_baseline is None
    // v4 → v5: cleanup_decisions field added (authority-critical).
    //          v4 journals cannot gain manual cleanup authority.
    if journal.schema_version < RUN_JOURNAL_SCHEMA_VERSION {
        let needs_audit_reset = journal.schema_version < 2
            || (journal.schema_version < 3
                && journal.audit_context.unresolved_crds.is_none()
                && !journal.operator.owned_crds.is_empty())
            || (journal.schema_version < 4
                && (journal.audit_context.unresolved_gvks.is_none()
                    || journal.audit_context.csv_baseline.is_none()));

        if needs_audit_reset && journal.last_residual_audit.is_some() {
            eprintln!(
                "  ℹ Migrating journal {} from schema v{} → v{}: \
                 discarding old residual audit (lacks required safety metadata)",
                journal.run_id, journal.schema_version, RUN_JOURNAL_SCHEMA_VERSION
            );
            journal.last_residual_audit = None;
            journal.residual_status = ResidualStatus::NotAudited;
        }
        // Only bump to v4 for audit migration. v4 journals stay at v4 —
        // cleanup operations check schema_version >= 5 at runtime.
        // v5 is only set when a NEW journal is created with cleanup support.
        if journal.schema_version < 4 {
            journal.schema_version = 4;
        }
        // v4 journals do NOT get bumped to v5/v6 — they cannot gain manual
        // cleanup authority that wasn't available at journal creation.

        // v5 journals: keep at schema_version 5 (read-only for inspection).
        // v6 journals: keep at schema_version 6 (read-only for inspection).
        // v7 adds approved_spec_name to CleanupDecision (authority-critical).
        // v5/v6 journals cannot gain new cleanup mutation authority.
        // execute_residual_cleanup requires schema_version == 7 (current).
    }

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
    // CRD name format: "pluralname.group" (e.g. "datascienceclusters.datasciencecluster.opendatahub.io")
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
    ctx
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_load_journal_v2_migration_discards_audit() {
        // A v2 journal with last_residual_audit containing ResidualEvidence
        // WITHOUT owner_ref_match. load_journal must:
        // 1. Deserialize successfully (serde(default) on owner_ref_match)
        // 2. Migrate to v3
        // 3. Discard old audit (set to None)
        // 4. Reset residual_status to NotAudited
        let v2_journal = r#"{
            "run_id": "run-test-v2",
            "schema_version": 2,
            "oc_deps_version": "0.1.0",
            "journal_revision": 5,
            "cluster_identity": {
                "api_server": "https://api.test:6443",
                "kube_system_uid": "test-uid"
            },
            "operator": {
                "generation_identity": { "Unverifiable": { "reason": "test" } },
                "operator_id": { "namespace": "ns", "csv_name": "test.1.0" },
                "csv_name": "test.1.0",
                "csv": { "resource": { "group": "operators.coreos.com", "version": "v1alpha1", "kind": "ClusterServiceVersion", "namespace": "ns", "name": "test.1.0", "uid": "csv-uid" }, "uid": "csv-uid" },
                "subscriptions": [],
                "controller_deployments": [],
                "service_accounts": [],
                "owned_crds": ["foos.example.com"],
                "required_crds": []
            },
            "created_at": "2026-01-01T00:00:00Z",
            "updated_at": "2026-01-01T01:00:00Z",
            "state": "ApplyCompleted",
            "residual_status": { "ResidualsObserved": { "count": 3 } },
            "audit_revision": 2,
            "audit_context": {
                "footprint_namespaces": ["ns"],
                "csv_names": ["test.1.0"],
                "controller_deployment_names": [],
                "service_account_names": [],
                "known_labels": [],
                "managed_field_managers": []
            },
            "plan_snapshot": {
                "targets": [],
                "preflight": { "checks": [] },
                "phases": [],
                "blockers": [],
                "warnings": [],
                "snapshot_taken_at": "2026-01-01"
            },
            "execution": {
                "phases_completed": 7,
                "phases_total": 7,
                "deleted": [],
                "already_gone": [],
                "failed": [],
                "kept": [],
                "reviewed": []
            },
            "last_residual_audit": {
                "planned_delete_still_present": [],
                "planned_expect_still_present": [],
                "expected_preserved": [],
                "likely_operator_residual": [{
                    "resource": {
                        "group": "apps", "version": "v1", "kind": "Deployment",
                        "namespace": "ns", "name": "old-dep", "uid": "uid-old"
                    },
                    "evidence": {
                        "matching_labels": [],
                        "matching_managers": ["test-mgr"],
                        "namespace_affinity": true,
                        "service_account_match": false
                    },
                    "confidence": "Low"
                }],
                "unattributed": [],
                "coverage": { "requested_probes": 5, "succeeded_probes": 5 },
                "scan_errors": []
            }
        }"#;

        let dir = std::env::temp_dir().join("oc-deps-test-v2-migration");
        let _ = std::fs::create_dir_all(&dir);
        let path = dir.join("v2-test.json");
        std::fs::write(&path, v2_journal).unwrap();

        let journal = load_journal(&path).unwrap();

        // Schema migrated to v4 (not v5 — old journals don't gain cleanup authority)
        assert_eq!(journal.schema_version, 4);

        // Old audit discarded (operator has owned CRDs but no unresolved_crds metadata)
        assert!(journal.last_residual_audit.is_none());
        assert!(matches!(
            journal.residual_status,
            ResidualStatus::NotAudited
        ));

        // Other fields preserved
        assert_eq!(journal.run_id, "run-test-v2");
        assert_eq!(journal.execution.phases_completed, 7);

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_load_journal_v2_no_owned_crds_discards_audit_for_v4() {
        // A v2 journal with NO owned CRDs — still discards audit because
        // csv_baseline and unresolved_gvks are missing (v4 safety requirement)
        let v2_journal = r#"{
            "run_id": "run-test-no-crds",
            "schema_version": 2,
            "oc_deps_version": "0.1.0",
            "journal_revision": 3,
            "cluster_identity": {
                "api_server": "https://api.test:6443",
                "kube_system_uid": "test-uid-2"
            },
            "operator": {
                "generation_identity": { "Unverifiable": { "reason": "test" } },
                "operator_id": { "namespace": "ns", "csv_name": "simple.1.0" },
                "csv_name": "simple.1.0",
                "csv": { "resource": { "group": "operators.coreos.com", "version": "v1alpha1", "kind": "ClusterServiceVersion", "namespace": "ns", "name": "simple.1.0", "uid": "csv-uid-2" }, "uid": "csv-uid-2" },
                "subscriptions": [],
                "controller_deployments": [],
                "service_accounts": [],
                "owned_crds": [],
                "required_crds": []
            },
            "created_at": "2026-01-01T00:00:00Z",
            "updated_at": "2026-01-01T01:00:00Z",
            "state": "ApplyCompleted",
            "residual_status": "NoneObservedInScope",
            "audit_revision": 1,
            "audit_context": {
                "footprint_namespaces": ["ns"],
                "csv_names": ["simple.1.0"],
                "controller_deployment_names": [],
                "service_account_names": [],
                "known_labels": [],
                "managed_field_managers": []
            },
            "plan_snapshot": {
                "targets": [],
                "preflight": { "checks": [] },
                "phases": [],
                "blockers": [],
                "warnings": [],
                "snapshot_taken_at": "2026-01-01"
            },
            "execution": {
                "phases_completed": 3,
                "phases_total": 3,
                "deleted": [],
                "already_gone": [],
                "failed": [],
                "kept": [],
                "reviewed": []
            },
            "last_residual_audit": {
                "planned_delete_still_present": [],
                "planned_expect_still_present": [],
                "expected_preserved": [],
                "likely_operator_residual": [],
                "unattributed": [],
                "coverage": { "requested_probes": 3, "succeeded_probes": 3 },
                "scan_errors": []
            }
        }"#;

        let dir = std::env::temp_dir().join("oc-deps-test-v2-no-crds");
        let _ = std::fs::create_dir_all(&dir);
        let path = dir.join("v2-no-crds.json");
        std::fs::write(&path, v2_journal).unwrap();

        let journal = load_journal(&path).unwrap();

        assert_eq!(journal.schema_version, 4);
        // v4 migration discards audit — unresolved_gvks and csv_baseline are None
        assert!(journal.last_residual_audit.is_none());
        assert!(matches!(
            journal.residual_status,
            ResidualStatus::NotAudited
        ));

        let _ = std::fs::remove_dir_all(&dir);
    }

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

        let v5_unknown: CleanupResult = serde_json::from_str(r#""something_else""#).unwrap();
        assert!(matches!(v5_unknown, CleanupResult::Failed(r) if r.contains("unknown result")));
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
    fn test_v5_journal_cleanup_decisions_preserved() {
        // A v5 journal with string-typed cleanup_decisions must:
        // 1. Deserialize successfully
        // 2. Migrate to v6
        // 3. Preserve cleanup_decisions (not clear them)
        let v5_journal = r#"{
            "run_id": "run-v5-test",
            "schema_version": 5,
            "oc_deps_version": "0.1.0",
            "journal_revision": 10,
            "cluster_identity": {
                "api_server": "https://api.test:6443",
                "kube_system_uid": "test-uid"
            },
            "operator": {
                "generation_identity": { "Unverifiable": { "reason": "test" } },
                "operator_id": { "namespace": "ns", "csv_name": "test.1.0" },
                "csv_name": "test.1.0",
                "csv": { "resource": { "group": "operators.coreos.com", "version": "v1alpha1", "kind": "ClusterServiceVersion", "namespace": "ns", "name": "test.1.0", "uid": "csv-uid" }, "uid": "csv-uid" },
                "subscriptions": [],
                "controller_deployments": [],
                "service_accounts": [],
                "owned_crds": [],
                "required_crds": []
            },
            "created_at": "2026-01-01T00:00:00Z",
            "updated_at": "2026-01-01T01:00:00Z",
            "state": "ApplyCompleted",
            "audit_context": {
                "target_namespaces": ["ns"],
                "scanned_kinds": [],
                "owned_gvks": [],
                "target_operators": []
            },
            "audit_revision": 5,
            "residual_status": "NotAudited",
            "plan_snapshot": { "targets": [], "preflight": { "checks": [] }, "phases": [], "blockers": [], "warnings": [], "snapshot_taken_at": "2026-01-01T00:00:00Z" },
            "execution": { "phases_completed": 0, "phases_total": 0, "deleted": [], "already_gone": [], "failed": [], "kept": [], "reviewed": [] },
            "cleanup_decisions": [
                {
                    "resource": { "group": "apps", "version": "v1", "kind": "Deployment", "namespace": "ns", "name": "my-deploy", "uid": "uid-123" },
                    "bound_uid": "uid-123",
                    "action": "delete",
                    "result": "deleted"
                },
                {
                    "resource": { "group": "apps", "version": "v1", "kind": "Deployment", "namespace": "ns", "name": "other", "uid": "uid-456" },
                    "bound_uid": "uid-456",
                    "action": "delete",
                    "result": "gone"
                }
            ]
        }"#;

        let dir = std::env::temp_dir().join("oc-deps-test-v5-decisions");
        let _ = std::fs::create_dir_all(&dir);
        let path = dir.join("v5-decisions.json");
        std::fs::write(&path, v5_journal).unwrap();

        let journal = load_journal(&path).unwrap();

        assert_eq!(
            journal.schema_version, 5,
            "v5 stays at 5 — read-only, no mutation authority"
        );
        assert_eq!(
            journal.cleanup_decisions.len(),
            2,
            "decisions must be preserved"
        );
        assert_eq!(
            journal.cleanup_decisions[0].result,
            Some(CleanupResult::DeleteRequested),
            "v5 'deleted' maps to DeleteRequested"
        );
        assert_eq!(
            journal.cleanup_decisions[1].result,
            Some(CleanupResult::Gone),
            "v5 'gone' maps to Gone"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_v5_journal_no_mutation_authority() {
        // v5 journals stay at schema_version 5.
        // execute_residual_cleanup requires schema_version == RUN_JOURNAL_SCHEMA_VERSION (6),
        // so v5 journals cannot gain new cleanup mutation authority.
        // The schema gate (not is_failed) is the actual mutation barrier.
        assert_ne!(
            5u32, RUN_JOURNAL_SCHEMA_VERSION,
            "v5 != current schema — core cleanup gate blocks mutations on v5 journals"
        );
        assert_ne!(
            6u32, RUN_JOURNAL_SCHEMA_VERSION,
            "v6 != current schema — core cleanup gate blocks mutations on v6 journals"
        );
        assert_eq!(
            7u32, RUN_JOURNAL_SCHEMA_VERSION,
            "current schema must be v7 for approved_spec_name support"
        );

        // v5 cleanup_decisions are still readable for inspection
        let result: CleanupResult = serde_json::from_str(r#""deleted""#).unwrap();
        assert_eq!(
            result,
            CleanupResult::DeleteRequested,
            "v5 string 'deleted' deserializes to DeleteRequested for read-only inspection"
        );

        // Roundtrip: v6 enum format also works
        let v6_serialized = serde_json::to_string(&CleanupResult::Gone).unwrap();
        let v6_roundtrip: CleanupResult = serde_json::from_str(&v6_serialized).unwrap();
        assert_eq!(
            v6_roundtrip,
            CleanupResult::Gone,
            "v6 enum roundtrips correctly"
        );
    }
}
