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

pub const RUN_JOURNAL_SCHEMA_VERSION: u32 = 2;

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

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AuditContext {
    pub footprint_namespaces: HashSet<String>,
    pub csv_names: HashSet<String>,
    pub controller_deployment_names: HashSet<String>,
    pub service_account_names: HashSet<String>,
    pub known_labels: Vec<(String, String)>,
    pub managed_field_managers: HashSet<String>,
    /// Discovery-derived GVR metadata for plan resources.
    /// None = GVR info not captured (old journal or discovery failure) → AuditIncomplete.
    /// Some(vec) = known GVRs for accurate probing.
    #[serde(default)]
    pub known_gvrs: Option<Vec<KnownGvr>>,
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

impl Default for AuditContext {
    fn default() -> Self {
        Self {
            footprint_namespaces: HashSet::new(),
            csv_names: HashSet::new(),
            controller_deployment_names: HashSet::new(),
            service_account_names: HashSet::new(),
            known_labels: Vec::new(),
            managed_field_managers: HashSet::new(),
            known_gvrs: None,
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
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

impl Default for ExecutionRecord {
    fn default() -> Self {
        Self {
            phases_completed: 0,
            phases_total: 0,
            deleted: Vec::new(),
            already_gone: Vec::new(),
            failed: Vec::new(),
            kept: Vec::new(),
            reviewed: Vec::new(),
        }
    }
}

// ──────────────────────────────────────────────────────────────
//  JournalStore — single-writer, revision-based CAS
// ──────────────────────────────────────────────────────────────

pub struct JournalStore {
    path: PathBuf,
    inner: Arc<Mutex<RunJournal>>,
}

impl JournalStore {
    pub fn new(journal: RunJournal, path: PathBuf) -> Self {
        Self {
            path,
            inner: Arc::new(Mutex::new(journal)),
        }
    }

    /// Update the journal via single-writer CAS.
    ///
    /// SAFETY: This uses in-process Mutex only. Only one JournalStore instance
    /// per journal file should exist in a process. Cross-process writes are NOT
    /// safe with this design — defer to PR3's full exclusive lock.
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
        .or_else(|| dirs::data_local_dir())
        .unwrap_or_else(|| PathBuf::from("/tmp"));
    Ok(base.join("oc-deps"))
}

pub fn runs_dir(cluster_id: &ClusterIdentity) -> Result<PathBuf> {
    let dir = state_dir()?.join("clusters").join(&cluster_id.kube_system_uid).join("runs");
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

    // v1 → v2 migration: discard old audit data (lacks UID tracking / recreation state).
    // The audit is non-authoritative and must be re-run with current code.
    if journal.schema_version < 2 {
        if journal.last_residual_audit.is_some() {
            eprintln!(
                "  ℹ Migrating journal {} from schema v{} → v{}: \
                 discarding old residual audit (lacks UID/recreation tracking)",
                journal.run_id, journal.schema_version, RUN_JOURNAL_SCHEMA_VERSION
            );
            journal.last_residual_audit = None;
            journal.residual_status = ResidualStatus::NotAudited;
        }
        journal.schema_version = RUN_JOURNAL_SCHEMA_VERSION;
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

    fs::rename(&tmp_path, path)
        .with_context(|| format!("Failed to rename {} -> {}", tmp_path.display(), path.display()))?;

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
    use kube::api::Api;
    use k8s_openapi::api::core::v1::Namespace;

    let ns_api: Api<Namespace> = Api::all(client.clone());
    let kube_system = ns_api.get("kube-system").await
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
        ctx.footprint_namespaces.insert(op.install_namespace.clone());
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
                    unresolved_gvks.push((rid.group.clone(), rid.version.clone(), rid.kind.clone()));
                }
            }
        }
    }

    // Also resolve owned CRDs — residual CR instances may exist outside the plan.
    // CRD name format: "pluralname.group" (e.g. "datascienceclusters.datasciencecluster.opendatahub.io")
    let mut unresolved_crds: Vec<String> = Vec::new();
    for op in operators {
        for crd_name in &op.owned_crds {
            let parts: Vec<&str> = crd_name.splitn(2, '.').collect();
            if parts.len() == 2 {
                let plural = parts[0];
                let group = parts[1];
                let mut found = false;
                for ((g, k), info) in gk_map.iter() {
                    if g == group && info.plural == plural {
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
                        found = true;
                        break;
                    }
                }
                if !found {
                    unresolved_crds.push(crd_name.clone());
                }
            }
        }
    }

    if !unresolved_gvks.is_empty() || !unresolved_crds.is_empty() {
        let total = unresolved_gvks.len() + unresolved_crds.len();
        eprintln!(
            "  ⚠ {} GVK(s) could not be resolved via API discovery \
             (audit will be incomplete for probes of these types)",
            total
        );
    }

    ctx.known_gvrs = Some(known_gvrs);
    ctx
}
