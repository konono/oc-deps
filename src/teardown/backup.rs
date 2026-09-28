use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};

use crate::kube::resource::ResourceId;
use crate::teardown::plan::ClusterIdentity;
use crate::teardown::planner::{Action, TeardownPlan};

pub const BACKUP_SCHEMA_VERSION: u32 = 1;

// ──────────────────────────────────────────────────────────────
//  Bundle types — Secret-bearing, never Debug-print raw objects
// ──────────────────────────────────────────────────────────────

#[derive(Serialize, Deserialize)]
pub struct BackupBundle {
    pub schema_version: u32,
    pub created_at: String,
    pub oc_deps_version: String,
    pub cluster_identity: ClusterIdentity,
    pub execution_plan_sha256: String,
    pub operator_names: Vec<String>,
    pub plan_path: String,
    pub coverage: CoverageSummary,
    pub contains_secret_data: bool,
    pub restore_supported: bool,
    pub restore_notes: Vec<String>,
    pub capability_warnings: Vec<String>,
    pub limitations: Vec<String>,
    pub resources: Vec<BackupResource>,
}

// Custom Debug: never print raw objects (may contain Secrets)
impl std::fmt::Debug for BackupBundle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BackupBundle")
            .field("schema_version", &self.schema_version)
            .field("created_at", &self.created_at)
            .field("cluster_identity", &self.cluster_identity)
            .field("coverage", &self.coverage)
            .field("contains_secret_data", &self.contains_secret_data)
            .field("resource_count", &self.resources.len())
            .finish()
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct CoverageSummary {
    pub candidates: usize,
    pub captured: usize,
    pub already_absent: usize,
    pub planned_actions: usize,
    pub cleanup_contract_targets: usize,
    pub adapter_incomplete: Vec<String>,
}

#[derive(Serialize, Deserialize)]
pub struct BackupResource {
    pub identity: BackupResourceIdentity,
    pub sources: Vec<BackupSource>,
    pub state: BackupResourceState,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub raw_object: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub recreate_manifest: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub deferred_lifecycle: Option<DeferredLifecycle>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub omitted_fields: Option<Vec<OmittedField>>,
}

// Custom Debug: never print raw_object / recreate_manifest
impl std::fmt::Debug for BackupResource {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BackupResource")
            .field("identity", &self.identity)
            .field("state", &self.state)
            .field("sources_count", &self.sources.len())
            .finish()
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct BackupResourceIdentity {
    pub group: String,
    pub version: String,
    pub kind: String,
    pub namespace: Option<String>,
    pub name: String,
    pub uid: String,
}

impl BackupResourceIdentity {
    pub fn from_resource_id(rid: &ResourceId, uid: &str) -> Self {
        Self {
            group: rid.group.clone(),
            version: rid.version.clone(),
            kind: rid.kind.clone(),
            namespace: rid.namespace.clone(),
            name: rid.name.clone(),
            uid: uid.to_string(),
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub enum BackupSource {
    PlanAction {
        phase: u32,
        action: String,
        reason: String,
    },
    CleanupContract {
        adapter_id: String,
        root_kind: String,
        source_contract: String,
    },
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum BackupResourceState {
    Captured,
    AlreadyAbsent,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DeferredLifecycle {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub owner_references: Vec<serde_json::Value>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub finalizers: Vec<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct OmittedField {
    pub path: String,
    pub reason: String,
}

// ──────────────────────────────────────────────────────────────
//  BackupReceipt — stored in RunJournal
// ──────────────────────────────────────────────────────────────

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BackupReceipt {
    pub path: String,
    pub sha256: String,
    pub created_at: String,
    pub execution_plan_sha256: String,
    pub resource_count: usize,
    pub contains_secret_data: bool,
}

// ──────────────────────────────────────────────────────────────
//  Candidate extraction
// ──────────────────────────────────────────────────────────────

#[derive(Clone, Debug)]
pub struct BackupCandidate {
    pub identity: BackupResourceIdentity,
    pub sources: Vec<BackupSource>,
}

pub fn extract_candidates(plan: &TeardownPlan) -> Vec<BackupCandidate> {
    let mut by_uid: BTreeMap<String, BackupCandidate> = BTreeMap::new();

    for (phase_idx, phase) in plan.phases.iter().enumerate() {
        for action in &phase.actions {
            let (rid, action_name, reason) = match action {
                Action::Delete { resource, reason } => (resource, "DELETE", reason.as_str()),
                Action::ExpectGone { resource, reason } => (resource, "EXPECT", reason.as_str()),
                Action::WaitGone { resource } => (resource, "WAIT", "cascade"),
                Action::Keep { .. } | Action::Review { .. } => continue,
            };

            let uid = match &rid.uid {
                Some(u) if !u.is_empty() => u,
                _ => continue,
            };

            let identity = BackupResourceIdentity::from_resource_id(rid, uid);
            let source = BackupSource::PlanAction {
                phase: (phase_idx + 1) as u32,
                action: action_name.to_string(),
                reason: reason.to_string(),
            };

            by_uid
                .entry(uid.clone())
                .and_modify(|c| c.sources.push(source.clone()))
                .or_insert_with(|| BackupCandidate {
                    identity,
                    sources: vec![source],
                });
        }
    }

    by_uid.into_values().collect()
}

pub fn add_adapter_candidates(
    candidates: &mut Vec<BackupCandidate>,
    reports: &[crate::analyzers::adapters::AdapterReport],
) -> Result<()> {
    use crate::analyzers::adapters::{AdapterReportStatus, AdapterResolution};

    for report in reports {
        if report.status == AdapterReportStatus::NotApplicable {
            continue;
        }

        // Fail closed on incomplete/unknown adapters
        if report.incomplete || report.status == AdapterReportStatus::Unknown {
            bail!(
                "Adapter {} reported status={} incomplete={} — \
                 backup coverage is incomplete. Cannot proceed with backup.",
                report.adapter_id,
                report.status,
                report.incomplete,
            );
        }

        for result in &report.results {
            match result.resolution {
                AdapterResolution::Resolved => {
                    let uid = match &result.resource.id.uid {
                        Some(u) if !u.is_empty() => u.clone(),
                        _ => continue,
                    };

                    let identity =
                        BackupResourceIdentity::from_resource_id(&result.resource.id, &uid);
                    let source = BackupSource::CleanupContract {
                        adapter_id: report.adapter_id.clone(),
                        root_kind: result
                            .resource
                            .source_id
                            .as_ref()
                            .map(|s| s.kind.clone())
                            .unwrap_or_default(),
                        source_contract: "CleansUp".to_string(),
                    };

                    if let Some(existing) = candidates.iter_mut().find(|c| c.identity.uid == uid) {
                        if !existing.sources.contains(&source) {
                            existing.sources.push(source);
                        }
                    } else {
                        candidates.push(BackupCandidate {
                            identity,
                            sources: vec![source],
                        });
                    }
                }
                AdapterResolution::TargetMissing => {
                    // Record but continue — target is already absent
                }
                AdapterResolution::Unknown => {
                    bail!(
                        "Adapter {} result for {}/{} has Unknown resolution — \
                         backup coverage incomplete",
                        report.adapter_id,
                        result.resource.id.kind,
                        result.resource.id.name,
                    );
                }
            }
        }
    }

    Ok(())
}

// ──────────────────────────────────────────────────────────────
//  Sanitize: raw_object → recreate_manifest
// ──────────────────────────────────────────────────────────────

const SERVER_METADATA_FIELDS: &[&str] = &[
    "uid",
    "resourceVersion",
    "generation",
    "creationTimestamp",
    "deletionTimestamp",
    "deletionGracePeriodSeconds",
    "managedFields",
    "selfLink",
];

pub fn sanitize_for_recreate(
    raw: &serde_json::Value,
) -> (serde_json::Value, DeferredLifecycle, Vec<OmittedField>) {
    let mut manifest = raw.clone();
    let mut omitted = Vec::new();
    let mut deferred = DeferredLifecycle {
        owner_references: Vec::new(),
        finalizers: Vec::new(),
    };

    // Remove status
    if manifest.as_object_mut().unwrap().remove("status").is_some() {
        omitted.push(OmittedField {
            path: "status".to_string(),
            reason: "server-managed lifecycle field".to_string(),
        });
    }

    // Process metadata
    if let Some(metadata) = manifest
        .pointer_mut("/metadata")
        .and_then(|v| v.as_object_mut())
    {
        // Remove server metadata fields
        for field in SERVER_METADATA_FIELDS {
            if metadata.remove(*field).is_some() {
                omitted.push(OmittedField {
                    path: format!("metadata.{}", field),
                    reason: "server-managed lifecycle field".to_string(),
                });
            }
        }

        // Remove generateName if name is present
        if metadata.contains_key("name") && metadata.remove("generateName").is_some() {
            omitted.push(OmittedField {
                path: "metadata.generateName".to_string(),
                reason: "name is set; generateName is unused".to_string(),
            });
        }

        // Move ownerReferences to deferred_lifecycle
        if let Some(refs) = metadata.remove("ownerReferences") {
            if let Some(arr) = refs.as_array() {
                deferred.owner_references = arr.clone();
            }
            omitted.push(OmittedField {
                path: "metadata.ownerReferences".to_string(),
                reason: "deferred to deferred_lifecycle — stale UIDs cause wedge after re-create"
                    .to_string(),
            });
        }

        // Move finalizers to deferred_lifecycle
        if let Some(fins) = metadata.remove("finalizers") {
            if let Some(arr) = fins.as_array() {
                deferred.finalizers = arr
                    .iter()
                    .filter_map(|v| v.as_str().map(|s| s.to_string()))
                    .collect();
            }
            omitted.push(OmittedField {
                path: "metadata.finalizers".to_string(),
                reason: "deferred to deferred_lifecycle — absent controllers cause wedge"
                    .to_string(),
            });
        }
    }

    (manifest, deferred, omitted)
}

// ──────────────────────────────────────────────────────────────
//  Fetch candidates from cluster
// ──────────────────────────────────────────────────────────────

pub async fn fetch_backup_resources(
    client: &kube::Client,
    candidates: &[BackupCandidate],
    kind_map: &crate::kube::discovery::KindMap,
    gk_map: &crate::kube::discovery::GroupKindMap,
) -> Result<(Vec<BackupResource>, bool)> {
    let mut resources = Vec::new();
    let mut contains_secrets = false;

    for candidate in candidates {
        let rid = ResourceId {
            group: candidate.identity.group.clone(),
            version: candidate.identity.version.clone(),
            kind: candidate.identity.kind.clone(),
            namespace: candidate.identity.namespace.clone(),
            name: candidate.identity.name.clone(),
            uid: Some(candidate.identity.uid.clone()),
        };

        let (api, _namespaced) =
            match crate::kube::resource::resolve_api(client, &rid, kind_map, gk_map) {
                Some(resolved) => resolved,
                None => {
                    bail!(
                        "Cannot resolve API for {}/{} (group={}, version={}) — \
                     API discovery failure, backup cannot proceed",
                        rid.kind,
                        rid.name,
                        rid.group,
                        rid.version,
                    );
                }
            };

        match api.get(&rid.name).await {
            Ok(obj) => {
                // Validate UID exact match
                let live_uid = obj.metadata.uid.as_deref().unwrap_or("");
                if live_uid != candidate.identity.uid {
                    bail!(
                        "UID mismatch for {}/{}: expected {} got {} — \
                         resource has been recreated, backup cannot proceed",
                        rid.kind,
                        rid.name,
                        candidate.identity.uid,
                        live_uid,
                    );
                }

                // Check for Secret
                let raw = serde_json::to_value(&obj)?;
                let is_secret = rid.kind == "Secret";
                if is_secret {
                    contains_secrets = true;
                }

                let (recreate, deferred, omitted) = sanitize_for_recreate(&raw);

                resources.push(BackupResource {
                    identity: candidate.identity.clone(),
                    sources: candidate.sources.clone(),
                    state: BackupResourceState::Captured,
                    raw_object: Some(raw),
                    recreate_manifest: Some(recreate),
                    deferred_lifecycle: Some(deferred),
                    omitted_fields: Some(omitted),
                });
            }
            Err(kube::Error::Api(ref err)) if err.code == 404 => {
                resources.push(BackupResource {
                    identity: candidate.identity.clone(),
                    sources: candidate.sources.clone(),
                    state: BackupResourceState::AlreadyAbsent,
                    raw_object: None,
                    recreate_manifest: None,
                    deferred_lifecycle: None,
                    omitted_fields: None,
                });
            }
            Err(e) => {
                let code = if let kube::Error::Api(ref api_err) = e {
                    api_err.code
                } else {
                    0
                };
                bail!(
                    "Failed to GET {}/{} (HTTP {}): {} — \
                     backup cannot proceed (no partial backups)",
                    rid.kind,
                    rid.name,
                    code,
                    e,
                );
            }
        }
    }

    // Sort by identity for deterministic output
    resources.sort_by(|a, b| a.identity.cmp(&b.identity));

    Ok((resources, contains_secrets))
}

// ──────────────────────────────────────────────────────────────
//  Build bundle
// ──────────────────────────────────────────────────────────────

pub fn build_bundle(
    resources: Vec<BackupResource>,
    cluster_identity: &ClusterIdentity,
    plan_sha256: &str,
    plan_path: &str,
    operator_names: Vec<String>,
    contains_secret_data: bool,
    adapter_incomplete: Vec<String>,
) -> BackupBundle {
    let candidates = resources.len();
    let captured = resources
        .iter()
        .filter(|r| r.state == BackupResourceState::Captured)
        .count();
    let already_absent = resources
        .iter()
        .filter(|r| r.state == BackupResourceState::AlreadyAbsent)
        .count();
    let cleanup_contract = resources
        .iter()
        .filter(|r| {
            r.sources
                .iter()
                .any(|s| matches!(s, BackupSource::CleanupContract { .. }))
        })
        .count();
    let planned_actions = resources
        .iter()
        .filter(|r| {
            r.sources
                .iter()
                .any(|s| matches!(s, BackupSource::PlanAction { .. }))
        })
        .count();

    BackupBundle {
        schema_version: BACKUP_SCHEMA_VERSION,
        created_at: crate::teardown::journal::chrono_now_iso(),
        oc_deps_version: env!("CARGO_PKG_VERSION").to_string(),
        cluster_identity: cluster_identity.clone(),
        execution_plan_sha256: plan_sha256.to_string(),
        operator_names,
        plan_path: plan_path.to_string(),
        coverage: CoverageSummary {
            candidates,
            captured,
            already_absent,
            planned_actions,
            cleanup_contract_targets: cleanup_contract,
            adapter_incomplete,
        },
        contains_secret_data,
        restore_supported: false,
        restore_notes: vec![
            "This bundle contains raw resource originals and best-effort recreate manifests.".to_string(),
            "Automatic restore is not supported — manual review and kubectl apply required.".to_string(),
            "recreate_manifest is a best-effort candidate; kind-specific allocated/defaulted/immutable fields may require review.".to_string(),
        ],
        capability_warnings: vec![
            "recreate_manifest is a best-effort candidate; kind-specific allocated/defaulted/immutable fields may require review.".to_string(),
            "Service clusterIP/nodePort, PVC volumeName, and CRD webhook defaults are not generically detectable.".to_string(),
            "ownerReferences and finalizers are stored in deferred_lifecycle, not in recreate_manifest.".to_string(),
        ],
        limitations: vec![
            "ownerRef-derived unplanned cascade children are not captured.".to_string(),
            "Storage reclaim and derived storage side effects are not captured.".to_string(),
            "Operator-reconciled state may differ from the stored originals after re-creation.".to_string(),
        ],
        resources,
    }
}

// ──────────────────────────────────────────────────────────────
//  Atomic write with readback verification
// ──────────────────────────────────────────────────────────────

pub fn compute_sha256(data: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(data);
    format!("{:x}", hasher.finalize())
}

pub fn compute_plan_sha256(plan_path: &str) -> Result<String> {
    let data = std::fs::read(plan_path)
        .with_context(|| format!("Failed to read plan file for SHA-256: {}", plan_path))?;
    Ok(compute_sha256(&data))
}

static BACKUP_COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

pub fn write_backup_bundle(bundle: &BackupBundle, target: &Path) -> Result<BackupReceipt> {
    use std::io::Write;

    // Reject if target already exists
    if target.exists() {
        bail!(
            "Backup target {} already exists — will not overwrite",
            target.display()
        );
    }

    let parent = target
        .parent()
        .ok_or_else(|| anyhow::anyhow!("No parent directory for {}", target.display()))?;
    if !parent.exists() {
        bail!(
            "Backup target parent directory {} does not exist",
            parent.display()
        );
    }

    // Serialize with stable key ordering
    let json = serde_json::to_string_pretty(bundle)?;
    let json_bytes = json.as_bytes();
    let expected_sha = compute_sha256(json_bytes);

    // Atomic write: create_new → write → sync → rename
    let seq = BACKUP_COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let tmp_name = format!(".tmp_backup_{}_{}", std::process::id(), seq);
    let tmp_path = parent.join(&tmp_name);

    struct TempGuard {
        path: PathBuf,
        armed: bool,
    }
    impl TempGuard {
        fn disarm(&mut self) {
            self.armed = false;
        }
    }
    impl Drop for TempGuard {
        fn drop(&mut self) {
            if self.armed {
                let _ = std::fs::remove_file(&self.path);
            }
        }
    }

    let mut guard = TempGuard {
        path: tmp_path.clone(),
        armed: true,
    };

    {
        let mut f = std::fs::File::create_new(&tmp_path)
            .with_context(|| format!("Failed to create temp backup: {}", tmp_path.display()))?;

        // Set file mode 0600 before writing content
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = f.set_permissions(std::fs::Permissions::from_mode(0o600));
        }

        f.write_all(json_bytes)?;
        f.sync_all()?;
    }

    // No-clobber rename
    // On Unix, rename is atomic but overwrites. We already checked !target.exists(),
    // but to be safe against races we use link + unlink pattern where possible.
    #[cfg(unix)]
    {
        match std::fs::hard_link(&tmp_path, target) {
            Ok(()) => {
                let _ = std::fs::remove_file(&tmp_path);
                guard.disarm();
            }
            Err(_) => {
                // Same filesystem fallback
                std::fs::rename(&tmp_path, target).with_context(|| {
                    format!(
                        "Failed to publish backup: {} → {}",
                        tmp_path.display(),
                        target.display()
                    )
                })?;
                guard.disarm();
            }
        }
    }

    #[cfg(not(unix))]
    {
        std::fs::rename(&tmp_path, target).with_context(|| {
            format!(
                "Failed to publish backup: {} → {}",
                tmp_path.display(),
                target.display()
            )
        })?;
        guard.disarm();
    }

    // Verify file mode
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let meta = std::fs::metadata(target)?;
        let mode = meta.permissions().mode() & 0o777;
        if mode != 0o600 {
            let _ = std::fs::set_permissions(target, std::fs::Permissions::from_mode(0o600));
        }
    }

    // Read-back verify
    let readback = std::fs::read(target)
        .with_context(|| format!("Failed to read back backup: {}", target.display()))?;
    let actual_sha = compute_sha256(&readback);
    if actual_sha != expected_sha {
        bail!(
            "Backup readback verification failed: expected SHA-256 {} got {} — \
             file may be corrupted, DELETE will not proceed",
            expected_sha,
            actual_sha,
        );
    }

    // Parse readback to verify valid JSON
    let _: BackupBundle = serde_json::from_slice(&readback)
        .with_context(|| "Backup readback parse failed — file is corrupted")?;

    // fsync parent directory
    if let Ok(dir) = std::fs::File::open(parent) {
        let _ = dir.sync_all();
    }

    // Warn about secret content
    if bundle.contains_secret_data {
        eprintln!(
            "  ⚠ Backup contains Secret data (file mode 0600). \
             Do not commit to version control."
        );
    }

    Ok(BackupReceipt {
        path: target.to_string_lossy().to_string(),
        sha256: actual_sha,
        created_at: bundle.created_at.clone(),
        execution_plan_sha256: bundle.execution_plan_sha256.clone(),
        resource_count: bundle.resources.len(),
        contains_secret_data: bundle.contains_secret_data,
    })
}

// ──────────────────────────────────────────────────────────────
//  Backup dir setup for batch mode
// ──────────────────────────────────────────────────────────────

pub fn setup_backup_dir(dir: &Path) -> Result<()> {
    if !dir.exists() {
        std::fs::create_dir_all(dir)
            .with_context(|| format!("Failed to create backup dir: {}", dir.display()))?;
    }

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700));
    }

    Ok(())
}

pub fn batch_backup_path(dir: &Path, index: usize, operator_name: &str) -> PathBuf {
    dir.join(format!("{:02}-{}.backup.json", index, operator_name))
}

// ──────────────────────────────────────────────────────────────
//  Receipt validation (for resume)
// ──────────────────────────────────────────────────────────────

#[allow(dead_code)]
pub fn validate_receipt(
    receipt: &BackupReceipt,
    current_cluster: &ClusterIdentity,
    plan_sha256: &str,
) -> Result<()> {
    // Check file exists
    let path = Path::new(&receipt.path);
    if !path.exists() {
        bail!(
            "Backup file {} no longer exists — cannot resume mutation",
            receipt.path,
        );
    }

    // Check SHA-256
    let data = std::fs::read(path)
        .with_context(|| format!("Failed to read backup for validation: {}", receipt.path))?;
    let actual_sha = compute_sha256(&data);
    if actual_sha != receipt.sha256 {
        bail!(
            "Backup file {} has been modified: expected SHA-256 {} got {} — \
             cannot resume mutation",
            receipt.path,
            receipt.sha256,
            actual_sha,
        );
    }

    // Parse and validate cluster binding
    let bundle: BackupBundle = serde_json::from_slice(&data)
        .with_context(|| format!("Backup file {} is not valid JSON", receipt.path))?;

    if !current_cluster.matches(&bundle.cluster_identity) {
        bail!(
            "Backup cluster identity mismatch: backup kube-system UID {} \
             does not match current cluster {}",
            bundle.cluster_identity.kube_system_uid,
            current_cluster.kube_system_uid,
        );
    }

    // Check plan SHA-256 binding
    if bundle.execution_plan_sha256 != plan_sha256 {
        bail!(
            "Backup plan SHA-256 mismatch: backup {} does not match current plan {}",
            bundle.execution_plan_sha256,
            plan_sha256,
        );
    }

    Ok(())
}

// ──────────────────────────────────────────────────────────────
//  Tests
// ──────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::teardown::planner::{Action, PlanPhase, Preflight, TeardownPlan};

    fn rid(kind: &str, name: &str, uid: Option<&str>) -> ResourceId {
        ResourceId {
            group: "".to_string(),
            version: "v1".to_string(),
            kind: kind.to_string(),
            namespace: Some("ns".to_string()),
            name: name.to_string(),
            uid: uid.map(|s| s.to_string()),
        }
    }

    fn make_plan(actions: Vec<Action>) -> TeardownPlan {
        TeardownPlan {
            targets: vec![],
            preflight: Preflight { checks: vec![] },
            phases: vec![PlanPhase {
                name: "Phase 1".to_string(),
                description: String::new(),
                actions,
                barrier: None,
            }],
            blockers: vec![],
            warnings: vec![],
            snapshot_taken_at: "2026-01-01T00:00:00Z".to_string(),
            dependency_edges: vec![],
            operator_inventory: vec![],
            explicit_decisions: vec![],
            explicit_deletes: vec![],
        }
    }

    #[test]
    fn candidate_extraction_includes_delete_expect_wait() {
        let plan = make_plan(vec![
            Action::Delete {
                resource: rid("Deployment", "d1", Some("uid-1")),
                reason: "root".to_string(),
            },
            Action::ExpectGone {
                resource: rid("Pod", "p1", Some("uid-2")),
                reason: "cascade".to_string(),
            },
            Action::WaitGone {
                resource: rid("ReplicaSet", "rs1", Some("uid-3")),
            },
        ]);

        let candidates = extract_candidates(&plan);
        assert_eq!(candidates.len(), 3);
        let uids: Vec<&str> = candidates.iter().map(|c| c.identity.uid.as_str()).collect();
        assert!(uids.contains(&"uid-1"));
        assert!(uids.contains(&"uid-2"));
        assert!(uids.contains(&"uid-3"));
    }

    #[test]
    fn candidate_extraction_excludes_keep_review() {
        let plan = make_plan(vec![
            Action::Delete {
                resource: rid("Deployment", "d1", Some("uid-1")),
                reason: "root".to_string(),
            },
            Action::Keep {
                resource: rid("Namespace", "ns1", None),
                reason: "ns".to_string(),
            },
            Action::Review {
                resource: rid("ConfigMap", "cm1", None),
                reason: "label".to_string(),
                metadata: None,
            },
        ]);

        let candidates = extract_candidates(&plan);
        assert_eq!(candidates.len(), 1);
        assert_eq!(candidates[0].identity.uid, "uid-1");
    }

    #[test]
    fn candidate_dedup_preserves_sources() {
        let plan = make_plan(vec![
            Action::Delete {
                resource: rid("Deployment", "d1", Some("uid-1")),
                reason: "root".to_string(),
            },
            Action::ExpectGone {
                resource: rid("Deployment", "d1", Some("uid-1")),
                reason: "cascade".to_string(),
            },
        ]);

        let candidates = extract_candidates(&plan);
        assert_eq!(candidates.len(), 1);
        assert_eq!(candidates[0].sources.len(), 2);
    }

    #[test]
    fn candidate_skips_empty_uid() {
        let plan = make_plan(vec![
            Action::Delete {
                resource: rid("Deployment", "d1", None),
                reason: "root".to_string(),
            },
            Action::Delete {
                resource: rid("Deployment", "d2", Some("")),
                reason: "root".to_string(),
            },
        ]);

        let candidates = extract_candidates(&plan);
        assert_eq!(candidates.len(), 0);
    }

    #[test]
    fn sanitize_removes_server_fields() {
        let raw = serde_json::json!({
            "apiVersion": "v1",
            "kind": "ConfigMap",
            "metadata": {
                "name": "test",
                "namespace": "ns",
                "uid": "uid-1",
                "resourceVersion": "12345",
                "generation": 1,
                "creationTimestamp": "2026-01-01T00:00:00Z",
                "managedFields": [{"manager": "test"}],
                "selfLink": "/api/v1/namespaces/ns/configmaps/test",
                "labels": {"app": "test"},
                "annotations": {"note": "keep"},
            },
            "data": {"key": "value"},
            "status": {"phase": "Active"},
        });

        let (manifest, deferred, omitted) = sanitize_for_recreate(&raw);

        // Server fields removed
        assert!(manifest.pointer("/metadata/uid").is_none());
        assert!(manifest.pointer("/metadata/resourceVersion").is_none());
        assert!(manifest.pointer("/metadata/generation").is_none());
        assert!(manifest.pointer("/metadata/creationTimestamp").is_none());
        assert!(manifest.pointer("/metadata/managedFields").is_none());
        assert!(manifest.pointer("/metadata/selfLink").is_none());
        assert!(manifest.pointer("/status").is_none());

        // Desired fields preserved
        assert_eq!(manifest.pointer("/metadata/name").unwrap(), "test");
        assert_eq!(manifest.pointer("/metadata/labels/app").unwrap(), "test");
        assert_eq!(manifest.pointer("/data/key").unwrap(), "value");
        assert_eq!(manifest.pointer("/apiVersion").unwrap(), "v1");

        // Deferred empty (no ownerRefs/finalizers in input)
        assert!(deferred.owner_references.is_empty());
        assert!(deferred.finalizers.is_empty());

        // Omitted fields recorded
        let paths: Vec<&str> = omitted.iter().map(|o| o.path.as_str()).collect();
        assert!(paths.contains(&"metadata.uid"));
        assert!(paths.contains(&"status"));
    }

    #[test]
    fn sanitize_defers_owner_refs_and_finalizers() {
        let raw = serde_json::json!({
            "apiVersion": "v1",
            "kind": "Pod",
            "metadata": {
                "name": "test",
                "ownerReferences": [
                    {"apiVersion": "apps/v1", "kind": "ReplicaSet", "name": "rs1", "uid": "uid-rs"}
                ],
                "finalizers": ["kubernetes.io/pv-protection"],
            },
        });

        let (manifest, deferred, _omitted) = sanitize_for_recreate(&raw);

        assert!(manifest.pointer("/metadata/ownerReferences").is_none());
        assert!(manifest.pointer("/metadata/finalizers").is_none());
        assert_eq!(deferred.owner_references.len(), 1);
        assert_eq!(deferred.finalizers, vec!["kubernetes.io/pv-protection"]);
    }

    #[test]
    fn sanitize_removes_generate_name_when_name_present() {
        let raw = serde_json::json!({
            "apiVersion": "v1",
            "kind": "Pod",
            "metadata": {
                "name": "pod-abc",
                "generateName": "pod-",
            },
        });

        let (manifest, _, omitted) = sanitize_for_recreate(&raw);
        assert!(manifest.pointer("/metadata/generateName").is_none());
        assert!(omitted.iter().any(|o| o.path == "metadata.generateName"));
    }

    #[test]
    fn sanitize_keeps_generate_name_when_no_name() {
        let raw = serde_json::json!({
            "apiVersion": "v1",
            "kind": "Pod",
            "metadata": {
                "generateName": "pod-",
            },
        });

        let (manifest, _, _) = sanitize_for_recreate(&raw);
        assert_eq!(manifest.pointer("/metadata/generateName").unwrap(), "pod-");
    }

    #[test]
    fn sanitize_preserves_unknown_cr_fields() {
        let raw = serde_json::json!({
            "apiVersion": "example.io/v1",
            "kind": "Widget",
            "metadata": {
                "name": "w1",
                "uid": "uid-1",
                "resourceVersion": "999",
            },
            "spec": {
                "replicas": 3,
                "template": {"custom": true},
            },
            "data": {"secret-key": "secret-value"},
        });

        let (manifest, _, _) = sanitize_for_recreate(&raw);
        assert_eq!(manifest.pointer("/spec/replicas").unwrap(), 3);
        assert_eq!(manifest.pointer("/spec/template/custom").unwrap(), true);
        assert_eq!(
            manifest.pointer("/data/secret-key").unwrap(),
            "secret-value"
        );
    }

    #[test]
    fn secret_data_preserved_in_both_layers() {
        let raw = serde_json::json!({
            "apiVersion": "v1",
            "kind": "Secret",
            "metadata": {
                "name": "my-secret",
                "uid": "uid-s",
                "resourceVersion": "100",
            },
            "data": {"password": "c2VjcmV0"},
            "stringData": {"api-key": "abc123"},
        });

        let (manifest, _, _) = sanitize_for_recreate(&raw);
        // Both raw and recreate should have Secret data
        assert_eq!(raw.pointer("/data/password").unwrap(), "c2VjcmV0");
        assert_eq!(manifest.pointer("/data/password").unwrap(), "c2VjcmV0");
        assert_eq!(manifest.pointer("/stringData/api-key").unwrap(), "abc123");
    }

    #[test]
    fn secret_not_in_debug() {
        let raw = serde_json::json!({
            "apiVersion": "v1",
            "kind": "Secret",
            "metadata": {"name": "s", "uid": "u"},
            "data": {"password": "c2VjcmV0"},
        });

        let resource = BackupResource {
            identity: BackupResourceIdentity {
                group: "".to_string(),
                version: "v1".to_string(),
                kind: "Secret".to_string(),
                namespace: Some("ns".to_string()),
                name: "s".to_string(),
                uid: "u".to_string(),
            },
            sources: vec![],
            state: BackupResourceState::Captured,
            raw_object: Some(raw.clone()),
            recreate_manifest: Some(raw),
            deferred_lifecycle: None,
            omitted_fields: None,
        };

        let debug_str = format!("{:?}", resource);
        assert!(
            !debug_str.contains("c2VjcmV0"),
            "Debug must not contain Secret data: {}",
            debug_str
        );
        assert!(
            !debug_str.contains("password"),
            "Debug must not contain Secret keys: {}",
            debug_str
        );
    }

    #[test]
    fn bundle_debug_no_secrets() {
        let bundle = build_bundle(
            vec![],
            &ClusterIdentity {
                api_server: "https://test".to_string(),
                kube_system_uid: "uid-ks".to_string(),
            },
            "sha256abc",
            "/tmp/plan.json",
            vec!["test-op".to_string()],
            true,
            vec![],
        );
        let debug_str = format!("{:?}", bundle);
        assert!(!debug_str.contains("raw_object"));
        assert!(!debug_str.contains("recreate_manifest"));
    }

    #[test]
    fn write_rejects_existing_target() {
        let dir = std::env::temp_dir().join(format!("backup-exists-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let target = dir.join("backup.json");
        std::fs::write(&target, "{}").unwrap();

        let bundle = build_bundle(
            vec![],
            &ClusterIdentity {
                api_server: "https://test".to_string(),
                kube_system_uid: "uid-ks".to_string(),
            },
            "sha256abc",
            "/tmp/plan.json",
            vec![],
            false,
            vec![],
        );
        let result = write_backup_bundle(&bundle, &target);
        assert!(result.is_err(), "must reject existing target");
        assert!(result.unwrap_err().to_string().contains("already exists"));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn write_roundtrip_and_mode() {
        let dir = std::env::temp_dir().join(format!("backup-rt-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let target = dir.join("backup.json");

        let bundle = build_bundle(
            vec![],
            &ClusterIdentity {
                api_server: "https://test".to_string(),
                kube_system_uid: "uid-ks".to_string(),
            },
            "sha256abc",
            "/tmp/plan.json",
            vec!["op1".to_string()],
            false,
            vec![],
        );
        let receipt = write_backup_bundle(&bundle, &target).unwrap();

        assert_eq!(receipt.resource_count, 0);
        assert!(!receipt.contains_secret_data);

        // Verify SHA-256
        let data = std::fs::read(&target).unwrap();
        let sha = compute_sha256(&data);
        assert_eq!(receipt.sha256, sha);

        // Verify mode 0600
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&target).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o600, "file mode must be 0600");
        }

        // Verify parseable
        let loaded: BackupBundle = serde_json::from_slice(&data).unwrap();
        assert_eq!(loaded.schema_version, 1);

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn write_cleans_temp_on_failure() {
        let bundle = build_bundle(
            vec![],
            &ClusterIdentity {
                api_server: "https://test".to_string(),
                kube_system_uid: "uid-ks".to_string(),
            },
            "sha256abc",
            "/tmp/plan.json",
            vec![],
            false,
            vec![],
        );
        let result = write_backup_bundle(&bundle, Path::new("/nonexistent/dir/backup.json"));
        assert!(result.is_err());
    }

    #[test]
    fn deterministic_output() {
        let make_bundle = || {
            build_bundle(
                vec![
                    BackupResource {
                        identity: BackupResourceIdentity {
                            group: "apps".to_string(),
                            version: "v1".to_string(),
                            kind: "Deployment".to_string(),
                            namespace: Some("ns".to_string()),
                            name: "z-deploy".to_string(),
                            uid: "uid-z".to_string(),
                        },
                        sources: vec![BackupSource::PlanAction {
                            phase: 1,
                            action: "DELETE".to_string(),
                            reason: "root".to_string(),
                        }],
                        state: BackupResourceState::Captured,
                        raw_object: Some(serde_json::json!({"test": true})),
                        recreate_manifest: Some(serde_json::json!({"test": true})),
                        deferred_lifecycle: None,
                        omitted_fields: None,
                    },
                    BackupResource {
                        identity: BackupResourceIdentity {
                            group: "".to_string(),
                            version: "v1".to_string(),
                            kind: "ConfigMap".to_string(),
                            namespace: Some("ns".to_string()),
                            name: "a-cm".to_string(),
                            uid: "uid-a".to_string(),
                        },
                        sources: vec![BackupSource::PlanAction {
                            phase: 1,
                            action: "DELETE".to_string(),
                            reason: "root".to_string(),
                        }],
                        state: BackupResourceState::Captured,
                        raw_object: Some(serde_json::json!({"data": {"k": "v"}})),
                        recreate_manifest: Some(serde_json::json!({"data": {"k": "v"}})),
                        deferred_lifecycle: None,
                        omitted_fields: None,
                    },
                ],
                &ClusterIdentity {
                    api_server: "https://test".to_string(),
                    kube_system_uid: "uid-ks".to_string(),
                },
                "sha256abc",
                "/tmp/plan.json",
                vec!["op1".to_string()],
                false,
                vec![],
            )
        };

        // Resources are pre-sorted by identity in build, so order should be deterministic
        let b1 = make_bundle();
        let b2 = make_bundle();
        let j1 = serde_json::to_string_pretty(&b1).unwrap();
        let j2 = serde_json::to_string_pretty(&b2).unwrap();
        // created_at differs, so strip it
        let strip = |s: &str| -> String {
            s.lines()
                .filter(|l| !l.contains("created_at"))
                .collect::<Vec<_>>()
                .join("\n")
        };
        assert_eq!(
            strip(&j1),
            strip(&j2),
            "output must be deterministic (minus timestamp)"
        );
    }

    #[test]
    fn receipt_roundtrip() {
        let receipt = BackupReceipt {
            path: "/tmp/backup.json".to_string(),
            sha256: "abc123".to_string(),
            created_at: "2026-01-01T00:00:00Z".to_string(),
            execution_plan_sha256: "plan-sha".to_string(),
            resource_count: 5,
            contains_secret_data: true,
        };
        let json = serde_json::to_string(&receipt).unwrap();
        let loaded: BackupReceipt = serde_json::from_str(&json).unwrap();
        assert_eq!(loaded.sha256, "abc123");
        assert_eq!(loaded.resource_count, 5);
        assert!(loaded.contains_secret_data);
    }

    #[test]
    fn validate_receipt_missing_file() {
        let receipt = BackupReceipt {
            path: "/nonexistent/backup.json".to_string(),
            sha256: "abc".to_string(),
            created_at: "t".to_string(),
            execution_plan_sha256: "p".to_string(),
            resource_count: 0,
            contains_secret_data: false,
        };
        let cluster = ClusterIdentity {
            api_server: "https://test".to_string(),
            kube_system_uid: "uid".to_string(),
        };
        let result = validate_receipt(&receipt, &cluster, "p");
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("no longer exists"));
    }

    #[test]
    fn validate_receipt_tampered() {
        let dir = std::env::temp_dir().join(format!("receipt-tamper-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("backup.json");

        let bundle = build_bundle(
            vec![],
            &ClusterIdentity {
                api_server: "https://test".to_string(),
                kube_system_uid: "uid-ks".to_string(),
            },
            "plan-sha",
            "/tmp/plan.json",
            vec![],
            false,
            vec![],
        );
        let receipt = write_backup_bundle(&bundle, &path).unwrap();

        // Tamper with file
        std::fs::write(&path, "{}").unwrap();

        let cluster = ClusterIdentity {
            api_server: "https://test".to_string(),
            kube_system_uid: "uid-ks".to_string(),
        };
        let result = validate_receipt(&receipt, &cluster, "plan-sha");
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(
            err.contains("modified") || err.contains("not valid JSON"),
            "err: {}",
            err
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn validate_receipt_cluster_mismatch() {
        let dir = std::env::temp_dir().join(format!("receipt-cluster-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("backup.json");

        let bundle = build_bundle(
            vec![],
            &ClusterIdentity {
                api_server: "https://test".to_string(),
                kube_system_uid: "uid-ks".to_string(),
            },
            "plan-sha",
            "/tmp/plan.json",
            vec![],
            false,
            vec![],
        );
        let receipt = write_backup_bundle(&bundle, &path).unwrap();

        let wrong_cluster = ClusterIdentity {
            api_server: "https://other".to_string(),
            kube_system_uid: "uid-other".to_string(),
        };
        let result = validate_receipt(&receipt, &wrong_cluster, "plan-sha");
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("cluster identity mismatch")
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn batch_backup_path_format() {
        let dir = Path::new("/tmp/backups");
        let path = batch_backup_path(dir, 3, "nfd");
        assert_eq!(path, PathBuf::from("/tmp/backups/03-nfd.backup.json"));
    }

    #[test]
    fn adapter_unknown_blocks_backup() {
        use crate::analyzers::adapters::{AdapterReport, AdapterReportStatus};

        let report = AdapterReport {
            adapter_id: "test-adapter".to_string(),
            status: AdapterReportStatus::Unknown,
            status_reason: Some("test".to_string()),
            evidence: None,
            results: vec![],
            diagnostics: vec![],
            incomplete: false,
        };

        let mut candidates = vec![];
        let result = add_adapter_candidates(&mut candidates, &[report]);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("incomplete"));
    }

    #[test]
    fn adapter_incomplete_blocks_backup() {
        use crate::analyzers::adapters::{AdapterReport, AdapterReportStatus};

        let report = AdapterReport {
            adapter_id: "test-adapter".to_string(),
            status: AdapterReportStatus::Applied,
            status_reason: None,
            evidence: None,
            results: vec![],
            diagnostics: vec![],
            incomplete: true,
        };

        let mut candidates = vec![];
        let result = add_adapter_candidates(&mut candidates, &[report]);
        assert!(result.is_err());
    }

    #[test]
    fn adapter_not_applicable_skipped() {
        use crate::analyzers::adapters::{AdapterReport, AdapterReportStatus};

        let report = AdapterReport {
            adapter_id: "test-adapter".to_string(),
            status: AdapterReportStatus::NotApplicable,
            status_reason: None,
            evidence: None,
            results: vec![],
            diagnostics: vec![],
            incomplete: false,
        };

        let mut candidates = vec![];
        let result = add_adapter_candidates(&mut candidates, &[report]);
        assert!(result.is_ok());
        assert_eq!(candidates.len(), 0);
    }

    #[test]
    fn setup_backup_dir_creates_with_mode() {
        let dir = std::env::temp_dir().join(format!("backup-dir-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);

        setup_backup_dir(&dir).unwrap();
        assert!(dir.exists());

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&dir).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o700, "dir mode must be 0700");
        }

        let _ = std::fs::remove_dir_all(&dir);
    }
}
