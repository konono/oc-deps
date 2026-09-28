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
    pub candidate_set_sha256: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub cleanup_contract_observations: Vec<CleanupContractObservation>,
}

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

/// Structured record for adapter targets that were TargetMissing.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CleanupContractObservation {
    pub adapter_id: String,
    pub group: String,
    pub version: String,
    pub kind: String,
    pub namespace: Option<String>,
    pub name: String,
    pub resolution: String,
    pub evidence: String,
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
    /// SHA-256 of the sorted backup candidate UIDs — binds receipt to the
    /// exact final plan target set (including overrides).
    pub candidate_set_sha256: String,
}

// ──────────────────────────────────────────────────────────────
//  Candidate extraction — fail closed on missing UIDs
// ──────────────────────────────────────────────────────────────

#[derive(Clone, Debug)]
pub struct BackupCandidate {
    pub identity: BackupResourceIdentity,
    pub sources: Vec<BackupSource>,
}

/// Extract backup candidates from the final plan.
/// Returns Err if any Delete/Expect/Wait action has missing or empty UID.
pub fn extract_candidates(plan: &TeardownPlan) -> Result<Vec<BackupCandidate>> {
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
                _ => {
                    bail!(
                        "Backup candidate {}/{} (phase {}, action {}) has missing or empty UID — \
                         backup cannot proceed",
                        rid.kind,
                        rid.name,
                        phase_idx + 1,
                        action_name,
                    );
                }
            };

            let identity = BackupResourceIdentity::from_resource_id(rid, uid);
            let source = BackupSource::PlanAction {
                phase: (phase_idx + 1) as u32,
                action: action_name.to_string(),
                reason: reason.to_string(),
            };

            match by_uid.get(uid) {
                Some(existing) if existing.identity != identity => {
                    bail!(
                        "Backup candidate UID {} has conflicting identity: \
                         {}/{} vs {}/{} — backup cannot proceed",
                        uid,
                        existing.identity.kind,
                        existing.identity.name,
                        identity.kind,
                        identity.name,
                    );
                }
                _ => {}
            }

            by_uid
                .entry(uid.clone())
                .and_modify(|c| {
                    if !c.sources.contains(&source) {
                        c.sources.push(source.clone());
                    }
                })
                .or_insert_with(|| BackupCandidate {
                    identity,
                    sources: vec![source],
                });
        }
    }

    // Sort sources for deterministic output
    let mut result: Vec<BackupCandidate> = by_uid.into_values().collect();
    for c in &mut result {
        c.sources.sort();
        c.sources.dedup();
    }
    Ok(result)
}

pub fn add_adapter_candidates(
    candidates: &mut Vec<BackupCandidate>,
    reports: &[crate::analyzers::adapters::AdapterReport],
    observations: &mut Vec<CleanupContractObservation>,
) -> Result<()> {
    use crate::analyzers::adapters::{AdapterReportStatus, AdapterResolution};

    for report in reports {
        if report.status == AdapterReportStatus::NotApplicable {
            continue;
        }

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

                    // Full identity + UID dedup with conflict check
                    if let Some(existing) = candidates.iter_mut().find(|c| c.identity.uid == uid) {
                        if existing.identity != identity {
                            bail!(
                                "Adapter {} cleanup target UID {} has conflicting identity: \
                                 {}/{} vs {}/{}",
                                report.adapter_id,
                                uid,
                                existing.identity.kind,
                                existing.identity.name,
                                identity.kind,
                                identity.name,
                            );
                        }
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
                    observations.push(CleanupContractObservation {
                        adapter_id: report.adapter_id.clone(),
                        group: result.resource.id.group.clone(),
                        version: result.resource.id.version.clone(),
                        kind: result.resource.id.kind.clone(),
                        namespace: result.resource.id.namespace.clone(),
                        name: result.resource.id.name.clone(),
                        resolution: "TargetMissing".to_string(),
                        evidence: result.adapter_evidence.adapter_id.clone(),
                    });
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

/// Compute SHA-256 of sorted full candidate identities for receipt binding.
pub fn candidate_set_hash(candidates: &[BackupCandidate]) -> String {
    let mut keys: Vec<String> = candidates
        .iter()
        .map(|c| {
            format!(
                "{}/{}/{}/{}/{}/{}",
                c.identity.group,
                c.identity.version,
                c.identity.kind,
                c.identity.namespace.as_deref().unwrap_or("-"),
                c.identity.name,
                c.identity.uid,
            )
        })
        .collect();
    keys.sort();
    compute_sha256(keys.join("\n").as_bytes())
}

/// Recompute candidate set hash from bundle resources for validation.
pub fn candidate_set_hash_from_resources(resources: &[BackupResource]) -> String {
    let mut keys: Vec<String> = resources
        .iter()
        .map(|r| {
            format!(
                "{}/{}/{}/{}/{}/{}",
                r.identity.group,
                r.identity.version,
                r.identity.kind,
                r.identity.namespace.as_deref().unwrap_or("-"),
                r.identity.name,
                r.identity.uid,
            )
        })
        .collect();
    keys.sort();
    compute_sha256(keys.join("\n").as_bytes())
}

/// Compute SHA-256 of the final TeardownPlan for bundle/receipt binding.
/// Used identically at creation and resume to ensure hash match.
pub fn bound_plan_sha256(plan: &TeardownPlan) -> Result<String> {
    let bytes =
        serde_json::to_vec(plan).context("Failed to serialize TeardownPlan for bound hash")?;
    Ok(compute_sha256(&bytes))
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

    if manifest.as_object_mut().unwrap().remove("status").is_some() {
        omitted.push(OmittedField {
            path: "status".to_string(),
            reason: "server-managed lifecycle field".to_string(),
        });
    }

    if let Some(metadata) = manifest
        .pointer_mut("/metadata")
        .and_then(|v| v.as_object_mut())
    {
        for field in SERVER_METADATA_FIELDS {
            if metadata.remove(*field).is_some() {
                omitted.push(OmittedField {
                    path: format!("metadata.{}", field),
                    reason: "server-managed lifecycle field".to_string(),
                });
            }
        }

        if metadata.contains_key("name") && metadata.remove("generateName").is_some() {
            omitted.push(OmittedField {
                path: "metadata.generateName".to_string(),
                reason: "name is set; generateName is unused".to_string(),
            });
        }

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
//  Live identity validation
// ──────────────────────────────────────────────────────────────

fn split_api_version(api_version: &str) -> (&str, &str) {
    match api_version.rsplit_once('/') {
        Some((group, version)) => (group, version),
        None => ("", api_version),
    }
}

fn validate_live_identity(
    candidate: &BackupCandidate,
    obj: &kube::api::DynamicObject,
) -> Result<()> {
    let tm = obj
        .types
        .as_ref()
        .context("GET response missing apiVersion/kind (TypeMeta)")?;
    let (group, version) = split_api_version(&tm.api_version);
    if group != candidate.identity.group {
        bail!(
            "group mismatch for {}/{}: expected {:?} got {:?}",
            candidate.identity.kind,
            candidate.identity.name,
            candidate.identity.group,
            group,
        );
    }
    if version != candidate.identity.version {
        bail!(
            "version mismatch for {}/{}: expected {:?} got {:?}",
            candidate.identity.kind,
            candidate.identity.name,
            candidate.identity.version,
            version,
        );
    }
    if tm.kind != candidate.identity.kind {
        bail!(
            "kind mismatch for {}/{}: expected {:?} got {:?}",
            candidate.identity.kind,
            candidate.identity.name,
            candidate.identity.kind,
            tm.kind,
        );
    }
    if obj.metadata.name.as_deref() != Some(candidate.identity.name.as_str()) {
        bail!(
            "name mismatch: expected {:?} got {:?}",
            candidate.identity.name,
            obj.metadata.name,
        );
    }
    if obj.metadata.namespace != candidate.identity.namespace {
        bail!(
            "namespace mismatch for {}/{}: expected {:?} got {:?}",
            candidate.identity.kind,
            candidate.identity.name,
            candidate.identity.namespace,
            obj.metadata.namespace,
        );
    }
    let live_uid = obj.metadata.uid.as_deref().unwrap_or("");
    if live_uid != candidate.identity.uid {
        bail!(
            "UID mismatch for {}/{}: expected {} got {}",
            candidate.identity.kind,
            candidate.identity.name,
            candidate.identity.uid,
            live_uid,
        );
    }
    Ok(())
}

// ──────────────────────────────────────────────────────────────
//  Fetch candidates from cluster — uses get_with_retry + GvkMap
// ──────────────────────────────────────────────────────────────

pub async fn fetch_backup_resources(
    client: &kube::Client,
    candidates: &[BackupCandidate],
    gvk_map: &crate::kube::discovery::GvkMap,
) -> Result<(Vec<BackupResource>, bool)> {
    use kube::api::{Api, ApiResource, DynamicObject};

    let mut resources = Vec::new();
    let mut contains_secrets = false;

    for candidate in candidates {
        // Exact served GVK validation — no fallback to preferred version
        let gvk_key = (
            candidate.identity.group.clone(),
            candidate.identity.version.clone(),
            candidate.identity.kind.clone(),
        );
        let info = match gvk_map.get(&gvk_key) {
            Some(i) => i,
            None => {
                bail!(
                    "Exact GVK ({}/{}/{}) not served by cluster — \
                     backup cannot proceed. Re-run teardown plan.",
                    candidate.identity.group,
                    candidate.identity.version,
                    candidate.identity.kind,
                );
            }
        };

        let gvk = kube::api::GroupVersionKind {
            group: info.group.clone(),
            version: info.version.clone(),
            kind: candidate.identity.kind.clone(),
        };
        let ar = ApiResource::from_gvk_with_plural(&gvk, &info.plural);

        let api: Api<DynamicObject> = if let Some(ref ns) = candidate.identity.namespace {
            Api::namespaced_with(client.clone(), ns, &ar)
        } else if info.namespaced {
            bail!(
                "Resource {}/{} is namespaced but has no namespace in candidate — \
                 backup cannot proceed",
                candidate.identity.kind,
                candidate.identity.name,
            );
        } else {
            Api::all_with(client.clone(), &ar)
        };

        match crate::kube::scanner::get_with_retry(
            &api,
            &candidate.identity.name,
            &info.group,
            &info.version,
            &info.plural,
        )
        .await
        {
            Ok(obj) => {
                validate_live_identity(candidate, &obj)
                    .context("live identity validation failed — backup cannot proceed")?;

                let raw = serde_json::to_value(&obj)?;
                if candidate.identity.kind == "Secret" {
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
            Err(w) if w.is_not_found() => {
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
            Err(w) => {
                bail!(
                    "Failed to GET {}/{}: {} — \
                     backup cannot proceed (no partial backups)",
                    candidate.identity.kind,
                    candidate.identity.name,
                    w,
                );
            }
        }
    }

    resources.sort_by(|a, b| a.identity.cmp(&b.identity));
    Ok((resources, contains_secrets))
}

// ──────────────────────────────────────────────────────────────
//  Build bundle
// ──────────────────────────────────────────────────────────────

#[allow(clippy::too_many_arguments)]
pub fn build_bundle(
    resources: Vec<BackupResource>,
    cluster_identity: &ClusterIdentity,
    plan_sha256: &str,
    plan_path: &str,
    operator_names: Vec<String>,
    contains_secret_data: bool,
    adapter_incomplete: Vec<String>,
    observations: Vec<CleanupContractObservation>,
    candidate_set_sha256: String,
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
        candidate_set_sha256,
        cleanup_contract_observations: observations,
    }
}

// ──────────────────────────────────────────────────────────────
//  Atomic write — P0 security: 0600 from creation, no-clobber
//  fail closed, readback guard
// ──────────────────────────────────────────────────────────────

pub fn compute_sha256(data: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(data);
    format!("{:x}", hasher.finalize())
}

/// Hash the raw execution plan file for provenance tracking (not used for receipt binding).
#[allow(dead_code)]
pub fn compute_plan_sha256(plan_path: &str) -> Result<String> {
    let data = std::fs::read(plan_path)
        .with_context(|| format!("Failed to read plan file for SHA-256: {}", plan_path))?;
    Ok(compute_sha256(&data))
}

static BACKUP_COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

pub fn write_backup_bundle(bundle: &BackupBundle, target: &Path) -> Result<BackupReceipt> {
    use std::io::Write;

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

    let json = serde_json::to_string_pretty(bundle)?;
    let json_bytes = json.as_bytes();
    let expected_sha = compute_sha256(json_bytes);

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

    let mut tmp_guard = TempGuard {
        path: tmp_path.clone(),
        armed: true,
    };

    // Create temp with 0600 from the start via OpenOptions
    {
        #[cfg(unix)]
        let f = {
            use std::os::unix::fs::OpenOptionsExt;
            std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(&tmp_path)
                .with_context(|| format!("Failed to create temp backup: {}", tmp_path.display()))?
        };
        #[cfg(not(unix))]
        let f = std::fs::File::create_new(&tmp_path)
            .with_context(|| format!("Failed to create temp backup: {}", tmp_path.display()))?;

        let mut f = f;
        f.write_all(json_bytes)?;
        f.sync_all()?;
    }

    // No-clobber publish via hard_link (Unix). If hard_link fails, fail closed —
    // do NOT fall back to rename which can overwrite.
    #[cfg(unix)]
    {
        std::fs::hard_link(&tmp_path, target).with_context(|| {
            format!(
                "Failed to publish backup (no-clobber link): {} → {}",
                tmp_path.display(),
                target.display()
            )
        })?;
        // link succeeded — remove temp (propagate error to avoid Secret-bearing residue)
        std::fs::remove_file(&tmp_path).with_context(|| {
            format!(
                "Failed to remove temp backup {} — Secret-bearing copy may remain",
                tmp_path.display()
            )
        })?;
        tmp_guard.disarm();
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
        tmp_guard.disarm();
    }

    // Target guard: if readback/hash/parse fails, remove the published file
    struct TargetGuard {
        path: PathBuf,
        armed: bool,
    }
    impl TargetGuard {
        fn disarm(&mut self) {
            self.armed = false;
        }
    }
    impl Drop for TargetGuard {
        fn drop(&mut self) {
            if self.armed {
                let _ = std::fs::remove_file(&self.path);
            }
        }
    }
    let mut target_guard = TargetGuard {
        path: target.to_path_buf(),
        armed: true,
    };

    // Verify mode 0600
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let meta = std::fs::metadata(target)
            .with_context(|| format!("Failed to stat backup: {}", target.display()))?;
        let mode = meta.permissions().mode() & 0o777;
        if mode != 0o600 {
            bail!(
                "Backup file {} has mode {:o}, expected 0600 — backup rejected",
                target.display(),
                mode,
            );
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

    let _: BackupBundle = serde_json::from_slice(&readback)
        .with_context(|| "Backup readback parse failed — file is corrupted")?;

    // fsync parent directory for crash consistency — must succeed before receipt
    let dir_fd = std::fs::File::open(parent)
        .with_context(|| format!("Failed to open backup directory {}", parent.display()))?;
    dir_fd
        .sync_all()
        .with_context(|| format!("Failed to fsync backup directory {}", parent.display()))?;

    // All verification + durability passed — disarm target guard
    target_guard.disarm();

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
        candidate_set_sha256: bundle.candidate_set_sha256.clone(),
    })
}

// ──────────────────────────────────────────────────────────────
//  Backup dir setup — propagate chmod errors
// ──────────────────────────────────────────────────────────────

pub fn setup_backup_dir(dir: &Path) -> Result<()> {
    if !dir.exists() {
        std::fs::create_dir_all(dir)
            .with_context(|| format!("Failed to create backup dir: {}", dir.display()))?;
    }

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700))
            .with_context(|| format!("Failed to set backup dir mode 0700: {}", dir.display()))?;
        // Re-stat to verify
        let meta = std::fs::metadata(dir)?;
        let mode = meta.permissions().mode() & 0o777;
        if mode != 0o700 {
            bail!(
                "Backup dir {} has mode {:o} after chmod, expected 0700",
                dir.display(),
                mode,
            );
        }
    }

    Ok(())
}

pub fn batch_backup_path(dir: &Path, index: usize, operator_name: &str) -> PathBuf {
    dir.join(format!("{:02}-{}.backup.json", index, operator_name))
}

// ──────────────────────────────────────────────────────────────
//  Receipt validation (for resume)
// ──────────────────────────────────────────────────────────────

pub fn validate_receipt(
    receipt: &BackupReceipt,
    current_cluster: &ClusterIdentity,
    bound_plan_sha: &str,
) -> Result<()> {
    let path = Path::new(&receipt.path);
    if !path.exists() {
        bail!(
            "Backup file {} no longer exists — cannot resume mutation",
            receipt.path,
        );
    }

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

    // Cross-validate all duplicated receipt fields against parsed bundle
    if bundle.execution_plan_sha256 != bound_plan_sha {
        bail!(
            "Backup plan SHA-256 mismatch: bundle {} does not match current plan {}",
            bundle.execution_plan_sha256,
            bound_plan_sha,
        );
    }

    if receipt.execution_plan_sha256 != bundle.execution_plan_sha256 {
        bail!(
            "Receipt/bundle plan SHA-256 mismatch: receipt {} vs bundle {}",
            receipt.execution_plan_sha256,
            bundle.execution_plan_sha256,
        );
    }

    if receipt.candidate_set_sha256 != bundle.candidate_set_sha256 {
        bail!(
            "Receipt/bundle candidate set hash mismatch: receipt {} vs bundle {}",
            receipt.candidate_set_sha256,
            bundle.candidate_set_sha256,
        );
    }

    // Recompute candidate set hash from bundle resources
    let recomputed = candidate_set_hash_from_resources(&bundle.resources);
    if recomputed != bundle.candidate_set_sha256 {
        bail!(
            "Candidate set hash verification failed: bundle {} vs recomputed {}",
            bundle.candidate_set_sha256,
            recomputed,
        );
    }

    if receipt.resource_count != bundle.resources.len() {
        bail!(
            "Resource count mismatch: receipt {} vs bundle {}",
            receipt.resource_count,
            bundle.resources.len(),
        );
    }

    if receipt.contains_secret_data != bundle.contains_secret_data {
        bail!(
            "Secret data flag mismatch: receipt {} vs bundle {}",
            receipt.contains_secret_data,
            bundle.contains_secret_data,
        );
    }

    Ok(())
}

// ──────────────────────────────────────────────────────────────
//  prepare_backup_gate — common entry point for all apply modes
// ──────────────────────────────────────────────────────────────

pub struct BackupGateContext<'a> {
    pub client: &'a kube::Client,
    pub final_plan: &'a TeardownPlan,
    pub target_operators: Vec<&'a crate::analyzers::olm::OperatorInstance>,
    pub cluster_identity: &'a ClusterIdentity,
    pub plan_path: &'a str,
    pub gvk_map: &'a crate::kube::discovery::GvkMap,
}

pub async fn prepare_backup_gate(
    ctx: &BackupGateContext<'_>,
    backup_path: &Path,
) -> Result<BackupReceipt> {
    eprintln!("\n📦 Backup: capturing pre-delete resource state...");

    // Extract candidates from final plan (after all overrides)
    let mut candidates = extract_candidates(ctx.final_plan)?;
    eprintln!("  {} candidate(s) from plan actions", candidates.len());

    // Run adapters for cleanup-contract targets on all target operators
    let mut observations = Vec::new();
    {
        // Build root ResourceIds from plan actions for adapter discovery
        let plan_rids: Vec<ResourceId> = ctx
            .final_plan
            .phases
            .iter()
            .flat_map(|p| &p.actions)
            .filter_map(|a| match a {
                Action::Delete { resource, .. }
                | Action::ExpectGone { resource, .. }
                | Action::WaitGone { resource } => Some(resource.clone()),
                _ => None,
            })
            .collect();

        // Create synthetic InspectedResources from plan ResourceIds for root discovery
        let cr_resources: Vec<crate::analyzers::inspect::InspectedResource> = plan_rids
            .iter()
            .map(|rid| crate::analyzers::inspect::InspectedResource {
                id: rid.clone(),
                source_id: None,
                relationship: crate::analyzers::inspect::Relationship::OwnedCrdInstance,
                evidence: "plan-action".to_string(),
                confidence: crate::analyzers::inspect::Confidence::Managed,
            })
            .collect();

        // Create a fresh QueryPlanner for adapter discovery (adapters use it to
        // probe cleanup targets — the redaction is OK since we re-GET raw later)
        let planner = crate::kube::planner::QueryPlanner::new(None);

        for op in &ctx.target_operators {
            let reports = crate::analyzers::adapters::run_adapters(
                ctx.client,
                op,
                Some(&planner),
                &cr_resources,
            )
            .await;
            add_adapter_candidates(&mut candidates, &reports, &mut observations)?;
        }
    }

    eprintln!(
        "  {} total candidate(s) (including cleanup-contract)",
        candidates.len()
    );

    let candidate_hash = candidate_set_hash(&candidates);

    // Compute bound plan hash from the final TeardownPlan
    let bound_plan_sha = bound_plan_sha256(ctx.final_plan)?;

    // Fetch all candidates from cluster (exact GVK only, no fallback)
    let (resources, contains_secrets) =
        fetch_backup_resources(ctx.client, &candidates, ctx.gvk_map).await?;

    let captured = resources
        .iter()
        .filter(|r| r.state == BackupResourceState::Captured)
        .count();
    let absent = resources
        .iter()
        .filter(|r| r.state == BackupResourceState::AlreadyAbsent)
        .count();
    eprintln!("  {} captured, {} already absent", captured, absent);

    let operator_names: Vec<String> = ctx
        .target_operators
        .iter()
        .map(|op| op.csv.name.clone())
        .collect();

    let bundle = build_bundle(
        resources,
        ctx.cluster_identity,
        &bound_plan_sha,
        ctx.plan_path,
        operator_names,
        contains_secrets,
        vec![],
        observations,
        candidate_hash,
    );

    let receipt = write_backup_bundle(&bundle, backup_path)?;

    eprintln!(
        "  ✅ Backup written: {} ({} resources, SHA-256: {})",
        receipt.path,
        receipt.resource_count,
        &receipt.sha256[..12.min(receipt.sha256.len())]
    );

    Ok(receipt)
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

    fn test_cluster() -> ClusterIdentity {
        ClusterIdentity {
            api_server: "https://test".to_string(),
            kube_system_uid: "uid-ks".to_string(),
        }
    }

    fn test_bundle(resources: Vec<BackupResource>) -> BackupBundle {
        let cand_hash = candidate_set_hash_from_resources(&resources);
        build_bundle(
            resources,
            &test_cluster(),
            "sha256abc",
            "/tmp/plan.json",
            vec!["op1".to_string()],
            false,
            vec![],
            vec![],
            cand_hash,
        )
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

        let candidates = extract_candidates(&plan).unwrap();
        assert_eq!(candidates.len(), 3);
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

        let candidates = extract_candidates(&plan).unwrap();
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

        let candidates = extract_candidates(&plan).unwrap();
        assert_eq!(candidates.len(), 1);
        assert_eq!(candidates[0].sources.len(), 2);
    }

    #[test]
    fn candidate_missing_uid_hard_fail() {
        let plan = make_plan(vec![Action::Delete {
            resource: rid("Deployment", "d1", None),
            reason: "root".to_string(),
        }]);

        let result = extract_candidates(&plan);
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("missing or empty UID")
        );
    }

    #[test]
    fn candidate_empty_uid_hard_fail() {
        let plan = make_plan(vec![Action::Delete {
            resource: rid("Deployment", "d1", Some("")),
            reason: "root".to_string(),
        }]);

        let result = extract_candidates(&plan);
        assert!(result.is_err());
    }

    #[test]
    fn candidate_same_uid_different_identity_hard_fail() {
        let plan = make_plan(vec![
            Action::Delete {
                resource: ResourceId {
                    group: "".to_string(),
                    version: "v1".to_string(),
                    kind: "ConfigMap".to_string(),
                    namespace: Some("ns".to_string()),
                    name: "cm1".to_string(),
                    uid: Some("uid-conflict".to_string()),
                },
                reason: "root".to_string(),
            },
            Action::Delete {
                resource: ResourceId {
                    group: "apps".to_string(),
                    version: "v1".to_string(),
                    kind: "Deployment".to_string(),
                    namespace: Some("ns".to_string()),
                    name: "dep1".to_string(),
                    uid: Some("uid-conflict".to_string()),
                },
                reason: "root".to_string(),
            },
        ]);

        let result = extract_candidates(&plan);
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("conflicting identity")
        );
    }

    #[test]
    fn candidate_same_uid_same_identity_merges() {
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

        let candidates = extract_candidates(&plan).unwrap();
        assert_eq!(candidates.len(), 1);
        assert_eq!(candidates[0].sources.len(), 2);
    }

    #[test]
    fn target_missing_recorded_in_observations() {
        use crate::analyzers::adapters::*;
        use crate::analyzers::inspect::*;

        let report = AdapterReport {
            adapter_id: "test-adapter".to_string(),
            status: AdapterReportStatus::Applied,
            status_reason: None,
            evidence: None,
            results: vec![AdapterResult {
                resource: InspectedResource {
                    id: ResourceId {
                        group: "security.openshift.io".to_string(),
                        version: "v1".to_string(),
                        kind: "SecurityContextConstraints".to_string(),
                        namespace: None,
                        name: "nfd-worker".to_string(),
                        uid: None,
                    },
                    source_id: None,
                    relationship: Relationship::CleansUp,
                    evidence: "cleanup".to_string(),
                    confidence: Confidence::Managed,
                },
                resolution: AdapterResolution::TargetMissing,
                adapter_evidence: AdapterEvidence {
                    adapter_id: "test-adapter".to_string(),
                    source_commit: "abc".to_string(),
                    source_url: "url".to_string(),
                    cleanup_function: "fn".to_string(),
                    naming_function: "fn".to_string(),
                    matched_csv_version: "v1".to_string(),
                    binding_note: None,
                },
            }],
            diagnostics: vec![],
            incomplete: false,
        };

        let mut candidates = vec![];
        let mut observations = vec![];
        let result = add_adapter_candidates(&mut candidates, &[report], &mut observations);
        assert!(result.is_ok());
        assert_eq!(candidates.len(), 0);
        assert_eq!(observations.len(), 1);
        assert_eq!(observations[0].resolution, "TargetMissing");
        assert_eq!(observations[0].name, "nfd-worker");
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

        assert!(manifest.pointer("/metadata/uid").is_none());
        assert!(manifest.pointer("/metadata/resourceVersion").is_none());
        assert!(manifest.pointer("/status").is_none());
        assert_eq!(manifest.pointer("/metadata/name").unwrap(), "test");
        assert_eq!(manifest.pointer("/data/key").unwrap(), "value");
        assert!(deferred.owner_references.is_empty());
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

        let (manifest, deferred, _) = sanitize_for_recreate(&raw);
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
            "metadata": {"name": "pod-abc", "generateName": "pod-"},
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
            "metadata": {"generateName": "pod-"},
        });

        let (manifest, _, _) = sanitize_for_recreate(&raw);
        assert_eq!(manifest.pointer("/metadata/generateName").unwrap(), "pod-");
    }

    #[test]
    fn sanitize_preserves_unknown_cr_fields() {
        let raw = serde_json::json!({
            "apiVersion": "example.io/v1",
            "kind": "Widget",
            "metadata": {"name": "w1", "uid": "uid-1", "resourceVersion": "999"},
            "spec": {"replicas": 3, "template": {"custom": true}},
            "data": {"secret-key": "secret-value"},
        });

        let (manifest, _, _) = sanitize_for_recreate(&raw);
        assert_eq!(manifest.pointer("/spec/replicas").unwrap(), 3);
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
            "metadata": {"name": "my-secret", "uid": "uid-s", "resourceVersion": "100"},
            "data": {"password": "c2VjcmV0"},
            "stringData": {"api-key": "abc123"},
        });

        let (manifest, _, _) = sanitize_for_recreate(&raw);
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
            "Debug must not contain Secret data"
        );
    }

    #[test]
    fn bundle_debug_no_secrets() {
        let bundle = test_bundle(vec![]);
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

        let bundle = test_bundle(vec![]);
        let result = write_backup_bundle(&bundle, &target);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("already exists"));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn write_roundtrip_and_mode() {
        let dir = std::env::temp_dir().join(format!("backup-rt-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let target = dir.join("backup.json");

        let bundle = test_bundle(vec![]);
        let receipt = write_backup_bundle(&bundle, &target).unwrap();

        assert_eq!(receipt.resource_count, 0);
        assert!(!receipt.contains_secret_data);

        let data = std::fs::read(&target).unwrap();
        let sha = compute_sha256(&data);
        assert_eq!(receipt.sha256, sha);

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&target).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o600, "file mode must be 0600");
        }

        let loaded: BackupBundle = serde_json::from_slice(&data).unwrap();
        assert_eq!(loaded.schema_version, 1);

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn write_cleans_temp_on_failure() {
        let bundle = test_bundle(vec![]);
        let result = write_backup_bundle(&bundle, Path::new("/nonexistent/dir/backup.json"));
        assert!(result.is_err());
    }

    #[test]
    fn concurrent_same_target_one_success() {
        let dir = std::env::temp_dir().join(format!("backup-conc-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let target = dir.join("backup.json");

        let handles: Vec<_> = (0..4)
            .map(|_| {
                let _dir = dir.clone();
                let target = target.clone();
                std::thread::spawn(move || {
                    let bundle = build_bundle(
                        vec![],
                        &ClusterIdentity {
                            api_server: "https://test".to_string(),
                            kube_system_uid: "uid-ks".to_string(),
                        },
                        "sha",
                        "/tmp/plan.json",
                        vec![],
                        false,
                        vec![],
                        vec![],
                        "cand".to_string(),
                    );
                    write_backup_bundle(&bundle, &target)
                })
            })
            .collect();

        let results: Vec<_> = handles.into_iter().map(|h| h.join().unwrap()).collect();
        let successes = results.iter().filter(|r| r.is_ok()).count();
        assert_eq!(
            successes, 1,
            "exactly 1 success expected, got {}",
            successes
        );
        assert!(target.exists(), "target file must exist after 1 success");
        let data = std::fs::read(&target).unwrap();
        let loaded: BackupBundle = serde_json::from_slice(&data).unwrap();
        assert_eq!(loaded.schema_version, BACKUP_SCHEMA_VERSION);
        // No temp residuals
        let tmps: Vec<_> = std::fs::read_dir(&dir)
            .unwrap()
            .filter_map(|e| e.ok())
            .filter(|e| {
                e.file_name()
                    .to_str()
                    .is_some_and(|n| n.starts_with(".tmp_"))
            })
            .collect();
        assert_eq!(tmps.len(), 0, "no temp residuals");
        let _ = std::fs::remove_dir_all(&dir);
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
                &test_cluster(),
                "sha256abc",
                "/tmp/plan.json",
                vec!["op1".to_string()],
                false,
                vec![],
                vec![],
                "fixed-cand-hash".to_string(),
            )
        };

        let b1 = make_bundle();
        let b2 = make_bundle();
        let j1 = serde_json::to_string_pretty(&b1).unwrap();
        let j2 = serde_json::to_string_pretty(&b2).unwrap();
        let strip = |s: &str| -> String {
            s.lines()
                .filter(|l| !l.contains("created_at"))
                .collect::<Vec<_>>()
                .join("\n")
        };
        assert_eq!(strip(&j1), strip(&j2));
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
            candidate_set_sha256: "cand-sha".to_string(),
        };
        let json = serde_json::to_string(&receipt).unwrap();
        let loaded: BackupReceipt = serde_json::from_str(&json).unwrap();
        assert_eq!(loaded.sha256, "abc123");
        assert_eq!(loaded.candidate_set_sha256, "cand-sha");
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
            candidate_set_sha256: "c".to_string(),
        };
        let result = validate_receipt(&receipt, &test_cluster(), "p");
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("no longer exists"));
    }

    #[test]
    fn validate_receipt_tampered() {
        let dir = std::env::temp_dir().join(format!("receipt-tamper-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("backup.json");

        let bundle = test_bundle(vec![]);
        let receipt = write_backup_bundle(&bundle, &path).unwrap();
        std::fs::write(&path, "{}").unwrap();

        let result = validate_receipt(&receipt, &test_cluster(), "sha256abc");
        assert!(result.is_err());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn validate_receipt_cluster_mismatch() {
        let dir = std::env::temp_dir().join(format!("receipt-cluster-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("backup.json");

        let bundle = test_bundle(vec![]);
        let receipt = write_backup_bundle(&bundle, &path).unwrap();

        let wrong_cluster = ClusterIdentity {
            api_server: "https://other".to_string(),
            kube_system_uid: "uid-other".to_string(),
        };
        let result = validate_receipt(&receipt, &wrong_cluster, "sha256abc");
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
        let mut observations = vec![];
        let result = add_adapter_candidates(&mut candidates, &[report], &mut observations);
        assert!(result.is_err());
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
        let mut observations = vec![];
        let result = add_adapter_candidates(&mut candidates, &[report], &mut observations);
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
        let mut observations = vec![];
        let result = add_adapter_candidates(&mut candidates, &[report], &mut observations);
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

    #[test]
    fn candidate_set_hash_deterministic() {
        let c1 = BackupCandidate {
            identity: BackupResourceIdentity {
                group: "".to_string(),
                version: "v1".to_string(),
                kind: "ConfigMap".to_string(),
                namespace: Some("ns".to_string()),
                name: "cm1".to_string(),
                uid: "uid-b".to_string(),
            },
            sources: vec![],
        };
        let c2 = BackupCandidate {
            identity: BackupResourceIdentity {
                group: "".to_string(),
                version: "v1".to_string(),
                kind: "Secret".to_string(),
                namespace: Some("ns".to_string()),
                name: "s1".to_string(),
                uid: "uid-a".to_string(),
            },
            sources: vec![],
        };

        // Order should not matter — hash sorts internally
        let h1 = candidate_set_hash(&[c1.clone(), c2.clone()]);
        let h2 = candidate_set_hash(&[c2, c1]);
        assert_eq!(h1, h2);
    }

    #[test]
    fn bound_plan_sha256_roundtrip() {
        let plan = make_plan(vec![Action::Delete {
            resource: rid("Deployment", "d1", Some("uid-1")),
            reason: "root".to_string(),
        }]);
        let h1 = bound_plan_sha256(&plan).unwrap();
        let h2 = bound_plan_sha256(&plan).unwrap();
        assert_eq!(h1, h2, "same plan must produce same hash");
        assert!(!h1.is_empty());
    }

    #[test]
    fn bound_plan_sha256_differs_after_override() {
        let mut plan = make_plan(vec![
            Action::Delete {
                resource: rid("Deployment", "d1", Some("uid-1")),
                reason: "root".to_string(),
            },
            Action::Review {
                resource: rid("ConfigMap", "cm1", Some("uid-2")),
                reason: "label".to_string(),
                metadata: None,
            },
        ]);
        let h1 = bound_plan_sha256(&plan).unwrap();

        // Simulate TUI override: Review → Delete
        plan.phases[0].actions[1] = Action::Delete {
            resource: rid("ConfigMap", "cm1", Some("uid-2")),
            reason: "approved via TUI".to_string(),
        };
        let h2 = bound_plan_sha256(&plan).unwrap();
        assert_ne!(h1, h2, "override must change plan hash");
    }

    #[test]
    fn validate_receipt_plan_hash_mismatch_fails() {
        let dir = std::env::temp_dir().join(format!("hash-mm-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("backup.json");

        let bundle = test_bundle(vec![]);
        let receipt = write_backup_bundle(&bundle, &path).unwrap();

        // Validate with a different plan hash
        let result = validate_receipt(&receipt, &test_cluster(), "wrong-plan-hash");
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("plan SHA-256"));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn validate_receipt_candidate_hash_cross_validated() {
        let dir = std::env::temp_dir().join(format!("cand-xv-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("backup.json");

        let bundle = test_bundle(vec![]);
        let receipt = write_backup_bundle(&bundle, &path).unwrap();

        // Receipt has candidate_set_sha256 from bundle — validate succeeds
        let result = validate_receipt(&receipt, &test_cluster(), "sha256abc");
        assert!(result.is_ok());

        // Tamper receipt candidate hash
        let mut bad_receipt = receipt.clone();
        bad_receipt.candidate_set_sha256 = "tampered".to_string();
        let result = validate_receipt(&bad_receipt, &test_cluster(), "sha256abc");
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("candidate set hash")
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn validate_receipt_resource_count_mismatch_fails() {
        let dir = std::env::temp_dir().join(format!("rcount-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("backup.json");

        let bundle = test_bundle(vec![]);
        let receipt = write_backup_bundle(&bundle, &path).unwrap();

        let mut bad_receipt = receipt;
        bad_receipt.resource_count = 999;
        let result = validate_receipt(&bad_receipt, &test_cluster(), "sha256abc");
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("Resource count"));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn validate_receipt_secret_flag_mismatch_fails() {
        let dir = std::env::temp_dir().join(format!("sflag-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("backup.json");

        let bundle = test_bundle(vec![]);
        let receipt = write_backup_bundle(&bundle, &path).unwrap();

        let mut bad_receipt = receipt;
        bad_receipt.contains_secret_data = true;
        let result = validate_receipt(&bad_receipt, &test_cluster(), "sha256abc");
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("Secret data flag"));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn validate_receipt_plan_sha_mismatch_in_receipt_fails() {
        let dir = std::env::temp_dir().join(format!("psha-mm-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("backup.json");

        let bundle = test_bundle(vec![]);
        let receipt = write_backup_bundle(&bundle, &path).unwrap();

        let mut bad_receipt = receipt;
        bad_receipt.execution_plan_sha256 = "tampered".to_string();
        let result = validate_receipt(&bad_receipt, &test_cluster(), "sha256abc");
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("plan SHA-256"));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn candidate_set_hash_uses_full_identity() {
        let c1 = BackupCandidate {
            identity: BackupResourceIdentity {
                group: "apps".to_string(),
                version: "v1".to_string(),
                kind: "Deployment".to_string(),
                namespace: Some("ns".to_string()),
                name: "dep1".to_string(),
                uid: "uid-1".to_string(),
            },
            sources: vec![],
        };
        let c2 = BackupCandidate {
            identity: BackupResourceIdentity {
                group: "".to_string(),
                version: "v1".to_string(),
                kind: "ConfigMap".to_string(),
                namespace: Some("ns".to_string()),
                name: "cm1".to_string(),
                uid: "uid-1".to_string(), // same UID, different identity
            },
            sources: vec![],
        };

        let h1 = candidate_set_hash(std::slice::from_ref(&c1));
        let h2 = candidate_set_hash(std::slice::from_ref(&c2));
        // Same UID but different group/kind → different hash
        assert_ne!(
            h1, h2,
            "full identity hash must differ when group/kind differ"
        );
    }

    #[test]
    fn bundle_contains_candidate_set_hash() {
        let bundle = test_bundle(vec![]);
        assert!(!bundle.candidate_set_sha256.is_empty());
        let json = serde_json::to_string(&bundle).unwrap();
        assert!(json.contains("candidate_set_sha256"));
        let recomputed = candidate_set_hash_from_resources(&bundle.resources);
        assert_eq!(bundle.candidate_set_sha256, recomputed);
    }

    // ── Identity validation tests ──

    fn make_candidate(
        group: &str,
        version: &str,
        kind: &str,
        ns: Option<&str>,
        name: &str,
        uid: &str,
    ) -> BackupCandidate {
        BackupCandidate {
            identity: BackupResourceIdentity {
                group: group.to_string(),
                version: version.to_string(),
                kind: kind.to_string(),
                namespace: ns.map(|s| s.to_string()),
                name: name.to_string(),
                uid: uid.to_string(),
            },
            sources: vec![],
        }
    }

    fn make_dyn_obj(
        api_version: &str,
        kind: &str,
        ns: Option<&str>,
        name: &str,
        uid: &str,
    ) -> kube::api::DynamicObject {
        kube::api::DynamicObject {
            types: Some(kube::api::TypeMeta {
                api_version: api_version.to_string(),
                kind: kind.to_string(),
            }),
            metadata: kube::core::ObjectMeta {
                name: Some(name.to_string()),
                namespace: ns.map(|s| s.to_string()),
                uid: Some(uid.to_string()),
                ..Default::default()
            },
            data: serde_json::json!({}),
        }
    }

    #[test]
    fn validate_identity_all_match() {
        let c = make_candidate("apps", "v1", "Deployment", Some("ns"), "dep1", "uid-1");
        let obj = make_dyn_obj("apps/v1", "Deployment", Some("ns"), "dep1", "uid-1");
        assert!(validate_live_identity(&c, &obj).is_ok());
    }

    #[test]
    fn validate_identity_core_group() {
        let c = make_candidate("", "v1", "ConfigMap", Some("ns"), "cm1", "uid-1");
        let obj = make_dyn_obj("v1", "ConfigMap", Some("ns"), "cm1", "uid-1");
        assert!(validate_live_identity(&c, &obj).is_ok());
    }

    #[test]
    fn validate_identity_wrong_group() {
        let c = make_candidate("apps", "v1", "Deployment", Some("ns"), "dep1", "uid-1");
        let obj = make_dyn_obj(
            "extensions/v1beta1",
            "Deployment",
            Some("ns"),
            "dep1",
            "uid-1",
        );
        let err = validate_live_identity(&c, &obj).unwrap_err().to_string();
        assert!(err.contains("group mismatch"), "err: {}", err);
    }

    #[test]
    fn validate_identity_wrong_version() {
        let c = make_candidate("apps", "v1", "Deployment", Some("ns"), "dep1", "uid-1");
        let obj = make_dyn_obj("apps/v1beta1", "Deployment", Some("ns"), "dep1", "uid-1");
        let err = validate_live_identity(&c, &obj).unwrap_err().to_string();
        assert!(err.contains("version mismatch"), "err: {}", err);
    }

    #[test]
    fn validate_identity_wrong_kind() {
        let c = make_candidate("apps", "v1", "Deployment", Some("ns"), "dep1", "uid-1");
        let obj = make_dyn_obj("apps/v1", "StatefulSet", Some("ns"), "dep1", "uid-1");
        let err = validate_live_identity(&c, &obj).unwrap_err().to_string();
        assert!(err.contains("kind mismatch"), "err: {}", err);
    }

    #[test]
    fn validate_identity_wrong_name() {
        let c = make_candidate("apps", "v1", "Deployment", Some("ns"), "dep1", "uid-1");
        let obj = make_dyn_obj("apps/v1", "Deployment", Some("ns"), "other", "uid-1");
        let err = validate_live_identity(&c, &obj).unwrap_err().to_string();
        assert!(err.contains("name mismatch"), "err: {}", err);
    }

    #[test]
    fn validate_identity_wrong_namespace() {
        let c = make_candidate("apps", "v1", "Deployment", Some("ns"), "dep1", "uid-1");
        let obj = make_dyn_obj("apps/v1", "Deployment", Some("other-ns"), "dep1", "uid-1");
        let err = validate_live_identity(&c, &obj).unwrap_err().to_string();
        assert!(err.contains("namespace mismatch"), "err: {}", err);
    }

    #[test]
    fn validate_identity_wrong_uid() {
        let c = make_candidate("apps", "v1", "Deployment", Some("ns"), "dep1", "uid-1");
        let obj = make_dyn_obj("apps/v1", "Deployment", Some("ns"), "dep1", "uid-2");
        let err = validate_live_identity(&c, &obj).unwrap_err().to_string();
        assert!(err.contains("UID mismatch"), "err: {}", err);
    }

    #[test]
    fn validate_identity_missing_type_meta() {
        let c = make_candidate("apps", "v1", "Deployment", Some("ns"), "dep1", "uid-1");
        let obj = kube::api::DynamicObject {
            types: None,
            metadata: kube::core::ObjectMeta {
                name: Some("dep1".to_string()),
                namespace: Some("ns".to_string()),
                uid: Some("uid-1".to_string()),
                ..Default::default()
            },
            data: serde_json::json!({}),
        };
        let err = validate_live_identity(&c, &obj).unwrap_err().to_string();
        assert!(err.contains("TypeMeta"), "err: {}", err);
    }

    #[test]
    fn split_api_version_core() {
        let (g, v) = split_api_version("v1");
        assert_eq!(g, "");
        assert_eq!(v, "v1");
    }

    #[test]
    fn split_api_version_grouped() {
        let (g, v) = split_api_version("apps/v1");
        assert_eq!(g, "apps");
        assert_eq!(v, "v1");
    }

    #[test]
    fn split_api_version_deep_group() {
        let (g, v) = split_api_version("operator.authorino.kuadrant.io/v1beta2");
        assert_eq!(g, "operator.authorino.kuadrant.io");
        assert_eq!(v, "v1beta2");
    }

    // ── Async tower mock tests for fetch_backup_resources ──

    use ::kube::client::Body;
    use std::pin::pin;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    fn mock_json_response(json: serde_json::Value) -> http::Response<Body> {
        http::Response::builder()
            .status(200)
            .body(Body::from(serde_json::to_vec(&json).unwrap()))
            .unwrap()
    }

    fn mock_status_response(code: u16, reason: &str) -> http::Response<Body> {
        let body = serde_json::json!({
            "apiVersion": "v1", "kind": "Status",
            "metadata": {},
            "status": "Failure",
            "reason": reason,
            "code": code
        });
        http::Response::builder()
            .status(code)
            .body(Body::from(serde_json::to_vec(&body).unwrap()))
            .unwrap()
    }

    fn test_gvk_map() -> crate::kube::discovery::GvkMap {
        let mut m = std::collections::HashMap::new();
        m.insert(
            ("".to_string(), "v1".to_string(), "ConfigMap".to_string()),
            crate::kube::discovery::KindInfo {
                group: "".to_string(),
                version: "v1".to_string(),
                plural: "configmaps".to_string(),
                namespaced: true,
                listable: true,
            },
        );
        m.insert(
            (
                "apps".to_string(),
                "v1".to_string(),
                "Deployment".to_string(),
            ),
            crate::kube::discovery::KindInfo {
                group: "apps".to_string(),
                version: "v1".to_string(),
                plural: "deployments".to_string(),
                namespaced: true,
                listable: true,
            },
        );
        m
    }

    fn configmap_obj(name: &str, ns: &str, uid: &str) -> serde_json::Value {
        serde_json::json!({
            "apiVersion": "v1",
            "kind": "ConfigMap",
            "metadata": {
                "name": name,
                "namespace": ns,
                "uid": uid,
                "resourceVersion": "100",
                "creationTimestamp": "2026-01-01T00:00:00Z",
            },
            "data": {"key": "value"}
        })
    }

    #[tokio::test]
    async fn fetch_200_configmap_captures_with_identity() {
        let request_count = Arc::new(AtomicUsize::new(0));
        let count = request_count.clone();

        let (mock_service, handle) =
            tower_test::mock::pair::<http::Request<Body>, http::Response<Body>>();
        let spawned = tokio::spawn(async move {
            let mut handle = pin!(handle);
            while let Some((req, send)) = handle.next_request().await {
                count.fetch_add(1, Ordering::SeqCst);
                assert!(
                    req.uri()
                        .to_string()
                        .contains("/namespaces/ns/configmaps/cm1"),
                    "URI must target exact resource: {}",
                    req.uri()
                );
                send.send_response(mock_json_response(configmap_obj("cm1", "ns", "uid-cm")));
            }
        });

        let client = ::kube::Client::new(mock_service, "default");
        let candidates = vec![make_candidate(
            "",
            "v1",
            "ConfigMap",
            Some("ns"),
            "cm1",
            "uid-cm",
        )];
        let gvk_map = test_gvk_map();

        let (resources, contains_secrets) = fetch_backup_resources(&client, &candidates, &gvk_map)
            .await
            .unwrap();

        drop(client);
        spawned.abort();

        assert_eq!(resources.len(), 1);
        assert_eq!(resources[0].state, BackupResourceState::Captured);
        assert!(resources[0].raw_object.is_some());
        assert!(resources[0].recreate_manifest.is_some());
        assert!(!contains_secrets);
        assert_eq!(request_count.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn fetch_404_records_already_absent() {
        let request_count = Arc::new(AtomicUsize::new(0));
        let count = request_count.clone();

        let (mock_service, handle) =
            tower_test::mock::pair::<http::Request<Body>, http::Response<Body>>();
        let spawned = tokio::spawn(async move {
            let mut handle = pin!(handle);
            while let Some((_req, send)) = handle.next_request().await {
                count.fetch_add(1, Ordering::SeqCst);
                send.send_response(mock_status_response(404, "NotFound"));
            }
        });

        let client = ::kube::Client::new(mock_service, "default");
        let candidates = vec![make_candidate(
            "",
            "v1",
            "ConfigMap",
            Some("ns"),
            "cm1",
            "uid-cm",
        )];

        let (resources, _) = fetch_backup_resources(&client, &candidates, &test_gvk_map())
            .await
            .unwrap();

        drop(client);
        spawned.abort();

        assert_eq!(resources.len(), 1);
        assert_eq!(resources[0].state, BackupResourceState::AlreadyAbsent);
        assert!(resources[0].raw_object.is_none());
    }

    #[tokio::test]
    async fn fetch_403_fails_one_request() {
        let request_count = Arc::new(AtomicUsize::new(0));
        let count = request_count.clone();

        let (mock_service, handle) =
            tower_test::mock::pair::<http::Request<Body>, http::Response<Body>>();
        let spawned = tokio::spawn(async move {
            let mut handle = pin!(handle);
            while let Some((_req, send)) = handle.next_request().await {
                count.fetch_add(1, Ordering::SeqCst);
                send.send_response(mock_status_response(403, "Forbidden"));
            }
        });

        let client = ::kube::Client::new(mock_service, "default");
        let candidates = vec![make_candidate(
            "",
            "v1",
            "ConfigMap",
            Some("ns"),
            "cm1",
            "uid-cm",
        )];

        let result = fetch_backup_resources(&client, &candidates, &test_gvk_map()).await;

        drop(client);
        spawned.abort();

        assert!(result.is_err());
        assert_eq!(
            request_count.load(Ordering::SeqCst),
            1,
            "403 must not retry"
        );
    }

    #[tokio::test]
    async fn fetch_persistent_500_fails_after_retries() {
        let request_count = Arc::new(AtomicUsize::new(0));
        let count = request_count.clone();

        let (mock_service, handle) =
            tower_test::mock::pair::<http::Request<Body>, http::Response<Body>>();
        let spawned = tokio::spawn(async move {
            let mut handle = pin!(handle);
            while let Some((_req, send)) = handle.next_request().await {
                count.fetch_add(1, Ordering::SeqCst);
                send.send_response(mock_status_response(500, "InternalServerError"));
            }
        });

        let client = ::kube::Client::new(mock_service, "default");
        let candidates = vec![make_candidate(
            "",
            "v1",
            "ConfigMap",
            Some("ns"),
            "cm1",
            "uid-cm",
        )];

        let result = fetch_backup_resources(&client, &candidates, &test_gvk_map()).await;

        drop(client);
        spawned.abort();

        assert!(result.is_err());
        assert_eq!(
            request_count.load(Ordering::SeqCst),
            3,
            "500 must retry 3 times"
        );
    }

    #[tokio::test]
    async fn fetch_wrong_identity_fails() {
        let (mock_service, handle) =
            tower_test::mock::pair::<http::Request<Body>, http::Response<Body>>();
        let spawned = tokio::spawn(async move {
            let mut handle = pin!(handle);
            while let Some((_req, send)) = handle.next_request().await {
                // Return object with wrong kind
                send.send_response(mock_json_response(serde_json::json!({
                    "apiVersion": "v1",
                    "kind": "Secret",
                    "metadata": {
                        "name": "cm1",
                        "namespace": "ns",
                        "uid": "uid-cm",
                        "resourceVersion": "1",
                        "creationTimestamp": "2026-01-01T00:00:00Z",
                    },
                })));
            }
        });

        let client = ::kube::Client::new(mock_service, "default");
        let candidates = vec![make_candidate(
            "",
            "v1",
            "ConfigMap",
            Some("ns"),
            "cm1",
            "uid-cm",
        )];

        let result = fetch_backup_resources(&client, &candidates, &test_gvk_map()).await;

        drop(client);
        spawned.abort();

        assert!(result.is_err());
        let err = format!("{:#}", result.unwrap_err());
        assert!(err.contains("kind mismatch"), "err: {}", err);
    }

    #[tokio::test]
    async fn fetch_exact_gvk_miss_zero_requests() {
        let request_count = Arc::new(AtomicUsize::new(0));
        let count = request_count.clone();

        let (mock_service, handle) =
            tower_test::mock::pair::<http::Request<Body>, http::Response<Body>>();
        let spawned = tokio::spawn(async move {
            let mut handle = pin!(handle);
            while let Some((_req, send)) = handle.next_request().await {
                count.fetch_add(1, Ordering::SeqCst);
                send.send_response(mock_status_response(200, "OK"));
            }
        });

        let client = ::kube::Client::new(mock_service, "default");
        // Use a version that doesn't exist in GvkMap
        let candidates = vec![make_candidate(
            "",
            "v2beta1",
            "ConfigMap",
            Some("ns"),
            "cm1",
            "uid-cm",
        )];

        let result = fetch_backup_resources(&client, &candidates, &test_gvk_map()).await;

        drop(client);
        spawned.abort();

        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("not served"));
        assert_eq!(
            request_count.load(Ordering::SeqCst),
            0,
            "GVK miss must issue zero GETs"
        );
    }

    // ── Resume receipt validation helper test ──

    #[test]
    fn resume_receipt_validation_roundtrip() {
        let dir = std::env::temp_dir().join(format!("resume-rt-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("backup.json");

        // Create a plan and compute its bound hash
        let plan = make_plan(vec![Action::Delete {
            resource: rid("Deployment", "d1", Some("uid-1")),
            reason: "root".to_string(),
        }]);
        let plan_sha = bound_plan_sha256(&plan).unwrap();

        // Build bundle with that plan hash
        let bundle = build_bundle(
            vec![],
            &test_cluster(),
            &plan_sha,
            "/tmp/plan.json",
            vec![],
            false,
            vec![],
            vec![],
            candidate_set_hash_from_resources(&[]),
        );
        let receipt = write_backup_bundle(&bundle, &path).unwrap();

        // Validate with same plan → success
        let result = validate_receipt(&receipt, &test_cluster(), &plan_sha);
        assert!(result.is_ok(), "valid receipt must pass: {:?}", result);

        // Validate with different plan → failure
        let mut altered_plan = plan.clone();
        altered_plan.phases[0].actions.push(Action::Delete {
            resource: rid("ConfigMap", "cm-extra", Some("uid-extra")),
            reason: "added".to_string(),
        });
        let altered_sha = bound_plan_sha256(&altered_plan).unwrap();
        let result = validate_receipt(&receipt, &test_cluster(), &altered_sha);
        assert!(result.is_err(), "altered plan must fail validation");

        let _ = std::fs::remove_dir_all(&dir);
    }
}
