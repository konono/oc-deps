use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};

use crate::kube::resource::ResourceId;
use crate::teardown::plan::ClusterIdentity;
use crate::teardown::planner::{Action, TeardownPlan};

pub const BACKUP_SCHEMA_VERSION: u32 = 2;

// ──────────────────────────────────────────────────────────────
//  Core types — reused across all backup paths
// ──────────────────────────────────────────────────────────────

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

    #[allow(dead_code)]
    pub fn uid_short(&self) -> &str {
        &self.uid[..12.min(self.uid.len())]
    }
}

#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub struct BackupSource {
    pub source_type: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub phase: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub action: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub operator: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub category: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub relationship: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub namespace: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub adapter_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub root_kind: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_contract: Option<String>,
}

impl BackupSource {
    #[allow(dead_code)]
    pub fn plan_action(phase: u32, action: &str, reason: &str) -> Self {
        Self {
            source_type: "plan_action".to_string(),
            phase: Some(phase),
            action: Some(action.to_string()),
            reason: Some(reason.to_string()),
            ..Default::default()
        }
    }
    pub fn operator_discovery(operator: &str, category: &str, relationship: &str) -> Self {
        Self {
            source_type: "operator_discovery".to_string(),
            operator: Some(operator.to_string()),
            category: Some(category.to_string()),
            relationship: Some(relationship.to_string()),
            ..Default::default()
        }
    }
    pub fn namespace_scan(namespace: &str) -> Self {
        Self {
            source_type: "namespace_scan".to_string(),
            namespace: Some(namespace.to_string()),
            ..Default::default()
        }
    }
    pub fn cleanup_contract(adapter_id: &str, root_kind: &str, source_contract: &str) -> Self {
        Self {
            source_type: "cleanup_contract".to_string(),
            adapter_id: Some(adapter_id.to_string()),
            root_kind: Some(root_kind.to_string()),
            source_contract: Some(source_contract.to_string()),
            ..Default::default()
        }
    }
}

// BackupSource derives Default via #[derive(Default)] below — all fields
// are Option<T> (which default to None) or String (which defaults to "").
// The struct-level derive produces the same result as the manual impl.

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

// ──────────────────────────────────────────────────────────────
//  BackupSelection — typed source of truth
// ──────────────────────────────────────────────────────────────

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BackupSelection {
    pub selection_type: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub operators: Vec<ResolvedOperatorIdentity>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub operator_names: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub namespaces: Vec<String>,
}

impl BackupSelection {
    #[allow(dead_code)]
    pub fn teardown_plan(operators: Vec<String>) -> Self {
        Self {
            selection_type: "teardown_plan".to_string(),
            operator_names: operators,
            operators: vec![],
            namespaces: vec![],
        }
    }
    pub fn operator(operators: Vec<ResolvedOperatorIdentity>) -> Self {
        Self {
            selection_type: "operator".to_string(),
            operators,
            operator_names: vec![],
            namespaces: vec![],
        }
    }
    pub fn namespace(namespaces: Vec<String>) -> Self {
        Self {
            selection_type: "namespace".to_string(),
            namespaces,
            operators: vec![],
            operator_names: vec![],
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct ResolvedOperatorIdentity {
    pub package_name: String,
    pub csv_name: String,
    pub install_namespace: String,
}

// ──────────────────────────────────────────────────────────────
//  BackupCandidate — pre-fetch identity + sources
// ──────────────────────────────────────────────────────────────

#[derive(Clone, Debug)]
pub struct BackupCandidate {
    pub identity: BackupResourceIdentity,
    pub sources: Vec<BackupSource>,
}

// ──────────────────────────────────────────────────────────────
//  Manifest — directory-level metadata (no raw objects / secrets)
// ──────────────────────────────────────────────────────────────

#[derive(Debug, Serialize, Deserialize)]
pub struct BackupManifest {
    pub schema_version: u32,
    pub created_at: String,
    pub oc_deps_version: String,
    pub cluster_identity: ClusterIdentity,
    pub selection: BackupSelection,
    pub coverage: CoverageSummary,
    pub contains_secret_data: bool,
    pub restore_supported: bool,
    pub restore_notes: Vec<String>,
    pub capability_warnings: Vec<String>,
    pub limitations: Vec<String>,
    pub resources: Vec<ResourceIndexEntry>,
    pub resource_set_sha256: String,
    pub tree_sha256: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub cleanup_contract_observations: Vec<CleanupContractObservation>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct CoverageSummary {
    pub total: usize,
    pub captured: usize,
    pub already_absent: usize,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ResourceIndexEntry {
    pub identity: BackupResourceIdentity,
    pub sources: Vec<BackupSource>,
    pub state: BackupResourceState,
    pub relative_path: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub raw_sha256: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub recreate_sha256: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub lifecycle_sha256: Option<String>,
}

// ──────────────────────────────────────────────────────────────
//  Lifecycle YAML — per-resource metadata (no raw object data)
// ──────────────────────────────────────────────────────────────

#[derive(Debug, Serialize, Deserialize)]
pub struct LifecycleEntry {
    pub identity: BackupResourceIdentity,
    pub sources: Vec<BackupSource>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub deferred_lifecycle: Option<DeferredLifecycle>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub omitted_fields: Option<Vec<OmittedField>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub raw_sha256: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub recreate_sha256: Option<String>,
}

// ──────────────────────────────────────────────────────────────
//  BackupReceipt — stored in RunJournal (directory-based)
// ──────────────────────────────────────────────────────────────

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BackupReceipt {
    pub root: String,
    pub manifest_sha256: String,
    pub tree_sha256: String,
    pub resource_set_sha256: String,
    pub resource_count: usize,
    pub contains_secret_data: bool,
    pub created_at: String,
}

// ──────────────────────────────────────────────────────────────
//  Candidate extraction — fail closed on missing UIDs
// ──────────────────────────────────────────────────────────────

#[allow(dead_code)]
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
            let source = BackupSource::plan_action((phase_idx + 1) as u32, action_name, reason);

            match by_uid.get(uid) {
                Some(existing) if existing.identity != identity => {
                    bail!(
                        "Backup candidate UID {} has conflicting identity: \
                         {}/{} vs {}/{}",
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
                    let source = BackupSource::cleanup_contract(
                        &report.adapter_id,
                        &result
                            .resource
                            .source_id
                            .as_ref()
                            .map(|s| s.kind.clone())
                            .unwrap_or_default(),
                        "CleansUp",
                    );
                    if let Some(existing) = candidates.iter_mut().find(|c| c.identity.uid == uid) {
                        if existing.identity != identity {
                            bail!(
                                "Adapter {} cleanup target UID {} has conflicting identity",
                                report.adapter_id,
                                uid,
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

// ──────────────────────────────────────────────────────────────
//  Hash helpers
// ──────────────────────────────────────────────────────────────

pub fn compute_sha256(data: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(data);
    format!("{:x}", hasher.finalize())
}

#[allow(dead_code)]
pub fn resource_set_hash(candidates: &[BackupCandidate]) -> String {
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

pub fn resource_set_hash_from_index(entries: &[ResourceIndexEntry]) -> String {
    let mut keys: Vec<String> = entries
        .iter()
        .map(|e| {
            format!(
                "{}/{}/{}/{}/{}/{}",
                e.identity.group,
                e.identity.version,
                e.identity.kind,
                e.identity.namespace.as_deref().unwrap_or("-"),
                e.identity.name,
                e.identity.uid,
            )
        })
        .collect();
    keys.sort();
    compute_sha256(keys.join("\n").as_bytes())
}

#[allow(dead_code)]
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
            group
        );
    }
    if version != candidate.identity.version {
        bail!(
            "version mismatch for {}/{}: expected {:?} got {:?}",
            candidate.identity.kind,
            candidate.identity.name,
            candidate.identity.version,
            version
        );
    }
    if tm.kind != candidate.identity.kind {
        bail!(
            "kind mismatch for {}/{}: expected {:?} got {:?}",
            candidate.identity.kind,
            candidate.identity.name,
            candidate.identity.kind,
            tm.kind
        );
    }
    if obj.metadata.name.as_deref() != Some(candidate.identity.name.as_str()) {
        bail!(
            "name mismatch: expected {:?} got {:?}",
            candidate.identity.name,
            obj.metadata.name
        );
    }
    if obj.metadata.namespace != candidate.identity.namespace {
        bail!(
            "namespace mismatch for {}/{}: expected {:?} got {:?}",
            candidate.identity.kind,
            candidate.identity.name,
            candidate.identity.namespace,
            obj.metadata.namespace
        );
    }
    let live_uid = obj.metadata.uid.as_deref().unwrap_or("");
    if live_uid != candidate.identity.uid {
        bail!(
            "UID mismatch for {}/{}: expected {} got {}",
            candidate.identity.kind,
            candidate.identity.name,
            candidate.identity.uid,
            live_uid
        );
    }
    Ok(())
}

// ──────────────────────────────────────────────────────────────
//  Fetch candidates from cluster
// ──────────────────────────────────────────────────────────────

pub struct FetchedResource {
    pub identity: BackupResourceIdentity,
    pub sources: Vec<BackupSource>,
    pub state: BackupResourceState,
    pub raw: Option<serde_json::Value>,
    pub recreate: Option<serde_json::Value>,
    pub deferred: Option<DeferredLifecycle>,
    pub omitted: Option<Vec<OmittedField>>,
}

impl std::fmt::Debug for FetchedResource {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FetchedResource")
            .field("identity", &self.identity)
            .field("state", &self.state)
            .field("sources_count", &self.sources.len())
            .finish()
    }
}

pub async fn fetch_backup_resources(
    client: &kube::Client,
    candidates: &[BackupCandidate],
    gvk_map: &crate::kube::discovery::GvkMap,
) -> Result<(Vec<FetchedResource>, bool)> {
    use kube::api::{Api, ApiResource, DynamicObject};

    let mut resources = Vec::new();
    let mut contains_secrets = false;

    for candidate in candidates {
        let gvk_key = (
            candidate.identity.group.clone(),
            candidate.identity.version.clone(),
            candidate.identity.kind.clone(),
        );
        let info = match gvk_map.get(&gvk_key) {
            Some(i) => i,
            None => bail!(
                "Exact GVK ({}/{}/{}) not served by cluster — backup cannot proceed.",
                candidate.identity.group,
                candidate.identity.version,
                candidate.identity.kind,
            ),
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
                "Resource {}/{} is namespaced but has no namespace in candidate",
                candidate.identity.kind,
                candidate.identity.name
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
                resources.push(FetchedResource {
                    identity: candidate.identity.clone(),
                    sources: candidate.sources.clone(),
                    state: BackupResourceState::Captured,
                    raw: Some(raw),
                    recreate: Some(recreate),
                    deferred: Some(deferred),
                    omitted: Some(omitted),
                });
            }
            Err(w) if w.is_not_found() => {
                resources.push(FetchedResource {
                    identity: candidate.identity.clone(),
                    sources: candidate.sources.clone(),
                    state: BackupResourceState::AlreadyAbsent,
                    raw: None,
                    recreate: None,
                    deferred: None,
                    omitted: None,
                });
            }
            Err(w) => bail!(
                "Failed to GET {}/{}: {} — backup cannot proceed",
                candidate.identity.kind,
                candidate.identity.name,
                w
            ),
        }
    }

    resources.sort_by(|a, b| a.identity.cmp(&b.identity));
    Ok((resources, contains_secrets))
}

// ──────────────────────────────────────────────────────────────
//  YAML serialization with sorted keys
// ──────────────────────────────────────────────────────────────

fn json_to_sorted_yaml(value: &serde_json::Value) -> Result<String> {
    let yaml_value: serde_yaml::Value = serde_json::from_value(sort_json_keys(value.clone()))?;
    Ok(serde_yaml::to_string(&yaml_value)?)
}

fn sort_json_keys(value: serde_json::Value) -> serde_json::Value {
    match value {
        serde_json::Value::Object(map) => {
            let mut sorted: BTreeMap<String, serde_json::Value> = BTreeMap::new();
            for (k, v) in map {
                sorted.insert(k, sort_json_keys(v));
            }
            serde_json::Value::Object(sorted.into_iter().collect())
        }
        serde_json::Value::Array(arr) => {
            serde_json::Value::Array(arr.into_iter().map(sort_json_keys).collect())
        }
        other => other,
    }
}

fn serialize_yaml<T: Serialize>(value: &T) -> Result<String> {
    let json = serde_json::to_value(value)?;
    json_to_sorted_yaml(&json)
}

// ──────────────────────────────────────────────────────────────
//  Path sanitization
// ──────────────────────────────────────────────────────────────

fn sanitize_path_component(s: &str) -> Result<String> {
    if s.is_empty() || s.trim().is_empty() {
        bail!("path component must not be empty or whitespace");
    }
    if s.contains('/') || s.contains('\\') || s.contains('\0') {
        bail!("path component {:?} contains forbidden characters", s);
    }
    if s == "." || s == ".." {
        bail!("path component {:?} is a traversal", s);
    }
    if s.starts_with('-') {
        return Ok(format!("_{}", s));
    }
    Ok(s.to_string())
}

fn resource_dir_path(identity: &BackupResourceIdentity) -> Result<String> {
    let group = if identity.group.is_empty() {
        "core".to_string()
    } else {
        sanitize_path_component(&identity.group)?
    };
    let version = sanitize_path_component(&identity.version)?;
    let kind = sanitize_path_component(&identity.kind)?;
    let ns = sanitize_path_component(identity.namespace.as_deref().unwrap_or("_cluster"))?;
    let name = sanitize_path_component(&identity.name)?;
    let uid_safe = sanitize_path_component(&identity.uid)?;

    Ok(format!(
        "resources/{}/{}/{}/{}/{}--{}",
        group, version, kind, ns, name, uid_safe,
    ))
}

// ──────────────────────────────────────────────────────────────
//  Directory writer — atomic staging → rename
// ──────────────────────────────────────────────────────────────

struct StagingGuard {
    path: PathBuf,
    armed: bool,
}

impl StagingGuard {
    fn disarm(&mut self) {
        self.armed = false;
    }
}

impl Drop for StagingGuard {
    fn drop(&mut self) {
        if self.armed {
            let _ = std::fs::remove_dir_all(&self.path);
        }
    }
}

fn set_dir_mode(path: &Path) -> Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))
            .with_context(|| format!("Failed to set dir mode 0700: {}", path.display()))?;
    }
    Ok(())
}

fn write_file_0600(path: &Path, content: &[u8]) -> Result<()> {
    use std::io::Write;
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(path)
            .with_context(|| format!("Failed to create {}", path.display()))?;
        f.write_all(content)?;
        f.sync_all()?;
    }
    #[cfg(not(unix))]
    {
        let mut f = std::fs::File::create_new(path)
            .with_context(|| format!("Failed to create {}", path.display()))?;
        f.write_all(content)?;
        f.sync_all()?;
    }
    Ok(())
}

fn sync_dir(path: &Path) -> Result<()> {
    let dir = std::fs::File::open(path)
        .with_context(|| format!("Failed to open dir {}", path.display()))?;
    dir.sync_all()
        .with_context(|| format!("Failed to fsync dir {}", path.display()))?;
    Ok(())
}

pub fn write_backup_directory(
    fetched: &[FetchedResource],
    cluster_identity: &ClusterIdentity,
    selection: BackupSelection,
    observations: Vec<CleanupContractObservation>,
    target_dir: &Path,
    run_name: &str,
) -> Result<BackupReceipt> {
    // Ensure target_dir exists
    if !target_dir.exists() {
        std::fs::create_dir_all(target_dir)
            .with_context(|| format!("Failed to create {}", target_dir.display()))?;
        set_dir_mode(target_dir)?;
    }

    // Create staging directory (sibling of final)
    let staging_name = format!(".staging-{}-{}", run_name, std::process::id());
    let staging_dir = target_dir.join(&staging_name);
    if staging_dir.exists() {
        bail!("Staging directory {} already exists", staging_dir.display());
    }
    std::fs::create_dir_all(&staging_dir)?;
    set_dir_mode(&staging_dir)?;

    let mut guard = StagingGuard {
        path: staging_dir.clone(),
        armed: true,
    };

    let mut index_entries = Vec::new();
    let mut file_hashes: BTreeMap<String, String> = BTreeMap::new();
    let mut contains_secrets = false;

    // Write per-resource files
    for res in fetched {
        let rel_path = resource_dir_path(&res.identity)?;
        let res_dir = staging_dir.join(&rel_path);
        std::fs::create_dir_all(&res_dir)?;
        set_dir_mode(&res_dir)?;

        let mut raw_sha: Option<String> = None;
        let mut recreate_sha: Option<String> = None;

        if let Some(ref raw) = res.raw {
            let yaml = json_to_sorted_yaml(raw)?;
            let bytes = yaml.as_bytes();
            let sha = compute_sha256(bytes);
            let file_path = res_dir.join("raw.yaml");
            write_file_0600(&file_path, bytes)?;
            file_hashes.insert(format!("{}/raw.yaml", rel_path), sha.clone());
            raw_sha = Some(sha);

            if res.identity.kind == "Secret" {
                contains_secrets = true;
            }
        }

        if let Some(ref recreate) = res.recreate {
            let yaml = json_to_sorted_yaml(recreate)?;
            let bytes = yaml.as_bytes();
            let sha = compute_sha256(bytes);
            let file_path = res_dir.join("recreate.yaml");
            write_file_0600(&file_path, bytes)?;
            file_hashes.insert(format!("{}/recreate.yaml", rel_path), sha.clone());
            recreate_sha = Some(sha);
        }

        // lifecycle.yaml
        let lifecycle = LifecycleEntry {
            identity: res.identity.clone(),
            sources: res.sources.clone(),
            deferred_lifecycle: res.deferred.clone(),
            omitted_fields: res.omitted.clone(),
            raw_sha256: raw_sha.clone(),
            recreate_sha256: recreate_sha.clone(),
        };
        let lifecycle_yaml = serialize_yaml(&lifecycle)?;
        let lifecycle_bytes = lifecycle_yaml.as_bytes();
        let lsha = compute_sha256(lifecycle_bytes);
        let lifecycle_path = res_dir.join("lifecycle.yaml");
        write_file_0600(&lifecycle_path, lifecycle_bytes)?;
        file_hashes.insert(format!("{}/lifecycle.yaml", rel_path), lsha.clone());
        let lifecycle_sha = lsha;

        // Sync resource directory
        sync_dir(&res_dir)?;

        index_entries.push(ResourceIndexEntry {
            identity: res.identity.clone(),
            sources: res.sources.clone(),
            state: res.state.clone(),
            relative_path: rel_path,
            raw_sha256: raw_sha,
            recreate_sha256: recreate_sha,
            lifecycle_sha256: Some(lifecycle_sha),
        });
    }

    // Sort index for determinism
    index_entries.sort_by(|a, b| a.identity.cmp(&b.identity));

    // Compute tree hash from sorted (path, hash) pairs
    let tree_hash = {
        let mut entries: Vec<(&str, &str)> = file_hashes
            .iter()
            .map(|(k, v)| (k.as_str(), v.as_str()))
            .collect();
        entries.sort();
        let tree_str: String = entries
            .iter()
            .map(|(p, h)| format!("{}:{}", p, h))
            .collect::<Vec<_>>()
            .join("\n");
        compute_sha256(tree_str.as_bytes())
    };

    let resource_set_sha = resource_set_hash_from_index(&index_entries);

    let captured = index_entries
        .iter()
        .filter(|e| e.state == BackupResourceState::Captured)
        .count();
    let absent = index_entries
        .iter()
        .filter(|e| e.state == BackupResourceState::AlreadyAbsent)
        .count();

    // Build manifest
    let manifest = BackupManifest {
        schema_version: BACKUP_SCHEMA_VERSION,
        created_at: crate::teardown::journal::chrono_now_iso(),
        oc_deps_version: env!("CARGO_PKG_VERSION").to_string(),
        cluster_identity: cluster_identity.clone(),
        selection,
        coverage: CoverageSummary { total: index_entries.len(), captured, already_absent: absent },
        contains_secret_data: contains_secrets,
        restore_supported: false,
        restore_notes: vec![
            "recreate.yaml is a best-effort candidate; kind-specific allocated/defaulted/immutable fields may require review.".to_string(),
        ],
        capability_warnings: vec![
            "Service clusterIP/nodePort, PVC volumeName, and CRD webhook defaults are not generically detectable.".to_string(),
        ],
        limitations: vec![
            "ownerRef-derived unplanned cascade children are not captured.".to_string(),
            "Storage reclaim and derived storage side effects are not captured.".to_string(),
        ],
        resources: index_entries,
        resource_set_sha256: resource_set_sha.clone(),
        tree_sha256: tree_hash.clone(),
        cleanup_contract_observations: observations,
    };

    let manifest_yaml = serialize_yaml(&manifest)?;
    let manifest_bytes = manifest_yaml.as_bytes();
    let manifest_sha = compute_sha256(manifest_bytes);
    let manifest_path = staging_dir.join("manifest.yaml");
    write_file_0600(&manifest_path, manifest_bytes)?;

    // Sync resources parent directories
    let resources_dir = staging_dir.join("resources");
    if resources_dir.exists() {
        sync_dir(&resources_dir)?;
    }
    sync_dir(&staging_dir)?;

    // Atomic publish: rename staging → final
    let final_dir = target_dir.join(run_name);
    if final_dir.exists() {
        bail!(
            "Target run directory {} already exists — will not overwrite",
            final_dir.display()
        );
    }
    std::fs::rename(&staging_dir, &final_dir).with_context(|| {
        format!(
            "Failed to publish backup: {} → {}",
            staging_dir.display(),
            final_dir.display()
        )
    })?;
    guard.disarm();

    // fsync parent for crash consistency
    sync_dir(target_dir)?;

    if contains_secrets {
        eprintln!(
            "  ⚠ Backup contains Secret data (file mode 0600). Do not commit to version control."
        );
    }

    Ok(BackupReceipt {
        root: final_dir.to_string_lossy().to_string(),
        manifest_sha256: manifest_sha,
        tree_sha256: tree_hash,
        resource_set_sha256: resource_set_sha,
        resource_count: manifest.resources.len(),
        contains_secret_data: contains_secrets,
        created_at: manifest.created_at,
    })
}

// ──────────────────────────────────────────────────────────────
//  Receipt validation (for resume)
// ──────────────────────────────────────────────────────────────

pub fn validate_receipt(receipt: &BackupReceipt, current_cluster: &ClusterIdentity) -> Result<()> {
    let root = Path::new(&receipt.root);
    if !root.exists() || !root.is_dir() {
        bail!(
            "Backup directory {} no longer exists — cannot resume",
            receipt.root
        );
    }

    // Read and verify manifest
    let manifest_path = root.join("manifest.yaml");
    let manifest_bytes = std::fs::read(&manifest_path)
        .with_context(|| format!("Failed to read manifest: {}", manifest_path.display()))?;
    let manifest_sha = compute_sha256(&manifest_bytes);
    if manifest_sha != receipt.manifest_sha256 {
        bail!(
            "Manifest SHA-256 mismatch: expected {} got {}",
            receipt.manifest_sha256,
            manifest_sha
        );
    }

    let manifest: BackupManifest =
        serde_yaml::from_slice(&manifest_bytes).with_context(|| "Failed to parse manifest.yaml")?;

    // Cluster identity
    if !current_cluster.matches(&manifest.cluster_identity) {
        bail!("Backup cluster identity mismatch");
    }

    // Resource set hash
    let recomputed = resource_set_hash_from_index(&manifest.resources);
    if recomputed != manifest.resource_set_sha256 {
        bail!(
            "Resource set hash mismatch: manifest {} vs recomputed {}",
            manifest.resource_set_sha256,
            recomputed
        );
    }
    if receipt.resource_set_sha256 != manifest.resource_set_sha256 {
        bail!("Receipt/manifest resource set hash mismatch");
    }

    // Verify each indexed file
    let mut actual_hashes: BTreeMap<String, String> = BTreeMap::new();
    for entry in &manifest.resources {
        let res_dir = root.join(&entry.relative_path);
        // AlreadyAbsent resources have lifecycle.yaml but no raw/recreate
        let files_to_check: Vec<(&str, &Option<String>)> =
            if entry.state == BackupResourceState::AlreadyAbsent {
                vec![("lifecycle.yaml", &entry.lifecycle_sha256)]
            } else {
                vec![
                    ("raw.yaml", &entry.raw_sha256),
                    ("recreate.yaml", &entry.recreate_sha256),
                    ("lifecycle.yaml", &entry.lifecycle_sha256),
                ]
            };
        for (filename, expected_sha) in files_to_check {
            if let Some(expected) = expected_sha {
                let file_path = res_dir.join(filename);
                let data = std::fs::read(&file_path)
                    .with_context(|| format!("Missing indexed file: {}", file_path.display()))?;
                let sha = compute_sha256(&data);
                if sha != *expected {
                    bail!(
                        "File hash mismatch: {}/{}: expected {} got {}",
                        entry.relative_path,
                        filename,
                        expected,
                        sha
                    );
                }
                actual_hashes.insert(format!("{}/{}", entry.relative_path, filename), sha);
            }
        }
    }

    // Verify tree hash
    let tree_hash = {
        let mut entries: Vec<(&str, &str)> = actual_hashes
            .iter()
            .map(|(k, v)| (k.as_str(), v.as_str()))
            .collect();
        entries.sort();
        let tree_str: String = entries
            .iter()
            .map(|(p, h)| format!("{}:{}", p, h))
            .collect::<Vec<_>>()
            .join("\n");
        compute_sha256(tree_str.as_bytes())
    };
    if tree_hash != receipt.tree_sha256 {
        bail!(
            "Tree hash mismatch: expected {} got {}",
            receipt.tree_sha256,
            tree_hash
        );
    }

    // Cross-validate receipt fields
    if receipt.resource_count != manifest.resources.len() {
        bail!(
            "Resource count mismatch: receipt {} vs manifest {}",
            receipt.resource_count,
            manifest.resources.len()
        );
    }
    if receipt.contains_secret_data != manifest.contains_secret_data {
        bail!("Secret data flag mismatch");
    }

    Ok(())
}

// ──────────────────────────────────────────────────────────────
//  Run name generation
// ──────────────────────────────────────────────────────────────

static RUN_COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

pub fn generate_run_name() -> String {
    let now = chrono::Utc::now();
    let ts = now.format("%Y%m%dT%H%M%SZ");
    let pid = std::process::id();
    let seq = RUN_COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    format!("{}-{:08x}-{}", ts, pid, seq)
}

// ──────────────────────────────────────────────────────────────
//  Operator backup target path
// ──────────────────────────────────────────────────────────────

pub fn operator_target_dir(root: &Path, operator_name: &str) -> PathBuf {
    root.join("operator").join(operator_name)
}

pub fn namespace_target_dir(root: &Path, namespace: &str) -> PathBuf {
    root.join("namespace").join(namespace)
}

// ──────────────────────────────────────────────────────────────
//  Apply backup gate — operator discovery → directory → receipt
// ──────────────────────────────────────────────────────────────

pub struct BackupGateContext<'a> {
    pub client: &'a kube::Client,
    #[allow(dead_code)]
    pub final_plan: &'a TeardownPlan,
    pub target_operators: Vec<&'a crate::analyzers::olm::OperatorInstance>,
    pub cluster_identity: &'a ClusterIdentity,
    #[allow(dead_code)]
    pub plan_path: &'a str,
    pub kind_map: &'a crate::kube::discovery::KindMap,
    pub gvr_map: &'a crate::kube::discovery::GvrMap,
    pub gk_map: &'a crate::kube::discovery::GroupKindMap,
    pub gvk_map: &'a crate::kube::discovery::GvkMap,
}

/// Shared operator backup discovery: uses the same inspection as
/// `operator resources --scope related`, producing the exact same identity set.
#[allow(clippy::too_many_arguments)]
pub async fn discover_operator_backup(
    client: &kube::Client,
    operator: &crate::analyzers::olm::OperatorInstance,
    kind_map: &crate::kube::discovery::KindMap,
    gvr_map: &crate::kube::discovery::GvrMap,
    gk_map: &crate::kube::discovery::GroupKindMap,
    _gvk_map: &crate::kube::discovery::GvkMap,
) -> Result<(
    Vec<BackupCandidate>,
    Vec<CleanupContractObservation>,
    ResolvedOperatorIdentity,
)> {
    let cmd_semaphore = std::sync::Arc::new(tokio::sync::Semaphore::new(
        crate::kube::scanner::DEFAULT_API_CONCURRENCY,
    ));
    let cmd_planner = crate::kube::planner::QueryPlanner::new(Some(cmd_semaphore));

    let inspection = crate::analyzers::inspect::inspect_operator_with_options_ledger(
        client,
        operator,
        kind_map,
        gvr_map,
        gk_map,
        true, // cross_namespace = related scope
        None,
        Some(cmd_planner.clone()),
    )
    .await?;

    // Fail closed on incomplete coverage
    if inspection.should_exit_strict() {
        bail!(
            "Operator {} discovery is incomplete ({} warnings, {} incomplete) — \
             backup cannot proceed",
            operator.csv.name,
            inspection.scan_warning_count,
            inspection.incomplete_count,
        );
    }

    let mut candidates: Vec<BackupCandidate> = Vec::new();
    let mut observations = Vec::new();

    // Collect all discovered resources by UID
    for category in &inspection.categories {
        for res in &category.resources {
            let uid = match &res.id.uid {
                Some(u) if !u.is_empty() => u.clone(),
                _ => {
                    bail!(
                        "Discovered resource {}/{} has no UID — backup cannot proceed",
                        res.id.kind,
                        res.id.name,
                    );
                }
            };

            let identity = BackupResourceIdentity::from_resource_id(&res.id, &uid);
            let source = BackupSource::operator_discovery(
                &operator.csv.name,
                &category.label,
                &format!("{:?}", res.relationship),
            );

            if let Some(existing) = candidates.iter_mut().find(|c| c.identity.uid == uid) {
                if existing.identity != identity {
                    bail!(
                        "UID {} has conflicting identity: {}/{} vs {}/{}",
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
    }

    // Include adapter cleanup targets
    add_adapter_candidates(
        &mut candidates,
        &inspection.adapter_reports,
        &mut observations,
    )?;

    let resolved = ResolvedOperatorIdentity {
        package_name: operator.package_name.clone().unwrap_or_default(),
        csv_name: operator.csv.name.clone(),
        install_namespace: operator.install_namespace.clone(),
    };

    Ok((candidates, observations, resolved))
}

/// Shared namespace backup discovery: uses the existing namespace scanner,
/// producing the same identity set as the scan/map path.
pub async fn discover_namespace_backup(
    client: &kube::Client,
    namespace: &str,
    kind_map: &crate::kube::discovery::KindMap,
    gk_map: &crate::kube::discovery::GroupKindMap,
) -> Result<Vec<BackupCandidate>> {
    let (index, warnings) =
        crate::kube::scanner::scan_namespace(client, namespace, kind_map, false, false, false)
            .await?;

    // Fail closed on scan warnings (403/timeout/500 on required APIs)
    let required_failures: Vec<&crate::kube::resource::ScanWarning> =
        warnings.iter().filter(|w| !w.is_not_found()).collect();
    if !required_failures.is_empty() {
        bail!(
            "Namespace {} scan has {} required failure(s) — backup cannot proceed: {}",
            namespace,
            required_failures.len(),
            required_failures
                .iter()
                .map(|w| w.to_string())
                .collect::<Vec<_>>()
                .join("; "),
        );
    }

    let mut candidates: Vec<BackupCandidate> = Vec::new();

    for (uid, info) in &index.by_uid {
        // Resolve version from gk_map (ResourceInfo has no version field)
        let gk_key = (info.group.clone(), info.kind.clone());
        let version = match gk_map.get(&gk_key) {
            Some(ki) => ki.version.clone(),
            None => {
                bail!(
                    "Cannot resolve version for {}/{} (group={}) — backup cannot proceed",
                    info.kind,
                    info.name,
                    info.group,
                );
            }
        };

        let identity = BackupResourceIdentity {
            group: info.group.clone(),
            version,
            kind: info.kind.clone(),
            namespace: info.namespace.clone(),
            name: info.name.clone(),
            uid: uid.clone(),
        };

        let source = BackupSource::namespace_scan(namespace);
        candidates.push(BackupCandidate {
            identity,
            sources: vec![source],
        });
    }

    Ok(candidates)
}

pub async fn prepare_backup_gate(
    ctx: &BackupGateContext<'_>,
    backup_root: &Path,
) -> Result<Vec<BackupReceipt>> {
    eprintln!("\n📦 Backup: capturing pre-delete resource state via operator discovery...");

    let mut all_receipts = Vec::new();

    for op in &ctx.target_operators {
        let (candidates, observations, resolved) = discover_operator_backup(
            ctx.client,
            op,
            ctx.kind_map,
            ctx.gvr_map,
            ctx.gk_map,
            ctx.gvk_map,
        )
        .await?;

        eprintln!("  {} candidate(s) for {}", candidates.len(), op.csv.name,);

        let (fetched, _) = fetch_backup_resources(ctx.client, &candidates, ctx.gvk_map).await?;

        let captured = fetched
            .iter()
            .filter(|r| r.state == BackupResourceState::Captured)
            .count();
        let absent = fetched
            .iter()
            .filter(|r| r.state == BackupResourceState::AlreadyAbsent)
            .count();
        eprintln!("  {} captured, {} already absent", captured, absent);

        let selection = BackupSelection::operator(vec![resolved]);
        let op_name = op.package_name.as_deref().unwrap_or(&op.csv.name);
        let target = operator_target_dir(backup_root, op_name);
        let run_name = generate_run_name();

        let receipt = write_backup_directory(
            &fetched,
            ctx.cluster_identity,
            selection,
            observations,
            &target,
            &run_name,
        )?;

        eprintln!(
            "  ✅ Backup: {} ({} resources)",
            receipt.root, receipt.resource_count,
        );
        all_receipts.push(receipt);
    }

    Ok(all_receipts)
}

/// Setup backup root directory with 0700 permissions.
pub fn setup_backup_dir(dir: &Path) -> Result<()> {
    if !dir.exists() {
        std::fs::create_dir_all(dir)
            .with_context(|| format!("Failed to create backup dir: {}", dir.display()))?;
    }
    set_dir_mode(dir)
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

    // ── Candidate extraction ──

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
    }

    #[test]
    fn candidate_missing_uid_hard_fail() {
        let plan = make_plan(vec![Action::Delete {
            resource: rid("Deployment", "d1", None),
            reason: "root".to_string(),
        }]);
        assert!(extract_candidates(&plan).is_err());
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
                    uid: Some("uid-x".to_string()),
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
                    uid: Some("uid-x".to_string()),
                },
                reason: "root".to_string(),
            },
        ]);
        assert!(extract_candidates(&plan).is_err());
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
        let c = extract_candidates(&plan).unwrap();
        assert_eq!(c.len(), 1);
        assert_eq!(c[0].sources.len(), 2);
    }

    // ── Sanitize ──

    #[test]
    fn sanitize_removes_server_fields() {
        let raw = serde_json::json!({
            "apiVersion": "v1", "kind": "ConfigMap",
            "metadata": { "name": "test", "uid": "u", "resourceVersion": "1", "creationTimestamp": "2026-01-01T00:00:00Z", "managedFields": [] },
            "data": {"k": "v"}, "status": {},
        });
        let (m, _, o) = sanitize_for_recreate(&raw);
        assert!(m.pointer("/metadata/uid").is_none());
        assert!(m.pointer("/status").is_none());
        assert_eq!(m.pointer("/data/k").unwrap(), "v");
        assert!(o.iter().any(|f| f.path == "metadata.uid"));
    }

    #[test]
    fn sanitize_defers_owner_refs() {
        let raw = serde_json::json!({
            "apiVersion": "v1", "kind": "Pod",
            "metadata": { "name": "t", "ownerReferences": [{"uid": "u"}], "finalizers": ["f"] },
        });
        let (m, d, _) = sanitize_for_recreate(&raw);
        assert!(m.pointer("/metadata/ownerReferences").is_none());
        assert_eq!(d.owner_references.len(), 1);
        assert_eq!(d.finalizers, vec!["f"]);
    }

    // ── Identity validation ──

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
    fn validate_identity_wrong_group() {
        let c = make_candidate("apps", "v1", "Deployment", Some("ns"), "dep1", "uid-1");
        let obj = make_dyn_obj(
            "extensions/v1beta1",
            "Deployment",
            Some("ns"),
            "dep1",
            "uid-1",
        );
        assert!(
            validate_live_identity(&c, &obj)
                .unwrap_err()
                .to_string()
                .contains("group mismatch")
        );
    }

    #[test]
    fn validate_identity_wrong_kind() {
        let c = make_candidate("apps", "v1", "Deployment", Some("ns"), "dep1", "uid-1");
        let obj = make_dyn_obj("apps/v1", "StatefulSet", Some("ns"), "dep1", "uid-1");
        assert!(
            validate_live_identity(&c, &obj)
                .unwrap_err()
                .to_string()
                .contains("kind mismatch")
        );
    }

    #[test]
    fn validate_identity_missing_type_meta() {
        let c = make_candidate("apps", "v1", "Deployment", Some("ns"), "dep1", "uid-1");
        let obj = kube::api::DynamicObject {
            types: None,
            metadata: kube::core::ObjectMeta {
                name: Some("dep1".to_string()),
                uid: Some("uid-1".to_string()),
                ..Default::default()
            },
            data: serde_json::json!({}),
        };
        assert!(
            validate_live_identity(&c, &obj)
                .unwrap_err()
                .to_string()
                .contains("TypeMeta")
        );
    }

    // ── Path sanitization ──

    #[test]
    fn path_sanitize_rejects_traversal() {
        assert!(sanitize_path_component("..").is_err());
        assert!(sanitize_path_component("a/b").is_err());
        assert!(sanitize_path_component("").is_err());
    }

    #[test]
    fn resource_dir_path_format() {
        let id = BackupResourceIdentity {
            group: "apps".to_string(),
            version: "v1".to_string(),
            kind: "Deployment".to_string(),
            namespace: Some("ns".to_string()),
            name: "dep1".to_string(),
            uid: "abcdef012345".to_string(),
        };
        let p = resource_dir_path(&id).unwrap();
        assert_eq!(p, "resources/apps/v1/Deployment/ns/dep1--abcdef012345");
    }

    #[test]
    fn resource_dir_path_core_group() {
        let id = BackupResourceIdentity {
            group: "".to_string(),
            version: "v1".to_string(),
            kind: "ConfigMap".to_string(),
            namespace: Some("ns".to_string()),
            name: "cm1".to_string(),
            uid: "uid123456789".to_string(),
        };
        let p = resource_dir_path(&id).unwrap();
        assert!(p.starts_with("resources/core/v1/ConfigMap/"));
    }

    #[test]
    fn resource_dir_path_cluster_scoped() {
        let id = BackupResourceIdentity {
            group: "rbac.authorization.k8s.io".to_string(),
            version: "v1".to_string(),
            kind: "ClusterRoleBinding".to_string(),
            namespace: None,
            name: "crb1".to_string(),
            uid: "uid123456789".to_string(),
        };
        let p = resource_dir_path(&id).unwrap();
        assert!(p.contains("/_cluster/"));
    }

    // ── Directory writer ──

    #[test]
    fn write_backup_directory_roundtrip() {
        let dir = std::env::temp_dir().join(format!("backup-dir-rt-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);

        let fetched = vec![FetchedResource {
            identity: BackupResourceIdentity {
                group: "".to_string(),
                version: "v1".to_string(),
                kind: "ConfigMap".to_string(),
                namespace: Some("ns".to_string()),
                name: "cm1".to_string(),
                uid: "uid123456789a".to_string(),
            },
            sources: vec![BackupSource::operator_discovery("test", "OLM", "owned")],
            state: BackupResourceState::Captured,
            raw: Some(
                serde_json::json!({"apiVersion": "v1", "kind": "ConfigMap", "metadata": {"name": "cm1"}, "data": {"k": "v"}}),
            ),
            recreate: Some(
                serde_json::json!({"apiVersion": "v1", "kind": "ConfigMap", "metadata": {"name": "cm1"}, "data": {"k": "v"}}),
            ),
            deferred: Some(DeferredLifecycle {
                owner_references: vec![],
                finalizers: vec![],
            }),
            omitted: Some(vec![]),
        }];

        let receipt = write_backup_directory(
            &fetched,
            &test_cluster(),
            BackupSelection::operator(vec![ResolvedOperatorIdentity {
                package_name: "test".to_string(),
                csv_name: "test.v1".to_string(),
                install_namespace: "ns".to_string(),
            }]),
            vec![],
            &dir,
            "test-run",
        )
        .unwrap();

        assert_eq!(receipt.resource_count, 1);
        assert!(!receipt.contains_secret_data);

        // Verify directory structure
        let run_dir = dir.join("test-run");
        assert!(run_dir.join("manifest.yaml").exists());
        assert!(
            run_dir
                .join("resources/core/v1/ConfigMap/ns/cm1--uid123456789a/raw.yaml")
                .exists()
        );
        assert!(
            run_dir
                .join("resources/core/v1/ConfigMap/ns/cm1--uid123456789a/recreate.yaml")
                .exists()
        );
        assert!(
            run_dir
                .join("resources/core/v1/ConfigMap/ns/cm1--uid123456789a/lifecycle.yaml")
                .exists()
        );

        // Verify manifest is valid YAML, no raw objects
        let manifest_content = std::fs::read_to_string(run_dir.join("manifest.yaml")).unwrap();
        assert!(!manifest_content.contains("\"k\": \"v\""));
        let _: BackupManifest = serde_yaml::from_str(&manifest_content).unwrap();

        // Verify raw.yaml contains the data
        let raw_content = std::fs::read_to_string(
            run_dir.join("resources/core/v1/ConfigMap/ns/cm1--uid123456789a/raw.yaml"),
        )
        .unwrap();
        assert!(raw_content.contains("k:") || raw_content.contains("\"k\""));

        // Verify receipt validation
        assert!(validate_receipt(&receipt, &test_cluster()).is_ok());

        // Verify file modes
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(run_dir.join("manifest.yaml"))
                .unwrap()
                .permissions()
                .mode()
                & 0o777;
            assert_eq!(mode, 0o600, "manifest must be 0600");
        }

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn write_rejects_existing_run() {
        let dir = std::env::temp_dir().join(format!("backup-exist-{}", std::process::id()));
        let run_dir = dir.join("existing-run");
        std::fs::create_dir_all(&run_dir).unwrap();

        let result = write_backup_directory(
            &[],
            &test_cluster(),
            BackupSelection::namespace(vec!["ns".to_string()]),
            vec![],
            &dir,
            "existing-run",
        );
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("already exists"));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn validate_receipt_missing_dir() {
        let receipt = BackupReceipt {
            root: "/nonexistent/dir".to_string(),
            manifest_sha256: "x".to_string(),
            tree_sha256: "x".to_string(),
            resource_set_sha256: "x".to_string(),
            resource_count: 0,
            contains_secret_data: false,
            created_at: "t".to_string(),
        };
        assert!(validate_receipt(&receipt, &test_cluster()).is_err());
    }

    #[test]
    fn validate_receipt_tampered_manifest() {
        let dir = std::env::temp_dir().join(format!("backup-tamper-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);

        let receipt = write_backup_directory(
            &[],
            &test_cluster(),
            BackupSelection::namespace(vec!["ns".to_string()]),
            vec![],
            &dir,
            "run1",
        )
        .unwrap();

        // Tamper manifest
        std::fs::write(dir.join("run1/manifest.yaml"), "tampered: true").unwrap();
        assert!(validate_receipt(&receipt, &test_cluster()).is_err());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn validate_receipt_cluster_mismatch() {
        let dir = std::env::temp_dir().join(format!("backup-cluster-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);

        let receipt = write_backup_directory(
            &[],
            &test_cluster(),
            BackupSelection::namespace(vec!["ns".to_string()]),
            vec![],
            &dir,
            "run1",
        )
        .unwrap();

        let wrong = ClusterIdentity {
            api_server: "x".to_string(),
            kube_system_uid: "wrong".to_string(),
        };
        assert!(validate_receipt(&receipt, &wrong).is_err());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn receipt_roundtrip() {
        let receipt = BackupReceipt {
            root: "/tmp/backup".to_string(),
            manifest_sha256: "abc".to_string(),
            tree_sha256: "def".to_string(),
            resource_set_sha256: "ghi".to_string(),
            resource_count: 5,
            contains_secret_data: true,
            created_at: "t".to_string(),
        };
        let json = serde_json::to_string(&receipt).unwrap();
        let loaded: BackupReceipt = serde_json::from_str(&json).unwrap();
        assert_eq!(loaded.tree_sha256, "def");
    }

    // ── YAML sorted keys ──

    #[test]
    fn yaml_sorted_keys() {
        let v = serde_json::json!({"z": 1, "a": 2, "m": {"z": 3, "a": 4}});
        let yaml = json_to_sorted_yaml(&v).unwrap();
        let a_pos = yaml.find("a:").unwrap();
        let z_pos = yaml.find("z:").unwrap();
        assert!(a_pos < z_pos, "keys must be sorted: a before z");
    }

    // ── Async tower tests ──

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
            "apiVersion": "v1", "kind": "Status", "metadata": {},
            "status": "Failure", "reason": reason, "code": code
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
        m
    }

    fn configmap_obj(name: &str, ns: &str, uid: &str) -> serde_json::Value {
        serde_json::json!({
            "apiVersion": "v1", "kind": "ConfigMap",
            "metadata": { "name": name, "namespace": ns, "uid": uid, "resourceVersion": "1", "creationTimestamp": "2026-01-01T00:00:00Z" },
            "data": {"key": "value"}
        })
    }

    #[tokio::test]
    async fn fetch_200_captures() {
        let count = Arc::new(AtomicUsize::new(0));
        let c = count.clone();
        let (svc, handle) = tower_test::mock::pair::<http::Request<Body>, http::Response<Body>>();
        let s = tokio::spawn(async move {
            let mut h = pin!(handle);
            while let Some((req, send)) = h.next_request().await {
                c.fetch_add(1, Ordering::SeqCst);
                assert!(
                    req.uri()
                        .to_string()
                        .contains("/namespaces/ns/configmaps/cm1")
                );
                send.send_response(mock_json_response(configmap_obj("cm1", "ns", "uid-cm")));
            }
        });
        let client = ::kube::Client::new(svc, "default");
        let candidates = vec![make_candidate(
            "",
            "v1",
            "ConfigMap",
            Some("ns"),
            "cm1",
            "uid-cm",
        )];
        let (resources, secrets) = fetch_backup_resources(&client, &candidates, &test_gvk_map())
            .await
            .unwrap();
        drop(client);
        s.abort();
        assert_eq!(resources.len(), 1);
        assert_eq!(resources[0].state, BackupResourceState::Captured);
        assert!(resources[0].raw.is_some());
        assert!(!secrets);
        assert_eq!(count.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn fetch_404_absent() {
        let (svc, handle) = tower_test::mock::pair::<http::Request<Body>, http::Response<Body>>();
        let s = tokio::spawn(async move {
            let mut h = pin!(handle);
            while let Some((_, send)) = h.next_request().await {
                send.send_response(mock_status_response(404, "NotFound"));
            }
        });
        let client = ::kube::Client::new(svc, "default");
        let (resources, _) = fetch_backup_resources(
            &client,
            &[make_candidate(
                "",
                "v1",
                "ConfigMap",
                Some("ns"),
                "cm1",
                "uid-cm",
            )],
            &test_gvk_map(),
        )
        .await
        .unwrap();
        drop(client);
        s.abort();
        assert_eq!(resources[0].state, BackupResourceState::AlreadyAbsent);
    }

    #[tokio::test]
    async fn fetch_403_one_request() {
        let count = Arc::new(AtomicUsize::new(0));
        let c = count.clone();
        let (svc, handle) = tower_test::mock::pair::<http::Request<Body>, http::Response<Body>>();
        let s = tokio::spawn(async move {
            let mut h = pin!(handle);
            while let Some((_, send)) = h.next_request().await {
                c.fetch_add(1, Ordering::SeqCst);
                send.send_response(mock_status_response(403, "Forbidden"));
            }
        });
        let client = ::kube::Client::new(svc, "default");
        let result = fetch_backup_resources(
            &client,
            &[make_candidate(
                "",
                "v1",
                "ConfigMap",
                Some("ns"),
                "cm1",
                "uid-cm",
            )],
            &test_gvk_map(),
        )
        .await;
        drop(client);
        s.abort();
        assert!(result.is_err());
        assert_eq!(count.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn fetch_500_retries() {
        let count = Arc::new(AtomicUsize::new(0));
        let c = count.clone();
        let (svc, handle) = tower_test::mock::pair::<http::Request<Body>, http::Response<Body>>();
        let s = tokio::spawn(async move {
            let mut h = pin!(handle);
            while let Some((_, send)) = h.next_request().await {
                c.fetch_add(1, Ordering::SeqCst);
                send.send_response(mock_status_response(500, "InternalServerError"));
            }
        });
        let client = ::kube::Client::new(svc, "default");
        let result = fetch_backup_resources(
            &client,
            &[make_candidate(
                "",
                "v1",
                "ConfigMap",
                Some("ns"),
                "cm1",
                "uid-cm",
            )],
            &test_gvk_map(),
        )
        .await;
        drop(client);
        s.abort();
        assert!(result.is_err());
        assert_eq!(count.load(Ordering::SeqCst), 3);
    }

    #[tokio::test]
    async fn fetch_wrong_identity_fails() {
        let (svc, handle) = tower_test::mock::pair::<http::Request<Body>, http::Response<Body>>();
        let s = tokio::spawn(async move {
            let mut h = pin!(handle);
            while let Some((_, send)) = h.next_request().await {
                send.send_response(mock_json_response(serde_json::json!({
                    "apiVersion": "v1", "kind": "Secret",
                    "metadata": {"name": "cm1", "namespace": "ns", "uid": "uid-cm", "resourceVersion": "1", "creationTimestamp": "2026-01-01T00:00:00Z"},
                })));
            }
        });
        let client = ::kube::Client::new(svc, "default");
        let result = fetch_backup_resources(
            &client,
            &[make_candidate(
                "",
                "v1",
                "ConfigMap",
                Some("ns"),
                "cm1",
                "uid-cm",
            )],
            &test_gvk_map(),
        )
        .await;
        drop(client);
        s.abort();
        assert!(format!("{:#}", result.unwrap_err()).contains("kind mismatch"));
    }

    #[tokio::test]
    async fn fetch_gvk_miss_zero_requests() {
        let count = Arc::new(AtomicUsize::new(0));
        let c = count.clone();
        let (svc, handle) = tower_test::mock::pair::<http::Request<Body>, http::Response<Body>>();
        let s = tokio::spawn(async move {
            let mut h = pin!(handle);
            while let Some((_, send)) = h.next_request().await {
                c.fetch_add(1, Ordering::SeqCst);
                send.send_response(mock_status_response(200, "OK"));
            }
        });
        let client = ::kube::Client::new(svc, "default");
        let result = fetch_backup_resources(
            &client,
            &[make_candidate(
                "",
                "v2beta1",
                "ConfigMap",
                Some("ns"),
                "cm1",
                "uid-cm",
            )],
            &test_gvk_map(),
        )
        .await;
        drop(client);
        s.abort();
        assert!(result.is_err());
        assert_eq!(count.load(Ordering::SeqCst), 0);
    }
}
