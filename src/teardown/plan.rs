use anyhow::Context;
use serde::{Deserialize, Serialize};

use crate::kube::resource::ResourceId;

// ──────────────────────────────────────────────────────────────
//  Observed identity — guarantees UID is present
// ──────────────────────────────────────────────────────────────

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ObservedResourceIdentity {
    pub resource: ResourceId,
    pub uid: String,
}

impl ObservedResourceIdentity {
    pub fn from_resource_id(rid: &ResourceId) -> Option<Self> {
        rid.uid.as_ref().map(|uid| Self {
            resource: rid.clone(),
            uid: uid.clone(),
        })
    }
}

// ──────────────────────────────────────────────────────────────
//  Operator generation identity
// ──────────────────────────────────────────────────────────────

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum OperatorGenerationIdentity {
    OlmPackage {
        package_name: String,
        install_namespace: String,
    },
    Unverifiable {
        reason: String,
    },
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct OperatorIdentitySnapshot {
    pub generation_identity: OperatorGenerationIdentity,
    pub operator_id: crate::analyzers::olm::OperatorId,
    pub csv_name: String,
    pub csv: ObservedResourceIdentity,
    pub subscriptions: Vec<ObservedResourceIdentity>,
    pub controller_deployments: Vec<ObservedResourceIdentity>,
    pub service_accounts: Vec<ObservedResourceIdentity>,
    pub owned_crds: Vec<String>,
    pub required_crds: Vec<String>,
}

// ──────────────────────────────────────────────────────────────
//  Cluster identity
// ──────────────────────────────────────────────────────────────

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClusterIdentity {
    /// Diagnostic / secondary check
    pub api_server: String,
    /// Trust anchor for identity equality (kube-system namespace UID)
    pub kube_system_uid: String,
}

impl ClusterIdentity {
    pub fn matches(&self, other: &ClusterIdentity) -> bool {
        self.kube_system_uid == other.kube_system_uid
    }
}

// ──────────────────────────────────────────────────────────────
//  Saved teardown plan — reusable across clusters, no UIDs
// ──────────────────────────────────────────────────────────────

#[allow(dead_code)]
pub const SAVED_PLAN_SCHEMA_VERSION: u32 = 1;

#[derive(Clone, Debug, Serialize, Deserialize)]
#[allow(dead_code)]
pub struct SavedTeardownPlan {
    pub schema_version: u32,
    pub target: SavedOperatorTarget,
    pub teardown_decisions: Vec<SavedDecision>,
    pub residual_decisions: Vec<SavedDecision>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[allow(dead_code)]
pub struct SavedOperatorTarget {
    pub package_name: String,
    pub install_namespace: String,
    pub csv_name_pattern: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[allow(dead_code)]
pub struct SavedDecision {
    pub match_spec: ResourceMatch,
    pub action: SavedAction,
    pub approval: ApprovalKind,
    pub basis: DecisionBasis,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[allow(dead_code)]
pub struct ResourceMatch {
    pub group: Option<String>,
    pub kind: String,
    pub namespace: Option<String>,
    pub name: String,
}

impl ResourceMatch {
    #[allow(dead_code)]
    pub fn from_resource_id(rid: &ResourceId) -> Self {
        Self {
            group: if rid.group.is_empty() {
                None
            } else {
                Some(rid.group.clone())
            },
            kind: rid.kind.clone(),
            namespace: rid.namespace.clone(),
            name: rid.name.clone(),
        }
    }

    #[allow(dead_code)]
    pub fn matches(&self, rid: &ResourceId) -> bool {
        // group=None matches core group (empty string) only, not a wildcard
        let group_ok = match &self.group {
            Some(g) => &rid.group == g,
            None => rid.group.is_empty(),
        };
        group_ok
            && self.kind == rid.kind
            && self.namespace == rid.namespace
            && self.name == rid.name
    }

    pub fn validate(&self) -> Result<(), String> {
        if self.kind.is_empty() || self.kind == "*" {
            return Err(format!("invalid kind: {:?}", self.kind));
        }
        if self.name.is_empty() || self.name == "*" {
            return Err(format!("invalid name: {:?}", self.name));
        }
        if self.group.as_deref() == Some("*") {
            return Err("wildcard group not allowed".to_string());
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[allow(dead_code)]
pub enum SavedAction {
    Delete,
    Keep,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[allow(dead_code)]
pub enum ApprovalKind {
    Explicit,
    ExplicitUnattributed,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[allow(dead_code)]
pub struct DecisionBasis {
    pub provenance: Option<String>,
    pub review_category: Option<String>,
    pub discovery_source: Option<String>,
    pub decisive_evidence: Vec<SavedEvidenceSignature>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[allow(dead_code)]
pub enum SavedEvidenceSignature {
    OwnerReference {
        group: String,
        kind: String,
        namespace: Option<String>,
        name: String,
    },
    Label {
        key: String,
        value: String,
    },
    ManagedFieldManager {
        manager: String,
    },
    ApiOwner {
        api_owner_key: String,
    },
    ServiceAccount {
        namespace: String,
        name: String,
    },
}

// ──────────────────────────────────────────────────────────────
//  ReviewMetadata — attached to Action::Review
// ──────────────────────────────────────────────────────────────

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ReviewMetadata {
    pub category: Option<ReviewCategorySer>,
    pub approval_class: Option<DeleteApprovalClassSer>,
    pub provenance: Option<ProvenanceSer>,
    pub discovery_source: Option<DiscoverySourceSer>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub decisive_label_pairs: Vec<(String, String)>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum ReviewCategorySer {
    OperandRoot,
    OperandDescendant,
    OperandIndependent,
    Ancillary,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum DeleteApprovalClassSer {
    Standard,
    ExplicitOnly,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum ProvenanceSer {
    Managed,
    LikelyManaged,
    Unknown,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum DiscoverySourceSer {
    Direct,
    RelatedLinked,
    RelatedLabelOnly,
}

// ──────────────────────────────────────────────────────────────
//  ExecutionPlan — cluster-bound plan with UIDs for safe replay
// ──────────────────────────────────────────────────────────────

pub const EXECUTION_PLAN_SCHEMA_VERSION: u32 = 1;

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExecutionPlan {
    pub schema_version: u32,
    pub cluster_identity: ClusterIdentity,
    pub created_at: String,
    pub targets: Vec<SavedOperatorTarget>,
    pub prune_crds: bool,
    pub approve_scopes: Vec<ApprovalScopeValue>,
    pub approve_resources: Vec<String>,
    pub keep_resources: Vec<String>,
    pub phases: Vec<ExecutionPhase>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum ApprovalScopeValue {
    #[serde(rename = "root")]
    Root,
    #[serde(rename = "independent")]
    Independent,
    #[serde(rename = "label-only")]
    LabelOnly,
    #[serde(rename = "operator-group")]
    OperatorGroup,
}

impl ApprovalScopeValue {
    pub fn cli_arg(&self) -> &'static str {
        match self {
            Self::Root => "root",
            Self::Independent => "independent",
            Self::LabelOnly => "label-only",
            Self::OperatorGroup => "operator-group",
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum ExecutionAction {
    #[serde(rename = "DELETE")]
    Delete,
    #[serde(rename = "KEEP")]
    Keep,
    #[serde(rename = "EXPECT")]
    Expect,
    #[serde(rename = "REVIEW")]
    Review,
    #[serde(rename = "WAIT")]
    Wait,
}

impl std::fmt::Display for ExecutionAction {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Delete => write!(f, "DELETE"),
            Self::Keep => write!(f, "KEEP"),
            Self::Expect => write!(f, "EXPECT"),
            Self::Review => write!(f, "REVIEW"),
            Self::Wait => write!(f, "WAIT"),
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExecutionPhase {
    pub phase: u32,
    pub name: String,
    pub resources: Vec<ExecutionResource>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExecutionResource {
    pub group: String,
    pub kind: String,
    pub namespace: Option<String>,
    pub name: String,
    pub uid: Option<String>,
    pub action: ExecutionAction,
}

pub fn save_execution_plan(plan: &ExecutionPlan, path: &str) -> anyhow::Result<()> {
    use std::io::Write;
    let parent = std::path::Path::new(path)
        .parent()
        .ok_or_else(|| anyhow::anyhow!("No parent directory for {}", path))?;
    let tmp_path = parent.join(format!(".tmp_exec_plan_{}", std::process::id()));
    let json = serde_json::to_string_pretty(plan)?;
    {
        let mut f = std::fs::File::create(&tmp_path)
            .with_context(|| format!("Failed to create temp file: {}", tmp_path.display()))?;
        f.write_all(json.as_bytes())?;
        f.sync_all()?;
    }
    std::fs::rename(&tmp_path, path)
        .with_context(|| format!("Failed to rename {} -> {}", tmp_path.display(), path))?;
    if let Ok(dir) = std::fs::File::open(parent) {
        let _ = dir.sync_all();
    }
    Ok(())
}

pub fn load_execution_plan(path: &str) -> anyhow::Result<ExecutionPlan> {
    let data = std::fs::read_to_string(path)
        .with_context(|| format!("Failed to read execution plan: {}", path))?;
    let plan: ExecutionPlan = serde_json::from_str(&data)
        .with_context(|| format!("Failed to parse execution plan: {}", path))?;
    if plan.schema_version != EXECUTION_PLAN_SCHEMA_VERSION {
        anyhow::bail!(
            "Execution plan schema version {} is not supported (expected {})",
            plan.schema_version,
            EXECUTION_PLAN_SCHEMA_VERSION
        );
    }
    // Validate approve_resources contain no scope tokens
    const SCOPE_TOKENS: &[&str] = &["root", "independent", "label-only", "operator-group", "all"];
    for spec in &plan.approve_resources {
        if SCOPE_TOKENS.contains(&spec.as_str()) {
            anyhow::bail!(
                "approve_resources contains scope token '{}' — use approve_scopes instead",
                spec
            );
        }
    }
    for spec in &plan.keep_resources {
        if SCOPE_TOKENS.contains(&spec.as_str()) {
            anyhow::bail!(
                "keep_resources contains scope token '{}' — this is not valid",
                spec
            );
        }
    }
    Ok(plan)
}

/// Validate an execution plan against a freshly generated plan.
/// Detects resource additions, removals, and UID changes.
pub fn validate_execution_plan_against_fresh(
    saved: &ExecutionPlan,
    fresh: &ExecutionPlan,
) -> Result<(), Vec<String>> {
    use std::collections::BTreeSet;

    let mut errors = Vec::new();

    // Phase count
    if saved.phases.len() != fresh.phases.len() {
        errors.push(format!(
            "Phase count drift: saved {}, fresh {}",
            saved.phases.len(),
            fresh.phases.len()
        ));
    }

    // Build sets: (phase, action, group, kind, namespace, name)
    type ResourceKey = (u32, String, String, String, Option<String>, String);

    let build_set = |plan: &ExecutionPlan| -> BTreeSet<ResourceKey> {
        plan.phases
            .iter()
            .flat_map(|p| {
                p.resources.iter().map(move |r| {
                    (
                        p.phase,
                        r.action.to_string(),
                        r.group.clone(),
                        r.kind.clone(),
                        r.namespace.clone(),
                        r.name.clone(),
                    )
                })
            })
            .collect()
    };

    let saved_set = build_set(saved);
    let fresh_set = build_set(fresh);

    // Added in fresh (not in saved)
    for item in fresh_set.difference(&saved_set) {
        errors.push(format!(
            "Resource added since plan: phase {}, {} {}/{} in {:?}",
            item.0, item.1, item.3, item.5, item.4
        ));
    }

    // Removed from fresh (was in saved)
    for item in saved_set.difference(&fresh_set) {
        errors.push(format!(
            "Resource missing from cluster: phase {}, {} {}/{} in {:?}",
            item.0, item.1, item.3, item.5, item.4
        ));
    }

    // UID changes for matching resources
    let saved_uid_map: std::collections::HashMap<
        (String, String, Option<String>, String),
        Option<String>,
    > = saved
        .phases
        .iter()
        .flat_map(|p| {
            p.resources.iter().map(|r| {
                (
                    (
                        r.group.clone(),
                        r.kind.clone(),
                        r.namespace.clone(),
                        r.name.clone(),
                    ),
                    r.uid.clone(),
                )
            })
        })
        .collect();

    for phase in &fresh.phases {
        for r in &phase.resources {
            let key = (
                r.group.clone(),
                r.kind.clone(),
                r.namespace.clone(),
                r.name.clone(),
            );
            if let Some(saved_uid) = saved_uid_map.get(&key)
                && saved_uid.is_some()
                && r.uid.is_some()
                && saved_uid != &r.uid
            {
                errors.push(format!(
                    "UID changed for {}/{} in {:?}: saved {:?}, fresh {:?}",
                    r.kind, r.name, r.namespace, saved_uid, r.uid
                ));
            }
        }
    }

    if errors.is_empty() {
        Ok(())
    } else {
        Err(errors)
    }
}

// ──────────────────────────────────────────────────────────────
//  PlannedPreserved — for ExecutionResult kept/reviewed tracking
// ──────────────────────────────────────────────────────────────

#[derive(Clone, Debug)]
pub struct PlannedPreserved {
    pub resource: ResourceId,
    pub reason: String,
    pub metadata: Option<ReviewMetadata>,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_cluster_identity(uid: &str) -> ClusterIdentity {
        ClusterIdentity {
            api_server: "https://test:6443".to_string(),
            kube_system_uid: uid.to_string(),
        }
    }

    #[allow(clippy::type_complexity)]
    fn make_exec_plan(
        cluster_uid: &str,
        resources: Vec<(
            &str,
            &str,
            Option<&str>,
            &str,
            Option<&str>,
            ExecutionAction,
        )>,
    ) -> ExecutionPlan {
        let phase_resources: Vec<ExecutionResource> = resources
            .into_iter()
            .map(|(group, kind, ns, name, uid, action)| ExecutionResource {
                group: group.to_string(),
                kind: kind.to_string(),
                namespace: ns.map(|s| s.to_string()),
                name: name.to_string(),
                uid: uid.map(|s| s.to_string()),
                action,
            })
            .collect();
        ExecutionPlan {
            schema_version: EXECUTION_PLAN_SCHEMA_VERSION,
            cluster_identity: make_cluster_identity(cluster_uid),
            created_at: "2026-01-01T00:00:00Z".to_string(),
            targets: vec![SavedOperatorTarget {
                package_name: "test-op".to_string(),
                install_namespace: "test-ns".to_string(),
                csv_name_pattern: "test.v1".to_string(),
            }],
            prune_crds: false,
            approve_scopes: vec![ApprovalScopeValue::Root],
            approve_resources: vec![],
            keep_resources: vec![],
            phases: vec![ExecutionPhase {
                phase: 1,
                name: "Phase 1".to_string(),
                resources: phase_resources,
            }],
        }
    }

    #[test]
    fn drift_detection_no_drift() {
        let plan = make_exec_plan(
            "uid-1",
            vec![(
                "",
                "Deployment",
                Some("ns"),
                "dep1",
                Some("uid-a"),
                ExecutionAction::Delete,
            )],
        );
        let result = validate_execution_plan_against_fresh(&plan, &plan);
        assert!(result.is_ok(), "identical plans must not drift");
    }

    #[test]
    fn drift_detection_resource_added() {
        let saved = make_exec_plan(
            "uid-1",
            vec![(
                "",
                "Deployment",
                Some("ns"),
                "dep1",
                Some("uid-a"),
                ExecutionAction::Delete,
            )],
        );
        let fresh = make_exec_plan(
            "uid-1",
            vec![
                (
                    "",
                    "Deployment",
                    Some("ns"),
                    "dep1",
                    Some("uid-a"),
                    ExecutionAction::Delete,
                ),
                (
                    "",
                    "Service",
                    Some("ns"),
                    "svc1",
                    Some("uid-b"),
                    ExecutionAction::Delete,
                ),
            ],
        );
        let result = validate_execution_plan_against_fresh(&saved, &fresh);
        assert!(result.is_err());
        let errors = result.unwrap_err();
        assert!(errors.iter().any(|e| e.contains("added since plan")));
    }

    #[test]
    fn drift_detection_resource_removed() {
        let saved = make_exec_plan(
            "uid-1",
            vec![
                (
                    "",
                    "Deployment",
                    Some("ns"),
                    "dep1",
                    Some("uid-a"),
                    ExecutionAction::Delete,
                ),
                (
                    "",
                    "Service",
                    Some("ns"),
                    "svc1",
                    Some("uid-b"),
                    ExecutionAction::Delete,
                ),
            ],
        );
        let fresh = make_exec_plan(
            "uid-1",
            vec![(
                "",
                "Deployment",
                Some("ns"),
                "dep1",
                Some("uid-a"),
                ExecutionAction::Delete,
            )],
        );
        let result = validate_execution_plan_against_fresh(&saved, &fresh);
        assert!(result.is_err());
        let errors = result.unwrap_err();
        assert!(errors.iter().any(|e| e.contains("missing from cluster")));
    }

    #[test]
    fn drift_detection_uid_changed() {
        let saved = make_exec_plan(
            "uid-1",
            vec![(
                "",
                "Deployment",
                Some("ns"),
                "dep1",
                Some("uid-a"),
                ExecutionAction::Delete,
            )],
        );
        let fresh = make_exec_plan(
            "uid-1",
            vec![(
                "",
                "Deployment",
                Some("ns"),
                "dep1",
                Some("uid-b"),
                ExecutionAction::Delete,
            )],
        );
        let result = validate_execution_plan_against_fresh(&saved, &fresh);
        assert!(result.is_err());
        let errors = result.unwrap_err();
        assert!(errors.iter().any(|e| e.contains("UID changed")));
    }

    #[test]
    fn cluster_identity_mismatch() {
        let id1 = make_cluster_identity("uid-1");
        let id2 = make_cluster_identity("uid-2");
        assert!(!id1.matches(&id2));
        assert!(id1.matches(&id1));
    }

    #[test]
    fn deny_unknown_fields_rejects_extra() {
        let json = r#"{
            "schema_version": 1,
            "cluster_identity": {"api_server": "https://x", "kube_system_uid": "u"},
            "created_at": "2026-01-01",
            "targets": [],
            "prune_crds": false,
            "approve_scopes": [],
            "approve_resources": [],
            "keep_resources": [],
            "phases": [],
            "extra_field": true
        }"#;
        let result: Result<ExecutionPlan, _> = serde_json::from_str(json);
        assert!(
            result.is_err(),
            "deny_unknown_fields must reject extra fields"
        );
    }

    #[test]
    fn scope_token_in_approve_resources_rejected() {
        let dir = std::env::temp_dir().join(format!("scope-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("plan.json");
        let json = r#"{
            "schema_version": 1,
            "cluster_identity": {"api_server": "https://x", "kube_system_uid": "u"},
            "created_at": "2026-01-01",
            "targets": [],
            "prune_crds": false,
            "approve_scopes": [],
            "approve_resources": ["root"],
            "keep_resources": [],
            "phases": []
        }"#;
        std::fs::write(&path, json).unwrap();
        let result = load_execution_plan(&path.to_string_lossy());
        assert!(
            result.is_err(),
            "scope token in approve_resources must be rejected"
        );
        let err = result.unwrap_err().to_string();
        assert!(err.contains("scope token"), "error: {}", err);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn save_failure_is_error() {
        let plan = make_exec_plan("uid-1", vec![]);
        let result = save_execution_plan(&plan, "/nonexistent/dir/plan.json");
        assert!(result.is_err(), "save to nonexistent dir must fail");
    }

    #[test]
    fn execution_plan_roundtrip() {
        let dir = std::env::temp_dir().join(format!("exec-rt-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("plan.json");
        let plan = make_exec_plan(
            "uid-1",
            vec![(
                "apps",
                "Deployment",
                Some("ns"),
                "dep1",
                Some("uid-a"),
                ExecutionAction::Delete,
            )],
        );
        save_execution_plan(&plan, &path.to_string_lossy()).unwrap();
        let loaded = load_execution_plan(&path.to_string_lossy()).unwrap();
        assert_eq!(loaded.schema_version, 1);
        assert_eq!(loaded.cluster_identity.kube_system_uid, "uid-1");
        assert_eq!(
            loaded.phases[0].resources[0].action,
            ExecutionAction::Delete
        );
        assert_eq!(loaded.approve_scopes, vec![ApprovalScopeValue::Root]);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn typed_action_serialization() {
        let r = ExecutionResource {
            group: "apps".to_string(),
            kind: "Deployment".to_string(),
            namespace: Some("ns".to_string()),
            name: "dep1".to_string(),
            uid: Some("uid-a".to_string()),
            action: ExecutionAction::Delete,
        };
        let json = serde_json::to_string(&r).unwrap();
        assert!(json.contains(r#""action":"DELETE""#), "json: {}", json);
        let rt: ExecutionResource = serde_json::from_str(&json).unwrap();
        assert_eq!(rt.action, ExecutionAction::Delete);
    }

    #[test]
    fn phase_count_drift_detected() {
        let mut saved = make_exec_plan("uid-1", vec![]);
        saved.phases.push(ExecutionPhase {
            phase: 2,
            name: "Phase 2".to_string(),
            resources: vec![],
        });
        let fresh = make_exec_plan("uid-1", vec![]);
        let result = validate_execution_plan_against_fresh(&saved, &fresh);
        assert!(result.is_err());
        let errors = result.unwrap_err();
        assert!(errors.iter().any(|e| e.contains("Phase count drift")));
    }
}
