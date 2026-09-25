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
pub struct ExecutionPlan {
    pub schema_version: u32,
    pub cluster_id: String,
    pub created_at: String,
    pub targets: Vec<SavedOperatorTarget>,
    pub prune_crds: bool,
    pub approve_scopes: Vec<String>,
    pub approve_resources: Vec<String>,
    pub keep_resources: Vec<String>,
    pub phases: Vec<ExecutionPhase>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ExecutionPhase {
    pub phase: u32,
    pub name: String,
    pub resources: Vec<ExecutionResource>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ExecutionResource {
    pub group: String,
    pub kind: String,
    pub namespace: Option<String>,
    pub name: String,
    pub uid: Option<String>,
    pub action: String,
    pub approval: Option<String>,
    pub basis: Option<String>,
}

pub fn save_execution_plan(plan: &ExecutionPlan, path: &str) -> anyhow::Result<()> {
    let json = serde_json::to_string_pretty(plan)?;
    std::fs::write(path, json)?;
    Ok(())
}

pub fn load_execution_plan(path: &str) -> anyhow::Result<ExecutionPlan> {
    let data = std::fs::read_to_string(path)?;
    let plan: ExecutionPlan = serde_json::from_str(&data)?;
    if plan.schema_version != EXECUTION_PLAN_SCHEMA_VERSION {
        anyhow::bail!(
            "Execution plan schema version {} is not supported (expected {})",
            plan.schema_version,
            EXECUTION_PLAN_SCHEMA_VERSION
        );
    }
    Ok(plan)
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
