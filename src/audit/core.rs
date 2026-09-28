use std::collections::{BTreeMap, HashMap, HashSet};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::kube::resource::{ClusterSnapshot, ResourceId, SpecRefSourceSer};
use crate::teardown::plan::{ExecutionAction, ExecutionPlan, ExecutionResource};

// ──────────────────────────────────────────────────────────────
//  Classification enum
// ──────────────────────────────────────────────────────────────

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize, PartialOrd, Ord)]
pub enum AuditClassification {
    PlannedDirectDelete,
    ExpectedControllerCleanup,
    OwnerRefGcDescendant,
    DerivedSideEffect,
    Recreated,
    OrphanOwnerRef,
    DanglingSpecReference,
    NewlyTerminating,
    UnexplainedChange,
}

impl std::fmt::Display for AuditClassification {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::PlannedDirectDelete => write!(f, "PlannedDirectDelete"),
            Self::ExpectedControllerCleanup => write!(f, "ExpectedControllerCleanup"),
            Self::OwnerRefGcDescendant => write!(f, "OwnerRefGcDescendant"),
            Self::DerivedSideEffect => write!(f, "DerivedSideEffect"),
            Self::Recreated => write!(f, "Recreated"),
            Self::OrphanOwnerRef => write!(f, "OrphanOwnerRef"),
            Self::DanglingSpecReference => write!(f, "DanglingSpecReference"),
            Self::NewlyTerminating => write!(f, "NewlyTerminating"),
            Self::UnexplainedChange => write!(f, "UnexplainedChange"),
        }
    }
}

// ──────────────────────────────────────────────────────────────
//  Identity layers
// ──────────────────────────────────────────────────────────────

#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub struct LogicalIdentity {
    pub group: String,
    pub kind: String,
    pub namespace: Option<String>,
    pub name: String,
}

impl LogicalIdentity {
    #[allow(dead_code)]
    pub fn from_resource_id(id: &ResourceId) -> Self {
        Self {
            group: id.group.clone(),
            kind: id.kind.clone(),
            namespace: id.namespace.clone(),
            name: id.name.clone(),
        }
    }
}

impl std::fmt::Display for LogicalIdentity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}/{}", self.kind, self.name)
    }
}

#[allow(dead_code)]
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub struct PhysicalId {
    pub uid: String,
    pub identity: LogicalIdentity,
}

// ──────────────────────────────────────────────────────────────
//  Observation set — 3-layer input for audit
// ──────────────────────────────────────────────────────────────

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AuditObservation {
    pub group: String,
    pub version: String,
    pub resource: String,
    pub kind: String,
    pub namespace: Option<String>,
    pub name: String,
    pub uid: Option<String>,
    pub owner_refs: Vec<ObsOwnerRef>,
    pub spec_refs: Vec<ObsSpecRef>,
    pub deletion_timestamp: Option<String>,
    pub finalizers: Option<Vec<String>>,
    pub labels: HashMap<String, String>,
    pub annotations: HashMap<String, String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ObsOwnerRef {
    pub api_version: String,
    pub kind: String,
    pub name: String,
    pub uid: String,
    #[serde(default)]
    pub controller: bool,
    #[serde(default)]
    pub block_owner_deletion: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ObsSpecRef {
    pub target_kind: String,
    pub target_name: String,
    pub field_path: String,
    pub target_group: Option<String>,
    pub target_namespace: Option<String>,
    pub source: SpecRefSourceLabel,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum SpecRefSourceLabel {
    Typed,
    Heuristic,
    Unknown,
}

impl std::fmt::Display for SpecRefSourceLabel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Typed => write!(f, "typed"),
            Self::Heuristic => write!(f, "heuristic"),
            Self::Unknown => write!(f, "unknown"),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum AbsenceCoverage {
    Complete,
    Incomplete {
        incomplete_namespaces: Vec<String>,
        scan_warning_count: usize,
    },
}

impl AbsenceCoverage {
    pub fn is_complete(&self) -> bool {
        matches!(self, Self::Complete)
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AuditObservationSet {
    pub observations: Vec<AuditObservation>,
    pub cluster_url: String,
    pub taken_at: String,
    pub capability_warnings: Vec<String>,
    pub has_deletion_timestamp: bool,
    pub has_spec_ref_source: bool,
    pub absence_coverage: AbsenceCoverage,
}

// ──────────────────────────────────────────────────────────────
//  Physical entity — merged from observations
// ──────────────────────────────────────────────────────────────

#[derive(Clone, Debug)]
struct PhysicalEntity {
    uid: String,
    identity: LogicalIdentity,
    owner_refs: Vec<ObsOwnerRef>,
    spec_refs: Vec<ObsSpecRef>,
    deletion_timestamp: Option<String>,
    finalizers: Option<Vec<String>>,
    labels: HashMap<String, String>,
    observed_apis: Vec<(String, String, String)>, // (group, version, resource)
}

fn build_physical_entities(obs: &AuditObservationSet) -> HashMap<String, PhysicalEntity> {
    // Sort observations by stable key before folding to ensure canonical identity is deterministic
    let mut sorted_obs: Vec<&AuditObservation> = obs
        .observations
        .iter()
        .filter(|o| o.uid.as_ref().is_some_and(|u| !u.is_empty()))
        .collect();
    sorted_obs.sort_by(|a, b| {
        (
            &a.group,
            &a.version,
            &a.resource,
            &a.kind,
            &a.namespace,
            &a.name,
        )
            .cmp(&(
                &b.group,
                &b.version,
                &b.resource,
                &b.kind,
                &b.namespace,
                &b.name,
            ))
    });

    let mut entities: HashMap<String, PhysicalEntity> = HashMap::new();
    for o in sorted_obs {
        let uid = o.uid.as_ref().unwrap().clone();
        let api = (o.group.clone(), o.version.clone(), o.resource.clone());
        if let Some(ent) = entities.get_mut(&uid) {
            if !ent.observed_apis.contains(&api) {
                ent.observed_apis.push(api);
            }
        } else {
            entities.insert(
                uid.clone(),
                PhysicalEntity {
                    uid: uid.clone(),
                    identity: LogicalIdentity {
                        group: o.group.clone(),
                        kind: o.kind.clone(),
                        namespace: o.namespace.clone(),
                        name: o.name.clone(),
                    },
                    owner_refs: o.owner_refs.clone(),
                    spec_refs: o.spec_refs.clone(),
                    deletion_timestamp: o.deletion_timestamp.clone(),
                    finalizers: o.finalizers.clone(),
                    labels: o.labels.clone(),
                    observed_apis: vec![api],
                },
            );
        }
    }
    // Sort observed_apis for determinism
    for ent in entities.values_mut() {
        ent.observed_apis.sort();
    }
    entities
}

// ──────────────────────────────────────────────────────────────
//  UID-null fingerprint
// ──────────────────────────────────────────────────────────────

#[allow(dead_code)]
pub fn uid_null_fingerprint(o: &AuditObservation) -> String {
    let mut hasher = Sha256::new();
    hasher.update(o.group.as_bytes());
    hasher.update(b"|");
    hasher.update(o.kind.as_bytes());
    hasher.update(b"|");
    hasher.update(o.namespace.as_deref().unwrap_or("").as_bytes());
    hasher.update(b"|");
    hasher.update(o.name.as_bytes());
    let mut label_pairs: Vec<_> = o.labels.iter().collect();
    label_pairs.sort();
    for (k, v) in label_pairs {
        hasher.update(b"|");
        hasher.update(format!("{}={}", k, v).as_bytes());
    }
    format!("{:x}", hasher.finalize())[..24].to_string()
}

// ──────────────────────────────────────────────────────────────
//  Snapshot → ObservationSet adapter
// ──────────────────────────────────────────────────────────────

pub fn snapshot_to_observation_set(snap: &ClusterSnapshot) -> AuditObservationSet {
    let mut warnings = Vec::new();
    let has_deletion_ts = snap.schema_version >= Some(4);
    let has_spec_ref_source = snap.schema_version >= Some(4);

    if !has_deletion_ts {
        warnings.push("Snapshot predates schema v4: deletion_timestamp unavailable, newly-terminating classification suppressed.".to_string());
    }
    if !has_spec_ref_source {
        warnings.push(
            "Snapshot predates schema v4: spec_ref source (typed/heuristic) unavailable."
                .to_string(),
        );
    }

    // Propagate scan coverage warnings
    if !snap.scan_warnings.is_empty() {
        warnings.push(format!(
            "Snapshot had {} scan warnings (some API types may be missing)",
            snap.scan_warnings.len()
        ));
    }
    if let Some(scope) = &snap.scope {
        for inc in &scope.incomplete_namespaces {
            warnings.push(format!(
                "Namespace {} had incomplete scan ({} warnings)",
                inc.namespace,
                inc.warnings.len()
            ));
        }
    }

    // Prefer v4 observations if available; fall back to resources map
    let observations = if !snap.observations.is_empty() {
        snap.observations
            .iter()
            .map(|o| {
                let owner_refs = o
                    .owner_refs
                    .iter()
                    .map(|r| ObsOwnerRef {
                        api_version: r.api_version.clone(),
                        kind: r.kind.clone(),
                        name: r.name.clone(),
                        uid: r.uid.clone(),
                        controller: r.controller,
                        block_owner_deletion: r.block_owner_deletion,
                    })
                    .collect();
                let spec_refs = o
                    .spec_refs
                    .iter()
                    .map(|r| {
                        let source = match &r.source {
                            Some(SpecRefSourceSer::Typed) => SpecRefSourceLabel::Typed,
                            Some(SpecRefSourceSer::Heuristic) => SpecRefSourceLabel::Heuristic,
                            None => SpecRefSourceLabel::Unknown,
                        };
                        ObsSpecRef {
                            target_kind: r.target_kind.clone(),
                            target_name: r.target_name.clone(),
                            field_path: r.field_path.clone(),
                            target_group: r.target_group.clone(),
                            target_namespace: r.target_namespace.clone(),
                            source,
                        }
                    })
                    .collect();
                AuditObservation {
                    group: o.group.clone(),
                    version: o.version.clone(),
                    resource: o.resource.clone(),
                    kind: o.kind.clone(),
                    namespace: o.namespace.clone(),
                    name: o.name.clone(),
                    uid: o.uid.clone(),
                    owner_refs,
                    spec_refs,
                    deletion_timestamp: o.deletion_timestamp.clone(),
                    finalizers: o.finalizers.clone(),
                    labels: o.labels.clone(),
                    annotations: HashMap::new(),
                }
            })
            .collect()
    } else {
        snap.resources
            .values()
            .flat_map(|entry| {
                let apis = entry.observed_apis.as_ref();
                let api_list: Vec<(String, String, String)> = if let Some(apis) = apis {
                    apis.iter()
                        .map(|a| (a.group.clone(), a.version.clone(), a.resource.clone()))
                        .collect()
                } else {
                    vec![(
                        entry.id.group.clone(),
                        entry.id.version.clone(),
                        String::new(),
                    )]
                };
                api_list.into_iter().map(move |(group, version, resource)| {
                    let owner_refs = entry
                        .owner_refs
                        .iter()
                        .map(|r| ObsOwnerRef {
                            api_version: r.api_version.clone(),
                            kind: r.kind.clone(),
                            name: r.name.clone(),
                            uid: r.uid.clone(),
                            controller: r.controller,
                            block_owner_deletion: r.block_owner_deletion,
                        })
                        .collect();
                    let spec_refs = entry
                        .spec_refs
                        .iter()
                        .map(|r| {
                            let source = match &r.source {
                                Some(SpecRefSourceSer::Typed) => SpecRefSourceLabel::Typed,
                                Some(SpecRefSourceSer::Heuristic) => SpecRefSourceLabel::Heuristic,
                                None => SpecRefSourceLabel::Unknown,
                            };
                            ObsSpecRef {
                                target_kind: r.target_kind.clone(),
                                target_name: r.target_name.clone(),
                                field_path: r.field_path.clone(),
                                target_group: r.target_group.clone(),
                                target_namespace: r.target_namespace.clone(),
                                source,
                            }
                        })
                        .collect();
                    AuditObservation {
                        group,
                        version,
                        resource,
                        kind: entry.id.kind.clone(),
                        namespace: entry.id.namespace.clone(),
                        name: entry.id.name.clone(),
                        uid: entry.id.uid.clone(),
                        owner_refs,
                        spec_refs,
                        deletion_timestamp: entry.deletion_timestamp.clone(),
                        finalizers: entry.finalizers.clone(),
                        labels: entry.labels.clone(),
                        annotations: entry.annotations.clone(),
                    }
                })
            })
            .collect()
    };

    let absence_coverage = {
        let mut incomplete_ns = Vec::new();
        let mut warn_count = snap.scan_warnings.len();
        if let Some(scope) = &snap.scope {
            for inc in &scope.incomplete_namespaces {
                incomplete_ns.push(inc.namespace.clone());
                warn_count += inc.warnings.len();
            }
        }
        if incomplete_ns.is_empty() && snap.scan_warnings.is_empty() {
            AbsenceCoverage::Complete
        } else {
            AbsenceCoverage::Incomplete {
                incomplete_namespaces: incomplete_ns,
                scan_warning_count: warn_count,
            }
        }
    };

    AuditObservationSet {
        observations,
        cluster_url: snap.cluster_url.clone(),
        taken_at: snap.taken_at.clone(),
        capability_warnings: warnings,
        has_deletion_timestamp: has_deletion_ts,
        has_spec_ref_source,
        absence_coverage,
    }
}

// ──────────────────────────────────────────────────────────────
//  Report types
// ──────────────────────────────────────────────────────────────

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ClassifiedRemoval {
    pub uid: String,
    pub identity: LogicalIdentity,
    pub classification: AuditClassification,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub evidence: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub plan_operator: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub derived_detail: Option<DerivedDetail>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub observed_apis: Vec<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DerivedDetail {
    pub derived_type: String,
    pub evidence: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub related_uid: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RecreatedEntry {
    pub identity: LogicalIdentity,
    pub pre_uid: String,
    pub post_uid: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct OrphanOwnerRefEntry {
    pub uid: String,
    pub identity: LogicalIdentity,
    pub deleted_owner_kind: String,
    pub deleted_owner_name: String,
    pub deleted_owner_uid: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DanglingSpecRefEntry {
    pub source_uid: String,
    pub source_identity: LogicalIdentity,
    pub target_kind: String,
    pub target_name: String,
    pub field_path: String,
    pub ref_type: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub target_group: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub target_namespace: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TerminatingEntry {
    pub uid: String,
    pub identity: LogicalIdentity,
    pub deletion_timestamp: String,
    pub preexisting: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub finalizers: Option<Vec<String>>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ProviderOperandResult {
    pub identity: LogicalIdentity,
    pub uid: String,
    pub api_provider_operator: String,
    pub physical_classification: AuditClassification,
    pub evidence: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub provider_api_evidence: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub lifecycle_owner_evidence: Option<serde_json::Value>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub observed_versions: Vec<String>,
}

pub const AUDIT_SCHEMA_VERSION: u32 = 1;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AuditReport {
    pub schema_version: u32,
    pub before_taken_at: String,
    pub after_taken_at: String,
    pub cluster_url: String,
    pub plans_loaded: Vec<String>,
    pub capability_warnings: Vec<String>,
    pub layers: AuditLayers,
    pub classification_summary: BTreeMap<String, usize>,
    pub removals: Vec<ClassifiedRemoval>,
    pub recreated: Vec<RecreatedEntry>,
    pub closure: ClosureSummary,
    pub terminating: TerminatingSummary,
    pub orphan_owner_refs: Vec<OrphanOwnerRefEntry>,
    pub dangling_spec_refs: Vec<DanglingSpecRefEntry>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub provider_operand_results: Vec<ProviderOperandResult>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub plan_collision_warnings: Vec<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AuditLayers {
    pub raw_observations: RawObsLayer,
    pub physical_uids: PhysicalLayer,
    pub logical: LogicalLayer,
    pub uid_null: UidNullLayer,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RawObsLayer {
    pub pre: usize,
    pub post: usize,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PhysicalLayer {
    pub pre: usize,
    pub post: usize,
    pub removed: usize,
    pub added: usize,
    pub multi_observed: usize,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct LogicalLayer {
    pub pre: usize,
    pub post: usize,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct UidNullLayer {
    pub pre: usize,
    pub post: usize,
    pub removed_fingerprints: usize,
    pub added_fingerprints: usize,
    pub pre_fingerprint_collision_groups: usize,
    pub post_fingerprint_collision_groups: usize,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ClosureSummary {
    pub delete_seeds: usize,
    pub total_closure: usize,
    pub removed_in_closure: usize,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TerminatingSummary {
    pub newly_terminating: usize,
    pub preexisting_retained: usize,
    pub details: Vec<TerminatingEntry>,
}

// ──────────────────────────────────────────────────────────────
//  Plan action index — full identity verification [P0-2, P0-5]
// ──────────────────────────────────────────────────────────────

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
struct FullPlanKey {
    group: String,
    kind: String,
    namespace: Option<String>,
    name: String,
    uid: String,
}

impl FullPlanKey {
    fn from_resource(r: &ExecutionResource) -> Option<Self> {
        r.uid.as_ref().map(|uid| Self {
            group: r.group.clone(),
            kind: r.kind.clone(),
            namespace: r.namespace.clone(),
            name: r.name.clone(),
            uid: uid.clone(),
        })
    }

    fn matches_entity(&self, ent: &PhysicalEntity) -> bool {
        self.uid == ent.uid
            && self.kind == ent.identity.kind
            && self.namespace == ent.identity.namespace
            && self.name == ent.identity.name
            && (self.group == ent.identity.group
                || ent.observed_apis.iter().any(|(g, _, _)| *g == self.group))
    }
}

#[derive(Clone, Debug)]
struct PlanActionEntry {
    action: ExecutionAction,
    operator: String,
    full_key: FullPlanKey,
}

fn build_plan_action_index(
    plans: &[(String, ExecutionPlan)],
) -> (
    HashMap<String, Vec<PlanActionEntry>>,
    Vec<String>,
    HashSet<String>,
) {
    let mut uid_actions: HashMap<String, Vec<PlanActionEntry>> = HashMap::new();
    let mut collision_warnings: Vec<String> = Vec::new();
    let mut conflicted_uids: HashSet<String> = HashSet::new();

    for (filename, plan) in plans {
        let op_name = extract_operator_name(filename);
        for phase in &plan.phases {
            for res in &phase.resources {
                if let Some(key) = FullPlanKey::from_resource(res) {
                    uid_actions
                        .entry(key.uid.clone())
                        .or_default()
                        .push(PlanActionEntry {
                            action: res.action.clone(),
                            operator: op_name.clone(),
                            full_key: key,
                        });
                }
            }
        }
    }

    // Detect collisions: same UID across multiple operators (diagnostic only).
    // KEEP/REVIEW/WAIT do not negate DELETE — they record that other operators'
    // plans preserved the resource. Only conflicting full identities on the same
    // UID (e.g. different group/kind/ns/name) are true identity conflicts.
    for (uid, actions) in &uid_actions {
        let operators: HashSet<_> = actions.iter().map(|a| &a.operator).collect();
        if operators.len() > 1 {
            let mut ops: Vec<_> = operators.iter().map(|s| s.as_str()).collect();
            ops.sort();
            let action_summary: Vec<String> = {
                let mut pairs: Vec<_> = actions
                    .iter()
                    .map(|a| format!("{}:{}", a.operator, a.action))
                    .collect();
                pairs.sort();
                pairs.dedup();
                pairs
            };
            collision_warnings.push(format!(
                "UID {} appears in {} operators: {} (actions: {})",
                &uid[..12.min(uid.len())],
                operators.len(),
                ops.join(", "),
                action_summary.join(", "),
            ));

            // Identity conflict: same UID, different full identity across DELETE actions
            let delete_identities: HashSet<_> = actions
                .iter()
                .filter(|a| a.action == ExecutionAction::Delete)
                .map(|a| {
                    (
                        &a.full_key.group,
                        &a.full_key.kind,
                        &a.full_key.namespace,
                        &a.full_key.name,
                    )
                })
                .collect();
            if delete_identities.len() > 1 {
                conflicted_uids.insert(uid.clone());
            }
        }
    }

    collision_warnings.sort();
    (uid_actions, collision_warnings, conflicted_uids)
}

fn extract_operator_name(filename: &str) -> String {
    let base = filename.trim_end_matches(".json");
    if let Some((_num, rest)) = base.split_once('-') {
        rest.to_string()
    } else {
        base.to_string()
    }
}

// ──────────────────────────────────────────────────────────────
//  ownerRef edge verification [P0-2]
// ──────────────────────────────────────────────────────────────

fn group_from_api_version(api_version: &str) -> &str {
    api_version.rsplit_once('/').map(|(g, _)| g).unwrap_or("")
}

fn verified_owner_edge(
    child: &PhysicalEntity,
    oref: &ObsOwnerRef,
    parent: &PhysicalEntity,
) -> bool {
    let oref_group = group_from_api_version(&oref.api_version);
    let namespace_ok = parent.identity.namespace.is_none()
        || parent.identity.namespace == child.identity.namespace;
    namespace_ok
        && parent.identity.kind == oref.kind
        && parent.identity.name == oref.name
        && parent.identity.group == oref_group
}

// ──────────────────────────────────────────────────────────────
//  BFS closure — DELETE seeds only [P0-3]
// ──────────────────────────────────────────────────────────────

pub fn bfs_closure(
    seeds: &HashSet<String>,
    parent_to_children: &HashMap<String, Vec<String>>,
) -> HashSet<String> {
    let mut closure: HashSet<String> = seeds.clone();
    let mut queue: Vec<String> = seeds.iter().cloned().collect();
    while let Some(parent) = queue.pop() {
        if let Some(children) = parent_to_children.get(&parent) {
            for child in children {
                if closure.insert(child.clone()) {
                    queue.push(child.clone());
                }
            }
        }
    }
    closure
}

// ──────────────────────────────────────────────────────────────
//  Derived classification
// ──────────────────────────────────────────────────────────────

fn classify_derived_pv(
    ent: &PhysicalEntity,
    deleted_pvc_uids: &HashSet<String>,
) -> Option<DerivedDetail> {
    for pvc_uid in deleted_pvc_uids {
        if ent.identity.name == format!("pvc-{}", pvc_uid) {
            return Some(DerivedDetail {
                derived_type: "pv_storage_reclaim".to_string(),
                evidence: format!("PV name == pvc-{{{}}}", pvc_uid),
                related_uid: Some(pvc_uid.clone()),
            });
        }
    }
    None
}

fn classify_derived_apiservice(
    ent: &PhysicalEntity,
    deleted_crd_entries: &HashMap<String, PhysicalEntity>,
    gvr_catalog: Option<&GvrCatalog>,
) -> Option<DerivedDetail> {
    let automanaged = ent
        .labels
        .get("kube-aggregator.kubernetes.io/automanaged")
        .map(|v| v == "true")
        .unwrap_or(false);
    if !automanaged {
        return None;
    }

    let parts: Vec<&str> = ent.identity.name.splitn(2, '.').collect();
    if parts.len() != 2 {
        return None;
    }
    let (as_version, as_group) = (parts[0], parts[1]);

    for (crd_uid, crd_ent) in deleted_crd_entries {
        let crd_parts: Vec<&str> = crd_ent.identity.name.splitn(2, '.').collect();
        if crd_parts.len() == 2 && crd_parts[1] == as_group {
            let version_served = gvr_catalog
                .map(|cat| {
                    cat.gvrs
                        .iter()
                        .any(|gvr| gvr.group == as_group && gvr.version == as_version)
                })
                .unwrap_or(false);
            if version_served {
                return Some(DerivedDetail {
                    derived_type: "api_deregistration".to_string(),
                    evidence: format!(
                        "APIService {}.{} matches deleted CRD {}, automanaged=true, version served",
                        as_version, as_group, crd_ent.identity.name
                    ),
                    related_uid: Some(crd_uid.clone()),
                });
            }
        }
    }
    None
}

// ──────────────────────────────────────────────────────────────
//  GVR catalog
// ──────────────────────────────────────────────────────────────

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct GvrCatalog {
    pub count: usize,
    pub gvrs: Vec<GvrEntry>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct GvrEntry {
    pub group: String,
    pub version: String,
    pub resource: String,
}

pub fn load_gvr_catalog(path: &str) -> anyhow::Result<GvrCatalog> {
    let data = std::fs::read_to_string(path)?;
    Ok(serde_json::from_str(&data)?)
}

// ──────────────────────────────────────────────────────────────
//  Provider API operands
// ──────────────────────────────────────────────────────────────

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ProviderApiOperands {
    #[serde(default)]
    pub schema_version: Option<u32>,
    pub count: usize,
    pub cases: Vec<ProviderCase>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ProviderCase {
    pub group: String,
    pub kind: String,
    pub namespace: Option<String>,
    pub name: String,
    pub uid: Option<String>,
    pub api_provider_operator: String,
    #[serde(default)]
    pub lifecycle_owner_evidence: Option<serde_json::Value>,
    #[serde(default)]
    pub provider_api_evidence: Option<serde_json::Value>,
    #[serde(default, rename = "observedVersions")]
    pub observed_versions: Option<Vec<String>>,
}

// ──────────────────────────────────────────────────────────────
//  Main audit function
// ──────────────────────────────────────────────────────────────

pub struct AuditInput {
    pub before: AuditObservationSet,
    pub after: AuditObservationSet,
    pub plans: Vec<(String, ExecutionPlan)>,
    pub gvr_catalog: Option<GvrCatalog>,
    pub provider_operands: Option<ProviderApiOperands>,
}

impl AuditInput {
    pub fn from_snapshots(
        before: &ClusterSnapshot,
        after: &ClusterSnapshot,
        plans: Vec<(String, ExecutionPlan)>,
        gvr_catalog: Option<GvrCatalog>,
        provider_operands: Option<ProviderApiOperands>,
    ) -> Self {
        Self {
            before: snapshot_to_observation_set(before),
            after: snapshot_to_observation_set(after),
            plans,
            gvr_catalog,
            provider_operands,
        }
    }
}

pub fn run_audit(input: &AuditInput) -> anyhow::Result<AuditReport> {
    let before = &input.before;
    let after = &input.after;

    // Validate cluster identity across plans
    if input.plans.len() > 1 {
        let first_id = &input.plans[0].1.cluster_identity;
        for (name, plan) in &input.plans[1..] {
            if !first_id.matches(&plan.cluster_identity) {
                anyhow::bail!(
                    "Cluster identity mismatch between plans: {} vs {} (kube-system UID {} vs {})",
                    input.plans[0].0,
                    name,
                    first_id.kube_system_uid,
                    plan.cluster_identity.kube_system_uid,
                );
            }
        }
    }

    // Capability warnings
    let mut capability_warnings = Vec::new();
    capability_warnings.extend(
        before
            .capability_warnings
            .iter()
            .map(|w| format!("before: {}", w)),
    );
    capability_warnings.extend(
        after
            .capability_warnings
            .iter()
            .map(|w| format!("after: {}", w)),
    );

    let has_deletion_ts = before.has_deletion_timestamp && after.has_deletion_timestamp;
    if !has_deletion_ts
        && before.capability_warnings.is_empty()
        && after.capability_warnings.is_empty()
    {
        capability_warnings.push(
            "Newly-terminating classification unavailable (deletion_timestamp not captured)."
                .to_string(),
        );
    }

    if input.plans.is_empty() {
        capability_warnings.push(
            "No execution plans provided. Classifications requiring plan evidence (PlannedDirectDelete, ExpectedControllerCleanup, OwnerRefGcDescendant) will be UnexplainedChange.".to_string()
        );
    }

    // Cluster URL mismatch
    if before.cluster_url != after.cluster_url {
        anyhow::bail!(
            "Cluster URL mismatch: before={}, after={}. Use snapshots from the same cluster.",
            before.cluster_url,
            after.cluster_url,
        );
    }

    // Build physical entities
    let pre_ents = build_physical_entities(before);
    let post_ents = build_physical_entities(after);

    let pre_uids: HashSet<String> = pre_ents.keys().cloned().collect();
    let post_uids: HashSet<String> = post_ents.keys().cloned().collect();
    let removed_uids: HashSet<String> = pre_uids.difference(&post_uids).cloned().collect();
    let added_uids: HashSet<String> = post_uids.difference(&pre_uids).cloned().collect();

    // Multi-observed count
    let multi_observed = pre_ents
        .values()
        .filter(|e| e.observed_apis.len() > 1)
        .count();

    // Build logical indexes (BTreeMap for determinism, Vec for multi-UID)
    let pre_logical = build_logical_index_multi(&pre_ents);
    let post_logical = build_logical_index_multi(&post_ents);

    // API-logical layer: built from raw observations (group, kind, ns, name)
    let pre_api_logical = build_api_logical_set(&before.observations);
    let post_api_logical = build_api_logical_set(&after.observations);

    // UID-null layer
    let pre_null: Vec<_> = before
        .observations
        .iter()
        .filter(|o| o.uid.as_ref().is_none_or(|u| u.is_empty()))
        .collect();
    let post_null: Vec<_> = after
        .observations
        .iter()
        .filter(|o| o.uid.as_ref().is_none_or(|u| u.is_empty()))
        .collect();
    let pre_null_fps = null_fingerprint_groups(&pre_null);
    let post_null_fps = null_fingerprint_groups(&post_null);
    let pre_fp_keys: HashSet<_> = pre_null_fps.keys().cloned().collect();
    let post_fp_keys: HashSet<_> = post_null_fps.keys().cloned().collect();
    let removed_fps = pre_fp_keys.difference(&post_fp_keys).count();
    let added_fps = post_fp_keys.difference(&pre_fp_keys).count();
    let pre_fp_collisions = pre_null_fps.values().filter(|rs| rs.len() > 1).count();
    let post_fp_collisions = post_null_fps.values().filter(|rs| rs.len() > 1).count();

    // Plan action index with full identity verification [P0-2, P0-5]
    let (uid_actions, collision_warnings, conflicted_uids) = build_plan_action_index(&input.plans);

    // Compute effective actions with identity verification
    let mut del_uids: HashSet<String> = HashSet::new();
    let mut exp_uids: HashSet<String> = HashSet::new();
    let mut uid_operator: HashMap<String, String> = HashMap::new();

    for uid in &removed_uids {
        if conflicted_uids.contains(uid) {
            continue; // P0-5: conflicted → UnexplainedChange
        }
        if let Some(actions) = uid_actions.get(uid)
            && let Some(ent) = pre_ents.get(uid)
        {
            let mut sorted: Vec<_> = actions.iter().collect();
            sorted.sort_by_key(|a| match a.action {
                ExecutionAction::Delete => 0,
                ExecutionAction::Expect => 1,
                _ => 2,
            });
            for entry in &sorted {
                if entry.full_key.matches_entity(ent) {
                    match entry.action {
                        ExecutionAction::Delete => {
                            del_uids.insert(uid.clone());
                            uid_operator.insert(uid.clone(), entry.operator.clone());
                        }
                        ExecutionAction::Expect if !del_uids.contains(uid) => {
                            exp_uids.insert(uid.clone());
                            uid_operator.insert(uid.clone(), entry.operator.clone());
                        }
                        _ => {}
                    }
                    break;
                }
            }
        }
    }

    // Build parent→children map with verified edges [P0-2]
    let mut parent_to_children: HashMap<String, Vec<String>> = HashMap::new();
    for (uid, ent) in &pre_ents {
        for oref in &ent.owner_refs {
            if let Some(parent) = pre_ents.get(&oref.uid)
                && verified_owner_edge(ent, oref, parent)
            {
                parent_to_children
                    .entry(oref.uid.clone())
                    .or_default()
                    .push(uid.clone());
            }
        }
    }

    // BFS closure from DELETE seeds only [P0-3]
    let closure = bfs_closure(&del_uids, &parent_to_children);
    let descendants: HashSet<String> = closure
        .intersection(&removed_uids)
        .filter(|u| !del_uids.contains(*u) && !exp_uids.contains(*u))
        .cloned()
        .collect();
    let removed_in_closure = closure.intersection(&removed_uids).count();

    // Derived classification
    let deleted_pvc_uids: HashSet<String> = removed_uids
        .iter()
        .filter(|u| {
            pre_ents
                .get(*u)
                .is_some_and(|e| e.identity.kind == "PersistentVolumeClaim")
        })
        .cloned()
        .collect();

    let deleted_crd_entries: HashMap<String, PhysicalEntity> = removed_uids
        .iter()
        .filter_map(|u| {
            let e = pre_ents.get(u)?;
            if e.identity.kind == "CustomResourceDefinition" {
                Some((u.clone(), e.clone()))
            } else {
                None
            }
        })
        .collect();

    let mut derived: HashMap<String, DerivedDetail> = HashMap::new();
    for uid in &removed_uids {
        if del_uids.contains(uid) || exp_uids.contains(uid) || closure.contains(uid) {
            continue;
        }
        let ent = match pre_ents.get(uid) {
            Some(e) => e,
            None => continue,
        };

        if ent.identity.kind == "PersistentVolume" {
            if let Some(detail) = classify_derived_pv(ent, &deleted_pvc_uids) {
                derived.insert(uid.clone(), detail);
            }
            continue;
        }
        if ent.identity.kind == "APIService" {
            if let Some(detail) =
                classify_derived_apiservice(ent, &deleted_crd_entries, input.gvr_catalog.as_ref())
            {
                derived.insert(uid.clone(), detail);
            }
            continue;
        }
    }

    // P0-2: if after coverage is incomplete, we cannot prove absence
    let after_can_prove_absent = after.absence_coverage.is_complete();

    // Classify all removed UIDs
    let mut removals: Vec<ClassifiedRemoval> = Vec::new();
    for uid in &removed_uids {
        let ent = match pre_ents.get(uid) {
            Some(e) => e,
            None => continue,
        };

        let observed_api_strs: Vec<String> = ent
            .observed_apis
            .iter()
            .map(|(g, v, r)| {
                if g.is_empty() {
                    format!("{}/{}", v, r)
                } else {
                    format!("{}/{}/{}", g, v, r)
                }
            })
            .collect();

        let (classification, evidence, plan_operator, derived_detail) = if !after_can_prove_absent {
            (
                AuditClassification::UnexplainedChange,
                Some("after snapshot coverage incomplete; absence not proven".to_string()),
                None,
                None,
            )
        } else if del_uids.contains(uid) {
            (
                AuditClassification::PlannedDirectDelete,
                Some("Plan DELETE action with full identity+UID match".to_string()),
                uid_operator.get(uid).cloned(),
                None,
            )
        } else if exp_uids.contains(uid) {
            (
                AuditClassification::ExpectedControllerCleanup,
                Some("Plan EXPECT action with full identity+UID match".to_string()),
                uid_operator.get(uid).cloned(),
                None,
            )
        } else if descendants.contains(uid) {
            (
                AuditClassification::OwnerRefGcDescendant,
                Some("UID-verified ownerRef chain reaches DELETE seed".to_string()),
                None,
                None,
            )
        } else if let Some(detail) = derived.get(uid) {
            (
                AuditClassification::DerivedSideEffect,
                Some(detail.evidence.clone()),
                None,
                Some(detail.clone()),
            )
        } else {
            (AuditClassification::UnexplainedChange, None, None, None)
        };

        removals.push(ClassifiedRemoval {
            uid: uid.clone(),
            identity: ent.identity.clone(),
            classification,
            evidence,
            plan_operator,
            derived_detail,
            observed_apis: observed_api_strs,
        });
    }

    // Recreated: same logical identity, different UID [using multi-UID index]
    let mut recreated: Vec<RecreatedEntry> = Vec::new();
    if after_can_prove_absent {
        for (key, pre_pids) in &pre_logical {
            if let Some(post_pids) = post_logical.get(key)
                && pre_pids.len() == 1
                && post_pids.len() == 1
                && pre_pids[0] != post_pids[0]
            {
                recreated.push(RecreatedEntry {
                    identity: key.clone(),
                    pre_uid: pre_pids[0].clone(),
                    post_uid: post_pids[0].clone(),
                });
            }
        }
    } else {
        capability_warnings
            .push("after snapshot coverage incomplete; recreated detection suppressed".into());
    }

    // Terminating
    let mut newly_terminating: Vec<TerminatingEntry> = Vec::new();
    let mut preexisting_terminating: Vec<TerminatingEntry> = Vec::new();
    if has_deletion_ts {
        let pre_terminating: HashSet<String> = pre_ents
            .iter()
            .filter(|(_, e)| e.deletion_timestamp.is_some())
            .map(|(uid, _)| uid.clone())
            .collect();
        for (uid, ent) in &post_ents {
            if let Some(ts) = &ent.deletion_timestamp {
                let te = TerminatingEntry {
                    uid: uid.clone(),
                    identity: ent.identity.clone(),
                    deletion_timestamp: ts.clone(),
                    preexisting: pre_terminating.contains(uid),
                    finalizers: ent.finalizers.clone(),
                };
                if pre_terminating.contains(uid) {
                    preexisting_terminating.push(te);
                } else {
                    newly_terminating.push(te);
                }
            }
        }
    }

    // Orphan ownerRefs — suppress when after incomplete
    let mut orphan_owner_refs: Vec<OrphanOwnerRefEntry> = Vec::new();
    if !after_can_prove_absent {
        capability_warnings.push(
            "after snapshot coverage incomplete; orphan ownerRef detection suppressed".into(),
        );
    }
    for (uid, ent) in &post_ents {
        if !after_can_prove_absent {
            break;
        }
        if ent.deletion_timestamp.is_some() {
            continue;
        }
        for oref in &ent.owner_refs {
            if !removed_uids.contains(&oref.uid) {
                continue;
            }
            if let Some(pre_owner) = pre_ents.get(&oref.uid) {
                let oref_group = group_from_api_version(&oref.api_version);
                let namespace_ok = pre_owner.identity.namespace.is_none()
                    || pre_owner.identity.namespace == ent.identity.namespace;
                if namespace_ok
                    && pre_owner.identity.kind == oref.kind
                    && pre_owner.identity.name == oref.name
                    && pre_owner.identity.group == oref_group
                {
                    orphan_owner_refs.push(OrphanOwnerRefEntry {
                        uid: uid.clone(),
                        identity: ent.identity.clone(),
                        deleted_owner_kind: oref.kind.clone(),
                        deleted_owner_name: oref.name.clone(),
                        deleted_owner_uid: oref.uid.clone(),
                    });
                }
            }
        }
    }

    // Dangling spec refs with proper source [P0-4]
    // Only report when after coverage is complete
    let mut dangling_spec_refs: Vec<DanglingSpecRefEntry> = Vec::new();
    if !after_can_prove_absent {
        capability_warnings.push(
            "after snapshot coverage incomplete; dangling spec-ref detection suppressed"
                .to_string(),
        );
    }
    for (uid, ent) in &post_ents {
        if !after_can_prove_absent {
            break;
        }
        for spec_ref in &ent.spec_refs {
            let target_ns = spec_ref
                .target_namespace
                .as_deref()
                .or(ent.identity.namespace.as_deref());
            let found = post_ents.values().any(|e| {
                e.identity.kind == spec_ref.target_kind
                    && e.identity.name == spec_ref.target_name
                    && e.identity.namespace.as_deref() == target_ns
                    && (spec_ref.target_group.is_none()
                        || spec_ref.target_group.as_deref() == Some(&e.identity.group))
            });
            if !found {
                // Only flag as dangling if the target existed in pre (proving removal)
                let was_in_pre = pre_ents.values().any(|e| {
                    e.identity.kind == spec_ref.target_kind
                        && e.identity.name == spec_ref.target_name
                        && e.identity.namespace.as_deref() == target_ns
                        && (spec_ref.target_group.is_none()
                            || spec_ref.target_group.as_deref() == Some(&e.identity.group))
                });
                if !was_in_pre {
                    continue;
                }
                dangling_spec_refs.push(DanglingSpecRefEntry {
                    source_uid: uid.clone(),
                    source_identity: ent.identity.clone(),
                    target_kind: spec_ref.target_kind.clone(),
                    target_name: spec_ref.target_name.clone(),
                    field_path: spec_ref.field_path.clone(),
                    ref_type: spec_ref.source.to_string(),
                    target_group: spec_ref.target_group.clone(),
                    target_namespace: spec_ref.target_namespace.clone(),
                });
            }
        }
    }

    // Provider operands — use classification from main removals (no double-compute)
    let classification_by_uid: HashMap<&str, &AuditClassification> = removals
        .iter()
        .map(|r| (r.uid.as_str(), &r.classification))
        .collect();

    let mut provider_operand_results: Vec<ProviderOperandResult> = Vec::new();
    if let Some(provider) = &input.provider_operands {
        for case in &provider.cases {
            let pre_uid = case.uid.as_deref().unwrap_or("");
            let classification = classification_by_uid
                .get(pre_uid)
                .cloned()
                .cloned()
                .unwrap_or(AuditClassification::UnexplainedChange);

            provider_operand_results.push(ProviderOperandResult {
                identity: LogicalIdentity {
                    group: case.group.clone(),
                    kind: case.kind.clone(),
                    namespace: case.namespace.clone(),
                    name: case.name.clone(),
                },
                uid: pre_uid.to_string(),
                api_provider_operator: case.api_provider_operator.clone(),
                physical_classification: classification,
                evidence: "provider API operand — expected cleanup via independent approval"
                    .to_string(),
                provider_api_evidence: case.provider_api_evidence.clone(),
                lifecycle_owner_evidence: case.lifecycle_owner_evidence.clone(),
                observed_versions: case.observed_versions.clone().unwrap_or_default(),
            });
        }
    }

    // Classification summary
    let mut classification_summary: BTreeMap<String, usize> = BTreeMap::new();
    for r in &removals {
        *classification_summary
            .entry(r.classification.to_string())
            .or_default() += 1;
    }

    // Deterministic sort [P1-2]
    let sort_key = |r: &ClassifiedRemoval| {
        (
            r.classification.clone(),
            r.identity.group.clone(),
            r.identity.kind.clone(),
            r.identity.namespace.clone(),
            r.identity.name.clone(),
            r.uid.clone(),
        )
    };
    removals.sort_by_key(sort_key);

    recreated.sort_by(|a, b| (&a.identity, &a.pre_uid).cmp(&(&b.identity, &b.pre_uid)));

    let te_sort = |a: &TerminatingEntry, b: &TerminatingEntry| {
        (&a.identity, &a.uid).cmp(&(&b.identity, &b.uid))
    };
    newly_terminating.sort_by(te_sort);
    preexisting_terminating.sort_by(te_sort);

    orphan_owner_refs.sort_by(|a, b| {
        (&a.identity, &a.uid, &a.deleted_owner_uid).cmp(&(
            &b.identity,
            &b.uid,
            &b.deleted_owner_uid,
        ))
    });

    dangling_spec_refs.sort_by(|a, b| {
        (
            &a.source_identity,
            &a.source_uid,
            &a.target_kind,
            &a.target_name,
            &a.ref_type,
        )
            .cmp(&(
                &b.source_identity,
                &b.source_uid,
                &b.target_kind,
                &b.target_name,
                &b.ref_type,
            ))
    });

    provider_operand_results.sort_by(|a, b| {
        (&a.api_provider_operator, &a.identity, &a.uid).cmp(&(
            &b.api_provider_operator,
            &b.identity,
            &b.uid,
        ))
    });

    capability_warnings.sort();

    let mut all_terminating = newly_terminating.clone();
    all_terminating.extend(preexisting_terminating.iter().cloned());
    all_terminating.sort_by(te_sort);

    let mut plan_names: Vec<String> = input.plans.iter().map(|(n, _)| n.clone()).collect();
    plan_names.sort();

    Ok(AuditReport {
        schema_version: AUDIT_SCHEMA_VERSION,
        before_taken_at: before.taken_at.clone(),
        after_taken_at: after.taken_at.clone(),
        cluster_url: before.cluster_url.clone(),
        plans_loaded: plan_names,
        capability_warnings,
        layers: AuditLayers {
            raw_observations: RawObsLayer {
                pre: before.observations.len(),
                post: after.observations.len(),
            },
            physical_uids: PhysicalLayer {
                pre: pre_uids.len(),
                post: post_uids.len(),
                removed: removed_uids.len(),
                added: added_uids.len(),
                multi_observed,
            },
            logical: LogicalLayer {
                pre: pre_api_logical.len(),
                post: post_api_logical.len(),
            },
            uid_null: UidNullLayer {
                pre: pre_null.len(),
                post: post_null.len(),
                removed_fingerprints: removed_fps,
                added_fingerprints: added_fps,
                pre_fingerprint_collision_groups: pre_fp_collisions,
                post_fingerprint_collision_groups: post_fp_collisions,
            },
        },
        classification_summary,
        removals,
        recreated,
        closure: ClosureSummary {
            delete_seeds: del_uids.len(),
            total_closure: closure.len(),
            removed_in_closure,
        },
        terminating: TerminatingSummary {
            newly_terminating: newly_terminating.len(),
            preexisting_retained: preexisting_terminating.len(),
            details: all_terminating,
        },
        orphan_owner_refs,
        dangling_spec_refs,
        provider_operand_results,
        plan_collision_warnings: collision_warnings,
    })
}

fn build_logical_index_multi(
    entities: &HashMap<String, PhysicalEntity>,
) -> BTreeMap<LogicalIdentity, Vec<String>> {
    let mut index: BTreeMap<LogicalIdentity, Vec<String>> = BTreeMap::new();
    for ent in entities.values() {
        index
            .entry(ent.identity.clone())
            .or_default()
            .push(ent.uid.clone());
    }
    for uids in index.values_mut() {
        uids.sort();
    }
    index
}

fn build_api_logical_set(observations: &[AuditObservation]) -> HashSet<LogicalIdentity> {
    observations
        .iter()
        .map(|o| LogicalIdentity {
            group: o.group.clone(),
            kind: o.kind.clone(),
            namespace: o.namespace.clone(),
            name: o.name.clone(),
        })
        .collect()
}

fn null_fingerprint_groups<'a>(
    null_obs: &[&'a AuditObservation],
) -> HashMap<String, Vec<&'a AuditObservation>> {
    let mut groups: HashMap<String, Vec<&'a AuditObservation>> = HashMap::new();
    for o in null_obs {
        let fp = uid_null_fingerprint(o);
        groups.entry(fp).or_default().push(o);
    }
    groups
}

// ──────────────────────────────────────────────────────────────
//  Tests
// ──────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::kube::resource::*;
    use crate::teardown::plan::*;

    fn make_obs(
        group: &str,
        kind: &str,
        ns: Option<&str>,
        name: &str,
        uid: Option<&str>,
    ) -> AuditObservation {
        AuditObservation {
            group: group.into(),
            version: "v1".into(),
            resource: format!("{}s", kind.to_lowercase()),
            kind: kind.into(),
            namespace: ns.map(|s| s.into()),
            name: name.into(),
            uid: uid.map(|s| s.into()),
            owner_refs: vec![],
            spec_refs: vec![],
            deletion_timestamp: None,
            finalizers: None,
            labels: HashMap::new(),
            annotations: HashMap::new(),
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn make_obs_with_owner(
        group: &str,
        kind: &str,
        ns: Option<&str>,
        name: &str,
        uid: &str,
        owner_api_version: &str,
        owner_kind: &str,
        owner_name: &str,
        owner_uid: &str,
    ) -> AuditObservation {
        let mut o = make_obs(group, kind, ns, name, Some(uid));
        o.owner_refs.push(ObsOwnerRef {
            api_version: owner_api_version.into(),
            kind: owner_kind.into(),
            name: owner_name.into(),
            uid: owner_uid.into(),
            controller: true,
            block_owner_deletion: false,
        });
        o
    }

    fn make_obs_set(obs: Vec<AuditObservation>) -> AuditObservationSet {
        AuditObservationSet {
            observations: obs,
            cluster_url: "https://api.test:6443".into(),
            taken_at: "2026-01-01T00:00:00Z".into(),
            capability_warnings: vec![],
            has_deletion_timestamp: true,
            has_spec_ref_source: true,
            absence_coverage: AbsenceCoverage::Complete,
        }
    }

    #[allow(clippy::type_complexity)]
    fn make_plan(
        resources: Vec<(&str, &str, Option<&str>, &str, &str, ExecutionAction)>,
    ) -> ExecutionPlan {
        let phase_resources: Vec<ExecutionResource> = resources
            .into_iter()
            .map(|(group, kind, ns, name, uid, action)| ExecutionResource {
                group: group.into(),
                kind: kind.into(),
                namespace: ns.map(|s| s.into()),
                name: name.into(),
                uid: Some(uid.into()),
                action,
            })
            .collect();
        ExecutionPlan {
            schema_version: EXECUTION_PLAN_SCHEMA_VERSION,
            cluster_identity: ClusterIdentity {
                api_server: "https://api.test:6443".into(),
                kube_system_uid: "kube-uid".into(),
            },
            created_at: "2026-01-01T00:00:00Z".into(),
            targets: vec![],
            prune_crds: false,
            approve_scopes: vec![],
            approve_resources: vec![],
            keep_resources: vec![],
            phases: vec![ExecutionPhase {
                phase: 1,
                name: "Phase 1".into(),
                resources: phase_resources,
            }],
            explicit_deletes: vec![],
        }
    }

    fn audit(
        before: AuditObservationSet,
        after: AuditObservationSet,
        plans: Vec<(String, ExecutionPlan)>,
    ) -> AuditReport {
        run_audit(&AuditInput {
            before,
            after,
            plans,
            gvr_catalog: None,
            provider_operands: None,
        })
        .unwrap()
    }

    #[test]
    fn diamond_dag_convergence() {
        let s = make_obs("", "Root", Some("ns"), "root", Some("uid-s"));
        let a = make_obs_with_owner(
            "",
            "A",
            Some("ns"),
            "a",
            "uid-a",
            "v1",
            "Root",
            "root",
            "uid-s",
        );
        let b = make_obs_with_owner(
            "",
            "B",
            Some("ns"),
            "b",
            "uid-b",
            "v1",
            "Root",
            "root",
            "uid-s",
        );
        let mut c = make_obs("", "C", Some("ns"), "c", Some("uid-c"));
        c.owner_refs.push(ObsOwnerRef {
            api_version: "v1".into(),
            kind: "A".into(),
            name: "a".into(),
            uid: "uid-a".into(),
            controller: true,
            block_owner_deletion: false,
        });
        c.owner_refs.push(ObsOwnerRef {
            api_version: "v1".into(),
            kind: "B".into(),
            name: "b".into(),
            uid: "uid-b".into(),
            controller: false,
            block_owner_deletion: false,
        });

        let before = make_obs_set(vec![s, a, b, c]);
        let after = make_obs_set(vec![]);
        let plan = make_plan(vec![(
            "",
            "Root",
            Some("ns"),
            "root",
            "uid-s",
            ExecutionAction::Delete,
        )]);
        let report = audit(before, after, vec![("plan.json".into(), plan)]);

        let desc_uids: HashSet<_> = report
            .removals
            .iter()
            .filter(|r| r.classification == AuditClassification::OwnerRefGcDescendant)
            .map(|r| r.uid.as_str())
            .collect();
        assert!(desc_uids.contains("uid-a"));
        assert!(desc_uids.contains("uid-b"));
        assert!(desc_uids.contains("uid-c"), "diamond leaf classified once");
    }

    #[test]
    fn ownerref_cycle_termination() {
        let mut a = make_obs("", "A", Some("ns"), "a", Some("uid-a"));
        a.owner_refs.push(ObsOwnerRef {
            api_version: "v1".into(),
            kind: "B".into(),
            name: "b".into(),
            uid: "uid-b".into(),
            controller: true,
            block_owner_deletion: false,
        });
        let mut b = make_obs("", "B", Some("ns"), "b", Some("uid-b"));
        b.owner_refs.push(ObsOwnerRef {
            api_version: "v1".into(),
            kind: "A".into(),
            name: "a".into(),
            uid: "uid-a".into(),
            controller: true,
            block_owner_deletion: false,
        });

        let before = make_obs_set(vec![a, b]);
        let after = make_obs_set(vec![]);
        let plan = make_plan(vec![(
            "",
            "A",
            Some("ns"),
            "a",
            "uid-a",
            ExecutionAction::Delete,
        )]);
        let report = audit(before, after, vec![("plan.json".into(), plan)]);
        assert_eq!(report.removals.len(), 2, "cycle must not hang");
    }

    #[test]
    fn multi_owner_surviving_owner_not_gc() {
        let root1 = make_obs("", "Root1", Some("ns"), "r1", Some("uid-r1"));
        let root2 = make_obs("", "Root2", Some("ns"), "r2", Some("uid-r2"));
        let mut child = make_obs("", "Child", Some("ns"), "c", Some("uid-c"));
        child.owner_refs.push(ObsOwnerRef {
            api_version: "v1".into(),
            kind: "Root1".into(),
            name: "r1".into(),
            uid: "uid-r1".into(),
            controller: true,
            block_owner_deletion: false,
        });
        child.owner_refs.push(ObsOwnerRef {
            api_version: "v1".into(),
            kind: "Root2".into(),
            name: "r2".into(),
            uid: "uid-r2".into(),
            controller: false,
            block_owner_deletion: false,
        });

        // Only root1 deleted, root2 survives in post
        let before = make_obs_set(vec![root1, root2.clone(), child.clone()]);
        let after = make_obs_set(vec![root2, child]);
        let plan = make_plan(vec![(
            "",
            "Root1",
            Some("ns"),
            "r1",
            "uid-r1",
            ExecutionAction::Delete,
        )]);
        let report = audit(before, after, vec![("plan.json".into(), plan)]);
        // child still exists in post, so not in removals at all
        assert!(report.removals.iter().all(|r| r.uid != "uid-c"));
    }

    #[test]
    fn same_uid_wrong_group_not_plan_direct() {
        let entry = make_obs("wrong.group", "Sub", Some("ns"), "s1", Some("uid-s1"));
        let before = make_obs_set(vec![entry]);
        let after = make_obs_set(vec![]);
        // Plan has correct group=""
        let plan = make_plan(vec![(
            "",
            "Sub",
            Some("ns"),
            "s1",
            "uid-s1",
            ExecutionAction::Delete,
        )]);
        let report = audit(before, after, vec![("plan.json".into(), plan)]);
        let r = &report.removals[0];
        // Identity mismatch: plan group="" vs entity group="wrong.group"
        // FullPlanKey.matches_entity checks kind/ns/name but group comes from entity identity
        // which uses observation group. Plan has group="" but entity has "wrong.group".
        // The plan key's group="" != entity identity group "wrong.group", so no match.
        assert_eq!(
            r.classification,
            AuditClassification::UnexplainedChange,
            "same UID wrong group must not be PlannedDirectDelete"
        );
    }

    #[test]
    fn same_uid_multi_group_api_alias() {
        // Same UID observed via two different API groups
        let obs1 = make_obs("", "Event", Some("ns"), "ev1", Some("uid-ev"));
        let mut obs2 = make_obs("events.k8s.io", "Event", Some("ns"), "ev1", Some("uid-ev"));
        obs2.resource = "events".into();

        let before = make_obs_set(vec![obs1, obs2]);
        let after = make_obs_set(vec![]);
        let report = audit(before, after, vec![]);
        // Should have 1 physical entity with 2 API observations
        assert_eq!(report.removals.len(), 1, "merged to 1 physical entity");
        assert_eq!(
            report.removals[0].observed_apis.len(),
            2,
            "2 API observations"
        );
    }

    #[test]
    fn uid_null_fingerprint_distinct() {
        let mut pm1 = make_obs(
            "packages.operators.coreos.com",
            "PackageManifest",
            None,
            "my-op",
            None,
        );
        pm1.labels
            .insert("catalog".into(), "redhat-operators".into());
        let mut pm2 = make_obs(
            "packages.operators.coreos.com",
            "PackageManifest",
            None,
            "my-op",
            None,
        );
        pm2.labels
            .insert("catalog".into(), "community-operators".into());

        let fp1 = uid_null_fingerprint(&pm1);
        let fp2 = uid_null_fingerprint(&pm2);
        assert_ne!(fp1, fp2, "different labels → different fingerprint");

        let lk1 = LogicalIdentity::from_resource_id(&ResourceId {
            group: pm1.group.clone(),
            version: pm1.version.clone(),
            kind: pm1.kind.clone(),
            namespace: pm1.namespace.clone(),
            name: pm1.name.clone(),
            uid: None,
        });
        let lk2 = LogicalIdentity::from_resource_id(&ResourceId {
            group: pm2.group.clone(),
            version: pm2.version.clone(),
            kind: pm2.kind.clone(),
            namespace: pm2.namespace.clone(),
            name: pm2.name.clone(),
            uid: None,
        });
        assert_eq!(lk1, lk2, "same logical identity = name collision");
    }

    #[test]
    fn same_logical_identity_different_uid_recreation() {
        let before = make_obs_set(vec![make_obs(
            "apps",
            "Deployment",
            Some("ns"),
            "web",
            Some("uid-old"),
        )]);
        let after = make_obs_set(vec![make_obs(
            "apps",
            "Deployment",
            Some("ns"),
            "web",
            Some("uid-new"),
        )]);
        let report = audit(before, after, vec![]);
        assert_eq!(report.recreated.len(), 1);
        assert_eq!(report.recreated[0].pre_uid, "uid-old");
        assert_eq!(report.recreated[0].post_uid, "uid-new");
    }

    #[test]
    fn exact_pv_reclaim_positive() {
        let pvc = make_obs(
            "",
            "PersistentVolumeClaim",
            Some("ns"),
            "data-pvc",
            Some("uid-pvc"),
        );
        let pv = make_obs("", "PersistentVolume", None, "pvc-uid-pvc", Some("uid-pv"));
        let before = make_obs_set(vec![pvc, pv]);
        let after = make_obs_set(vec![]);
        let plan = make_plan(vec![(
            "",
            "PersistentVolumeClaim",
            Some("ns"),
            "data-pvc",
            "uid-pvc",
            ExecutionAction::Delete,
        )]);
        let report = audit(before, after, vec![("plan.json".into(), plan)]);
        let pv_r = report.removals.iter().find(|r| r.uid == "uid-pv").unwrap();
        assert_eq!(pv_r.classification, AuditClassification::DerivedSideEffect);
    }

    #[test]
    fn near_name_pv_negative() {
        let pvc = make_obs(
            "",
            "PersistentVolumeClaim",
            Some("ns"),
            "data-pvc",
            Some("uid-pvc"),
        );
        let pv = make_obs(
            "",
            "PersistentVolume",
            None,
            "pvc-some-other-uid",
            Some("uid-pv"),
        );
        let before = make_obs_set(vec![pvc, pv]);
        let after = make_obs_set(vec![]);
        let plan = make_plan(vec![(
            "",
            "PersistentVolumeClaim",
            Some("ns"),
            "data-pvc",
            "uid-pvc",
            ExecutionAction::Delete,
        )]);
        let report = audit(before, after, vec![("plan.json".into(), plan)]);
        let pv_r = report.removals.iter().find(|r| r.uid == "uid-pv").unwrap();
        assert_ne!(pv_r.classification, AuditClassification::DerivedSideEffect);
    }

    #[test]
    fn apiservice_automanaged_positive() {
        let crd = make_obs(
            "apiextensions.k8s.io",
            "CustomResourceDefinition",
            None,
            "widgets.example.io",
            Some("uid-crd"),
        );
        let mut apiservice = make_obs(
            "apiregistration.k8s.io",
            "APIService",
            None,
            "v1.example.io",
            Some("uid-as"),
        );
        apiservice.labels.insert(
            "kube-aggregator.kubernetes.io/automanaged".into(),
            "true".into(),
        );

        let _before = make_obs_set(vec![crd, apiservice]);
        let _after = make_obs_set(vec![]);
        let catalog = GvrCatalog {
            count: 1,
            gvrs: vec![GvrEntry {
                group: "example.io".into(),
                version: "v1".into(),
                resource: "widgets".into(),
            }],
        };
        let plan = make_plan(vec![(
            "apiextensions.k8s.io",
            "CustomResourceDefinition",
            None,
            "widgets.example.io",
            "uid-crd",
            ExecutionAction::Delete,
        )]);
        let report = run_audit(&AuditInput {
            before: make_obs_set(vec![
                make_obs(
                    "apiextensions.k8s.io",
                    "CustomResourceDefinition",
                    None,
                    "widgets.example.io",
                    Some("uid-crd"),
                ),
                {
                    let mut a = make_obs(
                        "apiregistration.k8s.io",
                        "APIService",
                        None,
                        "v1.example.io",
                        Some("uid-as"),
                    );
                    a.labels.insert(
                        "kube-aggregator.kubernetes.io/automanaged".into(),
                        "true".into(),
                    );
                    a
                },
            ]),
            after: make_obs_set(vec![]),
            plans: vec![("plan.json".into(), plan)],
            gvr_catalog: Some(catalog),
            provider_operands: None,
        })
        .unwrap();
        let as_r = report.removals.iter().find(|r| r.uid == "uid-as").unwrap();
        assert_eq!(as_r.classification, AuditClassification::DerivedSideEffect);
    }

    #[test]
    fn apiservice_automanaged_false_negative() {
        let crd = make_obs(
            "apiextensions.k8s.io",
            "CustomResourceDefinition",
            None,
            "widgets.example.io",
            Some("uid-crd"),
        );
        let apiservice = make_obs(
            "apiregistration.k8s.io",
            "APIService",
            None,
            "v1.example.io",
            Some("uid-as"),
        );
        let plan = make_plan(vec![(
            "apiextensions.k8s.io",
            "CustomResourceDefinition",
            None,
            "widgets.example.io",
            "uid-crd",
            ExecutionAction::Delete,
        )]);
        let catalog = GvrCatalog {
            count: 1,
            gvrs: vec![GvrEntry {
                group: "example.io".into(),
                version: "v1".into(),
                resource: "widgets".into(),
            }],
        };
        let report = run_audit(&AuditInput {
            before: make_obs_set(vec![crd, apiservice]),
            after: make_obs_set(vec![]),
            plans: vec![("plan.json".into(), plan)],
            gvr_catalog: Some(catalog),
            provider_operands: None,
        })
        .unwrap();
        let as_r = report.removals.iter().find(|r| r.uid == "uid-as").unwrap();
        assert_ne!(as_r.classification, AuditClassification::DerivedSideEffect);
    }

    #[test]
    fn newly_terminating_vs_preexisting() {
        let mut pre_term = make_obs("", "Pod", Some("ns"), "term1", Some("uid-t1"));
        pre_term.deletion_timestamp = Some("2026-01-01T00:00:00Z".into());
        let pre_normal = make_obs("", "Pod", Some("ns"), "normal", Some("uid-n1"));

        let mut post_term_pre = make_obs("", "Pod", Some("ns"), "term1", Some("uid-t1"));
        post_term_pre.deletion_timestamp = Some("2026-01-01T00:00:00Z".into());
        let mut post_newly = make_obs("", "Pod", Some("ns"), "normal", Some("uid-n1"));
        post_newly.deletion_timestamp = Some("2026-01-02T00:00:00Z".into());

        let before = make_obs_set(vec![pre_term, pre_normal]);
        let after = make_obs_set(vec![post_term_pre, post_newly]);
        let report = audit(before, after, vec![]);
        assert_eq!(report.terminating.newly_terminating, 1);
        assert_eq!(report.terminating.preexisting_retained, 1);
    }

    #[test]
    fn provider_lifecycle_fields_separated() {
        let entry = make_obs(
            "authorino.kuadrant.io",
            "AuthConfig",
            Some("ns"),
            "ac1",
            Some("uid-ac"),
        );
        let plan = make_plan(vec![(
            "authorino.kuadrant.io",
            "AuthConfig",
            Some("ns"),
            "ac1",
            "uid-ac",
            ExecutionAction::Delete,
        )]);
        let provider = ProviderApiOperands {
            schema_version: Some(2),
            count: 1,
            cases: vec![ProviderCase {
                group: "authorino.kuadrant.io".into(),
                kind: "AuthConfig".into(),
                namespace: Some("ns".into()),
                name: "ac1".into(),
                uid: Some("uid-ac".into()),
                api_provider_operator: "authorino-operator".into(),
                lifecycle_owner_evidence: Some(
                    serde_json::json!({"route_rule_annotations": ["HTTPRouteRule"]}),
                ),
                provider_api_evidence: Some(
                    serde_json::json!({"type": "CsvOwnedCrd", "crd": "authconfigs.authorino.kuadrant.io"}),
                ),
                observed_versions: Some(vec!["authorino.kuadrant.io/v1beta3".into()]),
            }],
        };
        let report = run_audit(&AuditInput {
            before: make_obs_set(vec![entry]),
            after: make_obs_set(vec![]),
            plans: vec![("plan.json".into(), plan)],
            gvr_catalog: None,
            provider_operands: Some(provider),
        })
        .unwrap();
        assert_eq!(report.provider_operand_results.len(), 1);
        let pr = &report.provider_operand_results[0];
        assert_eq!(pr.api_provider_operator, "authorino-operator");
        assert_eq!(
            pr.physical_classification,
            AuditClassification::PlannedDirectDelete
        );
        assert!(pr.provider_api_evidence.is_some());
        assert!(pr.lifecycle_owner_evidence.is_some());
        assert_eq!(pr.observed_versions, vec!["authorino.kuadrant.io/v1beta3"]);
    }

    #[test]
    fn no_plans_capability_warning() {
        let before = make_obs_set(vec![make_obs("", "Pod", Some("ns"), "p1", Some("uid-1"))]);
        let after = make_obs_set(vec![]);
        let report = audit(before, after, vec![]);
        assert!(
            report
                .capability_warnings
                .iter()
                .any(|w| w.contains("No execution plans"))
        );
        assert_eq!(
            report.removals[0].classification,
            AuditClassification::UnexplainedChange
        );
    }

    #[test]
    fn old_snapshot_capability_warning() {
        let snap = ClusterSnapshot {
            schema_version: Some(3),
            resources: HashMap::new(),
            scan_warnings: vec![],
            cluster_url: "https://api.test:6443".into(),
            taken_at: "2026-01-01T00:00:00Z".into(),
            namespaces: vec![],
            scope: None,
            observations: vec![],
        };
        let obs = snapshot_to_observation_set(&snap);
        assert!(
            obs.capability_warnings
                .iter()
                .any(|w| w.contains("deletion_timestamp"))
        );
    }

    #[test]
    fn keep_does_not_negate_delete() {
        let entry = make_obs("", "Sub", Some("ns"), "s1", Some("uid-s1"));
        let before = make_obs_set(vec![entry]);
        let after = make_obs_set(vec![]);
        // DELETE from one operator, KEEP from another — KEEP does not negate DELETE
        let plan1 = make_plan(vec![(
            "",
            "Sub",
            Some("ns"),
            "s1",
            "uid-s1",
            ExecutionAction::Delete,
        )]);
        let mut plan2 = make_plan(vec![(
            "",
            "Sub",
            Some("ns"),
            "s1",
            "uid-s1",
            ExecutionAction::Keep,
        )]);
        plan2.cluster_identity.kube_system_uid = "kube-uid".into();
        let report = audit(
            before,
            after,
            vec![("1-op-a.json".into(), plan1), ("2-op-b.json".into(), plan2)],
        );
        let r = &report.removals[0];
        assert_eq!(
            r.classification,
            AuditClassification::PlannedDirectDelete,
            "KEEP from another operator does not negate DELETE"
        );
        assert!(!report.plan_collision_warnings.is_empty());
    }

    #[test]
    fn identity_conflict_same_uid_different_identity_unexplained() {
        let entry = make_obs("", "Sub", Some("ns"), "s1", Some("uid-s1"));
        let before = make_obs_set(vec![entry]);
        let after = make_obs_set(vec![]);
        // Same UID, different identity across DELETEs → true conflict
        let plan1 = make_plan(vec![(
            "",
            "Sub",
            Some("ns"),
            "s1",
            "uid-s1",
            ExecutionAction::Delete,
        )]);
        let mut plan2 = make_plan(vec![(
            "other.group",
            "Sub",
            Some("ns"),
            "s1",
            "uid-s1",
            ExecutionAction::Delete,
        )]);
        plan2.cluster_identity.kube_system_uid = "kube-uid".into();
        let report = audit(
            before,
            after,
            vec![("1-op-a.json".into(), plan1), ("2-op-b.json".into(), plan2)],
        );
        let r = &report.removals[0];
        assert_eq!(
            r.classification,
            AuditClassification::UnexplainedChange,
            "different identity DELETEs on same UID → conflict"
        );
    }

    #[test]
    fn plan_same_action_dedup_ok() {
        let entry = make_obs("", "Sub", Some("ns"), "s1", Some("uid-s1"));
        let before = make_obs_set(vec![entry]);
        let after = make_obs_set(vec![]);
        let plan1 = make_plan(vec![(
            "",
            "Sub",
            Some("ns"),
            "s1",
            "uid-s1",
            ExecutionAction::Delete,
        )]);
        let plan2 = make_plan(vec![(
            "",
            "Sub",
            Some("ns"),
            "s1",
            "uid-s1",
            ExecutionAction::Delete,
        )]);
        let report = audit(
            before,
            after,
            vec![("1-op-a.json".into(), plan1), ("2-op-b.json".into(), plan2)],
        );
        let r = &report.removals[0];
        assert_eq!(
            r.classification,
            AuditClassification::PlannedDirectDelete,
            "same action from multiple operators is ok"
        );
    }

    #[test]
    fn input_order_reversal_byte_identical() {
        let e1 = make_obs("", "A", Some("ns"), "a1", Some("uid-1"));
        let e2 = make_obs("", "B", Some("ns"), "b1", Some("uid-2"));
        let plan = make_plan(vec![(
            "",
            "A",
            Some("ns"),
            "a1",
            "uid-1",
            ExecutionAction::Delete,
        )]);

        let before_a = make_obs_set(vec![e1.clone(), e2.clone()]);
        let before_b = make_obs_set(vec![e2, e1]);
        let after = make_obs_set(vec![]);

        let report_a = audit(
            before_a,
            after.clone(),
            vec![("plan.json".into(), plan.clone())],
        );
        let report_b = audit(before_b, after, vec![("plan.json".into(), plan)]);

        let json_a = serde_json::to_string_pretty(&report_a).unwrap();
        let json_b = serde_json::to_string_pretty(&report_b).unwrap();
        assert_eq!(json_a, json_b);
    }

    #[test]
    fn plan_cluster_identity_mismatch_error() {
        let before = make_obs_set(vec![]);
        let after = make_obs_set(vec![]);
        let mut plan1 = make_plan(vec![]);
        let mut plan2 = make_plan(vec![]);
        plan1.cluster_identity.kube_system_uid = "uid-1".into();
        plan2.cluster_identity.kube_system_uid = "uid-2".into();
        let result = run_audit(&AuditInput {
            before,
            after,
            plans: vec![("p1.json".into(), plan1), ("p2.json".into(), plan2)],
            gvr_catalog: None,
            provider_operands: None,
        });
        assert!(result.is_err());
    }

    #[test]
    fn cluster_url_mismatch_error() {
        let mut before = make_obs_set(vec![]);
        before.cluster_url = "https://cluster-a:6443".into();
        let mut after = make_obs_set(vec![]);
        after.cluster_url = "https://cluster-b:6443".into();
        let result = run_audit(&AuditInput {
            before,
            after,
            plans: vec![],
            gvr_catalog: None,
            provider_operands: None,
        });
        assert!(result.is_err());
    }

    #[test]
    fn orphan_ownerref_in_post() {
        let parent = make_obs("", "Dep", Some("ns"), "dep1", Some("uid-parent"));
        let child = make_obs_with_owner(
            "",
            "RS",
            Some("ns"),
            "rs1",
            "uid-child",
            "v1",
            "Dep",
            "dep1",
            "uid-parent",
        );

        let before = make_obs_set(vec![parent, child.clone()]);
        let after = make_obs_set(vec![child]);
        let plan = make_plan(vec![(
            "",
            "Dep",
            Some("ns"),
            "dep1",
            "uid-parent",
            ExecutionAction::Delete,
        )]);
        let report = audit(before, after, vec![("plan.json".into(), plan)]);
        assert_eq!(report.orphan_owner_refs.len(), 1);
    }

    #[test]
    fn ownerref_wrong_identity_not_in_closure() {
        let root = make_obs("", "Root", Some("ns"), "root", Some("uid-root"));
        // Child has ownerRef with correct UID but wrong kind
        let mut child = make_obs("", "Child", Some("ns"), "child", Some("uid-child"));
        child.owner_refs.push(ObsOwnerRef {
            api_version: "v1".into(),
            kind: "WrongKind".into(),
            name: "root".into(),
            uid: "uid-root".into(),
            controller: true,
            block_owner_deletion: false,
        });

        let before = make_obs_set(vec![root, child]);
        let after = make_obs_set(vec![]);
        let plan = make_plan(vec![(
            "",
            "Root",
            Some("ns"),
            "root",
            "uid-root",
            ExecutionAction::Delete,
        )]);
        let report = audit(before, after, vec![("plan.json".into(), plan)]);
        let child_r = report
            .removals
            .iter()
            .find(|r| r.uid == "uid-child")
            .unwrap();
        assert_eq!(
            child_r.classification,
            AuditClassification::UnexplainedChange,
            "ownerRef with wrong kind must not be in closure"
        );
    }

    #[test]
    fn dangling_spec_ref_typed_vs_heuristic() {
        let mut entry = make_obs("", "Deployment", Some("ns"), "dep1", Some("uid-dep"));
        entry.spec_refs.push(ObsSpecRef {
            target_kind: "Secret".into(),
            target_name: "missing-secret".into(),
            field_path: "spec.volumes.[0].secret.secretName".into(),
            target_group: None,
            target_namespace: None,
            source: SpecRefSourceLabel::Typed,
        });
        entry.spec_refs.push(ObsSpecRef {
            target_kind: "ConfigMap".into(),
            target_name: "missing-cm".into(),
            field_path: "spec.annotations.config-ref".into(),
            target_group: None,
            target_namespace: None,
            source: SpecRefSourceLabel::Heuristic,
        });

        // Targets must exist in pre to be flagged as dangling (proving removal)
        let pre_secret = make_obs("", "Secret", Some("ns"), "missing-secret", Some("uid-s"));
        let pre_cm = make_obs("", "ConfigMap", Some("ns"), "missing-cm", Some("uid-cm"));
        let before = make_obs_set(vec![pre_secret, pre_cm]);
        let after = make_obs_set(vec![entry]);
        let report = audit(before, after, vec![]);
        assert_eq!(report.dangling_spec_refs.len(), 2);
        let typed = report
            .dangling_spec_refs
            .iter()
            .find(|d| d.target_name == "missing-secret")
            .unwrap();
        assert_eq!(typed.ref_type, "typed");
        let heuristic = report
            .dangling_spec_refs
            .iter()
            .find(|d| d.target_name == "missing-cm")
            .unwrap();
        assert_eq!(heuristic.ref_type, "heuristic");
    }

    #[test]
    fn typed_secret_ref_different_group_stays_dangling() {
        let mut dep = make_obs("apps", "Deployment", Some("ns"), "dep1", Some("uid-dep"));
        dep.spec_refs.push(ObsSpecRef {
            target_kind: "Secret".into(),
            target_name: "my-secret".into(),
            field_path: "spec.volumes.[0].secret.secretName".into(),
            target_group: Some("".into()),
            target_namespace: None,
            source: SpecRefSourceLabel::Typed,
        });
        let custom_secret = make_obs(
            "custom.io",
            "Secret",
            Some("ns"),
            "my-secret",
            Some("uid-cs"),
        );

        // Target existed as core Secret in pre (now only custom.io/Secret exists in post)
        let pre_core_secret = make_obs("", "Secret", Some("ns"), "my-secret", Some("uid-core"));
        let before = make_obs_set(vec![pre_core_secret]);
        let after = make_obs_set(vec![dep, custom_secret]);
        let report = audit(before, after, vec![]);
        assert_eq!(
            report.dangling_spec_refs.len(),
            1,
            "core Secret ref must not match custom.io/Secret"
        );
    }

    #[test]
    fn future_audit_schema_roundtrip() {
        let report = AuditReport {
            schema_version: 999,
            before_taken_at: "".into(),
            after_taken_at: "".into(),
            cluster_url: "".into(),
            plans_loaded: vec![],
            capability_warnings: vec![],
            layers: AuditLayers {
                raw_observations: RawObsLayer { pre: 0, post: 0 },
                physical_uids: PhysicalLayer {
                    pre: 0,
                    post: 0,
                    removed: 0,
                    added: 0,
                    multi_observed: 0,
                },
                logical: LogicalLayer { pre: 0, post: 0 },
                uid_null: UidNullLayer {
                    pre: 0,
                    post: 0,
                    removed_fingerprints: 0,
                    added_fingerprints: 0,
                    pre_fingerprint_collision_groups: 0,
                    post_fingerprint_collision_groups: 0,
                },
            },
            classification_summary: BTreeMap::new(),
            removals: vec![],
            recreated: vec![],
            closure: ClosureSummary {
                delete_seeds: 0,
                total_closure: 0,
                removed_in_closure: 0,
            },
            terminating: TerminatingSummary {
                newly_terminating: 0,
                preexisting_retained: 0,
                details: vec![],
            },
            orphan_owner_refs: vec![],
            dangling_spec_refs: vec![],
            provider_operand_results: vec![],
            plan_collision_warnings: vec![],
        };
        let json = serde_json::to_string(&report).unwrap();
        let parsed: AuditReport = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.schema_version, 999);
    }

    #[test]
    fn same_logical_two_pre_uids_not_silently_overwritten() {
        let o1 = make_obs("apps", "Deployment", Some("ns"), "web", Some("uid-1"));
        let o2 = make_obs("apps", "Deployment", Some("ns"), "web", Some("uid-2"));
        let before = make_obs_set(vec![o1, o2]);
        let after = make_obs_set(vec![]);
        let report = audit(before, after, vec![]);
        assert_eq!(report.removals.len(), 2, "both UIDs must appear");
    }

    #[test]
    fn namespaced_owner_different_namespace_not_in_closure() {
        let parent = make_obs(
            "apps",
            "Deployment",
            Some("ns-a"),
            "dep",
            Some("uid-parent"),
        );
        let mut child = make_obs("", "Pod", Some("ns-b"), "pod", Some("uid-child"));
        child.owner_refs.push(ObsOwnerRef {
            api_version: "apps/v1".into(),
            kind: "Deployment".into(),
            name: "dep".into(),
            uid: "uid-parent".into(),
            controller: true,
            block_owner_deletion: false,
        });

        let before = make_obs_set(vec![parent, child]);
        let after = make_obs_set(vec![]);
        let plan = make_plan(vec![(
            "apps",
            "Deployment",
            Some("ns-a"),
            "dep",
            "uid-parent",
            ExecutionAction::Delete,
        )]);
        let report = audit(before, after, vec![("plan.json".into(), plan)]);
        let child_r = report
            .removals
            .iter()
            .find(|r| r.uid == "uid-child")
            .unwrap();
        assert_eq!(
            child_r.classification,
            AuditClassification::UnexplainedChange,
            "namespaced owner in different namespace must not be in closure"
        );
    }

    #[test]
    fn cluster_scoped_owner_can_own_namespaced_child() {
        let parent = make_obs(
            "apiextensions.k8s.io",
            "CustomResourceDefinition",
            None,
            "widgets.example.io",
            Some("uid-crd"),
        );
        let mut child = make_obs("", "ConfigMap", Some("ns"), "cm", Some("uid-cm"));
        child.owner_refs.push(ObsOwnerRef {
            api_version: "apiextensions.k8s.io/v1".into(),
            kind: "CustomResourceDefinition".into(),
            name: "widgets.example.io".into(),
            uid: "uid-crd".into(),
            controller: true,
            block_owner_deletion: false,
        });

        let before = make_obs_set(vec![parent, child]);
        let after = make_obs_set(vec![]);
        let plan = make_plan(vec![(
            "apiextensions.k8s.io",
            "CustomResourceDefinition",
            None,
            "widgets.example.io",
            "uid-crd",
            ExecutionAction::Delete,
        )]);
        let report = audit(before, after, vec![("plan.json".into(), plan)]);
        let child_r = report.removals.iter().find(|r| r.uid == "uid-cm").unwrap();
        assert_eq!(
            child_r.classification,
            AuditClassification::OwnerRefGcDescendant,
            "cluster-scoped parent can own namespaced child"
        );
    }

    #[test]
    fn orphan_wrong_identity_not_reported() {
        let parent = make_obs("", "Dep", Some("ns"), "dep1", Some("uid-parent"));
        let mut child = make_obs("", "RS", Some("ns"), "rs1", Some("uid-child"));
        child.owner_refs.push(ObsOwnerRef {
            api_version: "v1".into(),
            kind: "WrongKind".into(),
            name: "wrong-name".into(),
            uid: "uid-parent".into(),
            controller: true,
            block_owner_deletion: false,
        });

        let before = make_obs_set(vec![parent, child.clone()]);
        let after = make_obs_set(vec![child]);
        let plan = make_plan(vec![(
            "",
            "Dep",
            Some("ns"),
            "dep1",
            "uid-parent",
            ExecutionAction::Delete,
        )]);
        let report = audit(before, after, vec![("plan.json".into(), plan)]);
        assert_eq!(
            report.orphan_owner_refs.len(),
            0,
            "stale/wrong identity ownerRef must not be reported as orphan"
        );
    }

    #[test]
    fn canonical_alias_order_independent() {
        let obs1 = make_obs("events.k8s.io", "Event", Some("ns"), "ev1", Some("uid-ev"));
        let mut obs2 = make_obs("", "Event", Some("ns"), "ev1", Some("uid-ev"));
        obs2.resource = "events".into();

        let before_a = make_obs_set(vec![obs1.clone(), obs2.clone()]);
        let before_b = make_obs_set(vec![obs2, obs1]);
        let after = make_obs_set(vec![]);

        let report_a = audit(before_a, after.clone(), vec![]);
        let report_b = audit(before_b, after, vec![]);

        let json_a = serde_json::to_string_pretty(&report_a).unwrap();
        let json_b = serde_json::to_string_pretty(&report_b).unwrap();
        assert_eq!(json_a, json_b, "alias order must not affect output");
    }

    #[test]
    fn incomplete_scope_produces_capability_warning() {
        use crate::kube::resource::*;
        let snap = ClusterSnapshot {
            schema_version: Some(4),
            resources: HashMap::new(),
            scan_warnings: vec![ScanWarning::Forbidden {
                gvr: "v1/secrets".into(),
                status: 403,
            }],
            cluster_url: "https://api.test:6443".into(),
            taken_at: "2026-01-01T00:00:00Z".into(),
            namespaces: vec!["ns".into()],
            scope: Some(SnapshotScope {
                mode: "single-namespace".into(),
                incomplete_namespaces: vec![IncompleteNamespace {
                    namespace: "ns".into(),
                    warnings: vec![ScanWarning::Forbidden {
                        gvr: "v1/secrets".into(),
                        status: 403,
                    }],
                    error: None,
                }],
                ..Default::default()
            }),
            observations: vec![],
        };
        let obs = snapshot_to_observation_set(&snap);
        assert!(
            obs.capability_warnings
                .iter()
                .any(|w| w.contains("scan warnings")),
            "scan warnings must propagate"
        );
        assert!(
            obs.capability_warnings
                .iter()
                .any(|w| w.contains("incomplete")),
            "incomplete scope must propagate"
        );
    }

    #[test]
    fn incomplete_after_downgrades_to_unexplained() {
        let entry = make_obs("", "Pod", Some("ns"), "p1", Some("uid-1"));
        let before = make_obs_set(vec![entry]);
        let mut after = make_obs_set(vec![]);
        after.absence_coverage = AbsenceCoverage::Incomplete {
            incomplete_namespaces: vec!["ns".into()],
            scan_warning_count: 1,
        };

        let plan = make_plan(vec![(
            "",
            "Pod",
            Some("ns"),
            "p1",
            "uid-1",
            ExecutionAction::Delete,
        )]);
        let report = audit(before, after, vec![("plan.json".into(), plan)]);
        let r = &report.removals[0];
        assert_eq!(
            r.classification,
            AuditClassification::UnexplainedChange,
            "incomplete after must not strongly classify even with plan DELETE"
        );
        assert!(r.evidence.as_ref().unwrap().contains("absence not proven"),);

        // Provider operand also downgraded
        let provider = ProviderApiOperands {
            schema_version: Some(2),
            count: 1,
            cases: vec![ProviderCase {
                group: "".into(),
                kind: "Pod".into(),
                namespace: Some("ns".into()),
                name: "p1".into(),
                uid: Some("uid-1".into()),
                api_provider_operator: "test-op".into(),
                lifecycle_owner_evidence: None,
                provider_api_evidence: None,
                observed_versions: None,
            }],
        };
        let entry2 = make_obs("", "Pod", Some("ns"), "p1", Some("uid-1"));
        let before2 = make_obs_set(vec![entry2]);
        let mut after2 = make_obs_set(vec![]);
        after2.absence_coverage = AbsenceCoverage::Incomplete {
            incomplete_namespaces: vec!["ns".into()],
            scan_warning_count: 1,
        };
        let plan2 = make_plan(vec![(
            "",
            "Pod",
            Some("ns"),
            "p1",
            "uid-1",
            ExecutionAction::Delete,
        )]);
        let report2 = run_audit(&AuditInput {
            before: before2,
            after: after2,
            plans: vec![("plan.json".into(), plan2)],
            gvr_catalog: None,
            provider_operands: Some(provider),
        })
        .unwrap();
        assert_eq!(
            report2.provider_operand_results[0].physical_classification,
            AuditClassification::UnexplainedChange,
            "incomplete after → provider also UnexplainedChange"
        );
        assert!(
            report2.orphan_owner_refs.is_empty(),
            "incomplete after → orphan suppressed"
        );
        assert!(
            report2.recreated.is_empty(),
            "incomplete after → recreated suppressed"
        );
    }

    #[test]
    fn orphan_wrong_namespace_not_reported() {
        let parent = make_obs(
            "apps",
            "Deployment",
            Some("ns-a"),
            "dep1",
            Some("uid-parent"),
        );
        let mut child = make_obs("", "RS", Some("ns-b"), "rs1", Some("uid-child"));
        child.owner_refs.push(ObsOwnerRef {
            api_version: "apps/v1".into(),
            kind: "Deployment".into(),
            name: "dep1".into(),
            uid: "uid-parent".into(),
            controller: true,
            block_owner_deletion: false,
        });

        let before = make_obs_set(vec![parent, child.clone()]);
        let after = make_obs_set(vec![child]);
        let plan = make_plan(vec![(
            "apps",
            "Deployment",
            Some("ns-a"),
            "dep1",
            "uid-parent",
            ExecutionAction::Delete,
        )]);
        let report = audit(before, after, vec![("plan.json".into(), plan)]);
        assert_eq!(
            report.orphan_owner_refs.len(),
            0,
            "namespaced owner in different namespace must not be reported as orphan"
        );
    }

    #[test]
    fn heuristic_dangling_with_correct_kind() {
        // Pre has a ConfigMap that the deployment references via heuristic string match
        let pre_cm = make_obs("", "ConfigMap", Some("ns"), "shared-config", Some("uid-cm"));
        let mut dep = make_obs("apps", "Deployment", Some("ns"), "dep1", Some("uid-dep"));
        // Simulate heuristic ref with correct kind
        dep.spec_refs.push(ObsSpecRef {
            target_kind: "ConfigMap".into(),
            target_name: "shared-config".into(),
            field_path: "spec.template.spec.containers.[0].env.[0].value".into(),
            target_group: None,
            target_namespace: None,
            source: SpecRefSourceLabel::Heuristic,
        });

        let before = make_obs_set(vec![pre_cm, dep.clone()]);
        let after = make_obs_set(vec![dep]);
        let report = audit(before, after, vec![]);
        assert_eq!(
            report.dangling_spec_refs.len(),
            1,
            "heuristic ref to removed ConfigMap should be dangling"
        );
        assert_eq!(report.dangling_spec_refs[0].target_kind, "ConfigMap");
        assert_eq!(report.dangling_spec_refs[0].ref_type, "heuristic");
    }

    #[test]
    fn heuristic_same_name_two_kinds_two_edges() {
        let cm = make_obs("", "ConfigMap", Some("ns"), "shared-name", Some("uid-cm"));
        let secret = make_obs("", "Secret", Some("ns"), "shared-name", Some("uid-sec"));
        let mut dep = make_obs("apps", "Deployment", Some("ns"), "dep1", Some("uid-dep"));
        dep.spec_refs.push(ObsSpecRef {
            target_kind: "ConfigMap".into(),
            target_name: "shared-name".into(),
            field_path: "spec.env.val".into(),
            target_group: None,
            target_namespace: None,
            source: SpecRefSourceLabel::Heuristic,
        });
        dep.spec_refs.push(ObsSpecRef {
            target_kind: "Secret".into(),
            target_name: "shared-name".into(),
            field_path: "spec.env.val".into(),
            target_group: None,
            target_namespace: None,
            source: SpecRefSourceLabel::Heuristic,
        });

        let before = make_obs_set(vec![cm.clone(), secret.clone(), dep.clone()]);
        // Both targets removed
        let after = make_obs_set(vec![dep]);
        let report = audit(before, after, vec![]);
        assert_eq!(
            report.dangling_spec_refs.len(),
            2,
            "two kinds with same name → two dangling edges"
        );
        let kinds: HashSet<_> = report
            .dangling_spec_refs
            .iter()
            .map(|d| d.target_kind.as_str())
            .collect();
        assert!(kinds.contains("ConfigMap"));
        assert!(kinds.contains("Secret"));
    }
}
