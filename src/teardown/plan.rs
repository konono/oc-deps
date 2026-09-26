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
#[serde(deny_unknown_fields)]
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
#[serde(deny_unknown_fields)]
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

pub fn validate_package_name(pkg: Option<&str>, csv_name: &str) -> anyhow::Result<String> {
    let Some(p) = pkg else {
        anyhow::bail!(
            "Operator {} has no package_name (no Subscription and CSV annotation evidence empty or ambiguous)",
            csv_name
        );
    };
    if p.trim().is_empty() || p != p.trim() {
        anyhow::bail!(
            "Operator {} has invalid package_name '{}' (empty or whitespace)",
            csv_name,
            p
        );
    }
    Ok(p.to_string())
}

pub const EXECUTION_PLAN_SCHEMA_VERSION: u32 = 2;

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
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub explicit_deletes: Vec<ExplicitDeleteTarget>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExplicitDeleteTarget {
    pub group: String,
    pub kind: String,
    pub namespace: Option<String>,
    pub name: String,
    pub uid: String,
    pub reason: String,
    pub inbound_refs_at_plan: Vec<InboundRefIdentity>,
    pub ref_scan_coverage: RefScanCoverage,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InboundRefIdentity {
    pub group: String,
    pub kind: String,
    pub namespace: Option<String>,
    pub name: String,
    pub uid: String,
    pub ref_field: String,
    pub in_deletion_plan: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RefScanCoverage {
    pub kinds_scanned: Vec<String>,
    pub scan_complete: bool,
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

pub fn csv_name_matches(saved_pattern: &str, live_csv_name: &str) -> bool {
    saved_pattern == live_csv_name
}

static SAVE_COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

pub fn save_execution_plan(plan: &ExecutionPlan, path: &str) -> anyhow::Result<()> {
    use std::io::Write;
    let parent = std::path::Path::new(path)
        .parent()
        .ok_or_else(|| anyhow::anyhow!("No parent directory for {}", path))?;

    struct TempGuard {
        path: std::path::PathBuf,
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

    let seq = SAVE_COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let tmp_path = parent.join(format!(".tmp_exec_plan_{}_{}", std::process::id(), seq));

    let json = serde_json::to_string_pretty(plan)?;
    let mut f = std::fs::File::create_new(&tmp_path)
        .with_context(|| format!("Failed to create temp file: {}", tmp_path.display()))?;
    let mut guard = TempGuard {
        path: tmp_path.clone(),
        armed: true,
    };
    f.write_all(json.as_bytes())?;
    f.sync_all()?;
    drop(f);
    std::fs::rename(&tmp_path, path)
        .with_context(|| format!("Failed to rename {} -> {}", tmp_path.display(), path))?;
    guard.disarm();
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
    // Validate targets have valid package_name
    for target in &plan.targets {
        validate_package_name(Some(&target.package_name), &target.csv_name_pattern)?;
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
    for phase in &plan.phases {
        for res in &phase.resources {
            if matches!(
                res.action,
                ExecutionAction::Delete | ExecutionAction::Expect | ExecutionAction::Wait
            ) && (res.uid.is_none() || res.uid.as_deref() == Some(""))
            {
                anyhow::bail!(
                    "Resource {}/{} in phase {} has action {} but no UID — plan may be tampered",
                    res.kind,
                    res.name,
                    phase.phase,
                    res.action
                );
            }
        }
    }
    const FORBIDDEN_EXPLICIT_KINDS: &[&str] = &[
        "Namespace",
        "PersistentVolume",
        "PersistentVolumeClaim",
        "CustomResourceDefinition",
        "APIService",
    ];
    for target in &plan.explicit_deletes {
        if target.uid.trim().is_empty() {
            anyhow::bail!(
                "Explicit delete target {}/{} has empty UID",
                target.kind,
                target.name
            );
        }
        if target.kind.trim().is_empty() || target.name.trim().is_empty() {
            anyhow::bail!(
                "Explicit delete target has empty kind or name: kind={:?}, name={:?}",
                target.kind,
                target.name
            );
        }
        if FORBIDDEN_EXPLICIT_KINDS.contains(&target.kind.as_str()) {
            anyhow::bail!(
                "Explicit delete target {}/{} uses forbidden kind {}",
                target.kind,
                target.name,
                target.kind
            );
        }
        if !target.ref_scan_coverage.scan_complete {
            anyhow::bail!(
                "Explicit delete target {}/{} has incomplete reference scan — plan is unsafe",
                target.kind,
                target.name
            );
        }
    }
    // Tamper check: explicit_deletes must exactly match Explicit cleanup phase actions
    #[allow(clippy::type_complexity)]
    let explicit_phase_actions: Vec<(&str, &str, Option<&str>, &str, Option<&str>)> = plan
        .phases
        .iter()
        .filter(|p| p.name == EXPLICIT_CLEANUP_PHASE_NAME)
        .flat_map(|p| &p.resources)
        .filter(|r| r.action == ExecutionAction::Delete)
        .map(|r| {
            (
                r.group.as_str(),
                r.kind.as_str(),
                r.namespace.as_deref(),
                r.name.as_str(),
                r.uid.as_deref(),
            )
        })
        .collect();
    let explicit_delete_specs: Vec<(&str, &str, Option<&str>, &str, &str)> = plan
        .explicit_deletes
        .iter()
        .map(|t| {
            (
                t.group.as_str(),
                t.kind.as_str(),
                t.namespace.as_deref(),
                t.name.as_str(),
                t.uid.as_str(),
            )
        })
        .collect();
    if explicit_delete_specs.len() != explicit_phase_actions.len() {
        anyhow::bail!(
            "Explicit delete count mismatch: {} explicit_deletes vs {} Explicit cleanup actions — plan may be tampered",
            explicit_delete_specs.len(),
            explicit_phase_actions.len()
        );
    }
    for (i, spec) in explicit_delete_specs.iter().enumerate() {
        let matching = explicit_phase_actions.iter().any(|a| {
            a.0 == spec.0 && a.1 == spec.1 && a.2 == spec.2 && a.3 == spec.3 && a.4 == Some(spec.4)
        });
        if !matching {
            anyhow::bail!(
                "Explicit delete {} ({}/{}) has no matching Explicit cleanup phase action — plan may be tampered",
                i,
                plan.explicit_deletes[i].kind,
                plan.explicit_deletes[i].name
            );
        }
    }
    // Also check no extra actions in explicit phase
    for action in &explicit_phase_actions {
        let matching = explicit_delete_specs
            .iter()
            .any(|s| s.0 == action.0 && s.1 == action.1 && s.2 == action.2 && s.3 == action.3);
        if !matching {
            anyhow::bail!(
                "Explicit cleanup phase has action {}/{} with no matching explicit_delete — plan may be tampered",
                action.1,
                action.3
            );
        }
    }
    Ok(plan)
}

/// Validate an execution plan against a freshly generated plan.
/// Uses sorted Vec of full tuples (phase, name, action, group, kind, ns, name, uid)
/// to detect additions, removals, UID changes, phase moves, and duplicates.
pub const EXPLICIT_CLEANUP_PHASE_NAME: &str = "Explicit cleanup";

pub fn validate_execution_plan_against_fresh(
    saved: &ExecutionPlan,
    fresh: &ExecutionPlan,
) -> Result<(), Vec<String>> {
    let mut errors = Vec::new();

    // Exclude explicit cleanup phases — they are not reproduced by fresh plan generation
    let saved_phases: Vec<&ExecutionPhase> = saved
        .phases
        .iter()
        .filter(|p| p.name != EXPLICIT_CLEANUP_PHASE_NAME)
        .collect();
    let fresh_phases: Vec<&ExecutionPhase> = fresh
        .phases
        .iter()
        .filter(|p| p.name != EXPLICIT_CLEANUP_PHASE_NAME)
        .collect();

    if saved_phases.len() != fresh_phases.len() {
        errors.push(format!(
            "Phase count drift: saved {} phases, fresh {} phases",
            saved_phases.len(),
            fresh_phases.len()
        ));
    }

    let saved_phase_names: Vec<&str> = saved_phases.iter().map(|p| p.name.as_str()).collect();
    let fresh_phase_names: Vec<&str> = fresh_phases.iter().map(|p| p.name.as_str()).collect();
    for (i, (s, f)) in saved_phase_names
        .iter()
        .zip(fresh_phase_names.iter())
        .enumerate()
    {
        if s != f {
            errors.push(format!(
                "Phase name drift at index {}: saved {:?} vs fresh {:?}",
                i, s, f
            ));
        }
    }

    type FullTuple = (
        u32,
        String,
        String,
        String,
        String,
        Option<String>,
        String,
        Option<String>,
    );

    let build_sorted = |plan: &ExecutionPlan| -> Vec<FullTuple> {
        let mut tuples: Vec<FullTuple> = plan
            .phases
            .iter()
            .filter(|p| p.name != EXPLICIT_CLEANUP_PHASE_NAME)
            .enumerate()
            .flat_map(|(idx, p)| {
                p.resources.iter().map(move |r| {
                    (
                        (idx + 1) as u32,
                        p.name.clone(),
                        r.action.to_string(),
                        r.group.clone(),
                        r.kind.clone(),
                        r.namespace.clone(),
                        r.name.clone(),
                        r.uid.clone(),
                    )
                })
            })
            .collect();
        tuples.sort();
        tuples
    };

    let saved_tuples = build_sorted(saved);
    let fresh_tuples = build_sorted(fresh);

    if saved_tuples.len() != fresh_tuples.len() {
        errors.push(format!(
            "Resource count drift: saved {}, fresh {}",
            saved_tuples.len(),
            fresh_tuples.len()
        ));
    }

    // Use multiset-style comparison: count occurrences and compare
    use std::collections::HashMap;
    let mut saved_counts: HashMap<&FullTuple, usize> = HashMap::new();
    for t in &saved_tuples {
        *saved_counts.entry(t).or_default() += 1;
    }
    let mut fresh_counts: HashMap<&FullTuple, usize> = HashMap::new();
    for t in &fresh_tuples {
        *fresh_counts.entry(t).or_default() += 1;
    }

    for (t, &sc) in &saved_counts {
        let fc = fresh_counts.get(t).copied().unwrap_or(0);
        if fc < sc {
            errors.push(format!(
                "Resource missing from cluster: phase {}/{} {} {}/{} uid={:?} (×{})",
                t.0,
                t.1,
                t.2,
                t.4,
                t.6,
                t.7,
                sc - fc
            ));
        }
    }
    for (t, &fc) in &fresh_counts {
        let sc = saved_counts.get(t).copied().unwrap_or(0);
        if fc > sc {
            errors.push(format!(
                "Resource added since plan: phase {}/{} {} {}/{} uid={:?} (×{})",
                t.0,
                t.1,
                t.2,
                t.4,
                t.6,
                t.7,
                fc - sc
            ));
        }
    }

    // UID changes: same identity (phase, action, group, kind, ns, name) but different UID
    type IdKey = (u32, String, String, String, Option<String>, String);
    let id_key = |t: &FullTuple| -> IdKey {
        (
            t.0,
            t.2.clone(),
            t.3.clone(),
            t.4.clone(),
            t.5.clone(),
            t.6.clone(),
        )
    };
    let mut saved_uids: HashMap<IdKey, Option<String>> = HashMap::new();
    for t in &saved_tuples {
        saved_uids.insert(id_key(t), t.7.clone());
    }
    for t in &fresh_tuples {
        let key = id_key(t);
        if let Some(saved_uid) = saved_uids.get(&key)
            && saved_uid != &t.7
        {
            errors.push(format!(
                "UID changed for {}/{} in {:?}: saved {:?} → fresh {:?}",
                t.4, t.6, t.5, saved_uid, t.7
            ));
        }
    }

    if errors.is_empty() {
        Ok(())
    } else {
        Err(errors)
    }
}

// ──────────────────────────────────────────────────────────────
//  Explicit target authority validation
// ──────────────────────────────────────────────────────────────

type ExplicitTargetKey = (
    String,         // group
    String,         // kind
    Option<String>, // namespace
    String,         // name
    String,         // uid
    String,         // reason
);

fn explicit_target_canonical_key(t: &ExplicitDeleteTarget) -> ExplicitTargetKey {
    (
        t.group.clone(),
        t.kind.clone(),
        t.namespace.clone(),
        t.name.clone(),
        t.uid.clone(),
        t.reason.clone(),
    )
}

type CanonicalInboundRef = (String, String, Option<String>, String, String, String, bool);

fn canonical_inbound_refs(refs: &[InboundRefIdentity]) -> Vec<CanonicalInboundRef> {
    let mut sorted: Vec<_> = refs
        .iter()
        .map(|r| {
            (
                r.group.clone(),
                r.kind.clone(),
                r.namespace.clone(),
                r.name.clone(),
                r.uid.clone(),
                r.ref_field.clone(),
                r.in_deletion_plan,
            )
        })
        .collect();
    sorted.sort();
    sorted
}

fn canonical_coverage(c: &RefScanCoverage) -> (bool, Vec<String>) {
    let mut kinds = c.kinds_scanned.clone();
    kinds.sort();
    (c.scan_complete, kinds)
}

pub fn validate_explicit_targets_authority(
    saved: &[ExplicitDeleteTarget],
    fresh: &[ExplicitDeleteTarget],
    plan_phases: &[ExecutionPhase],
) -> Result<(), Vec<String>> {
    use std::collections::HashMap;
    let mut errors = Vec::new();

    // 1. Reject duplicate identities in saved
    {
        let mut seen: HashMap<(String, String, Option<String>, String), usize> = HashMap::new();
        for t in saved {
            let id = (
                t.group.clone(),
                t.kind.clone(),
                t.namespace.clone(),
                t.name.clone(),
            );
            *seen.entry(id).or_default() += 1;
        }
        for ((g, k, ns, n), count) in &seen {
            if *count > 1 {
                errors.push(format!(
                    "Duplicate explicit target in saved metadata: {}/{} ns={:?} name={} (×{})",
                    g, k, ns, n, count
                ));
            }
        }
    }

    // 2. Count check
    if saved.len() != fresh.len() {
        errors.push(format!(
            "Explicit target count mismatch: saved {}, fresh {}",
            saved.len(),
            fresh.len()
        ));
        return Err(errors);
    }

    // 3. Order-independent multiset comparison of full canonical representation
    type CanonicalTarget = (
        ExplicitTargetKey,
        Vec<CanonicalInboundRef>,
        (bool, Vec<String>),
    );

    let canonicalize = |targets: &[ExplicitDeleteTarget]| -> Vec<CanonicalTarget> {
        let mut result: Vec<CanonicalTarget> = targets
            .iter()
            .map(|t| {
                (
                    explicit_target_canonical_key(t),
                    canonical_inbound_refs(&t.inbound_refs_at_plan),
                    canonical_coverage(&t.ref_scan_coverage),
                )
            })
            .collect();
        result.sort_by(|a, b| a.0.cmp(&b.0));
        result
    };

    let saved_canonical = canonicalize(saved);
    let fresh_canonical = canonicalize(fresh);

    for (i, (s, f)) in saved_canonical
        .iter()
        .zip(fresh_canonical.iter())
        .enumerate()
    {
        if s.0 != f.0 {
            errors.push(format!(
                "Explicit target identity mismatch at [{}]: saved ({}/{} uid={}) vs fresh ({}/{} uid={})",
                i, (s.0).1, (s.0).3, (s.0).4, (f.0).1, (f.0).3, (f.0).4
            ));
        }
        if s.1 != f.1 {
            errors.push(format!(
                "Explicit target inbound_refs mismatch for {}/{}: saved {} refs vs fresh {} refs",
                (s.0).1,
                (s.0).3,
                s.1.len(),
                f.1.len()
            ));
        }
        if s.2 != f.2 {
            errors.push(format!(
                "Explicit target coverage mismatch for {}/{}: saved complete={} vs fresh complete={}",
                (s.0).1, (s.0).3, (s.2).0, (f.2).0
            ));
        }
    }

    // 4. Cross-check: explicit_deletes metadata must match Explicit cleanup phase DELETE actions 1:1
    let phase_explicit_actions: Vec<(String, String, Option<String>, String)> = plan_phases
        .iter()
        .filter(|p| p.name == EXPLICIT_CLEANUP_PHASE_NAME)
        .flat_map(|p| {
            p.resources.iter().filter_map(|r| {
                if r.action == ExecutionAction::Delete {
                    Some((
                        r.group.clone(),
                        r.kind.clone(),
                        r.namespace.clone(),
                        r.name.clone(),
                    ))
                } else {
                    None
                }
            })
        })
        .collect();

    let metadata_identities: Vec<(String, String, Option<String>, String)> = saved
        .iter()
        .map(|t| {
            (
                t.group.clone(),
                t.kind.clone(),
                t.namespace.clone(),
                t.name.clone(),
            )
        })
        .collect();

    let mut meta_sorted = metadata_identities.clone();
    meta_sorted.sort();
    let mut phase_sorted = phase_explicit_actions.clone();
    phase_sorted.sort();

    if meta_sorted != phase_sorted {
        errors.push(format!(
            "Explicit cleanup phase actions ({}) do not match metadata explicit_deletes ({})",
            phase_sorted.len(),
            meta_sorted.len()
        ));
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
#[allow(clippy::cloned_ref_to_slice_refs)]
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
            explicit_deletes: vec![],
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
            "schema_version": 2,
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
            "schema_version": 2,
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
        assert_eq!(loaded.schema_version, 2);
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

    #[test]
    fn load_rejects_delete_with_uid_none() {
        let mut plan = make_exec_plan(
            "uid-1",
            vec![(
                "",
                "Sub",
                Some("ns"),
                "sub1",
                Some("uid-a"),
                ExecutionAction::Delete,
            )],
        );
        plan.phases[0].resources[0].uid = None;
        let dir = std::env::temp_dir().join(format!("test-uid-none-{}", std::process::id()));
        let _ = std::fs::create_dir_all(&dir);
        let path = dir.join("plan.json");
        save_execution_plan(&plan, path.to_str().unwrap()).unwrap();
        let result = load_execution_plan(path.to_str().unwrap());
        let _ = std::fs::remove_dir_all(&dir);
        assert!(result.is_err());
        assert!(format!("{}", result.unwrap_err()).contains("no UID"));
    }

    #[test]
    fn load_rejects_delete_with_uid_empty() {
        let mut plan = make_exec_plan(
            "uid-1",
            vec![(
                "",
                "Sub",
                Some("ns"),
                "sub1",
                Some("uid-a"),
                ExecutionAction::Delete,
            )],
        );
        plan.phases[0].resources[0].uid = Some(String::new());
        let dir = std::env::temp_dir().join(format!("test-uid-empty-{}", std::process::id()));
        let _ = std::fs::create_dir_all(&dir);
        let path = dir.join("plan.json");
        save_execution_plan(&plan, path.to_str().unwrap()).unwrap();
        let result = load_execution_plan(path.to_str().unwrap());
        let _ = std::fs::remove_dir_all(&dir);
        assert!(result.is_err());
    }

    #[test]
    fn load_accepts_keep_without_uid() {
        let mut plan = make_exec_plan(
            "uid-1",
            vec![("", "NS", Some("ns"), "ns1", None, ExecutionAction::Keep)],
        );
        plan.phases[0].resources[0].uid = None;
        let dir = std::env::temp_dir().join(format!("test-keep-none-{}", std::process::id()));
        let _ = std::fs::create_dir_all(&dir);
        let path = dir.join("plan.json");
        save_execution_plan(&plan, path.to_str().unwrap()).unwrap();
        let result = load_execution_plan(path.to_str().unwrap());
        let _ = std::fs::remove_dir_all(&dir);
        assert!(result.is_ok());
    }

    #[test]
    fn drift_empty_phase_name_change() {
        let mut saved = make_exec_plan("uid-1", vec![]);
        saved.phases[0].name = "Original".into();
        let mut fresh = make_exec_plan("uid-1", vec![]);
        fresh.phases[0].name = "Tampered".into();
        let result = validate_execution_plan_against_fresh(&saved, &fresh);
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .iter()
                .any(|e| e.contains("Phase name drift"))
        );
    }

    #[test]
    fn drift_uid_none_vs_some() {
        let saved = make_exec_plan(
            "uid-1",
            vec![("", "Svc", Some("ns"), "svc1", None, ExecutionAction::Keep)],
        );
        let fresh = make_exec_plan(
            "uid-1",
            vec![(
                "",
                "Svc",
                Some("ns"),
                "svc1",
                Some("new-uid"),
                ExecutionAction::Keep,
            )],
        );
        let result = validate_execution_plan_against_fresh(&saved, &fresh);
        assert!(result.is_err());
    }

    #[test]
    fn drift_namespace_none_vs_empty() {
        let saved = make_exec_plan(
            "uid-1",
            vec![(
                "",
                "CRD",
                None,
                "crd1",
                Some("uid-c"),
                ExecutionAction::Keep,
            )],
        );
        let fresh = make_exec_plan(
            "uid-1",
            vec![(
                "",
                "CRD",
                Some(""),
                "crd1",
                Some("uid-c"),
                ExecutionAction::Keep,
            )],
        );
        let result = validate_execution_plan_against_fresh(&saved, &fresh);
        assert!(result.is_err(), "None and Some('') namespace must differ");
    }

    #[test]
    fn nested_unknown_cluster_identity() {
        let json = r#"{"api_server":"url","kube_system_uid":"uid","extra":"bad"}"#;
        let result: Result<ClusterIdentity, _> = serde_json::from_str(json);
        assert!(result.is_err());
    }

    #[test]
    fn nested_unknown_saved_operator_target() {
        let json = r#"{"package_name":"p","install_namespace":"ns","csv_name_pattern":"csv","extra":"bad"}"#;
        let result: Result<SavedOperatorTarget, _> = serde_json::from_str(json);
        assert!(result.is_err());
    }

    #[test]
    fn load_rejects_expect_with_uid_none() {
        let mut plan = make_exec_plan(
            "uid-1",
            vec![(
                "",
                "Pod",
                Some("ns"),
                "p1",
                Some("uid-x"),
                ExecutionAction::Expect,
            )],
        );
        plan.phases[0].resources[0].uid = None;
        let dir = std::env::temp_dir().join(format!("test-expect-none-{}", std::process::id()));
        let _ = std::fs::create_dir_all(&dir);
        let p = dir.join("plan.json");
        save_execution_plan(&plan, p.to_str().unwrap()).unwrap();
        assert!(load_execution_plan(p.to_str().unwrap()).is_err());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn load_rejects_wait_with_uid_empty() {
        let mut plan = make_exec_plan(
            "uid-1",
            vec![(
                "",
                "Pod",
                Some("ns"),
                "p1",
                Some("uid-x"),
                ExecutionAction::Wait,
            )],
        );
        plan.phases[0].resources[0].uid = Some(String::new());
        let dir = std::env::temp_dir().join(format!("test-wait-empty-{}", std::process::id()));
        let _ = std::fs::create_dir_all(&dir);
        let p = dir.join("plan.json");
        save_execution_plan(&plan, p.to_str().unwrap()).unwrap();
        assert!(load_execution_plan(p.to_str().unwrap()).is_err());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn load_accepts_review_without_uid() {
        let plan = make_exec_plan(
            "uid-1",
            vec![("", "OG", Some("ns"), "og1", None, ExecutionAction::Review)],
        );
        let dir = std::env::temp_dir().join(format!("test-review-none-{}", std::process::id()));
        let _ = std::fs::create_dir_all(&dir);
        let p = dir.join("plan.json");
        save_execution_plan(&plan, p.to_str().unwrap()).unwrap();
        assert!(load_execution_plan(p.to_str().unwrap()).is_ok());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn drift_phase_number_change() {
        let saved = make_exec_plan(
            "uid-1",
            vec![(
                "",
                "Sub",
                Some("ns"),
                "s1",
                Some("uid-a"),
                ExecutionAction::Delete,
            )],
        );
        let mut fresh = make_exec_plan(
            "uid-1",
            vec![(
                "",
                "Sub",
                Some("ns"),
                "s1",
                Some("uid-a"),
                ExecutionAction::Delete,
            )],
        );
        fresh.phases[0].phase = 99;
        let result = validate_execution_plan_against_fresh(&saved, &fresh);
        assert!(
            result.is_ok(),
            "Phase number change alone is not drift (renumbering after explicit phase insertion)"
        );
    }

    #[test]
    fn drift_duplicate_count() {
        let saved = make_exec_plan(
            "uid-1",
            vec![
                (
                    "",
                    "Sub",
                    Some("ns"),
                    "s1",
                    Some("uid-a"),
                    ExecutionAction::Delete,
                ),
                (
                    "",
                    "Sub",
                    Some("ns"),
                    "s1",
                    Some("uid-a"),
                    ExecutionAction::Delete,
                ),
            ],
        );
        let fresh = make_exec_plan(
            "uid-1",
            vec![(
                "",
                "Sub",
                Some("ns"),
                "s1",
                Some("uid-a"),
                ExecutionAction::Delete,
            )],
        );
        let result = validate_execution_plan_against_fresh(&saved, &fresh);
        assert!(result.is_err(), "Duplicate count change must be detected");
    }

    #[test]
    fn drift_table_driven_single_field_changes() {
        let base = (
            "",
            "Sub",
            Some("ns"),
            "s1",
            Some("uid-a"),
            ExecutionAction::Delete,
        );
        #[allow(clippy::type_complexity)]
        let cases: Vec<(
            &str,
            (
                &str,
                &str,
                Option<&str>,
                &str,
                Option<&str>,
                ExecutionAction,
            ),
        )> = vec![
            (
                "action",
                (
                    "",
                    "Sub",
                    Some("ns"),
                    "s1",
                    Some("uid-a"),
                    ExecutionAction::Keep,
                ),
            ),
            (
                "group",
                (
                    "apps",
                    "Sub",
                    Some("ns"),
                    "s1",
                    Some("uid-a"),
                    ExecutionAction::Delete,
                ),
            ),
            (
                "kind",
                (
                    "",
                    "Deploy",
                    Some("ns"),
                    "s1",
                    Some("uid-a"),
                    ExecutionAction::Delete,
                ),
            ),
            (
                "namespace",
                (
                    "",
                    "Sub",
                    Some("other"),
                    "s1",
                    Some("uid-a"),
                    ExecutionAction::Delete,
                ),
            ),
            (
                "name",
                (
                    "",
                    "Sub",
                    Some("ns"),
                    "s2",
                    Some("uid-a"),
                    ExecutionAction::Delete,
                ),
            ),
        ];
        for (field, changed) in cases {
            let saved = make_exec_plan("uid-1", vec![base.clone()]);
            let fresh = make_exec_plan("uid-1", vec![changed]);
            let result = validate_execution_plan_against_fresh(&saved, &fresh);
            assert!(result.is_err(), "{} change must be detected", field);
        }
    }

    #[test]
    fn concurrent_save_same_target() {
        let dir = std::env::temp_dir().join(format!("test-concurrent-{}", std::process::id()));
        let _ = std::fs::create_dir_all(&dir);
        let target = dir.join("shared-plan.json");
        let plan = make_exec_plan(
            "uid-1",
            vec![(
                "",
                "Sub",
                Some("ns"),
                "s1",
                Some("uid-a"),
                ExecutionAction::Delete,
            )],
        );
        let handles: Vec<_> = (0..4)
            .map(|_| {
                let p = plan.clone();
                let t = target.clone();
                std::thread::spawn(move || {
                    save_execution_plan(&p, t.to_str().unwrap()).unwrap();
                })
            })
            .collect();
        for h in handles {
            h.join().unwrap();
        }
        let loaded = load_execution_plan(target.to_str().unwrap()).unwrap();
        assert_eq!(loaded.phases.len(), 1, "Final JSON must be valid");
        let tmps: Vec<_> = std::fs::read_dir(&dir)
            .unwrap()
            .filter_map(|e| e.ok())
            .filter(|e| {
                e.file_name()
                    .to_str()
                    .is_some_and(|n| n.starts_with(".tmp_"))
            })
            .collect();
        assert_eq!(tmps.len(), 0, "No temp files should remain");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn save_rename_failure_preserves_existing_and_cleans_temp() {
        let dir = std::env::temp_dir().join(format!("test-rename-fail-{}", std::process::id()));
        let _ = std::fs::create_dir_all(&dir);
        let existing = dir.join("existing.json");
        std::fs::write(&existing, r#"{"original": true}"#).unwrap();
        let plan = make_exec_plan("uid-1", vec![]);
        // Try to save to a path where rename will fail: use a directory as target
        let dir_target = dir.join("subdir");
        std::fs::create_dir_all(&dir_target).unwrap();
        std::fs::write(dir_target.join("blocker"), "x").unwrap();
        let result = save_execution_plan(&plan, dir_target.to_str().unwrap());
        assert!(result.is_err(), "rename to directory should fail");
        // Existing file preserved
        assert_eq!(
            std::fs::read_to_string(&existing).unwrap(),
            r#"{"original": true}"#
        );
        // No temp residual in parent
        let tmps: Vec<_> = std::fs::read_dir(&dir)
            .unwrap()
            .filter_map(|e| e.ok())
            .filter(|e| {
                e.file_name()
                    .to_str()
                    .is_some_and(|n| n.starts_with(".tmp_"))
            })
            .collect();
        assert_eq!(tmps.len(), 0, "Temp cleaned up on rename failure");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn save_to_nonexistent_dir_fails_no_temp() {
        let plan = make_exec_plan("uid-1", vec![]);
        let result = save_execution_plan(&plan, "/nonexistent/dir/plan.json");
        assert!(result.is_err());
    }

    #[test]
    fn csv_name_matches_production_helper() {
        assert!(csv_name_matches(
            "rhbk-operator.v26.6.7-opr.1",
            "rhbk-operator.v26.6.7-opr.1"
        ));
        assert!(
            !csv_name_matches("rhbk", "rhbk-operator.v26.6.7-opr.1"),
            "substring must not match"
        );
        assert!(
            !csv_name_matches("rhbk-operator.v26.6.7-opr.1", "rhbk-operator.v27.0.0"),
            "version upgrade must not match"
        );
        assert!(
            !csv_name_matches("rhbk-operator.v26.6.7-opr.1", "rhbk"),
            "reverse substring must not match"
        );
        assert!(
            !csv_name_matches("", "rhbk-operator.v26.6.7-opr.1"),
            "empty must not match"
        );
    }

    // ── Explicit target authority tests ──

    fn make_explicit_target(kind: &str, name: &str, uid: &str) -> ExplicitDeleteTarget {
        ExplicitDeleteTarget {
            group: "".to_string(),
            kind: kind.to_string(),
            namespace: Some("ns".to_string()),
            name: name.to_string(),
            uid: uid.to_string(),
            reason: "config".to_string(),
            inbound_refs_at_plan: vec![],
            ref_scan_coverage: RefScanCoverage {
                kinds_scanned: vec!["apps/Deployment".to_string()],
                scan_complete: true,
            },
        }
    }

    fn make_explicit_phase(targets: &[&ExplicitDeleteTarget]) -> ExecutionPhase {
        ExecutionPhase {
            phase: 99,
            name: EXPLICIT_CLEANUP_PHASE_NAME.to_string(),
            resources: targets
                .iter()
                .map(|t| ExecutionResource {
                    group: t.group.clone(),
                    kind: t.kind.clone(),
                    namespace: t.namespace.clone(),
                    name: t.name.clone(),
                    uid: Some(t.uid.clone()),
                    action: ExecutionAction::Delete,
                })
                .collect(),
        }
    }

    #[test]
    fn authority_identical_passes() {
        let t = make_explicit_target("ConfigMap", "cm1", "uid-1");
        let phase = make_explicit_phase(&[&t]);
        let result = validate_explicit_targets_authority(&[t.clone()], &[t], &[phase]);
        assert!(result.is_ok());
    }

    #[test]
    fn authority_uid_mutation_rejected() {
        let saved = make_explicit_target("ConfigMap", "cm1", "uid-1");
        let mut fresh = saved.clone();
        fresh.uid = "uid-2".to_string();
        let phase = make_explicit_phase(&[&saved]);
        let result = validate_explicit_targets_authority(&[saved], &[fresh], &[phase]);
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .iter()
                .any(|e| e.contains("identity mismatch"))
        );
    }

    #[test]
    fn authority_group_kind_ns_name_mutation_rejected() {
        let saved = make_explicit_target("ConfigMap", "cm1", "uid-1");
        let mut fresh = saved.clone();
        fresh.kind = "Secret".to_string();
        let phase = make_explicit_phase(&[&saved]);
        let result = validate_explicit_targets_authority(&[saved], &[fresh], &[phase]);
        assert!(result.is_err());
    }

    #[test]
    fn authority_inbound_ref_mutation_rejected() {
        let mut saved = make_explicit_target("ConfigMap", "cm1", "uid-1");
        saved.inbound_refs_at_plan.push(InboundRefIdentity {
            group: "apps".to_string(),
            kind: "Deployment".to_string(),
            namespace: Some("ns".to_string()),
            name: "dep1".to_string(),
            uid: "dep-uid".to_string(),
            ref_field: "spec.volumes".to_string(),
            in_deletion_plan: true,
        });
        let mut fresh = saved.clone();
        fresh.inbound_refs_at_plan[0].uid = "different-uid".to_string();
        let phase = make_explicit_phase(&[&saved]);
        let result = validate_explicit_targets_authority(&[saved], &[fresh], &[phase]);
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .iter()
                .any(|e| e.contains("inbound_refs"))
        );
    }

    #[test]
    fn authority_inbound_ref_field_mutation_rejected() {
        let mut saved = make_explicit_target("ConfigMap", "cm1", "uid-1");
        saved.inbound_refs_at_plan.push(InboundRefIdentity {
            group: "apps".to_string(),
            kind: "Deployment".to_string(),
            namespace: Some("ns".to_string()),
            name: "dep1".to_string(),
            uid: "dep-uid".to_string(),
            ref_field: "spec.volumes".to_string(),
            in_deletion_plan: true,
        });
        let mut fresh = saved.clone();
        fresh.inbound_refs_at_plan[0].in_deletion_plan = false;
        let phase = make_explicit_phase(&[&saved]);
        let result = validate_explicit_targets_authority(&[saved], &[fresh], &[phase]);
        assert!(result.is_err());
    }

    #[test]
    fn authority_coverage_mutation_rejected() {
        let saved = make_explicit_target("ConfigMap", "cm1", "uid-1");
        let mut fresh = saved.clone();
        fresh.ref_scan_coverage.scan_complete = false;
        let phase = make_explicit_phase(&[&saved]);
        let result = validate_explicit_targets_authority(&[saved], &[fresh], &[phase]);
        assert!(result.is_err());
        assert!(result.unwrap_err().iter().any(|e| e.contains("coverage")));
    }

    #[test]
    fn authority_coverage_kinds_mutation_rejected() {
        let saved = make_explicit_target("ConfigMap", "cm1", "uid-1");
        let mut fresh = saved.clone();
        fresh
            .ref_scan_coverage
            .kinds_scanned
            .push("extra/Kind".to_string());
        let phase = make_explicit_phase(&[&saved]);
        let result = validate_explicit_targets_authority(&[saved], &[fresh], &[phase]);
        assert!(result.is_err());
    }

    #[test]
    fn authority_duplicate_saved_rejected() {
        let t = make_explicit_target("ConfigMap", "cm1", "uid-1");
        let phase = make_explicit_phase(&[&t, &t]);
        let result =
            validate_explicit_targets_authority(&[t.clone(), t.clone()], &[t.clone(), t], &[phase]);
        assert!(result.is_err());
        assert!(result.unwrap_err().iter().any(|e| e.contains("Duplicate")));
    }

    #[test]
    fn authority_metadata_add_rejected() {
        let t1 = make_explicit_target("ConfigMap", "cm1", "uid-1");
        let t2 = make_explicit_target("ConfigMap", "cm2", "uid-2");
        let phase = make_explicit_phase(&[&t1]);
        let result =
            validate_explicit_targets_authority(&[t1.clone(), t2], &[t1.clone()], &[phase]);
        assert!(result.is_err());
    }

    #[test]
    fn authority_metadata_remove_rejected() {
        let t1 = make_explicit_target("ConfigMap", "cm1", "uid-1");
        let t2 = make_explicit_target("ConfigMap", "cm2", "uid-2");
        let phase = make_explicit_phase(&[&t1, &t2]);
        let result =
            validate_explicit_targets_authority(&[t1.clone()], &[t1.clone(), t2], &[phase]);
        assert!(result.is_err());
    }

    #[test]
    fn authority_phase_mismatch_rejected() {
        let t1 = make_explicit_target("ConfigMap", "cm1", "uid-1");
        let t2 = make_explicit_target("ConfigMap", "cm2", "uid-2");
        // metadata has t1, phase has t1+t2
        let phase = make_explicit_phase(&[&t1, &t2]);
        let result = validate_explicit_targets_authority(&[t1.clone()], &[t1], &[phase]);
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .iter()
                .any(|e| e.contains("phase actions"))
        );
    }

    #[test]
    fn authority_both_metadata_and_phase_replaced_rejected() {
        let t1 = make_explicit_target("ConfigMap", "cm1", "uid-1");
        let mut t2 = t1.clone();
        t2.name = "cm2".to_string();
        t2.uid = "uid-2".to_string();
        let phase = make_explicit_phase(&[&t1]);
        // saved has t1, fresh has t2 (different identity)
        let result = validate_explicit_targets_authority(&[t1], &[t2], &[phase]);
        assert!(result.is_err());
    }

    #[test]
    fn authority_same_target_in_both_metadata_and_extra_phase() {
        let t1 = make_explicit_target("ConfigMap", "cm1", "uid-1");
        // Phase has duplicate
        let mut phase = make_explicit_phase(&[&t1]);
        phase.resources.push(phase.resources[0].clone());
        let result = validate_explicit_targets_authority(&[t1.clone()], &[t1], &[phase]);
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .iter()
                .any(|e| e.contains("phase actions"))
        );
    }

    #[test]
    fn authority_order_independent() {
        let t1 = make_explicit_target("ConfigMap", "cm1", "uid-1");
        let mut t2 = make_explicit_target("Service", "svc1", "uid-2");
        t2.group = "".to_string();
        let phase = make_explicit_phase(&[&t1, &t2]);
        // saved in reverse order
        let result =
            validate_explicit_targets_authority(&[t2.clone(), t1.clone()], &[t1, t2], &[phase]);
        assert!(result.is_ok(), "order should not matter");
    }
}
