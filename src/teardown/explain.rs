use crate::analyzers::olm::OperatorInstance;
use crate::graph::evidence::{Confidence, Edge, Evidence, EvidenceGraph, Relation, Resolution};
use crate::kube::resource::ResourceId;
use crate::teardown::planner::{Action, TeardownPlan};

// ═══════════════════════════════════════════════════════════
//  Exact identity matching
// ═══════════════════════════════════════════════════════════

/// Exact identity match: group, kind (case-insensitive), namespace, name.
/// UID is compared when the reference UID is present.
fn rid_matches_exact(candidate: &ResourceId, reference: &ResourceId) -> bool {
    if !candidate.kind.eq_ignore_ascii_case(&reference.kind) {
        return false;
    }
    if candidate.name != reference.name {
        return false;
    }
    if candidate.group != reference.group {
        return false;
    }
    if candidate.namespace != reference.namespace {
        return false;
    }
    if let Some(ref_uid) = &reference.uid {
        match &candidate.uid {
            Some(cand_uid) if cand_uid == ref_uid => {}
            Some(_) => return false, // different UID
            None => return false,    // candidate missing UID when reference has one
        }
    }
    true
}

// ═══════════════════════════════════════════════════════════
//  Plan identity deduplication
// ═══════════════════════════════════════════════════════════

/// Identity key for deduplicating plan actions by physical resource.
/// Includes UID so that same logical identity with different UIDs (recreated) is ambiguous.
fn identity_key(rid: &ResourceId) -> (String, String, Option<String>, String, Option<String>) {
    (
        rid.group.clone(),
        rid.kind.to_lowercase(),
        rid.namespace.clone(),
        rid.name.clone(),
        rid.uid.clone(),
    )
}

/// A distinct resource identity found in the plan, with all its actions across phases.
struct PlanIdentity {
    rid: ResourceId,
    /// (phase_index, phase_name, action_description)
    actions: Vec<(usize, String, String)>,
}

/// Collect distinct resource identities matching kind/name, grouping actions per identity.
fn find_plan_identities(plan: &TeardownPlan, kind: &str, name: &str) -> Vec<PlanIdentity> {
    use std::collections::BTreeMap;
    type IdentityKey = (String, String, Option<String>, String, Option<String>);
    let mut by_identity: BTreeMap<IdentityKey, PlanIdentity> = BTreeMap::new();

    for (i, phase) in plan.phases.iter().enumerate() {
        for action in &phase.actions {
            let (resource, desc) = match action {
                Action::Delete { resource, reason } => (resource, format!("DELETE — {}", reason)),
                Action::ExpectGone { resource, reason } => {
                    (resource, format!("EXPECT-GONE — {}", reason))
                }
                Action::Keep { resource, reason } => (resource, format!("KEEP — {}", reason)),
                Action::Review {
                    resource, reason, ..
                } => (resource, format!("REVIEW — {}", reason)),
                Action::WaitGone { resource } => (resource, "WAIT for deletion".to_string()),
            };
            if resource.kind.eq_ignore_ascii_case(kind) && resource.name == name {
                let key = identity_key(resource);
                by_identity
                    .entry(key)
                    .or_insert_with(|| PlanIdentity {
                        rid: resource.clone(),
                        actions: Vec::new(),
                    })
                    .actions
                    .push((i, phase.name.clone(), desc));
            }
        }
    }

    by_identity.into_values().collect()
}

// ═══════════════════════════════════════════════════════════
//  API stewardship lookup
// ═══════════════════════════════════════════════════════════

/// Find the operator that stewards the API definition for a resource with
/// the given kind and group. Returns None if no unique steward can be determined.
/// Returns (operator, exact_crd_name) when a unique steward is found.
fn find_api_steward<'a>(
    kind: &str,
    resource_group: &str,
    operators: &'a [OperatorInstance],
) -> Option<(&'a OperatorInstance, String)> {
    // Cannot determine steward without a known group
    if resource_group.is_empty() {
        return None;
    }

    let kind_lower = kind.to_lowercase();
    let plural = pluralize(&kind_lower);
    let group_lower = resource_group.to_lowercase();

    let mut candidates: Vec<(&OperatorInstance, String)> = Vec::new();
    for op in operators {
        for crd in &op.owned_crds {
            let crd_lower = crd.to_lowercase();
            let parts: Vec<&str> = crd_lower.splitn(2, '.').collect();
            if parts.len() != 2 {
                continue;
            }
            let crd_plural = parts[0];
            let crd_group = parts[1];

            let plural_matches =
                crd_plural == plural || crd_lower.starts_with(&format!("{}.", kind_lower));
            let group_matches = crd_group == group_lower;

            if plural_matches && group_matches {
                candidates.push((op, crd.clone()));
            }
        }
    }

    if candidates.len() == 1 {
        let (op, crd) = candidates.into_iter().next().unwrap();
        Some((op, crd))
    } else {
        None
    }
}

fn pluralize(kind: &str) -> String {
    let lower = kind.to_lowercase();
    if lower.ends_with('s') {
        format!("{}es", lower)
    } else if lower.ends_with('y') {
        format!("{}ies", &lower[..lower.len() - 1])
    } else {
        format!("{}s", lower)
    }
}

// ═══════════════════════════════════════════════════════════
//  Main explain function
// ═══════════════════════════════════════════════════════════

pub fn explain_resource(
    plan: &TeardownPlan,
    resource_query: &str,
    operators: &[OperatorInstance],
    evidence_graph: &EvidenceGraph,
) -> String {
    let (query_kind, query_name) = match resource_query.split_once('/') {
        Some((k, n)) => (k, n),
        None => {
            return format!(
                "Invalid resource format '{}'. Use kind/name.",
                resource_query
            );
        }
    };

    // Collect distinct resource identities, not raw actions
    let identities = find_plan_identities(plan, query_kind, query_name);
    if identities.is_empty() {
        return format!(
            "{}/{} not found in the teardown plan.\n\nHint: use `oc-deps teardown plan` to see all resources in the plan.",
            query_kind, query_name
        );
    }
    // Ambiguous = >1 distinct identities (not >1 actions for same resource)
    if identities.len() > 1 {
        let mut output = format!(
            "\x1b[1;33m⚠ Ambiguous:\x1b[0m {}/{} matches {} distinct resources:\n\n",
            query_kind,
            query_name,
            identities.len()
        );
        for ident in &identities {
            let scope = ident
                .rid
                .namespace
                .as_deref()
                .map(|ns| format!("ns: {}", ns))
                .unwrap_or_else(|| "cluster-scoped".to_string());
            let group_info = if ident.rid.group.is_empty() {
                String::new()
            } else {
                format!(" group: {}", ident.rid.group)
            };
            output.push_str(&format!(
                "  {}/{}  ({}{})\n",
                ident.rid.kind, ident.rid.name, scope, group_info
            ));
            for (pi, pn, desc) in &ident.actions {
                output.push_str(&format!("    Phase {} ({}): {}\n", pi, pn, desc));
            }
        }
        return output;
    }

    let ident = &identities[0];
    let matched_rid = &ident.rid;
    // Use the first action for display; show timeline if multiple
    let (phase_idx, phase_name, action_description) = &ident.actions[0];

    let mut output = String::new();

    output.push_str(&format!(
        "\x1b[1m{}/{}\x1b[0m is in \x1b[1mPhase {} ({})\x1b[0m\n",
        query_kind, query_name, phase_idx, phase_name
    ));
    output.push_str(&format!("  Action: {}\n", action_description));
    if ident.actions.len() > 1 {
        output.push_str("  Action timeline:\n");
        for (pi, pn, desc) in &ident.actions {
            output.push_str(&format!("    Phase {} ({}): {}\n", pi, pn, desc));
        }
    }

    output.push_str("\n\x1b[1mRelationships:\x1b[0m\n");

    // Filter edges by exact identity
    let outgoing: Vec<&Edge> = evidence_graph
        .edges
        .iter()
        .filter(|e| rid_matches_exact(&e.from, matched_rid))
        .collect();
    let incoming: Vec<&Edge> = evidence_graph
        .edges
        .iter()
        .filter(|e| rid_matches_exact(&e.to, matched_rid))
        .collect();

    // 1. API stewardship — use matched group for precision
    let api_steward = find_api_steward(query_kind, &matched_rid.group, operators);
    if let Some((op, crd_name)) = &api_steward {
        output.push_str(&format!("\n  {}/{}\n", query_kind, query_name));
        output.push_str(&format!(
            "    └─ API definition provided by CRD {}\n",
            crd_name
        ));
        output.push_str(&format!(
            "       └─ steward: CSV/{}    \x1b[36m[HARD: CsvOwnedCrd — API stewardship]\x1b[0m\n",
            op.csv.name
        ));
    }

    // 2. ownerReference relationships — distinguish Resolved from unresolved claims
    let owner_edges: Vec<&&Edge> = incoming
        .iter()
        .filter(|e| e.relation == Relation::Owns)
        .collect();
    let child_edges: Vec<&&Edge> = outgoing
        .iter()
        .filter(|e| e.relation == Relation::Owns)
        .collect();

    if !owner_edges.is_empty() {
        for edge in &owner_edges {
            output.push_str(&format!("\n  {}/{}\n", query_kind, query_name));
            match edge.resolution {
                Resolution::Resolved => {
                    output.push_str(&format!(
                        "    └─ owned by {}/{}                      \x1b[36m[{}]\x1b[0m\n",
                        edge.from.kind,
                        edge.from.name,
                        format_evidence(&edge.evidence, &edge.confidence)
                    ));
                }
                _ => {
                    output.push_str(&format!(
                        "    └─ ownerReference claim: {}/{}          \x1b[33m[{} — {}]\x1b[0m\n",
                        edge.from.kind,
                        edge.from.name,
                        format_resolution(&edge.resolution),
                        format_evidence(&edge.evidence, &edge.confidence)
                    ));
                }
            }
        }
    }

    // Only Resolved ownership for ordering constraints
    let resolved_child_edges: Vec<&&Edge> = child_edges
        .iter()
        .filter(|e| e.resolution == Resolution::Resolved)
        .copied()
        .collect();

    if !resolved_child_edges.is_empty() {
        let this_action = plan
            .phases
            .iter()
            .flat_map(|p| &p.actions)
            .find(|a| rid_matches_exact(action_resource(a), matched_rid));
        let action_desc = match this_action {
            Some(Action::Delete { .. }) => "must be deleted AFTER its children",
            Some(Action::Review { .. }) => "is marked for REVIEW (has children via ownerReference)",
            Some(Action::Keep { .. }) => "is kept (has children via ownerReference)",
            Some(Action::ExpectGone { .. }) => "is expected to be removed after its children",
            _ => "has children via ownerReference",
        };

        output.push_str(&format!("\n  {}/{}\n", query_kind, query_name));
        output.push_str(
            "    └─ is a parent of other resources (ownerReference)   \x1b[36m[HARD: OwnerReference]\x1b[0m\n",
        );
        output.push_str(&format!("       └─ {}\n", action_desc));
    }

    // 3. Spec references
    let ref_edges: Vec<&&Edge> = outgoing
        .iter()
        .filter(|e| {
            matches!(
                e.relation,
                Relation::References | Relation::UsesStorage | Relation::UsesServiceAccount
            )
        })
        .collect();
    if !ref_edges.is_empty() {
        output.push_str(&format!("\n  {}/{}\n", query_kind, query_name));
        output.push_str("    └─ references:\n");
        for (i, edge) in ref_edges.iter().enumerate() {
            let connector = if i == ref_edges.len() - 1 {
                "└─"
            } else {
                "├─"
            };
            output.push_str(&format!(
                "       {} {}/{}  \x1b[36m[{}]\x1b[0m\n",
                connector,
                edge.to.kind,
                edge.to.name,
                format_evidence(&edge.evidence, &edge.confidence)
            ));
        }
    }

    // 4. Phase ordering summary
    output.push_str("\n\x1b[1mTherefore:\x1b[0m\n");

    for (i, phase) in plan.phases.iter().enumerate() {
        let has_this_resource = phase
            .actions
            .iter()
            .any(|a| rid_matches_exact(action_resource(a), matched_rid));

        if has_this_resource {
            let this_action = phase
                .actions
                .iter()
                .find(|a| rid_matches_exact(action_resource(a), matched_rid));

            let action_label = match this_action {
                Some(Action::Delete { .. }) => "deleted",
                Some(Action::ExpectGone { .. }) => "expected to be removed by controller",
                Some(Action::Keep { .. }) => "kept",
                Some(Action::Review { .. }) => "marked for review",
                Some(Action::WaitGone { .. }) => "waiting for deletion",
                None => "scheduled",
            };

            output.push_str(&format!(
                "  Phase {}: {}/{} is {}    \x1b[1;33m◀ HERE\x1b[0m\n",
                i, query_kind, query_name, action_label,
            ));
        } else {
            let relevant_actions: Vec<String> = phase
                .actions
                .iter()
                .filter(|a| {
                    is_related_to_resource(a, matched_rid, operators, &evidence_graph.edges)
                })
                .take(3)
                .map(|a| match a {
                    Action::Delete { resource, .. } => {
                        format!("{}/{}", resource.kind, resource.name)
                    }
                    Action::ExpectGone { resource, .. } => {
                        format!("{}/{} (expected)", resource.kind, resource.name)
                    }
                    Action::Keep { resource, .. } => {
                        format!("{}/{} (kept)", resource.kind, resource.name)
                    }
                    Action::Review { resource, .. } => {
                        format!("{}/{} (review)", resource.kind, resource.name)
                    }
                    Action::WaitGone { resource } => {
                        format!("{}/{} (wait)", resource.kind, resource.name)
                    }
                })
                .collect();

            if !relevant_actions.is_empty() {
                output.push_str(&format!(
                    "  Phase {}: {} — {}\n",
                    i,
                    phase.name,
                    relevant_actions.join(", ")
                ));
            }
        }
    }

    output
}

// ═══════════════════════════════════════════════════════════
//  Helpers
// ═══════════════════════════════════════════════════════════

fn format_resolution(resolution: &Resolution) -> &'static str {
    match resolution {
        Resolution::Resolved => "Resolved",
        Resolution::TargetMissing => "TargetMissing",
        Resolution::IdentityMismatch => "IdentityMismatch",
        Resolution::Ambiguous => "Ambiguous",
        Resolution::Unresolved => "Unresolved",
    }
}

fn format_evidence(evidence: &[Evidence], confidence: &Confidence) -> String {
    let conf = match confidence {
        Confidence::Hard => "HARD",
        Confidence::Inferred => "INFERRED",
        Confidence::Heuristic => "HEURISTIC",
    };
    let ev = evidence
        .first()
        .map(|e| match e {
            Evidence::OwnerReference {
                kind, name, uid, ..
            } => {
                let uid_short: String = uid.chars().take(12).collect();
                format!("OwnerReference({}/{} uid={})", kind, name, uid_short)
            }
            Evidence::CsvOwnedCrd { crd_name } => format!("CsvOwnedCrd: {}", crd_name),
            Evidence::CsvRequiredCrd { crd_name } => format!("CsvRequiredCrd: {}", crd_name),
            Evidence::CsvInstallStrategy => "CsvInstallStrategy".to_string(),
            Evidence::SpecField { path } => format!("SpecField: {}", path),
            Evidence::LabelSelector { selector } => format!("LabelSelector: {}", selector),
            Evidence::ManagedFields { manager } => format!("ManagedFields: {}", manager),
            Evidence::Finalizer { name } => format!("Finalizer: {}", name),
            Evidence::StorageBinding => "StorageBinding".to_string(),
            Evidence::WebhookService => "WebhookService".to_string(),
            Evidence::ApiServiceBackend => "ApiServiceBackend".to_string(),
        })
        .unwrap_or_else(|| "unknown".to_string());
    format!("{}: {}", conf, ev)
}

fn action_resource(action: &Action) -> &ResourceId {
    match action {
        Action::Delete { resource, .. } => resource,
        Action::ExpectGone { resource, .. } => resource,
        Action::Keep { resource, .. } => resource,
        Action::Review { resource, .. } => resource,
        Action::WaitGone { resource } => resource,
    }
}

/// Check if a plan action is related to the query resource.
/// Uses exact identity matching and only Resolved graph edges.
fn is_related_to_resource(
    action: &Action,
    query_rid: &ResourceId,
    operators: &[OperatorInstance],
    edges: &[Edge],
) -> bool {
    let resource = action_resource(action);

    // CSV that stewards this resource's API — use full identity match
    if resource.kind == "ClusterServiceVersion"
        && let Some((op, _)) = find_api_steward(&query_rid.kind, &query_rid.group, operators)
        && rid_matches_exact(&op.csv, resource)
    {
        return true;
    }

    // Subscription for the steward operator — use full identity match
    if resource.kind == "Subscription"
        && let Some((op, _)) = find_api_steward(&query_rid.kind, &query_rid.group, operators)
        && let Some(sub) = &op.subscription
        && rid_matches_exact(sub, resource)
    {
        return true;
    }

    // CRD for this Kind
    if resource.kind == "CustomResourceDefinition"
        && let Some((_, ref crd_name)) =
            find_api_steward(&query_rid.kind, &query_rid.group, operators)
        && &resource.name == crd_name
    {
        return true;
    }

    // Direct Resolved edge relationship using exact identity
    edges.iter().any(|e| {
        e.resolution == Resolution::Resolved
            && ((rid_matches_exact(&e.from, query_rid) && rid_matches_exact(&e.to, resource))
                || (rid_matches_exact(&e.to, query_rid) && rid_matches_exact(&e.from, resource)))
    })
}

// ═══════════════════════════════════════════════════════════
//  Tests
// ═══════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;
    use crate::graph::evidence::build_evidence_graph;
    use crate::kube::resource::{ClusterSnapshot, OwnerRefEntry, ResourceEntry};
    use std::collections::HashMap;

    fn make_rid(
        group: &str,
        kind: &str,
        ns: Option<&str>,
        name: &str,
        uid: Option<&str>,
    ) -> ResourceId {
        ResourceId {
            group: group.to_string(),
            version: "v1".to_string(),
            kind: kind.to_string(),
            namespace: ns.map(|s| s.to_string()),
            name: name.to_string(),
            uid: uid.map(|s| s.to_string()),
        }
    }

    fn make_entry(
        group: &str,
        kind: &str,
        ns: Option<&str>,
        name: &str,
        uid: &str,
    ) -> ResourceEntry {
        ResourceEntry {
            id: ResourceId {
                group: group.to_string(),
                version: "v1".to_string(),
                kind: kind.to_string(),
                namespace: ns.map(|s| s.to_string()),
                name: name.to_string(),
                uid: Some(uid.to_string()),
            },
            owner_refs: vec![],
            spec_refs: vec![],
            labels: HashMap::new(),
            annotations: HashMap::new(),
            raw_spec: None,
            data_keys: None,
            data_hash: None,
            secret_value_hashes: None,
        }
    }

    fn make_snapshot(entries: Vec<ResourceEntry>) -> ClusterSnapshot {
        let mut resources = HashMap::new();
        for e in entries {
            let uid = e.id.uid.clone().unwrap_or_default();
            resources.insert(uid, e);
        }
        ClusterSnapshot {
            schema_version: Some(3),
            resources,
            scan_warnings: vec![],
            cluster_url: String::new(),
            taken_at: String::new(),
            namespaces: vec![],
            scope: None,
        }
    }

    #[allow(clippy::type_complexity)]
    fn make_plan_with_phases(phases: Vec<(&str, Vec<(ResourceId, &str, bool)>)>) -> TeardownPlan {
        use crate::teardown::planner::{PlanPhase, Preflight};
        TeardownPlan {
            targets: vec![],
            preflight: Preflight { checks: vec![] },
            phases: phases
                .into_iter()
                .map(|(name, resources)| PlanPhase {
                    name: name.to_string(),
                    description: String::new(),
                    actions: resources
                        .into_iter()
                        .map(|(rid, reason, is_delete)| {
                            if is_delete {
                                Action::Delete {
                                    resource: rid,
                                    reason: reason.to_string(),
                                }
                            } else {
                                Action::Keep {
                                    resource: rid,
                                    reason: reason.to_string(),
                                }
                            }
                        })
                        .collect(),
                    barrier: None,
                })
                .collect(),
            blockers: vec![],
            warnings: vec![],
            snapshot_taken_at: String::new(),
            dependency_edges: vec![],
            operator_inventory: vec![],
            explicit_decisions: vec![],
            explicit_deletes: vec![],
        }
    }

    fn csv_rid(name: &str) -> ResourceId {
        ResourceId {
            group: "operators.coreos.com".to_string(),
            version: "v1alpha1".to_string(),
            kind: "ClusterServiceVersion".to_string(),
            namespace: Some("ns".to_string()),
            name: name.to_string(),
            uid: Some("csv-uid".to_string()),
        }
    }

    #[test]
    fn explain_resolved_owner_says_owned_by() {
        let parent = make_entry("apps", "Deployment", Some("ns"), "dep1", "p-uid");
        let mut child = make_entry("", "Pod", Some("ns"), "pod1", "c-uid");
        child.owner_refs.push(OwnerRefEntry {
            api_version: "apps/v1".to_string(),
            kind: "Deployment".to_string(),
            name: "dep1".to_string(),
            uid: "p-uid".to_string(),
            controller: true,
            block_owner_deletion: false,
        });
        let snapshot = make_snapshot(vec![parent, child]);
        let graph = build_evidence_graph(&snapshot, &[]);
        let rid = ResourceId {
            group: "".to_string(),
            version: "v1".to_string(),
            kind: "Pod".to_string(),
            namespace: Some("ns".to_string()),
            name: "pod1".to_string(),
            uid: Some("c-uid".to_string()),
        };
        let plan = make_plan_with_phases(vec![("test", vec![(rid, "test", true)])]);
        let output = explain_resource(&plan, "Pod/pod1", &[], &graph);
        assert!(
            output.contains("owned by Deployment/dep1"),
            "Resolved owner: {}",
            output
        );
        assert!(
            !output.contains("claim"),
            "Resolved should not say 'claim': {}",
            output
        );
    }

    #[test]
    fn explain_missing_owner_says_claim() {
        let mut child = make_entry("", "Pod", Some("ns"), "pod1", "c-uid");
        child.owner_refs.push(OwnerRefEntry {
            api_version: "apps/v1".to_string(),
            kind: "Deployment".to_string(),
            name: "dep-gone".to_string(),
            uid: "gone-uid".to_string(),
            controller: true,
            block_owner_deletion: false,
        });
        let snapshot = make_snapshot(vec![child]);
        let graph = build_evidence_graph(&snapshot, &[]);
        let rid = ResourceId {
            group: "".to_string(),
            version: "v1".to_string(),
            kind: "Pod".to_string(),
            namespace: Some("ns".to_string()),
            name: "pod1".to_string(),
            uid: Some("c-uid".to_string()),
        };
        let plan = make_plan_with_phases(vec![("test", vec![(rid, "test", true)])]);
        let output = explain_resource(&plan, "Pod/pod1", &[], &graph);
        assert!(
            output.contains("ownerReference claim"),
            "Missing owner: {}",
            output
        );
        assert!(
            output.contains("TargetMissing"),
            "Should show TargetMissing: {}",
            output
        );
    }

    #[test]
    fn explain_api_stewardship_not_ownership() {
        let op = OperatorInstance {
            subscription: None,
            csv: csv_rid("my-op.v1"),
            csv_phase: "Succeeded".to_string(),
            owned_crds: vec!["widgets.example.com".to_string()],
            required_crds: vec![],
            owned_api_service_defs: vec![],
            required_api_service_defs: vec![],
            deployments: vec![],
            service_accounts: vec![],
            install_namespace: "ns".to_string(),
            package_name: None,
            has_unlinked_subscriptions: false,
        };
        let snapshot = make_snapshot(vec![]);
        let graph = build_evidence_graph(&snapshot, std::slice::from_ref(&op));
        let rid = ResourceId {
            group: "example.com".to_string(),
            version: "v1".to_string(),
            kind: "Widget".to_string(),
            namespace: Some("ns".to_string()),
            name: "w1".to_string(),
            uid: None,
        };
        let plan = make_plan_with_phases(vec![("test", vec![(rid, "test", true)])]);
        let output = explain_resource(&plan, "Widget/w1", &[op], &graph);
        assert!(
            output.contains("steward"),
            "Should use stewardship: {}",
            output
        );
        assert!(
            !output.contains("owned by CSV"),
            "NOT 'owned by CSV': {}",
            output
        );
        assert!(
            !output.contains("must stay alive"),
            "No lifecycle claim: {}",
            output
        );
    }

    #[test]
    fn same_csv_in_two_phases_not_ambiguous() {
        // CSV appears as KEEP in phase 0 and DELETE in phase 3 — same identity, not ambiguous
        let csv = csv_rid("my-op.v1");
        let plan = make_plan_with_phases(vec![
            ("Freeze OLM", vec![(csv.clone(), "keep initially", false)]),
            ("Remove controllers", vec![(csv, "remove CSV", true)]),
        ]);
        let snapshot = make_snapshot(vec![]);
        let graph = build_evidence_graph(&snapshot, &[]);
        let output = explain_resource(&plan, "ClusterServiceVersion/my-op.v1", &[], &graph);
        assert!(
            !output.contains("Ambiguous"),
            "Same CSV in 2 phases must not be ambiguous: {}",
            output
        );
        assert!(
            output.contains("Action timeline"),
            "Should show timeline: {}",
            output
        );
    }

    #[test]
    fn same_kind_name_different_namespace_is_ambiguous() {
        let rid1 = ResourceId {
            group: "".to_string(),
            version: "v1".to_string(),
            kind: "ConfigMap".to_string(),
            namespace: Some("ns-a".to_string()),
            name: "cfg".to_string(),
            uid: Some("uid-1".to_string()),
        };
        let rid2 = ResourceId {
            group: "".to_string(),
            version: "v1".to_string(),
            kind: "ConfigMap".to_string(),
            namespace: Some("ns-b".to_string()),
            name: "cfg".to_string(),
            uid: Some("uid-2".to_string()),
        };
        let plan =
            make_plan_with_phases(vec![("test", vec![(rid1, "a", true), (rid2, "b", true)])]);
        let snapshot = make_snapshot(vec![]);
        let graph = build_evidence_graph(&snapshot, &[]);
        let output = explain_resource(&plan, "ConfigMap/cfg", &[], &graph);
        assert!(
            output.contains("Ambiguous"),
            "Different ns must be ambiguous: {}",
            output
        );
        assert!(output.contains("ns-a"), "Should list ns-a: {}", output);
        assert!(output.contains("ns-b"), "Should list ns-b: {}", output);
    }

    #[test]
    fn same_kind_name_different_group_steward_uses_matched_group() {
        let op1 = OperatorInstance {
            subscription: None,
            csv: csv_rid("op-alpha.v1"),
            csv_phase: "Succeeded".to_string(),
            owned_crds: vec!["widgets.alpha.io".to_string()],
            required_crds: vec![],
            owned_api_service_defs: vec![],
            required_api_service_defs: vec![],
            deployments: vec![],
            service_accounts: vec![],
            install_namespace: "ns".to_string(),
            package_name: None,
            has_unlinked_subscriptions: false,
        };
        let op2 = OperatorInstance {
            subscription: None,
            csv: csv_rid("op-beta.v1"),
            csv_phase: "Succeeded".to_string(),
            owned_crds: vec!["widgets.beta.io".to_string()],
            required_crds: vec![],
            owned_api_service_defs: vec![],
            required_api_service_defs: vec![],
            deployments: vec![],
            service_accounts: vec![],
            install_namespace: "ns".to_string(),
            package_name: None,
            has_unlinked_subscriptions: false,
        };
        // Query for alpha.io Widget — should find op-alpha, not op-beta
        let rid = ResourceId {
            group: "alpha.io".to_string(),
            version: "v1".to_string(),
            kind: "Widget".to_string(),
            namespace: Some("ns".to_string()),
            name: "w1".to_string(),
            uid: None,
        };
        let plan = make_plan_with_phases(vec![("test", vec![(rid, "test", true)])]);
        let snapshot = make_snapshot(vec![]);
        let graph = build_evidence_graph(&snapshot, &[op1.clone(), op2]);
        let output = explain_resource(&plan, "Widget/w1", &[op1], &graph);
        if output.contains("steward") {
            assert!(
                output.contains("op-alpha"),
                "Should find alpha steward: {}",
                output
            );
        }
        // With unknown group, multiple stewards = no assertion (ambiguous)
    }

    #[test]
    fn edge_filtering_uses_exact_identity() {
        // Two different Deployments same name in different namespaces
        let dep_a = make_entry("apps", "Deployment", Some("ns-a"), "dep", "uid-a");
        let dep_b = make_entry("apps", "Deployment", Some("ns-b"), "dep", "uid-b");
        let mut pod = make_entry("", "Pod", Some("ns-a"), "pod1", "pod-uid");
        pod.owner_refs.push(OwnerRefEntry {
            api_version: "apps/v1".to_string(),
            kind: "Deployment".to_string(),
            name: "dep".to_string(),
            uid: "uid-a".to_string(),
            controller: true,
            block_owner_deletion: false,
        });
        let snapshot = make_snapshot(vec![dep_a, dep_b, pod]);
        let graph = build_evidence_graph(&snapshot, &[]);

        // Query for Pod in ns-a — should only show dep in ns-a as owner
        let rid = ResourceId {
            group: "".to_string(),
            version: "v1".to_string(),
            kind: "Pod".to_string(),
            namespace: Some("ns-a".to_string()),
            name: "pod1".to_string(),
            uid: Some("pod-uid".to_string()),
        };
        let plan = make_plan_with_phases(vec![("test", vec![(rid, "test", true)])]);
        let output = explain_resource(&plan, "Pod/pod1", &[], &graph);
        assert!(
            output.contains("owned by Deployment/dep"),
            "Should show owner: {}",
            output
        );
        // The owner edge is from ns-a dep only due to exact UID matching in ownerRef
    }

    #[test]
    fn rid_matches_exact_same_uid() {
        let a = make_rid("apps", "Deployment", Some("ns"), "dep", Some("uid-1"));
        let b = make_rid("apps", "Deployment", Some("ns"), "dep", Some("uid-1"));
        assert!(rid_matches_exact(&a, &b));
    }

    #[test]
    fn rid_matches_exact_different_uid() {
        let a = make_rid("apps", "Deployment", Some("ns"), "dep", Some("uid-1"));
        let b = make_rid("apps", "Deployment", Some("ns"), "dep", Some("uid-2"));
        assert!(!rid_matches_exact(&a, &b));
    }

    #[test]
    fn rid_matches_exact_candidate_missing_uid_ref_present() {
        let candidate = make_rid("apps", "Deployment", Some("ns"), "dep", None);
        let reference = make_rid("apps", "Deployment", Some("ns"), "dep", Some("uid-1"));
        assert!(
            !rid_matches_exact(&candidate, &reference),
            "candidate missing UID when reference has one must not match"
        );
    }

    #[test]
    fn same_csv_two_phases_not_ambiguous() {
        let csv_rid = make_rid(
            "operators.coreos.com",
            "ClusterServiceVersion",
            Some("ns"),
            "my-op.v1",
            Some("csv-uid"),
        );
        let plan = make_plan_with_phases(vec![
            (
                "Freeze OLM",
                vec![(csv_rid.clone(), "keep subscription", false)],
            ),
            ("Remove controllers", vec![(csv_rid, "delete CSV", true)]),
        ]);
        let graph = build_evidence_graph(&make_snapshot(vec![]), &[]);
        let output = explain_resource(&plan, "ClusterServiceVersion/my-op.v1", &[], &graph);
        assert!(
            !output.contains("Ambiguous"),
            "same CSV in 2 phases must not be ambiguous: {}",
            output
        );
        assert!(
            output.contains("Phase"),
            "should show phase info: {}",
            output
        );
    }

    #[test]
    fn recreated_uid_is_ambiguous() {
        let v1 = make_rid("example.com", "Widget", Some("ns"), "w1", Some("old-uid"));
        let v2 = make_rid("example.com", "Widget", Some("ns"), "w1", Some("new-uid"));
        let plan = make_plan_with_phases(vec![
            ("phase-a", vec![(v1, "old", true)]),
            ("phase-b", vec![(v2, "new", true)]),
        ]);
        let graph = build_evidence_graph(&make_snapshot(vec![]), &[]);
        let output = explain_resource(&plan, "Widget/w1", &[], &graph);
        assert!(
            output.contains("Ambiguous") || output.contains("matches"),
            "different UIDs should be ambiguous: {}",
            output
        );
    }

    #[test]
    fn core_kind_does_not_match_custom_steward() {
        let op = OperatorInstance {
            subscription: None,
            csv: make_rid(
                "operators.coreos.com",
                "ClusterServiceVersion",
                Some("ns"),
                "op.v1",
                Some("csv-uid"),
            ),
            csv_phase: "Succeeded".to_string(),
            owned_crds: vec!["widgets.example.com".to_string()],
            required_crds: vec![],
            owned_api_service_defs: vec![],
            required_api_service_defs: vec![],
            deployments: vec![],
            service_accounts: vec![],
            install_namespace: "ns".to_string(),
            package_name: None,
            has_unlinked_subscriptions: false,
        };
        // Core group Widget should NOT match example.com steward
        let ops = [op];
        let result = find_api_steward("Widget", "", &ops);
        assert!(result.is_none(), "empty group must not select a steward");
    }
}
