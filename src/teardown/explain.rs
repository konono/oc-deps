use crate::analyzers::olm::OperatorInstance;
use crate::graph::evidence::{Confidence, Edge, Evidence, EvidenceGraph, Relation};
use crate::kube::resource::ResourceId;
use crate::teardown::planner::{Action, TeardownPlan};

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

    let (phase_idx, phase_name, action_description) = match find_in_plan(
        plan, query_kind, query_name,
    ) {
        Some(result) => result,
        None => {
            return format!(
                "{}/{} not found in the teardown plan.\n\nHint: use `oc-deps teardown plan` to see all resources in the plan.",
                query_kind, query_name
            );
        }
    };

    let mut output = String::new();

    output.push_str(&format!(
        "\x1b[1m{}/{}\x1b[0m is in \x1b[1mPhase {} ({})\x1b[0m\n",
        query_kind, query_name, phase_idx, phase_name
    ));
    output.push_str(&format!("  Action: {}\n", action_description));

    output.push_str("\n\x1b[1mOrdering constraints:\x1b[0m\n");

    let resource_id_matches = |id: &ResourceId| -> bool {
        id.kind.eq_ignore_ascii_case(query_kind) && id.name == query_name
    };

    // Collect relevant edges
    let outgoing: Vec<&Edge> = evidence_graph
        .edges
        .iter()
        .filter(|e| resource_id_matches(&e.from))
        .collect();
    let incoming: Vec<&Edge> = evidence_graph
        .edges
        .iter()
        .filter(|e| resource_id_matches(&e.to))
        .collect();

    // 1. OLM attribution — which operator owns this resource's CRD?
    let owning_operator = find_owning_operator(query_kind, operators);
    if let Some(op) = owning_operator {
        let crd_name = op
            .owned_crds
            .iter()
            .find(|crd| {
                let kind_from_crd = crd.split('.').next().unwrap_or("");
                kind_from_crd.eq_ignore_ascii_case(&pluralize(query_kind))
                    || crd.to_lowercase().starts_with(&query_kind.to_lowercase())
            })
            .cloned()
            .unwrap_or_else(|| "unknown".to_string());

        output.push_str(&format!("\n  {}/{}\n", query_kind, query_name));
        output.push_str(&format!("    └─ is an instance of CRD {}\n", crd_name));
        output.push_str(&format!(
            "       └─ owned by CSV/{}                    \x1b[36m[HARD: CsvOwnedCrd]\x1b[0m\n",
            op.csv.name
        ));
    }

    // 2. ownerReference relationships
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
            output.push_str(&format!(
                "    └─ owned by {}/{}                      \x1b[36m[{}]\x1b[0m\n",
                edge.from.kind,
                edge.from.name,
                format_evidence(&edge.evidence, &edge.confidence)
            ));
        }
    }

    if !child_edges.is_empty() {
        output.push_str(&format!("\n  {}/{}\n", query_kind, query_name));
        output.push_str("    └─ is a parent of other resources (ownerReference)   \x1b[36m[HARD: OwnerReference]\x1b[0m\n");
        output.push_str("       └─ must be deleted AFTER its children (Phase 1)\n");
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

    // 4. Safety invariant — controller must outlive operands
    if let Some(op) = owning_operator {
        output.push_str(&format!("\n  CSV/{}\n", op.csv.name));
        output.push_str("    └─ is the controller for this resource's CRD\n");
        output.push_str("       └─ must stay alive until all operands are gone (Phase 3)  \x1b[31m[SAFETY]\x1b[0m\n");
    }

    // 5. Phase ordering summary
    output.push_str("\n\x1b[1mTherefore:\x1b[0m\n");

    for (i, phase) in plan.phases.iter().enumerate() {
        let has_this_resource = phase.actions.iter().any(|a| {
            let r = action_resource(a);
            r.kind.eq_ignore_ascii_case(query_kind) && r.name == query_name
        });

        if has_this_resource {
            let this_action = phase.actions.iter().find(|a| {
                let r = action_resource(a);
                r.kind.eq_ignore_ascii_case(query_kind) && r.name == query_name
            });

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
                    is_related_to_resource(
                        a,
                        query_kind,
                        query_name,
                        operators,
                        &evidence_graph.edges,
                    )
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

fn find_in_plan(plan: &TeardownPlan, kind: &str, name: &str) -> Option<(usize, String, String)> {
    for (i, phase) in plan.phases.iter().enumerate() {
        for action in &phase.actions {
            let (resource, desc) = match action {
                Action::Delete { resource, reason } => (resource, format!("DELETE — {}", reason)),
                Action::ExpectGone { resource, reason } => {
                    (resource, format!("EXPECT-GONE — {}", reason))
                }
                Action::Keep { resource, reason } => (resource, format!("KEEP — {}", reason)),
                Action::Review { resource, reason, .. } => (resource, format!("REVIEW — {}", reason)),
                Action::WaitGone { resource } => (resource, "WAIT for deletion".to_string()),
            };
            if resource.kind.eq_ignore_ascii_case(kind) && resource.name == name {
                return Some((i, phase.name.clone(), desc));
            }
        }
    }
    None
}

fn find_owning_operator<'a>(
    kind: &str,
    operators: &'a [OperatorInstance],
) -> Option<&'a OperatorInstance> {
    let kind_lower = kind.to_lowercase();
    operators.iter().find(|op| {
        op.owned_crds.iter().any(|crd| {
            let crd_lower = crd.to_lowercase();
            let plural = pluralize(&kind_lower);
            crd_lower.starts_with(&format!("{}.", plural))
                || crd_lower.starts_with(&format!("{}.", kind_lower))
        })
    })
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

fn format_evidence(evidence: &[Evidence], confidence: &Confidence) -> String {
    let conf = match confidence {
        Confidence::Hard => "HARD",
        Confidence::Inferred => "INFERRED",
        Confidence::Heuristic => "HEURISTIC",
    };
    let ev = evidence
        .first()
        .map(|e| match e {
            Evidence::OwnerReference => "OwnerReference".to_string(),
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

fn is_related_to_resource(
    action: &Action,
    query_kind: &str,
    query_name: &str,
    operators: &[OperatorInstance],
    edges: &[Edge],
) -> bool {
    let resource = action_resource(action);

    // CSV that owns this resource's CRD
    if resource.kind == "ClusterServiceVersion"
        && let Some(op) = find_owning_operator(query_kind, operators)
        && op.csv.name == resource.name
    {
        return true;
    }

    // Subscription for the owning operator
    if resource.kind == "Subscription"
        && let Some(op) = find_owning_operator(query_kind, operators)
        && let Some(sub) = &op.subscription
        && sub.name == resource.name
    {
        return true;
    }

    // CRD for this Kind
    if resource.kind == "CustomResourceDefinition"
        && let Some(op) = find_owning_operator(query_kind, operators)
        && op.owned_crds.iter().any(|c| c == &resource.name)
    {
        return true;
    }

    // Direct edge relationship
    edges.iter().any(|e| {
        (e.from.kind.eq_ignore_ascii_case(query_kind)
            && e.from.name == query_name
            && e.to.kind == resource.kind
            && e.to.name == resource.name)
            || (e.to.kind.eq_ignore_ascii_case(query_kind)
                && e.to.name == query_name
                && e.from.kind == resource.kind
                && e.from.name == resource.name)
    })
}
