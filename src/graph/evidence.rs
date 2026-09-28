use std::collections::HashMap;

use serde::{Deserialize, Serialize};

use crate::analyzers::olm::OperatorInstance;
use crate::kube::resource::{ClusterSnapshot, ResourceId};

/// Evidence graph schema version. Bumped when Edge/Evidence serialization format changes.
pub const EVIDENCE_GRAPH_SCHEMA_VERSION: u32 = 3;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EvidenceGraph {
    pub schema_version: u32,
    pub edges: Vec<Edge>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Edge {
    pub from: ResourceId,
    pub to: ResourceId,
    pub relation: Relation,
    pub resolution: Resolution,
    pub evidence: Vec<Evidence>,
    pub confidence: Confidence,
}

/// How the edge target was resolved against live cluster state.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum Resolution {
    /// Target uniquely resolved against live cluster state.
    /// For ownerRef edges: exact UID + full identity (group/kind/namespace/name) verified.
    /// For spec-ref/OLM edges: unique target found by available reference identity within scope.
    Resolved,
    /// Owner UID not found in snapshot — parent may have been deleted or never observed.
    TargetMissing,
    /// Owner UID found but group/kind/name/namespace does not match the ownerRef claim.
    IdentityMismatch,
    /// Multiple candidates match the lookup key — cannot choose deterministically.
    Ambiguous,
    /// Target was constructed from reference metadata without live verification.
    Unresolved,
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum Relation {
    /// Kubernetes ownerReference — GC recognizes all ownerRefs (controller is an attribute).
    Owns,
    /// CSV declares CRD in its owned list — API stewardship only, NOT instance lifecycle
    /// ownership. A provider operator stewards the API definition; individual CR instances
    /// may be created/managed by entirely different controllers.
    ApiStewardship,
    /// CSV installStrategy declares a Deployment/ServiceAccount — creation evidence,
    /// not lifecycle ownership (the live ownerRef independently establishes Owns).
    Creates,
    /// Spec field reference (configMap, secret, service, etc.)
    References,
    /// Label/annotation selector relationship
    Selects,
    /// CSV requires CRD
    RequiresApi,
    /// Uses PVC/PV storage
    UsesStorage,
    /// References a webhook service
    ServesWebhook,
    /// Uses a ServiceAccount
    UsesServiceAccount,
    /// Managed-by correlation (label/annotation), not ownership
    ManagedBy,
    /// Finalizer or uninstall code explicitly deletes the object by deterministic name.
    /// Does NOT grant delete authority by itself — requires version-bound cleanup contract.
    CleansUp,
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum Evidence {
    /// Kubernetes ownerReference with full identity fields.
    OwnerReference {
        api_version: String,
        kind: String,
        name: String,
        uid: String,
        controller: bool,
        #[serde(default)]
        block_owner_deletion: bool,
    },
    CsvOwnedCrd {
        crd_name: String,
    },
    CsvRequiredCrd {
        crd_name: String,
    },
    CsvInstallStrategy,
    SpecField {
        path: String,
    },
    LabelSelector {
        selector: String,
    },
    ManagedFields {
        manager: String,
    },
    Finalizer {
        name: String,
    },
    StorageBinding,
    WebhookService,
    ApiServiceBackend,
    CleanupContract {
        adapter_id: String,
        source_revision: String,
        cleanup_function: String,
        matched_version: String,
    },
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum Confidence {
    Hard,
    Inferred,
    Heuristic,
}

// ═══════════════════════════════════════════════════════════
//  Index — namespace-scoped, group-aware, candidate sets
// ═══════════════════════════════════════════════════════════

type NsKindNameKey = (Option<String>, String, String); // (namespace, kind_lower, name)
type FullKey = (String, String, Option<String>, String); // (group, kind_lower, namespace, name)
type CandidateIndex = HashMap<NsKindNameKey, Vec<ResourceId>>;
type FullIndex = HashMap<FullKey, Vec<ResourceId>>;

fn build_ns_kind_name_index(snapshot: &ClusterSnapshot) -> CandidateIndex {
    let mut index: CandidateIndex = HashMap::new();
    for entry in snapshot.resources.values() {
        let key = (
            entry.id.namespace.clone(),
            entry.id.kind.to_lowercase(),
            entry.id.name.clone(),
        );
        index.entry(key).or_default().push(entry.id.clone());
    }
    index
}

fn build_full_index(snapshot: &ClusterSnapshot) -> FullIndex {
    let mut index: FullIndex = HashMap::new();
    for entry in snapshot.resources.values() {
        let key = (
            entry.id.group.clone(),
            entry.id.kind.to_lowercase(),
            entry.id.namespace.clone(),
            entry.id.name.clone(),
        );
        index.entry(key).or_default().push(entry.id.clone());
    }
    index
}

fn resolve_ns_kind_name(
    index: &CandidateIndex,
    ns: Option<&str>,
    kind: &str,
    name: &str,
) -> (Option<ResourceId>, Resolution) {
    let key = (
        ns.map(|s| s.to_string()),
        kind.to_lowercase(),
        name.to_string(),
    );
    match index.get(&key) {
        None => (None, Resolution::Unresolved),
        Some(candidates) if candidates.len() == 1 => {
            (Some(candidates[0].clone()), Resolution::Resolved)
        }
        Some(_) => (None, Resolution::Ambiguous),
    }
}

fn resolve_full(
    index: &FullIndex,
    group: &str,
    kind: &str,
    ns: Option<&str>,
    name: &str,
) -> (Option<ResourceId>, Resolution) {
    let key = (
        group.to_string(),
        kind.to_lowercase(),
        ns.map(|s| s.to_string()),
        name.to_string(),
    );
    match index.get(&key) {
        None => (None, Resolution::Unresolved),
        Some(candidates) if candidates.len() == 1 => {
            (Some(candidates[0].clone()), Resolution::Resolved)
        }
        Some(_) => (None, Resolution::Ambiguous),
    }
}

const WELL_KNOWN_SPEC_REF_KINDS: &[&str] = &[
    "Secret",
    "ConfigMap",
    "ServiceAccount",
    "PersistentVolumeClaim",
];

// ═══════════════════════════════════════════════════════════
//  Graph builder
// ═══════════════════════════════════════════════════════════

pub fn build_evidence_graph(
    snapshot: &ClusterSnapshot,
    operators: &[OperatorInstance],
) -> EvidenceGraph {
    let mut edges = Vec::new();

    let ns_index = build_ns_kind_name_index(snapshot);
    let full_index = build_full_index(snapshot);

    add_owner_ref_edges(snapshot, &mut edges);
    add_spec_ref_edges(snapshot, &ns_index, &full_index, &mut edges);
    add_olm_edges(operators, &full_index, &mut edges);
    add_service_account_edges(snapshot, &full_index, &mut edges);

    edges.sort_by(|a, b| {
        (
            &a.from.group,
            &a.from.version,
            &a.from.kind,
            &a.from.namespace,
            &a.from.name,
            &a.from.uid,
        )
            .cmp(&(
                &b.from.group,
                &b.from.version,
                &b.from.kind,
                &b.from.namespace,
                &b.from.name,
                &b.from.uid,
            ))
            .then_with(|| (&a.relation, &a.resolution).cmp(&(&b.relation, &b.resolution)))
            .then_with(|| {
                (
                    &a.to.group,
                    &a.to.version,
                    &a.to.kind,
                    &a.to.namespace,
                    &a.to.name,
                    &a.to.uid,
                )
                    .cmp(&(
                        &b.to.group,
                        &b.to.version,
                        &b.to.kind,
                        &b.to.namespace,
                        &b.to.name,
                        &b.to.uid,
                    ))
            })
            .then_with(|| (&a.evidence, &a.confidence).cmp(&(&b.evidence, &b.confidence)))
    });
    edges.dedup();

    EvidenceGraph {
        schema_version: EVIDENCE_GRAPH_SCHEMA_VERSION,
        edges,
    }
}

fn add_owner_ref_edges(snapshot: &ClusterSnapshot, edges: &mut Vec<Edge>) {
    for entry in snapshot.resources.values() {
        for oref in &entry.owner_refs {
            let (parent_id, resolution) =
                if let Some(parent_entry) = snapshot.resources.get(&oref.uid) {
                    // UID found — verify full identity
                    let (oref_group, oref_version) = match oref.api_version.rsplit_once('/') {
                        Some((g, v)) => (g, v),
                        None => ("", oref.api_version.as_str()),
                    };
                    let group_matches = parent_entry.id.group == oref_group;
                    let kind_matches = parent_entry.id.kind == oref.kind;
                    let name_matches = parent_entry.id.name == oref.name;
                    // Namespace: namespaced parent must be in child's namespace or cluster-scoped
                    let ns_ok = match (&parent_entry.id.namespace, &entry.id.namespace) {
                        (None, _) => true, // cluster-scoped parent can own anything
                        (Some(pns), Some(cns)) => pns == cns,
                        (Some(_), None) => false, // namespaced parent cannot own cluster-scoped
                    };

                    if group_matches && kind_matches && name_matches && ns_ok {
                        (parent_entry.id.clone(), Resolution::Resolved)
                    } else {
                        // UID exists but identity mismatch — do not bind to wrong live object
                        let claimed_id = ResourceId {
                            group: oref_group.to_string(),
                            version: oref_version.to_string(),
                            kind: oref.kind.clone(),
                            namespace: entry.id.namespace.clone(),
                            name: oref.name.clone(),
                            uid: Some(oref.uid.clone()),
                        };
                        (claimed_id, Resolution::IdentityMismatch)
                    }
                } else {
                    // UID not in snapshot — parent missing/deleted
                    let (group, version) = match oref.api_version.rsplit_once('/') {
                        Some((g, v)) => (g.to_string(), v.to_string()),
                        None => (String::new(), oref.api_version.clone()),
                    };
                    let claimed_id = ResourceId {
                        group,
                        version,
                        kind: oref.kind.clone(),
                        namespace: entry.id.namespace.clone(),
                        name: oref.name.clone(),
                        uid: Some(oref.uid.clone()),
                    };
                    (claimed_id, Resolution::TargetMissing)
                };

            edges.push(Edge {
                from: parent_id,
                to: entry.id.clone(),
                relation: Relation::Owns,
                resolution,
                evidence: vec![Evidence::OwnerReference {
                    api_version: oref.api_version.clone(),
                    kind: oref.kind.clone(),
                    name: oref.name.clone(),
                    uid: oref.uid.clone(),
                    controller: oref.controller,
                    block_owner_deletion: oref.block_owner_deletion,
                }],
                confidence: Confidence::Hard,
            });
        }
    }
}

fn add_spec_ref_edges(
    snapshot: &ClusterSnapshot,
    ns_index: &CandidateIndex,
    full_index: &FullIndex,
    edges: &mut Vec<Edge>,
) {
    for entry in snapshot.resources.values() {
        for sref in &entry.spec_refs {
            let is_well_known = WELL_KNOWN_SPEC_REF_KINDS
                .iter()
                .any(|k| k.eq_ignore_ascii_case(&sref.target_kind));

            // Well-known core kinds resolve via FullIndex with group="" for exact match.
            // Unknown-group heuristic refs use CandidateIndex (may be Ambiguous).
            let (target_id, resolution) = if is_well_known {
                resolve_full(
                    full_index,
                    "",
                    &sref.target_kind,
                    entry.id.namespace.as_deref(),
                    &sref.target_name,
                )
            } else {
                resolve_ns_kind_name(
                    ns_index,
                    entry.id.namespace.as_deref(),
                    &sref.target_kind,
                    &sref.target_name,
                )
            };

            let target_id = target_id.unwrap_or_else(|| ResourceId {
                group: String::new(),
                version: String::new(),
                kind: sref.target_kind.clone(),
                namespace: entry.id.namespace.clone(),
                name: sref.target_name.clone(),
                uid: None,
            });

            let (relation, confidence) = if sref.target_kind == "PersistentVolumeClaim" {
                (Relation::UsesStorage, Confidence::Hard)
            } else if sref.target_kind == "ServiceAccount" {
                (Relation::UsesServiceAccount, Confidence::Hard)
            } else if is_well_known {
                (Relation::References, Confidence::Hard)
            } else {
                (Relation::References, Confidence::Heuristic)
            };

            edges.push(Edge {
                from: entry.id.clone(),
                to: target_id,
                relation,
                resolution,
                evidence: vec![Evidence::SpecField {
                    path: sref.field_path.clone(),
                }],
                confidence,
            });
        }
    }
}

fn add_olm_edges(operators: &[OperatorInstance], full_index: &FullIndex, edges: &mut Vec<Edge>) {
    for op in operators {
        for crd_name in &op.owned_crds {
            let (crd_id, resolution) = resolve_full(
                full_index,
                "apiextensions.k8s.io",
                "CustomResourceDefinition",
                None,
                crd_name,
            );
            let crd_id = crd_id.unwrap_or_else(|| ResourceId {
                group: "apiextensions.k8s.io".to_string(),
                version: "v1".to_string(),
                kind: "CustomResourceDefinition".to_string(),
                namespace: None,
                name: crd_name.clone(),
                uid: None,
            });

            edges.push(Edge {
                from: op.csv.clone(),
                to: crd_id,
                relation: Relation::ApiStewardship,
                resolution,
                evidence: vec![Evidence::CsvOwnedCrd {
                    crd_name: crd_name.clone(),
                }],
                confidence: Confidence::Hard,
            });
        }

        for crd_name in &op.required_crds {
            let (crd_id, resolution) = resolve_full(
                full_index,
                "apiextensions.k8s.io",
                "CustomResourceDefinition",
                None,
                crd_name,
            );
            let crd_id = crd_id.unwrap_or_else(|| ResourceId {
                group: "apiextensions.k8s.io".to_string(),
                version: "v1".to_string(),
                kind: "CustomResourceDefinition".to_string(),
                namespace: None,
                name: crd_name.clone(),
                uid: None,
            });

            edges.push(Edge {
                from: op.csv.clone(),
                to: crd_id,
                relation: Relation::RequiresApi,
                resolution,
                evidence: vec![Evidence::CsvRequiredCrd {
                    crd_name: crd_name.clone(),
                }],
                confidence: Confidence::Hard,
            });
        }

        // CSV installStrategy Deployment — Creates evidence, not lifecycle Owns.
        // The live ownerRef independently produces Owns.
        // Keep edge even when target is unresolved/ambiguous.
        for deploy_name in &op.deployments {
            let (deploy_id, resolution) = resolve_full(
                full_index,
                "apps",
                "Deployment",
                op.csv.namespace.as_deref(),
                deploy_name,
            );
            let deploy_id = deploy_id.unwrap_or_else(|| ResourceId {
                group: "apps".to_string(),
                version: "v1".to_string(),
                kind: "Deployment".to_string(),
                namespace: op.csv.namespace.clone(),
                name: deploy_name.clone(),
                uid: None,
            });
            edges.push(Edge {
                from: op.csv.clone(),
                to: deploy_id,
                relation: Relation::Creates,
                resolution,
                evidence: vec![Evidence::CsvInstallStrategy],
                confidence: Confidence::Hard,
            });
        }

        for sa_name in &op.service_accounts {
            let (sa_id, resolution) = resolve_full(
                full_index,
                "",
                "ServiceAccount",
                op.csv.namespace.as_deref(),
                sa_name,
            );
            let sa_id = sa_id.unwrap_or_else(|| ResourceId {
                group: String::new(),
                version: "v1".to_string(),
                kind: "ServiceAccount".to_string(),
                namespace: op.csv.namespace.clone(),
                name: sa_name.clone(),
                uid: None,
            });
            edges.push(Edge {
                from: op.csv.clone(),
                to: sa_id,
                relation: Relation::References,
                resolution,
                evidence: vec![Evidence::CsvInstallStrategy],
                confidence: Confidence::Hard,
            });
        }
    }
}

fn add_service_account_edges(
    snapshot: &ClusterSnapshot,
    full_index: &FullIndex,
    edges: &mut Vec<Edge>,
) {
    for entry in snapshot.resources.values() {
        if entry.id.kind != "Pod" && entry.id.kind != "Deployment" && entry.id.kind != "ReplicaSet"
        {
            continue;
        }

        let sa_name = extract_service_account_name(&entry.id.kind, entry.raw_spec.as_ref());
        if let Some(sa_name) = sa_name {
            let already_has = edges.iter().any(|e| {
                e.from == entry.id
                    && e.relation == Relation::UsesServiceAccount
                    && e.to.name == sa_name
            });
            if already_has {
                continue;
            }

            let (target_id, resolution) = resolve_full(
                full_index,
                "",
                "ServiceAccount",
                entry.id.namespace.as_deref(),
                &sa_name,
            );
            let target_id = target_id.unwrap_or_else(|| ResourceId {
                group: String::new(),
                version: "v1".to_string(),
                kind: "ServiceAccount".to_string(),
                namespace: entry.id.namespace.clone(),
                name: sa_name,
                uid: None,
            });

            edges.push(Edge {
                from: entry.id.clone(),
                to: target_id,
                relation: Relation::UsesServiceAccount,
                resolution,
                evidence: vec![Evidence::SpecField {
                    path: "spec.serviceAccountName".to_string(),
                }],
                confidence: Confidence::Hard,
            });
        }
    }
}

fn extract_service_account_name(kind: &str, spec: Option<&serde_json::Value>) -> Option<String> {
    let spec = spec?;
    match kind {
        "Pod" => spec
            .get("serviceAccountName")
            .and_then(|v| v.as_str())
            .filter(|s| !s.is_empty())
            .map(String::from),
        "Deployment" | "ReplicaSet" => spec
            .get("template")
            .and_then(|t| t.get("spec"))
            .and_then(|s| s.get("serviceAccountName"))
            .and_then(|v| v.as_str())
            .filter(|s| !s.is_empty())
            .map(String::from),
        _ => None,
    }
}

// ═══════════════════════════════════════════════════════════
//  Tests
// ═══════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;
    use crate::kube::resource::{OwnerRefEntry, ResourceEntry, SpecRefEntry};

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
            deletion_timestamp: None,
            finalizers: None,
            observed_apis: None,
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
            observations: vec![],
        }
    }

    #[test]
    fn owner_ref_resolved_with_full_evidence() {
        let parent = make_entry("apps", "Deployment", Some("ns"), "dep1", "parent-uid");
        let mut child = make_entry("", "Pod", Some("ns"), "pod1", "child-uid");
        child.owner_refs.push(OwnerRefEntry {
            api_version: "apps/v1".to_string(),
            kind: "Deployment".to_string(),
            name: "dep1".to_string(),
            uid: "parent-uid".to_string(),
            controller: true,
            block_owner_deletion: true,
        });
        let snapshot = make_snapshot(vec![parent, child]);
        let graph = build_evidence_graph(&snapshot, &[]);

        let owns: Vec<_> = graph
            .edges
            .iter()
            .filter(|e| e.relation == Relation::Owns)
            .collect();
        assert_eq!(owns.len(), 1);
        assert_eq!(owns[0].resolution, Resolution::Resolved);
        assert_eq!(owns[0].from.name, "dep1");
        assert_eq!(owns[0].to.name, "pod1");
        match &owns[0].evidence[0] {
            Evidence::OwnerReference {
                api_version,
                kind,
                name,
                uid,
                controller,
                block_owner_deletion,
            } => {
                assert_eq!(api_version, "apps/v1");
                assert_eq!(kind, "Deployment");
                assert_eq!(name, "dep1");
                assert_eq!(uid, "parent-uid");
                assert!(*controller);
                assert!(*block_owner_deletion);
            }
            _ => panic!("expected OwnerReference evidence"),
        }
    }

    #[test]
    fn owner_ref_missing_parent() {
        let mut child = make_entry("", "Pod", Some("ns"), "pod1", "child-uid");
        child.owner_refs.push(OwnerRefEntry {
            api_version: "apps/v1".to_string(),
            kind: "Deployment".to_string(),
            name: "dep-gone".to_string(),
            uid: "missing-uid".to_string(),
            controller: true,
            block_owner_deletion: false,
        });
        let snapshot = make_snapshot(vec![child]);
        let graph = build_evidence_graph(&snapshot, &[]);
        let owns: Vec<_> = graph
            .edges
            .iter()
            .filter(|e| e.relation == Relation::Owns)
            .collect();
        assert_eq!(owns.len(), 1);
        assert_eq!(owns[0].resolution, Resolution::TargetMissing);
    }

    #[test]
    fn owner_ref_identity_mismatch() {
        // UID exists but points to wrong kind/name
        let wrong = make_entry("apps", "StatefulSet", Some("ns"), "sts1", "reused-uid");
        let mut child = make_entry("", "Pod", Some("ns"), "pod1", "child-uid");
        child.owner_refs.push(OwnerRefEntry {
            api_version: "apps/v1".to_string(),
            kind: "Deployment".to_string(),
            name: "dep1".to_string(),
            uid: "reused-uid".to_string(),
            controller: true,
            block_owner_deletion: false,
        });
        let snapshot = make_snapshot(vec![wrong, child]);
        let graph = build_evidence_graph(&snapshot, &[]);
        let owns: Vec<_> = graph
            .edges
            .iter()
            .filter(|e| e.relation == Relation::Owns)
            .collect();
        assert_eq!(owns.len(), 1);
        assert_eq!(owns[0].resolution, Resolution::IdentityMismatch);
        assert_eq!(
            owns[0].from.kind, "Deployment",
            "uses claimed identity, not live mismatch"
        );
    }

    #[test]
    fn owner_ref_cross_namespace_mismatch() {
        let parent = make_entry("apps", "Deployment", Some("other-ns"), "dep1", "parent-uid");
        let mut child = make_entry("", "Pod", Some("ns"), "pod1", "child-uid");
        child.owner_refs.push(OwnerRefEntry {
            api_version: "apps/v1".to_string(),
            kind: "Deployment".to_string(),
            name: "dep1".to_string(),
            uid: "parent-uid".to_string(),
            controller: true,
            block_owner_deletion: false,
        });
        let snapshot = make_snapshot(vec![parent, child]);
        let graph = build_evidence_graph(&snapshot, &[]);
        let owns: Vec<_> = graph
            .edges
            .iter()
            .filter(|e| e.relation == Relation::Owns)
            .collect();
        assert_eq!(
            owns[0].resolution,
            Resolution::IdentityMismatch,
            "cross-namespace must not resolve"
        );
    }

    #[test]
    fn cluster_scoped_parent_owns_namespaced_child() {
        let parent = make_entry("example.com", "ClusterWidget", None, "w1", "parent-uid");
        let mut child = make_entry("", "ConfigMap", Some("ns"), "cm1", "child-uid");
        child.owner_refs.push(OwnerRefEntry {
            api_version: "example.com/v1".to_string(),
            kind: "ClusterWidget".to_string(),
            name: "w1".to_string(),
            uid: "parent-uid".to_string(),
            controller: true,
            block_owner_deletion: false,
        });
        let snapshot = make_snapshot(vec![parent, child]);
        let graph = build_evidence_graph(&snapshot, &[]);
        let owns: Vec<_> = graph
            .edges
            .iter()
            .filter(|e| e.relation == Relation::Owns)
            .collect();
        assert_eq!(
            owns[0].resolution,
            Resolution::Resolved,
            "cluster-scoped parent can own namespaced child"
        );
    }

    #[test]
    fn non_controller_owner_also_produces_owns() {
        let parent = make_entry("apps", "Deployment", Some("ns"), "dep1", "parent-uid");
        let mut child = make_entry("", "Pod", Some("ns"), "pod1", "child-uid");
        child.owner_refs.push(OwnerRefEntry {
            api_version: "apps/v1".to_string(),
            kind: "Deployment".to_string(),
            name: "dep1".to_string(),
            uid: "parent-uid".to_string(),
            controller: false,
            block_owner_deletion: false,
        });
        let snapshot = make_snapshot(vec![parent, child]);
        let graph = build_evidence_graph(&snapshot, &[]);
        let owns: Vec<_> = graph
            .edges
            .iter()
            .filter(|e| e.relation == Relation::Owns)
            .collect();
        assert_eq!(owns.len(), 1, "non-controller ownerRef still produces Owns");
        assert_eq!(owns[0].resolution, Resolution::Resolved);
    }

    #[test]
    fn csv_owned_crd_is_api_stewardship_not_owns() {
        let op = OperatorInstance {
            subscription: None,
            csv: ResourceId {
                group: "operators.coreos.com".to_string(),
                version: "v1alpha1".to_string(),
                kind: "ClusterServiceVersion".to_string(),
                namespace: Some("ns".to_string()),
                name: "my-op.v1".to_string(),
                uid: Some("csv-uid".to_string()),
            },
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
        let graph = build_evidence_graph(&snapshot, &[op]);
        let steward: Vec<_> = graph
            .edges
            .iter()
            .filter(|e| e.relation == Relation::ApiStewardship)
            .collect();
        assert_eq!(steward.len(), 1);
        let owns: Vec<_> = graph
            .edges
            .iter()
            .filter(|e| e.relation == Relation::Owns)
            .collect();
        assert_eq!(owns.len(), 0, "CsvOwnedCrd must not produce Owns");
    }

    #[test]
    fn csv_install_strategy_deployment_is_creates() {
        let deploy = make_entry("apps", "Deployment", Some("ns"), "controller", "dep-uid");
        let op = OperatorInstance {
            subscription: None,
            csv: ResourceId {
                group: "operators.coreos.com".to_string(),
                version: "v1alpha1".to_string(),
                kind: "ClusterServiceVersion".to_string(),
                namespace: Some("ns".to_string()),
                name: "my-op.v1".to_string(),
                uid: Some("csv-uid".to_string()),
            },
            csv_phase: "Succeeded".to_string(),
            owned_crds: vec![],
            required_crds: vec![],
            owned_api_service_defs: vec![],
            required_api_service_defs: vec![],
            deployments: vec!["controller".to_string()],
            service_accounts: vec![],
            install_namespace: "ns".to_string(),
            package_name: None,
            has_unlinked_subscriptions: false,
        };
        let snapshot = make_snapshot(vec![deploy]);
        let graph = build_evidence_graph(&snapshot, &[op]);
        let creates: Vec<_> = graph
            .edges
            .iter()
            .filter(|e| e.relation == Relation::Creates)
            .collect();
        assert_eq!(creates.len(), 1);
        assert_eq!(creates[0].resolution, Resolution::Resolved);
        let owns: Vec<_> = graph
            .edges
            .iter()
            .filter(|e| {
                e.relation == Relation::Owns
                    && matches!(e.evidence[0], Evidence::CsvInstallStrategy)
            })
            .collect();
        assert_eq!(owns.len(), 0, "installStrategy must not produce Owns");
    }

    #[test]
    fn spec_ref_ambiguous_across_groups() {
        // Same kind/name in two different groups
        let cm1 = make_entry("", "Widget", Some("ns"), "w1", "uid-1");
        let cm2 = make_entry("example.com", "Widget", Some("ns"), "w1", "uid-2");
        let mut referrer = make_entry("apps", "Deployment", Some("ns"), "dep1", "dep-uid");
        referrer.spec_refs.push(SpecRefEntry {
            target_kind: "Widget".to_string(),
            target_name: "w1".to_string(),
            field_path: "spec.widgetRef".to_string(),
            target_group: None,
            target_namespace: None,
            source: None,
        });
        let snapshot = make_snapshot(vec![cm1, cm2, referrer]);
        let graph = build_evidence_graph(&snapshot, &[]);
        let refs: Vec<_> = graph
            .edges
            .iter()
            .filter(|e| e.relation == Relation::References)
            .collect();
        assert_eq!(refs.len(), 1);
        assert_eq!(
            refs[0].resolution,
            Resolution::Ambiguous,
            "multiple group candidates must be Ambiguous"
        );
    }

    #[test]
    fn graph_deterministic() {
        let parent = make_entry("apps", "Deployment", Some("ns"), "dep1", "parent-uid");
        let mut child = make_entry("", "Pod", Some("ns"), "pod1", "child-uid");
        child.owner_refs.push(OwnerRefEntry {
            api_version: "apps/v1".to_string(),
            kind: "Deployment".to_string(),
            name: "dep1".to_string(),
            uid: "parent-uid".to_string(),
            controller: true,
            block_owner_deletion: false,
        });
        child.spec_refs.push(SpecRefEntry {
            target_kind: "ConfigMap".to_string(),
            target_name: "cfg".to_string(),
            field_path: "spec.configMapRef".to_string(),
            target_group: None,
            target_namespace: None,
            source: None,
        });

        let snapshot = make_snapshot(vec![parent, child]);
        let g1 = serde_json::to_string(&build_evidence_graph(&snapshot, &[])).unwrap();
        let g2 = serde_json::to_string(&build_evidence_graph(&snapshot, &[])).unwrap();
        assert_eq!(g1, g2, "graph must be deterministic");
    }

    #[test]
    fn multiple_owners_all_produce_edges() {
        let p1 = make_entry("apps", "ReplicaSet", Some("ns"), "rs1", "rs-uid");
        let p2 = make_entry("apps", "Deployment", Some("ns"), "dep1", "dep-uid");
        let mut child = make_entry("", "Pod", Some("ns"), "pod1", "pod-uid");
        child.owner_refs.push(OwnerRefEntry {
            api_version: "apps/v1".to_string(),
            kind: "ReplicaSet".to_string(),
            name: "rs1".to_string(),
            uid: "rs-uid".to_string(),
            controller: true,
            block_owner_deletion: false,
        });
        child.owner_refs.push(OwnerRefEntry {
            api_version: "apps/v1".to_string(),
            kind: "Deployment".to_string(),
            name: "dep1".to_string(),
            uid: "dep-uid".to_string(),
            controller: false,
            block_owner_deletion: false,
        });
        let snapshot = make_snapshot(vec![p1, p2, child]);
        let graph = build_evidence_graph(&snapshot, &[]);
        let owns: Vec<_> = graph
            .edges
            .iter()
            .filter(|e| e.relation == Relation::Owns)
            .collect();
        assert_eq!(owns.len(), 2, "both ownerRefs produce edges");
    }

    #[test]
    fn cycle_does_not_hang() {
        let mut a = make_entry("apps", "Deployment", Some("ns"), "a", "uid-a");
        let mut b = make_entry("apps", "Deployment", Some("ns"), "b", "uid-b");
        a.owner_refs.push(OwnerRefEntry {
            api_version: "apps/v1".to_string(),
            kind: "Deployment".to_string(),
            name: "b".to_string(),
            uid: "uid-b".to_string(),
            controller: false,
            block_owner_deletion: false,
        });
        b.owner_refs.push(OwnerRefEntry {
            api_version: "apps/v1".to_string(),
            kind: "Deployment".to_string(),
            name: "a".to_string(),
            uid: "uid-a".to_string(),
            controller: false,
            block_owner_deletion: false,
        });
        let snapshot = make_snapshot(vec![a, b]);
        let graph = build_evidence_graph(&snapshot, &[]);
        let owns: Vec<_> = graph
            .edges
            .iter()
            .filter(|e| e.relation == Relation::Owns)
            .collect();
        assert_eq!(owns.len(), 2, "cycle produces edges without hanging");
    }

    #[test]
    fn diamond_dag_converges() {
        let root = make_entry("apps", "Deployment", Some("ns"), "root", "root-uid");
        let mut mid1 = make_entry("apps", "ReplicaSet", Some("ns"), "mid1", "mid1-uid");
        let mut mid2 = make_entry("apps", "ReplicaSet", Some("ns"), "mid2", "mid2-uid");
        let mut leaf = make_entry("", "Pod", Some("ns"), "leaf", "leaf-uid");
        mid1.owner_refs.push(OwnerRefEntry {
            api_version: "apps/v1".to_string(),
            kind: "Deployment".to_string(),
            name: "root".to_string(),
            uid: "root-uid".to_string(),
            controller: true,
            block_owner_deletion: false,
        });
        mid2.owner_refs.push(OwnerRefEntry {
            api_version: "apps/v1".to_string(),
            kind: "Deployment".to_string(),
            name: "root".to_string(),
            uid: "root-uid".to_string(),
            controller: true,
            block_owner_deletion: false,
        });
        leaf.owner_refs.push(OwnerRefEntry {
            api_version: "apps/v1".to_string(),
            kind: "ReplicaSet".to_string(),
            name: "mid1".to_string(),
            uid: "mid1-uid".to_string(),
            controller: true,
            block_owner_deletion: false,
        });
        leaf.owner_refs.push(OwnerRefEntry {
            api_version: "apps/v1".to_string(),
            kind: "ReplicaSet".to_string(),
            name: "mid2".to_string(),
            uid: "mid2-uid".to_string(),
            controller: false,
            block_owner_deletion: false,
        });
        let snapshot = make_snapshot(vec![root, mid1, mid2, leaf]);
        let graph = build_evidence_graph(&snapshot, &[]);
        let owns: Vec<_> = graph
            .edges
            .iter()
            .filter(|e| e.relation == Relation::Owns)
            .collect();
        assert_eq!(
            owns.len(),
            4,
            "diamond DAG: root→mid1, root→mid2, mid1→leaf, mid2→leaf"
        );
        assert!(owns.iter().all(|e| e.resolution == Resolution::Resolved));
    }

    #[test]
    fn core_secret_resolves_exactly_with_custom_same_kind() {
        // core Secret and custom example.com/Secret in same namespace
        let core_secret = make_entry("", "Secret", Some("ns"), "my-secret", "core-uid");
        let custom_secret = make_entry(
            "example.com",
            "Secret",
            Some("ns"),
            "my-secret",
            "custom-uid",
        );
        let mut referrer = make_entry("apps", "Deployment", Some("ns"), "dep1", "dep-uid");
        referrer.spec_refs.push(SpecRefEntry {
            target_kind: "Secret".to_string(),
            target_name: "my-secret".to_string(),
            field_path: "spec.secretRef".to_string(),
            target_group: None,
            target_namespace: None,
            source: None,
        });
        let snapshot = make_snapshot(vec![core_secret, custom_secret, referrer]);
        let graph = build_evidence_graph(&snapshot, &[]);
        let refs: Vec<_> = graph
            .edges
            .iter()
            .filter(|e| e.relation == Relation::References)
            .collect();
        assert_eq!(refs.len(), 1);
        assert_eq!(
            refs[0].resolution,
            Resolution::Resolved,
            "core Secret must resolve exactly via group=''"
        );
        assert_eq!(refs[0].to.group, "", "must resolve to core group");
    }

    #[test]
    fn install_strategy_missing_deployment_keeps_edge() {
        let op = OperatorInstance {
            subscription: None,
            csv: ResourceId {
                group: "operators.coreos.com".to_string(),
                version: "v1alpha1".to_string(),
                kind: "ClusterServiceVersion".to_string(),
                namespace: Some("ns".to_string()),
                name: "my-op.v1".to_string(),
                uid: Some("csv-uid".to_string()),
            },
            csv_phase: "Succeeded".to_string(),
            owned_crds: vec![],
            required_crds: vec![],
            owned_api_service_defs: vec![],
            required_api_service_defs: vec![],
            deployments: vec!["missing-controller".to_string()],
            service_accounts: vec!["missing-sa".to_string()],
            install_namespace: "ns".to_string(),
            package_name: None,
            has_unlinked_subscriptions: false,
        };
        let snapshot = make_snapshot(vec![]);
        let graph = build_evidence_graph(&snapshot, &[op]);
        let creates: Vec<_> = graph
            .edges
            .iter()
            .filter(|e| e.relation == Relation::Creates)
            .collect();
        assert_eq!(
            creates.len(),
            1,
            "missing deployment must keep Creates edge"
        );
        assert_eq!(creates[0].resolution, Resolution::Unresolved);
        assert_eq!(creates[0].to.name, "missing-controller");
        let refs: Vec<_> = graph
            .edges
            .iter()
            .filter(|e| {
                e.relation == Relation::References
                    && matches!(&e.evidence[0], Evidence::CsvInstallStrategy)
            })
            .collect();
        assert_eq!(refs.len(), 1, "missing SA must keep References edge");
        assert_eq!(refs[0].resolution, Resolution::Unresolved);
    }

    #[test]
    fn deterministic_with_different_insertion_order() {
        // Build two snapshots with same data but different HashMap insertion order
        let e1 = make_entry("apps", "Deployment", Some("ns"), "dep1", "uid-1");
        let e2 = make_entry("", "ConfigMap", Some("ns"), "cm1", "uid-2");
        let e3 = make_entry("apps", "ReplicaSet", Some("ns"), "rs1", "uid-3");

        let s1 = make_snapshot(vec![e1.clone(), e2.clone(), e3.clone()]);
        let s2 = make_snapshot(vec![e3, e1, e2]);

        let j1 = serde_json::to_string(&build_evidence_graph(&s1, &[])).unwrap();
        let j2 = serde_json::to_string(&build_evidence_graph(&s2, &[])).unwrap();
        assert_eq!(
            j1, j2,
            "different insertion order must produce identical JSON"
        );
    }

    #[test]
    fn schema_version_present() {
        let snapshot = make_snapshot(vec![]);
        let graph = build_evidence_graph(&snapshot, &[]);
        assert_eq!(graph.schema_version, EVIDENCE_GRAPH_SCHEMA_VERSION);
        let json: serde_json::Value =
            serde_json::from_str(&serde_json::to_string(&graph).unwrap()).unwrap();
        assert_eq!(json["schema_version"], 3);
    }

    #[test]
    fn evidence_owner_reference_serialization() {
        let ev = Evidence::OwnerReference {
            api_version: "apps/v1".to_string(),
            kind: "Deployment".to_string(),
            name: "dep1".to_string(),
            uid: "abc-123".to_string(),
            controller: true,
            block_owner_deletion: false,
        };
        let json = serde_json::to_value(&ev).unwrap();
        assert!(
            json.get("OwnerReference").is_some(),
            "serializes as tagged struct"
        );
        let inner = &json["OwnerReference"];
        assert_eq!(inner["api_version"], "apps/v1");
        assert_eq!(inner["kind"], "Deployment");
        assert_eq!(inner["uid"], "abc-123");
        assert_eq!(inner["controller"], true);
    }
}
