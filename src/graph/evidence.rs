use std::collections::HashMap;

use serde::{Deserialize, Serialize};

use crate::analyzers::olm::OperatorInstance;
use crate::kube::resource::{ClusterSnapshot, ResourceId};

// ═══════════════════════════════════════════════════════════
//  Physical entity model — canonical identity + API aliases
// ═══════════════════════════════════════════════════════════

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PhysicalEntity {
    pub canonical_id: ResourceId,
    pub observed_aliases: Vec<ApiObservation>,
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct ApiObservation {
    pub group: String,
    pub version: String,
    pub kind: String,
    pub resource: String,
}

// ═══════════════════════════════════════════════════════════
//  Observation input — lossless multi-API-version capture
// ═══════════════════════════════════════════════════════════

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ResourceObservation {
    pub uid: String,
    pub id: ResourceId,
    pub resource: String,
    pub namespaced: bool,
    pub is_preferred: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DeclaredCleanup {
    pub actor: ResourceId,
    pub target: ResourceId,
    pub source: CleanupSource,
    pub reason: String,
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum CleanupSource {
    ExecutionPlanExplicitDelete,
    VersionProfile,
}

pub struct EvidenceGraphInput<'a> {
    pub snapshot: &'a ClusterSnapshot,
    pub operators: &'a [OperatorInstance],
    pub observations: &'a [ResourceObservation],
    pub declared_cleanups: &'a [DeclaredCleanup],
}

// ═══════════════════════════════════════════════════════════
//  Graph model
// ═══════════════════════════════════════════════════════════

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EvidenceGraph {
    pub edges: Vec<Edge>,
    #[serde(serialize_with = "serialize_sorted_entities")]
    pub entities: HashMap<String, PhysicalEntity>,
}

fn serialize_sorted_entities<S: serde::Serializer>(
    entities: &HashMap<String, PhysicalEntity>,
    s: S,
) -> Result<S::Ok, S::Error> {
    use serde::ser::SerializeMap;
    let mut sorted: Vec<_> = entities.iter().collect();
    sorted.sort_by_key(|(k, _)| (*k).clone());
    let mut map = s.serialize_map(Some(sorted.len()))?;
    for (k, v) in sorted {
        map.serialize_entry(k, v)?;
    }
    map.end()
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Edge {
    pub from: ResourceId,
    pub to: ResourceId,
    pub relation: Relation,
    pub evidence: Vec<Evidence>,
    pub confidence: Confidence,
    pub resolution: Resolution,
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum Resolution {
    Resolved,
    TargetMissing,
    IdentityMismatch,
    Ambiguous,
    Unresolved,
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum Relation {
    Owns,
    ApiStewardship,
    Creates,
    CleansUp,
    References,
    Selects,
    Watches,
    Mutates,
    Renders,
    RemoteCreates,
    RequiresApi,
    UsesStorage,
    ServesWebhook,
    UsesServiceAccount,
    ManagedBy,
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum Evidence {
    OwnerReference {
        api_version: String,
        kind: String,
        name: String,
        uid: String,
        controller: bool,
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
    DeclaredCleanup {
        source: CleanupSource,
        reason: String,
    },
}

#[allow(dead_code)]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum NegativeEvidence {
    NotOwned,
    SharedInfrastructure,
    WatchOnly,
    ExternalProvisioner,
    ForeignOwnerRef {
        owner_uid: String,
        owner_kind: String,
        owner_name: String,
    },
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum Confidence {
    Hard,
    Inferred,
    Heuristic,
}

/// Deletion authority requires Resolved + Owns + Hard.
#[allow(dead_code)]
pub fn can_authorize_delete(edge: &Edge) -> bool {
    edge.resolution == Resolution::Resolved
        && edge.relation == Relation::Owns
        && edge.confidence == Confidence::Hard
}

// ═══════════════════════════════════════════════════════════
//  Index types — candidate sets, no silent overwrite
// ═══════════════════════════════════════════════════════════

type FullKey = (String, String, Option<String>, String);
type NsKindKey = (Option<String>, String, String); // (ns, kind_lower, name)

fn build_full_index(snapshot: &ClusterSnapshot) -> HashMap<FullKey, Vec<ResourceId>> {
    let mut index: HashMap<FullKey, Vec<ResourceId>> = HashMap::new();
    for entry in snapshot.resources.values() {
        let key = (
            entry.id.group.clone(),
            entry.id.kind.clone(),
            entry.id.namespace.clone(),
            entry.id.name.clone(),
        );
        index.entry(key).or_default().push(entry.id.clone());
    }
    index
}

fn build_ns_kind_index(snapshot: &ClusterSnapshot) -> HashMap<NsKindKey, Vec<ResourceId>> {
    let mut index: HashMap<NsKindKey, Vec<ResourceId>> = HashMap::new();
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

fn resolve_full(
    index: &HashMap<FullKey, Vec<ResourceId>>,
    key: &FullKey,
) -> (Option<ResourceId>, Resolution) {
    let Some(candidates) = index.get(key) else {
        return (None, Resolution::Unresolved);
    };
    match candidates.len() {
        0 => (None, Resolution::Unresolved),
        1 => (Some(candidates[0].clone()), Resolution::Resolved),
        _ => (None, Resolution::Ambiguous),
    }
}

fn resolve_ns_kind_exact_group(
    index: &HashMap<NsKindKey, Vec<ResourceId>>,
    ns: Option<&str>,
    kind: &str,
    name: &str,
    group: &str,
) -> (Option<ResourceId>, Resolution) {
    let key = (
        ns.map(|s| s.to_string()),
        kind.to_lowercase(),
        name.to_string(),
    );
    let Some(candidates) = index.get(&key) else {
        return (None, Resolution::Unresolved);
    };
    if group.is_empty() {
        // Well-known core: filter to group=""
        let core: Vec<_> = candidates.iter().filter(|c| c.group.is_empty()).collect();
        match core.len() {
            1 => (Some(core[0].clone()), Resolution::Resolved),
            0 => (None, Resolution::Unresolved),
            _ => (None, Resolution::Ambiguous),
        }
    } else {
        let matched: Vec<_> = candidates.iter().filter(|c| c.group == group).collect();
        match matched.len() {
            1 => (Some(matched[0].clone()), Resolution::Resolved),
            0 => (None, Resolution::Unresolved),
            _ => (None, Resolution::Ambiguous),
        }
    }
}

fn resolve_ns_kind_any_group(
    index: &HashMap<NsKindKey, Vec<ResourceId>>,
    ns: Option<&str>,
    kind: &str,
    name: &str,
) -> (Option<ResourceId>, Resolution) {
    let key = (
        ns.map(|s| s.to_string()),
        kind.to_lowercase(),
        name.to_string(),
    );
    let Some(candidates) = index.get(&key) else {
        return (None, Resolution::Unresolved);
    };
    match candidates.len() {
        1 => (Some(candidates[0].clone()), Resolution::Resolved),
        0 => (None, Resolution::Unresolved),
        _ => (None, Resolution::Ambiguous),
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

/// Backward-compatible wrapper: creates one observation per snapshot entry.
pub fn build_evidence_graph(
    snapshot: &ClusterSnapshot,
    operators: &[OperatorInstance],
) -> EvidenceGraph {
    let observations: Vec<ResourceObservation> = snapshot
        .resources
        .values()
        .map(|entry| ResourceObservation {
            uid: entry.id.uid.clone().unwrap_or_default(),
            id: entry.id.clone(),
            resource: String::new(),
            namespaced: entry.id.namespace.is_some(),
            is_preferred: true,
        })
        .filter(|o| !o.uid.is_empty())
        .collect();
    let input = EvidenceGraphInput {
        snapshot,
        operators,
        observations: &observations,
        declared_cleanups: &[],
    };
    build_evidence_graph_full(input)
}

/// Full graph constructor accepting all input sources.
pub fn build_evidence_graph_full(input: EvidenceGraphInput<'_>) -> EvidenceGraph {
    let mut edges = Vec::new();

    let by_full = build_full_index(input.snapshot);
    let by_ns_kind = build_ns_kind_index(input.snapshot);

    add_owner_ref_edges(input.snapshot, &mut edges);
    add_spec_ref_edges(input.snapshot, &by_ns_kind, &mut edges);
    add_olm_edges(input.operators, &by_full, &mut edges);
    add_service_account_edges(input.snapshot, &by_ns_kind, &mut edges);
    add_cleanup_edges(input.declared_cleanups, input.snapshot, &mut edges);

    sort_and_dedup_edges(&mut edges);

    let entities = build_entities_from_observations(input.observations);

    EvidenceGraph { edges, entities }
}

fn sort_and_dedup_edges(edges: &mut Vec<Edge>) {
    edges.sort_by(|a, b| {
        let from_a = (
            &a.from.group,
            &a.from.kind,
            &a.from.namespace,
            &a.from.name,
            &a.from.uid,
        );
        let from_b = (
            &b.from.group,
            &b.from.kind,
            &b.from.namespace,
            &b.from.name,
            &b.from.uid,
        );
        from_a
            .cmp(&from_b)
            .then_with(|| {
                let to_a = (
                    &a.to.group,
                    &a.to.kind,
                    &a.to.namespace,
                    &a.to.name,
                    &a.to.uid,
                );
                let to_b = (
                    &b.to.group,
                    &b.to.kind,
                    &b.to.namespace,
                    &b.to.name,
                    &b.to.uid,
                );
                to_a.cmp(&to_b)
            })
            .then_with(|| a.relation.cmp(&b.relation))
            .then_with(|| a.evidence.cmp(&b.evidence))
            .then_with(|| a.confidence.cmp(&b.confidence))
            .then_with(|| a.resolution.cmp(&b.resolution))
    });
    edges.dedup();
}

fn add_cleanup_edges(
    cleanups: &[DeclaredCleanup],
    snapshot: &ClusterSnapshot,
    edges: &mut Vec<Edge>,
) {
    for cleanup in cleanups {
        let target_uid = cleanup.target.uid.as_deref().unwrap_or("");
        let resolution = if target_uid.is_empty() {
            Resolution::Unresolved
        } else if let Some(live) = snapshot.resources.get(target_uid) {
            if live.id.group == cleanup.target.group
                && live.id.kind == cleanup.target.kind
                && live.id.name == cleanup.target.name
                && live.id.namespace == cleanup.target.namespace
            {
                Resolution::Resolved
            } else {
                Resolution::IdentityMismatch
            }
        } else {
            Resolution::TargetMissing
        };

        edges.push(Edge {
            from: cleanup.actor.clone(),
            to: cleanup.target.clone(),
            relation: Relation::CleansUp,
            evidence: vec![Evidence::DeclaredCleanup {
                source: cleanup.source.clone(),
                reason: cleanup.reason.clone(),
            }],
            confidence: Confidence::Hard,
            resolution,
        });
    }
}

/// Build physical entities from observations with deterministic canonical selection.
/// Rules: 1) prefer is_preferred=true, 2) lexical sort of (group,version,resource,kind).
fn build_entities_from_observations(
    observations: &[ResourceObservation],
) -> HashMap<String, PhysicalEntity> {
    let mut entities: HashMap<String, (ResourceId, Vec<ApiObservation>, bool)> = HashMap::new();

    for obs in observations {
        if obs.uid.is_empty() {
            continue;
        }
        let api_obs = ApiObservation {
            group: obs.id.group.clone(),
            version: obs.id.version.clone(),
            kind: obs.id.kind.clone(),
            resource: obs.resource.clone(),
        };

        entities
            .entry(obs.uid.clone())
            .and_modify(|(canonical, aliases, is_pref)| {
                if !aliases.contains(&api_obs) {
                    aliases.push(api_obs.clone());
                }
                // Update canonical if this observation is preferred and current is not,
                // or if both have same preference use lexical ordering for determinism
                let should_replace = if obs.is_preferred && !*is_pref {
                    true
                } else if obs.is_preferred == *is_pref {
                    let new_key = (&obs.id.group, &obs.id.version, &obs.resource, &obs.id.kind);
                    let cur_key = (
                        &canonical.group,
                        &canonical.version,
                        &String::new(),
                        &canonical.kind,
                    );
                    new_key < cur_key
                } else {
                    false
                };
                if should_replace {
                    *canonical = obs.id.clone();
                    *is_pref = obs.is_preferred;
                }
            })
            .or_insert_with(|| (obs.id.clone(), vec![api_obs], obs.is_preferred));
    }

    entities
        .into_iter()
        .map(|(uid, (canonical, mut aliases, _))| {
            aliases.sort();
            aliases.dedup();
            (
                uid,
                PhysicalEntity {
                    canonical_id: canonical,
                    observed_aliases: aliases,
                },
            )
        })
        .collect()
}

fn add_owner_ref_edges(snapshot: &ClusterSnapshot, edges: &mut Vec<Edge>) {
    for entry in snapshot.resources.values() {
        for oref in &entry.owner_refs {
            let (group, version) = match oref.api_version.rsplit_once('/') {
                Some((g, v)) => (g.to_string(), v.to_string()),
                None => (String::new(), oref.api_version.clone()),
            };

            let (parent_id, resolution) =
                if let Some(parent_entry) = snapshot.resources.get(&oref.uid) {
                    // Verify full identity: group, kind, name
                    if parent_entry.id.kind == oref.kind
                        && parent_entry.id.name == oref.name
                        && parent_entry.id.group == group
                    {
                        // P0-2: Namespace verification
                        // Namespaced parent must be in child's namespace; cluster-scoped (None) is OK
                        let ns_ok = match (&parent_entry.id.namespace, &entry.id.namespace) {
                            (None, _) => true,                    // cluster-scoped parent can own any child
                            (Some(pns), Some(cns)) => pns == cns, // same namespace
                            (Some(_), None) => false, // namespaced parent cannot own cluster-scoped child
                        };
                        if ns_ok {
                            (parent_entry.id.clone(), Resolution::Resolved)
                        } else {
                            // Namespace mismatch — use unresolved claim
                            (
                                ResourceId {
                                    group: group.clone(),
                                    version: version.clone(),
                                    kind: oref.kind.clone(),
                                    namespace: entry.id.namespace.clone(),
                                    name: oref.name.clone(),
                                    uid: Some(oref.uid.clone()),
                                },
                                Resolution::IdentityMismatch,
                            )
                        }
                    } else {
                        // Same UID but different identity — stale/recreated
                        (
                            ResourceId {
                                group: group.clone(),
                                version: version.clone(),
                                kind: oref.kind.clone(),
                                namespace: entry.id.namespace.clone(),
                                name: oref.name.clone(),
                                uid: Some(oref.uid.clone()),
                            },
                            Resolution::IdentityMismatch,
                        )
                    }
                } else {
                    // Parent not in snapshot
                    (
                        ResourceId {
                            group: group.clone(),
                            version: version.clone(),
                            kind: oref.kind.clone(),
                            namespace: entry.id.namespace.clone(),
                            name: oref.name.clone(),
                            uid: Some(oref.uid.clone()),
                        },
                        Resolution::TargetMissing,
                    )
                };

            edges.push(Edge {
                from: parent_id,
                to: entry.id.clone(),
                relation: Relation::Owns,
                evidence: vec![Evidence::OwnerReference {
                    api_version: oref.api_version.clone(),
                    kind: oref.kind.clone(),
                    name: oref.name.clone(),
                    uid: oref.uid.clone(),
                    controller: oref.controller,
                    block_owner_deletion: oref.block_owner_deletion,
                }],
                confidence: Confidence::Hard,
                resolution,
            });
        }
    }
}

fn add_spec_ref_edges(
    snapshot: &ClusterSnapshot,
    by_ns_kind: &HashMap<NsKindKey, Vec<ResourceId>>,
    edges: &mut Vec<Edge>,
) {
    for entry in snapshot.resources.values() {
        for sref in &entry.spec_refs {
            let is_well_known = WELL_KNOWN_SPEC_REF_KINDS
                .iter()
                .any(|k| k.eq_ignore_ascii_case(&sref.target_kind));

            // Well-known core refs resolve against exact group=""
            // Unknown-group refs with multiple candidates remain Ambiguous
            let (resolved, resolution) = if is_well_known {
                resolve_ns_kind_exact_group(
                    by_ns_kind,
                    entry.id.namespace.as_deref(),
                    &sref.target_kind,
                    &sref.target_name,
                    "", // core group
                )
            } else {
                resolve_ns_kind_any_group(
                    by_ns_kind,
                    entry.id.namespace.as_deref(),
                    &sref.target_kind,
                    &sref.target_name,
                )
            };

            let target_id = resolved.unwrap_or_else(|| ResourceId {
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
                evidence: vec![Evidence::SpecField {
                    path: sref.field_path.clone(),
                }],
                confidence,
                resolution,
            });
        }
    }
}

fn add_olm_edges(
    operators: &[OperatorInstance],
    by_full: &HashMap<FullKey, Vec<ResourceId>>,
    edges: &mut Vec<Edge>,
) {
    for op in operators {
        for crd_name in &op.owned_crds {
            // P1-1: resolve CRD against snapshot when present
            let crd_key = (
                "apiextensions.k8s.io".to_string(),
                "CustomResourceDefinition".to_string(),
                None,
                crd_name.clone(),
            );
            let (resolved, resolution) = resolve_full(by_full, &crd_key);
            let crd_id = resolved.unwrap_or_else(|| ResourceId {
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
                evidence: vec![Evidence::CsvOwnedCrd {
                    crd_name: crd_name.clone(),
                }],
                confidence: Confidence::Hard,
                resolution,
            });
        }

        for crd_name in &op.required_crds {
            let crd_key = (
                "apiextensions.k8s.io".to_string(),
                "CustomResourceDefinition".to_string(),
                None,
                crd_name.clone(),
            );
            let (resolved, resolution) = resolve_full(by_full, &crd_key);
            let crd_id = resolved.unwrap_or_else(|| ResourceId {
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
                evidence: vec![Evidence::CsvRequiredCrd {
                    crd_name: crd_name.clone(),
                }],
                confidence: Confidence::Hard,
                resolution,
            });
        }

        // CSV installStrategy deployment → Creates
        for deploy_name in &op.deployments {
            let deploy_key = (
                "apps".to_string(),
                "Deployment".to_string(),
                Some(op.install_namespace.clone()),
                deploy_name.clone(),
            );
            let (resolved, resolution) = resolve_full(by_full, &deploy_key);
            let Some(deploy_id) = resolved else {
                continue; // deployment not found — skip
            };
            edges.push(Edge {
                from: op.csv.clone(),
                to: deploy_id,
                relation: Relation::Creates,
                evidence: vec![Evidence::CsvInstallStrategy],
                confidence: Confidence::Hard,
                resolution,
            });
        }

        // CSV installStrategy ServiceAccounts → References
        for sa_name in &op.service_accounts {
            let sa_key = (
                String::new(),
                "ServiceAccount".to_string(),
                Some(op.install_namespace.clone()),
                sa_name.clone(),
            );
            let (resolved, resolution) = resolve_full(by_full, &sa_key);
            let Some(sa_id) = resolved else {
                continue;
            };
            edges.push(Edge {
                from: op.csv.clone(),
                to: sa_id,
                relation: Relation::References,
                evidence: vec![Evidence::CsvInstallStrategy],
                confidence: Confidence::Hard,
                resolution,
            });
        }
    }
}

fn add_service_account_edges(
    snapshot: &ClusterSnapshot,
    by_ns_kind: &HashMap<NsKindKey, Vec<ResourceId>>,
    edges: &mut Vec<Edge>,
) {
    for entry in snapshot.resources.values() {
        if !matches!(entry.id.kind.as_str(), "Pod" | "Deployment" | "ReplicaSet") {
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

            let (resolved, resolution) = resolve_ns_kind_exact_group(
                by_ns_kind,
                entry.id.namespace.as_deref(),
                "ServiceAccount",
                &sa_name,
                "", // core group
            );
            let target_id = resolved.unwrap_or_else(|| ResourceId {
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
                evidence: vec![Evidence::SpecField {
                    path: "spec.serviceAccountName".to_string(),
                }],
                confidence: Confidence::Hard,
                resolution,
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
        owner_refs: Vec<OwnerRefEntry>,
    ) -> ResourceEntry {
        use crate::kube::resource::ResourceEntry;
        ResourceEntry {
            id: make_rid(group, kind, ns, name, Some(uid)),
            owner_refs,
            spec_refs: vec![],
            labels: HashMap::new(),
            annotations: HashMap::new(),
            raw_spec: None,
            data_keys: None,
            data_hash: None,
            secret_value_hashes: None,
        }
    }

    fn make_oref(
        api_version: &str,
        kind: &str,
        name: &str,
        uid: &str,
        controller: bool,
    ) -> OwnerRefEntry {
        use crate::kube::resource::OwnerRefEntry;
        OwnerRefEntry {
            api_version: api_version.to_string(),
            kind: kind.to_string(),
            name: name.to_string(),
            uid: uid.to_string(),
            controller,
            block_owner_deletion: false,
        }
    }

    fn empty_snapshot() -> ClusterSnapshot {
        ClusterSnapshot {
            schema_version: Some(3),
            resources: HashMap::new(),
            scan_warnings: vec![],
            cluster_url: String::new(),
            taken_at: String::new(),
            namespaces: vec![],
            scope: None,
        }
    }

    fn make_operator(
        csv_name: &str,
        install_ns: &str,
        owned_crds: Vec<&str>,
        deployments: Vec<&str>,
    ) -> OperatorInstance {
        OperatorInstance {
            subscription: None,
            csv: make_rid(
                "operators.coreos.com",
                "ClusterServiceVersion",
                Some(install_ns),
                csv_name,
                Some(&format!("uid-{csv_name}")),
            ),
            csv_phase: "Succeeded".to_string(),
            owned_crds: owned_crds.into_iter().map(|s| s.to_string()).collect(),
            required_crds: vec![],
            owned_api_service_defs: vec![],
            required_api_service_defs: vec![],
            deployments: deployments.into_iter().map(|s| s.to_string()).collect(),
            service_accounts: vec![],
            install_namespace: install_ns.to_string(),
            package_name: None,
            has_unlinked_subscriptions: false,
        }
    }

    use crate::kube::resource::{OwnerRefEntry, ResourceEntry};

    // ── P0-1: Resolution + can_authorize_delete ──

    #[test]
    fn resolved_owns_can_authorize_delete() {
        let mut snap = empty_snapshot();
        let parent = make_entry("apps", "Deployment", Some("ns"), "dep1", "uid-p", vec![]);
        let child = make_entry(
            "",
            "Pod",
            Some("ns"),
            "pod1",
            "uid-c",
            vec![make_oref("apps/v1", "Deployment", "dep1", "uid-p", true)],
        );
        snap.resources.insert("uid-p".into(), parent);
        snap.resources.insert("uid-c".into(), child);
        let graph = build_evidence_graph(&snap, &[]);
        let edge = graph
            .edges
            .iter()
            .find(|e| e.relation == Relation::Owns)
            .unwrap();
        assert_eq!(edge.resolution, Resolution::Resolved);
        assert!(can_authorize_delete(edge));
    }

    #[test]
    fn missing_parent_cannot_authorize_delete() {
        let mut snap = empty_snapshot();
        let child = make_entry(
            "",
            "Pod",
            Some("ns"),
            "pod1",
            "uid-c",
            vec![make_oref(
                "apps/v1",
                "Deployment",
                "dep-gone",
                "uid-stale",
                true,
            )],
        );
        snap.resources.insert("uid-c".into(), child);
        let graph = build_evidence_graph(&snap, &[]);
        let edge = graph
            .edges
            .iter()
            .find(|e| e.relation == Relation::Owns)
            .unwrap();
        assert_eq!(edge.resolution, Resolution::TargetMissing);
        assert!(
            !can_authorize_delete(edge),
            "TargetMissing must not authorize delete"
        );
    }

    #[test]
    fn identity_mismatch_cannot_authorize_delete() {
        let mut snap = empty_snapshot();
        let wrong = make_entry("batch", "Job", Some("ns"), "job-new", "uid-reused", vec![]);
        let child = make_entry(
            "",
            "Pod",
            Some("ns"),
            "pod1",
            "uid-c",
            vec![make_oref(
                "apps/v1",
                "Deployment",
                "dep-old",
                "uid-reused",
                true,
            )],
        );
        snap.resources.insert("uid-reused".into(), wrong);
        snap.resources.insert("uid-c".into(), child);
        let graph = build_evidence_graph(&snap, &[]);
        let edge = graph
            .edges
            .iter()
            .find(|e| e.relation == Relation::Owns)
            .unwrap();
        assert_eq!(edge.resolution, Resolution::IdentityMismatch);
        assert!(!can_authorize_delete(edge));
    }

    #[test]
    fn recreated_same_identity_new_uid_is_target_missing() {
        let mut snap = empty_snapshot();
        let new_dep = make_entry("apps", "Deployment", Some("ns"), "dep1", "uid-new", vec![]);
        let child = make_entry(
            "",
            "Pod",
            Some("ns"),
            "pod1",
            "uid-c",
            vec![make_oref("apps/v1", "Deployment", "dep1", "uid-old", true)],
        );
        snap.resources.insert("uid-new".into(), new_dep);
        snap.resources.insert("uid-c".into(), child);
        let graph = build_evidence_graph(&snap, &[]);
        let edge = graph
            .edges
            .iter()
            .find(|e| e.relation == Relation::Owns)
            .unwrap();
        assert_eq!(edge.resolution, Resolution::TargetMissing);
        assert!(!can_authorize_delete(edge));
    }

    // ── P0-2: Namespace verification ──

    #[test]
    fn cross_namespace_owner_does_not_resolve() {
        let mut snap = empty_snapshot();
        let parent = make_entry("apps", "Deployment", Some("ns-a"), "dep1", "uid-p", vec![]);
        let child = make_entry(
            "",
            "Pod",
            Some("ns-b"),
            "pod1",
            "uid-c",
            vec![make_oref("apps/v1", "Deployment", "dep1", "uid-p", true)],
        );
        snap.resources.insert("uid-p".into(), parent);
        snap.resources.insert("uid-c".into(), child);
        let graph = build_evidence_graph(&snap, &[]);
        let edge = graph
            .edges
            .iter()
            .find(|e| e.relation == Relation::Owns)
            .unwrap();
        assert_eq!(
            edge.resolution,
            Resolution::IdentityMismatch,
            "namespaced parent in different namespace must not bind"
        );
        assert!(!can_authorize_delete(edge));
    }

    #[test]
    fn cluster_scoped_owner_can_own_namespaced_child() {
        let mut snap = empty_snapshot();
        let parent = make_entry("", "ClusterRole", None, "cr1", "uid-p", vec![]);
        let child = make_entry(
            "",
            "Pod",
            Some("ns"),
            "pod1",
            "uid-c",
            vec![make_oref("v1", "ClusterRole", "cr1", "uid-p", true)],
        );
        snap.resources.insert("uid-p".into(), parent);
        snap.resources.insert("uid-c".into(), child);
        let graph = build_evidence_graph(&snap, &[]);
        let edge = graph
            .edges
            .iter()
            .find(|e| e.relation == Relation::Owns)
            .unwrap();
        assert_eq!(edge.resolution, Resolution::Resolved);
    }

    // ── P0-3: Spec-ref ambiguity ──

    #[test]
    fn spec_ref_resolves_within_source_namespace() {
        use crate::kube::resource::SpecRefEntry;
        let mut snap = empty_snapshot();
        let cm_a = make_entry("", "ConfigMap", Some("ns-a"), "shared", "uid-cm-a", vec![]);
        let cm_b = make_entry("", "ConfigMap", Some("ns-b"), "shared", "uid-cm-b", vec![]);
        let mut dep = make_entry(
            "apps",
            "Deployment",
            Some("ns-a"),
            "dep1",
            "uid-dep",
            vec![],
        );
        dep.spec_refs.push(SpecRefEntry {
            target_kind: "ConfigMap".to_string(),
            target_name: "shared".to_string(),
            field_path: "spec.volumes[0].configMap.name".to_string(),
        });
        snap.resources.insert("uid-cm-a".into(), cm_a);
        snap.resources.insert("uid-cm-b".into(), cm_b);
        snap.resources.insert("uid-dep".into(), dep);
        let graph = build_evidence_graph(&snap, &[]);
        let refs: Vec<_> = graph
            .edges
            .iter()
            .filter(|e| e.relation == Relation::References)
            .collect();
        assert_eq!(refs.len(), 1);
        assert_eq!(refs[0].to.uid.as_deref(), Some("uid-cm-a"));
        assert_eq!(refs[0].resolution, Resolution::Resolved);
    }

    #[test]
    fn spec_ref_same_kind_different_group_stays_ambiguous() {
        use crate::kube::resource::SpecRefEntry;
        let mut snap = empty_snapshot();
        // Two "Widget" in same ns but different groups
        let w1 = make_entry("alpha.io", "Widget", Some("ns"), "w1", "uid-w1", vec![]);
        let w2 = make_entry("beta.io", "Widget", Some("ns"), "w1", "uid-w2", vec![]);
        let mut dep = make_entry("apps", "Deployment", Some("ns"), "dep1", "uid-dep", vec![]);
        dep.spec_refs.push(SpecRefEntry {
            target_kind: "Widget".to_string(),
            target_name: "w1".to_string(),
            field_path: "spec.ref".to_string(),
        });
        snap.resources.insert("uid-w1".into(), w1);
        snap.resources.insert("uid-w2".into(), w2);
        snap.resources.insert("uid-dep".into(), dep);
        let graph = build_evidence_graph(&snap, &[]);
        let refs: Vec<_> = graph
            .edges
            .iter()
            .filter(|e| e.relation == Relation::References)
            .collect();
        assert_eq!(refs.len(), 1);
        assert_eq!(
            refs[0].resolution,
            Resolution::Ambiguous,
            "same kind/name in different groups must be Ambiguous"
        );
        assert!(!can_authorize_delete(refs[0]));
    }

    #[test]
    fn spec_ref_insertion_order_independent() {
        use crate::kube::resource::SpecRefEntry;
        let build = |order: &[(&str, &str)]| {
            let mut snap = empty_snapshot();
            for (group, uid) in order {
                let e = make_entry(group, "Widget", Some("ns"), "w1", uid, vec![]);
                snap.resources.insert(uid.to_string(), e);
            }
            let mut dep = make_entry("apps", "Deployment", Some("ns"), "dep1", "uid-dep", vec![]);
            dep.spec_refs.push(SpecRefEntry {
                target_kind: "Widget".to_string(),
                target_name: "w1".to_string(),
                field_path: "spec.ref".to_string(),
            });
            snap.resources.insert("uid-dep".into(), dep);
            let g = build_evidence_graph(&snap, &[]);
            serde_json::to_string(&g.edges).unwrap()
        };
        let j1 = build(&[("alpha.io", "uid-1"), ("beta.io", "uid-2")]);
        let j2 = build(&[("beta.io", "uid-2"), ("alpha.io", "uid-1")]);
        assert_eq!(j1, j2, "insertion order must not affect output");
    }

    // ── OLM ──

    #[test]
    fn olm_deployment_resolves_exact_group_namespace() {
        let mut snap = empty_snapshot();
        let dep_ok = make_entry(
            "apps",
            "Deployment",
            Some("op-ns"),
            "ctrl",
            "uid-ok",
            vec![],
        );
        let dep_wrong = make_entry(
            "apps",
            "Deployment",
            Some("other"),
            "ctrl",
            "uid-wrong",
            vec![],
        );
        snap.resources.insert("uid-ok".into(), dep_ok);
        snap.resources.insert("uid-wrong".into(), dep_wrong);
        let op = make_operator("op.v1", "op-ns", vec![], vec!["ctrl"]);
        let graph = build_evidence_graph(&snap, &[op]);
        let creates: Vec<_> = graph
            .edges
            .iter()
            .filter(|e| e.relation == Relation::Creates)
            .collect();
        assert_eq!(creates.len(), 1);
        assert_eq!(creates[0].to.uid.as_deref(), Some("uid-ok"));
        assert_eq!(creates[0].resolution, Resolution::Resolved);
    }

    #[test]
    fn olm_crd_resolves_against_snapshot() {
        let mut snap = empty_snapshot();
        let crd = make_entry(
            "apiextensions.k8s.io",
            "CustomResourceDefinition",
            None,
            "widgets.example.com",
            "uid-crd",
            vec![],
        );
        snap.resources.insert("uid-crd".into(), crd);
        let op = make_operator("op.v1", "ns", vec!["widgets.example.com"], vec![]);
        let graph = build_evidence_graph(&snap, &[op]);
        let steward: Vec<_> = graph
            .edges
            .iter()
            .filter(|e| e.relation == Relation::ApiStewardship)
            .collect();
        assert_eq!(steward.len(), 1);
        assert_eq!(steward[0].to.uid.as_deref(), Some("uid-crd"));
        assert_eq!(steward[0].resolution, Resolution::Resolved);
    }

    #[test]
    fn olm_crd_unresolved_when_absent() {
        let snap = empty_snapshot();
        let op = make_operator("op.v1", "ns", vec!["missing.example.com"], vec![]);
        let graph = build_evidence_graph(&snap, &[op]);
        let steward: Vec<_> = graph
            .edges
            .iter()
            .filter(|e| e.relation == Relation::ApiStewardship)
            .collect();
        assert_eq!(steward.len(), 1);
        assert_eq!(steward[0].to.uid, None);
        assert_eq!(steward[0].resolution, Resolution::Unresolved);
    }

    // ── Authority ──

    #[test]
    fn csv_install_strategy_creates_cannot_authorize() {
        let mut snap = empty_snapshot();
        let dep = make_entry("apps", "Deployment", Some("ns"), "ctrl", "uid-dep", vec![]);
        snap.resources.insert("uid-dep".into(), dep);
        let op = make_operator("op.v1", "ns", vec![], vec!["ctrl"]);
        let graph = build_evidence_graph(&snap, &[op]);
        let creates = graph
            .edges
            .iter()
            .find(|e| e.relation == Relation::Creates)
            .unwrap();
        assert!(!can_authorize_delete(creates));
    }

    #[test]
    fn api_stewardship_cannot_authorize() {
        assert!(!can_authorize_delete(&Edge {
            from: make_rid("", "CSV", Some("ns"), "op.v1", None),
            to: make_rid("apiextensions.k8s.io", "CRD", None, "x", None),
            relation: Relation::ApiStewardship,
            evidence: vec![Evidence::CsvOwnedCrd {
                crd_name: "x".into()
            }],
            confidence: Confidence::Hard,
            resolution: Resolution::Resolved,
        }));
    }

    #[test]
    fn heuristic_owns_cannot_authorize() {
        assert!(!can_authorize_delete(&Edge {
            from: make_rid("", "A", Some("ns"), "a", None),
            to: make_rid("", "B", Some("ns"), "b", None),
            relation: Relation::Owns,
            evidence: vec![],
            confidence: Confidence::Heuristic,
            resolution: Resolution::Resolved,
        }));
    }

    // ── Golden ──

    #[test]
    fn golden_foreign_owner_not_claimed_by_steward() {
        let mut snap = empty_snapshot();
        let dashboard = make_entry(
            "perses.dev",
            "PersesDashboard",
            Some("monitoring"),
            "dash1",
            "uid-dash",
            vec![make_oref(
                "kserve.io/v1",
                "Kserve",
                "default-kserve",
                "uid-kserve",
                true,
            )],
        );
        snap.resources.insert("uid-dash".into(), dashboard);
        let coo = make_operator("coo.v1", "ns", vec!["persesdashboards.perses.dev"], vec![]);
        let graph = build_evidence_graph(&snap, &[coo]);
        // Dashboard Owns edge is from Kserve (TargetMissing since Kserve not in snapshot)
        let dash_owns: Vec<_> = graph
            .edges
            .iter()
            .filter(|e| e.relation == Relation::Owns && e.to.kind == "PersesDashboard")
            .collect();
        assert_eq!(dash_owns.len(), 1);
        assert_eq!(dash_owns[0].from.kind, "Kserve");
        assert!(
            !can_authorize_delete(dash_owns[0]),
            "TargetMissing foreign owner cannot authorize"
        );
        // COO only gets ApiStewardship
        let steward: Vec<_> = graph
            .edges
            .iter()
            .filter(|e| e.relation == Relation::ApiStewardship)
            .collect();
        assert_eq!(steward.len(), 1);
    }

    // ── Physical entities ──

    #[test]
    fn entities_populated_from_snapshot() {
        let mut snap = empty_snapshot();
        let e = make_entry("apps", "Deployment", Some("ns"), "dep1", "uid-dep", vec![]);
        snap.resources.insert("uid-dep".into(), e);
        let graph = build_evidence_graph(&snap, &[]);
        assert!(graph.entities.contains_key("uid-dep"));
        assert_eq!(graph.entities["uid-dep"].canonical_id.name, "dep1");
    }

    // ── Misc ──

    #[test]
    fn non_controller_owner_ref_also_produces_owns() {
        let mut snap = empty_snapshot();
        let parent = make_entry("apps", "RS", Some("ns"), "rs1", "uid-rs", vec![]);
        let child = make_entry(
            "",
            "Pod",
            Some("ns"),
            "pod1",
            "uid-c",
            vec![make_oref("apps/v1", "RS", "rs1", "uid-rs", false)],
        );
        snap.resources.insert("uid-rs".into(), parent);
        snap.resources.insert("uid-c".into(), child);
        let graph = build_evidence_graph(&snap, &[]);
        let owns: Vec<_> = graph
            .edges
            .iter()
            .filter(|e| e.relation == Relation::Owns)
            .collect();
        assert_eq!(owns.len(), 1);
        assert_eq!(owns[0].resolution, Resolution::Resolved);
    }

    #[test]
    fn block_owner_deletion_captured() {
        let mut snap = empty_snapshot();
        let parent = make_entry("apps", "Deployment", Some("ns"), "dep1", "uid-p", vec![]);
        let mut oref = make_oref("apps/v1", "Deployment", "dep1", "uid-p", true);
        oref.block_owner_deletion = true;
        let child = make_entry("", "Pod", Some("ns"), "pod1", "uid-c", vec![oref]);
        snap.resources.insert("uid-p".into(), parent);
        snap.resources.insert("uid-c".into(), child);
        let graph = build_evidence_graph(&snap, &[]);
        match &graph
            .edges
            .iter()
            .find(|e| e.relation == Relation::Owns)
            .unwrap()
            .evidence[0]
        {
            Evidence::OwnerReference {
                block_owner_deletion,
                ..
            } => assert!(block_owner_deletion),
            _ => panic!("expected OwnerReference"),
        }
    }

    #[test]
    fn graph_deterministic() {
        let build = |order: &[&str]| {
            let mut snap = empty_snapshot();
            for uid in order {
                snap.resources.insert(
                    uid.to_string(),
                    make_entry("apps", "Deployment", Some("ns"), uid, uid, vec![]),
                );
            }
            let orefs: Vec<_> = order
                .iter()
                .map(|uid| make_oref("apps/v1", "Deployment", uid, uid, false))
                .collect();
            snap.resources.insert(
                "uid-pod".into(),
                make_entry("", "Pod", Some("ns"), "pod1", "uid-pod", orefs),
            );
            serde_json::to_string(&build_evidence_graph(&snap, &[])).unwrap()
        };
        assert_eq!(build(&["a", "b", "c"]), build(&["c", "a", "b"]));
    }

    #[test]
    fn multiple_owners_both_produce_owns() {
        let mut snap = empty_snapshot();
        snap.resources.insert(
            "uid-rs1".into(),
            make_entry("apps", "RS", Some("ns"), "rs1", "uid-rs1", vec![]),
        );
        snap.resources.insert(
            "uid-rs2".into(),
            make_entry("apps", "RS", Some("ns"), "rs2", "uid-rs2", vec![]),
        );
        snap.resources.insert(
            "uid-pod".into(),
            make_entry(
                "",
                "Pod",
                Some("ns"),
                "pod1",
                "uid-pod",
                vec![
                    make_oref("apps/v1", "RS", "rs1", "uid-rs1", false),
                    make_oref("apps/v1", "RS", "rs2", "uid-rs2", false),
                ],
            ),
        );
        let graph = build_evidence_graph(&snap, &[]);
        assert_eq!(
            graph
                .edges
                .iter()
                .filter(|e| e.relation == Relation::Owns)
                .count(),
            2
        );
    }

    #[test]
    fn cycle_representation() {
        let mut snap = empty_snapshot();
        snap.resources.insert(
            "uid-a".into(),
            make_entry(
                "",
                "A",
                Some("ns"),
                "a1",
                "uid-a",
                vec![make_oref("v1", "B", "b1", "uid-b", false)],
            ),
        );
        snap.resources.insert(
            "uid-b".into(),
            make_entry(
                "",
                "B",
                Some("ns"),
                "b1",
                "uid-b",
                vec![make_oref("v1", "A", "a1", "uid-a", false)],
            ),
        );
        let graph = build_evidence_graph(&snap, &[]);
        assert_eq!(
            graph
                .edges
                .iter()
                .filter(|e| e.relation == Relation::Owns)
                .count(),
            2,
            "cycle: representation test — traversal in Phase 2"
        );
    }

    #[test]
    fn diamond_dag_representation() {
        let mut snap = empty_snapshot();
        snap.resources.insert(
            "uid-dep".into(),
            make_entry("apps", "Deployment", Some("ns"), "dep", "uid-dep", vec![]),
        );
        snap.resources.insert(
            "uid-rs-a".into(),
            make_entry(
                "apps",
                "RS",
                Some("ns"),
                "rs-a",
                "uid-rs-a",
                vec![make_oref("apps/v1", "Deployment", "dep", "uid-dep", true)],
            ),
        );
        snap.resources.insert(
            "uid-rs-b".into(),
            make_entry(
                "apps",
                "RS",
                Some("ns"),
                "rs-b",
                "uid-rs-b",
                vec![make_oref("apps/v1", "Deployment", "dep", "uid-dep", true)],
            ),
        );
        snap.resources.insert(
            "uid-pod".into(),
            make_entry(
                "",
                "Pod",
                Some("ns"),
                "pod1",
                "uid-pod",
                vec![
                    make_oref("apps/v1", "RS", "rs-a", "uid-rs-a", false),
                    make_oref("apps/v1", "RS", "rs-b", "uid-rs-b", false),
                ],
            ),
        );
        let graph = build_evidence_graph(&snap, &[]);
        assert_eq!(
            graph
                .edges
                .iter()
                .filter(|e| e.relation == Relation::Owns)
                .count(),
            4
        );
    }

    #[test]
    fn selects_exists() {
        let edge = Edge {
            from: make_rid("", "Deployment", Some("ns"), "d1", None),
            to: make_rid("", "Pod", Some("ns"), "p1", None),
            relation: Relation::Selects,
            evidence: vec![Evidence::LabelSelector {
                selector: "app=x".into(),
            }],
            confidence: Confidence::Hard,
            resolution: Resolution::Resolved,
        };
        assert!(!can_authorize_delete(&edge));
    }

    #[test]
    fn negative_evidence_serde() {
        let neg = NegativeEvidence::ForeignOwnerRef {
            owner_uid: "uid".into(),
            owner_kind: "Config".into(),
            owner_name: "default".into(),
        };
        let json = serde_json::to_string(&neg).unwrap();
        let deser: NegativeEvidence = serde_json::from_str(&json).unwrap();
        assert_eq!(deser, neg);
    }

    // ── Blocker 1: Observation model + entity aliases ──

    #[test]
    fn entities_from_observations_canonical_selection() {
        let obs = vec![
            ResourceObservation {
                uid: "uid-1".into(),
                id: make_rid("events.k8s.io", "Event", Some("ns"), "ev1", Some("uid-1")),
                resource: "events".into(),
                namespaced: true,
                is_preferred: true,
            },
            ResourceObservation {
                uid: "uid-1".into(),
                id: make_rid("", "Event", Some("ns"), "ev1", Some("uid-1")),
                resource: "events".into(),
                namespaced: true,
                is_preferred: false,
            },
        ];
        let entities = build_entities_from_observations(&obs);
        assert_eq!(entities.len(), 1, "same UID → 1 physical entity");
        let ent = entities.get("uid-1").unwrap();
        assert_eq!(ent.observed_aliases.len(), 2, "both aliases preserved");
        assert_eq!(
            ent.canonical_id.group, "events.k8s.io",
            "preferred observation is canonical"
        );
        assert!(
            ent.observed_aliases.iter().any(|a| a.resource == "events"),
            "resource field preserved"
        );
    }

    #[test]
    fn entities_reversed_insertion_order_identical() {
        let obs_fwd = vec![
            ResourceObservation {
                uid: "uid-1".into(),
                id: make_rid("", "Event", Some("ns"), "ev1", Some("uid-1")),
                resource: "events".into(),
                namespaced: true,
                is_preferred: false,
            },
            ResourceObservation {
                uid: "uid-1".into(),
                id: make_rid("events.k8s.io", "Event", Some("ns"), "ev1", Some("uid-1")),
                resource: "events".into(),
                namespaced: true,
                is_preferred: true,
            },
        ];
        let obs_rev: Vec<_> = obs_fwd.iter().rev().cloned().collect();
        let ent_fwd = build_entities_from_observations(&obs_fwd);
        let ent_rev = build_entities_from_observations(&obs_rev);
        let fwd_json = serde_json::to_string(&ent_fwd.get("uid-1")).unwrap();
        let rev_json = serde_json::to_string(&ent_rev.get("uid-1")).unwrap();
        assert_eq!(
            fwd_json, rev_json,
            "reversed observations → identical entity serialization"
        );
    }

    #[test]
    fn full_input_builder_uses_observations() {
        let mut snap = empty_snapshot();
        let entry = make_entry("", "ConfigMap", Some("ns"), "cm1", "uid-1", vec![]);
        snap.resources.insert("uid-1".into(), entry);
        let obs = vec![ResourceObservation {
            uid: "uid-1".into(),
            id: make_rid("", "ConfigMap", Some("ns"), "cm1", Some("uid-1")),
            resource: "configmaps".into(),
            namespaced: true,
            is_preferred: true,
        }];
        let input = EvidenceGraphInput {
            snapshot: &snap,
            operators: &[],
            observations: &obs,
            declared_cleanups: &[],
        };
        let graph = build_evidence_graph_full(input);
        assert_eq!(graph.entities.len(), 1);
        let ent = graph.entities.get("uid-1").unwrap();
        assert_eq!(ent.observed_aliases[0].resource, "configmaps");
    }

    // ── Blocker 2: Declared cleanup ──

    #[test]
    fn cleanup_resolved_cannot_authorize_delete() {
        let mut snap = empty_snapshot();
        let gw = make_entry(
            "gateway.networking.k8s.io",
            "Gateway",
            Some("ingress"),
            "gw1",
            "uid-gw",
            vec![],
        );
        snap.resources.insert("uid-gw".into(), gw);

        let cleanup = DeclaredCleanup {
            actor: make_rid("operators.coreos.com", "CSV", Some("ns"), "op.v1", None),
            target: make_rid(
                "gateway.networking.k8s.io",
                "Gateway",
                Some("ingress"),
                "gw1",
                Some("uid-gw"),
            ),
            source: CleanupSource::ExecutionPlanExplicitDelete,
            reason: "config explicit".into(),
        };
        let input = EvidenceGraphInput {
            snapshot: &snap,
            operators: &[],
            observations: &[],
            declared_cleanups: &[cleanup],
        };
        let graph = build_evidence_graph_full(input);
        let cu: Vec<_> = graph
            .edges
            .iter()
            .filter(|e| e.relation == Relation::CleansUp)
            .collect();
        assert_eq!(cu.len(), 1);
        assert_eq!(cu[0].resolution, Resolution::Resolved);
        assert!(
            !can_authorize_delete(cu[0]),
            "CleansUp must not authorize delete in Phase 1"
        );
    }

    #[test]
    fn cleanup_uid_mismatch_is_identity_mismatch() {
        let mut snap = empty_snapshot();
        let gw = make_entry(
            "gateway.networking.k8s.io",
            "Gateway",
            Some("ingress"),
            "gw1",
            "uid-new",
            vec![],
        );
        snap.resources.insert("uid-new".into(), gw);

        let cleanup = DeclaredCleanup {
            actor: make_rid("", "CSV", Some("ns"), "op.v1", None),
            target: make_rid(
                "gateway.networking.k8s.io",
                "Gateway",
                Some("ingress"),
                "gw1",
                Some("uid-old"),
            ),
            source: CleanupSource::ExecutionPlanExplicitDelete,
            reason: "config".into(),
        };
        let input = EvidenceGraphInput {
            snapshot: &snap,
            operators: &[],
            observations: &[],
            declared_cleanups: &[cleanup],
        };
        let graph = build_evidence_graph_full(input);
        let cu = graph
            .edges
            .iter()
            .find(|e| e.relation == Relation::CleansUp)
            .unwrap();
        assert_eq!(cu.resolution, Resolution::TargetMissing);
    }

    #[test]
    fn cleanup_missing_target_is_target_missing() {
        let snap = empty_snapshot();
        let cleanup = DeclaredCleanup {
            actor: make_rid("", "CSV", Some("ns"), "op.v1", None),
            target: make_rid("", "ConfigMap", Some("ns"), "cm-gone", Some("uid-gone")),
            source: CleanupSource::ExecutionPlanExplicitDelete,
            reason: "config".into(),
        };
        let input = EvidenceGraphInput {
            snapshot: &snap,
            operators: &[],
            observations: &[],
            declared_cleanups: &[cleanup],
        };
        let graph = build_evidence_graph_full(input);
        let cu = graph
            .edges
            .iter()
            .find(|e| e.relation == Relation::CleansUp)
            .unwrap();
        assert_eq!(cu.resolution, Resolution::TargetMissing);
    }

    #[test]
    fn cleanup_target_not_represented_as_owns() {
        let mut snap = empty_snapshot();
        let cm = make_entry("", "ConfigMap", Some("ns"), "cm1", "uid-cm", vec![]);
        snap.resources.insert("uid-cm".into(), cm);

        let cleanup = DeclaredCleanup {
            actor: make_rid("", "CSV", Some("ns"), "op.v1", None),
            target: make_rid("", "ConfigMap", Some("ns"), "cm1", Some("uid-cm")),
            source: CleanupSource::ExecutionPlanExplicitDelete,
            reason: "explicit".into(),
        };
        let input = EvidenceGraphInput {
            snapshot: &snap,
            operators: &[],
            observations: &[],
            declared_cleanups: &[cleanup],
        };
        let graph = build_evidence_graph_full(input);
        // Must have CleansUp, NOT Owns from the cleanup declaration
        let owns_from_csv: Vec<_> = graph
            .edges
            .iter()
            .filter(|e| e.relation == Relation::Owns && e.from.kind == "CSV")
            .collect();
        assert!(
            owns_from_csv.is_empty(),
            "cleanup must not produce Owns edges"
        );
        let cleanups: Vec<_> = graph
            .edges
            .iter()
            .filter(|e| e.relation == Relation::CleansUp)
            .collect();
        assert_eq!(cleanups.len(), 1);
    }

    // ── Blocker 3: resolve_full returns Resolution ──

    #[test]
    fn resolve_full_ambiguous_when_multiple_candidates() {
        let mut snap = empty_snapshot();
        // Two CRDs with same full key (shouldn't normally happen, but tests ambiguity)
        let crd1 = make_entry(
            "apiextensions.k8s.io",
            "CustomResourceDefinition",
            None,
            "x.example.com",
            "uid-1",
            vec![],
        );
        let crd2 = make_entry(
            "apiextensions.k8s.io",
            "CustomResourceDefinition",
            None,
            "x.example.com",
            "uid-2",
            vec![],
        );
        snap.resources.insert("uid-1".into(), crd1);
        snap.resources.insert("uid-2".into(), crd2);
        let op = make_operator("op.v1", "ns", vec!["x.example.com"], vec![]);
        let graph = build_evidence_graph(&snap, &[op]);
        let steward: Vec<_> = graph
            .edges
            .iter()
            .filter(|e| e.relation == Relation::ApiStewardship)
            .collect();
        assert_eq!(steward.len(), 1);
        assert_eq!(steward[0].resolution, Resolution::Ambiguous);
    }
}
