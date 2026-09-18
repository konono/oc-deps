use std::collections::HashMap;

use serde::{Deserialize, Serialize};

use crate::analyzers::olm::OperatorInstance;
use crate::kube::resource::{ClusterSnapshot, ResourceId};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EvidenceGraph {
    pub edges: Vec<Edge>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Edge {
    pub from: ResourceId,
    pub to: ResourceId,
    pub relation: Relation,
    pub evidence: Vec<Evidence>,
    pub confidence: Confidence,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Relation {
    Owns,
    References,
    Selects,
    RequiresApi,
    ProvidesApi,
    UsesStorage,
    ServesWebhook,
    UsesServiceAccount,
    ManagedBy,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Evidence {
    OwnerReference,
    CsvOwnedCrd { crd_name: String },
    CsvRequiredCrd { crd_name: String },
    CsvInstallStrategy,
    SpecField { path: String },
    LabelSelector { selector: String },
    ManagedFields { manager: String },
    Finalizer { name: String },
    StorageBinding,
    WebhookService,
    ApiServiceBackend,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Confidence {
    Hard,
    Inferred,
    Heuristic,
}

const WELL_KNOWN_SPEC_REF_KINDS: &[&str] = &[
    "Secret",
    "ConfigMap",
    "ServiceAccount",
    "PersistentVolumeClaim",
];

pub fn build_evidence_graph(
    snapshot: &ClusterSnapshot,
    operators: &[OperatorInstance],
) -> EvidenceGraph {
    let mut edges = Vec::new();

    let by_kind_name = build_kind_name_index(snapshot);

    add_owner_ref_edges(snapshot, &mut edges);
    add_spec_ref_edges(snapshot, &by_kind_name, &mut edges);
    add_olm_edges(operators, &by_kind_name, &mut edges);
    add_service_account_edges(snapshot, &by_kind_name, &mut edges);

    EvidenceGraph { edges }
}

fn build_kind_name_index(snapshot: &ClusterSnapshot) -> HashMap<(String, String), ResourceId> {
    let mut index = HashMap::new();
    for entry in snapshot.resources.values() {
        let key = (entry.id.kind.to_lowercase(), entry.id.name.clone());
        index.insert(key, entry.id.clone());
    }
    index
}

fn add_owner_ref_edges(snapshot: &ClusterSnapshot, edges: &mut Vec<Edge>) {
    for entry in snapshot.resources.values() {
        for oref in &entry.owner_refs {
            let parent_id = if let Some(parent_entry) = snapshot.resources.get(&oref.uid) {
                parent_entry.id.clone()
            } else {
                let (group, version) = match oref.api_version.rsplit_once('/') {
                    Some((g, v)) => (g.to_string(), v.to_string()),
                    None => (String::new(), oref.api_version.clone()),
                };
                ResourceId {
                    group,
                    version,
                    kind: oref.kind.clone(),
                    namespace: entry.id.namespace.clone(),
                    name: oref.name.clone(),
                    uid: Some(oref.uid.clone()),
                }
            };

            edges.push(Edge {
                from: parent_id,
                to: entry.id.clone(),
                relation: Relation::Owns,
                evidence: vec![Evidence::OwnerReference],
                confidence: Confidence::Hard,
            });
        }
    }
}

fn add_spec_ref_edges(
    snapshot: &ClusterSnapshot,
    by_kind_name: &HashMap<(String, String), ResourceId>,
    edges: &mut Vec<Edge>,
) {
    for entry in snapshot.resources.values() {
        for sref in &entry.spec_refs {
            let target_key = (sref.target_kind.to_lowercase(), sref.target_name.clone());
            let target_id = if let Some(id) = by_kind_name.get(&target_key) {
                id.clone()
            } else {
                ResourceId {
                    group: String::new(),
                    version: String::new(),
                    kind: sref.target_kind.clone(),
                    namespace: entry.id.namespace.clone(),
                    name: sref.target_name.clone(),
                    uid: None,
                }
            };

            let is_well_known = WELL_KNOWN_SPEC_REF_KINDS
                .iter()
                .any(|k| k.eq_ignore_ascii_case(&sref.target_kind));

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
            });
        }
    }
}

fn add_olm_edges(
    operators: &[OperatorInstance],
    by_kind_name: &HashMap<(String, String), ResourceId>,
    edges: &mut Vec<Edge>,
) {
    for op in operators {
        for crd_name in &op.owned_crds {
            let crd_id = ResourceId {
                group: "apiextensions.k8s.io".to_string(),
                version: "v1".to_string(),
                kind: "CustomResourceDefinition".to_string(),
                namespace: None,
                name: crd_name.clone(),
                uid: None,
            };

            edges.push(Edge {
                from: op.csv.clone(),
                to: crd_id,
                relation: Relation::ProvidesApi,
                evidence: vec![Evidence::CsvOwnedCrd {
                    crd_name: crd_name.clone(),
                }],
                confidence: Confidence::Hard,
            });
        }

        for crd_name in &op.required_crds {
            let crd_id = ResourceId {
                group: "apiextensions.k8s.io".to_string(),
                version: "v1".to_string(),
                kind: "CustomResourceDefinition".to_string(),
                namespace: None,
                name: crd_name.clone(),
                uid: None,
            };

            edges.push(Edge {
                from: op.csv.clone(),
                to: crd_id,
                relation: Relation::RequiresApi,
                evidence: vec![Evidence::CsvRequiredCrd {
                    crd_name: crd_name.clone(),
                }],
                confidence: Confidence::Hard,
            });
        }

        for deploy_name in &op.deployments {
            let deploy_key = ("deployment".to_string(), deploy_name.clone());
            if let Some(deploy_id) = by_kind_name.get(&deploy_key) {
                edges.push(Edge {
                    from: op.csv.clone(),
                    to: deploy_id.clone(),
                    relation: Relation::Owns,
                    evidence: vec![Evidence::CsvInstallStrategy],
                    confidence: Confidence::Hard,
                });
            }
        }

        for sa_name in &op.service_accounts {
            let sa_key = ("serviceaccount".to_string(), sa_name.clone());
            if let Some(sa_id) = by_kind_name.get(&sa_key) {
                edges.push(Edge {
                    from: op.csv.clone(),
                    to: sa_id.clone(),
                    relation: Relation::References,
                    evidence: vec![Evidence::CsvInstallStrategy],
                    confidence: Confidence::Hard,
                });
            }
        }
    }
}

fn add_service_account_edges(
    snapshot: &ClusterSnapshot,
    by_kind_name: &HashMap<(String, String), ResourceId>,
    edges: &mut Vec<Edge>,
) {
    for entry in snapshot.resources.values() {
        if entry.id.kind != "Pod" && entry.id.kind != "Deployment" && entry.id.kind != "ReplicaSet"
        {
            continue;
        }

        let sa_name = extract_service_account_name(&entry.id.kind, entry.raw_spec.as_ref());
        if let Some(sa_name) = sa_name {
            let sa_key = ("serviceaccount".to_string(), sa_name.clone());
            let already_has = edges.iter().any(|e| {
                e.from == entry.id
                    && e.relation == Relation::UsesServiceAccount
                    && e.to.name == sa_name
            });
            if already_has {
                continue;
            }

            let target_id = if let Some(id) = by_kind_name.get(&sa_key) {
                id.clone()
            } else {
                ResourceId {
                    group: String::new(),
                    version: "v1".to_string(),
                    kind: "ServiceAccount".to_string(),
                    namespace: entry.id.namespace.clone(),
                    name: sa_name,
                    uid: None,
                }
            };

            edges.push(Edge {
                from: entry.id.clone(),
                to: target_id,
                relation: Relation::UsesServiceAccount,
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
