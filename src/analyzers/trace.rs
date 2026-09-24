use std::collections::HashSet;

use anyhow::Result;
use kube::Client;
use serde::{Deserialize, Serialize};

use crate::analyzers::inspect::{Confidence, Relationship};
use crate::analyzers::olm::discover_operators;
use crate::cli::OutputFormat;
use crate::graph::tree::{TreeNode, build_child_tree};
use crate::kube::discovery::{GroupKindMap, GvrMap, KindMap};
use crate::kube::resource::{NamespaceIndex, ResourceId, ResourceInfo};
use crate::teardown::planner::{discover_cr_instances, resolve_operator_targets};

fn resource_id_from_info(
    info: &ResourceInfo,
    kind_map: &KindMap,
    gk_map: &GroupKindMap,
) -> ResourceId {
    let version = gk_map
        .get(&(info.group.clone(), info.kind.clone()))
        .map(|ki| ki.version.clone())
        .or_else(|| kind_map.get(&info.kind).map(|ki| ki.version.clone()))
        .unwrap_or_default();
    ResourceId {
        group: info.group.clone(),
        version,
        kind: info.kind.clone(),
        namespace: info.namespace.clone(),
        name: info.name.clone(),
        uid: Some(info.uid.clone()),
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TracedResource {
    pub id: ResourceId,
    pub relationship: Relationship,
    pub evidence: String,
    pub confidence: Confidence,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TraceCategory {
    pub label: String,
    pub description: String,
    pub resources: Vec<TracedResource>,
}

#[derive(Serialize)]
pub struct TraceResultJson {
    pub root: ResourceId,
    pub root_namespace: Option<String>,
    pub descendant_count: usize,
    pub descendants: Vec<TracedResource>,
    pub categories: Vec<TraceCategory>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub warnings: Vec<String>,
}

pub struct TraceResult {
    pub root: ResourceId,
    pub root_namespace: Option<String>,
    pub ownerref_tree: Option<TreeNode>,
    pub descendants: Vec<TracedResource>,
    pub categories: Vec<TraceCategory>,
    pub scan_failures: Vec<crate::kube::resource::ScanWarning>,
}

#[allow(clippy::too_many_arguments)]
pub async fn trace_resource(
    client: &Client,
    kind: &str,
    name: &str,
    namespace: &str,
    target_group: &str,
    index: &NamespaceIndex,
    kind_map: &KindMap,
    gvr_map: &GvrMap,
    gk_map: &GroupKindMap,
    max_depth: usize,
    confirmed_operator_csv: Option<&str>,
) -> Result<TraceResult> {
    let mut scan_failures: Vec<crate::kube::resource::ScanWarning> = Vec::new();
    let target_ki = if !target_group.is_empty() {
        gk_map.get(&(target_group.to_string(), kind.to_string()))
    } else {
        kind_map.get(kind)
    };
    let target_ns = if target_ki.map(|ki| ki.namespaced).unwrap_or(true) {
        Some(namespace)
    } else {
        None
    };
    let target_uid = index
        .lookup_exact(target_group, kind, target_ns, name)
        .ok_or_else(|| anyhow::anyhow!("{}/{} not found in namespace {}", kind, name, namespace))?;

    let target_info = index
        .by_uid
        .get(target_uid)
        .ok_or_else(|| anyhow::anyhow!("{}/{} UID not in index", kind, name))?;

    let root_id = resource_id_from_info(target_info, kind_map, gk_map);

    // 1. ownerRef descendants
    let mut visited = HashSet::new();
    let ownerref_tree = build_child_tree(target_uid, index, 0, max_depth, &mut visited, target_uid);
    let descendants = ownerref_tree
        .as_ref()
        .map(|t| flatten_tree(t, 0, kind_map, gk_map))
        .unwrap_or_default();

    // 2. spec references from this resource
    let mut spec_ref_resources = Vec::new();
    if let Some(refs) = index.refs_from.get(target_uid) {
        for spec_ref in refs {
            if let Some(ref_uid) = index.lookup_by_kind_name(
                None, // spec-ref group unknown, use kind+name fallback
                &spec_ref.target_kind,
                &spec_ref.target_name,
                target_ns,
            ) && let Some(ref_info) = index.by_uid.get(ref_uid)
            {
                spec_ref_resources.push(TracedResource {
                    id: resource_id_from_info(ref_info, kind_map, gk_map),
                    relationship: Relationship::SpecRef,
                    evidence: format!("spec.{}", spec_ref.field_path),
                    confidence: Confidence::Attributed,
                });
            }
        }
    }

    // 3. Same Operator CRDs — use confirmed operator (from who-manages), not CRD origin
    let mut same_operator_resources = Vec::new();
    if let Some(csv_name) = confirmed_operator_csv {
        let operators = match discover_operators(client, kind_map).await {
            Ok(ops) => ops,
            Err(e) => {
                scan_failures.push(crate::kube::resource::ScanWarning::Other {
                    gvr: "operators.coreos.com/v1alpha1/clusterserviceversions".to_string(),
                    message: format!("Operator discovery failed: {}", e),
                });
                vec![]
            }
        };
        let csv_query = csv_name.to_string();
        if let Ok(indices) = resolve_operator_targets(&[csv_query], &operators)
            && let Some(&idx) = indices.first()
        {
            let op = &operators[idx];
            let target_crd_name = target_ki.map(|ki| format!("{}.{}", ki.plural, ki.group));
            let sibling_crds: Vec<String> = op
                .owned_crds
                .iter()
                .filter(|crd| {
                    target_crd_name
                        .as_ref()
                        .map(|t| !crd.eq_ignore_ascii_case(t))
                        .unwrap_or(true)
                })
                .cloned()
                .collect();

            if !sibling_crds.is_empty() {
                let cr_report = discover_cr_instances(client, &sibling_crds, gvr_map, gk_map).await;
                scan_failures.extend(cr_report.unavailable_crds);
                for cr in &cr_report.instances {
                    same_operator_resources.push(TracedResource {
                        id: cr.id.clone(),
                        relationship: Relationship::SameOperatorCrd,
                        evidence: format!("CSV {} owns CRD {}", csv_name, cr.id.kind),
                        confidence: Confidence::Inferred,
                    });
                }
            }
        }
    }

    // 4. Label matches
    let mut label_resources = Vec::new();
    let part_of_keys = [
        "app.kubernetes.io/part-of",
        "app.kubernetes.io/managed-by",
        "app.kubernetes.io/instance",
    ];
    let target_label_values: Vec<(&str, &str)> = target_info
        .labels
        .iter()
        .filter(|(k, _)| part_of_keys.contains(&k.as_str()) || k.ends_with("/part-of"))
        .map(|(k, v)| (k.as_str(), v.as_str()))
        .collect();

    if !target_label_values.is_empty() {
        let descendant_uids: HashSet<&str> = visited.iter().map(|s| s.as_str()).collect();
        let spec_ref_uids: HashSet<String> = spec_ref_resources
            .iter()
            .filter_map(|r| r.id.uid.clone())
            .collect();

        for (uid, info) in &index.by_uid {
            if uid == target_uid
                || descendant_uids.contains(uid.as_str())
                || spec_ref_uids.contains(uid)
            {
                continue;
            }

            for (key, value) in &target_label_values {
                if info.labels.get(*key).map(|v| v.as_str()) == Some(value) {
                    label_resources.push(TracedResource {
                        id: resource_id_from_info(info, kind_map, gk_map),
                        relationship: Relationship::LabelMatch,
                        evidence: format!("label {}={}", key, value),
                        confidence: Confidence::Inferred,
                    });
                    break;
                }
            }
        }
    }

    let mut categories = Vec::new();
    if !spec_ref_resources.is_empty() {
        categories.push(TraceCategory {
            label: "spec references".to_string(),
            description: "Resources referenced in spec fields".to_string(),
            resources: spec_ref_resources,
        });
    }
    if !same_operator_resources.is_empty() {
        categories.push(TraceCategory {
            label: "Same Operator CRDs (correlation, not causation)".to_string(),
            description: "Other CRD instances owned by the same CSV".to_string(),
            resources: same_operator_resources,
        });
    }
    if !label_resources.is_empty() {
        categories.push(TraceCategory {
            label: "label matches (correlation only)".to_string(),
            description: "Resources sharing standard Kubernetes labels".to_string(),
            resources: label_resources,
        });
    }

    Ok(TraceResult {
        root: root_id,
        root_namespace: target_ns.map(|s| s.to_string()),
        ownerref_tree,
        descendants,
        categories,
        scan_failures,
    })
}

pub fn print_trace(result: &TraceResult, output: &OutputFormat) {
    match output {
        OutputFormat::Json => print_trace_json(result),
        OutputFormat::Table => print_trace_table(result),
        OutputFormat::Tree => print_trace_tree(result),
    }
}

fn print_trace_tree(result: &TraceResult) {
    let root_ns = result
        .root
        .namespace
        .as_ref()
        .map(|ns| format!("  \x1b[2m(ns: {})\x1b[0m", ns))
        .unwrap_or_else(|| "  \x1b[2m(cluster-scoped)\x1b[0m".to_string());
    println!(
        "\x1b[1m{}/{}\x1b[0m{}  ◀ root",
        result.root.kind, result.root.name, root_ns
    );
    println!();

    if let Some(tree) = &result.ownerref_tree {
        let descendant_count = count_descendants(tree);
        if descendant_count > 0 {
            println!(
                "── ownerRef descendants (confirmed, {}) ──",
                descendant_count
            );
            for child in &tree.children {
                print_tree_node(child, "  ", true);
            }
            println!();
        }
    }

    for category in &result.categories {
        println!("── {} ──", category.label);
        for r in &category.resources {
            let confidence_str = match r.confidence {
                Confidence::Managed => "High",
                Confidence::Attributed => "Medium",
                Confidence::Inferred => "Low",
            };
            let rel_str = crate::analyzers::inspect::relationship_display(&r.relationship);
            let ns_suffix =
                r.id.namespace
                    .as_ref()
                    .map(|ns| format!("  \x1b[2m(ns: {})\x1b[0m", ns))
                    .unwrap_or_default();
            println!(
                "  {}/{}{}  \x1b[2m[{}: {}, {}]\x1b[0m",
                r.id.kind, r.id.name, ns_suffix, rel_str, r.evidence, confidence_str
            );
        }
        println!();
    }

    for warning in &result.scan_failures {
        eprintln!("  \x1b[33m⚠ {}\x1b[0m", warning);
    }
}

fn print_tree_node(node: &TreeNode, prefix: &str, is_last: bool) {
    let connector = if is_last { "└─ " } else { "├─ " };
    let child_prefix = if is_last {
        format!("{}   ", prefix)
    } else {
        format!("{}│  ", prefix)
    };

    let ns_suffix = node
        .info
        .namespace
        .as_ref()
        .map(|ns| format!("  \x1b[2m(ns: {})\x1b[0m", ns))
        .unwrap_or_default();
    println!(
        "{}{}{}/{}{}  \x1b[2m[ownerRef, Managed]\x1b[0m",
        prefix, connector, node.info.kind, node.info.name, ns_suffix
    );

    let children_len = node.children.len();
    for (i, child) in node.children.iter().enumerate() {
        print_tree_node(child, &child_prefix, i == children_len - 1);
    }
}

fn count_descendants(tree: &TreeNode) -> usize {
    let mut count = 0;
    for child in &tree.children {
        count += 1 + count_descendants(child);
    }
    count
}

fn flatten_tree(
    node: &TreeNode,
    depth: usize,
    kind_map: &KindMap,
    gk_map: &GroupKindMap,
) -> Vec<TracedResource> {
    let mut resources = Vec::new();
    for child in &node.children {
        resources.push(TracedResource {
            id: resource_id_from_info(&child.info, kind_map, gk_map),
            relationship: Relationship::OwnerRef,
            evidence: format!("ownerRef UID match (depth {})", depth + 1),
            confidence: Confidence::Managed,
        });
        resources.extend(flatten_tree(child, depth + 1, kind_map, gk_map));
    }
    resources
}

fn print_trace_table(result: &TraceResult) {
    use comfy_table::Table;

    let mut table = Table::new();
    table.set_header(vec![
        "Category",
        "Group",
        "Kind",
        "Name",
        "Namespace",
        "Relationship",
        "Evidence",
        "Confidence",
    ]);

    for d in &result.descendants {
        let ns = d.id.namespace.as_deref().unwrap_or("(cluster-scoped)");
        let conf = match d.confidence {
            Confidence::Managed => "High",
            Confidence::Attributed => "Medium",
            Confidence::Inferred => "Low",
        };
        table.add_row(vec![
            "ownerRef descendants",
            &d.id.group,
            &d.id.kind,
            &d.id.name,
            ns,
            crate::analyzers::inspect::relationship_display(&d.relationship),
            &d.evidence,
            conf,
        ]);
    }

    for category in &result.categories {
        for r in &category.resources {
            let ns = r.id.namespace.as_deref().unwrap_or("(cluster-scoped)");
            let conf = match r.confidence {
                Confidence::Managed => "High",
                Confidence::Attributed => "Medium",
                Confidence::Inferred => "Low",
            };
            table.add_row(vec![
                &category.label,
                &r.id.group,
                &r.id.kind,
                &r.id.name,
                ns,
                crate::analyzers::inspect::relationship_display(&r.relationship),
                &r.evidence,
                conf,
            ]);
        }
    }

    println!(
        "\x1b[1m{}/{}\x1b[0m  ◀ root\n",
        result.root.kind, result.root.name
    );
    println!("{}", table);
}

fn print_trace_json(result: &TraceResult) {
    let descendant_count = result.descendants.len();
    let json_result = TraceResultJson {
        root: result.root.clone(),
        root_namespace: result.root_namespace.clone(),
        descendant_count,
        descendants: result.descendants.clone(),
        categories: result.categories.clone(),
        warnings: result
            .scan_failures
            .iter()
            .map(|w| format!("{}", w))
            .collect(),
    };
    println!(
        "{}",
        serde_json::to_string_pretty(&json_result).unwrap_or_default()
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::kube::resource::ResourceInfo;
    use std::collections::HashMap;

    fn make_info_with_group(group: &str, kind: &str, name: &str, uid: &str) -> ResourceInfo {
        ResourceInfo {
            group: group.into(),
            kind: kind.into(),
            name: name.into(),
            namespace: Some("test-ns".into()),
            uid: uid.into(),
            owner_refs: vec![],
            labels: HashMap::new(),
            annotations: HashMap::new(),
        }
    }

    fn make_info(kind: &str, name: &str, uid: &str) -> ResourceInfo {
        ResourceInfo {
            group: String::new(),
            kind: kind.into(),
            name: name.into(),
            namespace: Some("test-ns".into()),
            uid: uid.into(),
            owner_refs: vec![],
            labels: HashMap::new(),
            annotations: HashMap::new(),
        }
    }

    #[test]
    fn test_count_descendants_empty() {
        let tree = TreeNode {
            info: make_info("Deployment", "d1", "uid-1"),
            children: vec![],
            is_target: true,
            spec_refs: vec![],
            incoming_refs: vec![],
        };
        assert_eq!(count_descendants(&tree), 0);
    }

    #[test]
    fn test_count_descendants_nested() {
        let tree = TreeNode {
            info: make_info("Deployment", "d1", "uid-1"),
            children: vec![
                TreeNode {
                    info: make_info("ReplicaSet", "rs1", "uid-2"),
                    children: vec![TreeNode {
                        info: make_info("Pod", "p1", "uid-3"),
                        children: vec![],
                        is_target: false,
                        spec_refs: vec![],
                        incoming_refs: vec![],
                    }],
                    is_target: false,
                    spec_refs: vec![],
                    incoming_refs: vec![],
                },
                TreeNode {
                    info: make_info("ReplicaSet", "rs2", "uid-4"),
                    children: vec![],
                    is_target: false,
                    spec_refs: vec![],
                    incoming_refs: vec![],
                },
            ],
            is_target: true,
            spec_refs: vec![],
            incoming_refs: vec![],
        };
        assert_eq!(count_descendants(&tree), 3);
    }

    #[test]
    fn test_trace_category_json() {
        let category = TraceCategory {
            label: "spec references".into(),
            description: "test".into(),
            resources: vec![TracedResource {
                id: ResourceId {
                    group: String::new(),
                    version: String::new(),
                    kind: "Secret".into(),
                    namespace: Some("test-ns".into()),
                    name: "my-secret".into(),
                    uid: None,
                },
                relationship: Relationship::OwnerRef,
                evidence: "spec.volumes".into(),
                confidence: Confidence::Attributed,
            }],
        };
        let json = serde_json::to_string(&category).unwrap();
        assert!(json.contains("spec references"));
        assert!(json.contains("my-secret"));
    }

    #[test]
    fn test_trace_result_json_serialization() {
        let result = TraceResultJson {
            root: ResourceId {
                group: "example.com".into(),
                version: "v1".into(),
                kind: "Widget".into(),
                namespace: Some("test-ns".into()),
                name: "w1".into(),
                uid: None,
            },
            root_namespace: Some("test-ns".into()),
            descendant_count: 2,
            descendants: vec![
                TracedResource {
                    id: ResourceId {
                        group: "apps".into(),
                        version: "v1".into(),
                        kind: "ReplicaSet".into(),
                        namespace: Some("test-ns".into()),
                        name: "rs1".into(),
                        uid: None,
                    },
                    relationship: Relationship::OwnerRef,
                    evidence: "ownerRef UID match (depth 1)".into(),
                    confidence: Confidence::Managed,
                },
                TracedResource {
                    id: ResourceId {
                        group: String::new(),
                        version: "v1".into(),
                        kind: "Pod".into(),
                        namespace: Some("test-ns".into()),
                        name: "p1".into(),
                        uid: None,
                    },
                    relationship: Relationship::OwnerRef,
                    evidence: "ownerRef UID match (depth 2)".into(),
                    confidence: Confidence::Managed,
                },
            ],
            categories: vec![],
            warnings: vec![],
        };
        let json = serde_json::to_string_pretty(&result).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed["descendant_count"].as_u64().unwrap(), 2);
        assert_eq!(parsed["descendants"].as_array().unwrap().len(), 2);
        assert_eq!(parsed["root"]["kind"].as_str().unwrap(), "Widget");
    }

    #[test]
    fn test_flatten_tree_with_kind_map() {
        use crate::kube::discovery::{KindInfo, KindMap};

        let mut kind_map: KindMap = HashMap::new();
        kind_map.insert(
            "ReplicaSet".into(),
            KindInfo {
                group: "apps".into(),
                version: "v1".into(),
                plural: "replicasets".into(),
                namespaced: true,
                listable: true,
            },
        );
        kind_map.insert(
            "Pod".into(),
            KindInfo {
                group: String::new(),
                version: "v1".into(),
                plural: "pods".into(),
                namespaced: true,
                listable: true,
            },
        );

        let tree = TreeNode {
            info: make_info_with_group("apps", "Deployment", "d1", "uid-1"),
            children: vec![TreeNode {
                info: make_info_with_group("apps", "ReplicaSet", "rs1", "uid-2"),
                children: vec![TreeNode {
                    info: make_info_with_group("", "Pod", "p1", "uid-3"),
                    children: vec![],
                    is_target: false,
                    spec_refs: vec![],
                    incoming_refs: vec![],
                }],
                is_target: false,
                spec_refs: vec![],
                incoming_refs: vec![],
            }],
            is_target: true,
            spec_refs: vec![],
            incoming_refs: vec![],
        };

        let gk_map: crate::kube::discovery::GroupKindMap = HashMap::new();
        let flattened = flatten_tree(&tree, 0, &kind_map, &gk_map);
        assert_eq!(flattened.len(), 2);
        assert_eq!(flattened[0].id.group, "apps");
        assert_eq!(flattened[0].id.kind, "ReplicaSet");
        assert_eq!(flattened[1].id.group, "");
        assert_eq!(flattened[1].id.kind, "Pod");
        assert!(matches!(flattened[0].relationship, Relationship::OwnerRef));
        assert!(matches!(flattened[0].confidence, Confidence::Managed));
    }

    #[test]
    fn test_resource_id_from_info_populates_group() {
        use crate::kube::discovery::{KindInfo, KindMap};

        let mut kind_map: KindMap = HashMap::new();
        kind_map.insert(
            "Deployment".into(),
            KindInfo {
                group: "apps".into(),
                version: "v1".into(),
                plural: "deployments".into(),
                namespaced: true,
                listable: true,
            },
        );

        let gk_map: crate::kube::discovery::GroupKindMap = HashMap::new();
        let info = make_info_with_group("apps", "Deployment", "d1", "uid-1");
        let id = resource_id_from_info(&info, &kind_map, &gk_map);
        assert_eq!(id.group, "apps");
        assert_eq!(id.version, "v1");
        assert_eq!(id.kind, "Deployment");
    }

    #[test]
    fn test_spec_ref_relationship_in_json() {
        let r = TracedResource {
            id: ResourceId {
                group: String::new(),
                version: "v1".into(),
                kind: "Secret".into(),
                namespace: Some("test-ns".into()),
                name: "my-secret".into(),
                uid: None,
            },
            relationship: Relationship::SpecRef,
            evidence: "spec.volumes[0].secret.secretName".into(),
            confidence: Confidence::Attributed,
        };
        let json = serde_json::to_string(&r).unwrap();
        assert!(json.contains("\"spec-ref\""));
        assert!(json.contains("Attributed"));
    }
}
