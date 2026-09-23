use crate::graph::tree::TreeNode;
use crate::kube::resource::{ResourceInfo, filter_annotations};

pub fn tree_to_json(node: &TreeNode, include_annotations: bool) -> serde_json::Value {
    let mut obj = serde_json::json!({
        "kind": node.info.kind,
        "name": node.info.name,
        "namespace": node.info.namespace,
        "uid": node.info.uid,
        "isTarget": node.is_target,
        "children": node.children.iter().map(|c| tree_to_json(c, include_annotations)).collect::<Vec<_>>(),
    });
    obj["labels"] = serde_json::json!(node.info.labels);
    if include_annotations && !node.info.annotations.is_empty() {
        let filtered = filter_annotations(&node.info.annotations);
        if !filtered.is_empty() {
            obj["annotations"] = serde_json::json!(filtered);
        }
    }
    if !node.spec_refs.is_empty() {
        obj["specRefs"] = serde_json::json!(
            node.spec_refs
                .iter()
                .map(|r| serde_json::json!({
                    "kind": r.target_kind,
                    "name": r.target_name,
                    "fieldPath": r.field_path,
                }))
                .collect::<Vec<_>>()
        );
    }
    if !node.incoming_refs.is_empty() {
        obj["referencedBy"] = serde_json::json!(
            node.incoming_refs
                .iter()
                .map(|r| serde_json::json!({
                    "kind": r.source_kind,
                    "name": r.source_name,
                    "fieldPath": r.field_path,
                }))
                .collect::<Vec<_>>()
        );
    }
    obj
}

fn find_target_ref(node: &TreeNode) -> String {
    if node.is_target {
        return format!("{}/{}", node.info.kind, node.info.name);
    }
    for child in &node.children {
        let r = find_target_ref(child);
        if !r.is_empty() {
            return r;
        }
    }
    String::new()
}

pub fn print_json(tree: &TreeNode, namespace: &str, include_annotations: bool) {
    let target = find_target_ref(tree);
    let output = serde_json::json!({
        "namespace": namespace,
        "target": target,
        "tree": tree_to_json(tree, include_annotations),
    });
    println!(
        "{}",
        serde_json::to_string_pretty(&output).unwrap_or_default()
    );
}

pub fn print_chain_json(chain: &[ResourceInfo], namespace: &str, include_annotations: bool) {
    let items: Vec<_> = chain
        .iter()
        .enumerate()
        .map(|(i, info)| {
            let mut obj = serde_json::json!({
                "relation": if i == chain.len() - 1 { "self" } else { "parent" },
                "kind": info.kind,
                "name": info.name,
                "namespace": info.namespace,
                "uid": info.uid,
            });
            obj["labels"] = serde_json::json!(info.labels);
            if include_annotations && !info.annotations.is_empty() {
                let filtered = filter_annotations(&info.annotations);
                if !filtered.is_empty() {
                    obj["annotations"] = serde_json::json!(filtered);
                }
            }
            obj
        })
        .collect();
    let output = serde_json::json!({
        "namespace": namespace,
        "target": chain.last().map(|i| format!("{}/{}", i.kind, i.name)).unwrap_or_default(),
        "chain": items,
    });
    println!(
        "{}",
        serde_json::to_string_pretty(&output).unwrap_or_default()
    );
}
