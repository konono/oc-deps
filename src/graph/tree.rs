use std::collections::HashSet;

use anyhow::{Result, bail};

use crate::kube::resource::*;

pub struct TreeNode {
    pub info: ResourceInfo,
    pub children: Vec<TreeNode>,
    pub is_target: bool,
    pub spec_refs: Vec<SpecRef>,
    pub incoming_refs: Vec<IncomingRef>,
}

pub fn build_parent_chain(target_uid: &str, index: &NamespaceIndex) -> Vec<String> {
    let mut chain = vec![target_uid.to_string()];
    let mut current = target_uid.to_string();
    let mut visited = HashSet::new();

    loop {
        if !visited.insert(current.clone()) {
            break;
        }

        match index.by_uid.get(&current) {
            Some(info) => {
                if let Some(owner) = primary_owner(&info.owner_refs) {
                    chain.push(owner.uid.clone());
                    if !index.by_uid.contains_key(&owner.uid) {
                        break;
                    }
                    current = owner.uid.clone();
                } else {
                    break;
                }
            }
            None => break,
        }
    }

    chain.reverse();
    chain
}

pub fn build_child_tree(
    uid: &str,
    index: &NamespaceIndex,
    depth: usize,
    max_depth: usize,
    visited: &mut HashSet<String>,
    target_uid: &str,
) -> Option<TreeNode> {
    if depth > max_depth || !visited.insert(uid.to_string()) {
        return None;
    }

    let info = index.by_uid.get(uid)?.clone();
    let mut children: Vec<TreeNode> = index
        .children_of
        .get(uid)
        .map(|child_uids| {
            child_uids
                .iter()
                .filter_map(|child_uid| {
                    build_child_tree(child_uid, index, depth + 1, max_depth, visited, target_uid)
                })
                .collect()
        })
        .unwrap_or_default();

    children.sort_by(|a, b| {
        a.info
            .kind
            .cmp(&b.info.kind)
            .then(a.info.name.cmp(&b.info.name))
    });

    let spec_refs = index.refs_from.get(uid).cloned().unwrap_or_default();
    let incoming_refs = index.refs_to.get(uid).cloned().unwrap_or_default();

    Some(TreeNode {
        is_target: uid == target_uid,
        info,
        children,
        spec_refs,
        incoming_refs,
    })
}

fn find_owner_ref_info(parent_uid: &str, index: &NamespaceIndex) -> Option<ResourceInfo> {
    for info in index.by_uid.values() {
        for oref in &info.owner_refs {
            if oref.uid == parent_uid {
                return Some(ResourceInfo {
                    group: String::new(),
                    kind: oref.kind.clone(),
                    name: oref.name.clone(),
                    namespace: None,
                    uid: parent_uid.to_string(),
                    owner_refs: vec![],
                    labels: std::collections::HashMap::new(),
                    annotations: std::collections::HashMap::new(),
                });
            }
        }
    }
    None
}

pub fn build_full_tree(
    target_uid: &str,
    index: &NamespaceIndex,
    max_depth: usize,
) -> Option<TreeNode> {
    let parent_chain = build_parent_chain(target_uid, index);

    let mut visited = HashSet::new();
    for uid in &parent_chain {
        if uid != target_uid {
            visited.insert(uid.clone());
        }
    }

    let target_subtree =
        build_child_tree(target_uid, index, 0, max_depth, &mut visited, target_uid)?;

    if parent_chain.len() <= 1 {
        return Some(target_subtree);
    }

    let mut current = target_subtree;
    for uid in parent_chain.iter().rev().skip(1) {
        let info = index
            .by_uid
            .get(uid)
            .cloned()
            .or_else(|| find_owner_ref_info(uid, index))?;
        let spec_refs = index.refs_from.get(uid).cloned().unwrap_or_default();
        let incoming_refs = index.refs_to.get(uid).cloned().unwrap_or_default();
        current = TreeNode {
            info,
            children: vec![current],
            is_target: false,
            spec_refs,
            incoming_refs,
        };
    }

    Some(current)
}

pub fn build_namespace_map(index: &NamespaceIndex, max_depth: usize) -> Vec<TreeNode> {
    let root_uids: Vec<String> = index
        .by_uid
        .iter()
        .filter(|(_, info)| {
            info.owner_refs.is_empty()
                || info
                    .owner_refs
                    .iter()
                    .all(|r| !index.by_uid.contains_key(&r.uid))
        })
        .map(|(uid, _)| uid.clone())
        .collect();

    let mut trees = Vec::new();
    let mut visited = HashSet::new();

    for root_uid in &root_uids {
        if visited.contains(root_uid) {
            continue;
        }
        if let Some(tree) = build_child_tree(root_uid, index, 0, max_depth, &mut visited, "") {
            trees.push(tree);
        }
    }

    trees.sort_by(|a, b| {
        a.info
            .kind
            .cmp(&b.info.kind)
            .then(a.info.name.cmp(&b.info.name))
    });
    trees
}

#[derive(Clone, Debug)]
pub enum MapFilter {
    Kind(String),
    Label { key: String, value: String },
}

impl MapFilter {
    pub fn matches(&self, info: &ResourceInfo) -> bool {
        match self {
            MapFilter::Kind(k) => info.kind.eq_ignore_ascii_case(k),
            MapFilter::Label { key, value } => info.labels.get(key) == Some(value),
        }
    }
}

pub fn parse_filters(raw: &[String]) -> Result<Vec<MapFilter>> {
    let mut filters = Vec::new();
    for s in raw {
        if let Some(kind) = s.strip_prefix("kind=") {
            if kind.is_empty() {
                bail!("Invalid filter: 'kind=' requires a value (e.g. kind=Deployment)");
            }
            filters.push(MapFilter::Kind(kind.to_string()));
        } else if let Some(rest) = s.strip_prefix("label=") {
            let (key, value) = rest.split_once('=').ok_or_else(|| {
                anyhow::anyhow!(
                    "Invalid filter: 'label={}' requires key=value format (e.g. label=app=myapp)",
                    rest
                )
            })?;
            if key.is_empty() || value.is_empty() {
                bail!("Invalid filter: 'label={}' has empty key or value", rest);
            }
            filters.push(MapFilter::Label {
                key: key.to_string(),
                value: value.to_string(),
            });
        } else {
            bail!(
                "Invalid filter: '{}'. Supported: kind=<Kind>, label=<key>=<value>",
                s
            );
        }
    }
    Ok(filters)
}

pub fn apply_filters(trees: Vec<TreeNode>, filters: &[MapFilter]) -> Vec<TreeNode> {
    if filters.is_empty() {
        return trees;
    }
    trees
        .into_iter()
        .filter(|tree| filters.iter().all(|f| f.matches(&tree.info)))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn make_info_with(kind: &str, name: &str, labels: Vec<(&str, &str)>) -> ResourceInfo {
        ResourceInfo {
            group: String::new(),
            kind: kind.into(),
            name: name.into(),
            namespace: Some("test".into()),
            uid: format!("uid-{}", name),
            owner_refs: vec![],
            labels: labels
                .into_iter()
                .map(|(k, v)| (k.into(), v.into()))
                .collect(),
            annotations: HashMap::new(),
        }
    }

    fn make_tree(kind: &str, name: &str, labels: Vec<(&str, &str)>) -> TreeNode {
        TreeNode {
            info: make_info_with(kind, name, labels),
            children: vec![],
            is_target: false,
            spec_refs: vec![],
            incoming_refs: vec![],
        }
    }

    #[test]
    fn parse_kind_filter() {
        let filters = parse_filters(&["kind=Deployment".into()]).unwrap();
        assert_eq!(filters.len(), 1);
        assert!(matches!(&filters[0], MapFilter::Kind(k) if k == "Deployment"));
    }

    #[test]
    fn parse_label_filter() {
        let filters = parse_filters(&["label=app=myapp".into()]).unwrap();
        assert_eq!(filters.len(), 1);
        assert!(
            matches!(&filters[0], MapFilter::Label { key, value } if key == "app" && value == "myapp")
        );
    }

    #[test]
    fn parse_label_with_slashes() {
        let filters =
            parse_filters(&["label=app.kubernetes.io/part-of=opendatahub".into()]).unwrap();
        assert!(matches!(&filters[0], MapFilter::Label { key, value }
            if key == "app.kubernetes.io/part-of" && value == "opendatahub"));
    }

    #[test]
    fn parse_multiple_filters() {
        let filters = parse_filters(&["kind=Deployment".into(), "label=app=x".into()]).unwrap();
        assert_eq!(filters.len(), 2);
    }

    #[test]
    fn parse_empty_kind_rejected() {
        assert!(parse_filters(&["kind=".into()]).is_err());
    }

    #[test]
    fn parse_empty_label_key_rejected() {
        assert!(parse_filters(&["label==value".into()]).is_err());
    }

    #[test]
    fn parse_empty_label_value_rejected() {
        assert!(parse_filters(&["label=key=".into()]).is_err());
    }

    #[test]
    fn parse_label_no_equals_rejected() {
        assert!(parse_filters(&["label=justkey".into()]).is_err());
    }

    #[test]
    fn parse_unknown_type_rejected() {
        assert!(parse_filters(&["name=foo".into()]).is_err());
    }

    #[test]
    fn kind_filter_case_insensitive() {
        let f = MapFilter::Kind("deployment".into());
        let info = make_info_with("Deployment", "test", vec![]);
        assert!(f.matches(&info));

        let f2 = MapFilter::Kind("DEPLOYMENT".into());
        assert!(f2.matches(&info));
    }

    #[test]
    fn label_filter_exact_match() {
        let f = MapFilter::Label {
            key: "app".into(),
            value: "myapp".into(),
        };
        let info = make_info_with("Deployment", "test", vec![("app", "myapp")]);
        assert!(f.matches(&info));

        let info2 = make_info_with("Deployment", "test", vec![("app", "other")]);
        assert!(!f.matches(&info2));

        let info3 = make_info_with("Deployment", "test", vec![]);
        assert!(!f.matches(&info3));
    }

    #[test]
    fn apply_filters_and() {
        let trees = vec![
            make_tree("Deployment", "a", vec![("app", "x")]),
            make_tree("Deployment", "b", vec![("app", "y")]),
            make_tree("Service", "c", vec![("app", "x")]),
        ];
        let filters = vec![
            MapFilter::Kind("Deployment".into()),
            MapFilter::Label {
                key: "app".into(),
                value: "x".into(),
            },
        ];
        let result = apply_filters(trees, &filters);
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].info.name, "a");
    }

    #[test]
    fn apply_filters_empty_preserves_all() {
        let trees = vec![
            make_tree("Deployment", "a", vec![]),
            make_tree("Service", "b", vec![]),
        ];
        let result = apply_filters(trees, &[]);
        assert_eq!(result.len(), 2);
    }

    #[test]
    fn apply_filters_no_match_returns_empty() {
        let trees = vec![make_tree("Deployment", "a", vec![])];
        let filters = vec![MapFilter::Kind("Service".into())];
        let result = apply_filters(trees, &filters);
        assert!(result.is_empty());
    }

    #[test]
    fn apply_filters_root_only_children_preserved() {
        let mut tree = make_tree("Deployment", "parent", vec![("app", "x")]);
        tree.children.push(make_tree("ReplicaSet", "child", vec![]));
        let trees = vec![tree];
        let filters = vec![MapFilter::Kind("Deployment".into())];
        let result = apply_filters(trees, &filters);
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].children.len(), 1);
        assert_eq!(result[0].children[0].info.kind, "ReplicaSet");
    }
}
