use std::collections::HashSet;

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
                    kind: oref.kind.clone(),
                    name: oref.name.clone(),
                    namespace: None,
                    uid: parent_uid.to_string(),
                    owner_refs: vec![],
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
