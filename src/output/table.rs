use comfy_table::Table;

use crate::graph::tree::TreeNode;
use crate::kube::resource::ResourceInfo;

fn flatten_for_table(
    node: &TreeNode,
    rows: &mut Vec<(String, String, String)>,
    found_target: &mut bool,
) {
    let relation = if node.is_target {
        *found_target = true;
        "Self".to_string()
    } else if *found_target {
        "Child".to_string()
    } else {
        "Parent".to_string()
    };

    rows.push((relation, node.info.kind.clone(), node.info.name.clone()));

    for child in &node.children {
        flatten_for_table(child, rows, found_target);
    }

    for sref in &node.spec_refs {
        rows.push((
            "Ref".to_string(),
            sref.target_kind.clone(),
            sref.target_name.clone(),
        ));
    }

    for iref in &node.incoming_refs {
        rows.push((
            "RefBy".to_string(),
            iref.source_kind.clone(),
            iref.source_name.clone(),
        ));
    }
}

pub fn print_table(tree: &TreeNode) {
    let mut rows = Vec::new();
    let mut found_target = false;
    flatten_for_table(tree, &mut rows, &mut found_target);

    let mut table = Table::new();
    table.set_header(vec!["Relation", "Kind", "Name"]);
    for (rel, kind, name) in &rows {
        table.add_row(vec![rel.as_str(), kind.as_str(), name.as_str()]);
    }
    println!("{table}");
}

pub fn print_chain_table(chain: &[ResourceInfo]) {
    let mut table = Table::new();
    table.set_header(vec!["Relation", "Kind", "Name"]);
    for (i, info) in chain.iter().enumerate() {
        let rel = if i == chain.len() - 1 {
            "Self"
        } else {
            "Parent"
        };
        table.add_row(vec![rel, &info.kind, &info.name]);
    }
    println!("{table}");
}
