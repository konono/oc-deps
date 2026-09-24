use comfy_table::Table;

use crate::graph::tree::TreeNode;
use crate::kube::resource::{ChainEntry, ResourceInfo, SpecRefSource};
use crate::output::tree::format_container_resources;

struct TableRow {
    relation: String,
    kind: String,
    name: String,
    containers: String,
    source: String,
    field_path: String,
}

fn format_containers(info: &ResourceInfo) -> String {
    let pt = match &info.pod_template {
        Some(pt) => pt,
        None => return String::new(),
    };
    let mut parts = Vec::new();
    for c in &pt.containers {
        parts.push(format_container_resources(c, ""));
    }
    for c in &pt.init_containers {
        parts.push(format_container_resources(c, "init:"));
    }
    parts.join("; ")
}

fn flatten_for_table(
    node: &TreeNode,
    rows: &mut Vec<TableRow>,
    found_target: &mut bool,
    show_spec: bool,
) {
    let relation = if node.is_target {
        *found_target = true;
        "Self".to_string()
    } else if *found_target {
        "Child".to_string()
    } else {
        "Parent".to_string()
    };

    rows.push(TableRow {
        relation,
        kind: node.info.kind.clone(),
        name: node.info.name.clone(),
        containers: if show_spec {
            format_containers(&node.info)
        } else {
            String::new()
        },
        source: String::new(),
        field_path: String::new(),
    });

    for child in &node.children {
        flatten_for_table(child, rows, found_target, show_spec);
    }

    for sref in &node.spec_refs {
        let source_str = match sref.source {
            SpecRefSource::Typed => "typed",
            SpecRefSource::Heuristic => "heuristic",
        };
        rows.push(TableRow {
            relation: "Ref".to_string(),
            kind: sref.target_kind.clone(),
            name: sref.target_name.clone(),
            containers: String::new(),
            source: source_str.to_string(),
            field_path: sref.field_path.clone(),
        });
    }

    for iref in &node.incoming_refs {
        rows.push(TableRow {
            relation: "RefBy".to_string(),
            kind: iref.source_kind.clone(),
            name: iref.source_name.clone(),
            containers: String::new(),
            source: String::new(),
            field_path: iref.field_path.clone(),
        });
    }
}

pub fn print_table(tree: &TreeNode, show_spec: bool) {
    let mut rows = Vec::new();
    let mut found_target = false;
    flatten_for_table(tree, &mut rows, &mut found_target, show_spec);

    let has_refs = rows.iter().any(|r| !r.source.is_empty());
    let mut table = Table::new();
    if show_spec && has_refs {
        table.set_header(vec![
            "Relation",
            "Kind",
            "Name",
            "Containers",
            "Source",
            "Field Path",
        ]);
        for row in &rows {
            table.add_row(vec![
                &row.relation,
                &row.kind,
                &row.name,
                &row.containers,
                &row.source,
                &row.field_path,
            ]);
        }
    } else if show_spec {
        table.set_header(vec!["Relation", "Kind", "Name", "Containers"]);
        for row in &rows {
            table.add_row(vec![&row.relation, &row.kind, &row.name, &row.containers]);
        }
    } else if has_refs {
        table.set_header(vec!["Relation", "Kind", "Name", "Source", "Field Path"]);
        for row in &rows {
            table.add_row(vec![
                &row.relation,
                &row.kind,
                &row.name,
                &row.source,
                &row.field_path,
            ]);
        }
    } else {
        table.set_header(vec!["Relation", "Kind", "Name"]);
        for row in &rows {
            table.add_row(vec![&row.relation, &row.kind, &row.name]);
        }
    }
    println!("{table}");
}

pub fn print_chain_table(chain: &[ChainEntry], show_spec: bool) {
    let has_refs = chain.iter().any(|e| !e.spec_refs.is_empty());
    let mut table = Table::new();
    if show_spec && has_refs {
        table.set_header(vec![
            "Relation",
            "Kind",
            "Name",
            "Containers",
            "Source",
            "Field Path",
        ]);
    } else if show_spec {
        table.set_header(vec!["Relation", "Kind", "Name", "Containers"]);
    } else if has_refs {
        table.set_header(vec!["Relation", "Kind", "Name", "Source", "Field Path"]);
    } else {
        table.set_header(vec!["Relation", "Kind", "Name"]);
    }
    for (i, entry) in chain.iter().enumerate() {
        let rel = if i == chain.len() - 1 {
            "Self"
        } else {
            "Parent"
        };
        if has_refs {
            if show_spec {
                table.add_row(vec![
                    rel,
                    &entry.info.kind,
                    &entry.info.name,
                    &format_containers(&entry.info),
                    "",
                    "",
                ]);
            } else {
                table.add_row(vec![rel, &entry.info.kind, &entry.info.name, "", ""]);
            }
        } else if show_spec {
            table.add_row(vec![
                rel,
                &entry.info.kind,
                &entry.info.name,
                &format_containers(&entry.info),
            ]);
        } else {
            table.add_row(vec![rel, &entry.info.kind, &entry.info.name]);
        }
        for sref in &entry.spec_refs {
            let source_str = match sref.source {
                SpecRefSource::Typed => "typed",
                SpecRefSource::Heuristic => "heuristic",
            };
            if show_spec {
                table.add_row(vec![
                    "Ref",
                    &sref.target_kind,
                    &sref.target_name,
                    "",
                    source_str,
                    &sref.field_path,
                ]);
            } else {
                table.add_row(vec![
                    "Ref",
                    &sref.target_kind,
                    &sref.target_name,
                    source_str,
                    &sref.field_path,
                ]);
            }
        }
    }
    println!("{table}");
}
