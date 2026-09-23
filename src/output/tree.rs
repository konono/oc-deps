use crate::graph::tree::TreeNode;
use crate::kube::resource::{EXCLUDED_ANNOTATION_KEYS, ResourceInfo};

#[derive(Default)]
pub struct TreeDisplayOpts {
    pub show_labels: bool,
    pub show_annotations: bool,
}

fn format_label_suffix(info: &ResourceInfo, opts: &TreeDisplayOpts) -> String {
    if !opts.show_labels && !opts.show_annotations {
        return String::new();
    }

    let mut parts = Vec::new();

    if opts.show_labels && !info.labels.is_empty() {
        let mut labels: Vec<_> = info
            .labels
            .iter()
            .map(|(k, v)| format!("{}={}", k, v))
            .collect();
        labels.sort();
        parts.push(format!("\x1b[2m [{}]\x1b[0m", labels.join(", ")));
    }

    if opts.show_annotations && !info.annotations.is_empty() {
        let mut anns: Vec<_> = info
            .annotations
            .iter()
            .filter(|(k, _)| !EXCLUDED_ANNOTATION_KEYS.contains(&k.as_str()))
            .map(|(k, v)| {
                let display_v = if v.chars().count() > 40 {
                    let truncated: String = v.chars().take(37).collect();
                    format!("{}...", truncated)
                } else {
                    v.clone()
                };
                format!("{}={}", k, display_v)
            })
            .collect();
        anns.sort();
        if !anns.is_empty() {
            parts.push(format!("\x1b[2;35m [{}]\x1b[0m", anns.join(", ")));
        }
    }

    parts.join("")
}

pub fn print_tree(
    node: &TreeNode,
    prefix: &str,
    is_last: bool,
    is_root: bool,
    opts: &TreeDisplayOpts,
) {
    let has_refs = !node.spec_refs.is_empty();
    let has_incoming = !node.incoming_refs.is_empty();
    let has_trailing = has_refs || has_incoming;
    let connector = if is_root {
        ""
    } else if is_last {
        "└─ "
    } else {
        "├─ "
    };

    let target_marker = if node.is_target {
        "  \x1b[1;33m◀ target\x1b[0m"
    } else {
        ""
    };
    let resource_ref = format!("{}/{}", node.info.kind, node.info.name);
    let label_suffix = format_label_suffix(&node.info, opts);

    if node.is_target {
        println!(
            "{}{}\x1b[1;32m{}\x1b[0m{}{}",
            prefix, connector, resource_ref, target_marker, label_suffix
        );
    } else {
        println!(
            "{}{}{}{}{}",
            prefix, connector, resource_ref, target_marker, label_suffix
        );
    }

    let child_prefix = if is_root {
        prefix.to_string()
    } else if is_last {
        format!("{}   ", prefix)
    } else {
        format!("{}│  ", prefix)
    };

    for (i, child) in node.children.iter().enumerate() {
        let child_is_last = i == node.children.len() - 1 && !has_trailing;
        print_tree(child, &child_prefix, child_is_last, false, opts);
    }

    for (i, sref) in node.spec_refs.iter().enumerate() {
        let is_last_item = i == node.spec_refs.len() - 1 && !has_incoming;
        let ref_connector = if is_last_item { "└╌ " } else { "├╌ " };
        println!(
            "{}{}\x1b[36m{}/{}\x1b[0m  \x1b[2m(via {})\x1b[0m",
            child_prefix, ref_connector, sref.target_kind, sref.target_name, sref.field_path
        );
    }

    for (i, iref) in node.incoming_refs.iter().enumerate() {
        let is_last_item = i == node.incoming_refs.len() - 1;
        let ref_connector = if is_last_item { "└╌ " } else { "├╌ " };
        println!(
            "{}{}\x1b[35m◁ {}/{}\x1b[0m  \x1b[2m(via {})\x1b[0m",
            child_prefix, ref_connector, iref.source_kind, iref.source_name, iref.field_path
        );
    }
}

pub fn count_nodes(node: &TreeNode) -> usize {
    1 + node.children.iter().map(count_nodes).sum::<usize>()
}

pub fn print_chain_tree(chain: &[ResourceInfo], opts: &TreeDisplayOpts) {
    for (i, info) in chain.iter().enumerate() {
        let indent = if i == 0 {
            String::new()
        } else {
            format!("{}└─ ", "   ".repeat(i - 1))
        };
        let marker = if i == chain.len() - 1 {
            "  \x1b[1;33m◀ target\x1b[0m"
        } else {
            ""
        };
        let resource_ref = format!("{}/{}", info.kind, info.name);
        let label_suffix = format_label_suffix(info, opts);
        if i == chain.len() - 1 {
            println!(
                "{}\x1b[1;32m{}\x1b[0m{}{}",
                indent, resource_ref, marker, label_suffix
            );
        } else {
            println!("{}{}{}{}", indent, resource_ref, marker, label_suffix);
        }
    }
}
