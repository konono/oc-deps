use crate::graph::tree::TreeNode;
use crate::kube::resource::ResourceInfo;

pub fn print_tree(node: &TreeNode, prefix: &str, is_last: bool, is_root: bool) {
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

    if node.is_target {
        println!(
            "{}{}\x1b[1;32m{}\x1b[0m{}",
            prefix, connector, resource_ref, target_marker
        );
    } else {
        println!("{}{}{}{}", prefix, connector, resource_ref, target_marker);
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
        print_tree(child, &child_prefix, child_is_last, false);
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

pub fn print_chain_tree(chain: &[ResourceInfo]) {
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
        if i == chain.len() - 1 {
            println!("{}\x1b[1;32m{}\x1b[0m{}", indent, resource_ref, marker);
        } else {
            println!("{}{}{}", indent, resource_ref, marker);
        }
    }
}
