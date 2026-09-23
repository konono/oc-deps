use crate::graph::tree::TreeNode;
use crate::kube::resource::{EXCLUDED_ANNOTATION_KEYS, ResourceInfo};

const MAX_ANNOTATION_VALUE_CHARS: usize = 80;

#[derive(Default)]
pub struct TreeDisplayOpts {
    pub show_labels: bool,
    pub show_annotations: bool,
}

fn sanitize_value(v: &str) -> String {
    let cleaned: String = v
        .chars()
        .map(|c| match c {
            '\n' | '\r' | '\t' => ' ',
            _ => c,
        })
        .collect();
    if cleaned.chars().count() > MAX_ANNOTATION_VALUE_CHARS {
        let truncated: String = cleaned
            .chars()
            .take(MAX_ANNOTATION_VALUE_CHARS - 3)
            .collect();
        format!("{}...", truncated)
    } else {
        cleaned
    }
}

fn format_metadata_lines(
    info: &ResourceInfo,
    child_prefix: &str,
    opts: &TreeDisplayOpts,
) -> Vec<String> {
    let mut lines = Vec::new();
    if !opts.show_labels && !opts.show_annotations {
        return lines;
    }

    if opts.show_labels && !info.labels.is_empty() {
        let mut labels: Vec<_> = info.labels.iter().collect();
        labels.sort_by_key(|(k, _)| (*k).clone());
        lines.push(format!(
            "{}│  \x1b[2mlabels ({})\x1b[0m",
            child_prefix,
            labels.len()
        ));
        for (k, v) in &labels {
            lines.push(format!("{}│    \x1b[2m{}={}\x1b[0m", child_prefix, k, v));
        }
    }

    if opts.show_annotations {
        let mut anns: Vec<_> = info
            .annotations
            .iter()
            .filter(|(k, _)| !EXCLUDED_ANNOTATION_KEYS.contains(&k.as_str()))
            .collect();
        anns.sort_by_key(|(k, _)| (*k).clone());
        if !anns.is_empty() {
            lines.push(format!(
                "{}│  \x1b[2;35mannotations ({})\x1b[0m",
                child_prefix,
                anns.len()
            ));
            for (k, v) in &anns {
                lines.push(format!(
                    "{}│    \x1b[2;35m{}={}\x1b[0m",
                    child_prefix,
                    k,
                    sanitize_value(v)
                ));
            }
        }
    }

    lines
}

fn print_metadata_block(info: &ResourceInfo, child_prefix: &str, opts: &TreeDisplayOpts) {
    for line in format_metadata_lines(info, child_prefix, opts) {
        println!("{}", line);
    }
}

pub fn print_tree(
    node: &TreeNode,
    prefix: &str,
    is_last: bool,
    is_root: bool,
    opts: &TreeDisplayOpts,
) {
    let has_incoming = !node.incoming_refs.is_empty();
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

    print_metadata_block(&node.info, &child_prefix, opts);

    let has_children = !node.children.is_empty();

    for (i, sref) in node.spec_refs.iter().enumerate() {
        let is_last_item = i == node.spec_refs.len() - 1 && !has_children && !has_incoming;
        let ref_connector = if is_last_item { "└╌ " } else { "├╌ " };
        println!(
            "{}{}\x1b[36m{}/{}\x1b[0m  \x1b[2m(via {})\x1b[0m",
            child_prefix, ref_connector, sref.target_kind, sref.target_name, sref.field_path
        );
    }

    for (i, child) in node.children.iter().enumerate() {
        let child_is_last = i == node.children.len() - 1 && !has_incoming;
        print_tree(child, &child_prefix, child_is_last, false, opts);
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
        if i == chain.len() - 1 {
            println!("{}\x1b[1;32m{}\x1b[0m{}", indent, resource_ref, marker);
        } else {
            println!("{}{}{}", indent, resource_ref, marker);
        }

        let child_prefix = if i == 0 {
            String::new()
        } else {
            "   ".repeat(i)
        };
        print_metadata_block(info, &child_prefix, opts);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn make_info(
        labels: HashMap<String, String>,
        annotations: HashMap<String, String>,
    ) -> ResourceInfo {
        ResourceInfo {
            kind: "Deployment".into(),
            name: "test".into(),
            namespace: Some("ns".into()),
            uid: "uid-1".into(),
            owner_refs: vec![],
            labels,
            annotations,
        }
    }

    #[test]
    fn empty_labels_no_header() {
        let info = make_info(HashMap::new(), HashMap::new());
        let opts = TreeDisplayOpts {
            show_labels: true,
            show_annotations: false,
        };
        let lines = format_metadata_lines(&info, "", &opts);
        assert!(lines.is_empty(), "empty labels should produce no lines");
    }

    #[test]
    fn nonempty_labels_has_header_and_entries() {
        let mut labels = HashMap::new();
        labels.insert("app".into(), "test".into());
        labels.insert("tier".into(), "frontend".into());
        let info = make_info(labels, HashMap::new());
        let opts = TreeDisplayOpts {
            show_labels: true,
            show_annotations: false,
        };
        let lines = format_metadata_lines(&info, "", &opts);
        assert!(lines[0].contains("labels (2)"));
        assert!(lines.iter().any(|l| l.contains("app=test")));
        assert!(lines.iter().any(|l| l.contains("tier=frontend")));
    }

    #[test]
    fn flags_off_produces_no_lines() {
        let mut labels = HashMap::new();
        labels.insert("app".into(), "test".into());
        let info = make_info(labels, HashMap::new());
        let opts = TreeDisplayOpts::default();
        let lines = format_metadata_lines(&info, "", &opts);
        assert!(lines.is_empty());
    }

    #[test]
    fn annotations_sanitize_and_truncate() {
        let mut anns = HashMap::new();
        anns.insert("note".into(), "line1\nline2\ttab".into());
        anns.insert("long".into(), "x".repeat(100));
        let info = make_info(HashMap::new(), anns);
        let opts = TreeDisplayOpts {
            show_labels: false,
            show_annotations: true,
        };
        let lines = format_metadata_lines(&info, "", &opts);
        assert!(lines[0].contains("annotations (2)"));
        let long_line = lines.iter().find(|l| l.contains("long=")).unwrap();
        assert!(long_line.contains("..."));
        assert!(!long_line.contains('\n'));
        let note_line = lines.iter().find(|l| l.contains("note=")).unwrap();
        assert!(note_line.contains("line1 line2 tab"));
    }

    #[test]
    fn excluded_annotations_not_shown() {
        let mut anns = HashMap::new();
        anns.insert(
            "kubectl.kubernetes.io/last-applied-configuration".into(),
            "{}".into(),
        );
        anns.insert("visible".into(), "yes".into());
        let info = make_info(HashMap::new(), anns);
        let opts = TreeDisplayOpts {
            show_labels: false,
            show_annotations: true,
        };
        let lines = format_metadata_lines(&info, "", &opts);
        assert!(lines[0].contains("annotations (1)"));
        assert!(lines.iter().any(|l| l.contains("visible=yes")));
        assert!(!lines.iter().any(|l| l.contains("last-applied")));
    }

    #[test]
    fn metadata_lines_use_tree_connector() {
        let mut labels = HashMap::new();
        labels.insert("app".into(), "v".into());
        let info = make_info(labels, HashMap::new());
        let opts = TreeDisplayOpts {
            show_labels: true,
            show_annotations: false,
        };
        let lines = format_metadata_lines(&info, "│  ", &opts);
        for line in &lines {
            assert!(
                line.starts_with("│  │"),
                "metadata line should use │ connector: {}",
                line
            );
        }
    }
}
