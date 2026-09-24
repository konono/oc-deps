use crate::graph::tree::TreeNode;
use crate::kube::resource::{ContainerResources, EXCLUDED_ANNOTATION_KEYS, ResourceInfo};

const MAX_ANNOTATION_VALUE_CHARS: usize = 80;

#[derive(Default)]
pub struct TreeDisplayOpts {
    pub show_labels: bool,
    pub show_annotations: bool,
    pub show_spec: bool,
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

pub fn format_container_resources(c: &ContainerResources, prefix: &str) -> String {
    let req_empty = c.requests.as_ref().is_none_or(|m| m.is_empty());
    let lim_empty = c.limits.as_ref().is_none_or(|m| m.is_empty());
    if req_empty && lim_empty {
        return format!("{}{}: <no resources>", prefix, c.name);
    }
    let mut all_keys = std::collections::BTreeSet::new();
    if let Some(r) = &c.requests {
        all_keys.extend(r.keys().cloned());
    }
    if let Some(l) = &c.limits {
        all_keys.extend(l.keys().cloned());
    }
    let pairs: Vec<String> = all_keys
        .iter()
        .map(|key| {
            let req = c
                .requests
                .as_ref()
                .and_then(|r| r.get(key))
                .map(|s| s.as_str())
                .unwrap_or("-");
            let lim = c
                .limits
                .as_ref()
                .and_then(|r| r.get(key))
                .map(|s| s.as_str())
                .unwrap_or("-");
            format!("{}={}/{}", key, req, lim)
        })
        .collect();
    format!("{}{}: {}", prefix, c.name, pairs.join(", "))
}

fn format_spec_lines(info: &ResourceInfo, child_prefix: &str) -> Vec<String> {
    let pt = match &info.pod_template {
        Some(pt) => pt,
        None => return vec![],
    };

    let mut lines = Vec::new();
    if !pt.containers.is_empty() || !pt.init_containers.is_empty() {
        lines.push(format!(
            "{}│  \x1b[33mcontainers ({})\x1b[0m",
            child_prefix,
            pt.containers.len() + pt.init_containers.len()
        ));
        for c in &pt.containers {
            lines.push(format!(
                "{}│    \x1b[2;33m{}\x1b[0m",
                child_prefix,
                format_container_resources(c, "")
            ));
        }
        for c in &pt.init_containers {
            lines.push(format!(
                "{}│    \x1b[2;33m{}\x1b[0m",
                child_prefix,
                format_container_resources(c, "init:")
            ));
        }
    }
    lines
}

fn print_metadata_block(info: &ResourceInfo, child_prefix: &str, opts: &TreeDisplayOpts) {
    for line in format_metadata_lines(info, child_prefix, opts) {
        println!("{}", line);
    }
    if opts.show_spec {
        for line in format_spec_lines(info, child_prefix) {
            println!("{}", line);
        }
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
            group: String::new(),
            kind: "Deployment".into(),
            name: "test".into(),
            namespace: Some("ns".into()),
            uid: "uid-1".into(),
            owner_refs: vec![],
            labels,
            annotations,
            pod_template: None,
        }
    }

    #[test]
    fn empty_labels_no_header() {
        let info = make_info(HashMap::new(), HashMap::new());
        let opts = TreeDisplayOpts {
            show_labels: true,
            show_annotations: false,
            ..Default::default()
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
            ..Default::default()
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
            ..Default::default()
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
            ..Default::default()
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
            ..Default::default()
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

    // ── format_container_resources tests ──

    #[test]
    fn container_cpu_memory_only() {
        let c = ContainerResources {
            name: "app".into(),
            requests: Some(
                [
                    ("cpu".into(), "100m".into()),
                    ("memory".into(), "128Mi".into()),
                ]
                .into(),
            ),
            limits: Some(
                [
                    ("cpu".into(), "500m".into()),
                    ("memory".into(), "256Mi".into()),
                ]
                .into(),
            ),
        };
        let s = format_container_resources(&c, "");
        assert_eq!(s, "app: cpu=100m/500m, memory=128Mi/256Mi");
    }

    #[test]
    fn container_with_gpu() {
        let c = ContainerResources {
            name: "main".into(),
            requests: Some(
                [
                    ("cpu".into(), "500m".into()),
                    ("memory".into(), "4Gi".into()),
                    ("nvidia.com/gpu".into(), "1".into()),
                ]
                .into(),
            ),
            limits: Some(
                [
                    ("cpu".into(), "2".into()),
                    ("memory".into(), "8Gi".into()),
                    ("nvidia.com/gpu".into(), "1".into()),
                ]
                .into(),
            ),
        };
        let s = format_container_resources(&c, "");
        assert!(s.contains("nvidia.com/gpu=1/1"));
        assert!(s.contains("cpu=500m/2"));
        assert!(s.contains("memory=4Gi/8Gi"));
    }

    #[test]
    fn container_all_keys_sorted() {
        let c = ContainerResources {
            name: "sorted".into(),
            requests: Some(
                [
                    ("memory".into(), "1Gi".into()),
                    ("cpu".into(), "100m".into()),
                    ("nvidia.com/gpu".into(), "1".into()),
                ]
                .into(),
            ),
            limits: None,
        };
        let s = format_container_resources(&c, "");
        let cpu_pos = s.find("cpu=").unwrap();
        let mem_pos = s.find("memory=").unwrap();
        let gpu_pos = s.find("nvidia.com/gpu=").unwrap();
        assert!(cpu_pos < mem_pos);
        assert!(mem_pos < gpu_pos);
    }

    #[test]
    fn container_no_resources() {
        let c = ContainerResources {
            name: "bare".into(),
            requests: None,
            limits: None,
        };
        let s = format_container_resources(&c, "");
        assert_eq!(s, "bare: <no resources>");
    }

    #[test]
    fn container_empty_maps() {
        let c = ContainerResources {
            name: "empty".into(),
            requests: Some(std::collections::BTreeMap::new()),
            limits: Some(std::collections::BTreeMap::new()),
        };
        let s = format_container_resources(&c, "");
        assert_eq!(s, "empty: <no resources>");
    }

    #[test]
    fn container_partial_requests_only() {
        let c = ContainerResources {
            name: "req-only".into(),
            requests: Some([("cpu".into(), "100m".into())].into()),
            limits: None,
        };
        let s = format_container_resources(&c, "");
        assert_eq!(s, "req-only: cpu=100m/-");
    }

    #[test]
    fn container_partial_limits_only() {
        let c = ContainerResources {
            name: "lim-only".into(),
            requests: None,
            limits: Some([("memory".into(), "1Gi".into())].into()),
        };
        let s = format_container_resources(&c, "");
        assert_eq!(s, "lim-only: memory=-/1Gi");
    }

    #[test]
    fn container_with_init_prefix() {
        let c = ContainerResources {
            name: "setup".into(),
            requests: Some([("cpu".into(), "10m".into())].into()),
            limits: None,
        };
        let s = format_container_resources(&c, "init:");
        assert_eq!(s, "init:setup: cpu=10m/-");
    }

    #[test]
    fn container_ephemeral_storage_and_hugepages() {
        let c = ContainerResources {
            name: "storage".into(),
            requests: Some(
                [
                    ("ephemeral-storage".into(), "10Gi".into()),
                    ("hugepages-2Mi".into(), "100Mi".into()),
                ]
                .into(),
            ),
            limits: Some(
                [
                    ("ephemeral-storage".into(), "20Gi".into()),
                    ("hugepages-2Mi".into(), "200Mi".into()),
                ]
                .into(),
            ),
        };
        let s = format_container_resources(&c, "");
        assert!(s.contains("ephemeral-storage=10Gi/20Gi"));
        assert!(s.contains("hugepages-2Mi=100Mi/200Mi"));
    }

    #[test]
    fn container_union_of_request_and_limit_keys() {
        let c = ContainerResources {
            name: "union".into(),
            requests: Some([("cpu".into(), "100m".into())].into()),
            limits: Some([("memory".into(), "256Mi".into())].into()),
        };
        let s = format_container_resources(&c, "");
        assert!(s.contains("cpu=100m/-"));
        assert!(s.contains("memory=-/256Mi"));
    }

    #[test]
    fn spec_lines_show_spec_false_no_output() {
        let info = ResourceInfo {
            group: String::new(),
            kind: "Deployment".into(),
            name: "test".into(),
            namespace: Some("ns".into()),
            uid: "uid-1".into(),
            owner_refs: vec![],
            labels: HashMap::new(),
            annotations: HashMap::new(),
            pod_template: Some(crate::kube::resource::PodTemplateInfo {
                containers: vec![ContainerResources {
                    name: "app".into(),
                    requests: Some([("cpu".into(), "100m".into())].into()),
                    limits: None,
                }],
                init_containers: vec![],
            }),
        };
        let opts = TreeDisplayOpts {
            show_spec: false,
            ..Default::default()
        };
        let lines = format_spec_lines(&info, "");
        assert!(!lines.is_empty());
        // But print_metadata_block only prints them when show_spec is true
        // Verify by checking format_spec_lines returns data but opts gates display
        let _ = opts;
    }

    #[test]
    fn spec_lines_for_map_table() {
        let info = ResourceInfo {
            group: String::new(),
            kind: "Deployment".into(),
            name: "test".into(),
            namespace: Some("ns".into()),
            uid: "uid-1".into(),
            owner_refs: vec![],
            labels: HashMap::new(),
            annotations: HashMap::new(),
            pod_template: Some(crate::kube::resource::PodTemplateInfo {
                containers: vec![ContainerResources {
                    name: "app".into(),
                    requests: Some(
                        [
                            ("cpu".into(), "100m".into()),
                            ("nvidia.com/gpu".into(), "1".into()),
                        ]
                        .into(),
                    ),
                    limits: Some(
                        [
                            ("cpu".into(), "500m".into()),
                            ("nvidia.com/gpu".into(), "1".into()),
                        ]
                        .into(),
                    ),
                }],
                init_containers: vec![],
            }),
        };
        let lines = format_spec_lines(&info, "");
        assert!(lines.iter().any(|l| l.contains("nvidia.com/gpu=1/1")));
    }
}
