use crate::kube::resource::{SpecRef, dedup_spec_refs};

pub fn extract_well_known_refs(data: &serde_json::Value) -> Vec<SpecRef> {
    let mut refs = Vec::new();
    if let Some(spec) = data.get("spec") {
        let mut path = vec!["spec".to_string()];
        walk_for_well_known(spec, &mut path, &mut refs);
    }
    dedup_spec_refs(&mut refs);
    refs
}

fn walk_for_well_known(value: &serde_json::Value, path: &mut Vec<String>, refs: &mut Vec<SpecRef>) {
    match value {
        serde_json::Value::Object(map) => {
            for (key, val) in map {
                path.push(key.clone());
                match key.as_str() {
                    "secretKeyRef" => {
                        if let Some(name) = val.get("name").and_then(|n| n.as_str()) {
                            refs.push(SpecRef {
                                target_kind: "Secret".to_string(),
                                target_name: name.to_string(),
                                field_path: format!("{}.name", path.join(".")),
                            });
                        }
                    }
                    "configMapKeyRef" => {
                        if let Some(name) = val.get("name").and_then(|n| n.as_str()) {
                            refs.push(SpecRef {
                                target_kind: "ConfigMap".to_string(),
                                target_name: name.to_string(),
                                field_path: format!("{}.name", path.join(".")),
                            });
                        }
                    }
                    "configMapRef" => {
                        if let Some(name) = val.get("name").and_then(|n| n.as_str()) {
                            refs.push(SpecRef {
                                target_kind: "ConfigMap".to_string(),
                                target_name: name.to_string(),
                                field_path: format!("{}.name", path.join(".")),
                            });
                        }
                    }
                    "secretRef" => {
                        if let Some(name) = val.get("name").and_then(|n| n.as_str()) {
                            refs.push(SpecRef {
                                target_kind: "Secret".to_string(),
                                target_name: name.to_string(),
                                field_path: format!("{}.name", path.join(".")),
                            });
                        }
                    }
                    "serviceAccountName" => {
                        if let Some(name) = val.as_str()
                            && !name.is_empty()
                        {
                            refs.push(SpecRef {
                                target_kind: "ServiceAccount".to_string(),
                                target_name: name.to_string(),
                                field_path: path.join("."),
                            });
                        }
                    }
                    "configMap" if val.is_object() => {
                        if let Some(name) = val.get("name").and_then(|n| n.as_str()) {
                            refs.push(SpecRef {
                                target_kind: "ConfigMap".to_string(),
                                target_name: name.to_string(),
                                field_path: format!("{}.name", path.join(".")),
                            });
                        }
                    }
                    "secret" if val.is_object() => {
                        if let Some(name) = val.get("secretName").and_then(|n| n.as_str()) {
                            refs.push(SpecRef {
                                target_kind: "Secret".to_string(),
                                target_name: name.to_string(),
                                field_path: format!("{}.secretName", path.join(".")),
                            });
                        }
                    }
                    "persistentVolumeClaim" if val.is_object() => {
                        if let Some(name) = val.get("claimName").and_then(|n| n.as_str()) {
                            refs.push(SpecRef {
                                target_kind: "PersistentVolumeClaim".to_string(),
                                target_name: name.to_string(),
                                field_path: format!("{}.claimName", path.join(".")),
                            });
                        }
                    }
                    "imagePullSecrets" => {
                        if let Some(arr) = val.as_array() {
                            for (i, item) in arr.iter().enumerate() {
                                if let Some(name) = item.get("name").and_then(|n| n.as_str()) {
                                    refs.push(SpecRef {
                                        target_kind: "Secret".to_string(),
                                        target_name: name.to_string(),
                                        field_path: format!("{}[{}].name", path.join("."), i),
                                    });
                                }
                            }
                        }
                    }
                    "secretName" => {
                        if let Some(name) = val.as_str()
                            && !name.is_empty()
                        {
                            refs.push(SpecRef {
                                target_kind: "Secret".to_string(),
                                target_name: name.to_string(),
                                field_path: path.join("."),
                            });
                        }
                    }
                    _ => {}
                }

                if let Some(s) = val.as_str()
                    && let Some(rest) = s.strip_prefix("pvc://")
                {
                    let pvc_name = rest.split('/').next().unwrap_or(rest);
                    if !pvc_name.is_empty() {
                        refs.push(SpecRef {
                            target_kind: "PersistentVolumeClaim".to_string(),
                            target_name: pvc_name.to_string(),
                            field_path: path.join("."),
                        });
                    }
                }

                walk_for_well_known(val, path, refs);
                path.pop();
            }
        }
        serde_json::Value::Array(arr) => {
            for (i, item) in arr.iter().enumerate() {
                path.push(format!("[{}]", i));
                walk_for_well_known(item, path, refs);
                path.pop();
            }
        }
        _ => {}
    }
}

fn skip_subtree_for_heuristic(key: &str) -> bool {
    matches!(
        key,
        "labels"
            | "matchLabels"
            | "selector"
            | "annotations"
            | "matchExpressions"
            | "command"
            | "args"
            | "managedFields"
    )
}

fn skip_leaf_for_heuristic(key: &str) -> bool {
    matches!(
        key,
        "name"
            | "subdomain"
            | "containerPort"
            | "protocol"
            | "effect"
            | "operator"
            | "key"
            | "type"
            | "containerName"
            | "fieldPath"
            | "apiVersion"
            | "kind"
            | "generateName"
    )
}

pub fn collect_string_values(
    value: &serde_json::Value,
    path: &mut Vec<String>,
    out: &mut Vec<(String, String)>,
) {
    match value {
        serde_json::Value::String(s) => {
            if let Some(last_key) = path.last()
                && !last_key.starts_with('[')
                && skip_leaf_for_heuristic(last_key)
            {
                return;
            }
            out.push((path.join("."), s.clone()));
        }
        serde_json::Value::Object(map) => {
            for (key, val) in map {
                if skip_subtree_for_heuristic(key) {
                    continue;
                }
                path.push(key.clone());
                collect_string_values(val, path, out);
                path.pop();
            }
        }
        serde_json::Value::Array(arr) => {
            for (i, item) in arr.iter().enumerate() {
                path.push(format!("[{}]", i));
                collect_string_values(item, path, out);
                path.pop();
            }
        }
        _ => {}
    }
}
