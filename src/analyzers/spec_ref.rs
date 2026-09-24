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
                    "serviceAccountName" | "serviceAccount" => {
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
            | "serviceAccount"
            | "serviceAccountName"
            | "secretName"
            | "configMap"
            | "claimName"
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

#[cfg(test)]
mod tests {
    use super::*;

    fn deployment_spec_with_service_account(sa_name: &str) -> serde_json::Value {
        serde_json::json!({
            "spec": {
                "template": {
                    "spec": {
                        "serviceAccountName": sa_name,
                        "serviceAccount": sa_name,
                        "containers": [{
                            "name": "app",
                            "image": "registry.example.com/app:latest"
                        }]
                    }
                }
            }
        })
    }

    #[test]
    fn service_account_well_known_produces_single_ref() {
        let data = deployment_spec_with_service_account("rhods-dashboard");
        let refs = extract_well_known_refs(&data);
        let sa_refs: Vec<_> = refs
            .iter()
            .filter(|r| r.target_kind == "ServiceAccount")
            .collect();
        assert_eq!(sa_refs.len(), 1);
        assert_eq!(sa_refs[0].target_name, "rhods-dashboard");
    }

    #[test]
    fn service_account_not_in_heuristic() {
        let data = deployment_spec_with_service_account("rhods-dashboard");
        let spec = data.get("spec").unwrap();
        let mut strs = Vec::new();
        let mut path = vec!["spec".to_string()];
        collect_string_values(spec, &mut path, &mut strs);

        let sa_matches: Vec<_> = strs
            .iter()
            .filter(|(_, v)| v == "rhods-dashboard")
            .collect();
        assert!(
            sa_matches.is_empty(),
            "serviceAccount/serviceAccountName should be excluded from heuristic, found: {:?}",
            sa_matches
        );
    }

    #[test]
    fn secret_name_not_in_heuristic() {
        let data = serde_json::json!({
            "spec": {
                "volumes": [{
                    "name": "tls-vol",
                    "secret": {
                        "secretName": "my-tls-secret"
                    }
                }]
            }
        });
        let refs = extract_well_known_refs(&data);
        assert!(
            refs.iter()
                .any(|r| r.target_kind == "Secret" && r.target_name == "my-tls-secret")
        );

        let spec = data.get("spec").unwrap();
        let mut strs = Vec::new();
        let mut path = vec!["spec".to_string()];
        collect_string_values(spec, &mut path, &mut strs);
        let secret_matches: Vec<_> = strs.iter().filter(|(_, v)| v == "my-tls-secret").collect();
        assert!(
            secret_matches.is_empty(),
            "secretName should be excluded from heuristic"
        );
    }

    #[test]
    fn no_false_incoming_refs_from_service_account() {
        use crate::kube::resource::*;
        use std::collections::{HashMap, HashSet};

        let mut index = NamespaceIndex::new();
        index.insert(ResourceInfo {
            group: String::new(),
            kind: "Deployment".into(),
            name: "rhods-dashboard".into(),
            namespace: Some("test".into()),
            uid: "uid-deploy".into(),
            owner_refs: vec![],
            labels: HashMap::new(),
            annotations: HashMap::new(),
        });
        index.insert(ResourceInfo {
            group: String::new(),
            kind: "ServiceAccount".into(),
            name: "rhods-dashboard".into(),
            namespace: Some("test".into()),
            uid: "uid-sa".into(),
            owner_refs: vec![],
            labels: HashMap::new(),
            annotations: HashMap::new(),
        });
        index.insert(ResourceInfo {
            group: String::new(),
            kind: "Service".into(),
            name: "rhods-dashboard".into(),
            namespace: Some("test".into()),
            uid: "uid-svc".into(),
            owner_refs: vec![],
            labels: HashMap::new(),
            annotations: HashMap::new(),
        });
        index.insert(ResourceInfo {
            group: String::new(),
            kind: "Route".into(),
            name: "rhods-dashboard".into(),
            namespace: Some("test".into()),
            uid: "uid-route".into(),
            owner_refs: vec![],
            labels: HashMap::new(),
            annotations: HashMap::new(),
        });

        let data = deployment_spec_with_service_account("rhods-dashboard");
        let wk_refs = extract_well_known_refs(&data);
        let spec = data.get("spec").unwrap();
        let mut spec_strs = Vec::new();
        let mut path = vec!["spec".to_string()];
        collect_string_values(spec, &mut path, &mut spec_strs);

        let already_found: HashSet<(String, String)> = wk_refs
            .iter()
            .map(|r| (r.target_kind.clone(), r.target_name.clone()))
            .collect();

        let mut by_name: HashMap<String, Vec<String>> = HashMap::new();
        for info in index.by_uid.values() {
            by_name
                .entry(info.name.clone())
                .or_default()
                .push(info.kind.clone());
        }

        let heuristic = crate::kube::scanner::resolve_name_matches(
            &spec_strs,
            "rhods-dashboard",
            &by_name,
            &already_found,
        );

        assert!(
            heuristic.is_empty(),
            "No heuristic refs should be generated for serviceAccount field, got: {:?}",
            heuristic
                .iter()
                .map(|r| format!("{}/{}", r.target_kind, r.target_name))
                .collect::<Vec<_>>()
        );
    }
}
