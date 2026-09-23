use std::collections::BTreeMap;

use kube::{
    Client,
    api::{Api, ApiResource, DynamicObject, ListParams},
    core::GroupVersion,
};

use crate::kube::discovery::KindMap;
use crate::kube::resource::ScanWarning;

pub async fn get_service_selected_pods(
    client: &Client,
    name: &str,
    namespace: &str,
    kind_map: &KindMap,
) -> Vec<String> {
    let svc_info = match kind_map.get("Service") {
        Some(i) => i,
        None => return vec![],
    };

    let gvk = GroupVersion::gv(&svc_info.group, &svc_info.version).with_kind("Service");
    let ar = ApiResource::from_gvk_with_plural(&gvk, &svc_info.plural);
    let api: Api<DynamicObject> = Api::namespaced_with(client.clone(), namespace, &ar);

    let svc = match api.get(name).await {
        Ok(s) => s,
        Err(_) => return vec![],
    };

    let selector = match svc
        .data
        .get("spec")
        .and_then(|s| s.get("selector"))
        .and_then(|s| s.as_object())
    {
        Some(s) => s,
        None => return vec![],
    };

    let selector_str = selector
        .iter()
        .filter_map(|(k, v)| v.as_str().map(|val| format!("{}={}", k, val)))
        .collect::<Vec<_>>()
        .join(",");

    if selector_str.is_empty() {
        return vec![];
    }

    let pod_info = match kind_map.get("Pod") {
        Some(i) => i,
        None => return vec![],
    };

    let pod_gvk = GroupVersion::gv(&pod_info.group, &pod_info.version).with_kind("Pod");
    let pod_ar = ApiResource::from_gvk_with_plural(&pod_gvk, &pod_info.plural);
    let pod_api: Api<DynamicObject> = Api::namespaced_with(client.clone(), namespace, &pod_ar);

    match pod_api
        .list(&ListParams::default().labels(&selector_str))
        .await
    {
        Ok(pods) => pods
            .items
            .into_iter()
            .filter_map(|p| p.metadata.name)
            .map(|n| format!("Pod/{}", n))
            .collect(),
        Err(_) => vec![],
    }
}

// ──────────────────────────────────────────────────────────────
//  Network reverse lookup: Pod → Service → Ingress/Route
// ──────────────────────────────────────────────────────────────

#[derive(Clone, Debug)]
pub struct NetworkService {
    pub name: String,
    pub selector: BTreeMap<String, String>,
}

#[derive(Clone, Debug)]
pub struct NetworkIngress {
    pub kind: String,
    pub name: String,
    pub backend_services: Vec<String>,
}

#[derive(Clone, Debug)]
pub struct NetworkPath {
    pub service: NetworkService,
    pub ingresses: Vec<NetworkIngress>,
}

pub struct NetworkLookupResult {
    pub paths: Vec<NetworkPath>,
    pub warnings: Vec<ScanWarning>,
}

async fn list_services(
    client: &Client,
    namespace: &str,
    kind_map: &KindMap,
) -> Result<Vec<NetworkService>, ScanWarning> {
    let svc_info = match kind_map.get("Service") {
        Some(i) => i,
        None => return Ok(vec![]),
    };
    let gvk = GroupVersion::gv(&svc_info.group, &svc_info.version).with_kind("Service");
    let ar = ApiResource::from_gvk_with_plural(&gvk, &svc_info.plural);
    let api: Api<DynamicObject> = Api::namespaced_with(client.clone(), namespace, &ar);

    match api.list(&ListParams::default()).await {
        Ok(list) => {
            let services = list
                .items
                .into_iter()
                .filter_map(|obj| {
                    let name = obj.metadata.name?;
                    let selector = obj
                        .data
                        .get("spec")
                        .and_then(|s| s.get("selector"))
                        .and_then(|s| s.as_object())
                        .map(|m| {
                            m.iter()
                                .filter_map(|(k, v)| {
                                    v.as_str().map(|val| (k.clone(), val.to_string()))
                                })
                                .collect::<BTreeMap<_, _>>()
                        })
                        .unwrap_or_default();
                    if selector.is_empty() {
                        return None;
                    }
                    Some(NetworkService { name, selector })
                })
                .collect();
            Ok(services)
        }
        Err(e) => Err(ScanWarning::from_kube_error(
            &e,
            &svc_info.group,
            &svc_info.version,
            &svc_info.plural,
        )),
    }
}

fn extract_ingress_backends(data: &serde_json::Value) -> Vec<String> {
    let mut backends = Vec::new();
    if let Some(spec) = data.get("spec") {
        if let Some(default_backend) = spec
            .get("defaultBackend")
            .and_then(|b| b.get("service"))
            .and_then(|s| s.get("name"))
            .and_then(|n| n.as_str())
        {
            backends.push(default_backend.to_string());
        }
        if let Some(rules) = spec.get("rules").and_then(|r| r.as_array()) {
            for rule in rules {
                if let Some(paths) = rule
                    .get("http")
                    .and_then(|h| h.get("paths"))
                    .and_then(|p| p.as_array())
                {
                    for path in paths {
                        if let Some(svc_name) = path
                            .get("backend")
                            .and_then(|b| b.get("service"))
                            .and_then(|s| s.get("name"))
                            .and_then(|n| n.as_str())
                            && !backends.contains(&svc_name.to_string())
                        {
                            backends.push(svc_name.to_string());
                        }
                    }
                }
            }
        }
    }
    backends
}

fn extract_route_backends(data: &serde_json::Value) -> Vec<String> {
    let mut backends = Vec::new();
    if let Some(spec) = data.get("spec") {
        if let Some(to_name) = spec
            .get("to")
            .and_then(|t| t.get("name"))
            .and_then(|n| n.as_str())
        {
            backends.push(to_name.to_string());
        }
        if let Some(alts) = spec.get("alternateBackends").and_then(|a| a.as_array()) {
            for alt in alts {
                if let Some(name) = alt.get("name").and_then(|n| n.as_str())
                    && !backends.contains(&name.to_string())
                {
                    backends.push(name.to_string());
                }
            }
        }
    }
    backends
}

async fn list_ingresses(
    client: &Client,
    namespace: &str,
    kind_map: &KindMap,
) -> (Vec<NetworkIngress>, Vec<ScanWarning>) {
    let mut result = Vec::new();
    let mut warnings = Vec::new();

    if let Some(info) = kind_map.get("Ingress") {
        let gvk = GroupVersion::gv(&info.group, &info.version).with_kind("Ingress");
        let ar = ApiResource::from_gvk_with_plural(&gvk, &info.plural);
        let api: Api<DynamicObject> = Api::namespaced_with(client.clone(), namespace, &ar);
        match api.list(&ListParams::default()).await {
            Ok(list) => {
                for obj in list.items {
                    if let Some(name) = obj.metadata.name {
                        let backends = extract_ingress_backends(&obj.data);
                        if !backends.is_empty() {
                            result.push(NetworkIngress {
                                kind: "Ingress".into(),
                                name,
                                backend_services: backends,
                            });
                        }
                    }
                }
            }
            Err(e) => {
                warnings.push(ScanWarning::from_kube_error(
                    &e,
                    &info.group,
                    &info.version,
                    &info.plural,
                ));
            }
        }
    }

    if let Some(info) = kind_map.get("Route") {
        let gvk = GroupVersion::gv(&info.group, &info.version).with_kind("Route");
        let ar = ApiResource::from_gvk_with_plural(&gvk, &info.plural);
        let api: Api<DynamicObject> = Api::namespaced_with(client.clone(), namespace, &ar);
        match api.list(&ListParams::default()).await {
            Ok(list) => {
                for obj in list.items {
                    if let Some(name) = obj.metadata.name {
                        let backends = extract_route_backends(&obj.data);
                        if !backends.is_empty() {
                            result.push(NetworkIngress {
                                kind: "Route".into(),
                                name,
                                backend_services: backends,
                            });
                        }
                    }
                }
            }
            Err(e) => {
                warnings.push(ScanWarning::from_kube_error(
                    &e,
                    &info.group,
                    &info.version,
                    &info.plural,
                ));
            }
        }
    }

    (result, warnings)
}

pub async fn find_network_paths(
    client: &Client,
    pod_labels: &std::collections::HashMap<String, String>,
    namespace: &str,
    kind_map: &KindMap,
) -> NetworkLookupResult {
    let mut all_warnings = Vec::new();

    let services = match list_services(client, namespace, kind_map).await {
        Ok(svcs) => svcs,
        Err(w) => {
            all_warnings.push(w);
            vec![]
        }
    };

    let matching_services: Vec<NetworkService> = services
        .into_iter()
        .filter(|svc| {
            svc.selector
                .iter()
                .all(|(k, v)| pod_labels.get(k) == Some(v))
        })
        .collect();

    let (ingresses, ing_warnings) = list_ingresses(client, namespace, kind_map).await;
    all_warnings.extend(ing_warnings);

    let paths = matching_services
        .into_iter()
        .map(|svc| {
            let matching_ingresses: Vec<NetworkIngress> = ingresses
                .iter()
                .filter(|ing| ing.backend_services.contains(&svc.name))
                .cloned()
                .collect();
            NetworkPath {
                service: svc,
                ingresses: matching_ingresses,
            }
        })
        .collect();

    NetworkLookupResult {
        paths,
        warnings: all_warnings,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extract_ingress_backends_rules_and_default() {
        let data = serde_json::json!({
            "spec": {
                "defaultBackend": {
                    "service": { "name": "default-svc", "port": { "number": 80 } }
                },
                "rules": [{
                    "http": {
                        "paths": [{
                            "backend": {
                                "service": { "name": "path-svc", "port": { "number": 8080 } }
                            },
                            "path": "/api"
                        }]
                    }
                }]
            }
        });
        let backends = extract_ingress_backends(&data);
        assert_eq!(backends, vec!["default-svc", "path-svc"]);
    }

    #[test]
    fn extract_ingress_backends_no_default() {
        let data = serde_json::json!({
            "spec": {
                "rules": [{
                    "http": {
                        "paths": [{
                            "backend": {
                                "service": { "name": "only-svc" }
                            }
                        }]
                    }
                }]
            }
        });
        let backends = extract_ingress_backends(&data);
        assert_eq!(backends, vec!["only-svc"]);
    }

    #[test]
    fn extract_route_backends_with_alternates() {
        let data = serde_json::json!({
            "spec": {
                "to": { "kind": "Service", "name": "main-svc" },
                "alternateBackends": [
                    { "kind": "Service", "name": "canary-svc" }
                ]
            }
        });
        let backends = extract_route_backends(&data);
        assert_eq!(backends, vec!["main-svc", "canary-svc"]);
    }

    #[test]
    fn extract_route_backends_primary_only() {
        let data = serde_json::json!({
            "spec": {
                "to": { "kind": "Service", "name": "primary-svc" }
            }
        });
        let backends = extract_route_backends(&data);
        assert_eq!(backends, vec!["primary-svc"]);
    }

    #[test]
    fn extract_ingress_dedup_backends() {
        let data = serde_json::json!({
            "spec": {
                "defaultBackend": {
                    "service": { "name": "svc-a" }
                },
                "rules": [{
                    "http": {
                        "paths": [{
                            "backend": { "service": { "name": "svc-a" } }
                        }]
                    }
                }]
            }
        });
        let backends = extract_ingress_backends(&data);
        assert_eq!(backends, vec!["svc-a"]);
    }

    #[test]
    fn empty_spec_returns_no_backends() {
        let data = serde_json::json!({});
        assert!(extract_ingress_backends(&data).is_empty());
        assert!(extract_route_backends(&data).is_empty());
    }
}
