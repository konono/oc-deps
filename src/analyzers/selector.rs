use std::collections::BTreeMap;

use kube::{
    Client,
    api::{Api, ApiResource, DynamicObject, ListParams},
    core::GroupVersion,
};

use crate::kube::discovery::{GroupKindMap, KindMap};
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
pub struct ServicePort {
    pub port: u16,
    pub target_port: String,
    pub protocol: String,
}

#[derive(Clone, Debug)]
pub struct NetworkService {
    pub name: String,
    pub selector: BTreeMap<String, String>,
    pub cluster_ip: String,
    pub svc_type: String,
    pub ports: Vec<ServicePort>,
}

#[derive(Clone, Debug)]
pub struct NetworkIngress {
    pub kind: String,
    pub name: String,
    pub backend_service: String,
    pub host: Option<String>,
    pub path: Option<String>,
    pub tls: Option<String>,
}

#[derive(Clone, Debug)]
pub struct NetworkPath {
    pub service: NetworkService,
    pub ingresses: Vec<NetworkIngress>,
}

pub struct NetworkInventory {
    pub services: Vec<NetworkService>,
    pub ingresses: Vec<NetworkIngress>,
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
                    let spec = obj.data.get("spec");
                    let cluster_ip = spec
                        .and_then(|s| s.get("clusterIP"))
                        .and_then(|v| v.as_str())
                        .unwrap_or("None")
                        .to_string();
                    let svc_type = spec
                        .and_then(|s| s.get("type"))
                        .and_then(|v| v.as_str())
                        .unwrap_or("ClusterIP")
                        .to_string();
                    let ports = spec
                        .and_then(|s| s.get("ports"))
                        .and_then(|p| p.as_array())
                        .map(|arr| {
                            arr.iter()
                                .filter_map(|p| {
                                    let port = p.get("port")?.as_u64()? as u16;
                                    let target_port = p
                                        .get("targetPort")
                                        .map(|v| match v {
                                            serde_json::Value::Number(n) => n.to_string(),
                                            serde_json::Value::String(s) => s.clone(),
                                            _ => "?".into(),
                                        })
                                        .unwrap_or_else(|| port.to_string());
                                    let protocol = p
                                        .get("protocol")
                                        .and_then(|v| v.as_str())
                                        .unwrap_or("TCP")
                                        .to_string();
                                    Some(ServicePort {
                                        port,
                                        target_port,
                                        protocol,
                                    })
                                })
                                .collect()
                        })
                        .unwrap_or_default();
                    Some(NetworkService {
                        name,
                        selector,
                        cluster_ip,
                        svc_type,
                        ports,
                    })
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

fn extract_ingress_refs(ingress_name: &str, data: &serde_json::Value) -> Vec<NetworkIngress> {
    let mut refs = Vec::new();
    let Some(spec) = data.get("spec") else {
        return refs;
    };
    let tls_hosts: std::collections::HashSet<String> = spec
        .get("tls")
        .and_then(|t| t.as_array())
        .map(|arr| {
            arr.iter()
                .flat_map(|t| {
                    t.get("hosts")
                        .and_then(|h| h.as_array())
                        .into_iter()
                        .flatten()
                        .filter_map(|h| h.as_str().map(String::from))
                })
                .collect()
        })
        .unwrap_or_default();

    if let Some(svc) = spec
        .get("defaultBackend")
        .and_then(|b| b.get("service"))
        .and_then(|s| s.get("name"))
        .and_then(|n| n.as_str())
    {
        refs.push(NetworkIngress {
            kind: "Ingress".into(),
            name: ingress_name.into(),
            backend_service: svc.into(),
            host: None,
            path: None,
            tls: None,
        });
    }
    if let Some(rules) = spec.get("rules").and_then(|r| r.as_array()) {
        for rule in rules {
            let host = rule.get("host").and_then(|h| h.as_str()).map(String::from);
            let tls = host
                .as_ref()
                .filter(|h| tls_hosts.contains(h.as_str()))
                .map(|_| "TLS".to_string());
            if let Some(paths) = rule
                .get("http")
                .and_then(|h| h.get("paths"))
                .and_then(|p| p.as_array())
            {
                for p in paths {
                    if let Some(svc) = p
                        .get("backend")
                        .and_then(|b| b.get("service"))
                        .and_then(|s| s.get("name"))
                        .and_then(|n| n.as_str())
                    {
                        let path = p.get("path").and_then(|v| v.as_str()).map(String::from);
                        refs.push(NetworkIngress {
                            kind: "Ingress".into(),
                            name: ingress_name.into(),
                            backend_service: svc.into(),
                            host: host.clone(),
                            path,
                            tls: tls.clone(),
                        });
                    }
                }
            }
        }
    }
    refs
}

fn extract_route_refs(route_name: &str, data: &serde_json::Value) -> Vec<NetworkIngress> {
    let mut refs = Vec::new();
    let Some(spec) = data.get("spec") else {
        return refs;
    };
    let host = spec.get("host").and_then(|h| h.as_str()).map(String::from);
    let path = spec.get("path").and_then(|p| p.as_str()).map(String::from);
    let tls = spec
        .get("tls")
        .and_then(|t| t.get("termination"))
        .and_then(|t| t.as_str())
        .map(String::from);

    if let Some(to_name) = spec
        .get("to")
        .and_then(|t| t.get("name"))
        .and_then(|n| n.as_str())
    {
        refs.push(NetworkIngress {
            kind: "Route".into(),
            name: route_name.into(),
            backend_service: to_name.into(),
            host: host.clone(),
            path: path.clone(),
            tls: tls.clone(),
        });
    }
    if let Some(alts) = spec.get("alternateBackends").and_then(|a| a.as_array()) {
        for alt in alts {
            if let Some(name) = alt.get("name").and_then(|n| n.as_str()) {
                refs.push(NetworkIngress {
                    kind: "Route".into(),
                    name: route_name.into(),
                    backend_service: name.into(),
                    host: host.clone(),
                    path: path.clone(),
                    tls: tls.clone(),
                });
            }
        }
    }
    refs
}

async fn list_ingresses(
    client: &Client,
    namespace: &str,
    gk_map: &GroupKindMap,
) -> (Vec<NetworkIngress>, Vec<ScanWarning>) {
    let mut result = Vec::new();
    let mut warnings = Vec::new();

    if let Some(info) = gk_map.get(&("networking.k8s.io".to_string(), "Ingress".to_string())) {
        let gvk = GroupVersion::gv(&info.group, &info.version).with_kind("Ingress");
        let ar = ApiResource::from_gvk_with_plural(&gvk, &info.plural);
        let api: Api<DynamicObject> = Api::namespaced_with(client.clone(), namespace, &ar);
        match api.list(&ListParams::default()).await {
            Ok(list) => {
                for obj in list.items {
                    if let Some(name) = obj.metadata.name {
                        result.extend(extract_ingress_refs(&name, &obj.data));
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

    if let Some(info) = gk_map.get(&("route.openshift.io".to_string(), "Route".to_string())) {
        let gvk = GroupVersion::gv(&info.group, &info.version).with_kind("Route");
        let ar = ApiResource::from_gvk_with_plural(&gvk, &info.plural);
        let api: Api<DynamicObject> = Api::namespaced_with(client.clone(), namespace, &ar);
        match api.list(&ListParams::default()).await {
            Ok(list) => {
                for obj in list.items {
                    if let Some(name) = obj.metadata.name {
                        result.extend(extract_route_refs(&name, &obj.data));
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

pub async fn build_network_inventory(
    client: &Client,
    namespace: &str,
    kind_map: &KindMap,
    gk_map: &GroupKindMap,
) -> NetworkInventory {
    let mut warnings = Vec::new();

    let services = match list_services(client, namespace, kind_map).await {
        Ok(svcs) => svcs,
        Err(w) => {
            warnings.push(w);
            vec![]
        }
    };

    let (ingresses, ing_warnings) = list_ingresses(client, namespace, gk_map).await;
    warnings.extend(ing_warnings);

    NetworkInventory {
        services,
        ingresses,
        warnings,
    }
}

pub fn find_network_paths(
    pod_labels: &std::collections::HashMap<String, String>,
    inventory: &NetworkInventory,
) -> Vec<NetworkPath> {
    let matching_services: Vec<&NetworkService> = inventory
        .services
        .iter()
        .filter(|svc| {
            svc.selector
                .iter()
                .all(|(k, v)| pod_labels.get(k) == Some(v))
        })
        .collect();

    matching_services
        .into_iter()
        .map(|svc| {
            let matching_ingresses: Vec<NetworkIngress> = inventory
                .ingresses
                .iter()
                .filter(|ing| ing.backend_service == svc.name)
                .cloned()
                .collect();
            NetworkPath {
                service: svc.clone(),
                ingresses: matching_ingresses,
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ingress_per_backend_with_host_path_tls() {
        let data = serde_json::json!({
            "spec": {
                "defaultBackend": {
                    "service": { "name": "svc-default", "port": { "number": 80 } }
                },
                "tls": [{ "hosts": ["second.example.test"] }],
                "rules": [
                    {
                        "host": "first.example.test",
                        "http": {
                            "paths": [{
                                "backend": { "service": { "name": "svc-first" } },
                                "path": "/first"
                            }]
                        }
                    },
                    {
                        "host": "second.example.test",
                        "http": {
                            "paths": [{
                                "backend": { "service": { "name": "svc-second" } },
                                "path": "/second"
                            }]
                        }
                    }
                ]
            }
        });
        let refs = extract_ingress_refs("my-ingress", &data);
        assert_eq!(refs.len(), 3);

        let default = &refs[0];
        assert_eq!(default.backend_service, "svc-default");
        assert!(default.host.is_none());
        assert!(default.path.is_none());
        assert!(default.tls.is_none());

        let first = &refs[1];
        assert_eq!(first.backend_service, "svc-first");
        assert_eq!(first.host.as_deref(), Some("first.example.test"));
        assert_eq!(first.path.as_deref(), Some("/first"));
        assert!(first.tls.is_none(), "first host not in TLS hosts");

        let second = &refs[2];
        assert_eq!(second.backend_service, "svc-second");
        assert_eq!(second.host.as_deref(), Some("second.example.test"));
        assert_eq!(second.path.as_deref(), Some("/second"));
        assert_eq!(
            second.tls.as_deref(),
            Some("TLS"),
            "second host in TLS hosts"
        );
    }

    #[test]
    fn route_primary_and_alternate() {
        let data = serde_json::json!({
            "spec": {
                "host": "app.example.com",
                "path": "/api",
                "to": { "kind": "Service", "name": "main-svc" },
                "tls": { "termination": "edge" },
                "alternateBackends": [
                    { "kind": "Service", "name": "canary-svc" }
                ]
            }
        });
        let refs = extract_route_refs("my-route", &data);
        assert_eq!(refs.len(), 2);
        assert_eq!(refs[0].backend_service, "main-svc");
        assert_eq!(refs[0].host.as_deref(), Some("app.example.com"));
        assert_eq!(refs[0].path.as_deref(), Some("/api"));
        assert_eq!(refs[0].tls.as_deref(), Some("edge"));
        assert_eq!(refs[1].backend_service, "canary-svc");
    }

    #[test]
    fn ingress_no_default_backend() {
        let data = serde_json::json!({
            "spec": {
                "rules": [{
                    "host": "only.example.test",
                    "http": {
                        "paths": [{
                            "backend": { "service": { "name": "only-svc" } },
                            "path": "/"
                        }]
                    }
                }]
            }
        });
        let refs = extract_ingress_refs("test", &data);
        assert_eq!(refs.len(), 1);
        assert_eq!(refs[0].backend_service, "only-svc");
        assert_eq!(refs[0].host.as_deref(), Some("only.example.test"));
    }

    #[test]
    fn empty_spec_returns_no_refs() {
        let data = serde_json::json!({});
        assert!(extract_ingress_refs("test", &data).is_empty());
        assert!(extract_route_refs("test", &data).is_empty());
    }

    #[test]
    fn find_paths_matches_service_selector() {
        let inventory = NetworkInventory {
            services: vec![
                NetworkService {
                    name: "svc-a".into(),
                    selector: [("app".into(), "x".into())].into_iter().collect(),
                    cluster_ip: "10.0.0.1".into(),
                    svc_type: "ClusterIP".into(),
                    ports: vec![],
                },
                NetworkService {
                    name: "svc-b".into(),
                    selector: [("app".into(), "y".into())].into_iter().collect(),
                    cluster_ip: "10.0.0.2".into(),
                    svc_type: "ClusterIP".into(),
                    ports: vec![],
                },
            ],
            ingresses: vec![NetworkIngress {
                kind: "Route".into(),
                name: "route-a".into(),
                backend_service: "svc-a".into(),
                host: Some("a.example.com".into()),
                path: None,
                tls: None,
            }],
            warnings: vec![],
        };
        let labels: std::collections::HashMap<String, String> =
            [("app".into(), "x".into())].into_iter().collect();
        let paths = find_network_paths(&labels, &inventory);
        assert_eq!(paths.len(), 1);
        assert_eq!(paths[0].service.name, "svc-a");
        assert_eq!(paths[0].ingresses.len(), 1);
        assert_eq!(paths[0].ingresses[0].name, "route-a");
    }

    #[test]
    fn find_paths_no_match() {
        let inventory = NetworkInventory {
            services: vec![NetworkService {
                name: "svc-a".into(),
                selector: [("app".into(), "x".into())].into_iter().collect(),
                cluster_ip: "10.0.0.1".into(),
                svc_type: "ClusterIP".into(),
                ports: vec![],
            }],
            ingresses: vec![],
            warnings: vec![],
        };
        let labels: std::collections::HashMap<String, String> =
            [("app".into(), "z".into())].into_iter().collect();
        let paths = find_network_paths(&labels, &inventory);
        assert!(paths.is_empty());
    }
}
