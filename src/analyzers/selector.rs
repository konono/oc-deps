use std::collections::BTreeMap;

use kube::{
    Client,
    api::{Api, ApiResource, DynamicObject, ListParams},
    core::GroupVersion,
};

use crate::kube::discovery::{GroupKindMap, KindMap};
use crate::kube::resource::ScanWarning;

const MAX_RETRIES: usize = 2;
const REQUEST_TIMEOUT_SECS: u64 = 30;

pub async fn list_with_retry_and_timeout(
    api: &Api<DynamicObject>,
    group: &str,
    version: &str,
    plural: &str,
) -> std::result::Result<Vec<DynamicObject>, ScanWarning> {
    let gvr = if group.is_empty() {
        format!("{}/{}", version, plural)
    } else {
        format!("{}/{}/{}", group, version, plural)
    };
    for attempt in 0..=MAX_RETRIES {
        let timeout_dur = std::time::Duration::from_secs(REQUEST_TIMEOUT_SECS);
        match tokio::time::timeout(timeout_dur, api.list(&ListParams::default())).await {
            Ok(Ok(list)) => return Ok(list.items),
            Ok(Err(e)) => {
                let warning = ScanWarning::from_kube_error(&e, group, version, plural);
                if warning.is_retryable() && attempt < MAX_RETRIES {
                    let delay = std::time::Duration::from_millis(500 * (attempt as u64 + 1));
                    tokio::time::sleep(delay).await;
                    continue;
                }
                let mut w = ScanWarning::from_kube_error(&e, group, version, plural);
                w.set_retries(attempt);
                return Err(w);
            }
            Err(_elapsed) => {
                if attempt < MAX_RETRIES {
                    let delay = std::time::Duration::from_millis(500 * (attempt as u64 + 1));
                    tokio::time::sleep(delay).await;
                    continue;
                }
                return Err(ScanWarning::Timeout {
                    gvr: gvr.clone(),
                    message: Some(format!("LIST timeout ({}s)", REQUEST_TIMEOUT_SECS)),
                    retries: attempt,
                });
            }
        }
    }
    Err(ScanWarning::Other {
        gvr,
        message: "exhausted retries".to_string(),
    })
}

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
    pub node_port: Option<u16>,
}

#[derive(Clone, Debug)]
pub struct NetworkService {
    pub name: String,
    pub selector: BTreeMap<String, String>,
    pub cluster_ip: String,
    pub svc_type: String,
    pub ports: Vec<ServicePort>,
    pub external_ips: Vec<String>,
    pub ip_families: Vec<String>,
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
pub struct EndpointInfo {
    pub addresses: Vec<String>,
    pub port: Option<u16>,
    pub protocol: Option<String>,
    pub ready: Option<bool>,
    pub hostname: Option<String>,
    pub node_name: Option<String>,
    pub zone: Option<String>,
    pub target_ref_name: Option<String>,
    pub target_ref_uid: Option<String>,
    pub target_ref_kind: Option<String>,
}

#[derive(Clone, Debug)]
pub struct EndpointSliceInfo {
    pub name: String,
    pub address_type: String,
    pub endpoints: Vec<EndpointInfo>,
}

#[derive(Clone, Debug)]
pub struct NetworkPath {
    pub service: NetworkService,
    pub selector_matched_pods: Vec<String>,
    pub target_ref_matched_pods: Vec<String>,
    pub endpoint_slices: Vec<EndpointSliceInfo>,
    pub ingresses: Vec<NetworkIngress>,
}

pub struct NetworkInventory {
    pub services: Vec<NetworkService>,
    pub ingresses: Vec<NetworkIngress>,
    pub endpoint_slices: Vec<EndpointSliceInfo>,
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

    match list_with_retry_and_timeout(&api, &svc_info.group, &svc_info.version, &svc_info.plural)
        .await
    {
        Ok(items) => {
            let services = items
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
                    let spec = obj.data.get("spec");
                    let cluster_ip = spec
                        .and_then(|s| s.get("clusterIP"))
                        .and_then(|v| v.as_str())
                        .unwrap_or("None")
                        .to_string();
                    let mut svc_type = spec
                        .and_then(|s| s.get("type"))
                        .and_then(|v| v.as_str())
                        .unwrap_or("ClusterIP")
                        .to_string();
                    if cluster_ip == "None" && svc_type == "ClusterIP" {
                        svc_type = "Headless".to_string();
                    }
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
                                    let node_port = p
                                        .get("nodePort")
                                        .and_then(|v| v.as_u64())
                                        .map(|n| n as u16);
                                    Some(ServicePort {
                                        port,
                                        target_port,
                                        protocol,
                                        node_port,
                                    })
                                })
                                .collect()
                        })
                        .unwrap_or_default();
                    let external_ips = spec
                        .and_then(|s| s.get("externalIPs"))
                        .and_then(|v| v.as_array())
                        .map(|arr| {
                            arr.iter()
                                .filter_map(|v| v.as_str().map(String::from))
                                .collect()
                        })
                        .unwrap_or_default();
                    let ip_families = spec
                        .and_then(|s| s.get("ipFamilies"))
                        .and_then(|v| v.as_array())
                        .map(|arr| {
                            arr.iter()
                                .filter_map(|v| v.as_str().map(String::from))
                                .collect()
                        })
                        .unwrap_or_default();
                    Some(NetworkService {
                        name,
                        selector,
                        cluster_ip,
                        svc_type,
                        ports,
                        external_ips,
                        ip_families,
                    })
                })
                .collect();
            Ok(services)
        }
        Err(w) => Err(w),
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

async fn list_endpoint_slices(
    client: &Client,
    namespace: &str,
    gk_map: &GroupKindMap,
) -> (Vec<EndpointSliceInfo>, Vec<ScanWarning>) {
    let mut slices = Vec::new();
    let mut warnings = Vec::new();

    let info = match gk_map.get(&("discovery.k8s.io".to_string(), "EndpointSlice".to_string())) {
        Some(i) => i,
        None => return (slices, warnings),
    };

    let gvk = GroupVersion::gv(&info.group, &info.version).with_kind("EndpointSlice");
    let ar = ApiResource::from_gvk_with_plural(&gvk, &info.plural);
    let api: Api<DynamicObject> = Api::namespaced_with(client.clone(), namespace, &ar);

    match api.list(&ListParams::default()).await {
        Ok(list) => {
            for obj in list.items {
                let name = match obj.metadata.name {
                    Some(n) => n,
                    None => continue,
                };
                let address_type = obj
                    .data
                    .get("addressType")
                    .and_then(|v| v.as_str())
                    .unwrap_or("IPv4")
                    .to_string();

                let ep_ports: Vec<(Option<u16>, Option<String>)> = obj
                    .data
                    .get("ports")
                    .and_then(|v| v.as_array())
                    .map(|arr| {
                        arr.iter()
                            .map(|p| {
                                let port = p.get("port").and_then(|v| v.as_u64()).map(|n| n as u16);
                                let protocol =
                                    p.get("protocol").and_then(|v| v.as_str()).map(String::from);
                                (port, protocol)
                            })
                            .collect()
                    })
                    .unwrap_or_default();

                let endpoints = obj
                    .data
                    .get("endpoints")
                    .and_then(|v| v.as_array())
                    .map(|arr| {
                        arr.iter()
                            .flat_map(|ep| {
                                let addresses: Vec<String> = ep
                                    .get("addresses")
                                    .and_then(|v| v.as_array())
                                    .map(|a| {
                                        a.iter()
                                            .filter_map(|v| v.as_str().map(String::from))
                                            .collect()
                                    })
                                    .unwrap_or_default();
                                let ready = ep
                                    .get("conditions")
                                    .and_then(|c| c.get("ready"))
                                    .and_then(|v| v.as_bool());
                                let hostname = ep
                                    .get("hostname")
                                    .and_then(|v| v.as_str())
                                    .map(String::from);
                                let node_name = ep
                                    .get("nodeName")
                                    .and_then(|v| v.as_str())
                                    .map(String::from);
                                let zone =
                                    ep.get("zone").and_then(|v| v.as_str()).map(String::from);
                                let target_ref = ep.get("targetRef");
                                let target_ref_name = target_ref
                                    .and_then(|t| t.get("name"))
                                    .and_then(|v| v.as_str())
                                    .map(String::from);
                                let target_ref_uid = target_ref
                                    .and_then(|t| t.get("uid"))
                                    .and_then(|v| v.as_str())
                                    .map(String::from);
                                let target_ref_kind = target_ref
                                    .and_then(|t| t.get("kind"))
                                    .and_then(|v| v.as_str())
                                    .map(String::from);

                                if ep_ports.is_empty() {
                                    vec![EndpointInfo {
                                        addresses: addresses.clone(),
                                        port: None,
                                        protocol: None,
                                        ready,
                                        hostname: hostname.clone(),
                                        node_name: node_name.clone(),
                                        zone: zone.clone(),
                                        target_ref_name: target_ref_name.clone(),
                                        target_ref_uid: target_ref_uid.clone(),
                                        target_ref_kind: target_ref_kind.clone(),
                                    }]
                                } else {
                                    ep_ports
                                        .iter()
                                        .map(|(port, protocol)| EndpointInfo {
                                            addresses: addresses.clone(),
                                            port: *port,
                                            protocol: protocol.clone(),
                                            ready,
                                            hostname: hostname.clone(),
                                            node_name: node_name.clone(),
                                            zone: zone.clone(),
                                            target_ref_name: target_ref_name.clone(),
                                            target_ref_uid: target_ref_uid.clone(),
                                            target_ref_kind: target_ref_kind.clone(),
                                        })
                                        .collect()
                                }
                            })
                            .collect()
                    })
                    .unwrap_or_default();

                slices.push(EndpointSliceInfo {
                    name,
                    address_type,
                    endpoints,
                });
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

    (slices, warnings)
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

    let (endpoint_slices, eps_warnings) = list_endpoint_slices(client, namespace, gk_map).await;
    warnings.extend(eps_warnings);

    NetworkInventory {
        services,
        ingresses,
        endpoint_slices,
        warnings,
    }
}

/// Find network paths for a set of pods.
///
/// `pod_entries` is a slice of `(name, uid, labels)` tuples.
/// Each Service is matched against individual pod labels rather than merged labels,
/// so only pods whose labels actually satisfy the selector are included.
pub fn find_network_paths(
    pod_entries: &[(String, String, std::collections::HashMap<String, String>)],
    inventory: &NetworkInventory,
) -> Vec<NetworkPath> {
    let pod_uids: std::collections::HashSet<&str> =
        pod_entries.iter().map(|(_, uid, _)| uid.as_str()).collect();

    inventory
        .services
        .iter()
        .filter_map(|svc| {
            // Find pods whose labels match the service selector
            let selector_matched: Vec<String> = pod_entries
                .iter()
                .filter(|(_, _, labels)| {
                    !svc.selector.is_empty()
                        && svc.selector.iter().all(|(k, v)| labels.get(k) == Some(v))
                })
                .map(|(name, _, _)| name.clone())
                .collect();

            // Find EndpointSlices whose kubernetes.io/service-name label matches this service
            // and collect those with targetRef pointing to our pods
            let mut matched_slices = Vec::new();
            let mut target_ref_pods = Vec::new();
            for slice in &inventory.endpoint_slices {
                // EndpointSlice names typically start with the service name
                // We match by checking endpoints' targetRef UIDs against our pod UIDs
                let mut has_match = false;
                for ep in &slice.endpoints {
                    if let Some(ref uid) = ep.target_ref_uid
                        && pod_uids.contains(uid.as_str())
                    {
                        has_match = true;
                        if let Some(ref name) = ep.target_ref_name {
                            target_ref_pods.push(name.clone());
                        }
                    }
                }
                if has_match {
                    matched_slices.push(slice.clone());
                }
            }

            target_ref_pods.sort();
            target_ref_pods.dedup();

            if selector_matched.is_empty() && target_ref_pods.is_empty() {
                return None;
            }

            let matching_ingresses: Vec<NetworkIngress> = inventory
                .ingresses
                .iter()
                .filter(|ing| ing.backend_service == svc.name)
                .cloned()
                .collect();

            Some(NetworkPath {
                service: svc.clone(),
                selector_matched_pods: selector_matched,
                target_ref_matched_pods: target_ref_pods,
                endpoint_slices: matched_slices,
                ingresses: matching_ingresses,
            })
        })
        .collect()
}

pub fn network_path_to_json(path: &NetworkPath) -> serde_json::Value {
    let ports: Vec<_> = path
        .service
        .ports
        .iter()
        .map(|sp| {
            let mut obj = serde_json::json!({
                "port": sp.port,
                "targetPort": sp.target_port,
                "protocol": sp.protocol,
            });
            if let Some(np) = sp.node_port {
                obj["nodePort"] = serde_json::json!(np);
            }
            obj
        })
        .collect();

    let ingresses: Vec<_> = path
        .ingresses
        .iter()
        .map(|i| {
            let mut obj = serde_json::json!({
                "kind": i.kind,
                "name": i.name,
            });
            if let Some(h) = &i.host {
                obj["host"] = serde_json::json!(h);
            }
            if let Some(pa) = &i.path {
                obj["path"] = serde_json::json!(pa);
            }
            if let Some(t) = &i.tls {
                obj["tls"] = serde_json::json!(t);
            }
            obj
        })
        .collect();

    let endpoint_slices: Vec<_> = path
        .endpoint_slices
        .iter()
        .map(|es| {
            let endpoints: Vec<_> = es
                .endpoints
                .iter()
                .map(|ep| {
                    let mut obj = serde_json::json!({
                        "addresses": ep.addresses,
                    });
                    if let Some(p) = ep.port {
                        obj["port"] = serde_json::json!(p);
                    }
                    if let Some(ref proto) = ep.protocol {
                        obj["protocol"] = serde_json::json!(proto);
                    }
                    if let Some(r) = ep.ready {
                        obj["ready"] = serde_json::json!(r);
                    }
                    if let Some(ref h) = ep.hostname {
                        obj["hostname"] = serde_json::json!(h);
                    }
                    if let Some(ref n) = ep.node_name {
                        obj["nodeName"] = serde_json::json!(n);
                    }
                    if let Some(ref z) = ep.zone {
                        obj["zone"] = serde_json::json!(z);
                    }
                    if let Some(ref name) = ep.target_ref_name {
                        obj["targetRefName"] = serde_json::json!(name);
                    }
                    if let Some(ref uid) = ep.target_ref_uid {
                        obj["targetRefUID"] = serde_json::json!(uid);
                    }
                    if let Some(ref kind) = ep.target_ref_kind {
                        obj["targetRefKind"] = serde_json::json!(kind);
                    }
                    obj
                })
                .collect();
            serde_json::json!({
                "name": es.name,
                "addressType": es.address_type,
                "endpoints": endpoints,
            })
        })
        .collect();

    // Endpoint summary
    let total_endpoints: usize = path
        .endpoint_slices
        .iter()
        .map(|es| es.endpoints.len())
        .sum();
    let ready_count = path
        .endpoint_slices
        .iter()
        .flat_map(|es| &es.endpoints)
        .filter(|ep| ep.ready == Some(true))
        .count();
    let not_ready_count = path
        .endpoint_slices
        .iter()
        .flat_map(|es| &es.endpoints)
        .filter(|ep| ep.ready == Some(false))
        .count();
    let unknown_count = total_endpoints - ready_count - not_ready_count;

    let svc = &path.service;

    let mut config = serde_json::json!({
        "type": svc.svc_type,
        "clusterIP": svc.cluster_ip,
        "ports": ports,
        "selector": svc.selector,
        "hasSelector": !svc.selector.is_empty(),
    });
    if !svc.external_ips.is_empty() {
        config["externalIPs"] = serde_json::json!(svc.external_ips);
    }
    if !svc.ip_families.is_empty() {
        config["ipFamilies"] = serde_json::json!(svc.ip_families);
    }

    serde_json::json!({
        "service": {
            "name": svc.name,
            "config": config,
            "status": {},
        },
        "selectorMatchedPods": path.selector_matched_pods,
        "targetRefMatchedPods": path.target_ref_matched_pods,
        "endpointSlices": endpoint_slices,
        "endpointSummary": {
            "total": total_endpoints,
            "ready": ready_count,
            "notReady": not_ready_count,
            "unknown": unknown_count,
        },
        "ingresses": ingresses,
    })
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

    fn make_svc(
        name: &str,
        selector: &[(&str, &str)],
        svc_type: &str,
        cluster_ip: &str,
    ) -> NetworkService {
        NetworkService {
            name: name.into(),
            selector: selector
                .iter()
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect(),
            cluster_ip: cluster_ip.into(),
            svc_type: svc_type.into(),
            ports: vec![],
            external_ips: vec![],
            ip_families: vec![],
        }
    }

    fn make_inventory(
        services: Vec<NetworkService>,
        ingresses: Vec<NetworkIngress>,
    ) -> NetworkInventory {
        NetworkInventory {
            services,
            ingresses,
            endpoint_slices: vec![],
            warnings: vec![],
        }
    }

    #[test]
    fn find_paths_matches_service_selector() {
        let inventory = make_inventory(
            vec![
                make_svc("svc-a", &[("app", "x")], "ClusterIP", "10.0.0.1"),
                make_svc("svc-b", &[("app", "y")], "ClusterIP", "10.0.0.2"),
            ],
            vec![NetworkIngress {
                kind: "Route".into(),
                name: "route-a".into(),
                backend_service: "svc-a".into(),
                host: Some("a.example.com".into()),
                path: None,
                tls: None,
            }],
        );
        let pods = vec![(
            "pod-1".into(),
            "uid-1".into(),
            [("app".into(), "x".into())].into_iter().collect(),
        )];
        let paths = find_network_paths(&pods, &inventory);
        assert_eq!(paths.len(), 1);
        assert_eq!(paths[0].service.name, "svc-a");
        assert_eq!(paths[0].selector_matched_pods, vec!["pod-1"]);
        assert_eq!(paths[0].ingresses.len(), 1);
        assert_eq!(paths[0].ingresses[0].name, "route-a");
    }

    #[test]
    fn find_paths_no_match() {
        let inventory = make_inventory(
            vec![make_svc("svc-a", &[("app", "x")], "ClusterIP", "10.0.0.1")],
            vec![],
        );
        let pods = vec![(
            "pod-1".into(),
            "uid-1".into(),
            [("app".into(), "z".into())].into_iter().collect(),
        )];
        let paths = find_network_paths(&pods, &inventory);
        assert!(paths.is_empty());
    }

    #[test]
    fn service_type_classification() {
        // ClusterIP
        let svc = make_svc("s1", &[("a", "b")], "ClusterIP", "10.0.0.1");
        assert_eq!(svc.svc_type, "ClusterIP");

        // NodePort
        let svc = make_svc("s2", &[("a", "b")], "NodePort", "10.0.0.2");
        assert_eq!(svc.svc_type, "NodePort");

        // LoadBalancer
        let svc = make_svc("s3", &[("a", "b")], "LoadBalancer", "10.0.0.3");
        assert_eq!(svc.svc_type, "LoadBalancer");

        // Headless
        let svc = make_svc("s4", &[("a", "b")], "Headless", "None");
        assert_eq!(svc.svc_type, "Headless");

        // ExternalName
        let svc = make_svc("s5", &[("a", "b")], "ExternalName", "None");
        assert_eq!(svc.svc_type, "ExternalName");
    }

    #[test]
    fn load_balancer_status() {
        // This tests that NetworkPath JSON includes LB info when present
        let path = NetworkPath {
            service: NetworkService {
                name: "lb-svc".into(),
                selector: [("app".into(), "web".into())].into_iter().collect(),
                cluster_ip: "10.0.0.5".into(),
                svc_type: "LoadBalancer".into(),
                ports: vec![ServicePort {
                    port: 80,
                    target_port: "8080".into(),
                    protocol: "TCP".into(),
                    node_port: Some(31234),
                }],
                external_ips: vec![],
                ip_families: vec!["IPv4".into()],
            },
            selector_matched_pods: vec!["web-pod".into()],
            target_ref_matched_pods: vec![],
            endpoint_slices: vec![],
            ingresses: vec![],
        };
        let json = network_path_to_json(&path);
        assert_eq!(json["service"]["config"]["type"], "LoadBalancer");
        assert_eq!(json["service"]["config"]["ports"][0]["nodePort"], 31234);
    }

    #[test]
    fn endpoint_slice_api_absent() {
        // When GroupKindMap has no EndpointSlice entry, slices should be empty
        let inventory = make_inventory(
            vec![make_svc("svc", &[("app", "x")], "ClusterIP", "10.0.0.1")],
            vec![],
        );
        assert!(inventory.endpoint_slices.is_empty());
    }

    #[test]
    fn selectorless_uid_mismatch() {
        // EndpointSlice with targetRef UID that doesn't match any pod
        let inventory = NetworkInventory {
            services: vec![make_svc("svc", &[("app", "x")], "ClusterIP", "10.0.0.1")],
            ingresses: vec![],
            endpoint_slices: vec![EndpointSliceInfo {
                name: "svc-abc".into(),
                address_type: "IPv4".into(),
                endpoints: vec![EndpointInfo {
                    addresses: vec!["10.0.1.1".into()],
                    port: Some(80),
                    protocol: Some("TCP".into()),
                    ready: Some(true),
                    hostname: None,
                    node_name: None,
                    zone: None,
                    target_ref_name: Some("other-pod".into()),
                    target_ref_uid: Some("wrong-uid".into()),
                    target_ref_kind: Some("Pod".into()),
                }],
            }],
            warnings: vec![],
        };
        let pods = vec![(
            "my-pod".into(),
            "my-uid".into(),
            [("app".into(), "x".into())].into_iter().collect(),
        )];
        let paths = find_network_paths(&pods, &inventory);
        // Should match by selector but not by targetRef
        assert_eq!(paths.len(), 1);
        assert!(paths[0].endpoint_slices.is_empty());
        assert!(paths[0].target_ref_matched_pods.is_empty());
    }

    #[test]
    fn nodeport_in_service_port() {
        let sp = ServicePort {
            port: 80,
            target_port: "8080".into(),
            protocol: "TCP".into(),
            node_port: Some(31234),
        };
        assert_eq!(sp.node_port, Some(31234));
    }

    #[test]
    fn external_ips_and_ip_families() {
        let svc = NetworkService {
            name: "ext-svc".into(),
            selector: [("app".into(), "web".into())].into_iter().collect(),
            cluster_ip: "10.0.0.1".into(),
            svc_type: "ClusterIP".into(),
            ports: vec![],
            external_ips: vec!["1.2.3.4".into(), "5.6.7.8".into()],
            ip_families: vec!["IPv4".into(), "IPv6".into()],
        };
        assert_eq!(svc.external_ips, vec!["1.2.3.4", "5.6.7.8"]);
        assert_eq!(svc.ip_families, vec!["IPv4", "IPv6"]);

        // Verify JSON output includes them
        let path = NetworkPath {
            service: svc,
            selector_matched_pods: vec![],
            target_ref_matched_pods: vec![],
            endpoint_slices: vec![],
            ingresses: vec![],
        };
        let json = network_path_to_json(&path);
        assert_eq!(json["service"]["config"]["externalIPs"][0], "1.2.3.4");
        assert_eq!(json["service"]["config"]["ipFamilies"][1], "IPv6");
    }

    #[test]
    fn per_pod_selector_matching() {
        // Two pods with different labels; only one matches the service
        let inventory = make_inventory(
            vec![make_svc("svc", &[("app", "x")], "ClusterIP", "10.0.0.1")],
            vec![],
        );
        let pods = vec![
            (
                "pod-match".into(),
                "uid-1".into(),
                [("app".into(), "x".into())].into_iter().collect(),
            ),
            (
                "pod-no".into(),
                "uid-2".into(),
                [("app".into(), "y".into())].into_iter().collect(),
            ),
        ];
        let paths = find_network_paths(&pods, &inventory);
        assert_eq!(paths.len(), 1);
        assert_eq!(paths[0].selector_matched_pods, vec!["pod-match"]);
    }

    #[test]
    fn endpoint_info_fields() {
        let ep = EndpointInfo {
            addresses: vec!["10.0.1.1".into()],
            port: Some(8080),
            protocol: Some("TCP".into()),
            ready: Some(true),
            hostname: Some("pod-0".into()),
            node_name: Some("node-1".into()),
            zone: Some("us-east-1a".into()),
            target_ref_name: Some("pod-0".into()),
            target_ref_uid: Some("uid-123".into()),
            target_ref_kind: Some("Pod".into()),
        };
        assert_eq!(ep.hostname.as_deref(), Some("pod-0"));
        assert_eq!(ep.node_name.as_deref(), Some("node-1"));
        assert_eq!(ep.zone.as_deref(), Some("us-east-1a"));
    }

    #[test]
    fn json_config_status_separation() {
        let path = NetworkPath {
            service: NetworkService {
                name: "my-svc".into(),
                selector: [("app".into(), "web".into())].into_iter().collect(),
                cluster_ip: "10.0.0.1".into(),
                svc_type: "ClusterIP".into(),
                ports: vec![ServicePort {
                    port: 80,
                    target_port: "8080".into(),
                    protocol: "TCP".into(),
                    node_port: None,
                }],
                external_ips: vec![],
                ip_families: vec!["IPv4".into()],
            },
            selector_matched_pods: vec!["pod-1".into()],
            target_ref_matched_pods: vec![],
            endpoint_slices: vec![],
            ingresses: vec![],
        };
        let json = network_path_to_json(&path);
        // config/status separation
        assert!(json["service"]["config"].is_object());
        assert!(json["service"]["status"].is_object());
        assert_eq!(json["service"]["name"], "my-svc");
        assert_eq!(json["service"]["config"]["type"], "ClusterIP");
        assert_eq!(json["service"]["config"]["clusterIP"], "10.0.0.1");
        assert_eq!(json["service"]["config"]["hasSelector"], true);
        assert_eq!(json["selectorMatchedPods"][0], "pod-1");
        assert!(json["endpointSummary"]["total"].is_number());
    }

    // ── Mock retry tests for list_with_retry_and_timeout ──

    use kube::client::Body;
    use std::pin::pin;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    fn json_response(json: serde_json::Value) -> http::Response<Body> {
        http::Response::builder()
            .status(200)
            .body(Body::from(serde_json::to_vec(&json).unwrap()))
            .unwrap()
    }

    fn status_response(code: u16, reason: &str) -> http::Response<Body> {
        let body = serde_json::json!({
            "kind": "Status", "apiVersion": "v1", "metadata": {},
            "status": "Failure", "message": reason, "reason": reason, "code": code
        });
        http::Response::builder()
            .status(code)
            .body(Body::from(serde_json::to_vec(&body).unwrap()))
            .unwrap()
    }

    fn svc_list_response() -> http::Response<Body> {
        json_response(serde_json::json!({
            "apiVersion": "v1",
            "kind": "ServiceList",
            "metadata": {"resourceVersion": "1"},
            "items": [{
                "apiVersion": "v1",
                "kind": "Service",
                "metadata": {"name": "test-svc", "namespace": "default"}
            }]
        }))
    }

    #[tokio::test]
    async fn retry_403_no_retry() {
        let (mock_service, handle) =
            tower_test::mock::pair::<http::Request<Body>, http::Response<Body>>();
        let client = Client::new(mock_service, "default");
        let ar = ApiResource::from_gvk(&GroupVersion::gv("", "v1").with_kind("Service"));
        let api: Api<DynamicObject> = Api::namespaced_with(client, "default", &ar);
        let request_count = Arc::new(AtomicUsize::new(0));
        let rc = request_count.clone();

        let spawned = tokio::spawn(async move {
            let mut handle = pin!(handle);
            let (_req, send) = handle.next_request().await.expect("expected request");
            rc.fetch_add(1, Ordering::Relaxed);
            send.send_response(status_response(403, "Forbidden"));
        });

        let result = list_with_retry_and_timeout(&api, "", "v1", "services").await;
        spawned.await.unwrap();

        assert!(result.is_err(), "403 should fail");
        assert_eq!(
            request_count.load(Ordering::Relaxed),
            1,
            "403 should not retry"
        );
        let err = result.unwrap_err();
        assert!(
            matches!(err, ScanWarning::Forbidden { .. }),
            "should be Forbidden"
        );
    }

    #[tokio::test]
    async fn retry_500_persistent_3_requests() {
        let (mock_service, handle) =
            tower_test::mock::pair::<http::Request<Body>, http::Response<Body>>();
        let client = Client::new(mock_service, "default");
        let ar = ApiResource::from_gvk(&GroupVersion::gv("", "v1").with_kind("Service"));
        let api: Api<DynamicObject> = Api::namespaced_with(client, "default", &ar);
        let request_count = Arc::new(AtomicUsize::new(0));
        let rc = request_count.clone();

        let spawned = tokio::spawn(async move {
            let mut handle = pin!(handle);
            for _ in 0..3 {
                let (_req, send) = handle.next_request().await.expect("expected request");
                rc.fetch_add(1, Ordering::Relaxed);
                send.send_response(status_response(500, "Internal Server Error"));
            }
        });

        let result = list_with_retry_and_timeout(&api, "", "v1", "services").await;
        spawned.await.unwrap();

        assert!(result.is_err(), "persistent 500 should fail");
        assert_eq!(
            request_count.load(Ordering::Relaxed),
            3,
            "500 should retry — expected 3 requests (1 + 2 retries)"
        );
        let err = result.unwrap_err();
        assert!(
            matches!(err, ScanWarning::ServerError { retries: 2, .. }),
            "should be ServerError with 2 retries, got {:?}",
            err
        );
    }

    #[tokio::test]
    async fn retry_500_then_200_succeeds() {
        let (mock_service, handle) =
            tower_test::mock::pair::<http::Request<Body>, http::Response<Body>>();
        let client = Client::new(mock_service, "default");
        let ar = ApiResource::from_gvk(&GroupVersion::gv("", "v1").with_kind("Service"));
        let api: Api<DynamicObject> = Api::namespaced_with(client, "default", &ar);
        let request_count = Arc::new(AtomicUsize::new(0));
        let rc = request_count.clone();

        let spawned = tokio::spawn(async move {
            let mut handle = pin!(handle);
            // First: 500
            let (_req, send) = handle.next_request().await.unwrap();
            rc.fetch_add(1, Ordering::Relaxed);
            send.send_response(status_response(500, "Internal Server Error"));
            // Second: success
            let (_req, send) = handle.next_request().await.unwrap();
            rc.fetch_add(1, Ordering::Relaxed);
            send.send_response(svc_list_response());
        });

        let result = list_with_retry_and_timeout(&api, "", "v1", "services").await;
        spawned.await.unwrap();

        assert!(result.is_ok(), "should succeed after retry");
        let items = result.unwrap();
        assert_eq!(items.len(), 1);
        assert_eq!(
            request_count.load(Ordering::Relaxed),
            2,
            "500 then 200 = 2 requests"
        );
    }
}
