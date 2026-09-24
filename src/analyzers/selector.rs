use std::collections::BTreeMap;

use kube::{
    Client,
    api::{Api, ApiResource, DynamicObject, ListParams},
    core::GroupVersion,
};

use crate::kube::discovery::{GroupKindMap, KindMap};
use crate::kube::resource::ScanWarning;

// ──────────────────────────────────────────────────────────────
//  Shared retry+timeout helper for all LIST calls
// ──────────────────────────────────────────────────────────────

pub(crate) async fn list_with_retry_and_timeout(
    api: &Api<DynamicObject>,
    group: &str,
    version: &str,
    plural: &str,
) -> Result<Vec<DynamicObject>, ScanWarning> {
    list_with_retry_inner(
        api,
        group,
        version,
        plural,
        std::time::Duration::from_secs(30),
    )
    .await
}

pub(crate) async fn list_with_retry_inner(
    api: &Api<DynamicObject>,
    group: &str,
    version: &str,
    plural: &str,
    timeout_dur: std::time::Duration,
) -> Result<Vec<DynamicObject>, ScanWarning> {
    let is_tty = std::io::IsTerminal::is_terminal(&std::io::stderr());
    for attempt in 0..=2usize {
        match tokio::time::timeout(timeout_dur, api.list(&ListParams::default())).await {
            Ok(Ok(list)) => return Ok(list.items),
            Ok(Err(e)) => {
                let warning = ScanWarning::from_kube_error(&e, group, version, plural);
                if warning.is_retryable() && attempt < 2 {
                    let delay = std::time::Duration::from_millis(500 * (attempt as u64 + 1));
                    let gvr = if group.is_empty() {
                        format!("{}/{}", version, plural)
                    } else {
                        format!("{}/{}/{}", group, version, plural)
                    };
                    if is_tty {
                        eprintln!(
                            "   \x1b[33m\u{26a0} {} \u{2014} LIST attempt {}/3 failed; retrying in {}ms\x1b[0m",
                            gvr,
                            attempt + 1,
                            delay.as_millis()
                        );
                    } else {
                        eprintln!(
                            "   \u{26a0} {} \u{2014} LIST attempt {}/3 failed; retrying in {}ms",
                            gvr,
                            attempt + 1,
                            delay.as_millis()
                        );
                    }
                    tokio::time::sleep(delay).await;
                    continue;
                }
                let mut w = ScanWarning::from_kube_error(&e, group, version, plural);
                w.set_retries(attempt);
                return Err(w);
            }
            Err(_) => {
                let gvr = if group.is_empty() {
                    format!("{}/{}", version, plural)
                } else {
                    format!("{}/{}/{}", group, version, plural)
                };
                if attempt < 2 {
                    let delay = std::time::Duration::from_millis(500 * (attempt as u64 + 1));
                    if is_tty {
                        eprintln!(
                            "   \x1b[33m\u{26a0} {} \u{2014} LIST timeout (30s), attempt {}/3; retrying\x1b[0m",
                            gvr,
                            attempt + 1
                        );
                    } else {
                        eprintln!(
                            "   \u{26a0} {} \u{2014} LIST timeout (30s), attempt {}/3; retrying",
                            gvr,
                            attempt + 1
                        );
                    }
                    tokio::time::sleep(delay).await;
                    continue;
                }
                return Err(ScanWarning::Timeout {
                    gvr,
                    message: Some("timeout (30s)".into()),
                    retries: attempt,
                });
            }
        }
    }
    unreachable!()
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
pub struct LBIngress {
    pub ip: Option<String>,
    pub hostname: Option<String>,
    pub ip_mode: Option<String>,
}

#[derive(Clone, Debug)]
pub struct NetworkService {
    pub name: String,
    pub selector: BTreeMap<String, String>,
    pub has_selector: bool,
    pub cluster_ip: String,
    pub svc_type: String,
    pub ports: Vec<ServicePort>,
    pub health_check_node_port: Option<u16>,
    pub internal_traffic_policy: Option<String>,
    pub ip_family_policy: Option<String>,
    pub load_balancer_class: Option<String>,
    pub allocate_lb_node_ports: Option<bool>,
    pub external_traffic_policy: Option<String>,
    pub external_ips: Vec<String>,
    pub ip_families: Vec<String>,
    pub lb_ingress: Vec<LBIngress>,
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

// ──────────────────────────────────────────────────────────────
//  EndpointSlice types
// ──────────────────────────────────────────────────────────────

#[derive(Clone, Debug)]
pub struct EndpointTargetRef {
    pub api_version: Option<String>,
    pub kind: Option<String>,
    pub name: Option<String>,
    pub namespace: Option<String>,
    pub uid: Option<String>,
}

#[derive(Clone, Debug)]
pub struct EndpointPort {
    pub name: Option<String>,
    pub port: Option<u16>,
    pub protocol: String,
    pub app_protocol: Option<String>,
}

#[derive(Clone, Debug)]
pub struct EndpointInfo {
    pub addresses: Vec<String>,
    pub hostname: Option<String>,
    pub node_name: Option<String>,
    pub zone: Option<String>,
    pub conditions_ready: Option<bool>,
    pub conditions_serving: Option<bool>,
    pub conditions_terminating: Option<bool>,
    pub target_ref: Option<EndpointTargetRef>,
    pub hints: Option<Vec<String>>,
}

#[derive(Clone, Debug)]
pub struct EndpointSliceInfo {
    pub name: String,
    pub service_name: Option<String>,
    pub address_type: String,
    pub ports: Vec<EndpointPort>,
    pub endpoints: Vec<EndpointInfo>,
}

#[derive(Clone, Debug, Default)]
pub struct EndpointSummary {
    pub ready: usize,
    pub not_ready: usize,
    pub unknown: usize,
    pub serving: usize,
    pub terminating: usize,
    pub effective_ready: usize,
}

impl EndpointSummary {
    pub fn from_slices(slices: &[EndpointSliceInfo]) -> Self {
        let mut s = EndpointSummary::default();
        for slice in slices {
            for ep in &slice.endpoints {
                match ep.conditions_ready {
                    Some(true) => s.ready += 1,
                    Some(false) => s.not_ready += 1,
                    None => s.unknown += 1,
                }
                if ep.conditions_serving == Some(true) {
                    s.serving += 1;
                }
                if ep.conditions_terminating == Some(true) {
                    s.terminating += 1;
                }
            }
        }
        // Per K8s spec: ready=None is treated as effectively ready
        s.effective_ready = s.ready + s.unknown;
        s
    }
}

#[derive(Clone, Debug)]
pub struct NetworkPath {
    pub service: NetworkService,
    pub ingresses: Vec<NetworkIngress>,
    pub endpoint_slices: Vec<EndpointSliceInfo>,
    pub endpoint_summary: EndpointSummary,
    pub selector_matched_pods: Vec<String>,
    pub target_ref_matched_pods: Vec<String>,
}

pub struct NetworkInventory {
    pub services: Vec<NetworkService>,
    pub ingresses: Vec<NetworkIngress>,
    pub endpoint_slices: Vec<EndpointSliceInfo>,
    pub warnings: Vec<ScanWarning>,
}

pub(crate) fn parse_service(obj: DynamicObject) -> Option<NetworkService> {
    let name = obj.metadata.name?;
    let spec = obj.data.get("spec");
    let status = obj.data.get("status");

    let selector = spec
        .and_then(|s| s.get("selector"))
        .and_then(|s| s.as_object())
        .map(|m| {
            m.iter()
                .filter_map(|(k, v)| v.as_str().map(|val| (k.clone(), val.to_string())))
                .collect::<BTreeMap<_, _>>()
        })
        .unwrap_or_default();
    let has_selector = !selector.is_empty();

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
                    let node_port = p.get("nodePort").and_then(|v| v.as_u64()).map(|v| v as u16);
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

    // Extra Service fields
    let health_check_node_port = spec
        .and_then(|s| s.get("healthCheckNodePort"))
        .and_then(|v| v.as_u64())
        .map(|v| v as u16);
    let internal_traffic_policy = spec
        .and_then(|s| s.get("internalTrafficPolicy"))
        .and_then(|v| v.as_str())
        .map(String::from);
    let ip_family_policy = spec
        .and_then(|s| s.get("ipFamilyPolicy"))
        .and_then(|v| v.as_str())
        .map(String::from);
    let load_balancer_class = spec
        .and_then(|s| s.get("loadBalancerClass"))
        .and_then(|v| v.as_str())
        .map(String::from);
    let allocate_lb_node_ports = spec
        .and_then(|s| s.get("allocateLoadBalancerNodePorts"))
        .and_then(|v| v.as_bool());
    let external_traffic_policy = spec
        .and_then(|s| s.get("externalTrafficPolicy"))
        .and_then(|v| v.as_str())
        .map(String::from);

    // LB ingress from status
    let lb_ingress = status
        .and_then(|s| s.get("loadBalancer"))
        .and_then(|lb| lb.get("ingress"))
        .and_then(|i| i.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|entry| {
                    let ip = entry.get("ip").and_then(|v| v.as_str()).map(String::from);
                    let hostname = entry
                        .get("hostname")
                        .and_then(|v| v.as_str())
                        .map(String::from);
                    let ip_mode = entry
                        .get("ipMode")
                        .and_then(|v| v.as_str())
                        .map(String::from);
                    if ip.is_some() || hostname.is_some() {
                        Some(LBIngress {
                            ip,
                            hostname,
                            ip_mode,
                        })
                    } else {
                        None
                    }
                })
                .collect::<Vec<_>>()
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

    let svc_type = if cluster_ip == "None" && svc_type == "ClusterIP" {
        "Headless".to_string()
    } else {
        svc_type
    };

    Some(NetworkService {
        name,
        selector,
        has_selector,
        cluster_ip,
        svc_type,
        ports,
        health_check_node_port,
        internal_traffic_policy,
        ip_family_policy,
        load_balancer_class,
        allocate_lb_node_ports,
        external_traffic_policy,
        external_ips,
        ip_families,
        lb_ingress,
    })
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

    let items =
        list_with_retry_and_timeout(&api, &svc_info.group, &svc_info.version, &svc_info.plural)
            .await?;
    Ok(items.into_iter().filter_map(parse_service).collect())
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

async fn list_endpoint_slices(
    client: &Client,
    namespace: &str,
    gk_map: &GroupKindMap,
) -> (Vec<EndpointSliceInfo>, Vec<ScanWarning>) {
    let mut result = Vec::new();
    let mut warnings = Vec::new();

    let key = ("discovery.k8s.io".to_string(), "EndpointSlice".to_string());
    let info = match gk_map.get(&key) {
        Some(i) => i,
        None => return (result, warnings),
    };

    let gvk = GroupVersion::gv(&info.group, &info.version).with_kind("EndpointSlice");
    let ar = ApiResource::from_gvk_with_plural(&gvk, &info.plural);
    let api: Api<DynamicObject> = Api::namespaced_with(client.clone(), namespace, &ar);

    match list_with_retry_and_timeout(&api, &info.group, &info.version, &info.plural).await {
        Ok(items) => {
            for obj in items {
                let name = match obj.metadata.name {
                    Some(n) => n,
                    None => continue,
                };
                let service_name = obj
                    .metadata
                    .labels
                    .as_ref()
                    .and_then(|l| l.get("kubernetes.io/service-name"))
                    .cloned();
                let address_type = obj
                    .data
                    .get("addressType")
                    .and_then(|v| v.as_str())
                    .unwrap_or("IPv4")
                    .to_string();

                let ports = obj
                    .data
                    .get("ports")
                    .and_then(|p| p.as_array())
                    .map(|arr| {
                        arr.iter()
                            .map(|p| {
                                let port = p.get("port").and_then(|v| v.as_u64()).map(|v| v as u16);
                                let protocol = p
                                    .get("protocol")
                                    .and_then(|v| v.as_str())
                                    .unwrap_or("TCP")
                                    .to_string();
                                let app_protocol = p
                                    .get("appProtocol")
                                    .and_then(|v| v.as_str())
                                    .map(String::from);
                                let ep_name =
                                    p.get("name").and_then(|v| v.as_str()).map(String::from);
                                EndpointPort {
                                    name: ep_name,
                                    port,
                                    protocol,
                                    app_protocol,
                                }
                            })
                            .collect()
                    })
                    .unwrap_or_default();

                let mut endpoints: Vec<EndpointInfo> = obj
                    .data
                    .get("endpoints")
                    .and_then(|e| e.as_array())
                    .map(|arr| {
                        arr.iter()
                            .map(|ep| {
                                let addresses = ep
                                    .get("addresses")
                                    .and_then(|a| a.as_array())
                                    .map(|a| {
                                        a.iter()
                                            .filter_map(|v| v.as_str().map(String::from))
                                            .collect::<Vec<_>>()
                                    })
                                    .unwrap_or_default();
                                let conditions = ep.get("conditions");
                                let conditions_ready = conditions
                                    .and_then(|c| c.get("ready"))
                                    .and_then(|v| v.as_bool());
                                let conditions_serving = conditions
                                    .and_then(|c| c.get("serving"))
                                    .and_then(|v| v.as_bool());
                                let conditions_terminating = conditions
                                    .and_then(|c| c.get("terminating"))
                                    .and_then(|v| v.as_bool());
                                let target_ref = ep.get("targetRef").map(|tr| EndpointTargetRef {
                                    api_version: tr
                                        .get("apiVersion")
                                        .and_then(|v| v.as_str())
                                        .map(String::from),
                                    kind: tr.get("kind").and_then(|v| v.as_str()).map(String::from),
                                    name: tr.get("name").and_then(|v| v.as_str()).map(String::from),
                                    namespace: tr
                                        .get("namespace")
                                        .and_then(|v| v.as_str())
                                        .map(String::from),
                                    uid: tr.get("uid").and_then(|v| v.as_str()).map(String::from),
                                });
                                let hints = ep
                                    .get("hints")
                                    .and_then(|h| h.get("forZones"))
                                    .and_then(|fz| fz.as_array())
                                    .map(|arr| {
                                        arr.iter()
                                            .filter_map(|z| {
                                                z.get("name")
                                                    .and_then(|v| v.as_str())
                                                    .map(String::from)
                                            })
                                            .collect()
                                    });
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
                                EndpointInfo {
                                    addresses,
                                    hostname,
                                    node_name,
                                    zone,
                                    conditions_ready,
                                    conditions_serving,
                                    conditions_terminating,
                                    target_ref,
                                    hints,
                                }
                            })
                            .collect()
                    })
                    .unwrap_or_default();

                // Stable sort: endpoints by first address
                endpoints.sort_by(|a, b| {
                    let addr_a = a.addresses.first().map(|s| s.as_str()).unwrap_or("");
                    let addr_b = b.addresses.first().map(|s| s.as_str()).unwrap_or("");
                    addr_a.cmp(addr_b)
                });

                result.push(EndpointSliceInfo {
                    name,
                    service_name,
                    address_type,
                    ports,
                    endpoints,
                });
            }
        }
        Err(w) => {
            warnings.push(w);
        }
    }

    // Stable sort: slices by name
    result.sort_by(|a, b| a.name.cmp(&b.name));

    (result, warnings)
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
        match list_with_retry_and_timeout(&api, &info.group, &info.version, &info.plural).await {
            Ok(items) => {
                for obj in items {
                    if let Some(name) = obj.metadata.name {
                        result.extend(extract_ingress_refs(&name, &obj.data));
                    }
                }
            }
            Err(w) => {
                warnings.push(w);
            }
        }
    }

    if let Some(info) = gk_map.get(&("route.openshift.io".to_string(), "Route".to_string())) {
        let gvk = GroupVersion::gv(&info.group, &info.version).with_kind("Route");
        let ar = ApiResource::from_gvk_with_plural(&gvk, &info.plural);
        let api: Api<DynamicObject> = Api::namespaced_with(client.clone(), namespace, &ar);
        match list_with_retry_and_timeout(&api, &info.group, &info.version, &info.plural).await {
            Ok(items) => {
                for obj in items {
                    if let Some(name) = obj.metadata.name {
                        result.extend(extract_route_refs(&name, &obj.data));
                    }
                }
            }
            Err(w) => {
                warnings.push(w);
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

    let (endpoint_slices, eps_warnings) = list_endpoint_slices(client, namespace, gk_map).await;
    warnings.extend(eps_warnings);

    NetworkInventory {
        services,
        ingresses,
        endpoint_slices,
        warnings,
    }
}

/// Find EndpointSlices that belong to a Service (via kubernetes.io/service-name label).
fn find_service_endpoint_slices<'a>(
    svc_name: &str,
    slices: &'a [EndpointSliceInfo],
) -> Vec<&'a EndpointSliceInfo> {
    slices
        .iter()
        .filter(|s| s.service_name.as_deref() == Some(svc_name))
        .collect()
}

pub fn find_network_paths(
    pod_entries: &[(String, String, std::collections::HashMap<String, String>)],
    namespace: &str,
    inventory: &NetworkInventory,
) -> Vec<NetworkPath> {
    let mut paths = Vec::new();
    let pod_uid_set: std::collections::HashSet<&str> =
        pod_entries.iter().map(|(_, u, _)| u.as_str()).collect();

    for svc in &inventory.services {
        let matched_pod_names: Vec<String> = if svc.has_selector {
            pod_entries
                .iter()
                .filter(|(_, _, labels)| svc.selector.iter().all(|(k, v)| labels.get(k) == Some(v)))
                .map(|(n, _, _)| n.clone())
                .collect()
        } else {
            vec![]
        };
        let selector_matched = !matched_pod_names.is_empty();

        let svc_slices: Vec<EndpointSliceInfo> =
            find_service_endpoint_slices(&svc.name, &inventory.endpoint_slices)
                .into_iter()
                .cloned()
                .collect();

        let target_ref_match = !selector_matched
            && !svc.has_selector
            && svc_slices.iter().any(|s| {
                s.endpoints.iter().any(|ep| {
                    ep.target_ref.as_ref().is_some_and(|tr| {
                        tr.kind.as_deref() == Some("Pod")
                            && tr.namespace.as_deref().is_none_or(|ns| ns == namespace)
                            && tr
                                .uid
                                .as_deref()
                                .is_some_and(|uid| pod_uid_set.contains(uid))
                    })
                })
            });

        if !selector_matched && !target_ref_match {
            continue;
        }

        let matching_ingresses: Vec<NetworkIngress> = inventory
            .ingresses
            .iter()
            .filter(|ing| ing.backend_service == svc.name)
            .cloned()
            .collect();

        let endpoint_summary = EndpointSummary::from_slices(&svc_slices);

        let selector_matched_pods: Vec<String> = matched_pod_names
            .iter()
            .map(|n| format!("Pod/{}", n))
            .collect();

        let target_ref_matched_pods: Vec<String> = svc_slices
            .iter()
            .flat_map(|s| &s.endpoints)
            .filter_map(|ep| {
                let tr = ep.target_ref.as_ref()?;
                if tr.kind.as_deref() != Some("Pod") {
                    return None;
                }
                if tr.namespace.as_deref().is_some_and(|ns| ns != namespace) {
                    return None;
                }
                tr.name.as_ref().map(|n| format!("Pod/{}", n))
            })
            .collect::<std::collections::BTreeSet<_>>()
            .into_iter()
            .collect();

        paths.push(NetworkPath {
            service: svc.clone(),
            ingresses: matching_ingresses,
            endpoint_slices: svc_slices,
            endpoint_summary,
            selector_matched_pods,
            target_ref_matched_pods,
        });
    }

    paths
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

    fn test_svc(name: &str, selector: &[(&str, &str)]) -> NetworkService {
        NetworkService {
            name: name.into(),
            selector: selector
                .iter()
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect(),
            has_selector: !selector.is_empty(),
            cluster_ip: "10.0.0.1".into(),
            svc_type: "ClusterIP".into(),
            ports: vec![],
            health_check_node_port: None,
            internal_traffic_policy: None,
            ip_family_policy: None,
            load_balancer_class: None,
            allocate_lb_node_ports: None,
            external_traffic_policy: None,
            external_ips: vec![],
            ip_families: vec![],
            lb_ingress: vec![],
        }
    }

    #[test]
    fn find_paths_matches_service_selector() {
        let inventory = NetworkInventory {
            services: vec![
                test_svc("svc-a", &[("app", "x")]),
                test_svc("svc-b", &[("app", "y")]),
            ],
            ingresses: vec![NetworkIngress {
                kind: "Route".into(),
                name: "route-a".into(),
                backend_service: "svc-a".into(),
                host: Some("a.example.com".into()),
                path: None,
                tls: None,
            }],
            endpoint_slices: vec![],
            warnings: vec![],
        };
        let labels: std::collections::HashMap<String, String> =
            [("app".into(), "x".into())].into_iter().collect();
        let pod_entries = vec![("pod-1".into(), "uid-pod-1".into(), labels.clone())];
        let paths = find_network_paths(&pod_entries, "default", &inventory);
        assert_eq!(paths.len(), 1);
        assert_eq!(paths[0].service.name, "svc-a");
        assert_eq!(paths[0].ingresses.len(), 1);
        assert_eq!(paths[0].ingresses[0].name, "route-a");
    }

    #[test]
    fn find_paths_no_match() {
        let inventory = NetworkInventory {
            services: vec![test_svc("svc-a", &[("app", "x")])],
            ingresses: vec![],
            endpoint_slices: vec![],
            warnings: vec![],
        };
        let labels: std::collections::HashMap<String, String> =
            [("app".into(), "z".into())].into_iter().collect();
        let pod_entries = vec![("pod-1".into(), "uid-pod-1".into(), labels.clone())];
        let paths = find_network_paths(&pod_entries, "default", &inventory);
        assert!(paths.is_empty());
    }

    #[test]
    fn endpoint_summary_ready_none_counted_as_unknown() {
        let slices = vec![EndpointSliceInfo {
            name: "test-slice".into(),
            service_name: Some("test-svc".into()),
            address_type: "IPv4".into(),
            ports: vec![],
            endpoints: vec![
                EndpointInfo {
                    addresses: vec!["10.0.0.1".into()],
                    hostname: None,
                    node_name: None,
                    zone: None,
                    conditions_ready: Some(true),
                    conditions_serving: Some(true),
                    conditions_terminating: Some(false),
                    target_ref: None,
                    hints: None,
                },
                EndpointInfo {
                    addresses: vec!["10.0.0.2".into()],
                    hostname: None,
                    node_name: None,
                    zone: None,
                    conditions_ready: None, // unknown
                    conditions_serving: None,
                    conditions_terminating: None,
                    target_ref: None,
                    hints: None,
                },
                EndpointInfo {
                    addresses: vec!["10.0.0.3".into()],
                    hostname: None,
                    node_name: None,
                    zone: None,
                    conditions_ready: Some(false),
                    conditions_serving: Some(false),
                    conditions_terminating: Some(true),
                    target_ref: None,
                    hints: None,
                },
            ],
        }];
        let summary = EndpointSummary::from_slices(&slices);
        assert_eq!(summary.ready, 1);
        assert_eq!(summary.unknown, 1);
        assert_eq!(summary.not_ready, 1);
        assert_eq!(summary.effective_ready, 2); // ready + unknown
        assert_eq!(summary.serving, 1);
        assert_eq!(summary.terminating, 1);
    }

    #[test]
    #[allow(clippy::useless_vec)]
    fn endpoint_slices_stable_sort() {
        let mut slices = vec![
            EndpointSliceInfo {
                name: "svc-z-abc".into(),
                service_name: Some("svc-z".into()),
                address_type: "IPv4".into(),
                ports: vec![],
                endpoints: vec![
                    EndpointInfo {
                        addresses: vec!["10.0.0.5".into()],
                        hostname: None,
                        node_name: None,
                        zone: None,
                        conditions_ready: Some(true),
                        conditions_serving: None,
                        conditions_terminating: None,
                        target_ref: None,
                        hints: None,
                    },
                    EndpointInfo {
                        addresses: vec!["10.0.0.1".into()],
                        hostname: None,
                        node_name: None,
                        zone: None,
                        conditions_ready: Some(true),
                        conditions_serving: None,
                        conditions_terminating: None,
                        target_ref: None,
                        hints: None,
                    },
                ],
            },
            EndpointSliceInfo {
                name: "svc-a-xyz".into(),
                service_name: Some("svc-a".into()),
                address_type: "IPv4".into(),
                ports: vec![],
                endpoints: vec![],
            },
        ];
        slices.sort_by(|a, b| a.name.cmp(&b.name));
        assert_eq!(slices[0].name, "svc-a-xyz");
        assert_eq!(slices[1].name, "svc-z-abc");
        // Endpoints within a slice: sort by address (simulating what parsing does)
        for s in &mut slices {
            s.endpoints.sort_by(|a, b| {
                let aa = a.addresses.first().map(|s| s.as_str()).unwrap_or("");
                let ab = b.addresses.first().map(|s| s.as_str()).unwrap_or("");
                aa.cmp(ab)
            });
        }
        let eps = &slices[1].endpoints;
        assert!(eps[0].addresses[0] < eps[1].addresses[0]);
    }

    #[test]
    fn target_ref_matched_pods_vs_selector_matched_pods() {
        let inventory = NetworkInventory {
            services: vec![test_svc("svc-a", &[("app", "x")])],
            ingresses: vec![],
            endpoint_slices: vec![EndpointSliceInfo {
                name: "svc-a-abc".into(),
                service_name: Some("svc-a".into()),
                address_type: "IPv4".into(),
                ports: vec![],
                endpoints: vec![
                    EndpointInfo {
                        addresses: vec!["10.0.0.1".into()],
                        hostname: None,
                        node_name: None,
                        zone: None,
                        conditions_ready: Some(true),
                        conditions_serving: Some(true),
                        conditions_terminating: None,
                        target_ref: Some(EndpointTargetRef {
                            api_version: Some("v1".into()),
                            kind: Some("Pod".into()),
                            name: Some("pod-1".into()),
                            namespace: Some("default".into()),
                            uid: None,
                        }),
                        hints: None,
                    },
                    EndpointInfo {
                        addresses: vec!["10.0.0.2".into()],
                        hostname: None,
                        node_name: None,
                        zone: None,
                        conditions_ready: Some(true),
                        conditions_serving: Some(true),
                        conditions_terminating: None,
                        target_ref: Some(EndpointTargetRef {
                            api_version: Some("v1".into()),
                            kind: Some("Pod".into()),
                            name: Some("pod-2".into()),
                            namespace: Some("default".into()),
                            uid: None,
                        }),
                        hints: None,
                    },
                    // Non-Pod targetRef should be excluded
                    EndpointInfo {
                        addresses: vec!["10.0.0.3".into()],
                        hostname: None,
                        node_name: None,
                        zone: None,
                        conditions_ready: Some(true),
                        conditions_serving: Some(true),
                        conditions_terminating: None,
                        target_ref: Some(EndpointTargetRef {
                            api_version: Some("v1".into()),
                            kind: Some("Node".into()),
                            name: Some("node-1".into()),
                            namespace: None,
                            uid: None,
                        }),
                        hints: None,
                    },
                ],
            }],
            warnings: vec![],
        };
        let labels: std::collections::HashMap<String, String> =
            [("app".into(), "x".into())].into_iter().collect();
        let pod_entries = vec![
            ("pod-1".into(), "uid-pod-1".into(), labels.clone()),
            ("pod-3".into(), "uid-pod-3".into(), labels.clone()),
        ];
        let paths = find_network_paths(&pod_entries, "default", &inventory);
        assert_eq!(paths.len(), 1);
        // selector_matched_pods comes from per-pod label evaluation
        assert_eq!(
            paths[0].selector_matched_pods,
            vec!["Pod/pod-1", "Pod/pod-3"]
        );
        // target_ref_matched_pods comes from EndpointSlice targetRef (only kind=Pod, matching namespace)
        assert_eq!(
            paths[0].target_ref_matched_pods,
            vec!["Pod/pod-1", "Pod/pod-2"]
        );
    }

    // ── Mock retry tests ──

    use kube::client::Body;
    use std::pin::pin;

    fn mock_json_response(json: serde_json::Value) -> http::Response<Body> {
        http::Response::builder()
            .status(200)
            .body(Body::from(serde_json::to_vec(&json).unwrap()))
            .unwrap()
    }

    fn mock_status_response(code: u16, reason: &str) -> http::Response<Body> {
        let body = serde_json::json!({
            "kind": "Status", "apiVersion": "v1", "metadata": {},
            "status": "Failure", "message": reason, "reason": reason, "code": code
        });
        http::Response::builder()
            .status(code)
            .body(Body::from(serde_json::to_vec(&body).unwrap()))
            .unwrap()
    }

    fn mock_empty_list() -> http::Response<Body> {
        mock_json_response(serde_json::json!({
            "apiVersion": "v1", "kind": "List",
            "metadata": {"resourceVersion": "1"}, "items": []
        }))
    }

    #[tokio::test]
    async fn retry_403_no_retry() {
        let (mock_service, handle) =
            tower_test::mock::pair::<http::Request<Body>, http::Response<Body>>();
        let client = Client::new(mock_service, "default");
        let gvk = kube::core::GroupVersion::gv("", "v1").with_kind("Service");
        let ar = ApiResource::from_gvk_with_plural(&gvk, "services");
        let api: Api<DynamicObject> = Api::namespaced_with(client, "default", &ar);
        let rc = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let rc2 = rc.clone();

        let spawned = tokio::spawn(async move {
            let mut handle = pin!(handle);
            let (_req, send) = handle.next_request().await.unwrap();
            rc2.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            send.send_response(mock_status_response(403, "Forbidden"));
        });

        let result = list_with_retry_and_timeout(&api, "", "v1", "services").await;
        spawned.await.unwrap();
        assert!(result.is_err());
        assert_eq!(rc.load(std::sync::atomic::Ordering::Relaxed), 1);
        assert!(matches!(
            result.unwrap_err(),
            ScanWarning::Forbidden { status: 403, .. }
        ));
    }

    #[tokio::test]
    async fn retry_500_persistent_3_requests() {
        let (mock_service, handle) =
            tower_test::mock::pair::<http::Request<Body>, http::Response<Body>>();
        let client = Client::new(mock_service, "default");
        let gvk = kube::core::GroupVersion::gv("", "v1").with_kind("Service");
        let ar = ApiResource::from_gvk_with_plural(&gvk, "services");
        let api: Api<DynamicObject> = Api::namespaced_with(client, "default", &ar);
        let rc = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let rc2 = rc.clone();

        let spawned = tokio::spawn(async move {
            let mut handle = pin!(handle);
            for _ in 0..3 {
                let (_req, send) = handle.next_request().await.unwrap();
                rc2.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                send.send_response(mock_status_response(500, "Internal Server Error"));
            }
        });

        let result = list_with_retry_and_timeout(&api, "", "v1", "services").await;
        spawned.await.unwrap();
        assert!(result.is_err());
        assert_eq!(rc.load(std::sync::atomic::Ordering::Relaxed), 3);
        assert!(matches!(
            result.unwrap_err(),
            ScanWarning::ServerError { retries: 2, .. }
        ));
    }

    #[tokio::test]
    async fn retry_500_then_200_recovery() {
        let (mock_service, handle) =
            tower_test::mock::pair::<http::Request<Body>, http::Response<Body>>();
        let client = Client::new(mock_service, "default");
        let gvk = kube::core::GroupVersion::gv("", "v1").with_kind("Service");
        let ar = ApiResource::from_gvk_with_plural(&gvk, "services");
        let api: Api<DynamicObject> = Api::namespaced_with(client, "default", &ar);
        let rc = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let rc2 = rc.clone();

        let spawned = tokio::spawn(async move {
            let mut handle = pin!(handle);
            let (_req, send) = handle.next_request().await.unwrap();
            rc2.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            send.send_response(mock_status_response(500, "Internal Server Error"));
            let (_req, send) = handle.next_request().await.unwrap();
            rc2.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            send.send_response(mock_empty_list());
        });

        let result = list_with_retry_and_timeout(&api, "", "v1", "services").await;
        spawned.await.unwrap();
        assert!(result.is_ok());
        assert_eq!(rc.load(std::sync::atomic::Ordering::Relaxed), 2);
    }

    // ── Parse service via real parse_service function ──

    fn make_dynamic_object(name: &str, data: serde_json::Value) -> DynamicObject {
        DynamicObject {
            metadata: kube::core::ObjectMeta {
                name: Some(name.into()),
                ..Default::default()
            },
            types: None,
            data,
        }
    }

    #[test]
    fn parse_service_full_field_matrix() {
        let obj = make_dynamic_object(
            "lb-svc",
            serde_json::json!({
                "spec": {
                    "type": "LoadBalancer",
                    "clusterIP": "10.0.0.1",
                    "selector": {"app": "test"},
                    "ports": [{"port": 443, "targetPort": 8443, "protocol": "TCP", "nodePort": 31443}],
                    "externalIPs": ["192.168.1.1", "192.168.1.2"],
                    "ipFamilies": ["IPv4", "IPv6"],
                    "externalTrafficPolicy": "Local",
                    "internalTrafficPolicy": "Cluster",
                    "ipFamilyPolicy": "PreferDualStack",
                    "healthCheckNodePort": 30000,
                    "loadBalancerClass": "metallb",
                    "allocateLoadBalancerNodePorts": true
                },
                "status": {
                    "loadBalancer": {
                        "ingress": [
                            {"ip": "203.0.113.1", "hostname": "lb.example.com", "ipMode": "VIP"},
                            {"hostname": "lb2.example.com"}
                        ]
                    }
                }
            }),
        );

        let svc = parse_service(obj).expect("should parse");
        assert_eq!(svc.name, "lb-svc");
        assert_eq!(svc.svc_type, "LoadBalancer");
        assert_eq!(svc.cluster_ip, "10.0.0.1");
        assert!(svc.has_selector);
        assert_eq!(svc.selector.get("app").unwrap(), "test");

        assert_eq!(svc.ports.len(), 1);
        assert_eq!(svc.ports[0].port, 443);
        assert_eq!(svc.ports[0].node_port, Some(31443));

        assert_eq!(svc.external_ips, vec!["192.168.1.1", "192.168.1.2"]);
        assert_eq!(svc.ip_families, vec!["IPv4", "IPv6"]);
        assert_eq!(svc.external_traffic_policy.as_deref(), Some("Local"));
        assert_eq!(svc.internal_traffic_policy.as_deref(), Some("Cluster"));
        assert_eq!(svc.ip_family_policy.as_deref(), Some("PreferDualStack"));
        assert_eq!(svc.health_check_node_port, Some(30000));
        assert_eq!(svc.load_balancer_class.as_deref(), Some("metallb"));
        assert_eq!(svc.allocate_lb_node_ports, Some(true));

        assert_eq!(svc.lb_ingress.len(), 2);
        assert_eq!(svc.lb_ingress[0].ip.as_deref(), Some("203.0.113.1"));
        assert_eq!(
            svc.lb_ingress[0].hostname.as_deref(),
            Some("lb.example.com")
        );
        assert_eq!(svc.lb_ingress[0].ip_mode.as_deref(), Some("VIP"));
        assert_eq!(svc.lb_ingress[1].ip, None);
        assert_eq!(
            svc.lb_ingress[1].hostname.as_deref(),
            Some("lb2.example.com")
        );
    }

    #[test]
    fn parse_service_headless() {
        let obj = make_dynamic_object(
            "headless-svc",
            serde_json::json!({
                "spec": {
                    "type": "ClusterIP",
                    "clusterIP": "None",
                    "selector": {"app": "test"},
                    "ports": [{"port": 80, "targetPort": 8080, "protocol": "TCP"}]
                }
            }),
        );
        let svc = parse_service(obj).expect("should parse");
        assert_eq!(svc.svc_type, "Headless");
        assert_eq!(svc.cluster_ip, "None");
    }

    #[test]
    fn parse_service_nodeport() {
        let obj = make_dynamic_object(
            "np-svc",
            serde_json::json!({
                "spec": {
                    "type": "NodePort",
                    "clusterIP": "10.0.0.2",
                    "selector": {"app": "test"},
                    "ports": [{"port": 80, "targetPort": 8080, "protocol": "TCP", "nodePort": 30080}]
                }
            }),
        );
        let svc = parse_service(obj).expect("should parse");
        assert_eq!(svc.svc_type, "NodePort");
        assert_eq!(svc.ports[0].node_port, Some(30080));
    }

    #[test]
    fn parse_service_selectorless() {
        let obj = make_dynamic_object(
            "no-sel",
            serde_json::json!({
                "spec": {
                    "type": "ClusterIP",
                    "clusterIP": "10.0.0.3",
                    "ports": [{"port": 9090, "targetPort": 9090, "protocol": "TCP"}]
                }
            }),
        );
        let svc = parse_service(obj).expect("should parse selectorless");
        assert!(!svc.has_selector);
        assert!(svc.selector.is_empty());
    }

    #[tokio::test]
    async fn retry_timeout_3_attempts() {
        let (mock_service, handle) =
            tower_test::mock::pair::<http::Request<Body>, http::Response<Body>>();
        let client = Client::new(mock_service, "default");
        let gvk = kube::core::GroupVersion::gv("", "v1").with_kind("Service");
        let ar = ApiResource::from_gvk_with_plural(&gvk, "services");
        let api: Api<DynamicObject> = Api::namespaced_with(client, "default", &ar);
        let rc = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let rc2 = rc.clone();

        let spawned = tokio::spawn(async move {
            let mut handle = pin!(handle);
            for _ in 0..3 {
                let (_req, send) = handle.next_request().await.unwrap();
                rc2.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                // Don't respond — let it timeout
                tokio::time::sleep(std::time::Duration::from_millis(200)).await;
                send.send_response(mock_empty_list());
            }
        });

        // Use very short timeout (50ms) so test doesn't take 90s
        let result = list_with_retry_inner(
            &api,
            "",
            "v1",
            "services",
            std::time::Duration::from_millis(1),
        )
        .await;
        spawned.await.unwrap();

        assert!(result.is_err(), "should fail after 3 timeout attempts");
        assert_eq!(rc.load(std::sync::atomic::Ordering::Relaxed), 3);
        assert!(
            matches!(result.unwrap_err(), ScanWarning::Timeout { retries: 2, .. }),
            "should be Timeout with retries=2"
        );
    }
}
