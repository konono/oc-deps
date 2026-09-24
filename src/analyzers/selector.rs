use std::collections::BTreeMap;

use kube::{
    Client,
    api::{Api, ApiResource, DynamicObject, ListParams},
    core::GroupVersion,
};
use serde::Serialize;

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

#[derive(Clone, Debug, Serialize)]
pub struct ServicePort {
    pub port: u16,
    #[serde(rename = "targetPort")]
    pub target_port: String,
    pub protocol: String,
    #[serde(rename = "nodePort", skip_serializing_if = "Option::is_none")]
    pub node_port: Option<i64>,
}

#[derive(Clone, Debug, Serialize)]
pub struct LoadBalancerIngress {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ip: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hostname: Option<String>,
    #[serde(rename = "ipMode", skip_serializing_if = "Option::is_none")]
    pub ip_mode: Option<String>,
}

#[derive(Clone, Debug, Serialize)]
pub struct NetworkService {
    pub name: String,
    pub selector: BTreeMap<String, String>,
    #[serde(rename = "clusterIP", skip_serializing_if = "Option::is_none")]
    pub cluster_ip: Option<String>,
    #[serde(rename = "type")]
    pub svc_type: String,
    pub ports: Vec<ServicePort>,
    #[serde(rename = "externalIPs", skip_serializing_if = "Vec::is_empty")]
    pub external_ips: Vec<String>,
    #[serde(
        rename = "externalTrafficPolicy",
        skip_serializing_if = "Option::is_none"
    )]
    pub external_traffic_policy: Option<String>,
    #[serde(
        rename = "internalTrafficPolicy",
        skip_serializing_if = "Option::is_none"
    )]
    pub internal_traffic_policy: Option<String>,
    #[serde(
        rename = "healthCheckNodePort",
        skip_serializing_if = "Option::is_none"
    )]
    pub health_check_node_port: Option<i64>,
    #[serde(rename = "ipFamilies", skip_serializing_if = "Vec::is_empty")]
    pub ip_families: Vec<String>,
    #[serde(rename = "ipFamilyPolicy", skip_serializing_if = "Option::is_none")]
    pub ip_family_policy: Option<String>,
    #[serde(rename = "loadBalancerClass", skip_serializing_if = "Option::is_none")]
    pub load_balancer_class: Option<String>,
    #[serde(
        rename = "allocateLoadBalancerNodePorts",
        skip_serializing_if = "Option::is_none"
    )]
    pub allocate_lb_node_ports: Option<bool>,
    #[serde(rename = "loadBalancerIngress", skip_serializing_if = "Vec::is_empty")]
    pub load_balancer_ingress: Vec<LoadBalancerIngress>,
}

#[derive(Clone, Debug, Serialize)]
pub struct NetworkIngress {
    pub kind: String,
    pub name: String,
    #[serde(rename = "backendService")]
    pub backend_service: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub host: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tls: Option<String>,
}

// ──────────────────────────────────────────────────────────────
//  EndpointSlice types
// ──────────────────────────────────────────────────────────────

#[derive(Clone, Debug, Serialize)]
pub struct EndpointSliceInfo {
    pub name: String,
    #[serde(rename = "serviceName", skip_serializing_if = "Option::is_none")]
    pub service_name: Option<String>,
    #[serde(rename = "addressType")]
    pub address_type: String,
    pub endpoints: Vec<EndpointInfo>,
    pub ports: Vec<EndpointPort>,
}

#[derive(Clone, Debug, Serialize)]
pub struct EndpointInfo {
    pub addresses: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hostname: Option<String>,
    #[serde(rename = "nodeName", skip_serializing_if = "Option::is_none")]
    pub node_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub zone: Option<String>,
    #[serde(rename = "targetRef", skip_serializing_if = "Option::is_none")]
    pub target_ref: Option<EndpointTargetRef>,
    pub conditions: EndpointConditions,
}

#[derive(Clone, Debug, Serialize)]
pub struct EndpointTargetRef {
    pub kind: String,
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub namespace: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub uid: Option<String>,
}

#[derive(Clone, Debug, Serialize)]
pub struct EndpointConditions {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ready: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub serving: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub terminating: Option<bool>,
}

#[derive(Clone, Debug, Serialize)]
pub struct EndpointPort {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub port: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub protocol: Option<String>,
    #[serde(rename = "appProtocol", skip_serializing_if = "Option::is_none")]
    pub app_protocol: Option<String>,
}

#[derive(Clone, Debug, Serialize)]
pub struct EndpointSummary {
    pub ready: usize,
    #[serde(rename = "notReady")]
    pub not_ready: usize,
    pub unknown: usize,
    pub serving: usize,
    pub terminating: usize,
}

impl EndpointSummary {
    pub fn from_slices(slices: &[EndpointSliceInfo]) -> Self {
        let mut summary = EndpointSummary {
            ready: 0,
            not_ready: 0,
            unknown: 0,
            serving: 0,
            terminating: 0,
        };
        for slice in slices {
            for ep in &slice.endpoints {
                match ep.conditions.ready {
                    Some(true) => summary.ready += 1,
                    Some(false) => summary.not_ready += 1,
                    // Per K8s API docs: ready=None means consumer should treat as ready
                    None => summary.unknown += 1,
                }
                if ep.conditions.serving == Some(true) {
                    summary.serving += 1;
                }
                if ep.conditions.terminating == Some(true) {
                    summary.terminating += 1;
                }
            }
        }
        summary
    }
}

#[derive(Clone, Debug, Serialize)]
pub struct NetworkPath {
    pub service: NetworkService,
    pub ingresses: Vec<NetworkIngress>,
    #[serde(rename = "endpointSlices", skip_serializing_if = "Vec::is_empty")]
    pub endpoint_slices: Vec<EndpointSliceInfo>,
    #[serde(rename = "endpointSummary", skip_serializing_if = "Option::is_none")]
    pub endpoint_summary: Option<EndpointSummary>,
    #[serde(rename = "selectorMatchedPods", skip_serializing_if = "Vec::is_empty")]
    pub selector_matched_pods: Vec<String>,
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

    match api.list(&ListParams::default()).await {
        Ok(list) => {
            let mut services: Vec<NetworkService> = list
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
                    let spec = obj.data.get("spec");
                    let cluster_ip = spec
                        .and_then(|s| s.get("clusterIP"))
                        .and_then(|v| v.as_str())
                        .map(|s| s.to_string());
                    let raw_type = spec
                        .and_then(|s| s.get("type"))
                        .and_then(|v| v.as_str())
                        .unwrap_or("ClusterIP");
                    // Classify headless: clusterIP == "None"
                    let svc_type = if cluster_ip.as_deref() == Some("None") {
                        "Headless".to_string()
                    } else {
                        raw_type.to_string()
                    };
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
                                    let node_port = p.get("nodePort").and_then(|v| v.as_i64());
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
                    let external_traffic_policy = spec
                        .and_then(|s| s.get("externalTrafficPolicy"))
                        .and_then(|v| v.as_str())
                        .map(String::from);
                    let internal_traffic_policy = spec
                        .and_then(|s| s.get("internalTrafficPolicy"))
                        .and_then(|v| v.as_str())
                        .map(String::from);
                    let health_check_node_port = spec
                        .and_then(|s| s.get("healthCheckNodePort"))
                        .and_then(|v| v.as_i64());
                    let ip_families = spec
                        .and_then(|s| s.get("ipFamilies"))
                        .and_then(|v| v.as_array())
                        .map(|arr| {
                            arr.iter()
                                .filter_map(|v| v.as_str().map(String::from))
                                .collect()
                        })
                        .unwrap_or_default();
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
                    // Status: loadBalancer.ingress
                    let load_balancer_ingress = obj
                        .data
                        .get("status")
                        .and_then(|s| s.get("loadBalancer"))
                        .and_then(|lb| lb.get("ingress"))
                        .and_then(|v| v.as_array())
                        .map(|arr| {
                            arr.iter()
                                .map(|entry| LoadBalancerIngress {
                                    ip: entry.get("ip").and_then(|v| v.as_str()).map(String::from),
                                    hostname: entry
                                        .get("hostname")
                                        .and_then(|v| v.as_str())
                                        .map(String::from),
                                    ip_mode: entry
                                        .get("ipMode")
                                        .and_then(|v| v.as_str())
                                        .map(String::from),
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
                        external_ips,
                        external_traffic_policy,
                        internal_traffic_policy,
                        health_check_node_port,
                        ip_families,
                        ip_family_policy,
                        load_balancer_class,
                        allocate_lb_node_ports,
                        load_balancer_ingress,
                    })
                })
                .collect();
            services.sort_by(|a, b| a.name.cmp(&b.name));
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

async fn list_endpoint_slices(
    client: &Client,
    namespace: &str,
    gk_map: &GroupKindMap,
) -> (Vec<EndpointSliceInfo>, Vec<ScanWarning>) {
    let info = match gk_map.get(&("discovery.k8s.io".to_string(), "EndpointSlice".to_string())) {
        Some(i) => i,
        None => return (vec![], vec![]),
    };
    let gvk = GroupVersion::gv(&info.group, &info.version).with_kind("EndpointSlice");
    let ar = ApiResource::from_gvk_with_plural(&gvk, &info.plural);
    let api: Api<DynamicObject> = Api::namespaced_with(client.clone(), namespace, &ar);

    let list_result = tokio::time::timeout(
        std::time::Duration::from_secs(30),
        api.list(&ListParams::default()),
    )
    .await;

    let items = match list_result {
        Ok(Ok(list)) => list.items,
        Ok(Err(e)) => {
            return (
                vec![],
                vec![ScanWarning::from_kube_error(
                    &e,
                    &info.group,
                    &info.version,
                    &info.plural,
                )],
            );
        }
        Err(_) => {
            let gvr = format!("{}/{}/{}", info.group, info.version, info.plural);
            return (
                vec![],
                vec![ScanWarning::Timeout {
                    gvr,
                    message: Some("EndpointSlice list timed out after 30s".into()),
                    retries: 0,
                }],
            );
        }
    };

    let mut slices: Vec<EndpointSliceInfo> = items
        .into_iter()
        .filter_map(|obj| {
            let name = obj.metadata.name?;
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
            let endpoints = obj
                .data
                .get("endpoints")
                .and_then(|v| v.as_array())
                .map(|arr| {
                    arr.iter()
                        .map(|ep| {
                            let addresses = ep
                                .get("addresses")
                                .and_then(|v| v.as_array())
                                .map(|a| {
                                    a.iter()
                                        .filter_map(|v| v.as_str().map(String::from))
                                        .collect()
                                })
                                .unwrap_or_default();
                            let hostname = ep
                                .get("hostname")
                                .and_then(|v| v.as_str())
                                .map(String::from);
                            let node_name = ep
                                .get("nodeName")
                                .and_then(|v| v.as_str())
                                .map(String::from);
                            let zone = ep.get("zone").and_then(|v| v.as_str()).map(String::from);
                            let target_ref = ep.get("targetRef").and_then(|tr| {
                                Some(EndpointTargetRef {
                                    kind: tr.get("kind")?.as_str()?.to_string(),
                                    name: tr.get("name")?.as_str()?.to_string(),
                                    namespace: tr
                                        .get("namespace")
                                        .and_then(|v| v.as_str())
                                        .map(String::from),
                                    uid: tr.get("uid").and_then(|v| v.as_str()).map(String::from),
                                })
                            });
                            let conditions = ep.get("conditions");
                            EndpointInfo {
                                addresses,
                                hostname,
                                node_name,
                                zone,
                                target_ref,
                                conditions: EndpointConditions {
                                    ready: conditions
                                        .and_then(|c| c.get("ready"))
                                        .and_then(|v| v.as_bool()),
                                    serving: conditions
                                        .and_then(|c| c.get("serving"))
                                        .and_then(|v| v.as_bool()),
                                    terminating: conditions
                                        .and_then(|c| c.get("terminating"))
                                        .and_then(|v| v.as_bool()),
                                },
                            }
                        })
                        .collect()
                })
                .unwrap_or_default();
            let ports = obj
                .data
                .get("ports")
                .and_then(|v| v.as_array())
                .map(|arr| {
                    arr.iter()
                        .map(|p| EndpointPort {
                            name: p.get("name").and_then(|v| v.as_str()).map(String::from),
                            port: p.get("port").and_then(|v| v.as_i64()),
                            protocol: p.get("protocol").and_then(|v| v.as_str()).map(String::from),
                            app_protocol: p
                                .get("appProtocol")
                                .and_then(|v| v.as_str())
                                .map(String::from),
                        })
                        .collect()
                })
                .unwrap_or_default();
            Some(EndpointSliceInfo {
                name,
                service_name,
                address_type,
                endpoints,
                ports,
            })
        })
        .collect();
    // Stable sort: by service name, then slice name
    slices.sort_by(|a, b| {
        a.service_name
            .cmp(&b.service_name)
            .then(a.name.cmp(&b.name))
    });
    (slices, vec![])
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
/// `pod_entries`: Vec of (pod_name, pod_uid, pod_labels).
/// For selector-based Services, matches by label selector.
/// For selectorless Services, matches via EndpointSlice targetRef UID.
pub fn find_network_paths(
    pod_entries: &[(String, String, std::collections::HashMap<String, String>)],
    inventory: &NetworkInventory,
) -> Vec<NetworkPath> {
    use std::collections::HashSet;

    // Collect all pod UIDs for selectorless matching
    let pod_uids: HashSet<&str> = pod_entries.iter().map(|(_, uid, _)| uid.as_str()).collect();
    let pod_names_by_uid: std::collections::HashMap<&str, &str> = pod_entries
        .iter()
        .map(|(name, uid, _)| (uid.as_str(), name.as_str()))
        .collect();

    let mut paths = Vec::new();

    for svc in &inventory.services {
        // Get EndpointSlices for this service
        let svc_slices: Vec<EndpointSliceInfo> = inventory
            .endpoint_slices
            .iter()
            .filter(|es| es.service_name.as_deref() == Some(&svc.name))
            .cloned()
            .collect();

        if !svc.selector.is_empty() {
            // Selector-based: check if any pod's labels match
            let matched_pod_names: Vec<String> = pod_entries
                .iter()
                .filter(|(_, _, labels)| svc.selector.iter().all(|(k, v)| labels.get(k) == Some(v)))
                .map(|(name, _, _)| name.clone())
                .collect();

            if matched_pod_names.is_empty() {
                continue;
            }

            let matching_ingresses: Vec<NetworkIngress> = inventory
                .ingresses
                .iter()
                .filter(|ing| ing.backend_service == svc.name)
                .cloned()
                .collect();

            let endpoint_summary = if !svc_slices.is_empty() {
                Some(EndpointSummary::from_slices(&svc_slices))
            } else {
                None
            };

            paths.push(NetworkPath {
                service: svc.clone(),
                ingresses: matching_ingresses,
                endpoint_slices: svc_slices,
                endpoint_summary,
                selector_matched_pods: matched_pod_names,
            });
        } else {
            // Selectorless: check if any EndpointSlice targetRef UID matches a descendant pod
            let mut matched_pod_names: Vec<String> = Vec::new();
            for slice in &svc_slices {
                for ep in &slice.endpoints {
                    if let Some(ref tr) = ep.target_ref
                        && let Some(ref uid) = tr.uid
                        && pod_uids.contains(uid.as_str())
                        && let Some(name) = pod_names_by_uid.get(uid.as_str())
                    {
                        matched_pod_names.push(name.to_string());
                    }
                }
            }
            matched_pod_names.sort();
            matched_pod_names.dedup();

            if matched_pod_names.is_empty() {
                continue;
            }

            let matching_ingresses: Vec<NetworkIngress> = inventory
                .ingresses
                .iter()
                .filter(|ing| ing.backend_service == svc.name)
                .cloned()
                .collect();

            let endpoint_summary = if !svc_slices.is_empty() {
                Some(EndpointSummary::from_slices(&svc_slices))
            } else {
                None
            };

            paths.push(NetworkPath {
                service: svc.clone(),
                ingresses: matching_ingresses,
                endpoint_slices: svc_slices,
                endpoint_summary,
                selector_matched_pods: matched_pod_names,
            });
        }
    }

    // Stable sort by service name
    paths.sort_by(|a, b| a.service.name.cmp(&b.service.name));
    paths
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_svc(
        name: &str,
        selector: Vec<(&str, &str)>,
        svc_type: &str,
        cluster_ip: Option<&str>,
    ) -> NetworkService {
        NetworkService {
            name: name.into(),
            selector: selector
                .into_iter()
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect(),
            cluster_ip: cluster_ip.map(String::from),
            svc_type: svc_type.into(),
            ports: vec![],
            external_ips: vec![],
            external_traffic_policy: None,
            internal_traffic_policy: None,
            health_check_node_port: None,
            ip_families: vec![],
            ip_family_policy: None,
            load_balancer_class: None,
            allocate_lb_node_ports: None,
            load_balancer_ingress: vec![],
        }
    }

    fn make_inventory(
        services: Vec<NetworkService>,
        ingresses: Vec<NetworkIngress>,
        endpoint_slices: Vec<EndpointSliceInfo>,
    ) -> NetworkInventory {
        NetworkInventory {
            services,
            ingresses,
            endpoint_slices,
            warnings: vec![],
        }
    }

    #[allow(clippy::type_complexity)]
    fn make_pod_entries(
        entries: Vec<(&str, &str, Vec<(&str, &str)>)>,
    ) -> Vec<(String, String, std::collections::HashMap<String, String>)> {
        entries
            .into_iter()
            .map(|(name, uid, labels)| {
                (
                    name.to_string(),
                    uid.to_string(),
                    labels
                        .into_iter()
                        .map(|(k, v)| (k.to_string(), v.to_string()))
                        .collect(),
                )
            })
            .collect()
    }

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
        let inventory = make_inventory(
            vec![
                make_svc("svc-a", vec![("app", "x")], "ClusterIP", Some("10.0.0.1")),
                make_svc("svc-b", vec![("app", "y")], "ClusterIP", Some("10.0.0.2")),
            ],
            vec![NetworkIngress {
                kind: "Route".into(),
                name: "route-a".into(),
                backend_service: "svc-a".into(),
                host: Some("a.example.com".into()),
                path: None,
                tls: None,
            }],
            vec![],
        );
        let pods = make_pod_entries(vec![("my-pod", "uid-1", vec![("app", "x")])]);
        let paths = find_network_paths(&pods, &inventory);
        assert_eq!(paths.len(), 1);
        assert_eq!(paths[0].service.name, "svc-a");
        assert_eq!(paths[0].ingresses.len(), 1);
        assert_eq!(paths[0].ingresses[0].name, "route-a");
        assert_eq!(paths[0].selector_matched_pods, vec!["my-pod"]);
    }

    #[test]
    fn find_paths_no_match() {
        let inventory = make_inventory(
            vec![make_svc(
                "svc-a",
                vec![("app", "x")],
                "ClusterIP",
                Some("10.0.0.1"),
            )],
            vec![],
            vec![],
        );
        let pods = make_pod_entries(vec![("my-pod", "uid-1", vec![("app", "z")])]);
        let paths = find_network_paths(&pods, &inventory);
        assert!(paths.is_empty());
    }

    // ── Service type classification ──

    #[test]
    fn service_type_classification() {
        // Headless: clusterIP == "None"
        let headless = make_svc("h", vec![], "Headless", None);
        assert_eq!(headless.svc_type, "Headless");

        // NodePort
        let np = make_svc("np", vec![("app", "x")], "NodePort", Some("10.0.0.1"));
        assert_eq!(np.svc_type, "NodePort");

        // LoadBalancer
        let lb = make_svc("lb", vec![("app", "x")], "LoadBalancer", Some("10.0.0.2"));
        assert_eq!(lb.svc_type, "LoadBalancer");

        // ExternalName
        let en = make_svc("en", vec![], "ExternalName", None);
        assert_eq!(en.svc_type, "ExternalName");
    }

    #[test]
    fn load_balancer_status_with_ip_hostname() {
        let svc = NetworkService {
            load_balancer_ingress: vec![
                LoadBalancerIngress {
                    ip: Some("1.2.3.4".into()),
                    hostname: None,
                    ip_mode: None,
                },
                LoadBalancerIngress {
                    ip: None,
                    hostname: Some("lb.example.com".into()),
                    ip_mode: Some("VIP".into()),
                },
            ],
            ..make_svc(
                "lb-svc",
                vec![("app", "x")],
                "LoadBalancer",
                Some("10.0.0.1"),
            )
        };
        assert_eq!(svc.load_balancer_ingress.len(), 2);
        assert_eq!(svc.load_balancer_ingress[0].ip.as_deref(), Some("1.2.3.4"));
        assert_eq!(
            svc.load_balancer_ingress[1].hostname.as_deref(),
            Some("lb.example.com")
        );
        assert_eq!(svc.load_balancer_ingress[1].ip_mode.as_deref(), Some("VIP"));
    }

    // ── EndpointSlice parsing ──

    #[test]
    fn endpoint_slice_parsing_ready_not_ready_none() {
        let slice = EndpointSliceInfo {
            name: "svc-abc".into(),
            service_name: Some("my-svc".into()),
            address_type: "IPv4".into(),
            endpoints: vec![
                EndpointInfo {
                    addresses: vec!["10.0.0.1".into()],
                    hostname: None,
                    node_name: Some("node-1".into()),
                    zone: None,
                    target_ref: Some(EndpointTargetRef {
                        kind: "Pod".into(),
                        name: "pod-a".into(),
                        namespace: Some("default".into()),
                        uid: Some("uid-a".into()),
                    }),
                    conditions: EndpointConditions {
                        ready: Some(true),
                        serving: Some(true),
                        terminating: None,
                    },
                },
                EndpointInfo {
                    addresses: vec!["10.0.0.2".into()],
                    hostname: None,
                    node_name: None,
                    zone: None,
                    target_ref: None,
                    conditions: EndpointConditions {
                        ready: Some(false),
                        serving: None,
                        terminating: None,
                    },
                },
                EndpointInfo {
                    addresses: vec!["10.0.0.3".into()],
                    hostname: None,
                    node_name: None,
                    zone: None,
                    target_ref: None,
                    conditions: EndpointConditions {
                        ready: None,
                        serving: None,
                        terminating: None,
                    },
                },
            ],
            ports: vec![EndpointPort {
                name: Some("http".into()),
                port: Some(8080),
                protocol: Some("TCP".into()),
                app_protocol: Some("http".into()),
            }],
        };

        let summary = EndpointSummary::from_slices(&[slice]);
        assert_eq!(summary.ready, 1);
        assert_eq!(summary.not_ready, 1);
        assert_eq!(summary.unknown, 1); // ready=None
        assert_eq!(summary.serving, 1);
        assert_eq!(summary.terminating, 0);
    }

    #[test]
    fn endpoint_summary_multiple_slices() {
        let s1 = EndpointSliceInfo {
            name: "svc-a-1".into(),
            service_name: Some("svc-a".into()),
            address_type: "IPv4".into(),
            endpoints: vec![EndpointInfo {
                addresses: vec!["10.0.0.1".into()],
                hostname: None,
                node_name: None,
                zone: None,
                target_ref: None,
                conditions: EndpointConditions {
                    ready: Some(true),
                    serving: Some(true),
                    terminating: None,
                },
            }],
            ports: vec![],
        };
        let s2 = EndpointSliceInfo {
            name: "svc-a-2".into(),
            service_name: Some("svc-a".into()),
            address_type: "IPv4".into(),
            endpoints: vec![
                EndpointInfo {
                    addresses: vec!["10.0.0.2".into()],
                    hostname: None,
                    node_name: None,
                    zone: None,
                    target_ref: None,
                    conditions: EndpointConditions {
                        ready: Some(true),
                        serving: Some(true),
                        terminating: None,
                    },
                },
                EndpointInfo {
                    addresses: vec!["10.0.0.3".into()],
                    hostname: None,
                    node_name: None,
                    zone: None,
                    target_ref: None,
                    conditions: EndpointConditions {
                        ready: Some(false),
                        serving: None,
                        terminating: Some(true),
                    },
                },
            ],
            ports: vec![],
        };
        let summary = EndpointSummary::from_slices(&[s1, s2]);
        assert_eq!(summary.ready, 2);
        assert_eq!(summary.not_ready, 1);
        assert_eq!(summary.serving, 2);
        assert_eq!(summary.terminating, 1);
    }

    #[test]
    fn selectorless_service_matched_via_target_ref() {
        let inventory = make_inventory(
            vec![make_svc("headless-svc", vec![], "Headless", None)],
            vec![],
            vec![EndpointSliceInfo {
                name: "headless-svc-abc".into(),
                service_name: Some("headless-svc".into()),
                address_type: "IPv4".into(),
                endpoints: vec![EndpointInfo {
                    addresses: vec!["10.0.0.1".into()],
                    hostname: None,
                    node_name: None,
                    zone: None,
                    target_ref: Some(EndpointTargetRef {
                        kind: "Pod".into(),
                        name: "my-pod".into(),
                        namespace: Some("default".into()),
                        uid: Some("uid-match".into()),
                    }),
                    conditions: EndpointConditions {
                        ready: Some(true),
                        serving: Some(true),
                        terminating: None,
                    },
                }],
                ports: vec![],
            }],
        );
        let pods = make_pod_entries(vec![("my-pod", "uid-match", vec![])]);
        let paths = find_network_paths(&pods, &inventory);
        assert_eq!(paths.len(), 1);
        assert_eq!(paths[0].service.name, "headless-svc");
        assert_eq!(paths[0].selector_matched_pods, vec!["my-pod"]);
    }

    #[test]
    fn selectorless_target_ref_uid_mismatch_no_match() {
        let inventory = make_inventory(
            vec![make_svc("headless-svc", vec![], "Headless", None)],
            vec![],
            vec![EndpointSliceInfo {
                name: "headless-svc-abc".into(),
                service_name: Some("headless-svc".into()),
                address_type: "IPv4".into(),
                endpoints: vec![EndpointInfo {
                    addresses: vec!["10.0.0.1".into()],
                    hostname: None,
                    node_name: None,
                    zone: None,
                    target_ref: Some(EndpointTargetRef {
                        kind: "Pod".into(),
                        name: "other-pod".into(),
                        namespace: Some("default".into()),
                        uid: Some("uid-other".into()),
                    }),
                    conditions: EndpointConditions {
                        ready: Some(true),
                        serving: None,
                        terminating: None,
                    },
                }],
                ports: vec![],
            }],
        );
        let pods = make_pod_entries(vec![("my-pod", "uid-mine", vec![])]);
        let paths = find_network_paths(&pods, &inventory);
        assert!(paths.is_empty());
    }

    #[test]
    fn endpoint_slice_api_not_found_returns_empty() {
        // This tests the gk_map.get() path — if EndpointSlice is not in the map,
        // list_endpoint_slices returns empty vec with no error.
        // We simulate this by having an inventory with no endpoint_slices.
        let inventory = make_inventory(
            vec![make_svc(
                "svc-a",
                vec![("app", "x")],
                "ClusterIP",
                Some("10.0.0.1"),
            )],
            vec![],
            vec![], // no endpoint slices — API not available
        );
        let pods = make_pod_entries(vec![("my-pod", "uid-1", vec![("app", "x")])]);
        let paths = find_network_paths(&pods, &inventory);
        assert_eq!(paths.len(), 1);
        assert!(paths[0].endpoint_slices.is_empty());
        assert!(paths[0].endpoint_summary.is_none());
    }
}
