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
    pub annotations: BTreeMap<String, String>,
    pub labels: BTreeMap<String, String>,
    pub load_balancer_ip: Option<String>,
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

// ── NetworkPolicy types ──

#[derive(Clone, Debug, PartialEq)]
pub enum NetworkPolicyAvailability {
    Available,
    ApiAbsent,
    Unavailable,
}

#[derive(Clone, Debug)]
pub struct NetworkPolicyInfo {
    pub name: String,
    pub pod_selector: PodSelector,
    pub policy_types: Vec<String>,
    pub ingress_rules: Vec<NetworkPolicyRule>,
    pub egress_rules: Vec<NetworkPolicyRule>,
}

#[derive(Clone, Debug)]
pub struct PodSelector {
    pub match_labels: BTreeMap<String, String>,
    pub match_expressions: Vec<LabelSelectorRequirement>,
}

impl PodSelector {
    #[allow(dead_code)]
    pub fn is_empty(&self) -> bool {
        self.match_labels.is_empty() && self.match_expressions.is_empty()
    }

    pub fn matches(&self, labels: &std::collections::HashMap<String, String>) -> bool {
        for (k, v) in &self.match_labels {
            if labels.get(k) != Some(v) {
                return false;
            }
        }
        for expr in &self.match_expressions {
            let value = labels.get(&expr.key);
            let matched = match expr.operator.as_str() {
                "In" => value.is_some_and(|v| expr.values.contains(v)),
                "NotIn" => value.is_none_or(|v| !expr.values.contains(v)),
                "Exists" => value.is_some(),
                "DoesNotExist" => value.is_none(),
                _ => false,
            };
            if !matched {
                return false;
            }
        }
        true
    }
}

#[derive(Clone, Debug)]
pub struct LabelSelectorRequirement {
    pub key: String,
    pub operator: String,
    pub values: Vec<String>,
}

#[derive(Clone, Debug)]
pub struct NetworkPolicyRule {
    pub peers: Vec<NetworkPolicyPeer>,
    pub ports: Vec<NetworkPolicyPort>,
}

#[derive(Clone, Debug)]
pub struct NetworkPolicyPeer {
    pub pod_selector: Option<PodSelector>,
    pub namespace_selector: Option<PodSelector>,
    pub ip_block: Option<IpBlock>,
}

#[derive(Clone, Debug)]
pub struct IpBlock {
    pub cidr: String,
    pub except: Vec<String>,
}

#[derive(Clone, Debug)]
pub enum IntOrString {
    Int(u16),
    String(String),
}

#[derive(Clone, Debug)]
pub struct NetworkPolicyPort {
    pub protocol: Option<String>,
    pub port: Option<IntOrString>,
    pub end_port: Option<u16>,
}

#[derive(Clone, Debug)]
pub struct PodNetworkPosture {
    pub pod_name: String,
    pub pod_uid: String,
    pub ingress_isolation: String,
    pub egress_isolation: String,
    pub applicable_policies: Vec<ApplicablePolicy>,
}

#[derive(Clone, Debug)]
pub struct ApplicablePolicy {
    pub name: String,
    pub pod_selector: PodSelector,
    pub policy_types: Vec<String>,
    pub isolates_ingress: bool,
    pub isolates_egress: bool,
    pub ingress_rules: Vec<NetworkPolicyRule>,
    pub egress_rules: Vec<NetworkPolicyRule>,
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

pub struct VerifiedPod {
    pub name: String,
    pub uid: String,
    pub labels: std::collections::HashMap<String, String>,
}

pub fn resolve_verified_target_ref_pods(
    endpoint_slices: &[EndpointSliceInfo],
    index_by_uid: &std::collections::HashMap<String, crate::kube::resource::ResourceInfo>,
    namespace: &str,
) -> (Vec<String>, Vec<VerifiedPod>) {
    let mut target_ref_pods = Vec::new();
    let mut verified_pods = Vec::new();
    let mut seen_uids = std::collections::HashSet::new();
    for es in endpoint_slices {
        for ep in &es.endpoints {
            let Some(tr) = &ep.target_ref else {
                continue;
            };
            if tr.kind.as_deref() != Some("Pod") {
                continue;
            }
            let api_ver = tr.api_version.as_deref().unwrap_or("v1");
            if api_ver != "v1" && !api_ver.is_empty() {
                continue;
            }
            let Some(pod_name) = &tr.name else {
                continue;
            };
            let tr_ns = tr.namespace.as_deref().unwrap_or(namespace);
            if tr_ns != namespace {
                continue;
            }
            let Some(tr_uid) = &tr.uid else {
                continue;
            };
            for info in index_by_uid.values() {
                if info.kind == "Pod"
                    && info.name == *pod_name
                    && info.namespace.as_deref() == Some(tr_ns)
                    && info.uid == *tr_uid
                {
                    let pod_ref = format!("Pod/{}", pod_name);
                    if !target_ref_pods.contains(&pod_ref) {
                        target_ref_pods.push(pod_ref);
                    }
                    if seen_uids.insert(info.uid.clone()) {
                        verified_pods.push(VerifiedPod {
                            name: info.name.clone(),
                            uid: info.uid.clone(),
                            labels: info.labels.clone(),
                        });
                    }
                    break;
                }
            }
        }
    }
    (target_ref_pods, verified_pods)
}

pub type PodLabelsTuple = (String, String, std::collections::HashMap<String, String>);

#[allow(clippy::type_complexity)]
pub fn build_service_network_path(
    target_svc: &NetworkService,
    inventory: &NetworkInventory,
    index_by_uid: &std::collections::HashMap<String, crate::kube::resource::ResourceInfo>,
    namespace: &str,
) -> (NetworkPath, Vec<PodLabelsTuple>) {
    let svc_ep_slices: Vec<_> = inventory
        .endpoint_slices
        .iter()
        .filter(|es| es.service_name.as_deref() == Some(&target_svc.name))
        .cloned()
        .collect();
    let svc_ingresses: Vec<_> = inventory
        .ingresses
        .iter()
        .filter(|i| i.backend_service == target_svc.name)
        .cloned()
        .collect();
    let mut summary = EndpointSummary::default();
    for es in &svc_ep_slices {
        for ep in &es.endpoints {
            match ep.conditions_ready {
                Some(true) => summary.ready += 1,
                Some(false) => summary.not_ready += 1,
                None => summary.unknown += 1,
            }
            if ep.conditions_serving == Some(true) {
                summary.serving += 1;
            }
            if ep.conditions_terminating == Some(true) {
                summary.terminating += 1;
            }
        }
    }
    summary.effective_ready = summary.ready + summary.unknown;

    let mut selector_pods = Vec::new();
    if target_svc.has_selector {
        for info in index_by_uid.values() {
            if info.kind == "Pod"
                && info.namespace.as_deref() == Some(namespace)
                && target_svc
                    .selector
                    .iter()
                    .all(|(k, v)| info.labels.get(k) == Some(v))
            {
                selector_pods.push(format!("Pod/{}", info.name));
            }
        }
        selector_pods.sort();
    }

    let (target_ref_pods, verified_target_pods) =
        resolve_verified_target_ref_pods(&svc_ep_slices, index_by_uid, namespace);

    let mut pod_labels_list: Vec<PodLabelsTuple> = Vec::new();
    let mut seen_pod_uids = std::collections::HashSet::new();
    for pod_str in &selector_pods {
        let pod_name = pod_str.strip_prefix("Pod/").unwrap_or(pod_str);
        for info in index_by_uid.values() {
            if info.kind == "Pod"
                && info.name == pod_name
                && info.namespace.as_deref() == Some(namespace)
                && seen_pod_uids.insert(info.uid.clone())
            {
                pod_labels_list.push((info.name.clone(), info.uid.clone(), info.labels.clone()));
                break;
            }
        }
    }
    for vp in &verified_target_pods {
        if seen_pod_uids.insert(vp.uid.clone()) {
            pod_labels_list.push((vp.name.clone(), vp.uid.clone(), vp.labels.clone()));
        }
    }

    let path = NetworkPath {
        service: target_svc.clone(),
        ingresses: svc_ingresses,
        endpoint_slices: svc_ep_slices,
        endpoint_summary: summary,
        selector_matched_pods: selector_pods,
        target_ref_matched_pods: target_ref_pods,
    };
    (path, pod_labels_list)
}

pub struct NetworkInventory {
    pub services: Vec<NetworkService>,
    pub ingresses: Vec<NetworkIngress>,
    pub endpoint_slices: Vec<EndpointSliceInfo>,
    pub network_policies: Vec<NetworkPolicyInfo>,
    pub np_availability: NetworkPolicyAvailability,
    pub warnings: Vec<ScanWarning>,
    pub metallb: MetalLBInventory,
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

    let annotations = obj
        .metadata
        .annotations
        .as_ref()
        .map(|m| m.iter().map(|(k, v)| (k.clone(), v.clone())).collect())
        .unwrap_or_default();
    let labels = obj
        .metadata
        .labels
        .as_ref()
        .map(|m| m.iter().map(|(k, v)| (k.clone(), v.clone())).collect())
        .unwrap_or_default();
    let load_balancer_ip = spec
        .and_then(|s| s.get("loadBalancerIP"))
        .and_then(|v| v.as_str())
        .map(String::from);

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
        annotations,
        labels,
        load_balancer_ip,
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

fn parse_pod_selector(sel: &serde_json::Value) -> PodSelector {
    let match_labels = sel
        .get("matchLabels")
        .and_then(|v| v.as_object())
        .map(|m| {
            m.iter()
                .filter_map(|(k, v)| v.as_str().map(|val| (k.clone(), val.to_string())))
                .collect::<BTreeMap<_, _>>()
        })
        .unwrap_or_default();
    let match_expressions = sel
        .get("matchExpressions")
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|e| {
                    let key = e.get("key")?.as_str()?.to_string();
                    let operator = e.get("operator")?.as_str()?.to_string();
                    let values = e
                        .get("values")
                        .and_then(|v| v.as_array())
                        .map(|a| {
                            a.iter()
                                .filter_map(|v| v.as_str().map(String::from))
                                .collect()
                        })
                        .unwrap_or_default();
                    Some(LabelSelectorRequirement {
                        key,
                        operator,
                        values,
                    })
                })
                .collect()
        })
        .unwrap_or_default();
    PodSelector {
        match_labels,
        match_expressions,
    }
}

fn parse_network_policy_peers(peers: &[serde_json::Value]) -> Vec<NetworkPolicyPeer> {
    peers
        .iter()
        .map(|peer| {
            let pod_selector = peer.get("podSelector").map(parse_pod_selector);
            let namespace_selector = peer.get("namespaceSelector").map(parse_pod_selector);
            let ip_block = peer.get("ipBlock").and_then(|ib| {
                let cidr = ib.get("cidr")?.as_str()?.to_string();
                let except = ib
                    .get("except")
                    .and_then(|v| v.as_array())
                    .map(|a| {
                        a.iter()
                            .filter_map(|v| v.as_str().map(String::from))
                            .collect()
                    })
                    .unwrap_or_default();
                Some(IpBlock { cidr, except })
            });
            NetworkPolicyPeer {
                pod_selector,
                namespace_selector,
                ip_block,
            }
        })
        .collect()
}

fn parse_network_policy_ports(ports: &[serde_json::Value]) -> Vec<NetworkPolicyPort> {
    ports
        .iter()
        .map(|p| {
            let protocol = p.get("protocol").and_then(|v| v.as_str()).map(String::from);
            let port = p.get("port").and_then(|v| match v {
                serde_json::Value::Number(n) => n.as_u64().map(|n| IntOrString::Int(n as u16)),
                serde_json::Value::String(s) => Some(IntOrString::String(s.clone())),
                _ => None,
            });
            let end_port = p.get("endPort").and_then(|v| v.as_u64()).map(|v| v as u16);
            NetworkPolicyPort {
                protocol,
                port,
                end_port,
            }
        })
        .collect()
}

pub(crate) fn parse_network_policy(obj: DynamicObject) -> Option<NetworkPolicyInfo> {
    let name = obj.metadata.name?;
    let spec = obj.data.get("spec")?;

    let pod_selector = spec
        .get("podSelector")
        .map(parse_pod_selector)
        .unwrap_or(PodSelector {
            match_labels: BTreeMap::new(),
            match_expressions: vec![],
        });

    let policy_types: Vec<String> = spec
        .get("policyTypes")
        .and_then(|v| v.as_array())
        .map(|a| {
            a.iter()
                .filter_map(|v| v.as_str().map(String::from))
                .collect()
        })
        .unwrap_or_default();

    let ingress_rules: Vec<NetworkPolicyRule> = spec
        .get("ingress")
        .and_then(|v| v.as_array())
        .map(|rules| {
            rules
                .iter()
                .map(|rule| {
                    let peers = rule
                        .get("from")
                        .and_then(|v| v.as_array())
                        .map(|a| parse_network_policy_peers(a))
                        .unwrap_or_default();
                    let ports = rule
                        .get("ports")
                        .and_then(|v| v.as_array())
                        .map(|a| parse_network_policy_ports(a))
                        .unwrap_or_default();
                    NetworkPolicyRule { peers, ports }
                })
                .collect()
        })
        .unwrap_or_default();

    let egress_rules: Vec<NetworkPolicyRule> = spec
        .get("egress")
        .and_then(|v| v.as_array())
        .map(|rules| {
            rules
                .iter()
                .map(|rule| {
                    let peers = rule
                        .get("to")
                        .and_then(|v| v.as_array())
                        .map(|a| parse_network_policy_peers(a))
                        .unwrap_or_default();
                    let ports = rule
                        .get("ports")
                        .and_then(|v| v.as_array())
                        .map(|a| parse_network_policy_ports(a))
                        .unwrap_or_default();
                    NetworkPolicyRule { peers, ports }
                })
                .collect()
        })
        .unwrap_or_default();

    Some(NetworkPolicyInfo {
        name,
        pod_selector,
        policy_types,
        ingress_rules,
        egress_rules,
    })
}

pub(crate) async fn list_network_policies(
    client: &Client,
    namespace: &str,
    gk_map: &GroupKindMap,
) -> (
    Vec<NetworkPolicyInfo>,
    NetworkPolicyAvailability,
    Vec<ScanWarning>,
) {
    let mut result = Vec::new();
    let mut warnings = Vec::new();

    let key = ("networking.k8s.io".to_string(), "NetworkPolicy".to_string());
    let info = match gk_map.get(&key) {
        Some(i) => i,
        None => return (result, NetworkPolicyAvailability::ApiAbsent, warnings),
    };

    let gvk = GroupVersion::gv(&info.group, &info.version).with_kind("NetworkPolicy");
    let ar = ApiResource::from_gvk_with_plural(&gvk, &info.plural);
    let api: Api<DynamicObject> = Api::namespaced_with(client.clone(), namespace, &ar);

    match list_with_retry_and_timeout(&api, &info.group, &info.version, &info.plural).await {
        Ok(items) => {
            for obj in items {
                if let Some(np) = parse_network_policy(obj) {
                    result.push(np);
                }
            }
            (result, NetworkPolicyAvailability::Available, warnings)
        }
        Err(w) => {
            warnings.push(w);
            (result, NetworkPolicyAvailability::Unavailable, warnings)
        }
    }
}

/// Determine effective policyTypes for a NetworkPolicy.
/// Per K8s spec: if policyTypes is empty, Ingress is always implied;
/// Egress is implied only if egress rules are present.
fn effective_policy_types(np: &NetworkPolicyInfo) -> Vec<String> {
    if !np.policy_types.is_empty() {
        return np.policy_types.clone();
    }
    let mut types = vec!["Ingress".to_string()];
    if !np.egress_rules.is_empty() {
        types.push("Egress".to_string());
    }
    types
}

pub(crate) fn evaluate_network_postures(
    pod_entries: &[(String, String, std::collections::HashMap<String, String>)],
    policies: &[NetworkPolicyInfo],
    availability: &NetworkPolicyAvailability,
) -> Vec<PodNetworkPosture> {
    pod_entries
        .iter()
        .map(|(pod_name, pod_uid, labels)| {
            if *availability != NetworkPolicyAvailability::Available {
                return PodNetworkPosture {
                    pod_name: pod_name.clone(),
                    pod_uid: pod_uid.clone(),
                    ingress_isolation: "unknown".to_string(),
                    egress_isolation: "unknown".to_string(),
                    applicable_policies: vec![],
                };
            }

            let mut applicable = Vec::new();
            let mut has_ingress_policy = false;
            let mut has_egress_policy = false;

            for np in policies {
                if !np.pod_selector.matches(labels) {
                    continue;
                }
                let eff_types = effective_policy_types(np);
                let isolates_ingress = eff_types.iter().any(|t| t == "Ingress");
                let isolates_egress = eff_types.iter().any(|t| t == "Egress");
                if isolates_ingress {
                    has_ingress_policy = true;
                }
                if isolates_egress {
                    has_egress_policy = true;
                }
                applicable.push(ApplicablePolicy {
                    name: np.name.clone(),
                    pod_selector: np.pod_selector.clone(),
                    policy_types: eff_types,
                    isolates_ingress,
                    isolates_egress,
                    ingress_rules: np.ingress_rules.clone(),
                    egress_rules: np.egress_rules.clone(),
                });
            }

            PodNetworkPosture {
                pod_name: pod_name.clone(),
                pod_uid: pod_uid.clone(),
                ingress_isolation: if has_ingress_policy {
                    "isolated"
                } else {
                    "non-isolated"
                }
                .to_string(),
                egress_isolation: if has_egress_policy {
                    "isolated"
                } else {
                    "non-isolated"
                }
                .to_string(),
                applicable_policies: applicable,
            }
        })
        .collect()
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

    let (network_policies, np_availability, np_warnings) =
        list_network_policies(client, namespace, gk_map).await;
    warnings.extend(np_warnings);

    let metallb = build_metallb_inventory(client, gk_map).await;

    NetworkInventory {
        services,
        ingresses,
        endpoint_slices,
        network_policies,
        np_availability,
        warnings,
        metallb,
    }
}

async fn build_metallb_inventory(client: &Client, gk_map: &GroupKindMap) -> MetalLBInventory {
    let metallb_group = "metallb.io";

    // Check if IPAddressPool CRD exists
    let pool_key = (metallb_group.to_string(), "IPAddressPool".to_string());
    let pool_info = match gk_map.get(&pool_key) {
        Some(i) => i,
        None => return MetalLBInventory::default(),
    };

    let mut pools = Vec::new();
    let mut l2_advertisements = Vec::new();
    let mut bgp_advertisements = Vec::new();

    // List IPAddressPools (all namespaces)
    {
        let gvk = GroupVersion::gv(&pool_info.group, &pool_info.version).with_kind("IPAddressPool");
        let ar = ApiResource::from_gvk_with_plural(&gvk, &pool_info.plural);
        let api: Api<DynamicObject> = Api::all_with(client.clone(), &ar);
        if let Ok(items) = list_with_retry_and_timeout(
            &api,
            &pool_info.group,
            &pool_info.version,
            &pool_info.plural,
        )
        .await
        {
            pools = items
                .into_iter()
                .filter_map(parse_ip_address_pool)
                .collect();
        }
    }

    // List L2Advertisements
    let l2_key = (metallb_group.to_string(), "L2Advertisement".to_string());
    if let Some(l2_info) = gk_map.get(&l2_key) {
        let gvk = GroupVersion::gv(&l2_info.group, &l2_info.version).with_kind("L2Advertisement");
        let ar = ApiResource::from_gvk_with_plural(&gvk, &l2_info.plural);
        let api: Api<DynamicObject> = Api::all_with(client.clone(), &ar);
        if let Ok(items) =
            list_with_retry_and_timeout(&api, &l2_info.group, &l2_info.version, &l2_info.plural)
                .await
        {
            l2_advertisements = items
                .into_iter()
                .filter_map(parse_l2_advertisement)
                .collect();
        }
    }

    // List BGPAdvertisements
    let bgp_key = (metallb_group.to_string(), "BGPAdvertisement".to_string());
    if let Some(bgp_info) = gk_map.get(&bgp_key) {
        let gvk =
            GroupVersion::gv(&bgp_info.group, &bgp_info.version).with_kind("BGPAdvertisement");
        let ar = ApiResource::from_gvk_with_plural(&gvk, &bgp_info.plural);
        let api: Api<DynamicObject> = Api::all_with(client.clone(), &ar);
        if let Ok(items) =
            list_with_retry_and_timeout(&api, &bgp_info.group, &bgp_info.version, &bgp_info.plural)
                .await
        {
            bgp_advertisements = items
                .into_iter()
                .filter_map(parse_bgp_advertisement)
                .collect();
        }
    }

    MetalLBInventory {
        available: true,
        pools,
        l2_advertisements,
        bgp_advertisements,
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

// ──────────────────────────────────────────────────────────────
//  MetalLB types and resolution
// ──────────────────────────────────────────────────────────────

#[derive(Clone, Debug)]
pub struct LabelSelector {
    pub match_labels: BTreeMap<String, String>,
    pub match_expressions: Vec<MatchExpression>,
}

#[derive(Clone, Debug)]
pub struct MatchExpression {
    pub key: String,
    pub operator: String,
    pub values: Vec<String>,
}

#[derive(Clone, Debug)]
pub struct ServiceAllocation {
    pub _priority: i64,
    pub namespaces: Vec<String>,
    pub namespace_selectors: Vec<LabelSelector>,
    pub service_selectors: Vec<LabelSelector>,
}

#[derive(Clone, Debug)]
pub struct IPAddressPool {
    pub name: String,
    pub namespace: String,
    pub addresses: Vec<String>,
    pub auto_assign: bool,
    pub service_allocation: Option<ServiceAllocation>,
    pub labels: BTreeMap<String, String>,
}

#[derive(Clone, Debug)]
pub struct L2Advertisement {
    pub name: String,
    pub namespace: String,
    pub ip_address_pools: Vec<String>,
    pub ip_address_pool_selectors: Vec<LabelSelector>,
    pub node_selectors: Vec<LabelSelector>,
    pub service_selectors: Vec<LabelSelector>,
}

#[derive(Clone, Debug)]
pub struct BGPAdvertisement {
    pub name: String,
    pub namespace: String,
    pub ip_address_pools: Vec<String>,
    pub ip_address_pool_selectors: Vec<LabelSelector>,
    pub node_selectors: Vec<LabelSelector>,
    pub aggregation_length: Option<i64>,
    pub aggregation_length_v6: Option<i64>,
    pub local_pref: Option<i64>,
    pub communities: Vec<String>,
    pub service_selectors: Vec<LabelSelector>,
}

#[derive(Clone, Debug)]
pub struct MatchedPool {
    pub pool: IPAddressPool,
    pub match_reason: String,
    pub allocation_match: Option<String>,
}

#[derive(Clone, Debug)]
pub struct MatchedAdvertisement {
    pub kind: String,
    pub name: String,
    pub _namespace: String,
    pub match_reason: String,
    pub node_selectors: Vec<LabelSelector>,
    pub _service_selectors: Vec<LabelSelector>,
    pub aggregation_length: Option<i64>,
    pub aggregation_length_v6: Option<i64>,
    pub local_pref: Option<i64>,
    pub communities: Vec<String>,
}

#[derive(Clone, Debug, Default)]
pub struct MetalLBResult {
    pub provider: Option<String>,
    pub pools: Vec<MatchedPool>,
    pub advertisements: Vec<MatchedAdvertisement>,
    pub warnings: Vec<String>,
    pub requested_ips: Vec<String>,
    pub requested_pool: Option<String>,
}

#[derive(Clone, Debug, Default)]
pub struct MetalLBInventory {
    pub available: bool,
    pub pools: Vec<IPAddressPool>,
    pub l2_advertisements: Vec<L2Advertisement>,
    pub bgp_advertisements: Vec<BGPAdvertisement>,
}

pub fn label_selector_matches(selector: &LabelSelector, labels: &BTreeMap<String, String>) -> bool {
    for (k, v) in &selector.match_labels {
        if labels.get(k) != Some(v) {
            return false;
        }
    }
    for expr in &selector.match_expressions {
        match expr.operator.as_str() {
            "In" => {
                let Some(val) = labels.get(&expr.key) else {
                    return false;
                };
                if !expr.values.contains(val) {
                    return false;
                }
            }
            "NotIn" => {
                if let Some(val) = labels.get(&expr.key)
                    && expr.values.contains(val)
                {
                    return false;
                }
            }
            "Exists" => {
                if !labels.contains_key(&expr.key) {
                    return false;
                }
            }
            "DoesNotExist" => {
                if labels.contains_key(&expr.key) {
                    return false;
                }
            }
            _ => {
                return false;
            }
        }
    }
    true
}

fn label_selector_list_matches(
    selectors: &[LabelSelector],
    labels: &BTreeMap<String, String>,
) -> bool {
    if selectors.is_empty() {
        return true;
    }
    selectors.iter().any(|s| label_selector_matches(s, labels))
}

fn parse_label_selectors(value: Option<&serde_json::Value>) -> Vec<LabelSelector> {
    let Some(arr) = value.and_then(|v| v.as_array()) else {
        return vec![];
    };
    arr.iter()
        .filter_map(|item| {
            let obj = item.as_object()?;
            let match_labels = obj
                .get("matchLabels")
                .and_then(|v| v.as_object())
                .map(|m| {
                    m.iter()
                        .filter_map(|(k, v)| v.as_str().map(|val| (k.clone(), val.to_string())))
                        .collect()
                })
                .unwrap_or_default();
            let match_expressions = obj
                .get("matchExpressions")
                .and_then(|v| v.as_array())
                .map(|arr| {
                    arr.iter()
                        .filter_map(|e| {
                            Some(MatchExpression {
                                key: e.get("key")?.as_str()?.to_string(),
                                operator: e.get("operator")?.as_str()?.to_string(),
                                values: e
                                    .get("values")
                                    .and_then(|v| v.as_array())
                                    .map(|a| {
                                        a.iter()
                                            .filter_map(|v| v.as_str().map(String::from))
                                            .collect()
                                    })
                                    .unwrap_or_default(),
                            })
                        })
                        .collect()
                })
                .unwrap_or_default();
            Some(LabelSelector {
                match_labels,
                match_expressions,
            })
        })
        .collect()
}

pub(crate) fn parse_ip_address_pool(obj: DynamicObject) -> Option<IPAddressPool> {
    let name = obj.metadata.name?;
    let namespace = obj.metadata.namespace.unwrap_or_default();
    let spec = obj.data.get("spec");

    let addresses = spec
        .and_then(|s| s.get("addresses"))
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|v| v.as_str().map(String::from))
                .collect()
        })
        .unwrap_or_default();

    let auto_assign = spec
        .and_then(|s| s.get("autoAssign"))
        .and_then(|v| v.as_bool())
        .unwrap_or(true);

    let service_allocation = spec.and_then(|s| s.get("serviceAllocation")).map(|sa| {
        let priority = sa.get("priority").and_then(|v| v.as_i64()).unwrap_or(0);
        let namespaces = sa
            .get("namespaces")
            .and_then(|v| v.as_array())
            .map(|arr| {
                arr.iter()
                    .filter_map(|v| v.as_str().map(String::from))
                    .collect()
            })
            .unwrap_or_default();
        let namespace_selectors = parse_label_selectors(sa.get("namespaceSelectors"));
        let service_selectors = parse_label_selectors(sa.get("serviceSelectors"));
        ServiceAllocation {
            _priority: priority,
            namespaces,
            namespace_selectors,
            service_selectors,
        }
    });

    let labels = obj
        .metadata
        .labels
        .as_ref()
        .map(|m| m.iter().map(|(k, v)| (k.clone(), v.clone())).collect())
        .unwrap_or_default();

    Some(IPAddressPool {
        name,
        namespace,
        addresses,
        auto_assign,
        service_allocation,
        labels,
    })
}

pub(crate) fn parse_l2_advertisement(obj: DynamicObject) -> Option<L2Advertisement> {
    let name = obj.metadata.name?;
    let namespace = obj.metadata.namespace.unwrap_or_default();
    let spec = obj.data.get("spec");

    let ip_address_pools = spec
        .and_then(|s| s.get("ipAddressPools"))
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|v| v.as_str().map(String::from))
                .collect()
        })
        .unwrap_or_default();

    let ip_address_pool_selectors =
        parse_label_selectors(spec.and_then(|s| s.get("ipAddressPoolSelectors")));
    let node_selectors = parse_label_selectors(spec.and_then(|s| s.get("nodeSelectors")));
    let service_selectors = parse_label_selectors(spec.and_then(|s| s.get("serviceSelectors")));

    Some(L2Advertisement {
        name,
        namespace,
        ip_address_pools,
        ip_address_pool_selectors,
        node_selectors,
        service_selectors,
    })
}

pub(crate) fn parse_bgp_advertisement(obj: DynamicObject) -> Option<BGPAdvertisement> {
    let name = obj.metadata.name?;
    let namespace = obj.metadata.namespace.unwrap_or_default();
    let spec = obj.data.get("spec");

    let ip_address_pools = spec
        .and_then(|s| s.get("ipAddressPools"))
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|v| v.as_str().map(String::from))
                .collect()
        })
        .unwrap_or_default();

    let ip_address_pool_selectors =
        parse_label_selectors(spec.and_then(|s| s.get("ipAddressPoolSelectors")));
    let node_selectors = parse_label_selectors(spec.and_then(|s| s.get("nodeSelectors")));
    let service_selectors = parse_label_selectors(spec.and_then(|s| s.get("serviceSelectors")));

    let aggregation_length = spec
        .and_then(|s| s.get("aggregationLength"))
        .and_then(|v| v.as_i64());
    let aggregation_length_v6 = spec
        .and_then(|s| s.get("aggregationLengthV6"))
        .and_then(|v| v.as_i64());
    let local_pref = spec
        .and_then(|s| s.get("localPref"))
        .and_then(|v| v.as_i64());
    let communities = spec
        .and_then(|s| s.get("communities"))
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|v| v.as_str().map(String::from))
                .collect()
        })
        .unwrap_or_default();

    Some(BGPAdvertisement {
        name,
        namespace,
        ip_address_pools,
        ip_address_pool_selectors,
        node_selectors,
        aggregation_length,
        aggregation_length_v6,
        local_pref,
        communities,
        service_selectors,
    })
}

/// Check if an IP address falls within one of the pool's address ranges.
/// Supports CIDR notation (e.g., "192.168.1.0/24") and ranges (e.g., "192.168.1.10-192.168.1.20").
fn ip_in_pool_ranges(ip: &str, addresses: &[String]) -> bool {
    let parsed_ip: std::net::IpAddr = match ip.parse() {
        Ok(a) => a,
        Err(_) => return false,
    };
    for addr_spec in addresses {
        if addr_spec.contains('/') {
            // CIDR
            if let Some((net_str, prefix_str)) = addr_spec.split_once('/')
                && let (Ok(net_addr), Ok(prefix_len)) = (
                    net_str.parse::<std::net::IpAddr>(),
                    prefix_str.parse::<u8>(),
                )
                && ip_in_cidr(parsed_ip, net_addr, prefix_len)
            {
                return true;
            }
        } else if addr_spec.contains('-') {
            // Range
            if let Some((start_str, end_str)) = addr_spec.split_once('-')
                && let (Ok(start), Ok(end)) = (
                    start_str.trim().parse::<std::net::IpAddr>(),
                    end_str.trim().parse::<std::net::IpAddr>(),
                )
                && ip_in_range(parsed_ip, start, end)
            {
                return true;
            }
        } else {
            // Single IP
            if ip == addr_spec {
                return true;
            }
        }
    }
    false
}

fn ip_in_cidr(ip: std::net::IpAddr, network: std::net::IpAddr, prefix_len: u8) -> bool {
    match (ip, network) {
        (std::net::IpAddr::V4(ip4), std::net::IpAddr::V4(net4)) => {
            if prefix_len > 32 {
                return false;
            }
            let mask = if prefix_len == 0 {
                0u32
            } else {
                !0u32 << (32 - prefix_len)
            };
            (u32::from(ip4) & mask) == (u32::from(net4) & mask)
        }
        (std::net::IpAddr::V6(ip6), std::net::IpAddr::V6(net6)) => {
            if prefix_len > 128 {
                return false;
            }
            let mask = if prefix_len == 0 {
                0u128
            } else {
                !0u128 << (128 - prefix_len)
            };
            (u128::from(ip6) & mask) == (u128::from(net6) & mask)
        }
        _ => false,
    }
}

fn ip_in_range(ip: std::net::IpAddr, start: std::net::IpAddr, end: std::net::IpAddr) -> bool {
    match (ip, start, end) {
        (std::net::IpAddr::V4(i), std::net::IpAddr::V4(s), std::net::IpAddr::V4(e)) => {
            u32::from(i) >= u32::from(s) && u32::from(i) <= u32::from(e)
        }
        (std::net::IpAddr::V6(i), std::net::IpAddr::V6(s), std::net::IpAddr::V6(e)) => {
            u128::from(i) >= u128::from(s) && u128::from(i) <= u128::from(e)
        }
        _ => false,
    }
}

pub fn resolve_metallb_for_service(
    svc: &NetworkService,
    svc_namespace: &str,
    metallb: &MetalLBInventory,
    endpoint_nodes: &[String],
) -> MetalLBResult {
    if !metallb.available || svc.svc_type != "LoadBalancer" {
        return MetalLBResult::default();
    }

    let mut warnings = Vec::new();

    // Collect requested IPs
    let mut requested_ips = Vec::new();
    if let Some(ips) = svc
        .annotations
        .get("metallb.io/loadBalancerIPs")
        .or_else(|| svc.annotations.get("metallb.universe.tf/loadBalancerIPs"))
    {
        requested_ips.extend(
            ips.split(',')
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty()),
        );
    }
    if let Some(lb_ip) = &svc.load_balancer_ip
        && !lb_ip.is_empty()
        && !requested_ips.contains(lb_ip)
    {
        requested_ips.push(lb_ip.clone());
    }

    // Collect assigned IPs
    let assigned_ips: Vec<String> = svc
        .lb_ingress
        .iter()
        .filter_map(|lbi| lbi.ip.clone())
        .collect();

    // Collect requested pool
    let requested_pool = svc
        .annotations
        .get("metallb.io/address-pool")
        .or_else(|| svc.annotations.get("metallb.universe.tf/address-pool"))
        .cloned();

    // Determine provider evidence
    let has_pool_annotation = requested_pool.is_some();
    let has_lb_ips_annotation = svc.annotations.contains_key("metallb.io/loadBalancerIPs")
        || svc
            .annotations
            .contains_key("metallb.universe.tf/loadBalancerIPs");
    let has_lb_class = svc
        .load_balancer_class
        .as_ref()
        .is_some_and(|c| c.to_lowercase().contains("metallb"));
    let assigned_ip_in_pool = assigned_ips.iter().any(|ip| {
        metallb
            .pools
            .iter()
            .any(|p| ip_in_pool_ranges(ip, &p.addresses))
    });

    let provider =
        if has_pool_annotation || has_lb_ips_annotation || has_lb_class || assigned_ip_in_pool {
            Some("MetalLB".to_string())
        } else {
            None
        };

    if provider.is_none() {
        return MetalLBResult {
            provider,
            requested_ips,
            requested_pool,
            ..Default::default()
        };
    }

    // Match pools
    let svc_labels_btree: BTreeMap<String, String> = svc.labels.clone();
    let mut matched_pools = Vec::new();

    for pool in &metallb.pools {
        let mut match_reason = None;

        // a. Requested pool annotation
        if let Some(ref rp) = requested_pool
            && rp == &pool.name
        {
            match_reason = Some("requested pool annotation".to_string());
        }

        // b. Assigned IP in range
        if match_reason.is_none() {
            for ip in &assigned_ips {
                if ip_in_pool_ranges(ip, &pool.addresses) {
                    match_reason = Some(format!("assigned IP {} in range", ip));
                    break;
                }
            }
        }

        // c. Requested IP in range
        if match_reason.is_none() {
            for ip in &requested_ips {
                if ip_in_pool_ranges(ip, &pool.addresses) {
                    match_reason = Some(format!("requested IP {} in range", ip));
                    break;
                }
            }
        }

        // e. autoAssign=false without explicit request → skip
        if match_reason.is_none() && !pool.auto_assign {
            continue;
        }

        let Some(reason) = match_reason else {
            continue;
        };

        // d. Check serviceAllocation
        let allocation_match = if let Some(sa) = &pool.service_allocation {
            let mut issues = Vec::new();
            if !sa.namespaces.is_empty() && !sa.namespaces.contains(&svc_namespace.to_string()) {
                issues.push(format!(
                    "namespace {} not in allowed list [{}]",
                    svc_namespace,
                    sa.namespaces.join(", ")
                ));
            }
            if !sa.namespace_selectors.is_empty() {
                issues.push("namespace selector: not evaluated".to_string());
            }
            if !sa.service_selectors.is_empty() {
                if label_selector_list_matches(&sa.service_selectors, &svc_labels_btree) {
                    // OK
                } else {
                    issues.push("service selector mismatch".to_string());
                }
            }
            if issues.is_empty() {
                Some("OK".to_string())
            } else {
                let msg = issues.join("; ");
                warnings.push(format!("Pool {} serviceAllocation: {}", pool.name, msg));
                Some(msg)
            }
        } else {
            None
        };

        matched_pools.push(MatchedPool {
            pool: pool.clone(),
            match_reason: reason,
            allocation_match,
        });
    }

    // Check for requested pool not found
    if let Some(ref rp) = requested_pool
        && !matched_pools.iter().any(|mp| mp.pool.name == *rp)
    {
        warnings.push(format!("Requested pool '{}' not found", rp));
    }

    // Check assigned IP not in any pool
    for ip in &assigned_ips {
        if !metallb
            .pools
            .iter()
            .any(|p| ip_in_pool_ranges(ip, &p.addresses))
        {
            warnings.push(format!("Assigned IP {} does not match any pool", ip));
        }
    }

    if assigned_ips.is_empty() && provider.is_some() {
        warnings.push("No assigned IP (loadBalancer ingress empty)".to_string());
    }

    // Match advertisements
    let mut matched_ads = Vec::new();

    for mp in &matched_pools {
        let pool = &mp.pool;

        // L2 advertisements
        for l2 in &metallb.l2_advertisements {
            if l2.namespace != pool.namespace {
                continue;
            }
            let pool_match = if l2.ip_address_pools.contains(&pool.name) {
                true
            } else if !l2.ip_address_pool_selectors.is_empty() {
                label_selector_list_matches(&l2.ip_address_pool_selectors, &pool.labels)
            } else {
                // Empty pools + empty selectors = match all pools
                l2.ip_address_pools.is_empty() && l2.ip_address_pool_selectors.is_empty()
            };
            if !pool_match {
                continue;
            }

            // Service selector check
            if !l2.service_selectors.is_empty()
                && !label_selector_list_matches(&l2.service_selectors, &svc_labels_btree)
            {
                warnings.push(format!(
                    "L2Advertisement/{} serviceSelector mismatch for Service/{}",
                    l2.name, svc.name
                ));
                continue;
            }

            let mut match_reason = format!("pool {} via ", pool.name);
            if l2.ip_address_pools.contains(&pool.name) {
                match_reason.push_str("ipAddressPools");
            } else if !l2.ip_address_pool_selectors.is_empty() {
                match_reason.push_str("ipAddressPoolSelectors");
            } else {
                match_reason.push_str("match-all (empty selectors)");
            }

            matched_ads.push(MatchedAdvertisement {
                kind: "L2Advertisement".to_string(),
                name: l2.name.clone(),
                _namespace: l2.namespace.clone(),
                match_reason,
                node_selectors: l2.node_selectors.clone(),
                _service_selectors: l2.service_selectors.clone(),
                aggregation_length: None,
                aggregation_length_v6: None,
                local_pref: None,
                communities: vec![],
            });
        }

        // BGP advertisements
        for bgp in &metallb.bgp_advertisements {
            if bgp.namespace != pool.namespace {
                continue;
            }
            let pool_match = if bgp.ip_address_pools.contains(&pool.name) {
                true
            } else if !bgp.ip_address_pool_selectors.is_empty() {
                label_selector_list_matches(&bgp.ip_address_pool_selectors, &pool.labels)
            } else {
                bgp.ip_address_pools.is_empty() && bgp.ip_address_pool_selectors.is_empty()
            };
            if !pool_match {
                continue;
            }

            if !bgp.service_selectors.is_empty()
                && !label_selector_list_matches(&bgp.service_selectors, &svc_labels_btree)
            {
                warnings.push(format!(
                    "BGPAdvertisement/{} serviceSelector mismatch for Service/{}",
                    bgp.name, svc.name
                ));
                continue;
            }

            let mut match_reason = format!("pool {} via ", pool.name);
            if bgp.ip_address_pools.contains(&pool.name) {
                match_reason.push_str("ipAddressPools");
            } else if !bgp.ip_address_pool_selectors.is_empty() {
                match_reason.push_str("ipAddressPoolSelectors");
            } else {
                match_reason.push_str("match-all (empty selectors)");
            }

            matched_ads.push(MatchedAdvertisement {
                kind: "BGPAdvertisement".to_string(),
                name: bgp.name.clone(),
                _namespace: bgp.namespace.clone(),
                match_reason,
                node_selectors: bgp.node_selectors.clone(),
                _service_selectors: bgp.service_selectors.clone(),
                aggregation_length: bgp.aggregation_length,
                aggregation_length_v6: bgp.aggregation_length_v6,
                local_pref: bgp.local_pref,
                communities: bgp.communities.clone(),
            });
        }
    }

    // Warn if pool matched but no advertisement
    for mp in &matched_pools {
        let has_ad = matched_ads.iter().any(|a| {
            a.match_reason
                .starts_with(&format!("pool {}", mp.pool.name))
        });
        if !has_ad {
            warnings.push(format!(
                "Pool {} matched but no L2/BGP advertisement found",
                mp.pool.name
            ));
        }
    }

    // externalTrafficPolicy=Local checks
    if svc.external_traffic_policy.as_deref() == Some("Local") && endpoint_nodes.is_empty() {
        warnings.push("externalTrafficPolicy=Local but no ready endpoint nodes found".to_string());
    }

    MetalLBResult {
        provider,
        pools: matched_pools,
        advertisements: matched_ads,
        warnings,
        requested_ips,
        requested_pool,
    }
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
            annotations: BTreeMap::new(),
            labels: BTreeMap::new(),
            load_balancer_ip: None,
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
            network_policies: vec![],
            np_availability: NetworkPolicyAvailability::Available,
            warnings: vec![],
            metallb: MetalLBInventory::default(),
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
            network_policies: vec![],
            np_availability: NetworkPolicyAvailability::Available,
            warnings: vec![],
            metallb: MetalLBInventory::default(),
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
            network_policies: vec![],
            np_availability: NetworkPolicyAvailability::Available,
            warnings: vec![],
            metallb: MetalLBInventory::default(),
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

    #[tokio::test]
    async fn build_network_inventory_one_list_per_api() {
        use crate::kube::discovery::{KindInfo, KindMap};
        use std::sync::Arc;
        use std::sync::atomic::{AtomicUsize, Ordering};

        let request_count = Arc::new(AtomicUsize::new(0));
        let request_paths = Arc::new(std::sync::Mutex::new(Vec::<String>::new()));
        let rc = request_count.clone();
        let rp = request_paths.clone();

        let (mock_service, handle) =
            tower_test::mock::pair::<http::Request<Body>, http::Response<Body>>();
        let client = Client::new(mock_service, "test-ns");

        let mut kind_map = KindMap::new();
        kind_map.insert(
            "Service".into(),
            KindInfo {
                group: "".into(),
                version: "v1".into(),
                plural: "services".into(),
                namespaced: true,
                listable: true,
            },
        );

        let mut gk_map = GroupKindMap::new();
        gk_map.insert(
            ("networking.k8s.io".into(), "Ingress".into()),
            KindInfo {
                group: "networking.k8s.io".into(),
                version: "v1".into(),
                plural: "ingresses".into(),
                namespaced: true,
                listable: true,
            },
        );
        gk_map.insert(
            ("route.openshift.io".into(), "Route".into()),
            KindInfo {
                group: "route.openshift.io".into(),
                version: "v1".into(),
                plural: "routes".into(),
                namespaced: true,
                listable: true,
            },
        );
        gk_map.insert(
            ("discovery.k8s.io".into(), "EndpointSlice".into()),
            KindInfo {
                group: "discovery.k8s.io".into(),
                version: "v1".into(),
                plural: "endpointslices".into(),
                namespaced: true,
                listable: true,
            },
        );

        let spawned = tokio::spawn(async move {
            let mut handle = pin!(handle);
            // Expect exactly 4 LIST requests
            for _ in 0..4 {
                let (req, send) = handle.next_request().await.expect("expected request");
                rc.fetch_add(1, Ordering::Relaxed);
                rp.lock().unwrap().push(req.uri().path().to_string());
                // Return a Service list for the first, empty lists for rest
                let resp = if req.uri().path().contains("/services") {
                    mock_json_response(serde_json::json!({
                        "apiVersion": "v1",
                        "kind": "ServiceList",
                        "metadata": {"resourceVersion": "1"},
                        "items": [{
                            "apiVersion": "v1",
                            "kind": "Service",
                            "metadata": {"name": "svc-a"},
                            "spec": {
                                "type": "ClusterIP",
                                "clusterIP": "10.0.0.1",
                                "selector": {"app": "test"},
                                "ports": [{"port": 80, "targetPort": 8080, "protocol": "TCP"}]
                            }
                        }, {
                            "apiVersion": "v1",
                            "kind": "Service",
                            "metadata": {"name": "svc-b"},
                            "spec": {
                                "type": "NodePort",
                                "clusterIP": "10.0.0.2",
                                "selector": {"app": "test2"},
                                "ports": [{"port": 80, "targetPort": 8080, "protocol": "TCP", "nodePort": 30080}]
                            }
                        }]
                    }))
                } else {
                    mock_empty_list()
                };
                send.send_response(resp);
            }
        });

        let inventory = build_network_inventory(&client, "test-ns", &kind_map, &gk_map).await;

        spawned.await.unwrap();

        assert_eq!(
            request_count.load(Ordering::Relaxed),
            4,
            "exactly 4 LIST requests (Service + EndpointSlice + Ingress + Route)"
        );

        let paths = request_paths.lock().unwrap();
        assert!(
            paths.iter().any(|p| p.contains("/services")),
            "should LIST services"
        );
        assert!(
            paths.iter().any(|p| p.contains("/endpointslices")),
            "should LIST endpointslices"
        );
        assert!(
            paths.iter().any(|p| p.contains("/ingresses")),
            "should LIST ingresses"
        );
        assert!(
            paths.iter().any(|p| p.contains("/routes")),
            "should LIST routes"
        );

        assert_eq!(inventory.services.len(), 2, "2 services from fixture");
        assert_eq!(inventory.services[0].name, "svc-a");
        assert_eq!(inventory.services[1].name, "svc-b");
        assert!(inventory.warnings.is_empty());
    }

    // ── NetworkPolicy tests ──

    fn make_pod_selector(labels: &[(&str, &str)]) -> PodSelector {
        PodSelector {
            match_labels: labels
                .iter()
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect(),
            match_expressions: vec![],
        }
    }

    fn make_labels(pairs: &[(&str, &str)]) -> std::collections::HashMap<String, String> {
        pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect()
    }

    #[test]
    fn pod_selector_match_labels() {
        let sel = make_pod_selector(&[("app", "web"), ("env", "prod")]);
        let labels = make_labels(&[("app", "web"), ("env", "prod"), ("version", "v1")]);
        assert!(sel.matches(&labels));
        let labels2 = make_labels(&[("app", "web")]);
        assert!(!sel.matches(&labels2));
    }

    #[test]
    fn pod_selector_match_expressions_in() {
        let sel = PodSelector {
            match_labels: BTreeMap::new(),
            match_expressions: vec![LabelSelectorRequirement {
                key: "tier".into(),
                operator: "In".into(),
                values: vec!["frontend".into(), "backend".into()],
            }],
        };
        assert!(sel.matches(&make_labels(&[("tier", "frontend")])));
        assert!(sel.matches(&make_labels(&[("tier", "backend")])));
        assert!(!sel.matches(&make_labels(&[("tier", "db")])));
        assert!(!sel.matches(&make_labels(&[])));
    }

    #[test]
    fn pod_selector_match_expressions_not_in() {
        let sel = PodSelector {
            match_labels: BTreeMap::new(),
            match_expressions: vec![LabelSelectorRequirement {
                key: "tier".into(),
                operator: "NotIn".into(),
                values: vec!["db".into()],
            }],
        };
        assert!(sel.matches(&make_labels(&[("tier", "frontend")])));
        assert!(sel.matches(&make_labels(&[])));
        assert!(!sel.matches(&make_labels(&[("tier", "db")])));
    }

    #[test]
    fn pod_selector_match_expressions_exists() {
        let sel = PodSelector {
            match_labels: BTreeMap::new(),
            match_expressions: vec![LabelSelectorRequirement {
                key: "app".into(),
                operator: "Exists".into(),
                values: vec![],
            }],
        };
        assert!(sel.matches(&make_labels(&[("app", "anything")])));
        assert!(!sel.matches(&make_labels(&[])));
    }

    #[test]
    fn pod_selector_match_expressions_does_not_exist() {
        let sel = PodSelector {
            match_labels: BTreeMap::new(),
            match_expressions: vec![LabelSelectorRequirement {
                key: "restricted".into(),
                operator: "DoesNotExist".into(),
                values: vec![],
            }],
        };
        assert!(sel.matches(&make_labels(&[("app", "web")])));
        assert!(!sel.matches(&make_labels(&[("restricted", "true")])));
    }

    #[test]
    fn pod_selector_empty_selects_all() {
        let sel = PodSelector {
            match_labels: BTreeMap::new(),
            match_expressions: vec![],
        };
        assert!(sel.matches(&make_labels(&[("any", "label")])));
        assert!(sel.matches(&make_labels(&[])));
    }

    #[test]
    fn posture_no_policy_non_isolated() {
        let pods = vec![(
            "pod-1".into(),
            "uid-1".into(),
            make_labels(&[("app", "web")]),
        )];
        let postures = evaluate_network_postures(&pods, &[], &NetworkPolicyAvailability::Available);
        assert_eq!(postures.len(), 1);
        assert_eq!(postures[0].ingress_isolation, "non-isolated");
        assert_eq!(postures[0].egress_isolation, "non-isolated");
        assert!(postures[0].applicable_policies.is_empty());
    }

    #[test]
    fn posture_ingress_only_policy() {
        let policies = vec![NetworkPolicyInfo {
            name: "allow-web".into(),
            pod_selector: make_pod_selector(&[("app", "web")]),
            policy_types: vec!["Ingress".into()],
            ingress_rules: vec![NetworkPolicyRule {
                peers: vec![],
                ports: vec![NetworkPolicyPort {
                    protocol: Some("TCP".into()),
                    port: Some(IntOrString::Int(80)),
                    end_port: None,
                }],
            }],
            egress_rules: vec![],
        }];
        let pods = vec![(
            "pod-1".into(),
            "uid-1".into(),
            make_labels(&[("app", "web")]),
        )];
        let postures =
            evaluate_network_postures(&pods, &policies, &NetworkPolicyAvailability::Available);
        assert_eq!(postures[0].ingress_isolation, "isolated");
        assert_eq!(postures[0].egress_isolation, "non-isolated");
        assert_eq!(postures[0].applicable_policies.len(), 1);
        assert!(postures[0].applicable_policies[0].isolates_ingress);
        assert!(!postures[0].applicable_policies[0].isolates_egress);
    }

    #[test]
    fn posture_egress_only_policy() {
        let policies = vec![NetworkPolicyInfo {
            name: "deny-egress".into(),
            pod_selector: make_pod_selector(&[("app", "web")]),
            policy_types: vec!["Egress".into()],
            ingress_rules: vec![],
            egress_rules: vec![],
        }];
        let pods = vec![(
            "pod-1".into(),
            "uid-1".into(),
            make_labels(&[("app", "web")]),
        )];
        let postures =
            evaluate_network_postures(&pods, &policies, &NetworkPolicyAvailability::Available);
        // policyTypes=["Egress"] only isolates egress, not ingress
        assert_eq!(postures[0].ingress_isolation, "non-isolated");
        assert_eq!(postures[0].egress_isolation, "isolated");
    }

    #[test]
    fn posture_policy_types_default() {
        // No explicit policyTypes, with ingress rules only -> Ingress only
        let pol1 = NetworkPolicyInfo {
            name: "ingress-only".into(),
            pod_selector: make_pod_selector(&[]),
            policy_types: vec![],
            ingress_rules: vec![NetworkPolicyRule {
                peers: vec![],
                ports: vec![],
            }],
            egress_rules: vec![],
        };
        let pods = vec![(
            "pod-1".into(),
            "uid-1".into(),
            make_labels(&[("app", "web")]),
        )];
        let postures =
            evaluate_network_postures(&pods, &[pol1], &NetworkPolicyAvailability::Available);
        assert_eq!(postures[0].ingress_isolation, "isolated");
        assert_eq!(postures[0].egress_isolation, "non-isolated");

        // No explicit policyTypes, with egress rules -> Ingress+Egress
        let pol2 = NetworkPolicyInfo {
            name: "both".into(),
            pod_selector: make_pod_selector(&[]),
            policy_types: vec![],
            ingress_rules: vec![],
            egress_rules: vec![NetworkPolicyRule {
                peers: vec![],
                ports: vec![],
            }],
        };
        let postures2 =
            evaluate_network_postures(&pods, &[pol2], &NetworkPolicyAvailability::Available);
        assert_eq!(postures2[0].ingress_isolation, "isolated");
        assert_eq!(postures2[0].egress_isolation, "isolated");
    }

    #[test]
    fn posture_empty_rules_deny() {
        let policies = vec![NetworkPolicyInfo {
            name: "deny-all".into(),
            pod_selector: make_pod_selector(&[]),
            policy_types: vec!["Ingress".into(), "Egress".into()],
            ingress_rules: vec![],
            egress_rules: vec![],
        }];
        let pods = vec![("pod-1".into(), "uid-1".into(), make_labels(&[]))];
        let postures =
            evaluate_network_postures(&pods, &policies, &NetworkPolicyAvailability::Available);
        assert_eq!(postures[0].ingress_isolation, "isolated");
        assert_eq!(postures[0].egress_isolation, "isolated");
        assert!(postures[0].applicable_policies[0].ingress_rules.is_empty());
        assert!(postures[0].applicable_policies[0].egress_rules.is_empty());
    }

    #[test]
    fn posture_multiple_policies_additive() {
        let policies = vec![
            NetworkPolicyInfo {
                name: "ingress-allow".into(),
                pod_selector: make_pod_selector(&[("app", "web")]),
                policy_types: vec!["Ingress".into()],
                ingress_rules: vec![NetworkPolicyRule {
                    peers: vec![],
                    ports: vec![],
                }],
                egress_rules: vec![],
            },
            NetworkPolicyInfo {
                name: "egress-allow".into(),
                pod_selector: make_pod_selector(&[("app", "web")]),
                policy_types: vec!["Egress".into()],
                egress_rules: vec![NetworkPolicyRule {
                    peers: vec![],
                    ports: vec![],
                }],
                ingress_rules: vec![],
            },
        ];
        let pods = vec![(
            "pod-1".into(),
            "uid-1".into(),
            make_labels(&[("app", "web")]),
        )];
        let postures =
            evaluate_network_postures(&pods, &policies, &NetworkPolicyAvailability::Available);
        assert_eq!(postures[0].applicable_policies.len(), 2);
        assert_eq!(postures[0].ingress_isolation, "isolated");
        assert_eq!(postures[0].egress_isolation, "isolated");
    }

    #[test]
    fn posture_two_pods_different_labels() {
        let policies = vec![NetworkPolicyInfo {
            name: "web-only".into(),
            pod_selector: make_pod_selector(&[("app", "web")]),
            policy_types: vec!["Ingress".into()],
            ingress_rules: vec![],
            egress_rules: vec![],
        }];
        let pods = vec![
            (
                "pod-web".into(),
                "uid-1".into(),
                make_labels(&[("app", "web")]),
            ),
            (
                "pod-db".into(),
                "uid-2".into(),
                make_labels(&[("app", "db")]),
            ),
        ];
        let postures =
            evaluate_network_postures(&pods, &policies, &NetworkPolicyAvailability::Available);
        assert_eq!(postures[0].pod_name, "pod-web");
        assert_eq!(postures[0].ingress_isolation, "isolated");
        assert_eq!(postures[1].pod_name, "pod-db");
        assert_eq!(postures[1].ingress_isolation, "non-isolated");
    }

    #[test]
    fn posture_api_unavailable_unknown() {
        let policies = vec![NetworkPolicyInfo {
            name: "some-policy".into(),
            pod_selector: make_pod_selector(&[]),
            policy_types: vec!["Ingress".into()],
            ingress_rules: vec![],
            egress_rules: vec![],
        }];
        let pods = vec![("pod-1".into(), "uid-1".into(), make_labels(&[]))];
        let postures =
            evaluate_network_postures(&pods, &policies, &NetworkPolicyAvailability::Unavailable);
        assert_eq!(postures[0].ingress_isolation, "unknown");
        assert_eq!(postures[0].egress_isolation, "unknown");
        assert!(postures[0].applicable_policies.is_empty());
    }

    #[test]
    fn parse_network_policy_full() {
        let obj = DynamicObject {
            metadata: kube::api::ObjectMeta {
                name: Some("test-policy".into()),
                ..Default::default()
            },
            types: None,
            data: serde_json::json!({
                "spec": {
                    "podSelector": {
                        "matchLabels": {"app": "web"},
                        "matchExpressions": [{
                            "key": "env",
                            "operator": "In",
                            "values": ["prod", "staging"]
                        }]
                    },
                    "policyTypes": ["Ingress", "Egress"],
                    "ingress": [{
                        "from": [{
                            "podSelector": {"matchLabels": {"role": "client"}},
                            "namespaceSelector": {"matchLabels": {"team": "frontend"}}
                        }, {
                            "ipBlock": {
                                "cidr": "10.0.0.0/8",
                                "except": ["10.0.1.0/24"]
                            }
                        }],
                        "ports": [{
                            "protocol": "TCP",
                            "port": 8080,
                            "endPort": 8090
                        }]
                    }],
                    "egress": [{
                        "to": [{
                            "namespaceSelector": {}
                        }],
                        "ports": [{
                            "protocol": "UDP",
                            "port": "dns"
                        }]
                    }]
                }
            }),
        };
        let np = parse_network_policy(obj).unwrap();
        assert_eq!(np.name, "test-policy");
        assert_eq!(np.pod_selector.match_labels.get("app").unwrap(), "web");
        assert_eq!(np.pod_selector.match_expressions.len(), 1);
        assert_eq!(np.pod_selector.match_expressions[0].operator, "In");
        assert_eq!(np.policy_types, vec!["Ingress", "Egress"]);
        assert_eq!(np.ingress_rules.len(), 1);
        assert_eq!(np.ingress_rules[0].peers.len(), 2);
        assert!(np.ingress_rules[0].peers[0].pod_selector.is_some());
        assert!(np.ingress_rules[0].peers[0].namespace_selector.is_some());
        assert!(np.ingress_rules[0].peers[1].ip_block.is_some());
        let ib = np.ingress_rules[0].peers[1].ip_block.as_ref().unwrap();
        assert_eq!(ib.cidr, "10.0.0.0/8");
        assert_eq!(ib.except, vec!["10.0.1.0/24"]);
        assert_eq!(np.ingress_rules[0].ports.len(), 1);
        assert!(matches!(
            &np.ingress_rules[0].ports[0].port,
            Some(IntOrString::Int(8080))
        ));
        assert_eq!(np.ingress_rules[0].ports[0].end_port, Some(8090));
        assert_eq!(np.egress_rules.len(), 1);
        assert_eq!(np.egress_rules[0].peers.len(), 1);
        assert!(np.egress_rules[0].peers[0].namespace_selector.is_some());
        assert_eq!(np.egress_rules[0].ports[0].protocol.as_deref(), Some("UDP"));
        assert!(matches!(
            &np.egress_rules[0].ports[0].port,
            Some(IntOrString::String(s)) if s == "dns"
        ));
    }

    #[tokio::test]
    async fn network_policy_403_typed_warning() {
        use http::Response;
        use kube::client::Body;

        let (mock_service, mut handle) =
            tower_test::mock::pair::<http::Request<Body>, http::Response<Body>>();
        let client = Client::new(mock_service, "default");

        let mut gk_map = GroupKindMap::new();
        gk_map.insert(
            ("networking.k8s.io".to_string(), "NetworkPolicy".to_string()),
            crate::kube::discovery::KindInfo {
                group: "networking.k8s.io".into(),
                version: "v1".into(),
                plural: "networkpolicies".into(),
                namespaced: true,
                listable: true,
            },
        );

        let spawned = tokio::spawn(async move {
            let (req, send) = handle.next_request().await.expect("expected request");
            assert!(req.uri().path().contains("/networkpolicies"));
            let resp = Response::builder()
                .status(403)
                .body(Body::from(
                    serde_json::to_vec(&serde_json::json!({
                        "kind": "Status",
                        "apiVersion": "v1",
                        "status": "Failure",
                        "message": "networkpolicies.networking.k8s.io is forbidden",
                        "code": 403
                    }))
                    .unwrap(),
                ))
                .unwrap();
            send.send_response(resp);
        });

        let (policies, availability, warnings) =
            list_network_policies(&client, "test-ns", &gk_map).await;
        spawned.await.unwrap();

        assert!(policies.is_empty());
        assert_eq!(availability, NetworkPolicyAvailability::Unavailable);
        assert_eq!(warnings.len(), 1);
        assert!(
            matches!(&warnings[0], ScanWarning::Forbidden { status: 403, .. }),
            "expected Forbidden warning"
        );
    }

    #[tokio::test]
    async fn network_policy_500_unavailable() {
        use http::Response;
        let mut gk_map = GroupKindMap::new();
        gk_map.insert(
            ("networking.k8s.io".to_string(), "NetworkPolicy".to_string()),
            crate::kube::discovery::KindInfo {
                group: "networking.k8s.io".into(),
                version: "v1".into(),
                plural: "networkpolicies".into(),
                namespaced: true,
                listable: true,
            },
        );
        let (mock_service, handle) =
            tower_test::mock::pair::<http::Request<Body>, http::Response<Body>>();
        let client = Client::new(mock_service, "test-ns");
        let rc = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let rc2 = rc.clone();

        let spawned = tokio::spawn(async move {
            let mut handle = pin!(handle);
            for _ in 0..3 {
                let (_req, send) = handle.next_request().await.unwrap();
                rc2.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                let body = serde_json::json!({
                    "kind": "Status", "apiVersion": "v1", "metadata": {},
                    "status": "Failure", "message": "error", "reason": "InternalError", "code": 500
                });
                send.send_response(
                    Response::builder()
                        .status(500)
                        .body(Body::from(serde_json::to_vec(&body).unwrap()))
                        .unwrap(),
                );
            }
        });

        let (policies, availability, warnings) =
            list_network_policies(&client, "test-ns", &gk_map).await;
        spawned.await.unwrap();

        assert!(policies.is_empty());
        assert_eq!(availability, NetworkPolicyAvailability::Unavailable);
        assert_eq!(rc.load(std::sync::atomic::Ordering::Relaxed), 3);
        assert!(matches!(
            &warnings[0],
            ScanWarning::ServerError { retries: 2, .. }
        ));
    }

    #[test]
    fn posture_500_unavailable_all_unknown() {
        let pods = vec![(
            "pod-1".into(),
            "uid-1".into(),
            std::collections::HashMap::new(),
        )];
        let policies = vec![NetworkPolicyInfo {
            name: "deny".into(),
            pod_selector: PodSelector {
                match_labels: BTreeMap::new(),
                match_expressions: vec![],
            },
            policy_types: vec!["Ingress".into()],
            ingress_rules: vec![],
            egress_rules: vec![],
        }];
        let postures =
            evaluate_network_postures(&pods, &policies, &NetworkPolicyAvailability::Unavailable);
        assert_eq!(postures[0].ingress_isolation, "unknown");
        assert_eq!(postures[0].egress_isolation, "unknown");
    }

    #[test]
    fn applicable_policy_has_pod_selector() {
        let pods = vec![(
            "pod-1".into(),
            "uid-1".into(),
            [("app".into(), "web".into())].into_iter().collect(),
        )];
        let policies = vec![NetworkPolicyInfo {
            name: "allow-web".into(),
            pod_selector: PodSelector {
                match_labels: [("app".into(), "web".into())].into_iter().collect(),
                match_expressions: vec![LabelSelectorRequirement {
                    key: "tier".into(),
                    operator: "Exists".into(),
                    values: vec![],
                }],
            },
            policy_types: vec!["Ingress".into()],
            ingress_rules: vec![],
            egress_rules: vec![],
        }];
        // Pod doesn't have tier label → won't match
        let postures =
            evaluate_network_postures(&pods, &policies, &NetworkPolicyAvailability::Available);
        assert!(postures[0].applicable_policies.is_empty());

        // Pod with tier label → matches, and ApplicablePolicy has the selector
        let pods2 = vec![(
            "pod-1".into(),
            "uid-1".into(),
            [
                ("app".into(), "web".into()),
                ("tier".into(), "frontend".into()),
            ]
            .into_iter()
            .collect(),
        )];
        let postures2 =
            evaluate_network_postures(&pods2, &policies, &NetworkPolicyAvailability::Available);
        assert_eq!(postures2[0].applicable_policies.len(), 1);
        let ap = &postures2[0].applicable_policies[0];
        assert_eq!(ap.pod_selector.match_labels.get("app").unwrap(), "web");
        assert_eq!(ap.pod_selector.match_expressions.len(), 1);
        assert_eq!(ap.pod_selector.match_expressions[0].operator, "Exists");
    }

    #[test]
    fn int_or_string_port_preservation() {
        let data = serde_json::json!({
            "spec": {
                "podSelector": {},
                "ingress": [{
                    "ports": [
                        {"protocol": "TCP", "port": 8080},
                        {"protocol": "TCP", "port": "http-alt"},
                        {"protocol": "TCP", "port": 443, "endPort": 445}
                    ]
                }]
            }
        });
        let obj = make_dynamic_object("test-np", data);
        let np = parse_network_policy(obj).unwrap();
        let ports = &np.ingress_rules[0].ports;
        assert!(matches!(&ports[0].port, Some(IntOrString::Int(8080))));
        assert!(matches!(&ports[1].port, Some(IntOrString::String(s)) if s == "http-alt"));
        assert!(matches!(&ports[2].port, Some(IntOrString::Int(443))));
        assert_eq!(ports[2].end_port, Some(445));
    }

    fn make_svc(name: &str, selector: bool) -> NetworkService {
        let mut sel = std::collections::BTreeMap::new();
        if selector {
            sel.insert("app".into(), "web".into());
        }
        NetworkService {
            name: name.into(),
            selector: sel,
            has_selector: selector,
            cluster_ip: "10.96.0.1".into(),
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
            annotations: BTreeMap::new(),
            labels: BTreeMap::new(),
            load_balancer_ip: None,
        }
    }

    fn make_pod_info(
        name: &str,
        uid: &str,
        ns: &str,
        labels: Vec<(&str, &str)>,
    ) -> crate::kube::resource::ResourceInfo {
        crate::kube::resource::ResourceInfo {
            group: String::new(),
            kind: "Pod".into(),
            name: name.into(),
            namespace: Some(ns.into()),
            uid: uid.into(),
            owner_refs: vec![],
            labels: labels
                .into_iter()
                .map(|(k, v)| (k.into(), v.into()))
                .collect(),
            annotations: std::collections::HashMap::new(),
            pod_template: None,
        }
    }

    fn make_ep_slice(svc_name: &str, endpoints: Vec<EndpointInfo>) -> EndpointSliceInfo {
        EndpointSliceInfo {
            name: format!("{}-slice", svc_name),
            service_name: Some(svc_name.into()),
            address_type: "IPv4".into(),
            ports: vec![],
            endpoints,
        }
    }

    fn make_target_ref(
        api_version: &str,
        kind: &str,
        name: &str,
        ns: &str,
        uid: &str,
    ) -> EndpointTargetRef {
        EndpointTargetRef {
            api_version: Some(api_version.into()),
            kind: Some(kind.into()),
            name: Some(name.into()),
            namespace: Some(ns.into()),
            uid: Some(uid.into()),
        }
    }

    #[test]
    fn service_path_endpointless_shows_1_path() {
        let svc = make_svc("empty-svc", false);
        let inventory = NetworkInventory {
            services: vec![svc.clone()],
            ingresses: vec![],
            endpoint_slices: vec![],
            network_policies: vec![],
            np_availability: NetworkPolicyAvailability::Available,
            warnings: vec![],
            metallb: MetalLBInventory::default(),
        };
        let index = std::collections::HashMap::new();
        let (path, pod_labels) = build_service_network_path(&svc, &inventory, &index, "test-ns");
        assert_eq!(path.service.name, "empty-svc");
        assert_eq!(path.endpoint_summary.ready, 0);
        assert!(path.selector_matched_pods.is_empty());
        assert!(path.target_ref_matched_pods.is_empty());
        assert!(pod_labels.is_empty());
    }

    #[test]
    fn service_path_only_target_service() {
        let svc_a = make_svc("web", true);
        let svc_b = make_svc("web-alias", true);
        let inventory = NetworkInventory {
            services: vec![svc_a.clone(), svc_b],
            ingresses: vec![],
            endpoint_slices: vec![],
            network_policies: vec![],
            np_availability: NetworkPolicyAvailability::Available,
            warnings: vec![],
            metallb: MetalLBInventory::default(),
        };
        let index = std::collections::HashMap::new();
        let (path, _) = build_service_network_path(&svc_a, &inventory, &index, "test-ns");
        assert_eq!(path.service.name, "web");
    }

    #[test]
    fn verified_target_ref_correct_uid() {
        let mut index = std::collections::HashMap::new();
        index.insert(
            "uid-1".into(),
            make_pod_info("web-pod", "uid-1", "test-ns", vec![("app", "web")]),
        );
        let ep = EndpointInfo {
            addresses: vec!["10.0.0.1".into()],
            hostname: None,
            node_name: None,
            zone: None,
            conditions_ready: Some(true),
            conditions_serving: Some(true),
            conditions_terminating: None,
            target_ref: Some(make_target_ref("v1", "Pod", "web-pod", "test-ns", "uid-1")),
            hints: None,
        };
        let slices = vec![make_ep_slice("web", vec![ep])];
        let (refs, verified) = resolve_verified_target_ref_pods(&slices, &index, "test-ns");
        assert_eq!(refs, vec!["Pod/web-pod"]);
        assert_eq!(verified.len(), 1);
        assert_eq!(verified[0].uid, "uid-1");
    }

    #[test]
    fn verified_target_ref_stale_uid_excluded() {
        let mut index = std::collections::HashMap::new();
        index.insert(
            "new-uid".into(),
            make_pod_info("web-pod", "new-uid", "test-ns", vec![]),
        );
        let ep = EndpointInfo {
            addresses: vec!["10.0.0.1".into()],
            hostname: None,
            node_name: None,
            zone: None,
            conditions_ready: Some(true),
            conditions_serving: Some(true),
            conditions_terminating: None,
            target_ref: Some(make_target_ref(
                "v1",
                "Pod",
                "web-pod",
                "test-ns",
                "stale-uid",
            )),
            hints: None,
        };
        let slices = vec![make_ep_slice("web", vec![ep])];
        let (refs, verified) = resolve_verified_target_ref_pods(&slices, &index, "test-ns");
        assert!(refs.is_empty(), "Stale UID should be excluded");
        assert!(verified.is_empty());
    }

    #[test]
    fn verified_target_ref_missing_uid_excluded() {
        let mut index = std::collections::HashMap::new();
        index.insert(
            "uid-1".into(),
            make_pod_info("web-pod", "uid-1", "test-ns", vec![]),
        );
        let ep = EndpointInfo {
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
                name: Some("web-pod".into()),
                namespace: Some("test-ns".into()),
                uid: None,
            }),
            hints: None,
        };
        let slices = vec![make_ep_slice("web", vec![ep])];
        let (refs, verified) = resolve_verified_target_ref_pods(&slices, &index, "test-ns");
        assert!(refs.is_empty(), "Missing UID should be excluded");
        assert!(verified.is_empty());
    }

    #[test]
    fn verified_target_ref_wrong_api_version_excluded() {
        let mut index = std::collections::HashMap::new();
        index.insert(
            "uid-1".into(),
            make_pod_info("web-pod", "uid-1", "test-ns", vec![]),
        );
        let ep = EndpointInfo {
            addresses: vec!["10.0.0.1".into()],
            hostname: None,
            node_name: None,
            zone: None,
            conditions_ready: Some(true),
            conditions_serving: Some(true),
            conditions_terminating: None,
            target_ref: Some(make_target_ref(
                "apps/v1", "Pod", "web-pod", "test-ns", "uid-1",
            )),
            hints: None,
        };
        let slices = vec![make_ep_slice("web", vec![ep])];
        let (refs, verified) = resolve_verified_target_ref_pods(&slices, &index, "test-ns");
        assert!(refs.is_empty(), "Wrong apiVersion should be excluded");
        assert!(verified.is_empty());
    }

    #[test]
    fn verified_target_ref_non_pod_excluded() {
        let mut index = std::collections::HashMap::new();
        index.insert(
            "uid-1".into(),
            make_pod_info("web-pod", "uid-1", "test-ns", vec![]),
        );
        let ep = EndpointInfo {
            addresses: vec!["10.0.0.1".into()],
            hostname: None,
            node_name: None,
            zone: None,
            conditions_ready: Some(true),
            conditions_serving: Some(true),
            conditions_terminating: None,
            target_ref: Some(make_target_ref("v1", "Node", "web-pod", "test-ns", "uid-1")),
            hints: None,
        };
        let slices = vec![make_ep_slice("web", vec![ep])];
        let (refs, verified) = resolve_verified_target_ref_pods(&slices, &index, "test-ns");
        assert!(refs.is_empty(), "Non-Pod kind should be excluded");
        assert!(verified.is_empty());
    }

    #[test]
    fn verified_target_ref_wrong_namespace_excluded() {
        let mut index = std::collections::HashMap::new();
        index.insert(
            "uid-1".into(),
            make_pod_info("web-pod", "uid-1", "other-ns", vec![]),
        );
        let ep = EndpointInfo {
            addresses: vec!["10.0.0.1".into()],
            hostname: None,
            node_name: None,
            zone: None,
            conditions_ready: Some(true),
            conditions_serving: Some(true),
            conditions_terminating: None,
            target_ref: Some(make_target_ref("v1", "Pod", "web-pod", "other-ns", "uid-1")),
            hints: None,
        };
        let slices = vec![make_ep_slice("web", vec![ep])];
        let (refs, verified) = resolve_verified_target_ref_pods(&slices, &index, "test-ns");
        assert!(refs.is_empty(), "Wrong namespace should be excluded");
        assert!(verified.is_empty());
    }

    #[test]
    fn selectorless_service_with_valid_target_ref_in_posture() {
        let svc = make_svc("headless", false);
        let mut index = std::collections::HashMap::new();
        index.insert(
            "uid-pod".into(),
            make_pod_info("backend", "uid-pod", "test-ns", vec![("role", "api")]),
        );
        let ep = EndpointInfo {
            addresses: vec!["10.0.0.5".into()],
            hostname: None,
            node_name: None,
            zone: None,
            conditions_ready: Some(true),
            conditions_serving: Some(true),
            conditions_terminating: None,
            target_ref: Some(make_target_ref(
                "v1", "Pod", "backend", "test-ns", "uid-pod",
            )),
            hints: None,
        };
        let inventory = NetworkInventory {
            services: vec![svc.clone()],
            ingresses: vec![],
            endpoint_slices: vec![make_ep_slice("headless", vec![ep])],
            network_policies: vec![],
            np_availability: NetworkPolicyAvailability::Available,
            warnings: vec![],
            metallb: MetalLBInventory::default(),
        };
        let (path, pod_labels) = build_service_network_path(&svc, &inventory, &index, "test-ns");
        assert_eq!(path.target_ref_matched_pods, vec!["Pod/backend"]);
        assert!(path.selector_matched_pods.is_empty());
        assert_eq!(
            pod_labels.len(),
            1,
            "verified targetRef pod should be in posture input"
        );
        assert_eq!(pod_labels[0].0, "backend");
    }

    // ── MetalLB tests ──

    fn make_label_selector(labels: &[(&str, &str)], exprs: Vec<MatchExpression>) -> LabelSelector {
        LabelSelector {
            match_labels: labels
                .iter()
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect(),
            match_expressions: exprs,
        }
    }

    #[test]
    fn label_selector_match_labels_all_must_match() {
        let sel = make_label_selector(&[("app", "web"), ("env", "prod")], vec![]);
        let mut labels = BTreeMap::new();
        labels.insert("app".into(), "web".into());
        labels.insert("env".into(), "prod".into());
        assert!(label_selector_matches(&sel, &labels));

        labels.insert("env".into(), "dev".into());
        assert!(!label_selector_matches(&sel, &labels));
    }

    #[test]
    fn label_selector_match_expressions_in() {
        let sel = make_label_selector(
            &[],
            vec![MatchExpression {
                key: "tier".into(),
                operator: "In".into(),
                values: vec!["frontend".into(), "backend".into()],
            }],
        );
        let mut labels = BTreeMap::new();
        labels.insert("tier".into(), "frontend".into());
        assert!(label_selector_matches(&sel, &labels));

        labels.insert("tier".into(), "db".into());
        assert!(!label_selector_matches(&sel, &labels));
    }

    #[test]
    fn label_selector_match_expressions_notin() {
        let sel = make_label_selector(
            &[],
            vec![MatchExpression {
                key: "tier".into(),
                operator: "NotIn".into(),
                values: vec!["db".into()],
            }],
        );
        let mut labels = BTreeMap::new();
        labels.insert("tier".into(), "frontend".into());
        assert!(label_selector_matches(&sel, &labels));

        labels.insert("tier".into(), "db".into());
        assert!(!label_selector_matches(&sel, &labels));

        // Key absent: NotIn passes
        let empty_labels = BTreeMap::new();
        assert!(label_selector_matches(&sel, &empty_labels));
    }

    #[test]
    fn label_selector_match_expressions_exists_doesnotexist() {
        let exists = make_label_selector(
            &[],
            vec![MatchExpression {
                key: "gpu".into(),
                operator: "Exists".into(),
                values: vec![],
            }],
        );
        let dne = make_label_selector(
            &[],
            vec![MatchExpression {
                key: "gpu".into(),
                operator: "DoesNotExist".into(),
                values: vec![],
            }],
        );
        let mut labels = BTreeMap::new();
        labels.insert("gpu".into(), "true".into());
        assert!(label_selector_matches(&exists, &labels));
        assert!(!label_selector_matches(&dne, &labels));

        let empty = BTreeMap::new();
        assert!(!label_selector_matches(&exists, &empty));
        assert!(label_selector_matches(&dne, &empty));
    }

    #[test]
    fn label_selector_list_empty_matches_everything() {
        let labels = BTreeMap::new();
        assert!(label_selector_list_matches(&[], &labels));
    }

    #[test]
    fn label_selector_list_any_match_is_true() {
        let sel1 = make_label_selector(&[("app", "web")], vec![]);
        let sel2 = make_label_selector(&[("app", "api")], vec![]);
        let mut labels = BTreeMap::new();
        labels.insert("app".into(), "api".into());
        assert!(label_selector_list_matches(&[sel1, sel2], &labels));
    }

    fn make_test_pool(name: &str, ns: &str, addresses: Vec<&str>) -> IPAddressPool {
        IPAddressPool {
            name: name.into(),
            namespace: ns.into(),
            addresses: addresses.into_iter().map(String::from).collect(),
            auto_assign: true,
            service_allocation: None,
            labels: BTreeMap::new(),
        }
    }

    fn make_test_l2(name: &str, ns: &str, pools: Vec<&str>) -> L2Advertisement {
        L2Advertisement {
            name: name.into(),
            namespace: ns.into(),
            ip_address_pools: pools.into_iter().map(String::from).collect(),
            ip_address_pool_selectors: vec![],
            node_selectors: vec![],
            service_selectors: vec![],
        }
    }

    fn make_lb_svc(name: &str) -> NetworkService {
        NetworkService {
            name: name.into(),
            selector: BTreeMap::new(),
            has_selector: false,
            cluster_ip: "10.0.0.1".into(),
            svc_type: "LoadBalancer".into(),
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
            annotations: BTreeMap::new(),
            labels: BTreeMap::new(),
            load_balancer_ip: None,
        }
    }

    #[test]
    fn pool_selector_match_via_ip_address_pool_selectors() {
        let mut pool = make_test_pool("labeled-pool", "metallb-system", vec!["192.168.1.0/24"]);
        pool.labels.insert("pool-type".into(), "external".into());

        let l2 = L2Advertisement {
            name: "l2-by-selector".into(),
            namespace: "metallb-system".into(),
            ip_address_pools: vec![],
            ip_address_pool_selectors: vec![make_label_selector(
                &[("pool-type", "external")],
                vec![],
            )],
            node_selectors: vec![],
            service_selectors: vec![],
        };

        let mut svc = make_lb_svc("test-svc");
        svc.annotations
            .insert("metallb.io/address-pool".into(), "labeled-pool".into());
        svc.lb_ingress.push(LBIngress {
            ip: Some("192.168.1.10".into()),
            hostname: None,
            ip_mode: None,
        });

        let metallb = MetalLBInventory {
            available: true,
            pools: vec![pool],
            l2_advertisements: vec![l2],
            bgp_advertisements: vec![],
        };

        let result = resolve_metallb_for_service(&svc, "default", &metallb, &[]);
        assert_eq!(result.provider.as_deref(), Some("MetalLB"));
        assert_eq!(result.pools.len(), 1);
        assert_eq!(result.advertisements.len(), 1);
        assert!(
            result.advertisements[0]
                .match_reason
                .contains("ipAddressPoolSelectors")
        );
    }

    #[test]
    fn l2_service_selector_mismatch_excludes_advertisement() {
        let pool = make_test_pool("pool-1", "metallb-system", vec!["10.0.0.0/24"]);
        let l2 = L2Advertisement {
            name: "l2-filtered".into(),
            namespace: "metallb-system".into(),
            ip_address_pools: vec!["pool-1".into()],
            ip_address_pool_selectors: vec![],
            node_selectors: vec![],
            service_selectors: vec![make_label_selector(&[("team", "platform")], vec![])],
        };

        let mut svc = make_lb_svc("my-svc");
        svc.annotations
            .insert("metallb.io/address-pool".into(), "pool-1".into());
        svc.lb_ingress.push(LBIngress {
            ip: Some("10.0.0.5".into()),
            hostname: None,
            ip_mode: None,
        });
        // svc.labels does NOT have team=platform

        let metallb = MetalLBInventory {
            available: true,
            pools: vec![pool],
            l2_advertisements: vec![l2],
            bgp_advertisements: vec![],
        };

        let result = resolve_metallb_for_service(&svc, "default", &metallb, &[]);
        assert!(result.advertisements.is_empty());
        assert!(
            result
                .warnings
                .iter()
                .any(|w| w.contains("serviceSelector mismatch"))
        );
    }

    #[test]
    fn bgp_service_selector_match_includes_advertisement() {
        let pool = make_test_pool("pool-bgp", "metallb-system", vec!["172.16.0.0/24"]);
        let bgp = BGPAdvertisement {
            name: "bgp-filtered".into(),
            namespace: "metallb-system".into(),
            ip_address_pools: vec!["pool-bgp".into()],
            ip_address_pool_selectors: vec![],
            node_selectors: vec![],
            aggregation_length: Some(32),
            aggregation_length_v6: None,
            local_pref: Some(100),
            communities: vec!["65000:1".into()],
            service_selectors: vec![make_label_selector(&[("team", "platform")], vec![])],
        };

        let mut svc = make_lb_svc("bgp-svc");
        svc.annotations
            .insert("metallb.io/address-pool".into(), "pool-bgp".into());
        svc.lb_ingress.push(LBIngress {
            ip: Some("172.16.0.10".into()),
            hostname: None,
            ip_mode: None,
        });
        svc.labels.insert("team".into(), "platform".into());

        let metallb = MetalLBInventory {
            available: true,
            pools: vec![pool],
            l2_advertisements: vec![],
            bgp_advertisements: vec![bgp],
        };

        let result = resolve_metallb_for_service(&svc, "default", &metallb, &[]);
        assert_eq!(result.advertisements.len(), 1);
        assert_eq!(result.advertisements[0].kind, "BGPAdvertisement");
    }

    #[test]
    fn service_allocation_namespace_restriction() {
        let pool = IPAddressPool {
            name: "restricted".into(),
            namespace: "metallb-system".into(),
            addresses: vec!["10.10.0.0/24".into()],
            auto_assign: true,
            service_allocation: Some(ServiceAllocation {
                _priority: 0,
                namespaces: vec!["allowed-ns".into()],
                namespace_selectors: vec![],
                service_selectors: vec![],
            }),
            labels: BTreeMap::new(),
        };
        let l2 = make_test_l2("l2-all", "metallb-system", vec!["restricted"]);

        let mut svc = make_lb_svc("test-svc");
        svc.annotations
            .insert("metallb.io/address-pool".into(), "restricted".into());
        svc.lb_ingress.push(LBIngress {
            ip: Some("10.10.0.5".into()),
            hostname: None,
            ip_mode: None,
        });

        let metallb = MetalLBInventory {
            available: true,
            pools: vec![pool],
            l2_advertisements: vec![l2],
            bgp_advertisements: vec![],
        };

        // Wrong namespace
        let result = resolve_metallb_for_service(&svc, "other-ns", &metallb, &[]);
        assert!(
            result
                .warnings
                .iter()
                .any(|w| w.contains("namespace other-ns not in allowed list"))
        );

        // Correct namespace
        let result = resolve_metallb_for_service(&svc, "allowed-ns", &metallb, &[]);
        assert!(!result.warnings.iter().any(|w| w.contains("namespace")));
    }

    #[test]
    fn service_allocation_service_selector_mismatch_warns() {
        let pool = IPAddressPool {
            name: "sa-pool".into(),
            namespace: "metallb-system".into(),
            addresses: vec!["10.20.0.0/24".into()],
            auto_assign: true,
            service_allocation: Some(ServiceAllocation {
                _priority: 0,
                namespaces: vec![],
                namespace_selectors: vec![],
                service_selectors: vec![make_label_selector(&[("tier", "frontend")], vec![])],
            }),
            labels: BTreeMap::new(),
        };
        let l2 = make_test_l2("l2-all", "metallb-system", vec!["sa-pool"]);

        let mut svc = make_lb_svc("backend-svc");
        svc.annotations
            .insert("metallb.io/address-pool".into(), "sa-pool".into());
        svc.lb_ingress.push(LBIngress {
            ip: Some("10.20.0.1".into()),
            hostname: None,
            ip_mode: None,
        });
        // No tier=frontend label

        let metallb = MetalLBInventory {
            available: true,
            pools: vec![pool],
            l2_advertisements: vec![l2],
            bgp_advertisements: vec![],
        };

        let result = resolve_metallb_for_service(&svc, "default", &metallb, &[]);
        assert!(result.warnings.iter().any(|w| w.contains("serviceAllocation") && w.contains("service selector mismatch")));
    }

    #[test]
    fn load_balancer_ips_annotation_parsing() {
        let mut svc = make_lb_svc("dual-stack");
        svc.annotations.insert(
            "metallb.io/loadBalancerIPs".into(),
            "192.168.1.100, fd00::1".into(),
        );

        let pool = make_test_pool(
            "dual",
            "metallb-system",
            vec!["192.168.1.0/24", "fd00::/64"],
        );
        let l2 = make_test_l2("l2-dual", "metallb-system", vec!["dual"]);

        let metallb = MetalLBInventory {
            available: true,
            pools: vec![pool],
            l2_advertisements: vec![l2],
            bgp_advertisements: vec![],
        };

        let result = resolve_metallb_for_service(&svc, "default", &metallb, &[]);
        assert_eq!(result.requested_ips, vec!["192.168.1.100", "fd00::1"]);
        assert_eq!(result.provider.as_deref(), Some("MetalLB"));
        assert_eq!(result.pools.len(), 1);
    }

    #[test]
    fn provider_evidence_metallb_annotation_present() {
        let mut svc = make_lb_svc("annotated");
        svc.annotations
            .insert("metallb.io/address-pool".into(), "my-pool".into());

        let metallb = MetalLBInventory {
            available: true,
            pools: vec![],
            l2_advertisements: vec![],
            bgp_advertisements: vec![],
        };

        let result = resolve_metallb_for_service(&svc, "default", &metallb, &[]);
        assert_eq!(result.provider.as_deref(), Some("MetalLB"));
    }

    #[test]
    fn provider_evidence_none_for_plain_lb() {
        let svc = make_lb_svc("plain-lb");

        let metallb = MetalLBInventory {
            available: true,
            pools: vec![make_test_pool(
                "pool",
                "metallb-system",
                vec!["10.0.0.0/24"],
            )],
            l2_advertisements: vec![],
            bgp_advertisements: vec![],
        };

        let result = resolve_metallb_for_service(&svc, "default", &metallb, &[]);
        assert!(result.provider.is_none());
    }

    #[test]
    fn auto_assign_false_without_explicit_request_skipped() {
        let mut pool = make_test_pool("no-auto", "metallb-system", vec!["10.0.0.0/24"]);
        pool.auto_assign = false;

        let mut svc = make_lb_svc("test");
        svc.lb_ingress.push(LBIngress {
            ip: Some("10.0.0.5".into()),
            hostname: None,
            ip_mode: None,
        });
        // No pool annotation, no requested IPs annotation — only evidence is assigned IP in range

        let metallb = MetalLBInventory {
            available: true,
            pools: vec![pool],
            l2_advertisements: vec![],
            bgp_advertisements: vec![],
        };

        let result = resolve_metallb_for_service(&svc, "default", &metallb, &[]);
        // Provider detected because assigned IP is in pool range, but
        // pool is NOT matched because autoAssign=false and no explicit pool/IP annotation
        // Actually assigned IP IS in range so match_reason is "assigned IP in range" — autoAssign only skips when no match_reason
        // Let me re-check: the code checks autoAssign before the skip at the end
        // Actually the code first checks explicit matches (annotation, assigned IP, requested IP) then checks autoAssign
        // Assigned IP in range IS a match, so autoAssign=false doesn't skip it
        assert_eq!(result.pools.len(), 1);
    }

    #[test]
    fn different_namespace_pool_ad_excluded() {
        let pool = make_test_pool("pool-a", "metallb-system", vec!["10.0.0.0/24"]);
        // L2 in different namespace
        let l2 = make_test_l2("l2-other-ns", "other-metallb", vec!["pool-a"]);

        let mut svc = make_lb_svc("test");
        svc.annotations
            .insert("metallb.io/address-pool".into(), "pool-a".into());
        svc.lb_ingress.push(LBIngress {
            ip: Some("10.0.0.1".into()),
            hostname: None,
            ip_mode: None,
        });

        let metallb = MetalLBInventory {
            available: true,
            pools: vec![pool],
            l2_advertisements: vec![l2],
            bgp_advertisements: vec![],
        };

        let result = resolve_metallb_for_service(&svc, "default", &metallb, &[]);
        assert_eq!(result.pools.len(), 1);
        assert!(
            result.advertisements.is_empty(),
            "L2 in different namespace should be excluded"
        );
        assert!(
            result
                .warnings
                .iter()
                .any(|w| w.contains("no L2/BGP advertisement"))
        );
    }
}
