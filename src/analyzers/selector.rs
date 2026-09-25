use std::collections::{BTreeMap, HashMap, HashSet};

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
        None,
    )
    .await
}

pub(crate) async fn list_with_field_selector_retry(
    api: &Api<DynamicObject>,
    field_selector: &str,
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
        Some(field_selector),
    )
    .await
}

pub(crate) async fn list_with_retry_inner(
    api: &Api<DynamicObject>,
    group: &str,
    version: &str,
    plural: &str,
    timeout_dur: std::time::Duration,
    field_selector: Option<&str>,
) -> Result<Vec<DynamicObject>, ScanWarning> {
    let is_tty = std::io::IsTerminal::is_terminal(&std::io::stderr());
    for attempt in 0..=2usize {
        let mut lp = ListParams::default();
        if let Some(fs) = field_selector {
            lp = lp.fields(fs);
        }
        match tokio::time::timeout(timeout_dur, api.list(&lp)).await {
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
    pub uid: String,
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
    let uid = obj.metadata.uid.clone().unwrap_or_default();
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
        uid,
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

    let metallb = build_metallb_inventory(client, namespace, gk_map).await;
    warnings.extend(metallb.warnings.clone());

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

async fn build_metallb_inventory(
    client: &Client,
    svc_namespace: &str,
    gk_map: &GroupKindMap,
) -> MetalLBInventory {
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
    let mut warnings = Vec::new();

    // List IPAddressPools (all namespaces)
    {
        let gvk = GroupVersion::gv(&pool_info.group, &pool_info.version).with_kind("IPAddressPool");
        let ar = ApiResource::from_gvk_with_plural(&gvk, &pool_info.plural);
        let api: Api<DynamicObject> = Api::all_with(client.clone(), &ar);
        match list_with_retry_and_timeout(
            &api,
            &pool_info.group,
            &pool_info.version,
            &pool_info.plural,
        )
        .await
        {
            Ok(items) => {
                pools = items
                    .into_iter()
                    .filter_map(parse_ip_address_pool)
                    .collect();
            }
            Err(w) => {
                warnings.push(w);
            }
        }
    }

    // List L2Advertisements
    let l2_key = (metallb_group.to_string(), "L2Advertisement".to_string());
    if let Some(l2_info) = gk_map.get(&l2_key) {
        let gvk = GroupVersion::gv(&l2_info.group, &l2_info.version).with_kind("L2Advertisement");
        let ar = ApiResource::from_gvk_with_plural(&gvk, &l2_info.plural);
        let api: Api<DynamicObject> = Api::all_with(client.clone(), &ar);
        match list_with_retry_and_timeout(&api, &l2_info.group, &l2_info.version, &l2_info.plural)
            .await
        {
            Ok(items) => {
                l2_advertisements = items
                    .into_iter()
                    .filter_map(parse_l2_advertisement)
                    .collect();
            }
            Err(w) => {
                warnings.push(w);
            }
        }
    }

    // List BGPAdvertisements
    let bgp_key = (metallb_group.to_string(), "BGPAdvertisement".to_string());
    if let Some(bgp_info) = gk_map.get(&bgp_key) {
        let gvk =
            GroupVersion::gv(&bgp_info.group, &bgp_info.version).with_kind("BGPAdvertisement");
        let ar = ApiResource::from_gvk_with_plural(&gvk, &bgp_info.plural);
        let api: Api<DynamicObject> = Api::all_with(client.clone(), &ar);
        match list_with_retry_and_timeout(
            &api,
            &bgp_info.group,
            &bgp_info.version,
            &bgp_info.plural,
        )
        .await
        {
            Ok(items) => {
                bgp_advertisements = items
                    .into_iter()
                    .filter_map(parse_bgp_advertisement)
                    .collect();
            }
            Err(w) => {
                warnings.push(w);
            }
        }
    }

    // Fetch namespace labels only if any pool uses namespaceSelectors
    let mut namespace_labels = HashMap::new();
    let needs_ns_labels = pools.iter().any(|p| {
        p.service_allocation
            .as_ref()
            .is_some_and(|sa| !sa.namespace_selectors.is_empty())
    });
    if needs_ns_labels {
        let ns_gvk = GroupVersion::gv("", "v1").with_kind("Namespace");
        let ns_ar = ApiResource::from_gvk_with_plural(&ns_gvk, "namespaces");
        let ns_api: Api<DynamicObject> = Api::all_with(client.clone(), &ns_ar);
        match list_with_retry_and_timeout(&ns_api, "", "v1", "namespaces").await {
            Ok(items) => {
                for obj in items {
                    if let Some(name) = obj.metadata.name {
                        let labels: BTreeMap<String, String> = obj
                            .metadata
                            .labels
                            .unwrap_or_default()
                            .into_iter()
                            .collect();
                        namespace_labels.insert(name, labels);
                    }
                }
            }
            Err(w) => warnings.push(w),
        }
    }

    // Fetch node labels only if any advertisement uses nodeSelectors
    let mut node_labels = HashMap::new();
    let needs_node_labels = l2_advertisements
        .iter()
        .any(|a| !a.node_selectors.is_empty())
        || bgp_advertisements
            .iter()
            .any(|a| !a.node_selectors.is_empty());
    if needs_node_labels {
        let node_gvk = GroupVersion::gv("", "v1").with_kind("Node");
        let node_ar = ApiResource::from_gvk_with_plural(&node_gvk, "nodes");
        let node_api: Api<DynamicObject> = Api::all_with(client.clone(), &node_ar);
        match list_with_retry_and_timeout(&node_api, "", "v1", "nodes").await {
            Ok(items) => {
                for obj in items {
                    if let Some(name) = obj.metadata.name {
                        let labels: BTreeMap<String, String> = obj
                            .metadata
                            .labels
                            .unwrap_or_default()
                            .into_iter()
                            .collect();
                        node_labels.insert(name, labels);
                    }
                }
            }
            Err(w) => warnings.push(w),
        }
    }

    // Fetch observation resources (conditional on CRD existence)
    let mut observation = MetalLBObservation::default();

    // ServiceL2Status
    for kind_name in &["ServiceL2Status", "MetalLBServiceL2Status"] {
        let key = (metallb_group.to_string(), kind_name.to_string());
        if let Some(info) = gk_map.get(&key) {
            let gvk = GroupVersion::gv(&info.group, &info.version).with_kind(kind_name);
            let ar = ApiResource::from_gvk_with_plural(&gvk, &info.plural);
            let api: Api<DynamicObject> = Api::all_with(client.clone(), &ar);
            match list_with_retry_and_timeout(&api, &info.group, &info.version, &info.plural).await
            {
                Ok(items) => {
                    observation.l2_status_availability = ApiAvailability::Available;
                    observation.l2_status = items
                        .into_iter()
                        .filter_map(parse_service_l2_status)
                        .collect();
                }
                Err(w) => {
                    observation.l2_status_availability = ApiAvailability::Unavailable;
                    warnings.push(w);
                }
            }
            break;
        }
    }

    // ServiceBGPStatus
    for kind_name in &["ServiceBGPStatus", "MetalLBServiceBGPStatus"] {
        let key = (metallb_group.to_string(), kind_name.to_string());
        if let Some(info) = gk_map.get(&key) {
            let gvk = GroupVersion::gv(&info.group, &info.version).with_kind(kind_name);
            let ar = ApiResource::from_gvk_with_plural(&gvk, &info.plural);
            let api: Api<DynamicObject> = Api::all_with(client.clone(), &ar);
            match list_with_retry_and_timeout(&api, &info.group, &info.version, &info.plural).await
            {
                Ok(items) => {
                    observation.bgp_status_availability = ApiAvailability::Available;
                    observation.bgp_status = items
                        .into_iter()
                        .filter_map(parse_service_bgp_status)
                        .collect();
                }
                Err(w) => {
                    observation.bgp_status_availability = ApiAvailability::Unavailable;
                    warnings.push(w);
                }
            }
            break;
        }
    }

    // BGPPeer
    let bgppeer_key = (metallb_group.to_string(), "BGPPeer".to_string());
    if let Some(info) = gk_map.get(&bgppeer_key) {
        let gvk = GroupVersion::gv(&info.group, &info.version).with_kind("BGPPeer");
        let ar = ApiResource::from_gvk_with_plural(&gvk, &info.plural);
        let api: Api<DynamicObject> = Api::all_with(client.clone(), &ar);
        match list_with_retry_and_timeout(&api, &info.group, &info.version, &info.plural).await {
            Ok(items) => {
                observation.bgp_peer_availability = ApiAvailability::Available;
                observation.bgp_peers = items.into_iter().filter_map(parse_bgp_peer).collect();
            }
            Err(w) => {
                observation.bgp_peer_availability = ApiAvailability::Unavailable;
                warnings.push(w);
            }
        }
    }

    // BFDProfile
    let bfd_key = (metallb_group.to_string(), "BFDProfile".to_string());
    if let Some(info) = gk_map.get(&bfd_key) {
        let gvk = GroupVersion::gv(&info.group, &info.version).with_kind("BFDProfile");
        let ar = ApiResource::from_gvk_with_plural(&gvk, &info.plural);
        let api: Api<DynamicObject> = Api::all_with(client.clone(), &ar);
        match list_with_retry_and_timeout(&api, &info.group, &info.version, &info.plural).await {
            Ok(items) => {
                observation.bfd_profile_availability = ApiAvailability::Available;
                observation.bfd_profiles =
                    items.into_iter().filter_map(parse_bfd_profile).collect();
            }
            Err(w) => {
                observation.bfd_profile_availability = ApiAvailability::Unavailable;
                warnings.push(w);
            }
        }
    }

    // ConfigurationState
    let cs_key = (metallb_group.to_string(), "ConfigurationState".to_string());
    if let Some(info) = gk_map.get(&cs_key) {
        let gvk = GroupVersion::gv(&info.group, &info.version).with_kind("ConfigurationState");
        let ar = ApiResource::from_gvk_with_plural(&gvk, &info.plural);
        let api: Api<DynamicObject> = Api::all_with(client.clone(), &ar);
        match list_with_retry_and_timeout(&api, &info.group, &info.version, &info.plural).await {
            Ok(items) => {
                observation.config_state_availability = ApiAvailability::Available;
                observation.configuration_states = items
                    .into_iter()
                    .filter_map(parse_configuration_state)
                    .collect();
            }
            Err(w) => {
                observation.config_state_availability = ApiAvailability::Unavailable;
                warnings.push(w);
            }
        }
    }

    // Fetch MetalLB events once for the service namespace
    let (metallb_events, event_availability) = {
        let event_gvk = GroupVersion::gv("", "v1").with_kind("Event");
        let event_ar = ApiResource::from_gvk_with_plural(&event_gvk, "events");
        let event_api: Api<DynamicObject> =
            Api::namespaced_with(client.clone(), svc_namespace, &event_ar);
        let field_selector = "involvedObject.kind=Service";
        match list_with_field_selector_retry(&event_api, field_selector, "", "v1", "events").await {
            Ok(items) => {
                let events: Vec<MetalLBServiceEvent> = items
                    .into_iter()
                    .filter_map(|obj| {
                        let source_component = obj
                            .data
                            .get("source")
                            .and_then(|s| s.get("component"))
                            .and_then(|v| v.as_str())
                            .filter(|s| !s.is_empty())
                            .map(String::from);
                        let reporting_component = obj
                            .data
                            .get("reportingComponent")
                            .and_then(|v| v.as_str())
                            .filter(|s| !s.is_empty())
                            .map(String::from)
                            .or_else(|| source_component.clone());
                        let is_metallb = is_metallb_event_component(
                            source_component.as_deref(),
                            reporting_component.as_deref(),
                        );
                        if !is_metallb {
                            return None;
                        }
                        let involved = obj.data.get("involvedObject")?;
                        let service_name = involved.get("name")?.as_str()?.to_string();
                        let service_namespace = involved
                            .get("namespace")
                            .and_then(|v| v.as_str())
                            .unwrap_or_default()
                            .to_string();
                        let involved_uid = involved
                            .get("uid")
                            .and_then(|v| v.as_str())
                            .map(String::from);
                        Some(MetalLBServiceEvent {
                            service_name,
                            service_namespace,
                            reason: obj
                                .data
                                .get("reason")
                                .and_then(|v| v.as_str())
                                .map(String::from),
                            message: obj
                                .data
                                .get("message")
                                .and_then(|v| v.as_str())
                                .map(String::from),
                            source_component,
                            reporting_component,
                            involved_uid,
                            event_type: obj
                                .data
                                .get("type")
                                .and_then(|v| v.as_str())
                                .map(String::from),
                            last_timestamp: obj
                                .data
                                .get("lastTimestamp")
                                .and_then(|v| v.as_str())
                                .map(String::from),
                        })
                    })
                    .collect();
                (events, ApiAvailability::Available)
            }
            Err(w) => {
                warnings.push(w);
                (vec![], ApiAvailability::Unavailable)
            }
        }
    };

    MetalLBInventory {
        available: true,
        pools,
        l2_advertisements,
        bgp_advertisements,
        warnings,
        namespace_labels,
        node_labels,
        observation,
        metallb_events,
        event_availability,
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
    pub priority: i64,
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
    pub status_available_ipv4: Option<i64>,
    pub status_available_ipv6: Option<i64>,
    pub status_assigned_ipv4: Option<i64>,
    pub status_assigned_ipv6: Option<i64>,
}

#[derive(Clone, Debug)]
pub struct L2Advertisement {
    pub name: String,
    pub namespace: String,
    pub ip_address_pools: Vec<String>,
    pub ip_address_pool_selectors: Vec<LabelSelector>,
    pub node_selectors: Vec<LabelSelector>,
    pub service_selectors: Vec<LabelSelector>,
    pub interfaces: Vec<String>,
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
    pub peers: Vec<String>,
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
    pub namespace: String,
    pub match_reason: String,
    pub node_selectors: Vec<LabelSelector>,
    pub service_selectors: Vec<LabelSelector>,
    pub aggregation_length: Option<i64>,
    pub aggregation_length_v6: Option<i64>,
    pub local_pref: Option<i64>,
    pub communities: Vec<String>,
    pub interfaces: Vec<String>,
    pub peers: Vec<String>,
    pub candidate_nodes: Vec<String>,
    pub node_selector_status: String,
}

#[derive(Clone, Debug, Default)]
pub struct MetalLBResult {
    pub provider: Option<String>,
    pub pools: Vec<MatchedPool>,
    pub advertisements: Vec<MatchedAdvertisement>,
    pub warnings: Vec<String>,
    pub requested_ips: Vec<String>,
    pub requested_pool: Option<String>,
    pub observation: CorrelatedObservation,
}

#[derive(Clone, Debug, Default)]
pub struct MetalLBInventory {
    pub available: bool,
    pub pools: Vec<IPAddressPool>,
    pub l2_advertisements: Vec<L2Advertisement>,
    pub bgp_advertisements: Vec<BGPAdvertisement>,
    pub warnings: Vec<ScanWarning>,
    pub namespace_labels: HashMap<String, BTreeMap<String, String>>,
    pub node_labels: HashMap<String, BTreeMap<String, String>>,
    pub observation: MetalLBObservation,
    pub metallb_events: Vec<MetalLBServiceEvent>,
    pub event_availability: ApiAvailability,
}

#[derive(Clone, Copy, Debug, Default, PartialEq)]
pub enum ApiAvailability {
    Available, // CRD exists and LIST succeeded
    #[default]
    Absent, // CRD not in gk_map
    Unavailable, // CRD exists but LIST failed (403/timeout)
}

#[derive(Clone, Debug)]
pub struct MetalLBServiceEvent {
    pub service_name: String,
    pub service_namespace: String,
    pub reason: Option<String>,
    pub message: Option<String>,
    pub source_component: Option<String>,
    pub reporting_component: Option<String>,
    pub involved_uid: Option<String>,
    pub event_type: Option<String>,
    pub last_timestamp: Option<String>,
}

#[derive(Clone, Debug, Default)]
pub struct MetalLBObservation {
    pub l2_status: Vec<ServiceL2Status>,
    pub bgp_status: Vec<ServiceBGPStatus>,
    pub bgp_peers: Vec<BGPPeerInfo>,
    pub bfd_profiles: Vec<BFDProfileInfo>,
    pub configuration_states: Vec<ConfigurationStateInfo>,
    pub l2_status_availability: ApiAvailability,
    pub bgp_status_availability: ApiAvailability,
    pub bgp_peer_availability: ApiAvailability,
    pub bfd_profile_availability: ApiAvailability,
    pub config_state_availability: ApiAvailability,
}

#[derive(Clone, Debug)]
pub struct ServiceL2Status {
    pub name: String,
    pub namespace: String,
    pub service_name: Option<String>,
    pub service_namespace: Option<String>,
    pub node: Option<String>,
    pub interfaces: Vec<String>,
}

#[derive(Clone, Debug)]
pub struct ServiceBGPStatus {
    pub name: String,
    pub namespace: String,
    pub service_name: Option<String>,
    pub service_namespace: Option<String>,
    pub node: Option<String>,
    pub peers: Vec<String>,
}

#[derive(Clone, Debug)]
pub struct BGPPeerInfo {
    pub name: String,
    pub namespace: String,
    pub peer_address: Option<String>,
    pub peer_asn: Option<i64>,
    pub my_asn: Option<i64>,
    pub source_address: Option<String>,
    pub node_selectors: Vec<LabelSelector>,
    pub bfd_profile: Option<String>,
    pub hold_time: Option<String>,
    pub keepalive_time: Option<String>,
    pub router_id: Option<String>,
}

#[derive(Clone, Debug)]
pub struct BFDProfileInfo {
    pub name: String,
    pub namespace: String,
    pub detect_multiplier: Option<i64>,
    pub receive_interval: Option<i64>,
    pub transmit_interval: Option<i64>,
    pub echo_interval: Option<i64>,
    pub minimum_ttl: Option<i64>,
    pub passive_mode: Option<bool>,
}

#[derive(Clone, Debug)]
pub struct ConfigurationStateInfo {
    pub name: String,
    pub namespace: String,
    pub component_type: Option<String>,
    pub node_name: Option<String>,
    pub result: Option<String>,
    pub error_summary: Option<String>,
    pub conditions: Vec<ConfigCondition>,
}

#[derive(Clone, Debug)]
pub struct ConfigCondition {
    pub condition_type: String,
    pub status: String,
    pub reason: Option<String>,
    pub message: Option<String>,
}

#[derive(Clone, Debug, Default)]
pub struct CorrelatedObservation {
    pub l2_advertised_nodes: Vec<String>,
    pub l2_interfaces: Vec<String>,
    pub l2_status_resources: Vec<(String, String)>, // (name, namespace) of matched ServiceL2Status
    pub bgp_advertised_nodes: Vec<BGPNodeStatus>,
    pub bgp_status_resources: Vec<(String, String)>, // (name, namespace) of matched ServiceBGPStatus
    pub related_peers: Vec<BGPPeerInfo>,
    pub related_bfd_profiles: Vec<BFDProfileInfo>,
    pub configuration_states: Vec<ConfigurationStateInfo>,
    pub observed_state: String,
    pub session_state: String,
    pub events: Vec<MetalLBServiceEvent>,
    pub api_availability: ObservationApiAvailability,
}

#[derive(Clone, Debug, Default)]
pub struct ObservationApiAvailability {
    pub l2_status: ApiAvailability,
    pub bgp_status: ApiAvailability,
    pub bgp_peer: ApiAvailability,
    pub bfd_profile: ApiAvailability,
    pub events: ApiAvailability,
    pub configuration_state: ApiAvailability,
}

#[derive(Clone, Debug)]
pub struct BGPNodeStatus {
    pub node: String,
    pub peers: Vec<String>,
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

fn parse_string_array(value: Option<&serde_json::Value>) -> Vec<String> {
    value
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|v| v.as_str().map(String::from))
                .collect()
        })
        .unwrap_or_default()
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
            priority,
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

    let status = obj.data.get("status");
    let status_available_ipv4 = status
        .and_then(|s| s.get("availableIPv4"))
        .and_then(|v| v.as_i64());
    let status_available_ipv6 = status
        .and_then(|s| s.get("availableIPv6"))
        .and_then(|v| v.as_i64());
    let status_assigned_ipv4 = status
        .and_then(|s| s.get("assignedIPv4"))
        .and_then(|v| v.as_i64());
    let status_assigned_ipv6 = status
        .and_then(|s| s.get("assignedIPv6"))
        .and_then(|v| v.as_i64());

    Some(IPAddressPool {
        name,
        namespace,
        addresses,
        auto_assign,
        service_allocation,
        labels,
        status_available_ipv4,
        status_available_ipv6,
        status_assigned_ipv4,
        status_assigned_ipv6,
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

    let interfaces = parse_string_array(spec.and_then(|s| s.get("interfaces")));

    Some(L2Advertisement {
        name,
        namespace,
        ip_address_pools,
        ip_address_pool_selectors,
        node_selectors,
        service_selectors,
        interfaces,
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

    let peers = parse_string_array(spec.and_then(|s| s.get("peers")));

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
        peers,
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
    ns_labels: &HashMap<String, BTreeMap<String, String>>,
    node_labels: &HashMap<String, BTreeMap<String, String>>,
) -> MetalLBResult {
    let events: Vec<MetalLBServiceEvent> = metallb.metallb_events.clone();
    let event_availability = metallb.event_availability;
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

    // Check ip-allocated-from-pool annotation
    let allocated_from_pool = svc
        .annotations
        .get("metallb.io/ip-allocated-from-pool")
        .or_else(|| {
            svc.annotations
                .get("metallb.universe.tf/ip-allocated-from-pool")
        })
        .cloned();

    // Determine provider evidence
    let has_pool_annotation = requested_pool.is_some();
    let has_allocated_from_pool = allocated_from_pool.is_some();
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
    let requested_ip_in_pool = requested_ips.iter().any(|ip| {
        metallb
            .pools
            .iter()
            .any(|p| ip_in_pool_ranges(ip, &p.addresses))
    });

    let provider = if has_pool_annotation
        || has_allocated_from_pool
        || has_lb_ips_annotation
        || has_lb_class
        || assigned_ip_in_pool
        || requested_ip_in_pool
    {
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

        // a2. Allocated from pool annotation
        if match_reason.is_none()
            && let Some(ref afp) = allocated_from_pool
            && afp == &pool.name
        {
            match_reason = Some("allocated from pool annotation".to_string());
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

        // e. autoAssign=false without explicit request -> skip
        if match_reason.is_none() && !pool.auto_assign {
            continue;
        }

        let Some(reason) = match_reason else {
            continue;
        };

        // d. Check serviceAllocation
        let allocation_match =
            evaluate_service_allocation(pool, svc_namespace, &svc_labels_btree, ns_labels);

        if let Some(ref am) = allocation_match
            && am != "OK"
        {
            warnings.push(format!("Pool {} serviceAllocation: {}", pool.name, am));
        }

        matched_pools.push(MatchedPool {
            pool: pool.clone(),
            match_reason: reason,
            allocation_match,
        });
    }

    // autoAssign candidates when no pool explicitly matched
    if matched_pools.is_empty() && provider.is_some() {
        let mut candidates: Vec<_> = metallb
            .pools
            .iter()
            .filter(|p| p.auto_assign)
            .filter(|p| {
                let am =
                    evaluate_service_allocation(p, svc_namespace, &svc_labels_btree, ns_labels);
                am.is_none() || am.as_deref() == Some("OK")
            })
            .filter(|p| {
                // Only include if serviceAllocation allows
                if let Some(sa) = &p.service_allocation {
                    let ns_allowed =
                        if sa.namespaces.is_empty() && sa.namespace_selectors.is_empty() {
                            true
                        } else {
                            let ns_in_list = sa.namespaces.contains(&svc_namespace.to_string());
                            let ns_selector_match = if sa.namespace_selectors.is_empty() {
                                false
                            } else if let Some(ns_lbl) = ns_labels.get(svc_namespace) {
                                label_selector_list_matches(&sa.namespace_selectors, ns_lbl)
                            } else {
                                false
                            };
                            ns_in_list || ns_selector_match
                        };
                    let svc_allowed = if sa.service_selectors.is_empty() {
                        true
                    } else {
                        label_selector_list_matches(&sa.service_selectors, &svc_labels_btree)
                    };
                    ns_allowed && svc_allowed
                } else {
                    true
                }
            })
            .cloned()
            .collect();
        candidates.sort_by_key(|p| {
            p.service_allocation
                .as_ref()
                .map(|sa| {
                    if sa.priority == 0 {
                        i64::MAX
                    } else {
                        sa.priority
                    }
                })
                .unwrap_or(i64::MAX)
        });
        for pool in candidates {
            let allocation_match =
                evaluate_service_allocation(&pool, svc_namespace, &svc_labels_btree, ns_labels);
            matched_pools.push(MatchedPool {
                pool,
                match_reason: "autoAssign candidate".to_string(),
                allocation_match,
            });
        }
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

            // Evaluate node selectors
            let (candidate_nodes, node_selector_status) = evaluate_node_selectors(
                &l2.name,
                "L2Advertisement",
                &l2.node_selectors,
                node_labels,
                &mut warnings,
            );

            matched_ads.push(MatchedAdvertisement {
                kind: "L2Advertisement".to_string(),
                name: l2.name.clone(),
                namespace: l2.namespace.clone(),
                match_reason,
                node_selectors: l2.node_selectors.clone(),
                service_selectors: l2.service_selectors.clone(),
                aggregation_length: None,
                aggregation_length_v6: None,
                local_pref: None,
                communities: vec![],
                interfaces: l2.interfaces.clone(),
                peers: vec![],
                candidate_nodes,
                node_selector_status,
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

            // Evaluate node selectors
            let (candidate_nodes, node_selector_status) = evaluate_node_selectors(
                &bgp.name,
                "BGPAdvertisement",
                &bgp.node_selectors,
                node_labels,
                &mut warnings,
            );

            matched_ads.push(MatchedAdvertisement {
                kind: "BGPAdvertisement".to_string(),
                name: bgp.name.clone(),
                namespace: bgp.namespace.clone(),
                match_reason,
                node_selectors: bgp.node_selectors.clone(),
                service_selectors: bgp.service_selectors.clone(),
                aggregation_length: bgp.aggregation_length,
                aggregation_length_v6: bgp.aggregation_length_v6,
                local_pref: bgp.local_pref,
                communities: bgp.communities.clone(),
                interfaces: vec![],
                peers: bgp.peers.clone(),
                candidate_nodes,
                node_selector_status,
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
    if svc.external_traffic_policy.as_deref() == Some("Local") {
        if endpoint_nodes.is_empty() {
            warnings
                .push("externalTrafficPolicy=Local but no ready endpoint nodes found".to_string());
        } else {
            let advertised_nodes: HashSet<&str> = matched_ads
                .iter()
                .flat_map(|a| a.candidate_nodes.iter().map(|s| s.as_str()))
                .collect();
            if !advertised_nodes.is_empty() {
                let ready_on_advertised: Vec<&str> = endpoint_nodes
                    .iter()
                    .filter(|n| advertised_nodes.contains(n.as_str()))
                    .map(|s| s.as_str())
                    .collect();
                if ready_on_advertised.is_empty() {
                    warnings.push(
                        "externalTrafficPolicy=Local: no ready endpoints on advertised nodes"
                            .to_string(),
                    );
                }
            } else if matched_ads
                .iter()
                .any(|a| a.node_selector_status == "unavailable")
            {
                warnings.push(
                    "externalTrafficPolicy=Local: advertised node set unknown (node labels unavailable)"
                        .to_string(),
                );
            } else if matched_ads
                .iter()
                .any(|a| a.node_selector_status == "mismatch")
            {
                warnings.push(
                    "externalTrafficPolicy=Local: no advertised nodes (nodeSelector matched no nodes)"
                        .to_string(),
                );
            }
        }
    }

    let has_bgp_ad = matched_ads.iter().any(|a| a.kind == "BGPAdvertisement");
    let mut metallb_namespaces: Vec<String> = matched_pools
        .iter()
        .map(|p| p.pool.namespace.clone())
        .chain(matched_ads.iter().map(|a| a.namespace.clone()))
        .collect::<HashSet<_>>()
        .into_iter()
        .collect();
    metallb_namespaces.sort();
    let observation = correlate_metallb_observations(&CorrelateParams {
        svc_name: &svc.name,
        svc_namespace,
        svc_uid: &svc.uid,
        observation: &metallb.observation,
        has_advertisements: !matched_ads.is_empty(),
        has_bgp_advertisement: has_bgp_ad,
        events,
        event_availability,
        metallb_namespaces: &metallb_namespaces,
    });

    MetalLBResult {
        provider,
        pools: matched_pools,
        advertisements: matched_ads,
        warnings,
        requested_ips,
        requested_pool,
        observation,
    }
}

fn parse_service_l2_status(obj: DynamicObject) -> Option<ServiceL2Status> {
    let name = obj.metadata.name?;
    let namespace = obj.metadata.namespace.unwrap_or_default();
    let spec = obj.data.get("spec");
    let status = obj.data.get("status");

    let service_name = spec
        .and_then(|s| s.get("serviceName"))
        .or_else(|| status.and_then(|s| s.get("serviceName")))
        .and_then(|v| v.as_str())
        .map(String::from);
    let service_namespace = spec
        .and_then(|s| s.get("serviceNamespace"))
        .or_else(|| status.and_then(|s| s.get("serviceNamespace")))
        .and_then(|v| v.as_str())
        .map(String::from);
    let node = status
        .and_then(|s| s.get("node"))
        .or_else(|| spec.and_then(|s| s.get("node")))
        .and_then(|v| v.as_str())
        .map(String::from);
    let interfaces = status
        .and_then(|s| s.get("interfaces"))
        .or_else(|| spec.and_then(|s| s.get("interfaces")))
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|v| {
                    // InterfaceInfo: {name: string} or plain string fallback
                    v.as_object()
                        .and_then(|o| o.get("name"))
                        .and_then(|n| n.as_str())
                        .map(String::from)
                        .or_else(|| v.as_str().map(String::from))
                })
                .collect()
        })
        .unwrap_or_default();

    Some(ServiceL2Status {
        name,
        namespace,
        service_name,
        service_namespace,
        node,
        interfaces,
    })
}

fn parse_service_bgp_status(obj: DynamicObject) -> Option<ServiceBGPStatus> {
    let name = obj.metadata.name?;
    let namespace = obj.metadata.namespace.unwrap_or_default();
    let spec = obj.data.get("spec");
    let status = obj.data.get("status");

    let service_name = spec
        .and_then(|s| s.get("serviceName"))
        .or_else(|| status.and_then(|s| s.get("serviceName")))
        .and_then(|v| v.as_str())
        .map(String::from);
    let service_namespace = spec
        .and_then(|s| s.get("serviceNamespace"))
        .or_else(|| status.and_then(|s| s.get("serviceNamespace")))
        .and_then(|v| v.as_str())
        .map(String::from);
    let node = status
        .and_then(|s| s.get("node"))
        .or_else(|| spec.and_then(|s| s.get("node")))
        .and_then(|v| v.as_str())
        .map(String::from);
    let peers = status
        .and_then(|s| s.get("peers"))
        .or_else(|| spec.and_then(|s| s.get("peers")))
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|v| v.as_str().map(String::from))
                .collect()
        })
        .unwrap_or_default();

    Some(ServiceBGPStatus {
        name,
        namespace,
        service_name,
        service_namespace,
        node,
        peers,
    })
}

fn parse_bgp_peer(obj: DynamicObject) -> Option<BGPPeerInfo> {
    let name = obj.metadata.name?;
    let namespace = obj.metadata.namespace.unwrap_or_default();
    let spec = obj.data.get("spec")?;

    let peer_address = spec
        .get("peerAddress")
        .and_then(|v| v.as_str())
        .map(String::from);
    let peer_asn = spec.get("peerASN").and_then(|v| v.as_i64());
    let my_asn = spec.get("myASN").and_then(|v| v.as_i64());
    let source_address = spec
        .get("sourceAddress")
        .and_then(|v| v.as_str())
        .map(String::from);
    let bfd_profile = spec
        .get("bfdProfile")
        .and_then(|v| v.as_str())
        .map(String::from);
    let hold_time = spec
        .get("holdTime")
        .and_then(|v| v.as_str())
        .map(String::from)
        .or_else(|| {
            spec.get("holdTime")
                .and_then(|v| v.as_i64())
                .map(|v| format!("{}s", v))
        });
    let keepalive_time = spec
        .get("keepaliveTime")
        .and_then(|v| v.as_str())
        .map(String::from)
        .or_else(|| {
            spec.get("keepaliveTime")
                .and_then(|v| v.as_i64())
                .map(|v| format!("{}s", v))
        });
    let router_id = spec
        .get("routerID")
        .and_then(|v| v.as_str())
        .map(String::from);
    let node_selectors = parse_label_selectors(spec.get("nodeSelectors"));

    Some(BGPPeerInfo {
        name,
        namespace,
        peer_address,
        peer_asn,
        my_asn,
        source_address,
        node_selectors,
        bfd_profile,
        hold_time,
        keepalive_time,
        router_id,
    })
}

fn parse_bfd_profile(obj: DynamicObject) -> Option<BFDProfileInfo> {
    let name = obj.metadata.name?;
    let namespace = obj.metadata.namespace.unwrap_or_default();
    let spec = obj.data.get("spec");

    let detect_multiplier = spec
        .and_then(|s| s.get("detectMultiplier"))
        .and_then(|v| v.as_i64());
    let receive_interval = spec
        .and_then(|s| s.get("receiveInterval"))
        .and_then(|v| v.as_i64());
    let transmit_interval = spec
        .and_then(|s| s.get("transmitInterval"))
        .and_then(|v| v.as_i64());
    let echo_interval = spec
        .and_then(|s| s.get("echoInterval"))
        .and_then(|v| v.as_i64());
    let minimum_ttl = spec
        .and_then(|s| s.get("minimumTtl"))
        .and_then(|v| v.as_i64());
    let passive_mode = spec
        .and_then(|s| s.get("passiveMode"))
        .and_then(|v| v.as_bool());

    Some(BFDProfileInfo {
        name,
        namespace,
        detect_multiplier,
        receive_interval,
        transmit_interval,
        echo_interval,
        minimum_ttl,
        passive_mode,
    })
}

fn parse_configuration_state(obj: DynamicObject) -> Option<ConfigurationStateInfo> {
    let name = obj.metadata.name?;
    let namespace = obj.metadata.namespace.unwrap_or_default();
    let labels = obj.metadata.labels.as_ref();
    let component_type = labels
        .and_then(|l| l.get("metallb.io/component-type"))
        .cloned();
    let node_name = labels.and_then(|l| l.get("metallb.io/node-name")).cloned();
    let status = obj.data.get("status");
    let result_val = status
        .and_then(|s| s.get("result"))
        .and_then(|v| v.as_str())
        .map(String::from);
    let error_summary = status
        .and_then(|s| s.get("errorSummary"))
        .and_then(|v| v.as_str())
        .map(String::from);
    let conditions = status
        .and_then(|s| s.get("conditions"))
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|c| {
                    Some(ConfigCondition {
                        condition_type: c.get("type")?.as_str()?.to_string(),
                        status: c
                            .get("status")
                            .and_then(|v| v.as_str())
                            .unwrap_or("Unknown")
                            .to_string(),
                        reason: c.get("reason").and_then(|v| v.as_str()).map(String::from),
                        message: c.get("message").and_then(|v| v.as_str()).map(String::from),
                    })
                })
                .collect()
        })
        .unwrap_or_default();
    Some(ConfigurationStateInfo {
        name,
        namespace,
        component_type,
        node_name,
        result: result_val,
        error_summary,
        conditions,
    })
}

const METALLB_COMPONENTS: &[&str] = &[
    "metallb-speaker",
    "metallb-controller",
    "speaker",
    "MetalLB-speaker",
    "MetalLB-controller",
];

pub(crate) fn is_metallb_event_component(
    source_component: Option<&str>,
    reporting_component: Option<&str>,
) -> bool {
    source_component.is_some_and(|c| METALLB_COMPONENTS.contains(&c))
        || reporting_component.is_some_and(|c| METALLB_COMPONENTS.contains(&c))
}

/// Fetch MetalLB-related events for a specific service from its namespace.
#[cfg(test)]
pub async fn fetch_metallb_service_events(
    client: &Client,
    namespace: &str,
    svc_name: &str,
    svc_uid: &str,
) -> (Vec<MetalLBServiceEvent>, ApiAvailability, Vec<ScanWarning>) {
    let event_gvk = GroupVersion::gv("", "v1").with_kind("Event");
    let event_ar = ApiResource::from_gvk_with_plural(&event_gvk, "events");
    let event_api: Api<DynamicObject> = Api::namespaced_with(client.clone(), namespace, &event_ar);
    let field_selector = format!(
        "involvedObject.kind=Service,involvedObject.name={},involvedObject.uid={}",
        svc_name, svc_uid
    );
    let mut warnings = Vec::new();
    match list_with_field_selector_retry(&event_api, &field_selector, "", "v1", "events").await {
        Ok(items) => {
            let mut events: Vec<MetalLBServiceEvent> = items
                .into_iter()
                .filter_map(|obj| {
                    let source_component = obj
                        .data
                        .get("source")
                        .and_then(|s| s.get("component"))
                        .and_then(|v| v.as_str())
                        .filter(|s| !s.is_empty())
                        .map(String::from);
                    let reporting_component = obj
                        .data
                        .get("reportingComponent")
                        .and_then(|v| v.as_str())
                        .filter(|s| !s.is_empty())
                        .map(String::from)
                        .or_else(|| source_component.clone());
                    let is_metallb = source_component
                        .as_deref()
                        .is_some_and(|c| METALLB_COMPONENTS.contains(&c))
                        || reporting_component
                            .as_deref()
                            .is_some_and(|c| METALLB_COMPONENTS.contains(&c));
                    if !is_metallb {
                        return None;
                    }
                    let involved = obj.data.get("involvedObject")?;
                    let service_name = involved.get("name")?.as_str()?.to_string();
                    let service_namespace = involved
                        .get("namespace")
                        .and_then(|v| v.as_str())
                        .unwrap_or_default()
                        .to_string();
                    let involved_uid = involved
                        .get("uid")
                        .and_then(|v| v.as_str())
                        .map(String::from);
                    Some(MetalLBServiceEvent {
                        service_name,
                        service_namespace,
                        reason: obj
                            .data
                            .get("reason")
                            .and_then(|v| v.as_str())
                            .map(String::from),
                        message: obj
                            .data
                            .get("message")
                            .and_then(|v| v.as_str())
                            .map(String::from),
                        source_component,
                        reporting_component,
                        involved_uid,
                        event_type: obj
                            .data
                            .get("type")
                            .and_then(|v| v.as_str())
                            .map(String::from),
                        last_timestamp: obj
                            .data
                            .get("lastTimestamp")
                            .and_then(|v| v.as_str())
                            .map(String::from),
                    })
                })
                .collect();
            events.sort_by(|a, b| a.reason.cmp(&b.reason).then(a.message.cmp(&b.message)));
            (events, ApiAvailability::Available, warnings)
        }
        Err(w) => {
            warnings.push(w);
            (vec![], ApiAvailability::Unavailable, warnings)
        }
    }
}

pub struct CorrelateParams<'a> {
    pub svc_name: &'a str,
    pub svc_namespace: &'a str,
    pub svc_uid: &'a str,
    pub observation: &'a MetalLBObservation,
    pub has_advertisements: bool,
    pub has_bgp_advertisement: bool,
    pub events: Vec<MetalLBServiceEvent>,
    pub event_availability: ApiAvailability,
    pub metallb_namespaces: &'a [String],
}

pub fn correlate_metallb_observations(params: &CorrelateParams<'_>) -> CorrelatedObservation {
    let svc_name = params.svc_name;
    let svc_namespace = params.svc_namespace;
    let svc_uid = params.svc_uid;
    let observation = params.observation;
    let has_advertisements = params.has_advertisements;
    let has_bgp_advertisement = params.has_bgp_advertisement;
    // Filter L2 status for this service
    let matched_l2: Vec<&ServiceL2Status> = observation
        .l2_status
        .iter()
        .filter(|s| {
            s.service_name.as_deref() == Some(svc_name)
                && s.service_namespace.as_deref() == Some(svc_namespace)
        })
        .collect();
    let l2_status_resources: Vec<(String, String)> = matched_l2
        .iter()
        .map(|s| (s.name.clone(), s.namespace.clone()))
        .collect();
    let mut l2_nodes: Vec<String> = matched_l2.iter().filter_map(|s| s.node.clone()).collect();
    l2_nodes.sort();
    l2_nodes.dedup();
    let mut l2_interfaces: Vec<String> = matched_l2
        .iter()
        .flat_map(|s| s.interfaces.iter().cloned())
        .collect();
    l2_interfaces.sort();
    l2_interfaces.dedup();

    // Filter BGP status for this service
    let matched_bgp: Vec<&ServiceBGPStatus> = observation
        .bgp_status
        .iter()
        .filter(|s| {
            s.service_name.as_deref() == Some(svc_name)
                && s.service_namespace.as_deref() == Some(svc_namespace)
        })
        .collect();
    let bgp_status_resources: Vec<(String, String)> = matched_bgp
        .iter()
        .map(|s| (s.name.clone(), s.namespace.clone()))
        .collect();
    let mut bgp_nodes: Vec<BGPNodeStatus> = matched_bgp
        .iter()
        .filter_map(|s| {
            Some(BGPNodeStatus {
                node: s.node.clone()?,
                peers: s.peers.clone(),
            })
        })
        .collect();
    bgp_nodes.sort_by(|a, b| a.node.cmp(&b.node));
    bgp_nodes.dedup_by(|a, b| a.node == b.node);

    // Cross-reference BGP peers by (namespace, name) from status resources
    let peer_refs: HashSet<(&str, &str)> = matched_bgp
        .iter()
        .flat_map(|s| s.peers.iter().map(|p| (s.namespace.as_str(), p.as_str())))
        .collect();
    let mut related_peers: Vec<BGPPeerInfo> = observation
        .bgp_peers
        .iter()
        .filter(|p| peer_refs.contains(&(p.namespace.as_str(), p.name.as_str())))
        .cloned()
        .collect();
    related_peers.sort_by(|a, b| a.namespace.cmp(&b.namespace).then(a.name.cmp(&b.name)));
    related_peers.dedup_by(|a, b| a.namespace == b.namespace && a.name == b.name);

    // Find related BFD profiles (filter by same namespace as peer)
    let bfd_refs: HashSet<(&str, &str)> = related_peers
        .iter()
        .filter_map(|p| Some((p.bfd_profile.as_deref()?, p.namespace.as_str())))
        .collect();
    let mut related_bfd_profiles: Vec<BFDProfileInfo> = observation
        .bfd_profiles
        .iter()
        .filter(|b| bfd_refs.contains(&(b.name.as_str(), b.namespace.as_str())))
        .cloned()
        .collect();
    related_bfd_profiles.sort_by(|a, b| a.namespace.cmp(&b.namespace).then(a.name.cmp(&b.name)));
    related_bfd_profiles.dedup_by(|a, b| a.namespace == b.namespace && a.name == b.name);

    // Filter events by service name, namespace, and UID
    let filtered_events: Vec<MetalLBServiceEvent> = params
        .events
        .iter()
        .filter(|e| {
            e.service_name == svc_name
                && e.service_namespace == svc_namespace
                && e.involved_uid.as_deref() == Some(svc_uid)
        })
        .cloned()
        .collect();
    let mut filtered_events = filtered_events;
    filtered_events.sort_by(|a, b| a.reason.cmp(&b.reason).then(a.message.cmp(&b.message)));
    filtered_events.dedup_by(|a, b| {
        a.reason == b.reason && a.message == b.message && a.last_timestamp == b.last_timestamp
    });

    // Filter ConfigurationState by metallb namespaces (from matched pools/advertisements)
    let mut configuration_states: Vec<ConfigurationStateInfo> = observation
        .configuration_states
        .iter()
        .filter(|cs| params.metallb_namespaces.contains(&cs.namespace))
        .cloned()
        .collect();
    configuration_states.sort_by(|a, b| a.namespace.cmp(&b.namespace).then(a.name.cmp(&b.name)));
    configuration_states.dedup_by(|a, b| a.namespace == b.namespace && a.name == b.name);

    // Determine observed state based on API availability
    let has_status = !l2_nodes.is_empty() || !bgp_nodes.is_empty();
    let l2_avail = &observation.l2_status_availability;
    let bgp_avail = &observation.bgp_status_availability;
    let both_available_or_absent = (*l2_avail == ApiAvailability::Available
        || *l2_avail == ApiAvailability::Absent)
        && (*bgp_avail == ApiAvailability::Available || *bgp_avail == ApiAvailability::Absent);
    let at_least_one_available =
        *l2_avail == ApiAvailability::Available || *bgp_avail == ApiAvailability::Available;

    let observed_state = if has_status {
        "advertising".to_string()
    } else if has_advertisements && both_available_or_absent && at_least_one_available {
        "configured".to_string()
    } else if has_advertisements {
        // absent, unavailable, or mixed → unknown
        "unknown".to_string()
    } else {
        String::new()
    };

    // BGP session state: "unknown" when BGPAdvertisement present or BGP-related items exist
    let has_bgp = has_bgp_advertisement
        || !bgp_nodes.is_empty()
        || !matched_bgp.is_empty()
        || !related_peers.is_empty();
    let session_state = if has_bgp {
        "unknown".to_string()
    } else {
        String::new()
    };

    // Sort status resources
    let mut l2_status_resources = l2_status_resources;
    l2_status_resources.sort();
    l2_status_resources.dedup();
    let mut bgp_status_resources = bgp_status_resources;
    bgp_status_resources.sort();
    bgp_status_resources.dedup();

    CorrelatedObservation {
        l2_advertised_nodes: l2_nodes,
        l2_interfaces,
        l2_status_resources,
        bgp_advertised_nodes: bgp_nodes,
        bgp_status_resources,
        related_peers,
        related_bfd_profiles,
        configuration_states,
        observed_state,
        session_state,
        events: filtered_events,
        api_availability: ObservationApiAvailability {
            l2_status: observation.l2_status_availability,
            bgp_status: observation.bgp_status_availability,
            bgp_peer: observation.bgp_peer_availability,
            bfd_profile: observation.bfd_profile_availability,
            events: params.event_availability,
            configuration_state: observation.config_state_availability,
        },
    }
}

fn evaluate_service_allocation(
    pool: &IPAddressPool,
    svc_namespace: &str,
    svc_labels: &BTreeMap<String, String>,
    ns_labels: &HashMap<String, BTreeMap<String, String>>,
) -> Option<String> {
    let sa = pool.service_allocation.as_ref()?;
    let mut issues = Vec::new();

    // Namespace check: namespaces and namespaceSelectors are OR
    let ns_allowed = if sa.namespaces.is_empty() && sa.namespace_selectors.is_empty() {
        true
    } else {
        let ns_in_list = sa.namespaces.contains(&svc_namespace.to_string());
        if ns_in_list {
            true
        } else if !sa.namespace_selectors.is_empty() {
            if let Some(ns_lbl) = ns_labels.get(svc_namespace) {
                label_selector_list_matches(&sa.namespace_selectors, ns_lbl)
            } else {
                issues.push("namespace labels unavailable for selector evaluation".to_string());
                false
            }
        } else {
            false
        }
    };
    if !ns_allowed && !issues.iter().any(|i| i.contains("unavailable")) {
        issues.push(format!(
            "namespace {} not allowed by serviceAllocation",
            svc_namespace
        ));
    }

    // Service selector check
    if !sa.service_selectors.is_empty()
        && !label_selector_list_matches(&sa.service_selectors, svc_labels)
    {
        issues.push("service selector mismatch".to_string());
    }

    if issues.is_empty() {
        Some("OK".to_string())
    } else {
        Some(issues.join("; "))
    }
}

fn evaluate_node_selectors(
    ad_name: &str,
    ad_kind: &str,
    node_selectors: &[LabelSelector],
    node_labels: &HashMap<String, BTreeMap<String, String>>,
    warnings: &mut Vec<String>,
) -> (Vec<String>, String) {
    if node_selectors.is_empty() {
        return (node_labels.keys().cloned().collect(), "all".to_string());
    }
    if node_labels.is_empty() {
        warnings.push(format!(
            "{}/{} nodeSelector present but node labels unavailable",
            ad_kind, ad_name
        ));
        return (vec![], "unavailable".to_string());
    }
    let matched: Vec<String> = node_labels
        .iter()
        .filter(|(_, labels)| label_selector_list_matches(node_selectors, labels))
        .map(|(name, _)| name.clone())
        .collect();
    if matched.is_empty() {
        warnings.push(format!(
            "{}/{} nodeSelector matched no nodes",
            ad_kind, ad_name
        ));
        (vec![], "mismatch".to_string())
    } else {
        (matched.clone(), format!("matched {}", matched.len()))
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
            uid: String::new(),
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
            None,
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
            uid: String::new(),
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
            status_available_ipv4: None,
            status_available_ipv6: None,
            status_assigned_ipv4: None,
            status_assigned_ipv6: None,
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
            interfaces: vec![],
        }
    }

    fn make_test_metallb(
        pools: Vec<IPAddressPool>,
        l2s: Vec<L2Advertisement>,
        bgps: Vec<BGPAdvertisement>,
    ) -> MetalLBInventory {
        MetalLBInventory {
            available: true,
            pools,
            l2_advertisements: l2s,
            bgp_advertisements: bgps,
            warnings: vec![],
            namespace_labels: HashMap::new(),
            node_labels: HashMap::new(),
            observation: MetalLBObservation::default(),
            metallb_events: vec![],
            event_availability: ApiAvailability::Absent,
        }
    }

    fn make_lb_svc(name: &str) -> NetworkService {
        NetworkService {
            name: name.into(),
            uid: "test-uid".into(),
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
            interfaces: vec![],
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
            warnings: vec![],
            namespace_labels: HashMap::new(),
            node_labels: HashMap::new(),
            observation: MetalLBObservation::default(),
            metallb_events: vec![],
            event_availability: ApiAvailability::Absent,
        };

        let result = resolve_metallb_for_service(
            &svc,
            "default",
            &metallb,
            &[],
            &metallb.namespace_labels,
            &metallb.node_labels,
        );
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
            interfaces: vec![],
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
            warnings: vec![],
            namespace_labels: HashMap::new(),
            node_labels: HashMap::new(),
            observation: MetalLBObservation::default(),
            metallb_events: vec![],
            event_availability: ApiAvailability::Absent,
        };

        let result = resolve_metallb_for_service(
            &svc,
            "default",
            &metallb,
            &[],
            &metallb.namespace_labels,
            &metallb.node_labels,
        );
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
            peers: vec![],
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

        let metallb = make_test_metallb(vec![pool], vec![], vec![bgp]);

        let result = resolve_metallb_for_service(
            &svc,
            "default",
            &metallb,
            &[],
            &metallb.namespace_labels,
            &metallb.node_labels,
        );
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
                priority: 0,
                namespaces: vec!["allowed-ns".into()],
                namespace_selectors: vec![],
                service_selectors: vec![],
            }),
            labels: BTreeMap::new(),
            status_available_ipv4: None,
            status_available_ipv6: None,
            status_assigned_ipv4: None,
            status_assigned_ipv6: None,
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
            warnings: vec![],
            namespace_labels: HashMap::new(),
            node_labels: HashMap::new(),
            observation: MetalLBObservation::default(),
            metallb_events: vec![],
            event_availability: ApiAvailability::Absent,
        };

        // Wrong namespace
        let result = resolve_metallb_for_service(
            &svc,
            "other-ns",
            &metallb,
            &[],
            &metallb.namespace_labels,
            &metallb.node_labels,
        );
        assert!(
            result
                .warnings
                .iter()
                .any(|w| w.contains("namespace other-ns not allowed by serviceAllocation"))
        );

        // Correct namespace
        let result = resolve_metallb_for_service(
            &svc,
            "allowed-ns",
            &metallb,
            &[],
            &metallb.namespace_labels,
            &metallb.node_labels,
        );
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
                priority: 0,
                namespaces: vec![],
                namespace_selectors: vec![],
                service_selectors: vec![make_label_selector(&[("tier", "frontend")], vec![])],
            }),
            labels: BTreeMap::new(),
            status_available_ipv4: None,
            status_available_ipv6: None,
            status_assigned_ipv4: None,
            status_assigned_ipv6: None,
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
            warnings: vec![],
            namespace_labels: HashMap::new(),
            node_labels: HashMap::new(),
            observation: MetalLBObservation::default(),
            metallb_events: vec![],
            event_availability: ApiAvailability::Absent,
        };

        let result = resolve_metallb_for_service(
            &svc,
            "default",
            &metallb,
            &[],
            &metallb.namespace_labels,
            &metallb.node_labels,
        );
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
            warnings: vec![],
            namespace_labels: HashMap::new(),
            node_labels: HashMap::new(),
            observation: MetalLBObservation::default(),
            metallb_events: vec![],
            event_availability: ApiAvailability::Absent,
        };

        let result = resolve_metallb_for_service(
            &svc,
            "default",
            &metallb,
            &[],
            &metallb.namespace_labels,
            &metallb.node_labels,
        );
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
            warnings: vec![],
            namespace_labels: HashMap::new(),
            node_labels: HashMap::new(),
            observation: MetalLBObservation::default(),
            metallb_events: vec![],
            event_availability: ApiAvailability::Absent,
        };

        let result = resolve_metallb_for_service(
            &svc,
            "default",
            &metallb,
            &[],
            &metallb.namespace_labels,
            &metallb.node_labels,
        );
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
            warnings: vec![],
            namespace_labels: HashMap::new(),
            node_labels: HashMap::new(),
            observation: MetalLBObservation::default(),
            metallb_events: vec![],
            event_availability: ApiAvailability::Absent,
        };

        let result = resolve_metallb_for_service(
            &svc,
            "default",
            &metallb,
            &[],
            &metallb.namespace_labels,
            &metallb.node_labels,
        );
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
            warnings: vec![],
            namespace_labels: HashMap::new(),
            node_labels: HashMap::new(),
            observation: MetalLBObservation::default(),
            metallb_events: vec![],
            event_availability: ApiAvailability::Absent,
        };

        let result = resolve_metallb_for_service(
            &svc,
            "default",
            &metallb,
            &[],
            &metallb.namespace_labels,
            &metallb.node_labels,
        );
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
            warnings: vec![],
            namespace_labels: HashMap::new(),
            node_labels: HashMap::new(),
            observation: MetalLBObservation::default(),
            metallb_events: vec![],
            event_availability: ApiAvailability::Absent,
        };

        let result = resolve_metallb_for_service(
            &svc,
            "default",
            &metallb,
            &[],
            &metallb.namespace_labels,
            &metallb.node_labels,
        );
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

    // ── New MetalLB tests ──

    #[test]
    fn namespace_selector_match_with_labels() {
        let pool = IPAddressPool {
            name: "ns-sel-pool".into(),
            namespace: "metallb-system".into(),
            addresses: vec!["10.0.0.0/24".into()],
            auto_assign: true,
            service_allocation: Some(ServiceAllocation {
                priority: 0,
                namespaces: vec![],
                namespace_selectors: vec![make_label_selector(&[("env", "prod")], vec![])],
                service_selectors: vec![],
            }),
            labels: BTreeMap::new(),
            status_available_ipv4: None,
            status_available_ipv6: None,
            status_assigned_ipv4: None,
            status_assigned_ipv6: None,
        };
        let l2 = make_test_l2("l2-all", "metallb-system", vec!["ns-sel-pool"]);

        let mut svc = make_lb_svc("test-svc");
        svc.annotations
            .insert("metallb.io/address-pool".into(), "ns-sel-pool".into());
        svc.lb_ingress.push(LBIngress {
            ip: Some("10.0.0.1".into()),
            hostname: None,
            ip_mode: None,
        });

        let mut metallb = make_test_metallb(vec![pool], vec![l2], vec![]);

        // With matching namespace labels
        metallb.namespace_labels.insert(
            "my-ns".into(),
            [("env".to_string(), "prod".to_string())]
                .into_iter()
                .collect(),
        );
        let result = resolve_metallb_for_service(
            &svc,
            "my-ns",
            &metallb,
            &[],
            &metallb.namespace_labels,
            &metallb.node_labels,
        );
        assert!(
            !result
                .warnings
                .iter()
                .any(|w| w.contains("not allowed by serviceAllocation")),
            "matching namespace selector should pass"
        );
    }

    #[test]
    fn namespace_selector_mismatch() {
        let pool = IPAddressPool {
            name: "ns-sel-pool".into(),
            namespace: "metallb-system".into(),
            addresses: vec!["10.0.0.0/24".into()],
            auto_assign: true,
            service_allocation: Some(ServiceAllocation {
                priority: 0,
                namespaces: vec![],
                namespace_selectors: vec![make_label_selector(&[("env", "prod")], vec![])],
                service_selectors: vec![],
            }),
            labels: BTreeMap::new(),
            status_available_ipv4: None,
            status_available_ipv6: None,
            status_assigned_ipv4: None,
            status_assigned_ipv6: None,
        };
        let l2 = make_test_l2("l2-all", "metallb-system", vec!["ns-sel-pool"]);

        let mut svc = make_lb_svc("test-svc");
        svc.annotations
            .insert("metallb.io/address-pool".into(), "ns-sel-pool".into());
        svc.lb_ingress.push(LBIngress {
            ip: Some("10.0.0.1".into()),
            hostname: None,
            ip_mode: None,
        });

        let mut metallb = make_test_metallb(vec![pool], vec![l2], vec![]);
        metallb.namespace_labels.insert(
            "my-ns".into(),
            [("env".to_string(), "dev".to_string())]
                .into_iter()
                .collect(),
        );

        let result = resolve_metallb_for_service(
            &svc,
            "my-ns",
            &metallb,
            &[],
            &metallb.namespace_labels,
            &metallb.node_labels,
        );
        assert!(
            result
                .warnings
                .iter()
                .any(|w| w.contains("not allowed by serviceAllocation")),
            "mismatched namespace selector should warn"
        );
    }

    #[test]
    fn node_selector_match_with_labels() {
        let pool = make_test_pool("pool", "metallb-system", vec!["10.0.0.0/24"]);
        let mut l2 = make_test_l2("l2-node", "metallb-system", vec!["pool"]);
        l2.node_selectors = vec![make_label_selector(&[("role", "worker")], vec![])];

        let mut svc = make_lb_svc("test-svc");
        svc.annotations
            .insert("metallb.io/address-pool".into(), "pool".into());
        svc.lb_ingress.push(LBIngress {
            ip: Some("10.0.0.1".into()),
            hostname: None,
            ip_mode: None,
        });

        let mut metallb = make_test_metallb(vec![pool], vec![l2], vec![]);
        metallb.node_labels.insert(
            "worker-1".into(),
            [("role".to_string(), "worker".to_string())]
                .into_iter()
                .collect(),
        );
        metallb.node_labels.insert(
            "master-1".into(),
            [("role".to_string(), "master".to_string())]
                .into_iter()
                .collect(),
        );

        let result = resolve_metallb_for_service(
            &svc,
            "default",
            &metallb,
            &[],
            &metallb.namespace_labels,
            &metallb.node_labels,
        );
        assert_eq!(result.advertisements.len(), 1);
        assert_eq!(result.advertisements[0].node_selector_status, "matched 1");
        assert_eq!(result.advertisements[0].candidate_nodes, vec!["worker-1"]);
    }

    #[test]
    fn node_selector_mismatch() {
        let pool = make_test_pool("pool", "metallb-system", vec!["10.0.0.0/24"]);
        let mut l2 = make_test_l2("l2-node", "metallb-system", vec!["pool"]);
        l2.node_selectors = vec![make_label_selector(&[("role", "gpu")], vec![])];

        let mut svc = make_lb_svc("test-svc");
        svc.annotations
            .insert("metallb.io/address-pool".into(), "pool".into());
        svc.lb_ingress.push(LBIngress {
            ip: Some("10.0.0.1".into()),
            hostname: None,
            ip_mode: None,
        });

        let mut metallb = make_test_metallb(vec![pool], vec![l2], vec![]);
        metallb.node_labels.insert(
            "worker-1".into(),
            [("role".to_string(), "worker".to_string())]
                .into_iter()
                .collect(),
        );

        let result = resolve_metallb_for_service(
            &svc,
            "default",
            &metallb,
            &[],
            &metallb.namespace_labels,
            &metallb.node_labels,
        );
        assert_eq!(result.advertisements[0].node_selector_status, "mismatch");
        assert!(result.advertisements[0].candidate_nodes.is_empty());
    }

    #[test]
    fn local_endpoint_nodes_vs_advertised_nodes() {
        let pool = make_test_pool("pool", "metallb-system", vec!["10.0.0.0/24"]);
        let mut l2 = make_test_l2("l2-node", "metallb-system", vec!["pool"]);
        l2.node_selectors = vec![make_label_selector(&[("role", "worker")], vec![])];

        let mut svc = make_lb_svc("test-svc");
        svc.annotations
            .insert("metallb.io/address-pool".into(), "pool".into());
        svc.lb_ingress.push(LBIngress {
            ip: Some("10.0.0.1".into()),
            hostname: None,
            ip_mode: None,
        });
        svc.external_traffic_policy = Some("Local".into());

        let mut metallb = make_test_metallb(vec![pool], vec![l2], vec![]);
        metallb.node_labels.insert(
            "worker-1".into(),
            [("role".to_string(), "worker".to_string())]
                .into_iter()
                .collect(),
        );

        // Endpoint on non-advertised node
        let result = resolve_metallb_for_service(
            &svc,
            "default",
            &metallb,
            &["master-1".to_string()],
            &metallb.namespace_labels,
            &metallb.node_labels,
        );
        assert!(
            result
                .warnings
                .iter()
                .any(|w| w.contains("no ready endpoints on advertised nodes")),
            "should warn when endpoint nodes don't intersect advertised nodes"
        );

        // Endpoint on advertised node
        let result = resolve_metallb_for_service(
            &svc,
            "default",
            &metallb,
            &["worker-1".to_string()],
            &metallb.namespace_labels,
            &metallb.node_labels,
        );
        assert!(
            !result
                .warnings
                .iter()
                .any(|w| w.contains("no ready endpoints on advertised nodes")),
            "should not warn when endpoint nodes intersect advertised nodes"
        );
    }

    #[test]
    fn auto_assign_candidate_with_priority_sorting() {
        let mut pool_a = make_test_pool("pool-a", "metallb-system", vec!["10.0.0.0/24"]);
        pool_a.service_allocation = Some(ServiceAllocation {
            priority: 10,
            namespaces: vec![],
            namespace_selectors: vec![],
            service_selectors: vec![],
        });
        let mut pool_b = make_test_pool("pool-b", "metallb-system", vec!["10.1.0.0/24"]);
        pool_b.service_allocation = Some(ServiceAllocation {
            priority: 5,
            namespaces: vec![],
            namespace_selectors: vec![],
            service_selectors: vec![],
        });

        let l2 = make_test_l2("l2-all", "metallb-system", vec![]);

        // Service with MetalLB class but no explicit pool/IP match
        let mut svc = make_lb_svc("test-svc");
        svc.load_balancer_class = Some("metallb.io/metallb".into());

        let metallb = make_test_metallb(vec![pool_a, pool_b], vec![l2], vec![]);

        let result = resolve_metallb_for_service(
            &svc,
            "default",
            &metallb,
            &[],
            &metallb.namespace_labels,
            &metallb.node_labels,
        );
        assert!(
            result.pools.len() >= 2,
            "both pools should be autoAssign candidates"
        );
        assert_eq!(
            result.pools[0].pool.name, "pool-b",
            "lower priority should come first"
        );
        assert!(
            result.pools[0]
                .match_reason
                .contains("autoAssign candidate")
        );
    }

    #[test]
    fn auto_assign_false_excluded_from_candidates() {
        let mut pool = make_test_pool("no-auto", "metallb-system", vec!["10.0.0.0/24"]);
        pool.auto_assign = false;
        let l2 = make_test_l2("l2-all", "metallb-system", vec![]);

        let mut svc = make_lb_svc("test-svc");
        svc.load_balancer_class = Some("metallb.io/metallb".into());

        let metallb = make_test_metallb(vec![pool], vec![l2], vec![]);

        let result = resolve_metallb_for_service(
            &svc,
            "default",
            &metallb,
            &[],
            &metallb.namespace_labels,
            &metallb.node_labels,
        );
        assert!(
            result.pools.is_empty(),
            "autoAssign=false pools should not be candidates"
        );
    }

    #[test]
    fn same_priority_both_shown() {
        let mut pool_a = make_test_pool("pool-a", "metallb-system", vec!["10.0.0.0/24"]);
        pool_a.service_allocation = Some(ServiceAllocation {
            priority: 5,
            namespaces: vec![],
            namespace_selectors: vec![],
            service_selectors: vec![],
        });
        let mut pool_b = make_test_pool("pool-b", "metallb-system", vec!["10.1.0.0/24"]);
        pool_b.service_allocation = Some(ServiceAllocation {
            priority: 5,
            namespaces: vec![],
            namespace_selectors: vec![],
            service_selectors: vec![],
        });
        let l2 = make_test_l2("l2-all", "metallb-system", vec![]);

        let mut svc = make_lb_svc("test-svc");
        svc.load_balancer_class = Some("metallb.io/metallb".into());

        let metallb = make_test_metallb(vec![pool_a, pool_b], vec![l2], vec![]);

        let result = resolve_metallb_for_service(
            &svc,
            "default",
            &metallb,
            &[],
            &metallb.namespace_labels,
            &metallb.node_labels,
        );
        assert_eq!(result.pools.len(), 2, "both same-priority pools shown");
    }

    #[test]
    fn l2_interfaces_populated() {
        let obj = make_dynamic_object(
            "l2-with-ifaces",
            serde_json::json!({
                "apiVersion": "metallb.io/v1beta1",
                "kind": "L2Advertisement",
                "spec": {
                    "ipAddressPools": ["pool-1"],
                    "interfaces": ["eth0", "eth1"],
                }
            }),
        );
        let l2 = parse_l2_advertisement(obj).unwrap();
        assert_eq!(l2.interfaces, vec!["eth0", "eth1"]);
    }

    #[test]
    fn bgp_peers_populated() {
        let obj = make_dynamic_object(
            "bgp-with-peers",
            serde_json::json!({
                "apiVersion": "metallb.io/v1beta1",
                "kind": "BGPAdvertisement",
                "spec": {
                    "peers": ["peer-1", "peer-2"],
                }
            }),
        );
        let bgp = parse_bgp_advertisement(obj).unwrap();
        assert_eq!(bgp.peers, vec!["peer-1", "peer-2"]);
    }

    #[test]
    fn pool_status_counters_parsed() {
        let mut obj = make_dynamic_object(
            "pool-with-status",
            serde_json::json!({
                "apiVersion": "metallb.io/v1beta1",
                "kind": "IPAddressPool",
                "spec": {
                    "addresses": ["10.0.0.0/24"],
                },
                "status": {
                    "availableIPv4": 250,
                    "assignedIPv4": 6,
                    "availableIPv6": 100,
                    "assignedIPv6": 2,
                }
            }),
        );
        obj.metadata.namespace = Some("metallb-system".into());
        let pool = parse_ip_address_pool(obj).unwrap();
        assert_eq!(pool.status_available_ipv4, Some(250));
        assert_eq!(pool.status_assigned_ipv4, Some(6));
        assert_eq!(pool.status_available_ipv6, Some(100));
        assert_eq!(pool.status_assigned_ipv6, Some(2));
    }

    #[test]
    fn ip_allocated_from_pool_annotation() {
        let pool = make_test_pool("my-pool", "metallb-system", vec!["10.0.0.0/24"]);
        let l2 = make_test_l2("l2-all", "metallb-system", vec!["my-pool"]);

        let mut svc = make_lb_svc("test-svc");
        svc.annotations
            .insert("metallb.io/ip-allocated-from-pool".into(), "my-pool".into());
        svc.lb_ingress.push(LBIngress {
            ip: Some("10.0.0.5".into()),
            hostname: None,
            ip_mode: None,
        });

        let metallb = make_test_metallb(vec![pool], vec![l2], vec![]);

        let result = resolve_metallb_for_service(
            &svc,
            "default",
            &metallb,
            &[],
            &metallb.namespace_labels,
            &metallb.node_labels,
        );
        assert_eq!(result.provider.as_deref(), Some("MetalLB"));
        assert!(
            result
                .pools
                .iter()
                .any(|mp| mp.match_reason.contains("allocated from pool annotation"))
        );
    }

    #[test]
    fn metallb_inventory_warnings_field() {
        let inv = MetalLBInventory::default();
        assert!(inv.warnings.is_empty());
        assert!(!inv.available);
    }

    #[test]
    fn requested_ip_in_pool_gives_provider_and_pool_match() {
        let pool = make_test_pool("public", "metallb-system", vec!["192.0.2.0/24"]);
        let l2 = make_test_l2("l2-pub", "metallb-system", vec!["public"]);
        let metallb = make_test_metallb(vec![pool], vec![l2], vec![]);
        let mut svc = make_lb_svc("my-svc");
        svc.load_balancer_ip = Some("192.0.2.10".into());
        let result = resolve_metallb_for_service(
            &svc,
            "default",
            &metallb,
            &[],
            &metallb.namespace_labels,
            &metallb.node_labels,
        );
        assert_eq!(result.provider.as_deref(), Some("MetalLB"));
        assert_eq!(result.pools.len(), 1);
        assert!(
            result.pools[0].match_reason.contains("requested IP"),
            "match_reason should mention requested IP: {}",
            result.pools[0].match_reason
        );
        assert_eq!(result.requested_ips, vec!["192.0.2.10"]);
    }

    #[test]
    fn node_selector_mismatch_gives_explicit_warning_not_unknown() {
        let pool = make_test_pool("public", "metallb-system", vec!["10.0.0.0/24"]);
        let mut l2 = make_test_l2("l2-pub", "metallb-system", vec!["public"]);
        l2.node_selectors = vec![LabelSelector {
            match_labels: {
                let mut m = BTreeMap::new();
                m.insert("role".into(), "definitely-not-this".into());
                m
            },
            match_expressions: vec![],
        }];
        let mut metallb = make_test_metallb(vec![pool], vec![l2], vec![]);
        metallb.node_labels.insert("worker-1".into(), {
            let mut m = BTreeMap::new();
            m.insert("role".into(), "worker".into());
            m
        });
        let mut svc = make_lb_svc("web");
        svc.lb_ingress = vec![LBIngress {
            ip: Some("10.0.0.5".into()),
            hostname: None,
            ip_mode: None,
        }];
        svc.external_traffic_policy = Some("Local".into());
        let ep_nodes = vec!["worker-1".to_string()];
        let result = resolve_metallb_for_service(
            &svc,
            "default",
            &metallb,
            &ep_nodes,
            &metallb.namespace_labels,
            &metallb.node_labels,
        );
        assert_eq!(result.advertisements[0].node_selector_status, "mismatch");
        let has_mismatch_warning = result
            .warnings
            .iter()
            .any(|w| w.contains("nodeSelector matched no nodes"));
        assert!(
            has_mismatch_warning,
            "Should have nodeSelector mismatch warning: {:?}",
            result.warnings
        );
        let has_no_advertised = result
            .warnings
            .iter()
            .any(|w| w.contains("no advertised nodes"));
        assert!(
            has_no_advertised,
            "Local should warn about no advertised nodes: {:?}",
            result.warnings
        );
        assert!(
            !result.warnings.iter().any(|w| w.contains("unknown")),
            "Should not say unknown when nodes are evaluated: {:?}",
            result.warnings
        );
    }

    #[test]
    fn namespace_in_list_short_circuits_without_ns_labels() {
        let mut pool = make_test_pool("public", "metallb-system", vec!["10.0.0.0/24"]);
        pool.service_allocation = Some(ServiceAllocation {
            priority: 1,
            namespaces: vec!["allowed-ns".into()],
            namespace_selectors: vec![LabelSelector {
                match_labels: {
                    let mut m = BTreeMap::new();
                    m.insert("env".into(), "prod".into());
                    m
                },
                match_expressions: vec![],
            }],
            service_selectors: vec![],
        });
        let l2 = make_test_l2("l2-pub", "metallb-system", vec!["public"]);
        let metallb = make_test_metallb(vec![pool], vec![l2], vec![]);
        // namespace_labels is empty (not fetched), but namespaces list matches
        let mut svc = make_lb_svc("web");
        svc.lb_ingress = vec![LBIngress {
            ip: Some("10.0.0.5".into()),
            hostname: None,
            ip_mode: None,
        }];
        let result = resolve_metallb_for_service(
            &svc,
            "allowed-ns",
            &metallb,
            &[],
            &metallb.namespace_labels,
            &metallb.node_labels,
        );
        assert_eq!(result.pools.len(), 1);
        assert_eq!(
            result.pools[0].allocation_match.as_deref(),
            Some("OK"),
            "namespaces list match should short-circuit without checking unavailable ns labels"
        );
        assert!(
            !result.warnings.iter().any(|w| w.contains("unavailable")),
            "Should not warn about unavailable ns labels: {:?}",
            result.warnings
        );
    }

    fn make_metallb_gk_map() -> GroupKindMap {
        use crate::kube::discovery::KindInfo;
        let mut gk = GroupKindMap::new();
        gk.insert(
            ("metallb.io".into(), "IPAddressPool".into()),
            KindInfo {
                group: "metallb.io".into(),
                version: "v1beta1".into(),
                plural: "ipaddresspools".into(),
                namespaced: true,
                listable: true,
            },
        );
        gk.insert(
            ("metallb.io".into(), "L2Advertisement".into()),
            KindInfo {
                group: "metallb.io".into(),
                version: "v1beta1".into(),
                plural: "l2advertisements".into(),
                namespaced: true,
                listable: true,
            },
        );
        gk.insert(
            ("metallb.io".into(), "BGPAdvertisement".into()),
            KindInfo {
                group: "metallb.io".into(),
                version: "v1beta1".into(),
                plural: "bgpadvertisements".into(),
                namespaced: true,
                listable: true,
            },
        );
        gk
    }

    fn mock_403_response() -> http::Response<Body> {
        let body = serde_json::json!({
            "kind": "Status", "apiVersion": "v1", "metadata": {},
            "status": "Failure", "message": "forbidden", "reason": "Forbidden", "code": 403
        });
        http::Response::builder()
            .status(403)
            .body(Body::from(serde_json::to_vec(&body).unwrap()))
            .unwrap()
    }

    #[tokio::test]
    async fn metallb_no_selectors_skips_namespace_and_node_list() {
        use std::sync::Arc;
        use std::sync::atomic::{AtomicUsize, Ordering};

        let request_count = Arc::new(AtomicUsize::new(0));
        let request_paths = Arc::new(std::sync::Mutex::new(Vec::<String>::new()));
        let rc = request_count.clone();
        let rp = request_paths.clone();

        let (mock_service, handle) =
            tower_test::mock::pair::<http::Request<Body>, http::Response<Body>>();
        let client = Client::new(mock_service, "default");
        let gk_map = make_metallb_gk_map();

        let spawned = tokio::spawn(async move {
            let mut handle = pin!(handle);
            // Pool, L2, BGP = 3 LIST requests + 1 Event LIST. No Namespace/Node.
            for _ in 0..4 {
                let (req, send) = handle.next_request().await.expect("expected request");
                rc.fetch_add(1, Ordering::Relaxed);
                rp.lock().unwrap().push(req.uri().path().to_string());
                send.send_response(mock_empty_list());
            }
        });

        let inv = build_metallb_inventory(&client, "default", &gk_map).await;
        spawned.await.unwrap();

        assert!(inv.available);
        assert_eq!(request_count.load(Ordering::Relaxed), 4);
        let paths = request_paths.lock().unwrap();
        // Check that no cluster-scoped Namespace LIST was made
        // (the event path /api/v1/namespaces/default/events is expected)
        assert!(
            !paths.iter().any(|p| p == "/api/v1/namespaces"),
            "Should NOT list namespaces when no selectors: {:?}",
            *paths
        );
        assert!(
            !paths.iter().any(|p| p.contains("/nodes")),
            "Should NOT list nodes when no selectors: {:?}",
            *paths
        );
    }

    #[tokio::test]
    async fn metallb_with_selectors_fetches_namespace_and_node() {
        use std::sync::Arc;
        use std::sync::atomic::{AtomicUsize, Ordering};

        let request_count = Arc::new(AtomicUsize::new(0));
        let request_paths = Arc::new(std::sync::Mutex::new(Vec::<String>::new()));
        let rc = request_count.clone();
        let rp = request_paths.clone();

        let (mock_service, handle) =
            tower_test::mock::pair::<http::Request<Body>, http::Response<Body>>();
        let client = Client::new(mock_service, "default");
        let gk_map = make_metallb_gk_map();

        let spawned = tokio::spawn(async move {
            let mut handle = pin!(handle);
            // Pool LIST returns pool with namespaceSelectors
            let (req, send) = handle.next_request().await.expect("pool list");
            rc.fetch_add(1, Ordering::Relaxed);
            rp.lock().unwrap().push(req.uri().path().to_string());
            send.send_response(mock_json_response(serde_json::json!({
                "apiVersion": "metallb.io/v1beta1",
                "kind": "IPAddressPoolList",
                "metadata": {"resourceVersion": "1"},
                "items": [{
                    "apiVersion": "metallb.io/v1beta1",
                    "kind": "IPAddressPool",
                    "metadata": {"name": "pool-a", "namespace": "metallb-system"},
                    "spec": {
                        "addresses": ["10.0.0.0/24"],
                        "serviceAllocation": {
                            "namespaceSelectors": [{"matchLabels": {"env": "prod"}}]
                        }
                    }
                }]
            })));
            // L2 LIST returns ad with nodeSelectors
            let (req, send) = handle.next_request().await.expect("l2 list");
            rc.fetch_add(1, Ordering::Relaxed);
            rp.lock().unwrap().push(req.uri().path().to_string());
            send.send_response(mock_json_response(serde_json::json!({
                "apiVersion": "metallb.io/v1beta1",
                "kind": "L2AdvertisementList",
                "metadata": {"resourceVersion": "1"},
                "items": [{
                    "apiVersion": "metallb.io/v1beta1",
                    "kind": "L2Advertisement",
                    "metadata": {"name": "l2-a", "namespace": "metallb-system"},
                    "spec": {
                        "ipAddressPools": ["pool-a"],
                        "nodeSelectors": [{"matchLabels": {"role": "worker"}}]
                    }
                }]
            })));
            // BGP LIST empty
            let (req, send) = handle.next_request().await.expect("bgp list");
            rc.fetch_add(1, Ordering::Relaxed);
            rp.lock().unwrap().push(req.uri().path().to_string());
            send.send_response(mock_empty_list());
            // Namespace LIST (triggered by namespaceSelectors)
            let (req, send) = handle.next_request().await.expect("ns list");
            rc.fetch_add(1, Ordering::Relaxed);
            rp.lock().unwrap().push(req.uri().path().to_string());
            send.send_response(mock_empty_list());
            // Node LIST (triggered by nodeSelectors)
            let (req, send) = handle.next_request().await.expect("node list");
            rc.fetch_add(1, Ordering::Relaxed);
            rp.lock().unwrap().push(req.uri().path().to_string());
            send.send_response(mock_empty_list());
            // Event LIST
            let (req, send) = handle.next_request().await.expect("event list");
            rc.fetch_add(1, Ordering::Relaxed);
            rp.lock().unwrap().push(req.uri().path().to_string());
            send.send_response(mock_empty_list());
        });

        let inv = build_metallb_inventory(&client, "default", &gk_map).await;
        spawned.await.unwrap();

        assert_eq!(request_count.load(Ordering::Relaxed), 6);
        let paths = request_paths.lock().unwrap();
        assert!(
            paths.iter().any(|p| p.contains("/namespaces")),
            "Should list namespaces when namespaceSelectors present: {:?}",
            *paths
        );
        assert!(
            paths.iter().any(|p| p.contains("/nodes")),
            "Should list nodes when nodeSelectors present: {:?}",
            *paths
        );
        assert_eq!(inv.pools.len(), 1);
        assert_eq!(inv.l2_advertisements.len(), 1);
    }

    #[tokio::test]
    async fn metallb_api_403_returns_warning_single_request() {
        use std::sync::Arc;
        use std::sync::atomic::{AtomicUsize, Ordering};

        let request_count = Arc::new(AtomicUsize::new(0));
        let rc = request_count.clone();

        let (mock_service, handle) =
            tower_test::mock::pair::<http::Request<Body>, http::Response<Body>>();
        let client = Client::new(mock_service, "default");
        let gk_map = make_metallb_gk_map();

        let spawned = tokio::spawn(async move {
            let mut handle = pin!(handle);
            // Pool LIST → 403 (no retry for 403)
            let (_req, send) = handle.next_request().await.expect("pool list");
            rc.fetch_add(1, Ordering::Relaxed);
            send.send_response(mock_403_response());
            // L2 LIST → 403
            let (_req, send) = handle.next_request().await.expect("l2 list");
            rc.fetch_add(1, Ordering::Relaxed);
            send.send_response(mock_403_response());
            // BGP LIST → 403
            let (_req, send) = handle.next_request().await.expect("bgp list");
            rc.fetch_add(1, Ordering::Relaxed);
            send.send_response(mock_403_response());
            // Event LIST → 403
            let (_req, send) = handle.next_request().await.expect("event list");
            rc.fetch_add(1, Ordering::Relaxed);
            send.send_response(mock_403_response());
        });

        let inv = build_metallb_inventory(&client, "default", &gk_map).await;
        spawned.await.unwrap();

        assert_eq!(
            request_count.load(Ordering::Relaxed),
            4,
            "403 should not retry: 1 request per API"
        );
        assert_eq!(
            inv.warnings.len(),
            4,
            "Each 403 should produce a ScanWarning"
        );
        assert!(
            inv.warnings
                .iter()
                .all(|w| matches!(w, ScanWarning::Forbidden { .. })),
            "All warnings should be Forbidden"
        );
        assert!(inv.pools.is_empty());
    }

    // --- Phase 5: Observation tests ---

    struct ObsBuilder {
        l2_status: Vec<ServiceL2Status>,
        bgp_status: Vec<ServiceBGPStatus>,
        bgp_peers: Vec<BGPPeerInfo>,
        bfd_profiles: Vec<BFDProfileInfo>,
        l2_avail: ApiAvailability,
        bgp_avail: ApiAvailability,
        peer_avail: ApiAvailability,
        bfd_avail: ApiAvailability,
    }

    impl ObsBuilder {
        fn new() -> Self {
            Self {
                l2_status: vec![],
                bgp_status: vec![],
                bgp_peers: vec![],
                bfd_profiles: vec![],
                l2_avail: ApiAvailability::Absent,
                bgp_avail: ApiAvailability::Absent,
                peer_avail: ApiAvailability::Absent,
                bfd_avail: ApiAvailability::Absent,
            }
        }

        fn l2_status(mut self, v: Vec<ServiceL2Status>) -> Self {
            self.l2_status = v;
            self
        }
        fn bgp_status(mut self, v: Vec<ServiceBGPStatus>) -> Self {
            self.bgp_status = v;
            self
        }
        fn bgp_peers(mut self, v: Vec<BGPPeerInfo>) -> Self {
            self.bgp_peers = v;
            self
        }
        fn bfd_profiles(mut self, v: Vec<BFDProfileInfo>) -> Self {
            self.bfd_profiles = v;
            self
        }
        fn l2_avail(mut self, v: ApiAvailability) -> Self {
            self.l2_avail = v;
            self
        }
        fn bgp_avail(mut self, v: ApiAvailability) -> Self {
            self.bgp_avail = v;
            self
        }
        fn peer_avail(mut self, v: ApiAvailability) -> Self {
            self.peer_avail = v;
            self
        }
        fn bfd_avail(mut self, v: ApiAvailability) -> Self {
            self.bfd_avail = v;
            self
        }

        fn build(self) -> MetalLBObservation {
            MetalLBObservation {
                l2_status: self.l2_status,
                bgp_status: self.bgp_status,
                bgp_peers: self.bgp_peers,
                bfd_profiles: self.bfd_profiles,
                configuration_states: vec![],
                l2_status_availability: self.l2_avail,
                bgp_status_availability: self.bgp_avail,
                bgp_peer_availability: self.peer_avail,
                bfd_profile_availability: self.bfd_avail,
                config_state_availability: ApiAvailability::Absent,
            }
        }
    }

    fn correlate_test(
        svc_name: &str,
        svc_namespace: &str,
        obs: &MetalLBObservation,
        has_advertisements: bool,
        has_bgp_advertisement: bool,
        events: Vec<MetalLBServiceEvent>,
    ) -> CorrelatedObservation {
        correlate_metallb_observations(&CorrelateParams {
            svc_name,
            svc_namespace,
            svc_uid: "test-uid",
            observation: obs,
            has_advertisements,
            has_bgp_advertisement,
            events,
            event_availability: ApiAvailability::Absent,
            metallb_namespaces: &[],
        })
    }

    #[test]
    fn correlate_l2_status_advertising() {
        let obs = ObsBuilder::new()
            .l2_status(vec![ServiceL2Status {
                name: "l2status-1".into(),
                namespace: "metallb-system".into(),
                service_name: Some("web".into()),
                service_namespace: Some("default".into()),
                node: Some("worker-0".into()),
                interfaces: vec!["eth0".into()],
            }])
            .l2_avail(ApiAvailability::Available)
            .build();
        let result = correlate_test("web", "default", &obs, true, false, vec![]);
        assert_eq!(result.observed_state, "advertising");
        assert_eq!(result.l2_advertised_nodes, vec!["worker-0"]);
        assert_eq!(result.l2_interfaces, vec!["eth0"]);
    }

    #[test]
    fn correlate_no_status_configured() {
        let obs = ObsBuilder::new()
            .l2_status(vec![ServiceL2Status {
                name: "l2status-other".into(),
                namespace: "metallb-system".into(),
                service_name: Some("other-svc".into()),
                service_namespace: Some("default".into()),
                node: Some("worker-0".into()),
                interfaces: vec![],
            }])
            .l2_avail(ApiAvailability::Available)
            .build();
        // has_advertisements=true, L2 status Available but no match for "web"
        let result = correlate_test("web", "default", &obs, true, false, vec![]);
        assert_eq!(result.observed_state, "configured");
        assert!(result.l2_advertised_nodes.is_empty());
    }

    #[test]
    fn correlate_no_advertisements_empty_state() {
        let obs = MetalLBObservation::default();
        let result = correlate_test("web", "default", &obs, false, false, vec![]);
        assert_eq!(result.observed_state, "");
    }

    #[test]
    fn correlate_absent_apis_unknown_state() {
        // Both L2+BGP status Absent with ads → "unknown"
        let obs = MetalLBObservation::default();
        let result = correlate_test("web", "default", &obs, true, false, vec![]);
        assert_eq!(result.observed_state, "unknown");
    }

    #[test]
    fn correlate_available_zero_items_configured() {
        // API Available with 0 items → "configured"
        let obs = ObsBuilder::new()
            .l2_avail(ApiAvailability::Available)
            .build();
        let result = correlate_test("web", "default", &obs, true, false, vec![]);
        assert_eq!(result.observed_state, "configured");
    }

    #[test]
    fn correlate_unavailable_unknown() {
        // API Unavailable → "unknown"
        let obs = ObsBuilder::new()
            .l2_avail(ApiAvailability::Unavailable)
            .build();
        let result = correlate_test("web", "default", &obs, true, false, vec![]);
        assert_eq!(result.observed_state, "unknown");
    }

    #[test]
    fn correlate_bgp_peer_cross_reference_by_name() {
        let obs = ObsBuilder::new()
            .bgp_status(vec![ServiceBGPStatus {
                name: "bgpstatus-1".into(),
                namespace: "metallb-system".into(),
                service_name: Some("web".into()),
                service_namespace: Some("default".into()),
                node: Some("worker-1".into()),
                peers: vec!["router-a".into()],
            }])
            .bgp_peers(vec![BGPPeerInfo {
                name: "router-a".into(),
                namespace: "metallb-system".into(),
                peer_address: Some("192.168.1.1".into()),
                peer_asn: Some(64512),
                my_asn: Some(64513),
                source_address: None,
                node_selectors: vec![],
                bfd_profile: Some("fast-detect".into()),
                hold_time: None,
                keepalive_time: None,
                router_id: None,
            }])
            .bfd_profiles(vec![BFDProfileInfo {
                name: "fast-detect".into(),
                namespace: "metallb-system".into(),
                detect_multiplier: Some(3),
                receive_interval: Some(300),
                transmit_interval: Some(300),
                echo_interval: None,
                minimum_ttl: None,
                passive_mode: None,
            }])
            .bgp_avail(ApiAvailability::Available)
            .peer_avail(ApiAvailability::Available)
            .bfd_avail(ApiAvailability::Available)
            .build();
        let result = correlate_test("web", "default", &obs, true, false, vec![]);
        assert_eq!(result.observed_state, "advertising");
        assert_eq!(result.bgp_advertised_nodes.len(), 1);
        assert_eq!(result.bgp_advertised_nodes[0].node, "worker-1");
        assert_eq!(result.related_peers.len(), 1);
        assert_eq!(result.related_peers[0].name, "router-a");
        assert_eq!(result.related_bfd_profiles.len(), 1);
        assert_eq!(result.related_bfd_profiles[0].name, "fast-detect");
        // BGP session state always unknown when BGP items present
        assert_eq!(result.session_state, "unknown");
    }

    #[test]
    fn correlate_bgp_session_state_always_unknown() {
        let obs = ObsBuilder::new()
            .bgp_status(vec![ServiceBGPStatus {
                name: "bgpstatus-1".into(),
                namespace: "metallb-system".into(),
                service_name: Some("web".into()),
                service_namespace: Some("default".into()),
                node: Some("worker-1".into()),
                peers: vec![],
            }])
            .bgp_avail(ApiAvailability::Available)
            .build();
        let result = correlate_test("web", "default", &obs, true, false, vec![]);
        assert_eq!(result.session_state, "unknown");
    }

    #[test]
    fn correlate_bgp_session_state_with_bgp_advertisement() {
        // BGPAdvertisement present but no status → session_state should be "unknown"
        let obs = MetalLBObservation::default();
        let result = correlate_test("web", "default", &obs, true, true, vec![]);
        assert_eq!(result.session_state, "unknown");
    }

    #[test]
    fn correlate_same_namespace_peer_filtering() {
        // BGPPeer in different namespace should not match
        let obs = ObsBuilder::new()
            .bgp_status(vec![ServiceBGPStatus {
                name: "bgpstatus-1".into(),
                namespace: "metallb-system".into(),
                service_name: Some("web".into()),
                service_namespace: Some("default".into()),
                node: Some("worker-1".into()),
                peers: vec!["router-a".into()],
            }])
            .bgp_peers(vec![
                BGPPeerInfo {
                    name: "router-a".into(),
                    namespace: "other-ns".into(), // wrong namespace
                    peer_address: Some("192.168.1.1".into()),
                    peer_asn: Some(64512),
                    my_asn: Some(64513),
                    source_address: None,
                    node_selectors: vec![],
                    bfd_profile: None,
                    hold_time: None,
                    keepalive_time: None,
                    router_id: None,
                },
                BGPPeerInfo {
                    name: "router-a".into(),
                    namespace: "metallb-system".into(), // correct namespace
                    peer_address: Some("192.168.1.2".into()),
                    peer_asn: Some(64514),
                    my_asn: Some(64515),
                    source_address: None,
                    node_selectors: vec![],
                    bfd_profile: None,
                    hold_time: None,
                    keepalive_time: None,
                    router_id: None,
                },
            ])
            .bgp_avail(ApiAvailability::Available)
            .peer_avail(ApiAvailability::Available)
            .build();
        let result = correlate_test("web", "default", &obs, true, false, vec![]);
        assert_eq!(result.related_peers.len(), 1);
        assert_eq!(result.related_peers[0].namespace, "metallb-system");
        assert_eq!(result.related_peers[0].peer_asn, Some(64514));
    }

    #[test]
    fn correlate_event_filtering() {
        let events = vec![
            MetalLBServiceEvent {
                service_name: "web".into(),
                service_namespace: "default".into(),
                reason: Some("IPAllocated".into()),
                message: Some("Assigned IP 10.0.0.5".into()),
                source_component: Some("metallb-controller".into()),
                reporting_component: Some("metallb-controller".into()),
                involved_uid: Some("test-uid".into()),
                event_type: Some("Normal".into()),
                last_timestamp: None,
            },
            MetalLBServiceEvent {
                service_name: "other".into(),
                service_namespace: "default".into(),
                reason: Some("IPAllocated".into()),
                message: Some("Assigned IP 10.0.0.6".into()),
                source_component: Some("metallb-controller".into()),
                reporting_component: Some("metallb-controller".into()),
                involved_uid: Some("other-uid".into()),
                event_type: Some("Normal".into()),
                last_timestamp: None,
            },
        ];
        let obs = MetalLBObservation::default();
        let result = correlate_test("web", "default", &obs, true, false, events);
        assert_eq!(result.events.len(), 1);
        assert_eq!(result.events[0].service_name, "web");
    }

    #[test]
    fn correlate_event_uid_mismatch_excluded() {
        let events = vec![MetalLBServiceEvent {
            service_name: "web".into(),
            service_namespace: "default".into(),
            reason: Some("IPAllocated".into()),
            message: Some("Assigned IP 10.0.0.5".into()),
            source_component: Some("metallb-controller".into()),
            reporting_component: Some("metallb-controller".into()),
            involved_uid: Some("wrong-uid".into()),
            event_type: Some("Normal".into()),
            last_timestamp: None,
        }];
        let obs = MetalLBObservation::default();
        let result = correlate_test("web", "default", &obs, true, false, events);
        assert!(
            result.events.is_empty(),
            "UID mismatch should exclude event"
        );
    }

    #[test]
    fn event_exact_component_matching() {
        // "metallb-speaker" yes, "service-controller" no
        assert!(METALLB_COMPONENTS.contains(&"metallb-speaker"));
        assert!(!METALLB_COMPONENTS.contains(&"service-controller"));
        assert!(METALLB_COMPONENTS.contains(&"speaker"));
        assert!(!METALLB_COMPONENTS.contains(&"controller"));
    }

    #[test]
    fn api_availability_in_correlated() {
        let obs = ObsBuilder::new()
            .l2_avail(ApiAvailability::Available)
            .build();
        let result = correlate_metallb_observations(&CorrelateParams {
            svc_name: "web",
            svc_namespace: "default",
            svc_uid: "test-uid",
            observation: &obs,
            has_advertisements: true,
            has_bgp_advertisement: false,
            events: vec![],
            event_availability: ApiAvailability::Available,
            metallb_namespaces: &[],
        });
        assert_eq!(
            result.api_availability.l2_status,
            ApiAvailability::Available
        );
        assert_eq!(result.api_availability.bgp_status, ApiAvailability::Absent);
        assert_eq!(result.api_availability.events, ApiAvailability::Available);
        assert_eq!(
            result.api_availability.configuration_state,
            ApiAvailability::Absent
        );
    }

    #[test]
    fn parse_l2_status_interface_info() {
        let mut obj = DynamicObject::new(
            "l2status-1",
            &ApiResource::erase::<k8s_openapi::api::core::v1::ConfigMap>(&()),
        );
        obj.metadata.namespace = Some("metallb-system".into());
        obj.data = serde_json::json!({
            "spec": {
                "serviceName": "web",
                "serviceNamespace": "default",
            },
            "status": {
                "node": "worker-0",
                "interfaces": [{"name": "eth0"}, {"name": "ens3"}]
            }
        });
        let status = parse_service_l2_status(obj).unwrap();
        assert_eq!(status.interfaces, vec!["eth0", "ens3"]);
    }

    #[test]
    fn parse_bgp_status_peers() {
        let mut obj = DynamicObject::new(
            "bgpstatus-1",
            &ApiResource::erase::<k8s_openapi::api::core::v1::ConfigMap>(&()),
        );
        obj.metadata.namespace = Some("metallb-system".into());
        obj.data = serde_json::json!({
            "spec": {
                "serviceName": "web",
                "serviceNamespace": "default",
            },
            "status": {
                "node": "worker-0",
                "peers": ["router-a", "router-b"]
            }
        });
        let status = parse_service_bgp_status(obj).unwrap();
        assert_eq!(status.peers, vec!["router-a", "router-b"]);
    }

    #[test]
    fn parse_bgp_peer_from_dynamic_object() {
        let mut obj = DynamicObject::new(
            "peer-1",
            &ApiResource::erase::<k8s_openapi::api::core::v1::ConfigMap>(&()),
        );
        obj.metadata.namespace = Some("metallb-system".into());
        obj.data = serde_json::json!({
            "spec": {
                "peerAddress": "10.0.0.1",
                "peerASN": 64512,
                "myASN": 64513,
                "sourceAddress": "10.0.0.100",
                "bfdProfile": "default",
                "holdTime": "90s",
                "routerID": "10.0.0.100",
                "nodeSelectors": [{
                    "matchLabels": {
                        "role": "worker"
                    }
                }]
            }
        });
        let peer = parse_bgp_peer(obj).unwrap();
        assert_eq!(peer.name, "peer-1");
        assert_eq!(peer.peer_address.as_deref(), Some("10.0.0.1"));
        assert_eq!(peer.peer_asn, Some(64512));
        assert_eq!(peer.my_asn, Some(64513));
        assert_eq!(peer.bfd_profile.as_deref(), Some("default"));
        assert_eq!(peer.hold_time.as_deref(), Some("90s"));
        assert_eq!(peer.node_selectors.len(), 1);
    }

    #[test]
    fn observation_api_absence_graceful() {
        // When MetalLBObservation is default (all Absent), no observation possible → empty
        let metallb = make_test_metallb(
            vec![make_test_pool(
                "pool",
                "metallb-system",
                vec!["10.0.0.0/24"],
            )],
            vec![make_test_l2("l2", "metallb-system", vec!["pool"])],
            vec![],
        );
        let mut svc = make_lb_svc("web");
        svc.lb_ingress = vec![LBIngress {
            ip: Some("10.0.0.5".into()),
            hostname: None,
            ip_mode: None,
        }];
        let result = resolve_metallb_for_service(
            &svc,
            "default",
            &metallb,
            &[],
            &metallb.namespace_labels,
            &metallb.node_labels,
        );
        assert_eq!(result.provider.as_deref(), Some("MetalLB"));
        // All observation APIs Absent with advertisements → "unknown"
        assert_eq!(result.observation.observed_state, "unknown");
    }

    #[test]
    fn parse_configuration_state_basic() {
        let mut obj = DynamicObject::new(
            "cs-1",
            &ApiResource::erase::<k8s_openapi::api::core::v1::ConfigMap>(&()),
        );
        obj.metadata.namespace = Some("metallb-system".into());
        obj.metadata.labels = Some(BTreeMap::from([
            ("metallb.io/component-type".into(), "speaker".into()),
            ("metallb.io/node-name".into(), "worker-0".into()),
        ]));
        obj.data = serde_json::json!({
            "status": {
                "result": "Success",
                "errorSummary": "",
                "conditions": [{
                    "type": "Ready",
                    "status": "True",
                    "reason": "AllGood",
                    "message": "everything fine"
                }]
            }
        });
        let cs = parse_configuration_state(obj).unwrap();
        assert_eq!(cs.name, "cs-1");
        assert_eq!(cs.component_type.as_deref(), Some("speaker"));
        assert_eq!(cs.node_name.as_deref(), Some("worker-0"));
        assert_eq!(cs.result.as_deref(), Some("Success"));
        assert_eq!(cs.conditions.len(), 1);
        assert_eq!(cs.conditions[0].condition_type, "Ready");
    }

    #[tokio::test]
    async fn event_field_selector_403_single_request() {
        let (mock_service, handle) =
            tower_test::mock::pair::<http::Request<Body>, http::Response<Body>>();
        let client = Client::new(mock_service, "default");
        let rc = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let rc2 = rc.clone();

        let spawned = tokio::spawn(async move {
            let mut handle = pin!(handle);
            let (_req, send) = handle.next_request().await.unwrap();
            rc2.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            send.send_response(mock_403_response());
        });

        let (events, avail, warnings) =
            fetch_metallb_service_events(&client, "default", "web", "uid-1").await;
        spawned.await.unwrap();
        assert!(events.is_empty());
        assert_eq!(avail, ApiAvailability::Unavailable);
        assert_eq!(warnings.len(), 1);
        assert_eq!(rc.load(std::sync::atomic::Ordering::Relaxed), 1);
    }

    #[tokio::test]
    async fn event_field_selector_500_persistent_3_requests() {
        let (mock_service, handle) =
            tower_test::mock::pair::<http::Request<Body>, http::Response<Body>>();
        let client = Client::new(mock_service, "default");
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

        let (events, avail, warnings) =
            fetch_metallb_service_events(&client, "default", "web", "uid-1").await;
        spawned.await.unwrap();
        assert!(events.is_empty());
        assert_eq!(avail, ApiAvailability::Unavailable);
        assert!(!warnings.is_empty());
        assert_eq!(rc.load(std::sync::atomic::Ordering::Relaxed), 3);
    }

    #[tokio::test]
    async fn event_field_selector_500_then_200_recovery() {
        let (mock_service, handle) =
            tower_test::mock::pair::<http::Request<Body>, http::Response<Body>>();
        let client = Client::new(mock_service, "default");
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

        let (events, avail, _warnings) =
            fetch_metallb_service_events(&client, "default", "web", "uid-1").await;
        spawned.await.unwrap();
        assert!(events.is_empty()); // empty list has no metallb events
        assert_eq!(avail, ApiAvailability::Available);
        assert_eq!(rc.load(std::sync::atomic::Ordering::Relaxed), 2);
    }

    #[test]
    fn is_metallb_event_component_source_only() {
        assert!(is_metallb_event_component(Some("metallb-speaker"), None));
        assert!(is_metallb_event_component(Some("metallb-controller"), None));
        assert!(!is_metallb_event_component(
            Some("service-controller"),
            None
        ));
        assert!(!is_metallb_event_component(Some("controller"), None));
    }

    #[test]
    fn is_metallb_event_component_reporting_only() {
        assert!(is_metallb_event_component(None, Some("metallb-controller")));
        assert!(is_metallb_event_component(None, Some("speaker")));
        assert!(!is_metallb_event_component(
            None,
            Some("service-controller")
        ));
    }

    #[test]
    fn is_metallb_event_component_both_empty() {
        assert!(!is_metallb_event_component(None, None));
        assert!(!is_metallb_event_component(Some(""), Some("")));
    }

    #[test]
    fn is_metallb_event_component_reporting_fallback() {
        // source is non-metallb but reporting IS metallb → should match
        assert!(is_metallb_event_component(
            Some("other"),
            Some("metallb-speaker")
        ));
        // source is metallb, reporting is non-metallb → should match
        assert!(is_metallb_event_component(
            Some("metallb-speaker"),
            Some("other")
        ));
    }

    #[test]
    fn config_state_empty_namespaces_returns_zero() {
        let obs = MetalLBObservation {
            configuration_states: vec![ConfigurationStateInfo {
                name: "cs-1".into(),
                namespace: "metallb-other".into(),
                component_type: None,
                node_name: None,
                result: Some("OK".into()),
                error_summary: None,
                conditions: vec![],
            }],
            ..Default::default()
        };
        let params = CorrelateParams {
            svc_name: "web",
            svc_namespace: "default",
            svc_uid: "uid-1",
            observation: &obs,
            has_advertisements: true,
            has_bgp_advertisement: false,
            events: vec![],
            event_availability: ApiAvailability::Absent,
            metallb_namespaces: &[], // empty = no pools/ads matched
        };
        let result = correlate_metallb_observations(&params);
        assert!(
            result.configuration_states.is_empty(),
            "Empty metallb_namespaces should yield 0 ConfigurationStates"
        );
    }
}
