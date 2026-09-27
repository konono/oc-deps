use std::collections::HashMap;
#[cfg(test)]
use std::collections::HashSet;

use ::kube::{
    Client,
    api::{Api, DynamicObject},
};
use anyhow::Result;

use crate::kube::discovery::GroupKindMap;
use crate::kube::resource::ResourceId;
use crate::teardown::plan::{InboundRefIdentity, RefScanCoverage};

pub struct InboundRefScan {
    #[allow(dead_code)]
    pub target: ResourceId,
    pub blockers: Vec<InboundReferrer>,
    pub allowed: Vec<InboundReferrer>,
    pub coverage: RefScanCoverage,
}

pub struct InboundReferrer {
    pub resource: ResourceId,
    pub uid: String,
    pub ref_field: String,
}

pub type DeletionKey = (String, String, Option<String>, String);

pub fn deletion_key(group: &str, kind: &str, ns: Option<&str>, name: &str) -> DeletionKey {
    (
        group.to_string(),
        kind.to_string(),
        ns.map(|s| s.to_string()),
        name.to_string(),
    )
}

pub type DeletionClosureWithUid = HashMap<DeletionKey, String>;

#[cfg(test)]
pub fn build_deletion_closure_with_uid(
    phases: &[crate::teardown::plan::ExecutionPhase],
    explicit_targets: &[crate::DeleteResourceSpec],
) -> DeletionClosureWithUid {
    use crate::teardown::plan::ExecutionAction;
    let mut closure = DeletionClosureWithUid::new();
    for phase in phases {
        for res in &phase.resources {
            if matches!(
                res.action,
                ExecutionAction::Delete | ExecutionAction::Expect
            ) {
                let key = deletion_key(&res.group, &res.kind, res.namespace.as_deref(), &res.name);
                if let Some(uid) = &res.uid {
                    closure.insert(key, uid.clone());
                }
            }
        }
    }
    for t in explicit_targets {
        let key = deletion_key(&t.group, &t.kind, t.namespace.as_deref(), &t.name);
        closure.entry(key).or_default();
    }
    closure
}

struct OwnerEntry {
    group: String,
    kind: String,
    name: String,
    uid: String,
    ns: Option<String>,
}

struct LiveNodeIdentity {
    group: String,
    kind: String,
    name: String,
    ns: Option<String>,
    owners: Vec<OwnerEntry>,
}

struct OwnerGraph {
    nodes: HashMap<String, LiveNodeIdentity>,
}

struct TaggedObject<'a> {
    obj: &'a DynamicObject,
    group: &'a str,
    kind: &'a str,
}

fn build_owner_graph(tagged_objects: &[TaggedObject]) -> OwnerGraph {
    let mut nodes = HashMap::new();
    for tagged in tagged_objects {
        let obj = tagged.obj;
        let Some(uid) = obj.metadata.uid.as_deref() else {
            continue;
        };
        if uid.is_empty() {
            continue;
        }
        let ns = obj.metadata.namespace.clone();
        let name = obj.metadata.name.clone().unwrap_or_default();

        let owners = obj
            .metadata
            .owner_references
            .as_ref()
            .map(|refs| {
                refs.iter()
                    .map(|oref| {
                        let og = if let Some(idx) = oref.api_version.find('/') {
                            oref.api_version[..idx].to_string()
                        } else {
                            String::new()
                        };
                        OwnerEntry {
                            group: og,
                            kind: oref.kind.clone(),
                            name: oref.name.clone(),
                            uid: oref.uid.clone(),
                            ns: ns.clone(),
                        }
                    })
                    .collect()
            })
            .unwrap_or_default();

        nodes.insert(
            uid.to_string(),
            LiveNodeIdentity {
                group: tagged.group.to_string(),
                kind: tagged.kind.to_string(),
                name,
                ns,
                owners,
            },
        );
    }
    OwnerGraph { nodes }
}

fn owner_ref_matches_live_node(oref: &OwnerEntry, live: &LiveNodeIdentity) -> bool {
    oref.group == live.group
        && oref.kind == live.kind
        && oref.name == live.name
        && oref.ns == live.ns
}

fn is_in_deletion_closure(entry: &OwnerEntry, closure: &DeletionClosureWithUid) -> bool {
    if entry.uid.is_empty() {
        return false;
    }
    let keys = [
        deletion_key(&entry.group, &entry.kind, entry.ns.as_deref(), &entry.name),
        deletion_key(&entry.group, &entry.kind, None, &entry.name),
    ];
    for key in &keys {
        if let Some(closure_uid) = closure.get(key)
            && !closure_uid.is_empty()
            && *closure_uid == entry.uid
        {
            return true;
        }
    }
    false
}

/// Check if ALL owner branches of an object transitively resolve into the
/// deletion closure. Uses ALL-path semantics: every owner at every hop must
/// itself be in the closure or have all its owners resolve recursively.
/// Identity at each hop is verified against live objects.
#[derive(Clone, Copy, PartialEq)]
enum VisitState {
    Visiting,
    Resolved,
}

fn is_transitively_owned_by_closure(
    obj: &DynamicObject,
    closure: &DeletionClosureWithUid,
    graph: &OwnerGraph,
) -> bool {
    let obj_uid = match obj.metadata.uid.as_deref() {
        Some(u) if !u.is_empty() => u,
        _ => return false,
    };
    let node = match graph.nodes.get(obj_uid) {
        Some(n) => n,
        None => return false,
    };
    if node.owners.is_empty() {
        return false;
    }

    let mut memo: HashMap<String, VisitState> = HashMap::new();
    all_owners_resolve(&node.owners, closure, graph, &mut memo)
}

fn all_owners_resolve(
    owners: &[OwnerEntry],
    closure: &DeletionClosureWithUid,
    graph: &OwnerGraph,
    memo: &mut HashMap<String, VisitState>,
) -> bool {
    if owners.is_empty() {
        return false;
    }
    for owner in owners {
        if owner.uid.is_empty() {
            return false;
        }
        // 1. Exact closure hit needs no memo or identity check
        if is_in_deletion_closure(owner, closure) {
            continue;
        }
        // 2. Resolve live node and verify identity before trusting any cached state
        let Some(live_node) = graph.nodes.get(&owner.uid) else {
            return false;
        };
        if !owner_ref_matches_live_node(owner, live_node) {
            return false;
        }
        // 3. Consult memo only after identity is verified
        if let Some(&state) = memo.get(&owner.uid) {
            match state {
                VisitState::Resolved => continue,
                VisitState::Visiting => return false,
            }
        }
        memo.insert(owner.uid.clone(), VisitState::Visiting);
        if !all_owners_resolve(&live_node.owners, closure, graph, memo) {
            return false;
        }
        memo.insert(owner.uid.clone(), VisitState::Resolved);
    }
    true
}

/// Returns (group, kind) pairs of potential referrer kinds and whether they are
/// required (must exist in discovery) or optional (may not be served).
struct ReferrerSpec {
    group: &'static str,
    kind: &'static str,
    required: bool,
}

fn referrer_specs_for_target(target_kind: &str, target_group: &str) -> Vec<ReferrerSpec> {
    match (target_group, target_kind) {
        ("gateway.networking.k8s.io", "Gateway") => vec![
            ReferrerSpec {
                group: "gateway.networking.k8s.io",
                kind: "HTTPRoute",
                required: false,
            },
            ReferrerSpec {
                group: "gateway.networking.k8s.io",
                kind: "GRPCRoute",
                required: false,
            },
            ReferrerSpec {
                group: "gateway.networking.k8s.io",
                kind: "TCPRoute",
                required: false,
            },
            ReferrerSpec {
                group: "gateway.networking.k8s.io",
                kind: "TLSRoute",
                required: false,
            },
            ReferrerSpec {
                group: "gateway.networking.k8s.io",
                kind: "UDPRoute",
                required: false,
            },
        ],
        ("", "ConfigMap") => vec![
            ReferrerSpec {
                group: "apps",
                kind: "Deployment",
                required: true,
            },
            ReferrerSpec {
                group: "apps",
                kind: "StatefulSet",
                required: true,
            },
            ReferrerSpec {
                group: "apps",
                kind: "DaemonSet",
                required: true,
            },
            ReferrerSpec {
                group: "apps",
                kind: "ReplicaSet",
                required: true,
            },
            ReferrerSpec {
                group: "batch",
                kind: "Job",
                required: true,
            },
            ReferrerSpec {
                group: "batch",
                kind: "CronJob",
                required: true,
            },
            ReferrerSpec {
                group: "",
                kind: "Pod",
                required: true,
            },
            ReferrerSpec {
                group: "gateway.networking.k8s.io",
                kind: "Gateway",
                required: false,
            },
        ],
        ("", "Service") => vec![
            ReferrerSpec {
                group: "console.openshift.io",
                kind: "ConsolePlugin",
                required: false,
            },
            ReferrerSpec {
                group: "gateway.networking.k8s.io",
                kind: "HTTPRoute",
                required: false,
            },
            ReferrerSpec {
                group: "gateway.networking.k8s.io",
                kind: "GRPCRoute",
                required: false,
            },
            ReferrerSpec {
                group: "gateway.networking.k8s.io",
                kind: "TCPRoute",
                required: false,
            },
            ReferrerSpec {
                group: "gateway.networking.k8s.io",
                kind: "TLSRoute",
                required: false,
            },
            ReferrerSpec {
                group: "gateway.networking.k8s.io",
                kind: "UDPRoute",
                required: false,
            },
            ReferrerSpec {
                group: "networking.k8s.io",
                kind: "Ingress",
                required: true,
            },
            ReferrerSpec {
                group: "route.openshift.io",
                kind: "Route",
                required: false,
            },
        ],
        ("console.openshift.io", "ConsolePlugin") => vec![ReferrerSpec {
            group: "operator.openshift.io",
            kind: "Console",
            required: false,
        }],
        ("apps", "Deployment") => vec![ReferrerSpec {
            group: "autoscaling",
            kind: "HorizontalPodAutoscaler",
            required: true,
        }],
        _ => vec![],
    }
}

fn has_known_extractors(target_kind: &str, target_group: &str) -> bool {
    matches!(
        (target_group, target_kind),
        ("gateway.networking.k8s.io", "Gateway")
            | ("", "ConfigMap")
            | ("", "Service")
            | ("console.openshift.io", "ConsolePlugin")
            | ("apps", "Deployment")
    )
}

fn extract_gateway_parent_refs(
    route: &DynamicObject,
    target_name: &str,
    target_ns: Option<&str>,
) -> Vec<String> {
    let mut fields = Vec::new();
    let parent_refs = route
        .data
        .get("spec")
        .and_then(|s| s.get("parentRefs"))
        .and_then(|p| p.as_array());

    if let Some(refs) = parent_refs {
        for (i, pref) in refs.iter().enumerate() {
            let name = pref.get("name").and_then(|n| n.as_str()).unwrap_or("");
            let group = pref
                .get("group")
                .and_then(|g| g.as_str())
                .unwrap_or("gateway.networking.k8s.io");
            let kind = pref
                .get("kind")
                .and_then(|k| k.as_str())
                .unwrap_or("Gateway");
            let ref_ns = pref.get("namespace").and_then(|n| n.as_str());

            if kind != "Gateway" || group != "gateway.networking.k8s.io" {
                continue;
            }
            if name != target_name {
                continue;
            }
            let effective_ns = ref_ns.or(route.metadata.namespace.as_deref());
            if effective_ns != target_ns {
                continue;
            }
            fields.push(format!("spec.parentRefs[{}]", i));
        }
    }
    fields
}

fn extract_configmap_refs_from_pod_spec(
    pod_spec: &serde_json::Value,
    prefix: &str,
    target_name: &str,
) -> Vec<String> {
    let mut fields = Vec::new();
    if let Some(volumes) = pod_spec.get("volumes").and_then(|v| v.as_array()) {
        for (i, vol) in volumes.iter().enumerate() {
            if let Some(name) = vol
                .get("configMap")
                .and_then(|cm| cm.get("name"))
                .and_then(|n| n.as_str())
                && name == target_name
            {
                fields.push(format!("{prefix}volumes[{}].configMap.name", i));
            }
            if let Some(projected) = vol
                .get("projected")
                .and_then(|p| p.get("sources"))
                .and_then(|s| s.as_array())
            {
                for (si, src) in projected.iter().enumerate() {
                    if let Some(name) = src
                        .get("configMap")
                        .and_then(|cm| cm.get("name"))
                        .and_then(|n| n.as_str())
                        && name == target_name
                    {
                        fields.push(format!(
                            "{prefix}volumes[{}].projected.sources[{}].configMap.name",
                            i, si
                        ));
                    }
                }
            }
        }
    }
    for container_field in ["containers", "initContainers", "ephemeralContainers"] {
        if let Some(containers) = pod_spec.get(container_field).and_then(|c| c.as_array()) {
            for (ci, container) in containers.iter().enumerate() {
                if let Some(env_from) = container.get("envFrom").and_then(|e| e.as_array()) {
                    for (ei, ef) in env_from.iter().enumerate() {
                        if let Some(name) = ef
                            .get("configMapRef")
                            .and_then(|cm| cm.get("name"))
                            .and_then(|n| n.as_str())
                            && name == target_name
                        {
                            fields.push(format!(
                                "{prefix}{container_field}[{ci}].envFrom[{ei}].configMapRef.name"
                            ));
                        }
                    }
                }
                if let Some(env) = container.get("env").and_then(|e| e.as_array()) {
                    for (ei, ev) in env.iter().enumerate() {
                        if let Some(name) = ev
                            .get("valueFrom")
                            .and_then(|v| v.get("configMapKeyRef"))
                            .and_then(|cm| cm.get("name"))
                            .and_then(|n| n.as_str())
                            && name == target_name
                        {
                            fields.push(format!("{prefix}{container_field}[{ci}].env[{ei}].valueFrom.configMapKeyRef.name"));
                        }
                    }
                }
            }
        }
    }
    fields
}

fn extract_configmap_refs(
    obj: &DynamicObject,
    target_name: &str,
    target_ns: Option<&str>,
) -> Vec<String> {
    if let Some(target_ns) = target_ns
        && obj.metadata.namespace.as_deref() != Some(target_ns)
    {
        return Vec::new();
    }
    let spec = match obj.data.get("spec") {
        Some(s) => s,
        None => return Vec::new(),
    };
    // Pod has spec directly, workload resources have spec.template.spec
    if let Some(pod_spec) = spec.get("template").and_then(|t| t.get("spec")) {
        extract_configmap_refs_from_pod_spec(pod_spec, "spec.template.spec.", target_name)
    } else if spec.get("containers").is_some() || spec.get("volumes").is_some() {
        // Bare Pod spec
        extract_configmap_refs_from_pod_spec(spec, "spec.", target_name)
    } else if let Some(job_spec) = spec
        .get("jobTemplate")
        .and_then(|j| j.get("spec"))
        .and_then(|s| s.get("template"))
        .and_then(|t| t.get("spec"))
    {
        // CronJob: spec.jobTemplate.spec.template.spec
        extract_configmap_refs_from_pod_spec(
            job_spec,
            "spec.jobTemplate.spec.template.spec.",
            target_name,
        )
    } else {
        Vec::new()
    }
}

fn extract_service_backend_refs(
    route: &DynamicObject,
    target_name: &str,
    target_ns: Option<&str>,
) -> Vec<String> {
    let mut fields = Vec::new();
    if let Some(rules) = route
        .data
        .get("spec")
        .and_then(|s| s.get("rules"))
        .and_then(|r| r.as_array())
    {
        for (ri, rule) in rules.iter().enumerate() {
            if let Some(backend_refs) = rule.get("backendRefs").and_then(|b| b.as_array()) {
                for (bi, bref) in backend_refs.iter().enumerate() {
                    let name = bref.get("name").and_then(|n| n.as_str()).unwrap_or("");
                    let kind = bref
                        .get("kind")
                        .and_then(|k| k.as_str())
                        .unwrap_or("Service");
                    let group = bref.get("group").and_then(|g| g.as_str()).unwrap_or("");
                    let ref_ns = bref.get("namespace").and_then(|n| n.as_str());
                    if kind != "Service" || !group.is_empty() || name != target_name {
                        continue;
                    }
                    let effective_ns = ref_ns.or(route.metadata.namespace.as_deref());
                    if effective_ns != target_ns {
                        continue;
                    }
                    fields.push(format!("spec.rules[{}].backendRefs[{}].name", ri, bi));
                }
            }
        }
    }
    fields
}

fn extract_console_plugin_service_ref(
    plugin: &DynamicObject,
    target_name: &str,
    target_ns: Option<&str>,
) -> Vec<String> {
    let mut fields = Vec::new();
    if let Some(svc) = plugin
        .data
        .get("spec")
        .and_then(|s| s.get("backend"))
        .and_then(|b| b.get("service"))
    {
        let name = svc.get("name").and_then(|n| n.as_str()).unwrap_or("");
        let ns = svc.get("namespace").and_then(|n| n.as_str());
        if name == target_name && ns == target_ns {
            fields.push("spec.backend.service.name".to_string());
        }
    }
    fields
}

fn extract_gateway_parameters_ref(
    gw: &DynamicObject,
    target_name: &str,
    target_ns: Option<&str>,
) -> Vec<String> {
    let mut fields = Vec::new();
    if let Some(params_ref) = gw
        .data
        .get("spec")
        .and_then(|s| s.get("infrastructure"))
        .and_then(|i| i.get("parametersRef"))
    {
        let name = params_ref
            .get("name")
            .and_then(|n| n.as_str())
            .unwrap_or("");
        let kind = params_ref
            .get("kind")
            .and_then(|k| k.as_str())
            .unwrap_or("");
        let group = params_ref
            .get("group")
            .and_then(|g| g.as_str())
            .unwrap_or("");
        if kind == "ConfigMap" && group.is_empty() && name == target_name {
            let gw_ns = gw.metadata.namespace.as_deref();
            if gw_ns == target_ns {
                fields.push("spec.infrastructure.parametersRef".to_string());
            }
        }
    }
    fields
}

fn extract_ingress_service_ref(
    ingress: &DynamicObject,
    target_name: &str,
    target_ns: Option<&str>,
) -> Vec<String> {
    if let Some(target_ns) = target_ns
        && ingress.metadata.namespace.as_deref() != Some(target_ns)
    {
        return Vec::new();
    }
    let mut fields = Vec::new();
    let spec = match ingress.data.get("spec") {
        Some(s) => s,
        None => return fields,
    };
    if let Some(name) = spec
        .get("defaultBackend")
        .and_then(|b| b.get("service"))
        .and_then(|s| s.get("name"))
        .and_then(|n| n.as_str())
        && name == target_name
    {
        fields.push("spec.defaultBackend.service.name".to_string());
    }
    if let Some(rules) = spec.get("rules").and_then(|r| r.as_array()) {
        for (ri, rule) in rules.iter().enumerate() {
            if let Some(paths) = rule
                .get("http")
                .and_then(|h| h.get("paths"))
                .and_then(|p| p.as_array())
            {
                for (pi, path) in paths.iter().enumerate() {
                    if let Some(name) = path
                        .get("backend")
                        .and_then(|b| b.get("service"))
                        .and_then(|s| s.get("name"))
                        .and_then(|n| n.as_str())
                        && name == target_name
                    {
                        fields.push(format!(
                            "spec.rules[{ri}].http.paths[{pi}].backend.service.name"
                        ));
                    }
                }
            }
        }
    }
    fields
}

fn extract_route_service_ref(
    route: &DynamicObject,
    target_name: &str,
    target_ns: Option<&str>,
) -> Vec<String> {
    if let Some(target_ns) = target_ns
        && route.metadata.namespace.as_deref() != Some(target_ns)
    {
        return Vec::new();
    }
    let mut fields = Vec::new();
    let spec = match route.data.get("spec") {
        Some(s) => s,
        None => return fields,
    };
    if let Some(to) = spec.get("to") {
        let kind = to.get("kind").and_then(|k| k.as_str()).unwrap_or("Service");
        let name = to.get("name").and_then(|n| n.as_str()).unwrap_or("");
        if kind == "Service" && name == target_name {
            fields.push("spec.to.name".to_string());
        }
    }
    if let Some(alts) = spec.get("alternateBackends").and_then(|a| a.as_array()) {
        for (i, alt) in alts.iter().enumerate() {
            let kind = alt
                .get("kind")
                .and_then(|k| k.as_str())
                .unwrap_or("Service");
            let name = alt.get("name").and_then(|n| n.as_str()).unwrap_or("");
            if kind == "Service" && name == target_name {
                fields.push(format!("spec.alternateBackends[{i}].name"));
            }
        }
    }
    fields
}

fn extract_console_plugins_ref(console: &DynamicObject, target_name: &str) -> Vec<String> {
    let mut fields = Vec::new();
    if let Some(plugins) = console
        .data
        .get("spec")
        .and_then(|s| s.get("plugins"))
        .and_then(|p| p.as_array())
    {
        for (i, plugin) in plugins.iter().enumerate() {
            if let Some(name) = plugin.as_str()
                && name == target_name
            {
                fields.push(format!("spec.plugins[{i}]"));
            }
        }
    }
    fields
}

fn extract_hpa_scale_target_ref(
    hpa: &DynamicObject,
    target_name: &str,
    target_ns: Option<&str>,
    target_kind: &str,
    target_group: &str,
) -> Vec<String> {
    if let Some(target_ns) = target_ns
        && hpa.metadata.namespace.as_deref() != Some(target_ns)
    {
        return Vec::new();
    }
    let mut fields = Vec::new();
    if let Some(scale_ref) = hpa.data.get("spec").and_then(|s| s.get("scaleTargetRef")) {
        let name = scale_ref.get("name").and_then(|n| n.as_str()).unwrap_or("");
        let kind = scale_ref.get("kind").and_then(|k| k.as_str()).unwrap_or("");
        let api_version = scale_ref
            .get("apiVersion")
            .and_then(|a| a.as_str())
            .unwrap_or("apps/v1");
        let group = if let Some(idx) = api_version.find('/') {
            &api_version[..idx]
        } else {
            ""
        };
        if name == target_name && kind == target_kind && group == target_group {
            fields.push("spec.scaleTargetRef".to_string());
        }
    }
    fields
}

fn extract_refs_for_target(
    obj: &DynamicObject,
    referrer_group: &str,
    referrer_kind: &str,
    target_kind: &str,
    target_group: &str,
    target_name: &str,
    target_ns: Option<&str>,
) -> Vec<String> {
    match (target_group, target_kind) {
        ("gateway.networking.k8s.io", "Gateway") => {
            extract_gateway_parent_refs(obj, target_name, target_ns)
        }
        ("", "ConfigMap") => match (referrer_group, referrer_kind) {
            ("gateway.networking.k8s.io", "Gateway") => {
                extract_gateway_parameters_ref(obj, target_name, target_ns)
            }
            _ => extract_configmap_refs(obj, target_name, target_ns),
        },
        ("", "Service") => match (referrer_group, referrer_kind) {
            ("console.openshift.io", "ConsolePlugin") => {
                extract_console_plugin_service_ref(obj, target_name, target_ns)
            }
            (
                "gateway.networking.k8s.io",
                "HTTPRoute" | "GRPCRoute" | "TCPRoute" | "TLSRoute" | "UDPRoute",
            ) => extract_service_backend_refs(obj, target_name, target_ns),
            ("networking.k8s.io", "Ingress") => {
                extract_ingress_service_ref(obj, target_name, target_ns)
            }
            ("route.openshift.io", "Route") => {
                extract_route_service_ref(obj, target_name, target_ns)
            }
            _ => vec![],
        },
        ("console.openshift.io", "ConsolePlugin") => match (referrer_group, referrer_kind) {
            ("operator.openshift.io", "Console") => extract_console_plugins_ref(obj, target_name),
            _ => vec![],
        },
        ("apps", "Deployment") => match (referrer_group, referrer_kind) {
            ("autoscaling", "HorizontalPodAutoscaler") => {
                extract_hpa_scale_target_ref(obj, target_name, target_ns, target_kind, target_group)
            }
            _ => vec![],
        },
        _ => vec![],
    }
}

pub async fn check_inbound_refs(
    client: &Client,
    target: &ResourceId,
    deletion_closure: &DeletionClosureWithUid,
    gk_map: &GroupKindMap,
) -> Result<InboundRefScan> {
    let mut blockers = Vec::new();
    let mut allowed = Vec::new();
    let mut kinds_scanned = Vec::new();
    let mut scan_complete = true;

    if !has_known_extractors(&target.kind, &target.group) {
        return Ok(InboundRefScan {
            target: target.clone(),
            blockers,
            allowed,
            coverage: RefScanCoverage {
                kinds_scanned,
                scan_complete: false,
            },
        });
    }

    // Pass 1: LIST all referrer kinds, collect objects with their spec metadata
    let check_specs = referrer_specs_for_target(&target.kind, &target.group);
    struct CollectedKind {
        group: String,
        kind: String,
        items: Vec<DynamicObject>,
    }
    let mut collected: Vec<CollectedKind> = Vec::new();

    for spec in &check_specs {
        let kind_key = if spec.group.is_empty() {
            spec.kind.to_string()
        } else {
            format!("{}/{}", spec.group, spec.kind)
        };
        kinds_scanned.push(kind_key.clone());

        let gk = (spec.group.to_string(), spec.kind.to_string());
        let Some(info) = gk_map.get(&gk) else {
            if spec.required {
                scan_complete = false;
            }
            continue;
        };

        let gvk = ::kube::api::GroupVersionKind {
            group: info.group.clone(),
            version: info.version.clone(),
            kind: spec.kind.to_string(),
        };
        let ar = ::kube::api::ApiResource::from_gvk_with_plural(&gvk, &info.plural);
        let api: Api<DynamicObject> = Api::all_with(client.clone(), &ar);

        let list_result = crate::kube::scanner::list_all_with_retry(
            &api,
            &info.group,
            &info.version,
            &info.plural,
        )
        .await;
        match list_result {
            Ok(items) => {
                collected.push(CollectedKind {
                    group: spec.group.to_string(),
                    kind: spec.kind.to_string(),
                    items,
                });
            }
            Err(warning) => {
                let is_tty = std::io::IsTerminal::is_terminal(&std::io::stderr());
                if is_tty {
                    eprintln!(
                        "  \x1b[33m⚠ Failed to list {} for inbound reference check: {}\x1b[0m",
                        kind_key, warning
                    );
                } else {
                    eprintln!(
                        "  ⚠ Failed to list {} for inbound reference check: {}",
                        kind_key, warning
                    );
                }
                scan_complete = false;
            }
        }
    }

    // Build UID → ownerRefs map from all collected objects for transitive walk
    let tagged_objects: Vec<TaggedObject> = collected
        .iter()
        .flat_map(|c| {
            c.items.iter().map(move |obj| TaggedObject {
                obj,
                group: &c.group,
                kind: &c.kind,
            })
        })
        .collect();
    let owner_graph = build_owner_graph(&tagged_objects);

    // Pass 2: extract refs and classify using transitive ownership
    for ck in &collected {
        for obj in &ck.items {
            let ref_fields = extract_refs_for_target(
                obj,
                &ck.group,
                &ck.kind,
                &target.kind,
                &target.group,
                &target.name,
                target.namespace.as_deref(),
            );

            for field in ref_fields {
                let obj_name = obj.metadata.name.as_deref().unwrap_or("").to_string();
                let obj_ns = obj.metadata.namespace.clone();
                let obj_uid = obj.metadata.uid.as_deref().unwrap_or("").to_string();
                let obj_group = ck.group.clone();
                let obj_kind = ck.kind.clone();

                let referrer_key =
                    deletion_key(&obj_group, &obj_kind, obj_ns.as_deref(), &obj_name);

                let direct_match = if let Some(closure_uid) = deletion_closure.get(&referrer_key) {
                    !closure_uid.is_empty() && *closure_uid == obj_uid
                } else {
                    false
                };
                let in_closure = direct_match
                    || is_transitively_owned_by_closure(obj, deletion_closure, &owner_graph);

                let referrer = InboundReferrer {
                    resource: ResourceId {
                        group: obj_group,
                        version: String::new(),
                        kind: obj_kind,
                        namespace: obj_ns,
                        name: obj_name,
                        uid: Some(obj_uid.clone()),
                    },
                    uid: obj_uid,
                    ref_field: field,
                };

                if in_closure {
                    allowed.push(referrer);
                } else {
                    blockers.push(referrer);
                }
            }
        }
    }

    Ok(InboundRefScan {
        target: target.clone(),
        blockers,
        allowed,
        coverage: RefScanCoverage {
            kinds_scanned,
            scan_complete,
        },
    })
}

#[cfg(test)]
pub fn build_deletion_closure(
    phases: &[crate::teardown::plan::ExecutionPhase],
    explicit_targets: &[crate::DeleteResourceSpec],
) -> HashSet<DeletionKey> {
    let uid_closure = build_deletion_closure_with_uid(phases, explicit_targets);
    uid_closure.into_keys().collect()
}

pub fn to_inbound_ref_identities(scan: &InboundRefScan) -> Vec<InboundRefIdentity> {
    let mut ids = Vec::new();
    for r in &scan.allowed {
        ids.push(InboundRefIdentity {
            group: r.resource.group.clone(),
            kind: r.resource.kind.clone(),
            namespace: r.resource.namespace.clone(),
            name: r.resource.name.clone(),
            uid: r.uid.clone(),
            ref_field: r.ref_field.clone(),
            in_deletion_plan: true,
        });
    }
    for r in &scan.blockers {
        ids.push(InboundRefIdentity {
            group: r.resource.group.clone(),
            kind: r.resource.kind.clone(),
            namespace: r.resource.namespace.clone(),
            name: r.resource.name.clone(),
            uid: r.uid.clone(),
            ref_field: r.ref_field.clone(),
            in_deletion_plan: false,
        });
    }
    ids
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extract_gateway_parent_refs_matches() {
        let route_json = serde_json::json!({
            "apiVersion": "gateway.networking.k8s.io/v1",
            "kind": "HTTPRoute",
            "metadata": {"name": "my-route", "namespace": "ns-a"},
            "spec": {
                "parentRefs": [
                    {"name": "my-gw", "namespace": "ns-a"},
                    {"name": "other-gw", "namespace": "ns-b"}
                ]
            }
        });
        let route: DynamicObject = serde_json::from_value(route_json).unwrap();
        let fields = extract_gateway_parent_refs(&route, "my-gw", Some("ns-a"));
        assert_eq!(fields, vec!["spec.parentRefs[0]"]);
        let fields2 = extract_gateway_parent_refs(&route, "other-gw", Some("ns-b"));
        assert_eq!(fields2, vec!["spec.parentRefs[1]"]);
        let fields3 = extract_gateway_parent_refs(&route, "no-match", Some("ns-a"));
        assert!(fields3.is_empty());
    }

    #[test]
    fn extract_gateway_parent_refs_cross_namespace() {
        let route_json = serde_json::json!({
            "apiVersion": "gateway.networking.k8s.io/v1",
            "kind": "HTTPRoute",
            "metadata": {"name": "cross-route", "namespace": "other-ns"},
            "spec": {
                "parentRefs": [
                    {"name": "my-gw", "namespace": "target-ns"}
                ]
            }
        });
        let route: DynamicObject = serde_json::from_value(route_json).unwrap();
        let fields = extract_gateway_parent_refs(&route, "my-gw", Some("target-ns"));
        assert_eq!(
            fields,
            vec!["spec.parentRefs[0]"],
            "Cross-namespace parentRef must match"
        );
    }

    #[test]
    fn extract_gateway_parent_refs_implicit_namespace() {
        let route_json = serde_json::json!({
            "apiVersion": "gateway.networking.k8s.io/v1",
            "kind": "HTTPRoute",
            "metadata": {"name": "r1", "namespace": "ns-a"},
            "spec": { "parentRefs": [{"name": "my-gw"}] }
        });
        let route: DynamicObject = serde_json::from_value(route_json).unwrap();
        let fields = extract_gateway_parent_refs(&route, "my-gw", Some("ns-a"));
        assert_eq!(fields, vec!["spec.parentRefs[0]"]);
    }

    #[test]
    fn extract_gateway_parent_refs_non_gateway_kind() {
        let route_json = serde_json::json!({
            "apiVersion": "gateway.networking.k8s.io/v1",
            "kind": "HTTPRoute",
            "metadata": {"name": "r1", "namespace": "ns-a"},
            "spec": { "parentRefs": [{"name": "my-gw", "kind": "Service"}] }
        });
        let route: DynamicObject = serde_json::from_value(route_json).unwrap();
        let fields = extract_gateway_parent_refs(&route, "my-gw", Some("ns-a"));
        assert!(fields.is_empty());
    }

    #[test]
    fn extract_configmap_volume_ref() {
        let deploy_json = serde_json::json!({
            "apiVersion": "apps/v1",
            "kind": "Deployment",
            "metadata": {"name": "d1", "namespace": "ns"},
            "spec": {
                "template": {
                    "spec": {
                        "volumes": [
                            {"name": "cfg", "configMap": {"name": "my-cm"}},
                            {"name": "other", "configMap": {"name": "other-cm"}}
                        ]
                    }
                }
            }
        });
        let obj: DynamicObject = serde_json::from_value(deploy_json).unwrap();
        let fields = extract_configmap_refs(&obj, "my-cm", Some("ns"));
        assert_eq!(fields, vec!["spec.template.spec.volumes[0].configMap.name"]);
        let fields2 = extract_configmap_refs(&obj, "no-match", Some("ns"));
        assert!(fields2.is_empty());
        let fields3 = extract_configmap_refs(&obj, "my-cm", Some("other-ns"));
        assert!(
            fields3.is_empty(),
            "Cross-namespace ConfigMap ref should not match"
        );
    }

    #[test]
    fn extract_console_plugin_service() {
        let plugin_json = serde_json::json!({
            "apiVersion": "console.openshift.io/v1",
            "kind": "ConsolePlugin",
            "metadata": {"name": "my-plugin"},
            "spec": {
                "backend": {
                    "service": {"name": "my-svc", "namespace": "ns-a"}
                }
            }
        });
        let obj: DynamicObject = serde_json::from_value(plugin_json).unwrap();
        let fields = extract_console_plugin_service_ref(&obj, "my-svc", Some("ns-a"));
        assert_eq!(fields, vec!["spec.backend.service.name"]);
        let fields2 = extract_console_plugin_service_ref(&obj, "other-svc", Some("ns-a"));
        assert!(fields2.is_empty());
    }

    #[test]
    fn extract_service_backend_ref() {
        let route_json = serde_json::json!({
            "apiVersion": "gateway.networking.k8s.io/v1",
            "kind": "HTTPRoute",
            "metadata": {"name": "r1", "namespace": "ns-a"},
            "spec": {
                "rules": [{
                    "backendRefs": [
                        {"name": "my-svc", "port": 8080},
                        {"name": "other-svc", "port": 443}
                    ]
                }]
            }
        });
        let obj: DynamicObject = serde_json::from_value(route_json).unwrap();
        let fields = extract_service_backend_refs(&obj, "my-svc", Some("ns-a"));
        assert_eq!(fields, vec!["spec.rules[0].backendRefs[0].name"]);
    }

    fn make_dyn_obj(json: serde_json::Value) -> DynamicObject {
        serde_json::from_value(json).unwrap()
    }

    fn extract_gk(obj: &DynamicObject) -> (String, String) {
        let api_version = obj
            .types
            .as_ref()
            .map(|t| t.api_version.clone())
            .or_else(|| {
                obj.data
                    .get("apiVersion")
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string())
            })
            .unwrap_or_default();
        let group = if let Some(idx) = api_version.find('/') {
            api_version[..idx].to_string()
        } else {
            String::new()
        };
        let kind = obj
            .types
            .as_ref()
            .map(|t| t.kind.clone())
            .or_else(|| {
                obj.data
                    .get("kind")
                    .and_then(|k| k.as_str())
                    .map(|s| s.to_string())
            })
            .unwrap_or_default();
        (group, kind)
    }

    fn test_owner_graph(objects: &[&DynamicObject]) -> OwnerGraph {
        let gks: Vec<(String, String)> = objects.iter().map(|o| extract_gk(o)).collect();
        let tagged: Vec<TaggedObject> = objects
            .iter()
            .zip(gks.iter())
            .map(|(obj, (g, k))| TaggedObject {
                obj,
                group: g,
                kind: k,
            })
            .collect();
        build_owner_graph(&tagged)
    }

    #[test]
    fn transitive_owner_1hop_uid_match() {
        let obj = make_dyn_obj(serde_json::json!({
            "apiVersion": "v1", "kind": "Pod",
            "metadata": {
                "name": "pod-1", "namespace": "ns-a", "uid": "pod-uid",
                "ownerReferences": [{"apiVersion": "apps/v1", "kind": "Deployment", "name": "my-deploy", "uid": "abc123"}]
            }
        }));
        let owner_graph = test_owner_graph(&[&obj]);

        let mut closure = DeletionClosureWithUid::new();
        closure.insert(
            deletion_key("apps", "Deployment", Some("ns-a"), "my-deploy"),
            "abc123".to_string(),
        );
        assert!(is_transitively_owned_by_closure(
            &obj,
            &closure,
            &owner_graph
        ));

        let mut wrong_uid = DeletionClosureWithUid::new();
        wrong_uid.insert(
            deletion_key("apps", "Deployment", Some("ns-a"), "my-deploy"),
            "wrong-uid".to_string(),
        );
        assert!(
            !is_transitively_owned_by_closure(&obj, &wrong_uid, &owner_graph),
            "Stale UID must not match"
        );

        let empty_closure = DeletionClosureWithUid::new();
        assert!(!is_transitively_owned_by_closure(
            &obj,
            &empty_closure,
            &owner_graph
        ));

        let mut empty_uid_closure = DeletionClosureWithUid::new();
        empty_uid_closure.insert(
            deletion_key("apps", "Deployment", Some("ns-a"), "my-deploy"),
            String::new(),
        );
        assert!(
            !is_transitively_owned_by_closure(&obj, &empty_uid_closure, &owner_graph),
            "Empty UID in closure must not match"
        );
    }

    #[test]
    fn transitive_owner_3hop_allowed() {
        let pod = make_dyn_obj(serde_json::json!({
            "apiVersion": "v1", "kind": "Pod",
            "metadata": {"name": "pod-1", "namespace": "ns", "uid": "pod-uid",
                "ownerReferences": [{"apiVersion": "apps/v1", "kind": "ReplicaSet", "name": "rs-1", "uid": "rs-uid"}]}
        }));
        let rs = make_dyn_obj(serde_json::json!({
            "apiVersion": "apps/v1", "kind": "ReplicaSet",
            "metadata": {"name": "rs-1", "namespace": "ns", "uid": "rs-uid",
                "ownerReferences": [{"apiVersion": "apps/v1", "kind": "Deployment", "name": "dep-1", "uid": "dep-uid"}]}
        }));
        let owner_graph = test_owner_graph(&[&pod, &rs]);

        let mut closure = DeletionClosureWithUid::new();
        closure.insert(
            deletion_key("apps", "Deployment", Some("ns"), "dep-1"),
            "dep-uid".to_string(),
        );
        assert!(
            is_transitively_owned_by_closure(&pod, &closure, &owner_graph),
            "Pod→RS→Deployment must resolve"
        );
    }

    #[test]
    fn transitive_owner_stale_uid_at_each_hop_blocked() {
        let pod = make_dyn_obj(serde_json::json!({
            "apiVersion": "v1", "kind": "Pod",
            "metadata": {"name": "pod-1", "namespace": "ns", "uid": "pod-uid",
                "ownerReferences": [{"apiVersion": "apps/v1", "kind": "ReplicaSet", "name": "rs-1", "uid": "rs-uid-STALE"}]}
        }));
        let rs = make_dyn_obj(serde_json::json!({
            "apiVersion": "apps/v1", "kind": "ReplicaSet",
            "metadata": {"name": "rs-1", "namespace": "ns", "uid": "rs-uid-LIVE",
                "ownerReferences": [{"apiVersion": "apps/v1", "kind": "Deployment", "name": "dep-1", "uid": "dep-uid"}]}
        }));
        let owner_graph = test_owner_graph(&[&pod, &rs]);

        let mut closure = DeletionClosureWithUid::new();
        closure.insert(
            deletion_key("apps", "Deployment", Some("ns"), "dep-1"),
            "dep-uid".to_string(),
        );
        assert!(
            !is_transitively_owned_by_closure(&pod, &closure, &owner_graph),
            "Pod references stale RS UID — walk cannot reach live RS"
        );
    }

    #[test]
    fn transitive_owner_unrelated_blocked() {
        let pod = make_dyn_obj(serde_json::json!({
            "apiVersion": "v1", "kind": "Pod",
            "metadata": {"name": "pod-1", "namespace": "ns", "uid": "pod-uid",
                "ownerReferences": [{"apiVersion": "apps/v1", "kind": "ReplicaSet", "name": "rs-other", "uid": "rs-other-uid"}]}
        }));
        let rs_other = make_dyn_obj(serde_json::json!({
            "apiVersion": "apps/v1", "kind": "ReplicaSet",
            "metadata": {"name": "rs-other", "namespace": "ns", "uid": "rs-other-uid",
                "ownerReferences": [{"apiVersion": "apps/v1", "kind": "Deployment", "name": "dep-other", "uid": "dep-other-uid"}]}
        }));
        let owner_graph = test_owner_graph(&[&pod, &rs_other]);

        let mut closure = DeletionClosureWithUid::new();
        closure.insert(
            deletion_key("apps", "Deployment", Some("ns"), "dep-1"),
            "dep-uid".to_string(),
        );
        assert!(
            !is_transitively_owned_by_closure(&pod, &closure, &owner_graph),
            "Unrelated owner chain must not match"
        );
    }

    #[test]
    fn transitive_owner_cycle_terminates() {
        let a = make_dyn_obj(serde_json::json!({
            "apiVersion": "v1", "kind": "A",
            "metadata": {"name": "a", "namespace": "ns", "uid": "uid-a",
                "ownerReferences": [{"apiVersion": "v1", "kind": "B", "name": "b", "uid": "uid-b"}]}
        }));
        let b = make_dyn_obj(serde_json::json!({
            "apiVersion": "v1", "kind": "B",
            "metadata": {"name": "b", "namespace": "ns", "uid": "uid-b",
                "ownerReferences": [{"apiVersion": "v1", "kind": "A", "name": "a", "uid": "uid-a"}]}
        }));
        let owner_graph = test_owner_graph(&[&a, &b]);
        let empty_closure = DeletionClosureWithUid::new();
        assert!(
            !is_transitively_owned_by_closure(&a, &empty_closure, &owner_graph),
            "Cycle must terminate without panic"
        );
    }

    #[test]
    fn transitive_owner_same_uid_wrong_identity_blocked() {
        let pod = make_dyn_obj(serde_json::json!({
            "apiVersion": "v1", "kind": "Pod",
            "metadata": {"name": "pod-1", "namespace": "ns", "uid": "pod-uid",
                "ownerReferences": [{"apiVersion": "apps/v1", "kind": "ReplicaSet", "name": "rs-1", "uid": "shared-uid"}]}
        }));
        // Live object at shared-uid is a Deployment, not a ReplicaSet
        let wrong_kind = make_dyn_obj(serde_json::json!({
            "apiVersion": "apps/v1", "kind": "Deployment",
            "metadata": {"name": "dep-sneaky", "namespace": "ns", "uid": "shared-uid",
                "ownerReferences": [{"apiVersion": "apps/v1", "kind": "Deployment", "name": "dep-root", "uid": "root-uid"}]}
        }));
        let owner_graph = test_owner_graph(&[&pod, &wrong_kind]);

        let mut closure = DeletionClosureWithUid::new();
        closure.insert(
            deletion_key("apps", "Deployment", Some("ns"), "dep-root"),
            "root-uid".to_string(),
        );
        assert!(
            !is_transitively_owned_by_closure(&pod, &closure, &owner_graph),
            "OwnerRef claims RS but live object is Deployment — identity mismatch must block"
        );
    }

    #[test]
    fn transitive_owner_one_of_two_owners_outside_blocks() {
        let pod = make_dyn_obj(serde_json::json!({
            "apiVersion": "v1", "kind": "Pod",
            "metadata": {"name": "pod-1", "namespace": "ns", "uid": "pod-uid",
                "ownerReferences": [
                    {"apiVersion": "apps/v1", "kind": "ReplicaSet", "name": "rs-in", "uid": "rs-in-uid"},
                    {"apiVersion": "apps/v1", "kind": "ReplicaSet", "name": "rs-out", "uid": "rs-out-uid"}
                ]}
        }));
        let rs_in = make_dyn_obj(serde_json::json!({
            "apiVersion": "apps/v1", "kind": "ReplicaSet",
            "metadata": {"name": "rs-in", "namespace": "ns", "uid": "rs-in-uid",
                "ownerReferences": [{"apiVersion": "apps/v1", "kind": "Deployment", "name": "dep-in", "uid": "dep-in-uid"}]}
        }));
        let rs_out = make_dyn_obj(serde_json::json!({
            "apiVersion": "apps/v1", "kind": "ReplicaSet",
            "metadata": {"name": "rs-out", "namespace": "ns", "uid": "rs-out-uid",
                "ownerReferences": [{"apiVersion": "apps/v1", "kind": "Deployment", "name": "dep-out", "uid": "dep-out-uid"}]}
        }));
        let owner_graph = test_owner_graph(&[&pod, &rs_in, &rs_out]);

        let mut closure = DeletionClosureWithUid::new();
        closure.insert(
            deletion_key("apps", "Deployment", Some("ns"), "dep-in"),
            "dep-in-uid".to_string(),
        );
        // Only one of two owners in closure
        assert!(
            !is_transitively_owned_by_closure(&pod, &closure, &owner_graph),
            "One-of-two owners outside closure must block (ALL semantics)"
        );
    }

    #[test]
    fn transitive_owner_both_owners_in_closure_passes() {
        let pod = make_dyn_obj(serde_json::json!({
            "apiVersion": "v1", "kind": "Pod",
            "metadata": {"name": "pod-1", "namespace": "ns", "uid": "pod-uid",
                "ownerReferences": [
                    {"apiVersion": "apps/v1", "kind": "ReplicaSet", "name": "rs-a", "uid": "rs-a-uid"},
                    {"apiVersion": "apps/v1", "kind": "ReplicaSet", "name": "rs-b", "uid": "rs-b-uid"}
                ]}
        }));
        let rs_a = make_dyn_obj(serde_json::json!({
            "apiVersion": "apps/v1", "kind": "ReplicaSet",
            "metadata": {"name": "rs-a", "namespace": "ns", "uid": "rs-a-uid",
                "ownerReferences": [{"apiVersion": "apps/v1", "kind": "Deployment", "name": "dep-a", "uid": "dep-a-uid"}]}
        }));
        let rs_b = make_dyn_obj(serde_json::json!({
            "apiVersion": "apps/v1", "kind": "ReplicaSet",
            "metadata": {"name": "rs-b", "namespace": "ns", "uid": "rs-b-uid",
                "ownerReferences": [{"apiVersion": "apps/v1", "kind": "Deployment", "name": "dep-b", "uid": "dep-b-uid"}]}
        }));
        let owner_graph = test_owner_graph(&[&pod, &rs_a, &rs_b]);

        let mut closure = DeletionClosureWithUid::new();
        closure.insert(
            deletion_key("apps", "Deployment", Some("ns"), "dep-a"),
            "dep-a-uid".to_string(),
        );
        closure.insert(
            deletion_key("apps", "Deployment", Some("ns"), "dep-b"),
            "dep-b-uid".to_string(),
        );
        assert!(
            is_transitively_owned_by_closure(&pod, &closure, &owner_graph),
            "Both owners in closure must pass"
        );
    }

    #[test]
    fn transitive_owner_missing_intermediate_blocks() {
        let pod = make_dyn_obj(serde_json::json!({
            "apiVersion": "v1", "kind": "Pod",
            "metadata": {"name": "pod-1", "namespace": "ns", "uid": "pod-uid",
                "ownerReferences": [{"apiVersion": "apps/v1", "kind": "ReplicaSet", "name": "rs-1", "uid": "rs-uid-missing"}]}
        }));
        // No RS object in the graph
        let owner_graph = test_owner_graph(&[&pod]);

        let mut closure = DeletionClosureWithUid::new();
        closure.insert(
            deletion_key("apps", "Deployment", Some("ns"), "dep-1"),
            "dep-uid".to_string(),
        );
        assert!(
            !is_transitively_owned_by_closure(&pod, &closure, &owner_graph),
            "Missing intermediate must block (fail closed)"
        );
    }

    #[test]
    fn transitive_owner_dag_shared_ancestor_passes() {
        // Pod -> RS-A -> Deployment-X (in closure)
        //     -> RS-B -> Deployment-X (in closure)
        let pod = make_dyn_obj(serde_json::json!({
            "apiVersion": "v1", "kind": "Pod",
            "metadata": {"name": "pod-1", "namespace": "ns", "uid": "pod-uid",
                "ownerReferences": [
                    {"apiVersion": "apps/v1", "kind": "ReplicaSet", "name": "rs-a", "uid": "rs-a-uid"},
                    {"apiVersion": "apps/v1", "kind": "ReplicaSet", "name": "rs-b", "uid": "rs-b-uid"}
                ]}
        }));
        let rs_a = make_dyn_obj(serde_json::json!({
            "apiVersion": "apps/v1", "kind": "ReplicaSet",
            "metadata": {"name": "rs-a", "namespace": "ns", "uid": "rs-a-uid",
                "ownerReferences": [{"apiVersion": "apps/v1", "kind": "Deployment", "name": "dep-x", "uid": "dep-x-uid"}]}
        }));
        let rs_b = make_dyn_obj(serde_json::json!({
            "apiVersion": "apps/v1", "kind": "ReplicaSet",
            "metadata": {"name": "rs-b", "namespace": "ns", "uid": "rs-b-uid",
                "ownerReferences": [{"apiVersion": "apps/v1", "kind": "Deployment", "name": "dep-x", "uid": "dep-x-uid"}]}
        }));
        let owner_graph = test_owner_graph(&[&pod, &rs_a, &rs_b]);

        let mut closure = DeletionClosureWithUid::new();
        closure.insert(
            deletion_key("apps", "Deployment", Some("ns"), "dep-x"),
            "dep-x-uid".to_string(),
        );
        assert!(
            is_transitively_owned_by_closure(&pod, &closure, &owner_graph),
            "DAG with shared ancestor must pass — both branches converge on same closure owner"
        );
    }

    #[test]
    fn transitive_owner_dag_spoofed_identity_on_second_branch_blocked() {
        // Pod -> RS-A -> Deployment-X(name=dep-x, uid=dep-x-uid) — correct identity
        //     -> RS-B -> Deployment-X(name=spoofed, uid=dep-x-uid) — wrong name
        // RS-B's ownerRef claims a different name but same UID.
        let pod = make_dyn_obj(serde_json::json!({
            "apiVersion": "v1", "kind": "Pod",
            "metadata": {"name": "pod-1", "namespace": "ns", "uid": "pod-uid",
                "ownerReferences": [
                    {"apiVersion": "apps/v1", "kind": "ReplicaSet", "name": "rs-a", "uid": "rs-a-uid"},
                    {"apiVersion": "apps/v1", "kind": "ReplicaSet", "name": "rs-b", "uid": "rs-b-uid"}
                ]}
        }));
        let rs_a = make_dyn_obj(serde_json::json!({
            "apiVersion": "apps/v1", "kind": "ReplicaSet",
            "metadata": {"name": "rs-a", "namespace": "ns", "uid": "rs-a-uid",
                "ownerReferences": [{"apiVersion": "apps/v1", "kind": "Deployment", "name": "dep-x", "uid": "dep-x-uid"}]}
        }));
        let rs_b = make_dyn_obj(serde_json::json!({
            "apiVersion": "apps/v1", "kind": "ReplicaSet",
            "metadata": {"name": "rs-b", "namespace": "ns", "uid": "rs-b-uid",
                "ownerReferences": [{"apiVersion": "apps/v1", "kind": "Deployment", "name": "spoofed", "uid": "dep-x-uid"}]}
        }));
        // Live Deployment-X has the real name
        let dep = make_dyn_obj(serde_json::json!({
            "apiVersion": "apps/v1", "kind": "Deployment",
            "metadata": {"name": "dep-x", "namespace": "ns", "uid": "dep-x-uid"}
        }));
        let owner_graph = test_owner_graph(&[&pod, &rs_a, &rs_b, &dep]);

        let mut closure = DeletionClosureWithUid::new();
        closure.insert(
            deletion_key("apps", "Deployment", Some("ns"), "dep-x"),
            "dep-x-uid".to_string(),
        );
        assert!(
            !is_transitively_owned_by_closure(&pod, &closure, &owner_graph),
            "RS-B claims wrong name for same UID — identity mismatch must block even if RS-A resolved"
        );
    }

    #[test]
    fn deletion_closure_build() {
        use crate::teardown::plan::{ExecutionAction, ExecutionPhase, ExecutionResource};
        let phases = vec![ExecutionPhase {
            phase: 1,
            name: "test".into(),
            resources: vec![
                ExecutionResource {
                    group: "".into(),
                    kind: "ConfigMap".into(),
                    namespace: Some("ns".into()),
                    name: "cm1".into(),
                    uid: Some("u1".into()),
                    action: ExecutionAction::Delete,
                },
                ExecutionResource {
                    group: "".into(),
                    kind: "Secret".into(),
                    namespace: Some("ns".into()),
                    name: "s1".into(),
                    uid: Some("u2".into()),
                    action: ExecutionAction::Keep,
                },
            ],
        }];

        let closure = build_deletion_closure(&phases, &[]);
        assert!(closure.contains(&deletion_key("", "ConfigMap", Some("ns"), "cm1")));
        assert!(
            !closure.contains(&deletion_key("", "Secret", Some("ns"), "s1")),
            "KEEP should not be in closure"
        );
    }

    #[test]
    fn unsupported_target_kind_returns_incomplete() {
        assert!(
            !has_known_extractors("SomeCustomKind", "example.com"),
            "Unknown kind should not have extractors"
        );
    }

    #[test]
    fn optional_api_absent_stays_complete() {
        let specs = referrer_specs_for_target("Gateway", "gateway.networking.k8s.io");
        assert!(
            specs.iter().all(|s| !s.required),
            "All Gateway route referrers should be optional"
        );
    }

    #[test]
    fn configmap_core_referrers_are_required() {
        let specs = referrer_specs_for_target("ConfigMap", "");
        let required_groups: Vec<&str> = specs
            .iter()
            .filter(|s| s.required)
            .map(|s| s.group)
            .collect();
        assert!(
            required_groups.contains(&"apps"),
            "apps referrers should be required"
        );
        assert!(
            required_groups.contains(&"batch"),
            "batch referrers should be required"
        );
        assert!(
            required_groups.contains(&""),
            "Pod referrer should be required"
        );
        let optional = specs.iter().filter(|s| !s.required).collect::<Vec<_>>();
        assert!(
            optional
                .iter()
                .all(|s| s.group == "gateway.networking.k8s.io"),
            "Only Gateway parametersRef should be optional"
        );
    }

    #[test]
    fn extract_configmap_projected_volume() {
        let deploy_json = serde_json::json!({
            "apiVersion": "apps/v1", "kind": "Deployment",
            "metadata": {"name": "d1", "namespace": "ns"},
            "spec": {"template": {"spec": {"volumes": [
                {"name": "proj", "projected": {"sources": [
                    {"configMap": {"name": "my-cm"}}
                ]}}
            ]}}}
        });
        let obj: DynamicObject = serde_json::from_value(deploy_json).unwrap();
        let fields = extract_configmap_refs(&obj, "my-cm", Some("ns"));
        assert_eq!(
            fields,
            vec!["spec.template.spec.volumes[0].projected.sources[0].configMap.name"]
        );
    }

    #[test]
    fn extract_configmap_env_value_from() {
        let deploy_json = serde_json::json!({
            "apiVersion": "apps/v1", "kind": "Deployment",
            "metadata": {"name": "d1", "namespace": "ns"},
            "spec": {"template": {"spec": {"containers": [
                {"name": "c1", "env": [
                    {"name": "X", "valueFrom": {"configMapKeyRef": {"name": "my-cm", "key": "k"}}}
                ]}
            ]}}}
        });
        let obj: DynamicObject = serde_json::from_value(deploy_json).unwrap();
        let fields = extract_configmap_refs(&obj, "my-cm", Some("ns"));
        assert_eq!(
            fields,
            vec!["spec.template.spec.containers[0].env[0].valueFrom.configMapKeyRef.name"]
        );
    }

    #[test]
    fn extract_configmap_init_containers() {
        let deploy_json = serde_json::json!({
            "apiVersion": "apps/v1", "kind": "Deployment",
            "metadata": {"name": "d1", "namespace": "ns"},
            "spec": {"template": {"spec": {"initContainers": [
                {"name": "init", "envFrom": [{"configMapRef": {"name": "my-cm"}}]}
            ]}}}
        });
        let obj: DynamicObject = serde_json::from_value(deploy_json).unwrap();
        let fields = extract_configmap_refs(&obj, "my-cm", Some("ns"));
        assert_eq!(
            fields,
            vec!["spec.template.spec.initContainers[0].envFrom[0].configMapRef.name"]
        );
    }

    #[test]
    fn extract_configmap_cronjob() {
        let cj_json = serde_json::json!({
            "apiVersion": "batch/v1", "kind": "CronJob",
            "metadata": {"name": "cj1", "namespace": "ns"},
            "spec": {"jobTemplate": {"spec": {"template": {"spec": {"volumes": [
                {"name": "cfg", "configMap": {"name": "my-cm"}}
            ]}}}}}
        });
        let obj: DynamicObject = serde_json::from_value(cj_json).unwrap();
        let fields = extract_configmap_refs(&obj, "my-cm", Some("ns"));
        assert_eq!(
            fields,
            vec!["spec.jobTemplate.spec.template.spec.volumes[0].configMap.name"]
        );
    }

    #[test]
    fn extract_configmap_pod() {
        let pod_json = serde_json::json!({
            "apiVersion": "v1", "kind": "Pod",
            "metadata": {"name": "p1", "namespace": "ns"},
            "spec": {"volumes": [{"name": "cfg", "configMap": {"name": "my-cm"}}]}
        });
        let obj: DynamicObject = serde_json::from_value(pod_json).unwrap();
        let fields = extract_configmap_refs(&obj, "my-cm", Some("ns"));
        assert_eq!(fields, vec!["spec.volumes[0].configMap.name"]);
    }

    #[test]
    fn extract_ingress_default_backend() {
        let ingress_json = serde_json::json!({
            "apiVersion": "networking.k8s.io/v1", "kind": "Ingress",
            "metadata": {"name": "ing1", "namespace": "ns"},
            "spec": {"defaultBackend": {"service": {"name": "my-svc", "port": {"number": 80}}}}
        });
        let obj: DynamicObject = serde_json::from_value(ingress_json).unwrap();
        let fields = extract_ingress_service_ref(&obj, "my-svc", Some("ns"));
        assert_eq!(fields, vec!["spec.defaultBackend.service.name"]);
    }

    #[test]
    fn extract_ingress_rules_backend() {
        let ingress_json = serde_json::json!({
            "apiVersion": "networking.k8s.io/v1", "kind": "Ingress",
            "metadata": {"name": "ing1", "namespace": "ns"},
            "spec": {"rules": [{"http": {"paths": [
                {"path": "/", "backend": {"service": {"name": "my-svc"}}}
            ]}}]}
        });
        let obj: DynamicObject = serde_json::from_value(ingress_json).unwrap();
        let fields = extract_ingress_service_ref(&obj, "my-svc", Some("ns"));
        assert_eq!(
            fields,
            vec!["spec.rules[0].http.paths[0].backend.service.name"]
        );
    }

    #[test]
    fn extract_route_service() {
        let route_json = serde_json::json!({
            "apiVersion": "route.openshift.io/v1", "kind": "Route",
            "metadata": {"name": "r1", "namespace": "ns"},
            "spec": {
                "to": {"kind": "Service", "name": "my-svc"},
                "alternateBackends": [{"kind": "Service", "name": "alt-svc"}]
            }
        });
        let obj: DynamicObject = serde_json::from_value(route_json).unwrap();
        let fields = extract_route_service_ref(&obj, "my-svc", Some("ns"));
        assert_eq!(fields, vec!["spec.to.name"]);
        let fields2 = extract_route_service_ref(&obj, "alt-svc", Some("ns"));
        assert_eq!(fields2, vec!["spec.alternateBackends[0].name"]);
    }

    #[test]
    fn extract_console_plugins_ref_match() {
        let console_json = serde_json::json!({
            "apiVersion": "operator.openshift.io/v1", "kind": "Console",
            "metadata": {"name": "cluster"},
            "spec": {"plugins": ["kuadrant-console-plugin", "other-plugin"]}
        });
        let obj: DynamicObject = serde_json::from_value(console_json).unwrap();
        let fields = extract_console_plugins_ref(&obj, "kuadrant-console-plugin");
        assert_eq!(fields, vec!["spec.plugins[0]"]);
        let fields2 = extract_console_plugins_ref(&obj, "no-match");
        assert!(fields2.is_empty());
    }

    #[test]
    fn service_referrer_specs_include_routes_and_ingress() {
        let specs = referrer_specs_for_target("Service", "");
        let kinds: Vec<&str> = specs.iter().map(|s| s.kind).collect();
        assert!(kinds.contains(&"TCPRoute"));
        assert!(kinds.contains(&"TLSRoute"));
        assert!(kinds.contains(&"UDPRoute"));
        assert!(kinds.contains(&"Ingress"));
        assert!(kinds.contains(&"Route"));
    }

    #[test]
    fn console_plugin_has_console_referrer() {
        let specs = referrer_specs_for_target("ConsolePlugin", "console.openshift.io");
        assert_eq!(specs.len(), 1);
        assert_eq!(specs[0].group, "operator.openshift.io");
        assert_eq!(specs[0].kind, "Console");
        assert!(!specs[0].required);
    }

    #[test]
    fn hpa_cross_namespace_rejected() {
        let hpa = make_dyn_obj(serde_json::json!({
            "apiVersion": "autoscaling/v2", "kind": "HorizontalPodAutoscaler",
            "metadata": {"name": "hpa-1", "namespace": "other-ns"},
            "spec": {"scaleTargetRef": {"apiVersion": "apps/v1", "kind": "Deployment", "name": "dep-1"}}
        }));
        let fields =
            extract_hpa_scale_target_ref(&hpa, "dep-1", Some("target-ns"), "Deployment", "apps");
        assert!(fields.is_empty(), "Cross-namespace HPA must not match");
        let same_ns =
            extract_hpa_scale_target_ref(&hpa, "dep-1", Some("other-ns"), "Deployment", "apps");
        assert_eq!(
            same_ns,
            vec!["spec.scaleTargetRef"],
            "Same-namespace HPA must match"
        );
    }

    #[test]
    fn backend_ref_wrong_group_rejected() {
        let route = make_dyn_obj(serde_json::json!({
            "apiVersion": "gateway.networking.k8s.io/v1", "kind": "HTTPRoute",
            "metadata": {"name": "r1", "namespace": "ns"},
            "spec": {"rules": [{"backendRefs": [
                {"group": "example.com", "kind": "Service", "name": "my-svc"}
            ]}]}
        }));
        let fields = extract_service_backend_refs(&route, "my-svc", Some("ns"));
        assert!(
            fields.is_empty(),
            "Non-core group backendRef must not match Service target"
        );
    }

    #[test]
    fn backend_ref_core_group_accepted() {
        let route = make_dyn_obj(serde_json::json!({
            "apiVersion": "gateway.networking.k8s.io/v1", "kind": "HTTPRoute",
            "metadata": {"name": "r1", "namespace": "ns"},
            "spec": {"rules": [{"backendRefs": [
                {"name": "my-svc"}
            ]}]}
        }));
        let fields = extract_service_backend_refs(&route, "my-svc", Some("ns"));
        assert_eq!(fields, vec!["spec.rules[0].backendRefs[0].name"]);
    }

    #[test]
    fn gateway_parent_ref_wrong_group_rejected() {
        let route = make_dyn_obj(serde_json::json!({
            "apiVersion": "gateway.networking.k8s.io/v1", "kind": "HTTPRoute",
            "metadata": {"name": "r1", "namespace": "ns"},
            "spec": {"parentRefs": [{"group": "example.com", "kind": "Gateway", "name": "my-gw"}]}
        }));
        let fields = extract_gateway_parent_refs(&route, "my-gw", Some("ns"));
        assert!(
            fields.is_empty(),
            "Non-gateway group parentRef must not match"
        );
    }

    #[test]
    fn gateway_parent_ref_explicit_empty_group_rejected() {
        let route = make_dyn_obj(serde_json::json!({
            "apiVersion": "gateway.networking.k8s.io/v1", "kind": "HTTPRoute",
            "metadata": {"name": "r1", "namespace": "ns"},
            "spec": {"parentRefs": [{"group": "", "kind": "Gateway", "name": "my-gw"}]}
        }));
        let fields = extract_gateway_parent_refs(&route, "my-gw", Some("ns"));
        assert!(
            fields.is_empty(),
            "Explicit group:\"\" means core group, must not match Gateway"
        );
    }

    #[test]
    fn gateway_parameters_ref_exact_match() {
        let gw = make_dyn_obj(serde_json::json!({
            "apiVersion": "gateway.networking.k8s.io/v1", "kind": "Gateway",
            "metadata": {"name": "gw-1", "namespace": "ns"},
            "spec": {"infrastructure": {"parametersRef": {"group": "", "kind": "ConfigMap", "name": "my-cm"}}}
        }));
        let fields = extract_gateway_parameters_ref(&gw, "my-cm", Some("ns"));
        assert_eq!(fields, vec!["spec.infrastructure.parametersRef"]);
    }

    #[test]
    fn gateway_parameters_ref_wrong_group_rejected() {
        let gw = make_dyn_obj(serde_json::json!({
            "apiVersion": "gateway.networking.k8s.io/v1", "kind": "Gateway",
            "metadata": {"name": "gw-1", "namespace": "ns"},
            "spec": {"infrastructure": {"parametersRef": {"group": "example.com", "kind": "ConfigMap", "name": "my-cm"}}}
        }));
        let fields = extract_gateway_parameters_ref(&gw, "my-cm", Some("ns"));
        assert!(
            fields.is_empty(),
            "Non-core group parametersRef must not match ConfigMap"
        );
    }

    #[test]
    fn gateway_parameters_ref_wrong_ns_rejected() {
        let gw = make_dyn_obj(serde_json::json!({
            "apiVersion": "gateway.networking.k8s.io/v1", "kind": "Gateway",
            "metadata": {"name": "gw-1", "namespace": "other-ns"},
            "spec": {"infrastructure": {"parametersRef": {"group": "", "kind": "ConfigMap", "name": "my-cm"}}}
        }));
        let fields = extract_gateway_parameters_ref(&gw, "my-cm", Some("ns"));
        assert!(fields.is_empty(), "Different namespace must not match");
    }

    #[test]
    fn ingress_required_hpa_required() {
        let svc_specs = referrer_specs_for_target("Service", "");
        let ingress = svc_specs.iter().find(|s| s.kind == "Ingress").unwrap();
        assert!(
            ingress.required,
            "networking.k8s.io/Ingress should be required"
        );

        let dep_specs = referrer_specs_for_target("Deployment", "apps");
        let hpa = dep_specs
            .iter()
            .find(|s| s.kind == "HorizontalPodAutoscaler")
            .unwrap();
        assert!(hpa.required, "autoscaling/HPA should be required");
    }
}
