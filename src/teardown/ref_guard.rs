use std::collections::{HashMap, HashSet};

use ::kube::{
    Client,
    api::{Api, DynamicObject, ListParams},
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

fn is_owned_by_deletion_closure(obj: &DynamicObject, closure: &DeletionClosureWithUid) -> bool {
    if let Some(owner_refs) = &obj.metadata.owner_references {
        for oref in owner_refs {
            let group = if let Some(idx) = oref.api_version.find('/') {
                &oref.api_version[..idx]
            } else {
                ""
            };
            let ns = obj.metadata.namespace.as_deref();
            let key = deletion_key(group, &oref.kind, ns, &oref.name);
            if let Some(closure_uid) = closure.get(&key)
                && (closure_uid.is_empty() || closure_uid == &oref.uid)
            {
                return true;
            }
        }
    }
    false
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
        ],
        ("console.openshift.io", "ConsolePlugin") => vec![],
        ("apps", "Deployment") => vec![],
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

            if kind != "Gateway" || (group != "gateway.networking.k8s.io" && !group.is_empty()) {
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

fn extract_configmap_refs(obj: &DynamicObject, target_name: &str) -> Vec<String> {
    let mut fields = Vec::new();
    let spec = match obj.data.get("spec") {
        Some(s) => s,
        None => return fields,
    };
    if let Some(volumes) = spec
        .get("template")
        .and_then(|t| t.get("spec"))
        .and_then(|s| s.get("volumes"))
        .and_then(|v| v.as_array())
    {
        for (i, vol) in volumes.iter().enumerate() {
            if let Some(name) = vol
                .get("configMap")
                .and_then(|cm| cm.get("name"))
                .and_then(|n| n.as_str())
                && name == target_name
            {
                fields.push(format!("spec.template.spec.volumes[{}].configMap.name", i));
            }
        }
    }
    if let Some(containers) = spec
        .get("template")
        .and_then(|t| t.get("spec"))
        .and_then(|s| s.get("containers"))
        .and_then(|c| c.as_array())
    {
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
                            "spec.template.spec.containers[{}].envFrom[{}].configMapRef.name",
                            ci, ei
                        ));
                    }
                }
            }
        }
    }
    fields
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
                    let ref_ns = bref.get("namespace").and_then(|n| n.as_str());
                    if kind != "Service" || name != target_name {
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
        ("", "ConfigMap") => extract_configmap_refs(obj, target_name),
        ("", "Service") => match (referrer_group, referrer_kind) {
            ("console.openshift.io", "ConsolePlugin") => {
                extract_console_plugin_service_ref(obj, target_name, target_ns)
            }
            ("gateway.networking.k8s.io", "HTTPRoute" | "GRPCRoute") => {
                extract_service_backend_refs(obj, target_name, target_ns)
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

    let check_specs = referrer_specs_for_target(&target.kind, &target.group);
    let closure_keys: HashSet<&DeletionKey> = deletion_closure.keys().collect();

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

        // Always cluster-wide LIST for cross-namespace reference detection
        let api: Api<DynamicObject> = Api::all_with(client.clone(), &ar);

        let list_result = api.list(&ListParams::default()).await;
        match list_result {
            Ok(list) => {
                for obj in &list.items {
                    let ref_fields = extract_refs_for_target(
                        obj,
                        spec.group,
                        spec.kind,
                        &target.kind,
                        &target.group,
                        &target.name,
                        target.namespace.as_deref(),
                    );

                    for field in ref_fields {
                        let obj_name = obj.metadata.name.as_deref().unwrap_or("").to_string();
                        let obj_ns = obj.metadata.namespace.clone();
                        let obj_uid = obj.metadata.uid.as_deref().unwrap_or("").to_string();
                        let obj_group = spec.group.to_string();
                        let obj_kind = spec.kind.to_string();

                        let referrer_key =
                            deletion_key(&obj_group, &obj_kind, obj_ns.as_deref(), &obj_name);

                        let in_closure = closure_keys.contains(&referrer_key)
                            || is_owned_by_deletion_closure(obj, deletion_closure);

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
            Err(e) => {
                eprintln!(
                    "⚠ Failed to list {} for inbound reference check: {}",
                    kind_key, e
                );
                scan_complete = false;
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
        let fields = extract_configmap_refs(&obj, "my-cm");
        assert_eq!(fields, vec!["spec.template.spec.volumes[0].configMap.name"]);
        let fields2 = extract_configmap_refs(&obj, "no-match");
        assert!(fields2.is_empty());
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

    #[test]
    fn is_owned_by_deletion_closure_uid_match() {
        let obj_json = serde_json::json!({
            "apiVersion": "v1",
            "kind": "Pod",
            "metadata": {
                "name": "pod-1",
                "namespace": "ns-a",
                "ownerReferences": [{
                    "apiVersion": "apps/v1",
                    "kind": "Deployment",
                    "name": "my-deploy",
                    "uid": "abc123"
                }]
            }
        });
        let obj: DynamicObject = serde_json::from_value(obj_json).unwrap();

        let mut closure = DeletionClosureWithUid::new();
        closure.insert(
            deletion_key("apps", "Deployment", Some("ns-a"), "my-deploy"),
            "abc123".to_string(),
        );
        assert!(is_owned_by_deletion_closure(&obj, &closure));

        let mut wrong_uid = DeletionClosureWithUid::new();
        wrong_uid.insert(
            deletion_key("apps", "Deployment", Some("ns-a"), "my-deploy"),
            "wrong-uid".to_string(),
        );
        assert!(
            !is_owned_by_deletion_closure(&obj, &wrong_uid),
            "Stale UID must not match"
        );

        let empty_closure = DeletionClosureWithUid::new();
        assert!(!is_owned_by_deletion_closure(&obj, &empty_closure));
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
    fn configmap_referrers_are_required() {
        let specs = referrer_specs_for_target("ConfigMap", "");
        assert!(
            specs.iter().all(|s| s.required),
            "Deployment/StatefulSet/DaemonSet should be required"
        );
    }
}
