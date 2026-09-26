use std::collections::HashSet;

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

fn is_owned_by_deletion_closure(
    obj: &DynamicObject,
    deletion_closure: &HashSet<DeletionKey>,
) -> bool {
    if let Some(owner_refs) = &obj.metadata.owner_references {
        for oref in owner_refs {
            let group = if let Some(idx) = oref.api_version.find('/') {
                &oref.api_version[..idx]
            } else {
                ""
            };
            let ns = obj.metadata.namespace.as_deref();
            if deletion_closure.contains(&deletion_key(group, &oref.kind, ns, &oref.name)) {
                return true;
            }
        }
    }
    false
}

fn referrer_kinds_for_target(target_kind: &str) -> Vec<(&'static str, &'static str)> {
    match target_kind {
        "Gateway" => vec![
            ("gateway.networking.k8s.io", "HTTPRoute"),
            ("gateway.networking.k8s.io", "GRPCRoute"),
            ("gateway.networking.k8s.io", "TCPRoute"),
            ("gateway.networking.k8s.io", "TLSRoute"),
            ("gateway.networking.k8s.io", "UDPRoute"),
        ],
        _ => vec![],
    }
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

pub async fn check_inbound_refs(
    client: &Client,
    target: &ResourceId,
    deletion_closure: &HashSet<DeletionKey>,
    gk_map: &GroupKindMap,
) -> Result<InboundRefScan> {
    let mut blockers = Vec::new();
    let mut allowed = Vec::new();
    let mut kinds_scanned = Vec::new();
    let mut scan_complete = true;

    let check_kinds = referrer_kinds_for_target(&target.kind);

    for (group, kind) in &check_kinds {
        let kind_key = if group.is_empty() {
            kind.to_string()
        } else {
            format!("{}/{}", group, kind)
        };
        kinds_scanned.push(kind_key.clone());

        let gk = (group.to_string(), kind.to_string());
        let Some(info) = gk_map.get(&gk) else {
            scan_complete = false;
            continue;
        };

        let gvk = ::kube::api::GroupVersionKind {
            group: info.group.clone(),
            version: info.version.clone(),
            kind: kind.to_string(),
        };
        let ar = ::kube::api::ApiResource::from_gvk_with_plural(&gvk, &info.plural);

        let namespaces: Vec<Option<&str>> = if info.namespaced {
            if let Some(ref ns) = target.namespace {
                vec![Some(ns.as_str())]
            } else {
                vec![None]
            }
        } else {
            vec![None]
        };

        for ns in &namespaces {
            let api: Api<DynamicObject> = if let Some(ns) = ns {
                Api::namespaced_with(client.clone(), ns, &ar)
            } else {
                Api::all_with(client.clone(), &ar)
            };

            let list_result = api.list(&ListParams::default()).await;
            match list_result {
                Ok(list) => {
                    for obj in &list.items {
                        let ref_fields = match target.kind.as_str() {
                            "Gateway" => extract_gateway_parent_refs(
                                obj,
                                &target.name,
                                target.namespace.as_deref(),
                            ),
                            _ => vec![],
                        };

                        for field in ref_fields {
                            let obj_name = obj.metadata.name.as_deref().unwrap_or("").to_string();
                            let obj_ns = obj.metadata.namespace.clone();
                            let obj_uid = obj.metadata.uid.as_deref().unwrap_or("").to_string();
                            let obj_group = group.to_string();
                            let obj_kind = kind.to_string();

                            let referrer_key =
                                deletion_key(&obj_group, &obj_kind, obj_ns.as_deref(), &obj_name);

                            let in_closure = deletion_closure.contains(&referrer_key)
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

pub fn build_deletion_closure(
    phases: &[crate::teardown::plan::ExecutionPhase],
    explicit_targets: &[crate::DeleteResourceSpec],
) -> HashSet<DeletionKey> {
    use crate::teardown::plan::ExecutionAction;
    let mut closure = HashSet::new();
    for phase in phases {
        for res in &phase.resources {
            if matches!(
                res.action,
                ExecutionAction::Delete | ExecutionAction::Expect
            ) {
                closure.insert(deletion_key(
                    &res.group,
                    &res.kind,
                    res.namespace.as_deref(),
                    &res.name,
                ));
            }
        }
    }
    for t in explicit_targets {
        closure.insert(deletion_key(
            &t.group,
            &t.kind,
            t.namespace.as_deref(),
            &t.name,
        ));
    }
    closure
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
    fn extract_gateway_parent_refs_implicit_namespace() {
        let route_json = serde_json::json!({
            "apiVersion": "gateway.networking.k8s.io/v1",
            "kind": "HTTPRoute",
            "metadata": {"name": "r1", "namespace": "ns-a"},
            "spec": {
                "parentRefs": [
                    {"name": "my-gw"}
                ]
            }
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
            "spec": {
                "parentRefs": [
                    {"name": "my-gw", "kind": "Service"}
                ]
            }
        });
        let route: DynamicObject = serde_json::from_value(route_json).unwrap();
        let fields = extract_gateway_parent_refs(&route, "my-gw", Some("ns-a"));
        assert!(fields.is_empty(), "Non-Gateway parentRef should not match");
    }

    #[test]
    fn is_owned_by_deletion_closure_works() {
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

        let mut closure = HashSet::new();
        closure.insert(deletion_key(
            "apps",
            "Deployment",
            Some("ns-a"),
            "my-deploy",
        ));
        assert!(is_owned_by_deletion_closure(&obj, &closure));

        let empty_closure = HashSet::new();
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
}
