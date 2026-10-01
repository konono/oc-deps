use crate::analyzers::selector::{
    build_network_inventory, build_service_network_path, evaluate_network_postures,
    find_network_paths,
};
use crate::cli::OutputFormat;
use crate::kube::discovery::{build_kind_lookup_cached, resolve_kind_with_group};
use crate::kube::resource::format_scan_warnings;
use crate::kube::scanner::scan_namespace_with_extra_apis;
use anyhow::bail;
use std::time::Instant;

pub(crate) fn selector_to_json(sel: &crate::analyzers::selector::PodSelector) -> serde_json::Value {
    let mut obj = serde_json::json!({});
    if !sel.match_labels.is_empty() {
        obj["matchLabels"] = serde_json::json!(sel.match_labels);
    }
    if !sel.match_expressions.is_empty() {
        let exprs: Vec<_> = sel
            .match_expressions
            .iter()
            .map(|e| {
                serde_json::json!({
                    "key": e.key,
                    "operator": e.operator,
                    "values": e.values,
                })
            })
            .collect();
        obj["matchExpressions"] = serde_json::json!(exprs);
    }
    obj
}

pub(crate) fn label_selectors_to_json(
    selectors: &[crate::analyzers::selector::LabelSelector],
) -> serde_json::Value {
    let items: Vec<_> = selectors
        .iter()
        .map(|s| {
            let mut obj = serde_json::json!({});
            if !s.match_labels.is_empty() {
                obj["matchLabels"] = serde_json::json!(s.match_labels);
            }
            if !s.match_expressions.is_empty() {
                let exprs: Vec<_> = s
                    .match_expressions
                    .iter()
                    .map(|e| {
                        serde_json::json!({
                            "key": e.key,
                            "operator": e.operator,
                            "values": e.values,
                        })
                    })
                    .collect();
                obj["matchExpressions"] = serde_json::json!(exprs);
            }
            obj
        })
        .collect();
    serde_json::json!(items)
}

pub(crate) fn format_selector(sel: &crate::analyzers::selector::PodSelector) -> String {
    let mut parts = Vec::new();
    for (k, v) in &sel.match_labels {
        parts.push(format!("{}={}", k, v));
    }
    for expr in &sel.match_expressions {
        match expr.operator.as_str() {
            "In" => parts.push(format!("{} in ({})", expr.key, expr.values.join(","))),
            "NotIn" => parts.push(format!("{} notin ({})", expr.key, expr.values.join(","))),
            "Exists" => parts.push(expr.key.clone()),
            "DoesNotExist" => parts.push(format!("!{}", expr.key)),
            _ => parts.push(format!("{}?{}", expr.key, expr.operator)),
        }
    }
    if parts.is_empty() {
        "*".to_string()
    } else {
        parts.join(",")
    }
}

pub(crate) fn format_policy_peers(
    peers: &[crate::analyzers::selector::NetworkPolicyPeer],
) -> String {
    if peers.is_empty() {
        return String::new();
    }
    peers
        .iter()
        .map(|peer| {
            let mut parts = Vec::new();
            if let Some(ns) = &peer.namespace_selector {
                parts.push(format!("namespaceSelector{{{}}}", format_selector(ns)));
            }
            if let Some(ps) = &peer.pod_selector {
                parts.push(format!("podSelector{{{}}}", format_selector(ps)));
            }
            if let Some(ib) = &peer.ip_block {
                let mut s = format!("ipBlock:{}", ib.cidr);
                if !ib.except.is_empty() {
                    s.push_str(&format!(" except [{}]", ib.except.join(",")));
                }
                parts.push(s);
            }
            parts.join(" ")
        })
        .collect::<Vec<_>>()
        .join("; ")
}

pub(crate) fn format_policy_ports(
    ports: &[crate::analyzers::selector::NetworkPolicyPort],
) -> String {
    if ports.is_empty() {
        return String::new();
    }
    ports
        .iter()
        .map(|p| {
            let proto = p.protocol.as_deref().unwrap_or("TCP");
            let port = match &p.port {
                Some(crate::analyzers::selector::IntOrString::Int(n)) => n.to_string(),
                Some(crate::analyzers::selector::IntOrString::String(s)) => s.clone(),
                None => "*".to_string(),
            };
            if let Some(ep) = p.end_port {
                format!("{}/{}-{}", proto, port, ep)
            } else {
                format!("{}/{}", proto, port)
            }
        })
        .collect::<Vec<_>>()
        .join(", ")
}

pub(crate) fn network_paths_to_json(
    paths: &[(String, crate::analyzers::selector::NetworkPath)],
    metallb_results: &[crate::analyzers::selector::MetalLBResult],
    gateway_results: &[Vec<crate::analyzers::selector::MatchedGatewayRoute>],
) -> Vec<serde_json::Value> {
    let mut seen_svcs = std::collections::HashSet::new();
    let mut metallb_idx = 0usize;
    let mut gw_idx = 0usize;
    paths
        .iter()
        .filter(|(_, p)| seen_svcs.insert(p.service.name.clone()))
        .map(|(_, p)| {
            let mlb = metallb_results.get(metallb_idx);
            metallb_idx += 1;
            let gw_routes = gateway_results.get(gw_idx).cloned().unwrap_or_default();
            gw_idx += 1;
            let _ = mlb; // used below
            let ports: Vec<_> = p
                .service
                .ports
                .iter()
                .map(|sp| {
                    let mut port_obj = serde_json::json!({
                        "port": sp.port,
                        "targetPort": sp.target_port,
                        "protocol": sp.protocol,
                    });
                    if let Some(np) = sp.node_port {
                        port_obj["nodePort"] = serde_json::json!(np);
                    }
                    port_obj
                })
                .collect();
            let ingresses: Vec<_> = p
                .ingresses
                .iter()
                .map(|i| {
                    let mut obj = serde_json::json!({"kind": i.kind, "name": i.name});
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
            let endpoint_slices_json: Vec<_> = p
                .endpoint_slices
                .iter()
                .map(|es| {
                    let eps: Vec<_> = es
                        .endpoints
                        .iter()
                        .map(|ep| {
                            let mut obj = serde_json::json!({
                                "addresses": ep.addresses,
                                "ready": ep.conditions_ready,
                                "serving": ep.conditions_serving,
                                "terminating": ep.conditions_terminating,
                            });
                            if let Some(h) = &ep.hostname {
                                obj["hostname"] = serde_json::json!(h);
                            }
                            if let Some(n) = &ep.node_name {
                                obj["nodeName"] = serde_json::json!(n);
                            }
                            if let Some(z) = &ep.zone {
                                obj["zone"] = serde_json::json!(z);
                            }
                            if let Some(tr) = &ep.target_ref {
                                let mut tr_obj = serde_json::Map::new();
                                if let Some(v) = &tr.api_version {
                                    tr_obj.insert("apiVersion".into(), serde_json::json!(v));
                                }
                                if let Some(v) = &tr.kind {
                                    tr_obj.insert("kind".into(), serde_json::json!(v));
                                }
                                if let Some(v) = &tr.name {
                                    tr_obj.insert("name".into(), serde_json::json!(v));
                                }
                                if let Some(v) = &tr.namespace {
                                    tr_obj.insert("namespace".into(), serde_json::json!(v));
                                }
                                if let Some(v) = &tr.uid {
                                    tr_obj.insert("uid".into(), serde_json::json!(v));
                                }
                                obj["targetRef"] = serde_json::Value::Object(tr_obj);
                            }
                            if let Some(hints) = &ep.hints {
                                obj["hints"] = serde_json::json!(hints);
                            }
                            obj
                        })
                        .collect();
                    let es_ports: Vec<_> = es
                        .ports
                        .iter()
                        .map(|port| {
                            let mut obj =
                                serde_json::json!({"port": port.port, "protocol": port.protocol});
                            if let Some(n) = &port.name {
                                obj["name"] = serde_json::json!(n);
                            }
                            if let Some(ap) = &port.app_protocol {
                                obj["appProtocol"] = serde_json::json!(ap);
                            }
                            obj
                        })
                        .collect();
                    serde_json::json!({
                        "name": es.name,
                        "addressType": es.address_type,
                        "ports": es_ports,
                        "endpoints": eps,
                    })
                })
                .collect();
            let es = &p.endpoint_summary;
            let svc = &p.service;
            let mut config = serde_json::json!({
                "type": svc.svc_type,
                "clusterIP": svc.cluster_ip,
                "ports": ports,
                "selector": svc.selector,
                "hasSelector": svc.has_selector,
            });
            if !svc.external_ips.is_empty() {
                config["externalIPs"] = serde_json::json!(svc.external_ips);
            }
            if !svc.ip_families.is_empty() {
                config["ipFamilies"] = serde_json::json!(svc.ip_families);
            }
            if let Some(v) = &svc.external_traffic_policy {
                config["externalTrafficPolicy"] = serde_json::json!(v);
            }
            if let Some(v) = &svc.internal_traffic_policy {
                config["internalTrafficPolicy"] = serde_json::json!(v);
            }
            if let Some(v) = &svc.ip_family_policy {
                config["ipFamilyPolicy"] = serde_json::json!(v);
            }
            if let Some(v) = svc.health_check_node_port {
                config["healthCheckNodePort"] = serde_json::json!(v);
            }
            if let Some(v) = &svc.load_balancer_class {
                config["loadBalancerClass"] = serde_json::json!(v);
            }
            if let Some(v) = svc.allocate_lb_node_ports {
                config["allocateLoadBalancerNodePorts"] = serde_json::json!(v);
            }
            let mut status = serde_json::json!({});
            if !svc.lb_ingress.is_empty() {
                let lb: Vec<_> = svc
                    .lb_ingress
                    .iter()
                    .map(|lbi| {
                        let mut obj = serde_json::Map::new();
                        if let Some(ip) = &lbi.ip {
                            obj.insert("ip".into(), serde_json::json!(ip));
                        }
                        if let Some(h) = &lbi.hostname {
                            obj.insert("hostname".into(), serde_json::json!(h));
                        }
                        if let Some(m) = &lbi.ip_mode {
                            obj.insert("ipMode".into(), serde_json::json!(m));
                        }
                        serde_json::Value::Object(obj)
                    })
                    .collect();
                status["loadBalancerIngress"] = serde_json::json!(lb);
            }
            let mut result = serde_json::json!({
                "service": {"name": svc.name, "config": config, "status": status},
                "ingresses": ingresses,
                "endpointSlices": endpoint_slices_json,
                "endpointSummary": {"ready": es.ready, "notReady": es.not_ready, "unknown": es.unknown, "effectiveReady": es.effective_ready, "serving": es.serving, "terminating": es.terminating},
                "selectorMatchedPods": p.selector_matched_pods,
                "targetRefMatchedPods": p.target_ref_matched_pods,
            });
            // Always emit gatewayRoutes and gatewayWarnings (empty arrays when no routes)
            let gw_routes_json: Vec<serde_json::Value> = gw_routes
                .iter()
                .map(|gr| {
                    let listeners_json: Vec<serde_json::Value> = gr
                        .listeners
                        .iter()
                        .map(|l| {
                            let mut obj = serde_json::json!({
                                "name": l.name,
                                "port": l.port,
                                "protocol": l.protocol,
                            });
                            if let Some(h) = &l.hostname {
                                obj["hostname"] = serde_json::json!(h);
                            }
                            if let Some(t) = &l.tls_mode {
                                obj["tlsMode"] = serde_json::json!(t);
                            }
                            obj
                        })
                        .collect();
                    let matched_backends_json: Vec<serde_json::Value> = gr
                        .matched_backends
                        .iter()
                        .map(|mb| {
                            let rule_matches: Vec<serde_json::Value> = mb
                                .rule_matches
                                .iter()
                                .map(|m| {
                                    let mut obj = serde_json::Map::new();
                                    if let Some(pt) = &m.path_type {
                                        obj.insert("pathType".into(), serde_json::json!(pt));
                                    }
                                    if let Some(pv) = &m.path_value {
                                        obj.insert("pathValue".into(), serde_json::json!(pv));
                                    }
                                    if let Some(method) = &m.method {
                                        obj.insert("method".into(), serde_json::json!(method));
                                    }
                                    serde_json::Value::Object(obj)
                                })
                                .collect();
                            let mut obj = serde_json::Map::new();
                            if let Some(p) = mb.port {
                                obj.insert("port".into(), serde_json::json!(p));
                            }
                            if let Some(w) = mb.weight {
                                obj.insert("weight".into(), serde_json::json!(w));
                            }
                            if !rule_matches.is_empty() {
                                obj.insert("ruleMatches".into(), serde_json::json!(rule_matches));
                            }
                            serde_json::Value::Object(obj)
                        })
                        .collect();
                    let conditions_json: Vec<serde_json::Value> = gr
                        .status_conditions
                        .iter()
                        .map(|c| {
                            let mut obj = serde_json::json!({
                                "type": c.condition_type,
                                "status": c.status,
                            });
                            if let Some(r) = &c.reason {
                                obj["reason"] = serde_json::json!(r);
                            }
                            if let Some(m) = &c.message {
                                obj["message"] = serde_json::json!(m);
                            }
                            obj
                        })
                        .collect();
                    let cross_ns_str = match &gr.cross_namespace {
                        crate::analyzers::selector::CrossNamespaceStatus::SameNamespace => {
                            "same-namespace"
                        }
                        crate::analyzers::selector::CrossNamespaceStatus::Allowed => "allowed",
                        crate::analyzers::selector::CrossNamespaceStatus::NotAllowed => {
                            "not-allowed"
                        }
                        crate::analyzers::selector::CrossNamespaceStatus::Unknown => "unknown",
                    };
                    let mut route_json = serde_json::json!({
                        "kind": gr.route_kind,
                        "name": gr.route_name,
                        "namespace": gr.route_namespace,
                        "gatewayName": gr.gateway_name,
                        "gatewayNamespace": gr.gateway_namespace,
                        "listeners": listeners_json,
                        "matchedBackends": matched_backends_json,
                        "crossNamespace": cross_ns_str,
                        "statusConditions": conditions_json,
                    });
                    if !gr.hostnames.is_empty() {
                        route_json["hostnames"] = serde_json::json!(gr.hostnames);
                    }
                    if let Some(gc) = &gr.gateway_class_name {
                        route_json["gatewayClassName"] = serde_json::json!(gc);
                    }
                    if let Some(gc) = &gr.gateway_class_controller {
                        route_json["gatewayClassController"] = serde_json::json!(gc);
                    }
                    if let Some(sn) = &gr.section_name {
                        route_json["sectionName"] = serde_json::json!(sn);
                    }
                    if let Some(pp) = gr.parent_port {
                        route_json["parentPort"] = serde_json::json!(pp);
                    }
                    route_json
                })
                .collect();
            let gw_warnings_json: Vec<String> = gw_routes
                .iter()
                .flat_map(|gr| gr.warnings.clone())
                .collect();
            result["gatewayRoutes"] = serde_json::json!(gw_routes_json);
            result["gatewayWarnings"] = serde_json::json!(gw_warnings_json);
            if let Some(mlb) = mlb {
                let pools_json: Vec<_> = mlb.pools.iter().map(|mp| {
                    let mut obj = serde_json::json!({
                        "name": mp.pool.name,
                        "namespace": mp.pool.namespace,
                        "addresses": mp.pool.addresses,
                        "matchReason": mp.match_reason,
                        "autoAssign": mp.pool.auto_assign,
                    });
                    if let Some(am) = &mp.allocation_match {
                        obj["allocationMatch"] = serde_json::json!(am);
                    }
                    if let Some(sa) = &mp.pool.service_allocation {
                        let mut sa_obj = serde_json::json!({
                            "priority": sa.priority,
                            "namespaces": sa.namespaces,
                        });
                        if !sa.namespace_selectors.is_empty() {
                            sa_obj["namespaceSelectors"] =
                                label_selectors_to_json(&sa.namespace_selectors);
                        }
                        if !sa.service_selectors.is_empty() {
                            sa_obj["serviceSelectors"] =
                                label_selectors_to_json(&sa.service_selectors);
                        }
                        obj["serviceAllocation"] = sa_obj;
                    }
                    if let Some(v) = mp.pool.status_available_ipv4 {
                        obj["statusAvailableIPv4"] = serde_json::json!(v);
                    }
                    if let Some(v) = mp.pool.status_available_ipv6 {
                        obj["statusAvailableIPv6"] = serde_json::json!(v);
                    }
                    if let Some(v) = mp.pool.status_assigned_ipv4 {
                        obj["statusAssignedIPv4"] = serde_json::json!(v);
                    }
                    if let Some(v) = mp.pool.status_assigned_ipv6 {
                        obj["statusAssignedIPv6"] = serde_json::json!(v);
                    }
                    if !mp.pool.labels.is_empty() {
                        obj["labels"] = serde_json::json!(mp.pool.labels);
                    }
                    obj
                }).collect();
                let ads_json: Vec<_> = mlb.advertisements.iter().map(|a| {
                    let mut obj = serde_json::json!({
                        "kind": a.kind,
                        "name": a.name,
                        "namespace": a.namespace,
                        "matchReason": a.match_reason,
                        "nodeSelectorStatus": a.node_selector_status,
                    });
                    if !a.node_selectors.is_empty() {
                        obj["nodeSelectors"] = label_selectors_to_json(&a.node_selectors);
                    }
                    if !a.candidate_nodes.is_empty() {
                        obj["candidateNodes"] = serde_json::json!(a.candidate_nodes);
                    }
                    if !a.service_selectors.is_empty() {
                        obj["serviceSelectors"] = label_selectors_to_json(&a.service_selectors);
                    }
                    if !a.interfaces.is_empty() {
                        obj["interfaces"] = serde_json::json!(a.interfaces);
                    }
                    if !a.peers.is_empty() {
                        obj["peers"] = serde_json::json!(a.peers);
                    }
                    if let Some(al) = a.aggregation_length {
                        obj["aggregationLength"] = serde_json::json!(al);
                    }
                    if let Some(al6) = a.aggregation_length_v6 {
                        obj["aggregationLengthV6"] = serde_json::json!(al6);
                    }
                    if let Some(lp) = a.local_pref {
                        obj["localPref"] = serde_json::json!(lp);
                    }
                    if !a.communities.is_empty() {
                        obj["communities"] = serde_json::json!(a.communities);
                    }
                    obj
                }).collect();
                let obs = &mlb.observation;
                let bgp_node_json: Vec<serde_json::Value> = obs
                    .bgp_advertised_nodes
                    .iter()
                    .map(|n| {
                        serde_json::json!({
                            "node": n.node,
                            "peers": n.peers,
                        })
                    })
                    .collect();
                let peers_json: Vec<serde_json::Value> = obs
                    .related_peers
                    .iter()
                    .map(|p| {
                        serde_json::json!({
                            "name": p.name,
                            "namespace": p.namespace,
                            "peerAddress": p.peer_address,
                            "peerASN": p.peer_asn,
                            "myASN": p.my_asn,
                            "sourceAddress": p.source_address,
                            "bfdProfile": p.bfd_profile,
                            "holdTime": p.hold_time,
                            "keepaliveTime": p.keepalive_time,
                            "routerID": p.router_id,
                            "nodeSelectors": label_selectors_to_json(&p.node_selectors),
                        })
                    })
                    .collect();
                let bfd_json: Vec<serde_json::Value> = obs
                    .related_bfd_profiles
                    .iter()
                    .map(|b| {
                        serde_json::json!({
                            "name": b.name,
                            "namespace": b.namespace,
                            "detectMultiplier": b.detect_multiplier,
                            "receiveInterval": b.receive_interval,
                            "transmitInterval": b.transmit_interval,
                            "echoInterval": b.echo_interval,
                            "minimumTtl": b.minimum_ttl,
                            "passiveMode": b.passive_mode,
                        })
                    })
                    .collect();
                let events_json: Vec<serde_json::Value> = obs
                    .events
                    .iter()
                    .map(|e| {
                        serde_json::json!({
                            "reason": e.reason,
                            "message": e.message,
                            "sourceComponent": e.source_component,
                            "reportingComponent": e.reporting_component,
                            "type": e.event_type,
                            "lastTimestamp": e.last_timestamp,
                        })
                    })
                    .collect();
                let config_states_json: Vec<serde_json::Value> = obs
                    .configuration_states
                    .iter()
                    .map(|cs| {
                        let conditions: Vec<serde_json::Value> = cs
                            .conditions
                            .iter()
                            .map(|c| {
                                serde_json::json!({
                                    "type": c.condition_type,
                                    "status": c.status,
                                    "reason": c.reason,
                                    "message": c.message,
                                })
                            })
                            .collect();
                        serde_json::json!({
                            "name": cs.name,
                            "namespace": cs.namespace,
                            "componentType": cs.component_type,
                            "nodeName": cs.node_name,
                            "result": cs.result,
                            "errorSummary": cs.error_summary,
                            "conditions": conditions,
                        })
                    })
                    .collect();
                let avail_str = |a: &crate::analyzers::selector::ApiAvailability| match a {
                    crate::analyzers::selector::ApiAvailability::Available => "available",
                    crate::analyzers::selector::ApiAvailability::Absent => "absent",
                    crate::analyzers::selector::ApiAvailability::Unavailable => "unavailable",
                };
                let mut obs_json = serde_json::json!({
                    "observedState": obs.observed_state,
                    "l2AdvertisedNodes": obs.l2_advertised_nodes,
                    "l2Interfaces": obs.l2_interfaces,
                    "l2StatusResources": obs.l2_status_resources.iter().map(|(n, ns)| format!("{}/{}", ns, n)).collect::<Vec<_>>(),
                    "bgpNodeStatus": bgp_node_json,
                    "bgpStatusResources": obs.bgp_status_resources.iter().map(|(n, ns)| format!("{}/{}", ns, n)).collect::<Vec<_>>(),
                    "relatedPeers": peers_json,
                    "relatedBfdProfiles": bfd_json,
                    "configurationStates": config_states_json,
                    "events": events_json,
                    "apiAvailability": {
                        "l2Status": avail_str(&obs.api_availability.l2_status),
                        "bgpStatus": avail_str(&obs.api_availability.bgp_status),
                        "bgpPeer": avail_str(&obs.api_availability.bgp_peer),
                        "bfdProfile": avail_str(&obs.api_availability.bfd_profile),
                        "events": avail_str(&obs.api_availability.events),
                        "configurationState": avail_str(&obs.api_availability.configuration_state),
                    },
                    "note": "Status represents advertisement intent, not BGP session establishment"
                });
                if !obs.session_state.is_empty() {
                    obs_json["sessionState"] = serde_json::json!(obs.session_state);
                }
                result["metallb"] = serde_json::json!({
                    "provider": mlb.provider,
                    "requestedIPs": mlb.requested_ips,
                    "requestedPool": mlb.requested_pool,
                    "pools": pools_json,
                    "advertisements": ads_json,
                    "warnings": mlb.warnings,
                    "observation": obs_json
                });
            }
            result
        })
        .collect()
}

pub(crate) fn network_postures_to_json(
    postures: &[crate::analyzers::selector::PodNetworkPosture],
) -> Vec<serde_json::Value> {
    postures
        .iter()
        .map(|p| {
            let policies: Vec<_> = p
                .applicable_policies
                .iter()
                .map(|ap| {
                    let mk_rules = |rules: &[crate::analyzers::selector::NetworkPolicyRule]| {
                        rules
                            .iter()
                            .map(|r| {
                                serde_json::json!({
                                    "peers": r.peers.iter().map(|peer| {
                                        let mut obj = serde_json::Map::new();
                                        if let Some(ps) = &peer.pod_selector { obj.insert("podSelector".into(), selector_to_json(ps)); }
                                        if let Some(ns) = &peer.namespace_selector { obj.insert("namespaceSelector".into(), selector_to_json(ns)); }
                                        if let Some(ib) = &peer.ip_block { obj.insert("ipBlock".into(), serde_json::json!({"cidr": ib.cidr, "except": ib.except})); }
                                        serde_json::Value::Object(obj)
                                    }).collect::<Vec<_>>(),
                                    "ports": r.ports.iter().map(|port| {
                                        let mut obj = serde_json::Map::new();
                                        if let Some(proto) = &port.protocol { obj.insert("protocol".into(), serde_json::json!(proto)); }
                                        if let Some(p) = &port.port {
                                            match p {
                                                crate::analyzers::selector::IntOrString::Int(n) => { obj.insert("port".into(), serde_json::json!(n)); }
                                                crate::analyzers::selector::IntOrString::String(s) => { obj.insert("port".into(), serde_json::json!(s)); }
                                            }
                                        }
                                        if let Some(ep) = port.end_port { obj.insert("endPort".into(), serde_json::json!(ep)); }
                                        serde_json::Value::Object(obj)
                                    }).collect::<Vec<_>>(),
                                })
                            })
                            .collect::<Vec<_>>()
                    };
                    serde_json::json!({
                        "name": ap.name,
                        "podSelector": selector_to_json(&ap.pod_selector),
                        "policyTypes": ap.policy_types,
                        "isolatesIngress": ap.isolates_ingress,
                        "isolatesEgress": ap.isolates_egress,
                        "ingressRules": mk_rules(&ap.ingress_rules),
                        "egressRules": mk_rules(&ap.egress_rules),
                    })
                })
                .collect();
            serde_json::json!({
                "podName": p.pod_name,
                "podUid": p.pod_uid,
                "ingressIsolation": p.ingress_isolation,
                "egressIsolation": p.egress_isolation,
                "applicablePolicies": policies,
            })
        })
        .collect()
}

pub(crate) fn print_network_tree(
    kind: &str,
    name: &str,
    paths: &[(String, crate::analyzers::selector::NetworkPath)],
    postures: &[crate::analyzers::selector::PodNetworkPosture],
    metallb_results: &[crate::analyzers::selector::MetalLBResult],
    gateway_results: &[Vec<crate::analyzers::selector::MatchedGatewayRoute>],
) {
    let stdout_tty = std::io::IsTerminal::is_terminal(&std::io::stdout());
    if paths.is_empty() {
        println!("No Services select Pods under {}/{}", kind, name);
        return;
    }
    println!("Network paths for {}/{}:\n", kind, name);
    let mut seen_svcs = std::collections::HashSet::new();
    let mut mlb_idx = 0usize;
    let mut gw_idx = 0usize;
    for (_, path) in paths {
        if !seen_svcs.insert(path.service.name.clone()) {
            continue;
        }
        let svc = &path.service;
        if stdout_tty {
            println!("  \x1b[1mService/{}\x1b[0m", svc.name);
        } else {
            println!("  Service/{}", svc.name);
        }
        println!("    Type:      {}", svc.svc_type);
        println!("    ClusterIP: {}", svc.cluster_ip);
        for sp in &svc.ports {
            if let Some(np) = sp.node_port {
                println!(
                    "    Port:      {}/{} \u{2192} {} (nodePort: {})",
                    sp.port, sp.protocol, sp.target_port, np
                );
            } else {
                println!(
                    "    Port:      {}/{} \u{2192} {}",
                    sp.port, sp.protocol, sp.target_port
                );
            }
        }
        if !svc.external_ips.is_empty() {
            println!("    ExternalIPs: {}", svc.external_ips.join(", "));
        }
        if !svc.ip_families.is_empty() {
            println!("    IPFamilies: {}", svc.ip_families.join(", "));
        }
        let sel = svc
            .selector
            .iter()
            .map(|(k, v)| format!("{}={}", k, v))
            .collect::<Vec<_>>()
            .join(", ");
        println!("    Selector:  {}", sel);
        if let Some(v) = &svc.internal_traffic_policy {
            println!("    InternalTrafficPolicy: {}", v);
        }
        if let Some(v) = &svc.external_traffic_policy {
            println!("    ExternalTrafficPolicy: {}", v);
        }
        if let Some(v) = &svc.ip_family_policy {
            println!("    IPFamilyPolicy:        {}", v);
        }
        if let Some(v) = svc.health_check_node_port {
            println!("    HealthCheckNodePort:   {}", v);
        }
        if let Some(v) = &svc.load_balancer_class {
            println!("    LoadBalancerClass:     {}", v);
        }
        if let Some(v) = svc.allocate_lb_node_ports {
            println!("    AllocateLBNodePorts:   {}", v);
        }
        for lbi in &svc.lb_ingress {
            let mut parts = Vec::new();
            if let Some(ip) = &lbi.ip {
                parts.push(ip.clone());
            }
            if let Some(h) = &lbi.hostname {
                parts.push(h.clone());
            }
            let addr = if parts.is_empty() {
                "?".to_string()
            } else {
                parts.join(" / ")
            };
            let mode = lbi
                .ip_mode
                .as_deref()
                .map(|m| format!(" (ipMode: {})", m))
                .unwrap_or_default();
            println!("    LB Ingress: {}{}", addr, mode);
        }
        // MetalLB section
        if let Some(mlb) = metallb_results.get(mlb_idx)
            && let Some(provider) = &mlb.provider
        {
            println!("    LB Provider:   {}", provider);
            if !mlb.requested_ips.is_empty() {
                println!("    Requested IPs: {}", mlb.requested_ips.join(", "));
            }
            if let Some(rp) = &mlb.requested_pool {
                println!("    Requested Pool: {}", rp);
            }
            for mp in &mlb.pools {
                println!(
                    "    Pool: {} [{}] ({})",
                    mp.pool.name,
                    mp.pool.addresses.join(", "),
                    mp.match_reason
                );
                if let Some(am) = &mp.allocation_match {
                    println!("      Allocation: {}", am);
                }
                let mut status_parts = Vec::new();
                if let Some(v) = mp.pool.status_available_ipv4 {
                    status_parts.push(format!("available IPv4: {}", v));
                }
                if let Some(v) = mp.pool.status_assigned_ipv4 {
                    status_parts.push(format!("assigned IPv4: {}", v));
                }
                if let Some(v) = mp.pool.status_available_ipv6 {
                    status_parts.push(format!("available IPv6: {}", v));
                }
                if let Some(v) = mp.pool.status_assigned_ipv6 {
                    status_parts.push(format!("assigned IPv6: {}", v));
                }
                if !status_parts.is_empty() {
                    println!("      Status: {}", status_parts.join(", "));
                }
            }
            for ad in &mlb.advertisements {
                println!("    {}/{} ({})", ad.kind, ad.name, ad.match_reason);
                if !ad.interfaces.is_empty() {
                    println!("      interfaces: {}", ad.interfaces.join(", "));
                }
                if !ad.peers.is_empty() {
                    println!("      peers: {}", ad.peers.join(", "));
                }
                if !ad.node_selectors.is_empty() {
                    println!(
                        "      node selector: {} ({})",
                        ad.node_selector_status,
                        if ad.candidate_nodes.is_empty() {
                            "no matching nodes".to_string()
                        } else {
                            ad.candidate_nodes.join(", ")
                        }
                    );
                }
            }
            // Observed state
            if !mlb.observation.observed_state.is_empty() {
                println!("    Observed: {}", mlb.observation.observed_state);
                if !mlb.observation.l2_advertised_nodes.is_empty() {
                    println!(
                        "      L2 nodes: {}",
                        mlb.observation.l2_advertised_nodes.join(", ")
                    );
                }
                if !mlb.observation.l2_interfaces.is_empty() {
                    println!(
                        "      L2 interfaces: {}",
                        mlb.observation.l2_interfaces.join(", ")
                    );
                }
                for bgp_node in &mlb.observation.bgp_advertised_nodes {
                    let peers_str = if bgp_node.peers.is_empty() {
                        String::new()
                    } else {
                        format!(" peers: {}", bgp_node.peers.join(", "))
                    };
                    println!("      BGP node: {}{}", bgp_node.node, peers_str);
                }
                for peer in &mlb.observation.related_peers {
                    let addr = peer.peer_address.as_deref().unwrap_or("?");
                    let asn = peer
                        .peer_asn
                        .map(|a| format!(" ASN:{}", a))
                        .unwrap_or_default();
                    println!("      BGP peer: BGPPeer/{} ({}{})", peer.name, addr, asn);
                }
                for event in &mlb.observation.events {
                    let reason = event.reason.as_deref().unwrap_or("?");
                    let msg = event.message.as_deref().unwrap_or("");
                    println!("      Event: {} - {}", reason, msg);
                }
                for cs in &mlb.observation.configuration_states {
                    let result_str = cs.result.as_deref().unwrap_or("?");
                    let err = cs.error_summary.as_deref().unwrap_or("");
                    let comp = cs.component_type.as_deref().unwrap_or("");
                    let node = cs.node_name.as_deref().unwrap_or("");
                    println!("      ConfigurationState/{}:", cs.name);
                    println!("        Result: {}", result_str);
                    if !err.is_empty() {
                        println!("        Error: {}", err);
                    }
                    if !comp.is_empty() {
                        println!("        Component: {}", comp);
                    }
                    if !node.is_empty() {
                        println!("        Node: {}", node);
                    }
                    if result_str != "OK" && result_str != "Success" && !cs.conditions.is_empty() {
                        println!("        Conditions:");
                        for c in &cs.conditions {
                            let reason = c
                                .reason
                                .as_deref()
                                .map(|r| format!(" ({})", r))
                                .unwrap_or_default();
                            println!("          {}: {}{}", c.condition_type, c.status, reason);
                        }
                    }
                }
            }
            if !mlb.observation.session_state.is_empty() {
                println!(
                    "    BGP session: {} (status is advertisement intent, not session state)",
                    mlb.observation.session_state
                );
            }
            for w in &mlb.warnings {
                println!("    [!] {}", w);
            }
        }
        mlb_idx += 1;
        println!(
            "    SelectorPods:  {}",
            path.selector_matched_pods.join(", ")
        );
        if !path.target_ref_matched_pods.is_empty() {
            println!(
                "    TargetRefPods: {}",
                path.target_ref_matched_pods.join(", ")
            );
        }
        let es = &path.endpoint_summary;
        let unknown_note = if es.unknown > 0 {
            format!(" ({} unknown)", es.unknown)
        } else {
            String::new()
        };
        println!(
            "    Endpoints: {} ready{}, {} not-ready, {} terminating, {} serving",
            es.effective_ready, unknown_note, es.not_ready, es.terminating, es.serving
        );
        for es_info in &path.endpoint_slices {
            println!();
            if stdout_tty {
                println!(
                    "    \x1b[1mEndpointSlice/{}\x1b[0m ({})",
                    es_info.name, es_info.address_type
                );
            } else {
                println!(
                    "    EndpointSlice/{} ({})",
                    es_info.name, es_info.address_type
                );
            }
            for ep_port in &es_info.ports {
                let port_str = ep_port.port.map(|p| p.to_string()).unwrap_or("?".into());
                let name_str = ep_port.name.as_deref().unwrap_or("");
                let app_proto = ep_port
                    .app_protocol
                    .as_deref()
                    .map(|a| format!(" appProtocol={}", a))
                    .unwrap_or_default();
                if name_str.is_empty() {
                    println!("      Port: {}/{}{}", port_str, ep_port.protocol, app_proto);
                } else {
                    println!(
                        "      Port: {} {}/{}{}",
                        name_str, port_str, ep_port.protocol, app_proto
                    );
                }
            }
            for ep in &es_info.endpoints {
                let addrs = ep.addresses.join(", ");
                let ready_str = match ep.conditions_ready {
                    Some(true) => "ready",
                    Some(false) => "not-ready",
                    None => "unknown(ready)",
                };
                let serving_str = match ep.conditions_serving {
                    Some(true) => " serving",
                    Some(false) => " not-serving",
                    None => "",
                };
                let term_str = match ep.conditions_terminating {
                    Some(true) => " terminating",
                    _ => "",
                };
                let target = ep
                    .target_ref
                    .as_ref()
                    .map(|tr| {
                        let kind = tr.kind.as_deref().unwrap_or("?");
                        let name = tr.name.as_deref().unwrap_or("?");
                        format!(" \u{2192} {}/{}", kind, name)
                    })
                    .unwrap_or_default();
                let mut meta_parts = Vec::new();
                if let Some(h) = &ep.hostname {
                    meta_parts.push(format!("host={}", h));
                }
                if let Some(n) = &ep.node_name {
                    meta_parts.push(format!("node={}", n));
                }
                if let Some(z) = &ep.zone {
                    meta_parts.push(format!("zone={}", z));
                }
                let meta_str = if meta_parts.is_empty() {
                    String::new()
                } else {
                    format!(" {}", meta_parts.join(" "))
                };
                let hints_str = ep
                    .hints
                    .as_ref()
                    .map(|h| {
                        if h.is_empty() {
                            String::new()
                        } else {
                            format!(" zones={}", h.join(","))
                        }
                    })
                    .unwrap_or_default();
                println!(
                    "      {} [{}{}{}]{}{}{}",
                    addrs, ready_str, serving_str, term_str, target, meta_str, hints_str
                );
            }
        }
        for ing in &path.ingresses {
            println!();
            if stdout_tty {
                println!(
                    "    \x1b[1m{}/{}\x1b[0m \u{2192} Service/{}",
                    ing.kind, ing.name, svc.name
                );
            } else {
                println!(
                    "    {}/{} \u{2192} Service/{}",
                    ing.kind, ing.name, svc.name
                );
            }
            if let Some(host) = &ing.host {
                println!("      Host: {}", host);
            }
            if let Some(p) = &ing.path {
                println!("      Path: {}", p);
            }
            if let Some(tls) = &ing.tls {
                println!("      TLS:  {}", tls);
            }
        }
        // Gateway API routes
        if let Some(gw_routes) = gateway_results.get(gw_idx) {
            for gr in gw_routes {
                println!();
                let cross_ns_str = match &gr.cross_namespace {
                    crate::analyzers::selector::CrossNamespaceStatus::SameNamespace => "",
                    crate::analyzers::selector::CrossNamespaceStatus::Allowed => {
                        " [cross-ns: allowed]"
                    }
                    crate::analyzers::selector::CrossNamespaceStatus::NotAllowed => {
                        " [cross-ns: not-allowed]"
                    }
                    crate::analyzers::selector::CrossNamespaceStatus::Unknown => {
                        " [cross-ns: unknown]"
                    }
                };
                let gw_class_str = match (&gr.gateway_class_name, &gr.gateway_class_controller) {
                    (Some(name), Some(ctrl)) => {
                        format!(" (GatewayClass/{}, controller: {})", name, ctrl)
                    }
                    (Some(name), None) => format!(" (GatewayClass/{})", name),
                    (None, Some(ctrl)) => format!(" (controller: {})", ctrl),
                    (None, None) => String::new(),
                };
                let section_str = gr
                    .section_name
                    .as_deref()
                    .map(|sn| format!(" section={}", sn))
                    .unwrap_or_default();
                if stdout_tty {
                    println!(
                        "    \x1b[1m{}/{}\x1b[0m via Gateway/{}{}{}{} \u{2192} Service/{}",
                        gr.route_kind,
                        gr.route_name,
                        gr.gateway_name,
                        gw_class_str,
                        section_str,
                        cross_ns_str,
                        svc.name
                    );
                } else {
                    println!(
                        "    {}/{} via Gateway/{}{}{}{} \u{2192} Service/{}",
                        gr.route_kind,
                        gr.route_name,
                        gr.gateway_name,
                        gw_class_str,
                        section_str,
                        cross_ns_str,
                        svc.name
                    );
                }
                if !gr.hostnames.is_empty() {
                    println!("      Hostnames: {}", gr.hostnames.join(", "));
                }
                for listener in &gr.listeners {
                    let hostname = listener
                        .hostname
                        .as_deref()
                        .map(|h| format!(" hostname={}", h))
                        .unwrap_or_default();
                    let tls = listener
                        .tls_mode
                        .as_deref()
                        .map(|t| format!(" tls={}", t))
                        .unwrap_or_default();
                    println!(
                        "      Listener: {} port={}/{}{}{}",
                        listener.name, listener.port, listener.protocol, hostname, tls
                    );
                }
                for mb in &gr.matched_backends {
                    let mut backend_info = Vec::new();
                    if let Some(p) = mb.port {
                        backend_info.push(format!("port {}", p));
                    }
                    if let Some(w) = mb.weight {
                        backend_info.push(format!("weight {}", w));
                    }
                    if !backend_info.is_empty() {
                        println!("      Backend: {}", backend_info.join(", "));
                    }
                    for m in &mb.rule_matches {
                        let path_str = match (&m.path_type, &m.path_value) {
                            (Some(pt), Some(pv)) => format!("{} {}", pt, pv),
                            (None, Some(pv)) => pv.clone(),
                            _ => continue,
                        };
                        let method_str = m
                            .method
                            .as_deref()
                            .map(|meth| format!(" method={}", meth))
                            .unwrap_or_default();
                        println!("        Match: {}{}", path_str, method_str);
                    }
                }
                for c in &gr.status_conditions {
                    let reason = c
                        .reason
                        .as_deref()
                        .map(|r| format!(" ({})", r))
                        .unwrap_or_default();
                    println!("      Status: {}={}{}", c.condition_type, c.status, reason);
                }
                for w in &gr.warnings {
                    println!("      [!] {}", w);
                }
            }
        }
        gw_idx += 1;
        println!();
    }
    if !postures.is_empty() {
        println!("Network Policy posture for {}/{}:\n", kind, name);
        for posture in postures {
            if stdout_tty {
                println!("  \x1b[1mPod/{}\x1b[0m", posture.pod_name);
            } else {
                println!("  Pod/{}", posture.pod_name);
            }
            println!("    Ingress: {}", posture.ingress_isolation);
            println!("    Egress:  {}", posture.egress_isolation);
            for ap in &posture.applicable_policies {
                if stdout_tty {
                    println!("    \x1b[1mNetworkPolicy/{}\x1b[0m", ap.name);
                } else {
                    println!("    NetworkPolicy/{}", ap.name);
                }
                println!("      Types: {}", ap.policy_types.join(", "));
                println!("      Selector: {}", format_selector(&ap.pod_selector));
                let mut effects = Vec::new();
                if ap.isolates_ingress {
                    effects.push("isolates ingress");
                }
                if ap.isolates_egress {
                    effects.push("isolates egress");
                }
                println!("      Effect: {}", effects.join("; "));
                for rule in &ap.ingress_rules {
                    let peers_str = format_policy_peers(&rule.peers);
                    let ports_str = format_policy_ports(&rule.ports);
                    print!("      Allows ingress:");
                    if !peers_str.is_empty() {
                        print!(" from: {}", peers_str);
                    }
                    if !ports_str.is_empty() {
                        print!(" ports: {}", ports_str);
                    }
                    if peers_str.is_empty() && ports_str.is_empty() {
                        print!(" (all)");
                    }
                    println!();
                }
                for rule in &ap.egress_rules {
                    let peers_str = format_policy_peers(&rule.peers);
                    let ports_str = format_policy_ports(&rule.ports);
                    print!("      Allows egress:");
                    if !peers_str.is_empty() {
                        print!(" to: {}", peers_str);
                    }
                    if !ports_str.is_empty() {
                        print!(" ports: {}", ports_str);
                    }
                    if peers_str.is_empty() && ports_str.is_empty() {
                        print!(" (all)");
                    }
                    println!();
                }
                if ap.isolates_ingress && ap.ingress_rules.is_empty() {
                    println!("      (no ingress allow rules \u{2192} deny all ingress)");
                }
                if ap.isolates_egress && ap.egress_rules.is_empty() {
                    println!("      (no egress allow rules \u{2192} deny all egress)");
                }
            }
        }
        println!();
    }
}

pub(crate) async fn handle_network(
    client: &::kube::Client,
    config: &::kube::config::Config,
    resource: String,
    online: crate::cli::OnlineOpts,
) -> anyhow::Result<()> {
    let namespace = online
        .namespace
        .unwrap_or_else(|| config.default_namespace.clone());

    let (kind_input, name) = if let Some((k, n)) = resource.split_once('/') {
        (k.to_string(), n.to_string())
    } else {
        bail!("Resource must be in kind/name format (e.g. deployment/nginx)");
    };

    let t0 = Instant::now();
    eprintln!("🔍 Discovering API resources...");
    let (kind_map, gvr_map, gk_map, _) =
        build_kind_lookup_cached(client, config, online.refresh_discovery).await?;
    eprintln!("   Discovery: {:.1}s", t0.elapsed().as_secs_f64());

    let (kind, target_group) = resolve_kind_with_group(&kind_input, &kind_map, &gvr_map)?;

    const NETWORK_SUPPORTED_KINDS: &[&str] = &[
        "Pod",
        "Deployment",
        "ReplicaSet",
        "StatefulSet",
        "DaemonSet",
        "Service",
    ];
    if !NETWORK_SUPPORTED_KINDS.iter().any(|k| *k == kind) {
        bail!(
            "network subcommand requires Pod, Deployment, ReplicaSet, StatefulSet, DaemonSet, or Service, got {}",
            kind
        );
    }

    let (index, mut scan_warnings) = scan_namespace_with_extra_apis(
        client,
        &namespace,
        &kind_map,
        &gk_map,
        &target_group,
        &kind,
        false,
        true,
        false,
    )
    .await?;

    let inventory = build_network_inventory(client, &namespace, &kind_map, &gk_map).await;

    let group_for_lookup = Some(target_group.as_str()).filter(|g| !g.is_empty());

    // For Service target: build path directly from inventory using pure helper
    let (all_paths, postures): (Vec<(String, _)>, Vec<_>) = if kind == "Service" {
        let target_svc = inventory.services.iter().find(|s| s.name == name);
        let Some(target_svc) = target_svc else {
            bail!("Service/{} not found in namespace '{}'", name, namespace);
        };
        let (path, pod_labels_list) =
            build_service_network_path(target_svc, &inventory, &index.by_uid, &namespace);
        let postures = evaluate_network_postures(
            &pod_labels_list,
            &inventory.network_policies,
            &inventory.np_availability,
        );
        (vec![(String::new(), path)], postures)
    } else {
        // For workload targets: find target uid and descendant pods
        let target_uid =
            match index.lookup_by_kind_name(group_for_lookup, &kind, &name, Some(&namespace)) {
                Some(uid) => uid.clone(),
                None => {
                    if online.strict && !scan_warnings.is_empty() {
                        eprintln!(
                            "Error: {}/{} not found in namespace '{}' (scan was incomplete)",
                            kind, name, namespace
                        );
                        std::process::exit(2);
                    }
                    bail!("{}/{} not found in namespace '{}'", kind, name, namespace);
                }
            };

        let pod_labels_list = if kind == "Pod" {
            vec![(
                name.clone(),
                target_uid.clone(),
                index
                    .by_uid
                    .get(&target_uid)
                    .map(|info| info.labels.clone())
                    .unwrap_or_default(),
            )]
        } else {
            super::tree::find_descendant_pods(&target_uid, &index)
        };

        let paths = find_network_paths(&pod_labels_list, &namespace, &inventory);
        let postures = evaluate_network_postures(
            &pod_labels_list,
            &inventory.network_policies,
            &inventory.np_availability,
        );
        let result_paths: Vec<_> = paths.into_iter().map(|p| (String::new(), p)).collect();
        (result_paths, postures)
    };

    // Resolve MetalLB for each service path (events fetched once in inventory)
    let metallb_results: Vec<crate::analyzers::selector::MetalLBResult> = {
        let mut seen = std::collections::HashSet::new();
        let unique_paths: Vec<_> = all_paths
            .iter()
            .filter(|(_, p)| seen.insert(p.service.name.clone()))
            .collect();
        let mut results = Vec::new();
        for (_, p) in &unique_paths {
            let endpoint_nodes: Vec<String> = p
                .endpoint_slices
                .iter()
                .flat_map(|es| es.endpoints.iter())
                .filter(|ep| ep.conditions_ready == Some(true))
                .filter_map(|ep| ep.node_name.clone())
                .collect::<std::collections::HashSet<_>>()
                .into_iter()
                .collect();
            results.push(crate::analyzers::selector::resolve_metallb_for_service(
                &p.service,
                &namespace,
                &inventory.metallb,
                &endpoint_nodes,
                &inventory.metallb.namespace_labels,
                &inventory.metallb.node_labels,
            ));
        }
        results
    };

    // Resolve Gateway API routes per service
    let gateway_results: Vec<Vec<crate::analyzers::selector::MatchedGatewayRoute>> = {
        let mut seen = std::collections::HashSet::new();
        let mut results = Vec::new();
        for (_, p) in &all_paths {
            if !seen.insert(p.service.name.clone()) {
                continue;
            }
            results.push(
                crate::analyzers::selector::resolve_gateway_routes_for_service(
                    &p.service.name,
                    &namespace,
                    &inventory.gateway,
                ),
            );
        }
        results
    };

    // Merge inventory warnings
    let existing_keys: std::collections::HashSet<String> =
        scan_warnings.iter().map(|w| format!("{}", w)).collect();
    for w in &inventory.warnings {
        if !existing_keys.contains(&format!("{}", w)) {
            scan_warnings.push(w.clone());
        }
    }

    match online.output {
        OutputFormat::Json => {
            let json_paths = network_paths_to_json(&all_paths, &metallb_results, &gateway_results);
            let json_postures = network_postures_to_json(&postures);
            let json_warnings: Vec<serde_json::Value> = scan_warnings
                .iter()
                .map(|w| {
                    serde_json::to_value(w).unwrap_or_else(|_| serde_json::json!(w.to_string()))
                })
                .collect();
            let output = serde_json::json!({
                "namespace": namespace,
                "target": format!("{}/{}", kind, name),
                "scope": "namespace",
                "networkPaths": json_paths,
                "networkPolicyPostures": json_postures,
                "warnings": json_warnings,
                "scanWarningCount": scan_warnings.len(),
            });
            println!(
                "{}",
                serde_json::to_string_pretty(&output).unwrap_or_default()
            );
        }
        OutputFormat::Table => {
            let mut table = comfy_table::Table::new();
            table.set_header(vec![
                "Service",
                "Type",
                "ClusterIP",
                "Ports",
                "Endpoints",
                "LB Provider",
                "Pool",
                "Advertisement",
                "Observed",
                "Session",
                "Events",
                "Config",
                "Ingress/Route",
                "Gateway Routes",
                "Warnings",
            ]);
            let mut seen_svcs = std::collections::HashSet::new();
            let mut mlb_idx = 0usize;
            let mut gw_idx = 0usize;
            for (_, path) in &all_paths {
                if !seen_svcs.insert(path.service.name.clone()) {
                    continue;
                }
                let svc = &path.service;
                let ports_str: String = svc
                    .ports
                    .iter()
                    .map(|sp| {
                        if let Some(np) = sp.node_port {
                            format!("{}/{} (np:{})", sp.port, sp.protocol, np)
                        } else {
                            format!("{}/{}", sp.port, sp.protocol)
                        }
                    })
                    .collect::<Vec<_>>()
                    .join(", ");
                let es = &path.endpoint_summary;
                let eps_str = format!("{} ready, {} not-ready", es.effective_ready, es.not_ready);
                let ing_str: String = path
                    .ingresses
                    .iter()
                    .map(|i| format!("{}/{}", i.kind, i.name))
                    .collect::<Vec<_>>()
                    .join(", ");
                let lb_provider = metallb_results
                    .get(mlb_idx)
                    .and_then(|r| r.provider.as_deref())
                    .unwrap_or("-")
                    .to_string();
                mlb_idx += 1;
                let mlb = metallb_results.get(mlb_idx.saturating_sub(1));
                let pool_str = mlb
                    .map(|r| {
                        r.pools
                            .iter()
                            .map(|p| p.pool.name.clone())
                            .collect::<Vec<_>>()
                            .join(", ")
                    })
                    .unwrap_or_default();
                let ad_str = mlb
                    .map(|r| {
                        r.advertisements
                            .iter()
                            .map(|a| format!("{}/{}", a.kind, a.name))
                            .collect::<Vec<_>>()
                            .join(", ")
                    })
                    .unwrap_or_default();
                let warn_str = mlb
                    .map(|r| {
                        if r.warnings.is_empty() {
                            String::new()
                        } else {
                            format!("{} warning(s)", r.warnings.len())
                        }
                    })
                    .unwrap_or_default();
                let observed_str = mlb
                    .map(|r| r.observation.observed_state.clone())
                    .unwrap_or_default();
                let session_str = mlb
                    .map(|r| {
                        if r.observation.session_state.is_empty() {
                            "-".to_string()
                        } else {
                            r.observation.session_state.clone()
                        }
                    })
                    .unwrap_or_else(|| "-".to_string());
                let events_str = mlb
                    .map(|r| {
                        if r.observation.events.is_empty() {
                            "-".to_string()
                        } else {
                            format!("{}", r.observation.events.len())
                        }
                    })
                    .unwrap_or_else(|| "-".to_string());
                let config_str = mlb
                    .map(|r| {
                        r.observation
                            .configuration_states
                            .first()
                            .and_then(|cs| cs.result.clone())
                            .unwrap_or_else(|| "-".to_string())
                    })
                    .unwrap_or_else(|| "-".to_string());
                // Gateway Routes column
                let gw = gateway_results.get(gw_idx).cloned().unwrap_or_default();
                gw_idx += 1;
                let not_allowed_count = gw
                    .iter()
                    .filter(|gr| {
                        gr.cross_namespace
                            == crate::analyzers::selector::CrossNamespaceStatus::NotAllowed
                    })
                    .count();
                let gw_str = if gw.is_empty() {
                    String::new()
                } else if not_allowed_count > 0 {
                    format!("{} ({} not-allowed)", gw.len(), not_allowed_count)
                } else {
                    format!("{}", gw.len())
                };
                // Append gateway warnings to warn_str
                let gw_warn_count: usize = gw.iter().map(|gr| gr.warnings.len()).sum();
                let combined_warn = if !warn_str.is_empty() && gw_warn_count > 0 {
                    format!("{}, {} gw-warning(s)", warn_str, gw_warn_count)
                } else if gw_warn_count > 0 {
                    format!("{} gw-warning(s)", gw_warn_count)
                } else {
                    warn_str
                };
                table.add_row(vec![
                    format!("Service/{}", svc.name),
                    svc.svc_type.clone(),
                    svc.cluster_ip.clone(),
                    ports_str,
                    eps_str,
                    lb_provider,
                    pool_str,
                    ad_str,
                    observed_str,
                    session_str,
                    events_str,
                    config_str,
                    ing_str,
                    gw_str,
                    combined_warn,
                ]);
            }
            println!("{table}");

            if !postures.is_empty() {
                println!();
                let mut np_table = comfy_table::Table::new();
                np_table.set_header(vec!["Pod", "Ingress", "Egress", "Policies"]);
                for p in &postures {
                    let policies: String = p
                        .applicable_policies
                        .iter()
                        .map(|ap| ap.name.clone())
                        .collect::<Vec<_>>()
                        .join(", ");
                    np_table.add_row(vec![
                        format!("Pod/{}", p.pod_name),
                        p.ingress_isolation.clone(),
                        p.egress_isolation.clone(),
                        policies,
                    ]);
                }
                println!("{np_table}");
            }
        }
        OutputFormat::Tree => {
            print_network_tree(
                &kind,
                &name,
                &all_paths,
                &postures,
                &metallb_results,
                &gateway_results,
            );
        }
    }

    format_scan_warnings(&scan_warnings, online.verbose);

    if online.strict && !scan_warnings.is_empty() {
        std::process::exit(2);
    }
    Ok(())
}
