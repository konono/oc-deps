use std::collections::{HashMap, HashSet};

use anyhow::Result;
use kube::{
    Client,
    api::{Api, ApiResource, DynamicObject},
    core::GroupVersion,
};
use serde::{Deserialize, Serialize};

use crate::analyzers::olm::OperatorInstance;
use crate::kube::discovery::{GroupKindMap, GvrMap, KindMap};
use crate::kube::resource::{NamespaceIndex, ScanWarning};
use crate::kube::scanner::scan_namespace;
use crate::teardown::planner::discover_cr_instances;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum NamespaceEvidence {
    InstallNamespace,
    OperatorGroupTarget,
    OperatorGroupStatus,
    OwnedCrdInstance {
        crd: String,
    },
    LabelEvidence {
        key: String,
        value: String,
    },
    SpecNamespaceRef {
        source_kind: String,
        source_name: String,
        field: String,
    },
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CandidateNamespace {
    pub namespace: String,
    pub evidence: Vec<NamespaceEvidence>,
}

#[allow(dead_code)]
pub struct NamespaceScopeResult {
    pub candidates: Vec<CandidateNamespace>,
    pub is_all_namespaces: bool,
    pub info_messages: Vec<String>,
    pub scan_failures: Vec<ScanWarning>,
}

pub async fn discover_operator_namespaces(
    client: &Client,
    operator: &OperatorInstance,
    kind_map: &KindMap,
    gvr_map: &GvrMap,
    gk_map: &GroupKindMap,
) -> Result<NamespaceScopeResult> {
    let mut ns_evidence: HashMap<String, Vec<NamespaceEvidence>> = HashMap::new();
    let mut info_messages = Vec::new();
    let mut scan_failures: Vec<ScanWarning> = Vec::new();
    let mut is_all_namespaces = false;

    // 1. Install namespace (always included)
    ns_evidence
        .entry(operator.install_namespace.clone())
        .or_default()
        .push(NamespaceEvidence::InstallNamespace);

    // 2. OperatorGroup in install namespace
    let og_result =
        discover_operator_group_targets(client, &operator.install_namespace, kind_map).await;
    match og_result {
        Ok(OgTargets::Specific(namespaces, source)) => {
            for ns in namespaces {
                let ev = match source {
                    OgSource::Status => NamespaceEvidence::OperatorGroupStatus,
                    OgSource::Spec => NamespaceEvidence::OperatorGroupTarget,
                };
                ns_evidence.entry(ns).or_default().push(ev);
            }
        }
        Ok(OgTargets::AllNamespaces) => {
            is_all_namespaces = true;
        }
        Err(warning) => {
            scan_failures.push(warning);
        }
    }

    // 3. Owned CRD instances — discover which namespaces they live in
    if !operator.owned_crds.is_empty() {
        let cr_report = discover_cr_instances(client, &operator.owned_crds, gvr_map, gk_map).await;
        scan_failures.extend(cr_report.unavailable_crds);
        for cr in &cr_report.instances {
            if let Some(ns) = &cr.id.namespace {
                ns_evidence.entry(ns.clone()).or_default().push(
                    NamespaceEvidence::OwnedCrdInstance {
                        crd: cr.id.kind.clone(),
                    },
                );
            }
        }
    }

    // 3b. Typed spec namespace references — scan CR instance specs for namespace fields
    if !operator.owned_crds.is_empty() {
        let (spec_ns, spec_failures) =
            discover_spec_namespace_refs(client, &operator.owned_crds, gvr_map, gk_map).await;
        scan_failures.extend(spec_failures);
        for (ns, source_kind, source_name, field) in spec_ns {
            ns_evidence
                .entry(ns)
                .or_default()
                .push(NamespaceEvidence::SpecNamespaceRef {
                    source_kind,
                    source_name,
                    field,
                });
        }
    }

    // 4. Label evidence — discover namespaces from related CRD instances with matching labels
    let (label_pairs, seed_errors) =
        crate::teardown::planner::compute_part_of_seeds(&operator.owned_crds, kind_map, client)
            .await;
    scan_failures.extend(seed_errors);
    if !label_pairs.is_empty() {
        let owned_crd_set: HashSet<&str> = operator.owned_crds.iter().map(|s| s.as_str()).collect();
        let related_report = crate::teardown::planner::discover_related_crd_instances(
            client,
            &owned_crd_set,
            &label_pairs,
            kind_map,
            gvr_map,
            gk_map,
        )
        .await;
        scan_failures.extend(related_report.unavailable_crds);
        for cr in &related_report.instances {
            if let Some(ns) = &cr.id.namespace
                && !ns_evidence.contains_key(ns)
            {
                let label_desc = cr
                    .decisive_label_pairs
                    .first()
                    .map(|(k, v)| (k.clone(), v.clone()))
                    .unwrap_or_default();
                ns_evidence
                    .entry(ns.clone())
                    .or_default()
                    .push(NamespaceEvidence::LabelEvidence {
                        key: label_desc.0,
                        value: label_desc.1,
                    });
            }
        }
    }

    let candidates: Vec<CandidateNamespace> = ns_evidence
        .into_iter()
        .map(|(namespace, evidence)| CandidateNamespace {
            namespace,
            evidence,
        })
        .collect();

    if is_all_namespaces {
        info_messages.push(
            "AllNamespaces operator: showing namespaces discovered from owned CRD \
             instances, spec namespace references, and label evidence. Resources \
             in undiscovered namespaces may not be included."
                .to_string(),
        );
    }

    Ok(NamespaceScopeResult {
        candidates,
        is_all_namespaces,
        info_messages,
        scan_failures,
    })
}

async fn discover_spec_namespace_refs(
    client: &Client,
    target_crds: &[String],
    gvr_map: &crate::kube::discovery::GvrMap,
    gk_map: &crate::kube::discovery::GroupKindMap,
) -> (Vec<(String, String, String, String)>, Vec<ScanWarning>) {
    let mut results = Vec::new();
    let mut failures = Vec::new();

    for crd_name in target_crds {
        let (plural, group) = match crd_name.split_once('.') {
            Some((p, g)) => (p, g),
            None => continue,
        };

        let gvr_key = format!("{}.{}", plural, group).to_lowercase();
        let kind = match gvr_map.get(&gvr_key) {
            Some(k) => k.clone(),
            None => continue,
        };

        let kind_info = match gk_map.get(&(group.to_string(), kind.clone())) {
            Some(i) => i,
            None => continue,
        };

        let gvk = GroupVersion::gv(&kind_info.group, &kind_info.version).with_kind(&kind);
        let ar = ApiResource::from_gvk_with_plural(&gvk, &kind_info.plural);
        let api: Api<DynamicObject> = Api::all_with(client.clone(), &ar);

        let items = match crate::teardown::planner::list_paginated_with_retry(
            &api,
            &kind_info.group,
            &kind_info.version,
            &kind_info.plural,
        )
        .await
        {
            Ok(items) => items,
            Err(w) => {
                failures.push(w);
                continue;
            }
        };

        for item in &items {
            let item_name = item.metadata.name.as_deref().unwrap_or("").to_string();
            if let Some(spec) = item.data.get("spec") {
                extract_namespace_fields(spec, "", &kind, &item_name, &mut results);
            }
        }
    }

    // Dedup by (namespace, source_kind, source_name, field)
    let mut seen = std::collections::HashSet::new();
    results.retain(|entry| seen.insert(entry.clone()));

    (results, failures)
}

fn extract_namespace_fields(
    value: &serde_json::Value,
    path: &str,
    source_kind: &str,
    source_name: &str,
    results: &mut Vec<(String, String, String, String)>,
) {
    match value {
        serde_json::Value::Object(map) => {
            for (key, val) in map {
                let field_path = if path.is_empty() {
                    key.clone()
                } else {
                    format!("{}.{}", path, key)
                };
                let key_lower = key.to_lowercase();
                let is_negative = key_lower.contains("excluded")
                    || key_lower.contains("exclude")
                    || key_lower.contains("ignored")
                    || key_lower.contains("ignore");
                if !is_negative
                    && (key_lower.ends_with("namespace") || key_lower.ends_with("namespaces"))
                    && !key_lower.contains("install")
                {
                    match val {
                        serde_json::Value::String(ns) if !ns.is_empty() => {
                            results.push((
                                ns.clone(),
                                source_kind.to_string(),
                                source_name.to_string(),
                                field_path.clone(),
                            ));
                        }
                        serde_json::Value::Array(arr) => {
                            for v in arr {
                                if let serde_json::Value::String(ns) = v
                                    && !ns.is_empty()
                                {
                                    results.push((
                                        ns.clone(),
                                        source_kind.to_string(),
                                        source_name.to_string(),
                                        field_path.clone(),
                                    ));
                                }
                            }
                        }
                        _ => {}
                    }
                }
                extract_namespace_fields(val, &field_path, source_kind, source_name, results);
            }
        }
        serde_json::Value::Array(arr) => {
            for (i, val) in arr.iter().enumerate() {
                let field_path = format!("{}[{}]", path, i);
                extract_namespace_fields(val, &field_path, source_kind, source_name, results);
            }
        }
        _ => {}
    }
}

enum OgSource {
    Status,
    Spec,
}

enum OgTargets {
    Specific(Vec<String>, OgSource),
    AllNamespaces,
}

async fn discover_operator_group_targets(
    client: &Client,
    install_namespace: &str,
    _kind_map: &KindMap,
) -> std::result::Result<OgTargets, ScanWarning> {
    let og_gvk = GroupVersion::gv("operators.coreos.com", "v1").with_kind("OperatorGroup");
    let og_ar = ApiResource::from_gvk_with_plural(&og_gvk, "operatorgroups");
    let og_api: Api<DynamicObject> =
        Api::namespaced_with(client.clone(), install_namespace, &og_ar);

    let og_items = crate::teardown::planner::list_paginated_with_retry(
        &og_api,
        "operators.coreos.com",
        "v1",
        "operatorgroups",
    )
    .await?;

    for og in &og_items {
        // Priority 1: status.namespaces
        if let Some(namespaces) = og
            .data
            .get("status")
            .and_then(|s| s.get("namespaces"))
            .and_then(|n| n.as_array())
        {
            let ns_list: Vec<String> = namespaces
                .iter()
                .filter_map(|v| v.as_str().map(|s| s.to_string()))
                .collect();
            if ns_list.is_empty() {
                return Ok(OgTargets::AllNamespaces);
            }
            if ns_list.len() == 1 && ns_list[0].is_empty() {
                return Ok(OgTargets::AllNamespaces);
            }
            return Ok(OgTargets::Specific(ns_list, OgSource::Status));
        }

        // Priority 2: spec.targetNamespaces
        if let Some(spec) = og.data.get("spec") {
            if let Some(target_ns) = spec.get("targetNamespaces").and_then(|n| n.as_array()) {
                let ns_list: Vec<String> = target_ns
                    .iter()
                    .filter_map(|v| v.as_str().map(|s| s.to_string()))
                    .collect();
                if ns_list.is_empty() {
                    return Ok(OgTargets::AllNamespaces);
                }
                return Ok(OgTargets::Specific(ns_list, OgSource::Spec));
            }
            // No targetNamespaces field → AllNamespaces
            return Ok(OgTargets::AllNamespaces);
        }
    }

    // No OperatorGroup found — treat as install-namespace only
    Ok(OgTargets::Specific(vec![], OgSource::Status))
}

#[allow(dead_code)]
pub struct MultiNamespaceScanResult {
    pub index: NamespaceIndex,
    pub scan_warnings: Vec<ScanWarning>,
    pub namespace_warnings: Vec<String>,
    pub scanned_namespaces: Vec<String>,
    pub failed_namespaces: Vec<(String, String)>,
}

pub async fn scan_candidate_namespaces(
    client: &Client,
    candidates: &[CandidateNamespace],
    kind_map: &KindMap,
    already_scanned: Option<&str>,
) -> MultiNamespaceScanResult {
    let mut combined_index = NamespaceIndex::new();
    let mut all_scan_warnings = Vec::new();
    let mut namespace_warnings = Vec::new();
    let mut scanned = Vec::new();
    let mut failed = Vec::new();

    let mut seen = HashSet::new();
    if let Some(ns) = already_scanned {
        seen.insert(ns.to_string());
    }

    let namespaces_to_scan: Vec<&str> = candidates
        .iter()
        .filter(|c| seen.insert(c.namespace.clone()))
        .map(|c| c.namespace.as_str())
        .collect();

    if namespaces_to_scan.is_empty() {
        return MultiNamespaceScanResult {
            index: combined_index,
            scan_warnings: all_scan_warnings,
            namespace_warnings,
            scanned_namespaces: scanned,
            failed_namespaces: failed,
        };
    }

    let total_ns = namespaces_to_scan.len();
    eprintln!("🔍 Scanning {} additional namespace(s)...", total_ns);

    let t0 = std::time::Instant::now();
    for (i, ns) in namespaces_to_scan.iter().enumerate() {
        let elapsed = t0.elapsed().as_secs();
        eprintln!(
            "[namespace {}/{}: {}] elapsed {}s",
            i + 1,
            total_ns,
            ns,
            elapsed
        );
        let result = scan_namespace(client, ns, kind_map, false, true, false).await;
        match result {
            Ok((index, warnings)) => {
                let resource_count = index.by_uid.len();
                all_scan_warnings.extend(warnings);
                combined_index.merge(index);
                scanned.push(ns.to_string());
                eprintln!("   {} — {} resources", ns, resource_count);
            }
            Err(e) => {
                let msg = format!("Namespace {} scan failed: {}", ns, e);
                eprintln!("   \x1b[33m⚠ {}\x1b[0m", msg);
                namespace_warnings.push(msg);
                failed.push((ns.to_string(), e.to_string()));
            }
        }
    }

    MultiNamespaceScanResult {
        index: combined_index,
        scan_warnings: all_scan_warnings,
        namespace_warnings,
        scanned_namespaces: scanned,
        failed_namespaces: failed,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_namespace_field() {
        let spec = serde_json::json!({
            "registriesNamespace": "rhoai-model-registries",
            "name": "default"
        });
        let mut results = Vec::new();
        extract_namespace_fields(&spec, "", "ModelRegistry", "default", &mut results);
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].0, "rhoai-model-registries");
        assert_eq!(results[0].1, "ModelRegistry");
        assert_eq!(results[0].3, "registriesNamespace");
    }

    #[test]
    fn test_extract_nested_namespace() {
        let spec = serde_json::json!({
            "components": {
                "workbenches": {
                    "workbenchNamespace": "rhods-notebooks"
                }
            }
        });
        let mut results = Vec::new();
        extract_namespace_fields(&spec, "", "DSC", "default-dsc", &mut results);
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].0, "rhods-notebooks");
        assert_eq!(results[0].3, "components.workbenches.workbenchNamespace");
    }

    #[test]
    fn test_extract_namespace_array() {
        let spec = serde_json::json!({
            "targetNamespaces": ["ns-a", "ns-b"]
        });
        let mut results = Vec::new();
        extract_namespace_fields(&spec, "", "OG", "og1", &mut results);
        assert_eq!(results.len(), 2);
        assert_eq!(results[0].0, "ns-a");
        assert_eq!(results[1].0, "ns-b");
    }

    #[test]
    fn test_excluded_namespace_fields_skipped() {
        let spec = serde_json::json!({
            "targetNamespace": "good-ns",
            "excludedNamespaces": ["bad-ns-1", "bad-ns-2"],
            "excludeNamespace": "bad-ns-3",
            "ignoredNamespaces": ["bad-ns-4"],
            "ignoreNamespace": "bad-ns-5"
        });
        let mut results = Vec::new();
        extract_namespace_fields(&spec, "", "Widget", "w1", &mut results);
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].0, "good-ns");
    }

    #[test]
    fn test_empty_namespace_skipped() {
        let spec = serde_json::json!({
            "targetNamespace": "",
            "otherNamespace": "valid-ns"
        });
        let mut results = Vec::new();
        extract_namespace_fields(&spec, "", "Widget", "w1", &mut results);
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].0, "valid-ns");
    }

    #[test]
    fn test_dedup_spec_namespace_refs() {
        let mut results = vec![
            (
                "ns-a".to_string(),
                "DSC".to_string(),
                "default".to_string(),
                "field1".to_string(),
            ),
            (
                "ns-a".to_string(),
                "DSC".to_string(),
                "default".to_string(),
                "field1".to_string(),
            ),
            (
                "ns-b".to_string(),
                "DSC".to_string(),
                "default".to_string(),
                "field2".to_string(),
            ),
        ];
        let mut seen = std::collections::HashSet::new();
        results.retain(|r| seen.insert(r.clone()));
        assert_eq!(results.len(), 2);
    }
}
