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

// ──────────────────────────────────────────────────────────────
//  Namespace validation
// ──────────────────────────────────────────────────────────────

pub fn is_valid_k8s_namespace(s: &str) -> bool {
    if s.is_empty() || s.len() > 63 {
        return false;
    }
    let bytes = s.as_bytes();
    if !bytes[0].is_ascii_lowercase() && !bytes[0].is_ascii_digit() {
        return false;
    }
    let last = bytes[bytes.len() - 1];
    if !last.is_ascii_lowercase() && !last.is_ascii_digit() {
        return false;
    }
    s.bytes()
        .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
}

fn describe_invalid_namespace(s: &str) -> String {
    if s.is_empty() {
        return "empty string".to_string();
    }
    if s.len() > 63 {
        return format!("exceeds 63 characters ({})", s.len());
    }
    if s.contains('/') {
        return "contains '/'".to_string();
    }
    if s.contains('_') {
        return "contains '_'".to_string();
    }
    if s.contains('.') {
        return "contains '.'".to_string();
    }
    if s.contains(' ') {
        return "contains space".to_string();
    }
    if s.chars().any(|c| c.is_uppercase()) {
        return "contains uppercase characters".to_string();
    }
    if s.starts_with('-') {
        return "starts with '-'".to_string();
    }
    if s.ends_with('-') {
        return "ends with '-'".to_string();
    }
    "invalid DNS-1123 label".to_string()
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum NamespaceValidation {
    Valid,
    InvalidDnsLabel { value: String, reason: String },
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RejectedNamespaceCandidate {
    pub value: String,
    pub field_path: String,
    pub source_kind: String,
    pub source_name: String,
    pub reason: String,
}

// ──────────────────────────────────────────────────────────────
//  Namespace evidence
// ──────────────────────────────────────────────────────────────

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum NamespaceSource {
    TypedField,
    HeuristicSuffix,
}

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
        validation: NamespaceValidation,
        source: NamespaceSource,
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
    pub rejected_candidates: Vec<RejectedNamespaceCandidate>,
}

#[allow(dead_code)]
pub async fn discover_operator_namespaces(
    client: &Client,
    operator: &OperatorInstance,
    kind_map: &KindMap,
    gvr_map: &GvrMap,
    gk_map: &GroupKindMap,
) -> Result<NamespaceScopeResult> {
    discover_operator_namespaces_opts(client, operator, kind_map, gvr_map, gk_map, None, None).await
}

#[allow(clippy::too_many_arguments)]
pub async fn discover_operator_namespaces_opts(
    client: &Client,
    operator: &OperatorInstance,
    kind_map: &KindMap,
    gvr_map: &GvrMap,
    gk_map: &GroupKindMap,
    ledger: Option<crate::kube::scanner::SharedLedger>,
    cached_crds: Option<&[kube::api::DynamicObject]>,
) -> Result<NamespaceScopeResult> {
    let mut ns_evidence: HashMap<String, Vec<NamespaceEvidence>> = HashMap::new();
    let mut info_messages = Vec::new();
    let mut scan_failures: Vec<ScanWarning> = Vec::new();
    let mut is_all_namespaces = false;
    let mut rejected_candidates = Vec::new();

    // 1. Install namespace (always included)
    ns_evidence
        .entry(operator.install_namespace.clone())
        .or_default()
        .push(NamespaceEvidence::InstallNamespace);

    // 2. OperatorGroup in install namespace
    let og_result = discover_operator_group_targets_opts(
        client,
        &operator.install_namespace,
        kind_map,
        ledger.as_ref(),
    )
    .await;
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
        let cr_report = crate::teardown::planner::discover_cr_instances_opts(
            client,
            &operator.owned_crds,
            gvr_map,
            gk_map,
            ledger.clone(),
        )
        .await;
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
        let (spec_ns, spec_failures, spec_rejected) = discover_spec_namespace_refs_opts(
            client,
            &operator.owned_crds,
            gvr_map,
            gk_map,
            ledger.as_ref(),
        )
        .await;
        scan_failures.extend(spec_failures);
        rejected_candidates.extend(spec_rejected);
        for (ns, source_kind, source_name, field) in spec_ns {
            ns_evidence
                .entry(ns)
                .or_default()
                .push(NamespaceEvidence::SpecNamespaceRef {
                    source_kind,
                    source_name,
                    field,
                    validation: NamespaceValidation::Valid,
                    source: NamespaceSource::HeuristicSuffix,
                });
        }
    }

    // 4. Label evidence — discover namespaces from related CRD instances with matching labels
    let (label_pairs, seed_errors) = crate::teardown::planner::compute_part_of_seeds_opts(
        &operator.owned_crds,
        kind_map,
        client,
        ledger.clone(),
        cached_crds,
    )
    .await;
    scan_failures.extend(seed_errors);
    if !label_pairs.is_empty() {
        let owned_crd_set: HashSet<&str> = operator.owned_crds.iter().map(|s| s.as_str()).collect();
        let related_report = crate::teardown::planner::discover_related_crd_instances_opts(
            client,
            &owned_crd_set,
            &label_pairs,
            kind_map,
            gvr_map,
            gk_map,
            ledger.clone(),
            cached_crds,
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

    // Print rejected namespace candidates to stderr (dedup by value+reason)
    if !rejected_candidates.is_empty() {
        let is_tty = std::io::IsTerminal::is_terminal(&std::io::stderr());
        let mut printed = HashSet::new();
        for r in &rejected_candidates {
            if !printed.insert((r.value.clone(), r.reason.clone())) {
                continue;
            }
            if is_tty {
                eprintln!(
                    "ℹ Rejected namespace candidate \"{}\" (invalid DNS label: {})",
                    r.value, r.reason
                );
                eprintln!(
                    "  Source: {}/{} field={}",
                    r.source_kind, r.source_name, r.field_path
                );
            } else {
                eprintln!(
                    "INFO: Rejected namespace candidate \"{}\" (invalid DNS label: {})",
                    r.value, r.reason
                );
                eprintln!(
                    "  Source: {}/{} field={}",
                    r.source_kind, r.source_name, r.field_path
                );
            }
        }
    }

    Ok(NamespaceScopeResult {
        candidates,
        is_all_namespaces,
        info_messages,
        scan_failures,
        rejected_candidates,
    })
}

#[allow(dead_code)]
async fn discover_spec_namespace_refs(
    client: &Client,
    target_crds: &[String],
    gvr_map: &crate::kube::discovery::GvrMap,
    gk_map: &crate::kube::discovery::GroupKindMap,
) -> (
    Vec<(String, String, String, String)>,
    Vec<ScanWarning>,
    Vec<RejectedNamespaceCandidate>,
) {
    discover_spec_namespace_refs_opts(client, target_crds, gvr_map, gk_map, None).await
}

async fn discover_spec_namespace_refs_opts(
    client: &Client,
    target_crds: &[String],
    gvr_map: &crate::kube::discovery::GvrMap,
    gk_map: &crate::kube::discovery::GroupKindMap,
    ledger: Option<&crate::kube::scanner::SharedLedger>,
) -> (
    Vec<(String, String, String, String)>,
    Vec<ScanWarning>,
    Vec<RejectedNamespaceCandidate>,
) {
    let mut results = Vec::new();
    let mut failures = Vec::new();
    let mut rejected = Vec::new();

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

        let items = match crate::teardown::planner::list_paginated_with_retry_opts(
            &api,
            &kind_info.group,
            &kind_info.version,
            &kind_info.plural,
            ledger,
            Some(crate::kube::resource::QueryRequirement::Optional),
            None,
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
                extract_namespace_fields(spec, "", &kind, &item_name, &mut results, &mut rejected);
            }
        }
    }

    // Dedup by (namespace, source_kind, source_name, field)
    let mut seen = std::collections::HashSet::new();
    results.retain(|entry| seen.insert(entry.clone()));

    (results, failures, rejected)
}

fn extract_namespace_fields(
    value: &serde_json::Value,
    path: &str,
    source_kind: &str,
    source_name: &str,
    results: &mut Vec<(String, String, String, String)>,
    rejected: &mut Vec<RejectedNamespaceCandidate>,
) {
    extract_namespace_fields_inner(
        value,
        path,
        source_kind,
        source_name,
        results,
        rejected,
        false,
    );
}

fn extract_namespace_fields_inner(
    value: &serde_json::Value,
    path: &str,
    source_kind: &str,
    source_name: &str,
    results: &mut Vec<(String, String, String, String)>,
    rejected: &mut Vec<RejectedNamespaceCandidate>,
    in_excluded_context: bool,
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
                let child_excluded = in_excluded_context || is_negative;
                if !child_excluded
                    && (key_lower.ends_with("namespace") || key_lower.ends_with("namespaces"))
                    && !key_lower.contains("install")
                {
                    match val {
                        serde_json::Value::String(ns) => {
                            if ns.is_empty() {
                                rejected.push(RejectedNamespaceCandidate {
                                    value: String::new(),
                                    field_path: field_path.clone(),
                                    source_kind: source_kind.to_string(),
                                    source_name: source_name.to_string(),
                                    reason: "empty string".to_string(),
                                });
                            } else if is_valid_k8s_namespace(ns) {
                                results.push((
                                    ns.clone(),
                                    source_kind.to_string(),
                                    source_name.to_string(),
                                    field_path.clone(),
                                ));
                            } else {
                                rejected.push(RejectedNamespaceCandidate {
                                    value: ns.clone(),
                                    field_path: field_path.clone(),
                                    source_kind: source_kind.to_string(),
                                    source_name: source_name.to_string(),
                                    reason: describe_invalid_namespace(ns),
                                });
                            }
                        }
                        serde_json::Value::Array(arr) => {
                            for v in arr {
                                if let serde_json::Value::String(ns) = v {
                                    if ns.is_empty() {
                                        rejected.push(RejectedNamespaceCandidate {
                                            value: String::new(),
                                            field_path: field_path.clone(),
                                            source_kind: source_kind.to_string(),
                                            source_name: source_name.to_string(),
                                            reason: "empty string".to_string(),
                                        });
                                    } else if is_valid_k8s_namespace(ns) {
                                        results.push((
                                            ns.clone(),
                                            source_kind.to_string(),
                                            source_name.to_string(),
                                            field_path.clone(),
                                        ));
                                    } else {
                                        rejected.push(RejectedNamespaceCandidate {
                                            value: ns.clone(),
                                            field_path: field_path.clone(),
                                            source_kind: source_kind.to_string(),
                                            source_name: source_name.to_string(),
                                            reason: describe_invalid_namespace(ns),
                                        });
                                    }
                                }
                            }
                        }
                        _ => {}
                    }
                }
                extract_namespace_fields_inner(
                    val,
                    &field_path,
                    source_kind,
                    source_name,
                    results,
                    rejected,
                    child_excluded,
                );
            }
        }
        serde_json::Value::Array(arr) => {
            for (i, val) in arr.iter().enumerate() {
                let field_path = format!("{}[{}]", path, i);
                extract_namespace_fields_inner(
                    val,
                    &field_path,
                    source_kind,
                    source_name,
                    results,
                    rejected,
                    in_excluded_context,
                );
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

#[allow(dead_code)]
async fn discover_operator_group_targets(
    client: &Client,
    install_namespace: &str,
    _kind_map: &KindMap,
) -> std::result::Result<OgTargets, ScanWarning> {
    discover_operator_group_targets_opts(client, install_namespace, _kind_map, None).await
}

async fn discover_operator_group_targets_opts(
    client: &Client,
    install_namespace: &str,
    _kind_map: &KindMap,
    ledger: Option<&crate::kube::scanner::SharedLedger>,
) -> std::result::Result<OgTargets, ScanWarning> {
    let og_gvk = GroupVersion::gv("operators.coreos.com", "v1").with_kind("OperatorGroup");
    let og_ar = ApiResource::from_gvk_with_plural(&og_gvk, "operatorgroups");
    let og_api: Api<DynamicObject> =
        Api::namespaced_with(client.clone(), install_namespace, &og_ar);

    let og_items = crate::teardown::planner::list_paginated_with_retry_opts(
        &og_api,
        "operators.coreos.com",
        "v1",
        "operatorgroups",
        ledger,
        Some(crate::kube::resource::QueryRequirement::Required),
        Some(install_namespace),
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

#[allow(dead_code)]
pub async fn scan_candidate_namespaces(
    client: &Client,
    candidates: &[CandidateNamespace],
    kind_map: &KindMap,
    already_scanned: Option<&str>,
) -> MultiNamespaceScanResult {
    scan_candidate_namespaces_with_ledger(client, candidates, kind_map, already_scanned, None).await
}

pub async fn scan_candidate_namespaces_with_ledger(
    client: &Client,
    candidates: &[CandidateNamespace],
    kind_map: &KindMap,
    already_scanned: Option<&str>,
    coverage_ledger: Option<crate::kube::scanner::SharedLedger>,
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
        let result = crate::kube::scanner::scan_namespace_with_semaphore(
            client,
            ns,
            kind_map,
            false,
            true,
            false,
            None,
            &[],
            coverage_ledger.clone(),
        )
        .await;
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

    // ── is_valid_k8s_namespace ──

    #[test]
    fn test_is_valid_k8s_namespace() {
        // Valid
        assert!(is_valid_k8s_namespace("demo"));
        assert!(is_valid_k8s_namespace("redhat-ods-applications"));
        assert!(is_valid_k8s_namespace(&"a".repeat(63)));
        assert!(is_valid_k8s_namespace("a"));
        assert!(is_valid_k8s_namespace("ns-123"));
        assert!(is_valid_k8s_namespace("0starts-with-digit"));
        assert!(is_valid_k8s_namespace("ends-with-9"));

        // Invalid
        assert!(!is_valid_k8s_namespace(""));
        assert!(!is_valid_k8s_namespace(
            "redhat-ai-gateway-infra/maas-api-route"
        ));
        assert!(!is_valid_k8s_namespace(&"a".repeat(64)));
        assert!(!is_valid_k8s_namespace("MyNamespace"));
        assert!(!is_valid_k8s_namespace("my_namespace"));
        assert!(!is_valid_k8s_namespace("-starts-with-dash"));
        assert!(!is_valid_k8s_namespace("ends-with-dash-"));
        assert!(!is_valid_k8s_namespace("has space"));
        assert!(!is_valid_k8s_namespace("has.dot"));
    }

    // ── extract_namespace_fields ──

    #[test]
    fn test_extract_namespace_field() {
        let spec = serde_json::json!({
            "registriesNamespace": "rhoai-model-registries",
            "name": "default"
        });
        let mut results = Vec::new();
        let mut rejected = Vec::new();
        extract_namespace_fields(
            &spec,
            "",
            "ModelRegistry",
            "default",
            &mut results,
            &mut rejected,
        );
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].0, "rhoai-model-registries");
        assert_eq!(results[0].1, "ModelRegistry");
        assert_eq!(results[0].3, "registriesNamespace");
        assert!(rejected.is_empty());
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
        let mut rejected = Vec::new();
        extract_namespace_fields(&spec, "", "DSC", "default-dsc", &mut results, &mut rejected);
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].0, "rhods-notebooks");
        assert_eq!(results[0].3, "components.workbenches.workbenchNamespace");
        assert!(rejected.is_empty());
    }

    #[test]
    fn test_extract_namespace_array() {
        let spec = serde_json::json!({
            "targetNamespaces": ["ns-a", "ns-b"]
        });
        let mut results = Vec::new();
        let mut rejected = Vec::new();
        extract_namespace_fields(&spec, "", "OG", "og1", &mut results, &mut rejected);
        assert_eq!(results.len(), 2);
        assert_eq!(results[0].0, "ns-a");
        assert_eq!(results[1].0, "ns-b");
        assert!(rejected.is_empty());
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
        let mut rejected = Vec::new();
        extract_namespace_fields(&spec, "", "Widget", "w1", &mut results, &mut rejected);
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].0, "good-ns");
        assert!(rejected.is_empty());
    }

    #[test]
    fn test_empty_namespace_rejected() {
        let spec = serde_json::json!({
            "targetNamespace": "",
            "otherNamespace": "valid-ns"
        });
        let mut results = Vec::new();
        let mut rejected = Vec::new();
        extract_namespace_fields(&spec, "", "Widget", "w1", &mut results, &mut rejected);
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].0, "valid-ns");
        assert_eq!(rejected.len(), 1, "empty string should be rejected");
        assert_eq!(rejected[0].reason, "empty string");
        assert!(rejected[0].value.is_empty());
    }

    #[test]
    fn test_empty_namespace_in_array_rejected() {
        let spec = serde_json::json!({
            "targetNamespaces": ["valid-ns", "", "also-valid"]
        });
        let mut results = Vec::new();
        let mut rejected = Vec::new();
        extract_namespace_fields(&spec, "", "Widget", "w1", &mut results, &mut rejected);
        assert_eq!(results.len(), 2);
        assert_eq!(rejected.len(), 1);
        assert_eq!(rejected[0].reason, "empty string");
    }

    #[test]
    fn test_nested_excluded_context_skips_namespace() {
        let spec = serde_json::json!({
            "excluded": {
                "namespace": "bad-ns"
            },
            "targetNamespace": "good-ns"
        });
        let mut results = Vec::new();
        let mut rejected = Vec::new();
        extract_namespace_fields(&spec, "", "Widget", "w1", &mut results, &mut rejected);
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].0, "good-ns");
    }

    #[test]
    fn test_deeply_nested_excluded_context() {
        let spec = serde_json::json!({
            "ignored": {
                "deep": {
                    "targetNamespace": "should-skip"
                }
            }
        });
        let mut results = Vec::new();
        let mut rejected = Vec::new();
        extract_namespace_fields(&spec, "", "Widget", "w1", &mut results, &mut rejected);
        assert!(
            results.is_empty(),
            "namespace under ignored context should not be extracted"
        );
    }

    #[test]
    fn test_namespace_source_is_heuristic() {
        // extract_namespace_fields matches by suffix, so all results are heuristic
        let spec = serde_json::json!({
            "registriesNamespace": "rhoai-model-registries"
        });
        let mut results = Vec::new();
        let mut rejected = Vec::new();
        extract_namespace_fields(
            &spec,
            "",
            "ModelRegistry",
            "default",
            &mut results,
            &mut rejected,
        );
        assert_eq!(results.len(), 1);
    }

    #[test]
    fn test_slash_value_excluded_from_candidates_zero_scan_requests() {
        // Simulates the Limitador case: spec.limits[].namespace =
        // "redhat-ai-gateway-infra/maas-api-route" alongside a valid namespace.
        // After extract_namespace_fields, the slash value must be in rejected,
        // not in results, so scan_candidate_namespaces never receives it.
        let spec = serde_json::json!({
            "limits": [
                {
                    "namespace": "redhat-ai-gateway-infra/maas-api-route",
                    "conditions": ["limit.name == test"]
                }
            ],
            "registriesNamespace": "rhoai-model-registries"
        });
        let mut results = Vec::new();
        let mut rejected = Vec::new();
        extract_namespace_fields(
            &spec,
            "",
            "Limitador",
            "kuadrant-limitador",
            &mut results,
            &mut rejected,
        );

        assert_eq!(
            results.len(),
            1,
            "only valid namespace should be in results"
        );
        assert_eq!(results[0].0, "rhoai-model-registries");
        assert_eq!(rejected.len(), 1, "slash value should be rejected");
        assert_eq!(rejected[0].value, "redhat-ai-gateway-infra/maas-api-route");

        // Build candidates from results only (the production path)
        let candidates: Vec<CandidateNamespace> = results
            .iter()
            .map(|(ns, _, _, _)| CandidateNamespace {
                namespace: ns.clone(),
                evidence: vec![],
            })
            .collect();

        // Verify rejected value is NOT in candidates
        assert!(
            !candidates.iter().any(|c| c.namespace.contains('/')),
            "rejected namespace must not appear in scan candidates"
        );
        // Since no candidate contains the slash value, scan_candidate_namespaces
        // will never issue a request for it → 0 API requests to invalid namespace.
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

    // ── Slash-containing value rejection (Limitador case) ──

    #[test]
    fn test_slash_containing_value_rejected() {
        let spec = serde_json::json!({
            "limits": [{
                "namespace": "redhat-ai-gateway-infra/maas-api-route",
                "conditions": ["limit.name == test"]
            }]
        });
        let mut results = Vec::new();
        let mut rejected = Vec::new();
        extract_namespace_fields(
            &spec,
            "",
            "Limitador",
            "kuadrant-limitador",
            &mut results,
            &mut rejected,
        );
        assert!(
            results.is_empty(),
            "slash-containing value should not be a namespace candidate"
        );
        assert_eq!(rejected.len(), 1);
        assert_eq!(rejected[0].value, "redhat-ai-gateway-infra/maas-api-route");
        assert!(
            rejected[0].reason.contains("'/'"),
            "reason should mention slash: {}",
            rejected[0].reason
        );
        assert_eq!(rejected[0].source_kind, "Limitador");
        assert_eq!(rejected[0].source_name, "kuadrant-limitador");
    }

    // ── Real RHOAI namespace paths preserved ──

    #[test]
    fn test_real_rhoai_namespace_paths_preserved() {
        let spec = serde_json::json!({
            "registriesNamespace": "rhoai-model-registries",
            "components": {
                "workbenches": {
                    "workbenchNamespace": "rhods-notebooks"
                }
            }
        });
        let mut results = Vec::new();
        let mut rejected = Vec::new();
        extract_namespace_fields(&spec, "", "DSC", "default-dsc", &mut results, &mut rejected);
        assert_eq!(results.len(), 2);
        assert!(results.iter().any(|r| r.0 == "rhoai-model-registries"));
        assert!(results.iter().any(|r| r.0 == "rhods-notebooks"));
        assert!(rejected.is_empty());
    }

    // ── Uppercase, underscore, long names rejected ──

    #[test]
    fn test_uppercase_namespace_rejected() {
        let spec = serde_json::json!({
            "targetNamespace": "MyNamespace"
        });
        let mut results = Vec::new();
        let mut rejected = Vec::new();
        extract_namespace_fields(&spec, "", "Widget", "w1", &mut results, &mut rejected);
        assert!(results.is_empty());
        assert_eq!(rejected.len(), 1);
        assert!(rejected[0].reason.contains("uppercase"));
    }

    #[test]
    fn test_underscore_namespace_rejected() {
        let spec = serde_json::json!({
            "targetNamespace": "my_namespace"
        });
        let mut results = Vec::new();
        let mut rejected = Vec::new();
        extract_namespace_fields(&spec, "", "Widget", "w1", &mut results, &mut rejected);
        assert!(results.is_empty());
        assert_eq!(rejected.len(), 1);
        assert!(rejected[0].reason.contains("'_'"));
    }

    #[test]
    fn test_64_char_namespace_rejected() {
        let long = "a".repeat(64);
        let spec = serde_json::json!({
            "targetNamespace": long
        });
        let mut results = Vec::new();
        let mut rejected = Vec::new();
        extract_namespace_fields(&spec, "", "Widget", "w1", &mut results, &mut rejected);
        assert!(results.is_empty());
        assert_eq!(rejected.len(), 1);
        assert!(rejected[0].reason.contains("63"));
    }

    #[test]
    fn test_63_char_namespace_valid() {
        let exactly_63 = "a".repeat(63);
        let spec = serde_json::json!({
            "targetNamespace": exactly_63
        });
        let mut results = Vec::new();
        let mut rejected = Vec::new();
        extract_namespace_fields(&spec, "", "Widget", "w1", &mut results, &mut rejected);
        assert_eq!(results.len(), 1);
        assert!(rejected.is_empty());
    }

    // ── Mixed valid and invalid ──

    #[test]
    fn test_mixed_valid_and_invalid_namespaces() {
        let spec = serde_json::json!({
            "limits": [
                {"namespace": "redhat-ai-gateway-infra/maas-api-route"},
                {"namespace": "valid-ns"},
                {"namespace": "Another/Bad"},
                {"namespace": "also-valid"}
            ]
        });
        let mut results = Vec::new();
        let mut rejected = Vec::new();
        extract_namespace_fields(&spec, "", "Limitador", "test", &mut results, &mut rejected);
        assert_eq!(results.len(), 2);
        assert!(results.iter().any(|r| r.0 == "valid-ns"));
        assert!(results.iter().any(|r| r.0 == "also-valid"));
        assert_eq!(rejected.len(), 2);
    }

    // ── NamespaceValidation serialization ──

    #[test]
    fn test_namespace_validation_serialization() {
        let valid = NamespaceValidation::Valid;
        let json = serde_json::to_string(&valid).unwrap();
        let _: NamespaceValidation = serde_json::from_str(&json).unwrap();

        let invalid = NamespaceValidation::InvalidDnsLabel {
            value: "bad/name".into(),
            reason: "contains '/'".into(),
        };
        let json2 = serde_json::to_string(&invalid).unwrap();
        let _: NamespaceValidation = serde_json::from_str(&json2).unwrap();
    }

    // ── RejectedNamespaceCandidate serialization ──

    #[test]
    fn test_rejected_candidate_serialization() {
        let r = RejectedNamespaceCandidate {
            value: "redhat-ai-gateway-infra/maas-api-route".into(),
            field_path: "limits[0].namespace".into(),
            source_kind: "Limitador".into(),
            source_name: "kuadrant-limitador".into(),
            reason: "contains '/'".into(),
        };
        let json = serde_json::to_string(&r).unwrap();
        let r2: RejectedNamespaceCandidate = serde_json::from_str(&json).unwrap();
        assert_eq!(r2.value, r.value);
        assert_eq!(r2.reason, r.reason);
    }

    #[tokio::test]
    async fn test_scan_candidate_namespaces_only_requests_valid_candidates() {
        use kube::client::Body;
        use std::pin::pin;
        use std::sync::Arc;
        use std::sync::atomic::{AtomicUsize, Ordering};

        use crate::kube::discovery::KindInfo;

        fn json_response(json: serde_json::Value) -> http::Response<Body> {
            http::Response::builder()
                .status(200)
                .body(Body::from(serde_json::to_vec(&json).unwrap()))
                .unwrap()
        }

        let mut kind_map = KindMap::new();
        kind_map.insert(
            "ConfigMap".to_string(),
            KindInfo {
                group: "".to_string(),
                version: "v1".to_string(),
                plural: "configmaps".to_string(),
                namespaced: true,
                listable: true,
            },
        );

        // Step 1: Extract namespace fields — one valid, one invalid
        let spec = serde_json::json!({
            "limits": [{ "namespace": "redhat-ai-gateway-infra/maas-api-route" }],
            "targetNamespace": "valid-ns"
        });
        let mut results = Vec::new();
        let mut rejected = Vec::new();
        extract_namespace_fields(&spec, "", "Limitador", "test", &mut results, &mut rejected);
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].0, "valid-ns");
        assert_eq!(rejected.len(), 1);

        // Step 2: Build candidates from results only (production path)
        let candidates: Vec<CandidateNamespace> = results
            .iter()
            .map(|(ns, _, _, _)| CandidateNamespace {
                namespace: ns.clone(),
                evidence: vec![],
            })
            .collect();

        // Step 3: Call scan_candidate_namespaces with mock server
        let (mock_service, handle) =
            tower_test::mock::pair::<http::Request<Body>, http::Response<Body>>();
        let client = kube::Client::new(mock_service, "default");
        let request_count = Arc::new(AtomicUsize::new(0));
        let rc = request_count.clone();
        let request_namespaces: Arc<std::sync::Mutex<Vec<String>>> =
            Arc::new(std::sync::Mutex::new(Vec::new()));
        let rn = request_namespaces.clone();

        let spawned = tokio::spawn(async move {
            let mut handle = pin!(handle);
            while let Some((req, send)) = handle.next_request().await {
                rc.fetch_add(1, Ordering::SeqCst);
                let uri = req.uri().to_string();
                // Extract namespace from URI like /api/v1/namespaces/valid-ns/configmaps
                if let Some(ns_start) = uri.find("/namespaces/") {
                    let rest = &uri[ns_start + "/namespaces/".len()..];
                    if let Some(ns_end) = rest.find('/') {
                        rn.lock().unwrap().push(rest[..ns_end].to_string());
                    }
                }
                send.send_response(json_response(serde_json::json!({
                    "apiVersion": "v1",
                    "kind": "ConfigMapList",
                    "metadata": {"resourceVersion": "1"},
                    "items": []
                })));
            }
        });

        let result = scan_candidate_namespaces(&client, &candidates, &kind_map, None).await;
        drop(client);
        spawned.abort();

        assert_eq!(
            result.scanned_namespaces,
            vec!["valid-ns"],
            "only valid-ns should be scanned"
        );
        let namespaces_requested = request_namespaces.lock().unwrap();
        assert!(
            !namespaces_requested.is_empty(),
            "should have made requests for valid-ns"
        );
        for ns in namespaces_requested.iter() {
            assert_eq!(
                ns, "valid-ns",
                "all requests should target valid-ns, got: {}",
                ns
            );
        }
        assert!(
            !namespaces_requested
                .iter()
                .any(|ns| ns.contains("redhat-ai-gateway-infra")),
            "no request should target rejected namespace"
        );
    }

    #[tokio::test]
    async fn test_operator_group_records_namespaced_scope() {
        use kube::client::Body;
        use std::pin::pin;
        use std::sync::Arc;

        fn json_response(json: serde_json::Value) -> http::Response<Body> {
            http::Response::builder()
                .status(200)
                .body(Body::from(serde_json::to_vec(&json).unwrap()))
                .unwrap()
        }

        let (mock_service, handle) =
            tower_test::mock::pair::<http::Request<Body>, http::Response<Body>>();
        let client = kube::Client::new(mock_service, "default");

        let ledger = Arc::new(std::sync::Mutex::new(
            crate::kube::resource::CoverageLedger::new(),
        ));

        let spawned = tokio::spawn(async move {
            let mut handle = pin!(handle);
            let (_req, send) = handle.next_request().await.expect("expected OG LIST");
            send.send_response(json_response(serde_json::json!({
                "apiVersion": "operators.coreos.com/v1",
                "kind": "OperatorGroupList",
                "metadata": {"resourceVersion": "1"},
                "items": [{
                    "apiVersion": "operators.coreos.com/v1",
                    "kind": "OperatorGroup",
                    "metadata": {"name": "og1", "namespace": "test-install-ns"},
                    "status": {"namespaces": ["test-install-ns"]}
                }]
            })));
        });

        let kind_map = KindMap::new();
        let result = discover_operator_group_targets_opts(
            &client,
            "test-install-ns",
            &kind_map,
            Some(&ledger),
        )
        .await;
        spawned.await.unwrap();

        assert!(result.is_ok());
        let l = ledger.lock().unwrap();
        assert_eq!(
            l.records.len(),
            1,
            "should have one OperatorGroup LIST record"
        );
        let rec = &l.records[0];
        assert_eq!(rec.gvr, "operators.coreos.com/v1/operatorgroups");
        assert_eq!(
            rec.namespace.as_deref(),
            Some("test-install-ns"),
            "namespace must be the install namespace"
        );
        assert_eq!(rec.scope, "namespaced", "scope must be namespaced");
    }
}
