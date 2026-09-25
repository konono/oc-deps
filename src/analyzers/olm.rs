use std::collections::{HashMap, HashSet};
use std::time::Duration;

use anyhow::Result;
use comfy_table::Table;
use kube::{
    Client,
    api::{Api, ApiResource, DynamicObject, ListParams},
    core::GroupVersion,
};
use serde::{Deserialize, Serialize};

use crate::cli::OutputFormat;
use crate::kube::discovery::{GroupKindMap, KindMap};
use crate::kube::resource::ResourceId;

// ──────────────────────────────────────────────────────────────
//  Operator Instance — structured OLM operator representation
// ──────────────────────────────────────────────────────────────

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct OperatorInstance {
    pub subscription: Option<ResourceId>,
    pub package_name: Option<String>,
    pub csv: ResourceId,
    pub csv_phase: String,
    pub owned_crds: Vec<String>,
    pub required_crds: Vec<String>,
    pub owned_api_service_defs: Vec<OwnedApiServiceDef>,
    pub required_api_service_defs: Vec<OwnedApiServiceDef>,
    pub deployments: Vec<String>,
    pub service_accounts: Vec<String>,
    pub install_namespace: String,
    /// True if Subscription(s) exist in the install namespace that could not
    /// be linked to this CSV. Indicates broken linkage, not absence.
    #[serde(default)]
    pub has_unlinked_subscriptions: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct OperatorId {
    pub namespace: String,
    pub csv_name: String,
}

impl std::fmt::Display for OperatorId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}@{}", self.csv_name, self.namespace)
    }
}

impl OperatorId {
    pub fn from_instance(op: &OperatorInstance) -> Self {
        Self {
            namespace: op.install_namespace.clone(),
            csv_name: op.csv.name.clone(),
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum DependencyVia {
    Crd(String),
    ApiService(String),
}

impl std::fmt::Display for DependencyVia {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DependencyVia::Crd(name) => write!(f, "CRD/{}", name),
            DependencyVia::ApiService(name) => write!(f, "APIService/{}", name),
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct OperatorDependency {
    pub from: OperatorId,
    pub to: OperatorId,
    pub via: DependencyVia,
    pub confidence: f64,
}

fn extract_crd_names(csv_data: &serde_json::Value, field: &str) -> Vec<String> {
    csv_data
        .get("spec")
        .and_then(|s| s.get("customresourcedefinitions"))
        .and_then(|c| c.get(field))
        .and_then(|o| o.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|item| item.get("name").and_then(|n| n.as_str()).map(String::from))
                .collect()
        })
        .unwrap_or_default()
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct OwnedApiServiceDef {
    pub name: String,
    pub group: String,
    pub version: String,
    pub kind: String,
    pub deployment_name: Option<String>,
}

impl OwnedApiServiceDef {
    pub fn api_service_object_name(&self) -> String {
        format!("{}.{}", self.version, self.group)
    }

    pub fn matches_gvk(&self, other: &OwnedApiServiceDef) -> bool {
        self.group == other.group && self.version == other.version && self.kind == other.kind
    }
}

fn extract_api_service_defs(csv_data: &serde_json::Value, field: &str) -> Vec<OwnedApiServiceDef> {
    csv_data
        .get("spec")
        .and_then(|s| s.get("apiservicedefinitions"))
        .and_then(|c| c.get(field))
        .and_then(|o| o.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|item| {
                    let name = item.get("name")?.as_str()?.to_string();
                    let group = item
                        .get("group")
                        .and_then(|g| g.as_str())
                        .unwrap_or("")
                        .to_string();
                    let version = item
                        .get("version")
                        .and_then(|v| v.as_str())
                        .unwrap_or("")
                        .to_string();
                    let kind = item
                        .get("kind")
                        .and_then(|k| k.as_str())
                        .unwrap_or("")
                        .to_string();
                    let deployment_name = item
                        .get("deploymentName")
                        .and_then(|d| d.as_str())
                        .map(String::from);
                    Some(OwnedApiServiceDef {
                        name,
                        group,
                        version,
                        kind,
                        deployment_name,
                    })
                })
                .collect()
        })
        .unwrap_or_default()
}

fn extract_deployment_names(csv_data: &serde_json::Value) -> Vec<String> {
    csv_data
        .get("spec")
        .and_then(|s| s.get("install"))
        .and_then(|i| i.get("spec"))
        .and_then(|s| s.get("deployments"))
        .and_then(|d| d.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|item| item.get("name").and_then(|n| n.as_str()).map(String::from))
                .collect()
        })
        .unwrap_or_default()
}

fn extract_service_account_names(csv_data: &serde_json::Value) -> Vec<String> {
    let mut sa_names = Vec::new();
    let perms_keys = ["clusterPermissions", "permissions"];

    if let Some(install_spec) = csv_data
        .get("spec")
        .and_then(|s| s.get("install"))
        .and_then(|i| i.get("spec"))
    {
        for key in &perms_keys {
            if let Some(arr) = install_spec.get(*key).and_then(|p| p.as_array()) {
                for perm in arr {
                    if let Some(sa) = perm
                        .get("serviceAccountName")
                        .and_then(|n| n.as_str())
                        .map(String::from)
                        && !sa_names.contains(&sa)
                    {
                        sa_names.push(sa);
                    }
                }
            }
        }
    }
    sa_names
}

/// Check if ALL package evidence on a CSV exclusively confirms a single package.
/// Returns true only when evidence is absent (trust status) OR unanimously
/// points to the expected package. Any contradictory evidence → false.
pub fn csv_package_evidence_is_exclusive(
    csv: &DynamicObject,
    expected_pkg: &str,
    csv_ns: &str,
) -> bool {
    let mut evidence_packages: HashSet<String> = HashSet::new();

    // Collect from labels: operators.coreos.com/<pkg>.<ns>
    if let Some(labels) = &csv.metadata.labels {
        let suffix = format!(".{}", csv_ns);
        for key in labels.keys() {
            if let Some(rest) = key.strip_prefix("operators.coreos.com/")
                && let Some(pkg) = rest.strip_suffix(&suffix)
                && !pkg.is_empty()
            {
                evidence_packages.insert(pkg.to_string());
            }
        }
    }

    // Collect from annotations
    for pkg in extract_annotation_packages(csv) {
        evidence_packages.insert(pkg);
    }

    if evidence_packages.is_empty() {
        // No evidence at all → trust status link
        return true;
    }

    // Evidence must exclusively point to the expected package
    evidence_packages.len() == 1 && evidence_packages.contains(expected_pkg)
}

pub fn extract_annotation_packages(csv: &DynamicObject) -> Vec<String> {
    let mut packages = Vec::new();
    let annotations = match csv.metadata.annotations.as_ref() {
        Some(a) => a,
        None => return packages,
    };
    if let Some(props_str) = annotations.get("operatorframework.io/properties") {
        let props: Vec<serde_json::Value> =
            if let Ok(arr) = serde_json::from_str::<Vec<serde_json::Value>>(props_str) {
                arr
            } else if let Ok(obj) = serde_json::from_str::<serde_json::Value>(props_str) {
                obj.get("properties")
                    .and_then(|p| p.as_array())
                    .cloned()
                    .unwrap_or_default()
            } else {
                Vec::new()
            };
        for prop in &props {
            if prop.get("type").and_then(|t| t.as_str()) == Some("olm.package")
                && let Some(value) = prop.get("value")
            {
                let pkg_value = if let Some(s) = value.as_str() {
                    serde_json::from_str::<serde_json::Value>(s).ok()
                } else {
                    Some(value.clone())
                };
                if let Some(pkg_info) = pkg_value
                    && let Some(name) = pkg_info.get("packageName").and_then(|n| n.as_str())
                    && !name.trim().is_empty()
                    && name == name.trim()
                    && !packages.contains(&name.to_string())
                {
                    packages.push(name.to_string());
                }
            }
        }
    }
    packages
}

const LIST_PAGE_SIZE: u32 = 500;
const LIST_MAX_ATTEMPTS: usize = 3;
const CANONICAL_CSV_LABEL_SELECTOR: &str = "!olm.copiedFrom";

fn is_transient_list_error(error: &kube::Error) -> bool {
    match error {
        kube::Error::Api(response) => {
            response.code == 408 || response.code == 429 || response.code >= 500
        }
        _ => true,
    }
}

async fn list_all_paginated(
    api: &Api<DynamicObject>,
    label_selector: Option<&str>,
    group: &str,
    version: &str,
    plural: &str,
) -> std::result::Result<Vec<DynamicObject>, crate::kube::resource::ScanWarning> {
    use crate::kube::resource::ScanWarning;

    let gvr = if group.is_empty() {
        format!("{}/{}", version, plural)
    } else {
        format!("{}/{}/{}", group, version, plural)
    };
    let is_tty = std::io::IsTerminal::is_terminal(&std::io::stderr());
    let mut all_items = Vec::new();
    let mut continue_token: Option<String> = None;

    loop {
        let mut lp = ListParams::default().limit(LIST_PAGE_SIZE);
        if let Some(selector) = label_selector {
            lp = lp.labels(selector);
        }
        if let Some(token) = &continue_token {
            lp = lp.continue_token(token);
        }

        let mut attempt = 1;
        let list = loop {
            let timeout_dur = Duration::from_secs(30);
            match tokio::time::timeout(timeout_dur, api.list(&lp)).await {
                Ok(Ok(list)) => break list,
                Ok(Err(error))
                    if attempt < LIST_MAX_ATTEMPTS && is_transient_list_error(&error) =>
                {
                    let delay = Duration::from_millis(250 * attempt as u64);
                    let msg = format!(
                        "{} LIST attempt {}/{} failed; retrying as {}/{} in {}ms",
                        gvr,
                        attempt,
                        LIST_MAX_ATTEMPTS,
                        attempt + 1,
                        LIST_MAX_ATTEMPTS,
                        delay.as_millis()
                    );
                    if is_tty {
                        eprintln!("   \x1b[33m⚠ {}\x1b[0m", msg);
                    } else {
                        eprintln!("   ⚠ {}", msg);
                    }
                    tokio::time::sleep(delay).await;
                    attempt += 1;
                }
                Ok(Err(error)) => {
                    let mut w = ScanWarning::from_kube_error(&error, group, version, plural);
                    w.set_retries(attempt - 1);
                    return Err(w);
                }
                Err(_elapsed) if attempt < LIST_MAX_ATTEMPTS => {
                    let delay = Duration::from_millis(250 * attempt as u64);
                    let msg = format!(
                        "{} LIST timeout (30s), attempt {}/{} failed; retrying as {}/{}",
                        gvr,
                        attempt,
                        LIST_MAX_ATTEMPTS,
                        attempt + 1,
                        LIST_MAX_ATTEMPTS
                    );
                    if is_tty {
                        eprintln!("   \x1b[33m⚠ {}\x1b[0m", msg);
                    } else {
                        eprintln!("   ⚠ {}", msg);
                    }
                    tokio::time::sleep(delay).await;
                    attempt += 1;
                }
                Err(_elapsed) => {
                    return Err(ScanWarning::Timeout {
                        gvr: gvr.clone(),
                        message: Some(format!(
                            "LIST timeout (30s) after {} attempts",
                            LIST_MAX_ATTEMPTS
                        )),
                        retries: attempt - 1,
                    });
                }
            }
        };
        let metadata = list.metadata;
        all_items.extend(list.items);

        match metadata.continue_.filter(|t| !t.is_empty()) {
            Some(token) => continue_token = Some(token),
            None => break,
        }
    }

    Ok(all_items)
}

pub async fn discover_operators(
    client: &Client,
    kind_map: &KindMap,
) -> Result<Vec<OperatorInstance>> {
    let csv_info = match kind_map.get("ClusterServiceVersion") {
        Some(info) => info.clone(),
        None => return Ok(vec![]),
    };

    let csv_gvk =
        GroupVersion::gv(&csv_info.group, &csv_info.version).with_kind("ClusterServiceVersion");
    let csv_ar = ApiResource::from_gvk_with_plural(&csv_gvk, &csv_info.plural);
    let csv_api: Api<DynamicObject> = Api::all_with(client.clone(), &csv_ar);

    let sub_gvk = GroupVersion::gv("operators.coreos.com", "v1alpha1").with_kind("Subscription");
    let sub_ar = ApiResource::from_gvk_with_plural(&sub_gvk, "subscriptions");
    let sub_api: Api<DynamicObject> = Api::all_with(client.clone(), &sub_ar);

    // AllNamespaces operators create copied CSVs in watched namespaces. They carry
    // olm.copiedFrom and duplicate the canonical CSV's large install strategy.
    // Exclude them server-side so discovery transfers only real installations.
    let (csv_result, sub_result) = tokio::join!(
        list_all_paginated(
            &csv_api,
            Some(CANONICAL_CSV_LABEL_SELECTOR),
            &csv_info.group,
            &csv_info.version,
            &csv_info.plural,
        ),
        list_all_paginated(
            &sub_api,
            None,
            "operators.coreos.com",
            "v1alpha1",
            "subscriptions",
        ),
    );
    let csv_items = csv_result.map_err(|w| anyhow::anyhow!("{}", w))?;
    let sub_items = sub_result.map_err(|w| anyhow::anyhow!("{}", w))?;

    // P1-2: key by (sub_namespace, csv_name) so same CSV name in different
    // namespaces via different Subscriptions produces separate installations
    let mut sub_by_csv: HashMap<String, Vec<&DynamicObject>> = HashMap::new();
    let mut matched_sub_uids: HashSet<String> = HashSet::new();
    for sub in &sub_items {
        let csv_name_from_status = sub.data.get("status").and_then(|s| {
            s.get("installedCSV")
                .and_then(|v| v.as_str())
                .filter(|s| !s.is_empty())
                .or_else(|| {
                    s.get("currentCSV")
                        .and_then(|v| v.as_str())
                        .filter(|s| !s.is_empty())
                })
        });
        if let Some(csv_name) = csv_name_from_status {
            let sub_ns = sub.metadata.namespace.as_deref().unwrap_or("unknown");
            let sub_pkg = sub
                .data
                .get("spec")
                .and_then(|s| s.get("name"))
                .and_then(|n| n.as_str());

            // Verify: CSV exists in same namespace AND package evidence is
            // exclusively consistent with the Subscription's package.
            let csv_exists_and_consistent = csv_items.iter().any(|csv| {
                let name_match = csv.metadata.name.as_deref() == Some(csv_name)
                    && csv.metadata.namespace.as_deref() == Some(sub_ns);
                if !name_match {
                    return false;
                }
                if let Some(pkg) = sub_pkg {
                    csv_package_evidence_is_exclusive(csv, pkg, sub_ns)
                } else {
                    true
                }
            });

            if csv_exists_and_consistent {
                if let Some(uid) = &sub.metadata.uid {
                    matched_sub_uids.insert(uid.clone());
                }
                sub_by_csv
                    .entry(csv_name.to_string())
                    .or_default()
                    .push(sub);
            }
            // If CSV doesn't exist in this namespace: stale status — fall through
            // to label fallback below
        }
    }

    // Label-based fallback: for Subscriptions not matched via status,
    // try CSV labels. OLM CSVs carry labels like:
    //   operators.coreos.com/<package>.<namespace> = ""
    // where <package> = Subscription.spec.name and <namespace> = Subscription namespace.
    for sub in &sub_items {
        let sub_uid = sub.metadata.uid.as_deref().unwrap_or("");
        if sub_uid.is_empty() || matched_sub_uids.contains(sub_uid) {
            continue;
        }

        let sub_ns = sub.metadata.namespace.as_deref().unwrap_or("unknown");
        let pkg_name = sub
            .data
            .get("spec")
            .and_then(|s| s.get("name"))
            .and_then(|n| n.as_str());

        if let Some(pkg) = pkg_name {
            let label_key = format!("operators.coreos.com/{}.{}", pkg, sub_ns);

            let mut matched_csvs: Vec<String> = Vec::new();
            for csv in &csv_items {
                if csv.metadata.namespace.as_deref() != Some(sub_ns) {
                    continue;
                }
                if let Some(labels) = &csv.metadata.labels
                    && labels.contains_key(&label_key)
                    && let Some(csv_name) = &csv.metadata.name
                {
                    matched_csvs.push(csv_name.clone());
                }
            }

            if matched_csvs.len() == 1 {
                // Verify annotation evidence doesn't contradict label link
                let csv_obj = csv_items.iter().find(|c| {
                    c.metadata.name.as_deref() == Some(&matched_csvs[0])
                        && c.metadata.namespace.as_deref() == Some(sub_ns)
                });
                if let Some(csv_obj) = csv_obj
                    && !csv_package_evidence_is_exclusive(csv_obj, pkg, sub_ns)
                {
                    continue;
                }
                sub_by_csv
                    .entry(matched_csvs[0].clone())
                    .or_default()
                    .push(sub);
            }
            // 0 or >1 matches: leave unmatched — will produce subscription=None
        }
    }

    // Deduplicate CSV copies: OLM copies CSVs into every target namespace.
    // Key: (subscription_namespace, csv_name) — different Subscriptions = different installations.
    // For each installation, prefer the CSV copy in the Subscription's namespace.
    // (csv_object, subscription_resource_id, package_name, csv_phase)
    #[allow(clippy::type_complexity)]
    let mut best_csv: HashMap<
        (String, String),
        (&DynamicObject, Option<ResourceId>, Option<String>, String),
    > = HashMap::new();

    for csv in &csv_items {
        let phase = csv
            .data
            .get("status")
            .and_then(|s| s.get("phase"))
            .and_then(|p| p.as_str())
            .unwrap_or("Unknown")
            .to_string();

        let csv_name = match &csv.metadata.name {
            Some(n) => n.clone(),
            None => continue,
        };
        let csv_ns = csv.metadata.namespace.as_deref().unwrap_or("unknown");

        // Find matching subscription(s) for this CSV name
        let matching_subs = sub_by_csv.get(&csv_name);

        if let Some(subs) = matching_subs {
            for sub in subs {
                let sub_ns = sub.metadata.namespace.as_deref().unwrap_or("unknown");
                let subscription = Some(ResourceId {
                    group: "operators.coreos.com".to_string(),
                    version: "v1alpha1".to_string(),
                    kind: "Subscription".to_string(),
                    namespace: sub.metadata.namespace.clone(),
                    name: sub.metadata.name.clone().unwrap_or_default(),
                    uid: sub.metadata.uid.clone(),
                });

                let pkg_name = sub
                    .data
                    .get("spec")
                    .and_then(|s| s.get("name"))
                    .and_then(|n| n.as_str())
                    .map(String::from);

                let key = (sub_ns.to_string(), csv_name.clone());
                let new_matches_sub_ns = csv_ns == sub_ns;

                let should_replace = if let Some((existing, _, _, _)) = best_csv.get(&key) {
                    let existing_ns = existing.metadata.namespace.as_deref().unwrap_or("unknown");
                    let existing_matches = existing_ns == sub_ns;
                    new_matches_sub_ns && !existing_matches
                } else {
                    true
                };

                if should_replace {
                    best_csv.insert(key, (csv, subscription, pkg_name, phase.clone()));
                }
            }
        } else {
            let key = (csv_ns.to_string(), csv_name.clone());
            best_csv
                .entry(key)
                .or_insert_with(|| (csv, None, None, phase.clone()));
        }
    }

    let mut operators = Vec::new();

    for ((_, csv_name), (csv, subscription, pkg_name, csv_phase)) in &best_csv {
        let csv_ns = csv
            .metadata
            .namespace
            .clone()
            .unwrap_or_else(|| "unknown".to_string());
        let csv_uid = csv.metadata.uid.clone();

        let owned_crds = extract_crd_names(&csv.data, "owned");
        let required_crds = extract_crd_names(&csv.data, "required");
        let owned_api_service_defs = extract_api_service_defs(&csv.data, "owned");
        let required_api_service_defs = extract_api_service_defs(&csv.data, "required");
        let deployments = extract_deployment_names(&csv.data);
        let service_accounts = extract_service_account_names(&csv.data);

        // Check for ambiguous Subscription linkage:
        // 1. Multiple Subs linked to this CSV via sub_by_csv
        // 2. No Sub linked but Subs exist in namespace
        // 3. Sub linked but same-package Subs exist that aren't accounted for
        let multiple_subs_for_csv = sub_by_csv
            .get(csv_name.as_str())
            .is_some_and(|subs| subs.len() > 1);

        let same_pkg_unaccounted_subs = if let Some(pkg) = pkg_name {
            // Count Subs in this namespace with same spec.name
            let same_pkg_count = sub_items
                .iter()
                .filter(|sub| {
                    sub.metadata.namespace.as_deref() == Some(csv_ns.as_str())
                        && sub
                            .data
                            .get("spec")
                            .and_then(|s| s.get("name"))
                            .and_then(|n| n.as_str())
                            == Some(pkg.as_str())
                })
                .count();
            // If more than 1 Sub has the same package name, we can't prove all are in Phase 0
            same_pkg_count > 1
        } else {
            false
        };

        let has_unlinked = multiple_subs_for_csv
            || same_pkg_unaccounted_subs
            || (subscription.is_none()
                && sub_items
                    .iter()
                    .any(|sub| sub.metadata.namespace.as_deref() == Some(csv_ns.as_str())));

        // Derive package_name: subscription > CSV annotation > None
        let effective_package_name = if pkg_name.is_some() {
            pkg_name.clone()
        } else {
            let annotation_pkgs = extract_annotation_packages(csv);
            if annotation_pkgs.len() == 1 {
                Some(annotation_pkgs[0].clone())
            } else {
                None
            }
        };

        operators.push(OperatorInstance {
            subscription: subscription.clone(),
            package_name: effective_package_name,
            csv: ResourceId {
                group: csv_info.group.clone(),
                version: csv_info.version.clone(),
                kind: "ClusterServiceVersion".to_string(),
                namespace: Some(csv_ns.clone()),
                name: csv_name.clone(),
                uid: csv_uid,
            },
            csv_phase: csv_phase.clone(),
            owned_crds,
            required_crds,
            owned_api_service_defs,
            required_api_service_defs,
            deployments,
            service_accounts,
            install_namespace: csv_ns,
            has_unlinked_subscriptions: has_unlinked,
        });
    }

    operators.sort_by(|a, b| a.csv.name.cmp(&b.csv.name));

    Ok(operators)
}

pub fn compute_operator_dependencies(operators: &[OperatorInstance]) -> Vec<OperatorDependency> {
    let mut deps = Vec::new();

    for requirer in operators {
        for required_crd in &requirer.required_crds {
            for provider in operators {
                if std::ptr::eq(requirer, provider) {
                    continue;
                }
                if provider.owned_crds.contains(required_crd) {
                    deps.push(OperatorDependency {
                        from: OperatorId::from_instance(requirer),
                        to: OperatorId::from_instance(provider),
                        via: DependencyVia::Crd(required_crd.clone()),
                        confidence: 1.0,
                    });
                }
            }
        }

        for req_def in &requirer.required_api_service_defs {
            for provider in operators {
                if std::ptr::eq(requirer, provider) {
                    continue;
                }
                if provider
                    .owned_api_service_defs
                    .iter()
                    .any(|owned| owned.matches_gvk(req_def))
                {
                    deps.push(OperatorDependency {
                        from: OperatorId::from_instance(requirer),
                        to: OperatorId::from_instance(provider),
                        via: DependencyVia::ApiService(req_def.api_service_object_name()),
                        confidence: 1.0,
                    });
                }
            }
        }
    }

    deps
}

pub fn print_operators(
    operators: &[OperatorInstance],
    deps: &[OperatorDependency],
    output: &OutputFormat,
) {
    match output {
        OutputFormat::Tree => print_operators_tree(operators, deps),
        OutputFormat::Table => print_operators_table(operators),
        OutputFormat::Json => print_operators_json(operators, deps),
    }
}

fn print_operators_tree(operators: &[OperatorInstance], deps: &[OperatorDependency]) {
    for (i, op) in operators.iter().enumerate() {
        if i > 0 {
            println!();
        }

        if let Some(sub) = &op.subscription {
            println!(
                "Subscription/{} (ns: {})",
                sub.name,
                sub.namespace.as_deref().unwrap_or("?")
            );
            println!("└─ CSV/{}", op.csv.name);
        } else {
            println!("CSV/{} (ns: {})", op.csv.name, op.install_namespace);
        }

        let prefix = if op.subscription.is_some() { "   " } else { "" };

        let api_svc_display: Vec<String> = op
            .owned_api_service_defs
            .iter()
            .map(|d| d.api_service_object_name())
            .collect();

        let sections: Vec<(&str, Vec<&str>)> = vec![
            (
                "owned CRDs",
                op.owned_crds.iter().map(|s| s.as_str()).collect(),
            ),
            (
                "required CRDs",
                op.required_crds.iter().map(|s| s.as_str()).collect(),
            ),
            (
                "APIServices",
                api_svc_display.iter().map(|s| s.as_str()).collect(),
            ),
            (
                "Deployments",
                op.deployments.iter().map(|s| s.as_str()).collect(),
            ),
            (
                "ServiceAccounts",
                op.service_accounts.iter().map(|s| s.as_str()).collect(),
            ),
        ];

        let non_empty: Vec<_> = sections
            .iter()
            .filter(|(_, items)| !items.is_empty())
            .collect();

        for (sec_idx, (label, items)) in non_empty.iter().enumerate() {
            let is_last_section = sec_idx == non_empty.len() - 1;
            let sec_connector = if is_last_section { "└─" } else { "├─" };
            println!("{}{}  {}:", prefix, sec_connector, label);

            let child_prefix = if is_last_section {
                format!("{}   ", prefix)
            } else {
                format!("{}│  ", prefix)
            };

            for (item_idx, item) in items.iter().enumerate() {
                let item_connector = if item_idx == items.len() - 1 {
                    "└─"
                } else {
                    "├─"
                };
                println!("{}{} {}", child_prefix, item_connector, item);
            }
        }
    }

    if !deps.is_empty() {
        println!("\n\x1b[1m── Operator Dependencies ──\x1b[0m\n");
        for dep in deps {
            println!(
                "  {} \x1b[33m→\x1b[0m {} (via {})",
                dep.from, dep.to, dep.via
            );
        }
    }
}

fn print_operators_table(operators: &[OperatorInstance]) {
    let mut table = Table::new();
    table.set_header(vec![
        "CSV",
        "Namespace",
        "Subscription",
        "Owned CRDs",
        "Required CRDs",
    ]);
    for op in operators {
        let sub_name = op
            .subscription
            .as_ref()
            .map(|s| s.name.as_str())
            .unwrap_or("-");
        table.add_row(vec![
            &op.csv.name,
            &op.install_namespace,
            sub_name,
            &format!("{}", op.owned_crds.len()),
            &format!("{}", op.required_crds.len()),
        ]);
    }
    println!("{table}");
}

fn print_operators_json(operators: &[OperatorInstance], deps: &[OperatorDependency]) {
    let output = serde_json::json!({
        "operators": operators,
        "dependencies": deps,
    });
    println!(
        "{}",
        serde_json::to_string_pretty(&output).unwrap_or_default()
    );
}

#[allow(dead_code)]
pub struct CrdOriginChain {
    pub crd_name: String,
    pub crd_labels: Vec<(String, String)>,
    pub csv_name: Option<String>,
    pub csv_namespace: Option<String>,
    pub csv_match_method: Option<String>,
    pub subscription_name: Option<String>,
    pub subscription_namespace: Option<String>,
}

#[allow(dead_code)]
pub async fn find_crd_origin(
    client: &Client,
    kind: &str,
    kind_map: &KindMap,
) -> Option<CrdOriginChain> {
    let kind_info = kind_map.get(kind)?;
    let crd_name = if kind_info.group.is_empty() {
        return None;
    } else {
        format!("{}.{}", kind_info.plural, kind_info.group)
    };

    let mut crd_labels = Vec::new();
    if let Some(crd_kind_info) = kind_map.get("CustomResourceDefinition") {
        let crd_gvk = GroupVersion::gv(&crd_kind_info.group, &crd_kind_info.version)
            .with_kind("CustomResourceDefinition");
        let crd_ar = ApiResource::from_gvk_with_plural(&crd_gvk, &crd_kind_info.plural);
        let crd_api: Api<DynamicObject> = Api::all_with(client.clone(), &crd_ar);
        if let Ok(crd_obj) = crd_api.get(&crd_name).await
            && let Some(labels) = &crd_obj.metadata.labels
        {
            for (k, v) in labels {
                if k.contains("part-of") || k.contains("managed-by") {
                    crd_labels.push((k.clone(), v.clone()));
                }
            }
        }
    }

    let csv_info = kind_map.get("ClusterServiceVersion")?;
    let csv_gvk =
        GroupVersion::gv(&csv_info.group, &csv_info.version).with_kind("ClusterServiceVersion");
    let csv_ar = ApiResource::from_gvk_with_plural(&csv_gvk, &csv_info.plural);
    let csv_api: Api<DynamicObject> = Api::all_with(client.clone(), &csv_ar);
    let csvs = csv_api.list(&ListParams::default()).await.ok()?;

    let mut found_csv_name = None;
    let mut found_csv_ns = None;
    let mut match_method = None;

    'owned: for csv in &csvs.items {
        let owned = csv
            .data
            .get("spec")
            .and_then(|s| s.get("customresourcedefinitions"))
            .and_then(|c| c.get("owned"))
            .and_then(|o| o.as_array());
        if let Some(owned_crds) = owned {
            for crd in owned_crds {
                if crd.get("name").and_then(|n| n.as_str()) == Some(crd_name.as_str()) {
                    found_csv_name = csv.metadata.name.clone();
                    found_csv_ns = csv.metadata.namespace.clone();
                    match_method = Some("owned CRD".to_string());
                    break 'owned;
                }
            }
        }
    }

    if found_csv_name.is_none() {
        let target_group = &kind_info.group;
        let target_resource = &kind_info.plural;

        'perms: for csv in &csvs.items {
            let perms = csv
                .data
                .get("spec")
                .and_then(|s| s.get("install"))
                .and_then(|i| i.get("spec"))
                .and_then(|s| s.get("clusterPermissions"))
                .and_then(|p| p.as_array());
            if let Some(perm_list) = perms {
                for perm in perm_list {
                    let rules = perm.get("rules").and_then(|r| r.as_array());
                    if let Some(rules) = rules {
                        for rule in rules {
                            let groups = rule
                                .get("apiGroups")
                                .and_then(|g| g.as_array())
                                .map(|a| a.iter().filter_map(|v| v.as_str()).collect::<Vec<_>>())
                                .unwrap_or_default();
                            let resources = rule
                                .get("resources")
                                .and_then(|r| r.as_array())
                                .map(|a| a.iter().filter_map(|v| v.as_str()).collect::<Vec<_>>())
                                .unwrap_or_default();

                            if groups.contains(&target_group.as_str())
                                && resources.contains(&target_resource.as_str())
                            {
                                found_csv_name = csv.metadata.name.clone();
                                found_csv_ns = csv.metadata.namespace.clone();
                                match_method = Some("clusterPermissions".to_string());
                                break 'perms;
                            }
                        }
                    }
                }
            }
        }
    }

    let mut chain = CrdOriginChain {
        crd_name,
        crd_labels,
        csv_name: found_csv_name.clone(),
        csv_namespace: found_csv_ns.clone(),
        csv_match_method: match_method,
        subscription_name: None,
        subscription_namespace: None,
    };

    if let Some(csv_name) = &found_csv_name {
        let sub_gvk =
            GroupVersion::gv("operators.coreos.com", "v1alpha1").with_kind("Subscription");
        let sub_ar = ApiResource::from_gvk_with_plural(&sub_gvk, "subscriptions");
        let sub_api: Api<DynamicObject> = Api::all_with(client.clone(), &sub_ar);
        {
            if let Ok(subs) = sub_api.list(&ListParams::default()).await {
                for sub in &subs.items {
                    let matched_csv = sub.data.get("status").and_then(|s| {
                        s.get("installedCSV")
                            .and_then(|v| v.as_str())
                            .filter(|s| !s.is_empty())
                            .or_else(|| {
                                s.get("currentCSV")
                                    .and_then(|v| v.as_str())
                                    .filter(|s| !s.is_empty())
                            })
                    });
                    if matched_csv == Some(csv_name.as_str()) {
                        chain.subscription_name = sub.metadata.name.clone();
                        chain.subscription_namespace = sub.metadata.namespace.clone();
                        break;
                    }
                }
            }
        }
    }

    Some(chain)
}

#[allow(dead_code)]
pub fn print_crd_origin(chain: &CrdOriginChain, kind: &str, output: &OutputFormat) {
    match output {
        OutputFormat::Tree => {
            let match_note = chain
                .csv_match_method
                .as_ref()
                .map(|m| format!(" (via {})", m))
                .unwrap_or_default();

            if let Some(sub) = &chain.subscription_name {
                let sub_ns = chain.subscription_namespace.as_deref().unwrap_or("unknown");
                println!("Subscription/{} (ns: {})", sub, sub_ns);
                if let Some(csv) = &chain.csv_name {
                    let csv_ns = chain.csv_namespace.as_deref().unwrap_or("unknown");
                    println!(
                        "└─ ClusterServiceVersion/{} (ns: {}){}",
                        csv, csv_ns, match_note
                    );
                    println!("   └─ CRD/{}", chain.crd_name);
                    println!("      └─ \x1b[1;32m{}/...\x1b[0m", kind);
                }
            } else if let Some(csv) = &chain.csv_name {
                let csv_ns = chain.csv_namespace.as_deref().unwrap_or("unknown");
                println!(
                    "ClusterServiceVersion/{} (ns: {}){}",
                    csv, csv_ns, match_note
                );
                println!("└─ CRD/{}", chain.crd_name);
                println!("   └─ \x1b[1;32m{}/...\x1b[0m", kind);
            } else {
                println!("CRD/{}", chain.crd_name);
                println!("└─ \x1b[1;32m{}/...\x1b[0m (no managing CSV found)", kind);
            }

            if !chain.crd_labels.is_empty() {
                println!();
                println!("📎 CRD labels:");
                for (k, v) in &chain.crd_labels {
                    println!("   {}: {}", k, v);
                }
            }
        }
        OutputFormat::Table => {
            let mut table = Table::new();
            table.set_header(vec!["Level", "Kind", "Name", "Namespace"]);
            if let Some(sub) = &chain.subscription_name {
                table.add_row(vec![
                    "Subscription",
                    "Subscription",
                    sub,
                    chain.subscription_namespace.as_deref().unwrap_or("-"),
                ]);
            }
            if let Some(csv) = &chain.csv_name {
                table.add_row(vec![
                    "CSV",
                    "ClusterServiceVersion",
                    csv,
                    chain.csv_namespace.as_deref().unwrap_or("-"),
                ]);
            }
            table.add_row(vec![
                "CRD",
                "CustomResourceDefinition",
                &chain.crd_name,
                "-",
            ]);
            table.add_row(vec!["Kind", kind, "*", "-"]);
            println!("{table}");
        }
        OutputFormat::Json => {
            let labels: HashMap<&str, &str> = chain
                .crd_labels
                .iter()
                .map(|(k, v)| (k.as_str(), v.as_str()))
                .collect();
            let output = serde_json::json!({
                "kind": kind,
                "crd": chain.crd_name,
                "crdLabels": labels,
                "csv": chain.csv_name,
                "csvNamespace": chain.csv_namespace,
                "csvMatchMethod": chain.csv_match_method,
                "subscription": chain.subscription_name,
                "subscriptionNamespace": chain.subscription_namespace,
            });
            println!(
                "{}",
                serde_json::to_string_pretty(&output).unwrap_or_default()
            );
        }
    }
}

// ──────────────────────────────────────────────────────────────
//  who-manages: resource → operator attribution
// ──────────────────────────────────────────────────────────────

#[derive(Clone, Debug)]
pub struct OwnershipStep {
    pub kind: String,
    pub name: String,
    pub namespace: Option<String>,
    pub group: String,
    pub relationship: String,
    pub evidence: String,
    pub confidence: String,
}

#[derive(Debug)]
pub struct WhoManagesError {
    pub message: String,
    pub scan_failure: Option<crate::kube::resource::ScanWarning>,
}

impl std::fmt::Display for WhoManagesError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.message)
    }
}

impl std::error::Error for WhoManagesError {}

impl From<anyhow::Error> for WhoManagesError {
    fn from(e: anyhow::Error) -> Self {
        WhoManagesError {
            message: format!("{}", e),
            scan_failure: None,
        }
    }
}

#[derive(Clone, Debug)]
pub struct WhoManagesResult {
    pub chain: Vec<OwnershipStep>,
    pub operator_name: Option<String>,
    pub package_name: Option<String>,
    pub install_namespace: Option<String>,
    pub confidence: String,
    pub warnings: Vec<String>,
    pub scan_failures: Vec<crate::kube::resource::ScanWarning>,
}

const LABEL_MANAGED_BY: &str = "app.kubernetes.io/managed-by";
const LABEL_PART_OF: &str = "app.kubernetes.io/part-of";

fn resolve_owner_group(oref: &crate::kube::resource::OwnerRef) -> String {
    match oref.api_version.rsplit_once('/') {
        Some((g, _)) => g.to_string(),
        None => String::new(),
    }
}

fn resolve_owner_kind_info<'a>(
    oref: &crate::kube::resource::OwnerRef,
    kind_map: &'a KindMap,
    gk_map: &'a GroupKindMap,
) -> Option<&'a crate::kube::discovery::KindInfo> {
    let owner_group = resolve_owner_group(oref);
    if !owner_group.is_empty() {
        return gk_map.get(&(owner_group, oref.kind.clone()));
    }
    kind_map.get(&oref.kind)
}

pub struct WhoManagesInput<'a> {
    pub client: &'a Client,
    pub kind: &'a str,
    pub group: &'a str,
    pub name: &'a str,
    pub namespace: &'a str,
    pub kind_map: &'a KindMap,
    pub gk_map: &'a GroupKindMap,
}

pub fn resolve_crd_name_for_root(
    trusted_root: &Option<(String, String)>,
    target_group: &str,
    kind: &str,
    gk_map: &GroupKindMap,
) -> Option<String> {
    let (root_group, root_kind) = trusted_root
        .clone()
        .unwrap_or_else(|| (target_group.to_string(), kind.to_string()));
    if root_group.is_empty() {
        return None;
    }
    let ki = gk_map.get(&(root_group.clone(), root_kind.clone()))?;
    Some(format!("{}.{}", ki.plural, ki.group))
}

pub fn infer_operator_from_labels(labels: &HashMap<String, String>) -> Option<(String, String)> {
    if let Some(v) = labels.get(LABEL_MANAGED_BY) {
        return Some((LABEL_MANAGED_BY.to_string(), v.clone()));
    }
    if let Some(v) = labels.get(LABEL_PART_OF) {
        return Some((LABEL_PART_OF.to_string(), v.clone()));
    }
    None
}

pub async fn who_manages(
    input: &WhoManagesInput<'_>,
) -> std::result::Result<WhoManagesResult, WhoManagesError> {
    let client = input.client;
    let kind = input.kind;
    let target_group = input.group;
    let name = input.name;
    let namespace = input.namespace;
    let kind_map = input.kind_map;
    let gk_map = input.gk_map;

    let mut steps: Vec<OwnershipStep> = Vec::new();
    let mut warnings: Vec<String> = Vec::new();
    let mut scan_failures: Vec<crate::kube::resource::ScanWarning> = Vec::new();
    let mut current_kind = kind.to_string();
    let mut current_group = target_group.to_string();
    let mut current_name = name.to_string();
    let mut current_ns = namespace.to_string();
    let mut visited = HashSet::new();
    let mut chain_broken = false;
    let mut trusted_root: Option<(String, String)> = None; // (group, kind)
    let mut target_labels: HashMap<String, String> = HashMap::new();

    loop {
        let info = if !current_group.is_empty() {
            gk_map.get(&(current_group.clone(), current_kind.clone()))
        } else {
            kind_map.get(&current_kind)
        };
        let info = match info {
            Some(i) => i,
            None => {
                if steps.is_empty() {
                    return Err(WhoManagesError {
                        message: format!("{}/{} not found (kind not in discovery)", kind, name),
                        scan_failure: None,
                    });
                }
                chain_broken = true;
                break;
            }
        };

        let gvk = GroupVersion::gv(&info.group, &info.version).with_kind(&current_kind);
        let ar = ApiResource::from_gvk_with_plural(&gvk, &info.plural);
        let api: Api<DynamicObject> = if info.namespaced {
            Api::namespaced_with(client.clone(), &current_ns, &ar)
        } else {
            Api::all_with(client.clone(), &ar)
        };

        let obj = match crate::kube::scanner::get_with_retry(
            &api,
            &current_name,
            &info.group,
            &info.version,
            &info.plural,
        )
        .await
        {
            Ok(o) => o,
            Err(w) => {
                warnings.push(format!("{}", w));
                if steps.is_empty() {
                    return Err(WhoManagesError {
                        message: format!(
                            "{}/{} not found in namespace '{}': {}",
                            current_kind, current_name, current_ns, w
                        ),
                        scan_failure: Some(w),
                    });
                }
                scan_failures.push(w.clone());
                steps.push(OwnershipStep {
                    kind: current_kind.clone(),
                    name: current_name.clone(),
                    namespace: Some(current_ns.clone()),
                    group: info.group.clone(),
                    relationship: "ownerRef".into(),
                    evidence: format!("parent GET failed: {}", w),
                    confidence: "None (unreachable)".into(),
                });
                chain_broken = true;
                break;
            }
        };

        let uid = obj.metadata.uid.clone().unwrap_or_default();
        if !visited.insert(uid.clone()) {
            chain_broken = true;
            warnings.push("Cycle detected in ownerRef chain".into());
            break;
        }

        let owner_refs: Vec<crate::kube::resource::OwnerRef> = obj
            .metadata
            .owner_references
            .unwrap_or_default()
            .into_iter()
            .map(|r| crate::kube::resource::OwnerRef {
                api_version: r.api_version,
                kind: r.kind,
                name: r.name,
                uid: r.uid,
                controller: r.controller.unwrap_or(false),
            })
            .collect();

        let labels: HashMap<String, String> = obj
            .metadata
            .labels
            .unwrap_or_default()
            .into_iter()
            .collect();

        let is_self = steps.is_empty();
        if is_self {
            target_labels = labels;
        }

        steps.push(OwnershipStep {
            kind: current_kind.clone(),
            name: current_name.clone(),
            namespace: obj.metadata.namespace.clone(),
            group: info.group.clone(),
            relationship: if is_self { "self" } else { "ownerRef" }.into(),
            evidence: if is_self {
                "target resource".into()
            } else {
                "ownerReference".into()
            },
            confidence: if is_self {
                "N/A"
            } else {
                "High (UID verified)"
            }
            .into(),
        });

        if !is_self {
            trusted_root = Some((current_group.clone(), current_kind.clone()));
        }

        let primary = crate::kube::resource::primary_owner(&owner_refs).cloned();
        match primary {
            Some(oref) => {
                let next_info = resolve_owner_kind_info(&oref, kind_map, gk_map);
                if next_info.is_none() {
                    chain_broken = true;
                    break;
                }
                let next_info = next_info.unwrap();

                let next_gvk =
                    GroupVersion::gv(&next_info.group, &next_info.version).with_kind(&oref.kind);
                let next_ar = ApiResource::from_gvk_with_plural(&next_gvk, &next_info.plural);
                let next_api: Api<DynamicObject> = if next_info.namespaced {
                    Api::namespaced_with(client.clone(), &current_ns, &next_ar)
                } else {
                    Api::all_with(client.clone(), &next_ar)
                };

                match crate::kube::scanner::get_with_retry(
                    &next_api,
                    &oref.name,
                    &next_info.group,
                    &next_info.version,
                    &next_info.plural,
                )
                .await
                {
                    Ok(parent_obj) => {
                        let parent_uid = parent_obj.metadata.uid.clone().unwrap_or_default();
                        if parent_uid != oref.uid {
                            steps.push(OwnershipStep {
                                kind: oref.kind.clone(),
                                name: oref.name.clone(),
                                namespace: parent_obj.metadata.namespace.clone(),
                                group: next_info.group.clone(),
                                relationship: "ownerRef".into(),
                                evidence: format!(
                                    "UID mismatch: ref={}, live={}",
                                    &oref.uid[..8.min(oref.uid.len())],
                                    &parent_uid[..8.min(parent_uid.len())]
                                ),
                                confidence: "None (stale ownerRef)".into(),
                            });
                            chain_broken = true;
                            break;
                        }
                        current_group = resolve_owner_group(&oref);
                        current_kind = oref.kind;
                        current_name = oref.name;
                        current_ns = parent_obj
                            .metadata
                            .namespace
                            .unwrap_or_else(|| current_ns.clone());
                    }
                    Err(w) => {
                        scan_failures.push(w.clone());
                        warnings.push(format!("{}", w));
                        steps.push(OwnershipStep {
                            kind: oref.kind.clone(),
                            name: oref.name.clone(),
                            namespace: None,
                            group: next_info.group.clone(),
                            relationship: "ownerRef".into(),
                            evidence: format!("parent GET failed: {}", w),
                            confidence: "None (unreachable)".into(),
                        });
                        chain_broken = true;
                        break;
                    }
                }
            }
            None => break,
        }
    }

    steps.reverse();

    let mut operator_name = None;
    let mut package_name = None;
    let mut install_namespace = None;
    let mut overall_confidence = "Unattributed".to_string();

    if chain_broken {
        overall_confidence = "Incomplete (chain broken)".into();
        warnings.push("Ownership chain is incomplete. Attribution may be inaccurate.".into());
    }

    if !chain_broken {
        for step in &steps {
            if step.kind == "ClusterServiceVersion" {
                let operators = discover_operators(client, kind_map).await?;
                let matched_op = operators.iter().find(|op| {
                    op.csv.name == step.name
                        && step.namespace.as_deref() == Some(op.install_namespace.as_str())
                });
                if let Some(op) = matched_op {
                    operator_name = Some(op.csv.name.clone());
                    install_namespace = Some(op.install_namespace.clone());
                    package_name = op.package_name.clone();
                    overall_confidence = "Managed (ownerRef chain → CSV)".into();
                    if let Some(sub) = &op.subscription {
                        steps.insert(
                            0,
                            OwnershipStep {
                                kind: "Subscription".into(),
                                name: sub.name.clone(),
                                namespace: sub.namespace.clone(),
                                group: "operators.coreos.com".into(),
                                relationship: "installed-by".into(),
                                evidence: "status.installedCSV".into(),
                                confidence: "High".into(),
                            },
                        );
                    }
                }
                break;
            }
        }

        if operator_name.is_none() {
            let crd_name_for_lookup: Option<String> = if kind == "CustomResourceDefinition" {
                // Target IS a CRD object — its metadata.name is the canonical CRD name
                Some(name.to_string())
            } else {
                resolve_crd_name_for_root(&trusted_root, target_group, kind, gk_map)
            };

            if let Some(crd_name) = crd_name_for_lookup {
                let operators = discover_operators(client, kind_map).await?;
                let matched_op = operators
                    .iter()
                    .find(|op| op.owned_crds.contains(&crd_name));
                if let Some(op) = matched_op {
                    operator_name = Some(op.csv.name.clone());
                    install_namespace = Some(op.install_namespace.clone());
                    package_name = op.package_name.clone();
                    overall_confidence = "Attributed (CRD owned by CSV)".into();
                    steps.insert(
                        0,
                        OwnershipStep {
                            kind: "ClusterServiceVersion".into(),
                            name: op.csv.name.clone(),
                            namespace: Some(op.install_namespace.clone()),
                            group: "operators.coreos.com".into(),
                            relationship: "owns-api".into(),
                            evidence: "CSV spec.customresourcedefinitions.owned".into(),
                            confidence: "Medium".into(),
                        },
                    );
                    if let Some(sub) = &op.subscription {
                        steps.insert(
                            0,
                            OwnershipStep {
                                kind: "Subscription".into(),
                                name: sub.name.clone(),
                                namespace: sub.namespace.clone(),
                                group: "operators.coreos.com".into(),
                                relationship: "installed-by".into(),
                                evidence: "status.installedCSV".into(),
                                confidence: "High".into(),
                            },
                        );
                    }
                }
            }
        }

        if operator_name.is_none()
            && let Some((label_key, label_value)) = infer_operator_from_labels(&target_labels)
        {
            overall_confidence = format!("Inferred (label {}={})", label_key, label_value);
            operator_name = Some(label_value);
        }
    }

    Ok(WhoManagesResult {
        chain: steps,
        operator_name,
        package_name,
        install_namespace,
        confidence: overall_confidence,
        warnings,
        scan_failures,
    })
}

pub fn print_who_manages(result: &WhoManagesResult, output: &OutputFormat) {
    match output {
        OutputFormat::Tree => {
            if !result.warnings.is_empty() {
                for w in &result.warnings {
                    eprintln!("⚠ {}", w);
                }
                eprintln!();
            }
            println!("Ownership chain:");
            for (i, step) in result.chain.iter().enumerate() {
                let indent = "  ".repeat(i + 1);
                let ns = step
                    .namespace
                    .as_deref()
                    .map(|n| format!(" (ns: {})", n))
                    .unwrap_or_default();
                let direction = if step.relationship == "self" {
                    ""
                } else {
                    "← "
                };
                println!(
                    "{}{}[1m{}/{}[0m{}  [2m[{}, {}, {}][0m",
                    indent,
                    direction,
                    step.kind,
                    step.name,
                    ns,
                    step.relationship,
                    step.evidence,
                    step.confidence
                );
            }
            println!();
            if let Some(op) = &result.operator_name {
                println!("Operator:   {}", op);
            }
            if let Some(pkg) = &result.package_name {
                println!("Package:    {}", pkg);
            }
            if let Some(ns) = &result.install_namespace {
                println!("Namespace:  {}", ns);
            }
            println!("Confidence: {}", result.confidence);
        }
        OutputFormat::Table => {
            let mut table = Table::new();
            table.set_header(vec![
                "Relationship",
                "Group",
                "Kind",
                "Name",
                "Namespace",
                "Evidence",
                "Confidence",
            ]);
            for step in &result.chain {
                table.add_row(vec![
                    &step.relationship,
                    &step.group,
                    &step.kind,
                    &step.name,
                    step.namespace.as_deref().unwrap_or("-"),
                    &step.evidence,
                    &step.confidence,
                ]);
            }
            println!("{table}");
            println!();
            if !result.warnings.is_empty() {
                for w in &result.warnings {
                    eprintln!("⚠ {}", w);
                }
            }
            println!(
                "Operator:   {}",
                result.operator_name.as_deref().unwrap_or("(none)")
            );
            if let Some(pkg) = &result.package_name {
                println!("Package:    {}", pkg);
            }
            if let Some(ns) = &result.install_namespace {
                println!("Namespace:  {}", ns);
            }
            println!("Confidence: {}", result.confidence);
        }
        OutputFormat::Json => {
            let chain_json: Vec<_> = result
                .chain
                .iter()
                .map(|s| {
                    serde_json::json!({
                        "relationship": s.relationship,
                        "group": s.group,
                        "kind": s.kind,
                        "name": s.name,
                        "namespace": s.namespace,
                        "evidence": s.evidence,
                        "confidence": s.confidence,
                    })
                })
                .collect();
            let output = serde_json::json!({
                "chain": chain_json,
                "operator": result.operator_name,
                "package": result.package_name,
                "installNamespace": result.install_namespace,
                "confidence": result.confidence,
                "warnings": result.warnings,
            });
            println!(
                "{}",
                serde_json::to_string_pretty(&output).unwrap_or_default()
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn api_error(code: u16) -> kube::Error {
        kube::Error::Api(
            kube::core::Status {
                code,
                ..Default::default()
            }
            .boxed(),
        )
    }

    use crate::kube::discovery::KindInfo;
    use crate::kube::resource::OwnerRef;

    fn make_kind_info(group: &str, plural: &str) -> KindInfo {
        KindInfo {
            group: group.into(),
            version: "v1".into(),
            plural: plural.into(),
            namespaced: true,
            listable: true,
        }
    }

    fn make_oref(api_version: &str, kind: &str, name: &str, uid: &str) -> OwnerRef {
        OwnerRef {
            api_version: api_version.into(),
            kind: kind.into(),
            name: name.into(),
            uid: uid.into(),
            controller: true,
        }
    }

    #[test]
    fn resolve_owner_group_from_api_version() {
        let oref = make_oref("apps/v1", "Deployment", "web", "uid-1");
        assert_eq!(resolve_owner_group(&oref), "apps");

        let oref_core = make_oref("v1", "Pod", "pod-1", "uid-2");
        assert_eq!(resolve_owner_group(&oref_core), "");

        let oref_crd = make_oref(
            "datasciencecluster.opendatahub.io/v1",
            "DataScienceCluster",
            "dsc",
            "uid-3",
        );
        assert_eq!(
            resolve_owner_group(&oref_crd),
            "datasciencecluster.opendatahub.io"
        );
    }

    #[test]
    fn resolve_owner_kind_info_prefers_gk_map() {
        let mut km = KindMap::new();
        km.insert(
            "Ingress".into(),
            make_kind_info("config.openshift.io", "ingresses"),
        );
        let mut gk = GroupKindMap::new();
        gk.insert(
            ("networking.k8s.io".into(), "Ingress".into()),
            make_kind_info("networking.k8s.io", "ingresses"),
        );
        gk.insert(
            ("config.openshift.io".into(), "Ingress".into()),
            make_kind_info("config.openshift.io", "ingresses"),
        );

        let oref = make_oref("networking.k8s.io/v1", "Ingress", "my-ing", "uid-1");
        let info = resolve_owner_kind_info(&oref, &km, &gk).unwrap();
        assert_eq!(info.group, "networking.k8s.io");
    }

    #[test]
    fn resolve_owner_kind_info_no_fallback_to_wrong_group() {
        let mut km = KindMap::new();
        km.insert(
            "Ingress".into(),
            make_kind_info("config.openshift.io", "ingresses"),
        );
        let gk = GroupKindMap::new();

        let oref = make_oref("networking.k8s.io/v1", "Ingress", "my-ing", "uid-1");
        let info = resolve_owner_kind_info(&oref, &km, &gk);
        assert!(
            info.is_none(),
            "should not fallback to config.openshift.io when networking.k8s.io is specified"
        );
    }

    #[test]
    fn resolve_owner_kind_info_core_group_uses_kind_map() {
        let mut km = KindMap::new();
        km.insert("Pod".into(), make_kind_info("", "pods"));
        let gk = GroupKindMap::new();

        let oref = make_oref("v1", "Pod", "pod-1", "uid-1");
        let info = resolve_owner_kind_info(&oref, &km, &gk).unwrap();
        assert_eq!(info.group, "");
        assert_eq!(info.plural, "pods");
    }

    #[test]
    fn label_inference_managed_by_priority() {
        let mut labels = HashMap::new();
        labels.insert(LABEL_MANAGED_BY.into(), "operator-a".into());
        labels.insert(LABEL_PART_OF.into(), "component-b".into());
        let result = infer_operator_from_labels(&labels);
        assert!(result.is_some());
        let (key, value) = result.unwrap();
        assert_eq!(key, LABEL_MANAGED_BY);
        assert_eq!(value, "operator-a");
    }

    #[test]
    fn label_inference_part_of_fallback() {
        let mut labels = HashMap::new();
        labels.insert(LABEL_PART_OF.into(), "component-b".into());
        let result = infer_operator_from_labels(&labels);
        assert!(result.is_some());
        let (key, value) = result.unwrap();
        assert_eq!(key, LABEL_PART_OF);
        assert_eq!(value, "component-b");
    }

    #[test]
    fn label_inference_no_match() {
        let mut labels = HashMap::new();
        labels.insert("custom.io/managed-by".into(), "bogus".into());
        let result = infer_operator_from_labels(&labels);
        assert!(result.is_none(), "non-standard key should not match");
    }

    #[test]
    fn label_inference_empty() {
        let labels = HashMap::new();
        assert!(infer_operator_from_labels(&labels).is_none());
    }

    #[test]
    fn crd_object_uses_metadata_name_directly() {
        // Two CRDs for the same Kind "Kueue" in different groups
        let mut km = KindMap::new();
        km.insert(
            "Kueue".into(),
            make_kind_info("kueue.openshift.io", "kueues"),
        );
        let mut gk = GroupKindMap::new();
        gk.insert(
            ("kueue.openshift.io".into(), "Kueue".into()),
            make_kind_info("kueue.openshift.io", "kueues"),
        );
        gk.insert(
            ("components.platform.opendatahub.io".into(), "Kueue".into()),
            make_kind_info("components.platform.opendatahub.io", "kueues"),
        );

        // When target is CRD, we use metadata.name directly
        // CRD name = "kueues.kueue.openshift.io" → should match owned_crds directly
        // No need for resolve_crd_name_for_root — it's just the name itself

        // For non-CRD root, resolve_crd_name_for_root uses trusted_root
        let root = Some(("kueue.openshift.io".into(), "Kueue".into()));
        let result = resolve_crd_name_for_root(&root, "", "Kueue", &gk);
        assert_eq!(result, Some("kueues.kueue.openshift.io".into()));

        let root2 = Some(("components.platform.opendatahub.io".into(), "Kueue".into()));
        let result2 = resolve_crd_name_for_root(&root2, "", "Kueue", &gk);
        assert_eq!(
            result2,
            Some("kueues.components.platform.opendatahub.io".into())
        );
    }

    #[test]
    fn crd_name_for_built_in_returns_none() {
        let mut km = KindMap::new();
        km.insert("Pod".into(), make_kind_info("", "pods"));
        let gk = GroupKindMap::new();
        let result = resolve_crd_name_for_root(&None, "", "Pod", &gk);
        assert!(result.is_none());
    }

    #[test]
    fn retries_only_transient_api_statuses() {
        assert!(is_transient_list_error(&api_error(408)));
        assert!(is_transient_list_error(&api_error(429)));
        assert!(is_transient_list_error(&api_error(500)));
        assert!(!is_transient_list_error(&api_error(400)));
        assert!(!is_transient_list_error(&api_error(403)));
        assert!(!is_transient_list_error(&api_error(404)));
    }

    fn make_csv_with_annotation(annotation: &str) -> kube::api::DynamicObject {
        let mut obj = kube::api::DynamicObject::new(
            "test-csv",
            &kube::api::ApiResource::erase::<k8s_openapi::api::core::v1::Pod>(&()),
        );
        obj.metadata.annotations = Some(std::collections::BTreeMap::from([(
            "operatorframework.io/properties".to_string(),
            annotation.to_string(),
        )]));
        obj
    }

    #[test]
    fn extract_annotation_packages_array_single() {
        let csv = make_csv_with_annotation(
            r#"[{"type":"olm.package","value":"{\"packageName\":\"rhods-operator\",\"version\":\"3.5.1\"}"}]"#,
        );
        let pkgs = extract_annotation_packages(&csv);
        assert_eq!(pkgs, vec!["rhods-operator"]);
    }

    #[test]
    fn extract_annotation_packages_object_properties() {
        let csv = make_csv_with_annotation(
            r#"{"properties":[{"type":"olm.package","value":{"packageName":"my-operator","version":"1.0"}}]}"#,
        );
        let pkgs = extract_annotation_packages(&csv);
        assert_eq!(pkgs, vec!["my-operator"]);
    }

    #[test]
    fn extract_annotation_packages_empty_annotation() {
        let csv = make_csv_with_annotation("[]");
        let pkgs = extract_annotation_packages(&csv);
        assert!(pkgs.is_empty());
    }

    #[test]
    fn extract_annotation_packages_no_olm_package_type() {
        let csv =
            make_csv_with_annotation(r#"[{"type":"olm.gvk","value":{"group":"example.com"}}]"#);
        let pkgs = extract_annotation_packages(&csv);
        assert!(pkgs.is_empty());
    }

    #[test]
    fn extract_annotation_packages_invalid_json() {
        let csv = make_csv_with_annotation("not valid json");
        let pkgs = extract_annotation_packages(&csv);
        assert!(pkgs.is_empty());
    }

    #[test]
    fn extract_annotation_packages_multiple_distinct() {
        let csv = make_csv_with_annotation(
            r#"[{"type":"olm.package","value":"{\"packageName\":\"pkg-a\"}"},{"type":"olm.package","value":"{\"packageName\":\"pkg-b\"}"}]"#,
        );
        let pkgs = extract_annotation_packages(&csv);
        assert_eq!(pkgs.len(), 2);
        assert!(pkgs.contains(&"pkg-a".to_string()));
        assert!(pkgs.contains(&"pkg-b".to_string()));
    }

    #[test]
    fn extract_annotation_packages_no_annotation() {
        let obj = kube::api::DynamicObject::new(
            "test-csv",
            &kube::api::ApiResource::erase::<k8s_openapi::api::core::v1::Pod>(&()),
        );
        let pkgs = extract_annotation_packages(&obj);
        assert!(pkgs.is_empty());
    }

    // ── discover_operators tower_test mock tests ──

    use http::Response;
    use kube::Client;
    use std::pin::pin;
    use tower_test::mock::Handle;

    fn mock_list_response_olm(items: Vec<serde_json::Value>) -> Response<kube::client::Body> {
        let body = serde_json::json!({
            "apiVersion": "v1",
            "kind": "List",
            "metadata": {"resourceVersion": "1"},
            "items": items,
        });
        Response::builder()
            .status(200)
            .body(kube::client::Body::from(serde_json::to_vec(&body).unwrap()))
            .unwrap()
    }

    fn make_csv_json(
        name: &str,
        ns: &str,
        annotation_pkg: Option<&str>,
        labels: Vec<(&str, &str)>,
    ) -> serde_json::Value {
        let mut label_map = serde_json::Map::new();
        for (k, v) in labels {
            label_map.insert(k.to_string(), serde_json::json!(v));
        }
        let mut annotations = serde_json::Map::new();
        if let Some(pkg) = annotation_pkg {
            let inner = serde_json::json!([{
                "type": "olm.package",
                "value": serde_json::json!({"packageName": pkg}).to_string()
            }]);
            annotations.insert(
                "operatorframework.io/properties".to_string(),
                serde_json::Value::String(inner.to_string()),
            );
        }
        serde_json::json!({
            "apiVersion": "operators.coreos.com/v1alpha1",
            "kind": "ClusterServiceVersion",
            "metadata": {
                "name": name,
                "namespace": ns,
                "uid": format!("uid-{}-{}", name, ns),
                "labels": label_map,
                "annotations": annotations,
            },
            "status": {"phase": "Succeeded"},
            "spec": {"customresourcedefinitions": {"owned": []}, "install": {"spec": {"deployments": []}}}
        })
    }

    #[allow(dead_code)]
    fn make_sub_json(name: &str, ns: &str, pkg: &str, csv: &str) -> serde_json::Value {
        serde_json::json!({
            "apiVersion": "operators.coreos.com/v1alpha1",
            "kind": "Subscription",
            "metadata": {"name": name, "namespace": ns, "uid": format!("uid-sub-{}", name)},
            "spec": {"name": pkg, "channel": "stable", "source": "redhat-operators", "sourceNamespace": "openshift-marketplace"},
            "status": {"installedCSV": csv, "currentCSV": csv}
        })
    }

    fn olm_kind_map() -> KindMap {
        let mut km = KindMap::new();
        km.insert(
            "ClusterServiceVersion".into(),
            crate::kube::discovery::KindInfo {
                group: "operators.coreos.com".into(),
                version: "v1alpha1".into(),
                plural: "clusterserviceversions".into(),
                namespaced: true,
                listable: true,
            },
        );
        km
    }

    async fn handle_discover_requests(
        handle: Handle<http::Request<kube::client::Body>, Response<kube::client::Body>>,
        csv_items: Vec<serde_json::Value>,
        sub_items: Vec<serde_json::Value>,
        request_paths: std::sync::Arc<std::sync::Mutex<Vec<String>>>,
    ) {
        let mut handle = pin!(handle);
        // tokio::join sends 2 requests concurrently — order is not guaranteed
        for _ in 0..2 {
            let (req, send) = handle.next_request().await.expect("expected request");
            let path = req.uri().path().to_string();
            request_paths.lock().unwrap().push(path.clone());
            if path.contains("/clusterserviceversions") {
                send.send_response(mock_list_response_olm(csv_items.clone()));
            } else if path.contains("/subscriptions") {
                send.send_response(mock_list_response_olm(sub_items.clone()));
            } else {
                panic!("Unexpected request path: {}", path);
            }
        }
    }

    #[tokio::test]
    async fn discover_orphan_csv_single_annotation_package() {
        let (mock_service, handle) = tower_test::mock::pair::<
            http::Request<kube::client::Body>,
            Response<kube::client::Body>,
        >();
        let client = Client::new(mock_service, "default");
        let km = olm_kind_map();
        let paths = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let rp = paths.clone();

        let csv = make_csv_json("my-op.v1.0", "ns-a", Some("my-operator"), vec![]);
        let spawned = tokio::spawn(handle_discover_requests(handle, vec![csv], vec![], rp));

        let ops = discover_operators(&client, &km).await.unwrap();
        spawned.await.unwrap();

        assert_eq!(ops.len(), 1);
        assert_eq!(ops[0].package_name, Some("my-operator".to_string()));
        assert!(ops[0].subscription.is_none());
        let p = paths.lock().unwrap();
        assert_eq!(p.len(), 2, "Exactly 2 LIST requests (CSV + Subscription)");
    }

    #[tokio::test]
    async fn discover_annotation_no_package_gives_none() {
        let (mock_service, handle) = tower_test::mock::pair::<
            http::Request<kube::client::Body>,
            Response<kube::client::Body>,
        >();
        let client = Client::new(mock_service, "default");
        let km = olm_kind_map();
        let paths = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let rp = paths.clone();

        // CSV with no annotation
        let csv = make_csv_json("orphan.v1", "ns-a", None, vec![]);
        let spawned = tokio::spawn(handle_discover_requests(handle, vec![csv], vec![], rp));

        let ops = discover_operators(&client, &km).await.unwrap();
        spawned.await.unwrap();

        assert_eq!(ops.len(), 1);
        assert_eq!(ops[0].package_name, None, "No annotation → package None");
    }

    #[tokio::test]
    async fn discover_annotation_multiple_packages_gives_none() {
        let (mock_service, handle) = tower_test::mock::pair::<
            http::Request<kube::client::Body>,
            Response<kube::client::Body>,
        >();
        let client = Client::new(mock_service, "default");
        let km = olm_kind_map();
        let paths = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let rp = paths.clone();

        // CSV with 2 distinct packages in annotation
        let mut csv = make_csv_json("multi.v1", "ns-a", None, vec![]);
        csv["metadata"]["annotations"]["operatorframework.io/properties"] = serde_json::json!(
            r#"[{"type":"olm.package","value":"{\"packageName\":\"pkg-a\"}"},{"type":"olm.package","value":"{\"packageName\":\"pkg-b\"}"}]"#
        );
        let spawned = tokio::spawn(handle_discover_requests(handle, vec![csv], vec![], rp));

        let ops = discover_operators(&client, &km).await.unwrap();
        spawned.await.unwrap();

        assert_eq!(ops.len(), 1);
        assert_eq!(
            ops[0].package_name, None,
            "Multiple packages → None (ambiguous)"
        );
    }
}
