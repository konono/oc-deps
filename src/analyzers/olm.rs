use std::collections::HashMap;

use anyhow::Result;
use comfy_table::Table;
use kube::{
    Client,
    api::{Api, ApiResource, DynamicObject, ListParams},
    core::GroupVersion,
};
use serde::{Deserialize, Serialize};

use crate::cli::OutputFormat;
use crate::kube::discovery::KindMap;
use crate::kube::resource::ResourceId;

// ──────────────────────────────────────────────────────────────
//  Operator Instance — structured OLM operator representation
// ──────────────────────────────────────────────────────────────

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct OperatorInstance {
    pub subscription: Option<ResourceId>,
    pub csv: ResourceId,
    pub csv_phase: String,
    pub owned_crds: Vec<String>,
    pub required_crds: Vec<String>,
    pub owned_api_services: Vec<String>,
    pub required_api_services: Vec<String>,
    pub deployments: Vec<String>,
    pub service_accounts: Vec<String>,
    pub install_namespace: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct OperatorDependency {
    pub from_csv: String,
    pub to_csv: String,
    pub via_crd: String,
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

fn extract_api_service_names(csv_data: &serde_json::Value, field: &str) -> Vec<String> {
    csv_data
        .get("spec")
        .and_then(|s| s.get("apiservicedefinitions"))
        .and_then(|c| c.get(field))
        .and_then(|o| o.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|item| item.get("name").and_then(|n| n.as_str()).map(String::from))
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

const LIST_PAGE_SIZE: u32 = 500;

async fn list_all_paginated(api: &Api<DynamicObject>) -> Result<Vec<DynamicObject>> {
    let mut all_items = Vec::new();
    let mut continue_token: Option<String> = None;

    loop {
        let mut lp = ListParams::default().limit(LIST_PAGE_SIZE);
        if let Some(token) = &continue_token {
            lp = lp.continue_token(token);
        }
        let list = api.list(&lp).await?;
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

    let (csv_result, sub_result) =
        tokio::join!(list_all_paginated(&csv_api), list_all_paginated(&sub_api),);
    let csv_items = csv_result?;
    let sub_items = sub_result.unwrap_or_default();

    // P1-2: key by (sub_namespace, csv_name) so same CSV name in different
    // namespaces via different Subscriptions produces separate installations
    let mut sub_by_csv: HashMap<String, Vec<&DynamicObject>> = HashMap::new();
    for sub in &sub_items {
        if let Some(csv_name) = sub
            .data
            .get("status")
            .and_then(|s| s.get("currentCSV"))
            .and_then(|c| c.as_str())
        {
            sub_by_csv
                .entry(csv_name.to_string())
                .or_default()
                .push(sub);
        }
    }

    // Deduplicate CSV copies: OLM copies CSVs into every target namespace.
    // Key: (subscription_namespace, csv_name) — different Subscriptions = different installations.
    // For each installation, prefer the CSV copy in the Subscription's namespace.
    let mut best_csv: HashMap<(String, String), (&DynamicObject, Option<ResourceId>, String)> =
        HashMap::new();

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

                let key = (sub_ns.to_string(), csv_name.clone());
                let new_matches_sub_ns = csv_ns == sub_ns;

                let should_replace = if let Some((existing, _, _)) = best_csv.get(&key) {
                    let existing_ns = existing.metadata.namespace.as_deref().unwrap_or("unknown");
                    let existing_matches = existing_ns == sub_ns;
                    new_matches_sub_ns && !existing_matches
                } else {
                    true
                };

                if should_replace {
                    best_csv.insert(key, (csv, subscription, phase.clone()));
                }
            }
        } else {
            let key = (csv_ns.to_string(), csv_name.clone());
            best_csv
                .entry(key)
                .or_insert_with(|| (csv, None, phase.clone()));
        }
    }

    let mut operators = Vec::new();

    for ((_, csv_name), (csv, subscription, csv_phase)) in &best_csv {
        let csv_ns = csv
            .metadata
            .namespace
            .clone()
            .unwrap_or_else(|| "unknown".to_string());
        let csv_uid = csv.metadata.uid.clone();

        let owned_crds = extract_crd_names(&csv.data, "owned");
        let required_crds = extract_crd_names(&csv.data, "required");
        let owned_api_services = extract_api_service_names(&csv.data, "owned");
        let required_api_services = extract_api_service_names(&csv.data, "required");
        let deployments = extract_deployment_names(&csv.data);
        let service_accounts = extract_service_account_names(&csv.data);

        operators.push(OperatorInstance {
            subscription: subscription.clone(),
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
            owned_api_services,
            required_api_services,
            deployments,
            service_accounts,
            install_namespace: csv_ns,
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
                        from_csv: requirer.csv.name.clone(),
                        to_csv: provider.csv.name.clone(),
                        via_crd: required_crd.clone(),
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
                op.owned_api_services.iter().map(|s| s.as_str()).collect(),
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
                "  {} \x1b[33m→\x1b[0m {} (via CRD: {})",
                dep.from_csv, dep.to_csv, dep.via_crd
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

pub struct CrdOriginChain {
    pub crd_name: String,
    pub crd_labels: Vec<(String, String)>,
    pub csv_name: Option<String>,
    pub csv_namespace: Option<String>,
    pub csv_match_method: Option<String>,
    pub subscription_name: Option<String>,
    pub subscription_namespace: Option<String>,
}

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
                if k.contains("part-of") || k.contains("managed-by") || k.contains("opendatahub") {
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
                    let current_csv = sub
                        .data
                        .get("status")
                        .and_then(|s| s.get("currentCSV"))
                        .and_then(|c| c.as_str());
                    if current_csv == Some(csv_name.as_str()) {
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
