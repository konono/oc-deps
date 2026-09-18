use std::collections::HashMap;

use comfy_table::Table;
use kube::{
    Client,
    api::{Api, ApiResource, DynamicObject, ListParams},
    core::GroupVersion,
};

use crate::cli::OutputFormat;
use crate::kube::discovery::KindMap;

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
