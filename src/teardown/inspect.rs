use std::collections::HashSet;
use std::sync::Arc;

use anyhow::Result;
use futures::stream::StreamExt;
use kube::{
    Client,
    api::{Api, ApiResource, DynamicObject, ListParams},
    core::GroupVersion,
};
use serde::{Deserialize, Serialize};

use crate::analyzers::olm::OperatorInstance;
use crate::cli::OutputFormat;
use crate::kube::discovery::{GvrMap, KindMap};
use crate::kube::resource::ResourceId;

const DEFAULT_CONCURRENCY: usize = 16;
const LIST_PAGE_SIZE: u32 = 500;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct OperatorInspection {
    pub operator: OperatorInstance,
    pub cr_instances: Vec<ResourceId>,
    pub controller_pods: Vec<ResourceId>,
}

pub async fn inspect_operator(
    client: &Client,
    operator: &OperatorInstance,
    kind_map: &KindMap,
    gvr_map: &GvrMap,
) -> Result<OperatorInspection> {
    eprint!("🔍 Discovering CR instances...");

    // Dedup CRDs by GVR key
    let unique_crds: Vec<&String> = {
        let mut seen_gvr = HashSet::new();
        operator
            .owned_crds
            .iter()
            .filter(|crd| {
                let gvr_key = crd
                    .split_once('.')
                    .map(|(p, g)| format!("{}.{}", p, g).to_lowercase())
                    .unwrap_or_default();
                seen_gvr.insert(gvr_key)
            })
            .collect()
    };

    let kind_map = Arc::new(kind_map.clone());
    let gvr_map = Arc::new(gvr_map.clone());

    let futs = unique_crds.into_iter().map(|crd_name| {
        let client = client.clone();
        let crd_name = crd_name.clone();
        let km = kind_map.clone();
        let gm = gvr_map.clone();
        async move {
            let (plural, group) = match crd_name.split_once('.') {
                Some((p, g)) => (p, g),
                None => return vec![],
            };
            let gvr_key = format!("{}.{}", plural, group).to_lowercase();
            let kind = match gm.get(&gvr_key) {
                Some(k) => k.clone(),
                None => return vec![],
            };
            let kind_info = match km.get(&kind) {
                Some(i) => i,
                None => return vec![],
            };
            let gvk = GroupVersion::gv(&kind_info.group, &kind_info.version).with_kind(&kind);
            let ar = ApiResource::from_gvk_with_plural(&gvk, &kind_info.plural);
            let api: Api<DynamicObject> = Api::all_with(client, &ar);
            let items = match list_paginated(&api).await {
                Ok(items) => items,
                Err(_) => return vec![],
            };
            items
                .into_iter()
                .filter_map(|obj| {
                    let name = obj.metadata.name?;
                    Some(ResourceId {
                        group: kind_info.group.clone(),
                        version: kind_info.version.clone(),
                        kind: kind.clone(),
                        namespace: obj.metadata.namespace,
                        name,
                        uid: obj.metadata.uid,
                    })
                })
                .collect::<Vec<_>>()
        }
    });

    let results: Vec<Vec<ResourceId>> = futures::stream::iter(futs)
        .buffer_unordered(DEFAULT_CONCURRENCY)
        .collect()
        .await;

    let mut cr_instances: Vec<ResourceId> = results.into_iter().flatten().collect();

    // UID-based dedup
    let mut seen_uids = HashSet::new();
    cr_instances.retain(|cr| {
        if let Some(uid) = &cr.uid {
            seen_uids.insert(uid.clone())
        } else {
            true
        }
    });

    eprintln!(" found {} instances", cr_instances.len());

    let mut controller_pods = Vec::new();

    eprint!("🔍 Discovering controller pods...");
    for deploy_name in &operator.deployments {
        let deploy_info = match kind_map.get("Deployment") {
            Some(i) => i,
            None => continue,
        };

        let gvk =
            GroupVersion::gv(&deploy_info.group, &deploy_info.version).with_kind("Deployment");
        let ar = ApiResource::from_gvk_with_plural(&gvk, &deploy_info.plural);
        let api: Api<DynamicObject> =
            Api::namespaced_with(client.clone(), &operator.install_namespace, &ar);

        let deploy = match api.get(deploy_name).await {
            Ok(d) => d,
            Err(_) => continue,
        };

        let match_labels = deploy
            .data
            .get("spec")
            .and_then(|s| s.get("selector"))
            .and_then(|s| s.get("matchLabels"))
            .and_then(|m| m.as_object());

        let label_str = match match_labels {
            Some(labels) => labels
                .iter()
                .filter_map(|(k, v)| v.as_str().map(|val| format!("{}={}", k, val)))
                .collect::<Vec<_>>()
                .join(","),
            None => continue,
        };

        if label_str.is_empty() {
            continue;
        }

        let pod_info = match kind_map.get("Pod") {
            Some(i) => i,
            None => continue,
        };

        let pod_gvk = GroupVersion::gv(&pod_info.group, &pod_info.version).with_kind("Pod");
        let pod_ar = ApiResource::from_gvk_with_plural(&pod_gvk, &pod_info.plural);
        let pod_api: Api<DynamicObject> =
            Api::namespaced_with(client.clone(), &operator.install_namespace, &pod_ar);

        if let Ok(pods) = pod_api
            .list(&ListParams::default().labels(&label_str))
            .await
        {
            for pod in pods.items {
                let name = match pod.metadata.name {
                    Some(n) => n,
                    None => continue,
                };
                controller_pods.push(ResourceId {
                    group: String::new(),
                    version: "v1".to_string(),
                    kind: "Pod".to_string(),
                    namespace: Some(operator.install_namespace.clone()),
                    name,
                    uid: pod.metadata.uid,
                });
            }
        }
    }
    eprintln!(" found {} pods", controller_pods.len());

    Ok(OperatorInspection {
        operator: operator.clone(),
        cr_instances,
        controller_pods,
    })
}

async fn list_paginated(api: &Api<DynamicObject>) -> Result<Vec<DynamicObject>> {
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

pub fn print_inspection(inspection: &OperatorInspection, output: &OutputFormat) {
    match output {
        OutputFormat::Json => print_inspection_json(inspection),
        _ => print_inspection_tree(inspection),
    }
}

fn print_inspection_tree(inspection: &OperatorInspection) {
    let op = &inspection.operator;

    println!("\x1b[1mOperator: {}\x1b[0m\n", op.csv.name);

    // OLM
    println!("\x1b[1mOLM\x1b[0m");
    if let Some(sub) = &op.subscription {
        println!(
            "  Subscription/{}{}",
            sub.name,
            ns_suffix(sub.namespace.as_deref())
        );
    }
    println!(
        "  ClusterServiceVersion/{}{}",
        op.csv.name,
        ns_suffix(op.csv.namespace.as_deref())
    );

    // Controller
    println!("\n\x1b[1mController\x1b[0m");
    for deploy in &op.deployments {
        println!(
            "  Deployment/{}{}",
            deploy,
            ns_suffix(Some(&op.install_namespace))
        );
    }
    for sa in &op.service_accounts {
        println!(
            "  ServiceAccount/{}{}",
            sa,
            ns_suffix(Some(&op.install_namespace))
        );
    }
    for pod in &inspection.controller_pods {
        println!("  Pod/{}{}", pod.name, ns_suffix(pod.namespace.as_deref()));
    }

    // Owned CRDs (dedup)
    let mut unique_crds: Vec<&String> = op.owned_crds.iter().collect();
    unique_crds.dedup();
    println!("\n\x1b[1mOwned CRDs ({})\x1b[0m", unique_crds.len());
    for crd in &unique_crds {
        println!("  {}", crd);
    }

    // CR Instances
    println!(
        "\n\x1b[1mCR Instances ({})\x1b[0m",
        inspection.cr_instances.len()
    );
    if inspection.cr_instances.is_empty() {
        println!("  (none)");
    } else {
        for cr in &inspection.cr_instances {
            let scope = match &cr.namespace {
                Some(ns) => format!("  \x1b[2m(ns: {})\x1b[0m", ns),
                None => "  \x1b[2m(cluster-scoped)\x1b[0m".to_string(),
            };
            println!("  {}/{}{}", cr.kind, cr.name, scope);
        }
    }

    // Summary
    let olm_count = 1 + op.subscription.as_ref().map(|_| 1).unwrap_or(0);
    let controller_count =
        op.deployments.len() + op.service_accounts.len() + inspection.controller_pods.len();
    println!(
        "\n\x1b[1mSummary\x1b[0m: {} OLM, {} controller, {} CRDs, {} CR instances",
        olm_count,
        controller_count,
        unique_crds.len(),
        inspection.cr_instances.len()
    );
}

fn print_inspection_json(inspection: &OperatorInspection) {
    println!(
        "{}",
        serde_json::to_string_pretty(inspection).unwrap_or_default()
    );
}

fn ns_suffix(ns: Option<&str>) -> String {
    match ns {
        Some(ns) => format!("  \x1b[2m(ns: {})\x1b[0m", ns),
        None => String::new(),
    }
}
