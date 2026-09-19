use std::collections::HashSet;

use anyhow::Result;
use kube::{
    Client,
    api::{Api, ApiResource, DynamicObject, ListParams},
    core::GroupVersion,
};
use serde::{Deserialize, Serialize};

use crate::analyzers::olm::OperatorInstance;
use crate::cli::OutputFormat;
use crate::kube::discovery::{GroupKindMap, GvrMap, KindMap};
use crate::kube::resource::ResourceId;
use crate::teardown::planner::{discover_cr_instances, discover_related_crd_instances};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct OperatorInspection {
    pub operator: OperatorInstance,
    pub cr_instances: Vec<ResourceId>,
    pub related_cr_instances: Vec<ResourceId>,
    pub controller_pods: Vec<ResourceId>,
}

pub async fn inspect_operator(
    client: &Client,
    operator: &OperatorInstance,
    kind_map: &KindMap,
    gvr_map: &GvrMap,
    gk_map: &GroupKindMap,
) -> Result<OperatorInspection> {
    // Owned CRD instances — reuse planner's discovery
    eprint!("🔍 Discovering CR instances...");
    let cr_report = discover_cr_instances(client, &operator.owned_crds, gvr_map, gk_map).await;
    let cr_instances: Vec<ResourceId> = cr_report.instances.into_iter().map(|cr| cr.id).collect();
    eprintln!(" found {} instances", cr_instances.len());

    // Related CRDs (label-based, scoped by part-of value) — reuse planner's discovery
    eprint!("🔍 Discovering related CRDs...");
    let owned_crd_set: HashSet<&str> = operator.owned_crds.iter().map(|s| s.as_str()).collect();
    let target_part_of_values: HashSet<String> = {
        let mut values = HashSet::new();
        let label_key = "platform.opendatahub.io/part-of";
        const GENERIC_DOMAINS: &[&str] = &[
            "openshift.io",
            "k8s.io",
            "kubernetes.io",
            "coreos.com",
            "cncf.io",
        ];
        let target_root_domains: HashSet<String> = operator
            .owned_crds
            .iter()
            .filter_map(|crd| {
                let group = crd.split_once('.')?.1;
                let parts: Vec<&str> = group.rsplitn(3, '.').collect();
                if parts.len() >= 2 {
                    let root = format!("{}.{}", parts[1], parts[0]);
                    if GENERIC_DOMAINS.contains(&root.as_str()) {
                        None
                    } else {
                        Some(root)
                    }
                } else {
                    None
                }
            })
            .collect();
        if !target_root_domains.is_empty()
            && let Some(crd_ki) = kind_map.get("CustomResourceDefinition")
        {
            let crd_gvk = GroupVersion::gv(&crd_ki.group, &crd_ki.version)
                .with_kind("CustomResourceDefinition");
            let crd_ar = ApiResource::from_gvk_with_plural(&crd_gvk, &crd_ki.plural);
            let crd_api: Api<DynamicObject> = Api::all_with(client.clone(), &crd_ar);
            if let Ok(crd_list) = crd_api.list(&ListParams::default()).await {
                for crd in &crd_list.items {
                    let crd_name = crd.metadata.name.as_deref().unwrap_or("");
                    let crd_group = crd_name.split_once('.').map(|(_, g)| g).unwrap_or("");
                    let shares_domain = target_root_domains.iter().any(|d| crd_group.ends_with(d));
                    if shares_domain
                        && let Some(labels) = &crd.metadata.labels
                        && let Some(v) = labels.get(label_key)
                    {
                        values.insert(v.clone());
                    }
                }
            }
        }
        values
    };
    let related_report = discover_related_crd_instances(
        client,
        &owned_crd_set,
        &target_part_of_values,
        kind_map,
        gvr_map,
        gk_map,
    )
    .await;
    let related_cr_instances: Vec<ResourceId> = related_report
        .actions
        .into_iter()
        .filter_map(|action| match action {
            crate::teardown::planner::Action::Review { resource, .. } => Some(resource),
            _ => None,
        })
        .collect();
    eprintln!(" found {} related instances", related_cr_instances.len());

    // Controller pods
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
        related_cr_instances,
        controller_pods,
    })
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

    // Related CR Instances
    if !inspection.related_cr_instances.is_empty() {
        println!(
            "\n\x1b[1mRelated CR Instances ({})\x1b[0m",
            inspection.related_cr_instances.len()
        );
        for cr in &inspection.related_cr_instances {
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
        "\n\x1b[1mSummary\x1b[0m: {} OLM, {} controller, {} CRDs, {} CR instances, {} related",
        olm_count,
        controller_count,
        unique_crds.len(),
        inspection.cr_instances.len(),
        inspection.related_cr_instances.len()
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
