use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use anyhow::Result;
use kube::{
    Client,
    api::{Api, ApiResource, DynamicObject},
    core::GroupVersion,
};
use serde::{Deserialize, Serialize};

use crate::analyzers::namespace_scope::{
    CandidateNamespace, RejectedNamespaceCandidate, scan_candidate_namespaces_with_ledger,
};
use crate::analyzers::olm::OperatorInstance;
use crate::cli::OutputFormat;
use crate::kube::discovery::{GroupKindMap, GvrMap, KindMap};
use crate::kube::resource::{
    CoverageLedger, CoverageSummary, CrdCatalog, QueryRequirement, ResourceId,
};
use crate::kube::scanner::SharedLedger;
use crate::teardown::planner::{
    CrInstance, Provenance, compute_part_of_seeds_opts, discover_cr_instances_opts,
    discover_related_crd_instances_opts, fetch_crd_catalog,
};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum Relationship {
    #[serde(rename = "ownerRef")]
    OwnerRef,
    #[serde(rename = "installStrategy")]
    InstallStrategy,
    #[serde(rename = "olm")]
    Olm,
    #[serde(rename = "spec-ref")]
    SpecRef,
    #[serde(rename = "owned-crd-instance")]
    OwnedCrdInstance,
    #[serde(rename = "selector-match")]
    SelectorMatch,
    #[serde(rename = "same-operator-crd")]
    SameOperatorCrd,
    #[serde(rename = "label-match")]
    LabelMatch,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum Confidence {
    Managed,
    Attributed,
    Inferred,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct InspectedResource {
    pub id: ResourceId,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source_id: Option<ResourceId>,
    pub relationship: Relationship,
    pub evidence: String,
    pub confidence: Confidence,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct InspectionCategory {
    pub label: String,
    pub resources: Vec<InspectedResource>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct OperatorInspection {
    pub operator_name: String,
    pub csv_name: String,
    pub install_namespace: String,
    pub subscription_name: Option<String>,
    pub owned_crds: Vec<String>,
    pub categories: Vec<InspectionCategory>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub namespace_scope: Option<Vec<CandidateNamespace>>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub scope_warnings: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub warnings: Vec<String>,
    pub scan_warning_count: usize,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub rejected_namespace_candidates: Vec<RejectedNamespaceCandidate>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub coverage: Option<CoverageSummary>,
    pub incomplete_count: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub coverage_ledger: Option<CoverageLedger>,
}

impl OperatorInspection {
    pub fn should_exit_strict(&self) -> bool {
        self.scan_warning_count > 0
            || self.incomplete_count > 0
            || self
                .coverage_ledger
                .as_ref()
                .is_some_and(|l| l.has_incomplete())
    }
}

#[allow(dead_code)]
pub async fn inspect_operator_with_options(
    client: &Client,
    operator: &OperatorInstance,
    kind_map: &KindMap,
    gvr_map: &GvrMap,
    gk_map: &GroupKindMap,
    cross_namespace: bool,
) -> Result<OperatorInspection> {
    inspect_operator_with_options_ledger(
        client,
        operator,
        kind_map,
        gvr_map,
        gk_map,
        cross_namespace,
        None,
    )
    .await
}

#[allow(clippy::too_many_arguments)]
pub async fn inspect_operator_with_options_ledger(
    client: &Client,
    operator: &OperatorInstance,
    kind_map: &KindMap,
    gvr_map: &GvrMap,
    gk_map: &GroupKindMap,
    cross_namespace: bool,
    external_ledger: Option<SharedLedger>,
) -> Result<OperatorInspection> {
    let mut olm_resources = Vec::new();
    let mut controller_resources = Vec::new();
    let mut cr_resources = Vec::new();
    let mut related_resources = Vec::new();
    let mut namespace_scope = None;
    let mut scope_warnings = Vec::new();
    let mut all_warnings = Vec::new();
    let mut scan_warning_count = 0usize;
    let mut rejected_namespace_candidates = Vec::new();
    let shared_ledger: SharedLedger =
        external_ledger.unwrap_or_else(|| Arc::new(std::sync::Mutex::new(CoverageLedger::new())));

    // OLM resources
    if let Some(sub) = &operator.subscription {
        olm_resources.push(InspectedResource {
            id: sub.clone(),
            source_id: None,
            relationship: Relationship::Olm,
            evidence: "Subscription".to_string(),
            confidence: Confidence::Managed,
        });
    }
    olm_resources.push(InspectedResource {
        id: operator.csv.clone(),
        source_id: None,
        relationship: Relationship::Olm,
        evidence: "ClusterServiceVersion".to_string(),
        confidence: Confidence::Managed,
    });

    // Controller resources (Deployments, ServiceAccounts, Pods)
    for deploy_name in &operator.deployments {
        controller_resources.push(InspectedResource {
            id: ResourceId {
                group: "apps".to_string(),
                version: "v1".to_string(),
                kind: "Deployment".to_string(),
                namespace: Some(operator.install_namespace.clone()),
                name: deploy_name.clone(),
                uid: None,
            },
            source_id: None,
            relationship: Relationship::InstallStrategy,
            evidence: "CSV installStrategy.deployments".to_string(),
            confidence: Confidence::Managed,
        });
    }
    for sa_name in &operator.service_accounts {
        controller_resources.push(InspectedResource {
            id: ResourceId {
                group: String::new(),
                version: "v1".to_string(),
                kind: "ServiceAccount".to_string(),
                namespace: Some(operator.install_namespace.clone()),
                name: sa_name.clone(),
                uid: None,
            },
            source_id: None,
            relationship: Relationship::InstallStrategy,
            evidence: "CSV installStrategy serviceAccountName".to_string(),
            confidence: Confidence::Managed,
        });
    }

    // Discover controller pods via deployment selector
    eprint!("🔍 Discovering controller pods...");
    let (pods, pod_warnings) =
        discover_controller_pods(client, operator, kind_map, Some(&shared_ledger)).await;
    for pod_id in &pods {
        controller_resources.push(InspectedResource {
            id: pod_id.clone(),
            source_id: None,
            relationship: Relationship::SelectorMatch,
            evidence: "Deployment selector match".to_string(),
            confidence: Confidence::Attributed,
        });
    }
    for w in &pod_warnings {
        all_warnings.push(format!("{}", w));
        scan_warning_count += 1;
    }
    eprintln!(" found {} pods", pods.len());

    // CR instances (owned CRDs)
    eprint!("🔍 Discovering CR instances...");
    let cr_report = discover_cr_instances_opts(
        client,
        &operator.owned_crds,
        gvr_map,
        gk_map,
        Some(shared_ledger.clone()),
    )
    .await;
    eprintln!(" found {} instances", cr_report.instances.len());
    for w in &cr_report.unavailable_crds {
        all_warnings.push(format!("{}", w));
        scan_warning_count += 1;
    }
    for cr in &cr_report.instances {
        let (rel, ev, conf) = classify_cr_instance(cr);
        cr_resources.push(InspectedResource {
            id: cr.id.clone(),
            source_id: None,
            relationship: rel,
            evidence: ev,
            confidence: conf,
        });
    }

    // Fetch metadata-only CRD catalog lazily — only when owned CRDs exist
    let crd_catalog: Option<CrdCatalog> = if !operator.owned_crds.is_empty() {
        let catalog = fetch_crd_catalog(client, kind_map, Some(&shared_ledger)).await;
        if let CrdCatalog::Unavailable(ref w) = catalog {
            all_warnings.push(format!("{}", w));
            scan_warning_count += 1;
        }
        Some(catalog)
    } else {
        None
    };

    // Related CRD instances (label-based)
    eprint!("🔍 Discovering related CRDs...");
    let owned_crd_set: HashSet<&str> = operator.owned_crds.iter().map(|s| s.as_str()).collect();
    let (target_part_of_values, seed_errors) = compute_part_of_seeds_opts(
        &operator.owned_crds,
        kind_map,
        client,
        Some(shared_ledger.clone()),
        crd_catalog.as_ref(),
    )
    .await;
    for w in &seed_errors {
        all_warnings.push(format!("{}", w));
        scan_warning_count += 1;
    }
    let related_report = discover_related_crd_instances_opts(
        client,
        &owned_crd_set,
        &target_part_of_values,
        kind_map,
        gvr_map,
        gk_map,
        Some(shared_ledger.clone()),
        crd_catalog.as_ref(),
    )
    .await;
    for w in &related_report.unavailable_crds {
        all_warnings.push(format!("{}", w));
        scan_warning_count += 1;
    }
    eprintln!(" found {} related instances", related_report.instance_count);

    for cr in &related_report.instances {
        let label_desc = if cr.decisive_label_pairs.is_empty() {
            "label match".to_string()
        } else {
            cr.decisive_label_pairs
                .iter()
                .map(|(k, v)| format!("{}={}", k, v))
                .collect::<Vec<_>>()
                .join(", ")
        };
        related_resources.push(InspectedResource {
            id: cr.id.clone(),
            source_id: Some(operator.csv.clone()),
            relationship: Relationship::LabelMatch,
            evidence: format!("related CRD label: {}", label_desc),
            confidence: Confidence::Inferred,
        });
    }

    // Cross-namespace scope discovery + scan (before building categories so cr_resources can grow)
    if cross_namespace {
        eprint!("🔍 Discovering namespace scope...");
        let scope_result = crate::analyzers::namespace_scope::discover_operator_namespaces_opts(
            client,
            operator,
            kind_map,
            gvr_map,
            gk_map,
            Some(shared_ledger.clone()),
            crd_catalog.as_ref(),
        )
        .await?;
        eprintln!(
            " found {} candidate namespaces",
            scope_result.candidates.len()
        );
        scope_warnings = scope_result.info_messages;
        for w in &scope_result.scan_failures {
            all_warnings.push(format!("{}", w));
            scan_warning_count += 1;
        }
        namespace_scope = Some(scope_result.candidates.clone());
        rejected_namespace_candidates = scope_result.rejected_candidates;

        let scan_result = scan_candidate_namespaces_with_ledger(
            client,
            &scope_result.candidates,
            kind_map,
            None,
            Some(shared_ledger.clone()),
        )
        .await;
        scan_warning_count += scan_result.namespace_warnings.len();
        scope_warnings.extend(scan_result.namespace_warnings.clone());
        all_warnings.extend(scan_result.namespace_warnings);
        for w in &scan_result.scan_warnings {
            all_warnings.push(format!("{}", w));
            scan_warning_count += 1;
        }
        if !scan_result.scanned_namespaces.is_empty() {
            eprintln!(
                "   Scanned {} namespace(s), {} total resources",
                scan_result.scanned_namespaces.len(),
                scan_result.index.by_uid.len()
            );
        }

        // BFS from known CR UIDs through children_of to find actual descendants
        let known_cr_map: HashMap<String, ResourceId> = cr_resources
            .iter()
            .filter_map(|r| r.id.uid.clone().map(|uid| (uid, r.id.clone())))
            .collect();
        let known_cr_uids: HashSet<String> = known_cr_map.keys().cloned().collect();
        let mut reachable = HashSet::new();
        let mut bfs_queue: Vec<String> = known_cr_uids.iter().cloned().collect();
        while let Some(parent_uid) = bfs_queue.pop() {
            if let Some(children) = scan_result.index.children_of.get(&parent_uid) {
                for child_uid in children {
                    if reachable.insert(child_uid.clone()) {
                        bfs_queue.push(child_uid.clone());
                    }
                }
            }
        }
        let mut descendant_count = 0usize;
        for uid in &reachable {
            if known_cr_uids.contains(uid) {
                continue;
            }
            if let Some(info) = scan_result.index.by_uid.get(uid) {
                let parent_uid = info
                    .owner_refs
                    .first()
                    .map(|o| o.uid.clone())
                    .unwrap_or_default();
                let source = known_cr_map.get(&parent_uid).cloned().or_else(|| {
                    scan_result
                        .index
                        .by_uid
                        .get(&parent_uid)
                        .map(|p| ResourceId {
                            group: p.group.clone(),
                            version: kind_map
                                .get(&p.kind)
                                .map(|ki| ki.version.clone())
                                .unwrap_or_default(),
                            kind: p.kind.clone(),
                            namespace: p.namespace.clone(),
                            name: p.name.clone(),
                            uid: Some(p.uid.clone()),
                        })
                });
                let evidence_str = source
                    .as_ref()
                    .map(|s| format!("ownerRef descendant of {}/{}", s.kind, s.name))
                    .unwrap_or_else(|| "ownerRef descendant of CR root".to_string());
                cr_resources.push(InspectedResource {
                    id: ResourceId {
                        group: info.group.clone(),
                        version: kind_map
                            .get(&info.kind)
                            .map(|ki| ki.version.clone())
                            .unwrap_or_default(),
                        kind: info.kind.clone(),
                        namespace: info.namespace.clone(),
                        name: info.name.clone(),
                        uid: Some(info.uid.clone()),
                    },
                    source_id: source,
                    relationship: Relationship::OwnerRef,
                    evidence: evidence_str,
                    confidence: Confidence::Managed,
                });
                descendant_count += 1;
            }
        }
        if descendant_count > 0 {
            eprintln!(
                "   Found {} ownerRef descendants in scanned namespaces",
                descendant_count
            );
        }
    }

    // Build categories after cross-ns scan has enriched cr_resources
    let mut categories = Vec::new();
    if !olm_resources.is_empty() {
        categories.push(InspectionCategory {
            label: "OLM".to_string(),
            resources: olm_resources,
        });
    }
    if !controller_resources.is_empty() {
        categories.push(InspectionCategory {
            label: "Controller".to_string(),
            resources: controller_resources,
        });
    }
    if !cr_resources.is_empty() {
        categories.push(InspectionCategory {
            label: "CR Instances (owned CRDs)".to_string(),
            resources: cr_resources,
        });
    }
    if !related_resources.is_empty() {
        categories.push(InspectionCategory {
            label: "Related CR Instances (label, correlation only)".to_string(),
            resources: related_resources,
        });
    }

    let mut unique_crds: Vec<String> = operator.owned_crds.clone();
    unique_crds.dedup();

    let (snapshot_coverage, snapshot_incomplete, snapshot_ledger) =
        shared_ledger.lock().unwrap().snapshot();

    Ok(OperatorInspection {
        operator_name: operator
            .package_name
            .clone()
            .unwrap_or_else(|| operator.csv.name.clone()),
        csv_name: operator.csv.name.clone(),
        install_namespace: operator.install_namespace.clone(),
        subscription_name: operator.subscription.as_ref().map(|s| s.name.clone()),
        owned_crds: unique_crds,
        categories,
        namespace_scope,
        scope_warnings,
        warnings: all_warnings,
        scan_warning_count,
        rejected_namespace_candidates,
        coverage: snapshot_coverage,
        incomplete_count: snapshot_incomplete,
        coverage_ledger: snapshot_ledger,
    })
}

fn classify_cr_instance(cr: &CrInstance) -> (Relationship, String, Confidence) {
    match cr.provenance {
        Provenance::Managed => (
            Relationship::OwnerRef,
            "ownerRef UID match to CSV-owned CRD instance".to_string(),
            Confidence::Managed,
        ),
        Provenance::LikelyManaged => (
            Relationship::OwnedCrdInstance,
            "ownerRef chain (likely managed, no direct UID match)".to_string(),
            Confidence::Attributed,
        ),
        Provenance::Unknown => (
            Relationship::OwnedCrdInstance,
            "CSV-owned CRD instance (no ownerRef to operator)".to_string(),
            Confidence::Attributed,
        ),
    }
}

async fn discover_controller_pods(
    client: &Client,
    operator: &OperatorInstance,
    kind_map: &KindMap,
    ledger: Option<&SharedLedger>,
) -> (Vec<ResourceId>, Vec<crate::kube::resource::ScanWarning>) {
    use crate::kube::scanner::{get_with_retry_ledger, list_with_selector_retry_ledger};

    let mut pods = Vec::new();
    let mut warnings = Vec::new();
    let ns = Some(operator.install_namespace.as_str());
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

        let deploy = match get_with_retry_ledger(
            &api,
            deploy_name,
            &deploy_info.group,
            &deploy_info.version,
            &deploy_info.plural,
            ledger,
            ns,
            QueryRequirement::Required,
        )
        .await
        {
            Ok(d) => d,
            Err(w) => {
                if !matches!(
                    w,
                    crate::kube::resource::ScanWarning::Other { ref message, .. }
                        if message.contains("NotFound") || message.contains("not found")
                ) {
                    warnings.push(w);
                }
                continue;
            }
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

        match list_with_selector_retry_ledger(
            &pod_api,
            &label_str,
            &pod_info.group,
            &pod_info.version,
            &pod_info.plural,
            ledger,
            ns,
            QueryRequirement::Required,
        )
        .await
        {
            Ok(pod_list) => {
                for pod in pod_list {
                    let name = match pod.metadata.name {
                        Some(n) => n,
                        None => continue,
                    };
                    pods.push(ResourceId {
                        group: String::new(),
                        version: "v1".to_string(),
                        kind: "Pod".to_string(),
                        namespace: Some(operator.install_namespace.clone()),
                        name,
                        uid: pod.metadata.uid.clone(),
                    });
                }
            }
            Err(w) => {
                warnings.push(w);
            }
        }
    }
    (pods, warnings)
}

pub fn print_inspection(inspection: &OperatorInspection, output: &OutputFormat, verbose: bool) {
    match output {
        OutputFormat::Json => print_inspection_json(inspection),
        OutputFormat::Table => print_inspection_table(inspection),
        OutputFormat::Tree => print_inspection_tree(inspection, verbose),
    }
}

fn print_inspection_tree(inspection: &OperatorInspection, verbose: bool) {
    println!("\x1b[1mOperator: {}\x1b[0m", inspection.operator_name);
    println!("CSV: {}", inspection.csv_name);
    println!("Install namespace: {}", inspection.install_namespace);
    if let Some(sub) = &inspection.subscription_name {
        println!("Subscription: {}", sub);
    }
    println!();

    for category in &inspection.categories {
        println!("── {} ──", category.label);

        // Group by namespace
        let mut by_ns: HashMap<Option<String>, Vec<&InspectedResource>> = HashMap::new();
        for r in &category.resources {
            by_ns.entry(r.id.namespace.clone()).or_default().push(r);
        }

        let mut ns_keys: Vec<Option<String>> = by_ns.keys().cloned().collect();
        ns_keys.sort();

        let multi_ns = ns_keys.len() > 1 || ns_keys.first().map(|k| k.is_some()).unwrap_or(false);

        for ns_key in &ns_keys {
            if multi_ns {
                match ns_key {
                    Some(ns) => println!("  Namespace: {}", ns),
                    None => println!("  (cluster-scoped)"),
                }
            }
            let indent = if multi_ns { "    " } else { "  " };
            for r in &by_ns[ns_key] {
                let confidence_str = match r.confidence {
                    Confidence::Managed => "Managed",
                    Confidence::Attributed => "Attributed",
                    Confidence::Inferred => "Inferred",
                };
                let rel_str = relationship_display(&r.relationship);
                let source_str = r
                    .source_id
                    .as_ref()
                    .map(|s| {
                        let ns = s
                            .namespace
                            .as_ref()
                            .map(|n| format!(" ns:{}", n))
                            .unwrap_or_else(|| " cluster-scoped".to_string());
                        let group_prefix = if s.group.is_empty() {
                            String::new()
                        } else {
                            format!("{}/", s.group)
                        };
                        format!(" ← {}{}/{}{}", group_prefix, s.kind, s.name, ns)
                    })
                    .unwrap_or_default();
                println!(
                    "{}{}/{}  \x1b[2m[{}: {}, {}]{}\x1b[0m",
                    indent, r.id.kind, r.id.name, rel_str, r.evidence, confidence_str, source_str
                );
            }
        }
        println!();
    }

    // Namespace scope (cross-namespace)
    if let Some(scope) = &inspection.namespace_scope {
        println!("── Namespace Scope ({}) ──", scope.len());
        for candidate in scope {
            let evidence_strs: Vec<&str> = candidate
                .evidence
                .iter()
                .map(|e| match e {
                    crate::analyzers::namespace_scope::NamespaceEvidence::InstallNamespace => {
                        "install"
                    }
                    crate::analyzers::namespace_scope::NamespaceEvidence::OperatorGroupTarget => {
                        "OG target"
                    }
                    crate::analyzers::namespace_scope::NamespaceEvidence::OperatorGroupStatus => {
                        "OG status"
                    }
                    crate::analyzers::namespace_scope::NamespaceEvidence::OwnedCrdInstance {
                        ..
                    } => "CRD instance",
                    crate::analyzers::namespace_scope::NamespaceEvidence::LabelEvidence {
                        ..
                    } => "label",
                    crate::analyzers::namespace_scope::NamespaceEvidence::SpecNamespaceRef {
                        ..
                    } => "spec-ns-ref",
                })
                .collect();
            println!(
                "  {}  \x1b[2m[{}]\x1b[0m",
                candidate.namespace,
                evidence_strs.join(", ")
            );
        }
        println!();
    }

    for warning in &inspection.scope_warnings {
        println!("  \x1b[33m⚠ {}\x1b[0m", warning);
    }

    // Owned CRDs
    if !inspection.owned_crds.is_empty() {
        println!("── Owned CRDs ({}) ──", inspection.owned_crds.len());
        for crd in &inspection.owned_crds {
            println!("  {}", crd);
        }
        println!();
    }

    // Summary
    let total: usize = inspection
        .categories
        .iter()
        .map(|c| c.resources.len())
        .sum();
    println!(
        "\x1b[1mSummary\x1b[0m: {} resources across {} categories, {} owned CRDs",
        total,
        inspection.categories.len(),
        inspection.owned_crds.len()
    );
    if inspection.scan_warning_count > 0 {
        eprintln!(
            "\n⚠ {} scan warning(s). Results may be incomplete.",
            inspection.scan_warning_count
        );
        let display_warnings = if verbose {
            &inspection.warnings[..]
        } else if inspection.warnings.len() > 5 {
            &inspection.warnings[..5]
        } else {
            &inspection.warnings[..]
        };
        for w in display_warnings {
            eprintln!("  \x1b[33m⚠ {}\x1b[0m", w);
        }
        if !verbose && inspection.warnings.len() > 5 {
            eprintln!(
                "  ... and {} more (use --verbose to see all)",
                inspection.warnings.len() - 5
            );
        }
    }
}

pub fn relationship_display(r: &Relationship) -> &'static str {
    match r {
        Relationship::OwnerRef => "ownerRef",
        Relationship::InstallStrategy => "installStrategy",
        Relationship::Olm => "olm",
        Relationship::SpecRef => "spec-ref",
        Relationship::OwnedCrdInstance => "owned-crd-instance",
        Relationship::SelectorMatch => "selector-match",
        Relationship::SameOperatorCrd => "same-operator-crd",
        Relationship::LabelMatch => "label-match",
    }
}

fn print_inspection_table(inspection: &OperatorInspection) {
    use comfy_table::Table;

    let mut table = Table::new();
    table.set_header(vec![
        "Category",
        "Group",
        "Kind",
        "Name",
        "Namespace",
        "Relationship",
        "Confidence",
        "Source",
    ]);

    for category in &inspection.categories {
        for r in &category.resources {
            let ns = r.id.namespace.as_deref().unwrap_or("(cluster-scoped)");
            let source = r
                .source_id
                .as_ref()
                .map(|s| {
                    let g = if s.group.is_empty() {
                        String::new()
                    } else {
                        format!("{}/", s.group)
                    };
                    let sns = s.namespace.as_deref().unwrap_or("cluster");
                    format!("{}{}/{} ({})", g, s.kind, s.name, sns)
                })
                .unwrap_or_default();
            let conf = match r.confidence {
                Confidence::Managed => "Managed",
                Confidence::Attributed => "Attributed",
                Confidence::Inferred => "Inferred",
            };
            table.add_row(vec![
                &category.label,
                &r.id.group,
                &r.id.kind,
                &r.id.name,
                ns,
                relationship_display(&r.relationship),
                conf,
                &source,
            ]);
        }
    }

    println!("{}", table);
}

fn print_inspection_json(inspection: &OperatorInspection) {
    println!(
        "{}",
        serde_json::to_string_pretty(inspection).unwrap_or_default()
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::teardown::planner::{CrInstance, DiscoverySource, Provenance};
    use std::collections::HashMap;

    #[test]
    fn test_classify_cr_instance_managed() {
        let cr = CrInstance {
            id: ResourceId {
                group: "example.com".into(),
                version: "v1".into(),
                kind: "Widget".into(),
                namespace: Some("default".into()),
                name: "w1".into(),
                uid: Some("uid-1".into()),
            },
            owner_refs: vec![],
            api_owner_key: "widgets.example.com".into(),
            labels: HashMap::new(),
            managed_field_managers: vec![],
            provenance: Provenance::Managed,
            discovery_source: DiscoverySource::Direct,
            decisive_label_pairs: vec![],
            ownerref_to_owned_api_kind: None,
        };
        let (rel, _ev, conf) = classify_cr_instance(&cr);
        assert!(matches!(rel, Relationship::OwnerRef));
        assert!(matches!(conf, Confidence::Managed));
    }

    #[test]
    fn test_classify_cr_instance_unknown() {
        let cr = CrInstance {
            id: ResourceId {
                group: "example.com".into(),
                version: "v1".into(),
                kind: "Widget".into(),
                namespace: Some("default".into()),
                name: "w2".into(),
                uid: None,
            },
            owner_refs: vec![],
            api_owner_key: "widgets.example.com".into(),
            labels: HashMap::new(),
            managed_field_managers: vec![],
            provenance: Provenance::Unknown,
            discovery_source: DiscoverySource::Direct,
            decisive_label_pairs: vec![],
            ownerref_to_owned_api_kind: None,
        };
        let (_rel, _ev, conf) = classify_cr_instance(&cr);
        assert!(matches!(conf, Confidence::Attributed));
    }

    #[test]
    fn test_inspection_json_roundtrip() {
        let inspection = OperatorInspection {
            operator_name: "test-operator".into(),
            csv_name: "test-operator.v1.0.0".into(),
            install_namespace: "test-ns".into(),
            subscription_name: Some("test-sub".into()),
            owned_crds: vec!["widgets.example.com".into()],
            categories: vec![InspectionCategory {
                label: "OLM".into(),
                resources: vec![InspectedResource {
                    id: ResourceId {
                        group: "operators.coreos.com".into(),
                        version: "v1alpha1".into(),
                        kind: "Subscription".into(),
                        namespace: Some("test-ns".into()),
                        name: "test-sub".into(),
                        uid: None,
                    },
                    source_id: None,
                    relationship: Relationship::Olm,
                    evidence: "Subscription".into(),
                    confidence: Confidence::Managed,
                }],
            }],
            namespace_scope: None,
            scope_warnings: vec![],
            warnings: vec![],
            scan_warning_count: 0,
            rejected_namespace_candidates: vec![],
            coverage: None,
            incomplete_count: 0,
            coverage_ledger: None,
        };
        let json = serde_json::to_string(&inspection).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed["operator_name"].as_str().unwrap(), "test-operator");
        assert_eq!(
            parsed["categories"][0]["resources"]
                .as_array()
                .unwrap()
                .len(),
            1
        );
    }

    #[test]
    fn test_relationship_serde() {
        let rel = Relationship::OwnerRef;
        let json = serde_json::to_string(&rel).unwrap();
        assert_eq!(json, "\"ownerRef\"");

        let rel2 = Relationship::LabelMatch;
        let json2 = serde_json::to_string(&rel2).unwrap();
        assert_eq!(json2, "\"label-match\"");

        let rel3 = Relationship::SpecRef;
        let json3 = serde_json::to_string(&rel3).unwrap();
        assert_eq!(json3, "\"spec-ref\"");

        let rel4 = Relationship::OwnedCrdInstance;
        let json4 = serde_json::to_string(&rel4).unwrap();
        assert_eq!(json4, "\"owned-crd-instance\"");
    }

    #[test]
    fn test_source_id_serialization() {
        let resource = InspectedResource {
            id: ResourceId {
                group: "apps".into(),
                version: "v1".into(),
                kind: "Deployment".into(),
                namespace: Some("ns-a".into()),
                name: "child".into(),
                uid: Some("uid-child".into()),
            },
            source_id: Some(ResourceId {
                group: "example.com".into(),
                version: "v1".into(),
                kind: "Widget".into(),
                namespace: None,
                name: "root".into(),
                uid: Some("uid-root".into()),
            }),
            relationship: Relationship::OwnerRef,
            evidence: "ownerRef descendant of Widget/root".into(),
            confidence: Confidence::Managed,
        };
        let json = serde_json::to_string(&resource).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed["source_id"]["kind"].as_str().unwrap(), "Widget");
        assert_eq!(parsed["source_id"]["namespace"], serde_json::Value::Null);
        assert_eq!(
            parsed["source_id"]["group"].as_str().unwrap(),
            "example.com"
        );
    }

    #[test]
    fn test_source_id_null_when_none() {
        let resource = InspectedResource {
            id: ResourceId {
                group: String::new(),
                version: "v1".into(),
                kind: "Pod".into(),
                namespace: Some("default".into()),
                name: "p1".into(),
                uid: None,
            },
            source_id: None,
            relationship: Relationship::Olm,
            evidence: "test".into(),
            confidence: Confidence::Managed,
        };
        let json = serde_json::to_string(&resource).unwrap();
        assert!(!json.contains("source_id"));
    }

    #[test]
    fn test_inspection_json_includes_coverage_records() {
        use crate::kube::resource::{
            CoverageLedger, QueryOperation, QueryOutcome, QueryRecord, QueryRequirement,
        };

        let mut ledger = CoverageLedger::new();
        ledger.record(QueryRecord {
            gvr: "v1/pods".into(),
            namespace: Some("test-ns".into()),
            scope: "namespaced".into(),
            operation: QueryOperation::List,
            target_name: None,
            label_selector: None,
            field_selector: None,
            outcome: QueryOutcome::Success { count: 3, pages: 1 },
            elapsed_ms: 50,
            requirement: QueryRequirement::Required,
        });

        let inspection = OperatorInspection {
            operator_name: "test-op".into(),
            csv_name: "test-op.v1".into(),
            install_namespace: "test-ns".into(),
            subscription_name: None,
            owned_crds: vec![],
            categories: vec![],
            namespace_scope: None,
            scope_warnings: vec![],
            warnings: vec![],
            scan_warning_count: 0,
            rejected_namespace_candidates: vec![],
            coverage: Some(ledger.summary()),
            incomplete_count: 0,
            coverage_ledger: Some(ledger),
        };

        let json = serde_json::to_string_pretty(&inspection).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();

        assert!(
            parsed["coverage_ledger"].is_object(),
            "ledger should be serialized"
        );
        let records = parsed["coverage_ledger"]["records"].as_array().unwrap();
        assert_eq!(records.len(), 1);
        assert_eq!(records[0]["gvr"], "v1/pods");
        assert_eq!(records[0]["outcome"]["outcome"], "Success");
        assert_eq!(records[0]["outcome"]["count"], 3);
        assert_eq!(records[0]["requirement"], "Required");

        assert!(parsed["coverage"].is_object(), "summary should be present");
        assert_eq!(parsed["coverage"]["total_queries"], 1);
        assert_eq!(parsed["coverage"]["success"], 1);
    }

    #[test]
    fn test_strict_with_scan_warning_count() {
        let inspection = OperatorInspection {
            operator_name: "test-op".into(),
            csv_name: "test-op.v1".into(),
            install_namespace: "test-ns".into(),
            subscription_name: None,
            owned_crds: vec![],
            categories: vec![],
            namespace_scope: None,
            scope_warnings: vec![],
            warnings: vec!["apps/v1/deployments (403 Forbidden)".into()],
            scan_warning_count: 1,
            rejected_namespace_candidates: vec![],
            coverage: None,
            incomplete_count: 0,
            coverage_ledger: None,
        };

        assert!(
            inspection.scan_warning_count > 0,
            "uninstrumented warning should trigger strict via scan_warning_count"
        );
    }

    #[test]
    fn test_strict_not_triggered_by_optional_absent() {
        use crate::kube::resource::{
            CoverageLedger, QueryOperation, QueryOutcome, QueryRecord, QueryRequirement,
        };

        let mut ledger = CoverageLedger::new();
        ledger.record(QueryRecord {
            gvr: "custom/v1/widgets".into(),
            namespace: None,
            scope: "cluster".into(),
            operation: QueryOperation::List,
            target_name: None,
            label_selector: None,
            field_selector: None,
            outcome: QueryOutcome::ApiAbsent,
            elapsed_ms: 5,
            requirement: QueryRequirement::Optional,
        });

        let inspection = OperatorInspection {
            operator_name: "test-op".into(),
            csv_name: "test-op.v1".into(),
            install_namespace: "test-ns".into(),
            subscription_name: None,
            owned_crds: vec![],
            categories: vec![],
            namespace_scope: None,
            scope_warnings: vec![],
            warnings: vec![],
            scan_warning_count: 0,
            rejected_namespace_candidates: vec![],
            coverage: Some(ledger.summary()),
            incomplete_count: 0,
            coverage_ledger: Some(ledger),
        };

        assert_eq!(inspection.scan_warning_count, 0);
        assert_eq!(inspection.incomplete_count, 0);
        assert!(
            !inspection
                .coverage_ledger
                .as_ref()
                .unwrap()
                .has_incomplete(),
            "optional absent should not be strict failure"
        );
        assert!(
            !inspection.should_exit_strict(),
            "should_exit_strict must be false for optional absent"
        );
    }

    #[test]
    fn test_should_exit_strict_truth_table() {
        use crate::kube::resource::{
            CoverageLedger, QueryOperation, QueryOutcome, QueryRecord, QueryRequirement,
        };

        let make = |scan_warning_count: usize, records: Vec<(QueryOutcome, QueryRequirement)>| {
            let mut ledger = CoverageLedger::new();
            for (outcome, req) in records {
                ledger.record(QueryRecord {
                    gvr: "v1/test".into(),
                    namespace: None,
                    scope: "cluster".into(),
                    operation: QueryOperation::List,
                    target_name: None,
                    label_selector: None,
                    field_selector: None,
                    outcome,
                    elapsed_ms: 0,
                    requirement: req,
                });
            }
            let incomplete = ledger.incomplete_count();
            OperatorInspection {
                operator_name: "t".into(),
                csv_name: "t.v1".into(),
                install_namespace: "ns".into(),
                subscription_name: None,
                owned_crds: vec![],
                categories: vec![],
                namespace_scope: None,
                scope_warnings: vec![],
                warnings: vec![],
                scan_warning_count,
                rejected_namespace_candidates: vec![],
                coverage: Some(ledger.summary()),
                incomplete_count: incomplete,
                coverage_ledger: Some(ledger),
            }
        };

        // No warnings, no records → no strict
        let i = make(0, vec![]);
        assert!(!i.should_exit_strict());

        // Success only → no strict
        let i = make(
            0,
            vec![(
                QueryOutcome::Success { count: 5, pages: 1 },
                QueryRequirement::Required,
            )],
        );
        assert!(!i.should_exit_strict());

        // Optional absent → no strict
        let i = make(
            0,
            vec![(QueryOutcome::ApiAbsent, QueryRequirement::Optional)],
        );
        assert!(!i.should_exit_strict());

        // Required absent → strict (404 on required query)
        let i = make(
            0,
            vec![(QueryOutcome::ApiAbsent, QueryRequirement::Required)],
        );
        assert!(i.should_exit_strict(), "Required 404 must trigger strict");

        // Required forbidden → strict
        let i = make(
            0,
            vec![(
                QueryOutcome::Forbidden { status: 403 },
                QueryRequirement::Required,
            )],
        );
        assert!(i.should_exit_strict());

        // Optional forbidden → strict (could not determine)
        let i = make(
            0,
            vec![(
                QueryOutcome::Forbidden { status: 403 },
                QueryRequirement::Optional,
            )],
        );
        assert!(i.should_exit_strict());

        // scan_warning_count alone → strict
        let i = make(1, vec![]);
        assert!(i.should_exit_strict());

        // Optional ListUnsupported → no strict
        let i = make(
            0,
            vec![(QueryOutcome::ListUnsupported, QueryRequirement::Optional)],
        );
        assert!(!i.should_exit_strict());

        // Required ListUnsupported → strict
        let i = make(
            0,
            vec![(QueryOutcome::ListUnsupported, QueryRequirement::Required)],
        );
        assert!(i.should_exit_strict());
    }
}
