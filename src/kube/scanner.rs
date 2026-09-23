use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Instant;

use anyhow::Result;
use futures::stream::StreamExt;
use kube::{
    Client,
    api::{Api, ApiResource, DynamicObject, ListParams},
    core::GroupVersion,
};

use crate::analyzers::spec_ref::{collect_string_values, extract_well_known_refs};
use crate::kube::discovery::KindMap;
use crate::kube::resource::*;

const MAX_RETRIES: usize = 2;

pub(crate) fn resolve_name_matches(
    spec_strs: &[(String, String)],
    self_name: &str,
    by_name: &HashMap<String, Vec<String>>,
    already_found: &HashSet<(String, String)>,
) -> Vec<SpecRef> {
    let mut refs = Vec::new();
    let mut seen = HashSet::new();
    for (field_path, value) in spec_strs {
        if value == self_name || !is_plausible_resource_name(value) {
            continue;
        }
        if let Some(kinds) = by_name.get(value) {
            for kind in kinds {
                let key = (kind.clone(), value.clone());
                if already_found.contains(&key) || !seen.insert(key) {
                    continue;
                }
                refs.push(SpecRef {
                    target_kind: kind.clone(),
                    target_name: value.clone(),
                    field_path: field_path.clone(),
                });
            }
        }
    }
    refs
}

fn is_plausible_resource_name(s: &str) -> bool {
    if s.len() < 3 || s.contains(' ') || s.contains('\n') {
        return false;
    }
    if s.contains("://") {
        return false;
    }
    if s.starts_with('/') {
        return false;
    }
    if s.parse::<f64>().is_ok() {
        return false;
    }
    if matches!(
        s,
        "true" | "false" | "null" | "TCP" | "UDP" | "HTTP" | "HTTPS" | "REST" | "gRPC"
    ) {
        return false;
    }
    if s.contains('/') && s.contains(':') {
        return false;
    }
    true
}

pub async fn scan_namespace(
    client: &Client,
    namespace: &str,
    kind_map: &KindMap,
    include_events: bool,
    refs: bool,
) -> Result<(NamespaceIndex, Vec<ScanWarning>)> {
    let skip_kinds: HashSet<&str> = if include_events {
        HashSet::new()
    } else {
        HashSet::from(["Event"])
    };

    let scan_targets: Vec<_> = kind_map
        .iter()
        .filter(|(k, info)| info.namespaced && info.listable && !skip_kinds.contains(k.as_str()))
        .map(|(k, v)| (k.clone(), v.clone()))
        .collect();

    let total = scan_targets.len();
    let scanned = Arc::new(AtomicUsize::new(0));

    let futs = scan_targets.into_iter().map(|(kind, info)| {
        let client = client.clone();
        let ns = namespace.to_string();
        let scanned = scanned.clone();

        async move {
            let gvk = GroupVersion::gv(&info.group, &info.version).with_kind(&kind);
            let ar = ApiResource::from_gvk_with_plural(&gvk, &info.plural);
            let api: Api<DynamicObject> = Api::namespaced_with(client, &ns, &ar);

            let mut last_err = None;
            for attempt in 0..=MAX_RETRIES {
                let result = api.list(&ListParams::default()).await;
                if attempt == 0 {
                    let count = scanned.fetch_add(1, Ordering::Relaxed) + 1;
                    eprint!("\r\x1b[2K🔍 Scanning resources... ({}/{})", count, total);
                }

                match result {
                    Ok(list) => {
                        let items: Vec<ScanItem> = list
                            .items
                            .into_iter()
                            .filter_map(|obj| {
                                let data = obj.data;
                                let metadata = obj.metadata;
                                let uid = metadata.uid?;
                                let name = metadata.name?;
                                let ns = metadata.namespace;
                                let owner_refs = metadata
                                    .owner_references
                                    .unwrap_or_default()
                                    .into_iter()
                                    .map(|r| OwnerRef {
                                        api_version: r.api_version,
                                        kind: r.kind,
                                        name: r.name,
                                        uid: r.uid,
                                        controller: r.controller.unwrap_or(false),
                                    })
                                    .collect();

                                let (wk_refs, spec_strs) = if refs {
                                    let wk = extract_well_known_refs(&data);
                                    let mut strs = Vec::new();
                                    if let Some(spec) = data.get("spec") {
                                        let mut path = vec!["spec".to_string()];
                                        collect_string_values(spec, &mut path, &mut strs);
                                    }
                                    (wk, strs)
                                } else {
                                    (vec![], vec![])
                                };

                                let labels =
                                    metadata.labels.unwrap_or_default().into_iter().collect();
                                let annotations = metadata
                                    .annotations
                                    .unwrap_or_default()
                                    .into_iter()
                                    .collect();

                                Some((
                                    ResourceInfo {
                                        kind: kind.clone(),
                                        name,
                                        namespace: ns,
                                        uid,
                                        owner_refs,
                                        labels,
                                        annotations,
                                    },
                                    wk_refs,
                                    spec_strs,
                                ))
                            })
                            .collect();
                        return Ok(items);
                    }
                    Err(e) => {
                        let mut warning = ScanWarning::from_kube_error(
                            &e,
                            &info.group,
                            &info.version,
                            &info.plural,
                        );
                        if warning.is_retryable() && attempt < MAX_RETRIES {
                            let delay =
                                std::time::Duration::from_millis(500 * (attempt as u64 + 1));
                            tokio::time::sleep(delay).await;
                            last_err = Some(warning);
                            continue;
                        }
                        warning.set_retries(attempt);
                        return Err(warning);
                    }
                }
            }
            let mut w = last_err.unwrap();
            w.set_retries(MAX_RETRIES);
            Err(w)
        }
    });

    let scan_start = Instant::now();
    let results: Vec<Result<Vec<ScanItem>, ScanWarning>> = futures::stream::iter(futs)
        .buffer_unordered(50)
        .collect()
        .await;

    eprintln!(
        "\r\x1b[2K✅ Scanned {} resource types in {:.1}s",
        total,
        scan_start.elapsed().as_secs_f64()
    );

    let mut index = NamespaceIndex::new();
    let mut ref_data: Vec<RefData> = Vec::new();
    let mut warnings: Vec<ScanWarning> = Vec::new();

    for result in results {
        match result {
            Ok(items) => {
                for (info, wk_refs, spec_strs) in items {
                    if refs {
                        ref_data.push((info.uid.clone(), info.name.clone(), wk_refs, spec_strs));
                    }
                    index.insert(info);
                }
            }
            Err(warning) => {
                warnings.push(warning);
            }
        }
    }

    if refs {
        let mut by_name: HashMap<String, Vec<String>> = HashMap::new();
        for info in index.by_uid.values() {
            by_name
                .entry(info.name.clone())
                .or_default()
                .push(info.kind.clone());
        }

        for (uid, self_name, wk_refs, spec_strs) in ref_data {
            let already_found: HashSet<(String, String)> = wk_refs
                .iter()
                .map(|r| (r.target_kind.clone(), r.target_name.clone()))
                .collect();

            let heuristic_refs =
                resolve_name_matches(&spec_strs, &self_name, &by_name, &already_found);

            let mut all_refs = wk_refs;
            all_refs.extend(heuristic_refs);

            if !all_refs.is_empty() {
                index.refs_from.insert(uid, all_refs);
            }
        }

        for (source_uid, source_refs) in &index.refs_from {
            if let Some(source_info) = index.by_uid.get(source_uid) {
                let source_kind = source_info.kind.clone();
                let source_name = source_info.name.clone();
                for sref in source_refs {
                    let target_key = (sref.target_kind.to_lowercase(), sref.target_name.clone());
                    if let Some(target_uid) = index.by_kind_name.get(&target_key) {
                        index
                            .refs_to
                            .entry(target_uid.clone())
                            .or_default()
                            .push(IncomingRef {
                                source_kind: source_kind.clone(),
                                source_name: source_name.clone(),
                                field_path: sref.field_path.clone(),
                            });
                    }
                }
            }
        }

        for incoming in index.refs_to.values_mut() {
            let mut seen = HashSet::new();
            incoming.retain(|r| seen.insert((r.source_kind.clone(), r.source_name.clone())));
        }
    }

    Ok((index, warnings))
}

pub async fn resolve_missing_parents(
    index: &mut NamespaceIndex,
    start_uid: &str,
    client: &Client,
    namespace: &str,
    kind_map: &KindMap,
) {
    let mut current = start_uid.to_string();
    let mut visited = HashSet::new();

    loop {
        if !visited.insert(current.clone()) {
            break;
        }

        let owner = match index.by_uid.get(&current) {
            Some(info) => primary_owner(&info.owner_refs).cloned(),
            None => break,
        };

        let owner = match owner {
            Some(o) => o,
            None => break,
        };

        if index.by_uid.contains_key(&owner.uid) {
            current = owner.uid;
            continue;
        }

        let (owner_group, owner_version) = match owner.api_version.rsplit_once('/') {
            Some((g, v)) => (g.to_string(), v.to_string()),
            None => (String::new(), owner.api_version.clone()),
        };

        let kind_info = kind_map
            .iter()
            .find(|(k, info)| k.as_str() == owner.kind && info.group == owner_group)
            .map(|(_, info)| info)
            .or_else(|| kind_map.get(&owner.kind));

        let kind_info = match kind_info {
            Some(i) => i,
            None => break,
        };

        let gvk = GroupVersion::gv(&owner_group, &owner_version).with_kind(&owner.kind);
        let ar = ApiResource::from_gvk_with_plural(&gvk, &kind_info.plural);
        let api: Api<DynamicObject> = if kind_info.namespaced {
            Api::namespaced_with(client.clone(), namespace, &ar)
        } else {
            Api::all_with(client.clone(), &ar)
        };

        match api.get(&owner.name).await {
            Ok(obj) => {
                let uid = obj.metadata.uid.unwrap_or_default();
                let name = obj.metadata.name.unwrap_or_default();
                let ns = obj.metadata.namespace;
                let owner_refs = obj
                    .metadata
                    .owner_references
                    .unwrap_or_default()
                    .into_iter()
                    .map(|r| OwnerRef {
                        api_version: r.api_version,
                        kind: r.kind,
                        name: r.name,
                        uid: r.uid,
                        controller: r.controller.unwrap_or(false),
                    })
                    .collect();

                let labels = obj
                    .metadata
                    .labels
                    .unwrap_or_default()
                    .into_iter()
                    .collect();
                let annotations = obj
                    .metadata
                    .annotations
                    .unwrap_or_default()
                    .into_iter()
                    .collect();

                let next_uid = uid.clone();
                index.insert(ResourceInfo {
                    kind: owner.kind,
                    name,
                    namespace: ns,
                    uid,
                    owner_refs,
                    labels,
                    annotations,
                });
                current = next_uid;
            }
            Err(_) => break,
        }
    }
}

pub async fn find_parents_only(
    client: &Client,
    kind: &str,
    name: &str,
    namespace: &str,
    kind_map: &KindMap,
) -> Result<Vec<ResourceInfo>> {
    let mut chain = Vec::new();
    let mut current_kind = kind.to_string();
    let mut current_name = name.to_string();
    let mut visited = HashSet::new();

    loop {
        let info = match kind_map.get(&current_kind) {
            Some(i) => i,
            None => {
                chain.push(ResourceInfo {
                    kind: current_kind,
                    name: current_name,
                    namespace: None,
                    uid: String::new(),
                    owner_refs: vec![],
                    labels: HashMap::new(),
                    annotations: HashMap::new(),
                });
                break;
            }
        };

        let gvk = GroupVersion::gv(&info.group, &info.version).with_kind(&current_kind);
        let ar = ApiResource::from_gvk_with_plural(&gvk, &info.plural);
        let api: Api<DynamicObject> = if info.namespaced {
            Api::namespaced_with(client.clone(), namespace, &ar)
        } else {
            Api::all_with(client.clone(), &ar)
        };

        match api.get(&current_name).await {
            Ok(obj) => {
                let uid = obj.metadata.uid.unwrap_or_default();
                if !visited.insert(uid.clone()) {
                    break;
                }

                let owner_refs: Vec<OwnerRef> = obj
                    .metadata
                    .owner_references
                    .unwrap_or_default()
                    .into_iter()
                    .map(|r| OwnerRef {
                        api_version: r.api_version,
                        kind: r.kind,
                        name: r.name,
                        uid: r.uid,
                        controller: r.controller.unwrap_or(false),
                    })
                    .collect();

                let next = primary_owner(&owner_refs).cloned();

                let labels = obj
                    .metadata
                    .labels
                    .unwrap_or_default()
                    .into_iter()
                    .collect();
                let annotations = obj
                    .metadata
                    .annotations
                    .unwrap_or_default()
                    .into_iter()
                    .collect();

                chain.push(ResourceInfo {
                    kind: current_kind,
                    name: current_name,
                    namespace: obj.metadata.namespace,
                    uid,
                    owner_refs,
                    labels,
                    annotations,
                });

                match next {
                    Some(oref) => {
                        current_kind = oref.kind;
                        current_name = oref.name;
                    }
                    None => break,
                }
            }
            Err(e) => {
                chain.push(ResourceInfo {
                    kind: current_kind,
                    name: format!("{} (error: {})", current_name, e),
                    namespace: None,
                    uid: String::new(),
                    owner_refs: vec![],
                    labels: HashMap::new(),
                    annotations: HashMap::new(),
                });
                break;
            }
        }
    }

    chain.reverse();
    Ok(chain)
}
