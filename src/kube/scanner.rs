use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Instant;

use anyhow::{Result, bail};
use futures::stream::StreamExt;
use kube::{
    Client,
    api::{Api, ApiResource, DynamicObject, ListParams},
    core::GroupVersion,
};

use crate::analyzers::spec_ref::{collect_string_values, extract_well_known_refs};
use crate::kube::discovery::{GroupKindMap, KindMap};
use crate::kube::resource::*;

const MAX_RETRIES: usize = 2;
const SCAN_REQUEST_TIMEOUT_SECS: u64 = 30;

fn warn_retry(is_tty: bool, msg: &str) {
    if is_tty {
        eprintln!("   \x1b[33m⚠ {}\x1b[0m", msg);
    } else {
        eprintln!("   ⚠ {}", msg);
    }
}

pub async fn get_with_retry(
    api: &Api<DynamicObject>,
    name: &str,
    group: &str,
    version: &str,
    plural: &str,
) -> std::result::Result<DynamicObject, ScanWarning> {
    let is_tty = std::io::IsTerminal::is_terminal(&std::io::stderr());
    let gvr = if group.is_empty() {
        format!("{}/{}", version, plural)
    } else {
        format!("{}/{}/{}", group, version, plural)
    };
    for attempt in 0..=MAX_RETRIES {
        let timeout_dur = std::time::Duration::from_secs(SCAN_REQUEST_TIMEOUT_SECS);
        match tokio::time::timeout(timeout_dur, api.get(name)).await {
            Ok(Ok(obj)) => return Ok(obj),
            Ok(Err(e)) => {
                let warning = ScanWarning::from_kube_error(&e, group, version, plural);
                if warning.is_retryable() && attempt < MAX_RETRIES {
                    let delay = std::time::Duration::from_millis(500 * (attempt as u64 + 1));
                    warn_retry(
                        is_tty,
                        &format!(
                            "{} — GET attempt {}/{} failed; retrying as {}/{} in {}ms",
                            gvr,
                            attempt + 1,
                            MAX_RETRIES + 1,
                            attempt + 2,
                            MAX_RETRIES + 1,
                            delay.as_millis()
                        ),
                    );
                    tokio::time::sleep(delay).await;
                    continue;
                }
                let mut w = ScanWarning::from_kube_error(&e, group, version, plural);
                w.set_retries(attempt);
                return Err(w);
            }
            Err(_elapsed) => {
                if attempt < MAX_RETRIES {
                    let delay = std::time::Duration::from_millis(500 * (attempt as u64 + 1));
                    warn_retry(
                        is_tty,
                        &format!(
                            "{} — GET timeout ({}s), attempt {}/{} failed; retrying as {}/{}",
                            gvr,
                            SCAN_REQUEST_TIMEOUT_SECS,
                            attempt + 1,
                            MAX_RETRIES + 1,
                            attempt + 2,
                            MAX_RETRIES + 1
                        ),
                    );
                    tokio::time::sleep(delay).await;
                    continue;
                }
                return Err(ScanWarning::Timeout {
                    gvr: gvr.clone(),
                    message: Some(format!(
                        "GET {} timeout ({}s)",
                        name, SCAN_REQUEST_TIMEOUT_SECS
                    )),
                    retries: attempt,
                });
            }
        }
    }
    Err(ScanWarning::Other {
        gvr,
        message: "exhausted retries".to_string(),
    })
}

pub async fn list_with_selector_retry(
    api: &Api<DynamicObject>,
    selector: &str,
    group: &str,
    version: &str,
    plural: &str,
) -> std::result::Result<Vec<DynamicObject>, ScanWarning> {
    let is_tty = std::io::IsTerminal::is_terminal(&std::io::stderr());
    let gvr = if group.is_empty() {
        format!("{}/{}", version, plural)
    } else {
        format!("{}/{}/{}", group, version, plural)
    };
    for attempt in 0..=MAX_RETRIES {
        let timeout_dur = std::time::Duration::from_secs(SCAN_REQUEST_TIMEOUT_SECS);
        let lp = ListParams::default().labels(selector);
        match tokio::time::timeout(timeout_dur, api.list(&lp)).await {
            Ok(Ok(list)) => return Ok(list.items),
            Ok(Err(e)) => {
                let warning = ScanWarning::from_kube_error(&e, group, version, plural);
                if warning.is_retryable() && attempt < MAX_RETRIES {
                    let delay = std::time::Duration::from_millis(500 * (attempt as u64 + 1));
                    warn_retry(
                        is_tty,
                        &format!(
                            "{} — LIST attempt {}/{} failed; retrying as {}/{} in {}ms",
                            gvr,
                            attempt + 1,
                            MAX_RETRIES + 1,
                            attempt + 2,
                            MAX_RETRIES + 1,
                            delay.as_millis()
                        ),
                    );
                    tokio::time::sleep(delay).await;
                    continue;
                }
                let mut w = ScanWarning::from_kube_error(&e, group, version, plural);
                w.set_retries(attempt);
                return Err(w);
            }
            Err(_elapsed) => {
                if attempt < MAX_RETRIES {
                    let delay = std::time::Duration::from_millis(500 * (attempt as u64 + 1));
                    warn_retry(
                        is_tty,
                        &format!(
                            "{} — LIST timeout ({}s), attempt {}/{} failed; retrying as {}/{}",
                            gvr,
                            SCAN_REQUEST_TIMEOUT_SECS,
                            attempt + 1,
                            MAX_RETRIES + 1,
                            attempt + 2,
                            MAX_RETRIES + 1
                        ),
                    );
                    tokio::time::sleep(delay).await;
                    continue;
                }
                return Err(ScanWarning::Timeout {
                    gvr: gvr.clone(),
                    message: Some(format!(
                        "LIST selector={} timeout ({}s)",
                        selector, SCAN_REQUEST_TIMEOUT_SECS
                    )),
                    retries: attempt,
                });
            }
        }
    }
    Err(ScanWarning::Other {
        gvr,
        message: "exhausted retries".to_string(),
    })
}

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
                    source: SpecRefSource::Heuristic,
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

pub const DEFAULT_API_CONCURRENCY: usize = 50;

pub async fn scan_namespace(
    client: &Client,
    namespace: &str,
    kind_map: &KindMap,
    include_events: bool,
    refs: bool,
    show_spec: bool,
) -> Result<(NamespaceIndex, Vec<ScanWarning>)> {
    scan_namespace_with_semaphore(
        client,
        namespace,
        kind_map,
        include_events,
        refs,
        show_spec,
        None,
    )
    .await
}

pub async fn scan_namespace_with_semaphore(
    client: &Client,
    namespace: &str,
    kind_map: &KindMap,
    include_events: bool,
    refs: bool,
    show_spec: bool,
    api_semaphore: Option<Arc<tokio::sync::Semaphore>>,
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
    let scan_start = std::time::Instant::now();
    let is_tty = std::io::IsTerminal::is_terminal(&std::io::stderr());

    let api_sem = api_semaphore.clone();

    let futs = scan_targets.into_iter().map(|(kind, info)| {
        let client = client.clone();
        let ns = namespace.to_string();
        let scanned = scanned.clone();
        let sem = api_sem.clone();

        async move {
            let gvk = GroupVersion::gv(&info.group, &info.version).with_kind(&kind);
            let ar = ApiResource::from_gvk_with_plural(&gvk, &info.plural);
            let api: Api<DynamicObject> = Api::namespaced_with(client, &ns, &ar);

            let mut last_err = None;
            for attempt in 0..=MAX_RETRIES {
                let _permit = if let Some(s) = &sem {
                    Some(s.acquire().await.expect("semaphore closed"))
                } else {
                    None
                };
                let timeout_dur = std::time::Duration::from_secs(SCAN_REQUEST_TIMEOUT_SECS);
                let result =
                    tokio::time::timeout(timeout_dur, api.list(&ListParams::default())).await;
                if attempt == 0 {
                    let count = scanned.fetch_add(1, Ordering::Relaxed) + 1;
                    if is_tty {
                        let elapsed = scan_start.elapsed().as_secs();
                        eprint!(
                            "\r\x1b[2K🔍 Scanning resources... ({}/{}, {}s)",
                            count, total, elapsed
                        );
                    }
                }

                match result {
                    Ok(Ok(list)) => {
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

                                let pod_template = if show_spec {
                                    extract_pod_template(&kind, &data)
                                } else {
                                    None
                                };

                                Some((
                                    ResourceInfo {
                                        group: info.group.clone(),
                                        kind: kind.clone(),
                                        name,
                                        namespace: ns,
                                        uid,
                                        owner_refs,
                                        labels,
                                        annotations,
                                        pod_template,
                                    },
                                    wk_refs,
                                    spec_strs,
                                ))
                            })
                            .collect();
                        return Ok(items);
                    }
                    Ok(Err(e)) => {
                        let mut warning = ScanWarning::from_kube_error(
                            &e,
                            &info.group,
                            &info.version,
                            &info.plural,
                        );
                        if warning.is_retryable() && attempt < MAX_RETRIES {
                            let delay =
                                std::time::Duration::from_millis(500 * (attempt as u64 + 1));
                            let gvr_d = if info.group.is_empty() {
                                format!("{}/{}", info.version, info.plural)
                            } else {
                                format!("{}/{}/{}", info.group, info.version, info.plural)
                            };
                            warn_retry(
                                is_tty,
                                &format!(
                                    "{} — scan LIST attempt {}/{} failed; retrying as {}/{} in {}ms",
                                    gvr_d, attempt + 1, MAX_RETRIES + 1, attempt + 2, MAX_RETRIES + 1, delay.as_millis()
                                ),
                            );
                            tokio::time::sleep(delay).await;
                            last_err = Some(warning);
                            continue;
                        }
                        warning.set_retries(attempt);
                        return Err(warning);
                    }
                    Err(_elapsed) => {
                        let gvr = if info.group.is_empty() {
                            format!("{}/{}", info.version, info.plural)
                        } else {
                            format!("{}/{}/{}", info.group, info.version, info.plural)
                        };
                        let warning = ScanWarning::Timeout {
                            gvr: gvr.clone(),
                            message: Some(format!(
                                "request timeout ({}s)",
                                SCAN_REQUEST_TIMEOUT_SECS
                            )),
                            retries: attempt,
                        };
                        if attempt < MAX_RETRIES {
                            let delay =
                                std::time::Duration::from_millis(500 * (attempt as u64 + 1));
                            warn_retry(
                                is_tty,
                                &format!(
                                    "{} — scan LIST timeout ({}s), attempt {}/{} failed; retrying as {}/{}",
                                    gvr, SCAN_REQUEST_TIMEOUT_SECS, attempt + 1, MAX_RETRIES + 1, attempt + 2, MAX_RETRIES + 1
                                ),
                            );
                            tokio::time::sleep(delay).await;
                            last_err = Some(warning);
                            continue;
                        }
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
    let concurrency = if api_semaphore.is_some() {
        total
    } else {
        DEFAULT_API_CONCURRENCY
    };
    let results: Vec<Result<Vec<ScanItem>, ScanWarning>> = futures::stream::iter(futs)
        .buffer_unordered(concurrency)
        .collect()
        .await;

    if is_tty {
        eprintln!(
            "\r\x1b[2K✅ Scanned {} resource types in {:.1}s",
            total,
            scan_start.elapsed().as_secs_f64()
        );
    } else {
        eprintln!(
            "✅ Scanned {} resource types in {:.1}s",
            total,
            scan_start.elapsed().as_secs_f64()
        );
    }

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
                    if let Some(target_uid) = index.lookup_by_kind_name(
                        None, // spec-ref target group unknown
                        &sref.target_kind,
                        &sref.target_name,
                        source_info.namespace.as_deref(),
                    ) {
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

#[allow(clippy::too_many_arguments)]
pub async fn scan_single_api_into_index(
    client: &Client,
    group: &str,
    kind: &str,
    namespace: &str,
    kind_map: &KindMap,
    gk_map: &GroupKindMap,
    index: &mut NamespaceIndex,
    refs: bool,
    show_spec: bool,
) -> Vec<ScanWarning> {
    if group.is_empty() {
        return vec![];
    }
    if let Some(km_info) = kind_map.get(kind)
        && km_info.group == group
    {
        return vec![];
    }
    let Some(info) = gk_map.get(&(group.to_string(), kind.to_string())) else {
        return vec![];
    };
    if !info.namespaced {
        return vec![];
    }
    let gvk = GroupVersion::gv(&info.group, &info.version).with_kind(kind);
    let ar = ApiResource::from_gvk_with_plural(&gvk, &info.plural);
    let api: Api<DynamicObject> = Api::namespaced_with(client.clone(), namespace, &ar);

    let items = match crate::analyzers::selector::list_with_retry_and_timeout(
        &api,
        &info.group,
        &info.version,
        &info.plural,
    )
    .await
    {
        Ok(objects) => {
            let mut items: Vec<ScanItem> = Vec::new();
            for obj in objects {
                let data = obj.data;
                let metadata = obj.metadata;
                let Some(uid) = metadata.uid else {
                    continue;
                };
                let Some(res_name) = metadata.name else {
                    continue;
                };
                let ns = metadata.namespace;
                let owner_refs: Vec<OwnerRef> = metadata
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
                let labels = metadata.labels.unwrap_or_default().into_iter().collect();
                let annotations = metadata
                    .annotations
                    .unwrap_or_default()
                    .into_iter()
                    .collect();
                let pod_template = if show_spec {
                    extract_pod_template(kind, &data)
                } else {
                    None
                };
                items.push((
                    ResourceInfo {
                        group: info.group.clone(),
                        kind: kind.to_string(),
                        name: res_name,
                        namespace: ns,
                        uid,
                        owner_refs,
                        labels,
                        annotations,
                        pod_template,
                    },
                    wk_refs,
                    spec_strs,
                ));
            }
            items
        }
        Err(warning) => return vec![warning],
    };

    let mut ref_data: Vec<RefData> = Vec::new();
    for (info, wk_refs, spec_strs) in items {
        if refs {
            ref_data.push((info.uid.clone(), info.name.clone(), wk_refs, spec_strs));
        }
        index.insert(info);
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
                index.refs_from.insert(uid.clone(), all_refs);
            }
        }
        for (source_uid, source_refs) in &index.refs_from {
            if let Some(source_info) = index.by_uid.get(source_uid) {
                let source_kind = source_info.kind.clone();
                let source_name = source_info.name.clone();
                let source_ns = source_info.namespace.clone();
                for sref in source_refs {
                    if let Some(target_uid) = index.lookup_by_kind_name(
                        None,
                        &sref.target_kind,
                        &sref.target_name,
                        source_ns.as_deref(),
                    ) {
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
    vec![]
}

pub async fn resolve_missing_parents(
    index: &mut NamespaceIndex,
    start_uid: &str,
    client: &Client,
    namespace: &str,
    kind_map: &KindMap,
    gk_map: &GroupKindMap,
    show_spec: bool,
) -> Vec<ScanWarning> {
    let mut warnings = Vec::new();
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

        let kind_info = if !owner_group.is_empty() {
            gk_map.get(&(owner_group.clone(), owner.kind.clone()))
        } else {
            gk_map
                .get(&(String::new(), owner.kind.clone()))
                .or_else(|| kind_map.get(&owner.kind))
        };

        let kind_info = match kind_info {
            Some(i) => i,
            None => {
                let gvr = if owner_group.is_empty() {
                    format!("{}/{}", owner_version, owner.kind)
                } else {
                    format!("{}/{}/{}", owner_group, owner_version, owner.kind)
                };
                warnings.push(ScanWarning::Other {
                    gvr,
                    message: format!(
                        "parent {}/{} kind not found in discovery (group {})",
                        owner.kind, owner.name, owner_group
                    ),
                });
                break;
            }
        };

        let gvk = GroupVersion::gv(&owner_group, &owner_version).with_kind(&owner.kind);
        let ar = ApiResource::from_gvk_with_plural(&gvk, &kind_info.plural);
        let api: Api<DynamicObject> = if kind_info.namespaced {
            Api::namespaced_with(client.clone(), namespace, &ar)
        } else {
            Api::all_with(client.clone(), &ar)
        };

        match get_with_retry(
            &api,
            &owner.name,
            &kind_info.group,
            &kind_info.version,
            &kind_info.plural,
        )
        .await
        {
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

                let pod_template = if show_spec {
                    extract_pod_template(&owner.kind, &obj.data)
                } else {
                    None
                };
                let next_uid = uid.clone();
                index.insert(ResourceInfo {
                    group: owner_group.clone(),
                    kind: owner.kind,
                    name,
                    namespace: ns,
                    uid,
                    owner_refs,
                    labels,
                    annotations,
                    pod_template,
                });
                current = next_uid;
            }
            Err(w) => {
                warnings.push(w);
                break;
            }
        }
    }
    warnings
}

#[allow(clippy::too_many_arguments, clippy::type_complexity)]
pub async fn find_parents_only(
    client: &Client,
    group: &str,
    kind: &str,
    name: &str,
    namespace: &str,
    kind_map: &KindMap,
    gk_map: &GroupKindMap,
    show_spec: bool,
    refs: bool,
) -> Result<(Vec<ChainEntry>, Vec<ScanWarning>)> {
    let mut chain = Vec::new();
    let mut warnings = Vec::new();
    let mut current_kind = kind.to_string();
    let mut current_name = name.to_string();
    let mut current_group = group.to_string();
    let mut visited = HashSet::new();
    let mut is_first = true;

    loop {
        let info = if !current_group.is_empty() {
            gk_map
                .get(&(current_group.clone(), current_kind.clone()))
                .or_else(|| {
                    kind_map
                        .iter()
                        .find(|(k, ki)| *k == &current_kind && ki.group == current_group)
                        .map(|(_, ki)| ki)
                })
        } else {
            kind_map.get(&current_kind)
        };
        let info = match info {
            Some(i) => i,
            None => {
                if is_first {
                    bail!(
                        "{}/{} not found in API discovery (group: {})",
                        current_kind,
                        current_name,
                        if current_group.is_empty() {
                            "core"
                        } else {
                            &current_group
                        }
                    );
                }
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

        match get_with_retry(
            &api,
            &current_name,
            &info.group,
            &info.version,
            &info.plural,
        )
        .await
        {
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

                let pod_template = if show_spec {
                    extract_pod_template(&current_kind, &obj.data)
                } else {
                    None
                };

                let spec_refs = if refs {
                    let mut wk = extract_well_known_refs(&obj.data);
                    dedup_spec_refs(&mut wk);
                    wk
                } else {
                    vec![]
                };

                chain.push(ChainEntry {
                    info: ResourceInfo {
                        group: info.group.clone(),
                        kind: current_kind,
                        name: current_name,
                        namespace: obj.metadata.namespace,
                        uid,
                        owner_refs,
                        labels,
                        annotations,
                        pod_template,
                    },
                    spec_refs,
                });

                match next {
                    Some(oref) => {
                        current_group = oref
                            .api_version
                            .split_once('/')
                            .map(|(g, _)| g.to_string())
                            .unwrap_or_default();
                        current_kind = oref.kind;
                        current_name = oref.name;
                    }
                    None => break,
                }
            }
            Err(w) => {
                if is_first {
                    bail!(
                        "{}/{} not found in namespace '{}': {}",
                        current_kind,
                        current_name,
                        namespace,
                        w
                    );
                }
                warnings.push(w);
                break;
            }
        }
        is_first = false;
    }

    chain.reverse();
    Ok((chain, warnings))
}

pub async fn list_namespaces_with_retry(
    client: &Client,
) -> anyhow::Result<Vec<(String, std::collections::HashMap<String, String>)>> {
    use k8s_openapi::api::core::v1::Namespace;

    let ns_api: Api<Namespace> = Api::all(client.clone());
    let is_tty = std::io::IsTerminal::is_terminal(&std::io::stderr());

    for attempt in 0..=MAX_RETRIES as u32 {
        let timeout_dur = std::time::Duration::from_secs(SCAN_REQUEST_TIMEOUT_SECS);
        match tokio::time::timeout(timeout_dur, ns_api.list(&ListParams::default())).await {
            Ok(Ok(ns_list)) => {
                return Ok(ns_list
                    .items
                    .into_iter()
                    .filter_map(|ns| {
                        let name = ns.metadata.name?;
                        let labels = ns.metadata.labels.unwrap_or_default().into_iter().collect();
                        Some((name, labels))
                    })
                    .collect());
            }
            Ok(Err(e)) => {
                let warning = ScanWarning::from_kube_error(&e, "", "v1", "namespaces");
                if warning.is_retryable() && attempt < MAX_RETRIES as u32 {
                    let delay = std::time::Duration::from_millis(500 * (attempt as u64 + 1));
                    let msg = format!(
                        "v1/namespaces — LIST attempt {}/{} failed ({}); retrying in {}ms",
                        attempt + 1,
                        MAX_RETRIES + 1,
                        e,
                        delay.as_millis()
                    );
                    if is_tty {
                        eprintln!("   \x1b[33m⚠ {}\x1b[0m", msg);
                    } else {
                        eprintln!("   ⚠ {}", msg);
                    }
                    tokio::time::sleep(delay).await;
                    continue;
                }
                anyhow::bail!("Failed to list namespaces: {}", e);
            }
            Err(_) => {
                if attempt < MAX_RETRIES as u32 {
                    let delay = std::time::Duration::from_millis(500 * (attempt as u64 + 1));
                    let msg = format!(
                        "v1/namespaces — LIST timeout ({}s), attempt {}/{}; retrying",
                        SCAN_REQUEST_TIMEOUT_SECS,
                        attempt + 1,
                        MAX_RETRIES + 1
                    );
                    if is_tty {
                        eprintln!("   \x1b[33m⚠ {}\x1b[0m", msg);
                    } else {
                        eprintln!("   ⚠ {}", msg);
                    }
                    tokio::time::sleep(delay).await;
                    continue;
                }
                anyhow::bail!(
                    "Failed to list namespaces: timeout after {} attempts",
                    MAX_RETRIES + 1
                );
            }
        }
    }
    anyhow::bail!("Failed to list namespaces: exhausted retries");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolve_name_matches_produces_heuristic_source() {
        let spec_strs = vec![("spec.env.value".to_string(), "my-config".to_string())];
        let mut by_name: HashMap<String, Vec<String>> = HashMap::new();
        by_name.insert("my-config".to_string(), vec!["ConfigMap".to_string()]);
        let already_found = HashSet::new();

        let refs = resolve_name_matches(&spec_strs, "self-name", &by_name, &already_found);
        assert_eq!(refs.len(), 1);
        assert_eq!(refs[0].target_kind, "ConfigMap");
        assert_eq!(refs[0].target_name, "my-config");
        assert_eq!(refs[0].source, SpecRefSource::Heuristic);
    }

    #[test]
    fn resolve_name_matches_skips_already_found() {
        let spec_strs = vec![("spec.env.value".to_string(), "my-secret".to_string())];
        let mut by_name: HashMap<String, Vec<String>> = HashMap::new();
        by_name.insert("my-secret".to_string(), vec!["Secret".to_string()]);
        let mut already_found = HashSet::new();
        already_found.insert(("Secret".to_string(), "my-secret".to_string()));

        let refs = resolve_name_matches(&spec_strs, "self-name", &by_name, &already_found);
        assert!(refs.is_empty());
    }

    #[test]
    fn resolve_name_matches_skips_self_name() {
        let spec_strs = vec![("spec.field".to_string(), "my-deploy".to_string())];
        let mut by_name: HashMap<String, Vec<String>> = HashMap::new();
        by_name.insert("my-deploy".to_string(), vec!["Deployment".to_string()]);
        let already_found = HashSet::new();

        let refs = resolve_name_matches(&spec_strs, "my-deploy", &by_name, &already_found);
        assert!(refs.is_empty());
    }

    #[test]
    fn resolve_name_matches_dedup_same_kind_name() {
        let spec_strs = vec![
            ("spec.env1".to_string(), "shared".to_string()),
            ("spec.env2".to_string(), "shared".to_string()),
        ];
        let mut by_name: HashMap<String, Vec<String>> = HashMap::new();
        by_name.insert("shared".to_string(), vec!["ConfigMap".to_string()]);
        let already_found = HashSet::new();

        let refs = resolve_name_matches(&spec_strs, "self", &by_name, &already_found);
        assert_eq!(refs.len(), 1);
    }

    use crate::kube::discovery::KindInfo;
    use kube::client::Body;
    use std::pin::pin;
    use std::sync::atomic::AtomicUsize;

    fn json_response(json: serde_json::Value) -> http::Response<Body> {
        http::Response::builder()
            .status(200)
            .body(Body::from(serde_json::to_vec(&json).unwrap()))
            .unwrap()
    }

    fn make_kind_map() -> KindMap {
        let mut km = KindMap::new();
        km.insert(
            "Deployment".to_string(),
            KindInfo {
                group: "apps".to_string(),
                version: "v1".to_string(),
                plural: "deployments".to_string(),
                namespaced: true,
                listable: true,
            },
        );
        km.insert(
            "ReplicaSet".to_string(),
            KindInfo {
                group: "apps".to_string(),
                version: "v1".to_string(),
                plural: "replicasets".to_string(),
                namespaced: true,
                listable: true,
            },
        );
        km.insert(
            "Pod".to_string(),
            KindInfo {
                group: "".to_string(),
                version: "v1".to_string(),
                plural: "pods".to_string(),
                namespaced: true,
                listable: true,
            },
        );
        km
    }

    fn mock_deployment_obj() -> serde_json::Value {
        serde_json::json!({
            "apiVersion": "apps/v1",
            "kind": "Deployment",
            "metadata": {
                "name": "myapp",
                "namespace": "test-ns",
                "uid": "uid-deploy",
                "labels": {},
                "annotations": {}
            },
            "spec": {
                "template": {
                    "spec": {
                        "serviceAccountName": "myapp-sa",
                        "containers": [{"name": "app"}],
                        "volumes": [
                            {"name": "tls", "secret": {"secretName": "tls-cert"}},
                            {"name": "config", "configMap": {"name": "app-config"}}
                        ]
                    }
                }
            }
        })
    }

    fn mock_rs_obj() -> serde_json::Value {
        serde_json::json!({
            "apiVersion": "apps/v1",
            "kind": "ReplicaSet",
            "metadata": {
                "name": "myapp-abc",
                "namespace": "test-ns",
                "uid": "uid-rs",
                "labels": {},
                "annotations": {},
                "ownerReferences": [{"apiVersion": "apps/v1", "kind": "Deployment", "name": "myapp", "uid": "uid-deploy", "controller": true}]
            },
            "spec": {
                "template": {
                    "spec": {
                        "serviceAccountName": "myapp-sa",
                        "containers": [{"name": "app"}]
                    }
                }
            }
        })
    }

    fn mock_pod_obj() -> serde_json::Value {
        serde_json::json!({
            "apiVersion": "v1",
            "kind": "Pod",
            "metadata": {
                "name": "myapp-abc-xyz",
                "namespace": "test-ns",
                "uid": "uid-pod",
                "labels": {},
                "annotations": {},
                "ownerReferences": [{"apiVersion": "apps/v1", "kind": "ReplicaSet", "name": "myapp-abc", "uid": "uid-rs", "controller": true}]
            },
            "spec": {
                "serviceAccountName": "myapp-sa",
                "containers": [{"name": "app"}],
                "imagePullSecrets": [{"name": "registry-cred"}]
            }
        })
    }

    #[tokio::test]
    async fn find_parents_only_refs_true_extracts_typed_refs() {
        let (mock_service, handle) =
            tower_test::mock::pair::<http::Request<Body>, http::Response<Body>>();
        let client = Client::new(mock_service, "test-ns");
        let kind_map = make_kind_map();
        let request_count = Arc::new(AtomicUsize::new(0));
        let rc = request_count.clone();

        let spawned = tokio::spawn(async move {
            let mut handle = pin!(handle);

            // GET Pod
            let (req, send) = handle.next_request().await.expect("expected Pod GET");
            rc.fetch_add(1, Ordering::Relaxed);
            assert!(
                req.uri().path().contains("/pods/"),
                "first request should be Pod GET: {}",
                req.uri()
            );
            send.send_response(json_response(mock_pod_obj()));

            // GET ReplicaSet (parent)
            let (req, send) = handle.next_request().await.expect("expected RS GET");
            rc.fetch_add(1, Ordering::Relaxed);
            assert!(
                req.uri().path().contains("/replicasets/"),
                "second request should be RS GET: {}",
                req.uri()
            );
            send.send_response(json_response(mock_rs_obj()));

            // GET Deployment (grandparent)
            let (req, send) = handle.next_request().await.expect("expected Deploy GET");
            rc.fetch_add(1, Ordering::Relaxed);
            assert!(
                req.uri().path().contains("/deployments/"),
                "third request should be Deploy GET: {}",
                req.uri()
            );
            send.send_response(json_response(mock_deployment_obj()));
        });

        let gk_map: GroupKindMap = kind_map
            .iter()
            .map(|(k, v)| ((v.group.clone(), k.clone()), v.clone()))
            .collect();
        let (chain, _warnings) = find_parents_only(
            &client,
            "",
            "Pod",
            "myapp-abc-xyz",
            "test-ns",
            &kind_map,
            &gk_map,
            false,
            true,
        )
        .await
        .unwrap();

        spawned.await.unwrap();

        assert_eq!(
            request_count.load(Ordering::Relaxed),
            3,
            "exactly 3 GETs (no LIST, no ref-target GET)"
        );
        assert_eq!(chain.len(), 3);

        // Chain: Deployment → ReplicaSet → Pod
        assert_eq!(chain[0].info.kind, "Deployment");
        assert_eq!(chain[1].info.kind, "ReplicaSet");
        assert_eq!(chain[2].info.kind, "Pod");

        // Deployment has SA + Secret + ConfigMap refs
        assert!(
            !chain[0].spec_refs.is_empty(),
            "Deployment should have spec refs"
        );
        assert!(
            chain[0]
                .spec_refs
                .iter()
                .any(|r| r.target_kind == "ServiceAccount" && r.target_name == "myapp-sa")
        );
        assert!(
            chain[0]
                .spec_refs
                .iter()
                .any(|r| r.target_kind == "Secret" && r.target_name == "tls-cert")
        );
        assert!(
            chain[0]
                .spec_refs
                .iter()
                .any(|r| r.target_kind == "ConfigMap" && r.target_name == "app-config")
        );
        for r in &chain[0].spec_refs {
            assert_eq!(r.source, SpecRefSource::Typed);
        }

        // ReplicaSet has SA ref
        assert!(
            chain[1]
                .spec_refs
                .iter()
                .any(|r| r.target_kind == "ServiceAccount" && r.target_name == "myapp-sa")
        );

        // Pod has SA + imagePullSecret
        assert!(
            chain[2]
                .spec_refs
                .iter()
                .any(|r| r.target_kind == "ServiceAccount" && r.target_name == "myapp-sa")
        );
        assert!(
            chain[2]
                .spec_refs
                .iter()
                .any(|r| r.target_kind == "Secret" && r.target_name == "registry-cred")
        );
    }

    #[tokio::test]
    async fn find_parents_only_refs_false_no_refs_same_request_count() {
        let (mock_service, handle) =
            tower_test::mock::pair::<http::Request<Body>, http::Response<Body>>();
        let client = Client::new(mock_service, "test-ns");
        let kind_map = make_kind_map();
        let request_count = Arc::new(AtomicUsize::new(0));
        let rc = request_count.clone();

        let spawned = tokio::spawn(async move {
            let mut handle = pin!(handle);

            let (_req, send) = handle.next_request().await.expect("expected Pod GET");
            rc.fetch_add(1, Ordering::Relaxed);
            send.send_response(json_response(mock_pod_obj()));

            let (_req, send) = handle.next_request().await.expect("expected RS GET");
            rc.fetch_add(1, Ordering::Relaxed);
            send.send_response(json_response(mock_rs_obj()));

            let (_req, send) = handle.next_request().await.expect("expected Deploy GET");
            rc.fetch_add(1, Ordering::Relaxed);
            send.send_response(json_response(mock_deployment_obj()));
        });

        let gk_map2: GroupKindMap = kind_map
            .iter()
            .map(|(k, v)| ((v.group.clone(), k.clone()), v.clone()))
            .collect();
        let (chain, _warnings) = find_parents_only(
            &client,
            "",
            "Pod",
            "myapp-abc-xyz",
            "test-ns",
            &kind_map,
            &gk_map2,
            false,
            false,
        )
        .await
        .unwrap();

        spawned.await.unwrap();

        assert_eq!(
            request_count.load(Ordering::Relaxed),
            3,
            "same 3 GETs as refs=true"
        );
        assert_eq!(chain.len(), 3);
        for entry in &chain {
            assert!(
                entry.spec_refs.is_empty(),
                "{} should have no refs when refs=false",
                entry.info.kind
            );
        }
    }

    fn status_response(code: u16, reason: &str) -> http::Response<Body> {
        let body = serde_json::json!({
            "kind": "Status", "apiVersion": "v1", "metadata": {},
            "status": "Failure", "message": reason, "reason": reason, "code": code
        });
        http::Response::builder()
            .status(code)
            .body(Body::from(serde_json::to_vec(&body).unwrap()))
            .unwrap()
    }

    fn ns_list_response(names: &[&str]) -> http::Response<Body> {
        let items: Vec<serde_json::Value> = names
            .iter()
            .map(|n| {
                serde_json::json!({
                    "apiVersion": "v1",
                    "kind": "Namespace",
                    "metadata": {"name": n, "labels": {}}
                })
            })
            .collect();
        json_response(serde_json::json!({
            "apiVersion": "v1",
            "kind": "NamespaceList",
            "metadata": {"resourceVersion": "1"},
            "items": items
        }))
    }

    #[tokio::test]
    async fn list_namespaces_403_no_retry() {
        let (mock_service, handle) =
            tower_test::mock::pair::<http::Request<Body>, http::Response<Body>>();
        let client = Client::new(mock_service, "default");
        let request_count = Arc::new(AtomicUsize::new(0));
        let rc = request_count.clone();

        let spawned = tokio::spawn(async move {
            let mut handle = pin!(handle);
            let (_req, send) = handle.next_request().await.expect("expected request");
            rc.fetch_add(1, Ordering::Relaxed);
            send.send_response(status_response(403, "Forbidden"));
        });

        let result = list_namespaces_with_retry(&client).await;
        spawned.await.unwrap();

        assert!(result.is_err(), "403 should fail");
        assert_eq!(
            request_count.load(Ordering::Relaxed),
            1,
            "403 should not retry — expected 1 request"
        );
    }

    #[tokio::test]
    async fn list_namespaces_500_retries_3_times() {
        let (mock_service, handle) =
            tower_test::mock::pair::<http::Request<Body>, http::Response<Body>>();
        let client = Client::new(mock_service, "default");
        let request_count = Arc::new(AtomicUsize::new(0));
        let rc = request_count.clone();

        let spawned = tokio::spawn(async move {
            let mut handle = pin!(handle);
            for _ in 0..3 {
                let (_req, send) = handle.next_request().await.expect("expected request");
                rc.fetch_add(1, Ordering::Relaxed);
                send.send_response(status_response(500, "Internal Server Error"));
            }
        });

        let result = list_namespaces_with_retry(&client).await;
        spawned.await.unwrap();

        assert!(result.is_err(), "persistent 500 should fail");
        assert_eq!(
            request_count.load(Ordering::Relaxed),
            3,
            "500 should retry — expected 3 requests"
        );
    }

    #[tokio::test]
    async fn list_namespaces_500_then_success() {
        let (mock_service, handle) =
            tower_test::mock::pair::<http::Request<Body>, http::Response<Body>>();
        let client = Client::new(mock_service, "default");
        let request_count = Arc::new(AtomicUsize::new(0));
        let rc = request_count.clone();

        let spawned = tokio::spawn(async move {
            let mut handle = pin!(handle);
            // First: 500
            let (_req, send) = handle.next_request().await.unwrap();
            rc.fetch_add(1, Ordering::Relaxed);
            send.send_response(status_response(500, "Internal Server Error"));
            // Second: success
            let (_req, send) = handle.next_request().await.unwrap();
            rc.fetch_add(1, Ordering::Relaxed);
            send.send_response(ns_list_response(&["ns-a", "ns-b"]));
        });

        let result = list_namespaces_with_retry(&client).await;
        spawned.await.unwrap();

        assert!(result.is_ok(), "should succeed after retry");
        let namespaces = result.unwrap();
        assert_eq!(namespaces.len(), 2);
        assert_eq!(
            request_count.load(Ordering::Relaxed),
            2,
            "500 then 200 = 2 requests"
        );
    }

    #[tokio::test]
    async fn shared_semaphore_caps_concurrent_across_namespaces() {
        let permits = 2usize;
        let semaphore = Arc::new(tokio::sync::Semaphore::new(permits));
        let max_concurrent = Arc::new(AtomicUsize::new(0));
        let current_concurrent = Arc::new(AtomicUsize::new(0));

        let mut kind_map = KindMap::new();
        for i in 0..4 {
            kind_map.insert(
                format!("Kind{}", i),
                KindInfo {
                    group: "test".to_string(),
                    version: "v1".to_string(),
                    plural: format!("kind{}s", i),
                    namespaced: true,
                    listable: true,
                },
            );
        }

        let total_requests = 8; // 4 kinds × 2 namespaces
        let max_c = max_concurrent.clone();
        let cur_c = current_concurrent.clone();

        let (mock_service, handle) =
            tower_test::mock::pair::<http::Request<Body>, http::Response<Body>>();
        let client = Client::new(mock_service, "test-ns");

        let spawned = tokio::spawn(async move {
            let mut handle = pin!(handle);
            let mut tasks = Vec::new();
            for _ in 0..total_requests {
                let (_req, send) = handle.next_request().await.expect("expected request");
                let max_c = max_c.clone();
                let cur_c = cur_c.clone();
                tasks.push(tokio::spawn(async move {
                    let c = cur_c.fetch_add(1, Ordering::SeqCst) + 1;
                    max_c.fetch_max(c, Ordering::SeqCst);
                    tokio::time::sleep(std::time::Duration::from_millis(20)).await;
                    cur_c.fetch_sub(1, Ordering::SeqCst);
                    send.send_response(json_response(serde_json::json!({
                        "apiVersion": "v1",
                        "kind": "List",
                        "metadata": {"resourceVersion": "1"},
                        "items": []
                    })));
                }));
            }
            for t in tasks {
                t.await.unwrap();
            }
        });

        let sem1 = semaphore.clone();
        let sem2 = semaphore.clone();
        let km1 = kind_map.clone();
        let km2 = kind_map.clone();
        let c1 = client.clone();
        let c2 = client.clone();

        let (r1, r2) = tokio::join!(
            scan_namespace_with_semaphore(&c1, "ns-a", &km1, false, false, false, Some(sem1)),
            scan_namespace_with_semaphore(&c2, "ns-b", &km2, false, false, false, Some(sem2)),
        );

        spawned.await.unwrap();
        assert!(r1.is_ok());
        assert!(r2.is_ok());

        let observed_max = max_concurrent.load(Ordering::SeqCst);
        assert!(
            observed_max <= permits,
            "max concurrent requests across 2 namespaces should be <= {} permits, got {}",
            permits,
            observed_max
        );
        assert!(
            observed_max >= 2,
            "should achieve parallelism (>= 2), got {}",
            observed_max
        );
    }

    #[test]
    fn scan_warning_retryable_classification() {
        assert!(
            !ScanWarning::Forbidden {
                gvr: "v1/ns".into(),
                status: 403
            }
            .is_retryable()
        );
        assert!(
            !ScanWarning::Forbidden {
                gvr: "v1/ns".into(),
                status: 401
            }
            .is_retryable()
        );
        assert!(
            ScanWarning::ServerError {
                gvr: "v1/ns".into(),
                status: 500,
                message: String::new(),
                retries: 0
            }
            .is_retryable()
        );
        assert!(
            ScanWarning::RateLimited {
                gvr: "v1/ns".into(),
                retries: 0
            }
            .is_retryable()
        );
        assert!(
            ScanWarning::Timeout {
                gvr: "v1/ns".into(),
                message: None,
                retries: 0
            }
            .is_retryable()
        );
    }
}
