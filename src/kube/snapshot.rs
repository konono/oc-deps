use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Instant;

use anyhow::Result;
use futures::stream::StreamExt;
use kube::{
    Client,
    api::{Api, ApiResource, DynamicObject, ListParams},
    config::Config,
    core::GroupVersion,
};

use crate::analyzers::spec_ref::extract_well_known_refs;
use crate::kube::discovery::KindMap;
use crate::kube::resource::*;

const MAX_RETRIES: usize = 2;

pub async fn build_snapshot(
    client: &Client,
    config: &Config,
    namespace: &str,
    kind_map: &KindMap,
    include_events: bool,
) -> Result<ClusterSnapshot> {
    let skip_kinds: HashSet<&str> = if include_events {
        HashSet::new()
    } else {
        HashSet::from(["Event"])
    };

    let scan_targets: Vec<_> = kind_map
        .iter()
        .filter(|(k, info)| info.namespaced && !skip_kinds.contains(k.as_str()))
        .map(|(k, v)| (k.clone(), v.clone()))
        .collect();

    let total = scan_targets.len();
    let scanned = Arc::new(AtomicUsize::new(0));
    let scan_errors: Arc<std::sync::Mutex<Vec<ScanWarning>>> =
        Arc::new(std::sync::Mutex::new(Vec::new()));

    let futs = scan_targets.into_iter().map(|(kind, info)| {
        let client = client.clone();
        let ns = namespace.to_string();
        let scanned = scanned.clone();
        let scan_errors = scan_errors.clone();

        async move {
            let gvk = GroupVersion::gv(&info.group, &info.version).with_kind(&kind);
            let ar = ApiResource::from_gvk_with_plural(&gvk, &info.plural);
            let api: Api<DynamicObject> = Api::namespaced_with(client, &ns, &ar);

            let mut last_warning = None;
            for attempt in 0..=MAX_RETRIES {
                let result = api.list(&ListParams::default()).await;
                if attempt == 0 {
                    let count = scanned.fetch_add(1, Ordering::Relaxed) + 1;
                    eprint!("\r\x1b[2K🔍 Scanning resources... ({}/{})", count, total);
                }

                match result {
                    Ok(list) => {
                        let entries: Vec<(String, ResourceEntry)> = list
                            .items
                            .into_iter()
                            .filter_map(|obj| {
                                let data = obj.data;
                                let metadata = obj.metadata;
                                let uid = metadata.uid.clone()?;
                                let name = metadata.name?;
                                let ns = metadata.namespace;

                                let owner_refs: Vec<OwnerRefEntry> = metadata
                                    .owner_references
                                    .unwrap_or_default()
                                    .into_iter()
                                    .map(|r| OwnerRefEntry {
                                        api_version: r.api_version,
                                        kind: r.kind,
                                        name: r.name,
                                        uid: r.uid,
                                        controller: r.controller.unwrap_or(false),
                                    })
                                    .collect();

                                let wk_refs = extract_well_known_refs(&data);
                                let spec_refs: Vec<SpecRefEntry> = wk_refs
                                    .into_iter()
                                    .map(|r| SpecRefEntry {
                                        target_kind: r.target_kind,
                                        target_name: r.target_name,
                                        field_path: r.field_path,
                                    })
                                    .collect();

                                let labels =
                                    metadata.labels.unwrap_or_default().into_iter().collect();
                                let annotations = metadata
                                    .annotations
                                    .unwrap_or_default()
                                    .into_iter()
                                    .collect();

                                let raw_spec = data.get("spec").cloned();

                                let entry = ResourceEntry {
                                    id: ResourceId {
                                        group: info.group.clone(),
                                        version: info.version.clone(),
                                        kind: kind.clone(),
                                        namespace: ns,
                                        name,
                                        uid: Some(uid.clone()),
                                    },
                                    owner_refs,
                                    spec_refs,
                                    labels,
                                    annotations,
                                    raw_spec,
                                };

                                Some((uid, entry))
                            })
                            .collect();
                        return Some(entries);
                    }
                    Err(e) => {
                        let warning = ScanWarning::from_kube_error(
                            &e,
                            &info.group,
                            &info.version,
                            &info.plural,
                        );
                        if warning.is_retryable() && attempt < MAX_RETRIES {
                            let delay =
                                std::time::Duration::from_millis(500 * (attempt as u64 + 1));
                            tokio::time::sleep(delay).await;
                            last_warning = Some(warning);
                            continue;
                        }
                        if let Ok(mut errors) = scan_errors.lock() {
                            errors.push(warning);
                        }
                        return None;
                    }
                }
            }
            if let Some(w) = last_warning
                && let Ok(mut errors) = scan_errors.lock()
            {
                errors.push(w);
            }
            None
        }
    });

    let scan_start = Instant::now();
    let results: Vec<_> = futures::stream::iter(futs)
        .buffer_unordered(50)
        .collect()
        .await;

    eprintln!(
        "\r\x1b[2K✅ Scanned {} resource types in {:.1}s",
        total,
        scan_start.elapsed().as_secs_f64()
    );

    let mut resources = HashMap::new();
    for entries in results.into_iter().flatten() {
        for (uid, entry) in entries {
            resources.insert(uid, entry);
        }
    }

    let warnings = match Arc::try_unwrap(scan_errors) {
        Ok(mutex) => mutex.into_inner().unwrap_or_default(),
        Err(arc) => arc.lock().unwrap().clone(),
    };
    let errors: Vec<String> = warnings.iter().map(|w| w.to_string()).collect();

    let snapshot = ClusterSnapshot {
        resources,
        scan_errors: errors,
        cluster_url: config.cluster_url.to_string(),
        taken_at: chrono::Utc::now().to_rfc3339(),
        namespaces: vec![namespace.to_string()],
    };

    Ok(snapshot)
}

pub fn save_snapshot(snapshot: &ClusterSnapshot, path: &str) -> Result<()> {
    let json = serde_json::to_string_pretty(snapshot)?;
    std::fs::write(path, json)?;
    Ok(())
}

#[allow(dead_code)]
pub fn load_snapshot(path: &str) -> Result<ClusterSnapshot> {
    let data = std::fs::read_to_string(path)?;
    let snapshot: ClusterSnapshot = serde_json::from_str(&data)?;
    Ok(snapshot)
}
