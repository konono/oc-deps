use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Instant;

use anyhow::{Result, bail};
use futures::stream::StreamExt;
use kube::{
    Client,
    api::{Api, ApiResource, DynamicObject, ListParams},
    config::Config,
    core::GroupVersion,
};
use serde::Serialize;
use sha2::{Digest, Sha256};

use crate::analyzers::spec_ref::extract_well_known_refs;
use crate::kube::discovery::KindMap;
use crate::kube::resource::*;

const MAX_RETRIES: usize = 2;

fn sha256_hex(data: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(data);
    format!("{:x}", hasher.finalize())
}

type DataFields = (
    Option<Vec<String>>,
    Option<String>,
    Option<HashMap<String, String>>,
);

fn extract_data_fields(kind: &str, data: &serde_json::Value) -> DataFields {
    match kind {
        "ConfigMap" => {
            let mut all_keys = Vec::new();
            let mut canonical = serde_json::Map::new();
            if let Some(d) = data.get("data").and_then(|d| d.as_object()) {
                for (k, v) in d {
                    all_keys.push(k.clone());
                    canonical.insert(k.clone(), v.clone());
                }
            }
            if let Some(bd) = data.get("binaryData").and_then(|d| d.as_object()) {
                for (k, v) in bd {
                    all_keys.push(k.clone());
                    canonical.insert(format!("binaryData:{}", k), v.clone());
                }
            }
            all_keys.sort();
            let hash = if !canonical.is_empty() {
                let json = serde_json::to_string(&serde_json::Value::Object(canonical))
                    .unwrap_or_default();
                Some(sha256_hex(json.as_bytes()))
            } else {
                None
            };
            (Some(all_keys), hash, None)
        }
        "Secret" => {
            if let Some(d) = data.get("data").and_then(|d| d.as_object()) {
                let mut keys: Vec<String> = d.keys().cloned().collect();
                keys.sort();
                let hashes: HashMap<String, String> = d
                    .iter()
                    .map(|(k, v)| {
                        let val = v.as_str().unwrap_or("");
                        (k.clone(), sha256_hex(val.as_bytes()))
                    })
                    .collect();
                (Some(keys), None, Some(hashes))
            } else {
                (Some(vec![]), None, Some(HashMap::new()))
            }
        }
        _ => (None, None, None),
    }
}

pub async fn build_snapshot(
    client: &Client,
    config: &Config,
    namespace: &str,
    kind_map: &KindMap,
    include_events: bool,
) -> Result<ClusterSnapshot> {
    build_snapshot_inner(client, config, namespace, kind_map, include_events, None).await
}

pub async fn build_snapshot_with_semaphore(
    client: &Client,
    config: &Config,
    namespace: &str,
    kind_map: &KindMap,
    include_events: bool,
    api_semaphore: Arc<tokio::sync::Semaphore>,
) -> Result<ClusterSnapshot> {
    build_snapshot_inner(
        client,
        config,
        namespace,
        kind_map,
        include_events,
        Some(api_semaphore),
    )
    .await
}

async fn build_snapshot_inner(
    client: &Client,
    config: &Config,
    namespace: &str,
    kind_map: &KindMap,
    include_events: bool,
    api_semaphore: Option<Arc<tokio::sync::Semaphore>>,
) -> Result<ClusterSnapshot> {
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
    let scan_errors: Arc<std::sync::Mutex<Vec<ScanWarning>>> =
        Arc::new(std::sync::Mutex::new(Vec::new()));

    let api_sem = api_semaphore.clone();

    let futs = scan_targets.into_iter().map(|(kind, info)| {
        let client = client.clone();
        let ns = namespace.to_string();
        let sem = api_sem.clone();
        let scanned = scanned.clone();
        let scan_errors = scan_errors.clone();

        async move {
            let gvk = GroupVersion::gv(&info.group, &info.version).with_kind(&kind);
            let ar = ApiResource::from_gvk_with_plural(&gvk, &info.plural);
            let api: Api<DynamicObject> = Api::namespaced_with(client, &ns, &ar);

            let mut last_warning = None;
            for attempt in 0..=MAX_RETRIES {
                let _permit = if let Some(s) = &sem {
                    Some(s.acquire().await.expect("semaphore closed"))
                } else {
                    None
                };
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
                                let annotations: HashMap<String, String> = metadata
                                    .annotations
                                    .unwrap_or_default()
                                    .into_iter()
                                    .filter(|(k, _)| {
                                        !(kind == "Secret"
                                            && k == "kubectl.kubernetes.io/last-applied-configuration")
                                    })
                                    .collect();

                                let raw_spec = data.get("spec").cloned();

                                let (data_keys, data_hash, secret_value_hashes) =
                                    extract_data_fields(&kind, &data);

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
                                    data_keys,
                                    data_hash,
                                    secret_value_hashes,
                                };

                                Some((uid, entry))
                            })
                            .collect();
                        return Some(entries);
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
                            last_warning = Some(warning);
                            continue;
                        }
                        warning.set_retries(attempt);
                        if let Ok(mut errors) = scan_errors.lock() {
                            errors.push(warning);
                        }
                        return None;
                    }
                }
            }
            if let Some(mut w) = last_warning
                && let Ok(mut errors) = scan_errors.lock()
            {
                w.set_retries(MAX_RETRIES);
                errors.push(w);
            }
            None
        }
    });

    let scan_start = Instant::now();
    let concurrency = if api_semaphore.is_some() { total } else { 50 };
    let results: Vec<_> = futures::stream::iter(futs)
        .buffer_unordered(concurrency)
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

    let snapshot = ClusterSnapshot {
        schema_version: Some(SNAPSHOT_SCHEMA_VERSION),
        resources,
        scan_warnings: warnings,
        cluster_url: config.cluster_url.to_string(),
        taken_at: chrono::Utc::now().to_rfc3339(),
        namespaces: vec![namespace.to_string()],
        scope: Some(SnapshotScope {
            mode: "single-namespace".to_string(),
            requested_namespaces: vec![namespace.to_string()],
            complete_namespaces: vec![namespace.to_string()],
            ..Default::default()
        }),
    };

    Ok(snapshot)
}

pub fn save_snapshot(snapshot: &ClusterSnapshot, path: &str) -> Result<()> {
    let tmp_path = format!("{}.tmp", path);
    let json = serde_json::to_string_pretty(snapshot)?;
    std::fs::write(&tmp_path, &json)?;
    std::fs::rename(&tmp_path, path)?;
    Ok(())
}

pub fn load_snapshot(path: &str) -> Result<ClusterSnapshot> {
    let data = std::fs::read_to_string(path)?;
    let snapshot: ClusterSnapshot = serde_json::from_str(&data)?;
    if let Some(v) = snapshot.schema_version
        && v > SNAPSHOT_SCHEMA_VERSION
    {
        bail!(
            "Unsupported snapshot schema version {} (max supported: {}). Please upgrade oc-deps.",
            v,
            SNAPSHOT_SCHEMA_VERSION
        );
    }
    Ok(snapshot)
}

// ──────────────────────────────────────────────────────────────
//  Snapshot diff
// ──────────────────────────────────────────────────────────────

type LogicalKey = (String, String, Option<String>, String); // (group, kind, namespace, name)

fn logical_key(id: &ResourceId) -> LogicalKey {
    (
        id.group.clone(),
        id.kind.clone(),
        id.namespace.clone(),
        id.name.clone(),
    )
}

fn gvk_label(id: &ResourceId) -> String {
    if id.group.is_empty() {
        format!("{}/{}", id.version, id.kind)
    } else {
        format!("{}/{}/{}", id.group, id.version, id.kind)
    }
}

#[derive(Clone, Debug, Serialize)]
pub struct DiffResult {
    pub before_taken_at: String,
    pub after_taken_at: String,
    pub scope_warnings: Vec<String>,
    pub namespaces: Vec<NamespaceDiff>,
    pub summary: DiffSummary,
}

#[derive(Clone, Debug, Serialize)]
pub struct NamespaceDiff {
    pub namespace: String,
    pub added: Vec<DiffEntry>,
    pub removed: Vec<DiffEntry>,
    pub recreated: Vec<DiffEntry>,
    pub changed: Vec<DiffChange>,
}

#[derive(Clone, Debug, Serialize)]
pub struct DiffEntry {
    pub kind: String,
    pub name: String,
    pub gvk: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub uid_before: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub uid_after: Option<String>,
}

#[derive(Clone, Debug, Serialize)]
pub struct DiffChange {
    pub kind: String,
    pub name: String,
    pub gvk: String,
    pub changes: Vec<String>,
}

#[derive(Clone, Debug, Default, Serialize)]
pub struct DiffSummary {
    pub added: usize,
    pub removed: usize,
    pub recreated: usize,
    pub changed: usize,
}

const VOLATILE_ANNOTATION_KEYS: &[&str] = &[
    "kubectl.kubernetes.io/last-applied-configuration",
    "control-plane.alpha.kubernetes.io/leader",
    "deployment.kubernetes.io/desired-replicas",
    "deployment.kubernetes.io/max-replicas",
];

fn diff_spec(before: &Option<serde_json::Value>, after: &Option<serde_json::Value>) -> Vec<String> {
    match (before, after) {
        (Some(b), Some(a)) if b != a => vec!["spec changed".to_string()],
        (None, Some(_)) => vec!["spec added".to_string()],
        (Some(_), None) => vec!["spec removed".to_string()],
        _ => vec![],
    }
}

fn diff_labels(
    before: &std::collections::HashMap<String, String>,
    after: &std::collections::HashMap<String, String>,
) -> Vec<String> {
    if before == after {
        return vec![];
    }
    let mut changes = Vec::new();
    for k in after.keys() {
        if !before.contains_key(k) {
            changes.push(format!("label added: {}", k));
        }
    }
    for k in before.keys() {
        if !after.contains_key(k) {
            changes.push(format!("label removed: {}", k));
        }
    }
    for (k, v) in after {
        if let Some(bv) = before.get(k)
            && bv != v
        {
            changes.push(format!("label changed: {} ({} → {})", k, bv, v));
        }
    }
    changes
}

fn diff_annotations(
    before: &std::collections::HashMap<String, String>,
    after: &std::collections::HashMap<String, String>,
) -> Vec<String> {
    let filter = |m: &std::collections::HashMap<String, String>| -> std::collections::HashMap<String, String> {
        m.iter()
            .filter(|(k, _)| !VOLATILE_ANNOTATION_KEYS.contains(&k.as_str()))
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect()
    };
    let b = filter(before);
    let a = filter(after);
    if b == a {
        return vec![];
    }
    let mut changes = Vec::new();
    for k in a.keys() {
        if !b.contains_key(k) {
            changes.push(format!("annotation added: {}", k));
        }
    }
    for k in b.keys() {
        if !a.contains_key(k) {
            changes.push(format!("annotation removed: {}", k));
        }
    }
    for (k, v) in &a {
        if let Some(bv) = b.get(k)
            && bv != v
        {
            changes.push(format!("annotation changed: {}", k));
        }
    }
    changes
}

fn owner_ref_key(r: &OwnerRefEntry) -> String {
    format!(
        "{}|{}|{}|{}|{}",
        r.api_version, r.kind, r.name, r.uid, r.controller
    )
}

fn diff_owner_refs(before: &[OwnerRefEntry], after: &[OwnerRefEntry]) -> Vec<String> {
    let b_set: HashSet<String> = before.iter().map(owner_ref_key).collect();
    let a_set: HashSet<String> = after.iter().map(owner_ref_key).collect();
    if b_set == a_set {
        return vec![];
    }
    vec!["ownerRefs changed".to_string()]
}

fn diff_data_fields(before: &ResourceEntry, after: &ResourceEntry) -> Vec<String> {
    let mut changes = Vec::new();

    match (&before.data_keys, &after.data_keys) {
        (Some(bk), Some(ak)) if bk != ak => {
            changes.push(format!("data keys: {:?} → {:?}", bk, ak));
        }
        _ => {}
    }

    match (&before.data_hash, &after.data_hash) {
        (Some(bh), Some(ah)) if bh != ah => {
            changes.push("data content changed".to_string());
        }
        _ => {}
    }

    if let (Some(bh), Some(ah)) = (&before.secret_value_hashes, &after.secret_value_hashes) {
        for k in ah.keys() {
            if !bh.contains_key(k) {
                changes.push(format!("secret key added: {}", k));
            }
        }
        for k in bh.keys() {
            if !ah.contains_key(k) {
                changes.push(format!("secret key removed: {}", k));
            }
        }
        for (k, av) in ah {
            if let Some(bv) = bh.get(k)
                && bv != av
            {
                changes.push(format!("secret key value changed: {}", k));
            }
        }
    }

    changes
}

pub fn diff_snapshots(before: &ClusterSnapshot, after: &ClusterSnapshot) -> Result<DiffResult> {
    let max_known_version = SNAPSHOT_SCHEMA_VERSION;
    for (label, snap) in [("before", before), ("after", after)] {
        if let Some(v) = snap.schema_version
            && v > max_known_version
        {
            bail!(
                "Unsupported snapshot schema version {} in {} snapshot (max supported: {})",
                v,
                label,
                max_known_version
            );
        }
    }

    let mut scope_warnings = Vec::new();

    let bv = before.schema_version;
    let av = after.schema_version;
    if bv != av {
        scope_warnings.push(format!(
            "Schema version mismatch: before={}, after={}. ConfigMap/Secret data comparison may be incomplete",
            bv.map_or("legacy".into(), |v| v.to_string()),
            av.map_or("legacy".into(), |v| v.to_string()),
        ));
    }
    let has_old_schema = bv.is_none()
        || av.is_none()
        || bv < Some(SNAPSHOT_SCHEMA_VERSION)
        || av < Some(SNAPSHOT_SCHEMA_VERSION);
    if has_old_schema {
        scope_warnings.push(
            "One or both snapshots use an older schema. ConfigMap/Secret data comparison is unavailable for resources from old-schema snapshots".to_string(),
        );
    }
    if before.cluster_url != after.cluster_url {
        scope_warnings.push(format!(
            "Different clusters: {} vs {}",
            before.cluster_url, after.cluster_url
        ));
    }
    let b_ns: std::collections::BTreeSet<_> = before.namespaces.iter().cloned().collect();
    let a_ns: std::collections::BTreeSet<_> = after.namespaces.iter().cloned().collect();
    if b_ns != a_ns {
        scope_warnings.push(format!("Different namespaces: {:?} vs {:?}", b_ns, a_ns));
    }
    // Scope comparison (v3+)
    match (&before.scope, &after.scope) {
        (None, Some(_)) | (Some(_), None) => {
            scope_warnings.push(
                "Scope comparison unavailable (one snapshot is v2 or earlier without scope metadata)".to_string(),
            );
        }
        (Some(bs), Some(as_)) => {
            if bs.mode != as_.mode {
                scope_warnings.push(format!(
                    "Different snapshot modes: {} vs {}",
                    bs.mode, as_.mode
                ));
            }
            if bs.namespace_selectors != as_.namespace_selectors
                || bs.exclude_namespaces != as_.exclude_namespaces
                || bs.exclude_system_namespaces != as_.exclude_system_namespaces
            {
                scope_warnings.push("Different namespace filters applied".to_string());
            }
            if !bs.incomplete_namespaces.is_empty() || !as_.incomplete_namespaces.is_empty() {
                scope_warnings
                    .push("One or both snapshots have incomplete namespace scans".to_string());
            }
        }
        (None, None) => {}
    }

    if !before.scan_warnings.is_empty() {
        scope_warnings.push(format!(
            "Before snapshot had {} scan warnings",
            before.scan_warnings.len()
        ));
    }
    if !after.scan_warnings.is_empty() {
        scope_warnings.push(format!(
            "After snapshot had {} scan warnings",
            after.scan_warnings.len()
        ));
    }

    let mut before_by_key: std::collections::HashMap<LogicalKey, &ResourceEntry> =
        std::collections::HashMap::new();
    for entry in before.resources.values() {
        before_by_key.insert(logical_key(&entry.id), entry);
    }

    let mut after_by_key: std::collections::HashMap<LogicalKey, &ResourceEntry> =
        std::collections::HashMap::new();
    for entry in after.resources.values() {
        after_by_key.insert(logical_key(&entry.id), entry);
    }

    // Collect all namespaces from actual resources (including cluster-scoped as "")
    let all_namespaces: std::collections::BTreeSet<String> = before_by_key
        .keys()
        .chain(after_by_key.keys())
        .map(|k| k.2.clone().unwrap_or_default())
        .collect();

    let mut summary = DiffSummary::default();
    let mut ns_diffs = Vec::new();

    for ns in &all_namespaces {
        let mut added = Vec::new();
        let mut removed = Vec::new();
        let mut recreated = Vec::new();
        let mut changed = Vec::new();

        for (key, b_entry) in &before_by_key {
            let entry_ns = key.2.as_deref().unwrap_or("");
            if entry_ns != ns {
                continue;
            }
            match after_by_key.get(key) {
                None => {
                    removed.push(DiffEntry {
                        kind: b_entry.id.kind.clone(),
                        name: b_entry.id.name.clone(),
                        gvk: gvk_label(&b_entry.id),
                        uid_before: b_entry.id.uid.clone(),
                        uid_after: None,
                    });
                }
                Some(a_entry) => {
                    if b_entry.id.uid != a_entry.id.uid {
                        recreated.push(DiffEntry {
                            kind: b_entry.id.kind.clone(),
                            name: b_entry.id.name.clone(),
                            gvk: gvk_label(&b_entry.id),
                            uid_before: b_entry.id.uid.clone(),
                            uid_after: a_entry.id.uid.clone(),
                        });
                    } else {
                        let mut entry_changes = Vec::new();
                        entry_changes.extend(diff_spec(&b_entry.raw_spec, &a_entry.raw_spec));
                        entry_changes.extend(diff_labels(&b_entry.labels, &a_entry.labels));
                        entry_changes
                            .extend(diff_annotations(&b_entry.annotations, &a_entry.annotations));
                        entry_changes
                            .extend(diff_owner_refs(&b_entry.owner_refs, &a_entry.owner_refs));
                        entry_changes.extend(diff_data_fields(b_entry, a_entry));
                        if !entry_changes.is_empty() {
                            changed.push(DiffChange {
                                kind: a_entry.id.kind.clone(),
                                name: a_entry.id.name.clone(),
                                gvk: gvk_label(&a_entry.id),
                                changes: entry_changes,
                            });
                        }
                    }
                }
            }
        }

        for (key, a_entry) in &after_by_key {
            let entry_ns = key.2.as_deref().unwrap_or("");
            if entry_ns != ns {
                continue;
            }
            if !before_by_key.contains_key(key) {
                added.push(DiffEntry {
                    kind: a_entry.id.kind.clone(),
                    name: a_entry.id.name.clone(),
                    gvk: gvk_label(&a_entry.id),
                    uid_before: None,
                    uid_after: a_entry.id.uid.clone(),
                });
            }
        }

        added.sort_by(|a, b| a.kind.cmp(&b.kind).then(a.name.cmp(&b.name)));
        removed.sort_by(|a, b| a.kind.cmp(&b.kind).then(a.name.cmp(&b.name)));
        recreated.sort_by(|a, b| a.kind.cmp(&b.kind).then(a.name.cmp(&b.name)));
        changed.sort_by(|a, b| a.kind.cmp(&b.kind).then(a.name.cmp(&b.name)));

        summary.added += added.len();
        summary.removed += removed.len();
        summary.recreated += recreated.len();
        summary.changed += changed.len();

        if !added.is_empty() || !removed.is_empty() || !recreated.is_empty() || !changed.is_empty()
        {
            let display_ns = if ns.is_empty() {
                "(cluster-scoped)".to_string()
            } else {
                ns.clone()
            };
            ns_diffs.push(NamespaceDiff {
                namespace: display_ns,
                added,
                removed,
                recreated,
                changed,
            });
        }
    }

    Ok(DiffResult {
        before_taken_at: before.taken_at.clone(),
        after_taken_at: after.taken_at.clone(),
        scope_warnings,
        namespaces: ns_diffs,
        summary,
    })
}

pub fn print_diff_tree(result: &DiffResult) {
    if !result.scope_warnings.is_empty() {
        eprintln!("⚠ Snapshot scope:");
        for w in &result.scope_warnings {
            eprintln!("  {}", w);
        }
        eprintln!();
    }

    for ns_diff in &result.namespaces {
        println!("Namespace: {}", ns_diff.namespace);
        println!();

        if !ns_diff.added.is_empty() {
            println!("  Added ({}):", ns_diff.added.len());
            for e in &ns_diff.added {
                println!("    \x1b[32m+ {}/{}\x1b[0m  [{}]", e.kind, e.name, e.gvk);
            }
        }

        if !ns_diff.removed.is_empty() {
            println!("  Removed ({}):", ns_diff.removed.len());
            for e in &ns_diff.removed {
                println!("    \x1b[31m- {}/{}\x1b[0m  [{}]", e.kind, e.name, e.gvk);
            }
        }

        if !ns_diff.recreated.is_empty() {
            println!("  Recreated ({}):", ns_diff.recreated.len());
            for e in &ns_diff.recreated {
                println!(
                    "    \x1b[33m↻ {}/{}\x1b[0m  [UID {} → {}]",
                    e.kind,
                    e.name,
                    e.uid_before.as_deref().unwrap_or("?"),
                    e.uid_after.as_deref().unwrap_or("?")
                );
            }
        }

        if !ns_diff.changed.is_empty() {
            println!("  Changed ({}):", ns_diff.changed.len());
            for c in &ns_diff.changed {
                println!(
                    "    \x1b[36m~ {}/{}\x1b[0m  {}",
                    c.kind,
                    c.name,
                    c.changes.join(", ")
                );
            }
        }

        println!();
    }

    if result.namespaces.is_empty() {
        println!("No differences found.");
    } else {
        println!(
            "Summary: \x1b[32m+{} added\x1b[0m, \x1b[31m-{} removed\x1b[0m, \x1b[33m↻{} recreated\x1b[0m, \x1b[36m~{} changed\x1b[0m",
            result.summary.added,
            result.summary.removed,
            result.summary.recreated,
            result.summary.changed,
        );
    }
}

pub fn print_diff_table(result: &DiffResult) {
    if !result.scope_warnings.is_empty() {
        eprintln!("⚠ Snapshot scope:");
        for w in &result.scope_warnings {
            eprintln!("  {}", w);
        }
        eprintln!();
    }

    let mut table = comfy_table::Table::new();
    table.set_header(vec!["Status", "Kind", "Name", "Namespace", "Details"]);

    for ns_diff in &result.namespaces {
        for e in &ns_diff.added {
            table.add_row(vec!["Added", &e.kind, &e.name, &ns_diff.namespace, ""]);
        }
        for e in &ns_diff.removed {
            table.add_row(vec!["Removed", &e.kind, &e.name, &ns_diff.namespace, ""]);
        }
        for e in &ns_diff.recreated {
            table.add_row(vec![
                "Recreated",
                &e.kind,
                &e.name,
                &ns_diff.namespace,
                "UID changed",
            ]);
        }
        for c in &ns_diff.changed {
            table.add_row(vec![
                "Changed",
                &c.kind,
                &c.name,
                &ns_diff.namespace,
                &c.changes.join(", "),
            ]);
        }
    }
    println!("{table}");

    println!(
        "\nSummary: +{} added, -{} removed, ↻{} recreated, ~{} changed",
        result.summary.added,
        result.summary.removed,
        result.summary.recreated,
        result.summary.changed,
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_entry(
        group: &str,
        kind: &str,
        name: &str,
        ns: &str,
        uid: &str,
    ) -> (String, ResourceEntry) {
        let id = ResourceId {
            group: group.into(),
            version: "v1".into(),
            kind: kind.into(),
            namespace: Some(ns.into()),
            name: name.into(),
            uid: Some(uid.into()),
        };
        (
            uid.into(),
            ResourceEntry {
                id,
                owner_refs: vec![],
                spec_refs: vec![],
                labels: HashMap::new(),
                annotations: HashMap::new(),
                raw_spec: None,
                data_keys: None,
                data_hash: None,
                secret_value_hashes: None,
            },
        )
    }

    fn make_snapshot(entries: Vec<(String, ResourceEntry)>, ns: &str) -> ClusterSnapshot {
        ClusterSnapshot {
            schema_version: Some(SNAPSHOT_SCHEMA_VERSION),
            resources: entries.into_iter().collect(),
            scan_warnings: vec![],
            cluster_url: "https://api.test:6443".into(),
            taken_at: "2026-01-01T00:00:00Z".into(),
            namespaces: vec![ns.into()],
            scope: None,
        }
    }

    #[test]
    fn identical_snapshots_no_diff() {
        let snap = make_snapshot(
            vec![make_entry("apps", "Deployment", "web", "default", "uid-1")],
            "default",
        );
        let result = diff_snapshots(&snap, &snap).unwrap();
        assert!(result.namespaces.is_empty());
        assert_eq!(result.summary.added, 0);
        assert_eq!(result.summary.removed, 0);
    }

    #[test]
    fn added_resource_detected() {
        let before = make_snapshot(vec![], "default");
        let after = make_snapshot(
            vec![make_entry("apps", "Deployment", "web", "default", "uid-1")],
            "default",
        );
        let result = diff_snapshots(&before, &after).unwrap();
        assert_eq!(result.summary.added, 1);
        assert_eq!(result.namespaces[0].added[0].name, "web");
    }

    #[test]
    fn removed_resource_detected() {
        let before = make_snapshot(
            vec![make_entry("apps", "Deployment", "web", "default", "uid-1")],
            "default",
        );
        let after = make_snapshot(vec![], "default");
        let result = diff_snapshots(&before, &after).unwrap();
        assert_eq!(result.summary.removed, 1);
        assert_eq!(result.namespaces[0].removed[0].name, "web");
    }

    #[test]
    fn recreated_resource_detected() {
        let before = make_snapshot(
            vec![make_entry("apps", "Deployment", "web", "default", "uid-1")],
            "default",
        );
        let after = make_snapshot(
            vec![make_entry("apps", "Deployment", "web", "default", "uid-2")],
            "default",
        );
        let result = diff_snapshots(&before, &after).unwrap();
        assert_eq!(result.summary.recreated, 1);
        assert_eq!(
            result.namespaces[0].recreated[0].uid_before,
            Some("uid-1".into())
        );
        assert_eq!(
            result.namespaces[0].recreated[0].uid_after,
            Some("uid-2".into())
        );
    }

    #[test]
    fn changed_spec_detected() {
        let (uid, mut before_entry) = make_entry("apps", "Deployment", "web", "default", "uid-1");
        before_entry.raw_spec = Some(serde_json::json!({"replicas": 3}));
        let mut after_entry = before_entry.clone();
        after_entry.raw_spec = Some(serde_json::json!({"replicas": 1}));

        let before = make_snapshot(vec![(uid.clone(), before_entry)], "default");
        let after = make_snapshot(vec![(uid, after_entry)], "default");
        let result = diff_snapshots(&before, &after).unwrap();
        assert_eq!(result.summary.changed, 1);
        assert!(
            result.namespaces[0].changed[0]
                .changes
                .iter()
                .any(|c| c.contains("spec"))
        );
    }

    #[test]
    fn changed_labels_detected() {
        let (uid, mut before_entry) = make_entry("apps", "Deployment", "web", "default", "uid-1");
        before_entry.labels.insert("app".into(), "v1".into());
        let mut after_entry = before_entry.clone();
        after_entry.labels.insert("app".into(), "v2".into());

        let before = make_snapshot(vec![(uid.clone(), before_entry)], "default");
        let after = make_snapshot(vec![(uid, after_entry)], "default");
        let result = diff_snapshots(&before, &after).unwrap();
        assert_eq!(result.summary.changed, 1);
        assert!(
            result.namespaces[0].changed[0]
                .changes
                .iter()
                .any(|c| c.contains("label changed"))
        );
    }

    #[test]
    fn volatile_annotations_ignored() {
        let (uid, mut before_entry) = make_entry("apps", "Deployment", "web", "default", "uid-1");
        before_entry.annotations.insert(
            "kubectl.kubernetes.io/last-applied-configuration".into(),
            "old".into(),
        );
        let mut after_entry = before_entry.clone();
        after_entry.annotations.insert(
            "kubectl.kubernetes.io/last-applied-configuration".into(),
            "new".into(),
        );

        let before = make_snapshot(vec![(uid.clone(), before_entry)], "default");
        let after = make_snapshot(vec![(uid, after_entry)], "default");
        let result = diff_snapshots(&before, &after).unwrap();
        assert_eq!(result.summary.changed, 0);
    }

    #[test]
    fn scope_warning_different_clusters() {
        let mut before = make_snapshot(vec![], "default");
        before.cluster_url = "https://cluster-a:6443".into();
        let mut after = make_snapshot(vec![], "default");
        after.cluster_url = "https://cluster-b:6443".into();
        let result = diff_snapshots(&before, &after).unwrap();
        assert!(
            result
                .scope_warnings
                .iter()
                .any(|w| w.contains("Different clusters"))
        );
    }

    #[test]
    fn scope_warning_different_namespaces() {
        let before = make_snapshot(vec![], "ns-a");
        let after = make_snapshot(vec![], "ns-b");
        let result = diff_snapshots(&before, &after).unwrap();
        assert!(
            result
                .scope_warnings
                .iter()
                .any(|w| w.contains("Different namespaces"))
        );
    }

    #[test]
    fn scope_warning_scan_warnings_present() {
        let mut before = make_snapshot(vec![], "default");
        before.scan_warnings.push(ScanWarning::Forbidden {
            gvr: "v1/secrets".into(),
            status: 403,
        });
        let after = make_snapshot(vec![], "default");
        let result = diff_snapshots(&before, &after).unwrap();
        assert!(
            result
                .scope_warnings
                .iter()
                .any(|w| w.contains("scan warnings"))
        );
    }

    #[test]
    fn logical_identity_matches_by_group_kind_ns_name() {
        let before = make_snapshot(
            vec![make_entry("apps", "Deployment", "web", "default", "uid-1")],
            "default",
        );
        let after = make_snapshot(
            vec![make_entry(
                "extensions",
                "Deployment",
                "web",
                "default",
                "uid-2",
            )],
            "default",
        );
        let result = diff_snapshots(&before, &after).unwrap();
        assert_eq!(
            result.summary.added, 1,
            "different group = different resource"
        );
        assert_eq!(result.summary.removed, 1);
        assert_eq!(result.summary.recreated, 0);
    }

    #[test]
    fn kubeconfig_not_required() {
        let json = serde_json::json!({
            "resources": {},
            "scan_warnings": [],
            "cluster_url": "https://test:6443",
            "taken_at": "2026-01-01T00:00:00Z",
            "namespaces": ["default"]
        });
        let snap: ClusterSnapshot = serde_json::from_value(json).unwrap();
        let result = diff_snapshots(&snap, &snap).unwrap();
        assert!(result.namespaces.is_empty());
    }

    #[test]
    fn json_output_serializable() {
        let before = make_snapshot(
            vec![make_entry("apps", "Deployment", "web", "default", "uid-1")],
            "default",
        );
        let after = make_snapshot(vec![], "default");
        let result = diff_snapshots(&before, &after).unwrap();
        let json = serde_json::to_string_pretty(&result).unwrap();
        assert!(json.contains("\"removed\""));
        assert!(json.contains("web"));
    }

    #[test]
    fn future_schema_version_rejected() {
        let mut snap = make_snapshot(vec![], "default");
        snap.schema_version = Some(999);
        let snap2 = make_snapshot(vec![], "default");
        assert!(diff_snapshots(&snap, &snap2).is_err());
        assert!(diff_snapshots(&snap2, &snap).is_err());
    }

    #[test]
    fn old_schema_no_version_accepted() {
        let mut snap = make_snapshot(vec![], "default");
        snap.schema_version = None;
        let result = diff_snapshots(&snap, &snap).unwrap();
        assert!(result.namespaces.is_empty());
    }

    #[test]
    fn cluster_scoped_resource_detected() {
        let (uid, mut entry) = make_entry(
            "apiextensions.k8s.io",
            "CustomResourceDefinition",
            "widgets.example.io",
            "",
            "uid-crd",
        );
        entry.id.namespace = None;
        let before = make_snapshot(vec![], "default");
        let after = make_snapshot(vec![(uid, entry)], "default");
        let result = diff_snapshots(&before, &after).unwrap();
        assert_eq!(result.summary.added, 1);
        assert!(
            result
                .namespaces
                .iter()
                .any(|n| n.namespace == "(cluster-scoped)")
        );
    }

    #[test]
    fn configmap_data_change_detected() {
        let (uid, mut before_entry) = make_entry("", "ConfigMap", "settings", "default", "uid-cm");
        before_entry.data_keys = Some(vec!["key1".into(), "key2".into()]);
        before_entry.data_hash = Some("hash-before".into());
        let mut after_entry = before_entry.clone();
        after_entry.data_keys = Some(vec!["key1".into(), "key3".into()]);
        after_entry.data_hash = Some("hash-after".into());

        let before = make_snapshot(vec![(uid.clone(), before_entry)], "default");
        let after = make_snapshot(vec![(uid, after_entry)], "default");
        let result = diff_snapshots(&before, &after).unwrap();
        assert_eq!(result.summary.changed, 1);
        let changes = &result.namespaces[0].changed[0].changes;
        assert!(changes.iter().any(|c| c.contains("data keys")));
        assert!(changes.iter().any(|c| c.contains("data content changed")));
    }

    #[test]
    fn secret_key_value_change_detected() {
        let (uid, mut before_entry) = make_entry("", "Secret", "creds", "default", "uid-secret");
        before_entry.data_keys = Some(vec!["password".into()]);
        before_entry.secret_value_hashes = Some(
            [("password".into(), "hash-old".into())]
                .into_iter()
                .collect(),
        );
        let mut after_entry = before_entry.clone();
        after_entry.secret_value_hashes = Some(
            [("password".into(), "hash-new".into())]
                .into_iter()
                .collect(),
        );

        let before = make_snapshot(vec![(uid.clone(), before_entry)], "default");
        let after = make_snapshot(vec![(uid, after_entry)], "default");
        let result = diff_snapshots(&before, &after).unwrap();
        assert_eq!(result.summary.changed, 1);
        assert!(
            result.namespaces[0].changed[0]
                .changes
                .iter()
                .any(|c| c.contains("secret key value changed: password"))
        );
    }

    #[test]
    fn old_schema_vs_current_no_false_changed() {
        let (uid, entry) = make_entry("", "ConfigMap", "settings", "default", "uid-cm");
        let mut before = make_snapshot(vec![(uid.clone(), entry.clone())], "default");
        before.schema_version = None;
        let after = make_snapshot(vec![(uid, entry)], "default");
        let result = diff_snapshots(&before, &after).unwrap();
        assert_eq!(
            result.summary.changed, 0,
            "old schema should not produce false Changed"
        );
        assert!(
            result
                .scope_warnings
                .iter()
                .any(|w| w.contains("older schema")),
            "scope warning about old schema expected"
        );
    }

    #[test]
    fn schema_version_mismatch_warning() {
        let mut before = make_snapshot(vec![], "default");
        before.schema_version = Some(1);
        let after = make_snapshot(vec![], "default");
        let result = diff_snapshots(&before, &after).unwrap();
        assert!(
            result
                .scope_warnings
                .iter()
                .any(|w| w.contains("Schema version mismatch")),
            "version mismatch should warn"
        );
    }

    #[test]
    fn secret_snapshot_no_plaintext_in_annotations() {
        let data = serde_json::json!({
            "data": {
                "password": "YWxwaGE=",
                "token": "Zmlyc3Q="
            }
        });
        let (data_keys, _data_hash, secret_hashes) = extract_data_fields("Secret", &data);
        assert_eq!(data_keys.unwrap(), vec!["password", "token"]);
        let hashes = secret_hashes.unwrap();
        assert!(
            !hashes["password"].contains("alpha"),
            "hash must not contain plaintext"
        );
        assert!(
            !hashes["token"].contains("first"),
            "hash must not contain plaintext"
        );
    }

    #[test]
    fn owner_ref_uid_change_detected() {
        let (uid, mut before_entry) = make_entry("apps", "Deployment", "web", "default", "uid-1");
        before_entry.owner_refs.push(OwnerRefEntry {
            api_version: "apps/v1".into(),
            kind: "ReplicaSet".into(),
            name: "web-rs".into(),
            uid: "owner-uid-old".into(),
            controller: true,
        });
        let mut after_entry = before_entry.clone();
        after_entry.owner_refs[0].uid = "owner-uid-new".into();

        let before = make_snapshot(vec![(uid.clone(), before_entry)], "default");
        let after = make_snapshot(vec![(uid, after_entry)], "default");
        let result = diff_snapshots(&before, &after).unwrap();
        assert_eq!(result.summary.changed, 1);
        assert!(
            result.namespaces[0].changed[0]
                .changes
                .iter()
                .any(|c| c.contains("ownerRefs"))
        );
    }

    #[test]
    fn namespace_set_comparison_ignores_order() {
        let mut before = make_snapshot(vec![], "ns-a");
        before.namespaces = vec!["ns-b".into(), "ns-a".into()];
        let mut after = make_snapshot(vec![], "ns-a");
        after.namespaces = vec!["ns-a".into(), "ns-b".into()];
        let result = diff_snapshots(&before, &after).unwrap();
        assert!(
            !result
                .scope_warnings
                .iter()
                .any(|w| w.contains("namespace")),
            "same namespace set in different order should not warn"
        );
    }

    #[test]
    fn atomic_save_creates_file() {
        let dir = std::env::temp_dir().join("oc-deps-test-atomic");
        let _ = std::fs::create_dir_all(&dir);
        let path = dir.join("test-snap.json");
        let snap = make_snapshot(vec![], "default");
        save_snapshot(&snap, path.to_str().unwrap()).unwrap();
        assert!(path.exists());
        // tmp file should not remain
        assert!(!dir.join("test-snap.json.tmp").exists());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn atomic_save_does_not_corrupt_on_existing() {
        let dir = std::env::temp_dir().join("oc-deps-test-atomic2");
        let _ = std::fs::create_dir_all(&dir);
        let path = dir.join("snap.json");
        let snap1 = make_snapshot(
            vec![make_entry("", "ConfigMap", "cm1", "default", "uid-1")],
            "default",
        );
        save_snapshot(&snap1, path.to_str().unwrap()).unwrap();
        // Save again — should overwrite cleanly
        let snap2 = make_snapshot(
            vec![make_entry("", "ConfigMap", "cm2", "default", "uid-2")],
            "default",
        );
        save_snapshot(&snap2, path.to_str().unwrap()).unwrap();
        let loaded = load_snapshot(path.to_str().unwrap()).unwrap();
        assert!(loaded.resources.contains_key("uid-2"));
        assert!(!loaded.resources.contains_key("uid-1"));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn load_rejects_future_schema_version() {
        let dir = std::env::temp_dir().join("oc-deps-test-future");
        let _ = std::fs::create_dir_all(&dir);
        let path = dir.join("future.json");
        let json = serde_json::json!({
            "schema_version": 99,
            "resources": {},
            "scan_warnings": [],
            "cluster_url": "https://test:6443",
            "taken_at": "2026-01-01T00:00:00Z",
            "namespaces": ["default"]
        });
        std::fs::write(&path, serde_json::to_string(&json).unwrap()).unwrap();
        let result = load_snapshot(path.to_str().unwrap());
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("Unsupported"));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn diff_scope_warning_v2_vs_v3() {
        let mut before = make_snapshot(vec![], "default");
        before.scope = None; // v2 style
        let mut after = make_snapshot(vec![], "default");
        after.scope = Some(SnapshotScope {
            mode: "single-namespace".into(),
            ..Default::default()
        });
        let result = diff_snapshots(&before, &after).unwrap();
        assert!(
            result
                .scope_warnings
                .iter()
                .any(|w| w.contains("v2 or earlier")),
            "should warn about v2 snapshot missing scope"
        );
    }

    #[test]
    fn diff_scope_warning_different_mode() {
        let mut before = make_snapshot(vec![], "default");
        before.scope = Some(SnapshotScope {
            mode: "single-namespace".into(),
            ..Default::default()
        });
        let mut after = make_snapshot(vec![], "default");
        after.scope = Some(SnapshotScope {
            mode: "all-namespaces".into(),
            ..Default::default()
        });
        let result = diff_snapshots(&before, &after).unwrap();
        assert!(
            result
                .scope_warnings
                .iter()
                .any(|w| w.contains("Different snapshot modes")),
        );
    }

    #[test]
    fn diff_scope_warning_different_filters() {
        let mut before = make_snapshot(vec![], "default");
        before.scope = Some(SnapshotScope {
            mode: "filtered".into(),
            namespace_selectors: vec!["env=prod".into()],
            ..Default::default()
        });
        let mut after = make_snapshot(vec![], "default");
        after.scope = Some(SnapshotScope {
            mode: "filtered".into(),
            namespace_selectors: vec!["env=dev".into()],
            ..Default::default()
        });
        let result = diff_snapshots(&before, &after).unwrap();
        assert!(
            result
                .scope_warnings
                .iter()
                .any(|w| w.contains("Different namespace filters")),
        );
    }

    #[test]
    fn diff_scope_same_mode_no_warning() {
        let mut before = make_snapshot(vec![], "default");
        before.scope = Some(SnapshotScope {
            mode: "all-namespaces".into(),
            ..Default::default()
        });
        let mut after = make_snapshot(vec![], "default");
        after.scope = Some(SnapshotScope {
            mode: "all-namespaces".into(),
            ..Default::default()
        });
        let result = diff_snapshots(&before, &after).unwrap();
        assert!(
            !result
                .scope_warnings
                .iter()
                .any(|w| w.contains("mode") || w.contains("filter")),
        );
    }
}
