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
use serde::Serialize;

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
        .filter(|(k, info)| info.namespaced && info.listable && !skip_kinds.contains(k.as_str()))
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

    let snapshot = ClusterSnapshot {
        resources,
        scan_warnings: warnings,
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

pub fn load_snapshot(path: &str) -> Result<ClusterSnapshot> {
    let data = std::fs::read_to_string(path)?;
    let snapshot: ClusterSnapshot = serde_json::from_str(&data)?;
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

fn diff_owner_refs(before: &[OwnerRefEntry], after: &[OwnerRefEntry]) -> Vec<String> {
    let b_set: std::collections::HashSet<String> = before
        .iter()
        .map(|r| format!("{}/{}", r.kind, r.name))
        .collect();
    let a_set: std::collections::HashSet<String> = after
        .iter()
        .map(|r| format!("{}/{}", r.kind, r.name))
        .collect();
    if b_set == a_set {
        return vec![];
    }
    vec!["ownerRefs changed".to_string()]
}

pub fn diff_snapshots(before: &ClusterSnapshot, after: &ClusterSnapshot) -> DiffResult {
    let mut scope_warnings = Vec::new();
    if before.cluster_url != after.cluster_url {
        scope_warnings.push(format!(
            "Different clusters: {} vs {}",
            before.cluster_url, after.cluster_url
        ));
    }
    if before.namespaces != after.namespaces {
        scope_warnings.push(format!(
            "Different namespaces: {:?} vs {:?}",
            before.namespaces, after.namespaces
        ));
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

    let all_namespaces: std::collections::BTreeSet<String> = before
        .namespaces
        .iter()
        .chain(after.namespaces.iter())
        .cloned()
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
            ns_diffs.push(NamespaceDiff {
                namespace: ns.clone(),
                added,
                removed,
                recreated,
                changed,
            });
        }
    }

    DiffResult {
        before_taken_at: before.taken_at.clone(),
        after_taken_at: after.taken_at.clone(),
        scope_warnings,
        namespaces: ns_diffs,
        summary,
    }
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
            },
        )
    }

    fn make_snapshot(entries: Vec<(String, ResourceEntry)>, ns: &str) -> ClusterSnapshot {
        ClusterSnapshot {
            resources: entries.into_iter().collect(),
            scan_warnings: vec![],
            cluster_url: "https://api.test:6443".into(),
            taken_at: "2026-01-01T00:00:00Z".into(),
            namespaces: vec![ns.into()],
        }
    }

    #[test]
    fn identical_snapshots_no_diff() {
        let snap = make_snapshot(
            vec![make_entry("apps", "Deployment", "web", "default", "uid-1")],
            "default",
        );
        let result = diff_snapshots(&snap, &snap);
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
        let result = diff_snapshots(&before, &after);
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
        let result = diff_snapshots(&before, &after);
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
        let result = diff_snapshots(&before, &after);
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
        let result = diff_snapshots(&before, &after);
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
        let result = diff_snapshots(&before, &after);
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
        let result = diff_snapshots(&before, &after);
        assert_eq!(result.summary.changed, 0);
    }

    #[test]
    fn scope_warning_different_clusters() {
        let mut before = make_snapshot(vec![], "default");
        before.cluster_url = "https://cluster-a:6443".into();
        let mut after = make_snapshot(vec![], "default");
        after.cluster_url = "https://cluster-b:6443".into();
        let result = diff_snapshots(&before, &after);
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
        let result = diff_snapshots(&before, &after);
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
        let result = diff_snapshots(&before, &after);
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
        let result = diff_snapshots(&before, &after);
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
        let result = diff_snapshots(&snap, &snap);
        assert!(result.namespaces.is_empty());
    }

    #[test]
    fn json_output_serializable() {
        let before = make_snapshot(
            vec![make_entry("apps", "Deployment", "web", "default", "uid-1")],
            "default",
        );
        let after = make_snapshot(vec![], "default");
        let result = diff_snapshots(&before, &after);
        let json = serde_json::to_string_pretty(&result).unwrap();
        assert!(json.contains("\"removed\""));
        assert!(json.contains("web"));
    }
}
