//! Corpus replay test for Phase C audit.
//!
//! Converts inventory JSONL to v4 snapshot JSON (preserving all raw observations),
//! runs `oc-deps snapshot audit` via CLI, and verifies exact classification counts.
//!
//! Runs only when CORPUS_REPLAY=1 is set (requires corpus archive).

use std::collections::HashMap;
use std::io::BufRead;
use std::path::{Path, PathBuf};
use std::process::Command;

fn corpus_archive() -> PathBuf {
    PathBuf::from("logs/discovery-baseline/20260926-cycle-b2-3c77a17/full-corpus.tar.zst")
}

fn binary() -> &'static str {
    env!("CARGO_BIN_EXE_oc-deps")
}

fn should_run() -> bool {
    std::env::var("CORPUS_REPLAY").is_ok()
}

#[derive(serde::Deserialize)]
struct InventoryRow {
    group: String,
    version: String,
    resource: String,
    kind: String,
    namespace: Option<String>,
    name: String,
    uid: Option<String>,
    #[serde(rename = "deletionTimestamp")]
    deletion_timestamp: Option<String>,
    finalizers: Option<Vec<String>>,
    #[serde(rename = "ownerReferences")]
    owner_references: Option<Vec<serde_json::Value>>,
    labels: Option<HashMap<String, String>>,
    annotations: Option<HashMap<String, String>>,
}

#[derive(serde::Deserialize)]
struct ORef {
    #[serde(rename = "apiVersion")]
    api_version: String,
    kind: String,
    name: String,
    uid: String,
    #[serde(default)]
    controller: bool,
    #[serde(default, rename = "blockOwnerDeletion")]
    block_owner_deletion: bool,
}

#[derive(Clone, serde::Serialize)]
struct OwnerRefSer {
    api_version: String,
    kind: String,
    name: String,
    uid: String,
    controller: bool,
    block_owner_deletion: bool,
}

#[derive(serde::Serialize)]
struct SnapshotObservation {
    group: String,
    version: String,
    resource: String,
    kind: String,
    namespace: Option<String>,
    name: String,
    uid: Option<String>,
    owner_refs: Vec<OwnerRefSer>,
    spec_refs: Vec<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    deletion_timestamp: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    finalizers: Option<Vec<String>>,
    labels: HashMap<String, String>,
}

#[derive(serde::Serialize)]
struct ResourceId {
    group: String,
    version: String,
    kind: String,
    namespace: Option<String>,
    name: String,
    uid: Option<String>,
}

#[derive(serde::Serialize)]
struct ResourceEntry {
    id: ResourceId,
    owner_refs: Vec<OwnerRefSer>,
    spec_refs: Vec<serde_json::Value>,
    labels: HashMap<String, String>,
    annotations: HashMap<String, String>,
    raw_spec: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    deletion_timestamp: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    finalizers: Option<Vec<String>>,
}

#[derive(serde::Serialize)]
struct Snapshot {
    schema_version: u32,
    resources: HashMap<String, ResourceEntry>,
    scan_warnings: Vec<serde_json::Value>,
    cluster_url: String,
    taken_at: String,
    namespaces: Vec<String>,
    observations: Vec<SnapshotObservation>,
}

fn convert_orefs(raw: Vec<serde_json::Value>) -> Vec<OwnerRefSer> {
    raw.into_iter()
        .filter_map(|v| {
            let o: ORef = serde_json::from_value(v).ok()?;
            Some(OwnerRefSer {
                api_version: o.api_version,
                kind: o.kind,
                name: o.name,
                uid: o.uid,
                controller: o.controller,
                block_owner_deletion: o.block_owner_deletion,
            })
        })
        .collect()
}

fn inventory_to_snapshot(path: &Path) -> (Snapshot, usize) {
    let file = std::fs::File::open(path).unwrap();
    let reader = std::io::BufReader::new(file);
    let mut resources: HashMap<String, ResourceEntry> = HashMap::new();
    let mut observations: Vec<SnapshotObservation> = Vec::new();
    let mut raw_count = 0usize;

    for line in reader.lines() {
        let line = line.unwrap();
        let row: InventoryRow = serde_json::from_str(&line).unwrap();
        raw_count += 1;

        let orefs = convert_orefs(row.owner_references.unwrap_or_default());

        observations.push(SnapshotObservation {
            group: row.group.clone(),
            version: row.version.clone(),
            resource: row.resource.clone(),
            kind: row.kind.clone(),
            namespace: row.namespace.clone(),
            name: row.name.clone(),
            uid: row.uid.clone(),
            owner_refs: orefs.clone(),
            spec_refs: vec![],
            deletion_timestamp: row.deletion_timestamp.clone(),
            finalizers: row.finalizers.clone(),
            labels: row.labels.clone().unwrap_or_default(),
        });

        if let Some(ref uid) = row.uid
            && !uid.is_empty()
            && !resources.contains_key(uid)
        {
            resources.insert(
                uid.clone(),
                ResourceEntry {
                    id: ResourceId {
                        group: row.group,
                        version: row.version,
                        kind: row.kind,
                        namespace: row.namespace,
                        name: row.name,
                        uid: Some(uid.clone()),
                    },
                    owner_refs: orefs,
                    spec_refs: vec![],
                    labels: row.labels.unwrap_or_default(),
                    annotations: row.annotations.unwrap_or_default(),
                    raw_spec: None,
                    deletion_timestamp: row.deletion_timestamp,
                    finalizers: row.finalizers,
                },
            );
        }
    }

    (
        Snapshot {
            schema_version: 4,
            resources,
            scan_warnings: vec![],
            cluster_url: "https://api.test:6443".into(),
            taken_at: "2026-01-01T00:00:00Z".into(),
            namespaces: vec![],
            observations,
        },
        raw_count,
    )
}

#[test]
fn corpus_replay_exact_counts() {
    if !should_run() {
        eprintln!("Skipping corpus replay (set CORPUS_REPLAY=1 to enable)");
        return;
    }

    let workdir = std::env::temp_dir().join(format!("oc-deps-corpus-{}", std::process::id()));
    std::fs::create_dir_all(&workdir).unwrap();

    let status = Command::new("tar")
        .args(["--zstd", "-xf"])
        .arg(corpus_archive())
        .arg("-C")
        .arg(&workdir)
        .status()
        .expect("tar failed");
    assert!(status.success());

    let (before_snap, pre_raw) =
        inventory_to_snapshot(&workdir.join("inventory/pre-inventory.jsonl"));
    let (after_snap, post_raw) =
        inventory_to_snapshot(&workdir.join("inventory/post-inventory.jsonl"));

    assert_eq!(pre_raw, 17786, "pre raw observations");
    assert_eq!(post_raw, 14761, "post raw observations");

    let before_path = workdir.join("before-snapshot.json");
    let after_path = workdir.join("after-snapshot.json");
    std::fs::write(&before_path, serde_json::to_string(&before_snap).unwrap()).unwrap();
    std::fs::write(&after_path, serde_json::to_string(&after_snap).unwrap()).unwrap();

    let plans_dir = workdir.join("batch-plans");
    let mut plan_args: Vec<String> = Vec::new();
    let mut entries: Vec<_> = std::fs::read_dir(&plans_dir)
        .unwrap()
        .filter_map(|e| e.ok())
        .filter(|e| e.path().extension().is_some_and(|ext| ext == "json"))
        .collect();
    entries.sort_by_key(|e| e.file_name());
    for entry in &entries {
        plan_args.push("--plan".to_string());
        plan_args.push(entry.path().to_string_lossy().to_string());
    }

    let catalog_path = workdir.join("inventory/gvr-catalog.json");
    let provider_path = PathBuf::from(
        "logs/discovery-baseline/20260926-cycle-b2-3c77a17/provider-api-operands.json",
    );

    let mut args = vec![
        "snapshot".to_string(),
        "audit".to_string(),
        before_path.to_string_lossy().to_string(),
        after_path.to_string_lossy().to_string(),
    ];
    args.extend(plan_args);
    args.push("--gvr-catalog".to_string());
    args.push(catalog_path.to_string_lossy().to_string());
    args.push("--provider-operands".to_string());
    args.push(provider_path.to_string_lossy().to_string());
    args.push("-o".to_string());
    args.push("json".to_string());

    let output = Command::new(binary())
        .args(&args)
        .output()
        .expect("failed to run oc-deps");

    assert!(
        output.status.success(),
        "audit failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let report: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("invalid JSON output");

    let summary = &report["classification_summary"];
    let direct_delete = summary["PlannedDirectDelete"].as_u64().unwrap_or(0);
    let expect = summary["ExpectedControllerCleanup"].as_u64().unwrap_or(0);
    let descendant = summary["OwnerRefGcDescendant"].as_u64().unwrap_or(0);
    let derived = summary["DerivedSideEffect"].as_u64().unwrap_or(0);
    let total_removed = report["layers"]["physical_uids"]["removed"]
        .as_u64()
        .unwrap_or(0);
    let closure_seeds = report["closure"]["delete_seeds"].as_u64().unwrap_or(0);
    let closure_total = report["closure"]["total_closure"].as_u64().unwrap_or(0);
    let newly_term = report["terminating"]["newly_terminating"]
        .as_u64()
        .unwrap_or(0);
    let provider_count = report["provider_operand_results"]
        .as_array()
        .map(|a| a.len())
        .unwrap_or(0);

    // 3-layer counts
    let raw_pre = report["layers"]["raw_observations"]["pre"]
        .as_u64()
        .unwrap_or(0);
    let raw_post = report["layers"]["raw_observations"]["post"]
        .as_u64()
        .unwrap_or(0);
    let phys_pre = report["layers"]["physical_uids"]["pre"]
        .as_u64()
        .unwrap_or(0);
    let phys_post = report["layers"]["physical_uids"]["post"]
        .as_u64()
        .unwrap_or(0);

    eprintln!("=== Corpus Replay Results ===");
    eprintln!("Raw: {} → {}", raw_pre, raw_post);
    eprintln!("Physical: {} → {}", phys_pre, phys_post);
    eprintln!("PlannedDirectDelete: {}", direct_delete);
    eprintln!("ExpectedControllerCleanup: {}", expect);
    eprintln!("OwnerRefGcDescendant: {}", descendant);
    eprintln!("DerivedSideEffect: {}", derived);
    eprintln!("Total removed: {}", total_removed);
    eprintln!("Closure: seeds={}, total={}", closure_seeds, closure_total);
    eprintln!("Newly terminating: {}", newly_term);
    eprintln!("Provider operands: {}", provider_count);

    // Phase C exact acceptance criteria (Issue #38)
    assert_eq!(raw_pre, 17786, "raw pre observations");
    assert_eq!(raw_post, 14761, "raw post observations");
    assert_eq!(phys_pre, 11716, "physical pre UIDs");
    assert_eq!(phys_post, 9165, "physical post UIDs");
    assert_eq!(direct_delete, 91, "direct DELETE");
    assert_eq!(expect, 72, "EXPECT");
    assert_eq!(closure_seeds, 91, "DELETE seeds");
    assert_eq!(closure_total, 1460, "DELETE-seed closure");
    assert_eq!(derived, 2, "derived");
    assert_eq!(total_removed, 2784, "total physical removed");
    assert_eq!(newly_term, 0, "newly terminating");
    assert_eq!(provider_count, 25, "provider operands");
    assert_eq!(descendant, 1282, "OwnerRefGcDescendant");

    // Verify determinism: run again
    let output2 = Command::new(binary())
        .args(&args)
        .output()
        .expect("second run failed");
    assert_eq!(output.stdout, output2.stdout, "deterministic JSON output");

    let _ = std::fs::remove_dir_all(&workdir);
}
