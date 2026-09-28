//! Corpus replay test for Phase C audit.
//!
//! Converts inventory JSONL to snapshot JSON, runs `oc-deps snapshot audit` via CLI,
//! and verifies exact classification counts against the Python analyzer.
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
    #[allow(dead_code)]
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

#[derive(serde::Serialize)]
struct SnapshotEntry {
    id: ResourceId,
    owner_refs: Vec<serde_json::Value>,
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
struct ResourceId {
    group: String,
    version: String,
    kind: String,
    namespace: Option<String>,
    name: String,
    uid: Option<String>,
}

#[derive(serde::Serialize)]
struct Snapshot {
    schema_version: u32,
    resources: HashMap<String, SnapshotEntry>,
    scan_warnings: Vec<serde_json::Value>,
    cluster_url: String,
    taken_at: String,
    namespaces: Vec<String>,
}

fn inventory_to_snapshot(path: &Path) -> Snapshot {
    let file = std::fs::File::open(path).unwrap();
    let reader = std::io::BufReader::new(file);
    let mut resources: HashMap<String, SnapshotEntry> = HashMap::new();

    for line in reader.lines() {
        let line = line.unwrap();
        let row: InventoryRow = serde_json::from_str(&line).unwrap();
        let uid = match &row.uid {
            Some(u) if !u.is_empty() => u.clone(),
            _ => continue,
        };
        if resources.contains_key(&uid) {
            continue;
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
        let raw_orefs: Vec<ORef> = row
            .owner_references
            .unwrap_or_default()
            .into_iter()
            .map(|v| serde_json::from_value(v).unwrap())
            .collect();
        let owner_refs: Vec<serde_json::Value> = raw_orefs
            .into_iter()
            .map(|o| {
                serde_json::json!({
                    "api_version": o.api_version,
                    "kind": o.kind,
                    "name": o.name,
                    "uid": o.uid,
                    "controller": o.controller,
                    "block_owner_deletion": o.block_owner_deletion,
                })
            })
            .collect();

        let entry = SnapshotEntry {
            id: ResourceId {
                group: row.group,
                version: row.version,
                kind: row.kind,
                namespace: row.namespace,
                name: row.name,
                uid: Some(uid.clone()),
            },
            owner_refs,
            spec_refs: vec![],
            labels: row.labels.unwrap_or_default(),
            annotations: row.annotations.unwrap_or_default(),
            raw_spec: None,
            deletion_timestamp: row.deletion_timestamp,
            finalizers: row.finalizers,
        };
        resources.insert(uid, entry);
    }

    Snapshot {
        schema_version: 4,
        resources,
        scan_warnings: vec![],
        cluster_url: "https://api.test:6443".into(),
        taken_at: "2026-01-01T00:00:00Z".into(),
        namespaces: vec![],
    }
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

    // Convert inventories to snapshots
    let before_snap = inventory_to_snapshot(&workdir.join("inventory/pre-inventory.jsonl"));
    let after_snap = inventory_to_snapshot(&workdir.join("inventory/post-inventory.jsonl"));

    let before_path = workdir.join("before-snapshot.json");
    let after_path = workdir.join("after-snapshot.json");
    std::fs::write(&before_path, serde_json::to_string(&before_snap).unwrap()).unwrap();
    std::fs::write(&after_path, serde_json::to_string(&after_snap).unwrap()).unwrap();

    // Build plan args
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

    // Run audit
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
    let unexplained = summary["UnexplainedChange"].as_u64().unwrap_or(0);
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

    eprintln!("=== Corpus Replay Results ===");
    eprintln!("PlannedDirectDelete: {}", direct_delete);
    eprintln!("ExpectedControllerCleanup: {}", expect);
    eprintln!("OwnerRefGcDescendant: {}", descendant);
    eprintln!("DerivedSideEffect: {}", derived);
    eprintln!("UnexplainedChange: {}", unexplained);
    eprintln!("Total removed: {}", total_removed);
    eprintln!("Closure: seeds={}, total={}", closure_seeds, closure_total);
    eprintln!("Newly terminating: {}", newly_term);
    eprintln!("Provider operands: {}", provider_count);

    // Phase C exact acceptance
    // Python analyzer: 91 DELETE. Production: 90 DELETE + 1 PlanEvidenceConflict.
    // UID 835a3fee-4c6... appears in 4 operators (authorino, dns, limitador, rhcl) with
    // conflicting actions (DELETE vs KEEP/REVIEW). Per P0-5 requirement, conflicting
    // plan actions → UnexplainedChange, not strong classification.
    assert_eq!(direct_delete, 90, "direct DELETE (91 - 1 plan conflict)");
    assert_eq!(expect, 72, "EXPECT");
    assert_eq!(closure_seeds, 90, "DELETE seeds");
    assert_eq!(
        closure_total, 1459,
        "DELETE-seed closure (1460 - 1 conflict)"
    );
    assert_eq!(derived, 2, "derived");
    assert_eq!(total_removed, 2784, "total physical removed");
    assert_eq!(newly_term, 0, "newly terminating");
    assert_eq!(provider_count, 25, "provider operands");

    // Python: 1282 planned_ownerref_descendant + 10 owner_disappeared_unlinked.
    // Production: 1282 OwnerRefGcDescendant (only verified ownerRef chains to DELETE seeds).
    // The 10 owner_disappeared_unlinked fall to UnexplainedChange per P0-3.
    assert_eq!(descendant, 1282, "OwnerRefGcDescendant");

    // Verify determinism: run again
    let output2 = Command::new(binary())
        .args(&args)
        .output()
        .expect("second run failed");
    assert_eq!(output.stdout, output2.stdout, "deterministic JSON output");

    let _ = std::fs::remove_dir_all(&workdir);
}
