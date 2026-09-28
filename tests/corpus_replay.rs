//! Corpus replay test for Phase C audit.
//!
//! Converts inventory JSONL to v4 snapshot JSON (preserving all raw observations),
//! runs `oc-deps snapshot audit` via CLI, and verifies exact classification counts.
//!
//! Runs only when CORPUS_REPLAY=1 is set (requires corpus archive).

use std::collections::{HashMap, HashSet};
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
    let (mut after_snap, post_raw) =
        inventory_to_snapshot(&workdir.join("inventory/post-inventory.jsonl"));

    assert_eq!(pre_raw, 17786, "pre raw observations");
    assert_eq!(post_raw, 14761, "post raw observations");

    // Inject all spec-refs from the Phase 0 post-specref-map.json into after observations.
    // The inventory JSONL doesn't contain raw spec — spec-refs were extracted at runtime.
    // We load the full map (2587 edges) and inject per-UID.
    let specref_map_path = workdir.join("post-specref-map.json");
    let specref_map: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&specref_map_path).unwrap()).unwrap();

    let mut total_injected = 0usize;
    let mut typed_injected = 0usize;
    let mut heuristic_injected = 0usize;
    let mut uid_refs: HashMap<String, Vec<serde_json::Value>> = HashMap::new();

    fn walk_tree(
        node: &serde_json::Value,
        uid_refs: &mut HashMap<String, Vec<serde_json::Value>>,
        total: &mut usize,
        typed: &mut usize,
        heuristic: &mut usize,
    ) {
        let uid = node["uid"].as_str().unwrap_or("");
        for spec_ref in node["specRefs"].as_array().unwrap_or(&vec![]) {
            let source = spec_ref["source"].as_str().unwrap_or("typed");
            let target_kind = spec_ref["kind"].as_str().unwrap_or("");
            let target_name = spec_ref["name"].as_str().unwrap_or("");
            let field_path = spec_ref["fieldPath"].as_str().unwrap_or("");
            let ser_source = if source == "typed" {
                "Typed"
            } else {
                "Heuristic"
            };
            uid_refs
                .entry(uid.to_string())
                .or_default()
                .push(serde_json::json!({
                    "target_kind": target_kind,
                    "target_name": target_name,
                    "field_path": field_path,
                    "target_group": "",
                    "source": ser_source,
                }));
            *total += 1;
            if source == "typed" {
                *typed += 1;
            } else {
                *heuristic += 1;
            }
        }
        for child in node["children"].as_array().unwrap_or(&vec![]) {
            walk_tree(child, uid_refs, total, typed, heuristic);
        }
    }

    for ns in specref_map["namespaces"].as_array().unwrap_or(&vec![]) {
        for tree in ns["trees"].as_array().unwrap_or(&vec![]) {
            walk_tree(
                tree,
                &mut uid_refs,
                &mut total_injected,
                &mut typed_injected,
                &mut heuristic_injected,
            );
        }
    }
    eprintln!(
        "Injected spec-refs: {} total ({} typed, {} heuristic)",
        total_injected, typed_injected, heuristic_injected
    );
    assert_eq!(total_injected, 2587, "total spec-ref edges");
    assert_eq!(typed_injected, 2155, "typed spec-ref edges");
    assert_eq!(heuristic_injected, 432, "heuristic spec-ref edges");

    for obs in &mut after_snap.observations {
        if let Some(refs) = obs.uid.as_ref().and_then(|u| uid_refs.get(u)) {
            obs.spec_refs.extend(refs.iter().cloned());
        }
    }
    for (uid, refs) in &uid_refs {
        if let Some(entry) = after_snap.resources.get_mut(uid) {
            entry.spec_refs.extend(refs.iter().cloned());
        }
    }

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

    let logical_pre = report["layers"]["logical"]["pre"].as_u64().unwrap_or(0);
    let logical_post = report["layers"]["logical"]["post"].as_u64().unwrap_or(0);
    let uid_null_pre = report["layers"]["uid_null"]["pre"].as_u64().unwrap_or(0);
    let uid_null_post = report["layers"]["uid_null"]["post"].as_u64().unwrap_or(0);
    let pre_fp_collisions = report["layers"]["uid_null"]["pre_fingerprint_collision_groups"]
        .as_u64()
        .unwrap_or(99);
    let post_fp_collisions = report["layers"]["uid_null"]["post_fingerprint_collision_groups"]
        .as_u64()
        .unwrap_or(99);

    eprintln!("=== Corpus Replay Results ===");
    eprintln!("Raw: {} → {}", raw_pre, raw_post);
    eprintln!("Logical: {} → {}", logical_pre, logical_post);
    eprintln!("Physical: {} → {}", phys_pre, phys_post);
    eprintln!(
        "UID-null: {} → {} (fp collisions: {}/{})",
        uid_null_pre, uid_null_post, pre_fp_collisions, post_fp_collisions
    );
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
    assert_eq!(logical_pre, 17668, "API-logical pre identities");
    assert_eq!(logical_post, 14719, "API-logical post identities");
    assert_eq!(phys_pre, 11716, "physical pre UIDs");
    assert_eq!(phys_post, 9165, "physical post UIDs");
    assert_eq!(uid_null_pre, 820, "UID-null pre observations");
    assert_eq!(uid_null_post, 731, "UID-null post observations");
    assert_eq!(pre_fp_collisions, 0, "pre fingerprint collision groups");
    assert_eq!(post_fp_collisions, 0, "post fingerprint collision groups");
    assert_eq!(direct_delete, 91, "direct DELETE");
    assert_eq!(expect, 72, "EXPECT");
    assert_eq!(closure_seeds, 91, "DELETE seeds");
    assert_eq!(closure_total, 1460, "DELETE-seed closure");
    assert_eq!(derived, 2, "derived");
    assert_eq!(total_removed, 2784, "total physical removed");
    assert_eq!(newly_term, 0, "newly terminating");
    assert_eq!(provider_count, 25, "provider operands");
    assert_eq!(descendant, 1282, "OwnerRefGcDescendant");

    // Dangling spec-ref fixture: 12 edges to 2 targets
    let dangling_count = report["dangling_spec_refs"]
        .as_array()
        .map(|a| a.len())
        .unwrap_or(0);
    let dangling_targets: HashSet<String> = report["dangling_spec_refs"]
        .as_array()
        .unwrap_or(&vec![])
        .iter()
        .map(|d| {
            format!(
                "{}/{}",
                d["target_kind"].as_str().unwrap_or(""),
                d["target_name"].as_str().unwrap_or("")
            )
        })
        .collect();
    // The Phase 0 fixture identifies 12 edges to 2 removed targets.
    // Full corpus dangling is higher (146 targets not in JSONL scope)
    // because the inventory covers teardown-scoped namespaces only.
    // Validate the 2 known removed targets are in the dangling set.
    let known_removed = vec![
        "ConfigMap/model-catalog-kube-rbac-proxy-config",
        "Secret/model-catalog-postgres",
    ];
    eprintln!(
        "Dangling spec refs: {} edges, {} targets",
        dangling_count,
        dangling_targets.len()
    );
    for target in &known_removed {
        assert!(
            dangling_targets.contains(*target),
            "known removed target {} must be in dangling set",
            target
        );
    }
    assert!(
        dangling_count >= 12,
        "at least 12 dangling edges (Phase 0 fixture)"
    );

    // Verify determinism: run again
    let output2 = Command::new(binary())
        .args(&args)
        .output()
        .expect("second run failed");
    assert_eq!(output.stdout, output2.stdout, "deterministic JSON output");

    let _ = std::fs::remove_dir_all(&workdir);
}
