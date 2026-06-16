use std::collections::{HashMap, HashSet};
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Instant;

use anyhow::{Result, bail};
use clap::{Parser, ValueEnum};
use comfy_table::Table;
use futures::stream::StreamExt;
use kube::{
    Client,
    api::{Api, ApiResource, DynamicObject, ListParams},
    config::Config,
    core::GroupVersion,
    discovery::{Discovery, Scope},
};

// ──────────────────────────────────────────────────────────────
//  CLI
// ──────────────────────────────────────────────────────────────

#[derive(Parser)]
#[command(
    name = "oc-deps",
    version,
    about = "Kubernetes Resource Dependency Inspector"
)]
struct Args {
    /// Namespace (default: kubeconfig の default namespace)
    #[arg(short = 'n', long)]
    namespace: Option<String>,

    /// Resource kind (e.g. Pod, Deployment). RESOURCE が kind/name なら不要
    #[arg(short = 'k', long)]
    kind: Option<String>,

    /// Output format: tree, table, json
    #[arg(short = 'o', long, value_enum, default_value = "tree")]
    output: OutputFormat,

    /// Max traversal depth
    #[arg(short = 'd', long, default_value_t = 20)]
    depth: usize,

    /// Show only parent chain (namespace scan をスキップして高速)
    #[arg(long)]
    up_only: bool,

    /// Show only child resources
    #[arg(long)]
    down_only: bool,

    /// Show ALL dependency trees in the namespace
    #[arg(long)]
    map: bool,

    /// Show which Operator/CSV installed the CRD for this Kind
    #[arg(long)]
    crd_origin: bool,

    /// Disable spec-level references (Secret, ConfigMap, CRD cross-references)
    #[arg(long)]
    no_refs: bool,

    /// Include Event resources in scan (default: skip)
    #[arg(long)]
    include_events: bool,

    /// Skip discovery cache (force fresh API discovery)
    #[arg(long)]
    no_cache: bool,

    /// Target resource: kind/name or name (with -k). --map 使用時は省略可
    #[arg(value_name = "RESOURCE")]
    resource: Option<String>,
}

#[derive(Clone, Debug, ValueEnum)]
enum OutputFormat {
    Tree,
    Table,
    Json,
}

// ──────────────────────────────────────────────────────────────
//  API Discovery
// ──────────────────────────────────────────────────────────────

#[derive(Clone)]
struct KindInfo {
    group: String,
    version: String,
    plural: String,
    namespaced: bool,
}

type KindMap = HashMap<String, KindInfo>;
type GvrMap = HashMap<String, String>;

async fn load_config_and_client() -> Result<(Config, Client)> {
    let config = Config::infer().await?;
    let client = Client::try_from(config.clone())?;
    Ok((config, client))
}

async fn build_kind_lookup(client: &Client) -> Result<(KindMap, GvrMap)> {
    let discovery = Discovery::new(client.clone()).run().await?;
    let mut kind_map = KindMap::new();
    let mut gvr_map = GvrMap::new();

    for group in discovery.groups() {
        for version in group.versions() {
            for (ar, caps) in group.versioned_resources(version) {
                let kind = ar.kind.clone();
                let group_name = ar.group.clone();
                let plural = ar.plural.clone();
                let namespaced = caps.scope == Scope::Namespaced;

                let gvr_key = if group_name.is_empty() {
                    plural.clone()
                } else {
                    format!("{}.{}", plural, group_name)
                };

                kind_map.entry(kind.clone()).or_insert_with(|| KindInfo {
                    group: group_name.clone(),
                    version: ar.version.clone(),
                    plural: plural.clone(),
                    namespaced,
                });
                gvr_map
                    .entry(gvr_key.to_lowercase())
                    .or_insert_with(|| kind.clone());
                if !group_name.is_empty() {
                    let singular_key = format!("{}.{}", kind.to_lowercase(), group_name);
                    gvr_map.entry(singular_key).or_insert_with(|| kind.clone());
                }
            }
        }

        for (ar, caps) in group.recommended_resources() {
            let kind = ar.kind.clone();
            let group_name = ar.group.clone();
            let plural = ar.plural.clone();
            let namespaced = caps.scope == Scope::Namespaced;

            kind_map.insert(
                kind.clone(),
                KindInfo {
                    group: group_name.clone(),
                    version: ar.version.clone(),
                    plural: plural.clone(),
                    namespaced,
                },
            );

            let gvr_key = if group_name.is_empty() {
                plural.clone()
            } else {
                format!("{}.{}", plural, group_name)
            };
            gvr_map.insert(gvr_key.to_lowercase(), kind.clone());
            if !group_name.is_empty() {
                let singular_key = format!("{}.{}", kind.to_lowercase(), group_name);
                gvr_map.insert(singular_key, kind.clone());
            }
        }
    }

    Ok((kind_map, gvr_map))
}

// ──────────────────────────────────────────────────────────────
//  Discovery Cache — 28秒の discovery を5分間キャッシュ
// ──────────────────────────────────────────────────────────────

const CACHE_TTL_SECS: u64 = 300;

fn discovery_cache_path(config: &Config) -> PathBuf {
    let url = config.cluster_url.to_string();
    let mut hash = 0u64;
    for b in url.bytes() {
        hash = hash.wrapping_mul(31).wrapping_add(b as u64);
    }
    let dir = std::env::temp_dir().join("oc-deps-cache");
    std::fs::create_dir_all(&dir).ok();
    dir.join(format!("{:016x}.json", hash))
}

fn serialize_discovery(kind_map: &KindMap, gvr_map: &GvrMap) -> serde_json::Value {
    let km: serde_json::Map<String, serde_json::Value> = kind_map
        .iter()
        .map(|(k, v)| {
            (
                k.clone(),
                serde_json::json!([v.group, v.version, v.plural, v.namespaced]),
            )
        })
        .collect();

    let gm: serde_json::Map<String, serde_json::Value> = gvr_map
        .iter()
        .map(|(k, v)| (k.clone(), serde_json::json!(v)))
        .collect();

    serde_json::json!({ "kind_map": km, "gvr_map": gm })
}

fn deserialize_discovery(value: &serde_json::Value) -> Option<(KindMap, GvrMap)> {
    let km_val = value.get("kind_map")?.as_object()?;
    let gm_val = value.get("gvr_map")?.as_object()?;

    let mut kind_map = KindMap::new();
    for (k, v) in km_val {
        let arr = v.as_array()?;
        kind_map.insert(
            k.clone(),
            KindInfo {
                group: arr.first()?.as_str()?.to_string(),
                version: arr.get(1)?.as_str()?.to_string(),
                plural: arr.get(2)?.as_str()?.to_string(),
                namespaced: arr.get(3)?.as_bool()?,
            },
        );
    }

    let mut gvr_map = GvrMap::new();
    for (k, v) in gm_val {
        gvr_map.insert(k.clone(), v.as_str()?.to_string());
    }

    Some((kind_map, gvr_map))
}

async fn build_kind_lookup_cached(
    client: &Client,
    config: &Config,
    no_cache: bool,
) -> Result<(KindMap, GvrMap)> {
    let path = discovery_cache_path(config);

    if !no_cache
        && let Ok(metadata) = std::fs::metadata(&path)
        && let Ok(modified) = metadata.modified()
        && modified.elapsed().unwrap_or_default().as_secs() < CACHE_TTL_SECS
        && let Ok(data) = std::fs::read_to_string(&path)
        && let Some(result) = serde_json::from_str::<serde_json::Value>(&data)
            .ok()
            .and_then(|v| deserialize_discovery(&v))
    {
        eprintln!("   (cached, {} types)", result.0.len());
        return Ok(result);
    }

    let (kind_map, gvr_map) = build_kind_lookup(client).await?;

    let json = serialize_discovery(&kind_map, &gvr_map);
    if let Ok(data) = serde_json::to_string(&json) {
        std::fs::write(&path, data).ok();
    }

    Ok((kind_map, gvr_map))
}

fn resolve_kind(input: &str, kind_map: &KindMap, gvr_map: &GvrMap) -> Result<String> {
    let lower = input.to_lowercase();

    if let Some(k) = kind_map.keys().find(|k| k.to_lowercase() == lower) {
        return Ok(k.clone());
    }

    if let Some(k) = gvr_map.get(&lower) {
        return Ok(k.clone());
    }

    if let Some((sing, grp)) = lower.split_once('.')
        && let Some((_, info)) = kind_map.iter().find(|(k, _)| k.to_lowercase() == sing)
    {
        let gvr_key = format!("{}.{}", info.plural, grp);
        if let Some(k) = gvr_map.get(&gvr_key) {
            return Ok(k.clone());
        }
    }

    let mut candidates: Vec<&String> = kind_map
        .keys()
        .filter(|k| {
            let kl = k.to_lowercase();
            kl.contains(&lower) || lower.contains(&kl)
        })
        .collect();
    candidates.sort();

    if candidates.is_empty() {
        bail!("Unsupported kind: {}. Try plural.group/name format.", input);
    }
    bail!(
        "Unsupported kind: {}. Candidates: {}",
        input,
        candidates
            .iter()
            .map(|s| s.as_str())
            .collect::<Vec<_>>()
            .join(", ")
    );
}

// ──────────────────────────────────────────────────────────────
//  Resource Index — namespace-wide scan + reverse ownerRef map
// ──────────────────────────────────────────────────────────────

#[derive(Clone)]
struct ResourceInfo {
    kind: String,
    name: String,
    namespace: Option<String>,
    uid: String,
    owner_refs: Vec<OwnerRef>,
}

#[derive(Clone)]
struct OwnerRef {
    api_version: String,
    kind: String,
    name: String,
    uid: String,
    controller: bool,
}

#[derive(Clone)]
struct SpecRef {
    target_kind: String,
    target_name: String,
    field_path: String,
}

#[derive(Clone)]
struct IncomingRef {
    source_kind: String,
    source_name: String,
    field_path: String,
}

type ScanItem = (ResourceInfo, Vec<SpecRef>, Vec<(String, String)>);
type RefData = (String, String, Vec<SpecRef>, Vec<(String, String)>);

struct NamespaceIndex {
    by_uid: HashMap<String, ResourceInfo>,
    children_of: HashMap<String, Vec<String>>,
    by_kind_name: HashMap<(String, String), String>,
    refs_from: HashMap<String, Vec<SpecRef>>,
    refs_to: HashMap<String, Vec<IncomingRef>>,
}

impl NamespaceIndex {
    fn new() -> Self {
        Self {
            by_uid: HashMap::new(),
            children_of: HashMap::new(),
            by_kind_name: HashMap::new(),
            refs_from: HashMap::new(),
            refs_to: HashMap::new(),
        }
    }

    fn insert(&mut self, info: ResourceInfo) {
        let uid = info.uid.clone();
        let kind_lower = info.kind.to_lowercase();
        let name = info.name.clone();

        for oref in &info.owner_refs {
            self.children_of
                .entry(oref.uid.clone())
                .or_default()
                .push(uid.clone());
        }

        self.by_kind_name.insert((kind_lower, name), uid.clone());
        self.by_uid.insert(uid, info);
    }
}

async fn scan_namespace(
    client: &Client,
    namespace: &str,
    kind_map: &KindMap,
    include_events: bool,
    refs: bool,
) -> Result<NamespaceIndex> {
    let skip_kinds: HashSet<&str> = if include_events {
        HashSet::new()
    } else {
        HashSet::from(["Event"])
    };

    // namespaced タイプのみスキャン — cluster-scoped は親チェーンで必要時に個別fetch
    let scan_targets: Vec<_> = kind_map
        .iter()
        .filter(|(k, info)| info.namespaced && !skip_kinds.contains(k.as_str()))
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

            let result = api.list(&ListParams::default()).await;
            let count = scanned.fetch_add(1, Ordering::Relaxed) + 1;
            eprint!("\r\x1b[2K🔍 Scanning resources... ({}/{})", count, total);

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

                            Some((
                                ResourceInfo {
                                    kind: kind.clone(),
                                    name,
                                    namespace: ns,
                                    uid,
                                    owner_refs,
                                },
                                wk_refs,
                                spec_strs,
                            ))
                        })
                        .collect();
                    Some(items)
                }
                Err(_) => None,
            }
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

    let mut index = NamespaceIndex::new();
    let mut ref_data: Vec<RefData> = Vec::new();

    for items in results.into_iter().flatten() {
        for (info, wk_refs, spec_strs) in items {
            if refs {
                ref_data.push((info.uid.clone(), info.name.clone(), wk_refs, spec_strs));
            }
            index.insert(info);
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

    Ok(index)
}

fn resolve_name_matches(
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

/// ownerRef で参照される cluster-scoped な親を個別に fetch してインデックスに追加
async fn resolve_missing_parents(
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

        // ownerRef の apiVersion から正しい group/version を特定
        // apiVersion 形式: "v1" (core), "apps/v1", "operator.openshift.io/v1"
        let (owner_group, owner_version) = match owner.api_version.rsplit_once('/') {
            Some((g, v)) => (g.to_string(), v.to_string()),
            None => (String::new(), owner.api_version.clone()),
        };

        // kind_map から ownerRef の group に一致する KindInfo を探す
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

                let next_uid = uid.clone();
                index.insert(ResourceInfo {
                    kind: owner.kind,
                    name,
                    namespace: ns,
                    uid,
                    owner_refs,
                });
                current = next_uid;
            }
            Err(_) => break,
        }
    }
}

// ──────────────────────────────────────────────────────────────
//  Spec Reference Extraction
// ──────────────────────────────────────────────────────────────

fn extract_well_known_refs(data: &serde_json::Value) -> Vec<SpecRef> {
    let mut refs = Vec::new();
    if let Some(spec) = data.get("spec") {
        let mut path = vec!["spec".to_string()];
        walk_for_well_known(spec, &mut path, &mut refs);
    }
    dedup_spec_refs(&mut refs);
    refs
}

fn walk_for_well_known(value: &serde_json::Value, path: &mut Vec<String>, refs: &mut Vec<SpecRef>) {
    match value {
        serde_json::Value::Object(map) => {
            for (key, val) in map {
                path.push(key.clone());
                match key.as_str() {
                    "secretKeyRef" => {
                        if let Some(name) = val.get("name").and_then(|n| n.as_str()) {
                            refs.push(SpecRef {
                                target_kind: "Secret".to_string(),
                                target_name: name.to_string(),
                                field_path: format!("{}.name", path.join(".")),
                            });
                        }
                    }
                    "configMapKeyRef" => {
                        if let Some(name) = val.get("name").and_then(|n| n.as_str()) {
                            refs.push(SpecRef {
                                target_kind: "ConfigMap".to_string(),
                                target_name: name.to_string(),
                                field_path: format!("{}.name", path.join(".")),
                            });
                        }
                    }
                    "configMapRef" => {
                        if let Some(name) = val.get("name").and_then(|n| n.as_str()) {
                            refs.push(SpecRef {
                                target_kind: "ConfigMap".to_string(),
                                target_name: name.to_string(),
                                field_path: format!("{}.name", path.join(".")),
                            });
                        }
                    }
                    "secretRef" => {
                        if let Some(name) = val.get("name").and_then(|n| n.as_str()) {
                            refs.push(SpecRef {
                                target_kind: "Secret".to_string(),
                                target_name: name.to_string(),
                                field_path: format!("{}.name", path.join(".")),
                            });
                        }
                    }
                    "serviceAccountName" => {
                        if let Some(name) = val.as_str()
                            && !name.is_empty()
                        {
                            refs.push(SpecRef {
                                target_kind: "ServiceAccount".to_string(),
                                target_name: name.to_string(),
                                field_path: path.join("."),
                            });
                        }
                    }
                    "configMap" if val.is_object() => {
                        if let Some(name) = val.get("name").and_then(|n| n.as_str()) {
                            refs.push(SpecRef {
                                target_kind: "ConfigMap".to_string(),
                                target_name: name.to_string(),
                                field_path: format!("{}.name", path.join(".")),
                            });
                        }
                    }
                    "secret" if val.is_object() => {
                        if let Some(name) = val.get("secretName").and_then(|n| n.as_str()) {
                            refs.push(SpecRef {
                                target_kind: "Secret".to_string(),
                                target_name: name.to_string(),
                                field_path: format!("{}.secretName", path.join(".")),
                            });
                        }
                    }
                    "persistentVolumeClaim" if val.is_object() => {
                        if let Some(name) = val.get("claimName").and_then(|n| n.as_str()) {
                            refs.push(SpecRef {
                                target_kind: "PersistentVolumeClaim".to_string(),
                                target_name: name.to_string(),
                                field_path: format!("{}.claimName", path.join(".")),
                            });
                        }
                    }
                    "imagePullSecrets" => {
                        if let Some(arr) = val.as_array() {
                            for (i, item) in arr.iter().enumerate() {
                                if let Some(name) = item.get("name").and_then(|n| n.as_str()) {
                                    refs.push(SpecRef {
                                        target_kind: "Secret".to_string(),
                                        target_name: name.to_string(),
                                        field_path: format!("{}[{}].name", path.join("."), i),
                                    });
                                }
                            }
                        }
                    }
                    "secretName" => {
                        if let Some(name) = val.as_str()
                            && !name.is_empty()
                        {
                            refs.push(SpecRef {
                                target_kind: "Secret".to_string(),
                                target_name: name.to_string(),
                                field_path: path.join("."),
                            });
                        }
                    }
                    _ => {}
                }

                // pvc:// URI detection on any string value
                if let Some(s) = val.as_str()
                    && let Some(rest) = s.strip_prefix("pvc://")
                {
                    let pvc_name = rest.split('/').next().unwrap_or(rest);
                    if !pvc_name.is_empty() {
                        refs.push(SpecRef {
                            target_kind: "PersistentVolumeClaim".to_string(),
                            target_name: pvc_name.to_string(),
                            field_path: path.join("."),
                        });
                    }
                }

                walk_for_well_known(val, path, refs);
                path.pop();
            }
        }
        serde_json::Value::Array(arr) => {
            for (i, item) in arr.iter().enumerate() {
                path.push(format!("[{}]", i));
                walk_for_well_known(item, path, refs);
                path.pop();
            }
        }
        _ => {}
    }
}

fn dedup_spec_refs(refs: &mut Vec<SpecRef>) {
    let mut seen = HashSet::new();
    refs.retain(|r| seen.insert((r.target_kind.clone(), r.target_name.clone())));
}

// ──────────────────────────────────────────────────────────────
//  Spec Reference — name-match heuristic
// ──────────────────────────────────────────────────────────────

fn skip_subtree_for_heuristic(key: &str) -> bool {
    matches!(
        key,
        "labels"
            | "matchLabels"
            | "selector"
            | "annotations"
            | "matchExpressions"
            | "command"
            | "args"
            | "managedFields"
    )
}

fn skip_leaf_for_heuristic(key: &str) -> bool {
    matches!(
        key,
        "name"
            | "subdomain"
            | "containerPort"
            | "protocol"
            | "effect"
            | "operator"
            | "key"
            | "type"
            | "containerName"
            | "fieldPath"
            | "apiVersion"
            | "kind"
            | "generateName"
    )
}

fn collect_string_values(
    value: &serde_json::Value,
    path: &mut Vec<String>,
    out: &mut Vec<(String, String)>,
) {
    match value {
        serde_json::Value::String(s) => {
            if let Some(last_key) = path.last()
                && !last_key.starts_with('[')
                && skip_leaf_for_heuristic(last_key)
            {
                return;
            }
            out.push((path.join("."), s.clone()));
        }
        serde_json::Value::Object(map) => {
            for (key, val) in map {
                if skip_subtree_for_heuristic(key) {
                    continue;
                }
                path.push(key.clone());
                collect_string_values(val, path, out);
                path.pop();
            }
        }
        serde_json::Value::Array(arr) => {
            for (i, item) in arr.iter().enumerate() {
                path.push(format!("[{}]", i));
                collect_string_values(item, path, out);
                path.pop();
            }
        }
        _ => {}
    }
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
    // skip values that look like container images (contain : and /)
    if s.contains('/') && s.contains(':') {
        return false;
    }
    true
}

// ──────────────────────────────────────────────────────────────
//  Tree Building
// ──────────────────────────────────────────────────────────────

struct TreeNode {
    info: ResourceInfo,
    children: Vec<TreeNode>,
    is_target: bool,
    spec_refs: Vec<SpecRef>,
    incoming_refs: Vec<IncomingRef>,
}

fn primary_owner(refs: &[OwnerRef]) -> Option<&OwnerRef> {
    refs.iter().find(|r| r.controller).or(refs.first())
}

fn build_parent_chain(target_uid: &str, index: &NamespaceIndex) -> Vec<String> {
    let mut chain = vec![target_uid.to_string()];
    let mut current = target_uid.to_string();
    let mut visited = HashSet::new();

    loop {
        if !visited.insert(current.clone()) {
            break;
        }

        match index.by_uid.get(&current) {
            Some(info) => {
                if let Some(owner) = primary_owner(&info.owner_refs) {
                    chain.push(owner.uid.clone());
                    if !index.by_uid.contains_key(&owner.uid) {
                        break;
                    }
                    current = owner.uid.clone();
                } else {
                    break;
                }
            }
            None => break,
        }
    }

    chain.reverse();
    chain
}

fn build_child_tree(
    uid: &str,
    index: &NamespaceIndex,
    depth: usize,
    max_depth: usize,
    visited: &mut HashSet<String>,
    target_uid: &str,
) -> Option<TreeNode> {
    if depth > max_depth || !visited.insert(uid.to_string()) {
        return None;
    }

    let info = index.by_uid.get(uid)?.clone();
    let mut children: Vec<TreeNode> = index
        .children_of
        .get(uid)
        .map(|child_uids| {
            child_uids
                .iter()
                .filter_map(|child_uid| {
                    build_child_tree(child_uid, index, depth + 1, max_depth, visited, target_uid)
                })
                .collect()
        })
        .unwrap_or_default();

    children.sort_by(|a, b| {
        a.info
            .kind
            .cmp(&b.info.kind)
            .then(a.info.name.cmp(&b.info.name))
    });

    let spec_refs = index.refs_from.get(uid).cloned().unwrap_or_default();
    let incoming_refs = index.refs_to.get(uid).cloned().unwrap_or_default();

    Some(TreeNode {
        is_target: uid == target_uid,
        info,
        children,
        spec_refs,
        incoming_refs,
    })
}

fn find_owner_ref_info(parent_uid: &str, index: &NamespaceIndex) -> Option<ResourceInfo> {
    for info in index.by_uid.values() {
        for oref in &info.owner_refs {
            if oref.uid == parent_uid {
                return Some(ResourceInfo {
                    kind: oref.kind.clone(),
                    name: oref.name.clone(),
                    namespace: None,
                    uid: parent_uid.to_string(),
                    owner_refs: vec![],
                });
            }
        }
    }
    None
}

fn build_full_tree(target_uid: &str, index: &NamespaceIndex, max_depth: usize) -> Option<TreeNode> {
    let parent_chain = build_parent_chain(target_uid, index);

    let mut visited = HashSet::new();
    for uid in &parent_chain {
        if uid != target_uid {
            visited.insert(uid.clone());
        }
    }

    let target_subtree =
        build_child_tree(target_uid, index, 0, max_depth, &mut visited, target_uid)?;

    if parent_chain.len() <= 1 {
        return Some(target_subtree);
    }

    let mut current = target_subtree;
    for uid in parent_chain.iter().rev().skip(1) {
        let info = index
            .by_uid
            .get(uid)
            .cloned()
            .or_else(|| find_owner_ref_info(uid, index))?;
        let spec_refs = index.refs_from.get(uid).cloned().unwrap_or_default();
        let incoming_refs = index.refs_to.get(uid).cloned().unwrap_or_default();
        current = TreeNode {
            info,
            children: vec![current],
            is_target: false,
            spec_refs,
            incoming_refs,
        };
    }

    Some(current)
}

/// --map: namespace 内の全リソースをルートからツリー表示
fn build_namespace_map(index: &NamespaceIndex, max_depth: usize) -> Vec<TreeNode> {
    let root_uids: Vec<String> = index
        .by_uid
        .iter()
        .filter(|(_, info)| {
            info.owner_refs.is_empty()
                || info
                    .owner_refs
                    .iter()
                    .all(|r| !index.by_uid.contains_key(&r.uid))
        })
        .map(|(uid, _)| uid.clone())
        .collect();

    let mut trees = Vec::new();
    let mut visited = HashSet::new();

    for root_uid in &root_uids {
        if visited.contains(root_uid) {
            continue;
        }
        if let Some(tree) = build_child_tree(root_uid, index, 0, max_depth, &mut visited, "") {
            trees.push(tree);
        }
    }

    trees.sort_by(|a, b| {
        a.info
            .kind
            .cmp(&b.info.kind)
            .then(a.info.name.cmp(&b.info.name))
    });
    trees
}

// ──────────────────────────────────────────────────────────────
//  Up-Only Mode — targeted API calls, no namespace scan
// ──────────────────────────────────────────────────────────────

async fn find_parents_only(
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

                chain.push(ResourceInfo {
                    kind: current_kind,
                    name: current_name,
                    namespace: obj.metadata.namespace,
                    uid,
                    owner_refs,
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
                });
                break;
            }
        }
    }

    chain.reverse();
    Ok(chain)
}

// ──────────────────────────────────────────────────────────────
//  Output — Tree
// ──────────────────────────────────────────────────────────────

fn print_tree(node: &TreeNode, prefix: &str, is_last: bool, is_root: bool) {
    let has_refs = !node.spec_refs.is_empty();
    let has_incoming = !node.incoming_refs.is_empty();
    let has_trailing = has_refs || has_incoming;
    let connector = if is_root {
        ""
    } else if is_last {
        "└─ "
    } else {
        "├─ "
    };

    let target_marker = if node.is_target {
        "  \x1b[1;33m◀ target\x1b[0m"
    } else {
        ""
    };
    let resource_ref = format!("{}/{}", node.info.kind, node.info.name);

    if node.is_target {
        println!(
            "{}{}\x1b[1;32m{}\x1b[0m{}",
            prefix, connector, resource_ref, target_marker
        );
    } else {
        println!("{}{}{}{}", prefix, connector, resource_ref, target_marker);
    }

    let child_prefix = if is_root {
        prefix.to_string()
    } else if is_last {
        format!("{}   ", prefix)
    } else {
        format!("{}│  ", prefix)
    };

    for (i, child) in node.children.iter().enumerate() {
        let child_is_last = i == node.children.len() - 1 && !has_trailing;
        print_tree(child, &child_prefix, child_is_last, false);
    }

    for (i, sref) in node.spec_refs.iter().enumerate() {
        let is_last_item = i == node.spec_refs.len() - 1 && !has_incoming;
        let ref_connector = if is_last_item { "└╌ " } else { "├╌ " };
        println!(
            "{}{}\x1b[36m{}/{}\x1b[0m  \x1b[2m(via {})\x1b[0m",
            child_prefix, ref_connector, sref.target_kind, sref.target_name, sref.field_path
        );
    }

    for (i, iref) in node.incoming_refs.iter().enumerate() {
        let is_last_item = i == node.incoming_refs.len() - 1;
        let ref_connector = if is_last_item { "└╌ " } else { "├╌ " };
        println!(
            "{}{}\x1b[35m◁ {}/{}\x1b[0m  \x1b[2m(via {})\x1b[0m",
            child_prefix, ref_connector, iref.source_kind, iref.source_name, iref.field_path
        );
    }
}

fn count_nodes(node: &TreeNode) -> usize {
    1 + node.children.iter().map(count_nodes).sum::<usize>()
}

// ──────────────────────────────────────────────────────────────
//  Output — Table
// ──────────────────────────────────────────────────────────────

fn flatten_for_table(
    node: &TreeNode,
    rows: &mut Vec<(String, String, String)>,
    found_target: &mut bool,
) {
    let relation = if node.is_target {
        *found_target = true;
        "Self".to_string()
    } else if *found_target {
        "Child".to_string()
    } else {
        "Parent".to_string()
    };

    rows.push((relation, node.info.kind.clone(), node.info.name.clone()));

    for child in &node.children {
        flatten_for_table(child, rows, found_target);
    }

    for sref in &node.spec_refs {
        rows.push((
            "Ref".to_string(),
            sref.target_kind.clone(),
            sref.target_name.clone(),
        ));
    }

    for iref in &node.incoming_refs {
        rows.push((
            "RefBy".to_string(),
            iref.source_kind.clone(),
            iref.source_name.clone(),
        ));
    }
}

fn print_table(tree: &TreeNode) {
    let mut rows = Vec::new();
    let mut found_target = false;
    flatten_for_table(tree, &mut rows, &mut found_target);

    let mut table = Table::new();
    table.set_header(vec!["Relation", "Kind", "Name"]);
    for (rel, kind, name) in &rows {
        table.add_row(vec![rel.as_str(), kind.as_str(), name.as_str()]);
    }
    println!("{table}");
}

// ──────────────────────────────────────────────────────────────
//  Output — JSON
// ──────────────────────────────────────────────────────────────

fn tree_to_json(node: &TreeNode) -> serde_json::Value {
    let mut obj = serde_json::json!({
        "kind": node.info.kind,
        "name": node.info.name,
        "namespace": node.info.namespace,
        "uid": node.info.uid,
        "isTarget": node.is_target,
        "children": node.children.iter().map(tree_to_json).collect::<Vec<_>>(),
    });
    if !node.spec_refs.is_empty() {
        obj["specRefs"] = serde_json::json!(
            node.spec_refs
                .iter()
                .map(|r| serde_json::json!({
                    "kind": r.target_kind,
                    "name": r.target_name,
                    "fieldPath": r.field_path,
                }))
                .collect::<Vec<_>>()
        );
    }
    if !node.incoming_refs.is_empty() {
        obj["referencedBy"] = serde_json::json!(
            node.incoming_refs
                .iter()
                .map(|r| serde_json::json!({
                    "kind": r.source_kind,
                    "name": r.source_name,
                    "fieldPath": r.field_path,
                }))
                .collect::<Vec<_>>()
        );
    }
    obj
}

fn print_json(tree: &TreeNode, namespace: &str) {
    let target = find_target_ref(tree);
    let output = serde_json::json!({
        "namespace": namespace,
        "target": target,
        "tree": tree_to_json(tree),
    });
    println!(
        "{}",
        serde_json::to_string_pretty(&output).unwrap_or_default()
    );
}

fn find_target_ref(node: &TreeNode) -> String {
    if node.is_target {
        return format!("{}/{}", node.info.kind, node.info.name);
    }
    for child in &node.children {
        let r = find_target_ref(child);
        if !r.is_empty() {
            return r;
        }
    }
    String::new()
}

// ──────────────────────────────────────────────────────────────
//  CRD Origin — Kind → CRD → CSV → Subscription 逆引き
// ──────────────────────────────────────────────────────────────

struct CrdOriginChain {
    crd_name: String,
    crd_labels: Vec<(String, String)>,
    csv_name: Option<String>,
    csv_namespace: Option<String>,
    csv_match_method: Option<String>,
    subscription_name: Option<String>,
    subscription_namespace: Option<String>,
}

async fn find_crd_origin(
    client: &Client,
    kind: &str,
    kind_map: &KindMap,
) -> Option<CrdOriginChain> {
    let kind_info = kind_map.get(kind)?;
    let crd_name = if kind_info.group.is_empty() {
        return None;
    } else {
        format!("{}.{}", kind_info.plural, kind_info.group)
    };

    // CRD 自体のラベルを取得
    let mut crd_labels = Vec::new();
    if let Some(crd_kind_info) = kind_map.get("CustomResourceDefinition") {
        let crd_gvk = GroupVersion::gv(&crd_kind_info.group, &crd_kind_info.version)
            .with_kind("CustomResourceDefinition");
        let crd_ar = ApiResource::from_gvk_with_plural(&crd_gvk, &crd_kind_info.plural);
        let crd_api: Api<DynamicObject> = Api::all_with(client.clone(), &crd_ar);
        if let Ok(crd_obj) = crd_api.get(&crd_name).await
            && let Some(labels) = &crd_obj.metadata.labels
        {
            for (k, v) in labels {
                if k.contains("part-of") || k.contains("managed-by") || k.contains("opendatahub") {
                    crd_labels.push((k.clone(), v.clone()));
                }
            }
        }
    }

    // CSV を全 namespace から取得
    let csv_info = kind_map.get("ClusterServiceVersion")?;
    let csv_gvk =
        GroupVersion::gv(&csv_info.group, &csv_info.version).with_kind("ClusterServiceVersion");
    let csv_ar = ApiResource::from_gvk_with_plural(&csv_gvk, &csv_info.plural);
    let csv_api: Api<DynamicObject> = Api::all_with(client.clone(), &csv_ar);
    let csvs = csv_api.list(&ListParams::default()).await.ok()?;

    let mut found_csv_name = None;
    let mut found_csv_ns = None;
    let mut match_method = None;

    // 1) spec.customresourcedefinitions.owned で完全一致
    'owned: for csv in &csvs.items {
        let owned = csv
            .data
            .get("spec")
            .and_then(|s| s.get("customresourcedefinitions"))
            .and_then(|c| c.get("owned"))
            .and_then(|o| o.as_array());
        if let Some(owned_crds) = owned {
            for crd in owned_crds {
                if crd.get("name").and_then(|n| n.as_str()) == Some(crd_name.as_str()) {
                    found_csv_name = csv.metadata.name.clone();
                    found_csv_ns = csv.metadata.namespace.clone();
                    match_method = Some("owned CRD".to_string());
                    break 'owned;
                }
            }
        }
    }

    // 2) clusterPermissions.rules で apiGroup + resource 一致
    if found_csv_name.is_none() {
        let target_group = &kind_info.group;
        let target_resource = &kind_info.plural;

        'perms: for csv in &csvs.items {
            let perms = csv
                .data
                .get("spec")
                .and_then(|s| s.get("install"))
                .and_then(|i| i.get("spec"))
                .and_then(|s| s.get("clusterPermissions"))
                .and_then(|p| p.as_array());
            if let Some(perm_list) = perms {
                for perm in perm_list {
                    let rules = perm.get("rules").and_then(|r| r.as_array());
                    if let Some(rules) = rules {
                        for rule in rules {
                            let groups = rule
                                .get("apiGroups")
                                .and_then(|g| g.as_array())
                                .map(|a| a.iter().filter_map(|v| v.as_str()).collect::<Vec<_>>())
                                .unwrap_or_default();
                            let resources = rule
                                .get("resources")
                                .and_then(|r| r.as_array())
                                .map(|a| a.iter().filter_map(|v| v.as_str()).collect::<Vec<_>>())
                                .unwrap_or_default();

                            if groups.contains(&target_group.as_str())
                                && resources.contains(&target_resource.as_str())
                            {
                                found_csv_name = csv.metadata.name.clone();
                                found_csv_ns = csv.metadata.namespace.clone();
                                match_method = Some("clusterPermissions".to_string());
                                break 'perms;
                            }
                        }
                    }
                }
            }
        }
    }

    let mut chain = CrdOriginChain {
        crd_name,
        crd_labels,
        csv_name: found_csv_name.clone(),
        csv_namespace: found_csv_ns.clone(),
        csv_match_method: match_method,
        subscription_name: None,
        subscription_namespace: None,
    };

    // Subscription 検索 — OLM の operators.coreos.com/v1alpha1 を直接指定
    // (kind_map は同名 Kind を1つしか保持できないため、直接 GVK を構築)
    if let Some(csv_name) = &found_csv_name {
        let sub_gvk =
            GroupVersion::gv("operators.coreos.com", "v1alpha1").with_kind("Subscription");
        let sub_ar = ApiResource::from_gvk_with_plural(&sub_gvk, "subscriptions");
        let sub_api: Api<DynamicObject> = Api::all_with(client.clone(), &sub_ar);
        {
            if let Ok(subs) = sub_api.list(&ListParams::default()).await {
                for sub in &subs.items {
                    let current_csv = sub
                        .data
                        .get("status")
                        .and_then(|s| s.get("currentCSV"))
                        .and_then(|c| c.as_str());
                    if current_csv == Some(csv_name.as_str()) {
                        chain.subscription_name = sub.metadata.name.clone();
                        chain.subscription_namespace = sub.metadata.namespace.clone();
                        break;
                    }
                }
            }
        }
    }

    Some(chain)
}

fn print_crd_origin(chain: &CrdOriginChain, kind: &str, output: &OutputFormat) {
    match output {
        OutputFormat::Tree => {
            let match_note = chain
                .csv_match_method
                .as_ref()
                .map(|m| format!(" (via {})", m))
                .unwrap_or_default();

            if let Some(sub) = &chain.subscription_name {
                let sub_ns = chain.subscription_namespace.as_deref().unwrap_or("unknown");
                println!("Subscription/{} (ns: {})", sub, sub_ns);
                if let Some(csv) = &chain.csv_name {
                    let csv_ns = chain.csv_namespace.as_deref().unwrap_or("unknown");
                    println!(
                        "└─ ClusterServiceVersion/{} (ns: {}){}",
                        csv, csv_ns, match_note
                    );
                    println!("   └─ CRD/{}", chain.crd_name);
                    println!("      └─ \x1b[1;32m{}/...\x1b[0m", kind);
                }
            } else if let Some(csv) = &chain.csv_name {
                let csv_ns = chain.csv_namespace.as_deref().unwrap_or("unknown");
                println!(
                    "ClusterServiceVersion/{} (ns: {}){}",
                    csv, csv_ns, match_note
                );
                println!("└─ CRD/{}", chain.crd_name);
                println!("   └─ \x1b[1;32m{}/...\x1b[0m", kind);
            } else {
                println!("CRD/{}", chain.crd_name);
                println!("└─ \x1b[1;32m{}/...\x1b[0m (no managing CSV found)", kind);
            }

            if !chain.crd_labels.is_empty() {
                println!();
                println!("📎 CRD labels:");
                for (k, v) in &chain.crd_labels {
                    println!("   {}: {}", k, v);
                }
            }
        }
        OutputFormat::Table => {
            let mut table = Table::new();
            table.set_header(vec!["Level", "Kind", "Name", "Namespace"]);
            if let Some(sub) = &chain.subscription_name {
                table.add_row(vec![
                    "Subscription",
                    "Subscription",
                    sub,
                    chain.subscription_namespace.as_deref().unwrap_or("-"),
                ]);
            }
            if let Some(csv) = &chain.csv_name {
                table.add_row(vec![
                    "CSV",
                    "ClusterServiceVersion",
                    csv,
                    chain.csv_namespace.as_deref().unwrap_or("-"),
                ]);
            }
            table.add_row(vec![
                "CRD",
                "CustomResourceDefinition",
                &chain.crd_name,
                "-",
            ]);
            table.add_row(vec!["Kind", kind, "*", "-"]);
            println!("{table}");
        }
        OutputFormat::Json => {
            let labels: HashMap<&str, &str> = chain
                .crd_labels
                .iter()
                .map(|(k, v)| (k.as_str(), v.as_str()))
                .collect();
            let output = serde_json::json!({
                "kind": kind,
                "crd": chain.crd_name,
                "crdLabels": labels,
                "csv": chain.csv_name,
                "csvNamespace": chain.csv_namespace,
                "csvMatchMethod": chain.csv_match_method,
                "subscription": chain.subscription_name,
                "subscriptionNamespace": chain.subscription_namespace,
            });
            println!(
                "{}",
                serde_json::to_string_pretty(&output).unwrap_or_default()
            );
        }
    }
}

// ──────────────────────────────────────────────────────────────
//  Service — selector-based pod discovery
// ──────────────────────────────────────────────────────────────

async fn get_service_selected_pods(
    client: &Client,
    name: &str,
    namespace: &str,
    kind_map: &KindMap,
) -> Vec<String> {
    let svc_info = match kind_map.get("Service") {
        Some(i) => i,
        None => return vec![],
    };

    let gvk = GroupVersion::gv(&svc_info.group, &svc_info.version).with_kind("Service");
    let ar = ApiResource::from_gvk_with_plural(&gvk, &svc_info.plural);
    let api: Api<DynamicObject> = Api::namespaced_with(client.clone(), namespace, &ar);

    let svc = match api.get(name).await {
        Ok(s) => s,
        Err(_) => return vec![],
    };

    let selector = match svc
        .data
        .get("spec")
        .and_then(|s| s.get("selector"))
        .and_then(|s| s.as_object())
    {
        Some(s) => s,
        None => return vec![],
    };

    let selector_str = selector
        .iter()
        .filter_map(|(k, v)| v.as_str().map(|val| format!("{}={}", k, val)))
        .collect::<Vec<_>>()
        .join(",");

    if selector_str.is_empty() {
        return vec![];
    }

    let pod_info = match kind_map.get("Pod") {
        Some(i) => i,
        None => return vec![],
    };

    let pod_gvk = GroupVersion::gv(&pod_info.group, &pod_info.version).with_kind("Pod");
    let pod_ar = ApiResource::from_gvk_with_plural(&pod_gvk, &pod_info.plural);
    let pod_api: Api<DynamicObject> = Api::namespaced_with(client.clone(), namespace, &pod_ar);

    match pod_api
        .list(&ListParams::default().labels(&selector_str))
        .await
    {
        Ok(pods) => pods
            .items
            .into_iter()
            .filter_map(|p| p.metadata.name)
            .map(|n| format!("Pod/{}", n))
            .collect(),
        Err(_) => vec![],
    }
}

// ──────────────────────────────────────────────────────────────
//  Output helpers for up-only chain
// ──────────────────────────────────────────────────────────────

fn print_chain_tree(chain: &[ResourceInfo]) {
    for (i, info) in chain.iter().enumerate() {
        let indent = if i == 0 {
            String::new()
        } else {
            format!("{}└─ ", "   ".repeat(i - 1))
        };
        let marker = if i == chain.len() - 1 {
            "  \x1b[1;33m◀ target\x1b[0m"
        } else {
            ""
        };
        let resource_ref = format!("{}/{}", info.kind, info.name);
        if i == chain.len() - 1 {
            println!("{}\x1b[1;32m{}\x1b[0m{}", indent, resource_ref, marker);
        } else {
            println!("{}{}{}", indent, resource_ref, marker);
        }
    }
}

fn print_chain_table(chain: &[ResourceInfo]) {
    let mut table = Table::new();
    table.set_header(vec!["Relation", "Kind", "Name"]);
    for (i, info) in chain.iter().enumerate() {
        let rel = if i == chain.len() - 1 {
            "Self"
        } else {
            "Parent"
        };
        table.add_row(vec![rel, &info.kind, &info.name]);
    }
    println!("{table}");
}

fn print_chain_json(chain: &[ResourceInfo], namespace: &str) {
    let items: Vec<_> = chain
        .iter()
        .enumerate()
        .map(|(i, info)| {
            serde_json::json!({
                "relation": if i == chain.len() - 1 { "self" } else { "parent" },
                "kind": info.kind,
                "name": info.name,
                "namespace": info.namespace,
                "uid": info.uid,
            })
        })
        .collect();
    let output = serde_json::json!({
        "namespace": namespace,
        "target": chain.last().map(|i| format!("{}/{}", i.kind, i.name)).unwrap_or_default(),
        "chain": items,
    });
    println!(
        "{}",
        serde_json::to_string_pretty(&output).unwrap_or_default()
    );
}

// ──────────────────────────────────────────────────────────────
//  Main
// ──────────────────────────────────────────────────────────────

fn display_tree(tree: &TreeNode, output: &OutputFormat, namespace: &str) {
    match output {
        OutputFormat::Tree => {
            eprintln!("\n📦 Namespace: {}\n", namespace);
            print_tree(tree, "", true, true);
        }
        OutputFormat::Table => print_table(tree),
        OutputFormat::Json => print_json(tree, namespace),
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();

    let (config, client) = load_config_and_client().await?;
    let namespace = args
        .namespace
        .clone()
        .unwrap_or(config.default_namespace.clone());

    // --map モード: RESOURCE 不要
    if args.map {
        let t0 = Instant::now();
        eprintln!("🔍 Discovering API resources...");
        let (kind_map, _) = build_kind_lookup_cached(&client, &config, args.no_cache).await?;
        eprintln!("   Discovery: {:.1}s", t0.elapsed().as_secs_f64());
        let mut index = scan_namespace(
            &client,
            &namespace,
            &kind_map,
            args.include_events,
            !args.no_refs,
        )
        .await?;

        // cluster-scoped 親を全リソースに対して解決 → ツリーが収束する
        let uids_with_missing_parents: Vec<String> = index
            .by_uid
            .iter()
            .filter(|(_, info)| {
                info.owner_refs
                    .iter()
                    .any(|r| !index.by_uid.contains_key(&r.uid))
            })
            .map(|(uid, _)| uid.clone())
            .collect();
        if !uids_with_missing_parents.is_empty() {
            eprint!("🔗 Resolving cluster-scoped parents...");
            for uid in &uids_with_missing_parents {
                resolve_missing_parents(&mut index, uid, &client, &namespace, &kind_map).await;
            }
            eprintln!(" done");
        }

        let trees = build_namespace_map(&index, args.depth);

        match args.output {
            OutputFormat::Tree => {
                eprintln!(
                    "\n📦 Namespace: {} ({} trees, {} resources)\n",
                    namespace,
                    trees.len(),
                    index.by_uid.len()
                );
                for (i, tree) in trees.iter().enumerate() {
                    print_tree(tree, "", true, true);
                    if i < trees.len() - 1 {
                        println!();
                    }
                }
            }
            OutputFormat::Table => {
                let mut table = Table::new();
                table.set_header(vec!["Root", "Kind", "Name", "Children"]);
                for tree in &trees {
                    let total = count_nodes(tree);
                    table.add_row(vec![
                        format!("{}/{}", tree.info.kind, tree.info.name),
                        tree.info.kind.clone(),
                        tree.info.name.clone(),
                        total.to_string(),
                    ]);
                }
                println!("{table}");
            }
            OutputFormat::Json => {
                let output = serde_json::json!({
                    "namespace": namespace,
                    "totalResources": index.by_uid.len(),
                    "trees": trees.iter().map(tree_to_json).collect::<Vec<_>>(),
                });
                println!(
                    "{}",
                    serde_json::to_string_pretty(&output).unwrap_or_default()
                );
            }
        }
        return Ok(());
    }

    // RESOURCE 必須
    let resource = args
        .resource
        .as_ref()
        .unwrap_or_else(|| {
            eprintln!("Error: RESOURCE is required (use --map for namespace-wide view)");
            std::process::exit(1);
        })
        .clone();

    let t0 = Instant::now();
    eprintln!("🔍 Discovering API resources...");
    let (kind_map, gvr_map) = build_kind_lookup_cached(&client, &config, args.no_cache).await?;
    eprintln!("   Discovery: {:.1}s", t0.elapsed().as_secs_f64());

    let (kind_input, name) = if let Some((k, n)) = resource.split_once('/') {
        (k.to_string(), n.to_string())
    } else {
        let k = args.kind.clone().unwrap_or_else(|| {
            eprintln!("Error: specify kind/name or use -k <KIND>");
            std::process::exit(1);
        });
        (k, resource)
    };

    let kind = resolve_kind(&kind_input, &kind_map, &gvr_map)?;

    // ── CRD origin mode ──
    if args.crd_origin {
        eprint!("🔍 Tracing CRD origin...");
        match find_crd_origin(&client, &kind, &kind_map).await {
            Some(chain) => {
                eprintln!(" done\n");
                print_crd_origin(&chain, &kind, &args.output);
            }
            None => {
                eprintln!();
                println!("{} is a built-in resource (no CRD).", kind);
            }
        }
        return Ok(());
    }

    // ── Up-only mode ──
    if args.up_only {
        let chain = find_parents_only(&client, &kind, &name, &namespace, &kind_map).await?;
        if chain.is_empty() {
            println!("No resources found.");
            return Ok(());
        }
        match args.output {
            OutputFormat::Tree => {
                eprintln!("\n📦 Namespace: {}\n", namespace);
                print_chain_tree(&chain);
            }
            OutputFormat::Table => print_chain_table(&chain),
            OutputFormat::Json => print_chain_json(&chain, &namespace),
        }
        return Ok(());
    }

    // ── Full scan (namespaced only) ──
    let mut index = scan_namespace(
        &client,
        &namespace,
        &kind_map,
        args.include_events,
        !args.no_refs,
    )
    .await?;

    let target_uid = match index.by_kind_name.get(&(kind.to_lowercase(), name.clone())) {
        Some(uid) => uid.clone(),
        None => {
            bail!("{}/{} not found in namespace '{}'", kind, name, namespace);
        }
    };

    // cluster-scoped な親を個別 fetch して index に追加
    resolve_missing_parents(&mut index, &target_uid, &client, &namespace, &kind_map).await;

    // ── Down-only mode ──
    if args.down_only {
        let mut visited = HashSet::new();
        match build_child_tree(
            &target_uid,
            &index,
            0,
            args.depth,
            &mut visited,
            &target_uid,
        ) {
            Some(tree) => display_tree(&tree, &args.output, &namespace),
            None => println!("No resources found."),
        }
    } else {
        // ── Full tree: parents + children ──
        match build_full_tree(&target_uid, &index, args.depth) {
            Some(tree) => display_tree(&tree, &args.output, &namespace),
            None => println!("No resources found."),
        }
    }

    // ── Service selector pods ──
    if kind == "Service" {
        let pods = get_service_selected_pods(&client, &name, &namespace, &kind_map).await;
        if !pods.is_empty() {
            match args.output {
                OutputFormat::Json => {
                    let output = serde_json::json!({ "selectorPods": pods });
                    println!(
                        "{}",
                        serde_json::to_string_pretty(&output).unwrap_or_default()
                    );
                }
                _ => {
                    println!("\n📎 Service selector matches:");
                    for pod in &pods {
                        println!("   {}", pod);
                    }
                }
            }
        }
    }

    Ok(())
}
