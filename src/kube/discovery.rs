use std::collections::HashMap;
use std::path::PathBuf;

use anyhow::{Result, bail};
use kube::{
    Client,
    config::Config,
    discovery::{Discovery, Scope},
};

#[derive(Clone)]
pub struct KindInfo {
    pub group: String,
    pub version: String,
    pub plural: String,
    pub namespaced: bool,
}

pub type KindMap = HashMap<String, KindInfo>;
pub type GvrMap = HashMap<String, String>;
/// (group, kind) → KindInfo — handles duplicate Kinds across API groups
pub type GroupKindMap = HashMap<(String, String), KindInfo>;

pub async fn load_config_and_client() -> Result<(Config, Client)> {
    let config = Config::infer().await?;
    let client = Client::try_from(config.clone())?;
    Ok((config, client))
}

pub async fn build_kind_lookup(client: &Client) -> Result<(KindMap, GvrMap, GroupKindMap)> {
    let discovery = Discovery::new(client.clone()).run().await?;
    let mut kind_map = KindMap::new();
    let mut gvr_map = GvrMap::new();
    let mut gk_map = GroupKindMap::new();

    for group in discovery.groups() {
        for version in group.versions() {
            for (ar, caps) in group.versioned_resources(version) {
                let kind = ar.kind.clone();
                let group_name = ar.group.clone();
                let plural = ar.plural.clone();
                let namespaced = caps.scope == Scope::Namespaced;

                let info = KindInfo {
                    group: group_name.clone(),
                    version: ar.version.clone(),
                    plural: plural.clone(),
                    namespaced,
                };

                let gvr_key = if group_name.is_empty() {
                    plural.clone()
                } else {
                    format!("{}.{}", plural, group_name)
                };

                kind_map.entry(kind.clone()).or_insert_with(|| info.clone());
                gk_map
                    .entry((group_name.clone(), kind.clone()))
                    .or_insert_with(|| info);
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

            let info = KindInfo {
                group: group_name.clone(),
                version: ar.version.clone(),
                plural: plural.clone(),
                namespaced,
            };

            kind_map.insert(kind.clone(), info.clone());
            gk_map.insert((group_name.clone(), kind.clone()), info);

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

    Ok((kind_map, gvr_map, gk_map))
}

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

fn gk_map_from_kind_map(kind_map: &KindMap) -> GroupKindMap {
    kind_map
        .iter()
        .map(|(k, v)| ((v.group.clone(), k.clone()), v.clone()))
        .collect()
}

pub async fn build_kind_lookup_cached(
    client: &Client,
    config: &Config,
    no_cache: bool,
) -> Result<(KindMap, GvrMap, GroupKindMap)> {
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
        let gk = gk_map_from_kind_map(&result.0);
        return Ok((result.0, result.1, gk));
    }

    let (kind_map, gvr_map, gk_map) = build_kind_lookup(client).await?;

    let json = serialize_discovery(&kind_map, &gvr_map);
    if let Ok(data) = serde_json::to_string(&json) {
        std::fs::write(&path, data).ok();
    }

    Ok((kind_map, gvr_map, gk_map))
}

pub fn resolve_kind(input: &str, kind_map: &KindMap, gvr_map: &GvrMap) -> Result<String> {
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
