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

fn serialize_discovery(
    kind_map: &KindMap,
    gvr_map: &GvrMap,
    gk_map: &GroupKindMap,
) -> serde_json::Value {
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

    let gk: serde_json::Map<String, serde_json::Value> = gk_map
        .iter()
        .map(|((group, kind), v)| {
            let key = format!("{}/{}", group, kind);
            (
                key,
                serde_json::json!([v.group, v.version, v.plural, v.namespaced]),
            )
        })
        .collect();

    serde_json::json!({ "version": 2, "kind_map": km, "gvr_map": gm, "gk_map": gk })
}

fn deserialize_discovery(value: &serde_json::Value) -> Option<(KindMap, GvrMap, GroupKindMap)> {
    let version = value.get("version").and_then(|v| v.as_u64()).unwrap_or(1);
    if version < 2 {
        return None;
    }
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

    let mut gk_map = GroupKindMap::new();
    {
        let gk_val = value.get("gk_map").and_then(|v| v.as_object())?;
        for (k, v) in gk_val {
            let (group, kind) = k.split_once('/').unwrap_or(("", k));
            let arr = match v.as_array() {
                Some(a) => a,
                None => continue,
            };
            if arr.len() >= 4 {
                gk_map.insert(
                    (group.to_string(), kind.to_string()),
                    KindInfo {
                        group: arr[0].as_str().unwrap_or("").to_string(),
                        version: arr[1].as_str().unwrap_or("").to_string(),
                        plural: arr[2].as_str().unwrap_or("").to_string(),
                        namespaced: arr[3].as_bool().unwrap_or(true),
                    },
                );
            }
        }
    }

    Some((kind_map, gvr_map, gk_map))
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
        return Ok(result);
    }

    let (kind_map, gvr_map, gk_map) = build_kind_lookup(client).await?;

    let json = serialize_discovery(&kind_map, &gvr_map, &gk_map);
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn old_cache_version_rejected() {
        let old_cache = serde_json::json!({
            "kind_map": { "Pod": ["", "v1", "pods", true] },
            "gvr_map": { "pods": "Pod" }
        });
        assert!(deserialize_discovery(&old_cache).is_none());
    }

    #[test]
    fn explicit_v1_cache_rejected() {
        let cache = serde_json::json!({
            "version": 1,
            "kind_map": { "Pod": ["", "v1", "pods", true] },
            "gvr_map": { "pods": "Pod" }
        });
        assert!(deserialize_discovery(&cache).is_none());
    }

    #[test]
    fn v2_cache_with_gk_map_accepted() {
        let cache = serde_json::json!({
            "version": 2,
            "kind_map": { "Pod": ["", "v1", "pods", true] },
            "gvr_map": { "pods": "Pod" },
            "gk_map": { "/Pod": ["", "v1", "pods", true] }
        });
        let result = deserialize_discovery(&cache);
        assert!(result.is_some());
        let (km, gvr, gk) = result.unwrap();
        assert_eq!(km.len(), 1);
        assert_eq!(gvr.len(), 1);
        assert!(gk.contains_key(&("".to_string(), "Pod".to_string())));
    }

    #[test]
    fn v2_cache_without_gk_map_rejected() {
        let cache = serde_json::json!({
            "version": 2,
            "kind_map": { "Pod": ["", "v1", "pods", true] },
            "gvr_map": { "pods": "Pod" }
        });
        assert!(deserialize_discovery(&cache).is_none());
    }

    #[test]
    fn v2_cache_with_multiple_groups() {
        let cache = serde_json::json!({
            "version": 2,
            "kind_map": {
                "Pod": ["", "v1", "pods", true],
                "Subscription": ["operators.coreos.com", "v1alpha1", "subscriptions", true]
            },
            "gvr_map": {
                "pods": "Pod",
                "subscriptions.operators.coreos.com": "Subscription"
            },
            "gk_map": {
                "/Pod": ["", "v1", "pods", true],
                "operators.coreos.com/Subscription": ["operators.coreos.com", "v1alpha1", "subscriptions", true],
                "messaging.example.com/Subscription": ["messaging.example.com", "v1", "messagingsubs", true]
            }
        });
        let result = deserialize_discovery(&cache);
        assert!(result.is_some());
        let (km, _, gk) = result.unwrap();
        assert_eq!(km.len(), 2);
        assert_eq!(gk.len(), 3);
        let olm_sub = gk
            .get(&(
                "operators.coreos.com".to_string(),
                "Subscription".to_string(),
            ))
            .unwrap();
        assert_eq!(olm_sub.plural, "subscriptions");
        let msg_sub = gk
            .get(&(
                "messaging.example.com".to_string(),
                "Subscription".to_string(),
            ))
            .unwrap();
        assert_eq!(msg_sub.plural, "messagingsubs");
    }

    #[test]
    fn serialize_roundtrip() {
        let mut km = KindMap::new();
        km.insert(
            "Pod".to_string(),
            KindInfo {
                group: "".to_string(),
                version: "v1".to_string(),
                plural: "pods".to_string(),
                namespaced: true,
            },
        );
        let mut gvr = GvrMap::new();
        gvr.insert("pods".to_string(), "Pod".to_string());
        let mut gk = GroupKindMap::new();
        gk.insert(
            ("".to_string(), "Pod".to_string()),
            KindInfo {
                group: "".to_string(),
                version: "v1".to_string(),
                plural: "pods".to_string(),
                namespaced: true,
            },
        );

        let json = serialize_discovery(&km, &gvr, &gk);
        let result = deserialize_discovery(&json);
        assert!(result.is_some());
        let (km2, gvr2, gk2) = result.unwrap();
        assert_eq!(km2.len(), km.len());
        assert_eq!(gvr2.len(), gvr.len());
        assert_eq!(gk2.len(), gk.len());
    }
}
