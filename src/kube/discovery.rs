use std::collections::HashMap;
use std::path::PathBuf;

use anyhow::{Result, bail};
use kube::{
    Client,
    config::Config,
    discovery::{Discovery, Scope, verbs},
};

#[derive(Clone)]
pub struct KindInfo {
    pub group: String,
    pub version: String,
    pub plural: String,
    pub namespaced: bool,
    pub listable: bool,
}

pub type KindMap = HashMap<String, KindInfo>;
pub type GvrMap = HashMap<String, String>;
/// (group, kind) → KindInfo — handles duplicate Kinds across API groups
pub type GroupKindMap = HashMap<(String, String), KindInfo>;
/// (group, version, kind) → KindInfo — exact version match for APIService resolution
pub type GvkMap = HashMap<(String, String, String), KindInfo>;

pub async fn load_config_and_client() -> Result<(Config, Client)> {
    let config = Config::infer().await?;
    let client = Client::try_from(config.clone())?;
    Ok((config, client))
}

pub async fn build_kind_lookup(client: &Client) -> Result<(KindMap, GvrMap, GroupKindMap, GvkMap)> {
    let discovery = Discovery::new(client.clone()).run().await?;
    let mut kind_map = KindMap::new();
    let mut gvr_map = GvrMap::new();
    let mut gk_map = GroupKindMap::new();
    let mut gvk_map = GvkMap::new();

    for group in discovery.groups() {
        for version in group.versions() {
            for (ar, caps) in group.versioned_resources(version) {
                let kind = ar.kind.clone();
                let group_name = ar.group.clone();
                let plural = ar.plural.clone();
                let namespaced = caps.scope == Scope::Namespaced;
                let listable = caps.supports_operation(verbs::LIST);

                let info = KindInfo {
                    group: group_name.clone(),
                    version: ar.version.clone(),
                    plural: plural.clone(),
                    namespaced,
                    listable,
                };

                let gvr_key = if group_name.is_empty() {
                    plural.clone()
                } else {
                    format!("{}.{}", plural, group_name)
                };

                kind_map.entry(kind.clone()).or_insert_with(|| info.clone());
                gk_map
                    .entry((group_name.clone(), kind.clone()))
                    .or_insert_with(|| info.clone());
                gvk_map
                    .entry((group_name.clone(), ar.version.clone(), kind.clone()))
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
            let listable = caps.supports_operation(verbs::LIST);

            let info = KindInfo {
                group: group_name.clone(),
                version: ar.version.clone(),
                plural: plural.clone(),
                namespaced,
                listable,
            };

            kind_map.insert(kind.clone(), info.clone());
            gk_map.insert((group_name.clone(), kind.clone()), info.clone());
            gvk_map.insert((group_name.clone(), ar.version.clone(), kind.clone()), info);

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

    Ok((kind_map, gvr_map, gk_map, gvk_map))
}

const CACHE_TTL_SECS: u64 = 30 * 60;
pub(crate) const APPLY_SET_REUSE_CACHE_ENV: &str = "OC_DEPS_APPLY_SET_REUSE_DISCOVERY_CACHE";

fn discovery_cache_age_allowed(age_secs: u64, reuse_for_apply_set: bool) -> bool {
    reuse_for_apply_set || age_secs < CACHE_TTL_SECS
}

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
    gvk_map: &GvkMap,
) -> serde_json::Value {
    let km: serde_json::Map<String, serde_json::Value> = kind_map
        .iter()
        .map(|(k, v)| {
            (
                k.clone(),
                serde_json::json!([v.group, v.version, v.plural, v.namespaced, v.listable]),
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
                serde_json::json!([v.group, v.version, v.plural, v.namespaced, v.listable]),
            )
        })
        .collect();

    let gvk: serde_json::Map<String, serde_json::Value> = gvk_map
        .iter()
        .map(|((group, version, kind), v)| {
            let key = format!("{}/{}/{}", group, version, kind);
            (
                key,
                serde_json::json!([v.group, v.version, v.plural, v.namespaced, v.listable]),
            )
        })
        .collect();

    serde_json::json!({ "version": 4, "kind_map": km, "gvr_map": gm, "gk_map": gk, "gvk_map": gvk })
}

fn deserialize_discovery(
    value: &serde_json::Value,
) -> Option<(KindMap, GvrMap, GroupKindMap, GvkMap)> {
    let version = value.get("version").and_then(|v| v.as_u64()).unwrap_or(1);
    if version < 4 {
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
                listable: arr.get(4).and_then(|v| v.as_bool()).unwrap_or(true),
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
                        listable: arr.get(4).and_then(|v| v.as_bool()).unwrap_or(true),
                    },
                );
            }
        }
    }

    let mut gvk_map = GvkMap::new();
    {
        let gvk_val = value.get("gvk_map").and_then(|v| v.as_object())?;
        for (k, v) in gvk_val {
            let parts: Vec<&str> = k.splitn(3, '/').collect();
            if parts.len() < 3 {
                continue;
            }
            let (group, version, kind) = (parts[0], parts[1], parts[2]);
            let arr = match v.as_array() {
                Some(a) if a.len() >= 4 => a,
                _ => continue,
            };
            gvk_map.insert(
                (group.to_string(), version.to_string(), kind.to_string()),
                KindInfo {
                    group: arr[0].as_str().unwrap_or("").to_string(),
                    version: arr[1].as_str().unwrap_or("").to_string(),
                    plural: arr[2].as_str().unwrap_or("").to_string(),
                    namespaced: arr[3].as_bool().unwrap_or(true),
                    listable: arr.get(4).and_then(|v| v.as_bool()).unwrap_or(true),
                },
            );
        }
    }

    Some((kind_map, gvr_map, gk_map, gvk_map))
}

pub async fn build_kind_lookup_cached(
    client: &Client,
    config: &Config,
    no_cache: bool,
) -> Result<(KindMap, GvrMap, GroupKindMap, GvkMap)> {
    let path = discovery_cache_path(config);
    // apply-set refreshes this cache in its first child process, then marks the
    // remaining children so they can reuse that same snapshot for the whole run.
    let reuse_for_apply_set = std::env::var_os(APPLY_SET_REUSE_CACHE_ENV).is_some();

    if !no_cache
        && let Ok(metadata) = std::fs::metadata(&path)
        && let Ok(modified) = metadata.modified()
        && discovery_cache_age_allowed(
            modified.elapsed().unwrap_or_default().as_secs(),
            reuse_for_apply_set,
        )
        && let Ok(data) = std::fs::read_to_string(&path)
        && let Some(result) = serde_json::from_str::<serde_json::Value>(&data)
            .ok()
            .and_then(|v| deserialize_discovery(&v))
    {
        eprintln!("   (cached, {} types)", result.0.len());
        return Ok(result);
    }

    let (kind_map, gvr_map, gk_map, gvk_map) = build_kind_lookup(client).await?;

    let json = serialize_discovery(&kind_map, &gvr_map, &gk_map, &gvk_map);
    if let Ok(data) = serde_json::to_string(&json) {
        std::fs::write(&path, data).ok();
    }

    Ok((kind_map, gvr_map, gk_map, gvk_map))
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
    fn apply_set_cache_reuse_ignores_normal_ttl() {
        assert!(!discovery_cache_age_allowed(CACHE_TTL_SECS, false));
        assert!(discovery_cache_age_allowed(CACHE_TTL_SECS, true));
    }

    #[test]
    fn normal_discovery_cache_expires_after_thirty_minutes() {
        assert!(discovery_cache_age_allowed(CACHE_TTL_SECS - 1, false));
        assert!(!discovery_cache_age_allowed(CACHE_TTL_SECS, false));
    }

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
    fn v3_cache_rejected() {
        let cache = serde_json::json!({
            "version": 3,
            "kind_map": { "Pod": ["", "v1", "pods", true] },
            "gvr_map": { "pods": "Pod" },
            "gk_map": { "/Pod": ["", "v1", "pods", true] },
            "gvk_map": { "/v1/Pod": ["", "v1", "pods", true] }
        });
        assert!(deserialize_discovery(&cache).is_none());
    }

    #[test]
    fn v2_cache_rejected() {
        let cache = serde_json::json!({
            "version": 2,
            "kind_map": { "Pod": ["", "v1", "pods", true] },
            "gvr_map": { "pods": "Pod" },
            "gk_map": { "/Pod": ["", "v1", "pods", true] }
        });
        assert!(deserialize_discovery(&cache).is_none());
    }

    #[test]
    fn v4_cache_accepted() {
        let cache = serde_json::json!({
            "version": 4,
            "kind_map": { "Pod": ["", "v1", "pods", true, true] },
            "gvr_map": { "pods": "Pod" },
            "gk_map": { "/Pod": ["", "v1", "pods", true, true] },
            "gvk_map": { "/v1/Pod": ["", "v1", "pods", true, true] }
        });
        let result = deserialize_discovery(&cache);
        assert!(result.is_some());
        let (km, gvr, gk, gvk) = result.unwrap();
        assert_eq!(km.len(), 1);
        assert_eq!(gvr.len(), 1);
        assert!(gk.contains_key(&("".to_string(), "Pod".to_string())));
        assert!(gvk.contains_key(&("".to_string(), "v1".to_string(), "Pod".to_string())));
    }

    #[test]
    fn v4_cache_preserves_multiple_versions() {
        let cache = serde_json::json!({
            "version": 4,
            "kind_map": {
                "Widget": ["example.io", "v1", "widgets", true, true]
            },
            "gvr_map": {
                "widgets.example.io": "Widget"
            },
            "gk_map": {
                "example.io/Widget": ["example.io", "v1", "widgets", true, true]
            },
            "gvk_map": {
                "example.io/v1alpha1/Widget": ["example.io", "v1alpha1", "widgets", true, true],
                "example.io/v1beta1/Widget": ["example.io", "v1beta1", "widgets", true, true],
                "example.io/v1/Widget": ["example.io", "v1", "widgets", true, true]
            }
        });
        let result = deserialize_discovery(&cache);
        assert!(result.is_some());
        let (_, _, _, gvk) = result.unwrap();
        assert_eq!(gvk.len(), 3);
        assert!(gvk.contains_key(&(
            "example.io".to_string(),
            "v1alpha1".to_string(),
            "Widget".to_string()
        )));
        assert!(gvk.contains_key(&(
            "example.io".to_string(),
            "v1beta1".to_string(),
            "Widget".to_string()
        )));
        assert!(gvk.contains_key(&(
            "example.io".to_string(),
            "v1".to_string(),
            "Widget".to_string()
        )));
    }

    #[test]
    fn v4_cache_with_multiple_groups() {
        let cache = serde_json::json!({
            "version": 4,
            "kind_map": {
                "Pod": ["", "v1", "pods", true, true],
                "Subscription": ["operators.coreos.com", "v1alpha1", "subscriptions", true, true]
            },
            "gvr_map": {
                "pods": "Pod",
                "subscriptions.operators.coreos.com": "Subscription"
            },
            "gk_map": {
                "/Pod": ["", "v1", "pods", true, true],
                "operators.coreos.com/Subscription": ["operators.coreos.com", "v1alpha1", "subscriptions", true, true],
                "messaging.example.com/Subscription": ["messaging.example.com", "v1", "messagingsubs", true, true]
            },
            "gvk_map": {
                "/v1/Pod": ["", "v1", "pods", true, true],
                "operators.coreos.com/v1alpha1/Subscription": ["operators.coreos.com", "v1alpha1", "subscriptions", true, true],
                "messaging.example.com/v1/Subscription": ["messaging.example.com", "v1", "messagingsubs", true, true]
            }
        });
        let result = deserialize_discovery(&cache);
        assert!(result.is_some());
        let (km, _, gk, gvk) = result.unwrap();
        assert_eq!(km.len(), 2);
        assert_eq!(gk.len(), 3);
        assert_eq!(gvk.len(), 3);
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
                listable: true,
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
                listable: true,
            },
        );

        let mut gvk = GvkMap::new();
        gvk.insert(
            ("".to_string(), "v1".to_string(), "Pod".to_string()),
            KindInfo {
                group: "".to_string(),
                version: "v1".to_string(),
                plural: "pods".to_string(),
                namespaced: true,
                listable: true,
            },
        );

        let json = serialize_discovery(&km, &gvr, &gk, &gvk);
        let result = deserialize_discovery(&json);
        assert!(result.is_some());
        let (km2, gvr2, gk2, gvk2) = result.unwrap();
        assert_eq!(km2.len(), km.len());
        assert_eq!(gvr2.len(), gvr.len());
        assert_eq!(gk2.len(), gk.len());
        assert_eq!(gvk2.len(), gvk.len());
    }

    #[test]
    fn gvk_cache_roundtrip_preserves_multiple_versions() {
        let mut km = KindMap::new();
        km.insert(
            "Widget".to_string(),
            KindInfo {
                group: "example.io".to_string(),
                version: "v1".to_string(),
                plural: "widgets".to_string(),
                namespaced: true,
                listable: true,
            },
        );
        let gvr = GvrMap::new();
        let mut gk = GroupKindMap::new();
        gk.insert(
            ("example.io".to_string(), "Widget".to_string()),
            KindInfo {
                group: "example.io".to_string(),
                version: "v1".to_string(),
                plural: "widgets".to_string(),
                namespaced: true,
                listable: true,
            },
        );
        let mut gvk = GvkMap::new();
        for ver in &["v1alpha1", "v1beta1", "v1"] {
            gvk.insert(
                (
                    "example.io".to_string(),
                    ver.to_string(),
                    "Widget".to_string(),
                ),
                KindInfo {
                    group: "example.io".to_string(),
                    version: ver.to_string(),
                    plural: "widgets".to_string(),
                    namespaced: true,
                    listable: true,
                },
            );
        }
        assert_eq!(gvk.len(), 3);

        let json = serialize_discovery(&km, &gvr, &gk, &gvk);
        let result = deserialize_discovery(&json);
        assert!(result.is_some());
        let (_, _, _, gvk2) = result.unwrap();
        assert_eq!(gvk2.len(), 3);
        assert!(gvk2.contains_key(&(
            "example.io".to_string(),
            "v1alpha1".to_string(),
            "Widget".to_string()
        )));
        assert!(gvk2.contains_key(&(
            "example.io".to_string(),
            "v1beta1".to_string(),
            "Widget".to_string()
        )));
        assert!(gvk2.contains_key(&(
            "example.io".to_string(),
            "v1".to_string(),
            "Widget".to_string()
        )));
    }
}
