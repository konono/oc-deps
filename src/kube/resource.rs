use std::collections::{HashMap, HashSet};
use std::fmt;

use serde::{Deserialize, Serialize};

// ──────────────────────────────────────────────────────────────
//  Scan warning types
// ──────────────────────────────────────────────────────────────

#[derive(Clone, Debug)]
pub enum ScanWarning {
    Forbidden { gvr: String, status: u16 },
    Timeout { gvr: String },
    RateLimited { gvr: String },
    ServerError { gvr: String, status: u16, message: String },
    Other { gvr: String, message: String },
}

impl ScanWarning {
    pub fn gvr(&self) -> &str {
        match self {
            ScanWarning::Forbidden { gvr, .. } => gvr,
            ScanWarning::Timeout { gvr, .. } => gvr,
            ScanWarning::RateLimited { gvr, .. } => gvr,
            ScanWarning::ServerError { gvr, .. } => gvr,
            ScanWarning::Other { gvr, .. } => gvr,
        }
    }

    pub fn from_kube_error(err: &kube::Error, group: &str, version: &str, plural: &str) -> Self {
        let gvr = if group.is_empty() {
            format!("{}/{}", version, plural)
        } else {
            format!("{}/{}/{}", group, version, plural)
        };
        match err {
            kube::Error::Api(resp) => match resp.code {
                401 | 403 => ScanWarning::Forbidden { gvr, status: resp.code },
                408 => ScanWarning::Timeout { gvr },
                429 => ScanWarning::RateLimited { gvr },
                500..=599 => ScanWarning::ServerError {
                    gvr,
                    status: resp.code,
                    message: resp.message.clone(),
                },
                _ => ScanWarning::Other {
                    gvr,
                    message: resp.message.clone(),
                },
            },
            _ => {
                let msg = err.to_string();
                if msg.contains("timed out") || msg.contains("timeout") {
                    ScanWarning::Timeout { gvr }
                } else {
                    ScanWarning::Other { gvr, message: msg }
                }
            }
        }
    }

    pub fn is_retryable(&self) -> bool {
        matches!(
            self,
            ScanWarning::Timeout { .. }
                | ScanWarning::RateLimited { .. }
                | ScanWarning::ServerError { .. }
        )
    }
}

impl fmt::Display for ScanWarning {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ScanWarning::Forbidden { gvr, status } => {
                write!(f, "{} ({} Forbidden)", gvr, status)
            }
            ScanWarning::Timeout { gvr } => write!(f, "{} (timeout)", gvr),
            ScanWarning::RateLimited { gvr } => write!(f, "{} (429 Too Many Requests)", gvr),
            ScanWarning::ServerError { gvr, status, .. } => {
                write!(f, "{} ({} Server Error)", gvr, status)
            }
            ScanWarning::Other { gvr, message } => write!(f, "{} ({})", gvr, message),
        }
    }
}

pub fn format_scan_warnings(warnings: &[ScanWarning], verbose: bool) {
    if warnings.is_empty() {
        return;
    }
    eprintln!(
        "\n⚠ {} API type{} skipped during scan:",
        warnings.len(),
        if warnings.len() == 1 { "" } else { "s" }
    );
    for w in warnings {
        if verbose {
            match w {
                ScanWarning::ServerError { gvr, status, message } => {
                    eprintln!("  - {} ({}: {})", gvr, status, message);
                }
                ScanWarning::Other { gvr, message } => {
                    eprintln!("  - {} ({})", gvr, message);
                }
                _ => eprintln!("  - {}", w),
            }
        } else {
            eprintln!("  - {}", w);
        }
    }
    eprintln!("  Results may be incomplete.");
}

// ──────────────────────────────────────────────────────────────
//  Snapshot types — serializable, designed for persistence
// ──────────────────────────────────────────────────────────────

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ResourceId {
    pub group: String,
    pub version: String,
    pub kind: String,
    pub namespace: Option<String>,
    pub name: String,
    pub uid: Option<String>,
}

impl std::fmt::Display for ResourceId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}/{}", self.kind, self.name)
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct OwnerRefEntry {
    pub api_version: String,
    pub kind: String,
    pub name: String,
    pub uid: String,
    pub controller: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SpecRefEntry {
    pub target_kind: String,
    pub target_name: String,
    pub field_path: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ResourceEntry {
    pub id: ResourceId,
    pub owner_refs: Vec<OwnerRefEntry>,
    pub spec_refs: Vec<SpecRefEntry>,
    pub labels: HashMap<String, String>,
    pub annotations: HashMap<String, String>,
    pub raw_spec: Option<serde_json::Value>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ClusterSnapshot {
    pub resources: HashMap<String, ResourceEntry>,
    pub scan_errors: Vec<String>,
    pub cluster_url: String,
    pub taken_at: String,
    pub namespaces: Vec<String>,
}

// ──────────────────────────────────────────────────────────────
//  Runtime types — used for live tree traversal (existing)
// ──────────────────────────────────────────────────────────────

#[derive(Clone)]
pub struct ResourceInfo {
    pub kind: String,
    pub name: String,
    pub namespace: Option<String>,
    pub uid: String,
    pub owner_refs: Vec<OwnerRef>,
}

#[derive(Clone)]
pub struct OwnerRef {
    pub api_version: String,
    pub kind: String,
    pub name: String,
    pub uid: String,
    pub controller: bool,
}

#[derive(Clone)]
pub struct SpecRef {
    pub target_kind: String,
    pub target_name: String,
    pub field_path: String,
}

#[derive(Clone)]
pub struct IncomingRef {
    pub source_kind: String,
    pub source_name: String,
    pub field_path: String,
}

pub type ScanItem = (ResourceInfo, Vec<SpecRef>, Vec<(String, String)>);
pub type RefData = (String, String, Vec<SpecRef>, Vec<(String, String)>);

pub struct NamespaceIndex {
    pub by_uid: HashMap<String, ResourceInfo>,
    pub children_of: HashMap<String, Vec<String>>,
    pub by_kind_name: HashMap<(String, String), String>,
    pub refs_from: HashMap<String, Vec<SpecRef>>,
    pub refs_to: HashMap<String, Vec<IncomingRef>>,
}

impl NamespaceIndex {
    pub fn new() -> Self {
        Self {
            by_uid: HashMap::new(),
            children_of: HashMap::new(),
            by_kind_name: HashMap::new(),
            refs_from: HashMap::new(),
            refs_to: HashMap::new(),
        }
    }

    pub fn insert(&mut self, info: ResourceInfo) {
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

pub fn resolve_kind_info<'a>(
    resource: &ResourceId,
    kind_map: &'a crate::kube::discovery::KindMap,
    gk_map: &'a crate::kube::discovery::GroupKindMap,
) -> Option<&'a crate::kube::discovery::KindInfo> {
    if !resource.group.is_empty() {
        gk_map.get(&(resource.group.clone(), resource.kind.clone()))
    } else {
        kind_map.get(&resource.kind)
    }
}

/// Resolve the correct API endpoint for a ResourceId.
/// Uses GroupKindMap for precise (group, kind) lookup, falls back to KindMap.
pub fn resolve_api(
    client: &kube::Client,
    resource: &ResourceId,
    kind_map: &crate::kube::discovery::KindMap,
    gk_map: &crate::kube::discovery::GroupKindMap,
) -> Option<(kube::api::Api<kube::api::DynamicObject>, bool)> {
    let kind_info = resolve_kind_info(resource, kind_map, gk_map)?;

    let (group, version) = if !resource.group.is_empty() && !resource.version.is_empty() {
        (resource.group.as_str(), resource.version.as_str())
    } else {
        (kind_info.group.as_str(), kind_info.version.as_str())
    };

    let gvk = kube::core::GroupVersion::gv(group, version).with_kind(&resource.kind);
    let ar = kube::api::ApiResource::from_gvk_with_plural(&gvk, &kind_info.plural);

    let api = if let Some(ns) = &resource.namespace {
        kube::api::Api::namespaced_with(client.clone(), ns, &ar)
    } else if kind_info.namespaced {
        return None;
    } else {
        kube::api::Api::all_with(client.clone(), &ar)
    };

    Some((api, kind_info.namespaced))
}

pub fn primary_owner(refs: &[OwnerRef]) -> Option<&OwnerRef> {
    refs.iter().find(|r| r.controller).or(refs.first())
}

pub fn dedup_spec_refs(refs: &mut Vec<SpecRef>) {
    let mut seen = HashSet::new();
    refs.retain(|r| seen.insert((r.target_kind.clone(), r.target_name.clone())));
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::kube::discovery::{GroupKindMap, KindInfo, KindMap};

    fn make_resource_id(group: &str, kind: &str, name: &str) -> ResourceId {
        ResourceId {
            group: group.to_string(),
            version: "v1".to_string(),
            kind: kind.to_string(),
            namespace: None,
            name: name.to_string(),
            uid: None,
        }
    }

    fn make_kind_info(group: &str, plural: &str) -> KindInfo {
        KindInfo {
            group: group.to_string(),
            version: "v1".to_string(),
            plural: plural.to_string(),
            namespaced: true,
        }
    }

    fn make_test_maps() -> (KindMap, GroupKindMap) {
        let mut km = KindMap::new();
        let mut gk = GroupKindMap::new();

        km.insert("Pod".to_string(), make_kind_info("", "pods"));
        gk.insert(
            ("".to_string(), "Pod".to_string()),
            make_kind_info("", "pods"),
        );

        // Subscription exists in two groups
        km.insert(
            "Subscription".to_string(),
            make_kind_info("operators.coreos.com", "subscriptions"),
        );
        gk.insert(
            (
                "operators.coreos.com".to_string(),
                "Subscription".to_string(),
            ),
            make_kind_info("operators.coreos.com", "subscriptions"),
        );
        gk.insert(
            (
                "messaging.example.com".to_string(),
                "Subscription".to_string(),
            ),
            make_kind_info("messaging.example.com", "messagingsubscriptions"),
        );

        (km, gk)
    }

    #[test]
    fn resolve_kind_info_with_group_uses_gk_map() {
        let (km, gk) = make_test_maps();
        let res = make_resource_id("operators.coreos.com", "Subscription", "test");
        let info = resolve_kind_info(&res, &km, &gk).unwrap();
        assert_eq!(info.plural, "subscriptions");
        assert_eq!(info.group, "operators.coreos.com");
    }

    #[test]
    fn resolve_kind_info_with_group_picks_correct_group() {
        let (km, gk) = make_test_maps();
        let res = make_resource_id("messaging.example.com", "Subscription", "test");
        let info = resolve_kind_info(&res, &km, &gk).unwrap();
        assert_eq!(info.plural, "messagingsubscriptions");
        assert_eq!(info.group, "messaging.example.com");
    }

    #[test]
    fn resolve_kind_info_group_mismatch_returns_none() {
        let (km, gk) = make_test_maps();
        let res = make_resource_id("nonexistent.group", "Subscription", "test");
        assert!(resolve_kind_info(&res, &km, &gk).is_none());
    }

    #[test]
    fn resolve_kind_info_without_group_uses_kind_map() {
        let (km, gk) = make_test_maps();
        let res = make_resource_id("", "Pod", "test");
        let info = resolve_kind_info(&res, &km, &gk).unwrap();
        assert_eq!(info.plural, "pods");
    }

    #[test]
    fn resolve_kind_info_unknown_kind_returns_none() {
        let (km, gk) = make_test_maps();
        let res = make_resource_id("", "NonExistentKind", "test");
        assert!(resolve_kind_info(&res, &km, &gk).is_none());
    }
}
