use std::collections::{HashMap, HashSet};
use std::fmt;

use serde::{Deserialize, Serialize};

// ──────────────────────────────────────────────────────────────
//  Scan warning types
// ──────────────────────────────────────────────────────────────

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum ScanWarning {
    Forbidden {
        gvr: String,
        status: u16,
    },
    Timeout {
        gvr: String,
        message: Option<String>,
        retries: usize,
    },
    RateLimited {
        gvr: String,
        retries: usize,
    },
    ServerError {
        gvr: String,
        status: u16,
        message: String,
        retries: usize,
    },
    Other {
        gvr: String,
        message: String,
    },
}

impl ScanWarning {
    pub fn from_kube_error(err: &kube::Error, group: &str, version: &str, plural: &str) -> Self {
        let gvr = if group.is_empty() {
            format!("{}/{}", version, plural)
        } else {
            format!("{}/{}/{}", group, version, plural)
        };
        match err {
            kube::Error::Api(resp) => match resp.code {
                401 => ScanWarning::Forbidden { gvr, status: 401 },
                403 => ScanWarning::Forbidden { gvr, status: 403 },
                408 => ScanWarning::Timeout {
                    gvr,
                    message: Some(resp.message.clone()),
                    retries: 0,
                },
                429 => ScanWarning::RateLimited { gvr, retries: 0 },
                500..=599 => ScanWarning::ServerError {
                    gvr,
                    status: resp.code,
                    message: resp.message.clone(),
                    retries: 0,
                },
                _ => ScanWarning::Other {
                    gvr,
                    message: resp.message.clone(),
                },
            },
            _ => {
                let msg = err.to_string();
                if msg.contains("timed out") || msg.contains("timeout") {
                    ScanWarning::Timeout {
                        gvr,
                        message: Some(msg),
                        retries: 0,
                    }
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

    pub fn set_retries(&mut self, count: usize) {
        match self {
            ScanWarning::Timeout { retries, .. } => *retries = count,
            ScanWarning::RateLimited { retries, .. } => *retries = count,
            ScanWarning::ServerError { retries, .. } => *retries = count,
            _ => {}
        }
    }
}

impl fmt::Display for ScanWarning {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ScanWarning::Forbidden { gvr, status } => {
                let label = if *status == 401 {
                    "Unauthorized"
                } else {
                    "Forbidden"
                };
                write!(f, "{} ({} {})", gvr, status, label)
            }
            ScanWarning::Timeout { gvr, retries, .. } => {
                if *retries > 0 {
                    write!(f, "{} (timeout, retried {}x)", gvr, retries)
                } else {
                    write!(f, "{} (timeout)", gvr)
                }
            }
            ScanWarning::RateLimited { gvr, retries } => {
                if *retries > 0 {
                    write!(f, "{} (429 Too Many Requests, retried {}x)", gvr, retries)
                } else {
                    write!(f, "{} (429 Too Many Requests)", gvr)
                }
            }
            ScanWarning::ServerError {
                gvr,
                status,
                retries,
                ..
            } => {
                if *retries > 0 {
                    write!(f, "{} ({} Server Error, retried {}x)", gvr, status, retries)
                } else {
                    write!(f, "{} ({} Server Error)", gvr, status)
                }
            }
            ScanWarning::Other { gvr, message } => write!(f, "{} ({})", gvr, message),
        }
    }
}

const MAX_DEFAULT_WARNINGS: usize = 5;

pub fn format_scan_warnings(warnings: &[ScanWarning], verbose: bool) {
    if warnings.is_empty() {
        return;
    }
    eprintln!(
        "\n⚠ {} API type{} skipped during scan:",
        warnings.len(),
        if warnings.len() == 1 { "" } else { "s" }
    );
    let display_items: &[ScanWarning] = if verbose {
        warnings
    } else if warnings.len() > MAX_DEFAULT_WARNINGS {
        &warnings[..MAX_DEFAULT_WARNINGS]
    } else {
        warnings
    };
    for w in display_items {
        if verbose {
            match w {
                ScanWarning::ServerError {
                    gvr,
                    status,
                    message,
                    retries,
                } => {
                    eprintln!(
                        "  - {} ({}: {}, retried {}x)",
                        gvr, status, message, retries
                    );
                }
                ScanWarning::Timeout {
                    gvr,
                    message,
                    retries,
                } => {
                    let msg = message.as_deref().unwrap_or("no details");
                    eprintln!("  - {} (timeout: {}, retried {}x)", gvr, msg, retries);
                }
                ScanWarning::RateLimited { gvr, retries } => {
                    eprintln!("  - {} (429 Too Many Requests, retried {}x)", gvr, retries);
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
    if !verbose && warnings.len() > MAX_DEFAULT_WARNINGS {
        eprintln!(
            "  ... and {} more (use --verbose to see all)",
            warnings.len() - MAX_DEFAULT_WARNINGS
        );
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
    #[serde(
        default,
        alias = "scan_errors",
        deserialize_with = "deserialize_scan_warnings"
    )]
    pub scan_warnings: Vec<ScanWarning>,
    pub cluster_url: String,
    pub taken_at: String,
    pub namespaces: Vec<String>,
}

fn deserialize_scan_warnings<'de, D>(deserializer: D) -> Result<Vec<ScanWarning>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    use serde::de;

    #[derive(Deserialize)]
    #[serde(untagged)]
    enum WarningOrString {
        Warning(ScanWarning),
        LegacyString(String),
    }

    struct WarningsVisitor;

    impl<'de> de::Visitor<'de> for WarningsVisitor {
        type Value = Vec<ScanWarning>;

        fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
            formatter.write_str("a sequence of ScanWarning or legacy string errors")
        }

        fn visit_seq<A>(self, mut seq: A) -> Result<Vec<ScanWarning>, A::Error>
        where
            A: de::SeqAccess<'de>,
        {
            let mut warnings = Vec::new();
            while let Some(item) = seq.next_element::<WarningOrString>()? {
                match item {
                    WarningOrString::Warning(w) => warnings.push(w),
                    WarningOrString::LegacyString(s) => {
                        let (gvr, message) = s.split_once(": ").unwrap_or(("unknown", &s));
                        warnings.push(ScanWarning::Other {
                            gvr: gvr.to_string(),
                            message: message.to_string(),
                        });
                    }
                }
            }
            Ok(warnings)
        }
    }

    deserializer.deserialize_seq(WarningsVisitor)
}

pub const EXCLUDED_ANNOTATION_KEYS: &[&str] = &[
    "kubectl.kubernetes.io/last-applied-configuration",
    "control-plane.alpha.kubernetes.io/leader",
];

pub fn filter_annotations(annotations: &HashMap<String, String>) -> HashMap<String, String> {
    annotations
        .iter()
        .filter(|(k, _)| !EXCLUDED_ANNOTATION_KEYS.contains(&k.as_str()))
        .map(|(k, v)| (k.clone(), v.clone()))
        .collect()
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
    pub labels: HashMap<String, String>,
    pub annotations: HashMap<String, String>,
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
            listable: true,
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

    #[test]
    fn scan_warning_display_with_group() {
        let w = ScanWarning::Forbidden {
            gvr: "apps/v1/deployments".into(),
            status: 403,
        };
        assert_eq!(format!("{}", w), "apps/v1/deployments (403 Forbidden)");
    }

    #[test]
    fn scan_warning_display_core_group() {
        let w = ScanWarning::Forbidden {
            gvr: "v1/pods".into(),
            status: 403,
        };
        assert_eq!(format!("{}", w), "v1/pods (403 Forbidden)");
    }

    #[test]
    fn scan_warning_401_unauthorized() {
        let w = ScanWarning::Forbidden {
            gvr: "apps/v1/deployments".into(),
            status: 401,
        };
        let display = format!("{}", w);
        assert!(display.contains("Unauthorized"), "got: {}", display);
        assert!(!display.contains("Forbidden"), "got: {}", display);
    }

    #[test]
    fn scan_warning_retryable() {
        let timeout = ScanWarning::Timeout {
            gvr: "v1/pods".into(),
            message: None,
            retries: 0,
        };
        let rate = ScanWarning::RateLimited {
            gvr: "v1/pods".into(),
            retries: 0,
        };
        let server = ScanWarning::ServerError {
            gvr: "v1/pods".into(),
            status: 500,
            message: "err".into(),
            retries: 0,
        };
        let forbidden = ScanWarning::Forbidden {
            gvr: "v1/pods".into(),
            status: 403,
        };
        let other = ScanWarning::Other {
            gvr: "v1/pods".into(),
            message: "err".into(),
        };

        assert!(timeout.is_retryable());
        assert!(rate.is_retryable());
        assert!(server.is_retryable());
        assert!(!forbidden.is_retryable());
        assert!(!other.is_retryable());
    }

    #[test]
    fn scan_warning_set_retries_display() {
        let mut w = ScanWarning::Timeout {
            gvr: "v1/pods".into(),
            message: None,
            retries: 0,
        };
        w.set_retries(2);
        assert!(format!("{}", w).contains("retried 2x"));

        let mut w2 = ScanWarning::ServerError {
            gvr: "v1/pods".into(),
            status: 503,
            message: "unavail".into(),
            retries: 0,
        };
        w2.set_retries(1);
        assert!(format!("{}", w2).contains("retried 1x"));
    }

    #[test]
    fn scan_warning_zero_retries_no_suffix() {
        let w = ScanWarning::Timeout {
            gvr: "v1/pods".into(),
            message: None,
            retries: 0,
        };
        assert!(!format!("{}", w).contains("retried"));
    }

    #[test]
    fn scan_warning_serialization_roundtrip() {
        let w = ScanWarning::Forbidden {
            gvr: "apps/v1/deployments".into(),
            status: 403,
        };
        let json = serde_json::to_string(&w).unwrap();
        let w2: ScanWarning = serde_json::from_str(&json).unwrap();
        assert_eq!(format!("{}", w), format!("{}", w2));
    }

    #[test]
    fn scan_warning_serialization_timeout_with_retries() {
        let w = ScanWarning::Timeout {
            gvr: "v1/pods".into(),
            message: Some("conn timeout".into()),
            retries: 2,
        };
        let json = serde_json::to_string(&w).unwrap();
        let w2: ScanWarning = serde_json::from_str(&json).unwrap();
        assert!(format!("{}", w2).contains("retried 2x"));
    }

    #[test]
    fn filter_annotations_excludes_last_applied() {
        let mut anns = HashMap::new();
        anns.insert(
            "kubectl.kubernetes.io/last-applied-configuration".into(),
            "{}".into(),
        );
        anns.insert("app.kubernetes.io/name".into(), "myapp".into());
        let filtered = filter_annotations(&anns);
        assert_eq!(filtered.len(), 1);
        assert!(filtered.contains_key("app.kubernetes.io/name"));
    }

    #[test]
    fn filter_annotations_excludes_leader() {
        let mut anns = HashMap::new();
        anns.insert(
            "control-plane.alpha.kubernetes.io/leader".into(),
            "{}".into(),
        );
        let filtered = filter_annotations(&anns);
        assert!(filtered.is_empty());
    }

    #[test]
    fn filter_annotations_keeps_revision() {
        let mut anns = HashMap::new();
        anns.insert("deployment.kubernetes.io/revision".into(), "3".into());
        let filtered = filter_annotations(&anns);
        assert_eq!(filtered.len(), 1);
        assert!(filtered.contains_key("deployment.kubernetes.io/revision"));
    }

    #[test]
    fn scan_warning_gvr_format_construction() {
        let w = ScanWarning::Other {
            gvr: "apps/v1/deployments".into(),
            message: "test".into(),
        };
        assert!(format!("{}", w).starts_with("apps/v1/deployments"));

        let w2 = ScanWarning::Other {
            gvr: "v1/pods".into(),
            message: "test".into(),
        };
        assert!(format!("{}", w2).starts_with("v1/pods"));
    }

    #[test]
    fn snapshot_deserialize_legacy_scan_errors() {
        let json = serde_json::json!({
            "resources": {},
            "scan_errors": ["Pod: 403 Forbidden", "Deployment: timeout"],
            "cluster_url": "https://api.test:6443",
            "taken_at": "2026-01-01T00:00:00Z",
            "namespaces": ["default"]
        });
        let snap: ClusterSnapshot = serde_json::from_value(json).unwrap();
        assert_eq!(snap.scan_warnings.len(), 2);
        match &snap.scan_warnings[0] {
            ScanWarning::Other { gvr, message } => {
                assert_eq!(gvr, "Pod");
                assert_eq!(message, "403 Forbidden");
            }
            other => panic!("expected Other, got {:?}", other),
        }
        match &snap.scan_warnings[1] {
            ScanWarning::Other { gvr, message } => {
                assert_eq!(gvr, "Deployment");
                assert_eq!(message, "timeout");
            }
            other => panic!("expected Other, got {:?}", other),
        }
    }

    #[test]
    fn snapshot_deserialize_typed_scan_warnings() {
        let json = serde_json::json!({
            "resources": {},
            "scan_warnings": [
                {"type": "Forbidden", "gvr": "apps/v1/deployments", "status": 403},
                {"type": "Timeout", "gvr": "v1/pods", "message": null, "retries": 2}
            ],
            "cluster_url": "https://api.test:6443",
            "taken_at": "2026-01-01T00:00:00Z",
            "namespaces": ["default"]
        });
        let snap: ClusterSnapshot = serde_json::from_value(json).unwrap();
        assert_eq!(snap.scan_warnings.len(), 2);
        match &snap.scan_warnings[0] {
            ScanWarning::Forbidden { gvr, status } => {
                assert_eq!(gvr, "apps/v1/deployments");
                assert_eq!(*status, 403);
            }
            other => panic!("expected Forbidden, got {:?}", other),
        }
        match &snap.scan_warnings[1] {
            ScanWarning::Timeout { gvr, retries, .. } => {
                assert_eq!(gvr, "v1/pods");
                assert_eq!(*retries, 2);
            }
            other => panic!("expected Timeout, got {:?}", other),
        }
    }

    #[test]
    fn snapshot_deserialize_missing_warnings_field() {
        let json = serde_json::json!({
            "resources": {},
            "cluster_url": "https://api.test:6443",
            "taken_at": "2026-01-01T00:00:00Z",
            "namespaces": ["default"]
        });
        let snap: ClusterSnapshot = serde_json::from_value(json).unwrap();
        assert!(snap.scan_warnings.is_empty());
    }

    #[test]
    fn snapshot_serialize_roundtrip() {
        let snap = ClusterSnapshot {
            resources: HashMap::new(),
            scan_warnings: vec![
                ScanWarning::Forbidden {
                    gvr: "v1/secrets".into(),
                    status: 403,
                },
                ScanWarning::Timeout {
                    gvr: "apps/v1/deployments".into(),
                    message: Some("conn".into()),
                    retries: 1,
                },
            ],
            cluster_url: "https://api.test:6443".into(),
            taken_at: "2026-01-01T00:00:00Z".into(),
            namespaces: vec!["default".into()],
        };
        let json = serde_json::to_string(&snap).unwrap();
        let snap2: ClusterSnapshot = serde_json::from_str(&json).unwrap();
        assert_eq!(snap2.scan_warnings.len(), 2);
        assert_eq!(
            format!("{}", snap2.scan_warnings[0]),
            format!("{}", snap.scan_warnings[0])
        );
        assert_eq!(
            format!("{}", snap2.scan_warnings[1]),
            format!("{}", snap.scan_warnings[1])
        );
    }
}
