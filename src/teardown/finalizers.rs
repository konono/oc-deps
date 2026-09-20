use std::sync::Arc;

use futures::stream::StreamExt;
use kube::Client;

use crate::kube::discovery::{GroupKindMap, KindMap};
use crate::kube::resource::{ResourceId, resolve_api};

#[derive(Debug, Clone)]
pub enum FinalizerCheck {
    KnownEmpty,
    KnownFinalizers(Vec<String>),
    Unknown(String),
}

pub async fn check_resource_finalizers(
    client: &Client,
    resource: &ResourceId,
    kind_map: &KindMap,
    gk_map: &GroupKindMap,
) -> FinalizerCheck {
    let (api, _) = match resolve_api(client, resource, kind_map, gk_map) {
        Some(r) => r,
        None => {
            return FinalizerCheck::Unknown(format!(
                "cannot resolve API for {}/{}",
                resource.kind, resource.name
            ));
        }
    };

    match api.get(&resource.name).await {
        Ok(obj) => {
            let fins = obj.metadata.finalizers.unwrap_or_default();
            if fins.is_empty() {
                FinalizerCheck::KnownEmpty
            } else {
                FinalizerCheck::KnownFinalizers(fins)
            }
        }
        Err(kube::Error::Api(err)) if err.code == 404 => FinalizerCheck::KnownEmpty,
        Err(e) => FinalizerCheck::Unknown(format!("GET failed: {}", e)),
    }
}

pub async fn check_finalizers_batch(
    client: &Client,
    resources: &[ResourceId],
    kind_map: &KindMap,
    gk_map: &GroupKindMap,
    concurrency: usize,
) -> Vec<(ResourceId, FinalizerCheck)> {
    let km = Arc::new(kind_map.clone());
    let gk = Arc::new(gk_map.clone());
    let futs = resources.iter().map(|res| {
        let client = client.clone();
        let res = res.clone();
        let km = km.clone();
        let gk = gk.clone();
        async move {
            let r = check_resource_finalizers(&client, &res, &km, &gk).await;
            (res, r)
        }
    });

    futures::stream::iter(futs)
        .buffer_unordered(concurrency)
        .collect()
        .await
}

/// Returns true if any result has finalizers or is unknown (fail-closed).
pub fn requires_serialization(results: &[(ResourceId, FinalizerCheck)]) -> bool {
    results.iter().any(|(_, r)| {
        matches!(
            r,
            FinalizerCheck::KnownFinalizers(_) | FinalizerCheck::Unknown(_)
        )
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_resource(kind: &str, name: &str) -> ResourceId {
        ResourceId {
            group: "test.example.com".to_string(),
            version: "v1".to_string(),
            kind: kind.to_string(),
            namespace: Some("test-ns".to_string()),
            name: name.to_string(),
            uid: None,
        }
    }

    #[test]
    fn unknown_finalizer_check_triggers_serialization() {
        let results = vec![
            (make_resource("Pod", "a"), FinalizerCheck::KnownEmpty),
            (
                make_resource("Pod", "b"),
                FinalizerCheck::Unknown("GET failed".to_string()),
            ),
        ];
        assert!(requires_serialization(&results));
    }

    #[test]
    fn known_finalizers_trigger_serialization() {
        let results = vec![(
            make_resource("Pod", "a"),
            FinalizerCheck::KnownFinalizers(vec!["foo/bar".to_string()]),
        )];
        assert!(requires_serialization(&results));
    }

    #[test]
    fn all_empty_does_not_trigger_serialization() {
        let results = vec![
            (make_resource("Pod", "a"), FinalizerCheck::KnownEmpty),
            (make_resource("Pod", "b"), FinalizerCheck::KnownEmpty),
        ];
        assert!(!requires_serialization(&results));
    }

    #[test]
    fn empty_results_does_not_trigger_serialization() {
        let results: Vec<(ResourceId, FinalizerCheck)> = vec![];
        assert!(!requires_serialization(&results));
    }
}
