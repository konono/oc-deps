use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use futures::stream::StreamExt;
use kube::Client;
use kube::api::{Api, ApiResource, DynamicObject, ListParams};
use kube::core::GroupVersion;
use tokio::task::JoinHandle;

use crate::kube::discovery::{GroupKindMap, KindMap};
use crate::kube::resource::{ResourceId, resolve_api};
use crate::teardown::runtime::{ResourceRuntimeState, RuntimeObservation, RuntimeStateStore};

const RECONCILE_CONCURRENCY: usize = 16;
const WATCH_TIMEOUT_SECS: u32 = 300;

// ──────────────────────────────────────────────────────────────
//  Watch manager
// ──────────────────────────────────────────────────────────────

pub struct WatchManager {
    /// Counter for WATCH stream IDs. Each new stream gets a unique ID.
    /// Used to reject events from old/cancelled streams.
    /// NOT used for authoritative GET — GETs are always accepted.
    next_stream_id: Arc<AtomicU64>,
    store: Arc<RuntimeStateStore>,
}

pub enum WatchWaitResult {
    AllGone,
    Stalled {
        remaining: Vec<ResourceId>,
        finalizer_details: Vec<(ResourceId, usize)>,
        reason: String,
    },
}

impl WatchManager {
    pub fn new(store: Arc<RuntimeStateStore>) -> Self {
        Self {
            next_stream_id: Arc::new(AtomicU64::new(1)),
            store,
        }
    }

    /// Reconcile specific resources via parallel authoritative GETs.
    /// Authoritative observations bypass stream_id checks.
    pub async fn reconcile(
        &self,
        client: &Client,
        resources: &[ResourceId],
        kind_map: &KindMap,
        gk_map: &GroupKindMap,
    ) {
        let km = Arc::new(kind_map.clone());
        let gk = Arc::new(gk_map.clone());

        let futs = resources.iter().map(|res| {
            let client = client.clone();
            let res = res.clone();
            let km = km.clone();
            let gk = gk.clone();
            async move {
                let obs = observe_resource(&client, &res, &km, &gk).await;
                (res, obs)
            }
        });

        let results: Vec<_> = futures::stream::iter(futs)
            .buffer_unordered(RECONCILE_CONCURRENCY)
            .collect()
            .await;

        for (resource, obs) in results {
            match obs {
                ObserveResult::Observation(o) => {
                    // stream_id=0 for authoritative GETs (always accepted)
                    self.store.update_from_observation(&resource, o, 0);
                }
                ObserveResult::ApiError(reason) => {
                    self.store.update_from_executor(
                        &resource,
                        ResourceRuntimeState::Unknown { reason },
                    );
                }
                ObserveResult::Unresolvable(reason) => {
                    self.store.update_from_executor(
                        &resource,
                        ResourceRuntimeState::Unknown { reason },
                    );
                }
            }
        }
    }

    /// Wait for all specified resources to reach Gone state.
    ///
    /// Uses Kubernetes WATCH for low-latency hints, with periodic
    /// authoritative GET reconciliation as safety confirmation.
    ///
    /// WATCH events are non-authoritative: Deleted → needs_verification hint,
    /// UID change → needs_verification hint. Only authoritative GETs can
    /// confirm Gone or Recreated.
    pub async fn wait_for_gone(
        &self,
        client: &Client,
        resources: &[ResourceId],
        kind_map: &KindMap,
        gk_map: &GroupKindMap,
        timeout: Duration,
        stall_timeout: Duration,
    ) -> WatchWaitResult {
        // Initial authoritative reconcile
        self.reconcile(client, resources, kind_map, gk_map).await;

        if self.store.all_gone_for(resources) {
            return WatchWaitResult::AllGone;
        }

        // Start background WATCH tasks for low-latency hints
        let watch_handles = self.start_watch_tasks(client, resources, kind_map, gk_map);

        let start = Instant::now();
        let mut last_progress_check = Instant::now();
        let mut consecutive_unknown_cycles = 0u32;
        const MAX_UNKNOWN_RETRIES: u32 = 3;

        let result = loop {
            // Authoritative reconcile for resources needing verification
            let needs_verify = self.store.resources_needing_verification(resources);
            if !needs_verify.is_empty() {
                self.reconcile(client, &needs_verify, kind_map, gk_map).await;
            }

            // Periodic full reconcile (safety fallback)
            self.reconcile(client, resources, kind_map, gk_map).await;

            if self.store.all_gone_for(resources) {
                break WatchWaitResult::AllGone;
            }

            let summary = self.store.summary_for(resources);

            if summary.unknown > 0 {
                consecutive_unknown_cycles += 1;
                if consecutive_unknown_cycles >= MAX_UNKNOWN_RETRIES {
                    break self.build_stalled_result(
                        resources,
                        format!(
                            "{} resource(s) unreachable after {} retries",
                            summary.unknown, MAX_UNKNOWN_RETRIES
                        ),
                    );
                }
                tokio::time::sleep(Duration::from_secs(5)).await;
                continue;
            }
            consecutive_unknown_cycles = 0;

            if self
                .store
                .any_meaningful_progress_since(last_progress_check, resources)
            {
                last_progress_check = Instant::now();
            }

            if start.elapsed() >= timeout {
                break self.build_stalled_result(
                    resources,
                    format!("timeout after {}s", start.elapsed().as_secs()),
                );
            }

            if last_progress_check.elapsed() >= stall_timeout {
                let has_stuck = summary.deleting > 0
                    || summary.finalizer_blocked > 0
                    || summary.stalled > 0;
                if has_stuck {
                    break self.build_stalled_result(
                        resources,
                        format!(
                            "no meaningful progress for {}s — {} Deleting, {} FinalizerBlocked",
                            last_progress_check.elapsed().as_secs(),
                            summary.deleting,
                            summary.finalizer_blocked,
                        ),
                    );
                }
            }

            // Wait for WATCH hint or polling interval
            let mut rx = self.store.subscribe();
            tokio::select! {
                _ = rx.changed() => {
                    // WATCH hint received — re-check immediately
                }
                _ = tokio::time::sleep(Duration::from_secs(5)) => {
                    // Periodic safety reconcile
                }
            }
        };

        for handle in watch_handles {
            handle.abort();
        }

        result
    }

    fn start_watch_tasks(
        &self,
        client: &Client,
        resources: &[ResourceId],
        kind_map: &KindMap,
        gk_map: &GroupKindMap,
    ) -> Vec<JoinHandle<()>> {
        let mut groups: HashMap<(String, String, String, Option<String>), Vec<ResourceId>> =
            HashMap::new();
        for res in resources {
            let key = (
                res.group.clone(),
                res.version.clone(),
                res.kind.clone(),
                res.namespace.clone(),
            );
            groups.entry(key).or_default().push(res.clone());
        }

        let mut handles = Vec::new();
        for ((group, version, kind, namespace), tracked_resources) in groups {
            let sample = &tracked_resources[0];
            let resolved = resolve_api(client, sample, kind_map, gk_map);
            if resolved.is_none() {
                continue;
            }
            let (api, _) = resolved.unwrap();

            let store = self.store.clone();
            let stream_id_counter = self.next_stream_id.clone();

            let handle = tokio::spawn(async move {
                run_watch_loop(
                    api,
                    &group,
                    &version,
                    &kind,
                    namespace.as_deref(),
                    &tracked_resources,
                    store,
                    stream_id_counter,
                )
                .await;
            });
            handles.push(handle);
        }
        handles
    }

    fn build_stalled_result(
        &self,
        resources: &[ResourceId],
        reason: String,
    ) -> WatchWaitResult {
        let snapshot = self.store.snapshot();
        let remaining: Vec<_> = snapshot
            .iter()
            .filter(|e| {
                resources.iter().any(|r| {
                    r.group == e.resource.group
                        && r.kind == e.resource.kind
                        && r.name == e.resource.name
                        && r.namespace == e.resource.namespace
                })
            })
            .filter(|e| e.state != ResourceRuntimeState::Gone)
            .map(|e| e.resource.clone())
            .collect();
        let finalizer_details: Vec<_> = snapshot
            .iter()
            .filter(|e| {
                resources.iter().any(|r| {
                    r.group == e.resource.group
                        && r.kind == e.resource.kind
                        && r.name == e.resource.name
                        && r.namespace == e.resource.namespace
                }) && e.finalizer_count > 0
            })
            .map(|e| (e.resource.clone(), e.finalizer_count))
            .collect();
        WatchWaitResult::Stalled {
            remaining,
            finalizer_details,
            reason,
        }
    }
}

// ──────────────────────────────────────────────────────────────
//  Resource observation (GET-based, authoritative)
// ──────────────────────────────────────────────────────────────

enum ObserveResult {
    Observation(RuntimeObservation),
    ApiError(String),
    Unresolvable(String),
}

/// Run a WATCH loop for a single (GVR, namespace) group.
///
/// WATCH events are NON-AUTHORITATIVE:
///   - Deleted → sets needs_verification (hint for barrier to re-GET)
///   - UID change → sets needs_verification
///   - Matching UID + state change → updates deletionTimestamp/finalizer
///
/// Each reconnection gets a new stream_id to reject old-stream events.
async fn run_watch_loop(
    api: Api<DynamicObject>,
    group: &str,
    version: &str,
    kind: &str,
    namespace: Option<&str>,
    tracked_resources: &[ResourceId],
    store: Arc<RuntimeStateStore>,
    stream_id_counter: Arc<AtomicU64>,
) {
    let tracked_names: std::collections::HashSet<String> = tracked_resources
        .iter()
        .map(|r| r.name.clone())
        .collect();

    loop {
        // Each reconnection gets a new stream_id
        let stream_id = stream_id_counter.fetch_add(1, Ordering::SeqCst) + 1;

        // LIST to get initial resourceVersion
        let rv = match api.list(&ListParams::default()).await {
            Ok(list) => {
                // Initial LIST results are authoritative
                for obj in &list.items {
                    let name = match &obj.metadata.name {
                        Some(n) if tracked_names.contains(n.as_str()) => n,
                        _ => continue,
                    };
                    let resource = ResourceId {
                        group: group.to_string(),
                        version: version.to_string(),
                        kind: kind.to_string(),
                        namespace: namespace.map(String::from),
                        name: name.clone(),
                        uid: obj.metadata.uid.clone(),
                    };
                    let obs = RuntimeObservation {
                        exists: true,
                        uid: obj.metadata.uid.clone(),
                        has_deletion_timestamp: obj.metadata.deletion_timestamp.is_some(),
                        finalizer_count: obj
                            .metadata
                            .finalizers
                            .as_ref()
                            .map_or(0, |f| f.len()),
                        authoritative: true,
                    };
                    // Authoritative → stream_id=0 (always accepted)
                    store.update_from_observation(&resource, obs, 0);
                }
                list.metadata.resource_version.unwrap_or_default()
            }
            Err(_) => {
                tokio::time::sleep(Duration::from_secs(10)).await;
                continue;
            }
        };

        // Start WATCH from resourceVersion
        let wp = kube::api::WatchParams::default().timeout(WATCH_TIMEOUT_SECS);
        let watch_stream = match api.watch(&wp, &rv).await {
            Ok(s) => s,
            Err(_) => {
                tokio::time::sleep(Duration::from_secs(5)).await;
                continue;
            }
        };

        let mut stream = watch_stream.boxed();

        while let Some(event) = stream.next().await {
            match event {
                Ok(kube::api::WatchEvent::Added(obj))
                | Ok(kube::api::WatchEvent::Modified(obj)) => {
                    let name = match &obj.metadata.name {
                        Some(n) if tracked_names.contains(n.as_str()) => n,
                        _ => continue,
                    };
                    let resource = ResourceId {
                        group: group.to_string(),
                        version: version.to_string(),
                        kind: kind.to_string(),
                        namespace: namespace.map(String::from),
                        name: name.clone(),
                        uid: obj.metadata.uid.clone(),
                    };
                    let obs = RuntimeObservation {
                        exists: true,
                        uid: obj.metadata.uid.clone(),
                        has_deletion_timestamp: obj.metadata.deletion_timestamp.is_some(),
                        finalizer_count: obj
                            .metadata
                            .finalizers
                            .as_ref()
                            .map_or(0, |f| f.len()),
                        authoritative: false, // WATCH is non-authoritative
                    };
                    store.update_from_observation(&resource, obs, stream_id);
                }
                Ok(kube::api::WatchEvent::Deleted(obj)) => {
                    let name = match &obj.metadata.name {
                        Some(n) if tracked_names.contains(n.as_str()) => n,
                        _ => continue,
                    };
                    let resource = ResourceId {
                        group: group.to_string(),
                        version: version.to_string(),
                        kind: kind.to_string(),
                        namespace: namespace.map(String::from),
                        name: name.clone(),
                        uid: obj.metadata.uid.clone(),
                    };
                    let obs = RuntimeObservation {
                        exists: false,
                        uid: obj.metadata.uid.clone(),
                        has_deletion_timestamp: false,
                        finalizer_count: 0,
                        authoritative: false, // WATCH Deleted = hint, not Gone
                    };
                    store.update_from_observation(&resource, obs, stream_id);
                }
                Ok(kube::api::WatchEvent::Error(err)) => {
                    if err.code == 410 {
                        // 410 Gone — resourceVersion too old, re-LIST
                        break;
                    }
                    break;
                }
                Ok(kube::api::WatchEvent::Bookmark(_)) => {}
                Err(_) => {
                    break;
                }
            }
        }

        // Disconnected — new stream_id on next loop iteration
        tokio::time::sleep(Duration::from_secs(1)).await;
    }
}

/// Observe a single resource via authoritative GET.
///
/// 404 → verify endpoint via LIST(limit=1):
///   - LIST success → resource genuinely absent (exists=false)
///   - LIST failure → API endpoint may be gone → ApiError (NOT Gone)
/// 403/timeout/transport → ApiError (NOT Gone).
async fn observe_resource(
    client: &Client,
    resource: &ResourceId,
    kind_map: &KindMap,
    gk_map: &GroupKindMap,
) -> ObserveResult {
    let (api, _) = match resolve_api(client, resource, kind_map, gk_map) {
        Some(r) => r,
        None => {
            return ObserveResult::Unresolvable(format!(
                "cannot resolve API for {}/{}",
                resource.kind, resource.name
            ));
        }
    };

    match api.get(&resource.name).await {
        Ok(obj) => ObserveResult::Observation(RuntimeObservation {
            exists: true,
            uid: obj.metadata.uid,
            has_deletion_timestamp: obj.metadata.deletion_timestamp.is_some(),
            finalizer_count: obj.metadata.finalizers.as_ref().map_or(0, |f| f.len()),
            authoritative: true,
        }),
        Err(kube::Error::Api(err)) if err.code == 404 => {
            match api.list(&kube::api::ListParams::default().limit(1)).await {
                Ok(_) => ObserveResult::Observation(RuntimeObservation {
                    exists: false,
                    uid: None,
                    has_deletion_timestamp: false,
                    finalizer_count: 0,
                    authoritative: true,
                }),
                Err(_) => ObserveResult::ApiError(format!(
                    "GET 404 but endpoint verification failed for {}/{} — \
                     cannot distinguish object absence from endpoint absence",
                    resource.kind, resource.name
                )),
            }
        }
        Err(e) => ObserveResult::ApiError(format!("GET failed: {}", e)),
    }
}
