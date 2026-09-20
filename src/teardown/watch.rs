use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use futures::stream::StreamExt;
use futures::TryStreamExt;
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
//  Watch manager — epoch-based reconciliation
// ──────────────────────────────────────────────────────────────

/// Manages resource state reconciliation via parallel GETs.
///
/// Each reconciliation cycle increments the epoch. RuntimeStateStore
/// ignores observations from older epochs, preventing stale late events
/// from reverting current state.
///
/// Safety: The watch manager NEVER calls delete/mutation APIs. It only
/// observes via GET and reports to the store. The store itself also has
/// no mutation methods.
pub struct WatchManager {
    epoch: Arc<AtomicU64>,
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
            epoch: Arc::new(AtomicU64::new(0)),
            store,
        }
    }

    /// Reconcile all tracked resources via parallel GETs.
    ///
    /// Increments epoch before reconciliation. Results from this cycle
    /// are tagged with the new epoch, so old-epoch observations in the
    /// store are automatically superseded.
    ///
    /// API failures (403, timeout, transport) → Unknown, NOT Gone.
    pub async fn reconcile(
        &self,
        client: &Client,
        resources: &[ResourceId],
        kind_map: &KindMap,
        gk_map: &GroupKindMap,
    ) {
        let current_epoch = self.epoch.fetch_add(1, Ordering::SeqCst) + 1;

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
                    self.store.update_from_observation(&resource, o, current_epoch);
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
    /// Uses Kubernetes WATCH for low-latency state updates, with periodic
    /// authoritative GET reconciliation as safety fallback.
    ///
    /// WATCH events are non-authoritative (authoritative: false) and cannot
    /// revive a Gone resource. GET reconciliation is authoritative.
    ///
    /// Returns AllGone or Stalled (with remaining resources and reason).
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

        let summary = self.store.summary_for(resources);
        if summary.gone == summary.total {
            return WatchWaitResult::AllGone;
        }

        // Start background WATCH tasks per (GVR, namespace) for low-latency updates.
        // WATCH events are non-authoritative and feed into the store.
        let watch_handles = self.start_watch_tasks(client, resources, kind_map, gk_map);

        let start = Instant::now();
        let mut last_progress_check = Instant::now();

        let mut consecutive_unknown_cycles = 0u32;
        const MAX_UNKNOWN_RETRIES: u32 = 3;

        let result = loop {
            self.reconcile(client, resources, kind_map, gk_map).await;

            let summary = self.store.summary_for(resources);

            // Handle unknown/unreachable resources
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

            // Check if all gone
            if summary.gone == summary.total {
                break WatchWaitResult::AllGone;
            }

            // Use store's meaningful progress tracking (covers finalizer
            // decrease, state transitions, Gone — not just Gone count)
            if self
                .store
                .any_meaningful_progress_since(last_progress_check, resources)
            {
                last_progress_check = Instant::now();
            }

            // Timeout checks
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

            // Wait with WATCH-based notification or polling fallback
            let mut rx = self.store.subscribe();
            tokio::select! {
                _ = rx.changed() => {
                    // State changed via WATCH — re-check immediately
                }
                _ = tokio::time::sleep(Duration::from_secs(5)) => {
                    // Periodic authoritative GET reconciliation (safety fallback)
                }
            }
        };

        // Cleanup: cancel all background WATCH tasks
        for handle in watch_handles {
            handle.abort();
        }

        result
    }

    /// Start background WATCH tasks per (GVR, namespace) group.
    /// WATCH events are non-authoritative (authoritative: false).
    /// Each task runs until cancelled, handling disconnect/410 by re-LISTing.
    fn start_watch_tasks(
        &self,
        client: &Client,
        resources: &[ResourceId],
        kind_map: &KindMap,
        gk_map: &GroupKindMap,
    ) -> Vec<JoinHandle<()>> {
        // Group resources by (group, version, kind, namespace) for shared watches
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
            // Try to resolve the API
            let sample = &tracked_resources[0];
            let resolved = resolve_api(client, sample, kind_map, gk_map);
            if resolved.is_none() {
                continue; // Can't watch what we can't resolve
            }
            let (api, _) = resolved.unwrap();

            let store = self.store.clone();
            let epoch = self.epoch.clone();

            let handle = tokio::spawn(async move {
                run_watch_loop(api, &group, &version, &kind, namespace.as_deref(), &tracked_resources, store, epoch).await;
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

    pub fn current_epoch(&self) -> u64 {
        self.epoch.load(Ordering::SeqCst)
    }
}

// ──────────────────────────────────────────────────────────────
//  Resource observation (GET-based)
// ──────────────────────────────────────────────────────────────

enum ObserveResult {
    Observation(RuntimeObservation),
    ApiError(String),
    Unresolvable(String),
}

/// Run a WATCH loop for a single (GVR, namespace) group.
/// Handles disconnect/410 by incrementing epoch and re-LISTing.
/// WATCH events are non-authoritative (authoritative: false).
async fn run_watch_loop(
    api: Api<DynamicObject>,
    group: &str,
    version: &str,
    kind: &str,
    namespace: Option<&str>,
    tracked_resources: &[ResourceId],
    store: Arc<RuntimeStateStore>,
    epoch_counter: Arc<AtomicU64>,
) {
    let tracked_names: std::collections::HashSet<String> = tracked_resources
        .iter()
        .map(|r| r.name.clone())
        .collect();

    loop {
        // LIST to get initial resourceVersion
        let rv = match api.list(&ListParams::default()).await {
            Ok(list) => {
                // Process initial LIST results as authoritative
                let current_epoch = epoch_counter.fetch_add(1, Ordering::SeqCst) + 1;
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
                    store.update_from_observation(&resource, obs, current_epoch);
                }
                list.metadata.resource_version.unwrap_or_default()
            }
            Err(_) => {
                // LIST failed — wait and retry
                tokio::time::sleep(Duration::from_secs(10)).await;
                continue;
            }
        };

        // Start WATCH from the resourceVersion
        let wp = kube::api::WatchParams::default().timeout(WATCH_TIMEOUT_SECS);
        let watch_stream = match api.watch(&wp, &rv).await {
            Ok(s) => s,
            Err(_) => {
                tokio::time::sleep(Duration::from_secs(5)).await;
                continue;
            }
        };

        let watch_epoch = epoch_counter.load(Ordering::SeqCst);
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
                    // WATCH events are non-authoritative
                    let obs = RuntimeObservation {
                        exists: true,
                        uid: obj.metadata.uid.clone(),
                        has_deletion_timestamp: obj.metadata.deletion_timestamp.is_some(),
                        finalizer_count: obj
                            .metadata
                            .finalizers
                            .as_ref()
                            .map_or(0, |f| f.len()),
                        authoritative: false,
                    };
                    store.update_from_observation(&resource, obs, watch_epoch);
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
                    // Deleted events from WATCH are reliable (the API confirmed deletion)
                    let obs = RuntimeObservation {
                        exists: false,
                        uid: None,
                        has_deletion_timestamp: false,
                        finalizer_count: 0,
                        authoritative: false,
                    };
                    store.update_from_observation(&resource, obs, watch_epoch);
                }
                Ok(kube::api::WatchEvent::Error(err)) => {
                    if err.code == 410 {
                        // 410 Gone — resourceVersion too old, need to re-LIST
                        break;
                    }
                    // Other errors — break and retry
                    break;
                }
                Ok(kube::api::WatchEvent::Bookmark(_)) => {
                    // Bookmark — no action needed
                }
                Err(_) => {
                    // Stream error — disconnect, will re-LIST
                    break;
                }
            }
        }

        // WATCH disconnected or 410 — epoch increment + re-LIST on next iteration
        tokio::time::sleep(Duration::from_secs(1)).await;
    }
}

/// Observe a single resource via authoritative GET.
///
/// 404 → verify endpoint via LIST(limit=1) first:
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
            // Verify endpoint exists via LIST(limit=1) to distinguish
            // "object absent" from "API endpoint absent (CRD removed)"
            match api.list(&kube::api::ListParams::default().limit(1)).await {
                Ok(_) => {
                    // Endpoint exists, resource genuinely absent
                    ObserveResult::Observation(RuntimeObservation {
                        exists: false,
                        uid: None,
                        has_deletion_timestamp: false,
                        finalizer_count: 0,
                        authoritative: true,
                    })
                }
                Err(_) => {
                    // Endpoint verification failed — API may be gone
                    ObserveResult::ApiError(format!(
                        "GET 404 but endpoint verification failed for {}/{} — \
                         cannot distinguish object absence from endpoint absence",
                        resource.kind, resource.name
                    ))
                }
            }
        }
        Err(e) => ObserveResult::ApiError(format!("GET failed: {}", e)),
    }
}
