use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use futures::stream::StreamExt;
use kube::Client;

use crate::kube::discovery::{GroupKindMap, KindMap};
use crate::kube::resource::{ResourceId, resolve_api};
use crate::teardown::runtime::{ResourceRuntimeState, RuntimeObservation, RuntimeStateStore};

const RECONCILE_CONCURRENCY: usize = 16;

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
    epoch: AtomicU64,
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
            epoch: AtomicU64::new(0),
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

    /// Wait for all specified resources to reach Gone state, polling
    /// via reconcile cycles.
    ///
    /// Returns AllGone or Stalled (with remaining resources and reason).
    /// The CLI renderer can read the store between cycles for progress.
    pub async fn wait_for_gone(
        &self,
        client: &Client,
        resources: &[ResourceId],
        kind_map: &KindMap,
        gk_map: &GroupKindMap,
        timeout: Duration,
        stall_timeout: Duration,
    ) -> WatchWaitResult {
        let start = Instant::now();
        let mut last_progress = Instant::now();
        let mut prev_gone = 0usize;

        let mut consecutive_unknown_cycles = 0u32;
        const MAX_UNKNOWN_RETRIES: u32 = 3;

        loop {
            self.reconcile(client, resources, kind_map, gk_map).await;

            let snapshot = self.store.snapshot();
            let tracked: Vec<_> = snapshot
                .iter()
                .filter(|e| {
                    resources.iter().any(|r| {
                        r.kind == e.resource.kind
                            && r.name == e.resource.name
                            && r.namespace == e.resource.namespace
                    })
                })
                .collect();

            let gone = tracked
                .iter()
                .filter(|e| e.state == ResourceRuntimeState::Gone)
                .count();
            let unknown = tracked
                .iter()
                .filter(|e| matches!(e.state, ResourceRuntimeState::Unknown { .. }))
                .count();

            // Handle unknown/unreachable resources
            if unknown > 0 {
                consecutive_unknown_cycles += 1;
                if consecutive_unknown_cycles >= MAX_UNKNOWN_RETRIES {
                    let remaining: Vec<_> = tracked
                        .iter()
                        .filter(|e| e.state != ResourceRuntimeState::Gone)
                        .map(|e| e.resource.clone())
                        .collect();
                    let finalizer_details: Vec<_> = tracked
                        .iter()
                        .filter(|e| e.finalizer_count > 0)
                        .map(|e| (e.resource.clone(), e.finalizer_count))
                        .collect();
                    return WatchWaitResult::Stalled {
                        remaining,
                        finalizer_details,
                        reason: format!(
                            "{} resource(s) unreachable after {} retries",
                            unknown, MAX_UNKNOWN_RETRIES
                        ),
                    };
                }
                tokio::time::sleep(Duration::from_secs(5)).await;
                continue;
            }
            consecutive_unknown_cycles = 0;

            // Check if all gone
            if gone == resources.len() {
                return WatchWaitResult::AllGone;
            }

            // Progress tracking
            if gone > prev_gone {
                last_progress = Instant::now();
                prev_gone = gone;
            }

            // Timeout checks
            if start.elapsed() >= timeout {
                let remaining: Vec<_> = tracked
                    .iter()
                    .filter(|e| e.state != ResourceRuntimeState::Gone)
                    .map(|e| e.resource.clone())
                    .collect();
                let finalizer_details: Vec<_> = tracked
                    .iter()
                    .filter(|e| e.finalizer_count > 0)
                    .map(|e| (e.resource.clone(), e.finalizer_count))
                    .collect();
                return WatchWaitResult::Stalled {
                    remaining,
                    finalizer_details,
                    reason: format!("timeout after {}s", start.elapsed().as_secs()),
                };
            }

            if last_progress.elapsed() >= stall_timeout {
                let stalled: Vec<_> = tracked
                    .iter()
                    .filter(|e| e.state != ResourceRuntimeState::Gone)
                    .collect();
                let deleting_count = stalled
                    .iter()
                    .filter(|e| {
                        matches!(
                            e.state,
                            ResourceRuntimeState::Deleting
                                | ResourceRuntimeState::FinalizerBlocked { .. }
                        )
                    })
                    .count();
                if deleting_count > 0 {
                    let remaining: Vec<_> =
                        stalled.iter().map(|e| e.resource.clone()).collect();
                    let finalizer_details: Vec<_> = stalled
                        .iter()
                        .filter(|e| e.finalizer_count > 0)
                        .map(|e| (e.resource.clone(), e.finalizer_count))
                        .collect();
                    return WatchWaitResult::Stalled {
                        remaining,
                        finalizer_details,
                        reason: format!(
                            "no progress for {}s — {} resources stuck with finalizers",
                            last_progress.elapsed().as_secs(),
                            deleting_count
                        ),
                    };
                }
            }

            tokio::time::sleep(Duration::from_secs(5)).await;
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

/// Observe a single resource via GET.
///
/// 404 → exists=false (genuinely gone).
/// 403/timeout/transport → ApiError (NOT gone).
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
        }),
        Err(kube::Error::Api(err)) if err.code == 404 => {
            ObserveResult::Observation(RuntimeObservation {
                exists: false,
                uid: None,
                has_deletion_timestamp: false,
                finalizer_count: 0,
            })
        }
        Err(e) => ObserveResult::ApiError(format!("GET failed: {}", e)),
    }
}
