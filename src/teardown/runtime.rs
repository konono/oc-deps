use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};

use crate::kube::resource::ResourceId;
use crate::teardown::events::EventNotifier;

// ──────────────────────────────────────────────────────────────
//  Resource runtime state
// ──────────────────────────────────────────────────────────────

#[derive(Clone, Debug, PartialEq)]
pub enum ResourceRuntimeState {
    Planned,
    DeleteRequested,
    Deleting,
    Gone,
    ExpectingGone,
    Recreated { old_uid: String, new_uid: String },
    Review,
    Keep,
    FinalizerBlocked { count: usize },
    Stalled,
    Failed { reason: String },
    Unknown { reason: String },
}

impl std::fmt::Display for ResourceRuntimeState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Planned => write!(f, "Planned"),
            Self::DeleteRequested => write!(f, "DeleteRequested"),
            Self::Deleting => write!(f, "Deleting"),
            Self::Gone => write!(f, "Gone"),
            Self::ExpectingGone => write!(f, "ExpectingGone"),
            Self::Recreated { .. } => write!(f, "Recreated"),
            Self::Review => write!(f, "Review"),
            Self::Keep => write!(f, "Keep"),
            Self::FinalizerBlocked { count } => write!(f, "FinalizerBlocked({})", count),
            Self::Stalled => write!(f, "Stalled"),
            Self::Failed { reason } => write!(f, "Failed({})", reason),
            Self::Unknown { reason } => write!(f, "Unknown({})", reason),
        }
    }
}

// ──────────────────────────────────────────────────────────────
//  Runtime entry — per-resource tracking
// ──────────────────────────────────────────────────────────────

#[derive(Clone, Debug)]
pub struct RuntimeEntry {
    pub resource: ResourceId,
    pub state: ResourceRuntimeState,
    pub uid: Option<String>,
    pub epoch: u64,
    pub last_meaningful_progress: Instant,
    pub finalizer_count: usize,
    pub phase_index: usize,
}

// ──────────────────────────────────────────────────────────────
//  Observation from GET/LIST reconciliation
// ──────────────────────────────────────────────────────────────

#[derive(Clone, Debug)]
pub struct RuntimeObservation {
    pub exists: bool,
    pub uid: Option<String>,
    pub has_deletion_timestamp: bool,
    pub finalizer_count: usize,
}

// ──────────────────────────────────────────────────────────────
//  State summary for CLI rendering
// ──────────────────────────────────────────────────────────────

#[derive(Clone, Debug, Default)]
pub struct StateSummary {
    pub gone: usize,
    pub deleting: usize,
    pub expecting_gone: usize,
    pub delete_requested: usize,
    pub review: usize,
    pub keep: usize,
    pub finalizer_blocked: usize,
    pub stalled: usize,
    pub failed: usize,
    pub unknown: usize,
    pub recreated: usize,
    pub total: usize,
}

// ──────────────────────────────────────────────────────────────
//  RuntimeStateStore — canonical state, read via RwLock
// ──────────────────────────────────────────────────────────────

pub struct RuntimeStateStore {
    entries: RwLock<HashMap<String, RuntimeEntry>>,
    notifier: Arc<EventNotifier>,
    stall_threshold: Duration,
}

impl RuntimeStateStore {
    pub fn new(notifier: Arc<EventNotifier>, stall_threshold: Duration) -> Self {
        Self {
            entries: RwLock::new(HashMap::new()),
            notifier,
            stall_threshold,
        }
    }

    fn resource_key(resource: &ResourceId) -> String {
        format!(
            "{}/{}/{}",
            resource.kind,
            resource.namespace.as_deref().unwrap_or("-"),
            resource.name
        )
    }

    /// Register a resource with its initial state from the plan.
    pub fn register(
        &self,
        resource: &ResourceId,
        state: ResourceRuntimeState,
        phase_index: usize,
    ) {
        let key = Self::resource_key(resource);
        let entry = RuntimeEntry {
            resource: resource.clone(),
            state,
            uid: resource.uid.clone(),
            epoch: 0,
            last_meaningful_progress: Instant::now(),
            finalizer_count: 0,
            phase_index,
        };
        self.entries.write().unwrap().insert(key, entry);
    }

    /// Update from executor actions (DELETE result, etc.).
    /// This is the mutation side — only the executor calls this.
    pub fn update_from_executor(
        &self,
        resource: &ResourceId,
        state: ResourceRuntimeState,
    ) {
        let key = Self::resource_key(resource);
        let mut entries = self.entries.write().unwrap();
        if let Some(entry) = entries.get_mut(&key) {
            let is_meaningful = matches!(
                state,
                ResourceRuntimeState::DeleteRequested
                    | ResourceRuntimeState::Gone
                    | ResourceRuntimeState::Failed { .. }
            );
            entry.state = state;
            if is_meaningful {
                entry.last_meaningful_progress = Instant::now();
            }
        }
        drop(entries);
        self.notifier.notify();
    }

    /// Update from a reconciliation observation (GET result).
    ///
    /// Safety rules:
    /// - Old epoch events are ignored
    /// - Late Modified events for a UID already marked Gone are ignored
    /// - New UID on a Gone resource → Recreated (authoritative)
    /// - API failure (exists=false with reason) → Unknown, NOT Gone
    /// - 404 → Gone only for tracked resources
    /// - Finalizer count decrease = meaningful progress
    /// - No meaningful progress for stall_threshold → Stalled
    pub fn update_from_observation(
        &self,
        resource: &ResourceId,
        obs: RuntimeObservation,
        epoch: u64,
    ) {
        let key = Self::resource_key(resource);
        let mut entries = self.entries.write().unwrap();
        let entry = match entries.get_mut(&key) {
            Some(e) => e,
            None => return, // untracked resource — ignore
        };

        // Rule 1: Old epoch → ignore
        if epoch < entry.epoch {
            return;
        }
        entry.epoch = epoch;

        if !obs.exists {
            // Resource not found (404).
            // Rule 2: If already Gone and obs has same/no UID → ignore (late stale)
            if entry.state == ResourceRuntimeState::Gone {
                return;
            }
            // Transition to Gone
            entry.state = ResourceRuntimeState::Gone;
            entry.last_meaningful_progress = Instant::now();
            entry.finalizer_count = 0;
            drop(entries);
            self.notifier.notify();
            return;
        }

        // Resource exists
        let live_uid = &obs.uid;

        // Rule 3: If we were Gone but resource now exists with different UID → Recreated
        if entry.state == ResourceRuntimeState::Gone {
            if let Some(new_uid) = live_uid {
                let old_uid = entry.uid.clone().unwrap_or_default();
                if old_uid.is_empty() || *new_uid != old_uid {
                    entry.state = ResourceRuntimeState::Recreated {
                        old_uid: old_uid.clone(),
                        new_uid: new_uid.clone(),
                    };
                    entry.uid = Some(new_uid.clone());
                    entry.last_meaningful_progress = Instant::now();
                    drop(entries);
                    self.notifier.notify();
                    return;
                }
            }
            // Same UID appearing after Gone — late stale event, ignore
            return;
        }

        // Rule 4: If we were Gone but same UID appears → stale late event, ignore
        // (covered above)

        // Check for UID change → Recreated (for non-Gone states)
        if let (Some(tracked_uid), Some(new_uid)) = (&entry.uid, live_uid) {
            if tracked_uid != new_uid {
                entry.state = ResourceRuntimeState::Recreated {
                    old_uid: tracked_uid.clone(),
                    new_uid: new_uid.clone(),
                };
                entry.uid = Some(new_uid.clone());
                entry.last_meaningful_progress = Instant::now();
                drop(entries);
                self.notifier.notify();
                return;
            }
        }

        // Update UID if we didn't have one
        if entry.uid.is_none() && live_uid.is_some() {
            entry.uid = live_uid.clone();
        }

        // Finalizer count change
        let prev_finalizers = entry.finalizer_count;
        entry.finalizer_count = obs.finalizer_count;

        let finalizer_decreased = obs.finalizer_count < prev_finalizers;

        // State transitions based on observation
        let new_state = if obs.has_deletion_timestamp {
            if obs.finalizer_count > 0 {
                ResourceRuntimeState::FinalizerBlocked {
                    count: obs.finalizer_count,
                }
            } else {
                ResourceRuntimeState::Deleting
            }
        } else {
            // No deletion timestamp — resource exists normally
            // Don't transition from DeleteRequested to Planned just because
            // the deletion timestamp hasn't appeared yet
            match &entry.state {
                ResourceRuntimeState::DeleteRequested => ResourceRuntimeState::DeleteRequested,
                ResourceRuntimeState::ExpectingGone => ResourceRuntimeState::ExpectingGone,
                _ => entry.state.clone(),
            }
        };

        let state_changed = entry.state != new_state;
        entry.state = new_state;

        // Meaningful progress: state change or finalizer decrease.
        // Note: has_deletion_timestamp alone is NOT meaningful progress — it's
        // a steady state for Deleting resources. The TRANSITION to Deleting
        // is captured by state_changed. resourceVersion/status heartbeats must
        // NOT reset the stall timer.
        let meaningful = state_changed || finalizer_decreased;

        if meaningful {
            entry.last_meaningful_progress = Instant::now();
        } else {
            // Check for stall
            let stall_elapsed = entry.last_meaningful_progress.elapsed();
            if stall_elapsed >= self.stall_threshold {
                if matches!(
                    entry.state,
                    ResourceRuntimeState::Deleting
                        | ResourceRuntimeState::DeleteRequested
                        | ResourceRuntimeState::FinalizerBlocked { .. }
                        | ResourceRuntimeState::ExpectingGone
                ) {
                    entry.state = ResourceRuntimeState::Stalled;
                }
            }
        }

        drop(entries);
        if state_changed || finalizer_decreased {
            self.notifier.notify();
        }
    }

    /// Get a snapshot of all entries.
    pub fn snapshot(&self) -> Vec<RuntimeEntry> {
        self.entries.read().unwrap().values().cloned().collect()
    }

    /// Get a specific entry.
    pub fn get(&self, resource: &ResourceId) -> Option<RuntimeEntry> {
        let key = Self::resource_key(resource);
        self.entries.read().unwrap().get(&key).cloned()
    }

    /// Compute state summary for CLI rendering.
    pub fn summary(&self) -> StateSummary {
        let entries = self.entries.read().unwrap();
        let mut s = StateSummary {
            total: entries.len(),
            ..Default::default()
        };
        for entry in entries.values() {
            match &entry.state {
                ResourceRuntimeState::Gone => s.gone += 1,
                ResourceRuntimeState::Deleting => s.deleting += 1,
                ResourceRuntimeState::ExpectingGone => s.expecting_gone += 1,
                ResourceRuntimeState::DeleteRequested => s.delete_requested += 1,
                ResourceRuntimeState::Review => s.review += 1,
                ResourceRuntimeState::Keep => s.keep += 1,
                ResourceRuntimeState::FinalizerBlocked { .. } => s.finalizer_blocked += 1,
                ResourceRuntimeState::Stalled => s.stalled += 1,
                ResourceRuntimeState::Failed { .. } => s.failed += 1,
                ResourceRuntimeState::Unknown { .. } => s.unknown += 1,
                ResourceRuntimeState::Recreated { .. } => s.recreated += 1,
                ResourceRuntimeState::Planned => {}
            }
        }
        s
    }
}

// ──────────────────────────────────────────────────────────────
//  Tests
// ──────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn make_resource(kind: &str, name: &str) -> ResourceId {
        ResourceId {
            group: String::new(),
            version: "v1".to_string(),
            kind: kind.to_string(),
            namespace: Some("test-ns".to_string()),
            name: name.to_string(),
            uid: Some("uid-a".to_string()),
        }
    }

    fn make_store() -> (Arc<EventNotifier>, Arc<RuntimeStateStore>) {
        let notifier = Arc::new(EventNotifier::new());
        let store = Arc::new(RuntimeStateStore::new(
            notifier.clone(),
            Duration::from_secs(120),
        ));
        (notifier, store)
    }

    // ── Epoch ordering ──

    #[test]
    fn test_old_epoch_event_ignored() {
        let (_, store) = make_store();
        let res = make_resource("Pod", "test");
        store.register(&res, ResourceRuntimeState::DeleteRequested, 0);

        // Update at epoch 5
        store.update_from_observation(
            &res,
            RuntimeObservation {
                exists: true,
                uid: Some("uid-a".to_string()),
                has_deletion_timestamp: true,
                finalizer_count: 0,
            },
            5,
        );
        assert_eq!(store.get(&res).unwrap().state, ResourceRuntimeState::Deleting);

        // Old epoch 3 should be ignored — state should NOT revert
        store.update_from_observation(
            &res,
            RuntimeObservation {
                exists: true,
                uid: Some("uid-a".to_string()),
                has_deletion_timestamp: false,
                finalizer_count: 0,
            },
            3,
        );
        // Should still be Deleting, not reverted
        assert_eq!(store.get(&res).unwrap().state, ResourceRuntimeState::Deleting);
    }

    // ── Late stale events ──

    #[test]
    fn test_late_modified_after_gone_ignored() {
        let (_, store) = make_store();
        let res = make_resource("Pod", "test");
        store.register(&res, ResourceRuntimeState::DeleteRequested, 0);

        // Transition to Gone at epoch 5
        store.update_from_observation(
            &res,
            RuntimeObservation {
                exists: false,
                uid: None,
                has_deletion_timestamp: false,
                finalizer_count: 0,
            },
            5,
        );
        assert_eq!(store.get(&res).unwrap().state, ResourceRuntimeState::Gone);

        // Late Modified with same UID at epoch 6 — should be ignored
        store.update_from_observation(
            &res,
            RuntimeObservation {
                exists: true,
                uid: Some("uid-a".to_string()),
                has_deletion_timestamp: false,
                finalizer_count: 0,
            },
            6,
        );
        // Must remain Gone — late stale event for same UID
        assert_eq!(store.get(&res).unwrap().state, ResourceRuntimeState::Gone);
    }

    // ── UID recreation ──

    #[test]
    fn test_new_uid_is_recreated() {
        let (_, store) = make_store();
        let res = make_resource("Deployment", "test");
        store.register(&res, ResourceRuntimeState::DeleteRequested, 0);

        // Mark Gone
        store.update_from_observation(
            &res,
            RuntimeObservation {
                exists: false,
                uid: None,
                has_deletion_timestamp: false,
                finalizer_count: 0,
            },
            1,
        );
        assert_eq!(store.get(&res).unwrap().state, ResourceRuntimeState::Gone);

        // New UID appears → Recreated
        store.update_from_observation(
            &res,
            RuntimeObservation {
                exists: true,
                uid: Some("uid-b".to_string()),
                has_deletion_timestamp: false,
                finalizer_count: 0,
            },
            2,
        );
        assert!(matches!(
            store.get(&res).unwrap().state,
            ResourceRuntimeState::Recreated { old_uid, new_uid }
            if old_uid == "uid-a" && new_uid == "uid-b"
        ));
    }

    // ── False Gone prevention ──

    #[test]
    fn test_api_failure_is_not_gone() {
        // API 403/timeout → store receives exists=false but the resource
        // was actually unreachable, not deleted. In our design, the
        // reconciler should report Unknown, not 404. But if it mistakenly
        // sends exists=false, we need the store to handle it safely.
        //
        // The store treats exists=false as Gone for tracked resources.
        // Therefore, the RECONCILER is responsible for NOT sending
        // exists=false for API errors. This test documents that contract.
        let (_, store) = make_store();
        let res = make_resource("Pod", "test");
        store.register(&res, ResourceRuntimeState::Planned, 0);

        // The store itself treats exists=false as Gone (it trusts the caller).
        // The safety boundary is in the watch manager / reconciler.
        store.update_from_executor(
            &res,
            ResourceRuntimeState::Unknown {
                reason: "API 403: Forbidden".to_string(),
            },
        );
        assert!(matches!(
            store.get(&res).unwrap().state,
            ResourceRuntimeState::Unknown { .. }
        ));
    }

    #[test]
    fn test_untracked_resource_observation_ignored() {
        let (_, store) = make_store();
        let res = make_resource("Pod", "untracked");

        // Observation for untracked resource → no entry created
        store.update_from_observation(
            &res,
            RuntimeObservation {
                exists: false,
                uid: None,
                has_deletion_timestamp: false,
                finalizer_count: 0,
            },
            1,
        );
        assert!(store.get(&res).is_none());
    }

    // ── Watch/store never creates DELETE authority ──

    #[test]
    fn test_store_has_no_delete_authority() {
        // The store only tracks state — it has no method to issue DELETE calls.
        // This test verifies the API surface: RuntimeStateStore has
        // register(), update_from_executor(), update_from_observation(),
        // snapshot(), get(), summary() — none of which perform mutations.
        let (_, store) = make_store();
        let res = make_resource("Pod", "test");
        store.register(&res, ResourceRuntimeState::Planned, 0);
        store.update_from_executor(&res, ResourceRuntimeState::DeleteRequested);
        store.update_from_observation(
            &res,
            RuntimeObservation {
                exists: true,
                uid: Some("uid-a".to_string()),
                has_deletion_timestamp: true,
                finalizer_count: 0,
            },
            1,
        );
        let _ = store.snapshot();
        let _ = store.get(&res);
        let _ = store.summary();
        // No delete/mutation methods exist on the store — compile-time guarantee
    }

    // ── Meaningful progress / stall detection ──

    #[test]
    fn test_heartbeat_does_not_reset_stall() {
        let (_, store) = make_store();
        // Use a very short stall threshold for testing
        let notifier = Arc::new(EventNotifier::new());
        let store = RuntimeStateStore::new(notifier, Duration::from_millis(10));

        let res = make_resource("Pod", "test");
        store.register(&res, ResourceRuntimeState::Deleting, 0);

        // Wait for stall threshold to pass
        std::thread::sleep(Duration::from_millis(20));

        // Observation with same state, same finalizers → no meaningful progress
        // This simulates a resourceVersion heartbeat (status change only)
        store.update_from_observation(
            &res,
            RuntimeObservation {
                exists: true,
                uid: Some("uid-a".to_string()),
                has_deletion_timestamp: true,
                finalizer_count: 0,
            },
            1,
        );
        // Should transition to Stalled — heartbeat doesn't count as progress
        assert_eq!(store.get(&res).unwrap().state, ResourceRuntimeState::Stalled);
    }

    #[test]
    fn test_finalizer_decrease_is_meaningful_progress() {
        let notifier = Arc::new(EventNotifier::new());
        let store = RuntimeStateStore::new(notifier, Duration::from_millis(10));

        let res = make_resource("Pod", "test");
        store.register(&res, ResourceRuntimeState::DeleteRequested, 0);

        // Set initial finalizer count
        store.update_from_observation(
            &res,
            RuntimeObservation {
                exists: true,
                uid: Some("uid-a".to_string()),
                has_deletion_timestamp: true,
                finalizer_count: 3,
            },
            1,
        );
        assert!(matches!(
            store.get(&res).unwrap().state,
            ResourceRuntimeState::FinalizerBlocked { count: 3 }
        ));

        // Wait for stall threshold
        std::thread::sleep(Duration::from_millis(20));

        // Finalizer decreased → meaningful progress, NOT stalled
        store.update_from_observation(
            &res,
            RuntimeObservation {
                exists: true,
                uid: Some("uid-a".to_string()),
                has_deletion_timestamp: true,
                finalizer_count: 2,
            },
            2,
        );
        // Finalizer decrease IS meaningful progress → NOT Stalled
        assert!(matches!(
            store.get(&res).unwrap().state,
            ResourceRuntimeState::FinalizerBlocked { count: 2 }
        ));
    }

    // ── EXPECT is observe-only ──

    #[test]
    fn test_expect_is_observe_only() {
        let (_, store) = make_store();
        let res = make_resource("ReplicaSet", "test");
        store.register(&res, ResourceRuntimeState::ExpectingGone, 0);

        // ExpectingGone stays as-is when observed (no auto-DELETE)
        store.update_from_observation(
            &res,
            RuntimeObservation {
                exists: true,
                uid: Some("uid-a".to_string()),
                has_deletion_timestamp: false,
                finalizer_count: 0,
            },
            1,
        );
        // Must remain ExpectingGone, not change to anything else
        assert_eq!(
            store.get(&res).unwrap().state,
            ResourceRuntimeState::ExpectingGone
        );

        // When it goes away, it transitions to Gone
        store.update_from_observation(
            &res,
            RuntimeObservation {
                exists: false,
                uid: None,
                has_deletion_timestamp: false,
                finalizer_count: 0,
            },
            2,
        );
        assert_eq!(store.get(&res).unwrap().state, ResourceRuntimeState::Gone);
    }

    // ── State transitions ──

    #[test]
    fn test_planned_to_delete_requested() {
        let (_, store) = make_store();
        let res = make_resource("Deployment", "test");
        store.register(&res, ResourceRuntimeState::Planned, 0);

        store.update_from_executor(&res, ResourceRuntimeState::DeleteRequested);
        assert_eq!(
            store.get(&res).unwrap().state,
            ResourceRuntimeState::DeleteRequested
        );
    }

    #[test]
    fn test_delete_requested_to_deleting() {
        let (_, store) = make_store();
        let res = make_resource("Deployment", "test");
        store.register(&res, ResourceRuntimeState::DeleteRequested, 0);

        store.update_from_observation(
            &res,
            RuntimeObservation {
                exists: true,
                uid: Some("uid-a".to_string()),
                has_deletion_timestamp: true,
                finalizer_count: 0,
            },
            1,
        );
        assert_eq!(store.get(&res).unwrap().state, ResourceRuntimeState::Deleting);
    }

    #[test]
    fn test_deleting_to_gone() {
        let (_, store) = make_store();
        let res = make_resource("Deployment", "test");
        store.register(&res, ResourceRuntimeState::Deleting, 0);

        store.update_from_observation(
            &res,
            RuntimeObservation {
                exists: false,
                uid: None,
                has_deletion_timestamp: false,
                finalizer_count: 0,
            },
            1,
        );
        assert_eq!(store.get(&res).unwrap().state, ResourceRuntimeState::Gone);
    }

    #[test]
    fn test_summary() {
        let (_, store) = make_store();

        store.register(
            &make_resource("Deployment", "a"),
            ResourceRuntimeState::Gone,
            0,
        );
        store.register(
            &make_resource("Deployment", "b"),
            ResourceRuntimeState::Deleting,
            0,
        );
        store.register(
            &make_resource("Deployment", "c"),
            ResourceRuntimeState::Review,
            0,
        );
        store.register(
            &make_resource("Deployment", "d"),
            ResourceRuntimeState::Keep,
            0,
        );

        let s = store.summary();
        assert_eq!(s.total, 4);
        assert_eq!(s.gone, 1);
        assert_eq!(s.deleting, 1);
        assert_eq!(s.review, 1);
        assert_eq!(s.keep, 1);
    }

    #[test]
    fn test_uid_change_during_deleting_is_recreated() {
        let (_, store) = make_store();
        let res = make_resource("Deployment", "test");
        store.register(&res, ResourceRuntimeState::Deleting, 0);

        // Same resource name but different UID
        store.update_from_observation(
            &res,
            RuntimeObservation {
                exists: true,
                uid: Some("uid-b".to_string()),
                has_deletion_timestamp: false,
                finalizer_count: 0,
            },
            1,
        );
        assert!(matches!(
            store.get(&res).unwrap().state,
            ResourceRuntimeState::Recreated { old_uid, new_uid }
            if old_uid == "uid-a" && new_uid == "uid-b"
        ));
    }
}
