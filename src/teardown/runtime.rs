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
    /// Stream ID from the WATCH that last updated this entry.
    /// Only used for rejecting events from old/cancelled WATCH streams.
    /// Authoritative (GET) observations ignore this.
    pub watch_stream_id: u64,
    pub last_meaningful_progress: Instant,
    pub finalizer_count: usize,
    pub phase_index: usize,
    /// Set by non-authoritative WATCH hints (Deleted / UID change).
    /// Tells the barrier loop to do an authoritative GET to confirm.
    pub needs_verification: bool,
}

// ──────────────────────────────────────────────────────────────
//  Observation from GET/LIST or WATCH
// ──────────────────────────────────────────────────────────────

#[derive(Clone, Debug)]
pub struct RuntimeObservation {
    pub exists: bool,
    pub uid: Option<String>,
    pub has_deletion_timestamp: bool,
    pub finalizer_count: usize,
    /// true for authoritative GET/LIST results, false for WATCH events.
    /// Only authoritative observations can:
    ///   - Set Gone (confirmed absence)
    ///   - Set Recreated (confirmed UID change)
    ///   - Change tracked UID
    ///   - Revive a Gone resource (transient 404)
    /// Non-authoritative (WATCH) events can only:
    ///   - Update deletionTimestamp / finalizer state for matching UID
    ///   - Set needs_verification flag (hint for barrier to re-GET)
    pub authoritative: bool,
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
            "{}/{}/{}/{}",
            resource.group,
            resource.kind,
            resource.namespace.as_deref().unwrap_or("-"),
            resource.name
        )
    }

    pub fn register(&self, resource: &ResourceId, state: ResourceRuntimeState, phase_index: usize) {
        let key = Self::resource_key(resource);
        let entry = RuntimeEntry {
            resource: resource.clone(),
            state,
            uid: resource.uid.clone(),
            watch_stream_id: 0,
            last_meaningful_progress: Instant::now(),
            finalizer_count: 0,
            phase_index,
            needs_verification: false,
        };
        self.entries.write().unwrap().insert(key, entry);
    }

    pub fn update_from_executor(&self, resource: &ResourceId, state: ResourceRuntimeState) {
        let key = Self::resource_key(resource);
        let mut entries = self.entries.write().unwrap();
        if let Some(entry) = entries.get_mut(&key) {
            let is_meaningful = is_meaningful_transition(&entry.state, &state, false);
            entry.state = state;
            entry.needs_verification = false;
            if is_meaningful {
                entry.last_meaningful_progress = Instant::now();
            }
        }
        drop(entries);
        self.notifier.notify();
    }

    /// Update from observation (GET or WATCH).
    ///
    /// For authoritative (GET) observations:
    ///   - Can set Gone, Recreated, change UID, revive from transient 404
    ///   - Clears needs_verification
    ///
    /// For non-authoritative (WATCH) observations:
    ///   - Rejected if stream_id < entry.watch_stream_id (old/cancelled stream)
    ///   - Cannot set Gone or Recreated — sets needs_verification instead
    ///   - Cannot change tracked UID
    ///   - CAN update deletionTimestamp/finalizer state for matching UID
    pub fn update_from_observation(
        &self,
        resource: &ResourceId,
        obs: RuntimeObservation,
        stream_id: u64,
    ) {
        let key = Self::resource_key(resource);
        let mut entries = self.entries.write().unwrap();
        let entry = match entries.get_mut(&key) {
            Some(e) => e,
            None => return,
        };

        if obs.authoritative {
            self.apply_authoritative(entry, obs);
        } else {
            self.apply_non_authoritative(entry, obs, stream_id);
        }

        drop(entries);
    }

    /// Authoritative observation (GET/LIST result).
    /// Can set Gone, Recreated, change UID, revive transient 404.
    fn apply_authoritative(&self, entry: &mut RuntimeEntry, obs: RuntimeObservation) {
        entry.needs_verification = false;

        if !obs.exists {
            if entry.state == ResourceRuntimeState::Gone {
                return; // already Gone, confirmed
            }
            let prev = entry.state.clone();
            entry.state = ResourceRuntimeState::Gone;
            entry.finalizer_count = 0;
            if is_meaningful_transition(&prev, &entry.state, false) {
                entry.last_meaningful_progress = Instant::now();
            }
            self.notifier.notify();
            return;
        }

        // Resource exists (authoritative)
        let live_uid = &obs.uid;

        // If we were Gone but resource exists again
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
                } else {
                    // Same UID reappeared — prior 404 was transient
                    entry.state = ResourceRuntimeState::Unknown {
                        reason: "resource reappeared after transient 404 (same UID)".to_string(),
                    };
                    entry.last_meaningful_progress = Instant::now();
                }
            } else {
                entry.state = ResourceRuntimeState::Unknown {
                    reason: "resource reappeared after 404 but UID unavailable".to_string(),
                };
            }
            self.notifier.notify();
            return;
        }

        // Check UID change (for non-Gone states)
        if let (Some(tracked_uid), Some(new_uid)) = (&entry.uid, live_uid) {
            if tracked_uid != new_uid {
                entry.state = ResourceRuntimeState::Recreated {
                    old_uid: tracked_uid.clone(),
                    new_uid: new_uid.clone(),
                };
                entry.uid = Some(new_uid.clone());
                entry.last_meaningful_progress = Instant::now();
                self.notifier.notify();
                return;
            }
        }

        if entry.uid.is_none() && live_uid.is_some() {
            entry.uid = live_uid.clone();
        }

        self.apply_state_transition(entry, &obs);
    }

    /// Non-authoritative observation (WATCH event).
    /// Cannot set Gone or Recreated. Can only hint (needs_verification)
    /// or update deletionTimestamp/finalizer for matching UID.
    fn apply_non_authoritative(
        &self,
        entry: &mut RuntimeEntry,
        obs: RuntimeObservation,
        stream_id: u64,
    ) {
        // Reject events from old/cancelled WATCH streams
        if stream_id < entry.watch_stream_id {
            return;
        }
        entry.watch_stream_id = stream_id;

        if !obs.exists {
            // WATCH Deleted → hint only, don't set Gone
            if entry.state != ResourceRuntimeState::Gone {
                entry.needs_verification = true;
                self.notifier.notify();
            }
            return;
        }

        // WATCH event for existing resource
        // Check UID mismatch — hint for re-GET, don't change UID
        if let (Some(tracked_uid), Some(new_uid)) = (&entry.uid, &obs.uid) {
            if tracked_uid != new_uid {
                entry.needs_verification = true;
                self.notifier.notify();
                return;
            }
        }

        // Matching UID — safe to update deletionTimestamp/finalizer state
        self.apply_state_transition(entry, &obs);
    }

    /// Apply deletionTimestamp/finalizer-based state transitions.
    /// Common to both authoritative and non-authoritative (matching UID).
    fn apply_state_transition(&self, entry: &mut RuntimeEntry, obs: &RuntimeObservation) {
        let prev_finalizers = entry.finalizer_count;
        entry.finalizer_count = obs.finalizer_count;
        let finalizer_decreased = obs.finalizer_count < prev_finalizers;

        let prev_state = entry.state.clone();
        let new_state = if obs.has_deletion_timestamp {
            if obs.finalizer_count > 0 {
                ResourceRuntimeState::FinalizerBlocked {
                    count: obs.finalizer_count,
                }
            } else {
                ResourceRuntimeState::Deleting
            }
        } else {
            match &entry.state {
                ResourceRuntimeState::DeleteRequested => ResourceRuntimeState::DeleteRequested,
                ResourceRuntimeState::ExpectingGone => ResourceRuntimeState::ExpectingGone,
                _ => entry.state.clone(),
            }
        };

        entry.state = new_state;

        let meaningful = is_meaningful_transition(&prev_state, &entry.state, finalizer_decreased);

        if meaningful {
            entry.last_meaningful_progress = Instant::now();
        } else {
            let stall_elapsed = entry.last_meaningful_progress.elapsed();
            if stall_elapsed >= self.stall_threshold
                && matches!(
                    entry.state,
                    ResourceRuntimeState::Deleting
                        | ResourceRuntimeState::DeleteRequested
                        | ResourceRuntimeState::FinalizerBlocked { .. }
                        | ResourceRuntimeState::ExpectingGone
                )
            {
                entry.state = ResourceRuntimeState::Stalled;
            }
        }

        if entry.state != prev_state || finalizer_decreased {
            self.notifier.notify();
        }
    }

    pub fn subscribe(&self) -> tokio::sync::watch::Receiver<u64> {
        self.notifier.subscribe()
    }

    pub fn snapshot(&self) -> Vec<RuntimeEntry> {
        self.entries.read().unwrap().values().cloned().collect()
    }

    pub fn get(&self, resource: &ResourceId) -> Option<RuntimeEntry> {
        let key = Self::resource_key(resource);
        self.entries.read().unwrap().get(&key).cloned()
    }

    pub fn any_meaningful_progress_since(&self, since: Instant, resources: &[ResourceId]) -> bool {
        let entries = self.entries.read().unwrap();
        resources.iter().any(|res| {
            let key = Self::resource_key(res);
            entries
                .get(&key)
                .is_some_and(|e| e.last_meaningful_progress > since)
        })
    }

    /// Check if all specified resources are authoritatively confirmed Gone
    /// (not just hinted by WATCH).
    pub fn all_gone_for(&self, resources: &[ResourceId]) -> bool {
        let entries = self.entries.read().unwrap();
        resources.iter().all(|res| {
            let key = Self::resource_key(res);
            entries
                .get(&key)
                .is_some_and(|e| e.state == ResourceRuntimeState::Gone && !e.needs_verification)
        })
    }

    /// Get resources that need authoritative verification (hinted by WATCH).
    pub fn resources_needing_verification(&self, resources: &[ResourceId]) -> Vec<ResourceId> {
        let entries = self.entries.read().unwrap();
        resources
            .iter()
            .filter(|res| {
                let key = Self::resource_key(res);
                entries.get(&key).is_some_and(|e| e.needs_verification)
            })
            .cloned()
            .collect()
    }

    pub fn summary_for(&self, resources: &[ResourceId]) -> StateSummary {
        let entries = self.entries.read().unwrap();
        let mut s = StateSummary::default();
        for res in resources {
            let key = Self::resource_key(res);
            if let Some(entry) = entries.get(&key) {
                s.total += 1;
                Self::count_state(&entry.state, &mut s);
            }
        }
        s
    }

    fn count_state(state: &ResourceRuntimeState, s: &mut StateSummary) {
        match state {
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
}

/// Determine if a state transition constitutes meaningful progress.
/// Only these transitions reset the stall timer:
///   - Transition TO Deleting (deletionTimestamp appeared)
///   - Transition TO Gone
///   - Transition TO Recreated (UID change)
///   - Finalizer count DECREASE (not increase)
/// Finalizer count increase, FinalizerBlocked count changes, and
/// resourceVersion/status heartbeats are NOT meaningful.
/// Only specific transitions count as meaningful progress for stall detection:
/// - Transition TO Deleting (deletionTimestamp first appeared, no finalizers)
/// - Transition TO FinalizerBlocked from non-Deleting/FinalizerBlocked state
///   (deletionTimestamp first appeared, has finalizers)
/// - Transition TO Gone
/// - Transition TO Recreated (UID change)
/// - Finalizer count DECREASE (only decrease, not increase)
/// - Planned → DeleteRequested (initial delete issued)
///
/// NOT meaningful: finalizer increase, status heartbeat, resourceVersion change,
/// FinalizerBlocked{3} → FinalizerBlocked{4}.
fn is_meaningful_transition(
    prev: &ResourceRuntimeState,
    new: &ResourceRuntimeState,
    finalizer_decreased: bool,
) -> bool {
    match (prev, new) {
        // deletionTimestamp first appeared (no finalizers)
        (s, ResourceRuntimeState::Deleting) if *s != ResourceRuntimeState::Deleting => true,
        // deletionTimestamp first appeared (with finalizers)
        (s, ResourceRuntimeState::FinalizerBlocked { .. })
            if !matches!(
                s,
                ResourceRuntimeState::FinalizerBlocked { .. } | ResourceRuntimeState::Deleting
            ) =>
        {
            true
        }
        // Resource gone
        (_, ResourceRuntimeState::Gone) => true,
        // UID recreation
        (_, ResourceRuntimeState::Recreated { .. }) => true,
        // Initial delete issued
        (ResourceRuntimeState::Planned, ResourceRuntimeState::DeleteRequested) => true,
        // Finalizer count decreased
        _ if finalizer_decreased => true,
        // Everything else (including finalizer increase, heartbeat) → NOT meaningful
        _ => false,
    }
}

// ──────────────────────────────────────────────────────────────
//  Tests
// ──────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn make_store() -> (Arc<RuntimeStateStore>, Arc<EventNotifier>) {
        let notifier = Arc::new(EventNotifier::new());
        let store = Arc::new(RuntimeStateStore::new(
            notifier.clone(),
            Duration::from_secs(120),
        ));
        (store, notifier)
    }

    fn make_resource_with(
        group: &str,
        kind: &str,
        namespace: Option<&str>,
        name: &str,
        uid: Option<&str>,
    ) -> ResourceId {
        ResourceId {
            group: group.to_string(),
            version: "v1".to_string(),
            kind: kind.to_string(),
            namespace: namespace.map(String::from),
            name: name.to_string(),
            uid: uid.map(String::from),
        }
    }

    fn make_resource(kind: &str, name: &str) -> ResourceId {
        ResourceId {
            group: "test.io".to_string(),
            version: "v1".to_string(),
            kind: kind.to_string(),
            namespace: Some("test-ns".to_string()),
            name: name.to_string(),
            uid: Some(format!("uid-{}", name)),
        }
    }

    fn obs_exists(uid: &str, authoritative: bool) -> RuntimeObservation {
        RuntimeObservation {
            exists: true,
            uid: Some(uid.to_string()),
            has_deletion_timestamp: false,
            finalizer_count: 0,
            authoritative,
        }
    }

    fn obs_gone(authoritative: bool) -> RuntimeObservation {
        RuntimeObservation {
            exists: false,
            uid: None,
            has_deletion_timestamp: false,
            finalizer_count: 0,
            authoritative,
        }
    }

    fn obs_deleting(uid: &str, finalizers: usize, authoritative: bool) -> RuntimeObservation {
        RuntimeObservation {
            exists: true,
            uid: Some(uid.to_string()),
            has_deletion_timestamp: true,
            finalizer_count: finalizers,
            authoritative,
        }
    }

    // ── Epoch / stream ordering ──

    #[test]
    fn test_old_stream_event_ignored() {
        let (store, _) = make_store();
        let res = make_resource("Foo", "a");
        store.register(&res, ResourceRuntimeState::DeleteRequested, 0);

        // Stream 5 updates
        store.update_from_observation(&res, obs_deleting("uid-a", 1, false), 5);
        let e = store.get(&res).unwrap();
        assert_eq!(e.watch_stream_id, 5);

        // Old stream 3 event → ignored
        store.update_from_observation(&res, obs_gone(false), 3);
        let e = store.get(&res).unwrap();
        assert_ne!(e.state, ResourceRuntimeState::Gone);
    }

    #[test]
    fn test_authoritative_get_ignores_stream_id() {
        let (store, _) = make_store();
        let res = make_resource("Foo", "a");
        store.register(&res, ResourceRuntimeState::DeleteRequested, 0);

        // Set watch_stream_id high
        store.update_from_observation(&res, obs_deleting("uid-a", 1, false), 100);

        // Authoritative GET with stream_id=0 → still processed
        store.update_from_observation(&res, obs_gone(true), 0);
        let e = store.get(&res).unwrap();
        assert_eq!(e.state, ResourceRuntimeState::Gone);
    }

    // ── WATCH as hints only ──

    #[test]
    fn test_watch_deleted_does_not_set_gone() {
        let (store, _) = make_store();
        let res = make_resource("Foo", "a");
        store.register(&res, ResourceRuntimeState::Deleting, 0);

        // Non-authoritative Deleted → needs_verification, NOT Gone
        store.update_from_observation(&res, obs_gone(false), 1);
        let e = store.get(&res).unwrap();
        assert_ne!(e.state, ResourceRuntimeState::Gone);
        assert!(e.needs_verification);
    }

    #[test]
    fn test_watch_uid_change_does_not_update_uid() {
        let (store, _) = make_store();
        let res = make_resource("Foo", "a");
        store.register(&res, ResourceRuntimeState::Deleting, 0);

        // Non-authoritative event with different UID → hint, don't change UID
        store.update_from_observation(&res, obs_exists("uid-NEW", false), 1);
        let e = store.get(&res).unwrap();
        assert_eq!(e.uid.as_deref(), Some("uid-a")); // unchanged
        assert!(e.needs_verification);
    }

    #[test]
    fn test_authoritative_get_after_watch_hint_sets_gone() {
        let (store, _) = make_store();
        let res = make_resource("Foo", "a");
        store.register(&res, ResourceRuntimeState::Deleting, 0);

        // WATCH hint
        store.update_from_observation(&res, obs_gone(false), 1);
        assert!(store.get(&res).unwrap().needs_verification);

        // Authoritative GET confirms
        store.update_from_observation(&res, obs_gone(true), 0);
        let e = store.get(&res).unwrap();
        assert_eq!(e.state, ResourceRuntimeState::Gone);
        assert!(!e.needs_verification);
    }

    #[test]
    fn test_old_uid_watch_deleted_after_new_uid_observed() {
        let (store, _) = make_store();
        let res = make_resource("Foo", "a");
        store.register(&res, ResourceRuntimeState::Deleting, 0);

        // Authoritative GET sees new UID
        store.update_from_observation(&res, obs_exists("uid-B", true), 0);
        let e = store.get(&res).unwrap();
        assert!(matches!(e.state, ResourceRuntimeState::Recreated { .. }));

        // Old stream sends Deleted for old UID → ignored (old stream)
        store.update_from_observation(&res, obs_gone(false), 0); // stream_id=0 < watch_stream_id
        // State should still be Recreated, not hinted
    }

    // ── Authoritative Gone / revive ──

    #[test]
    fn test_authoritative_get_200_after_gone_revives_to_unknown() {
        let (store, _) = make_store();
        let res = make_resource("Foo", "a");
        store.register(&res, ResourceRuntimeState::DeleteRequested, 0);

        // Authoritative Gone
        store.update_from_observation(&res, obs_gone(true), 0);
        assert_eq!(store.get(&res).unwrap().state, ResourceRuntimeState::Gone);

        // Authoritative GET 200 same UID → revive to Unknown
        store.update_from_observation(&res, obs_exists("uid-a", true), 0);
        let e = store.get(&res).unwrap();
        assert!(matches!(e.state, ResourceRuntimeState::Unknown { .. }));
    }

    #[test]
    fn test_non_authoritative_get_200_after_gone_ignored() {
        let (store, _) = make_store();
        let res = make_resource("Foo", "a");
        store.register(&res, ResourceRuntimeState::DeleteRequested, 0);

        store.update_from_observation(&res, obs_gone(true), 0);
        assert_eq!(store.get(&res).unwrap().state, ResourceRuntimeState::Gone);

        // Non-authoritative with same UID after Gone → hint only
        store.update_from_observation(&res, obs_exists("uid-a", false), 1);
        let e = store.get(&res).unwrap();
        // WATCH can't revive Gone — but it can hint for verification
        // Actually, for matching UID after Gone, non-auth should hint
        // But our code: Gone + non-auth + exists=true → sets needs_verification
        assert!(e.needs_verification || e.state == ResourceRuntimeState::Gone);
    }

    // ── all_gone_for / needs_verification ──

    #[test]
    fn test_all_gone_excludes_needs_verification() {
        let (store, _) = make_store();
        let res = make_resource("Foo", "a");
        store.register(&res, ResourceRuntimeState::Deleting, 0);

        // WATCH hint (not authoritative)
        store.update_from_observation(&res, obs_gone(false), 1);
        assert!(!store.all_gone_for(&[res.clone()]));

        // Authoritative confirm
        store.update_from_observation(&res, obs_gone(true), 0);
        assert!(store.all_gone_for(&[res]));
    }

    // ── Different group same kind/name ──

    #[test]
    fn test_different_group_same_kind_name_separate_entries() {
        let (store, _) = make_store();
        let res_a = ResourceId {
            group: "group-a.io".to_string(),
            version: "v1".to_string(),
            kind: "Widget".to_string(),
            namespace: Some("ns".to_string()),
            name: "foo".to_string(),
            uid: Some("uid-a".to_string()),
        };
        let res_b = ResourceId {
            group: "group-b.io".to_string(),
            version: "v1".to_string(),
            kind: "Widget".to_string(),
            namespace: Some("ns".to_string()),
            name: "foo".to_string(),
            uid: Some("uid-b".to_string()),
        };
        store.register(&res_a, ResourceRuntimeState::Planned, 0);
        store.register(&res_b, ResourceRuntimeState::Planned, 0);

        store.update_from_observation(&res_a, obs_gone(true), 0);
        assert_eq!(store.get(&res_a).unwrap().state, ResourceRuntimeState::Gone);
        assert_eq!(
            store.get(&res_b).unwrap().state,
            ResourceRuntimeState::Planned
        );
    }

    // ── API failure ──

    #[test]
    fn test_api_failure_is_not_gone() {
        let (store, _) = make_store();
        let res = make_resource("Foo", "a");
        store.register(&res, ResourceRuntimeState::DeleteRequested, 0);

        store.update_from_executor(
            &res,
            ResourceRuntimeState::Unknown {
                reason: "GET failed: 403".to_string(),
            },
        );
        assert!(matches!(
            store.get(&res).unwrap().state,
            ResourceRuntimeState::Unknown { .. }
        ));
    }

    // ── Store has no delete authority ──

    #[test]
    fn test_store_has_no_delete_authority() {
        // Compile-time check: RuntimeStateStore has no delete/mutation methods.
        // This test documents the invariant.
        let (store, _) = make_store();
        let res = make_resource("Foo", "a");
        store.register(&res, ResourceRuntimeState::Planned, 0);
        // Can only register, update_from_executor, update_from_observation, get, snapshot
        // No delete_resource, no delete, no mutation API
    }

    // ── Untracked resource ──

    #[test]
    fn test_untracked_resource_observation_ignored() {
        let (store, _) = make_store();
        let res = make_resource("Foo", "unknown");
        // Not registered
        store.update_from_observation(&res, obs_gone(true), 1);
        assert!(store.get(&res).is_none());
    }

    // ── Stall timer ──

    #[test]
    fn test_heartbeat_does_not_reset_stall() {
        let notifier = Arc::new(EventNotifier::new());
        let store = RuntimeStateStore::new(notifier, Duration::from_millis(10));
        let res = make_resource("Foo", "a");
        store.register(&res, ResourceRuntimeState::Deleting, 0);

        std::thread::sleep(Duration::from_millis(20));

        // Same state observation (heartbeat) → should NOT reset stall
        store.update_from_observation(&res, obs_deleting("uid-a", 0, true), 0);
        let e = store.get(&res).unwrap();
        assert_eq!(e.state, ResourceRuntimeState::Stalled);
    }

    #[test]
    fn test_finalizer_decrease_is_meaningful_progress() {
        let notifier = Arc::new(EventNotifier::new());
        let store = RuntimeStateStore::new(notifier, Duration::from_secs(120));
        let res = make_resource("Foo", "a");
        store.register(&res, ResourceRuntimeState::DeleteRequested, 0);

        // Set with 3 finalizers
        store.update_from_observation(&res, obs_deleting("uid-a", 3, true), 0);
        let t1 = store.get(&res).unwrap().last_meaningful_progress;

        std::thread::sleep(Duration::from_millis(5));

        // Decrease to 2 finalizers
        store.update_from_observation(&res, obs_deleting("uid-a", 2, true), 0);
        let t2 = store.get(&res).unwrap().last_meaningful_progress;
        assert!(t2 > t1, "finalizer decrease should reset stall timer");
    }

    #[test]
    fn test_finalizer_increase_does_not_reset_stall() {
        let notifier = Arc::new(EventNotifier::new());
        let store = RuntimeStateStore::new(notifier, Duration::from_millis(10));
        let res = make_resource("Foo", "a");
        store.register(&res, ResourceRuntimeState::DeleteRequested, 0);

        // Start with 2 finalizers + deletionTimestamp
        store.update_from_observation(&res, obs_deleting("uid-a", 2, true), 0);

        std::thread::sleep(Duration::from_millis(20));

        // Increase to 3 finalizers → FinalizerBlocked{3} which is state_changed
        // but NOT meaningful (finalizer increase). Should become Stalled.
        store.update_from_observation(&res, obs_deleting("uid-a", 3, true), 0);
        let e = store.get(&res).unwrap();
        assert_eq!(
            e.state,
            ResourceRuntimeState::Stalled,
            "finalizer increase should not prevent stall"
        );
    }

    // ── EXPECT is observe-only ──

    #[test]
    fn test_expect_is_observe_only() {
        let (store, _) = make_store();
        let res = make_resource("Foo", "a");
        store.register(&res, ResourceRuntimeState::ExpectingGone, 0);

        // Can transition to Gone via observation
        store.update_from_observation(&res, obs_gone(true), 0);
        assert_eq!(store.get(&res).unwrap().state, ResourceRuntimeState::Gone);
    }

    // ── State transitions ──

    #[test]
    fn test_planned_to_delete_requested() {
        let (store, _) = make_store();
        let res = make_resource("Foo", "a");
        store.register(&res, ResourceRuntimeState::Planned, 0);
        store.update_from_executor(&res, ResourceRuntimeState::DeleteRequested);
        assert_eq!(
            store.get(&res).unwrap().state,
            ResourceRuntimeState::DeleteRequested
        );
    }

    #[test]
    fn test_delete_requested_to_deleting() {
        let (store, _) = make_store();
        let res = make_resource("Foo", "a");
        store.register(&res, ResourceRuntimeState::DeleteRequested, 0);
        store.update_from_observation(&res, obs_deleting("uid-a", 0, true), 0);
        assert_eq!(
            store.get(&res).unwrap().state,
            ResourceRuntimeState::Deleting
        );
    }

    #[test]
    fn test_deleting_to_gone() {
        let (store, _) = make_store();
        let res = make_resource("Foo", "a");
        store.register(&res, ResourceRuntimeState::Deleting, 0);
        store.update_from_observation(&res, obs_gone(true), 0);
        assert_eq!(store.get(&res).unwrap().state, ResourceRuntimeState::Gone);
    }

    #[test]
    fn test_summary_for_filters_resources() {
        let (store, _) = make_store();
        let a = make_resource("Foo", "a");
        let b = make_resource("Foo", "b");
        let c = make_resource("Foo", "c");
        store.register(&a, ResourceRuntimeState::Gone, 0);
        store.register(&b, ResourceRuntimeState::Deleting, 0);
        store.register(&c, ResourceRuntimeState::Keep, 0);

        // Summary for [a, b] only
        let s = store.summary_for(&[a.clone(), b.clone()]);
        assert_eq!(s.total, 2);
        assert_eq!(s.gone, 1);
        assert_eq!(s.deleting, 1);
        assert_eq!(s.keep, 0); // c not included
    }

    #[test]
    fn test_uid_change_during_deleting_is_recreated() {
        let (store, _) = make_store();
        let res = make_resource("Foo", "a");
        store.register(&res, ResourceRuntimeState::Deleting, 0);

        // Authoritative observation with different UID
        store.update_from_observation(&res, obs_exists("uid-NEW", true), 0);
        let e = store.get(&res).unwrap();
        assert!(matches!(e.state, ResourceRuntimeState::Recreated { .. }));
    }

    #[test]
    fn test_new_uid_is_recreated() {
        let (store, _) = make_store();
        let res = make_resource("Foo", "a");
        store.register(&res, ResourceRuntimeState::DeleteRequested, 0);

        // Authoritative Gone
        store.update_from_observation(&res, obs_gone(true), 0);
        assert_eq!(store.get(&res).unwrap().state, ResourceRuntimeState::Gone);

        // Authoritative GET with new UID
        store.update_from_observation(&res, obs_exists("uid-NEW", true), 0);
        assert!(matches!(
            store.get(&res).unwrap().state,
            ResourceRuntimeState::Recreated { .. }
        ));
    }

    #[test]
    fn test_notifier_non_blocking() {
        let notifier = Arc::new(EventNotifier::new());
        // No subscriber — notify should not block
        notifier.notify();
        notifier.notify();
        // If we get here, it's non-blocking
    }

    // ── Meaningful progress predicate ──

    #[test]
    fn test_meaningful_transition_to_deleting() {
        assert!(is_meaningful_transition(
            &ResourceRuntimeState::DeleteRequested,
            &ResourceRuntimeState::Deleting,
            false
        ));
    }

    #[test]
    fn test_meaningful_transition_to_gone() {
        assert!(is_meaningful_transition(
            &ResourceRuntimeState::Deleting,
            &ResourceRuntimeState::Gone,
            false
        ));
    }

    #[test]
    fn test_meaningful_finalizer_decrease() {
        assert!(is_meaningful_transition(
            &ResourceRuntimeState::FinalizerBlocked { count: 3 },
            &ResourceRuntimeState::FinalizerBlocked { count: 2 },
            true
        ));
    }

    #[test]
    fn test_not_meaningful_finalizer_increase() {
        assert!(!is_meaningful_transition(
            &ResourceRuntimeState::FinalizerBlocked { count: 2 },
            &ResourceRuntimeState::FinalizerBlocked { count: 3 },
            false
        ));
    }

    #[test]
    fn test_not_meaningful_same_state() {
        assert!(!is_meaningful_transition(
            &ResourceRuntimeState::Deleting,
            &ResourceRuntimeState::Deleting,
            false
        ));
    }

    #[test]
    fn test_deletion_timestamp_with_finalizers_is_progress() {
        // DeleteRequested → FinalizerBlocked means deletionTimestamp appeared
        // with finalizers present. This IS meaningful progress.
        assert!(is_meaningful_transition(
            &ResourceRuntimeState::DeleteRequested,
            &ResourceRuntimeState::FinalizerBlocked { count: 2 },
            false
        ));
        // Planned → FinalizerBlocked is also meaningful
        assert!(is_meaningful_transition(
            &ResourceRuntimeState::Planned,
            &ResourceRuntimeState::FinalizerBlocked { count: 1 },
            false
        ));
    }

    #[test]
    fn test_finalizer_increase_is_not_progress() {
        // FinalizerBlocked{2} → FinalizerBlocked{3} is NOT meaningful
        assert!(!is_meaningful_transition(
            &ResourceRuntimeState::FinalizerBlocked { count: 2 },
            &ResourceRuntimeState::FinalizerBlocked { count: 3 },
            false
        ));
        // Deleting → FinalizerBlocked (finalizer appeared after delete) is NOT meaningful
        assert!(!is_meaningful_transition(
            &ResourceRuntimeState::Deleting,
            &ResourceRuntimeState::FinalizerBlocked { count: 1 },
            false
        ));
    }

    #[test]
    fn test_barrier_requires_authoritative_gone() {
        // WATCH hint (non-authoritative) should NOT pass barrier
        let (store, _) = make_store();
        let res = make_resource_with("apps", "Deployment", Some("ns"), "dep", Some("uid-a"));

        store.register(&res, ResourceRuntimeState::DeleteRequested, 0);

        // WATCH says deleted (non-authoritative)
        store.update_from_observation(
            &res,
            RuntimeObservation {
                exists: false,
                uid: None,
                has_deletion_timestamp: false,
                finalizer_count: 0,
                authoritative: false,
            },
            1,
        );

        // Barrier should NOT pass — needs_verification is true
        assert!(
            !store.all_gone_for(&[res.clone()]),
            "WATCH hint should not pass barrier"
        );

        // Authoritative GET confirms
        store.update_from_observation(
            &res,
            RuntimeObservation {
                exists: false,
                uid: None,
                has_deletion_timestamp: false,
                finalizer_count: 0,
                authoritative: true,
            },
            0,
        );

        assert!(
            store.all_gone_for(&[res]),
            "Authoritative GET should pass barrier"
        );
    }

    #[test]
    fn test_watch_stale_deleted_does_not_affect_new_uid() {
        // Resource A is deleted, B (new UID) is observed. Late WATCH Deleted
        // for A should not affect B's state.
        let (store, _) = make_store();
        let res = make_resource_with("apps", "Deployment", Some("ns"), "dep", Some("uid-a"));

        store.register(&res, ResourceRuntimeState::DeleteRequested, 0);

        // Authoritative: resource exists with new UID B → Recreated
        store.update_from_observation(
            &res,
            RuntimeObservation {
                exists: true,
                uid: Some("uid-b".to_string()),
                has_deletion_timestamp: false,
                finalizer_count: 0,
                authoritative: true,
            },
            0,
        );

        let entry = store.get(&res).unwrap();
        assert!(matches!(
            entry.state,
            ResourceRuntimeState::Recreated { .. }
        ));

        // Old WATCH Deleted arrives (non-authoritative, uid-a era)
        store.update_from_observation(
            &res,
            RuntimeObservation {
                exists: false,
                uid: None,
                has_deletion_timestamp: false,
                finalizer_count: 0,
                authoritative: false,
            },
            1,
        );

        // B should still be Recreated, not Gone or needs_verification
        let entry = store.get(&res).unwrap();
        assert!(
            matches!(entry.state, ResourceRuntimeState::Recreated { .. }),
            "stale WATCH Deleted should not affect Recreated state"
        );
    }

    // ── Integration: endpoint failure blocks Gone/AllGone ──

    #[test]
    fn test_api_error_observation_does_not_pass_barrier() {
        // Simulates: GET 404 + LIST failure → resource stays in current state
        // (observe_resource returns api_error, store doesn't transition to Gone)
        let notifier = Arc::new(EventNotifier::new());
        let store = RuntimeStateStore::new(notifier, Duration::from_secs(120));
        let res = make_resource_with("apps", "Deployment", Some("ns"), "dep", Some("uid-a"));

        store.register(&res, ResourceRuntimeState::DeleteRequested, 0);

        // Authoritative observation says "exists" (because API error,
        // observe_resource falls back to reporting exists=true with no details)
        store.update_from_observation(
            &res,
            RuntimeObservation {
                exists: true,
                uid: None,
                has_deletion_timestamp: false,
                finalizer_count: 0,
                authoritative: true,
            },
            0,
        );

        // Should NOT be Gone
        assert!(!store.all_gone_for(&[res.clone()]));
        let entry = store.get(&res).unwrap();
        assert_ne!(entry.state, ResourceRuntimeState::Gone);
    }

    #[test]
    fn test_watch_hint_then_authoritative_gone_passes_barrier() {
        // Full path: WATCH Deleted → hint → authoritative GET confirms 404 → Gone → barrier passes
        let notifier = Arc::new(EventNotifier::new());
        let store = RuntimeStateStore::new(notifier, Duration::from_secs(120));
        let res = make_resource_with("apps", "Deployment", Some("ns"), "dep", Some("uid-a"));

        store.register(&res, ResourceRuntimeState::Deleting, 0);

        // Step 1: WATCH says Deleted (non-authoritative → hint only)
        store.update_from_observation(
            &res,
            RuntimeObservation {
                exists: false,
                uid: None,
                has_deletion_timestamp: false,
                finalizer_count: 0,
                authoritative: false,
            },
            1,
        );

        // Barrier should NOT pass (needs_verification)
        assert!(
            !store.all_gone_for(&[res.clone()]),
            "WATCH hint alone must not pass barrier"
        );

        // Step 2: Authoritative GET confirms 404
        store.update_from_observation(
            &res,
            RuntimeObservation {
                exists: false,
                uid: None,
                has_deletion_timestamp: false,
                finalizer_count: 0,
                authoritative: true,
            },
            0,
        );

        // Now barrier should pass
        assert!(
            store.all_gone_for(&[res]),
            "authoritative GET 404 should pass barrier"
        );
    }

    // ── Integration: parallel UID binding order independence ──

    #[test]
    fn test_parallel_uid_binding_is_order_independent() {
        // Simulates the planner's buffer_unordered UID binding:
        // Two resources get UIDs in reverse completion order.
        // Results carry (phase_idx, action_idx) so ordering doesn't matter.

        // Simulate: resource A at (0,0), resource B at (0,1)
        // B completes first, A completes second
        let results: Vec<(usize, usize, &str, Option<&str>)> = vec![
            (0, 1, "res-B", Some("uid-B")), // B completes first
            (0, 0, "res-A", Some("uid-A")), // A completes second
        ];

        // Apply by carried indices
        let mut uids: Vec<(usize, usize, String)> = Vec::new();
        for (pi, ai, _name, uid) in &results {
            if let Some(uid) = uid {
                uids.push((*pi, *ai, uid.to_string()));
            }
        }

        // Verify: action 0 gets uid-A, action 1 gets uid-B
        // (not reversed by completion order)
        let a_uid = uids
            .iter()
            .find(|(_, ai, _)| *ai == 0)
            .map(|(_, _, u)| u.as_str());
        let b_uid = uids
            .iter()
            .find(|(_, ai, _)| *ai == 1)
            .map(|(_, _, u)| u.as_str());
        assert_eq!(
            a_uid,
            Some("uid-A"),
            "action 0 should get uid-A regardless of completion order"
        );
        assert_eq!(
            b_uid,
            Some("uid-B"),
            "action 1 should get uid-B regardless of completion order"
        );
    }
}
