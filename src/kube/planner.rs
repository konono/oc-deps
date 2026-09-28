use std::collections::HashMap;
use std::hash::{Hash, Hasher};
use std::sync::Arc;
use std::time::Instant;

use kube::Client;
use kube::api::{Api, ApiResource, DynamicObject, ListParams};
use kube::core::GroupVersion;
use serde::{Deserialize, Serialize};
use tokio::sync::{Mutex, Notify, Semaphore};

use crate::kube::resource::{
    QueryOperation, QueryOutcome, QueryRecord, QueryRequirement, ScanWarning,
};
use crate::kube::scanner::{MAX_RETRIES, SCAN_REQUEST_TIMEOUT_SECS, SharedLedger, canonical_gvr};

// ── QueryKey ────────────────────────────────────────────────────

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CanonicalGvr {
    pub group: String,
    pub version: String,
    pub plural: String,
}

impl CanonicalGvr {
    pub fn new(group: &str, version: &str, plural: &str) -> Self {
        Self {
            group: group.to_string(),
            version: version.to_string(),
            plural: plural.to_string(),
        }
    }
}

impl std::fmt::Display for CanonicalGvr {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}",
            canonical_gvr(&self.group, &self.version, &self.plural)
        )
    }
}

impl PartialEq for CanonicalGvr {
    fn eq(&self, other: &Self) -> bool {
        self.group == other.group && self.version == other.version && self.plural == other.plural
    }
}

impl Eq for CanonicalGvr {}

impl Hash for CanonicalGvr {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.group.hash(state);
        self.version.hash(state);
        self.plural.hash(state);
    }
}

impl PartialOrd for CanonicalGvr {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for CanonicalGvr {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.group
            .cmp(&other.group)
            .then(self.version.cmp(&other.version))
            .then(self.plural.cmp(&other.plural))
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub struct QueryKey {
    pub operation: QueryOperation,
    pub gvr: CanonicalGvr,
    pub namespace: Option<String>,
    pub target_name: Option<String>,
    pub label_selector: Option<String>,
    pub field_selector: Option<String>,
}

impl QueryKey {
    pub fn get(gvr: CanonicalGvr, namespace: Option<String>, name: String) -> Self {
        Self {
            operation: QueryOperation::Get,
            gvr,
            namespace,
            target_name: Some(name),
            label_selector: None,
            field_selector: None,
        }
    }

    pub fn list(gvr: CanonicalGvr, namespace: Option<String>) -> Self {
        Self {
            operation: QueryOperation::List,
            gvr,
            namespace,
            target_name: None,
            label_selector: None,
            field_selector: None,
        }
    }

    pub fn list_with_selector(
        gvr: CanonicalGvr,
        namespace: Option<String>,
        label_selector: String,
    ) -> Self {
        Self {
            operation: QueryOperation::List,
            gvr,
            namespace,
            target_name: None,
            label_selector: Some(label_selector),
            field_selector: None,
        }
    }

    pub fn gvr_string(&self) -> String {
        format!("{}", self.gvr)
    }
}

// ── Cached result ───────────────────────────────────────────────

#[derive(Clone, Debug)]
#[allow(clippy::large_enum_variant)]
pub enum CachedQueryResult {
    GetSuccess(DynamicObject),
    ListSuccess {
        items: Arc<Vec<DynamicObject>>,
        pages: usize,
    },
    Failure(ScanWarning),
}

impl CachedQueryResult {
    pub fn to_outcome(&self) -> QueryOutcome {
        match self {
            CachedQueryResult::GetSuccess(_) => QueryOutcome::Success { count: 1, pages: 1 },
            CachedQueryResult::ListSuccess { items, pages } => QueryOutcome::Success {
                count: items.len(),
                pages: *pages,
            },
            CachedQueryResult::Failure(w) => crate::kube::resource::scan_warning_to_outcome(w),
        }
    }

    pub fn is_success(&self) -> bool {
        matches!(
            self,
            CachedQueryResult::GetSuccess(_) | CachedQueryResult::ListSuccess { .. }
        )
    }
}

// ── Query flight state ──────────────────────────────────────────

#[allow(clippy::large_enum_variant)]
enum FlightState {
    InFlight(Arc<Notify>),
    Completed(CachedQueryResult),
}

// ── Planner metrics ─────────────────────────────────────────────

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct PlannerMetrics {
    pub total_demands: usize,
    pub unique_queries: usize,
    pub network_queries: usize,
    pub cache_hits: usize,
    pub completed: usize,
    pub incomplete: usize,
    pub retry_count: usize,
    pub total_elapsed_ms: u64,
}

// ── QueryPlanner ────────────────────────────────────────────────

#[allow(dead_code)]
pub struct QueryPlanner {
    flights: Mutex<HashMap<QueryKey, FlightState>>,
    requirements: Mutex<HashMap<QueryKey, QueryRequirement>>,
    demand_count: Mutex<usize>,
    cache_hit_count: Mutex<usize>,
    network_count: Mutex<usize>,
    retry_total: Mutex<usize>,
    elapsed_total: Mutex<u64>,
    semaphore: Option<Arc<Semaphore>>,
    cancelled: tokio::sync::watch::Sender<bool>,
    cancel_rx: tokio::sync::watch::Receiver<bool>,
}

impl QueryPlanner {
    pub fn new(semaphore: Option<Arc<Semaphore>>) -> Arc<Self> {
        let (cancelled, cancel_rx) = tokio::sync::watch::channel(false);
        Arc::new(Self {
            flights: Mutex::new(HashMap::new()),
            requirements: Mutex::new(HashMap::new()),
            demand_count: Mutex::new(0),
            cache_hit_count: Mutex::new(0),
            network_count: Mutex::new(0),
            retry_total: Mutex::new(0),
            elapsed_total: Mutex::new(0),
            semaphore,
            cancelled,
            cancel_rx,
        })
    }

    #[allow(dead_code)]
    pub fn cancel(&self) {
        let _ = self.cancelled.send(true);
    }

    fn is_cancelled(&self) -> bool {
        *self.cancel_rx.borrow()
    }

    pub async fn demand(
        self: &Arc<Self>,
        key: QueryKey,
        requirement: QueryRequirement,
        client: &Client,
    ) -> CachedQueryResult {
        {
            let mut dc = self.demand_count.lock().await;
            *dc += 1;
        }

        // Upgrade requirement if needed
        {
            let mut reqs = self.requirements.lock().await;
            let entry = reqs
                .entry(key.clone())
                .or_insert(QueryRequirement::Optional);
            if requirement == QueryRequirement::Required {
                *entry = QueryRequirement::Required;
            }
        }

        // Check cancellation
        if self.is_cancelled() {
            return CachedQueryResult::Failure(ScanWarning::Other {
                gvr: key.gvr_string(),
                message: "cancelled".to_string(),
            });
        }

        // Check if completed or in-flight
        let notify = {
            let mut flights = self.flights.lock().await;
            match flights.get(&key) {
                Some(FlightState::Completed(result)) => {
                    let mut ch = self.cache_hit_count.lock().await;
                    *ch += 1;
                    return result.clone();
                }
                Some(FlightState::InFlight(notify)) => {
                    // Wait for the in-flight query
                    notify.clone()
                }
                None => {
                    // We'll execute this query
                    let notify = Arc::new(Notify::new());
                    flights.insert(key.clone(), FlightState::InFlight(notify.clone()));
                    drop(flights);
                    let result = self.execute_query(&key, client).await;
                    let mut flights = self.flights.lock().await;
                    flights.insert(key.clone(), FlightState::Completed(result.clone()));
                    // Wake all waiters
                    notify.notify_waiters();
                    return result;
                }
            }
        };

        // Wait for in-flight completion
        notify.notified().await;

        let flights = self.flights.lock().await;
        match flights.get(&key) {
            Some(FlightState::Completed(result)) => {
                let mut ch = self.cache_hit_count.lock().await;
                *ch += 1;
                result.clone()
            }
            _ => CachedQueryResult::Failure(ScanWarning::Other {
                gvr: key.gvr_string(),
                message: "flight disappeared".to_string(),
            }),
        }
    }

    async fn execute_query(&self, key: &QueryKey, client: &Client) -> CachedQueryResult {
        let start = Instant::now();

        let _permit = if let Some(sem) = &self.semaphore {
            Some(sem.acquire().await.expect("semaphore closed"))
        } else {
            None
        };

        {
            let mut nc = self.network_count.lock().await;
            *nc += 1;
        }

        let gvk = GroupVersion::gv(&key.gvr.group, &key.gvr.version).with_kind("_"); // kind not needed for ApiResource from plural
        let ar = ApiResource::from_gvk_with_plural(&gvk, &key.gvr.plural);

        let api: Api<DynamicObject> = match &key.namespace {
            Some(ns) => Api::namespaced_with(client.clone(), ns, &ar),
            None => Api::all_with(client.clone(), &ar),
        };

        let result = match key.operation {
            QueryOperation::Get => {
                let name = key.target_name.as_deref().unwrap_or("");
                self.execute_get(&api, name, key).await
            }
            QueryOperation::List => self.execute_list(&api, key).await,
        };

        let elapsed = start.elapsed();
        {
            let mut et = self.elapsed_total.lock().await;
            *et += elapsed.as_millis() as u64;
        }

        result
    }

    async fn execute_get(
        &self,
        api: &Api<DynamicObject>,
        name: &str,
        key: &QueryKey,
    ) -> CachedQueryResult {
        let is_tty = std::io::IsTerminal::is_terminal(&std::io::stderr());
        let gvr = key.gvr_string();

        for attempt in 0..=MAX_RETRIES {
            if self.is_cancelled() {
                return CachedQueryResult::Failure(ScanWarning::Other {
                    gvr,
                    message: "cancelled".to_string(),
                });
            }

            let timeout_dur = std::time::Duration::from_secs(SCAN_REQUEST_TIMEOUT_SECS);
            match tokio::time::timeout(timeout_dur, api.get(name)).await {
                Ok(Ok(obj)) => return CachedQueryResult::GetSuccess(obj),
                Ok(Err(e)) => {
                    let warning = ScanWarning::from_kube_error(
                        &e,
                        &key.gvr.group,
                        &key.gvr.version,
                        &key.gvr.plural,
                    );
                    if warning.is_retryable() && attempt < MAX_RETRIES {
                        let delay = std::time::Duration::from_millis(500 * (attempt as u64 + 1));
                        if is_tty {
                            eprintln!(
                                "   \x1b[33m⚠ {} — GET attempt {}/{} failed; retrying in {}ms\x1b[0m",
                                gvr,
                                attempt + 1,
                                MAX_RETRIES + 1,
                                delay.as_millis()
                            );
                        }
                        self.record_retry().await;
                        tokio::time::sleep(delay).await;
                        continue;
                    }
                    let mut w = ScanWarning::from_kube_error(
                        &e,
                        &key.gvr.group,
                        &key.gvr.version,
                        &key.gvr.plural,
                    );
                    w.set_retries(attempt);
                    if attempt > 0 {
                        self.record_retry_count(attempt).await;
                    }
                    return CachedQueryResult::Failure(w);
                }
                Err(_) => {
                    if attempt < MAX_RETRIES {
                        let delay = std::time::Duration::from_millis(500 * (attempt as u64 + 1));
                        if is_tty {
                            eprintln!(
                                "   \x1b[33m⚠ {} — GET timeout ({}s), attempt {}/{}; retrying\x1b[0m",
                                gvr,
                                SCAN_REQUEST_TIMEOUT_SECS,
                                attempt + 1,
                                MAX_RETRIES + 1
                            );
                        }
                        self.record_retry().await;
                        tokio::time::sleep(delay).await;
                        continue;
                    }
                    return CachedQueryResult::Failure(ScanWarning::Timeout {
                        gvr,
                        message: Some(format!(
                            "GET {} timeout ({}s)",
                            name, SCAN_REQUEST_TIMEOUT_SECS
                        )),
                        retries: attempt,
                    });
                }
            }
        }
        CachedQueryResult::Failure(ScanWarning::Other {
            gvr,
            message: "exhausted retries".to_string(),
        })
    }

    async fn execute_list(&self, api: &Api<DynamicObject>, key: &QueryKey) -> CachedQueryResult {
        let is_tty = std::io::IsTerminal::is_terminal(&std::io::stderr());
        let gvr = key.gvr_string();

        if key.label_selector.is_some() {
            return self.execute_list_with_selector(api, key).await;
        }

        // Paginated list
        let mut all_items = Vec::new();
        let mut continue_token: Option<String> = None;
        let mut pages: usize = 0;

        loop {
            if self.is_cancelled() {
                return CachedQueryResult::Failure(ScanWarning::Other {
                    gvr,
                    message: "cancelled".to_string(),
                });
            }

            let mut lp = ListParams::default().limit(500);
            if let Some(ref token) = continue_token {
                lp = lp.continue_token(token);
            }

            let mut page_result = None;
            for attempt in 0..=MAX_RETRIES {
                let timeout_dur = std::time::Duration::from_secs(SCAN_REQUEST_TIMEOUT_SECS);
                match tokio::time::timeout(timeout_dur, api.list(&lp)).await {
                    Ok(Ok(list)) => {
                        page_result = Some(list);
                        break;
                    }
                    Ok(Err(e)) => {
                        let warning = ScanWarning::from_kube_error(
                            &e,
                            &key.gvr.group,
                            &key.gvr.version,
                            &key.gvr.plural,
                        );
                        if warning.is_retryable() && attempt < MAX_RETRIES {
                            let delay =
                                std::time::Duration::from_millis(500 * (attempt as u64 + 1));
                            if is_tty {
                                eprintln!(
                                    "   \x1b[33m⚠ {} — LIST attempt {}/{} failed; retrying in {}ms\x1b[0m",
                                    gvr,
                                    attempt + 1,
                                    MAX_RETRIES + 1,
                                    delay.as_millis()
                                );
                            }
                            self.record_retry().await;
                            tokio::time::sleep(delay).await;
                            continue;
                        }
                        let mut w = ScanWarning::from_kube_error(
                            &e,
                            &key.gvr.group,
                            &key.gvr.version,
                            &key.gvr.plural,
                        );
                        w.set_retries(attempt);
                        return CachedQueryResult::Failure(w);
                    }
                    Err(_) => {
                        if attempt < MAX_RETRIES {
                            let delay =
                                std::time::Duration::from_millis(500 * (attempt as u64 + 1));
                            if is_tty {
                                eprintln!(
                                    "   \x1b[33m⚠ {} — LIST timeout ({}s), attempt {}/{}; retrying\x1b[0m",
                                    gvr,
                                    SCAN_REQUEST_TIMEOUT_SECS,
                                    attempt + 1,
                                    MAX_RETRIES + 1
                                );
                            }
                            self.record_retry().await;
                            tokio::time::sleep(delay).await;
                            continue;
                        }
                        return CachedQueryResult::Failure(ScanWarning::Timeout {
                            gvr,
                            message: Some(format!("LIST timeout ({}s)", SCAN_REQUEST_TIMEOUT_SECS)),
                            retries: attempt,
                        });
                    }
                }
            }

            match page_result {
                Some(list) => {
                    pages += 1;
                    all_items.extend(list.items);
                    match list.metadata.continue_.filter(|t| !t.is_empty()) {
                        Some(token) => continue_token = Some(token),
                        None => break,
                    }
                }
                None => {
                    return CachedQueryResult::Failure(ScanWarning::Other {
                        gvr,
                        message: "exhausted retries".to_string(),
                    });
                }
            }
        }

        CachedQueryResult::ListSuccess {
            items: Arc::new(all_items),
            pages,
        }
    }

    async fn execute_list_with_selector(
        &self,
        api: &Api<DynamicObject>,
        key: &QueryKey,
    ) -> CachedQueryResult {
        let is_tty = std::io::IsTerminal::is_terminal(&std::io::stderr());
        let gvr = key.gvr_string();
        let selector = key.label_selector.as_deref().unwrap_or("");

        for attempt in 0..=MAX_RETRIES {
            if self.is_cancelled() {
                return CachedQueryResult::Failure(ScanWarning::Other {
                    gvr,
                    message: "cancelled".to_string(),
                });
            }

            let lp = ListParams::default().labels(selector);
            let timeout_dur = std::time::Duration::from_secs(SCAN_REQUEST_TIMEOUT_SECS);
            match tokio::time::timeout(timeout_dur, api.list(&lp)).await {
                Ok(Ok(list)) => {
                    return CachedQueryResult::ListSuccess {
                        items: Arc::new(list.items),
                        pages: 1,
                    };
                }
                Ok(Err(e)) => {
                    let warning = ScanWarning::from_kube_error(
                        &e,
                        &key.gvr.group,
                        &key.gvr.version,
                        &key.gvr.plural,
                    );
                    if warning.is_retryable() && attempt < MAX_RETRIES {
                        let delay = std::time::Duration::from_millis(500 * (attempt as u64 + 1));
                        if is_tty {
                            eprintln!(
                                "   \x1b[33m⚠ {} — LIST attempt {}/{} failed; retrying in {}ms\x1b[0m",
                                gvr,
                                attempt + 1,
                                MAX_RETRIES + 1,
                                delay.as_millis()
                            );
                        }
                        self.record_retry().await;
                        tokio::time::sleep(delay).await;
                        continue;
                    }
                    let mut w = ScanWarning::from_kube_error(
                        &e,
                        &key.gvr.group,
                        &key.gvr.version,
                        &key.gvr.plural,
                    );
                    w.set_retries(attempt);
                    return CachedQueryResult::Failure(w);
                }
                Err(_) => {
                    if attempt < MAX_RETRIES {
                        let delay = std::time::Duration::from_millis(500 * (attempt as u64 + 1));
                        if is_tty {
                            eprintln!(
                                "   \x1b[33m⚠ {} — LIST timeout ({}s), attempt {}/{}; retrying\x1b[0m",
                                gvr,
                                SCAN_REQUEST_TIMEOUT_SECS,
                                attempt + 1,
                                MAX_RETRIES + 1
                            );
                        }
                        self.record_retry().await;
                        tokio::time::sleep(delay).await;
                        continue;
                    }
                    return CachedQueryResult::Failure(ScanWarning::Timeout {
                        gvr,
                        message: Some(format!(
                            "LIST selector={} timeout ({}s)",
                            selector, SCAN_REQUEST_TIMEOUT_SECS
                        )),
                        retries: attempt,
                    });
                }
            }
        }
        CachedQueryResult::Failure(ScanWarning::Other {
            gvr,
            message: "exhausted retries".to_string(),
        })
    }

    async fn record_retry(&self) {
        let mut rt = self.retry_total.lock().await;
        *rt += 1;
    }

    async fn record_retry_count(&self, count: usize) {
        let mut rt = self.retry_total.lock().await;
        *rt += count;
    }

    pub async fn metrics(&self) -> PlannerMetrics {
        let flights = self.flights.lock().await;
        let mut completed = 0;
        let mut incomplete = 0;
        for state in flights.values() {
            match state {
                FlightState::Completed(r) if r.is_success() => completed += 1,
                FlightState::Completed(_) => incomplete += 1,
                FlightState::InFlight(_) => incomplete += 1,
            }
        }
        let demands = *self.demand_count.lock().await;
        let cache_hits = *self.cache_hit_count.lock().await;
        let network = *self.network_count.lock().await;
        let retries = *self.retry_total.lock().await;
        let elapsed = *self.elapsed_total.lock().await;
        PlannerMetrics {
            total_demands: demands,
            unique_queries: flights.len(),
            network_queries: network,
            cache_hits,
            completed,
            incomplete,
            retry_count: retries,
            total_elapsed_ms: elapsed,
        }
    }

    /// Record all completed queries to a CoverageLedger, using final requirements.
    pub async fn flush_to_ledger(&self, ledger: &SharedLedger) {
        let flights = self.flights.lock().await;
        let reqs = self.requirements.lock().await;

        let mut entries: Vec<_> = flights.iter().collect();
        entries.sort_by_key(|(k, _)| (*k).clone());

        for (key, state) in entries {
            if let FlightState::Completed(result) = state {
                let requirement = reqs.get(key).cloned().unwrap_or(QueryRequirement::Optional);
                let outcome = result.to_outcome();
                let scope = if key.namespace.is_some() {
                    "namespaced"
                } else {
                    "cluster"
                };
                if let Ok(mut l) = ledger.lock() {
                    l.record(QueryRecord {
                        gvr: key.gvr_string(),
                        namespace: key.namespace.clone(),
                        scope: scope.to_string(),
                        operation: key.operation.clone(),
                        target_name: key.target_name.clone(),
                        label_selector: key.label_selector.clone(),
                        field_selector: key.field_selector.clone(),
                        outcome,
                        elapsed_ms: 0, // per-query timing not tracked individually in planner
                        requirement,
                    });
                }
            }
        }
    }

    /// Produce a sorted query plan for JSON/debug output.
    #[allow(dead_code)]
    pub async fn query_plan_sorted(&self) -> Vec<QueryPlanEntry> {
        let flights = self.flights.lock().await;
        let reqs = self.requirements.lock().await;

        let mut entries: Vec<QueryPlanEntry> = flights
            .iter()
            .map(|(key, state)| {
                let requirement = reqs.get(key).cloned().unwrap_or(QueryRequirement::Optional);
                let (outcome, status) = match state {
                    FlightState::Completed(r) => (Some(r.to_outcome()), "completed".to_string()),
                    FlightState::InFlight(_) => (None, "in_flight".to_string()),
                };
                QueryPlanEntry {
                    key: key.clone(),
                    requirement,
                    outcome,
                    status,
                }
            })
            .collect();

        entries.sort_by(|a, b| a.key.cmp(&b.key));
        entries
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[allow(dead_code)]
pub struct QueryPlanEntry {
    pub key: QueryKey,
    pub requirement: QueryRequirement,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub outcome: Option<QueryOutcome>,
    pub status: String,
}

// ── Convenience wrappers ────────────────────────────────────────

#[allow(clippy::too_many_arguments)]
impl QueryPlanner {
    pub async fn get(
        self: &Arc<Self>,
        client: &Client,
        group: &str,
        version: &str,
        plural: &str,
        namespace: Option<&str>,
        name: &str,
        requirement: QueryRequirement,
    ) -> Result<DynamicObject, ScanWarning> {
        let key = QueryKey::get(
            CanonicalGvr::new(group, version, plural),
            namespace.map(|s| s.to_string()),
            name.to_string(),
        );
        match self.demand(key, requirement, client).await {
            CachedQueryResult::GetSuccess(obj) => Ok(obj),
            CachedQueryResult::Failure(w) => Err(w),
            CachedQueryResult::ListSuccess { .. } => Err(ScanWarning::Other {
                gvr: canonical_gvr(group, version, plural),
                message: "internal: GET returned LIST result".to_string(),
            }),
        }
    }

    pub async fn list_all(
        self: &Arc<Self>,
        client: &Client,
        group: &str,
        version: &str,
        plural: &str,
        namespace: Option<&str>,
        requirement: QueryRequirement,
    ) -> Result<Arc<Vec<DynamicObject>>, ScanWarning> {
        let key = QueryKey::list(
            CanonicalGvr::new(group, version, plural),
            namespace.map(|s| s.to_string()),
        );
        match self.demand(key, requirement, client).await {
            CachedQueryResult::ListSuccess { items, .. } => Ok(items),
            CachedQueryResult::Failure(w) => Err(w),
            CachedQueryResult::GetSuccess(_) => Err(ScanWarning::Other {
                gvr: canonical_gvr(group, version, plural),
                message: "internal: LIST returned GET result".to_string(),
            }),
        }
    }

    pub async fn list_with_selector(
        self: &Arc<Self>,
        client: &Client,
        group: &str,
        version: &str,
        plural: &str,
        namespace: Option<&str>,
        selector: &str,
        requirement: QueryRequirement,
    ) -> Result<Arc<Vec<DynamicObject>>, ScanWarning> {
        let key = QueryKey::list_with_selector(
            CanonicalGvr::new(group, version, plural),
            namespace.map(|s| s.to_string()),
            selector.to_string(),
        );
        match self.demand(key, requirement, client).await {
            CachedQueryResult::ListSuccess { items, .. } => Ok(items),
            CachedQueryResult::Failure(w) => Err(w),
            CachedQueryResult::GetSuccess(_) => Err(ScanWarning::Other {
                gvr: canonical_gvr(group, version, plural),
                message: "internal: LIST returned GET result".to_string(),
            }),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    fn json_response(json: serde_json::Value) -> http::Response<kube::client::Body> {
        http::Response::builder()
            .status(200)
            .body(kube::client::Body::from(serde_json::to_vec(&json).unwrap()))
            .unwrap()
    }

    fn status_response(code: u16, reason: &str) -> http::Response<kube::client::Body> {
        let body = serde_json::json!({
            "kind": "Status", "apiVersion": "v1", "metadata": {},
            "status": "Failure", "message": reason, "reason": reason, "code": code
        });
        http::Response::builder()
            .status(code)
            .body(kube::client::Body::from(serde_json::to_vec(&body).unwrap()))
            .unwrap()
    }

    #[allow(dead_code)]
    fn deploy_list_response(names: &[&str]) -> serde_json::Value {
        let items: Vec<serde_json::Value> = names
            .iter()
            .map(|n| {
                serde_json::json!({
                    "apiVersion": "apps/v1",
                    "kind": "Deployment",
                    "metadata": {"name": n, "namespace": "test-ns", "uid": format!("uid-{}", n)}
                })
            })
            .collect();
        serde_json::json!({
            "apiVersion": "apps/v1",
            "kind": "DeploymentList",
            "metadata": {"resourceVersion": "1"},
            "items": items
        })
    }

    fn deploy_get_response(name: &str) -> serde_json::Value {
        serde_json::json!({
            "apiVersion": "apps/v1",
            "kind": "Deployment",
            "metadata": {"name": name, "namespace": "test-ns", "uid": format!("uid-{}", name)}
        })
    }

    // Test 1: Same QueryKey from 2 concurrent consumers = 1 network request
    #[tokio::test]
    async fn single_flight_dedup_concurrent() {
        let request_count = Arc::new(AtomicUsize::new(0));
        let rc = request_count.clone();

        let (mock_service, handle) = tower_test::mock::pair::<
            http::Request<kube::client::Body>,
            http::Response<kube::client::Body>,
        >();
        let client = Client::new(mock_service, "test-ns");
        let planner = QueryPlanner::new(None);

        let spawned = tokio::spawn(async move {
            use std::pin::pin;
            let mut handle = pin!(handle);
            let (_req, send) = handle.next_request().await.expect("expected 1 request");
            rc.fetch_add(1, Ordering::SeqCst);
            // Small delay to let both demands arrive
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
            send.send_response(json_response(deploy_get_response("myapp")));
        });

        let p1 = planner.clone();
        let p2 = planner.clone();
        let c1 = client.clone();
        let c2 = client.clone();

        let (r1, r2) = tokio::join!(
            p1.get(
                &c1,
                "apps",
                "v1",
                "deployments",
                Some("test-ns"),
                "myapp",
                QueryRequirement::Required
            ),
            p2.get(
                &c2,
                "apps",
                "v1",
                "deployments",
                Some("test-ns"),
                "myapp",
                QueryRequirement::Optional
            ),
        );

        spawned.await.unwrap();

        assert!(r1.is_ok());
        assert!(r2.is_ok());
        assert_eq!(
            request_count.load(Ordering::SeqCst),
            1,
            "concurrent demands for same key should result in 1 network request"
        );

        let metrics = planner.metrics().await;
        assert_eq!(metrics.total_demands, 2);
        assert_eq!(metrics.unique_queries, 1);
        assert_eq!(metrics.network_queries, 1);
    }

    // Test 2: Completed cache reuse = still 1 request
    #[tokio::test]
    async fn cache_reuse_after_completion() {
        let request_count = Arc::new(AtomicUsize::new(0));
        let rc = request_count.clone();

        let (mock_service, handle) = tower_test::mock::pair::<
            http::Request<kube::client::Body>,
            http::Response<kube::client::Body>,
        >();
        let client = Client::new(mock_service, "test-ns");
        let planner = QueryPlanner::new(None);

        let spawned = tokio::spawn(async move {
            use std::pin::pin;
            let mut handle = pin!(handle);
            let (_req, send) = handle.next_request().await.expect("expected request");
            rc.fetch_add(1, Ordering::SeqCst);
            send.send_response(json_response(deploy_get_response("myapp")));
        });

        // First demand
        let r1 = planner
            .get(
                &client,
                "apps",
                "v1",
                "deployments",
                Some("test-ns"),
                "myapp",
                QueryRequirement::Required,
            )
            .await;
        assert!(r1.is_ok());

        // Second demand (from cache)
        let r2 = planner
            .get(
                &client,
                "apps",
                "v1",
                "deployments",
                Some("test-ns"),
                "myapp",
                QueryRequirement::Optional,
            )
            .await;
        assert!(r2.is_ok());

        spawned.await.unwrap();
        assert_eq!(request_count.load(Ordering::SeqCst), 1);

        let metrics = planner.metrics().await;
        assert_eq!(metrics.cache_hits, 1);
    }

    // Test 3: Different keys = different queries
    #[tokio::test]
    async fn different_keys_separate_queries() {
        let request_count = Arc::new(AtomicUsize::new(0));
        let rc = request_count.clone();

        let (mock_service, handle) = tower_test::mock::pair::<
            http::Request<kube::client::Body>,
            http::Response<kube::client::Body>,
        >();
        let client = Client::new(mock_service, "test-ns");
        let planner = QueryPlanner::new(None);

        let spawned = tokio::spawn(async move {
            use std::pin::pin;
            let mut handle = pin!(handle);
            // GET myapp
            let (_req, send) = handle.next_request().await.expect("req 1");
            rc.fetch_add(1, Ordering::SeqCst);
            send.send_response(json_response(deploy_get_response("myapp")));
            // GET other
            let (_req, send) = handle.next_request().await.expect("req 2");
            rc.fetch_add(1, Ordering::SeqCst);
            send.send_response(json_response(deploy_get_response("other")));
        });

        let r1 = planner
            .get(
                &client,
                "apps",
                "v1",
                "deployments",
                Some("test-ns"),
                "myapp",
                QueryRequirement::Required,
            )
            .await;
        let r2 = planner
            .get(
                &client,
                "apps",
                "v1",
                "deployments",
                Some("test-ns"),
                "other",
                QueryRequirement::Required,
            )
            .await;

        spawned.await.unwrap();
        assert!(r1.is_ok());
        assert!(r2.is_ok());
        assert_eq!(request_count.load(Ordering::SeqCst), 2);
    }

    // Test 4: Optional then Required → final requirement = Required
    #[tokio::test]
    async fn requirement_upgrade_optional_to_required() {
        let (mock_service, handle) = tower_test::mock::pair::<
            http::Request<kube::client::Body>,
            http::Response<kube::client::Body>,
        >();
        let client = Client::new(mock_service, "test-ns");
        let planner = QueryPlanner::new(None);

        let spawned = tokio::spawn(async move {
            use std::pin::pin;
            let mut handle = pin!(handle);
            let (_req, send) = handle.next_request().await.expect("req");
            send.send_response(json_response(deploy_get_response("myapp")));
        });

        // Optional first
        let _ = planner
            .get(
                &client,
                "apps",
                "v1",
                "deployments",
                Some("test-ns"),
                "myapp",
                QueryRequirement::Optional,
            )
            .await;
        // Required second
        let _ = planner
            .get(
                &client,
                "apps",
                "v1",
                "deployments",
                Some("test-ns"),
                "myapp",
                QueryRequirement::Required,
            )
            .await;

        spawned.await.unwrap();

        let reqs = planner.requirements.lock().await;
        let key = QueryKey::get(
            CanonicalGvr::new("apps", "v1", "deployments"),
            Some("test-ns".to_string()),
            "myapp".to_string(),
        );
        assert_eq!(reqs.get(&key), Some(&QueryRequirement::Required));
    }

    // Test 5: 403 shared across consumers
    #[tokio::test]
    async fn forbidden_shared_single_request() {
        let request_count = Arc::new(AtomicUsize::new(0));
        let rc = request_count.clone();

        let (mock_service, handle) = tower_test::mock::pair::<
            http::Request<kube::client::Body>,
            http::Response<kube::client::Body>,
        >();
        let client = Client::new(mock_service, "test-ns");
        let planner = QueryPlanner::new(None);

        let spawned = tokio::spawn(async move {
            use std::pin::pin;
            let mut handle = pin!(handle);
            let (_req, send) = handle.next_request().await.expect("req");
            rc.fetch_add(1, Ordering::SeqCst);
            send.send_response(status_response(403, "Forbidden"));
        });

        let r1 = planner
            .get(
                &client,
                "apps",
                "v1",
                "deployments",
                Some("test-ns"),
                "myapp",
                QueryRequirement::Required,
            )
            .await;
        // Second demand gets cached failure
        let r2 = planner
            .get(
                &client,
                "apps",
                "v1",
                "deployments",
                Some("test-ns"),
                "myapp",
                QueryRequirement::Required,
            )
            .await;

        spawned.await.unwrap();
        assert!(r1.is_err());
        assert!(r2.is_err());
        assert!(matches!(r1.unwrap_err(), ScanWarning::Forbidden { .. }));
        assert!(matches!(r2.unwrap_err(), ScanWarning::Forbidden { .. }));
        assert_eq!(request_count.load(Ordering::SeqCst), 1);
    }

    // Test 6: Persistent 500 = 3 attempts, failure shared
    #[tokio::test]
    async fn server_error_retries_and_shares() {
        let request_count = Arc::new(AtomicUsize::new(0));
        let rc = request_count.clone();

        let (mock_service, handle) = tower_test::mock::pair::<
            http::Request<kube::client::Body>,
            http::Response<kube::client::Body>,
        >();
        let client = Client::new(mock_service, "test-ns");
        let planner = QueryPlanner::new(None);

        let spawned = tokio::spawn(async move {
            use std::pin::pin;
            let mut handle = pin!(handle);
            for _ in 0..3 {
                let (_req, send) = handle.next_request().await.expect("req");
                rc.fetch_add(1, Ordering::SeqCst);
                send.send_response(status_response(500, "Internal Server Error"));
            }
        });

        let r1 = planner
            .get(
                &client,
                "apps",
                "v1",
                "deployments",
                Some("test-ns"),
                "myapp",
                QueryRequirement::Required,
            )
            .await;

        spawned.await.unwrap();
        assert!(r1.is_err());
        assert_eq!(request_count.load(Ordering::SeqCst), 3);

        // Second consumer gets same cached failure
        let r2 = planner
            .get(
                &client,
                "apps",
                "v1",
                "deployments",
                Some("test-ns"),
                "myapp",
                QueryRequirement::Required,
            )
            .await;
        assert!(r2.is_err());
    }

    // Test 7: 500 then 200 recovery
    #[tokio::test]
    async fn server_error_then_recovery() {
        let request_count = Arc::new(AtomicUsize::new(0));
        let rc = request_count.clone();

        let (mock_service, handle) = tower_test::mock::pair::<
            http::Request<kube::client::Body>,
            http::Response<kube::client::Body>,
        >();
        let client = Client::new(mock_service, "test-ns");
        let planner = QueryPlanner::new(None);

        let spawned = tokio::spawn(async move {
            use std::pin::pin;
            let mut handle = pin!(handle);
            // First: 500
            let (_req, send) = handle.next_request().await.expect("req 1");
            rc.fetch_add(1, Ordering::SeqCst);
            send.send_response(status_response(500, "Internal Server Error"));
            // Second: success
            let (_req, send) = handle.next_request().await.expect("req 2");
            rc.fetch_add(1, Ordering::SeqCst);
            send.send_response(json_response(deploy_get_response("myapp")));
        });

        let r1 = planner
            .get(
                &client,
                "apps",
                "v1",
                "deployments",
                Some("test-ns"),
                "myapp",
                QueryRequirement::Required,
            )
            .await;

        spawned.await.unwrap();
        assert!(r1.is_ok());
        assert_eq!(request_count.load(Ordering::SeqCst), 2);
    }

    // Test 8: Paginated list
    #[tokio::test]
    async fn paginated_list_collects_all_pages() {
        let request_count = Arc::new(AtomicUsize::new(0));
        let rc = request_count.clone();

        let (mock_service, handle) = tower_test::mock::pair::<
            http::Request<kube::client::Body>,
            http::Response<kube::client::Body>,
        >();
        let client = Client::new(mock_service, "test-ns");
        let planner = QueryPlanner::new(None);

        let spawned = tokio::spawn(async move {
            use std::pin::pin;
            let mut handle = pin!(handle);
            // Page 1
            let (_req, send) = handle.next_request().await.expect("page 1");
            rc.fetch_add(1, Ordering::SeqCst);
            send.send_response(json_response(serde_json::json!({
                "apiVersion": "apps/v1",
                "kind": "DeploymentList",
                "metadata": {"resourceVersion": "1", "continue": "token-1"},
                "items": [{"apiVersion": "apps/v1", "kind": "Deployment", "metadata": {"name": "d1", "namespace": "test-ns", "uid": "uid-d1"}}]
            })));
            // Page 2
            let (_req, send) = handle.next_request().await.expect("page 2");
            rc.fetch_add(1, Ordering::SeqCst);
            send.send_response(json_response(serde_json::json!({
                "apiVersion": "apps/v1",
                "kind": "DeploymentList",
                "metadata": {"resourceVersion": "2"},
                "items": [{"apiVersion": "apps/v1", "kind": "Deployment", "metadata": {"name": "d2", "namespace": "test-ns", "uid": "uid-d2"}}]
            })));
        });

        let items = planner
            .list_all(
                &client,
                "apps",
                "v1",
                "deployments",
                Some("test-ns"),
                QueryRequirement::Required,
            )
            .await
            .unwrap();

        spawned.await.unwrap();
        assert_eq!(items.len(), 2);
        assert_eq!(request_count.load(Ordering::SeqCst), 2);
    }

    // Test 9: Semaphore limits concurrency
    #[tokio::test]
    async fn semaphore_limits_concurrent_requests() {
        let permits = 2usize;
        let semaphore = Arc::new(Semaphore::new(permits));
        let max_concurrent = Arc::new(AtomicUsize::new(0));
        let current_concurrent = Arc::new(AtomicUsize::new(0));

        let (mock_service, handle) = tower_test::mock::pair::<
            http::Request<kube::client::Body>,
            http::Response<kube::client::Body>,
        >();
        let client = Client::new(mock_service, "test-ns");
        let planner = QueryPlanner::new(Some(semaphore));

        let max_c = max_concurrent.clone();
        let cur_c = current_concurrent.clone();

        let spawned = tokio::spawn(async move {
            use std::pin::pin;
            let mut handle = pin!(handle);
            for i in 0..4 {
                let (_req, send) = handle.next_request().await.expect("req");
                let mc = max_c.clone();
                let cc = cur_c.clone();
                tokio::spawn(async move {
                    let c = cc.fetch_add(1, Ordering::SeqCst) + 1;
                    mc.fetch_max(c, Ordering::SeqCst);
                    tokio::time::sleep(std::time::Duration::from_millis(20)).await;
                    cc.fetch_sub(1, Ordering::SeqCst);
                    send.send_response(json_response(deploy_get_response(&format!("d{}", i))));
                });
            }
        });

        let futs: Vec<_> = (0..4)
            .map(|i| {
                let p = planner.clone();
                let c = client.clone();
                tokio::spawn(async move {
                    p.get(
                        &c,
                        "apps",
                        "v1",
                        "deployments",
                        Some("test-ns"),
                        &format!("d{}", i),
                        QueryRequirement::Required,
                    )
                    .await
                })
            })
            .collect();

        for f in futs {
            let _ = f.await.unwrap();
        }
        spawned.await.unwrap();

        let observed_max = max_concurrent.load(Ordering::SeqCst);
        assert!(
            observed_max <= permits,
            "max concurrent should be <= {} permits, got {}",
            permits,
            observed_max
        );
    }

    // Test 10: Cancellation prevents new queries
    #[tokio::test]
    async fn cancellation_prevents_new_queries() {
        let (mock_service, _handle) = tower_test::mock::pair::<
            http::Request<kube::client::Body>,
            http::Response<kube::client::Body>,
        >();
        let client = Client::new(mock_service, "test-ns");
        let planner = QueryPlanner::new(None);

        planner.cancel();

        let result = planner
            .get(
                &client,
                "apps",
                "v1",
                "deployments",
                Some("test-ns"),
                "myapp",
                QueryRequirement::Required,
            )
            .await;
        assert!(result.is_err());
        let err = result.unwrap_err();
        match err {
            ScanWarning::Other { message, .. } => assert!(message.contains("cancelled")),
            _ => panic!("expected cancelled error"),
        }
    }

    // Test 11: Insertion order doesn't affect query plan sort
    #[tokio::test]
    async fn stable_sort_regardless_of_insertion_order() {
        // Create two planners with reversed insertion order, verify same output
        let keys = vec![
            QueryKey::get(
                CanonicalGvr::new("apps", "v1", "deployments"),
                Some("ns-a".to_string()),
                "deploy-a".to_string(),
            ),
            QueryKey::get(
                CanonicalGvr::new("", "v1", "pods"),
                Some("ns-b".to_string()),
                "pod-b".to_string(),
            ),
            QueryKey::list(
                CanonicalGvr::new("apps", "v1", "deployments"),
                Some("ns-a".to_string()),
            ),
        ];

        let plan_forward = {
            let planner = QueryPlanner::new(None);
            let mut flights = planner.flights.lock().await;
            for key in &keys {
                flights.insert(
                    key.clone(),
                    FlightState::Completed(CachedQueryResult::Failure(ScanWarning::NotFound {
                        gvr: key.gvr_string(),
                    })),
                );
            }
            drop(flights);
            planner.query_plan_sorted().await
        };

        let plan_reverse = {
            let planner = QueryPlanner::new(None);
            let mut flights = planner.flights.lock().await;
            for key in keys.iter().rev() {
                flights.insert(
                    key.clone(),
                    FlightState::Completed(CachedQueryResult::Failure(ScanWarning::NotFound {
                        gvr: key.gvr_string(),
                    })),
                );
            }
            drop(flights);
            planner.query_plan_sorted().await
        };

        let json_f = serde_json::to_string(&plan_forward).unwrap();
        let json_r = serde_json::to_string(&plan_reverse).unwrap();
        assert_eq!(
            json_f, json_r,
            "query plan must be byte-identical regardless of insertion order"
        );
    }

    // Test 12: Secret data doesn't leak into Debug/JSON/metrics
    #[tokio::test]
    async fn secret_data_not_in_debug_or_json() {
        let secret_value = "super-secret-token-12345";
        let secret_obj = serde_json::json!({
            "apiVersion": "v1",
            "kind": "Secret",
            "metadata": {"name": "my-secret", "namespace": "test-ns", "uid": "uid-secret"},
            "data": {"token": secret_value}
        });

        let (mock_service, handle) = tower_test::mock::pair::<
            http::Request<kube::client::Body>,
            http::Response<kube::client::Body>,
        >();
        let client = Client::new(mock_service, "test-ns");
        let planner = QueryPlanner::new(None);

        let spawned = tokio::spawn(async move {
            use std::pin::pin;
            let mut handle = pin!(handle);
            let (_req, send) = handle.next_request().await.expect("req");
            send.send_response(json_response(secret_obj));
        });

        let _ = planner
            .get(
                &client,
                "",
                "v1",
                "secrets",
                Some("test-ns"),
                "my-secret",
                QueryRequirement::Required,
            )
            .await;

        spawned.await.unwrap();

        // Check that metrics/plan JSON don't contain secret data
        let metrics = planner.metrics().await;
        let metrics_json = serde_json::to_string(&metrics).unwrap();
        assert!(
            !metrics_json.contains(secret_value),
            "Secret value must not appear in metrics JSON"
        );

        let plan = planner.query_plan_sorted().await;
        let plan_json = serde_json::to_string(&plan).unwrap();
        assert!(
            !plan_json.contains(secret_value),
            "Secret value must not appear in query plan JSON"
        );

        // QueryKey debug shouldn't contain secret values
        let key = QueryKey::get(
            CanonicalGvr::new("", "v1", "secrets"),
            Some("test-ns".to_string()),
            "my-secret".to_string(),
        );
        let key_debug = format!("{:?}", key);
        assert!(
            !key_debug.contains(secret_value),
            "Secret value must not appear in QueryKey debug"
        );
    }

    // Test: GET vs LIST for same GVR are separate queries
    #[tokio::test]
    async fn get_and_list_are_separate_keys() {
        let get_key = QueryKey::get(
            CanonicalGvr::new("apps", "v1", "deployments"),
            Some("ns".to_string()),
            "myapp".to_string(),
        );
        let list_key = QueryKey::list(
            CanonicalGvr::new("apps", "v1", "deployments"),
            Some("ns".to_string()),
        );
        assert_ne!(get_key, list_key);
    }

    // Test: Different selectors are separate keys
    #[tokio::test]
    async fn different_selectors_are_separate_keys() {
        let k1 = QueryKey::list_with_selector(
            CanonicalGvr::new("apps", "v1", "deployments"),
            Some("ns".to_string()),
            "app=foo".to_string(),
        );
        let k2 = QueryKey::list_with_selector(
            CanonicalGvr::new("apps", "v1", "deployments"),
            Some("ns".to_string()),
            "app=bar".to_string(),
        );
        assert_ne!(k1, k2);
    }

    // Test: Different namespaces are separate keys
    #[tokio::test]
    async fn different_namespaces_are_separate_keys() {
        let k1 = QueryKey::get(
            CanonicalGvr::new("apps", "v1", "deployments"),
            Some("ns-a".to_string()),
            "myapp".to_string(),
        );
        let k2 = QueryKey::get(
            CanonicalGvr::new("apps", "v1", "deployments"),
            Some("ns-b".to_string()),
            "myapp".to_string(),
        );
        assert_ne!(k1, k2);
    }

    // Test: Different GVRs are separate keys
    #[tokio::test]
    async fn different_gvrs_are_separate_keys() {
        let k1 = QueryKey::get(
            CanonicalGvr::new("apps", "v1", "deployments"),
            Some("ns".to_string()),
            "myapp".to_string(),
        );
        let k2 = QueryKey::get(
            CanonicalGvr::new("apps", "v1", "statefulsets"),
            Some("ns".to_string()),
            "myapp".to_string(),
        );
        assert_ne!(k1, k2);
    }

    // Test 13: Production-path dedup via scanner wrappers
    #[tokio::test]
    async fn production_path_list_dedup_via_planner() {
        use crate::kube::scanner::{SharedPlanner, list_with_selector_retry_planner};
        use std::pin::pin;

        let request_count = Arc::new(AtomicUsize::new(0));
        let rc = request_count.clone();

        let (mock_service, handle) = tower_test::mock::pair::<
            http::Request<kube::client::Body>,
            http::Response<kube::client::Body>,
        >();
        let client = Client::new(mock_service, "default");
        let planner: SharedPlanner = QueryPlanner::new(None);

        let spawned = tokio::spawn(async move {
            let mut handle = pin!(handle);
            let (_req, send) = handle.next_request().await.expect("expected 1 LIST");
            rc.fetch_add(1, Ordering::SeqCst);
            send.send_response(json_response(serde_json::json!({
                "apiVersion": "operators.coreos.com/v1alpha1",
                "kind": "ClusterServiceVersionList",
                "metadata": {"resourceVersion": "1"},
                "items": [{
                    "apiVersion": "operators.coreos.com/v1alpha1",
                    "kind": "ClusterServiceVersion",
                    "metadata": {"name": "test-csv.v1", "namespace": "ns-a", "uid": "uid-csv"}
                }]
            })));
        });

        let gvk = kube::core::GroupVersion::gv("operators.coreos.com", "v1alpha1")
            .with_kind("ClusterServiceVersion");
        let ar = kube::api::ApiResource::from_gvk_with_plural(&gvk, "clusterserviceversions");
        let api: kube::api::Api<kube::api::DynamicObject> =
            kube::api::Api::all_with(client.clone(), &ar);

        // First call via scanner wrapper
        let r1 = list_with_selector_retry_planner(
            &api,
            "operators.coreos.com/managed-by-csv",
            "operators.coreos.com",
            "v1alpha1",
            "clusterserviceversions",
            None,
            None,
            QueryRequirement::Required,
            Some(&planner),
            &client,
        )
        .await;
        assert!(r1.is_ok());
        assert_eq!(r1.unwrap().len(), 1);

        // Second call — same query, should use cache
        let r2 = list_with_selector_retry_planner(
            &api,
            "operators.coreos.com/managed-by-csv",
            "operators.coreos.com",
            "v1alpha1",
            "clusterserviceversions",
            None,
            None,
            QueryRequirement::Optional,
            Some(&planner),
            &client,
        )
        .await;
        assert!(r2.is_ok());
        assert_eq!(r2.unwrap().len(), 1);

        spawned.await.unwrap();
        assert_eq!(
            request_count.load(Ordering::SeqCst),
            1,
            "second call via scanner wrapper should hit planner cache, not make new request"
        );

        let metrics = planner.metrics().await;
        assert_eq!(metrics.total_demands, 2);
        assert_eq!(metrics.network_queries, 1);
        assert_eq!(metrics.cache_hits, 1);
    }

    // Test 14: Phase A strict truth table maintained
    #[test]
    fn strict_truth_table_maintained() {
        use crate::kube::resource::QueryOutcome;

        // Required + Success = not incomplete
        assert!(
            !QueryOutcome::Success { count: 5, pages: 1 }
                .is_incomplete(&QueryRequirement::Required)
        );
        // Required + Forbidden = incomplete
        assert!(QueryOutcome::Forbidden { status: 403 }.is_incomplete(&QueryRequirement::Required));
        // Required + ApiAbsent = incomplete
        assert!(QueryOutcome::ApiAbsent.is_incomplete(&QueryRequirement::Required));
        // Required + TargetMissing = incomplete
        assert!(QueryOutcome::TargetMissing.is_incomplete(&QueryRequirement::Required));
        // Optional + ApiAbsent = not incomplete
        assert!(!QueryOutcome::ApiAbsent.is_incomplete(&QueryRequirement::Optional));
        // Optional + TargetMissing = not incomplete
        assert!(!QueryOutcome::TargetMissing.is_incomplete(&QueryRequirement::Optional));
        // Optional + Forbidden = incomplete
        assert!(QueryOutcome::Forbidden { status: 403 }.is_incomplete(&QueryRequirement::Optional));
        // Optional + Success = not incomplete
        assert!(
            !QueryOutcome::Success { count: 0, pages: 1 }
                .is_incomplete(&QueryRequirement::Optional)
        );
    }
}
