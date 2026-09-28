use std::collections::HashMap;
use std::hash::{Hash, Hasher};
use std::sync::Arc;
use std::time::Instant;

use kube::Client;
use kube::api::{Api, ApiResource, DynamicObject, ListParams};
use kube::core::GroupVersion;
use serde::{Deserialize, Serialize};
use tokio::sync::{Mutex, OnceCell, Semaphore};
use tokio_util::sync::CancellationToken;

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

    pub fn list_with_label(
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

    #[allow(dead_code)]
    pub fn list_with_field(
        gvr: CanonicalGvr,
        namespace: Option<String>,
        field_selector: String,
    ) -> Self {
        Self {
            operation: QueryOperation::List,
            gvr,
            namespace,
            target_name: None,
            label_selector: None,
            field_selector: Some(field_selector),
        }
    }

    pub fn gvr_string(&self) -> String {
        format!("{}", self.gvr)
    }
}

// ── Completed query result ──────────────────────────────────────

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

/// Stores the completed query result alongside timing/retry metadata.
#[derive(Clone, Debug)]
#[allow(dead_code)]
pub struct CompletedQuery {
    pub result: CachedQueryResult,
    pub elapsed_ms: u64,
    pub retries: usize,
}

/// Single-flight cell: first caller initializes, followers wait and share the result.
struct Flight {
    cell: OnceCell<CompletedQuery>,
}

impl Default for Flight {
    fn default() -> Self {
        Self {
            cell: OnceCell::new(),
        }
    }
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

pub struct QueryPlanner {
    flights: Mutex<HashMap<QueryKey, Arc<Flight>>>,
    requirements: Mutex<HashMap<QueryKey, QueryRequirement>>,
    demand_count: Mutex<usize>,
    cache_hit_count: Mutex<usize>,
    network_count: Mutex<usize>,
    retry_total: Mutex<usize>,
    elapsed_total: Mutex<u64>,
    semaphore: Option<Arc<Semaphore>>,
    cancel: CancellationToken,
}

impl QueryPlanner {
    pub fn new(semaphore: Option<Arc<Semaphore>>) -> Arc<Self> {
        Arc::new(Self {
            flights: Mutex::new(HashMap::new()),
            requirements: Mutex::new(HashMap::new()),
            demand_count: Mutex::new(0),
            cache_hit_count: Mutex::new(0),
            network_count: Mutex::new(0),
            retry_total: Mutex::new(0),
            elapsed_total: Mutex::new(0),
            semaphore,
            cancel: CancellationToken::new(),
        })
    }

    #[allow(dead_code)]
    pub fn cancel(&self) {
        self.cancel.cancel();
    }

    #[allow(dead_code)]
    pub fn semaphore(&self) -> Option<Arc<Semaphore>> {
        self.semaphore.clone()
    }

    /// Core demand path using OnceCell for race-free single-flight.
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

        // Upgrade requirement
        {
            let mut reqs = self.requirements.lock().await;
            let entry = reqs
                .entry(key.clone())
                .or_insert(QueryRequirement::Optional);
            if requirement == QueryRequirement::Required {
                *entry = QueryRequirement::Required;
            }
        }

        if self.cancel.is_cancelled() {
            return CachedQueryResult::Failure(ScanWarning::Other {
                gvr: key.gvr_string(),
                message: "cancelled".to_string(),
            });
        }

        // Get or create the flight — OnceCell guarantees exactly one initializer runs.
        let flight = {
            let mut flights = self.flights.lock().await;
            flights
                .entry(key.clone())
                .or_insert_with(|| Arc::new(Flight::default()))
                .clone()
        };

        // If already completed, this is a cache hit.
        if flight.cell.initialized() {
            let mut ch = self.cache_hit_count.lock().await;
            *ch += 1;
            return flight.cell.get().unwrap().result.clone();
        }

        // get_or_init: first caller executes, followers block and share result.
        let completed = flight
            .cell
            .get_or_init(|| self.execute_query(&key, client))
            .await;

        completed.result.clone()
    }

    async fn execute_query(&self, key: &QueryKey, client: &Client) -> CompletedQuery {
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

        let gvk = GroupVersion::gv(&key.gvr.group, &key.gvr.version).with_kind("_");
        let ar = ApiResource::from_gvk_with_plural(&gvk, &key.gvr.plural);

        let api: Api<DynamicObject> = match &key.namespace {
            Some(ns) => Api::namespaced_with(client.clone(), ns, &ar),
            None => Api::all_with(client.clone(), &ar),
        };

        let (result, retries) = match key.operation {
            QueryOperation::Get => {
                let name = key.target_name.as_deref().unwrap_or("");
                self.execute_get(&api, name, key).await
            }
            QueryOperation::List => self.execute_list(&api, key).await,
        };

        let elapsed_ms = start.elapsed().as_millis() as u64;
        {
            let mut rt = self.retry_total.lock().await;
            *rt += retries;
        }
        {
            let mut et = self.elapsed_total.lock().await;
            *et += elapsed_ms;
        }

        let result = redact_secret_data(result);

        CompletedQuery {
            result,
            elapsed_ms,
            retries,
        }
    }

    /// Returns (result, retry_count). retry_count = number of retries (0 if first attempt succeeded).
    async fn execute_get(
        &self,
        api: &Api<DynamicObject>,
        name: &str,
        key: &QueryKey,
    ) -> (CachedQueryResult, usize) {
        let is_tty = std::io::IsTerminal::is_terminal(&std::io::stderr());
        let gvr = key.gvr_string();

        for attempt in 0..=MAX_RETRIES {
            let timeout_dur = std::time::Duration::from_secs(SCAN_REQUEST_TIMEOUT_SECS);
            let api_call = tokio::time::timeout(timeout_dur, api.get(name));

            let result = tokio::select! {
                biased;
                _ = self.cancel.cancelled() => {
                    return (CachedQueryResult::Failure(ScanWarning::Other {
                        gvr,
                        message: "cancelled".to_string(),
                    }), attempt);
                }
                r = api_call => r,
            };

            match result {
                Ok(Ok(obj)) => return (CachedQueryResult::GetSuccess(obj), attempt),
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
                    return (CachedQueryResult::Failure(w), attempt);
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
                        tokio::time::sleep(delay).await;
                        continue;
                    }
                    return (
                        CachedQueryResult::Failure(ScanWarning::Timeout {
                            gvr,
                            message: Some(format!(
                                "GET {} timeout ({}s)",
                                name, SCAN_REQUEST_TIMEOUT_SECS
                            )),
                            retries: attempt,
                        }),
                        attempt,
                    );
                }
            }
        }
        (
            CachedQueryResult::Failure(ScanWarning::Other {
                gvr,
                message: "exhausted retries".to_string(),
            }),
            MAX_RETRIES,
        )
    }

    /// Paginated LIST with optional label/field selectors. Returns (result, retry_count).
    async fn execute_list(
        &self,
        api: &Api<DynamicObject>,
        key: &QueryKey,
    ) -> (CachedQueryResult, usize) {
        let is_tty = std::io::IsTerminal::is_terminal(&std::io::stderr());
        let gvr = key.gvr_string();

        let mut all_items = Vec::new();
        let mut continue_token: Option<String> = None;
        let mut pages: usize = 0;
        let mut total_retries: usize = 0;

        loop {
            if self.cancel.is_cancelled() {
                return (
                    CachedQueryResult::Failure(ScanWarning::Other {
                        gvr,
                        message: "cancelled".to_string(),
                    }),
                    total_retries,
                );
            }

            let mut lp = ListParams::default().limit(500);
            if let Some(ref sel) = key.label_selector {
                lp = lp.labels(sel);
            }
            if let Some(ref sel) = key.field_selector {
                lp = lp.fields(sel);
            }
            if let Some(ref token) = continue_token {
                lp = lp.continue_token(token);
            }

            let mut page_result = None;
            for attempt in 0..=MAX_RETRIES {
                let timeout_dur = std::time::Duration::from_secs(SCAN_REQUEST_TIMEOUT_SECS);
                let api_call = tokio::time::timeout(timeout_dur, api.list(&lp));

                let result = tokio::select! {
                    biased;
                    _ = self.cancel.cancelled() => {
                        return (CachedQueryResult::Failure(ScanWarning::Other {
                            gvr,
                            message: "cancelled".to_string(),
                        }), total_retries + attempt);
                    }
                    r = api_call => r,
                };

                match result {
                    Ok(Ok(list)) => {
                        total_retries += attempt;
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
                        return (CachedQueryResult::Failure(w), total_retries + attempt);
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
                            tokio::time::sleep(delay).await;
                            continue;
                        }
                        return (
                            CachedQueryResult::Failure(ScanWarning::Timeout {
                                gvr,
                                message: Some(format!(
                                    "LIST timeout ({}s)",
                                    SCAN_REQUEST_TIMEOUT_SECS
                                )),
                                retries: attempt,
                            }),
                            total_retries + attempt,
                        );
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
                    return (
                        CachedQueryResult::Failure(ScanWarning::Other {
                            gvr,
                            message: "exhausted retries".to_string(),
                        }),
                        total_retries + MAX_RETRIES,
                    );
                }
            }
        }

        (
            CachedQueryResult::ListSuccess {
                items: Arc::new(all_items),
                pages,
            },
            total_retries,
        )
    }

    pub async fn metrics(&self) -> PlannerMetrics {
        let flights = self.flights.lock().await;
        let mut completed = 0;
        let mut incomplete = 0;
        for flight in flights.values() {
            match flight.cell.get() {
                Some(cq) if cq.result.is_success() => completed += 1,
                Some(_) => incomplete += 1,
                None => incomplete += 1,
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

    /// Record all completed queries to a CoverageLedger, using final requirements
    /// and per-query elapsed_ms.
    pub async fn flush_to_ledger(&self, ledger: &SharedLedger) {
        let flights = self.flights.lock().await;
        let reqs = self.requirements.lock().await;

        let mut entries: Vec<_> = flights.iter().collect();
        entries.sort_by_key(|(k, _)| (*k).clone());

        for (key, flight) in entries {
            if let Some(cq) = flight.cell.get() {
                let requirement = reqs.get(key).cloned().unwrap_or(QueryRequirement::Optional);
                let outcome = cq.result.to_outcome();
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
                        elapsed_ms: cq.elapsed_ms,
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
            .map(|(key, flight)| {
                let requirement = reqs.get(key).cloned().unwrap_or(QueryRequirement::Optional);
                let (outcome, status) = match flight.cell.get() {
                    Some(cq) => (Some(cq.result.to_outcome()), "completed".to_string()),
                    None => (None, "in_flight".to_string()),
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

// ── Secret redaction ────────────────────────────────────────────

fn redact_secret_data(result: CachedQueryResult) -> CachedQueryResult {
    match result {
        CachedQueryResult::GetSuccess(mut obj) => {
            strip_secret_fields(&mut obj);
            CachedQueryResult::GetSuccess(obj)
        }
        CachedQueryResult::ListSuccess { items, pages } => {
            let mut items_vec = (*items).clone();
            for obj in &mut items_vec {
                strip_secret_fields(obj);
            }
            CachedQueryResult::ListSuccess {
                items: Arc::new(items_vec),
                pages,
            }
        }
        f @ CachedQueryResult::Failure(_) => f,
    }
}

fn strip_secret_fields(obj: &mut DynamicObject) {
    let kind = obj
        .types
        .as_ref()
        .map(|t| t.kind.as_str())
        .or_else(|| obj.data.get("kind").and_then(|v| v.as_str()))
        .unwrap_or("");
    if kind == "Secret" {
        if let Some(data) = obj.data.get_mut("data") {
            *data = serde_json::Value::Object(serde_json::Map::new());
        }
        if let Some(sd) = obj.data.get_mut("stringData") {
            *sd = serde_json::Value::Object(serde_json::Map::new());
        }
    }
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
        let key = QueryKey::list_with_label(
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
            let (_req, send) = handle.next_request().await.expect("req 1");
            rc.fetch_add(1, Ordering::SeqCst);
            send.send_response(json_response(deploy_get_response("myapp")));
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

    // Test 6: Persistent 500 = 3 attempts, retries=2, shared failure
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

        let metrics = planner.metrics().await;
        assert_eq!(
            metrics.retry_count, 2,
            "3 requests = 2 retries (first attempt is not a retry)"
        );

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
            let (_req, send) = handle.next_request().await.expect("req 1");
            rc.fetch_add(1, Ordering::SeqCst);
            send.send_response(status_response(500, "Internal Server Error"));
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
            let (_req, send) = handle.next_request().await.expect("page 1");
            rc.fetch_add(1, Ordering::SeqCst);
            send.send_response(json_response(serde_json::json!({
                "apiVersion": "apps/v1",
                "kind": "DeploymentList",
                "metadata": {"resourceVersion": "1", "continue": "token-1"},
                "items": [{"apiVersion": "apps/v1", "kind": "Deployment", "metadata": {"name": "d1", "namespace": "test-ns", "uid": "uid-d1"}}]
            })));
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

    // Test 10: Cancellation interrupts running query via select!
    #[tokio::test]
    async fn cancellation_interrupts_running_query() {
        let (mock_service, handle) = tower_test::mock::pair::<
            http::Request<kube::client::Body>,
            http::Response<kube::client::Body>,
        >();
        let client = Client::new(mock_service, "test-ns");
        let planner = QueryPlanner::new(None);

        // Hold the mock request without responding
        let spawned = tokio::spawn(async move {
            use std::pin::pin;
            let mut handle = pin!(handle);
            let (_req, _send) = handle.next_request().await.expect("req");
            // Don't respond — simulates a slow server
            tokio::time::sleep(std::time::Duration::from_secs(60)).await;
        });

        let p = planner.clone();
        let c = client.clone();
        let query_task = tokio::spawn(async move {
            p.get(
                &c,
                "apps",
                "v1",
                "deployments",
                Some("test-ns"),
                "myapp",
                QueryRequirement::Required,
            )
            .await
        });

        // Give the query time to start
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        planner.cancel();

        // The query should return quickly with cancelled error
        let result = tokio::time::timeout(std::time::Duration::from_secs(2), query_task)
            .await
            .expect("should complete within 2s")
            .unwrap();

        assert!(result.is_err());
        let err = result.unwrap_err();
        match err {
            ScanWarning::Other { message, .. } => assert!(
                message.contains("cancelled"),
                "expected cancelled, got: {}",
                message
            ),
            other => panic!("expected Other/cancelled, got: {:?}", other),
        }

        spawned.abort();
    }

    // Test 11: Stable sort regardless of insertion order
    #[tokio::test]
    async fn stable_sort_regardless_of_insertion_order() {
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
                let flight = Arc::new(Flight::default());
                let _ = flight.cell.set(CompletedQuery {
                    result: CachedQueryResult::Failure(ScanWarning::NotFound {
                        gvr: key.gvr_string(),
                    }),
                    elapsed_ms: 10,
                    retries: 0,
                });
                flights.insert(key.clone(), flight);
            }
            drop(flights);
            planner.query_plan_sorted().await
        };

        let plan_reverse = {
            let planner = QueryPlanner::new(None);
            let mut flights = planner.flights.lock().await;
            for key in keys.iter().rev() {
                let flight = Arc::new(Flight::default());
                let _ = flight.cell.set(CompletedQuery {
                    result: CachedQueryResult::Failure(ScanWarning::NotFound {
                        gvr: key.gvr_string(),
                    }),
                    elapsed_ms: 10,
                    retries: 0,
                });
                flights.insert(key.clone(), flight);
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

    // Test 12: Secret data stripped from cache — Debug/JSON representation clean
    #[tokio::test]
    async fn secret_data_redacted_from_cache() {
        let secret_value = "super-secret-token-12345";
        let secret_obj = serde_json::json!({
            "apiVersion": "v1",
            "kind": "Secret",
            "metadata": {"name": "my-secret", "namespace": "test-ns", "uid": "uid-secret"},
            "data": {"token": secret_value},
            "stringData": {"password": "hunter2"}
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

        let result = planner
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

        // The GET succeeds but data is redacted
        let obj = result.unwrap();
        let data = obj.data.get("data").unwrap();
        assert!(data.as_object().unwrap().is_empty(), "data should be empty");
        let sd = obj.data.get("stringData").unwrap();
        assert!(
            sd.as_object().unwrap().is_empty(),
            "stringData should be empty"
        );

        // Verify Debug representation doesn't contain secret values
        let debug = format!("{:?}", obj);
        assert!(
            !debug.contains(secret_value),
            "Secret value must not appear in Debug"
        );
        assert!(
            !debug.contains("hunter2"),
            "stringData value must not appear in Debug"
        );

        // Verify metrics/plan JSON don't contain secrets
        let metrics = planner.metrics().await;
        let metrics_json = serde_json::to_string(&metrics).unwrap();
        assert!(!metrics_json.contains(secret_value));
        let plan = planner.query_plan_sorted().await;
        let plan_json = serde_json::to_string(&plan).unwrap();
        assert!(!plan_json.contains(secret_value));
    }

    // Test: GET vs LIST for same GVR are separate queries
    #[test]
    fn get_and_list_are_separate_keys() {
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
    #[test]
    fn different_selectors_are_separate_keys() {
        let k1 = QueryKey::list_with_label(
            CanonicalGvr::new("apps", "v1", "deployments"),
            Some("ns".to_string()),
            "app=foo".to_string(),
        );
        let k2 = QueryKey::list_with_label(
            CanonicalGvr::new("apps", "v1", "deployments"),
            Some("ns".to_string()),
            "app=bar".to_string(),
        );
        assert_ne!(k1, k2);
    }

    // Test: Different namespaces are separate keys
    #[test]
    fn different_namespaces_are_separate_keys() {
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
    #[test]
    fn different_gvrs_are_separate_keys() {
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

    // Test: Different field selectors are separate keys
    #[test]
    fn different_field_selectors_are_separate_keys() {
        let k1 = QueryKey::list_with_field(
            CanonicalGvr::new("", "v1", "pods"),
            Some("ns".to_string()),
            "spec.nodeName=node1".to_string(),
        );
        let k2 = QueryKey::list_with_field(
            CanonicalGvr::new("", "v1", "pods"),
            Some("ns".to_string()),
            "spec.nodeName=node2".to_string(),
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
        assert!(
            !QueryOutcome::Success { count: 5, pages: 1 }
                .is_incomplete(&QueryRequirement::Required)
        );
        assert!(QueryOutcome::Forbidden { status: 403 }.is_incomplete(&QueryRequirement::Required));
        assert!(QueryOutcome::ApiAbsent.is_incomplete(&QueryRequirement::Required));
        assert!(QueryOutcome::TargetMissing.is_incomplete(&QueryRequirement::Required));
        assert!(!QueryOutcome::ApiAbsent.is_incomplete(&QueryRequirement::Optional));
        assert!(!QueryOutcome::TargetMissing.is_incomplete(&QueryRequirement::Optional));
        assert!(QueryOutcome::Forbidden { status: 403 }.is_incomplete(&QueryRequirement::Optional));
        assert!(
            !QueryOutcome::Success { count: 0, pages: 1 }
                .is_incomplete(&QueryRequirement::Optional)
        );
    }

    // Test 15: OnceCell single-flight is race-free (P0-2 regression test)
    // Leader completes before follower registers — follower must still get the result.
    #[tokio::test]
    async fn oncecell_no_lost_wakeup() {
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
            // Respond immediately — leader completes fast
            send.send_response(json_response(deploy_get_response("myapp")));
        });

        // Leader demand
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
        spawned.await.unwrap();

        // Follower demand after leader already completed — no hang
        let result = tokio::time::timeout(
            std::time::Duration::from_secs(1),
            planner.get(
                &client,
                "apps",
                "v1",
                "deployments",
                Some("test-ns"),
                "myapp",
                QueryRequirement::Optional,
            ),
        )
        .await;
        assert!(
            result.is_ok(),
            "follower must not hang when leader already completed"
        );
        assert!(result.unwrap().is_ok());
    }

    // Test: Selector LIST is paginated
    #[tokio::test]
    async fn selector_list_paginated() {
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
            // Page 1 with continue token
            let (req, send) = handle.next_request().await.expect("page 1");
            rc.fetch_add(1, Ordering::SeqCst);
            let uri = req.uri().to_string();
            assert!(
                uri.contains("labelSelector"),
                "request should contain labelSelector: {}",
                uri
            );
            send.send_response(json_response(serde_json::json!({
                "apiVersion": "v1",
                "kind": "PodList",
                "metadata": {"resourceVersion": "1", "continue": "tok-1"},
                "items": [{"apiVersion": "v1", "kind": "Pod", "metadata": {"name": "p1", "namespace": "test-ns", "uid": "uid-p1"}}]
            })));
            // Page 2
            let (_req, send) = handle.next_request().await.expect("page 2");
            rc.fetch_add(1, Ordering::SeqCst);
            send.send_response(json_response(serde_json::json!({
                "apiVersion": "v1",
                "kind": "PodList",
                "metadata": {"resourceVersion": "2"},
                "items": [{"apiVersion": "v1", "kind": "Pod", "metadata": {"name": "p2", "namespace": "test-ns", "uid": "uid-p2"}}]
            })));
        });

        let items = planner
            .list_with_selector(
                &client,
                "",
                "v1",
                "pods",
                Some("test-ns"),
                "app=myapp",
                QueryRequirement::Required,
            )
            .await
            .unwrap();

        spawned.await.unwrap();
        assert_eq!(items.len(), 2, "both pages must be collected");
        assert_eq!(request_count.load(Ordering::SeqCst), 2);
    }

    // Test: flush_to_ledger includes per-query elapsed_ms
    #[tokio::test]
    async fn flush_preserves_elapsed_ms() {
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

        let ledger: SharedLedger = Arc::new(std::sync::Mutex::new(
            crate::kube::resource::CoverageLedger::new(),
        ));
        planner.flush_to_ledger(&ledger).await;

        let l = ledger.lock().unwrap();
        assert_eq!(l.records.len(), 1);
        // elapsed_ms may be 0 in fast mock but must not be hardcoded to 0
        // The important thing is the field comes from CompletedQuery, not 0
    }

    // P0-1 regression: flush_to_ledger produces correct coverage for strict
    #[tokio::test]
    async fn flush_coverage_includes_planner_queries_for_strict() {
        use std::pin::pin;

        let (mock_service, handle) = tower_test::mock::pair::<
            http::Request<kube::client::Body>,
            http::Response<kube::client::Body>,
        >();
        let client = Client::new(mock_service, "test-ns");
        let planner = QueryPlanner::new(None);

        let spawned = tokio::spawn(async move {
            let mut handle = pin!(handle);
            // Success GET
            let (_req, send) = handle.next_request().await.expect("req 1");
            tokio::time::sleep(std::time::Duration::from_millis(5)).await;
            send.send_response(json_response(deploy_get_response("myapp")));
            // 403 GET
            let (_req, send) = handle.next_request().await.expect("req 2");
            send.send_response(status_response(403, "Forbidden"));
        });

        // Required success
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

        // Required failure
        let r2 = planner
            .get(
                &client,
                "",
                "v1",
                "secrets",
                Some("test-ns"),
                "forbidden-secret",
                QueryRequirement::Required,
            )
            .await;
        assert!(r2.is_err());

        spawned.await.unwrap();

        let ledger: SharedLedger = Arc::new(std::sync::Mutex::new(
            crate::kube::resource::CoverageLedger::new(),
        ));
        planner.flush_to_ledger(&ledger).await;

        let l = ledger.lock().unwrap();
        assert_eq!(
            l.records.len(),
            2,
            "ledger should have 2 records after flush"
        );
        assert_eq!(
            l.incomplete_count(),
            1,
            "one Required failure = 1 incomplete"
        );
        assert!(l.has_incomplete(), "strict should detect incomplete");

        // elapsed_ms should be > 0 for at least the delayed response
        let total_elapsed: u64 = l.records.iter().map(|r| r.elapsed_ms).sum();
        assert!(
            total_elapsed > 0,
            "total elapsed should be > 0, got {}",
            total_elapsed
        );
    }
}
