use kube::Client;
use kube::api::DynamicObject;

use crate::analyzers::adapters::{
    AdapterEvidence, AdapterReport, AdapterReportStatus, AdapterResolution, AdapterResult,
};
use crate::analyzers::inspect::{Confidence, InspectedResource, Relationship};
use crate::analyzers::olm::OperatorInstance;
use crate::kube::resource::{QueryRequirement, ResourceId};
use crate::kube::scanner::SharedPlanner;

pub const ADAPTER_ID: &str = "nfd-finalizer-cleanup";

const SUPPORTED_CSV_VERSIONS: &[&str] = &["4.22.0-202609151747"];

const SOURCE_COMMIT: &str = "3931a6191fa842897327f105a862f58f59db1a7d";
const SOURCE_URL: &str = "https://github.com/openshift/cluster-nfd-operator/tree/3931a6191fa842897327f105a862f58f59db1a7d";
const CLEANUP_FUNCTION: &str =
    "internal/controllers/nodefeaturediscovery_reconciler.go:finalizeComponents";
const NAMING_FUNCTION: &str = "internal/controllers/nodefeaturediscovery_reconciler.go:handleSCCs (hardcoded deterministic names)";
const BINDING_NOTE: &str = "binding=package nfd + exact CSV 4.22.0-202609151747 (corpus/live empirical); source contract reference=upstream commit 3931a619 (approximate for downstream image)";

const ROOT_GROUP: &str = "nfd.openshift.io";
const ROOT_VERSION: &str = "v1";
const ROOT_KIND: &str = "NodeFeatureDiscovery";

const SCC_NAMES: [&str; 2] = ["nfd-topology-updater", "nfd-worker"];

fn extract_csv_version(csv_name: &str) -> Option<&str> {
    csv_name.strip_prefix("nfd.")
}

pub fn matches_operator(operator: &OperatorInstance) -> bool {
    operator.package_name.as_deref().is_some_and(|p| p == "nfd")
}

pub fn find_nfd_roots(cr_resources: &[InspectedResource]) -> Vec<ResourceId> {
    let mut roots: Vec<ResourceId> = cr_resources
        .iter()
        .map(|r| &r.id)
        .filter(|id| {
            id.group == ROOT_GROUP
                && id.version == ROOT_VERSION
                && id.kind == ROOT_KIND
                && id.namespace.as_deref().is_some_and(|ns| !ns.is_empty())
                && id.uid.as_deref().is_some_and(|uid| !uid.is_empty())
        })
        .cloned()
        .collect();
    roots.sort_by(|a, b| (&a.namespace, &a.name, &a.uid).cmp(&(&b.namespace, &b.name, &b.uid)));
    roots.dedup_by(|a, b| a.uid == b.uid);
    roots
}

pub fn make_evidence(csv_name: &str) -> AdapterEvidence {
    AdapterEvidence {
        adapter_id: ADAPTER_ID.to_string(),
        source_commit: SOURCE_COMMIT.to_string(),
        source_url: SOURCE_URL.to_string(),
        cleanup_function: CLEANUP_FUNCTION.to_string(),
        naming_function: NAMING_FUNCTION.to_string(),
        matched_csv_version: csv_name.to_string(),
        binding_note: Some(BINDING_NOTE.to_string()),
    }
}

pub fn resolve_scc(expected_name: &str, obj: &DynamicObject) -> Result<ResourceId, String> {
    let tm = obj
        .types
        .as_ref()
        .ok_or_else(|| "missing type metadata".to_string())?;
    if tm.api_version != "security.openshift.io/v1" {
        return Err(format!(
            "apiVersion mismatch: expected security.openshift.io/v1, got {}",
            tm.api_version
        ));
    }
    if tm.kind != "SecurityContextConstraints" {
        return Err(format!(
            "kind mismatch: expected SecurityContextConstraints, got {}",
            tm.kind
        ));
    }
    let actual_name = obj.metadata.name.as_deref().unwrap_or("");
    if actual_name != expected_name {
        return Err(format!(
            "name mismatch: expected {}, got {}",
            expected_name, actual_name
        ));
    }
    let uid = obj
        .metadata
        .uid
        .as_deref()
        .filter(|u| !u.is_empty())
        .ok_or_else(|| "missing or empty UID".to_string())?;
    Ok(ResourceId {
        group: "security.openshift.io".to_string(),
        version: "v1".to_string(),
        kind: "SecurityContextConstraints".to_string(),
        namespace: None,
        name: expected_name.to_string(),
        uid: Some(uid.to_string()),
    })
}

pub async fn discover(
    client: &Client,
    operator: &OperatorInstance,
    planner: &SharedPlanner,
    roots: &[ResourceId],
) -> AdapterReport {
    let csv_name = &operator.csv.name;
    let evidence = make_evidence(csv_name);

    match extract_csv_version(csv_name) {
        Some(v) if SUPPORTED_CSV_VERSIONS.contains(&v) => {}
        Some(v) => {
            return AdapterReport {
                adapter_id: ADAPTER_ID.to_string(),
                status: AdapterReportStatus::Unknown,
                status_reason: Some(format!("UnsupportedVersion: {}", v)),
                evidence: Some(evidence),
                results: vec![],
                diagnostics: vec![format!(
                    "UnsupportedVersion: CSV {} version {} not in supported set {:?}",
                    csv_name, v, SUPPORTED_CSV_VERSIONS
                )],
                incomplete: false,
            };
        }
        None => {
            return AdapterReport {
                adapter_id: ADAPTER_ID.to_string(),
                status: AdapterReportStatus::Unknown,
                status_reason: Some(format!(
                    "UnsupportedVersion: cannot parse version from '{}'",
                    csv_name
                )),
                evidence: Some(evidence),
                results: vec![],
                diagnostics: vec![format!(
                    "UnsupportedVersion: cannot parse version from '{}'",
                    csv_name
                )],
                incomplete: false,
            };
        }
    };

    let mut sorted_roots = roots.to_vec();
    sorted_roots
        .sort_by(|a, b| (&a.namespace, &a.name, &a.uid).cmp(&(&b.namespace, &b.name, &b.uid)));
    sorted_roots.dedup_by(|a, b| a.uid == b.uid);
    let roots = &sorted_roots;

    if roots.is_empty() {
        return AdapterReport {
            adapter_id: ADAPTER_ID.to_string(),
            status: AdapterReportStatus::NotApplicable,
            status_reason: Some(
                "no NodeFeatureDiscovery CR roots found in discovered resources".to_string(),
            ),
            evidence: Some(evidence),
            results: vec![],
            diagnostics: vec![],
            incomplete: false,
        };
    }

    if roots.len() > 1 {
        return AdapterReport {
            adapter_id: ADAPTER_ID.to_string(),
            status: AdapterReportStatus::Unknown,
            status_reason: Some(format!(
                "Ambiguous: {} NodeFeatureDiscovery roots found; shared fixed SCC names prevent safe attribution",
                roots.len()
            )),
            evidence: Some(evidence),
            results: vec![],
            diagnostics: vec![format!(
                "Ambiguous: {} roots share deterministic SCC names nfd-worker/nfd-topology-updater; cannot attribute safely",
                roots.len()
            )],
            incomplete: false,
        };
    }

    let root = &roots[0];
    let mut results = Vec::new();
    let mut diagnostics = Vec::new();
    let mut has_unknown = false;

    for scc_name in &SCC_NAMES {
        let get_result = planner
            .get(
                client,
                "security.openshift.io",
                "v1",
                "securitycontextconstraints",
                None,
                scc_name,
                QueryRequirement::Optional,
            )
            .await;

        match get_result {
            Ok(obj) => match resolve_scc(scc_name, &obj) {
                Ok(verified_id) => {
                    results.push(AdapterResult {
                        resource: InspectedResource {
                            id: verified_id,
                            source_id: Some(root.clone()),
                            relationship: Relationship::CleansUp,
                            evidence: format!(
                                "adapter:{}; commit:{}; cleanup:{}; naming:{}; root:{}/{}",
                                ADAPTER_ID,
                                SOURCE_COMMIT,
                                CLEANUP_FUNCTION,
                                NAMING_FUNCTION,
                                root.kind,
                                root.name
                            ),
                            confidence: Confidence::Managed,
                        },
                        resolution: AdapterResolution::Resolved,
                        adapter_evidence: evidence.clone(),
                    });
                }
                Err(mismatch) => {
                    has_unknown = true;
                    diagnostics.push(format!(
                        "SecurityContextConstraints/{}: identity mismatch: {}",
                        scc_name, mismatch
                    ));
                    results.push(AdapterResult {
                        resource: InspectedResource {
                            id: ResourceId {
                                group: "security.openshift.io".to_string(),
                                version: "v1".to_string(),
                                kind: "SecurityContextConstraints".to_string(),
                                namespace: None,
                                name: scc_name.to_string(),
                                uid: None,
                            },
                            source_id: Some(root.clone()),
                            relationship: Relationship::CleansUp,
                            evidence: format!(
                                "adapter:{}; commit:{}; root:{}/{}; identity-mismatch:{}",
                                ADAPTER_ID, SOURCE_COMMIT, root.kind, root.name, mismatch
                            ),
                            confidence: Confidence::Managed,
                        },
                        resolution: AdapterResolution::Unknown,
                        adapter_evidence: evidence.clone(),
                    });
                }
            },
            Err(w) => {
                let resolution =
                    crate::analyzers::adapters::authorino::map_scan_warning_to_resolution(&w);
                if resolution == AdapterResolution::Unknown {
                    has_unknown = true;
                }
                diagnostics.push(format!(
                    "SecurityContextConstraints/{}: {} ({})",
                    scc_name, resolution, w
                ));
                results.push(AdapterResult {
                    resource: InspectedResource {
                        id: ResourceId {
                            group: "security.openshift.io".to_string(),
                            version: "v1".to_string(),
                            kind: "SecurityContextConstraints".to_string(),
                            namespace: None,
                            name: scc_name.to_string(),
                            uid: None,
                        },
                        source_id: Some(root.clone()),
                        relationship: Relationship::CleansUp,
                        evidence: format!(
                            "adapter:{}; commit:{}; root:{}/{}; status:{}",
                            ADAPTER_ID, SOURCE_COMMIT, root.kind, root.name, resolution
                        ),
                        confidence: Confidence::Managed,
                    },
                    resolution,
                    adapter_evidence: evidence.clone(),
                });
            }
        }
    }

    AdapterReport {
        adapter_id: ADAPTER_ID.to_string(),
        status: AdapterReportStatus::Applied,
        status_reason: None,
        evidence: Some(evidence),
        results,
        diagnostics,
        incomplete: has_unknown,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::analyzers::adapters::{AdapterReport, merge_adapter_reports};
    use crate::kube::planner::QueryPlanner;
    use std::sync::Arc;
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

    fn scc_response(name: &str, uid: &str) -> serde_json::Value {
        serde_json::json!({
            "apiVersion": "security.openshift.io/v1",
            "kind": "SecurityContextConstraints",
            "metadata": { "name": name, "uid": uid }
        })
    }

    fn test_operator(csv_name: &str, package: &str) -> OperatorInstance {
        OperatorInstance {
            subscription: None,
            package_name: Some(package.to_string()),
            csv: ResourceId {
                group: "operators.coreos.com".to_string(),
                version: "v1alpha1".to_string(),
                kind: "ClusterServiceVersion".to_string(),
                namespace: Some("openshift-nfd".to_string()),
                name: csv_name.to_string(),
                uid: Some("csv-uid-nfd".to_string()),
            },
            csv_phase: "Succeeded".to_string(),
            owned_crds: vec![],
            required_crds: vec![],
            owned_api_service_defs: vec![],
            required_api_service_defs: vec![],
            deployments: vec![],
            service_accounts: vec![],
            install_namespace: "openshift-nfd".to_string(),
            has_unlinked_subscriptions: false,
        }
    }

    fn default_root() -> ResourceId {
        ResourceId {
            group: "nfd.openshift.io".to_string(),
            version: "v1".to_string(),
            kind: "NodeFeatureDiscovery".to_string(),
            namespace: Some("openshift-nfd".to_string()),
            name: "nfd-instance".to_string(),
            uid: Some("root-uid-nfd".to_string()),
        }
    }

    fn custom_root(name: &str, uid: &str) -> ResourceId {
        ResourceId {
            group: "nfd.openshift.io".to_string(),
            version: "v1".to_string(),
            kind: "NodeFeatureDiscovery".to_string(),
            namespace: Some("openshift-nfd".to_string()),
            name: name.to_string(),
            uid: Some(uid.to_string()),
        }
    }

    // Test 1: supported version + one root -> exact 2 GET paths, 2 Resolved, source_id=root
    #[tokio::test]
    async fn one_root_both_scc_resolved() {
        let request_count = Arc::new(AtomicUsize::new(0));
        let rc = request_count.clone();

        let (mock_service, handle) = tower_test::mock::pair::<
            http::Request<kube::client::Body>,
            http::Response<kube::client::Body>,
        >();
        let client = kube::Client::new(mock_service, "default");
        let planner = QueryPlanner::new(None);

        let spawned = tokio::spawn(async move {
            use std::pin::pin;
            let mut handle = pin!(handle);
            let mut paths = Vec::new();

            let (req, send) = handle.next_request().await.expect("req 1");
            rc.fetch_add(1, Ordering::SeqCst);
            paths.push(req.uri().path().to_string());
            send.send_response(json_response(scc_response("nfd-topology-updater", "uid-1")));

            let (req, send) = handle.next_request().await.expect("req 2");
            rc.fetch_add(1, Ordering::SeqCst);
            paths.push(req.uri().path().to_string());
            send.send_response(json_response(scc_response("nfd-worker", "uid-2")));

            paths
        });

        let operator = test_operator("nfd.4.22.0-202609151747", "nfd");
        let roots = vec![default_root()];
        let report = discover(&client, &operator, &planner, &roots).await;
        let request_paths = spawned.await.unwrap();

        assert_eq!(report.status, AdapterReportStatus::Applied);
        assert!(!report.incomplete);
        assert_eq!(report.results.len(), 2);
        assert!(report.diagnostics.is_empty());
        assert_eq!(
            request_paths[0],
            "/apis/security.openshift.io/v1/securitycontextconstraints/nfd-topology-updater"
        );
        assert_eq!(
            request_paths[1],
            "/apis/security.openshift.io/v1/securitycontextconstraints/nfd-worker"
        );

        for r in &report.results {
            assert_eq!(r.resolution, AdapterResolution::Resolved);
            assert!(r.resource.id.uid.is_some());
            let src = r.resource.source_id.as_ref().unwrap();
            assert_eq!(src.kind, "NodeFeatureDiscovery");
            assert_eq!(src.name, "nfd-instance");
            assert_eq!(src.uid, Some("root-uid-nfd".to_string()));
        }

        let metrics = planner.metrics().await;
        assert_eq!(metrics.network_queries, 2);
        assert_eq!(request_count.load(Ordering::SeqCst), 2);
    }

    // Test 2: root 0 -> NotApplicable, query 0
    #[tokio::test]
    async fn zero_roots_not_applicable() {
        let (mock_service, _handle) = tower_test::mock::pair::<
            http::Request<kube::client::Body>,
            http::Response<kube::client::Body>,
        >();
        let client = kube::Client::new(mock_service, "default");
        let planner = QueryPlanner::new(None);

        let operator = test_operator("nfd.4.22.0-202609151747", "nfd");
        let report = discover(&client, &operator, &planner, &[]).await;

        assert_eq!(report.status, AdapterReportStatus::NotApplicable);
        assert!(report.results.is_empty());
        assert!(report.evidence.is_some());

        let metrics = planner.metrics().await;
        assert_eq!(metrics.network_queries, 0);
    }

    // Test 3: root >1 -> Unknown/Ambiguous, query 0
    #[tokio::test]
    async fn multiple_roots_ambiguous() {
        let (mock_service, _handle) = tower_test::mock::pair::<
            http::Request<kube::client::Body>,
            http::Response<kube::client::Body>,
        >();
        let client = kube::Client::new(mock_service, "default");
        let planner = QueryPlanner::new(None);

        let operator = test_operator("nfd.4.22.0-202609151747", "nfd");
        let roots = vec![custom_root("nfd-a", "uid-a"), custom_root("nfd-b", "uid-b")];
        let report = discover(&client, &operator, &planner, &roots).await;

        assert_eq!(report.status, AdapterReportStatus::Unknown);
        assert!(report.status_reason.as_ref().unwrap().contains("Ambiguous"));
        assert!(report.results.is_empty());

        let metrics = planner.metrics().await;
        assert_eq!(metrics.network_queries, 0);
    }

    // Test 4: wrong package -> adapter not dispatched
    #[test]
    fn wrong_package_no_match() {
        let operator = test_operator("nfd.4.22.0-202609151747", "some-other-operator");
        assert!(!matches_operator(&operator));
    }

    // Test 5: unsupported CSV -> Unknown/UnsupportedVersion, query 0
    #[tokio::test]
    async fn unsupported_version_unknown_status() {
        let (mock_service, _handle) = tower_test::mock::pair::<
            http::Request<kube::client::Body>,
            http::Response<kube::client::Body>,
        >();
        let client = kube::Client::new(mock_service, "default");
        let planner = QueryPlanner::new(None);

        let operator = test_operator("nfd.5.0.0-999999", "nfd");
        let report = discover(&client, &operator, &planner, &[default_root()]).await;

        assert_eq!(report.status, AdapterReportStatus::Unknown);
        assert!(
            report
                .status_reason
                .as_ref()
                .unwrap()
                .contains("UnsupportedVersion")
        );
        assert!(report.evidence.is_some());
        assert!(report.results.is_empty());

        let metrics = planner.metrics().await;
        assert_eq!(metrics.network_queries, 0);

        let json = serde_json::to_value(&report).unwrap();
        assert_eq!(json["status"], "Unknown");
        assert!(
            json["status_reason"]
                .as_str()
                .unwrap()
                .contains("UnsupportedVersion")
        );
    }

    // Test 6: one 404 + one success -> TargetMissing + Resolved
    #[tokio::test]
    async fn one_scc_missing_404() {
        let (mock_service, handle) = tower_test::mock::pair::<
            http::Request<kube::client::Body>,
            http::Response<kube::client::Body>,
        >();
        let client = kube::Client::new(mock_service, "default");
        let planner = QueryPlanner::new(None);

        let spawned = tokio::spawn(async move {
            use std::pin::pin;
            let mut handle = pin!(handle);
            let (_req, send) = handle.next_request().await.expect("req 1");
            send.send_response(json_response(scc_response("nfd-topology-updater", "uid-1")));
            let (_req, send) = handle.next_request().await.expect("req 2");
            send.send_response(status_response(404, "NotFound"));
        });

        let operator = test_operator("nfd.4.22.0-202609151747", "nfd");
        let report = discover(&client, &operator, &planner, &[default_root()]).await;
        spawned.await.unwrap();

        assert_eq!(report.status, AdapterReportStatus::Applied);
        assert!(!report.incomplete);
        assert_eq!(report.results[0].resolution, AdapterResolution::Resolved);
        assert_eq!(
            report.results[1].resolution,
            AdapterResolution::TargetMissing
        );

        let ledger: crate::kube::scanner::SharedLedger = std::sync::Arc::new(
            std::sync::Mutex::new(crate::kube::resource::CoverageLedger::new()),
        );
        planner.flush_to_ledger(&ledger).await;
        let guard = ledger.lock().unwrap();
        assert!(!guard.has_incomplete());
    }

    // Test 7: 403 -> Unknown/incomplete, exactly 1 report warning, strict true after planner flush
    #[tokio::test]
    async fn forbidden_produces_unknown_incomplete() {
        let (mock_service, handle) = tower_test::mock::pair::<
            http::Request<kube::client::Body>,
            http::Response<kube::client::Body>,
        >();
        let client = kube::Client::new(mock_service, "default");
        let planner = QueryPlanner::new(None);

        let spawned = tokio::spawn(async move {
            use std::pin::pin;
            let mut handle = pin!(handle);
            let (_req, send) = handle.next_request().await.expect("req 1");
            send.send_response(status_response(403, "Forbidden"));
            let (_req, send) = handle.next_request().await.expect("req 2");
            send.send_response(status_response(403, "Forbidden"));
        });

        let operator = test_operator("nfd.4.22.0-202609151747", "nfd");
        let report = discover(&client, &operator, &planner, &[default_root()]).await;
        spawned.await.unwrap();

        assert!(report.incomplete);
        assert_eq!(report.status, AdapterReportStatus::Applied);
        for r in &report.results {
            assert_eq!(r.resolution, AdapterResolution::Unknown);
        }
        assert_eq!(report.diagnostics.len(), 2);

        let merged = merge_adapter_reports(&[report]);
        assert_eq!(merged.incomplete_count, 1);
        assert_eq!(merged.warnings.len(), 1);
        assert_eq!(merged.resources.len(), 0);
    }

    // Test 8: response wrong apiVersion/kind/name/missing UID -> Unknown/incomplete
    #[tokio::test]
    async fn identity_mismatch_produces_unknown() {
        let (mock_service, handle) = tower_test::mock::pair::<
            http::Request<kube::client::Body>,
            http::Response<kube::client::Body>,
        >();
        let client = kube::Client::new(mock_service, "default");
        let planner = QueryPlanner::new(None);

        let spawned = tokio::spawn(async move {
            use std::pin::pin;
            let mut handle = pin!(handle);
            let (_req, send) = handle.next_request().await.expect("req 1");
            send.send_response(json_response(serde_json::json!({
                "apiVersion": "v1",
                "kind": "ConfigMap",
                "metadata": { "name": "nfd-topology-updater", "uid": "uid-wrong" }
            })));
            let (_req, send) = handle.next_request().await.expect("req 2");
            send.send_response(json_response(scc_response("nfd-worker", "uid-2")));
        });

        let operator = test_operator("nfd.4.22.0-202609151747", "nfd");
        let report = discover(&client, &operator, &planner, &[default_root()]).await;
        spawned.await.unwrap();

        assert!(report.incomplete);
        assert_eq!(report.results[0].resolution, AdapterResolution::Unknown);
        assert!(report.results[0].resource.id.uid.is_none());
        assert_eq!(report.results[1].resolution, AdapterResolution::Resolved);
        assert!(report.results[1].resource.id.uid.is_some());
        assert_eq!(report.diagnostics.len(), 1);
        assert!(report.diagnostics[0].contains("identity mismatch"));
    }

    // Test 9: root input reversal -> byte-identical output (N/A for NFD: >1 roots = Ambiguous)
    // NFD uses fixed names shared across all roots, so >1 roots returns Ambiguous.
    // Instead test that a single root always produces deterministic output.
    #[tokio::test]
    async fn single_root_deterministic() {
        async fn run_once() -> String {
            let (mock_service, handle) = tower_test::mock::pair::<
                http::Request<kube::client::Body>,
                http::Response<kube::client::Body>,
            >();
            let client = kube::Client::new(mock_service, "default");
            let planner = QueryPlanner::new(None);

            let spawned = tokio::spawn(async move {
                use std::pin::pin;
                let mut handle = pin!(handle);
                let (_req, send) = handle.next_request().await.expect("req 1");
                send.send_response(json_response(scc_response("nfd-topology-updater", "uid-1")));
                let (_req, send) = handle.next_request().await.expect("req 2");
                send.send_response(json_response(scc_response("nfd-worker", "uid-2")));
            });

            let operator = test_operator("nfd.4.22.0-202609151747", "nfd");
            let report = discover(&client, &operator, &planner, &[default_root()]).await;
            spawned.await.unwrap();
            serde_json::to_string(&report).unwrap()
        }

        let json1 = run_once().await;
        let json2 = run_once().await;
        assert_eq!(json1, json2);
    }

    // Test 10: registry wiring through run_adapters
    #[tokio::test]
    async fn registry_wiring() {
        let (mock_service, handle) = tower_test::mock::pair::<
            http::Request<kube::client::Body>,
            http::Response<kube::client::Body>,
        >();
        let client = kube::Client::new(mock_service, "default");
        let planner = QueryPlanner::new(None);

        let spawned = tokio::spawn(async move {
            use std::pin::pin;
            let mut handle = pin!(handle);
            let (_req, send) = handle.next_request().await.expect("req 1");
            send.send_response(json_response(scc_response("nfd-topology-updater", "uid-1")));
            let (_req, send) = handle.next_request().await.expect("req 2");
            send.send_response(json_response(scc_response("nfd-worker", "uid-2")));
        });

        let operator = test_operator("nfd.4.22.0-202609151747", "nfd");
        let cr_resources = vec![InspectedResource {
            id: default_root(),
            source_id: None,
            relationship: Relationship::OwnedCrdInstance,
            evidence: String::new(),
            confidence: Confidence::Managed,
        }];

        let reports = crate::analyzers::adapters::run_adapters(
            &client,
            &operator,
            Some(&planner),
            &cr_resources,
        )
        .await;
        spawned.await.unwrap();

        assert_eq!(reports.len(), 1);
        assert_eq!(reports[0].adapter_id, ADAPTER_ID);
        assert_eq!(reports[0].status, AdapterReportStatus::Applied);
        assert_eq!(reports[0].results.len(), 2);
    }

    // Test 11: Authorino adapter regression - wrong package for NFD
    #[test]
    fn authorino_package_does_not_match_nfd() {
        let operator = test_operator("nfd.4.22.0-202609151747", "nfd");
        assert!(!crate::analyzers::adapters::authorino::matches_operator(
            &operator
        ));
    }

    // Test 12: resolve_scc identity checks
    #[test]
    fn resolve_scc_wrong_api_version() {
        let obj: DynamicObject = serde_json::from_value(serde_json::json!({
            "apiVersion": "v1",
            "kind": "SecurityContextConstraints",
            "metadata": { "name": "nfd-worker", "uid": "uid-1" }
        }))
        .unwrap();
        assert!(
            resolve_scc("nfd-worker", &obj)
                .unwrap_err()
                .contains("apiVersion mismatch")
        );
    }

    #[test]
    fn resolve_scc_wrong_kind() {
        let obj: DynamicObject = serde_json::from_value(serde_json::json!({
            "apiVersion": "security.openshift.io/v1",
            "kind": "ConfigMap",
            "metadata": { "name": "nfd-worker", "uid": "uid-1" }
        }))
        .unwrap();
        assert!(
            resolve_scc("nfd-worker", &obj)
                .unwrap_err()
                .contains("kind mismatch")
        );
    }

    #[test]
    fn resolve_scc_wrong_name() {
        let obj: DynamicObject = serde_json::from_value(serde_json::json!({
            "apiVersion": "security.openshift.io/v1",
            "kind": "SecurityContextConstraints",
            "metadata": { "name": "other-name", "uid": "uid-1" }
        }))
        .unwrap();
        assert!(
            resolve_scc("nfd-worker", &obj)
                .unwrap_err()
                .contains("name mismatch")
        );
    }

    #[test]
    fn resolve_scc_missing_uid() {
        let obj: DynamicObject = serde_json::from_value(serde_json::json!({
            "apiVersion": "security.openshift.io/v1",
            "kind": "SecurityContextConstraints",
            "metadata": { "name": "nfd-worker" }
        }))
        .unwrap();
        assert!(resolve_scc("nfd-worker", &obj).unwrap_err().contains("UID"));
    }

    #[test]
    fn resolve_scc_success() {
        let obj: DynamicObject = serde_json::from_value(serde_json::json!({
            "apiVersion": "security.openshift.io/v1",
            "kind": "SecurityContextConstraints",
            "metadata": { "name": "nfd-worker", "uid": "uid-1" }
        }))
        .unwrap();
        let result = resolve_scc("nfd-worker", &obj);
        assert!(result.is_ok());
        let id = result.unwrap();
        assert_eq!(id.uid, Some("uid-1".to_string()));
        assert_eq!(id.kind, "SecurityContextConstraints");
        assert_eq!(id.group, "security.openshift.io");
    }

    // Test: find_nfd_roots version/scope-bound filtering
    #[test]
    fn find_roots_version_scope_bound() {
        fn make_resource(
            group: &str,
            version: &str,
            kind: &str,
            namespace: Option<&str>,
            uid: Option<&str>,
        ) -> InspectedResource {
            InspectedResource {
                id: ResourceId {
                    group: group.to_string(),
                    version: version.to_string(),
                    kind: kind.to_string(),
                    namespace: namespace.map(|s| s.to_string()),
                    name: "nfd-instance".to_string(),
                    uid: uid.map(|s| s.to_string()),
                },
                source_id: None,
                relationship: Relationship::OwnedCrdInstance,
                evidence: String::new(),
                confidence: Confidence::Managed,
            }
        }

        struct Case {
            label: &'static str,
            group: &'static str,
            version: &'static str,
            kind: &'static str,
            namespace: Option<&'static str>,
            uid: Option<&'static str>,
            expected: bool,
        }

        let cases = vec![
            Case {
                label: "v1 namespaced positive",
                group: "nfd.openshift.io",
                version: "v1",
                kind: "NodeFeatureDiscovery",
                namespace: Some("openshift-nfd"),
                uid: Some("uid-1"),
                expected: true,
            },
            Case {
                label: "v1alpha1 negative",
                group: "nfd.openshift.io",
                version: "v1alpha1",
                kind: "NodeFeatureDiscovery",
                namespace: Some("openshift-nfd"),
                uid: Some("uid-2"),
                expected: false,
            },
            Case {
                label: "namespace=None negative (cluster-scoped)",
                group: "nfd.openshift.io",
                version: "v1",
                kind: "NodeFeatureDiscovery",
                namespace: None,
                uid: Some("uid-3"),
                expected: false,
            },
            Case {
                label: "empty namespace negative",
                group: "nfd.openshift.io",
                version: "v1",
                kind: "NodeFeatureDiscovery",
                namespace: Some(""),
                uid: Some("uid-4"),
                expected: false,
            },
            Case {
                label: "UID None negative",
                group: "nfd.openshift.io",
                version: "v1",
                kind: "NodeFeatureDiscovery",
                namespace: Some("openshift-nfd"),
                uid: None,
                expected: false,
            },
            Case {
                label: "empty UID negative",
                group: "nfd.openshift.io",
                version: "v1",
                kind: "NodeFeatureDiscovery",
                namespace: Some("openshift-nfd"),
                uid: Some(""),
                expected: false,
            },
            Case {
                label: "wrong kind negative",
                group: "nfd.openshift.io",
                version: "v1",
                kind: "NodeFeatureRule",
                namespace: Some("openshift-nfd"),
                uid: Some("uid-5"),
                expected: false,
            },
            Case {
                label: "wrong group negative",
                group: "nfd.k8s-sigs.io",
                version: "v1",
                kind: "NodeFeatureDiscovery",
                namespace: Some("openshift-nfd"),
                uid: Some("uid-6"),
                expected: false,
            },
        ];

        for case in &cases {
            let resources = vec![make_resource(
                case.group,
                case.version,
                case.kind,
                case.namespace,
                case.uid,
            )];
            let roots = find_nfd_roots(&resources);
            assert_eq!(
                roots.len(),
                if case.expected { 1 } else { 0 },
                "case '{}' expected roots={}",
                case.label,
                if case.expected { 1 } else { 0 }
            );
        }
    }

    // Test: merge only Resolved+UID
    #[test]
    fn merge_only_resolved_with_uid() {
        let evidence = make_evidence("nfd.4.22.0-202609151747");
        let reports = vec![AdapterReport {
            adapter_id: ADAPTER_ID.to_string(),
            status: AdapterReportStatus::Applied,
            status_reason: None,
            evidence: Some(evidence.clone()),
            results: vec![
                AdapterResult {
                    resource: InspectedResource {
                        id: ResourceId {
                            group: "security.openshift.io".to_string(),
                            version: "v1".to_string(),
                            kind: "SecurityContextConstraints".to_string(),
                            namespace: None,
                            name: "nfd-worker".to_string(),
                            uid: Some("uid-1".to_string()),
                        },
                        source_id: None,
                        relationship: Relationship::CleansUp,
                        evidence: String::new(),
                        confidence: Confidence::Managed,
                    },
                    resolution: AdapterResolution::Resolved,
                    adapter_evidence: evidence.clone(),
                },
                AdapterResult {
                    resource: InspectedResource {
                        id: ResourceId {
                            group: "security.openshift.io".to_string(),
                            version: "v1".to_string(),
                            kind: "SecurityContextConstraints".to_string(),
                            namespace: None,
                            name: "nfd-topology-updater".to_string(),
                            uid: None,
                        },
                        source_id: None,
                        relationship: Relationship::CleansUp,
                        evidence: String::new(),
                        confidence: Confidence::Managed,
                    },
                    resolution: AdapterResolution::TargetMissing,
                    adapter_evidence: evidence.clone(),
                },
            ],
            diagnostics: vec![],
            incomplete: false,
        }];

        let merged = merge_adapter_reports(&reports);
        assert_eq!(merged.resources.len(), 1);
        assert_eq!(merged.resources[0].id.name, "nfd-worker");
        assert_eq!(merged.incomplete_count, 0);
    }
}
