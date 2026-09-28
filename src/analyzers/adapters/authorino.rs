use kube::Client;
use kube::api::DynamicObject;

use crate::analyzers::adapters::{
    AdapterEvidence, AdapterReport, AdapterReportStatus, AdapterResolution, AdapterResult,
};
use crate::analyzers::inspect::{Confidence, InspectedResource, Relationship};
use crate::analyzers::olm::OperatorInstance;
use crate::kube::resource::{QueryRequirement, ResourceId};
use crate::kube::scanner::SharedPlanner;

pub const ADAPTER_ID: &str = "authorino-finalizer-cleanup";

const SUPPORTED_CSV_VERSIONS: &[&str] = &["1.4.3"];

const SOURCE_COMMIT: &str = "e8623b50995c0ff54042e63d83c56d207b324d96";
const SOURCE_URL: &str =
    "https://github.com/Kuadrant/authorino-operator/tree/e8623b50995c0ff54042e63d83c56d207b324d96";
const CLEANUP_FUNCTION: &str =
    "controllers/authorino_controller.go:cleanupClusterScopedPermissions";
const NAMING_FUNCTION: &str = "pkg/resources/k8s_util.go:authorinoClusterRoleBindingName";
const BINDING_NOTE: &str = "binding=package authorino-operator + exact CSV 1.4.3 (corpus/live empirical); source contract reference=upstream commit e8623b50";

fn extract_csv_version(csv_name: &str) -> Option<&str> {
    csv_name.strip_prefix("authorino-operator.v")
}

pub fn matches_operator(operator: &OperatorInstance) -> bool {
    operator
        .package_name
        .as_deref()
        .is_some_and(|p| p == "authorino-operator")
}

pub fn find_authorino_roots(cr_resources: &[InspectedResource]) -> Vec<ResourceId> {
    let mut roots: Vec<ResourceId> = cr_resources
        .iter()
        .map(|r| &r.id)
        .filter(|id| {
            id.group == "operator.authorino.kuadrant.io"
                && id.kind == "Authorino"
                && id.uid.is_some()
        })
        .cloned()
        .collect();
    roots.sort_by(|a, b| (&a.namespace, &a.name, &a.uid).cmp(&(&b.namespace, &b.name, &b.uid)));
    roots.dedup_by(|a, b| a.uid == b.uid);
    roots
}

fn cleanup_crb_names(root_name: &str) -> [String; 2] {
    [
        format!("{}-authorino", root_name),
        format!("{}-authorino-k8s-auth", root_name),
    ]
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

pub fn map_scan_warning_to_resolution(w: &crate::kube::resource::ScanWarning) -> AdapterResolution {
    if w.is_not_found() {
        AdapterResolution::TargetMissing
    } else {
        AdapterResolution::Unknown
    }
}

pub fn resolve_crb(expected_name: &str, obj: &DynamicObject) -> Result<ResourceId, String> {
    let tm = obj
        .types
        .as_ref()
        .ok_or_else(|| "missing type metadata".to_string())?;
    if tm.api_version != "rbac.authorization.k8s.io/v1" {
        return Err(format!(
            "apiVersion mismatch: expected rbac.authorization.k8s.io/v1, got {}",
            tm.api_version
        ));
    }
    if tm.kind != "ClusterRoleBinding" {
        return Err(format!(
            "kind mismatch: expected ClusterRoleBinding, got {}",
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
        group: "rbac.authorization.k8s.io".to_string(),
        version: "v1".to_string(),
        kind: "ClusterRoleBinding".to_string(),
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
            status_reason: Some("no Authorino CR roots found in discovered resources".to_string()),
            evidence: Some(evidence),
            results: vec![],
            diagnostics: vec![],
            incomplete: false,
        };
    }

    let mut results = Vec::new();
    let mut diagnostics = Vec::new();
    let mut has_unknown = false;

    for root in roots {
        let crb_names = cleanup_crb_names(&root.name);
        for crb_name in &crb_names {
            let get_result = planner
                .get(
                    client,
                    "rbac.authorization.k8s.io",
                    "v1",
                    "clusterrolebindings",
                    None,
                    crb_name,
                    QueryRequirement::Optional,
                )
                .await;

            match get_result {
                Ok(obj) => match resolve_crb(crb_name, &obj) {
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
                            "ClusterRoleBinding/{}: identity mismatch: {}",
                            crb_name, mismatch
                        ));
                        results.push(AdapterResult {
                            resource: InspectedResource {
                                id: ResourceId {
                                    group: "rbac.authorization.k8s.io".to_string(),
                                    version: "v1".to_string(),
                                    kind: "ClusterRoleBinding".to_string(),
                                    namespace: None,
                                    name: crb_name.clone(),
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
                    let resolution = map_scan_warning_to_resolution(&w);
                    if resolution == AdapterResolution::Unknown {
                        has_unknown = true;
                    }
                    diagnostics.push(format!(
                        "ClusterRoleBinding/{}: {} ({})",
                        crb_name, resolution, w
                    ));
                    results.push(AdapterResult {
                        resource: InspectedResource {
                            id: ResourceId {
                                group: "rbac.authorization.k8s.io".to_string(),
                                version: "v1".to_string(),
                                kind: "ClusterRoleBinding".to_string(),
                                namespace: None,
                                name: crb_name.clone(),
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

    fn crb_response(name: &str, uid: &str) -> serde_json::Value {
        serde_json::json!({
            "apiVersion": "rbac.authorization.k8s.io/v1",
            "kind": "ClusterRoleBinding",
            "metadata": { "name": name, "uid": uid },
            "roleRef": {
                "apiGroup": "rbac.authorization.k8s.io",
                "kind": "ClusterRole",
                "name": "authorino-manager-role"
            },
            "subjects": [{
                "kind": "ServiceAccount",
                "name": "authorino-authorino",
                "namespace": "openshift-rhcl"
            }]
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
                namespace: Some("openshift-operators".to_string()),
                name: csv_name.to_string(),
                uid: Some("csv-uid-123".to_string()),
            },
            csv_phase: "Succeeded".to_string(),
            owned_crds: vec![],
            required_crds: vec![],
            owned_api_service_defs: vec![],
            required_api_service_defs: vec![],
            deployments: vec![],
            service_accounts: vec![],
            install_namespace: "openshift-operators".to_string(),
            has_unlinked_subscriptions: false,
        }
    }

    fn default_root() -> ResourceId {
        ResourceId {
            group: "operator.authorino.kuadrant.io".to_string(),
            version: "v1beta2".to_string(),
            kind: "Authorino".to_string(),
            namespace: Some("openshift-rhcl".to_string()),
            name: "authorino".to_string(),
            uid: Some("root-uid-1".to_string()),
        }
    }

    fn custom_root(name: &str, uid: &str) -> ResourceId {
        ResourceId {
            group: "operator.authorino.kuadrant.io".to_string(),
            version: "v1beta2".to_string(),
            kind: "Authorino".to_string(),
            namespace: Some("openshift-rhcl".to_string()),
            name: name.to_string(),
            uid: Some(uid.to_string()),
        }
    }

    // Test 1: default root both CRBs resolved, exact request paths, source_id=root
    #[tokio::test]
    async fn default_root_both_crb_resolved() {
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
            send.send_response(json_response(crb_response("authorino-authorino", "uid-1")));

            let (req, send) = handle.next_request().await.expect("req 2");
            rc.fetch_add(1, Ordering::SeqCst);
            paths.push(req.uri().path().to_string());
            send.send_response(json_response(crb_response(
                "authorino-authorino-k8s-auth",
                "uid-2",
            )));

            paths
        });

        let operator = test_operator("authorino-operator.v1.4.3", "authorino-operator");
        let roots = vec![default_root()];
        let report = discover(&client, &operator, &planner, &roots).await;
        let request_paths = spawned.await.unwrap();

        assert_eq!(report.status, AdapterReportStatus::Applied);
        assert!(!report.incomplete);
        assert_eq!(report.results.len(), 2);
        assert!(report.diagnostics.is_empty());
        assert_eq!(
            request_paths[0],
            "/apis/rbac.authorization.k8s.io/v1/clusterrolebindings/authorino-authorino"
        );
        assert_eq!(
            request_paths[1],
            "/apis/rbac.authorization.k8s.io/v1/clusterrolebindings/authorino-authorino-k8s-auth"
        );

        for r in &report.results {
            assert_eq!(r.resolution, AdapterResolution::Resolved);
            assert!(r.resource.id.uid.is_some());
            let src = r.resource.source_id.as_ref().unwrap();
            assert_eq!(src.kind, "Authorino");
            assert_eq!(src.name, "authorino");
            assert_eq!(src.uid, Some("root-uid-1".to_string()));
        }

        let metrics = planner.metrics().await;
        assert_eq!(metrics.network_queries, 2);
        assert_eq!(request_count.load(Ordering::SeqCst), 2);
    }

    // Test 2: custom root name
    #[tokio::test]
    async fn custom_root_generates_correct_crb_names() {
        let (mock_service, handle) = tower_test::mock::pair::<
            http::Request<kube::client::Body>,
            http::Response<kube::client::Body>,
        >();
        let client = kube::Client::new(mock_service, "default");
        let planner = QueryPlanner::new(None);

        let spawned = tokio::spawn(async move {
            use std::pin::pin;
            let mut handle = pin!(handle);
            let (req, send) = handle.next_request().await.expect("req 1");
            let path1 = req.uri().path().to_string();
            send.send_response(json_response(crb_response("my-auth-authorino", "uid-a")));
            let (req, send) = handle.next_request().await.expect("req 2");
            let path2 = req.uri().path().to_string();
            send.send_response(json_response(crb_response(
                "my-auth-authorino-k8s-auth",
                "uid-b",
            )));
            (path1, path2)
        });

        let operator = test_operator("authorino-operator.v1.4.3", "authorino-operator");
        let report = discover(
            &client,
            &operator,
            &planner,
            &[custom_root("my-auth", "rx")],
        )
        .await;
        let (p1, p2) = spawned.await.unwrap();

        assert!(p1.ends_with("/clusterrolebindings/my-auth-authorino"));
        assert!(p2.ends_with("/clusterrolebindings/my-auth-authorino-k8s-auth"));
        assert_eq!(report.results[0].resource.id.name, "my-auth-authorino");
        for r in &report.results {
            assert_eq!(r.resource.source_id.as_ref().unwrap().name, "my-auth");
        }
    }

    // Test 3: zero roots → zero requests, NotApplicable
    #[tokio::test]
    async fn zero_roots_not_applicable() {
        let (mock_service, _handle) = tower_test::mock::pair::<
            http::Request<kube::client::Body>,
            http::Response<kube::client::Body>,
        >();
        let client = kube::Client::new(mock_service, "default");
        let planner = QueryPlanner::new(None);

        let operator = test_operator("authorino-operator.v1.4.3", "authorino-operator");
        let report = discover(&client, &operator, &planner, &[]).await;

        assert_eq!(report.status, AdapterReportStatus::NotApplicable);
        assert!(report.results.is_empty());
        assert!(report.evidence.is_some());

        let metrics = planner.metrics().await;
        assert_eq!(metrics.network_queries, 0);
    }

    // Test 4: one CRB missing (404)
    #[tokio::test]
    async fn one_crb_missing_404() {
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
            send.send_response(json_response(crb_response("authorino-authorino", "uid-1")));
            let (_req, send) = handle.next_request().await.expect("req 2");
            send.send_response(status_response(404, "NotFound"));
        });

        let operator = test_operator("authorino-operator.v1.4.3", "authorino-operator");
        let report = discover(&client, &operator, &planner, &[default_root()]).await;
        spawned.await.unwrap();

        assert_eq!(report.status, AdapterReportStatus::Applied);
        assert!(!report.incomplete);
        assert_eq!(report.results[0].resolution, AdapterResolution::Resolved);
        assert_eq!(
            report.results[1].resolution,
            AdapterResolution::TargetMissing
        );
    }

    // Test 5: 404 does NOT cause strict failure via ledger
    #[tokio::test]
    async fn not_found_does_not_trigger_strict() {
        let (mock_service, handle) = tower_test::mock::pair::<
            http::Request<kube::client::Body>,
            http::Response<kube::client::Body>,
        >();
        let client = kube::Client::new(mock_service, "default");
        let planner = QueryPlanner::new(None);
        let ledger: crate::kube::scanner::SharedLedger = std::sync::Arc::new(
            std::sync::Mutex::new(crate::kube::resource::CoverageLedger::new()),
        );

        let spawned = tokio::spawn(async move {
            use std::pin::pin;
            let mut handle = pin!(handle);
            let (_req, send) = handle.next_request().await.expect("req 1");
            send.send_response(status_response(404, "NotFound"));
            let (_req, send) = handle.next_request().await.expect("req 2");
            send.send_response(status_response(404, "NotFound"));
        });

        let operator = test_operator("authorino-operator.v1.4.3", "authorino-operator");
        let report = discover(&client, &operator, &planner, &[default_root()]).await;
        spawned.await.unwrap();

        assert!(!report.incomplete);

        planner.flush_to_ledger(&ledger).await;
        let guard = ledger.lock().unwrap();
        assert!(
            !guard.has_incomplete(),
            "404 with Optional must not make ledger incomplete"
        );
    }

    // Test 6: 403 → Unknown results, report.incomplete=true
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

        let operator = test_operator("authorino-operator.v1.4.3", "authorino-operator");
        let report = discover(&client, &operator, &planner, &[default_root()]).await;
        spawned.await.unwrap();

        assert!(report.incomplete);
        assert_eq!(report.status, AdapterReportStatus::Applied);
        for r in &report.results {
            assert_eq!(r.resolution, AdapterResolution::Unknown);
        }
        assert_eq!(report.diagnostics.len(), 2);

        // merge should produce 1 warning for incomplete
        let merged = merge_adapter_reports(&[report]);
        assert_eq!(merged.incomplete_count, 1);
        assert_eq!(merged.warnings.len(), 1);
        assert_eq!(merged.resources.len(), 0);
    }

    // Test 7: unsupported version → Unknown status, structured output, query 0
    #[tokio::test]
    async fn unsupported_version_unknown_status() {
        let (mock_service, _handle) = tower_test::mock::pair::<
            http::Request<kube::client::Body>,
            http::Response<kube::client::Body>,
        >();
        let client = kube::Client::new(mock_service, "default");
        let planner = QueryPlanner::new(None);

        let operator = test_operator("authorino-operator.v2.0.0", "authorino-operator");
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

    // Test 8: wrong package → no match
    #[test]
    fn wrong_package_no_match() {
        let operator = test_operator("authorino-operator.v1.4.3", "some-other-operator");
        assert!(!matches_operator(&operator));
    }

    // Test 9: multiple roots reversed → byte-identical JSON
    #[tokio::test]
    async fn multiple_roots_reversed_deterministic() {
        async fn run_with_roots(roots: Vec<ResourceId>) -> String {
            let (mock_service, handle) = tower_test::mock::pair::<
                http::Request<kube::client::Body>,
                http::Response<kube::client::Body>,
            >();
            let client = kube::Client::new(mock_service, "default");
            let planner = QueryPlanner::new(None);

            let spawned = tokio::spawn(async move {
                use std::pin::pin;
                let mut handle = pin!(handle);
                for i in 0..4 {
                    let (req, send) = handle
                        .next_request()
                        .await
                        .unwrap_or_else(|| panic!("req {}", i));
                    let path = req.uri().path().to_string();
                    let name = path.rsplit('/').next().unwrap_or("unknown");
                    let uid = format!("uid-{}", name);
                    send.send_response(json_response(crb_response(name, &uid)));
                }
            });

            let operator = test_operator("authorino-operator.v1.4.3", "authorino-operator");
            let report = discover(&client, &operator, &planner, &roots).await;
            spawned.await.unwrap();
            serde_json::to_string(&report).unwrap()
        }

        let json_fwd = run_with_roots(vec![
            custom_root("alpha", "uid-alpha"),
            custom_root("beta", "uid-beta"),
        ])
        .await;
        let json_rev = run_with_roots(vec![
            custom_root("beta", "uid-beta"),
            custom_root("alpha", "uid-alpha"),
        ])
        .await;
        assert_eq!(json_fwd, json_rev);
    }

    // Test 10: identity verification — wrong apiVersion
    #[test]
    fn resolve_crb_wrong_api_version() {
        let obj: DynamicObject = serde_json::from_value(serde_json::json!({
            "apiVersion": "v1",
            "kind": "ClusterRoleBinding",
            "metadata": { "name": "test", "uid": "uid-1" }
        }))
        .unwrap();
        let result = resolve_crb("test", &obj);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("apiVersion mismatch"));
    }

    // Test 11: identity verification — wrong kind
    #[test]
    fn resolve_crb_wrong_kind() {
        let obj: DynamicObject = serde_json::from_value(serde_json::json!({
            "apiVersion": "rbac.authorization.k8s.io/v1",
            "kind": "ClusterRole",
            "metadata": { "name": "test", "uid": "uid-1" }
        }))
        .unwrap();
        let result = resolve_crb("test", &obj);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("kind mismatch"));
    }

    // Test 12: identity verification — wrong name
    #[test]
    fn resolve_crb_wrong_name() {
        let obj: DynamicObject = serde_json::from_value(serde_json::json!({
            "apiVersion": "rbac.authorization.k8s.io/v1",
            "kind": "ClusterRoleBinding",
            "metadata": { "name": "other-name", "uid": "uid-1" }
        }))
        .unwrap();
        let result = resolve_crb("expected-name", &obj);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("name mismatch"));
    }

    // Test 13: identity verification — missing UID
    #[test]
    fn resolve_crb_missing_uid() {
        let obj: DynamicObject = serde_json::from_value(serde_json::json!({
            "apiVersion": "rbac.authorization.k8s.io/v1",
            "kind": "ClusterRoleBinding",
            "metadata": { "name": "test" }
        }))
        .unwrap();
        let result = resolve_crb("test", &obj);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("UID"));
    }

    // Test 14: identity verification — correct response
    #[test]
    fn resolve_crb_success() {
        let obj: DynamicObject = serde_json::from_value(serde_json::json!({
            "apiVersion": "rbac.authorization.k8s.io/v1",
            "kind": "ClusterRoleBinding",
            "metadata": { "name": "authorino-authorino", "uid": "uid-1" }
        }))
        .unwrap();
        let result = resolve_crb("authorino-authorino", &obj);
        assert!(result.is_ok());
        let id = result.unwrap();
        assert_eq!(id.uid, Some("uid-1".to_string()));
    }

    // Test 15: identity mismatch in discover produces Unknown+incomplete
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
            // Return wrong kind for first request
            let (_req, send) = handle.next_request().await.expect("req 1");
            send.send_response(json_response(serde_json::json!({
                "apiVersion": "rbac.authorization.k8s.io/v1",
                "kind": "ClusterRole",
                "metadata": { "name": "authorino-authorino", "uid": "uid-wrong" }
            })));
            // Return correct for second
            let (_req, send) = handle.next_request().await.expect("req 2");
            send.send_response(json_response(crb_response(
                "authorino-authorino-k8s-auth",
                "uid-2",
            )));
        });

        let operator = test_operator("authorino-operator.v1.4.3", "authorino-operator");
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

    // Test 16: merge only Resolved+UID
    #[test]
    fn merge_only_resolved_with_uid() {
        let evidence = make_evidence("authorino-operator.v1.4.3");
        let reports = vec![AdapterReport {
            adapter_id: ADAPTER_ID.to_string(),
            status: AdapterReportStatus::Applied,
            status_reason: None,
            evidence: Some(evidence.clone()),
            results: vec![
                AdapterResult {
                    resource: InspectedResource {
                        id: ResourceId {
                            group: "rbac.authorization.k8s.io".to_string(),
                            version: "v1".to_string(),
                            kind: "ClusterRoleBinding".to_string(),
                            namespace: None,
                            name: "authorino-authorino".to_string(),
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
                            group: "rbac.authorization.k8s.io".to_string(),
                            version: "v1".to_string(),
                            kind: "ClusterRoleBinding".to_string(),
                            namespace: None,
                            name: "missing".to_string(),
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
        assert_eq!(merged.resources[0].id.name, "authorino-authorino");
        assert_eq!(merged.incomplete_count, 0);
    }

    // Test 17: find_authorino_roots filters correctly
    #[test]
    fn find_roots_filters_kind_and_group() {
        let resources = vec![
            InspectedResource {
                id: ResourceId {
                    group: "operator.authorino.kuadrant.io".to_string(),
                    version: "v1beta2".to_string(),
                    kind: "Authorino".to_string(),
                    namespace: Some("ns1".to_string()),
                    name: "auth1".to_string(),
                    uid: Some("uid-1".to_string()),
                },
                source_id: None,
                relationship: Relationship::OwnedCrdInstance,
                evidence: String::new(),
                confidence: Confidence::Managed,
            },
            InspectedResource {
                id: ResourceId {
                    group: "rbac.authorization.k8s.io".to_string(),
                    version: "v1".to_string(),
                    kind: "ClusterRoleBinding".to_string(),
                    namespace: None,
                    name: "auth1".to_string(),
                    uid: Some("uid-2".to_string()),
                },
                source_id: None,
                relationship: Relationship::OwnerRef,
                evidence: String::new(),
                confidence: Confidence::Managed,
            },
        ];

        let roots = find_authorino_roots(&resources);
        assert_eq!(roots.len(), 1);
        assert_eq!(roots[0].kind, "Authorino");
    }

    // Test 18: resolution mapping
    #[test]
    fn resolution_mapping() {
        use crate::kube::resource::ScanWarning;

        let not_found = ScanWarning::NotFound {
            gvr: "test".to_string(),
        };
        assert_eq!(
            map_scan_warning_to_resolution(&not_found),
            AdapterResolution::TargetMissing
        );

        let forbidden = ScanWarning::Other {
            gvr: "test".to_string(),
            message: "Forbidden".to_string(),
        };
        assert_eq!(
            map_scan_warning_to_resolution(&forbidden),
            AdapterResolution::Unknown
        );
    }

    // Test 19: source evidence serialization
    #[tokio::test]
    async fn source_evidence_in_report() {
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
            send.send_response(json_response(crb_response("authorino-authorino", "uid-1")));
            let (_req, send) = handle.next_request().await.expect("req 2");
            send.send_response(json_response(crb_response(
                "authorino-authorino-k8s-auth",
                "uid-2",
            )));
        });

        let operator = test_operator("authorino-operator.v1.4.3", "authorino-operator");
        let report = discover(&client, &operator, &planner, &[default_root()]).await;
        spawned.await.unwrap();

        let ev = report.evidence.as_ref().unwrap();
        assert!(ev.source_url.contains("Kuadrant/authorino-operator"));
        assert!(ev.source_url.contains(SOURCE_COMMIT));
        assert!(
            ev.cleanup_function
                .contains("cleanupClusterScopedPermissions")
        );
    }
}
