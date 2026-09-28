use crate::analyzers::adapters::{
    AdapterEvidence, AdapterReport, AdapterResolution, AdapterResult,
};
use crate::analyzers::inspect::{Confidence, InspectedResource, Relationship};
use crate::analyzers::olm::OperatorInstance;
use crate::kube::resource::{QueryRequirement, ResourceId};
use crate::kube::scanner::SharedPlanner;
use kube::Client;

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

fn make_evidence(csv_name: &str) -> AdapterEvidence {
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

pub async fn discover(
    client: &Client,
    operator: &OperatorInstance,
    planner: &SharedPlanner,
    roots: &[ResourceId],
) -> AdapterReport {
    let csv_name = &operator.csv.name;

    match extract_csv_version(csv_name) {
        Some(v) if SUPPORTED_CSV_VERSIONS.contains(&v) => {}
        Some(v) => {
            return AdapterReport {
                adapter_id: ADAPTER_ID.to_string(),
                results: vec![],
                skipped: false,
                skip_reason: Some(format!(
                    "unsupported version {} (supported: {:?})",
                    v, SUPPORTED_CSV_VERSIONS
                )),
                diagnostics: vec![format!(
                    "UnsupportedVersion: CSV {} version {} not in supported set",
                    csv_name, v
                )],
                incomplete: false,
            };
        }
        None => {
            return AdapterReport {
                adapter_id: ADAPTER_ID.to_string(),
                results: vec![],
                skipped: false,
                skip_reason: Some(format!("cannot parse CSV version from '{}'", csv_name)),
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
            results: vec![],
            skipped: false,
            skip_reason: Some("no Authorino CR roots found in discovered resources".to_string()),
            diagnostics: vec![],
            incomplete: false,
        };
    }

    let evidence = make_evidence(csv_name);
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
                    QueryRequirement::Required,
                )
                .await;

            match get_result {
                Ok(obj) => {
                    let uid = obj.metadata.uid.clone();
                    results.push(AdapterResult {
                        resource: InspectedResource {
                            id: ResourceId {
                                group: "rbac.authorization.k8s.io".to_string(),
                                version: "v1".to_string(),
                                kind: "ClusterRoleBinding".to_string(),
                                namespace: None,
                                name: crb_name.clone(),
                                uid,
                            },
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
        results,
        skipped: false,
        skip_reason: None,
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

    // Test 1: default root "authorino" → 2 CRBs resolved, exact request URIs
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

        assert!(!report.skipped);
        assert!(!report.incomplete);
        assert_eq!(report.results.len(), 2);
        assert!(report.diagnostics.is_empty());

        // Exact request path assertions
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
            assert_eq!(r.resource.relationship, Relationship::CleansUp);
            assert!(r.resource.id.uid.is_some());
            // source_id is root, not CSV
            let src = r.resource.source_id.as_ref().unwrap();
            assert_eq!(src.kind, "Authorino");
            assert_eq!(src.name, "authorino");
            assert_eq!(src.uid, Some("root-uid-1".to_string()));
        }

        assert_eq!(report.results[0].resource.id.name, "authorino-authorino");
        assert_eq!(
            report.results[1].resource.id.name,
            "authorino-authorino-k8s-auth"
        );

        let metrics = planner.metrics().await;
        assert_eq!(metrics.network_queries, 2);
        assert_eq!(request_count.load(Ordering::SeqCst), 2);
    }

    // Test 2: custom root "my-auth" → CRB names are my-auth-authorino{,-k8s-auth}
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
            let mut paths = Vec::new();

            let (req, send) = handle.next_request().await.expect("req 1");
            paths.push(req.uri().path().to_string());
            send.send_response(json_response(crb_response("my-auth-authorino", "uid-a")));

            let (req, send) = handle.next_request().await.expect("req 2");
            paths.push(req.uri().path().to_string());
            send.send_response(json_response(crb_response(
                "my-auth-authorino-k8s-auth",
                "uid-b",
            )));

            paths
        });

        let operator = test_operator("authorino-operator.v1.4.3", "authorino-operator");
        let roots = vec![custom_root("my-auth", "root-uid-x")];
        let report = discover(&client, &operator, &planner, &roots).await;
        let paths = spawned.await.unwrap();

        assert_eq!(report.results.len(), 2);
        assert!(paths[0].ends_with("/clusterrolebindings/my-auth-authorino"));
        assert!(paths[1].ends_with("/clusterrolebindings/my-auth-authorino-k8s-auth"));
        assert_eq!(report.results[0].resource.id.name, "my-auth-authorino");
        assert_eq!(
            report.results[1].resource.id.name,
            "my-auth-authorino-k8s-auth"
        );

        // source_id is the custom root
        for r in &report.results {
            let src = r.resource.source_id.as_ref().unwrap();
            assert_eq!(src.name, "my-auth");
            assert_eq!(src.uid, Some("root-uid-x".to_string()));
        }
    }

    // Test 3: zero roots → zero requests
    #[tokio::test]
    async fn zero_roots_zero_requests() {
        let (mock_service, _handle) = tower_test::mock::pair::<
            http::Request<kube::client::Body>,
            http::Response<kube::client::Body>,
        >();
        let client = kube::Client::new(mock_service, "default");
        let planner = QueryPlanner::new(None);

        let operator = test_operator("authorino-operator.v1.4.3", "authorino-operator");
        let report = discover(&client, &operator, &planner, &[]).await;

        assert!(!report.skipped);
        assert!(report.results.is_empty());
        assert!(
            report
                .skip_reason
                .as_ref()
                .unwrap()
                .contains("no Authorino CR roots")
        );

        let metrics = planner.metrics().await;
        assert_eq!(metrics.network_queries, 0);
    }

    // Test 4: one CRB missing (404) → TargetMissing, other Resolved
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

        assert_eq!(report.results.len(), 2);
        assert!(!report.incomplete);
        assert_eq!(report.results[0].resolution, AdapterResolution::Resolved);
        assert_eq!(
            report.results[1].resolution,
            AdapterResolution::TargetMissing
        );
        assert!(report.results[0].resource.id.uid.is_some());
        assert!(report.results[1].resource.id.uid.is_none());
    }

    // Test 5: forbidden → Unknown, incomplete=true
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

        assert_eq!(report.results.len(), 2);
        assert!(report.incomplete);
        for r in &report.results {
            assert_eq!(r.resolution, AdapterResolution::Unknown);
        }
        assert_eq!(report.diagnostics.len(), 2);
    }

    // Test 6: unsupported version → no queries, structured UnsupportedVersion output
    #[tokio::test]
    async fn unsupported_version_no_queries_structured() {
        let (mock_service, _handle) = tower_test::mock::pair::<
            http::Request<kube::client::Body>,
            http::Response<kube::client::Body>,
        >();
        let client = kube::Client::new(mock_service, "default");
        let planner = QueryPlanner::new(None);

        let operator = test_operator("authorino-operator.v2.0.0", "authorino-operator");
        let report = discover(&client, &operator, &planner, &[default_root()]).await;

        assert!(!report.skipped);
        assert!(report.results.is_empty());
        assert!(report.skip_reason.as_ref().unwrap().contains("unsupported"));
        assert!(report.diagnostics[0].contains("UnsupportedVersion"));

        let metrics = planner.metrics().await;
        assert_eq!(metrics.network_queries, 0);
    }

    // Test 7: wrong package + same CSV prefix → no match
    #[test]
    fn wrong_package_no_match() {
        let operator = test_operator("authorino-operator.v1.4.3", "some-other-operator");
        assert!(!matches_operator(&operator));
    }

    // Test 8: correct package + unsupported CSV → query 0
    #[tokio::test]
    async fn correct_package_unsupported_csv_no_queries() {
        let (mock_service, _handle) = tower_test::mock::pair::<
            http::Request<kube::client::Body>,
            http::Response<kube::client::Body>,
        >();
        let client = kube::Client::new(mock_service, "default");
        let planner = QueryPlanner::new(None);

        let operator = test_operator("authorino-operator.v99.0.0", "authorino-operator");
        let report = discover(&client, &operator, &planner, &[default_root()]).await;

        assert!(report.results.is_empty());
        assert!(report.skip_reason.as_ref().unwrap().contains("unsupported"));
        let metrics = planner.metrics().await;
        assert_eq!(metrics.network_queries, 0);
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

        let roots_forward = vec![
            custom_root("alpha", "uid-alpha"),
            custom_root("beta", "uid-beta"),
        ];
        let roots_reversed = vec![
            custom_root("beta", "uid-beta"),
            custom_root("alpha", "uid-alpha"),
        ];

        let json_fwd = run_with_roots(roots_forward).await;
        let json_rev = run_with_roots(roots_reversed).await;
        assert_eq!(
            json_fwd, json_rev,
            "output must be byte-identical regardless of root input order"
        );
    }

    // Test 10: source evidence exact serialization
    #[tokio::test]
    async fn source_evidence_exact_fields() {
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

        let ev = &report.results[0].adapter_evidence;
        assert_eq!(ev.source_commit, SOURCE_COMMIT);
        assert!(ev.source_url.contains("Kuadrant/authorino-operator"));
        assert!(ev.source_url.contains(SOURCE_COMMIT));
        assert!(
            ev.cleanup_function
                .contains("cleanupClusterScopedPermissions")
        );
        assert!(
            ev.naming_function
                .contains("authorinoClusterRoleBindingName")
        );
        assert!(ev.binding_note.is_some());
    }

    // Test 11: find_authorino_roots filters correctly
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
            // Same name different kind — should NOT match
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
            // No UID — should NOT match
            InspectedResource {
                id: ResourceId {
                    group: "operator.authorino.kuadrant.io".to_string(),
                    version: "v1beta2".to_string(),
                    kind: "Authorino".to_string(),
                    namespace: Some("ns2".to_string()),
                    name: "auth-no-uid".to_string(),
                    uid: None,
                },
                source_id: None,
                relationship: Relationship::OwnedCrdInstance,
                evidence: String::new(),
                confidence: Confidence::Managed,
            },
        ];

        let roots = find_authorino_roots(&resources);
        assert_eq!(roots.len(), 1);
        assert_eq!(roots[0].name, "auth1");
        assert_eq!(roots[0].kind, "Authorino");
        assert_eq!(roots[0].group, "operator.authorino.kuadrant.io");
    }

    // Test 12: merge_adapter_reports only includes Resolved with UID
    #[test]
    fn merge_only_resolved_with_uid() {
        let evidence = make_evidence("authorino-operator.v1.4.3");
        let reports = vec![AdapterReport {
            adapter_id: ADAPTER_ID.to_string(),
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
                            name: "authorino-authorino-k8s-auth".to_string(),
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
            skipped: false,
            skip_reason: None,
            diagnostics: vec![],
            incomplete: false,
        }];

        let merged = merge_adapter_reports(&reports);
        assert_eq!(merged.resources.len(), 1);
        assert_eq!(merged.resources[0].id.name, "authorino-authorino");
        assert_eq!(merged.warnings.len(), 0);
        assert_eq!(merged.incomplete_count, 0);
    }

    // Test 13: merge incomplete report produces exactly 1 warning
    #[test]
    fn merge_incomplete_one_warning() {
        let reports = vec![AdapterReport {
            adapter_id: ADAPTER_ID.to_string(),
            results: vec![],
            skipped: false,
            skip_reason: None,
            diagnostics: vec!["diag1".to_string(), "diag2".to_string()],
            incomplete: true,
        }];

        let merged = merge_adapter_reports(&reports);
        assert_eq!(merged.warnings.len(), 1);
        assert_eq!(merged.incomplete_count, 1);
    }

    // Test 14: resolution mapping helper
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
            message: "Forbidden: access denied".to_string(),
        };
        assert_eq!(
            map_scan_warning_to_resolution(&forbidden),
            AdapterResolution::Unknown
        );
    }
}
