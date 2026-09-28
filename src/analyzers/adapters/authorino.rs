use crate::analyzers::adapters::{
    AdapterEvidence, AdapterReport, AdapterResolution, AdapterResult,
};
use crate::analyzers::inspect::{Confidence, InspectedResource, Relationship};
use crate::analyzers::olm::OperatorInstance;
use crate::kube::planner::CanonicalGvr;
use crate::kube::resource::{QueryRequirement, ResourceId};
use crate::kube::scanner::SharedPlanner;
use kube::Client;

pub const ADAPTER_ID: &str = "authorino-finalizer-cleanup";

const SUPPORTED_CSV_VERSIONS: &[&str] = &["1.4.3"];

const SOURCE_REVISION: &str = "v0.25.3";
const SOURCE_URL: &str =
    "https://github.com/Kuadrant/authorino/blob/v0.25.3/controllers/authorino_controller.go";

const CLEANUP_CRB_NAMES: &[&str] = &["authorino-authorino", "authorino-authorino-k8s-auth"];

fn crb_gvr() -> CanonicalGvr {
    CanonicalGvr::new("rbac.authorization.k8s.io", "v1", "clusterrolebindings")
}

fn extract_csv_version(csv_name: &str) -> Option<&str> {
    csv_name.strip_prefix("authorino-operator.v")
}

fn is_supported_version(csv_name: &str) -> bool {
    extract_csv_version(csv_name)
        .map(|v| SUPPORTED_CSV_VERSIONS.contains(&v))
        .unwrap_or(false)
}

pub fn matches_operator(operator: &OperatorInstance) -> bool {
    let package = operator.package_name.as_deref().unwrap_or("");
    let csv_name = &operator.csv.name;
    package == "authorino-operator" || csv_name.starts_with("authorino-operator.")
}

pub async fn discover(
    client: &Client,
    operator: &OperatorInstance,
    planner: &SharedPlanner,
) -> AdapterReport {
    let csv_name = &operator.csv.name;

    if !is_supported_version(csv_name) {
        let version = extract_csv_version(csv_name).unwrap_or("unknown");
        return AdapterReport {
            adapter_id: ADAPTER_ID.to_string(),
            results: vec![],
            skipped: true,
            skip_reason: Some(format!(
                "unsupported version {} (supported: {:?})",
                version, SUPPORTED_CSV_VERSIONS
            )),
            diagnostics: vec![format!(
                "CSV {} has version {} which is not in the supported set",
                csv_name, version
            )],
            incomplete: false,
        };
    }

    let gvr = crb_gvr();
    let mut results = Vec::new();
    let mut diagnostics = Vec::new();
    let mut has_unknown = false;

    let evidence = AdapterEvidence {
        adapter_id: ADAPTER_ID.to_string(),
        source_revision: SOURCE_REVISION.to_string(),
        source_url: SOURCE_URL.to_string(),
        cleanup_rule: "finalizer deterministic-name delete".to_string(),
        matched_csv_version: csv_name.to_string(),
    };

    for &crb_name in CLEANUP_CRB_NAMES {
        let get_result = planner
            .get(
                client,
                &gvr.group,
                &gvr.version,
                &gvr.plural,
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
                            name: crb_name.to_string(),
                            uid,
                        },
                        source_id: Some(operator.csv.clone()),
                        relationship: Relationship::CleansUp,
                        evidence: format!(
                            "adapter:{}; source:{}; cleanup:finalizer deterministic-name delete; target:ClusterRoleBinding/{}",
                            ADAPTER_ID, SOURCE_REVISION, crb_name
                        ),
                        confidence: Confidence::Managed,
                    },
                    resolution: AdapterResolution::Resolved,
                    adapter_evidence: evidence.clone(),
                });
            }
            Err(w) => {
                let resolution = if w.is_not_found() {
                    AdapterResolution::TargetMissing
                } else {
                    has_unknown = true;
                    AdapterResolution::Unknown
                };
                diagnostics.push(format!(
                    "ClusterRoleBinding/{}: {} (resolution: {})",
                    crb_name, w, resolution
                ));
                results.push(AdapterResult {
                    resource: InspectedResource {
                        id: ResourceId {
                            group: "rbac.authorization.k8s.io".to_string(),
                            version: "v1".to_string(),
                            kind: "ClusterRoleBinding".to_string(),
                            namespace: None,
                            name: crb_name.to_string(),
                            uid: None,
                        },
                        source_id: None,
                        relationship: Relationship::CleansUp,
                        evidence: format!(
                            "adapter:{}; source:{}; target:ClusterRoleBinding/{} ({})",
                            ADAPTER_ID, SOURCE_REVISION, crb_name, resolution
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

    #[tokio::test]
    async fn supported_version_both_crb_resolved() {
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

            let (req1, send1) = handle.next_request().await.expect("req 1");
            rc.fetch_add(1, Ordering::SeqCst);
            let uri1 = req1.uri().to_string();
            assert!(
                uri1.contains("/clusterrolebindings/authorino-authorino")
                    && !uri1.contains("k8s-auth"),
                "first request URI: {}",
                uri1
            );
            send1.send_response(json_response(crb_response(
                "authorino-authorino",
                "uid-crb-1",
            )));

            let (req2, send2) = handle.next_request().await.expect("req 2");
            rc.fetch_add(1, Ordering::SeqCst);
            let uri2 = req2.uri().to_string();
            assert!(
                uri2.contains("/clusterrolebindings/authorino-authorino-k8s-auth"),
                "second request URI: {}",
                uri2
            );
            send2.send_response(json_response(crb_response(
                "authorino-authorino-k8s-auth",
                "uid-crb-2",
            )));
        });

        let operator = test_operator("authorino-operator.v1.4.3", "authorino-operator");
        let report = discover(&client, &operator, &planner).await;
        spawned.await.unwrap();

        assert!(!report.skipped);
        assert!(!report.incomplete);
        assert_eq!(report.results.len(), 2);
        assert!(report.diagnostics.is_empty());

        for r in &report.results {
            assert_eq!(r.resolution, AdapterResolution::Resolved);
            assert_eq!(r.resource.relationship, Relationship::CleansUp);
            assert!(r.resource.id.uid.is_some());
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
            send.send_response(json_response(crb_response(
                "authorino-authorino",
                "uid-crb-1",
            )));
            let (_req, send) = handle.next_request().await.expect("req 2");
            send.send_response(status_response(404, "NotFound"));
        });

        let operator = test_operator("authorino-operator.v1.4.3", "authorino-operator");
        let report = discover(&client, &operator, &planner).await;
        spawned.await.unwrap();

        assert_eq!(report.results.len(), 2);
        assert!(!report.incomplete);
        assert_eq!(report.results[0].resolution, AdapterResolution::Resolved);
        assert_eq!(
            report.results[1].resolution,
            AdapterResolution::TargetMissing
        );
    }

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
        let report = discover(&client, &operator, &planner).await;
        spawned.await.unwrap();

        assert_eq!(report.results.len(), 2);
        assert!(report.incomplete);
        for r in &report.results {
            assert_eq!(r.resolution, AdapterResolution::Unknown);
        }
        assert_eq!(report.diagnostics.len(), 2);
    }

    #[tokio::test]
    async fn unsupported_version_skipped_no_queries() {
        let (mock_service, _handle) = tower_test::mock::pair::<
            http::Request<kube::client::Body>,
            http::Response<kube::client::Body>,
        >();
        let client = kube::Client::new(mock_service, "default");
        let planner = QueryPlanner::new(None);

        let operator = test_operator("authorino-operator.v2.0.0", "authorino-operator");
        let report = discover(&client, &operator, &planner).await;

        assert!(report.skipped);
        assert!(report.results.is_empty());
        assert!(report.skip_reason.as_ref().unwrap().contains("unsupported"));

        let metrics = planner.metrics().await;
        assert_eq!(metrics.network_queries, 0);
    }

    #[test]
    fn non_authorino_no_match() {
        let operator = test_operator("rhods-operator.3.5.1", "rhods-operator");
        assert!(!matches_operator(&operator));
    }

    #[tokio::test]
    async fn deterministic_output() {
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
                send.send_response(json_response(crb_response("authorino-authorino", "uid-1")));
                let (_req, send) = handle.next_request().await.expect("req 2");
                send.send_response(json_response(crb_response(
                    "authorino-authorino-k8s-auth",
                    "uid-2",
                )));
            });

            let operator = test_operator("authorino-operator.v1.4.3", "authorino-operator");
            let report = discover(&client, &operator, &planner).await;
            spawned.await.unwrap();
            serde_json::to_string(&report).unwrap()
        }

        let json1 = run_once().await;
        let json2 = run_once().await;
        assert_eq!(json1, json2, "output must be byte-identical");
    }

    #[test]
    fn negative_identity_fixture() {
        let gvr = crb_gvr();
        assert_eq!(gvr.group, "rbac.authorization.k8s.io");
        assert_eq!(gvr.plural, "clusterrolebindings");
        assert_eq!(CLEANUP_CRB_NAMES.len(), 2);
        assert_eq!(CLEANUP_CRB_NAMES[0], "authorino-authorino");
        assert_eq!(CLEANUP_CRB_NAMES[1], "authorino-authorino-k8s-auth");
    }

    #[tokio::test]
    async fn wiring_registry_to_adapter() {
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
        let reports =
            crate::analyzers::adapters::run_adapters(&client, &operator, Some(&planner)).await;
        spawned.await.unwrap();

        assert_eq!(reports.len(), 1);
        assert_eq!(reports[0].adapter_id, ADAPTER_ID);
        assert!(!reports[0].skipped);
        assert_eq!(reports[0].results.len(), 2);
    }
}
