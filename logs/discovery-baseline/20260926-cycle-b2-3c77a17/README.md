# Phase 0 Cycle B2 Discovery Baseline Corpus (Replacement)

## Collection Identity

- **Git**: `3c77a17a606d9030def827b0fd8dd1d7e2e43b44` (cli-v2-phase4)
- **Binary**: SHA256 `029f0eea4ad7fd7ac84a8302fec7e2c95206c4a1e605416b232af0c4f1bd4db6`
- **Cluster**: kube-system UID `73072fbb-5d55-4ad1-a239-256da1ebea4e`
- **Config**: `configs/full-teardown.json` SHA256 `428eeb78...`

## Pre-Collection (all gates PASSED)

### Exact Invocations

```bash
# Operator resources (15/15, pre-delete)
./target/release/oc-deps operator resources "<operator>" --scope related -o json

# Teardown plans (15/15)
./target/release/oc-deps teardown plan "<operator>" --approve-scope root \
  --approve-scope independent --approve-scope label-only \
  --approve-scope operator-group [--delete-resource ...] \
  --file plans/<name>-plan.json -o json

# Pre-inventory (all served GVR, raw API discovery)
python3 scripts/collect-inventory.py \
  inventory/pre-inventory.jsonl \
  inventory/pre-list-failures.jsonl \
  inventory/gvr-catalog.json

# Golden validation
python3 scripts/validate-pre-inventory.py inventory/pre-inventory.jsonl
```

### Collection Stats

| Metric | Value |
|--------|-------|
| Catalog GVRs | 538 (all served versions, not just preferred) |
| Raw objects | 17,786 |
| Logical identities (deduped) | 17,668 |
| UID-null collisions | 22 (PackageManifest virtual API) |
| LIST failures | 0 |
| Redacted GVRs | 3 (OAuthAccessToken/UserOAuthAccessToken/OAuthAuthorizeToken) |
| Secret rows | 986 (metadata only, no .data/.stringData) |
| Token rows in inventory | 0 |

### All-Served Version Discovery

The collector queries `/api/v1` and every version listed in `/apis/{group}` (not just preferredVersion).
This ensures resources served only on non-preferred versions are captured:
- `kuadrant.io/v1alpha1/TokenRateLimitPolicy` (preferred is v1, but TRL only on v1alpha1)
- `networking.istio.io/v1alpha3/EnvoyFilter` (preferred is v1, but EnvoyFilter only on v1alpha3)

Multi-version raw rows are preserved. Logical identity dedup uses `(group, kind, namespace, name)`.
UID-null collisions (PackageManifest) preserve both rows with labels/observation fingerprint.

### Version Normalization

- `isPreferred`: true if version == group preferredVersion
- `isStorage`: resolved from CRD.spec.versions[].storage for CRD-backed; null for built-in/APIService
- `storageVersionHash`: preserved from discovery API separately

### Annotation Redaction Policy

- **Preserved full**: `operator-sdk(.io)/`, `opendatahub.io/`, `platform.opendatahub.io/`,
  `component.opendatahub.io/`, `kuadrant.io/`, `HTTPRouteRule.gateway.networking.k8s.io`,
  `GRPCRouteRule.gateway.networking.k8s.io`, `instrumentation.opentelemetry.io/`,
  `sidecar.opentelemetry.io/`, `sidecar.istio.io/`, `cert-manager.io/`,
  `app.kubernetes.io/`, `olm.*`, `operators.coreos.com/`, `serving.kserve.io/`
- **Hashed (key + sha256)**: all other annotations (prevents credential leak)
- **Dropped**: `kubectl.kubernetes.io/last-applied-configuration`

### Golden Validation Results

All assertions PASS:
- TokenRateLimitPolicy/gateway-default-deny: exists, ownerRef Config/default ✓
- EnvoyFilter ×6 in openshift-ingress ✓
- PersesDashboard ×4: exists, ownerRef Kserve/Config ✓
- Certificate/Issuer ×3 in openshift-jobset ✓
- AuthPolicy/maas-gateway-auth: exists, managed-by maas-controller label ✓
- AuthConfig ×4: exists, RouteRule annotations ✓

### Known Incomplete Scope

**Limitador namespace misparse** (Phase 3 defect): `spec.limits[0].namespace` value
`redhat-ai-gateway-infra/maas-api-route` misidentified as K8s namespace, producing
271 scan warnings. Limitador operator resources scope is incomplete. See
`gaps-limitador-namespace-misparse.md`.

## Tools

| Tool | Corpus path | SHA256 |
|------|-------------|--------|
| Collector | tools-collect-inventory.py | `102a795f48fbf7db7...` |
| Validator | tools-validate-pre-inventory.py | `5cb38d3da018ebb1c...` |

## Batch Execution

### Attempt 1 (drift failure)
```bash
./target/release/oc-deps teardown batch configs/full-teardown.json --refresh-discovery
# Exit 1: OGX/default-ogx appeared during plan-apply gap (RHOAI operator reconciliation)
```

### Attempt 2 (success)
```bash
./target/release/oc-deps teardown batch configs/full-teardown.json --refresh-discovery
# Exit 0: 15/15 succeeded, 0 failed, 0 skipped
```

15 runtime plans captured in `batch-plans/`. Stderr: 2868 lines, final summary present.

## Post-Collection

### Invocation
```bash
python3 scripts/collect-inventory.py \
  inventory/post-inventory.jsonl \
  inventory/post-list-failures.jsonl \
  inventory/post-gvr-catalog.json

python3 scripts/post-analysis.py \
  inventory/pre-inventory.jsonl \
  inventory/post-inventory.jsonl \
  batch-plans \
  post-analysis.json
```

### Post Stats

| Metric | Pre | Post | Delta |
|--------|-----|------|-------|
| Raw objects | 17,786 | 14,761 | -3,025 |
| Logical identities | 17,668 | 14,719 | -2,949 |
| LIST failures | 0 | 0 | — |

### Disappearance Classification (3,408 logical)

| Category | Count | Description |
|----------|-------|-------------|
| direct_delete | 91 | Runtime plan DELETE action executed |
| expect_gone | 72 | Runtime plan EXPECT action |
| ownerref_descendant | 1,694 | K8s GC cascade via ownerRef |
| derived_side_effect | 2 | PV reclaim, APIService deregistration |
| unexplained_or_churn | 1,549 | No plan action, no ownerRef to deleted parent |
| **Cross-operator collisions** | 17 | Same identity in multiple operator plans |

### Unplanned Protected-Kind Deletions (4)

| Resource | Classification | Causal Chain |
|----------|---------------|--------------|
| CRD/jobsets.jobset.x-k8s.io | ownerref_descendant | JobSetOperator DELETE → GC cascade |
| PVC/mlflow-pvc | ownerref_descendant | MLflow DELETE → GC cascade |
| PV/pvc-78fb5c3e | derived_side_effect | PVC deletion → PV reclaim |
| APIService/v1alpha2.jobset.x-k8s.io | derived_side_effect | CRD deletion → API deregistration |

### Terminating
- newly_terminating: 0
- preexisting_retained: 3 (NooBaa since 09-20, Secret/ogx-obc since 09-21, ServiceMesh since 09-25)

### Orphan ownerRefs (non-terminating): 1
- OAuthClient/data-science → deleted GatewayConfig/default-gateway

### Golden False Attribution (25 cases)
Isolated-plan DELETE with foreign ownerRef/managed-by/annotation evidence.
Ground truth in `golden-false-attribution.json`.

| Initial plan operator | Count | Evidence type |
|----------------------|-------|---------------|
| authorino-operator | 5 | ownerRef Kuadrant + RouteRule annotations |
| cluster-observability-operator | 4 | ownerRef Kserve/Config |
| limitador-operator | 1 | ownerRef Kuadrant |
| openshift-cert-manager-operator | 3 | ownerRef JobSetOperator |
| rhcl-operator | 2 | ownerRef Config + managed-by maas-controller |
| servicemeshoperator3 | 10 | ownerRef GatewayConfig/Config/Gateway |

Excludes: 4 RHCL explicit targets (user-approved positives), NFD NodeFeature (self-owned).

## Tools

| Tool | Corpus path | SHA256 |
|------|-------------|--------|
| Collector | tools-collect-inventory.py | `102a795f...` |
| Validator | tools-validate-pre-inventory.py | `5cb38d3d...` |
| Post-analysis | tools-post-analysis.py | `f35c52ed...` |

## Linked Artifacts

- [Source Study: Go Operators](../source-study-go-operators.md)
- [Discovery Improvement Plan](../discovery-improvement-plan.md)
- [Prior corpus (gap analysis only)](../20260926-cycle-b-3c77a17/)
