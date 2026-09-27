# Phase 0 Cycle B2 Discovery Baseline Corpus

## Purpose

This corpus freezes the behavior of `oc-deps` at the PR #35 release cutoff. It records
what the tool discovered, planned, deleted, expected to disappear, and observed after a
full 15-operator teardown. It is evidence for later Discovery work; it is not production
runtime input.

The 25 cross-controller objects in `provider-api-operands.json` are **positive full
teardown cases**. A dependency operator provided their API while another controller
created or managed the object. The generic discovery path found them through the
provider CSV's owned CRD and the full teardown configuration explicitly approved the
`independent` scope.

## Identity

- Git: `3c77a17a606d9030def827b0fd8dd1d7e2e43b44`
- Binary SHA256: `029f0eea4ad7fd7ac84a8302fec7e2c95206c4a1e605416b232af0c4f1bd4db6`
- Cluster kube-system UID: `73072fbb-5d55-4ad1-a239-256da1ebea4e`
- Config SHA256: `428eeb789b97227ff1950d120bbf20b0baa0ab5e35ee72c23933c533b3211263`

## Collection gates

- 538 served GVRs catalogued across all served versions.
- Pre inventory: 17,786 raw observations, 17,668 API-logical identities, 11,716 physical UIDs.
- Post inventory: 14,761 raw observations, 14,719 API-logical identities, 9,165 physical UIDs.
- Pre/post LIST failures: 0.
- Operator resources: 15/15 captured before deletion.
- Isolated plans: 15/15 captured before deletion.
- Batch attempt 2: 15/15 succeeded, 0 failed, 0 skipped.
- Secrets contain metadata only; token-bearing APIs use redacted count records.

## Exact core invocations

```bash
./target/release/oc-deps operator resources '<operator>' --scope related -o json

./target/release/oc-deps teardown plan '<operator>' \
  --approve-scope root \
  --approve-scope independent \
  --approve-scope label-only \
  --approve-scope operator-group \
  --file plans/<operator>-plan.json -o json

./target/release/oc-deps teardown batch configs/full-teardown.json \
  --refresh-discovery

python3 tools-collect-inventory.py \
  inventory/pre-inventory.jsonl \
  inventory/pre-list-failures.jsonl \
  inventory/gvr-catalog.json

python3 tools-post-analysis.py \
  inventory/pre-inventory.jsonl \
  inventory/post-inventory.jsonl \
  batch-plans \
  provider-api-operands.json \
  inventory/gvr-catalog.json \
  post-analysis.json
```

## Provider API operands: 25 positive cases

Discovery path:

```text
Subscription -> canonical CSV -> spec.customresourcedefinitions.owned
  -> resolve CRD to served GVR -> cluster-wide LIST -> UID deduplication
  -> graph position independent -> explicit independent approval -> DELETE
```

| API provider operator | Count | Operand kinds | Lifecycle creator evidence |
|---|---:|---|---|
| authorino-operator | 5 | AuthConfig, Authorino | RouteRule annotations, Kuadrant ownerRef |
| cluster-observability-operator | 4 | PersesDashboard | Kserve/MaaS Config ownerRefs |
| limitador-operator | 1 | Limitador | Kuadrant ownerRef |
| openshift-cert-manager-operator | 3 | Certificate, Issuer | JobSetOperator ownerRef |
| rhcl-operator | 2 | AuthPolicy, TokenRateLimitPolicy | MaaS managed-by/Config ownerRef |
| servicemeshoperator3 | 10 | DestinationRule, EnvoyFilter | GatewayConfig/MaaS Config/Gateway ownerRefs |

Required semantics:

- Without `independent` approval: `REVIEW`.
- With the recorded full teardown config: `DELETE`.
- The lifecycle creator evidence remains visible for explanation and ordering.
- A foreign lifecycle owner is not a veto when full teardown explicitly authorizes
  provider API operand cleanup.

## Physical UID removal classification

| Category | Count |
|---|---:|
| Direct DELETE | 91 |
| EXPECT gone | 72 |
| Planned ownerRef descendants | 1,282 |
| Owner disappeared, unlinked | 10 |
| Proven derived side effects | 2 |
| Other removed/churn | 1,327 |
| **Total removed physical UIDs** | **2,784** |

The DELETE-seed ownerRef closure contains 1,460 UIDs; 1,445 disappeared.

## Direct-action versus outcome contract

`--prune-crds=false` and the Namespace/PV/PVC/CRD/APIService exclusions prevent
`oc-deps` from creating direct DELETE actions for those protected kinds under the normal
teardown contract. They do not guarantee survival from Kubernetes ownerReference garbage
collection, storage reclaim, or API deregistration.

Observed side effects:

- `CRD/jobsets.jobset.x-k8s.io`: ownerRef descendant of JobSetOperator.
- `APIService/v1alpha2.jobset.x-k8s.io`: API deregistration after CRD removal.
- `PVC/mlflow-pvc`: ownerRef descendant of MLflow.
- `PV/pvc-78fb5c3e`: PVC binding/reclaim side effect.

This behavior was explicitly accepted for the PR #35 release cutoff on 2026-09-27.

## Other frozen observations

- Newly terminating objects: 0.
- Pre-existing terminating objects retained: 3.
- Non-terminating orphan ownerRef: 1 (`OAuthClient/data-science` to deleted GatewayConfig).
- Post-live to pre-removed spec refs: 12 edges across 2 targets.
- Multi-observed physical UIDs: 4,510.
- Recreated objects: 2 physical objects across 3 API-logical identities.
- UID-null observations are retained with collision fingerprints.

## Known limitation

Limitador's `spec.limits[].namespace` value
`redhat-ai-gateway-infra/maas-api-route` is an application rate-limit namespace, but the
current related-scope heuristic treats it as a Kubernetes namespace. This produced 271
scan warnings in `operator resources --scope related`. It did not prevent teardown and is
frozen as a later scope-discovery regression case.

## Compact repository representation

The repository keeps this README, manifest, compact machine-readable summaries,
validation tools, and a compressed full corpus. Expanded inventories, plans, and command
logs are inside `full-corpus.tar.zst` to avoid adding more than 185,000 generated lines to
the product PR.

Restore and verify:

```bash
sha256sum -c ARTIFACT_SHA256
mkdir /tmp/oc-deps-phase0-corpus
tar --zstd -xf full-corpus.tar.zst -C /tmp/oc-deps-phase0-corpus
python3 /tmp/oc-deps-phase0-corpus/tools-post-analysis.py \
  /tmp/oc-deps-phase0-corpus/inventory/pre-inventory.jsonl \
  /tmp/oc-deps-phase0-corpus/inventory/post-inventory.jsonl \
  /tmp/oc-deps-phase0-corpus/batch-plans \
  /tmp/oc-deps-phase0-corpus/provider-api-operands.json \
  /tmp/oc-deps-phase0-corpus/inventory/gvr-catalog.json \
  /tmp/oc-deps-phase0-corpus/post-analysis.rebuilt.json
```
