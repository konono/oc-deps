# P0 Gap: Unplanned transitive/derived deletions of protected resources

## Finding

`--prune-crds=false` guarantees no direct CRD DELETE actions, but does NOT prevent
transitive deletion via Kubernetes GC ownerRef cascade or side effects.

4 protected-kind resources were deleted without direct plan action:

### 1. CRD: jobsets.jobset.x-k8s.io
- **Pre UID**: from pre-inventory
- **ownerRef**: JobSetOperator/cluster (uid=b943...)
- **Causal chain**: job-set plan DELETE JobSetOperator/cluster → K8s GC cascades to owned CRD
- **Impact**: jobset.x-k8s.io/v1alpha2 API disappears (pre GVR=538, post=537)

### 2. APIService: v1alpha2.jobset.x-k8s.io
- **ownerRef**: none (aggregator registration)
- **Causal chain**: CRD deletion causes API server to deregister the aggregated APIService
- **Impact**: secondary side effect of CRD cascade

### 3. PVC: mlflow-pvc (ns: redhat-ods-applications)
- **ownerRef**: MLflow/mlflow
- **Causal chain**: RHOAI plan DELETE MLflow/mlflow → K8s GC cascades to owned PVC
- **Impact**: persistent data loss (mlflow workspace data)

### 4. PV: pvc-78fb5c3e-4a6e-4cc3-a9aa-5b332657ab53
- **ownerRef**: none (provisioner binding)
- **Causal chain**: PVC deletion → PV reclaim policy triggers PV deletion
- **Impact**: secondary side effect of PVC cascade, storage deprovisioned

## Root Cause

Current `--prune-crds=false` and "Namespace/PV/PVC/CRD/APIService KEEP" is implemented as
direct-action exclusion only. If a planned DELETE target owns a protected resource via
ownerRef, K8s GC will cascade-delete it regardless.

## Design Fix (Phase 1 graph + Phase 2 safety gates)

- Phase 1: ResourceNode graph must include ownerRef edges from protected kinds
  to their owners. If owner is in DELETE closure, the protected descendant must
  be flagged as CASCADE_AT_RISK.
- Phase 2: Planner safety gate must detect when a DELETE action would transitively
  cascade to a protected kind and either:
  - Block the DELETE with explanation
  - Require explicit acknowledgment
  - Remove the ownerRef before deleting the owner (orphan the protected resource)
- distinction: direct action exclusion vs outcome protection
- regression test: JobSetOperator/cluster DELETE must warn about owned CRD cascade
- regression test: MLflow/mlflow DELETE must warn about owned PVC cascade

## Additional Findings

### Post Terminating (3 stuck resources)
- Secret/ogx-obc: finalizer objectbucket.io/finalizer, since 2026-09-21
- NooBaa/noobaa: finalizer noobaa.io/graceful_finalizer, since 2026-09-20 (pre-existing ODF)
- ServiceMesh/default-servicemesh: finalizer platform.opendatahub.io/finalizer, since 2026-09-25

### Orphan ownerRef (1)
- OAuthClient/data-science → deleted GatewayConfig/default-gateway (cluster-scoped
  OAuthClient not GC'd despite controller ownerRef to deleted resource)

### Cross-controller provider API operands — expected cleanup

The batch directly deleted provider-API operands discovered from CSV-owned CRDs. These
are desired full-teardown results because `independent` scope was explicitly approved:

- TokenRateLimitPolicy/gateway-default-deny: deleted via RHCL provider API inventory.
- PersesDashboard ×4: deleted via COO/Perses provider API inventory.
- Certificate/Issuer ×3: deleted via cert-manager provider API inventory.
- AuthPolicy/maas-gateway-auth: deleted via RHCL provider API inventory.
- AuthConfig ×4 and Authorino ×1: deleted via Authorino provider API inventory.
- Limitador ×1: deleted via Limitador provider API inventory.
- DestinationRule ×4 and EnvoyFilter ×6: deleted via Service Mesh provider API inventory.

The lifecycle creator evidence is retained separately. It explains why the objects exist
and informs ordering, but it does not veto explicitly approved full teardown cleanup.
The complete 25-case oracle is `provider-api-operands.json`.
