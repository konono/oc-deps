# Go Operator Source Study for Discovery Design

This document records source-level relationship patterns found across the operator
families used by the Cycle B corpus. It is research input, not deletion authority by
itself. Exact source revisions are recorded where the installed image exposed a public
commit; otherwise the closest public release is marked as approximate.

## Semantic rule

The implementation must preserve the difference between these relationships:

| Relationship | Meaning | May grant DELETE authority by itself? |
|---|---|---|
| `OWNS` | Exact live ownerRef identity, including apiVersion/kind/name/UID | Yes, within a verified target closure |
| `CREATES` | Controller source renders or applies the object | No; requires live/source-bound re-identification |
| `CLEANS_UP` | Finalizer or uninstall code explicitly deletes the object | No; requires version-bound cleanup contract and safety classification |
| `REFERENCES` | Spec, annotation, or field-index dependency | No |
| `WATCHES` | Reconcile trigger or map function | No |
| `MUTATES` | Controller patches a shared object or a field of it | Never delete the object from this evidence |
| `RENDERS` | Embedded manifest or Helm output contains the object | Inventory evidence, not proof it was created live |
| `REMOTE_CREATES` | Controller creates objects in another cluster/provider | Requires external inventory; local absence is inconclusive |

`CSV.spec.customresourcedefinitions.owned` is `API_STEWARDSHIP`: it says which
operator supplies an API. It does not establish lifecycle ownership of every instance.

## Operator matrix

### RHOAI / OpenDataHub

- Installed source: `rhods-operator.3.5.1`; image commit
  [`521e115`](https://github.com/red-hat-data-services/rhods-operator/tree/521e11529f00a74fbc3f8cc683c5fb8b7fd11ba4).
- Workbenches suboperator image commit
  [`9b87a69`](https://github.com/red-hat-data-services/workbenches-operator/tree/9b87a6903bb7e9643530f6c9292c5a2a6553220f).
- Uses controller ownerRefs for many module CRs and children.
- Uses an annotation/label tuple containing part-of, instance name, instance UID,
  generation, and platform version to re-identify resources.
- Module CR finalizers require their suboperator controller to remain live. Parent
  deletion can garbage-collect that controller before finalization completes.
- Embedded Helm/Kustomize assets and deterministic module names provide desired
  inventory.
- Generated namespaces use `opendatahub.io/generated-namespace=true`, but an existing
  namespace can receive this label; the label alone is not deletion authority.
- Workbench ImageStreams are intentionally retained even when management labels match.
- Discovery additions: annotation-tuple matcher, rendered inventory, finalizer-controller
  dependency, expected-retained classification, namespace provenance.

### Keycloak / RHBK

- Installed `rhbk-operator.v26.6.7-opr.1`; public upstream `26.6.7` is approximate
  because the downstream image revision is not public.
- Keycloak children include StatefulSet, Services, admin Secret, Ingress,
  NetworkPolicy, and optional ServiceMonitor, generally with ownerRefs.
- `KeycloakRealmImport.spec.keycloakCRName` references a Keycloak CR without making
  the RealmImport its child. RealmImport-created Job/Secret use ownerRefs.
- Discovery additions: CRD-schema/source-derived nonstandard spec reference and an
  ordering edge from RealmImport to its referenced Keycloak.

### LeaderWorkerSet

- Closest source: [`openshift/lws-operator release-4.22`](https://github.com/openshift/lws-operator/tree/release-4.22)
  and [`kubernetes-sigs/lws v0.8.0`](https://github.com/kubernetes-sigs/lws/tree/v0.8.0).
- Downstream operator applies a finite embedded manifest inventory and attaches the
  cluster-scoped `LeaderWorkerSetOperator/cluster` ownerRef.
- Operand graph is multi-hop: LeaderWorkerSet -> leader StatefulSet -> leader Pod ->
  worker StatefulSet -> Pods/PVCs. The worker StatefulSet can be owned by a Pod.
- Label map functions are reconcile hints; recursive UID-verified owner traversal is
  the lifecycle evidence.

### JobSet

- Source: [`openshift/jobset-operator release-4.22`](https://github.com/openshift/jobset-operator/tree/release-4.22),
  operand near [`c1fa7bc`](https://github.com/kubernetes-sigs/jobset/tree/c1fa7bc0de0a6ef1dc2f899562501c0fe9ae0862).
- Downstream operator uses embedded assets with root ownerRefs.
- JobSet owns Jobs, headless Service, and optional PVCs; Jobs own Pods.
- The controller uses owner field indexes for child Jobs and label watches for Pods.
- JobSet-created Certificate/Issuer objects consume cert-manager APIs. They are not
  cert-manager lifecycle children.

### Kueue

- Source: [`openshift/kueue-operator release-1.4`](https://github.com/openshift/kueue-operator/tree/release-1.4),
  pinned upstream commit near `1ec8e50`.
- Downstream root owns embedded assets across namespaces and cluster scope.
- Operand integrations own Kueue Workloads from source Jobs, while queue, flavor,
  admission, topology, and RuntimeClass edges are references.
- Kueue mutates source workloads (suspend, scheduling gates, status); it does not own
  those source objects.
- MultiKueue may create remote resources, so local inventory cannot prove completeness.
- Finalizer cleanup includes deterministic resources and broad name matches; broad
  source predicates must be narrowed by live identity before use as deletion authority.

### Service Mesh 3 / Sail

- Closest source: [`sail-operator 1.30.4`](https://github.com/istio-ecosystem/sail-operator/tree/1.30.4).
- Istio deterministically creates IstioRevision; revision, CNI, and ztunnel controllers
  render Helm inventories.
- Same-namespace or cluster-scoped children receive ownerRefs.
- Cross-namespace rendered resources receive `operator-sdk/primary-resource-type` and
  `operator-sdk/primary-resource=<namespace>/<name>` annotations.
- Helm release Secrets hold the concrete rendered manifest and are strong inventory
  candidates.
- Istio DestinationRule/EnvoyFilter instances created by RHOAI/Kuadrant are consumers
  of Istio APIs, not Sail-owned instances.
- Discovery additions: cross-namespace primary-resource annotations plus Helm release
  manifest inventory, with source UID/manager verification.

### Node Feature Discovery

- Source: [`openshift/cluster-nfd-operator release-4.22`](https://github.com/openshift/cluster-nfd-operator/tree/release-4.22).
- Root ownerRef covers Deployment, DaemonSet, ConfigMap, and Job.
- Namespaced root cannot own cluster-scoped SCCs; finalizer cleanup uses deterministic
  names `nfd-worker` and `nfd-topology-updater`.
- NFD mutates Node feature labels and taints; Nodes must never become deletion targets.
- Compatibility code creates same-name CRs across old/new API groups.
- Discovery additions: deterministic cluster-scoped cleanup contract, mutation ledger,
  and cross-group conversion edge.

### NVIDIA GPU Operator

- Source: [`NVIDIA/gpu-operator v26.7.1`](https://github.com/NVIDIA/gpu-operator/tree/v26.7.1).
- ClusterPolicy attaches ownerRefs to broad namespaced and cluster-scoped child sets.
- Driver DaemonSet names may include OS/kernel suffixes; prefix matching alone is unsafe.
- GPUCluster finalizer foreground-deletes controlled DaemonSets after verifying
  `IsControlledBy`.
- Operator mutates Node labels and an admin-access namespace label; these are mutation
  records, not owned resources. Some namespace mutations are intentionally retained.

### OpenShift cert-manager Operator

- Source family: [`openshift/cert-manager-operator cert-manager-1.20`](https://github.com/openshift/cert-manager-operator/tree/cert-manager-1.20).
- Static-resource controllers and embedded assets manage exact Deployments, Services,
  RBAC, webhooks, NetworkPolicies, samples, and operand namespace resources, commonly
  without a root ownerRef.
- TrustManager and IstioCSR use label/inventory identification; cleanup is incomplete
  in the studied source.
- `istiocsr.openshift.operator.io/watched-by` marks watched input Secret/Issuer/ConfigMap
  objects, not owned children.
- Certificate `secretName` and `issuerRef` are references; output Secret ownership is
  configuration-dependent.
- JobSet Certificates/Issuer are a corpus-negative case for API stewardship confusion.

### Kuadrant / RHCL

- Closest public source matching the image version:
  [`Kuadrant/kuadrant-operator v1.5.3`](https://github.com/Kuadrant/kuadrant-operator/tree/v1.5.3).
- Authorino and Limitador root CRs receive Kuadrant ownerRefs.
- DNSRecord and policy extension output use ownerRefs where possible.
- AuthConfig, monitoring objects, developer portal, and ConsolePlugin resources may be
  ownerRef-less and are re-identified by exact labels, annotations, namespace mapping,
  and deterministic names.
- ConsolePlugin identities include ConsolePlugin/Deployment/Service
  `kuadrant-console-plugin`, ConfigMap `kuadrant-console-nginx-conf`, and serving Secret
  `plugin-serving-cert`; `spec.backend.service` is a reverse reference.
- Gateway, Route, AuthPolicy, RateLimitPolicy, and similar CRs are controller inputs.
  Watching or providing their CRD does not establish ownership.

### Authorino

- Source: [`Kuadrant/authorino v0.25.3`](https://github.com/Kuadrant/authorino/tree/v0.25.3).
- Authorino root owns Deployment, Services, ServiceAccount, Role, and RoleBinding, even
  though controller-runtime `.Owns()` registers only Deployment.
- ClusterRoleBindings `authorino-authorino` and `authorino-authorino-k8s-auth` cannot
  have the namespaced root as owner and are removed by deterministic-name finalizer code.
- Hash-named AuthConfig objects in the corpus are generated by Kuadrant and must not be
  assigned to Authorino merely because Authorino provides the API.

### DNS Operator

- Source: [`Kuadrant/dns-operator v0.17.2`](https://github.com/Kuadrant/dns-operator/tree/v0.17.2).
- DNSRecord owns DNSHealthCheckProbe; cleanup also lists probes by
  `kuadrant.io/health-probes-owner`.
- Probe watch mapping is a reconcile relationship, separate from ownership.
- DNS finalizers delete and verify records at the external DNS provider. Stripping the
  finalizer can orphan external state.
- `kuadrant.io/multicluster-kubeconfig=true` Secrets enable remote-cluster resources;
  local inventory is incomplete without the remote target.

### Limitador

- Source: [`Kuadrant/limitador-operator v0.18.4`](https://github.com/Kuadrant/limitador-operator/tree/v0.18.4).
- Limitador owns Deployment, Service, ConfigMap, PVC, and PDB, while `.Owns()` registers
  only Deployment, ConfigMap, and PDB.
- Deterministic names plus `limitador-resource`, managed-by, and part-of labels provide
  additional re-identification evidence.

### Cluster Observability Operator

- Exact public image commit:
  [`rhobs/observability-operator b0d29de`](https://github.com/rhobs/observability-operator/tree/b0d29debe1173ee0c4634ac78c34f0031a511e48).
- One CSV contains observability, Prometheus, admission, and Perses controllers.
- Generated resources share an exact managed-by/part-of/name label tuple. OwnerRefs are
  used only where scope permits.
- MonitoringStack cluster RBAC is ownerRef-less and is deleted through finalizer cleanup.
- ThanosQuerier indexes TLS Secret reference fields; those Secrets are dependencies.
- UIPlugin mutates shared `Console/cluster.spec.plugins[]`; the Console must be patched,
  not deleted.
- ObservabilityInstaller distinguishes operator-created Subscriptions using both name
  rules and managed-by labels so user-installed subscriptions remain untouched.
- RHOAI PersesDashboard instances are the primary corpus-negative case.

### OpenTelemetry Operator

- Closest public source: [`open-telemetry/opentelemetry-operator v0.158.0`](https://github.com/open-telemetry/opentelemetry-operator/tree/v0.158.0).
- Namespaced children are listed through owner field indexes; candidate types include
  workloads, Services, ConfigMaps, RBAC, monitoring objects, Route, and HTTPRoute.
- Cluster RBAC lacks ownerRefs and is identified by an exact four-label tuple including
  a truncated `<namespace>.<collector-name>` instance value; finalizer removes it.
- TargetAllocator is a nested owner root with its own children.
- Injection and sidecar annotations resolve Instrumentation/Collector inputs in the
  same or another namespace. Annotated workloads are consumers, never delete targets.

## Re-identification functions suitable for the generic core

These recur across multiple independent operator families:

1. `OwnerUID(apiVersion, kind, namespace, name, uid, controller)`
2. `ExactGet(GVR, namespace, deterministicName)`
3. `LabelList(GVR, scope, complete key/value tuple)`
4. `FieldIndex(GVR, fieldPath, referenced identity)`
5. `SpecReference(source GVK, fieldPath, target identity)`
6. `AnnotationReference(key, structured value, target identity)`
7. `RenderedInventory(source digest/version, object identities)`
8. `FinalizerCleanup(source version, selector/name recipe, cleanup domain)`
9. `CrossNamespacePrimaryResource(annotation tuple)`
10. `Mutation(object identity, field path, manager)`

Each query should be executed once per unique `(GVR, scope, selector)` and reused by all
operators. Results enter a typed relationship graph. Discovery breadth and DELETE
authority remain separate decisions.

## Source-profile boundary

Rules observed in two or more independent operator families may enter the generic core.
Single-family behavior belongs in a typed, version-bound source profile with:

- installed image digest and source revision,
- supported CSV/package versions,
- exact query recipe,
- relationship type,
- evidence strength and negative evidence,
- expected retained behavior,
- finalizer cleanup domain,
- tests against live corpus identities.

Profiles must degrade to `Unknown/Review` when the installed digest or version does not
match. They must never silently fall back to a similarly named operator or API group.
