# Discovery Improvement Plan

## Objective

Improve discovery accuracy, completeness, and speed without encoding operator names in
the core. Every phase is compared with the same Cycle B corpus and committed only after
reviewer GO. A larger result set is not automatically better: DELETE precision is the
first invariant.

## Phase 0: corpus and ground truth gate

Phase 0 is evidence collection and is not one of the ten implementation phases.

Required before Phase 1:

- all 15 target operators present before collection,
- canonical raw API discovery with GVR, GVK, namespaced, verbs, preferred/storage
  version information,
- all-GVR pre inventory with zero unrecorded LIST failures,
- `operator resources --scope related` for all 15, completed before deletion, exit 0,
  valid JSON,
- human-readable plan and ExecutionPlan for all 15,
- batch runtime plans and stdout/stderr,
- all-GVR post inventory with deletionTimestamp, finalizers, ownerRefs, labels,
  annotations, managed-field managers,
- version-normalized pre/post diff,
- orphan ownerRef report, remaining references to deleted objects, and resources newly
  stuck in deletion,
- explicit result for every known positive, negative, retained, and residual golden.

Inventory comparisons deduplicate by logical identity plus UID and preserve all served
versions as observations. Raw rows remain available for audit.

## Metrics used in every phase

| Metric | Required interpretation |
|---|---|
| DELETE precision | Confirmed lifecycle-owned DELETEs / all proposed DELETEs. Must remain 100%. |
| Discovery recall | Confirmed related objects found / source+live ground truth objects. Report by relationship type. |
| Authority recall | Confirmed deletable lifecycle children granted authority / all confirmed deletable children. |
| Unknown coverage | APIs/objects that could not be classified. Never count as absent. |
| Residual recall | Known post-delete residuals predicted before mutation. |
| Query cost | Unique LIST/GET calls, bytes, elapsed time, retry count, and cache hits. |

Any phase that converts a known negative case into DELETE is NO-GO regardless of recall
or speed improvements.

## Phase 1: typed relationship graph

### Deliverable

- Replace overloaded related/owned notions with typed edges:
  `OWNS`, `API_STEWARDSHIP`, `CREATES`, `CLEANS_UP`, `REFERENCES`, `WATCHES`,
  `MUTATES`, `RENDERS`, `REMOTE_CREATES`.
- Preserve full ownerRef identity: apiVersion/group/version, kind, namespace inferred
  from owner/child scope, name, UID, controller, blockOwnerDeletion.
- Store positive and negative evidence separately.
- Keep current CLI output available through projections of the new graph.

### Ground-truth comparison

- Existing expected owner chains still resolve.
- PersesDashboard, RHCL policy, JobSet certificate, Istio config, and Kuadrant AuthConfig
  cases are represented as API stewardship/watch/reference plus their actual owner,
  never as target lifecycle ownership.
- No loss of ResourceId group/version/namespace/name/UID.

### GO condition

Graph snapshot is deterministic and old plan behavior can be explained from typed
evidence without using operator-name conditionals.

## Phase 2: deletion authority and foreign-owner veto

### Deliverable

- Separate discovery from authority evaluation.
- Automatic authority requires exact live controller ownerRef lineage into the target
  closure, or an explicitly approved version-bound cleanup contract.
- A live owner outside the target closure is `ForeignOwned` and blocks all bulk scopes.
- Unresolved/stale/malformed owner identity is REVIEW/fail-closed.
- `CSV owned CRD/APIService` never grants instance DELETE authority.
- `managed-by`, watch labels, managedFields, deterministic names, and spec references
  can add evidence or veto, but cannot grant core authority alone.

### Golden negatives

- COO must preserve four RHOAI-owned PersesDashboard objects.
- RHCL must preserve MaaS AuthPolicy/TokenRateLimitPolicy objects.
- cert-manager must preserve JobSet Certificate/Issuer objects.
- Service Mesh must preserve RHOAI/Kuadrant DestinationRule/EnvoyFilter objects.
- Authorino must preserve Kuadrant-managed AuthConfig objects while Kuadrant owns them.

### Golden positives

- Root CR exact approval remains effective.
- Exact UID-verified descendants remain EXPECT/DELETE as intended.
- Explicit configured cleanup remains possible and retains inbound-reference guard.

### GO condition

DELETE precision is 100% on plan-only evaluation of the complete corpus. Then run the
first destructive Cycle B checkpoint and independently verify post state.

## Phase 3: scope discovery as a fixpoint

### Deliverable

- Begin with target OLM objects, install namespace, root CRs, and source-profile seeds.
- Expand candidate namespaces/GVRs through typed owner, spec namespace, annotation,
  rendered inventory, and operator-family edges until no new scope is found.
- Track why each namespace/GVR entered scope.
- Query each unique `(GVR, scope, selector)` at most once per snapshot.

### Ground-truth comparison

- Discover cert-manager operand namespace `cert-manager` from its root/source inventory.
- Discover RHOAI generated namespaces and `rhoai-model-registries` without global
  hardcoded namespace lists.
- Discover Sail cross-namespace objects through primary-resource annotations.
- Do not promote unrelated namespaces merely because they contain an API instance.

### GO condition

All known relevant namespaces are explained by evidence; unrelated namespace growth is
zero on the corpus.

## Phase 4: coverage ledger and fail-closed completeness

### Deliverable

- Record every intended and executed GET/LIST with canonical GVR, scope, selector,
  pagination, retry, result count, and typed failure.
- Distinguish API absent, forbidden, timeout, server failure, unsupported LIST, and
  empty result.
- Attach coverage requirements to authority rules. Missing required coverage prevents
  DELETE but still emits partial discovery output.
- Preserve the `--strict` partial-output contract.

### Ground-truth comparison

- Synthetic 403/timeout/5xx cases cannot appear as empty success.
- All APIs needed by each proposed DELETE have complete ledger entries.
- Optional APIs remain optional only when the rule explicitly declares them optional.

### GO condition

Corpus contains a machine-readable proof of what was and was not enumerated, with zero
silent coverage gaps.

## Phase 5: operator-family and controller-liveness graph

### Deliverable

- Model OLM requires/provides APIs separately from runtime lifecycle relations.
- Join suboperators through exact root ownership, install strategy, source profile, and
  controller identity.
- Associate each finalizer with the controller that processes it and record controller
  liveness.
- Add ordering constraints so finalizer-bearing objects finish cleanup before their
  controller is removed.

### Ground-truth comparison

- Kuadrant -> Authorino/Limitador family is visible without assigning their input CRs to
  the API provider.
- RHOAI module CRs and suboperator deployments form correct cleanup ordering.
- Authorino deterministic CRBs are expected finalizer cleanup outputs.
- All 15 plans no longer report an empty dependency graph when runtime dependencies are
  present.

### GO condition

Every finalizer strip candidate has a known/unknown controller and cleanup-domain record;
no controller is scheduled before a child finalizer it must process.

## Phase 6: shared query planner and performance

### Deliverable

- Compile relationship recipes into a shared query plan.
- Coalesce equal LISTs and serve multiple operators/edges from one result.
- Build reusable owner UID, exact identity, labels, annotations, field paths, and
  reverse-reference indexes.
- Prefer server-side selectors when semantically complete; apply client filtering where
  Kubernetes selectors cannot express the rule.
- Cache discovery by cluster UID and API surface version with explicit refresh.

### Ground-truth comparison

- Graph and plan output are identical to Phase 5 after canonical sorting.
- Measure unique requests, transferred bytes, and wall time against Phase 0.
- Pagination and multi-version identities remain correct.

### GO condition

No accuracy regression and a documented request/time improvement. Then run the second
destructive Cycle B checkpoint.

## Phase 7: version-bound rendered and source profiles

### Deliverable

- Typed profiles bind installed package/CSV/image digest to source revision.
- Profiles can supply embedded/Helm inventory, deterministic names, exact label tuples,
  field indexes, cleanup recipes, retained exceptions, and cross-namespace mappings.
- Profiles degrade to Unknown/Review on version/digest mismatch.
- Generic engine remains free of operator/resource names.

### Initial profiles from source study

- RHOAI annotation tuple and retained ImageStreams.
- Sail primary-resource annotations and Helm release inventory.
- NFD SCC deterministic cleanup.
- cert-manager static operand inventory and watched-by negative rule.
- Kuadrant ConsolePlugin/AuthConfig rules.
- Authorino CRB deterministic cleanup.
- COO/OTel ownerRef-less cluster RBAC label tuples.

### GO condition

Each profile improves at least one known recall gap, introduces no new DELETE without
live/source-bound evidence, and has version mismatch tests.

## Phase 8: pre/post graph diff and residual auditor

### Deliverable

- Predict expected gone, expected retained, expected mutation rollback, unknown, and
  external-unverifiable objects before apply.
- Compare the post snapshot to that prediction.
- Report orphan ownerRefs, inbound references to deleted objects, newly terminating
  resources, retained mutations, and unplanned disappearances.
- Treat Kubernetes GC and finalizer deletion as observed mechanisms, not assumed success.

### Ground-truth comparison

- Detect `OAuthClient/data-science` orphan and stuck `ServiceMesh/default-servicemesh`.
- Report cert-manager operand residuals and generated namespaces.
- Classify `download-qwen3-06b` as unknown/user-managed rather than auto-delete.
- Distinguish known Issue #4 residuals from newly discovered residuals.

### GO condition

The auditor finds every known Phase 0 residual and produces no unreviewed destructive
recommendation.

## Phase 9: mutation, shared singleton, finalizer, and external-state safety

### Deliverable

- Represent field-level mutations separately from resource deletion.
- Support safe patch actions for shared singleton fields only with before/value/manager
  evidence and drift checks.
- Classify finalizer cleanup domains: Kubernetes-only, cluster-scoped, external system,
  remote cluster, unknown.
- Unknown/external finalizers require explicit approval; automatic blanket stripping is
  removed.
- Report resources whose absence cannot prove external cleanup.

### Ground-truth comparison

- Node and Namespace objects are never deleted due to NFD/GPU mutations.
- COO Console plugin deregistration patches only its array entry.
- DNS finalizer is never stripped automatically.
- RHOAI controller race is solved by ordering before considering recovery.

### GO condition

Every forced finalizer action is visible in the plan, identifies lost cleanup, and has
the required approval. Shared objects have field-level rollback only.

## Phase 10: adapter completion and cross-cluster provenance

### Deliverable

- Complete source profiles for the Cycle B operator families.
- Add remote target descriptors for MultiKueue, DNS multicluster, and external providers.
- Surface `Verified`, `Partial`, `Unavailable`, or `NotConfigured` per external target.
- Add a profile conformance suite so a new operator can be evaluated without adding
  core branches.
- Document how to author, version, and audit profiles.

### GO condition

- Full plan-only comparison passes for 15/15 operators.
- DELETE precision remains 100%.
- Each source-confirmed relationship is found or explicitly classified unsupported.
- Coverage ledger has no unexplained gaps.
- Final destructive Cycle B passes; independent reviewer verifies the deleted cluster
  before recovery.

## Per-phase review protocol

1. Implement one phase on its own branch/commit candidate.
2. Run fmt, clippy, all targets, release build.
3. Generate discovery graph and all 15 plans from the unchanged recovered baseline.
4. Canonically diff against the Phase 0 corpus and previous accepted phase.
5. Produce precision/recall/unknown/query metrics and named golden results.
6. Send the evidence to terminal_4.
7. terminal_4 independently inspects code and live/read-only evidence.
8. Commit only after explicit GO; otherwise fix and repeat the same phase.
9. Run destructive Cycle B only at the Phase 2, Phase 6, and Phase 10 checkpoints.
10. Leave the cluster deleted for reviewer verification after each destructive run.

After Phase 10, resume the remaining open #28 CLI documentation/UX work and #21 network
runtime metrics work.
