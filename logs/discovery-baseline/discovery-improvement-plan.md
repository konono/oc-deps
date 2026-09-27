# Discovery Improvement Plan after Phase 0

## Goal

Improve discovery completeness, scope accuracy, explainability, and request cost while
preserving the behavior proven by the Phase 0 Cycle B corpus.

The 25 cross-controller provider API operands are positive cases. They prove that the
current CSV-owned-CRD path finds operands created by an upstream platform controller but
served by a dependency operator. The redesign must preserve this recall.

## Fixed semantics

- `Owns`: exact Kubernetes ownerReference identity and UID.
- `ApiStewardship`: a CSV declares the CRD/APIService as owned.
- `References`, `Selects`, `Watches`, `Creates`, and `CleansUp` remain distinct evidence.
- Relationship evidence alone does not silently change CLI policy.
- `--approve-scope independent` explicitly authorizes provider API operand cleanup.
- Without that approval, independent operands remain REVIEW.
- A foreign lifecycle owner is useful for ordering and explanation; it is not a veto in
  an explicitly approved full teardown.
- Protected-kind exclusions govern direct actions. Kubernetes GC, reclaim, and API
  deregistration are reported outcomes rather than survival guarantees.

## Workstream 1: typed observation graph

Deliverable:

- Physical entity keyed by UID with every observed API alias.
- Full `group/version/kind/namespace/name/uid` identity.
- Typed relation and resolution state.
- Owner references retain controller and blockOwnerDeletion.
- API stewardship remains different from lifecycle ownership.
- Deterministic serialization.

Acceptance:

- All 25 provider operands have `ApiStewardship` to their provider operator and retain
  their actual lifecycle-owner/label/annotation evidence.
- Their full-teardown decision remains DELETE when independent scope is approved.
- Without independent approval they remain REVIEW.
- Same-kind different-group, stale UID, multi-owner, cycle, diamond, recreation,
  multi-version alias, and UID-null fixtures pass.
- No planner behavior changes in this workstream.

## Workstream 2: scope accuracy and coverage ledger

Deliverable:

- Record why each namespace and GVR entered discovery scope.
- Record every intended LIST/GET and its terminal outcome.
- Distinguish absent, forbidden, timeout, server failure, unsupported LIST, and empty.
- Fix namespace-reference heuristics using Kubernetes name validation, known typed paths,
  and schema/source evidence where necessary.
- Add cluster-scoped spec-ref coverage to the current namespaced map.

Acceptance:

- Limitador `spec.limits[].namespace=redhat-ai-gateway-infra/maas-api-route` is not
  treated as a Kubernetes namespace.
- Existing RHOAI namespace references remain discovered.
- 401/403 do not retry; timeout/408/429/5xx do.
- Strict mode emits partial results then exits 2.
- No silent empty result for a failed required query.
- Provider operand count remains 25/25.

## Workstream 3: shared query planner and performance

Deliverable:

- Compile discovery needs into unique `(GVR, scope, selector)` requests.
- Reuse LIST results across operators and relation extractors.
- Maintain indexes for UID, exact identity, label, ownerRef, and reverse spec references.
- Preserve pagination, retry, timeout, and shared concurrency limits.

Acceptance:

- Canonically sorted plans and discovery results match the accepted Workstream 2 output.
- Requests, bytes, retries, cache hits, and elapsed time are measured.
- No loss in provider operands, explicit targets, owner descendants, or known residuals.
- Demonstrate an actual request/time reduction before merging.

## Workstream 4: explainable pre/post audit

Deliverable:

- Before apply: expected direct deletes, expected GC descendants, expected controller
  cleanup, possible derived side effects, retained resources, and unknowns.
- After apply: compare actual state and report recreation, new Terminating objects,
  orphan ownerRefs, dangling references, and unexplained disappearance.
- Display API provider and lifecycle creator as separate fields.

Acceptance:

- Phase 0 classifications reproduce: 91 direct, 72 expected, 1,282 owner descendants,
  10 owner-unlinked, 2 proven derived, and 1,327 other/churn.
- Four protected-kind side effects remain visible as outcomes.
- OAuthClient orphan and 12 dangling refs across 2 targets are reported.
- Every report identifies the 25 cases as expected provider API cleanup.

## Workstream 5: targeted adapters only for demonstrated gaps

Do not implement broad operator-specific profiles preemptively. Add a version-bound
adapter only when the generic engine misses a resource in a reproducible corpus or live
comparison.

Candidate gaps already supported by evidence:

- controller/finalizer ordering where cleanup races controller removal,
- deterministic cluster resources absent from ownerRef/CSV inventory,
- field-level shared singleton mutations,
- external or remote cleanup that cannot be verified from the cluster.

Acceptance for each adapter:

- exact package/CSV or image/version binding,
- generic core remains free of operator names,
- mismatch degrades to REVIEW/Unknown,
- positive and negative fixtures,
- live `oc` comparison,
- measurable recall gain with no unrelated DELETE.

## Removed from the mandatory roadmap

The following are no longer required by the current evidence and should not be
implemented without a new concrete defect:

- automatic rejection of provider operands solely because their lifecycle owner differs,
- removal of `independent` approval,
- treating the 25 provider operands as wrong DELETEs,
- blanket source profiles for every operator,
- cross-cluster provenance framework,
- universal field-mutation rollback engine,
- outcome protection that promises CRD/PV/PVC survival from Kubernetes GC/reclaim.

## Review protocol

For each workstream:

1. Run fmt, clippy, all-target tests, and release build.
2. Run the offline Phase 0 validator twice and require byte-identical output.
3. Compare all 15 plans canonically with the previous accepted output.
4. Report additions/removals by relationship and action, including exact identities.
5. For read-only changes, compare representative results with `oc get -o json`.
6. Run destructive Cycle A/B only when planner/executor behavior changes.
7. Leave the cluster deleted until independent review when destructive tests run.
