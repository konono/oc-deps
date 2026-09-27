# Discovery Implementation Handoff

## 1. Current release boundary

PR #35 is cut at product commit `3c77a17`. This commit passed the complete Cycle B
teardown with 15/15 operators, zero operator failures, explicit RHOAI/RHCL cleanup, plan
drift validation, and post-delete inventory collection.

Phase 1 experimental graph work is preserved separately on branch
`wip/discovery-phase1`. Do not merge that branch into PR #35.

The canonical Phase 0 evidence is:

```text
logs/discovery-baseline/20260926-cycle-b2-3c77a17/
```

The expanded corpus is stored as `full-corpus.tar.zst`; compact summaries and validators
remain reviewable in the repository.

## 2. Product semantics established by Phase 0

### 2.1 Provider API operands are desired cleanup targets

The following is an intended generic discovery route:

```text
Subscription
  -> canonical CSV
  -> spec.customresourcedefinitions.owned / owned APIService
  -> resolve served GVR
  -> cluster-wide LIST
  -> UID deduplication
  -> graph position
  -> configured approval policy
```

Twenty-five objects were created or managed by an upstream controller while their APIs
were provided by a dependency operator. Examples include:

- Kuadrant-created Authorino and Limitador operands,
- RHOAI-created Perses dashboards,
- JobSet-created cert-manager operands,
- MaaS-created Kuadrant policies,
- RHOAI/MaaS/Gateway-created Istio resources.

These are positive full-teardown cases.

Required decision behavior:

```text
independent approval absent  -> REVIEW
independent approval present -> DELETE
```

The actual lifecycle creator remains evidence for ordering and explanation. It does not
block explicitly approved provider API cleanup.

### 2.2 Direct action exclusion is not outcome protection

Namespace, PV, PVC, CRD, and APIService are excluded from normal direct DELETE actions.
Kubernetes may still remove them through ownerReference garbage collection, storage
reclaim, or API deregistration. Phase 0 observed four such side effects. This contract
was accepted for the PR #35 cutoff.

### 2.3 Evidence must remain multi-dimensional

Do not collapse these concepts:

- API provider/steward,
- Kubernetes lifecycle owner,
- creator or field manager,
- selector/reference consumer,
- explicit cleanup declaration,
- deletion approval policy.

A single object can correctly have an API provider different from its lifecycle creator.

## 3. Frozen Phase 0 facts

```text
pre raw observations:          17,786
post raw observations:         14,761
pre API-logical identities:    17,668
post API-logical identities:   14,719
pre physical UIDs:             11,716
post physical UIDs:             9,165
removed physical UIDs:          2,784
added physical UIDs:               233
```

Removal classification:

```text
direct DELETE:                     91
EXPECT gone:                       72
planned ownerRef descendants:   1,282
owner disappeared/unlinked:        10
proven derived side effects:         2
other removed/churn:             1,327
```

Additional oracles:

- provider API operands: 25 positive cases,
- protected-kind side effects: 4,
- newly Terminating: 0,
- pre-existing Terminating retained: 3,
- orphan ownerRef: 1,
- dangling post-live spec refs: 12 edges to 2 removed targets,
- multi-observed physical UIDs: 4,510,
- pre/post LIST failures: 0.

## 4. What is complete

- CLI v2 teardown plan/apply/batch structure.
- Typed saved plans, cluster identity, UID binding, authority/drift comparison.
- Apply-time fresh revalidation.
- Explicit cleanup with inbound-reference guard.
- Recursive multi-owner ownerRef closure checks.
- Presence-only batch baseline gate.
- Advisory CSV health and controller availability.
- Full Cycle A and Cycle B execution.
- Phase 0 all-GVR pre/post evidence and deterministic offline analyzer.
- Go operator source study.

## 5. Experimental Phase 1 status

Branch `wip/discovery-phase1` contains an unmerged typed graph prototype. It includes
relations such as Owns, ApiStewardship, Creates, References, Watches, and CleansUp;
resolution states; physical UID entities; and alias preservation.

Before resuming it:

1. Use the provider API operand terminology and schema from the corrected Phase 0 corpus.
2. Keep the graph observational. Do not connect graph-only `can_authorize_delete` logic
   to the teardown planner without an explicit policy layer.
3. Validate all 25 cases as ApiStewardship plus their actual lifecycle evidence.
4. Require DELETE with independent approval and REVIEW without it.
5. Preserve exact group/kind/namespace/name/UID matching.
6. Generate deterministic corpus output twice and compare bytes.

The prototype may be simplified or discarded if it does not improve a measured gap.
Its existence does not require completing a graph redesign.

## 6. Remaining work, reduced scope

The mandatory ten-phase roadmap has been reduced to five evidence-driven workstreams.
Full details are in `logs/discovery-baseline/discovery-improvement-plan.md`.

### Workstream 1: typed observation graph

Purpose: explain different relationships without changing current teardown behavior.

Code areas likely involved:

```text
src/graph/evidence.rs
src/graph/mod.rs
src/kube/resource.rs
src/kube/snapshot.rs
src/teardown/explain.rs
```

Required tests:

- exact ownerRef identity and UID,
- stale/recreated owner,
- same kind/name across groups,
- namespace mismatch,
- multiple owners,
- cycle and diamond DAG,
- API alias preservation,
- UID-null representation,
- deterministic output,
- all 25 provider operands retain provider and creator evidence.

No destructive E2E is required because planner/executor behavior must remain unchanged.
Read-only live checks should compare representative graph nodes with `oc get -o json`.

### Workstream 2: scope accuracy and coverage

Primary concrete defect:

```text
Limitador.spec.limits[].namespace = redhat-ai-gateway-infra/maas-api-route
```

This is not a Kubernetes namespace. Fix with Kubernetes DNS-name validation and typed or
schema-backed namespace paths. Avoid a Limitador-specific name check.

Add a coverage ledger for every intended GET/LIST. Required query state:

```rust
pub enum QueryOutcome {
    Success { count: usize, pages: usize },
    ApiAbsent,
    Forbidden,
    Timeout,
    RateLimited,
    ServerError,
    ListUnsupported,
}
```

Tests:

- invalid slash-containing namespace rejected,
- real RHOAI namespace fields retained,
- 403 has one request,
- timeout/429/5xx retry and record retry count,
- required query failure makes strict exit 2 after output,
- optional absent API does not fail,
- 25 provider operands remain present.

Read-only E2E:

- collect all 15 `operator resources` results before deletion,
- compare discovered namespace names with `oc get namespace`,
- require Limitador warning count to fall from 271 without losing real resources,
- save stdout, stderr, exit code, request summary, and canonical JSON.

### Workstream 3: shared query planner

Only begin after Workstream 2 output is accepted.

Implement a unique request key:

```rust
struct QueryKey {
    gvr: CanonicalGvr,
    namespace: Option<String>,
    label_selector: Option<String>,
    field_selector: Option<String>,
}
```

Reuse one result across relation extractors and operator analyses. Keep shared semaphore,
pagination, timeout, retry, and refresh-discovery behavior.

Acceptance:

- identical canonical resource and plan output,
- lower unique request count or elapsed time,
- no new warning or incomplete namespace,
- all 25 provider operands and all six explicit cleanup targets remain visible.

### Workstream 4: pre/post audit and explanation

The existing Phase 0 analyzer should become a product-facing projection only if it can
reuse production identities and relations.

Report:

- planned direct delete,
- expected controller cleanup,
- ownerRef GC descendant,
- derived side effect,
- recreation,
- orphan ownerRef,
- dangling spec reference,
- newly Terminating,
- unexplained change.

Acceptance against Phase 0 counts is exact. The output must identify API provider and
lifecycle creator separately and must describe the 25 cases as expected cleanup.

### Workstream 5: targeted adapters

Add an adapter only after a generic miss is proven by corpus plus live `oc` comparison.
Every adapter must be version-bound, produce positive and negative fixtures, degrade to
Unknown on mismatch, and leave operator names out of generic code.

Potential future subjects are controller/finalizer ordering, deterministic cluster
resources, shared singleton field mutation, and external cleanup. They are not mandatory
until a concrete failure is reproduced.

## 7. Work explicitly removed

Do not implement these based on the current evidence:

- automatic rejection of provider operands solely because their lifecycle owner differs,
- removal or rejection of `independent` approval,
- conversion of the 25 cases to KEEP,
- blanket profiles for all operators,
- generic cross-cluster provenance,
- universal field rollback,
- guaranteed survival of protected kinds from Kubernetes GC/reclaim.

Create a separate issue if a real cluster failure later requires one of them.

## 8. Standard test gates

For every code change:

```bash
cargo fmt --all -- --check
cargo test --all-targets
cargo clippy --all-targets -- -D warnings
cargo build --release
```

Offline corpus gate:

```bash
python3 tools-post-analysis.py \
  inventory/pre-inventory.jsonl \
  inventory/post-inventory.jsonl \
  batch-plans \
  provider-api-operands.json \
  inventory/gvr-catalog.json \
  /tmp/post-analysis-1.json

python3 tools-post-analysis.py ... /tmp/post-analysis-2.json
cmp /tmp/post-analysis-1.json /tmp/post-analysis-2.json
```

Required invariant summary:

```text
provider operands: 25/25
full teardown decision: DELETE
without independent approval: REVIEW
direct DELETE: 91
EXPECT: 72
owner descendants: 1,282
derived: 2
total physical removed: 2,784
```

## 9. Live E2E policy

### Read-only changes

Run recovered-cluster discovery and compare with independent `oc` queries. Save:

- exact command,
- Git commit and binary SHA256,
- kube-system UID,
- stdout/stderr/exit code,
- canonical tool output,
- matching `oc get -o json` evidence,
- request/retry/elapsed metrics.

### Planner or executor changes

Run both:

1. Cycle A: every operator individually, preserving the deleted state for review.
2. Recover and establish 15/15 presence baseline.
3. Cycle B: `teardown batch configs/full-teardown.json`.
4. Collect post inventory before recovery.

Required Cycle B assertions:

- 15/15 target entries succeed unless an explicitly tested skip policy applies,
- zero action failures,
- plan/apply drift gate passes,
- RHOAI two and RHCL four explicit targets are absent,
- provider API operands are deleted as expected,
- target Subscription/CSV objects are absent,
- Namespace/PV/PVC/CRD/APIService direct DELETE action count follows the command contract,
- newly Terminating count is reported,
- residuals and side effects are enumerated,
- cluster remains deleted until reviewer verification.

### No-go conditions

- production behavior changes without a new Cycle A/B,
- provider operand recall drops below 25,
- a query failure is represented as empty success,
- identity resolution ignores group, namespace, or UID,
- output is nondeterministic,
- new direct protected-kind DELETE outside explicit contract,
- credentials or Secret values enter artifacts.

## 10. Coordination

The reviewer operates as `terminal_4`. Send review requests with delayed Enter:

```python
import subprocess, time
message = "<review request with commit, changes, gates, and E2E evidence>"
subprocess.run([
    "zellij", "action", "write-chars", "--pane-id", "terminal_4", message
], check=True)
time.sleep(2)
subprocess.run([
    "zellij", "action", "write", "13", "--pane-id", "terminal_4"
], check=True)
```

Wait for the reviewer response before editing the same review findings. Dump the screen
only when no response has arrived for more than one hour.
