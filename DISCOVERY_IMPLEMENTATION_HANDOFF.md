# Discovery redesign implementation handoff

## 1. Purpose and authority

This document is the implementation handoff for completing the discovery redesign after
the reviewer session becomes unavailable. It is intended to be sufficient for the
implementer in `terminal_0` to continue without reconstructing decisions from chat.

The governing requirements are:

1. Discovery must remain operator agnostic in the core. Operator-specific knowledge is
   allowed only in version-bound data profiles introduced in Phase 7.
2. More discovered resources is not automatically better. DELETE precision is the first
   invariant and must remain 100% for reviewed ground truth.
3. Every phase uses the frozen Phase 0 corpus and is committed only after reviewer GO.
4. Destructive Cycle B is run only after Phases 2, 6, and 10.
5. After every destructive checkpoint, leave the cluster deleted for independent review.
6. Do not recover the currently deleted cluster while Phase 1 is being completed.
7. Do not commit a phase merely because unit tests pass. The corpus acceptance gate is
   part of the phase.

The high-level plan remains:

- [Discovery Improvement Plan](logs/discovery-baseline/discovery-improvement-plan.md)
- [Go operator source study](logs/discovery-baseline/source-study-go-operators.md)
- [Frozen Phase 0 corpus](logs/discovery-baseline/20260926-cycle-b2-3c77a17/README.md)

## 2. Current repository and cluster state

As of 2026-09-27:

```text
branch:              cli-v2-phase4
remote branch HEAD:  3c77a17
local HEAD:          efa687b
local ahead:         1 commit
cluster:             deleted after Phase 0 Cycle B2
open PR:             #35
open issues:         #21 and #28
```

`efa687b` is the accepted Phase 0 corpus commit:

```text
efa687b chore: Phase 0 discovery baseline corpus and analysis tools
```

There are uncommitted Phase 1 changes in:

```text
src/graph/evidence.rs
src/kube/resource.rs
src/kube/snapshot.rs
src/teardown/explain.rs
```

Do not reset these files. Continue from the current worktree.

There are many unrelated untracked Ansible files and credential files. Never use
`git add .` or `git add -A`. Stage an explicit allowlist only. In particular, never stage:

```text
ansible/.credentials/
ansible/.generated-passwords.yml
ansible/.maas-policies-generated.yaml
.claude/
.aw.yml
apply_output*.txt
plan_output.json
plan_stderr.txt
trace_stderr.txt
```

The older corpus directory below is incomplete and is not a validation source:

```text
logs/discovery-baseline/20260926-cycle-b-3c77a17/
```

Only use:

```text
logs/discovery-baseline/20260926-cycle-b2-3c77a17/
```

## 3. Work completed before the redesign

The following are already merged and should not be reimplemented:

- Issue #11: labels, annotations, pod resource display, parent-only spec refs.
- Issues #12 and #16: operator owner/resources/trace and related-namespace discovery.
- Issue #13: typed `ScanWarning`, retry, timeout, strict partial-output behavior.
- Issue #14: snapshot diff.
- Issue #15: Service/Ingress/Route reverse paths.
- Issue #18: cluster-wide map and snapshot.
- Issue #21 Phases 1-5: EndpointSlice, NetworkPolicy posture, MetalLB configuration,
  Gateway API, and MetalLB observed status.
- Issue #28 CLI Phases 1-3: task-oriented commands, operator/snapshot/graph hierarchy.
- PR #35 CLI Phase 4 implementation: typed plan/apply/batch, explicit cleanup,
  plan drift checks, inbound reference guard, presence-only batch gate.

PR #35 has passed earlier Cycle A and Cycle B execution mechanics, but must not be merged
yet. The Phase 0 corpus proved that the legacy discovery/authority logic still made
25 false-attribution DELETE decisions. Functional E2E success does not override this
correctness failure.

After the discovery redesign is complete, finish:

1. Issue #28 Phase 5 documentation and UX.
2. Issue #21 optional Phase 6 runtime metrics.
3. Rebase/finalize PR #35 and run the final full gates.

## 4. Frozen Phase 0 facts

The corpus is the oracle for Phases 1-10. Do not regenerate it to make a test pass.

### Inventory counts

```text
pre raw API observations:       17,786
post raw API observations:      14,761
pre API-logical observations:   17,668
post API-logical observations:  14,719
pre physical UIDs:              11,716
post physical UIDs:              9,165
removed physical UIDs:           2,784
added physical UIDs:               233
```

### Removal classification

```text
direct DELETE:                    91
EXPECT gone:                      72
planned ownerRef descendants:   1282
owner-disappeared unlinked:       10
proven derived side effects:       2
other removed:                  1327
total:                          2784
```

DELETE-seed ownerRef closure contains 1,460 UIDs; 1,445 of those disappeared.

### Required regression oracles

- 25 isolated-plan false attributions:
  `20260926-cycle-b2-3c77a17/golden-false-attribution.json`
- 4 protected transitive removals:
  - `jobsets.jobset.x-k8s.io` CRD: ownerRef descendant of JobSetOperator.
  - `v1alpha2.jobset.x-k8s.io` APIService: derived from removed CRD/API group.
  - `mlflow-pvc` PVC: ownerRef descendant of MLflow.
  - `pvc-78fb5c3e` PV: derived PVC binding/reclaim side effect.
- One non-terminating orphan ownerRef:
  `OAuthClient/data-science -> deleted GatewayConfig`.
- Three terminating objects existed before deletion; newly terminating count is zero.
- 12 dangling post-live-to-pre-removed spec-ref edges across 2 targets:
  - 3 references to `ConfigMap/model-catalog-kube-rbac-proxy-config`.
  - 9 references to `Secret/model-catalog-postgres`.
- 4,510 UIDs were observed through multiple API identities/aliases.
- Recreated resources and UID-null objects are explicitly represented in analysis.
- Known residuals include postgres, maas-postgres, ogx-postgres, and model-catalog.

The Phase 0 validator and analyzer must continue to pass unchanged. Their hashes and
exact invocations are recorded in the corpus README and manifest.

## 5. Semantic rules that must not be weakened

### Relationship meanings

Use distinct typed relations:

```text
Owns             exact Kubernetes ownerReference relationship
ApiStewardship    CSV provides/owns an API definition, not its instances
Creates           controller/install strategy creates an object, no delete authority alone
CleansUp          declared/version-bound cleanup intent, no authority alone in Phase 1
References        spec or configuration reference
Selects           label selector relation
Watches           reconcile input/watch relation
Mutates           field-level update relationship
Renders           embedded/Helm/rendered inventory relationship
RemoteCreates     creates an object in another cluster/provider
RequiresApi       CSV required API
UsesStorage       storage reference
UsesServiceAccount
ManagedBy         managed-by correlation, not ownership
```

CSV `owned CRDs` means API stewardship. It never proves that every instance of that CRD
belongs to the operator. This distinction prevents the PersesDashboard, RHCL policy,
cert-manager, Service Mesh, and Authorino false deletions in the golden set.

### Authority rule

At the end of Phase 1, only this primitive may return lifecycle authority:

```text
relation == Owns
AND confidence == Hard
AND resolution == Resolved
AND owner UID and full identity are verified
```

Phase 2 adds closure evaluation and vetoes. Do not allow `Creates`, `CleansUp`, labels,
managed fields, deterministic names, API stewardship, watches, or spec references to
grant lifecycle DELETE authority by themselves.

### Identity rule

Resource identity is:

```text
group + kind + namespace + name + UID
```

Version is an API observation. A physical Kubernetes object may be observed through
multiple group/version/resource aliases. Never choose a HashMap winner silently.

## 6. Phase 1 current state and exact remaining work

### Already implemented provisionally

The current uncommitted code has:

- `Relation`, `Evidence`, `Confidence`, and `Resolution`.
- `Resolution::{Resolved,TargetMissing,IdentityMismatch,Ambiguous,Unresolved}`.
- Full ownerRef evidence including apiVersion, UID, controller, blockOwnerDeletion.
- `can_authorize_delete(edge)` requiring Resolved + Owns + Hard.
- Namespace checks for ownerRef resolution.
- Candidate-set indexes rather than single-value overwrite for relationship lookup.
- Core-group exact resolution for Secret, ConfigMap, ServiceAccount, and PVC refs.
- `ApiStewardship` for CSV owned CRDs.
- `Creates` for CSV install strategy deployments.
- Edge sorting and deduplication.
- `block_owner_deletion` snapshot capture with serde default.

These changes are not committed. The last implementer-reported gates were 965 tests,
fmt, clippy, and release build, but corpus validation was not done.

### Blocker 1: observation and physical entity model

Current `ClusterSnapshot.resources` is `HashMap<UID, ResourceEntry>`. Snapshot collection
inserts by UID, so later API aliases overwrite earlier observations. The current
`PhysicalEntity.observed_aliases` builder therefore receives at most one observation per
UID. `ApiObservation.resource` is currently an empty string. This does not solve aliasing.

Implement a separate lossless observation input. A suggested model is:

```rust
pub struct ResourceObservation {
    pub uid: String,
    pub id: ResourceId,
    pub resource: String,
    pub namespaced: bool,
    pub is_preferred: bool,
    pub is_storage_version: bool,
}

pub struct PhysicalEntity {
    pub uid: String,
    pub canonical_id: ResourceId,
    pub observed_aliases: Vec<ApiObservation>,
}
```

Do not change snapshot compatibility by replacing `resources` immediately. Add a graph
builder input capable of accepting observations:

```rust
pub struct EvidenceGraphInput<'a> {
    pub snapshot: &'a ClusterSnapshot,
    pub operators: &'a [OperatorInstance],
    pub observations: &'a [ResourceObservation],
    pub declared_cleanups: &'a [DeclaredCleanup],
    pub historical_entities: &'a [HistoricalEntity],
}

pub fn build_evidence_graph(input: EvidenceGraphInput<'_>) -> EvidenceGraph
```

If preserving the existing signature temporarily is useful, make it a wrapper that
creates one observation per snapshot entry. The corpus and future discovery engine must
call the full-input constructor.

Canonical selection must be deterministic:

1. Prefer CRD storage version for custom resources when catalog evidence exists.
2. Otherwise prefer discovery preferred version.
3. Otherwise use stable lexical ordering of `(group, version, resource, kind, ns, name)`.
4. UID and object scope/name must agree; disagreement is an integrity error, not an alias.
5. Sort and deduplicate all aliases before serialization.

Required tests:

- Same UID through core/OpenShift API aliases in forward/reverse insertion order.
- Same custom-resource UID through storage and served non-storage versions.
- Same UID with inconsistent name/namespace is rejected or marked integrity failure.
- `resource` is preserved and never empty for real discovery observations.
- Serialized graph bytes are identical for reversed observations.

### Blocker 2: declared cleanup graph producer

`Relation::CleansUp` exists but has no production producer. Add a neutral declared input,
not a dependency from graph code to all planner internals:

```rust
pub struct DeclaredCleanup {
    pub actor: ResourceId,          // operator CSV or plan target
    pub target: ResourceId,
    pub source: CleanupSource,      // ExecutionPlanExplicitDelete / VersionProfile
    pub reason: String,
}
```

Convert `ExecutionPlan.explicit_deletes` in `src/teardown/plan.rs` to this input through
an adapter in teardown code. Preserve target UID, group, kind, namespace, and name.
Resolution is:

- `Resolved` only if exact live UID and identity match.
- `TargetMissing` if absent.
- `IdentityMismatch` if UID/name/scope conflicts.
- `Ambiguous` if multiple candidate physical entities exist.

Create `CleansUp` edges with a typed evidence variant such as:

```rust
Evidence::DeclaredCleanup {
    source: CleanupSource,
    reason: String,
}
```

`can_authorize_delete` must remain false for CleansUp in Phase 1. Phase 2 combines this
intent with explicit approval, inbound-reference coverage, drift checks, and exact live
identity.

Required tests:

- Exact explicit target becomes Resolved CleansUp but does not authorize on its own.
- UID mismatch becomes IdentityMismatch.
- Missing target becomes TargetMissing.
- RHOAI Gateway/ConfigMap and RHCL four explicit targets appear as CleansUp.
- No explicit target is represented as Owns unless a separate real ownerRef exists.

### Blocker 3: full-index ambiguity

Change `resolve_full` from `Option<ResourceId>` to an explicit result:

```rust
fn resolve_full(...) -> (Option<ResourceId>, Resolution)
```

Zero candidates is `Unresolved` or `TargetMissing` depending on the caller contract;
one exact candidate is `Resolved`; more than one is `Ambiguous`. OLM CRD, deployment,
and service-account producers must retain this distinction.

### Blocker 4: Phase 1 corpus exporter and validator

Add a deterministic offline corpus projection that calls the same production graph
constructor. Do not reimplement relationship decisions independently in Python.

Recommended implementation:

1. Put JSONL/catalog loading in a small Rust module under `src/graph/corpus.rs` or a
   repository-only binary under `src/bin/` if the crate structure permits it.
2. Convert every pre inventory row into `ResourceObservation`.
3. Build snapshot-like `ResourceEntry` objects by UID without discarding alias rows.
4. Load operator inventory and plans from the frozen files.
5. Convert explicit plan targets to `DeclaredCleanup`.
6. For post dangling references, use post source objects plus pre historical targets.
7. Serialize a canonical Phase 1 graph and a compact validation summary.

Save under the frozen corpus directory:

```text
phase1-evidence-graph.json
phase1-evidence-summary.json
tools-phase1-evidence-export.*
tools-validate-phase1-evidence.*
```

Record exact invocations and SHA256 hashes in the corpus README/manifest.

The validator must fail nonzero unless all of these hold:

1. All 25 golden false-attribution objects have no lifecycle DELETE authority from their
   initial-plan operator.
2. Their actual ownerRef/managed-by/RouteRule evidence remains visible.
3. Four protected transitive removals retain causal evidence and are not converted to
   declared direct DELETE authority.
4. All 12 dangling spec refs and 2 removed targets exist as References with non-Resolved
   target resolution.
5. RHOAI/RHCL explicit cleanup targets are CleansUp, not synthesized Owns.
6. Owner cycles terminate.
7. Diamond DAG paths converge without being rejected as cycles.
8. The 4,510 multi-observed UIDs collapse to physical entities while preserving every
   API observation.
9. Two independent exporter runs are byte-identical.

Only after this validator and the standard Rust gates pass may Phase 1 receive GO and be
committed. Suggested commit:

```text
feat: add typed relationship graph and corpus validation
```

## 7. Phase 2: authority engine and foreign-owner veto

### Objective

Separate relationship discovery from permission to delete. Replace broad attribution
with an explainable decision containing grants, vetoes, unknowns, and coverage needs.

### Suggested types

Add `src/graph/authority.rs`:

```rust
pub enum AuthorityStatus {
    Authorized,
    Review,
    Blocked,
}

pub enum AuthorityReason {
    ExactOwnerLineage,
    ExplicitCleanupApproval,
    ForeignLiveOwner,
    StaleOwner,
    MissingOwner,
    AmbiguousIdentity,
    ApiStewardshipOnly,
    CorrelationOnly,
    MissingCoverage,
}

pub struct AuthorityDecision {
    pub target: ResourceId,
    pub status: AuthorityStatus,
    pub grants: Vec<AuthorityEvidence>,
    pub vetoes: Vec<AuthorityEvidence>,
    pub required_coverage: Vec<CoverageRequirement>,
}
```

### Algorithm

1. Build the exact target closure from operator CSV/subscription/root approvals and live
   typed graph edges.
2. For each candidate resource, evaluate every ownerRef, not only the controller owner.
3. A resolved owner within the target closure may grant lineage authority.
4. Any live resolved owner outside the target closure is `ForeignLiveOwner` and vetoes
   all bulk approvals.
5. Missing, stale, malformed, cyclic, or ambiguous owner paths are Review/fail-closed.
6. Multiple owners use ALL-owner safety semantics: all branches must be safe.
7. Memoized DFS must distinguish `Visiting` from `Resolved`; check live identity before
   trusting memoized state.
8. ApiStewardship, Creates, Watches, Selects, ManagedBy, managedFields, names, and spec
   refs never grant core lifecycle authority.
9. Explicit cleanup requires explicit approval, exact UID, complete inbound-ref scan,
   and drift-free revalidation at apply time.
10. Keep legacy planner decisions in shadow comparison until corpus precision is 100%.

Reuse lessons and tests from `src/teardown/ref_guard.rs`, especially the transitive
ALL-owner walk, stale UID checks, cycle guard, and diamond DAG behavior. Refactor rather
than maintaining two subtly different authority algorithms.

### Required corpus results

- COO preserves all four RHOAI-owned PersesDashboard objects.
- RHCL preserves MaaS AuthPolicy and TokenRateLimitPolicy objects.
- cert-manager preserves JobSet Certificate/Issuer objects.
- Service Mesh preserves RHOAI/Kuadrant DestinationRule/EnvoyFilter objects.
- Authorino preserves Kuadrant-managed AuthConfig while foreign ownership is live.
- Root exact approvals and exact descendants still work.
- Explicit configured cleanup remains available through its reference guard.
- DELETE precision is 100% for the full 15-operator plan-only corpus.

### Tests

- Single exact owner, multiple all-safe owners, one foreign owner, stale UID, recreated
  identity, missing intermediate, cycle, diamond convergence, same UID wrong identity.
- ApiStewardship never grants instance delete.
- Label-only `all` remains conservative.
- Explicit cleanup with new inbound ref blocks both real apply and dry-run.
- Coverage missing produces Review/Blocked, never absence.
- Plan snapshots for all 15 operators compared canonically with named differences.

### Checkpoint

After plan-only precision reaches 100%:

1. Recover the cluster to the documented 15-operator baseline.
2. Verify all target subscriptions/CSVs are present; Succeeded is advisory, not required.
3. Run full `teardown batch configs/full-teardown.json`.
4. Capture pre/plans/runtime/post data with the same Phase 0 collector.
5. Leave the cluster deleted.
6. Independently verify the post state before recovery.

Commit only after this checkpoint passes.

## 8. Phase 3: scope discovery fixpoint

### Objective

Replace one-pass namespace expansion and broad field-name guessing with a reasoned
fixpoint over typed scope edges.

### Suggested design

Add `src/graph/scope.rs`:

```rust
pub struct ScopeKey {
    pub gvr: CanonicalGvr,
    pub namespace: Option<String>,
}

pub enum ScopeReason {
    InstallNamespace,
    RootResource,
    ExactOwner,
    TypedNamespaceReference { path: String },
    RenderedInventory,
    SourceProfile,
    OperatorGroupTarget,
    LabelEvidence,
}

pub struct ScopeCandidate {
    pub key: ScopeKey,
    pub reasons: Vec<ScopeReason>,
}
```

Maintain a queue and a visited set keyed by exact `(GVR, scope, selector)`. Each result
may add new candidates. Continue until the queue is empty. Record every reason.

Do not treat every field ending in `namespace` as a Kubernetes namespace. The frozen
Limitador defect (`spec.limits[].namespace`) must be fixed with typed path rules or a
version-bound profile. Generic fields with unknown semantics produce evidence only, not
scope expansion.

### Acceptance

- cert-manager operand namespace discovered without a hardcoded namespace.
- RHOAI generated namespaces and `rhoai-model-registries` discovered.
- Sail cross-namespace objects discovered from primary-resource evidence.
- Limitador value namespaces do not create 271 false scans.
- No unrelated namespace growth.
- Every namespace/GVR in scope has at least one serialized reason.
- Each unique query key is executed once.

## 9. Phase 4: coverage ledger

### Objective

Make it impossible to confuse API absence, empty success, and failed enumeration.

### Suggested design

Add `src/graph/coverage.rs` and route all discovery GET/LIST through it:

```rust
pub enum CoverageOutcome {
    Complete { count: usize, pages: usize },
    ApiAbsent,
    Forbidden,
    Timeout,
    RateLimited,
    ServerError,
    UnsupportedList,
    Cancelled,
}

pub struct CoverageEntry {
    pub operation: GetOrList,
    pub gvr: CanonicalGvr,
    pub scope: Scope,
    pub selector: Option<String>,
    pub attempts: usize,
    pub elapsed_ms: u64,
    pub bytes: u64,
    pub outcome: CoverageOutcome,
}
```

Authority rules declare required coverage keys. An incomplete required key prevents
DELETE. Optional coverage must be explicitly marked optional by the rule/profile.

### Tests and acceptance

- 401/403 do not retry and never look like zero objects.
- timeout/408/429/5xx retry with recorded count.
- pagination records all pages.
- strict outputs partial results, then exits 2.
- every proposed DELETE in corpus has complete required coverage.
- zero silent coverage gaps in machine-readable report.

## 10. Phase 5: operator family, controller liveness, and finalizer ordering

### Objective

Model which controller is responsible for cleanup and preserve it until its children
finish.

### Suggested additions

```rust
pub struct ControllerIdentity {
    pub deployment: ResourceId,
    pub csv: Option<ResourceId>,
    pub service_account: Option<ResourceId>,
    pub live: ControllerLiveness,
}

pub struct FinalizerContract {
    pub finalizer: String,
    pub controller: Option<ControllerIdentity>,
    pub domain: CleanupDomain,
    pub evidence: Vec<Evidence>,
}
```

Join OLM install strategy, live ownerRefs, source-profile controller identity, watched
types, and finalizers. Generate ordering constraints rather than assuming phase numbers.

### Acceptance

- Kuadrant -> Authorino/Limitador family visible without ownership transfer.
- RHOAI module controllers remain until their cleanup finishes.
- Authorino CRBs are predicted cleanup outputs.
- every finalizer-strip candidate has known/unknown controller and cleanup domain.
- no controller is scheduled before a child finalizer it processes.
- all 15 dependency graphs contain the runtime edges known from source/corpus.

## 11. Phase 6: shared query planner and performance

### Objective

Compile all scope and relationship needs into one reusable query plan.

### Suggested design

Add `src/graph/query.rs`:

```rust
pub struct QueryKey {
    pub gvr: CanonicalGvr,
    pub namespace: Option<String>,
    pub label_selector: Option<String>,
    pub field_selector: Option<String>,
}

pub struct QueryPlan {
    pub queries: BTreeMap<QueryKey, Vec<QueryConsumer>>,
}
```

Execute each query once with global concurrency control. Build reusable indexes for UID,
exact identity, label tuples, annotations, ownerRefs, managedFields, and reverse typed
references. Cache discovery by cluster UID and API-surface fingerprint. Preserve explicit
refresh behavior.

### Metrics

Compare against Phase 0 and Phase 5:

- unique GET/LIST requests,
- transferred bytes,
- wall time,
- retries,
- cache hits,
- graph and plan byte-equivalence after canonical sorting.

Accuracy must be identical or better. Then run the second destructive Cycle B checkpoint
using the same procedure as Phase 2.

## 12. Phase 7: version-bound source profiles

### Objective

Add operator-specific knowledge without adding operator names to generic algorithms.

### Profile contract

Profiles must bind to installed package + CSV/version + image digest or source revision.
On mismatch they degrade to Unknown/Review.

Suggested data model:

```rust
pub struct DiscoveryProfile {
    pub profile_version: u32,
    pub package: String,
    pub csv_constraint: VersionConstraint,
    pub image_digests: Vec<String>,
    pub relationship_recipes: Vec<RelationshipRecipe>,
    pub cleanup_contracts: Vec<CleanupContract>,
    pub retained_exceptions: Vec<ResourcePattern>,
}
```

Initial profiles come from the committed source study:

- RHOAI annotation tuples and retained ImageStreams.
- Sail primary-resource annotations and rendered inventory.
- NFD SCC deterministic cleanup.
- cert-manager static operand inventory and watched-by negative evidence.
- Kuadrant ConsolePlugin/AuthConfig rules.
- Authorino deterministic CRB cleanup.
- COO/OTel ownerRef-less RBAC label tuples.

### Acceptance

- Each profile closes at least one named corpus/source gap.
- No profile grants delete on version/digest mismatch.
- Core modules contain no branch on package/operator/resource names.
- Profile schema has conformance and malformed-data tests.

## 13. Phase 8: residual auditor

### Objective

Predict before apply, then compare actual post state.

Suggested outcome model:

```rust
pub enum ExpectedOutcome {
    GoneDirect,
    GoneByOwnerGc,
    Retained,
    MutationReverted,
    ExternalUnverifiable,
    Unknown,
}
```

Report:

- orphan ownerRefs,
- inbound refs to removed objects,
- newly terminating objects,
- retained mutations,
- recreated identities,
- unexpected disappearances,
- expected-but-retained resources.

### Acceptance

- Detect the Phase 0 OAuthClient orphan.
- Detect the pre-existing ServiceMesh termination without calling it newly stuck.
- Detect the 12 dangling spec refs.
- Predict known Issue #4 residuals separately from new residuals.
- `download-qwen3-06b` remains Unknown/user-managed.
- No destructive recommendation is emitted without review.

## 14. Phase 9: mutation and finalizer safety

### Objective

Represent shared-object changes and irreversible/external cleanup separately from delete.

Suggested actions:

```rust
pub enum LifecycleAction {
    Delete(ResourceId),
    ExpectGone(ResourceId),
    Patch(FieldPatch),
    RemoveFinalizer(FinalizerAction),
    Keep(ResourceId),
    Review(ResourceId),
}
```

`FieldPatch` must include before value, desired value, field manager evidence, and drift
precondition. `FinalizerAction` must include cleanup domain and lost-cleanup description.

Classify domains:

- KubernetesOnly,
- ClusterScoped,
- ExternalSystem,
- RemoteCluster,
- Unknown.

Unknown and external finalizers require explicit approval. Remove blanket automatic
stripping.

### Acceptance

- Node and Namespace are never deleted for NFD/GPU mutations.
- shared Console singleton is patched by array entry, not deleted.
- DNS external finalizer is never automatically stripped.
- RHOAI controller race is solved through ordering first.
- every forced finalizer action is visible with required approval and cleanup loss.

## 15. Phase 10: adapter completion and remote provenance

### Objective

Complete profiles for all Cycle B families and model external/remote targets.

Represent each remote target as:

```text
Verified | Partial | Unavailable | NotConfigured
```

Initial remote cases:

- MultiKueue worker clusters,
- DNS multicluster targets,
- external cloud/provider resources.

Add a profile conformance suite so a new operator can be evaluated by adding data and
fixtures without changing generic core branches.

### Final acceptance

- 15/15 plan-only comparisons pass.
- DELETE precision remains 100%.
- Every source-confirmed relation is found or explicitly Unsupported.
- Coverage ledger has no unexplained required gaps.
- Final destructive Cycle B passes.
- Independent reviewer verifies deleted cluster before recovery.

## 16. Per-phase mandatory workflow

For every Phase 1-10:

1. Work only on that phase.
2. Keep changes uncommitted until review GO.
3. Run:

   ```bash
   cargo fmt --all -- --check
   cargo clippy --all-targets -- -D warnings
   cargo test --all-targets
   cargo build --release
   ```

4. Generate canonical graph and all 15 plan comparisons from the frozen corpus or the
   unchanged recovered baseline as required.
5. Report:
   - DELETE precision,
   - discovery recall by relation,
   - authority recall,
   - unknown coverage,
   - residual recall,
   - unique requests/bytes/time/retries/cache hits.
6. Include named golden pass/fail results, not only counts.
7. Send review request to `terminal_4`.
8. Wait for explicit GO or CHANGES REQUESTED.
9. Commit only after GO with one phase-focused commit.
10. Never combine a later phase into the current commit.

Do not weaken or rewrite the oracle when a gate fails. Fix production behavior or record
the case as explicitly unsupported/review.

## 17. Zellij communication protocol

The implementer is `terminal_0`; the reviewer is `terminal_4`.

Send review messages with delayed Enter:

```python
import subprocess
import time

subprocess.run([
    "zellij", "action", "write-chars",
    "--pane-id", "terminal_4",
    MESSAGE,
], check=True)
time.sleep(2)
subprocess.run([
    "zellij", "action", "write", "13",
    "--pane-id", "terminal_4",
], check=True)
```

If no response arrives for more than one hour, inspect before resending:

```bash
zellij action dump-screen --pane-id terminal_4 --full | tail -n 160
```

Do not repeatedly send duplicate review requests. Preserve full context in each request:
phase, commit candidate, files, named corpus results, gates, cluster state, and explicit
statement that no commit was made before GO.

## 18. Cluster lifecycle protocol

Current state: deleted. Do not recover for Phase 1.

Recovery is allowed only when a phase requires live plan generation or at the authorized
destructive checkpoints. Before destructive runs, verify:

- node Ready and schedulable,
- 15 target operators present,
- subscriptions present,
- CSV health reported but not required to be Succeeded,
- DSC/DSCI and required operands sufficiently restored for the scenario,
- no unexpected Terminating resources,
- verification playbooks pass for their declared scope.

Presence-only semantics are intentional. Failed/Pending CSV must not automatically block
teardown. Subscription authority, identity, discovery completeness, drift, and reference
guards remain safety-critical.

After a destructive checkpoint:

1. Do not run recovery.
2. Capture post inventory.
3. Verify explicit targets and planned resources.
4. Audit retained CRD/APIService/PV/PVC/Namespace policy.
5. Audit residuals, orphans, dangling refs, and terminating objects.
6. Leave the cluster deleted for reviewer inspection.

## 19. Remaining Issue #28 work after Phase 10

PR #35 remains open. Once Discovery Phase 10 is accepted:

1. Rebase or split discovery commits as agreed; do not lose Phase 0 artifacts.
2. Finish CLI v2 Phase 5:
   - reorganize README by user goal,
   - document every command and concrete examples,
   - document exit codes,
   - add shell completion if retained,
   - finalize `--progress auto|always|never`,
   - finalize `--color auto|always|never`,
   - verify stdout=result and stderr=progress/warnings,
   - parse-test README commands,
   - ensure no old CLI aliases remain.
3. Update Issue #28 checkboxes using actual tests, not manual assertion only.
4. Run full CLI E2E and PR gates.

## 20. Remaining Issue #21 work after Phase 10

Phases 1-5 are merged. The only open optional scope is runtime metrics:

- opt-in Prometheus lookup for `metallb_bgp_session_up` and
  `frrk8s_bgp_session_up`,
- MetalLB stale-configuration metrics,
- explicit `Unavailable/Unknown` when metrics cannot be read,
- never infer external reachability from Kubernetes or metrics alone,
- no packet capture or external router mutation.

If runtime metrics is declined as optional, document that decision and close #21 based on
the completed Phase 1-5 acceptance list.

## 21. Common failure modes to avoid

1. Do not use Kind alone as identity. Ingress and other names collide across API groups.
2. Do not treat CSV owned CRD as ownership of every CR instance.
3. Do not let label-only, managed-by, managedFields, deterministic names, or watch
   relationships grant DELETE authority.
4. Do not ignore non-controller ownerRefs. Kubernetes GC considers all ownerRefs.
5. Do not accept one safe owner when another live owner is outside the closure.
6. Do not share a plain visited set across DFS sibling branches; use tri-state memoization.
7. Do not trust memoized resolution before rechecking current node identity.
8. Do not use `HashMap` iteration order to choose API aliases or candidates.
9. Do not equate API absence with 403/timeout/5xx.
10. Do not treat a successful process exit as deletion correctness.
11. Do not call cascade/derived deletion a direct action.
12. Do not make operator-specific core branches. Put source-bound knowledge in profiles.
13. Do not auto-strip unknown or external finalizers.
14. Do not recover the cluster before independent post-delete review.
15. Do not stage credentials or unrelated Ansible workspace files.

## 22. Definition of overall completion

The entire request is complete only when:

- Phases 1-10 each have an accepted commit and corpus report.
- Cycle B checkpoints after 2, 6, and 10 pass and are independently reviewed.
- Final DELETE precision is 100% for all named ground truth.
- 15/15 target operator plans have no unexplained coverage gaps.
- Residual auditor accounts for every Phase 0 known residual and new residual.
- PR #35 is updated, fully tested, and merged.
- Issue #28 Phase 5 is completed and #28 closed.
- Issue #21 runtime metrics is implemented or explicitly declined/documented, and #21
  is closed.
- The repository contains no staged secrets and the final cluster state/recovery status
  is explicitly reported.

## 23. E2E is a release gate, not supporting evidence

Unit tests and offline corpus tests are necessary but insufficient. Each accepted phase
must state which behaviors were verified against a live cluster, which were verified
offline, and which remain unverified. A phase may not be marked complete using only
`cargo test` when its behavior depends on Kubernetes discovery, scope, pagination,
reconciliation, garbage collection, finalizers, or OLM state.

There are four test layers:

| Layer | Purpose | Mutation allowed |
|---|---|---|
| L1 Rust tests | Type/algorithm boundaries and failure injection | No cluster |
| L2 frozen corpus | Full deterministic regression against Phase 0 truth | No cluster |
| L3 live read-only | Compare tool results to independent `oc` queries | No target deletion |
| L4 destructive checkpoint | Prove plans and real outcomes | Yes, only after Phases 2/6/10 |

Every review request must list L1-L4 separately. “E2E passed” without commands, expected
results, actual counts, and independent `oc` comparison is not acceptable.

## 24. E2E run directory and evidence contract

Every live test creates a new immutable run directory. Never overwrite an earlier run:

```bash
export RUN_ID="$(date -u +%Y%m%dT%H%M%SZ)-phase${PHASE}-$(git rev-parse --short HEAD)"
export RUN_DIR="$PWD/logs/discovery-e2e/$RUN_ID"
mkdir -p "$RUN_DIR"/{commands,plans,operator-resources,inventory,oc,results}
```

Write these files before any cluster mutation:

```text
git-head.txt                 exact git SHA and git status
binary-sha256.txt            target/release/oc-deps SHA256
cluster-identity.json        API URL and kube-system UID; no credentials
config-sha256.txt            configs/full-teardown.json SHA256
environment.txt              oc version, server version, architecture
commands/*.command           exact shell command, with secrets removed
commands/*.stdout
commands/*.stderr
commands/*.exit
```

The harness must capture stdout and stderr separately. Do not use a pipeline that loses
the real command exit status. A suitable shell helper is:

```bash
run_capture() {
  local name="$1"; shift
  printf '%q ' "$@" >"$RUN_DIR/commands/$name.command"
  printf '\n' >>"$RUN_DIR/commands/$name.command"
  set +e
  "$@" >"$RUN_DIR/commands/$name.stdout" 2>"$RUN_DIR/commands/$name.stderr"
  local rc=$?
  set -e
  printf '%s\n' "$rc" >"$RUN_DIR/commands/$name.exit"
  return "$rc"
}
```

Add a `manifest.json` recording:

- phase and checkpoint type,
- git/binary/config/cluster identities,
- start/end timestamps,
- baseline status,
- commands and exits,
- expected and actual counts,
- deviations with disposition,
- whether the cluster was left recovered or deleted.

Do not write bearer tokens, Secret data, generated passwords, kubeconfig contents, or
last-applied configuration to the run directory.

## 25. Baseline recovery and readiness gate

Recovery commands depend on the configured test inventory. The standard project path is:

```bash
cd ansible
uv run ansible-playbook site.yml -i inventory/myenv
uv run ansible-playbook playbooks/verify.yml -i inventory/myenv
cd ..
```

If the inventory name differs, record the exact inventory in the run manifest. Do not
invent credentials or copy host-only kubeconfig paths into a container. Confirm first:

```bash
oc whoami
oc get --raw=/healthz
oc get node -o wide
oc get namespace kube-system -o jsonpath='{.metadata.uid}{"\n"}'
```

The baseline gate is presence based for target operators. CSV `Succeeded`, `Failed`, or
`Pending` is diagnostic and must not by itself block teardown. Capture:

```bash
oc get subscriptions.operators.coreos.com -A -o json > "$RUN_DIR/oc/subscriptions-pre.json"
oc get clusterserviceversions.operators.coreos.com -A -o json > "$RUN_DIR/oc/csv-pre.json"
oc get pods -A -o json > "$RUN_DIR/oc/pods-pre.json"
oc get events -A -o json > "$RUN_DIR/oc/events-pre.json"
```

Run the explicit target-presence verifier:

```bash
cd ansible
uv run ansible-playbook playbooks/verify.yml -i inventory/myenv --tags teardown_targets
cd ..
```

Expected baseline:

- all 15 configured target Subscriptions are present,
- every target resolves to a canonical CSV/package identity,
- node is Ready and schedulable,
- no unexpected newly Terminating objects,
- kube-system UID matches the intended test cluster,
- RHOAI explicit targets and RHCL explicit targets exist before a destructive run,
- known pre-existing terminating objects are recorded rather than silently treated as new.

For a final release checkpoint, also run the full verification playbook. If a known
optional workload is skipped, record the exact tags/extra-vars and never report it as a
full baseline pass.

Any missing target without an explicitly approved `--skip-missing` test is a baseline
failure. Do not reinterpret a partial baseline as a teardown success.

## 26. Canonical pre-mutation collection

At every destructive checkpoint, collect an all-served-GVR inventory using the saved
Phase 0 collector or an accepted later version. Save its hash:

```bash
export CORPUS="$PWD/logs/discovery-baseline/20260926-cycle-b2-3c77a17"
python3 "$CORPUS/tools-collect-inventory.py" \
  "$RUN_DIR/inventory/pre-inventory.jsonl" \
  "$RUN_DIR/inventory/pre-list-failures.jsonl" \
  "$RUN_DIR/inventory/pre-gvr-catalog.json"
```

Expected:

- zero unrecorded LIST failures,
- redacted sensitive virtual APIs recorded in the ledger,
- no Secret data or OAuth token values,
- all served versions preserved,
- preferred/storage flags available,
- target golden resources present with the expected UID/evidence where the baseline
  requires them.

Then collect `operator resources --scope related -o json` for all 15 operators before
any deletion. Operator names are exactly those in `configs/full-teardown.json`:

```text
rhods-operator
rhbk-operator
leader-worker-set
job-set
kueue-operator
servicemeshoperator3
nfd
gpu-operator-certified
openshift-cert-manager-operator
rhcl-operator
authorino-operator
dns-operator
limitador-operator
cluster-observability-operator
opentelemetry-product
```

For each:

```bash
./target/release/oc-deps operator resources "$operator" \
  --scope related -o json --refresh-discovery \
  >"$RUN_DIR/operator-resources/$operator.json" \
  2>"$RUN_DIR/operator-resources/$operator.stderr"
```

Only the first call needs `--refresh-discovery` if the accepted implementation shares a
fresh cache safely. Record which command refreshed it. Every JSON document must parse and
the command must exit 0. Warnings are not discarded; typed warnings and incomplete scope
must be reflected in the result and manifest.

Generate and save all 15 isolated plans while every operator is still present. This is
essential: generating later plans after earlier deletions changes the evidence and cannot
serve as isolated attribution ground truth. Apply each operator's config defaults and
per-operator exact resources/delete_resources. Prefer a checked-in harness that reads
`configs/full-teardown.json` rather than manually duplicating flags.

Expected isolated-plan result after Phase 2:

- the 25 golden objects are not DELETE-authorized by the wrong initial operator,
- four RHCL explicit targets and two RHOAI explicit targets appear only as explicit
  cleanup intent with exact UID and complete reference coverage,
- CRD/APIService/PV/PVC/Namespace are not direct DELETE actions unless the corresponding
  supported explicit feature says so; current config uses `prune_crds=false`,
- no plan contains an unexplained required coverage gap,
- every plan is valid JSON and carries cluster identity and resource UIDs.

## 27. Dry-run E2E and no-mutation proof

Before real deletion, run both individual apply dry-runs and batch dry-run. Dry-run must
execute fresh discovery, drift comparison, explicit-target UID validation, and inbound
reference revalidation. It must not skip safety work merely because no DELETE is sent.

For every saved individual plan:

```bash
./target/release/oc-deps teardown apply "$plan" \
  --dry-run --refresh-discovery -y
```

Then:

```bash
./target/release/oc-deps teardown batch configs/full-teardown.json \
  --dry-run --refresh-discovery
```

Capture a lightweight UID inventory before and after dry-run. Expected:

- dry-run exits 0 for all valid plans,
- all phases are displayed, including Explicit cleanup where configured,
- plan drift is reported as absent,
- reference revalidation runs for all six explicit cleanup targets,
- no resource UID disappears,
- no deletionTimestamp changes from null to non-null,
- Subscriptions and CSVs remain present,
- no finalizer is changed,
- dry-run stdout/stderr is valid for non-TTY use and contains no ANSI escapes.

Any mutation during dry-run is P0 and blocks the phase.

## 28. Safety-boundary E2E fixtures

Run these on isolated temporary namespaces/resources before destructive target teardown.
Name every fixture with the run ID and delete it afterward.

### New inbound reference between plan and apply

1. Create a temporary Gateway or supported explicit-cleanup target.
2. Generate a plan while no inbound reference exists.
3. Create an HTTPRoute whose `parentRef` points to the target.
4. Run `teardown apply --dry-run` and real apply against the saved plan.

Expected for both dry-run and real apply:

- fresh revalidation sees the new reference,
- apply exits nonzero before deletion,
- target UID remains live,
- error identifies the exact referrer and field,
- coverage is marked complete or the operation fails closed.

### Recreated explicit target

1. Plan an isolated explicit target.
2. Delete and recreate it with the same group/kind/ns/name and a new UID.
3. Apply the old plan.

Expected: UID mismatch/drift, nonzero exit, recreated target preserved.

### Tampered plan

Make copies of a plan and alter one field at a time: cluster UID, phase number/name,
action, group, kind, namespace, name, UID, explicit target evidence, coverage, and
duplicate count.

Expected: every tampered plan fails before mutation. Reordering only explicitly
order-insensitive collections may be accepted.

### RBAC partial coverage

Create a temporary service account and restricted kubeconfig with enough permission for
basic discovery but without one required API LIST. Never log the token. Run a read-only
plan and strict mode.

Expected:

- partial results are emitted,
- a typed Forbidden warning names canonical GVR,
- required missing coverage prevents DELETE authority,
- `--strict` exits 2 after output,
- unrestricted kubeconfig remains unaffected.

Persistent 500, timeout, and 429 paths may use mock HTTP integration tests when safely
injecting them into a live cluster is impractical. Their request count and retry count
must be asserted in production helper paths.

## 29. Destructive checkpoint suite

The checkpoint suite contains two modes because they detect different regressions.

### Cycle A: sequential individual operators

Required after Phase 2 and again for the final Phase 10 release candidate. It verifies
that individual `plan -> apply` works and makes each operator boundary observable.

Procedure:

1. Start from a fully recovered baseline.
2. Collect all 15 isolated plans before mutation as described above.
3. In config order, regenerate a fresh plan for the next operator, save it, and apply it.
4. After each operator, collect:
   - command exit and phase summary,
   - runtime plan,
   - target Subscription/CSV presence,
   - exact golden resources relevant to that operator,
   - new Terminating objects,
   - plan drift and finalizer recovery events.
5. Continue only when the previous operator exited 0 with zero failed actions, or stop and
   preserve state/logs for review.

Expected after the authority fix:

- every present target completes its declared phases with zero failed actions,
- a resource may later disappear under its true owner, but it must not be authorized by
  the wrong operator,
- RHOAI explicit Gateway/ConfigMap are deleted only in its Explicit cleanup phase after
  reference revalidation,
- RHCL ConsolePlugin/Deployment/Service/ConfigMap are deleted only in RHCL Explicit
  cleanup,
- no direct CRD/APIService/PV/PVC/Namespace delete is introduced by config defaults,
- any GC cascade is predicted and later classified, not silently called direct DELETE.

After independent review, recover the cluster before Cycle B.

### Cycle B: config-driven batch

Required after Phases 2, 6, and 10:

```bash
./target/release/oc-deps teardown batch configs/full-teardown.json \
  --refresh-discovery
```

Expected:

- baseline gate sees all 15 targets before mutation,
- CSV phases are diagnostic only,
- 15/15 entries exit 0, with 0 failed and 0 skipped in the normal baseline run,
- discovery refresh occurs once and is reused only where safe,
- each operator still performs current CR/operator/resource discovery after preceding
  deletions,
- no plan drift is accepted,
- all six explicit cleanup targets are revalidated and deleted in their correct phase,
- final summary distinguishes Succeeded/Skipped/Failed accurately,
- process exit is 0 only if every non-skipped operator succeeds.

Do not automatically rerun after a drift or partial mutation. Save the first attempt,
inspect journals and cluster state, and determine whether it is safe to continue. The
Phase 0 OGX drift attempt is evidence that reconciliation can occur between plan/apply.

At Phase 6, Cycle B is mandatory. Cycle A may be limited to operators whose query/scope
behavior changed, but final Phase 10 requires the full Cycle A and Cycle B again.

## 30. Post-delete collection and expected state

Immediately after a destructive run, before recovery:

```bash
python3 "$CORPUS/tools-collect-inventory.py" \
  "$RUN_DIR/inventory/post-inventory.jsonl" \
  "$RUN_DIR/inventory/post-list-failures.jsonl" \
  "$RUN_DIR/inventory/post-gvr-catalog.json"
```

Run the accepted post-analysis tool and the Phase-specific residual auditor. Capture:

```bash
oc get subscriptions.operators.coreos.com -A -o json > "$RUN_DIR/oc/subscriptions-post.json"
oc get clusterserviceversions.operators.coreos.com -A -o json > "$RUN_DIR/oc/csv-post.json"
oc get pods -A -o json > "$RUN_DIR/oc/pods-post.json"
oc get events -A -o json > "$RUN_DIR/oc/events-post.json"
oc get namespaces -o json > "$RUN_DIR/oc/namespaces-post.json"
oc get pv -o json > "$RUN_DIR/oc/pv-post.json"
oc get pvc -A -o json > "$RUN_DIR/oc/pvc-post.json"
oc get crd -o json > "$RUN_DIR/oc/crd-post.json"
oc get apiservice -o json > "$RUN_DIR/oc/apiservice-post.json"
```

Expected high-level state for the current config:

- all 15 target Subscriptions/CSVs are gone,
- group-sync and ODF resources remain because they are outside target scope,
- six explicit cleanup targets are NotFound,
- Namespace, PV, PVC, CRD, and APIService are not directly deleted by default,
- cascades/derived effects may remove protected kinds only when predicted and reported,
- no newly Terminating object remains unexplained,
- known residual workloads are reported, not silently ignored,
- node remains Ready,
- no unrelated system operator is removed.

Do not assert that all 25 golden objects must survive to final batch completion. Some can
legitimately disappear later when their actual owner operator is torn down. The required
assertion is:

```text
wrong operator plan did not grant/delete them;
if they later disappeared, the actual causal owner/cleanup path is recorded.
```

For every removed physical UID, classify exactly one primary mechanism:

- direct action,
- expected controller cleanup,
- ownerRef GC descendant,
- proven derived side effect,
- recreated identity,
- unexplained.

Any unexplained protected-kind removal, new orphan, dangling reference, or terminating
resource is NO-GO until reviewed.

## 31. Phase-specific live E2E matrix

### Phase 1: graph model

Live mutation is not required while the cluster remains deleted. Required E2E is the
offline frozen-corpus exporter, because it contains full all-version observations that
the normal snapshot previously lost.

On the next recovered baseline, add a read-only spot check:

- select at least one owner chain per built-in workload and CRD-backed resource,
- compare graph owner UID/API identity with `oc get ... -o json`,
- compare an API-alias UID through every served version,
- compare RHOAI/RHCL explicit targets to saved plan declarations.

Expected: exact identity/UID equality; no unresolved edge reported as authoritative.

### Phase 2: authority

Required: full isolated-plan collection, safety fixtures, Cycle A, recovery, Cycle B.
Expected: 25/25 golden false attributions blocked; legitimate descendants retained in
authority recall; six explicit cleanup targets still succeed through explicit approval.

### Phase 3: scope fixpoint

Read-only live commands must prove scope reasons against `oc`:

- RHOAI includes `rhoai-model-registries`, `rhods-notebooks`, and
  `redhat-ods-monitoring` when current resources reference them.
- cert-manager finds its operand namespace from discovered evidence.
- Sail objects linked by primary-resource annotation are included.
- Limitador's `spec.limits[].namespace` route-like value does not become a namespace.

For every added namespace, save the exact source object, field path, and `oc get`
evidence. Expected unrelated namespace growth is zero.

### Phase 4: coverage ledger

Run unrestricted read-only discovery and restricted-RBAC discovery. Compare ledger
queries with API audit/request counters if available. Expected: every intended query has
one terminal outcome; no 403/timeout becomes an empty success; strict exits 2 after
partial output.

### Phase 5: controller/finalizer ordering

On a recovered test cluster, compare:

- CSV installStrategy deployments/service accounts,
- controller Deployments and Pods,
- finalizers on candidate CRs,
- plan phase/order constraints.

In an isolated fixture, scale a test controller deployment to zero and restore it in a
trap. Expected: liveness changes to unavailable/unknown and automatic finalizer recovery
does not become more permissive. Never scale a production target controller without a
recorded restoration command.

### Phase 6: query planner/performance

Run the same 15 plans at least three times:

1. cold discovery with `--refresh-discovery`,
2. warm cache,
3. repeated cold run for variance.

Expected graph/plan output is canonically identical to accepted Phase 5. Unique LIST/GET
count and transferred bytes must not increase. Shared duplicate LISTs must decrease.
Report median wall time; do not claim improvement from one run. Then execute Cycle B.

### Phase 7: version-bound profiles

Live current-version profile must match package/CSV/image digest and add its named
evidence. Offline or isolated altered-version fixture must produce Unknown/Review and no
profile-granted delete. Compare every profile-provided resource to `oc get` and the
corresponding source-study rule.

### Phase 8: residual auditor

Run against saved Phase 0 pre/post first, then against the latest destructive checkpoint.
Expected Phase 0 findings include the OAuthClient orphan, dangling model-catalog refs,
known residuals, pre-existing termination distinction, and protected cascades. Zero known
finding may be lost. New findings must be named and reviewed.

### Phase 9: mutation/finalizer safety

Use isolated fixtures for:

- shared singleton array-entry patch with before/value/manager drift,
- Kubernetes-only finalizer,
- unknown finalizer,
- simulated external finalizer.

Expected: shared object is patched, not deleted; unknown/external strip requires explicit
approval; stale before-value blocks patch; absence never claims external cleanup success.
Also inspect NFD/GPU plans and assert Node/Namespace DELETE count is zero.

### Phase 10: profiles and remote provenance

Run profile conformance for all Cycle B operator families. For remote targets, exercise
configured reachable, configured unavailable, partial, and not-configured fixtures.
Expected status is explicit and does not turn Unavailable into absence. Finish with full
Cycle A, recovery, and Cycle B; leave cluster deleted for independent review.

## 32. E2E NO-GO conditions

Stop the phase and do not commit if any of these occurs:

1. Any golden negative receives automatic lifecycle DELETE authority.
2. Any unresolved/ambiguous/stale identity is treated as Resolved.
3. Required API coverage is missing but plan continues as though the result were empty.
4. Dry-run mutates any Kubernetes object.
5. Plan/apply accepts a recreated UID or tampered authority metadata.
6. An explicit target gains a new inbound ref and is still deleted.
7. A direct protected-kind DELETE appears with `prune_crds=false` or outside supported
   explicit cleanup policy.
8. A new unexplained Terminating object, orphan ownerRef, or dangling live reference is
   introduced.
9. Finalizer stripping becomes broader or loses cleanup-domain evidence.
10. Query optimization changes the canonical graph/plan set.
11. Batch says success with a failed non-skipped operator.
12. Expected target operator was absent at baseline and the run was still reported as a
    normal 15/15 success.
13. Non-TTY output contains ANSI or progress overwrites.
14. Credentials or Secret data enter logs.
15. The cluster is recovered before independent post-delete review.

## 33. Required E2E review report format

Every checkpoint review request must contain:

```text
Phase / git SHA / binary SHA / config SHA / kube-system UID
Baseline:
  target subscriptions present: N/15
  CSV phase distribution: ...
  node Ready: yes/no
  unexpected Terminating: N
Offline corpus:
  DELETE precision: ...
  named golden pass: ...
  authority recall: ...
  unknown coverage: ...
Read-only live:
  commands: artifact paths
  oc equality checks: pass/fail with counts
Dry-run:
  individual: N/15
  batch: exit
  mutation diff: 0 expected
Destructive, if checkpoint:
  Cycle A per operator results
  Cycle B 15 result summary
  direct/expected/GC/derived/unexplained counts
Post-state:
  target Sub/CSV remaining
  explicit target state
  newly Terminating/orphans/dangling refs
  known/new residuals
  protected kinds
Performance:
  queries/bytes/time/retries/cache hits
Deviations:
  each named with disposition
Cluster final state:
  deleted; no recovery performed
```

Attach the run directory and machine-readable manifest. A prose-only statement such as
“15/15 passed” is insufficient.

## 34. Recommended conservative release cutoff

If the full Phase 1-10 redesign cannot be completed in the current review window, do not
merge Phase 1 by itself. Phase 1 is an internal graph foundation and is not connected to
the planner authority path, so it does not correct the 25 known false-attribution
deletions.

The smallest coherent product release is PR #35 as a **conservative teardown MVP** based
on remote commit `3c77a17`, with one additional safety change:

1. Remove bulk deletion authorization for `independent` and `label-only` scopes.
2. Keep uncertain resources as REVIEW.
3. Require `--approve-resource` exact identity for those resources.
4. Retain `root` and `operator-group` only after their current exact checks pass.
5. Retain the six config-declared explicit cleanup targets with UID/drift/reference guard.
6. Keep `prune_crds=false` as the default and keep Namespace/PV/PVC/CRD/APIService outside
   explicit cleanup.

This is intentionally less complete but is a complete, explainable safety contract:

```text
automatic deletion: OLM objects, approved roots, exact UID owner lineage
explicit deletion:  exact resource approval or guarded explicit cleanup
uncertain relation: REVIEW and retained
```

Why both scopes are removed:

- All 25 frozen golden false attributions were authorized through
  `--approve-scope independent`.
- Label correlation is not lifecycle ownership and source study established that it must
  not grant core delete authority by itself, even though no current golden case happened
  to use that path.

Do not silently keep accepting these CLI values while ignoring them. Remove them from the
new-plan CLI/config value enum, or return an explicit error directing the user to exact
`--approve-resource`. Legacy saved plans containing either scope must be rejected with a
clear regenerate-plan message. Bump the execution-plan schema if required by the changed
authority contract.

Update `configs/full-teardown.json` defaults to remove both scopes. Preserve exact RHOAI
resource approvals and the RHOAI/RHCL `delete_resources` arrays. Increased residuals are
expected and must be reported as retained REVIEW resources, not treated as test failure.

### Branch/worktree handling

Do not destroy the current Phase 1 worktree. It contains uncommitted redesign work and
local Phase 0 commit `efa687b`. Create a separate worktree from the remote PR head:

```bash
git worktree add ../oc-deps-safe-cutoff -b release/cli-v2-safe \
  origin/cli-v2-phase4
```

Implement the small conservative patch there. After review, push that branch commit to
the PR head only with an explicit lease check. Do not mix the 1,500+ line unaccepted Phase
1 diff into PR #35. Resume it later on a dedicated discovery branch.

The Phase 0 commit reports more than 185,000 added lines, but this is not implementation
code: about 181,657 lines (roughly 98%) are generated raw inventory, plans, maps, and
command output. The current directory is also inflated by an uncommitted Phase 1 graph.
Even though the data volume is explainable, generated raw evidence should not be placed in
the normal product PR. Keep the full corpus as a compressed evidence artifact with a
SHA256 manifest. Commit only compact golden fixtures, summaries, the single canonical
copy of each tool, source study, and this handoff. Remove duplicate tool copies under
`scripts/` versus the corpus directory. A separate evidence branch is acceptable when no
artifact store is available.

### Required acceptance for the conservative cutoff

- fmt, clippy, all tests, release build pass.
- CLI/config parse rejects new `independent` and `label-only` bulk authorization.
- legacy execution plans with those scopes are rejected before mutation.
- all 25 golden false-attribution identities are absent from wrong-operator DELETEs.
- guarded explicit cleanup still contains exactly the two RHOAI and four RHCL targets.
- dry-run proves zero mutation and performs drift/reference revalidation.
- recovered-cluster isolated plans for all 15 operators are captured before mutation.
- final release runs full Cycle A and Cycle B as described above.
- all 15 target operator controllers/OLM objects can be removed; additional uncertain
  operand residuals are enumerated as expected conservative retention.
- no unexplained protected-kind direct delete, new termination, orphan, or dangling ref.
- README states that independent/label-only resources require exact approval until the
  typed authority redesign is released.

This cutoff completes CLI v2 teardown behavior without claiming that the discovery
redesign is finished. Continue Phases 1-10 later from the preserved worktree and corpus.
