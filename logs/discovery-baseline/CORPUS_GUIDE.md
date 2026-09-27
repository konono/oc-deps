# Discovery corpus guide

This guide explains what the Phase 0 corpus contains, what conclusions it can support,
and how to use it when changing discovery code. The canonical frozen run is:

```text
logs/discovery-baseline/20260926-cycle-b2-3c77a17/
```

The corpus is test evidence, not runtime input and not a universal model of every
Kubernetes cluster.

## What it records

The corpus combines four views of one complete 15-Operator teardown:

1. **Pre-state**: every listable served GVR, Operator inspection output, and isolated
   teardown plan before mutation.
2. **Execution**: batch plans and command logs for the successful Cycle B run.
3. **Post-state**: the same all-GVR inventory after teardown.
4. **Interpretation**: deterministic summaries that classify direct actions,
   owner-reference descendants, derived side effects, recreated identities, dangling
   references, and provider API operands.

The compact files are reviewable in Git. `full-corpus.tar.zst` contains expanded JSONL
inventories, plans, and logs. Its hash is pinned by `ARTIFACT_SHA256`.

## Three identity layers

Do not compare only line counts. The same object can be observed through multiple served
versions or API aliases.

| Layer | Identity | Use |
|---|---|---|
| Raw observation | One row returned by one GVR LIST | API coverage and retry analysis |
| API-logical | group/kind/namespace/name | User-facing identity and version comparison |
| Physical | Kubernetes UID | Ownership closure and actual disappearance |

UID-null objects are retained separately with a stable fingerprint. Never merge a
UID-null row into a physical entity merely because kind/name match.

## The 25 provider API operands

`provider-api-operands.json` is a positive oracle. These objects are not false
attributions. Their API was supplied by one dependency Operator while a different
controller created or managed the instance.

Expected policy:

```text
without independent approval -> REVIEW
with full-teardown independent approval -> DELETE
```

Owner references, managed-by labels, and RouteRule annotations remain lifecycle evidence.
They explain the relationship but do not veto an explicitly approved full teardown.

## Reproduce the frozen analysis

Run from the corpus directory:

```bash
sha256sum -c ARTIFACT_SHA256

workdir=$(mktemp -d)
tar --zstd -xf full-corpus.tar.zst -C "$workdir"

python3 "$workdir/tools-post-analysis.py" \
  "$workdir/inventory/pre-inventory.jsonl" \
  "$workdir/inventory/post-inventory.jsonl" \
  "$workdir/batch-plans" \
  "$workdir/provider-api-operands.json" \
  "$workdir/inventory/gvr-catalog.json" \
  "$workdir/post-analysis.rebuilt.json"

cmp post-analysis.json "$workdir/post-analysis.rebuilt.json"
```

Expected core invariants:

```text
provider API operands:             25/25
direct DELETE physical UIDs:          91
EXPECT-gone physical UIDs:            72
planned ownerRef descendants:       1282
DELETE-seed ownerRef closure:       1460
removed physical UIDs:              2784
newly Terminating objects:             0
pre/post LIST failures:                0
```

The exact inventory counts and analyzer hashes are in `manifest.json`. A count change is
not automatically a regression; it must be explained by code, cluster, API version, or
fixture changes.

## How to use it for implementation tests

### Discovery-only changes

Examples: identity indexes, relationship typing, namespace extraction, GVR
normalization, and query scheduling.

Required checks:

1. Run normal focused Rust unit tests against production helpers.
2. Replay the frozen analyzer and require byte-identical output unless the PR explicitly
   changes an interpretation.
3. Validate all 25 provider operands and preserve their approval-dependent decisions.
4. Compare raw, logical, and physical layers separately.
5. Inspect `post-specref-summary.json` and `post-specref-dangling.json` when changing
   reference extraction.

Do not load the 30+ MiB expanded corpus in every default unit test. Extract the smallest
representative records into focused Rust fixtures. An opt-in or ignored integration test
may unpack the archive, but its assertions must call the same production helpers used by
the command path rather than reimplementing the algorithm in the test.

### Planner or approval changes

The frozen plans are input oracles. Check both policy states:

- no `independent` approval: provider operands remain REVIEW;
- recorded full teardown approvals: the same 25 become DELETE.

Also require zero direct DELETE actions for Namespace, PV, PVC, CRD, and APIService when
their corresponding direct-action option is disabled. This is an action guarantee, not
an outcome-survival guarantee: ownerRef GC, storage reclaim, and API deregistration can
still remove objects.

Planner/executor changes require a recovered-cluster Cycle A and Cycle B rerun after the
offline gates pass. Discovery-only observational changes do not require destructive E2E.

### Performance changes

Use `gvr-catalog.json` and raw LIST records to calculate request coverage. Preserve:

- canonical GVR in every warning;
- 401/403 without retry;
- timeout, 408, 429, and 5xx retry counts;
- pagination;
- shared concurrency limits;
- final incomplete/strict semantics.

Report both request count and elapsed time. A faster run that silently drops GVRs or
namespaces is a regression.

## Live validation after offline gates

When a cluster is available, validate read-only behavior before destructive testing:

```bash
oc-deps operator resources <operator> --scope related -o json
oc-deps graph -n <namespace> --file /tmp/evidence-graph.json
oc get <resource> -n <namespace> -o json
```

Compare group, version, kind, namespace, name, UID, all owner references, and the exact
spec field that produced each typed reference. Record final scan warnings separately
from retry events.

Run destructive Cycle A/B only when planner, approval, execution, finalizer recovery, or
reference-guard behavior changes. Capture the same pre/post artifacts and leave the
cluster state unchanged until independent review completes.

## Updating or replacing the corpus

A replacement corpus must include:

- commit and binary hash;
- kube-system UID and config hash;
- complete GVR catalog and LIST failure ledger;
- pre-delete Operator resources and isolated plans for every configured Operator;
- batch command, result, and per-Operator plans;
- post inventory;
- secret/token redaction checks;
- deterministic analyzer rerun;
- documented expected semantic changes.

Never overwrite the existing directory in place. Add a dated directory, compare it with
the prior corpus, review the interpretation, and only then nominate it as canonical.

## Known limits

- The corpus represents one OpenShift/RHOAI topology and one point in time.
- Namespaced spec-reference coverage is recorded; cluster-scoped spec-reference coverage
  is incomplete.
- `other_removed/churn` contains unrelated reconciliation and needs live evidence before
  being attributed to teardown.
- The Limitador slash-containing application namespace is a frozen namespace-discovery
  false positive, documented for a later generic fix.

See the corpus README for exact collection commands and
`DISCOVERY_IMPLEMENTATION_HANDOFF.md` for the remaining discovery roadmap.
