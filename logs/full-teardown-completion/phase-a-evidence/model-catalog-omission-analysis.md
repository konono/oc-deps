# model-catalog Residual Audit Omission Analysis

## Summary

`model-catalog` (Deployment in `rhoai-model-registries` namespace) was **completely absent** from all
15 operators' residual audit reports in Cycle B. The other three residuals (keycloak/postgres,
maas-postgres, ogx-postgres) appeared as UNATTRIBUTED. The root cause is an **inventory gap**:
the `rhoai-model-registries` namespace was never included in any operator's `footprint_namespaces`,
so the namespace scan that discovers unattributed residuals never ran there.

## Production Path Analysis

### How `footprint_namespaces` is built

`src/teardown/journal.rs:738-774` — `build_audit_context()`:

1. **Line 747-748**: Adds operator's `install_namespace` (e.g., `redhat-ods-operator` for rhods-operator)
2. **Line 772-773**: Adds namespaces from plan action resources (DELETE, EXPECT, KEEP, REVIEW actions)

```rust
// journal.rs:747-748
ctx.footprint_namespaces.insert(op.install_namespace.clone());

// journal.rs:772-773
if let Some(ns) = &rid.namespace {
    ctx.footprint_namespaces.insert(ns.clone());
}
```

### How residual audit uses `footprint_namespaces`

`src/teardown/audit.rs:808-839` — Phase B+C of `run_residual_audit()`:

```rust
// audit.rs:823
for ns in &ctx.footprint_namespaces {
    for target in &all_targets {
        scan_namespace_for_target(...)
    }
}
```

The scan iterates NATIVE_WORKLOAD_TARGETS (Deployment, StatefulSet, DaemonSet, etc.) + OLM_TARGETS +
OPENSHIFT_TARGETS **only in footprint_namespaces**. Any namespace not in this set is invisible.

### Why `rhoai-model-registries` is not in the scope

The `rhoai-model-registries` namespace is **not** in any operator's footprint because:

1. **Not an install namespace**: rhods-operator installs to `redhat-ods-operator`, not `rhoai-model-registries`
2. **No plan action references it**: The rhods-operator plan contains actions for resources in
   `redhat-ods-operator`, `redhat-ods-applications`, `redhat-ods-monitoring`, etc., but
   `model-catalog` has **no ownerRef** chain back to any plan resource, so its namespace
   never enters the plan action resource set.

The `model-catalog` Deployment has `app.kubernetes.io/managed-by=model-registry-operator` label,
suggesting it was created by the model-registry-operator (a component installed by RHOAI/ODH).
However, the model-registry-operator creates it in a **cross-namespace** pattern — the operator
controller runs in `redhat-ods-applications` but creates the workload in `rhoai-model-registries`.

### Cycle B Evidence

From `logs/discovery-phase-d/20260928T113949Z-6186729/cycle-b/batch-output.txt`:

- `rhoai-model-registries` appears **zero** times in the entire batch output
- rhods-operator residual audit shows scope of **5 namespace(s)** — confirmed `rhoai-model-registries` not among them
- `maas-postgres` and `ogx-postgres` appear as UNATTRIBUTED under rhods-operator (in `redhat-ods-applications`)
- `keycloak/postgres` appears as UNATTRIBUTED under rhbk-operator (in `keycloak` namespace)
- Total 0 operators have `rhoai-model-registries` in their footprint

## Gap Classification

| Workload | Gap Type | Explanation |
|---|---|---|
| `keycloak/postgres` | **Attribution gap** | In `keycloak` namespace (rhbk-operator footprint), scanned, found, but no ownerRef/label evidence → UNATTRIBUTED |
| `maas-postgres` | **Attribution gap** | In `redhat-ods-applications` (rhods-operator footprint), scanned, found, but no ownerRef/label evidence → UNATTRIBUTED |
| `ogx-postgres` | **Attribution gap** | In `redhat-ods-applications` (rhods-operator footprint), scanned, found, but no ownerRef/label evidence → UNATTRIBUTED |
| `model-catalog` | **Inventory gap** | In `rhoai-model-registries` which is **not in any operator's footprint_namespaces** → never scanned → never reported |

## Observation Point Note

`model-catalog` (UID `e983d126-bc36-41f0-8a55-070b0df2a405`) has different ownerRef state depending
on observation point:
- **Recovered state** (operators present): ownerRef to `ModelRegistry/default-modelregistry` exists
- **Deleted state** (post-teardown): ownerRef is **absent**

The mechanism that removed the ownerRef (and re-added it after recovery) was not captured in these
artifacts. The inventory gap classification applies to the **post-delete audit** — the point where
the residual report runs. At that point, no ownerRef chain exists on this resource.

## Root Cause

The `footprint_namespaces` construction at `journal.rs:738-774` only includes:
- Operator install namespaces
- Namespaces explicitly referenced by plan action resources

It does **not** include:
- Namespaces referenced by OperatorGroup `spec.targetNamespaces`
- Namespaces referenced by spec fields of operator CRs (e.g., a ModelRegistry CR might reference `rhoai-model-registries`)
- Namespaces where operator-managed workloads are actually running (cross-namespace operand pattern)

This is the design gap identified in Issue #46 Phase A: the footprint is derived only from the
plan's own resource references, not from the operator's actual deployment footprint.

## Fix Direction (from Issue #46)

Issue #46 Phase B specifies: save plan-time namespace provenance (spec namespace references,
OperatorGroup targets, explicit target namespaces) into journal audit scope, then use that
expanded scope for fresh post-delete scan. This would cause `rhoai-model-registries` to enter
the scan scope via OperatorGroup target or spec reference evidence.
