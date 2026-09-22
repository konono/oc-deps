# oc-deps

Kubernetes resource dependency inspector. Given any resource, walks both up (ownerReferences) and down (reverse ownerReference lookup) to show the full parent-child hierarchy.

Works with **any** resource type — built-in kinds, CRDs, and Operator-managed resources.

```
$ oc-deps pod/my-app-6f8b9c4d7-x2k4p -n demo

📦 Namespace: demo

Deployment/my-app
├─ ReplicaSet/my-app-6f8b9c4d7
│  └─ Pod/my-app-6f8b9c4d7-x2k4p  ◀ target
│     └╌ Secret/my-app-tls  (via spec.volumes[].secret.secretName)
└╌ ◁ Service/my-app  (via spec.selector)
```

## Install

```bash
cargo install --git https://github.com/konono/oc-deps.git
```

Or from a local clone:

```bash
cargo install --path .
```

Requires Rust toolchain and an active kubeconfig (`~/.kube/config`, `KUBECONFIG`, or in-cluster).

## Usage

```bash
# Basic: kind/name format
oc-deps pod/<pod-name> -n <namespace>
oc-deps deployment/<name> -n <namespace>

# Specify kind separately
oc-deps -k Deployment <name> -n <namespace>

# GVR notation (useful for CRDs)
oc-deps -k deployments.apps <name> -n <namespace>

# Fast parent chain only (no namespace scan)
oc-deps --up-only pod/<pod-name> -n <namespace>

# Children only
oc-deps --down-only deployment/<name> -n <namespace>

# All dependency trees in a namespace
oc-deps --map -n <namespace>

# Trace which Operator installed a CRD
oc-deps --crd-origin -k MyCustomResource -n <namespace>

# Output formats
oc-deps -o tree  deployment/<name> -n <namespace>   # default
oc-deps -o table deployment/<name> -n <namespace>
oc-deps -o json  deployment/<name> -n <namespace>
```

### Options

| Flag | Description |
|------|-------------|
| `-n, --namespace` | Target namespace (default: kubeconfig default) |
| `-k, --kind` | Resource kind when not using `kind/name` format |
| `-o, --output` | Output format: `tree` (default), `table`, `json` |
| `-d, --depth` | Max traversal depth (default: 20) |
| `--up-only` | Show only parent chain (fast, no namespace scan) |
| `--down-only` | Show only child resources |
| `--map` | Show all dependency trees in the namespace |
| `--crd-origin` | Show which Operator/CSV installed the CRD |
| `--no-refs` | Disable spec-level reference detection |
| `--include-events` | Include Event resources in scan (skipped by default) |
| `--no-cache` | Skip API discovery cache |

## How it works

1. **API Discovery** — queries the cluster's API server to build a map of all available resource types (cached for 5 minutes in `/tmp/oc-deps-cache/`)
2. **Namespace Scan** — concurrently fetches all namespaced resources in the target namespace (concurrency: 50) and builds a reverse ownerReference index
3. **Tree Construction** — walks the index to build the full parent-child tree using pure HashMap lookups (no async recursion)
4. **Cluster-scoped Parents** — individually fetches any cluster-scoped parents (e.g., ClusterRole, Namespace) not covered by the namespace scan
5. **Spec References** — optionally detects Secret, ConfigMap, and other resource references embedded in spec fields

The `--up-only` mode skips step 2 entirely and uses targeted API calls to walk the parent chain, making it much faster for simple lookups.

## Output formats

**Tree** (default) — uses `Kind/name` format so you can copy-paste directly into `oc get` / `kubectl get` commands. The target resource is highlighted. Spec-level references (Secrets, ConfigMaps) are shown with dashed lines.

**Table** — tabular view showing Kind, Name, and relationship (Parent/Self/Child).

**JSON** — structured output for scripting and automation.

## Operator Teardown

`oc-deps` includes a teardown planner that generates safe, phased deletion plans for OLM-managed operators.

### List operators

```bash
oc-deps operators              # tree view
oc-deps operators -o table     # table view
oc-deps operators -o json      # JSON output
```

### Inspect an operator

Show all resources belonging to an operator (OLM resources, controllers, CRDs, CR instances, pods):

```bash
oc-deps teardown inspect rhods-operator
```

### Generate a teardown plan

```bash
oc-deps teardown plan rhods-operator
oc-deps teardown plan rhods-operator odf-operator   # multiple operators
oc-deps teardown plan rhods-operator -o json         # JSON output
oc-deps teardown plan rhods-operator --prune-apis    # include CRD deletion
```

The plan is read-only — nothing is deleted. It generates a phased deletion sequence:

| Phase | Name | Action |
|-------|------|--------|
| 0 | Freeze OLM | DELETE Subscription, KEEP CSV |
| 1 | Trigger operand cleanup | DELETE root CRs, EXPECT managed descendants to vanish |
| 2 | Remaining cleanup | DELETE any remaining operands |
| 3 | Remove controllers | DELETE CSV (GC removes Deployments) |
| 4 | APIs | KEEP CRDs by default (DELETE with `--prune-apis`) |
| 5 | Namespaces | KEEP (manual verification required) |

### Check resource status

```bash
oc-deps teardown status rhods-operator
```

Shows the current cluster state of each resource in the plan (EXISTS, DELETING, GONE) with finalizer details.

### Explain plan ordering

```bash
oc-deps teardown explain rhods-operator --resource datasciencecluster/default-dsc
```

Explains why a specific resource is in its phase, showing the evidence chain from OLM attribution and safety invariants.

### Execute a plan

```bash
oc-deps teardown apply rhods-operator --dry-run    # preview only
oc-deps teardown apply rhods-operator              # warnings and interactive confirmation
oc-deps teardown apply rhods-operator --force       # suppress advisory warnings
```

### Cluster snapshot and evidence graph

```bash
oc-deps snapshot -n <namespace> -o snapshot.json
oc-deps graph -n <namespace> -o evidence-graph.json
```

### Safety tiers

`apply` enforces a multi-layer safety model before any deletion:

| Tier | Condition | Override |
|------|-----------|----------|
| **Blocker** | External operator depends on target CRD | Cannot override |
| **Critical preflight** | CSV not Succeeded, controller unavailable | Cannot override (`--force` ignored) |
| **Non-critical preflight** | Uncertain CR provenance | Warn and continue |
| **REVIEW items** | Resources with unknown provenance | Preserve unless explicitly approved |
| **Confirmation** | Interactive y/N prompt | User types `y` |
| **Barrier** | Resources must vanish before next phase | Times out after 300s or stalls after 120s |
| **Pre-controller guard** | REVIEW resources with finalizers block CSV deletion | Cannot override |

### Provenance classification

CRs are classified by how strongly they can be attributed to the target operator:

- **Managed**: ownerRef points to operator's CSV or Deployment
- **LikelyManaged**: labels contain the operator's CSV name prefix, or managedFields manager matches a deployment name
- **Unknown**: no attributable evidence

Only `Managed` CRs are auto-deleted. `LikelyManaged` and `Unknown` become REVIEW items and remain preserved unless explicitly approved with `--approve-delete` or in the TUI. Unresolved REVIEW items do not block the interactive CLI; the operator cleanup continues after a final `y` confirmation. Non-interactive execution still requires all REVIEW items to be resolved.

### Key flags

| Flag | Description |
|------|-------------|
| `--dry-run` | Show what would be done without executing |
| `--prune-apis` | Include CRD deletion in plan (default: KEEP) |
| `--approve-delete label-only` | Delete REVIEW CRs discovered only through matching platform labels; excludes Namespace, PV, PVC, and CRD |
| `--approve-delete operator-group` | Delete an OperatorGroup only when no non-target operator remains in its namespace |
| `--force` | Suppress advisory warnings. Does not authorize REVIEW deletion or override blockers and safety guards |
| `--no-cache` | Skip API discovery cache (force fresh discovery) |

`--force` changes warning output only. It does not change the plan, authorize additional
deletions, bypass confirmation, or relax execution guards.

The API discovery cache is valid for 30 minutes. Use `--no-cache` after changing CRDs or
APIService registrations when the command must observe those changes immediately.

For `teardown apply-set`, `--no-cache` refreshes API discovery for the first operator and reuses
that fresh snapshot for later operators in the same run. Operator, CR, and namespace discovery
still runs for every operator so each plan observes changes made by earlier teardowns.

### Apply-set deletion approvals

Apply-set config separates bulk REVIEW scopes from exact resource approvals:

```json
"approve_delete": {
  "scopes": ["root", "independent", "label-only", "operator-group"],
  "resources": [
    "maas.opendatahub.io/Config/-/default",
    "MLflow/mlflow"
  ]
}
```

Each scope is opt-in. If a scope is omitted, matching REVIEW resources remain preserved. The
structured form intentionally has no `all` scope; use `root` and `independent` explicitly.
`resources` contains exact approvals only. The original array form remains accepted for existing
configs.

## Build

```bash
cargo build --release
# or
make build           # dev build
make release         # release build
make check           # fmt + lint + build
make test            # run tests
```

The binary is at `target/release/oc-deps`.

## License

MIT
