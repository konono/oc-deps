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

# Filter --map by root resource kind
oc-deps --map --filter kind=Deployment -n <namespace>

# Filter --map by root resource label
oc-deps --map --filter label=app.kubernetes.io/part-of=myapp -n <namespace>

# Combine filters (AND)
oc-deps --map --filter kind=Deployment --filter label=app=myapp -n <namespace>

# Which Operator manages this resource?
oc-deps who-manages deployment/<name> -n <namespace>
oc-deps who-manages pod/<pod-name> -n <namespace>
oc-deps who-manages -o json deployment/<name> -n <namespace>

# Inspect all resources managed by an operator
oc-deps inspect rhods-operator
oc-deps inspect rhods-operator -o json
oc-deps inspect rhods-operator --cross-namespace   # discover across namespaces

# Trace impact radius from a root CR
oc-deps trace datasciencecluster/default-dsc -n redhat-ods-applications
oc-deps trace deployment/<name> -n <namespace> -o json
oc-deps trace deployment/<name> -n <namespace> --cross-namespace

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
| `--filter` | Filter `--map` results by root node. `kind=X` or `label=key=value`. Repeatable (AND). Requires `--map` |
| `--crd-origin` | Show which Operator/CSV installed the CRD |
| `--labels` | Show labels on each resource in tree output |
| `--annotations` | Show annotations on each resource (opt-in). Excludes `kubectl.kubernetes.io/last-applied-configuration` and `control-plane.alpha.kubernetes.io/leader` |
| `-v, --verbose` | Show all scan/discovery warnings (default: first 5) |
| `--strict` | Exit with code 2 if discovery/scan is incomplete. Partial results are output before exit. AllNamespaces scope messages alone do not trigger exit 2 |
| `--show-spec` | Show container resource requests/limits for Pod, Deployment, StatefulSet, DaemonSet, Job, CronJob, DeploymentConfig |
| `--network` | Show network paths (Service/Ingress/Route) for Pod, Deployment, ReplicaSet, StatefulSet, DaemonSet |
| `--no-refs` | Disable spec-level reference detection |
| `--include-events` | Include Event resources in scan (skipped by default) |
| `--no-cache` | Skip API discovery cache |

**JSON output:** Labels are always included (even when empty: `"labels": {}`). Annotations are included only with `--annotations`.

**Root-level options:** `--verbose`, `--strict`, `--labels`, and `--annotations` are root-level flags for commands like `snapshot` and `graph` — they must precede the subcommand name:

```bash
oc-deps --strict snapshot -n <namespace> -o snapshot.json
oc-deps --verbose graph -n <namespace> -o evidence-graph.json
```

**`inspect` and `trace`** have their own `--verbose` and `--strict` flags, so both positions work:

```bash
oc-deps inspect rhods-operator --strict --verbose
oc-deps --strict inspect rhods-operator    # also works (merged with subcommand flags)
```

## How it works

1. **API Discovery** — queries the cluster's API server to build a map of all available resource types (cached for 30 minutes in `/tmp/oc-deps-cache/`). Only resource types that support the `list` verb are included in scans
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

Show all resources belonging to an operator, classified by Relationship / Evidence / Confidence:

```bash
oc-deps inspect rhods-operator              # top-level subcommand
oc-deps inspect rhods-operator -o json       # JSON output
oc-deps inspect rhods-operator --cross-namespace  # discover across namespaces
oc-deps inspect rhods-operator -o table           # tabular output with group/source
oc-deps teardown inspect rhods-operator            # also available under teardown
```

Resources are grouped into categories with **Relationship**, **Evidence**, and **Confidence**:
- **OLM** — Subscription, CSV (`olm`, Managed)
- **Controller** — Deployments, ServiceAccounts from CSV installStrategy (`installStrategy`, Managed), Pods by selector match (`selector-match`, Attributed)
- **CR Instances** — owned CRD instances with ownerRef UID match (`ownerRef`, Managed) or without (`owned-crd-instance`, Attributed)
- **Related CR Instances** — label-matched CRDs (`label-match`, Inferred — correlation only, not causation)

Each resource may have a **`source_id`** indicating the relationship edge source. For ownerRef edges, this is the parent resource; for label-match edges, this is the attributed Operator CSV. In tree output this appears as `← group/Kind/name ns:xxx`. In JSON, `source_id` is a full ResourceId with `group/kind/namespace/name/uid`; when absent the field is omitted (not null). AllNamespaces scope messages appear in `scope_warnings` (not `warnings`).

**`--cross-namespace`** discovers candidate namespaces from:
1. Install namespace (always included)
2. OperatorGroup `status.namespaces` / `spec.targetNamespaces`
3. Owned CRD instances' actual namespaces
4. Spec namespace references — fields matching `*namespace*`/`*Namespace*` in CR specs (heuristic; exclusion fields like `excludedNamespaces` are skipped)
5. Label evidence from related CRD instances

Namespaces are scanned sequentially to avoid connection exhaustion. For AllNamespaces operators, only namespaces with known evidence are scanned — the tool does not scan all cluster namespaces.

If some namespaces or CRDs fail (403, timeout), partial results are still returned. Use `--strict` to exit with code 2 when discovery is incomplete. Use `--verbose` to see all warnings (default: first 5). In JSON output, `warnings` contains all failure messages and `scan_warning_count` is the total count.

### Trace impact radius

Show the impact radius from a root resource — ownerRef descendants, spec references, same-operator CRDs, and label matches:

```bash
oc-deps trace datasciencecluster/default-dsc -n redhat-ods-applications --cross-namespace  # cluster-scoped, scan operand ns
oc-deps trace deployment/dashboard-operator -n redhat-ods-applications
oc-deps trace deployment/<name> -n <ns> -o json
oc-deps trace deployment/<name> -n <ns> -o table
oc-deps trace deployment/<name> -n <ns> --cross-namespace --strict
```

Each category shows Relationship and Confidence:
- **ownerRef descendants** — `ownerRef`, Managed (High), confirmed by UID match
- **spec references** — `spec-ref`, Attributed (Medium), detected from spec field paths
- **Same Operator CRDs** — `same-operator-crd`, Inferred (Low), correlation only, not causation
- **label matches** — `label-match`, Inferred (Low), correlation only

The managing operator is determined via `who-manages` (ownerRef chain → CSV), not CRD origin. This prevents misattribution for built-in kinds like Deployment.

`--cross-namespace` uses the same evidence-based namespace discovery as `inspect`. `--strict` exits with code 2 when any discovery or scan fails, after outputting partial results. In JSON, `warnings` contains all failure messages and `descendants` contains the full ownerRef tree with `group/kind/namespace/name` identity.

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

### Snapshot diff

Compare two snapshots offline (no cluster connection required):

```bash
oc-deps diff before.json after.json                 # tree output (default)
oc-deps diff before.json after.json --format table   # table output
oc-deps diff before.json after.json --format json    # JSON output
```

Resources are matched by logical identity (group/kind/namespace/name). UID changes are detected as Recreated. Volatile annotations (`last-applied-configuration`, etc.) are excluded from change detection.

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

Apply-set config can declare common REVIEW approvals once and keep per-operator entries focused on
exceptions:

```json
"defaults": {
  "approve_delete": {
    "scopes": ["root", "independent", "label-only", "operator-group"]
  }
},
"operators": [
  {
    "name": "rhods-operator",
    "approve_delete": {
      "resources": [
        "maas.opendatahub.io/Config/-/default",
        "MLflow/mlflow"
      ]
    }
  },
  { "name": "rhbk-operator" }
]
```

Each scope is opt-in. If a scope is omitted, matching REVIEW resources remain preserved. The
structured form intentionally has no `all` scope; use `root` and `independent` explicitly.
Operator-level approvals and preserves are added to the defaults. Operator-level `force` and
`non_interactive` values override their defaults. `resources` contains exact approvals only. The
original array form remains accepted for existing configs.

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
