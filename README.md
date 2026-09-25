# oc-deps

Kubernetes resource dependency inspector. Given any resource, walks both up (ownerReferences) and down (reverse ownerReference lookup) to show the full parent-child hierarchy.

Works with **any** resource type — built-in kinds, CRDs, and Operator-managed resources.

```
$ oc-deps tree pod/my-app-6f8b9c4d7-x2k4p -n demo

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

A subcommand is always required. Resource arguments use `kind/name` format.

```bash
# Show dependency tree around a resource
oc-deps tree pod/<pod-name> -n <namespace>
oc-deps tree deployment/<name> -n <namespace>

# Fast parent chain only (no namespace scan)
oc-deps tree pod/<pod-name> -n <namespace> --direction parents

# Children only
oc-deps tree deployment/<name> -n <namespace> --direction children

# All dependency trees in a namespace
oc-deps map -n <namespace>

# Filter map by root resource kind or label
oc-deps map -n <namespace> --root-kind Deployment
oc-deps map -n <namespace> --root-kind Deployment --root-label app=myapp

# Network diagnostics (Service, EndpointSlice, NetworkPolicy)
oc-deps network deployment/<name> -n <namespace>
oc-deps network pod/<pod-name> -n <namespace> -o json
oc-deps network service/<name> -n <namespace>       # Service target (selectorless OK)

# Which Operator manages this resource?
oc-deps who-manages deployment/<name> -n <namespace>

# Inspect all resources managed by an operator
oc-deps inspect rhods-operator
oc-deps inspect rhods-operator --cross-namespace

# Trace discovered relationships from a resource
oc-deps trace datasciencecluster/default-dsc -n redhat-ods-applications
oc-deps trace deployment/<name> -n <namespace> --scope related

# Output formats (available on tree, map, network, trace)
oc-deps tree deployment/<name> -n <namespace> -o tree    # default
oc-deps tree deployment/<name> -n <namespace> -o table
oc-deps tree deployment/<name> -n <namespace> -o json

# Show labels, annotations, or pod resources
oc-deps tree deployment/<name> -n <namespace> --show labels --show annotations
oc-deps tree deployment/<name> -n <namespace> --show pod-resources
```

### Common options (tree, map, network, trace)

| Flag | Description |
|------|-------------|
| `-n, --namespace` | Target namespace (default: kubeconfig default) |
| `-o, --output` | Output format: `tree` (default), `table`, `json` |
| `--refresh-discovery` | Refresh API discovery cache |
| `-v, --verbose` | Show all scan/discovery warnings (default: first 5) |
| `--strict` | Exit with code 2 if discovery/scan is incomplete |
| `--show` | Show additional fields: `labels`, `annotations`, `pod-resources` (repeatable) |
| `-d, --depth` | Max traversal depth (default: 20) |
| `--no-refs` | Disable spec-level reference detection |
| `--include-events` | Include Event resources in scan |

### tree-specific options

| Flag | Description |
|------|-------------|
| `--direction` | Traversal direction: `both` (default), `parents` (fast, no scan), `children` |

### map-specific options

| Flag | Description |
|------|-------------|
| `-A, --all-namespaces` | Scan all namespaces (mutually exclusive with `-n`) |
| `--namespace-selector` | Select namespaces by label `key=value` (repeatable, AND). Requires `-A` |
| `--exclude-namespace` | Exclude namespaces matching pattern (repeatable). Requires `-A` |
| `--exclude-system-namespaces` | Exclude `openshift-*`, `kube-*`, `default`. Requires `-A` |
| `--root-kind` | Filter by root resource kind (repeatable) |
| `--root-label` | Filter by root resource label `key=value` (repeatable, AND) |

**JSON output:** Labels are always included (even when empty: `"labels": {}`). Annotations are included only with `--show annotations`.

### Network Paths (`network`)

The `network` subcommand shows the full network reachability chain for workloads: Pod labels → Service selector → Ingress/Route backends, plus EndpointSlice health and NetworkPolicy posture.

**Service as target:** `network service/<name>` diagnoses a specific Service directly. The Service's config, status, EndpointSlices, and Ingress/Route backends are always shown, even when the Service has no selector or no endpoints. For selectorless Services, `targetRefMatchedPods` from EndpointSlice targetRefs are included in NetworkPolicy posture evaluation.

**MetalLB integration:** When MetalLB CRDs exist on the cluster, `network` diagnoses LoadBalancer Services' advertisement path. Provider detection is per-service evidence-based: MetalLB annotations (`metallb.io/address-pool`, `metallb.io/loadBalancerIPs`, `metallb.io/ip-allocated-from-pool`, legacy `metallb.universe.tf/*`), `loadBalancerClass` containing "metallb", or assigned IP matching a MetalLB pool range. Services without MetalLB evidence show `provider: null`.

Pool resolution evaluates: assigned IPs, requested IPs (from `metallb.io/loadBalancerIPs` comma-separated, `spec.loadBalancerIP`), requested pool name, `ip-allocated-from-pool` annotation, IP range matching (IPv4/IPv6 CIDR and dash-range), `autoAssign`, and `serviceAllocation` constraints (namespaces, namespaceSelectors, serviceSelectors, priority). When no pool explicitly matches but MetalLB evidence is present, autoAssign-eligible pools are shown as candidates sorted by serviceAllocation priority (lower = higher priority). Pool status counters (`available`, `assigned`) are included in JSON output when present.

Namespace selector evaluation uses actual namespace labels fetched from the cluster. The `namespaces` and `namespaceSelectors` fields in serviceAllocation are OR: if either matches, the namespace is allowed. When namespace labels are unavailable (e.g., 403), a warning is shown.

Advertisement resolution evaluates pool selectors (`ipAddressPools` direct name OR `ipAddressPoolSelectors` label match against pool labels) and service selectors against Service labels. L2 interfaces and BGP details (aggregationLength/V6, localPref, communities, peers) are displayed. Node selector evaluation uses actual node labels fetched from the cluster: candidate nodes are computed and displayed with status ("all", "matched N", "mismatch", "unavailable"). `externalTrafficPolicy: Local` checks the intersection of ready endpoint nodes with advertised (candidate) nodes and warns when no overlap exists. Pool and advertisement are matched within the same namespace.

MetalLB LIST failures (403, 500, timeout) propagate as typed warnings rather than being silently swallowed. MetalLB CRD absence is handled gracefully. JSON includes a `metallb` object per service path with `provider`, `requestedIPs`, `requestedPool`, `pools[]` (with `allocationMatch`, `namespace`, `labels`, `serviceAllocation`, `statusAvailable`, `statusAssigned`), `advertisements[]` (with `namespace`, `interfaces`, `peers`, `serviceSelectors`, `nodeSelectors`, `candidateNodes`, `nodeSelectorStatus`), and `warnings[]`.

**Service fields displayed:**

| Field | Description |
|-------|-------------|
| `type` | ClusterIP, NodePort, LoadBalancer, ExternalName |
| `clusterIP` | Virtual IP assigned to the service |
| `selector` | Label selector used to match Pods |
| `internalTrafficPolicy` | Cluster or Local |
| `externalTrafficPolicy` | Cluster or Local (NodePort/LB only) |
| `ipFamilyPolicy` | SingleStack, PreferDualStack, RequireDualStack |
| `healthCheckNodePort` | Port for LB health checks (when externalTrafficPolicy=Local) |
| `loadBalancerClass` | Custom LB implementation class |
| `allocateLoadBalancerNodePorts` | Whether to allocate NodePorts for LB type |
| `loadBalancerIngress` | LB-assigned addresses with optional `ipMode` |

**EndpointSlice and endpoint conditions:**

EndpointSlices are the modern replacement for Endpoints. Each slice contains a list of endpoints with conditions:

- `ready` -- the endpoint is ready to receive traffic
- `serving` -- the endpoint is serving traffic (can be true even when terminating)
- `terminating` -- the endpoint's Pod is terminating
- When `ready` is `None` (null), the K8s spec treats it as effectively ready. The `effectiveReady` count = `ready` + `unknown`

**Selector vs selectorless Services:**

- Services with a `selector` field match Pods by label. `selectorMatchedPods` lists these
- EndpointSlice `targetRef` points to the actual backing Pods. `targetRefMatchedPods` lists these
- For selectorless Services, only `targetRefMatchedPods` is populated (manual Endpoints/EndpointSlices)

**External reachability** is not determined by Service type alone. A LoadBalancer type does not guarantee external access — it depends on cloud provider, MetalLB, or other LB implementation.

**JSON field reference (`network -o json`):**

Each entry in `networkPaths[]` contains:
- `service: {name, config: {...}, status: {...}}` — config holds spec fields, status holds observed state
  - Config: `type`, `clusterIP`, `ports[]` (with `nodePort`), `selector`, `hasSelector`, `externalIPs`, `ipFamilies`, `externalTrafficPolicy`, `internalTrafficPolicy`, `ipFamilyPolicy`, `healthCheckNodePort`, `loadBalancerClass`, `allocateLoadBalancerNodePorts`
  - Status: `loadBalancerIngress[]` (with `ip`, `hostname`, `ipMode`)
- `endpointSlices[]` with `name`, `addressType`, `ports[]` (including `appProtocol`), `endpoints[]`
- Each endpoint: `addresses[]`, `hostname`, `nodeName`, `zone`, `ready`, `serving`, `terminating`, `targetRef` (with `apiVersion`), `hints`
- `endpointSummary`: `ready`, `notReady`, `unknown`, `effectiveReady`, `serving`, `terminating`
- `selectorMatchedPods[]`, `targetRefMatchedPods[]`
- `ingresses[]` with `kind`, `name`, `host`, `path`, `tls`
- Top-level `warnings[]` (typed ScanWarning array) and `scanWarningCount`

**Example tree output:**

```
Service/my-app
    Type:      NodePort
    ClusterIP: 10.96.100.42
    Port:      8080/TCP → 8080 (nodePort: 31234)
    ExternalIPs: 192.0.2.50
    IPFamilies: IPv4
    ExternalTrafficPolicy: Cluster
    Selector:  app=my-app
    SelectorPods:  Pod/my-app-abc123
    Endpoints: 2 ready, 0 not-ready, 0 terminating, 2 serving

    EndpointSlice/my-app-abc12 (IPv4)
      Port: http 8080/TCP
      10.244.0.5 [ready serving] -> Pod/my-app-abc123
      10.244.0.6 [ready serving] -> Pod/my-app-def456

    Route/my-app-route -> Service/my-app
      Host: my-app.example.com
      TLS:  edge
```

#### Network Policy Posture

The `network` subcommand also evaluates the NetworkPolicy posture of each Pod in the dependency tree. For every Pod, it determines:

- **Ingress isolation**: "isolated" if any applicable NetworkPolicy includes "Ingress" in its policyTypes; "non-isolated" otherwise.
- **Egress isolation**: "isolated" if any applicable NetworkPolicy includes "Egress" in its policyTypes; "non-isolated" otherwise.
- **Applicable policies**: NetworkPolicies whose `spec.podSelector` matches the Pod's labels.

**policyTypes defaults** (per Kubernetes spec): If `policyTypes` is omitted, "Ingress" is always implied. "Egress" is implied only when egress rules are present.

**Selector evaluation**: `matchLabels` requires all key-value pairs to match. `matchExpressions` supports `In`, `NotIn`, `Exists`, and `DoesNotExist` operators. An empty podSelector (`{}`) selects all pods in the namespace.

**Caveat**: oc-deps shows which policies apply and their rules, but does not compute whether a specific connection is allowed or denied. Multiple policies are additive -- a Pod's allowed traffic is the union of all applicable policy rules.

```
  Pod/app-xxx
    Ingress: isolated
    Egress: non-isolated
    NetworkPolicy/default-deny
      Types: Ingress
      Effect: isolates ingress
      (no ingress allow rules -> deny all ingress)
    NetworkPolicy/allow-web
      Types: Ingress
      Effect: isolates ingress
      Selector: app=web
      Allows ingress: from: namespaceSelector{team in (frontend,mobile)} podSelector{role notin (blocked)} ports: TCP/8080, TCP/http-alt
```

**JSON `networkPolicyPostures[]`:**
Each entry: `podName`, `podUid`, `ingressIsolation`, `egressIsolation`, `applicablePolicies[]`. Each policy: `name`, `podSelector` (with `matchLabels` and `matchExpressions`), `policyTypes`, `isolatesIngress`, `isolatesEgress`, `ingressRules[]`, `egressRules[]`. Ports preserve type: numeric as JSON number, named as string.

**API failure**: If NetworkPolicy LIST fails (403/500/timeout), isolation is shown as "unknown" and partial Service/EndpointSlice results are preserved. `--strict` exits 2 after output. Warnings are typed ScanWarning objects in JSON.

### Cluster-Wide Map (`map -A`)

Scan all namespaces (or a filtered subset) and display dependency trees grouped by namespace. Discovery cache is shared across all namespaces. Namespace scan concurrency is bounded (max 5 parallel) to prevent connection exhaustion.

```bash
# All namespaces
oc-deps map -A

# Filter by namespace label (AND)
oc-deps map -A --namespace-selector env=prod --namespace-selector team=platform

# Exclude patterns and system namespaces
oc-deps map -A --exclude-system-namespaces --exclude-namespace "temp-*"

# JSON output with scope metadata
oc-deps map -A -o json --exclude-system-namespaces

# Partial failures: 403/timeout namespaces shown as incomplete
oc-deps map -A --strict  # outputs results, then exit 2 if any namespace failed
```

**Identity:** Resources use `group/kind/namespace/name` — no cross-namespace name-match edges. Each namespace is scanned independently.

**JSON schema (cluster-wide):** `{"scope", "totalNamespaces", "completeNamespaceCount", "incompleteNamespaceCount", "totalResources", "totalTrees", "namespaces": [{namespace, totalResources, totalTrees, matchedTrees, trees[], warnings?}], "incompleteNamespaces?": [{namespace, error?, warnings?}], "namespaceSelectors?", "excludeNamespaces?", "excludeSystemNamespaces?"}`. Count fields use `*Count` suffix; `incompleteNamespaces` is an array of namespace objects with typed ScanWarning details.

**Progress:** Per-namespace progress on stderr (`[current/total] namespace — resources, elapsed`). Non-TTY output uses plain line-per-namespace format.

### `--show pod-resources` — Container Resource Display

Shows container names, resource requests, and limits for workload resources. Supports all resource keys including `cpu`, `memory`, `nvidia.com/gpu`, `ephemeral-storage`, `hugepages-*`, and any extended resources. Format: `name: key=request/limit` (dash `-` for unset values). initContainers are prefixed with `init:`. Resources without requests/limits show `<no resources>`.

```bash
# Tree output
oc-deps tree deployment/myapp -n mynamespace --show pod-resources

# Table output — adds a Containers column
oc-deps tree deployment/myapp -n mynamespace --show pod-resources -o table

# JSON output — adds podTemplate field with full requests/limits
oc-deps tree deployment/myapp -n mynamespace --show pod-resources -o json

# Parent chain only (fast, no namespace scan)
oc-deps tree pod/myapp-abc123 -n mynamespace --direction parents --show pod-resources

# Map mode with spec
oc-deps map -n mynamespace --show pod-resources -o table

# Combine with labels
oc-deps tree deployment/myapp -n mynamespace --show pod-resources --show labels
```

### `tree --direction parents` Spec-Level References

With `--direction parents`, oc-deps extracts spec-level references (Secret, ConfigMap, ServiceAccount, PVC) from each parent's GET response — no namespace scan or additional API calls. References are **typed** (from well-known fields like `spec.volumes[].secret.secretName`). Use `--no-refs` to suppress.

```bash
# Show parent chain with spec refs (typed source + field path shown)
oc-deps tree deployment/myapp -n mynamespace --direction parents

# Table output — Source and Field Path columns added when refs present
oc-deps tree deployment/myapp -n mynamespace --direction parents -o table

# JSON output — specRefs array per chain entry with kind/name/fieldPath/source
oc-deps tree deployment/myapp -n mynamespace --direction parents -o json

# Suppress refs
oc-deps tree deployment/myapp -n mynamespace --direction parents --no-refs

# Combine with show options
oc-deps tree deployment/myapp -n mynamespace --direction parents --show pod-resources --show labels
```

**Ref dedup:** Same Secret/ConfigMap referenced from multiple field paths (e.g., volume and envFrom) produces distinct entries per field path. Only exact (kind, name, fieldPath, source) duplicates are removed. `serviceAccount` and `serviceAccountName` are canonicalized to `serviceAccountName`. Output is sorted by kind → name → fieldPath for stable ordering.

**JSON `specRefs` format:** Each chain entry may include `specRefs`, an array of `{"kind", "name", "fieldPath", "source"}`. `source` is `"typed"` (from well-known field paths) or `"heuristic"` (from name matching in full scan mode). Omitted when empty. In `--up-only` mode, only typed refs are produced (no heuristic name matching).

Each subcommand defines its own options — no root-level flags exist. Options are always placed after the subcommand name.

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
oc-deps operators             # tree view
oc-deps operators -o table    # table view
oc-deps operators -o json     # JSON output
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
oc-deps trace datasciencecluster/default-dsc -n redhat-ods-applications --scope related  # discover across namespaces
oc-deps trace deployment/dashboard-operator -n redhat-ods-applications
oc-deps trace deployment/<name> -n <ns> -o json
oc-deps trace deployment/<name> -n <ns> -o table
oc-deps trace deployment/<name> -n <ns> --scope related --strict
```

Each category shows Relationship and Confidence:
- **ownerRef descendants** — `ownerRef`, Managed (High), confirmed by UID match
- **spec references** — `spec-ref`, Attributed (Medium), detected from spec field paths
- **Same Operator CRDs** — `same-operator-crd`, Inferred (Low), correlation only, not causation
- **label matches** — `label-match`, Inferred (Low), correlation only

The managing operator is determined via `who-manages` (ownerRef chain → CSV), not CRD origin. This prevents misattribution for built-in kinds like Deployment.

`--scope related` uses the same evidence-based namespace discovery as `inspect`. `--strict` exits with code 2 when any discovery or scan fails, after outputting partial results. In JSON, `warnings` contains all failure messages, `scanWarningCount` gives the count, and `descendants` contains the full ownerRef tree with `group/kind/namespace/name` identity.

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
# Single namespace
oc-deps snapshot -n <namespace> -o snapshot.json

# Cluster-wide (schema v3 with scope metadata)
oc-deps snapshot -A -o cluster-snapshot.json
oc-deps snapshot -A --namespace-selector env=prod -o filtered.json
oc-deps snapshot -A --exclude-system-namespaces --exclude-namespace "temp-*" -o clean.json
oc-deps snapshot -A --strict -o snap.json  # save then exit 2 on warnings

oc-deps graph -n <namespace> -o evidence-graph.json
```

**Cluster-wide snapshot:** Scans all namespaces (or filtered subset) with bounded concurrency (shared global API semaphore, max 50 concurrent LIST requests). Schema v3 adds `scope` with mode (`single-namespace`/`all-namespaces`/`filtered`), requested filters, complete/incomplete namespace lists with typed ScanWarning. Atomic save (temp file + rename) prevents corruption on Ctrl-C (exit 130). Secret values stored as SHA-256 hashes.

**Diff scope comparison:** When comparing snapshots with different scopes (mode, filters, namespaces), diff adds scope warnings. v2 vs v3 snapshots accepted with "scope comparison unavailable" warning. Resource diff proceeds regardless.

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

The API discovery cache is valid for 30 minutes. Use `--refresh-discovery` (or `--no-cache` on
teardown/snapshot/graph subcommands) after changing CRDs or APIService registrations when the
command must observe those changes immediately.

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
