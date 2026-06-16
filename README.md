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

## Build

```bash
cargo build --release
```

The binary is at `target/release/oc-deps`.

## License

MIT
