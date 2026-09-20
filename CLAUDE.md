# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

`oc-deps` is a Rust CLI tool that discovers and displays Kubernetes resource dependency chains. Given a resource, it walks both up (ownerReferences) and down (reverse ownerReference lookup via namespace-wide scan) to show the full parent-child hierarchy. Works with ANY resource type including CRDs and Operator-managed resources.

## Commands

```bash
# Build
cargo build
cargo build --release

# Run (requires active kubeconfig)
cargo run -- pod/<pod-name> -n <namespace>
cargo run -- -k Deployment <name> -n <namespace>
cargo run -- --up-only pod/<pod-name>          # fast parent chain only
cargo run -- --map -n <namespace>              # all dependency trees in namespace
cargo run -- -o json deployment/<name>         # JSON output
cargo run -- -o table deployment/<name>        # table output

# Lint and format
cargo clippy
cargo fmt
```

## Architecture

All logic lives in a single file: `src/main.rs`.

**Core design: Namespace-wide scan + reverse ownerReference index**
- Scans all namespaced resource types in the target namespace (concurrency 50)
- Builds a reverse ownerRef index: `parent_uid → [child_uid]`
- Tree traversal is pure HashMap lookups (no async recursion, no BoxFuture)
- Cluster-scoped parents are fetched individually via targeted API calls
- API discovery results cached for 5 minutes (`/tmp/oc-deps-cache/`)

**Key data structures:**
- `KindInfo` — metadata about a Kubernetes resource type
- `KindMap` / `GvrMap` — Kind name and GVR notation lookups
- `NamespaceIndex` — the core index: `by_uid`, `children_of`, `by_kind_name`
- `TreeNode` — recursive tree structure for display

**Key functions:**
- `build_kind_lookup_cached()` — API discovery with filesystem cache (5min TTL)
- `scan_namespace()` — parallel namespace-wide resource scan → NamespaceIndex
- `resolve_missing_parents()` — fetches cluster-scoped parents not in the scan
- `build_parent_chain()` / `build_child_tree()` / `build_full_tree()` — tree construction
- `build_namespace_map()` — builds all root-to-leaf trees for --map mode
- `find_parents_only()` — fast up-only mode (targeted gets, no scan)

**Output formats:** Tree (default, `kind/name` for easy `oc get/edit` copy-paste), Table, JSON

## Kubernetes Configuration

`oc` や `kubectl` を使用する際は、リポジトリ内の `.kube/` ディレクトリの kubeconfig を使用すること。

```bash
export KUBECONFIG=.kube/config
```

## E2E Testing (teardown apply)

### Ansible の実行方法

aw コンテナでは stdout/stderr が non-blocking のため、Python ラッパー経由で実行する。
`capture_output=True` は**使わない**こと（リアルタイムログが見えなくなる）。

```bash
cd ansible
python3 -c "
import fcntl, os, sys
for fd in [sys.stdout, sys.stderr, sys.stdin]:
    flags = fcntl.fcntl(fd, fcntl.F_GETFL)
    fcntl.fcntl(fd, fcntl.F_SETFL, flags & ~os.O_NONBLOCK)
import subprocess
sys.exit(subprocess.run([
    'uv', 'run', 'ansible-playbook', 'site.yml', '-i', 'inventory/aws-sno-disconnected',
    '--tags', '<TAGS>', '-v'
]).returncode)
"
```

### Verify

```bash
cd ansible
# 同じ Python ラッパーで実行
uv run ansible-playbook playbooks/verify.yml -i inventory/aws-sno-disconnected
```

### Quick テスト（RHOAI のみ）

RHOAI operator の teardown → Ansible 復旧 → verify の1サイクル。

```bash
# 1. teardown
cargo build --release
echo "y" | ./target/release/oc-deps teardown apply rhods-operator.3.5.0 \
  --approve-delete all \
  --approve-delete maas.opendatahub.io/Config/-/default \
  --approve-delete MLflow/mlflow \
  --force --strip-finalizers --no-cache

# 2. ログ検証（自動化する場合）
#   - EXPECT に RE-DELETE が 0 件であること
#   - 未承認 REVIEW に DELETE/RE-DELETE が 0 件であること
#   - strip が operand のみ（CRD/CSV/Subscription に STRIPPED が出ないこと）
#   - 7/7 phases completed, 0 failed

# 3. Ansible 復旧（MLflow + OGX は別タグ）
cd ansible
# platform + workload + integration（llm は chat_template.jinja 未配置のためスキップ）
ansible-playbook site.yml -i inventory/aws-sno-disconnected --tags platform,workload,integration --skip-tags llm -v
# MLflow 単体
ansible-playbook site.yml -i inventory/aws-sno-disconnected --tags mlflow -v

# 4. verify
ansible-playbook playbooks/verify.yml -i inventory/aws-sno-disconnected
```

所要時間: teardown 約8-10分 + 復旧 約10-15分 = 1サイクル約20-25分

### Full テスト（全 operator 削除）

Ansible デプロイ前の状態に戻ることを検証する。RHOAI → Keycloak → 依存 operator の順で削除。

```bash
cargo build --release
OC_DEPS=./target/release/oc-deps

# Step 1: RHOAI
echo "y" | $OC_DEPS teardown apply rhods-operator.3.5.0 \
  --approve-delete all \
  --approve-delete maas.opendatahub.io/Config/-/default \
  --approve-delete MLflow/mlflow \
  --force --strip-finalizers --no-cache

# Step 2: Keycloak
echo "y" | $OC_DEPS teardown apply rhbk-operator \
  --approve-delete all --force --strip-finalizers --no-cache

# Step 3: 依存 operator（順序は問わない）
for op in leader-worker-set job-set kueue-operator servicemeshoperator3 \
          nfd gpu-operator-certified cert-manager-operator \
          rhcl-operator authorino-operator dns-operator limitador-operator \
          cluster-observability-operator opentelemetry-product; do
  echo "--- $op ---"
  echo "y" | $OC_DEPS teardown apply "$op" \
    --approve-delete all --force --strip-finalizers --no-cache
done

# Step 4: 残留リソース確認
oc get subscriptions.operators.coreos.com -A --no-headers  # group-sync-operator のみ期待
oc get pods -A --no-headers | grep -v "^openshift-\|^kube-\|Completed\|^default " | grep Running
```

所要時間: 約30-40分

### 残留リソースの既知事項 (Issue #4)

Full テスト後に残るリソース:
- **keycloak/postgres**: Ansible 直接作成の StatefulSet（ownerRef なし）→ scope 外
- **redhat-ods-applications の maas-postgres, nemo-guardrails, ogx-server**: REVIEW label-only の workload
- **NooBaa CR**: ODF 依存 operator (mcg-operator) の operand
- **Namespaces**: 設計通り KEEP
- **CRDs**: `--prune-apis` 未指定時は KEEP

### 復旧時の注意

- keycloak の postgres を削除した後に復旧すると、Keycloak admin token 取得で `Invalid user credentials` エラーになる。PVC も一緒に削除してから Ansible を再実行すること。
- OGX の postgres/PVC を削除した後は `--tags ogx` で再デプロイが必要。

## Dependencies

- `kube` 0.84 with k8s-openapi `v1_26` — Kubernetes client and API types
- `clap` 4.1 — CLI argument parsing
- `tokio` 1.28 (full) — async runtime
- `comfy-table` 6.0 — table formatting
- `anyhow` — error handling
- `futures` 0.3 — stream utilities for parallel scan
- `serde_json` 1.0 — JSON output and discovery cache
