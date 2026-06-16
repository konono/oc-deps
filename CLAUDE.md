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

## Dependencies

- `kube` 0.84 with k8s-openapi `v1_26` — Kubernetes client and API types
- `clap` 4.1 — CLI argument parsing
- `tokio` 1.28 (full) — async runtime
- `comfy-table` 6.0 — table formatting
- `anyhow` — error handling
- `futures` 0.3 — stream utilities for parallel scan
- `serde_json` 1.0 — JSON output and discovery cache
