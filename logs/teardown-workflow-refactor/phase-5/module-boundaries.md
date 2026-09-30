# Phase 5 Module Boundaries

## Before (f7826cd)
- `main.rs` (50 LOC) — entry point + targeted re-exports for workflow.rs
- `commands/mod.rs` (316 LOC) — dispatch
- `commands/teardown.rs` (4576 LOC) — mixed: ApplySet, batch, journal helpers, resume, provenance, network tests, dead code
- Core modules (workflow.rs, ref_guard.rs) depended on commands layer via crate:: root re-exports

## After
| Module | LOC | Responsibility |
|--------|-----|---------------|
| `main.rs` | 42 | Entry point only, zero re-exports |
| `commands/mod.rs` | 316 | Client init + validation + dispatch |
| `commands/teardown.rs` | 2390 | ApplySet config, batch, print_run_journal, handle_teardown |
| `commands/network.rs` | 1638 | Network formatters, print_network_tree, handle_network, tests |
| `commands/map.rs` | 1043 | Namespace filters, cluster-wide map, handle_map, tests |
| `commands/snapshot.rs` | 442 | Snapshot audit/diff/create handlers |
| `commands/tree.rs` | 238 | Tree display helpers, handle_tree |
| `commands/operator.rs` | 191 | Operator resources/list/owner handlers |
| `commands/trace.rs` | 333 | Trace handler |
| `commands/graph.rs` | 50 | Evidence graph handler |
| `commands/backup.rs` | 158 | Backup handler |

## Dependency direction fix (P0-1)
Core modules no longer depend on commands layer:
- `teardown::plan` ← `DeleteResourceSpec`
- `teardown::planner` ← plan construction helpers
- `teardown::journal` ← audit scope, journal creation, identity snapshot
- `teardown::workflow` ← resume classification, explicit cleanup mode

`workflow.rs` and `ref_guard.rs` now import from `super::plan::`, `super::planner::`, `journal::` — no `crate::` root bridge.

## Dead code removed (P1-2)
33 tests and their production fossils removed. Zero `#[allow(dead_code)]` in commands/.
