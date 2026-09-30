# Phase 5 Module Boundaries

## Before
- `main.rs` (50 LOC) → `commands::run()`
- `commands/mod.rs` (1528 LOC) — inline handlers for all commands + dispatch
- `commands/teardown.rs` (7239 LOC) — teardown + network + backup + map helpers + tests

## After
| Module | LOC | Responsibility |
|--------|-----|---------------|
| `main.rs` | 50 | Entry point |
| `commands/mod.rs` | 316 | Client init + validation + dispatch |
| `commands/teardown.rs` | 4576 | ApplySet, batch, journal, resume, provenance, handle_teardown |
| `commands/network.rs` | 1638 | Network formatters, print_network_tree, handle_network |
| `commands/map.rs` | 1043 | Namespace filters, cluster-wide map, validate_map_args, handle_map |
| `commands/snapshot.rs` | 442 | Snapshot audit/diff/create handlers |
| `commands/tree.rs` | 238 | Tree display helpers, handle_tree |
| `commands/operator.rs` | 191 | Operator resources/list/owner handlers |
| `commands/trace.rs` | 333 | Trace handler |
| `commands/graph.rs` | 50 | Evidence graph handler |
| `commands/backup.rs` | 158 | Backup handler |

## Key decisions
- `#[allow(clippy::too_many_arguments)]` on handler functions — CLI dispatch pattern, args come directly from clap destructuring
- `build_residual_evidence` kept with `#[allow(dead_code)]` — was dead in original, likely future use
- Network-related tests in `basis_drift_tests` kept in teardown.rs with cross-module import rather than splitting the test module
- `filter_namespaces` and `MAX_NAMESPACE_CONCURRENCY` placed in map.rs, referenced by snapshot.rs via `super::map::`
