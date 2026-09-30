# Phase 1 — Production Call-Site Inventory

Base commit: ad93e09 (PR #50 merge)

## 1. `execute_plan` call sites

| Call Site | file:line | Enclosing Context | Callers/Notes |
|---|---|---|---|
| Definition (import) | src/main.rs:80 | top-level `use` | `use crate::teardown::executor::{execute_plan, print_execution_result}` |
| Script-mode call | src/main.rs:2768 | `TeardownAction::Apply` → script-mode branch (`let mut app = AppState::new(...)`) | Called inside `AppCommand::Approve` handler within script JSON loop |
| Headless (normal + TUI) call | src/main.rs:3178 | `TeardownAction::Apply` → non-TUI / headless branch | Main production apply path; preceded by backup gate, journal creation |
| Resume call | src/main.rs:5102 | `TeardownAction::Resume` | Resume path; preceded by journal reload, authority validation, drift check, backup receipt validation |

**Total production call sites: 3** (script, headless apply, resume)

## 2. `prepare_backup_gate` call sites

| Call Site | file:line | Enclosing Context | Callers/Notes |
|---|---|---|---|
| Script-mode call | src/main.rs:2716 | `TeardownAction::Apply` → script-mode branch | Before script-mode execute_plan; requires CommandContext |
| Headless apply call | src/main.rs:3110 | `TeardownAction::Apply` → non-TUI / headless branch | Before headless execute_plan; same CommandContext construction |

**Total production call sites: 2** (script, headless apply)

**Note:** Resume path does NOT call `prepare_backup_gate` — it validates existing receipt instead.

## 3. Journal state mutation sites

| Mutation | file:line | Enclosing Context | State Transition |
|---|---|---|---|
| `create_run_journal` | src/main.rs:8606 (fn def), called at :2416 (TUI), :2735 (script) | `TeardownAction::Apply` | Creates new journal with initial state |
| `journal::fetch_cluster_identity` | src/main.rs:2112, 2158, 2428, 2754 | Apply + Resume paths | Records cluster identity for drift detection |
| `RunState::Paused` persist | src/main.rs:2788 | Script-mode Apply | Ctrl-C / gate close → Paused |
| `RunState::ApplyCompleted` persist | src/main.rs:2793 | Script-mode Apply | All phases done successfully |
| `RunState::Failed` persist | src/main.rs:2795, 2807, 2831 | Script-mode Apply | Execution failure; `mark_failed_preserving_retryable` |
| Residual audit persist | src/main.rs:2859–2919 | Script-mode Apply | `run_post_mutation_audit` → `residual_status_from_audit` → journal update |
| `RunState::Finished` persist | src/main.rs:3062 | Script-mode Apply | Residual cleanup complete |
| Headless journal state persist | src/main.rs:3178–3330 (range) | Headless Apply | Same transitions: ApplyCompleted/Failed/Paused, residual audit |
| Resume `Applying` persist | src/main.rs:5096–5102 | Resume | Clears explicit_cleanup_error, sets Applying |
| Resume post-exec state persist | src/main.rs:5120–5200 (range) | Resume | ApplyCompleted/Failed, residual audit |
| `ExplicitCleanupBlocked` detection | src/main.rs:1026–1211 | `classify_explicit_cleanup_resume` fn | Read-only classification, not mutation; but drives resume decision |

## 4. Post-execution audit call sites

| Call Site | file:line | Enclosing Context | Callers/Notes |
|---|---|---|---|
| Script-mode post-mutation | src/main.rs:2859 | `TeardownAction::Apply` script branch | `run_post_mutation_audit` after execute_plan completes |
| Headless post-mutation | src/main.rs:3246 | `TeardownAction::Apply` headless branch | `run_post_mutation_audit` after execute_plan completes |
| Resume post-mutation | src/main.rs:5025 | `TeardownAction::Resume` | `run_post_mutation_audit` after resume execute_plan |
| Resume explicit-cleanup post | src/main.rs:5172 | `TeardownAction::Resume` | After explicit cleanup mutations |
| Observed audit (status) | src/main.rs:4458, 4656, 4847, 5638–5656 | Status/Runs/Journal commands | `run_observed_audit` — read-only, no mutation |
| Journal residual audit check | src/main.rs:3432, 3852, 4237 | Various Apply/Resume paths | `residual_status_from_audit` on existing journal data |

**Mutation-path audit sites: 4** (script, headless, resume, resume-explicit-cleanup)

## 5. Self-spawning `std::process::Command` sites

| Call Site | file:line | Enclosing Context | Command Built |
|---|---|---|---|
| Batch resume child | src/main.rs:5410 | `TeardownAction::Batch` | `oc-deps teardown resume --run <RUN_ID>` — for entries that already have a pending journal |
| Batch plan child | src/main.rs:5460 | `TeardownAction::Batch` | `oc-deps teardown plan <OPERATOR> --file <plan_path>` |
| Batch apply child | src/main.rs:5513 | `TeardownAction::Batch` | `oc-deps teardown apply <plan_path> [-y] [--dry-run] [--backup-dir] [--non-interactive]` |

**Total self-spawn sites: 3** — all in batch. Phase 4 target: replace with direct Rust API calls.

## 6. TUI-only safety logic and references

| Reference | file:line | Type | Notes |
|---|---|---|---|
| `mod tui` | src/main.rs:35 | Module declaration | Entire TUI module |
| `crate::tui::run_tui` | src/main.rs:2448 | TUI entry point | Full interactive Plan Review → Execution → Residual screen |
| `crate::tui::run_residual_only` | src/main.rs:5083 | TUI residual screen | Resume-path residual re-entry into TUI |
| `crate::tui::check_and_persist_paused` | src/tui/mod.rs:1171 | Safety function | Checks MutationGate + persists Paused state — **non-UI safety logic to preserve** |
| `AppState::new` | src/main.rs:2472 | Script-mode state machine | Script mode reuses TUI's AppState for JSON command driving |
| `AppStateSnapshot` | src/main.rs:2493 | Script-mode state readback | Script mode snapshot of AppState |
| `apply_command` | src/main.rs:2470 | Script-mode command dispatch | Drives AppState transitions via JSON commands |
| `AppCommand`, `AppScreen` | src/main.rs:2470 | Script-mode types | Shared with TUI |
| `non_interactive` field | src/main.rs:114, 206, 214, 233 | CLI config | `--non-interactive` flag; propagated to batch child at :5519 |
| TUI guard (dry_run check) | src/main.rs:2406 | TUI launch guard | `if use_tui && !dry_run` — skips TUI for dry-run |
| Test: `check_and_persist_paused` | src/main.rs:10820–10849 | Test | Tests for the paused-gate safety function |

### TUI source files

| File | Description |
|---|---|
| src/tui/mod.rs | Main TUI module: `run_tui`, `run_tui_inner`, `check_and_persist_paused`, `run_residual_only` |
| src/tui/*.rs (all) | Full TUI implementation — AppState, rendering, event loop, etc. |

### Safety logic to extract before TUI removal

1. **`check_and_persist_paused`** (src/tui/mod.rs:1171) — checks if MutationGate is closed and persists Paused state to journal. Non-UI logic, must move to teardown/workflow.
2. **MutationGate / Ctrl-C signal handling** — gate closure on SIGINT, persisted as Paused. Currently wired through TUI event loop.
3. **Residual audit → screen transition guard** — checks `RunState::ApplyCompleted` before entering residual cleanup. Must survive in workflow module.
