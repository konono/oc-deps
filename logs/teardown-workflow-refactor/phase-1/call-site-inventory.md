# Production Call Site Inventory — Phase 1

Base commit: ad93e096eb05502a33281f3501eab001b834f544

## 1. execute_plan / execute_plan_with_store

**Definition:** `src/teardown/executor.rs:339` (public wrapper) → `src/teardown/executor.rs:372` (impl)

**Production call sites in main.rs:**

| Line | Context | Caller Path |
|------|---------|-------------|
| 2768 | TeardownAction::Apply (non-TUI, non-script) — fresh apply | apply with confirmation |
| 3178 | TeardownAction::Apply (TUI mode) — via app state | TUI executor |
| 5102 | TeardownAction::Resume — explicit cleanup resume | resume flow |

**Notes:**
- All 3 call sites are in `async fn main()` within `TeardownAction::Apply` and `TeardownAction::Resume` match arms
- Each has its own backup gate, journal setup, and error handling
- This is the exact duplication Issue #49 aims to eliminate

## 2. prepare_backup_gate

**Definition:** `src/teardown/backup.rs:1903`

**Production call sites in main.rs:**

| Line | Context |
|------|---------|
| 2716 | TeardownAction::Apply (non-TUI, non-script) — fresh apply backup |
| 3110 | TeardownAction::Apply (TUI mode) — TUI backup |

**Notes:**
- Resume path does NOT call prepare_backup_gate (receipts validated from journal)
- Batch delegates to child process which calls prepare_backup_gate via apply
- Only 2 production call sites, but should be 1 in the unified workflow

## 3. journal state mutations (store.update)

**Production call sites in main.rs (non-test):**

26 `store.update(|j| { ... })` calls spanning lines 2800-5212:

| Lines | State Transition | Context |
|-------|-----------------|---------|
| 2800 | → Applying, set phases_total | apply start |
| 2830 | mark_failed_preserving_retryable | apply error handler |
| 2914 | set last_residual_audit | post-execution audit |
| 3058 | → Applying | TUI apply start |
| 3211 | → InteractiveCleanup/Finished | TUI post-audit |
| 3299 | set last_residual_audit | TUI audit store |
| 3612 | mark_failed_preserving_retryable | TUI error handler |
| 3948 | → ExplicitCleanupBlocked (legacy migration) | resume legacy upgrade |
| 4252 | → Paused | resume pause |
| 4265 | → InteractiveCleanup | resume cleanup start |
| 4335 | set cleanup_decisions | residual cleanup decision |
| 4371 | → Finished | cleanup complete |
| 4408 | finalizer_recovery | finalizer strip |
| 4529-4567 | cleanup decision results | cleanup execution results |
| 4703 | set last_residual_audit | re-audit after cleanup |
| 4787 | → Finished | re-audit complete |
| 4914 | → AuditingResiduals | resume audit start |
| 4972 | set last_residual_audit | resume audit store |
| 5032 | set last_residual_audit | explicit resume re-audit |
| 5067 | → Applying | explicit resume start |
| 5095 | clear explicit_cleanup_error | explicit resume clear error |
| 5134 | set last_residual_audit | explicit resume post-audit |
| 5194 | set last_residual_audit | explicit resume audit store |
| 5212 | mark_failed_preserving_retryable | explicit resume error |

**mark_failed_preserving_retryable:**
- Definition: `src/teardown/journal.rs:418`
- Production calls: main.rs:2831, 3613, 5213
- Test calls: main.rs:10743, 10747

## 4. Post-execution audit (residual audit)

**Production audit call sites in main.rs:**

| Line | Context |
|------|---------|
| 2917 | Post-execution audit after fresh apply |
| 3255 | TUI audit print |
| 3302 | TUI audit store |
| 3532 | TUI post-cleanup re-audit |
| 5030 | Explicit resume re-audit |
| 5180 | Explicit resume post-audit |

**Audit definition:** `src/teardown/audit.rs`
- `print_residual_audit` referenced at: main.rs:3255, 5030, 5180, 5677, 5712
- `format_residual_audit_json` at: main.rs:5666
- `format_residual_audit_table` at: main.rs:5672

## 5. Self-spawning std::process::Command

**All call sites in main.rs:**

| Line | Command | Purpose |
|------|---------|---------|
| 5410 | `oc-deps teardown resume --run <id>` | Batch: pending explicit cleanup resume |
| 5460 | `oc-deps teardown plan <name> [flags] --file <path>` | Batch: plan generation per operator |
| 5513 | `oc-deps teardown apply <plan> [flags]` | Batch: apply execution per operator |

**All 3 are in TeardownAction::Batch match arm.**
- Batch is the only code path that spawns child processes
- Each child inherits stdout/stderr
- apply child receives `y\n` on stdin for auto-confirmation
- KUBECONFIG env passed through
- Issue #49 requires eliminating these in Phase 4

## 6. TUI-only safety logic

**File:** `src/teardown/app.rs` (531 lines)

**Key types:**
- `AppState` (L62): TUI state machine with approval/rejection/pause
- `AppCommand` enum: Approve, Reject, Pause, Resume, etc.
- `validate_command` (L87): command validation against current state
- `apply_command` (L126): state transition logic
- `AppStateSnapshot` (L179): serializable state snapshot

**TUI-related code in main.rs:**
- TeardownAction::Apply with `tui: true` starts at ~L3050
- Uses `crossterm` for terminal raw mode
- Uses `ratatui` for rendering
- Contains its own backup gate (L3110), execute_plan (L3178), and audit path
- Has Ctrl-C / pause safety logic that should move to workflow module

**Dependencies (Cargo.toml):**
- `ratatui` — TUI framework
- `crossterm` — terminal control

**Tests:** 26 tests in `src/teardown/app.rs` (all TUI state machine tests)
