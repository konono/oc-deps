# Proposed `run_teardown_workflow` API — Phase 3 Target

## Module Ownership

```
src/teardown/workflow.rs    — single mutation entry point
src/teardown/config.rs      — ApplyOptions, BatchConfig
```

## Core Types

```rust
/// How the workflow starts — distinguishes fresh apply from resume.
pub enum ApplyStart {
    /// Fresh execution from a saved ExecutionPlan file.
    Fresh {
        plan: ExecutionPlan,
        plan_path: PathBuf,
    },
    /// Resume from a locked, validated RunJournal.
    /// The caller must have already:
    ///   1. Acquired process lock (JournalStore::new_with_lock)
    ///   2. Validated cluster identity against authoritative journal
    ///   3. Validated schema version
    ///   4. Validated backup receipts against cluster identity
    ///   5. Checked operator generation (SameGeneration or Absent)
    ///   6. Performed legacy Failed → ExplicitCleanupBlocked migration if eligible
    Resume {
        store: Arc<JournalStore>,
        /// Typed resume context — preserves the validation decisions
        /// made during pre-resume checks.
        mode: ResumeMode,
    },
}

/// Resume modes — typed so the workflow enforces correct boundaries.
pub enum ResumeMode {
    /// Normal resume from Paused, Applying, or ApplyCompleted.
    /// Continues from journal's phases_completed.
    Normal {
        start_phase: usize,
    },
    /// Resume from ExplicitCleanupBlocked (typed or legacy-migrated).
    /// Re-enters at the explicit cleanup phase with fresh reference guard.
    ExplicitCleanup,
}

/// Options that control workflow behavior.
pub struct ApplyOptions {
    /// Skip interactive confirmation (--yes / -y).
    pub auto_approve: bool,
    /// Dry-run mode: execute_plan runs with dry_run=true (no mutations).
    /// Journal is NOT created in dry-run. Backup IS published if backup_dir
    /// is Some — the accepted contract allows `--dry-run --backup-dir` to
    /// capture a read-only backup with zero DELETEs.
    pub dry_run: bool,
    /// Backup directory. None = no backup. Some = mandatory backup gate
    /// before execute_plan (both in normal and dry-run modes).
    pub backup_dir: Option<PathBuf>,
    /// Force refresh API discovery cache.
    pub refresh_discovery: bool,
}

/// Outcome of a single workflow execution.
pub struct ApplyOutcome {
    /// Terminal RunState (ApplyCompleted, Failed, Paused, Finished,
    /// ExplicitCleanupBlocked).
    pub final_state: RunState,
    /// Execution summary (phases completed, deleted, failed, etc).
    pub execution_result: ExecutionResult,
    /// Backup receipts created (empty if no backup_dir).
    pub backup_receipts: Vec<BackupReceipt>,
    /// Post-execution audit result (None if not reached).
    pub audit: Option<AuditResult>,
    /// Residual cleanup result (None if not reached).
    pub residual_cleanup: Option<ResidualCleanupResult>,
    /// Path to the journal file (None for dry-run).
    pub journal_path: Option<PathBuf>,
}
```

## Entry Point

```rust
/// Single production entry point for all teardown mutations.
///
/// Workflow stages (all enforced by this function):
///
/// 1. Prepare/Load — resolve plan or load journal
/// 2. Validate authority — cluster identity, drift, UID, generation
/// 3. Backup — prepare_backup_gate (Fresh: always when backup_dir is Some,
///    including dry-run; Resume: validate existing receipts)
/// 4. Journal — create (Fresh, non-dry-run only) or use locked store (Resume)
/// 5. Execute — single execute_plan call with MutationGate
///    - ExplicitCleanupBlocked may be set INSIDE execute_plan if the
///      pre-DELETE explicit reference guard fails (executor.rs:739)
/// 6. Determine final state — gate.is_open() + result → Paused / ApplyCompleted / Failed
/// 7. Residual Audit — post-execution completeness check (only if ApplyCompleted
///    and operator generation is Absent)
/// 8. Residual Cleanup — execute_residual_cleanup for unfinished items
///    (only if audit finds actionable residuals and operator is Absent)
/// 9. Complete — persist Finished (or remain in current state)
pub async fn run_teardown_workflow(
    start: ApplyStart,
    client: &kube::Client,
    config: &kube::Config,
    options: &ApplyOptions,
) -> Result<ApplyOutcome>;
```

## Invariants

1. **Single `execute_plan` call site** — only `run_teardown_workflow` calls `execute_plan`.
2. **Single `prepare_backup_gate` call site** — only `run_teardown_workflow` calls it (Fresh path).
3. **Single `execute_residual_cleanup` call site** — only `run_teardown_workflow` calls it (stage 8).
   Currently TUI has its own call site; Phase 2 removes TUI, so this converges naturally.
4. **Journal state transitions** — all mutations to `RunJournal.state` happen within
   `run_teardown_workflow` or within `execute_plan` (for ExplicitCleanupBlocked only).
5. **No mutation before gate** — if `backup_dir` is Some, backup must succeed before `execute_plan`
   (both normal and dry-run modes).
6. **Ctrl-C/pause** — MutationGate is owned by workflow; gate closure → Paused state.
7. **ExplicitCleanupBlocked** — set INSIDE execute_plan during the explicit phase's
   pre-DELETE reference guard scan (executor.rs:739). This is NOT after residual audit.
   Resume re-enters at the explicit phase with fresh reference guard.
8. **Cancellation** — MutationGate.close_and_drain() is the only cancellation mechanism.
9. **Failed is non-resumable** — generic Failed state cannot be resumed. Only a structurally
   eligible legacy Failed journal (v12, explicit phases completed, explicit_cleanup_error absent,
   operator absent) may migrate to ExplicitCleanupBlocked after cluster identity + receipt
   validation. This migration happens in the Resume caller before constructing ApplyStart::Resume.

## Mutation Path Elimination

Current production has these mutation entry points that Phase 2/3 must consolidate:

| Current path | Mutations | Phase 2/3 disposition |
|---|---|---|
| main.rs headless `execute_plan` | DELETE/PATCH via executor | → `run_teardown_workflow` stage 5 |
| main.rs script-mode `execute_plan` | DELETE/PATCH via executor | Phase 2 removes script mode |
| tui/mod.rs `execute_plan_with_store` | DELETE/PATCH via executor | Phase 2 removes TUI |
| main.rs `execute_residual_cleanup` (×4 sites) | DELETE for residual items | → `run_teardown_workflow` stage 8 |
| tui/mod.rs `execute_residual_cleanup` | DELETE for residual items | Phase 2 removes TUI |
| tui/mod.rs `execute_residual_cleanup_with_progress` | DELETE with TUI progress | Phase 2 removes TUI |
| executor.rs internal journal mutations | ExplicitCleanupBlocked | Stays inside executor (stage 5) |

After Phase 3, the only production mutation callers are `run_teardown_workflow` (stages 5+8).

## Batch Integration (Phase 4)

```rust
/// Thin orchestrator — calls run_teardown_workflow per entry.
pub async fn run_batch(
    config: &BatchConfig,
    client: &kube::Client,
    kube_config: &kube::Config,
    options: &ApplyOptions,
) -> Result<BatchOutcome>;
```

No `std::process::Command` — each operator entry calls `run_teardown_workflow` directly
with `ApplyStart::Fresh`. Pending explicit cleanup entries use `ApplyStart::Resume` with
`ResumeMode::ExplicitCleanup` after the batch orchestrator performs the pre-resume
validation sequence (lock, cluster identity, receipts, generation, legacy migration).

## Resume Flow

Pre-resume validation (done by caller, NOT by `run_teardown_workflow`):

1. Load journal by run_id or operator name
2. Pre-lock state check — reject Finished, reject non-eligible Failed
3. Acquire process lock (JournalStore::new_with_lock)
4. Re-read authoritative state after lock
5. Schema version gate (must match RUN_JOURNAL_SCHEMA_VERSION)
6. Re-verify cluster identity with authoritative journal
7. Validate backup receipts against cluster identity
8. Legacy Failed migration: if structurally eligible (v12 + explicit phases completed +
   no explicit_cleanup_error + operator Absent), migrate to ExplicitCleanupBlocked
9. Check operator generation (SameGeneration for normal, Absent for explicit cleanup)
10. Reconcile completed phases via live GET (journal = hint, live GET = truth)
11. Construct `ApplyStart::Resume { store, mode }` and call `run_teardown_workflow`

## Dry-Run

- `options.dry_run = true`
- Journal is NOT created
- Backup IS published if `backup_dir` is Some (accepted contract: `--dry-run --backup-dir`
  captures read-only backup with zero DELETEs)
- `execute_plan` runs with `dry_run=true` — no DELETE/PATCH/POST mutations
- Returns `ApplyOutcome` with `journal_path = None`

## Residual Cleanup

Residual cleanup is a **stage** within the workflow (stage 8), not a separate workflow
start mode. It runs only when:
- Stage 6 determined ApplyCompleted
- Stage 7 audit found the operator generation is Absent
- Actionable residual items exist (incomplete cleanup, finalizer recovery)

Its mutations (execute_residual_cleanup) go through the same MutationGate and journal.
The workflow owns this path — after Phase 2/3, no separate TUI or script residual
cleanup exists.

## State Diagram

```
Fresh ──→ [Validate] ──→ [Backup†] ──→ [Journal:Applying‡]
                                               │
Resume ──→ [Pre-validated] ──→ [Receipt check] ┘
                                               │
                                               v
                                        [execute_plan]
                                         │    │    │
                                    gate  │ gate  explicit
                                    open  │ closed ref-guard
                                         │    │    fail
                                         v    v    v
                              [determine   [Paused] [ExplicitCleanup
                                state]               Blocked]
                                  │
                     ┌────────────┤
                     v            v
              [ApplyCompleted] [Failed*]
                     │
                     v
              [Residual Audit]
                     │
              ┌──────┤
              v      v
        [Residual  [Finished]
         Cleanup]
              │
              v
        [Finished]

† Backup runs for both normal and dry-run when backup_dir is Some
‡ Journal not created in dry-run
* Failed is terminal and non-resumable (except structurally eligible
  legacy journals that migrate to ExplicitCleanupBlocked before resume)
```
