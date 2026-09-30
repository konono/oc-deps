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
    /// Resume from a persisted RunJournal (locked).
    Resume {
        store: Arc<JournalStore>,
    },
}

/// Options that control workflow behavior.
pub struct ApplyOptions {
    /// Skip interactive confirmation (--yes / -y).
    pub auto_approve: bool,
    /// Dry-run mode: no mutations, no journal, no backup.
    pub dry_run: bool,
    /// Backup directory. None = no backup. Some = mandatory backup gate.
    pub backup_dir: Option<PathBuf>,
    /// Force refresh API discovery cache.
    pub refresh_discovery: bool,
}

/// Outcome of a single workflow execution.
pub struct ApplyOutcome {
    /// Terminal RunState (ApplyCompleted, Failed, Paused, Finished).
    pub final_state: RunState,
    /// Execution summary (phases completed, deleted, failed, etc).
    pub execution_result: ExecutionResult,
    /// Backup receipts created (empty if no backup or dry-run).
    pub backup_receipts: Vec<BackupReceipt>,
    /// Post-execution audit result (None if not reached).
    pub audit: Option<AuditResult>,
    /// Path to the journal file (None for dry-run).
    pub journal_path: Option<PathBuf>,
}
```

## Entry Point

```rust
/// Single production entry point for all teardown mutations.
///
/// Workflow stages (all enforced by this function):
/// 1. Prepare/Load — resolve plan or load journal
/// 2. Validate authority — cluster identity, drift, UID, generation
/// 3. Backup — prepare_backup_gate (Fresh only; Resume validates existing receipts)
/// 4. Journal — create or lock
/// 5. Execute — single execute_plan call with MutationGate
/// 6. Residual Audit — post-execution completeness check
/// 7. Complete — persist final state
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
3. **Journal state transitions** — all mutations to `RunJournal.state` happen within `run_teardown_workflow` or its direct helpers.
4. **No mutation before gate** — if `backup_dir` is Some, backup must succeed before `execute_plan`.
5. **Ctrl-C/pause** — MutationGate is owned by workflow; gate closure → Paused state.
6. **ExplicitCleanupBlocked** — explicit phase ref-scan failure sets this state; resume re-enters at explicit phase.
7. **Cancellation** — MutationGate.close_and_drain() is the only cancellation mechanism.

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

No `std::process::Command` — each operator entry calls `run_teardown_workflow` directly with `ApplyStart::Fresh`. Pending explicit cleanup entries use `ApplyStart::Resume`.

## Resume Flow

1. Load journal by run_id or operator name
2. Acquire process lock (JournalStore::new_with_lock)
3. Validate: cluster identity, schema version, backup receipts, operator generation
4. Construct `ApplyStart::Resume { store }`
5. Call `run_teardown_workflow` — which determines start_phase from journal

## Dry-Run

- `options.dry_run = true`
- No journal created, no backup, execute_plan runs with `dry_run=true`
- Returns `ApplyOutcome` with `journal_path = None`

## State Diagram

```
Fresh ──→ [Validate] ──→ [Backup] ──→ [Journal:Applying]
                                              │
Resume ──→ [Validate] ──→ [Receipt check] ────┘
                                              │
                                              v
                                       [execute_plan]
                                        │         │
                                   gate open   gate closed
                                        │         │
                                        v         v
                              [determine state] [Paused]
                                        │
                           ┌────────────┤
                           v            v
                    [ApplyCompleted] [Failed]
                           │
                           v
                    [Residual Audit]
                           │
                    ┌──────┤
                    v      v
              [Finished] [ExplicitCleanupBlocked]
```
