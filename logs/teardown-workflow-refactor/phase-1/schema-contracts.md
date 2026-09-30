# Schema Contracts — Phase 1 Freeze

Base commit: ad93e096eb05502a33281f3501eab001b834f544

## 1. RunJournal Schema (v12)

File: `src/teardown/journal.rs:21-66`

```
RUN_JOURNAL_SCHEMA_VERSION = 12

RunJournal {
    run_id: String,
    schema_version: u32,
    oc_deps_version: String,
    journal_revision: u64,
    cluster_identity: ClusterIdentity,
    operator: OperatorIdentitySnapshot,
    created_at: String,
    updated_at: String,
    state: RunState,
    residual_status: ResidualStatus,
    audit_revision: u64,
    audit_context: AuditContext,
    plan_snapshot: TeardownPlan,
    execution: ExecutionRecord,
    last_residual_audit: Option<ResidualAudit>,       // serde(default, skip_serializing_if)
    cleanup_decisions: Vec<CleanupDecision>,            // serde(default)
    finalizer_recovery_approved: bool,                  // NO serde(default) — v9 required
    finalizer_recoveries: Vec<FinalizerRecoveryRecord>, // NO serde(default) — v9 required
    backup_receipts: Vec<BackupReceipt>,                // serde(default, skip_serializing_if)
}
```

### RunState (journal.rs:252-263)
```
enum RunState {
    Prepared,
    Applying,
    ApplyCompleted,
    AuditingResiduals,
    InteractiveCleanup,
    ExplicitCleanupBlocked,
    Paused,
    Finished,
    Failed,
}
```

### State Transitions (production paths)
```
Prepared → Applying                         (execute_plan start)
Applying → ApplyCompleted                   (all phases complete)
Applying → ExplicitCleanupBlocked           (explicit cleanup guard failure)
Applying → Failed                           (non-retryable error, if not already ExplicitCleanupBlocked)
ApplyCompleted → AuditingResiduals          (post-execution audit)
AuditingResiduals → InteractiveCleanup      (residuals found)
AuditingResiduals → Finished                (no residuals / audit complete)
InteractiveCleanup → InteractiveCleanup     (cleanup decisions in progress)
InteractiveCleanup → Finished               (all residuals resolved)
InteractiveCleanup → Paused                 (user pause)
ExplicitCleanupBlocked → Applying           (resume clears error, retries)
Failed → Applying                           (resume)
Paused → InteractiveCleanup                 (resume)
```

### ResidualStatus (journal.rs:265-272)
```
enum ResidualStatus {
    NotAudited,
    ResidualsObserved { count: usize },
    NoneObservedInScope,
    AuditIncomplete,
    SupersededByNewGeneration,
}
```

### ExecutionRecord (journal.rs:372-392)
```
ExecutionRecord {
    phases_completed: usize,
    phases_total: usize,
    deleted: Vec<ResourceId>,
    already_gone: Vec<ResourceId>,
    failed: Vec<(ResourceId, String)>,
    kept: Vec<PreservedRecord>,
    reviewed: Vec<PreservedRecord>,
    barrier_timeout: Option<BarrierTimeoutRecord>,       // serde(default, skip_if)
    re_delete_records: Vec<ReDeleteRecord>,               // NO serde(default) — v9 required
    explicit_cleanup_error: Option<ExplicitCleanupError>, // serde(default, skip_if)
}
```

### AuditContext (journal.rs:274-319)
```
AuditContext {
    footprint_namespaces: HashSet<String>,
    csv_names: HashSet<String>,
    controller_deployment_names: HashSet<String>,
    service_account_names: HashSet<String>,
    known_labels: Vec<(String, String)>,
    managed_field_managers: HashSet<String>,
    known_gvrs: Option<Vec<KnownGvr>>,
    unresolved_crds: Option<Vec<String>>,
    unresolved_gvks: Option<Vec<(String, String, String)>>,
    owned_cr_gvrs: Option<Vec<KnownGvr>>,
    csv_baseline: Option<Vec<CsvBaselineEntry>>,
    namespace_scope: Option<Vec<NamespaceScopeEntry>>,
}
```

### Journal Load Gate (journal.rs:656-682)
- Pre-checks raw JSON schema_version before deserialize
- Rejects any version != 12
- No migration path — old journals must be discarded

### JournalStore (journal.rs:487-607)
- Process-level flock(LOCK_EX|LOCK_NB) for single-writer
- CAS via in-process Mutex + revision bump
- Re-loads from disk AFTER lock acquisition (TOCTOU defense)
- atomic_write_json: tmp file → fsync → rename → fsync parent

## 2. BackupReceipt Schema (v2)

File: `src/teardown/backup.rs:11,272-281`

```
BACKUP_SCHEMA_VERSION = 2

BackupReceipt {
    root: String,
    manifest_sha256: String,
    tree_sha256: String,
    resource_set_sha256: String,
    resource_count: usize,
    contains_secret_data: bool,
    created_at: String,
}
```

### BackupManifest (backup.rs:208-226)
```
BackupManifest {
    schema_version: u32,
    created_at: String,
    oc_deps_version: String,
    cluster_identity: ClusterIdentity,
    selection: BackupSelection,
    coverage: CoverageSummary,
    contains_secret_data: bool,
    restore_supported: bool,
    restore_notes: Vec<String>,
    capability_warnings: Vec<String>,
    limitations: Vec<String>,
    resources: Vec<ResourceIndexEntry>,
    resource_set_sha256: String,
    tree_sha256: String,
    cleanup_contract_observations: Vec<CleanupContractObservation>,
}
```

### Receipt Validation (backup.rs:1222-1514)
Validates on resume:
- Directory exists and is not symlink
- manifest.yaml SHA-256 matches receipt
- Schema version == 2
- Cluster identity matches
- Resource set hash: receipt == manifest == recomputed
- Per-file hash verification (raw.yaml, recreate.yaml, lifecycle.yaml)
- Extra/unexpected file detection
- Lifecycle identity/state cross-check
- Tree hash triple-check: manifest == receipt == recomputed
- Coverage counts match resource states
- Captured resources have all 3 files, AlreadyAbsent has lifecycle only

## 3. ExecutionPlan Schema (v2)

File: `src/teardown/plan.rs:268-284`

```
EXECUTION_PLAN_SCHEMA_VERSION = 2

ExecutionPlan {
    schema_version: u32,            // deny_unknown_fields
    cluster_identity: ClusterIdentity,
    created_at: String,
    targets: Vec<SavedOperatorTarget>,
    prune_crds: bool,
    approve_scopes: Vec<ApprovalScopeValue>,
    approve_resources: Vec<String>,
    keep_resources: Vec<String>,
    phases: Vec<ExecutionPhase>,
    explicit_deletes: Vec<ExplicitDeleteTarget>,  // serde(default, skip_if)
}

ExecutionPhase {
    phase: u32,                     // deny_unknown_fields
    name: String,
    resources: Vec<ExecutionResource>,
}

ExecutionResource {
    group: String,                  // deny_unknown_fields
    kind: String,
    namespace: Option<String>,
    name: String,
    uid: Option<String>,
    action: ExecutionAction,        // DELETE|KEEP|EXPECT|REVIEW|WAIT
}
```

### Load-time Validation (plan.rs:437-591)
- Schema version must == 2
- Targets must have valid package_name
- approve_resources must not contain scope tokens
- DELETE/EXPECT/WAIT actions must have non-empty UID
- KEEP/REVIEW may have uid=None
- Explicit deletes: non-empty UID, non-empty kind/name, forbidden kinds rejected
- Explicit deletes must have complete ref scan
- Explicit deletes must 1:1 match "Explicit cleanup" phase DELETE actions

## 4. Resume Classification

File: `src/main.rs:1023-1027`

```
enum ExplicitCleanupResumeMode {
    TypedBlocked,   // state == ExplicitCleanupBlocked
    LegacyFailed,   // state == Failed (v12 journal from before ExplicitCleanupBlocked)
}
```

### Resume Eligibility (main.rs:9342)
States eligible for resume: `ExplicitCleanupBlocked | Failed`

Additional checks (main.rs:1048-1064):
- Schema version must match current
- Phase count must match plan
- Plan must have no blockers
- Explicit phase indices must exist if explicit_deletes non-empty

### Legacy Migration (main.rs:3940-3962)
v12 journals written before ExplicitCleanupBlocked: if state==Failed and explicit cleanup
phases are present and all non-explicit phases completed, state is migrated to
ExplicitCleanupBlocked at resume time.

## 5. Batch Config & Behavior

File: `src/main.rs:98-236`

```
ApplySetConfig {
    description: Option<String>,
    defaults: ApplySetDefaults,     // deny_unknown_fields
    operators: Vec<ApplySetEntry>,
}

ApplySetDefaults {
    approve_delete: ApplySetDeleteApprovals,
    preserve: Vec<String>,
    non_interactive: bool,
}

ApplySetEntry {
    name: String,                   // deny_unknown_fields
    approve_delete: ApplySetDeleteApprovals,
    preserve: Vec<String>,
    non_interactive: Option<bool>,
    delete_resources: Vec<DeleteResourceSpec>,
}
```

### Batch Execution Order
1. Validate config: non-empty operators, no empty names
2. Baseline gate: verify all target operators present (or --skip-missing)
3. Check for pending explicit cleanup journals (absent operators with pending resume)
4. Sequential iteration: for each entry:
   a. If pending resume → spawn `oc-deps teardown resume --run <RUN_ID>` as child process
   b. Else → spawn `oc-deps teardown plan <name>` → spawn `oc-deps teardown apply <plan>`
5. On any child failure → stop batch, remaining entries marked NotRun
6. Summary: count succeeded/skipped/failed/not-run

### Child Process Spawning (main.rs:5410-5549)
- 3 `std::process::Command::new(&exe)` call sites:
  - L5410: `teardown resume --run <id>` (pending explicit cleanup)
  - L5460: `teardown plan <name> [--approve-scope...] [--file path]`
  - L5513: `teardown apply <plan> [--dry-run] [--non-interactive] [--backup-dir]`
- Passes stdin `y\n` to apply child for auto-confirmation
- Passes KUBECONFIG env var

### BatchOutcome (main.rs:979-984)
```
enum BatchOutcome {
    Succeeded,
    Skipped,
    Failed(i32),
    NotRun,
}
```

## 6. Output Format Contracts

File: `src/cli.rs:661-665`

```
enum OutputFormat {
    Tree,
    Table,
    Json,
}
```

### TTY vs Non-TTY
- No explicit `atty`/`is_terminal` call in main.rs for teardown output
- Tree/Table output goes to stderr via `eprintln!`
- JSON plan output goes to stdout via `println!` (pipe-safe)
- Batch child process inherits stdout/stderr (`Stdio::inherit()`)
- `--non-interactive` flag disables confirmation prompts (used by batch children)

### Output Contracts
- **Tree**: `kind/name` format for easy `oc get/edit` copy-paste (CLAUDE.md requirement)
- **Table**: comfy-table formatted
- **JSON**: serde_json::to_string_pretty for plans; structured output for journal/audit
- Plan output: respects `--file` to save ExecutionPlan JSON, tree/table to stderr
