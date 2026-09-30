# Phase 1 — Production Call-Site Inventory (Complete)

Base commit: ad93e09 (PR #50 merge)

## Summary

| Category | Production callers | Test-only | Files | Verified by |
|---|---|---|---|---|
| `execute_plan` / `execute_plan_with_store` | 4 | 6 | main.rs(3), tui/mod.rs(1) | validate-callsite-counts.py |
| `prepare_backup_gate` | 3 | 0 | main.rs(2), tui/mod.rs(1) | validate-callsite-counts.py |
| `execute_residual_cleanup` / `_with_progress` | 6 | 0 | main.rs(4), tui/mod.rs(2) | validate-callsite-counts.py |
| `run_post_mutation_audit` | 6 | 0 | main.rs(4), tui/mod.rs(1), executor.rs(1) | validate-callsite-counts.py |
| `check_operator_generation_fresh` | 26 | 0 | main.rs(16), tui/mod.rs(7), executor.rs(3) | validate-callsite-counts.py |
| Journal `.update()` closures | 74 | 6 | main.rs(27), executor.rs(28), tui/mod.rs(19) | validate-callsite-counts.py |
| `std::process::Command` (self-spawn) | 3 | 0 | main.rs (Batch arm only) | validate-callsite-counts.py |
| `MutationGate::new` | 4 | 21 | main.rs(4 prod, 1 test), permit.rs(9), executor.rs(6), harness.rs(4), watch.rs(1) | validate-callsite-counts.py |
| `check_and_persist_paused` | 6 | 1 | tui/mod.rs(6), main.rs(1 test) | rg count |
| TUI entry points (`run_tui`, `run_residual_only`) | 3 | 0 | main.rs(2 callers), tui/mod.rs(1 def) | rg count |
| `AppState::new` | 2 | 10 | main.rs(1), tui/mod.rs(1), app.rs(10 test) | rg count |

Counts are generated/verified by `scripts/validate-callsite-counts.py` which scans
the pinned source. The `#[cfg(test)]` boundary in each file separates production
from test-only sites.

## Reproducible search commands

```bash
# All commands run from repo root: /tmp/oc-deps-issue49-impl

# execute_plan / execute_plan_with_store (call sites, not definitions)
grep -rn 'execute_plan\|execute_plan_with_store' src/ --include="*.rs" | grep -v 'fn execute_plan'

# prepare_backup_gate
grep -rn 'prepare_backup_gate' src/ --include="*.rs"

# execute_residual_cleanup
grep -rn 'execute_residual_cleanup' src/ --include="*.rs"

# Journal .update() closures
grep -rn '\.update(|j\|\.update(|journal\|\.update(|jrnl' src/ --include="*.rs"

# run_post_mutation_audit
grep -rn 'run_post_mutation_audit' src/ --include="*.rs" | grep -v 'fn run_post'

# check_operator_generation_fresh
grep -rn 'check_operator_generation_fresh' src/ --include="*.rs" | grep -v 'fn check_\|///\|//'

# std::process::Command
grep -rn 'std::process::Command::new\|process::Command::new' src/ --include="*.rs"

# MutationGate
grep -rn 'MutationGate::new' src/ --include="*.rs"

# check_and_persist_paused
grep -rn 'check_and_persist_paused' src/ --include="*.rs"

# TUI entry points
grep -rn 'run_tui\|run_residual_only' src/ --include="*.rs" | grep -v '//\|///'

# AppState
grep -rn 'AppState::new\|AppState {' src/ --include="*.rs" | grep -v '//\|///'
```

## Test module boundaries (for production vs test classification)

| File | `#[cfg(test)]` line | Production lines | Test lines |
|---|---|---|---|
| `src/main.rs` | 9403, 9753, 11548, 11742 | 1–9402 | 9403–11786 |
| `src/teardown/executor.rs` | 4544 | 1–4543 | 4544–EOF |
| `src/tui/mod.rs` | (none) | 1–1307 (all) | (none) |
| `src/teardown/app.rs` | 236 (approx) | 1–235 | 236–EOF |
| `src/teardown/permit.rs` | 128 (approx) | 1–127 | 128–EOF |

---

## 1. `execute_plan` / `execute_plan_with_store`

### Definitions

| Function | File:Line | Visibility |
|---|---|---|
| `execute_plan` (public wrapper) | `src/teardown/executor.rs:339` | `pub async fn` |
| `execute_plan_with_store` (low-level) | `src/teardown/executor.rs:372` | `pub async fn` |

### Production call sites (4)

| # | File:Line | Enclosing context | Category |
|---|---|---|---|
| 1 | `src/main.rs:2768` | Apply arm → script mode | wrapper call |
| 2 | `src/main.rs:3178` | Apply arm → headless CLI mode | wrapper call |
| 3 | `src/main.rs:5102` | Resume arm | wrapper call |
| 4 | `src/tui/mod.rs:478` | `run_tui_inner` TUI execution loop | low-level `execute_plan_with_store` |

### Test-only call sites (6)

| # | File:Line | Test function |
|---|---|---|
| 1 | `src/teardown/executor.rs:5530` | tower mock test |
| 2 | `src/teardown/executor.rs:5756` | tower mock test |
| 3 | `src/teardown/executor.rs:5895` | tower mock test |
| 4 | `src/teardown/executor.rs:6012` | tower mock test |
| 5 | `src/teardown/executor.rs:8949` | tower mock test |
| 6 | `src/teardown/executor.rs:9151` | tower mock test |

### Import

| File:Line | Import |
|---|---|
| `src/main.rs:80` | `use crate::teardown::executor::{execute_plan, print_execution_result}` |

---

## 2. `prepare_backup_gate`

### Definition

| File:Line | Visibility |
|---|---|
| `src/teardown/backup.rs:1903` | `pub async fn` |

### Production call sites (3)

| # | File:Line | Enclosing context | Category |
|---|---|---|---|
| 1 | `src/main.rs:2716` | Apply arm → script mode | backup before script execution |
| 2 | `src/main.rs:3110` | Apply arm → headless CLI mode | backup before headless execution |
| 3 | `src/tui/mod.rs:409` | `run_tui_inner` → backup before TUI execution | TUI backup |

---

## 3. `execute_residual_cleanup` / `execute_residual_cleanup_with_progress`

### Definitions

| Function | File:Line |
|---|---|
| `execute_residual_cleanup` (wrapper) | `src/teardown/executor.rs:3921` |
| `execute_residual_cleanup_with_progress` (low-level) | `src/teardown/executor.rs:3941` |

### Production call sites (6)

| # | File:Line | Enclosing context | Category |
|---|---|---|---|
| 1 | `src/main.rs:2934` | Apply → script mode → residual cleanup loop | residual-mutation |
| 2 | `src/main.rs:2990` | Apply → script mode → another residual cleanup path | residual-mutation |
| 3 | `src/main.rs:3340` | Apply → headless CLI → residual cleanup loop | residual-mutation |
| 4 | `src/main.rs:3512` | Apply → headless CLI → explicit cleanup retry path | residual-mutation |
| 5 | `src/tui/mod.rs:771` | `run_tui_inner` → residual delete | residual-mutation (TUI) |
| 6 | `src/tui/mod.rs:946` | `run_residual_tui` → `execute_residual_cleanup_with_progress` | residual-mutation (TUI with progress) |

---

## 4. `run_post_mutation_audit`

### Definition

| File:Line | Notes |
|---|---|
| `src/teardown/audit.rs:972` | Delegates to `run_post_mutation_audit_until_settled` |

### Production call sites (6)

| # | File:Line | Enclosing context | Category |
|---|---|---|---|
| 1 | `src/main.rs:2859` | Apply → script mode → post-apply audit | audit |
| 2 | `src/main.rs:3246` | Apply → headless CLI → post-apply audit | audit |
| 3 | `src/main.rs:5025` | Resume arm → audit recovery path | audit |
| 4 | `src/main.rs:5172` | Resume arm → post-resume audit | audit |
| 5 | `src/tui/mod.rs:1125` | `run_residual_only` → TUI audit | audit (TUI) |
| 6 | `src/teardown/executor.rs:4462` | executor post-explicit-cleanup audit | audit (executor) |

Note: `audit.rs:972` is the definition, which delegates to `run_post_mutation_audit_until_settled`.

---

## 5. `check_operator_generation_fresh`

### Production call sites (26 = main.rs 16 + tui/mod.rs 7 + executor.rs 3)

| # | File:Line | Enclosing context |
|---|---|---|
| 1 | `src/main.rs:2849` | Apply → script mode → post-apply |
| 2 | `src/main.rs:2875` | Apply → script mode → generation recheck |
| 3 | `src/main.rs:3047` | Apply → script mode → finish gate |
| 4 | `src/main.rs:3237` | Apply → headless → post-apply |
| 5 | `src/main.rs:3288` | Apply → headless → generation recheck |
| 6 | `src/main.rs:3987` | Resume → pre-execution generation check |
| 7 | `src/main.rs:4286` | Resume → residual cleanup generation gate |
| 8 | `src/main.rs:4442` | Resume → explicit cleanup generation gate |
| 9 | `src/main.rs:4478` | Resume → explicit cleanup re-gen |
| 10 | `src/main.rs:4644` | Resume → residual explicit retry generation |
| 11 | `src/main.rs:4835` | Resume → post-process generation |
| 12 | `src/main.rs:4874` | Resume → post-process generation recheck |
| 13 | `src/main.rs:5012` | Resume → final state generation |
| 14 | `src/main.rs:5165` | Resume → post-resume audit generation |
| 15 | `src/main.rs:5183` | Resume → post-resume audit re-gen |
| 16 | `src/main.rs:5646` | Journal arm → read-only status |
| 17 | `src/tui/mod.rs:357` | TUI pre-execution |
| 18 | `src/tui/mod.rs:698` | TUI post-execution |
| 19 | `src/tui/mod.rs:731` | TUI post-execution recheck |
| 20 | `src/tui/mod.rs:1119` | TUI residual audit |
| 21 | `src/tui/mod.rs:1130` | TUI residual audit recheck |
| 22 | `src/tui/mod.rs:1204` | TUI residual cleanup generation gate |
| 23 | `src/tui/mod.rs:1229` | TUI residual cleanup final gen |
| 24 | `src/teardown/executor.rs:3990` | executor residual cleanup pre-check |
| 25 | `src/teardown/executor.rs:4058` | executor residual cleanup post-permit |
| 26 | `src/teardown/executor.rs:4442` | executor post-explicit-cleanup audit |

---

## 6. Journal `.update()` closures

### Production (74 total)

| File | Count | Lines (sample) |
|---|---|---|
| `src/main.rs` | 27 | 2800, 2830, 2914, 3058, 3211, 3299, 3612, 3948, 4252, 4265, 4335, 4371, 4408, 4529, 4548, 4567, 4703, 4787, 4914, 4972, 5032, 5067, 5095, 5134, 5194, 5212, and 1 more |
| `src/teardown/executor.rs` | 28 | 513, 738, 843, 1102, 1352, 1524, 1672, 1709, 2080, 2126, 2454, 2477, 2540, 2635, 2816, 3292, 3362, 3395, 3512, 4033, 4185, 4221, 4367, 4415, 4452, 4466, 4478, 4522 |
| `src/tui/mod.rs` | 19 | 596, 1013, 1022, and 16 others across run_tui_inner and run_residual_tui |

#### main.rs breakdown by arm

| Arm | Count | Lines (range) |
|---|---|---|
| Apply → script mode | 6 | 2800, 2830, 2914, 3058 and 2 more |
| Apply → headless CLI | 5 | 3211, 3299, 3612 and 2 more |
| Resume | 15 | 3948, 4252, 4265, 4335, 4371, 4408, 4529, 4548, 4567, 4703, 4787, 4914, 4972, 5032, 5067 |
| Resume → final state | 2 | 5095, 5134 |
| Resume → post-audit | 2 | 5194, 5212 |

### Test-only (6)

| File | Lines |
|---|---|
| `src/teardown/executor.rs` | 6372, 6432, 6510, 8188, 8666, 9141 |

---

## 7. `std::process::Command` (self-spawning)

### Production call sites (3) — all in Batch arm

| # | File:Line | Purpose |
|---|---|---|
| 1 | `src/main.rs:5410` | Batch → spawn `teardown resume --run` for pending explicit cleanup |
| 2 | `src/main.rs:5460` | Batch → spawn `teardown plan` for operator |
| 3 | `src/main.rs:5513` | Batch → spawn `teardown apply` for operator plan |

---

## 8. `MutationGate`

### Production `MutationGate::new` (4) — all in main.rs

| # | File:Line | Enclosing context |
|---|---|---|
| 1 | `src/main.rs:2435` | Apply → TUI mode |
| 2 | `src/main.rs:2766` | Apply → script mode |
| 3 | `src/main.rs:3160` | Apply → headless CLI mode |
| 4 | `src/main.rs:4219` | Resume arm |

### Production `gate.is_open()` checks (6)

| # | File:Line | Purpose |
|---|---|---|
| 1 | `src/main.rs:2787` | script mode → determine Paused vs completed |
| 2 | `src/main.rs:3198` | headless → determine Paused vs completed |
| 3 | `src/main.rs:4304` | Resume → check pause after explicit cleanup |
| 4 | `src/main.rs:4637` | Resume → check pause after residual retry |
| 5 | `src/main.rs:5018` | Resume → final state determination |
| 6 | `src/main.rs:5122` | Resume → post-audit state determination |

### Test-only `MutationGate::new` (21)

| File | Count | Lines |
|---|---|---|
| `src/teardown/permit.rs` | 9 | 141, 148, 156, 166, 197, 226, 252, 263, 282 |
| `src/teardown/executor.rs` | 6 | 5316, 6104, 7879, 7974, 8044, 8193 |
| `src/teardown/harness.rs` | 4 | 217, 245, 277, 492 |
| `src/teardown/watch.rs` | 1 | 677 |
| `src/main.rs` | 1 | 10839 |

---

## 9. `check_and_persist_paused`

### Definition

| File:Line |
|---|
| `src/tui/mod.rs:1171` |

### Production call sites (6) — all in tui/mod.rs

| Lines |
|---|
| 1197, 1206, 1217, 1223, 1231, 1240 |

All within `run_residual_only` — non-UI safety logic that Phase 2 must extract.

### Test-only (1)

| File:Line |
|---|
| `src/main.rs:10842` (+ 10849 re-check in same test) |

---

## 10. TUI entry points

### Production (3)

| # | File:Line | Function | Called from |
|---|---|---|---|
| 1 | `src/main.rs:2448` | `crate::tui::run_tui(...)` | Apply arm (TUI mode) |
| 2 | `src/main.rs:5083` | `crate::tui::run_residual_only(...)` | Resume arm |
| 3 | `src/tui/mod.rs:31,79` | `run_tui` → `run_tui_inner` | Definition |
| 4 | `src/tui/mod.rs:1189` | `run_residual_only` | Definition |

---

## 11. `AppState`

### Production (2)

| # | File:Line | Context |
|---|---|---|
| 1 | `src/main.rs:2472` | Apply → script mode → `AppState::new(...)` |
| 2 | `src/tui/mod.rs:95` | `run_tui_inner` → `AppState::new(...)` |

### Test-only (10)

All in `src/teardown/app.rs` (lines 243–325), testing AppState transitions.

---

## Phase 2/3 removal map

The following production sites are removed or relocated:

| Phase | Action | Sites affected |
|---|---|---|
| Phase 2 | Remove TUI code | tui/mod.rs: all 19 journal updates, 1 execute_plan_with_store, 1 prepare_backup_gate, 2 execute_residual_cleanup, 6 check_and_persist_paused, 1 AppState, 6 check_operator_generation_fresh |
| Phase 2 | Remove script mode | main.rs: 6 journal updates, 1 execute_plan, 1 prepare_backup_gate, 2 execute_residual_cleanup, 1 AppState, 3 check_operator_generation_fresh |
| Phase 2 | Extract `check_and_persist_paused` safety logic | tui/mod.rs:1171 → teardown/runtime.rs or workflow.rs |
| Phase 3 | Consolidate headless | main.rs headless: 5 journal updates, 1 execute_plan, 1 prepare_backup_gate, 2 execute_residual_cleanup → all into run_teardown_workflow |
| Phase 3 | Consolidate resume | main.rs resume: ~19 journal updates, 1 execute_plan, 4 run_post_mutation_audit, 1 MutationGate → into run_teardown_workflow |
| Phase 4 | Eliminate self-spawn | main.rs batch: 3 std::process::Command → direct run_teardown_workflow calls |

After Phase 3+4, remaining production mutation sites:
- `run_teardown_workflow`: 1 execute_plan, 1 prepare_backup_gate, 1 execute_residual_cleanup
- `executor.rs` internal: 28 journal updates (within execute_plan_with_store, immovable)
- `audit.rs` internal: 1 run_post_mutation_audit (within executor post-explicit-cleanup)
