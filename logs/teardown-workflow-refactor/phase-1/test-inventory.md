# Test Inventory — Phase 1

Base commit: ad93e09 (Merge pull request #50)

## Summary

| Location | Test Count |
|---|---|
| `src/main.rs` | 121 |
| `tests/cli_ux.rs` | 5 |
| `tests/corpus_replay.rs` | 1 |
| Other `src/` modules | 1,234 |
| **Total** | **1,361** |

## Tests outside main.rs by module (top 15)

| File | Tests | Domain |
|---|---|---|
| `src/teardown/audit.rs` | 192 | Residual audit |
| `src/analyzers/selector.rs` | 131 | Network/selector analysis |
| `src/teardown/planner.rs` | 92 | Plan generation |
| `src/kube/resource.rs` | 81 | Resource identity/parsing |
| `src/teardown/executor.rs` | 79 | Execution engine |
| `src/cli.rs` | 65 | CLI parsing |
| `src/kube/snapshot.rs` | 51 | Snapshot audit |
| `src/teardown/ref_guard.rs` | 46 | Reference guard |
| `src/teardown/backup.rs` | 44 | Backup gate/receipt |
| `src/teardown/plan.rs` | 43 | Plan schema/serialization |
| `src/teardown/runtime.rs` | 40 | Runtime state machine |
| `src/audit/core.rs` | 36 | Core audit |
| `src/teardown/harness.rs` | 28 | Teardown harness |
| `src/kube/scanner.rs` | 27 | Namespace scanner |
| `src/teardown/app.rs` | 26 | TUI app state |

## main.rs Test Modules

### Module 1: `cluster_wide_map_tests` (lines 9403–9751, 26 tests)

| # | Test Name | Line | Safety Contract | Category |
|---|---|---|---|---|
| 1 | `is_system_namespace_matches` | 9409 | Namespace filtering | Pure unit |
| 2 | `matches_glob_prefix` | 9420 | Glob pattern matching | Pure unit |
| 3 | `matches_glob_suffix` | 9426 | Glob pattern matching | Pure unit |
| 4 | `matches_glob_exact` | 9432 | Glob pattern matching | Pure unit |
| 5 | `filter_namespaces_exclude_system` | 9448 | Namespace filtering | Pure unit |
| 6 | `filter_namespaces_selector_and` | 9460 | Label selector AND semantics | Pure unit |
| 7 | `filter_namespaces_exclude_pattern` | 9472 | Exclude pattern filter | Pure unit |
| 8 | `filter_namespaces_all_combined` | 9484 | Combined filter pipeline | Pure unit |
| 9 | `filter_namespaces_no_filters_returns_all` | 9498 | No-filter passthrough | Pure unit |
| 10 | `max_namespace_concurrency_is_bounded` | 9509 | Concurrency bound | Constant validation |
| 11 | `cli_map_a_and_n_mutually_exclusive` | 9516 | CLI mutual exclusion (-A vs -n) | CLI contract |
| 12 | `cli_namespace_selector_repeatable` | 9523 | CLI repeatable flag | CLI contract |
| 13 | `cli_exclude_namespace_repeatable` | 9545 | CLI repeatable flag | CLI contract |
| 14 | `matches_glob_mid_star_no_match` | 9567 | Glob rejection (mid-star) | Pure unit |
| 15 | `api_concurrency_constant_bounded` | 9572 | Concurrency bound | Constant validation |
| 16 | `validate_map_a_and_n_rejects` | 9603 | Map validation error | CLI contract |
| 17 | `validate_selector_without_a_rejects` | 9610 | Selector requires -A | CLI contract |
| 18 | `validate_invalid_selector_rejects` | 9616 | Bad selector format | CLI contract |
| 19 | `validate_invalid_glob_mid_star_rejects` | 9623 | Bad glob rejected | CLI contract |
| 20 | `validate_invalid_glob_multi_star_rejects` | 9630 | Bad glob rejected | CLI contract |
| 21 | `validate_valid_glob_prefix_accepts` | 9637 | Valid glob accepted | CLI contract |
| 22 | `validate_valid_glob_suffix_accepts` | 9644 | Valid glob accepted | CLI contract |
| 23 | `validate_valid_glob_exact_accepts` | 9649 | Valid glob accepted | CLI contract |
| 24 | `json_schema_warning_namespace_is_incomplete` | 9654 | JSON schema: incomplete ns | Output format |
| 25 | `json_schema_error_namespace_not_in_namespaces` | 9708 | JSON schema: error ns excluded | Output format |
| 26 | `validate_map_selector_without_a_via_fn` | 9745 | Selector validation (fn call) | CLI contract |

**Notes:** Tests 16 and 11 are near-duplicates (both test -A/-n mutual exclusion). Tests 17 and 26 both validate selector-without-A (one via CLI parse, one via fn). These are not true duplicates — one tests Clap enforcement, the other tests the validation function directly.

### Module 2: `basis_drift_tests` (lines 9753–11546, 88 tests)

#### Batch/Config subgroup (7 tests)

| # | Test Name | Line | Safety Contract | Category |
|---|---|---|---|---|
| 27 | `apply_set_no_cache_only_refreshes_first_entry` | 9760 | Cache bypass logic | Batch config |
| 28 | `structured_apply_set_approvals_separate_scopes_and_resources` | 9767 | Structured approval parsing | Batch config |
| 29 | `apply_set_defaults_are_merged_with_operator_exceptions` | 9794 | Defaults merge with overrides | Batch config |
| 30 | `batch_config_rejects_force_field` | 9827 | deny_unknown_fields enforcement | Batch config |
| 31 | `structured_apply_set_approvals_reject_all_scope` | 9841 | "all" scope rejection | Batch config |
| 32 | `legacy_apply_set_approval_array_rejected` | 9854 | Legacy array form rejection | Batch config |

#### Provenance drift subgroup (10 tests)

| # | Test Name | Line | Safety Contract | Category |
|---|---|---|---|---|
| 33 | `managed_to_managed_ok` | 9885 | Provenance: stable managed | Drift detection |
| 34 | `managed_downgrade_blocked` | 9894 | Provenance: downgrade blocked | Drift detection |
| 35 | `likely_to_unknown_blocked` | 9903 | Provenance: downgrade blocked | Drift detection |
| 36 | `unknown_no_discovery_source_blocked` | 9912 | Provenance: unknown without source | Drift detection |
| 37 | `unknown_direct_source_blocked` | 9921 | Provenance: direct source blocked | Drift detection |
| 38 | `unknown_related_label_only_needs_crd_verification` | 9933 | Provenance: label-only→CRD check | Drift detection |
| 39 | `no_stored_provenance_blocked` | 9944 | Provenance: missing blocked | Drift detection |
| 40 | `no_metadata_blocked` | 9954 | Provenance: no metadata blocked | Drift detection |

#### CRD label verification subgroup (9 tests)

| # | Test Name | Line | Safety Contract | Category |
|---|---|---|---|---|
| 41 | `crd_label_exact_pair_matches` | 9984 | CRD label pair match | Identity/hash |
| 42 | `crd_label_wrong_value_blocked` | 9991 | CRD label value mismatch | Identity/hash |
| 43 | `crd_label_wrong_key_blocked` | 9998 | CRD label key mismatch | Identity/hash |
| 44 | `crd_label_missing_blocked` | 10005 | CRD label missing blocked | Identity/hash |
| 45 | `empty_pairs_blocked` | 10011 | Empty seed pairs rejected | Identity/hash |
| 46 | `multiple_pairs_match_any` | 10020 | Multi-pair match-any | Identity/hash |
| 47 | `basis_drift_pair_a_removed_pair_b_only_blocked` | 10030 | Basis drift: pair removal blocked | Drift detection |
| 48 | `basis_drift_pair_a_maintained_ok` | 10044 | Basis drift: maintained OK | Drift detection |
| 49 | `multi_pair_allows_crd_verification` | 10058 | Multi-pair triggers CRD verify | Drift detection |
| 50 | `single_pair_allows_crd_verification` | 10076 | Single pair triggers CRD verify | Drift detection |
| 51 | `empty_pairs_in_metadata_blocked_at_caller` | 10091 | Empty pairs in metadata → verify | Drift detection |

#### Resume classification subgroup (23 tests)

| # | Test Name | Line | Safety Contract | Category |
|---|---|---|---|---|
| 52 | `classify_resume_paused_from_residual_routes_to_cleanup` | 10226 | Resume: paused→cleanup | Resume classification |
| 53 | `classify_resume_paused_from_main_routes_to_execution` | 10233 | Resume: paused→execution | Resume classification |
| 54 | `classify_resume_interactive_cleanup_routes_to_cleanup` | 10243 | Resume: interactive→cleanup | Resume classification |
| 55 | `classify_resume_paused_with_pending_complete_routes_to_cleanup` | 10250 | Resume: pending+complete→cleanup | Resume classification |
| 56 | `classify_resume_pending_with_incomplete_phases_is_error` | 10263 | Resume: inconsistent journal | Resume classification |
| 57 | `classify_resume_interactive_cleanup_incomplete_phases_is_error` | 10279 | Resume: inconsistent journal | Resume classification |
| 58 | `hard_failure_blocks_resume` | 10289 | Resume: hard failure blocks | Resume classification |
| 59 | `classify_resume_apply_completed_no_audit_routes_to_cleanup` | 10308 | Resume: crash recovery | Resume classification |
| 60 | `classify_resume_apply_completed_with_audit_routes_to_cleanup` | 10319 | Resume: complete+audit→cleanup | Resume classification |
| 61 | `no_hard_failure_allows_resume` | 10330 | Resume: retryable allows | Resume classification |
| 62 | `classify_resume_blocks_on_unresolved_patch_requested` | 10351 | Resume: PatchRequested blocks | Resume classification |
| 63 | `classify_resume_allows_resolved_recovery` | 10387 | Resume: resolved recovery OK | Resume classification |
| 64 | `classify_resume_explicit_cleanup_blocked_routes_to_main` | 10508 | Resume: ExplicitCleanupBlocked→main | Resume classification |
| 65 | `classify_resume_explicit_cleanup_blocked_no_explicit_deletes_is_error` | 10524 | Resume: blocked without targets | Resume classification |
| 66 | `classify_resume_explicit_cleanup_blocked_wrong_phase_is_error` | 10533 | Resume: blocked wrong phase | Resume classification |
| 67 | `classify_resume_generic_failed_remains_non_resumable` | 10545 | Resume: generic Failed blocked | Resume classification |
| 68 | `legacy_failed_exact_explicit_boundary_is_narrowly_eligible` | 10556 | Resume: legacy Failed eligible | Resume classification |
| 69 | `legacy_failed_without_backup_is_not_migrated` | 10580 | Resume: legacy Failed needs backup | Resume classification |
| 70 | `batch_selection_delegates_eligible_legacy_failed_journal` | 10588 | Batch: delegate eligible journal | Batch resume |
| 71 | `batch_selection_rejects_ineligible_latest_explicit_journal` | 10609 | Batch: reject ineligible | Batch resume |
| 72 | `batch_dry_run_never_executes_pending_resume` | 10619 | Batch: dry-run skip | Batch resume |
| 73 | `explicit_cleanup_resume_rejects_prior_target_outcome` | 10625 | Resume: prior outcome blocks | Resume classification |
| 74 | `explicit_cleanup_resume_rejects_metadata_action_mismatch` | 10646 | Resume: UID mismatch blocks | Resume classification |

#### Explicit guard subgroup (5 tests)

| # | Test Name | Line | Safety Contract | Category |
|---|---|---|---|---|
| 75 | `explicit_guard_transient_timeout_classifies_correctly` | 10663 | Guard: timeout→transient | State transition |
| 76 | `explicit_guard_forbidden_classifies_transient` | 10682 | Guard: 403→transient | State transition |
| 77 | `explicit_guard_server_error_classifies_transient` | 10700 | Guard: 500→transient | State transition |
| 78 | `explicit_guard_other_error_classifies_hard` | 10720 | Guard: other→hard | State transition |
| 79 | `executor_error_checkpoint_preserves_only_typed_retryable_state` | 10732 | Checkpoint: preserve retryable | State transition |

#### can_finish_run subgroup (7 tests)

| # | Test Name | Line | Safety Contract | Category |
|---|---|---|---|---|
| 80 | `can_finish_apply_completed_with_audit` | 10754 | Finish: complete+audit OK | Journal state |
| 81 | `cannot_finish_without_audit` | 10761 | Finish: no audit blocked | Journal state |
| 82 | `cannot_finish_with_incomplete_audit` | 10769 | Finish: incomplete audit blocked | Journal state |
| 83 | `cannot_finish_with_hard_failed_decision` | 10778 | Finish: hard failure blocked | Journal state |
| 84 | `cannot_finish_with_not_audited_status` | 10795 | Finish: not audited blocked | Journal state |
| 85 | `cannot_finish_with_incomplete_phases` | 10804 | Finish: incomplete phases blocked | Journal state |
| 86 | `cannot_finish_from_paused_state` | 10812 | Finish: paused blocked | Journal state |

#### Mutation gate / TUI safety (1 test)

| # | Test Name | Line | Safety Contract | Category |
|---|---|---|---|---|
| 87 | `check_and_persist_paused_with_closed_gate` | 10820 | MutationGate: gate close→pause | **TUI safety (async)** |

**TUI dependency:** Test 87 calls `crate::tui::check_and_persist_paused` — this is TUI-only safety logic that Phase 2 must move to workflow module before removal.

#### MVP safety (6 tests)

| # | Test Name | Line | Safety Contract | Category |
|---|---|---|---|---|
| 88 | `prepared_journal_rejects_resume_mutation` | 10868 | Prepared state rejects resume | Journal state |
| 89 | `expect_resources_do_not_create_re_delete_authority` | 10880 | EXPECT→no re-delete authority | Journal state |
| 90 | `unresolved_redelete_blocks_resume` | 10912 | Re-delete blocks resume | Resume classification |
| 91 | `resolved_redelete_allows_resume` | 10947 | Gone re-delete allows resume | Resume classification |
| 92 | `re_delete_record_roundtrip` | 10970 | Re-delete JSON roundtrip | Schema |
| 93 | `pending_cleanup_blocks_finish` | 11004 | Pending cleanup blocks Finish | Journal state |

#### Network JSON (3 tests)

| # | Test Name | Line | Safety Contract | Category |
|---|---|---|---|---|
| 94 | `network_json_has_typed_warnings` | 11034 | Network JSON: typed warnings | Output format |
| 95 | `network_json_gateway_routes_always_present` | 11047 | Network JSON: gateway routes | Output format |
| 96 | `network_json_gateway_route_fields` | 11115 | Network JSON: route fields | Output format |

#### DeleteResourceSpec (8 tests)

| # | Test Name | Line | Safety Contract | Category |
|---|---|---|---|---|
| 97 | `delete_resource_spec_parse_core_group` | 11221 | Spec parse: core group | Identity/hash |
| 98 | `delete_resource_spec_parse_with_group` | 11230 | Spec parse: custom group | Identity/hash |
| 99 | `delete_resource_spec_parse_cluster_scoped` | 11241 | Spec parse: cluster-scoped | Identity/hash |
| 100 | `delete_resource_spec_rejects_forbidden_kinds` | 11252 | Spec: forbidden kinds rejected | Identity/hash |
| 101 | `delete_resource_spec_rejects_empty_fields` | 11266 | Spec: empty fields rejected | Identity/hash |
| 102 | `delete_resource_spec_rejects_whitespace` | 11272 | Spec: whitespace rejected | Identity/hash |
| 103 | `batch_config_parses_delete_resources` | 11291 | Batch config: delete_resources | Batch config |
| 104 | `batch_config_without_delete_resources_ok` | 11310 | Batch config: omission OK | Batch config |
| 105 | `delete_resource_to_cli_arg_roundtrip` | 11321 | Spec: roundtrip parse↔format | Identity/hash |

#### Explicit phase injection (1 test)

| # | Test Name | Line | Safety Contract | Category |
|---|---|---|---|---|
| 106 | `inject_explicit_phase_errors_on_missing_gk` | 11348 | Inject: missing GK errors | State transition |

#### Discovery refresh (1 test)

| # | Test Name | Line | Safety Contract | Category |
|---|---|---|---|---|
| 107 | `should_refresh_discovery_logic` | 11389 | Discovery refresh decision | Pure unit |

#### Batch / operator presence (6 tests)

| # | Test Name | Line | Safety Contract | Category |
|---|---|---|---|---|
| 108 | `presence_gate_succeeded_passes` | 11437 | Operator match: Succeeded | Batch gate |
| 109 | `presence_gate_failed_passes` | 11443 | Operator match: Failed | Batch gate |
| 110 | `presence_gate_pending_passes` | 11449 | Operator match: Pending | Batch gate |
| 111 | `presence_gate_missing_fails` | 11462 | Operator match: missing | Batch gate |
| 112 | `batch_summary_counts_outcomes_correctly` | 11475 | Batch summary counts | Batch |
| 113 | `batch_skipped_excluded_from_success` | 11490 | Batch: skipped≠succeeded | Batch |

#### Health/preflight (2 tests)

| # | Test Name | Line | Safety Contract | Category |
|---|---|---|---|---|
| 114 | `health_preflight_produces_warning_not_critical` | 11499 | Preflight: health=Warning | Preflight |
| 115 | `blocking_preflight_filters_critical_only` | 11519 | Preflight: only Critical blocks | Preflight |

### Module 3: `resolve_explicit_target_tests` (lines 11548–11740, 3 tests)

| # | Test Name | Line | Safety Contract | Category |
|---|---|---|---|---|
| 116 | `resolve_404_one_request_not_found` | 11630 | 404: one request, no retry | Tower mock |
| 117 | `resolve_403_one_request_fails` | 11662 | 403: one request, no retry | Tower mock |
| 118 | `resolve_500_then_200_recovers` | 11693 | 500→200: retry recovery | Tower mock |

### Module 4: `config_parse_tests` (lines 11742–11786, 3 tests)

| # | Test Name | Line | Safety Contract | Category |
|---|---|---|---|---|
| 119 | `full_teardown_config_parses_as_apply_set_config` | 11747 | Config file: parse+validate | Config/corpus |
| 120 | `config_with_unknown_field_fails` | 11767 | Config: unknown field rejected | Config validation |
| 121 | `config_delete_resource_validate_rejects_empty_kind` | 11774 | Config: empty kind rejected | Config validation |

### External: `tests/cli_ux.rs` (5 tests)

| # | Test Name | Line | Safety Contract | Category |
|---|---|---|---|---|
| 122 | `help_and_version_are_offline` | 29 | CLI: help/version offline | CLI contract |
| 123 | `completions_are_offline_for_every_documented_shell` | 40 | CLI: completions offline | CLI contract |
| 124 | `redirected_offline_output_has_no_ansi` | 51 | CLI: no ANSI in redirected output | Output format |
| 125 | `journal_output_flag_parses` | 78 | CLI: journal output flag | CLI contract |
| 126 | `full_teardown_config_parses` | 95 | CLI: full-teardown config parse | CLI contract |

### External: `tests/corpus_replay.rs` (1 test)

| # | Test Name | Line | Safety Contract | Category |
|---|---|---|---|---|
| 127 | `corpus_replay_exact_counts` | 206 | Corpus: exact count invariants | Corpus/golden |

## Category Summary (main.rs + external tests)

| Category | Count | Teardown-relevant? |
|---|---|---|
| Resume classification | 25 | YES — must preserve |
| Drift detection | 13 | YES — must preserve |
| Identity/hash | 11 | YES — must preserve |
| Journal state | 9 | YES — must preserve |
| CLI contract | 12 | YES — move to `tests/cli_contract.rs` |
| Batch config | 9 | YES — move to batch module |
| Batch gate/resume | 5 | YES — move to batch module |
| State transition | 6 | YES — move to workflow module |
| Output format | 5 | Move to output module |
| Pure unit | 10 | Move with functions |
| Tower mock | 3 | YES — must preserve |
| Preflight | 2 | YES — move to planner/executor |
| Config validation | 3 | YES — move to config module |
| Corpus/golden | 1 | YES — must preserve |
| TUI safety (async) | 1 | **MUST MOVE to workflow before TUI removal** |
| Constant validation | 2 | Move with constants |
| Batch (summary) | 2 | YES — move to batch module |

## Duplicate / Near-Duplicate Tests

| Test A | Test B | Verdict |
|---|---|---|
| `cli_map_a_and_n_mutually_exclusive` (9516) | `validate_map_a_and_n_rejects` (9603) | Near-dup: both test -A/-n exclusion. Keep both — one tests Clap, one tests validation fn. |
| `validate_selector_without_a_rejects` (9610) | `validate_map_selector_without_a_via_fn` (9745) | Near-dup: both test selector-without-A. One via CLI parse, one via direct fn. Keep both. |

No true duplicates found across TUI/script/apply paths in main.rs tests. The TUI-specific test (`check_and_persist_paused_with_closed_gate`, #87) is unique and tests safety logic that must be preserved during TUI removal.

## TUI-dependent tests (Phase 2 migration required)

| Test | Line | Dependency | Migration target |
|---|---|---|---|
| `check_and_persist_paused_with_closed_gate` | 10820 | `crate::tui::check_and_persist_paused` | `teardown/workflow.rs` or `teardown/runtime.rs` |

## Tests in `src/teardown/app.rs` (TUI app state, 26 tests)

These 26 tests in `src/teardown/app.rs` are TUI-specific state machine tests that will be removed with Phase 2. Non-UI safety contracts they cover must be verified as covered by workflow/runtime tests before deletion.
