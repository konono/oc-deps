# Phase 5 Test Migration

## Summary
- Before: 1347 tests
- After: 1314 tests
- Deleted: 33 (dead production code fossils)
- Moved: 3 (network tests to commands/network.rs)
- safety_contracts_lost: 0

## Deleted tests (dead production code removed)

### Provenance drift tests (8) — tested `check_provenance_drift` / `ProvenanceDriftResult`
- managed_to_managed_ok
- managed_downgrade_blocked
- likely_to_unknown_blocked
- unknown_no_discovery_source_blocked
- unknown_direct_source_blocked
- unknown_related_label_only_needs_crd_verification
- no_stored_provenance_blocked
- no_metadata_blocked

### CRD label verification tests (11) — tested `verify_crd_label_pairs`
- crd_label_exact_pair_matches
- crd_label_wrong_value_blocked
- crd_label_wrong_key_blocked
- crd_label_missing_blocked
- empty_pairs_blocked
- multiple_pairs_match_any
- basis_drift_pair_a_removed_pair_b_only_blocked
- basis_drift_pair_a_maintained_ok
- multi_pair_allows_crd_verification
- single_pair_allows_crd_verification
- empty_pairs_in_metadata_blocked_at_caller

### Resume guard tests (2) — tested `resume_has_blocking_hard_failure`
- hard_failure_blocks_resume
- no_hard_failure_allows_resume

### Finish gate tests (8) — tested `can_finish_run`
- cannot_finish_without_audit
- cannot_finish_with_incomplete_audit
- cannot_finish_with_hard_failed_decision
- cannot_finish_with_not_audited_status
- cannot_finish_with_incomplete_phases
- cannot_finish_from_paused_state
- pending_cleanup_blocks_finish
- can_finish_apply_completed_with_audit

### Roundtrip test (1) — tested `DeleteResourceSpec::to_cli_arg`
- delete_resource_to_cli_arg_roundtrip

### Helper removal (3) — only used by deleted tests
- make_metadata
- make_labels
- make_seed_pairs

## Moved tests (3) — from commands/teardown.rs → commands/network.rs
- network_json_has_typed_warnings
- network_json_gateway_routes_always_present
- network_json_gateway_route_fields

## Reason
All deleted production functions had `#[allow(dead_code)]` and zero callers outside their own test module. They were fossils from incomplete feature work, not active safety paths.
