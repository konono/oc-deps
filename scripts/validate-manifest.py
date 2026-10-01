#!/usr/bin/env python3
"""Validate Phase 1 manifest: SHA-256 hashes, ALL nonempty counts, internal consistency."""
import hashlib
import json
import os
import sys

PHASE1 = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "logs", "teardown-workflow-refactor", "phase-1")
MANIFEST = os.path.join(PHASE1, "manifest.json")

EXPECTED_COUNTS = {
    "operators": 15,
    "plan_resources": 343,
    "explicit_deletes": 10,
    "execute_plan_sites": 4,
    "prepare_backup_gate_sites": 3,
    "execute_residual_cleanup_sites": 6,
    "check_operator_generation_fresh_callers": 26,
    "run_post_mutation_audit_callers": 6,
    "mutation_gate_new_production": 4,
    "journal_update_production_sites": 74,
    "std_process_command_sites": 3,
    "existing_tests_base": 1369,
    "new_contract_tests": 6,
    "total_tests_branch": 1375,
}


def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            h.update(chunk)
    return h.hexdigest()


def main():
    with open(MANIFEST) as f:
        m = json.load(f)

    errors = []

    # 1. Check file hashes for all deliverables
    for key, info in m["deliverables"].items():
        fpath = os.path.join(PHASE1, info["file"])
        if not os.path.exists(fpath):
            errors.append(f"Missing file: {info['file']}")
            continue
        actual = sha256_file(fpath)
        if actual != info["sha256"]:
            errors.append(f"Hash mismatch for {info['file']}: manifest={info['sha256'][:16]}... actual={actual[:16]}...")

    # 2. Check ALL nonempty_counts fields against expected
    counts = m.get("nonempty_counts", {})
    for key, expected in EXPECTED_COUNTS.items():
        actual = counts.get(key)
        if actual is None:
            errors.append(f"nonempty_counts missing key: {key}")
        elif actual != expected:
            errors.append(f"nonempty_counts.{key}={actual}, expected {expected}")

    # Warn about unexpected keys in nonempty_counts
    for key in counts:
        if key not in EXPECTED_COUNTS:
            errors.append(f"nonempty_counts has unexpected key: {key}")

    # 3. Plan tuples cross-check
    plan_info = m["deliverables"]["plan_semantic_tuples"]
    if plan_info.get("total_resources") != 343:
        errors.append(f"plan deliverable total_resources={plan_info.get('total_resources')}, expected 343")
    if plan_info.get("explicit_deletes") != 10:
        errors.append(f"plan deliverable explicit_deletes={plan_info.get('explicit_deletes')}, expected 10")

    # Action totals
    actions = plan_info.get("action_totals", {})
    expected_actions = {"DELETE": 112, "EXPECT": 77, "KEEP": 136, "REVIEW": 18}
    for action, expected in expected_actions.items():
        actual = actions.get(action)
        if actual != expected:
            errors.append(f"action {action}={actual}, expected {expected}")

    if errors:
        print("FAIL")
        for e in errors:
            print(f"  {e}")
        sys.exit(1)
    else:
        print("PASS")
        print(f"  files={len(m['deliverables'])}, "
              f"all {len(EXPECTED_COUNTS)} nonempty_counts verified")
        sys.exit(0)


if __name__ == "__main__":
    main()
