#!/usr/bin/env python3
"""Validate Phase 1 manifest: SHA-256 hashes, nonempty counts, internal consistency."""
import hashlib
import json
import os
import sys

PHASE1 = os.path.join(os.path.dirname(__file__), "..", "logs", "teardown-workflow-refactor", "phase-1")
MANIFEST = os.path.join(PHASE1, "manifest.json")

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

    # Check file hashes
    for key, info in m["deliverables"].items():
        fpath = os.path.join(PHASE1, info["file"])
        if not os.path.exists(fpath):
            errors.append(f"Missing file: {info['file']}")
            continue
        actual = sha256_file(fpath)
        if actual != info["sha256"]:
            errors.append(f"Hash mismatch for {info['file']}: manifest={info['sha256'][:16]}... actual={actual[:16]}...")

    # Nonempty counts
    counts = m["nonempty_counts"]
    if counts["operators"] != 15:
        errors.append(f"operators={counts['operators']}, expected 15")
    if counts["plan_resources"] != 343:
        errors.append(f"plan_resources={counts['plan_resources']}, expected 343")
    if counts["explicit_deletes"] != 10:
        errors.append(f"explicit_deletes={counts['explicit_deletes']}, expected 10")
    if counts["execute_plan_sites"] != 4:
        errors.append(f"execute_plan_sites={counts['execute_plan_sites']}, expected 4")
    if counts["prepare_backup_gate_sites"] != 3:
        errors.append(f"prepare_backup_gate_sites={counts['prepare_backup_gate_sites']}, expected 3")

    # Plan tuples cross-check
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
        print(f"  files={len(m['deliverables'])}, operators={counts['operators']}, "
              f"resources={counts['plan_resources']}, explicit={counts['explicit_deletes']}")
        sys.exit(0)

if __name__ == "__main__":
    main()
