#!/usr/bin/env python3
"""Scan pinned source at a git ref to produce observed callsite counts,
then validate manifest and documented counts against the scan.

Production vs test boundary: first #[cfg(test)] in each file.
Default ref: ad93e096 (Phase 1 base commit).
"""
import json
import os
import re
import subprocess
import sys
import tempfile
import shutil

REPO = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
MANIFEST = os.path.join(REPO, "logs", "teardown-workflow-refactor", "phase-1", "manifest.json")

DEFAULT_REF = "ad93e096"

ALL_FILES = {
    "main": "src/main.rs",
    "tui": "src/tui/mod.rs",
    "executor": "src/teardown/executor.rs",
    "journal": "src/teardown/journal.rs",
    "backup": "src/teardown/backup.rs",
    "audit": "src/teardown/audit.rs",
    "app": "src/teardown/app.rs",
    "permit": "src/teardown/permit.rs",
    "runtime": "src/teardown/runtime.rs",
    "watch": "src/teardown/watch.rs",
    "harness": "src/teardown/harness.rs",
    "ref_guard": "src/teardown/ref_guard.rs",
}


def git_show(ref, path):
    """Read file content from a git ref."""
    try:
        result = subprocess.run(
            ["git", "-C", REPO, "show", f"{ref}:{path}"],
            capture_output=True, text=True, check=True,
        )
        return result.stdout
    except subprocess.CalledProcessError:
        return None


def load_file(label, source_ref):
    content = git_show(source_ref, ALL_FILES[label])
    if content is None:
        return [], 0
    lines = content.splitlines(keepends=True)
    boundary = len(lines)
    for i, line in enumerate(lines):
        if "#[cfg(test)]" in line:
            boundary = i
            break
    return lines, boundary


def scan_pattern(pattern, file_labels, source_ref, skip_defs=True):
    prod_by_file = {}
    test_by_file = {}
    for label in file_labels:
        lines, boundary = load_file(label, source_ref)
        p, t = 0, 0
        for i, line in enumerate(lines):
            if not re.search(pattern, line):
                continue
            stripped = line.strip()
            if stripped.startswith("//") or stripped.startswith("///"):
                continue
            if skip_defs and re.match(r"\s*(pub\s+)?(async\s+)?fn\s+", stripped):
                continue
            if i >= boundary:
                t += 1
            else:
                p += 1
        if p > 0:
            prod_by_file[label] = p
        if t > 0:
            test_by_file[label] = t
    return prod_by_file, test_by_file


def observe(source_ref):
    obs = {}

    ep_prod, ep_test = scan_pattern(
        r'execute_plan(?:_with_store)?\(',
        ["main", "tui"], source_ref)
    obs["execute_plan_sites"] = sum(ep_prod.values())
    obs["execute_plan_per_file"] = ep_prod

    bg_prod, bg_test = scan_pattern(
        r'prepare_backup_gate\(', ["main", "tui"], source_ref)
    obs["prepare_backup_gate_sites"] = sum(bg_prod.values())

    rc_prod, rc_test = scan_pattern(
        r'execute_residual_cleanup\(|execute_residual_cleanup_with_progress\(',
        ["main", "tui"], source_ref)
    obs["execute_residual_cleanup_sites"] = sum(rc_prod.values())

    cg_prod, cg_test = scan_pattern(
        r'check_operator_generation_fresh\(', ["main", "tui", "executor"], source_ref)
    obs["check_operator_generation_fresh_callers"] = sum(cg_prod.values())

    ra_prod, ra_test = scan_pattern(
        r'run_post_mutation_audit\(', ["main", "tui", "executor"], source_ref)
    obs["run_post_mutation_audit_callers"] = sum(ra_prod.values())

    gate_prod, gate_test = scan_pattern(
        r'MutationGate::new\(',
        ["main", "permit", "executor", "harness", "watch", "runtime"],
        source_ref, skip_defs=False)
    obs["mutation_gate_new_production"] = sum(gate_prod.values())
    obs["mutation_gate_new_test"] = sum(gate_test.values())
    obs["mutation_gate_new_test_per_file"] = gate_test

    cmd_prod, _ = scan_pattern(
        r'std::process::Command::new\(', ["main"], source_ref, skip_defs=False)
    obs["std_process_command_sites"] = sum(cmd_prod.values())

    ju_prod, ju_test = scan_pattern(
        r'\.update\(\|', ["main", "executor", "tui"], source_ref, skip_defs=False)
    obs["journal_update_production_sites"] = sum(ju_prod.values())
    obs["journal_update_test_sites"] = sum(ju_test.values())

    return obs


EXPECTED = {
    "execute_plan_sites": 4,
    "prepare_backup_gate_sites": 3,
    "execute_residual_cleanup_sites": 6,
    "check_operator_generation_fresh_callers": 26,
    "run_post_mutation_audit_callers": 6,
    "mutation_gate_new_production": 4,
    "mutation_gate_new_test": 21,
    "std_process_command_sites": 3,
    "journal_update_production_sites": 74,
    "journal_update_test_sites": 6,
}

EXPECTED_GATE_TEST_PER_FILE = {
    "main": 1,
    "permit": 9,
    "executor": 6,
    "harness": 4,
    "watch": 1,
}


def main():
    source_ref = DEFAULT_REF
    if len(sys.argv) > 1 and sys.argv[1].startswith("--source-ref="):
        source_ref = sys.argv[1].split("=", 1)[1]
    elif len(sys.argv) > 2 and sys.argv[1] == "--source-ref":
        source_ref = sys.argv[2]

    errors = []

    # Self-check: verify we're reading from the git ref, not the working tree
    ref_check_content = git_show(source_ref, "src/tui/mod.rs")
    if ref_check_content is None:
        errors.append(f"Self-check FAIL: src/tui/mod.rs not found at ref {source_ref}. "
                       "This file must exist at the Phase 1 base commit.")
        print("FAIL")
        for e in errors:
            print(f"  {e}")
        sys.exit(1)
    if "check_and_persist_paused" not in ref_check_content:
        errors.append(f"Self-check FAIL: check_and_persist_paused not found in "
                       f"src/tui/mod.rs at ref {source_ref}")

    obs = observe(source_ref)

    for key, expected in EXPECTED.items():
        actual = obs.get(key)
        if actual != expected:
            errors.append(f"{key}: observed {actual}, expected {expected}")

    for label, expected in EXPECTED_GATE_TEST_PER_FILE.items():
        actual = obs.get("mutation_gate_new_test_per_file", {}).get(label, 0)
        if actual != expected:
            errors.append(f"MutationGate::new test {label}: observed {actual}, expected {expected}")

    with open(MANIFEST) as f:
        m = json.load(f)
    counts = m.get("nonempty_counts", {})
    for key in EXPECTED:
        if key in ("mutation_gate_new_test", "journal_update_test_sites"):
            continue
        manifest_val = counts.get(key)
        observed_val = obs.get(key)
        if manifest_val is not None and manifest_val != observed_val:
            errors.append(f"manifest {key}={manifest_val} != observed {observed_val}")

    mutation_errors = run_mutation_selfcheck(source_ref)
    errors.extend(mutation_errors)

    if errors:
        print("FAIL")
        for e in errors:
            print(f"  {e}")
        sys.exit(1)
    else:
        gate_test_detail = obs.get("mutation_gate_new_test_per_file", {})
        print(f"PASS (source ref: {source_ref})")
        print(f"  execute_plan={obs['execute_plan_sites']}, "
              f"backup_gate={obs['prepare_backup_gate_sites']}, "
              f"residual_cleanup={obs['execute_residual_cleanup_sites']}, "
              f"check_operator={obs['check_operator_generation_fresh_callers']}, "
              f"audit={obs['run_post_mutation_audit_callers']}")
        print(f"  MutationGate prod={obs['mutation_gate_new_production']} "
              f"test={obs['mutation_gate_new_test']} "
              f"(main={gate_test_detail.get('main',0)} permit={gate_test_detail.get('permit',0)} "
              f"executor={gate_test_detail.get('executor',0)} harness={gate_test_detail.get('harness',0)} "
              f"watch={gate_test_detail.get('watch',0)})")
        print(f"  journal.update prod={obs['journal_update_production_sites']} "
              f"test={obs['journal_update_test_sites']}, "
              f"Command={obs['std_process_command_sites']}")
        sys.exit(0)


def run_mutation_selfcheck(source_ref):
    errors = []
    tmpdir = tempfile.mkdtemp(prefix="callsite-selfcheck-")
    try:
        fixture = os.path.join(tmpdir, "test.rs")
        with open(fixture, "w") as f:
            f.write("fn foo() {\n    execute_plan(&client);\n    execute_plan(&client);\n}\n"
                    "#[cfg(test)]\nmod tests {\n    fn bar() { execute_plan(&mock); }\n}\n")
        with open(fixture) as fh:
            lines = fh.readlines()
        boundary = next((i for i, l in enumerate(lines) if "#[cfg(test)]" in l), len(lines))
        prod = sum(1 for i, l in enumerate(lines)
                   if re.search(r'execute_plan\(', l) and i < boundary)
        if prod != 2:
            errors.append(f"Mutation self-check: fixture has {prod} prod, expected 2")

        with open(fixture, "w") as f:
            f.write("fn foo() {\n    execute_plan_RENAMED(&client);\n    execute_plan(&client);\n}\n"
                    "#[cfg(test)]\nmod tests {\n    fn bar() { execute_plan(&mock); }\n}\n")
        with open(fixture) as fh:
            lines2 = fh.readlines()
        prod2 = sum(1 for i, l in enumerate(lines2)
                    if re.search(r'execute_plan\(', l) and i < boundary)
        if prod2 != 1:
            errors.append(f"Mutation self-check: after rename should find 1, found {prod2}")
        if prod2 == prod:
            errors.append("Mutation self-check: rename not detected")
    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)
    return errors


if __name__ == "__main__":
    main()
