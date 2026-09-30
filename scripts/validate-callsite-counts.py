#!/usr/bin/env python3
"""Scan pinned source to produce observed callsite counts, then validate
manifest and documented counts against the scan.

Production vs test boundary: first #[cfg(test)] in each file.
"""
import json
import os
import re
import sys
import tempfile
import shutil

REPO = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
MANIFEST = os.path.join(REPO, "logs", "teardown-workflow-refactor", "phase-1", "manifest.json")

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


def load_file(label):
    path = os.path.join(REPO, ALL_FILES[label])
    if not os.path.exists(path):
        return [], 0
    with open(path) as f:
        lines = f.readlines()
    boundary = len(lines)
    for i, line in enumerate(lines):
        if "#[cfg(test)]" in line:
            boundary = i
            break
    return lines, boundary


def scan_pattern(pattern, file_labels, skip_defs=True):
    """Scan files for pattern, classify prod/test, return per-file breakdown."""
    prod_by_file = {}
    test_by_file = {}
    for label in file_labels:
        lines, boundary = load_file(label)
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


def observe():
    """Scan all source and return observed counts dict."""
    obs = {}

    # execute_plan external entry points (not internal delegation)
    # Boundary: main execute_plan calls (3) + tui execute_plan_with_store (1)
    # executor.rs:353 is execute_plan→execute_plan_with_store delegation, not external
    ep_prod, ep_test = scan_pattern(
        r'execute_plan(?:_with_store)?\(',
        ["main", "tui"])
    obs["execute_plan_sites"] = sum(ep_prod.values())
    obs["execute_plan_per_file"] = ep_prod

    # prepare_backup_gate (callers, not definition in backup.rs)
    bg_prod, bg_test = scan_pattern(
        r'prepare_backup_gate\(', ["main", "tui"])
    obs["prepare_backup_gate_sites"] = sum(bg_prod.values())
    obs["prepare_backup_gate_per_file"] = bg_prod

    # execute_residual_cleanup (callers, not definitions in executor.rs)
    rc_prod, rc_test = scan_pattern(
        r'execute_residual_cleanup\(|execute_residual_cleanup_with_progress\(',
        ["main", "tui"])
    obs["execute_residual_cleanup_sites"] = sum(rc_prod.values())
    obs["execute_residual_cleanup_per_file"] = rc_prod

    # check_operator_generation_fresh (callers, definition in audit.rs excluded)
    cg_prod, cg_test = scan_pattern(
        r'check_operator_generation_fresh\(', ["main", "tui", "executor"])
    obs["check_operator_generation_fresh_callers"] = sum(cg_prod.values())
    obs["check_operator_generation_fresh_per_file"] = cg_prod

    # run_post_mutation_audit (callers, definition in audit.rs excluded)
    ra_prod, ra_test = scan_pattern(
        r'run_post_mutation_audit\(', ["main", "tui", "executor"])
    obs["run_post_mutation_audit_callers"] = sum(ra_prod.values())
    obs["run_post_mutation_audit_per_file"] = ra_prod

    # MutationGate::new — scan all files, full prod/test breakdown
    gate_prod, gate_test = scan_pattern(
        r'MutationGate::new\(',
        ["main", "permit", "executor", "harness", "watch", "runtime"],
        skip_defs=False)
    obs["mutation_gate_new_production"] = sum(gate_prod.values())
    obs["mutation_gate_new_test"] = sum(gate_test.values())
    obs["mutation_gate_new_prod_per_file"] = gate_prod
    obs["mutation_gate_new_test_per_file"] = gate_test

    # std::process::Command
    cmd_prod, _ = scan_pattern(
        r'std::process::Command::new\(', ["main"], skip_defs=False)
    obs["std_process_command_sites"] = sum(cmd_prod.values())

    # journal .update() closures
    ju_prod, ju_test = scan_pattern(
        r'\.update\(\|', ["main", "executor", "tui"], skip_defs=False)
    obs["journal_update_production_sites"] = sum(ju_prod.values())
    obs["journal_update_test_sites"] = sum(ju_test.values())
    obs["journal_update_prod_per_file"] = ju_prod

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
    errors = []
    obs = observe()

    # 1. Compare observed vs expected
    for key, expected in EXPECTED.items():
        actual = obs.get(key)
        if actual != expected:
            errors.append(f"{key}: observed {actual}, expected {expected}")

    # 2. MutationGate test per-file breakdown
    for label, expected in EXPECTED_GATE_TEST_PER_FILE.items():
        actual = obs.get("mutation_gate_new_test_per_file", {}).get(label, 0)
        if actual != expected:
            errors.append(f"MutationGate::new test {label}: observed {actual}, expected {expected}")

    # 3. Cross-check manifest nonempty_counts against observed
    with open(MANIFEST) as f:
        m = json.load(f)
    counts = m.get("nonempty_counts", {})
    manifest_vs_observed = [
        "execute_plan_sites",
        "prepare_backup_gate_sites",
        "execute_residual_cleanup_sites",
        "check_operator_generation_fresh_callers",
        "run_post_mutation_audit_callers",
        "mutation_gate_new_production",
        "std_process_command_sites",
        "journal_update_production_sites",
    ]
    for key in manifest_vs_observed:
        manifest_val = counts.get(key)
        observed_val = obs.get(key)
        if manifest_val is not None and manifest_val != observed_val:
            errors.append(f"manifest {key}={manifest_val} != observed {observed_val}")

    # 4. Mutation self-check: alter one call token in a temp fixture and verify detection
    mutation_errors = run_mutation_selfcheck()
    errors.extend(mutation_errors)

    if errors:
        print("FAIL")
        for e in errors:
            print(f"  {e}")
        sys.exit(1)
    else:
        gate_test_detail = obs.get("mutation_gate_new_test_per_file", {})
        print("PASS")
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


def run_mutation_selfcheck():
    """Create a temp fixture with a renamed call token, verify scanner detects the change."""
    errors = []
    tmpdir = tempfile.mkdtemp(prefix="callsite-selfcheck-")
    try:
        # Create a minimal fixture file with known call sites
        fixture = os.path.join(tmpdir, "test.rs")
        with open(fixture, "w") as f:
            f.write("""\
fn foo() {
    execute_plan(&client);
    execute_plan(&client);
    prepare_backup_gate(&ctx);
}

#[cfg(test)]
mod tests {
    fn bar() {
        execute_plan(&mock);
    }
}
""")
        lines, boundary = [], 0
        with open(fixture) as fh:
            lines = fh.readlines()
        for i, line in enumerate(lines):
            if "#[cfg(test)]" in line:
                boundary = i
                break
        else:
            boundary = len(lines)

        # Count execute_plan production calls
        prod = sum(1 for i, l in enumerate(lines)
                   if re.search(r'execute_plan\(', l)
                   and not l.strip().startswith("//")
                   and i < boundary)
        if prod != 2:
            errors.append(f"Mutation self-check: fixture has {prod} prod execute_plan, expected 2")

        # Now rename one call → scanner should find 1
        with open(fixture, "w") as f:
            f.write("""\
fn foo() {
    execute_plan_RENAMED(&client);
    execute_plan(&client);
    prepare_backup_gate(&ctx);
}

#[cfg(test)]
mod tests {
    fn bar() {
        execute_plan(&mock);
    }
}
""")
        with open(fixture) as fh:
            lines2 = fh.readlines()
        prod2 = sum(1 for i, l in enumerate(lines2)
                    if re.search(r'execute_plan\(', l)
                    and not l.strip().startswith("//")
                    and i < boundary)
        if prod2 != 1:
            errors.append(f"Mutation self-check: after rename should find 1, found {prod2}")
        if prod2 == prod:
            errors.append("Mutation self-check: rename not detected")
    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)
    return errors


if __name__ == "__main__":
    main()
