#!/usr/bin/env python3
"""Validate plan-semantic-tuples.json golden against source plans.

Recomputes from the 15 non-final Cycle A v3 source plans and asserts:
- Byte equality with saved golden
- 15 nonempty operators, 343 resources, 10 explicit targets
- Action totals: DELETE=112, EXPECT=77, KEEP=136, REVIEW=18
- Real phase numbers (>= 1, not zero-based)
- Exact 1:1 explicit matching (each explicit_delete has one DELETE in Explicit cleanup)
"""
import hashlib
import json
import os
import sys

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
REPO_ROOT = os.path.join(SCRIPT_DIR, "..")

PLANS_DIR = os.path.join(
    REPO_ROOT,
    "logs/full-teardown-completion/phase-d-evidence/cycle-a-v3/plans",
)
GOLDEN_PATH = os.path.join(
    REPO_ROOT,
    "logs/teardown-workflow-refactor/phase-1/plan-semantic-tuples.json",
)

SOURCE_FILES = [
    "rhods-operator.json",
    "rhbk-operator.json",
    "leader-worker-set.json",
    "job-set.json",
    "kueue-operator.json",
    "servicemeshoperator3.json",
    "nfd.json",
    "gpu-operator-certified.json",
    "cert-manager-operator.json",
    "rhcl-operator.json",
    "authorino-operator.json",
    "dns-operator.json",
    "limitador-operator.json",
    "cluster-observability-operator.json",
    "opentelemetry-product.json",
]

EXPECTED = {
    "operators": 15,
    "resources": 343,
    "explicit_deletes": 10,
    "DELETE": 112,
    "EXPECT": 77,
    "KEEP": 136,
    "REVIEW": 18,
}

EXPECTED_PER_OP = {
    "rhods-operator": {"resources": 134, "explicit": 5},
    "rhbk-operator": {"resources": 10, "explicit": 1},
    "rhcl-operator": {"resources": 25, "explicit": 4},
}


def is_explicit_match(resource, explicit_deletes):
    for ed in explicit_deletes:
        if (ed["kind"] == resource["kind"]
                and ed.get("namespace", "") == resource.get("namespace", "")
                and ed["name"] == resource["name"]):
            return True
    return False


def recompute_golden():
    golden = {}
    for filename in SOURCE_FILES:
        op_name = filename.replace(".json", "")
        path = os.path.join(PLANS_DIR, filename)
        with open(path) as f:
            plan = json.load(f)

        explicit_deletes = plan.get("explicit_deletes", [])
        resources = []
        for phase in plan["phases"]:
            for r in phase["resources"]:
                resources.append({
                    "phase": phase["phase"],
                    "phase_name": phase["name"],
                    "action": r["action"],
                    "group": r["group"],
                    "version": None,
                    "kind": r["kind"],
                    "namespace": r.get("namespace", ""),
                    "name": r["name"],
                    "uid": r.get("uid", ""),
                    "explicit": is_explicit_match(r, explicit_deletes),
                })

        sorted_explicits = sorted(
            explicit_deletes,
            key=lambda e: (e["kind"], e.get("namespace", ""), e["name"]),
        )

        golden[op_name] = {
            "resources": resources,
            "explicit_deletes": sorted_explicits,
        }

    return golden


def main():
    failures = []

    # Recompute
    recomputed = recompute_golden()
    recomputed_bytes = json.dumps(recomputed, indent=2, ensure_ascii=False) + "\n"

    # Load saved golden
    with open(GOLDEN_PATH) as f:
        saved_bytes = f.read()

    # 1. Byte equality
    if recomputed_bytes != saved_bytes:
        r_hash = hashlib.sha256(recomputed_bytes.encode()).hexdigest()[:16]
        s_hash = hashlib.sha256(saved_bytes.encode()).hexdigest()[:16]
        failures.append(f"Byte equality: recomputed ({r_hash}) != saved ({s_hash})")

    saved = json.loads(saved_bytes)

    # 2. 15 nonempty operators
    if len(saved) != EXPECTED["operators"]:
        failures.append(f"Operators: {len(saved)} != {EXPECTED['operators']}")
    for op, data in saved.items():
        if not data["resources"]:
            failures.append(f"{op}: empty resource set")

    # 3. Total resources
    total_res = sum(len(d["resources"]) for d in saved.values())
    if total_res != EXPECTED["resources"]:
        failures.append(f"Total resources: {total_res} != {EXPECTED['resources']}")

    # 4. Total explicit_deletes
    total_exp = sum(len(d["explicit_deletes"]) for d in saved.values())
    if total_exp != EXPECTED["explicit_deletes"]:
        failures.append(f"Total explicit_deletes: {total_exp} != {EXPECTED['explicit_deletes']}")

    # 5. Action totals
    action_counts = {}
    for d in saved.values():
        for r in d["resources"]:
            action_counts[r["action"]] = action_counts.get(r["action"], 0) + 1
    for action in ("DELETE", "EXPECT", "KEEP", "REVIEW"):
        actual = action_counts.get(action, 0)
        expected = EXPECTED[action]
        if actual != expected:
            failures.append(f"{action}: {actual} != {expected}")

    # 6. Real phase numbers (>= 1)
    for op, data in saved.items():
        for r in data["resources"]:
            if r["phase"] < 1:
                failures.append(f"{op}: zero-based phase {r['phase']} for {r['kind']}/{r['name']}")
                break

    # 7. version is explicitly null
    for op, data in saved.items():
        for r in data["resources"]:
            if r["version"] is not None:
                failures.append(f"{op}: version is not null for {r['kind']}/{r['name']}")
                break

    # 8. Exact 1:1 explicit matching
    for op, data in saved.items():
        for ed in data["explicit_deletes"]:
            matches = [
                r for r in data["resources"]
                if (r["action"] == "DELETE"
                    and r["phase_name"] == "Explicit cleanup"
                    and r["kind"] == ed["kind"]
                    and r["namespace"] == ed.get("namespace", "")
                    and r["name"] == ed["name"])
            ]
            if len(matches) != 1:
                failures.append(
                    f"{op}: explicit {ed['kind']}/{ed['name']} has "
                    f"{len(matches)} matching DELETE (expected 1)"
                )

    # 9. Per-operator expected counts
    for op, exp in EXPECTED_PER_OP.items():
        if op not in saved:
            failures.append(f"{op}: missing from golden")
            continue
        actual_res = len(saved[op]["resources"])
        actual_exp = len(saved[op]["explicit_deletes"])
        if actual_res != exp["resources"]:
            failures.append(f"{op}: resources {actual_res} != {exp['resources']}")
        if actual_exp != exp["explicit"]:
            failures.append(f"{op}: explicit {actual_exp} != {exp['explicit']}")

    if failures:
        print("FAIL")
        for f in failures:
            print(f"  - {f}")
        sys.exit(1)
    else:
        print("PASS")
        print(f"  operators={len(saved)}, resources={total_res}, "
              f"explicit_deletes={total_exp}")
        print(f"  DELETE={action_counts.get('DELETE',0)}, "
              f"EXPECT={action_counts.get('EXPECT',0)}, "
              f"KEEP={action_counts.get('KEEP',0)}, "
              f"REVIEW={action_counts.get('REVIEW',0)}")
        print(f"  All phase numbers >= 1, version=null, 1:1 explicit matching")


if __name__ == "__main__":
    main()
