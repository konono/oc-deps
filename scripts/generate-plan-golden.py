#!/usr/bin/env python3
"""Generate plan-semantic-tuples.json golden from Cycle A v3 source plans."""
import json
import os
import sys

PLANS_DIR = os.path.join(
    os.path.dirname(__file__), "..",
    "logs/full-teardown-completion/phase-d-evidence/cycle-a-v3/plans",
)
OUTPUT_JSON = os.path.join(
    os.path.dirname(__file__), "..",
    "logs/teardown-workflow-refactor/phase-1/plan-semantic-tuples.json",
)
OUTPUT_MD = os.path.join(
    os.path.dirname(__file__), "..",
    "logs/teardown-workflow-refactor/phase-1/plan-semantic-tuples.md",
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


def is_explicit_match(resource, explicit_deletes):
    """Full identity match: group + kind + namespace + name + UID (when nonempty)."""
    for ed in explicit_deletes:
        if (ed.get("group", "") == resource.get("group", "")
                and ed["kind"] == resource["kind"]
                and ed.get("namespace", "") == resource.get("namespace", "")
                and ed["name"] == resource["name"]
                and bool(ed.get("uid")) and bool(resource.get("uid"))
                and ed["uid"] == resource["uid"]):
            return True
    return False


def process_plan(path):
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

    return resources, sorted_explicits


def validate_explicit_matching(resources, explicit_deletes, operator_name):
    errors = []
    for ed in explicit_deletes:
        matches = [
            r for r in resources
            if (r["action"] == "DELETE"
                and r["phase_name"] == "Explicit cleanup"
                and r.get("group", "") == ed.get("group", "")
                and r["kind"] == ed["kind"]
                and r["namespace"] == ed.get("namespace", "")
                and r["name"] == ed["name"]
                and (not ed.get("uid") or not r.get("uid")
                     or ed["uid"] == r["uid"]))
        ]
        if len(matches) != 1:
            errors.append(
                f"{operator_name}: explicit_delete {ed['kind']}/{ed['name']} "
                f"has {len(matches)} matching DELETE actions (expected 1)"
            )
    return errors


def main():
    golden = {}
    all_errors = []
    total_resources = 0
    total_explicits = 0
    action_totals = {}

    for filename in SOURCE_FILES:
        op_name = filename.replace(".json", "")
        path = os.path.join(PLANS_DIR, filename)
        if not os.path.exists(path):
            print(f"FAIL: source plan not found: {path}", file=sys.stderr)
            sys.exit(1)

        resources, explicits = process_plan(path)

        if not resources:
            all_errors.append(f"{op_name}: empty resource set")

        errors = validate_explicit_matching(resources, explicits, op_name)
        all_errors.extend(errors)

        # Reverse check: every explicit=true resource maps back to exactly one explicit_delete
        marked = [r for r in resources if r["explicit"]]
        for mr in marked:
            back_matches = [
                ed for ed in explicits
                if (ed.get("group", "") == mr.get("group", "")
                    and ed["kind"] == mr["kind"]
                    and ed.get("namespace", "") == mr.get("namespace", "")
                    and ed["name"] == mr["name"]
                    and (not ed.get("uid") or not mr.get("uid")
                         or ed["uid"] == mr["uid"]))
            ]
            if len(back_matches) != 1:
                all_errors.append(
                    f"{op_name}: explicit-marked {mr['kind']}/{mr['name']} "
                    f"maps to {len(back_matches)} explicit_deletes (expected 1)"
                )

        for r in resources:
            action_totals[r["action"]] = action_totals.get(r["action"], 0) + 1

        golden[op_name] = {
            "resources": resources,
            "explicit_deletes": explicits,
        }
        total_resources += len(resources)
        total_explicits += len(explicits)

    # Total marked resources must equal total explicit_deletes
    total_marked = sum(
        len([r for r in data["resources"] if r["explicit"]])
        for data in golden.values()
    )
    if total_marked != total_explicits:
        all_errors.append(
            f"total explicit-marked resources ({total_marked}) != "
            f"total explicit_deletes ({total_explicits})"
        )

    if all_errors:
        for e in all_errors:
            print(f"FAIL: {e}", file=sys.stderr)
        sys.exit(1)

    assert len(golden) == EXPECTED["operators"], \
        f"operators: {len(golden)} != {EXPECTED['operators']}"
    assert total_resources == EXPECTED["resources"], \
        f"resources: {total_resources} != {EXPECTED['resources']}"
    assert total_explicits == EXPECTED["explicit_deletes"], \
        f"explicit_deletes: {total_explicits} != {EXPECTED['explicit_deletes']}"
    for action, count in EXPECTED.items():
        if action in ("operators", "resources", "explicit_deletes"):
            continue
        assert action_totals.get(action, 0) == count, \
            f"{action}: {action_totals.get(action, 0)} != {count}"

    json_out = json.dumps(golden, indent=2, ensure_ascii=False) + "\n"
    os.makedirs(os.path.dirname(OUTPUT_JSON), exist_ok=True)
    with open(OUTPUT_JSON, "w") as f:
        f.write(json_out)

    # Generate markdown
    md = generate_markdown(golden, total_resources, total_explicits, action_totals)
    with open(OUTPUT_MD, "w") as f:
        f.write(md)

    print(f"Generated: {OUTPUT_JSON} ({total_resources} resources, "
          f"{total_explicits} explicit_deletes)")
    print(f"Generated: {OUTPUT_MD}")


def generate_markdown(golden, total_resources, total_explicits, action_totals):
    lines = [
        "# Plan Semantic Tuples — 15 Operators (Issue #46 Cycle A v3)",
        "",
        "Source: `logs/full-teardown-completion/phase-d-evidence/cycle-a-v3/plans/` (non-final files only)",
        "",
        "## Summary",
        "",
        f"- **Operators**: {len(golden)}",
        f"- **Total resources**: {total_resources}",
        f"- **Total explicit_deletes**: {total_explicits}",
        f"- **Action breakdown**: DELETE={action_totals.get('DELETE',0)}, "
        f"EXPECT={action_totals.get('EXPECT',0)}, "
        f"KEEP={action_totals.get('KEEP',0)}, "
        f"REVIEW={action_totals.get('REVIEW',0)}",
        "",
        "**Limitation**: ExecutionPlan v2 does not store `version` (apiVersion group version). "
        "The `version` field is `null` in all tuples.",
        "",
        "## Per-Operator Breakdown",
        "",
        "| # | Operator | Resources | Explicit | DELETE | EXPECT | KEEP | REVIEW | Phases |",
        "|---|----------|-----------|----------|--------|--------|------|--------|--------|",
    ]

    for i, (op, data) in enumerate(golden.items(), 1):
        res = data["resources"]
        exp = len(data["explicit_deletes"])
        ac = {}
        phases = set()
        for r in res:
            ac[r["action"]] = ac.get(r["action"], 0) + 1
            phases.add(r["phase"])
        phase_range = f"{min(phases)}..{max(phases)}" if phases else "—"
        lines.append(
            f"| {i} | {op} | {len(res)} | {exp} | "
            f"{ac.get('DELETE',0)} | {ac.get('EXPECT',0)} | "
            f"{ac.get('KEEP',0)} | {ac.get('REVIEW',0)} | {phase_range} |"
        )

    lines.extend(["", "## Explicit Deletes (10 targets)", ""])
    lines.append("| Operator | Kind | Namespace | Name | UID | Reason |")
    lines.append("|----------|------|-----------|------|-----|--------|")
    for op, data in golden.items():
        for ed in data["explicit_deletes"]:
            lines.append(
                f"| {op} | {ed['kind']} | {ed.get('namespace','')} | "
                f"{ed['name']} | {ed.get('uid','')[:12]}... | {ed.get('reason','')} |"
            )

    lines.extend(["", "## Resource Details", ""])
    for op, data in golden.items():
        lines.append(f"### {op} ({len(data['resources'])} resources)")
        lines.append("")
        lines.append("| Phase | Phase Name | Action | Kind | Namespace | Name | UID | Explicit |")
        lines.append("|-------|-----------|--------|------|-----------|------|-----|----------|")
        for r in data["resources"]:
            uid_short = (r["uid"][:12] + "...") if r["uid"] else "—"
            ns = r["namespace"] or "—"
            exp = "**yes**" if r["explicit"] else ""
            lines.append(
                f"| {r['phase']} | {r['phase_name']} | {r['action']} | "
                f"{r['kind']} | {ns} | {r['name']} | {uid_short} | {exp} |"
            )
        lines.append("")

    return "\n".join(lines) + "\n"


if __name__ == "__main__":
    main()
