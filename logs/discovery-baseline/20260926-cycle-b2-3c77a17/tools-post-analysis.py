#!/usr/bin/env python3
"""Post-delete 3-layer analysis with physical UID classification.

Layers: raw observations -> physical UID entities -> API logical identities.
Consumes provider-api-operands.json for hard positive-oracle validation.
Synthetic fixture tests run before analysis. Evidence-based derived classification.
"""
import json, sys, os, hashlib
from collections import defaultdict

# ═══════════════════════════════════════════════════════════
#  Synthetic fixture tests (item 1)
# ═══════════════════════════════════════════════════════════
def bfs_closure(seeds, parent_to_children):
    """Production BFS from seed UIDs through parent→children. Used by analyzer and tests."""
    cl = set(seeds)
    q = list(seeds)
    while q:
        p = q.pop(0)
        for c in parent_to_children.get(p, set()):
            if c not in cl:
                cl.add(c)
                q.append(c)
    return cl


def build_entities(rows):
    """Production: raw rows → {uid: {obj, api_observations}}. Used by analyzer and tests."""
    ents = {}
    for r in rows:
        uid = r.get("uid")
        if not uid:
            continue
        obs = (r["group"], r["version"], r["kind"], r["resource"])
        if uid not in ents:
            ents[uid] = {"obj": r, "api_observations": [obs]}
        elif obs not in ents[uid]["api_observations"]:
            ents[uid]["api_observations"].append(obs)
    return ents


def build_logical(rows):
    """Production: raw rows → {(group,kind,ns,name): obj}. Used by analyzer and tests."""
    lg = {}
    for r in rows:
        k = (r["group"], r["kind"], r.get("namespace"), r["name"])
        if k not in lg:
            lg[k] = r
    return lg


def detect_recreated(pre_lg, post_lg, pre_ent, post_ent):
    """Production: find logical identities with different UID pre vs post."""
    recs = []
    for k in pre_lg:
        if k in post_lg:
            pu, qu = pre_lg[k].get("uid"), post_lg[k].get("uid")
            if pu and qu and pu != qu:
                recs.append({"group": k[0], "kind": k[1], "namespace": k[2], "name": k[3],
                             "pre_uid": pu, "post_uid": qu,
                             "pre_observations": sorted(pre_ent[pu]["api_observations"]) if pu in pre_ent else [],
                             "post_observations": sorted(post_ent[qu]["api_observations"]) if qu in post_ent else []})
    return recs


def null_fingerprint_groups(null_rows):
    """Production: group UID-null rows by stable fingerprint."""
    fps = defaultdict(list)
    for r in null_rows:
        fps[obs_fingerprint(r)].append(r)
    return fps


def run_synthetic_tests():
    """Fixture tests calling production helpers; fails nonzero on assertion error."""
    # (a) Diamond DAG via production bfs_closure
    p2c = defaultdict(set)
    p2c["S"].update(["A", "B"]); p2c["A"].add("C"); p2c["B"].add("C")
    cl = bfs_closure({"S"}, p2c)
    assert cl == {"S", "A", "B", "C"}, f"diamond DAG: {cl}"

    # (b) Cycle via production bfs_closure
    p2c2 = defaultdict(set); p2c2["A"].add("B"); p2c2["B"].add("A")
    cl2 = bfs_closure({"A"}, p2c2)
    assert cl2 == {"A", "B"}, f"cycle: {cl2}"

    # (c) Multi-group same UID via production build_entities
    rows = [
        {"group": "", "version": "v1", "kind": "Event", "resource": "events",
         "namespace": "ns", "name": "ev1", "uid": "uid-1"},
        {"group": "events.k8s.io", "version": "v1", "kind": "Event", "resource": "events",
         "namespace": "ns", "name": "ev1", "uid": "uid-1"},
    ]
    ents = build_entities(rows)
    assert len(ents) == 1, f"multi-group same UID: {len(ents)}"
    assert len(ents["uid-1"]["api_observations"]) == 2

    # (d) Recreated via production detect_recreated
    pre_rows = [{"group": "", "version": "v1", "kind": "ConfigMap", "resource": "configmaps",
                 "namespace": "ns", "name": "cm1", "uid": "old-uid"}]
    post_rows = [{"group": "", "version": "v1", "kind": "ConfigMap", "resource": "configmaps",
                  "namespace": "ns", "name": "cm1", "uid": "new-uid"}]
    recs = detect_recreated(build_logical(pre_rows), build_logical(post_rows),
                            build_entities(pre_rows), build_entities(post_rows))
    assert len(recs) == 1, f"recreated: {len(recs)}"

    # (e) UID-null fingerprint via production helpers
    pm1 = {"group": "packages.operators.coreos.com", "kind": "PackageManifest",
            "namespace": None, "name": "my-op", "labels": {"catalog": "redhat-operators"}}
    pm2 = {"group": "packages.operators.coreos.com", "kind": "PackageManifest",
            "namespace": None, "name": "my-op", "labels": {"catalog": "community-operators"}}
    fps = null_fingerprint_groups([pm1, pm2])
    assert len(fps) == 2, f"distinct fingerprints expected, got {len(fps)}"
    lk1 = (pm1["group"], pm1["kind"], pm1.get("namespace"), pm1["name"])
    lk2 = (pm2["group"], pm2["kind"], pm2.get("namespace"), pm2["name"])
    assert lk1 == lk2, "same logical key = name collision"

    # (f) Derived APIService: automanaged=false must NOT be proven
    assert_derived_apiservice_automanaged_false()
    # (g) Derived APIService: wrong version must NOT be proven
    assert_derived_apiservice_wrong_version()

    print("Synthetic fixture tests PASS (7/7)", file=sys.stderr)


def classify_derived_apiservice(obj, deleted_crds, catalog_gvrs):
    """Production: classify APIService disappearance as derived_side_effect or derived_candidate.
    Requires: automanaged=true label AND exact (group, version) in catalog served versions
    matching a deleted CRD's group."""
    labels = obj.get("labels") or {}
    automanaged = labels.get("kube-aggregator.kubernetes.io/automanaged") == "true"
    as_parts = obj["name"].split(".", 1)
    if len(as_parts) != 2:
        return {"type": "derived_candidate", "evidence": "APIService name not in version.group format"}
    as_version, as_group = as_parts[0], as_parts[1]
    if not automanaged:
        return {"type": "derived_candidate", "evidence": "automanaged!=true"}
    for cu, co in deleted_crds.items():
        crd_parts = co["name"].split(".", 1)
        if len(crd_parts) == 2 and crd_parts[1] == as_group:
            version_served = any(
                g["group"] == as_group and g["version"] == as_version
                for g in catalog_gvrs
            )
            if version_served:
                return {"type": "derived_side_effect",
                        "evidence": f"APIService {as_version}.{as_group} matches deleted CRD {co['name']}, automanaged=true, version served",
                        "automanaged_label": True, "version_served": True,
                        "related_crd": co["name"], "related_crd_uid": cu}
            else:
                return {"type": "derived_candidate",
                        "evidence": f"version {as_version} not in catalog for {as_group}"}
    return {"type": "derived_candidate", "evidence": "no deleted CRD group match"}


def assert_derived_apiservice_automanaged_false():
    obj = {"kind": "APIService", "name": "v1alpha2.jobset.x-k8s.io",
           "labels": {}}  # no automanaged
    crds = {"crd-uid": {"name": "jobsets.jobset.x-k8s.io"}}
    cat = [{"group": "jobset.x-k8s.io", "version": "v1alpha2", "resource": "jobsets"}]
    result = classify_derived_apiservice(obj, crds, cat)
    assert result["type"] == "derived_candidate", f"automanaged=false must be candidate: {result}"


def assert_derived_apiservice_wrong_version():
    obj = {"kind": "APIService", "name": "v99.jobset.x-k8s.io",
           "labels": {"kube-aggregator.kubernetes.io/automanaged": "true"}}
    crds = {"crd-uid": {"name": "jobsets.jobset.x-k8s.io"}}
    cat = [{"group": "jobset.x-k8s.io", "version": "v1alpha2", "resource": "jobsets"}]
    result = classify_derived_apiservice(obj, crds, cat)
    assert result["type"] == "derived_candidate", f"wrong version must be candidate: {result}"


def obs_fingerprint(obj):
    labels = obj.get("labels") or {}
    parts = [obj["group"], obj["kind"], obj.get("namespace", ""), obj["name"]]
    parts += sorted(f"{k}={v}" for k, v in labels.items())
    return hashlib.sha256("|".join(str(p) for p in parts).encode()).hexdigest()[:24]


def main():
    if len(sys.argv) < 6:
        print("Usage: post-analysis.py <pre.jsonl> <post.jsonl> <batch-plans-dir> <provider-api-operands.json> <gvr-catalog.json> [output.json]", file=sys.stderr)
        sys.exit(1)
    pre_path, post_path, plans_dir, provider_path, catalog_path = sys.argv[1:6]
    out_path = sys.argv[6] if len(sys.argv) > 6 else "post-analysis.json"

    catalog_data = json.load(open(catalog_path))
    catalog_gvrs = catalog_data.get("gvrs", [])

    run_synthetic_tests()

    # ── Load raw ──
    pre_rows = [json.loads(l) for l in open(pre_path)]
    post_rows = [json.loads(l) for l in open(post_path)]
    layer_raw = {"pre": len(pre_rows), "post": len(post_rows)}

    # ── UID-null dual reporting ──
    pre_null = [r for r in pre_rows if not r.get("uid")]
    post_null = [r for r in post_rows if not r.get("uid")]
    pre_null_by_lk = defaultdict(list)
    for r in pre_null:
        pre_null_by_lk[(r["group"], r["kind"], r.get("namespace"), r["name"])].append(r)
    logical_name_collisions = {k: v for k, v in pre_null_by_lk.items() if len(v) > 1}
    pre_null_fps = null_fingerprint_groups(pre_null)
    post_null_fps = null_fingerprint_groups(post_null)
    fp_collision_groups = {fp: rs for fp, rs in pre_null_fps.items() if len(rs) > 1}

    # ── Physical UID entities (production helper) ──
    pre_ent = build_entities(pre_rows)
    post_ent = build_entities(post_rows)
    removed_uids = set(pre_ent) - set(post_ent)
    added_uids = set(post_ent) - set(pre_ent)

    # ── Logical identities (production helper) ──
    pre_lg = build_logical(pre_rows)
    post_lg = build_logical(post_rows)
    lg_gone = {k for k in pre_lg if k not in post_lg}
    lg_new = {k for k in post_lg if k not in pre_lg}

    # ── Recreated (production helper) ──
    recreated = detect_recreated(pre_lg, post_lg, pre_ent, post_ent)
    recreated_phys = len({r["pre_uid"] for r in recreated})

    # ── Plan actions by UID ──
    def parse_order(fn):
        try: return int(fn.split("-")[0])
        except: return 999

    uid_actions = defaultdict(list)
    logical_plan_ops = defaultdict(set)
    logical_plan_actions = defaultdict(list)  # logical key -> list of action entries
    for pf in sorted(os.listdir(plans_dir), key=parse_order):
        if not pf.endswith(".json"): continue
        order = parse_order(pf)
        op = pf.replace(".json", "").split("-", 1)[-1] if "-" in pf else pf.replace(".json", "")
        try: plan = json.load(open(os.path.join(plans_dir, pf)))
        except: continue
        for phase in plan.get("phases", []):
            for res in phase.get("resources", []):
                uid = res.get("uid")
                if uid:
                    uid_actions[uid].append({"action": res["action"], "operator": op, "order": order, "phase": phase.get("name", "")})
                lk = (res.get("group", ""), res["kind"], res.get("namespace"), res["name"])
                logical_plan_ops[lk].add(op)
                logical_plan_actions[lk].append({"action": res["action"], "operator": op, "order": order})

    uid_effective = {}
    for uid, acts in uid_actions.items():
        acts.sort(key=lambda a: a["order"])
        dels = [a for a in acts if a["action"] == "DELETE"]
        uid_effective[uid] = dels[0] if dels else acts[-1]

    # ── Collision metrics (item B: 4 distinct metrics) ──
    uid_with_multiple_actions = sum(1 for v in uid_actions.values() if len(v) > 1)
    uid_used_by_multiple_ops = sum(1 for v in uid_actions.values() if len({a["operator"] for a in v}) > 1)
    logical_with_multiple_actions = sum(1 for v in logical_plan_actions.values() if len(v) > 1)
    logical_used_by_multiple_ops = sum(1 for v in logical_plan_ops.values() if len(v) > 1)

    # ── BFS closure (production helper) ──
    del_uids = {u for u in removed_uids if u in uid_effective and uid_effective[u]["action"] == "DELETE"}
    exp_uids = {u for u in removed_uids if u in uid_effective and uid_effective[u]["action"] == "EXPECT" and u not in del_uids}

    p2c = defaultdict(set)
    for uid, ent in pre_ent.items():
        for oref in (ent["obj"].get("ownerReferences") or []):
            puid = oref.get("uid")
            if puid:
                p2c[puid].add(uid)

    closure = bfs_closure(del_uids, p2c)
    descendants = closure & removed_uids - del_uids - exp_uids
    removed_in_closure = closure & removed_uids

    # ── Classification ──
    owner_unlinked = set()
    derived = {}
    deleted_pvc_uids = {u for u in removed_uids if pre_ent[u]["obj"]["kind"] == "PersistentVolumeClaim"}
    deleted_crds = {u: pre_ent[u]["obj"] for u in removed_uids if pre_ent[u]["obj"]["kind"] == "CustomResourceDefinition"}

    for uid in removed_uids:
        if uid in del_uids or uid in exp_uids or uid in closure: continue
        obj = pre_ent[uid]["obj"]
        owners = obj.get("ownerReferences") or []
        if any(oref.get("uid") in removed_uids for oref in owners if oref.get("uid")):
            owner_unlinked.add(uid); continue
        if obj["kind"] == "PersistentVolume":
            # Require exact: PV name == "pvc-" + deleted PVC UID
            matched = [u for u in deleted_pvc_uids if obj["name"] == f"pvc-{u}"]
            if matched:
                derived[uid] = {"type": "derived_side_effect",
                                "evidence": "PV name == pvc-{PVC_UID}",
                                "related_pvc_uid": matched[0],
                                "limitation": "claimRef/reclaimPolicy not captured in metadata-only inventory"}
                continue
            else:
                derived[uid] = {"type": "derived_candidate",
                                "evidence": "PV disappeared without exact PVC UID name match"}
                continue
        if obj["kind"] == "APIService":
            derived[uid] = classify_derived_apiservice(obj, deleted_crds, catalog_gvrs)
            continue
    # Reclassify derived_candidate vs derived_side_effect
    proven_derived = {u for u, d in derived.items() if d["type"] == "derived_side_effect"}
    candidate_derived = {u for u, d in derived.items() if d["type"] == "derived_candidate"}

    other = removed_uids - del_uids - exp_uids - descendants - owner_unlinked - set(derived)

    # ── Protected ──
    prot_kinds = {"Namespace", "PersistentVolume", "PersistentVolumeClaim", "CustomResourceDefinition", "APIService"}
    protected = []
    for uid in removed_uids:
        obj = pre_ent[uid]["obj"]
        if obj["kind"] not in prot_kinds or uid in del_uids: continue
        cat = "planned_ownerref_descendant" if uid in descendants else \
              derived.get(uid, {}).get("type", "other") if uid in derived else "other"
        protected.append({"kind": obj["kind"], "name": obj["name"], "namespace": obj.get("namespace"),
                          "uid": uid, "classification": cat, "ownerReferences": obj.get("ownerReferences"),
                          "derived_evidence": derived.get(uid)})

    # ── Terminating ──
    pre_term = {u for u, e in pre_ent.items() if e["obj"].get("deletionTimestamp")}
    post_term = {u for u, e in post_ent.items() if e["obj"].get("deletionTimestamp")}
    new_term = post_term - pre_term; kept_term = post_term & pre_term
    term_details = [{"kind": post_ent[u]["obj"]["kind"], "name": post_ent[u]["obj"]["name"],
                     "namespace": post_ent[u]["obj"].get("namespace"), "uid": u,
                     "deletionTimestamp": post_ent[u]["obj"]["deletionTimestamp"],
                     "finalizers": post_ent[u]["obj"].get("finalizers"), "preexisting": u in kept_term}
                    for u in post_term]

    # ── Orphans ──
    orphans = []
    for uid, ent in post_ent.items():
        if ent["obj"].get("deletionTimestamp"): continue
        for oref in (ent["obj"].get("ownerReferences") or []):
            ou = oref.get("uid")
            if ou and ou in removed_uids:
                orphans.append({"kind": ent["obj"]["kind"], "name": ent["obj"]["name"],
                                "namespace": ent["obj"].get("namespace"), "uid": uid,
                                "deleted_owner_kind": oref["kind"], "deleted_owner_name": oref["name"],
                                "deleted_owner_uid": ou})

    # ── Provider operand hard validation (items 2, 7) ──
    provider_data = json.load(open(provider_path))
    assert provider_data.get("schema_version") == 2, "provider operand schema_version must be 2"
    provider_cases = provider_data["cases"]
    provider_errors = []
    if len(provider_cases) != 25:
        provider_errors.append(f"expected 25 provider operand cases, got {len(provider_cases)}")

    plans_base = os.path.join(os.path.dirname(pre_path), "..", "plans")
    provider_results = []
    for gc in provider_cases:
        k = (gc["group"], gc["kind"], gc.get("namespace"), gc["name"])
        pre_obj = pre_lg.get(k)
        if not pre_obj:
            provider_errors.append(f"ABSENT from pre: {gc['kind']}/{gc['name']}"); continue
        pre_uid = pre_obj.get("uid")
        if pre_uid != gc.get("uid"):
            provider_errors.append(f"UID mismatch for {gc['kind']}/{gc['name']}: fixture={gc.get('uid','?')[:12]} pre={pre_uid[:12] if pre_uid else '?'}")
        # Check initial plan has DELETE
        initial_has_del = False
        for pf in os.listdir(plans_base):
            if gc["api_provider_operator"] in pf and pf.endswith(".json"):
                try:
                    pl = json.load(open(os.path.join(plans_base, pf)))
                    for ph in pl.get("phases", []):
                        for r in ph.get("resources", []):
                            rk = (r.get("group", ""), r["kind"], r.get("namespace"), r["name"])
                            if rk == k and r["action"] == "DELETE": initial_has_del = True
                except: pass
        if not initial_has_del:
            provider_errors.append(f"initial plan {gc['api_provider_operator']} has no DELETE for {gc['kind']}/{gc['name']}")
        if gc.get("initial_action") != "DELETE":
            provider_errors.append(f"provider operand initial_action must be DELETE for {gc['kind']}/{gc['name']}, got {gc.get('initial_action')}")
        if gc.get("approval_scope") != "independent":
            provider_errors.append(f"approval_scope must be independent for {gc['kind']}/{gc['name']}")
        if gc.get("expected_full_teardown_decision") != "DELETE":
            provider_errors.append(f"full teardown decision must be DELETE for {gc['kind']}/{gc['name']}")
        if gc.get("expected_without_independent_approval") != "REVIEW":
            provider_errors.append(f"unapproved decision must be REVIEW for {gc['kind']}/{gc['name']}")
        pe = gc.get("provider_api_evidence") or {}
        if pe.get("type") != "CsvOwnedCrd" or not pe.get("crd"):
            provider_errors.append(f"missing CsvOwnedCrd provider evidence for {gc['kind']}/{gc['name']}")
        # Validate version against pre
        if gc.get("version") and gc["version"] != "unknown":
            if pre_obj.get("version") and pre_obj["version"] != gc["version"]:
                provider_errors.append(f"version mismatch for {gc['kind']}/{gc['name']}: fixture={gc['version']} pre={pre_obj['version']}")
        # Validate observedVersions against all pre observations for this UID
        if gc.get("observedVersions") and pre_uid and pre_uid in pre_ent:
            actual_obs = sorted(set(f"{g}/{v}" for g, v, _, _ in pre_ent[pre_uid]["api_observations"]))
            fixture_obs = sorted(gc["observedVersions"])
            if actual_obs != fixture_obs:
                provider_errors.append(f"observedVersions mismatch for {gc['kind']}/{gc['name']}: fixture={fixture_obs} actual={actual_obs}")
        # Validate evidence — full ownerRef fields
        ev = gc.get("lifecycle_owner_evidence", {})
        if "ownerRef" in ev:
            pre_owners = pre_obj.get("ownerReferences") or []
            oref_ev = ev["ownerRef"]
            match = any(
                o.get("uid") == oref_ev.get("uid") and
                o.get("kind") == oref_ev.get("kind") and
                o.get("name") == oref_ev.get("name") and
                (oref_ev.get("apiVersion") is None or o.get("apiVersion") == oref_ev.get("apiVersion")) and
                (oref_ev.get("controller") is None or o.get("controller") == oref_ev.get("controller"))
                for o in pre_owners
            )
            if not match:
                provider_errors.append(f"ownerRef evidence mismatch for {gc['kind']}/{gc['name']}: expected {oref_ev}")
        if "managed_by_label" in ev:
            pre_labels = pre_obj.get("labels") or {}
            if pre_labels.get("app.kubernetes.io/managed-by") != ev["managed_by_label"]:
                provider_errors.append(f"managed-by label mismatch for {gc['kind']}/{gc['name']}")
        if "route_rule_annotations" in ev:
            pre_annots = pre_obj.get("annotations") or {}
            for rk in ev["route_rule_annotations"]:
                if rk not in pre_annots:
                    provider_errors.append(f"RouteRule annotation {rk} missing for {gc['kind']}/{gc['name']}")
        # Physical disappearance cause (item 7)
        phys_cause = "unknown"
        if pre_uid in del_uids:
            rt = uid_effective.get(pre_uid)
            phys_cause = f"direct_delete_by_{rt['operator']}" if rt else "direct_delete"
        elif pre_uid in descendants: phys_cause = "planned_ownerref_descendant"
        elif pre_uid in owner_unlinked: phys_cause = "owner_disappeared_unlinked"
        elif pre_uid in derived: phys_cause = derived[pre_uid]["type"]
        elif k not in post_lg: phys_cause = "removed_by_other_or_controller_cleanup"
        # Full-teardown correctness: provider API operand DELETE is expected when independent scope is explicitly approved
        plan_correct = "expected_provider_operand_cleanup"
        provider_results.append({**gc, "in_pre": True, "pre_uid_match": pre_uid == gc.get("uid"),
                               "in_post": k in post_lg, "initial_plan_has_delete": initial_has_del,
                               "physical_disappearance_cause": phys_cause,
                               "initial_plan_correctness": plan_correct,
                               "action_history": uid_actions.get(pre_uid, [])})

    if provider_errors:
        print("PROVIDER OPERAND VALIDATION FAILED:", file=sys.stderr)
        for e in provider_errors: print(f"  {e}", file=sys.stderr)
        sys.exit(1)
    print(f"Provider operand hard validation PASS ({len(provider_cases)} cases)", file=sys.stderr)

    # ── Corpus invariants ──
    total = len(del_uids) + len(exp_uids) + len(descendants) + len(owner_unlinked) + len(derived) + len(other)
    inv_errors = []
    if total != len(removed_uids): inv_errors.append(f"sum {total} != removed {len(removed_uids)}")
    if len(closure) != 1460: inv_errors.append(f"closure {len(closure)} != 1460")
    if len(removed_in_closure) != 1445: inv_errors.append(f"removed_in_closure {len(removed_in_closure)} != 1445")
    if len(descendants) != 1282: inv_errors.append(f"descendants {len(descendants)} != 1282")
    if len(del_uids) != 91: inv_errors.append(f"delete {len(del_uids)} != 91")
    if len(exp_uids) != 72: inv_errors.append(f"expect {len(exp_uids)} != 72")
    if inv_errors:
        print("INVARIANT FAILURES:", file=sys.stderr)
        for e in inv_errors: print(f"  {e}", file=sys.stderr)
        sys.exit(1)
    print("Corpus invariants PASS", file=sys.stderr)

    # ── Output ──
    report = {
        "layers": {
            "raw": layer_raw,
            "logical": {"pre": len(pre_lg), "post": len(post_lg), "disappeared": len(lg_gone), "appeared": len(lg_new)},
            "physical_uid": {"pre": len(pre_ent), "post": len(post_ent), "removed": len(removed_uids), "added": len(added_uids)},
            "uid_null": {"pre_observations": len(pre_null), "post_observations": len(post_null),
                         "logical_name_collisions": len(logical_name_collisions),
                         "fingerprint_collision_groups": len(fp_collision_groups),
                         "removed_fingerprints": len(set(pre_null_fps) - set(post_null_fps)),
                         "added_fingerprints": len(set(post_null_fps) - set(pre_null_fps))},
        },
        "recreated": {"physical_objects": recreated_phys, "api_logical_identities": len(recreated), "details": recreated},
        "physical_uid_classification": {
            "direct_delete": len(del_uids), "expect_gone": len(exp_uids),
            "planned_ownerref_descendant": len(descendants),
            "owner_disappeared_unlinked": len(owner_unlinked),
            "derived_side_effect": len(proven_derived),
            "derived_candidate": len(candidate_derived),
            "other_removed": len(other),
        },
        "closure": {"delete_seed": len(del_uids), "total": len(closure), "removed_in_closure": len(removed_in_closure)},
        "cross_operator_collisions": {
            "uid_with_multiple_action_entries": uid_with_multiple_actions,
            "uid_used_by_multiple_operators": uid_used_by_multiple_ops,
            "logical_identity_with_multiple_action_entries": logical_with_multiple_actions,
            "logical_identity_used_by_multiple_operators": logical_used_by_multiple_ops,
        },
        "protected_transitive_deletions": protected,
        "terminating": {"newly_terminating": len(new_term), "preexisting_retained": len(kept_term), "details": term_details},
        "orphan_ownerrefs_non_terminating": orphans,
        "provider_api_operands": {"total": len(provider_results), "results": provider_results},
        "derived_evidence": dict(sorted(derived.items())),
    }
    # Deterministic sort all list fields
    def sort_key(obj):
        return (obj.get("kind",""), obj.get("namespace",""), obj.get("name",""), obj.get("uid",""))

    protected.sort(key=sort_key)
    term_details.sort(key=sort_key)
    orphans.sort(key=sort_key)
    provider_results.sort(key=lambda g: (g.get("api_provider_operator",""), g.get("kind",""), g.get("name","")))
    recreated.sort(key=lambda r: (r.get("kind",""), r.get("namespace",""), r.get("name","")))
    for uid in pre_ent:
        pre_ent[uid]["api_observations"] = sorted(pre_ent[uid]["api_observations"])
    for uid in post_ent:
        post_ent[uid]["api_observations"] = sorted(post_ent[uid]["api_observations"])

    json.dump(report, open(out_path, "w"), indent=2, sort_keys=False)

    # ── Summary ──
    print(f"\n=== 3-Layer Summary ===", file=sys.stderr)
    print(f"Raw: {layer_raw['pre']} -> {layer_raw['post']}", file=sys.stderr)
    print(f"Logical: {len(pre_lg)} -> {len(post_lg)} ({len(lg_gone)} gone, {len(lg_new)} new)", file=sys.stderr)
    print(f"Physical UID: {len(pre_ent)} -> {len(post_ent)} ({len(removed_uids)} removed, {len(added_uids)} added)", file=sys.stderr)
    print(f"UID-null: {len(pre_null)} -> {len(post_null)}, logical collisions={len(logical_name_collisions)}, fp collisions={len(fp_collision_groups)}", file=sys.stderr)
    print(f"Recreated: {recreated_phys} physical, {len(recreated)} API identities", file=sys.stderr)
    cats = report["physical_uid_classification"]
    for c in cats: print(f"  {c}: {cats[c]}", file=sys.stderr)
    print(f"Closure: seed={len(del_uids)}, total={len(closure)}, removed_in_closure={len(removed_in_closure)}", file=sys.stderr)
    print(f"Collisions: uid_actions={uid_with_multiple_actions}, uid_ops={uid_used_by_multiple_ops}, logical_actions={logical_with_multiple_actions}, logical_ops={logical_used_by_multiple_ops}", file=sys.stderr)
    print(f"Protected transitive: {len(protected)}", file=sys.stderr)
    print(f"Terminating: newly={len(new_term)}, preexisting={len(kept_term)}", file=sys.stderr)
    print(f"Orphan non-terminating: {len(orphans)}", file=sys.stderr)
    print(f"Provider operands: {len(provider_results)} validated", file=sys.stderr)
    print(f"Saved to {out_path}", file=sys.stderr)


if __name__ == "__main__":
    main()
