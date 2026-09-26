#!/usr/bin/env python3
"""Parse post spec-ref map for edges pointing to physically removed pre identities.
Outputs dangling reference summary with exact source/target/path records."""
import json, sys

if len(sys.argv) < 4:
    print("Usage: parse-specref-dangling.py <specref-map.json> <pre.jsonl> <post.jsonl> [output.json]", file=sys.stderr)
    sys.exit(1)

map_path, pre_path, post_path = sys.argv[1:4]
out_path = sys.argv[4] if len(sys.argv) > 4 else "post-specref-dangling.json"

# Build removed pre identity set by (kind, ns, name)
pre_by_knn = {}
for line in open(pre_path):
    obj = json.loads(line)
    uid = obj.get("uid")
    if uid:
        knn = (obj["kind"], obj.get("namespace"), obj["name"])
        if knn not in pre_by_knn:
            pre_by_knn[knn] = uid

post_uids = set()
for line in open(post_path):
    obj = json.loads(line)
    uid = obj.get("uid")
    if uid:
        post_uids.add(uid)

removed_pre = {knn: uid for knn, uid in pre_by_knn.items() if uid not in post_uids}
print(f"Removed pre identities (kind,ns,name): {len(removed_pre)}", file=sys.stderr)

# Parse spec-ref map
data = json.load(open(map_path))
namespaces = data.get("namespaces", [])

# Flatten trees into edges: source -> target via fieldPath
def flatten_tree(node, ns, edges):
    """Extract specRefs only (outgoing spec-field references from this node).
    referencedBy is excluded: it is reverse presentation of live targets,
    can double-count, and lacks source UID."""
    source = {"kind": node.get("kind"), "namespace": node.get("namespace", ns),
              "name": node.get("name"), "uid": node.get("uid")}
    for ref in node.get("specRefs", []):
        edge = {
            "source": source,
            "target": {"kind": ref.get("kind"), "namespace": ref.get("namespace", ns),
                       "name": ref.get("name")},
            "fieldPath": ref.get("fieldPath", ""),
            "refSource": ref.get("source", "typed"),
        }
        edges.append(edge)
    for child in node.get("children", []):
        flatten_tree(child, ns, edges)

all_edges = []
for ns_entry in namespaces:
    ns = ns_entry.get("namespace", "")
    for tree in ns_entry.get("trees", []):
        flatten_tree(tree, ns, all_edges)

# Dedup by (source_uid, target_kind, target_ns, target_name, fieldPath)
seen = set()
unique_edges = []
for e in all_edges:
    key = (e["source"].get("uid",""), e["target"]["kind"], e["target"].get("namespace",""),
           e["target"]["name"], e["fieldPath"])
    if key not in seen:
        seen.add(key)
        unique_edges.append(e)

typed = sum(1 for e in unique_edges if e["refSource"] == "typed")
heuristic = sum(1 for e in unique_edges if e["refSource"] == "heuristic")
print(f"Total unique specRef edges: {len(unique_edges)} (typed={typed}, heuristic={heuristic})", file=sys.stderr)

# Find dangling: target matches a removed pre identity (same-namespace kind/name match)
dangling = []
for e in unique_edges:
    t = e["target"]
    knn = (t["kind"], t.get("namespace"), t["name"])
    if knn in removed_pre:
        e["removed_target_uid"] = removed_pre[knn]
        dangling.append(e)

# Group by target
by_target = {}
for d in dangling:
    tk = (d["target"]["kind"], d["target"].get("namespace"), d["target"]["name"])
    by_target.setdefault(tk, []).append(d)

print(f"Dangling edges (post -> removed pre): {len(dangling)}", file=sys.stderr)
print(f"Distinct removed targets referenced: {len(by_target)}", file=sys.stderr)
for tk, edges in sorted(by_target.items()):
    print(f"  {tk[0]}/{tk[2]} ns={tk[1]}: {len(edges)} edges", file=sys.stderr)

result = {
    "total_unique_specref_edges": len(unique_edges),
    "typed_edges": typed,
    "heuristic_edges": heuristic,
    "dangling_edges": len(dangling),
    "distinct_removed_targets": len(by_target),
    "details": sorted(dangling, key=lambda d: (d["target"]["kind"], d["target"]["name"], d["source"]["kind"], d["source"]["name"])),
    "coverage_limitations": {
        "target_group_version": "NOT available (spec-ref matches kind+name only)",
        "namespace_inference": "same-namespace assumed for all spec-ref targets",
        "cluster_scoped": "NOT covered (map -A is namespaced-only)",
        "generic_refs": "heuristic name-match, not GVK-typed"
    }
}
json.dump(result, open(out_path, "w"), indent=2)
print(f"Saved to {out_path}", file=sys.stderr)
