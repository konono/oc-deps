#!/usr/bin/env python3
"""Validate evidence manifest consistency."""
import json, sys, os, glob, hashlib, subprocess

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
errors = []

def check(cond, msg):
    if not cond: errors.append(msg)

evidence_dirs = sorted(glob.glob(os.path.join(ROOT, "logs/teardown-workflow-refactor/final-e2e/*/evidence-manifest.json")))
if not evidence_dirs:
    print("SKIP: no evidence manifest found")
    sys.exit(0)

manifest_path = evidence_dirs[-1]
edir = os.path.dirname(manifest_path)

with open(manifest_path) as f:
    m = json.load(f)

# ── tested_code_commit ancestry ──
tested = m.get("tested_code_commit", "")
check(len(tested) == 40, f"tested_code_commit must be full SHA, got len={len(tested)}")
if len(tested) == 40:
    r = subprocess.run(["git", "merge-base", "--is-ancestor", tested, "HEAD"],
                       capture_output=True, cwd=ROOT)
    check(r.returncode == 0, f"tested_code_commit {tested[:12]} is not ancestor of HEAD")

# ── provenance agreement ──
prov_path = os.path.join(edir, "provenance.yaml")
check(os.path.exists(prov_path), "provenance.yaml missing")
if os.path.exists(prov_path):
    prov = {}
    with open(prov_path) as f:
        for line in f:
            if ":" in line:
                k, v = line.split(":", 1)
                prov[k.strip()] = v.strip()
    check("binary_sha256" in prov, "provenance.yaml missing binary_sha256")
    check("git_sha" in prov, "provenance.yaml missing git_sha")
    check(prov.get("binary_sha256") == m.get("binary_sha256"),
          f"binary_sha256 mismatch: manifest={m.get('binary_sha256','?')[:12]} provenance={prov.get('binary_sha256','?')[:12]}")
    if tested:
        check(prov.get("git_sha", "").startswith(tested[:7]),
              f"provenance git_sha={prov.get('git_sha','?')[:12]} != tested_code_commit={tested[:12]}")

# ── journal counts: exactly 15+15=30 ──
a_journals = m.get("cycle_a", {}).get("journals", [])
b_journals = m.get("cycle_b", {}).get("journals", [])
check(len(a_journals) == 15, f"cycle_a journals: {len(a_journals)} (expect 15)")
check(len(b_journals) == 15, f"cycle_b journals: {len(b_journals)} (expect 15)")
check(len(a_journals) + len(b_journals) == 30, f"total journals: {len(a_journals)+len(b_journals)} (expect 30)")

# ── backup receipts: exactly 1 per journal ──
for j in a_journals + b_journals:
    check(j.get("backup_receipt_count") == 1,
          f"{j.get('run_id','?')}: backup_receipt_count={j.get('backup_receipt_count')} (expect 1)")
    check(j.get("backup_receipt") is not None,
          f"{j.get('run_id','?')}: backup_receipt missing")
    if j.get("backup_receipt"):
        check(j["backup_receipt"].get("resource_count", 0) > 0,
              f"{j.get('run_id','?')}: resource_count=0")

# ── log_sha256: git-tracked + hash-correct ──
log_hashes = m.get("log_sha256", {})
for rel_path, expected_hash in log_hashes.items():
    full = os.path.join(edir, rel_path)
    repo_rel = os.path.relpath(full, ROOT)

    r = subprocess.run(["git", "ls-files", "--error-unmatch", repo_rel],
                       capture_output=True, cwd=ROOT)
    check(r.returncode == 0, f"log_sha256 path not git-tracked: {rel_path}")

    if os.path.exists(full):
        h = hashlib.sha256()
        with open(full, "rb") as fh:
            for chunk in iter(lambda: fh.read(8192), b""):
                h.update(chunk)
        actual = h.hexdigest()
        check(actual == expected_hash,
              f"hash mismatch: {rel_path} expected={expected_hash[:12]} actual={actual[:12]}")

    check("/raw.yaml" not in rel_path and "/recreate.yaml" not in rel_path
          and "/lifecycle.yaml" not in rel_path,
          f"log_sha256 contains backup resource path: {rel_path}")

if errors:
    print("FAIL")
    for e in errors:
        print(f"  ✗ {e}")
    sys.exit(1)
else:
    print(f"PASS ({len(a_journals)}+{len(b_journals)} journals, {len(log_hashes)} committed log hashes verified)")
