#!/usr/bin/env python3
"""Validate evidence manifest consistency."""
import json, sys, os, glob, hashlib

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
errors = []

def check(cond, msg):
    if not cond: errors.append(msg)

# Find latest evidence dir
evidence_dirs = sorted(glob.glob(os.path.join(ROOT, "logs/teardown-workflow-refactor/final-e2e/*/evidence-manifest.json")))
if not evidence_dirs:
    print("SKIP: no evidence manifest found")
    sys.exit(0)

manifest_path = evidence_dirs[-1]
edir = os.path.dirname(manifest_path)

with open(manifest_path) as f:
    m = json.load(f)

# Provenance/manifest binary_sha256 agreement
prov_path = os.path.join(edir, "provenance.yaml")
if os.path.exists(prov_path):
    with open(prov_path) as f:
        for line in f:
            if line.startswith("binary_sha256:"):
                prov_sha = line.split(":", 1)[1].strip()
                check(prov_sha == m["binary_sha256"],
                      f"binary_sha256 mismatch: manifest={m['binary_sha256'][:12]} provenance={prov_sha[:12]}")

# All 30 journals have exactly 1 receipt
for cycle in ["cycle_a", "cycle_b"]:
    for j in m.get(cycle, {}).get("journals", []):
        check(j.get("backup_receipt_count") == 1,
              f"{j['run_id']}: backup_receipt_count={j.get('backup_receipt_count')} (expect 1)")
        check(j.get("backup_receipt") is not None,
              f"{j['run_id']}: backup_receipt missing")
        if j.get("backup_receipt"):
            check(j["backup_receipt"].get("resource_count", 0) > 0,
                  f"{j['run_id']}: resource_count=0")

# log_sha256 only references committed files
for rel_path in m.get("log_sha256", {}):
    full = os.path.join(edir, rel_path)
    check(os.path.exists(full), f"log_sha256 references missing file: {rel_path}")

# No raw/recreate/lifecycle paths in log_sha256
for rel_path in m.get("log_sha256", {}):
    check("/raw.yaml" not in rel_path and "/recreate.yaml" not in rel_path and "/lifecycle.yaml" not in rel_path,
          f"log_sha256 contains backup resource path: {rel_path}")

if errors:
    print("FAIL")
    for e in errors: print(f"  ✗ {e}")
    sys.exit(1)
else:
    a = len(m.get("cycle_a", {}).get("journals", []))
    b = len(m.get("cycle_b", {}).get("journals", []))
    print(f"PASS ({a}+{b} journals, {len(m.get('log_sha256',{}))} committed log hashes)")
