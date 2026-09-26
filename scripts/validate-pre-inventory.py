#!/usr/bin/env python3
"""Corpus-specific pre-inventory validator with golden identity + evidence assertions.
Run AFTER collect-inventory.py on the pre-delete inventory.
Uses logical identity (group, kind, namespace, name) with UID dedup across served versions."""
import json, sys

if len(sys.argv) < 2:
    print("Usage: validate-pre-inventory.py <pre-inventory.jsonl>", file=sys.stderr)
    sys.exit(1)

path = sys.argv[1]

# Load and dedup by logical identity (group, kind, namespace, name) → first UID seen
objects = {}  # (group, kind, ns, name) → obj
with open(path) as f:
    for line in f:
        obj = json.loads(line)
        key = (obj["group"], obj["kind"], obj.get("namespace"), obj["name"])
        if key not in objects:
            objects[key] = obj

print(f"Loaded {len(objects)} logical identities (deduped across versions)", file=sys.stderr)

def find(group, kind, ns, name):
    return objects.get((group, kind, ns, name))

def assert_exists(group, kind, ns, name, label):
    obj = find(group, kind, ns, name)
    if not obj:
        print(f"FAIL: {label} — {group}/{kind} {ns}/{name} not found", file=sys.stderr)
        return False
    print(f"OK: {label} — {group}/{kind} {ns}/{name} uid={obj['uid'][:12]}", file=sys.stderr)
    return True

def assert_owner(group, kind, ns, name, owner_kind, owner_name, label):
    obj = find(group, kind, ns, name)
    if not obj:
        print(f"FAIL: {label} — {group}/{kind} {ns}/{name} not found", file=sys.stderr)
        return False
    owners = obj.get("ownerReferences") or []
    match = [o for o in owners if o.get("kind") == owner_kind and o.get("name") == owner_name]
    if not match:
        owner_desc = [(o.get("kind"), o.get("name")) for o in owners]
        print(f"FAIL: {label} — owner {owner_kind}/{owner_name} not found in {owner_desc}", file=sys.stderr)
        return False
    print(f"OK: {label} — owner {owner_kind}/{owner_name} uid={match[0].get('uid','?')[:12]}", file=sys.stderr)
    return True

def assert_managed_by(group, kind, ns, name, manager, label):
    obj = find(group, kind, ns, name)
    if not obj:
        print(f"FAIL: {label} — not found", file=sys.stderr)
        return False
    managers = obj.get("managedFieldManagers") or []
    if manager in managers:
        print(f"OK: {label} — managedFieldManager includes {manager}", file=sys.stderr)
        return True
    # Check labels (app.kubernetes.io/managed-by)
    labels = obj.get("labels") or {}
    for k, v in labels.items():
        if "managed-by" in k.lower() and v == manager:
            print(f"OK: {label} — label {k}={v}", file=sys.stderr)
            return True
    # Check annotations
    annots = obj.get("annotations") or {}
    for k, v in annots.items():
        if "managed-by" in k.lower() and manager in str(v):
            print(f"OK: {label} — annotation {k}={v}", file=sys.stderr)
            return True
    print(f"FAIL: {label} — {manager} not in managers={managers} labels={labels}", file=sys.stderr)
    return False

def assert_annotation_key(group, kind, ns, name, annot_key, label):
    obj = find(group, kind, ns, name)
    if not obj:
        print(f"FAIL: {label} — not found", file=sys.stderr)
        return False
    annots = obj.get("annotations") or {}
    if annot_key in annots:
        print(f"OK: {label} — has annotation {annot_key}", file=sys.stderr)
        return True
    print(f"FAIL: {label} — missing annotation {annot_key}", file=sys.stderr)
    return False

ok = True

print("\n=== TokenRateLimitPolicy (RHCL foreign-owner) ===", file=sys.stderr)
ok &= assert_exists("kuadrant.io", "TokenRateLimitPolicy", "openshift-ingress", "gateway-default-deny",
                     "RHCL golden: TRL exists")
ok &= assert_owner("kuadrant.io", "TokenRateLimitPolicy", "openshift-ingress", "gateway-default-deny",
                    "Config", "default", "RHCL golden: TRL owned by maas Config")

print("\n=== EnvoyFilter (ServiceMesh foreign-consumer) ===", file=sys.stderr)
envoyfilter_names = [
    k for k in objects if k[0] == "networking.istio.io" and k[1] == "EnvoyFilter" and k[2] == "openshift-ingress"
]
print(f"EnvoyFilter in openshift-ingress: {len(envoyfilter_names)}", file=sys.stderr)
if len(envoyfilter_names) < 6:
    print(f"FAIL: expected >=6 EnvoyFilter in openshift-ingress, got {len(envoyfilter_names)}", file=sys.stderr)
    ok = False
else:
    print(f"OK: {len(envoyfilter_names)} EnvoyFilter in openshift-ingress", file=sys.stderr)

print("\n=== PersesDashboard (COO ApiStewardship foreign-owner) ===", file=sys.stderr)
perses_golden = [
    ("perses.dev", "PersesDashboard", "redhat-ods-monitoring", "dashboard-2-llm-d-traffic-admin", "Kserve", "default-kserve"),
    ("perses.dev", "PersesDashboard", "redhat-ods-monitoring", "dashboard-3-llm-d-utilization-admin", "Kserve", "default-kserve"),
    ("perses.dev", "PersesDashboard", "redhat-ods-monitoring", "dashboard-3-maas-usage-admin", "Config", "default"),
    ("perses.dev", "PersesDashboard", "redhat-ods-monitoring", "dashboard-4-llm-d-performance-admin", "Kserve", "default-kserve"),
]
for g, k, ns, n, ok_kind, ok_name in perses_golden:
    ok &= assert_exists(g, k, ns, n, f"COO golden: {n}")
    ok &= assert_owner(g, k, ns, n, ok_kind, ok_name, f"COO golden: {n} owner")

print("\n=== JobSet Certificate/Issuer (cert-manager foreign-consumer) ===", file=sys.stderr)
ok &= assert_exists("cert-manager.io", "Certificate", "openshift-jobset", "jobset-metrics-cert",
                     "cert-manager golden: jobset-metrics-cert")
ok &= assert_exists("cert-manager.io", "Certificate", "openshift-jobset", "jobset-serving-cert",
                     "cert-manager golden: jobset-serving-cert")
ok &= assert_exists("cert-manager.io", "Issuer", "openshift-jobset", "jobset-selfsigned-issuer",
                     "cert-manager golden: jobset-selfsigned-issuer")

print("\n=== MaaS AuthPolicy (RHCL foreign-managed, no ownerRef) ===", file=sys.stderr)
ok &= assert_exists("kuadrant.io", "AuthPolicy", "openshift-ingress", "maas-gateway-auth",
                     "RHCL golden: AuthPolicy")
ok &= assert_managed_by("kuadrant.io", "AuthPolicy", "openshift-ingress", "maas-gateway-auth",
                         "maas-controller", "RHCL golden: AuthPolicy managed-by maas-controller")

print("\n=== Kuadrant AuthConfig (Authorino foreign-managed) ===", file=sys.stderr)
authconfigs = [
    k for k in objects if k[0] == "authorino.kuadrant.io" and k[1] == "AuthConfig"
]
print(f"AuthConfig total: {len(authconfigs)}", file=sys.stderr)
if len(authconfigs) < 4:
    print(f"FAIL: expected >=4 AuthConfig, got {len(authconfigs)}", file=sys.stderr)
    ok = False
else:
    print(f"OK: {len(authconfigs)} AuthConfig found", file=sys.stderr)
    # Check for managed label and RouteRule annotation on at least one
    ac_with_route_annot = 0
    for ac_key in authconfigs:
        obj = objects[ac_key]
        annots = obj.get("annotations") or {}
        for ak in annots:
            if "HTTPRouteRule.gateway.networking.k8s.io" in ak or "GRPCRouteRule.gateway.networking.k8s.io" in ak:
                ac_with_route_annot += 1
                break
    if ac_with_route_annot > 0:
        print(f"OK: {ac_with_route_annot} AuthConfig with RouteRule annotation", file=sys.stderr)
    else:
        print("FAIL: no AuthConfig with RouteRule annotation", file=sys.stderr)
        ok = False

print(file=sys.stderr)
if ok:
    print("Pre-inventory golden validation PASS", file=sys.stderr)
else:
    print("Pre-inventory golden validation FAIL", file=sys.stderr)
    sys.exit(1)
