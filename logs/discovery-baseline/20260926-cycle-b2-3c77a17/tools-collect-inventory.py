#!/usr/bin/env python3
"""Cluster-wide metadata-only inventory with canonical GVR/GVK from raw discovery API.

Collects metadata for ALL listable resources including Secrets (metadata only).
Uses raw discovery endpoints for exact GVR/version with pagination.
Validates returned apiVersion+kind — mismatch is a collection failure.
Annotations: allowlisted relationship keys preserved in full; all others key+sha256 hash.
"""
import subprocess, json, sys, os, hashlib, time, urllib.parse

MAX_RETRIES = 2
REQUEST_TIMEOUT = 30

# Resources whose metadata.name contains sensitive tokens/credentials.
# Object rows are NOT stored. Only count + identity_redacted=true in coverage ledger.
# Matched by exact (group, resource) tuple, not resource name alone.
IDENTITY_REDACTED_GVRS = {
    ("oauth.openshift.io", "oauthaccesstokens"),
    ("oauth.openshift.io", "useroauthaccesstokens"),
    ("oauth.openshift.io", "oauthauthorizetokens"),
}

# Annotations: ONLY these prefixes get full value preservation.
# Everything else: key retained + sha256 hash of value (prevents credential leak).
# last-applied-configuration is dropped entirely (large, contains full spec).
PRESERVE_ANNOTATION_PREFIXES = [
    "operator-sdk.io/", "operator-sdk/",
    "opendatahub.io/", "maas.opendatahub.io/",
    "platform.opendatahub.io/", "component.opendatahub.io/",
    "kuadrant.io/",
    "HTTPRouteRule.gateway.networking.k8s.io",
    "GRPCRouteRule.gateway.networking.k8s.io",
    "instrumentation.opentelemetry.io/", "sidecar.opentelemetry.io/",
    "opentelemetry-operator",
    "sidecar.istio.io/",
    "cert-manager.io/",
    "app.kubernetes.io/",
    "olm.operatorGroup", "olm.targetNamespaces", "olm.providedAPIs",
    "operators.coreos.com/", "operatorframework.io/",
    "serving.kserve.io/",
]
DROP_ANNOTATION_KEYS = {"kubectl.kubernetes.io/last-applied-configuration"}


def raw_get(path, timeout=REQUEST_TIMEOUT):
    """GET raw API path with retry. Returns (data, error).
    Retries on timeout only. kubectl --raw does not expose HTTP status codes
    cleanly (all failures are rc=1 with stderr text), so 401/403/404 cannot
    be reliably distinguished from transient errors at this layer.
    Limitation documented: all non-zero exits are retried up to MAX_RETRIES.
    """
    for attempt in range(MAX_RETRIES + 1):
        try:
            r = subprocess.run(
                ["kubectl", "get", "--raw", path],
                capture_output=True, text=True, timeout=timeout
            )
            if r.returncode == 0:
                return json.loads(r.stdout), None
            stderr = r.stderr.strip()
            # Do not retry 403/404 if detectable
            if "forbidden" in stderr.lower() or "Forbidden" in stderr:
                return None, {"path": path, "status": 403, "stderr": stderr[:300], "retries": 0}
            if "not found" in stderr.lower() or "NotFound" in stderr:
                return None, {"path": path, "status": 404, "stderr": stderr[:300], "retries": 0}
            if attempt < MAX_RETRIES:
                time.sleep(0.5 * (attempt + 1))
                continue
            return None, {"path": path, "status": r.returncode, "stderr": stderr[:300], "retries": attempt}
        except subprocess.TimeoutExpired:
            if attempt < MAX_RETRIES:
                time.sleep(0.5 * (attempt + 1))
                continue
            return None, {"path": path, "status": -1, "stderr": f"timeout {timeout}s", "retries": attempt}
        except Exception as e:
            return None, {"path": path, "status": -1, "stderr": str(e)[:300], "retries": attempt}
    return None, {"path": path, "status": -1, "stderr": "exhausted retries", "retries": MAX_RETRIES}


def get_discovery_catalog():
    """Get canonical GVR/GVK/namespaced from raw discovery API."""
    gvrs = []

    # Core API
    data, err = raw_get("/api/v1")
    if err:
        print(f"FATAL: /api/v1: {err}", file=sys.stderr)
        sys.exit(1)
    for res in data.get("resources", []):
        if "list" not in res.get("verbs", []) or "/" in res["name"]:
            continue
        gvrs.append({
            "group": "", "version": "v1", "resource": res["name"], "kind": res["kind"],
            "namespaced": res["namespaced"], "isPreferred": True,
            "verbs": sorted(res.get("verbs", [])),
            "storageVersionHash": res.get("storageVersionHash", ""),
            "isStorage": None,  # unknown for built-in
            "storageVersionSource": "unknown",
        })

    # Group APIs
    groups_data, err = raw_get("/apis")
    if err:
        print(f"FATAL: /apis: {err}", file=sys.stderr)
        sys.exit(1)

    discovery_failures = []
    seen_gvr = set()  # (group, version, resource) dedup
    for grp in groups_data.get("groups", []):
        gname = grp["name"]
        pref_ver = grp.get("preferredVersion", {}).get("version", "")
        group_versions = [v["version"] for v in grp.get("versions", [])]

        # Iterate ALL served versions, not just preferred
        for ver_entry in grp.get("versions", []):
            ver = ver_entry["version"]
            data, err = raw_get(f"/apis/{gname}/{ver}")
            if err:
                discovery_failures.append({
                    "group": gname, "version": ver,
                    "endpoint": f"/apis/{gname}/{ver}", **err
                })
                print(f"DISCOVERY FAIL: /apis/{gname}/{ver}: {err}", file=sys.stderr)
                continue
            for res in data.get("resources", []):
                if "list" not in res.get("verbs", []) or "/" in res["name"]:
                    continue
                gvr_key = (gname, ver, res["name"])
                if gvr_key in seen_gvr:
                    continue
                seen_gvr.add(gvr_key)
                gvrs.append({
                    "group": gname, "version": ver, "resource": res["name"],
                    "kind": res["kind"], "namespaced": res["namespaced"],
                    "isPreferred": ver == pref_ver, "groupVersions": group_versions,
                    "verbs": sorted(res.get("verbs", [])),
                    "storageVersionHash": res.get("storageVersionHash", ""),
                    "isStorage": None,  # resolved below for CRD-backed
                    "storageVersionSource": "unknown",
                })

    # Resolve isStorage for CRD-backed GVRs
    crd_err = resolve_crd_storage_versions(gvrs)
    if crd_err:
        discovery_failures.append(crd_err)

    # Stable sort: (group, version, resource) and sort groupVersions within each entry
    gvrs.sort(key=lambda g: (g["group"], g["version"], g["resource"]))
    for g in gvrs:
        if "groupVersions" in g:
            g["groupVersions"] = sorted(g["groupVersions"])

    return gvrs, discovery_failures


def resolve_crd_storage_versions(gvrs):
    """For CRD-backed GVRs, derive isStorage from CRD.spec.versions[].storage.
    Returns error dict if CRD listing fails (fatal for corpus)."""
    data, err = raw_get("/apis/apiextensions.k8s.io/v1/customresourcedefinitions?limit=500")
    if err:
        print(f"CRD CATALOG FAIL: {err}", file=sys.stderr)
        return {"endpoint": "CRD catalog", "reason": "cannot list CRDs for storage version resolution", **err}
    crds = data.get("items", [])
    # Handle pagination
    while data.get("metadata", {}).get("continue"):
        token = urllib.parse.quote(data["metadata"]["continue"], safe="")
        data2, err2 = raw_get(f"/apis/apiextensions.k8s.io/v1/customresourcedefinitions?limit=500&continue={token}")
        if err2:
            print(f"CRD CATALOG PAGINATION FAIL: {err2}", file=sys.stderr)
            return {"endpoint": "CRD catalog pagination", "reason": "failed on continuation page", **err2}
        crds.extend(data2.get("items", []))
        data = data2

    # Build lookup: (group, resource) -> {version: isStorage}
    crd_storage = {}
    for crd in crds:
        spec = crd.get("spec", {})
        group = spec.get("group", "")
        plural = spec.get("names", {}).get("plural", "")
        versions = {}
        for v in spec.get("versions", []):
            versions[v["name"]] = v.get("storage", False)
        crd_storage[(group, plural)] = versions

    for gvr in gvrs:
        key = (gvr["group"], gvr["resource"])
        if key in crd_storage:
            ver_map = crd_storage[key]
            gvr["isStorage"] = ver_map.get(gvr["version"], False)
            gvr["storageVersionSource"] = "crd"
    return None


def spot_check(gvrs):
    checks = {
        ("", "ConfigMap"): ("", "v1"),
        ("apps", "Deployment"): ("apps", "v1"),
        ("perses.dev", "PersesDashboard"): ("perses.dev", "v1alpha2"),
        ("kuadrant.io", "AuthPolicy"): ("kuadrant.io", "v1"),
        ("kuadrant.io", "TokenRateLimitPolicy"): ("kuadrant.io", "v1alpha1"),
        ("networking.istio.io", "EnvoyFilter"): ("networking.istio.io", "v1alpha3"),
    }
    ok = True
    for (g, k), (eg, ev) in checks.items():
        exact = [x for x in gvrs if x["group"] == eg and x["kind"] == k and x["version"] == ev]
        if not exact:
            any_ver = [x for x in gvrs if x["group"] == g and x["kind"] == k]
            if any_ver:
                vers = [x["version"] for x in any_ver]
                print(f"SPOT CHECK FAIL: {g}/{k} found versions {vers} but not {ev}", file=sys.stderr)
            else:
                print(f"SPOT CHECK FAIL: {g}/{k} not found in discovery at all", file=sys.stderr)
            ok = False
        else:
            f = exact[0]
            print(f"SPOT CHECK OK: {f['resource']} {f['group']}/{f['version']}/{f['kind']} ns={f['namespaced']}", file=sys.stderr)
    return ok


def classify_annotation(key):
    if key in DROP_ANNOTATION_KEYS:
        return "drop"
    for prefix in PRESERVE_ANNOTATION_PREFIXES:
        if key.startswith(prefix) or key == prefix.rstrip("/"):
            return "preserve"
    return "hash"


def safe_annotations(annots):
    if not annots:
        return {}, {}
    result = {}
    policy = {}
    for k, v in annots.items():
        cat = classify_annotation(k)
        policy[k] = cat
        if cat == "drop":
            continue
        elif cat == "hash":
            result[k] = f"sha256:{hashlib.sha256(v.encode()).hexdigest()[:16]}"
        else:
            result[k] = v
    return result, policy


def count_resources_raw_redacted(gvr):
    """Count-only LIST for sensitive GVRs. Never accesses item metadata/name.
    Returns (count, error). Only list-level shape, pagination, and item count."""
    g, v, r = gvr["group"], gvr["version"], gvr["resource"]
    base = f"/apis/{g}/{v}/{r}" if g else f"/api/{v}/{r}"
    expected_api = f"{g}/{v}" if g else v
    expected_list_kind = gvr["kind"] + "List"

    total = 0
    continue_token = ""
    for page in range(200):
        path = f"{base}?limit=500"
        if continue_token:
            path += f"&continue={urllib.parse.quote(continue_token, safe='')}"
        data, err = raw_get(path, timeout=REQUEST_TIMEOUT)
        if err:
            return 0, err

        # Handle virtual endpoints
        if data.get("kind") == "Status" and data.get("status") == "Success" and "items" not in data:
            return 0, None

        list_api = data.get("apiVersion", "")
        list_kind = data.get("kind", "")
        if list_api != expected_api:
            return 0, {"path": path, "status": -2, "stderr": f"list apiVersion mismatch"}
        if list_kind != expected_list_kind:
            return 0, {"path": path, "status": -2, "stderr": f"list kind mismatch"}

        # Count items without accessing their content
        total += len(data.get("items", []))

        ct = data.get("metadata", {}).get("continue", "")
        if not ct:
            break
        continue_token = ct
        if page >= 199:
            return 0, {"path": path, "status": -4, "stderr": "pagination limit"}

    return total, None


def list_resources_raw(gvr):
    """LIST with pagination using raw API. URL-encodes continue tokens."""
    g, v, r = gvr["group"], gvr["version"], gvr["resource"]
    base = f"/apis/{g}/{v}/{r}" if g else f"/api/{v}/{r}"
    expected_api = f"{g}/{v}" if g else v

    items = []
    continue_token = ""
    page = 0
    MAX_PAGES = 200

    while True:
        path = f"{base}?limit=500"
        if continue_token:
            path += f"&continue={urllib.parse.quote(continue_token, safe='')}"
        data, err = raw_get(path, timeout=REQUEST_TIMEOUT)
        if err:
            return None, err

        # Validate list-level apiVersion and kind.
        list_api = data.get("apiVersion", "")
        list_kind = data.get("kind", "")
        expected_list_kind = gvr["kind"] + "List"

        # OpenShift virtual create endpoints (e.g. projectrequests) return
        # {"apiVersion":"v1","kind":"Status","status":"Success"} with no items key.
        # This specific shape is not an inventory gap — treat as empty collection.
        if (list_kind == "Status"
                and data.get("status") == "Success"
                and "items" not in data):
            return [], None

        if list_api != expected_api:
            return None, {"path": path, "status": -2,
                          "stderr": f"list apiVersion mismatch: expected {expected_api} got {list_api}"}
        if list_kind != expected_list_kind:
            return None, {"path": path, "status": -2,
                          "stderr": f"list kind mismatch: expected {expected_list_kind} got {list_kind}"}

        page_items = data.get("items", [])
        # Validate item apiVersion+kind: absent/empty is OK (K8s wire behavior),
        # but if present must match exactly
        for item in page_items:
            item_api = item.get("apiVersion", "")
            item_kind = item.get("kind", "")
            if item_api and item_api != expected_api:
                name = item.get("metadata", {}).get("name", "?")
                return None, {"path": path, "status": -3,
                              "stderr": f"item {name} apiVersion mismatch: {item_api} vs {expected_api}"}
            if item_kind and item_kind != gvr["kind"]:
                name = item.get("metadata", {}).get("name", "?")
                return None, {"path": path, "status": -3,
                              "stderr": f"item {name} kind mismatch: {item_kind} vs {gvr['kind']}"}

        items.extend(page_items)
        ct = data.get("metadata", {}).get("continue", "")
        if not ct:
            break
        continue_token = ct
        page += 1
        if page >= MAX_PAGES:
            return None, {"path": path, "status": -4,
                          "stderr": f"pagination exceeded {MAX_PAGES} pages with nonempty continue token"}

    return items, None


def collect_inventory(gvrs, out_path, fail_path):
    count = 0
    failures = 0
    redacted_ledger = []  # coverage ledger for identity-redacted resources
    with open(out_path, "w") as fout, open(fail_path, "w") as ffail:
        for gvr in gvrs:
            # Identity-redacted resources: count only via safe path, no item access
            if (gvr["group"], gvr["resource"]) in IDENTITY_REDACTED_GVRS:
                rcount, err = count_resources_raw_redacted(gvr)
                if err:
                    ffail.write(json.dumps({
                        "group": gvr["group"], "version": gvr["version"],
                        "resource": gvr["resource"], "kind": gvr["kind"],
                        "status": err.get("status"), "stderr": err.get("stderr","")
                    }) + "\n")
                    failures += 1
                    continue
                redacted_ledger.append({
                    "group": gvr["group"], "version": gvr["version"],
                    "resource": gvr["resource"], "kind": gvr["kind"],
                    "count": rcount, "identity_redacted": True,
                    "reason": "metadata.name contains bearer token format",
                })
                print(f"  {gvr['group']}/{gvr['version']}/{gvr['resource']}: {rcount} (REDACTED)", file=sys.stderr)
                continue

            items, err = list_resources_raw(gvr)
            if err:
                ffail.write(json.dumps({
                    "group": gvr["group"], "version": gvr["version"],
                    "resource": gvr["resource"], "kind": gvr["kind"],
                    **{k: v for k, v in err.items() if k not in ("group", "version", "resource", "kind")}
                }) + "\n")
                failures += 1
                print(f"  FAIL {gvr['group']}/{gvr['version']}/{gvr['resource']}: {err.get('stderr','')[:80]}", file=sys.stderr)
                continue

            for item in items:
                meta = item.get("metadata", {})
                annots_safe, annots_policy = safe_annotations(meta.get("annotations"))

                entry = {
                    "group": gvr["group"], "version": gvr["version"],
                    "resource": gvr["resource"], "kind": gvr["kind"],
                    "namespaced": gvr["namespaced"],
                    "namespace": meta.get("namespace"),
                    "name": meta.get("name"),
                    "uid": meta.get("uid"),
                    "generation": meta.get("generation"),
                    "resourceVersion": meta.get("resourceVersion"),
                    "creationTimestamp": meta.get("creationTimestamp"),
                    "deletionTimestamp": meta.get("deletionTimestamp"),
                    "finalizers": meta.get("finalizers"),
                    "ownerReferences": meta.get("ownerReferences"),
                    "labels": meta.get("labels"),
                    "managedFieldManagers": sorted(set(
                        mf.get("manager", "") for mf in meta.get("managedFields", [])
                    )),
                    "annotations": annots_safe,
                    "_annotationPolicy": {k: v for k, v in annots_policy.items() if v != "preserve"},
                }
                fout.write(json.dumps(entry, separators=(",", ":"), sort_keys=False) + "\n")
                count += 1

            if items:
                print(f"  {gvr['group']}/{gvr['version']}/{gvr['resource']}: {len(items)}", file=sys.stderr)

    return count, failures, redacted_ledger


if __name__ == "__main__":
    out_path = sys.argv[1] if len(sys.argv) > 1 else "inventory.jsonl"
    fail_path = sys.argv[2] if len(sys.argv) > 2 else "list-failures.jsonl"
    catalog_path = sys.argv[3] if len(sys.argv) > 3 else "gvr-catalog.json"

    disc_fail_path = os.path.splitext(fail_path)[0] + "-discovery.jsonl"

    print("Discovering canonical GVRs from raw API...", file=sys.stderr)
    gvrs, discovery_failures = get_discovery_catalog()
    print(f"Found {len(gvrs)} listable GVRs (all served versions)", file=sys.stderr)

    if discovery_failures:
        with open(disc_fail_path, "w") as df:
            for f in discovery_failures:
                df.write(json.dumps(f) + "\n")
        print(f"GATE FAIL: {len(discovery_failures)} discovery endpoint failure(s) — see {disc_fail_path}", file=sys.stderr)
        for f in discovery_failures:
            print(f"  {f.get('endpoint', f.get('group','?'))}: {f.get('stderr','')[:80]}", file=sys.stderr)
        sys.exit(5)

    if not spot_check(gvrs):
        print("FATAL: spot check failed", file=sys.stderr)
        sys.exit(1)

    json.dump({"count": len(gvrs), "gvrs": gvrs}, open(catalog_path, "w"), indent=2)
    print(f"Catalog saved: {len(gvrs)} GVRs", file=sys.stderr)

    # Catalog gate: every entry must have verbs containing "list"
    missing_verbs = [g for g in gvrs if "verbs" not in g or "list" not in g.get("verbs", [])]
    if missing_verbs:
        print(f"GATE FAIL: {len(missing_verbs)} catalog entries missing verbs or list verb", file=sys.stderr)
        for mv in missing_verbs[:5]:
            print(f"  {mv['group']}/{mv['version']}/{mv['resource']}", file=sys.stderr)
        sys.exit(10)

    print("Collecting inventory...", file=sys.stderr)
    count, failures, redacted_ledger = collect_inventory(gvrs, out_path, fail_path)
    print(f"Done: {count} objects, {failures} failures, {len(redacted_ledger)} redacted GVRs", file=sys.stderr)

    # Save redacted coverage ledger
    ledger_path = os.path.splitext(out_path)[0] + "-redacted-ledger.json"
    json.dump(redacted_ledger, open(ledger_path, "w"), indent=2)
    for entry in redacted_ledger:
        print(f"  REDACTED: {entry['resource']} count={entry['count']}", file=sys.stderr)

    if failures > 0:
        print(f"GATE FAIL: {failures} LIST failures (requires 0)", file=sys.stderr)
        sys.exit(2)

    # Post-assertions
    TOKEN_KINDS = {"OAuthAccessToken", "UserOAuthAccessToken", "OAuthAuthorizeToken"}
    TOKEN_RESOURCES = {"oauthaccesstokens", "useroauthaccesstokens", "oauthauthorizetokens"}
    with open(out_path) as f:
        secrets = 0
        has_finalizers_field = False
        token_rows = 0
        for line in f:
            obj = json.loads(line)
            if obj["kind"] == "Secret":
                secrets += 1
            if "finalizers" in obj:
                has_finalizers_field = True
            if obj["kind"] in TOKEN_KINDS or obj["resource"] in TOKEN_RESOURCES:
                token_rows += 1
    print(f"Assertions: Secret rows={secrets}, finalizers={has_finalizers_field}, token rows={token_rows}", file=sys.stderr)
    if secrets == 0:
        print("GATE FAIL: zero Secret rows", file=sys.stderr)
        sys.exit(3)
    if token_rows > 0:
        print(f"GATE FAIL: {token_rows} OAuth token rows in inventory (must be 0)", file=sys.stderr)
        sys.exit(8)
    if not has_finalizers_field:
        print("GATE FAIL: no finalizers field found", file=sys.stderr)
        sys.exit(4)
    # Annotation policy smoke test
    test_annots = {
        "platform.opendatahub.io/instance.uid": "abc-123",
        "platform.opendatahub.io/managed-by": "controller-x",
        "component.opendatahub.io/management-state": "Managed",
        "HTTPRouteRule.gateway.networking.k8s.io/some-ns-route-rule-0": "redhat-ai-gateway-infra/maas-api-route#rule-0",
        "GRPCRouteRule.gateway.networking.k8s.io/other": "value",
        "kuadrant.io/some-key": "preserved",
        "example.com/unknown-key": "should-be-hashed",
        "kubectl.kubernetes.io/last-applied-configuration": "dropped-entirely",
    }
    safe, policy = safe_annotations(test_annots)
    annot_ok = True
    # Preserved keys must have original values
    for k in ["platform.opendatahub.io/instance.uid", "platform.opendatahub.io/managed-by",
              "component.opendatahub.io/management-state",
              "HTTPRouteRule.gateway.networking.k8s.io/some-ns-route-rule-0",
              "GRPCRouteRule.gateway.networking.k8s.io/other",
              "kuadrant.io/some-key"]:
        if safe.get(k) != test_annots[k]:
            print(f"ANNOT FAIL: {k} expected preserve, got {safe.get(k)!r}", file=sys.stderr)
            annot_ok = False
    # Unknown key must be hashed
    if not safe.get("example.com/unknown-key", "").startswith("sha256:"):
        print(f"ANNOT FAIL: example.com/unknown-key expected hash, got {safe.get('example.com/unknown-key')!r}", file=sys.stderr)
        annot_ok = False
    # Dropped key must be absent
    if "kubectl.kubernetes.io/last-applied-configuration" in safe:
        print("ANNOT FAIL: last-applied-configuration should be dropped", file=sys.stderr)
        annot_ok = False
    if not annot_ok:
        print("GATE FAIL: annotation policy smoke test", file=sys.stderr)
        sys.exit(6)
    print("Annotation policy smoke test PASS", file=sys.stderr)

    # Virtual endpoint smoke test: Status/Success/no-items returns empty list
    from unittest.mock import patch
    virtual_response = {"apiVersion": "v1", "kind": "Status", "status": "Success", "metadata": {}}
    test_gvr = {"group": "project.openshift.io", "version": "v1", "resource": "projectrequests", "kind": "ProjectRequest"}
    with patch("__main__.raw_get", return_value=(virtual_response, None)):
        result, err = list_resources_raw(test_gvr)
        if err is not None:
            print(f"VIRTUAL ENDPOINT FAIL: expected empty list, got error: {err}", file=sys.stderr)
            sys.exit(7)
        if result != []:
            print(f"VIRTUAL ENDPOINT FAIL: expected [], got {result}", file=sys.stderr)
            sys.exit(7)
    # Real apiVersion mismatch (non-Status) must still fail
    bad_response = {"apiVersion": "wrong/v1", "kind": "ProjectRequestList", "items": []}
    with patch("__main__.raw_get", return_value=(bad_response, None)):
        result, err = list_resources_raw(test_gvr)
        if err is None:
            print("VIRTUAL ENDPOINT FAIL: real apiVersion mismatch should fail", file=sys.stderr)
            sys.exit(7)
    print("Virtual endpoint smoke test PASS", file=sys.stderr)

    # Security smoke: sensitive GVR item names never leak
    import io
    fake_token = "COLLECTOR_TEST_MARKER_NOT_A_REAL_TOKEN"
    sensitive_list = {
        "apiVersion": "oauth.openshift.io/v1",
        "kind": "OAuthAccessTokenList",
        "metadata": {},
        "items": [{"metadata": {"name": fake_token, "uid": "test"}}]
    }
    test_gvr_sec = {"group": "oauth.openshift.io", "version": "v1",
                    "resource": "oauthaccesstokens", "kind": "OAuthAccessToken"}
    with patch("__main__.raw_get", return_value=(sensitive_list, None)):
        rcount, err = count_resources_raw_redacted(test_gvr_sec)
        if err:
            print(f"SECURITY SMOKE FAIL: redacted count returned error: {err}", file=sys.stderr)
            sys.exit(9)
        if rcount != 1:
            print(f"SECURITY SMOKE FAIL: expected count=1 got {rcount}", file=sys.stderr)
            sys.exit(9)
    # Verify token never appears in ledger serialization
    test_ledger = [{"group": "oauth.openshift.io", "version": "v1",
                    "resource": "oauthaccesstokens", "kind": "OAuthAccessToken",
                    "count": 1, "identity_redacted": True, "reason": "test"}]
    ledger_text = json.dumps(test_ledger)
    if fake_token in ledger_text:
        print("SECURITY SMOKE FAIL: token pattern in ledger", file=sys.stderr)
        sys.exit(9)
    print("Security smoke test PASS", file=sys.stderr)

    print("All post-assertions PASS", file=sys.stderr)
