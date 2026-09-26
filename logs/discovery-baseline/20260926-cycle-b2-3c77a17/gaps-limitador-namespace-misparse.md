# Phase 3 Defect: Limitador spec.limits[].namespace misidentified as K8s namespace

## Finding

`operator resources limitador-operator --scope related` produces 271 scan warnings
because it treats `spec.limits[0].namespace = "redhat-ai-gateway-infra/maas-api-route"`
as a Kubernetes namespace reference and attempts to LIST resources in it.

The Limitador CRD `spec.limits[].namespace` field is a rate-limit domain namespace
(an application-level concept), not a Kubernetes namespace.

## Evidence

```json
{
  "namespace": "redhat-ai-gateway-infra/maas-api-route",
  "evidence": [{"SpecNamespaceRef": {
    "source_kind": "Limitador",
    "source_name": "limitador",
    "field": "limits[0].namespace"
  }}]
}
```

scan_warning_count: 271 (all from LIST attempts against this invalid namespace)

## Root Cause

Current `spec_ref` namespace extraction heuristic treats any field named "namespace"
in a CR spec as a Kubernetes namespace reference. This is a false positive for
domain-specific "namespace" fields.

## Phase 3 Fix (fixpoint scope expansion)

- CRD/OpenAPI schema-aware namespace field identification
- Only `metadata.namespace` and well-known spec fields (e.g., `targetNamespace`,
  `installNamespace`) should be treated as K8s namespace references
- Fields named "namespace" in arbitrary CRD specs need schema context or
  version-bound source profile validation
- Slash-containing values (`foo/bar`) are never valid K8s namespaces — quick filter

## Impact on Current Corpus

- 271 scan warnings are noise, not real failures
- The Limitador operator resources JSON is otherwise valid
- Preserving as-is for Phase 3 regression baseline
