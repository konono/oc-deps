# Upstream Source Evidence — Authorino Finalizer Cleanup

## Source Identity

- Repository: `Kuadrant/authorino-operator`
- Commit: `e8623b50995c0ff54042e63d83c56d207b324d96`
- Tag: `v0.25.3`
- URL: https://github.com/Kuadrant/authorino-operator/tree/e8623b50995c0ff54042e63d83c56d207b324d96

## Cleanup Contract

### Cleanup Function
- File: `controllers/authorino_controller.go`
- Function: `cleanupClusterScopedPermissions`
- Called from Authorino CR finalizer when the CR is being deleted

### Naming Function
- File: `pkg/resources/k8s_util.go`
- Function: `authorinoClusterRoleBindingName(crName string, suffix string) string`
- Returns: `fmt.Sprintf("%s-%s", crName, suffix)`
- Suffixes: `"authorino"`, `"authorino-k8s-auth"`

### Production Names (for root named "authorino")
- `authorino-authorino` (roleRef: `authorino-manager-role`)
- `authorino-authorino-k8s-auth` (roleRef: `authorino-manager-k8s-auth-role`)

## Version Binding Note

The adapter binds to:
- Package: `authorino-operator` (exact match)
- CSV: `authorino-operator.v1.4.3` (exact match)

The installed CSV 1.4.3 and the upstream tag v0.25.3 cannot be proven to be the
same build from public evidence alone. The binding is empirical: corpus and live
cluster observation confirm that CSV 1.4.3 instances create these CRBs with the
deterministic naming pattern documented in the upstream source.

## Why Generic Discovery Cannot Express This

1. No ownerReference: namespaced Authorino CR cannot own cluster-scoped CRB
2. Not in CSV `spec.customresourcedefinitions.owned`: CRB is rbac, not a CRD
3. No spec-ref or label selector pointing from CR to CRB
4. The relationship is a finalizer cleanup contract: the CR's controller
   explicitly deletes these CRBs by deterministic name during finalization
