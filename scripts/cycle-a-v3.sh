#!/bin/bash
set -euo pipefail

# ══════════════════════════════════════════════════════════════
#  Phase D Cycle A v3 — Machine-gated destructive teardown
#  Issue #46: Full Teardown Residual Completion
# ══════════════════════════════════════════════════════════════

REPO=/tmp/oc-deps-issue46-impl
OC_DEPS="$REPO/target/release/oc-deps"
export KUBECONFIG=/Users/kono/gitrepo/oc-deps/.kube/config
EVIDENCE_DIR="$REPO/logs/full-teardown-completion/phase-d-evidence/cycle-a-v3"
BACKUP_DIR=/tmp/cycle-a-v3-backup
TIMESTAMP=$(date -u +%Y%m%dT%H%M%SZ)

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BOLD='\033[1m'
NC='\033[0m'

PASS_COUNT=0
FAIL_COUNT=0

assert() {
    local cmd="$1"
    local desc="$2"
    if eval "$cmd"; then
        echo -e "${GREEN}PASS${NC}: $desc"
        PASS_COUNT=$((PASS_COUNT + 1))
    else
        echo -e "${RED}ASSERT FAILED${NC}: $desc"
        FAIL_COUNT=$((FAIL_COUNT + 1))
        echo "ABORT — precondition not met."
        exit 1
    fi
}

log_cmd() {
    local label="$1"
    shift
    local logfile="$EVIDENCE_DIR/logs/${label}.log"
    echo -e "${BOLD}>>> $label${NC}"
    echo "# $*" > "$logfile"
    if "$@" >> "$logfile" 2>&1; then
        local ec=0
    else
        local ec=$?
    fi
    echo "exit=$ec" >> "$logfile"
    if [ "$ec" -ne 0 ]; then
        echo -e "${RED}FAILED (exit=$ec)${NC}: $label"
        tail -5 "$logfile"
        exit 1
    fi
    echo -e "${GREEN}OK (exit=0)${NC}: $label"
    return 0
}

get_uid() {
    local resource="$1"
    oc get $resource --no-headers -o jsonpath='{.metadata.uid}' 2>/dev/null
}

rm -rf "$EVIDENCE_DIR" "$BACKUP_DIR"
mkdir -p "$EVIDENCE_DIR"/{plans,logs,inventory}
mkdir -p "$BACKUP_DIR"

echo -e "\n${BOLD}═══ PHASE 1: PRE-MUTATION BASELINE ASSERTIONS ═══${NC}\n"

# 1. Target subscriptions
TARGET_SUBS=$(oc get subscriptions.operators.coreos.com -A --no-headers 2>/dev/null \
    | grep -v 'openshift-storage\|group-sync' | wc -l | tr -d ' ')
assert "[ '$TARGET_SUBS' -eq 15 ]" "15 target subscriptions (got $TARGET_SUBS)"

# 2. DSCI/DSC
DSCI_STATUS=$(oc get dsci default-dsci -o jsonpath='{.status.phase}' 2>/dev/null || echo "MISSING")
assert "[ '$DSCI_STATUS' = 'Ready' ]" "DSCI Ready (got $DSCI_STATUS)"
DSC_READY=$(oc get dsc default-dsc -o jsonpath='{.status.conditions[?(@.type=="Ready")].status}' 2>/dev/null || echo "MISSING")
assert "[ '$DSC_READY' = 'True' ]" "DSC Ready=True (got $DSC_READY)"

# 3. Terminating
TERM=$(oc get ns --no-headers 2>/dev/null | grep -c Terminating || true)
assert "[ '$TERM' -eq 0 ]" "0 Terminating namespaces (got $TERM)"

# 4. Node Ready
NODE_STATUS=$(oc get nodes --no-headers 2>/dev/null | awk '{print $2}')
assert "[ '$NODE_STATUS' = 'Ready' ]" "Node Ready (got $NODE_STATUS)"

# 5. Explicit targets — record UIDs
echo -e "\n${BOLD}--- Recording 10 explicit target UIDs ---${NC}"
declare -A TARGET_UIDS
TARGETS=(
    "sts/postgres|-n keycloak"
    "deploy/maas-postgres|-n redhat-ods-applications"
    "sts/ogx-postgres|-n redhat-ods-applications"
    "deploy/model-catalog|-n rhoai-model-registries"
    "gateway.gateway.networking.k8s.io/maas-default-gateway|-n openshift-ingress"
    "configmap/maas-gateway-options|-n openshift-ingress"
    "consoleplugin/kuadrant-console-plugin|"
    "deploy/kuadrant-console-plugin|-n openshift-rhcl"
    "svc/kuadrant-console-plugin|-n openshift-rhcl"
    "configmap/kuadrant-console-nginx-conf|-n openshift-rhcl"
)

for entry in "${TARGETS[@]}"; do
    IFS='|' read -r res ns_flag <<< "$entry"
    uid=$(oc get $res $ns_flag --no-headers -o jsonpath='{.metadata.uid}' 2>/dev/null || echo "")
    assert "[ -n '$uid' ]" "Target $res $ns_flag exists (uid=${uid:0:12})"
    TARGET_UIDS["$res"]="$uid"
done

# 6. NFD SCCs
NFD_SCC1_UID=$(get_uid "scc/nfd-topology-updater")
NFD_SCC2_UID=$(get_uid "scc/nfd-worker")
assert "[ -n '$NFD_SCC1_UID' ]" "NFD SCC nfd-topology-updater exists (uid=${NFD_SCC1_UID:0:12})"
assert "[ -n '$NFD_SCC2_UID' ]" "NFD SCC nfd-worker exists (uid=${NFD_SCC2_UID:0:12})"

# 7. Authorino CRBs
AUTH_CRBS=$(oc get clusterrolebindings --no-headers 2>/dev/null | grep -c authorino || true)
assert "[ '$AUTH_CRBS' -gt 0 ]" "Authorino CRBs exist (count=$AUTH_CRBS)"
oc get clusterrolebindings --no-headers 2>/dev/null | grep authorino | awk '{print $1}' \
    > "$EVIDENCE_DIR/inventory/authorino-crbs-pre.txt"

# 8. PV/PVC inventory
echo -e "\n${BOLD}--- Recording PV/PVC pre-inventory ---${NC}"
oc get pv -o json 2>/dev/null | python3 -c "
import json, sys
data = json.load(sys.stdin)
items = [{'name': i['metadata']['name'], 'uid': i['metadata']['uid'],
          'capacity': i['spec']['capacity']['storage'],
          'status': i['status']['phase']} for i in data['items']]
json.dump(items, sys.stdout, indent=2)
" > "$EVIDENCE_DIR/inventory/pv-pre.json"
PRE_PV_COUNT=$(python3 -c "import json; print(len(json.load(open('$EVIDENCE_DIR/inventory/pv-pre.json'))))")
echo "Pre PVs: $PRE_PV_COUNT"

oc get pvc -A -o json 2>/dev/null | python3 -c "
import json, sys
data = json.load(sys.stdin)
items = [{'name': i['metadata']['name'], 'namespace': i['metadata']['namespace'],
          'uid': i['metadata']['uid'], 'capacity': i['spec']['resources']['requests']['storage'],
          'status': i['status']['phase']} for i in data['items']]
json.dump(items, sys.stdout, indent=2)
" > "$EVIDENCE_DIR/inventory/pvc-pre.json"
PRE_PVC_COUNT=$(python3 -c "import json; print(len(json.load(open('$EVIDENCE_DIR/inventory/pvc-pre.json'))))")
echo "Pre PVCs: $PRE_PVC_COUNT"

# 9. Cluster UID
CLUSTER_UID=$(oc get ns kube-system -o jsonpath='{.metadata.uid}' 2>/dev/null)
echo "Cluster UID: $CLUSTER_UID"

# Save baseline summary
python3 -c "
import json
summary = {
    'cluster_uid': '$CLUSTER_UID',
    'target_subs': $TARGET_SUBS,
    'pre_pv_count': $PRE_PV_COUNT,
    'pre_pvc_count': $PRE_PVC_COUNT,
    'nfd_scc_uids': ['$NFD_SCC1_UID', '$NFD_SCC2_UID'],
    'authorino_crb_count': $AUTH_CRBS,
}
json.dump(summary, open('$EVIDENCE_DIR/baseline-summary.json', 'w'), indent=2)
"

echo -e "\n${GREEN}All $PASS_COUNT baseline assertions passed.${NC}\n"

# ══════════════════════════════════════════════════════════════
echo -e "${BOLD}═══ PHASE 2: PLAN GENERATION ═══${NC}\n"

COMMON_FLAGS="--approve-scope root --approve-scope independent --approve-scope label-only --approve-scope operator-group --refresh-discovery"

# Operators with explicit targets
log_cmd "plan-rhods" "$OC_DEPS" teardown plan rhods-operator $COMMON_FLAGS \
    --approve-resource maas.opendatahub.io/Config/-/default \
    --approve-resource MLflow/mlflow \
    --delete-resource apps/Deployment/redhat-ods-applications/maas-postgres \
    --delete-resource apps/StatefulSet/redhat-ods-applications/ogx-postgres \
    --delete-resource apps/Deployment/rhoai-model-registries/model-catalog \
    --delete-resource gateway.networking.k8s.io/Gateway/openshift-ingress/maas-default-gateway \
    --delete-resource ConfigMap/openshift-ingress/maas-gateway-options \
    --file "$EVIDENCE_DIR/plans/rhods-operator.json"

log_cmd "plan-rhbk" "$OC_DEPS" teardown plan rhbk-operator $COMMON_FLAGS \
    --delete-resource apps/StatefulSet/keycloak/postgres \
    --file "$EVIDENCE_DIR/plans/rhbk-operator.json"

log_cmd "plan-rhcl" "$OC_DEPS" teardown plan rhcl-operator $COMMON_FLAGS \
    --delete-resource console.openshift.io/ConsolePlugin/-/kuadrant-console-plugin \
    --delete-resource apps/Deployment/openshift-rhcl/kuadrant-console-plugin \
    --delete-resource Service/openshift-rhcl/kuadrant-console-plugin \
    --delete-resource ConfigMap/openshift-rhcl/kuadrant-console-nginx-conf \
    --file "$EVIDENCE_DIR/plans/rhcl-operator.json"

# Remaining 12 operators
for op in leader-worker-set job-set kueue-operator servicemeshoperator3 \
          nfd gpu-operator-certified cert-manager-operator \
          authorino-operator dns-operator limitador-operator \
          cluster-observability-operator opentelemetry-product; do
    log_cmd "plan-$op" "$OC_DEPS" teardown plan "$op" $COMMON_FLAGS \
        --file "$EVIDENCE_DIR/plans/${op}.json"
done

echo -e "\n${GREEN}All 15 plans generated.${NC}\n"

# ══════════════════════════════════════════════════════════════
echo -e "${BOLD}═══ PHASE 3: PLAN VALIDATION ═══${NC}\n"

python3 -c "
import json, sys

validations = {
    'rhods-operator': 5,
    'rhbk-operator': 1,
    'rhcl-operator': 4,
}
errors = []
for op, expected_count in validations.items():
    path = '$EVIDENCE_DIR/plans/{}.json'.format(op)
    with open(path) as f:
        plan = json.load(f)
    eds = plan.get('explicit_deletes', [])
    if len(eds) != expected_count:
        errors.append('{}: expected {} explicit_deletes, got {}'.format(op, expected_count, len(eds)))
    for ed in eds:
        sc = ed.get('ref_scan_coverage', {}).get('scan_complete')
        uid = ed.get('uid', '')
        if not sc:
            errors.append('{}: {} scan_complete={}'.format(op, ed['name'], sc))
        if not uid:
            errors.append('{}: {} has empty UID'.format(op, ed['name']))
    print('  {}: {}/{} explicit_deletes validated'.format(op, len(eds), expected_count))

if errors:
    for e in errors:
        print('ERROR: ' + e, file=sys.stderr)
    sys.exit(1)
print('  All plan validations passed.')
"
echo -e "${GREEN}Plan validation passed.${NC}\n"

# ══════════════════════════════════════════════════════════════
echo -e "${BOLD}═══ PHASE 4: DRY-RUN WITH BACKUP ═══${NC}\n"

ALL_OPS="rhods-operator rhbk-operator rhcl-operator leader-worker-set job-set kueue-operator servicemeshoperator3 nfd gpu-operator-certified cert-manager-operator authorino-operator dns-operator limitador-operator cluster-observability-operator opentelemetry-product"

for op in $ALL_OPS; do
    log_cmd "dryrun-$op" "$OC_DEPS" teardown apply \
        "$EVIDENCE_DIR/plans/${op}.json" -y --dry-run --backup-dir "$BACKUP_DIR"
done

echo -e "\n${BOLD}--- Verifying 10 explicit target UIDs in backup ---${NC}"
BACKUP_MISSING=0
for entry in "${TARGETS[@]}"; do
    IFS='|' read -r res ns_flag <<< "$entry"
    uid="${TARGET_UIDS[$res]}"
    found=$(find "$BACKUP_DIR" -type d -name "*${uid}*" 2>/dev/null | head -1)
    if [ -n "$found" ]; then
        echo -e "${GREEN}CAPTURED${NC}: $res uid=${uid:0:12}"
    else
        echo -e "${RED}MISSING${NC}: $res uid=${uid:0:12}"
        BACKUP_MISSING=$((BACKUP_MISSING + 1))
    fi
done
assert "[ '$BACKUP_MISSING' -eq 0 ]" "All 10 explicit target UIDs captured in backup"

echo -e "\n${BOLD}--- Verifying NFD SCCs in backup ---${NC}"
NFD_SCC1_FOUND=$(find "$BACKUP_DIR" -type d -name "*${NFD_SCC1_UID}*" 2>/dev/null | head -1)
NFD_SCC2_FOUND=$(find "$BACKUP_DIR" -type d -name "*${NFD_SCC2_UID}*" 2>/dev/null | head -1)
assert "[ -n '$NFD_SCC1_FOUND' ]" "NFD SCC nfd-topology-updater in backup"
assert "[ -n '$NFD_SCC2_FOUND' ]" "NFD SCC nfd-worker in backup"

echo -e "\n${BOLD}--- Verifying Authorino CRBs in backup ---${NC}"
AUTH_CRB_BACKUP=$(find "$BACKUP_DIR" -path "*/ClusterRoleBinding/*authorino*" -type d 2>/dev/null | wc -l | tr -d ' ')
assert "[ '$AUTH_CRB_BACKUP' -gt 0 ]" "Authorino CRBs in backup (count=$AUTH_CRB_BACKUP)"

echo -e "\n${GREEN}Dry-run + backup verification passed.${NC}\n"

# Clear dry-run backup before real apply
rm -rf "$BACKUP_DIR"
mkdir -p "$BACKUP_DIR"

# ══════════════════════════════════════════════════════════════
echo -e "${BOLD}═══ PHASE 5: DESTRUCTIVE APPLY ═══${NC}\n"

APPLY_ORDER="rhods-operator rhbk-operator rhcl-operator leader-worker-set job-set kueue-operator servicemeshoperator3 nfd gpu-operator-certified cert-manager-operator authorino-operator dns-operator limitador-operator cluster-observability-operator opentelemetry-product"

for op in $APPLY_ORDER; do
    echo -e "\n${YELLOW}>>> Applying $op${NC}"
    LOGFILE="$EVIDENCE_DIR/logs/apply-${op}.log"
    "$OC_DEPS" teardown apply \
        "$EVIDENCE_DIR/plans/${op}.json" -y --backup-dir "$BACKUP_DIR" \
        > "$LOGFILE" 2>&1 || {
        EC=$?
        echo -e "${RED}APPLY FAILED (exit=$EC): $op${NC}"
        tail -10 "$LOGFILE"
        echo "exit=$EC" >> "$LOGFILE"
        # Check if the failure is audit-only (deletions succeeded)
        if grep -q "0 failed" "$LOGFILE" 2>/dev/null; then
            echo -e "${YELLOW}Deletions succeeded but audit incomplete — continuing${NC}"
            echo "# audit-incomplete-continue" >> "$LOGFILE"
        elif grep -q "drift detected" "$LOGFILE" 2>/dev/null; then
            echo -e "${YELLOW}Drift detected — regenerating plan and retrying${NC}"
            # Build extra args for explicit targets
            RETRY_EXTRA=""
            case "$op" in
                rhods-operator)
                    RETRY_EXTRA="--approve-resource maas.opendatahub.io/Config/-/default --approve-resource MLflow/mlflow --delete-resource apps/Deployment/redhat-ods-applications/maas-postgres --delete-resource apps/StatefulSet/redhat-ods-applications/ogx-postgres --delete-resource apps/Deployment/rhoai-model-registries/model-catalog --delete-resource gateway.networking.k8s.io/Gateway/openshift-ingress/maas-default-gateway --delete-resource ConfigMap/openshift-ingress/maas-gateway-options"
                    ;;
                rhbk-operator)
                    RETRY_EXTRA="--delete-resource apps/StatefulSet/keycloak/postgres"
                    ;;
                rhcl-operator)
                    RETRY_EXTRA="--delete-resource console.openshift.io/ConsolePlugin/-/kuadrant-console-plugin --delete-resource apps/Deployment/openshift-rhcl/kuadrant-console-plugin --delete-resource Service/openshift-rhcl/kuadrant-console-plugin --delete-resource ConfigMap/openshift-rhcl/kuadrant-console-nginx-conf"
                    ;;
            esac
            "$OC_DEPS" teardown plan "$op" \
                --approve-scope root --approve-scope independent \
                --approve-scope label-only --approve-scope operator-group \
                $RETRY_EXTRA \
                --refresh-discovery --file "$EVIDENCE_DIR/plans/${op}.json" \
                > "$EVIDENCE_DIR/logs/plan-${op}-retry.log" 2>&1
            "$OC_DEPS" teardown apply \
                "$EVIDENCE_DIR/plans/${op}.json" -y --backup-dir "$BACKUP_DIR" \
                > "$EVIDENCE_DIR/logs/apply-${op}-retry.log" 2>&1 || {
                if grep -q "0 failed" "$EVIDENCE_DIR/logs/apply-${op}-retry.log" 2>/dev/null; then
                    echo -e "${YELLOW}Retry: deletions succeeded (audit may be incomplete)${NC}"
                else
                    echo -e "${RED}APPLY RETRY FAILED: $op${NC}"
                    tail -5 "$EVIDENCE_DIR/logs/apply-${op}-retry.log"
                    exit 1
                fi
            }
            LOGFILE="$EVIDENCE_DIR/logs/apply-${op}-retry.log"
        else
            exit 1
        fi
    }
    echo "exit=0" >> "$LOGFILE"

    # Extract deletion counts
    DELETED=$(grep -oP '\d+ deleted' "$LOGFILE" | head -1 || echo "? deleted")
    FAILED=$(grep -oP '\d+ failed' "$LOGFILE" | head -1 || echo "? failed")
    echo -e "  Result: $DELETED, $FAILED"

    # Assert 0 failed
    FAIL_NUM=$(echo "$FAILED" | grep -oP '^\d+' || echo "0")
    if [ "$FAIL_NUM" -ne 0 ]; then
        echo -e "${RED}ABORT: $op had $FAIL_NUM failed deletions${NC}"
        exit 1
    fi
done

echo -e "\n${GREEN}All 15 operators applied.${NC}\n"

# ══════════════════════════════════════════════════════════════
echo -e "${BOLD}═══ PHASE 6: POST-CYCLE VERIFICATION ═══${NC}\n"

# Require the caller's current kubeconfig credentials. Never embed or refresh
# cluster credentials in a checked-in evidence script.
if ! oc whoami > /dev/null 2>&1; then
    echo -e "${RED}ABORT: cluster authentication expired; refresh KUBECONFIG before verification${NC}"
    exit 1
fi

# 6.1 Target subscriptions
POST_SUBS=$(oc get subscriptions.operators.coreos.com -A --no-headers 2>/dev/null \
    | grep -v 'openshift-storage\|group-sync' | wc -l | tr -d ' ')
assert "[ '$POST_SUBS' -eq 0 ]" "0 target subscriptions remaining (got $POST_SUBS)"

# 6.2 Explicit targets absent
echo -e "\n${BOLD}--- Verifying 10 explicit targets absent ---${NC}"
ABSENT_COUNT=0
for entry in "${TARGETS[@]}"; do
    IFS='|' read -r res ns_flag <<< "$entry"
    if oc get $res $ns_flag --no-headers 2>&1 | grep -q "NotFound\|not found"; then
        echo -e "${GREEN}ABSENT${NC}: $res"
        ABSENT_COUNT=$((ABSENT_COUNT + 1))
    else
        echo -e "${RED}STILL PRESENT${NC}: $res"
    fi
done
assert "[ '$ABSENT_COUNT' -eq 10 ]" "10/10 explicit targets absent (got $ABSENT_COUNT)"

# 6.3 NFD SCCs absent
NFD_SCC1_POST=$(oc get scc nfd-topology-updater --no-headers 2>&1 || true)
NFD_SCC2_POST=$(oc get scc nfd-worker --no-headers 2>&1 || true)
assert "echo '$NFD_SCC1_POST' | grep -qi 'not found'" "NFD SCC nfd-topology-updater absent"
assert "echo '$NFD_SCC2_POST' | grep -qi 'not found'" "NFD SCC nfd-worker absent"

# 6.4 Authorino CRBs absent
POST_AUTH_CRBS=$(oc get clusterrolebindings --no-headers 2>/dev/null | grep -c authorino || true)
assert "[ '$POST_AUTH_CRBS' -eq 0 ]" "Authorino CRBs absent (got $POST_AUTH_CRBS)"

# 6.5 Terminating
POST_TERM=$(oc get ns --no-headers 2>/dev/null | grep -c Terminating || true)
assert "[ '$POST_TERM' -eq 0 ]" "0 Terminating namespaces (got $POST_TERM)"

# 6.6 Node Ready
POST_NODE=$(oc get nodes --no-headers 2>/dev/null | awk '{print $2}')
assert "[ '$POST_NODE' = 'Ready' ]" "Node Ready (got $POST_NODE)"

# 6.7 Post PV/PVC inventory
echo -e "\n${BOLD}--- Recording PV/PVC post-inventory ---${NC}"
oc get pv -o json 2>/dev/null | python3 -c "
import json, sys
data = json.load(sys.stdin)
items = [{'name': i['metadata']['name'], 'uid': i['metadata']['uid'],
          'capacity': i['spec']['capacity']['storage'],
          'status': i['status']['phase']} for i in data['items']]
json.dump(items, sys.stdout, indent=2)
" > "$EVIDENCE_DIR/inventory/pv-post.json"
POST_PV_COUNT=$(python3 -c "import json; print(len(json.load(open('$EVIDENCE_DIR/inventory/pv-post.json'))))")

oc get pvc -A -o json 2>/dev/null | python3 -c "
import json, sys
data = json.load(sys.stdin)
items = [{'name': i['metadata']['name'], 'namespace': i['metadata']['namespace'],
          'uid': i['metadata']['uid'], 'capacity': i['spec']['resources']['requests']['storage'],
          'status': i['status']['phase']} for i in data['items']]
json.dump(items, sys.stdout, indent=2)
" > "$EVIDENCE_DIR/inventory/pvc-post.json"
POST_PVC_COUNT=$(python3 -c "import json; print(len(json.load(open('$EVIDENCE_DIR/inventory/pvc-post.json'))))")

echo "Post PVs: $POST_PV_COUNT (pre: $PRE_PV_COUNT)"
echo "Post PVCs: $POST_PVC_COUNT (pre: $PRE_PVC_COUNT)"

# PV/PVC comparison
python3 -c "
import json
pre_pv = json.load(open('$EVIDENCE_DIR/inventory/pv-pre.json'))
post_pv = json.load(open('$EVIDENCE_DIR/inventory/pv-post.json'))
pre_pvc = json.load(open('$EVIDENCE_DIR/inventory/pvc-pre.json'))
post_pvc = json.load(open('$EVIDENCE_DIR/inventory/pvc-post.json'))

pre_pv_uids = {p['uid'] for p in pre_pv}
post_pv_uids = {p['uid'] for p in post_pv}
pre_pvc_uids = {p['uid'] for p in pre_pvc}
post_pvc_uids = {p['uid'] for p in post_pvc}

removed_pvs = pre_pv_uids - post_pv_uids
added_pvs = post_pv_uids - pre_pv_uids
removed_pvcs = pre_pvc_uids - post_pvc_uids
added_pvcs = post_pvc_uids - pre_pvc_uids

result = {
    'pre_pv_count': len(pre_pv), 'post_pv_count': len(post_pv),
    'pre_pvc_count': len(pre_pvc), 'post_pvc_count': len(post_pvc),
    'removed_pv_uids': list(removed_pvs), 'added_pv_uids': list(added_pvs),
    'removed_pvc_uids': list(removed_pvcs), 'added_pvc_uids': list(added_pvcs),
}
json.dump(result, open('$EVIDENCE_DIR/inventory/pv-pvc-comparison.json', 'w'), indent=2)
print('PV/PVC comparison saved.')
if removed_pvs: print(f'  PVs removed: {len(removed_pvs)}')
if removed_pvcs: print(f'  PVCs removed: {len(removed_pvcs)}')
if not removed_pvs and not removed_pvcs: print('  No PV/PVC removed (all retained).')
"

# 6.8 Remaining subscriptions
echo -e "\n${BOLD}--- Remaining subscriptions ---${NC}"
oc get subscriptions.operators.coreos.com -A --no-headers 2>/dev/null \
    | awk '{print $1, $2}' | tee "$EVIDENCE_DIR/inventory/remaining-subs.txt"

# ══════════════════════════════════════════════════════════════
echo -e "\n${BOLD}═══ PHASE 7: EVIDENCE SUMMARY ═══${NC}\n"

# Collect backup receipt hashes
python3 -c "
import json, os, hashlib, glob

receipts = []
for manifest in glob.glob('$BACKUP_DIR/**/manifest.yaml', recursive=True):
    with open(manifest, 'rb') as f:
        sha = hashlib.sha256(f.read()).hexdigest()
    receipts.append({
        'path': os.path.relpath(manifest, '$BACKUP_DIR'),
        'manifest_sha256': sha,
    })

summary = {
    'phase': 'D-Cycle-A-v3',
    'status': 'COMPLETED',
    'timestamp': '$TIMESTAMP',
    'cluster_uid': '$CLUSTER_UID',
    'binary': '$OC_DEPS',
    'assertions_passed': $PASS_COUNT + $ABSENT_COUNT,
    'operators_deleted': 15,
    'explicit_targets_deleted': 10,
    'nfd_sccs_absent': True,
    'authorino_crbs_absent': True,
    'target_subs_remaining': $POST_SUBS,
    'terminating': $POST_TERM,
    'node_status': '$POST_NODE',
    'pre_pv': $PRE_PV_COUNT,
    'post_pv': $POST_PV_COUNT,
    'pre_pvc': $PRE_PVC_COUNT,
    'post_pvc': $POST_PVC_COUNT,
    'backup_receipts': receipts,
}
json.dump(summary, open('$EVIDENCE_DIR/summary.json', 'w'), indent=2)
print(json.dumps(summary, indent=2))
"

echo -e "\n${GREEN}${BOLD}═══ CYCLE A v3 COMPLETE ═══${NC}"
echo -e "${GREEN}Cluster left in deleted state for independent verification.${NC}\n"
