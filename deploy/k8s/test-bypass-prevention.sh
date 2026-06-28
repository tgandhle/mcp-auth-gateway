#!/usr/bin/env bash
# Bypass-prevention proof for the gateway-to-upstream trust boundary.
#
# Asserts two things against a live cluster with an enforcing CNI:
#   POSITIVE: a pod with the gateway's label CAN reach the upstream on :9000.
#   NEGATIVE: a pod WITHOUT the gateway's label CANNOT reach the upstream --
#             a direct bypass attempt (the forged-X-Forwarded-Sub path) is
#             refused at the network layer.
#
# If the NEGATIVE assertion fails (the bypass pod reaches the upstream), the
# trust boundary is not enforced and the test fails loudly. This is the whole
# point of the PR: prove the boundary, don't just document it.
set -euo pipefail

NS=mcp-gateway
UPSTREAM_URL="http://upstream.${NS}.svc.cluster.local:9000/"
TIMEOUT=5

echo "== waiting for upstream to be ready =="
kubectl -n "$NS" rollout status deploy/upstream --timeout=120s

# --- POSITIVE: a pod LABELLED app=gateway can reach the upstream ----------
echo "== POSITIVE: gateway-labelled pod should reach upstream =="
set +e
POS_OUT=$(kubectl -n "$NS" run probe-allowed \
  --labels="app=gateway" \
  --image=curlimages/curl:8.10.1 \
  --restart=Never --rm -i --quiet \
  --command -- curl -s --max-time "$TIMEOUT" "$UPSTREAM_URL")
POS_RC=$?
set -e
echo "  result: rc=$POS_RC out='${POS_OUT}'"
if [ "$POS_RC" -ne 0 ] || ! echo "$POS_OUT" | grep -q "upstream-reached"; then
  echo "FAIL: gateway-labelled pod could NOT reach upstream (policy too strict or upstream down)"
  exit 1
fi
echo "  PASS: gateway path works"

# --- NEGATIVE: a pod NOT labelled app=gateway must be blocked --------------
echo "== NEGATIVE: non-gateway pod must be blocked from upstream =="
set +e
NEG_OUT=$(kubectl -n "$NS" run probe-bypass \
  --labels="app=attacker" \
  --image=curlimages/curl:8.10.1 \
  --restart=Never --rm -i --quiet \
  --command -- curl -s --max-time "$TIMEOUT" "$UPSTREAM_URL")
NEG_RC=$?
set -e
echo "  result: rc=$NEG_RC out='${NEG_OUT}'"
# A blocked connection times out / fails: curl returns non-zero and no body.
if [ "$NEG_RC" -eq 0 ] && echo "$NEG_OUT" | grep -q "upstream-reached"; then
  echo "FAIL: BYPASS SUCCEEDED -- non-gateway pod reached the upstream directly."
  echo "      The NetworkPolicy is not being enforced. Trust boundary broken."
  exit 1
fi
echo "  PASS: direct bypass was refused at the network layer"

echo "== ALL ASSERTIONS PASSED: trust boundary enforced =="
