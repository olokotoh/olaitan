#!/usr/bin/env bash
# Does this cluster's CNI actually ENFORCE NetworkPolicy?
#
# Olaitan's entire response mechanism writes NetworkPolicies. On a cluster whose
# CNI ignores them (kind's default kindnet, k3s with stock flannel) the API
# server accepts every policy and the data plane does nothing -- so the agent
# reports a workload QUARANTINED while it keeps talking to the internet.
#
# This script proves enforcement empirically instead of assuming it:
#   1. run a client pod and a server pod
#   2. confirm the client CAN reach the server (baseline: without this, a later
#      "blocked" result would prove nothing -- it might have been broken all along)
#   3. apply a deny-all ingress policy on the server
#   4. re-test: blocked => ENFORCED, still reachable => NOT ENFORCED
#
# Exit 0 = enforced, 1 = NOT enforced, 2 = inconclusive (setup failed).
set -uo pipefail

NS="${NS:-olaitan-netpol-probe}"
TIMEOUT="${TIMEOUT:-90s}"

cleanup() { kubectl delete ns "$NS" --wait=false >/dev/null 2>&1 || true; }
trap cleanup EXIT

echo "== NetworkPolicy enforcement probe =="
echo "   context: $(kubectl config current-context 2>/dev/null || echo '?')"

kubectl create ns "$NS" >/dev/null 2>&1 || true

kubectl -n "$NS" run server --image=registry.k8s.io/e2e-test-images/agnhost:2.47 \
  --labels=app=server --port=8080 \
  --command -- /agnhost netexec --http-port=8080 >/dev/null 2>&1

if ! kubectl -n "$NS" wait --for=condition=Ready pod/server --timeout="$TIMEOUT" >/dev/null 2>&1; then
  echo "INCONCLUSIVE: server pod never became Ready"
  exit 2
fi
SERVER_IP="$(kubectl -n "$NS" get pod server -o jsonpath='{.status.podIP}')"
echo "   server pod IP: $SERVER_IP"

probe() {
  kubectl -n "$NS" run probe-$1 --rm -i --restart=Never --quiet \
    --image=registry.k8s.io/e2e-test-images/agnhost:2.47 \
    --command -- /agnhost connect --timeout=5s "${SERVER_IP}:8080" 2>&1
}

# What "blocked" looks like. agnhost prints a bare uppercase TIMEOUT on a
# blocked connection, NOT the "timed out" phrasing wget/curl use -- an earlier
# version of this script grepped for "timed out", never matched, and therefore
# reported NOT ENFORCED on every cluster including ones that enforce correctly.
# For a security tool that failure direction is the dangerous one: it accuses a
# working CNI of being broken, and it would have shipped as a documented
# "finding" about kind. Match the real strings, and verify the matcher itself
# against a known-blocked destination before trusting the verdict.
BLOCKED_RE="TIMEOUT|timed out|refused|no route|REFUSED|unreachable"

# Self-test: probe an address nothing can reach. If THIS does not read as
# blocked, the matcher is broken and every later verdict is meaningless.
SELFTEST="$(kubectl -n "$NS" run probe-selftest --rm -i --restart=Never --quiet \
  --image=registry.k8s.io/e2e-test-images/agnhost:2.47 \
  --command -- /agnhost connect --timeout=5s 10.255.255.1:8080 2>&1 || true)"
if ! echo "$SELFTEST" | grep -qiE "$BLOCKED_RE"; then
  echo "INCONCLUSIVE: the blocked-connection matcher does not recognise a known"
  echo "   unreachable destination, so this script cannot tell enforced from not."
  echo "   probe output was: $SELFTEST"
  exit 2
fi

# Step 2: baseline reachability. Without this the test is worthless.
OUT_BEFORE="$(probe before)"
if echo "$OUT_BEFORE" | grep -qiE "$BLOCKED_RE"; then
  echo "INCONCLUSIVE: client could not reach server BEFORE any policy"
  echo "   $OUT_BEFORE"
  exit 2
fi
echo "   baseline: client CAN reach server (as expected)"

# Step 3: deny all ingress to the server.
kubectl -n "$NS" apply -f - >/dev/null <<'EOF'
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: deny-all-ingress-to-server
spec:
  podSelector:
    matchLabels:
      app: server
  policyTypes: [Ingress]
EOF
sleep 5

# Step 4: the verdict.
OUT_AFTER="$(probe after)"
if echo "$OUT_AFTER" | grep -qiE "$BLOCKED_RE"; then
  echo
  echo "RESULT: NetworkPolicy IS ENFORCED on this cluster."
  echo "        Olaitan's isolation response will actually contain a workload."
  exit 0
fi

echo
echo "RESULT: NetworkPolicy is NOT ENFORCED on this cluster."
echo "        The API server accepted a deny-all policy and traffic still flowed."
echo
echo "   WHY THIS MATTERS: Olaitan would mark a workload QUARANTINED, write the"
echo "   audit record and move the state machine, while the pod keeps talking to"
echo "   the internet. Containment would be reported but not achieved."
echo
echo "   FIX: install a CNI that enforces NetworkPolicy (Calico, Cilium), or run"
echo "   Olaitan in observe-only mode (response.networkPolicy.enabled=false, the"
echo "   default) so it never claims containment it cannot deliver."
exit 1
