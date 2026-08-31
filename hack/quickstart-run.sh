#!/usr/bin/env bash
# hack/quickstart-run.sh -- port-forward NATS and drive the quickstart demo.
#
# Split out of the Makefile because it needs a trap to clean up the
# port-forward, and a `make` recipe runs each line in its own shell.
#
# Usage: hack/quickstart-run.sh [namespace]
set -euo pipefail

NS="${1:-default}"
LOCAL_PORT="${QUICKSTART_NATS_PORT:-4222}"

# Resolve the NATS service the chart installed rather than assuming a release
# name, so a demo installed under a different release still works.
SVC="$(kubectl get svc -n "$NS" -l app.kubernetes.io/name=nats \
        -o jsonpath='{.items[0].metadata.name}' 2>/dev/null || true)"
if [ -z "$SVC" ]; then
  echo "quickstart: no NATS service found in namespace $NS" >&2
  echo "  kubectl get svc -n $NS" >&2
  exit 1
fi

kubectl port-forward -n "$NS" "svc/$SVC" "$LOCAL_PORT:4222" >/dev/null 2>&1 &
PF_PID=$!
cleanup() { kill "$PF_PID" 2>/dev/null || true; wait "$PF_PID" 2>/dev/null || true; }
trap cleanup EXIT

# Wait for the forward to accept connections rather than sleeping a guess.
for _ in $(seq 1 50); do
  if (exec 3<>/dev/tcp/127.0.0.1/"$LOCAL_PORT") 2>/dev/null; then
    exec 3<&- 3>&-
    break
  fi
  sleep 0.2
done

# The correlator resolves the pod through the apiserver and walks its
# OwnerReferences to a Deployment. Events attributed to a pod name that does
# not exist fall back to a pod-name-keyed identity with OwnerKind="Pod", and
# the OLT rules require owner_kind in [Deployment, StatefulSet], so nothing
# matches and the demo silently shows nothing. Resolve the REAL pod name, the
# way tests/e2e/rs_smoke_test.go does.
POD="$(kubectl get pods -n tenant-acme -l app=web-quickstart \
        -o jsonpath='{.items[0].metadata.name}' 2>/dev/null || true)"
if [ -z "$POD" ]; then
  echo "quickstart: demo workload pod not found in tenant-acme" >&2
  echo "  kubectl get pods -n tenant-acme" >&2
  exit 1
fi

go run ./cmd/olaitan-quickstart \
  --nats-url "nats://localhost:$LOCAL_PORT" \
  --scenario s1 \
  --pod "$POD"
