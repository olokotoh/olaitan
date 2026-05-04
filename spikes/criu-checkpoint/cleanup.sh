#!/usr/bin/env bash
# Tear down the CRIU spike kind cluster.
set -euo pipefail

CLUSTER_NAME="${CLUSTER_NAME:-olaitan-criu-spike}"

if kind get clusters 2>/dev/null | grep -q "^${CLUSTER_NAME}$"; then
  echo "Deleting kind cluster: ${CLUSTER_NAME}"
  kind delete cluster --name "${CLUSTER_NAME}"
else
  echo "No cluster named '${CLUSTER_NAME}' found — nothing to do."
fi
