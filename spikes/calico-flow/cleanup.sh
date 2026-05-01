#!/usr/bin/env bash
# Tear down the kind cluster used by the spike. Idempotent.
set -euo pipefail

CLUSTER_NAME="${CLUSTER_NAME:-olaitan-flow-spike}"

if kind get clusters 2>/dev/null | grep -qx "${CLUSTER_NAME}"; then
  echo "Deleting kind cluster ${CLUSTER_NAME}..."
  kind delete cluster --name "${CLUSTER_NAME}"
else
  echo "No kind cluster named ${CLUSTER_NAME} present; nothing to do."
fi
