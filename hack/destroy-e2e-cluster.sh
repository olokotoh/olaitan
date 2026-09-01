#!/usr/bin/env bash
# Safety net for the Olaitan kubeadm e2e cluster.
#
# The instruction was "test and delete, dont keep it running at all". A cluster
# billed by the hour must not outlive the session that created it, and the
# session can die (crash, /stop, network loss) with the cluster still up.
# This script is the backstop: it destroys unconditionally and is safe to run
# any number of times, including when nothing exists.
#
# Wired to a cron watchdog with a deadline, so the cluster is destroyed even if
# nobody is watching. Manual use: ./hack/destroy-e2e-cluster.sh
set -uo pipefail

# All four are overridable. They were hard-coded to one workstation (an
# absolute /home path and a named AWS profile), which made this script
# unusable for anyone else and unusable from CI. TFDIR now resolves relative
# to this script, so a clone anywhere works.
TFDIR="${TFDIR:-$(cd "$(dirname "$0")/../deploy/terraform" && pwd)}"
PROFILE="${AWS_PROFILE:-default}"
REGION="${AWS_REGION:-us-east-1}"
DEADLINE_FILE="${DEADLINE_FILE:-/tmp/olaitan-e2e-deadline}"

log() { printf '[%s] %s\n' "$(date -u +%H:%M:%SZ)" "$*"; }

# When invoked by the watchdog, only fire after the deadline has passed, so a
# legitimately running test is never killed mid-flight.
if [ "${1:-}" = "--if-expired" ]; then
  if [ ! -f "$DEADLINE_FILE" ]; then
    exit 0   # no test in flight; nothing to police
  fi
  now=$(date +%s)
  deadline=$(cat "$DEADLINE_FILE" 2>/dev/null || echo 0)
  if [ "$now" -lt "$deadline" ]; then
    exit 0   # still within the allotted window; stay quiet
  fi
  log "DEADLINE EXPIRED -- destroying the e2e cluster unconditionally."
fi

cd "$TFDIR" || { log "cannot cd to $TFDIR"; exit 1; }

log "destroying terraform-managed resources..."
terraform destroy -input=false -auto-approve -var="key_name=olaitan-e2e" 2>&1 | tail -5

# Terraform state can drift from reality (a partial apply, a manual console
# change). The bill is charged on what AWS actually runs, not on what the state
# file believes, so verify against the API and sweep any stragglers by tag.
log "verifying against AWS..."
LEFT=$(aws --profile "$PROFILE" --region "$REGION" ec2 describe-instances \
  --filters 'Name=tag:Project,Values=olaitan' \
            'Name=instance-state-name,Values=pending,running,stopping,stopped' \
  --query 'Reservations[].Instances[].InstanceId' --output text 2>/dev/null)

if [ -n "$LEFT" ]; then
  log "terraform left instances behind: $LEFT -- terminating directly."
  aws --profile "$PROFILE" --region "$REGION" ec2 terminate-instances \
    --instance-ids $LEFT --output table 2>&1 | tail -5
else
  log "confirmed: 0 instances tagged Project=olaitan remain."
fi

rm -f "$DEADLINE_FILE"
log "done."
