#!/usr/bin/env bash
# hack/stranger.sh: the stranger-path check (Story 12.5), run by
# .github/workflows/stranger.yml on every release tag and nightly.
#
# rc3 shipped broken because nothing installed the published chart the way
# the README says. This script does exactly that. It reads README.md when it
# runs, takes the install block of one path out of it, and runs that text
# as it stands, so a README change that breaks the install breaks this
# check. Then it checks for itself that every workload rolled out, every pod
# is Ready and a Falco pod is among them, and runs a real attack: a
# throwaway pod reads /etc/shadow until Falco has raised an alert on that
# read from that pod AND the aggregator has logged an FSM transition for a
# workload in its namespace. It then prints every Falco rule that fired for
# that pod up to the transition, with its priority, and says so when none of
# them was the read: several real alerts can feed one transition, and on
# kind without the kind overlay the node's own hook trips a Critical rule
# for the pod (#177), which once passed for the read's result. On the helm
# path (kind overlay) a transition the read did not cause fails the check;
# on the kubectl path (install.yaml, no kind hook exception) it is a
# warning in the log and the job summary.
#
# Nothing here talks to NATS and nothing turns Falco off.
#
# Every failure names its phase, so a flaky runner is told apart from a
# broken release: readme (the block moved or names another version),
# install (the README block itself failed), infra: cluster / rollout /
# pull / exec / kubectl logs, and product: no Falco alert / no FSM
# transition / the read did not cause the transition (helm path). A rollout that never goes Ready can still have a product
# cause (a crash loop); the diagnostics step shows which.
#
# Usage: hack/stranger.sh helm|kubectl
#   helm     README "### Try it on kind", bash block 1 (it creates the kind
#            cluster itself, installs the published chart, waits)
#   kubectl  README "## Install", bash block 2 (namespace, Secret,
#            kubectl apply of the release's install.yaml) on a fresh kind
#            cluster this script creates first. Releases before Story 12.4
#            have no install.yaml; only those are skipped (ST_NO_MANIFEST).
#
# Settings (environment):
#   STRANGER_README           README to read (README.md of this checkout)
#   STRANGER_EXPECT_VERSION   fail unless the block installs this version
#   STRANGER_PLAN=1           print the block and the commands; run nothing
set -euo pipefail

ST_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# The transition and Falco-alert parsers and the pinned busybox image are
# the quickstart's (Story 12.2). Sourcing it does not run it.
# shellcheck source=hack/quickstart.sh
source "$ST_ROOT/hack/quickstart.sh"

ST_NS="olaitan"
ST_CLUSTER="olaitan"
ST_DEMO_NS="olaitan-stranger"
ST_DEMO_POD="stranger-demo"
ST_ATTEMPTS=8
ST_ATTEMPT_GAP=15
ST_POLL=5
# Releases cut before install.yaml was a release asset (Story 12.4).
ST_NO_MANIFEST="1.0.0-rc1 1.0.0-rc2 1.0.0-rc3 1.0.0-rc4"
ST_HELM_MARK="helm install olaitan oci://ghcr.io/olokotoh/charts/olaitan"
ST_KUBECTL_MARK="kubectl apply -f https://github.com/olokotoh/olaitan/releases/download/"

# stranger_readme_block FILE HEADING N: print the N-th ```bash block after
# the line equal to HEADING, stopping at the next heading. Lines inside a
# fence are never headings. Exit 1 when there is no such block.
stranger_readme_block() {
	awk -v h="$2" -v n="$3" '
		!found { if ($0 == h) found = 1; next }
		!infence && /^#/ { exit }
		!infence && /^```/ {
			infence = 1
			lang = substr($0, 4)
			gsub(/^[ \t]+|[ \t]+$/, "", lang)
			isbash = (lang == "bash")
			if (isbash) c++
			next
		}
		infence && /^```/ {
			if (isbash && c == n) { done = 1; exit }
			infence = 0
			next
		}
		infence && isbash && c == n { out = out $0 "\n" }
		END { if (!done) exit 1; printf "%s", out }
	' "$1"
}

st_say() { printf '==> %s\n' "$*"; }

# st_summary LINE: add a line to the job summary when there is one.
st_summary() {
	if [ -n "${GITHUB_STEP_SUMMARY:-}" ]; then
		printf '%s\n' "$*" >>"$GITHUB_STEP_SUMMARY"
	fi
}

# st_fail PHASE MESSAGE: stop the check, naming the phase that failed, in the
# log, as an annotation and in the job summary.
st_fail() {
	local phase="$1"
	shift
	printf 'stranger: FAILED [%s] %s\n' "$phase" "$*" >&2
	printf '::error title=stranger-path check failed [%s]::%s\n' "$phase" "$*"
	st_summary "- **FAILED [$phase]** $*"
	exit 1
}

st_run() {
	printf '+ %s\n' "$*"
	[ "${STRANGER_PLAN:-}" = "1" ] && return 0
	"$@"
}

# st_step PHASE CMD...: st_run, and on failure st_fail PHASE with the exit code.
# The command's own stderr stays in the log.
st_step() {
	local phase="$1" rc=0
	shift
	st_run "$@" || rc=$?
	[ "$rc" -eq 0 ] || st_fail "$phase" "'$*' exited $rc"
}

st_no_manifest() {
	local v
	for v in $ST_NO_MANIFEST; do
		[ "$v" = "$1" ] && return 0
	done
	return 1
}

# The log readers keep kubectl's stderr and exit code: a failed read is an
# infra fault, never "no alert yet".
st_aggregator_logs() {
	kubectl -n "$ST_NS" logs -l app.kubernetes.io/component=aggregator --tail=-1
}

st_falco_logs() {
	kubectl -n "$ST_NS" logs -l app.kubernetes.io/name=falco -c falco --tail=-1
}

# st_rollout TYPE: wait for every object of TYPE in the namespace to roll
# out. The kubectl path has no wait of its own in the README.
st_rollout() {
	local type="$1" names name rc=0
	if [ "${STRANGER_PLAN:-}" = "1" ]; then
		printf '+ kubectl -n %s rollout status %s/<each> --timeout=10m\n' "$ST_NS" "$type"
		return 0
	fi
	# Listed first, on its own: a failed `get` inside the `for` list would
	# look like "no workloads of this type" and pass.
	names="$(kubectl -n "$ST_NS" get "$type" -o name)" || rc=$?
	[ "$rc" -eq 0 ] || st_fail "infra: rollout" "kubectl get $type in $ST_NS exited $rc"
	for name in $names; do
		st_step "infra: rollout" kubectl -n "$ST_NS" rollout status "$name" --timeout=10m
	done
}

main() {
	local leg="${1:-}"
	local readme="${STRANGER_README:-$ST_ROOT/README.md}"
	local expect="${STRANGER_EXPECT_VERSION:-}"
	local plan="${STRANGER_PLAN:-}"
	local heading n mark version block

	case "$leg" in
	helm) heading="### Try it on kind" n=1 mark="$ST_HELM_MARK" ;;
	kubectl) heading="## Install" n=2 mark="$ST_KUBECTL_MARK" ;;
	*)
		echo "usage: hack/stranger.sh helm|kubectl" >&2
		exit 2
		;;
	esac

	if ! block="$(stranger_readme_block "$readme" "$heading" "$n")"; then
		st_fail readme "$readme has no bash block $n under '$heading'; the check follows the README, so fix the README or this script"
	fi
	if [[ "$block" != *"$mark"* ]]; then
		printf '%s\n' "$block" >&2
		st_fail readme "bash block $n under '$heading' in $readme does not contain '$mark'; it is not the $leg path any more (block above)"
	fi
	if [ "$leg" = helm ]; then
		# Only the `helm install` command itself, continuation lines joined:
		# a --version in a comment or another command is not what installs.
		version="$(sed -e ':a' -e '/\\$/{N;s/\\\n//;ba' -e '}' <<<"$block" |
			sed -n 's/^[[:space:]]*helm install[[:space:]].*--version[ =]\{1,\}\([0-9A-Za-z.+-]\{1,\}\).*/\1/p' | head -n 1)"
	else
		version="$(sed -n 's#.*/releases/download/v\([^/[:space:]]\{1,\}\)/install\.yaml.*#\1#p' <<<"$block" | head -n 1)"
	fi
	if [ -z "$version" ]; then
		st_fail readme "cannot read the version the $leg block installs (helm: --version on the helm install command)"
	fi
	if [ -n "$expect" ] && [ "$version" != "$expect" ]; then
		st_fail readme "the README's $leg block installs $version, this run tests $expect"
	fi
	st_say "$leg path: $(basename "$readme"), '$heading', bash block $n, version $version"

	if [ "$leg" = kubectl ] && st_no_manifest "$version"; then
		local why="kubectl path skipped: v$version was released before install.yaml was a release asset (Story 12.4); it runs from the next release on"
		st_say "$why"
		printf '::warning title=stranger-path check::%s\n' "$why"
		st_summary "- **WARNING** $why"
		return 0
	fi

	local t0
	t0="$(date +%s)"
	if [ "$leg" = kubectl ]; then
		st_say "a fresh kind cluster for the kubectl path (the README assumes one)"
		st_step "infra: cluster" kind create cluster --name "$ST_CLUSTER"
	fi

	st_say "running the README block as written"
	echo "--- README block begin"
	printf '%s\n' "$block"
	echo "--- README block end"
	if [ "$plan" != "1" ]; then
		local rc=0
		bash -e -o pipefail -c "$block" || rc=$?
		[ "$rc" -eq 0 ] || st_fail install "the README $leg block exited $rc (its output is above)"
	fi

	st_say "every workload rolled out, every pod Ready, Falco among them"
	st_rollout daemonset
	st_rollout deployment
	st_rollout statefulset
	st_step "infra: rollout" kubectl -n "$ST_NS" wait pod --all --for=condition=Ready --timeout=10m
	st_step "infra: rollout" kubectl -n "$ST_NS" wait pod -l app.kubernetes.io/name=falco --for=condition=Ready --timeout=5m
	st_step "infra: rollout" kubectl -n "$ST_NS" get pods -o wide
	local t_ready
	t_ready="$(date +%s)"

	st_say "a throwaway pod in $ST_DEMO_NS (a namespace the agent scores)"
	st_step "infra: pull" kubectl create namespace "$ST_DEMO_NS"
	st_step "infra: pull" kubectl -n "$ST_DEMO_NS" run "$ST_DEMO_POD" --image="$QS_DEMO_IMAGE" --restart=Never -- sleep 3600
	st_step "infra: pull" kubectl -n "$ST_DEMO_NS" wait "pod/$ST_DEMO_POD" --for=condition=Ready --timeout=3m

	st_say "the real action: cat /etc/shadow in the pod, until there is a Falco alert on /etc/shadow from it and an FSM transition for its namespace"
	if [ "$plan" = "1" ]; then
		st_run kubectl -n "$ST_DEMO_NS" exec "$ST_DEMO_POD" -- cat /etc/shadow
		return 0
	fi

	local attempt found="" rule="" t_seen="" t_attack logs rc
	for attempt in $(seq 1 "$ST_ATTEMPTS"); do
		# A read before Falco's driver is loaded is not seen, so the real
		# read is repeated until both signals are there. Each one is counted.
		printf '+ kubectl -n %s exec %s -- cat /etc/shadow   (read %s of %s)\n' \
			"$ST_DEMO_NS" "$ST_DEMO_POD" "$attempt" "$ST_ATTEMPTS"
		rc=0
		kubectl -n "$ST_DEMO_NS" exec "$ST_DEMO_POD" -- cat /etc/shadow >/dev/null || rc=$?
		[ "$rc" -eq 0 ] || st_fail "infra: exec" "kubectl exec cat /etc/shadow in $ST_DEMO_NS/$ST_DEMO_POD exited $rc"
		t_attack="$(date +%s)"
		while [ $(($(date +%s) - t_attack)) -lt "$ST_ATTEMPT_GAP" ]; do
			sleep "$ST_POLL"
			# Read the log first, on its own, so a kubectl failure stops the
			# check as an infra fault; a parser miss only means "not yet".
			if [ -z "$found" ]; then
				rc=0
				logs="$(st_aggregator_logs)" || rc=$?
				[ "$rc" -eq 0 ] || st_fail "infra: kubectl logs" "reading the aggregator log exited $rc (kubectl's error is above)"
				found="$(qs_parse_transition "$ST_DEMO_NS" <<<"$logs")" || found=""
			fi
			if [ -z "$rule" ]; then
				rc=0
				logs="$(st_falco_logs)" || rc=$?
				[ "$rc" -eq 0 ] || st_fail "infra: kubectl logs" "reading the Falco log exited $rc (kubectl's error is above)"
				rule="$(qs_parse_rule "$ST_DEMO_NS" "$ST_DEMO_POD" <<<"$logs")" || rule=""
			fi
			if [ -n "$found" ] && [ -n "$rule" ]; then
				t_seen="$(date +%s)"
				break 2
			fi
		done
	done

	if [ -z "$t_seen" ]; then
		echo "stranger: after $ST_ATTEMPTS reads of /etc/shadow:" >&2
		echo "stranger:   Falco alert on /etc/shadow from $ST_DEMO_NS/$ST_DEMO_POD: ${rule:-none}" >&2
		echo "stranger:   FSM transition in $ST_DEMO_NS: ${found:-none}" >&2
		local missing=()
		[ -n "$rule" ] || missing+=("product: no Falco alert")
		[ -n "$found" ] || missing+=("product: no FSM transition")
		local phase
		phase="$(printf '%s, ' "${missing[@]}")"
		st_fail "${phase%, }" "after $ST_ATTEMPTS real reads of /etc/shadow every pod was Ready but detection did not complete"
	fi

	local wl from to score ts report line
	IFS=$'\t' read -r wl from to score ts <<<"$found"
	rc=0
	logs="$(st_falco_logs)" || rc=$?
	[ "$rc" -eq 0 ] || st_fail "infra: kubectl logs" "reading the Falco log exited $rc (kubectl's error is above)"
	rc=0
	report="$(qs_report_rules "$ST_DEMO_NS" "$ST_DEMO_POD" "$ts" <<<"$logs")" || rc=$?
	echo
	echo "  The $leg path of the README installed v$version. $(qs_headline "$rc" "$report")"
	echo
	printf '    %-10s %s\n' "workload" "$wl"
	printf '    %-10s %s\n' "from" "$from"
	printf '    %-10s %s\n' "to" "$to"
	printf '    %-10s %s\n' "score" "$score"
	printf '    %-10s %s\n' "logged at" "$ts (aggregator clock)"
	printf '    %-10s %s\n' "reads" "$attempt of /etc/shadow"
	echo
	printf '%s\n' "$report"
	echo
	st_summary "- $leg path, v$version: $wl $from -> $to, score $score"
	while IFS= read -r line; do
		st_summary "  - ${line#"${line%%[![:space:]]*}"}"
	done <<<"$report"
	printf '  start -> every pod Ready:                          %ss\n' "$((t_ready - t0))"
	printf '  start -> Falco alert and FSM transition both seen:  %ss\n' "$((t_seen - t0))"
	# 0: the read alone (by priority); 3: the read and higher-priority rules,
	# named in the headline. Anything else means the read was not shown to
	# cause the transition. The helm path installs the kind overlay, so that
	# is a product fault. The kubectl path installs install.yaml, which has
	# no kind hook exception (#180), so there kind's own node hook can move
	# the pod first: a warning, never a silent pass.
	if [ "$rc" -ne 0 ] && [ "$rc" -ne 3 ]; then
		local why="the $leg path: the read of /etc/shadow was not shown to cause the transition of $wl (score $score); the rules that fired are above"
		if [ "$leg" = helm ]; then
			st_fail "product: the read did not cause the transition" "$why"
		fi
		why="$why. install.yaml has no kind hook exception, so on kind the node's mount-product-files hook can trip a Critical rule for the pod first (#180)"
		printf '::warning title=stranger-path check::%s\n' "$why"
		st_summary "- **WARNING** $why"
	fi
}

if [ "${BASH_SOURCE[0]}" = "$0" ]; then
	main "$@"
fi
