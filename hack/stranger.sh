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
# workload in its namespace. It does not claim the transition came from
# that one alert; several real Falco alerts can feed it.
#
# Nothing here talks to NATS and nothing turns Falco off.
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
ST_NO_MANIFEST="1.0.0-rc1 1.0.0-rc2 1.0.0-rc3"
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

st_run() {
	printf '+ %s\n' "$*"
	[ "${STRANGER_PLAN:-}" = "1" ] && return 0
	"$@"
}

st_no_manifest() {
	local v
	for v in $ST_NO_MANIFEST; do
		[ "$v" = "$1" ] && return 0
	done
	return 1
}

st_aggregator_logs() {
	kubectl -n "$ST_NS" logs -l app.kubernetes.io/component=aggregator --tail=-1 2>/dev/null || true
}

st_falco_logs() {
	kubectl -n "$ST_NS" logs -l app.kubernetes.io/name=falco -c falco --tail=-1 2>/dev/null || true
}

# st_rollout TYPE: wait for every object of TYPE in the namespace to roll
# out. The kubectl path has no wait of its own in the README.
st_rollout() {
	local type="$1" name
	if [ "${STRANGER_PLAN:-}" = "1" ]; then
		printf '+ kubectl -n %s rollout status %s/<each> --timeout=10m\n' "$ST_NS" "$type"
		return 0
	fi
	for name in $(kubectl -n "$ST_NS" get "$type" -o name); do
		st_run kubectl -n "$ST_NS" rollout status "$name" --timeout=10m
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
		echo "stranger: $readme has no bash block $n under '$heading'; the check follows the README, so fix the README or this script" >&2
		exit 1
	fi
	if [[ "$block" != *"$mark"* ]]; then
		echo "stranger: bash block $n under '$heading' in $readme does not contain '$mark'; it is not the $leg path any more:" >&2
		printf '%s\n' "$block" >&2
		exit 1
	fi
	if [ "$leg" = helm ]; then
		version="$(sed -n 's/.*--version[ =]\{1,\}\([0-9A-Za-z.+-]\{1,\}\).*/\1/p' <<<"$block" | head -n 1)"
	else
		version="$(sed -n 's#.*/releases/download/v\([^/[:space:]]\{1,\}\)/install\.yaml.*#\1#p' <<<"$block" | head -n 1)"
	fi
	if [ -z "$version" ]; then
		echo "stranger: cannot read the version the $leg block installs" >&2
		exit 1
	fi
	if [ -n "$expect" ] && [ "$version" != "$expect" ]; then
		echo "stranger: the README's $leg block installs $version, this run tests $expect" >&2
		exit 1
	fi
	st_say "$leg path: $(basename "$readme"), '$heading', bash block $n, version $version"

	if [ "$leg" = kubectl ] && st_no_manifest "$version"; then
		st_say "kubectl path skipped: v$version was released before install.yaml was a release asset (Story 12.4); it runs from the next release on"
		return 0
	fi

	local t0
	t0="$(date +%s)"
	if [ "$leg" = kubectl ]; then
		st_say "a fresh kind cluster for the kubectl path (the README assumes one)"
		st_run kind create cluster --name "$ST_CLUSTER"
	fi

	if [ "$leg" = kubectl ]; then
		# THROWAWAY: rc4 has no install.yaml asset; render one from the
		# published rc4 chart with the release's own script, in place of the URL.
		mkdir -p /tmp/st
		helm pull oci://ghcr.io/olokotoh/charts/olaitan --version "$version" -d /tmp/st
		"$ST_ROOT/hack/render-install-manifest.sh" "/tmp/st/olaitan-$version.tgz" /tmp/st/install.yaml
		block="${block//"https://github.com/olokotoh/olaitan/releases/download/v$version/install.yaml"//tmp/st/install.yaml}"
	fi
	st_say "running the README block as written"
	echo "--- README block begin"
	printf '%s\n' "$block"
	echo "--- README block end"
	if [ "$plan" != "1" ]; then
		bash -e -o pipefail -c "$block"
	fi

	st_say "every workload rolled out, every pod Ready, Falco among them"
	st_rollout daemonset
	st_rollout deployment
	st_rollout statefulset
	st_run kubectl -n "$ST_NS" wait pod --all --for=condition=Ready --timeout=10m
	st_run kubectl -n "$ST_NS" wait pod -l app.kubernetes.io/name=falco --for=condition=Ready --timeout=5m
	st_run kubectl -n "$ST_NS" get pods -o wide
	local t_ready
	t_ready="$(date +%s)"

	st_say "a throwaway pod in $ST_DEMO_NS (a namespace the agent scores)"
	st_run kubectl create namespace "$ST_DEMO_NS"
	st_run kubectl -n "$ST_DEMO_NS" run "$ST_DEMO_POD" --image="$QS_DEMO_IMAGE" --restart=Never -- sleep 3600
	st_run kubectl -n "$ST_DEMO_NS" wait "pod/$ST_DEMO_POD" --for=condition=Ready --timeout=3m

	st_say "the real action: cat /etc/shadow in the pod, until there is a Falco alert on /etc/shadow from it and an FSM transition for its namespace"
	if [ "$plan" = "1" ]; then
		st_run kubectl -n "$ST_DEMO_NS" exec "$ST_DEMO_POD" -- cat /etc/shadow
		return 0
	fi

	local attempt found="" rule="" t_seen="" t_attack
	for attempt in $(seq 1 "$ST_ATTEMPTS"); do
		# A read before Falco's driver is loaded is not seen, so the real
		# read is repeated until both signals are there. Each one is counted.
		printf '+ kubectl -n %s exec %s -- cat /etc/shadow   (read %s of %s)\n' \
			"$ST_DEMO_NS" "$ST_DEMO_POD" "$attempt" "$ST_ATTEMPTS"
		kubectl -n "$ST_DEMO_NS" exec "$ST_DEMO_POD" -- cat /etc/shadow >/dev/null
		t_attack="$(date +%s)"
		while [ $(($(date +%s) - t_attack)) -lt "$ST_ATTEMPT_GAP" ]; do
			sleep "$ST_POLL"
			[ -n "$found" ] || found="$(st_aggregator_logs | qs_parse_transition "$ST_DEMO_NS")" || found=""
			[ -n "$rule" ] || rule="$(st_falco_logs | qs_parse_rule "$ST_DEMO_NS" "$ST_DEMO_POD")" || rule=""
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
		exit 1
	fi

	local wl from to score ts
	IFS=$'\t' read -r wl from to score ts <<<"$found"
	echo
	echo "  The $leg path of the README installed v$version and Olaitan saw a real action:"
	echo
	printf '    %-10s %s\n' "workload" "$wl"
	printf '    %-10s %s\n' "from" "$from"
	printf '    %-10s %s\n' "to" "$to"
	printf '    %-10s %s\n' "score" "$score"
	printf '    %-10s %s\n' "logged at" "$ts (aggregator clock)"
	printf '    %-10s %s\n' "falco rule" "$rule (on /etc/shadow, from $ST_DEMO_POD)"
	printf '    %-10s %s\n' "reads" "$attempt of /etc/shadow"
	echo
	printf '  start -> every pod Ready:                          %ss\n' "$((t_ready - t0))"
	printf '  start -> Falco alert and FSM transition both seen:  %ss\n' "$((t_seen - t0))"
}

if [ "${BASH_SOURCE[0]}" = "$0" ]; then
	main "$@"
fi
