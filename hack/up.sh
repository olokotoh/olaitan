#!/usr/bin/env bash
# hack/up.sh: one command to a full live system (Story 12.3), run by `make up`.
#
# It checks the host first and stops, with the exact remedy for each problem,
# before anything is created. Then it stages the chart, brings up the kind-full
# reference cluster with the full profile (every source on, Falco on) through
# hack/install-full-kind.sh, reads /etc/shadow inside a throwaway pod in a
# namespace the agent scores, and prints the aggregator's first decision about
# that pod with the time since `make up` started.
#
# Nothing here talks to NATS. The detection has to come from Falco seeing a
# real action; it is read from the aggregator's own log line (the parsers are
# Story 12.2's, from hack/quickstart.sh).
#
# `make down` (hack/down.sh) removes everything this creates.
#
# Settings (environment; the make targets pass the kind-full ones):
#   UP_CLUSTER   kind cluster name                          (olaitan-full)
#   UP_OUT_DIR   key material and kubeconfig, outside repo  ($HOME/.olaitan-full)
#   UP_WORKERS   worker nodes; empty = hack/kind-full.yaml  (1)
#   UP_BUDGET    seconds allowed, make up to detection      (900)
#   UP_PLAN=1    run preflight, print the commands, create nothing
# Host facts, overridable so the tests can use fixtures:
#   UP_INOTIFY_DIR (/proc/sys/fs/inotify), UP_BTF_FILE (/sys/kernel/btf/vmlinux),
#   UP_KERNEL (uname -r), UP_OS (uname -s)
set -euo pipefail

UP_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck source=hack/quickstart.sh
. "$UP_ROOT/hack/quickstart.sh"
# shellcheck source=hack/lib/falco-kernel.sh
. "$UP_ROOT/hack/lib/falco-kernel.sh"

UP_NS="default" # hack/install-full-kind.sh installs the release here
UP_DEMO_NS="olaitan-up"
UP_DEMO_POD="up-demo"
UP_ATTEMPT_GAP=15
UP_POLL=5
# The same floor hack/preflight.sh reports and kind documents.
UP_MIN_INSTANCES=512
UP_MIN_WATCHES=524288

UP_BLOCKERS=0
up_ok() { printf '  ok       %s\n' "$*"; }
up_note() { printf '  caveat   %s\n' "$*"; }
up_block() {
	printf '  BLOCKER  %s\n' "$1"
	shift
	local l
	for l in "$@"; do printf '           %s\n' "$l"; done
	UP_BLOCKERS=$((UP_BLOCKERS + 1))
}

up_check_tools() {
	local tool missing=""
	local -A how=(
		[docker]="install it: https://docs.docker.com/engine/install/"
		[kind]="install it: https://kind.sigs.k8s.io/docs/user/quick-start/#installation (tested with v0.30.0)"
		[helm]="install it: https://helm.sh/docs/intro/install/"
		[kubectl]="install it: https://kubernetes.io/docs/tasks/tools/"
		[openssl]="install it: sudo apt-get install -y openssl (Debian/Ubuntu); hack/install-full-kind.sh makes the audit and webhook certificates with it"
	)
	for tool in docker kind helm kubectl openssl; do
		if ! command -v "$tool" >/dev/null 2>&1; then
			up_block "$tool is not on PATH" "fix: ${how[$tool]}"
			missing+=" $tool"
		fi
	done
	[ -n "$missing" ] || up_ok "docker, kind, helm, kubectl and openssl are on PATH"
}

up_check_docker() {
	command -v docker >/dev/null 2>&1 || return 0
	if docker info >/dev/null 2>&1; then
		up_ok "Docker is reachable"
	else
		up_block "Docker is not reachable (docker info failed)" \
			"fix: sudo systemctl start docker" \
			"and, if it runs but your user cannot use it: sudo usermod -aG docker \$USER, then log in again"
	fi
}

up_check_python() {
	[ -n "$1" ] || return 0
	if command -v python3 >/dev/null 2>&1 && python3 -c 'import yaml' >/dev/null 2>&1; then
		up_ok "python3 with PyYAML (trims hack/kind-full.yaml to $1 worker(s))"
	else
		up_block "python3 with PyYAML is needed to trim hack/kind-full.yaml to $1 worker(s)" \
			"fix: sudo apt-get install -y python3-yaml (Debian/Ubuntu), or pip install pyyaml" \
			"or keep kind-full.yaml's two workers, which needs no python: make up FULL_WORKERS="
	fi
}

# up_check_inotify INSTANCES WATCHES: Falco on kind-full dies with "could not
# initialize inotify handler" below these limits (PR #147). The remedy raises
# only what is low, so it never lowers the other limit.
up_check_inotify() {
	local inst="$1" watch="$2" set=""
	if [ "$inst" -lt "$UP_MIN_INSTANCES" ]; then set+=" fs.inotify.max_user_instances=$UP_MIN_INSTANCES"; fi
	if [ "$watch" -lt "$UP_MIN_WATCHES" ]; then set+=" fs.inotify.max_user_watches=$UP_MIN_WATCHES"; fi
	if [ -z "$set" ]; then
		up_ok "inotify limits: instances=$inst, watches=$watch"
		return 0
	fi
	up_block "inotify limits too low for Falco on kind-full: instances=$inst (need >= $UP_MIN_INSTANCES), watches=$watch (need >= $UP_MIN_WATCHES)" \
		"Falco would crash with 'could not initialize inotify handler' and never see the attack." \
		"fix: sudo sysctl -w${set}" \
		"to keep it after a reboot, put the same settings in /etc/sysctl.d/99-olaitan.conf"
}

up_check_host_kernel() {
	local os="$1" kernel="$2" btf="$3" inodir="$4" verdict rc=0
	if [ "$os" != "Linux" ]; then
		up_note "host is $os, not Linux: BTF and inotify live in Docker's VM and cannot be checked from here"
		return 0
	fi
	if [ -e "$btf" ]; then
		up_ok "kernel BTF present ($btf)"
	else
		up_block "no $btf: Falco's modern_ebpf driver needs a kernel with BTF, so no attack would be seen" \
			"fix: run on a kernel built with CONFIG_DEBUG_INFO_BTF=y (check with: ls /sys/kernel/btf/vmlinux)"
	fi
	verdict="$(falco_kernel_verdict "$kernel")" || rc=$?
	case "$rc" in
	0) up_ok "$verdict" ;;
	1)
		local -a lines
		mapfile -t lines <<<"$verdict"
		up_block "${lines[0]#BLOCKER }" "${lines[@]:1}" "fix: pin a Falco release with the fix (hack/falco-support.env), or use a kernel below 7.0"
		;;
	*) up_note "$(head -n 1 <<<"$verdict")" ;;
	esac
	local inst watch
	inst="$(cat "$inodir/max_user_instances" 2>/dev/null || true)"
	watch="$(cat "$inodir/max_user_watches" 2>/dev/null || true)"
	if [[ $inst =~ ^[0-9]+$ ]] && [[ $watch =~ ^[0-9]+$ ]]; then
		up_check_inotify "$inst" "$watch"
	else
		up_note "cannot read the inotify limits in $inodir"
	fi
}

up_check_cluster() {
	command -v kind >/dev/null 2>&1 || return 0
	if kind get clusters 2>/dev/null | grep -qxF "$1"; then
		up_block "kind cluster $1 already exists" \
			"make up starts from nothing (the time is measured from the start); fix: make down"
	else
		up_ok "no kind cluster named $1 yet"
	fi
}

# up_preflight CLUSTER WORKERS: every check runs, so one run lists every
# blocker. Returns 1 when any blocker was found.
up_preflight() {
	UP_BLOCKERS=0
	qs_say "preflight (host): nothing is created until every check passes"
	up_check_tools
	up_check_docker
	up_check_host_kernel "${UP_OS:-$(uname -s)}" "${UP_KERNEL:-$(uname -r)}" \
		"${UP_BTF_FILE:-/sys/kernel/btf/vmlinux}" "${UP_INOTIFY_DIR:-/proc/sys/fs/inotify}"
	up_check_python "$2"
	up_check_cluster "$1"
	if [ "$UP_BLOCKERS" -gt 0 ]; then
		echo "up: preflight found $UP_BLOCKERS blocker(s); nothing was created. Fix them and run make up again." >&2
		return 1
	fi
	qs_say "preflight passed"
}

up_logs() {
	kubectl "${UP_K[@]}" -n "$UP_NS" logs "$@" 2>/dev/null || true
}

# up_print_access: how to reach what make up built. Stories 13.2 (#126) and
# 13.3 (#127) add the Grafana and console URLs here.
up_print_access() {
	local cluster="$1" out="$2"
	echo "  Use it:     export KUBECONFIG=$out/kubeconfig   (context kind-$cluster)"
	echo "  Watch it:   kubectl --kubeconfig $out/kubeconfig -n $UP_NS logs -l app.kubernetes.io/component=aggregator -f"
	echo "  Remove it:  make down"
}

UP_CREATED=0
up_on_exit() {
	local rc=$?
	if [ "$rc" -ne 0 ] && [ "$UP_CREATED" = 1 ]; then
		echo "up: stopped after creating the cluster; make down removes everything it made." >&2
	fi
}

main() {
	local t0
	t0="$(date +%s)"
	local cluster="${UP_CLUSTER:-olaitan-full}"
	local out="${UP_OUT_DIR:-$HOME/.olaitan-full}"
	local workers="${UP_WORKERS-1}"
	local budget="${UP_BUDGET:-900}"
	local plan="${UP_PLAN:-}"
	if ! [[ $budget =~ ^[0-9]+$ ]]; then
		echo "up: UP_BUDGET must be a whole number of seconds (0 or more), got '$budget'" >&2
		exit 1
	fi
	# qs_run reads the quickstart's plan switch.
	# shellcheck disable=SC2034 # read by qs_run in hack/quickstart.sh
	QUICKSTART_PLAN="$plan"
	UP_K=(--kubeconfig "$out/kubeconfig" --context "kind-$cluster")
	cd "$UP_ROOT"

	qs_say "clock starts: make up (budget ${budget}s to a live detection)"
	up_preflight "$cluster" "$workers" || exit 1

	trap up_on_exit EXIT
	qs_say "staging the chart from this checkout"
	qs_run make -s helm-deps

	qs_say "kind-full: cluster $cluster, Calico, the full profile with Falco on"
	UP_CREATED=1
	qs_run env CLUSTER_NAME="$cluster" WORKERS="$workers" KUBECONFIG="$out/kubeconfig" \
		hack/install-full-kind.sh "$out"
	# helm --wait counts a DaemonSet ready with one pod unavailable. The Ollama
	# pull Job's pod completes and is never Ready, so wait pod --all cannot be
	# used here; these three are what the detection needs.
	local rs
	for rs in ds/olaitan-falco ds/olaitan-collector deploy/olaitan-aggregator; do
		qs_run kubectl "${UP_K[@]}" -n "$UP_NS" rollout status "$rs" --timeout=10m
	done
	local t_ready
	t_ready="$(date +%s)"
	[ "$plan" = "1" ] || qs_say "Falco, collector and aggregator ready after $((t_ready - t0))s"

	qs_say "starting a throwaway pod in $UP_DEMO_NS (a namespace the agent scores)"
	qs_run kubectl "${UP_K[@]}" create namespace "$UP_DEMO_NS"
	qs_run kubectl "${UP_K[@]}" -n "$UP_DEMO_NS" run "$UP_DEMO_POD" --image="$QS_DEMO_IMAGE" --restart=Never -- sleep 3600
	qs_run kubectl "${UP_K[@]}" -n "$UP_DEMO_NS" wait "pod/$UP_DEMO_POD" --for=condition=Ready --timeout=3m

	qs_say "the smoke attack: read /etc/shadow inside the pod (Falco rule: Read sensitive file untrusted)"
	# -c: the full profile injects the applog sidecar into the pod.
	local -a attack=(kubectl "${UP_K[@]}" -n "$UP_DEMO_NS" exec "$UP_DEMO_POD" -c "$UP_DEMO_POD" -- cat /etc/shadow)
	if [ "$plan" = "1" ]; then
		qs_run "${attack[@]}"
		qs_run kubectl "${UP_K[@]}" -n "$UP_NS" logs -l app.kubernetes.io/component=aggregator --tail=-1
		return 0
	fi

	# Repeat the real read until the aggregator reacts or the budget is spent:
	# a read before Falco's driver is loaded is not seen. A failed exec is
	# reported, not fatal, and the next read is tried.
	local reads=0 found="" t_seen="" t_attack
	while [ $(($(date +%s) - t0)) -lt "$budget" ]; do
		reads=$((reads + 1))
		t_attack="$(date +%s)"
		printf '+ %s   (read %s)\n' "${attack[*]}" "$reads"
		if ! "${attack[@]}" >/dev/null; then
			echo "up: read $reads failed (kubectl's error is above); trying again" >&2
		fi
		while [ $(($(date +%s) - t_attack)) -lt "$UP_ATTEMPT_GAP" ]; do
			sleep "$UP_POLL"
			if found="$(up_logs -l app.kubernetes.io/component=aggregator --tail=-1 | qs_parse_transition "$UP_DEMO_NS")"; then
				t_seen="$(date +%s)"
				break 2
			fi
		done
	done

	if [ -z "$t_seen" ]; then
		echo "up: no detection for $UP_DEMO_NS within ${budget}s ($reads reads of /etc/shadow)." >&2
		echo "up: check Falco: kubectl ${UP_K[*]} -n $UP_NS logs -l app.kubernetes.io/name=falco -c falco" >&2
		echo "up: and the aggregator: kubectl ${UP_K[*]} -n $UP_NS logs -l app.kubernetes.io/component=aggregator --tail=200" >&2
		exit 1
	fi

	local wl from to score ts rule
	IFS=$'\t' read -r wl from to score ts <<<"$found"
	rule="$(up_logs -l app.kubernetes.io/name=falco -c falco --tail=-1 | qs_parse_rule "$UP_DEMO_NS" "$UP_DEMO_POD" || true)"
	local elapsed=$((t_seen - t0))

	echo
	echo "  Olaitan (full profile, Falco on) saw a real action and moved the workload:"
	echo
	printf '    %-10s %s\n' "workload" "$wl"
	printf '    %-10s %s\n' "from" "$from"
	printf '    %-10s %s\n' "to" "$to"
	printf '    %-10s %s\n' "score" "$score"
	printf '    %-10s %s\n' "logged at" "$ts (aggregator clock)"
	printf '    %-10s %s\n' "falco rule" "${rule:-(not found in the Falco log)}"
	printf '    %-10s %s\n' "reads" "$reads of /etc/shadow before the transition"
	echo
	printf '  make up -> Falco, collector, aggregator ready:  %ss\n' "$((t_ready - t0))"
	printf '  make up -> first detection:                     %ss (budget %ss)\n' "$elapsed" "$budget"
	echo
	up_print_access "$cluster" "$out"
	if ! qs_within_budget "$elapsed" "$budget"; then
		echo "up: over budget: ${elapsed}s > ${budget}s" >&2
		exit 1
	fi
}

if [ "${BASH_SOURCE[0]}" = "$0" ]; then
	main "$@"
fi
