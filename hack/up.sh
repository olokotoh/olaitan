#!/usr/bin/env bash
# hack/up.sh: one command to a full live system (Story 12.3), run by `make up`.
#
# It checks the host first and stops, with the exact remedy for each problem,
# before anything is created. Then it stages the chart, brings up the kind-full
# reference cluster with the full profile (every source on, Falco on) through
# hack/install-full-kind.sh, runs a real three-step attack inside a throwaway
# pod in a namespace the agent scores (the Epic 10 audit's, #117: read
# /etc/shadow, read the service-account token, request the cloud metadata
# IP), and prints the aggregator's first decision about that pod, the Falco
# rules that fired, and the time since `make up` started.
#
# Nothing here talks to NATS. The detection has to come from Falco seeing a
# real action; it is read from the aggregator's own log line (the parsers are
# Story 12.2's, from hack/quickstart.sh).
#
# `make down` (hack/down.sh) removes everything this creates.
#
# The first thing it writes, once preflight has passed, is <out>/.olaitan-up
# with the cluster name: `make down` removes the out dir only when that marker
# is there, so it never removes a directory make up did not make.
#
# It succeeds only when Falco has alerted on the demo pod's /etc/shadow read
# AND the aggregator has moved a workload in that namespace, as
# hack/stranger.sh (Story 12.5) requires. The metadata request usually gets
# no answer on kind; the connect is the real syscall Falco sees, so its exit
# code is not counted.
#
# Settings (environment; the make targets pass the kind-full ones):
#   UP_CLUSTER   kind cluster name                          (olaitan-full)
#   UP_OUT_DIR   key material and kubeconfig, outside repo  ($HOME/.olaitan-full;
#                set but empty is refused, as in hack/down.sh)
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
# shellcheck source=hack/lib/out-dir.sh
. "$UP_ROOT/hack/lib/out-dir.sh"

UP_NS="default" # hack/install-full-kind.sh installs the release here
UP_DEMO_NS="olaitan-up"
UP_DEMO_POD="up-demo"
UP_ATTEMPT_GAP=15
# The attack, one kubectl exec per step, in this order. Every step is a real
# syscall in the demo pod; the output is thrown away (the token is a secret).
UP_ATTACK=(
	"cat /etc/shadow"
	"cat /var/run/secrets/kubernetes.io/serviceaccount/token"
	"wget -q -T 3 -O /dev/null http://169.254.169.254/latest/meta-data/"
)
UP_POLL=5
# The same floor hack/preflight.sh reports and kind documents.
UP_MIN_INSTANCES=512
UP_MIN_WATCHES=524288

UP_K=()
UP_CMD=()
UP_OUT=""
UP_CLUSTER_EXISTS=0

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
	local -a conf=()
	if [ "$inst" -lt "$UP_MIN_INSTANCES" ]; then
		set+=" fs.inotify.max_user_instances=$UP_MIN_INSTANCES"
		conf+=("fs.inotify.max_user_instances = $UP_MIN_INSTANCES")
	fi
	if [ "$watch" -lt "$UP_MIN_WATCHES" ]; then
		set+=" fs.inotify.max_user_watches=$UP_MIN_WATCHES"
		conf+=("fs.inotify.max_user_watches = $UP_MIN_WATCHES")
	fi
	if [ -z "$set" ]; then
		up_ok "inotify limits: instances=$inst, watches=$watch"
		return 0
	fi
	up_block "inotify limits too low for Falco on kind-full: instances=$inst (need >= $UP_MIN_INSTANCES), watches=$watch (need >= $UP_MIN_WATCHES)" \
		"Falco would crash with 'could not initialize inotify handler' and never see the attack." \
		"fix: sudo sysctl -w${set}" \
		"to keep it after a reboot, put these lines in /etc/sysctl.d/99-olaitan.conf:" \
		"${conf[@]}"
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
		UP_CLUSTER_EXISTS=1
		up_block "kind cluster $1 already exists" \
			"make up starts from nothing (the time is measured from the start); fix: make down"
	else
		up_ok "no kind cluster named $1 yet"
	fi
}

# up_check_out_dir RAW CLUSTER: the out dir passes make down's guard (the
# same rules, hack/lib/out-dir.sh), and holds nothing left from an earlier
# run or from anyone else: make up writes private keys into it and marks it
# as its own, and make down then removes it. Sets UP_OUT to the canonical
# path.
up_check_out_dir() {
	local raw="$1" cluster="$2" d name f stale=""
	if ! d="$(olaitan_out_dir "$raw" "$UP_ROOT")"; then
		up_block "refusing out dir '$raw' (FULL_OUT_DIR, UP_OUT_DIR): $d" \
			"make down removes the out dir with rm -rf, so it must be a directory of its own" \
			"fix: make up FULL_OUT_DIR=\$HOME/.olaitan-full (or any new directory outside the repository)"
		return 0
	fi
	UP_OUT="$d"
	# An existing cluster is its own blocker, with make down as the fix.
	[ "$UP_CLUSTER_EXISTS" = 0 ] || return 0
	if [ -e "$d" ] && [ ! -d "$d" ]; then
		up_block "out dir $d exists and is not a directory" \
			"fix: make up FULL_OUT_DIR=<a new directory>"
		return 0
	fi
	if name="$(olaitan_out_marked "$d")"; then
		if [ "$name" = "$cluster" ]; then
			up_block "out dir $d is left from an earlier run of make up, with no kind cluster $cluster behind it" \
				"make up starts from nothing; fix: make down"
		else
			up_block "out dir $d was made by make up for kind cluster $name (its $OLAITAN_OUT_MARKER)" \
				"fix: make down FULL_CLUSTER_NAME=$name FULL_OUT_DIR=$d, or make up FULL_OUT_DIR=<a new directory>"
		fi
		return 0
	fi
	for f in calico audit-certs applog-certs kubeconfig; do
		[ ! -e "$d/$f" ] || stale+=" $f"
	done
	if [ -n "$stale" ]; then
		up_block "out dir $d holds${stale} from an earlier run of make e2e-full (no $OLAITAN_OUT_MARKER, so make up did not make it)" \
			"fix: make e2e-full-down (removes the cluster, $d and hack/.audit-full)"
		return 0
	fi
	if [ -d "$d" ] && [ -n "$(ls -A "$d")" ]; then
		up_block "out dir $d is not empty and was not made by make up (no $OLAITAN_OUT_MARKER)" \
			"make up writes private keys into it and make down would then remove it" \
			"fix: make up FULL_OUT_DIR=<a new or empty directory>, for example \$HOME/.olaitan-full"
		return 0
	fi
	up_ok "out dir $d is new or empty"
}

# up_preflight CLUSTER WORKERS OUT: every check runs, so one run lists every
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
	up_check_out_dir "$3" "$1"
	if [ "$UP_BLOCKERS" -gt 0 ]; then
		echo "up: preflight found $UP_BLOCKERS blocker(s); nothing was created. Fix them and run make up again." >&2
		return 1
	fi
	qs_say "preflight passed"
}

# up_mark OUT CLUSTER: create OUT (0700) and write make up's marker into it,
# the first write after preflight. make down removes OUT only when the marker
# is there and names CLUSTER.
up_mark() {
	printf '+ mark %s/%s %s\n' "$1" "$OLAITAN_OUT_MARKER" "$2"
	[ "${UP_PLAN:-}" = "1" ] && return 0
	(umask 077 && mkdir -p "$1")
	chmod 700 "$1"
	printf '%s\n' "$2" >"$1/$OLAITAN_OUT_MARKER"
}

# up_logs SELECTOR [ARGS]: the log reader keeps kubectl's stderr and exit
# code, so a failed read is never taken for "nothing yet".
up_logs() {
	kubectl "${UP_K[@]}" -n "$UP_NS" logs -l "$@" --tail=-1
}

# up_parse_rules NS POD: read Falco's JSON log lines on stdin and print every
# distinct rule raised for pod POD in namespace NS, in order of first
# appearance, joined with ", ". Exit 1 when there is none.
up_parse_rules() {
	local ns="$1" pod="$2" line rule out="" seen=$'\n'
	while IFS= read -r line; do
		case "$line" in
		*'"k8s.ns.name":"'"$ns"'"'*) ;;
		*) continue ;;
		esac
		case "$line" in
		*'"k8s.pod.name":"'"$pod"'"'*) ;;
		*) continue ;;
		esac
		rule="$(sed -n 's/.*"rule":"\([^"]*\)".*/\1/p' <<<"$line")"
		[ -n "$rule" ] || continue
		case "$seen" in
		*$'\n'"$rule"$'\n'*) continue ;;
		esac
		seen+="$rule"$'\n'
		out+="${out:+, }$rule"
	done
	[ -n "$out" ] || return 1
	printf '%s\n' "$out"
}

# up_attack_cmd N: set UP_CMD to attack step N (0-based) as a kubectl exec
# into the demo pod's own container (-c: the full profile injects the applog
# sidecar). The only exec in make up.
up_attack_cmd() {
	local -a step
	read -ra step <<<"${UP_ATTACK[$1]}"
	UP_CMD=(kubectl "${UP_K[@]}" -n "$UP_DEMO_NS" exec "$UP_DEMO_POD" -c "$UP_DEMO_POD" -- "${step[@]}")
}

# up_attack_step N: run attack step N in the demo pod, output thrown away.
up_attack_step() {
	up_attack_cmd "$1"
	printf '+ %s\n' "${UP_CMD[*]}"
	"${UP_CMD[@]}" >/dev/null
}

# up_detect T0 BUDGET: run the attack in the demo pod until Falco has
# alerted on that read from that pod AND the aggregator has logged a
# transition for a workload in its namespace (hack/stranger.sh's rule), or
# until BUDGET seconds after T0. A failed exec is reported and counted apart
# from the rounds that ran (a round counts as a read when both file reads
# ran; the metadata request's exit code is not counted); a log that cannot be
# read stops make up. Sets UP_FOUND, UP_RULE (the /etc/shadow alert),
# UP_RULES (every rule raised for the demo pod), UP_T_SEEN, UP_READS,
# UP_FAILED. Returns 1 on no detection, naming what is missing.
up_detect() {
	local t0="$1" budget="$2" n t_attack logs rc ok
	UP_FOUND="" UP_RULE="" UP_RULES="" UP_T_SEEN="" UP_READS=0 UP_FAILED=0
	while [ $(($(date +%s) - t0)) -lt "$budget" ]; do
		n=$((UP_READS + UP_FAILED + 1))
		echo "==> attack round $n"
		ok=1
		up_attack_step 0 || ok=0
		up_attack_step 1 || ok=0
		up_attack_step 2 || echo "up: round $n: no answer from 169.254.169.254 (expected on kind; the connect is what Falco sees)"
		if [ "$ok" = 1 ]; then
			UP_READS=$((UP_READS + 1))
		else
			UP_FAILED=$((UP_FAILED + 1))
			echo "up: exec $n failed (kubectl's error is above); trying again" >&2
		fi
		t_attack="$(date +%s)"
		while [ $(($(date +%s) - t_attack)) -lt "$UP_ATTEMPT_GAP" ]; do
			sleep "$UP_POLL"
			if [ -z "$UP_FOUND" ]; then
				rc=0
				logs="$(up_logs app.kubernetes.io/component=aggregator)" || rc=$?
				if [ "$rc" -ne 0 ]; then
					echo "up: reading the aggregator log exited $rc (kubectl's error is above)" >&2
					exit 1
				fi
				UP_FOUND="$(qs_parse_transition "$UP_DEMO_NS" <<<"$logs")" || UP_FOUND=""
			fi
			rc=0
			logs="$(up_logs app.kubernetes.io/name=falco -c falco)" || rc=$?
			if [ "$rc" -ne 0 ]; then
				echo "up: reading the Falco log exited $rc (kubectl's error is above)" >&2
				exit 1
			fi
			[ -n "$UP_RULE" ] || UP_RULE="$(qs_parse_rule "$UP_DEMO_NS" "$UP_DEMO_POD" <<<"$logs")" || UP_RULE=""
			UP_RULES="$(up_parse_rules "$UP_DEMO_NS" "$UP_DEMO_POD" <<<"$logs")" || UP_RULES=""
			if [ -n "$UP_FOUND" ] && [ -n "$UP_RULE" ]; then
				UP_T_SEEN="$(date +%s)"
				return 0
			fi
		done
	done
	echo "up: no detection for $UP_DEMO_NS within ${budget}s ($UP_READS attack rounds, $UP_FAILED failed execs):" >&2
	echo "up:   Falco alert on /etc/shadow from $UP_DEMO_NS/$UP_DEMO_POD: ${UP_RULE:-none (product: no Falco alert)}" >&2
	echo "up:   every Falco rule raised for $UP_DEMO_NS/$UP_DEMO_POD: ${UP_RULES:-none}" >&2
	echo "up:   FSM transition in $UP_DEMO_NS: ${UP_FOUND:-none (product: no FSM transition)}" >&2
	echo "up: check Falco: kubectl ${UP_K[*]} -n $UP_NS logs -l app.kubernetes.io/name=falco -c falco" >&2
	echo "up: and the aggregator: kubectl ${UP_K[*]} -n $UP_NS logs -l app.kubernetes.io/component=aggregator --tail=200" >&2
	return 1
}

# up_print_access: how to reach what make up built. Story 13.3 (#127) adds
# the console URL here.
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
	local out="${UP_OUT_DIR-$HOME/.olaitan-full}"
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
	cd "$UP_ROOT"

	qs_say "clock starts: make up (budget ${budget}s to a live detection)"
	up_preflight "$cluster" "$workers" "$out" || exit 1
	out="$UP_OUT"
	UP_K=(--kubeconfig "$out/kubeconfig" --context "kind-$cluster")

	trap up_on_exit EXIT
	qs_say "marking $out as make up's (make down removes it only with this marker)"
	up_mark "$out" "$cluster"
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

	qs_say "the smoke attack, real syscalls in the pod: read /etc/shadow, read the service-account token, request 169.254.169.254; repeated until Falco alerts and the aggregator moves the pod"
	if [ "$plan" = "1" ]; then
		local i
		for i in "${!UP_ATTACK[@]}"; do
			up_attack_cmd "$i"
			qs_run "${UP_CMD[@]}"
		done
		qs_run kubectl "${UP_K[@]}" -n "$UP_NS" logs -l app.kubernetes.io/component=aggregator --tail=-1
		qs_run kubectl "${UP_K[@]}" -n "$UP_NS" logs -l app.kubernetes.io/name=falco -c falco --tail=-1
		return 0
	fi

	# A read before Falco's driver is loaded is not seen, so the real read is
	# repeated until both signals are there or the budget is spent.
	up_detect "$t0" "$budget" || exit 1

	local wl from to score ts
	IFS=$'\t' read -r wl from to score ts <<<"$UP_FOUND"
	local elapsed=$((UP_T_SEEN - t0))

	echo
	echo "  Olaitan (full profile, Falco on) saw a real action and moved the workload:"
	echo
	printf '    %-10s %s\n' "workload" "$wl"
	printf '    %-10s %s\n' "from" "$from"
	printf '    %-10s %s\n' "to" "$to"
	printf '    %-10s %s\n' "score" "$score"
	printf '    %-10s %s\n' "logged at" "$ts (aggregator clock)"
	printf '    %-10s %s\n' "falco rule" "$UP_RULE (on /etc/shadow, from $UP_DEMO_POD)"
	printf '    %-10s %s\n' "all rules" "$UP_RULES (every Falco rule raised for $UP_DEMO_POD)"
	printf '    %-10s %s\n' "rounds" "$UP_READS attack rounds ($UP_FAILED failed execs) until both were seen"
	echo
	printf '  make up -> Falco, collector, aggregator ready:  %ss\n' "$((t_ready - t0))"
	printf '  make up -> Falco alert and FSM transition:      %ss (budget %ss)\n' "$elapsed" "$budget"
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
