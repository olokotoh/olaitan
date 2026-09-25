#!/usr/bin/env bash
# hack/quickstart.sh: the ten-minute path (Story 12.2), run by `make quickstart`.
#
# It creates a fresh kind cluster, installs Olaitan with Falco on and the kind
# overlay (values-kind.yaml, whose narrow exception stops kind's own node
# hook from tripping a Critical Falco rule for every new container), starts a
# throwaway pod in a namespace the agent scores, reads /etc/shadow inside it
# (a real syscall that trips Falco's stock "Read sensitive file untrusted"
# rule, Warning, score 20: SUSPICIOUS on its own), and waits for the
# aggregator to log its decision about that pod. It then prints the
# transition, every Falco rule that fired for the pod up to it, and the time
# from `kind create cluster` to it. It exits non-zero when the read was not
# shown to cause the transition, or when the Falco log cannot be read.
#
# Nothing here talks to NATS. The detection has to come from Falco seeing a
# real action; the transition is read from the aggregator's own log line,
# which it writes only after it scored a real evidence package.
#
# Settings (environment, or make variables of the same name):
#   QUICKSTART_CLUSTER  kind cluster name              (olaitan-quickstart)
#   QUICKSTART_CHART    published | local              (published)
#   QUICKSTART_VERSION  published chart version        (Chart.yaml version)
#   QUICKSTART_IMAGE    repo:tag of a local image to kind-load (local only)
#   QUICKSTART_BUDGET   seconds allowed, kind create to transition (600)
#   QUICKSTART_PLAN=1   print the commands and exit; touches nothing
set -euo pipefail

QS_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
QS_PUBLISHED_CHART="oci://ghcr.io/olokotoh/charts/olaitan"
QS_LOCAL_CHART="deploy/helm/olaitan"
# The kind overlay. Its narrow exception for kind's own node hook
# (kind_mount_product_files_hook) keeps Falco's Critical "Drop and execute
# new binary in container" from firing for every new container and every
# exec on kind, which would move the demo pod before the read is seen. The
# published path takes the overlay of the release it installs, the way the
# README does.
QS_KIND_OVERLAY="deploy/helm/olaitan/values-kind.yaml"
QS_KIND_OVERLAY_URL="https://raw.githubusercontent.com/olokotoh/olaitan"
QS_NS="olaitan"
QS_RELEASE="olaitan"
QS_DEMO_NS="olaitan-quickstart"
QS_DEMO_POD="quickstart-demo"
# busybox 1.37.0, pinned by digest like every other image the project runs
# (Story 12.6). Reading /etc/shadow needs nothing more than cat.
QS_DEMO_IMAGE="busybox:1.37.0@sha256:bdf57e528e45e4433820e045b29b4597825a1c9e38353532d90a01445013f82e"
QS_ATTEMPTS=8     # real reads, one every QS_ATTEMPT_GAP seconds
QS_ATTEMPT_GAP=15
QS_POLL=5         # how often the aggregator log is checked

# qs_parse_transition NS: read aggregator log lines on stdin and print the
# first FSM transition of a workload in namespace NS as
# workload<TAB>from<TAB>to<TAB>score<TAB>time. Exit 1 when there is none.
qs_parse_transition() {
	local ns="$1" line wl from to score ts
	while IFS= read -r line; do
		case "$line" in
		*'"msg":"aggregator: fsm transition"'*'"workload_id":"'"$ns"'/'*) ;;
		*) continue ;;
		esac
		wl="$(sed -n 's/.*"workload_id":"\([^"]*\)".*/\1/p' <<<"$line")"
		from="$(sed -n 's/.*"from_state":"\([^"]*\)".*/\1/p' <<<"$line")"
		to="$(sed -n 's/.*"to_state":"\([^"]*\)".*/\1/p' <<<"$line")"
		score="$(sed -n 's/.*"score":\([-0-9.eE+]*\).*/\1/p' <<<"$line")"
		ts="$(sed -n 's/.*"time":"\([^"]*\)".*/\1/p' <<<"$line")"
		printf '%s\t%s\t%s\t%s\t%s\n' "$wl" "$from" "$to" "$score" "$ts"
		return 0
	done
	return 1
}

# qs_parse_rule NS POD: read Falco's JSON log lines on stdin and print the
# rule of the first alert on /etc/shadow raised for pod POD in namespace NS
# (both are in the alert's output_fields). Exit 1 when there is none, so an
# alert from any other container is never shown as the demo pod's reason.
qs_parse_rule() {
	local ns="$1" pod="$2" line
	while IFS= read -r line; do
		case "$line" in
		*'"k8s.ns.name":"'"$ns"'"'*) ;;
		*) continue ;;
		esac
		case "$line" in
		*'"k8s.pod.name":"'"$pod"'"'*) ;;
		*) continue ;;
		esac
		case "$line" in
		*'/etc/shadow'*) ;;
		*) continue ;;
		esac
		line="$(sed -n 's/.*"rule":"\([^"]*\)".*/\1/p' <<<"$line")"
		[ -n "$line" ] || continue
		printf '%s\n' "$line"
		return 0
	done
	return 1
}

# qs_ts_key TIME: print an RFC 3339 UTC time (YYYY-MM-DDTHH:MM:SS[.frac]Z)
# with the fraction padded to nine digits, so two times compare as strings.
# Exit 1 for any other shape.
qs_ts_key() {
	local re='^([0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2})(\.([0-9]{1,9}))?Z$' frac
	[[ $1 =~ $re ]] || return 1
	frac="${BASH_REMATCH[3]}000000000"
	printf '%s.%s' "${BASH_REMATCH[1]}" "${frac:0:9}"
}

# qs_parse_rules NS POD UNTIL: read Falco's JSON log lines on stdin and print
# every rule that fired for pod POD in namespace NS at or before time UNTIL
# (the transition's time), one line per rule in the order each first fired:
# first-time<TAB>priority<TAB>rule<TAB>alerts<TAB>yes|no (an alert of that
# rule was the read: its Falco field fd.name is exactly /etc/shadow). The
# log lines need not be in time order. Exit 1 when there is none. The
# transition can have more than one cause; on kind without the kind overlay,
# the node's own mount-product-files hook trips a Critical rule for the pod
# (#177).
#
# Fails closed: when UNTIL, or the time of an alert for the pod, is not an
# RFC 3339 UTC time (an offset such as +01:00, say), nothing can be said
# about what came first, so it prints "cannot compare times: ..." on stdout
# and exits 1 instead of listing anything.
qs_parse_rules() {
	local ns="$1" pod="$2" until="$3" ukey line ts key prio rule shadow rows=""
	if ! ukey="$(qs_ts_key "$until")"; then
		printf 'cannot compare times: the transition time %s is not an RFC 3339 UTC time\n' "'$until'"
		return 1
	fi
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
		prio="$(sed -n 's/.*"priority":"\([^"]*\)".*/\1/p' <<<"$line")"
		ts="$(sed -n 's/.*"time":"\([^"]*\)".*/\1/p' <<<"$line")"
		if ! key="$(qs_ts_key "$ts")"; then
			printf 'cannot compare times: the time %s of a "%s" alert for %s is not an RFC 3339 UTC time\n' "'$ts'" "$rule" "$pod"
			return 1
		fi
		if [[ $key > $ukey ]]; then
			continue
		fi
		case "$line" in
		*'"fd.name":"/etc/shadow"'*) shadow=yes ;;
		*) shadow=no ;;
		esac
		rows+="$(printf '%s\t%s\t%s\t%s\t%s' "$key" "$ts" "${prio:-?}" "$rule" "$shadow")"$'\n'
	done
	[ -n "$rows" ] || return 1
	printf '%s' "$rows" | LC_ALL=C sort -s -t "$(printf '\t')" -k1,1 | awk -F '\t' '
		!($4 in n) { order[++k] = $4; first[$4] = $2; prio[$4] = $3; sh[$4] = "no" }
		{ n[$4]++; if ($5 == "yes") sh[$4] = "yes" }
		END {
			for (i = 1; i <= k; i++) {
				r = order[i]
				printf "%s\t%s\t%s\t%d\t%s\n", first[r], prio[r], r, n[r], sh[r]
			}
		}'
}

# qs_prio_rank PRIORITY: print Falco's priority as a number, higher is more
# severe. An unknown priority ranks above every known one, so a rule of
# unknown weight is never ruled out as a contributor.
qs_prio_rank() {
	case "$1" in
	Debug) echo 1 ;;
	Informational | Info) echo 2 ;;
	Notice) echo 3 ;;
	Warning) echo 4 ;;
	Error) echo 5 ;;
	Critical) echo 6 ;;
	Alert) echo 7 ;;
	Emergency) echo 8 ;;
	*) echo 9 ;;
	esac
}

# qs_report_rules NS POD UNTIL: print, from Falco's log on stdin, every rule
# that fired for the demo pod up to the transition at UNTIL, with priority
# and alert count, and what that means for the read:
#   0  an alert on /etc/shadow (the read) came before the transition, and no
#      other rule of higher priority did;
#   3  the read came before it, and so did rules of higher priority than
#      the read's; the score is the highest rule's (max-based,
#      internal/correlator/trigger/falco.go), so they contributed. A line
#      "Other rules contributed: A, B (...)" names them;
#   1  no read came before it, or the times cannot be compared: the
#      transition was not shown to be the read's.
qs_report_rules() {
	local ns="$1" pod="$2" until="$3" rules first prio rule n shadow read=1 top=0 r others=""
	echo "  Falco rules that fired for $pod up to the transition:"
	if ! rules="$(qs_parse_rules "$ns" "$pod" "$until")"; then
		if [[ $rules == "cannot compare times"* ]]; then
			echo "    ($rules)"
			echo "  The transition was not shown to be the read's: its cause cannot be told from the Falco log."
		else
			echo "    (none found in the Falco log)"
			echo "  The transition was not caused by the read: no alert on /etc/shadow from $pod came before it."
		fi
		return 1
	fi
	while IFS=$'\t' read -r first prio rule n shadow; do
		if [ "$shadow" = yes ]; then
			read=0
			r="$(qs_prio_rank "$prio")"
			if [ "$r" -gt "$top" ]; then top="$r"; fi
			shadow="  (on /etc/shadow)"
		else
			shadow=""
		fi
		printf '    %-9s %s, %s alert(s), first at %s%s\n' "$prio" "$rule" "$n" "$first" "$shadow"
	done <<<"$rules"
	if [ "$read" != 0 ]; then
		echo "  The transition was not caused by the read: no alert on /etc/shadow from $pod came before it."
		return 1
	fi
	while IFS=$'\t' read -r first prio rule n shadow; do
		if [ "$shadow" = no ] && [ "$(qs_prio_rank "$prio")" -gt "$top" ]; then
			others+="${others:+, }$rule"
		fi
	done <<<"$rules"
	if [ -n "$others" ]; then
		echo "  Other rules contributed: $others (higher priority than the read's, before the transition; the score is the highest rule's)."
		return 3
	fi
	return 0
}

# qs_headline RC REPORT: the headline for qs_report_rules' exit status RC
# and its output REPORT.
qs_headline() {
	local others
	case "$1" in
	0) echo "Olaitan saw the read of /etc/shadow and moved the workload:" ;;
	3)
		others="$(sed -n 's/^  Other rules contributed: \(.*\) (higher priority.*/\1/p' <<<"$2")"
		echo "Olaitan moved the workload; the read of /etc/shadow and other rules contributed ($others):"
		;;
	*) echo "Olaitan moved the workload, but not because of the read (rules below):" ;;
	esac
}

# qs_check_published VERSION: fail before any cluster exists when the chart
# VERSION is not in the registry. Chart.yaml carries the release this tree
# is heading for, which is not published until the release run.
qs_check_published() {
	local version="$1"
	# Printed like qs_run, but only helm's own output (the chart metadata) is
	# dropped.
	printf '+ %s\n' "helm show chart $QS_PUBLISHED_CHART --version $version"
	[ "${QUICKSTART_PLAN:-}" = "1" ] && return 0
	if ! helm show chart "$QS_PUBLISHED_CHART" --version "$version" >/dev/null; then
		echo "quickstart: cannot fetch chart $QS_PUBLISHED_CHART version $version: it is not published yet, or the registry cannot be reached (helm's error is above)." >&2
		echo "quickstart: use a published one, QUICKSTART_VERSION=<version>, or this checkout's chart, QUICKSTART_CHART=local" >&2
		exit 1
	fi
}

# qs_within_budget ELAPSED BUDGET: exit 0 when ELAPSED <= BUDGET seconds.
qs_within_budget() {
	[ "$1" -le "$2" ]
}

qs_say() { printf '==> %s\n' "$*"; }

# qs_run prints a command the way the tests read it, then runs it (unless
# this is a plan).
qs_run() {
	printf '+ %s\n' "$*"
	[ "${QUICKSTART_PLAN:-}" = "1" ] && return 0
	"$@"
}

qs_chart_version() {
	sed -n 's/^version:[[:space:]]*"\{0,1\}\([^"[:space:]]*\)"\{0,1\}[[:space:]]*$/\1/p' \
		"$QS_ROOT/$QS_LOCAL_CHART/Chart.yaml" | head -n 1
}

qs_require() {
	local missing=0 tool
	for tool in docker kind helm kubectl; do
		if ! command -v "$tool" >/dev/null 2>&1; then
			echo "quickstart: $tool is required and not on PATH" >&2
			missing=1
		fi
	done
	[ "$missing" = 0 ] || exit 1
	if [ "$(uname -s)" = "Linux" ] && [ ! -e /sys/kernel/btf/vmlinux ]; then
		echo "quickstart: warning: /sys/kernel/btf/vmlinux is missing; Falco's modern eBPF probe needs BTF and may not load" >&2
	fi
	if kind get clusters 2>/dev/null | grep -qxF "$QS_CLUSTER"; then
		echo "quickstart: kind cluster $QS_CLUSTER already exists." >&2
		echo "quickstart: the timing is measured from kind create cluster, so start clean: make quickstart-clean" >&2
		exit 1
	fi
}

qs_aggregator_logs() {
	kubectl "${QS_KCTX[@]}" -n "$QS_NS" logs -l app.kubernetes.io/component=aggregator \
		--tail=-1 2>/dev/null || true
}

main() {
	QS_CLUSTER="${QUICKSTART_CLUSTER:-olaitan-quickstart}"
	local chart="${QUICKSTART_CHART:-published}"
	local budget="${QUICKSTART_BUDGET:-600}"
	local image="${QUICKSTART_IMAGE:-}"
	local plan="${QUICKSTART_PLAN:-}"
	QS_KCTX=(--context "kind-$QS_CLUSTER")
	if ! [[ $budget =~ ^[0-9]+$ ]]; then
		echo "quickstart: QUICKSTART_BUDGET must be a whole number of seconds (0 or more), got '$budget'" >&2
		exit 1
	fi

	local -a install=(helm install "$QS_RELEASE")
	case "$chart" in
	published)
		local version="${QUICKSTART_VERSION:-$(qs_chart_version)}"
		[ -n "$version" ] || { echo "quickstart: cannot read the chart version from $QS_LOCAL_CHART/Chart.yaml" >&2; exit 1; }
		[ -z "$image" ] || { echo "quickstart: QUICKSTART_IMAGE needs QUICKSTART_CHART=local (the published chart pins its image)" >&2; exit 1; }
		install+=("$QS_PUBLISHED_CHART" --version "$version" -f "$QS_KIND_OVERLAY_URL/v$version/$QS_KIND_OVERLAY")
		;;
	local)
		install+=("$QS_LOCAL_CHART" -f "$QS_KIND_OVERLAY")
		;;
	*)
		echo "quickstart: QUICKSTART_CHART must be published or local, not '$chart'" >&2
		exit 1
		;;
	esac
	install+=(--kube-context "kind-$QS_CLUSTER" --namespace "$QS_NS" --create-namespace)
	if [ -n "$image" ]; then
		local repo="${image%:*}" tag="${image##*:}"
		if [ "$repo" = "$image" ] || [ -z "$repo" ] || [ -z "$tag" ] || [[ "$tag" == */* ]] || [[ "$image" == *@* ]]; then
			echo "quickstart: QUICKSTART_IMAGE must be repo:tag, got '$image'" >&2
			exit 1
		fi
		install+=(--set "image.repository=$repo" --set-string "image.tag=$tag"
			--set "image.digest=" --set "image.pullPolicy=Never")
	fi
	install+=(--wait --timeout 10m)

	cd "$QS_ROOT"
	[ "$plan" = "1" ] || qs_require

	if [ "$chart" = "local" ]; then
		qs_say "staging the chart from this checkout (before the clock starts)"
		qs_run make -s helm-deps
	else
		qs_say "checking that chart $version is published (before the clock starts)"
		qs_check_published "$version"
	fi

	qs_say "clock starts: kind create cluster (budget ${budget}s to the first transition)"
	local t0
	t0="$(date +%s)"
	qs_run kind create cluster --name "$QS_CLUSTER"
	if [ -n "$image" ]; then
		qs_run kind load docker-image "$image" --name "$QS_CLUSTER"
	fi

	qs_say "installing Olaitan with Falco on (the chart default) and the kind overlay"
	qs_run "${install[@]}"
	# helm --wait counts a DaemonSet ready with one pod unavailable, so on one
	# node it can return while the collector is still restarting (it and the
	# aggregator restart a few times until NATS is up). This is the real check.
	qs_run kubectl "${QS_KCTX[@]}" -n "$QS_NS" wait pod --all --for=condition=Ready --timeout=10m
	local t_ready
	t_ready="$(date +%s)"
	[ "$plan" = "1" ] || qs_say "every pod Ready after $((t_ready - t0))s"

	qs_say "starting a throwaway pod in $QS_DEMO_NS (a namespace the agent scores)"
	qs_run kubectl "${QS_KCTX[@]}" create namespace "$QS_DEMO_NS"
	qs_run kubectl "${QS_KCTX[@]}" -n "$QS_DEMO_NS" run "$QS_DEMO_POD" --image="$QS_DEMO_IMAGE" --restart=Never -- sleep 3600
	qs_run kubectl "${QS_KCTX[@]}" -n "$QS_DEMO_NS" wait "pod/$QS_DEMO_POD" --for=condition=Ready --timeout=3m

	qs_say "the real action: read /etc/shadow inside the pod (Falco rule: Read sensitive file untrusted)"
	if [ "$plan" = "1" ]; then
		qs_run kubectl "${QS_KCTX[@]}" -n "$QS_DEMO_NS" exec "$QS_DEMO_POD" -- cat /etc/shadow
		qs_run kubectl "${QS_KCTX[@]}" -n "$QS_NS" logs -l app.kubernetes.io/component=aggregator --tail=-1
		return 0
	fi

	local attempt found="" t_seen="" t_attack
	for attempt in $(seq 1 "$QS_ATTEMPTS"); do
		# A read before Falco's driver has loaded is not seen, so the action is
		# repeated (for real) until the agent reacts. Each attempt is counted.
		t_attack="$(date +%s)"
		printf '+ kubectl %s -n %s exec %s -- cat /etc/shadow   (read %s of %s)\n' \
			"${QS_KCTX[*]}" "$QS_DEMO_NS" "$QS_DEMO_POD" "$attempt" "$QS_ATTEMPTS"
		kubectl "${QS_KCTX[@]}" -n "$QS_DEMO_NS" exec "$QS_DEMO_POD" -- cat /etc/shadow >/dev/null
		while [ $(($(date +%s) - t_attack)) -lt "$QS_ATTEMPT_GAP" ]; do
			sleep "$QS_POLL"
			if found="$(qs_aggregator_logs | qs_parse_transition "$QS_DEMO_NS")"; then
				t_seen="$(date +%s)"
				break 2
			fi
		done
	done

	if [ -z "$t_seen" ]; then
		echo "quickstart: no transition for $QS_DEMO_NS after $QS_ATTEMPTS reads of /etc/shadow." >&2
		echo "quickstart: check Falco: kubectl --context kind-$QS_CLUSTER -n $QS_NS logs -l app.kubernetes.io/name=falco -c falco" >&2
		echo "quickstart: and the aggregator: kubectl --context kind-$QS_CLUSTER -n $QS_NS logs -l app.kubernetes.io/component=aggregator --tail=200" >&2
		exit 1
	fi

	local wl from to score ts report falco rc=0
	IFS=$'\t' read -r wl from to score ts <<<"$found"
	# Every rule that fired for the demo pod up to the transition, not only
	# the read's: the score is theirs together, and a transition some other
	# rule caused is said to be one (#177 showed the hook's 36 as the read's).
	# The log is read on its own first: a kubectl failure is an infra fault,
	# never an empty log that the verdict is drawn from.
	falco="$(kubectl "${QS_KCTX[@]}" -n "$QS_NS" logs -l app.kubernetes.io/name=falco -c falco --tail=-1)" || rc=$?
	if [ "$rc" != 0 ]; then
		echo "quickstart: infra: cannot read the Falco log (kubectl exited $rc, its error is above); the transition of $wl was seen but its cause cannot be checked." >&2
		exit 1
	fi
	report="$(qs_report_rules "$QS_DEMO_NS" "$QS_DEMO_POD" "$ts" <<<"$falco")" || rc=$?
	local elapsed=$((t_seen - t0))

	echo
	echo "  $(qs_headline "$rc" "$report")"
	echo
	printf '    %-10s %s\n' "workload" "$wl"
	printf '    %-10s %s\n' "from" "$from"
	printf '    %-10s %s\n' "to" "$to"
	printf '    %-10s %s\n' "score" "$score"
	printf '    %-10s %s\n' "logged at" "$ts (aggregator clock)"
	printf '    %-10s %s\n' "reads" "$attempt of /etc/shadow before the transition"
	echo
	printf '%s\n' "$report"
	echo
	printf '  kind create cluster -> every pod Ready:       %ss\n' "$((t_ready - t0))"
	printf '  kind create cluster -> first FSM transition:  %ss (budget %ss)\n' "$elapsed" "$budget"
	echo
	echo "  Watch it:  kubectl --context kind-$QS_CLUSTER -n $QS_NS logs -l app.kubernetes.io/component=aggregator -f"
	echo "  Clean up:  make quickstart-clean"
	local fail=0
	if [ "$rc" != 0 ] && [ "$rc" != 3 ]; then
		echo "quickstart: the read of /etc/shadow did not cause the transition (or its cause cannot be told); see the rules above." >&2
		fail=1
	fi
	if ! qs_within_budget "$elapsed" "$budget"; then
		echo "quickstart: over budget: ${elapsed}s > ${budget}s" >&2
		fail=1
	fi
	[ "$fail" = 0 ] || exit 1
}

if [ "${BASH_SOURCE[0]}" = "$0" ]; then
	main "$@"
fi
