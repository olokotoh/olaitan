#!/usr/bin/env bash
# hack/down.sh: remove everything `make up` created (Story 12.3), run by
# `make down`.
#
# Deletes the kind cluster named UP_CLUSTER, removes any node container kind
# left behind, and removes the kind-<cluster> context, cluster and user from
# the default kubeconfig if they are there. It goes by name: any kind cluster
# and kind-<cluster> entries with that name are removed, whoever made them,
# and each removal is printed. Then it removes the out dir (key material and
# the kubeconfig), but only when make up's marker (<out>/.olaitan-up) is there
# and names this cluster; any other directory is left alone, said so, and the
# run exits non-zero. hack/.audit-full is removed too. It ends by checking
# that no cluster, node container or kubeconfig context is left, and exits
# non-zero if one is, or if it could not look. Safe to run when nothing, or
# only part, is there.
#
# The out dir is refused outright (nothing runs) when it is empty, relative,
# a symlink, /, the home directory or a parent of it, or the repository, a
# parent of it or a path inside it; see hack/lib/out-dir.sh.
#
# Settings: UP_CLUSTER (olaitan-full), UP_OUT_DIR ($HOME/.olaitan-full; set
# but empty is refused, as in hack/up.sh), UP_PLAN=1 (print the commands that
# would change something; run only the read-only probes).
set -euo pipefail

DOWN_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck source=hack/lib/out-dir.sh
. "$DOWN_ROOT/hack/lib/out-dir.sh"
DOWN_CLUSTER="${UP_CLUSTER:-olaitan-full}"
DOWN_OUT="${UP_OUT_DIR-$HOME/.olaitan-full}"

down_run() {
	printf '+ %s\n' "$*"
	[ "${UP_PLAN:-}" = "1" ] && return 0
	"$@"
}

down_say() { printf '==> %s\n' "$*"; }

# down_owns DIR CLUSTER: DIR holds make up's marker naming CLUSTER.
down_owns() {
	local name
	name="$(olaitan_out_marked "$1")" || return 1
	[ "$name" = "$2" ]
}

down_node_containers() {
	docker ps -a --filter "label=io.x-k8s.kind.cluster=$DOWN_CLUSTER" -q 2>/dev/null || true
}

# down_kubeconfig_has KIND NAME: KIND is contexts, clusters or users.
down_kubeconfig_has() {
	case "$1" in
	contexts) kubectl config get-contexts -o name 2>/dev/null | grep -qxF "$2" ;;
	*) kubectl config "get-$1" 2>/dev/null | tail -n +2 | grep -qxF "$2" ;;
	esac
}

# down_leftovers: print what is left and return 1, or confirm nothing is. A
# probe that cannot run (tool missing or failing) is reported as "could not
# verify" and also returns 1: it never counts as nothing left.
down_leftovers() {
	local left=0 unknown=0 out c
	if command -v kind >/dev/null 2>&1 && out="$(kind get clusters 2>/dev/null)"; then
		if grep -qxF "$DOWN_CLUSTER" <<<"$out"; then
			echo "  left: kind cluster $DOWN_CLUSTER"
			left=1
		fi
	else
		echo "  could not verify the kind cluster: kind get clusters did not run"
		unknown=1
	fi
	if command -v docker >/dev/null 2>&1 &&
		out="$(docker ps -a --filter "label=io.x-k8s.kind.cluster=$DOWN_CLUSTER" -q 2>/dev/null)"; then
		for c in $out; do
			echo "  left: container $c (kind cluster $DOWN_CLUSTER)"
			left=1
		done
	else
		echo "  could not verify the node containers: docker ps did not run"
		unknown=1
	fi
	if command -v kubectl >/dev/null 2>&1 && out="$(kubectl config get-contexts -o name 2>/dev/null)"; then
		if grep -qxF "kind-$DOWN_CLUSTER" <<<"$out"; then
			echo "  left: context kind-$DOWN_CLUSTER in the default kubeconfig"
			left=1
		fi
	else
		echo "  could not verify the default kubeconfig: kubectl config get-contexts did not run"
		unknown=1
	fi
	if [ -e "$DOWN_OUT/kubeconfig" ]; then
		echo "  left: $DOWN_OUT/kubeconfig"
		left=1
	fi
	if [ "$left" = 1 ]; then
		echo "down: something is left (above)" >&2
		return 1
	fi
	if [ "$unknown" = 1 ]; then
		echo "down: could not verify that nothing is left (above)" >&2
		return 1
	fi
	echo "==> no cluster, no container, no kubeconfig context left for $DOWN_CLUSTER"
}

main() {
	local why
	if ! why="$(olaitan_out_dir "$DOWN_OUT" "$DOWN_ROOT")"; then
		echo "down: refusing UP_OUT_DIR='$DOWN_OUT' (FULL_OUT_DIR): $why; nothing was removed" >&2
		exit 1
	fi
	DOWN_OUT="$why"
	local owned=0 kept=0 name
	down_owns "$DOWN_OUT" "$DOWN_CLUSTER" && owned=1

	down_say "deleting kind cluster $DOWN_CLUSTER (any kind cluster with this name)"
	# Through make up's kubeconfig while it exists, so kind removes the context
	# there; kind cannot lock a kubeconfig in a directory that is gone. Never
	# through a kubeconfig in a directory make up did not mark.
	if [ "$owned" = 1 ] && [ -e "$DOWN_OUT/kubeconfig" ]; then
		down_run kind delete cluster --name "$DOWN_CLUSTER" --kubeconfig "$DOWN_OUT/kubeconfig"
	else
		down_run kind delete cluster --name "$DOWN_CLUSTER"
	fi
	local c
	for c in $(down_node_containers); do
		down_say "removing leftover node container $c (kind cluster $DOWN_CLUSTER)"
		down_run docker rm -f "$c"
	done
	local what
	for what in context cluster user; do
		if down_kubeconfig_has "${what}s" "kind-$DOWN_CLUSTER"; then
			down_say "removing $what kind-$DOWN_CLUSTER from the default kubeconfig"
			down_run kubectl config "delete-$what" "kind-$DOWN_CLUSTER"
		fi
	done
	if [ "$owned" = 1 ]; then
		down_say "removing $DOWN_OUT (make up's marker names $DOWN_CLUSTER)"
		down_run rm -rf "$DOWN_OUT"
	elif [ -e "$DOWN_OUT" ] || [ -L "$DOWN_OUT" ]; then
		if name="$(olaitan_out_marked "$DOWN_OUT")"; then
			why="its $OLAITAN_OUT_MARKER names $name, not $DOWN_CLUSTER"
		else
			why="it has no $OLAITAN_OUT_MARKER, so make up did not make it"
		fi
		echo "down: not removing $DOWN_OUT: $why. If it is left over from make e2e-full, make e2e-full-down removes it; otherwise remove it yourself if it is yours." >&2
		kept=1
	else
		down_say "no $DOWN_OUT to remove"
	fi
	down_say "removing $DOWN_ROOT/hack/.audit-full"
	down_run rm -rf "$DOWN_ROOT/hack/.audit-full"
	if [ "${UP_PLAN:-}" != "1" ]; then
		down_leftovers || kept=1
	fi
	[ "$kept" = 0 ] || exit 1
}

if [ "${BASH_SOURCE[0]}" = "$0" ]; then
	main "$@"
fi
