#!/usr/bin/env bash
# hack/down.sh: remove everything `make up` created (Story 12.3), run by
# `make down`.
#
# Deletes the kind cluster through the kubeconfig make up wrote, removes any
# node container kind left behind, removes a kind-<cluster> context, cluster
# and user from the default kubeconfig if one is there, then the out dir (key
# material and the kubeconfig) and hack/.audit-full. It ends by checking that
# no cluster, node container or kubeconfig context is left, and exits
# non-zero if one is. Safe to run when nothing, or only part, is there.
#
# Settings: UP_CLUSTER (olaitan-full), UP_OUT_DIR ($HOME/.olaitan-full),
# UP_PLAN=1 (print the commands that would change something; run only the
# read-only probes).
set -euo pipefail

DOWN_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DOWN_CLUSTER="${UP_CLUSTER:-olaitan-full}"
DOWN_OUT="${UP_OUT_DIR-$HOME/.olaitan-full}"

down_run() {
	printf '+ %s\n' "$*"
	[ "${UP_PLAN:-}" = "1" ] && return 0
	"$@"
}

# down_safe_out DIR: the out dir is removed with rm -rf, so only an absolute
# path that is not /, the home directory or inside this repository passes.
down_safe_out() {
	local d="${1%/}"
	case "$1" in
	/*) ;;
	*)
		echo "down: refusing UP_OUT_DIR='$1': it must be an absolute path" >&2
		return 1
		;;
	esac
	if [ -z "$d" ] || [ "$d" = "${HOME%/}" ]; then
		echo "down: refusing UP_OUT_DIR='$1': it is / or the home directory" >&2
		return 1
	fi
	case "$d/" in
	"$DOWN_ROOT"/*)
		echo "down: refusing UP_OUT_DIR='$1': it is inside the repository" >&2
		return 1
		;;
	esac
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

# down_leftovers: print what is left and return 1, or confirm nothing is.
down_leftovers() {
	local left=0 c
	if kind get clusters 2>/dev/null | grep -qxF "$DOWN_CLUSTER"; then
		echo "  left: kind cluster $DOWN_CLUSTER"
		left=1
	fi
	for c in $(down_node_containers); do
		echo "  left: container $c (kind cluster $DOWN_CLUSTER)"
		left=1
	done
	if down_kubeconfig_has contexts "kind-$DOWN_CLUSTER"; then
		echo "  left: context kind-$DOWN_CLUSTER in the default kubeconfig"
		left=1
	fi
	if [ -e "$DOWN_OUT/kubeconfig" ]; then
		echo "  left: $DOWN_OUT/kubeconfig"
		left=1
	fi
	if [ "$left" = 1 ]; then
		echo "down: something is left (above)" >&2
		return 1
	fi
	echo "==> no cluster, no container, no kubeconfig context left for $DOWN_CLUSTER"
}

main() {
	down_safe_out "$DOWN_OUT" || exit 1
	echo "==> removing kind cluster $DOWN_CLUSTER and everything make up wrote"
	# Through make up's kubeconfig while it exists, so kind removes the context
	# there; kind cannot lock a kubeconfig in a directory that is gone.
	if [ -e "$DOWN_OUT/kubeconfig" ]; then
		down_run kind delete cluster --name "$DOWN_CLUSTER" --kubeconfig "$DOWN_OUT/kubeconfig"
	else
		down_run kind delete cluster --name "$DOWN_CLUSTER"
	fi
	local c
	for c in $(down_node_containers); do
		down_run docker rm -f "$c"
	done
	local what
	for what in context cluster user; do
		if down_kubeconfig_has "${what}s" "kind-$DOWN_CLUSTER"; then
			down_run kubectl config "delete-$what" "kind-$DOWN_CLUSTER"
		fi
	done
	down_run rm -rf "$DOWN_OUT"
	down_run rm -rf "$DOWN_ROOT/hack/.audit-full"
	[ "${UP_PLAN:-}" = "1" ] && return 0
	down_leftovers
}

if [ "${BASH_SOURCE[0]}" = "$0" ]; then
	main "$@"
fi
