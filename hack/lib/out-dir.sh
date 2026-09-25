# shellcheck shell=bash
# hack/lib/out-dir.sh: the out-dir rules `make up` and `make down` share
# (Story 12.3). Sourced by hack/up.sh and hack/down.sh; defines functions
# only.
#
# `make down` removes the out dir with rm -rf, so the path is checked on its
# canonical form, and it is removed only when `make up` marked it as its own.

# The file make up writes into the out dir, first thing after preflight. It
# holds the cluster name on one line.
OLAITAN_OUT_MARKER=".olaitan-up"

# olaitan_out_dir RAW REPO: print the canonical out dir and return 0, or print
# why RAW is refused and return 1. Refused: empty, relative, a symbolic link
# (the last component checked before resolving, trailing slashes ignored;
# any other component by comparing realpath -m with realpath -m -s), /, the
# home directory
# or any of its parents, the repository REPO or any of its parents, and any
# path inside the repository. The home directory and the repository are
# canonical too (realpath -m, pwd -P), so // and .. spellings do not slip by.
olaitan_out_dir() {
	local raw="$1" d home repo
	case "$raw" in
	"")
		echo "it is empty"
		return 1
		;;
	/*) ;;
	*)
		echo "it must be an absolute path"
		return 1
		;;
	esac
	d="$raw"
	while [ "${#d}" -gt 1 ] && [ "${d%/}" != "$d" ]; do d="${d%/}"; done
	if [ -L "$d" ]; then
		echo "it is a symbolic link; name the directory itself"
		return 1
	fi
	if ! d="$(realpath -m -- "$raw" 2>/dev/null)" || [ -z "$d" ]; then
		echo "it cannot be resolved (realpath -m failed)"
		return 1
	fi
	# A symlink anywhere in the path (link/., link/sub) resolves somewhere
	# else; only a path with no symlink in it is accepted.
	local plain
	if ! plain="$(realpath -m -s -- "$raw" 2>/dev/null)" || [ "$plain" != "$d" ]; then
		echo "it goes through a symbolic link (it resolves to $d); name the real path"
		return 1
	fi
	if [ "$d" = "/" ]; then
		echo "it is /"
		return 1
	fi
	if ! repo="$(cd "$2" 2>/dev/null && pwd -P)"; then
		echo "the repository $2 cannot be resolved"
		return 1
	fi
	home="$(realpath -m -- "${HOME:-/}" 2>/dev/null)" || home="/"
	case "$home/" in
	"$d"/*)
		echo "it is the home directory ($home) or one of its parents"
		return 1
		;;
	esac
	case "$repo/" in
	"$d"/*)
		echo "it is the repository ($repo) or one of its parents"
		return 1
		;;
	esac
	case "$d/" in
	"$repo"/*)
		echo "it is inside the repository ($repo)"
		return 1
		;;
	esac
	printf '%s\n' "$d"
}

# olaitan_out_marked DIR: print the cluster name DIR's marker holds and
# return 0, or return 1 when there is no marker (a symlink does not count).
olaitan_out_marked() {
	local m="$1/$OLAITAN_OUT_MARKER" name=""
	[ -f "$m" ] && [ ! -L "$m" ] || return 1
	IFS= read -r name <"$m" || [ -n "$name" ] || return 1
	printf '%s\n' "$name"
}
