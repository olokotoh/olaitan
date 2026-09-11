# shellcheck shell=bash
# falco_kernel_verdict <kernelVersion> -- judge a node kernel against the
# pinned Falco (hack/falco-support.env). Sourced by hack/preflight.sh and by
# deploy/helm/falco_pin_test.go.
#
# Exit 0: supported. Exit 1: BLOCKER, a pairing known to fail. Exit 3: a
# caveat, meaning we cannot vouch for it either way.
#
# Only a KNOWN failure is a blocker. Below the modern_ebpf floor is a caveat,
# not a blocker, because distributions backport BTF and the ring buffer (RHEL
# 8's 4.18 runs modern_ebpf); calling it a blocker would be a false claim.

_falco_support_file="$(dirname "${BASH_SOURCE[0]}")/../falco-support.env"
if [ -r "$_falco_support_file" ]; then
  while IFS='=' read -r _k _v; do
    case "$_k" in ''|\#*) continue ;; esac
    # Values already in the environment win, so tests (and operators) can
    # ask "what if the pin were X".
    if [ -z "${!_k:-}" ]; then
      printf -v "$_k" '%s' "$_v"
    fi
  done < "$_falco_support_file"
fi

# _fk_ver_ge A B: true when version A >= B, comparing numeric major.minor.patch
# only. A pre-release suffix is dropped, so 0.45.0-rc1 counts as 0.45.0: the
# fix landed in rc1 and GA must not read as older than it.
_fk_ver_ge() {
  local a b
  a="$(printf '%s' "$1" | grep -oE '^[0-9]+(\.[0-9]+){0,2}')"
  b="$(printf '%s' "$2" | grep -oE '^[0-9]+(\.[0-9]+){0,2}')"
  [ -n "$a" ] && [ -n "$b" ] || return 2
  [ "$(printf '%s\n%s\n' "$a" "$b" | sort -V | head -1)" = "$b" ]
}

# _fk_series 7.0.0-31-generic -> 7.0
_fk_series() { printf '%s' "$1" | grep -oE '^[0-9]+\.[0-9]+'; }

falco_kernel_verdict() {
  local kernel="$1" series
  series="$(_fk_series "$kernel")"
  if [ -z "$series" ]; then
    echo "could not read a kernel version from '${kernel}'; check the node before trusting Falco on it"
    return 3
  fi
  if _fk_ver_ge "$series" 7.0 && ! _fk_ver_ge "$FALCO_PINNED_VERSION" "$FALCO_PREEMPT_FIX_VERSION"; then
    echo "BLOCKER Falco ${FALCO_PINNED_VERSION} crashes every few minutes on kernel ${kernel}"
    echo "        (falcosecurity/falco#3955: modern_bpf auxmap race on preemptible 7.x kernels)."
    echo "        Fixed by falcosecurity/libs#3086 in Falco >= ${FALCO_PREEMPT_FIX_VERSION}."
    return 1
  fi
  if ! _fk_ver_ge "$series" "$FALCO_MIN_KERNEL"; then
    echo "kernel ${kernel} is below ${FALCO_MIN_KERNEL}, the usual floor for Falco's modern_ebpf driver."
    echo "It works only if the distribution backported BTF and the BPF ring buffer. Check a node:"
    echo "  bpftool feature probe kernel | grep -E 'ringbuf|btf'"
    return 3
  fi
  if ! _fk_ver_ge "$FALCO_MAX_TESTED_KERNEL" "$series"; then
    echo "kernel ${kernel} is newer than ${FALCO_MAX_TESTED_KERNEL}, the newest series Falco ${FALCO_PINNED_VERSION} has been tested on here."
    echo "It has not been tested; watch the Falco pod's restart count after install."
    return 3
  fi
  echo "kernel ${kernel} is supported by Falco ${FALCO_PINNED_VERSION} (modern_ebpf, tested through ${FALCO_MAX_TESTED_KERNEL})"
  return 0
}
