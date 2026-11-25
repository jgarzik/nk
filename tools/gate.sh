#!/bin/sh
# The commit gate: every commit must pass this alone (bisectable history).
# Runs each step in order, stops at the first failure, prints GATE-OK.
#
# `gate.sh ci` is the subset hosted CI runs: without KVM both architectures
# are emulated, so it boots only the main scenario of each instead of the
# whole gate tier.
set -u
cd "$(dirname "$0")/.."
out=target/gate
rm -rf "$out"
mkdir -p "$out"
start=$(date +%s)

case "${1:-gate}" in
gate) boots="boot-gate" ;;
ci) boots="check check-arm" ;;
*) echo "usage: gate.sh [ci]" >&2; exit 2 ;;
esac

# The ledger is generated from the boot logs, so it is checked after them.
for step in fmt-check clippy clippy-arm test $boots ledger-check; do
    printf '%-12s' "$step"
    if make --no-print-directory "$step" >"$out/$step.out" 2>&1; then
        echo ok
    else
        echo FAILED
        tail -n 40 "$out/$step.out"
        echo "GATE-FAILED ($step; full log: $out/$step.out)"
        exit 1
    fi
done
echo "GATE-OK ($(( $(date +%s) - start ))s)"
