#!/bin/sh
# The commit gate: every commit must pass this alone (bisectable history).
# Runs each step in order, stops at the first failure, prints GATE-OK.
# Hosted CI runs the same thing, with both architectures emulated.
set -u
cd "$(dirname "$0")/.."
out=target/gate
rm -rf "$out"
mkdir -p "$out"
start=$(date +%s)

# The ledger is generated from the boot logs, so it is checked after them.
for step in fmt-check clippy clippy-arm test boot-gate ledger-check unwind-check; do
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
