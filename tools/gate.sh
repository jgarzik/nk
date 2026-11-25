#!/bin/sh
# The commit gate: every commit must pass this alone (bisectable history).
# Runs each step in order, stops at the first failure, prints GATE-OK.
set -u
cd "$(dirname "$0")/.."
out=target/gate
rm -rf "$out"
mkdir -p "$out"
start=$(date +%s)

for step in fmt-check clippy test ledger-check; do
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
