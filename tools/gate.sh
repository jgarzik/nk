#!/bin/sh
# The three gates (doc/TESTING.md). Usage: gate.sh fast|batch|full
#
#   fast   every commit: x86-64 only, the boots the change selects
#   batch  the merged tip of `updates`, and CI: all of x86-64, and arm64
#          compiles
#   full   nightly and milestones: everything, on both architectures
#
# Runs each step in order (those joined by a comma at once: the host
# tests run while the machines boot, both with the fixtures already
# fetched), stops after the first step that
# fails, prints the gate's OK line. Which boots a gate runs:
# tools/boot_test.py.
set -u
cd "$(dirname "$0")/.."
case "${1:-}" in
fast)  steps="fmt-check clippy fixtures test,boot-fast unwind-check" ok=GATE-FAST-OK ;;
batch) steps="fmt-check clippy clippy-arm fixtures test,boot-gate unwind-check" ok=GATE-OK ;;
full)  steps="fmt-check clippy clippy-arm fixtures test,boot-full unwind-check unwind-check-arm" ok=GATE-FULL-OK ;;
*)     echo "usage: $0 fast|batch|full" >&2; exit 2 ;;
esac
out=target/gate
rm -rf "$out"
mkdir -p "$out"
start=$(date +%s)

# Run one step; leave its output, and its verdict as a line.
run() {
    began=$(date +%s)
    if make --no-print-directory "$1" >"$out/$1.out" 2>&1; then verdict=ok; else verdict=FAILED; fi
    printf '%-17s%s (%ss)\n' "$1" "$verdict" "$(( $(date +%s) - began ))" >"$out/$1.verdict"
}

for group in $steps; do
    for step in $(echo "$group" | tr , ' '); do
        run "$step" &
    done
    wait
    failed=
    for step in $(echo "$group" | tr , ' '); do
        cat "$out/$step.verdict"
        grep -q ' ok ' "$out/$step.verdict" && continue
        failed="$failed $step"
        # The boots are printed in the order they are listed, so the end
        # of the output need not be about the one that failed: show the
        # failed boots. Anything else shows its last lines.
        case $step in
        boot-*) tools/boot_test.py --failures "$out/$step.out" || tail -n 40 "$out/$step.out" ;;
        *) tail -n 40 "$out/$step.out" ;;
        esac
    done
    if [ -n "$failed" ]; then
        echo "GATE-FAILED ($1 gate:$failed; full logs: $out/<step>.out)"
        exit 1
    fi
done
# What the batch gate next compares the tree with: this commit, if the
# tree is this commit. The full gate proves all the batch gate does.
if [ "$1" != fast ] && [ -z "$(git status --porcelain)" ]; then
    git rev-parse HEAD >target/gate-passed
fi
grep -h '^tier gate' "$out"/boot-*.out
echo "$ok ($(( $(date +%s) - start ))s)"
