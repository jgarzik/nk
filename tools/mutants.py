#!/usr/bin/env python3
"""Mutation checks: break the kernel on purpose and require a test to fail.

A test that still passes when the thing it tests is broken proves nothing.
Each file in tools/mutants/ describes one deliberate break:

    # Why this break matters, in a line or two.
    scenario: x86_64
    fails: cpu.fp-preserved
    file: kernel/arch/x86_64/trap.rs
    remove:     movups xmm3, xmmword ptr [rsp + 48]

`remove:` deletes the first line of the file equal to the text after
`remove: ` (leading spaces count); `occurrence: 3` picks the third such
line instead. `replace:` followed by `with:` swaps the line instead of
deleting it. `fails:` names the test that must report FAIL, or is
`scenario` when the scenario as a whole must fail (one that expects a
particular bugcheck, say, and no longer gets it).

Usage: mutants.py [name...]      (default: every mutant)

For each mutant: apply it, build, boot the scenario, check the named test
failed, and put the file back, whatever happened in between. Not part of
the gate (it rebuilds the kernel once per mutant); run it when tests or
the code they cover change, and at the end of a phase.
"""

import os
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
MUTANTS = ROOT / "tools" / "mutants"


def parse(path):
    fields = {}
    for line in path.read_text().splitlines():
        if line.startswith("#") or not line.strip():
            continue
        key, _, value = line.partition(":")
        # One space separates the key from its text; the rest is literal.
        fields[key] = value[1:] if value.startswith(" ") else value
    missing = {"scenario", "fails", "file"} - fields.keys()
    if missing or ("remove" in fields) == ("replace" in fields):
        sys.exit(f"mutants: {path.name}: needs scenario, fails, file and one of remove/replace")
    if "replace" in fields and "with" not in fields:
        sys.exit(f"mutants: {path.name}: replace needs with")
    return fields


def mutate(text, fields, name):
    target = fields.get("remove", fields.get("replace"))
    lines = text.split("\n")
    matches = [i for i, line in enumerate(lines) if line == target]
    occurrence = int(fields.get("occurrence", "1"))
    if len(matches) < occurrence:
        sys.exit(f"mutants: {name}: {fields['file']} has {len(matches)} lines equal to "
                 f"{target!r}, not {occurrence}")
    at = matches[occurrence - 1]
    lines[at:at + 1] = [] if "remove" in fields else [fields["with"]]
    return "\n".join(lines)


def run(name):
    """True if the mutant was caught."""
    fields = parse(MUTANTS / f"{name}.mutant")
    source = ROOT / fields["file"]
    original = source.read_bytes()
    arch = "aarch64" if fields["scenario"].startswith("aarch64") else "x86_64"
    build = "build-arm" if arch == "aarch64" else "build"
    try:
        source.write_text(mutate(original.decode(), fields, name))
        built = subprocess.run(["make", "--no-print-directory", build], cwd=ROOT,
                               capture_output=True, text=True)
        if built.returncode != 0:
            print(f"{name}: the mutant does not build:\n{built.stderr[-2000:]}")
            return False
        # A broken kernel may well hang: do not wait two minutes for it.
        env = {**os.environ, "BOOT_TEST_TIMEOUT": os.environ.get("MUTANT_TIMEOUT", "30")}
        boot = subprocess.run([ROOT / "tools" / "boot_test.py", fields["scenario"]],
                              cwd=ROOT, capture_output=True, text=True, env=env)
        out = boot.stdout
    finally:
        source.write_bytes(original)
    wanted = fields["fails"]
    caught = wanted == "scenario" or bool(
        re.search(rf"NK-TEST {re.escape(wanted)}:FAIL", out))
    if boot.returncode == 0:
        print(f"{name}: SURVIVED: the boot passed with the kernel broken")
        return False
    if not caught:
        print(f"{name}: the boot failed, but not as expected ({wanted}):\n{out[-1500:]}")
        return False
    print(f"{name}: caught ({wanted})")
    return True


def main():
    names = sys.argv[1:] or sorted(p.stem for p in MUTANTS.glob("*.mutant"))
    if not names:
        sys.exit("mutants: none defined")
    try:
        results = [run(name) for name in names]
    finally:
        # Leave binaries that match the sources again.
        subprocess.run(["make", "--no-print-directory", "build", "build-arm"], cwd=ROOT,
                       capture_output=True)
    survivors = results.count(False)
    print(f"mutants: {len(results) - survivors} of {len(results)} caught")
    return 1 if survivors else 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        sys.exit(130)
