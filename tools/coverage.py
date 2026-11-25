#!/usr/bin/env python3
"""Unit-test coverage of the library crates, with a floor.

Pure logic lives in lib/ so the host can test it; this checks that it is.
Runs the host unit tests under `cargo llvm-cov` and fails if any file in
lib/ has fewer than FLOOR percent of its lines executed.

Not part of the gate: it needs the `cargo-llvm-cov` tool, which the gate
does not otherwise require. Run it when a library changes and at the end
of a roadmap phase (`make coverage`).

Left out: lib/ntabi/pdb.rs and probe.rs, which are tests themselves and
skip most of their body when a fixture is not downloaded.
"""

import json
import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
FLOOR = 95.0
SKIP = {"lib/ntabi/pdb.rs", "lib/ntabi/probe.rs"}


def main():
    if not shutil.which("cargo-llvm-cov"):
        sys.exit("coverage: cargo-llvm-cov is not installed (cargo install cargo-llvm-cov)")
    out = subprocess.run(["cargo", "llvm-cov", "--json", "--summary-only"], cwd=ROOT,
                         capture_output=True, text=True)
    if out.returncode != 0:
        sys.exit(f"coverage: the unit tests failed\n{out.stderr[-3000:]}")
    low = []
    for entry in json.loads(out.stdout)["data"][0]["files"]:
        name = str(Path(entry["filename"]).relative_to(ROOT))
        if not name.startswith("lib/") or name in SKIP:
            continue
        lines = entry["summary"]["lines"]
        print(f"{lines['percent']:6.2f}%  {lines['covered']:5}/{lines['count']:<5} {name}")
        if lines["percent"] < FLOOR:
            low.append(name)
    if low:
        print(f"coverage: below {FLOOR:.0f}% of lines: {', '.join(low)}")
        return 1
    print(f"coverage: every library file is at or above {FLOOR:.0f}% of lines")
    return 0


if __name__ == "__main__":
    sys.exit(main())
