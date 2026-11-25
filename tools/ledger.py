#!/usr/bin/env python3
"""Generate the compatibility ledger: what each fixture driver imports, and
what the kernel does about each import.

Imports are read from the fetched fixture binaries with `peinfo`, which uses
the kernel's own PE loader. Export states come from the kernel itself: the
boot test saves the `NK-EXPORT <module> <name> <state>` lines the kernel
prints. With no boot log yet, every import is "missing".

Usage: ledger.py [--check]
  default  rewrite ledger/<arch>.json
  --check  fail if a committed ledger differs from what would be generated
           (fixtures that are not downloaded make the check a visible SKIP)
"""

import json
import subprocess
import sys
import tomllib
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
CACHE = ROOT / "target" / "fixtures"
PEINFO = ROOT / "target" / "debug" / "peinfo"
REFERENCE = "Windows 10 22H2, NT 10.0.19045.2006"
# States the kernel may report, best first. "missing" is ours: no export.
STATES = ["implemented", "partial", "traps", "missing"]


def kernel_exports(arch):
    """{(module, name): state} from the last boot test of this arch."""
    path = ROOT / "target" / "qemu" / f"exports-{arch}.txt"
    exports = {}
    if path.exists():
        for line in path.read_text().splitlines():
            _, module, name, state = line.split()
            exports[(module.lower(), name)] = state
    return exports, path.exists()


def imports_of(path):
    out = subprocess.run([PEINFO, path], check=True, capture_output=True, text=True).stdout
    return [line.split()[1:] for line in out.splitlines() if line.startswith("import ")]


def build(arch, fixtures):
    exports, booted = kernel_exports(arch)
    entries, needed = [], {}
    for fx in fixtures:
        imports = []
        for module, name in imports_of(CACHE / fx["file"]):
            state = exports.get((module.lower(), name), "missing")
            imports.append({"module": module, "name": name, "state": state})
            if fx.get("boot", True):
                needed[(module.lower(), name)] = state
        entries.append({
            "name": fx["name"], "file": fx["file"], "sha256": fx["sha256"],
            "status": fx["status"], "loaded_at_boot": fx.get("boot", True),
            "imports": imports,
        })
    return {
        "reference": REFERENCE,
        "arch": arch,
        "export_states_from_boot_log": booted,
        "summary": {
            "note": "distinct imports of the fixtures loaded at boot",
            "total": len(needed),
            **{s: sum(1 for v in needed.values() if v == s) for s in STATES},
        },
        "fixtures": entries,
    }


def main():
    check = "--check" in sys.argv
    manifest = tomllib.loads((ROOT / "fixtures" / "manifest.toml").read_text())["fixture"]
    # Only driver images have import tables.
    manifest = [fx for fx in manifest if fx.get("kind") != "abi-table"]
    absent = [fx["file"] for fx in manifest if not (CACHE / fx["file"]).exists()]
    if absent:
        print(f"ledger: SKIP, fixtures not downloaded: {', '.join(absent)} (run: make fixtures)")
        return 0 if check else 1
    subprocess.run(["cargo", "build", "-q", "-p", "peinfo"], check=True, cwd=ROOT)
    rc = 0
    for arch in ("x86_64", "aarch64"):
        text = json.dumps(build(arch, [f for f in manifest if f["arch"] == arch]), indent=1) + "\n"
        path = ROOT / "ledger" / f"{arch}.json"
        if not check:
            path.write_text(text)
            print(f"wrote {path.relative_to(ROOT)}")
        elif not path.exists() or path.read_text() != text:
            print(f"ledger: {path.relative_to(ROOT)} is stale (run: make ledger)")
            rc = 1
    return rc


if __name__ == "__main__":
    sys.exit(main())
