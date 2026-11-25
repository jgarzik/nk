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


KERNEL_MODULES = ("ntoskrnl.exe", "hal.dll")
CORPUS = ROOT / "ledger" / "corpus.x86_64.txt"


def corpus(exports, lists):
    """How much of what Microsoft's own kernel-mode binaries import NK
    provides. `lists` is the text of the committed import lists
    (ledger/corpus.x86_64.txt, written by tools/corpus.py), so no Windows
    binary is needed to compute it."""
    union, binaries = {}, {}
    for line in lists.splitlines():
        if line.startswith("#"):
            continue
        head, _, symbols = line.partition(":")
        file, version, module = head.split()
        entry = binaries.setdefault(file, {"file": file, "version": version,
                                           "kernel": dict.fromkeys(["total"] + STATES, 0),
                                           "by_ordinal": 0, "other_modules": {}})
        symbols = symbols.split()
        if module not in KERNEL_MODULES:
            if module != "-":
                entry["other_modules"][module] = len(symbols)
            continue
        for name in symbols:
            # hal.dll only forwards to the kernel in this build: one name
            # space, whichever module a driver imports it from.
            state = next((exports[(m, name)] for m in KERNEL_MODULES if (m, name) in exports),
                         "missing")
            union[name] = state
            entry["kernel"]["total"] += 1
            entry["kernel"][state] += 1
            entry["by_ordinal"] += name.startswith("#")
    return {
        "note": "Microsoft's kernel-mode binaries of the pinned build (fixtures/corpus.toml): "
                "distinct names they import from ntoskrnl.exe and hal.dll, by what NK does "
                "about each. Nothing here is loaded yet.",
        "binaries": len(binaries),
        "kernel_names": {"total": len(union),
                         **{s: sum(1 for v in union.values() if v == s) for s in STATES}},
        "by_binary": [binaries[f] for f in sorted(binaries)],
    }


def build(arch, fixtures):
    exports, booted = kernel_exports(arch)
    entries, needed = [], {}
    for fx in fixtures:
        imports = []
        for module, name in imports_of(CACHE / fx["file"]):
            # hal.dll only forwards to the kernel: one name space.
            state = exports.get((module.lower(), name),
                                exports.get((KERNEL_MODULES[0], name), "missing")
                                if module.lower() in KERNEL_MODULES else "missing")
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
        # No source offers Windows 10 arm64 binaries, so only x86-64 has one.
        **({"corpus": corpus(exports, CORPUS.read_text())} if arch == "x86_64" else {}),
    }


def main():
    check = "--check" in sys.argv
    manifest = tomllib.loads((ROOT / "fixtures" / "manifest.toml").read_text())["fixture"]
    # Only driver images have import tables.
    # Tables and symbol files are not images: they import nothing.
    manifest = [fx for fx in manifest if "kind" not in fx]
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
