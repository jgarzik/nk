#!/usr/bin/env python3
"""Generate the compatibility ledger: what each fixture driver imports, and
what the kernel does about each import.

Imports are read from the fetched fixture binaries with `peinfo`, which uses
the kernel's own PE loader. Export states come from the kernel itself: the
boot test saves the `NK-EXPORT <module> <name> <state>` lines the kernel
prints. With no boot log yet, every import is "missing". The names drivers
looked up at run time (`MmGetSystemRoutineAddress`) and did not find come
from the same boot, as `NK-LOOKUP <name> absent` lines.

Usage: ledger.py [--check | --missing <binary>...]
  default    rewrite ledger/<arch>.json
  --check    fail if a committed ledger differs from what would be generated
             (fixtures that are not downloaded make the check a visible SKIP)
  --missing  print, by area, the kernel names the named corpus binaries
             import that the last x86-64 boot did not export as implemented
"""

import json
import re
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
# An import from another fixture, an export driver, that exports it.
LIBRARY = "library"


def kernel_exports(arch):
    """{(module, name): state} from the last boot test of this arch."""
    path = ROOT / "target" / "qemu" / f"exports-{arch}.txt"
    exports = {}
    if path.exists():
        for line in path.read_text().splitlines():
            _, module, name, state = line.split()
            exports[(module.lower(), name)] = state
    return exports, path.exists()


def looked_up_absent(lines):
    """The names in the kernel's `NK-LOOKUP <name> absent` lines, each once,
    sorted. No import table shows such a name: a driver asks for it by
    name while it runs and does without when the kernel has none."""
    names = set()
    for line in lines:
        words = line.split()
        if len(words) == 3 and words[0] == "NK-LOOKUP" and words[2] == "absent":
            names.add(words[1])
    return sorted(names)


def kernel_lookups(arch):
    path = ROOT / "target" / "qemu" / f"lookups-{arch}.txt"
    return looked_up_absent(path.read_text().splitlines()) if path.exists() else []


def peinfo(path):
    return subprocess.run([PEINFO, path], check=True, capture_output=True, text=True).stdout


def imports_of(path):
    return [line.split()[1:] for line in peinfo(path).splitlines() if line.startswith("import ")]


def exports_of(listing):
    """What an image exports, from peinfo's `export <ordinal> <name> ...`
    lines: every name, and every ordinal as `#<ordinal>`, which is how an
    import by ordinal is written."""
    exported = set()
    for line in listing.splitlines():
        words = line.split()
        if words[:1] == ["export"]:
            exported.add(f"#{words[1]}")
            if words[2] != "-":
                exported.add(words[2])
    return exported


def import_state(module, name, exports, libraries):
    """What NK does about an import of `module!name`: the state of the
    kernel's export of that name; or, for a module that is a fixture
    itself (`libraries`: {file name: what it exports}), "library" if it
    exports the name. Anything else is "missing"."""
    module = module.lower()
    if module in KERNEL_MODULES:
        # hal.dll only forwards to the kernel: one name space.
        return exports.get((module, name), exports.get((KERNEL_MODULES[0], name), "missing"))
    return LIBRARY if name in libraries.get(module, ()) else "missing"


KERNEL_MODULES = ("ntoskrnl.exe", "hal.dll")
CORPUS = ROOT / "ledger" / "corpus.x86_64.txt"
KERNEL = ROOT / "ledger" / "ntoskrnl.x86_64.txt"


def microsoft_kernel(exports, listing):
    """What Microsoft's kernel of the pinned build exports, and how much
    of it NK does. `listing` is the text of ledger/ntoskrnl.x86_64.txt
    (written by tools/corpus.py from the binary)."""
    names, forwarded, unnamed = set(), 0, 0
    for line in listing.splitlines():
        if line.startswith("#"):
            continue
        _, name, where = line.split()
        forwarded += where.startswith("forward:")
        if name == "-":
            unnamed += 1
        else:
            names.add(name)
    ours = {name for (module, name) in exports if module == KERNEL_MODULES[0]}
    return {
        "note": "the export directory of Microsoft's ntoskrnl.exe (fixtures/corpus.toml), "
                "which NK never loads, against the names NK exports",
        "names": len(names),
        "by_ordinal_only": unnamed,
        "forwarded": forwarded,
        "exported_by_nk": len(names & ours),
        "nk_names_it_lacks": sorted(ours - names),
    }


def missing(exports, lists, wanted):
    """{area: [names]} that the binaries in `wanted` import from the
    kernel and NK does not export as implemented. An area is a name's
    leading capitalised word (`Io`, `Rtl`); `other` holds the rest."""
    areas, seen = {}, set()
    for line in lists.splitlines():
        if line.startswith("#"):
            continue
        head, _, symbols = line.partition(":")
        file, _, module = head.split()
        if file not in wanted or module not in KERNEL_MODULES:
            continue
        seen.add(file)
        for name in symbols.split():
            state = next((exports[(m, name)] for m in KERNEL_MODULES if (m, name) in exports),
                         "missing")
            if state == "implemented":
                continue
            # `IoCreateDevice` is Io's; `ObfReferenceObject` is Ob's fast form.
            prefix = re.match(r"[A-Z][a-z]+", name)
            area = prefix.group().removesuffix("f") if prefix else "other"
            areas.setdefault(area, set()).add(name if state == "missing" else f"{name}({state})")
    return {area: sorted(names) for area, names in sorted(areas.items())}, sorted(seen)


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
        **({"microsoft_kernel": microsoft_kernel(exports, KERNEL.read_text())}
           if KERNEL.exists() else {}),
    }


def build(arch, fixtures):
    exports, booted = kernel_exports(arch)
    # A fixture is on the boot volume as <name>.sys, which is what an
    # importer's table calls it.
    libraries = {fx["name"].lower() + ".sys": exports_of(peinfo(CACHE / fx["file"]))
                 for fx in fixtures}
    entries, needed = [], {}
    for fx in fixtures:
        imports = []
        for module, name in imports_of(CACHE / fx["file"]):
            state = import_state(module, name, exports, libraries)
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
            **{s: sum(1 for v in needed.values() if v == s) for s in STATES + [LIBRARY]},
        },
        "looked_up_absent": {
            "note": "names MmGetSystemRoutineAddress was asked for during the boot test, by "
                    "the fixtures and by the kernel's own test of the routine, that the "
                    "kernel does not export; in no import table",
            "names": kernel_lookups(arch),
        },
        "fixtures": entries,
        # No source offers Windows 10 arm64 binaries, so only x86-64 has one.
        **({"corpus": corpus(exports, CORPUS.read_text())} if arch == "x86_64" else {}),
    }


def print_missing(wanted):
    exports, booted = kernel_exports("x86_64")
    if not booted:
        print("ledger: no boot log (run: make check)")
        return 1
    areas, seen = missing(exports, CORPUS.read_text(), {w.lower() for w in wanted})
    for name in sorted({w.lower() for w in wanted} - set(seen)):
        print(f"ledger: {name} is not in the corpus")
    total = sum(len(names) for names in areas.values())
    print(f"{', '.join(seen)}: {total} kernel names not implemented")
    for area, names in areas.items():
        print(f"  {area} ({len(names)}): {' '.join(names)}")
    return 0


def main():
    if sys.argv[1:2] == ["--missing"] and len(sys.argv) > 2:
        return print_missing(sys.argv[2:])
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
