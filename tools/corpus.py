#!/usr/bin/env python3
"""The corpus: Microsoft's own kernel-mode binaries of the pinned build.

NK's destination is to run these unmodified, so what they import is the
measure of how far there is to go. The ledger counts it.

Usage:
  corpus.py resolve <file>...   look the files up for the pinned build and
                                add them to fixtures/corpus.toml (network)
  corpus.py kernel              look up Microsoft's kernel of the pinned
                                build and pin it as `[kernel]` (network)
  corpus.py imports             download the corpus and write its import
                                lists to ledger/corpus.x86_64.txt, and the
                                kernel's exports to ledger/ntoskrnl.x86_64.txt
  corpus.py check               as `imports`, but compare with the files

`[kernel]` is Microsoft's `ntoskrnl.exe` itself. NK never loads or runs
it: its export directory is the measure of what a kernel of this build
offers (names, ordinals, forwarders).

fixtures/corpus.toml pins each binary by URL and SHA-256, like the driver
fixtures. The binaries are downloaded to $NK_CACHE/corpus (default
~/.cache/nk), never committed. What is committed is the list of names each
one imports: that is all the ledger needs, so the gate and CI never fetch
the corpus. `make corpus` runs `check`.

`resolve` asks Winbindex (https://winbindex.m417z.com) which build of a
file belongs to Windows 10 22H2 as first released, the build of NK's
reference Windows, and takes the file itself from Microsoft's symbol
server. x86-64 only: no index or server offers Windows 10 arm64 files.
"""

import gzip
import hashlib
import json
import os
import subprocess
import sys
import tomllib
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
MANIFEST = ROOT / "fixtures" / "corpus.toml"
IMPORTS = ROOT / "ledger" / "corpus.x86_64.txt"
EXPORTS = ROOT / "ledger" / "ntoskrnl.x86_64.txt"
CACHE = Path(os.environ.get("NK_CACHE", Path.home() / ".cache" / "nk")) / "corpus"
PEINFO = ROOT / "target" / "debug" / "peinfo"
INDEX = "https://winbindex.m417z.com/data/by_filename_compressed/{}.json.gz"
SERVER = "https://msdl.microsoft.com/download/symbols/{0}/{1:08X}{2:x}/{0}"
AMD64 = 0x8664
HEADER = """\
# Microsoft's kernel-mode binaries of the pinned build, Windows 10 22H2
# 19045.2006 (x86-64): the drivers and libraries NK means to run unmodified.
# Not fixtures of any test: nothing loads them yet. tools/corpus.py reads
# their import tables for the ledger. Maintained by `tools/corpus.py
# resolve`; the SHA-256 is of the bytes Microsoft's symbol server serves.
"""


def get(url, agent):
    request = urllib.request.Request(url, headers={"User-Agent": agent})
    with urllib.request.urlopen(request, timeout=120) as response:
        return response.read()


def manifest():
    return tomllib.loads(MANIFEST.read_text()) if MANIFEST.exists() else {}


def load():
    return manifest().get("binary", [])


def kernel():
    """The pinned `ntoskrnl.exe`, or None if it is not pinned."""
    return manifest().get("kernel")


def entry(table, b):
    return (f'\n{table}\nfile = "{b["file"]}"\nversion = "{b["version"]}"\n'
            f'url = "{b["url"]}"\nsha256 = "{b["sha256"]}"\n')


def save(binaries, kernel):
    text = HEADER
    if kernel:
        text += ("\n# Microsoft's kernel of the pinned build. Never loaded: its export\n"
                 "# directory is what the ledger measures NK's exports against.\n"
                 + entry("[kernel]", kernel)[1:])
    for b in sorted(binaries, key=lambda b: b["file"]):
        text += entry("[[binary]]", b)
    MANIFEST.write_text(text)


def look_up(name):
    """The pin of `name` as Windows 10 22H2 first shipped it, fetched
    into the cache; None if the index does not name exactly one."""
    index = json.loads(gzip.decompress(get(INDEX.format(name), "nk-corpus")))
    found = [e["fileInfo"] for e in index.values()
             if "BASE" in e.get("windowsVersions", {}).get("22H2", {})
             and e.get("fileInfo", {}).get("machineType") == AMD64]
    if len(found) != 1:
        print(f"{name}: {len(found)} candidates for 22H2 as released; skipped")
        return None
    info = found[0]
    url = SERVER.format(name, info["timestamp"], info["virtualSize"])
    data = get(url, "Microsoft-Symbol-Server/10.0.0.0")
    CACHE.mkdir(parents=True, exist_ok=True)
    (CACHE / name).write_bytes(data)
    pin = {"file": name, "version": info["version"].split()[0], "url": url,
           "sha256": hashlib.sha256(data).hexdigest()}
    print(f"{name}: {pin['version']}")
    return pin


def resolve(names):
    binaries = {b["file"]: b for b in load()}
    for name in names:
        pin = look_up(name.lower())
        if pin:
            binaries[pin["file"]] = pin
    save(binaries.values(), kernel())


def resolve_kernel():
    pin = look_up("ntoskrnl.exe")
    if pin:
        save(load(), pin)


def fetch(binary):
    """The binary's bytes, from the cache or the symbol server, verified."""
    path = CACHE / binary["file"]
    if path.exists() and hashlib.sha256(path.read_bytes()).hexdigest() == binary["sha256"]:
        return path
    data = get(binary["url"], "Microsoft-Symbol-Server/10.0.0.0")
    if hashlib.sha256(data).hexdigest() != binary["sha256"]:
        sys.exit(f"corpus: {binary['file']}: SHA-256 mismatch")
    CACHE.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)
    return path


def imports_text():
    """One line per (binary, module it imports from): the symbols, sorted.
    An import by ordinal reads `#<n>`."""
    subprocess.run(["cargo", "build", "-q", "-p", "peinfo"], check=True, cwd=ROOT)
    lines = ["# What each binary of fixtures/corpus.toml imports. Generated by",
             "# tools/corpus.py from the binaries themselves; do not edit.",
             "# <binary> <version> <module>: <symbol> ..."]
    for binary in sorted(load(), key=lambda b: b["file"]):
        out = subprocess.run([PEINFO, fetch(binary)], check=True, capture_output=True,
                             text=True).stdout
        by_module = {}
        for line in out.splitlines():
            if line.startswith("import "):
                _, module, symbol = line.split()
                by_module.setdefault(module.lower(), set()).add(symbol)
        if not by_module:
            lines.append(f"{binary['file']} {binary['version']} -:")
        for module in sorted(by_module):
            symbols = " ".join(sorted(by_module[module]))
            lines.append(f"{binary['file']} {binary['version']} {module}: {symbols}")
    return "\n".join(lines) + "\n"


def exports_text():
    """One line per export of the pinned kernel, by ordinal: its name
    (`-` if it has none) and `code` or `forward:<target>`."""
    subprocess.run(["cargo", "build", "-q", "-p", "peinfo"], check=True, cwd=ROOT)
    pin = kernel()
    out = subprocess.run([PEINFO, fetch(pin)], check=True, capture_output=True,
                         text=True).stdout
    lines = [f"# What {pin['file']} {pin['version']} of fixtures/corpus.toml exports.",
             "# Generated by tools/corpus.py from the binary itself; do not edit.",
             "# <ordinal> <name> code|forward:<target>"]
    for line in out.splitlines():
        if line.startswith("export "):
            _, ordinal, name, where = line.split()
            kind, _, target = where.partition("=")
            lines.append(f"{ordinal} {name} " + ("code" if kind == "rva" else f"forward:{target}"))
    return "\n".join(lines) + "\n"


def main():
    args = sys.argv[1:]
    if args[:1] == ["resolve"] and len(args) > 1:
        resolve(args[1:])
        return 0
    if args == ["kernel"]:
        resolve_kernel()
        return 0
    lists = [(IMPORTS, imports_text)] + ([(EXPORTS, exports_text)] if kernel() else [])
    if args == ["imports"]:
        for path, text in lists:
            path.write_text(text())
            print(f"wrote {path.relative_to(ROOT)}")
        return 0
    if args == ["check"]:
        for path, text in lists:
            if not path.exists() or path.read_text() != text():
                print(f"corpus: {path.relative_to(ROOT)} is not what the binaries say "
                      "(run: tools/corpus.py imports)")
                return 1
        print(f"corpus: the lists match {len(load())} binaries"
              + (" and the kernel" if kernel() else ""))
        return 0
    sys.exit(__doc__)


if __name__ == "__main__":
    sys.exit(main())
