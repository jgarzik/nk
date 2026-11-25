#!/usr/bin/env python3
"""Which code of the kernel image has no unwind entry, and may it?

A stack walk needs a `.pdata` entry for every function that makes a call
(doc/DESIGN.md, "Unwind tables"). This reads the built kernel image and
its link map, finds every code symbol whose address no `.pdata` entry
covers, and holds them to tools/unwind/<arch>.txt:

    lib <name>      <why>   a library whose code may be uncovered
    sym <name>      <why>   one symbol of NK's own that may be

Usage: unwind_coverage.py [arch...]   (default: both; `make unwind-check`)

An uncovered symbol passes if it is

- in a listed library: the prebuilt `core`, `alloc` and
  `compiler_builtins`, which Rust ships without tables. They are allowed
  whole, because which of their functions a build links in changes with
  unrelated code and with the compiler's version;
- a Rust function compiled with NK (a mangled name in an object that is
  not a listed library): the compiler gives every function that uses the
  stack an entry, so one without is a leaf;
- a listed symbol: assembly, which the compiler does not check.

Anything else fails, and so does a listed library or symbol that no
longer has uncovered code: the list says what is, not what was.
"""

import re
import struct
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
TARGETS = {"x86_64": "x86_64-unknown-uefi", "aarch64": "aarch64-unknown-uefi"}
MACHINE_AMD64, MACHINE_ARM64 = 0x8664, 0xAA64
SCN_MEM_EXECUTE = 0x2000_0000
DIR_EXCEPTION = 3


class Image:
    """The parts of a PE32+ file this needs."""

    def __init__(self, data):
        self.data = data
        pe = struct.unpack_from("<I", data, 0x3C)[0]
        if data[:2] != b"MZ" or data[pe:pe + 4] != b"PE\0\0":
            raise ValueError("not a PE image")
        self.machine, nsections = struct.unpack_from("<HH", data, pe + 4)
        opt_size = struct.unpack_from("<H", data, pe + 20)[0]
        opt = pe + 24
        self.pdata = struct.unpack_from("<II", data, opt + 112 + 8 * DIR_EXCEPTION)
        self.sections = []
        for i in range(nsections):
            at = opt + opt_size + 40 * i
            vsize, rva, raw_size, raw_off = struct.unpack_from("<IIII", data, at + 8)
            flags = struct.unpack_from("<I", data, at + 36)[0]
            self.sections.append((rva, vsize, raw_off, raw_size, flags))

    def at(self, rva, fmt):
        """Unpack `fmt` from the image at `rva`."""
        for start, _, raw_off, raw_size, _ in self.sections:
            if start <= rva < start + raw_size:
                return struct.unpack_from(fmt, self.data, raw_off + rva - start)
        raise ValueError(f"rva {rva:#x} is in no section's data")

    def code(self):
        """The (start, end) RVA ranges of the executable sections."""
        return [(rva, rva + vsize) for rva, vsize, _, _, flags in self.sections
                if flags & SCN_MEM_EXECUTE]

    def covered(self):
        """The (start, end) RVA ranges that `.pdata` entries describe."""
        rva, size = self.pdata
        ranges = []
        if self.machine == MACHINE_AMD64:
            for at in range(rva, rva + size, 12):
                begin, end, _ = self.at(at, "<III")
                ranges.append((begin, end))
        elif self.machine == MACHINE_ARM64:
            for at in range(rva, rva + size, 8):
                begin, word = self.at(at, "<II")
                if word & 3:
                    # Packed unwind data: the length is in instructions.
                    length = ((word >> 2) & 0x7FF) * 4
                else:
                    length = (self.at(word, "<I")[0] & 0x3FFFF) * 4
                ranges.append((begin, begin + length))
        else:
            raise ValueError(f"machine {self.machine:#x}")
        return ranges


SYMBOL = re.compile(r"^ [0-9a-f]{4}:[0-9a-f]{8}\s+(\S+)\s+([0-9a-f]{16})\s+(?:\S\s+)*?(\S+)$")
BASE = re.compile(r"Preferred load address is ([0-9a-fA-F]+)")


def origin(obj):
    """The library or crate an object file of the link map belongs to:
    `libcore-<hash>.rlib:core-...o` gives `core`, `nkkrnl.nkkrnl...o`
    gives `nkkrnl`."""
    if ":" in obj:
        lib = obj.split(":")[0].rsplit("/", 1)[-1].rsplit("\\", 1)[-1]
        lib = re.sub(r"\.rlib$", "", lib)
        return re.sub(r"-[0-9a-f]+$", "", lib).removeprefix("lib")
    return obj.split(".")[0]


def symbols(map_text):
    """`[(rva, name, origin)]` of the symbols in a link map, by address."""
    base = int(BASE.search(map_text).group(1), 16)
    found = []
    for line in map_text.splitlines():
        m = SYMBOL.match(line)
        if m and not m.group(3).startswith("<"):
            found.append((int(m.group(2), 16) - base, m.group(1), origin(m.group(3))))
    return sorted(found)


def uncovered(syms, code, covered):
    """`[(name, origin, bytes)]`: the code symbols whose address no
    covered range holds. A symbol runs to the next address that has one,
    or to the end of its section; names at one address are one symbol,
    reported under each name."""
    covered = sorted(covered)
    starts = [start for start, _ in covered]
    out = []
    for start, end in code:
        here = [s for s in syms if start <= s[0] < end]
        addresses = sorted({s[0] for s in here}) + [end]
        following = dict(zip(addresses, addresses[1:]))
        for rva, name, lib in here:
            # The last covered range starting at or below the symbol.
            lo, hi = 0, len(starts)
            while lo < hi:
                mid = (lo + hi) // 2
                if starts[mid] <= rva:
                    lo = mid + 1
                else:
                    hi = mid
            if lo == 0 or rva >= covered[lo - 1][1]:
                out.append((name, lib, following[rva] - rva))
    return out


def mangled(name):
    """Whether `name` is a Rust function's symbol, not an assembly label
    or an unmangled export."""
    return name.startswith(("_R", "_ZN"))


def read_allowed(text):
    """`(libraries, symbols)` named by a golden list."""
    libs, syms = set(), set()
    for line in text.splitlines():
        if line.strip() and not line.startswith("#"):
            kind, name = line.split()[:2]
            {"lib": libs, "sym": syms}[kind].add(name)
    return libs, syms


def judge(found, libs, syms):
    """Problems, as text lines, of the uncovered symbols `found` against
    the allowed libraries and symbols; empty if there are none."""
    problems = []
    seen_libs, seen_syms = set(), set()
    for name, lib, size in found:
        if lib in libs:
            seen_libs.add(lib)
        elif name in syms:
            seen_syms.add(name)
        elif not mangled(name):
            problems.append(f"{name} ({lib}, {size} bytes) has no unwind entry and is not listed")
    problems += [f"library {lib} is listed but has no uncovered code" for lib in sorted(libs - seen_libs)]
    problems += [f"symbol {name} is listed but is covered or gone" for name in sorted(syms - seen_syms)]
    return problems


def summary(found, libs):
    """One line per origin: how many uncovered symbols and bytes."""
    totals = {}
    for name, lib, size in found:
        kind = lib if lib in libs else ("NK leaf functions" if mangled(name) else "NK assembly")
        count, total = totals.get(kind, (0, 0))
        totals[kind] = (count + 1, total + size)
    return [f"  {kind}: {count} symbols, {total} bytes"
            for kind, (count, total) in sorted(totals.items())]


def check(arch):
    build = ROOT / "target" / TARGETS[arch] / "release"
    image = Image((build / "nkkrnl.efi").read_bytes())
    syms = symbols((build / "nkkrnl.map").read_text())
    found = uncovered(syms, image.code(), image.covered())
    libs, allowed = read_allowed((ROOT / "tools" / "unwind" / f"{arch}.txt").read_text())
    print(f"unwind coverage {arch}: code without an unwind entry")
    print("\n".join(summary(found, libs)))
    problems = judge(found, libs, allowed)
    for problem in problems:
        print(f"unwind coverage {arch}: {problem}")
    return not problems


def main():
    ok = all([check(arch) for arch in sys.argv[1:] or list(TARGETS)])
    print("unwind coverage: " + ("ok" if ok else "FAILED (tools/unwind/<arch>.txt)"))
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
