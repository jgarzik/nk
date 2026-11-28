#!/usr/bin/env python3
"""Verify `kernel/svc/services.tsv` against the pinned `ntdll.dll`.

Reads the committed 471-entry NT system-service table (`kernel/svc/services.tsv`),
validates its structure, and — when `target/fixtures/ntdll.dll` (or an explicit
PE path) is present — parses every exported `Nt*`/`Zw*` syscall stub
(`4c 8b d1 b8 <imm32>`) and checks that every stub's number and name match the
table.

Exit codes:
  0  table valid (and matches `ntdll.dll` when present, or skipped if absent)
  1  validation or mismatch failure
"""

from __future__ import annotations

import struct
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DEFAULT_TSV = ROOT / "kernel" / "svc" / "services.tsv"
DEFAULT_NTDLL = ROOT / "target" / "fixtures" / "ntdll.dll"

# Windows 10 19045.2006 x86-64 NT service table size (0..=0x1d6).
EXPECTED_COUNT = 471
MAX_STACK_ARGS = 13
STUB_PREFIX = b"\x4c\x8b\xd1\xb8"  # mov r10, rcx; mov eax, imm32


def load_tsv(path: Path) -> list[tuple[int, str, int, bool]]:
    """Parse `services.tsv` into `(number, name, stack_args, has_ntdll_stub)`."""
    rows: list[tuple[int, str, int, bool]] = []
    for lineno, raw in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split("\t")
        if len(parts) != 4:
            raise ValueError(f"{path}:{lineno}: expected 4 tab-separated columns, got {len(parts)}")
        num = int(parts[0], 0)
        name = parts[1]
        stack_args = int(parts[2], 0)
        if parts[3] not in ("yes", "no"):
            raise ValueError(f"{path}:{lineno}: ntdll_stub must be 'yes' or 'no', got {parts[3]!r}")
        has_stub = parts[3] == "yes"
        rows.append((num, name, stack_args, has_stub))
    return rows


def validate_rows(rows: list[tuple[int, str, int, bool]]) -> None:
    """Validate structural invariants of the service table."""
    if len(rows) != EXPECTED_COUNT:
        raise ValueError(f"expected {EXPECTED_COUNT} services, got {len(rows)}")
    seen_names: set[str] = set()
    for expected_num, (num, name, stack_args, _has_stub) in enumerate(rows):
        if num != expected_num:
            raise ValueError(f"expected service number {expected_num}, got {num} ({name})")
        if not name.startswith("Nt") or not name.isascii() or not name.isalnum():
            raise ValueError(f"invalid service name {name!r} at #{num}")
        if name in seen_names:
            raise ValueError(f"duplicate service name {name!r} at #{num}")
        seen_names.add(name)
        if not (0 <= stack_args <= MAX_STACK_ARGS):
            raise ValueError(f"invalid stack_args {stack_args} for {name} (#{num})")


def parse_ntdll_stubs(data: bytes) -> dict[int, tuple[str, str]]:
    """Return `{number: (nt_name, zw_name)}` from a PE32+ `ntdll.dll` image."""
    if len(data) < 0x40 or data[:2] != b"MZ":
        raise ValueError("not a PE file (missing MZ)")
    pe = struct.unpack_from("<I", data, 0x3C)[0]
    if data[pe : pe + 4] != b"PE\0\0":
        raise ValueError("not a PE file (missing PE signature)")
    nsects = struct.unpack_from("<H", data, pe + 6)[0]
    opt_size = struct.unpack_from("<H", data, pe + 20)[0]
    opt = pe + 24
    magic = struct.unpack_from("<H", data, opt)[0]
    if magic != 0x20B:
        raise ValueError(f"expected PE32+ (0x20b), got {magic:#x}")
    exp_rva, exp_size = struct.unpack_from("<II", data, opt + 112)
    if exp_rva == 0 or exp_size == 0:
        raise ValueError("PE image has no export directory")

    sects: list[tuple[int, int, int]] = []
    sec_off = opt + opt_size
    for i in range(nsects):
        vsize, va, rsize, roff = struct.unpack_from("<IIII", data, sec_off + i * 40 + 8)
        sects.append((va, max(vsize, rsize), roff))

    def rva_to_off(rva: int) -> int | None:
        for va, span, roff in sects:
            if va <= rva < va + span:
                off = roff + (rva - va)
                return off if off < len(data) else None
        return None

    def read_cstr(rva: int) -> str:
        off = rva_to_off(rva)
        if off is None:
            raise ValueError(f"unmapped RVA {rva:#x}")
        end = data.index(b"\0", off)
        return data[off:end].decode("ascii")

    exp_off = rva_to_off(exp_rva)
    if exp_off is None:
        raise ValueError(f"export directory RVA {exp_rva:#x} unmapped")
    num_funcs, num_names, funcs_rva, names_rva, ords_rva = struct.unpack_from(
        "<IIIII", data, exp_off + 20
    )
    funcs_off = rva_to_off(funcs_rva)
    names_off = rva_to_off(names_rva)
    ords_off = rva_to_off(ords_rva)
    if funcs_off is None or names_off is None or ords_off is None:
        raise ValueError("export tables unmapped")

    nt_by_num: dict[int, str] = {}
    zw_by_num: dict[int, str] = {}
    for i in range(num_names):
        name_rva = struct.unpack_from("<I", data, names_off + 4 * i)[0]
        ord_idx = struct.unpack_from("<H", data, ords_off + 2 * i)[0]
        if ord_idx >= num_funcs:
            continue
        fn_rva = struct.unpack_from("<I", data, funcs_off + 4 * ord_idx)[0]
        if exp_rva <= fn_rva < exp_rva + exp_size:
            continue  # forwarder
        fn_off = rva_to_off(fn_rva)
        if fn_off is None or fn_off + 8 > len(data):
            continue
        if data[fn_off : fn_off + 4] != STUB_PREFIX:
            continue
        num = struct.unpack_from("<I", data, fn_off + 4)[0]
        name = read_cstr(name_rva)
        if name.startswith("Nt"):
            nt_by_num[num] = name
        elif name.startswith("Zw"):
            zw_by_num[num] = name

    out: dict[int, tuple[str, str]] = {}
    for num in sorted(set(nt_by_num) | set(zw_by_num)):
        nt_name = nt_by_num.get(num, "")
        zw_name = zw_by_num.get(num, "")
        if not nt_name or not zw_name or nt_name[2:] != zw_name[2:]:
            raise ValueError(f"mismatched Nt/Zw pair for #{num}: {nt_name!r} vs {zw_name!r}")
        out[num] = (nt_name, zw_name)
    return out


def verify_against_ntdll(
    rows: list[tuple[int, str, int, bool]], ntdll_path: Path
) -> bool:
    """Compare `rows` against `ntdll_path`. Returns False if `ntdll_path` is absent."""
    if not ntdll_path.is_file():
        return False
    stubs = parse_ntdll_stubs(ntdll_path.read_bytes())
    expected_stubs = {num: name for num, name, _sargs, has_stub in rows if has_stub}
    actual_stubs = {num: nt_name for num, (nt_name, _zw_name) in stubs.items()}
    if expected_stubs != actual_stubs:
        missing = sorted(set(expected_stubs) - set(actual_stubs))
        extra = sorted(set(actual_stubs) - set(expected_stubs))
        diff = [
            (n, expected_stubs[n], actual_stubs[n])
            for n in sorted(set(expected_stubs) & set(actual_stubs))
            if expected_stubs[n] != actual_stubs[n]
        ]
        raise ValueError(
            f"services.tsv vs {ntdll_path} mismatch: "
            f"missing={missing[:5]}, extra={extra[:5]}, diff={diff[:5]}"
        )
    return True


def main(argv: list[str]) -> int:
    tsv_path = Path(argv[1]) if len(argv) > 1 else DEFAULT_TSV
    ntdll_path = Path(argv[2]) if len(argv) > 2 else DEFAULT_NTDLL
    try:
        rows = load_tsv(tsv_path)
        validate_rows(rows)
        if verify_against_ntdll(rows, ntdll_path):
            print(f"svctable: {len(rows)} services verified against {ntdll_path.name}")
        else:
            print(f"svctable: {len(rows)} services structurally valid (SKIP: {ntdll_path} absent)")
    except Exception as exc:
        print(f"svctable: ERROR: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
