"""Host unit tests for `tools/svctable.py` and `kernel/svc/services.tsv`."""

from __future__ import annotations

import struct
import unittest
from pathlib import Path

import svctable


def build_tiny_pe(exports: list[tuple[str, bytes]]) -> bytes:
    """Build a minimal PE32+ image with one `.text` section holding `exports`."""
    pe_off = 0x80
    opt_size = 0xF0
    sec_off = pe_off + 24 + opt_size
    raw_off = 0x200
    sec_rva = 0x1000

    # Lay out stub code, then strings, then export tables inside the section.
    sec = bytearray()
    code_rvas: list[int] = []
    for _name, code in exports:
        code_rvas.append(sec_rva + len(sec))
        sec.extend(code)
        while len(sec) % 16:
            sec.append(0x90)

    name_rvas: list[int] = []
    for name, _code in exports:
        name_rvas.append(sec_rva + len(sec))
        sec.extend(name.encode("ascii") + b"\0")
    while len(sec) % 4:
        sec.append(0)

    exp_dir_rva = sec_rva + len(sec)
    n = len(exports)
    funcs_rva = exp_dir_rva + 40
    names_rva = funcs_rva + 4 * n
    ords_rva = names_rva + 4 * n
    sec.extend(
        struct.pack(
            "<IIIIIIIIII",
            0, 0, 0, 0, 1,
            n, n,
            funcs_rva, names_rva, ords_rva,
        )
    )
    for rva in code_rvas:
        sec.extend(struct.pack("<I", rva))
    for rva in name_rvas:
        sec.extend(struct.pack("<I", rva))
    for i in range(n):
        sec.extend(struct.pack("<H", i))
    exp_size = sec_rva + len(sec) - exp_dir_rva

    img = bytearray(raw_off + len(sec))
    img[0:2] = b"MZ"
    struct.pack_into("<I", img, 0x3C, pe_off)
    img[pe_off : pe_off + 4] = b"PE\0\0"
    struct.pack_into("<HH", img, pe_off + 4, 0x8664, 1)
    struct.pack_into("<H", img, pe_off + 20, opt_size)
    opt = pe_off + 24
    struct.pack_into("<H", img, opt, 0x20B)
    struct.pack_into("<II", img, opt + 112, exp_dir_rva, exp_size)
    img[sec_off : sec_off + 8] = b".text\0\0\0"
    struct.pack_into("<IIII", img, sec_off + 8, len(sec), sec_rva, len(sec), raw_off)
    img[raw_off:] = sec
    return bytes(img)


class SvcTableTests(unittest.TestCase):
    def test_committed_table_is_valid(self) -> None:
        rows = svctable.load_tsv(svctable.DEFAULT_TSV)
        svctable.validate_rows(rows)
        by_name = {name: (num, sargs, has_stub) for num, name, sargs, has_stub in rows}
        self.assertEqual(by_name["NtAccessCheck"], (0x0, 4, True))
        self.assertEqual(by_name["NtClose"], (0xF, 0, True))
        self.assertEqual(by_name["NtCreateFile"], (0x55, 7, True))
        self.assertEqual(by_name["NtQuerySystemTime"], (0x5A, 0, False))
        self.assertEqual(by_name["NtContinueEx"], (0xA1, 0, True))
        self.assertEqual(by_name["NtLoadKey3"], (0x1D6, 4, True))

    def test_parse_ntdll_stubs(self) -> None:
        stub_f = svctable.STUB_PREFIX + struct.pack("<I", 0xF) + b"\x0f\x05\xc3"
        stub_18 = svctable.STUB_PREFIX + struct.pack("<I", 0x18) + b"\x0f\x05\xc3"
        non_stub = b"\x48\x8b\x05\x00\x00\x00\x00\xc3"
        pe = build_tiny_pe(
            [
                ("NtAllocateVirtualMemory", stub_18),
                ("NtClose", stub_f),
                ("NtQuerySystemTime", non_stub),
                ("RtlInitUnicodeString", non_stub),
                ("ZwAllocateVirtualMemory", stub_18),
                ("ZwClose", stub_f),
            ]
        )
        stubs = svctable.parse_ntdll_stubs(pe)
        self.assertEqual(
            stubs,
            {
                0xF: ("NtClose", "ZwClose"),
                0x18: ("NtAllocateVirtualMemory", "ZwAllocateVirtualMemory"),
            },
        )

    def test_committed_table_matches_fixture_when_present(self) -> None:
        rows = svctable.load_tsv(svctable.DEFAULT_TSV)
        # Verify against target/fixtures/ntdll.dll when staged (SKIP otherwise).
        svctable.verify_against_ntdll(rows, svctable.DEFAULT_NTDLL)
        # Also verify against local research cache if present on developer host.
        cached = Path.home() / ".cache" / "nk" / "plan" / "fixtures" / "ntdll.dll"
        if cached.is_file():
            self.assertTrue(svctable.verify_against_ntdll(rows, cached))


if __name__ == "__main__":
    unittest.main()
