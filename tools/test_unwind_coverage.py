"""Unit tests for tools/unwind_coverage.py. Run by `make test`."""

import struct
import unittest

import unwind_coverage as uc

MAP = """\
 nkkrnl

 Timestamp is 6b07638f (Wed Nov 25 22:39:11 2026)

 Preferred load address is 0000000140000000

 Start         Length     Name                   Class
 0001:00000000 00000400H .text                   CODE
 0002:00000000 00000100H .rdata                  DATA

  Address         Publics by Value              Rva+Base               Lib:Object

 0000:00000000       __guard_flags              0000000000000000     <absolute>
 0001:00000000       nk_entry                   0000000140001000     nkkrnl.nkkrnl.6f0b-cgu.00.rcgu.o
 0001:00000100       _RNvNtCs9x_6nkkrnl2ke4leaf 0000000140001100     nkkrnl.nkkrnl.6f0b-cgu.00.rcgu.o
 0001:00000200       memcpy                     0000000140001200     libcompiler_builtins-cfa80c7f:compiler_builtins-cfa8.cgu.092.rcgu.o
 0001:00000200       .weak.memcpy.default       0000000140001200     libcompiler_builtins-cfa80c7f:compiler_builtins-cfa8.cgu.092.rcgu.o
 0002:00000000       nk_ap_trampoline           0000000140002000     nkkrnl.nkkrnl.6f0b-cgu.00.rcgu.o

 entry point at         0001:00000000

 Static symbols

 0001:00000300       nk_stub                    0000000140001300 f   nkkrnl.nkkrnl.6f0b-cgu.00.rcgu.o
 0001:00000180       _ZN4core3fmt5write17h0123E 0000000140001180 f   libcore-0a1b2c3d:core-0a1b.core.9e7e-cgu.1.rcgu.o
"""


def image(machine, pdata, entries):
    """A PE32+ file with a `.text` at RVA 0x1000 and `pdata` as the
    contents of its `.pdata` section at RVA 0x2000, of which the first
    `entries` bytes are the exception directory."""
    headers = bytearray(0x400)
    headers[:2] = b"MZ"
    struct.pack_into("<I", headers, 0x3C, 0x80)
    headers[0x80:0x84] = b"PE\0\0"
    struct.pack_into("<HH", headers, 0x84, machine, 2)
    struct.pack_into("<H", headers, 0x94, 240)
    opt = 0x98
    struct.pack_into("<H", headers, opt, 0x20B)
    struct.pack_into("<II", headers, opt + 112 + 8 * 3, 0x2000, entries)
    sections = opt + 240
    struct.pack_into("<8sIIII", headers, sections, b".text", 0x400, 0x1000, 0x400, 0x400)
    struct.pack_into("<I", headers, sections + 36, 0x6000_0020)
    struct.pack_into("<8sIIII", headers, sections + 40, b".pdata", 0x200, 0x2000, 0x200, 0x800)
    struct.pack_into("<I", headers, sections + 76, 0x4000_0040)
    return bytes(headers) + bytes(0x400) + pdata.ljust(0x200, b"\0")


class LinkMap(unittest.TestCase):
    def test_symbols_have_an_rva_and_an_origin(self):
        self.assertEqual(uc.symbols(MAP), [
            (0x1000, "nk_entry", "nkkrnl"),
            (0x1100, "_RNvNtCs9x_6nkkrnl2ke4leaf", "nkkrnl"),
            (0x1180, "_ZN4core3fmt5write17h0123E", "core"),
            (0x1200, ".weak.memcpy.default", "compiler_builtins"),
            (0x1200, "memcpy", "compiler_builtins"),
            (0x1300, "nk_stub", "nkkrnl"),
            (0x2000, "nk_ap_trampoline", "nkkrnl"),
        ])

    def test_an_object_names_its_library_or_crate(self):
        self.assertEqual(uc.origin("nkkrnl.nkkrnl.6f0b-cgu.13.rcgu.o"), "nkkrnl")
        self.assertEqual(uc.origin("libnk_mm-0123abcd.rlib:nk_mm-0123.nk_mm.1-cgu.0.rcgu.o"), "nk_mm")
        self.assertEqual(uc.origin("/x/y/liballoc-0123abcd.rlib:alloc-0123.o"), "alloc")


class Coverage(unittest.TestCase):
    def test_x64_entries_cover_begin_to_end(self):
        pdata = struct.pack("<III", 0x1000, 0x1080, 0) + struct.pack("<III", 0x1300, 0x1310, 0)
        img = uc.Image(image(uc.MACHINE_AMD64, pdata, len(pdata)))
        self.assertEqual(img.code(), [(0x1000, 0x1400)])
        self.assertEqual(img.covered(), [(0x1000, 0x1080), (0x1300, 0x1310)])

    def test_arm64_entries_take_their_length_from_the_unwind_data(self):
        # Packed: 0x20 instructions. Then one whose record, at RVA
        # 0x2100, says 0x10 instructions.
        pdata = struct.pack("<II", 0x1000, 1 | 0x20 << 2) + struct.pack("<II", 0x1300, 0x2100)
        section = pdata.ljust(0x100, b"\0") + struct.pack("<I", 0x10)
        img = uc.Image(image(uc.MACHINE_ARM64, section, len(pdata)))
        self.assertEqual(img.covered(), [(0x1000, 0x1080), (0x1300, 0x1340)])

    def test_a_symbol_is_uncovered_if_no_entry_holds_its_address(self):
        syms = uc.symbols(MAP)
        found = uc.uncovered(syms, [(0x1000, 0x1400)], [(0x1000, 0x1080), (0x1300, 0x1310)])
        # nk_entry and nk_stub are covered; data symbols are not code.
        # Each runs to the next symbol.
        self.assertEqual(found, [
            ("_RNvNtCs9x_6nkkrnl2ke4leaf", "nkkrnl", 0x80),
            ("_ZN4core3fmt5write17h0123E", "core", 0x80),
            (".weak.memcpy.default", "compiler_builtins", 0x100),
            ("memcpy", "compiler_builtins", 0x100),
        ])
        # With no entries the last symbol runs to the end of the section.
        self.assertEqual(uc.uncovered(syms, [(0x1000, 0x1400)], [])[-1], ("nk_stub", "nkkrnl", 0x100))


class Judge(unittest.TestCase):
    LIBS = {"core", "compiler_builtins"}
    FOUND = [
        ("_RNvNtCs9x_6nkkrnl2ke4leaf", "nkkrnl", 0x80),
        ("_ZN4core3fmt5write17h0123E", "core", 0x80),
        ("memcpy", "compiler_builtins", 0x100),
        ("nk_vectors", "nkkrnl", 0x800),
    ]

    def test_the_golden_list_names_libraries_and_symbols(self):
        text = "# comment\nlib core\tprebuilt\n\nsym nk_vectors\texception entry\n"
        self.assertEqual(uc.read_allowed(text), ({"core"}, {"nk_vectors"}))

    def test_listed_libraries_listed_symbols_and_rust_leaves_pass(self):
        self.assertEqual(uc.judge(self.FOUND, self.LIBS, {"nk_vectors"}), [])

    def test_unlisted_assembly_fails(self):
        problems = uc.judge(self.FOUND, self.LIBS, set())
        self.assertEqual(len(problems), 1)
        self.assertIn("nk_vectors", problems[0])

    def test_an_unlisted_library_s_unmangled_symbol_fails(self):
        problems = uc.judge(self.FOUND, {"core"}, {"nk_vectors"})
        self.assertEqual(len(problems), 1)
        self.assertIn("memcpy", problems[0])

    def test_a_stale_entry_fails(self):
        problems = uc.judge(self.FOUND, self.LIBS | {"alloc"}, {"nk_vectors", "nk_gone"})
        self.assertEqual(len(problems), 2)
        self.assertIn("alloc", problems[0])
        self.assertIn("nk_gone", problems[1])

    def test_the_summary_counts_by_origin(self):
        self.assertEqual(uc.summary(self.FOUND, self.LIBS), [
            "  NK assembly: 1 symbols, 2048 bytes",
            "  NK leaf functions: 1 symbols, 128 bytes",
            "  compiler_builtins: 1 symbols, 256 bytes",
            "  core: 1 symbols, 128 bytes",
        ])


if __name__ == "__main__":
    unittest.main()
