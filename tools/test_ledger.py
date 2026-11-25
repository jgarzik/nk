"""Unit tests for the corpus arithmetic of tools/ledger.py. Run by `make test`."""

import unittest

import ledger

LISTS = """\
# comment
a.sys 10.0.1 ntoskrnl.exe: #4 IoCreateDevice KeSetEvent ZwClose
a.sys 10.0.1 hal.dll: KeStallExecutionProcessor
a.sys 10.0.1 wmilib.sys: WmiCompleteRequest WmiSystemControl
b.sys 10.0.2 ntoskrnl.exe: IoCreateDevice KeStallExecutionProcessor ProbeForRead
c.sys 10.0.3 storport.sys: StorPortInitialize
d.sys 10.0.4 -:
"""
EXPORTS = {
    ("ntoskrnl.exe", "IoCreateDevice"): "implemented",
    ("ntoskrnl.exe", "ProbeForRead"): "partial",
    ("ntoskrnl.exe", "ZwClose"): "traps",
    # Exported under the kernel's name, imported by a.sys from hal.dll.
    ("ntoskrnl.exe", "KeStallExecutionProcessor"): "implemented",
}


class Corpus(unittest.TestCase):
    def setUp(self):
        self.corpus = ledger.corpus(EXPORTS, LISTS)
        self.by_file = {b["file"]: b for b in self.corpus["by_binary"]}

    def test_union_counts_each_name_once(self):
        self.assertEqual(self.corpus["binaries"], 4)
        self.assertEqual(self.corpus["kernel_names"],
                         {"total": 6, "implemented": 2, "partial": 1, "traps": 1, "missing": 2})

    def test_per_binary_counts(self):
        a = self.by_file["a.sys"]
        self.assertEqual(a["version"], "10.0.1")
        self.assertEqual(a["kernel"],
                         {"total": 5, "implemented": 2, "partial": 0, "traps": 1, "missing": 2})
        self.assertEqual(a["by_ordinal"], 1)
        self.assertEqual(a["other_modules"], {"wmilib.sys": 2})

    def test_hal_and_kernel_are_one_name_space(self):
        # b.sys imports from ntoskrnl.exe the name a.sys imports from hal.dll.
        self.assertEqual(self.by_file["b.sys"]["kernel"]["implemented"], 2)

    def test_binaries_that_import_nothing_from_the_kernel(self):
        self.assertEqual(self.by_file["c.sys"]["kernel"]["total"], 0)
        self.assertEqual(self.by_file["c.sys"]["other_modules"], {"storport.sys": 1})
        self.assertEqual(self.by_file["d.sys"]["other_modules"], {})


KERNEL = """\
# comment
1 - code
2 IoCreateDevice code
3 KeSetEvent code
4 KeStallExecutionProcessor forward:HAL.KeStallExecutionProcessor
5 ZwClose code
"""


class MicrosoftKernel(unittest.TestCase):
    def test_counts(self):
        exports = dict(EXPORTS)
        exports[("ntoskrnl.exe", "NkOnly")] = "implemented"
        exports[("other.sys", "KeSetEvent")] = "implemented"
        kernel = ledger.microsoft_kernel(exports, KERNEL)
        self.assertEqual((kernel["names"], kernel["by_ordinal_only"], kernel["forwarded"]),
                         (4, 1, 1))
        # ProbeForRead and NkOnly are not names of this (made-up) kernel.
        self.assertEqual(kernel["exported_by_nk"], 3)
        self.assertEqual(kernel["nk_names_it_lacks"], ["NkOnly", "ProbeForRead"])


class Missing(unittest.TestCase):
    def test_names_by_area_for_the_binaries_asked(self):
        areas, seen = ledger.missing(EXPORTS, LISTS, {"a.sys", "nosuch.sys"})
        self.assertEqual(seen, ["a.sys"])
        # Implemented names are left out; a partial or trapping one says so.
        self.assertEqual(areas, {"Ke": ["KeSetEvent"], "Zw": ["ZwClose(traps)"],
                                 "other": ["#4"]})

    def test_the_union_of_several_binaries(self):
        areas, seen = ledger.missing(EXPORTS, LISTS, {"a.sys", "b.sys", "c.sys"})
        self.assertEqual(seen, ["a.sys", "b.sys"])
        self.assertEqual(areas["Probe"], ["ProbeForRead(partial)"])
        # A fast-call form belongs to its area.
        areas, _ = ledger.missing({}, "x.sys 1 ntoskrnl.exe: ObfReferenceObject\n", {"x.sys"})
        self.assertEqual(areas, {"Ob": ["ObfReferenceObject"]})


if __name__ == "__main__":
    unittest.main()
