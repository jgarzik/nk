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
        exports[("ntoskrnl.exe", "#4")] = "implemented"
        exports[("other.sys", "KeSetEvent")] = "implemented"
        kernel = ledger.microsoft_kernel(exports, KERNEL)
        self.assertEqual((kernel["names"], kernel["by_ordinal_only"], kernel["forwarded"]),
                         (4, 1, 1))
        # ProbeForRead and NkOnly are not names of this (made-up) kernel.
        self.assertEqual(kernel["exported_by_nk"], 3)
        self.assertEqual(kernel["nk_names_it_lacks"], ["NkOnly", "ProbeForRead"])


class Libraries(unittest.TestCase):
    LISTING = """\
machine x86_64
import ntoskrnl.exe KeSetEvent
export 1 DllInitialize rva=0x1000
export 7 - rva=0x1010
export 8 NkcLibAdd rva=0x1020
export 9 Forwarded forward=NTOSKRNL.KeSetEvent
"""

    def test_an_image_exports_names_and_ordinals(self):
        self.assertEqual(ledger.exports_of(self.LISTING),
                         {"#1", "DllInitialize", "#7", "#8", "NkcLibAdd", "#9", "Forwarded"})
        self.assertEqual(ledger.exports_of("machine x86_64\n"), set())

    def test_an_import_is_the_kernels_or_a_librarys_or_missing(self):
        libraries = {"nkc-lib.sys": ledger.exports_of(self.LISTING), "plain.sys": set()}

        def state(module, name):
            return ledger.import_state(module, name, EXPORTS, libraries)

        self.assertEqual(state("ntoskrnl.exe", "ProbeForRead"), "partial")
        self.assertEqual(state("HAL.dll", "KeStallExecutionProcessor"), "implemented")
        self.assertEqual(state("ntoskrnl.exe", "NkcLibAdd"), "missing")
        # From a fixture that exports it: by name, by ordinal.
        self.assertEqual(state("NKC-LIB.sys", "NkcLibAdd"), "library")
        self.assertEqual(state("nkc-lib.sys", "#7"), "library")
        self.assertEqual(state("nkc-lib.sys", "NkcLibAbsent"), "missing")
        self.assertEqual(state("nkc-lib.sys", "#2"), "missing")
        # A kernel name is not a library's; a module that is no fixture
        # exports nothing.
        self.assertEqual(state("nkc-lib.sys", "KeSetEvent"), "missing")
        self.assertEqual(state("plain.sys", "X"), "missing")
        self.assertEqual(state("wdfldr.sys", "WdfVersionBind"), "missing")


class LookedUp(unittest.TestCase):
    def test_names_the_kernel_reported_absent_once_each_and_sorted(self):
        lines = [
            "NK-LOOKUP PsGetVersion absent",
            "NK-EXPORT ntoskrnl.exe ZwClose implemented",
            "NK-LOOKUP EtwRegister absent",
            "NK-LOOKUP PsGetVersion absent",
            "NK-TEST null.load:OK",
            # Not the kernel's line: torn, or another word.
            "NK-LOOKUP Torn",
            "NK-LOOKUP KeSetEvent found",
        ]
        self.assertEqual(ledger.looked_up_absent(lines), ["EtwRegister", "PsGetVersion"])
        self.assertEqual(ledger.looked_up_absent([]), [])


class Missing(unittest.TestCase):
    def test_names_by_area_for_the_binaries_asked(self):
        areas, seen, others = ledger.missing(EXPORTS, LISTS, {"a.sys", "nosuch.sys"})
        self.assertEqual(seen, ["a.sys"])
        self.assertEqual(others, ["wmilib.sys"])
        # Implemented names are left out; a partial or trapping one says so.
        self.assertEqual(areas, {"Ke": ["KeSetEvent"], "Zw": ["ZwClose(traps)"],
                                 "other": ["#4"]})

    def test_the_union_of_several_binaries(self):
        areas, seen, others = ledger.missing(EXPORTS, LISTS, {"a.sys", "b.sys", "c.sys"})
        self.assertEqual(seen, ["a.sys", "b.sys", "c.sys"])
        self.assertEqual(others, ["storport.sys", "wmilib.sys"])
        self.assertEqual(areas["Probe"], ["ProbeForRead(partial)"])
        # A fast-call form belongs to its area.
        areas, _, _ = ledger.missing({}, "x.sys 1 ntoskrnl.exe: ObfReferenceObject\n", {"x.sys"})
        self.assertEqual(areas, {"Ob": ["ObfReferenceObject"]})

    def test_a_binary_that_imports_nothing_from_the_kernel_is_in_the_corpus(self):
        # c.sys imports from its port driver only; d.sys imports nothing.
        self.assertEqual(ledger.missing(EXPORTS, LISTS, {"c.sys"}),
                         ({}, ["c.sys"], ["storport.sys"]))
        self.assertEqual(ledger.missing(EXPORTS, LISTS, {"d.sys"}), ({}, ["d.sys"], []))
        self.assertEqual(ledger.missing_report(EXPORTS, LISTS, ["C.SYS"]), [
            "c.sys: 0 kernel names not implemented",
            "  imports from other modules: storport.sys",
        ])

    def test_the_report_names_what_the_corpus_lacks(self):
        self.assertEqual(ledger.missing_report(EXPORTS, LISTS, ["nosuch.sys"]),
                         ["ledger: nosuch.sys is not in the corpus"])
        self.assertEqual(ledger.missing_report(EXPORTS, LISTS, ["nosuch.sys", "a.sys"]), [
            "ledger: nosuch.sys is not in the corpus",
            "a.sys: 3 kernel names not implemented",
            "  Ke (1): KeSetEvent",
            "  Zw (1): ZwClose(traps)",
            "  other (1): #4",
            "  imports from other modules: wmilib.sys",
        ])


class Services(unittest.TestCase):
    def test_parses_ssdt_summary_lines(self):
        lines = [
            "NK-SVC-TOTAL 471",
            "NK-SVC 15 NtClose implemented",
            "NK-SVC 4 NtWaitForSingleObject partial",
        ]
        summary = ledger.parse_services(lines)
        self.assertEqual(summary["total"], 471)
        self.assertEqual(summary["implemented"], 1)
        self.assertEqual(summary["partial"], 1)
        self.assertEqual(summary["traps"], 0)
        self.assertEqual(summary["missing"], 469)
        self.assertEqual(
            summary["registered"],
            [
                {"number": 4, "name": "NtWaitForSingleObject", "state": "partial"},
                {"number": 15, "name": "NtClose", "state": "implemented"},
            ],
        )
        self.assertIsNone(ledger.parse_services([]))


class HighPriority(unittest.TestCase):
    PRIO_LISTS = """\
storport.sys 10.0.1 ntoskrnl.exe: IoCreateDevice ProbeForRead ZwClose
tcpip.sys 10.0.2 ntoskrnl.exe: IoCreateDevice KeSetEvent SharedMissing
tcpip.sys 10.0.2 netio.sys: NmrRegisterClient
ndis.sys 10.0.3 ntoskrnl.exe: KeStallExecutionProcessor NdisOnlyMissing SharedMissing
afd.sys 10.0.4 ntoskrnl.exe: IoCreateDevice SharedMissing ProbeForRead
afd.sys 10.0.4 netio.sys: NmrRegisterClient
ntfs.sys 10.0.5 ntoskrnl.exe: IoCreateDevice NtfsOnlyMissing SharedMissing
ntfs.sys 10.0.5 ext-ms-win-fs-clfs-l1-1-0.dll: ClfsCreateLogFile
netio.sys 10.0.6 ntoskrnl.exe: NetioDepMissing
clfs.sys 10.0.7 ntoskrnl.exe: ClfsDepMissing
unrelated.sys 10.0.8 ntoskrnl.exe: UnrelatedMissing
"""

    def test_absent_when_none_present(self):
        self.assertNotIn("high_priority", ledger.corpus(EXPORTS, LISTS))

    def test_union_per_binary_and_transitive_closure(self):
        c = ledger.corpus(EXPORTS, self.PRIO_LISTS)
        hp = c["high_priority"]
        self.assertEqual(
            hp["binaries"],
            ["storport.sys", "tcpip.sys", "ndis.sys", "afd.sys", "ntfs.sys"],
        )
        # Direct distinct union: IoCreateDevice (impl), KeStallExecutionProcessor (impl),
        # ProbeForRead (partial), ZwClose (traps), KeSetEvent (missing),
        # NdisOnlyMissing (missing), NtfsOnlyMissing (missing), SharedMissing (missing) = 8.
        self.assertEqual(
            hp["kernel_names"],
            {"total": 8, "implemented": 2, "partial": 1, "traps": 1, "missing": 4},
        )
        by_file = {b["file"]: b for b in hp["by_binary"]}
        self.assertEqual(
            by_file["storport.sys"]["not_implemented"],
            {"missing": [], "traps": ["ZwClose"], "partial": ["ProbeForRead"]},
        )
        self.assertEqual(
            by_file["afd.sys"]["not_implemented"],
            {"missing": ["SharedMissing"], "traps": [], "partial": ["ProbeForRead"]},
        )
        self.assertEqual(
            by_file["ntfs.sys"]["not_implemented"],
            {"missing": ["NtfsOnlyMissing", "SharedMissing"], "traps": [], "partial": []},
        )
        # Shared gaps ranked by count desc, then name asc.
        self.assertEqual(
            hp["shared_gaps"],
            [
                {
                    "name": "SharedMissing",
                    "state": "missing",
                    "count": 4,
                    "binaries": ["afd.sys", "ndis.sys", "ntfs.sys", "tcpip.sys"],
                },
                {
                    "name": "ProbeForRead",
                    "state": "partial",
                    "count": 2,
                    "binaries": ["afd.sys", "storport.sys"],
                },
            ],
        )
        # Transitive closure pulls in netio.sys and clfs.sys (via ext-ms-win-fs-clfs-l1-1-0.dll),
        # excluding unrelated.sys.
        deps = hp["with_dependencies"]
        self.assertEqual(
            deps["binaries"],
            ["afd.sys", "clfs.sys", "ndis.sys", "netio.sys", "ntfs.sys", "storport.sys", "tcpip.sys"],
        )
        self.assertEqual(deps["kernel_names"]["missing"], 6)

    def test_priority_report_output(self):
        lines = ledger.priority_report(EXPORTS, self.PRIO_LISTS)
        self.assertTrue(any("storport.sys" in line for line in lines))
        self.assertTrue(any("afd.sys" in line for line in lines))
        self.assertTrue(any("WITH DEPS" in line and "7 binaries" in line for line in lines))
        self.assertTrue(any("4x SharedMissing" in line for line in lines))
        self.assertTrue(any("NtfsOnlyMissing" in line for line in lines))


if __name__ == "__main__":
    unittest.main()
