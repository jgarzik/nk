"""Checks on tools/scenarios.toml and the golden lists. Run by `make test`."""

import re
import tomllib
import unittest
from pathlib import Path

import boot_test
import datadisk
import fatdisk
import mkesp

TOOLS = Path(__file__).resolve().parent
SCENARIOS = tomllib.loads((TOOLS / "scenarios.toml").read_text())
KEYS = {
    "arch", "tier", "smp", "accel", "cmdline", "expect", "match", "then", "must_fail",
    "golden", "canonical", "disk", "disk_size", "disk_image", "disk_expect", "registry",
    "paths", "usb", "usb_kbd", "serial2", "hotplug", "memory",
}


def golden_lists():
    """{list name: [[test, verdict]]}: a list is a directory of files, one
    per first word of the tests' names."""
    lists = {}
    for directory in sorted(p for p in (TOOLS / "golden").iterdir() if p.is_dir()):
        lists[directory.name] = [
            l.split() for path in sorted(directory.glob("*.txt"))
            for l in path.read_text().splitlines() if l and l[0] != "#"]
    return lists


def blocked():
    lines = (TOOLS / "golden" / "blocked.txt").read_text().splitlines()
    return {l.split("\t")[0]: l.split("\t")[1] for l in lines if l and l[0] != "#"}


class Scenarios(unittest.TestCase):
    def test_every_scenario_is_well_formed(self):
        for name, sc in SCENARIOS.items():
            with self.subTest(scenario=name):
                self.assertFalse(sc.keys() - KEYS, "unknown keys")
                self.assertIn(sc["arch"], ("x86_64", "aarch64"))
                self.assertIn(sc["tier"], ("gate", "soak"))
                expect = sc.get("expect", "ok")
                self.assertIn(expect, ("ok", "bugcheck", "fail"))
                self.assertEqual("match" in sc, expect == "bugcheck")
                self.assertEqual("must_fail" in sc, expect == "fail")
                if "match" in sc:
                    re.compile(sc["match"])
                if "then" in sc:
                    self.assertEqual(expect, "bugcheck")
                    re.compile(sc["then"])
                if "golden" in sc:
                    self.assertTrue((TOOLS / "golden" / sc["golden"]).is_dir())
                self.assertLess(len(sc.get("cmdline", "")), 256)
                if "paths" in sc:
                    # Only the fast and batch gates select by path, and
                    # they boot x86-64 scenarios of the gate tier.
                    self.assertEqual((sc["arch"], sc["tier"]), ("x86_64", "gate"))
                    self.assertTrue(sc["paths"])
                    for path in sc["paths"]:
                        # A path that names nothing selects nothing.
                        there = TOOLS.parent / path
                        self.assertTrue(there.is_dir() if path.endswith("/") else there.is_file(),
                                        f"{path} is not in the tree")
                # A disk is always checked after the boot, and only a
                # scenario with a disk says anything about one.
                self.assertEqual("disk_expect" in sc, "disk" in sc)
                if "disk_size" in sc:
                    self.assertIn("disk", sc)
                for name in sc.get("registry", ()):
                    self.assertTrue(mkesp.registry_file(name).exists(), name)
                if "disk_image" in sc:
                    self.assertIn(sc.get("disk"), ("ahci", "nvme"))
                    self.assertNotIn("disk_size", sc, "a FAT disk has its own size")
                    self.assertIn(sc["disk_image"], fatdisk.LAYOUTS)
                    self.assertIn(sc["disk_expect"], fatdisk.CHECKS)
                elif "disk" in sc:
                    self.assertIn(sc["disk"], ("ahci", "nvme"))
                    self.assertIn(sc["disk_expect"], datadisk.CHECKS)
                    size = sc.get("disk_size", datadisk.DEFAULT_MIB)
                    self.assertIsInstance(size, int)
                    # Room for the write range, and sectors after it.
                    self.assertGreater(size << 20, datadisk.WRITE_END * datadisk.SECTOR)
                if "usb" in sc:
                    self.assertEqual(sc["usb"], "xhci")
                    self.assertEqual(sc["arch"], "x86_64")
                if sc.get("usb_kbd") or sc.get("hotplug"):
                    self.assertEqual(sc.get("usb"), "xhci")
                if sc.get("serial2"):
                    self.assertEqual(sc["arch"], "x86_64")

    def test_each_architecture_has_its_main_scenario(self):
        # `make check` / `check-arm` and the ledger rely on these.
        for arch in ("x86_64", "aarch64"):
            sc = SCENARIOS[arch]
            self.assertEqual((sc["arch"], sc.get("canonical"), sc["tier"]), (arch, True, "gate"))
            self.assertEqual(sc.get("expect", "ok"), "ok")
            self.assertNotIn("cmdline", sc, "the main scenario runs every test")

    def test_the_gate_proves_a_disk_is_attached_and_compared(self):
        sc = SCENARIOS["x86_64-disk-present"]
        self.assertEqual((sc["tier"], sc["disk"], sc["disk_expect"], sc.get("expect", "ok")),
                         ("gate", "ahci", "unchanged", "ok"))

    def test_the_fast_gate_runs_microsoft_s_stack_for_a_kernel_change(self):
        for changed in ("kernel/io/irp.rs", "kernel/pnp/mod.rs", "lib/ntabi/lib.rs"):
            names = boot_test.select(SCENARIOS, "fast", [changed])
            self.assertLessEqual({"x86_64", "x86_64-storage", "x86_64-storage-direct"},
                                 set(names), changed)
        self.assertEqual(boot_test.select(SCENARIOS, "fast", ["doc/TESTING.md"]), ["x86_64"])

    def test_the_batch_gate_with_no_base_and_the_full_gate_run_what_they_say(self):
        gate = [n for n, sc in SCENARIOS.items() if sc["tier"] == "gate"]
        self.assertEqual(boot_test.select(SCENARIOS, "full", []), gate)
        self.assertEqual(boot_test.select(SCENARIOS, "batch", None),
                         [n for n in gate if SCENARIOS[n]["arch"] == "x86_64"])
        # With nothing changed, the batch gate still boots all that must pass.
        self.assertEqual(boot_test.select(SCENARIOS, "batch", []),
                         [n for n in gate if SCENARIOS[n]["arch"] == "x86_64"
                          and SCENARIOS[n].get("expect", "ok") == "ok"])

    def test_the_gate_proves_failures_are_seen(self):
        for arch in ("x86_64", "aarch64"):
            kinds = {sc.get("expect", "ok") for sc in SCENARIOS.values()
                     if sc["arch"] == arch and sc["tier"] == "gate"}
            self.assertEqual(kinds, {"ok", "bugcheck", "fail"}, arch)

    def test_golden_lists_are_used_and_well_formed(self):
        used = {sc["golden"] for sc in SCENARIOS.values() if "golden" in sc}
        lists = golden_lists()
        self.assertEqual(set(lists), used)
        for name, entries in lists.items():
            with self.subTest(golden=name):
                self.assertTrue(all(len(e) == 2 and e[1] in ("ok", "skip") for e in entries))
                names = [e[0] for e in entries]
                self.assertEqual(len(names), len(set(names)), "duplicate test names")
                for path in (TOOLS / "golden" / name).glob("*.txt"):
                    for line in path.read_text().splitlines():
                        self.assertEqual(line.split(".")[0].split()[0] + ".txt", path.name,
                                         f"{line.split()[0]} is in the wrong file")

    def test_no_test_is_skipped_everywhere_unless_it_says_why(self):
        ok, skipped = set(), set()
        for entries in golden_lists().values():
            for name, verdict in entries:
                (ok if verdict == "ok" else skipped).add(name)
        self.assertEqual(skipped - ok, set(blocked()),
                         "tests skipped in every scenario must be listed, with the reason, "
                         "in tools/golden/blocked.txt, and only those")
        self.assertTrue(all(reason.strip() for reason in blocked().values()))


if __name__ == "__main__":
    unittest.main()
