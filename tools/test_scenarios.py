"""Checks on tools/scenarios.toml and the golden lists. Run by `make test`."""

import re
import tomllib
import unittest
from pathlib import Path

TOOLS = Path(__file__).resolve().parent
SCENARIOS = tomllib.loads((TOOLS / "scenarios.toml").read_text())
KEYS = {
    "arch", "tier", "smp", "accel", "cmdline", "expect", "match", "then", "must_fail",
    "golden", "canonical",
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

    def test_each_architecture_has_its_main_scenario(self):
        # `make check` / `check-arm` and the ledger rely on these.
        for arch in ("x86_64", "aarch64"):
            sc = SCENARIOS[arch]
            self.assertEqual((sc["arch"], sc.get("canonical"), sc["tier"]), (arch, True, "gate"))
            self.assertEqual(sc.get("expect", "ok"), "ok")
            self.assertNotIn("cmdline", sc, "the main scenario runs every test")

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
