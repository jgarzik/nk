"""Checks on the oracle files. Run by `make test`.

A transcript in oracle/ is only evidence about the script and the driver
it was recorded with. Each records their hashes; this fails when a script
was edited, or a fixture replaced, without recording again on Windows
(`tools/oracle.py record <name>`).
"""

import hashlib
import re
import tomllib
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
ORACLE = ROOT / "oracle"
SCENARIOS = tomllib.loads((ROOT / "tools" / "scenarios.toml").read_text())
FIXTURES = tomllib.loads((ROOT / "fixtures" / "manifest.toml").read_text())["fixture"]


def fixture_sha256(file_name):
    """The pinned hash of the x86-64 fixture a script calls `file_name`."""
    stem = Path(file_name).stem
    matches = [fx["sha256"] for fx in FIXTURES
               if fx["name"] == stem and fx["arch"] == "x86_64" and "kind" not in fx]
    return matches[0] if len(matches) == 1 else None


class Oracle(unittest.TestCase):
    def test_every_script_has_a_current_transcript(self):
        scripts = sorted(ORACLE.glob("*.script"))
        self.assertTrue(scripts)
        for script in scripts:
            with self.subTest(script=script.name):
                text = script.read_text()
                lines = (ORACLE / f"{script.stem}.txt").read_text().splitlines()
                header = [l for l in lines if l.startswith("#")]
                body = [l for l in lines if not l.startswith("#")]
                self.assertIn(f"# script sha256 {hashlib.sha256(text.encode()).hexdigest()}",
                              header, "the script changed since it was recorded")
                # The file is the last field of `load` and of `install`.
                files = {l.split()[-1] for l in text.splitlines()
                         if l.split()[:1] in (["load"], ["install"])}
                recorded = dict(re.findall(r"^# driver (\S+) sha256 (\S+)$",
                                           "\n".join(header), re.M))
                self.assertEqual(sorted(recorded), sorted(files))
                for file_name, digest in recorded.items():
                    self.assertEqual(digest, fixture_sha256(file_name),
                                     f"{file_name} is not the fixture it was recorded with")
                steps = [l for l in text.splitlines() if l.strip() and not l.startswith("#")]
                if steps[0] == "debugger":
                    # Recorded with a debugger attached: NK must be run
                    # the same way, in a boot that says so.
                    self.assertEqual(body[0], "debugger: attached")
                    held = [sc for sc in SCENARIOS.values()
                            if f"test=oracle.{script.stem}" in sc.get("cmdline", "").split()]
                    self.assertTrue(held, "no scenario runs this script")
                    for sc in held:
                        self.assertIn("debug=on", sc["cmdline"].split())
                stopped = re.fullmatch(r".*: stopped ([0-9a-f]{8}) ([0-9a-f]{8})", body[-1])
                if stopped:
                    # Windows did not survive the last step recorded:
                    # nothing follows it, and a scenario must hold NK
                    # to the same stop.
                    self.assertLessEqual(len(body), len(steps))
                    wanted = [f"0x{int(n, 16):08X}" for n in stopped.groups()]
                    held = [sc for sc in SCENARIOS.values()
                            if f"test=oracle.{script.stem}" in sc.get("cmdline", "").split()]
                    self.assertTrue(held, "no scenario runs this script")
                    for sc in held:
                        self.assertEqual(sc.get("expect"), "bugcheck")
                        for number in wanted:
                            self.assertIn(number, sc["match"])
                else:
                    self.assertEqual(body[-1], "end")
                    self.assertEqual(len(body), len(steps) + 1, "one line per step, then `end`")

    def test_no_transcript_without_a_script(self):
        for transcript in ORACLE.glob("*.txt"):
            self.assertTrue((ORACLE / f"{transcript.stem}.script").exists(), transcript.name)


if __name__ == "__main__":
    unittest.main()
