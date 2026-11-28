"""Checks that every mutant in tools/mutants/ still applies. Run by
`make test`: a mutant whose line has moved or changed would otherwise
only be noticed the next time someone runs `make mutants`."""

import tomllib
import unittest
from pathlib import Path

import mutants

SCENARIOS = tomllib.loads((mutants.ROOT / "tools" / "scenarios.toml").read_text())


class Mutants(unittest.TestCase):
    def test_every_mutant_applies(self):
        paths = sorted(mutants.MUTANTS.glob("*.mutant"))
        self.assertTrue(paths)
        for path in paths:
            with self.subTest(mutant=path.stem):
                fields = mutants.parse(path)
                self.assertIn(fields["scenario"], SCENARIOS)
                # A named test can only be seen to fail in a scenario that
                # otherwise passes. Any scenario can fail as a whole.
                if fields["fails"] != "scenario":
                    self.assertEqual(SCENARIOS[fields["scenario"]].get("expect", "ok"), "ok")
                text = (mutants.ROOT / fields["file"]).read_text()
                changed = mutants.mutate(text, fields, path.stem)
                self.assertNotEqual(changed, text)
                self.assertTrue(path.read_text().startswith("#"), "say why the break matters")

    def test_build_env_and_cli_args(self):
        args = mutants.parse_args(["--jobs", "4", "--fat", "clock-fast"])
        self.assertEqual(args.jobs, 4)
        self.assertTrue(args.fat)
        self.assertEqual(args.names, ["clock-fast"])
        thin = mutants.build_env(thin_lto=True, parallel_workers=4)
        self.assertEqual(thin["CARGO_PROFILE_RELEASE_LTO"], "thin")
        self.assertEqual(thin["CARGO_PROFILE_RELEASE_CODEGEN_UNITS"], "4")
        self.assertEqual(thin["CARGO_BUILD_JOBS"], "2")
        fat = mutants.build_env(thin_lto=False, parallel_workers=1)
        self.assertNotIn("CARGO_PROFILE_RELEASE_LTO", fat)


if __name__ == "__main__":
    unittest.main()
