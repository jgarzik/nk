"""Unit tests for tools/negpe.py: generated negative PE32+ fixtures parse
cleanly through NK's own `peinfo` binary for both architectures. Run by
`make test`."""

import subprocess
import tempfile
import unittest
from pathlib import Path

import negpe

ROOT = Path(__file__).resolve().parent.parent
PEINFO = ROOT / "target" / "debug" / "peinfo"


class NegativePe(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        subprocess.run(["cargo", "build", "-q", "-p", "peinfo"], check=True, cwd=ROOT)

    def test_generated_fixtures_parse_with_peinfo_for_both_arches(self):
        with tempfile.TemporaryDirectory() as tmp:
            for arch in ("x86_64", "aarch64"):
                items = list(negpe.generate_all(arch))
                self.assertEqual([n for n, _ in items], ["unresolved.sys", "nomodule.sys"])
                for (name, data), (_, dll, sym) in zip(items, negpe.NEGATIVE_FIXTURES):
                    with self.subTest(arch=arch, name=name):
                        path = Path(tmp) / f"{arch}-{name}"
                        path.write_bytes(data)
                        out = subprocess.run([PEINFO, path], check=True,
                                             capture_output=True, text=True).stdout
                        lines = out.splitlines()
                        self.assertIn(f"machine {arch}", lines)
                        self.assertIn(f"import {dll.decode()} {sym.decode()}", lines)


if __name__ == "__main__":
    unittest.main()
