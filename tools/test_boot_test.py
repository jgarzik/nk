"""Unit tests for the parts of tools/boot_test.py that boot nothing. Run by
`make test`."""

import unittest

import boot_test

TIER = """\
   Compiling nkkrnl v0.2.0
ok       null.x64.sys
boot test x86_64: PASSED (pass=3 skip=0)
  NK-TEST io.late:SKIP no fixture
  NK-TEST mm.pool:FAIL lost a block
boot test aarch64: FAILED
  NK-TEST mm.pool:FAIL lost a block
  last serial lines (target/qemu/aarch64/serial.log):
    NK-TEST-COMPLETE pass=2 fail=1 skip=1
boot test x86_64-smp1: PASSED (pass=3 skip=0)
boot test x86_64-neg-panic: firmware never started the loader; booting once more
boot test x86_64-neg-panic: PASSED (expected bugcheck)
Traceback (most recent call last):
OSError: no space left
boot test aarch64-smp1: FAILED (exit status 1, no verdict)
boot test aarch64-neg-panic: PASSED (expected bugcheck)
tier gate: FAILED 2 of 6 boots (aarch64, aarch64-smp1)
make: *** [Makefile:66: boot-gate] Error 1
"""


class Failures(unittest.TestCase):
    def test_the_failed_boots_and_the_last_line(self):
        self.assertEqual(boot_test.failures(TIER), [
            "boot test aarch64: FAILED",
            "  NK-TEST mm.pool:FAIL lost a block",
            "  last serial lines (target/qemu/aarch64/serial.log):",
            "    NK-TEST-COMPLETE pass=2 fail=1 skip=1",
            "boot test aarch64-smp1: FAILED (exit status 1, no verdict)",
            "tier gate: FAILED 2 of 6 boots (aarch64, aarch64-smp1)",
            "make: *** [Makefile:66: boot-gate] Error 1",
        ])

    def test_output_that_names_no_failed_boot_yields_nothing(self):
        # The caller then shows the end of the output instead.
        self.assertEqual(boot_test.failures(""), [])
        self.assertEqual(boot_test.failures("error: could not compile `nkkrnl`\n"), [])
        self.assertEqual(boot_test.failures(
            "boot test x86_64: PASSED (pass=3 skip=0)\ntier gate: 1 scenarios passed\n"), [])


if __name__ == "__main__":
    unittest.main()
