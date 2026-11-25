"""Unit tests for tools/judge.py: every way a boot can be wrong must be
caught, and a good boot must pass. Run by `make test`."""

import unittest

from judge import judge

GOOD = """\
nkload: starting kernel
NK 0.0.1 (x86_64)
NK-EXPORT ntoskrnl.exe DbgPrint implemented
NK-TEST-PLAN 3
NK-TEST boot:OK
NK-TEST mm.pool:OK
NK-TEST sioctl.neither:SKIP needs SEH
NK-TEST-COMPLETE pass=2 fail=0 skip=1
"""
GOLDEN = {"boot": "ok", "mm.pool": "ok", "sioctl.neither": "skip"}

ARMED = """\
NK-TEST-PLAN 1
NK-NEG-ARMED neg.panic
BUGCHECK: KERNEL PANIC: panicked at kernel/selftest/neg.rs:26:5:
neg.panic: deliberate panic
"""

KNOWN_BAD = """\
NK-TEST-PLAN 1
NK-TEST meta.fail:FAIL deliberate failure
NK-TEST-COMPLETE pass=0 fail=1 skip=0
"""


def edit(text, old, new):
    assert old in text, old
    return text.replace(old, new)


class ExpectOk(unittest.TestCase):
    def assertProblem(self, text, fragment, **kw):
        problems = judge(text, golden=GOLDEN, **kw)
        self.assertTrue(any(fragment in p for p in problems),
                        f"wanted a problem containing {fragment!r}, got {problems}")

    def test_good_boot_passes(self):
        self.assertEqual(judge(GOOD, golden=GOLDEN), [])
        self.assertEqual(judge(GOOD), [])

    def test_carriage_returns_and_blank_lines_are_tolerated(self):
        self.assertEqual(judge(GOOD.replace("\n", "\r\n\r\n"), golden=GOLDEN), [])

    def test_failed_test(self):
        text = edit(GOOD, "NK-TEST mm.pool:OK", "NK-TEST mm.pool:FAIL overrun")
        text = edit(text, "pass=2 fail=0", "pass=1 fail=1")
        self.assertProblem(text, "NK-TEST mm.pool:FAIL overrun")
        self.assertProblem(text, "1 failed")

    def test_failure_line_alone_is_enough(self):
        # Even if the totals lie.
        text = edit(GOOD, "NK-TEST mm.pool:OK", "NK-TEST mm.pool:FAIL overrun")
        self.assertProblem(text, "NK-TEST mm.pool:FAIL")

    def test_totals_must_match_the_lines(self):
        self.assertProblem(edit(GOOD, "pass=2", "pass=3"), "do not match")

    def test_no_complete_line(self):
        text = edit(GOOD, "NK-TEST-COMPLETE pass=2 fail=0 skip=1\n", "")
        self.assertProblem(text, "expected one NK-TEST-COMPLETE line, found 0")

    def test_two_complete_lines(self):
        self.assertProblem(GOOD + "NK-TEST-COMPLETE pass=2 fail=0 skip=1\n",
                           "expected one NK-TEST-COMPLETE line, found 2")

    def test_no_plan_line(self):
        self.assertProblem(edit(GOOD, "NK-TEST-PLAN 3\n", ""),
                           "expected one NK-TEST-PLAN line, found 0")

    def test_fewer_verdicts_than_planned(self):
        text = edit(GOOD, "NK-TEST mm.pool:OK\n", "")
        text = edit(text, "pass=2", "pass=1")
        self.assertProblem(text, "plan declared 3 verdicts, 2 were reported")
        self.assertProblem(text, "mm.pool: in the golden list but not run")

    def test_more_verdicts_than_planned(self):
        text = edit(GOOD, "NK-TEST mm.pool:OK\n", "NK-TEST mm.pool:OK\nNK-TEST extra:OK\n")
        text = edit(text, "pass=2", "pass=3")
        self.assertProblem(text, "plan declared 3 verdicts, 4 were reported")
        self.assertProblem(text, "extra: run but not in the golden list")

    def test_duplicate_verdict(self):
        text = edit(GOOD, "NK-TEST mm.pool:OK\n", "NK-TEST mm.pool:OK\nNK-TEST mm.pool:OK\n")
        self.assertProblem(text, "mm.pool: reported 2 times")

    def test_torn_line(self):
        # Two CPUs printing at once.
        text = edit(GOOD, "NK-TEST mm.pool:OK\n", "NK-TEST mm.pNK-TEST boot:OK\nool:OK\n")
        self.assertProblem(text, "malformed test line")

    def test_truncated_line(self):
        self.assertProblem(edit(GOOD, "NK-TEST mm.pool:OK", "NK-TEST mm.pool:O"),
                           "malformed test line")

    def test_bugcheck_after_the_tests(self):
        self.assertProblem(GOOD + "BUGCHECK: page fault (vector 14)\n", "BUGCHECK: page fault")

    def test_panic(self):
        self.assertProblem(GOOD + "KERNEL PANIC: oops\n", "KERNEL PANIC")

    def test_timeout(self):
        self.assertProblem(GOOD, "timeout after 120s", timed_out=120)

    def test_a_driver_breaking_a_rule_windows_tolerates(self):
        self.assertProblem(GOOD + "NK-VERIFY IRQL raised from 2 down to 1\n",
                           "NK-VERIFY IRQL raised from 2 down to 1")

    def test_empty_log(self):
        problems = judge("", golden=GOLDEN)
        self.assertTrue(any("NK-TEST-PLAN" in p for p in problems))
        self.assertTrue(any("NK-TEST-COMPLETE" in p for p in problems))

    def test_unfinished_run_does_not_list_every_missing_test(self):
        problems = judge("NK 0.0.1\n", golden=GOLDEN, timed_out=5)
        self.assertFalse(any("golden list" in p for p in problems), problems)

    def test_ok_that_became_skip(self):
        text = edit(GOOD, "NK-TEST mm.pool:OK", "NK-TEST mm.pool:SKIP no module")
        text = edit(text, "pass=2 fail=0 skip=1", "pass=1 fail=0 skip=2")
        self.assertProblem(text, "mm.pool: golden list says ok, the run says skip")

    def test_missing_fixtures_allow_skip_only(self):
        text = edit(GOOD, "NK-TEST mm.pool:OK", "NK-TEST mm.pool:SKIP no module")
        text = edit(text, "pass=2 fail=0 skip=1", "pass=1 fail=0 skip=2")
        self.assertEqual(judge(text, golden=GOLDEN, degraded=True), [])
        # A new or vanished test is still a problem.
        self.assertProblem(edit(text, "mm.pool", "mm.other"), "mm.other", degraded=True)

    def test_skip_that_became_ok_must_be_blessed(self):
        text = edit(GOOD, "NK-TEST sioctl.neither:SKIP needs SEH", "NK-TEST sioctl.neither:OK")
        text = edit(text, "pass=2 fail=0 skip=1", "pass=3 fail=0 skip=0")
        self.assertProblem(text, "sioctl.neither: golden list says skip, the run says ok")

    def test_unplanned_leak_line(self):
        text = edit(GOOD, "NK-TEST-COMPLETE pass=2 fail=0",
                    "NK-TEST leak:FAIL group of boot: before 1, after 2\n"
                    "NK-TEST-COMPLETE pass=2 fail=1")
        self.assertProblem(text, "NK-TEST leak:FAIL")
        self.assertProblem(text, "plan declared 3 verdicts, 4 were reported")


class ExpectBugcheck(unittest.TestCase):
    MATCH = r"KERNEL PANIC: panicked at kernel/selftest/neg\.rs"

    def problems(self, text, **kw):
        return judge(text, "bugcheck", match=self.MATCH, **kw)

    def test_armed_bugcheck_passes(self):
        self.assertEqual(self.problems(ARMED), [])

    def test_bugcheck_before_the_test_armed(self):
        text = "BUGCHECK: KERNEL PANIC: panicked at kernel/selftest/neg.rs:1:1:\n" \
               "NK-NEG-ARMED neg.panic\n"
        self.assertTrue(any("before the test was armed" in p for p in self.problems(text)))

    def test_bugcheck_that_was_never_armed(self):
        text = edit(ARMED, "NK-NEG-ARMED neg.panic\n", "")
        self.assertTrue(any("NK-NEG-ARMED" in p for p in self.problems(text)))

    def test_the_wrong_bugcheck(self):
        text = edit(ARMED, "KERNEL PANIC: panicked at kernel/selftest/neg.rs:26:5:",
                    "page fault (vector 14)")
        self.assertTrue(any("does not match" in p for p in self.problems(text)))

    def test_no_bugcheck_at_all(self):
        text = "NK-TEST-PLAN 1\nNK-NEG-ARMED neg.panic\n" \
               "NK-TEST neg.panic:OK\nNK-TEST-COMPLETE pass=1 fail=0 skip=0\n"
        problems = self.problems(text)
        self.assertTrue(any("expected one BUGCHECK line, found 0" in p for p in problems))
        self.assertTrue(any("ran to completion" in p for p in problems))

    def test_two_bugchecks(self):
        self.assertTrue(any("found 2" in p for p in self.problems(ARMED + "BUGCHECK: again\n")))

    def test_timeout(self):
        self.assertTrue(any("timeout" in p for p in self.problems(ARMED, timed_out=9)))

    def test_a_failed_test_before_the_bugcheck(self):
        text = "NK-TEST neg.fault:FAIL no kernel address space\n" + ARMED
        self.assertTrue(any("neg.fault:FAIL" in p for p in self.problems(text)))


class ExpectFail(unittest.TestCase):
    def problems(self, text, **kw):
        return judge(text, "fail", must_fail=["meta.fail"], **kw)

    def test_the_known_bad_run_is_judged_bad(self):
        self.assertEqual(self.problems(KNOWN_BAD), [])
        # ... which is to say, as a plain run it fails.
        self.assertNotEqual(judge(KNOWN_BAD), [])

    def test_a_run_that_passes_is_wrong(self):
        text = "NK-TEST-PLAN 1\nNK-TEST meta.fail:OK\nNK-TEST-COMPLETE pass=1 fail=0 skip=0\n"
        self.assertTrue(any("judged a pass" in p for p in self.problems(text)))

    def test_failing_for_another_reason_is_wrong(self):
        text = edit(KNOWN_BAD, "NK-TEST-PLAN 1\n", "")
        self.assertTrue(any("unexpected problem" in p for p in self.problems(text)))
        self.assertTrue(any("unexpected problem" in p
                            for p in self.problems(KNOWN_BAD + "BUGCHECK: x\n")))
        self.assertTrue(any("unexpected problem" in p
                            for p in self.problems(KNOWN_BAD, timed_out=3)))

    def test_a_different_test_failing_is_wrong(self):
        text = edit(KNOWN_BAD, "meta.fail", "mm.pool")
        self.assertTrue(any("expected exactly ['meta.fail'] to fail" in p
                            for p in self.problems(text)))


if __name__ == "__main__":
    unittest.main()
