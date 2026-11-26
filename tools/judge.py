"""Decide whether a boot passed, from its serial log alone.

A pure function over text, so it can be tested without booting anything
(`tools/test_judge.py`). The kernel's side of the format is documented at
the top of `kernel/test.rs`.

A scenario states what it expects:

  ok        the tests ran to the end and none failed
  bugcheck  the kernel stopped with a bugcheck that a test armed first
  fail      the named tests failed and the run was reported as failed
            (proves that a failure is not mistaken for a pass)
"""

import re

TEST = re.compile(r"^NK-TEST (\S+):(OK|FAIL|SKIP)(?: (.*))?$")
PLAN = re.compile(r"^NK-TEST-PLAN (\d+)$")
COMPLETE = re.compile(r"^NK-TEST-COMPLETE pass=(\d+) fail=(\d+) skip=(\d+)$")
ARMED = re.compile(r"^NK-NEG-ARMED (\S+)$")
FATAL = re.compile(r"BUGCHECK|KERNEL PANIC")


class Log:
    """What the serial log says, with nothing decided yet."""

    def __init__(self, text):
        self.lines = [l.strip() for l in text.splitlines()]
        self.tests = []      # (name, verdict, detail)
        self.plans = []      # declared verdict counts
        self.completes = []  # (pass, fail, skip)
        self.armed = []      # (line number, test name)
        self.fatal = []      # (line number, line)
        self.malformed = []  # lines that mention the protocol but break it
        self.verify = []     # a driver broke a rule Windows does not enforce
        for n, line in enumerate(self.lines):
            if FATAL.search(line):
                self.fatal.append((n, line))
            if line.startswith("NK-VERIFY "):
                self.verify.append(line)
            if m := TEST.match(line):
                self.tests.append((m[1], m[2], m[3] or ""))
            elif m := PLAN.match(line):
                self.plans.append(int(m[1]))
            elif m := COMPLETE.match(line):
                self.completes.append(tuple(int(x) for x in m.groups()))
            elif m := ARMED.match(line):
                self.armed.append((n, m[1]))
            elif "NK-TEST" in line or "NK-NEG-ARMED" in line:
                # Torn or interleaved output: two lines run together, or a
                # line cut short. Never ignore it.
                self.malformed.append(line)

    def verdicts(self):
        """{name: verdict}; a repeated name keeps its last verdict."""
        return {name: verdict for name, verdict, _ in self.tests}

    def exports(self):
        return [l for l in self.lines if l.startswith("NK-EXPORT ")]

    def lookups(self):
        """The names drivers asked `MmGetSystemRoutineAddress` for that the
        kernel does not export, as it printed them."""
        return [l for l in self.lines if l.startswith("NK-LOOKUP ")]

    def tail(self, count=8):
        return [l for l in self.lines if l][-count:]


def _run_problems(log, timed_out):
    """Problems of a boot that should have run its tests to the end."""
    problems = [f"malformed test line: {l}" for l in log.malformed]
    problems += log.verify
    problems += [l for _, l in log.fatal]
    problems += [f"NK-TEST {n}:FAIL {d}".rstrip() for n, v, d in log.tests if v == "FAIL"]
    if timed_out:
        problems.append(f"timeout after {timed_out}s: the kernel did not power off")

    names = [n for n, _, _ in log.tests]
    for name in sorted({n for n in names if names.count(n) > 1}):
        problems.append(f"{name}: reported {names.count(name)} times")

    if len(log.plans) != 1:
        problems.append(f"expected one NK-TEST-PLAN line, found {len(log.plans)}")
    elif log.plans[0] != len(log.tests):
        problems.append(f"plan declared {log.plans[0]} verdicts, {len(log.tests)} were reported")

    if len(log.completes) != 1:
        problems.append(f"expected one NK-TEST-COMPLETE line, found {len(log.completes)}")
    else:
        counted = tuple(sum(1 for _, v, _ in log.tests if v == k) for k in ("OK", "FAIL", "SKIP"))
        if log.completes[0] != counted:
            problems.append(
                f"totals pass/fail/skip {log.completes[0]} do not match the lines {counted}")
        if log.completes[0][1] != 0:
            problems.append(f"{log.completes[0][1]} failed")
    return problems


# The kernel marks the start and end of a stall it believes lasts this
# long; the harness times the marks with the host's clock.
MARKED_SECONDS = 2.0


def _clock_problems(log, marks):
    """Check NK's second against the host's. The lower bound is strict: a
    stall may run long on a busy host but never short, and a kernel whose
    clock runs fast shows up as a short one. `marks` are the host times at
    which the kernel's NK-CLOCK-MARK lines arrived."""
    printed = sum(1 for l in log.lines if l.startswith("NK-CLOCK-MARK"))
    if printed == 0:
        return []
    if printed != 2 or marks is None or len(marks) != 2:
        return [f"expected two clock marks, the log has {printed}"]
    elapsed = marks[1] - marks[0]
    if elapsed < 0.95 * MARKED_SECONDS:
        return [f"{MARKED_SECONDS:g} s by NK's clock took {elapsed:.2f} s by the host's: "
                "NK's clock runs fast"]
    if elapsed > 10 * MARKED_SECONDS:
        return [f"{MARKED_SECONDS:g} s by NK's clock took {elapsed:.2f} s by the host's: "
                "NK's clock runs slow"]
    return []


def firmware_hung(text, timed_out):
    """Whether a boot that had to be killed never got as far as NK: the
    machine's firmware did not start the loader, whose first act is to
    print a line beginning `nkload:`. Nothing of NK's ran, so the boot
    says nothing about NK and may be tried again."""
    return bool(timed_out) and "nkload:" not in text


def _golden_problems(log, golden, degraded):
    """Compare the verdicts with the committed list for this scenario.

    `golden` maps each test name to "ok" or "skip". A test that vanishes,
    appears, or silently turns into a skip is a failure. `degraded` (driver
    fixtures are absent) allows ok -> skip and nothing else.
    """
    problems = []
    seen = log.verdicts()
    for name in sorted(golden.keys() - seen.keys()):
        problems.append(f"{name}: in the golden list but not run")
    for name in sorted(seen.keys() - golden.keys()):
        problems.append(f"{name}: run but not in the golden list")
    for name in sorted(golden.keys() & seen.keys()):
        want, got = golden[name], seen[name].lower()
        if got == "fail" or got == want:
            continue  # a failure is already reported as one
        if want == "ok" and got == "skip" and degraded:
            continue
        problems.append(f"{name}: golden list says {want}, the run says {got}")
    return problems


def _bugcheck_problems(log, match, then, timed_out):
    """Problems of a boot that should have ended in an armed bugcheck."""
    problems = [f"malformed test line: {l}" for l in log.malformed]
    problems += log.verify
    problems += [f"NK-TEST {n}:FAIL {d}".rstrip() for n, v, d in log.tests if v == "FAIL"]
    if timed_out:
        problems.append(f"timeout after {timed_out}s: the kernel did not power off")
    if log.completes:
        problems.append("the tests ran to completion; a bugcheck was expected")
    bugchecks = [(n, l) for n, l in log.fatal if "BUGCHECK" in l]
    if len(log.armed) != 1:
        problems.append(f"expected one NK-NEG-ARMED line, found {len(log.armed)}")
    if len(bugchecks) != 1:
        problems.append(f"expected one BUGCHECK line, found {len(bugchecks)}")
        problems += [l for _, l in bugchecks]
    elif log.armed and bugchecks[0][0] < log.armed[0][0]:
        problems.append(f"bugcheck before the test was armed: {bugchecks[0][1]}")
    elif not re.search(match, bugchecks[0][1]):
        problems.append(f"bugcheck does not match /{match}/: {bugchecks[0][1]}")
    elif then and not any(re.search(then, l) for l in log.lines[bugchecks[0][0] + 1:]):
        problems.append(f"no line after the bugcheck matches /{then}/")
    return problems


def judge(text, expect="ok", *, golden=None, degraded=False, match=None,
          then=None, must_fail=(), timed_out=0, marks=None):
    """Return the list of problems; an empty list means the boot passed.

    text       the serial log
    expect     "ok", "bugcheck" or "fail"
    golden     {name: "ok"|"skip"} to compare against, or None
    degraded   driver fixtures are missing: ok may become skip
    match      regular expression the bugcheck line must contain
    then       regular expression a line after the bugcheck line must
               contain: what a bugcheck callback printed
    must_fail  for expect="fail": exactly these tests must fail
    timed_out  the timeout in seconds if QEMU had to be killed, else 0
    marks      host times at which the kernel's clock marks arrived
    """
    log = Log(text)
    if expect == "bugcheck":
        return _bugcheck_problems(log, match or "", then, timed_out)

    problems = _run_problems(log, timed_out) + _clock_problems(log, marks)
    # A run that never finished has said why above; listing every test it
    # did not reach would only bury that.
    if golden is not None and len(log.completes) == 1:
        problems += _golden_problems(log, golden, degraded)
    if expect == "ok":
        return problems

    if expect != "fail":
        raise ValueError(f"unknown expectation {expect!r}")
    # The run must have been judged a failure, for exactly the stated
    # reason: the named tests failed and nothing else went wrong.
    failed = sorted(n for n, v, _ in log.tests if v == "FAIL")
    wanted = sorted(must_fail)
    inverted = []
    if not problems:
        inverted.append("the boot was judged a pass; a failure was expected")
    if failed != wanted:
        inverted.append(f"expected exactly {wanted} to fail, got {failed}")
    allowed = [f"NK-TEST {n}:FAIL" for n in wanted] + [f"{len(wanted)} failed"]
    for p in problems:
        if not any(p == a or p.startswith(a + " ") for a in allowed):
            inverted.append(f"unexpected problem: {p}")
    return inverted
