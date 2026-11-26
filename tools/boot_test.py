#!/usr/bin/env python3
"""Boot NK under QEMU and judge the result from the serial log.

Usage:
  boot_test.py <scenario>            run one scenario from tools/scenarios.toml
  boot_test.py --tier <tier>         run every scenario of a tier, in parallel
  boot_test.py <scenario> --run      serial console on this terminal, no verdict
  boot_test.py <scenario> --image <esp.img>
                                     boot an existing image (e.g. from `make
                                     dist`) instead of building one
  boot_test.py --tier <tier> --repeat <n>
                                     every scenario of the tier n times, on
                                     an overloaded host (`make soak`)
  boot_test.py <scenario> --bless    rewrite the scenario's golden list from
                                     this run
  boot_test.py --failures <log>      from the saved output of a tier, print
                                     what the boots that failed said, and
                                     the tier's last line; status 1 if the
                                     log names no failed boot

What passing means is the scenario's `expect` (see tools/judge.py). A hung
boot is killed at the timeout, after every CPU's registers are saved.

Each scenario works in target/qemu/<scenario>/. QEMU runs in its own
session, is killed on every exit path (success, failure, timeout, Ctrl-C,
SIGTERM), and dies with this process even if this process is killed
outright. A passing run deletes its directory; a failing run keeps the
logs and says where. The logs of the scenarios marked `canonical` are also
kept as target/qemu/serial-<arch>.log and exports-<arch>.txt.

Environment: BOOT_TEST_TIMEOUT (seconds, default 120), QEMU_SMP, QEMU_MEM,
NO_KVM=1 (emulate x86-64 too), JOBS (parallel boots in a tier), KEEP=1
(keep every scenario directory), QEMU_LOG_DIR (default target/qemu).
"""

import concurrent.futures
import ctypes
import json
import os
import shutil
import signal
import socket
import subprocess
import sys
import threading
import time
import tomllib
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import judge  # noqa: E402
import mkesp  # noqa: E402

ROOT = Path(__file__).resolve().parent.parent
TOOLS = ROOT / "tools"
OUT = Path(os.environ.get("QEMU_LOG_DIR", ROOT / "target" / "qemu")).resolve()
TIMEOUT = int(os.environ.get("BOOT_TEST_TIMEOUT", "120"))
SMP = os.environ.get("QEMU_SMP", "4")
MEM = os.environ.get("QEMU_MEM", "512M")
KEEP = bool(os.environ.get("KEEP"))

FIRMWARE = {
    "x86_64": ("/usr/share/OVMF/OVMF_CODE_4M.fd", "/usr/share/OVMF/OVMF_VARS_4M.fd"),
    "aarch64": ("/usr/share/AAVMF/AAVMF_CODE.fd", "/usr/share/AAVMF/AAVMF_VARS.fd"),
}

_LIBC = ctypes.CDLL(None, use_errno=True)
PR_SET_PDEATHSIG = 1


def die_with_parent():
    """Run in a child before exec: be killed when the parent dies, however
    it dies. Without this a SIGKILLed harness would leave QEMU running."""
    _LIBC.prctl(PR_SET_PDEATHSIG, signal.SIGKILL)


def load_scenarios():
    return tomllib.loads((TOOLS / "scenarios.toml").read_text())


def golden_path(name):
    return TOOLS / "golden" / f"{name}.txt"


def load_golden(name):
    """{test name: "ok"|"skip"} from tools/golden/<name>.txt."""
    golden = {}
    for line in golden_path(name).read_text().splitlines():
        if line and not line.startswith("#"):
            test, verdict = line.split()
            golden[test] = verdict
    return golden


def kvm_usable():
    return os.access("/dev/kvm", os.R_OK | os.W_OK) and not os.environ.get("NO_KVM")


def smp_of(sc):
    """Guest CPUs: the scenario's `smp`, else QEMU_SMP, else 4."""
    return int(sc.get("smp", SMP))


def kernel_cmdline(sc):
    """The scenario's command line, plus the CPU count the kernel should
    find, so that a processor that fails to show up fails a test."""
    words = sc.get("cmdline", "").split()
    if not any(w.startswith("cpus=") for w in words):
        words.append(f"cpus={smp_of(sc)}")
    return " ".join(words)


def qemu_command(arch, smp, interactive):
    """The command line. Paths are relative to the scenario directory, where
    QEMU is started, so the QMP socket path stays short."""
    code, _ = FIRMWARE[arch]
    if arch == "x86_64":
        cmd = ["qemu-system-x86_64", "-machine", "q35"]
        cmd += ["-enable-kvm", "-cpu", "host"] if kvm_usable() else ["-cpu", "max"]
    else:
        # TCG on an x86 host. gic-version=3 and ACPI are what Windows on
        # arm64 expects of the `virt` machine.
        cmd = ["qemu-system-aarch64", "-machine", "virt,gic-version=3", "-cpu", "neoverse-n1"]
    cmd += [
        "-m", MEM, "-smp", str(smp),
        "-drive", f"if=pflash,format=raw,readonly=on,file={code}",
        "-drive", "if=pflash,format=raw,file=vars.fd",
        "-drive", "if=none,id=esp,format=raw,snapshot=on,file=esp.img",
        "-device", "virtio-blk-pci,drive=esp,bootindex=0",
        "-nic", "none", "-display", "none", "-no-reboot",
    ]
    if interactive:
        return cmd + ["-serial", "mon:stdio"]
    return cmd + [
        "-monitor", "none", "-serial", "stdio", "-pidfile", "qemu.pid",
        "-qmp", "unix:qmp.sock,server=on,wait=off",
    ]


def qmp(directory, commands):
    """Send QMP commands to the scenario's QEMU; return their results.
    Best effort: a QEMU too far gone to answer yields an error string."""
    results = []
    try:
        with socket.socket(socket.AF_UNIX) as s:
            s.settimeout(5)
            # A relative path keeps within the socket-name length limit.
            cwd = os.getcwd()
            os.chdir(directory)
            try:
                s.connect("qmp.sock")
            finally:
                os.chdir(cwd)
            f = s.makefile("rw")

            def reply():
                while True:
                    msg = json.loads(f.readline())
                    if "return" in msg or "error" in msg:
                        return msg

            json.loads(f.readline())  # greeting
            for command in [{"execute": "qmp_capabilities"}] + commands:
                f.write(json.dumps(command) + "\n")
                f.flush()
                results.append(reply())
    except (OSError, ValueError) as e:
        results.append({"error": str(e)})
    return results[1:]


def hang_evidence(arch, directory):
    """A hung kernel says nothing more on its own: record where every CPU
    is, then (x86) send an NMI so the kernel dumps its own view."""
    dump = qmp(directory, [{
        "execute": "human-monitor-command",
        "arguments": {"command-line": "info registers -a"},
    }])
    text = "\n".join(str(r.get("return", r)) for r in dump)
    (directory / "hang-registers.txt").write_text(text + "\n")
    if arch == "x86_64":
        qmp(directory, [{"execute": "inject-nmi"}])
        time.sleep(1)


def kill_stale(directory):
    """Kill a QEMU left behind by an earlier run of this scenario."""
    try:
        pid = int((directory / "qemu.pid").read_text())
        cmdline = Path(f"/proc/{pid}/cmdline").read_bytes()
        cwd = os.readlink(f"/proc/{pid}/cwd")
    except (OSError, ValueError):
        return
    if b"qemu-system" in cmdline and Path(cwd) == directory:
        try:
            os.kill(pid, signal.SIGKILL)
        except ProcessLookupError:
            pass


def boot(arch, smp, directory, interactive):
    """Run QEMU in `directory` (which holds esp.img and vars.fd). Returns
    the timeout in seconds if it had to be killed (else 0), and the host
    times at which the kernel's clock marks arrived. The serial output
    goes to serial.log there."""
    proc, timed_out, marks = None, 0, []
    try:
        if interactive:
            proc = subprocess.Popen(qemu_command(arch, smp, True), cwd=directory)
            proc.wait()
            return 0, marks
        with open(directory / "serial.log", "wb") as log, \
                open(directory / "qemu.err", "wb") as err:
            proc = subprocess.Popen(
                qemu_command(arch, smp, False), cwd=directory,
                stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=err,
                start_new_session=True, preexec_fn=die_with_parent,
            )

            def pump():
                # Unbuffered copy: a hung boot still leaves what it printed.
                # Note when each clock mark arrives, by the host's clock.
                tail = b""
                for chunk in iter(lambda: proc.stdout.read1(4096), b""):
                    log.write(chunk)
                    log.flush()
                    *lines, tail = (tail + chunk).split(b"\n")
                    marks.extend(time.monotonic() for l in lines if b"NK-CLOCK-MARK" in l)

            reader = threading.Thread(target=pump, daemon=True)
            reader.start()
            try:
                proc.wait(timeout=TIMEOUT)
            except subprocess.TimeoutExpired:
                timed_out = TIMEOUT
                hang_evidence(arch, directory)
            finally:
                kill(proc)
                reader.join()
        return timed_out, marks
    finally:
        if proc:
            kill(proc)


def kill(proc):
    if proc.poll() is None:
        try:
            # QEMU leads its own session: take the whole group.
            os.killpg(proc.pid, signal.SIGKILL)
        except (ProcessLookupError, PermissionError):
            proc.kill()
    proc.wait()


def run_scenario(name, sc, image=None, interactive=False, bless=False, instance=None):
    arch = sc["arch"]
    for f in FIRMWARE[arch]:
        if not Path(f).exists():
            sys.exit(f"boot_test: firmware {f} not found (see DEVELOPMENT.md)")
    if image and not image.exists():
        sys.exit(f"boot_test: {image} not found")

    # A scenario repeated in one run gets a directory per repetition.
    directory = OUT / (name if instance is None else f"{name}.{instance}")
    if sc.get("accel") == "tcg":
        os.environ["NO_KVM"] = "1"
    kill_stale(directory)
    shutil.rmtree(directory, ignore_errors=True)
    directory.mkdir(parents=True)
    esp = directory / "esp.img"
    passed = False
    try:
        if image:
            # Booted as a snapshot, never written; a link keeps it in place.
            esp.symlink_to(image.resolve())
            missing = ["(prebuilt image)"]
        else:
            missing = mkesp.build(arch, esp, cmdline=kernel_cmdline(sc))
        shutil.copyfile(FIRMWARE[arch][1], directory / "vars.fd")
        timed_out, marks = boot(arch, smp_of(sc), directory, interactive)
        if interactive:
            passed = True
            return 0

        text = (directory / "serial.log").read_text(errors="replace")
        if judge.firmware_hung(text, timed_out):
            # Rare, and not NK: the firmware itself hung before starting
            # the loader. Say so, keep what was saved, and boot once
            # more; a second hang is judged like any other.
            print(f"boot test {name}: firmware never started the loader; booting once more")
            for kept in ("serial.log", "hang-registers.txt"):
                if (directory / kept).exists():
                    (directory / kept).rename(directory / f"firmware-hang.{kept}")
            shutil.copyfile(FIRMWARE[arch][1], directory / "vars.fd")
            timed_out, marks = boot(arch, smp_of(sc), directory, interactive)
            text = (directory / "serial.log").read_text(errors="replace")
        log = judge.Log(text)
        golden = load_golden(sc["golden"]) if "golden" in sc and not bless else None
        problems = judge.judge(
            text, sc.get("expect", "ok"), golden=golden, degraded=bool(missing),
            match=sc.get("match"), then=sc.get("then"),
            must_fail=sc.get("must_fail", ()),
            timed_out=timed_out, marks=marks,
        )
        if sc.get("canonical") and not image:
            shutil.copyfile(directory / "serial.log", OUT / f"serial-{arch}.log")
            if log.exports():
                (OUT / f"exports-{arch}.txt").write_text("\n".join(log.exports()) + "\n")
                (OUT / f"lookups-{arch}.txt").write_text("".join(f"{l}\n" for l in log.lookups()))

        for test, verdict, detail in log.tests:
            if verdict != "OK":
                print(f"  NK-TEST {test}:{verdict} {detail}".rstrip())
        if missing:
            print(f"  fixtures absent, their tests may skip: {', '.join(missing)}")
        if problems:
            print(f"boot test {name}: FAILED")
            for p in problems:
                print(f"  {p}")
            print(f"  last serial lines ({directory / 'serial.log'}):")
            for line in log.tail():
                print(f"    {line}")
            return 1
        if bless and "golden" in sc:
            lines = [f"{t} {v.lower()}" for t, v, _ in log.tests]
            golden_path(sc["golden"]).write_text("\n".join(lines) + "\n")
            print(f"  wrote {golden_path(sc['golden']).relative_to(ROOT)}")
        expect = sc.get("expect", "ok")
        counts = log.completes[0] if log.completes else (0, 0, 0)
        detail = f"pass={counts[0]} skip={counts[2]}" if expect == "ok" else f"expected {expect}"
        print(f"boot test {name}: PASSED ({detail})")
        passed = True
        return 0
    finally:
        # The image and the firmware variables are rebuilt each run and
        # never help a diagnosis; the logs stay unless the run passed.
        for scratch in ("esp.img", "vars.fd", "qmp.sock", "qemu.pid"):
            (directory / scratch).unlink(missing_ok=True)
        if passed and not KEEP:
            shutil.rmtree(directory, ignore_errors=True)


def run_tier(tier, scenarios, repeat=1):
    """Run every scenario of `tier`, `repeat` times each, several at a
    time, each in its own process so that one cannot disturb another."""
    names = [n for n, sc in scenarios.items() if sc.get("tier") == tier]
    if not names:
        sys.exit(f"boot_test: no scenario in tier {tier!r}")
    # Each boot runs up to its `smp` guest CPUs flat out. The gate keeps
    # within the host's processors. A repeated run asks for twice that on
    # purpose: a host with more to do than it can do at once makes guest
    # processors stall at arbitrary instants, which is what shakes races
    # out.
    widest = max(smp_of(scenarios[n]) for n in names)
    cpus = os.cpu_count() or 1
    default_jobs = cpus // widest if repeat == 1 else 2 * cpus // widest
    jobs = int(os.environ.get("JOBS", max(1, default_jobs)))
    runs = [(n, i) for i in range(repeat) for n in names]
    children, lock = [], threading.Lock()

    def one(run):
        name, instance = run
        command = [sys.executable, __file__, name]
        if repeat > 1:
            command += ["--instance", str(instance)]
        proc = subprocess.Popen(
            command, stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT, text=True, preexec_fn=die_with_parent,
        )
        with lock:
            children.append(proc)
        out, _ = proc.communicate()
        return name if repeat == 1 else f"{name}.{instance}", proc.returncode, out

    failed = []
    pool = concurrent.futures.ThreadPoolExecutor(max_workers=jobs)
    try:
        for name, status, out in pool.map(one, runs):
            if status == 0:
                # A long run says only what went wrong, and what was
                # retried.
                if repeat == 1:
                    print(out.strip().splitlines()[-1])
                for line in out.splitlines():
                    if repeat > 1 and "once more" in line:
                        print(line)
            else:
                failed.append(name)
                print(out.rstrip())
                # A boot that died without a verdict still gets the line
                # `failures` finds it by.
                if not any(is_failed_line(line) for line in out.splitlines()):
                    print(f"boot test {name}: FAILED (exit status {status}, no verdict)")
    finally:
        # Reached on Ctrl-C or SIGTERM too: each child then cleans up its
        # own QEMU and files.
        with lock:
            for proc in children:
                if proc.poll() is None:
                    proc.terminate()
        pool.shutdown(wait=True, cancel_futures=True)
    if failed:
        print(f"tier {tier}: FAILED {len(failed)} of {len(runs)} boots ({', '.join(failed)})")
        return 1
    if repeat == 1:
        print(f"tier {tier}: {len(names)} scenarios passed")
    else:
        print(f"tier {tier}: {len(runs)} boots passed ({len(names)} scenarios, {repeat} times each)")
    return 0


def is_failed_line(line):
    return line.startswith("boot test ") and ": FAILED" in line


def failures(text):
    """From the output of a tier, the lines of the boots that failed: each
    one's `boot test <name>: FAILED` line and what follows it, up to the
    next boot's line; then the tier's own last line and anything after
    it. Empty if no boot is reported as failed: the output is then of
    something else that went wrong (a build, say).

    The boots of a tier are printed in the order they were listed, so the
    one that failed can be far from the end of a long output."""
    kept, showing, any_failed = [], False, False
    for line in text.splitlines():
        if line.startswith("boot test "):
            showing = is_failed_line(line)
            any_failed |= showing
        elif line.startswith("tier "):
            showing = True
        if showing:
            kept.append(line)
    return kept if any_failed else []


def main():
    argv = sys.argv[1:]

    def option(flag):
        if flag not in argv:
            return None
        i = argv.index(flag)
        if i + 1 >= len(argv):
            sys.exit(__doc__)
        value = argv[i + 1]
        del argv[i:i + 2]
        return value

    log = option("--failures")
    if log:
        if argv:
            sys.exit(__doc__)
        lines = failures(Path(log).read_text(errors="replace"))
        for line in lines:
            print(line)
        return 0 if lines else 1
    image, tier = option("--image"), option("--tier")
    repeat, instance = int(option("--repeat") or 1), option("--instance")
    flags = {a for a in argv if a.startswith("--")}
    args = [a for a in argv if not a.startswith("--")]
    scenarios = load_scenarios()
    if flags - {"--run", "--bless"}:
        sys.exit(__doc__)
    # Turn a polite kill into an exception, so every `finally` runs.
    for sig in (signal.SIGTERM, signal.SIGHUP):
        signal.signal(sig, lambda n, _: sys.exit(128 + n))
    OUT.mkdir(parents=True, exist_ok=True)
    if tier:
        if args or flags or image:
            sys.exit(__doc__)
        return run_tier(tier, scenarios, repeat)
    if len(args) != 1 or args[0] not in scenarios:
        sys.exit(f"{__doc__}\nscenarios: {', '.join(scenarios)}")
    return run_scenario(
        args[0], scenarios[args[0]], image=Path(image) if image else None,
        interactive="--run" in flags, bless="--bless" in flags, instance=instance,
    )


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        sys.exit(130)
