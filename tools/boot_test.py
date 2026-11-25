#!/usr/bin/env python3
"""Boot NK under QEMU and judge the result from the serial log.

Usage: boot_test.py <x86_64|aarch64> [--run] [--image <esp.img>]

Default (test) mode boots headless with a timeout and passes only if all of
these hold:
  - the kernel printed `NK-TEST-COMPLETE ... fail=0`
  - no line reports a failure, a panic or a bugcheck
  - QEMU exited by itself (the kernel powered the machine off)

`--run` boots with the serial console on this terminal instead (Ctrl-A X
quits) and judges nothing.

`--image` boots an existing EFI system partition image (for example one
from `make dist`) instead of building one. The image is opened as a
snapshot and never written.

Everything the run creates lives in target/qemu/. The ESP image and the
firmware variable copy are removed afterwards; the serial log and the
kernel's export list are kept. QEMU runs in its own process group and is
killed on any exit path, including Ctrl-C.
"""

import os
import re
import shutil
import signal
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import mkesp  # noqa: E402

ROOT = Path(__file__).resolve().parent.parent
OUT = Path(os.environ.get("QEMU_LOG_DIR", ROOT / "target" / "qemu"))
TIMEOUT = int(os.environ.get("BOOT_TEST_TIMEOUT", "120"))
SMP = os.environ.get("QEMU_SMP", "4")
MEM = os.environ.get("QEMU_MEM", "512M")
BAD = re.compile(r"NK-TEST \S+:FAIL|KERNEL PANIC|BUGCHECK")

FIRMWARE = {
    "x86_64": ("/usr/share/OVMF/OVMF_CODE_4M.fd", "/usr/share/OVMF/OVMF_VARS_4M.fd"),
    "aarch64": ("/usr/share/AAVMF/AAVMF_CODE.fd", "/usr/share/AAVMF/AAVMF_VARS.fd"),
}


def qemu_command(arch, esp, variables, serial):
    code, _ = FIRMWARE[arch]
    if arch == "x86_64":
        kvm = os.access("/dev/kvm", os.R_OK | os.W_OK) and not os.environ.get("NO_KVM")
        cmd = ["qemu-system-x86_64", "-machine", "q35"]
        cmd += ["-enable-kvm", "-cpu", "host"] if kvm else ["-cpu", "max"]
    else:
        # TCG on an x86 host. gic-version=3 and ACPI are what Windows on
        # arm64 expects of the `virt` machine.
        cmd = ["qemu-system-aarch64", "-machine", "virt,gic-version=3", "-cpu", "neoverse-n1"]
    return cmd + [
        "-m", MEM, "-smp", SMP,
        "-drive", f"if=pflash,format=raw,readonly=on,file={code}",
        "-drive", f"if=pflash,format=raw,file={variables}",
        "-drive", f"if=none,id=esp,format=raw,snapshot=on,file={esp}",
        "-device", "virtio-blk-pci,drive=esp,bootindex=0",
        "-nic", "none", "-display", "none", "-monitor", "none", "-no-reboot",
        "-serial", serial,
    ]


def judge(arch, log_path, timed_out):
    text = log_path.read_text(errors="replace") if log_path.exists() else ""
    lines = [l.strip() for l in text.splitlines()]
    exports = [l for l in lines if l.startswith("NK-EXPORT ")]
    if exports:
        (OUT / f"exports-{arch}.txt").write_text("\n".join(exports) + "\n")
    tests = [l for l in lines if l.startswith("NK-TEST ")]
    done = [l for l in lines if l.startswith("NK-TEST-COMPLETE")]
    problems = [l for l in lines if BAD.search(l)]
    if timed_out:
        problems.append(f"timeout after {TIMEOUT}s: the kernel did not power off")
    if not done:
        problems.append("no NK-TEST-COMPLETE line")
    elif "fail=0" not in done[-1]:
        problems.append(done[-1])

    for l in tests:
        if ":OK" not in l:
            print(f"  {l}")
    print(f"  {done[-1] if done else '(no totals)'}")
    if problems:
        print(f"boot test {arch}: FAILED")
        for p in problems:
            print(f"  {p}")
        print(f"  last serial lines ({log_path}):")
        for l in [l for l in lines if l][-8:]:
            print(f"    {l}")
        return 1
    print(f"boot test {arch}: PASSED")
    return 0


def main():
    argv = sys.argv[1:]
    given = None
    if "--image" in argv:
        i = argv.index("--image")
        if i + 1 >= len(argv):
            sys.exit(__doc__)
        given = Path(argv[i + 1])
        del argv[i:i + 2]
    args = [a for a in argv if not a.startswith("--")]
    if len(args) != 1 or args[0] not in FIRMWARE:
        sys.exit(__doc__)
    arch, interactive = args[0], "--run" in argv
    for f in FIRMWARE[arch]:
        if not Path(f).exists():
            sys.exit(f"boot_test: firmware {f} not found (see DEVELOPMENT.md)")
    if given and not given.exists():
        sys.exit(f"boot_test: {given} not found")

    OUT.mkdir(parents=True, exist_ok=True)
    esp = given or OUT / f"esp-{arch}.img"
    variables = OUT / f"vars-{arch}.fd"
    log = OUT / f"serial-{arch}.log"
    log.unlink(missing_ok=True)
    proc, timed_out = None, False
    try:
        if not given:
            mkesp.build(arch, esp)
        shutil.copyfile(FIRMWARE[arch][1], variables)
        serial = "mon:stdio" if interactive else f"file:{log}"
        proc = subprocess.Popen(
            qemu_command(arch, esp, variables, serial),
            stdin=None if interactive else subprocess.DEVNULL,
            start_new_session=not interactive,
        )
        try:
            proc.wait(timeout=None if interactive else TIMEOUT)
        except subprocess.TimeoutExpired:
            timed_out = True
    finally:
        if proc and proc.poll() is None:
            try:
                os.killpg(proc.pid, signal.SIGKILL) if not interactive else proc.kill()
            except ProcessLookupError:
                pass
            proc.wait()
        if not given:
            esp.unlink(missing_ok=True)
        variables.unlink(missing_ok=True)
    return 0 if interactive else judge(arch, log, timed_out)


if __name__ == "__main__":
    sys.exit(main())
