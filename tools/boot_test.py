#!/usr/bin/env python3
"""Boot NK under QEMU and judge the result from the serial log.

Usage:
  boot_test.py <scenario>            run one scenario from tools/scenarios.toml
  boot_test.py --tier <tier>         run every scenario of a tier, in parallel
  boot_test.py --gate fast|batch|full
                                     run the gate tier's scenarios that this
                                     gate selects (below), in parallel
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

The three gates (`make gate-fast`, `gate`, `gate-full`) each boot a
selection of the gate tier (`select`):

  fast   the scenario `x86_64`, and the x86-64 scenarios whose `paths`
         name a file changed since the merge base with the branch
         `updates` ($GATE_BASE names another commit to compare with)
  batch  every x86-64 scenario that must pass (`expect = "ok"`); those
         that must end in a bugcheck or a failed test only when their
         `paths` name a file changed since the commit the batch gate last
         passed at (target/gate-passed, written by tools/gate.sh)
  full   every scenario of the tier, on both architectures

A file is changed if it differs between that commit and the working tree,
or is not yet tracked. Where the commit is not known (no branch `updates`,
no target/gate-passed, as in CI) every file counts as changed.

Each scenario works in target/qemu/<scenario>/. QEMU runs in its own
session, is killed on every exit path (success, failure, timeout, Ctrl-C,
SIGTERM), and dies with this process even if this process is killed
outright. A passing run deletes its directory; a failing run keeps the
logs and says where. The logs of the scenarios marked `canonical` are also
kept as target/qemu/serial-<arch>.log and exports-<arch>.txt.

A scenario with `disk` gets a data disk, data.img in its directory, made
before the boot and compared after it with what the scenario's
`disk_expect` allows (tools/datadisk.py).

Environment: BOOT_TEST_TIMEOUT (seconds, default 120), QEMU_SMP, QEMU_MEM,
NO_KVM=1 (emulate x86-64 too), JOBS (parallel boots in a tier), KEEP=1
(keep every scenario directory), QEMU_LOG_DIR (default target/qemu),
GATE_BASE (above).
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
import datadisk  # noqa: E402
import fatdisk  # noqa: E402
import judge  # noqa: E402
import mkesp  # noqa: E402

ROOT = Path(__file__).resolve().parent.parent
TOOLS = ROOT / "tools"
OUT = Path(os.environ.get("QEMU_LOG_DIR", ROOT / "target" / "qemu")).resolve()
TIMEOUT = int(os.environ.get("BOOT_TEST_TIMEOUT", "120"))
SMP = os.environ.get("QEMU_SMP", "4")
MEM = os.environ.get("QEMU_MEM", "512M")
KEEP = bool(os.environ.get("KEEP"))
# The commit the batch gate last passed at (tools/gate.sh writes it).
GATE_PASSED = ROOT / "target" / "gate-passed"

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


def golden_dir(name):
    return TOOLS / "golden" / name


def golden_file(test):
    """The file of a golden list a test is in: the first word of its name."""
    return test.split(".")[0] + ".txt"


def load_golden(name):
    """{test name: "ok"|"skip"} from the files of tools/golden/<name>/."""
    golden = {}
    lines = [line for path in sorted(golden_dir(name).glob("*.txt"))
             for line in path.read_text().splitlines()]
    for line in lines:
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


def disk_devices(arch, disk):
    """QEMU's arguments for the scenario's data disk (`disk`: "ahci", "nvme"
    or None). Not a snapshot: what the guest writes has to be in the file
    after the boot."""
    if disk is None:
        return []
    drive = ["-drive", "if=none,id=nkdata,format=raw,file=data.img"]
    if disk == "ahci":
        if arch == "x86_64":
            # q35 has an ICH9 AHCI controller; its ports are the bus `ide`.
            return drive + ["-device", "ide-hd,drive=nkdata,bus=ide.0"]
        # `virt` has none: the same controller, as a PCIe device.
        return drive + ["-device", "ich9-ahci,id=ahci", "-device", "ide-hd,drive=nkdata,bus=ahci.0"]
    if disk == "nvme":
        if arch != "x86_64":
            raise ValueError("nvme disk is supported on x86_64 only")
        return drive + ["-device", "nvme,drive=nkdata,serial=nk-nvme"]
    raise ValueError(f"unknown disk {disk!r}")


def extra_devices(arch, usb=None, usb_kbd=False, serial2=False):
    """QEMU's arguments for optional Phase 5 devices: xHCI host controller,
    preattached USB keyboard, and secondary ISA UART backed by a host socket."""
    args = []
    if usb is not None:
        if usb != "xhci" or arch != "x86_64":
            raise ValueError(f"unsupported usb {usb!r} on {arch}")
        args += ["-device", "qemu-xhci,id=xhci"]
        if usb_kbd:
            args += ["-device", "usb-kbd,bus=xhci.0,port=1,id=kbd0"]
    elif usb_kbd:
        raise ValueError("usb_kbd requires usb = 'xhci'")
    if serial2:
        if arch != "x86_64":
            raise ValueError("serial2 is supported on x86_64 only")
        args += [
            "-chardev", "socket,id=ser2,path=ser2.sock,server=on,wait=off",
            "-device", "isa-serial,index=1,chardev=ser2",
        ]
    return args


def qemu_command(arch, smp, interactive, disk=None, usb=None, usb_kbd=False, serial2=False):
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
    cmd += disk_devices(arch, disk)
    cmd += extra_devices(arch, usb=usb, usb_kbd=usb_kbd, serial2=serial2)
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


SERIAL2_EXPECT = b"NK-SER-TX:HELLO-HOST\n"
SERIAL2_REPLY = b"NK-SER-RX:HELLO-GUEST\n"

# QMP key sequences sent on `NK-QMP-KEYS <name>` markers.
QMP_KEY_SEQS = {
    "seq1": [["a"], ["b"]],
    "seq2": [["shift", "c"], ["d"]],
}


def _connect_unix(directory, sock_name, timeout=20.0):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        s = socket.socket(socket.AF_UNIX)
        try:
            s.settimeout(5)
            s.connect(str(directory / sock_name))
            return s
        except OSError:
            s.close()
            time.sleep(0.05)
    raise TimeoutError(f"timed out connecting to {sock_name}")


def run_serial2_peer(directory, stop_event, errors):
    """Host peer for the secondary ISA UART (`serial2 = true`). Reads the
    expected guest->host payload and sends a distinct host->guest payload."""
    try:
        s = _connect_unix(directory, "ser2.sock", timeout=30.0)
    except OSError as e:
        errors.append(f"serial2 peer failed to connect: {e}")
        return
    try:
        s.settimeout(0.2)
        buf = bytearray()
        deadline = time.monotonic() + TIMEOUT
        while not stop_event.is_set() and time.monotonic() < deadline:
            try:
                chunk = s.recv(256)
                if not chunk:
                    break
                buf.extend(chunk)
                if SERIAL2_EXPECT in buf:
                    s.sendall(SERIAL2_REPLY)
                    (directory / "serial2.log").write_bytes(bytes(buf))
                    # Keep the peer socket open until QEMU exits so QEMU's
                    # chardev does not disconnect on HUP before the 16550 FIFO
                    # drains all reply bytes.
                    stop_event.wait(timeout=TIMEOUT)
                    return
            except TimeoutError:
                continue
        (directory / "serial2.log").write_bytes(bytes(buf))
        errors.append(f"serial2 peer did not receive expected guest payload (got {bytes(buf)!r})")
    except OSError as e:
        errors.append(f"serial2 peer I/O error: {e}")
    finally:
        s.close()


class QmpSession:
    """Persistent QMP connection supporting command replies and async events
    (such as `DEVICE_DELETED`) for host-driven USB hotplug scenarios.

    Uses raw `socket.recv()` with an internal byte buffer rather than
    `socket.makefile()`, because a `TimeoutError` on a Python `BufferedReader`
    invalidates the file wrapper and drops subsequent reads."""

    def __init__(self, directory=None, sock=None, stop_event=None):
        self.stop_event = stop_event
        if sock is None:
            self.sock = _connect_unix(directory, "qmp.sock", timeout=30.0)
        else:
            self.sock = sock
        self._buf = bytearray()
        self.events = []
        greeting = self._readline(timeout=20.0)
        if not greeting:
            raise OSError("QMP socket closed before greeting")
        json.loads(greeting)
        self.execute("qmp_capabilities")

    def close(self):
        self.sock.close()

    def _readline(self, timeout):
        deadline = time.monotonic() + timeout
        while True:
            if self.stop_event is not None and self.stop_event.is_set():
                raise TimeoutError("QMP session stopped")
            nl = self._buf.find(b"\n")
            if nl != -1:
                line = bytes(self._buf[:nl + 1])
                del self._buf[:nl + 1]
                return line.decode("utf-8")
            rem = deadline - time.monotonic()
            if rem <= 0:
                raise TimeoutError("timed out reading QMP line")
            slice_t = min(rem, 0.2 if self.stop_event is not None else 1.0)
            self.sock.settimeout(slice_t)
            try:
                chunk = self.sock.recv(4096)
            except TimeoutError:
                continue
            if not chunk:
                return ""
            self._buf.extend(chunk)

    def execute(self, cmd, arguments=None, timeout=20.0):
        req = {"execute": cmd}
        if arguments is not None:
            req["arguments"] = arguments
        self.sock.settimeout(timeout)
        self.sock.sendall((json.dumps(req) + "\n").encode("utf-8"))
        deadline = time.monotonic() + timeout
        while True:
            rem = deadline - time.monotonic()
            if rem <= 0:
                raise TimeoutError(f"timed out waiting for QMP reply to {cmd}")
            line = self._readline(timeout=rem)
            if not line:
                raise OSError("QMP socket closed")
            msg = json.loads(line)
            if "event" in msg:
                self.events.append(msg)
                continue
            if "error" in msg:
                raise RuntimeError(f"QMP {cmd} failed: {msg['error']}")
            if "return" in msg:
                return msg["return"]

    def wait_event(self, name, device_id=None, timeout=20.0):
        deadline = time.monotonic() + timeout
        while True:
            for i, ev in enumerate(self.events):
                if ev.get("event") == name and (
                    device_id is None or ev.get("data", {}).get("device") == device_id
                ):
                    return self.events.pop(i)
            rem = deadline - time.monotonic()
            if rem <= 0:
                raise TimeoutError(f"timed out waiting for QMP event {name} ({device_id})")
            line = self._readline(timeout=rem)
            if not line:
                raise OSError("QMP socket closed while waiting for event")
            msg = json.loads(line)
            if "event" in msg:
                self.events.append(msg)


def handle_qmp_marker(session, line, errors, actions):
    """Execute one host QMP step requested by a guest serial marker."""
    text = line.decode(errors="replace").strip()
    try:
        if "NK-QMP-ADD-KBD" in text:
            session.execute("device_add", {
                "driver": "usb-kbd", "bus": "xhci.0", "port": "1", "id": "kbd0",
            })
            actions.append("add-kbd")
        elif "NK-QMP-DEL-KBD" in text:
            session.execute("device_del", {"id": "kbd0"})
            session.wait_event("DEVICE_DELETED", device_id="kbd0", timeout=20.0)
            actions.append("del-kbd")
        elif "NK-QMP-KEYS " in text:
            seq_name = text.split("NK-QMP-KEYS ", 1)[1].split()[0]
            keys = QMP_KEY_SEQS.get(seq_name)
            if not keys:
                errors.append(f"unknown QMP key sequence {seq_name!r}")
                return
            for chord in keys:
                session.execute("send-key", {
                    "keys": [{"type": "qcode", "data": k} for k in chord],
                    "hold-time": 40,
                })
                time.sleep(0.08)
            actions.append(f"keys:{seq_name}")
    except (OSError, RuntimeError, TimeoutError, ValueError) as e:
        errors.append(f"QMP action failed for {text!r}: {e}")


def boot(arch, smp, directory, interactive, disk=None, usb=None, usb_kbd=False,
         serial2=False, hotplug=False):
    """Run QEMU in `directory` (which holds esp.img, vars.fd and, for a
    scenario with a disk, data.img). Returns
    (timed_out, marks, host_errors)."""
    proc, timed_out, marks, host_errors = None, 0, [], []
    stop_event = threading.Event()
    peer_thread = None
    qmp_queue = []
    qmp_cond = threading.Condition()
    qmp_thread = None
    qmp_actions = []
    cmd = qemu_command(arch, smp, interactive, disk=disk, usb=usb,
                       usb_kbd=usb_kbd, serial2=serial2)
    try:
        if interactive:
            proc = subprocess.Popen(cmd, cwd=directory)
            proc.wait()
            return 0, marks, host_errors
        with open(directory / "serial.log", "wb") as log, \
                open(directory / "qemu.err", "wb") as err:
            proc = subprocess.Popen(
                cmd, cwd=directory,
                stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=err,
                start_new_session=True, preexec_fn=die_with_parent,
            )
            if serial2:
                peer_thread = threading.Thread(
                    target=run_serial2_peer, args=(directory, stop_event, host_errors), daemon=True,
                )
                peer_thread.start()
            if hotplug:
                def qmp_worker():
                    try:
                        session = QmpSession(directory, stop_event=stop_event)
                    except (OSError, RuntimeError, TimeoutError) as e:
                        if not stop_event.is_set():
                            host_errors.append(f"QMP connect failed: {e}")
                        return
                    try:
                        while True:
                            with qmp_cond:
                                while not qmp_queue and not stop_event.is_set():
                                    qmp_cond.wait(timeout=0.2)
                                if stop_event.is_set():
                                    return
                                marker = qmp_queue.pop(0)
                            handle_qmp_marker(session, marker, host_errors, qmp_actions)
                    finally:
                        session.close()

                qmp_thread = threading.Thread(target=qmp_worker, daemon=True)
                qmp_thread.start()

            def pump():
                # Unbuffered copy: a hung boot still leaves what it printed.
                # Note when each clock mark arrives, by the host's clock.
                tail = b""
                for chunk in iter(lambda: proc.stdout.read1(4096), b""):
                    log.write(chunk)
                    log.flush()
                    *lines, tail = (tail + chunk).split(b"\n")
                    for l in lines:
                        if b"NK-CLOCK-MARK" in l:
                            marks.append(time.monotonic())
                        if hotplug and b"NK-QMP-" in l:
                            with qmp_cond:
                                qmp_queue.append(l)
                                qmp_cond.notify()

            reader = threading.Thread(target=pump, daemon=True)
            reader.start()
            try:
                proc.wait(timeout=TIMEOUT)
            except subprocess.TimeoutExpired:
                timed_out = TIMEOUT
                # Release the live QMP worker's socket before hang_evidence
                # connects to QEMU's single-client qmp.sock.
                stop_event.set()
                with qmp_cond:
                    qmp_cond.notify_all()
                if qmp_thread:
                    qmp_thread.join(timeout=3)
                hang_evidence(arch, directory)
            finally:
                stop_event.set()
                with qmp_cond:
                    qmp_cond.notify_all()
                kill(proc)
                reader.join()
                if peer_thread:
                    peer_thread.join(timeout=5)
                if qmp_thread:
                    qmp_thread.join(timeout=5)
        if hotplug and not qmp_actions and not host_errors and not timed_out:
            host_errors.append("hotplug scenario performed no host QMP actions")
        return timed_out, marks, host_errors
    finally:
        stop_event.set()
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


def make_disk(sc, data):
    """Write the scenario's data disk: a FAT volume if it names one
    (`disk_image`), else the pattern disk."""
    if "disk_image" in sc:
        fatdisk.create(data, sc["disk_image"])
    else:
        datadisk.create(data, sc.get("disk_size", datadisk.DEFAULT_MIB))


def check_disk(sc, data):
    """What is wrong with the data disk after the boot."""
    if "disk_image" in sc:
        return fatdisk.verify(data, sc["disk_expect"])
    return datadisk.verify(data, sc["disk_expect"], sc.get("disk_size", datadisk.DEFAULT_MIB))


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
    disk, data = sc.get("disk"), directory / "data.img"
    passed, disk_wrong = False, False
    try:
        if image:
            # Booted as a snapshot, never written; a link keeps it in place.
            esp.symlink_to(image.resolve())
            missing = ["(prebuilt image)"]
        else:
            missing = mkesp.build(arch, esp, cmdline=kernel_cmdline(sc),
                                  registry=sc.get("registry", ()))
        shutil.copyfile(FIRMWARE[arch][1], directory / "vars.fd")
        if disk:
            make_disk(sc, data)
        usb = sc.get("usb")
        usb_kbd = bool(sc.get("usb_kbd", False))
        serial2 = bool(sc.get("serial2", False))
        hotplug = bool(sc.get("hotplug", False))
        timed_out, marks, host_errors = boot(
            arch, smp_of(sc), directory, interactive, disk=disk,
            usb=usb, usb_kbd=usb_kbd, serial2=serial2, hotplug=hotplug,
        )
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
            if disk:
                make_disk(sc, data)
            timed_out, marks, host_errors = boot(
                arch, smp_of(sc), directory, interactive, disk=disk,
                usb=usb, usb_kbd=usb_kbd, serial2=serial2, hotplug=hotplug,
            )
            text = (directory / "serial.log").read_text(errors="replace")
        log = judge.Log(text)
        golden = load_golden(sc["golden"]) if "golden" in sc and not bless else None
        problems = judge.judge(
            text, sc.get("expect", "ok"), golden=golden, degraded=bool(missing),
            match=sc.get("match"), then=sc.get("then"),
            must_fail=sc.get("must_fail", ()),
            timed_out=timed_out, marks=marks,
        )
        problems += host_errors
        if disk:
            # QEMU has exited, or been killed: either way what it wrote
            # is in the file.
            wrong = check_disk(sc, data)
            disk_wrong = bool(wrong)
            problems += wrong
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
            if disk_wrong:
                print(f"  the data disk is kept: {data}")
            print(f"  last serial lines ({directory / 'serial.log'}):")
            for line in log.tail():
                print(f"    {line}")
            return 1
        if bless and "golden" in sc:
            files = {}
            for test, verdict, _ in log.tests:
                files.setdefault(golden_file(test), []).append(f"{test} {verdict.lower()}")
            # Not `directory`: that is the run's own, deleted on a pass.
            listed = golden_dir(sc["golden"])
            listed.mkdir(exist_ok=True)
            for stale in set(p.name for p in listed.glob("*.txt")) - set(files):
                (listed / stale).unlink()
            for file, lines in files.items():
                (listed / file).write_text("\n".join(lines) + "\n")
            print(f"  wrote {listed.relative_to(ROOT)}/")
        expect = sc.get("expect", "ok")
        counts = log.completes[0] if log.completes else (0, 0, 0)
        detail = f"pass={counts[0]} skip={counts[2]}" if expect == "ok" else f"expected {expect}"
        print(f"boot test {name}: PASSED ({detail})")
        passed = True
        return 0
    finally:
        # The image and the firmware variables are rebuilt each run and
        # never help a diagnosis; the logs stay unless the run passed.
        for scratch in ("esp.img", "vars.fd", "qmp.sock", "ser2.sock", "qemu.pid"):
            (directory / scratch).unlink(missing_ok=True)
        # The disk is the evidence when it is what was wrong.
        if not disk_wrong:
            data.unlink(missing_ok=True)
        if passed and not KEEP:
            shutil.rmtree(directory, ignore_errors=True)


def matches(paths, changed):
    """Does a scenario's `paths` name one of the changed files? Each path
    is a file, or a directory ending in `/`: a prefix of what it names.
    `changed` None is "everything changed"."""
    if changed is None:
        return True
    return any(file.startswith(path) for path in paths for file in changed)


def select(scenarios, gate, changed):
    """The names of the gate tier's scenarios that `gate` ("fast", "batch"
    or "full") boots, given the changed files (None: all of them)."""
    names = []
    for name, sc in scenarios.items():
        if sc.get("tier") != "gate":
            continue
        selected = "paths" in sc and matches(sc["paths"], changed)
        if gate == "fast":
            run = sc["arch"] == "x86_64" and (name == "x86_64" or selected)
        elif gate == "batch":
            run = sc["arch"] == "x86_64" and (
                sc.get("expect", "ok") == "ok" or changed is None or selected)
        else:
            run = True
        if run:
            names.append(name)
    return names


def git(*args):
    """The output of a git command in the tree, or None if it failed."""
    done = subprocess.run(["git", "-C", str(ROOT), *args], capture_output=True, text=True)
    return done.stdout if done.returncode == 0 else None


def gate_base(gate):
    """The commit a gate compares the tree with, or None if there is none:
    the fast gate's is where the branch left `updates`, the batch gate's
    is where that gate last passed."""
    if gate == "fast":
        base = os.environ.get("GATE_BASE") or (git("merge-base", "HEAD", "updates") or "").strip()
    else:
        try:
            base = GATE_PASSED.read_text().strip()
        except OSError:
            base = ""
    if base and git("cat-file", "-e", f"{base}^{{commit}}") is not None:
        return base
    return None


def changed_files(base):
    """The files that differ between the commit `base` and the working
    tree, and those not tracked; None (everything) if `base` is None or
    git cannot say."""
    if base is None:
        return None
    differing = git("diff", "--name-only", base)
    untracked = git("ls-files", "--others", "--exclude-standard")
    if differing is None or untracked is None:
        return None
    return sorted(set((differing + untracked).split("\n")) - {""})


def run_gate(gate, scenarios):
    """Run what `gate` selects of the gate tier, and say what that was."""
    if gate == "full":
        return run_tier("gate", scenarios)
    total = sum(sc.get("tier") == "gate" for sc in scenarios.values())
    base = gate_base(gate)
    changed = changed_files(base)
    names = select(scenarios, gate, changed)
    since = "every file taken as changed" if changed is None \
        else f"{len(changed)} files changed since {base[:12]}"
    print(f"{gate} gate: {len(names)} of the gate tier's {total} scenarios ({since})")
    return run_tier("gate", scenarios, label=f"tier gate ({gate})", names=names)


def run_tier(tier, scenarios, repeat=1, label=None, names=None):
    """Run every scenario of `tier` (or those of it in `names`), `repeat`
    times each, several at a time, each in its own process so that one
    cannot disturb another."""
    label = label or f"tier {tier}"
    if names is None:
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
        print(f"{label}: FAILED {len(failed)} of {len(runs)} boots ({', '.join(failed)})")
        return 1
    if repeat == 1:
        print(f"{label}: {len(names)} scenarios passed")
    else:
        print(f"{label}: {len(runs)} boots passed ({len(names)} scenarios, {repeat} times each)")
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
    image, tier, gate = option("--image"), option("--tier"), option("--gate")
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
    if gate:
        if args or flags or image or tier or repeat != 1 or gate not in ("fast", "batch", "full"):
            sys.exit(__doc__)
        return run_gate(gate, scenarios)
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
