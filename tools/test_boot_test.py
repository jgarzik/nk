"""Unit tests for the parts of tools/boot_test.py that boot nothing. Run by
`make test`."""

import json
import socket
import threading
import time
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

    def test_a_gate_s_last_line_is_kept_too(self):
        self.assertEqual(boot_test.failures(
            "fast gate: 2 of the gate tier's 9 scenarios (3 files changed since 0123456789ab)\n"
            "boot test x86_64: PASSED (pass=3 skip=0)\n"
            "boot test x86_64-storage: FAILED\n"
            "  NK-TEST stor.load:FAIL no disk\n"
            "tier gate (fast): FAILED 1 of 2 boots (x86_64-storage)\n"), [
            "boot test x86_64-storage: FAILED",
            "  NK-TEST stor.load:FAIL no disk",
            "tier gate (fast): FAILED 1 of 2 boots (x86_64-storage)",
        ])


def scenario(arch="x86_64", tier="gate", **keys):
    return {"arch": arch, "tier": tier, **keys}


SCENARIOS = {
    "x86_64": scenario(),
    "aarch64": scenario("aarch64"),
    "x86_64-smp1": scenario(smp=1),
    "x86_64-storage": scenario(paths=["kernel/", "lib/"]),
    "x86_64-neg-lock": scenario(expect="bugcheck", paths=["kernel/ke/spinlock.rs", "lib/ke/"]),
    "x86_64-neg-other": scenario(expect="bugcheck"),
    "x86_64-known-bad": scenario(expect="fail", paths=["tools/"]),
    "aarch64-neg-lock": scenario("aarch64", expect="bugcheck", paths=["kernel/ke/spinlock.rs"]),
    "x86_64-soak": scenario(tier="soak", paths=["kernel/"]),
}


class Selection(unittest.TestCase):
    def select(self, gate, changed):
        return boot_test.select(SCENARIOS, gate, changed)

    def test_a_path_is_a_file_or_a_directory_s_prefix(self):
        paths = ["kernel/ke/spinlock.rs", "lib/ke/"]
        self.assertTrue(boot_test.matches(paths, ["doc/x.md", "kernel/ke/spinlock.rs"]))
        self.assertTrue(boot_test.matches(paths, ["lib/ke/order.rs"]))
        self.assertFalse(boot_test.matches(paths, ["kernel/ke/kspin.rs", "lib/kernel.rs"]))
        self.assertFalse(boot_test.matches(paths, []))
        # Nothing known about what changed: everything did.
        self.assertTrue(boot_test.matches(paths, None))

    def test_the_fast_gate_boots_the_main_scenario_whatever_changed(self):
        self.assertEqual(self.select("fast", []), ["x86_64"])
        self.assertEqual(self.select("fast", ["doc/DESIGN.md"]), ["x86_64"])

    def test_the_fast_gate_adds_the_scenarios_whose_paths_changed(self):
        self.assertEqual(self.select("fast", ["kernel/io/irp.rs"]), ["x86_64", "x86_64-storage"])
        self.assertEqual(self.select("fast", ["lib/ke/order.rs"]),
                         ["x86_64", "x86_64-storage", "x86_64-neg-lock"])
        self.assertEqual(self.select("fast", ["tools/judge.py"]), ["x86_64", "x86_64-known-bad"])

    def test_the_fast_gate_with_no_base_boots_every_scenario_with_paths(self):
        self.assertEqual(self.select("fast", None),
                         ["x86_64", "x86_64-storage", "x86_64-neg-lock", "x86_64-known-bad"])

    def test_the_batch_gate_boots_what_must_pass_and_the_changed_must_fail(self):
        passing = ["x86_64", "x86_64-smp1", "x86_64-storage"]
        self.assertEqual(self.select("batch", []), passing)
        self.assertEqual(self.select("batch", ["kernel/ke/spinlock.rs"]),
                         passing + ["x86_64-neg-lock"])
        self.assertEqual(self.select("batch", ["tools/boot_test.py"]),
                         passing + ["x86_64-known-bad"])

    def test_the_batch_gate_with_no_base_boots_all_of_x86_64(self):
        self.assertEqual(self.select("batch", None), [
            "x86_64", "x86_64-smp1", "x86_64-storage", "x86_64-neg-lock",
            "x86_64-neg-other", "x86_64-known-bad"])

    def test_the_full_gate_boots_the_whole_tier(self):
        whole = [name for name in SCENARIOS if name != "x86_64-soak"]
        self.assertEqual(self.select("full", None), whole)
        self.assertEqual(self.select("full", []), whole)

    def test_no_gate_boots_another_tier_or_arm64_but_the_full_one(self):
        for gate in ("fast", "batch"):
            for changed in (None, ["kernel/ke/spinlock.rs"]):
                names = self.select(gate, changed)
                self.assertFalse([n for n in names if SCENARIOS[n]["arch"] != "x86_64"])
                self.assertNotIn("x86_64-soak", names)


class Devices(unittest.TestCase):
    def test_nvme_and_phase5_devices_emit_expected_qemu_args(self):
        self.assertEqual(
            boot_test.disk_devices("x86_64", "nvme"),
            ["-drive", "if=none,id=nkdata,format=raw,file=data.img",
             "-device", "nvme,drive=nkdata,serial=nk-nvme"],
        )
        self.assertEqual(
            boot_test.extra_devices("x86_64", usb="xhci", usb_kbd=True, serial2=True),
            ["-device", "qemu-xhci,id=xhci",
             "-device", "usb-kbd,bus=xhci.0,port=1,id=kbd0",
             "-chardev", "socket,id=ser2,path=ser2.sock,server=on,wait=off",
             "-device", "isa-serial,index=1,chardev=ser2"],
        )
        with self.assertRaises(ValueError):
            boot_test.disk_devices("aarch64", "nvme")
        with self.assertRaises(ValueError):
            boot_test.extra_devices("x86_64", usb_kbd=True)


class Qmp(unittest.TestCase):
    def test_wait_event_survives_internal_recv_timeout_and_chunked_lines(self):
        client, server = socket.socketpair()
        errors = []

        def peer():
            try:
                server.sendall(b'{"QMP": {"version": {}}}\n')
                buf = b""
                while b"\n" not in buf:
                    buf += server.recv(4096)
                req = json.loads(buf.decode("utf-8"))
                if req.get("execute") != "qmp_capabilities":
                    errors.append(f"unexpected cmd {req!r}")
                    return
                server.sendall(b'{"return": {}}\n')
                # Delay past QmpSession's 1.0s internal recv timeout slice so
                # socket.makefile() would have poisoned the reader, then send
                # the event split across two chunks.
                time.sleep(1.15)
                ev = b'{"event": "DEVICE_DELETED", "data": {"device": "kbd0"}}\n'
                server.sendall(ev[:20])
                time.sleep(0.05)
                server.sendall(ev[20:])
            except OSError as e:
                errors.append(str(e))
            finally:
                server.close()

        t = threading.Thread(target=peer, daemon=True)
        t.start()
        session = boot_test.QmpSession(sock=client)
        try:
            event = session.wait_event("DEVICE_DELETED", device_id="kbd0", timeout=3.0)
            self.assertEqual(event["event"], "DEVICE_DELETED")
            self.assertEqual(event["data"]["device"], "kbd0")
        finally:
            session.close()
            t.join(timeout=2.0)
        self.assertEqual(errors, [])

    def test_qmp_session_stops_promptly_on_stop_event(self):
        client, server = socket.socketpair()
        stop = threading.Event()

        def peer():
            try:
                server.sendall(b'{"QMP": {"version": {}}}\n')
                buf = b""
                while b"\n" not in buf:
                    buf += server.recv(4096)
                server.sendall(b'{"return": {}}\n')
                time.sleep(0.15)
                stop.set()
                time.sleep(0.5)
            except OSError:
                pass
            finally:
                server.close()

        t = threading.Thread(target=peer, daemon=True)
        t.start()
        session = boot_test.QmpSession(sock=client, stop_event=stop)
        started = time.monotonic()
        try:
            with self.assertRaises(TimeoutError):
                session.wait_event("DEVICE_DELETED", device_id="kbd0", timeout=20.0)
            elapsed = time.monotonic() - started
            self.assertLess(elapsed, 2.0)
        finally:
            session.close()
            t.join(timeout=2.0)


if __name__ == "__main__":
    unittest.main()
