# Roadmap

## 0.0.1: driver bootstrap (in progress)

Stop goal: both architectures boot under QEMU, load real Windows driver
binaries, complete real IRPs and report PASS.

| # | Phase | State |
| --- | --- | --- |
| 0 | Workspace, gate, docs, compiler ABI probes | done |
| 1 | `lib/pe`: parse, map, relocate, bind imports | done |
| 2 | Fixture fetch by URL + SHA-256; ledger from real import tables | done |
| 3 | `nkload`: UEFI loader, boot test harness | done |
| 4 | Kernel entry: own page tables, serial, power off | done |
| 5 | CPU state: descriptor tables, exceptions, processor control region | done |
| 6 | Memory: frames, mappings, pool | done |
| 7 | `lib/ntabi` layouts, runtime library | done |
| 8 | Export registry and driver loader | done |
| 9 | Object and I/O managers: devices, IRPs | done |
| 10 | `null.sys` proof | done (x86-64; arm64 blocked on the fixture) |
| 11 | `sioctl.sys` buffered I/O proof, unload, leak check | done, both architectures |
| 12 | MDLs and direct I/O | done, both architectures |
| 13 | WDK-built ABI probe for layout verification | |
| 14 | Ledger and documentation pass | |

## After 0.0.1

- Application processors online; scheduler, waits, timers.
- SEH unwinding, then `METHOD_NEITHER` I/O.
- KMDF: `echo.sys` through a WDF runtime.
- A Windows 10 reference VM for differential testing.
- Physical boot on the Dell OptiPlex.
- A real hardware driver against a QEMU virtual device.
