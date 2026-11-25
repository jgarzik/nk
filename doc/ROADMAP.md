# Roadmap

## 0.0.1: driver bootstrap (in progress)

Stop goal: both architectures boot under QEMU, load real Windows driver
binaries, complete real IRPs and report PASS.

| # | Phase | State |
| --- | --- | --- |
| 0 | Workspace, gate, docs, compiler ABI probes | done |
| 1 | `lib/pe`: parse, map, relocate, bind imports | done |
| 2 | Fixture fetch by URL + SHA-256; ledger from real import tables | |
| 3 | `nkload`: UEFI loader, boot test harness | |
| 4 | Kernel entry: own page tables, serial, power off | |
| 5 | CPU state: descriptor tables, exceptions, processor control region | |
| 6 | Memory: frames, mappings, pool | |
| 7 | `lib/ntabi` layouts, runtime library, IRQL and locks | |
| 8 | Export registry and driver loader | |
| 9 | Object and I/O managers: devices, symbolic links, IRPs | |
| 10 | `null.sys` proof | |
| 11 | `sioctl.sys` buffered I/O proof, unload, leak check | |
| 12 | MDLs and direct I/O | |
| 13 | WDK-built ABI probe for layout verification | |
| 14 | Ledger and documentation pass | |

## After 0.0.1

- Application processors online; scheduler, waits, timers.
- SEH unwinding, then `METHOD_NEITHER` I/O.
- KMDF: `echo.sys` through a WDF runtime.
- A Windows 10 reference VM for differential testing.
- Physical boot on the Dell OptiPlex.
- A real hardware driver against a QEMU virtual device.
