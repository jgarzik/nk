# Roadmap

## 0.0.1: driver bootstrap (this release)

The first milestone: prove, end to end and on both architectures, that a
kernel written from scratch can run an unmodified Windows driver binary.

What is in it:

| Area | State |
| --- | --- |
| Boot | UEFI loader (`nkload`), own page tables, power-off through UEFI runtime services, on x86-64 and arm64 under QEMU |
| CPU | Descriptor tables and exception vectors; a fault is a bugcheck with a register dump; the processor control region drivers reach through GS / x18 |
| Memory | Frame allocator, kernel mappings with per-page protection, pool with overrun and bad-free detection |
| Loader | PE32+ drivers mapped, relocated and import-bound; stack cookie set; wrong-architecture and unresolved-import images refused |
| I/O | Driver, device and file objects; IRPs with completion routines; buffered and direct (MDL) transfers; symbolic links |
| Drivers | `null.sys` from Windows 10 (x86-64); the WDK-built `sioctl.sys` sample (both), including 100 load/unload cycles without a leak |
| Verification | Structure layouts checked against a WDK-built table; every import of the test drivers tracked in `ledger/` |

What 0.0.1 deliberately leaves out: threads and scheduling, interrupts
and timers, more than one CPU, structured exception handling, Plug and
Play and power management, user mode, and any real hardware device.

### Known gaps in this release

These fall short of what the milestone set out to do, and are stated
rather than hidden:

- **`null.sys` on arm64 is untested.** The test binary comes from
  Microsoft's symbol server, which needs the file's timestamp and size;
  no public index lists them for Windows 10 arm64. It needs a copy from a
  licensed Windows 10 arm64 installation. A Windows 11 binary would not
  be a valid substitute.
- **Nothing has been compared with real Windows.** Expected results come
  from Microsoft's documentation, the sample's source and the binaries.
  A Windows 10 reference machine running the same drivers is needed to
  call any behaviour verified.
- **`METHOD_NEITHER` requests are not exercised.** `sioctl.sys` handles
  them by probing user memory inside `__try`, which needs a user address
  space and structured exception handling.
- **Not run on physical hardware.**
- **Partly verified ABI.** Structure layouts are checked against the WDK.
  The offsets of the current-thread pointer in the processor control
  region, and function signatures in general, are not.

## Next

In rough order; each step is chosen because a real driver needs it.

1. **Threads, waits and timers; all CPUs online.** Most drivers block,
   queue work or take locks at raised IRQL. This is the largest missing
   piece and unlocks asynchronous I/O.
2. **Structured exception handling.** Unwinding on both architectures,
   then `METHOD_NEITHER` and the rest of the IOCTL sample.
3. **A Windows 10 reference machine**, so tests assert what Windows does
   rather than what the documentation says.
4. **KMDF.** Microsoft's `echo.sys` sample through a driver-framework
   runtime: device add and start, queues, timers, cancellation.
5. **Physical hardware:** boot on a PC.
6. **A real device.** An existing Windows driver doing I/O against a QEMU
   virtual device, chosen by how much it needs rather than by how simple
   the device is. Then storage, then networking.
