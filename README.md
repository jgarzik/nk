# NK

A Windows NT-compatible kernel written in Rust, for x86-64 and arm64.

## What it does

NK replaces the Windows 10 kernel and HAL, and nothing else. Its rule: an
unmodified Windows kernel-mode driver cannot tell NK from Windows. The
same `.sys` file that loads on Windows 10 (2004-22H2) loads on NK.

Under QEMU on x86-64 and arm64, NK boots from UEFI through its own
loader, runs every processor with preemptive threads, waits, timers,
DPCs and work items, and loads unmodified driver binaries: on x86-64
Microsoft's own, among them the named pipe and mailslot file systems
and the libraries drivers import from; on both architectures
Microsoft's WDM samples and NK's conformance drivers
([ledger/](ledger/README.md) lists them). It reads its registry from a
hive file Windows wrote and starts the boot drivers that hive names.
Drivers and the files they open are objects in an NT object namespace,
opened by handle, with tokens and access checks behind them; a driver
may import from another driver and send it requests. NK sends drivers
real IRPs, which they may pend, complete later or have cancelled, and
what they answer matches a recording made on real Windows 10, request
by request. Their `__try` blocks work: exceptions, kernel-raised or
from a processor fault, are dispatched and unwound as on Windows.

Absent: APCs, device interrupts, Plug and Play, user mode, physical
hardware ([doc/DESIGN.md](doc/DESIGN.md), "What is absent").

## What it intends to do

Boot the rest of Windows on top of NK, unmodified: Microsoft's own bus,
storage and file-system drivers, then Microsoft's user mode, up to a
Windows rescue disk at a `cmd.exe` prompt. NK contains and ships no
Windows code. The phases are in [doc/ROADMAP.md](doc/ROADMAP.md).

## Quick start

On Ubuntu 24.04:

```sh
sudo apt-get install make qemu-system-x86 qemu-system-arm ovmf qemu-efi-aarch64 mtools python3
# Rust: install rustup from https://rustup.rs; the repository selects the toolchain.

make check        # build, boot x86-64 under QEMU, run the driver tests
make check-arm    # the same for arm64
make run          # boot with the serial console attached (Ctrl-A X to quit)
```

The first run downloads the test drivers and verifies their SHA-256. A
passing boot ends with `NK-TEST-COMPLETE pass=<n> fail=0 skip=<n>`.

## Documentation

- [DEVELOPMENT.md](DEVELOPMENT.md): setup, everyday commands, debugging a failed boot, releases
- [CONTRIBUTING.md](CONTRIBUTING.md): where code may come from, what a change must do
- [SECURITY.md](SECURITY.md): what NK does not protect against
- [doc/DESIGN.md](doc/DESIGN.md): scope, principles, source map, how each part works
- [doc/BOOT.md](doc/BOOT.md): from firmware to the kernel's first instruction
- [doc/LOCKING.md](doc/LOCKING.md): IRQL, locks and their order, the SMP rules
- [doc/ABI.md](doc/ABI.md): compiler and layout facts
- [doc/TESTING.md](doc/TESTING.md): unit tests, boot tests, fixtures, the Windows oracle
- [doc/ROADMAP.md](doc/ROADMAP.md): the phases to a Windows rescue disk
- [doc/UNSAFE.md](doc/UNSAFE.md): rules for `unsafe`
- [ledger/](ledger/README.md): every import of every test driver, and what NK does about it

## License

MIT; see `LICENSE`.
