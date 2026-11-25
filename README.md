# NK

A Windows NT-compatible kernel written in Rust, for x86-64 and arm64.

NK's rule: an unmodified Windows kernel-mode driver cannot tell NK from
Windows. The same `.sys` file that loads on Windows loads on NK. The
target is the Windows 10 2004-22H2 family (NT 10.0, builds 19041 to
19045). Windows defines the driver ABI and the behaviour drivers
observe; the implementation behind it is NK's own.

NK replaces only the Windows kernel and HAL. The goal is to boot the
rest of Windows on it, unmodified: Microsoft's bus, storage and
file-system drivers, then Microsoft's user mode, up to a Windows rescue
disk at a `cmd.exe` prompt (`doc/ROADMAP.md`). NK contains and ships no
Windows code, and boots on its own through UEFI.

## Status: kernel core

Under QEMU, on both architectures, NK boots from UEFI through its own
loader; runs every processor with interrupts, a clock, preemptive
threads, waits, timers, DPCs and work items; loads real Windows driver
binaries (map, relocate, bind imports, call the entry point); sends them
real IRPs, which they may pend, complete later or have cancelled; then
unloads them and verifies nothing leaked.

The drivers are Microsoft's, not written for NK:

| Driver | What it is | Result |
| --- | --- | --- |
| `null.sys` | the Null driver shipped in Windows 10 | runs (x86-64; no arm64 binary) |
| `sioctl.sys` | Microsoft's WDM IOCTL sample | runs |
| `event.sys` | Microsoft's WDM event sample | runs as on Windows with a debugger attached; without one, stops where Windows stops |
| `cancel.sys` | Microsoft's WDM cancel sample | reads cancelled while queued; 100 load/unload cycles without a leak |
| `nkc-*.sys` (eleven) | NK's conformance drivers, each recorded on Windows first | match Windows value for value |

All but `null.sys` are built with Microsoft's WDK and run on both
architectures. What they answer, request by request, matches a run on
real Windows 10 (`oracle/`).

**What this is not.** A few software drivers are not general driver
compatibility. There are no APCs, device interrupts, structured
exception handling, Plug and Play or user mode; the registry is in
memory and nothing enforces a security descriptor. NK has not run on
physical hardware.

## Try it

On Ubuntu 24.04 (other hosts: `DEVELOPMENT.md`):

```sh
sudo apt-get install make qemu-system-x86 qemu-system-arm ovmf qemu-efi-aarch64 mtools python3
# Rust: install rustup from https://rustup.rs; the repository selects the toolchain.

make check        # build, boot x86-64 under QEMU, run the driver tests
make check-arm    # the same for arm64
make run          # boot with the serial console attached (Ctrl-A X to quit)
make gate         # everything a change must pass
```

The first run downloads the test drivers and verifies their SHA-256. A
passing boot ends like this on the serial console:

```
NK-TEST sioctl.cycles:OK
NK-TEST cancel.cancelled:OK reads cancelled while queued: 7
NK-TEST oracle.sioctl:OK 31 lines as on Windows
NK-TEST-COMPLETE pass=132 fail=0 skip=1
```

## How compatibility is measured

At the driver interface, not by lines of code or counts of exports.

- **Real import tables.** NK exports a routine because a test driver
  imports it. `ledger/` lists every import of every test driver and what
  NK does about it: implemented, partial, traps (present so the driver
  loads; stops the machine if called), or missing.
- **No fake success.** A driver with an import NK lacks is refused, with
  the symbol named. A routine that cannot do its job fails as its
  contract says or stops the machine.
- **Layouts checked against Microsoft's compiler.** The structures
  drivers see are compared with a table produced by the WDK and with
  Microsoft's public symbols (`doc/ABI.md`).
- **Unmodified binaries.** Test drivers are identified by hash, never
  patched or rebuilt to suit NK, and never stored here:
  `fixtures/manifest.toml` gives each one's URL and SHA-256. `null.sys`
  comes from Microsoft's symbol server; the rest from
  [nk-fixtures](https://github.com/jgarzik/nk-fixtures), a separate
  repository that builds Microsoft's samples with the WDK, kept separate
  so the test drivers cannot drift toward what NK supports.

## Documentation

- `doc/DESIGN.md`: scope, principles, source map, how each part works
- `doc/BOOT.md`: from firmware to the kernel's first instruction
- `doc/LOCKING.md`: IRQL, locks and their order, the SMP rules
- `doc/ABI.md`: compiler and layout facts, and what is unverified
- `doc/TESTING.md`: unit tests, boot tests, fixtures, the oracle
- `doc/ROADMAP.md`: the phases to a Windows rescue disk
- `doc/UNSAFE.md`: rules for `unsafe`
- `DEVELOPMENT.md`, `CONTRIBUTING.md`, `SECURITY.md`

## Releases

Tagged `vX.Y.Z`; the version is in the workspace `Cargo.toml`. A release
is the tagged source plus one boot image per architecture from
`make dist`, holding only NK's loader and kernel: booted, they run the
kernel's self-tests and skip the driver tests.

NK builds with stable Rust: no nightly features, no third-party crates.

## License

MIT; see `LICENSE`.
