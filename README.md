# NK

A Windows NT-compatible kernel written in Rust, for x86-64 and arm64.

NK's rule is that an unmodified Windows kernel-mode driver cannot tell NK
from Windows: the same `.sys` file that loads on Windows loads on NK. The
compatibility target is the Windows 10 2004-22H2 family (NT 10.0, builds
19041 to 19045). Windows defines the driver ABI and the behaviour drivers
observe; the implementation behind it is NK's own.

NK replaces only the Windows kernel and HAL. The long-term goal is to
boot the rest of Windows on top of it, unmodified: Microsoft's own bus,
storage and file-system drivers, then Microsoft's user mode, up to a
Windows rescue disk at a `cmd.exe` prompt. `doc/ROADMAP.md` lays out the
phases. NK contains and ships no Windows code, and boots on its own
through UEFI.

## Status: driver bootstrap

NK is a proof that the approach works end to end, on a deliberately
small surface. Under QEMU, on both architectures, NK:

1. boots from UEFI firmware through its own loader,
2. takes over the CPU and memory,
3. loads a real Windows driver binary: maps it, relocates it, binds its
   imports,
4. calls the driver's own entry point, which creates its device,
5. opens the device and sends it real I/O request packets (IRPs),
6. checks status, byte counts and payloads, unloads the driver, and
   verifies nothing leaked.

The drivers are Microsoft's, not written for NK:

| Driver | What it is | x86-64 | arm64 |
| --- | --- | --- | --- |
| `null.sys` | The Null device driver shipped in Windows 10 | runs | no test binary yet |
| `sioctl.sys` | Microsoft's WDM IOCTL sample, built with Microsoft's WDK | runs | runs |
| `event.sys` | Microsoft's WDM event sample, built with Microsoft's WDK | loads, and stops where Windows stops | the same |

**What this is not.** Two software drivers are not general driver
compatibility. NK has preemptive threads that wait on events,
semaphores, timers and mutexes, and requests that pend and can be
cancelled, but no APCs, no
device interrupts, no structured exception handling, no Plug and Play
and no user mode. It
has not been run on physical hardware. The two
drivers' request-by-request results match a run on real Windows 10
(`oracle/`); the rest of what the tests expect comes from Microsoft's
documentation, sample source and binaries. `doc/ROADMAP.md` says what is
open and the path from here to Windows user mode.

## Try it

On Ubuntu 24.04 (other hosts: see `DEVELOPMENT.md`):

```sh
sudo apt-get install make qemu-system-x86 qemu-system-arm ovmf qemu-efi-aarch64 mtools python3
# Rust: install rustup from https://rustup.rs; the repository selects the toolchain.

make check        # build, then boot x86-64 under QEMU and run the driver tests
make check-arm    # the same for arm64
make run          # boot with the serial console attached (Ctrl-A X to quit)
```

The first run downloads the test drivers (a few kilobytes each) and
verifies their SHA-256. A passing boot ends like this on the serial
console:

```
NK 0.0.1 (x86_64)
...
NK-TEST null.load:OK
NK-TEST null.read:OK
NK-TEST null.write:OK
NK-TEST sioctl.buffered:OK
NK-TEST sioctl.out-direct:OK
sioctl: 100 load/exercise/unload cycles, resources unchanged
NK-TEST sioctl.cycles:OK
NK-TEST-COMPLETE pass=28 fail=0 skip=1
```

`make gate` runs everything a change must pass: formatting, lints, host
unit tests and both boot tests. `make help` lists the other targets.

## How compatibility is measured

Progress is measured at the driver interface, not by lines of code or
counts of exported names.

- **Real import tables.** NK exports a routine because a driver in the
  test set imports it. `ledger/` lists, per architecture, every import of
  every test driver and what NK does about it: implemented, partial,
  traps (present so the driver loads, but stops the machine if called), or
  missing.
- **No fake success.** A driver with an import NK lacks is refused, with
  the symbol named. A routine that cannot do its job fails as its contract
  says or stops the machine; it never reports success it did not earn.
- **Layouts checked against Microsoft's compiler.** The structures drivers
  see (`DEVICE_OBJECT`, `IRP`, `MDL`, ...) are compared in the unit tests
  with a table produced by the WDK itself. See `doc/ABI.md`.
- **Unmodified binaries.** Test drivers are identified by hash and never
  patched or rebuilt to suit NK.

## Test drivers and licensing

No Windows binary is stored in this repository or in its release images.
`fixtures/manifest.toml` lists each test driver with its source URL and
SHA-256; the tests download them and reject a mismatch.

- `null.sys` comes from Microsoft's public symbol server.
- `sioctl.sys`, and the layout tables, come from
  [nk-fixtures](https://github.com/jgarzik/nk-fixtures), a separate
  repository that builds Microsoft's published driver samples, unmodified,
  with the WDK on GitHub's Windows runners. Keeping it separate stops the
  test drivers from drifting toward what NK happens to support.

## Repository map

| Path | Contents |
| --- | --- |
| `boot/` | `nkload`, the UEFI loader |
| `kernel/` | the kernel: `arch/` (CPU-specific), `mm/`, `io/`, `ldr/`, `ob/`, `ke/`, `export/`, `selftest/` |
| `lib/` | hardware-independent logic, unit-tested on the build host: PE loading, page tables, allocators, structure layouts, ACPI tables, PDB symbol files |
| `fixtures/` | the manifest of test drivers |
| `ledger/` | generated compatibility ledger |
| `tools/` | fixture fetcher, boot-test harness and judge, image builder, PE and PDB dumpers, the gate |
| `doc/` | design and reference notes |

## Documentation

- `doc/DESIGN.md`: what NK is, its principles, and the decisions behind
  the code
- `doc/BOOT.md`: from firmware to the kernel's first instruction
- `doc/ABI.md`: what the kernel relies on about compilers and layouts,
  and what is still unverified
- `doc/TESTING.md`: unit tests, boot tests, fixtures
- `doc/ROADMAP.md`: the phases from here to a Windows rescue disk
- `doc/LOCKING.md`: IRQL, the kernel's locks, their order
- `doc/UNSAFE.md`: rules for `unsafe` code

## Releases

Versions are tagged `vX.Y.Z`; the version lives in the workspace
`Cargo.toml` and the kernel prints it at boot. A release consists of the
tagged source plus one bootable image per architecture built by
`make dist`. The images contain only NK's loader and kernel. Booted as
they are, they run the kernel's own self-tests and skip the driver tests;
to see drivers run, build from source with `make check`.

NK builds with the current stable Rust toolchain and uses no nightly
features and no third-party crates.

## Contributing and security

See `CONTRIBUTING.md` and `SECURITY.md`. One rule matters more than the
rest: NK is written from published documentation and from observing
behaviour. Do not contribute anything derived from leaked or restricted
Windows source, or translated from GPL-licensed code.

## License

MIT; see `LICENSE`.
