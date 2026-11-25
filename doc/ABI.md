# ABI notes

What was measured about the compiler targets, and what the kernel relies
on. Layout verification of individual structures is tracked in the
ledger, not here.

## Compiler targets (measured on stable rustc 1.100.0)

| Question | x86_64-unknown-uefi | aarch64-unknown-uefi |
| --- | --- | --- |
| Integer argument registers for `extern "C"` | rcx, rdx, r8, r9, then stack above 32 bytes of shadow space: the Microsoft x64 convention | x0-x7 |
| Platform register | n/a | x18 never appears in generated code |
| Defining C-variadic functions (`...`) | compiles; `VaList::next_arg` | compiles |
| Floating point | soft-float: `f64` arguments travel in integer registers and arithmetic calls `__muldf3` | hardware (NEON) |

Consequences:

- Exported functions are plain `extern "C"` and are Windows-ABI correct
  for integer and pointer arguments on both targets.
- **x86-64 floating-point arguments are not Windows-ABI correct.** The
  target does not use SSE registers. No kernel export in 0.0.1 takes a
  float, and the kernel itself uses none (`clippy::float_arithmetic`
  warns). An export that needs one must go through an assembly thunk.
- Because NK's own code never touches XMM registers on x86-64, a driver's
  SSE state survives calls into the kernel without save/restore. The
  kernel still has to keep SSE enabled, since drivers use it.
- x18 holds the processor control region on arm64 Windows; the target
  leaves it alone, so the kernel can set it once per CPU.
- `DbgPrint` and friends can be written in Rust.

How to re-measure: compile a small `#![no_std]` library for each target
with `rustc --emit asm` and read the argument registers.

## Processor state drivers depend on

WDK headers compile some kernel "calls" into direct register-relative
loads, so these are ABI even though no import shows them. Offsets are in
`lib/ntabi/pcr.rs`.

| | x86-64 | arm64 |
| --- | --- | --- |
| Processor control region | GS base | x18 (also kept in `TPIDR_EL1`) |
| Current thread | `gs:[0x188]` | `[x18, #0x988]` |
| Current IRQL | register CR8 | kernel-private; drivers call an export |

There are no threads yet. The current-thread slot points at a zeroed
placeholder so the inlined load returns a stable non-null pointer; a
driver that looks inside the thread object will not find Windows' fields.

Segment selectors on x86-64 match Windows (kernel code 0x10, data 0x18,
TSS 0x40). That is a debugging convenience, not a driver dependency.

Any exception other than a breakpoint is a fatal bugcheck with a register
dump. There is no SEH: a driver's `__try` block cannot catch anything.

## Found by reading the fixture binaries

- Drivers reach the current IRP stack location at `IRP+0xB8` and the
  status block at `IRP+0x30` directly; `IoGetCurrentIrpStackLocation` and
  friends are inlined, never imported.
- A WDK-built driver's real entry point is a compiler wrapper that
  validates the stack cookie before the author's `DriverEntry` runs. See
  "Loading a driver" in `doc/DESIGN.md`.
- `null.sys` writes a `FAST_IO_DISPATCH` table into its device extension.
  NK never calls fast I/O routines; every request is an IRP.

## Structure layouts

`lib/ntabi` declares the structures; its tests pin every size and offset.
Three sources back those numbers, in increasing order of authority:

1. Microsoft's documentation and public symbols (what the definitions
   were written from).
2. The fixture binaries: the offsets Microsoft's `null.sys` and the
   WDK-built `sioctl.sys` actually use agree, on both architectures, and
   the drivers work.
3. The ABI probe: a table of `sizeof`/`FIELD_OFFSET` values compiled by
   the WDK itself in the nk-fixtures repository. `lib/ntabi/probe.rs`
   compares all of NK's facts against it when the table is downloaded.

**Status of 3: agrees.** The tables from the nk-fixtures v2 release are
pinned by hash in `fixtures/manifest.toml`, and `make test` compares
against them: all 120 facts NK states match on x64 and all 118 on arm64,
including `sizeof DEVICE_OBJECT` = 0x150. The two architectures' tables
are identical apart from the x64-only KPCR lines. If the tables cannot be
downloaded the test prints SKIP rather than pass silently on nothing.

One thing the probe cannot tell: where the KPRCB and the current-thread
slot sit. The public `KPCR` is 0x178 bytes and stops short of the PRCB.
NK's `gs:[0x188]` comes from the WDK's inlined `KeGetCurrentThread`, and
is exercised by no fixture yet.

## Not yet verified

- The current-thread offsets in the PCR, on either architecture: neither
  the probe nor a fixture driver exercises them yet.
- Behaviour against a real Windows 10 installation: there is no
  reference VM yet, so "expected" results come from documentation, sample
  source and the binaries themselves.
- Pointer authentication on arm64: WDK-built arm64 drivers contain
  `pacibsp`/`autibsp`. They execute as no-ops on the emulated CPU used
  for testing; NK does not enable or manage PAC keys.
