# ABI notes

What the compiler targets do, what the kernel relies on, and how the
layouts in `lib/ntabi` are verified.

## Compiler targets (stable Rust)

| Question | x86_64-unknown-uefi | aarch64-unknown-uefi |
| --- | --- | --- |
| Integer argument registers for `extern "C"` | rcx, rdx, r8, r9, then stack above 32 bytes of shadow space: the Microsoft x64 convention | x0-x7 |
| Platform register | n/a | x18 never appears in generated code |
| Floating point | soft-float: `f64` arguments travel in integer registers and arithmetic calls `__muldf3` | hardware (NEON) |

Consequences:

- Exported functions are plain `extern "C"` and are Windows-ABI correct
  for integer and pointer arguments on both targets.
- **x86-64 floating-point arguments are not Windows-ABI correct.** The
  target does not use SSE registers. No kernel export takes a
  float, and the kernel itself uses none (`clippy::float_arithmetic`
  warns). An export that needs one must go through an assembly thunk.
- Because NK's own code never touches XMM registers on x86-64, a driver's
  SSE state survives calls into the kernel without save/restore. The
  kernel keeps SSE enabled (CR0 and CR4 are set on each processor), since
  drivers use it.
- Exceptions and interrupts preserve vector state. On x86-64 the entry
  stub saves XMM0-XMM5 and MXCSR, the registers Windows saves in a trap
  frame: code an interrupt goes on to run may use them, and the other ten
  are preserved by any function that touches them. On arm64 it saves all
  of v0-v31 with FPCR and FPSR, because the kernel's own code is compiled
  to use them. In both cases the handler runs with the kernel's control
  word (round to nearest, exceptions masked), not the interrupted code's.
  `cpu.fp-preserved` checks this with a handler that overwrites every
  register it is entitled to.
- A fault that becomes an exception needs the faulting code's whole
  `CONTEXT`. On x86-64 XMM6-XMM15 are not in the trap frame: they are
  read from the processor, where they still are because nothing NK ran
  in between uses them, and loaded back if a handler changed them.
- x18 holds the processor control region on arm64 Windows; the target
  leaves it alone, so the kernel can set it once per CPU.
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
| Processor number | `gs:[0x1A4]` (32 bits); `gs:[0x184]` (one byte, older headers) | NK's own: `[x18, #0x9A4]` |
| Current IRQL | register CR8 | the GIC's priority mask (`ICC_PMR_EL1`); drivers call an export |

The current-thread slot holds the address of the running thread's
`ETHREAD`-sized block. The fields NK maintains in it are at Windows'
x86-64 offsets (`lib/ntabi/thread.rs`, checked against the kernel's
symbols); the rest of the block is zero.

Segment selectors on x86-64 match Windows (kernel code 0x10, data 0x18,
TSS 0x40). That is a debugging convenience, not a driver dependency.

## What is a call and what is not

The import tables of the conformance drivers, built with the current WDK,
show which routines a driver calls and which the headers compile in line:

| | x86-64 | arm64 |
| --- | --- | --- |
| `KeGetCurrentIrql`, `KeRaiseIrql` (`KfRaiseIrql`) | imported from `ntoskrnl.exe` | imported from `HAL.dll` |
| `KeLowerIrql` | imported from `ntoskrnl.exe` | imported from `HAL.dll` as `KfLowerIrql` |
| `KeStallExecutionProcessor`, `KeQueryPerformanceCounter` | imported from `HAL.dll` | imported from `HAL.dll` |
| `KeGetCurrentThread` | in line: `gs:[0x188]` | imported |
| `KeQueryTickCount`, `KeQueryInterruptTime`, `KeQuerySystemTime` | in line: read from the shared data page | in line, likewise |

Code built with older headers reads and writes the IRQL in line on
x86-64 (register CR8), so both must work. `HAL.dll` is a second name for
the kernel: in the Windows build NK follows, each of its exports forwards
to `ntoskrnl.exe`, and NK resolves either module name against one table.

## Functions with a variable number of arguments

`DbgPrint` and `_snwprintf` take a variable number of arguments, and
stable Rust cannot define such a function. Each is entered through a few
instructions of assembly (`kernel/arch/*/variadic.rs`) that make the
call's arguments one array and pass its address on:

- x86-64: the caller leaves room above the return address for the four
  register arguments, and the rest follow on the stack; storing the four
  registers there completes the array.
- arm64: Windows passes a variadic call's arguments in x0-x7, floating
  point included, then on the stack; pushing the eight registers
  directly below the stack arguments completes it.

A `va_list` is the address of such an array on both architectures:
Windows declares it `char *`, `va_start` points it at the first unnamed
argument, and every argument takes eight bytes. So `_vsnwprintf`, which
takes one, is an ordinary function, and `_snwprintf` calls it with the
address of what follows its three named arguments.

The formatting itself is `nk_rtl::format`, tested on the host: flags,
width, precision, the Microsoft size prefixes (`I64`, `w`, `h`), `%p` as
sixteen upper-case digits, strings of either width, counted strings.
No floating point.

## Exception handling

What a driver's compiled code and its handlers can observe of an
exception (`doc/DESIGN.md`, "Exceptions"):

| | x86-64 | arm64 |
| --- | --- | --- |
| A language handler's arguments | rcx record, rdx frame, r8 context, r9 dispatcher context | x0-x3, likewise |
| The frame it is given | the function's stack pointer after its prologue, or its frame register less the offset its unwind record states | the stack pointer the function was entered with |
| A filter's arguments | rcx `EXCEPTION_POINTERS`, rdx the frame | x0 `EXCEPTION_POINTERS`, x1 the function's frame pointer (x29), not the frame its handler is given: a compiled filter begins `mov x29, x1` |
| A `__finally` block's arguments | cl whether the termination is abnormal, rdx the frame | w0 likewise, x1 the function's frame pointer |
| At an `__except` block | rax the exception's code; rbx, rbp, rsi, rdi, r12-r15, xmm6-xmm15 and the stack pointer as the function had them | x0 the code; x19-x30, the low halves of v8-v15 and the stack pointer |
| A frame's program counter, for looking its function and scopes up | the return address as it is | the instruction before the return address, when the frame was left by a call (`ControlPcIsUnwound`) |

The other registers at an `__except` block are whatever the dispatcher
left: compiled code expects nothing of them. The context a routine that
raises records for its caller marks its program counter as a return
address the way Windows does on arm64, with `CONTEXT_UNWOUND_TO_CALL`
in the context's flags.

`EXCEPTION_RECORD`, `CONTEXT` and `DISPATCHER_CONTEXT` are in
`lib/ntabi/seh.rs`, checked against the WDK's table on both
architectures and against the kernel's symbols on x86-64.

## What the fixture binaries show

- Drivers reach the current IRP stack location at `IRP+0xB8` and the
  status block at `IRP+0x30` directly; `IoGetCurrentIrpStackLocation` and
  friends are inlined, never imported.
- A WDK-built driver's real entry point is a compiler wrapper that
  validates the stack cookie before the author's `DriverEntry` runs. See
  "Loading a driver" in `doc/DESIGN.md`.
- `null.sys` writes a `FAST_IO_DISPATCH` table into its device extension.
  NK never calls fast I/O routines; every request is an IRP.

## Structure layouts

`lib/ntabi` declares the structures and asserts every size and offset at
compile time. Three sources back those numbers, in increasing order of
authority:

1. Microsoft's documentation and public symbols (what the definitions
   were written from).
2. The fixture binaries: the offsets Microsoft's `null.sys` and the
   WDK-built `sioctl.sys` actually use agree, on both architectures, and
   the drivers work.
3. The ABI probe: a table of `sizeof`/`FIELD_OFFSET` values compiled by
   the WDK itself in the nk-fixtures repository. `lib/ntabi/probe.rs`
   compares all of NK's facts against it when the table is downloaded.

**Status of 3: agrees.** The tables are pinned by hash in
`fixtures/manifest.toml` and `make test` compares against them: every
fact NK states matches on both architectures, whose tables are identical
apart from the x64-only KPCR lines. Without the tables the test prints
SKIP.

One thing the probe cannot tell: where the KPRCB and the current-thread
slot sit. The public `KPCR` is 0x178 bytes and stops short of the PRCB.

## Private layouts: the kernel's public symbols

Microsoft's own drivers were compiled against private headers, so they
can read fields the WDK never declares. For those the authority is the
type information in the public PDB of the pinned kernel
(`ntoskrnl.exe` 10.0.19041.2006, the kernel of Windows build
19045.2006), a fixture fetched from Microsoft's
symbol server by the GUID and age in that kernel's debug directory.
`lib/pdb` reads it, `tools/pdbinfo` prints any structure from it, and
`lib/ntabi/pdb.rs` compares NK's definitions with it in `make test`.

The PDB holds two bodies named `_KPCR`: the public 0x178-byte head, and
the full 0xB080-byte region that ends with the processor block. NK takes
the largest body of a name and requires every smaller one to agree with
it on the fields they share.

**Status: agrees, x86-64.** `KPCR.Self` 0x18, `CurrentPrcb` 0x20, `Prcb`
0x180, `KPRCB.CurrentThread` 0x8, `Number` 0x24, `LegacyNumber` 0x4 and
the KPCR's size, 0xB080, are what `lib/ntabi/pcr.rs` states, so
`gs:[0x188]` is the current thread and `gs:[0x1A4]` the processor number.
Security descriptors (absolute and self-relative), ACL and SID headers
agree too. A structure is added to the
comparison by the commit that starts using it.

There is nothing to compare arm64 with: NK has no source of Windows 10
arm64 kernels or symbols. arm64 uses the documented structures, the facts
the WDK compiles into the probe, and layouts of NK's own for whatever no
available binary can observe.

The executive's structures that live in a driver's memory (`ERESOURCE`,
`OWNER_ENTRY`, the lookaside lists, `SLIST_HEADER`) are documented ones:
the probe states them for both architectures and the symbols agree on
x86-64. The bits of a push lock's word are the symbols'
(`_EX_PUSH_LOCK`), on both architectures: no header declares them, and
only the kernel's routines look inside the word. `EX_TIMER` is in
neither the headers nor the symbols; all a driver may do with one is
wait on its address, so NK's begins with a `KTIMER` and is otherwise
its own.

## Not yet verified

- `SE_EXPORTS` past `SeUserModeDriversSid` (0x210). Up to there, the
  offsets are the ones the WDK probe records and Microsoft's
  device-security library, linked into the `cancel` fixture, reads SIDs
  from. The two SIDs and one privilege after it, and the structure's
  size (0x230), are what NK takes the Windows 10 kernel to publish; the
  current WDK's header has grown further (0x260), so the probe cannot
  say, and no fixture reads them yet.

- The PCR on arm64. The current-thread offset (`[x18, #0x988]`) is the
  documented convention; no symbol file, probe fact or fixture driver
  confirms it yet. Where the processor number sits, and the PCR's size,
  are NK's own until something shows what Windows uses.
- Behaviour beyond the oracle scripts. What `oracle/` replays on real
  Windows is verified line for line (`doc/TESTING.md`); every other
  expectation still comes from documentation, sample source and the
  binaries themselves.
- Pointer authentication on arm64: WDK-built arm64 drivers contain
  `pacibsp`/`autibsp`. They execute as no-ops on the emulated CPU used
  for testing; NK does not enable or manage PAC keys.
