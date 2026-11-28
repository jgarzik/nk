# NK design

What NK is, its principles, and how the code works. NT itself is not
explained here: see Microsoft's
[driver documentation](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/_kernel/)
and the [PE format](https://learn.microsoft.com/en-us/windows/win32/debug/pe-format).

Related: `doc/BOOT.md` (loader hand-off), `doc/LOCKING.md` (IRQL, locks,
SMP rules), `doc/ABI.md` (compiler and layout facts), `doc/TESTING.md`,
`doc/ROADMAP.md` (order of work).

## Scope

NK replaces two files of Windows 10, `ntoskrnl.exe` and `hal.dll`, plus a
loader (`nkload`) standing in for Microsoft's boot manager and `winload`.

- Every other kernel-mode component is Microsoft's binary, loaded as a
  driver: ACPI, PCI, storage, file systems, KMDF, network, window system.
- All of user mode is Microsoft's. NK serves it the system calls of one
  exact build.
- NK ships none of it. Tests fetch x86-64 files from Microsoft's symbol
  server; nothing comes from the deployment kit (WinPE), whose licence
  does not cover testing.

Why: if an unmodified driver cannot tell NK from Windows, Microsoft's
inbox drivers are just more drivers, and Microsoft's frameworks (KMDF,
USB) ask little of the kernel, because they carry the rest themselves:
`doc/ROADMAP.md` ("Measurements") has what the corpus imports.
Rewriting those layers would cost years and create second ABIs
(storport, NDIS, KMDF) to get wrong.

Destination: Microsoft's Windows PE at a `cmd.exe` prompt on QEMU x86-64,
QEMU arm64 and a Dell OptiPlex.

## Principles

1. **An unmodified Windows driver binary cannot tell NK from Windows.**
   Exports, calling conventions, structure layouts, IRQL and lifetime
   rules are binding. This outranks everything below.
2. **Windows-shaped wherever a binary can look; NK's own elsewhere.**
   Third-party drivers see the documented structures; Microsoft's inbox
   drivers also read private ones (thread, process, processor, object
   header) in line. Any object a binary can reach has Windows' size and
   offsets for the pinned build; NK's private state sits beside it, never
   in a larger struct in its place. Algorithms, internal tables and the
   loader hand-off are NK's to design.
3. **No fake success.** A missing import rejects the driver and names the
   symbol. A routine that cannot do its job fails per its contract or
   stops the machine. A feature NK lacks (hypervisor, secure kernel, code
   integrity) answers "not present" as Windows does without it.
4. **Windows is the oracle.** A behaviour is verified when the same test
   gives the same result on reference Windows and on NK. Until then the
   ledger says "implemented", not "verified".
5. **Scope follows evidence.** An export exists because a binary in the
   pinned corpus imports it. The ledger carries the denominators.
6. **One exact build.** Drivers of the whole Windows 10 2004-22H2 family
   must run. User mode, system-call numbers and private layouts come from
   one revision: 10.0.19045.2006, Microsoft's Windows 10 Enterprise
   evaluation ISO, which the reference VM also runs.
7. **Hardware is found through ACPI on both architectures,** because
   Microsoft's `acpi.sys` and `pci.sys` do the enumerating.
8. **Sources.** Microsoft's documentation, headers and samples; the
   pinned build's public symbols; the fixture binaries, read for what
   they expect; a reference Windows VM. ReactOS and Wine may be read for
   understanding; no code is copied or translated from them. Nothing from
   leaked Windows source or the Windows Research Kernel, ever.
9. **Written fresh.** No external crates, and no code from the sibling
   Linux-compatible kernel [hk](https://github.com/jgarzik/hk), which is
   a reference for hardware bring-up and the model for the gate, the boot
   harness and differential testing.
10. **x86-64 first, arm64 kept portable.** arm64 boots are paused until
    x86-64 reaches `cmd.exe`; meanwhile every merged batch still
    compiles for arm64 and nothing generic assumes x86-64. Every commit
    passes the fast gate, every merged tip the batch gate, and the full
    gate (both architectures booted) runs nightly and at milestones
    ([TESTING.md](TESTING.md)). Where a Microsoft arm64 binary cannot be
    obtained its test prints SKIP; the NK code beneath it is still built
    and run.

Drivers are trusted but memory-unsafe: NK never holds a Rust reference
into memory a driver can write.

## Source map

| Path | Contents |
| --- | --- |
| `boot/` | `nkload`, the UEFI loader |
| `kernel/main.rs` | entry and boot order |
| `kernel/arch/{x86_64,aarch64}/` | everything CPU-specific: traps, thread switch, interrupt controller, clock, processor start. The only place `cfg(target_arch)` appears |
| `kernel/<part>/` | one directory per NT part: `ke`, `ex`, `mm`, `ob`, `io`, `cc`, `fsrtl`, `pnp`, `po`, `ps`, `se`, `cm`, `rtl`, `etw`, `whea`, plus `hal`, `ldr` (image loading, boot files), `kd` (console, bugcheck) |
| `kernel/export/` | the export table, and the traps |
| `kernel/rt.rs` | Rust's allocator on the kernel pool |
| `kernel/test.rs`, `kernel/selftest/` | the boot-test runner and the test groups |
| `lib/` | pure, host-tested crates, each named for the kernel part whose rules it holds (`ke`, `ex`, `mm`, `ob`, `io`, `cc`, `fsrtl`, `po`, `ps`, `se`, `cm`, `rtl`, `etw`, `hal`, `whea`, `pnp`), and: `pe` and `pdb` (image and symbol-file readers), `unwind` (function tables, unwinding, exception decisions), `ntabi` (structure layouts), `acpi` (firmware tables), `bootinfo` (the loader's hand-off block), `oracle` (the script and transcript format), `disk` (the data disk's pattern, a disk's answers to its control codes and the transfers it takes), `selftest` (the test runner's bookkeeping). A crate's top comment says what it holds |
| `tools/` | the gate; boot harness and judge; ESP image builder; fixture and corpus fetchers; ledger; oracle VM and its debugger stub; mutants; coverage of `lib/` and of the kernel's unwind tables; `peinfo` and `pdbinfo` |
| `fixtures/`, `ledger/`, `oracle/` | fixture manifests; generated compatibility ledger; oracle scripts and Windows transcripts |

Anything that can be written without touching hardware goes in a
`no_std` `lib/` crate with host unit tests. The kernel binary is the glue
and the `unsafe`.

## Boot order

Firmware starts `nkload`, which loads the kernel and drivers and jumps to
`nk_entry` (`doc/BOOT.md`). Then, in `kernel/main.rs`:

1. `arch::cpu_init`: the boot processor's PCR (static: needed before
   memory is), which locks and the IRQL depend on. Console. Firmware
   runtime table.
2. `BootInfo` checked; `arch::mm_init`, `mm::init`: frames, pool, mappings;
   `arch::low_half_init`: on arm64, NK's own low half replaces firmware's.
   `ldr::init`: the boot files and the table of images, the kernel's own
   first.
3. Move from the loader's stack to a guarded kernel stack.
4. `hal::platform` (MADT), interrupt controller; the object types and the
   System process with its tokens, because threads are objects of that
   process; the idle thread (the context being run); interrupts on: from
   here only the IRQL holds them back.
5. Time, IPIs, DPCs, the other processors, work queues, the object
   namespace, the registry.
6. A thread at priority 8 and `PASSIVE_LEVEL`, what a driver expects of
   its caller, prints the export table, makes the root of the device
   tree and the HAL's device (Plug and Play), starts the services the
   hive starts at boot, bringing up the devices each one serves before
   the next starts, and runs the test groups, which load drivers and send
   them IRPs; the machine powers off. The boot context becomes processor
   0's idle loop.

Any step that fails prints a `FAIL` line and stops. No user-mode code
runs.

## Address space

| Range | Contents |
| --- | --- |
| low half | NK's own table on both architectures: firmware runtime regions, identity-mapped, so UEFI runtime services stay callable (`doc/BOOT.md`), and the user range. Nothing at address zero |
| `0xFFFF_8000_0000_0000` + phys | direct map of physical memory: 2 MiB blocks, not executable; ranges without RAM as device memory |
| `0xFFFF_F780_0000_0000` | `KUSER_SHARED_DATA`, one page, Windows' address |
| `0xFFFF_F800_0000_0000` | the kernel image: 4 KiB pages, each section's own protection |
| `0xFFFF_F880_0000_0000` to `0xFFFF_F900_0000_0000` | dynamic mappings: driver images and the views of images, kernel stacks, MDL views |

**The user range** (`kernel/mm/user.rs`) is `0x1_0000` up to Windows'
`MmUserProbeAddress`, `0x7FFF_FFFF_0000`, on both architectures (the
low half is 47 bits wide on x86-64 and 48 on arm64). There is one
address space, the System process's, so the range is every thread's.
`mm::user` maps fresh zeroed frames there and unmaps them, with page
tables made on demand and every processor's translation dropped on
unmap; it has no exports. It is where a user-mode requestor's buffers
are (see [I/O](design/io.md)). A range that touches a firmware runtime
region is refused, since those share the low half.

The pages are kernel-only: writable, not executable, not marked
user-accessible. Nothing runs in user mode, and a kernel-only page is
one the kernel can always touch: x86-64 SMAP and arm64 PAN, neither of
which NK enables, restrict only pages marked for user mode.

## How each part works

One document per part of the kernel, each with the decisions NK made there:

- [Memory](design/memory.md): Physical frames, the kernel pool and the dynamic region.
- [Processors, interrupts and time](design/processors.md): Per-processor state, interrupt dispatch, clocks.
- [Devices](design/devices.md): PCI configuration space, device memory, device interrupts, DMA.
- [Threads and scheduling](design/threads.md): Threads, the System process and silos, waits, mutexes, DPCs, timers, work items.
- [The executive's locks, lists and timers](design/executive.md): Push locks, sequenced and lookaside lists, resources, executive timers and the rest.
- [System calls](design/syscalls.md): The system-service table, `Nt*`/`Zw*` split and `PreviousMode`.
- [Objects, references and handles](design/objects.md): The object manager and the namespace.
- [The kernel image and its exports](design/image.md): The kernel as a PE image, unwind tables, exports, ABI structures.
- [Exceptions](design/exceptions.md): Structured exception handling and unwinding.
- [Loading and starting drivers](design/drivers.md): The loader and driver start-up.
- [I/O](design/io.md): The I/O manager.
- [The file-system runtime library](design/fsrtl.md): What the kernel does for file systems.
- [The cache manager](design/cc.md): Cache maps, views, pins, copies, flushes and the lazy writer.
- [Power](design/power.md): The power manager and the power framework.
- [Plug and Play](design/pnp.md): The Plug and Play manager.
- [The registry](design/registry.md): Hives, keys, watches and query tables.
- [Strings and the runtime library](design/rtl.md): Strings, file names, tables, bitmaps, descriptors, range lists.
- [Security](design/security.md): Security descriptors, tokens and access state.
- [Tracing](design/tracing.md): Event tracing.
- [The system as a whole](design/system.md): System information, firmware variables, hardware errors, stopping, debug output.
- [What is absent](design/absent.md): What NK does not have, and what happens when it is asked.
