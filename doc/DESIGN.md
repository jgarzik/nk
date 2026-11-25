# NK design

What NK is, the principles every phase follows, and the decisions already
built into the code, each with its reason. Windows concepts are not
explained here; see Microsoft's
[driver documentation](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/_kernel/)
and the [PE format](https://learn.microsoft.com/en-us/windows/win32/debug/pe-format).
The order of work is in `doc/ROADMAP.md`.

## What NK is

NK is a replacement for two files of Windows 10: `ntoskrnl.exe` and
`hal.dll`, plus a loader (`nkload`) that stands in for Microsoft's boot
manager and `winload`. Nothing else is NK's.

- **Every other kernel-mode component is Microsoft's binary, loaded as a
  driver:** the ACPI and PCI drivers, the storage port and its miniports,
  the file systems, the driver framework (KMDF), the network stack, the
  window system. NK does not write its own PCI bus driver, AML
  interpreter, SCSI layer or file system.
- **All of user mode is Microsoft's:** `ntdll.dll`, the session manager,
  `csrss.exe`, `cmd.exe`. NK serves them the system calls of one exact
  Windows build.
- **NK ships none of it.** The Windows files come from Microsoft's own
  servers or the user's media, at test or install time. Tests fetch
  x86-64 files from Microsoft's symbol server; nothing is taken from the
  deployment kit (WinPE), whose licence does not cover testing.

The reason is the golden rule turned on Microsoft's own code: if an
unmodified driver cannot tell NK from Windows, then Microsoft's inbox
drivers are simply more drivers. Measurement supports it: the whole
corpus of 58 inbox kernel binaries needs 1740 of the kernel's roughly
3070 exports, and stacking Microsoft's KMDF and USB drivers on top of the
storage and file-system set adds only 40 of those (`doc/ROADMAP.md`).
Rewriting those layers would take years and create second ABIs (storport,
NDIS, KMDF) for third-party drivers to find fault with.

The destination is a Windows rescue disk: Microsoft's Windows PE image at
a `cmd.exe` prompt on QEMU x86-64, QEMU arm64 and a Dell OptiPlex.

## Principles

1. **An unmodified Windows driver binary must not be able to tell NK from
   Windows.** Exports, calling conventions, structure layouts, IRQL and
   lifetime rules are binding. This outranks every other principle.
2. **Windows-shaped wherever a binary can look; NK's own everywhere
   else.** Third-party drivers see the documented structures. Microsoft's
   inbox drivers and the window system were built against private headers
   and may also read the thread, process, processor and object-header
   structures in line. Any object a binary can reach has Windows' size and
   field offsets for the pinned build, and NK keeps its private state
   beside it, never inside a larger struct in its place. What no binary
   can observe (algorithms, internal tables, the loader hand-off) is NK's
   to design.
3. **No fake success.** A missing import rejects the driver and names the
   symbol. A routine that cannot do its job fails as its contract says or
   stops the machine. A feature NK lacks (hypervisor, secure kernel, code
   integrity) answers "not present" the way Windows does without it.
4. **Windows is the oracle.** A behaviour is verified when the same test
   gives the same result on a reference Windows installation and on NK.
   Until then the ledger says "implemented", not "verified".
5. **Scope follows evidence.** NK exports a routine because a binary in
   the pinned corpus imports it. The ledger carries the denominators.
6. **One exact build.** Drivers of the whole Windows 10 2004-22H2 family
   must run. User mode, the system-call numbers and the private layouts
   come from a single revision of it: 10.0.19045.2006, the build of
   Microsoft's Windows 10 Enterprise evaluation ISO, which is also what the
   reference VM runs.
7. **Hardware is found through ACPI on both architectures,** because
   Microsoft's `acpi.sys` and `pci.sys` do the enumerating.
8. **Sources.** Microsoft's documentation, headers and samples; the
   public symbols of the pinned build; the fixture binaries themselves,
   read for what they expect of a kernel; a reference Windows VM. ReactOS
   and Wine may be read to understand behaviour. No code is copied or
   translated from them, and nothing from leaked Windows source or the
   Windows Research Kernel is used at all.
9. **Written fresh.** The kernel has no external crates and takes no code
   from its sibling Linux-compatible kernel,
   [hk](https://github.com/jgarzik/hk). hk is a reference for hardware
   bring-up and the model for the gate, the boot-test harness and
   differential testing against the real system.
10. **Both architectures are first class.** Every commit builds and boots
    x86-64 and arm64. Where a Microsoft arm64 binary cannot be obtained,
    its test prints SKIP; the NK code beneath it is still built and run.

Drivers are trusted but memory-unsafe code: NK never holds a Rust
reference into memory a driver can write.

## Boot, mirroring Windows

Windows on QEMU boots as: UEFI firmware, `bootmgfw.efi` from the EFI
system partition, `winload.efi`, which loads `ntoskrnl.exe`, `hal.dll`,
the `SYSTEM` registry hive and the boot-start drivers it names, builds a
loader block, leaves boot services and jumps to the kernel. On arm64 the
`virt` machine is described by ACPI, as on x86.

NK keeps that shape with one loader, `nkload`, standing in for both
Microsoft stages. It hands the kernel a private `BootInfo` block. NK does
not imitate the Windows loader block: no driver sees it, so it is not part
of the contract. Today `nkload` loads the kernel and a fixed list of test
drivers; reading the hive and its driver list arrives with the registry.

## As built in 0.0.1

The rest of this file records what the code does today. On QEMU, x86-64
and arm64 alike:

1. UEFI firmware starts `nkload`.
2. `nkload` reads the kernel and the driver files from the EFI system
   partition, maps the kernel, leaves boot services and jumps to it.
3. The kernel takes over the CPU and memory, then loads each driver:
   map, relocate, bind imports, call the real `DriverEntry`.
4. A built-in test opens the driver's device, sends real IRPs and checks
   status, byte count and payload.
5. Results go to the serial port as `NK-TEST` lines; the machine powers
   off.

There is no user mode, no scheduler and only the boot CPU runs. The
proof drivers are Microsoft's inbox `null.sys` and Microsoft's `sioctl`
sample built with the WDK (see `doc/TESTING.md`).

### The machine description

`kernel/hal/platform.rs` reads the ACPI MADT once, on both architectures:
the processors firmware lists as usable, and where the interrupt
controllers are (local and I/O APICs; the GIC distributor and
redistributors). The boot processor is number 0, as on Windows, and at
most 64 processors are kept, one Windows processor group. Nothing starts
the other processors or touches the controllers yet.

### The kernel is a PE image

NK builds the kernel for Rust's stock `x86_64-unknown-uefi` and
`aarch64-unknown-uefi` targets, which produce PE images, rather than as a
freestanding ELF. Reasons:

- They are prebuilt targets on stable Rust. No nightly, no `build-std`,
  no custom target file.
- The Windows calling convention is the target's native `extern "C"`,
  so every export has the ABI drivers expect without per-function
  annotation. Measured results are in `doc/ABI.md`.
- One PE loader, `lib/pe`, is used twice: the loader maps the kernel with
  it and the kernel maps drivers with it. The code that must be right for
  drivers is exercised on every boot.
- PE images carry unwind tables, which SEH needs.

### Exports are a table, not a PE export directory

Drivers import from `ntoskrnl.exe` and `HAL.dll` by name. NK resolves
those names against a static registry built by a macro. Each entry
records the module, the name, the function and an honest status. The same
registry feeds the import binder and the compatibility ledger, so the
ledger cannot drift from what the kernel really exports.

An import with no entry rejects the driver and names the symbol.

Not yet handled, and needed by Microsoft's inbox drivers: imports by
ordinal, kernel-mode API-set names (`ext-ms-*`), and drivers that export
to other drivers.

### ABI structures

Everything a driver can see is declared once in `lib/ntabi` as
`#[repr(C)]` with compile-time size and offset checks for each
architecture. Documented structures are compared with a table built by
the WDK; private ones (principle 2) with the type information in the
public symbols of the pinned kernel, read by NK's own PDB reader
(`lib/pdb`). `doc/ABI.md` has the state of both.

### Pure logic lives in `lib/`

Anything that can be written without touching hardware goes in a
`no_std` library crate and is unit-tested on the build host: PE loading,
structure layouts, string and list routines, allocator arithmetic, page
table construction. The kernel binary is the glue and the `unsafe`.

### Memory

- **Frames.** A bitmap allocator over `EfiConventionalMemory` only.
  Loader allocations and firmware boot-services memory stay reserved (on
  arm64 the latter holds firmware's live page tables). Reclaiming them is
  future work.
- **Pool.** Small requests come from 1 MiB arenas with 16-byte alignment;
  requests of about a page or more get their own page-aligned frames, as
  on Windows. All pool memory is in the direct map: non-paged and
  physically contiguous. There is no paged pool; a paged-pool request
  gets non-paged memory, which is always a legal answer.
- **Pool checking.** Each block ends in guard bytes checked on free, a
  free of anything but a live block is refused, and live counts are kept.
  The driver-unload leak test compares those counts.
- **Kernel mappings.** Driver images are mapped above the kernel image
  with 4 KiB pages and each section's own protection. Address space is
  bump-allocated and not reused; frames are freed on unmap.

### Loading a driver

`kernel/ldr` checks the image is a native PE32+ for this machine, lays it
out in fresh frames, relocates it to a fresh kernel address, binds every
import against the export table, and only then maps it with each
section's protection. Two things the import table does not show:

- **The stack cookie.** MSVC-built drivers check at entry that the loader
  replaced the default `__security_cookie`, and `__fastfail` if not. The
  loader finds the cookie through the load configuration directory and
  writes a per-image value (non-zero, not the default, top 16 bits clear
  as the x86-64 check requires). Its entropy is only the cycle counter.
- **Instruction cache.** On arm64 the image is written through one address
  and run from another, so the loader synchronises the caches.

A refused image leaves nothing allocated; the boot tests check that.

### I/O

Driver, device and file objects and IRPs are pool allocations of exactly
their Windows size, reached by raw pointer. A device object is followed
by the driver's extension and then a private NK block (where Windows has
its own private extension).

`kernel/io/file.rs` plays the part of the I/O system services: it
resolves a name, builds a real IRP and calls the driver's dispatch
routine. Completion follows the Windows sequence: unwind the stack
locations running completion routines, then copy results to the
requestor, signal its event and free the IRP.

Requests are synchronous. A driver that returns without completing its
IRP cannot be waited for without threads, so that is reported as a
failure rather than hung on. A dispatch routine that returns a different
status than it completed the IRP with is reported too.

Direct I/O uses real MDLs: the requestor's buffer is described by its
physical pages, and when the driver asks for a system address the pages
are mapped at a fresh kernel address, so the driver works through its own
view of the caller's memory. Limits are listed at the top of
`kernel/io/mdl.rs`; the main one is that only kernel buffers can be
described, since there is no user address space.

The object namespace is a flat table of device names and symbolic links,
case-insensitive, with `\DosDevices`, `\??` and `\GLOBAL??` as one
directory. There are no handles, no directories and no security checks.

### What 0.0.1 leaves out, and how it stays honest

No threads, waits, timers, SEH, PnP or power management. Where a proof
driver imports something in that territory but never reaches it on the
tested path, the export exists and stops the machine with a named
bugcheck if called. The ledger lists those separately; they never count
as implemented.

SEH is the sharpest edge. `sioctl.sys` imports `__C_specific_handler`
and `ProbeForRead` for its `METHOD_NEITHER` path. `ProbeForRead` performs
the Windows checks, but where Windows raises an exception NK bugchecks,
and so does `MmProbeAndLockPages` on an inaccessible buffer. A driver's
`__try` block protects nothing on NK yet.

### Dependencies

The loader speaks UEFI through its own small bindings and the kernel has
no external crates.
