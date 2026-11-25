# NK design

Decisions and their reasons. Where NK departs from `doc/handoff.md`, it
says so. Windows concepts are not explained here; see Microsoft's
[driver documentation](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/_kernel/)
and the [PE format](https://learn.microsoft.com/en-us/windows/win32/debug/pe-format).

## The MVP: 0.0.1, driver bootstrap

On QEMU, x86-64 and arm64 alike:

1. UEFI firmware starts `nkload`, NK's own loader.
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

## Boot, mirroring Windows

Windows on QEMU boots as: UEFI firmware, `bootmgfw.efi` from the EFI
system partition, `winload.efi`, which loads `ntoskrnl.exe`, `hal.dll`
and the boot-start drivers as PE images, builds a loader block, leaves
boot services and jumps to the kernel. On arm64 the `virt` machine is
described by ACPI, as on x86.

NK keeps that shape with one loader, `nkload`, standing in for both
Microsoft stages. It hands the kernel a private `BootInfo` block. NK does
not imitate the Windows loader block: no driver sees it, so it is not part
of the contract.

## The kernel is a PE image

The handoff suggests a freestanding ELF kernel. NK builds the kernel for
Rust's stock `x86_64-unknown-uefi` and `aarch64-unknown-uefi` targets
instead, which produce PE images. Reasons:

- They are prebuilt targets on stable Rust. No nightly, no `build-std`,
  no custom target file.
- The Windows calling convention is the target's native `extern "C"`,
  so every export has the ABI drivers expect without per-function
  annotation. Measured results are in `doc/ABI.md`.
- One PE loader, `lib/pe`, is used twice: the loader maps the kernel with
  it and the kernel maps drivers with it. The code that must be right for
  drivers is exercised on every boot.
- PE images carry unwind tables, which SEH will need later.

## Exports are a table, not a PE export directory

Drivers import from `ntoskrnl.exe` and `HAL.dll` by name. NK resolves
those names against a static registry built by a macro. Each entry
records the module, the name, the function and an honest status. The same
registry feeds the import binder and the compatibility ledger, so the
ledger cannot drift from what the kernel really exports.

An import with no entry rejects the driver and names the symbol.

## ABI structures

Everything a driver can see is declared once in `lib/ntabi` as
`#[repr(C)]` with compile-time size and offset checks for each
architecture. The kernel keeps its private state beside these objects,
never inside a larger struct in their place.

## Pure logic lives in `lib/`

Anything that can be written without touching hardware goes in a
`no_std` library crate and is unit-tested on the build host: PE loading,
structure layouts, string and list routines, allocator arithmetic, page
table construction. The kernel binary is the glue and the `unsafe`.

## Memory

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

## Loading a driver

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

## I/O

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

The object namespace is a flat table of device names and symbolic links,
case-insensitive, with `\DosDevices`, `\??` and `\GLOBAL??` as one
directory. There are no handles, no directories and no security checks.

## What the MVP leaves out, and how it stays honest

No threads, waits, timers, SEH, PnP or power management. Where a proof
driver imports something in that territory but never reaches it on the
tested path, the export exists and stops the machine with a named
bugcheck if called. The ledger lists those separately; they never count
as implemented.

## Dependencies

The loader speaks UEFI through its own small bindings and the kernel has
no external crates. Reuse from the sibling `hk` kernel is by idea and by
small MIT-licensed pieces with attribution, not by wholesale import.
