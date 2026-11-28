# The kernel image and its exports

Part of NK's design ([DESIGN.md](../DESIGN.md)): the principles there apply.

## The kernel is a PE image

The kernel builds for Rust's stock `x86_64-unknown-uefi` and
`aarch64-unknown-uefi` targets:

- prebuilt on stable Rust: no nightly, no `build-std`, no target file;
- the Windows calling convention is the target's native `extern "C"`, so
  every export has the ABI drivers expect (`doc/ABI.md`);
- one PE loader, `lib/pe`, maps the kernel (in `nkload`) and the drivers
  (in the kernel), so the code that must be right for drivers runs on
  every boot.

### Unwind tables

The kernel image has a function table (`.pdata`) like any driver's, so
its frames can be walked by the rules of
[x64](https://learn.microsoft.com/en-us/cpp/build/exception-handling-x64)
and [arm64](https://learn.microsoft.com/en-us/cpp/build/arm64-exception-handling)
exception handling. The Makefile builds the loader and kernel with
`-C force-unwind-tables=yes`; every assembly routine states its own with
`.seh_*` directives.

- **A stack ends at return address zero.** A thread's start stub, the
  boot stack, a started processor's stack and arm64's overflow stack are
  all entered as if called from address zero.
- **Interrupt frames are crossed like any other frame.** x86-64: each
  vector's stub calls the common path, so the frame holds an ordinary
  return address above the saved registers and below the error code and
  the CPU's frame. From any instruction of entry or exit a walk recovers
  the interrupted code's `rip`, `rsp`, every integer register and
  XMM0-XMM5. arm64: from the handler's call until the frame is given up
  a walk recovers `pc`, `sp`, x19-x30 and d8-d15; `sp` and `pc` sit in
  the frame as the pair the unwind codes call a machine frame.
- **A thread that is not running** is walked from its saved stack
  pointer as if stopped inside the switch routine.

Not covered:

- arm64 exception entry up to the frame's last store, and the last two
  instructions of the way out: the interrupted `pc` is in `ELR_EL1`
  alone there, where no unwind code reaches. The vector table and the
  overflow stub have no entries.
- Code that starts a processor before it is on the kernel's page tables
  (the x86-64 trampoline, arm64's `nk_ap_stub`).
- The prebuilt `compiler_builtins` (`memcpy`, 128-bit division): Rust
  ships it without tables, and the link-time optimisation leaves it
  apart. `core` and `alloc` are optimised with the kernel as one
  program (`lto = "fat"` in the workspace's release profile), so their
  code is compiled with NK and has entries.
- x86-64 MXCSR and arm64 FPCR of interrupted code: they are in the trap
  frame, but unwind codes have no way to name them.

A compiled function that uses no stack has no entry either, on both
architectures. That is the convention for a leaf: its return address is
where the call left it, at `[rsp]` or in `x30`.

The gate holds the uncovered code to this list (`make unwind-check`,
`doc/TESTING.md`): a new assembly routine without unwind directives
fails it.

**Walking a stack** (`kernel/ke/unwind.rs`). A walk starts from the
registers a function captures of itself (`arch::unwind::capture`) and
undoes one frame at a time: the image the program counter is in, the
function's entry in that image's table, the registers of the frame
beneath (`nk_unwind`). It ends at the zero return address. It stops
with an error, never a guess or a fault, when:

- a program counter is in no image;
- a frame needs a stack slot outside the stacks the processor can be
  on: the running thread's and, at `DISPATCH_LEVEL` or above, the
  processor's DPC stack;
- a function has no entry and is not where a leaf can be. A leaf calls
  nothing, so only the code an interrupt stopped, the frame right
  beneath an interrupt frame, can be one. Any other frame is waiting
  for a call to return and must have an entry; the error names the
  image and offset. So a walk never passes through a prebuilt function
  that called NK code. Where an interrupt stopped inside a prebuilt
  function the walk cannot tell: it takes it for a leaf, which it need
  not be.

A return address is looked up as Windows does: as it is on x86-64, as
the instruction before it on arm64.

The tests `seh.walk.*` walk from a thread, from a DPC routine across
the change of stack, and from an interrupt handler through the
interrupt frame, each down to the thread's start stub; mutants take an
unwind directive away from a stub on each architecture.

**Image views.** Unwind data is read through a second mapping of each
image, the kernel's included, made when the image is entered in the
table of images (`ldr::view`): all of the image, read-only, where a page
of a section the image cannot write shows that page and every other
page shows zeros. Nothing can change a byte of it and no offset into it
faults, so the unwinder can be handed the whole image as one slice
while the image's own data keeps changing.

## Exports

Drivers import from `ntoskrnl.exe` and `HAL.dll` by name; both names
resolve against one static table, kept as a list per part of the kernel
that implements the routines (`kernel/export/list/`). Each entry is
the name, the address and a state: `Implemented`, `Partial` (gaps
documented at the function) or `Traps` (bound so the driver loads;
bugchecks by name if called). The same table feeds the import binder and,
through the boot log, the ledger, so the ledger cannot drift from what
the kernel exports. An import with no entry rejects the driver and names
the symbol.

Two more spellings reach the same table (`kernel/export/mod.rs`). An
import from the kernel by number is bound through a short list of the
numbers Microsoft's binaries use, each with the name Microsoft's public
symbols give the routine: NK's table has names, not Microsoft's
numbering.

An import from an extension API set (`ext-ms-*`: `acpi.sys` and
`pci.sys` import `ext-ms-win-ntos-ksr`) is left as the image has it.
Such a set may have no module on a given Windows, so the linker puts
in each import's slot a routine of the importing image itself, which
answers "not supported"; Windows' loader overwrites the slot only when
its API-set schema names a host. NK hosts no extension set: the slot
stays, checked to hold an address inside the image (`nk_pe::Bind::Own`).

A driver can also ask for a routine by name while it runs
(`MmGetSystemRoutineAddress`) and do without it when the answer is
null. No import table shows such a name, so each one not found is
printed in the boot log and the ledger lists them (`looked_up_absent`).

### Exported variables

Some imports are variables: the driver reads, and sometimes writes,
through the address its import is bound to. No trap can stand in for
one, so a variable is exported only when it is real.

`HalDispatchTable` and `HalPrivateDispatchTable` (`kernel/hal/dispatch.rs`,
slots listed in `nk_ntabi::hal`) are the tables Microsoft's bus drivers
call the HAL through and store their own routines into. They have
Windows' versions, sizes and slot order; the private table is in no
header, and its slots are checked against the pinned kernel's symbols.
A slot NK has no routine for holds a trap that stops the system naming
the table and the slot. NK reads a slot atomically each time it uses
one, since a driver may have replaced it.

What the slots hold so far, each as the pinned kernel's HAL behaves:
`HalInitPowerManagement` (`kernel/hal/acpi.rs`) takes `acpi.sys`'s
table of routines and gives it the HAL's ACPI table, a third table of
the same kind with Windows' signature, version and slot order, whose
`HalAcpiGetTable` finds a firmware table by signature (`RSDT` and
`XSDT` both name the root table there is; `DSDT` is found through the
FADT; `nk_acpi::lookup`), and whose `HalAcpiGetAllTables` lists every
table the root table lists but the root tables, the DSDT and the FACS,
as a count and pointers, made once. Both give the firmware's own
tables where Windows gives copies. The public table's
`HalGetCachedAcpiTable` holds the same routine as `HalAcpiGetTable`, as
in Windows' HAL (`pshed.dll` would look for the boot error record
table through it). `HalAcpiMachineStateInit` takes
the sleep states the firmware has and answers with the interrupt model
for the firmware's `_PIC` method (the APIC's on x86-64, a version 3
GIC's on arm64); Windows' HAL registers its sleep routine with the
power manager for each state, NK registers nothing, since it never
sleeps and powers off through the firmware's runtime services.
`HalInterruptGetApicVersion` (`kernel/hal/interrupt.rs`) tells it how
many lines an interrupt controller has, in the shape of an I/O APIC's
version register, which Windows' HAL makes up from its own count
rather than read. `HalPciInterfaceReadConfig` and
`HalPciInterfaceWriteConfig` (`kernel/hal/pci.rs`) are the
configuration access `acpi.sys` uses for firmware's AML and hands
`pci.sys` as a root bus's interface: the HAL's own access, by bus and
slot number, always reporting the whole length done as Windows' do.
`HalSetMaxLegacyPciBusNumber` has nothing to do: Windows' HAL answers
its bus-data exports only up to the highest bus `acpi.sys` reports,
NK's for every bus a configuration mechanism reaches. The table's
remaining routines that
`acpi.sys` uses at start (`kernel/hal/pm.rs`) give it the FACS and
ACPI's fixed hardware: whether a register block exists, and one access
of it read or written. The blocks are set up once from the FADT by
Windows' rules (`nk_acpi::pm_registers`: the 32-bit ports before
revision 5 of the table, the extended addresses from it, none on a
hardware-reduced machine), and `acpi.sys` names a block by its number
in Windows' order. A block in PCI configuration space, which Windows
supports, is absent on NK. `HalQuerySystemInformation`
(`kernel/hal/sysinfo.rs`) answers the information classes drivers
reach and stops the system naming any other. One is the list of I/O
ports the ACPI driver must keep firmware's AML code away from: on
x86-64 the PC's interrupt controllers, timers, clock and DMA
controllers, as Windows' HAL lists them, and the PCI configuration
ports, which carry a routine of the HAL's: AML's accesses to those are
not made on the ports but carried out by the HAL through its own
configuration access. arm64 has no I/O ports and an empty list. Two
more are asked by `acpi.sys`'s interrupt arbiter as it is set up: the
HAL's secondary interrupt services, which NK lacks (no interrupt
controller behind another interrupt, such as a GPIO controller, is
served) and reports as Windows' HAL does while it has none, a failure;
and the limit of message-signalled interrupts for one device, where NK
keeps Windows' value, 2048, which is no limit. `pci.sys` asks, for
each device it reports, what memory an IOMMU reserves for it: NK
drives no IOMMU and answers as Windows' HAL does when it finds none
for the device, `STATUS_NOT_FOUND`. For the same reason
the private table's `HalIsInterruptTypeSecondary`, which the arbiter
asks of every line it gives out, says no for every interrupt.

`HalGetInterruptTargetInformation` (`kernel/hal/target.rs`), an export
rather than a slot, tells `pci.sys` how interrupts name their
destination: by a processor's own identifier (physical mode) on both
architectures, with messages deliverable where the architecture's
controller takes them. `acpi.sys` asks it for each processor the
firmware lists, by its controller's identifier, and gets the
processor's number, or `STATUS_NOT_FOUND` for one that is not running.

Four more undocumented exports answer from the same facts
(`kernel/hal/query.rs`). `HalGetProcessorIdByNtNumber` gives a
processor's identifier: its local APIC's on x86-64, its `MPIDR`
affinity on arm64, where one that does not fit 32 bits stops the system
(NK has no arm64 Windows kernel to learn how that is named).
`HalConvertDeviceIdtToIrql` is Windows' rule on x86-64 and the level NK
gives the interrupt id on arm64. `HalGetMessageRoutingInfo` routes a
message as it stands, since NK remaps no interrupts: its own address
and data come back, for one running processor or all of them in
physical mode, and any other target is refused. NK takes no caching
requirements from firmware, so `HalGetMemoryCachingRequirements` finds
none for any range, as Windows does with an empty table.

The start-up state drivers read (`kernel/kd/variables.rs`):
`KdDebuggerEnabled` is false and `KdDebuggerNotPresent` true, NK
speaking no Windows debugger protocol; `KdComPortInUse` names the I/O
port of NK's own console, as Windows names its debugger's, so that
`acpi.sys` and `serial.sys` leave the port alone; `InitSafeBootMode` is
0; `Mm64BitPhysicalAddress` is true.

### Drivers that export to drivers

An import from any other module is from an export driver, a library
([Creating Export Drivers](https://learn.microsoft.com/en-us/windows-hardware/drivers/kernel/creating-export-drivers)).
The loader binds it through that image's export directory
(`nk_pe::exports`), by name or by ordinal. An export that is a forwarder
(`MODULE.Name`, `MODULE.#ordinal`) is followed, to the kernel's table
or to another loaded library, at most eight in a row; a forwarder does
not load its target.

- **Where a library comes from.** An image of that file name that is
  loaded as a library; else the boot file of that name, loaded now. The
  boot files stand for both places Windows looks, beside the importer
  and then `System32\drivers`.
- **Loading one.** Like any image; then its export `DllInitialize` is
  called at `PASSIVE_LEVEL` with
  `\Registry\Machine\System\CurrentControlSet\Services\<name>`, a
  key that need not exist. Its entry point is not called. A failing
  `DllInitialize` unloads it and fails the importer's load.
- **A library that is also a boot driver.** A boot-start service whose image is loaded
  already as a library (`ksecdd.sys`, which `fastfat.sys` imports from
  and which starts after it) is started from that image: its entry point
  is called then, as Windows' loader, which loads each image once,
  calls a boot driver's entry point however many others import from
  it. The library keeps the image; the driver's unload leaves it. A
  service started later is refused, `STATUS_IMAGE_ALREADY_LOADED`, as
  Windows refuses it.
- **Lifetime.** Each loaded importer counts once, in the library's
  record in the table of images. When the last goes, the library's
  `DllUnload` is called and the library unloaded, after its importer;
  the next importer loads it afresh. As Microsoft documents, a library
  without `DllUnload`, or whose `DllUnload` fails, stays loaded.
- **A refused importer leaves nothing.** Its libraries lose it as an
  importer again, and one loaded for it alone is unloaded. The memory
  to count an importer and to list a library is taken before the
  library is loaded and before its code runs, so a load that runs out
  of memory fails with nothing loaded and nothing to undo.

What a refused load is called is what Windows' `NtLoadDriver` returns
on the reference system; the transcripts (`oracle/nkc-lib*.txt`) show
only that the load failed:

| Refusal | Status |
| --- | --- |
| the library lacks a name the importer asks for | `STATUS_DRIVER_ENTRYPOINT_NOT_FOUND` |
| the library is nowhere | `STATUS_OBJECT_NAME_NOT_FOUND` |
| the driver is loaded already | `STATUS_IMAGE_ALREADY_LOADED` |
| a library started as a service | its entry point's own status (`nkc-lib`: `STATUS_NOT_SUPPORTED`) |

A missing ordinal is `STATUS_DRIVER_ORDINAL_NOT_FOUND`, by the name of
the status alone.

Not handled:

- API sets that must have a host (`api-ms-*`);
- importing from an image that runs as a driver (started from its
  service key) rather than as a library: refused;
- images that import from each other in a circle: refused, at eight
  libraries deep.

## ABI structures

Everything a driver can see is declared once in `lib/ntabi` as
`#[repr(C)]` with compile-time size and offset asserts per architecture.
Documented structures are compared with a table built by the WDK;
private ones with the pinned kernel's public symbols, through NK's own
PDB reader (`lib/pdb`). State of both: `doc/ABI.md`.
