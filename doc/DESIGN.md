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

## As built

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

There is no user mode. The proof drivers are Microsoft's inbox `null.sys` and Microsoft's `sioctl`
sample built with the WDK (see `doc/TESTING.md`).

### The machine description

`kernel/hal/platform.rs` reads the ACPI MADT once, on both architectures:
the processors firmware lists as usable, and where the interrupt
controllers are (local and I/O APICs; the GIC distributor and
redistributors). The boot processor is number 0, as on Windows, and at
most 64 processors are kept, one Windows processor group.

### Every processor

The boot processor starts the others one at a time and waits for each to
report in; one that does not is a failed boot, never a smaller machine.
On x86-64 a processor is woken by INIT and start-up interrupts into a
real-mode trampoline copied to a free page below 1 MiB, which climbs to
long mode on the kernel's page tables. On arm64 firmware starts it (PSCI
`CPU_ON`, by the call the FADT names) in a stub that runs with the MMU
off, on a table mapping only the stub's own page, and then adopts the
boot processor's translation settings.

Each processor has its own area, the PCR at its start, allocated before
it is started (the boot processor's is static: it is needed before memory
is). Each brings up its own interrupt controller and clock interrupt.
Processor 0 alone keeps the time. The context a processor starts in
becomes its idle thread.

`ke::ipi` has other processors run a routine, at the interprocessor
IRQL (14), and waits for all of them; one call is in progress at a time.
A processor that does not answer within five seconds is stuck with
interrupts off, and the system stops. x86-64 uses this to drop a
translation everywhere when a page is unmapped; arm64's invalidation
instruction broadcasts by itself.

The processor that stops the system stops the others first: by a
non-maskable interrupt on x86-64, by the most urgent software-generated
interrupt on arm64 (which a processor with interrupts masked altogether
does not take). A second processor reaching a bugcheck halts silently, so
one report is printed.

### Interrupts

Each processor's interrupt controller is brought up with everything
masked that NK did not ask for: the local APIC on x86-64 (x2APIC mode
when the processor has it), with the legacy 8259s and every I/O APIC
input masked; GICv3 on arm64, where a processor finds its redistributor
by its affinity, not by position. The IRQL is the controller's priority
mask (`doc/LOCKING.md`). So far the interrupts are the clock and ones a
processor sends itself; there is no device interrupt.

### Time

One free-running counter is the source of all time: the TSC on x86-64,
whose rate is measured against the ACPI power-management timer at boot;
the generic timer's counter on arm64, which states its own rate. The
clock interrupt fires 64 times a second, Windows' default, from the local
APIC timer or the generic timer's virtual timer, at IRQL 13. Each tick
recomputes the time from the counter rather than counting ticks, so a
late or lost tick costs nothing.

Code built with the WDK reads the tick count, interrupt time and system
time directly from `KUSER_SHARED_DATA`, a page at a fixed address; the
tick keeps that page current, and its layout is checked against the
kernel's public symbols. The wall clock starts from the firmware's time,
read by the loader.

### Threads

A thread is an `ETHREAD`-sized block, laid out as Windows lays it out
for the fields NK keeps, followed by NK's own state, with a 32 KiB
kernel stack that has nothing mapped below it. Each processor has a
ready queue per priority (0 to 31) with a summary word, and an idle
thread. A thread has an affinity (the processors it may run on) and an
ideal processor, handed out in turn. Made ready, it goes on the queues
of its ideal processor if that one is idle, else of any idle processor
its affinity allows, else of its ideal processor. A processor with
nothing to run takes the best waiting thread it is allowed from another
processor's queues, and a processor that leaves a thread waiting wakes
an idle one to do so.

A processor leaves a thread when the thread yields (giving way to ready
threads of its own priority or higher) or exits; when a thread of higher
priority becomes ready on that processor; or when the thread has run for
its quantum, two clock ticks as on Windows client systems, and another
of its priority is waiting. A thread pushed aside by a higher priority
goes to the front of its queue; one whose quantum is spent, to the back.
There are no priority boosts.

Preemption is requested, then done at the end of an interrupt: readying
a thread, or the clock tick, marks the processor, and the switch happens
when an interrupt handler is about to return below `DISPATCH_LEVEL`,
after the interrupt controller has been told the interrupt is over.
Marking the processor one is on also raises the DISPATCH-level
interrupt, so that moment comes as soon as the IRQL allows, however it
was lowered. The preempted thread resumes inside that interrupt's frame
on its own stack. The switch keeps what a call preserves on the outgoing thread's stack
(vector registers included: xmm6-15 and MXCSR, or d8-d15 and FPCR) and
the stack pointer in the thread's `KernelStack`. An exited thread is
freed by the thread that runs next.

After boot the kernel's own work, the tests today, runs in a thread at
priority 8 and `PASSIVE_LEVEL`, which is what a driver expects of its
caller.

### Mutexes and critical regions

A mutex (`KMUTANT`) is waited for like any other object, but has an
owner: the owner may take it again, only the owner may release it, and
it is free when released as often as taken. A waiter that is let in owns
the mutex from the moment the releasing thread claims it, before it has
run. While a thread holds a mutex or is inside a critical region its
`KernelApcDisable` count is negative, as on Windows, which is what
`KeAreApcsDisabled` reports. A thread that ends holding a mutex stops
the system (`THREAD_TERMINATE_HELD_MUTEX`); releasing one that is not
owned, an exception on Windows, stops it too.

A fast mutex is a count and an event, set up in line by the driver: 1
when free, 0 when held, one lower per waiter. Taking a free one is a
single atomic step; a release that finds waiters passes the mutex to one
through the event. Taking it raises the IRQL to `APC_LEVEL`.

NK does not queue APCs: nothing loaded delivers work that way yet. The
counts and the IRQL are kept as Windows keeps them, so that code which
asks whether APCs are disabled gets Windows' answer.

### Work items

Three queues, as on Windows (critical, delayed, hypercritical), each
with a couple of worker threads at that queue's priority, started at
boot and free to run on any processor. A work item is the driver's
memory, linked through its list entry, whose forward link is null
exactly while it is on no queue, as Windows keeps it. A worker takes an
item off before running it, so a routine may queue its item again or
free it. Queueing is allowed at `DISPATCH_LEVEL`; the routine runs at
`PASSIVE_LEVEL` and must return there with APCs enabled, or the system
stops (`WORKER_THREAD_RETURNED_AT_BAD_IRQL`).

An I/O work item is allocated by the kernel at Windows' size and tied to
a device, which is referenced from queueing until the routine has
returned.

### Breakpoints and the debugger

A driver that executes a breakpoint (`DbgBreakPoint`, which is in-line
code) gets what Windows gives it, and Windows has two answers. Booted
normally, with no kernel debugger, the breakpoint is an exception nobody
handles, and the system stops: bugcheck `0x7E` with exception
`0x80000003`. Booted with debugging enabled, it is the debugger's to
decide, and the system waits for it.

NK does the first by default. With `debug=on` on the kernel command line
it behaves as with a debugger attached that says "go" at every
breakpoint: it notes the breakpoint on the console and continues. NK has
no debugger protocol; `debug=on` only stands for the answer one would
give. The reference Windows machine is given a real one: `tools/kd.py`
plays the debugger over its serial port and says go. The kernel's own tests announce the breakpoints they execute.

### Objects, references and handles

What the object manager allocates has Windows' `OBJECT_HEADER` in front
of it: a pointer count, a handle count, a type. Events and threads are
such objects so far. An object is freed when its last reference goes. A
thread holds a reference on itself until it has ended and been buried,
so a thread nobody else refers to frees itself, and one that is referred
to stays a valid object, signalled, after it ends.

Kernel handles are entries in one table; a handle holds a reference
until closed and has Windows' kernel-handle bits set. There are no
per-process tables and no access checks. A type is named by its address:
a driver imports a variable holding it (`ExEventObjectType`) and passes
the value back, so the type structure itself is NK's own.

### Deferred procedure calls

Each processor has a queue of DPCs. Queueing one puts it on the queue of
the processor that queued it and has that processor's interrupt
controller raise an interrupt at `DISPATCH_LEVEL` (vector 0x2F on
x86-64, a software-generated interrupt on arm64). The interrupt is
delivered when the IRQL falls below `DISPATCH_LEVEL`, by whatever means:
code built with the WDK lowers the IRQL in line on x86-64, so there is no
call for NK to hook. Its handler runs the queue in order.

The driver owns the `KDPC`. As on Windows, `DpcData` is non-null exactly
while the DPC is queued; NK stores the queue's address there. One DPC
that runs for more than 20 seconds stops the system
(`DPC_WATCHDOG_VIOLATION`); the clock tick checks. DPCs run on the stack
of whatever they interrupted, and there is no targeting of another
processor or importance ordering: nothing loaded asks for them.

### Timers

Each processor has a table of the timers set on it and not yet due: 256
buckets, one per clock tick modulo 256, each in order of due time
(`nk_ke::TimerBuckets`). The clock tick reads each bucket's earliest due
time without a lock and, when one has come, queues the processor's expiry
DPC. That takes the due timers out, marks them signalled, puts periodic
ones back, and queues their DPCs with the system time as arguments.

A timer never fires before its due time, and fires at the first tick
after it. A due time already past fires inside `KeSetTimer`. The driver
owns the `KTIMER`; its layout, and the header bits NK uses (`Inserted`,
the lock bit, `Expired`), are Windows'. A timer is also an object threads
wait on: expiry signals it and wakes them.

### Waits

A thread waits on an event, a semaphore or a timer by linking one of the
four wait blocks built into every thread on the object's wait list, and
sleeping until a waker claims it. A wait with a time limit also sets the
thread's own timer and links a second block there, whose key is
`STATUS_TIMEOUT`: the time limit is one more object, and the first to be
signalled ends the wait. A wait may name up to 64 objects, with the
caller's wait blocks beyond three, and be for any one of them (it
reports which) or for all at once (it takes all or none).
`doc/LOCKING.md` gives the rules that make this safe on several
processors.

Events, semaphores, wait blocks and the dispatcher header are laid out
as on Windows (`lib/ntabi/ke.rs`, checked against the kernel's symbols).
Waits are not alertable and deliver no APCs: there are none yet. A wait
that would have to block at `DISPATCH_LEVEL` stops the system
(`ATTEMPTED_SWITCH_FROM_DPC` from a DPC routine). There are no priority
boosts on wake-up. Releasing a semaphore past its limit, which raises an
exception on Windows, stops the system: NK has no exceptions yet.

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
  bump-allocated, with a small cache of freed ranges reused by size;
  frames are freed on unmap.
- **Kernel stacks.** 32 KiB each, mapped in the same region with the
  32 KiB below left unmapped, so running off the bottom faults. The top
  is a multiple of 64 KiB, which puts one address bit at 1 across the
  stack and at 0 across the gap. On x86-64 the overflow arrives as a
  double fault on its own stack and is recognised by the faulting
  address. arm64 takes exceptions on the current stack, so exception
  entry tests that bit of the stack pointer before it stores anything and
  reports from a per-processor overflow stack. Either way the bugcheck
  says "kernel stack overflow". The kernel moves from the loader's stack
  to one of these as soon as memory is up. Windows' kernel stacks are
  24 KiB on x86-64; no driver can depend on the exact size.

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
requestor and signal its event.

A dispatch routine is called inside a critical region, as on Windows for
a synchronous request: a driver that asks finds kernel APCs disabled.

A driver may pend a request (`STATUS_PENDING`) and complete it later,
from a DPC, a timer or a worker thread; the requestor waits on an event
that completion sets. The requestor owns the IRP and frees it once it
has seen the completion, so a request can be cancelled at any time
before that. Windows finishes a request in the requesting thread, by an
APC; NK finishes it wherever it was completed, at `DISPATCH_LEVEL` or
below, which no driver can tell apart while there is no user memory to
copy to.

Cancelling (`IoCancelIrp`) marks the IRP, takes out its cancel routine
in one atomic step, and calls it holding the system-wide cancel spin
lock, which the routine releases. A driver completing a request takes
the routine out the same way, so exactly one of the two completes it. An
IRP completed with its cancel routine still set stops the system when it
is cancelled (`CANCEL_STATE_IN_COMPLETED_IRP`).

A driver that returns something other than `STATUS_PENDING` without
completing its IRP, or a different status than it completed the IRP
with, has broken the contract; both are reported as failures.

Direct I/O uses real MDLs: the requestor's buffer is described by its
physical pages, and when the driver asks for a system address the pages
are mapped at a fresh kernel address, so the driver works through its own
view of the caller's memory. Limits are listed at the top of
`kernel/io/mdl.rs`; the main one is that only kernel buffers can be
described, since there is no user address space.

The object namespace is a flat table of device names and symbolic links,
case-insensitive, with `\DosDevices`, `\??` and `\GLOBAL??` as one
directory. Names are not opened by handle; there are no directories and
no security checks.

### What NK leaves out, and how it stays honest

No waits, SEH, PnP or power management. Where a proof
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
