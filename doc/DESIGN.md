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
inbox drivers are just more drivers. The inbox corpus needs a little
over half of the kernel's exports, and Microsoft's frameworks (KMDF,
USB) add few of those, because they carry the rest themselves
(`doc/ROADMAP.md`). Rewriting those layers would cost years and create
second ABIs (storport, NDIS, KMDF) to get wrong.

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
10. **Both architectures are first class.** Every commit builds and boots
    both. Where a Microsoft arm64 binary cannot be obtained its test
    prints SKIP; the NK code beneath it is still built and run.

Drivers are trusted but memory-unsafe: NK never holds a Rust reference
into memory a driver can write.

## Source map

| Path | Contents |
| --- | --- |
| `boot/` | `nkload`, the UEFI loader |
| `kernel/main.rs` | entry and boot order |
| `kernel/arch/{x86_64,aarch64}/` | everything CPU-specific: traps, thread switch, interrupt controller, clock, processor start. The only place `cfg(target_arch)` appears |
| `kernel/<part>/` | one directory per NT part: `ke`, `ex`, `mm`, `ob`, `io`, `ps`, `se`, `cm`, `rtl`, plus `hal`, `ldr` (image loading, boot files), `kd` (console, bugcheck) |
| `kernel/export/` | the export table |
| `kernel/selftest/` | the boot-test groups |
| `lib/` | pure, host-tested crates: PE and PDB readers, function tables, unwinding and exception decisions (`unwind`), page tables and allocators (`mm`), scheduler, wait and timer logic (`ke`), interrupt-controller encodings and MADT reading (`hal`), namespace and handle slots (`ob`), structure layouts (`ntabi`), registry, security descriptors |
| `tools/` | boot harness and judge, fixture fetcher, ledger, oracle VM, mutants, the gate |
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
3. Move from the loader's stack to a guarded kernel stack.
4. `hal::platform` (MADT), interrupt controller, the idle thread (the
   context being run), interrupts on: from here only the IRQL holds them
   back.
5. Time, IPIs, DPCs, the other processors, work queues, registry.
6. A thread at priority 8 and `PASSIVE_LEVEL`, what a driver expects of
   its caller, prints the export table and runs the test groups, which
   load the drivers and send them IRPs; the machine powers off. The boot
   context becomes processor 0's idle loop.

Any step that fails prints a `FAIL` line and stops. There is no user mode.

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
are (see "I/O"). A range that touches a firmware runtime
region is refused, since those share the low half.

The pages are kernel-only: writable, not executable, not marked
user-accessible. Nothing runs in user mode, and a kernel-only page is
one the kernel can always touch: x86-64 SMAP and arm64 PAN, neither of
which NK enables, restrict only pages marked for user mode.

## Memory

- **Frames.** A bitmap allocator over `EfiConventionalMemory` only,
  never below 1 MiB. Loader allocations and firmware boot-services memory
  stay reserved.
- **Pool.** Small requests come from 1 MiB arenas at 16-byte alignment;
  requests of about a page or more get their own page-aligned frames, as
  on Windows. All pool is in the direct map: non-paged and physically
  contiguous. A paged-pool request gets non-paged memory, always a legal
  answer.
- **Pool checking.** Each block ends in guard bytes checked on free, a
  free of anything but a live block is refused, and live counts are kept;
  leak tests compare them. These are bug detectors, not mitigations.
- **Dynamic mappings.** Address space is bump-allocated with one unmapped
  page after each range, plus a small cache of freed ranges reused by
  exact size, so a driver loaded and unloaded repeatedly lands on the
  same addresses and leak checks can compare frame counts. Frames are
  freed on unmap; intermediate page tables never are.
- **Kernel stacks.** 32 KiB, with 32 KiB unmapped below. The top is a
  multiple of 64 KiB, so one address bit is 1 across the stack and 0
  across the gap. x86-64 takes the overflow as a double fault on its own
  IST stack and recognises it by the faulting address. arm64 takes
  exceptions on the current stack, so exception entry tests that bit of
  the stack pointer before storing anything and reports from a
  per-processor overflow stack. Windows' stacks are 24 KiB on x86-64; no
  driver can depend on the size.

## Processors

`kernel/hal/platform.rs` reads the ACPI MADT once: the usable processors
and the interrupt controllers (local and I/O APICs; GIC distributor and
redistributors). The boot processor is number 0; at most 64 are kept, one
Windows processor group.

The boot processor starts the others one at a time and waits for each; one
that does not report is a failed boot, never a smaller machine. x86-64:
INIT and start-up interrupts into a real-mode trampoline copied below
1 MiB, which climbs to long mode on the kernel's page tables. arm64: PSCI
`CPU_ON` (by the call the FADT names) into a stub that runs with the MMU
off on a table mapping only its own page, then adopts the boot
processor's translation settings and NK's low half.

Each processor has its own area, the PCR at its start and NK's `PerCpu`
(held locks, DPC queue, timer table, ready queues) beside it, allocated
before the processor starts. Each brings up its own interrupt controller
and clock interrupt; processor 0 alone keeps the time. The context a
processor starts in becomes its idle thread.

`ke::ipi` runs a routine on other processors at IRQL 14 and waits for all
of them; one call is in progress at a time. A processor silent for five
seconds is stuck with interrupts off, and the system stops. x86-64 uses
this to drop a translation everywhere on unmap; arm64's invalidation
broadcasts by itself.

The processor that stops the system stops the others first: by NMI on
x86-64, by the most urgent software-generated interrupt on arm64 (which a
processor with interrupts fully masked does not take). A second processor
reaching a bugcheck halts silently, so one report is printed.

## Interrupts

Each controller comes up with everything masked that NK did not ask for:
the local APIC (x2APIC when available) with the 8259s and every I/O APIC
input masked; GICv3, where a processor finds its redistributor by
affinity, not position. The IRQL is the controller's priority mask;
levels and vectors are in `doc/LOCKING.md`. The only interrupts are the
clock and ones a processor sends itself or another: no device interrupts.

A processor fault is an exception for the faulting code's handlers
("Exceptions") or a bugcheck with a register dump.

## Time

One free-running counter is the source of all time: the TSC on x86-64,
its rate measured against the ACPI PM timer at boot; the generic timer's
counter on arm64, which states its rate. The clock interrupt fires 64
times a second (Windows' default) at IRQL 13, from the local APIC timer
or the generic timer's virtual timer. Each tick recomputes time from the
counter rather than counting ticks, so a late or lost tick costs nothing.

WDK-built code reads tick count, interrupt time and system time in line
from `KUSER_SHARED_DATA`; the tick keeps that page current. The wall
clock starts from firmware's time, read by the loader.

## Threads

A thread is an `ETHREAD`-sized block with Windows' layout for the fields
NK keeps, followed by NK's own state, and a kernel stack. Each processor
has a ready queue per priority (0 to 31) with a summary word, and an idle
thread. A thread has an affinity and an ideal processor, handed out in
turn. Made ready, it goes to its ideal processor if idle, else any idle
processor its affinity allows, else its ideal processor. A processor with
nothing to run takes the best thread it is allowed from another's queues,
and one that leaves a thread waiting wakes an idle processor to take it.

A processor leaves a thread when it yields, waits or exits; when a higher
priority becomes ready there; or when its quantum (two clock ticks, as on
Windows client) is spent and an equal is waiting. A preempted thread goes
to the front of its queue; one out of quantum, to the back. No priority
boosts. A thread may change its own priority (`KeSetPriorityThread`);
changing another's stops the system, because no lock covers a thread
wherever it is queued.

Preemption is requested, then done at the end of an interrupt: readying a
thread, or the tick, marks the processor, and the switch happens when an
interrupt handler is about to return below `DISPATCH_LEVEL`, after
end-of-interrupt. Marking one's own processor also raises the
DISPATCH-level interrupt, so that moment comes as soon as the IRQL
allows, however it was lowered. An interrupt that ends at
`DISPATCH_LEVEL` or above on a marked processor does the same, so the
switch is not left to whatever interrupt comes next.

The preempted thread resumes inside that interrupt's frame on its own
stack. The switch saves what a call preserves on the outgoing stack
(xmm6-15 and MXCSR, or d8-d15 and FPCR, included) and the stack pointer
in the thread's `KernelStack`. An exited thread is freed by the thread
that runs next. The SMP rules are in `doc/LOCKING.md`.

## The System process

There is one process, System, with Windows' id for it (4). Its block has
`EPROCESS`'s size and Windows' layout for the fields NK keeps; the rest
is zero. Every thread belongs to it, the idle threads included (Windows
gives those a process of their own), and carries a client id: the
process id and a thread id from the same sequence of multiples of four.
The kernel handle table is its handle table. `EPROCESS.Token` holds its
primary token the way Windows stores it, as a fast reference: a pointer
whose low four bits count references handed out in advance. NK hands out
none, so the bits are zero.

## Waits

A thread waits on an event, semaphore, timer, mutex or thread by linking
one of its four built-in wait blocks on the object's wait list and
sleeping until a waker claims it. A time limit sets the thread's own
timer and links a second block there with key `STATUS_TIMEOUT`: the
limit is one more object, and the first signalled ends the wait. A wait
may name up to 64 objects (the caller's wait blocks beyond three), for
any one (it reports which) or for all (it takes all or none).

Waits are not alertable. A wait that would block at `DISPATCH_LEVEL`
stops the system (`ATTEMPTED_SWITCH_FROM_DPC` from a DPC). Releasing a
semaphore past its limit, an exception on Windows, stops the system.

## Mutexes and critical regions

A mutex (`KMUTANT`) has an owner: recursive, released only by the owner,
free when released as often as taken. A waiter let in owns the mutex from
the moment the releasing thread claims it, before it has run. While a
thread holds a mutex or is in a critical region its `KernelApcDisable` is
negative, as on Windows; `KeAreApcsDisabled` reports it. A thread that
ends holding a mutex stops the system (`THREAD_TERMINATE_HELD_MUTEX`);
releasing one not owned, an exception on Windows, stops it too.

A fast mutex is a count and an event set up in line by the driver: 1
free, 0 held, one lower per waiter. Taking a free one is one atomic step;
a release that finds waiters passes it on through the event. Holding it
raises the IRQL to `APC_LEVEL`.

NK queues no APCs. The counts and the IRQL are kept as Windows keeps
them, so code that asks whether APCs are disabled gets Windows' answer.

## Deferred procedure calls

Each processor has a DPC queue. Queueing puts the DPC on the queueing
processor's queue and raises that processor's DISPATCH-level interrupt,
delivered when the IRQL falls below `DISPATCH_LEVEL` by whatever means:
WDK-built x86-64 code lowers the IRQL in line, so there is no call to
hook. The handler runs the queue in order.

DPC routines run on a stack of their processor's, as on Windows: an
ordinary kernel stack, allocated with the processor's state and kept.
The handler changes stacks around the queue run only. The interrupt
itself begins and ends on the interrupted thread's stack, because a
thread switch at its end leaves that thread there to be resumed. An
interrupt that arrives during a routine is handled on the DPC stack, and
an overflow of it is reported as a kernel stack overflow. No thread can
be left on that stack: a thread switch while a routine runs, possible
only if the routine lowered the IRQL, stops the system
(`ATTEMPTED_SWITCH_FROM_DPC`), and a DPC interrupt arriving inside such
a routine leaves the queue to the run in progress.

The driver owns the `KDPC`. As on Windows `DpcData` is non-null exactly
while queued; NK stores the queue's address there. A DPC running over 20
seconds stops the system (`DPC_WATCHDOG_VIOLATION`); the tick checks.
No targeting of another processor and no importance ordering.

## Timers

Each processor has a table of timers set on it and not yet due: 256
buckets, one per tick modulo 256, each ordered by due time
(`nk_ke::TimerBuckets`). The tick reads each bucket's earliest due time
without a lock and, when one has come, queues the processor's expiry
DPC, which takes the due timers out, signals them, re-inserts periodic
ones and queues their DPCs with the system time as arguments.

A timer never fires early, and fires at the first tick after its due
time; one already past fires inside `KeSetTimer`. The driver owns the
`KTIMER`; its layout and the header bits NK uses (`Inserted`, the lock
bit, `Expired`) are Windows'.

## Work items

Three queues (critical, delayed, hypercritical), each with worker threads
at that queue's priority, free to run on any processor. Windows 10's
other kinds map onto them: normal and background to delayed, real-time
to hypercritical, super-critical to critical. A work item is the
driver's memory, linked through its list entry, whose forward link is
null exactly while it is on no queue, as Windows keeps it. A worker
unlinks an item before running it, so a routine may requeue or free its
item. Queueing is allowed at `DISPATCH_LEVEL`; the routine runs at
`PASSIVE_LEVEL` and must return there with APCs enabled, or the system
stops (`WORKER_THREAD_RETURNED_AT_BAD_IRQL`).

An I/O work item is kernel-allocated at Windows' size and tied to a
device, referenced from queueing until the routine returns, or to a
driver object, which has no count to hold it by.

## Objects, references and handles

Object-manager allocations have Windows' `OBJECT_HEADER` in front:
pointer count, handle count, type. Events, threads, the System process,
tokens, drivers, devices, open files, open registry keys, directories
and symbolic links are such objects. An object is freed when its last
reference goes; its type may name a delete procedure that first releases
what it owns, and a close procedure that is told of every handle closed
and how many there were. A thread references itself until it has ended
and been reaped, so an unreferenced thread frees itself and a referenced
one stays a valid, signalled object.

Kernel handles are entries in one table, the System process's, with
Windows' kernel-handle bits; a handle holds a reference until closed. No
per-process tables. Each handle has the access it was granted and its
attributes (inherit, protect from close). A handle protected from close
stays open: user mode closing it is refused
(`STATUS_HANDLE_NOT_CLOSABLE`), kernel mode closing it stops the system
(`INVALID_KERNEL_HANDLE`), as on Windows. Nothing decides what a subject
may have: a handle is granted what its opener asked for, generic rights
turned into what they mean for the object's type. A use of a handle on
behalf of user mode is refused (`STATUS_ACCESS_DENIED`) access the handle
lacks; kernel mode is not held to it, as `ObReferenceObjectByHandle`
documents. A type's generic rights are Windows' for files and registry
keys; the other types have none recorded, and a generic right asked of
them grants nothing. `NtCurrentThread()` (-2) names the caller and
`NtCurrentProcess()` (-1) its process, with every access.

A type is an `OBJECT_TYPE` with Windows' layout, named by its address: a
driver imports a variable holding it (`ExEventObjectType`). Its index
numbers are NK's own. An object's header names its type as Windows 10
does, by the index combined with a cookie chosen at boot and a byte of
the header's address (`nk_ob::header`). The fields of a type NK does not
keep (its counts, its lists) are zero.

### The namespace

A tree of directories holding named objects and symbolic links
(`nk_ob::tree`, under one lock; `kernel/ob/mod.rs`). The root and the
directories every Windows system has (`\Device`, `\Driver`,
`\FileSystem`, `\GLOBAL??`, `\BaseNamedObjects`, `\KernelObjects`) are
directory objects made at boot; nothing else makes or removes one. `\??`
is `\GLOBAL??`, there being one session, and `\DosDevices` is a symbolic
link to `\??`. A named device is an entry in the directory its name puts
it in, a symbolic link is a symbolic-link object there, a loaded
driver's object is `\Driver\<service>`, and `\Registry` is the
registry's root key.

Names compare case-insensitively whatever the caller asks, which is
Windows' default configuration, by the same upper-case table as the
registry's. A look-up follows symbolic links, at
most eight, and stops at the first object on the path, handing back the
object, referenced, and the rest of the path. A directory missing on the
way is `STATUS_OBJECT_PATH_NOT_FOUND`; a missing last name is
`STATUS_OBJECT_NAME_NOT_FOUND`.

An entry does not keep its object alive (a symbolic link's excepted,
which nothing else holds): whoever names an object takes the name away
before giving up the reference the object was made with.

A named object carries Windows' `OBJECT_HEADER_NAME_INFO` in front of
its header, as the header's `InfoMask` says: its directory and its name
there, both emptied when the object loses its name. Name information,
header, body and the name's characters are one pool block. Directory and
symbolic-link bodies have Windows' sizes: a link's holds its target and
creation time; a directory's is zero, the entries being in NK's tree.

What is done with the rest of a path is the business of the type the
look-up ended at, after the namespace's lock is dropped: a device's
driver parses it as a file name (see "I/O"). The types' parse steps are
NK's own code, not `OBJECT_TYPE` procedures. No security checks.

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
- The prebuilt `core`, `alloc` and `compiler_builtins`: Rust ships them
  without tables. What NK instantiates from them (generic code) is
  compiled with NK and has entries; their own non-generic functions
  (formatting, `memcpy`, 128-bit division) do not.
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

## Exceptions

Structured exception handling as Windows defines it
([x64](https://learn.microsoft.com/en-us/cpp/build/exception-handling-x64),
[arm64](https://learn.microsoft.com/en-us/cpp/build/arm64-exception-handling),
[in drivers](https://learn.microsoft.com/en-us/windows-hardware/drivers/kernel/handling-exceptions)):
`kernel/ke/seh.rs`, over the frame-by-frame unwinder and the decisions
of `nk_unwind` (`scope`, `dispatch`), with a few assembly routines per
architecture (`kernel/arch/*/seh.rs`).

**Raising.** A routine that raises is entered through assembly that
records its caller's `CONTEXT` as it will be when the call has
returned. The exception is raised there: its address is the return
address in the driver, and no frame of NK's lies between the driver and
its exception. Such an exception cannot be continued.

**Processor faults.** The trap handler builds the faulting code's full
`CONTEXT` and raises the fault there, as an exception that may be
continued: a handler that changes the context and says "continue" has
the code go on with every register, the stack pointer and the program
counter as changed.

| Fault | Exception | Parameters |
| --- | --- | --- |
| memory fault on an address in the user half, below `DISPATCH_LEVEL` | `STATUS_ACCESS_VIOLATION` | 0 read, 1 write, 8 execute; the address |
| x86-64 general protection fault | `STATUS_ACCESS_VIOLATION` | 0; -1 |
| x86-64 divide error; arm64 `brk #0xF004`, which compiled code executes for a zero divisor | `STATUS_INTEGER_DIVIDE_BY_ZERO` | |
| x86-64 overflow trap | `STATUS_INTEGER_OVERFLOW` | |
| undefined instruction | `STATUS_ILLEGAL_INSTRUCTION` | |
| breakpoint (`int3`, `brk #0xF000`), no debugger | `STATUS_BREAKPOINT`, at the instruction | 0 |

Not exceptions, whatever `__try` surrounds them, as on Windows: a
memory fault on a kernel address (`0x50 PAGE_FAULT_IN_NONPAGED_AREA`),
one at `DISPATCH_LEVEL` or above (`0xA IRQL_NOT_LESS_OR_EQUAL`, `0xD1`
in a driver), a fast-fail, a stack overflow. The decision is
`nk_unwind::dispatch::memory_fault`.

A call through a pointer that leads nowhere faults at its target, in no
image: that frame is undone as a leaf's, and the search goes on in the
caller.

NK's own accesses to memory that may not be there (a requestor's
buffer) are all one assembly routine, `mm::user::copy`. A fault in its
access is not an exception: the trap handler resumes the routine at its
way out, and it returns the address and the kind of access as an error.
Nothing is unwound.

**Probes.** `ProbeForRead`, `ProbeForWrite` and `MmProbeAndLockPages`
raise in their caller. A probe looks at alignment first
(`STATUS_DATATYPE_MISALIGNMENT`) and at nothing for a range of no
bytes. A range outside user space is refused as Windows 10 refuses it:
by a read probe with the access violation of a memory fault (two
parameters), by a write probe with the one `ExRaiseAccessViolation`
raises (none). A write probe then reads and writes back a byte of each
page, through the copy above; a read probe touches nothing.
`MmProbeAndLockPages` raises `STATUS_ACCESS_VIOLATION` for a page that
is not mapped, and for user mode a page outside the user range.

**Finding a handler.** The dispatcher walks the stack from that context
and calls the language handler of each function that names one,
innermost first, with the `EXCEPTION_RECORD`, the `CONTEXT` and a
`DISPATCHER_CONTEXT` filled in as Windows fills it: a driver's own
handler (the stack-cookie check) reads the function entry, the image
base and the handler data from it. `__C_specific_handler` asks the
filters of the scopes around the frame's program counter. An exception
raised inside a handler is searched for in turn; handlers between it
and the frame the first search had reached are told so
(`EXCEPTION_NESTED_CALL`).

**Unwinding.** A filter that accepts unwinds: the same frames are
walked again and their handlers called a second time, which runs the
`__finally` blocks, innermost first; then the accepting function goes
on at its `__except` block with the registers a call preserves as it
had them and the exception's code where a call's result would be.
`_local_unwind` is the same walk without an exception. An unwind that
begins inside a `__finally` block run by another takes that one over
where it stood (a collided unwind), so no block runs twice.

**NK's own frames.** They are walked like a driver's, by their unwind
tables, and an unwind discards them: no destructor runs. Three rules
make that safe.

- Every call into a driver is `ke::seh::call`: an assembly frame with a
  language handler of NK's own, holding a guard record the caller
  passes. Nothing else lies between NK's Rust and the driver's routine,
  so no frame without an unwind entry can. A routine of more than four
  arguments is called by a function of NK's own that is itself called
  this way: one Rust frame more, which has an unwind entry and holds
  nothing.
- A guard says what the caller owes if the routine does not return.
  `Undo`: a function to call, once, when an unwind passes the frame
  (leave a critical region, lower the IRQL, drop a reference).
  `Nothing`: nothing is owed. `Base`: no driver's frame can lie beneath
  this call, so no handler can; an exception that reaches it is
  unhandled, the system stops there, and nothing is ever unwound
  through it.
- Between a call into a driver and the driver's frame beneath (if any),
  an NK frame keeps nothing that only a destructor would give back: no
  lock guard, and no IRQL, critical region or reference that is not in
  a guard. What belongs to the request being abandoned (its IRP, the
  block its results go to, its hold on the file object) is left as it
  is, on purpose: the driver that raised may still hold the IRP.
  Windows has no handlers on these paths either.

| Call into a driver | Guard |
| --- | --- |
| dispatch routine, for a request NK sends | undo: leave the critical region the request is sent in |
| dispatch routine, for a request a driver sends (`IoCallDriver`) | nothing |
| completion routine, cancel routine, a cancel-safe queue's callbacks | nothing: the cancel lock and its IRQL are the routine's to release, the queue's lock the driver's own |
| I/O work item's routine | undo: the device's reference |
| work item's routine (from the worker), a system thread's start routine, `DriverEntry`, the unload routine, a library's `DllInitialize` and `DllUnload` | base: a system thread |
| DPC routine, a timer's included | base: kernel mode |
| a query table's routine (`RtlQueryRegistryValues`) | undo: what the query holds, in one block: its copy of the table, the value lent to the routine, its count on the key |
| a system service made for user mode (the oracle's requests) | base: a system service |

**Nothing handles it.** The system stops with Windows' bugcheck for
where the exception was raised:

| Where | Bugcheck | First parameter |
| --- | --- | --- |
| a system service made for user mode | `0x3B SYSTEM_SERVICE_EXCEPTION` | the exception's code |
| a system thread: a worker, a driver's thread, `DriverEntry` | `0x7E SYSTEM_THREAD_EXCEPTION_NOT_HANDLED` | the code, sign-extended |
| a DPC routine; a stack that cannot be searched | `0x1E KMODE_EXCEPTION_NOT_HANDLED` | the code, sign-extended |

The search does not go on from a DPC routine into whatever the DPC
interrupted. It stops, naming the place, at a function that is waiting
for a call to return and has no unwind entry, and at a frame that is
not on the stack: never a guess.

The tests `seh.*` stack assembly routines shaped like a driver's
compiled C (`kernel/arch/*/seh_test.rs`) around NK frames of each kind
and around instructions that fault, and check what ran, in which order,
with what record, and what state came back. `oracle.nkc-seh` holds NK
to what a conformance driver's own `__try` blocks saw on Windows
(nested and collided unwinds, `__leave`, `goto` and `return` out of a
`__try`, the raising routines, the probes, faults), and the
`*-oracle-nkc-seh-fatal-*` scenarios to the bugcheck Windows stopped
with in each place an exception went unhandled. `oracle.nkc-cross` has
one driver send requests of its own to another: an exception raised in
the far driver's dispatch routine, or in the sender's completion
routine under the far driver's `IoCompleteRequest`, passes NK's frames
to the sender's handlers as it passes Windows'.

## Exports

Drivers import from `ntoskrnl.exe` and `HAL.dll` by name; both names
resolve against one static table (`kernel/export/mod.rs`). Each entry is
the name, the address and a state: `Implemented`, `Partial` (gaps
documented at the function) or `Traps` (bound so the driver loads;
bugchecks by name if called). The same table feeds the import binder and,
through the boot log, the ledger, so the ledger cannot drift from what
the kernel exports. An import with no entry rejects the driver and names
the symbol.

A driver can also ask for a routine by name while it runs
(`MmGetSystemRoutineAddress`) and do without it when the answer is
null. No import table shows such a name, so each one not found is
printed in the boot log and the ledger lists them (`looked_up_absent`).

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
- **Lifetime.** Each loaded importer counts once, in the library's
  record in the table of images. When the last goes, the library's
  `DllUnload` is called and the library unloaded, after its importer;
  the next importer loads it afresh. As Microsoft documents, a library
  without `DllUnload`, or whose `DllUnload` fails, stays loaded.
- **A refused importer leaves nothing.** Its libraries lose it as an
  importer again, and one loaded for it alone is unloaded.

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

- imports by ordinal from the kernel itself: NK's table has no
  ordinals;
- kernel-mode API-set names (`ext-ms-*`);
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

## Loading a driver

`kernel/ldr` checks the image is a native PE32+ for this machine, lays it
out in fresh frames, relocates it to a fresh address, binds every import,
and only then maps it with each section's protection. Also:

- **Stack cookie.** MSVC-built drivers check at entry that the loader
  replaced the default `__security_cookie`, and `__fastfail` if not. The
  loader finds it through the load configuration directory and writes a
  per-image value (non-zero, not the default, top 16 bits clear as the
  x86-64 check requires). Its entropy is only the cycle counter.
- **Instruction cache.** On arm64 the image is written through one
  address and run from another, so the loader synchronises the caches.

A refused image leaves nothing allocated.

Every image in memory, the kernel's own first (as `ntoskrnl.exe`), is in
one fixed-size table by file name, address range, function table, view
and export directory (`nk_pe::modules`): a fatal trap names the image
and offset it happened at, a stack walk finds each frame's function
there, and an import from a library is bound through it. An image of a
file name that is loaded is not loaded again.

One image is loaded or unloaded at a time, under a mutex
(`doc/LOCKING.md`): loading calls a library's `DllInitialize`, which may
wait, and loads a library from inside the load of its importer.

## Starting a driver

A driver is started from its service key, as on Windows
(`kernel/io/service.rs`): `...\Services\<name>\ImagePath` names the
image, and a key without that value means `System32\drivers\<name>.sys`.
The last part of the path is looked up among the boot files, the
contents of `\NK\drivers`, which stand for `System32\drivers` until
there is a file system. Nothing else starts a driver; a library is
loaded when an image imports from it (Exports). The driver's entry
point is given the path to its key. Stopping a service runs the driver's
unload routine and frees its image; the key stays.

**At boot**, before anything else is done with drivers, the system
thread starts those whose keys say `Start` 0 (boot) or 1 (system), in
Windows' order (`nk_cm::services`): boot start before system start; in
each, by the place of the service's `Group` in
`Control\ServiceGroupOrder`, then by the place of its `Tag` in the
group's list under `Control\GroupOrderList`; services of no listed
group last; a service after those it names in `DependOnService` and
`DependOnGroup`. Only keys whose `Type` is a driver's count. Windows'
loader reads boot-start drivers into memory before the kernel runs and
the I/O manager starts system-start ones later; on NK both are boot
files and the order is all that tells them apart.

- A service whose image is not among the boot files is passed over,
  with a line in the log: a test image holds only the drivers it was
  given.
- Any other failure is logged, and stops the boot if the key's
  `ErrorControl` is 3 (critical). Windows restarts with the
  last-known-good control set first; NK has the one.

Other services start when something asks: the tests make a key the way
`sc create` does and start it, or start one the hive describes.

## I/O

Driver, device and file objects are object-manager objects of exactly
their Windows size, and IRPs pool allocations of theirs; all are reached
by raw pointer. An IRP's allocation ends, past its stack locations, with
one word of NK's: the room in the requestor's buffer. A device object is
followed by the driver's extension, then a private NK block. A device's
own `ReferenceCount` decides when a deleted device stops being one, the
object's pointer count when its memory goes.

`kernel/io/file.rs` plays the I/O system services, by handle: `open`
(`NtCreateFile`, `NtCreateNamedPipeFile`), `read`, `write`,
`device_control`, `fs_control`, `close` (`NtClose`). Each builds a real
IRP and calls the dispatch routine inside a critical region (as Windows
does for a synchronous request).

**The requestor.** A request is made on behalf of kernel mode, whose
buffers are trusted, or of user mode (`user_control`,
`user_transfer`), whose buffers are an address and a length taken at
their word no further than Windows takes them. For the buffered and
direct methods the I/O manager probes them, copies the input through
`mm::user::copy` and locks a direct buffer's pages; a buffer it cannot
use fails the request with `STATUS_ACCESS_VIOLATION` before any driver
sees it. A null buffer that it would copy is no buffer, and its length
goes to the driver as zero; a direct method's second buffer keeps its
length, and null fails the probe. For `METHOD_NEITHER` the driver is handed both addresses as they
are, and what is there is the driver's to find out. The oracle's
requests are user mode's, their buffers pages of the user range. Completion follows the Windows
sequence: unwind the stack locations running completion routines, then
copy results to the requestor and signal its event. A buffered request's
results are copied only as far as the requestor asked; a driver that
reports more stops the system. A driver that returns other than
`STATUS_PENDING` without completing, or a status different from the one
it completed with, fails the request's test. A request made through a
handle holds the file object until it has been waited for.

**Open.** The name is looked up in the namespace, from the root or from
a directory a root handle names. The look-up ends at a device, and what
is left of the path is the device's to parse (Windows' `IopParseDevice`):
it becomes the new file object's `FileName`, backslash first, in a pool
block of the I/O manager's. A name relative to an open file goes to that
file's device as given, with the file as `RelatedFileObject`: referenced
until the create request has completed, which is as long as Microsoft
documents the field to be valid, and cleared then. Anything
but a device at the end of the look-up is `STATUS_OBJECT_TYPE_MISMATCH`.

Finding a device and counting the open are two steps, and the device may
be deleted between them. The look-up takes a pointer reference while the
name still leads to the device; the open is then counted under the I/O
database lock, or refused if the device is deleted.

The create request (`IRP_MJ_CREATE`, or `IRP_MJ_CREATE_NAMED_PIPE` with
the pipe's `NAMED_PIPE_CREATE_PARAMETERS`) carries what Windows' does:
`Parameters.Create` with the disposition and create options, the share
access, no attributes and no extended attributes; an
`IO_SECURITY_CONTEXT` with the desired access and an `ACCESS_STATE` for
the System process, generic rights mapped to the file rights in both;
the requestor's mode in the IRP. What the driver leaves in
`IoStatus.Information` is the open's result. A create the driver fails
leaves a file object with no device, about which the driver hears no
more.

**Cleanup and close.** A file object is an object of the file type, and
the open returns a handle to it. The type's close procedure sends
`IRP_MJ_CLEANUP` when the last handle in the system closes; its delete
procedure sends `IRP_MJ_CLOSE` when the last reference goes, then drops
the file's count on the device and frees the name. A driver is called
at `PASSIVE_LEVEL`: a file whose last reference goes above it is put on
a list through its header (`NextToFree`) and deleted by a worker
thread, as on Windows. Other types' objects are deleted where their last
reference goes.

**Pending.** A driver may return `STATUS_PENDING` and complete later from
a DPC, timer or worker; the requestor waits on an event completion sets.
The requestor owns the IRP and frees it after seeing completion, so
cancelling is safe until then. Windows finishes a request in the
requesting thread by APC; NK finishes it wherever it was completed, at
`DISPATCH_LEVEL` or below. There is one address space, so a user-mode
requestor's buffer is there to copy to from any thread; the copy is the
one that may fail, and a buffer gone by then fails the request with the
access violation.

**Cancel.** `IoCancelIrp` marks the IRP, takes its cancel routine in one
atomic step, and calls it holding the cancel spin lock, which the routine
releases. A completing driver takes the routine the same way, so exactly
one of the two completes it. "Install the routine, then read the cancel
flag" races "set the flag, then take the routine"; both sides use
sequentially consistent operations, since with less each can miss the
other's write and a cancelled request is never completed. Cancelling a
completed IRP whose routine is still set stops the system
(`CANCEL_STATE_IN_COMPLETED_IRP`).

**Cancel-safe queues** (`IoCsq*`, `kernel/io/csq.rs`). While a request is
queued its fourth driver-context pointer names the queue (or the
caller's context block) and its cancel routine is the I/O manager's,
which unlinks it under the queue's lock and has the driver complete it.
Removal skips a request whose cancel routine is already gone: the
canceller has it.

**Direct I/O** uses real MDLs: the buffer, the kernel's or one in the
user range, is described by its physical pages, and a system address is
a fresh mapping of them, so the driver works through its own view.
Limits are at the top of `kernel/io/mdl.rs`.

## The registry

One tree of keys and values in memory (`lib/cm`; exports in `kernel/cm`).
It is built at boot:

1. the keys every system has: `\Registry\Machine\System` with
   `Select`, `\Registry\Machine\Hardware`, `\Registry\User`;
2. the SYSTEM hive the loader read (`doc/BOOT.md`), if it read one,
   copied over `\Registry\Machine\System`: keys, values, classes,
   security descriptors, times. A hive that is damaged, or that needs
   its transaction log, fails the boot: nothing replays a log;
3. the control set `Select\Current` names (`ControlSet001`), with
   `Control\Class` and `Services` made if the hive did not bring them,
   and `CurrentControlSet`, a symbolic link to it.

Without a hive the registry is 1 and 3 alone. It holds what drivers
write until power-off; nothing is written back to a file.

A symbolic link is what it is on Windows: a key flagged as one, whose
`SymbolicLinkValue` (`REG_LINK`) is the full path of another key. A
look-up that reaches a link goes on from that key, so a key made under
`CurrentControlSet` is made in the control set. A link whose target is
missing leads nowhere (`STATUS_OBJECT_NAME_NOT_FOUND`). Only the kernel
makes links; no export opens the link itself.

Names compare without regard to case, upper case against upper case by
a full table (`nk_rtl::upcase_char`, built from the Unicode character
database: Windows' own table may differ for a few characters, listed
there). A key handle is a handle to a small object naming
the key. The root key is such an object too, called `\Registry` in the
object namespace: an absolute name, or one relative to a directory, is
looked up there, through symbolic links like any other, and must end at
that key, which walks the rest of the path in the registry's own tree. A
name relative to an open key starts at that key. A key is no file:
opening one through the I/O manager is `STATUS_OBJECT_TYPE_MISMATCH`.

Subkeys are enumerated in the order of their upper-cased names, values
in the order they were first set, as on Windows
([`ZwEnumerateKey`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-zwenumeratekey),
[`ZwEnumerateValueKey`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-zwenumeratevaluekey)).
A key or value is described in Microsoft's information structures
(`lib/cm` writes them; the classes are those of
[`KEY_INFORMATION_CLASS`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/ne-wdm-_key_information_class)
and
[`KEY_VALUE_INFORMATION_CLASS`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/ne-wdm-_key_value_information_class)).
A buffer with room for a structure's fixed part and not all of the rest
gets what fits and `STATUS_BUFFER_OVERFLOW`; one with less gets nothing
and `STATUS_BUFFER_TOO_SMALL`; both are told the length that holds
everything. Where a class or a value's data is aligned after a name,
the bytes between are the caller's, untouched. A value's data start at
a multiple of eight bytes in the full form, aligned or not, as Windows
10 x64 places them.

An open key describes itself
([`ZwQueryKey`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-zwquerykey))
in every form. Its full name starts at `\REGISTRY`, each part in the
letter case it was created in (`MACHINE`, `SYSTEM`, `HARDWARE` and
`USER` are Windows' spellings), with symbolic links followed: a key
opened through `CurrentControlSet` names its control set. What NK has
none of is reported as Windows reports a key without it: no flags, no
virtualization, no handle tags, no layer. Every key is trusted
(`KeyTrustInformation`), because the registry holds only the system's
own hive.

A key remembers the longest subkey name, subkey class, value name and
value data it has held, which is what it reports as the longest it
holds: as on Windows, the numbers only grow while the key has subkeys
(or values) and start again when the last one goes. A key copied from a
hive file starts from the numbers the file gives it.

Creating makes only the last key of a path, as on Windows, and gives a
new key its class. A value is read by name in the forms it is
enumerated in; there are no layered keys, so the form that describes a
value of one (`KeyValueLayerInformation`) is refused like a form that
does not exist, `STATUS_INVALID_PARAMETER`. A deleted value leaves its
place in the order to the next; set again, it is the key's last. A key
without subkeys can be
deleted: gone by name at once, open handles good only for closing. No
access checks or notification. Leak checks leave out the
registry's memory, as they do the handle table's.

### Query tables

[`RtlQueryRegistryValues`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-rtlqueryregistryvalues)
and `RtlQueryRegistryValuesEx` read values as a table of entries asks:
each value goes to the entry's routine or is stored where the entry
points. What an entry's flags mean is Microsoft's to say, and
`nk_cm::query` works it out without touching a driver's memory; the
kernel (`kernel/cm/table.rs`) copies the table, reads the registry, and
does what the query says. NK's decisions:

- **The table is copied first**: every entry up to the one that ends
  it, names and default data too (a string default of length zero is
  measured), and the environment block. A routine that rewrites the
  table changes nothing for the call in progress.
- **The key is found once** and counted as open for the length of the
  call. Each entry reads the registry afresh, holding the lock for the
  read alone, so a routine may open, change or delete any key, this one
  included. The query sees what the routine left: a key it deleted ends
  the query with `STATUS_KEY_DELETED`.
- **A routine is lent copies** of the value's name and data in a pool
  block, never the registry's own memory. The data are followed by a
  terminator, whether or not the value was stored with one. The call
  that carries no value (`RTL_QUERY_REGISTRY_NOVALUE`) passes null for
  both.
- **A stored string** is the value without the terminator it ends
  with, and a terminator after it: a counted string without a buffer is
  given one from the pool, which the caller frees; one with a buffer
  must have room for the terminator (`STATUS_BUFFER_TOO_SMALL`).
- **`RelativeTo`**: `RTL_REGISTRY_OPTIONAL` changes nothing, a key that
  is not there fails the call. `RTL_REGISTRY_USER` is
  `\Registry\User\.Default`: the system is the only user.
- **The type check** (`RTL_QUERY_REGISTRY_TYPECHECK`) is made where an
  entry asks for it and demanded of none. Windows demands it of a key
  in a hive it does not trust, and that is all that tells its two
  exports apart; NK has no such hive, and the two are one routine.
- **A routine that raises** an exception is unwound through the query
  like any call into a driver (Exceptions). All the query holds is one
  pool block, which the guard of that call gives back.

## Security descriptors

SIDs, ACLs and descriptors are byte layouts with rules: `lib/se`, with
the exports in `kernel/se`. A driver's descriptor is the driver's memory:
read and written through raw pointers, the rules run on copies.
`SeExports` points to the well-known SIDs and privilege numbers, laid out
as in `ntifs.h`.

Nothing is enforced: there is no user mode to check. Descriptors are
built, converted, captured and stored faithfully. `ZwSetSecurityObject`
replaces the named parts of a device's descriptor; for other objects it
answers `STATUS_NOT_SUPPORTED`. A new device has no descriptor until one
is set, where Windows gives a default. `SeCaptureSecurityDescriptor`,
forced, returns a self-relative pool copy, the caller's to free.

Where a descriptor lives:

- A device's is in `DEVICE_OBJECT.SecurityDescriptor`, a documented
  field a driver can read, as on Windows: a pool block the device owns,
  replaced under the I/O database lock.
- Any other object can carry one in `OBJECT_HEADER.SecurityDescriptor`
  (`kernel/ob/security.rs`): a counted pool block of its own, set,
  referenced and released by kernel routines, freed with the object or
  when replaced and no reader holds it. Windows shares one block among
  objects with equal descriptors; NK does not. The field is Windows' fast
  reference with its count bits zero. Nothing gives an object a
  descriptor yet: that comes with the types' security procedures.

## Tokens and access state

A token is an object whose body is NK's own (`nk_se::token::Token`):
drivers treat `TOKEN` as opaque and ask through routines. There is one,
the System process's, with the user, groups and privileges of Windows'
SYSTEM token (the table at `Token::system` says which of those facts
Microsoft documents). No thread impersonates.

What an open carries about its requestor has Windows' layout, because a
file system reads it in line (`kernel/se/token.rs`):

- the subject context: no client token, the primary token (referenced
  until the context is released), the process id for auditing;
- the access state: the subject, an operation id of its own, the access
  asked for as both original and remaining, generic rights as given (the
  type being opened maps them), nothing granted yet, and the traverse
  flag when the token holds `SeChangeNotifyPrivilege` enabled. Its
  security descriptor, auxiliary data, privileges and names are empty.

## Breakpoints and the debugger

A driver's breakpoint (`DbgBreakPoint`, in-line code) gets one of
Windows' two answers. By default, as with no debugger: an exception,
`0x80000003`, which stops the system unless a handler takes it (bugcheck
`0x7E` in a system thread). With `debug=on` on the command line, as with
a debugger that says "go" every time: noted on the console and passed
over, before any handler is asked. NK has no debugger protocol; the reference
Windows machine gets a real debugger, played by `tools/kd.py`.

## What is absent

No APCs, device interrupts, PnP, power management, user processes or
user mode. Where a fixture imports something in that territory but never
reaches it on the tested path, the export is `Traps`.
