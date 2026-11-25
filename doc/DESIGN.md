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
| `lib/` | pure, host-tested crates: PE and PDB readers, function tables and unwinding (`unwind`), page tables and allocators (`mm`), scheduler, wait and timer logic (`ke`), interrupt-controller encodings and MADT reading (`hal`), namespace and handle slots (`ob`), structure layouts (`ntabi`), registry, security descriptors |
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
2. `BootInfo` checked; `arch::mm_init`, `mm::init`: frames, pool, mappings.
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
| low half | firmware runtime regions, identity-mapped, so UEFI runtime services stay callable (`doc/BOOT.md`). No user space |
| `0xFFFF_8000_0000_0000` + phys | direct map of physical memory: 2 MiB blocks, not executable; ranges without RAM as device memory |
| `0xFFFF_F780_0000_0000` | `KUSER_SHARED_DATA`, one page, Windows' address |
| `0xFFFF_F800_0000_0000` | the kernel image: 4 KiB pages, each section's own protection |
| `0xFFFF_F880_0000_0000` to `0xFFFF_F900_0000_0000` | dynamic mappings: driver images, kernel stacks, MDL views |

## Memory

- **Frames.** A bitmap allocator over `EfiConventionalMemory` only,
  never below 1 MiB. Loader allocations and firmware boot-services memory
  stay reserved (on arm64 the latter holds firmware's live page tables).
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
processor's translation settings.

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

Any exception other than a breakpoint is a bugcheck with a register dump.

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

The driver owns the `KDPC`. As on Windows `DpcData` is non-null exactly
while queued; NK stores the queue's address there. A DPC running over 20
seconds stops the system (`DPC_WATCHDOG_VIOLATION`); the tick checks.
DPCs run on the interrupted stack. No targeting of another processor and
no importance ordering.

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
attributes (inherit, protect from close). Nothing decides what a subject
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
Windows' default configuration. A look-up follows symbolic links, at
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

The kernel image itself has no unwind tables (no `.pdata`): SEH through
NK's own frames needs them built in.

## Exports

Drivers import from `ntoskrnl.exe` and `HAL.dll` by name; both names
resolve against one static table (`kernel/export/mod.rs`). Each entry is
the name, the address and a state: `Implemented`, `Partial` (gaps
documented at the function) or `Traps` (bound so the driver loads;
bugchecks by name if called). The same table feeds the import binder and,
through the boot log, the ledger, so the ledger cannot drift from what
the kernel exports. An import with no entry rejects the driver and names
the symbol.

Not handled: imports by ordinal, kernel-mode API-set names (`ext-ms-*`),
drivers that export to other drivers.

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
one fixed-size table by file name, address range and function table
(`nk_pe::modules`): a fatal trap names the image and offset it happened
at.

## Starting a driver

A driver is started from its service key, as on Windows
(`kernel/io/service.rs`): `...\Services\<name>\ImagePath` names the
image, and the last part of that path is looked up among the boot files,
the contents of `\NK\drivers`, which stand for `System32\drivers` until
there is a file system. Nothing else loads a driver. The tests make a
key the way `sc create` does and then start the service; the driver's
entry point is given the path to that key. Stopping a service runs the
driver's unload routine and frees its image; the key stays.

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
does for a synchronous request). Completion follows the Windows
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
the file's count on the device and frees the name. The last reference
to an open file must go at `PASSIVE_LEVEL` (Windows defers such a
delete to a worker thread; NK stops the system).

**Pending.** A driver may return `STATUS_PENDING` and complete later from
a DPC, timer or worker; the requestor waits on an event completion sets.
The requestor owns the IRP and frees it after seeing completion, so
cancelling is safe until then. Windows finishes a request in the
requesting thread by APC; NK finishes it wherever it was completed, at
`DISPATCH_LEVEL` or below, indistinguishable while there is no user
memory to copy to.

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

**Direct I/O** uses real MDLs: the buffer is described by its physical
pages, and a system address is a fresh mapping of them, so the driver
works through its own view. Only kernel buffers can be described; other
limits are at the top of `kernel/io/mdl.rs`.

## The registry

One tree of keys and values in memory (`lib/cm`; exports in `kernel/cm`).
Nothing is loaded from or saved to a hive: it starts with
`\Registry\Machine\System\CurrentControlSet` (`Control\Class`,
`Services`) and holds what drivers write until power-off. Names compare
case-insensitively. A key handle is a handle to a small object naming
the key. The root key is such an object too, called `\Registry` in the
object namespace: an absolute name, or one relative to a directory, is
looked up there, through symbolic links like any other, and must end at
that key, which walks the rest of the path in the registry's own tree. A
name relative to an open key starts at that key. A key is no file:
opening one through the I/O manager is `STATUS_OBJECT_TYPE_MISMATCH`.

Creating makes only the last key of a path, as on Windows. Values are
read as `KeyValuePartialInformation` or `KeyValueFullInformation`; other
forms answer `STATUS_NOT_IMPLEMENTED`. A key without subkeys can be
deleted: gone by name at once, open handles good only for closing. No
access checks, registry symbolic links or notification. Leak checks leave out the
registry's memory, as they do the handle table's.

## Security descriptors

SIDs, ACLs and descriptors are byte layouts with rules: `lib/se`, with
the exports in `kernel/se`. A driver's descriptor is the driver's memory:
read and written through raw pointers, the rules run on copies.
`SeExports` points to the well-known SIDs and privilege numbers, laid out
as in `ntifs.h`.

Nothing is enforced: there is no user mode to check. Descriptors are
built, converted, captured and stored faithfully. `ZwSetSecurityObject`
replaces the named parts of a device's descriptor
(`DEVICE_OBJECT.SecurityDescriptor`); other objects have none and answer
`STATUS_NOT_SUPPORTED`. A new device has no descriptor until one is set,
where Windows gives a default. `SeCaptureSecurityDescriptor`, forced,
returns a self-relative pool copy, the caller's to free.

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
Windows' two answers. By default, as with no debugger: an unhandled
exception, bugcheck `0x7E` with `0x80000003`. With `debug=on` on the
command line, as with a debugger that says "go" every time: noted on the
console and passed over. NK has no debugger protocol; the reference
Windows machine gets a real debugger, played by `tools/kd.py`.

## What is absent

No SEH, APCs, device interrupts, PnP, power management, user processes
or user mode. Where a fixture imports something in that territory but never
reaches it on the tested path, the export is `Traps`.

SEH is the sharpest edge (`kernel/ke/seh.rs`). `ProbeForRead` performs
Windows' checks, but where Windows raises NK bugchecks, as does
`MmProbeAndLockPages` on an inaccessible buffer. A driver's `__try`
protects nothing.
