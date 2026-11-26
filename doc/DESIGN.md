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
| `kernel/<part>/` | one directory per NT part: `ke`, `ex`, `mm`, `ob`, `io`, `ps`, `se`, `cm`, `rtl`, `etw`, plus `hal`, `ldr` (image loading, boot files), `kd` (console, bugcheck) |
| `kernel/export/` | the export table, and the traps |
| `kernel/rt.rs` | Rust's allocator on the kernel pool |
| `kernel/test.rs`, `kernel/selftest/` | the boot-test runner and the test groups |
| `lib/` | pure, host-tested crates, each named for the kernel part whose rules it holds (`ke`, `ex`, `mm`, `ob`, `ps`, `se`, `cm`, `rtl`, `etw`, `hal`), and: `pe` and `pdb` (image and symbol-file readers), `unwind` (function tables, unwinding, exception decisions), `ntabi` (structure layouts), `acpi` (firmware tables), `bootinfo` (the loader's hand-off block), `oracle` (the script and transcript format), `selftest` (the test runner's bookkeeping). A crate's top comment says what it holds |
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
   its caller, prints the export table, starts the services the hive
   starts at boot, and runs the test groups, which load drivers and send
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
  answer. A request's priority (`ExAllocatePoolWithTagPriority`) is not
  used: NK refuses only when it has no memory, which every priority
  allows. A refusal is null, or the exception
  `STATUS_INSUFFICIENT_RESOURCES` raised in the caller where Microsoft
  documents one: a quota allocation without
  `POOL_QUOTA_FAIL_INSTEAD_OF_RAISE`, any allocation with
  `POOL_RAISE_IF_ALLOCATION_FAILURE`.
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
boosts.

A thread's priority may be set by any thread (`KeSetPriorityThread`),
wherever the thread is. If it is on a ready queue it moves to the back
of the queue of its new priority and that processor looks again; if it
is waiting it wakes with the new priority; if it is running and was
lowered, its processor looks for a better thread. Its base priority
stays. As on Windows, a thread with a base priority asked for 0 gets 1,
and one whose base is real-time (16 and up) is not taken below 16
(`nk_ke::sched::priority_to_set`).

A thread's base priority is its process's (8 for the System process,
`KPROCESS.BasePriority`) plus a step, set through
`ZwSetInformationThread` (`ThreadBasePriority`): -2 to 2, or 16 and
-16, which pin the thread at 15 and at 1 (`KTHREAD.Saturation`). The
priority moves by as much as the base moved, so a priority that was
set apart from the base keeps its distance
(`nk_ps::info::set_base_priority`, from what Windows 10 computes).
`ThreadPriority` sets the priority alone, 1 to 31. Each class makes
its checks in Windows' order; a class Windows never sets is
`STATUS_INVALID_INFO_CLASS`, and one it sets and NK does not is
`STATUS_NOT_IMPLEMENTED`.

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
in the thread's `KernelStack`. An exited thread is buried by the thread
that runs next: its stack is freed, the reference it held on itself is
dropped, and it is signalled. Its end cannot be seen before the burial:
a wait for a thread returns, and a look at one finds it signalled, only
once the thread is no longer counted and holds nothing, so its memory
goes with the last reference of whoever watched. The SMP rules are in
`doc/LOCKING.md`.

`PsCreateSystemThread` makes the thread, opens the creator's handle and
writes it out, and only then makes the thread ready, as Windows does.
A thread that cannot be given its handle is taken back unstarted, so
the routine reports failure only for a thread that never ran.

## The System process

There is one process, System, with Windows' id for it (4). Its block has
`EPROCESS`'s size and Windows' layout for the fields NK keeps; the rest
is zero. Every thread belongs to it, the idle threads included (Windows
gives those a process of their own), and carries a client id: the
process id and a thread id from the same sequence of multiples of four.
The id routines read those fields (`PsGetCurrentProcessId`,
`PsGetThreadProcessId`, ...). There are no sessions: the process's
`Session` is null, which Windows reads as session 0, and so do
`PsGetProcessSessionId` and `PsGetThreadSessionId`.

The System process is charged no quota, as on Windows, where the quota
routines know it by `PsInitialSystemProcess` and answer success
without a look at a quota block: `PsChargeProcessPagedPoolQuota`
succeeds for any amount and `PsReturnProcessPagedPoolQuota` does
nothing. Its `QuotaBlock` is null.

A thread attaching to a process (`KeStackAttachProcess`) can only name
the one it is in. Windows saves nothing then and marks the caller's
`KAPC_STATE` with a 1 where the process would be; NK does exactly that,
and `KeUnstackDetachProcess` accepts exactly that mark. Any other
process pointer names no process, and a detach with any other state
was preceded by no attach: both stop the system, the second with
Windows' `INVALID_PROCESS_DETACH_ATTEMPT`, as does an attach from a DPC
routine (`INVALID_PROCESS_ATTACH_ATTEMPT`).
The kernel handle table is its handle table. `EPROCESS.Token` holds its
primary token the way Windows stores it, as a fast reference: a pointer
whose low four bits count references handed out in advance. NK hands out
none, so the bits are zero: `PsReferencePrimaryToken` takes each
reference on the token itself. `PsInitialSystemProcess` holds the
process, and the current process (`PsGetCurrentProcess`,
`IoGetCurrentProcess`) is the one the calling thread says it is attached
to, `KTHREAD.ApcState.Process`.

### Silos

A silo is a job that isolates what runs in it
([silo DDIs](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntddk/)).
NK has no jobs, so there is one silo, the host, which Windows too names
by a null pointer. For that silo the routines do what they do on
Windows (`kernel/ps/silo.rs`):

- A thread is attached to a silo through `ETHREAD.Silo`, which starts
  out as Windows' mark for "none; use the process's" (-3).
  `PsAttachSiloToCurrentThread` returns what was there for the detach
  to put back. The current silo is the attached one, else that of the
  process's job: the host, the System process having no job.
- A silo context is an object of one of two types, as on Windows
  (`PsSiloContextPaged`, `PsSiloContextNonPaged`), with the driver's
  bytes as its body. Its cleanup routine is called when its last
  reference goes. NK's record of the silo and the routine sits in front
  of the object's headers, where no binary looks.
- Slots are numbers, the lowest free one first, 288 of them as on
  Windows (`nk_ps::silo`). The host silo keeps one context per slot,
  put there to stay (`PsInsertPermanentSiloContext`), and holds a
  reference to it; `PsGetPermanentSiloContext` hands it out without
  one, as Windows does. Freeing a slot does not empty it for the host
  silo, on Windows either.
- A silo monitor gets a slot of its own when registered. Started, one
  that watches the host has its create callback called for the host
  silo then and there, on the caller's thread; unregistered, its
  terminate callback, and then what the host holds in its slot is let
  go. No other silo is ever announced. The details (a monitor without a
  create callback is never started; a failing create callback is undone
  by the terminate callback) are Windows 10's.

A silo pointer that is not null, or a job, names nothing that exists:
where Windows would read the job behind it, NK stops by name. The job
type itself is real (`PsJobType`): a driver that asks for the job
behind a handle is told the handle names another type of object, which
is true of every handle there is.

## Waits

A thread waits on an event, semaphore, timer, mutex or thread by linking
one of its four built-in wait blocks on the object's wait list and
sleeping until a waker claims it. A time limit sets the thread's own
timer and links a second block there with key `STATUS_TIMEOUT`: the
limit is one more object, and the first signalled ends the wait. A wait
may name up to 64 objects (the caller's wait blocks beyond three), for
any one (it reports which) or for all (it takes all or none).

A wait by handle (`ZwWaitForSingleObject`) is a wait on the object the
handle names, referenced for as long: an event, a thread, or the
process, which never ends. Windows waits on an object of any other
type through that type's default object; NK does not, and stops by
name. `ZwCreateEvent` makes an event object without a name and hands
back a handle; a name, or the attributes that go with one, is refused
(`STATUS_NOT_IMPLEMENTED`). Both are `Partial` in the ledger for that.

A wait that would block at `DISPATCH_LEVEL` stops the system
(`ATTEMPTED_SWITCH_FROM_DPC` from a DPC). Releasing a semaphore past
its limit, an exception on Windows, stops the system.

**Alerts.** A thread can be alerted (`ZwAlertThread`), and an alert
ends an alertable wait with `STATUS_ALERTED`
([Waits and APCs](https://learn.microsoft.com/en-us/windows-hardware/drivers/kernel/waits-and-apcs)).
The state is where Windows keeps it: `KTHREAD.Alerted`, a byte per
processor mode, and the `Alertable` flag and `WaitMode` of the wait in
progress. A thread in an alertable wait is woken; any other keeps the
alert, one at most per mode, for its next alertable wait, which
returns at once without looking at its objects or its time limit and
takes nothing. An alert made in kernel mode ends a wait of either
mode; `ZwAlertThread` alerts in kernel mode. Waits that are not
alertable never see an alert. An alert is the only thing that ends a
wait this way: there are no APCs to deliver.

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

`ke::dpc::flush` waits until every DPC that was queued or running
anywhere has finished: an interprocessor call has each processor queue
one DPC more, and the caller, below `DISPATCH_LEVEL`, waits for those
to run. The kernel uses it before freeing what a DPC may refer to.

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

## The executive's locks, lists and timers

Each is state in the driver's memory, laid out as Windows lays it out,
with the rules for changing it in `lib/ex` (tested on the host, the
locks in every interleaving of a few threads) and the kernel's part,
atomic steps on the driver's memory and sleeping, in `kernel/ex`.
How they sit with the IRQL and NK's own locks: `doc/LOCKING.md`.

### Push locks

A push lock is one word: `Locked`, `Waiting`, `Waking`, and from bit 4
the number of shared holders, where the pinned kernel's symbols put
them. Semantics are the ones Microsoft documents for
[`FltAcquirePushLockExclusive`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/fltkernel/nf-fltkernel-fltacquirepushlockexclusive)
and its siblings. NK's decisions:

- **Waiters are not in the word.** Windows chains wait blocks through
  the word once a thread waits, and moves the share count into the
  chain. NK keeps the count in the word always and the waiters in
  queues of its own, found by the lock's address. So the word of a
  contended lock reads `Locked`, `Waiting` and a count where Windows
  has an address, and `MultipleShared` is never set. Nothing but the
  kernel's routines reads the word.
- **A waiter is woken to try again,** not handed the lock, as on
  Windows; an arrival may get there first. When the lock comes free
  the oldest waiter is woken alone if it wants exclusive access, and
  every waiter if it wants shared.
- **Nobody joins shared holders past a waiter,** so readers cannot
  starve a writer.
- The flags argument is not looked at. The WDK's own macros pass zero
  (`EX_DEFAULT_PUSH_LOCK_FLAGS`); what other values ask of Windows is
  not documented.
- Releasing a lock the word says is not held stops the system.

### Sequenced lists

`SLIST_HEADER` is 16 bytes with the same fields on both architectures:
depth, a sequence number, the first entry
([Singly and doubly linked lists](https://learn.microsoft.com/en-us/windows-hardware/drivers/kernel/singly-and-doubly-linked-lists)).
Push, pop and flush are lock-free: each stores its new header with one
16-byte compare-and-swap, `CMPXCHG16B` on x86-64 and an exclusive
load and store of the pair on arm64 (`arch::swap_pair`).

- The sequence number goes up on a push and stays on a pop or flush,
  as Windows' x86-64 routines are seen to do; that is what makes a
  swap against a stale header fail.
- **A pop reads the first entry's link before it knows the entry is
  still listed.** If the entry was popped and freed meanwhile the swap
  fails and the value is dropped, but the read has happened. Windows
  forgives a page fault at that instruction. NK relies on the memory
  being mapped: pool memory always is, and lookaside lists, the main
  user, keep pool blocks. An entry inside a driver's image goes when
  the driver is unloaded; unloading with a pop in flight elsewhere is
  a page fault that stops the system.
- Pushing an entry that is not 16-byte aligned stops the system.

### Lookaside lists

Allocating from a
[lookaside list](https://learn.microsoft.com/en-us/windows-hardware/drivers/kernel/using-lookaside-lists)
and freeing to it are code from the WDK's headers inside the driver,
which works on the structure directly and calls its `Allocate` and
`Free` pointers. The kernel initialises the structure and, on delete,
hands the blocks still kept to `Free`.

- `Allocate` and `Free` are the driver's routines or, where it gave
  none, `ExAllocatePoolWithTag` and `ExFreePool`.
- `Size` is stored as given, not rounded up.
- `Depth` starts at 4 and stays there, `MaximumDepth` at 256. Windows
  scans all lists periodically and moves `Depth` with the miss counts;
  NK has no scan, and `ListEntry`, by which Windows finds the lists,
  links the list to itself.

### Resources

An
[`ERESOURCE`](https://learn.microsoft.com/en-us/windows-hardware/drivers/kernel/introduction-to-eresource-routines)
is a reader/writer lock that records its owners, so that an owner may
acquire it again. The acquire rules are the ones Microsoft documents
for each routine. NK's decisions:

- **State is in Windows' fields:** `Flag`, `OwnerEntry`,
  `ActiveEntries`, `ContentionCount`, the two waiter counts, all
  changed under `ERESOURCE.SpinLock`. Owners beyond the first are in
  `OwnerTable`, a pool block the kernel allocates when it is first
  needed, doubles when it is full and frees in
  `ExDeleteResourceLite`.
- **Ownership is handed over.** A release that frees the resource
  records the waiters it lets in as owners before it wakes them; a
  woken thread does not compete again. The order is not documented and
  NK's is: after an exclusive owner, every thread waiting for shared
  access, or failing any the oldest exclusive waiter; after the last
  shared owner, the oldest exclusive waiter.
- **Waiters are on their own stacks.** `ExclusiveWaiters` and
  `SharedWaiters` point to the oldest waiter of each kind, a block
  that begins with the event its thread sleeps on. Windows allocates
  one event and one semaphore per resource there.
- `SystemResourcesList`, by which Windows links every resource for
  its debugger, links the resource to itself.
- No priority is raised for an owner that keeps others waiting, and a
  thread that waits for a resource it can never get waits for ever
  without the diagnostics Windows prints.
- Releasing or converting a resource the thread does not own stops the
  system (`RESOURCE_NOT_OWNED`).
- `ExEnterCriticalRegionAndAcquireResource...` are not exported: what
  they return is not documented.

### Executive timers

An
[`EX_TIMER`](https://learn.microsoft.com/en-us/windows-hardware/drivers/kernel/exxxxtimer-routines-and-ex-timer-objects)
is opaque to a driver except that its address can be waited on. NK's
is a pool block that begins with a `KTIMER`, followed by the DPC that
calls the driver's callback at `DISPATCH_LEVEL` and by NK's own state
(`kernel/ex/timer.rs`); the pinned kernel's symbols do not describe
Windows'. Setting, cancelling, expiring and waiting are the kernel
timer's. NK's decisions:

- **Freed only when nothing can reach it.** A delete can race an
  expiry on another processor, or come from the callback itself, and
  the callback is promised a valid timer. Retiring a timer cancels it
  and waits until every DPC queued on any processor has run
  (`ke::dpc::flush`, the promise of Windows' `KeFlushQueuedDpcs`),
  three times over: `kernel/ex/timer.rs` says why three. A delete that
  waits does this itself; otherwise a worker thread does and the
  delete returns at once.
- **Deleted without cancelling,** a timer that is set stays for one
  more expiry, callback included, and is retired then. Microsoft says
  only that it is not cancelled.
- The delete callback of `EXT_DELETE_PARAMETERS` is called after the
  timer is freed, from the thread that retired it.
- A period is kept in whole milliseconds, rounded up (the kernel
  timer's unit), where Windows keeps 100 ns: `ExSetTimer` is partial.
- A high-resolution timer expires on the clock tick like any other:
  `ExAllocateTimer` is partial. The no-wake attribute and a stated
  tolerance permit lateness NK never adds.
- An attribute bit Windows does not define fails the allocation.
  What Microsoft documents as a bug check is one: high resolution with
  no-wake, a high-resolution timer set for a system time, a delete
  that waits without cancelling. So is a period outside the
  documented range.

### UUIDs

[`ExUuidCreate`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntddk/nf-ntddk-exuuidcreate)
makes version-1 UUIDs ([RFC 4122](https://www.rfc-editor.org/rfc/rfc4122)):
a time, a clock sequence, a node.

- **The node is random and says so.** NK has no network card whose
  address could be the node, so every UUID is unique on this machine
  only and every call returns `RPC_NT_UUID_LOCAL_ONLY`, a success
  status. The node carries both the multicast bit of an 802 address,
  as the RFC asks of a made-up node, and the top bit of its first
  byte.
- **Each UUID is later than the last.** It carries the wall clock's
  time, or one unit more than the UUID before it if the clock has not
  moved or has gone back. So `STATUS_RETRY`, Windows' answer to a
  caller faster than its clock, is never returned.
- The clock sequence and the node are fixed at the first call, from
  the wall clock, the cycle counter and the time since boot: enough to
  tell boots and machines apart most of the time, and no secret.

## Objects, references and handles

Object-manager allocations have Windows' `OBJECT_HEADER` in front:
pointer count, handle count, type. Events, threads, the System process,
tokens, drivers, devices, open files, open registry keys, directories,
symbolic links and silo contexts are such objects. An object is freed when its last
reference goes; its type may name a delete procedure that first releases
what it owns, and a close procedure that is told of every handle closed
and how many there were. A thread references itself until it has ended
and been reaped, so an unreferenced thread frees itself and a referenced
one stays a valid, signalled object.

A driver's reference returns the count it made, its release the count it
left. The tagged forms (`ObfReferenceObjectWithTag`) count on the same
count: the tag is for
[reference tracing](https://learn.microsoft.com/en-us/windows-hardware/drivers/kernel/object-reference-tracing-with-tags),
which is off, as it is on Windows unless asked for. A reference taken to
an object that has none stops the system (`REFERENCE_BY_POINTER`).

Handles are entries in one table, the System process's, which is the
kernel's handle table as on Windows; a handle holds a reference until
closed. An entry has two names: the kernel handle, with Windows'
kernel-handle bits, which is a handle for kernel mode only
(`STATUS_INVALID_HANDLE` for user mode), and the same number without
those bits, the System process's own handle, good in that process for
either mode. Every open returns the kernel handle, a driver's with
`OBJ_KERNEL_HANDLE` or without (`ObOpenObjectByPointer`,
`ZwCreateEvent`): on Windows a handle made in the System process is in
the kernel's table whatever was asked. No other process, no other
table. A handle's number is predictable (the lowest free slot), so it
can be closed the instant it is in the table: it is given its reference
and its place in the object's handle count under the table's lock,
which a close takes to remove it. Each handle has the access it was
granted and its
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
caller. A null pointer is no exception: address zero ends a stack only
as a return address, never as the place a fault stopped the code.

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
is not mapped, for user mode a page outside the user range, and for
`IoWriteAccess` or `IoModifyAccess` a page whose mapping is read-only.
Firmware's runtime regions lie in the low half, mapped and writable, and
are outside the user range to every probe, the I/O manager's own
included: a requestor cannot name them as a buffer.

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
| dispatch routine, for WMI's registration request | nothing: it is sent from a worker, whose base stops the system |
| completion routine, cancel routine, a cancel-safe queue's callbacks | nothing: the cancel lock and its IRQL are the routine's to release, the queue's lock the driver's own |
| I/O work item's routine | undo: the device's reference |
| silo monitor's create and terminate callbacks | undo: release the mutex that serialises monitors |
| silo context's cleanup routine | nothing: the context is left allocated, as Windows leaves it |
| work item's routine (from the worker), a system thread's start routine, `DriverEntry`, the unload routine, a library's `DllInitialize` and `DllUnload` | base: a system thread |
| DPC routine, a timer's included | base: kernel mode |
| an executive timer's callback (from the timer's DPC) | base: kernel mode |
| an executive timer's delete callback | nothing: the timer is freed before it is called |
| a lookaside list's `Free` routine, for each block kept when the list is deleted | nothing: the blocks not yet handed over are left |
| a stream context's `FreeCallback` (`FsRtlTeardownPerStreamContexts`) | nothing: the context is off the header's list, and the header's lock and the critical region are given up before the call |
| a query table's routine (`RtlQueryRegistryValues`) | undo: what the query holds, in one block: its copy of the table, the value lent to the routine, its count on the key |
| a system service made for user mode (the oracle's requests) | base: a system service |
| bugcheck callback, as the system stops | base: kernel mode. The stop is reported already; a second error on the way ends it |

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

**Paging a driver.** `MmPageEntireDriver` and `MmResetDriverPaging`,
which a driver calls to let its whole image be paged out while it is
idle and to take that back, change nothing: NK never pages kernel
memory out, so an image is resident from load to unload, which is
within what both promise. The first still answers the base of the image
an address is in, or null.

## Starting a driver

A driver is started from its service key, as on Windows
(`kernel/io/service.rs`): `...\Services\<name>\ImagePath` names the
image, and a key without that value means `System32\drivers\<name>.sys`.
The last part of the path is looked up among the boot files, the
contents of `\NK\drivers`, which stand for `System32\drivers`: NK
reads no file system. Nothing else starts a driver; a library is
loaded when an image imports from it (Exports). The driver's entry
point is given the path to its key. Stopping a service runs the driver's
unload routine and frees its image; the key stays.

**At boot**, before anything else is done with drivers, the system
thread starts those whose keys say `Start` 0 (boot) or 1 (system), in
Windows' order (`nk_cm::services`): boot start before system start; in
each, by the place of the service's `Group` in
`Control\ServiceGroupOrder`, then by the place of its `Tag` in the
group's list under `Control\GroupOrderList` (a tag the list has not, or
none, after those it has); services of no listed group last; a service
after those it names in `DependOnService` and `DependOnGroup`. A group
is the same group in any letter case: Windows' own keys say
`File system` where its list says `File System`. Only keys whose `Type`
is a driver's count. Windows'
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
(`NtCreateFile`, `NtCreateNamedPipeFile`, `NtCreateMailslotFile`),
`read`, `write`,
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
requests are user mode's, their buffers pages of the user range.

A driver sends requests of its own with
[`IoAllocateIrp`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-ioallocateirp),
`IoCallDriver` (`IofCallDriver`) and `IoFreeIrp`: the IRP is the
driver's, with no thread and no requestor's buffers of NK's making, and
its completion routine keeps it or lets NK free it. It finds another
driver's device by name with
[`IoGetDeviceObjectPointer`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-iogetdeviceobjectpointer):
NK opens the device for kernel mode and closes the handle again, so the
device's driver is sent a create and a cleanup at once and a close when
the caller gives up the file object's reference it is handed.

A driver counts the requests in progress on a device with a
[remove lock](https://learn.microsoft.com/en-us/windows-hardware/drivers/kernel/using-remove-locks)
(`kernel/io/remlock.rs`): the lock is the driver's memory in the
free-build layout, and the `Ex` routines are what the documented macros
expand to.

A driver asks whose request it has with `IoGetRequestorProcess`: the
process of the thread in the IRP, which for every request NK sends is
the System process, and none for an IRP a driver allocated and gave no
thread. `IoGetFileObjectGenericMapping` hands a file system the file
type's own generic mapping, the one an open's desired access is mapped
with.

A request for user mode is also held to what its handle was granted,
before any driver sees it (`STATUS_ACCESS_DENIED`): `FILE_READ_DATA` to
read; `FILE_WRITE_DATA` to write, or `FILE_APPEND_DATA` unless the file
is a named pipe; for a control request the access its code names (bits
14 and 15). Kernel mode's handle is asked for nothing.

Completion follows the Windows
sequence: unwind the stack locations running completion routines, then
copy results to the requestor and signal its event. A buffered request's
results are copied only as far as the requestor asked; a driver that
reports more stops the system. A driver that returns other than
`STATUS_PENDING` without completing, or a status different from the one
it completed with, fails the request's test. A request made through a
handle holds the file object until it has been waited for.

**Open.** The name is looked up in the namespace, from the root or from
a directory a root handle names. The root handle is referenced on
behalf of the open's requestor, with no access asked of it, as Windows
references it: a kernel handle is no root for user mode
(`STATUS_INVALID_HANDLE`). The look-up ends at a device, and what
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
the pipe's `NAMED_PIPE_CREATE_PARAMETERS`, or `IRP_MJ_CREATE_MAILSLOT`
with the mailslot's `MAILSLOT_CREATE_PARAMETERS`) carries what Windows' does:
`Parameters.Create` with the disposition and create options, the share
access, no attributes and no extended attributes; an
`IO_SECURITY_CONTEXT` with the desired access and an `ACCESS_STATE` for
the System process, generic rights mapped to the file rights in both;
the requestor's mode in the IRP. What the driver leaves in
`IoStatus.Information` is the open's result. A create the driver fails
leaves a file object with no device, about which the driver hears no
more. The opener waits for a create the driver pends; what the request
points to is on the opener's stack until then. A dispatch routine that
returns anything but `STATUS_PENDING` for a create it has not completed
may still hold that IRP: the system stops, naming the routine.

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
one that may fail, and a buffer gone by then makes the access violation
the request's final status, in its status block. That is what the
request returns if the driver pended it; one completed before the
dispatch routine returned returns the routine's status, as Windows'
system services do. The driver is held to the status it completed the
request with, which the fault does not change.

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

**Stream contexts** (`kernel/io/fsrtl.rs`). A file system puts an
`FSRTL_ADVANCED_FCB_HEADER` at the front of each stream's control block
and initialises it with code compiled into the driver; `npfs.sys` and
`msfs.sys` make it version 3, advanced, supporting filter contexts.
When it frees the block it calls
[`FsRtlTeardownPerStreamContexts`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-fsrtlteardownperstreamcontexts),
and NK does what the pinned kernel does: under the header's own lock
(its push lock inside a critical region, or the file system's fast
mutex in a version 0 header) it unlinks the first context, lets the
lock go, calls the context's `FreeCallback`, and takes the lock again,
until the list is empty. A list found empty is not locked. A list whose
links do not lead back stops the system (`0x139`). NK differs in one
thing no correct file system can see: a header whose flags say it is
not advanced or supports no filter contexts is not read further, where
Windows reads the list regardless. Nothing in NK attaches a context:
no binary NK loads imports the routines that do
(`FsRtlInsertPerStreamContext`), so they are not exported. The test
`fsrtl.teardown-stream-contexts` attaches them by hand to headers set
up as the two drivers' code sets them up; the
`*-neg-stream-context-list` scenarios break a list.

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
a full table (`nk_rtl::upcase_char`: Windows' own, recorded from Windows
10). A key handle is a handle to a small object naming
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
opened through `CurrentControlSet` names its control set. The cached
form (`KEY_CACHED_INFORMATION`) is all there or not at all: it wants
room for the structure as C sizes it, 40 bytes, and writes the 36 of
its fields. What NK has
none of is reported as Windows reports a key without it: no flags, no
virtualization, no handle tags. Every key is trusted
(`KeyTrustInformation`), because the registry holds only the system's
own hive. Where a form is a word of bit fields (virtualization, trust)
the flags are written and the reserved bits stay the caller's. The
forms are those Windows 10 answers: it has no layer form
(`KeyLayerInformation` is `STATUS_INVALID_PARAMETER`).

A key's last write time is when its values or its list of subkeys last
changed: setting or deleting a value stamps the key, making or deleting
a key stamps the key above it, and a new key is stamped as it is made.
A key copied from the hive keeps the file's time until then.

A key remembers the longest subkey name, subkey class, value name and
value data it has held, which is what it reports as the longest it
holds: as on Windows, the numbers only grow while the key has subkeys
(or values) and start again when the last one goes. A key copied from a
hive file starts from the numbers the file gives it.

Creating makes only the last key of a path, as on Windows, and gives a
new key its class. A value is enumerated in the basic, full and partial
forms, and read by name in those and the two aligned for 64 bits, which
Windows 10 refuses to enumerate in (`STATUS_INVALID_PARAMETER`); there
are no layered keys, so the form that describes a value of one
(`KeyValueLayerInformation`) is refused the same way. A deleted value leaves its
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
  measured). A routine that rewrites the table changes nothing for the
  call in progress.
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
  must have room for the terminator.
- **No room is no failure**: `STATUS_BUFFER_TOO_SMALL` from delivering
  a value does not end the query, as on Windows, whether a routine
  answers it or the place an entry points to (a counted string's
  buffer, a buffer that states its size) is too small. Nothing is
  stored there, the table goes on, and the call succeeds if nothing
  else fails.
- **Several strings as one** (`REG_MULTI_SZ` with
  `RTL_QUERY_REGISTRY_NOEXPAND`) are delivered from the registry with
  one terminator more than the value holds, counted in the length, as
  Windows delivers them: `a\0bc\0\0`, 12 bytes, reaches a routine as
  14 and a counted string with a `Length` of 12.
- **Nothing is expanded**: the environment a caller passes is not
  read. A `REG_EXPAND_SZ`, value or default, asked for without
  `RTL_QUERY_REGISTRY_NOEXPAND` ends the call with
  `STATUS_INVALID_PARAMETER`, which is what the kernel of Windows 10
  answers even when the environment has the variable. With the flag it
  is delivered as stored.
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

## Strings

The rules are `lib/rtl`; the exports in `kernel/rtl` read and write a
driver's strings where they lie. A routine that cannot fail (a
comparison, a search, `RtlCompareMemory`) takes its input one unit at a
time and stops at the unit that decides the answer, so it needs neither
a copy nor memory for one. Strings the routines allocate come from the
pool and are freed by `RtlFreeUnicodeString` or `RtlFreeAnsiString`.

- **The ANSI code page is Windows-1252**, the page of the reference
  machine's English (United States) installation, compiled in
  (`nk_rtl::codepage`); the registry's `Nls\CodePage` key is not
  consulted. A character the page lacks becomes its best fit by
  Windows' table (a fullwidth or accented letter to its plain form),
  recorded from Windows 10 like the upper-case table, and `?` where
  that has none.
- **Upper case** is one table, `nk_rtl::upcase`: Windows' own, every
  unit as `RtlUpcaseUnicodeChar` answers on Windows 10, recorded there
  by the conformance driver `nkc-rtl`. It is older than the Unicode
  character database and leaves alone some units that maps (the micro
  sign, dotless i, long s, final sigma, Georgian). The string
  comparisons, the object namespace and the registry all use it.
- **The C runtime's comparisons** (`_stricmp`, `_wcsicmp`, `_wcsnicmp`)
  fold `A` to `Z` only and do not use that table.

### File names

`FsRtlIsNameInExpression` and `FsRtlLegalAnsiCharacterArray` are
exported from `kernel/rtl` with the strings they work on. The matcher
(`nk_rtl::wildcard`) runs the expression as a state machine over the
name, a bit per expression character in a fixed four kilobytes of the
caller's stack: its time is bounded by the product of the two lengths
whatever the pattern, it allocates nothing, and so it never raises,
where Windows raises `STATUS_NO_MEMORY`. What matches is what Windows
matches, the two cases included that the documented wording of the DOS
wildcards does not cover (stated in `nk_rtl::wildcard`). The name is
upper-cased by the caller's table when one is passed, read from the
caller's memory a unit at a time. The table of legal characters is
built from each file system's naming rules (`nk_rtl::legal`) and is
Windows 10's entry for entry: Microsoft publishes the flags and the
macros that read the table, not its contents.

### The prefix table

A [prefix table](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-rtlinsertunicodeprefix)
and its entries are the driver's memory, with the fields `ntifs.h`
declares (`nk_ntabi::rtl`), and an entry points to the caller's name
without copying it. NK keeps nothing beside them: the routines link the
driver's entries through the driver's own fields, as the header's names
describe (a list of trees by number of name components, a search tree
in each, a ring of the names that differ only in case). The algorithm
is `nk_rtl::prefix`, written against a store of nodes: the kernel's
store is the driver's fields behind raw pointers, the host tests' is a
vector, checked against a plain list over random sequences. No routine
allocates, so none can fail for want of memory. Which rotations balance
a tree is NK's choice: a name found without regard to case is splayed
to its tree's root. The caller serialises the calls on one table, as on
Windows. `RtlNextUnicodePrefix` is not exported.

## Security descriptors

SIDs, ACLs and descriptors are byte layouts with rules: `lib/se`, with
the exports in `kernel/se`. A driver's descriptor is the driver's memory:
read and written through raw pointers, the rules run on copies.
`SeExports` points to the well-known SIDs and privilege numbers, laid out
as in `ntifs.h`.

A SID's first two bytes say whether it is one and how long it is, so
the routines that take one read those before the rest and never read a
SID by a length it does not have; they copy at most the 68 bytes of the
largest SID, onto the stack. `RtlValidSecurityDescriptor` judges an
access list on a pool copy and answers "not valid" without memory for
one. App-container SIDs (`RtlGetAppContainerSidType`,
`RtlGetAppContainerParent`) are told apart by shape alone, `S-1-15-2`
with eight or twelve sub-authorities, and refused with Windows'
statuses (`nk_se::sid`); a parent's SID is a pool block the caller
frees.

NK itself enforces none: every open it makes is a kernel-mode open,
which Windows does not check either, and no user-mode code runs. A
driver that guards its own objects asks
[`SeAccessCheck`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-seaccesscheck)
and gets Windows' answer (below). Descriptors are
built, converted, captured and stored faithfully. `ZwSetSecurityObject`
replaces the named parts of a device's descriptor; for other objects it
answers `STATUS_NOT_SUPPORTED`. A new device has no descriptor until one
is set, where Windows gives a default. `SeCaptureSecurityDescriptor`,
forced, returns a self-relative pool copy, the caller's to free.

A driver that keeps descriptors for its own objects (a file system)
gets them from
[`SeAssignSecurity`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-seassignsecurity)
(the rules: `lib/se/assign.rs`), reads parts of one with
`SeQuerySecurityDescriptorInfo` and changes one with
`SeSetSecurityDescriptorInfo` (`lib/se/descriptor.rs`). Each descriptor
handed out is one self-relative pool block, the driver's to keep and
free, laid out lists first, then owner and group; what a query copies
out is laid out owner, group, DACL, SACL, as Windows' is; a changed descriptor is a new block and the old one is the
driver's to free. A list the creator supplies, or the token's default,
is assigned whole, as long as it says it is, its generic rights mapped
and the masks kept within what "generic all" maps to; the
creator-owner and creator-group SIDs are replaced by the new owner and
group only in entries inherited from the parent. Every creator is a kernel-mode creator, which may
name any owner for a new object; changing an owner asks the caller's
token, as on Windows. A changed descriptor always has an owner and a
group: naming one and supplying none is refused
(`STATUS_INVALID_OWNER`, `STATUS_INVALID_PRIMARY_GROUP`), where naming
the DACL and supplying none leaves the object a null DACL, which
allows everyone everything: Windows' rules, a caller's to know.

Where a descriptor lives:

- A device's is in `DEVICE_OBJECT.SecurityDescriptor`, a documented
  field a driver can read, as on Windows: a pool block the device owns,
  replaced under the I/O database lock.
- Any other object can carry one in `OBJECT_HEADER.SecurityDescriptor`
  (`kernel/ob/security.rs`): a reference to a copy in the store below,
  set, referenced and released by kernel routines, given up with the
  object or when replaced. The field is Windows' fast reference with
  its count bits zero. No object type gives its objects a descriptor:
  NK has no types' security procedures.
- The store (`nk_ob::descriptors`) keeps one counted, self-relative
  copy of each distinct descriptor, as Windows' does: logging the same
  bytes again, from whatever address, returns the same copy with more
  references, and the copy is freed with its last. A file system logs
  its files' descriptors there (`ObLogSecurityDescriptor`) and holds
  the copies (`ObReferenceSecurityDescriptor`,
  `ObDereferenceSecurityDescriptor`); objects with equal descriptors
  share a copy. What precedes a copy in its block (its count, a hash of
  its bytes) is NK's own. Giving up more references than are held stops
  the system, as Windows' fast fail does (`0x139`).

## Tokens and access state

A token is an object whose body is NK's own (`nk_se::token::Token`):
drivers treat `TOKEN` as opaque and ask through routines. There is one
logon, the system's: the System process's token has the user, groups
and privileges of Windows' SYSTEM token (the table at `Token::system`
says which of those facts Microsoft documents), and every other token
is a copy of it, but one. That one is the anonymous logon's
(`Token::anonymous`, S-1-5-7), made at boot as Windows makes it, which
a thread takes on to act as nobody (`ZwImpersonateAnonymousToken`):
it is in no group, not even everyone, and holds no privilege. Its
integrity level is "untrusted", by which Windows would also deny it
write access to objects that carry no label; NK applies no mandatory
policy.

A thread may impersonate: act with another token than its process's.
It keeps that token where Windows does, since Microsoft's drivers are
built against the thread's layout: `ETHREAD.ClientSecurity` holds the
token's address, the impersonation level and "effective only", and two
bits of `CrossThreadFlags` say that it impersonates and that opening
its token copies it (`kernel/se/impersonate.rs`). The thread holds a
reference to the token until it puts it off or is freed. A thread
takes a token on through `ZwSetInformationThread`
(`ThreadImpersonationToken`: an impersonation token by handle, or
none), and anyone may ask what a thread wears
(`PsReferenceImpersonationToken`, `ZwOpenThreadTokenEx`). A server
records its client in a `SECURITY_CLIENT_CONTEXT` of its own
([`SeCreateClientSecurity`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-secreateclientsecurity):
the client's token itself when tracked dynamically, a copy at the
level asked when tracked statically) and later takes it on
(`SeImpersonateClientEx`). Windows
lowers the level of an impersonation its process is not entitled to;
the System process, the only one, is entitled to all.

A driver asks a token about itself with
[`SeQueryInformationToken`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-sequeryinformationtoken)
(`lib/se/information.rs` lists the classes answered; the others fail
with `STATUS_INVALID_INFO_CLASS`) and `SeTokenType`. An answer with
parts of variable length is a pool block the driver frees; the session
id, the integrity level and "is an app container" are numbers written
in place of the block's address, as on Windows.

By handle a driver opens the process's token (`ZwOpenProcessTokenEx`),
asks it the same questions into a buffer of its own
(`ZwQueryInformationToken`) and copies it (`ZwDuplicateToken`). A copy
is a new token object: the same user, groups, privileges and defaults,
of the type asked, at the impersonation level its quality of service
names or else the source's own, with ids of its own. Every token's
statistics report Windows' least charge for its dynamic part, 0x1000
bytes, and none of it available, as Windows' do. An effective-only
copy leaves out the privileges and groups not in effect
(`Token::duplicate`).

A token never changes once it is made: NK exports nothing that adjusts
one. So a token has no lock, and
[`SeLockSubjectContext`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-selocksubjectcontext)
is what is left of Windows' routine when the token lock cannot be
contended: a critical region for each token of the subject.

What an open carries about its requestor has Windows' layout, because a
file system reads it in line (`kernel/se/token.rs`):

- the subject context
  ([`SeCaptureSubjectContext`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-secapturesubjectcontext)):
  the token the thread impersonates and at which level, the primary
  token (both referenced until the context is released), the process
  id for auditing. With no client token the impersonation level is not
  written, as on Windows;
- the access state (`SeCreateAccessState`), in the two structures its
  maker supplies, `ACCESS_STATE` and `AUX_ACCESS_DATA`: the subject, an
  operation id of its own, the access asked for as both original and
  remaining (generic rights mapped when a mapping is given), nothing
  granted yet, the traverse flag when the token holds
  `SeChangeNotifyPrivilege` enabled, and the privileges used, which
  start in the state's own set. An open NK makes itself gets both
  structures, with the file type's mapping. `SeDeleteAccessState` frees
  what the state came to own in the pool and releases the subject.

`SeAccessCheck` decides by the descriptor's DACL and owner and by the
subject's token: the client token of the captured subject if it has
one, else the primary token. The rules, their order and their statuses
are those of the pinned kernel's code (`lib/se/access.rs` lists them);
what that code does beyond them (mandatory integrity labels, restricted
tokens, object-specific and conditional entries, AppContainers) is not
done. Generic rights are the caller's to map, as on Windows. A right
that a privilege granted comes back in a privilege set from the pool,
which `SeFreePrivileges` frees.

Nothing audits: NK has no audit policy and nobody to report to, which
is Windows with every audit category off. `SeOpenObjectAuditAlarm`
does what Windows' does then (`kernel/se/audit.rs`): it clears the
access state's "generate audit" mark and leaves the caller's
"generate on close" as it was.

The privilege checks (`SePrivilegeCheck`, `SeSinglePrivilegeCheck`)
answer for the same subject, and mark in the caller's set the
privileges found enabled (`lib/se/privilege.rs`). A kernel-mode caller
holds every privilege, unmarked. `SeAppendPrivileges` records the
privileges an open used in its access state: in the state's own set
while three are enough, in a pool block after.

## Tracing

**NK starts no trace session.** Windows starts sessions at boot from
the registry's `Control\WMI\Autologger` keys and lets programs start
more ([Event Tracing](https://learn.microsoft.com/en-us/windows-hardware/drivers/devtest/event-tracing-for-windows--etw-));
NK ignores those keys and has no program to ask. So no provider is ever
enabled, and every answer below is the one Windows gives a provider
nobody listens to: real per its contract, with nothing recorded. NK
stands for a machine whose autologgers are all disabled.

**Providers** (`kernel/etw`, bookkeeping in `nk_etw`).
[`EtwRegister`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-etwregister)
makes a registration and hands out its handle. The enable callback is
never called, since nothing enables. An event written
(`EtwWriteTransfer`) is dropped with success, the event itself not
looked at, as Windows drops it. `EtwSetInformation` makes Windows'
checks in Windows' order (traits are set once, and must be well formed)
and keeps only the fact that traits are set: their content would go
into events.

A handle is NK's own: it names a slot of a fixed table and carries a
number no other registration has had, so one that was unregistered
stays invalid when the slot is taken again. The table is words changed
by compare-and-swap, with no lock, because events are written at any
IRQL. Windows' handle is a pointer it does not check: a stale one there
reads freed memory. NK answers `STATUS_INVALID_HANDLE` to a write or a
set through one, and stops with `EVENT_TRACING_FATAL_ERROR` (`0x11D`)
when one is unregistered, the bugcheck Windows has for a registration
handle that is not one. A full table is `STATUS_NO_MEMORY`, Windows'
status for a registration it cannot allocate.

**Classic providers and WPP.** The tracing start-up the WDK compiles
into every driver that traces with WPP looks routines up by name
(`MmGetSystemRoutineAddress`) and, where `EtwRegisterClassicProvider`
is absent, registers with WMI the way drivers did before Windows 7. NK
exports it, so such a driver takes the path it takes on Windows 10: a
registration in the same table, of the classic kind (it must have a
callback and cannot have traits), ended with `EtwUnregister`. The
callback would carry an enabling session's handle and is never called.

`WmiTraceMessage` writes a WPP message to a session: there is none,
whatever its number, and the answer is Windows' for a session that does
not exist (`STATUS_INVALID_HANDLE`), given before any argument is read.
`WmiQueryTraceInformation` is what a provider asks about the session
that enabled it (`nk_etw::logger`): the classes that take a session's
handle apart answer as on Windows, where they do not ask whether the
session exists; the rest find no session; the kernel's tables of trace
routines are `STATUS_DEVICE_NOT_READY`, Windows' answer before tracing
has started.

**WMI** (`kernel/io/wmi.rs`, bookkeeping and the check of a driver's
answer in `nk_etw::wmi`). There is no consumer of WMI data and never a
query, so what a driver sees is what Windows shows one that nobody asks
anything: its registration, and the request that follows it.

- [`IoWMIRegistrationControl`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-iowmiregistrationcontrol)
  records the device, references it, gives it a provider id (counted
  up, never reused) and returns. A system worker then sends the device
  `IRP_MJ_SYSTEM_CONTROL` with `IRP_MN_REGINFO_EX`, and with
  `IRP_MN_REGINFO` if the driver fails that; a driver that says how
  large a buffer it needs is asked again with one that large. The
  request is built as Windows builds it: a stack location of WMI's own
  above the driver's, a pool buffer of 0x2000 bytes that is not zeroed,
  the device as provider id, a completion routine that takes the IRP
  back. NK has no device stacks, so it goes to the device itself where
  Windows sends it to the top of the stack.
- The answer is checked as Windows checks it and then let go: nothing
  could ever read it. The references a driver takes on physical device
  objects for WMI when it answers the newer request are given back.
- `WMIREG_ACTION_UPDATE_GUIDS` sends the request again, marked as an
  update; `WMIREG_ACTION_BLOCK_IRPS` ends the sending. Deregistering
  drops what waits for the device, waits for a request that is with the
  driver, and gives the device back.
- A registration by callback or as a trace provider
  (`WMIREG_FLAG_CALLBACK`, `WMIREG_FLAG_TRACE_PROVIDER`) is how WPP
  registered before `EtwRegisterClassicProvider`. NK does not take it:
  `STATUS_UNSUCCESSFUL`, Windows' answer while WMI is not running. The
  export is `Partial` for that.
- `IoWMIWriteEvent` takes an event and frees its block, the event
  having nowhere to go. A trace event (`WNODE_FLAG_TRACED_GUID`) names
  a session, of which there is none.

One rule is NK's own: a driver that keeps asking for a buffer no larger
than the one it was given is not asked again, where Windows asks for
ever.

The tests `etw.*` and `wmi.*` call the exports as a driver does, the
latter with a driver object of their own that records each request as
it arrives; a test group that leaves a provider registered fails like
any other leak.

## Questions about the system

`kernel/ex/sysinfo.rs`, with the length rules in `nk_ex::sysinfo`.

`ZwQuerySystemInformation` and `NtQuerySystemInformation` are one
routine: every caller is in kernel mode. It answers the classes the
binaries NK runs ask for; any other is `STATUS_INVALID_INFO_CLASS`.
Lengths, and what is reported as the length needed, are the pinned
kernel's, class by class.

| Class | Answer |
| --- | --- |
| 0, basic | page size, 64 KiB granularity, Windows' user range, the processors running, the memory NK uses as RAM |
| 11, modules | the images in memory (below) |
| 35, kernel debugger | enabled and present with `debug=on`; else neither |
| 165, isolated user mode | sixteen zero bytes: no secure kernel. `msrpc.sys` asks, and pages itself out unless the first bit is set |

**The module list** is the table of images in load order, as Windows
lists them: `ntoskrnl.exe` first, then `hal.dll`, then the drivers.
NK has no HAL image; `hal.dll` is a second name of the kernel's and is
listed with the kernel's range, so a driver that expects Windows' first
two modules finds them, and an address in the kernel is the kernel's to
whoever takes the first module that contains it. The kernel and
`hal.dll` are reported in `\SystemRoot\system32`, every other image in
`\SystemRoot\System32\drivers`, which the boot files stand for. An
entry's `Flags` is zero and its `Section` and `MappedBase` are left as
the caller had them, which is what Windows does with those two.
`RtlQueryModuleInformation`, which the WDK's auxiliary library calls,
reports the same list in its two sizes. Either is answered from a copy
of the table, made in memory sized outside the table's lock; without
that memory the query fails with `STATUS_INSUFFICIENT_RESOURCES` and
writes nothing.

`PsGetVersion` gives `RtlGetVersion`'s numbers. `MmIsDriverVerifying`
is false: there is no verifier. `DbgkWerCaptureLiveKernelDump` answers
`STATUS_DEVICE_NOT_READY`, Windows' answer before its live-dump support
has started.

## Stopping the system

Every fatal error ends in one place (`kd::bugcheck`): the first
processor to get there stops the others, prints one `BUGCHECK:` line,
calls the drivers' bugcheck callbacks and powers the machine off. A
stop with a Windows code prints the code first, then its name.

[`KeBugCheckEx`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-kebugcheckex)
is that stop with the driver's code and four parameters, which
`KiBugCheckData` (five words a driver imports) holds from then on. A
stop of NK's own that carries no parameters leaves those words zero.

**Bugcheck callbacks**
([`KeRegisterBugCheckReasonCallback`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-keregisterbugcheckreasoncallback),
`kernel/ke/bugcheck.rs`, rules in `nk_ke::bugcheck`). The record is the
driver's memory, filled in and linked as Windows does it: routine,
reason, component, the checksum of the three, `State` inserted. One
list holds them all, newest first, triage-data records behind the rest
in the order they came. Any reason is accepted.

NK writes no crash dump and has no debugger, and calls what Windows
calls on such a system, at `HIGH_LEVEL` with the other processors
stopped, after the report:

| Reason | Called | With |
| --- | --- | --- |
| `KbCallbackReserved1` | yes | no data |
| `KbCallbackTriageDumpData` | yes, after the above | `KBUGCHECK_TRIAGE_DUMP_DATA`: the code and parameters of `KiBugCheckData`, no ranges named |
| `KbCallbackSecondaryDumpData`, `KbCallbackDumpIo`, `KbCallbackAddPages`, `KbCallbackRemovePages`, any other | never | they belong to the writing of a dump |

Before a routine is called its record is looked at as Windows looks: it
must lie where a pointer can, be linked from the record before it,
still be in the inserted state, still add up to its checksum, and be
registered for the reason being called. A record that fails the first
two ends the walk; one that fails the others is passed over. Windows
also asks whether the record's and the routine's pages are mapped; NK
does not, and a record in unmapped memory is a second error. Afterwards
the record's state is finished; a triage record whose routine named no
ranges is incomplete. The ranges are not read: they would go into a
dump.

A callback may call only what Microsoft documents as safe at that
point: a kernel routine that takes a lock may find it held by a stopped
processor. What a callback prints goes out whoever held the console. An
error inside a callback is a second error on the stopping processor:
it is noted, nothing more is called, and the machine powers off.

`KeRegisterBugCheckCallback`'s list, which Windows calls last, has no
importer among the binaries NK runs and is not exported.

The tests `ke.bugcheck.*` check registration; the
`*-neg-bugcheck-callback` scenarios stop the system with callbacks of
each kind registered, and the last one called prints which ran, in what
order, and what they were shown.

## Breakpoints and the debugger

A driver's breakpoint (`DbgBreakPoint`, in-line code) gets one of
Windows' two answers. By default, as with no debugger: an exception,
`0x80000003`, which stops the system unless a handler takes it (bugcheck
`0x7E` in a system thread). With `debug=on` on the command line, as with
a debugger that says "go" every time: noted on the console and passed
over, before any handler is asked. NK has no debugger protocol; the reference
Windows machine gets a real debugger, played by `tools/kd.py`.

## What is absent

No APCs, device interrupts, Plug and Play, power management, processes
other than System, user-mode code, ALPC ports, I/O completion ports,
priority boosts or registry write-back; the clock ticks at a fixed
rate; NK enforces no security descriptor on its own opens; the loader
binds no import from the kernel by ordinal or from an API set. Microsoft
publishes no arm64 binaries NK may use, so its own drivers run on x86-64
alone. NK has run on no physical machine.

**Traps.** Where a binary imports a routine in territory NK lacks and
does not reach it on the paths NK runs, the export is `Traps`
(`kernel/export/trap.rs`, which names them): the import binds, so the
binary loads, and a call stops the system with `BUGCHECK: <name>: NK
does not implement this routine`. One macro makes every such routine,
so none can return. The ledger lists them in the state `traps`, apart
from `implemented`.

| Territory | Imported by | Why |
| --- | --- | --- |
| ALPC ports (`ZwAlpc*`) | `msrpc.sys` | `msrpc.sys` is a library, loaded for what it exports; its `DllInitialize` calls none of these, which serve the RPC calls made through it |
| I/O completion ports | `msrpc.sys` | on which `msrpc.sys` waits for its ALPC messages |

The `*-neg-trap` scenarios call one through the address its name
resolves to and require the stop that names it.
