# Threads and scheduling

Part of NK's design ([DESIGN.md](../DESIGN.md)): the principles there apply.

## Threads

A thread is an `ETHREAD`-sized block with Windows' layout for the fields
NK keeps, followed by NK's own state, and a kernel stack. Each processor
has a ready queue per priority (0 to 31) with a summary word, and an idle
thread. A thread has an affinity and an ideal processor, handed out in
turn. Made ready, it goes to its ideal processor if idle, else any idle
processor its affinity allows, else its ideal processor. A processor with
nothing to run takes the best thread it is allowed from another's queues,
and one that leaves a thread waiting wakes an idle processor to take it.

A thread changes its own affinity while it runs
(`KeSetSystemGroupAffinityThread`, `KeRevertToUserGroupAffinityThread`):
nothing reads a running thread's affinity but the thread, so no lock is
involved. If the processor it is on is no longer allowed, the dispatcher
takes whatever is ready there, or the idle thread, and makes the thread
ready on a processor of its affinity: before the call returns, or, for
a caller at `DISPATCH_LEVEL`, when the IRQL comes down. `UserAffinity`
and `UserIdealProcessor` keep what the thread was created with, and
`SystemAffinityActive` says a system affinity is in force, as on
Windows. An ideal processor the new affinity does not allow becomes the
highest one it does.

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
(`STATUS_NOT_IMPLEMENTED`). `ZwOpenEvent` looks the name up and hands
back a handle to an event found there; what it finds otherwise is
answered as the namespace answers it (`mountmgr.sys` asks for an event
that only the session manager makes, and it is not found), and a name
relative to a directory handle stops by name. All three are `Partial`
in the ledger for that.

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
alertable never see an alert. Kernel APCs interrupt a wait too, and
it goes on (below).

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

Releasing the mutex or leaving the last critical region lets through
the kernel APCs held back meanwhile.

## Asynchronous procedure calls

An APC runs a routine in one thread's context (`kernel/ke/apc.rs`;
[Types of APCs](https://learn.microsoft.com/en-us/windows-hardware/drivers/kernel/types-of-apcs)).
The `KAPC` is the caller's; it is linked into the thread's `KAPC_STATE`
at Windows' offsets, under the thread's APC lock, and `KeInitializeApc`,
`KeInsertQueueApc` and `KeRemoveQueueApc` are exported as ntoskrnl
exports them. The rules are those of Windows' `KiInsertQueueApc`,
`KiSignalThreadForApc` and `KiDeliverApc`, read in the pinned kernel;
the decisions are `lib/ke/apc.rs`, tested on the host:

- A special kernel APC (no normal routine) goes after the last special
  one, ahead of every normal one; a normal one at the tail.
- Special APCs run at `APC_LEVEL` unless the thread is in a guarded
  region (`SpecialApcDisable`, `KeEnterGuardedRegion`). A normal one runs
  its kernel routine at `APC_LEVEL` and then its normal routine at
  `PASSIVE_LEVEL`, unless the thread is also in a critical region or
  already delivering one; then it and those behind it wait.
- They run when the IRQL falls below `APC_LEVEL`: queueing one for a
  thread that can run it raises the APC_LEVEL interrupt on its processor
  (vector `0x1F` on x86-64, as on Windows; SGI 4 on arm64), which the
  processor holds back while the IRQL is higher however it came down,
  and runs them after its end of interrupt. Leaving the last critical or
  guarded region runs them at once at `PASSIVE_LEVEL`, or raises the
  interrupt above it. A thread that gets a processor with APCs pending
  raises it for itself.
- A wait entered at `PASSIVE_LEVEL` (`WaitIrql`), alertable or not, is
  ended internally for them (`STATUS_KERNEL_APC`); the thread runs them
  and waits again with the same time limit. Whether the thread waits is
  its wait register's to say, so an APC queued as the wait begins is
  seen by one side or the other.
- `KeAreAllApcsDisabled` is a guarded region, interrupts off or an IRQL
  of `APC_LEVEL` and above.
- An ending thread takes no more APCs, runs the kernel APCs it can, and
  runs down its user APCs; one with kernel APCs it cannot run stops the
  system (`KERNEL_APC_PENDING_DURING_EXIT`), as Windows'
  `KeRundownApcQueues` does.

User-mode APCs are queued but never delivered; see [absent](absent.md).

## Stack expansion

`KeExpandKernelStackAndCalloutEx` (`kernel/ke/expand.rs`) runs a
routine with the stack it asks for, on the current stack when that has
the room, else on a stack segment: a kernel stack like a thread's
([Memory](memory.md): same size, alignment and guard, so both
architectures' overflow checks hold on it). The rules are Windows'
`KiExpandKernelStackAndCalloutSwitchStack`, read in the pinned kernel:
a size above 0x11800 fails with `STATUS_INVALID_PARAMETER_3`; above
`DISPATCH_LEVEL` the system stops; at `DISPATCH_LEVEL` a caller that
may wait fails with `STATUS_INVALID_PARAMETER_4`; a size equal to the
kernel stack's, or 0x6000, always gets a segment, as the file systems'
0x6000 on every create and transfer does.

The switch is `arch::call_on_stack`, whose unwind information leads a
walk back to the stack it left. While the routine runs on a segment the
thread's `InitialStack`, `StackBase` and `StackLimit`, `IoGetStackLimits`,
the overflow check and the unwinder see the segment. An exception the
routine lets out unwinds across the switch: the guarded call around it
puts the thread back on its stack as the unwind passes, and the
segment, still under the unwind, stays walkable and is never handed
out again; it is freed once the thread is back on its own stack, or
ends. A segment is allocated before it is installed, and the counts
change at `DISPATCH_LEVEL`, so an APC that expands the stack meanwhile
finds them whole. A segment is never larger than a
thread's stack, so a size it cannot hold fails with
`STATUS_INSUFFICIENT_RESOURCES`, as does one at `DISPATCH_LEVEL` the
current stack cannot hold (Windows may switch there), and a thread runs
on at most six segments at once.

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
A DPC given a target with `KeSetTargetProcessorDpcEx` goes on that
processor's queue, whichever processor queues it; `Number` holds the
target as Windows encodes it, and otherwise the processor that last
queued the DPC. The processor whose queue it is, is interrupted for
every DPC queued, at once: Windows holds some back by importance, queue
depth and rate, and NK runs none later than Windows would. Of the
importance set with `KeSetImportanceDpc` NK acts on what orders the
queue: a DPC of high importance goes in front. A threaded DPC (`KeInitializeThreadedDpc`) is an ordinary
DPC, run at `DISPATCH_LEVEL`, which is how Windows runs one with
threaded DPCs turned off. `KeSetCoalescableTimer` sets a timer that is
never delayed.

Drivers that ask about processors by group or NUMA node are told of
one group and one node, numbers 0, holding every running processor
(`nk_ke::topology`); a processor's index is its number in the group.
NK reads no topology from the processors or the firmware, so
`KeQueryLogicalProcessorRelationship` states each logical processor as
a core of its own in a package of its own, and no cache; its records
come in Windows' order from `nk_ke::topology::relationships`.
`KeRegisterProcessorChangeCallback` registers the routine with
`\Callback\ProcessorAdd`, as Windows does, and tells it of the
processors there are if asked to; no processor is added while NK runs,
so the object is never notified, and no lock keeps a registration and
an addition apart. `KeReportCacheIncoherentDevice` records nothing:
NK flushes buffers for devices wherever the architecture needs it,
reported or not.
`KeFlushIoBuffers` does nothing on x86-64 and, on arm64, writes the
buffer's cache lines back and drops them.

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

A `KTIMER2` (`KeInitializeTimer2`, `KeSetTimer2`, `KeCancelTimer2`) is
storage of the driver's whose fields no driver reads, so NK uses its
136 bytes its own way (`ke::timer2`): a kernel timer where Windows has
the dispatcher header, the DPC each expiry queues, and the callback's
context. It behaves as an executive timer does, with the same
departures: periods in whole milliseconds, no high resolution, never
late on purpose. The header's type byte is a kernel timer's, not
Windows' value for a `KTIMER2`.

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

A driver may keep an I/O work item in memory of its own instead:
`IoSizeofWorkItem` bytes (Windows' `IO_WORKITEM`, which NK's is, so
nothing of NK's lies outside them), made a work item by
`IoInitializeWorkItem` and given up with `IoUninitializeWorkItem`,
which stops the system if the item is still queued. A routine queued
with `IoQueueWorkItemEx` is handed the item as well. Which kind of
routine an item has is its `Type`, set as the pinned kernel sets it:
`IoInitializeWorkItem` makes the newer kind, `IoQueueWorkItem` the
older, and `IoQueueWorkItemEx` leaves it.
