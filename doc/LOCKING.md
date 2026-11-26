# Locking

How NK protects its own data on several processors. A new or changed
lock changes this file in the same commit.

## IRQL

| Level | Value | x86-64 vector | arm64 interrupt | What runs there |
| --- | --- | --- | --- | --- |
| `PASSIVE_LEVEL` | 0 | | | threads: driver entry, dispatch routines, work items, the tests |
| `APC_LEVEL` | 1 | | | a thread holding a fast mutex |
| `DISPATCH_LEVEL` | 2 | `0x2F` | SGI 3 | DPCs, the dispatcher, code holding a spin lock |
| clock | 13 | `0xD1` | virtual timer PPI | the clock tick |
| interprocessor | 14 | `0xE1` | SGI 1 | `ke::ipi` routines |
| `HIGH_LEVEL` | 15 | | | the locks of the highest ranks (the DPC queues, the console and those beside them in the table below); the bugcheck path |

The IRQL is the interrupt controller's priority mask and nothing else;
on neither architecture is it a copy in memory (see "Per-processor
state"):

- x86-64: CR8, the local APIC's task priority, because WDK-built code
  reads and writes it there. A vector's IRQL is its upper four bits, as
  on Windows.
- arm64: the GIC's priority mask, through an export. An interrupt at
  IRQL `n` has priority `0xF0 - 0x10*n`.

Interrupts are enabled from early boot and never disabled to protect
data; raising the IRQL keeps them out. A handler runs at its interrupt's
IRQL with interrupts enabled, so only something more urgent preempts it;
end-of-interrupt is sent before the IRQL comes back down
(`kernel/ke/interrupt.rs`).

Rules (`kernel/ke/irql.rs`, checked on every change):

- `raise` goes up or stays; `lower` goes down or stays. The reverse is a
  bugcheck: `IRQL_NOT_GREATER_OR_EQUAL` (0x9), `IRQL_NOT_LESS_OR_EQUAL`
  (0xA).
- A driver is loaded and unloaded at `PASSIVE_LEVEL`, else bugcheck 0xA.
- Every test group ends at the level it started.

## Spin locks

`ke::SpinLock<T>` is NK's lock for its own data. It is not the
driver-visible `KSPIN_LOCK`. Taking one raises the IRQL to the level of
its rank, waits its turn (waiters are served in order of arrival), and
gives access to the `T` inside until the guard is dropped, which restores
the IRQL.

Per processor, the kernel records which locks are held
(`ke::percpu::PerCpu`). The record is updated at `HIGH_LEVEL`, whatever
the lock's own level: an interrupt handler may take a lock too, and must
never find the record half written.

### Order

Locks nest in strictly rising rank. A lock is taken only while every lock
already held has a lower rank; two locks of one rank never nest.

| Rank | Lock | Protects | Level |
| --- | --- | --- | --- |
| 10 | `io::driver::DRIVERS` | records of loaded drivers | DISPATCH |
| 25 | `io::device::DATABASE` | every device's reference count, `ExtensionFlags` (delete pending among them), place in a stack (`AttachedDevice`, the extension's `AttachedTo`, and `StackSize` as it is set by attaching) and security descriptor pointer; each driver's list of devices and of driver-object extensions | DISPATCH |
| 27 | `io::wmi::WMI` | which devices are registered with WMI, their provider ids, and the registration requests waiting to be sent | DISPATCH |
| 30 | `ob::NAMESPACE` | the namespace's directories and entries; each named object's name information | DISPATCH |
| 33 | `cm::HIVE` | the registry's keys and values | DISPATCH |
| 35 | `ob::handle::TABLE` | which object each handle names; a handle's reference and its place in its object's handle count from the moment it is in the table | DISPATCH |
| 40 | `mm::pool::POOL` | pool arenas and large allocations | DISPATCH |
| 50 | `mm::map::NEXT_VA` | kernel address space and page-table edits | DISPATCH |
| 60 | `mm::FRAMES` | the frame bitmap | DISPATCH |
| 200 | `ke::ipi::CALL` | the interprocessor call in progress | DISPATCH |
| 210 | a work queue (`ex::work`) | the work items waiting for a worker thread | DISPATCH |
| 215 | a queue of push-lock waiters (`ex::pushlock`) | which threads wait for the push locks whose addresses lead to that queue; the `Waiting` bit of those locks | DISPATCH |
| 217 | `ex::uuid::IDENTITY` | the time of the last UUID made, and the clock sequence and node all of them carry | DISPATCH |
| 220 | a processor's ready queues (`ke::thread`) | which threads are ready there, their links and state, and the priority each is queued at | DISPATCH |
| 230 | a processor's timer table (`ke::timer`) | which timers are pending there, and when | DISPATCH |
| 232 | `ob::security::STORE` | which security descriptors are stored, and each bucket's chain | DISPATCH |
| 233 | `ps::silo::HOST` | which silo context slots are allocated, and the context the host silo holds in each | DISPATCH |
| 234 | `se::impersonate::IMPERSONATION` | what every thread impersonates: `ETHREAD.ClientSecurity` and the two flags that go with it | DISPATCH |
| 235 | an object's header lock (`ob::security`) | the security descriptor pointer in that object's header | DISPATCH |
| 240 | a processor's DPC queue (`ke::dpc`) | the DPCs waiting to run there | HIGH |
| 242 | `ke::bugcheck::RECORDS` | the list of bugcheck callback records drivers registered, and each record's links and state | HIGH |
| 245 | `ldr::MODULES` | which image an address is in; how many images import from each library | HIGH |
| 250 | `kd::CONSOLE` | the diagnostic UART | HIGH |

Why this order:

- A device's reference count and its delete-pending mark change only
  under the I/O database lock, so "the last reference went" and "the
  device was deleted" are seen together by whichever comes second. That
  one frees the device, after dropping the lock.
- The attachment chain of every stack is under the same lock, as
  Windows keeps it under its one database lock: a device is attached,
  detached, and the top or bottom of its stack found and referenced,
  with the lock held, so a walk of the chain never meets a device that
  is being unlinked. "Nothing is attached any more" joins the two
  conditions above: the last of the three to come true, seen under the
  lock, frees the device after dropping it. A driver's
  `FastIoDetachDevice` is called with the lock dropped and the deleted
  device counted.
- The namespace is one lock: every directory, every entry. An object
  found by name is given a pointer reference under it, and whoever named
  an object takes the name away under it before giving up the reference
  the object was made with; so a name leads to a live object. A look-up
  returns with the lock dropped and that reference held: whatever is
  done with the object and the rest of the path (counting an open under
  the database lock, sending a driver the create request) happens
  outside it.
- No object's last reference is dropped under the namespace lock: a
  removed symbolic link's object is released after it.
- A device's security descriptor is replaced under the same lock, new
  block built from old while it is held (the pool ranks above it), so
  two changes at once cannot both start from the same descriptor. The
  old block is freed after the lock is dropped.
- WMI's lock covers its lists and nothing else: a device is referenced
  before it is entered and released after it is taken out, the worker
  is queued after the lock is dropped, and a driver is sent its
  registration request with no lock held. Like the tables above the
  pool, the lists allocate from it under the lock.
- The registry's lock is held only around a look-up or a change of the
  tree; a key handle is resolved before it is taken and the driver's
  memory is read and written outside it. The key object the handle
  named stays referenced until the lock has been released for the last
  time in the call: an object counts its key as open, and a key that
  is open keeps its place in the tree, so what the call finds under
  the lock is that key or its deletion, never a key made since. The
  reference is dropped outside the lock, which the last one takes. No routine of a driver's runs
  under it: a query table takes it for each read and gives the routine
  copies.
- A driver's entry point and unload routine run with the driver
  table's lock released, so the table changes under them: an unload
  finds its driver's record again once the routine has returned, under
  the lock hold that removes it.
- The tables above the pool hold `Vec`s, which allocate from the pool
  while the table's lock is held. A new handle takes its reference and
  its place in the object's handle count under the handle table's lock,
  so that a close, which removes the entry under it, never gives back
  what the handle has not yet got. An object's last reference is never
  dropped under the handle table's lock, nor is its type told of a
  closed handle there: freeing takes the pool's lock, and a file's close
  and delete procedures call its driver.
- The pool and the address space each take frames while holding their own
  lock (a new arena; a new page table). They never take each other.
- An interprocessor call may be made with any of the above held:
  unmapping a page holds the address-space lock while every processor
  drops the translation. The call lock is held at `DISPATCH_LEVEL`, below
  the interprocessor interrupt, so a processor waiting for it still
  answers the call in progress. A routine run by a call takes no lock
  below rank 200: its caller may hold any of them.
- A work queue's lock covers only linking and unlinking items. The
  semaphore that wakes a worker is released after the lock is dropped,
  and no work routine runs with it held.
- A queue of push-lock waiters is locked only to link a waiter, or to
  take waiters off and store the lock's word. Nothing is taken inside
  it: the waiters' events are set, and so the ready queues locked,
  after it is dropped. The queues share a rank and no two are held
  together.
- The UUID lock is held while one UUID's time is chosen, reading the
  clock and nothing else; nothing is taken inside it.
- A timer table's lock owns a pending timer's links, due time,
  processor and `Inserted` bit. Expiry holds it while it takes a due
  timer out and puts a periodic one back, then drops it before queueing
  the timer's DPC. No two tables are held together: a timer moves from
  one processor's table to another's by leaving the first under its lock
  and entering the second under its own.
- The store of security descriptors is searched and changed under its
  lock and nothing else is done there: a descriptor's block is
  allocated before the lock is taken and freed after it is dropped, so
  the pool's lock, though it ranks below, is never wanted inside. A
  descriptor's count is raised without the lock by whoever already
  holds a reference, and lowered only under it, so a count that
  reaches zero there finds the entry still in its bucket to take out.
- The silo lock is held to read or change one word of the slot table
  or of the host silo's storage. A context's reference is taken before
  the lock and dropped after it, never inside: dropping the last calls
  the driver's cleanup routine.
- An object's header lock is the `Lock` word of its `OBJECT_HEADER`,
  where Windows has it, not a `SpinLock`: its holder spins on the word,
  and the hold is ranked and recorded all the same (`ke::Ranked`). It
  ranks above every other lock held at `DISPATCH_LEVEL`, so it may be
  taken with any of them held and none of them inside it: not the
  pool's (a replaced descriptor is freed after the lock is dropped),
  not a second object's.
- A DPC is queued from any IRQL, an interrupt handler's included, so the
  queue's lock is held at `HIGH_LEVEL` and nothing but the console is
  taken inside it. No DPC routine runs with it held.
- A bugcheck callback record is registered and taken back at any IRQL,
  so the list's lock is held at `HIGH_LEVEL`; it covers a few pointer
  writes and nothing is taken inside it. The stop itself walks the list
  without the lock: no other processor runs.
- The table of loaded images is searched from any context, a fault
  handler included, so it is held at `HIGH_LEVEL` and holds no memory:
  nothing but the console is taken inside it.
- The console is innermost and at `HIGH_LEVEL` so that anything can print
  from anywhere, a fault handler included.

### Rules

Each of these stops the system when broken:

- **Rank order**, as above ("lock order violation").
- **Never twice.** A processor does not take a lock it holds:
  `SPIN_LOCK_ALREADY_OWNED` (0xF).
- **Release what you hold, innermost first.** Dropping guards in scope
  order does this. Releasing out of order would lower the IRQL while an
  outer lock is still held. `SPIN_LOCK_NOT_OWNED` (0x10) or "lock order
  violation".
- **No call into a driver with a lock held.** A driver entry point
  expects `PASSIVE_LEVEL`; a held lock means `DISPATCH_LEVEL`.

The locks ranked below the pool's protect data that Windows guards with
locks a thread can sleep on. Spin locks stand in for those; they are stricter,
never looser.

`force_lock` takes a lock regardless, without bookkeeping. Only the
path that stops the system uses it, on the console, the table of
loaded images and the list of bugcheck callback records, and never
returns.

### The loader's mutex

Loading and unloading an image are serialised by a kernel mutex
(`KMUTANT`), `ldr::LOADER`, not by a spin lock: a load calls a library's
`DllInitialize` and an unload its `DllUnload`, either of which may
wait, and a library is loaded from inside the load of the image that
imports from it, by the same thread (a mutex may be taken again by its
owner).

- It is taken at `PASSIVE_LEVEL` with no spin lock held, since taking
  it may sleep; whoever holds it may take any ranked lock.
- It covers the list of libraries and the order of events: an image is
  entered in the table of images, bound to its libraries and counted as
  their importer, or none of it, without another load or unload in
  between. The counts themselves are in the table of images, under its
  own lock.
- A library's `DllInitialize` and `DllUnload` run with it held, as on
  Windows, where the system's load lock is held around them. A driver's
  entry point and unload routine run without it.

### The silo monitors' mutex

Starting and unregistering silo monitors are serialised by a kernel
mutex, `ps::silo::MONITORS`, as Windows serialises them with a lock a
thread can sleep on: the monitor's create and terminate callbacks run
with it held, at `PASSIVE_LEVEL`, and may wait. It is taken with no
spin lock held and nothing ranked is held across a callback. An
exception that unwinds a callback releases it (the guard of that call,
`doc/DESIGN.md`). What a monitor's slot holds is let go after the mutex
is released.

### Per-processor state

What a processor keeps for itself is found through a register that
names the processor (GS, x18). Below `DISPATCH_LEVEL` a thread can be
preempted and moved to another processor at any instruction, so finding
the processor and then using what was found is two steps with a hole
between them: the thread may read, or write, the state of a processor it
is no longer on. Therefore:

- per-processor state is used at `DISPATCH_LEVEL` or above, where the
  thread cannot move; or
- it is read in one instruction that both finds and reads (the current
  thread, as drivers' in-line code does; the IRQL, which is a register).

A processor number read below `DISPATCH_LEVEL` is where the thread was a
moment ago, and is treated as no more than that.

The register itself belongs to the processor too. A thread's saved state
never carries it: the thread switch leaves it alone, and the arm64
interrupt exit takes x18 from the processor (`TPIDR_EL1`), not from the
frame it saved on entry, because the thread being resumed may have been
taken by another processor in between.

### Switching threads

The dispatcher runs at `DISPATCH_LEVEL` and holds no lock across a
switch: the ready-queue lock is dropped first, and the record of held
locks is the processor's, so nothing held could follow the thread. Two
rules stand in for the lock:

- **`swap_busy`.** A thread that gives up its processor is put on a
  queue while still running on its stack. The flag is set before it
  becomes visible there and cleared by the next thread on that
  processor, once the old stack is no longer in use. A processor never
  switches to a thread with the flag set; it waits.
- **Only idle threads wait, and only idle threads take.** A thread that
  finds its successor's flag still set does not wait for it: it switches
  to its processor's idle thread, which waits instead. And only an idle
  thread takes a thread from another processor's queues. An idle thread
  is never wanted by another processor, so there can be no ring of
  processors each waiting for the thread the next is leaving. No two
  processors' ready queues are ever locked together.
- **The next thread cleans up.** The thread switched to clears the flag
  of the one before it, or buries it if it exited. A thread never frees
  its own stack. The burial signals the thread and drops the thread's
  reference to itself under the thread's lock (its header's object
  lock, below), so that nobody sees the one without the other; the last
  reference may then go from anywhere, and the thread's delete
  procedure takes and releases that lock before the block is freed.

A thread's priority can be changed by another thread while the thread
runs, waits or is queued, and no one lock covers all three. Two rules
do:

- **One change at a time.** Whoever changes a thread's priority holds
  that thread's own lock (its header's object lock, below) for the
  whole change, and takes a ready queue's lock inside it.
- **Write, then look; publish, then read.** The changer writes the
  priority and then looks whether the thread is queued. A processor
  queueing a thread marks it queued, under its queue's lock, and then
  reads the priority. Whatever the interleaving, one of the two sees
  the other: either the queueing processor reads the new priority, or
  the changer finds the thread queued and moves it, under that queue's
  lock. So a thread is never left queued at a priority it no longer
  has.
- **Whoever queues, answers for the queue.** A changer that finds the
  thread on no queue does nothing more about a raise. So a processor
  looking for work reads another's threads where they are, under that
  queue's lock, from the best down to the first it is allowed to run,
  and takes that one off only to run it. And a processor that
  queues a thread has the queue's processor look again: always, for a
  thread made ready; for the thread it is itself leaving, when the
  priority it queued the thread at is above the one it chose the next
  thread against. (A thread put back because it is still leaving its
  last stack is put back for the idle thread, which looks at once.)

A thread at `DISPATCH_LEVEL` or above is never switched away from:
preemption happens only at the end of an interrupt that returns below
`DISPATCH_LEVEL`. So a held spin lock, which raises the IRQL, also pins
the thread to its processor.

The IRQL belongs to the processor, not the thread. Every switch happens
at `DISPATCH_LEVEL`, and each thread lowers it again on its own way out
of the dispatcher.

### Object locks

Every object a thread can wait on (event, semaphore, timer, mutex,
thread) has a lock of
its own, bit 7 of its header's type byte, as on Windows. It covers the
object's signal state, its list of wait blocks, and the blocks linked
there. It is taken at `DISPATCH_LEVEL`, before any ranked lock. These
locks are in the driver's memory and are not ranked or recorded. (The
lock in an object's header is another matter: rank 235 above.) Nothing
holds two, with one exception: a wait for all of several objects holds
all their locks at once while it looks and takes, locking in order of
address and unlocking in reverse.

For a timer the lock also serialises setting and cancelling. Expiry
takes the timer out under the table's lock, lets go, and only then takes
the timer's own lock to signal it; a timer that was set again in
between is left alone.

A thread's lock also serialises changes of its priority ("Switching
threads" above): a ready queue's lock is taken inside it. A thread's
delete procedure takes it as a barrier, whatever its caller holds: the
burial it waits out takes nothing inside it but wait registers. And it
covers the thread's alert state (`Alerted`, `Alertable`, `WaitMode`).
A thread takes its own lock, holding no other, to say its wait is
alertable, after looking for an alert left for it, and again to say
the wait is over; an alerter takes it to claim such a wait through the
wait register or else to leave the alert. So an alert either ends the
wait in progress or is found by the next: none falls between.

A mutex's lock also covers its owner and its place in the owner's list
of mutexes held. A thread being let in to a mutex while it sleeps has
its list and its APC-disable count changed on its behalf by the
releasing thread, under that mutex's lock; otherwise only a thread
itself changes them.

### Impersonation

One lock covers what every thread impersonates, where Windows has a
lock per thread: a thread asks about another's token, or changes it,
rarely and briefly. Under it a token is read out of a thread and
referenced, so the thread cannot let go of it in between; a token
replaced or put off is dereferenced after the lock is dropped, since
its last reference frees pool memory. Nothing else is taken inside it.
A thread being freed reads its own fields without the lock: nothing
else can reach it any more.

### Tokens

A token is written once, before anything else can reach it, and never
again, so it has no lock: whoever holds a reference reads it freely.
What Windows guards with the token's lock (`SeLockSubjectContext`,
`SeQueryInformationToken`) NK reads without one. `SeLockSubjectContext`
still enters the critical regions a driver can observe.

### Waiting and waking

The race between a thread going to sleep and whatever would wake it is
settled by one word per thread, the wait register
(`nk_ke::WaitRegister`), changed only by compare-and-swap. Its every
interleaving with several wakers is checked on the host.

- **Begin before linking.** A thread marks its wait begun, under the
  object's lock, before its wait block is linked there. From then on a
  waker may claim it.
- **One claim ends a wait.** A waker that finds a signalled object and a
  wait block claims the block's thread with the status its wait is to
  return. One claim succeeds per wait, whether it comes from the object,
  from the thread's timer (a time limit is a second wait block, on the
  thread's own timer), or both at once.
- **The claim says what to do.** If the thread had already committed to
  sleep, the claimer makes it ready. If it had not, the claimer leaves it
  alone: the thread's own commit fails and it never sleeps. A thread is
  never made ready while it is running.
- **Ready after unlocking.** A waker collects the threads it claimed and
  makes them ready only after dropping the object's lock, and never
  touches the object again. So an event on a thread's stack may be freed
  as soon as that thread's wait returns.
- **The waiter unlinks what is left.** The winning waker unlinks its own
  block. Any other block of the wait (the timer's, when the object won;
  the object's, when time ran out) is unlinked by the thread itself,
  under that object's lock, before its wait returns. A waker that meets
  such a leftover block cannot claim its thread and passes over it.
- **All or nothing.** A waker does not take its object for a thread
  that waits for all of several; it only wakes it. The thread then looks
  again, holding every object's lock, and takes all of them or none and
  waits again. Its time limit is fixed once, however often it looks.
- **Only what was linked.** After a wait the kernel looks only at the
  wait blocks that wait linked. The rest of a caller's wait block array
  is the caller's memory, in whatever state it was left.
- **A thread takes no timer to its grave.** A wait cancels its timer
  and, if an expiry had already taken the timer out of its table, waits
  until that expiry has finished with it, before it returns. Reaping a
  thread checks that its timer is neither pending nor mid-expiry.

## Without a lock

Some shared state has no lock, because a driver may reach it at any
IRQL or because Windows defines it as one word changed atomically:

- The table of registered trace providers (`kernel/etw`): a slot is
  claimed and given up by compare-and-swap, so a provider writes an
  event at any IRQL.
- A sequenced list (`SLIST_HEADER`): push, pop and flush are one
  16-byte compare-and-swap on the header in the driver's memory
  (`arch::swap_pair`).
- A push lock's word and a thread's wait register
  (`nk_ke::WaitRegister`), each changed only by compare-and-swap; the
  queues of threads behind them are under ranked locks (the table
  above).

## What drivers get

Drivers use Windows' routines, not `ke::SpinLock`
(`kernel/ke/kspin.rs`). A `KSPIN_LOCK` is one word the driver owns, zero
when free; NK touches it only with single atomic operations through the
driver's pointer and keeps no state of its own about it. The acquire
routines raise the IRQL to `DISPATCH_LEVEL` and return the old level; the
`AtDpcLevel` ones leave it alone. A queued spin lock fills in the
driver's handle as Windows does but does not queue its waiters, so the
arrival order Windows guarantees is absent; the ledger marks that export
partial.

The cancel spin lock (`IoAcquireCancelSpinLock`, `io::irp::CANCEL_LOCK`)
is a driver's kind of lock too: one for the whole system, taken by
`IoCancelIrp` and released by the driver's cancel routine, so it cannot
be a guard and has no rank. It is held at `DISPATCH_LEVEL`. NK takes
none of its ranked locks while holding it, except through what the
driver's routine calls; the cancel routine of a cancel-safe queue
releases it before it takes the queue's lock.

### Locks a driver's thread sleeps on

A push lock (`kernel/ex/pushlock.rs`) is one word the driver owns, with
Windows' bits; NK changes it only by compare-and-swap through the
driver's pointer. A thread that cannot have it sleeps: the routines
are for `PASSIVE_LEVEL` and `APC_LEVEL`, and a wait at `DISPATCH_LEVEL`
stops the system like any other. They leave the IRQL and the thread's
APC state alone. As on Windows it is the caller that enters a critical
region first, so that the holder cannot be suspended; NK queues no
APCs and does not check that it did. The waiters are in NK's own
queues (rank 215), not chained through the word as Windows chains
them.

A resource (`ERESOURCE`, `kernel/ex/resource.rs`) keeps its state in
the driver's structure under the structure's own `SpinLock`, a
`KSPIN_LOCK` like any the driver has: held at `DISPATCH_LEVEL`, not
ranked or recorded. NK takes none of its ranked locks inside it: the
owner table is allocated and freed with it dropped, and waiters are
woken after it. An acquire that may wait is for below `DISPATCH_LEVEL`;
the queries and an acquire that does not wait work at `DISPATCH_LEVEL`
too. The critical region is the caller's to enter, as for a push lock.

The lock of a stream's FCB header is the file system's too: the push
lock in the header, or in an old header the fast mutex it points to.
`FsRtlTeardownPerStreamContexts` (`kernel/io/fsrtl.rs`) takes it, in a
critical region it enters itself, only to unlink one context at a
time; it holds neither while the context's `FreeCallback` runs, and
takes no ranked lock inside it.

NK's own rules above are not applied to drivers. A driver that moves the
IRQL the wrong way gets what a normal Windows build gives it: the move.
NK also prints an `NK-VERIFY` line, which fails a test run. Where Windows
itself stops the system (freeing memory that is not a pool block, say),
so does NK, with the same bugcheck code.

### A device's queue

A device queue's lock (`KDEVICE_QUEUE.Lock`, `io::startio`) is a
driver's kind of spin lock, in the driver's device object: a driver's
cancel routine takes a waiting request out under it. NK takes it only
around linking and unlinking an entry, inside the cancel spin lock when
the driver's requests are cancellable and never the other way round,
and calls nothing while it is held.

## How it is tested

- `lib/ke`: the rules as pure functions (`Held`, `check_raise`,
  `check_lower`), the lock (`TicketLock`, host threads contending) and
  the wait register (every interleaving with several wakers).
- `ke.irql-and-locks`, `ke.interrupts`: on the booted kernel, the IRQL
  moves as stated, interrupts arrive once, at their level and in order of
  urgency, and nothing is left held. x86-64 runs x2APIC under KVM and
  xAPIC under emulation.
- `*-neg-lock-order`, `*-neg-lock-twice`, `*-neg-irql-lower`: boots that
  break a rule on purpose and must end in the bugcheck named above.
- `oracle.nkc-irql`: a conformance driver raises and lowers the IRQL,
  takes each kind of spin lock and allocates pool at `DISPATCH_LEVEL`;
  the values it reports are the ones it reported on Windows.
- Mutants (`tools/mutants/`): a lock that does not raise the IRQL, a
  rank check that accepts any order, no end-of-interrupt, an IRQL that
  does not move the GIC's mask, a driver lock that does not raise.
- `lib/ex`: the push lock's transitions, every interleaving of three
  threads; `ex.pushlock.*`: on the booted kernel a waiter is woken for
  each pairing of shared and exclusive, readers that waited get in
  together, and threads taking the lock every way at once keep a
  writer alone. Mutants: a releaser that wakes nobody, one that wakes
  a single reader.
- `lib/ex`: the resource's rules, and every interleaving of its
  hand-over; `ex.resource.*`: recursion both ways, a waiter of each
  kind let in as owner, the starving and yielding acquisitions, an
  owner table that grows, and contention. Mutants: a waiter let in
  but not woken, one woken but not recorded, a table grown without
  its owners.
