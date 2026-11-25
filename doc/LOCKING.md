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
| `HIGH_LEVEL` | 15 | | | the DPC-queue and console locks; the bugcheck path |

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
| 25 | `io::device::DATABASE` | every device's reference count, delete-pending mark and security descriptor pointer; each driver's list of devices | DISPATCH |
| 30 | `ob::NAMESPACE` | the namespace's directories and entries; each named object's name information | DISPATCH |
| 33 | `cm::HIVE` | the registry's keys and values | DISPATCH |
| 35 | `ob::handle::TABLE` | which object each kernel handle names | DISPATCH |
| 40 | `mm::pool::POOL` | pool arenas and large allocations | DISPATCH |
| 50 | `mm::map::NEXT_VA` | kernel address space and page-table edits | DISPATCH |
| 60 | `mm::FRAMES` | the frame bitmap | DISPATCH |
| 200 | `ke::ipi::CALL` | the interprocessor call in progress | DISPATCH |
| 210 | a work queue (`ex::work`) | the work items waiting for a worker thread | DISPATCH |
| 220 | a processor's ready queues (`ke::thread`) | which threads are ready there, their links, state and priority while queued | DISPATCH |
| 230 | a processor's timer table (`ke::timer`) | which timers are pending there, and when | DISPATCH |
| 240 | a processor's DPC queue (`ke::dpc`) | the DPCs waiting to run there | HIGH |
| 245 | `ldr::MODULES` | which image an address is in | HIGH |
| 250 | `kd::CONSOLE` | the diagnostic UART | HIGH |

Why this order:

- A device's reference count and its delete-pending mark change only
  under the I/O database lock, so "the last reference went" and "the
  device was deleted" are seen together by whichever comes second. That
  one frees the device, after dropping the lock.
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
- The registry's lock is held only around a look-up or a change of the
  tree; a key handle is resolved before it is taken and the driver's
  memory is read and written outside it.
- The tables above the pool hold `Vec`s, which allocate from the pool
  while the table's lock is held. An object's last reference is never
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
- A timer table's lock owns a pending timer's links, due time,
  processor and `Inserted` bit. Expiry holds it while it takes a due
  timer out and puts a periodic one back, then drops it before queueing
  the timer's DPC. No two tables are held together: a timer moves from
  one processor's table to another's by leaving the first under its lock
  and entering the second under its own.
- A DPC is queued from any IRQL, an interrupt handler's included, so the
  queue's lock is held at `HIGH_LEVEL` and nothing but the console is
  taken inside it. No DPC routine runs with it held.
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

The locks at ranks 10 to 30 protect data that Windows guards with locks a
thread can sleep on. Spin locks stand in for those; they are stricter,
never looser.

`force_lock` takes a lock regardless, without bookkeeping. Only the
path that stops the system uses it, on the console and on the table of
loaded images, and never returns.

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
  of the one before it, or frees it if it exited. A thread never frees
  its own stack.

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
locks are in the driver's memory and are not ranked or recorded. Nothing
holds two, with one exception: a wait for all of several objects holds
all their locks at once while it looks and takes, locking in order of
address and unlocking in reverse.

Every object-manager object has another lock of its own, the `Lock`
word of its header, which covers the header's security descriptor
pointer (`ob::security`). It is held at `DISPATCH_LEVEL` for a pointer
read or swap and a count, takes nothing inside, and is not ranked or
recorded; a replaced descriptor is freed after it is dropped.

For a timer the lock also serialises setting and cancelling. Expiry
takes the timer out under the table's lock, lets go, and only then takes
the timer's own lock to signal it; a timer that was set again in
between is left alone.

A mutex's lock also covers its owner and its place in the owner's list
of mutexes held. A thread being let in to a mutex while it sleeps has
its list and its APC-disable count changed on its behalf by the
releasing thread, under that mutex's lock; otherwise only a thread
itself changes them.

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

NK's own rules above are not applied to drivers. A driver that moves the
IRQL the wrong way gets what a normal Windows build gives it: the move.
NK also prints an `NK-VERIFY` line, which fails a test run. Where Windows
itself stops the system (freeing memory that is not a pool block, say),
so does NK, with the same bugcheck code.

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
