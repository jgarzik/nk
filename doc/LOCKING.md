# Locking

How NK protects its own data. Changing a lock, or adding one, changes
this file in the same commit.

## IRQL

Every processor runs at an interrupt request level (IRQL). Code at one
level is not interrupted by anything that runs at that level or below on
the same processor. The levels NK uses so far:

| Level | Value | What runs there |
| --- | --- | --- |
| `PASSIVE_LEVEL` | 0 | ordinary code: driver entry, dispatch routines, the tests |
| `DISPATCH_LEVEL` | 2 | code holding a spin lock |
| `HIGH_LEVEL` | 15 | code holding the console lock; the path that stops the system |

On x86-64 the IRQL is register CR8, because code built with the WDK reads
it there. On arm64 drivers call the kernel for it, and it is a field of
NK's per-processor state.

The interrupt controller enforces it. An interrupt runs at an IRQL of its
own, and the controller holds back every interrupt whose IRQL is not
above the current one:

- x86-64: the local APIC. A vector's IRQL is its upper four bits, as on
  Windows, and CR8 is the APIC's task priority, so setting the IRQL is
  setting the mask. A driver that writes CR8 itself gets the same effect.
- arm64: the GIC. An interrupt at IRQL `n` has priority `0xF0 - 0x10*n`,
  and setting the IRQL writes that value for the new level to the
  priority mask.

Interrupts are enabled from early boot on and never disabled to protect
data; raising the IRQL is how code keeps interrupts out. A handler runs
at its interrupt's IRQL with interrupts enabled, so only something more
urgent can preempt it; the controller is told the interrupt has finished
before the IRQL comes back down (`kernel/ke/interrupt.rs`).

The rules (`kernel/ke/irql.rs`, checked on every change):

- `raise` goes up or stays; `lower` goes down or stays. The reverse is a
  bugcheck: `IRQL_NOT_GREATER_OR_EQUAL` (0x9), `IRQL_NOT_LESS_OR_EQUAL`
  (0xA).
- A driver is loaded and unloaded at `PASSIVE_LEVEL`; doing it with the
  level raised is a bugcheck (0xA).
- Every test group must end at the level it started.

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
| 20 | `ldr::LOADED` | table of loaded images | DISPATCH |
| 30 | `ob::NAMESPACE` | device names and symbolic links | DISPATCH |
| 40 | `mm::pool::POOL` | pool arenas and large allocations | DISPATCH |
| 50 | `mm::map::NEXT_VA` | kernel address space and page-table edits | DISPATCH |
| 60 | `mm::FRAMES` | the frame bitmap | DISPATCH |
| 200 | `ke::ipi::CALL` | the interprocessor call in progress | DISPATCH |
| 220 | a processor's ready queues (`ke::thread`) | which threads are ready there, their links, state and priority while queued | DISPATCH |
| 230 | a processor's timer table (`ke::timer`) | which timers are pending there, and when | DISPATCH |
| 240 | a processor's DPC queue (`ke::dpc`) | the DPCs waiting to run there | HIGH |
| 250 | `kd::CONSOLE` | the diagnostic UART | HIGH |

Why this order:

- The three tables at the top hold `Vec`s, which allocate from the pool
  while the table's lock is held.
- The pool and the address space each take frames while holding their own
  lock (a new arena; a new page table). They never take each other.
- An interprocessor call may be made with any of the above held:
  unmapping a page holds the address-space lock while every processor
  drops the translation. The call lock is held at `DISPATCH_LEVEL`, below
  the interprocessor interrupt, so a processor waiting for it still
  answers the call in progress. A routine run by a call takes no lock
  below rank 200: its caller may hold any of them.
- A timer table's lock owns a pending timer's links, due time,
  processor and `Inserted` bit. Expiry holds it while it takes a due
  timer out and puts a periodic one back, then drops it before queueing
  the timer's DPC. No two tables are held together: a timer moves from
  one processor's table to another's by leaving the first under its lock
  and entering the second under its own.
- A DPC is queued from any IRQL, an interrupt handler's included, so the
  queue's lock is held at `HIGH_LEVEL` and nothing but the console is
  taken inside it. No DPC routine runs with it held.
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
thread can sleep on. Spin locks stand in until threads can block; they
are stricter, never looser.

`force_lock` takes a lock regardless, without bookkeeping. Only the
bugcheck path uses it, on the console, and never returns.

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

A `KTIMER` has a lock of its own, bit 7 of its header's type byte, as on
Windows. It is taken at `DISPATCH_LEVEL` before any ranked lock, and
serialises setting and cancelling one timer. Expiry does not take it:
what expiry touches belongs to the table's lock. These locks are in the
driver's memory and are not ranked or recorded; nothing holds two.

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

NK's own rules above are not applied to drivers. A driver that moves the
IRQL the wrong way gets what a normal Windows build gives it: the move.
NK also prints an `NK-VERIFY` line, which fails a test run. Where Windows
itself stops the system (freeing memory that is not a pool block, say),
so does NK, with the same bugcheck code.

## How it is tested

- `lib/ke`: the rules as pure functions (`Held`, `check_raise`,
  `check_lower`) with unit tests of every violation, and the lock itself
  (`TicketLock`) with eight threads contending on the build host.
- `ke.irql-and-locks`: on the booted kernel, raising, lowering and nested
  locks move the IRQL as stated and leave nothing held.
- `*-neg-lock-order`, `*-neg-lock-twice`, `*-neg-irql-lower`: boots that
  break a rule on purpose and must end in the bugcheck named above.
- `ke.interrupts`: a processor interrupts itself and checks that the
  interrupt arrives once and at its IRQL, a second one arrives after it,
  one sent while the IRQL is raised waits until it is lowered, a more
  urgent interrupt preempts a handler and a less urgent one waits for it,
  and an interrupt nothing handles is counted and survived. x86-64 runs
  it in x2APIC mode under KVM and xAPIC mode under emulation. Mutants: no
  end-of-interrupt (each architecture), a handler left at the interrupted
  code's IRQL, and an IRQL that does not move the GIC's mask.
- Mutants: a lock that does not raise the IRQL, and a rank check that
  accepts any order.
- `oracle.nkc-irql`: the conformance driver `nkc-irql` raises and lowers
  the IRQL, takes each kind of spin lock and allocates pool at
  `DISPATCH_LEVEL`; the 29 values it reports must be the ones it reported
  on Windows. Mutants: a driver lock that does not raise the IRQL, and a
  try that always succeeds.
