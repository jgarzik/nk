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
NK's per-processor state. Nothing generates interrupts yet, so today the
level has only the kernel's own checks behind it.

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
(`ke::percpu::PerCpu`). That state is touched only at `DISPATCH_LEVEL` or
above, where nothing else on the processor can interleave.

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
| 250 | `kd::CONSOLE` | the diagnostic UART | HIGH |

Why this order:

- The three tables at the top hold `Vec`s, which allocate from the pool
  while the table's lock is held.
- The pool and the address space each take frames while holding their own
  lock (a new arena; a new page table). They never take each other.
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
thread can sleep on. Spin locks stand in until threads exist; they are
stricter, never looser.

`force_lock` takes a lock regardless, without bookkeeping. Only the
bugcheck path uses it, on the console, and never returns.

## How it is tested

- `lib/ke`: the rules as pure functions (`Held`, `check_raise`,
  `check_lower`) with unit tests of every violation, and the lock itself
  (`TicketLock`) with eight threads contending on the build host.
- `ke.irql-and-locks`: on the booted kernel, raising, lowering and nested
  locks move the IRQL as stated and leave nothing held.
- `*-neg-lock-order`, `*-neg-lock-twice`, `*-neg-irql-lower`: boots that
  break a rule on purpose and must end in the bugcheck named above.
- Mutants: a lock that does not raise the IRQL, and a rank check that
  accepts any order.
