# The executive's locks, lists and timers

Part of NK's design ([DESIGN.md](../DESIGN.md)): the principles there apply.

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

An owner may pass what it holds to an owner pointer
(`ExSetResourceOwnerPointer`), an address with its low two bits set
that another thread later names to `ExReleaseResourceForThreadLite`:
a file system does so when its I/O completes elsewhere. If the pointer
already owns the resource shared, the two are one entry with both
counts.

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

### Run-down protection

[Run-down protection](https://learn.microsoft.com/en-us/windows-hardware/drivers/kernel/run-down-protection)
is one word of the driver's memory with Windows' values
(`nk_ex::rundown`): a count of holders, then, once the object is being
run down, the address of a block on the stack of the thread doing it.
That thread sleeps on an event in the block; each release counts the
block down and the last one sets the event. The word is left naming
the block, as on Windows, until the driver initialises it again. A
release after run-down with nobody waiting stops the system.

The cache-aware kind has a word a processor that is running, each on a
64-byte line; a thread uses the word of the processor it is on at that
moment, so a word may count below zero and only the sum means
anything. Running it down closes every word in turn and adds up what
they held. The header's layout and the size
`ExSizeOfRundownProtectionCacheAware` answers are the kernel's own,
which a driver that sets the memory aside itself relies on.

### Spin locks with readers, and lists under a spin lock

An `EX_SPIN_LOCK` is a `LONG` of the driver's memory with Windows'
bits (`nk_ex::spinlock`): the writer's bit, a count of readers, and a
note that somebody is spinning. Nobody queues. A writer claims its bit
first and then waits for the readers inside to leave, and new readers
wait for the writer, so a stream of readers cannot keep a writer out.

The `ExInterlocked...List` routines take the driver's `KSPIN_LOCK`
with the IRQL at `HIGH_LEVEL`, where Windows turns interrupts off, so
they can be called at any IRQL. `ExTryQueueWorkItem` always queues and
says so. `ExQueryTimerResolution` answers NK's one clock rate three
times.

### Callback objects and one-time initialisation

A [callback object](https://learn.microsoft.com/en-us/windows-hardware/drivers/kernel/callback-objects)
is an object of type `Callback`; the named ones live in `\Callback`.
Its body is a list of registrations, each a pool block holding a
reference to the object, all under one lock (`doc/LOCKING.md`). A
notification calls each routine with the lock dropped, at the caller's
IRQL, its registration counted busy so that unregistering waits for the
call to end. NK makes the three objects Windows has from the start
(`SetSystemTime`, `PowerState`, `ProcessorAdd`) and never notifies
them: nothing they report happens. A named object made without
`OBJ_PERMANENT` has no name, which is what Windows leaves of it too;
making one relative to a directory handle is refused.

`RtlRunOnceExecuteOnce` keeps Windows' values in the driver's word
(`nk_rtl::once`). A thread that finds the initialisation under way
sleeps a millisecond and looks again, where Windows queues it.

### Extension hosts and performance counters

`ExRegisterExtension` plugs a driver's table of routines into one of
the kernel's extension hosts (`kernel/ex/extension.rs`). Windows makes
sixteen at boot; NK makes the ones its drivers use, as Windows makes
them: `ksecdd.sys`'s authorization routines (id 2) and `cng.sys`'s
cryptography (id 3). A registration is checked as the pinned kernel
checks it (version, table, number of routines, a null routine, one
table per host). A host Windows has and NK does not stops the system
naming it; one Windows does not have either is `STATUS_NOT_FOUND`.
Nothing on NK calls a registered table yet.

The performance-counter routines (`Pcw*`, `kernel/ex/pcw.rs`) are
`pcw.sys`'s, reached on Windows through its extension host. With no
`pcw.sys` registered they give the status Windows gives then: not
implemented when the `pcw` service is to start (or has no key),
success with nothing registered when it is not.

### The time zone

Local time is UTC (`kernel/ex/timezone.rs`): Windows' bias comes from
the registry's `Control\TimeZoneInformation`, and NK's registry has
none, so the bias is zero as on Windows without that key. NK computes
no bias from a configured zone; a registry with one stops the system at
boot by name.
