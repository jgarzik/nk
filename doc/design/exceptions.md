# Exceptions

Part of NK's design ([DESIGN.md](../DESIGN.md)): the principles there apply.

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
| dispatch routine, for a request a driver sends (`IoCallDriver`, `IoSynchronousCallDriver`) | nothing: the request, and for `IoSynchronousCallDriver` the event in the sender's frame that its completion routine sets, are left to the driver that raised |
| dispatch routine, for a request the kernel sends to a stack and waits for (`io::stack::send_synchronous`) | nothing: the request, and the block its results go to, are left to the driver that raised |
| dispatch routine, for WMI's registration request | nothing: it is sent from a worker, whose base stops the system |
| dispatch routine, for a power request the power manager makes for a driver (`PoRequestPowerIrp`) | nothing: the request, and the power manager's record of it, are left to the driver that raised |
| a driver's power completion function (`PoRequestPowerIrp`) | nothing: the request stays as it is, and the device's later queries and sets wait behind it |
| a power setting callback | nothing: it is called from a worker, whose base stops the system |
| a component's active-condition callback (PoFx) | nothing: the component stays in its transition, which never finishes |
| a component's idle-condition callback (PoFx) | undo: the IRQL NK raised to `DISPATCH_LEVEL` for the call; the component stays in its transition |
| completion routine, cancel routine, a cancel-safe queue's callbacks | nothing: the cancel lock and its IRQL are the routine's to release, the queue's lock the driver's own |
| I/O work item's routine | undo: the device's reference |
| a driver's `AddDevice` (the Plug and Play manager) | base: a system thread |
| a Plug and Play notification callback | nothing: the registration's count of calls in progress stays raised, so it can no longer be taken back |
| boot driver's reinitialisation routine | base of the system thread: the queue's reference to the driver object is not given back |
| a driver's `StartIo`, and its cancel routine for a request already cancelled, from `IoStartPacket` | undo: the IRQL `IoStartPacket` raised |
| a driver's `StartIo`, from `IoStartNextPacket` | nothing: the caller's IRQL is its own; with deferred start the count of calls at work is left raised, and the device's queue stays where it is, as on Windows |
| a driver's `FastIoDetachDevice` (the device its own is attached to is being deleted) | nothing: the deleted device keeps the count taken for the call, and stays |
| silo monitor's create and terminate callbacks | undo: release the mutex that serialises monitors |
| silo context's cleanup routine | nothing: the context is left allocated, as Windows leaves it |
| work item's routine (from the worker), a system thread's start routine, `DriverEntry`, the unload routine, a library's `DllInitialize` and `DllUnload` | base: a system thread |
| DPC routine, a timer's included | base: kernel mode |
| interrupt service routine, a message's included | base: kernel mode |
| a DMA execution routine (adapter channel, scatter/gather list) | undo: the IRQL, if NK raised it to `DISPATCH_LEVEL` for the call |
| the routine of `KeSynchronizeExecution` | undo: release the interrupt's lock and restore the IRQL |
| an executive timer's callback, and a `KTIMER2`'s (from the timer's DPC) | base: kernel mode |
| an executive timer's delete callback | nothing: the timer is freed before it is called |
| a lookaside list's `Free` routine, for each block kept when the list is deleted | nothing: the blocks not yet handed over are left |
| a stream context's `FreeCallback` (`FsRtlTeardownPerStreamContexts`) | nothing: the context is off the header's list, and the header's lock and the critical region are given up before the call |
| a callback object's registered routine (`ExNotifyCallback`) | undo: the registration is no longer in use, so unregistering it does not wait for ever |
| a one-time initialisation routine (`RtlRunOnceExecuteOnce`) | undo: the `RTL_RUN_ONCE` is new again, so the threads waiting for it try in their turn |
| a range list's conflict callback (`RtlFindRange`, `RtlIsRangeAvailable`) | nothing: the search holds nothing, and the list is the caller's |
| an AVL table's compare, allocate and free routines | nothing: the table is the caller's, a new node is linked only after its routines have returned, and a deleted one is freed after it is unlinked |
| a query table's routine (`RtlQueryRegistryValues`) | undo: what the query holds, in one block: its copy of the table, the value lent to the routine, its count on the key |
| a system service made for user mode (the oracle's requests) | base: a system service |
| a hardware error source's `Initialize` (`WheaAddErrorSourceDeviceDriverV1`, `WheaAddErrorSource`) | undo: the source's count of calls in progress. The source stays started, as Windows leaves it |
| the `Correct` of a kind of hardware error source (`WheaAddErrorSource`) | nothing: the source is in the table, stopped, and stays |
| a hardware error source's `Uninitialize` (`WheaRemoveErrorSource`) | nothing: the source stays pending removal, closed to calls |
| the work item of a key's watcher (`ZwNotifyChangeKey`) | none of NK's: it is queued, and runs from a worker, whose base stops the system |
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
