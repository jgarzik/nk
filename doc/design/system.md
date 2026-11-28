# The system as a whole

Part of NK's design ([DESIGN.md](../DESIGN.md)): the principles there apply.

## Questions about the system

`kernel/ex/sysinfo.rs`, with the length rules in `nk_ex::sysinfo`.

`ZwQuerySystemInformation` and `NtQuerySystemInformation` are one
routine: every caller is in kernel mode. It answers the classes the
binaries NK runs ask for; any other is `STATUS_INVALID_INFO_CLASS`.
Lengths, and what is reported as the length needed, are the pinned
kernel's, class by class.

`ZwSetSystemInformation` takes two classes. `acpi.sys` sets the
registration of a firmware table provider (75), kept by the pinned
kernel's rules with a reference to the provider's driver object
(`kernel/ex/firmware.rs`, `nk_ex::firmware`). Nothing asks a provider
for a table: the class that would is not among those answered.
`cng.sys` registers its routine for the times of interrupts (0x83,
[Processors](processors.md), Interrupts). Any other class set stops
the system naming it.

| Class | Answer |
| --- | --- |
| 0, basic | page size, 64 KiB granularity, Windows' user range, the processors running, the memory NK uses as RAM |
| 11, modules | the images in memory (below) |
| 35, kernel debugger | enabled and present with `debug=on`; else neither |
| 0x75, boot entropy | the head of the loader's entropy block, once; `STATUS_UNSUCCESSFUL` after (`doc/BOOT.md`, Boot entropy) |
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

`NtQuerySystemInformationEx` (`kernel/ex/sysinfo_ex.rs`, rules in
`lib/ex/sysinfo_ex.rs`) takes the classes that come with an input.
Two are answered: the processor relationships a driver asks for by
kind, of which NK states the NUMA node and the group (one of each,
holding every running processor; cores, caches and packages are not
stated), and whether interrupts are steered between processors, which
they are not. Any other class, and any other part of these two, stops
the system naming it.

## Firmware variables

`pshed.dll` keeps hardware error records in firmware variables.
`NtGetEnvironmentVariableEx`, `NtQueryEnvironmentVariableInfoEx`,
`HalEnumerateEnvironmentVariablesEx` and `HalSetEnvironmentVariableEx`
(`kernel/hal/variables.rs`) are UEFI's variable services
(`GetVariable`, `QueryVariableInfo`, `GetNextVariableName`,
`SetVariable`), called like the shutdown: in the kernel's address
space, with the caller's buffers. What Windows adds is kept
(`nk_hal::variables`): the firmware's status becomes the status of the
pinned kernel's table; a variable must be non-volatile and is given
both access bits; a write deletes the variable first; the name is
copied to a buffer of 256 characters; an enumeration is laid out as
`VARIABLE_NAME` or `VARIABLE_NAME_AND_VALUE` entries, and says the
size it needs. UEFI forbids entering the services twice at once: one
lock is held across each call, where Windows keeps such calls on the
boot processor. The `Nt` routines are for kernel mode alone on
Windows; NK's have no other caller.

## Hardware errors

WHEA is Windows' path for hardware errors: a *source* reports them, the
kernel makes a record of each. NK keeps the sources (`kernel/whea`;
the rules and sizes are `lib/whea`, taken from the pinned kernel's
code).

- A driver registers as a source with
  `WheaAddErrorSourceDeviceDriverV1`. NK builds the descriptor Windows
  builds (type 16, version 11, the kernel's two sections added to the
  driver's, the report packets preallocated), gives the source the next
  id, counting from zero, marks it started and calls the driver's
  `Initialize(Context, ErrorSourceId)` before returning, at the
  caller's IRQL with no lock held. The status of `Initialize` is the
  routine's.
- A source whose `Initialize` fails is left by Windows stopped, in a
  table nothing looks stopped sources up in. NK frees it; its id is not
  used again.
- A descriptor is a pool block of exactly the descriptor's size, which
  `WheaGetErrorSource` hands out for a started source. What NK decides
  by (state, calls in progress, context) is in its own table; the state
  in the descriptor is a copy for drivers to read.
- `WheaRemoveErrorSource` waits for the calls into the source to end,
  calls `Uninitialize(Context)` and leaves the descriptor allocated in
  the removed state, as Windows does. The packets NK allocated for a
  device driver's source are freed there: NK's table records which
  those are, and the packet pointers in a descriptor a driver brought
  to `WheaAddErrorSource` are never freed.
- NK has no firmware or platform sources: the first source a driver
  adds has id 0.
- A source of another kind is added with `WheaAddErrorSource`. Its
  routines are those `WheaConfigureErrorSource` recorded for its kind:
  `Correct(Descriptor, SectionLength)` and
  `Initialize(1, Descriptor, Context)` when it is added,
  `Uninitialize(Context)` when it is removed; a kind not configured
  has none and its sources start with nothing called. The kinds the
  firmware's tables describe are refused, as on Windows.
- A device driver reports an error with
  `WheaReportHwErrorDeviceDriverEx`. The report is held to the limits
  the source registered with, an error record is made (the header of
  `WheaInitializeRecordHeader`, the source's GUID, creator and
  partition, one section: the driver's data, with the device's name),
  and its summary is printed: NK has no event log, and does not keep
  the record or the log data. Windows' record carries sections of its
  own besides; NK's does not.
- `WheaReportFatalHwErrorDeviceDriverEx` does the same and stops the
  system with `0x124 WHEA_UNCORRECTABLE_ERROR`: the source's type, the
  record, the source's GUID, the driver's word.
- `WheaReportHwError` judges a packet as Windows does before a record
  is made: a malformed severity is refused, an informational report
  dropped, a report from no started source stops the system
  (`0x122 WHEA_INTERNAL_ERROR`) when it is recoverable or fatal and is
  `STATUS_DEVICE_DOES_NOT_EXIST` otherwise. For a started source the
  record would come from its kind's `CreateRecord`, which NK does not
  call: the system stops naming the kind.
- Reports are made at or below `DISPATCH_LEVEL`: the table's lock and
  the pool are that high and no higher.
- `pshed.dll`, the platform's part of the error path, is loaded as a
  library for what `pci.sys` imports from it. NK does not call its
  `PshedInitialize`, which takes Windows' loader block, nor any other
  of its routines. The first call of `PshedInitialize` reads two
  things of the block: whether the firmware is UEFI (the first byte of
  `FirmwareInformation`) and the memory descriptor list, searched for
  a descriptor of type 0x1C; the second call goes on to the firmware's
  error tables (the boot error record table through
  `HalGetCachedAcpiTable`, which NK provides) and the error sources.
  Until both are made, `PshedGetErrorSourceInfo` waits on an event the
  first call would have initialised. `pci.sys` calls it only for a PCI
  Express port with advanced error reporting, which the machines NK's
  tests run on do not have.
- `HalBugCheckSystem` (`kernel/hal/fatal.rs`), which `pshed.dll` calls
  for a fatal error, stops the system as Windows does: by the record's
  first section that is an NMI not the hypervisor's
  (`0x80 NMI_HARDWARE_FAILURE`) or a machine check
  (`0x124 WHEA_UNCORRECTABLE_ERROR`: the source's type, the record, the
  two halves of the bank's status), and with `0x124` and no status for
  a record with neither.

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

## Debug messages

`DbgPrint` goes to the console, prefixed `DbgPrint:`. `DbgPrintEx` and
`vDbgPrintExWithPrefix` go there too when the component filter lets
them through (`lib/rtl/dbgfilter.rs`): at boot, as on Windows, only
messages at the error level; `DbgSetDebugFilterState` changes a
component's mask. `DbgCommandString` does nothing, as with no debugger.
`DbgPrompt` is a breakpoint (next section); when it is passed over the
response is empty.

`__chkstk` (`kernel/arch/*/chkstk.rs`) probes each page of the stack a
function is about to take. Kernel stacks are committed whole, so the
probe finds every page there or lands in the unmapped stretch below
the stack, which is a stack overflow.

## Breakpoints and the debugger

A driver's breakpoint (`DbgBreakPoint`, in-line code) gets one of
Windows' two answers. By default, as with no debugger: an exception,
`0x80000003`, which stops the system unless a handler takes it (bugcheck
`0x7E` in a system thread). With `debug=on` on the command line, as with
a debugger that says "go" every time: noted on the console and passed
over, before any handler is asked. NK has no debugger protocol; the reference
Windows machine gets a real debugger, played by `tools/kd.py`.

What a driver asks of the debugger (`kernel/kd/debugger.rs`) is
answered as Windows answers with a debugger never set up:
`KdDisableDebugger` and `KdEnableDebugger` are
`STATUS_DEBUGGER_INACTIVE`, and `KdPowerTransitionEx` succeeds at once.
The debugger's lock (`KdAcquireDebuggerLock`) is a real spin lock, and
power handlers register and deregister (`lib/ke/kdpower.rs`); no
transition calls them.
