# Tracing

Part of NK's design ([DESIGN.md](../DESIGN.md)): the principles there apply.

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
  back. It goes to the top of the stack the device is in, as on
  Windows.
- The answer is checked as Windows checks it, and of it the names of
  the data blocks are kept; the references a driver takes on physical
  device objects for WMI when it answers the newer request are given
  back.
- [`IoWMIOpenBlock`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-iowmiopenblock)
  for a block no registered device names answers
  `STATUS_WMI_GUID_NOT_FOUND`, as Windows answers an open for query of
  such a block (`acpi.sys` asks for one). A block that is registered
  cannot be queried: that open, and an open for events, stop the
  system by name, and the export is `Partial`. `IoWMIQueryAllData` and
  `IoWMIExecuteMethod` take the object an open gives, of which NK gives
  none; they stay traps.
- `WMIREG_ACTION_UPDATE_GUIDS` sends the request again, marked as an
  update; `WMIREG_ACTION_BLOCK_IRPS` ends the sending. Deregistering
  drops what waits for the device, waits for a request that is with the
  driver, and gives the device back.
- An action with `WMIREG_FLAG_TRACE_PROVIDER` and the trace-notification
  bits (`partmgr.sys`, `volmgr.sys`) is taken without them, as the
  pinned kernel takes it: the device registers as any other, and no
  session ever enables it. A registration by callback
  (`WMIREG_FLAG_CALLBACK`) is how WPP registered before
  `EtwRegisterClassicProvider`. NK does not take it:
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

`EtwWrite` is `EtwWriteTransfer` without a related activity, and
`EtwEventEnabled` is false: no session takes any event.
`WmiTraceMessageVa` answers as `WmiTraceMessage`. `EtwActivityIdControl`
makes activity ids (`lib/etw/activity.rs`: this boot's base and a
count); the codes that read or set the calling thread's id are
`STATUS_NOT_SUPPORTED`, as Windows answers a system thread, whose id
would live in a TEB it does not have.
