# Power

Part of NK's design ([DESIGN.md](../DESIGN.md)): the principles there apply.

## Power

The machine is on and stays on: the system is in S0 and every device in
D0, always. NK never sleeps, hibernates, powers a device down for
being idle, or wakes. What is left of a power manager is what a driver
must be able to ask of one and get Windows' answer to (`kernel/po`;
rules in `lib/po`).

**Power requests.**
[`PoRequestPowerIrp`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-porequestpowerirp)
builds a request as the pinned kernel does: an IRP one stack location
deeper than the stack, whose topmost location is the power manager's
own, starting out as `STATUS_NOT_SUPPORTED`, sent to the top of the
stack. A wait-wake is sent at once and stays where the bus driver
holds it: nothing on NK ever wakes, and the driver that asked cancels
it with `IoCancelIrp`. Queries and sets of a device's power state are
sent to one stack one at a time, in the order asked for; the next goes
down from the thread that completed the one before, after that one's
completion function has run. The power manager's completion routine
calls the driver's completion function at whatever IRQL the request was
completed, and frees the IRP. A stack whose bottom device has no device
node (`DEVOBJ_EXTENSION.DeviceNode`, the Plug and Play manager's) is
refused, as on Windows. NK runs no watchdog on a request
(`PoQueryWatchdogTime` says so), and there is no platform extension to
tell.

Windows sends a device no power request when it is started: a driver
is in D0 when its start request arrives and says so itself
(`PoSetPowerState`). The state a driver reports is recorded where
Windows records it, in the device object's `PowerFlags`, and nobody is
told, as nobody is by the pinned kernel. What else the power manager
keeps about a device is in a block of NK's own that the extension's
`Dope` points to, as Windows' own block is; it goes with the device
object's memory.

**Power settings.** A driver registers for a setting by GUID
([`PoRegisterPowerSettingCallback`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-poregisterpowersettingcallback))
and Windows calls it, from a worker thread, with the value the setting
has. Two settings have a value on NK, the two the pinned kernel itself
sets as it starts: the power source is AC, the console's display is on.
Every other setting gets its value on Windows from something NK lacks
(the power scheme, which user mode's power service applies; the
platform's idle driver; a session), so a registration for one is kept
and never called, which is Windows' behaviour for a setting that has
not been given a value. No setting changes, so no callback is called
twice. Taking a registration back waits for its callback if another
thread is in it.

**The runtime power framework (PoFx).** A driver registers a device
as a set of components
([`PoFxRegisterDevice`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-pofxregisterdevice),
all three versions of the description), and says when it uses each and
when it has stopped. NK counts as Windows does and tells the driver in
the same order (`lib/po/fx.rs`): a component is registered active with
one activation, which `PoFxStartDevicePowerManagement` gives up; when
the last activation goes the idle-condition callback is made, at
`DISPATCH_LEVEL` as the pinned kernel makes it, and the component is
idle once the driver has called `PoFxCompleteIdleCondition`; the first
activation of an idle component makes the active-condition callback, in
the caller's thread before the call returns, or from a worker thread
when the caller asks (`PO_FX_FLAG_ASYNC_ONLY`) or when the activation
had to wait for an idle transition to finish. One transition of a
component is under way at a time. A blocking call waits for the
component to be at rest.

That is where NK stops. A component stays in F0 and a device in D0:
`ComponentIdleStateCallback`, `DevicePowerNotRequiredCallback`,
`DevicePowerRequiredCallback` and the directed power callbacks are
recorded and never called, and the idle timeout, latency, residency and
watchdog callback a driver sets are recorded and never acted on.
Completing what NK never asked for stops the system with the bugcheck
the pinned kernel raises for it. There is no platform extension (PEP),
and what a driver asks of one gets the pinned kernel's answer with
none: a power control request is not supported, no crash dump device
can be registered, performance states the extension must supply or
handle are not implemented. Performance states a driver manages itself
and dependencies between components (providers) stop the system,
naming themselves. The Plug and Play manager's own activations of a
device around enumeration, which on Windows keep it in D0, are not
made.

The framework accepts a device only once the Plug and Play manager has
begun to start it, as on Windows (`po::fx::prepare_device`, called
before the start request; `po::fx::abandon_device` on removal takes
away a registration its drivers left behind).

**Registered and never acted on.** Coalescing callbacks
(`PoRegisterCoalescingCallback`: Windows coalesces I/O only in the
platform's low-power idle state), a device's flags for that state
(`PoDirectedDripsSetDeviceFlags`, and the two internal requests of
`ZwPowerInformation` through which `storport.sys` sets and clears
them) and the reasons a sleep state is unavailable
(`ZwPowerInformation`, `SystemPowerLoggingEntry`: `acpi.sys` logs one
for each sleep state the firmware lacks; one entry a reason, a second
refused, `nk_po::logging`).

**Power information** (`ZwPowerInformation`, `kernel/po/mod.rs`). The
platform is not always on, always connected (`PlatformInformation`),
so the question whether a device would keep it out of the low-power
idle state is not supported (`QueryPotentialDripsConstraint`, asked by
`pci.sys` as it starts a device), and the notice that the firmware's
tables can be read (`FirmwareTableInformationRegistered`, from
`acpi.sys`) changes nothing: Windows reads from them again whether the
platform has that state. Any other level stops the system, naming
itself.

**Shutting down.** A driver's request for a shutdown that ends with
the power off (`ZwInitiatePowerAction`: `acpi.sys`, for the power button
and for a critical temperature) powers the machine off at once, by the
path the kernel ends a run by: there is no user mode to ask and nothing
to flush. That path first sends `IRP_MJ_SHUTDOWN` to the devices
registered for it (`io::shutdown`), to the top of each one's stack, one
at a time and waited for, newest first: the
`IoRegisterShutdownNotification` queue; then each file system
registered on the disk, CD-ROM and tape queues, the queues looked at
afresh each time since a file system unregisters as it shuts down, as
Windows' `IopShutdownBaseFileSystems` does, after which nothing mounts;
then the last-chance queue ([I/O](io.md)). A device deleted
while registered leaves its queue. What the pinned kernel refuses outright is refused; every
other action is its policy manager's, which NK lacks, and stops the
system naming the action.

**Absent.** Hibernation: `PoSetHiberRange` stops the system with the
bugcheck the pinned kernel raises when it is called and no hibernation
is in progress. An ordered shutdown before a bugcheck:
`PoShutdownBugCheck` stops at once with the code it is given. Thermal
requests are traps.

The tests `po.*` run a bus driver and a function driver of their own:
requests of each kind go down their stack and come back to the
completion function, a held set keeps the next query waiting, a
wait-wake is marked and cancelled; settings callbacks are registered,
called and taken back, from another thread and from inside; a
device is registered with the framework in each version, and its
components activated and idled with the callbacks, their order, thread
and IRQL checked.
