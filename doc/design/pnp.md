# Plug and Play

Part of NK's design ([DESIGN.md](../DESIGN.md)): the principles there apply.

## Plug and Play

`kernel/pnp` is the Plug and Play manager; the rules it applies are
`lib/pnp`, tested on the host. What a driver sees is Windows': the
requests a device stack is sent and their order, `AddDevice`, the
resource lists a start carries, the keys under `Enum`. The rest is NK's.

**The tree.** One node per device (`pnp/node.rs`), NK's own structure,
found by the address of the device's physical device object. Windows'
`DEVICE_NODE` is private to its kernel, yet its drivers read its front:
`partmgr.sys` follows a disk's `DeviceNode` to its `Parent` and that
node's `PhysicalDeviceObject`. So each node has a `DEVICE_NODE` of
Windows' size (`nk_ntabi::pnp`, checked against the kernel's symbols),
a pool block the device extension's `DeviceNode` field points to, whose
tree links (`Sibling`, `Child`, `Parent`, `LastChild`) and device NK
keeps as nodes come and go, under the tree's lock; the rest of it is
zero, and NK never reads it back. The field is cleared before the block
is freed. The root is `HTREE\ROOT\0`, a device of
`\Driver\PnpManager` (`pnp/root.rs`).

**Reported devices.** A driver that detects its own device reports it
(`pnp::report_detected_device`; the export `IoReportDetectedDevice`,
which `volmgr.sys` calls, for a report without resources): the device
becomes `ROOT\<service>\0000`, a child of the root, with a physical
device object of the manager's. The reporting driver attaches its own
device and serves it; the manager adds no driver and sends no start,
and the interfaces the driver enabled meanwhile arrive when the device
counts as started (`volmgr.sys` enables its manager's interface in its
own `AddDevice`). A report that names resources, or hands back a device
of an earlier boot, stops the system by name. The HAL does this at boot, as on Windows
(`hal/bus.rs`): `ROOT\ACPI_HAL\0000`, on whose bus the HAL's driver
`\Driver\ACPI_HAL` enumerates `ACPI_HAL\PNP0C08\0`, the device the ACPI
driver serves. What those two devices answer is read from the pinned
kernel's HAL. The interrupts the ACPI device is offered follow Windows'
rule on x86-64 (`nk_hal::x86::acpi_device_interrupts`); on arm64, where
no kernel is pinned to read the rule or the hardware identifier from,
the device has neither. Windows' HAL hands three interfaces out of the
ACPI device (the standard bus interface, ACPI's CMOS interface, DMA
cache coherency); NK's hands out none.

**One piece of work at a time.** Everything the manager does to a
device is done by the thread that holds the engine's mutex
(`pnp/engine.rs`): the boot thread as it starts drivers, the engine's
own thread for what drivers ask for (`IoInvalidateDeviceRelations`
queues, wakes it and returns; `SingleBusRelations` is taken as
`BusRelations`, since NK asks only the device itself in either case),
a test. `pnp::settle` does all there is
to do and returns when nothing moves. Windows queues device actions for
one worker of its own in the same way. The engine's thread is not a
thread of the system's work queues: the engine waits for drivers with
its mutex held, and drivers complete what it waits for from work items
(`acpi.sys` completes a start so), so the work queues' threads must
never wait for the engine.

**A new device** is asked, in Windows' order (`PiProcessNewDeviceNode`):
its device identifier, capabilities, description and location text,
instance identifier, hardware and compatible identifiers, bus
information, resource requirements and boot configuration, and is then
told it has been enumerated. NK does not send the query for the
extended-address interface Windows sends after the capabilities. An
identifier is taken by Windows' rule (`PnpFixupID`: spaces become
underscores; a control character, a character above `0x7F`, a comma,
or the wrong number of backslashes refuses it) and a device whose
device or instance identifier is refused is left unstarted (problem
9). An answer a driver hands over is copied as far as its pool block
reaches and read from the copy, whatever lengths it states. The
instance path, the parent prefix for a bus whose children are not
unique (`ParentIdPrefix`, `NextParentID.<hash>.<depth>`), and the
hash behind it are Windows' (`nk_pnp::ids`, held to the reference
machine's values). The key gets the values the manager writes on
Windows; a device that cannot be removed is put in the machine's
container, one that can gets no `ContainerID` (Windows makes one from
its identifiers). Two devices with one instance path stop Windows; NK
leaves the second unstarted (problem 42).

**Finding the driver.** Windows installs a device once, from its INF,
in user mode, and at every later boot uses what installation left in
the device's key. NK's registry starts without the keys of enumerated
devices and NK runs no installer, so NK applies the driver database's
record the first time it sees a device (`pnp/registry.rs`): the first
hardware identifier, else the first compatible identifier, that has a
record under `DriverDatabase\DeviceIds` whose configuration does not
exclude the device, and from it the values installation writes
(`Service`, `ClassGUID`, `Driver`, `DeviceDesc`, `Mfg`, `ConfigFlags`),
the driver key under the class, and the configuration's `Device`
subtree copied into `Device Parameters` (where `pci.sys` looks for
`MSISupported`). Differences: the text behind the `;` of `DeviceDesc`
and `Mfg` is the bus's description or empty, because the INF's strings
are not in the database; the configuration's `Services` subtree is not
merged into the service key; ranking is by position only (Windows also
weighs signature and date). A device with a key already (a `ClassGUID`,
a `Driver`, or for an enumerated device a `Service`) is not installed
again. A device just installed is asked for its resource requirements
again: a bus driver may build them from the settings installation put
in the device's key, as `pci.sys` does for message-signalled
interrupts, and on Windows those were there when it was first asked.

**The stack.** Lower filters of the device, then of its class; the
service; upper filters of the device, then of its class. Each driver's
`AddDevice` is called from the base of a system thread. While
boot-start drivers are being started, a device whose drivers are not
all running waits and is looked at again after each driver's entry
(Windows does the same per boot driver); afterwards a driver is loaded
when a device needs it. A device with no driver is started raw if its
bus says it may be (`RawDeviceOK`), else left with problem 28.
A filter whose service has no image is left out of the stack, with a
line in the log; Windows fails the device ([What is absent](absent.md)). A driver
whose entry failed is not tried again (problem 37); a failed
`AddDevice` has the devices attached so far removed (problem 31).

**Resources.** The stack filters the requirements
(`IRP_MN_FILTER_RESOURCE_REQUIREMENTS`, sent as Windows sends it:
successful, holding the list). NK then chooses itself
(`nk_pnp::assign`), where Windows asks arbiters: one table of claims
for the machine; a device's ancestors do not stand in its way; each
requirement gets its first choice that can be had, at the boot
configuration if the choice allows it, else at the lowest free place;
a boot configuration is kept for its device until the device is
assigned, and gives way only to a requirement that names one place
(as Windows' arbiters let a fixed requirement overlap a boot
allocation). A line interrupt is given only where the requirement names
one line or firmware configured one: NK asks no bus driver's arbiter or
translator interface. Translation: memory, ports and bus numbers are
what they are; an interrupt gets its vector from the hardware layer
(`hal::interrupt::translate`, a line by its number, messages by their
count) and is recorded for `IoConnectInterruptEx`
(`io::interrupt::assign`), and how each is delivered (a line's number
and signalling, a message's address and data) is put in the device's
interrupt connection data, the property `pci.sys` reads to program a
device's messages; the interrupts of the HAL's own child are
vectors already and stay as stated, as the reference Windows records
them. The start carries the raw and the translated list; `Control`
gets `AllocConfig` and `FilteredConfigVector`, and the service's `Enum`
key the device.

**After the start** the capabilities are asked again and the device
state; a device its drivers call failed, disabled or removed is taken
down (problem 43). A failed start has the stack told the device is
removed, so that its drivers detach and delete what they attached, and
what it was given is taken back (problem 10). Then the device is asked
for its children; new ones get a node and `DO_BUS_ENUMERATED_DEVICE`,
those no longer reported are told they are gone in two phases, matching
Windows: `IRP_MN_SURPRISE_REMOVAL` is sent bottom-up across the
disappeared subtree (disabling its interfaces and moving each node to
`State::SurpriseRemoved`), and `IRP_MN_REMOVE_DEVICE` is deferred for
any node whose device stack still holds open references
(`ReferenceCount > 0`) until the last handle closes and the engine
thread completes teardown. That, the removal after a failed
start, and `pnp::remove_reported_device` are the only removals: there
is no query-remove, no eject, no stop and no rebalance.

**What drivers call** (`pnp/export.rs`, `pnp/interface.rs`,
`pnp/notify.rs`). A device's properties (`IoGetDeviceProperty`) come
from its node and its key; `IoOpenDeviceRegistryKey` opens its
`Device Parameters` key or its driver key. A property set with
`IoSetDevicePropertyData` is kept in the key where Windows keeps it and
read back by `IoGetDevicePropertyData`. Of the properties Windows
computes, NK answers those Microsoft's binaries ask of a disk:
`DEVPKEY_Device_ClassGuid`, `_BusNumber` and `_Address` (from what
`IoGetDeviceProperty` answers) and `DEVPKEY_Device_Parent` (the
parent's instance path); any other is not found unless a driver set
it. A
device interface is registered under Windows' link name and
`DeviceClasses` record; enabling it makes the symbolic link to the
physical device object (which therefore needs a name) and queues the
callbacks registered for the class's arrivals onto an executive worker
thread (matching Windows, while `PNPNOTIFY_DEVICE_INTERFACE_INCLUDE_EXISTING_INTERFACES`
delivers existing interfaces synchronously before registration returns);
enabled before its device has
started, an interface waits for the start. Disabling one answers
success whatever came of it, as Windows' routine does: `partmgr.sys`
disables an interface it never enabled on each disk it starts. A
registration for a device's changes names a file; the device is what
the file's stack answers `TargetDeviceRelation` with, as on Windows,
held by the registration. A custom event a driver reports for a device
(`IoReportTargetDeviceChangeAsynchronous`; `mountmgr.sys` reports a
volume's new names) is copied and told, from a worker, to every
registration for that device, each with its own file in the
structure, and then the reporter's routine is called; the call answers
`STATUS_PENDING`. One of the predefined removal events is refused as
Windows refuses it. When a device is finally removed, NK queues a
`GUID_TARGET_DEVICE_REMOVE_COMPLETE` notification on an executive worker
thread for every `EventCategoryTargetDeviceChange` registration targeting
that physical device object. Notification registrations for hardware
profile changes are never called: NK has one hardware profile.
`IoInvalidateDeviceState` has a started device asked for its state
again by the worker. Dependencies between devices
(`IoReserveDependency`, `IoResolveDependency`, `IoSetDependency`;
`pnp/depend.rs`, rules in `nk_pnp::depend`) are kept, and a device's
drivers are not added while a device it depends on is unbound or not
started (problem 51); NK treats the two kinds of dependency alike and
derives no power relations from them.
