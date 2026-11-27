# I/O

Part of NK's design ([DESIGN.md](../DESIGN.md)): the principles there apply.

## I/O

Driver, device and file objects are object-manager objects of exactly
their Windows size, and IRPs pool allocations of theirs; all are reached
by raw pointer. An IRP that NK allocates ends, past its stack locations, with
a block of NK's: the room in the requestor's buffer, and whether NK's
own requestor keeps the IRP when it completes. The pool tells such an
IRP from one a driver laid out in its own memory, which has no such
block. A device object is
followed by the driver's extension, then the I/O manager's own
(`DEVOBJ_EXTENSION`, which `DeviceObjectExtension` points to), laid out
as the pinned kernel's and with nothing of NK's after it: what NK keeps
about a device it keeps in the fields Windows keeps it in (deletion
pending is `DOE_DELETE_PENDING` in `ExtensionFlags`). A device's
own `ReferenceCount` decides when a deleted device stops being one, the
object's pointer count when its memory goes. A device of a type a file
system mounts on (disk, CD-ROM, tape, virtual disk) is created with a
volume parameter block (`VPB`), as Windows makes it, which a class
driver writes to (`disk.sys` sets `VPB_RAW_MOUNT`); the block goes
with the device. Nothing mounts on NK, so no block is ever another
device's.

**Stacks.** Devices are stacked as on Windows
([`IoAttachDeviceToDeviceStack`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-ioattachdevicetodevicestack),
`IoDetachDevice`): the chain up is `AttachedDevice`, the chain down the
extension's `AttachedTo`, and a device's `StackSize` is one more than
that of the device it was attached to. Attaching goes to the top of the
stack the target is in and looks at that device only: it is refused
while the top is still initialising, is going away, or has a stack as
deep as the pinned kernel allows (`MAXIMUM_ATTACH_STACK_SIZE`).
`IoGetAttachedDeviceReference` and `IoGetDeviceAttachmentBaseRef` hand
out the top and the bottom with a pointer reference.

A request for a device is a request for its stack: an open sends the
create to the top of the stack the named device is in, in an IRP with a
location for every device of it, and so does every later request on the
file (`file::related_device`, Windows' `IoGetRelatedDeviceObject`). The
file stays counted on the device that was named, and
`IoGetDeviceObjectPointer` hands out the top. How a read's or a write's
buffer travels is the top device's choice (`DO_BUFFERED_IO`).

**Mounting** (`io/mount.rs`, `io/raw.rs`). A device a file system can be
mounted on has a volume parameter block (`VPB`), and an open of it that
is not a direct device open (the device itself, for its attributes,
synchronisation or security alone) mounts the block first, as Windows'
`IopCheckVpbMounted` does: the file object gets the block, with a
reference, and its requests go to the top of the mounted volume
device's stack. NK has one file system, RAW, the kernel's own as on
Windows (`\FileSystem\RAW`): it mounts when the device itself is
opened, or when the block allows a raw mount (`VPB_RAW_MOUNT`), and
otherwise the open fails with `STATUS_UNRECOGNIZED_VOLUME`. RAW's
volume device takes the buffering of the device beneath, lets the
volume itself be opened and nothing in it (a name, a related file, a
disposition other than "open", or a directory is
`STATUS_INVALID_PARAMETER`, as Windows' RAW answers), and passes
reads, writes, control requests and flushes down unchanged; NK's own
disk tests read `\Device\Harddisk0\DR0` through it. Mounting clears
the device's `DO_VERIFY_VOLUME`. Two opens mounting at once make two
volume devices; the first published wins and the other is deleted. A
volume stays mounted until its device is deleted (`VPB_REMOVE_PENDING`)
and nothing is open on it; then RAW's device goes.

A deleted device with another still attached to it stays, deletion
pending, until that one detaches. The driver of the attached device is
told at once if it has a `FastIoDetachDevice` routine, as the pinned
kernel tells it. A device deleted while it is itself still attached to
the one below would leave that one pointing at freed memory, as it does
on Windows: NK stops, naming both.

`kernel/io/file.rs` plays the I/O system services, by handle: `open`
(`NtCreateFile`, `NtCreateNamedPipeFile`, `NtCreateMailslotFile`),
`read`, `write`, `read_at`, `write_at` (`NtReadFile`, `NtWriteFile`
without and with a byte offset), `flush` (`NtFlushBuffersFile`),
`device_control`, `fs_control`, `close` (`NtClose`). Each builds a real
IRP and calls the dispatch routine inside a critical region (as Windows
does for a synchronous request).

A read's or a write's buffer reaches the driver the way the device at
the top of the stack asks for, as on Windows: through a system buffer
(`DO_BUFFERED_IO`), as an MDL over the requestor's own buffer with its
pages locked (`DO_DIRECT_IO`; a read locks them for writing, a write
for reading, and final completion unlocks and frees the MDL), or as
the address it is. A transfer of no bytes has neither system buffer nor
MDL. Without a byte offset the transfer is where the file object's
`CurrentByteOffset` says; NK does not move that position after a
transfer, so a requestor that wants the next bytes says where they are.
A flush is a request with no buffer and no parameters. A disk is read
and written this way, with direct I/O at byte offsets: by NK's own test
disk and by Microsoft's `disk.sys` alike (`doc/TESTING.md`, "The data
disk").

**The requestor.** A request is made on behalf of kernel mode, whose
buffers are trusted, or of user mode (`user_control`,
`user_transfer`), whose buffers are an address and a length taken at
their word no further than Windows takes them. For the buffered and
direct methods the I/O manager probes them, copies the input through
`mm::user::copy` and locks a direct buffer's pages; a buffer it cannot
use fails the request with `STATUS_ACCESS_VIOLATION` before any driver
sees it. A null buffer that it would copy is no buffer, and its length
goes to the driver as zero; a direct method's second buffer keeps its
length, and null fails the probe. For `METHOD_NEITHER` the driver is handed both addresses as they
are, and what is there is the driver's to find out. The oracle's
requests are user mode's, their buffers pages of the user range.

A driver sends requests of its own with
[`IoAllocateIrp`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-ioallocateirp),
`IoCallDriver` (`IofCallDriver`) and `IoFreeIrp`: the IRP is the
driver's, with no thread and no requestor's buffers of NK's making, and
its completion routine keeps it or lets NK free it. It finds another
driver's device by name with
[`IoGetDeviceObjectPointer`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-iogetdeviceobjectpointer):
NK opens the device for kernel mode and closes the handle again, so the
device's driver is sent a create and a cleanup at once and a close when
the caller gives up the file object's reference it is handed.

A driver opens a name itself with
[`ZwCreateFile`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-ntcreatefile)
or `ZwOpenFile` (`kernel/io/zwfile.rs`), which are the requestor's open
on kernel mode's behalf. As in the pinned kernel, a kernel-mode
caller's share access, disposition and options are not checked: they
go to the device's driver as given, with the file attributes and the
allocation size, and the stack location says whether the name was to
be case-sensitive or the access checked. The handle is the kernel
handle if `OBJ_KERNEL_HANDLE` asks for one, else the System process's
own; it and the status block are written only when the open succeeds.
A name that leads nowhere fails with what the namespace says
(`\Device\RESOURCE_HUB`, which `acpi.sys` looks for, is not found; a
`\SystemRoot` path has no `\SystemRoot` to start at). An
extended-attribute buffer and a security quality of service are
refused, not ignored.

A driver also has the I/O manager build a request for it
([`IoBuildSynchronousFsdRequest`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-iobuildsynchronousfsdrequest),
[`IoBuildDeviceIoControlRequest`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-iobuilddeviceiocontrolrequest),
`kernel/io/build.rs`): the request names the calling thread, carries
the I/O priority hint of a normal thread in its flags as the pinned
kernel's does, and has its buffers set up the way the device or the
control code asks for. Such a request is the I/O manager's. When it has
completed all the way up, final completion copies the results out,
writes the caller's status block, frees the IRP with its system buffer
and MDL, and sets the caller's event; the caller never frees it. A
flush, a shutdown, a power and a Plug and Play request are built with
no buffer, as the pinned kernel builds them.

[`IoSynchronousCallDriver`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-iosynchronouscalldriver)
sends a driver's own IRP with a completion routine of the I/O manager's
that keeps it, and waits if the request was pended: the IRP comes back
uncompleted. `IoReuseIrp` and `IoInitializeIrp` clear an IRP for
another use, in the pool or in the driver's own memory. A driver that
splits a request folds the parts' statuses into the master's with
`IoSetMasterIrpStatus`, by the pinned kernel's rule
(`nk_ntabi::io::master_irp_status`).

**IRP extensions** (`kernel/io/irpext.rs`). What Windows keeps about a
request beside the IRP is NK's too, by the pinned kernel's rules and in
its layout (`IOP_IRP_EXTENSION`): an activity id
([`IoSetActivityIdIrp`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-iosetactivityidirp),
`IoGetActivityIdIrp`) and four bytes of a driver's own
(`IoSetGenericIrpExtension`), in a pool block the IRP points to and its
allocation flags mark. A generic extension alone is kept in the
pointer's own place, and moves to a block when an activity id joins
it. `IoPropagateIrpExtension` copies both to another IRP, `IoReuseIrp`
keeps the block and the activity id and drops the rest, and the block
is freed with the IRP. The I/O manager itself gives a request no
activity id: Windows does while I/O tracing is on
(`IoIsActivityTracingEnabled`), which it never is here. A thread works
under an IRP's activity id through the pointer in its `ETHREAD`
(`IoPropagateActivityIdToThread`, `IoClearActivityIdThread`). The kinds
of extension only Windows' own components make (a file system's
tracked offset, a disk I/O attribution handle, an adapter's crypto
parameters) are in no IRP: asked for, they are not found, and I/O
recorded against an attribution handle names no handle
(`STATUS_INVALID_HANDLE`).

What a driver asks about a request is read from the IRP as the pinned
kernel reads it (`kernel/io/irpinfo.rs`): the I/O priority from the
flags (`IoGetIoPriorityHint`, `IoGetPagingIoPriority`), the requestor's
process id, the bounds of the stack the caller is on
(`IoGetStackLimits`: the thread's, or the processor's DPC stack).
`IoIs32bitProcess` says no: NK runs no 32-bit code.
`IoSetHardErrorOrVerifyDevice` notes its device on the requestor's
thread, where Windows keeps it.

A driver keeps what it needs per driver object in extensions it
allocates and finds again by an address of its choosing
([`IoAllocateDriverObjectExtension`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-ioallocatedriverobjectextension),
`IoGetDriverObjectExtension`). They hang off the driver extension's
`ClientDriverExtension`, as on Windows, each behind an
`IO_CLIENT_EXTENSION`, and are freed by the driver type's delete
procedure when the driver object goes.

A driver reports an error with a device through the error log
([`IoAllocateErrorLogEntry`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-ioallocateerrorlogentry),
`IoWriteErrorLogEntry`, `kernel/io/errlog.rs`). A packet is allocated
as the pinned kernel allocates it: within Windows' sizes, behind the
I/O manager's header, counted against the limit on outstanding
packets, holding its device and driver object. NK has no event log
service to queue it to: writing a packet prints one `NK-ERRORLOG` line
to the boot log, naming the driver, the device, the error code and the
final status, and frees the packet.

A driver counts the requests in progress on a device with a
[remove lock](https://learn.microsoft.com/en-us/windows-hardware/drivers/kernel/using-remove-locks)
(`kernel/io/remlock.rs`): the lock is the driver's memory in the
free-build layout, and the `Ex` routines are what the documented macros
expand to.

A driver asks whose request it has with `IoGetRequestorProcess`: the
process of the thread in the IRP, which for every request NK sends is
the System process, and none for an IRP a driver allocated and gave no
thread. `IoGetFileObjectGenericMapping` hands a file system the file
type's own generic mapping, the one an open's desired access is mapped
with.

A request for user mode is also held to what its handle was granted,
before any driver sees it (`STATUS_ACCESS_DENIED`): `FILE_READ_DATA` to
read; `FILE_WRITE_DATA` to write, or `FILE_APPEND_DATA` unless the file
is a named pipe; for a control request the access its code names (bits
14 and 15). Kernel mode's handle is asked for nothing.

Completion follows the Windows
sequence: unwind the stack locations running completion routines, then
copy results to the requestor, free the IRP and signal the requestor's
event. NK's own requestor keeps its IRP instead, and frees it once it
has seen the completion. A buffered request's
results are copied only as far as the requestor asked; a driver that
reports more stops the system. A driver that returns other than
`STATUS_PENDING` without completing, or a status different from the one
it completed with, fails the request's test. A request made through a
handle holds the file object until it has been waited for.

**Open.** The name is looked up in the namespace, from the root or from
a directory a root handle names. The root handle is referenced on
behalf of the open's requestor, with no access asked of it, as Windows
references it: a kernel handle is no root for user mode
(`STATUS_INVALID_HANDLE`). The look-up ends at a device, and what
is left of the path is the device's to parse (Windows' `IopParseDevice`):
it becomes the new file object's `FileName`, backslash first, in a pool
block of the I/O manager's. A name relative to an open file goes to that
file's device as given, with the file as `RelatedFileObject`: referenced
until the create request has completed, which is as long as Microsoft
documents the field to be valid, and cleared then. Anything
but a device at the end of the look-up is `STATUS_OBJECT_TYPE_MISMATCH`.

Finding a device and counting the open are two steps, and the device may
be deleted between them. The look-up takes a pointer reference while the
name still leads to the device; the open is then counted under the I/O
database lock, or refused if the device is deleted.

The create request (`IRP_MJ_CREATE`, or `IRP_MJ_CREATE_NAMED_PIPE` with
the pipe's `NAMED_PIPE_CREATE_PARAMETERS`, or `IRP_MJ_CREATE_MAILSLOT`
with the mailslot's `MAILSLOT_CREATE_PARAMETERS`) carries what Windows' does:
`Parameters.Create` with the disposition and create options, the share
access, no attributes and no extended attributes; an
`IO_SECURITY_CONTEXT` with the desired access and an `ACCESS_STATE` for
the System process, generic rights mapped to the file rights in both;
the requestor's mode in the IRP. What the driver leaves in
`IoStatus.Information` is the open's result. A create the driver fails
leaves a file object with no device, about which the driver hears no
more. The opener waits for a create the driver pends; what the request
points to is on the opener's stack until then. A dispatch routine that
returns anything but `STATUS_PENDING` for a create it has not completed
may still hold that IRP: the system stops, naming the routine.

**Cleanup and close.** A file object is an object of the file type, and
the open returns a handle to it. The type's close procedure sends
`IRP_MJ_CLEANUP` when the last handle in the system closes; its delete
procedure sends `IRP_MJ_CLOSE` when the last reference goes, then drops
the file's count on the device and frees the name. A driver is called
at `PASSIVE_LEVEL`: a file whose last reference goes above it is put on
a list through its header (`NextToFree`) and deleted by a worker
thread, as on Windows. Other types' objects are deleted where their last
reference goes.

A file object's `Flags` have no lock. The open marks the file as having
had a handle (`FO_HANDLE_CREATED`, which spares it a cleanup request
when it is deleted) before the handle is in the table, and takes the
mark back if no handle is made: once the handle is there, another
thread may close it, and the flags are that close's to write.

**Pending.** A driver may return `STATUS_PENDING` and complete later from
a DPC, timer or worker; the requestor waits on an event completion sets.
The requestor owns the IRP and frees it after seeing completion, so
cancelling is safe until then. Windows finishes a request in the
requesting thread by APC; NK finishes it wherever it was completed, at
`DISPATCH_LEVEL` or below. There is one address space, so a user-mode
requestor's buffer is there to copy to from any thread; the copy is the
one that may fail, and a buffer gone by then makes the access violation
the request's final status, in its status block. That is what the
request returns if the driver pended it; one completed before the
dispatch routine returned returns the routine's status, as Windows'
system services do. The driver is held to the status it completed the
request with, which the fault does not change.

**Cancel.** `IoCancelIrp` marks the IRP, takes its cancel routine in one
atomic step, and calls it holding the cancel spin lock, which the routine
releases. A completing driver takes the routine the same way, so exactly
one of the two completes it. "Install the routine, then read the cancel
flag" races "set the flag, then take the routine"; both sides use
sequentially consistent operations, since with less each can miss the
other's write and a cancelled request is never completed. Cancelling a
completed IRP whose routine is still set stops the system
(`CANCEL_STATE_IN_COMPLETED_IRP`).

**Plug and Play and power requests.** The minor function codes of
`IRP_MJ_PNP` and `IRP_MJ_POWER`, where each request's parameters lie in
the stack location, and the structures they point to (device relations
and capabilities, resource lists and requirements, interfaces) are in
`lib/ntabi/pnp.rs`, held to the kernel's symbols where those name them.
A power request is sent as any other: `PoCallDriver` is `IofCallDriver`
and `PoStartNextPowerIrp` does nothing, as in the pinned kernel. A
driver's dispatch table starts out with one routine for every major
function, these two included, which fails the request as invalid for
the device, as Windows' does.

The kernel's own requests to a stack go through
`io::stack::send_synchronous(device, major, minor, parameters)`, which
returns `(status, information)`: it builds an IRP for the whole stack
the device is in, sends it to the top in the name of the calling
thread, and waits for it, at `PASSIVE_LEVEL`. It is what the Plug and
Play manager asks a device's drivers through. A Plug and Play or a
power request starts out with `STATUS_NOT_SUPPORTED`, as Windows
requires, so that status coming back means no driver handled it. A
driver that returns other than `STATUS_PENDING` without completing the
request keeps it: the breach is reported and the returned status is
the answer.

**StartIo** (`kernel/io/startio.rs`). A driver with a `StartIo` routine
queues its requests with
[`IoStartPacket`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-iostartpacket)
and asks for the next with `IoStartNextPacket`. The queue is the device
object's `DeviceQueue` with Windows' meaning (busy while one request is
`CurrentIrp`, the others linked through each IRP's device queue entry,
by arrival or by key, under the queue's own spin lock); NK implements
of the device queue what these routines need and exports none of the
`Ke` routines for it, which nothing NK loads imports. `StartIo` is
called at `DISPATCH_LEVEL`. The cancel routine is set, and a request
already cancelled when it is queued has it called, under the cancel
spin lock, as Microsoft documents. What `IoSetStartIoAttributes` chose
is in the extension's `StartIoFlags`: with deferred start a call of
`IoStartNextPacket` made while another is at work for the device (from
`StartIo` itself) leaves word there, and the outer call starts the next
request once `StartIo` has returned, as the pinned kernel does it.

**Cancel-safe queues** (`IoCsq*`, `kernel/io/csq.rs`). While a request is
queued its fourth driver-context pointer names the queue (or the
caller's context block) and its cancel routine is the I/O manager's,
which unlinks it under the queue's lock and has the driver complete it.
Removal skips a request whose cancel routine is already gone: the
canceller has it.

**Stream contexts** (`kernel/fsrtl/mod.rs`). A file system puts an
`FSRTL_ADVANCED_FCB_HEADER` at the front of each stream's control block
and initialises it with code compiled into the driver; `npfs.sys` and
`msfs.sys` make it version 3, advanced, supporting filter contexts.
When it frees the block it calls
[`FsRtlTeardownPerStreamContexts`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-fsrtlteardownperstreamcontexts),
and NK does what the pinned kernel does: under the header's own lock
(its push lock inside a critical region, or the file system's fast
mutex in a version 0 header) it unlinks the first context, lets the
lock go, calls the context's `FreeCallback`, and takes the lock again,
until the list is empty. A list found empty is not locked. A list whose
links do not lead back stops the system (`0x139`). NK differs in one
thing no correct file system can see: a header whose flags say it is
not advanced or supports no filter contexts is not read further, where
Windows reads the list regardless. Nothing in NK attaches a context:
no binary NK loads imports the routines that do
(`FsRtlInsertPerStreamContext`), so they are not exported. The test
`fsrtl.teardown-stream-contexts` attaches them by hand to headers set
up as the two drivers' code sets them up; the
`*-neg-stream-context-list` scenarios break a list.

**Direct I/O** uses real MDLs: the buffer, the kernel's or one in the
user range, is described by its physical pages, and a system address is
a fresh mapping of them, so the driver works through its own view.
Limits are at the top of `kernel/io/mdl.rs`. An MDL of up to seventeen
pages is a block with room for seventeen, marked
`MDL_ALLOCATED_FIXED_SIZE`, as Windows' is (it takes them from a list
of blocks of that size): Storport describes a longer buffer with an
MDL it allocated for a shorter one. A partial MDL
([`IoBuildPartialMdl`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-iobuildpartialmdl))
shares the pages of the part of the source's buffer it names, and the
source's system mapping if there is one; mapped on its own, it keeps
that mapping until it is freed. A part outside the source's buffer
stops the system.
