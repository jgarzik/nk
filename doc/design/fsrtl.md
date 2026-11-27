# The file-system runtime library

Part of NK's design ([DESIGN.md](../DESIGN.md)): the principles there apply.

The routines the kernel exports for file systems (`FsRtl*`), in
`kernel/fsrtl`; what can be written without touching a driver's memory
is in `lib/fsrtl`. Stream contexts, which filters attach to a file
system's control blocks, are described with the I/O manager
([I/O](io.md)).

## Filter callbacks

A file system registers its own filter callbacks
(`FsRtlRegisterFileSystemFilterCallbacks`): a copy of its
`FS_FILTER_CALLBACKS` hangs on its driver extension until the driver
object goes, as on Windows. The kernel calls them around the operations
it starts on the file system's behalf, before it falls back to the
fast-I/O dispatch entries and then to its own defaults.

## Taking a file for the kernel's own I/O

When the memory manager flushes for the cache manager, it takes the file
through `FsRtlAcquireFileForCcFlushEx` and gives it back through
`FsRtlReleaseFileForCcFlush` (`kernel/fsrtl/acquire.rs`), as the pinned
kernel does: inside a critical region kept until the release, first the
file system's own filter callback for the operation (its
`STATUS_FSFILTER_OP_COMPLETED_SUCCESSFULLY` means it did the work), then
`AcquireForCcFlush` of its fast-I/O table if the table reaches it, and
when there is none, or it answers `STATUS_INVALID_DEVICE_REQUEST`, the
default: the FCB header's main resource exclusive (shared again by a
thread that holds it shared), then the paging resource shared; the
release gives back the paging resource, then the main one. A failed
acquisition leaves the critical region; a post-operation callback
follows a pre-operation callback that succeeded. The device asked is
the file system's own; NK attaches no filter to a file system.

The lazy writer's deletion of a cache map takes the file the same way
through `FsRtlAcquireFileExclusive` and `FsRtlReleaseFile`: the file
system's `PreAcquireForSectionSynchronization` (asked for a section of
no particular kind), then `AcquireFileForNtCreateSection` of its fast-I/O
table, then the main resource exclusive. The acquisitions for the
modified-page writer and for creating a section are not built: nothing
in NK calls them yet.

## Fast I/O through the cache

`FsRtlCopyRead`, `FsRtlCopyWrite`, `FsRtlMdlReadDev`,
`FsRtlPrepareMdlWriteDev` and their completions (`kernel/fsrtl/fastio.rs`)
are what a file system's fast-I/O table points at, as the pinned kernel
does them: FALSE (the caller sends an IRP) when a top-level IRP is set;
the FCB header's main resource inside a critical region, shared, or
exclusive for a write that appends or passes the valid data length;
FALSE unless the file is cached and fast I/O possible; reads clamped to
the file size (at or past it, TRUE with `STATUS_END_OF_FILE`); writes
refused when the cache manager throttles them, through a write-through
file object, at 16 MiB or more, past the allocation size or more than
8 KiB beyond the valid data length. A write zeroes the gap below it,
raises the file size first under the paging resource and puts it back
on failure, and on success raises the valid data length and the cache
map's file size and marks the file object. The top-level IRP is
`FSRTL_FAST_IO_TOP_LEVEL_IRP` around the cache manager's call, and a
failure there is FALSE. NK's difference: a file whose fast I/O is
questionable takes the IRP path at once, where Windows first asks the
file system's eight-argument `FastIoCheckIfPossible`, more arguments than
NK's guarded call into a driver passes.

## Mapping control blocks

A file system keeps, per file, which runs of its virtual blocks lie at
which logical blocks of the volume in a `LARGE_MCB`
(`kernel/fsrtl/mcb.rs`, rules in `nk_fsrtl::mcb`). The array of pairs
and its mutex are pool blocks, as on Windows; numbers are cut to 32
bits as Windows cuts them, and the map is always in Windows' one form
(no empty runs, no two runs that continue each other, no hole at the
end), so look-ups and enumerations report what Windows reports. A
range added over runs that map it differently is refused. When memory
runs out the routine raises `STATUS_INSUFFICIENT_RESOURCES` in its
caller, entered through `nk_with_caller_context` so the exception
starts in the file system's own frame. The array grows by doubling and
never shrinks.

## Names and statuses

Taking a path apart (`FsRtlDissectName`), comparing names, finding
wildcards and judging a FAT short name (`FsRtlIsFatDbcsLegal`) follow
the pinned kernel (`nk_rtl::fatname`); the OEM page has no double-byte
characters, so Windows' double-byte branches never apply. The branches
of `FsRtlIsFatDbcsLegal` that permit a path or a leading backslash were
not read, and no binary NK runs asks for them: asking stops the system
by name, and the export is partial. `FsRtlAreNamesEqual` compares a
unit at a time where Windows upper-cases copies, so it needs no memory
and never raises. Which exception statuses a file system lets through
and which failures mean the device is gone are Windows' lists
(`nk_fsrtl::status`).

## Oplocks

NK grants no opportunistic locks: `FsRtlOplockFsctrl`, the only routine
that creates one, is a trap. The rest do what the pinned kernel does
with a stream that has none (`kernel/fsrtl/oplock.rs`): checks and
breaks let the operation go on, fast I/O is possible, no batch or
handle oplock is held. No oplock keys are recorded. An oplock field
that is not null stops the system by name, so those exports are
partial.

## Byte-range locks

NK takes no byte-range locks: `FsRtlProcessFileLock` and
`FsRtlPrivateLock`, which lock, are traps. A `FILE_LOCK` is initialised
as Windows initialises it, and the other routines do what the pinned
kernel does with no record of locks (`kernel/fsrtl/lock.rs`): every
access is allowed, nothing waits, an unlock finds no range locked. A
record that is not null stops the system by name.

## Tunnel caches

A volume's tunnel cache remembers, for a short while, the names and
data (a creation time) of files just renamed or deleted, so a file made
with one of those names gets them back; the rules are the pinned
kernel's (`nk_fsrtl::tunnel`): keyed by directory and one name without
regard to case, pruned by age and number on every addition and
look-up. The limits are Windows' defaults, 256 entries and 15 seconds,
unless `Control\FileSystem\MaximumTunnelEntries` or
`MaximumTunnelEntryAgeInSeconds` says otherwise (read at boot); an age
of 0 turns tunnelling off. The `TUNNEL` structure's mutex serialises
the routines; NK's record of the entries hangs on its `Cache` field.

## Change notification

The per-volume synchronisation object is Windows' (a fast mutex its
owner may take again, from the pool). A directory watch is registered
only by `FsRtlNotifyFullChangeDirectory`, a trap, so the list is always
empty: reporting a change or cleaning up a handle finds nothing to
complete, and a watch on the list stops the system by name.

## Volume events

`FsRtlNotifyVolumeEvent` reports a mount (from a worker), a dismount, a
lock or an unlock (before it returns) as a target-device change of the
volume's physical device object, found as Windows finds it: the
target-device relation of the top of the stack a request on the file
goes to, the file system's own volume device on a mounted volume. Its
status is that of finding the device, as on Windows. Other events were
not read and stop the system by name.

## Asking the volume

Requests the runtime library sends a file system's devices go to the
device named, not the top of its stack, as Windows'
`FsRtlIssueDeviceIoControl` sends them (`kernel/fsrtl/device.rs`). A
volume's correlation id is its answer to
`IOCTL_MOUNTDEV_QUERY_STABLE_GUID`, or for one that does not answer the
GUID of its name (`IoVolumeDeviceToGuid`), as Windows falls back. A create request's extra create parameters are
none. The volume start-up applications have not run (user mode reports
them), as on Windows before they do. The disk counters file systems add
to are kept, and read by nothing, as on Windows; a process's own
counters are added to where it has them.
