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
