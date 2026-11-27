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
