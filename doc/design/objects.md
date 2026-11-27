# Objects, references and handles

Part of NK's design ([DESIGN.md](../DESIGN.md)): the principles there apply.

## Objects, references and handles

Object-manager allocations have Windows' `OBJECT_HEADER` in front:
pointer count, handle count, type. Events, threads, the System process,
tokens, drivers, devices, open files, open registry keys, directories,
symbolic links and silo contexts are such objects. An object is freed when its last
reference goes; its type may name a delete procedure that first releases
what it owns, and a close procedure that is told of every handle closed
and how many there were. A thread references itself until it has ended
and been reaped, so an unreferenced thread frees itself and a referenced
one stays a valid, signalled object.

A driver's reference returns the count it made, its release the count it
left. The tagged forms (`ObfReferenceObjectWithTag`) count on the same
count: the tag is for
[reference tracing](https://learn.microsoft.com/en-us/windows-hardware/drivers/kernel/object-reference-tracing-with-tags),
which is off, as it is on Windows unless asked for. A reference taken to
an object that has none stops the system (`REFERENCE_BY_POINTER`).

Handles are entries in one table, the System process's, which is the
kernel's handle table as on Windows; a handle holds a reference until
closed. An entry has two names: the kernel handle, with Windows'
kernel-handle bits, which is a handle for kernel mode only
(`STATUS_INVALID_HANDLE` for user mode), and the same number without
those bits, the System process's own handle, good in that process for
either mode. Every open returns the kernel handle, a driver's with
`OBJ_KERNEL_HANDLE` or without (`ObOpenObjectByPointer`,
`ZwCreateEvent`): on Windows a handle made in the System process is in
the kernel's table whatever was asked. No other process, no other
table. A handle's number is predictable (the lowest free slot), so it
can be closed the instant it is in the table: it is given its reference
and its place in the object's handle count under the table's lock,
which a close takes to remove it. Each handle has the access it was
granted and its
attributes (inherit, protect from close). A handle protected from close
stays open: user mode closing it is refused
(`STATUS_HANDLE_NOT_CLOSABLE`), kernel mode closing it stops the system
(`INVALID_KERNEL_HANDLE`), as on Windows. Nothing decides what a subject
may have: a handle is granted what its opener asked for, generic rights
turned into what they mean for the object's type. A use of a handle on
behalf of user mode is refused (`STATUS_ACCESS_DENIED`) access the handle
lacks; kernel mode is not held to it, as `ObReferenceObjectByHandle`
documents. A type's generic rights are Windows' for files and registry
keys; the other types have none recorded, and a generic right asked of
them grants nothing. `NtCurrentThread()` (-2) names the caller and
`NtCurrentProcess()` (-1) its process, with every access.
`ObReferenceObjectByPointer` takes a reference to an object the caller
already has, if it is of the type named (`STATUS_OBJECT_TYPE_MISMATCH`
otherwise, for either mode); with no type named it does so for kernel
mode only, as the pinned kernel decides it.

Inside the kernel a pointer reference a function takes and gives up
itself is an `ob::object::ObRef`, which gives it up when dropped, on
every path out; `into_raw` hands it on to whatever keeps it (a handle,
a driver, a watch). The handle look-ups (`ob::handle::reference`,
`reference_for`) and the namespace's (`ob::lookup`) return one.

A type is an `OBJECT_TYPE` with Windows' layout, named by its address: a
driver imports a variable holding it (`ExEventObjectType`). Its index
numbers are NK's own. An object's header names its type as Windows 10
does, by the index combined with a cookie chosen at boot and a byte of
the header's address (`nk_ob::header`). The fields of a type NK does not
keep (its counts, its lists) are zero.

A driver may make a type (`ObCreateObjectType`; `pcw.sys` makes one):
the arguments are checked as the pinned kernel checks them (a bad one
stops at a breakpoint and is then `STATUS_INVALID_PARAMETER`, a name
with a backslash `STATUS_OBJECT_NAME_INVALID`, a name already taken
`STATUS_OBJECT_NAME_COLLISION`), and the type, a copy of the caller's
initializer under the next free index, lives for ever, as on Windows.
NK makes no object of a driver's type: `ObCreateObject` stops the
system by name, so none of such a type's procedures is called yet.

### The namespace

A tree of directories holding named objects and symbolic links
(`nk_ob::tree`, under one lock; `kernel/ob/mod.rs`). The root and the
directories every Windows system has (`\Device`, `\Driver`,
`\FileSystem`, `\GLOBAL??`, `\BaseNamedObjects`, `\KernelObjects`) are
directory objects made at boot. `\??`
is `\GLOBAL??`, there being one session, and `\DosDevices` is a symbolic
link to `\??`. A named device is an entry in the directory its name puts
it in, a symbolic link is a symbolic-link object there, a loaded
driver's object is `\Driver\<service>`, and `\Registry` is the
registry's root key.

Names compare case-insensitively whatever the caller asks, which is
Windows' default configuration, by the same upper-case table as the
registry's. A look-up follows symbolic links, at
most eight, and stops at the first object on the path, handing back the
object, referenced, and the rest of the path. A directory missing on the
way is `STATUS_OBJECT_PATH_NOT_FOUND`; a missing last name is
`STATUS_OBJECT_NAME_NOT_FOUND`.

An entry does not keep its object alive (a symbolic link's and a
directory's excepted, which nothing else holds): whoever names an
object takes the name away before giving up the reference the object
was made with.

A driver makes a directory with
[`ZwCreateDirectoryObject`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-zwcreatedirectoryobject)
(`kernel/ob/directory.rs`), as `disk.sys` makes `\Device\HarddiskN`
for each disk. A directory is temporary or permanent, with Windows'
meaning: a temporary directory's name is taken away when the last
handle to it closes; a permanent one (`OBJ_PERMANENT`, the header's
permanent flag, which the boot directories have too) keeps its name
until
[`ZwMakeTemporaryObject`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-zwmaketemporaryobject)
clears the flag, and then loses it at once if no handle is open, or
with the last handle. The name holds a reference to the directory, and
whatever is in a directory holds one too (its name information points
there), so a directory that has lost its name stays, reachable by
handle and by what is in it but by no path, until it is empty; its
old name is free at once. A directory made without a name is reached
by handle alone. NK makes only directories permanent by handle: a
device's or a link's name is its maker's to take away, and
`ZwMakeTemporaryObject` on a handle to such a named object stops the
system by name.

A named object carries Windows' `OBJECT_HEADER_NAME_INFO` in front of
its header, as the header's `InfoMask` says: its directory and its name
there, both emptied when the object loses its name. Name information,
header, body and the name's characters are one pool block. Directory and
symbolic-link bodies have Windows' sizes: a link's holds its target and
creation time; a directory's is zero, the entries being in NK's tree.

What is done with the rest of a path is the business of the type the
look-up ended at, after the namespace's lock is dropped: a device's
driver parses it as a file name (see [I/O](io.md)). The types' parse steps are
NK's own code, not `OBJECT_TYPE` procedures. No security checks.
