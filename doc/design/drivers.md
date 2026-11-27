# Loading and starting drivers

Part of NK's design ([DESIGN.md](../DESIGN.md)): the principles there apply.

## Loading a driver

`kernel/ldr` checks the image is a native PE32+ for this machine, lays it
out in fresh frames, relocates it to a fresh address, binds every import,
and only then maps it with each section's protection. Also:

- **Stack cookie.** MSVC-built drivers check at entry that the loader
  replaced the default `__security_cookie`, and `__fastfail` if not. The
  loader finds it through the load configuration directory and writes a
  per-image value (non-zero, not the default, top 16 bits clear as the
  x86-64 check requires). Its entropy is only the cycle counter.
- **Instruction cache.** On arm64 the image is written through one
  address and run from another, so the loader synchronises the caches.

A refused image leaves nothing allocated.

Every image in memory, the kernel's own first (as `ntoskrnl.exe`), is in
one fixed-size table by file name, address range, function table, view
and export directory (`nk_pe::modules`): a fatal trap names the image
and offset it happened at, a stack walk finds each frame's function
there, and an import from a library is bound through it. An image of a
file name that is loaded is not loaded again.

One image is loaded or unloaded at a time, under a mutex
(`doc/LOCKING.md`): loading calls a library's `DllInitialize`, which may
wait, and loads a library from inside the load of its importer.

**Paging a driver.** `MmPageEntireDriver` and `MmResetDriverPaging`,
which a driver calls to let its whole image be paged out while it is
idle and to take that back, change nothing: NK never pages kernel
memory out, so an image is resident from load to unload, which is
within what both promise. The first still answers the base of the image
an address is in, or null.

**An image's messages.** A driver reads text from a message table in
an image's resources with
[`RtlFindMessage`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-rtlfindmessage)
(`pci.sys` takes its device descriptions from its own). The resource
directory and the table are read through the image's view
(`nk_pe::resources`, `kernel/rtl/image.rs`), and the entry is handed
out at its address in the image. The languages tried are the pinned
kernel's: the one asked for and its parents, and for a request without
a language the system's languages, then US English, then whichever the
table has first. NK is a US English system. A language's parent is its
primary language (Windows asks its locale data, which for a few
languages names a script instead), and no language files stand beside
an image. `RtlPcToFileName` names the loaded image an address is in.

## Starting a driver

A driver is started from its service key, as on Windows
(`kernel/io/service.rs`): `...\Services\<name>\ImagePath` names the
image, and a key without that value means `System32\drivers\<name>.sys`.
The last part of the path is looked up among the boot files, the
contents of `\NK\drivers`, which stand for `System32\drivers`: NK
reads no file system. Nothing else starts a driver; a library is
loaded when an image imports from it ([Exports](image.md)). The driver's entry
point is given the path to its key. Stopping a service runs the driver's
unload routine and frees its image; the key stays.

**At boot**, before anything else is done with drivers, the system
thread starts those whose keys say `Start` 0 (boot) or 1 (system), in
Windows' order (`nk_cm::services`): boot start before system start; in
each, by the place of the service's `Group` in
`Control\ServiceGroupOrder`, then by the place of its `Tag` in the
group's list under `Control\GroupOrderList` (a tag the list has not, or
none, after those it has); services of no listed group last; a service
after those it names in `DependOnService` and `DependOnGroup`. The
group `Core` comes before every listed group, in the order of its
tags, though neither list names it: it is `acpi.sys`'s group, and the
reference Windows' boot log has `acpi.sys` loaded before every bus
driver. A group
is the same group in any letter case: Windows' own keys say
`File system` where its list says `File System`. Only keys whose `Type`
is a driver's count. Windows'
loader reads boot-start drivers into memory before the kernel runs and
the I/O manager starts system-start ones later; on NK both are boot
files and the order is all that tells them apart.

When they have all started, the routines boot drivers registered with
`IoRegisterBootDriverReinitialization` are called in the order
registered, each with the number of times that driver has now been
reinitialised; one may register again from within itself. Afterwards
the queue is closed, and a routine registered later is never called, as
on Windows.

The routines drivers registered with `IoRegisterDriverReinitialization`
are called at the three points the pinned kernel calls them: after a
driver is loaded for a device, after one is loaded by `ZwLoadDriver`,
and when the system has finished starting (after the boot queue). Each
point calls the routines registered before it, in order; a routine
registered meanwhile, or by itself again, waits for the next point.
`mountmgr.sys` names drive letters only from its reinitialisation
routine. `IoGetBootDiskInformationLite` lists the disks the loader
names, which for NK's UEFI loader are none, and answers
`STATUS_TOO_LATE` once the system has started, as Windows does.

- A service whose image is not among the boot files is passed over,
  with a line in the log: a test image holds only the drivers it was
  given.
- Any other failure is logged, and stops the boot if the key's
  `ErrorControl` is 3 (critical). Windows restarts with the
  last-known-good control set first; NK has the one.

Other services start when something asks: the tests make a key the way
`sc create` does and start it, or start one the hive describes.
A driver asks with
[`ZwLoadDriver`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-zwloaddriver),
naming the key by its full path; the status is the entry point's, or
that of opening the key when there is none (`acpi.sys` asks for
`acpiex`, the resource hub, which no key of NK's describes). The entry
point runs in the caller's thread, as it does on Windows for a caller
in the System process.
