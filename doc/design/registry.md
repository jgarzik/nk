# The registry

Part of NK's design ([DESIGN.md](../DESIGN.md)): the principles there apply.

## The registry

One tree of keys and values in memory (`lib/cm`; exports in `kernel/cm`).
It is built at boot:

1. the keys every system has: `\Registry\Machine\System` with
   `Select`, `\Registry\Machine\Hardware` with `DeviceMap` and
   `ResourceMap` (which Windows makes at every boot, and under which
   drivers make volatile keys of their own: storport its
   `DeviceMap\Scsi\Scsi Port N`; every key of NK's lives in memory, so
   `REG_OPTION_VOLATILE` changes nothing), `\Registry\User`;
2. the SYSTEM hive the loader read (`doc/BOOT.md`), if it read one,
   copied over `\Registry\Machine\System`: keys, values, classes,
   security descriptors, times. A hive that is damaged, or that needs
   its transaction log, fails the boot: nothing replays a log;
3. the registry overlay the loader read, if it read one, laid over
   `\Registry\Machine\System` in turn: a key that is not there is
   made, with the keys above it, and a value takes the place of the
   hive's value of the same name;
4. the control set `Select\Current` names (`ControlSet001`), with
   `Control\Class` and `Services` made if the hive did not bring them,
   and `CurrentControlSet`, a symbolic link to it.

Without a hive and an overlay the registry is 1 and 4 alone. It holds
what drivers write until power-off; nothing is written back to a file.

The overlay is NK's own: Windows has nothing like it. The hive is
written by Windows from a text manifest in nk-fixtures, so a change to
it takes a release of the fixtures; `fixtures/registry-overlay.txt`
holds, in that manifest's format, the keys and values work in progress
needs before the release. `tools/mkesp.py` puts the file in a boot image
that has the fixtures, as `\NK\OVERLAY`; `lib/cm/manifest.rs` reads it.
Nothing has read the registry when it is applied, so to every reader
its content is the hive's. A line that cannot be read fails the boot
and is named in the log: the file is NK's, and half of it is not used.
Its content belongs in the Windows-written hive: a release of the
fixtures takes it into the hive's manifest, and the file keeps its
header comment alone.

A symbolic link is what it is on Windows: a key flagged as one, whose
`SymbolicLinkValue` (`REG_LINK`) is the full path of another key. A
look-up that reaches a link goes on from that key, so a key made under
`CurrentControlSet` is made in the control set. A link whose target is
missing leads nowhere (`STATUS_OBJECT_NAME_NOT_FOUND`). Only the kernel
makes links; no export opens the link itself.

Names compare without regard to case, upper case against upper case by
a full table (`nk_rtl::upcase_char`: Windows' own, recorded from Windows
10). A key handle is a handle to a small object naming
the key. The root key is such an object too, called `\Registry` in the
object namespace: an absolute name, or one relative to a directory, is
looked up there, through symbolic links like any other, and must end at
that key, which walks the rest of the path in the registry's own tree. A
name relative to an open key starts at that key. A key is no file:
opening one through the I/O manager is `STATUS_OBJECT_TYPE_MISMATCH`.

Subkeys are enumerated in the order of their upper-cased names, values
in the order they were first set, as on Windows
([`ZwEnumerateKey`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-zwenumeratekey),
[`ZwEnumerateValueKey`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-zwenumeratevaluekey)).
A key or value is described in Microsoft's information structures
(`lib/cm` writes them; the classes are those of
[`KEY_INFORMATION_CLASS`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/ne-wdm-_key_information_class)
and
[`KEY_VALUE_INFORMATION_CLASS`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/ne-wdm-_key_value_information_class)).
A buffer with room for a structure's fixed part and not all of the rest
gets what fits and `STATUS_BUFFER_OVERFLOW`; one with less gets nothing
and `STATUS_BUFFER_TOO_SMALL`; both are told the length that holds
everything. Where a class or a value's data is aligned after a name,
the bytes between are the caller's, untouched. A value's data start at
a multiple of eight bytes in the full form, aligned or not, as Windows
10 x64 places them.

An open key describes itself
([`ZwQueryKey`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-zwquerykey))
in every form. Its full name starts at `\REGISTRY`, each part in the
letter case it was created in (`MACHINE`, `SYSTEM`, `HARDWARE` and
`USER` are Windows' spellings), with symbolic links followed: a key
opened through `CurrentControlSet` names its control set. The cached
form (`KEY_CACHED_INFORMATION`) is all there or not at all: it wants
room for the structure as C sizes it, 40 bytes, and writes the 36 of
its fields. What NK has
none of is reported as Windows reports a key without it: no flags, no
virtualization, no handle tags. Every key is trusted
(`KeyTrustInformation`), because the registry holds only the system's
own hive. Where a form is a word of bit fields (virtualization, trust)
the flags are written and the reserved bits stay the caller's. The
forms are those Windows 10 answers: it has no layer form
(`KeyLayerInformation` is `STATUS_INVALID_PARAMETER`).

A key's last write time is when its values or its list of subkeys last
changed: setting or deleting a value stamps the key, making or deleting
a key stamps the key above it, and a new key is stamped as it is made.
A key copied from the hive keeps the file's time until then.

A key remembers the longest subkey name, subkey class, value name and
value data it has held, which is what it reports as the longest it
holds: as on Windows, the numbers only grow while the key has subkeys
(or values) and start again when the last one goes. A key copied from a
hive file starts from the numbers the file gives it.

Creating makes only the last key of a path, as on Windows, and gives a
new key its class. A value is enumerated in the basic, full and partial
forms, and read by name in those and the two aligned for 64 bits, which
Windows 10 refuses to enumerate in (`STATUS_INVALID_PARAMETER`); there
are no layered keys, so the form that describes a value of one
(`KeyValueLayerInformation`) is refused the same way. A deleted value leaves its
place in the order to the next; set again, it is the key's last. A key
without subkeys can be
deleted: gone by name at once, open handles good only for closing. A
call that was given a handle keeps the key's object until it returns,
so a handle closed under it, and a key deleted and another made
meanwhile, leave the call with the key it was asked about
(`STATUS_KEY_DELETED`) and not with whichever key has its place. No
access checks or notification. Leak checks leave out the
registry's memory, as they do the handle table's.

### Watching a key

`ZwNotifyChangeKey` (`kernel/cm/notify.rs`, rules in
`lib/cm/notify.rs`) makes a watch on a key: for some kinds of change,
with the keys below it or not. NK has the form kernel-mode callers
use, asynchronous: the call returns `STATUS_PENDING`, and the change
that meets the watch writes `STATUS_NOTIFY_ENUM_DIR` to the caller's
status block, sets its event and queues its work item (the routine's
`ApcRoutine` and `ApcContext` are a work item and its queue for a
kernel-mode caller). A watch is met once. Closing the handle it was
made through ends it and tells the watcher `STATUS_NOTIFY_CLEANUP`.
The changes seen are a value set or deleted (`ZwSetValueKey`,
`ZwDeleteValueKey`, NK's own writes) and a key made or deleted, which
is a change of name at the key above; a change made through the query
table routines' deletions or `RtlWriteRegistryValue` is not seen. A
synchronous request stops the system by name.

### Query tables

[`RtlQueryRegistryValues`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-rtlqueryregistryvalues)
and `RtlQueryRegistryValuesEx` read values as a table of entries asks:
each value goes to the entry's routine or is stored where the entry
points. What an entry's flags mean is Microsoft's to say, and
`nk_cm::query` works it out without touching a driver's memory; the
kernel (`kernel/cm/table.rs`) copies the table, reads the registry, and
does what the query says. NK's decisions:

- **The table is copied first**: every entry up to the one that ends
  it, names and default data too (a string default of length zero is
  measured). A routine that rewrites the table changes nothing for the
  call in progress.
- **The key is found once** and counted as open for the length of the
  call. Each entry reads the registry afresh, holding the lock for the
  read alone, so a routine may open, change or delete any key, this one
  included. The query sees what the routine left: a key it deleted ends
  the query with `STATUS_KEY_DELETED`.
- **A routine is lent copies** of the value's name and data in a pool
  block, never the registry's own memory. The data are followed by a
  terminator, whether or not the value was stored with one. The call
  that carries no value (`RTL_QUERY_REGISTRY_NOVALUE`) passes null for
  both.
- **A stored string** is the value without the terminator it ends
  with, and a terminator after it: a counted string without a buffer is
  given one from the pool, which the caller frees; one with a buffer
  must have room for the terminator.
- **No room is no failure**: `STATUS_BUFFER_TOO_SMALL` from delivering
  a value does not end the query, as on Windows, whether a routine
  answers it or the place an entry points to (a counted string's
  buffer, a buffer that states its size) is too small. Nothing is
  stored there, the table goes on, and the call succeeds if nothing
  else fails.
- **Several strings as one** (`REG_MULTI_SZ` with
  `RTL_QUERY_REGISTRY_NOEXPAND`) are delivered from the registry with
  one terminator more than the value holds, counted in the length, as
  Windows delivers them: `a\0bc\0\0`, 12 bytes, reaches a routine as
  14 and a counted string with a `Length` of 12.
- **Nothing is expanded**: the environment a caller passes is not
  read. A `REG_EXPAND_SZ`, value or default, asked for without
  `RTL_QUERY_REGISTRY_NOEXPAND` ends the call with
  `STATUS_INVALID_PARAMETER`, which is what the kernel of Windows 10
  answers even when the environment has the variable. With the flag it
  is delivered as stored.
- **`RelativeTo`**: `RTL_REGISTRY_OPTIONAL` changes nothing, a key that
  is not there fails the call. `RTL_REGISTRY_USER` is
  `\Registry\User\.Default`: the system is the only user.
- **The type check** (`RTL_QUERY_REGISTRY_TYPECHECK`) is made where an
  entry asks for it and demanded of none. Windows demands it of a key
  in a hive it does not trust, and that is all that tells its two
  exports apart; NK has no such hive, and the two are one routine.
- **A routine that raises** an exception is unwound through the query
  like any call into a driver ([Exceptions](exceptions.md)). All the query holds is one
  pool block, which the guard of that call gives back.

`RtlCheckRegistryKey`, `RtlCreateRegistryKey`, `RtlWriteRegistryValue`
and `RtlDeleteRegistryValue` (`kernel/cm/helper.rs`) name their key the
same way and find it by the same code. Each is what the pinned kernel
makes of it: the key opened, or for all but the check made if it is
not there (under a key that is), then the one system service; so a
value written or deleted stamps the key and tells its watchers as
`ZwSetValueKey` and `ZwDeleteValueKey` do, and deleting a value of a
key that is not there makes the key. A key given by handle is not
looked at by the check or the create, which succeed.

### The machine's description

`\Registry\Machine\Hardware\Description\System` is not in any hive
file: Windows' loader and kernel write it at every boot from what
firmware says. NK writes, after the registry is built and before any
driver starts (`kernel/hal/description.rs`, formats in
`nk_hal::description`), the keys Microsoft's drivers read: the
`MultifunctionAdapter` key whose `Identifier` is "ACPI BIOS", with the
root ACPI table's address and the firmware's memory map as an E820 map
(one range per region of the UEFI map, by kind), without which
`acpi.sys` stops the system when its device starts; and the one whose
`Identifier` is "PCI", a bus with nothing more said, as on the
reference Windows. Drivers find these by `Identifier`. Windows has an
"ISA" key before them and processor, BIOS and video keys beside them;
NK writes none of those.
