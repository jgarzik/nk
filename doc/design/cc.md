# The cache manager

Part of NK's design ([DESIGN.md](../DESIGN.md)): the principles there apply.

The cache manager keeps files' data in memory for file systems
(`Cc*`). Microsoft's file systems depend on its exact behaviour: which
routines raise and which return a status, what each handle is, when a
cache map goes away and who writes dirty data. Each rule here is the
pinned kernel's, read from its code; where NK chooses for itself, this
document says so. The memory manager's side, sections and system-cache
views, is in [Memory](memory.md).

## Rules without memory

What needs no file, lock or page lives in `lib/cc`, tested on the host:

- **The VACB index.** For each 256 KiB view of a file's section, the
  VACB mapping it: four entries inline for a section up to 1 MiB, an
  array up to 32 MiB, beyond that a tree of 128-entry leaves made on
  demand, as `CcCreateVacbArray` sizes them. Nothing is allocated while
  an entry is read or set; a leaf or a larger index is made first.
- **Section sizes.** `CcInitializeCacheMap` makes a section of the
  allocation size (0 counting as 1) rounded up to 1 MiB for a file
  object with write access and to 256 KiB for one without;
  `CcSetFileSizes` extends it to the new allocation size rounded up to
  1 MiB.
- **The MBCB.** Pages dirtied by copy and MDL writes, as bitmaps of
  4096 pages made when first needed and dropped when clean. The lazy
  writer takes runs from where its last pass stopped and goes round to
  the start; a flush takes them in offset order within its range; a
  failed write puts its run back.
- **The BCB list.** Pinned ranges sorted by offset; a pin uses the
  latest-starting BCB that wholly covers its range, or gets a BCB of its
  own, which may overlap others. Dirty runs gather the dirty BCBs that
  overlap or adjoin from the first one on. A handle is told apart as
  `CcUnpinData` tells it: bit 0 set is a mapping (the VACB plus one),
  else the node type it points at, 0x2FD for a BCB and 0x2FA for an
  OBCB.
- **Read-ahead.** `CcDetermineReadPattern`'s patterns from the last two
  reads (sequential, strided, none; "roughly equal" is within 512 bytes
  with the same high 32 bits). A sequential read is followed by the
  read's length rounded to the granularity from the page where it ended;
  a strided one by its length at the next stride. Windows' pipelined
  read-ahead is left out: no file system of the set asks for it.
- **Write-behind sizing.** The dirty-page threshold is an eighth of
  physical memory and the target three quarters of that. A pass writes
  every dirty page up to 256, else an eighth of them, plus what would
  stay above the target (three times that when available pages are
  below 4096), as `CcCalculatePagesToWrite` does.
- **Closing a cache map.** `CcUninitializeCacheMap` deletes the shared
  cache map at once only when no file object has it open, it holds no
  dirty data, no write-behind is queued, and it was cached for pinning
  or a truncate size was passed; otherwise the lazy writer deletes it
  after flushing it.

## Cache maps

- **Shared and private maps** (`kernel/cc/mod.rs`, `map.rs`). A file's
  shared cache map hangs from `SectionObjectPointer->SharedCacheMap`
  and is non-null exactly while it lives; each file object caching the
  file has a private map in `FileObject->PrivateCacheMap` (the first
  inside the shared map), and the open count is the number of private
  maps. Both are NK's structures with Windows' field names: no file
  system reads them.
- **Creation.** `CcInitializeCacheMap` puts a fresh map in
  `SharedCacheMap`, marked as being created, before the section exists;
  whoever finds a map being created or deleted waits 10 ms and looks
  again (Windows waits on an event: no binary can tell). The creator
  makes the section (`MmCreateCacheManagerSection`) with no lock held;
  a failure the file system would not expect becomes
  `STATUS_UNEXPECTED_MM_CREATE_ERR`, the half-made map is undone and
  the status raised. The map takes a reference on the file object and
  keeps it until it is deleted. A stream file object (`FsContext2`
  null) whose header lacks `FSRTL_FLAG2_DO_MODIFIED_WRITE` gets
  `MmDisableModifiedWriteOfSection`: only the cache manager writes the
  pages of a file system's metadata. A map that exists is extended for
  a larger allocation size, as `CcSetFileSizes` extends it.
- **Uninitialize.** The private map goes; a truncate size below the
  file size becomes the file size and marks the map for truncation.
  The decision is `lib/cc`'s; a map the cache manager's own work still
  holds is left for later. The caller's event is signalled once: at
  once when the file was not cached or the map was deleted in the call,
  else when the map is deleted. TRUE means deleted in this call.
- **Deletion.** The views are taken back (waiting for any in use), the
  file is purged from its size if it was truncated, the BCBs freed,
  `SharedCacheMap` cleared, the events signalled, the map freed, and the
  reference on the file object dropped last: for a stream file object
  that may send the file system its close.

## Views and pins

- **Views** (`kernel/cc/vacb.rs`). A pool of 256 VACBs (64 MiB of the
  system cache, NK's choice) is reserved at start. A view is mapped on
  first use (`MmMapViewInSystemCache`, at most 256 KiB, no I/O) and
  counts its users; one nobody uses stays mapped until its VACB is
  wanted for another view, unmapped VACBs first, then the least
  recently used. With every VACB in use, `STATUS_INSUFFICIENT_RESOURCES`;
  a memory-manager failure the file system would not expect becomes
  `STATUS_UNEXPECTED_MM_MAP_ERROR`.
- **`CcMapData`** (`kernel/cc/pin.rs`) hands back the view's VACB plus
  one. Waiting, it reads what is not in memory and raises a failed
  read's status; without waiting it returns FALSE, the handle untouched
  and the buffer cleared, if anything would need a read.
- **Pins.** `CcPinRead`, `CcPinMappedData` and `CcPreparePinWrite` find
  the BCB covering the range or make one (on a pinned metadata stream
  covering whole pages); the BCB keeps its view while pinned. On a
  stream whose modified writing is disabled a pin takes the BCB's
  resource (exclusive with `PIN_EXCLUSIVE`, else shared, starving
  exclusive waiters) and the unpin releases it; elsewhere the resource
  is not used, as `CcPinFileData` and `CcUnpinFileDataEx` decide.
  Without waiting, a pin whose resource or pages are not to be had
  undoes itself and returns FALSE. `CcPreparePinWrite` reads no page it
  overwrites whole and is dirty from the start.
- **Dirty BCBs.** `CcSetDirtyPinnedData` marks the BCB and charges its
  pages to the map and the cache; the memory manager hears of it only
  when the range is written (`MmSetAddressRangeModified`, then
  `MmFlushSection`). A BCB nobody pins goes when clean; a dirty one
  stays for its writer. `CcRepinBcb` adds a pin;
  `CcUnpinRepinnedBcb` with write-through writes a dirty range
  synchronously, never raises, and leaves the range dirty again after a
  failure the memory manager does not call fatal.
- **Not built**: a map or pin across a view's end stops the system by
  name (Windows reads past the view for a map and gives an OBCB for a
  pin; no file system of the set does either), as does
  `PIN_CALLER_TRACKS_DIRTY_DATA`.
