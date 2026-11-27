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
  synchronously (the file taken for the flush through FsRtl,
  [FsRtl](fsrtl.md)), never raises, and leaves the range dirty again after a
  failure the memory manager does not call fatal.
- **Not built**: a map or pin across a view's end stops the system by
  name (Windows reads past the view for a map and gives an OBCB for a
  pin; no file system of the set does either), as does
  `PIN_CALLER_TRACKS_DIRTY_DATA`.

## Copies, MDLs and dirty data

- **Copy reads** (`kernel/cc/copy.rs`). `CcCopyReadEx` of bytes past
  the file size stops the system (0x34, 0x273), as Windows' does: a file
  system clamps first. View by view, the pages are made resident (or,
  without waiting, the call returns FALSE, the status block untouched)
  and copied; a fault on the buffer raises
  `STATUS_INVALID_USER_BUFFER`, a failed read its status (or
  `STATUS_UNEXPECTED_IO_ERROR` when a file system would not expect it).
  The file object's read history is rotated and a read-ahead queued as
  its pattern calls for (`CcMdlRead` too).
- **Copy writes.** `CcCopyWrite` and `CcCopyWriteEx` make no read of a
  page they overwrite whole or of one wholly at or beyond the valid
  data length in the FCB header (`MmCopyToCachedPage`: the rest of such
  a page is zero); other pages are read in. The range is marked in the
  map's dirty-page bitmap and charged. Without waiting, a write-through
  file object returns FALSE at once; with write-through the range is
  flushed before returning and a failure raised.
- **MDLs** (`kernel/cc/mdl.rs`). `CcMdlRead` and `CcPrepareMdlWrite`
  lock the cache's pages into one MDL per view, chained. A prepared
  write reads only pages it covers in part and keeps the map open until
  `CcMdlWriteComplete` (which marks the range modified in the memory
  manager, as locking pages for writing does on Windows, then dirty, or
  writes it through) or `CcMdlWriteAbort`. The completions go through
  the file system's `MdlReadComplete`/`MdlWriteComplete` when it has
  them.
- **Flushes** (`kernel/cc/flush.rs`). A flush takes the dirty runs in
  offset order, the dirty BCBs' first (each BCB's resource taken
  exclusive on a metadata stream, waiting for its pinners, and its
  range handed to the memory manager as modified), then the bitmap's,
  at most 16 pages a write, each written by `MmFlushSection` with the
  file taken through FsRtl. A failed write leaves its run dirty unless
  the memory manager calls the error fatal; a range flush ends with a
  flush of the whole range for pages dirtied elsewhere. Write errors are
  returned, never raised. With no cache map the section is flushed.
  `CcIsThereDirtyData` looks for a map on the volume with dirty pages.

## Sizes and purges

- **`CcSetFileSizes`** (`kernel/cc/size.rs`) extends the section for a
  larger allocation (rounded up to 1 MiB; an unexpected failure becomes
  `STATUS_UNEXPECTED_MM_EXTEND_ERR`, raised by `CcSetFileSizes` and
  returned by `CcSetFileSizesEx`). A smaller file size, on a map not
  cached for pinning, takes back the views beyond it, forgets the dirt
  there and purges from the page boundary at or after it; the valid data
  length only goes down. With no map, the section is purged beyond the
  new size. Windows zeroes the tail of the last page when a purge is
  refused; NK leaves it, and purges whole pages only.
- **`CcPurgeCacheSection`** fails if a view in the range is in use or
  the memory manager refuses (and, for a purge to the end, if the file
  cannot be truncated there); otherwise the pages are discarded with
  their dirt. Bit 0 stops every file object caching the file first.
  A purge that collides with I/O in progress fails rather than waiting
  and trying again. **`CcCoherencyFlushAndPurgeCache`** flushes, then
  purges unless told not to; a refused purge makes the status
  `STATUS_CACHE_PAGE_LOCKED`. NK maps files in no user view, so there is
  no user view's dirt to gather.
- **`CcZeroData`** zeroes through the cache, reading no page it zeroes
  whole, and marks the range dirty. Zeroing a file that is not cached
  (on disk, `MmZeroPageWrite`) is not built and stops the system by
  name.
- **Attributes.** `CcSetReadAheadGranularity` sets the file object's
  read-ahead mask unchecked. `CcSetAdditionalCacheAttributes` sets the
  map's no-read-ahead and no-write-behind flags; turning write-behind off
  also turns modified writing off, which turning it on does not undo.
  The `Ex` form takes those from bits 1 and 2 and records its other bits
  as the pinned kernel records them.

## The lazy writer

- **Scans** (`kernel/cc/lazy.rs`). The first dirt arms the scan timer
  for 3 s (`CcFirstDelay`); while dirt remains, or a map waits to be
  closed, it is armed again every second (`CcIdleDelay`). Its DPC has a
  worker scan: the pages to write (`lib/cc`, from the cache's dirty
  pages, the pages throttled writers wait for, the threshold and target,
  and the available pages), then a write-behind queued for each map with
  dirty data (unless write-behind is off and the map is still open) or
  open by nobody, at most 64 a scan, each with its share of the pages.
- **Write-behind.** On a worker, the file is taken through the file
  system's `AcquireForLazyWrite` (FALSE: the next scan tries again), the
  share flushed, the file given back with `ReleaseFromLazyWrite`; the
  cache manager sets no top-level IRP, the file system's callbacks do.
  Deferred writes are posted after it.
- **Lazy close.** A map nobody has open, nothing dirties and no other
  work holds is deleted after its write-behind, which keeps its own
  reference on the map until the decision is taken, with its file taken through
  `FsRtlAcquireFileExclusive` and given back with `FsRtlReleaseFile`
  ([FsRtl](fsrtl.md)); dropping the map's file object then may send a
  stream file object's close from the worker.
- **Workers.** Scans, write-behinds and read-aheads run on the
  executive's critical work queue (`ex::work`), as on Windows, bounded
  by a small pool of reusable work items (`2 + cpus / 4`, at most 8)
  draining the cache manager's queue under `DIRTY`. Read-ahead runs
  between the file system's `AcquireForReadAhead` and
  `ReleaseFromReadAhead` (FALSE skips it) with the memory manager's
  prefetch, and never raises.
- **Throttling** (`kernel/cc/throttle.rs`). `CcCanIWrite` lets a write go
  while the cache's dirty pages and its own stay within the threshold
  and no writer is queued before it; otherwise FALSE, or with `Wait` a
  wait on an entry of the deferred-write queue (first when retrying).
  `CcDeferWrite` queues the file system's post routine, or calls it at
  once when its entry cannot be had. The queue is served in order as
  dirty pages are written. Windows' soft throttle and the memory check
  for the write are not built.
- **Waiting for it.** `CcWaitForCurrentLazyWriterActivity` runs a scan at
  once, which writes every dirty page (NK's choice for a scan asked
  for), attaches a barrier behind that scan, and returns once no scan or
  item remains queued or running: concurrent waiters never wait for each
  other. The I/O manager's shutdown calls it after every file system has
  had its shutdown request, where Windows calls it.
