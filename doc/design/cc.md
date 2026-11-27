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
