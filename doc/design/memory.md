# Memory

Part of NK's design ([DESIGN.md](../DESIGN.md)): the principles there apply.

## Memory

- **Frames.** A bitmap allocator over `EfiConventionalMemory` only,
  never below 1 MiB. Loader allocations and firmware boot-services memory
  stay reserved. The bitmap hands out single frames and the contiguous
  runs the pool, stacks and DMA buffers need.
- **PFN database.** One entry per frame up to the highest usable one
  (`lib/mm/pfn.rs`, `kernel/mm/pfn.rs`), allocated at boot, behind the
  same lock as the bitmap (rank 60). The states are Windows' `_MMLISTS`:
  zeroed, free, standby, modified, modified-no-write, bad, active,
  transition. Free and zeroed frames are the bitmap's: NK zeroes a frame
  as it hands it out, so no zeroed list is kept and no zeroing thread
  runs. Standby, modified, modified-no-write and bad are lists linked
  through the entries. The counts follow Windows: `share_count` counts
  the valid PTEs mapping a frame, `ref_count` one for "mapped" plus one
  per I/O or lock; a frame goes onto a list only when `ref_count` reaches
  zero, standby if clean, modified if dirty, modified-no-write if its
  section is written only by the cache manager. The entry's layout is
  NK's (no driver sees `_MMPFN`).
- **Pool.** Small requests come from 1 MiB arenas at 16-byte alignment,
  staying within a single 4 KiB page (so neither the payload nor
  `payload + 16` is page-aligned, matching Windows' executive pool
  invariant relied on by KMDF `FxPoolFree`);
  requests of about a page or more get their own page-aligned frames, as
  on Windows. All pool is in the direct map: non-paged and physically
  contiguous. A paged-pool request gets non-paged memory, always a legal
  answer. A request's priority (`ExAllocatePoolWithTagPriority`) is not
  used: NK refuses only when it has no memory, which every priority
  allows. A refusal is null, or the exception
  `STATUS_INSUFFICIENT_RESOURCES` raised in the caller where Microsoft
  documents one: a quota allocation without
  `POOL_QUOTA_FAIL_INSTEAD_OF_RAISE`, any allocation with
  `POOL_RAISE_IF_ALLOCATION_FAILURE`.
- **Pool checking.** Each block ends in guard bytes checked on free, a
  free of anything but a live block is refused, and live counts are kept;
  leak tests compare them. These are bug detectors, not mitigations.
- **Dynamic mappings.** Address space is bump-allocated with one unmapped
  page after each range, plus a small cache of freed ranges reused by
  exact size, so a driver loaded and unloaded repeatedly lands on the
  same addresses and leak checks can compare frame counts. Frames are
  freed on unmap; intermediate page tables never are.
- **Kernel stacks.** 32 KiB, with 32 KiB unmapped below. The top is a
  multiple of 64 KiB, so one address bit is 1 across the stack and 0
  across the gap. x86-64 takes the overflow as a double fault on its own
  IST stack and recognises it by the faulting address. arm64 takes
  exceptions on the current stack, so exception entry tests that bit of
  the stack pointer before storing anything and reports from a
  per-processor overflow stack. Windows' stacks are 24 KiB on x86-64; no
  driver can depend on the size.

## Files in memory

Phase 4 adds pageable memory of one kind: a file's pages, mapped in the
system cache for the cache manager. Pool stays non-paged and driver
images stay resident. Microsoft's file systems see the memory manager
only through `SECTION_OBJECT_POINTERS`, paging IRPs, MDLs and a few
exports; the rest is NK's design, following Windows' semantics (and
Windows' x64 software PTE formats, `lib/mm/pte.rs`).

- **Sections** (`kernel/mm/section.rs`). One data control area per file,
  named by `SectionObjectPointer->DataSectionObject`, which is non-null
  exactly while the control area lives. It keeps Windows' counts
  (sections, views, system-cache views, frames, user references,
  locked pages starting at 1, flushes) and `_MMSECTION_FLAGS`. Its
  subsections cover 256 KiB each, one system-cache view, and hold that
  range's 64 prototype PTEs; one is made when a view or a read-ahead
  first needs it and freed when nothing maps it and none of its pages
  is in memory, as Windows makes and frees a mapped file's prototype
  PTEs per range. A prototype PTE of a page that is only in the file
  is in subsection format. `MmCreateCacheManagerSection` takes the size
  it is given (the cache manager's allocation size rounded to 1 MiB)
  and does no I/O. A section object (type `Section`) holds the control
  area. When no section, view, frame or flush holds a control area
  (`MiCheckControlArea`), `DataSectionObject` is cleared and the area is
  freed with its reference to the file, which may send the file system
  its close. Clean pages on standby keep the control area, and so the
  file object, alive until they are reused or purged, as on Windows.
- **System-cache views** (`kernel/mm/cache.rs`). A region of 4 GiB of
  256 KiB slots whose page tables are made when the cache manager
  reserves its slots and never freed; its entries are written under
  the PFN lock, never through `mm::map`. Mapping a view writes
  prototype pointers; unmapping moves each valid entry's dirty bit to
  the PFN entry, drops the translations on every processor in one
  request, and lists the pages nothing else holds. On arm64 NK does not
  enable hardware dirty tracking, so a writable entry counts as dirty.
- **Page faults.** A fault on a mapped page of a view, taken in kernel
  mode with interrupts on below `DISPATCH_LEVEL`, is resolved before the kernel's
  rule that a fault on a kernel address stops the system (bugcheck 0x50
  stays for an address nothing maps; 0xA/0xD1 for a fault that may not
  wait). As in `MmAccessFault`, a user-mode access, an execution, or
  a write to a valid entry that refuses it is no page to bring in and
  falls to those rules (`pte::view_fault`, host-tested); a fault on an
  entry another processor made valid meanwhile runs the access again.
  A read that fails is raised in the faulting code as
  `STATUS_IN_PAGE_ERROR` with the access, the address and the read's
  status, as Microsoft documents `EXCEPTION_IN_PAGE_ERROR`; a kernel
  copy routine with a fix-up returns its error instead.
  `MmProbeAndLockPages` brings a view's page in and holds its frame
  (a reference, and one more locked page in the control area) until
  `MmUnlockPages`.
- **Resolving a page** (`kernel/mm/fault.rs`), one path for every
  caller: valid, soft (off a list), collided (wait for the read in
  flight, then again) or hard. A hard fault reads the page and up to 15
  after it that are in the file only, within the subsection and the
  section, in one synchronous paging read
  (`IRP_NOCACHE|IRP_PAGING_IO|IRP_SYNCHRONOUS_PAGING_IO`, `io::paging`,
  completed inline with no APC as Windows completes it); no cluster
  when `MmIsRecursiveIoFault`. The faulting page is mapped, the rest go
  to standby, and what the file system did not return is zero. A read
  that fails frees its frames, restores the prototype PTEs, and gives
  its status to the faulting thread and every waiter. A driver's system
  mapping of the paging MDL is undone when the read is over.
  `MmCheckCachedPageStates` (`make_resident`) resolves each page of a
  range, with no read for pages the caller overwrites whole, or stops
  at the first that would need one; `MmCopyToCachedPage` never reads.
  Read-ahead for the cache manager reads into standby before it
  returns.
- **Paging requests** are waited for only when the file system
  returns `STATUS_PENDING`; a request that could not be sent for want of
  an IRP fails the fault or the write with
  `STATUS_INSUFFICIENT_RESOURCES`.
- **Flush** (`kernel/mm/flush.rs`, `MmFlushSection`): the range's
  modified pages (a view's dirty bits first moved to the PFN entries)
  are written in runs of at most 16 contiguous pages by synchronous
  paging writes, with `ETHREAD.CacheManagerActive` set around them; the
  cache manager passes FsRtl's acquire and release routines when the
  file is to be acquired. A page is clean once its write starts; a
  failed write leaves its pages modified, and one that failed for want
  of memory or over a bad sector is tried again page by page
  (`MiIsRetryIoStatus`). `MmCanFileBeTruncated`, `MmFlushImageSection`
  and `MmDoesFileHaveUserWritableReferences` follow Windows' checks; NK
  makes no image sections.
- **Purge** (`kernel/mm/flush.rs`): Windows' rule
  (`MiCanFileBeTruncatedInternal` with the purge's checks, host-tested
  in `lib/mm/section.rs`) decides; a page a view still maps leaves the
  view first; a page under I/O or locked refuses the purge.
- **Memory pressure.** When the frame bitmap is empty the oldest standby
  page is taken from its file. What that leaves unused is freed by the
  next memory-manager call, never under the PFN lock.

## Designed, not yet built

- **Page writers and trimming.** The mapped-page writer is a system
  thread woken when the modified list passes a threshold or on a timer.
  It takes pages of control areas without `NoModifiedWriting` off the
  modified list, clustered by file offset (at most 16 pages per
  write), acquires the file through FsRtl's acquire-for-mod-write, and
  writes with `IoAsynchronousPageWrite` (flags `IRP_NOCACHE |
  IRP_PAGING_IO`, 0x3, no event). Completion is a special kernel APC to
  the writer thread (`IopCompletePageWrite`), which settles the pages as
  a flush does. It never writes modified-no-write pages. With no paging
  file, the modified-page writer has nothing to write and does not
  exist. The trimmer takes valid pages out of system-cache views the
  cache manager holds inactive, oldest first, when available pages fall
  below a low mark; the cache manager's own unmapping of inactive views
  is the first relief. Both wait for kernel APCs and for the thresholds
  and aging read from the pinned kernel (`MiMappedPageWriter`,
  `MiGatherMappedPages`, `MiTrimWorkingSet`).
- **Image sections.** A separate control area hangs from
  `SectionObjectPointer->ImageSectionObject`. The PE headers are read at
  creation through a paging read; each PE section becomes a subsection
  with its protection; pages are shared read-only across mappings and
  writable sections are copy-on-write; relocation happens as pages are
  read when the image cannot load at its preferred base. Views go
  through VADs. NK's loader keeps loading drivers itself unless a binary
  can tell. Until then `ImageSectionObject` is always null, and the
  routines that would delete an image section (`MmFlushImageSection`,
  the first step of `MmCanFileBeTruncated`) find none.
- **User address spaces (VADs).** One address space per process: the
  page-table root (`KPROCESS.DirectoryTableBase`), an AVL tree of VADs
  keyed by page number (private, mapped, image), a working set, and the
  address-creation push lock taken before the PFN lock. Faults in the
  user half go through the same resolver; one with no VAD raises
  `STATUS_ACCESS_VIOLATION`. `Nt/ZwAllocateVirtualMemory`,
  `MmMapViewOfSection` and their kin build on VADs. Paging-file-backed
  sections are anonymous memory committed against RAM: with no paging
  file, anonymous pages are never written out or trimmed, and a commit
  beyond physical memory less a reserve fails with
  `STATUS_COMMITMENT_LIMIT`.
