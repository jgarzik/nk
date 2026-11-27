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
- **Pool.** Small requests come from 1 MiB arenas at 16-byte alignment;
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
