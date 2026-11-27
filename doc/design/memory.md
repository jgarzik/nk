# Memory

Part of NK's design ([DESIGN.md](../DESIGN.md)): the principles there apply.

## Memory

- **Frames.** A bitmap allocator over `EfiConventionalMemory` only,
  never below 1 MiB. Loader allocations and firmware boot-services memory
  stay reserved.
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
