//! The executive pool: the memory behind `ExAllocatePoolWithTag`.
//!
//! Small requests come from 1 MiB arenas managed by `nk_mm::heap`; a
//! request of a page or more gets its own page-aligned run of frames, as
//! drivers expect of Windows. Both live in the direct map, so pool memory
//! is non-paged and physically contiguous.
//!
//! Every allocation is tracked: `usage()` is what the driver-unload leak
//! check compares, and a bad or overrunning free is reported, not obeyed.

use super::{PAGE_SIZE, alloc_frames, direct_to_phys, free_frames, phys_to_virt};
use crate::ke::{Rank, SpinLock};
use nk_mm::frames::Within;
use nk_mm::heap::{Arena, HeapError, Usage};

const ARENA_PAGES: usize = 256;
const MAX_ARENAS: usize = 64;
const MAX_LARGE: usize = 256;
/// Requests at least this big bypass the arenas.
const LARGE_MIN: usize = PAGE_SIZE - 64;

#[derive(Clone, Copy)]
struct Large {
    addr: usize,
    pages: usize,
    size: usize,
    tag: u32,
}

struct Pool {
    /// Each arena with the address its offsets are relative to.
    arenas: [Option<(usize, Arena<'static>)>; MAX_ARENAS],
    large: [Option<Large>; MAX_LARGE],
}

static POOL: SpinLock<Pool> = SpinLock::new(
    Rank::Pool,
    Pool {
        arenas: [const { None }; MAX_ARENAS],
        large: [None; MAX_LARGE],
    },
);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PoolError {
    /// The pointer was not returned by `alloc`, or was already freed.
    NotAllocated,
    /// The allocation was written past its end.
    Overrun { tag: u32, size: usize },
}

fn alloc_large(pool: &mut Pool, size: usize, tag: u32, within: Option<&Within>) -> *mut u8 {
    let pages = size.div_ceil(PAGE_SIZE);
    let Some(slot) = pool.large.iter_mut().find(|s| s.is_none()) else {
        return core::ptr::null_mut();
    };
    let frames = match within {
        Some(within) => super::alloc_frames_within(pages, within),
        None => alloc_frames(pages),
    };
    let Some(pa) = frames else {
        return core::ptr::null_mut();
    };
    let addr = phys_to_virt(pa);
    *slot = Some(Large {
        addr: addr as usize,
        pages,
        size,
        tag,
    });
    addr
}

/// Allocate `size` bytes labelled `tag`. Null if memory is exhausted.
/// The contents are unspecified, as with the Windows routine.
pub fn alloc(size: usize, tag: u32) -> *mut u8 {
    let mut pool = POOL.lock();
    if size >= LARGE_MIN {
        return alloc_large(&mut pool, size, tag, None);
    }
    for slot in pool.arenas.iter_mut() {
        match slot {
            Some((base, arena)) => {
                if let Some(off) = arena.alloc(size, tag) {
                    return (*base + off) as *mut u8;
                }
            }
            None => {
                // Every existing arena is full: add one.
                let Some(pa) = alloc_frames(ARENA_PAGES) else {
                    return core::ptr::null_mut();
                };
                let base = phys_to_virt(pa);
                // SAFETY: these frames were just allocated for this arena
                // and are never freed, so the slice is exclusive and
                // lives forever.
                let mem = unsafe { core::slice::from_raw_parts_mut(base, ARENA_PAGES * PAGE_SIZE) };
                let (base, arena) = slot.insert((base as usize, Arena::new(mem)));
                return arena
                    .alloc(size, tag)
                    .map_or(core::ptr::null_mut(), |off| (*base + off) as *mut u8);
            }
        }
    }
    core::ptr::null_mut()
}

/// Allocate `size` bytes labelled `tag` as whole, zeroed pages whose
/// frames are one run where `within` allows. Null if there is no such
/// run free. The block is freed like any other.
pub fn alloc_contiguous(size: usize, tag: u32, within: &Within) -> *mut u8 {
    alloc_large(&mut POOL.lock(), size.max(1), tag, Some(within))
}

/// Free an allocation. Returns its size and tag.
pub fn free(ptr: *mut u8) -> Result<(usize, u32), PoolError> {
    let addr = ptr as usize;
    let mut pool = POOL.lock();
    if let Some(slot) = pool
        .large
        .iter_mut()
        .find(|s| s.is_some_and(|l| l.addr == addr))
    {
        let l = slot.take().ok_or(PoolError::NotAllocated)?;
        free_frames(direct_to_phys(ptr), l.pages);
        return Ok((l.size, l.tag));
    }
    for (base, arena) in pool.arenas.iter_mut().flatten() {
        if (*base..*base + arena.len()).contains(&addr) {
            return arena.free(addr - *base).map_err(|e| match e {
                HeapError::Overrun { tag, size } => PoolError::Overrun { tag, size },
                HeapError::NotAllocated | HeapError::Corrupt => PoolError::NotAllocated,
            });
        }
    }
    Err(PoolError::NotAllocated)
}

/// Size and tag of the live allocation at `ptr`, if it is one.
pub fn info(ptr: *const u8) -> Option<(usize, u32)> {
    let addr = ptr as usize;
    let pool = POOL.lock();
    if let Some(l) = pool.large.iter().flatten().find(|l| l.addr == addr) {
        return Some((l.size, l.tag));
    }
    pool.arenas
        .iter()
        .flatten()
        .find(|(base, arena)| (*base..*base + arena.len()).contains(&addr))
        .and_then(|(base, arena)| arena.info(addr - *base).ok())
}

/// Allocate `size` zeroed bytes. Null if memory is exhausted.
pub fn alloc_zeroed(size: usize, tag: u32) -> *mut u8 {
    let ptr = alloc(size, tag);
    if !ptr.is_null() {
        // SAFETY: `ptr` is a fresh allocation of `size` bytes.
        unsafe { core::ptr::write_bytes(ptr, 0, size) };
    }
    ptr
}

/// Live allocations: how many, and how many bytes were asked for.
pub fn usage() -> Usage {
    let pool = POOL.lock();
    let mut total = Usage::default();
    for (_, arena) in pool.arenas.iter().flatten() {
        total.blocks += arena.usage().blocks;
        total.bytes += arena.usage().bytes;
    }
    for l in pool.large.iter().flatten() {
        total.blocks += 1;
        total.bytes += l.size;
    }
    total
}

/// Frames the pool holds: its arenas, which are kept once made, and the
/// pages of each live block too large for an arena. A leak check counts
/// blocks and bytes for what the pool hands out, so it must not count
/// these frames as lost as well: a block that only grew past a page,
/// and moved from an arena to pages of its own, is not a leak.
pub fn frames() -> u64 {
    let pool = POOL.lock();
    let arenas = pool.arenas.iter().flatten().count() * ARENA_PAGES;
    let large: usize = pool.large.iter().flatten().map(|l| l.pages).sum();
    (arenas + large) as u64
}

/// Walk every arena checking headers and guard bytes.
pub fn check() -> Result<(), HeapError> {
    POOL.lock()
        .arenas
        .iter()
        .flatten()
        .try_for_each(|(_, arena)| arena.walk(|_, _| {}))
}

pub fn self_test() -> Result<(), &'static str> {
    const TAG: u32 = u32::from_le_bytes(*b"NkTs");
    let before = usage();
    let small = alloc(100, TAG);
    let large = alloc(3 * PAGE_SIZE + 1, TAG);
    if small.is_null() || large.is_null() {
        return Err("allocation failed");
    }
    if small as usize % 16 != 0 || large as usize % PAGE_SIZE != 0 {
        return Err("small blocks must be 16-byte aligned and large ones page aligned");
    }
    // SAFETY: both blocks were just allocated with at least these sizes.
    unsafe {
        core::ptr::write_bytes(small, 0x11, 100);
        core::ptr::write_bytes(large, 0x22, 3 * PAGE_SIZE + 1);
    }
    let now = usage();
    if (now.blocks, now.bytes) != (before.blocks + 2, before.bytes + 100 + 3 * PAGE_SIZE + 1) {
        return Err("usage does not account for the allocations");
    }
    check().map_err(|_| "pool walk failed after in-bounds writes")?;
    if free(small.wrapping_add(16)) != Err(PoolError::NotAllocated) {
        return Err("free of an interior pointer was not refused");
    }
    if free(small) != Ok((100, TAG)) || free(large) != Ok((3 * PAGE_SIZE + 1, TAG)) {
        return Err("free returned the wrong size or tag");
    }
    if free(small) != Err(PoolError::NotAllocated) || free(large) != Err(PoolError::NotAllocated) {
        return Err("double free was not refused");
    }
    // An overrun must be reported at free time.
    let victim = alloc(24, TAG);
    // SAFETY: deliberately writes one byte past a 24-byte block; the
    // allocator keeps at least 8 guard bytes there for exactly this.
    unsafe { victim.add(24).write(0) };
    if free(victim) != Err(PoolError::Overrun { tag: TAG, size: 24 }) {
        return Err("overrun was not detected");
    }
    if usage() != before {
        return Err("pool leaked");
    }
    Ok(())
}

/// `POOL_QUOTA_FAIL_INSTEAD_OF_RAISE`, or'ed into the pool type.
const QUOTA_FAIL_INSTEAD_OF_RAISE: u32 = 8;
/// `POOL_RAISE_IF_ALLOCATION_FAILURE`, or'ed into the pool type.
const RAISE_IF_ALLOCATION_FAILURE: u32 = 16;

/// Raise `STATUS_INSUFFICIENT_RESOURCES` in the routine that calls
/// this, as `ExRaiseStatus` would there. The caller holds nothing an
/// unwind would have to give back.
fn raise_no_memory() -> ! {
    // SAFETY: raising is what the entry is for; it does not return.
    unsafe {
        crate::arch::seh::nk_entry_ExRaiseStatus(nk_ntabi::status::STATUS_INSUFFICIENT_RESOURCES);
    }
    crate::kd::bugcheck(format_args!("ExRaiseStatus returned"))
}

/// [`ExAllocatePoolWithTag`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-exallocatepoolwithtag).
/// Every pool type gets non-paged memory, which is always a legal answer.
/// When memory is exhausted: null, or with
/// `POOL_RAISE_IF_ALLOCATION_FAILURE` in the pool type the exception
/// `STATUS_INSUFFICIENT_RESOURCES`. The contents are unspecified.
#[allow(non_snake_case)]
pub extern "C" fn ExAllocatePoolWithTag(
    pool_type: u32,
    number_of_bytes: usize,
    tag: u32,
) -> *mut core::ffi::c_void {
    // Windows gives a zero-byte request a minimal block, not null.
    let block = alloc(number_of_bytes.max(1), tag);
    if block.is_null() && pool_type & RAISE_IF_ALLOCATION_FAILURE != 0 {
        raise_no_memory();
    }
    block.cast()
}

/// [`ExAllocatePool2`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-exallocatepool2):
/// a block of `number_of_bytes`, zeroed unless `POOL_FLAG_UNINITIALIZED`
/// is given. Each of the three pool types is given non-paged memory, as
/// `ExAllocatePoolWithTag` gives it. When memory is exhausted: null, or
/// with `POOL_FLAG_RAISE_ON_FAILURE` the exception
/// `STATUS_INSUFFICIENT_RESOURCES`.
///
/// Partial: quota charging, session pool and cache alignment, which no
/// binary NK runs asks for, stop the system by name.
#[allow(non_snake_case)]
pub extern "C" fn ExAllocatePool2(
    flags: u64,
    number_of_bytes: usize,
    tag: u32,
) -> *mut core::ffi::c_void {
    const USE_QUOTA: u64 = 0x1;
    const UNINITIALIZED: u64 = 0x2;
    const SESSION: u64 = 0x4;
    const CACHE_ALIGNED: u64 = 0x8;
    const RAISE_ON_FAILURE: u64 = 0x20;
    const NON_PAGED: u64 = 0x40;
    const NON_PAGED_EXECUTE: u64 = 0x80;
    const PAGED: u64 = 0x100;
    let unsupported = flags & (USE_QUOTA | SESSION | CACHE_ALIGNED);
    let types = flags & (NON_PAGED | NON_PAGED_EXECUTE | PAGED);
    if unsupported != 0 || types.count_ones() != 1 {
        crate::kd::bugcheck(format_args!(
            "ExAllocatePool2: NK does not implement the pool flags {flags:#x}"
        ));
    }
    let block = alloc(number_of_bytes.max(1), tag);
    if block.is_null() {
        if flags & RAISE_ON_FAILURE != 0 {
            raise_no_memory();
        }
        return core::ptr::null_mut();
    }
    if flags & UNINITIALIZED == 0 {
        // SAFETY: a fresh block of at least that many bytes.
        unsafe { block.write_bytes(0, number_of_bytes) };
    }
    block.cast()
}

/// [`ExAllocatePool`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-exallocatepool):
/// `ExAllocatePoolWithTag` under the tag Windows gives a caller that
/// names none, `None`.
#[allow(non_snake_case)]
pub extern "C" fn ExAllocatePool(pool_type: u32, number_of_bytes: usize) -> *mut core::ffi::c_void {
    ExAllocatePoolWithTag(pool_type, number_of_bytes, u32::from_le_bytes(*b"None"))
}

/// [`ExAllocatePoolWithQuotaTag`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-exallocatepoolwithquotatag).
/// NK charges no quotas: there is one process. When memory is exhausted
/// it raises `STATUS_INSUFFICIENT_RESOURCES`, unless the caller asked
/// for null instead (`POOL_QUOTA_FAIL_INSTEAD_OF_RAISE`).
#[allow(non_snake_case)]
pub extern "C" fn ExAllocatePoolWithQuotaTag(
    pool_type: u32,
    number_of_bytes: usize,
    tag: u32,
) -> *mut core::ffi::c_void {
    let block = alloc(number_of_bytes.max(1), tag);
    if block.is_null() && pool_type & QUOTA_FAIL_INSTEAD_OF_RAISE == 0 {
        raise_no_memory();
    }
    block.cast()
}

/// [`ExFreePoolWithTag`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-exfreepoolwithtag).
/// Freeing what was not allocated, or a block written past its end, stops
/// the system, as on Windows.
///
/// # Safety
/// `p` came from a pool allocation routine and is not used afterwards.
#[allow(non_snake_case)]
pub unsafe extern "C" fn ExFreePoolWithTag(p: *mut core::ffi::c_void, _tag: u32) {
    match free(p.cast()) {
        Ok(_) => {}
        Err(PoolError::NotAllocated) => crate::kd::bugcheck(format_args!(
            "0x000000C2 BAD_POOL_CALLER: free of {p:p}, which is not a live pool block"
        )),
        Err(PoolError::Overrun { tag, size }) => crate::kd::bugcheck(format_args!(
            "0x00000019 BAD_POOL_HEADER: block {p:p} (tag {tag:#x}, {size} bytes) was overrun"
        )),
    }
}

/// [`ExFreePool`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntddk/nf-ntddk-exfreepool):
/// `ExFreePoolWithTag` for a caller that names no tag.
///
/// # Safety
/// As `ExFreePoolWithTag`.
#[allow(non_snake_case)]
pub unsafe extern "C" fn ExFreePool(p: *mut core::ffi::c_void) {
    // SAFETY: per the contract.
    unsafe { ExFreePoolWithTag(p, 0) }
}

/// [`ExAllocatePoolWithTagPriority`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-exallocatepoolwithtagpriority).
/// The priority says how readily Windows may refuse when memory runs
/// low. NK refuses only when it has none, which every priority allows.
#[allow(non_snake_case)]
pub extern "C" fn ExAllocatePoolWithTagPriority(
    pool_type: u32,
    number_of_bytes: usize,
    tag: u32,
    _priority: u32,
) -> *mut core::ffi::c_void {
    ExAllocatePoolWithTag(pool_type, number_of_bytes, tag)
}

/// The variants give what the plain routines give: blocks aligned by
/// size, a block for no bytes, null (and nothing worse) for more than
/// there is; and the free that names no tag gives it all back. Returns
/// the blocks allocated and freed.
pub fn variants_test() -> Result<u32, &'static str> {
    const TAG: u32 = u32::from_le_bytes(*b"NkPv");
    /// `HighPoolPriority`, `LowPoolPriority`, `NormalPoolPriority`.
    const PRIORITIES: [u32; 3] = [32, 0, 16];
    let before = usage();
    let mut blocks = 0;
    for (size, align) in [(64, 16), (PAGE_SIZE + 64, PAGE_SIZE), (0, 16)] {
        for priority in PRIORITIES {
            let block = ExAllocatePoolWithTagPriority(1, size, TAG, priority);
            if block.is_null() {
                return Err("an allocation with a priority failed");
            }
            if block as usize % align != 0 {
                return Err("a block is not aligned as its size requires");
            }
            // SAFETY: a fresh block of `size` bytes, freed once.
            unsafe {
                block.cast::<u8>().write_bytes(0x5A, size);
                ExFreePool(block);
            }
            blocks += 1;
        }
    }
    if !ExAllocatePoolWithTagPriority(0, 1 << 46, TAG, 16).is_null() {
        return Err("more memory than there is was allocated");
    }
    if usage() != before {
        return Err("ExFreePool did not give the blocks back");
    }
    Ok(blocks)
}
