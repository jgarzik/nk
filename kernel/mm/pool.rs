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

fn alloc_large(pool: &mut Pool, size: usize, tag: u32) -> *mut u8 {
    let pages = size.div_ceil(PAGE_SIZE);
    let Some(slot) = pool.large.iter_mut().find(|s| s.is_none()) else {
        return core::ptr::null_mut();
    };
    let Some(pa) = alloc_frames(pages) else {
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
        return alloc_large(&mut pool, size, tag);
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

/// Frames held as arenas. An arena is kept once made, so a leak check
/// must not count its frames as lost.
pub fn arena_frames() -> u64 {
    (POOL.lock().arenas.iter().flatten().count() * ARENA_PAGES) as u64
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

/// [`ExAllocatePoolWithTag`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-exallocatepoolwithtag).
/// Every pool type gets non-paged memory, which is always a legal answer.
/// Null if memory is exhausted; the contents are unspecified.
#[allow(non_snake_case)]
pub extern "C" fn ExAllocatePoolWithTag(
    _pool_type: u32,
    number_of_bytes: usize,
    tag: u32,
) -> *mut core::ffi::c_void {
    // Windows gives a zero-byte request a minimal block, not null.
    alloc(number_of_bytes.max(1), tag).cast()
}

/// `POOL_QUOTA_FAIL_INSTEAD_OF_RAISE`, or'ed into the pool type.
const QUOTA_FAIL_INSTEAD_OF_RAISE: u32 = 8;

/// [`ExAllocatePoolWithQuotaTag`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-exallocatepoolwithquotatag).
/// NK charges no quotas: there is one process. On failure Windows raises
/// an exception unless the caller asked for null instead; NK has no
/// exceptions to raise yet, and an unhandled one stops Windows too.
#[allow(non_snake_case)]
pub extern "C" fn ExAllocatePoolWithQuotaTag(
    pool_type: u32,
    number_of_bytes: usize,
    tag: u32,
) -> *mut core::ffi::c_void {
    let block = alloc(number_of_bytes.max(1), tag);
    if block.is_null() && pool_type & QUOTA_FAIL_INSTEAD_OF_RAISE == 0 {
        crate::kd::bugcheck(format_args!(
            "0x0000001E KMODE_EXCEPTION_NOT_HANDLED: STATUS_INSUFFICIENT_RESOURCES \
             (a pool allocation with quota of {number_of_bytes} bytes failed)"
        ));
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
