//! The executive pool: the memory behind `ExAllocatePoolWithTag`.
//!
//! Small requests come from 1 MiB arenas managed by `nk_mm::heap`, as
//! many as the pool needs, tried next fit; a request of a page or more
//! gets its own page-aligned run of frames, as drivers expect of
//! Windows, noted in a table (`nk_mm::pooltab`) that grows with them.
//! Both live in the direct map, so pool memory is non-paged and
//! physically contiguous. The pool's own records are in frames of their
//! own, never in the pool.
//!
//! Every allocation is tracked: `usage()` is what the driver-unload leak
//! check compares, and a bad or overrunning free is reported, not obeyed.

use super::{PAGE_SIZE, alloc_frames, direct_to_phys, free_frames, phys_to_virt};
use crate::ke::{Rank, SpinLock};
use nk_mm::frames::Within;
use nk_mm::heap::{Arena, HeapError, Usage};
use nk_mm::pooltab::{self, Entry};

const ARENA_PAGES: usize = 256;
/// Requests at least this big bypass the arenas.
const LARGE_MIN: usize = PAGE_SIZE - 64;
/// The large-block table's first size, in slots (a power of two).
const FIRST_SLOTS: usize = 512;

/// A growable array of `T` in frames of its own, never in the pool it
/// keeps: the pool's own records, which grow with it.
struct FrameVec<T> {
    ptr: *mut T,
    cap: usize,
    len: usize,
}

// SAFETY: the array is reached only under the pool's lock.
unsafe impl<T> Send for FrameVec<T> {}

impl<T> FrameVec<T> {
    const fn new() -> Self {
        Self {
            ptr: core::ptr::null_mut(),
            cap: 0,
            len: 0,
        }
    }

    fn pages(cap: usize) -> usize {
        (cap * size_of::<T>()).div_ceil(PAGE_SIZE)
    }

    /// The frames the array holds.
    fn frames(&self) -> usize {
        Self::pages(self.cap)
    }

    /// Room for at least `cap` elements, the first `len` moved; the new
    /// part is zeroed. False without frames, the array unchanged.
    fn reserve(&mut self, cap: usize) -> bool {
        if cap <= self.cap {
            return true;
        }
        let Some(pa) = alloc_frames(Self::pages(cap)) else {
            return false;
        };
        let fresh = phys_to_virt(pa).cast::<T>();
        // SAFETY: fresh, zeroed frames for `cap` elements; the old array
        // holds `len`, moved bitwise and then given back.
        unsafe {
            if !self.ptr.is_null() {
                core::ptr::copy_nonoverlapping(self.ptr, fresh, self.len);
                free_frames(direct_to_phys(self.ptr.cast()), Self::pages(self.cap));
            }
        }
        self.ptr = fresh;
        self.cap = PAGE_SIZE * Self::pages(cap) / size_of::<T>();
        true
    }

    fn as_slice(&self) -> &[T] {
        if self.ptr.is_null() {
            return &[];
        }
        // SAFETY: `len` initialised elements.
        unsafe { core::slice::from_raw_parts(self.ptr, self.len) }
    }

    fn as_mut_slice(&mut self) -> &mut [T] {
        if self.ptr.is_null() {
            return &mut [];
        }
        // SAFETY: `len` initialised elements, under the pool's lock.
        unsafe { core::slice::from_raw_parts_mut(self.ptr, self.len) }
    }
}

struct Pool {
    /// Each arena with the address its offsets are relative to, in order
    /// of address.
    arenas: FrameVec<(usize, Arena<'static>)>,
    /// The arena that last had room: the next request starts there.
    hint: usize,
    /// The large blocks: all `cap` slots in use as the table, `len`
    /// counting the entries.
    large: FrameVec<Entry>,
}

static POOL: SpinLock<Pool> = SpinLock::new(
    Rank::Pool,
    Pool {
        arenas: FrameVec::new(),
        hint: 0,
        large: FrameVec::new(),
    },
);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PoolError {
    /// The pointer was not returned by `alloc`, or was already freed.
    NotAllocated,
    /// The allocation was written past its end.
    Overrun { tag: u32, size: usize },
}

impl Pool {
    /// The large-block table's slots, all of them.
    fn slots(&mut self) -> &mut [Entry] {
        if self.large.ptr.is_null() {
            return &mut [];
        }
        // SAFETY: the table's `cap` slots are initialised (zeroed frames
        // are empty entries), under the pool's lock.
        unsafe { core::slice::from_raw_parts_mut(self.large.ptr, self.large.cap) }
    }

    /// Room for one more large block: the table doubled, its entries
    /// moved, when it would be more than three quarters full.
    fn room_for_large(&mut self) -> bool {
        let (cap, used) = (self.large.cap, self.large.len);
        if cap != 0 && !pooltab::full(cap, used) {
            return true;
        }
        let want = if cap == 0 { FIRST_SLOTS } else { cap * 2 };
        let mut bigger = FrameVec::<Entry>::new();
        if !bigger.reserve(want) {
            return false;
        }
        // The table hashes over a power of two: use exactly `want` slots.
        bigger.cap = want;
        bigger.len = used;
        // SAFETY: `want` zeroed slots in the new frames.
        let to = unsafe { core::slice::from_raw_parts_mut(bigger.ptr, want) };
        pooltab::rehash(self.slots(), to);
        let old = core::mem::replace(&mut self.large, bigger);
        if !old.ptr.is_null() {
            free_frames(
                direct_to_phys(old.ptr.cast()),
                FrameVec::<Entry>::pages(old.cap),
            );
        }
        true
    }

    /// Add an arena of fresh frames, keeping the arenas in order of
    /// address. Its index, or none without frames.
    fn add_arena(&mut self) -> Option<usize> {
        let len = self.arenas.len;
        if !self.arenas.reserve(len + 1) {
            return None;
        }
        let pa = alloc_frames(ARENA_PAGES)?;
        let base = phys_to_virt(pa);
        // SAFETY: these frames were just allocated for this arena and are
        // never freed, so the slice is exclusive and lives for ever.
        let mem = unsafe { core::slice::from_raw_parts_mut(base, ARENA_PAGES * PAGE_SIZE) };
        let at = self
            .arenas
            .as_slice()
            .partition_point(|(b, _)| *b < base as usize);
        // SAFETY: room was reserved for one more; the tail moves up one.
        unsafe {
            let p = self.arenas.ptr;
            core::ptr::copy(p.add(at), p.add(at + 1), len - at);
            p.add(at).write((base as usize, Arena::new(mem)));
        }
        self.arenas.len = len + 1;
        Some(at)
    }

    /// The arena holding `addr`.
    fn arena_of(&mut self, addr: usize) -> Option<&mut (usize, Arena<'static>)> {
        let arenas = self.arenas.as_mut_slice();
        let at = arenas.partition_point(|(b, _)| *b <= addr).checked_sub(1)?;
        let entry = &mut arenas[at];
        (addr < entry.0 + entry.1.len()).then_some(entry)
    }
}

fn alloc_large(pool: &mut Pool, size: usize, tag: u32, within: Option<&Within>) -> *mut u8 {
    if !pool.room_for_large() {
        return core::ptr::null_mut();
    }
    let pages = size.div_ceil(PAGE_SIZE);
    let frames = match within {
        Some(within) => super::alloc_frames_within(pages, within),
        None => alloc_frames(pages),
    };
    let Some(pa) = frames else {
        return core::ptr::null_mut();
    };
    let addr = phys_to_virt(pa);
    pooltab::insert(
        pool.slots(),
        Entry {
            addr: addr as usize,
            pages,
            size,
            tag,
        },
    );
    pool.large.len += 1;
    addr
}

/// Allocate `size` bytes labelled `tag`. Null if memory is exhausted.
/// The contents are unspecified, as with the Windows routine.
pub fn alloc(size: usize, tag: u32) -> *mut u8 {
    let mut pool = POOL.lock();
    if size >= LARGE_MIN {
        return alloc_large(&mut pool, size, tag, None);
    }
    // Next fit over the arenas, from the one that last had room.
    let count = pool.arenas.len;
    let first = pool.hint;
    for step in 0..count {
        let at = (first + step) % count;
        let (base, arena) = &mut pool.arenas.as_mut_slice()[at];
        if let Some(off) = arena.alloc(size, tag) {
            let block = (*base + off) as *mut u8;
            pool.hint = at;
            return block;
        }
    }
    let Some(at) = pool.add_arena() else {
        return core::ptr::null_mut();
    };
    pool.hint = at;
    let (base, arena) = &mut pool.arenas.as_mut_slice()[at];
    arena
        .alloc(size, tag)
        .map_or(core::ptr::null_mut(), |off| (*base + off) as *mut u8)
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
    if let Some(l) = pooltab::remove(pool.slots(), addr) {
        pool.large.len -= 1;
        free_frames(direct_to_phys(ptr), l.pages);
        return Ok((l.size, l.tag));
    }
    let (base, arena) = pool.arena_of(addr).ok_or(PoolError::NotAllocated)?;
    arena.free(addr - *base).map_err(|e| match e {
        HeapError::Overrun { tag, size } => PoolError::Overrun { tag, size },
        HeapError::NotAllocated | HeapError::Corrupt => PoolError::NotAllocated,
    })
}

/// Size and tag of the live allocation at `ptr`, if it is one.
pub fn info(ptr: *const u8) -> Option<(usize, u32)> {
    let addr = ptr as usize;
    let mut pool = POOL.lock();
    if let Some(at) = pooltab::find(pool.slots(), addr) {
        let l = pool.slots()[at];
        return Some((l.size, l.tag));
    }
    let (base, arena) = pool.arena_of(addr)?;
    arena.info(addr - *base).ok()
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
    let mut pool = POOL.lock();
    let mut total = Usage::default();
    for (_, arena) in pool.arenas.as_slice() {
        total.blocks += arena.usage().blocks;
        total.bytes += arena.usage().bytes;
    }
    for l in pool.slots().iter().filter(|l| l.addr != 0) {
        total.blocks += 1;
        total.bytes += l.size;
    }
    total
}

/// Frames the pool holds: its arenas, which are kept once made, the
/// pages of each live block too large for an arena, and its own records
/// of both. A leak check counts blocks and bytes for what the pool hands
/// out, so it must not count these frames as lost as well: a block that
/// only grew past a page, and moved from an arena to pages of its own,
/// is not a leak, nor is the record that grew to note it.
pub fn frames() -> u64 {
    let mut pool = POOL.lock();
    let arenas = pool.arenas.len * ARENA_PAGES + pool.arenas.frames();
    let large: usize = pool
        .slots()
        .iter()
        .filter(|l| l.addr != 0)
        .map(|l| l.pages)
        .sum();
    (arenas + large + pool.large.frames()) as u64
}

/// Walk every arena checking headers and guard bytes.
pub fn check() -> Result<(), HeapError> {
    POOL.lock()
        .arenas
        .as_slice()
        .iter()
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
    // More large blocks at once than the table's first size holds, and
    // more than the pool once allowed: the record grows and every block
    // is still found.
    let mut many = alloc::vec::Vec::new();
    many.try_reserve_exact(600)
        .map_err(|_| "no memory for the list")?;
    for i in 0..600 {
        let block = alloc(PAGE_SIZE, TAG ^ i);
        if block.is_null() {
            return Err("a large block was refused");
        }
        many.push(block);
    }
    for (i, &block) in many.iter().enumerate() {
        if info(block) != Some((PAGE_SIZE, TAG ^ i as u32)) {
            return Err("a large block's record was lost as the table grew");
        }
    }
    for block in many.drain(..) {
        free(block).map_err(|_| "a large block could not be freed")?;
    }
    drop(many);
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
