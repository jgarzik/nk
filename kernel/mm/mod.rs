//! Memory manager: physical frames, kernel mappings, the pool.
//!
//! The arithmetic lives in `lib/mm`, where the host tests it. This module
//! binds it to real memory.
//!
//! Only `EfiConventionalMemory` is handed to the frame allocator. Memory
//! the loader allocated and firmware's boot-services memory stay
//! reserved: on arm64 the latter still holds firmware's live page tables.

pub mod map;
pub mod pool;
pub mod stack;

use crate::ke::{Rank, SpinLock};
use core::sync::atomic::{AtomicU64, Ordering};
use nk_bootinfo::{BootInfo, EFI_CONVENTIONAL, regions};
use nk_mm::frames::FrameBitmap;

pub const PAGE_SIZE: usize = 4096;
/// Frames below 1 MiB are never allocated: legacy firmware and devices
/// make assumptions about that range that are not worth discovering.
const LOW_RESERVED_FRAMES: u64 = 256;

static HHDM: AtomicU64 = AtomicU64::new(0);
static FRAMES: SpinLock<Option<FrameBitmap<'static>>> = SpinLock::new(Rank::Frames, None);

/// The direct-map address of physical address `pa`.
pub fn phys_to_virt(pa: u64) -> *mut u8 {
    (HHDM.load(Ordering::Relaxed) + pa) as *mut u8
}

/// The physical address behind a direct-map pointer.
pub fn direct_to_phys(ptr: *const u8) -> u64 {
    ptr as u64 - HHDM.load(Ordering::Relaxed)
}

/// Set up the frame allocator from the firmware memory map.
pub fn init(info: &BootInfo) -> Result<(), &'static str> {
    HHDM.store(info.hhdm_base, Ordering::Relaxed);
    // SAFETY: the loader left `mmap_len` bytes of memory map at
    // `mmap_phys` in loader-reserved memory, reachable through the direct
    // map and never written again.
    let map = unsafe {
        core::slice::from_raw_parts(phys_to_virt(info.mmap_phys), info.mmap_len as usize)
    };
    let usable =
        || regions(map, info.mmap_desc_size as usize).filter(|r| r.kind == EFI_CONVENTIONAL);

    let nframes = usable()
        .map(|r| r.end() / PAGE_SIZE as u64)
        .max()
        .ok_or("no usable memory")?;
    let words = FrameBitmap::words_for(nframes);
    let bitmap_frames = (words * 8).div_ceil(PAGE_SIZE) as u64;
    // The bitmap lives at the start of the largest usable region.
    let home = usable()
        .max_by_key(|r| r.pages)
        .filter(|r| r.pages > bitmap_frames);
    let home = home.ok_or("no region large enough for the frame bitmap")?;
    // SAFETY: `home` is free RAM per the memory map, large enough for
    // `words` u64s, page aligned, and reserved below so nothing else is
    // ever handed this storage.
    let bits =
        unsafe { core::slice::from_raw_parts_mut(phys_to_virt(home.phys).cast::<u64>(), words) };

    let mut frames = FrameBitmap::new(bits, nframes);
    for r in usable() {
        frames.release(r.phys / PAGE_SIZE as u64, r.pages);
    }
    frames.reserve(home.phys / PAGE_SIZE as u64, bitmap_frames);
    frames.reserve(0, LOW_RESERVED_FRAMES);
    *FRAMES.lock() = Some(frames);
    Ok(())
}

/// The physical address behind the direct-map address `va`.
pub fn virt_to_phys(va: *const u8) -> u64 {
    va as u64 - HHDM.load(Ordering::Relaxed)
}

/// Allocate `count` contiguous, zeroed frames. Returns the physical address.
pub fn alloc_frames(count: usize) -> Option<u64> {
    let pfn = FRAMES.lock().as_mut()?.alloc(count as u64)?;
    let pa = pfn * PAGE_SIZE as u64;
    // SAFETY: the allocator just gave us exclusive ownership of these
    // frames, and the direct map covers all RAM.
    unsafe { core::ptr::write_bytes(phys_to_virt(pa), 0, count * PAGE_SIZE) };
    Some(pa)
}

/// Return frames from `alloc_frames`. A double free is a kernel bug.
pub fn free_frames(pa: u64, count: usize) {
    let ok = FRAMES
        .lock()
        .as_mut()
        .is_some_and(|f| f.dealloc(pa / PAGE_SIZE as u64, count as u64));
    assert!(ok, "free of frames not allocated: {pa:#x} x{count}");
}

pub fn free_frame_count() -> u64 {
    FRAMES.lock().as_ref().map_or(0, |f| f.free_frames())
}

/// Frames: allocate, write, free, and get the same count back.
pub fn frames_self_test() -> Result<(), &'static str> {
    let before = free_frame_count();
    let a = alloc_frames(1).ok_or("cannot allocate one frame")?;
    let b = alloc_frames(16).ok_or("cannot allocate 16 contiguous frames")?;
    if a == b || a % PAGE_SIZE as u64 != 0 || b % PAGE_SIZE as u64 != 0 {
        return Err("bad frame addresses");
    }
    // SAFETY: both runs were just allocated to us and are in the direct map.
    unsafe {
        let p = phys_to_virt(b);
        if (0..16 * PAGE_SIZE).any(|i| p.add(i).read() != 0) {
            return Err("frames are not zeroed");
        }
        p.add(16 * PAGE_SIZE - 1).write(0xA5);
    }
    if free_frame_count() != before - 17 {
        return Err("free count did not drop by 17");
    }
    free_frames(a, 1);
    free_frames(b, 16);
    if free_frame_count() != before {
        return Err("frames leaked");
    }
    Ok(())
}
