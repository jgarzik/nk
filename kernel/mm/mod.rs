//! Memory manager: physical frames and their database, kernel mappings,
//! the pool.
//!
//! The arithmetic lives in `lib/mm`, where the host tests it. This module
//! binds it to real memory.
//!
//! Only `EfiConventionalMemory` is handed to the frame allocator. Memory
//! the loader allocated and firmware's boot-services memory stay
//! reserved.

pub mod cache;
pub mod contig;
pub mod fault;
pub mod flush;
pub mod io;
pub mod map;
pub mod pfn;
pub mod pool;
pub mod section;
pub mod space;
pub mod stack;
pub mod user;
pub mod view;
pub mod vm;

use core::sync::atomic::{AtomicU64, Ordering};
use nk_bootinfo::{BootInfo, EFI_CONVENTIONAL, FirmwareUse, MemRegion, regions};
use nk_mm::frames::{Layout, LayoutError, Within};

pub const PAGE_SIZE: usize = 4096;
static HHDM: AtomicU64 = AtomicU64::new(0);
/// Where RAM ends, once `init` has run.
static RAM_TOP: AtomicU64 = AtomicU64::new(0);

/// The direct-map address of physical address `pa`.
pub fn phys_to_virt(pa: u64) -> *mut u8 {
    (HHDM.load(Ordering::Relaxed) + pa) as *mut u8
}

/// The physical address behind a direct-map pointer.
pub fn direct_to_phys(ptr: *const u8) -> u64 {
    ptr as u64 - HHDM.load(Ordering::Relaxed)
}

/// Where the loader left firmware's memory map: physical address, bytes,
/// and bytes per descriptor.
static MEMORY_MAP: [AtomicU64; 3] = [const { AtomicU64::new(0) }; 3];

/// The regions of firmware's memory map, once `init` has run.
fn memory_map() -> impl Iterator<Item = MemRegion> {
    let [phys, len, desc_size] = [0, 1, 2].map(|i| MEMORY_MAP[i].load(Ordering::Relaxed));
    // SAFETY: the loader left `len` bytes of memory map at `phys` in
    // loader-reserved memory, reachable through the direct map and never
    // written again.
    let map = unsafe { core::slice::from_raw_parts(phys_to_virt(phys), len as usize) };
    regions(map, desc_size as usize)
}

/// The memory firmware's runtime services use, code and data: what the
/// low half of the address space holds, each region at its physical
/// address.
pub fn firmware_regions() -> impl Iterator<Item = (MemRegion, FirmwareUse)> {
    memory_map().filter_map(|r| match r.firmware_use() {
        Some(FirmwareUse::LoaderCode) | None => None,
        Some(use_) => Some((r, use_)),
    })
}

/// Set up the frame allocator and the page-frame-number database from
/// the firmware memory map.
pub fn init(info: &BootInfo) -> Result<(), &'static str> {
    HHDM.store(info.hhdm_base, Ordering::Relaxed);
    for (slot, value) in MEMORY_MAP
        .iter()
        .zip([info.mmap_phys, info.mmap_len, info.mmap_desc_size])
    {
        slot.store(value, Ordering::Relaxed);
    }
    let ram_top = memory_map().filter(|r| r.is_ram()).map(|r| r.end()).max();
    RAM_TOP.store(ram_top.unwrap_or(0), Ordering::Relaxed);
    let usable = || {
        memory_map()
            .filter(|r| r.kind == EFI_CONVENTIONAL)
            .map(|r| (r.phys, r.pages))
    };
    let layout = Layout::of(usable()).map_err(|e| match e {
        LayoutError::NoMemory => "no usable memory",
        LayoutError::NoRoom => "no region large enough for the frame bitmap",
    })?;
    // SAFETY: `home` is free RAM per the memory map, large enough for
    // `words` u64s, page aligned, and reserved by `build` so nothing
    // else is ever handed this storage.
    let bits = unsafe {
        core::slice::from_raw_parts_mut(phys_to_virt(layout.home).cast::<u64>(), layout.words)
    };
    pfn::init(layout.build(bits, usable()), layout.nframes)
}

/// Allocate `count` contiguous, zeroed frames. Returns the physical address.
pub fn alloc_frames(count: usize) -> Option<u64> {
    let pfn = pfn::take(&mut pfn::lock(), count as u64, None)?;
    let pa = pfn * PAGE_SIZE as u64;
    // SAFETY: the allocator just gave us exclusive ownership of these
    // frames, and the direct map covers all RAM.
    unsafe { core::ptr::write_bytes(phys_to_virt(pa), 0, count * PAGE_SIZE) };
    Some(pa)
}

/// Allocate `count` contiguous, zeroed frames where `within` allows.
/// Returns the physical address.
pub fn alloc_frames_within(count: usize, within: &Within) -> Option<u64> {
    let pfn = pfn::take(&mut pfn::lock(), count as u64, Some(within))?;
    let pa = pfn * PAGE_SIZE as u64;
    // SAFETY: as in `alloc_frames`.
    unsafe { core::ptr::write_bytes(phys_to_virt(pa), 0, count * PAGE_SIZE) };
    Some(pa)
}

/// Whether the `bytes` bytes of physical memory at `pa` are all RAM, of
/// any kind: memory firmware's map describes that is not device
/// registers.
pub fn is_ram(pa: u64, bytes: u64) -> bool {
    let Some(end) = pa.checked_add(bytes) else {
        return false;
    };
    let mut at = pa;
    // The range may run across regions that touch.
    while at < end {
        match memory_map().find(|r| r.is_ram() && r.contains(at, 1)) {
            Some(region) => at = region.end(),
            None => return false,
        }
    }
    true
}

/// How much physical memory, from address zero, the direct map holds
/// for certain: up to where RAM ends.
pub fn direct_map_bytes() -> u64 {
    RAM_TOP.load(Ordering::Relaxed)
}

/// Return frames from `alloc_frames`. A double free is a kernel bug.
pub fn free_frames(pa: u64, count: usize) {
    pfn::give_back(&mut pfn::lock(), pa / PAGE_SIZE as u64, count as u64);
}

/// The memory NK uses as RAM, in frames: how many there are, and the
/// numbers of the lowest and the highest.
pub fn physical_memory() -> (u64, u64, u64) {
    let frame = PAGE_SIZE as u64;
    memory_map()
        .filter(|r| r.kind == EFI_CONVENTIONAL && r.pages != 0)
        .fold((0, u64::MAX, 0), |(pages, lowest, highest), r| {
            let first = r.phys / frame;
            (
                pages + r.pages,
                lowest.min(first),
                highest.max(first + r.pages - 1),
            )
        })
}

pub fn free_frame_count() -> u64 {
    pfn::lock().as_ref().map_or(0, |f| f.bitmap.free_frames())
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
    // The database knows them as the kernel's.
    if pfn::state(b + 15 * PAGE_SIZE as u64) != (nk_mm::pfn::Location::Active, 1, 0) {
        return Err("an allocated frame is not active in the PFN database");
    }
    free_frames(a, 1);
    free_frames(b, 16);
    if free_frame_count() != before {
        return Err("frames leaked");
    }
    if pfn::state(a).0 != nk_mm::pfn::Location::Free {
        return Err("a freed frame is not free in the PFN database");
    }
    pfn::check()
}
