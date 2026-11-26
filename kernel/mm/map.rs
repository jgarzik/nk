//! Kernel virtual mappings above the image: driver images and mapped
//! buffers live here, with real per-page protections.
//!
//! Address space is handed out by `nk_mm::space`, which reuses freed
//! ranges by exact size. That is enough for a driver loaded and
//! unloaded repeatedly to land on the same addresses, so the cycle
//! allocates no new page tables and leak checks can compare frame counts.
//! Intermediate page tables are never freed.

use super::{PAGE_SIZE, alloc_frames, phys_to_virt};
use crate::arch;
use crate::ke::{Rank, SpinLock};
use core::sync::atomic::{AtomicU64, Ordering};
use nk_mm::pt::{self, MapError, Prot, TableMem};
use nk_mm::space::Space;

/// Frames taken for page tables. They are kept for good, so a leak check
/// must not count them as lost.
static TABLE_FRAMES: AtomicU64 = AtomicU64::new(0);

/// Frames this module holds as page tables.
pub fn table_frames() -> u64 {
    TABLE_FRAMES.load(Ordering::Relaxed)
}

/// The region for dynamic kernel mappings.
const REGION_BASE: u64 = 0xFFFF_F880_0000_0000;
const REGION_END: u64 = 0xFFFF_F900_0000_0000;

/// Serialises page-table edits; holds the address-space allocator.
static NEXT_VA: SpinLock<Space> =
    SpinLock::new(Rank::AddressSpace, Space::new(REGION_BASE, REGION_END));

/// Page tables, edited through the direct map.
pub struct Tables;

impl TableMem for Tables {
    fn alloc_table(&mut self) -> Option<u64> {
        let frame = alloc_frames(1)?;
        TABLE_FRAMES.fetch_add(1, Ordering::Relaxed);
        Some(frame)
    }

    fn read(&self, table: u64, index: usize) -> u64 {
        // SAFETY: `table` is a page-table frame reachable through the
        // direct map; `index` is below 512. Edits hold `NEXT_VA`.
        unsafe { phys_to_virt(table).cast::<u64>().add(index).read_volatile() }
    }

    fn write(&mut self, table: u64, index: usize, entry: u64) {
        // SAFETY: as in `read`.
        unsafe {
            phys_to_virt(table)
                .cast::<u64>()
                .add(index)
                .write_volatile(entry)
        }
    }
}

/// Reserve `pages` pages of kernel address space. A gap page follows each
/// reservation, so running off the end of one mapping faults.
pub fn alloc_va(pages: usize) -> Option<u64> {
    NEXT_VA.lock().take(pages, PAGE_SIZE as u64)
}

/// As `alloc_va`, at an address that is a multiple of `align` bytes (a
/// power of two, at least a page).
pub fn alloc_va_aligned(pages: usize, align: u64) -> Option<u64> {
    NEXT_VA.lock().take(pages, align)
}

/// Give back address space from `alloc_va`, once nothing is mapped there.
/// If the reuse cache is full the range is simply not reused.
pub fn free_va(va: u64, pages: usize) {
    NEXT_VA.lock().give_back(va, pages);
}

/// Map `pages` pages at `va` to the physical range starting at `pa`.
pub fn map(va: u64, pa: u64, pages: usize, prot: Prot) -> Result<(), MapError> {
    let _guard = NEXT_VA.lock();
    let (root, arch_pt) = (arch::pt_root_of(va), arch::pt_arch());
    pt::map_range(
        &mut Tables,
        &arch_pt,
        root,
        va,
        pa,
        (pages * PAGE_SIZE) as u64,
        0,
        prot,
    )?;
    arch::mapping_sync();
    Ok(())
}

/// Map the device registers in the `bytes` bytes of physical memory at
/// `pa` (both multiples of a page) at a fresh address, for good, and
/// return that address. A stretch that begins and ends on 2 MiB
/// boundaries is mapped in 2 MiB blocks, which [`unmap`] does not take
/// apart: this is for what the kernel keeps for its whole life.
pub fn map_device_for_good(pa: u64, bytes: u64) -> Option<u64> {
    const BLOCK: u64 = 2 << 20;
    let large = (pa | bytes).is_multiple_of(BLOCK);
    let align = if large { BLOCK } else { PAGE_SIZE as u64 };
    let mut space = NEXT_VA.lock();
    let va = space.take((bytes / PAGE_SIZE as u64) as usize, align)?;
    let (root, arch_pt) = (arch::pt_root_of(va), arch::pt_arch());
    pt::map_range(
        &mut Tables,
        &arch_pt,
        root,
        va,
        pa,
        bytes,
        u8::from(large),
        Prot::DEVICE,
    )
    .ok()?;
    arch::mapping_sync();
    Some(va)
}

/// Remove `pages` mappings starting at `va`. Unmapped pages are skipped.
pub fn unmap(va: u64, pages: usize) {
    let _guard = NEXT_VA.lock();
    let (root, arch_pt) = (arch::pt_root_of(va), arch::pt_arch());
    for i in 0..pages {
        let page = va + (i * PAGE_SIZE) as u64;
        if pt::unmap(&mut Tables, &arch_pt, root, page).is_some() {
            arch::flush_tlb_page(page);
        }
    }
}

/// The physical address `va` maps to in the kernel address space.
pub fn translate(va: u64) -> Option<u64> {
    lookup(va).map(|(pa, _)| pa)
}

/// The physical address `va` maps to in the kernel address space, and
/// whether the mapping may be written.
pub fn lookup(va: u64) -> Option<(u64, bool)> {
    let _guard = NEXT_VA.lock();
    pt::lookup(&Tables, &arch::pt_arch(), arch::pt_root_of(va), va)
}

/// The low half holds firmware's runtime regions, each at its physical
/// address, and neither address zero nor ordinary memory. Returns the
/// number of regions.
pub fn low_half_test() -> Result<usize, &'static str> {
    if translate(0).is_some() {
        return Err("address zero is mapped");
    }
    let frame = alloc_frames(1).ok_or("no frames")?;
    let stray = translate(frame);
    super::free_frames(frame, 1);
    if stray.is_some() {
        return Err("ordinary memory is mapped at its physical address");
    }
    let mut regions = 0;
    for (region, _) in super::firmware_regions() {
        let last = region.end() - PAGE_SIZE as u64;
        if translate(region.phys) != Some(region.phys) || translate(last) != Some(last) {
            return Err("a firmware runtime region is not mapped at its physical address");
        }
        regions += 1;
    }
    if regions == 0 {
        return Err("firmware names no runtime regions");
    }
    Ok(regions)
}

/// Map a frame at a fresh address, see the same bytes through both views,
/// unmap, and confirm the translation is gone.
pub fn self_test() -> Result<(), &'static str> {
    let pa = alloc_frames(2).ok_or("no frames")?;
    let va = alloc_va(2).ok_or("no address space")?;
    map(va, pa, 2, Prot::RW).map_err(|_| "map failed")?;
    if translate(va + 0x1234) != Some(pa + 0x1234) {
        return Err("translate disagrees with map");
    }
    if map(va, pa, 1, Prot::RW) != Err(MapError::AlreadyMapped) {
        return Err("double map was not refused");
    }
    // SAFETY: `va` maps two frames we own, read-write; the direct map
    // aliases the same frames.
    unsafe {
        let p = va as *mut u64;
        p.write_volatile(0x1122_3344_5566_7788);
        p.add(PAGE_SIZE / 8).write_volatile(0x99AA_BBCC_DDEE_FF00);
        let d = phys_to_virt(pa).cast::<u64>();
        if d.read_volatile() != 0x1122_3344_5566_7788
            || d.add(PAGE_SIZE / 8).read_volatile() != 0x99AA_BBCC_DDEE_FF00
        {
            return Err("mapped view and direct map differ");
        }
    }
    unmap(va, 2);
    if translate(va).is_some() || translate(va + PAGE_SIZE as u64).is_some() {
        return Err("still mapped after unmap");
    }
    // The kernel's own text must be mapped, and the direct map must agree
    // with the page tables about itself.
    if translate(self_test as fn() -> _ as usize as u64).is_none() {
        return Err("kernel text is not mapped?");
    }
    if translate(phys_to_virt(pa) as u64) != Some(pa) {
        return Err("direct map translation is wrong");
    }
    super::free_frames(pa, 2);
    free_va(va, 2);
    if alloc_va(2) != Some(va) {
        return Err("freed address space was not reused");
    }
    free_va(va, 2);
    Ok(())
}
