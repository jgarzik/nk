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
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU64, Ordering};
use nk_mm::pt::{self, MapError, Prot, TableMem};
use nk_mm::space::{self, Space};

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
        // direct map; `index` is below 512. Edits hold `NEXT_VA`; a read
        // may be made without it (`physical`), so entries are atomics.
        unsafe { AtomicU64::from_ptr(phys_to_virt(table).cast::<u64>().add(index)) }
            .load(Ordering::Relaxed)
    }

    fn write(&mut self, table: u64, index: usize, entry: u64) {
        // SAFETY: as in `read`.
        unsafe { AtomicU64::from_ptr(phys_to_virt(table).cast::<u64>().add(index)) }
            .store(entry, Ordering::Relaxed);
    }
}

/// The ranges `alloc_va` handed out and that are not given back yet,
/// sorted by address: what may be unmapped and given back. A mapping
/// made for good (`map_device_for_good`) is not among them. Room for
/// [`ROOM`] ranges is taken once, at the first reservation, so that the
/// record does not grow while drivers and tests come and go.
static LIVE: SpinLock<Vec<(u64, usize)>> = SpinLock::new(Rank::Mappings, Vec::new());

/// The ranges [`LIVE`] has room for from the start.
const ROOM: usize = 512;

/// Reserve `pages` pages of kernel address space. A gap page follows each
/// reservation, so running off the end of one mapping faults.
pub fn alloc_va(pages: usize) -> Option<u64> {
    alloc_va_aligned(pages, PAGE_SIZE as u64)
}

/// As `alloc_va`, at an address that is a multiple of `align` bytes (a
/// power of two, at least a page).
pub fn alloc_va_aligned(pages: usize, align: u64) -> Option<u64> {
    let va = NEXT_VA.lock().take(pages, align)?;
    let recorded = {
        let mut live = LIVE.lock();
        if live.capacity() == 0 {
            let _ = live.try_reserve_exact(ROOM);
        }
        let room = live.try_reserve(1).is_ok();
        if room {
            let at = live.partition_point(|&(start, _)| start < va);
            live.insert(at, (va, pages));
        }
        room
    };
    if !recorded {
        NEXT_VA.lock().give_back(va, pages);
        return None;
    }
    Some(va)
}

/// Stop the system if the `pages` pages at `va` are not all held by one
/// range `alloc_va` handed out, as Windows' `MiReleasePtes` stops when
/// system PTEs it is given back were not allocated: `SYSTEM_PTE_MISUSE`
/// with 0x302, the address and the count. (Windows' fourth parameter
/// is a position in its allocation bitmap, which NK does not have.)
pub fn check_held(va: u64, pages: usize) {
    if space::holder(&LIVE.lock(), va, pages).is_none() {
        crate::ke::bugcheck::KeBugCheckEx(0xDA, 0x302, va as usize, pages, 0);
    }
}

/// Give back the `pages` pages at `va`, all of them held by one range
/// `alloc_va` handed out ([`check_held`] stops the system otherwise).
/// A whole range goes back for reuse; part of one is given up but not
/// reused, as the rest stays mapped beside it without a gap page.
///
/// # Safety
/// Nothing is mapped in the pages any more, and nothing refers to them.
pub unsafe fn free_va(va: u64, pages: usize) {
    check_held(va, pages);
    let whole = {
        let mut live = LIVE.lock();
        match space::holder(&live, va, pages) {
            Some(at) => {
                let range = live[at];
                let (before, after) = space::remainder(range, va, pages);
                // Splitting a range needs one more entry; without the
                // room the range stays recorded whole, and what was
                // given back is simply not handed out again.
                if before.is_none() || after.is_none() || live.try_reserve(1).is_ok() {
                    live.remove(at);
                    for piece in [after, before].into_iter().flatten() {
                        live.insert(at, piece);
                    }
                }
                range == (va, pages)
            }
            None => false,
        }
    };
    if whole {
        NEXT_VA.lock().give_back(va, pages);
    }
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
///
/// # Safety
/// Nothing still uses the pages: no reference into them, and no driver
/// that holds them.
pub unsafe fn unmap(va: u64, pages: usize) {
    let _guard = NEXT_VA.lock();
    let (root, arch_pt) = (arch::pt_root_of(va), arch::pt_arch());
    for i in 0..pages {
        let page = va + (i * PAGE_SIZE) as u64;
        if pt::unmap(&mut Tables, &arch_pt, root, page).is_some() {
            arch::flush_tlb_page(page);
        }
    }
}

/// Give each of the `pages` pages at `va` the protection `prot`, page
/// `i` mapped to the frame at physical address `frame(i)`; `None` leaves
/// them unmapped. Whatever was mapped there before is replaced, and
/// every processor's translation dropped.
pub fn remap(
    va: u64,
    pages: usize,
    frame: impl Fn(usize) -> u64,
    prot: Option<Prot>,
) -> Result<(), MapError> {
    let _guard = NEXT_VA.lock();
    let (root, arch_pt) = (arch::pt_root_of(va), arch::pt_arch());
    for i in 0..pages {
        let page = va + (i * PAGE_SIZE) as u64;
        if pt::unmap(&mut Tables, &arch_pt, root, page).is_some() {
            arch::flush_tlb_page(page);
        }
        if let Some(prot) = prot {
            pt::map(&mut Tables, &arch_pt, root, page, frame(i), 0, prot)?;
        }
    }
    arch::mapping_sync();
    Ok(())
}

/// The physical address `va` maps to, found without a lock, so at any
/// IRQL: by arithmetic for an address in the map of all RAM, else by
/// reading the page tables as the processor reads them. Tables are
/// never freed, so the walk is over tables whatever is being mapped or
/// unmapped meanwhile; its answer is then the old one or the new.
pub fn physical(va: u64) -> Option<u64> {
    let direct = phys_to_virt(0) as u64;
    if (direct..direct + super::direct_map_bytes()).contains(&va) {
        return Some(va - direct);
    }
    pt::translate(&Tables, &arch::pt_arch(), arch::pt_root_of(va), va)
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
    // SAFETY: the test's own two pages.
    unsafe { unmap(va, 2) };
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
    // SAFETY: unmapped above; the test's own range.
    unsafe { free_va(va, 2) };
    if alloc_va(2) != Some(va) {
        return Err("freed address space was not reused");
    }
    // SAFETY: just reserved, never mapped.
    unsafe { free_va(va, 2) };
    Ok(())
}
