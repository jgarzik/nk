//! System-cache views: the 256 KiB windows onto files that the cache
//! manager maps (`MmReserveViewInSystemCache`, `MmMapViewInSystemCache`,
//! `MmUnmapViewInSystemCache`), and the calls it makes on their pages.
//!
//! The views live in a region of kernel address space of their own.
//! Its page tables are made when slots are reserved and never freed,
//! and its entries are written here directly, under the PFN lock, never
//! through `mm::map` (whose lock ranks below this one). Mapping a view
//! writes prototype pointers and does no I/O; a page becomes valid when
//! it is touched (`fault`) or when the cache manager asks for it
//! ([`make_resident`]). Unmapping moves each valid entry's dirty bit to
//! the page's PFN entry, so no write is lost, and the page goes to a
//! list when nothing else holds it.
//!
//! Each slot maps at most one subsection, and each subsection is mapped
//! by at most one slot, as the cache manager keeps one view per 256 KiB
//! of a file; [`OWNER`] is the way back from a slot to its subsection.

use super::fault::{self, Got, Mode};
use super::pfn::{self, Guard};
use super::section::{self, SectionRef, Subsection};
use super::{PAGE_SIZE, map};
use crate::arch;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicPtr, AtomicU64, AtomicUsize, Ordering};
use nk_mm::pt::{Arch, Prot};
use nk_mm::pte::{self, Proto};
use nk_mm::section::{SUBSECTION_BYTES, SUBSECTION_PAGES};
use nk_ntabi::status::*;

/// A view's size.
pub const VIEW_BYTES: usize = SUBSECTION_BYTES as usize;
/// The region, and how many slots it holds: 4 GiB of views.
const BASE: u64 = 0xFFFF_F980_0000_0000;
const MAX_SLOTS: usize = 16384;
/// Slots per table of 4 KiB entries (2 MiB).
const SLOTS_PER_TABLE: usize = 8;

/// One slot of reserved system-cache address space, 256 KiB aligned
/// and sized: its address.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CacheSlot(pub usize);

/// `MmCheckCachedPageStates`' modes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum Resident {
    /// Make every page valid, reading what is in the file only.
    FaultIn = 0,
    /// The caller overwrites the range: a page wholly inside it that is
    /// in the file only gets a zeroed frame, with no read.
    WillOverwrite = 1,
    /// Make valid what is in memory; stop at the first page that needs
    /// a read.
    NoIo = 2,
}

static NEXT_SLOT: AtomicUsize = AtomicUsize::new(0);
/// The physical address of each table of entries made for the region.
static TABLES: [AtomicU64; MAX_SLOTS / SLOTS_PER_TABLE] =
    [const { AtomicU64::new(0) }; MAX_SLOTS / SLOTS_PER_TABLE];
/// The subsection each slot maps, or null.
static OWNER: [AtomicPtr<Subsection>; MAX_SLOTS] =
    [const { AtomicPtr::new(core::ptr::null_mut()) }; MAX_SLOTS];

/// Whether `va` is in a reserved slot.
pub fn is_cache_va(va: u64) -> bool {
    va >= BASE && va < BASE + (NEXT_SLOT.load(Ordering::Acquire) * VIEW_BYTES) as u64
}

fn slot_index(va: u64) -> usize {
    ((va - BASE) / VIEW_BYTES as u64) as usize
}

/// The page-table entry of `va`, an address in a reserved slot.
fn entry(va: u64) -> &'static AtomicU64 {
    let table = TABLES[slot_index(va) / SLOTS_PER_TABLE].load(Ordering::Acquire);
    let index = (va >> 12 & 511) as usize;
    // SAFETY: the table was made when the slot was reserved and is
    // never freed; it is in the direct map; entries are read and written
    // as atomics.
    unsafe { AtomicU64::from_ptr(super::phys_to_virt(table).cast::<u64>().add(index)) }
}

/// The page-table entry of `va`, an address in a reserved slot, for
/// the memory manager's other parts.
pub(super) fn entry_of(va: u64) -> &'static AtomicU64 {
    entry(va)
}

/// The subsection a slot maps, and the index of `va`'s page in it.
fn owner(va: u64) -> (*mut Subsection, usize) {
    (
        OWNER[slot_index(va)].load(Ordering::Acquire),
        (va as usize % VIEW_BYTES) / PAGE_SIZE,
    )
}

/// The valid entry that maps frame `pfn` read-write.
pub(super) fn valid_entry(pfn: u64) -> u64 {
    arch::pt_arch().leaf(pfn * PAGE_SIZE as u64, 0, Prot::RW)
}

/// `MmReserveViewInSystemCache`, `count` times, once, as the cache
/// manager reserves its views when it starts: the slots, each with its
/// page table made.
pub fn reserve_cache_slots(count: usize) -> Result<Vec<CacheSlot>, NTSTATUS> {
    let mut slots = Vec::new();
    slots
        .try_reserve_exact(count)
        .map_err(|_| STATUS_INSUFFICIENT_RESOURCES)?;
    let first = NEXT_SLOT.load(Ordering::Acquire);
    if first + count > MAX_SLOTS {
        return Err(STATUS_INSUFFICIENT_RESOURCES);
    }
    for slot in first..first + count {
        let table = &TABLES[slot / SLOTS_PER_TABLE];
        if table.load(Ordering::Acquire) == 0 {
            let va = BASE + (slot * VIEW_BYTES) as u64;
            let pa = map::leaf_table(va).map_err(|_| STATUS_INSUFFICIENT_RESOURCES)?;
            table.store(pa, Ordering::Release);
        }
        slots.push(CacheSlot(BASE as usize + slot * VIEW_BYTES));
    }
    NEXT_SLOT.store(first + count, Ordering::Release);
    Ok(slots)
}

/// `MmMapViewInSystemCache`: map the `size` bytes (at most 256 KiB) of
/// the section at `offset` (a multiple of 256 KiB, inside the section)
/// in `slot`. The entries point at the prototype PTEs; nothing is read.
pub fn map_cache_view(
    s: &SectionRef,
    slot: CacheSlot,
    offset: u64,
    size: u32,
) -> Result<(), NTSTATUS> {
    let va = slot.0 as u64;
    if !is_cache_va(va) || va % VIEW_BYTES as u64 != 0 {
        crate::kd::bugcheck(format_args!("mm: {va:#x} is no system-cache slot"));
    }
    if offset % SUBSECTION_BYTES != 0 || size as usize > VIEW_BYTES || offset >= s.size() {
        return Err(STATUS_INVALID_PARAMETER);
    }
    let pages = u64::from(size)
        .min(s.size() - offset)
        .div_ceil(PAGE_SIZE as u64) as usize;
    let index = (offset / SUBSECTION_BYTES) as usize;
    let mut spare = core::ptr::null_mut();
    let ss = loop {
        let g = pfn::lock();
        // SAFETY: the section's reference keeps its control area.
        let ca = unsafe { &*s.ca() };
        if let Some(ss) = section::subsection_or(&g, ca, index, &mut spare) {
            map_entries(&g, ss, va, pages);
            ca.mapped_views.set(ca.mapped_views.get() + 1);
            ca.cache_views.set(ca.cache_views.get() + 1);
            break ss;
        }
        drop(g);
        if !spare.is_null() {
            return Err(STATUS_INVALID_PARAMETER);
        }
        spare = section::spare_subsection();
        if spare.is_null() {
            return Err(STATUS_INSUFFICIENT_RESOURCES);
        }
    };
    section::drop_spare(spare);
    section::trace(format_args!(
        "map view {va:#x} of {:p} at {offset:#x}, {pages} pages, subsection {ss:p}",
        s.ca()
    ));
    Ok(())
}

/// Point the `pages` entries at `va` at the prototype PTEs of `ss`.
fn map_entries(_: &Guard, ss: *mut Subsection, va: u64, pages: usize) {
    // SAFETY: a live subsection, under the lock.
    let ss_ref = unsafe { &*ss };
    if !OWNER[slot_index(va)].swap(ss, Ordering::AcqRel).is_null() || ss_ref.view_va.get() != 0 {
        crate::kd::bugcheck(format_args!(
            "mm: a system-cache slot or subsection is mapped twice"
        ));
    }
    ss_ref.views.set(ss_ref.views.get() + 1);
    ss_ref.view_va.set(va);
    for (i, proto) in ss_ref.protos.iter().enumerate().take(pages) {
        let e = entry(va + (i * PAGE_SIZE) as u64);
        if e.swap(
            pte::prototype_pointer(core::ptr::from_ref(proto).addr() as u64),
            Ordering::AcqRel,
        ) != 0
        {
            crate::kd::bugcheck(format_args!("mm: a system-cache slot held a mapping"));
        }
    }
}

/// `MmUnmapViewInSystemCache`: unmap `slot`, which maps part of `s`.
/// Each valid entry's dirty bit goes to its page's PFN entry; a page
/// nothing else holds goes onto standby (at the head with
/// `front_of_list`, to be reused first) or modified.
pub fn unmap_cache_view(s: &SectionRef, slot: CacheSlot, front_of_list: bool) {
    let va = slot.0 as u64;
    let mut g = pfn::lock();
    let ss = OWNER[slot_index(va)].swap(core::ptr::null_mut(), Ordering::AcqRel);
    // SAFETY: a mapped view keeps its subsection; null is a slot never
    // mapped, a caller's bug.
    let Some(ss) = (unsafe { ss.as_ref() }) else {
        crate::kd::bugcheck(format_args!(
            "mm: unmapping system-cache slot {va:#x}, which maps nothing"
        ));
    };
    // SAFETY: a subsection's control area outlives it.
    let ca = unsafe { &*ss.ca };
    if !core::ptr::eq(ca, s.ca()) {
        crate::kd::bugcheck(format_args!("mm: slot {va:#x} maps another section"));
    }
    let mut old = [0u64; SUBSECTION_PAGES];
    for (i, slot_entry) in old.iter_mut().enumerate() {
        *slot_entry = entry(va + (i * PAGE_SIZE) as u64).swap(0, Ordering::AcqRel);
    }
    arch::flush_tlb_range(va, SUBSECTION_PAGES);
    let a = arch::pt_arch();
    let no_write = ca.no_write();
    let mut dirty = 0;
    for (i, &e) in old.iter().enumerate() {
        if !a.present(e) {
            continue;
        }
        let frame = a.addr(e) / PAGE_SIZE as u64;
        let db = &mut pfn::frames(&mut g).db;
        if a.dirty(e) {
            db.get_mut(frame).flags |= nk_mm::pfn::flag::MODIFIED;
            dirty += 1;
        }
        match db.unshare(frame, no_write, front_of_list) {
            Ok(Some(_)) => ss.protos[i].store(Proto::Transition(frame).encode(), Ordering::Relaxed),
            Ok(None) => {}
            Err(e) => crate::kd::bugcheck(format_args!("mm: unmapping a view: {}", e.0)),
        }
    }
    ss.views.set(ss.views.get() - 1);
    ss.view_va.set(0);
    ca.mapped_views.set(ca.mapped_views.get() - 1);
    ca.cache_views.set(ca.cache_views.get() - 1);
    section::unused_subsection(&g, ss);
    section::check(&g, ca);
    drop(g);
    section::reap();
    section::trace(format_args!(
        "unmap view {va:#x} of {ca:p}, {dirty} pages dirty"
    ));
}

/// `MmCheckCachedPageStates`: make the `len` bytes at `va`, in a mapped
/// view, valid. `Ok(false)` only with [`Resident::NoIo`]: a page needs a
/// read, and nothing was waited for. `Err` is the status of a read that
/// failed, for the cache manager to raise.
pub fn make_resident(va: usize, len: usize, mode: Resident) -> Result<bool, NTSTATUS> {
    let (start, end) = (
        va & !(PAGE_SIZE - 1),
        (va + len).next_multiple_of(PAGE_SIZE),
    );
    for page in (start..end).step_by(PAGE_SIZE) {
        let whole = page >= va && page + PAGE_SIZE <= va + len;
        let mode = match mode {
            Resident::FaultIn => Mode::FaultIn,
            Resident::WillOverwrite if whole => Mode::NoRead,
            Resident::WillOverwrite => Mode::FaultIn,
            Resident::NoIo => Mode::NoIo,
        };
        if resolve(page as u64, mode)? == Got::NeedsIo {
            return Ok(false);
        }
    }
    Ok(true)
}

/// Resolve the page at `va` of a mapped view.
fn resolve(va: u64, mode: Mode) -> Result<Got, NTSTATUS> {
    if !is_cache_va(va) {
        crate::kd::bugcheck(format_args!("mm: {va:#x} is not in the system cache"));
    }
    let (ss, index) = owner(va);
    if ss.is_null() {
        crate::kd::bugcheck(format_args!("mm: {va:#x} is in no mapped view"));
    }
    fault::resolve(ss, index, Some(entry(va)), mode)
}

/// What the trap handler asks of a fault on `va`: `None` if `va` is not
/// in a mapped page of a view; else the page made valid, or the status
/// of the read that failed.
pub fn fault(va: u64) -> Option<Result<(), NTSTATUS>> {
    if !is_cache_va(va) {
        return None;
    }
    let va = va & !(PAGE_SIZE as u64 - 1);
    if pte::prototype_target(entry(va).load(Ordering::Acquire)).is_none()
        && !arch::pt_arch().present(entry(va).load(Ordering::Acquire))
    {
        return None;
    }
    Some(resolve(va, Mode::FaultIn).map(|_| ()))
}

/// The frame behind `va`, a page of a mapped view, made valid and
/// locked for I/O (`MmProbeAndLockPages`): the frame stays in memory
/// until [`unlock_page`].
pub fn lock_page(va: u64) -> Result<u64, NTSTATUS> {
    loop {
        resolve(va & !(PAGE_SIZE as u64 - 1), Mode::FaultIn)?;
        let mut g = pfn::lock();
        let e = entry(va).load(Ordering::Acquire);
        let a = arch::pt_arch();
        if !a.present(e) {
            continue; // trimmed meanwhile: again
        }
        let frame = a.addr(e) / PAGE_SIZE as u64;
        if let Err(e) = pfn::frames(&mut g).db.reference(frame) {
            crate::kd::bugcheck(format_args!("mm: locking a cache page: {}", e.0));
        }
        let (ss, _) = owner(va);
        // SAFETY: a mapped view keeps its subsection and control area.
        let ca = unsafe { &*(*ss).ca };
        ca.locked_pages.set(ca.locked_pages.get() + 1);
        return Ok(frame);
    }
}

/// Undo [`lock_page`] for frame `frame`. False, changing nothing, if
/// the frame is not a section's.
pub fn unlock_page(frame: u64) -> bool {
    let mut g = pfn::lock();
    let e = *pfn::frames(&mut g).db.get(frame);
    if !e.has(nk_mm::pfn::flag::PROTOTYPE) {
        return false;
    }
    let (ss, _) = section::locate_proto(e.original_pte, e.pte);
    // SAFETY: a page in memory keeps its subsection and control area.
    let ca = unsafe { &*(*ss).ca };
    ca.locked_pages.set(ca.locked_pages.get() - 1);
    if let Err(e) = pfn::frames(&mut g)
        .db
        .dereference(frame, ca.no_write(), false)
    {
        crate::kd::bugcheck(format_args!("mm: unlocking a cache page: {}", e.0));
    }
    true
}

/// `MmCopyToCachedPage`: put the `len` bytes at `src` at
/// `offset_in_page` in the page of a mapped view at `va`, with no read:
/// a page that is in the file only gets a zeroed frame first, so its
/// bytes outside the range are zero; a page in memory keeps them.
/// `Err(STATUS_ACCESS_VIOLATION)` if `src` is a user buffer that is not
/// all there.
///
/// # Safety
/// `src` is readable for `len` bytes, or is in the user range.
pub unsafe fn copy_to_cached_page(
    va: usize,
    src: *const u8,
    offset_in_page: u32,
    len: u32,
) -> Result<(), NTSTATUS> {
    let page = va & !(PAGE_SIZE - 1);
    if offset_in_page as usize + len as usize > PAGE_SIZE {
        return Err(STATUS_INVALID_PARAMETER);
    }
    resolve(page as u64, Mode::NoRead)?;
    let dst = (page + offset_in_page as usize) as *mut u8;
    // SAFETY: the page was just made valid in a view the caller holds;
    // per the contract for `src`, whose faults the copy turns into an
    // error.
    unsafe { super::user::copy(dst, src, len as usize) }.map_err(|_| STATUS_ACCESS_VIOLATION)
}

/// `MmHardFaultBytesRequired`: how many of the `len` bytes at `va`, in a
/// mapped view, are in pages that only the file holds.
pub fn hard_fault_bytes(va: usize, len: usize) -> usize {
    let (start, end) = (
        va & !(PAGE_SIZE - 1),
        (va + len).next_multiple_of(PAGE_SIZE),
    );
    let _g = pfn::lock();
    (start..end)
        .step_by(PAGE_SIZE)
        .filter(|&page| {
            let (ss, index) = owner(page as u64);
            // SAFETY: a mapped view keeps its subsection; the lock guards
            // the prototype PTEs.
            !ss.is_null()
                && matches!(
                    Proto::decode(unsafe { (*ss).protos[index].load(Ordering::Relaxed) }),
                    Proto::Subsection(_)
                )
        })
        .count()
        * PAGE_SIZE
}

/// `MmSetAddressRangeModified`: the valid pages of the `len` bytes at
/// `va`, in a mapped view, are modified: their PFN entries say so, and
/// the next flush writes them.
pub fn set_range_modified(va: usize, len: usize) {
    let (start, end) = (
        va & !(PAGE_SIZE - 1),
        (va + len).next_multiple_of(PAGE_SIZE),
    );
    let a = arch::pt_arch();
    let mut g = pfn::lock();
    for page in (start..end).step_by(PAGE_SIZE) {
        let e = entry(page as u64).load(Ordering::Acquire);
        if a.present(e) {
            pfn::frames(&mut g)
                .db
                .get_mut(a.addr(e) / PAGE_SIZE as u64)
                .flags |= nk_mm::pfn::flag::MODIFIED;
        }
    }
}

/// A read-ahead's result (`MmPrefetchForCacheManager`).
pub struct Prefetch(NTSTATUS);

/// `MmPrefetchForCacheManager`: read the pages of the `len` bytes of `s`
/// at `offset` that only the file holds into memory, onto standby, for a
/// later view to find. NK reads them before returning; the result is
/// what [`wait_prefetch`] gives.
pub fn prefetch_for_cc(
    s: &SectionRef,
    offset: u64,
    len: u32,
    _priority: u8,
) -> Result<Prefetch, NTSTATUS> {
    let end = (offset + u64::from(len)).min(s.size());
    let mut at = offset & !(PAGE_SIZE as u64 - 1);
    while at < end {
        let index = (at / SUBSECTION_BYTES) as usize;
        let mut spare = section::spare_subsection();
        if spare.is_null() {
            return Err(STATUS_INSUFFICIENT_RESOURCES);
        }
        let ss = {
            let g = pfn::lock();
            // SAFETY: the section's reference keeps its control area.
            let ss = section::subsection_or(&g, unsafe { &*s.ca() }, index, &mut spare);
            // The read-ahead holds the subsection like a view.
            ss.inspect(|&ss| {
                // SAFETY: live under the lock.
                let ss = unsafe { &*ss };
                ss.views.set(ss.views.get() + 1);
            })
        };
        section::drop_spare(spare);
        let Some(ss) = ss else {
            return Err(STATUS_INVALID_PARAMETER);
        };
        let stop = end.min((index as u64 + 1) * SUBSECTION_BYTES);
        let mut result = Ok(());
        while at < stop && result.is_ok() {
            let page = ((at % SUBSECTION_BYTES) / PAGE_SIZE as u64) as usize;
            result = fault::resolve(ss, page, None, Mode::FaultIn).map(|_| ());
            at += PAGE_SIZE as u64;
        }
        {
            let g = pfn::lock();
            // SAFETY: held like a view until here.
            let ss = unsafe { &*ss };
            ss.views.set(ss.views.get() - 1);
            section::unused_subsection(&g, ss);
        }
        section::reap();
        if let Err(status) = result {
            return Ok(Prefetch(status));
        }
        at = stop;
    }
    Ok(Prefetch(STATUS_SUCCESS))
}

/// `MmWaitForCacheManagerPrefetch`: the read-ahead's status.
pub fn wait_prefetch(p: Prefetch) -> NTSTATUS {
    p.0
}
