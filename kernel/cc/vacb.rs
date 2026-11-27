//! Views (VACBs): the slots of the system cache the cache manager maps
//! 256 KiB of a file in, each through the memory manager
//! (`MmMapViewInSystemCache`), as `CcGetVirtualAddress` and
//! `CcFreeVirtualAddress` hand them out.
//!
//! A pool of VACBs is made at start; a view in use counts its users
//! (`ActiveCount`). A view nobody uses stays mapped until its VACB is
//! needed for another view, the least recently used first. A VACB being
//! mapped or unmapped is in neither state: whoever finds it waits.
//!
//! [`VACBS`] guards every VACB and every shared cache map's VACB index;
//! the memory manager is called with it dropped.

use super::{Scm, cache_manager_bugcheck, short_delay};
use crate::ke::spinlock::{Rank, SpinLock};
use crate::mm::cache::{self, CacheSlot};
use crate::mm::section::SectionRef;
use alloc::vec::Vec;
use nk_cc::VIEW_BYTES;
use nk_cc::vacbidx::Leaf;
use nk_ntabi::status::*;

/// One view.
pub struct Vacb {
    slot: CacheSlot,
    /// The map whose view it is, or null.
    scm: *const Scm,
    view: usize,
    /// Its users (`ActiveCount`).
    active: u32,
    /// When it was last handed out, for reuse in that order.
    used: u64,
    /// Mapped and usable; false while it is being mapped or unmapped.
    ready: bool,
    /// The section it maps, held while it does.
    section: Option<SectionRef>,
}

/// The pool of views.
pub struct Vacbs {
    vacbs: Vec<Vacb>,
    tick: u64,
}

// SAFETY: the raw pointers name shared cache maps, reached only under
// the lock.
unsafe impl Send for Vacbs {}

/// The views and every map's index of them.
pub static VACBS: SpinLock<Option<Vacbs>> = SpinLock::new(Rank::CcVacbs, None);

/// A view handed out: the address of the requested offset, the bytes
/// from it to the view's end (within the section), and the VACB.
#[derive(Debug, Clone, Copy)]
pub struct View {
    pub va: usize,
    pub left: u32,
    pub vacb: usize,
}

/// Make the pool of `count` views (`CcInitializePartitionVacbs`).
pub fn init(count: usize) -> Result<(), &'static str> {
    let slots = cache::reserve_cache_slots(count).map_err(|_| "no system-cache slots")?;
    let mut vacbs = Vec::new();
    vacbs
        .try_reserve_exact(count)
        .map_err(|_| "no memory for the views")?;
    vacbs.extend(slots.into_iter().map(|slot| Vacb {
        slot,
        scm: core::ptr::null(),
        view: 0,
        active: 0,
        used: 0,
        ready: true,
        section: None,
    }));
    *VACBS.lock() = Some(Vacbs { vacbs, tick: 0 });
    Ok(())
}

impl Vacbs {
    /// The view to reuse: unmapped ones first, then the least recently
    /// used of those nobody uses.
    fn victim(&self) -> Option<usize> {
        self.vacbs
            .iter()
            .enumerate()
            .filter(|(_, v)| v.active == 0 && v.ready)
            .min_by_key(|(_, v)| (!v.scm.is_null(), v.used))
            .map(|(i, _)| i)
    }

    /// The handle `CcMapData` gives for VACB `i`: its address plus one.
    pub fn handle(&self, i: usize) -> usize {
        core::ptr::from_ref(&self.vacbs[i]).addr() + 1
    }

    /// The VACB a mapping handle names, if it names one.
    pub fn vacb_of_handle(&self, address: usize) -> Option<usize> {
        let base = self.vacbs.as_ptr().addr();
        let offset = address.checked_sub(base)?;
        (offset % size_of::<Vacb>() == 0 && offset / size_of::<Vacb>() < self.vacbs.len())
            .then_some(offset / size_of::<Vacb>())
    }
}

fn view_of(v: &Vacb, offset: u64, section_size: u64, i: usize) -> View {
    let base = v.view as u64 * VIEW_BYTES;
    let end = (base + VIEW_BYTES).min(section_size);
    View {
        va: v.slot.0 + (offset - base) as usize,
        left: (end - offset) as u32,
        vacb: i,
    }
}

/// `CcGetVirtualAddress`: the view of `scm` holding `offset`, mapped if
/// it is not, with one more user. `STATUS_INSUFFICIENT_RESOURCES` when
/// every view is in use; a memory-manager failure as Windows maps it.
pub fn get_va(scm: &Scm, offset: u64) -> Result<View, NTSTATUS> {
    let section_size = scm.section_size.get();
    if offset >= section_size {
        cache_manager_bugcheck(format_args!(
            "offset {offset:#x} is beyond the section ({section_size:#x}) of the map at {:p}",
            core::ptr::from_ref(scm)
        ));
    }
    let view = (offset / VIEW_BYTES) as usize;
    let mut leaf = None;
    let (i, old, slot) = loop {
        let mut g = VACBS.lock();
        let v = g.as_mut().expect("the cache manager has started");
        // SAFETY: the index is guarded by this lock.
        let index = unsafe { &mut *scm.index.get() }
            .as_mut()
            .expect("a shared cache map with no index");
        if let Some(i) = index.get(view) {
            let i = i as usize;
            if !v.vacbs[i].ready {
                drop(g);
                short_delay();
                continue;
            }
            v.tick += 1;
            let tick = v.tick;
            let e = &mut v.vacbs[i];
            e.active += 1;
            e.used = tick;
            return Ok(view_of(e, offset, section_size, i));
        }
        if index.needs_leaf(view) {
            match leaf.take() {
                Some(l) => {
                    let _unused = index.insert_leaf(view, l);
                    debug_assert!(_unused.is_none());
                }
                None => {
                    drop(g);
                    leaf = Some(Leaf::new().map_err(|_| STATUS_INSUFFICIENT_RESOURCES)?);
                    continue;
                }
            }
        }
        let Some(i) = v.victim() else {
            return Err(STATUS_INSUFFICIENT_RESOURCES);
        };
        v.tick += 1;
        let tick = v.tick;
        let e = &mut v.vacbs[i];
        let old = e.section.take();
        // SAFETY: a map a VACB names keeps its index until its views are
        // taken back, under this lock.
        if let Some(previous) = unsafe { e.scm.as_ref() } {
            // SAFETY: as above.
            unsafe { &mut *previous.index.get() }
                .as_mut()
                .expect("a mapped map has an index")
                .set(e.view, None);
        }
        e.scm = scm;
        e.view = view;
        e.active = 1;
        e.used = tick;
        e.ready = false;
        index.set(view, Some(i as u32));
        break (i, old, e.slot);
    };
    drop(leaf);
    if let Some(old) = old {
        cache::unmap_cache_view(&old, slot, false);
    }
    let section = scm.section().clone();
    let base = view as u64 * VIEW_BYTES;
    let size = VIEW_BYTES.min(section_size - base) as u32;
    let mapped = cache::map_cache_view(&section, slot, base, size);
    super::trace(format_args!(
        "view {:#x} of {:p} at {base:#x}: {mapped:x?}",
        slot.0,
        core::ptr::from_ref(scm)
    ));
    let mut g = VACBS.lock();
    let v = g.as_mut().expect("started");
    let e = &mut v.vacbs[i];
    match mapped {
        Ok(()) => {
            e.section = Some(section);
            e.ready = true;
            Ok(view_of(e, offset, section_size, i))
        }
        Err(status) => {
            e.scm = core::ptr::null();
            e.active = 0;
            e.ready = true;
            // SAFETY: as above.
            unsafe { &mut *scm.index.get() }
                .as_mut()
                .expect("index")
                .set(view, None);
            drop(g);
            drop(section);
            Err(
                nk_fsrtl::status::normalize(status as u32, STATUS_UNEXPECTED_MM_MAP as u32)
                    as NTSTATUS,
            )
        }
    }
}

const STATUS_UNEXPECTED_MM_MAP: NTSTATUS = super::STATUS_UNEXPECTED_MM_MAP_ERROR;

/// `CcFreeVirtualAddress`: one user fewer of VACB `i`.
pub fn free_va(i: usize) {
    let mut g = VACBS.lock();
    let e = &mut g.as_mut().expect("started").vacbs[i];
    if e.active == 0 {
        drop(g);
        cache_manager_bugcheck(format_args!("a view nobody uses is given back (VACB {i})"));
    }
    e.active -= 1;
}

/// Whether to wait for views in use, or fail.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Busy {
    Fail,
    Wait,
}

/// `CcUnmapVacbArray`: take back every view of `scm` from view
/// `first` on. A view in use fails the call (with [`Busy::Fail`],
/// unmapping nothing) or is waited for.
pub fn unmap_views(scm: &Scm, first: usize, busy: Busy) -> bool {
    let room = VACBS.lock().as_ref().map_or(0, |v| v.vacbs.len());
    let mut taken: Vec<(usize, CacheSlot, Option<SectionRef>)> = Vec::with_capacity(room);
    loop {
        let mut g = VACBS.lock();
        let v = g.as_mut().expect("started");
        // SAFETY: the index is guarded by this lock.
        let Some(index) = (unsafe { &mut *scm.index.get() }).as_mut() else {
            return true;
        };
        let in_use = index
            .mapped()
            .filter(|&(view, _)| view >= first)
            .any(|(_, i)| v.vacbs[i as usize].active != 0 || !v.vacbs[i as usize].ready);
        if in_use {
            drop(g);
            if busy == Busy::Fail {
                return false;
            }
            short_delay();
            continue;
        }
        for view in first..index.views() {
            let Some(i) = index.get(view) else { continue };
            index.set(view, None);
            let e = &mut v.vacbs[i as usize];
            e.scm = core::ptr::null();
            e.active = 1;
            e.ready = false;
            taken.push((i as usize, e.slot, e.section.take()));
        }
        break;
    }
    for (i, slot, section) in &mut taken {
        if let Some(section) = section.take() {
            cache::unmap_cache_view(&section, *slot, false);
        }
        let mut g = VACBS.lock();
        let e = &mut g.as_mut().expect("started").vacbs[*i];
        e.active = 0;
        e.ready = true;
    }
    true
}

/// Run `f` on the pool with its lock held.
pub fn with<R>(f: impl FnOnce(&Vacbs) -> R) -> R {
    f(VACBS.lock().as_ref().expect("started"))
}

/// The index of a map's views, made for a section of `size` bytes and
/// installed, or `STATUS_INSUFFICIENT_RESOURCES`.
pub fn make_index(scm: &Scm, size: u64) -> Result<(), NTSTATUS> {
    let index = nk_cc::vacbidx::VacbIndex::new(size).map_err(|_| STATUS_INSUFFICIENT_RESOURCES)?;
    let old = {
        let _g = VACBS.lock();
        // SAFETY: guarded by the lock.
        unsafe { (*scm.index.get()).replace(index) }
    };
    drop(old);
    Ok(())
}

/// Grow a map's index for a section of `size` bytes, keeping its views.
pub fn grow_index(scm: &Scm, size: u64) -> Result<(), NTSTATUS> {
    let mut index =
        nk_cc::vacbidx::VacbIndex::new(size).map_err(|_| STATUS_INSUFFICIENT_RESOURCES)?;
    let old_views = {
        let _g = VACBS.lock();
        // SAFETY: guarded by the lock.
        unsafe { (*scm.index.get()).as_ref().map_or(0, |i| i.views()) }
    };
    if index.needs_leaf_to_adopt(old_views) {
        let leaf = Leaf::new().map_err(|_| STATUS_INSUFFICIENT_RESOURCES)?;
        let _ = index.insert_leaf(0, leaf);
    }
    let old = {
        let _g = VACBS.lock();
        // SAFETY: guarded by the lock.
        let slot = unsafe { &mut *scm.index.get() };
        match slot.as_mut() {
            Some(old) if old.views() > index.views() => None,
            Some(old) => {
                index.adopt(old);
                slot.replace(index)
            }
            None => slot.replace(index),
        }
    };
    drop(old);
    Ok(())
}

/// Drop a map's index once its views are taken back.
pub fn drop_index(scm: &Scm) {
    let old = {
        let _g = VACBS.lock();
        // SAFETY: guarded by the lock.
        unsafe { (*scm.index.get()).take() }
    };
    if let Some(old) = &old
        && old.mapped().next().is_some()
    {
        cache_manager_bugcheck(format_args!("a map is deleted with views mapped"));
    }
    drop(old);
}
