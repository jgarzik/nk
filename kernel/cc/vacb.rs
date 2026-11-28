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

use super::{Scm, cache_manager_bugcheck};
use crate::ke::spinlock::{Rank, SpinLock};
use crate::ke::wait;
use crate::mm::cache::{self, CacheSlot};
use crate::mm::section::SectionRef;
use alloc::vec::Vec;
use core::mem::MaybeUninit;
use nk_cc::VIEW_BYTES;
use nk_cc::vacbidx::Leaf;
use nk_ntabi::ke::KEVENT;
use nk_ntabi::status::*;

/// A thread waiting on a VACB transition (mapping, eviction, or release),
/// living on the sleeper's stack until its event is signalled.
struct Waiter {
    next: *mut Waiter,
    event: *mut KEVENT,
}

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
    waiters: *mut Waiter,
}

// SAFETY: the raw pointers name shared cache maps and stack-pinned waiters,
// reached only under the lock.
unsafe impl Send for Vacbs {}

/// The views and every map's index of them.
pub static VACBS: SpinLock<Option<Vacbs>> = SpinLock::new(Rank::CcVacbs, None);

/// Signal every waiter detached from `Vacbs::waiters`, with `VACBS` dropped.
fn wake_waiters(mut head: *mut Waiter) {
    while !head.is_null() {
        // SAFETY: each waiter lives on its sleeper's stack until signalled;
        // read `next` before waking.
        unsafe {
            let next = (*head).next;
            wait::KeSetEvent((*head).event, 0, 0);
            head = next;
        }
    }
}

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
    *VACBS.lock() = Some(Vacbs {
        vacbs,
        tick: 0,
        waiters: core::ptr::null_mut(),
    });
    Ok(())
}

impl Vacbs {
    fn enqueue_waiter(&mut self, waiter: *mut Waiter) {
        // SAFETY: `waiter` lives on the caller's stack until signalled.
        unsafe { (*waiter).next = self.waiters };
        self.waiters = waiter;
    }

    fn take_waiters(&mut self) -> *mut Waiter {
        core::mem::replace(&mut self.waiters, core::ptr::null_mut())
    }

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
/// it is not, with one more user. Waits for an in-flight mapping or
/// eviction of that range.
pub fn get_va(scm: &Scm, offset: u64) -> Result<View, NTSTATUS> {
    get_va_wait(scm, offset, true).map(|v| v.expect("waiting get_va always yields a view"))
}

/// As [`get_va`], honoring `wait` when the requested range is currently
/// being mapped or evicted on another processor: returns `Ok(None)` when
/// `!wait` rather than sleeping.
pub fn get_va_wait(scm: &Scm, offset: u64, wait_ok: bool) -> Result<Option<View>, NTSTATUS> {
    let section_size = scm.section_size.get();
    if offset >= section_size {
        cache_manager_bugcheck(format_args!(
            "offset {offset:#x} is beyond the section ({section_size:#x}) of the map at {:p}",
            core::ptr::from_ref(scm)
        ));
    }
    let view = (offset / VIEW_BYTES) as usize;
    let mut leaf = None;
    let (i, slot) = loop {
        let mut g = VACBS.lock();
        let v = g.as_mut().expect("the cache manager has started");
        // SAFETY: the index is guarded by this lock.
        let index = unsafe { &mut *scm.index.get() }
            .as_mut()
            .expect("a shared cache map with no index");
        if let Some(i) = index.get(view) {
            let i = i as usize;
            if !v.vacbs[i].ready {
                if !wait_ok {
                    return Ok(None);
                }
                let mut event = MaybeUninit::<KEVENT>::uninit();
                // SAFETY: stack event, signalled before this block ends.
                unsafe { wait::KeInitializeEvent(event.as_mut_ptr(), 0, 0) };
                let mut waiter = Waiter {
                    next: core::ptr::null_mut(),
                    event: event.as_mut_ptr(),
                };
                v.enqueue_waiter(&raw mut waiter);
                drop(g);
                // SAFETY: as above.
                unsafe { wait::wait(Some(event.as_mut_ptr().cast()), None) };
                continue;
            }
            v.tick += 1;
            let tick = v.tick;
            let e = &mut v.vacbs[i];
            e.active += 1;
            e.used = tick;
            return Ok(Some(view_of(e, offset, section_size, i)));
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
        let e = &mut v.vacbs[i];
        if !e.scm.is_null() {
            // Two-phase eviction: keep `previous.index[old_view]` pointing at
            // this `!ready` VACB until MM finishes unmapping `slot`, so any
            // concurrent lookup of the evicted range waits (or declines)
            // instead of double-mapping the subsection. `unmap_views(...,
            // Busy::Wait)` also waits on `!ready`, keeping `previous` alive.
            let old = e.section.take();
            let old_slot = e.slot;
            e.active = 1;
            e.ready = false;
            drop(g);
            if let Some(old) = old {
                cache::unmap_cache_view(&old, old_slot, false);
            }
            let waiters = {
                let mut g = VACBS.lock();
                let v = g.as_mut().expect("started");
                let e = &mut v.vacbs[i];
                // SAFETY: `previous` kept its index while our `!ready` entry
                // remained registered in it.
                if let Some(previous) = unsafe { e.scm.as_ref() } {
                    // SAFETY: guarded by `VACBS`.
                    unsafe { &mut *previous.index.get() }
                        .as_mut()
                        .expect("a mapped map has an index")
                        .set(e.view, None);
                }
                e.scm = core::ptr::null();
                e.view = 0;
                e.active = 0;
                e.ready = true;
                v.take_waiters()
            };
            wake_waiters(waiters);
            continue;
        }
        v.tick += 1;
        let tick = v.tick;
        e.scm = scm;
        e.view = view;
        e.active = 1;
        e.used = tick;
        e.ready = false;
        index.set(view, Some(i as u32));
        break (i, e.slot);
    };
    drop(leaf);
    let section = scm.section().clone();
    let base = view as u64 * VIEW_BYTES;
    let size = VIEW_BYTES.min(section_size - base) as u32;
    let mapped = cache::map_cache_view(&section, slot, base, size);
    super::trace(format_args!(
        "view {:#x} of {:p} at {base:#x}: {mapped:x?}",
        slot.0,
        core::ptr::from_ref(scm)
    ));
    let (result, waiters, drop_section) = {
        let mut g = VACBS.lock();
        let v = g.as_mut().expect("started");
        let e = &mut v.vacbs[i];
        match mapped {
            Ok(()) => {
                e.section = Some(section);
                e.ready = true;
                let view_out = view_of(e, offset, section_size, i);
                let waiters = v.take_waiters();
                (Ok(Some(view_out)), waiters, None)
            }
            Err(status) => {
                e.scm = core::ptr::null();
                e.view = 0;
                e.active = 0;
                e.ready = true;
                // SAFETY: as above.
                unsafe { &mut *scm.index.get() }
                    .as_mut()
                    .expect("index")
                    .set(view, None);
                let waiters = v.take_waiters();
                (
                    Err(
                        nk_fsrtl::status::normalize(status as u32, STATUS_UNEXPECTED_MM_MAP as u32)
                            as NTSTATUS,
                    ),
                    waiters,
                    Some(section),
                )
            }
        }
    };
    wake_waiters(waiters);
    drop(drop_section);
    result
}

const STATUS_UNEXPECTED_MM_MAP: NTSTATUS = super::STATUS_UNEXPECTED_MM_MAP_ERROR;

/// `CcFreeVirtualAddress`: one user fewer of VACB `i`.
pub fn free_va(i: usize) {
    let waiters = {
        let mut g = VACBS.lock();
        let v = g.as_mut().expect("started");
        let e = &mut v.vacbs[i];
        if e.active == 0 {
            drop(g);
            cache_manager_bugcheck(format_args!("a view nobody uses is given back (VACB {i})"));
        }
        e.active -= 1;
        if e.active == 0 {
            v.take_waiters()
        } else {
            core::ptr::null_mut()
        }
    };
    wake_waiters(waiters);
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
    let mut taken: Vec<(usize, usize, CacheSlot, Option<SectionRef>)> = Vec::with_capacity(room);
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
            if busy == Busy::Fail {
                return false;
            }
            let mut event = MaybeUninit::<KEVENT>::uninit();
            // SAFETY: stack event, signalled before this block ends.
            unsafe { wait::KeInitializeEvent(event.as_mut_ptr(), 0, 0) };
            let mut waiter = Waiter {
                next: core::ptr::null_mut(),
                event: event.as_mut_ptr(),
            };
            v.enqueue_waiter(&raw mut waiter);
            drop(g);
            // SAFETY: as above.
            unsafe { wait::wait(Some(event.as_mut_ptr().cast()), None) };
            continue;
        }
        for view in first..index.views() {
            let Some(i) = index.get(view) else { continue };
            // Keep `index[view]` pointing at this `!ready` VACB until MM
            // finishes unmapping `slot`, so a racing `get_va` cannot map
            // the same subsection into another slot meanwhile.
            let e = &mut v.vacbs[i as usize];
            e.active = 1;
            e.ready = false;
            taken.push((i as usize, view, e.slot, e.section.take()));
        }
        break;
    }
    for (i, view, slot, section) in &mut taken {
        if let Some(section) = section.take() {
            cache::unmap_cache_view(&section, *slot, false);
        }
        let waiters = {
            let mut g = VACBS.lock();
            let v = g.as_mut().expect("started");
            // SAFETY: guarded by `VACBS`.
            if let Some(index) = (unsafe { &mut *scm.index.get() }).as_mut() {
                index.set(*view, None);
            }
            let e = &mut v.vacbs[*i];
            e.scm = core::ptr::null();
            e.view = 0;
            e.active = 0;
            e.ready = true;
            v.take_waiters()
        };
        wake_waiters(waiters);
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

// ---- tests --------------------------------------------------------------

/// Exercise concurrent VACB eviction (both `get_va` recycling and
/// `unmap_views`) against waiting and no-wait lookups of the evicted view
/// from another processor.
pub fn evict_race_test(scm: &Scm) -> Result<(), &'static str> {
    use crate::ke::thread;
    use core::sync::atomic::{AtomicBool, AtomicU32, Ordering};

    struct Shared {
        scm: *const Scm,
        stop: AtomicBool,
        acquired: AtomicU32,
        declined: AtomicU32,
        bad: AtomicBool,
    }

    fn reader(arg: usize) {
        // SAFETY: `arg` points to `Shared` on the test's stack until this
        // thread exits.
        let s = unsafe { &*(arg as *const Shared) };
        // SAFETY: `scm` stays cached for the whole test.
        let scm = unsafe { &*s.scm };
        while !s.stop.load(Ordering::Acquire) {
            match get_va_wait(scm, 0, false) {
                Ok(Some(v)) => {
                    s.acquired.fetch_add(1, Ordering::Relaxed);
                    free_va(v.vacb);
                }
                Ok(None) => {
                    s.declined.fetch_add(1, Ordering::Relaxed);
                }
                Err(STATUS_INSUFFICIENT_RESOURCES) => {}
                Err(_) => s.bad.store(true, Ordering::Release),
            }
            match get_va_wait(scm, 0, true) {
                Ok(Some(v)) => {
                    s.acquired.fetch_add(1, Ordering::Relaxed);
                    free_va(v.vacb);
                }
                Ok(None) | Err(STATUS_INSUFFICIENT_RESOURCES) => {}
                Err(_) => s.bad.store(true, Ordering::Release),
            }
            thread::yield_now();
        }
    }

    // Start clean, then map view 0 and keep only its VACB unpinned so every
    // `get_va(scm, VIEW_BYTES)` must evict view 0.
    unmap_views(scm, 0, Busy::Wait);
    let v0 = get_va(scm, 0).map_err(|_| "could not map view 0")?;
    let keep_vacb = v0.vacb;
    free_va(keep_vacb);

    let room = VACBS.lock().as_ref().map_or(0, |v| v.vacbs.len());
    let mut pinned = Vec::with_capacity(room);
    {
        let mut g = VACBS.lock();
        let v = g.as_mut().expect("started");
        for (i, e) in v.vacbs.iter_mut().enumerate() {
            if i != keep_vacb {
                e.active += 1;
                pinned.push(i);
            }
        }
    }
    let shared = Shared {
        scm: core::ptr::from_ref(scm),
        stop: AtomicBool::new(false),
        acquired: AtomicU32::new(0),
        declined: AtomicU32::new(0),
        bad: AtomicBool::new(false),
    };
    let before = thread::count();
    let worker = thread::create_referenced(
        reader,
        core::ptr::from_ref(&shared).addr(),
        thread::NORMAL_PRIORITY,
        thread::ANYWHERE,
    );
    let worker = match worker {
        Ok(w) => w,
        Err(why) => {
            let mut g = VACBS.lock();
            let v = g.as_mut().expect("started");
            for &i in &pinned {
                v.vacbs[i].active -= 1;
            }
            drop(g);
            return Err(why);
        }
    };

    // Phase 1: recycle the single unpinned VACB between view 0 and view 1
    // while another CPU concurrently looks up view 0 (wait and no-wait).
    for _ in 0..32 {
        if let Ok(v1) = get_va(scm, VIEW_BYTES) {
            free_va(v1.vacb);
        }
        thread::yield_now();
    }

    // Phase 2: release one extra slot so a racing lookup could claim a
    // second slot if eviction hid the index entry before MM unmapped, and
    // stress `unmap_views` against concurrent lookups.
    let unpin_extra = pinned.last().copied();
    if let Some(extra) = unpin_extra {
        let waiters = {
            let mut g = VACBS.lock();
            let v = g.as_mut().expect("started");
            v.vacbs[extra].active -= 1;
            v.take_waiters()
        };
        wake_waiters(waiters);
    }
    for _ in 0..32 {
        if let Ok(v0) = get_va(scm, 0) {
            free_va(v0.vacb);
        }
        let _ = unmap_views(scm, 0, Busy::Wait);
        thread::yield_now();
    }

    shared.stop.store(true, Ordering::Release);
    // SAFETY: referenced thread object.
    unsafe {
        wait::wait(Some(worker.cast()), None);
        crate::ob::object::dereference(worker.cast());
    }
    thread::settle(before);

    // Restore all temporarily pinned VACBs and unmap test views cleanly.
    let waiters = {
        let mut g = VACBS.lock();
        let v = g.as_mut().expect("started");
        for &i in &pinned {
            if Some(i) != unpin_extra {
                v.vacbs[i].active -= 1;
            }
        }
        v.take_waiters()
    };
    wake_waiters(waiters);
    unmap_views(scm, 0, Busy::Wait);

    if shared.bad.load(Ordering::Acquire) {
        return Err("concurrent lookup during VACB eviction failed unexpectedly");
    }
    if shared.acquired.load(Ordering::Relaxed) == 0 {
        return Err("concurrent reader never acquired view 0 during eviction test");
    }
    Ok(())
}
