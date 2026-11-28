//! Cache maps: `CcInitializeCacheMap` makes a file's shared cache map and
//! a file object's private one; `CcUninitializeCacheMap` takes the
//! private one away and deletes the shared one as Windows decides
//! (`nk_cc::uninit`).
//!
//! A shared cache map is put in `SharedCacheMap` before its section is
//! made, marked as being created; whoever finds it so waits. Its
//! creator then makes the section with no lock held, takes a reference
//! on the file object (kept until the map is deleted), and, for a stream
//! file object whose header does not ask for the modified-page writer,
//! has the memory manager leave its pages to the cache manager alone.

use super::vacb::{self, Busy};
use super::{
    MASTER, Pcm, Scm, TAG_PCM, TAG_SCM, alloc_in_pool, cache_manager_bugcheck, flag, free_in_pool,
    or_raise, trace, wait_lifecycle, wake_lifecycle_waiters,
};
use crate::arch::seh::{Context, fourth_argument, stack_argument};
use crate::mm::{flush, section};
use crate::ob::object;
use core::cell::{Cell, UnsafeCell};
use core::ffi::c_void;
use nk_cc::mbcb::Mbcb;
use nk_cc::uninit::{self, Outcome};
use nk_ntabi::cc::*;
use nk_ntabi::io::{FILE_OBJECT, SECTION_OBJECT_POINTERS};
use nk_ntabi::status::*;

/// The read-ahead granularity a private map starts with, minus one.
const READ_AHEAD_MASK: u32 = 0xFFFF;

fn new_pcm(file: *mut FILE_OBJECT, scm: *mut Scm) -> Pcm {
    Pcm {
        file_object: Cell::new(file),
        scm: Cell::new(scm),
        next: Cell::new(core::ptr::null_mut()),
        history: Cell::new(nk_cc::readahead::History::default()),
        read_ahead_mask: Cell::new(READ_AHEAD_MASK),
    }
}

/// A fresh shared cache map for `sop`, being created, or null.
fn new_scm(
    sop: *mut SECTION_OBJECT_POINTERS,
    callbacks: *const CACHE_MANAGER_CALLBACKS,
    context: *mut c_void,
) -> *mut Scm {
    let scm = alloc_in_pool(
        Scm {
            open_count: Cell::new(0),
            refs: Cell::new(1),
            flags: core::sync::atomic::AtomicU32::new(flag::BEING_CREATED),
            file_size: Cell::new(0),
            valid_data_length: Cell::new(0),
            valid_data_goal: Cell::new(0),
            section_size: Cell::new(0),
            next: Cell::new(core::ptr::null_mut()),
            prev: Cell::new(core::ptr::null_mut()),
            privates: Cell::new(core::ptr::null_mut()),
            uninit_events: Cell::new(core::ptr::null_mut()),
            inflight: Cell::new(core::ptr::null_mut()),
            flush_waiters: Cell::new(core::ptr::null_mut()),
            sop,
            file_object: Cell::new(core::ptr::null_mut()),
            callbacks,
            lazy_write_context: context,
            pages_to_write: Cell::new(0),
            section: UnsafeCell::new(None),
            index: UnsafeCell::new(None),
            dirty_pages: Cell::new(0),
            bcb_lock: UnsafeCell::new(
                // SAFETY: a FAST_MUTEX is plain data; it is initialised
                // below before use.
                unsafe { core::mem::zeroed() },
            ),
            bcbs: UnsafeCell::new(alloc::vec::Vec::new()),
            mbcb: UnsafeCell::new(Mbcb::new()),
            pcm: new_pcm(core::ptr::null_mut(), core::ptr::null_mut()),
            pcm_used: Cell::new(false),
        },
        TAG_SCM,
    );
    if !scm.is_null() {
        // SAFETY: the fresh block, ours alone; it does not move.
        unsafe {
            crate::ke::mutex::KeInitializeGuardedMutex((*scm).bcb_lock.get());
            core::ptr::write(&raw mut (*scm).pcm, new_pcm(core::ptr::null_mut(), scm));
        }
    }
    scm
}

/// Link `scm` at the head of the list of maps.
fn link(m: &mut super::Master, scm: &Scm) {
    scm.prev.set(core::ptr::null_mut());
    scm.next.set(m.head);
    // SAFETY: maps on the list are live under the lock.
    if let Some(head) = unsafe { m.head.as_ref() } {
        head.prev.set(core::ptr::from_ref(scm).cast_mut());
    }
    m.head = core::ptr::from_ref(scm).cast_mut();
}

/// Every shared cache map, under the lock.
pub fn each(m: &super::Master, mut f: impl FnMut(&Scm)) {
    let mut at = m.head;
    // SAFETY: maps on the list are live under the lock.
    while let Some(scm) = unsafe { at.as_ref() } {
        f(scm);
        at = scm.next.get();
    }
}

/// Take `scm` off the list.
fn unlink(m: &mut super::Master, scm: &Scm) {
    let (prev, next) = (scm.prev.get(), scm.next.get());
    // SAFETY: as in `link`.
    unsafe {
        match prev.as_ref() {
            Some(p) => p.next.set(next),
            None => m.head = next,
        }
        if let Some(n) = next.as_ref() {
            n.prev.set(prev);
        }
    }
    scm.next.set(core::ptr::null_mut());
    scm.prev.set(core::ptr::null_mut());
}

/// What `CcInitializeCacheMap` is entered as (`nk_with_caller_context`):
/// the fourth argument is the callbacks, the fifth the lazy-write
/// context.
///
/// # Safety
/// Called by a file system as `CcInitializeCacheMap`, at
/// `PASSIVE_LEVEL`, with `context` from `nk_with_caller_context`.
#[unsafe(no_mangle)]
unsafe extern "C" fn nk_cc_initialize_cache_map(
    file: *mut FILE_OBJECT,
    sizes: *const CC_FILE_SIZES,
    pin_access: u8,
    context: *mut Context,
) {
    // SAFETY: per the contract.
    unsafe {
        let callbacks = fourth_argument(&*context) as *const CACHE_MANAGER_CALLBACKS;
        let lazy = stack_argument(&*context, 4) as *mut c_void;
        let sizes = sizes.read_unaligned();
        let r = initialize(file, &sizes, pin_access != 0, callbacks, lazy);
        or_raise(context, r);
    }
}

/// `CcInitializeCacheMap`.
///
/// # Safety
/// `file` is a live file object whose section object pointers and FCB
/// header the file system set up.
unsafe fn initialize(
    file: *mut FILE_OBJECT,
    sizes: &CC_FILE_SIZES,
    pin_access: bool,
    callbacks: *const CACHE_MANAGER_CALLBACKS,
    lazy_context: *mut c_void,
) -> Result<(), NTSTATUS> {
    crate::ke::irql::expect_passive("CcInitializeCacheMap");
    if sizes.AllocationSize < 0 || sizes.FileSize < 0 || sizes.ValidDataLength < 0 {
        return Err(STATUS_INVALID_PARAMETER);
    }
    // SAFETY: per the contract.
    let sop = unsafe { (*file).SectionObjectPointer }.cast::<SECTION_OBJECT_POINTERS>();
    let fresh = new_scm(sop, callbacks, lazy_context);
    let spare = alloc_in_pool(new_pcm(file, core::ptr::null_mut()), TAG_PCM);
    let free_unused = |fresh: *mut Scm, spare: *mut Pcm| {
        if !fresh.is_null() {
            // SAFETY: a block of this call nothing else has seen.
            unsafe { free_in_pool(fresh) };
        }
        if !spare.is_null() {
            // SAFETY: as above.
            unsafe { free_in_pool(spare) };
        }
    };
    if fresh.is_null() || spare.is_null() {
        free_unused(fresh, spare);
        return Err(STATUS_INSUFFICIENT_RESOURCES);
    }
    // Find the map, or install the fresh one, holding a reference.
    let (scm, created) = loop {
        let mut m = MASTER.lock();
        // SAFETY: the file system's block; the field is the cache
        // manager's, under the lock.
        let existing = unsafe { (*sop).SharedCacheMap }.cast::<Scm>();
        // SAFETY: a map named by the pointer is live under the lock.
        match unsafe { existing.as_ref() } {
            None => {
                // SAFETY: the fresh map, not yet seen by anyone else.
                let s = unsafe { &*fresh };
                if pin_access {
                    s.set_flags(s.flags() | flag::PIN_ACCESS);
                }
                link(&mut m, s);
                // SAFETY: as above.
                unsafe { (*sop).SharedCacheMap = fresh.cast() };
                break (s, true);
            }
            Some(s) if s.flags() & (flag::BEING_CREATED | flag::BEING_DELETED) != 0 => {
                wait_lifecycle(m, sop);
            }
            Some(s) => {
                s.refs.set(s.refs.get() + 1);
                break (s, false);
            }
        }
    };
    let result = if created {
        create(scm, file, sizes)
    } else {
        extend_for(scm, sizes.AllocationSize as u64)
    };
    if let Err(status) = result {
        if created {
            abandon(scm);
        } else {
            release(scm);
        }
        free_unused(
            if created {
                core::ptr::null_mut()
            } else {
                fresh
            },
            spare,
        );
        return Err(status);
    }
    // The file object's private map.
    let used_spare = {
        let _m = MASTER.lock();
        // SAFETY: the file object's field is the cache manager's.
        let has = unsafe { !(*file).PrivateCacheMap.is_null() };
        let mut used_spare = false;
        if !has {
            let pcm = if scm.pcm_used.get() {
                used_spare = true;
                spare
            } else {
                scm.pcm_used.set(true);
                core::ptr::from_ref(&scm.pcm).cast_mut()
            };
            // SAFETY: a private map not yet on any list, ours.
            unsafe {
                let p = &*pcm;
                p.file_object.set(file);
                p.scm.set(core::ptr::from_ref(scm).cast_mut());
                p.next.set(scm.privates.get());
                scm.privates.set(pcm);
                (*file).PrivateCacheMap = pcm.cast();
            }
            scm.open_count.set(scm.open_count.get() + 1);
        }
        scm.refs.set(scm.refs.get() - 1);
        used_spare
    };
    free_unused(
        if created {
            core::ptr::null_mut()
        } else {
            fresh
        },
        if used_spare {
            core::ptr::null_mut()
        } else {
            spare
        },
    );
    trace(format_args!(
        "initialize {file:p}: map {:p}{}, open {}",
        core::ptr::from_ref(scm),
        if created { " (new)" } else { "" },
        scm.open_count.get()
    ));
    Ok(())
}

/// Make a fresh map's section and the rest, with no lock held.
fn create(scm: &Scm, file: *mut FILE_OBJECT, sizes: &CC_FILE_SIZES) -> Result<(), NTSTATUS> {
    // SAFETY: the caller's live file object.
    let write_access = unsafe { (*file).WriteAccess } != 0;
    let size = nk_cc::first_section_size(sizes.AllocationSize as u64, write_access);
    let section = section::create_cache_manager_section(file, size).map_err(|status| {
        nk_fsrtl::status::normalize(status as u32, super::STATUS_UNEXPECTED_MM_CREATE_ERR as u32)
            as NTSTATUS
    })?;
    let size = section.size();
    // SAFETY: the map is ours until it is no longer being created.
    unsafe { *scm.section.get() = Some(section) };
    vacb::make_index(scm, size)?;
    // SAFETY: the caller's live file object.
    unsafe { object::reference(file.cast()) };
    scm.file_object.set(file);
    let (flags2, stream) = Scm::file_kind(file);
    let mut flags = 0;
    if flags2 & FSRTL_FLAG2_DO_MODIFIED_WRITE == 0 && stream {
        section::disable_modified_write(scm.sop);
        flags |= flag::MODIFIED_WRITE_DISABLED;
    }
    let waiters = {
        let mut m = MASTER.lock();
        scm.section_size.set(size);
        scm.file_size.set(sizes.FileSize);
        scm.valid_data_length.set(sizes.ValidDataLength);
        scm.valid_data_goal.set(sizes.ValidDataLength);
        scm.set_flags((scm.flags() | flags) & !flag::BEING_CREATED);
        m.take_waiters_for(scm.sop)
    };
    wake_lifecycle_waiters(waiters);
    Ok(())
}

/// Undo a map whose creation failed: out of `SharedCacheMap` and freed.
fn abandon(scm: &Scm) {
    let waiters = {
        let mut m = MASTER.lock();
        unlink(&mut m, scm);
        // SAFETY: the file system's block; the field is ours, under the
        // lock.
        unsafe { (*scm.sop).SharedCacheMap = core::ptr::null_mut() };
        m.take_waiters_for(scm.sop)
    };
    let file = scm.file_object.get();
    vacb::drop_index(scm);
    // SAFETY: nobody finds the map any more: it was being created, so
    // whoever looked waited and will look again.
    unsafe { free_in_pool(core::ptr::from_ref(scm).cast_mut()) };
    wake_lifecycle_waiters(waiters);
    if !file.is_null() {
        // SAFETY: the reference `create` took.
        unsafe { object::dereference(file.cast()) };
    }
}

/// Give back a reference a call took on a map.
fn release(scm: &Scm) {
    let _m = MASTER.lock();
    scm.refs.set(scm.refs.get() - 1);
}

/// Grow `scm`'s section for an allocation size, as `CcSetFileSizes`
/// does: to the size rounded up to 1 MiB, when it is larger.
pub fn extend_for(scm: &Scm, allocation: u64) -> Result<(), NTSTATUS> {
    if allocation <= scm.section_size.get() {
        return Ok(());
    }
    let size = nk_cc::extended_section_size(allocation);
    let grown = section::extend_section(scm.section(), size).map_err(|status| {
        nk_fsrtl::status::normalize(status as u32, super::STATUS_UNEXPECTED_MM_EXTEND_ERR as u32)
            as NTSTATUS
    })?;
    vacb::grow_index(scm, grown)?;
    let _m = MASTER.lock();
    scm.section_size.set(scm.section_size.get().max(grown));
    Ok(())
}

/// [`CcUninitializeCacheMap`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-ccuninitializecachemap):
/// the file object no longer caches the file. TRUE only when the shared
/// cache map was deleted in this call; `event`, if given, is signalled
/// once, when the shared cache map is deleted (at once if the file was
/// not cached).
///
/// # Safety
/// `file` is a live file object; `truncate` null or readable; `event`
/// null or an initialised `CACHE_UNINITIALIZE_EVENT` that stays valid
/// until signalled. At `PASSIVE_LEVEL`.
pub unsafe extern "C" fn CcUninitializeCacheMap(
    file: *mut FILE_OBJECT,
    truncate: *const i64,
    event: *mut CACHE_UNINITIALIZE_EVENT,
) -> u8 {
    crate::ke::irql::expect_passive("CcUninitializeCacheMap");
    // SAFETY: per the contract.
    let truncate = unsafe { truncate.as_ref() }.copied();
    // SAFETY: per the contract.
    let sop = unsafe { (*file).SectionObjectPointer }.cast::<SECTION_OBJECT_POINTERS>();
    let mut freed_pcm = core::ptr::null_mut();
    let outcome = loop {
        let mut m = MASTER.lock();
        // SAFETY: as in `initialize`.
        let scm = unsafe { sop.as_ref() }
            .map_or(core::ptr::null_mut(), |s| s.SharedCacheMap.cast::<Scm>());
        // SAFETY: as in `initialize`.
        match unsafe { scm.as_ref() } {
            None => break None,
            Some(s) if s.flags() & (flag::BEING_CREATED | flag::BEING_DELETED) != 0 => {
                wait_lifecycle(m, sop);
                continue;
            }
            Some(scm) => {
                // SAFETY: the file object's field is the cache manager's.
                let pcm = unsafe { (*file).PrivateCacheMap }.cast::<Pcm>();
                // SAFETY: a private map the field names is live.
                if let Some(p) = unsafe { pcm.as_ref() } {
                    if !core::ptr::eq(p.scm.get(), scm) || p.file_object.get() != file {
                        drop(m);
                        cache_manager_bugcheck(format_args!(
                            "the private cache map of {file:p} is not its file's (0x994)"
                        ));
                    }
                    unlink_pcm(scm, pcm);
                    // SAFETY: as above.
                    unsafe { (*file).PrivateCacheMap = core::ptr::null_mut() };
                    scm.open_count.set(scm.open_count.get() - 1);
                    if core::ptr::eq(pcm, &raw const scm.pcm) {
                        scm.pcm_used.set(false);
                    } else {
                        freed_pcm = pcm;
                    }
                }
                if let Some(t) = truncate
                    && scm.file_size.get() > t
                {
                    scm.file_size.set(t);
                    scm.set_flags(scm.flags() | flag::TRUNCATE_REQUIRED);
                }
                let dirty_pages = {
                    let _d = super::DIRTY.lock();
                    scm.dirty_pages.get()
                };
                let f = scm.flags();
                let state = uninit::State {
                    open_count: scm.open_count.get(),
                    dirty_pages,
                    write_queued: f & flag::WRITE_QUEUED != 0,
                    pin_access: f & flag::PIN_ACCESS != 0,
                    truncate: truncate.is_some(),
                };
                let outcome = match uninit::decide(&state) {
                    Outcome::DeleteNow if scm.refs.get() == 0 => {
                        begin_delete(&mut m, scm);
                        Outcome::DeleteNow
                    }
                    Outcome::DeleteNow => Outcome::Lazy,
                    other => other,
                };
                if outcome != Outcome::DeleteNow && !event.is_null() {
                    // SAFETY: the caller's event, valid until signalled.
                    unsafe { (*event).Next = scm.uninit_events.get() };
                    scm.uninit_events.set(event);
                }
                break Some((scm, outcome));
            }
        }
    };
    if !freed_pcm.is_null() {
        // SAFETY: off every list, nothing names it.
        unsafe { free_in_pool(freed_pcm) };
    }
    let deleted = match outcome {
        None => {
            if let Some(t) = truncate {
                flush::purge_section(sop, Some((t as u64, 0)), false);
            }
            if !event.is_null() {
                // SAFETY: the caller's event.
                unsafe { signal(event) };
            }
            false
        }
        Some((scm, Outcome::DeleteNow)) => {
            delete(scm);
            if !event.is_null() {
                // SAFETY: as above.
                unsafe { signal(event) };
            }
            true
        }
        Some((_, Outcome::Lazy)) => {
            super::lazy::schedule_scan();
            false
        }
        Some(_) => false,
    };
    trace(format_args!(
        "uninitialize {file:p}: {}",
        if deleted { "deleted" } else { "kept" }
    ));
    u8::from(deleted)
}

/// Signal an uninitialize event.
///
/// # Safety
/// `event` is a live `CACHE_UNINITIALIZE_EVENT`.
unsafe fn signal(event: *mut CACHE_UNINITIALIZE_EVENT) {
    // SAFETY: per the contract.
    unsafe { crate::ke::wait::KeSetEvent(&raw mut (*event).Event, 0, 0) };
}

/// Take `pcm` off `scm`'s list, under the lock.
fn unlink_pcm(scm: &Scm, pcm: *mut Pcm) {
    let mut at = &scm.privates;
    // SAFETY: private maps on the list are live under the lock.
    while let Some(p) = unsafe { at.get().as_ref() } {
        if core::ptr::eq(p, pcm) {
            at.set(p.next.get());
            return;
        }
        at = &p.next;
    }
}

/// Start deleting `scm`, under the lock: nobody else finds it to use.
pub fn begin_delete(m: &mut super::Master, scm: &Scm) {
    scm.set_flags(scm.flags() | flag::BEING_DELETED);
    unlink(m, scm);
}

/// `CcDeleteSharedCacheMap`, once [`begin_delete`] ran: take back the
/// views, purge from the file size if it was truncated, free the BCBs,
/// clear `SharedCacheMap`, signal the uninitialize events, free the
/// map, and drop the reference on the file object last (which may send
/// its file system the close).
pub fn delete(scm: &Scm) {
    vacb::unmap_views(scm, 0, Busy::Wait);
    if scm.flags() & flag::TRUNCATE_REQUIRED != 0 {
        flush::purge_section(scm.sop, Some((scm.file_size.get() as u64, 0)), false);
    }
    super::pin::delete_bcbs(scm);
    vacb::drop_index(scm);
    // SAFETY: the deletion owns the map now; nothing maps it.
    let section = unsafe { (*scm.section.get()).take() };
    drop(section);
    let (events, waiters) = {
        let mut m = MASTER.lock();
        // SAFETY: the file system's block; the field is ours.
        unsafe { (*scm.sop).SharedCacheMap = core::ptr::null_mut() };
        (
            scm.uninit_events.replace(core::ptr::null_mut()),
            m.take_waiters_for(scm.sop),
        )
    };
    let mut event = events;
    while !event.is_null() {
        // SAFETY: each event on the chain is its caller's, valid until
        // signalled; its link is read before.
        unsafe {
            let next = (*event).Next;
            signal(event);
            event = next;
        }
    }
    let file = scm.file_object.get();
    trace(format_args!(
        "delete map {:p} of {file:p}",
        core::ptr::from_ref(scm)
    ));
    // SAFETY: off the list and out of `SharedCacheMap`: nothing names
    // it.
    unsafe { free_in_pool(core::ptr::from_ref(scm).cast_mut()) };
    // Wake lifecycle waiters before dropping the file reference (which may
    // call into the file system for IRP_MJ_CLOSE) so waiters never block on
    // file-system callbacks or FCB locks.
    wake_lifecycle_waiters(waiters);
    // SAFETY: the reference `create` took.
    unsafe { object::dereference(file.cast()) };
}
