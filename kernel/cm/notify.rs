//! `ZwNotifyChangeKey`: telling a driver that a key has changed.
//!
//! The registry lives in memory and changes there: drivers and NK set
//! and delete values and make and delete keys. A driver that watches a
//! key (`nk_cm::notify`) is told once, by the change that meets its
//! watch; the watch ends, untold, when the handle it was made through
//! is closed. Telling is what the kernel-mode form of the routine asks
//! for: the status block is written, the event set, the caller's work
//! item queued.

#![allow(non_snake_case)]

use super::key_of;
use crate::ex::work;
use crate::ke::{Rank, SpinLock, wait};
use crate::ob::{handle, object};
use alloc::vec::Vec;
use core::ffi::c_void;
use core::mem::MaybeUninit;
use core::sync::atomic::{AtomicI32, Ordering};
use nk_cm::notify::{self, Watch, Watches};
use nk_cm::{Hive, KeyId};
use nk_ntabi::io::IO_STATUS_BLOCK;
use nk_ntabi::ke::KEVENT;
use nk_ntabi::status::{
    NTSTATUS, STATUS_INSUFFICIENT_RESOURCES, STATUS_INVALID_PARAMETER, STATUS_NOTIFY_CLEANUP,
    STATUS_NOTIFY_ENUM_DIR, STATUS_PENDING,
};

/// How a watcher is told: each part may be absent (0).
#[derive(Clone, Copy)]
struct Telling {
    /// The caller's `IO_STATUS_BLOCK` (for async watches).
    status_block: usize,
    /// The caller's event, an object referenced for the watch.
    event: usize,
    /// The caller's `WORK_QUEUE_ITEM`, and the queue it goes on.
    work_item: usize,
    queue: u32,
    /// Stack-resident `KEVENT` and status slot for synchronous watches
    /// (`asynchronous == 0`); not an object-manager object.
    sync_event: usize,
    sync_status: usize,
}

static WATCHES: SpinLock<Watches<Telling>> = SpinLock::new(Rank::RegistryWatches, Watches::new());

/// The watches a change has met, taken out of the table, to be told
/// once the registry's lock is released.
#[must_use]
pub(super) struct Met(Option<Vec<Watch<Telling>>>);

impl Met {
    /// Tell every watcher: the key changed.
    pub(super) fn tell(self) {
        tell_all(self.0, STATUS_NOTIFY_ENUM_DIR);
    }
}

/// Tell each of `watches` with `status`.
fn tell_all(watches: Option<Vec<Watch<Telling>>>, status: NTSTATUS) {
    for watch in watches.into_iter().flatten() {
        // SAFETY: what the watcher gave when it made the watch, which
        // by the routine's contract stays valid until it is told.
        unsafe { tell(watch.what, status) };
    }
}

/// Tell one watcher.
///
/// # Safety
/// The parts of `telling` are what `ZwNotifyChangeKey` was given, still
/// valid, and the event is referenced.
unsafe fn tell(telling: Telling, status: NTSTATUS) {
    // SAFETY: per the contract. The work item and sync event are signalled
    // last: their waiters may free the rest.
    unsafe {
        if telling.sync_status != 0 {
            let slot = core::ptr::with_exposed_provenance::<AtomicI32>(telling.sync_status);
            (*slot).store(status, Ordering::Release);
        }
        if telling.status_block != 0 {
            core::ptr::with_exposed_provenance_mut::<IO_STATUS_BLOCK>(telling.status_block)
                .write_unaligned(IO_STATUS_BLOCK {
                    Status: status,
                    Information: 0,
                });
        }
        if telling.event != 0 {
            let event = core::ptr::with_exposed_provenance_mut::<u8>(telling.event);
            wait::KeSetEvent(event.cast(), 0, 0);
            object::dereference(event);
        }
        if telling.sync_event != 0 {
            let event = core::ptr::with_exposed_provenance_mut::<KEVENT>(telling.sync_event);
            wait::KeSetEvent(event, 0, 0);
        }
        if telling.work_item != 0 {
            work::ExQueueWorkItem(
                core::ptr::with_exposed_provenance_mut(telling.work_item),
                telling.queue,
            );
        }
    }
}

/// Note a change of the kinds `change` to `key`: the watches it meets.
/// Called with the registry's lock held, after the change; the caller
/// tells them once it has released that lock.
///
/// Without memory to list the keys above, or the watches met, nobody
/// is told and the watches stay.
pub(super) fn changed(hive: &Hive, key: KeyId, change: u32) -> Met {
    let mut watches = WATCHES.lock();
    if watches.count() == 0 {
        return Met(None);
    }
    // The key, the key it is a subkey of, and so on up to the root,
    // which is its own parent.
    let mut chain = Vec::new();
    let mut at = key;
    loop {
        if chain.try_reserve(1).is_err() {
            return Met(None);
        }
        chain.push(at.index());
        match hive.parent(at) {
            Ok(parent) if parent != at => at = parent,
            _ => break,
        }
    }
    Met(watches.changed(&chain, change))
}

/// The key object `body` is going: the watches made through it end,
/// each told `STATUS_NOTIFY_CLEANUP`.
pub(super) fn closed(body: *mut c_void) {
    let ended = WATCHES.lock().closed(body.addr());
    tell_all(ended, STATUS_NOTIFY_CLEANUP);
}

/// [`ZwNotifyChangeKey`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-zwnotifychangekey):
/// ask to be told of the next change to a key, or to the keys below it
/// too. NK has the form a kernel-mode caller uses, asynchronous: the
/// routine returns `STATUS_PENDING`, and when a change of a kind in
/// `filter` is made the status block is given `STATUS_NOTIFY_ENUM_DIR`,
/// the event is set, and the work item `work_item` is queued on the
/// queue `queue`; any of the three may be absent. The watch is met
/// once. Closing the handle ends it, telling the same way with
/// `STATUS_NOTIFY_CLEANUP`.
///
/// The changes seen are those made through `ZwSetValueKey`,
/// `ZwDeleteValueKey` (last set), `ZwCreateKey` and `ZwDeleteKey` (a
/// name, at the key above) and by NK itself. No buffer of changes is
/// filled, as Windows fills none.
///
/// | Refusal | Status |
/// | --- | --- |
/// | a filter of no change, or of unknown ones | `STATUS_INVALID_PARAMETER` |
/// | a handle that is not a key's, or an event handle that is not an event's | what the handle look-up says |
/// | no memory | `STATUS_INSUFFICIENT_RESOURCES` |
///
/// A synchronous request, which waits for the change, stops the system
/// by name.
///
/// # Safety
/// `status_block` and `work_item` are null or stay valid until the
/// watcher is told.
#[allow(clippy::too_many_arguments)]
pub unsafe extern "C" fn NtNotifyChangeKey(
    key_handle: *mut c_void,
    event: *mut c_void,
    work_item: *mut c_void,
    queue: *mut c_void,
    status_block: *mut IO_STATUS_BLOCK,
    filter: u32,
    watch_tree: u8,
    _buffer: *mut c_void,
    _buffer_size: u32,
    asynchronous: u8,
) -> NTSTATUS {
    let mode = crate::svc::capture::mode();
    let handle_mode = crate::svc::capture::handle_mode(mode);
    // Held to the end of the call: longer than any lock.
    let held = match key_of(key_handle) {
        Ok(held) => held,
        Err(status) => return status,
    };
    if !notify::filter_is_legal(filter) {
        return STATUS_INVALID_PARAMETER;
    }
    let event = if event.is_null() {
        core::ptr::null_mut()
    } else {
        match handle::reference_for(
            event as u64,
            Some(&raw const object::EVENT_TYPE),
            0x2,
            handle_mode,
        ) {
            // The watch's reference from here: given up when it fires
            // or goes.
            Ok((body, _)) => body.into_raw(),
            Err(status) => return status,
        }
    };
    if asynchronous == 0 {
        let mut sync_event = MaybeUninit::<KEVENT>::uninit();
        let sync_status = AtomicI32::new(STATUS_PENDING);
        // SAFETY: stack-resident `KEVENT` initialised before registration and
        // kept alive until `wait_as` returns (after `tell` signals it).
        unsafe { wait::KeInitializeEvent(sync_event.as_mut_ptr(), 0, 0) };
        let watch = Watch {
            key: held.key().index(),
            owner: held.body().addr(),
            filter,
            subtree: watch_tree != 0,
            what: Telling {
                status_block: 0,
                event: event.expose_provenance(),
                work_item: 0,
                queue: 0,
                sync_event: sync_event.as_mut_ptr().expose_provenance(),
                sync_status: (&raw const sync_status).expose_provenance(),
            },
        };
        if WATCHES.lock().add(watch).is_err() {
            if !event.is_null() {
                // SAFETY: the reference taken above.
                unsafe { object::dereference(event) };
            }
            return STATUS_INSUFFICIENT_RESOURCES;
        }
        // SAFETY: `sync_event` is initialised and live until `tell` signals it.
        let _ = unsafe { wait::wait_as(Some(sync_event.as_mut_ptr().cast()), None, mode, false) };
        let final_status = sync_status.load(Ordering::Acquire);
        if !status_block.is_null() {
            let iosb = IO_STATUS_BLOCK {
                Status: final_status,
                Information: 0,
            };
            // SAFETY: per the contract; fault-protected for `UserMode`.
            if let Err(fault) = unsafe { crate::svc::capture::write(status_block, iosb, mode) } {
                return fault;
            }
        }
        return final_status;
    }
    let watch = Watch {
        key: held.key().index(),
        owner: held.body().addr(),
        filter,
        subtree: watch_tree != 0,
        what: Telling {
            status_block: status_block.expose_provenance(),
            event: event.expose_provenance(),
            work_item: work_item.expose_provenance(),
            // A `WORK_QUEUE_TYPE`, passed in a pointer's place.
            queue: queue.addr() as u32,
            sync_event: 0,
            sync_status: 0,
        },
    };
    let added = WATCHES.lock().add(watch);
    match added {
        Ok(()) => STATUS_PENDING,
        Err(_) => {
            if !event.is_null() {
                // SAFETY: the reference taken above.
                unsafe { object::dereference(event) };
            }
            STATUS_INSUFFICIENT_RESOURCES
        }
    }
}

/// For the self-tests: how many watches there are.
pub fn watches() -> usize {
    WATCHES.lock().count()
}

pub use crate::svc::zw::ZwNotifyChangeKey;
