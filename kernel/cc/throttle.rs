//! Throttling writers: `CcCanIWrite` and `CcDeferWrite`.
//!
//! A write may proceed while the cache's dirty pages and its own stay
//! within the dirty-page threshold. Otherwise a writer that may wait is
//! queued (on its own stack, with an event) and one that may not gets
//! FALSE; `CcDeferWrite` queues the file system's post routine instead.
//! The queue is served in order, as dirty pages are written: after every
//! write-behind and scan (`CcPostDeferredWrites`). An entry that cannot
//! be allocated has its post routine called at once, as on Windows.
//!
//! Windows' soft throttle (a delay) and the memory manager's check of
//! memory for the write are not built: a writer over the threshold waits
//! for the lazy writer.

use super::DIRTY;
use super::lazy::{schedule_scan, threshold};
use crate::ke::seh::{self, Guard};
use crate::ke::wait;
use crate::mm::{PAGE_SIZE, pool};
use core::ffi::c_void;
use core::mem::MaybeUninit;
use nk_ntabi::io::FILE_OBJECT;
use nk_ntabi::ke::KEVENT;

const TAG_DEFERRED: u32 = u32::from_le_bytes(*b"CcDw");

/// What a deferred write is waiting to do.
enum Then {
    Signal(*mut KEVENT),
    Post {
        routine: usize,
        context1: usize,
        context2: usize,
    },
}

/// A deferred write (`_DEFERRED_WRITE`).
pub struct Deferred {
    next: *mut Deferred,
    pages: u64,
    then: Then,
    /// From the pool (else on a waiter's stack).
    pooled: bool,
}

/// The queue of deferred writes, under [`DIRTY`].
pub struct Queue {
    head: *mut Deferred,
}

impl Queue {
    pub const fn new() -> Self {
        Self {
            head: core::ptr::null_mut(),
        }
    }

    fn insert(&mut self, d: *mut Deferred, first: bool) {
        // SAFETY: entries are the queue's while on it.
        unsafe {
            if first || self.head.is_null() {
                (*d).next = self.head;
                self.head = d;
                return;
            }
            let mut at = self.head;
            while !(*at).next.is_null() {
                at = (*at).next;
            }
            (*d).next = core::ptr::null_mut();
            (*at).next = d;
        }
    }
}

// SAFETY: entries are reached only under the lock.
unsafe impl Send for Queue {}

/// The pages of a write of `bytes`.
fn pages(bytes: u32) -> u64 {
    u64::from(bytes).div_ceil(PAGE_SIZE as u64)
}

/// Whether `pages` more dirty pages stay within the threshold.
fn fits(dirty: u64, pages: u64) -> bool {
    dirty + pages <= threshold()
}

/// The pages the queued writers wait to dirty.
pub fn pending_pages() -> u64 {
    let d = DIRTY.lock();
    let mut at = d.deferred.head;
    let mut total = 0;
    // SAFETY: entries are the queue's under the lock.
    while let Some(e) = unsafe { at.as_ref() } {
        total += e.pages;
        at = e.next;
    }
    total
}

/// `CcPostDeferredWrites`: let the queued writers go, in order, while
/// their pages fit.
pub fn post_deferred() {
    loop {
        let e = {
            let mut d = DIRTY.lock();
            let head = d.deferred.head;
            // SAFETY: as above.
            match unsafe { head.as_ref() } {
                Some(e) if fits(d.pages, e.pages) => {
                    d.deferred.head = e.next;
                    head
                }
                _ => return,
            }
        };
        // SAFETY: off the queue: the waiter's or ours.
        unsafe {
            match (*e).then {
                Then::Signal(event) => {
                    wait::KeSetEvent(event, 0, 0);
                }
                Then::Post {
                    routine,
                    context1,
                    context2,
                } => {
                    let pooled = (*e).pooled;
                    if pooled {
                        let _ = pool::free(e.cast());
                    }
                    seh::call(routine, [context1, context2, 0, 0], &Guard::Nothing);
                }
            }
        }
    }
}

/// [`CcCanIWrite`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-ccaniwrite):
/// whether a write of `bytes` may go ahead now; with `wait`, it waits
/// until it may, queued first when `retrying`.
///
/// # Safety
/// `file` is a live file object. With `wait`, at `PASSIVE_LEVEL`.
pub unsafe extern "C" fn CcCanIWrite(
    _file: *mut FILE_OBJECT,
    bytes: u32,
    wait_for_it: u8,
    retrying: u8,
) -> u8 {
    let want = pages(bytes);
    {
        let d = DIRTY.lock();
        if d.deferred.head.is_null() && fits(d.pages, want) {
            return 1;
        }
    }
    if wait_for_it == 0 {
        return 0;
    }
    let mut event = MaybeUninit::<KEVENT>::uninit();
    // SAFETY: an event on this stack, signalled before it ends.
    unsafe { wait::KeInitializeEvent(event.as_mut_ptr(), 0, 0) };
    let mut entry = Deferred {
        next: core::ptr::null_mut(),
        pages: want,
        then: Then::Signal(event.as_mut_ptr()),
        pooled: false,
    };
    DIRTY.lock().deferred.insert(&raw mut entry, retrying != 0);
    schedule_scan();
    post_deferred();
    // SAFETY: as above; the entry leaves the queue before the event is
    // signalled.
    unsafe { wait::wait(Some(event.as_mut_ptr().cast()), None) };
    1
}

/// [`CcDeferWrite`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-ccdeferwrite):
/// have `post(context1, context2)` called once a write of `bytes` may go
/// ahead: at once if it may now, or if the queue's entry cannot be had.
///
/// # Safety
/// `post` is the file system's routine, callable at `PASSIVE_LEVEL` with
/// the contexts.
pub unsafe extern "C" fn CcDeferWrite(
    _file: *mut FILE_OBJECT,
    post: usize,
    context1: *mut c_void,
    context2: *mut c_void,
    bytes: u32,
    retrying: u8,
) {
    let then = Then::Post {
        routine: post,
        context1: context1.addr(),
        context2: context2.addr(),
    };
    let e = super::alloc_in_pool(
        Deferred {
            next: core::ptr::null_mut(),
            pages: pages(bytes),
            then,
            pooled: true,
        },
        TAG_DEFERRED,
    );
    if e.is_null() {
        // SAFETY: per the contract.
        unsafe {
            seh::call(
                post,
                [context1.addr(), context2.addr(), 0, 0],
                &Guard::Nothing,
            )
        };
        return;
    }
    DIRTY.lock().deferred.insert(e, retrying != 0);
    post_deferred();
    schedule_scan();
}
