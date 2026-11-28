//! The lazy writer and the cache manager's background work.
//!
//! The first dirt arms the scan timer for 3 s (`CcFirstDelay`); while
//! dirt remains it is armed again every second (`CcIdleDelay`). Its DPC
//! wakes a worker to run a scan (`CcLazyWriteScan`): how many pages to
//! write (`nk_cc::pages`), and a write-behind queued for each map with
//! dirty data that is not already queued, and for each that no file
//! object has open any more. A write-behind (`CcWriteBehind`) takes the
//! file through the file system's `AcquireForLazyWrite`, flushes its
//! share of the pages, gives the file back, and then deletes a map
//! nobody has open and nothing dirties (lazy close), with the file
//! taken exclusive through FsRtl; dropping the map's file object may
//! send its file system the close. Deferred writes are posted after
//! every write-behind.
//!
//! Scans, write-behinds and read-aheads run on the executive's
//! `CriticalWorkQueue` (`ex::work`), as on Windows, bounded by a small
//! pool of reusable work items (`2 + cpus / 4`, at most `MAX_WORKERS`)
//! draining the cache manager's queue under [`DIRTY`].
//! `CcWaitForCurrentLazyWriterActivity` attaches a barrier behind a
//! scan run at once; every waiting barrier is signalled when no scan or
//! item remains queued or running, so concurrent waiters never wait for
//! each other.

use super::flush::flush_scm;
use super::{DIRTY, MASTER, Scm, flag, map, trace};
use crate::ke::seh::{self, Guard, Unhandled};
use crate::ke::wait;
use crate::mm::pool;
use core::cell::UnsafeCell;
use core::ffi::c_void;
use core::mem::MaybeUninit;
use core::sync::atomic::{AtomicU64, Ordering};
use nk_cc::pages::{self, Scan};
use nk_ntabi::ex::{CRITICAL_WORK_QUEUE, WORK_QUEUE_ITEM};
use nk_ntabi::io::FILE_OBJECT;
use nk_ntabi::ke::{KDPC, KEVENT, KTIMER, LIST_ENTRY};
use nk_ntabi::status::*;

/// `CcFirstDelay` and `CcIdleDelay`, in 100 ns units, relative.
const FIRST_DELAY: i64 = -30_000_000;
const IDLE_DELAY: i64 = -10_000_000;
/// The most maps one scan queues.
const SCAN_ROOM: usize = 64;
/// Upper bound on concurrent executive work items draining the cache
/// manager's queue.
const MAX_WORKERS: usize = 8;
const TAG_WORK: u32 = u32::from_le_bytes(*b"CcWk");

/// The dirty-page threshold and target (`nk_cc::pages::thresholds`).
static THRESHOLD: AtomicU64 = AtomicU64::new(0);
static TARGET: AtomicU64 = AtomicU64::new(0);

pub fn threshold() -> u64 {
    THRESHOLD.load(Ordering::Relaxed)
}

/// What a worker does with an item.
pub enum Work {
    WriteBehind(*const Scm),
    ReadAhead {
        scm: *const Scm,
        file: *mut FILE_OBJECT,
        offset: u64,
        length: u32,
    },
}

/// An item of the queue, from the pool.
pub struct Entry {
    next: *mut Entry,
    work: Work,
}

/// A waiter in [`CcWaitForCurrentLazyWriterActivity`], living on the
/// caller's stack until its event is signalled.
struct Barrier {
    next: *mut Barrier,
    event: *mut KEVENT,
}

/// The queue and the scan's state, under [`DIRTY`].
pub struct Queue {
    head: *mut Entry,
    tail: *mut Entry,
    /// Waiters waiting for the next scan to finish before joining
    /// `barriers`.
    post_tick: *mut Barrier,
    /// Waiters waiting for all queued and running work to finish.
    barriers: *mut Barrier,
    /// The timer is armed or a scan is under way.
    scan_active: bool,
    /// A scan is to run.
    scan_pending: bool,
    /// The next scan writes every dirty page.
    everything: bool,
    /// Scans and work items currently executing.
    running: u32,
    /// Bitmask of `STATICS.items` currently queued or running on
    /// `ex::work`.
    active_mask: u8,
    /// How many `STATICS.items` slots may be active at once.
    limit: usize,
}

impl Queue {
    pub const fn new() -> Self {
        Self {
            head: core::ptr::null_mut(),
            tail: core::ptr::null_mut(),
            post_tick: core::ptr::null_mut(),
            barriers: core::ptr::null_mut(),
            scan_active: false,
            scan_pending: false,
            everything: false,
            running: 0,
            active_mask: 0,
            limit: 2,
        }
    }

    fn push(&mut self, e: *mut Entry) {
        // SAFETY: an entry being queued is the queue's.
        unsafe { (*e).next = core::ptr::null_mut() };
        // SAFETY: as above.
        match unsafe { self.tail.as_mut() } {
            Some(t) => t.next = e,
            None => self.head = e,
        }
        self.tail = e;
    }

    fn pop(&mut self) -> *mut Entry {
        let e = self.head;
        // SAFETY: a queued entry.
        if let Some(entry) = unsafe { e.as_ref() } {
            self.head = entry.next;
            if self.head.is_null() {
                self.tail = core::ptr::null_mut();
            }
        }
        e
    }

    fn claim_slot(&mut self) -> Option<usize> {
        for slot in 0..self.limit {
            let bit = 1u8 << slot;
            if self.active_mask & bit == 0 {
                self.active_mask |= bit;
                return Some(slot);
            }
        }
        None
    }
}

// SAFETY: the entries and barriers are reached only under the lock.
unsafe impl Send for Queue {}

/// The scan's timer, its DPC and the reusable executive work items.
struct Statics {
    timer: UnsafeCell<MaybeUninit<KTIMER>>,
    dpc: UnsafeCell<MaybeUninit<KDPC>>,
    items: [UnsafeCell<WORK_QUEUE_ITEM>; MAX_WORKERS],
}

// SAFETY: the timer and DPC are dispatcher objects used through kernel
// routines; each work item is owned exclusively by the slot bit in
// `Queue::active_mask`.
unsafe impl Sync for Statics {}

const EMPTY_WORK_ITEM: WORK_QUEUE_ITEM = WORK_QUEUE_ITEM {
    List: LIST_ENTRY {
        Flink: core::ptr::null_mut(),
        Blink: core::ptr::null_mut(),
    },
    WorkerRoutine: None,
    Parameter: core::ptr::null_mut(),
};

static STATICS: Statics = Statics {
    timer: UnsafeCell::new(MaybeUninit::uninit()),
    dpc: UnsafeCell::new(MaybeUninit::uninit()),
    items: [const { UnsafeCell::new(EMPTY_WORK_ITEM) }; MAX_WORKERS],
};

/// Start the lazy writer: thresholds, timer and executive work-item
/// slots. Runs on `ex::work`'s critical work queue, so no threads of
/// its own are created.
pub fn init() -> Result<(), &'static str> {
    let (threshold, target) = pages::thresholds(crate::mm::physical_memory().0);
    THRESHOLD.store(threshold, Ordering::Relaxed);
    TARGET.store(target, Ordering::Relaxed);
    let limit = (2 + crate::ke::smp::online_count() / 4).min(MAX_WORKERS);
    DIRTY.lock().queue.limit = limit;
    // SAFETY: static storage nothing uses yet.
    unsafe {
        crate::ke::timer::KeInitializeTimer(STATICS.timer.get().cast());
        crate::ke::dpc::KeInitializeDpc(
            STATICS.dpc.get().cast(),
            Some(scan_dpc),
            core::ptr::null_mut(),
        );
        for (slot, cell) in STATICS.items.iter().enumerate() {
            let item = cell.get();
            (&raw mut (*item).List.Flink).write(core::ptr::null_mut());
            (&raw mut (*item).WorkerRoutine).write(Some(worker_item));
            (&raw mut (*item).Parameter).write(slot as *mut c_void);
        }
    }
    Ok(())
}

/// Queue an executive critical work item if work is waiting and a slot
/// is free.
fn wake() {
    let slot = {
        let mut d = DIRTY.lock();
        let q = &mut d.queue;
        if !q.scan_pending && q.head.is_null() {
            return;
        }
        q.claim_slot()
    };
    if let Some(slot) = slot {
        // SAFETY: `slot` is exclusively owned by this claim until
        // `worker_item` clears its bit in `active_mask`.
        unsafe { crate::ex::work::ExQueueWorkItem(STATICS.items[slot].get(), CRITICAL_WORK_QUEUE) };
    }
}

/// Signal every barrier on `list`.
fn signal_barriers(mut node: *mut Barrier) {
    while !node.is_null() {
        // SAFETY: each node stays live on its waiter's stack until its
        // event is signalled; read `next` before signalling.
        unsafe {
            let next = (*node).next;
            let event = (*node).event;
            wait::KeSetEvent(event, 0, 0);
            node = next;
        }
    }
}

/// Arm the timer, under the lock, if no scan is active.
fn arm(q: &mut Queue, delay: i64) {
    q.scan_active = true;
    // SAFETY: the static timer and DPC, initialised at start.
    unsafe {
        crate::ke::timer::KeSetTimer(STATICS.timer.get().cast(), delay, STATICS.dpc.get().cast())
    };
}

/// `CcScheduleLazyWriteScan`: a scan in 3 s, unless one is active.
pub fn schedule_scan() {
    let mut d = DIRTY.lock();
    if !d.queue.scan_active {
        arm(&mut d.queue, FIRST_DELAY);
    }
}

/// The scan timer's DPC: have a worker scan.
///
/// # Safety
/// Called as a DPC routine.
unsafe extern "C" fn scan_dpc(_: *mut KDPC, _: *mut c_void, _: *mut c_void, _: *mut c_void) {
    {
        let mut d = DIRTY.lock();
        d.queue.scan_pending = true;
    }
    wake();
}

/// Queue `work`; `Err` if the pool has no room for it.
pub fn post(work: Work) -> Result<(), ()> {
    let e = super::alloc_in_pool(
        Entry {
            next: core::ptr::null_mut(),
            work,
        },
        TAG_WORK,
    );
    if e.is_null() {
        return Err(());
    }
    DIRTY.lock().queue.push(e);
    wake();
    Ok(())
}

/// Executive critical worker callback: drain scans and items from the
/// cache manager's queue, then release its slot back to `ex::work`.
///
/// # Safety
/// Called as a work-queue routine with the slot index as `parameter`.
unsafe extern "C" fn worker_item(parameter: *mut c_void) {
    let slot = parameter.addr();
    loop {
        let (scan, entry, done) = {
            let mut d = DIRTY.lock();
            let q = &mut d.queue;
            if core::mem::replace(&mut q.scan_pending, false) {
                q.running += 1;
                (true, core::ptr::null_mut(), core::ptr::null_mut())
            } else {
                let e = q.pop();
                if !e.is_null() {
                    q.running += 1;
                    (false, e, core::ptr::null_mut())
                } else {
                    let done = if q.running == 0 {
                        core::mem::replace(&mut q.barriers, core::ptr::null_mut())
                    } else {
                        core::ptr::null_mut()
                    };
                    q.active_mask &= !(1u8 << slot);
                    (false, core::ptr::null_mut(), done)
                }
            }
        };
        if !scan && entry.is_null() {
            signal_barriers(done);
            return;
        }
        if scan {
            lazy_write_scan();
        } else {
            // SAFETY: an entry taken off the queue, now this worker's.
            let work = unsafe { core::ptr::read(&raw const (*entry).work) };
            // The entry's work was moved out: only its block is left.
            if let Err(e) = pool::free(entry.cast()) {
                crate::kd::bugcheck(format_args!("cc: freeing a work item: {e:?}"));
            }
            run(work);
        }
        let done = {
            let mut d = DIRTY.lock();
            let q = &mut d.queue;
            q.running -= 1;
            if q.running == 0 && !q.scan_pending && q.head.is_null() {
                core::mem::replace(&mut q.barriers, core::ptr::null_mut())
            } else {
                core::ptr::null_mut()
            }
        };
        signal_barriers(done);
    }
}

fn run(work: Work) {
    match work {
        Work::WriteBehind(scm) => {
            // SAFETY: queued with a reference on the map.
            write_behind(unsafe { &*scm });
        }
        Work::ReadAhead {
            scm,
            file,
            offset,
            length,
        } => {
            // SAFETY: queued with references on the map and the file.
            let scm = unsafe { &*scm };
            read_ahead(scm, offset, length);
            super::dereference(scm);
            // SAFETY: the reference the queuing took.
            unsafe { crate::ob::object::dereference(file.cast()) };
        }
    }
}

/// Whether a map is for the lazy writer: dirty (and writing behind),
/// or open by nobody and to be deleted.
fn wanted(scm: &Scm, dirty: u64) -> bool {
    let f = scm.flags();
    if f & (flag::WRITE_QUEUED | flag::BEING_CREATED | flag::BEING_DELETED) != 0 {
        return false;
    }
    let closing = scm.open_count.get() == 0;
    (dirty != 0 && (f & flag::DISABLE_WRITE_BEHIND == 0 || closing)) || closing
}

/// `CcLazyWriteScan`.
fn lazy_write_scan() {
    let (total, everything) = {
        let mut d = DIRTY.lock();
        (d.pages, core::mem::replace(&mut d.queue.everything, false))
    };
    let available = crate::mm::flush::available_pages() as u64;
    let mut budget = pages::pages_to_write(&Scan {
        dirty: total,
        pending: super::throttle::pending_pages(),
        threshold: threshold(),
        target: TARGET.load(Ordering::Relaxed),
        low_memory: available < pages::LOW_AVAILABLE_PAGES,
        everything,
    });
    let mut chosen: alloc::vec::Vec<(*const Scm, u64)> = alloc::vec::Vec::with_capacity(SCAN_ROOM);
    let mut more = false;
    {
        let m = MASTER.lock();
        map::each(&m, |scm| {
            let dirty = {
                let _d = DIRTY.lock();
                scm.dirty_pages.get()
            };
            if !wanted(scm, dirty) {
                more |= dirty != 0;
                return;
            }
            if chosen.len() == SCAN_ROOM {
                more = true;
                return;
            }
            let share = dirty.min(budget);
            budget -= share;
            scm.set_flags(scm.flags() | flag::WRITE_QUEUED);
            scm.refs.set(scm.refs.get() + 1);
            chosen.push((scm, share));
            more |= dirty > share;
        });
    }
    for &(scm, share) in &chosen {
        // SAFETY: referenced above.
        set_share(unsafe { &*scm }, share);
        if post(Work::WriteBehind(scm)).is_err() {
            // SAFETY: as above.
            unqueue(unsafe { &*scm });
            more = true;
        }
    }
    trace(format_args!(
        "scan: {total} dirty, {} maps queued",
        chosen.len()
    ));
    super::throttle::post_deferred();
    let mut d = DIRTY.lock();
    let q = &mut d.queue;
    let mut b = core::mem::replace(&mut q.post_tick, core::ptr::null_mut());
    while !b.is_null() {
        // SAFETY: barriers of the post-tick list live on their waiters'
        // stacks until signalled.
        let next = unsafe { (*b).next };
        // SAFETY: as above.
        unsafe { (*b).next = q.barriers };
        q.barriers = b;
        b = next;
    }
    if more || !chosen.is_empty() {
        arm(q, IDLE_DELAY);
    } else {
        q.scan_active = false;
    }
    drop(d);
}

/// The pages a queued write-behind may write, kept in its map until it
/// runs (Windows' `PagesToWrite`).
fn set_share(scm: &Scm, share: u64) {
    let _m = MASTER.lock();
    scm.pages_to_write.set(share);
}

/// Take back a write-behind that could not be queued.
fn unqueue(scm: &Scm) {
    let _m = MASTER.lock();
    scm.set_flags(scm.flags() & !flag::WRITE_QUEUED);
    scm.refs.set(scm.refs.get() - 1);
}

/// Call an acquire callback of the file system's.
fn acquire(routine: Option<nk_ntabi::cc::ACQUIRE_FOR_CC>, context: *mut c_void) -> bool {
    match routine {
        // SAFETY: the file system's routine, called on a worker as
        // Windows calls it, waiting.
        Some(r) => unsafe {
            seh::call(
                r as usize,
                [context.addr(), 1, 0, 0],
                &Guard::Base(Unhandled::SystemThread),
            ) as u8
                != 0
        },
        None => true,
    }
}

/// Call a release callback of the file system's.
fn release(routine: Option<nk_ntabi::cc::RELEASE_FROM_CC>, context: *mut c_void) {
    if let Some(r) = routine {
        // SAFETY: as in `acquire`.
        unsafe {
            seh::call(
                r as usize,
                [context.addr(), 0, 0, 0],
                &Guard::Base(Unhandled::SystemThread),
            )
        };
    }
}

/// `CcWriteBehind`.
fn write_behind(scm: &Scm) {
    // SAFETY: the file system's callbacks, kept while the map lives.
    let callbacks = unsafe { scm.callbacks.as_ref() };
    let dirty = {
        let _d = DIRTY.lock();
        scm.dirty_pages.get()
    };
    if dirty != 0 {
        let context = scm.lazy_write_context;
        if !acquire(callbacks.and_then(|c| c.AcquireForLazyWrite), context) {
            // Not now: the next scan tries again.
            unqueue(scm);
            return;
        }
        let share = scm.pages_to_write.get();
        let result = flush_scm(scm, None, Some(share.max(1)));
        release(callbacks.and_then(|c| c.ReleaseFromLazyWrite), context);
        trace(format_args!(
            "write-behind {:p}: {:#x}, {:#x} bytes",
            core::ptr::from_ref(scm),
            result.Status,
            result.Information
        ));
    }
    super::throttle::post_deferred();
    lazy_close(scm);
}

/// After a write-behind, which holds the queued reference on `scm` and
/// gives it up here: delete the map if nobody has it open, nothing
/// dirties it and no other work holds it, with its file taken
/// exclusive.
fn lazy_close(scm: &Scm) {
    // With the write-behind's own reference the only one.
    let closing = |scm: &Scm| {
        let _d = DIRTY.lock();
        scm.open_count.get() == 0
            && scm.refs.get() == 1
            && scm.dirty_pages.get() == 0
            && scm.flags() & flag::BEING_DELETED == 0
    };
    let file = {
        let _m = MASTER.lock();
        scm.set_flags(scm.flags() & !flag::WRITE_QUEUED);
        if !closing(scm) {
            scm.refs.set(scm.refs.get() - 1);
            return;
        }
        scm.file_object.get()
    };
    // The map holds its file; one more reference keeps it past the
    // deletion until the file is given back.
    // SAFETY: the map's file object, live while the map is.
    unsafe { crate::ob::object::reference(file.cast()) };
    crate::fsrtl::acquire::acquire_file_exclusive(file);
    let delete = {
        let mut m = MASTER.lock();
        let now = closing(scm);
        scm.refs.set(scm.refs.get() - 1);
        if now {
            map::begin_delete(&mut m, scm);
        }
        now
    };
    if delete {
        trace(format_args!("lazy close {:p}", core::ptr::from_ref(scm)));
        map::delete(scm);
    }
    crate::fsrtl::acquire::release_file(file);
    // SAFETY: the reference taken above.
    unsafe { crate::ob::object::dereference(file.cast()) };
}

/// Read ahead `length` bytes of `scm` at `offset`, between the file
/// system's callbacks. Failures are dropped.
fn read_ahead(scm: &Scm, offset: u64, length: u32) {
    // SAFETY: as in `write_behind`.
    let callbacks = unsafe { scm.callbacks.as_ref() };
    let context = scm.lazy_write_context;
    if !acquire(callbacks.and_then(|c| c.AcquireForReadAhead), context) {
        return;
    }
    let end = (offset + u64::from(length)).min(scm.file_size.get() as u64);
    if offset < end
        && let Ok(p) =
            crate::mm::cache::prefetch_for_cc(scm.section(), offset, (end - offset) as u32, 0)
    {
        let status = crate::mm::cache::wait_prefetch(p);
        trace(format_args!(
            "read-ahead {:p} {offset:#x}+{:#x}: {status:#x}",
            core::ptr::from_ref(scm),
            end - offset
        ));
    }
    release(callbacks.and_then(|c| c.ReleaseFromReadAhead), context);
}

/// Queue a read-ahead after a read of `length` bytes at `offset` through
/// `file`, if the read's pattern calls for one (`CcScheduleReadAhead`).
pub fn schedule_read_ahead(
    file: *mut FILE_OBJECT,
    scm: &Scm,
    before: nk_cc::readahead::History,
    offset: u64,
    length: u32,
    mask: u32,
) {
    use nk_cc::readahead::{pattern, plan};
    if scm.flags() & flag::DISABLE_READ_AHEAD != 0 {
        return;
    }
    // SAFETY: a live file object of the caller's.
    let fo_flags = unsafe { (*file).Flags };
    let p = pattern(&before, offset, fo_flags);
    let Some((at, len)) = plan(&before, p, offset, u64::from(length), u64::from(mask)) else {
        return;
    };
    if at >= scm.file_size.get() as u64 {
        return;
    }
    super::reference(scm);
    // SAFETY: as above.
    unsafe { crate::ob::object::reference(file.cast()) };
    let queued = post(Work::ReadAhead {
        scm,
        file,
        offset: at,
        length: len.min(u64::from(u32::MAX)) as u32,
    });
    if queued.is_err() {
        super::dereference(scm);
        // SAFETY: the reference just taken.
        unsafe { crate::ob::object::dereference(file.cast()) };
    }
}

/// [`CcWaitForCurrentLazyWriterActivity`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-ccwaitforcurrentlazywriteractivity):
/// run a scan now and wait until its work and everything queued before
/// is done. NK's scan here writes every dirty page.
pub extern "C" fn CcWaitForCurrentLazyWriterActivity() -> NTSTATUS {
    crate::ke::irql::expect_passive("CcWaitForCurrentLazyWriterActivity");
    let mut event = MaybeUninit::<KEVENT>::uninit();
    // SAFETY: an event on this stack, signalled before it ends.
    unsafe { wait::KeInitializeEvent(event.as_mut_ptr(), 0, 0) };
    let mut barrier = Barrier {
        next: core::ptr::null_mut(),
        event: event.as_mut_ptr(),
    };
    let b = &raw mut barrier;
    {
        let mut d = DIRTY.lock();
        let q = &mut d.queue;
        // SAFETY: the fresh barrier, the list's until signalled.
        unsafe { (*b).next = q.post_tick };
        q.post_tick = b;
        q.everything = true;
        q.scan_active = true;
        q.scan_pending = true;
    }
    wake();
    // SAFETY: as above.
    unsafe { wait::wait(Some(event.as_mut_ptr().cast()), None) };
    STATUS_SUCCESS
}

/// What the I/O manager's shutdown calls once every file system has had
/// its shutdown request, as Windows' calls
/// `CcWaitForCurrentLazyWriterActivity` there.
pub fn shutdown_flush() {
    CcWaitForCurrentLazyWriterActivity();
}
