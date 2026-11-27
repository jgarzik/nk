//! The lazy writer and the cache manager's worker threads.
//!
//! The first dirt arms the scan timer for 3 s (`CcFirstDelay`); while
//! dirt remains it is armed again every second (`CcIdleDelay`). Its DPC
//! has a worker run a scan (`CcLazyWriteScan`): how many pages to write
//! (`nk_cc::pages`), and a write-behind queued for each map with dirty
//! data that is not already queued, and for each that no file object
//! has open any more. A write-behind (`CcWriteBehind`) takes the file
//! through the file system's `AcquireForLazyWrite`, flushes its share
//! of the pages, gives the file back, and then deletes a map nobody has
//! open and nothing dirties (lazy close), with the file taken exclusive
//! through FsRtl; dropping the map's file object may send its file
//! system the close. Deferred writes are posted after every write-behind.
//!
//! The workers (2, and one more per 4 processors: NK's number; Windows
//! uses its critical worker threads) share one queue under [`DIRTY`].
//! Read-ahead runs on them too, between the file system's
//! `AcquireForReadAhead` and `ReleaseFromReadAhead`, and never raises.
//! `CcWaitForCurrentLazyWriterActivity` queues an item behind the work
//! of a scan run at once, which waits for every item before it to end.

use super::flush::flush_scm;
use super::{DIRTY, MASTER, Scm, flag, map, short_delay, trace};
use crate::ke::seh::{self, Guard, Unhandled};
use crate::ke::{thread, wait};
use crate::mm::pool;
use core::cell::UnsafeCell;
use core::ffi::c_void;
use core::mem::MaybeUninit;
use core::sync::atomic::{AtomicU64, Ordering};
use nk_cc::pages::{self, Scan};
use nk_ntabi::io::FILE_OBJECT;
use nk_ntabi::ke::{KDPC, KEVENT, KSEMAPHORE, KTIMER};
use nk_ntabi::status::*;

/// `CcFirstDelay` and `CcIdleDelay`, in 100 ns units, relative.
const FIRST_DELAY: i64 = -30_000_000;
const IDLE_DELAY: i64 = -10_000_000;
/// The most maps one scan queues.
const SCAN_ROOM: usize = 64;
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
    /// Wait for every item before it to end, then signal the event.
    Barrier(*mut KEVENT),
}

/// An item of the queue, from the pool.
pub struct Entry {
    next: *mut Entry,
    work: Work,
}

/// The queue and the scan's state, under [`DIRTY`].
pub struct Queue {
    head: *mut Entry,
    tail: *mut Entry,
    /// Items to queue at the end of the next scan.
    post_tick: *mut Entry,
    /// The timer is armed or a scan is under way.
    scan_active: bool,
    /// A scan is to run.
    scan_pending: bool,
    /// The next scan writes every dirty page.
    everything: bool,
    /// Items being run.
    running: u32,
}

impl Queue {
    pub const fn new() -> Self {
        Self {
            head: core::ptr::null_mut(),
            tail: core::ptr::null_mut(),
            post_tick: core::ptr::null_mut(),
            scan_active: false,
            scan_pending: false,
            everything: false,
            running: 0,
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
}

// SAFETY: the entries are reached only under the lock.
unsafe impl Send for Queue {}

/// The scan's timer, its DPC and the workers' semaphore.
struct Statics {
    timer: UnsafeCell<MaybeUninit<KTIMER>>,
    dpc: UnsafeCell<MaybeUninit<KDPC>>,
    work: UnsafeCell<MaybeUninit<KSEMAPHORE>>,
}

// SAFETY: dispatcher objects, used through the kernel's routines.
unsafe impl Sync for Statics {}

static STATICS: Statics = Statics {
    timer: UnsafeCell::new(MaybeUninit::uninit()),
    dpc: UnsafeCell::new(MaybeUninit::uninit()),
    work: UnsafeCell::new(MaybeUninit::uninit()),
};

fn semaphore() -> *mut KSEMAPHORE {
    STATICS.work.get().cast()
}

/// Start the lazy writer: thresholds, timer, workers.
pub fn init() -> Result<(), &'static str> {
    let (threshold, target) = pages::thresholds(crate::mm::physical_memory().0);
    THRESHOLD.store(threshold, Ordering::Relaxed);
    TARGET.store(target, Ordering::Relaxed);
    // SAFETY: static storage nothing uses yet.
    unsafe {
        crate::ke::timer::KeInitializeTimer(STATICS.timer.get().cast());
        crate::ke::dpc::KeInitializeDpc(
            STATICS.dpc.get().cast(),
            Some(scan_dpc),
            core::ptr::null_mut(),
        );
        wait::KeInitializeSemaphore(semaphore(), 0, i32::MAX);
    }
    let workers = 2 + crate::ke::smp::online_count() / 4;
    for _ in 0..workers {
        thread::create(worker, 0, 13, thread::ANYWHERE)?;
    }
    Ok(())
}

/// Wake a worker for one more item.
fn wake() {
    // SAFETY: the workers' semaphore, initialised at start.
    unsafe { wait::KeReleaseSemaphore(semaphore(), 0, 1, 0) };
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
    let first = {
        let mut d = DIRTY.lock();
        !core::mem::replace(&mut d.queue.scan_pending, true)
    };
    if first {
        wake();
    }
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

/// A worker: scans and items, for ever.
fn worker(_: usize) {
    loop {
        // SAFETY: the workers' semaphore.
        unsafe { wait::wait(Some(semaphore().cast()), None) };
        let (scan, entry) = {
            let mut d = DIRTY.lock();
            let q = &mut d.queue;
            q.running += 1;
            if core::mem::replace(&mut q.scan_pending, false) {
                (true, core::ptr::null_mut())
            } else {
                (false, q.pop())
            }
        };
        if scan {
            lazy_write_scan();
        } else if !entry.is_null() {
            // SAFETY: an entry taken off the queue, now this worker's.
            let work = unsafe { core::ptr::read(&raw const (*entry).work) };
            // The entry's work was moved out: only its block is left.
            if let Err(e) = pool::free(entry.cast()) {
                crate::kd::bugcheck(format_args!("cc: freeing a work item: {e:?}"));
            }
            run(work);
        }
        DIRTY.lock().queue.running -= 1;
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
        Work::Barrier(event) => {
            while DIRTY.lock().queue.running > 1 {
                short_delay();
            }
            // SAFETY: the waiter's event, valid until signalled.
            unsafe { wait::KeSetEvent(event, 0, 0) };
        }
    }
}

/// Whether a map is for the lazy writer: dirty (and writing behind),
/// or open by nobody and to be deleted.
fn wanted(scm: &Scm, dirty: u64) -> bool {
    let f = scm.flags.get();
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
            scm.flags.set(scm.flags.get() | flag::WRITE_QUEUED);
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
    let mut e = core::mem::replace(&mut q.post_tick, core::ptr::null_mut());
    let mut moved = 0;
    while !e.is_null() {
        // SAFETY: entries of the post-tick list are the queue's.
        let next = unsafe { (*e).next };
        q.push(e);
        moved += 1;
        e = next;
    }
    if more || !chosen.is_empty() {
        arm(q, IDLE_DELAY);
    } else {
        q.scan_active = false;
    }
    drop(d);
    for _ in 0..moved {
        wake();
    }
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
    scm.flags.set(scm.flags.get() & !flag::WRITE_QUEUED);
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
    unqueue(scm);
    super::throttle::post_deferred();
    lazy_close(scm);
}

/// Delete a map nobody has open and nothing dirties, with its file taken
/// exclusive.
fn lazy_close(scm: &Scm) {
    let closing = |scm: &Scm| {
        let _d = DIRTY.lock();
        scm.open_count.get() == 0
            && scm.refs.get() == 0
            && scm.dirty_pages.get() == 0
            && scm.flags.get() & (flag::WRITE_QUEUED | flag::BEING_DELETED) == 0
    };
    let file = {
        let _m = MASTER.lock();
        if !closing(scm) {
            return;
        }
        // The map holds the file; one more reference keeps it past the
        // deletion until it is given back.
        scm.refs.set(scm.refs.get() + 1);
        scm.file_object.get()
    };
    // SAFETY: the map's file object, live while it does.
    unsafe { crate::ob::object::reference(file.cast()) };
    crate::fsrtl::acquire::acquire_file_exclusive(file);
    let delete = {
        let mut m = MASTER.lock();
        scm.refs.set(scm.refs.get() - 1);
        let now = closing(scm);
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
    if scm.flags.get() & flag::DISABLE_READ_AHEAD != 0 {
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
    let e = super::alloc_in_pool(
        Entry {
            next: core::ptr::null_mut(),
            work: Work::Barrier(event.as_mut_ptr()),
        },
        TAG_WORK,
    );
    if e.is_null() {
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    let first = {
        let mut d = DIRTY.lock();
        let q = &mut d.queue;
        // SAFETY: the fresh entry, the list's from now on.
        unsafe { (*e).next = q.post_tick };
        q.post_tick = e;
        q.everything = true;
        q.scan_active = true;
        !core::mem::replace(&mut q.scan_pending, true)
    };
    if first {
        wake();
    }
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
