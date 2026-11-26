//! Work items: routines a driver hands to a system thread to run at
//! `PASSIVE_LEVEL`, where it may block.
//!
//! There are three queues (critical, delayed, hypercritical), each
//! served by a few worker threads at that queue's priority. Windows 10
//! names four more kinds of queue; NK serves each from the nearest of
//! its three ([`queue_of`]). A work item is the driver's memory; it is linked into a
//! queue through its list entry, whose forward link is null exactly
//! while the item is on no queue, as Windows keeps it. A worker takes an
//! item off before running it, so a routine may queue its own item
//! again, or free it.
//!
//! An I/O work item is one the kernel allocates, tied to a device: the
//! device is referenced from queueing until the routine has returned, so
//! the driver cannot be unloaded under its own routine.

#![allow(non_snake_case)]

use crate::io::device;
use crate::ke::seh::{self, Guard, Unhandled};
use crate::ke::{Rank, SpinLock, irql, mutex, thread, wait};
use crate::mm::pool;
use core::cell::UnsafeCell;
use core::ffi::c_void;
use core::mem::MaybeUninit;
use nk_ntabi::ex::{IO_WORKITEM, WORK_QUEUE_ITEM, WORK_QUEUES, work_queue};
use nk_ntabi::io::DEVICE_OBJECT;
use nk_ntabi::ke::{KSEMAPHORE, LIST_ENTRY};

/// The queues NK keeps.
const QUEUES: usize = WORK_QUEUES;

/// The queue that serves a `WORK_QUEUE_TYPE` (`nk_ntabi::ex::work_queue`).
/// `None` for a value Windows does not define.
fn queue_of(queue_type: u32) -> Option<&'static Queue> {
    work_queue(queue_type).map(|index| &QUEUE[index])
}
/// Each queue's worker threads: how many, and at what priority. Indexed
/// by `WORK_QUEUE_TYPE`: critical, delayed, hypercritical.
const WORKERS: [(usize, u8); QUEUES] = [(2, 13), (2, 12), (1, 15)];

/// Pool tag of I/O work items.
const TAG: u32 = u32::from_le_bytes(*b"IoWI");

struct Queue {
    /// The items waiting, oldest first: a circular list through the
    /// items' list entries, with this head.
    items: SpinLock<UnsafeCell<LIST_ENTRY>>,
    /// Counts the items waiting; the workers wait on it.
    waiting: UnsafeCell<MaybeUninit<KSEMAPHORE>>,
}

// SAFETY: the list is only touched under its lock; the semaphore only
// through the kernel routines, which lock for themselves.
unsafe impl Sync for Queue {}

static QUEUE: [Queue; QUEUES] = [const {
    Queue {
        items: SpinLock::new(
            Rank::WorkQueue,
            UnsafeCell::new(LIST_ENTRY {
                Flink: core::ptr::null_mut(),
                Blink: core::ptr::null_mut(),
            }),
        ),
        waiting: UnsafeCell::new(MaybeUninit::uninit()),
    }
}; QUEUES];

impl Queue {
    fn semaphore(&self) -> *mut KSEMAPHORE {
        self.waiting.get().cast()
    }
}

/// Start the worker threads. Once, after every processor is running.
pub fn init() -> Result<(), &'static str> {
    for (index, queue) in QUEUE.iter().enumerate() {
        {
            let items = queue.items.lock();
            let head = items.get();
            // SAFETY: the head is this queue's own, under its lock. An
            // empty list points at itself.
            unsafe {
                head.write(LIST_ENTRY {
                    Flink: head,
                    Blink: head,
                });
            }
        }
        // SAFETY: static storage for a semaphore nothing waits on yet.
        unsafe { wait::KeInitializeSemaphore(queue.semaphore(), 0, i32::MAX) };
        let (workers, priority) = WORKERS[index];
        for _ in 0..workers {
            thread::create(worker, index, priority, thread::ANYWHERE)?;
        }
    }
    Ok(())
}

/// A worker thread: run the items of queue `index`, for ever.
fn worker(index: usize) {
    let queue = &QUEUE[index];
    loop {
        // SAFETY: the queue's semaphore, initialised before any worker
        // was created.
        unsafe { wait::wait(Some(queue.semaphore().cast()), None) };
        let (routine, parameter);
        {
            let items = queue.items.lock();
            let head = items.get();
            // SAFETY: the semaphore counted an item in, so the list is
            // not empty; queued items are live, and their list entries
            // belong to this lock.
            unsafe {
                let entry = (*head).Flink;
                let next = (*entry).Flink;
                (&raw mut (*head).Flink).write(next);
                (&raw mut (*next).Blink).write(head);
                let item = entry.cast::<WORK_QUEUE_ITEM>();
                routine = (&raw const (*item).WorkerRoutine).read();
                parameter = (&raw const (*item).Parameter).read();
                // On no queue again: its owner may queue it, or free it,
                // from the routine on.
                (&raw mut (*entry).Flink).write(core::ptr::null_mut());
            }
        }
        let Some(routine) = routine else {
            crate::kd::bugcheck(format_args!(
                "0x000000E4 WORKER_INVALID: a work item with no routine"
            ));
        };
        // SAFETY: the routine the driver registered, at PASSIVE_LEVEL in
        // a system thread, with the parameter it gave. Nothing lies
        // beneath a worker: an exception the routine lets out is
        // unhandled in a system thread.
        unsafe {
            seh::call(
                routine as usize,
                [parameter.addr(), 0, 0, 0],
                &Guard::Base(Unhandled::SystemThread),
            )
        };
        let level = irql::current();
        if level != irql::PASSIVE_LEVEL || mutex::KeAreApcsDisabled() != 0 {
            crate::kd::bugcheck(format_args!(
                "0x000000E1 WORKER_THREAD_RETURNED_AT_BAD_IRQL: a work routine returned at \
                 IRQL {level}{}",
                if level == irql::PASSIVE_LEVEL {
                    " with APCs disabled"
                } else {
                    ""
                }
            ));
        }
    }
}

/// [`ExQueueWorkItem`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-exqueueworkitem):
/// have a worker thread of queue `queue_type` run the item's routine.
/// Callable at `DISPATCH_LEVEL` and below.
///
/// # Safety
/// `item` was set up by `ExInitializeWorkItem`, is on no queue, and
/// stays valid until its routine is called.
pub unsafe extern "C" fn ExQueueWorkItem(item: *mut WORK_QUEUE_ITEM, queue_type: u32) {
    let Some(queue) = queue_of(queue_type) else {
        crate::kd::bugcheck(format_args!(
            "0x000000E4 WORKER_INVALID: a work item for queue {queue_type}"
        ));
    };
    {
        let items = queue.items.lock();
        let head = items.get();
        // SAFETY: per the contract; the list belongs to this lock.
        unsafe {
            let entry = item.cast::<LIST_ENTRY>();
            if !(*entry).Flink.is_null() {
                crate::kd::bugcheck(format_args!(
                    "0x000000E4 WORKER_INVALID: a work item queued while already queued"
                ));
            }
            let last = (*head).Blink;
            entry.write(LIST_ENTRY {
                Flink: head,
                Blink: last,
            });
            (&raw mut (*last).Flink).write(entry);
            (&raw mut (*head).Blink).write(entry);
        }
    }
    // SAFETY: the queue's semaphore; one more item waits.
    unsafe { wait::KeReleaseSemaphore(queue.semaphore(), 0, 1, 0) };
}

/// What an I/O work item's routine looks like to a driver.
type IoWorkRoutine = unsafe extern "C" fn(*mut DEVICE_OBJECT, *mut c_void);

/// Whether an I/O work item's object is a device. It may be a driver
/// object instead, which has no reference count to hold it by: the
/// driver must not unload with such an item outstanding, as on Windows
/// it could not.
///
/// # Safety
/// `object` is a live device or driver object.
unsafe fn is_device(object: *mut c_void) -> bool {
    // SAFETY: per the contract; both begin with their type.
    unsafe { object.cast::<i16>().read() == nk_ntabi::io::IO_TYPE_DEVICE }
}

/// [`IoAllocateWorkItem`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-ioallocateworkitem).
/// Null if memory ran out.
///
/// # Safety
/// `device` is a live device object, or a driver object.
pub unsafe extern "C" fn IoAllocateWorkItem(device: *mut DEVICE_OBJECT) -> *mut IO_WORKITEM {
    let item = pool::alloc_zeroed(size_of::<IO_WORKITEM>(), TAG).cast::<IO_WORKITEM>();
    if !item.is_null() {
        // SAFETY: a fresh block of the right size.
        unsafe { (&raw mut (*item).IoObject).write(device.cast()) };
    }
    item
}

/// [`IoFreeWorkItem`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-iofreeworkitem).
///
/// # Safety
/// `item` came from `IoAllocateWorkItem` and is not queued.
pub unsafe extern "C" fn IoFreeWorkItem(item: *mut IO_WORKITEM) {
    let freed = pool::free(item.cast());
    debug_assert!(freed.is_ok());
}

/// What a queued I/O work item owes its device if its routine is
/// unwound: the reference taken when it was queued.
///
/// # Safety
/// `device` is a device object referenced by `IoQueueWorkItem`.
unsafe fn release_device(device: *mut c_void) {
    // SAFETY: per the contract.
    unsafe { device::dereference(device.cast()) };
}

/// [`IoQueueWorkItem`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-ioqueueworkitem).
///
/// # Safety
/// `item` came from `IoAllocateWorkItem`, is not queued, and its device
/// is live; `routine` may be called with `context` at any later time.
pub unsafe extern "C" fn IoQueueWorkItem(
    item: *mut IO_WORKITEM,
    routine: Option<IoWorkRoutine>,
    queue_type: u32,
    context: *mut c_void,
) {
    /// Run a queued I/O work item.
    ///
    /// # Safety
    /// `parameter` is an I/O work item queued by `IoQueueWorkItem`.
    unsafe extern "C" fn run(parameter: *mut c_void) {
        let item = parameter.cast::<IO_WORKITEM>();
        // SAFETY: per the contract. Everything is read first: the
        // routine may free the item.
        unsafe {
            let routine: Option<IoWorkRoutine> =
                core::mem::transmute((&raw const (*item).Routine).read());
            let object = (&raw const (*item).IoObject).read();
            let context = (&raw const (*item).Context).read();
            let referenced = is_device(object);
            // The device's reference is given back whether the routine
            // returns or is unwound.
            let guard = if referenced {
                Guard::Undo {
                    undo: release_device,
                    context: object,
                }
            } else {
                Guard::Nothing
            };
            if let Some(routine) = routine {
                seh::call(
                    routine as usize,
                    [object.addr(), context.addr(), 0, 0],
                    &guard,
                );
            }
            if referenced {
                device::dereference(object.cast());
            }
        }
    }
    // SAFETY: per the contract.
    unsafe {
        (&raw mut (*item).Routine).write(
            core::mem::transmute::<Option<IoWorkRoutine>, *mut c_void>(routine),
        );
        (&raw mut (*item).Context).write(context);
        (&raw mut (*item).WorkItem.WorkerRoutine).write(Some(run));
        (&raw mut (*item).WorkItem.Parameter).write(item.cast());
        // A device stays until the routine has returned.
        let object = (&raw const (*item).IoObject).read();
        if is_device(object) {
            device::reference(object.cast());
        }
        ExQueueWorkItem(&raw mut (*item).WorkItem, queue_type);
    }
}

// ---- tests --------------------------------------------------------------

use crate::ke::{dpc, time};
use crate::test::Slot;
use core::sync::atomic::{AtomicU32, AtomicU64, AtomicUsize, Ordering};
use nk_ntabi::ke::{KDPC, KEVENT};

const ITEMS: usize = 256;
static WORK: [Slot<WORK_QUEUE_ITEM>; ITEMS] = [const { Slot::new() }; ITEMS];
/// How often each item's routine ran.
static RAN: [AtomicU32; ITEMS] = [const { AtomicU32::new(0) }; ITEMS];
static DONE: AtomicU64 = AtomicU64::new(0);
static WRONG: AtomicU32 = AtomicU32::new(0);
/// The thread that queued, to tell it from the worker.
static QUEUER: AtomicUsize = AtomicUsize::new(0);
static FINISHED: Slot<KEVENT> = Slot::new();

/// # Safety
/// Called as a work routine with an item's index as its parameter.
unsafe extern "C" fn count(parameter: *mut c_void) {
    if irql::current() != irql::PASSIVE_LEVEL
        || thread::current().addr() == QUEUER.load(Ordering::Acquire)
    {
        WRONG.fetch_add(1, Ordering::Relaxed);
    }
    RAN[parameter.addr()].fetch_add(1, Ordering::AcqRel);
    DONE.fetch_add(1, Ordering::AcqRel);
}

fn prepare(index: usize) {
    // What `ExInitializeWorkItem` compiles to in a driver.
    // SAFETY: static storage for an item that is on no queue.
    unsafe {
        let item = WORK[index].ptr();
        (&raw mut (*item).WorkerRoutine).write(Some(count));
        (&raw mut (*item).Parameter).write(index as *mut c_void);
        (&raw mut (*item).List.Flink).write(core::ptr::null_mut());
    }
}

fn queue(index: usize, queue_type: u32) {
    // SAFETY: a prepared static item that is on no queue.
    unsafe { ExQueueWorkItem(WORK[index].ptr(), queue_type) };
}

/// Sleep until `wanted` routines have run; `false` after five seconds.
fn finished(wanted: u64) -> bool {
    let deadline = time::interrupt_time() + 50_000_000;
    while DONE.load(Ordering::Acquire) < wanted {
        if time::interrupt_time() > deadline {
            return false;
        }
        // SAFETY: no object is involved.
        unsafe { wait::wait(None, Some(-10_000)) };
    }
    true
}

fn reset() {
    for ran in &RAN {
        ran.store(0, Ordering::Relaxed);
    }
    DONE.store(0, Ordering::Relaxed);
    WRONG.store(0, Ordering::Relaxed);
    QUEUER.store(thread::current().addr(), Ordering::Release);
}

/// A work item's routine runs once, at PASSIVE_LEVEL, in another thread,
/// on each of the three queues, and the item can be queued again
/// afterwards. Returns the routines run.
pub fn runs_test() -> Result<u64, &'static str> {
    reset();
    for queue_type in 0..QUEUES as u32 {
        prepare(queue_type as usize);
        queue(queue_type as usize, queue_type);
    }
    if !finished(3) {
        return Err("a queued work item's routine did not run");
    }
    // Used once, an item is free to be queued again.
    queue(1, 1);
    if !finished(4) {
        return Err("a work item could not be queued a second time");
    }
    let ran: [u32; 3] = core::array::from_fn(|i| RAN[i].load(Ordering::Acquire));
    if ran != [1, 2, 1] || WRONG.load(Ordering::Relaxed) != 0 {
        return Err(
            "a work routine ran the wrong number of times, or not as a worker at PASSIVE_LEVEL",
        );
    }
    Ok(4)
}

/// Many items queued at once, from threads on every processor and from
/// DPC routines, each run exactly once. Returns the items.
pub fn many_test() -> Result<u64, &'static str> {
    /// Queue the items `first..first + 32` from a thread.
    fn from_thread(first: usize) {
        for index in first..first + 32 {
            queue(index, (index % QUEUES) as u32);
        }
    }
    /// # Safety
    /// Called as a DPC routine; its context is an item index.
    unsafe extern "C" fn from_dpc(
        _: *mut KDPC,
        first: *mut c_void,
        _: *mut c_void,
        _: *mut c_void,
    ) {
        for index in first.addr()..first.addr() + 16 {
            queue(index, 1);
        }
    }
    static DPCS: [Slot<KDPC>; 4] = [const { Slot::new() }; 4];
    reset();
    for index in 0..ITEMS {
        prepare(index);
    }
    // 192 items from six threads, 64 from four DPCs.
    let threads = thread::count();
    for n in 0..6 {
        thread::create(
            from_thread,
            n * 32,
            thread::NORMAL_PRIORITY,
            thread::ANYWHERE,
        )?;
    }
    for (n, slot) in DPCS.iter().enumerate() {
        // SAFETY: static storage for a DPC that is not queued.
        unsafe {
            dpc::KeInitializeDpc(slot.ptr(), Some(from_dpc), (192 + n * 16) as *mut c_void);
            dpc::KeInsertQueueDpc(slot.ptr(), core::ptr::null_mut(), core::ptr::null_mut());
        }
    }
    if !finished(ITEMS as u64) {
        return Err("not every queued work item ran");
    }
    // The items have run; the threads that queued them end in their
    // own time, and are waited for, so that none is left to end under
    // the next test.
    super::stress::ended(threads);
    // SAFETY: no object is involved. Time for a second run to show.
    unsafe { wait::wait(None, Some(-200_000)) };
    if RAN.iter().any(|ran| ran.load(Ordering::Acquire) != 1) {
        return Err("a work item ran more than once, or not at all");
    }
    if WRONG.load(Ordering::Relaxed) != 0 {
        return Err("a work routine did not run as a worker at PASSIVE_LEVEL");
    }
    Ok(ITEMS as u64)
}

/// What the I/O work routine saw.
static IO_DEVICE: AtomicUsize = AtomicUsize::new(0);
static IO_ITEM: AtomicUsize = AtomicUsize::new(0);

/// # Safety
/// Called as an I/O work routine.
unsafe extern "C" fn io_routine(device: *mut DEVICE_OBJECT, context: *mut c_void) {
    if irql::current() != irql::PASSIVE_LEVEL
        || thread::current().addr() == QUEUER.load(Ordering::Acquire)
    {
        WRONG.fetch_add(1, Ordering::Relaxed);
    }
    IO_DEVICE.store(device.addr(), Ordering::Release);
    if context.addr() == 2 {
        // The last use: a routine may free its own item.
        // SAFETY: the item came from `IoAllocateWorkItem`, and a worker
        // took it off the queue before calling this.
        unsafe { IoFreeWorkItem(IO_ITEM.load(Ordering::Acquire) as *mut IO_WORKITEM) };
    }
    DONE.fetch_add(1, Ordering::AcqRel);
    // SAFETY: a static, initialised event.
    unsafe { wait::KeSetEvent(FINISHED.ptr(), 0, 0) };
}

/// An I/O work item's routine is given its device and context, the item
/// can be queued again and freed by its own routine, and the device is
/// referenced exactly while an item is on its way. Returns the routines
/// run.
pub fn io_test(device_object: *mut DEVICE_OBJECT) -> Result<u64, &'static str> {
    let references = || {
        // SAFETY: the caller's device is live.
        unsafe { (&raw const (*device_object).ReferenceCount).read_volatile() }
    };
    reset();
    // SAFETY: static storage for an event nothing waits on.
    unsafe { wait::KeInitializeEvent(FINISHED.ptr(), 1, 0) };
    let before = references();
    // SAFETY: the caller's device is live; the item is queued only
    // while it is on no queue.
    unsafe {
        let item = IoAllocateWorkItem(device_object);
        if item.is_null() {
            return Err("no memory for an I/O work item");
        }
        IO_ITEM.store(item.addr(), Ordering::Release);
        for context in 1..=2usize {
            IO_DEVICE.store(0, Ordering::Release);
            IoQueueWorkItem(item, Some(io_routine), 1, context as *mut c_void);
            if wait::wait(Some(FINISHED.ptr().cast()), Some(-50_000_000)) != wait::STATUS_SUCCESS {
                return Err("an I/O work item's routine did not run");
            }
            if IO_DEVICE.load(Ordering::Acquire) != device_object.addr() {
                return Err("an I/O work routine was not given its device");
            }
        }
    }
    // The reference goes when the routine has returned, a moment after
    // it signalled.
    let deadline = time::interrupt_time() + 20_000_000;
    while references() != before && time::interrupt_time() < deadline {
        thread::yield_now();
    }
    if references() != before {
        return Err("the device was left referenced after its work items ran");
    }
    if DONE.load(Ordering::Acquire) != 2 || WRONG.load(Ordering::Relaxed) != 0 {
        return Err("an I/O work routine did not run once per queueing, as a worker");
    }
    Ok(2)
}

/// A device is deleted while a work item of its is still on the way,
/// over and over, so that the deletion and the item's last reference
/// meet in every order. The device must be freed exactly once, by
/// whichever comes second. `make_device` creates one. Returns the
/// devices deleted.
pub fn delete_race_test(
    make_device: fn() -> Option<*mut DEVICE_OBJECT>,
) -> Result<u64, &'static str> {
    /// # Safety
    /// Called as an I/O work routine; the context is its own item.
    unsafe extern "C" fn routine(_: *mut DEVICE_OBJECT, item: *mut c_void) {
        // SAFETY: the item came from `IoAllocateWorkItem` and is off
        // the queue.
        unsafe { IoFreeWorkItem(item.cast()) };
        DONE.fetch_add(1, Ordering::AcqRel);
    }
    const ROUNDS: u64 = 400;
    reset();
    let pool_before = pool::usage().blocks;
    for round in 0..ROUNDS {
        let device_object = make_device().ok_or("could not create a device object")?;
        // SAFETY: a live device; the item frees itself in its routine.
        unsafe {
            let item = IoAllocateWorkItem(device_object);
            if item.is_null() {
                return Err("no memory for an I/O work item");
            }
            IoQueueWorkItem(item, Some(routine), (round % 3) as u32, item.cast());
            // Now and then let the routine get there first.
            if round % 3 == 0 {
                thread::yield_now();
            }
            device::IoDeleteDevice(device_object);
        }
    }
    if !finished(ROUNDS) {
        return Err("not every work item ran");
    }
    // The last reference goes a moment after the routine returns.
    let deadline = time::interrupt_time() + 20_000_000;
    while pool::usage().blocks != pool_before && time::interrupt_time() < deadline {
        thread::yield_now();
    }
    if pool::usage().blocks != pool_before {
        return Err("a device deleted with a work item on the way was never freed");
    }
    Ok(ROUNDS)
}

/// A work routine that returns with the IRQL raised. The system must
/// stop.
pub fn bad_return_test() {
    /// # Safety
    /// Called as a work routine.
    unsafe extern "C" fn raise(_: *mut c_void) {
        crate::arch::set_irql(irql::DISPATCH_LEVEL);
    }
    // SAFETY: static storage for an item that is on no queue.
    unsafe {
        let item = WORK[0].ptr();
        (&raw mut (*item).WorkerRoutine).write(Some(raise));
        (&raw mut (*item).Parameter).write(core::ptr::null_mut());
        (&raw mut (*item).List.Flink).write(core::ptr::null_mut());
        ExQueueWorkItem(item, 1);
        wait::wait(None, Some(-20_000_000));
    }
}
