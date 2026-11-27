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
use nk_ex::work::Pool;
use nk_ntabi::ex::{IO_WORKITEM, WORK_QUEUE_ITEM, WORK_QUEUES, work_queue};
use nk_ntabi::io::DEVICE_OBJECT;
use nk_ntabi::ke::{KEVENT, KSEMAPHORE, LIST_ENTRY};

/// The queues NK keeps.
const QUEUES: usize = WORK_QUEUES;

/// The queue that serves a `WORK_QUEUE_TYPE` (`nk_ntabi::ex::work_queue`).
/// `None` for a value Windows does not define.
fn queue_of(queue_type: u32) -> Option<&'static Queue> {
    work_queue(queue_type).map(|index| &QUEUE[index])
}
/// Each queue's worker threads: `(min, max, priority)`. Indexed by
/// `WORK_QUEUE_TYPE`: critical, delayed, hypercritical.
const WORKERS: [(u32, u32, u8); QUEUES] = [(2, 16, 13), (2, 16, 12), (1, 4, 15)];

/// How long an extra dynamic worker waits idle before retiring (5 s,
/// relative 100 ns units).
const IDLE_TIMEOUT: i64 = -50_000_000;
/// Grace period before the spawner creates another worker, so brief
/// non-blocking bursts drain without spawning threads (15 ms, relative
/// 100 ns units).
const SPAWN_GRACE: i64 = -150_000;

/// Pool tag of I/O work items.
const TAG: u32 = u32::from_le_bytes(*b"IoWI");

struct QueueState {
    /// The items waiting, oldest first: a circular list through the
    /// items' list entries, with this head.
    head: LIST_ENTRY,
    /// Dynamic worker counts (`nk_ex::work::Pool`).
    pool: Pool,
}

// SAFETY: the list and pool counts are only touched under the queue's lock.
unsafe impl Send for QueueState {}

struct Queue {
    /// Items waiting and worker pool state.
    state: SpinLock<QueueState>,
    /// Counts the items waiting; the workers wait on it.
    waiting: UnsafeCell<MaybeUninit<KSEMAPHORE>>,
}

// SAFETY: the state is only touched under its lock; the semaphore only
// through the kernel routines, which lock for themselves.
unsafe impl Sync for Queue {}

const fn new_queue(min: u32, max: u32) -> Queue {
    Queue {
        state: SpinLock::new(
            Rank::WorkQueue,
            QueueState {
                head: LIST_ENTRY {
                    Flink: core::ptr::null_mut(),
                    Blink: core::ptr::null_mut(),
                },
                pool: Pool::new(min, max),
            },
        ),
        waiting: UnsafeCell::new(MaybeUninit::uninit()),
    }
}

static QUEUE: [Queue; QUEUES] = [
    new_queue(WORKERS[0].0, WORKERS[0].1),
    new_queue(WORKERS[1].0, WORKERS[1].1),
    new_queue(WORKERS[2].0, WORKERS[2].1),
];

/// Wakes the spawner thread when a queue has work waiting with no idle
/// worker to take it.
struct SpawnEvent(UnsafeCell<MaybeUninit<KEVENT>>);

// SAFETY: a dispatcher object, used only through the kernel wait routines.
unsafe impl Sync for SpawnEvent {}

static SPAWN_EVENT: SpawnEvent = SpawnEvent(UnsafeCell::new(MaybeUninit::uninit()));

fn spawn_event() -> *mut KEVENT {
    SPAWN_EVENT.0.get().cast()
}

impl Queue {
    fn semaphore(&self) -> *mut KSEMAPHORE {
        self.waiting.get().cast()
    }
}

/// Start the base worker threads and the dynamic-worker spawner. Once,
/// after every processor is running.
pub fn init() -> Result<(), &'static str> {
    // SAFETY: static storage for a synchronization event nothing waits on yet.
    unsafe { wait::KeInitializeEvent(spawn_event(), 1, 0) };
    for (index, queue) in QUEUE.iter().enumerate() {
        {
            let mut state = queue.state.lock();
            let head = &raw mut state.head;
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
        let (min, _, priority) = WORKERS[index];
        for _ in 0..min {
            thread::create_uncounted(worker, index, priority, thread::ANYWHERE)?;
        }
    }
    thread::create(spawner, 0, 15, thread::ANYWHERE)?;
    Ok(())
}

/// Dynamic worker spawner: grows any queue whose items stay waiting
/// with no idle worker beyond [`SPAWN_GRACE`], up to its cap. Runs at
/// `PASSIVE_LEVEL` so `ExQueueWorkItem` never allocates stacks or
/// touches memory-manager locks at `DISPATCH_LEVEL`.
fn spawner(_: usize) {
    loop {
        // SAFETY: the static synchronization event, initialised at start.
        unsafe { wait::wait(Some(spawn_event().cast()), None) };
        loop {
            // SAFETY: no object is involved.
            unsafe { wait::wait(None, Some(SPAWN_GRACE)) };
            let mut spawned = false;
            for (index, queue) in QUEUE.iter().enumerate() {
                if !queue.state.lock().pool.begin_spawn() {
                    continue;
                }
                let (_, _, priority) = WORKERS[index];
                match thread::create_uncounted(worker, index, priority, thread::ANYWHERE) {
                    Ok(_) => {
                        queue.state.lock().pool.spawn_succeeded();
                        spawned = true;
                    }
                    Err(_) => {
                        queue.state.lock().pool.spawn_failed();
                    }
                }
            }
            if !spawned || !QUEUE.iter().any(|q| q.state.lock().pool.wants_worker()) {
                break;
            }
        }
    }
}

/// A worker thread: run items of queue `index`, retiring on an idle
/// timeout when extra dynamic workers are no longer needed.
fn worker(index: usize) {
    let queue = &QUEUE[index];
    loop {
        // SAFETY: the queue's semaphore, initialised before any worker
        // was created.
        let status = unsafe { wait::wait(Some(queue.semaphore().cast()), Some(IDLE_TIMEOUT)) };
        if status == wait::STATUS_TIMEOUT {
            if queue.state.lock().pool.on_idle_timeout() {
                return;
            }
            continue;
        }
        let (routine, parameter, need_spawn) = {
            let mut state = queue.state.lock();
            let head = &raw mut state.head;
            // SAFETY: the semaphore counted an item in, so the list is
            // not empty; queued items are live, and their list entries
            // belong to this lock.
            let (routine, parameter) = unsafe {
                let entry = (*head).Flink;
                let next = (*entry).Flink;
                (&raw mut (*head).Flink).write(next);
                (&raw mut (*next).Blink).write(head);
                let item = entry.cast::<WORK_QUEUE_ITEM>();
                let routine = (&raw const (*item).WorkerRoutine).read();
                let parameter = (&raw const (*item).Parameter).read();
                // On no queue again: its owner may queue it, or free it,
                // from the routine on.
                (&raw mut (*entry).Flink).write(core::ptr::null_mut());
                (routine, parameter)
            };
            let need_spawn = state.pool.on_dequeue();
            (routine, parameter, need_spawn)
        };
        if need_spawn {
            // SAFETY: the static event, initialised before any worker started.
            unsafe { wait::KeSetEvent(spawn_event(), 0, 0) };
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
        queue.state.lock().pool.on_done();
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
    let need_spawn = {
        let mut state = queue.state.lock();
        let head = &raw mut state.head;
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
        state.pool.on_queue()
    };
    // SAFETY: the queue's semaphore; one more item waits.
    unsafe { wait::KeReleaseSemaphore(queue.semaphore(), 0, 1, 0) };
    if need_spawn {
        // SAFETY: the static event, initialised before any worker started.
        unsafe { wait::KeSetEvent(spawn_event(), 0, 0) };
    }
}

/// `ExTryQueueWorkItem` (exported, not documented): `ExQueueWorkItem`
/// that says whether the item was queued. `TRUE` always: an item NK is
/// handed is on its queue when this returns.
///
/// INFERRED: that Windows returns `FALSE` only when it cannot hand the
/// item to a worker at that moment. Read from the kernel NK follows, an
/// item already queued or a queue that does not exist stops the system
/// here as in `ExQueueWorkItem`.
///
/// # Safety
/// As [`ExQueueWorkItem`].
pub unsafe extern "C" fn ExTryQueueWorkItem(item: *mut WORK_QUEUE_ITEM, queue_type: u32) -> u8 {
    // SAFETY: per the contract.
    unsafe { ExQueueWorkItem(item, queue_type) };
    1
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

/// `IO_WORKITEM.Type`, as the pinned kernel sets it: an item is made
/// (`IoInitializeWorkItem`) as one whose routine is handed the item
/// itself, and `IoQueueWorkItem` turns it into one whose routine is
/// not. `IoQueueWorkItemEx` leaves the type as it finds it.
const ITEM_ROUTINE_EX: u32 = 1;
const ITEM_ROUTINE: u32 = 0;

/// [`IoSizeofWorkItem`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-iosizeofworkitem):
/// how much memory a driver sets aside for a work item it initialises
/// itself: Windows' `IO_WORKITEM`, which NK's is.
pub extern "C" fn IoSizeofWorkItem() -> u32 {
    size_of::<IO_WORKITEM>() as u32
}

/// [`IoInitializeWorkItem`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-ioinitializeworkitem):
/// make `IoSizeofWorkItem()` bytes of the driver's a work item for
/// `io_object`, a device or a driver object. The fields the pinned
/// kernel writes are written; the rest is the driver's to have
/// cleared or not.
///
/// # Safety
/// `io_object` is a live device or driver object; `item` is writable
/// for `IoSizeofWorkItem()` bytes and is not queued.
pub unsafe extern "C" fn IoInitializeWorkItem(io_object: *mut c_void, item: *mut IO_WORKITEM) {
    // SAFETY: per the contract; both kinds of object begin with their
    // type.
    unsafe {
        let kind = io_object.cast::<i16>().read();
        if kind != nk_ntabi::io::IO_TYPE_DEVICE && kind != nk_ntabi::io::IO_TYPE_DRIVER {
            crate::kd::bugcheck(format_args!(
                "IoInitializeWorkItem: {io_object:p} is neither a device nor a driver object"
            ));
        }
        (&raw mut (*item).WorkOnBehalfThread).write(core::ptr::null_mut());
        (&raw mut (*item).Type).write(ITEM_ROUTINE_EX);
        (&raw mut (*item).IoObject).write(io_object);
        (&raw mut (*item).WorkItem.List.Flink).write(core::ptr::null_mut());
        (&raw mut (*item).WorkItem.WorkerRoutine).write(Some(run_io_item));
        (&raw mut (*item).WorkItem.Parameter).write(item.cast());
    }
}

/// [`IoUninitializeWorkItem`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-iouninitializeworkitem):
/// the driver is about to free the memory of a work item it
/// initialised. An item still queued stops the system, as on Windows:
/// a worker would run freed memory.
///
/// # Safety
/// `item` was initialised by `IoInitializeWorkItem`.
pub unsafe extern "C" fn IoUninitializeWorkItem(item: *mut IO_WORKITEM) {
    // SAFETY: per the contract.
    if !unsafe { (&raw const (*item).WorkItem.List.Flink).read() }.is_null() {
        crate::kd::bugcheck(format_args!(
            "IoUninitializeWorkItem: work item {item:p} is still queued"
        ));
    }
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
        unsafe { IoInitializeWorkItem(device.cast(), item) };
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

/// Run a queued I/O work item: its routine is handed the item's object
/// and context, and the item itself if it was queued by
/// `IoQueueWorkItemEx`.
///
/// # Safety
/// `parameter` is an I/O work item queued by [`queue_io_item`].
unsafe extern "C" fn run_io_item(parameter: *mut c_void) {
    let item = parameter.cast::<IO_WORKITEM>();
    // SAFETY: per the contract. Everything is read first: the
    // routine may free the item.
    unsafe {
        let routine = (&raw const (*item).Routine).read();
        let object = (&raw const (*item).IoObject).read();
        let context = (&raw const (*item).Context).read();
        let handed = if (&raw const (*item).Type).read() == ITEM_ROUTINE {
            0
        } else {
            item.addr()
        };
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
        if !routine.is_null() {
            seh::call(
                routine.addr(),
                [object.addr(), context.addr(), handed, 0],
                &guard,
            );
        }
        if referenced {
            device::dereference(object.cast());
        }
    }
}

/// Queue an I/O work item to call `routine`.
///
/// # Safety
/// `item` is an initialised I/O work item that is not queued, and its
/// object is live; `routine` may be called at any later time.
unsafe fn queue_io_item(
    item: *mut IO_WORKITEM,
    routine: *mut c_void,
    queue_type: u32,
    context: *mut c_void,
) {
    // SAFETY: per the contract.
    unsafe {
        (&raw mut (*item).Routine).write(routine);
        (&raw mut (*item).Context).write(context);
        (&raw mut (*item).WorkItem.WorkerRoutine).write(Some(run_io_item));
        (&raw mut (*item).WorkItem.Parameter).write(item.cast());
        // A device stays until the routine has returned.
        let object = (&raw const (*item).IoObject).read();
        if is_device(object) {
            device::reference(object.cast());
        }
        ExQueueWorkItem(&raw mut (*item).WorkItem, queue_type);
    }
}

/// [`IoQueueWorkItem`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-ioqueueworkitem).
///
/// # Safety
/// `item` came from `IoAllocateWorkItem` or `IoInitializeWorkItem`, is
/// not queued, and its device is live; `routine` may be called with
/// `context` at any later time.
pub unsafe extern "C" fn IoQueueWorkItem(
    item: *mut IO_WORKITEM,
    routine: Option<IoWorkRoutine>,
    queue_type: u32,
    context: *mut c_void,
) {
    // SAFETY: per the contract.
    unsafe {
        (&raw mut (*item).Type).write(ITEM_ROUTINE);
        let routine = core::mem::transmute::<Option<IoWorkRoutine>, *mut c_void>(routine);
        queue_io_item(item, routine, queue_type, context);
    }
}

/// What a routine queued by `IoQueueWorkItemEx` looks like to a driver:
/// it is handed the work item too, which it may free or queue again.
type IoWorkRoutineEx = unsafe extern "C" fn(*mut c_void, *mut c_void, *mut IO_WORKITEM);

/// [`IoQueueWorkItemEx`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-ioqueueworkitemex):
/// as [`IoQueueWorkItem`], for a routine that is handed the work item.
/// As in the pinned kernel, which kind of routine an item has is
/// decided by `IoQueueWorkItem` alone: an item once queued by it stays
/// one whose routine is not handed the item.
///
/// # Safety
/// As [`IoQueueWorkItem`].
pub unsafe extern "C" fn IoQueueWorkItemEx(
    item: *mut IO_WORKITEM,
    routine: Option<IoWorkRoutineEx>,
    queue_type: u32,
    context: *mut c_void,
) {
    // SAFETY: per the contract.
    unsafe {
        let routine = core::mem::transmute::<Option<IoWorkRoutineEx>, *mut c_void>(routine);
        queue_io_item(item, routine, queue_type, context);
    }
}

// ---- tests --------------------------------------------------------------

use crate::ke::{dpc, time};
use crate::test::Slot;
use core::sync::atomic::{AtomicU32, AtomicU64, AtomicUsize, Ordering};
use nk_ntabi::ke::KDPC;

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
    // SAFETY: a prepared static item that is on no queue.
    if unsafe { ExTryQueueWorkItem(WORK[1].ptr(), 1) } != 1 {
        return Err("ExTryQueueWorkItem did not say it queued the item");
    }
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
    let live_blocks = || pool::usage().blocks - thread::uncounted_storage().0;
    let pool_before = live_blocks();
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
    while live_blocks() != pool_before && time::interrupt_time() < deadline {
        thread::yield_now();
    }
    if live_blocks() != pool_before {
        return Err("a device deleted with a work item on the way was never freed");
    }
    Ok(ROUNDS)
}

/// Blocking every existing worker on a queue and queueing another item
/// grows the pool dynamically so the extra item still runs, without
/// perturbing `thread::count()`. Returns the items run.
pub fn dynamic_test() -> Result<u64, &'static str> {
    static BLOCK_RELEASE: Slot<KEVENT> = Slot::new();
    static EXTRA_RAN: Slot<KEVENT> = Slot::new();
    static ENTERED: AtomicU32 = AtomicU32::new(0);
    static BLOCK_DONE: AtomicU32 = AtomicU32::new(0);
    static DYN_ITEMS: [Slot<WORK_QUEUE_ITEM>; 16] = [const { Slot::new() }; 16];

    /// # Safety
    /// Called as a work routine while `BLOCK_RELEASE` is live.
    unsafe extern "C" fn blocker(_: *mut c_void) {
        ENTERED.fetch_add(1, Ordering::AcqRel);
        // SAFETY: static notification event, initialised before queueing.
        unsafe { wait::wait(Some(BLOCK_RELEASE.ptr().cast()), None) };
        BLOCK_DONE.fetch_add(1, Ordering::AcqRel);
    }

    /// # Safety
    /// Called as a work routine while `EXTRA_RAN` is live.
    unsafe extern "C" fn extra(_: *mut c_void) {
        // SAFETY: static notification event, initialised before queueing.
        unsafe { wait::KeSetEvent(EXTRA_RAN.ptr(), 0, 0) };
    }

    let before_threads = thread::count();
    let current_workers = QUEUE[1].state.lock().pool.workers() as usize;
    let blockers = current_workers.min(12);
    ENTERED.store(0, Ordering::Relaxed);
    BLOCK_DONE.store(0, Ordering::Relaxed);
    // SAFETY: static notification events, not waited on yet.
    unsafe {
        wait::KeInitializeEvent(BLOCK_RELEASE.ptr(), 0, 0);
        wait::KeInitializeEvent(EXTRA_RAN.ptr(), 0, 0);
    }
    for slot in &DYN_ITEMS[..blockers] {
        // SAFETY: static work item off any queue.
        unsafe {
            let item = slot.ptr();
            (&raw mut (*item).WorkerRoutine).write(Some(blocker));
            (&raw mut (*item).Parameter).write(core::ptr::null_mut());
            (&raw mut (*item).List.Flink).write(core::ptr::null_mut());
            ExQueueWorkItem(item, 1);
        }
    }
    let deadline = time::interrupt_time() + 50_000_000;
    while (ENTERED.load(Ordering::Acquire) as usize) < blockers {
        if time::interrupt_time() > deadline {
            // SAFETY: release any workers already blocked before returning.
            unsafe { wait::KeSetEvent(BLOCK_RELEASE.ptr(), 0, 0) };
            return Err("base workers did not all start the blocking items");
        }
        // SAFETY: no object is involved.
        unsafe { wait::wait(None, Some(-10_000)) };
    }
    // Every worker on queue 1 is blocked; this item needs a dynamic worker.
    // SAFETY: static work item off any queue.
    unsafe {
        let item = DYN_ITEMS[blockers].ptr();
        (&raw mut (*item).WorkerRoutine).write(Some(extra));
        (&raw mut (*item).Parameter).write(core::ptr::null_mut());
        (&raw mut (*item).List.Flink).write(core::ptr::null_mut());
        ExQueueWorkItem(item, 1);
    }
    // SAFETY: static event.
    let status = unsafe { wait::wait(Some(EXTRA_RAN.ptr().cast()), Some(-50_000_000)) };
    let peak_workers = QUEUE[1].state.lock().pool.workers() as usize;
    // Release the blockers and wait for them to finish before returning.
    // SAFETY: static event.
    unsafe { wait::KeSetEvent(BLOCK_RELEASE.ptr(), 0, 0) };
    let deadline = time::interrupt_time() + 50_000_000;
    while (BLOCK_DONE.load(Ordering::Acquire) as usize) < blockers {
        if time::interrupt_time() > deadline {
            return Err("blocked workers did not finish after release");
        }
        // SAFETY: no object is involved.
        unsafe { wait::wait(None, Some(-10_000)) };
    }
    if status != wait::STATUS_SUCCESS {
        return Err("a dynamic worker was not spawned when all workers were blocked");
    }
    if peak_workers <= blockers {
        return Err("the queue's worker count did not grow");
    }
    if thread::count() != before_threads {
        return Err("a dynamic executive worker changed thread::count()");
    }
    Ok(blockers as u64 + 1)
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
