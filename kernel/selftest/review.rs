//! Tests for faults found by reading the code rather than by running
//! it: each failed before its fix.

use crate::io::device::{IoCreateDevice, IoDeleteDevice};
use crate::ke::{irql, smp, thread, time, wait};
use crate::mm::pool;
use crate::ob::handle::ObReferenceObjectByHandle;
use crate::ob::object::{ExEventObjectType, ObfDereferenceObject, PsThreadType};
use crate::test::{Group, Report, Slot};
use core::ffi::c_void;
use core::sync::atomic::{AtomicBool, AtomicPtr, AtomicU32, Ordering};
use nk_bootinfo::BootInfo;
use nk_ntabi::io::{DEVICE_OBJECT, DRIVER_EXTENSION, DRIVER_OBJECT};
use nk_ntabi::ke::KEVENT;

pub static GROUP: Group = Group {
    names: &[
        "ob.current-thread",
        "io.device-list",
        "io.open-delete",
        "thread.wake-at-dispatch",
        "work.queue-types",
        "work.driver-object",
        "ps.thread.no-handle",
    ],
    run,
    manual: false,
};

/// Another processor that is running, or this one if it is alone.
fn other_processor() -> usize {
    let me = crate::ke::pcr::current_processor() as usize;
    (0..64)
        .find(|&cpu| cpu != me && smp::is_online(cpu))
        .unwrap_or(me)
}

/// `NtCurrentThread()` is a handle like any other to
/// `ObReferenceObjectByHandle`: it names the calling thread.
fn current_thread() -> Result<(), &'static str> {
    let pseudo = -2isize as *mut c_void;
    let me = thread::current().cast::<c_void>();
    let mut object = core::ptr::null_mut();
    // SAFETY: the outputs are locals; the reference taken is given up.
    unsafe {
        if ObReferenceObjectByHandle(
            pseudo,
            0,
            PsThreadType.value(),
            0,
            &raw mut object,
            core::ptr::null_mut(),
        ) != 0
            || object != me
        {
            return Err("the current-thread handle does not name the calling thread");
        }
        ObfDereferenceObject(object);
        if ObReferenceObjectByHandle(
            pseudo,
            0,
            core::ptr::null(),
            0,
            &raw mut object,
            core::ptr::null_mut(),
        ) != 0
            || object != me
        {
            return Err("the current-thread handle needs a type to be named");
        }
        ObfDereferenceObject(object);
        let status = ObReferenceObjectByHandle(
            pseudo,
            0,
            ExEventObjectType.value(),
            0,
            &raw mut object,
            core::ptr::null_mut(),
        );
        if status as u32 != 0xC000_0024 || !object.is_null() {
            return Err("the current thread was handed out as an event");
        }
    }
    Ok(())
}

static DRIVER: AtomicPtr<DRIVER_OBJECT> = AtomicPtr::new(core::ptr::null_mut());
static GO: AtomicBool = AtomicBool::new(false);
static FINISHED: AtomicU32 = AtomicU32::new(0);
static FAILED: AtomicBool = AtomicBool::new(false);
const DEVICES: usize = 300;

fn create_devices(_: usize) {
    while !GO.load(Ordering::Acquire) {
        thread::yield_now();
    }
    for _ in 0..DEVICES {
        let mut device: *mut DEVICE_OBJECT = core::ptr::null_mut();
        // SAFETY: the test's driver object, alive until both creators
        // have finished.
        if unsafe {
            IoCreateDevice(
                DRIVER.load(Ordering::Acquire),
                0,
                core::ptr::null(),
                0x22,
                0,
                0,
                &raw mut device,
            )
        } != 0
        {
            FAILED.store(true, Ordering::Release);
        }
    }
    FINISHED.fetch_add(1, Ordering::AcqRel);
}

/// Two processors create devices for one driver at once: every device
/// ends up on the driver's list. Returns how many.
fn device_list() -> Result<u32, &'static str> {
    let size = size_of::<DRIVER_OBJECT>() + size_of::<DRIVER_EXTENSION>();
    let driver = pool::alloc_zeroed(size, u32::from_le_bytes(*b"Test")).cast::<DRIVER_OBJECT>();
    if driver.is_null() {
        return Err("no memory for a driver object");
    }
    let threads = thread::count();
    DRIVER.store(driver, Ordering::Release);
    GO.store(false, Ordering::Release);
    FINISHED.store(0, Ordering::Release);
    FAILED.store(false, Ordering::Release);
    let me = crate::ke::pcr::current_processor() as usize;
    let started =
        thread::create(create_devices, 0, thread::NORMAL_PRIORITY, 1 << me).and_then(|_| {
            thread::create(
                create_devices,
                0,
                thread::NORMAL_PRIORITY,
                1 << other_processor(),
            )
        });
    GO.store(true, Ordering::Release);
    if started.is_ok() {
        while FINISHED.load(Ordering::Acquire) != 2 {
            thread::yield_now();
        }
    }
    while thread::count() != threads {
        thread::yield_now();
    }
    // Count what the list holds, and take it all down.
    let mut listed = 0;
    // SAFETY: the creators have finished; the list is this test's.
    unsafe {
        loop {
            let device = (*driver).DeviceObject;
            if device.is_null() {
                break;
            }
            listed += 1;
            IoDeleteDevice(device);
        }
    }
    let _ = pool::free(driver.cast());
    if started.is_err() || FAILED.load(Ordering::Acquire) {
        return Err("devices could not be created");
    }
    if listed != 2 * DEVICES as u32 {
        return Err("devices created at the same time are missing from the driver's list");
    }
    Ok(listed)
}

static EVENT: Slot<KEVENT> = Slot::new();
static WOKEN: AtomicBool = AtomicBool::new(false);
static SET: AtomicBool = AtomicBool::new(false);

fn sleeper(_: usize) {
    // SAFETY: the test's event, initialised before this thread exists.
    unsafe { wait::wait(Some(EVENT.ptr().cast()), None) };
    WOKEN.store(true, Ordering::Release);
}

fn waker(_: usize) {
    while !GO.load(Ordering::Acquire) {
        thread::yield_now();
    }
    // SAFETY: as in `sleeper`.
    unsafe { wait::KeSetEvent(EVENT.ptr(), 0, 0) };
    SET.store(true, Ordering::Release);
}

/// A thread of higher priority is made ready for this processor, from
/// another, while this one is at `DISPATCH_LEVEL`. It cannot run yet;
/// it must run the moment the IRQL comes down, not at the next
/// interrupt that happens along.
fn wake_at_dispatch() -> Result<(), &'static str> {
    let threads = thread::count();
    let me = crate::ke::pcr::current_processor() as usize;
    let other = other_processor();
    GO.store(false, Ordering::Release);
    WOKEN.store(false, Ordering::Release);
    SET.store(false, Ordering::Release);
    // SAFETY: static storage, used by this test's threads only.
    unsafe { wait::KeInitializeEvent(EVENT.ptr(), 1, 0) };
    // Above this thread: it runs at once, as far as its wait.
    thread::create(sleeper, 0, thread::NORMAL_PRIORITY + 4, 1 << me).map_err(|_| "no thread")?;
    let alone = other == me;
    if !alone {
        thread::create(waker, 0, thread::NORMAL_PRIORITY, 1 << other).map_err(|_| "no thread")?;
    }
    let old = irql::raise(irql::DISPATCH_LEVEL);
    if alone {
        // SAFETY: as in `sleeper`.
        unsafe { wait::KeSetEvent(EVENT.ptr(), 0, 0) };
    } else {
        GO.store(true, Ordering::Release);
        while !SET.load(Ordering::Acquire) {
            core::hint::spin_loop();
        }
        // Long enough for the other processor's notice to arrive, well
        // short of a clock tick.
        time::stall(300);
    }
    let early = WOKEN.load(Ordering::Acquire);
    irql::lower(old);
    let ran = WOKEN.load(Ordering::Acquire);
    while thread::count() != threads {
        thread::yield_now();
    }
    if early {
        return Err("a thread ran on a processor that was at DISPATCH_LEVEL");
    }
    if !ran {
        return Err(
            "a higher-priority thread made ready during DISPATCH_LEVEL did not run when the IRQL came down",
        );
    }
    Ok(())
}

static NAMED: AtomicU32 = AtomicU32::new(0);
const NAME: &str = "\\Device\\NkOpenDelete";

fn create_and_delete(_: usize) {
    let name: alloc::vec::Vec<u16> = NAME.encode_utf16().collect();
    let name = nk_ntabi::io::UNICODE_STRING {
        Length: (name.len() * 2) as u16,
        MaximumLength: (name.len() * 2) as u16,
        Buffer: name.as_ptr().cast_mut(),
    };
    for _ in 0..2000 {
        let mut device: *mut DEVICE_OBJECT = core::ptr::null_mut();
        // SAFETY: the test's driver object, alive until this thread has
        // finished; the device is deleted by the thread that made it.
        unsafe {
            if IoCreateDevice(
                DRIVER.load(Ordering::Acquire),
                0,
                &raw const name,
                0x22,
                0,
                0,
                &raw mut device,
            ) == 0
            {
                NAMED.fetch_add(1, Ordering::AcqRel);
                IoDeleteDevice(device);
            }
        }
    }
    FINISHED.fetch_add(1, Ordering::AcqRel);
}

/// A device is opened by name on one processor while another keeps
/// creating and deleting it. The device is never finished being set up,
/// so no open may succeed; and none may touch a device that has gone.
/// Returns how many opens were tried.
fn open_delete() -> Result<u32, &'static str> {
    let size = size_of::<DRIVER_OBJECT>() + size_of::<DRIVER_EXTENSION>();
    let driver = pool::alloc_zeroed(size, u32::from_le_bytes(*b"Test")).cast::<DRIVER_OBJECT>();
    if driver.is_null() {
        return Err("no memory for a driver object");
    }
    let threads = thread::count();
    DRIVER.store(driver, Ordering::Release);
    FINISHED.store(0, Ordering::Release);
    NAMED.store(0, Ordering::Release);
    let (mut tried, mut opened) = (0, false);
    if thread::create(
        create_and_delete,
        0,
        thread::NORMAL_PRIORITY,
        1 << other_processor(),
    )
    .is_ok()
    {
        while FINISHED.load(Ordering::Acquire) != 1 {
            match super::open(NAME) {
                Ok(file) => {
                    opened = true;
                    crate::io::file::close(file);
                }
                Err(_) => tried += 1,
            }
            thread::yield_now();
        }
    }
    while thread::count() != threads {
        thread::yield_now();
    }
    let _ = pool::free(driver.cast());
    if opened {
        return Err("a device that was never finished being set up was opened");
    }
    if NAMED.load(Ordering::Acquire) != 2000 {
        return Err("the device could not be created and deleted");
    }
    Ok(tried)
}

static RAN: AtomicU32 = AtomicU32::new(0);
static GOT: AtomicPtr<c_void> = AtomicPtr::new(core::ptr::null_mut());
static ITEM: Slot<nk_ntabi::ex::WORK_QUEUE_ITEM> = Slot::new();

/// Wait, a second at most, for `RAN` to reach `count`.
fn ran(count: u32) -> bool {
    for _ in 0..1000 {
        if RAN.load(Ordering::Acquire) == count {
            return true;
        }
        time::stall(1_000);
    }
    false
}

/// A work routine that counts its runs.
///
/// # Safety
/// Called as a work routine.
unsafe extern "C" fn count_run(_: *mut c_void) {
    RAN.fetch_add(1, Ordering::AcqRel);
}

/// Windows 10 has seven kinds of work queue; an item sent to any of
/// them runs.
fn queue_types() -> Result<(), &'static str> {
    RAN.store(0, Ordering::Release);
    for queue_type in 0..7u32 {
        // SAFETY: static storage for an item that is on no queue: the
        // one before has run.
        unsafe {
            let item = ITEM.ptr();
            (&raw mut (*item).WorkerRoutine).write(Some(count_run));
            (&raw mut (*item).Parameter).write(core::ptr::null_mut());
            (&raw mut (*item).List.Flink).write(core::ptr::null_mut());
            crate::ex::work::ExQueueWorkItem(item, queue_type);
        }
        if !ran(queue_type + 1) {
            return Err("a work item sent to one of Windows' queue types did not run");
        }
    }
    Ok(())
}

/// The routine of the driver-object work item.
///
/// # Safety
/// Called as an I/O work routine.
unsafe extern "C" fn io_routine(object: *mut DEVICE_OBJECT, _: *mut c_void) {
    GOT.store(object.cast(), Ordering::Release);
    RAN.fetch_add(1, Ordering::AcqRel);
}

/// An I/O work item may be allocated against a driver object instead
/// of a device; its routine is handed that object.
fn driver_object() -> Result<(), &'static str> {
    let size = size_of::<DRIVER_OBJECT>() + size_of::<DRIVER_EXTENSION>();
    let driver = pool::alloc_zeroed(size, u32::from_le_bytes(*b"Test")).cast::<DRIVER_OBJECT>();
    if driver.is_null() {
        return Err("no memory for a driver object");
    }
    RAN.store(0, Ordering::Release);
    // SAFETY: the test's own driver object, marked as one, which
    // outlives the item's run.
    let result = unsafe {
        (*driver).Type = nk_ntabi::io::IO_TYPE_DRIVER;
        let item = crate::ex::work::IoAllocateWorkItem(driver.cast());
        if item.is_null() {
            Err("no memory for a work item")
        } else {
            crate::ex::work::IoQueueWorkItem(item, Some(io_routine), 1, core::ptr::null_mut());
            let result = if !ran(1) {
                Err("a work item of a driver object did not run")
            } else if GOT.load(Ordering::Acquire) != driver.cast() {
                Err("the routine was not handed the driver object")
            } else {
                Ok(())
            };
            // The worker is out of the routine a moment after it counts.
            time::stall(2_000);
            crate::ex::work::IoFreeWorkItem(item);
            result
        }
    };
    let _ = pool::free(driver.cast());
    result
}

/// What a system thread's routine found: that it ran, and the handle
/// its creator was to be given.
static STARTED: AtomicU32 = AtomicU32::new(0);
static HANDLE: AtomicPtr<c_void> = AtomicPtr::new(core::ptr::null_mut());
static HANDLE_SEEN: AtomicPtr<c_void> = AtomicPtr::new(core::ptr::null_mut());

/// # Safety
/// Called as a system thread's start routine.
unsafe extern "C" fn note_start(_: *mut c_void) {
    HANDLE_SEEN.store(HANDLE.load(Ordering::Acquire), Ordering::Release);
    STARTED.fetch_add(1, Ordering::AcqRel);
}

/// `PsCreateSystemThread` reports failure only for a thread that never
/// runs: one that cannot be given its handle is not started, and
/// leaves nothing behind. One that can finds the handle already handed
/// to its creator when it starts, as on Windows, which readies the
/// thread last.
fn thread_without_handle() -> Result<(), &'static str> {
    const STATUS_INSUFFICIENT_RESOURCES: i32 = 0xC000_009Au32 as i32;
    let threads = thread::count();
    STARTED.store(0, Ordering::Release);
    // SAFETY: the routine takes any context.
    let status = unsafe {
        crate::ps::create_system_thread(note_start, core::ptr::null_mut(), |_| {
            STATUS_INSUFFICIENT_RESOURCES
        })
    };
    if status != STATUS_INSUFFICIENT_RESOURCES {
        return Err("a thread that got no handle was not reported as the failure it was");
    }
    // Long enough for a thread that was started to run.
    for _ in 0..100 {
        time::stall(1_000);
        thread::yield_now();
    }
    if STARTED.load(Ordering::Acquire) != 0 {
        return Err("PsCreateSystemThread failed, and the thread ran all the same");
    }
    if thread::count() != threads {
        return Err("a thread that was never started is still there");
    }

    HANDLE.store(core::ptr::null_mut(), Ordering::Release);
    HANDLE_SEEN.store(core::ptr::null_mut(), Ordering::Release);
    // SAFETY: `HANDLE` is room for a handle; the routine takes any
    // context.
    let status = unsafe {
        crate::ps::PsCreateSystemThread(
            HANDLE.as_ptr(),
            0x001F_FFFF,
            core::ptr::null_mut(),
            core::ptr::null_mut(),
            core::ptr::null_mut(),
            Some(note_start),
            core::ptr::null_mut(),
        )
    };
    if status != 0 {
        return Err("a system thread could not be created");
    }
    let handle = HANDLE.load(Ordering::Acquire);
    let deadline = time::interrupt_time() + 20_000_000;
    while STARTED.load(Ordering::Acquire) != 1 || thread::count() != threads {
        if time::interrupt_time() > deadline {
            crate::ps::ZwClose(handle);
            return Err("a system thread did not run and end");
        }
        thread::yield_now();
    }
    if crate::ps::ZwClose(handle) != 0 {
        return Err("the new thread's handle did not close");
    }
    if handle.is_null() || HANDLE_SEEN.load(Ordering::Acquire) != handle {
        return Err("a system thread ran before its creator had been given its handle");
    }
    Ok(())
}

fn run(r: &mut Report, _: &BootInfo) {
    r.check("ob.current-thread", current_thread);
    r.check("ps.thread.no-handle", thread_without_handle);
    match device_list() {
        Ok(n) => r.ok_with(
            "io.device-list",
            format_args!("devices created by two threads at once: {n}"),
        ),
        Err(why) => r.fail("io.device-list", format_args!("{why}")),
    }
    match open_delete() {
        Ok(n) => r.ok_with(
            "io.open-delete",
            format_args!("opens tried against a device being created and deleted: {n}"),
        ),
        Err(why) => r.fail("io.open-delete", format_args!("{why}")),
    }
    r.check("thread.wake-at-dispatch", wake_at_dispatch);
    r.check("work.driver-object", driver_object);
    r.check("work.queue-types", queue_types);
}
