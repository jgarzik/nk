//! Tests for faults found by reading the code rather than by running
//! it: each failed before its fix.

use crate::io::device::{IoCreateDevice, IoDeleteDevice};
use crate::io::mdl::{IoAllocateMdl, IoFreeMdl, MmUnlockPages};
use crate::ke::seh::STATUS_ACCESS_VIOLATION;
use crate::ke::{irql, smp, thread, time, wait};
use crate::mm::pool;
use crate::ob::handle::{self, ObReferenceObjectByHandle};
use crate::ob::object::{ExEventObjectType, ObfDereferenceObject, PsThreadType};
use crate::test::{Group, Report, Slot};
use core::ffi::c_void;
use core::sync::atomic::{AtomicBool, AtomicPtr, AtomicU32, AtomicU64, Ordering};
use nk_bootinfo::BootInfo;
use nk_ntabi::io::{
    DEVICE_OBJECT, DRIVER_EXTENSION, DRIVER_OBJECT, IO_MODIFY_ACCESS, IO_READ_ACCESS,
    IO_WRITE_ACCESS, KERNEL_MODE, MDL, MDL_PAGES_LOCKED,
};
use nk_ntabi::ke::KEVENT;

pub static GROUP: Group = Group {
    names: &[
        "ob.current-thread",
        "io.device-list",
        "io.device-vpb",
        "io.mdl.fixed-size",
        "io.open-delete",
        "thread.wake-at-dispatch",
        "work.queue-types",
        "work.driver-object",
        "ps.thread.no-handle",
        "ob.handle.open-close-race",
        "mm.probe-and-lock.read-only",
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

/// A disk device is created with a volume parameter block, as Windows
/// makes it (zeroed but for its type, its size and its device), which
/// `disk.sys` writes to; a device of a type nothing mounts on has
/// none. The block goes with its device.
fn device_vpb() -> Result<(), &'static str> {
    use nk_ntabi::io::{IO_TYPE_VPB, VPB};
    const FILE_DEVICE_DISK: u32 = 0x07;
    const FILE_DEVICE_UNKNOWN: u32 = 0x22;
    let size = size_of::<DRIVER_OBJECT>() + size_of::<DRIVER_EXTENSION>();
    let driver = pool::alloc_zeroed(size, u32::from_le_bytes(*b"Test")).cast::<DRIVER_OBJECT>();
    if driver.is_null() {
        return Err("no memory for a driver object");
    }
    let before = pool::usage().blocks;
    let mut verdict = Ok(());
    for (kind, expected) in [(FILE_DEVICE_DISK, true), (FILE_DEVICE_UNKNOWN, false)] {
        let mut device: *mut DEVICE_OBJECT = core::ptr::null_mut();
        // SAFETY: the test's driver object; the device made is read
        // and deleted here.
        unsafe {
            if IoCreateDevice(driver, 0, core::ptr::null(), kind, 0, 0, &raw mut device) != 0 {
                verdict = Err("a device could not be created");
                break;
            }
            let vpb = (*device).Vpb.cast::<VPB>();
            if vpb.is_null() == expected {
                verdict = Err("only a device a file system mounts on has a parameter block");
            } else if expected
                && ((*vpb).Type != IO_TYPE_VPB
                    || (*vpb).Size != 0x60
                    || (*vpb).RealDevice != device
                    || !(*vpb).DeviceObject.is_null()
                    || (*vpb).Flags != 0
                    || (*vpb).ReferenceCount != 0)
            {
                verdict = Err("the parameter block is not as Windows makes it");
            }
            IoDeleteDevice(device);
        }
    }
    if verdict.is_ok() && pool::usage().blocks != before {
        verdict = Err("a deleted device left its parameter block behind");
    }
    let _ = pool::free(driver.cast());
    verdict
}

/// An MDL for a small buffer has room for seventeen pages, whatever
/// the buffer it was allocated for: Windows takes such an MDL from a
/// list of blocks of one size and marks it `MDL_ALLOCATED_FIXED_SIZE`,
/// and Storport describes a longer buffer with an MDL it allocated for
/// a shorter one (`MmInitializeMdl` again, then
/// `MmBuildMdlForNonPagedPool`). Returns the pages described.
fn mdl_fixed_size() -> Result<usize, &'static str> {
    use crate::io::mdl::MmBuildMdlForNonPagedPool;
    use nk_ntabi::io::MDL_ALLOCATED_FIXED_SIZE;
    const PAGE: usize = crate::mm::PAGE_SIZE;
    const PAGES: usize = 17;
    let buffer = pool::alloc_zeroed(PAGES * PAGE, u32::from_le_bytes(*b"Test"));
    if buffer.is_null() {
        return Err("no memory for a buffer");
    }
    // SAFETY: the buffer just made; the MDL is the test's, and is
    // initialised again as the header's `MmInitializeMdl` does it.
    let verdict = unsafe {
        let mdl = IoAllocateMdl(buffer.cast(), 16, 0, 0, core::ptr::null_mut());
        if mdl.is_null() {
            Err("no memory for an MDL")
        } else {
            let verdict = if (*mdl).Size != 0x38 {
                Err("an MDL of one page does not state the size of one page")
            } else if (*mdl).MdlFlags & MDL_ALLOCATED_FIXED_SIZE == 0 {
                Err("a small MDL is not marked as one of the fixed size")
            } else {
                let start = buffer as usize;
                let length = PAGES * PAGE - (start & (PAGE - 1));
                let pages = nk_ntabi::io::span_pages(start, length);
                (*mdl).Next = core::ptr::null_mut();
                (*mdl).Size = (size_of::<MDL>() + pages * 8) as i16;
                (*mdl).MdlFlags = 0;
                (*mdl).StartVa = (start & !(PAGE - 1)) as *mut c_void;
                (*mdl).ByteOffset = (start & (PAGE - 1)) as u32;
                (*mdl).ByteCount = length as u32;
                MmBuildMdlForNonPagedPool(mdl);
                Ok(pages)
            };
            // An MDL too short for what was written to it stops the
            // system here.
            IoFreeMdl(mdl);
            verdict
        }
    };
    let _ = pool::free(buffer);
    verdict
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
    // The thread runs and ends, however long that takes.
    while STARTED.load(Ordering::Acquire) != 1 || thread::count() != threads {
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

/// The handle the opener keeps getting, for the closer to close, and
/// how often the closer got there first.
static GUESSED: AtomicU64 = AtomicU64::new(0);
static STOLEN: AtomicU32 = AtomicU32::new(0);

fn close_guessed(_: usize) {
    while !GO.load(Ordering::Acquire) {
        thread::yield_now();
    }
    while GO.load(Ordering::Acquire) {
        if handle::close(GUESSED.load(Ordering::Relaxed)) == 0 {
            STOLEN.fetch_add(1, Ordering::AcqRel);
        }
    }
    FINISHED.fetch_add(1, Ordering::AcqRel);
}

/// Handle numbers are predictable: the lowest free slot is used first.
/// So a handle can be closed, from another processor, the instant it
/// is in the table, before its opener has returned. It owns its
/// reference and its place in the object's handle count by then: the
/// close gives up what the handle had, never what it was about to get.
/// The object here has one reference besides the handle's, so a close
/// that came too early would free it under its opener. Returns the
/// handles opened and how many of them the other processor closed.
fn open_close_race() -> Result<(u32, u32), &'static str> {
    let threads = thread::count();
    let (pool_before, handles_before) = (pool::usage().blocks, handle::count());
    GO.store(false, Ordering::Release);
    FINISHED.store(0, Ordering::Release);
    STOLEN.store(0, Ordering::Release);
    GUESSED.store(0, Ordering::Release);
    thread::create(
        close_guessed,
        0,
        thread::NORMAL_PRIORITY,
        1 << other_processor(),
    )?;
    let mut opened = 0;
    let mut wrong = None;
    let deadline = time::interrupt_time() + RACE_TIME;
    while time::interrupt_time() < deadline && wrong.is_none() {
        // A few hundred opens between looks at the clock.
        for _ in 0..256 {
            let Some(body) =
                crate::ob::object::create(&crate::ob::object::EVENT_TYPE, size_of::<KEVENT>())
            else {
                wrong = Some("no memory for an object");
                break;
            };
            // SAFETY: a fresh object this test holds the reference to,
            // which it gives up last.
            unsafe {
                let stolen = STOLEN.load(Ordering::Acquire);
                let Ok(opened_as) = handle::open(body, 0) else {
                    crate::ob::object::dereference(body);
                    wrong = Some("no memory for a handle");
                    break;
                };
                opened += 1;
                GUESSED.store(opened_as, Ordering::Relaxed);
                GO.store(true, Ordering::Release);
                if handle::close(opened_as) != 0 {
                    // The closer has it: wait until it is done with it.
                    while STOLEN.load(Ordering::Acquire) == stolen {
                        core::hint::spin_loop();
                    }
                }
                if crate::ob::object::handle_count(body).load(Ordering::Acquire) != 0 {
                    wrong = Some("an object's handle count is not zero with its handle closed");
                }
                if crate::ob::object::dereference(body) != 0 {
                    wrong = Some("an object outlived its handle and its creator's reference");
                }
            }
        }
    }
    GO.store(true, Ordering::Release);
    GO.store(false, Ordering::Release);
    while FINISHED.load(Ordering::Acquire) != 1 || thread::count() != threads {
        thread::yield_now();
    }
    if let Some(wrong) = wrong {
        return Err(wrong);
    }
    if handle::count() != handles_before || pool::usage().blocks != pool_before {
        return Err("handles closed from two processors left a handle or an object behind");
    }
    Ok((opened, STOLEN.load(Ordering::Acquire)))
}

/// How long the race is run: 300 ms.
const RACE_TIME: u64 = 3_000_000;

/// The MDL [`probe_for`] probes.
static PROBED: AtomicPtr<MDL> = AtomicPtr::new(core::ptr::null_mut());

/// `MmProbeAndLockPages(Mdl, KernelMode, operation)`, as a driver calls
/// it.
extern "C" fn probe_for(operation: usize) {
    // SAFETY: the test's MDL, whose pages are not locked.
    unsafe {
        crate::arch::seh::nk_entry_MmProbeAndLockPages(
            PROBED.load(Ordering::Acquire).cast(),
            KERNEL_MODE,
            operation as u32,
        );
    }
}

/// `MmProbeAndLockPages` looks at the operation its caller means to
/// do: pages that cannot be written are locked for `IoReadAccess` and
/// refused for `IoWriteAccess` and `IoModifyAccess` with the access
/// violation Windows raises. Pages that can be written are locked for
/// all three. Returns the probes made.
fn read_only_probe() -> Result<u32, &'static str> {
    use crate::mm::{self, map};
    use nk_mm::pt::Prot;
    let frame = mm::alloc_frames(1).ok_or("no frames")?;
    let Some(va) = map::alloc_va(1) else {
        mm::free_frames(frame, 1);
        return Err("no address space");
    };
    let mut probes = 0;
    let mut check = |prot: Prot, writable: bool| -> Result<(), &'static str> {
        map::map(va, frame, 1, prot).map_err(|_| "map failed")?;
        // SAFETY: a page mapped just above, and the MDL made for it
        // here, which is unlocked before it is freed.
        let verdict = unsafe {
            let mdl = IoAllocateMdl((va + 0x10) as *mut c_void, 32, 0, 0, core::ptr::null_mut());
            if mdl.is_null() {
                Err("no memory for an MDL")
            } else {
                PROBED.store(mdl, Ordering::Release);
                let mut verdict = Ok(());
                for operation in [IO_READ_ACCESS, IO_WRITE_ACCESS, IO_MODIFY_ACCESS] {
                    let raised = super::except::raises(
                        probe_for,
                        operation as usize,
                        STATUS_ACCESS_VIOLATION,
                    )
                    .is_ok();
                    let locked = (*mdl).MdlFlags & MDL_PAGES_LOCKED != 0;
                    if locked {
                        MmUnlockPages(mdl);
                    }
                    probes += 1;
                    let allowed = writable || operation == IO_READ_ACCESS;
                    if raised == allowed || locked != allowed {
                        verdict = Err(if allowed {
                            "pages were not locked for an access their mapping allows"
                        } else {
                            "read-only pages were locked for writing"
                        });
                    }
                }
                IoFreeMdl(mdl);
                verdict
            }
        };
        map::unmap(va, 1);
        verdict
    };
    let verdict = check(Prot::RO, false).and_then(|()| check(Prot::RW, true));
    map::free_va(va, 1);
    mm::free_frames(frame, 1);
    verdict.map(|()| probes)
}

fn run(r: &mut Report, _: &BootInfo) {
    r.check("ob.current-thread", current_thread);
    match read_only_probe() {
        Ok(n) => r.ok_with("mm.probe-and-lock.read-only", format_args!("probes: {n}")),
        Err(why) => r.fail("mm.probe-and-lock.read-only", format_args!("{why}")),
    }
    match open_close_race() {
        Ok((opened, stolen)) => r.ok_with(
            "ob.handle.open-close-race",
            format_args!("handles opened: {opened}, closed by the other processor: {stolen}"),
        ),
        Err(why) => r.fail("ob.handle.open-close-race", format_args!("{why}")),
    }
    r.check("ps.thread.no-handle", thread_without_handle);
    match device_list() {
        Ok(n) => r.ok_with(
            "io.device-list",
            format_args!("devices created by two threads at once: {n}"),
        ),
        Err(why) => r.fail("io.device-list", format_args!("{why}")),
    }
    r.check("io.device-vpb", device_vpb);
    match mdl_fixed_size() {
        Ok(n) => r.ok_with("io.mdl.fixed-size", format_args!("pages described: {n}")),
        Err(why) => r.fail("io.mdl.fixed-size", format_args!("{why}")),
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

/// This file's test groups, in the order they run.
pub static GROUPS: &[&Group] = &[&GROUP];
