//! Tests of the device queue of a driver with a `StartIo` routine:
//! `IoStartPacket`, `IoStartNextPacket`, `IoSetStartIoAttributes`, and
//! cancelling a request that waits in the queue.
//!
//! The driver is here, in Rust, written as Microsoft documents such a
//! driver: its dispatch routine queues each request, its `StartIo`
//! takes the cancel routine out under the cancel spin lock, and its DPC
//! completes the current request and starts the next.

use super::stack;
use crate::io::file::{self, Pending};
use crate::io::{device, irp, startio};
use crate::ke::{dpc, irql, kspin};
use crate::test::{Group, Report, Slot};
use alloc::vec::Vec;
use core::ffi::c_void;
use core::sync::atomic::{AtomicPtr, AtomicU32, AtomicUsize, Ordering};
use nk_bootinfo::BootInfo;
use nk_ntabi::io::*;
use nk_ntabi::ke::KDPC;
use nk_ntabi::status::*;

pub static GROUP: Group = Group {
    names: &[
        "io.start-io.queue",
        "io.start-io.cancel",
        "io.start-io.deferred",
    ],
    run,
    manual: false,
};

pub static GROUPS: &[&Group] = &[&GROUP];

const NAME: &str = "\\Device\\NkStartIo";

/// What a control code asks of the driver: its function number.
/// `StartIo` leaves the request current; the DPC completes it.
const HELD: u32 = 0x900;
/// `StartIo` completes the request and starts the next, from within
/// itself.
const INLINE: u32 = 0x901;
/// As `HELD`, queued by the key in the request's second input byte.
const KEYED: u32 = 0x902;

const fn code(function: u32) -> u32 {
    ctl_code(0x22, function, METHOD_BUFFERED, 0)
}

/// The requests `StartIo` was entered for, by the tag in each one's
/// first input byte, in order.
static STARTED: [AtomicU32; 16] = [const { AtomicU32::new(0) }; 16];
static STARTS: AtomicUsize = AtomicUsize::new(0);
/// How deep `StartIo` is entered within itself, and the deepest seen.
static DEPTH: AtomicU32 = AtomicU32::new(0);
static DEEPEST: AtomicU32 = AtomicU32::new(0);
/// Whether a request still had its cancel routine when `StartIo` was
/// entered for it (bit `n` for the `n`th start), and the IRQL `StartIo`
/// was entered at, if ever below `DISPATCH_LEVEL`.
static HAD_ROUTINE: AtomicU32 = AtomicU32::new(0);
static LOW_IRQL: AtomicU32 = AtomicU32::new(0);
/// Requests the cancel routine completed.
static CANCELLED: AtomicU32 = AtomicU32::new(0);
static DPC: Slot<KDPC> = Slot::new();
/// The driver's device, for its DPC.
static DEVICE: AtomicPtr<DEVICE_OBJECT> = AtomicPtr::new(core::ptr::null_mut());

fn started() -> Vec<u32> {
    let count = STARTS.load(Ordering::Acquire).min(STARTED.len());
    STARTED[..count]
        .iter()
        .map(|slot| slot.load(Ordering::Acquire))
        .collect()
}

fn reset() {
    STARTS.store(0, Ordering::Release);
    DEEPEST.store(0, Ordering::Release);
    HAD_ROUTINE.store(0, Ordering::Release);
    LOW_IRQL.store(0, Ordering::Release);
    CANCELLED.store(0, Ordering::Release);
}

/// # Safety
/// `request` is a request the driver holds and has not completed.
unsafe fn complete(request: *mut IRP, status: NTSTATUS) {
    // SAFETY: per the contract.
    unsafe {
        (*request).IoStatus.Status = status;
        (*request).IoStatus.Information = 0;
        irp::IofCompleteRequest(request, 0);
    }
}

/// The driver's `StartIo`.
///
/// # Safety
/// Called as a `StartIo` routine.
unsafe extern "C" fn start_io(device: *mut DEVICE_OBJECT, request: *mut IRP) {
    let depth = DEPTH.fetch_add(1, Ordering::AcqRel) + 1;
    DEEPEST.fetch_max(depth, Ordering::AcqRel);
    if irql::current() != irql::DISPATCH_LEVEL {
        LOW_IRQL.fetch_add(1, Ordering::AcqRel);
    }
    // SAFETY: a request the driver queued, now the device's current
    // one unless it was cancelled on the way here.
    unsafe {
        let mut old = 0;
        irp::IoAcquireCancelSpinLock(&raw mut old);
        if request != (*device).CurrentIrp {
            // Cancelled meanwhile: its cancel routine has it.
            irp::IoReleaseCancelSpinLock(old);
            DEPTH.fetch_sub(1, Ordering::AcqRel);
            return;
        }
        // `IoSetCancelRoutine(Irp, NULL)`.
        let routine = AtomicPtr::from_ptr(&raw mut (*request).CancelRoutine)
            .swap(core::ptr::null_mut(), Ordering::SeqCst);
        irp::IoReleaseCancelSpinLock(old);
        let at = STARTS.fetch_add(1, Ordering::AcqRel);
        if let Some(slot) = STARTED.get(at) {
            slot.store(
                u32::from((*request).SystemBuffer.cast::<u8>().read()),
                Ordering::Release,
            );
        }
        if !routine.is_null() {
            HAD_ROUTINE.fetch_or(1 << at, Ordering::AcqRel);
        }
        let parameters = (*(*request).CurrentStackLocation).Parameters;
        if parameters[2] as u32 == code(INLINE) {
            complete(request, STATUS_SUCCESS);
            startio::IoStartNextPacket(device, 1);
        }
    }
    DEPTH.fetch_sub(1, Ordering::AcqRel);
}

/// The driver's DPC: the device is done with its current request.
///
/// # Safety
/// Called as a DPC routine; it dereferences none of its arguments.
unsafe extern "C" fn finished(_: *mut KDPC, _: *mut c_void, _: *mut c_void, _: *mut c_void) {
    let device = DEVICE.load(Ordering::Acquire);
    // SAFETY: the driver's device, which outlives its DPC; the current
    // request is the driver's until it completes it.
    unsafe {
        let request = (*device).CurrentIrp;
        if !request.is_null() {
            complete(request, STATUS_SUCCESS);
        }
        startio::IoStartNextPacket(device, 1);
    }
}

/// The driver's cancel routine, for a request `IoStartPacket` queued.
///
/// # Safety
/// Called as a cancel routine, holding the cancel spin lock.
unsafe extern "C" fn cancel(device: *mut DEVICE_OBJECT, request: *mut IRP) {
    // SAFETY: per the contract. A request that is not the current one
    // waits in the device queue, under the queue's own lock.
    unsafe {
        if request == (*device).CurrentIrp {
            irp::IoReleaseCancelSpinLock((*request).CancelIrql);
            startio::IoStartNextPacket(device, 1);
        } else {
            // `KeRemoveEntryDeviceQueue`.
            let queue = &raw mut (*device).DeviceQueue;
            let entry = request
                .byte_add(IRP_DEVICE_QUEUE_ENTRY)
                .cast::<KDEVICE_QUEUE_ENTRY>();
            let old = kspin::KeAcquireSpinLockRaiseToDpc(&raw mut (*queue).Lock);
            if (*entry).Inserted != 0 {
                let link = &raw mut (*entry).DeviceListEntry;
                (*(*link).Blink).Flink = (*link).Flink;
                (*(*link).Flink).Blink = (*link).Blink;
                (*entry).Inserted = 0;
            }
            kspin::KeReleaseSpinLock(&raw mut (*queue).Lock, old);
            irp::IoReleaseCancelSpinLock((*request).CancelIrql);
        }
        CANCELLED.fetch_add(1, Ordering::AcqRel);
        complete(request, STATUS_CANCELLED);
    }
}

/// The driver's dispatch routine: a control request is queued, anything
/// else succeeds.
///
/// # Safety
/// Called as a dispatch routine.
unsafe extern "C" fn dispatch(device: *mut DEVICE_OBJECT, request: *mut IRP) -> NTSTATUS {
    // SAFETY: a live IRP being dispatched.
    unsafe {
        let location = (*request).CurrentStackLocation;
        if (*location).MajorFunction != IRP_MJ_DEVICE_CONTROL {
            complete(request, STATUS_SUCCESS);
            return STATUS_SUCCESS;
        }
        // `IoMarkIrpPending`.
        (*location).Control |= SL_PENDING_RETURNED;
        let key = u32::from((*request).SystemBuffer.cast::<u8>().add(1).read());
        let key = if (*location).Parameters[2] as u32 == code(KEYED) {
            &raw const key
        } else {
            core::ptr::null()
        };
        startio::IoStartPacket(device, request, key, Some(cancel));
    }
    STATUS_PENDING
}

/// The driver and its device, open.
struct Driver {
    object: *mut DRIVER_OBJECT,
    device: *mut DEVICE_OBJECT,
    opened: u64,
}

impl Driver {
    fn new() -> Result<Self, &'static str> {
        let object = stack::make_driver(dispatch)?;
        let made = stack::make_device(object, stack::PDO, Some(NAME));
        let device = match made {
            Ok(device) => device,
            Err(why) => {
                // SAFETY: the driver has no device.
                unsafe { stack::free_driver(object) };
                return Err(why);
            }
        };
        // SAFETY: the test's own driver object and DPC.
        unsafe {
            (*object).DriverStartIo = start_io as *mut c_void;
            dpc::KeInitializeDpc(DPC.ptr(), Some(finished), core::ptr::null_mut());
        }
        DEVICE.store(device, Ordering::Release);
        reset();
        let mut driver = Driver {
            object,
            device,
            opened: 0,
        };
        driver.opened = super::open(NAME).map_err(|_| "the device could not be opened")?;
        Ok(driver)
    }

    /// Send a request tagged `tag`, of `function`, with `key`, and do
    /// not wait for it.
    fn send(&self, function: u32, tag: u8, key: u8) -> Result<Pending, &'static str> {
        // SAFETY: a buffered request with no output: nothing of the
        // caller's is named after the call returns.
        unsafe { file::device_control_start(self.opened, code(function), &[tag, key], &mut []) }
            .map_err(|_| "a request could not be sent")
    }

    /// Have the driver's DPC complete the current request and start the
    /// next, and wait until it has.
    fn finish_current(&self) {
        // SAFETY: the driver's DPC, initialised.
        unsafe { dpc::KeInsertQueueDpc(DPC.ptr(), core::ptr::null_mut(), core::ptr::null_mut()) };
        // Until it has run: what it started is then there to be seen.
        dpc::flush();
    }

    /// Whether the device is busy, and with which request.
    fn busy(&self) -> (bool, *mut IRP) {
        // SAFETY: the driver's live device.
        unsafe {
            (
                (&raw const (*self.device).DeviceQueue.Busy)
                    .cast::<u8>()
                    .read_volatile()
                    != 0,
                (&raw const (*self.device).CurrentIrp).read_volatile(),
            )
        }
    }
}

impl Drop for Driver {
    fn drop(&mut self) {
        if self.opened != 0 {
            file::close(self.opened);
        }
        // SAFETY: the driver's device, with no request left, and then
        // the driver object.
        unsafe {
            device::IoDeleteDevice(self.device);
            stack::free_driver(self.object);
        }
    }
}

/// Wait for a request and say what it completed with.
fn status_of(pending: Pending) -> Result<NTSTATUS, &'static str> {
    pending
        .wait()
        .map(|result| result.status)
        .map_err(|_| "a queued request did not complete as a pended request does")
}

/// The first request starts at once, at `DISPATCH_LEVEL`; the others
/// wait while the device is busy and start one by one as the driver
/// asks for the next, in the order they came, or in the order of their
/// keys; with none left the device is idle. Returns the starts checked.
fn queue() -> Result<u32, &'static str> {
    let driver = Driver::new()?;
    let first = driver.send(HELD, 1, 0)?;
    if started() != [1] || !driver.busy().0 || driver.busy().1.is_null() {
        return Err("the first request was not started at once");
    }
    let second = driver.send(HELD, 2, 0)?;
    let third = driver.send(HELD, 3, 0)?;
    if started() != [1] {
        return Err("a request was started while the device was busy");
    }
    for (pending, then) in [
        (first, &[1, 2][..]),
        (second, &[1, 2, 3]),
        (third, &[1, 2, 3]),
    ] {
        driver.finish_current();
        if status_of(pending)? != STATUS_SUCCESS {
            return Err("a queued request did not succeed");
        }
        if started() != then {
            return Err("the queued requests were not started one by one, in order");
        }
    }
    // The device is idle when the last request has been completed and
    // the next asked for.
    if driver.busy() != (false, core::ptr::null_mut()) {
        return Err("the device is still busy with nothing queued");
    }
    if LOW_IRQL.load(Ordering::Acquire) != 0 {
        return Err("StartIo was entered below DISPATCH_LEVEL");
    }
    // By key: the lowest first, whatever order they came in.
    reset();
    let current = driver.send(HELD, 9, 0)?;
    let waiting = [
        driver.send(KEYED, 30, 30)?,
        driver.send(KEYED, 10, 10)?,
        driver.send(KEYED, 20, 20)?,
        driver.send(KEYED, 11, 10)?,
    ];
    driver.finish_current();
    if status_of(current)? != STATUS_SUCCESS {
        return Err("a queued request did not succeed");
    }
    for _ in 0..waiting.len() {
        driver.finish_current();
    }
    for pending in waiting {
        if status_of(pending)? != STATUS_SUCCESS {
            return Err("a request queued by key did not succeed");
        }
    }
    if started() != [9, 10, 11, 20, 30] {
        return Err("requests queued by key were not started in the order of their keys");
    }
    if LOW_IRQL.load(Ordering::Acquire) != 0 {
        return Err("StartIo was entered below DISPATCH_LEVEL");
    }
    if HAD_ROUTINE.load(Ordering::Acquire) != 0b1_1111 {
        return Err("a started request had lost its cancel routine");
    }
    Ok(8)
}

/// A request cancelled while it waits is taken out of the queue by the
/// driver's cancel routine and never started; the current request, its
/// routine taken out by `StartIo`, is past cancelling; a request that
/// is already cancelled when it is queued has the routine called at
/// once. Returns the facts checked.
fn cancel_test() -> Result<u32, &'static str> {
    let driver = Driver::new()?;
    let current = driver.send(HELD, 1, 0)?;
    let second = driver.send(HELD, 2, 0)?;
    let third = driver.send(HELD, 3, 0)?;
    if !third.cancel() {
        return Err("a waiting request had no cancel routine");
    }
    if status_of(third)? != STATUS_CANCELLED || CANCELLED.load(Ordering::Acquire) != 1 {
        return Err("a waiting request was not completed as cancelled by its cancel routine");
    }
    if current.cancel() {
        return Err("the current request still had a cancel routine");
    }
    // Cancelled before it is queued: the I/O manager calls the routine
    // itself. The test's own IRP, sent as a driver above would send it.
    let (mut event, mut block) = (
        // SAFETY: an all-zero event is a valid value, initialised below.
        unsafe { core::mem::zeroed::<KEVENT>() },
        IO_STATUS_BLOCK {
            Status: STATUS_PENDING,
            Information: 0,
        },
    );
    let mut input = [4u8, 0];
    // SAFETY: the event, the status block and the buffer outlive the
    // request, which is waited for here.
    let early = unsafe {
        crate::ke::wait::KeInitializeEvent(&raw mut event, 0, 0);
        let request = crate::io::build::IoBuildDeviceIoControlRequest(
            code(HELD),
            driver.device,
            input.as_mut_ptr().cast(),
            2,
            core::ptr::null_mut(),
            0,
            0,
            &raw mut event,
            &raw mut block,
        );
        if request.is_null() {
            return Err("a control request could not be built");
        }
        (*request).Cancel = 1;
        let returned = irp::IofCallDriver(driver.device, request);
        crate::ke::wait::wait(Some((&raw mut event).cast()), None);
        (returned, (&raw const block).read_volatile().Status)
    };
    if early != (STATUS_PENDING, STATUS_CANCELLED) || CANCELLED.load(Ordering::Acquire) != 2 {
        return Err("a request cancelled before it was queued did not have its routine called");
    }
    if irql::current() != irql::PASSIVE_LEVEL {
        return Err("IoStartPacket did not give back the IRQL it raised");
    }
    // The queue goes on without the cancelled requests.
    driver.finish_current();
    if status_of(current)? != STATUS_SUCCESS {
        return Err("the current request did not complete");
    }
    driver.finish_current();
    if status_of(second)? != STATUS_SUCCESS || started() != [1, 2] {
        return Err("a cancelled request was started, or the one behind it was not");
    }
    driver.finish_current();
    if driver.busy() != (false, core::ptr::null_mut()) {
        return Err("the device is still busy with nothing queued");
    }
    Ok(7)
}

/// Send one held request and three that `StartIo` completes and
/// follows with `IoStartNextPacket` from within itself; finish the
/// first; return how deep `StartIo` was entered within itself.
fn nested(driver: &Driver) -> Result<u32, &'static str> {
    reset();
    let first = driver.send(HELD, 1, 0)?;
    let rest = [
        driver.send(INLINE, 2, 0)?,
        driver.send(INLINE, 3, 0)?,
        driver.send(INLINE, 4, 0)?,
    ];
    driver.finish_current();
    if status_of(first)? != STATUS_SUCCESS {
        return Err("the held request did not complete");
    }
    for pending in rest {
        if status_of(pending)? != STATUS_SUCCESS {
            return Err("a request completed from StartIo did not succeed");
        }
    }
    if started() != [1, 2, 3, 4] || driver.busy() != (false, core::ptr::null_mut()) {
        return Err("the queue was not worked off in order");
    }
    Ok(DEEPEST.load(Ordering::Acquire))
}

/// Without deferred start, `IoStartNextPacket` called from `StartIo`
/// enters `StartIo` again, one level deeper for each waiting request;
/// with it, `StartIo` returns first. A driver whose requests are not
/// cancellable once started finds their cancel routines already taken
/// out. Returns the facts checked.
fn deferred() -> Result<u32, &'static str> {
    {
        let driver = Driver::new()?;
        if nested(&driver)? != 3 {
            return Err("StartIo was not entered from within itself without deferred start");
        }
        if HAD_ROUTINE.load(Ordering::Acquire) != 0b1111 {
            return Err("a started request had lost its cancel routine");
        }
    }
    let driver = Driver::new()?;
    // SAFETY: the driver's live device.
    unsafe {
        startio::IoSetStartIoAttributes(driver.device, 1, 1);
        let flags = (*(*driver.device).DeviceObjectExtension).StartIoFlags;
        if flags != DOE_SIO_DEFERRED | DOE_SIO_NO_CANCEL {
            return Err("the start attributes are not in the extension's StartIoFlags");
        }
    }
    if nested(&driver)? != 1 {
        return Err("with deferred start, StartIo was entered from within itself");
    }
    if HAD_ROUTINE.load(Ordering::Acquire) != 0 {
        return Err("a request not cancellable once started still had its cancel routine");
    }
    // SAFETY: the driver's live device.
    unsafe {
        let extension = (*driver.device).DeviceObjectExtension;
        if (*extension).StartIoCount != 0
            || (*extension).StartIoFlags != DOE_SIO_DEFERRED | DOE_SIO_NO_CANCEL
        {
            return Err("deferred start left word of a call that was carried out");
        }
    }
    Ok(6)
}

fn run(report: &mut Report, _: &BootInfo) {
    let mut numbered = |name: &str, result: Result<u32, &'static str>| match result {
        Ok(n) => report.ok_with(name, format_args!("{n} checked")),
        Err(why) => report.fail(name, format_args!("{why}")),
    };
    numbered("io.start-io.queue", queue());
    numbered("io.start-io.cancel", cancel_test());
    numbered("io.start-io.deferred", deferred());
}
