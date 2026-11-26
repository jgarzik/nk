//! Tests of requests a driver does not complete at once: pended and
//! completed later from a DPC, a timer or a worker thread, and
//! cancelled.
//!
//! The driver is here, in Rust, written the way a WDM driver in C is
//! (the in-line macros spelled out), because what is under test is the
//! I/O manager's side. Conformance drivers built with the WDK cover the
//! same ground from the outside once they are listed.

use crate::ex::work;
use crate::io::file::{self, IoResult};
use crate::io::{device, irp};
use crate::ke::{dpc, time, timer, wait};
use crate::mm::pool;
use crate::test::{Group, Report, Slot};
use core::ffi::c_void;
use core::fmt::Display;
use core::sync::atomic::{AtomicPtr, AtomicU32, Ordering};
use nk_bootinfo::BootInfo;
use nk_ntabi::ex::WORK_QUEUE_ITEM;
use nk_ntabi::io::*;
use nk_ntabi::ke::{KDPC, KTIMER};
use nk_ntabi::status::*;

pub static GROUP: Group = Group {
    names: &[
        "io.pend-dpc",
        "io.pend-timer",
        "io.pend-work",
        "io.pend-inline",
        "io.cancel",
        "io.cancel-race",
    ],
    run,
    manual: false,
};

/// How the driver is asked to complete a request: the control code's
/// function number.
const BY_DPC: u32 = 0x900;
const BY_TIMER: u32 = 0x901;
const BY_WORKER: u32 = 0x902;
/// Marked pending, completed before the dispatch routine returns.
const BEFORE_RETURN: u32 = 0x903;
/// Held until cancelled.
const HOLD: u32 = 0x904;
/// Held, cancellable, and completed by a timer if not cancelled first.
/// The delay in milliseconds is the first input byte.
const HOLD_OR_TIMER: u32 = 0x905;
/// Completed at once, claiming to have returned as many bytes as the
/// input held, whatever room the requestor has for output.
const OVERSTATE: u32 = 0x906;

const fn code(function: u32) -> u32 {
    ctl_code(0x22, function, METHOD_BUFFERED, 0)
}

const STATUS_CANCELLED: NTSTATUS = 0xC000_0120u32 as NTSTATUS;
/// What a completed request carries back.
const ANSWER: [u8; 4] = *b"done";

/// The one request the driver holds.
static HELD: AtomicPtr<IRP> = AtomicPtr::new(core::ptr::null_mut());
static DPC: Slot<KDPC> = Slot::new();
static TIMER: Slot<KTIMER> = Slot::new();
static WORK: Slot<WORK_QUEUE_ITEM> = Slot::new();
/// Requests the driver completed, and how many of them as cancelled.
static COMPLETED: AtomicU32 = AtomicU32::new(0);
static CANCELLED: AtomicU32 = AtomicU32::new(0);

/// Complete `irp` with `status`, and the answer if it succeeded.
///
/// # Safety
/// The driver owns `irp` and has not completed it.
unsafe fn complete(irp: *mut IRP, status: NTSTATUS) {
    // SAFETY: per the contract; a buffered request's system buffer is
    // at least as long as the output the requestor asked for.
    unsafe {
        let wanted = (*(*irp).CurrentStackLocation).Parameters[0] as usize;
        let n = if status == STATUS_SUCCESS {
            wanted.min(ANSWER.len())
        } else {
            0
        };
        core::ptr::copy_nonoverlapping(ANSWER.as_ptr(), (*irp).SystemBuffer.cast::<u8>(), n);
        (*irp).IoStatus.Status = status;
        (*irp).IoStatus.Information = n;
        COMPLETED.fetch_add(1, Ordering::AcqRel);
        if status == STATUS_CANCELLED {
            CANCELLED.fetch_add(1, Ordering::AcqRel);
        }
        irp::IofCompleteRequest(irp, 0);
    }
}

/// Complete the held request, unless its cancel routine has it.
fn complete_held() {
    let irp = HELD.swap(core::ptr::null_mut(), Ordering::AcqRel);
    if irp.is_null() {
        return;
    }
    // SAFETY: the driver put `irp` in `HELD` and has not completed it.
    // `IoSetCancelRoutine(Irp, NULL)`: whoever takes the routine out
    // completes the request; if it is gone, the cancel routine will.
    unsafe {
        let had = AtomicPtr::from_ptr(&raw mut (*irp).CancelRoutine);
        let cancellable =
            (*(*irp).CurrentStackLocation).Parameters[2] as u32 == code(HOLD_OR_TIMER);
        if cancellable && had.swap(core::ptr::null_mut(), Ordering::AcqRel).is_null() {
            return;
        }
        complete(irp, STATUS_SUCCESS);
    }
}

/// # Safety
/// Called as a DPC routine; it dereferences none of its arguments.
unsafe extern "C" fn dpc_routine(_: *mut KDPC, _: *mut c_void, _: *mut c_void, _: *mut c_void) {
    complete_held();
}

/// # Safety
/// Called as a work routine.
unsafe extern "C" fn work_routine(_: *mut c_void) {
    complete_held();
}

/// The driver's cancel routine.
///
/// # Safety
/// Called by `IoCancelIrp` with the cancel spin lock held.
unsafe extern "C" fn cancel_routine(_: *mut DEVICE_OBJECT, irp: *mut IRP) {
    // SAFETY: per the contract. The lock goes first, at the level the
    // canceller came from; then the request is this routine's.
    unsafe {
        irp::IoReleaseCancelSpinLock((*irp).CancelIrql);
        // If the timer's DPC has not taken the request yet, it is not
        // to: this routine owns it now.
        let _ = HELD.compare_exchange(
            irp,
            core::ptr::null_mut(),
            Ordering::AcqRel,
            Ordering::Acquire,
        );
        complete(irp, STATUS_CANCELLED);
    }
}

/// # Safety
/// Called as a dispatch routine.
unsafe extern "C" fn create_close(_: *mut DEVICE_OBJECT, irp: *mut IRP) -> NTSTATUS {
    // SAFETY: a live IRP being dispatched.
    unsafe {
        (*irp).IoStatus.Status = STATUS_SUCCESS;
        (*irp).IoStatus.Information = 0;
        irp::IofCompleteRequest(irp, 0);
    }
    STATUS_SUCCESS
}

/// # Safety
/// Called as a dispatch routine.
unsafe extern "C" fn control(_: *mut DEVICE_OBJECT, irp: *mut IRP) -> NTSTATUS {
    // SAFETY: a live IRP being dispatched; the statics are the driver's.
    unsafe {
        let location = (*irp).CurrentStackLocation;
        let how = (*location).Parameters[2] as u32;
        let delay = if (*location).Parameters[1] != 0 {
            i64::from((*irp).SystemBuffer.cast::<u8>().read())
        } else {
            20
        };
        // `IoMarkIrpPending`.
        (*location).Control |= SL_PENDING_RETURNED;
        if how == code(BEFORE_RETURN) {
            complete(irp, STATUS_SUCCESS);
            return STATUS_PENDING;
        }
        if how == code(OVERSTATE) {
            (*irp).IoStatus.Status = STATUS_SUCCESS;
            (*irp).IoStatus.Information = (*location).Parameters[1] as usize;
            irp::IofCompleteRequest(irp, 0);
            return STATUS_PENDING;
        }
        if how == code(HOLD) || how == code(HOLD_OR_TIMER) {
            // `IoSetCancelRoutine`, then look whether it was cancelled
            // before there was a routine to call.
            AtomicPtr::from_ptr(&raw mut (*irp).CancelRoutine)
                .store(cancel_routine as *mut c_void, Ordering::Release);
        }
        HELD.store(irp, Ordering::Release);
        if how == code(BY_DPC) {
            dpc::KeInsertQueueDpc(DPC.ptr(), core::ptr::null_mut(), core::ptr::null_mut());
        } else if how == code(BY_TIMER) || how == code(HOLD_OR_TIMER) {
            timer::KeSetTimer(TIMER.ptr(), -delay * 10_000, DPC.ptr());
        } else if how == code(BY_WORKER) {
            (&raw mut (*WORK.ptr()).List.Flink).write(core::ptr::null_mut());
            (&raw mut (*WORK.ptr()).WorkerRoutine).write(Some(work_routine));
            work::ExQueueWorkItem(WORK.ptr(), 1);
        } else if how != code(HOLD) {
            HELD.store(core::ptr::null_mut(), Ordering::Release);
            (*location).Control &= !SL_PENDING_RETURNED;
            (*irp).IoStatus.Status = STATUS_INVALID_DEVICE_REQUEST;
            irp::IofCompleteRequest(irp, 0);
            return STATUS_INVALID_DEVICE_REQUEST;
        }
        STATUS_PENDING
    }
}

/// Make the driver and its device, run `test` with the device open, and
/// take everything down again.
fn with_driver(test: impl FnOnce(u64) -> Result<u32, &'static str>) -> Result<u32, &'static str> {
    let size = size_of::<DRIVER_OBJECT>() + size_of::<DRIVER_EXTENSION>();
    let driver = pool::alloc_zeroed(size, u32::from_le_bytes(*b"Test")).cast::<DRIVER_OBJECT>();
    if driver.is_null() {
        return Err("no memory for a driver object");
    }
    let mut name: alloc::vec::Vec<u16> = "\\Device\\NkPend".encode_utf16().collect();
    let name = UNICODE_STRING {
        Length: (name.len() * 2) as u16,
        MaximumLength: (name.len() * 2) as u16,
        Buffer: name.as_mut_ptr(),
    };
    let mut device_object = core::ptr::null_mut();
    // SAFETY: the test's own driver object, set up as `driver::load`
    // sets one up; static storage for the driver's DPC and timer.
    let result = unsafe {
        (*driver).MajorFunction = [Some(irp::invalid_device_request); IRP_MJ_MAXIMUM_FUNCTION + 1];
        (*driver).MajorFunction[usize::from(IRP_MJ_CREATE)] = Some(create_close);
        (*driver).MajorFunction[usize::from(IRP_MJ_CLOSE)] = Some(create_close);
        (*driver).MajorFunction[usize::from(IRP_MJ_CLEANUP)] = Some(create_close);
        (*driver).MajorFunction[usize::from(IRP_MJ_DEVICE_CONTROL)] = Some(control);
        dpc::KeInitializeDpc(DPC.ptr(), Some(dpc_routine), core::ptr::null_mut());
        timer::KeInitializeTimer(TIMER.ptr());
        if device::IoCreateDevice(
            driver,
            0,
            &raw const name,
            0x22,
            0,
            0,
            &raw mut device_object,
        ) != 0
        {
            let _ = pool::free(driver.cast());
            return Err("could not create the test device");
        }
        (*device_object).Flags &= !DO_DEVICE_INITIALIZING;
        let result = match super::open("\\Device\\NkPend") {
            Ok(opened) => {
                let result = test(opened);
                match file::close(opened) {
                    STATUS_SUCCESS => result,
                    _ => result.and(Err("closing the test device failed")),
                }
            }
            Err(_) => Err("could not open the test device"),
        };
        device::IoDeleteDevice(device_object);
        result
    };
    let _ = pool::free(driver.cast());
    result
}

/// Send one request and wait for it.
fn request(opened: u64, how: u32) -> Result<(IoResult, [u8; 4]), &'static str> {
    let mut output = [0u8; 4];
    let result = file::device_control(opened, code(how), &[], &mut output)
        .map_err(|_| "the request was not carried out")?;
    Ok((result, output))
}

/// A request pended and completed later, by `how`, comes back whole.
fn pended(opened: u64, how: u32, least: u64) -> Result<u32, &'static str> {
    const ROUNDS: u32 = 20;
    for _ in 0..ROUNDS {
        let before = time::interrupt_time();
        let (result, output) = request(opened, how)?;
        if result.status != STATUS_SUCCESS || result.information != 4 || output != ANSWER {
            return Err("a pended request did not come back with its status and data");
        }
        if time::interrupt_time() - before < least {
            return Err("the requestor did not wait for the request to complete");
        }
    }
    Ok(ROUNDS)
}

/// A held request is cancelled: it completes as cancelled, once, and
/// cancelling again finds nothing to cancel.
fn cancel(opened: u64) -> Result<u32, &'static str> {
    let cancelled = CANCELLED.load(Ordering::Acquire);
    let mut output = [0u8; 4];
    // SAFETY: the output outlives the request, which is waited for
    // below.
    let pending = unsafe { file::device_control_start(opened, code(HOLD), &[], &mut output) }
        .map_err(|_| "the request could not be sent")?;
    // SAFETY: no object is involved.
    unsafe { wait::wait(None, Some(-200_000)) };
    if HELD.load(Ordering::Acquire).is_null() {
        return Err("the driver is not holding the request");
    }
    if !pending.cancel() || pending.cancel() {
        return Err("a held request's cancel routine was not called exactly once");
    }
    let result = pending
        .wait()
        .map_err(|_| "the cancelled request was not completed")?;
    if result.status != STATUS_CANCELLED || result.information != 0 {
        return Err("a cancelled request did not complete as cancelled");
    }
    if CANCELLED.load(Ordering::Acquire) != cancelled + 1 {
        return Err("the driver did not complete the request as cancelled exactly once");
    }
    Ok(1)
}

/// Requests that a timer will complete are cancelled at about the time
/// the timer goes off, so that the two meet in every order. Each
/// request completes exactly once, as done or as cancelled. Returns how
/// many came back cancelled.
fn cancel_race(opened: u64) -> Result<u32, &'static str> {
    const ROUNDS: u32 = 300;
    let (completed, cancelled) = (
        COMPLETED.load(Ordering::Acquire),
        CANCELLED.load(Ordering::Acquire),
    );
    let mut seen_cancelled = 0;
    for round in 0..ROUNDS {
        let mut output = [0u8; 4];
        // The timer goes off at the next clock tick after one
        // millisecond; the cancel comes somewhere around it.
        // SAFETY: the output outlives the request, which is waited for
        // below.
        let pending =
            unsafe { file::device_control_start(opened, code(HOLD_OR_TIMER), &[1], &mut output) }
                .map_err(|_| "the request could not be sent")?;
        time::stall(u64::from(round % 40) * 500);
        pending.cancel();
        let result = pending
            .wait()
            .map_err(|_| "a request was never completed")?;
        match result.status {
            STATUS_SUCCESS if output == ANSWER && result.information == 4 => {}
            STATUS_CANCELLED if result.information == 0 => seen_cancelled += 1,
            _ => return Err("a request completed as neither done nor cancelled"),
        }
    }
    if COMPLETED.load(Ordering::Acquire) != completed + ROUNDS {
        return Err("the driver did not complete each request exactly once");
    }
    if CANCELLED.load(Ordering::Acquire) != cancelled + seen_cancelled {
        return Err("the requestor and the driver disagree on what was cancelled");
    }
    Ok(seen_cancelled)
}

/// A driver that claims to have returned more than the requestor has
/// room for must stop the system: the bytes cannot be delivered, and
/// handing over only some would pass a broken driver off as working.
pub static OVERSTATED: Group = Group {
    names: &["neg.information-overstated"],
    run: overstated,
    manual: true,
};

fn overstated(r: &mut Report, _: &BootInfo) {
    kprintln!("NK-NEG-ARMED neg.information-overstated");
    let _ = with_driver(|opened| {
        let mut output = [0u8; 8];
        let _ = file::device_control(opened, code(OVERSTATE), &[0x55; 64], &mut output);
        Ok(0)
    });
    r.fail(
        "neg.information-overstated",
        format_args!(
            "a driver claimed 64 bytes of output for an 8-byte buffer, and nothing happened"
        ),
    );
}

fn counted<N: Display>(r: &mut Report, name: &str, what: &str, result: Result<N, &'static str>) {
    match result {
        Ok(n) => r.ok_with(name, format_args!("{what} {n}")),
        Err(why) => r.fail(name, format_args!("{why}")),
    }
}

fn run(r: &mut Report, _: &BootInfo) {
    counted(
        r,
        "io.pend-dpc",
        "requests:",
        with_driver(|f| pended(f, BY_DPC, 0)),
    );
    // The timer's 20 ms is the least the requestor can have waited.
    counted(
        r,
        "io.pend-timer",
        "requests:",
        with_driver(|f| pended(f, BY_TIMER, 200_000)),
    );
    counted(
        r,
        "io.pend-work",
        "requests:",
        with_driver(|f| pended(f, BY_WORKER, 0)),
    );
    counted(
        r,
        "io.pend-inline",
        "requests:",
        with_driver(|f| pended(f, BEFORE_RETURN, 0)),
    );
    counted(r, "io.cancel", "cancelled:", with_driver(cancel));
    counted(
        r,
        "io.cancel-race",
        "of 300 came back cancelled:",
        with_driver(cancel_race),
    );
}

/// This file's test groups, in the order they run.
pub static GROUPS: &[&Group] = &[&GROUP, &OVERSTATED];
