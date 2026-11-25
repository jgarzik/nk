//! Tests of cancel-safe queues, with a queue and lock of the test's own
//! as the driver's callbacks.

use crate::io::csq::{
    IoCsqInitialize, IoCsqInsertIrp, IoCsqRemoveNextIrp, IoIsWdmVersionAvailable,
};
use crate::io::irp;
use crate::test::{Group, Report};
use core::ffi::c_void;
use core::sync::atomic::{AtomicBool, AtomicPtr, AtomicU32, Ordering};
use nk_bootinfo::BootInfo;
use nk_ntabi::io::{IO_CSQ, IO_CSQ_IRP_CONTEXT, IRP, SL_PENDING_RETURNED};

pub static GROUP: Group = Group {
    names: &["io.csq", "io.csq-cancel", "io.wdm-version"],
    run,
    manual: false,
};

/// The test driver's queue: requests in the order they were inserted.
static QUEUE: [AtomicPtr<IRP>; 4] = [const { AtomicPtr::new(core::ptr::null_mut()) }; 4];
static LOCKED: AtomicBool = AtomicBool::new(false);
/// Requests completed as cancelled, and the last of them.
static CANCELLED: AtomicU32 = AtomicU32::new(0);
static LAST_CANCELLED: AtomicPtr<IRP> = AtomicPtr::new(core::ptr::null_mut());
/// A callback ran without the queue's lock held.
static UNLOCKED_USE: AtomicBool = AtomicBool::new(false);

fn must_be_locked() {
    if !LOCKED.load(Ordering::Acquire) {
        UNLOCKED_USE.store(true, Ordering::Release);
    }
}

extern "C" fn insert(_: *mut IO_CSQ, irp: *mut IRP) {
    must_be_locked();
    let free = QUEUE
        .iter()
        .rposition(|slot| !slot.load(Ordering::Acquire).is_null())
        .map_or(0, |last| last + 1);
    QUEUE[free].store(irp, Ordering::Release);
}

extern "C" fn remove(_: *mut IO_CSQ, irp: *mut IRP) {
    must_be_locked();
    for slot in &QUEUE {
        let _ = slot.compare_exchange(
            irp,
            core::ptr::null_mut(),
            Ordering::AcqRel,
            Ordering::Acquire,
        );
    }
}

/// The request after `irp` (the first, given none) whose first driver
/// context matches `wanted`, or any if `wanted` is null.
extern "C" fn peek(_: *mut IO_CSQ, irp: *mut IRP, wanted: *mut c_void) -> *mut IRP {
    must_be_locked();
    let start = match QUEUE
        .iter()
        .position(|slot| !irp.is_null() && slot.load(Ordering::Acquire) == irp)
    {
        Some(at) => at + 1,
        None => 0,
    };
    QUEUE[start..]
        .iter()
        .map(|slot| slot.load(Ordering::Acquire))
        .find(|&next| {
            // SAFETY: queued requests are live while the lock is held.
            !next.is_null() && (wanted.is_null() || unsafe { (*next).DriverContext[0] } == wanted)
        })
        .unwrap_or(core::ptr::null_mut())
}

extern "C" fn acquire(_: *mut IO_CSQ, irql: *mut u8) {
    let old = crate::ke::irql::current();
    crate::arch::set_irql(crate::ke::irql::DISPATCH_LEVEL);
    while LOCKED.swap(true, Ordering::AcqRel) {
        core::hint::spin_loop();
    }
    // SAFETY: the I/O manager passes room for a level.
    unsafe { irql.write(old) };
}

extern "C" fn release(_: *mut IO_CSQ, irql: u8) {
    LOCKED.store(false, Ordering::Release);
    crate::arch::set_irql(irql);
}

extern "C" fn complete(_: *mut IO_CSQ, irp: *mut IRP) {
    // Called without the lock, as a completion must be.
    if LOCKED.load(Ordering::Acquire) {
        UNLOCKED_USE.store(true, Ordering::Release);
    }
    LAST_CANCELLED.store(irp, Ordering::Release);
    CANCELLED.fetch_add(1, Ordering::AcqRel);
}

/// A request as a dispatch routine sees it: on its stack location.
fn request(tag: usize) -> Result<*mut IRP, &'static str> {
    let irp = irp::alloc(1);
    if irp.is_null() {
        return Err("no memory for a request");
    }
    // SAFETY: a fresh request with one location, stepped onto as
    // `IoCallDriver` does.
    unsafe {
        (*irp).CurrentLocation -= 1;
        (*irp).CurrentStackLocation = (*irp).CurrentStackLocation.sub(1);
        (*irp).DriverContext[0] = tag as *mut c_void;
    }
    Ok(irp)
}

fn queue() -> IO_CSQ {
    // SAFETY: all zeroes is an `IO_CSQ` (no callbacks), filled in next.
    let mut csq = unsafe { core::mem::zeroed::<IO_CSQ>() };
    // SAFETY: a local queue.
    unsafe {
        IoCsqInitialize(
            &raw mut csq,
            insert,
            remove,
            peek,
            acquire,
            release,
            complete,
        )
    };
    csq
}

/// Requests go in marked pending and cancellable, and come out in
/// order, or by what the caller asks for, unmarked.
fn in_and_out() -> Result<(), &'static str> {
    let mut csq = queue();
    let csq = &raw mut csq;
    let requests = [request(1)?, request(2)?, request(3)?];
    // SAFETY: the test's own queue, requests and context block.
    let result = unsafe {
        (|| {
            if (*csq).Type != 2 || !(*csq).ReservePointer.is_null() {
                return Err("the queue was not initialized as a cancel-safe queue");
            }
            let mut context = core::mem::zeroed::<IO_CSQ_IRP_CONTEXT>();
            IoCsqInsertIrp(csq, requests[0], core::ptr::null_mut());
            IoCsqInsertIrp(csq, requests[1], &raw mut context);
            IoCsqInsertIrp(csq, requests[2], core::ptr::null_mut());
            for &irp in &requests {
                if (*(*irp).CurrentStackLocation).Control & SL_PENDING_RETURNED == 0
                    || (*irp).CancelRoutine.is_null()
                {
                    return Err("a queued request was not marked pending and made cancellable");
                }
            }
            if (*requests[0]).DriverContext[3] != csq.cast()
                || (*requests[1]).DriverContext[3] != (&raw mut context).cast()
                || (context.Type, context.Irp, context.Csq) != (1, requests[1], csq)
            {
                return Err("a queued request does not name its queue");
            }
            // By tag first, then whatever is next.
            let order = [
                IoCsqRemoveNextIrp(csq, 2 as *mut c_void),
                IoCsqRemoveNextIrp(csq, core::ptr::null_mut()),
                IoCsqRemoveNextIrp(csq, 7 as *mut c_void),
                IoCsqRemoveNextIrp(csq, core::ptr::null_mut()),
                IoCsqRemoveNextIrp(csq, core::ptr::null_mut()),
            ];
            if order
                != [
                    requests[1],
                    requests[0],
                    core::ptr::null_mut(),
                    requests[2],
                    core::ptr::null_mut(),
                ]
            {
                return Err("requests did not come off the queue in order");
            }
            for &irp in &requests {
                if !(*irp).CancelRoutine.is_null() || !(*irp).DriverContext[3].is_null() {
                    return Err("a request taken off the queue is still marked as queued");
                }
            }
            if !context.Irp.is_null() {
                return Err("the caller's context still names a request that left the queue");
            }
            Ok(())
        })()
    };
    for irp in requests {
        // SAFETY: the test's own requests, on no queue.
        unsafe { irp::free(irp) };
    }
    if UNLOCKED_USE.load(Ordering::Acquire) {
        return Err(
            "the queue's callbacks were called without its lock, or the completion with it",
        );
    }
    result
}

/// A queued request that is cancelled leaves the queue and is completed
/// as cancelled, once; one that is already being cancelled is passed
/// over; one cancelled before it was queued never stays.
fn cancel() -> Result<(), &'static str> {
    let mut csq = queue();
    let csq = &raw mut csq;
    let requests = [request(1)?, request(2)?, request(3)?];
    CANCELLED.store(0, Ordering::Release);
    // SAFETY: the test's own queue and requests.
    let result = unsafe {
        (|| {
            let mut context = core::mem::zeroed::<IO_CSQ_IRP_CONTEXT>();
            IoCsqInsertIrp(csq, requests[0], &raw mut context);
            IoCsqInsertIrp(csq, requests[1], core::ptr::null_mut());
            if irp::IoCancelIrp(requests[0]) != 1 {
                return Err("a queued request had no cancel routine to call");
            }
            if CANCELLED.load(Ordering::Acquire) != 1
                || LAST_CANCELLED.load(Ordering::Acquire) != requests[0]
            {
                return Err("a cancelled request was not completed as cancelled, once");
            }
            if !context.Irp.is_null() || !(*requests[0]).DriverContext[3].is_null() {
                return Err("a cancelled request is still marked as queued");
            }
            if QUEUE
                .iter()
                .any(|slot| slot.load(Ordering::Acquire) == requests[0])
            {
                return Err("a cancelled request is still on the driver's queue");
            }
            if crate::ke::irql::current() != 0 {
                return Err("cancelling left the IRQL raised");
            }
            if irp::IoCancelIrp(requests[0]) != 0 || CANCELLED.load(Ordering::Acquire) != 1 {
                return Err("a request was cancelled twice");
            }
            // Its cancel routine taken, as a canceller on its way would
            // have: the request is not handed out.
            let taken =
                core::mem::replace(&mut (*requests[1]).CancelRoutine, core::ptr::null_mut());
            if !IoCsqRemoveNextIrp(csq, core::ptr::null_mut()).is_null() {
                return Err("a request that is being cancelled was handed out");
            }
            (*requests[1]).CancelRoutine = taken;
            if IoCsqRemoveNextIrp(csq, core::ptr::null_mut()) != requests[1] {
                return Err("the queue lost a request");
            }
            // Cancelled before it is queued.
            (*requests[2]).Cancel = 1;
            IoCsqInsertIrp(csq, requests[2], core::ptr::null_mut());
            if CANCELLED.load(Ordering::Acquire) != 2
                || LAST_CANCELLED.load(Ordering::Acquire) != requests[2]
            {
                return Err(
                    "a request cancelled before it was queued was not completed as cancelled",
                );
            }
            if !IoCsqRemoveNextIrp(csq, core::ptr::null_mut()).is_null()
                || !(*requests[2]).CancelRoutine.is_null()
            {
                return Err("a request cancelled before it was queued stayed on the queue");
            }
            Ok(())
        })()
    };
    for irp in requests {
        // SAFETY: the test's own requests, on no queue.
        unsafe { irp::free(irp) };
    }
    if UNLOCKED_USE.load(Ordering::Acquire) {
        return Err(
            "the queue's callbacks were called without its lock, or the completion with it",
        );
    }
    result
}

/// Windows 10 implements WDM 6.0 and everything before it.
fn wdm_version() -> Result<(), &'static str> {
    let answers = [
        (1, 0),
        (1, 0x20),
        (1, 0x30),
        (5, 0xFF),
        (6, 0),
        (6, 1),
        (7, 0),
    ]
    .map(|(major, minor)| IoIsWdmVersionAvailable(major, minor));
    if answers != [1, 1, 1, 1, 1, 0, 0] {
        return Err("the WDM versions offered are not those up to 6.0");
    }
    Ok(())
}

fn run(r: &mut Report, _: &BootInfo) {
    r.check("io.csq", in_and_out);
    r.check("io.csq-cancel", cancel);
    r.check("io.wdm-version", wdm_version);
}
