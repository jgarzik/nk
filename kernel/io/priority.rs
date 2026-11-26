//! I/O priority boosts: a storage class driver registers a routine to
//! be told when a thread's I/O priority is raised, so that it can
//! raise the requests it holds for that thread.
//!
//! NK never raises a thread's I/O priority, so a registered routine is
//! never called. The registration itself is real and behaves as
//! Windows': eight routines system-wide, one per driver.

#![allow(non_snake_case)]

use core::sync::atomic::{AtomicPtr, AtomicUsize, Ordering};
use nk_ntabi::io::DRIVER_OBJECT;
use nk_ntabi::status::{NTSTATUS, STATUS_INVALID_PARAMETER, STATUS_SUCCESS};

/// `STATUS_ALREADY_REGISTERED`.
const STATUS_ALREADY_REGISTERED: NTSTATUS = 0xC000_0718u32 as NTSTATUS;

/// The driver-object flag Windows sets on a driver that has a routine
/// registered.
const DRVO_PRIORITY_CALLBACK: u32 = 0x200;

/// How many routines there can be, as on Windows.
const ROUTINES: usize = 8;

/// A registered routine: its driver, null for a free place, and the
/// routine.
struct Routine {
    driver: AtomicPtr<DRIVER_OBJECT>,
    routine: AtomicUsize,
}

static REGISTERED: [Routine; ROUTINES] = [const {
    Routine {
        driver: AtomicPtr::new(core::ptr::null_mut()),
        routine: AtomicUsize::new(0),
    }
}; ROUTINES];

/// `IoRegisterPriorityCallback` (undocumented): register `routine` as
/// `driver`'s. A driver that has one already is
/// `STATUS_ALREADY_REGISTERED`; a ninth routine is
/// `STATUS_INVALID_PARAMETER`, as in Windows' own routine.
///
/// # Safety
/// `driver` is a live driver object.
pub unsafe extern "C" fn IoRegisterPriorityCallback(
    driver: *mut DRIVER_OBJECT,
    routine: usize,
) -> NTSTATUS {
    // SAFETY: per the contract; a driver registers from its own entry
    // point or unload path, one at a time.
    unsafe {
        if (*driver).Flags & DRVO_PRIORITY_CALLBACK != 0 {
            return STATUS_ALREADY_REGISTERED;
        }
        for place in &REGISTERED {
            let free = core::ptr::null_mut();
            if place
                .driver
                .compare_exchange(free, driver, Ordering::AcqRel, Ordering::Acquire)
                .is_ok()
            {
                place.routine.store(routine, Ordering::Release);
                (*driver).Flags |= DRVO_PRIORITY_CALLBACK;
                return STATUS_SUCCESS;
            }
        }
    }
    STATUS_INVALID_PARAMETER
}

/// `IoUnregisterPriorityCallback` (undocumented): take `driver`'s
/// routine back. Nothing, for a driver that has none.
///
/// # Safety
/// `driver` is a live driver object.
pub unsafe extern "C" fn IoUnregisterPriorityCallback(driver: *mut DRIVER_OBJECT) {
    // SAFETY: per the contract.
    unsafe {
        if (*driver).Flags & DRVO_PRIORITY_CALLBACK == 0 {
            return;
        }
        for place in &REGISTERED {
            if place.driver.load(Ordering::Acquire) == driver {
                place.routine.store(0, Ordering::Release);
                place.driver.store(core::ptr::null_mut(), Ordering::Release);
            }
        }
        (*driver).Flags &= !DRVO_PRIORITY_CALLBACK;
    }
}

/// For the self-tests, with a driver object of the test's own.
///
/// # Safety
/// `driver` is a live driver object nothing else is registering.
pub unsafe fn test(driver: *mut DRIVER_OBJECT) -> Result<(), &'static str> {
    // SAFETY: per the contract.
    unsafe {
        if IoRegisterPriorityCallback(driver, test as *const () as usize) != STATUS_SUCCESS
            || (*driver).Flags & DRVO_PRIORITY_CALLBACK == 0
        {
            return Err("a driver's routine was not registered");
        }
        if IoRegisterPriorityCallback(driver, test as *const () as usize)
            != STATUS_ALREADY_REGISTERED
        {
            return Err("a driver's second routine was not refused");
        }
        IoUnregisterPriorityCallback(driver);
        if (*driver).Flags & DRVO_PRIORITY_CALLBACK != 0
            || REGISTERED
                .iter()
                .any(|place| place.driver.load(Ordering::Acquire) == driver)
        {
            return Err("a driver's routine was not taken back");
        }
        // Taking back what is not registered does nothing.
        IoUnregisterPriorityCallback(driver);
    }
    Ok(())
}
