//! What drivers ask of the kernel debugger. NK has none: Windows'
//! state for that is a debugger never set up (`KdPitchDebugger`), and
//! each routine here answers as the pinned kernel's does in it. The
//! debugger's lock and its list of power handlers are real all the
//! same, as they are on Windows.

#![allow(non_snake_case)]

use crate::ke::kspin;
use crate::ke::{Rank, SpinLock};
use core::cell::UnsafeCell;
use core::ffi::c_void;
use nk_ke::kdpower::{Handler, Handlers};
use nk_ntabi::ke::KSPIN_LOCK;
use nk_ntabi::status::{
    NTSTATUS, STATUS_DEBUGGER_INACTIVE, STATUS_INSUFFICIENT_RESOURCES, STATUS_NOT_FOUND,
    STATUS_SUCCESS,
};

/// The debugger's lock: a spin lock of the kind drivers have, which a
/// driver holds from `KdAcquireDebuggerLock` to `KdReleaseDebuggerLock`.
struct DebuggerLock(UnsafeCell<KSPIN_LOCK>);

// SAFETY: the word is only reached through the spin lock routines,
// which make every access to it atomic.
unsafe impl Sync for DebuggerLock {}

static DEBUGGER_LOCK: DebuggerLock = DebuggerLock(UnsafeCell::new(0));

/// The routines registered to be called around a power transition.
static POWER_HANDLERS: SpinLock<Handlers> = SpinLock::new(Rank::KdPower, Handlers::new());

/// `KdAcquireDebuggerLock` (undocumented): take the debugger's lock,
/// raising to `DISPATCH_LEVEL`; the IRQL before goes to `old_irql`.
///
/// # Safety
/// `old_irql` points to room for an IRQL; the caller is at or below
/// `DISPATCH_LEVEL` and does not hold the lock.
pub unsafe extern "C" fn KdAcquireDebuggerLock(old_irql: *mut u8) {
    // SAFETY: the lock's word, initialised free; the caller's place
    // for the IRQL.
    unsafe {
        let old = kspin::KeAcquireSpinLockRaiseToDpc(DEBUGGER_LOCK.0.get());
        old_irql.write(old);
    }
}

/// `KdReleaseDebuggerLock` (undocumented): give the debugger's lock
/// back and return to `old_irql`.
///
/// # Safety
/// The caller holds the lock, taken with `KdAcquireDebuggerLock`, which
/// gave it `old_irql`.
pub unsafe extern "C" fn KdReleaseDebuggerLock(old_irql: u8) {
    // SAFETY: per the contract.
    unsafe { kspin::KeReleaseSpinLock(DEBUGGER_LOCK.0.get(), old_irql) };
}

/// [`KdDisableDebugger`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-kddisabledebugger):
/// turn the debugger off. There is none to turn off:
/// `STATUS_DEBUGGER_INACTIVE`.
pub extern "C" fn KdDisableDebugger() -> NTSTATUS {
    STATUS_DEBUGGER_INACTIVE
}

/// [`KdEnableDebugger`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-kdenabledebugger):
/// turn the debugger back on. There is none: `STATUS_DEBUGGER_INACTIVE`.
pub extern "C" fn KdEnableDebugger() -> NTSTATUS {
    STATUS_DEBUGGER_INACTIVE
}

/// `KdRegisterPowerHandler` (undocumented): register a routine for the
/// debugger to call around a power transition, for a handle. With no
/// debugger no transition calls it (`KdPowerTransitionEx`).
///
/// Callable at or below `DISPATCH_LEVEL`.
///
/// # Safety
/// `handle` points to room for a pointer.
pub unsafe extern "C" fn KdRegisterPowerHandler(
    routine: *mut c_void,
    context: *mut c_void,
    handle: *mut *mut c_void,
) -> NTSTATUS {
    let registered = POWER_HANDLERS.lock().register(Handler {
        routine: routine.addr(),
        context: context.addr(),
    });
    match registered {
        Some(number) => {
            // SAFETY: per the contract. The handle is the
            // registration's number: it is opaque to the driver.
            unsafe { handle.write_unaligned(core::ptr::without_provenance_mut(number)) };
            STATUS_SUCCESS
        }
        None => STATUS_INSUFFICIENT_RESOURCES,
    }
}

/// `KdDeregisterPowerHandler` (undocumented): take back a registration.
/// `STATUS_NOT_FOUND` for a handle that names none.
pub extern "C" fn KdDeregisterPowerHandler(handle: *mut c_void) -> NTSTATUS {
    match POWER_HANDLERS.lock().deregister(handle.addr()) {
        Some(_) => STATUS_SUCCESS,
        None => STATUS_NOT_FOUND,
    }
}

/// `KdPowerTransitionEx` (undocumented): tell the debugger the machine
/// is entering or leaving a power state, so that it moves its
/// transport and calls the registered routines. With a debugger never
/// set up Windows' routine succeeds at once, calling none.
pub extern "C" fn KdPowerTransitionEx(_state: u32, _reinitialize: u8) -> NTSTATUS {
    STATUS_SUCCESS
}

/// [`DbgBreakPoint`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-dbgbreakpoint):
/// execute a breakpoint trap instruction. With no debugger attached this
/// raises `STATUS_BREAKPOINT` through SEH (stopping the system if unhandled),
/// or resumes past the instruction when `debug=on` is set.
pub extern "C" fn DbgBreakPoint() {
    crate::arch::driver_breakpoint();
}

/// [`KdRefreshDebuggerNotPresent`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-kdrefreshdebuggernotpresent):
/// refresh and return `KdDebuggerNotPresent`. NK speaks no Windows kernel
/// debugger protocol, so this always returns true (`1`).
pub extern "C" fn KdRefreshDebuggerNotPresent() -> u8 {
    super::variables::KdDebuggerNotPresent
        .0
        .load(core::sync::atomic::Ordering::Relaxed)
}
