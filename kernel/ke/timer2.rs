//! `KTIMER2`: the timer behind `ExAllocateTimer` on Windows, which some
//! of Microsoft's drivers also use directly, in storage of their own.
//!
//! `wdm.h` declares the structure so that a driver can set the memory
//! aside, and no driver reads its fields: the routines are all there is
//! to it (`KeInitializeTimer2`, `KeSetTimer2`, `KeCancelTimer2`, none
//! of them documented; `ExAllocateTimer`'s family is their documented
//! face, and they behave as it does). So NK uses the driver's 136 bytes
//! in its own way ([`Timer2`]): a kernel timer first, where Windows has
//! the dispatcher header too, then the DPC each expiry queues, then the
//! callback's context. Setting, cancelling and expiring are the kernel
//! timer's (`ke::timer`).
//!
//! What is not Windows':
//!
//! - The header's type byte is a kernel timer's (8 or 9), where Windows
//!   has 0x18 or 0x19 for a `KTIMER2`.
//! - A period is kept in whole milliseconds, rounded up; a
//!   high-resolution timer expires on the clock tick; and the tolerance
//!   in the set parameters is not used: the timer is never late on
//!   purpose. As for an executive timer (`ex::timer`).
//! - The parameters of a cancel are not read.

#![allow(non_snake_case)]

use super::seh::{self, Guard, Unhandled};
use super::{dpc, timer};
use core::ffi::c_void;
use core::mem::{offset_of, size_of};
use nk_ntabi::ke::{KDPC, KTIMER, KTIMER2, TIMER_SYNCHRONIZATION_OBJECT};

/// `KE_TIMER2_NOTIFICATION`... the attribute bit, shared with
/// `EX_TIMER_NOTIFICATION`, that makes a timer stay signalled until it
/// is set again.
const NOTIFICATION: u32 = nk_ex::timer::NOTIFICATION;

/// How NK uses a driver's `KTIMER2`.
#[repr(C)]
struct Timer2 {
    /// First: the address can be waited on.
    timer: KTIMER,
    /// Queued by each expiry. Its context is the driver's callback.
    dpc: KDPC,
    /// What the callback is called with.
    context: *mut c_void,
}

const _: () = {
    assert!(size_of::<Timer2>() <= size_of::<KTIMER2>());
    assert!(offset_of!(Timer2, timer) == offset_of!(KTIMER2, Header));
};

/// The timer's DPC: call the driver's callback, which is the DPC's
/// context, with the timer and its own context.
///
/// # Safety
/// Called as the DPC routine of a [`Timer2`].
unsafe extern "C" fn expired(
    dpc: *mut KDPC,
    callback: *mut c_void,
    _: *mut c_void,
    _: *mut c_void,
) {
    if callback.is_null() {
        return;
    }
    // SAFETY: per the contract: the DPC lies in a timer the driver keeps
    // valid while it can fire. The callback is called as Windows calls
    // it, at DISPATCH_LEVEL; nothing of a driver's lies beneath a DPC,
    // so an exception it lets out is unhandled in kernel mode.
    unsafe {
        let timer = dpc.byte_sub(offset_of!(Timer2, dpc)).cast::<Timer2>();
        let context = (&raw const (*timer).context).read();
        seh::call(
            callback.addr(),
            [timer.addr(), context.addr(), 0, 0],
            &Guard::Base(Unhandled::KernelMode),
        );
    }
}

/// `KeInitializeTimer2`: make the driver's storage a timer that calls
/// `callback(timer, context)` at `DISPATCH_LEVEL` when it expires. The
/// attributes are `ExAllocateTimer`'s; all but the notification bit ask
/// for what NK does not vary (see the top of the file).
///
/// # Safety
/// `timer` is writable; `callback` is null or may be called so until
/// the timer is cancelled for good.
pub unsafe extern "C" fn KeInitializeTimer2(
    timer: *mut KTIMER2,
    callback: *mut c_void,
    context: *mut c_void,
    attributes: u32,
) {
    let timer = timer.cast::<Timer2>();
    // SAFETY: per the contract; `Timer2` fits a `KTIMER2`.
    unsafe {
        timer::KeInitializeTimer(&raw mut (*timer).timer);
        if attributes & NOTIFICATION == 0 {
            (&raw mut (*timer).timer.Header.Type).write(TIMER_SYNCHRONIZATION_OBJECT);
        }
        dpc::KeInitializeDpc(&raw mut (*timer).dpc, Some(expired), callback);
        (&raw mut (*timer).context).write(context);
    }
}

/// `KeSetTimer2`: set the timer to expire at `due_time` (negative: that
/// long from now, in 100 ns units; otherwise a system time) and, with a
/// `period` in 100 ns units, every so often after. Returns whether it
/// was set already. A period that is negative or over `MAXLONG` stops
/// the system, as `ExSetTimer` does.
///
/// # Safety
/// `timer` was set up by `KeInitializeTimer2` and stays valid while it
/// can fire.
pub unsafe extern "C" fn KeSetTimer2(
    timer: *mut KTIMER2,
    due_time: i64,
    period: i64,
    _parameters: *mut c_void,
) -> u8 {
    let Ok(period_ms) = nk_ex::timer::period_ms(period) else {
        crate::kd::bugcheck(format_args!(
            "KeSetTimer2: a period of {period} is negative or more than MAXLONG"
        ));
    };
    let timer = timer.cast::<Timer2>();
    // SAFETY: per the contract.
    unsafe {
        timer::KeSetTimerEx(
            &raw mut (*timer).timer,
            due_time,
            period_ms,
            &raw mut (*timer).dpc,
        )
    }
}

/// `KeCancelTimer2`: returns whether the timer was set. A callback
/// already on its way still runs.
///
/// # Safety
/// `timer` was set up by `KeInitializeTimer2`.
pub unsafe extern "C" fn KeCancelTimer2(timer: *mut KTIMER2, _parameters: *mut c_void) -> u8 {
    // SAFETY: per the contract.
    unsafe { timer::KeCancelTimer(timer.cast()) }
}

/// A timer in a driver's storage calls its callback with the timer and
/// its context, once and periodically, and a cancelled one does not.
/// Returns the callbacks counted.
pub fn self_test() -> Result<u32, &'static str> {
    use crate::ke::{time, wait};
    use core::sync::atomic::{AtomicU32, AtomicUsize, Ordering};
    static CALLS: AtomicU32 = AtomicU32::new(0);
    static SEEN: AtomicUsize = AtomicUsize::new(0);
    extern "C" fn callback(timer: *mut KTIMER2, context: *mut c_void) {
        SEEN.store(timer.addr() ^ context.addr(), Ordering::Release);
        CALLS.fetch_add(1, Ordering::AcqRel);
    }
    let nap = || {
        // SAFETY: no object is involved.
        unsafe { wait::wait(None, Some(-10_000)) };
    };
    let until = |calls: u32| {
        let deadline = time::interrupt_time() + 100_000_000;
        while CALLS.load(Ordering::Acquire) < calls {
            if time::interrupt_time() > deadline {
                return false;
            }
            nap();
        }
        true
    };
    CALLS.store(0, Ordering::Release);
    // SAFETY: a `KTIMER2` is plain bytes.
    let mut storage = unsafe { core::mem::zeroed::<KTIMER2>() };
    let timer = &raw mut storage;
    let context = core::ptr::without_provenance_mut::<c_void>(0x5A5A_0000);
    let none = core::ptr::null_mut();
    // SAFETY: the timer is this frame's, and is cancelled and every DPC
    // waited out before the frame goes.
    let result = unsafe {
        KeInitializeTimer2(timer, callback as *mut c_void, context, 8);
        (|| {
            if KeCancelTimer2(timer, none) != 0 {
                return Err("a timer never set was cancelled");
            }
            if KeSetTimer2(timer, -10_000, 0, none) != 0 || !until(1) {
                return Err("a timer set for a millisecond from now did not call its callback");
            }
            if SEEN.load(Ordering::Acquire) != timer.addr() ^ context.addr() {
                return Err("the callback was not given the timer and its context");
            }
            // Set far off, set again (which says it was set), cancelled.
            if KeSetTimer2(timer, -6_000_000_000, 0, none) != 0
                || KeSetTimer2(timer, -6_000_000_000, 0, none) != 1
                || KeCancelTimer2(timer, none) != 1
                || KeCancelTimer2(timer, none) != 0
            {
                return Err("setting and cancelling did not say whether the timer was set");
            }
            // Every two milliseconds until cancelled.
            if KeSetTimer2(timer, -10_000, 20_000, none) != 0 || !until(4) {
                return Err("a periodic timer did not keep calling its callback");
            }
            if KeCancelTimer2(timer, none) != 1 {
                return Err("a periodic timer was not set when cancelled");
            }
            Ok(())
        })()
    };
    // SAFETY: as above.
    unsafe { KeCancelTimer2(timer, none) };
    dpc::flush();
    dpc::flush();
    let calls = CALLS.load(Ordering::Acquire);
    for _ in 0..5 {
        nap();
    }
    result?;
    if CALLS.load(Ordering::Acquire) != calls {
        return Err("a cancelled timer went on calling its callback");
    }
    Ok(calls)
}
