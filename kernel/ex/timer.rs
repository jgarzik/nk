//! Executive timers (`EX_TIMER`): kernel timers the kernel allocates,
//! with a callback.
//! <https://learn.microsoft.com/en-us/windows-hardware/drivers/kernel/exxxxtimer-routines-and-ex-timer-objects>
//!
//! An `EX_TIMER` is opaque to drivers but for one thing: its address can
//! be waited on. So NK's begins with a `KTIMER`, and the rest is NK's
//! own: the DPC that calls the driver's callback at `DISPATCH_LEVEL`,
//! and what deleting needs. Setting, cancelling, expiring and waiting
//! are the kernel timer's (`ke::timer`); `nk_ex::timer` reads the
//! arguments.
//!
//! # Deleting
//!
//! `ExDeleteTimer` may be called while an expiry is under way on another
//! processor, or from the callback itself, and the callback is promised
//! a timer that is still there. So the memory is freed only once nothing
//! can be on its way to it ([`retire`]): the timer is cancelled and
//! every processor's queued DPCs are waited out (`ke::dpc::flush`),
//! which a callback already running, the expiry that queues it, and
//! anything the callback set in motion before it could know of the
//! deletion have then all passed. A caller that asked to wait does this
//! itself; otherwise a worker thread does, and the delete returns at
//! once.
//!
//! Deleted without cancelling, a timer that is set stays until it has
//! expired once more, callback included, and is retired then.
//!
//! # What is not Windows'
//!
//! - A period is kept in whole milliseconds, rounded up: the kernel
//!   timer's unit. Windows keeps 100 ns.
//! - A high-resolution timer expires on the clock tick like any other;
//!   NK's clock does not speed up for it.
//! - The tolerance a driver states when setting (`EXT_SET_PARAMETERS`)
//!   and the no-wake attribute let Windows expire a timer late to save
//!   power. NK never does, which both allow.

#![allow(non_snake_case)]

use super::work;
use crate::ke::seh::{self, Guard, Unhandled};
use crate::ke::{dpc, irql, timer};
use crate::mm::pool;
use core::ffi::c_void;
use core::mem::offset_of;
use core::sync::atomic::{AtomicBool, AtomicU8, Ordering};
use nk_ex::timer::{BadAttributes, Kind};
use nk_ntabi::ex::{
    DELAYED_WORK_QUEUE, EXT_DELETE_CALLBACK, EXT_DELETE_PARAMETERS, WORK_QUEUE_ITEM,
};
use nk_ntabi::ke::{KDPC, KTIMER, TIMER_SYNCHRONIZATION_OBJECT};

/// `EXT_CALLBACK`: a driver's routine for an expired timer: the timer
/// and the context given to `ExAllocateTimer`.
pub type ExtCallback = unsafe extern "C" fn(*mut ExTimer, *mut c_void);

/// Pool tag of executive timers.
const TAG: u32 = u32::from_le_bytes(*b"ExTm");

/// In use.
const LIVE: u8 = 0;
/// Deleted and cancelled: being retired.
const DELETED: u8 = 1;
/// Deleted without cancelling: to be retired after its next expiry.
const LAST_EXPIRY: u8 = 2;

/// NK's `EX_TIMER`.
#[repr(C)]
pub struct ExTimer {
    /// First: a driver waits on the timer's address.
    timer: KTIMER,
    /// Queued by each expiry; calls `callback`.
    dpc: KDPC,
    /// Queued to a worker thread to retire the timer.
    retirement: WORK_QUEUE_ITEM,
    callback: Option<ExtCallback>,
    context: *mut c_void,
    kind: Kind,
    /// [`LIVE`], [`DELETED`] or [`LAST_EXPIRY`].
    state: AtomicU8,
    /// Set by whoever retires the timer: one does.
    retiring: AtomicBool,
    /// What `ExDeleteTimer` was asked to call when the timer is gone.
    delete_callback: Option<EXT_DELETE_CALLBACK>,
    delete_context: *mut c_void,
}

const _: () = assert!(offset_of!(ExTimer, timer) == 0);

/// # Safety
/// `timer` points to a live `ExTimer`.
unsafe fn state<'a>(timer: *mut ExTimer) -> &'a AtomicU8 {
    // SAFETY: per the contract.
    unsafe { &(*timer).state }
}

/// # Safety
/// `timer` points to a live `ExTimer`.
unsafe fn retiring<'a>(timer: *mut ExTimer) -> &'a AtomicBool {
    // SAFETY: per the contract.
    unsafe { &(*timer).retiring }
}

/// The timer's DPC: call the driver's callback.
///
/// # Safety
/// Called as the DPC routine of an `ExTimer`, with its address.
unsafe extern "C" fn expired(_: *mut KDPC, timer: *mut c_void, _: *mut c_void, _: *mut c_void) {
    let timer = timer.cast::<ExTimer>();
    // SAFETY: per the contract; a timer is not freed while its DPC can
    // run (`retire`). The callback is the driver's, called as Windows
    // calls it: at DISPATCH_LEVEL, with the timer and its context.
    // Nothing of a driver's lies beneath a DPC: an exception the
    // callback lets out is unhandled in kernel mode.
    unsafe {
        if let Some(callback) = (&raw const (*timer).callback).read() {
            seh::call(
                callback as usize,
                [
                    timer.addr(),
                    (&raw const (*timer).context).read().addr(),
                    0,
                    0,
                ],
                &Guard::Base(Unhandled::KernelMode),
            );
        }
        if state(timer).load(Ordering::Acquire) == LAST_EXPIRY {
            retire_later(timer);
        }
    }
}

/// Cancel the timer, wait until nothing can still be on its way to it,
/// tell the driver if it asked, and free it.
///
/// Three rounds. The first flush waits out a callback that began before
/// the timer was marked deleted, and so may have set it again; the
/// second cancel takes that setting back. An expiry that had already
/// taken the timer out of its table when it was cancelled finishes
/// within one flush, and the DPC it queued within the next.
///
/// # Safety
/// `timer` is a deleted `ExTimer` that only this caller retires; the
/// caller is below `DISPATCH_LEVEL`.
unsafe fn retire(timer: *mut ExTimer) {
    // SAFETY: per the contract. Marked deleted, the timer is not set
    // again once the callbacks that predate the mark have returned.
    unsafe {
        timer::KeCancelTimer(timer.cast());
        dpc::flush();
        timer::KeCancelTimer(timer.cast());
        dpc::flush();
        dpc::flush();
        let callback = (&raw const (*timer).delete_callback).read();
        let context = (&raw const (*timer).delete_context).read();
        let freed = pool::free(timer.cast());
        debug_assert!(freed.is_ok());
        // The timer is gone already: if the callback does not return,
        // nothing is owed.
        if let Some(callback) = callback {
            seh::call(
                callback as usize,
                [context.addr(), 0, 0, 0],
                &Guard::Nothing,
            );
        }
    }
}

/// Have a worker thread retire the timer, unless somebody already is.
///
/// # Safety
/// `timer` is a deleted `ExTimer`. It may be gone when this returns.
unsafe fn retire_later(timer: *mut ExTimer) {
    /// # Safety
    /// Called as a work routine, with a timer to retire.
    unsafe extern "C" fn run(timer: *mut c_void) {
        // SAFETY: per the contract; a worker thread is at PASSIVE_LEVEL.
        unsafe { retire(timer.cast()) }
    }
    // SAFETY: per the contract. The work item is the timer's own, on no
    // queue: only the one who sets `retiring` queues it.
    unsafe {
        if retiring(timer).swap(true, Ordering::AcqRel) {
            return;
        }
        let item = &raw mut (*timer).retirement;
        (&raw mut (*item).List.Flink).write(core::ptr::null_mut());
        (&raw mut (*item).WorkerRoutine).write(Some(run));
        (&raw mut (*item).Parameter).write(timer.cast());
        work::ExQueueWorkItem(item, DELAYED_WORK_QUEUE);
    }
}

/// [`ExAllocateTimer`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-exallocatetimer):
/// a new timer, not set. Null if there is no memory or the attributes
/// have a bit Windows does not define. High resolution and no-wake
/// together stop the system, as Microsoft documents.
///
/// Partial: a high-resolution timer expires on the clock tick like any
/// other.
///
/// # Safety
/// `callback`, if any, may be called with the timer and `context` at
/// `DISPATCH_LEVEL` until the timer is deleted.
pub unsafe extern "C" fn ExAllocateTimer(
    callback: Option<ExtCallback>,
    context: *mut c_void,
    attributes: u32,
) -> *mut ExTimer {
    let kind = match nk_ex::timer::kind(attributes) {
        Ok(kind) => kind,
        Err(BadAttributes::Unknown) => return core::ptr::null_mut(),
        Err(BadAttributes::Conflict) => crate::kd::bugcheck(format_args!(
            "ExAllocateTimer: a timer cannot be both high-resolution and no-wake \
             (attributes {attributes:#x})"
        )),
    };
    let timer = pool::alloc_zeroed(size_of::<ExTimer>(), TAG).cast::<ExTimer>();
    if timer.is_null() {
        return timer;
    }
    // SAFETY: a fresh, zeroed block of the right size, which nothing
    // else has yet. Zeroed, it is live, not retiring, with no delete
    // callback.
    unsafe {
        timer::KeInitializeTimer(&raw mut (*timer).timer);
        if !kind.notification {
            (&raw mut (*timer).timer.Header.Type).write(TIMER_SYNCHRONIZATION_OBJECT);
        }
        dpc::KeInitializeDpc(&raw mut (*timer).dpc, Some(expired), timer.cast());
        (&raw mut (*timer).callback).write(callback);
        (&raw mut (*timer).context).write(context);
        (&raw mut (*timer).kind).write(kind);
    }
    timer
}

/// [`ExSetTimer`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-exsettimer):
/// set the timer to expire at `due_time` (negative: that long from now,
/// in 100 ns units; otherwise a system time) and, with a `period`, every
/// so often after. Returns whether it was set already. A period outside
/// what Microsoft documents, and a high-resolution timer set for a
/// system time, stop the system. A timer being deleted is left alone.
///
/// Partial: the period is rounded up to a whole millisecond, and the
/// tolerance in `parameters` is not used (the timer is never late on
/// purpose).
///
/// # Safety
/// `timer` came from `ExAllocateTimer` and has not been deleted with
/// waiting.
pub unsafe extern "C" fn ExSetTimer(
    timer: *mut ExTimer,
    due_time: i64,
    period: i64,
    _parameters: *mut c_void,
) -> u8 {
    let Ok(period_ms) = nk_ex::timer::period_ms(period) else {
        crate::kd::bugcheck(format_args!(
            "ExSetTimer: a period of {period} is negative or more than MAXLONG"
        ));
    };
    // SAFETY: per the contract.
    unsafe {
        if !nk_ex::timer::due_time_allowed((&raw const (*timer).kind).read(), due_time) {
            crate::kd::bugcheck(format_args!(
                "ExSetTimer: a high-resolution timer set for a system time ({due_time:#x})"
            ));
        }
        if state(timer).load(Ordering::Acquire) != LIVE {
            return 0;
        }
        timer::KeSetTimerEx(timer.cast(), due_time, period_ms, &raw mut (*timer).dpc)
    }
}

/// [`ExCancelTimer`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-excanceltimer):
/// returns whether the timer was set. A callback already on its way
/// still runs. `parameters` is reserved.
///
/// # Safety
/// As `ExSetTimer`.
pub unsafe extern "C" fn ExCancelTimer(timer: *mut ExTimer, _parameters: *mut c_void) -> u8 {
    // SAFETY: per the contract.
    unsafe { timer::KeCancelTimer(timer.cast()) }
}

/// [`ExDeleteTimer`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-exdeletetimer):
/// see "Deleting" at the top. Returns whether `cancel` was asked and the
/// timer was set. With `wait` it returns when the timer is gone, and is
/// for below `DISPATCH_LEVEL`; `wait` without `cancel` stops the system,
/// as Microsoft documents.
///
/// # Safety
/// `timer` came from `ExAllocateTimer` and is deleted once; the caller
/// does not use it afterwards. `parameters` is null or points to
/// initialised `EXT_DELETE_PARAMETERS`.
pub unsafe extern "C" fn ExDeleteTimer(
    timer: *mut ExTimer,
    cancel: u8,
    wait: u8,
    parameters: *mut EXT_DELETE_PARAMETERS,
) -> u8 {
    if wait != 0 && cancel == 0 {
        crate::kd::bugcheck(format_args!(
            "ExDeleteTimer: asked to wait for a timer it was not asked to cancel"
        ));
    }
    // SAFETY: per the contract. The timer is not touched after its
    // retirement has been handed on.
    unsafe {
        if !parameters.is_null() {
            (&raw mut (*timer).delete_callback)
                .write((&raw const (*parameters).DeleteCallback).read());
            (&raw mut (*timer).delete_context)
                .write((&raw const (*parameters).DeleteContext).read());
        }
        if cancel == 0 {
            // At DISPATCH_LEVEL from the mark to the look: an expiry
            // that sees the mark hands the timer to a worker, whose
            // flush cannot finish, nor the timer go, while this
            // processor's DPCs are held off.
            let old = irql::raise(irql::DISPATCH_LEVEL);
            state(timer).store(LAST_EXPIRY, Ordering::Release);
            // Not set: there is no expiry to keep it for. An expiry
            // that is just finishing sees the mark, or this does.
            if !timer::pending(timer.cast()) {
                retire_later(timer);
            }
            irql::lower(old);
            return 0;
        }
        state(timer).store(DELETED, Ordering::Release);
        let cancelled = timer::KeCancelTimer(timer.cast());
        if wait == 0 {
            retire_later(timer);
        } else if !retiring(timer).swap(true, Ordering::AcqRel) {
            retire(timer);
        }
        cancelled
    }
}

// ---- tests --------------------------------------------------------------

use super::stress;
use crate::ke::{time, wait};
use core::sync::atomic::{AtomicPtr, AtomicU32};

static CALLS: AtomicU32 = AtomicU32::new(0);
/// Calls that were not at `DISPATCH_LEVEL` with the timer and context
/// expected.
static BAD_CALLS: AtomicU32 = AtomicU32::new(0);
static EXPECTED: AtomicPtr<ExTimer> = AtomicPtr::new(core::ptr::null_mut());
static DELETIONS: AtomicU32 = AtomicU32::new(0);

/// The context the test timers are allocated with.
const CONTEXT: usize = 0x7E57_C0DE;

/// # Safety
/// Called as a timer's callback.
unsafe extern "C" fn tick(timer: *mut ExTimer, context: *mut c_void) {
    if irql::current() != irql::DISPATCH_LEVEL
        || timer != EXPECTED.load(Ordering::Acquire)
        || context.addr() != CONTEXT
    {
        BAD_CALLS.fetch_add(1, Ordering::AcqRel);
    }
    CALLS.fetch_add(1, Ordering::AcqRel);
}

/// # Safety
/// Called as a timer's delete callback.
unsafe extern "C" fn gone(context: *mut c_void) {
    if context.addr() == CONTEXT {
        DELETIONS.fetch_add(1, Ordering::AcqRel);
    }
}

fn calls() -> u32 {
    CALLS.load(Ordering::Acquire)
}

/// 100 ns units for `ms` milliseconds from now, as a due time.
const fn in_ms(ms: i64) -> i64 {
    -ms * 10_000
}

/// A timer with the test callback.
fn allocate(attributes: u32) -> Result<*mut ExTimer, &'static str> {
    // SAFETY: the callback is a function of this file.
    let timer = unsafe { ExAllocateTimer(Some(tick), CONTEXT as *mut c_void, attributes) };
    if timer.is_null() {
        return Err("a timer could not be allocated");
    }
    EXPECTED.store(timer, Ordering::Release);
    Ok(timer)
}

fn set(timer: *mut ExTimer, due_time: i64, period: i64) -> bool {
    // SAFETY: a timer the caller allocated and has not deleted.
    unsafe { ExSetTimer(timer, due_time, period, core::ptr::null_mut()) != 0 }
}

fn cancel(timer: *mut ExTimer) -> bool {
    // SAFETY: as `set`.
    unsafe { ExCancelTimer(timer, core::ptr::null_mut()) != 0 }
}

/// Delete, cancelling and waiting.
fn delete(timer: *mut ExTimer) -> bool {
    // SAFETY: a timer the caller allocated, deleted once.
    unsafe { ExDeleteTimer(timer, 1, 1, core::ptr::null_mut()) != 0 }
}

fn sleep(ms: u32) {
    for _ in 0..ms {
        stress::nap();
    }
}

/// A timer's callback runs once per expiry, at `DISPATCH_LEVEL`, with
/// the timer and its context; set and cancel say whether the timer was
/// set. Returns the callbacks seen.
pub fn callback_test() -> Result<u32, &'static str> {
    let before = pool::usage();
    CALLS.store(0, Ordering::Release);
    BAD_CALLS.store(0, Ordering::Release);
    let timer = allocate(0)?;
    let result = (|| {
        if cancel(timer) {
            return Err("cancelling a timer never set said it was set");
        }
        if set(timer, in_ms(20), 0) {
            return Err("setting a timer never set said it was set");
        }
        if !stress::until(stress::PROMPT_MS, || calls() == 1) {
            return Err("a timer's callback was not called");
        }
        if cancel(timer) {
            return Err("a timer that had expired was cancelled as if set");
        }
        if set(timer, in_ms(10_000), 0) || !set(timer, in_ms(10_000), 0) {
            return Err("setting a set timer again did not say it was set");
        }
        if !cancel(timer) || cancel(timer) {
            return Err("a set timer was not cancelled once, and once only");
        }
        sleep(40);
        if calls() != 1 {
            return Err("a one-shot timer called back twice, or a cancelled one at all");
        }
        if BAD_CALLS.load(Ordering::Acquire) != 0 {
            return Err("the callback was not at DISPATCH_LEVEL with its timer and context");
        }
        Ok(())
    })();
    if delete(timer) {
        return Err("deleting a timer that is not set said it was cancelled");
    }
    result?;
    if pool::usage() != before {
        return Err("a timer deleted with waiting was not freed by the time the delete returned");
    }
    Ok(calls())
}

/// A periodic timer calls back again and again until cancelled, and no
/// more after. Returns the callbacks seen.
pub fn periodic_test() -> Result<u32, &'static str> {
    CALLS.store(0, Ordering::Release);
    let timer = allocate(0)?;
    let result = (|| {
        if set(timer, in_ms(10), 100_000) {
            return Err("setting a timer never set said it was set");
        }
        if !stress::until(stress::PROMPT_MS, || calls() >= 4) {
            return Err("a periodic timer did not keep calling back");
        }
        if !cancel(timer) {
            return Err("a periodic timer between expiries was not cancelled as set");
        }
        // A callback already queued may still run; then no more.
        sleep(40);
        let then = calls();
        sleep(80);
        if calls() != then {
            return Err("a cancelled periodic timer called back");
        }
        Ok(then)
    })();
    delete(timer);
    result
}

/// A timer deleted without waiting is cancelled at once and freed by a
/// worker; one deleted without cancelling expires once more first; and
/// the driver is told when it asked to be. Returns the timers deleted.
pub fn delete_test() -> Result<u32, &'static str> {
    let before = pool::usage();
    CALLS.store(0, Ordering::Release);
    DELETIONS.store(0, Ordering::Release);
    let freed = || stress::until(stress::PROMPT_MS, || pool::usage() == before);

    // Set far ahead, deleted with cancel and wait: gone on return.
    let timer = allocate(0)?;
    set(timer, in_ms(10_000), 0);
    if !delete(timer) {
        return Err("deleting a set timer with cancel did not say it was cancelled");
    }
    if pool::usage() != before {
        return Err("a timer deleted with waiting was not freed on return");
    }

    // The same without waiting, and with a delete callback.
    let timer = allocate(0)?;
    set(timer, in_ms(10_000), 100_000);
    let mut parameters = EXT_DELETE_PARAMETERS {
        Version: 0,
        Reserved: 0,
        DeleteCallback: Some(gone),
        DeleteContext: CONTEXT as *mut c_void,
    };
    // SAFETY: a timer allocated above, deleted once.
    if unsafe { ExDeleteTimer(timer, 1, 0, &raw mut parameters) } == 0 {
        return Err("deleting a set timer without waiting did not say it was cancelled");
    }
    if !freed() || DELETIONS.load(Ordering::Acquire) != 1 {
        return Err("a timer deleted without waiting was not freed, or its owner not told");
    }

    // Deleted without cancelling: it expires, calls back, and goes.
    let timer = allocate(0)?;
    set(timer, in_ms(30), 0);
    // SAFETY: as above.
    if unsafe { ExDeleteTimer(timer, 0, 0, core::ptr::null_mut()) } != 0 {
        return Err("a delete that does not cancel said it cancelled");
    }
    if !stress::until(stress::PROMPT_MS, || calls() == 1) || !freed() {
        return Err("a timer deleted without cancelling did not expire and go");
    }

    // Not set and not cancelled: nothing to wait for.
    let timer = allocate(0)?;
    // SAFETY: as above.
    unsafe { ExDeleteTimer(timer, 0, 0, core::ptr::null_mut()) };
    if !freed() {
        return Err("an unset timer deleted without cancelling was not freed");
    }
    sleep(40);
    if calls() != 1 {
        return Err("a deleted timer called back");
    }
    Ok(4)
}

/// A timer's address can be waited on: by default satisfying a wait
/// resets it, a notification timer stays signalled until set again.
pub fn wait_test() -> Result<(), &'static str> {
    let before = pool::usage();
    let wait_for = |timer: *mut ExTimer, timeout: i64| {
        // SAFETY: a live timer begins with a dispatcher object.
        unsafe { wait::wait(Some(timer.cast()), Some(timeout)) }
    };
    for notification in [false, true] {
        let attributes = if notification {
            nk_ex::timer::NOTIFICATION
        } else {
            0
        };
        // SAFETY: no callback to call.
        let timer = unsafe { ExAllocateTimer(None, core::ptr::null_mut(), attributes) };
        if timer.is_null() {
            return Err("a timer without a callback could not be allocated");
        }
        set(timer, in_ms(20), 0);
        let asked = time::interrupt_time();
        let first = wait_for(timer, in_ms(10_000));
        let waited = time::interrupt_time() - asked;
        let second = wait_for(timer, 0);
        let again = set(timer, in_ms(10_000), 0);
        let third = wait_for(timer, 0);
        let cancelled = delete(timer);
        if first != wait::STATUS_SUCCESS || waited < 20 * 10_000 {
            return Err("a wait on a timer did not end when it expired");
        }
        let second_expected = if notification {
            wait::STATUS_SUCCESS
        } else {
            wait::STATUS_TIMEOUT
        };
        if second != second_expected {
            return Err("after a wait was satisfied the timer was not in the state of its kind");
        }
        if again || third != wait::STATUS_TIMEOUT || !cancelled {
            return Err("a timer set again was still signalled, or not set");
        }
    }
    // A high-resolution timer is a timer; an unknown attribute is not.
    let timer = allocate(nk_ex::timer::HIGH_RESOLUTION)?;
    if delete(timer) {
        return Err("an unset high-resolution timer was cancelled");
    }
    // SAFETY: no callback to call.
    if !unsafe { ExAllocateTimer(None, core::ptr::null_mut(), 1) }.is_null() {
        return Err("a timer was allocated with an attribute Windows does not define");
    }
    if pool::usage() != before {
        return Err("deleted timers were not freed");
    }
    Ok(())
}
