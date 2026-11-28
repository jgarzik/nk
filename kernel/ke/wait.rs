//! Waiting: events, semaphores, delays, and `KeWaitForSingleObject`.
//!
//! A wait links one of the thread's built-in wait blocks on the object.
//! A wait with a time limit also sets the thread's own timer and links a
//! second block on that, whose key is `STATUS_TIMEOUT`: a time limit is
//! just another object, and whichever is signalled first ends the wait.
//! The race between the thread going to sleep and its wakers is the wait
//! register's (`nk_ke::WaitRegister`).
//!
//! The order of a wait:
//!
//! 1. Under the object's lock: take it if signalled, and return. Else
//!    begin the wait and link the block.
//! 2. Set the timer, then, under the timer's lock, link the timer block,
//!    or end the wait at once if the time has already come.
//! 3. Give up the processor, unless a waker got there first.
//! 4. Awake: cancel the timer, wait out any expiry of it already under
//!    way, and unlink whichever blocks are still linked, each under its
//!    object's lock. Only then is the wait over
//!    and the blocks free for the next one.
//!
//! Wakers never wait for the waiter and never touch the object after
//! dropping its lock, so an event on a thread's stack may be freed as
//! soon as that thread's wait returns.
//!
//! An alert is one more waker, of alertable waits only ([`alert`]). A
//! thread says under its own lock that its wait may be alerted, having
//! first looked for an alert left for it; the alerter, under the same
//! lock, either claims such a wait or leaves the alert for the next
//! one. An alert that is waiting is looked at before the objects and
//! before the time limit, as on Windows: the wait returns
//! `STATUS_ALERTED` and takes nothing.

#![allow(non_snake_case)]

use super::object::{self, ObjectLock};
use super::{dpc, irql, thread, time, timer};
use crate::arch;
use core::ffi::c_void;
use core::sync::atomic::{AtomicU8, AtomicU32, Ordering};
use nk_ke::Claimed;
use nk_ke::wait::MAXIMUM_WAIT_OBJECTS;
use nk_ntabi::io::KERNEL_MODE;
use nk_ntabi::ke::{
    DISPATCHER_HEADER, EVENT_NOTIFICATION_OBJECT, EVENT_SYNCHRONIZATION_OBJECT, KEVENT, KSEMAPHORE,
    KWAIT_BLOCK, SEMAPHORE_OBJECT, WAIT_BLOCK_INACTIVE,
};
use nk_ntabi::thread::{
    ALERTED, MISC_FLAG_ALERTABLE, MISC_FLAGS, TIMER_WAIT_BLOCK, WAIT_IRQL, WAIT_MODE,
};

pub const STATUS_SUCCESS: u32 = 0;
/// The thread was alerted: an alertable wait returns this.
pub const STATUS_ALERTED: u32 = 0x101;
/// The wait's time limit passed first.
pub const STATUS_TIMEOUT: u32 = 0x102;
/// What a wait entered at `PASSIVE_LEVEL` is ended with internally when
/// kernel APCs are queued to its thread: it delivers them and waits
/// again (`ke::apc`). No wait returns it.
pub const STATUS_KERNEL_APC: u32 = 0x100;

/// `WAIT_TYPE`: `WaitAll` and `WaitAny`.
const WAIT_ALL: u8 = 0;
const WAIT_ANY: u8 = 1;
/// What a waker claims a wait-for-all thread with: not a status the
/// wait returns, but "something changed; look again".
const WAKE_AND_LOOK: u32 = 0x2000;

/// Stop the system if the caller may not block: a wait that has to
/// sleep needs an IRQL below `DISPATCH_LEVEL`.
fn must_be_able_to_block(irql_at_call: u8) {
    if irql_at_call < irql::DISPATCH_LEVEL {
        return;
    }
    if dpc::running() {
        crate::kd::bugcheck(format_args!(
            "0x000000B8 ATTEMPTED_SWITCH_FROM_DPC: a DPC routine waited"
        ));
    }
    crate::kd::bugcheck(format_args!(
        "0x0000000A IRQL_NOT_LESS_OR_EQUAL: a wait that must block at IRQL {irql_at_call}"
    ));
}

/// Fill in a wait block, not yet linked.
///
/// # Safety
/// `block` is one of the running thread's wait blocks, linked nowhere.
unsafe fn prepare(block: *mut KWAIT_BLOCK, object: *mut DISPATCHER_HEADER, key: u32, kind: u8) {
    // SAFETY: per the contract. Field by field: the spare fields of a
    // thread's built-in blocks hold other things.
    unsafe {
        (&raw mut (*block).WaitType).write(kind);
        (&raw mut (*block).WaitKey).write(key as u16);
        (&raw mut (*block).Thread).write(thread::current().cast());
        (&raw mut (*block).Object).write(object.cast());
    }
}

/// Unlink a wait block that its object's waker did not.
///
/// # Safety
/// `block` is one of the running thread's wait blocks and `object` is
/// the live object it was linked on, if it still is.
unsafe fn withdraw(object: *mut DISPATCHER_HEADER, block: *mut KWAIT_BLOCK) {
    // SAFETY: per the contract.
    unsafe {
        let _lock = ObjectLock::take(object);
        object::unlink(block);
    }
}

/// Whether an alert in `mode` is waiting for `thread`.
///
/// # Safety
/// `thread` is a live thread; `mode` is a processor mode, 0 or 1.
unsafe fn alerted<'a>(thread: *mut thread::Thread, mode: i8) -> &'a AtomicU8 {
    // SAFETY: per the contract: a byte of the thread's block.
    unsafe { AtomicU8::from_ptr(thread::object_field(thread, ALERTED + mode as usize)) }
}

/// The thread's `MiscFlags`.
///
/// # Safety
/// `thread` is a live thread.
unsafe fn misc_flags<'a>(thread: *mut thread::Thread) -> &'a AtomicU32 {
    // SAFETY: per the contract: an aligned field of the thread's block.
    unsafe { AtomicU32::from_ptr(thread::object_field(thread, MISC_FLAGS)) }
}

/// The running thread begins a wait in `mode` that an alert may end.
/// `true` if an alert was waiting for it: the alert is used up, and the
/// wait is to return `STATUS_ALERTED` at once. An alert made in kernel
/// mode ends a wait of either mode, one made in user mode a user-mode
/// wait only, as on Windows. Otherwise the thread is marked as
/// alertable until [`alertable_wait_over`].
///
/// # Safety
/// `me` is the running thread, at `DISPATCH_LEVEL`, its wait begun and
/// no object lock held.
unsafe fn alertable_wait_begins(me: *mut thread::Thread, mode: i8) -> bool {
    // SAFETY: per the contract; the thread's own lock covers its alert
    // state.
    unsafe {
        let _lock = ObjectLock::take(me.cast());
        if alerted(me, mode).swap(0, Ordering::Relaxed) != 0
            || (mode != KERNEL_MODE && alerted(me, KERNEL_MODE).swap(0, Ordering::Relaxed) != 0)
        {
            return true;
        }
        thread::object_field::<i8>(me, WAIT_MODE).write(mode);
        misc_flags(me).fetch_or(MISC_FLAG_ALERTABLE, Ordering::Relaxed);
        false
    }
}

/// The running thread's alertable wait is over: an alert from now on
/// is kept for its next one.
///
/// # Safety
/// As [`alertable_wait_begins`].
unsafe fn alertable_wait_over(me: *mut thread::Thread) {
    // SAFETY: per the contract.
    unsafe {
        let _lock = ObjectLock::take(me.cast());
        misc_flags(me).fetch_and(!MISC_FLAG_ALERTABLE, Ordering::Relaxed);
    }
}

/// Alert `thread` in `mode`, as Windows' `KeAlertThread` does. If the
/// thread is in an alertable wait the alert's mode may end (a
/// kernel-mode alert ends any, a user-mode alert a user-mode wait),
/// that wait returns `STATUS_ALERTED`. Otherwise, or if something else
/// ended the wait first, the alert is left for the thread's next
/// alertable wait. An alert already waiting is not doubled. Returns
/// whether one was.
///
/// # Safety
/// `thread` is a live thread the caller holds a reference to; `mode`
/// is a processor mode, 0 or 1.
pub unsafe fn alert(thread: *mut thread::Thread, mode: i8) -> bool {
    // SAFETY: per the contract. The thread's lock covers its alert
    // state; a thread claimed asleep is made ready after the lock is
    // dropped, like any waiter.
    unsafe {
        let (was, asleep) = {
            let _lock = ObjectLock::take(thread.cast());
            let waiting = alerted(thread, mode);
            if waiting.load(Ordering::Relaxed) != 0 {
                (true, false)
            } else {
                let alertable = misc_flags(thread).load(Ordering::Relaxed) & MISC_FLAG_ALERTABLE
                    != 0
                    && mode <= thread::object_field::<i8>(thread, WAIT_MODE).read();
                let claimed = if alertable {
                    thread::wait_register(thread).claim(STATUS_ALERTED)
                } else {
                    None
                };
                if claimed.is_none() {
                    waiting.store(1, Ordering::Relaxed);
                }
                (false, claimed == Some(Claimed::Asleep))
            }
        };
        if asleep {
            thread::make_ready(thread);
        }
        was
    }
}

/// Wait until `object` (if any) is signalled or `timeout` (if any)
/// passes: a negative timeout is that many 100 ns units from now, a
/// positive one a system time. Returns `STATUS_SUCCESS` or
/// `STATUS_TIMEOUT`. Not alertable.
///
/// # Safety
/// `object` is a live dispatcher object that stays valid until this
/// returns.
pub unsafe fn wait(object: Option<*mut DISPATCHER_HEADER>, timeout: Option<i64>) -> u32 {
    let blocks = thread::wait_block(thread::current(), 0);
    // SAFETY: per the contract; the blocks are the running thread's own.
    unsafe { wait_objects(object.as_slice(), false, timeout, blocks, None) }
}

/// As [`wait`], for a caller that says whether the wait is alertable
/// and in which processor mode: what `KeWaitForSingleObject` is given.
/// An alertable wait may also return `STATUS_ALERTED`.
///
/// # Safety
/// As [`wait`]; `wait_mode` is a processor mode, 0 or 1.
pub unsafe fn wait_as(
    object: Option<*mut DISPATCHER_HEADER>,
    timeout: Option<i64>,
    wait_mode: i8,
    alertable: bool,
) -> u32 {
    let blocks = thread::wait_block(thread::current(), 0);
    // SAFETY: per the contract; the blocks are the running thread's own.
    unsafe {
        wait_objects(
            object.as_slice(),
            false,
            timeout,
            blocks,
            alertable.then_some(wait_mode),
        )
    }
}

/// Wait on several objects: until any one is signalled (returning its
/// index) or, with `all`, until all are at once (returning
/// `STATUS_SUCCESS`); or until `timeout` passes (`STATUS_TIMEOUT`); or,
/// if `alert` gives the processor mode of an alertable wait, until the
/// thread is alerted (`STATUS_ALERTED`).
///
/// A wait for all takes all the objects or none. Wakers do not take
/// objects for such a waiter: they only wake it, and it looks again for
/// itself, holding every object's lock at once, in address order. That
/// is the one place more than one object lock is held.
///
/// # Safety
/// Every object is a live dispatcher object that stays valid until this
/// returns; no object appears twice when `all`; `blocks` has room for
/// one wait block per object and is used by nothing else meanwhile;
/// `alert`, if any, is a processor mode, 0 or 1.
pub unsafe fn wait_objects(
    objects: &[*mut DISPATCHER_HEADER],
    all: bool,
    timeout: Option<i64>,
    blocks: *mut KWAIT_BLOCK,
    alert: Option<i8>,
) -> u32 {
    let old = irql::current();
    if old > irql::DISPATCH_LEVEL {
        must_be_able_to_block(old);
    }
    arch::set_irql(irql::DISPATCH_LEVEL);
    let me = thread::current();
    // SAFETY: the running thread.
    let register = unsafe { thread::wait_register(me) };
    let timer_block = thread::wait_block(me, TIMER_WAIT_BLOCK);
    let my_timer = thread::timer(me);
    // A time limit is fixed once, as a system time, however often a
    // wait for all has to look again.
    let deadline = timeout.map(|due| nk_ke::wait::deadline(due, time::system_time()));
    // The order in which a wait for all locks its objects.
    let mut by_address = [0usize; MAXIMUM_WAIT_OBJECTS];
    for (slot, index) in by_address.iter_mut().zip(0..objects.len()) {
        *slot = index;
    }
    let by_address = &mut by_address[..objects.len()];
    by_address.sort_unstable_by_key(|&index| objects[index].addr());

    // SAFETY: per the contract throughout.
    let status = unsafe {
        loop {
            // Nothing is linked yet, so nothing can claim the thread
            // until a block goes on a list below. Only blocks linked
            // here are looked at again afterwards: the rest of the
            // caller's array is whatever the caller left in it.
            set_wait_irql(me, old);
            register.begin();
            // Kernel APCs queued before the wait began, which no waker
            // will now interrupt it for, are delivered first.
            if old == irql::PASSIVE_LEVEL && super::apc::interrupts_wait() {
                let _ = register.claim(STATUS_KERNEL_APC);
            }
            let mut linked = 0;
            // An alert left for the thread comes before everything
            // else: nothing is looked at, nothing taken.
            if let Some(mode) = alert {
                if alertable_wait_begins(me, mode) {
                    let _ = register.claim(STATUS_ALERTED);
                } else if mode == nk_ntabi::io::USER_MODE && !super::apc::user_queue_empty(me) {
                    super::apc::set_user_pending(me);
                    let _ = register.claim(nk_ntabi::status::STATUS_USER_APC as u32);
                }
            }
            if register.status().is_some() {
                // Alerted already.
            } else if all {
                let mut locks: [Option<ObjectLock>; MAXIMUM_WAIT_OBJECTS] =
                    [const { None }; MAXIMUM_WAIT_OBJECTS];
                for (lock, &index) in locks.iter_mut().zip(by_address.iter()) {
                    *lock = Some(ObjectLock::take(objects[index]));
                }
                if objects.iter().all(|&object| object::available(object, me)) {
                    for &object in objects {
                        object::take(object, me);
                    }
                    let _ = register.claim(STATUS_SUCCESS);
                } else if deadline != Some(0) {
                    for (index, &object) in objects.iter().enumerate() {
                        let block = blocks.add(index);
                        prepare(block, object, WAKE_AND_LOOK, WAIT_ALL);
                        object::link(object, block);
                    }
                    linked = objects.len();
                }
                // Released in the reverse of the order taken.
                for lock in locks.iter_mut().rev() {
                    drop(lock.take());
                }
            } else {
                for (index, &object) in objects.iter().enumerate() {
                    let _lock = ObjectLock::take(object);
                    if object::available(object, me) {
                        // Unless an object earlier in the list was
                        // signalled meanwhile and got in first.
                        if register.claim(index as u32).is_some() {
                            object::take(object, me);
                        }
                        break;
                    }
                    let block = blocks.add(index);
                    prepare(block, object, index as u32, WAIT_ANY);
                    object::link(object, block);
                    linked = index + 1;
                }
            }
            if register.status().is_none() {
                if deadline == Some(0) {
                    let _ = register.claim(STATUS_TIMEOUT);
                } else {
                    must_be_able_to_block(old);
                }
            }
            let timed = register.status().is_none() && deadline.is_some();
            if let Some(due) = deadline.filter(|_| timed) {
                // Set first, then look: setting clears what an earlier
                // expiry may have left, and a timer that has already
                // gone off by the time its block would be linked ends
                // the wait here instead.
                timer::KeSetTimer(my_timer, due, core::ptr::null_mut());
                let header = &raw mut (*my_timer).Header;
                let _lock = ObjectLock::take(header);
                if object::signal(header).load(Ordering::Relaxed) > 0 {
                    let _ = register.claim(STATUS_TIMEOUT);
                } else {
                    prepare(timer_block, header, STATUS_TIMEOUT, WAIT_ANY);
                    object::link(header, timer_block);
                }
            }

            thread::sleep();

            let status = register
                .status()
                .expect("a thread woke from a wait that nothing ended");
            if timed {
                // Not just cancelled: an expiry of this timer may be
                // under way on another processor, and once this wait
                // returns the thread, timer and all, may be freed.
                timer::cancel_and_settle(my_timer);
                withdraw(&raw mut (*my_timer).Header, timer_block);
            }
            for (index, &object) in objects.iter().enumerate().take(linked) {
                withdraw(object, blocks.add(index));
            }
            if alert.is_some() {
                alertable_wait_over(me);
            }
            register.finish();
            if status == STATUS_KERNEL_APC {
                // Delivered, and the wait goes on, its time limit as it
                // was. A wait entered above PASSIVE_LEVEL, ended by an
                // APC queued as it began, just waits again.
                if old == irql::PASSIVE_LEVEL {
                    arch::set_irql(nk_ntabi::pcr::APC_LEVEL);
                    super::apc::deliver();
                    arch::set_irql(irql::DISPATCH_LEVEL);
                }
                continue;
            }
            if status != WAKE_AND_LOOK {
                break status;
            }
        }
    };
    // SAFETY: `me` is the running thread.
    unsafe { thread::set_wait_status(me, status) };
    arch::set_irql(old);
    status
}

/// Record the IRQL the thread's wait was entered at (`WaitIrql`), which
/// decides whether a kernel APC interrupts it.
///
/// # Safety
/// `me` is the running thread.
unsafe fn set_wait_irql(me: *mut thread::Thread, level: u8) {
    // SAFETY: per the contract; a byte other processors read.
    unsafe { AtomicU8::from_ptr(thread::object_field(me, WAIT_IRQL)) }
        .store(level, Ordering::Relaxed);
}

/// Start the running thread's wait blocks off as unlinked. Once per
/// thread, before its first wait.
///
/// # Safety
/// `thread` is a thread being created.
pub unsafe fn init_thread(thread: *mut thread::Thread) {
    // SAFETY: per the contract.
    unsafe {
        for index in 0..=TIMER_WAIT_BLOCK {
            (&raw mut (*thread::wait_block(thread, index)).BlockState).write(WAIT_BLOCK_INACTIVE);
        }
        timer::KeInitializeTimer(thread::timer(thread));
    }
}

/// [`NtDelayExecution`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-kedelayexecutionthread):
/// sleep for `delay_interval` (negative = relative 100ns, positive = absolute).
///
/// # Safety
/// `delay_interval` must satisfy `PreviousMode`.
pub unsafe extern "C" fn NtDelayExecution(
    alertable: u8,
    delay_interval: *const i64,
) -> nk_ntabi::status::NTSTATUS {
    let mode = crate::svc::capture::mode();
    // SAFETY: per the contract; `capture::read` probes user pointers.
    let interval = match unsafe { crate::svc::capture::read(delay_interval, mode) } {
        Ok(v) => v,
        Err(st) => return st,
    };
    if interval == 0 {
        if alertable != 0
            && mode == nk_ntabi::io::USER_MODE
            && !super::apc::user_queue_empty(thread::current())
        {
            super::apc::set_user_pending(thread::current());
            return nk_ntabi::status::STATUS_USER_APC;
        }
        thread::yield_now();
        return 0;
    }
    // SAFETY: no dispatcher object waited on; `interval` is a valid timeout.
    let status = unsafe { wait_as(None, Some(interval), mode, alertable != 0) };
    if status == STATUS_TIMEOUT {
        0
    } else {
        status as nk_ntabi::status::NTSTATUS
    }
}

/// `NtYieldExecution`: yield the current processor timeslice.
pub extern "C" fn NtYieldExecution() -> nk_ntabi::status::NTSTATUS {
    thread::yield_now();
    0
}

/// [`KeInitializeEvent`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-keinitializeevent).
/// `kind` is 0 for a notification event, 1 for a synchronization event.
///
/// # Safety
/// `event` points to writable storage for a `KEVENT`.
pub unsafe extern "C" fn KeInitializeEvent(event: *mut KEVENT, kind: u32, state: u8) {
    // SAFETY: per the contract.
    unsafe {
        let header = &raw mut (*event).Header;
        header
            .cast::<u8>()
            .write_bytes(0, size_of::<DISPATCHER_HEADER>());
        (&raw mut (*header).Type).write(if kind == 0 {
            EVENT_NOTIFICATION_OBJECT
        } else {
            EVENT_SYNCHRONIZATION_OBJECT
        });
        (&raw mut (*header).SignalState).write(i32::from(state != 0));
        object::init_wait_list(header);
    }
}

/// [`KeSetEvent`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-kesetevent).
/// Returns the previous signal state. There are no priority boosts, and
/// `wait` changes nothing: it only promises a wait will follow.
///
/// # Safety
/// `event` is a live, initialised `KEVENT`.
pub unsafe extern "C" fn KeSetEvent(event: *mut KEVENT, _increment: i32, _wait: u8) -> i32 {
    // SAFETY: per the contract.
    unsafe {
        let header = &raw mut (*event).Header;
        let (previous, woken) = {
            let _lock = ObjectLock::take(header);
            let previous = object::signal(header).swap(1, Ordering::Relaxed);
            (previous, object::satisfy(header))
        };
        woken.ready();
        previous
    }
}

/// [`KeResetEvent`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-keresetevent).
/// Returns the previous signal state.
///
/// # Safety
/// `event` is a live, initialised `KEVENT`.
pub unsafe extern "C" fn KeResetEvent(event: *mut KEVENT) -> i32 {
    // SAFETY: per the contract.
    unsafe {
        let header = &raw mut (*event).Header;
        let _lock = ObjectLock::take(header);
        object::signal(header).swap(0, Ordering::Relaxed)
    }
}

/// [`KeClearEvent`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-keclearevent):
/// make the event not signalled.
///
/// # Safety
/// `event` is a live, initialised `KEVENT`.
pub unsafe extern "C" fn KeClearEvent(event: *mut KEVENT) {
    // SAFETY: per the contract.
    unsafe { KeResetEvent(event) };
}

/// [`KeReadStateEvent`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-kereadstateevent).
///
/// # Safety
/// `event` is a live, initialised `KEVENT`.
pub unsafe extern "C" fn KeReadStateEvent(event: *mut KEVENT) -> i32 {
    // SAFETY: per the contract.
    unsafe { object::signal(&raw mut (*event).Header).load(Ordering::Acquire) }
}

/// [`KeInitializeSemaphore`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-keinitializesemaphore).
///
/// # Safety
/// `semaphore` points to writable storage for a `KSEMAPHORE`.
pub unsafe extern "C" fn KeInitializeSemaphore(semaphore: *mut KSEMAPHORE, count: i32, limit: i32) {
    // SAFETY: per the contract.
    unsafe {
        let header = &raw mut (*semaphore).Header;
        header
            .cast::<u8>()
            .write_bytes(0, size_of::<DISPATCHER_HEADER>());
        (&raw mut (*header).Type).write(SEMAPHORE_OBJECT);
        (&raw mut (*header).SignalState).write(count);
        object::init_wait_list(header);
        (&raw mut (*semaphore).Limit).write(limit);
    }
}

/// [`KeReleaseSemaphore`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-kereleasesemaphore).
/// Returns the previous count. Going past the limit raises
/// `STATUS_SEMAPHORE_LIMIT_EXCEEDED` on Windows; NK has no exceptions to
/// raise yet, and an unhandled one stops Windows too.
///
/// # Safety
/// `semaphore` is a live, initialised `KSEMAPHORE`.
pub unsafe extern "C" fn KeReleaseSemaphore(
    semaphore: *mut KSEMAPHORE,
    _increment: i32,
    adjustment: i32,
    _wait: u8,
) -> i32 {
    // SAFETY: per the contract.
    unsafe {
        let header = &raw mut (*semaphore).Header;
        let (previous, woken) = {
            let _lock = ObjectLock::take(header);
            let state = object::signal(header);
            let previous = state.load(Ordering::Relaxed);
            let limit = (&raw const (*semaphore).Limit).read();
            match nk_ke::wait::semaphore_release(previous, adjustment, limit) {
                Some(count) => state.store(count, Ordering::Relaxed),
                None => crate::kd::bugcheck(format_args!(
                    "0x0000001E KMODE_EXCEPTION_NOT_HANDLED: STATUS_SEMAPHORE_LIMIT_EXCEEDED \
                     (count {previous}, release {adjustment}, limit {limit})"
                )),
            }
            (previous, object::satisfy(header))
        };
        woken.ready();
        previous
    }
}

/// Release `semaphore` by `adjustment` without bugchecking on limit overflow
/// (returns `Err(STATUS_SEMAPHORE_LIMIT_EXCEEDED)` for `NtReleaseSemaphore`).
///
/// # Safety
/// `semaphore` is a live, initialized `KSEMAPHORE`.
pub unsafe fn try_release_semaphore(
    semaphore: *mut KSEMAPHORE,
    adjustment: i32,
) -> Result<i32, nk_ntabi::status::NTSTATUS> {
    if adjustment <= 0 {
        return Err(nk_ntabi::status::STATUS_INVALID_PARAMETER);
    }
    // SAFETY: per the contract.
    unsafe {
        let header = &raw mut (*semaphore).Header;
        let (previous, woken) = {
            let _lock = ObjectLock::take(header);
            let state = object::signal(header);
            let previous = state.load(Ordering::Relaxed);
            let limit = (&raw const (*semaphore).Limit).read();
            let Some(count) = nk_ke::wait::semaphore_release(previous, adjustment, limit) else {
                return Err(nk_ntabi::status::STATUS_SEMAPHORE_LIMIT_EXCEEDED);
            };
            state.store(count, Ordering::Relaxed);
            (previous, object::satisfy(header))
        };
        woken.ready();
        Ok(previous)
    }
}

/// [`KeReadStateSemaphore`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-kereadstatesemaphore).
///
/// # Safety
/// `semaphore` is a live, initialised `KSEMAPHORE`.
pub unsafe extern "C" fn KeReadStateSemaphore(semaphore: *mut KSEMAPHORE) -> i32 {
    // SAFETY: per the contract.
    unsafe { object::signal(&raw mut (*semaphore).Header).load(Ordering::Acquire) }
}

/// [`KeWaitForSingleObject`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-kewaitforsingleobject).
/// An alertable wait returns `STATUS_ALERTED` when the thread is
/// alerted ([`alert`]). A wait entered at `PASSIVE_LEVEL` runs the
/// kernel APCs queued to its thread and goes on waiting.
///
/// # Safety
/// `object` is a live dispatcher object that stays valid until this
/// returns; `timeout` is null or points to a due time.
pub unsafe extern "C" fn KeWaitForSingleObject(
    object: *mut c_void,
    _wait_reason: u32,
    wait_mode: i8,
    alertable: u8,
    timeout: *const i64,
) -> i32 {
    // SAFETY: per the contract.
    unsafe {
        let timeout = (!timeout.is_null()).then(|| timeout.read_unaligned());
        wait_as(
            Some(object.cast()),
            timeout,
            i8::from(wait_mode != KERNEL_MODE),
            alertable != 0,
        ) as i32
    }
}

/// [`KeWaitForMultipleObjects`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-kewaitformultipleobjects).
/// `wait_type` is 0 to wait for all, 1 for any. More than three objects
/// need the caller's wait blocks; more than 64, or more than three
/// without, stops the system as on Windows.
///
/// # Safety
/// `object` points to `count` pointers to live dispatcher objects that
/// stay valid until this returns; `timeout` is null or points to a due
/// time; `wait_block_array` is null or has room for `count` wait blocks.
pub unsafe extern "C" fn KeWaitForMultipleObjects(
    count: u32,
    object: *const *mut c_void,
    wait_type: u32,
    _wait_reason: u32,
    wait_mode: i8,
    alertable: u8,
    timeout: *const i64,
    wait_block_array: *mut KWAIT_BLOCK,
) -> i32 {
    let count = count as usize;
    if !nk_ke::wait::count_allowed(count, !wait_block_array.is_null()) {
        crate::kd::bugcheck(format_args!(
            "0x0000000C MAXIMUM_WAIT_OBJECTS_EXCEEDED: a wait on {count} objects"
        ));
    }
    let mut objects = [core::ptr::null_mut::<DISPATCHER_HEADER>(); MAXIMUM_WAIT_OBJECTS];
    // SAFETY: per the contract.
    unsafe {
        for (index, slot) in objects.iter_mut().enumerate().take(count) {
            *slot = object.add(index).read_unaligned().cast();
        }
        let objects = &objects[..count];
        let all = wait_type == u32::from(WAIT_ALL);
        if all && nk_ke::wait::repeated(objects) {
            // One object twice can never be taken twice at once.
            return nk_ntabi::status::STATUS_INVALID_PARAMETER;
        }
        let blocks = if wait_block_array.is_null() {
            thread::wait_block(thread::current(), 0)
        } else {
            wait_block_array
        };
        let timeout = (!timeout.is_null()).then(|| timeout.read_unaligned());
        let alert = (alertable != 0).then_some(i8::from(wait_mode != KERNEL_MODE));
        wait_objects(objects, all, timeout, blocks, alert) as i32
    }
}

/// [`KeDelayExecutionThread`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-kedelayexecutionthread).
/// An alertable delay ends early, with `STATUS_ALERTED`, when the
/// thread is alerted.
///
/// # Safety
/// `interval` points to a due time.
pub unsafe extern "C" fn KeDelayExecutionThread(
    wait_mode: i8,
    alertable: u8,
    interval: *const i64,
) -> i32 {
    // SAFETY: per the contract; no object is involved.
    let status = unsafe {
        wait_as(
            None,
            Some(interval.read_unaligned()),
            i8::from(wait_mode != KERNEL_MODE),
            alertable != 0,
        )
    };
    // The time passing is how a delay succeeds.
    if status == STATUS_ALERTED {
        STATUS_ALERTED as i32
    } else {
        STATUS_SUCCESS as i32
    }
}

// ---- tests --------------------------------------------------------------

use super::{pcr, smp};
use crate::test::Slot;
use core::mem::MaybeUninit;
use core::sync::atomic::{AtomicBool, AtomicU64};
use nk_ke::TIME_INCREMENT;

static EVENT: Slot<KEVENT> = Slot::new();
static REPLY: Slot<KEVENT> = Slot::new();
static SEMAPHORE: Slot<KSEMAPHORE> = Slot::new();
static WOKE: AtomicU32 = AtomicU32::new(0);
static TAKEN: AtomicU64 = AtomicU64::new(0);
static STOP: AtomicBool = AtomicBool::new(false);
static WRONG: AtomicU32 = AtomicU32::new(0);

fn init_event(event: &Slot<KEVENT>, synchronization: bool, state: bool) {
    // SAFETY: static storage that nothing is waiting on.
    unsafe { KeInitializeEvent(event.ptr(), u32::from(synchronization), u8::from(state)) };
}

fn set(event: &Slot<KEVENT>) -> i32 {
    // SAFETY: a static, initialised event.
    unsafe { KeSetEvent(event.ptr(), 0, 0) }
}

/// Wait on a test event, the way a driver would call for it; `ms` is a
/// time limit in milliseconds.
fn wait_event(event: &Slot<KEVENT>, ms: Option<i64>) -> u32 {
    let due = ms.map(|ms| -ms * 10_000);
    let timeout = due.as_ref().map_or(core::ptr::null(), core::ptr::from_ref);
    // SAFETY: a static, initialised event; the due time is a local.
    unsafe { KeWaitForSingleObject(event.ptr().cast(), 0, 0, 0, timeout) as u32 }
}

fn delay_ms(ms: i64) {
    // SAFETY: no object is involved.
    unsafe { wait(None, Some(-ms * 10_000)) };
}

/// As [`thread::settle`], sleeping between looks instead of yielding,
/// so that threads of any priority get the processor meanwhile.
fn settle(threads: u32) {
    while thread::count() != threads {
        delay_ms(1);
    }
}

fn waiter(_: usize) {
    if wait_event(&EVENT, None) != STATUS_SUCCESS {
        WRONG.fetch_add(1, Ordering::Relaxed);
    }
    WOKE.fetch_add(1, Ordering::Release);
}

fn spawn(entry: thread::Entry, argument: usize, n: usize) -> Result<(), &'static str> {
    for _ in 0..n {
        thread::create(entry, argument, thread::NORMAL_PRIORITY, thread::ANYWHERE)?;
    }
    Ok(())
}

/// Setting a notification event wakes every waiter and leaves it
/// signalled until reset. Returns the threads woken.
pub fn notification_test() -> Result<u32, &'static str> {
    let before = thread::count();
    init_event(&EVENT, false, false);
    WOKE.store(0, Ordering::Relaxed);
    WRONG.store(0, Ordering::Relaxed);
    spawn(waiter, 0, 3)?;
    delay_ms(20);
    if WOKE.load(Ordering::Acquire) != 0 {
        return Err("a wait on an event that is not signalled returned");
    }
    if set(&EVENT) != 0 {
        return Err("setting an event that was not signalled reported it signalled");
    }
    settle(before);
    if WOKE.load(Ordering::Acquire) != 3 {
        return Err("setting a notification event did not wake all three waiters");
    }
    // SAFETY: a static, initialised event.
    let (state, again, reset) = unsafe {
        (
            KeReadStateEvent(EVENT.ptr()),
            wait_event(&EVENT, None),
            KeResetEvent(EVENT.ptr()),
        )
    };
    if state != 1 || again != STATUS_SUCCESS || reset != 1 {
        return Err("a notification event did not stay signalled until reset");
    }
    if wait_event(&EVENT, Some(0)) != STATUS_TIMEOUT {
        return Err("a reset event is still signalled");
    }
    if WRONG.load(Ordering::Relaxed) != 0 {
        return Err("a wait returned the wrong status");
    }
    Ok(3)
}

/// Each setting of a synchronization event lets exactly one waiter
/// through; with none waiting it stays set for the next. Returns the
/// settings made.
pub fn synchronization_test() -> Result<u32, &'static str> {
    let before = thread::count();
    init_event(&EVENT, true, false);
    WOKE.store(0, Ordering::Relaxed);
    WRONG.store(0, Ordering::Relaxed);
    spawn(waiter, 0, 3)?;
    delay_ms(20);
    for expected in 1..=3 {
        if set(&EVENT) != 0 {
            return Err("a synchronization event with waiters was left signalled");
        }
        delay_ms(20);
        if WOKE.load(Ordering::Acquire) != expected {
            return Err("one setting of a synchronization event did not wake exactly one waiter");
        }
    }
    settle(before);
    // Nobody waiting: it stays set, once, for whoever comes next.
    let (first, second) = (set(&EVENT), set(&EVENT));
    let (taken, gone) = (wait_event(&EVENT, Some(0)), wait_event(&EVENT, Some(0)));
    if (first, second) != (0, 1) || (taken, gone) != (STATUS_SUCCESS, STATUS_TIMEOUT) {
        return Err("a synchronization event set with no waiter was not taken exactly once");
    }
    if WRONG.load(Ordering::Relaxed) != 0 {
        return Err("a wait returned the wrong status");
    }
    Ok(5)
}

/// A wait with a time limit returns `STATUS_TIMEOUT`, never early; with
/// no time at all it does not block, even at DISPATCH_LEVEL; and a wait
/// that is satisfied in time leaves no timer behind to disturb the
/// next. Returns the limits tried.
pub fn timeout_test() -> Result<u32, &'static str> {
    fn set_soon(_: usize) {
        delay_ms(5);
        set(&EVENT);
    }
    fn wait_long_then_exit(_: usize) {
        // Satisfied at once, with ten seconds of time limit unused: the
        // thread must not take a pending timer to its grave.
        if wait_event(&REPLY, Some(10_000)) != STATUS_SUCCESS {
            WRONG.fetch_add(1, Ordering::Relaxed);
        }
    }
    let before = thread::count();
    init_event(&EVENT, true, false);
    let limits = [1, 16, 30];
    for &ms in &limits {
        let asked = time::interrupt_time();
        if wait_event(&EVENT, Some(ms)) != STATUS_TIMEOUT {
            return Err("a wait on an unsignalled event did not time out");
        }
        let waited = time::interrupt_time() - asked;
        if waited < ms as u64 * 10_000 {
            return Err("a wait timed out early");
        }
        if waited > ms as u64 * 10_000 + 20 * TIME_INCREMENT {
            return Err("a wait timed out more than twenty ticks late");
        }
    }
    // A system time as the limit.
    let asked = time::interrupt_time();
    // SAFETY: a static, initialised event.
    let status = unsafe {
        wait(
            Some(EVENT.ptr().cast()),
            Some((time::system_time() + 200_000) as i64),
        )
    };
    if status != STATUS_TIMEOUT || time::interrupt_time() - asked < 200_000 {
        return Err("a wait until a system time did not last until then");
    }
    // No time: an answer at once, which is why it is allowed here.
    let old = irql::raise(irql::DISPATCH_LEVEL);
    let unsignalled = wait_event(&EVENT, Some(0));
    set(&EVENT);
    let signalled = wait_event(&EVENT, Some(0));
    irql::lower(old);
    if (unsignalled, signalled) != (STATUS_TIMEOUT, STATUS_SUCCESS) {
        return Err("a wait with no time did not just report the event's state");
    }
    // Satisfied well inside its limit; then the limit's time comes and
    // goes during another wait, which must run its own full length.
    thread::create(set_soon, 0, thread::NORMAL_PRIORITY, thread::ANYWHERE)?;
    let asked = time::interrupt_time();
    if wait_event(&EVENT, Some(50)) != STATUS_SUCCESS {
        return Err("an event set within the time limit did not satisfy the wait");
    }
    // Anything short of the limit: how soon the other thread runs is
    // the host's to say when it is busy.
    if time::interrupt_time() - asked >= 500_000 {
        return Err("a satisfied wait waited out its time limit anyway");
    }
    let asked = time::interrupt_time();
    if wait_event(&EVENT, Some(80)) != STATUS_TIMEOUT || time::interrupt_time() - asked < 800_000 {
        return Err("an earlier wait's time limit cut a later wait short");
    }
    init_event(&REPLY, true, false);
    WRONG.store(0, Ordering::Relaxed);
    thread::create(
        wait_long_then_exit,
        0,
        thread::NORMAL_PRIORITY,
        thread::ANYWHERE,
    )?;
    delay_ms(5);
    set(&REPLY);
    settle(before);
    if WRONG.load(Ordering::Relaxed) != 0 {
        return Err("a wait with a long time limit was not satisfied by its event");
    }
    Ok(limits.len() as u32 + 1)
}

/// What is released to a semaphore is taken exactly once, by however
/// many threads, and the count never passes its limit. Returns the
/// units passed through.
pub fn semaphore_test() -> Result<u64, &'static str> {
    fn taker(_: usize) {
        loop {
            // SAFETY: a static, initialised semaphore.
            if unsafe { wait(Some(SEMAPHORE.ptr().cast()), None) } != STATUS_SUCCESS {
                WRONG.fetch_add(1, Ordering::Relaxed);
            }
            if STOP.load(Ordering::Acquire) {
                return;
            }
            TAKEN.fetch_add(1, Ordering::AcqRel);
        }
    }
    const UNITS: u64 = 3000;
    const TAKERS: usize = 4;
    let before = thread::count();
    let sem = SEMAPHORE.ptr();
    // SAFETY: static storage, not waited on; then an initialised
    // semaphore.
    let start = unsafe {
        KeInitializeSemaphore(sem, 2, 64);
        (
            wait(Some(sem.cast()), Some(0)),
            wait(Some(sem.cast()), Some(0)),
            wait(Some(sem.cast()), Some(0)),
        )
    };
    if start != (STATUS_SUCCESS, STATUS_SUCCESS, STATUS_TIMEOUT) {
        return Err("a semaphore's starting count was not taken exactly that many times");
    }
    TAKEN.store(0, Ordering::Relaxed);
    WRONG.store(0, Ordering::Relaxed);
    STOP.store(false, Ordering::Release);
    spawn(taker, 0, TAKERS)?;
    let mut released = 0;
    while released < UNITS {
        let n = (released % 3 + 1).min(UNITS - released);
        // Stay well under the limit: the takers may lag.
        // SAFETY: a static, initialised semaphore.
        while unsafe { KeReadStateSemaphore(sem) } > 32 {
            thread::yield_now();
        }
        // SAFETY: as above.
        unsafe { KeReleaseSemaphore(sem, 0, n as i32, 0) };
        released += n;
    }
    let deadline = time::interrupt_time() + 50_000_000;
    while TAKEN.load(Ordering::Acquire) < UNITS && time::interrupt_time() < deadline {
        delay_ms(1);
    }
    let taken = TAKEN.load(Ordering::Acquire);
    // SAFETY: as above.
    let left = unsafe { KeReadStateSemaphore(sem) };
    STOP.store(true, Ordering::Release);
    // SAFETY: as above. One unit each to let the takers see the stop.
    unsafe { KeReleaseSemaphore(sem, 0, TAKERS as i32, 0) };
    settle(before);
    if taken != UNITS || left != 0 {
        return Err("units released to a semaphore were lost or taken twice");
    }
    if WRONG.load(Ordering::Relaxed) != 0 {
        return Err("a wait returned the wrong status");
    }
    Ok(taken)
}

/// Two threads on different processors hand a turn back and forth
/// through two events; every hand-over arrives. Returns the round
/// trips.
pub fn ping_pong_test() -> Result<u64, &'static str> {
    fn partner(_: usize) {
        loop {
            wait_event(&EVENT, None);
            if STOP.load(Ordering::Acquire) {
                return;
            }
            TAKEN.fetch_add(1, Ordering::AcqRel);
            set(&REPLY);
        }
    }
    const ROUNDS: u64 = 10_000;
    let before = thread::count();
    init_event(&EVENT, true, false);
    init_event(&REPLY, true, false);
    TAKEN.store(0, Ordering::Relaxed);
    STOP.store(false, Ordering::Release);
    let other = 1 << (smp::online_count() - 1);
    thread::create(partner, 0, thread::NORMAL_PRIORITY, other)?;
    let mut rounds = 0;
    let deadline = time::interrupt_time() + 100_000_000;
    while rounds < ROUNDS && time::interrupt_time() < deadline {
        set(&EVENT);
        if wait_event(&REPLY, Some(2000)) != STATUS_SUCCESS {
            return Err("a hand-over was lost: no reply in two seconds");
        }
        rounds += 1;
    }
    STOP.store(true, Ordering::Release);
    set(&EVENT);
    settle(before);
    if TAKEN.load(Ordering::Acquire) != rounds {
        return Err("the two sides disagree on how many turns were handed over");
    }
    if rounds < 100 {
        return Err("fewer than a hundred round trips in ten seconds");
    }
    Ok(rounds)
}

/// An event is set over and over while another thread waits for it over
/// and over with short time limits, so that settings land before the
/// wait, in the middle of going to sleep, during sleep, and against the
/// time limit. Every setting that found the event unsignalled is taken
/// by exactly one wait, or is still there at the end. Returns those
/// settings.
pub fn race_test() -> Result<u64, &'static str> {
    fn taker(_: usize) {
        while !STOP.load(Ordering::Acquire) {
            if wait_event(&EVENT, Some(1)) == STATUS_SUCCESS {
                TAKEN.fetch_add(1, Ordering::AcqRel);
            }
        }
    }
    let before = thread::count();
    init_event(&EVENT, true, false);
    TAKEN.store(0, Ordering::Relaxed);
    STOP.store(false, Ordering::Release);
    let other = 1 << (smp::online_count() - 1);
    thread::create(taker, 0, thread::NORMAL_PRIORITY, other)?;
    let mut effective = 0u64;
    let until = time::interrupt_time() + 5_000_000;
    let mut round = 0u64;
    while time::interrupt_time() < until {
        if set(&EVENT) == 0 {
            effective += 1;
        }
        round += 1;
        // Now and then let the time limit win.
        match round % 512 {
            0 => delay_ms(20),
            n if n % 7 == 0 => time::stall(n % 40),
            _ => {}
        }
        if pcr::current_processor() == other.trailing_zeros() {
            thread::yield_now();
        }
    }
    STOP.store(true, Ordering::Release);
    settle(before);
    // SAFETY: a static, initialised event.
    let left = unsafe { KeReadStateEvent(EVENT.ptr()) } as u64;
    if TAKEN.load(Ordering::Acquire) + left != effective {
        return Err("settings of an event were lost or taken twice");
    }
    Ok(effective)
}

static NEVER: Slot<KEVENT> = Slot::new();
static GO: Slot<KEVENT> = Slot::new();
/// What the alerted threads' waits returned.
static SAW: [AtomicU32; 2] = [const { AtomicU32::new(0) }; 2];

/// An alertable wait on a test event, the way a driver would call for
/// it; `ms` is a time limit in milliseconds.
fn wait_alertable(event: &Slot<KEVENT>, mode: i8, ms: Option<i64>) -> u32 {
    let due = ms.map(|ms| -ms * 10_000);
    let timeout = due.as_ref().map_or(core::ptr::null(), core::ptr::from_ref);
    // SAFETY: a static, initialised event; the due time is a local.
    unsafe { KeWaitForSingleObject(event.ptr().cast(), 0, mode, 1, timeout) as u32 }
}

/// Alerts as drivers make and meet them: a thread in an alertable wait
/// is woken with `STATUS_ALERTED`, once; a thread that is not keeps
/// the alert for its next alertable wait, which it ends before the
/// object or the time is looked at; waits that are not alertable never
/// see one. Returns the waits made.
pub fn alert_test() -> Result<u32, &'static str> {
    use crate::ob::{handle, object};
    use crate::ps::ZwAlertThread;
    use nk_ntabi::status::{STATUS_INVALID_HANDLE, STATUS_OBJECT_TYPE_MISMATCH};
    const UNSEEN: u32 = 0xAAAA_AAAA;
    fn alerted_waiting(_: usize) {
        // Five seconds stand for "for ever": the test must not hang
        // when the alert does not arrive.
        SAW[0].store(wait_alertable(&NEVER, 0, Some(5_000)), Ordering::Release);
        SAW[1].store(wait_alertable(&NEVER, 0, Some(0)), Ordering::Release);
    }
    fn alerted_before(_: usize) {
        wait_event(&GO, Some(5_000));
        SAW[0].store(wait_alertable(&NEVER, 0, Some(0)), Ordering::Release);
    }
    let start = |entry: thread::Entry| -> Result<(*mut thread::Thread, u64), &'static str> {
        for saw in &SAW {
            saw.store(UNSEEN, Ordering::Release);
        }
        let new = thread::create_referenced(entry, 0, thread::NORMAL_PRIORITY, thread::ANYWHERE)?;
        // SAFETY: a thread this test holds a reference to.
        match unsafe { handle::open(new.cast(), 0x001F_FFFF) } {
            Ok(opened) => Ok((new, opened)),
            Err(_) => Err("no memory for a handle"),
        }
    };
    // Ten seconds for a thread whose own waits end within five: a
    // thread an alert left asleep must fail the test, not hang it.
    let end = |(ended, opened): (*mut thread::Thread, u64)| {
        // SAFETY: a thread this test holds a reference to, which it
        // gives up here.
        unsafe {
            let status = wait(Some(ended.cast()), Some(-100_000_000));
            object::dereference(ended.cast());
            handle::close(opened);
            status
        }
    };
    let alert_me = || ZwAlertThread(-2i64 as *mut c_void);
    let before = thread::count();
    init_event(&NEVER, false, false);
    init_event(&GO, false, false);

    // In an alertable wait: woken, and the alert is used up.
    let waiting = start(alerted_waiting)?;
    delay_ms(20);
    let asked = time::interrupt_time();
    let alerted_it = ZwAlertThread(waiting.1 as *mut c_void);
    let ended = end(waiting);
    let took = time::interrupt_time() - asked;
    let in_wait = [
        SAW[0].load(Ordering::Acquire),
        SAW[1].load(Ordering::Acquire),
    ];

    // In a wait that is not alertable: the wait goes on, and the alert
    // ends the thread's next alertable wait though that has no time.
    let later = start(alerted_before)?;
    delay_ms(20);
    let alerted_later = ZwAlertThread(later.1 as *mut c_void);
    delay_ms(20);
    // SAFETY: a thread this test holds a reference to.
    let still_waiting = unsafe { wait(Some(later.0.cast()), Some(0)) };
    set(&GO);
    let later_ended = end(later);
    let kept = SAW[0].load(Ordering::Acquire);

    // This thread, alerted by itself. A signalled event is not taken
    // by the wait the alert ends.
    init_event(&EVENT, true, true);
    let own = [
        alert_me() as u32,
        wait_alertable(&EVENT, 0, Some(0)),
        wait_alertable(&EVENT, 0, Some(0)),
        wait_alertable(&EVENT, 0, Some(0)),
    ];
    // Two alerts are one; a wait that is not alertable sees none; a
    // kernel-mode alert ends a user-mode wait.
    let twice = [
        alert_me() as u32,
        alert_me() as u32,
        wait_event(&EVENT, Some(0)),
        wait_alertable(&EVENT, 1, Some(0)),
        wait_alertable(&EVENT, 1, Some(0)),
    ];
    // A delay and a wait on several objects are alertable waits too.
    let interval = -300_000i64;
    let objects = [EVENT.ptr().cast::<c_void>(), NEVER.ptr().cast::<c_void>()];
    let none = 0i64;
    let asked = time::interrupt_time();
    // SAFETY: static, initialised events; the times are locals.
    let others = unsafe {
        [
            alert_me() as u32,
            KeDelayExecutionThread(0, 1, &raw const interval) as u32,
            KeDelayExecutionThread(0, 1, &raw const interval) as u32,
            alert_me() as u32,
            KeWaitForMultipleObjects(
                2,
                objects.as_ptr(),
                1,
                0,
                0,
                1,
                &raw const none,
                core::ptr::null_mut(),
            ) as u32,
            alert_me() as u32,
            KeWaitForMultipleObjects(
                2,
                objects.as_ptr(),
                0,
                0,
                0,
                1,
                &raw const none,
                core::ptr::null_mut(),
            ) as u32,
        ]
    };
    let delayed = time::interrupt_time() - asked;
    // What is not a thread cannot be alerted.
    // SAFETY: a fresh event object, which this test gives up.
    let not_a_thread = unsafe {
        let body = object::create(&object::EVENT_TYPE, size_of::<KEVENT>()).ok_or("no memory")?;
        KeInitializeEvent(body.cast(), 0, 0);
        let opened = handle::open(body, 0);
        object::dereference(body);
        let opened = opened.map_err(|_| "no memory for a handle")?;
        let status = ZwAlertThread(opened as *mut c_void);
        handle::close(opened);
        status
    };
    let no_handle = ZwAlertThread(core::ptr::null_mut());

    // Bounded: a thread an alert should have woken may never end, and
    // the checks below then say why.
    let settled = thread::settle_within(before, 100_000_000);
    if alerted_it != 0 || ended != STATUS_SUCCESS || in_wait[0] != STATUS_ALERTED {
        return Err("an alert did not end an alertable wait with STATUS_ALERTED");
    }
    if took > 20_000_000 {
        return Err("an alerted wait went on to its time limit");
    }
    if in_wait[1] != STATUS_TIMEOUT {
        return Err("an alert was not used up by the wait it ended");
    }
    if alerted_later != 0 || still_waiting != STATUS_TIMEOUT || later_ended != STATUS_SUCCESS {
        return Err("an alert disturbed a wait that is not alertable");
    }
    if kept != STATUS_ALERTED {
        return Err("an alert was not kept for the next alertable wait, ahead of its time limit");
    }
    if own != [0, STATUS_ALERTED, STATUS_SUCCESS, STATUS_TIMEOUT] {
        return Err("an alerted wait took its object, or the alert was not looked at first");
    }
    if twice != [0, 0, STATUS_TIMEOUT, STATUS_ALERTED, STATUS_TIMEOUT] {
        return Err("two alerts were not one, or a wait saw an alert it should not");
    }
    if others != [0, STATUS_ALERTED, 0, 0, STATUS_ALERTED, 0, STATUS_ALERTED]
        || !(300_000..3_000_000).contains(&delayed)
    {
        return Err("a delay or a wait on several objects was not alertable");
    }
    if not_a_thread != STATUS_OBJECT_TYPE_MISMATCH || no_handle != STATUS_INVALID_HANDLE {
        return Err("something that is not a thread was alerted");
    }
    if !settled {
        return Err("a thread the test started did not end");
    }
    Ok(19)
}

/// Alerts race with the event a thread waits for and with its time
/// limit, on every processor: each alert that took ends exactly one
/// wait, and no setting of the event is lost to one. Returns the
/// alerts that took.
pub fn alert_race_test() -> Result<u64, &'static str> {
    use crate::ob::object;
    static ALERTS: AtomicU64 = AtomicU64::new(0);
    static SIGNALS: AtomicU64 = AtomicU64::new(0);
    static SETS: AtomicU64 = AtomicU64::new(0);
    fn count(status: u32) {
        match status {
            STATUS_ALERTED => ALERTS.fetch_add(1, Ordering::Relaxed),
            STATUS_SUCCESS => SIGNALS.fetch_add(1, Ordering::Relaxed),
            STATUS_TIMEOUT => 0,
            _ => u64::from(WRONG.fetch_add(1, Ordering::Relaxed)),
        };
    }
    fn waiter(_: usize) {
        while !STOP.load(Ordering::Acquire) {
            count(wait_alertable(&EVENT, 0, Some(1)));
        }
        // What is still there for it: the last setting, the last alert.
        loop {
            let status = wait_alertable(&EVENT, 0, Some(0));
            count(status);
            if status == STATUS_TIMEOUT {
                break;
            }
        }
    }
    fn setter(_: usize) {
        while !STOP.load(Ordering::Acquire) {
            if set(&EVENT) == 0 {
                SETS.fetch_add(1, Ordering::Relaxed);
            }
            thread::yield_now();
        }
    }
    let before = thread::count();
    init_event(&EVENT, true, false);
    STOP.store(false, Ordering::Release);
    for counter in [&ALERTS, &SIGNALS, &SETS] {
        counter.store(0, Ordering::Relaxed);
    }
    WRONG.store(0, Ordering::Relaxed);
    let target = thread::create_referenced(waiter, 0, thread::NORMAL_PRIORITY, thread::ANYWHERE)?;
    let helper = thread::create_referenced(setter, 0, thread::NORMAL_PRIORITY, thread::ANYWHERE)?;
    let mut took = 0u64;
    let until = time::interrupt_time() + 8_000_000;
    while time::interrupt_time() < until {
        for _ in 0..50 {
            // SAFETY: a thread this test holds a reference to.
            if !unsafe { alert(target, 0) } {
                took += 1;
            }
            core::hint::spin_loop();
        }
        thread::yield_now();
    }
    STOP.store(true, Ordering::Release);
    // SAFETY: threads this test holds references to, which it gives up
    // here; the setter has ended before the waiter is let run dry.
    unsafe {
        wait(Some(helper.cast()), None);
        wait(Some(target.cast()), None);
        object::dereference(helper.cast());
        object::dereference(target.cast());
    }
    settle(before);
    if WRONG.load(Ordering::Relaxed) != 0 {
        return Err("a wait returned a status that is none of its three");
    }
    if ALERTS.load(Ordering::Relaxed) != took {
        return Err("alerts that took and waits they ended do not match");
    }
    if SIGNALS.load(Ordering::Relaxed) != SETS.load(Ordering::Relaxed) {
        return Err("a setting of the event was lost or taken twice among the alerts");
    }
    if took == 0 || SETS.load(Ordering::Relaxed) == 0 {
        return Err("the race was not run");
    }
    Ok(took)
}

/// A delay lasts at least as long as asked. Returns the delays tried.
pub fn delay_test() -> Result<u32, &'static str> {
    let delays = [1, 20, 33];
    for &ms in &delays {
        let asked = time::interrupt_time();
        let interval = -ms * 10_000i64;
        // SAFETY: the interval is a local.
        let status = unsafe { KeDelayExecutionThread(0, 0, &raw const interval) };
        let waited = time::interrupt_time() - asked;
        if status != 0 || waited < ms as u64 * 10_000 {
            return Err("a delay returned early");
        }
        if waited > ms as u64 * 10_000 + 20 * TIME_INCREMENT {
            return Err("a delay lasted more than twenty ticks too long");
        }
    }
    // No time at all is not a wait.
    delay_ms(0);
    Ok(delays.len() as u32)
}

/// A wait that must block, at DISPATCH_LEVEL. The system must stop.
pub fn blocked_at_dispatch_test() {
    init_event(&EVENT, true, false);
    let _old = irql::raise(irql::DISPATCH_LEVEL);
    wait_event(&EVENT, None);
}

/// A wait that must block, in a DPC routine. The system must stop. With
/// `lowered` the routine first lowers the IRQL, so the wait is allowed
/// to begin: then the thread switch itself must stop the system.
pub fn blocked_in_dpc_test(lowered: bool) {
    /// # Safety
    /// Called as a DPC routine; it dereferences none of its arguments.
    unsafe extern "C" fn routine(
        _: *mut nk_ntabi::ke::KDPC,
        lowered: *mut c_void,
        _: *mut c_void,
        _: *mut c_void,
    ) {
        if !lowered.is_null() {
            arch::set_irql(irql::PASSIVE_LEVEL);
        }
        wait_event(&EVENT, None);
    }
    static DPC: Slot<nk_ntabi::ke::KDPC> = Slot::new();
    init_event(&EVENT, true, false);
    // SAFETY: static storage for a `KDPC`, not queued.
    unsafe {
        dpc::KeInitializeDpc(
            DPC.ptr(),
            Some(routine),
            core::ptr::without_provenance_mut(usize::from(lowered)),
        );
        dpc::KeInsertQueueDpc(DPC.ptr(), core::ptr::null_mut(), core::ptr::null_mut());
    }
}

static EVENTS: [Slot<KEVENT>; 4] = [const { Slot::new() }; 4];

/// The test events' states as bits, event 0 lowest.
fn states() -> u32 {
    let mut bits = 0;
    for (index, event) in EVENTS.iter().enumerate() {
        // SAFETY: static, initialised events.
        if unsafe { KeReadStateEvent(event.ptr()) } != 0 {
            bits |= 1 << index;
        }
    }
    bits
}

fn set_event(index: usize) -> i32 {
    set(&EVENTS[index])
}

/// Wait on the first `count` test events, as a driver would call for
/// it, with wait blocks of the caller's own; `ms` is a time limit.
fn wait_events(count: usize, all: bool, ms: Option<i64>) -> u32 {
    let objects: [*mut c_void; 4] = core::array::from_fn(|i| EVENTS[i].ptr().cast());
    // A driver's wait blocks are whatever was on its stack. Fill them
    // with the worst case: every byte says "linked", every pointer is
    // wild. The kernel must look only at blocks it linked itself.
    let mut blocks = MaybeUninit::<[KWAIT_BLOCK; 4]>::uninit();
    // SAFETY: plain bytes into local storage.
    unsafe {
        blocks.as_mut_ptr().cast::<u8>().write_bytes(
            nk_ntabi::ke::WAIT_BLOCK_ACTIVE,
            size_of::<[KWAIT_BLOCK; 4]>(),
        );
    }
    let due = ms.map(|ms| -ms * 10_000);
    let timeout = due.as_ref().map_or(core::ptr::null(), core::ptr::from_ref);
    // SAFETY: static, initialised events; the due time and the blocks
    // are locals that outlive the call.
    unsafe {
        KeWaitForMultipleObjects(
            count as u32,
            objects.as_ptr(),
            u32::from(!all),
            0,
            0,
            0,
            timeout,
            blocks.as_mut_ptr().cast(),
        ) as u32
    }
}

fn init_events() {
    for event in &EVENTS {
        init_event(event, true, false);
    }
}

/// A wait for any of several objects reports the first that is
/// signalled, in the order given, and takes only that one.
pub fn any_test() -> Result<(), &'static str> {
    init_events();
    if wait_events(3, false, Some(0)) != STATUS_TIMEOUT {
        return Err("a wait for any of three unsignalled events did not time out");
    }
    set_event(1);
    if (wait_events(3, false, Some(0)), states()) != (1, 0) {
        return Err("a wait for any did not report and take the one signalled event");
    }
    set_event(2);
    set_event(0);
    if (wait_events(3, false, Some(0)), states()) != (0, 0b100) {
        return Err("a wait for any did not take the first signalled event and leave the other");
    }
    // The built-in blocks serve up to three objects.
    let objects: [*mut c_void; 3] = core::array::from_fn(|i| EVENTS[i].ptr().cast());
    let none = 0i64;
    // SAFETY: static, initialised events; the due time is a local.
    let status = unsafe {
        KeWaitForMultipleObjects(
            3,
            objects.as_ptr(),
            1,
            0,
            0,
            0,
            &raw const none,
            core::ptr::null_mut(),
        )
    };
    if (status, states()) != (2, 0) {
        return Err("a wait for any with the thread's own wait blocks went wrong");
    }
    Ok(())
}

/// A wait for all of several objects takes all of them or none.
pub fn all_test() -> Result<(), &'static str> {
    init_events();
    set_event(2);
    if (wait_events(3, true, Some(0)), states()) != (STATUS_TIMEOUT, 0b100) {
        return Err("a wait for all took an object though not all were signalled");
    }
    if (wait_events(3, true, Some(20)), states()) != (STATUS_TIMEOUT, 0b100) {
        return Err("a wait for all that timed out took an object");
    }
    set_event(0);
    set_event(1);
    if (wait_events(3, true, Some(0)), states()) != (STATUS_SUCCESS, 0) {
        return Err("a wait for all did not take all three signalled events");
    }
    // The same object twice can never be had twice at once.
    let twice: [*mut c_void; 2] = [EVENTS[0].ptr().cast(); 2];
    let none = 0i64;
    // SAFETY: a static, initialised event; the due time is a local.
    let status = unsafe {
        KeWaitForMultipleObjects(
            2,
            twice.as_ptr(),
            0,
            0,
            0,
            0,
            &raw const none,
            core::ptr::null_mut(),
        )
    };
    if status != nk_ntabi::status::STATUS_INVALID_PARAMETER {
        return Err("a wait for all of the same object twice was not refused");
    }
    Ok(())
}

/// Blocking waits on four objects: a wait for any returns when another
/// thread sets one; a wait for all only when all four have been set,
/// one after another; and a wait for all that runs out of time leaves
/// what was set. Returns the waits made.
pub fn blocking_many_test() -> Result<u32, &'static str> {
    /// Set `count` events from `first` up, 15 ms apart.
    fn setter(packed: usize) {
        let (first, count) = (packed >> 8, packed & 0xFF);
        for index in first..first + count {
            delay_ms(15);
            set_event(index);
        }
    }
    let before = thread::count();
    init_events();
    thread::create(
        setter,
        3 << 8 | 1,
        thread::NORMAL_PRIORITY,
        thread::ANYWHERE,
    )?;
    if (wait_events(4, false, None), states()) != (3, 0) {
        return Err("a blocking wait for any did not report the event another thread set");
    }
    settle(before);
    let started = time::interrupt_time();
    thread::create(setter, 4, thread::NORMAL_PRIORITY, thread::ANYWHERE)?;
    if (wait_events(4, true, None), states()) != (STATUS_SUCCESS, 0) {
        return Err("a blocking wait for all did not take all four events");
    }
    if time::interrupt_time() - started < 600_000 {
        return Err("a wait for all returned before the last object was set");
    }
    settle(before);
    // Three of four set, and time runs out.
    thread::create(setter, 3, thread::NORMAL_PRIORITY, thread::ANYWHERE)?;
    if wait_events(4, true, Some(120)) != STATUS_TIMEOUT {
        return Err("a wait for all succeeded with one object never set");
    }
    settle(before);
    if states() != 0b0111 {
        return Err("a wait for all that timed out took objects");
    }
    Ok(3)
}

/// Two threads each wait for both of two events, over and over, while a
/// third sets the events. A wait for all takes one setting of each or
/// neither: at the end every setting that found its event unsignalled
/// is accounted for, per event. Returns the waits that succeeded.
pub fn all_race_test() -> Result<u64, &'static str> {
    fn taker(_: usize) {
        while !STOP.load(Ordering::Acquire) {
            if wait_events(2, true, Some(1)) == STATUS_SUCCESS {
                TAKEN.fetch_add(1, Ordering::AcqRel);
            }
        }
    }
    let before = thread::count();
    init_events();
    TAKEN.store(0, Ordering::Relaxed);
    STOP.store(false, Ordering::Release);
    spawn(taker, 0, 2)?;
    let mut effective = [0u64; 2];
    let until = time::interrupt_time() + 5_000_000;
    let mut round = 0usize;
    while time::interrupt_time() < until {
        let which = round % 2;
        if set_event(which) == 0 {
            effective[which] += 1;
        }
        round += 1;
        match round % 512 {
            0 => delay_ms(20),
            n if n % 5 == 0 => time::stall((n % 30) as u64),
            _ => {}
        }
        if round % 64 == 0 {
            thread::yield_now();
        }
    }
    STOP.store(true, Ordering::Release);
    settle(before);
    let taken = TAKEN.load(Ordering::Acquire);
    let left = states();
    for (which, &set) in effective.iter().enumerate() {
        if taken + u64::from(left >> which & 1) != set {
            return Err("a wait for all took one event without the other");
        }
    }
    Ok(taken)
}
