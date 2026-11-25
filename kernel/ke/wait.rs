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

#![allow(non_snake_case)]

use super::object::{self, ObjectLock};
use super::{dpc, irql, thread, timer};
use crate::arch;
use core::ffi::c_void;
use core::sync::atomic::Ordering;
use nk_ntabi::ke::{
    DISPATCHER_HEADER, EVENT_NOTIFICATION_OBJECT, EVENT_SYNCHRONIZATION_OBJECT, KEVENT, KSEMAPHORE,
    KWAIT_BLOCK, SEMAPHORE_OBJECT, WAIT_BLOCK_INACTIVE,
};
use nk_ntabi::thread::TIMER_WAIT_BLOCK;

pub const STATUS_SUCCESS: u32 = 0;
/// The wait's time limit passed first.
pub const STATUS_TIMEOUT: u32 = 0x102;

/// `WAIT_TYPE`: `WaitAny`.
const WAIT_ANY: u8 = 1;

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
unsafe fn prepare(block: *mut KWAIT_BLOCK, object: *mut DISPATCHER_HEADER, key: u32) {
    // SAFETY: per the contract. Field by field: the spare fields of a
    // thread's built-in blocks hold other things.
    unsafe {
        (&raw mut (*block).WaitType).write(WAIT_ANY);
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

/// Wait until `object` (if any) is signalled or `timeout` (if any)
/// passes: a negative timeout is that many 100 ns units from now, a
/// positive one a system time. Returns `STATUS_SUCCESS` or
/// `STATUS_TIMEOUT`.
///
/// # Safety
/// `object` is a live dispatcher object that stays valid until this
/// returns.
pub unsafe fn wait(object: Option<*mut DISPATCHER_HEADER>, timeout: Option<i64>) -> u32 {
    let old = irql::current();
    if old > irql::DISPATCH_LEVEL {
        must_be_able_to_block(old);
    }
    arch::set_irql(irql::DISPATCH_LEVEL);
    let me = thread::current();
    let register = thread::wait_register(me);
    let object_block = thread::wait_block(me, 0);
    let timer_block = thread::wait_block(me, TIMER_WAIT_BLOCK);
    let my_timer = thread::timer(me);
    // SAFETY: per the contract for `object`; the blocks and the timer
    // are the running thread's own.
    unsafe {
        match object {
            Some(object) => {
                let _lock = ObjectLock::take(object);
                let taken = object::try_take(object);
                if taken || timeout == Some(0) {
                    drop(_lock);
                    arch::set_irql(old);
                    return if taken {
                        STATUS_SUCCESS
                    } else {
                        STATUS_TIMEOUT
                    };
                }
                must_be_able_to_block(old);
                // From here wakers can find the thread.
                register.begin();
                prepare(object_block, object, STATUS_SUCCESS);
                object::link(object, object_block);
            }
            None => {
                must_be_able_to_block(old);
                register.begin();
            }
        }
        if let Some(due) = timeout {
            // Set first, then look: setting clears what an earlier
            // expiry may have left, and a timer that has already gone
            // off by the time its block would be linked ends the wait
            // here instead.
            timer::KeSetTimer(my_timer, due, core::ptr::null_mut());
            let header = &raw mut (*my_timer).Header;
            let _lock = ObjectLock::take(header);
            if object::signal(header).load(Ordering::Relaxed) > 0 {
                let _ = register.claim(STATUS_TIMEOUT);
            } else {
                prepare(timer_block, header, STATUS_TIMEOUT);
                object::link(header, timer_block);
            }
        }

        thread::sleep();

        let status = register
            .status()
            .expect("a thread woke from a wait that nothing ended");
        if timeout.is_some() {
            // Not just cancelled: an expiry of this timer may be under
            // way on another processor, and once this wait returns the
            // thread, timer and all, may be freed.
            timer::cancel_and_settle(my_timer);
            withdraw(&raw mut (*my_timer).Header, timer_block);
        }
        if let Some(object) = object {
            withdraw(object, object_block);
        }
        register.finish();
        thread::set_wait_status(me, status);
        arch::set_irql(old);
        status
    }
}

/// Start the running thread's wait blocks off as unlinked. Once per
/// thread, before its first wait.
///
/// # Safety
/// `thread` is a thread being created.
pub unsafe fn init_thread(thread: *mut thread::Thread) {
    // SAFETY: per the contract.
    unsafe {
        for index in [0, TIMER_WAIT_BLOCK] {
            (&raw mut (*thread::wait_block(thread, index)).BlockState).write(WAIT_BLOCK_INACTIVE);
        }
        timer::KeInitializeTimer(thread::timer(thread));
    }
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
            match previous.checked_add(adjustment) {
                Some(count) if count > previous && count <= limit => {
                    state.store(count, Ordering::Relaxed);
                }
                _ => crate::kd::bugcheck(format_args!(
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

/// [`KeReadStateSemaphore`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-kereadstatesemaphore).
///
/// # Safety
/// `semaphore` is a live, initialised `KSEMAPHORE`.
pub unsafe extern "C" fn KeReadStateSemaphore(semaphore: *mut KSEMAPHORE) -> i32 {
    // SAFETY: per the contract.
    unsafe { object::signal(&raw mut (*semaphore).Header).load(Ordering::Acquire) }
}

/// [`KeWaitForSingleObject`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-kewaitforsingleobject).
/// Waits are not alertable and take no APCs yet: there are none.
///
/// # Safety
/// `object` is a live dispatcher object that stays valid until this
/// returns; `timeout` is null or points to a due time.
pub unsafe extern "C" fn KeWaitForSingleObject(
    object: *mut c_void,
    _wait_reason: u32,
    _wait_mode: i8,
    _alertable: u8,
    timeout: *const i64,
) -> i32 {
    // SAFETY: per the contract.
    unsafe {
        let timeout = (!timeout.is_null()).then(|| timeout.read_unaligned());
        wait(Some(object.cast()), timeout) as i32
    }
}

/// [`KeDelayExecutionThread`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-kedelayexecutionthread).
///
/// # Safety
/// `interval` points to a due time.
pub unsafe extern "C" fn KeDelayExecutionThread(
    _wait_mode: i8,
    _alertable: u8,
    interval: *const i64,
) -> i32 {
    // SAFETY: per the contract; no object is involved.
    unsafe {
        wait(None, Some(interval.read_unaligned()));
    }
    STATUS_SUCCESS as i32
}

// ---- tests --------------------------------------------------------------

use super::{pcr, smp, time};
use crate::test::Slot;
use core::sync::atomic::{AtomicBool, AtomicU32, AtomicU64};
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

/// Sleep until only `threads` threads exist; `false` after three
/// seconds.
fn settle(threads: u32) -> bool {
    let deadline = time::interrupt_time() + 30_000_000;
    while thread::count() != threads {
        if time::interrupt_time() > deadline {
            return false;
        }
        delay_ms(1);
    }
    true
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
    if !settle(before) || WOKE.load(Ordering::Acquire) != 3 {
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
    if !settle(before) {
        return Err("the waiters did not finish");
    }
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
    if time::interrupt_time() - asked > 400_000 {
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
    if !settle(before) {
        return Err("the helper threads did not finish");
    }
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
    if !settle(before) {
        return Err("the takers did not finish");
    }
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
    if !settle(before) {
        return Err("the partner did not finish");
    }
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
    if !settle(before) {
        return Err("the taker did not finish");
    }
    // SAFETY: a static, initialised event.
    let left = unsafe { KeReadStateEvent(EVENT.ptr()) } as u64;
    if TAKEN.load(Ordering::Acquire) + left != effective {
        return Err("settings of an event were lost or taken twice");
    }
    Ok(effective)
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

/// A wait that must block, in a DPC routine. The system must stop.
pub fn blocked_in_dpc_test() {
    /// # Safety
    /// Called as a DPC routine; it dereferences none of its arguments.
    unsafe extern "C" fn routine(
        _: *mut nk_ntabi::ke::KDPC,
        _: *mut c_void,
        _: *mut c_void,
        _: *mut c_void,
    ) {
        wait_event(&EVENT, None);
    }
    static DPC: Slot<nk_ntabi::ke::KDPC> = Slot::new();
    init_event(&EVENT, true, false);
    // SAFETY: static storage for a `KDPC`, not queued.
    unsafe {
        dpc::KeInitializeDpc(DPC.ptr(), Some(routine), core::ptr::null_mut());
        dpc::KeInsertQueueDpc(DPC.ptr(), core::ptr::null_mut(), core::ptr::null_mut());
    }
}
