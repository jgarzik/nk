//! Kernel timers.
//!
//! Each processor has a table of pending timers (`nk_ke::TimerBuckets`).
//! A timer goes into the table of the processor that set it. The clock
//! tick looks, without taking a lock, at the published earliest due time
//! of each bucket whose tick has come; if one is due it queues that
//! processor's expiry DPC, which takes the due timers out, marks them
//! signalled, re-inserts the periodic ones and queues their DPCs.
//!
//! A timer never fires before its due time; it fires at the first clock
//! tick after it, so up to one tick late.
//!
//! The driver owns the `KTIMER`. Two locks cover it:
//!
//! - the timer's own lock, bit 7 of its header's type byte, serialises
//!   set and cancel on one timer;
//! - the table's lock owns whether the timer is in the table: its links,
//!   `DueTime`, `Processor` and the `Inserted` bit. The DPC pointer and
//!   the period are written only while the timer is in no table, and read
//!   by expiry only while it is in one.
//!
//! Order: timer, then table (`doc/LOCKING.md`). No two tables are held
//! together.

#![allow(non_snake_case)]

use super::object::{self, ObjectLock};
use super::{Rank, SpinLock, dpc, irql, pcr, time};
use crate::arch;
use core::cell::UnsafeCell;
use core::ffi::c_void;
use core::mem::offset_of;
use core::sync::atomic::{AtomicI32, AtomicU8, AtomicU64, Ordering};
use nk_ke::{ListEntry, TIMER_BUCKETS, TimerBuckets, hands_to_check, ticks_in, timer_hand};
use nk_ntabi::ke::{
    DISPATCHER_HEADER, KDPC, KTIMER, LIST_ENTRY, TIMER_EXPIRED, TIMER_INSERTED,
    TIMER_NOTIFICATION_OBJECT,
};

/// One processor's pending timers.
pub struct Table {
    buckets: SpinLock<TimerBuckets>,
    /// The earliest due time in each bucket, `u64::MAX` when empty: what
    /// the clock tick reads.
    earliest: [AtomicU64; TIMER_BUCKETS],
    /// The clock tick up to which expiry has looked.
    checked: AtomicU64,
    /// The DPC that expires this processor's timers.
    expiry: UnsafeCell<KDPC>,
}

impl Table {
    pub const fn new() -> Self {
        Self {
            buckets: SpinLock::new(Rank::TimerTable, TimerBuckets::new()),
            earliest: [const { AtomicU64::new(u64::MAX) }; TIMER_BUCKETS],
            checked: AtomicU64::new(0),
            expiry: UnsafeCell::new(KDPC {
                Type: nk_ntabi::ke::DPC_OBJECT,
                Importance: nk_ntabi::ke::MEDIUM_IMPORTANCE,
                Number: 0,
                DpcListEntry: nk_ntabi::ke::SINGLE_LIST_ENTRY {
                    Next: core::ptr::null_mut(),
                },
                ProcessorHistory: 0,
                DeferredRoutine: Some(expire),
                DeferredContext: core::ptr::null_mut(),
                SystemArgument1: core::ptr::null_mut(),
                SystemArgument2: core::ptr::null_mut(),
                DpcData: core::ptr::null_mut(),
            }),
        }
    }
}

/// The timer a table link belongs to.
fn timer_of(link: *mut ListEntry) -> *mut KTIMER {
    link.wrapping_byte_sub(offset_of!(KTIMER, TimerListEntry))
        .cast()
}

fn link_of(timer: *mut KTIMER) -> *mut ListEntry {
    const { assert!(size_of::<ListEntry>() == size_of::<LIST_ENTRY>()) };
    timer
        .wrapping_byte_add(offset_of!(KTIMER, TimerListEntry))
        .cast()
}

/// The due time of a listed timer, given its link.
fn due_of(link: *mut ListEntry) -> u64 {
    // SAFETY: called by the table on links of listed timers, which their
    // owners keep valid while listed, under the table's lock, which owns
    // `DueTime`.
    unsafe { (&raw const (*timer_of(link)).DueTime).read() }
}

/// # Safety
/// `timer` points to a live `KTIMER`.
unsafe fn misc_flags<'a>(timer: *mut KTIMER) -> &'a AtomicU8 {
    // SAFETY: per the contract.
    unsafe { AtomicU8::from_ptr(&raw mut (*timer).Header.TimerMiscFlags) }
}

/// # Safety
/// `timer` points to a live `KTIMER`.
unsafe fn signal<'a>(timer: *mut KTIMER) -> &'a AtomicI32 {
    // SAFETY: per the contract.
    unsafe { AtomicI32::from_ptr(&raw mut (*timer).Header.SignalState) }
}

/// Take a timer's own lock.
///
/// # Safety
/// `timer` points to a `KTIMER` that stays valid while the lock is held.
unsafe fn lock(timer: *mut KTIMER) -> ObjectLock {
    // SAFETY: per the contract; a timer begins with its header.
    unsafe { ObjectLock::take(&raw mut (*timer).Header) }
}

/// Take `timer` out of whatever table it is in. Returns whether it was
/// in one.
///
/// # Safety
/// `timer` is live and its own lock is held.
unsafe fn withdraw(timer: *mut KTIMER) -> bool {
    // SAFETY: per the contract throughout. With the timer's lock held
    // nothing else inserts it, so once seen in a table it stays in that
    // table until expiry there, under that table's lock, takes it out.
    unsafe {
        if misc_flags(timer).load(Ordering::Acquire) & TIMER_INSERTED == 0 {
            return false;
        }
        let processor = usize::from((&raw const (*timer).Processor).read());
        let Some(table) = arch::percpu_of(processor).map(|p| p.timers()) else {
            return false;
        };
        let mut buckets = table.buckets.lock();
        if misc_flags(timer).load(Ordering::Acquire) & TIMER_INSERTED == 0 {
            // It expired while this processor waited for the table.
            return false;
        }
        let due = (&raw const (*timer).DueTime).read();
        let earliest = buckets.remove(link_of(timer), due, due_of);
        table.earliest[timer_hand(due)].store(earliest, Ordering::Release);
        misc_flags(timer).fetch_and(!TIMER_INSERTED, Ordering::Release);
        true
    }
}

/// Put `timer` in this processor's table, due at `due`.
///
/// # Safety
/// `timer` is live, in no table, and stays valid while it is in one; the
/// caller is at `DISPATCH_LEVEL` or above. `buckets` is the lock of
/// `table`, which is this processor's.
unsafe fn insert(table: &Table, buckets: &mut TimerBuckets, timer: *mut KTIMER, due: u64) {
    // SAFETY: per the contract; these fields belong to the table's lock.
    unsafe {
        (&raw mut (*timer).DueTime).write(due);
        (&raw mut (*timer).Processor).write(pcr::current_processor() as u16);
        (&raw mut (*timer).Header.Hand).write(timer_hand(due) as u8);
        let earliest = buckets.insert(link_of(timer), due, due_of);
        table.earliest[timer_hand(due)].store(earliest, Ordering::Release);
        misc_flags(timer).fetch_or(TIMER_INSERTED, Ordering::Release);
    }
}

/// Queue a timer's DPC, if it has one, with the system time as its
/// arguments, as Windows does.
///
/// # Safety
/// `timer_dpc` is null or a live, initialised `KDPC`.
unsafe fn fire(timer_dpc: *mut KDPC) {
    if !timer_dpc.is_null() {
        let now = time::system_time();
        // SAFETY: per the contract.
        unsafe {
            dpc::KeInsertQueueDpc(
                timer_dpc,
                (now as u32 as usize) as *mut c_void,
                ((now >> 32) as usize) as *mut c_void,
            );
        }
    }
}

/// Called from the clock tick: if a timer of this processor is due,
/// queue the DPC that expires them.
pub fn tick(now: u64) {
    let table = arch::percpu().timers();
    let checked = table.checked.load(Ordering::Relaxed);
    if hands_to_check(checked, ticks_in(now))
        .any(|hand| table.earliest[hand].load(Ordering::Acquire) <= now)
    {
        // SAFETY: the expiry DPC is this processor's own, lives for
        // ever, and is only ever queued here.
        unsafe {
            dpc::KeInsertQueueDpc(
                table.expiry.get(),
                core::ptr::null_mut(),
                core::ptr::null_mut(),
            );
        }
    }
}

/// The expiry DPC: take out every timer of this processor that is due.
///
/// # Safety
/// Called as a DPC routine; it dereferences none of its arguments.
unsafe extern "C" fn expire(_: *mut KDPC, _: *mut c_void, _: *mut c_void, _: *mut c_void) {
    let table = arch::percpu().timers();
    let now = time::interrupt_time();
    let now_tick = ticks_in(now);
    let checked = table.checked.load(Ordering::Relaxed);
    for hand in hands_to_check(checked, now_tick) {
        loop {
            let (timer_dpc, expired);
            {
                let mut buckets = table.buckets.lock();
                // SAFETY: listed timers are kept valid by their owners.
                let Some((link, earliest)) = (unsafe { buckets.pop_due(hand, now, due_of) }) else {
                    break;
                };
                table.earliest[hand].store(earliest, Ordering::Release);
                let timer = timer_of(link);
                // SAFETY: as above; the timer was in this table, so
                // these fields are this lock's to read and write.
                unsafe {
                    timer_dpc = (&raw const (*timer).Dpc).read();
                    let period = (&raw const (*timer).Period).read();
                    // It has gone off, and nobody has set it since.
                    misc_flags(timer).fetch_or(TIMER_EXPIRED, Ordering::Release);
                    expired = timer;
                    if period == 0 {
                        misc_flags(timer).fetch_and(!TIMER_INSERTED, Ordering::Release);
                    } else {
                        // Before its DPC is queued: the DPC may cancel it.
                        let due = (&raw const (*timer).DueTime).read();
                        let next = (due + u64::from(period) * 10_000).max(now + 1);
                        insert(table, &mut buckets, timer, next);
                    }
                }
            }
            // Signal it and wake its waiters, under its own lock, unless
            // it was set again in the meantime: then this expiry is
            // history. Then its DPC, after which the timer is not
            // touched again: the DPC may free it.
            // SAFETY: a timer that has gone off stays valid until its
            // DPC has run (Windows asks the same of drivers); the DPC
            // pointer was read while the timer was listed.
            unsafe {
                let woken = {
                    let _lock = lock(expired);
                    let flags = misc_flags(expired);
                    if flags.fetch_and(!TIMER_EXPIRED, Ordering::AcqRel) & TIMER_EXPIRED != 0 {
                        signal(expired).store(1, Ordering::Release);
                        object::satisfy(&raw mut (*expired).Header)
                    } else {
                        object::Woken::none()
                    }
                };
                woken.ready();
                fire(timer_dpc);
            }
        }
    }
    table.checked.store(now_tick, Ordering::Relaxed);
}

/// Whether `timer` is in a timer table, or has been taken out of one by
/// an expiry that has not finished with it.
///
/// # Safety
/// `timer` points to a live `KTIMER`.
pub unsafe fn pending(timer: *mut KTIMER) -> bool {
    // SAFETY: per the contract.
    unsafe { misc_flags(timer) }.load(Ordering::Acquire) & (TIMER_INSERTED | TIMER_EXPIRED) != 0
}

/// Cancel `timer` and do not return while an expiry is still working on
/// it: afterwards nothing in the kernel refers to the timer, and its
/// memory may go. For timers NK owns (a thread's wait timer); a driver's
/// timer has Windows' contract instead.
///
/// Expiry takes a due timer out of its table and marks it expired under
/// the table's lock, then signals it under the timer's own lock, where
/// it clears the mark, and does not touch it after letting that lock go.
/// So once the timer is out of every table: a mark means an expiry is on
/// its way, and taking the timer's lock after the mark is gone waits out
/// one that is finishing. The expiry runs in a DPC, which thread code at
/// `DISPATCH_LEVEL` on the same processor cannot have interrupted, so
/// the one being waited for is on another processor and will finish.
///
/// # Safety
/// `timer` is a live `KTIMER` with no DPC, which nothing else sets.
pub unsafe fn cancel_and_settle(timer: *mut KTIMER) {
    // SAFETY: per the contract.
    unsafe {
        KeCancelTimer(timer);
        while misc_flags(timer).load(Ordering::Acquire) & TIMER_EXPIRED != 0 {
            core::hint::spin_loop();
        }
        drop(lock(timer));
    }
}

/// [`KeInitializeTimer`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-keinitializetimer).
///
/// # Safety
/// `timer` points to writable storage for a `KTIMER`.
pub unsafe extern "C" fn KeInitializeTimer(timer: *mut KTIMER) {
    // SAFETY: per the contract. The wait list is empty: it points at
    // itself.
    unsafe {
        let waiters = &raw mut (*timer).Header.WaitListHead;
        object::init_wait_list(&raw mut (*timer).Header);
        timer.write(KTIMER {
            Header: DISPATCHER_HEADER {
                Type: TIMER_NOTIFICATION_OBJECT,
                TimerControlFlags: 0,
                Hand: 0,
                TimerMiscFlags: 0,
                SignalState: 0,
                WaitListHead: LIST_ENTRY {
                    Flink: waiters,
                    Blink: waiters,
                },
            },
            DueTime: 0,
            TimerListEntry: LIST_ENTRY {
                Flink: core::ptr::null_mut(),
                Blink: core::ptr::null_mut(),
            },
            Dpc: core::ptr::null_mut(),
            Processor: 0,
            TimerType: 0,
            Period: 0,
        });
    }
}

/// [`KeSetTimerEx`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-kesettimerex).
/// Returns whether the timer was already pending.
///
/// # Safety
/// `timer` was set up by `KeInitializeTimer` and stays valid while it is
/// pending; `timer_dpc` is null or an initialised `KDPC` that stays valid
/// as long as the timer can fire.
pub unsafe extern "C" fn KeSetTimerEx(
    timer: *mut KTIMER,
    due_time: i64,
    period: i32,
    timer_dpc: *mut KDPC,
) -> u8 {
    // SAFETY: per the contract throughout.
    unsafe {
        let timer_lock = lock(timer);
        let was_pending = withdraw(timer);
        // In no table now, so these are this call's to write. An expiry
        // still on its way to signal the timer finds it set anew.
        (&raw mut (*timer).Dpc).write(timer_dpc);
        (&raw mut (*timer).Period).write(period.max(0) as u32);
        misc_flags(timer).fetch_and(!TIMER_EXPIRED, Ordering::Release);
        signal(timer).store(0, Ordering::Release);

        let now = time::interrupt_time();
        // Negative: that long from now. Otherwise a system time.
        let due = if due_time < 0 {
            now.saturating_add(due_time.unsigned_abs())
        } else {
            (due_time as u64).saturating_sub(time::boot_time())
        };
        let table = arch::percpu().timers();
        if due > now {
            insert(table, &mut table.buckets.lock(), timer, due);
        } else {
            // Already due: it fires here and now.
            signal(timer).store(1, Ordering::Release);
            let woken = object::satisfy(&raw mut (*timer).Header);
            if period > 0 {
                let next = now + period as u64 * 10_000;
                insert(table, &mut table.buckets.lock(), timer, next);
            }
            drop(timer_lock);
            woken.ready();
            fire(timer_dpc);
        }
        u8::from(was_pending)
    }
}

/// [`KeSetTimer`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-kesettimer).
///
/// # Safety
/// As `KeSetTimerEx`.
pub unsafe extern "C" fn KeSetTimer(timer: *mut KTIMER, due_time: i64, timer_dpc: *mut KDPC) -> u8 {
    // SAFETY: per the contract.
    unsafe { KeSetTimerEx(timer, due_time, 0, timer_dpc) }
}

/// [`KeCancelTimer`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-kecanceltimer).
/// Returns whether the timer was pending. Its DPC may still be queued or
/// running.
///
/// # Safety
/// `timer` is a live `KTIMER` set up by `KeInitializeTimer`.
pub unsafe extern "C" fn KeCancelTimer(timer: *mut KTIMER) -> u8 {
    // SAFETY: per the contract.
    unsafe {
        let _lock = lock(timer);
        u8::from(withdraw(timer))
    }
}

/// [`KeReadStateTimer`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-kereadstatetimer).
///
/// # Safety
/// `timer` is a live `KTIMER`.
pub unsafe extern "C" fn KeReadStateTimer(timer: *mut KTIMER) -> u8 {
    // SAFETY: per the contract.
    u8::from(unsafe { signal(timer) }.load(Ordering::Acquire) != 0)
}

// ---- tests --------------------------------------------------------------

use core::sync::atomic::AtomicU32;
use nk_ke::TIME_INCREMENT;

/// A timer and its DPC, the kernel's own, for the tests.
struct TestTimer(UnsafeCell<core::mem::MaybeUninit<(KTIMER, KDPC)>>);

// SAFETY: accessed only through the timer and DPC routines, by pointer,
// as a driver's would be.
unsafe impl Sync for TestTimer {}

static TEST: TestTimer = TestTimer(UnsafeCell::new(core::mem::MaybeUninit::uninit()));
static FIRED: AtomicU32 = AtomicU32::new(0);
/// Interrupt time, and processor, of the last firing.
static FIRED_AT: AtomicU64 = AtomicU64::new(0);
static FIRED_ON: AtomicU32 = AtomicU32::new(0);
/// How many more times the DPC should set the timer again itself.
static CHAIN: AtomicU32 = AtomicU32::new(0);

fn test_timer() -> *mut KTIMER {
    TEST.0.get().cast()
}

fn test_dpc() -> *mut KDPC {
    // SAFETY: the offset of the second field of the static pair.
    unsafe { &raw mut (*TEST.0.get().cast::<(KTIMER, KDPC)>()).1 }
}

/// 100 ns units for `ms` milliseconds from now, as a due time.
const fn in_ms(ms: i64) -> i64 {
    -ms * 10_000
}

/// # Safety
/// Called as a DPC routine; it dereferences none of its arguments.
unsafe extern "C" fn fired(_: *mut KDPC, _: *mut c_void, _: *mut c_void, _: *mut c_void) {
    FIRED_AT.store(time::interrupt_time(), Ordering::Relaxed);
    FIRED_ON.store(pcr::current_processor(), Ordering::Relaxed);
    if CHAIN
        .try_update(Ordering::Relaxed, Ordering::Relaxed, |n| n.checked_sub(1))
        .is_ok()
    {
        // SAFETY: the test timer and DPC are static and initialised.
        unsafe { KeSetTimer(test_timer(), in_ms(1), test_dpc()) };
    }
    FIRED.fetch_add(1, Ordering::Release);
}

fn prepare() {
    // SAFETY: static storage; the timer is pending in no table (every
    // test cancels before it returns).
    unsafe {
        KeInitializeTimer(test_timer());
        dpc::KeInitializeDpc(test_dpc(), Some(fired), core::ptr::null_mut());
    }
    FIRED.store(0, Ordering::Relaxed);
    CHAIN.store(0, Ordering::Relaxed);
}

fn set(due: i64, period: i32) -> bool {
    // SAFETY: the test timer and DPC are static and initialised.
    unsafe { KeSetTimerEx(test_timer(), due, period, test_dpc()) != 0 }
}

fn cancel() -> bool {
    // SAFETY: as above.
    unsafe { KeCancelTimer(test_timer()) != 0 }
}

fn signalled() -> bool {
    // SAFETY: as above.
    unsafe { KeReadStateTimer(test_timer()) != 0 }
}

/// Wait up to `ms` milliseconds for `wanted` firings; returns the count.
fn await_fired(wanted: u32, ms: u64) -> u32 {
    let deadline = time::interrupt_time() + ms * 10_000;
    while FIRED.load(Ordering::Acquire) < wanted && time::interrupt_time() < deadline {
        core::hint::spin_loop();
    }
    FIRED.load(Ordering::Acquire)
}

/// A timer fires once, never before its time and not long after, for a
/// spread of delays around the tick length. Returns the delays tried.
pub fn never_early_test() -> Result<u32, &'static str> {
    let delays = [1, 5, 15, 16, 17, 31, 47, 100];
    for &ms in &delays {
        prepare();
        let asked = time::interrupt_time();
        if set(in_ms(ms), 0) {
            return Err("an idle timer was reported pending");
        }
        if await_fired(1, ms as u64 + 500) != 1 {
            return Err("a timer did not fire");
        }
        let waited = FIRED_AT.load(Ordering::Relaxed) - asked;
        if waited < ms as u64 * 10_000 {
            return Err("a timer fired before its time");
        }
        // Due, the next tick, its DPC: two ticks is already generous on
        // real hardware; an emulated machine gets more.
        if waited > ms as u64 * 10_000 + 20 * TIME_INCREMENT {
            return Err("a timer fired more than twenty ticks late");
        }
        if !signalled() {
            return Err("a fired timer is not signalled");
        }
        time::stall(2 * TIME_INCREMENT / 10);
        if FIRED.load(Ordering::Acquire) != 1 {
            return Err("a one-shot timer fired twice");
        }
    }
    Ok(delays.len() as u32)
}

/// A second timer and DPC, for the test that needs two.
static SECOND: TestTimer = TestTimer(UnsafeCell::new(core::mem::MaybeUninit::uninit()));
static SECOND_FIRED: AtomicU32 = AtomicU32::new(0);

/// # Safety
/// Called as a DPC routine; it dereferences none of its arguments.
unsafe extern "C" fn second_fired(_: *mut KDPC, _: *mut c_void, _: *mut c_void, _: *mut c_void) {
    SECOND_FIRED.fetch_add(1, Ordering::Release);
}

/// Two timers a whole turn of the table apart share a bucket. When the
/// first is due the second, four seconds off, must stay where it is.
pub fn shared_bucket_test() -> Result<(), &'static str> {
    use nk_ke::TIMER_BUCKETS;
    let second = SECOND.0.get().cast::<KTIMER>();
    // SAFETY: the offset of the second field of the static pair.
    let second_dpc = unsafe { &raw mut (*SECOND.0.get().cast::<(KTIMER, KDPC)>()).1 };
    prepare();
    SECOND_FIRED.store(0, Ordering::Relaxed);
    let turn = (TIMER_BUCKETS as u64 * TIME_INCREMENT) as i64;
    // Raised, so that both are set at the same instant and land in the
    // same bucket.
    let old = irql::raise(irql::DISPATCH_LEVEL);
    // SAFETY: static storage; neither is pending.
    unsafe {
        KeInitializeTimer(second);
        dpc::KeInitializeDpc(second_dpc, Some(second_fired), core::ptr::null_mut());
        KeSetTimer(second, in_ms(20) - turn, second_dpc);
    }
    set(in_ms(20), 0);
    irql::lower(old);
    let first_fired = await_fired(1, 500);
    time::stall(100_000);
    let early = SECOND_FIRED.load(Ordering::Acquire);
    // SAFETY: as above.
    let still_pending = unsafe { KeCancelTimer(second) } != 0;
    if first_fired != 1 {
        return Err("the timer that was due did not fire");
    }
    if early != 0 || !still_pending {
        return Err("a timer fired a turn of the table early, with its bucket-mate");
    }
    Ok(())
}

/// Cancelling stops a timer; setting a pending timer replaces its due
/// time; a system time in the past, or no delay, fires at once.
pub fn cancel_test() -> Result<(), &'static str> {
    prepare();
    set(in_ms(30), 0);
    if !cancel() || cancel() {
        return Err("a pending timer was not cancelled exactly once");
    }
    if await_fired(1, 80) != 0 {
        return Err("a cancelled timer fired");
    }
    // Far off, then brought forward.
    set(in_ms(60_000), 0);
    if !set(in_ms(20), 0) {
        return Err("setting a pending timer did not report it pending");
    }
    if signalled() {
        return Err("a timer just set is signalled");
    }
    if await_fired(1, 500) != 1 {
        return Err("a timer set again did not fire at its new time");
    }
    time::stall(50_000);
    if FIRED.load(Ordering::Acquire) != 1 || cancel() {
        return Err("a timer set again kept its old setting too");
    }
    // Already due, as a delay and as a system time.
    set(in_ms(0), 0);
    if FIRED.load(Ordering::Acquire) != 2 || !signalled() {
        return Err("a timer with no delay did not fire at once");
    }
    set((time::system_time() - 10_000_000) as i64, 0);
    if FIRED.load(Ordering::Acquire) != 3 {
        return Err("a timer due at a past system time did not fire at once");
    }
    // A system time ahead.
    let asked = time::interrupt_time();
    set((time::system_time() + 300_000) as i64, 0);
    if await_fired(4, 500) != 4 {
        return Err("a timer due at a system time did not fire");
    }
    if FIRED_AT.load(Ordering::Relaxed) - asked < 300_000 {
        return Err("a timer due at a system time fired early");
    }
    Ok(())
}

/// A periodic timer fires again and again, no oftener than its period
/// allows, until cancelled. Returns the firings in half a second.
pub fn periodic_test() -> Result<u32, &'static str> {
    prepare();
    // Period 20 ms: 25 firings in 500 ms, less what tick rounding costs.
    set(in_ms(20), 20);
    time::stall(500_000);
    let was_pending = cancel();
    let fired = FIRED.load(Ordering::Acquire);
    time::stall(100_000);
    if !was_pending {
        return Err("a periodic timer was not pending between firings");
    }
    if FIRED.load(Ordering::Acquire) != fired {
        return Err("a periodic timer fired after it was cancelled");
    }
    if !(12..=26).contains(&fired) {
        return Err("a 20 ms periodic timer did not fire 12 to 26 times in 500 ms");
    }
    // A period shorter than the tick must not starve everything else:
    // the test itself keeps running.
    prepare();
    set(in_ms(1), 1);
    time::stall(200_000);
    cancel();
    if FIRED.load(Ordering::Acquire) < 5 {
        return Err("a 1 ms periodic timer hardly fired");
    }
    Ok(fired)
}

/// A timer's DPC may set the timer again. Returns the firings.
pub fn chain_test() -> Result<u32, &'static str> {
    prepare();
    CHAIN.store(5, Ordering::Relaxed);
    set(in_ms(1), 0);
    if await_fired(6, 2000) != 6 {
        return Err("a timer set again from its own DPC did not keep firing");
    }
    time::stall(50_000);
    if FIRED.load(Ordering::Acquire) != 6 || cancel() {
        return Err("the chain did not stop");
    }
    Ok(6)
}

/// A DPC that sets the test timer on whatever processor it runs on:
/// timers are set at DISPATCH_LEVEL or below, not from an interrupt.
static SETTER: TestTimer = TestTimer(UnsafeCell::new(core::mem::MaybeUninit::uninit()));

/// # Safety
/// Called as a DPC routine; it dereferences none of its arguments.
unsafe extern "C" fn set_here(_: *mut KDPC, ms: *mut c_void, _: *mut c_void, _: *mut c_void) {
    set(in_ms(ms.addr() as i64), 0);
    SET_DONE.fetch_add(1, Ordering::Release);
}

static SET_DONE: AtomicU32 = AtomicU32::new(0);

/// Have processor `target` set the test timer `ms` milliseconds ahead.
fn set_on(target: usize, ms: usize) -> bool {
    fn queue(_: usize) {
        // SAFETY: static storage for a `KDPC`, not queued.
        unsafe {
            let setter = SETTER.0.get().cast::<KDPC>();
            dpc::KeInsertQueueDpc(setter, core::ptr::null_mut(), core::ptr::null_mut());
        }
    }
    let before = SET_DONE.load(Ordering::Acquire);
    // SAFETY: as above; the context carries the delay.
    unsafe {
        dpc::KeInitializeDpc(SETTER.0.get().cast(), Some(set_here), ms as *mut c_void);
    }
    super::ipi::call_on(target, queue, 0);
    for _ in 0..1000 {
        if SET_DONE.load(Ordering::Acquire) != before {
            return true;
        }
        time::stall(1000);
    }
    false
}

/// A timer set on another processor fires there, and can be cancelled
/// from here. Returns the processor used.
pub fn other_cpu_test() -> Result<u32, &'static str> {
    let target = super::smp::online_count() as u32 - 1;
    prepare();
    if !set_on(target as usize, 20) {
        return Err("the DPC that sets the timer did not run");
    }
    if await_fired(1, 500) != 1 {
        return Err("a timer set on another processor did not fire");
    }
    if FIRED_ON.load(Ordering::Relaxed) != target {
        return Err("the timer's DPC did not run on the processor that set it");
    }
    if !set_on(target as usize, 60_000) || !cancel() {
        return Err("a timer pending on another processor could not be cancelled");
    }
    Ok(target)
}
