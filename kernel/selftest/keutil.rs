//! The kernel core's smaller routines, through the exports: queued spin
//! locks, guarded mutexes, the processor queries and the precise times.

use crate::ke::{bugcheck, dpc, irql, kspin, mutex, smp, time, timer, wait};
use crate::test::{Group, Report};
use core::ffi::c_void;
use core::sync::atomic::{AtomicU32, Ordering};
use nk_bootinfo::BootInfo;
use nk_ntabi::ke::{FAST_MUTEX, KDPC, KEVENT, KTIMER};

static GROUP: Group = Group {
    names: &["ke.queued-lock", "ke.processors", "ke.small-routines"],
    run,
    manual: false,
};

static RAN: AtomicU32 = AtomicU32::new(0);

/// A DPC routine: add its context to the count.
///
/// # Safety
/// Called as a DPC routine; it dereferences none of its arguments.
unsafe extern "C" fn count(_: *mut KDPC, context: *mut c_void, _: *mut c_void, _: *mut c_void) {
    RAN.fetch_add(context.addr() as u32, Ordering::AcqRel);
}

fn small_routines() -> Result<(), &'static str> {
    let level = irql::current();
    // SAFETY: every object is a local, zeroed and then initialised by
    // its own routine, and done with before the frame goes.
    unsafe {
        let mut mutex = core::mem::zeroed::<FAST_MUTEX>();
        let guarded = &raw mut mutex;
        mutex::KeInitializeGuardedMutex(guarded);
        mutex::KeAcquireGuardedMutex(guarded);
        let held = (
            irql::current(),
            (*guarded).Count,
            (*guarded).Owner.is_null(),
        );
        let again = mutex::ExTryToAcquireFastMutex(guarded);
        mutex::KeReleaseGuardedMutex(guarded);
        if held.0 != 1 || held.2 || again != 0 || irql::current() != level || (*guarded).Count != 1
        {
            return Err("a guarded mutex is not a fast mutex held at APC_LEVEL");
        }

        let mut event = core::mem::zeroed::<KEVENT>();
        wait::KeInitializeEvent(&raw mut event, 0, 1);
        wait::KeClearEvent(&raw mut event);
        if wait::KeReadStateEvent(&raw mut event) != 0 {
            return Err("KeClearEvent left the event signalled");
        }

        // A threaded DPC runs as a DPC; a flush waits for it; a timer
        // that tolerates delay is not delayed.
        RAN.store(0, Ordering::Release);
        let mut threaded = core::mem::zeroed::<KDPC>();
        let dpc = &raw mut threaded;
        dpc::KeInitializeThreadedDpc(dpc, Some(count), core::ptr::without_provenance_mut(1));
        dpc::KeSetImportanceDpc(dpc, 2);
        let old = irql::raise(irql::DISPATCH_LEVEL);
        let queued = dpc::KeInsertQueueDpc(dpc, core::ptr::null_mut(), core::ptr::null_mut());
        let before = RAN.load(Ordering::Acquire);
        irql::lower(old);
        dpc::KeFlushQueuedDpcs();
        if queued != 1 || before != 0 || RAN.load(Ordering::Acquire) != 1 || (*dpc).Importance != 2
        {
            return Err(
                "a threaded DPC did not run once the IRQL allowed, or the flush returned early",
            );
        }
        let mut timer = core::mem::zeroed::<KTIMER>();
        let mut timer_dpc = core::mem::zeroed::<KDPC>();
        timer::KeInitializeTimer(&raw mut timer);
        dpc::KeInitializeDpc(
            &raw mut timer_dpc,
            Some(count),
            core::ptr::without_provenance_mut(16),
        );
        let was = timer::KeSetCoalescableTimer(&raw mut timer, -10_000, 0, 500, &raw mut timer_dpc);
        let deadline = time::interrupt_time() + 100_000_000;
        while RAN.load(Ordering::Acquire) < 17 && time::interrupt_time() < deadline {
            wait::wait(None, Some(-10_000));
        }
        timer::KeCancelTimer(&raw mut timer);
        dpc::KeFlushQueuedDpcs();
        if was != 0 || RAN.load(Ordering::Acquire) != 17 {
            return Err("a coalescable timer did not expire and queue its DPC");
        }

        // The precise times are the counter's, and go forward.
        let (mut first, mut second) = (0u64, 0u64);
        let unbiased = time::KeQueryUnbiasedInterruptTime();
        let precise = time::KeQueryInterruptTimePrecise(&raw mut first);
        let later = time::KeQueryUnbiasedInterruptTimePrecise(&raw mut second);
        if precise < unbiased || later < precise || second < first || first == 0 {
            return Err("the precise interrupt times do not go forward with the counter");
        }
    }
    // `KeBugCheck` is `KeBugCheckEx` without parameters: it is exported,
    // and calling it would end the test.
    let stop: extern "C" fn(u32) -> ! = bugcheck::KeBugCheck;
    if crate::export::resolve(b"ntoskrnl.exe", b"KeBugCheck") != Some(stop as usize as u64) {
        return Err("KeBugCheck is not exported");
    }
    Ok(())
}

fn run(r: &mut Report, _: &BootInfo) {
    match kspin::queued_test() {
        Ok(handles) => r.ok_with("ke.queued-lock", format_args!("{handles} handles")),
        Err(why) => r.fail("ke.queued-lock", format_args!("{why}")),
    }
    match smp::queries_test() {
        Ok(processors) => r.ok_with("ke.processors", format_args!("{processors} processors")),
        Err(why) => r.fail("ke.processors", format_args!("{why}")),
    }
    r.check("ke.small-routines", small_routines);
}

/// This file's test groups, in the order they run.
pub static GROUPS: &[&Group] = &[&GROUP];
