//! Interprocessor interrupts: have other processors run a routine.
//!
//! One call is in progress at a time. The caller names the routine and
//! the processors, interrupts them, runs the routine itself if it is
//! among them, and waits until every one has finished. The routine runs
//! at the interprocessor-interrupt IRQL on each.
//!
//! A processor waiting for its turn to make a call still answers the
//! call in progress: the lock that serialises calls is held at
//! `DISPATCH_LEVEL`, below the interrupt. A processor that does not
//! answer within the timeout is stuck with interrupts off, and the
//! system stops.

use super::{Rank, SpinLock, irql, pcr, smp, time};
use crate::arch;
use core::sync::atomic::{AtomicPtr, AtomicU64, AtomicUsize, Ordering};

/// What a call runs on each processor.
pub type Routine = fn(argument: usize);

/// Serialises calls.
static CALL: SpinLock<()> = SpinLock::new(Rank::Ipi, ());
static ROUTINE: AtomicPtr<()> = AtomicPtr::new(core::ptr::null_mut());
static ARGUMENT: AtomicUsize = AtomicUsize::new(0);
/// Bit `n`: processor `n` has yet to run the routine.
static PENDING: AtomicU64 = AtomicU64::new(0);

/// How long a processor gets to answer, in 100 ns units.
const TIMEOUT: u64 = 5 * 10_000_000;

fn interrupt(_: u32) {
    let me = 1 << pcr::current_processor();
    if PENDING.load(Ordering::Acquire) & me == 0 {
        return;
    }
    let routine = ROUTINE.load(Ordering::Acquire);
    // SAFETY: the only values stored are `Routine`s, and one is stored
    // before any bit of `PENDING` is set.
    let routine: Routine = unsafe { core::mem::transmute(routine) };
    routine(ARGUMENT.load(Ordering::Acquire));
    PENDING.fetch_and(!me, Ordering::Release);
}

/// Take the interprocessor interrupt. Before any other processor starts.
pub fn init() {
    let (vector, level) = arch::IPI;
    super::interrupt::register(vector, level, interrupt);
}

/// Run `routine(argument)` on each running processor in the mask
/// `processors`, this one included if it is named, and return when all
/// have finished.
pub fn call(processors: u64, routine: Routine, argument: usize) {
    let _call = CALL.lock();
    let me = pcr::current_processor();
    let others = processors & smp::online() & !(1 << me);
    ROUTINE.store(routine as *mut (), Ordering::Release);
    ARGUMENT.store(argument, Ordering::Release);
    PENDING.store(others, Ordering::Release);
    for number in (0..64).filter(|n| others & 1 << n != 0) {
        arch::ipi_send(number);
    }
    if processors & 1 << me != 0 {
        let old = irql::raise(arch::IPI.1);
        routine(argument);
        irql::lower(old);
    }
    if others == 0 {
        return;
    }
    let deadline = time::interrupt_time() + TIMEOUT;
    loop {
        let pending = PENDING.load(Ordering::Acquire);
        if pending == 0 {
            return;
        }
        if time::interrupt_time() > deadline {
            crate::kd::bugcheck(format_args!(
                "processor {} did not answer an interprocessor interrupt",
                pending.trailing_zeros()
            ));
        }
        core::hint::spin_loop();
    }
}

/// Run `routine(argument)` on every running processor.
pub fn call_all(routine: Routine, argument: usize) {
    call(u64::MAX, routine, argument);
}

/// Run `routine(argument)` on processor `number`.
pub fn call_on(number: usize, routine: Routine, argument: usize) {
    call(1 << number, routine, argument);
}

// ---- tests --------------------------------------------------------------

const CPUS: usize = crate::hal::platform::MAX_CPUS;
/// What each processor recorded, by its own number.
static SLOT: [AtomicU64; CPUS] = [const { AtomicU64::new(0) }; CPUS];
/// How often each processor ran a test routine.
static RUNS: [AtomicU64; CPUS] = [const { AtomicU64::new(0) }; CPUS];
/// Bit `n`: processor `n` ran a routine at the wrong IRQL.
static WRONG_IRQL: AtomicU64 = AtomicU64::new(0);

fn me() -> usize {
    pcr::current_processor() as usize
}

fn reset() {
    for (slot, runs) in SLOT.iter().zip(&RUNS) {
        slot.store(0, Ordering::Relaxed);
        runs.store(0, Ordering::Relaxed);
    }
    WRONG_IRQL.store(0, Ordering::Relaxed);
}

fn count(_: usize) {
    RUNS[me()].fetch_add(1, Ordering::Relaxed);
    if irql::current() != arch::IPI.1 {
        WRONG_IRQL.fetch_or(1 << me(), Ordering::Relaxed);
    }
}

fn record_pcr(_: usize) {
    count(0);
    SLOT[me()].store(arch::pcr() as u64, Ordering::Relaxed);
}

fn record_counter(_: usize) {
    SLOT[me()].store(arch::counter(), Ordering::Relaxed);
}

fn read_page(va: usize) {
    // SAFETY: the test keeps a readable page mapped at `va` for the
    // length of the call.
    SLOT[me()].store(
        unsafe { (va as *const u64).read_volatile() },
        Ordering::Relaxed,
    );
}

/// A call to all reaches every processor once, at the interprocessor
/// IRQL, and each finds its own PCR with its own number in it. Returns
/// the number of processors.
pub fn each_test() -> Result<usize, &'static str> {
    let cpus = smp::online_count();
    reset();
    call_all(record_pcr, 0);
    for n in 0..cpus {
        if RUNS[n].load(Ordering::Relaxed) != 1 {
            return Err("a call to all did not run exactly once on each processor");
        }
        let pcr = SLOT[n].load(Ordering::Relaxed);
        if pcr == 0 || (0..n).any(|m| SLOT[m].load(Ordering::Relaxed) == pcr) {
            return Err("two processors share a PCR");
        }
    }
    if RUNS[cpus..].iter().any(|r| r.load(Ordering::Relaxed) != 0) {
        return Err("a processor reported a number firmware did not list");
    }
    if WRONG_IRQL.load(Ordering::Relaxed) != 0 {
        return Err("the routine did not run at the interprocessor IRQL");
    }
    Ok(cpus)
}

/// Many calls, each to one processor: every one arrives, none twice,
/// none elsewhere. Returns the calls made.
pub fn count_test() -> Result<u64, &'static str> {
    const ROUNDS: u64 = 500;
    let cpus = smp::online_count();
    reset();
    for round in 0..ROUNDS * cpus as u64 {
        call_on(round as usize % cpus, count, 0);
    }
    if RUNS[..cpus]
        .iter()
        .any(|r| r.load(Ordering::Relaxed) != ROUNDS)
    {
        return Err("calls to single processors were lost, repeated or misdirected");
    }
    if WRONG_IRQL.load(Ordering::Relaxed) != 0 {
        return Err("the routine did not run at the interprocessor IRQL");
    }
    Ok(ROUNDS * cpus as u64)
}

/// The time counter, read on each processor in turn, never runs
/// backwards from one to the next. Returns the readings taken.
pub fn counter_test() -> Result<u64, &'static str> {
    let cpus = smp::online_count();
    let mut last = arch::counter();
    for round in 0..200 * cpus {
        let n = round % cpus;
        call_on(n, record_counter, 0);
        let now = SLOT[n].load(Ordering::Relaxed);
        if now < last {
            return Err("the time counter of one processor is behind another's");
        }
        last = now;
    }
    Ok(200 * cpus as u64)
}

/// After a page is unmapped and another mapped in its place, no
/// processor still sees the old one. Returns the processors checked.
pub fn tlb_test() -> Result<usize, &'static str> {
    use crate::mm::{self, map};
    use nk_mm::pt::Prot;
    const OLD: u64 = 0x1111_1111_1111_1111;
    const NEW: u64 = 0x2222_2222_2222_2222;
    let cpus = smp::online_count();
    let frames = mm::alloc_frames(2).ok_or("no frames")?;
    let va = map::alloc_va(1).ok_or("no address space")?;
    // SAFETY: two fresh frames in the direct map.
    unsafe {
        mm::phys_to_virt(frames).cast::<u64>().write(OLD);
        mm::phys_to_virt(frames + 4096).cast::<u64>().write(NEW);
    }
    let check = || {
        map::map(va, frames, 1, Prot::RO).map_err(|_| "map failed")?;
        // Every processor now holds the translation.
        reset();
        call_all(read_page, va as usize);
        if SLOT[..cpus]
            .iter()
            .any(|s| s.load(Ordering::Relaxed) != OLD)
        {
            return Err("a processor did not read the page first mapped");
        }
        map::unmap(va, 1);
        map::map(va, frames + 4096, 1, Prot::RO).map_err(|_| "remap failed")?;
        call_all(read_page, va as usize);
        if SLOT[..cpus]
            .iter()
            .any(|s| s.load(Ordering::Relaxed) != NEW)
        {
            return Err("a processor still sees a page that was unmapped");
        }
        Ok(())
    };
    let verdict = check();
    map::unmap(va, 1);
    map::free_va(va, 1);
    mm::free_frames(frames, 2);
    verdict.map(|()| cpus)
}

/// Processor 1 takes an interprocessor call and never returns from it,
/// interrupts off. The caller must give up and stop the system.
pub fn stuck_test() {
    fn stick(_: usize) {
        arch::disable_interrupts();
        loop {
            core::hint::spin_loop();
        }
    }
    call_on(1, stick, 0);
}
