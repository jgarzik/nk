//! Deferred procedure calls.
//!
//! A DPC is work a driver wants done soon, at `DISPATCH_LEVEL`, usually
//! on behalf of an interrupt handler that must not do it itself. Each
//! processor has a queue. Queueing a DPC puts it on the queue of the
//! processor that queued it and asks that processor's interrupt
//! controller for an interrupt at `DISPATCH_LEVEL`; the interrupt arrives
//! as soon as the IRQL is below that, however the IRQL came down (code
//! built with the WDK lowers it in line on x86-64, without a call), and
//! its handler runs the queue.
//!
//! The driver owns the `KDPC`. NK reads and writes its fields through the
//! driver's pointer, under the queue's lock, and keeps no reference to
//! it. `DpcData` holds the address of the queue the DPC is on, and is
//! null when it is on none: that is the test for "already queued".
//!
//! DPC routines run on a stack of their processor's, as on Windows, not
//! on the stack of whatever the interrupt found running. Only the routines
//! do: the interrupt arrives and ends on the interrupted thread's stack,
//! which is where a thread switch at its end must be made.
//!
//! A DPC that runs longer than Windows allows stops the system, as it
//! does there; the clock tick checks.

#![allow(non_snake_case)]

use super::seh::{self, Guard, Unhandled};
use super::{Rank, SpinLock, interrupt, irql, time};
use crate::arch;
use crate::hal::platform::MAX_CPUS;
use crate::mm::stack::{self, Stack};
use core::cell::UnsafeCell;
use core::ffi::c_void;
use core::mem::{MaybeUninit, offset_of};
use core::sync::atomic::{AtomicPtr, AtomicU32, AtomicU64, Ordering};
use nk_bootinfo::BootInfo;
use nk_ke::{DPC_TIME_LIMIT_TICKS, Fifo, Link, TIME_INCREMENT};
use nk_ntabi::ke::{DPC_OBJECT, KDEFERRED_ROUTINE, KDPC, MEDIUM_IMPORTANCE};

/// One processor's queue of DPCs. Queued from any IRQL, so its lock is
/// held at `HIGH_LEVEL`.
pub struct Queue {
    list: SpinLock<Fifo>,
    /// When the DPC now running began, in interrupt time; 0 when none is.
    running_since: AtomicU64,
    /// Lowest address of the stack the routines run on. Set once, before
    /// the processor can take the DPC interrupt, and kept for good.
    stack: AtomicU64,
}

impl Queue {
    pub const fn new() -> Self {
        Self {
            list: SpinLock::new(Rank::DpcQueue, Fifo::new()),
            running_since: AtomicU64::new(0),
            stack: AtomicU64::new(0),
        }
    }

    /// The stack this processor's DPC routines run on.
    pub fn stack(&self) -> Stack {
        let base = self.stack.load(Ordering::Acquire);
        Stack {
            base,
            top: base + nk_bootinfo::KERNEL_STACK_SIZE,
        }
    }
}

/// Give processor `number` the stack its DPC routines run on. Once for
/// each processor, before it can take the DPC interrupt.
pub fn prepare_cpu(number: usize) -> Result<(), &'static str> {
    let queue = arch::percpu_of(number)
        .ok_or("a processor without state cannot have a DPC stack")?
        .dpcs();
    let stack = stack::alloc().ok_or("no memory for a processor's DPC stack")?;
    queue.stack.store(stack.base, Ordering::Release);
    Ok(())
}

/// How long one DPC may run, in 100 ns units.
static TIME_LIMIT: AtomicU64 = AtomicU64::new(DPC_TIME_LIMIT_TICKS * TIME_INCREMENT);

/// The link inside a driver's DPC.
fn link_of(dpc: *mut KDPC) -> *mut Link {
    dpc.wrapping_byte_add(offset_of!(KDPC, DpcListEntry)).cast()
}

/// The word that says which queue a DPC is on.
///
/// # Safety
/// `dpc` points to a live `KDPC`.
unsafe fn queue_word<'a>(dpc: *mut KDPC) -> &'a AtomicPtr<c_void> {
    // SAFETY: per the contract; the field is an aligned pointer that
    // other processors read and write, hence the atomic view.
    unsafe { AtomicPtr::from_ptr(&raw mut (*dpc).DpcData) }
}

/// Take the DPC interrupt, on the boot processor's DPC stack; read the
/// time limit from the command line (`dpc-limit=<ticks>`, for the test
/// that exceeds it).
pub fn init(info: &BootInfo) -> Result<(), &'static str> {
    if let Some(ticks) = info.option("dpc-limit").and_then(|v| v.parse::<u64>().ok()) {
        TIME_LIMIT.store(ticks * TIME_INCREMENT, Ordering::Relaxed);
    }
    prepare_cpu(super::pcr::current_processor() as usize)?;
    let (vector, level) = arch::DPC;
    interrupt::register(vector, level, run_queue);
    Ok(())
}

/// The DPC interrupt: run this processor's queue on its DPC stack.
///
/// The interrupt is not taken again while the queue runs: its IRQL is
/// `DISPATCH_LEVEL`, and so is the queue run's. The exception is a
/// routine that lowers the IRQL, a driver's bug that is reported when it
/// returns: the interrupt can then arrive inside it, with the stack in
/// use. Nothing is run then: the run in progress goes on until the queue
/// is empty.
fn run_queue(_: u32) {
    let queue = arch::percpu().dpcs();
    if queue.running_since.load(Ordering::Relaxed) != 0 {
        return;
    }
    let argument = core::ptr::from_ref(queue) as usize;
    // SAFETY: the stack is this processor's own and mapped for good; per
    // the above nothing else on this processor is on it, and a thread
    // switch while a routine runs stops the system (`thread::switch_to`).
    unsafe { arch::call_on_stack(queue.stack().top, drain, argument) };
}

/// Run the DPCs of the queue at address `queue`, this processor's, until
/// it is empty.
extern "C" fn drain(queue: usize) {
    // SAFETY: the address of a processor's queue, which lives for ever.
    let queue = unsafe { &*(queue as *const Queue) };
    loop {
        let (dpc, routine, context, argument1, argument2);
        {
            let mut list = queue.list.lock();
            // SAFETY: a queued DPC stays valid until it has run or been
            // removed: that is the driver's side of the contract.
            let link = unsafe { list.pop() };
            if link.is_null() {
                return;
            }
            dpc = link
                .wrapping_byte_sub(offset_of!(KDPC, DpcListEntry))
                .cast::<KDPC>();
            // SAFETY: as above. Read under the lock, before the DPC is
            // marked free: from then on the driver may queue it again
            // with other arguments, or free it.
            unsafe {
                routine = (&raw const (*dpc).DeferredRoutine).read();
                context = (&raw const (*dpc).DeferredContext).read();
                argument1 = (&raw const (*dpc).SystemArgument1).read();
                argument2 = (&raw const (*dpc).SystemArgument2).read();
                queue_word(dpc).store(core::ptr::null_mut(), Ordering::Release);
            }
        }
        let Some(routine) = routine else {
            crate::kd::verify(format_args!("a DPC with no routine was queued"));
            continue;
        };
        queue
            .running_since
            .store(time::interrupt_time().max(1), Ordering::Relaxed);
        // SAFETY: calling the routine the driver registered, at
        // DISPATCH_LEVEL, with the arguments it queued. An exception
        // it lets out is unhandled: the search for a handler ends
        // here, and does not go on into whatever this processor was
        // doing when the queue was run.
        unsafe {
            seh::call(
                routine as usize,
                [
                    dpc.addr(),
                    context.addr(),
                    argument1.addr(),
                    argument2.addr(),
                ],
                &Guard::Base(Unhandled::KernelMode),
            )
        };
        queue.running_since.store(0, Ordering::Relaxed);
        let level = irql::current();
        if level != irql::DISPATCH_LEVEL {
            crate::kd::verify(format_args!("a DPC routine returned at IRQL {level}"));
            arch::set_irql(irql::DISPATCH_LEVEL);
        }
    }
}

/// Whether a DPC routine is running on this processor.
pub fn running() -> bool {
    arch::percpu().dpcs().running_since.load(Ordering::Relaxed) != 0
}

/// Called from the clock tick: stop the system if the DPC running on
/// this processor has run too long.
pub fn watchdog() {
    let since = arch::percpu().dpcs().running_since.load(Ordering::Relaxed);
    let limit = TIME_LIMIT.load(Ordering::Relaxed);
    if since != 0 && time::interrupt_time().saturating_sub(since) > limit {
        crate::kd::bugcheck(format_args!(
            "0x00000133 DPC_WATCHDOG_VIOLATION: one DPC ran for more than {} ticks",
            limit / TIME_INCREMENT
        ));
    }
}

/// [`KeInitializeDpc`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-keinitializedpc).
///
/// # Safety
/// `dpc` points to writable storage for a `KDPC`.
pub unsafe extern "C" fn KeInitializeDpc(
    dpc: *mut KDPC,
    deferred_routine: Option<KDEFERRED_ROUTINE>,
    deferred_context: *mut c_void,
) {
    // SAFETY: per the contract.
    unsafe {
        dpc.write(KDPC {
            Type: DPC_OBJECT,
            Importance: MEDIUM_IMPORTANCE,
            Number: 0,
            DpcListEntry: nk_ntabi::ke::SINGLE_LIST_ENTRY {
                Next: core::ptr::null_mut(),
            },
            ProcessorHistory: 0,
            DeferredRoutine: deferred_routine,
            DeferredContext: deferred_context,
            SystemArgument1: core::ptr::null_mut(),
            SystemArgument2: core::ptr::null_mut(),
            DpcData: core::ptr::null_mut(),
        });
    }
}

/// [`KeInsertQueueDpc`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-keinsertqueuedpc):
/// queue a DPC on this processor. `FALSE` if it is already queued.
///
/// # Safety
/// `dpc` points to a `KDPC` set up by `KeInitializeDpc` that stays valid
/// until it has run or been removed.
pub unsafe extern "C" fn KeInsertQueueDpc(
    dpc: *mut KDPC,
    system_argument1: *mut c_void,
    system_argument2: *mut c_void,
) -> u8 {
    // Stay on one processor from choosing its queue to asking for its
    // interrupt.
    let old = irql::current();
    if old < irql::DISPATCH_LEVEL {
        arch::set_irql(irql::DISPATCH_LEVEL);
    }
    let queue = arch::percpu().dpcs();
    let queued = {
        let mut list = queue.list.lock();
        // SAFETY: per the contract.
        let free = unsafe { queue_word(dpc) }
            .compare_exchange(
                core::ptr::null_mut(),
                core::ptr::from_ref(queue).cast_mut().cast(),
                Ordering::AcqRel,
                Ordering::Relaxed,
            )
            .is_ok();
        if free {
            // SAFETY: per the contract; the DPC was on no queue, and this
            // processor now owns it under the queue's lock.
            unsafe {
                (&raw mut (*dpc).SystemArgument1).write(system_argument1);
                (&raw mut (*dpc).SystemArgument2).write(system_argument2);
                list.push(link_of(dpc));
            }
        }
        free
    };
    if queued {
        arch::self_interrupt(arch::DPC.0);
    }
    // If this lowers the IRQL below DISPATCH_LEVEL the DPC runs here.
    arch::set_irql(old);
    u8::from(queued)
}

/// [`KeRemoveQueueDpc`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-keremovequeuedpc):
/// take a DPC off whatever queue it is on. `FALSE` if it is on none.
///
/// # Safety
/// `dpc` points to a live `KDPC` set up by `KeInitializeDpc`.
pub unsafe extern "C" fn KeRemoveQueueDpc(dpc: *mut KDPC) -> u8 {
    loop {
        // SAFETY: per the contract.
        let word = unsafe { queue_word(dpc) };
        let on = word.load(Ordering::Acquire);
        if on.is_null() {
            return 0;
        }
        // SAFETY: the only non-null values stored are addresses of
        // processors' queues, which live for ever.
        let queue = unsafe { &*on.cast::<Queue>() };
        let mut list = queue.list.lock();
        // It may have run, or run and been queued elsewhere, meanwhile.
        if word.load(Ordering::Acquire) != on {
            continue;
        }
        // SAFETY: the DPC is on this queue, whose lock is held.
        let removed = unsafe { list.remove(link_of(dpc)) };
        debug_assert!(removed);
        word.store(core::ptr::null_mut(), Ordering::Release);
        return 1;
    }
}

/// What one [`flush`] waits for: a DPC for each processor and the count
/// of those that have yet to run.
struct Barrier {
    dpcs: [UnsafeCell<MaybeUninit<KDPC>>; MAX_CPUS],
    left: AtomicU32,
}

/// Queue this processor's DPC of the barrier at address `barrier`.
fn plant(barrier: usize) {
    // SAFETY: the address of the `Barrier` of a `flush` that does not
    // return before every processor has run this and its DPC; each
    // processor touches its own DPC only.
    unsafe {
        let barrier = &*(barrier as *const Barrier);
        let dpc = barrier.dpcs[super::pcr::current_processor() as usize]
            .get()
            .cast::<KDPC>();
        KeInitializeDpc(
            dpc,
            Some(passed),
            (&raw const barrier.left).cast_mut().cast(),
        );
        KeInsertQueueDpc(dpc, core::ptr::null_mut(), core::ptr::null_mut());
    }
}

/// A barrier's DPC: everything queued here before it has run.
///
/// # Safety
/// Called as a DPC routine, with the address of its barrier's count.
unsafe extern "C" fn passed(_: *mut KDPC, left: *mut c_void, _: *mut c_void, _: *mut c_void) {
    // SAFETY: per the contract; the count outlives the DPCs it counts.
    unsafe { &*left.cast::<AtomicU32>() }.fetch_sub(1, Ordering::AcqRel);
}

/// Return once every DPC that was queued or running on any processor
/// when this was called has finished: what Windows' `KeFlushQueuedDpcs`
/// promises. A queue runs in order, so a DPC queued now on each
/// processor runs after all of those.
///
/// For a caller below `DISPATCH_LEVEL`, where its own processor's queue
/// can run.
pub fn flush() {
    let level = irql::current();
    if level >= irql::DISPATCH_LEVEL {
        crate::kd::bugcheck(format_args!(
            "0x0000000A IRQL_NOT_LESS_OR_EQUAL: waiting for queued DPCs to run at IRQL {level}"
        ));
    }
    let barrier = Barrier {
        dpcs: [const { UnsafeCell::new(MaybeUninit::uninit()) }; MAX_CPUS],
        left: AtomicU32::new(super::smp::online_count() as u32),
    };
    super::ipi::call_all(plant, core::ptr::from_ref(&barrier) as usize);
    while barrier.left.load(Ordering::Acquire) != 0 {
        core::hint::spin_loop();
    }
}

// ---- tests --------------------------------------------------------------

/// One slow DPC per processor, for the test of `flush`.
struct Slow([UnsafeCell<MaybeUninit<KDPC>>; MAX_CPUS]);

// SAFETY: each processor touches its own DPC only, through the DPC
// routines.
unsafe impl Sync for Slow {}

static SLOW: Slow = Slow([const { UnsafeCell::new(MaybeUninit::uninit()) }; MAX_CPUS]);
static SLOW_DONE: AtomicU32 = AtomicU32::new(0);

/// # Safety
/// Called as a DPC routine; it dereferences none of its arguments.
unsafe extern "C" fn dawdle(_: *mut KDPC, _: *mut c_void, _: *mut c_void, _: *mut c_void) {
    // Slow everywhere but on the processor of the thread that will
    // flush: its own DPC must not be what keeps it.
    if super::pcr::current_processor() != SLOW_ORIGIN.load(Ordering::Acquire) {
        time::stall(5_000);
    }
    SLOW_DONE.fetch_add(1, Ordering::AcqRel);
}

/// The processor the test's thread queued the slow DPCs from.
static SLOW_ORIGIN: AtomicU32 = AtomicU32::new(0);

fn plant_slow(_: usize) {
    let dpc = SLOW.0[super::pcr::current_processor() as usize]
        .get()
        .cast::<KDPC>();
    // SAFETY: static storage, this processor's own; the DPC is not
    // queued, the last test's having run before its flush returned.
    unsafe {
        KeInitializeDpc(dpc, Some(dawdle), core::ptr::null_mut());
        KeInsertQueueDpc(dpc, core::ptr::null_mut(), core::ptr::null_mut());
    }
}

/// A flush returns only when the DPCs queued before it, on every
/// processor, have run to their end. Returns how many it waited for.
pub fn flush_test() -> Result<u32, &'static str> {
    SLOW_DONE.store(0, Ordering::Release);
    // Raised while the DPCs are queued: the thread stays on its
    // processor, whose DPC runs, at once, only when the level comes
    // down again. The others are then still dawdling.
    let old = irql::raise(irql::DISPATCH_LEVEL);
    SLOW_ORIGIN.store(super::pcr::current_processor(), Ordering::Release);
    super::ipi::call_all(plant_slow, 0);
    irql::lower(old);
    flush();
    let done = SLOW_DONE.load(Ordering::Acquire);
    if done as usize != super::smp::online_count() {
        return Err("a flush returned before a DPC queued ahead of it had finished");
    }
    Ok(done)
}

/// A DPC of the kernel's own, for the tests.
struct TestDpc(UnsafeCell<core::mem::MaybeUninit<KDPC>>);

// SAFETY: accessed only through the DPC routines, by pointer, as a
// driver's would be.
unsafe impl Sync for TestDpc {}

impl TestDpc {
    const fn new() -> Self {
        Self(UnsafeCell::new(core::mem::MaybeUninit::uninit()))
    }
    fn ptr(&self) -> *mut KDPC {
        self.0.get().cast()
    }
}

static DPCS: [TestDpc; 3] = [const { TestDpc::new() }; 3];
static RUNS: AtomicU32 = AtomicU32::new(0);
/// What the routines saw, four bits a run: the context they were given.
static TRACE: AtomicU32 = AtomicU32::new(0);
/// IRQL, processor, and whether the arguments arrived, of the last run.
static SEEN_IRQL: AtomicU32 = AtomicU32::new(0);
static SEEN_CPU: AtomicU32 = AtomicU32::new(0);
static SEEN_ARGUMENTS: AtomicU32 = AtomicU32::new(0);

/// The test DPCs' routine: note what it sees.
///
/// # Safety
/// Called as a DPC routine; it dereferences none of its arguments.
unsafe extern "C" fn record(_: *mut KDPC, context: *mut c_void, a1: *mut c_void, a2: *mut c_void) {
    SEEN_IRQL.store(u32::from(irql::current()), Ordering::Relaxed);
    SEEN_CPU.store(super::pcr::current_processor(), Ordering::Relaxed);
    SEEN_ARGUMENTS.store(
        u32::from(a1.addr() == 0x1111 && a2.addr() == 0x2222),
        Ordering::Relaxed,
    );
    let _ = TRACE.try_update(Ordering::Relaxed, Ordering::Relaxed, |t| {
        Some(t << 4 | context.addr() as u32)
    });
    RUNS.fetch_add(1, Ordering::Release);
}

/// Wait up to a second for `wanted` runs; returns the count seen.
fn runs(wanted: u32) -> u32 {
    for _ in 0..1000 {
        if RUNS.load(Ordering::Acquire) >= wanted {
            break;
        }
        time::stall(1000);
    }
    RUNS.load(Ordering::Acquire)
}

fn insert(n: usize) -> bool {
    // SAFETY: the test DPCs are static and initialised by `prepare`.
    unsafe { KeInsertQueueDpc(DPCS[n].ptr(), 0x1111 as *mut c_void, 0x2222 as *mut c_void) != 0 }
}

fn prepare() {
    for (n, dpc) in DPCS.iter().enumerate() {
        // SAFETY: static storage for a `KDPC`, not queued.
        unsafe { KeInitializeDpc(dpc.ptr(), Some(record), (n + 1) as *mut c_void) };
    }
    RUNS.store(0, Ordering::Relaxed);
    TRACE.store(0, Ordering::Relaxed);
}

/// Queued below DISPATCH_LEVEL, a DPC runs at once: once, at
/// DISPATCH_LEVEL, on the same processor, with what it was queued with.
pub fn run_test() -> Result<(), &'static str> {
    prepare();
    if !insert(0) {
        return Err("a fresh DPC was refused");
    }
    if RUNS.load(Ordering::Acquire) != 1 {
        return Err("a DPC queued at PASSIVE_LEVEL had not run when the insert returned");
    }
    if SEEN_IRQL.load(Ordering::Relaxed) != u32::from(irql::DISPATCH_LEVEL) {
        return Err("the routine did not run at DISPATCH_LEVEL");
    }
    if SEEN_ARGUMENTS.load(Ordering::Relaxed) != 1 || TRACE.load(Ordering::Relaxed) != 1 {
        return Err("the routine did not get its context and arguments");
    }
    if SEEN_CPU.load(Ordering::Relaxed) != super::pcr::current_processor() {
        return Err("the routine ran on another processor");
    }
    if irql::current() != irql::PASSIVE_LEVEL {
        return Err("the IRQL did not come back down");
    }
    Ok(())
}

/// At DISPATCH_LEVEL DPCs wait, a queued one is refused a second time,
/// and when the IRQL drops they run in the order queued. Returns the
/// number run.
pub fn order_test() -> Result<u32, &'static str> {
    prepare();
    let old = irql::raise(irql::DISPATCH_LEVEL);
    let accepted = insert(1) && insert(0) && insert(2);
    let again = insert(0);
    time::stall(2000);
    let early = RUNS.load(Ordering::Acquire);
    irql::lower(old);
    if !accepted {
        return Err("a fresh DPC was refused");
    }
    if again {
        return Err("a DPC already queued was accepted again");
    }
    if early != 0 {
        return Err("a DPC ran while the IRQL was at DISPATCH_LEVEL");
    }
    if runs(3) != 3 {
        return Err("three queued DPCs did not each run once");
    }
    // Contexts are 1, 2, 3; queued as 2, 1, 3.
    if TRACE.load(Ordering::Relaxed) != 0x213 {
        return Err("DPCs did not run in the order they were queued");
    }
    Ok(3)
}

/// A waiting DPC can be removed, once, from any place in the queue, and
/// then does not run; the others still do. Returns the number removed.
pub fn remove_test() -> Result<u32, &'static str> {
    let mut removed = 0;
    for victim in 0..3 {
        prepare();
        let old = irql::raise(irql::DISPATCH_LEVEL);
        let accepted = insert(0) && insert(1) && insert(2);
        // SAFETY: the test DPCs are static and initialised.
        let (first, second) = unsafe {
            (
                KeRemoveQueueDpc(DPCS[victim].ptr()),
                KeRemoveQueueDpc(DPCS[victim].ptr()),
            )
        };
        irql::lower(old);
        if !accepted || first != 1 {
            return Err("a queued DPC could not be removed");
        }
        if second != 0 {
            return Err("a DPC was removed twice");
        }
        time::stall(2000);
        if runs(2) != 2 {
            return Err("after a removal the other DPCs did not each run once");
        }
        let expected = [0x23, 0x13, 0x12][victim];
        if TRACE.load(Ordering::Relaxed) != expected {
            return Err("the removed DPC ran, or the others ran out of order");
        }
        // Removed, it can be queued again.
        if !insert(victim) || runs(3) != 3 {
            return Err("a removed DPC could not be queued again");
        }
        removed += 1;
    }
    Ok(removed)
}

/// A DPC queued from another processor's interrupt handler runs on that
/// processor. Returns the processor used.
pub fn other_cpu_test() -> Result<u32, &'static str> {
    fn queue(_: usize) {
        insert(0);
    }
    let target = super::smp::online_count() as u32 - 1;
    prepare();
    super::ipi::call_on(target as usize, queue, 0);
    if runs(1) != 1 {
        return Err("a DPC queued at the interprocessor IRQL did not run once");
    }
    if SEEN_CPU.load(Ordering::Relaxed) != target {
        return Err("the DPC did not run on the processor that queued it");
    }
    if SEEN_IRQL.load(Ordering::Relaxed) != u32::from(irql::DISPATCH_LEVEL) {
        return Err("the routine did not run at DISPATCH_LEVEL");
    }
    Ok(target)
}

/// An address in the frame of the stack tests' routine, when it last ran.
static SEEN_SP: AtomicU64 = AtomicU64::new(0);
/// Set by the thread the stack test's routine wakes.
static WOKEN: AtomicU32 = AtomicU32::new(0);
static WAKE: crate::test::Slot<nk_ntabi::ke::KEVENT> = crate::test::Slot::new();

/// The stack tests' routine: note where its frame is and on which
/// processor, and set the event it was given, if any.
///
/// # Safety
/// Called as a DPC routine; `context` is null or an initialised event.
unsafe extern "C" fn locate(_: *mut KDPC, context: *mut c_void, _: *mut c_void, _: *mut c_void) {
    let here = 0u8;
    SEEN_SP.store(
        core::hint::black_box(&raw const here) as u64,
        Ordering::Relaxed,
    );
    SEEN_CPU.store(super::pcr::current_processor(), Ordering::Relaxed);
    if !context.is_null() {
        // SAFETY: per the contract.
        unsafe { super::wait::KeSetEvent(context.cast(), 0, 0) };
    }
    RUNS.fetch_add(1, Ordering::Release);
}

/// A DPC routine runs on its processor's DPC stack, here and on another
/// processor, and not on the stack of the thread it interrupts; that
/// thread is on its own stack afterwards; and a thread the routine wakes
/// runs before the interrupted one goes on. Returns the other processor
/// used.
pub fn stack_test() -> Result<u32, &'static str> {
    fn holds(stack: Stack, address: u64) -> bool {
        (stack.base..stack.top).contains(&address)
    }
    fn dpc_stack_holds(processor: u32, address: u64) -> bool {
        arch::percpu_of(processor as usize).is_some_and(|p| holds(p.dpcs().stack(), address))
    }
    fn queue(_: usize) {
        insert(0);
    }
    fn waiter(_: usize) {
        // SAFETY: a static event, initialised before this thread is made.
        unsafe {
            super::wait::KeWaitForSingleObject(WAKE.ptr().cast(), 0, 0, 0, core::ptr::null())
        };
        WOKEN.store(1, Ordering::Release);
    }
    let own = super::thread::current_stack();
    let me = super::pcr::current_processor();

    // SAFETY: static storage for a `KDPC`, not queued.
    unsafe { KeInitializeDpc(DPCS[0].ptr(), Some(locate), core::ptr::null_mut()) };
    RUNS.store(0, Ordering::Relaxed);
    if !insert(0) || RUNS.load(Ordering::Acquire) != 1 {
        return Err("a DPC queued at PASSIVE_LEVEL had not run when the insert returned");
    }
    let seen = SEEN_SP.load(Ordering::Relaxed);
    if holds(own, seen) {
        return Err("a DPC routine ran on the stack of the thread it interrupted");
    }
    if !dpc_stack_holds(SEEN_CPU.load(Ordering::Relaxed), seen) {
        return Err("a DPC routine did not run on its processor's DPC stack");
    }
    let here = 0u8;
    if !holds(own, core::hint::black_box(&raw const here) as u64) {
        return Err("after a DPC the thread was not on its own stack");
    }

    let target = super::smp::online_count() as u32 - 1;
    RUNS.store(0, Ordering::Relaxed);
    super::ipi::call_on(target as usize, queue, 0);
    if runs(1) != 1 {
        return Err("a DPC queued at the interprocessor IRQL did not run once");
    }
    if SEEN_CPU.load(Ordering::Relaxed) != target
        || !dpc_stack_holds(target, SEEN_SP.load(Ordering::Relaxed))
    {
        return Err("a DPC routine did not run on the DPC stack of the processor it was queued on");
    }

    // A thread of higher priority, waiting. The routine wakes it; the
    // switch to it is made at the end of the DPC interrupt, on this
    // thread's stack, before the insert returns.
    let threads = super::thread::count();
    WOKEN.store(0, Ordering::Relaxed);
    // SAFETY: static storage for an event nothing waits on; then static
    // storage for a `KDPC`, not queued.
    unsafe {
        super::wait::KeInitializeEvent(WAKE.ptr(), 0, 0);
        KeInitializeDpc(DPCS[0].ptr(), Some(locate), WAKE.ptr().cast());
    }
    super::thread::create(waiter, 0, super::thread::NORMAL_PRIORITY + 1, 1 << me)?;
    let queued = insert(0);
    let woken = WOKEN.load(Ordering::Acquire);
    super::thread::settle(threads);
    if !queued || woken != 1 {
        return Err("a thread woken by a DPC routine did not run before the interrupted thread");
    }
    Ok(target)
}

/// A DPC that never returns. The clock tick must notice.
pub fn stuck_test() {
    /// # Safety
    /// Called as a DPC routine; it dereferences none of its arguments.
    unsafe extern "C" fn spin(_: *mut KDPC, _: *mut c_void, _: *mut c_void, _: *mut c_void) {
        loop {
            core::hint::spin_loop();
        }
    }
    // SAFETY: static storage for a `KDPC`, not queued.
    unsafe { KeInitializeDpc(DPCS[0].ptr(), Some(spin), core::ptr::null_mut()) };
    insert(0);
}
