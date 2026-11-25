//! Threads and the dispatcher.
//!
//! A thread is an `ETHREAD`-sized block laid out as Windows lays it out
//! where NK keeps the same facts (`nk_ntabi::thread`), followed by NK's
//! own state, with a kernel stack of its own. `KeGetCurrentThread()`,
//! which drivers compile to a load from the processor control region,
//! yields the block's address.
//!
//! Each processor has ready queues, one per priority, and an idle thread
//! (the context the processor booted in) that runs when they are empty.
//! A thread belongs to one processor's queues. A processor gives up a
//! thread only at a call into the dispatcher: when it yields, or exits.
//!
//! Switching, the rules (`doc/LOCKING.md`):
//!
//! - The dispatcher runs at `DISPATCH_LEVEL`. The ready-queue lock is
//!   dropped before the switch itself; no lock is held across it.
//! - A thread put on a queue may still be running on its old stack for a
//!   few more instructions. `swap_busy` says so: it is set before the
//!   thread becomes visible, and cleared by whatever runs next on that
//!   processor, once it is off the old stack. A processor never switches
//!   to a thread whose `swap_busy` is set; it waits.
//! - A thread that exits is freed by the thread that runs after it.

use super::{Rank, SpinLock, irql, pcr};
use crate::arch;
use crate::mm::{self, stack::Stack};
use core::sync::atomic::{AtomicBool, AtomicPtr, AtomicU32, AtomicU64, Ordering};
use nk_ke::{ListEntry, ReadyQueues};
use nk_ntabi::pcr::NATIVE as PCR;
use nk_ntabi::thread as layout;

/// What a thread runs.
pub type Entry = fn(argument: usize);

/// The priority of an ordinary system thread, as on Windows.
pub const NORMAL_PRIORITY: u8 = 8;

/// A thread. The Windows-shaped block comes first, so a pointer to the
/// thread is a pointer to its `KTHREAD`.
#[repr(C, align(16))]
pub struct Thread {
    /// `ETHREAD`. Drivers hold its address and Microsoft's may read it,
    /// so it is only ever touched through raw pointers.
    object: [u8; layout::ETHREAD_SIZE],
    stack: Stack,
    entry: Option<Entry>,
    argument: usize,
    /// Still on its stack, though already marked as not running.
    swap_busy: AtomicBool,
    /// A processor's idle thread: never queued.
    idle: bool,
}

const _: () = assert!(size_of::<Thread>() <= mm::PAGE_SIZE);

/// One processor's dispatcher state.
pub struct Dispatcher {
    ready: SpinLock<ReadyQueues>,
    idle: AtomicPtr<Thread>,
    /// The thread this processor just switched away from, until the
    /// thread it switched to has cleaned up after it.
    previous: AtomicPtr<Thread>,
    /// Switches made here.
    switches: AtomicU64,
}

impl Dispatcher {
    pub const fn new() -> Self {
        Self {
            ready: SpinLock::new(Rank::Ready, ReadyQueues::new()),
            idle: AtomicPtr::new(core::ptr::null_mut()),
            previous: AtomicPtr::new(core::ptr::null_mut()),
            switches: AtomicU64::new(0),
        }
    }
}

/// Threads that exist, idle threads not counted.
static THREADS: AtomicU32 = AtomicU32::new(0);

pub fn count() -> u32 {
    THREADS.load(Ordering::Acquire)
}

/// A field of the thread's Windows-shaped block.
fn field<T>(thread: *mut Thread, offset: usize) -> *mut T {
    thread.wrapping_byte_add(offset).cast()
}

fn link_of(thread: *mut Thread) -> *mut ListEntry {
    field(thread, layout::WAIT_LIST_ENTRY)
}

fn thread_of(link: *mut ListEntry) -> *mut Thread {
    link.wrapping_byte_sub(layout::WAIT_LIST_ENTRY).cast()
}

/// # Safety
/// `thread` is a live thread.
unsafe fn priority(thread: *mut Thread) -> u8 {
    // SAFETY: per the contract.
    unsafe { field::<u8>(thread, layout::PRIORITY).read() }
}

/// # Safety
/// `thread` is a live thread that the caller may change the state of.
unsafe fn set_state(thread: *mut Thread, state: u8) {
    // SAFETY: per the contract.
    unsafe {
        field::<u8>(thread, layout::STATE).write(state);
        field::<u8>(thread, layout::RUNNING).write(u8::from(state == layout::state::RUNNING));
    }
}

/// The thread running on this processor.
pub fn current() -> *mut Thread {
    pcr::current_thread().cast()
}

fn set_current(thread: *mut Thread) {
    // SAFETY: the field is this processor's, an aligned pointer; drivers
    // read it but never write it.
    unsafe {
        arch::pcr()
            .add(PCR.current_thread)
            .cast::<*mut Thread>()
            .write(thread);
    }
}

/// Allocate a thread block and fill in what every thread has.
fn allocate(stack: Stack, thread_priority: u8, state: u8) -> Option<*mut Thread> {
    let thread = mm::phys_to_virt(mm::alloc_frames(1)?).cast::<Thread>();
    // SAFETY: a fresh, zeroed page, larger than a `Thread` and aligned
    // for it. Zero is valid for the Windows block; the rest is written.
    unsafe {
        (&raw mut (*thread).stack).write(stack);
        (&raw mut (*thread).entry).write(None);
        (&raw mut (*thread).swap_busy).write(AtomicBool::new(false));
        (&raw mut (*thread).idle).write(false);
        field::<u8>(thread, 0).write(layout::THREAD_OBJECT);
        field::<u64>(thread, layout::INITIAL_STACK).write(stack.top);
        field::<u64>(thread, layout::STACK_BASE).write(stack.top);
        field::<u64>(thread, layout::STACK_LIMIT).write(stack.base);
        field::<u8>(thread, layout::PRIORITY).write(thread_priority);
        field::<u8>(thread, layout::BASE_PRIORITY).write(thread_priority);
        field::<u32>(thread, layout::NEXT_PROCESSOR).write(pcr::current_processor());
        set_state(thread, state);
    }
    Some(thread)
}

/// Make the context this processor is running in its idle thread. Once
/// per processor, on `stack`, before anything else here is used.
pub fn init_cpu(stack: Stack) -> Result<(), &'static str> {
    let thread = allocate(stack, 0, layout::state::RUNNING).ok_or("no memory for a thread")?;
    // SAFETY: nothing else has the thread yet.
    unsafe { (&raw mut (*thread).idle).write(true) };
    arch::percpu()
        .dispatcher()
        .idle
        .store(thread, Ordering::Release);
    set_current(thread);
    Ok(())
}

/// Create a thread that runs `entry(argument)` at `thread_priority` on
/// processor `processor`, and make it ready.
pub fn create(
    entry: Entry,
    argument: usize,
    thread_priority: u8,
    processor: usize,
) -> Result<*mut Thread, &'static str> {
    let stack = mm::stack::alloc().ok_or("no memory for a thread's stack")?;
    let Some(thread) = allocate(stack, thread_priority, layout::state::INITIALIZED) else {
        mm::stack::free(stack);
        return Err("no memory for a thread");
    };
    // SAFETY: nothing else has the thread yet; the stack is fresh.
    unsafe {
        (&raw mut (*thread).entry).write(Some(entry));
        (&raw mut (*thread).argument).write(argument);
        field::<u64>(thread, layout::START_ADDRESS).write(entry as usize as u64);
        field::<u32>(thread, layout::NEXT_PROCESSOR).write(processor as u32);
        field::<u64>(thread, layout::KERNEL_STACK).write(arch::new_context(stack.top, start));
    }
    THREADS.fetch_add(1, Ordering::AcqRel);
    // SAFETY: the thread is whole and on no queue.
    unsafe { make_ready(thread) };
    Ok(thread)
}

/// Put `thread` at the back of its processor's queue for its priority,
/// and wake that processor if it is another.
///
/// # Safety
/// `thread` is live, on no queue, and not running (or about to stop:
/// `swap_busy` set).
unsafe fn make_ready(thread: *mut Thread) {
    let old = irql::current();
    if old < irql::DISPATCH_LEVEL {
        arch::set_irql(irql::DISPATCH_LEVEL);
    }
    // SAFETY: per the contract.
    let processor = unsafe { field::<u32>(thread, layout::NEXT_PROCESSOR).read() } as usize;
    let dispatcher = arch::percpu_of(processor)
        .expect("a thread for a processor that is not running")
        .dispatcher();
    {
        let mut ready = dispatcher.ready.lock();
        // SAFETY: per the contract; the state and the link belong to
        // the queue's lock from here on.
        unsafe {
            set_state(thread, layout::state::READY);
            ready.insert(link_of(thread), priority(thread), false);
        }
    }
    if processor != pcr::current_processor() as usize {
        // It may be idle, halted until an interrupt.
        arch::ipi_send(processor);
    }
    arch::set_irql(old);
}

/// Why the running thread is calling the dispatcher.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Leaving {
    /// It can go on running; others at its priority or above go first.
    Yield,
    /// It has finished.
    Exit,
}

/// Pick the next thread for this processor and switch to it. Called at
/// `DISPATCH_LEVEL` with no lock held. Returns (unless `Exit`) when the
/// calling thread next runs, possibly at once.
fn dispatch(leaving: Leaving) {
    let me = current();
    let dispatcher = arch::percpu().dispatcher();
    // SAFETY: `me` is the running thread.
    let (idle_thread, my_priority) = unsafe { ((*me).idle, priority(me)) };
    let next = {
        let mut ready = dispatcher.ready.lock();
        // The idle thread gives way to anything; a thread that yields,
        // to its equals and betters.
        let floor = match leaving {
            Leaving::Yield if !idle_thread => my_priority,
            _ => 0,
        };
        // SAFETY: queued threads are live.
        let next = match unsafe { ready.take(floor) } {
            Some((link, _)) => thread_of(link),
            None if leaving == Leaving::Exit => dispatcher.idle.load(Ordering::Acquire),
            None => return,
        };
        // SAFETY: `me` is the running thread. From the moment it is on
        // a queue another processor may want it: `swap_busy` first.
        unsafe {
            (*me).swap_busy.store(true, Ordering::Release);
            match leaving {
                Leaving::Exit => set_state(me, layout::state::TERMINATED),
                Leaving::Yield if idle_thread => set_state(me, layout::state::READY),
                Leaving::Yield => {
                    set_state(me, layout::state::READY);
                    ready.insert(link_of(me), my_priority, false);
                }
            }
        }
        next
    };
    // SAFETY: `next` came off this processor's queue (or is its idle
    // thread), so no other processor will run it; it may still be
    // leaving its last stack.
    unsafe {
        while (*next).swap_busy.load(Ordering::Acquire) {
            core::hint::spin_loop();
        }
        set_state(next, layout::state::RUNNING);
        set_current(next);
        arch::set_kernel_stack((*next).stack.base);
        dispatcher.previous.store(me, Ordering::Release);
        dispatcher.switches.fetch_add(1, Ordering::Relaxed);
        arch::context_switch(
            field(me, layout::KERNEL_STACK),
            field::<u64>(next, layout::KERNEL_STACK).read(),
        );
    }
    // Running again, on whatever processor took this thread.
    after_switch();
}

/// The first thing a thread does when it gets a processor: release, or
/// bury, the thread that had it before.
fn after_switch() {
    let previous = arch::percpu()
        .dispatcher()
        .previous
        .swap(core::ptr::null_mut(), Ordering::AcqRel);
    if previous.is_null() {
        return;
    }
    // SAFETY: the previous thread is off its stack now. If it exited,
    // nothing else refers to it and it is on no queue.
    unsafe {
        if field::<u8>(previous, layout::STATE).read() == layout::state::TERMINATED {
            mm::stack::free((*previous).stack);
            mm::free_frames(mm::virt_to_phys(previous.cast()), 1);
            THREADS.fetch_sub(1, Ordering::AcqRel);
        } else {
            (*previous).swap_busy.store(false, Ordering::Release);
        }
    }
}

/// Where a new thread begins.
extern "C" fn start() -> ! {
    after_switch();
    arch::set_irql(irql::PASSIVE_LEVEL);
    let me = current();
    // SAFETY: `me` is the running thread; these were written at creation.
    let (entry, argument) = unsafe { ((*me).entry, (*me).argument) };
    if let Some(entry) = entry {
        entry(argument);
    }
    exit()
}

/// Let threads of this thread's priority or above run, if any are ready.
pub fn yield_now() {
    let old = irql::raise(irql::DISPATCH_LEVEL);
    dispatch(Leaving::Yield);
    irql::lower(old);
}

/// End the calling thread.
pub fn exit() -> ! {
    irql::expect_passive("thread exit");
    arch::set_irql(irql::DISPATCH_LEVEL);
    dispatch(Leaving::Exit);
    unreachable!("a thread that exited ran again")
}

/// What a processor does when it has nothing else to do: run whatever
/// becomes ready, and otherwise wait for an interrupt.
pub fn idle_loop() -> ! {
    let dispatcher = arch::percpu().dispatcher();
    loop {
        yield_now();
        // An interrupt between looking and halting would be slept
        // through, so look with interrupts off.
        arch::disable_interrupts();
        if dispatcher.ready.lock().highest().is_none() {
            arch::wait_for_interrupt();
        } else {
            arch::enable_interrupts();
        }
    }
}

// ---- tests --------------------------------------------------------------

static RAN: AtomicU32 = AtomicU32::new(0);
/// What the test threads saw, four bits each.
static TRACE: AtomicU64 = AtomicU64::new(0);
static WRONG: AtomicU32 = AtomicU32::new(0);

fn note(tag: u64) {
    let _ = TRACE.try_update(Ordering::AcqRel, Ordering::Acquire, |t| Some(t << 4 | tag));
}

/// Wait, yielding, until only `threads` threads exist; `false` after two
/// seconds.
fn settle(threads: u32) -> bool {
    let deadline = super::time::interrupt_time() + 20_000_000;
    while count() != threads {
        if super::time::interrupt_time() > deadline {
            return false;
        }
        yield_now();
        core::hint::spin_loop();
    }
    true
}

/// Threads are created, run on their own stacks at PASSIVE_LEVEL as the
/// current thread, exit, and leave nothing behind. Returns how many ran.
pub fn lifecycle_test() -> Result<u32, &'static str> {
    fn body(argument: usize) {
        let me = current();
        let sp = &raw const argument as u64;
        // SAFETY: `me` is the running thread.
        let stack = unsafe { (*me).stack };
        if irql::current() != irql::PASSIVE_LEVEL
            || !(stack.base..stack.top).contains(&sp)
            || argument != 0x1234
        {
            WRONG.fetch_add(1, Ordering::Relaxed);
        }
        RAN.fetch_add(1, Ordering::Release);
    }
    const ROUNDS: u32 = 200;
    let before = count();
    let frames = mm::free_frame_count();
    RAN.store(0, Ordering::Relaxed);
    WRONG.store(0, Ordering::Relaxed);
    let me = pcr::current_processor() as usize;
    for _ in 0..ROUNDS {
        create(body, 0x1234, NORMAL_PRIORITY, me)?;
        yield_now();
    }
    if !settle(before) {
        return Err("threads that returned from their entry were not reaped");
    }
    if RAN.load(Ordering::Acquire) != ROUNDS {
        return Err("not every thread ran once");
    }
    if WRONG.load(Ordering::Relaxed) != 0 {
        return Err("a thread ran at the wrong IRQL, off its stack, or without its argument");
    }
    if mm::free_frame_count() < frames {
        return Err("threads leaked memory");
    }
    Ok(ROUNDS)
}

/// Threads of one priority take turns in the order they became ready;
/// a yield goes to the back.
pub fn turns_test() -> Result<(), &'static str> {
    fn body(tag: usize) {
        note(tag as u64);
        yield_now();
        note(tag as u64 + 8);
    }
    let before = count();
    TRACE.store(0, Ordering::Relaxed);
    let me = pcr::current_processor() as usize;
    for tag in 1..=3 {
        create(body, tag, NORMAL_PRIORITY, me)?;
    }
    if !settle(before) {
        return Err("the threads did not finish");
    }
    // 1, 2, 3 each run to their yield, then each finishes, in order.
    if TRACE.load(Ordering::Acquire) != 0x123_9AB {
        return Err("threads of one priority did not take turns in order");
    }
    Ok(())
}

/// A yield gives way to a higher priority and to an equal one, never to
/// a lower one.
pub fn priority_test() -> Result<(), &'static str> {
    fn body(tag: usize) {
        note(tag as u64);
    }
    let before = count();
    TRACE.store(0, Ordering::Relaxed);
    let me = pcr::current_processor() as usize;
    create(body, 1, NORMAL_PRIORITY - 1, me)?;
    create(body, 2, NORMAL_PRIORITY, me)?;
    create(body, 3, NORMAL_PRIORITY + 4, me)?;
    yield_now();
    // The higher and the equal one have run, in that order; the lower
    // one has not, for all that it was ready first.
    let after_yield = TRACE.load(Ordering::Acquire);
    // Without waits, a lower thread runs only when this one is out of
    // the way: move it up for the purpose.
    // SAFETY: only the tag-1 thread is left; it is on this processor's
    // queue, which is not running while this thread is.
    let moved = unsafe { raise_ready(NORMAL_PRIORITY - 1, NORMAL_PRIORITY) };
    if !settle(before) {
        return Err("the threads did not finish");
    }
    if after_yield != 0x32 {
        return Err("a yield did not run the higher then the equal thread, and only those");
    }
    if !moved || TRACE.load(Ordering::Acquire) != 0x321 {
        return Err("the lower-priority thread did not run last");
    }
    Ok(())
}

/// Move the first ready thread of this processor at priority `from` to
/// priority `to`. For the tests.
///
/// # Safety
/// The caller is a thread on this processor.
unsafe fn raise_ready(from: u8, to: u8) -> bool {
    let mut ready = arch::percpu().dispatcher().ready.lock();
    // SAFETY: queued threads are live, and their priority belongs to
    // the queue's lock while they are queued.
    unsafe {
        let Some((link, found)) = ready.take(from) else {
            return false;
        };
        if found != from {
            ready.insert(link, found, true);
            return false;
        }
        field::<u8>(thread_of(link), layout::PRIORITY).write(to);
        ready.insert(link, to, false);
    }
    true
}

/// A thread created for another processor runs there. Returns that
/// processor's number.
pub fn other_cpu_test() -> Result<u32, &'static str> {
    fn body(_: usize) {
        note(u64::from(pcr::current_processor()) + 1);
    }
    let before = count();
    let target = super::smp::online_count() - 1;
    TRACE.store(0, Ordering::Relaxed);
    create(body, 0, NORMAL_PRIORITY, target)?;
    if !settle(before) {
        return Err("a thread created for another processor did not run and exit");
    }
    if TRACE.load(Ordering::Acquire) != target as u64 + 1 {
        return Err("the thread did not run on the processor it was created for");
    }
    Ok(target as u32)
}

/// Registers a call preserves, vector ones included, survive switches:
/// two threads fill them with different values and yield to each other.
pub fn registers_test() -> Result<u32, &'static str> {
    extern "C" fn switch_away() {
        yield_now();
    }
    fn body(seed: usize) {
        for round in 0..50 {
            if !arch::callee_saved_survive(seed as u64 * 1000 + round, switch_away) {
                WRONG.fetch_add(1, Ordering::Relaxed);
            }
        }
        RAN.fetch_add(1, Ordering::Release);
    }
    let before = count();
    RAN.store(0, Ordering::Relaxed);
    WRONG.store(0, Ordering::Relaxed);
    let me = pcr::current_processor() as usize;
    for seed in 1..=3 {
        create(body, seed, NORMAL_PRIORITY, me)?;
    }
    if !settle(before) || RAN.load(Ordering::Acquire) != 3 {
        return Err("the threads did not finish");
    }
    if WRONG.load(Ordering::Relaxed) != 0 {
        return Err("a register a call preserves changed across a thread switch");
    }
    Ok(150)
}
