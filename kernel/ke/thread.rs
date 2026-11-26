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
//! A ready thread is on one processor's queues. It is put on its ideal
//! processor's if that one is idle, else on those of any idle processor
//! its affinity allows, else on its ideal processor's; and an idle
//! processor with nothing of its own takes a thread from another's. A processor gives up a
//! thread when the thread yields or exits, when a thread of higher
//! priority becomes ready there, or when the thread has run for its
//! quantum and another of its priority is waiting.
//!
//! Preemption is asked for, not done on the spot: readying a thread or
//! the clock tick marks the processor, and the switch happens at the end
//! of the next interrupt that returns below `DISPATCH_LEVEL`
//! (`interrupt::dispatch`). Marking the processor one is running on also
//! requests the DISPATCH-level interrupt, so that end comes as soon as
//! the IRQL allows.
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
//! - Only an idle thread waits for a `swap_busy` thread, and only an
//!   idle thread takes from another processor's queues. A thread that
//!   finds its successor still busy switches to its processor's idle
//!   thread instead, which is never busy for long and never wanted
//!   elsewhere; so no ring of processors can form, each waiting for the
//!   thread the next is leaving.
//! - A thread that exits is buried by the thread that runs after it:
//!   its stack is freed, it is signalled (a thread is an object others
//!   can wait on), and the reference it held on itself while it ran is
//!   dropped. The block itself lives until the last reference goes.

use super::{Rank, SpinLock, irql, pcr};
use crate::arch;
use crate::mm::{self, stack::Stack};
use crate::ob;
use core::sync::atomic::{AtomicBool, AtomicPtr, AtomicU8, AtomicU32, AtomicU64, Ordering};
use nk_ke::sched::{self, Leaving};
use nk_ke::{ListEntry, QUANTUM_TICKS, ReadyQueues, WaitRegister};
use nk_ntabi::ke::{DISPATCHER_HEADER, KTIMER, KWAIT_BLOCK};
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
    /// Clock ticks left before threads of this priority get a turn.
    quantum: AtomicU8,
    /// Where the thread stands with respect to waiting.
    wait: WaitRegister,
    /// The next thread in a waker's list of threads to make ready.
    wake_link: *mut Thread,
}

/// One processor's dispatcher state.
pub struct Dispatcher {
    ready: SpinLock<ReadyQueues>,
    idle: AtomicPtr<Thread>,
    /// The thread this processor just switched away from, until the
    /// thread it switched to has cleaned up after it.
    previous: AtomicPtr<Thread>,
    /// Switches made here.
    switches: AtomicU64,
    /// Something happened that may call for a different thread here.
    switch_wanted: AtomicBool,
    /// The idle thread is what is running here.
    idling: AtomicBool,
}

impl Dispatcher {
    pub const fn new() -> Self {
        Self {
            ready: SpinLock::new(Rank::Ready, ReadyQueues::new()),
            idle: AtomicPtr::new(core::ptr::null_mut()),
            previous: AtomicPtr::new(core::ptr::null_mut()),
            switches: AtomicU64::new(0),
            switch_wanted: AtomicBool::new(false),
            idling: AtomicBool::new(true),
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

/// The running thread's stack.
pub fn current_stack() -> Stack {
    // SAFETY: the running thread exists, and its stack is set when it is
    // made and never changed.
    unsafe { (*current()).stack }
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
    let thread =
        ob::object::create(&ob::object::THREAD_TYPE, size_of::<Thread>())?.cast::<Thread>();
    assert!(
        thread.is_aligned(),
        "the pool gave a misaligned thread block"
    );
    // SAFETY: a fresh, zeroed object of a thread's size, aligned for
    // it. Zero is valid for the Windows block; the rest is written.
    unsafe {
        super::object::init_wait_list(thread.cast());
        (&raw mut (*thread).stack).write(stack);
        (&raw mut (*thread).entry).write(None);
        (&raw mut (*thread).swap_busy).write(AtomicBool::new(false));
        (&raw mut (*thread).idle).write(false);
        (&raw mut (*thread).quantum).write(AtomicU8::new(QUANTUM_TICKS));
        (&raw mut (*thread).wait).write(WaitRegister::new());
        (&raw mut (*thread).wake_link).write(core::ptr::null_mut());
        super::wait::init_thread(thread);
        super::mutex::init_thread(thread);
        field::<u8>(thread, 0).write(layout::THREAD_OBJECT);
        field::<u64>(thread, layout::INITIAL_STACK).write(stack.top);
        field::<u64>(thread, layout::STACK_BASE).write(stack.top);
        field::<u64>(thread, layout::STACK_LIMIT).write(stack.base);
        field::<u8>(thread, layout::PRIORITY).write(thread_priority);
        field::<u8>(thread, layout::BASE_PRIORITY).write(thread_priority);
        field::<u32>(thread, layout::NEXT_PROCESSOR).write(pcr::current_processor());
        let process = crate::ps::process::system();
        field::<*mut u8>(thread, layout::PROCESS).write(process);
        field::<*mut u8>(thread, layout::APC_STATE_PROCESS).write(process);
        field::<[u64; 2]>(thread, layout::CID).write([
            nk_ntabi::process::SYSTEM_PROCESS_ID,
            crate::ps::process::new_thread_id(),
        ]);
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

/// The next ideal processor to hand out: threads are spread in turn.
static NEXT_IDEAL: AtomicU32 = AtomicU32::new(0);

/// Every processor: the affinity of a thread that may run anywhere.
pub const ANYWHERE: u64 = u64::MAX;

/// Create a thread that runs `entry(argument)` at `thread_priority` on
/// the processors in the mask `affinity`, and make it ready. With
/// `keep`, the caller gets a reference of its own.
fn create_thread(
    entry: Entry,
    argument: usize,
    thread_priority: u8,
    affinity: u64,
    keep: bool,
) -> Result<*mut Thread, &'static str> {
    let thread = new_thread(entry, argument, thread_priority, affinity)?;
    // SAFETY: the thread is whole and on no queue. The caller's
    // reference is taken first: the thread may run and end at once.
    unsafe {
        if keep {
            ob::object::reference(thread.cast());
        }
        make_ready(thread);
    }
    Ok(thread)
}

/// Create a thread as [`create_referenced`] does, but do not make it
/// ready: it runs once [`begin`] has started it, or never, if
/// [`discard`] takes it back. For a creator that has something to do
/// that may fail before the thread may run.
pub fn create_unstarted(
    entry: Entry,
    argument: usize,
    thread_priority: u8,
    affinity: u64,
) -> Result<*mut Thread, &'static str> {
    let thread = new_thread(entry, argument, thread_priority, affinity)?;
    // SAFETY: a live thread nothing else has.
    unsafe { ob::object::reference(thread.cast()) };
    Ok(thread)
}

/// Start a thread from [`create_unstarted`].
///
/// # Safety
/// `thread` came from `create_unstarted` and has been neither started
/// nor discarded.
pub unsafe fn begin(thread: *mut Thread) {
    // SAFETY: per the contract: whole, and on no queue.
    unsafe { make_ready(thread) };
}

/// Take back a thread from [`create_unstarted`] that will never run:
/// its stack, its count, and the reference it holds on itself. The
/// caller's reference stays the caller's to drop.
///
/// # Safety
/// As [`begin`].
pub unsafe fn discard(thread: *mut Thread) {
    // SAFETY: per the contract: the thread is on no queue and never
    // ran, so nothing waits on it and nothing uses its stack.
    unsafe {
        mm::stack::free((*thread).stack);
        ob::object::dereference(thread.cast());
    }
    THREADS.fetch_sub(1, Ordering::AcqRel);
}

/// A new thread that will run `entry(argument)`, whole, counted and on
/// no queue: not yet ready.
fn new_thread(
    entry: Entry,
    argument: usize,
    thread_priority: u8,
    affinity: u64,
) -> Result<*mut Thread, &'static str> {
    let allowed = affinity & super::smp::online();
    if allowed == 0 {
        return Err("a thread's affinity names no running processor");
    }
    // The ideal processor: the next in turn among those allowed.
    let turn = NEXT_IDEAL.fetch_add(1, Ordering::Relaxed);
    let ideal = sched::ideal_processor(allowed, turn).unwrap_or(0);
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
        field::<u64>(thread, layout::AFFINITY).write(allowed);
        field::<u32>(thread, layout::IDEAL_PROCESSOR).write(ideal as u32);
        field::<u64>(thread, layout::KERNEL_STACK).write(arch::new_context(stack.top, start));
    }
    THREADS.fetch_add(1, Ordering::AcqRel);
    Ok(thread)
}

/// Create a thread and forget it: it frees itself when it ends. The
/// pointer returned is for identification only.
pub fn create(
    entry: Entry,
    argument: usize,
    thread_priority: u8,
    affinity: u64,
) -> Result<*mut Thread, &'static str> {
    create_thread(entry, argument, thread_priority, affinity, false)
}

/// Create a thread and keep a reference to it, to wait for its end. The
/// caller drops the reference with `ob::object::dereference`.
pub fn create_referenced(
    entry: Entry,
    argument: usize,
    thread_priority: u8,
    affinity: u64,
) -> Result<*mut Thread, &'static str> {
    create_thread(entry, argument, thread_priority, affinity, true)
}

/// Whether processor `number` is running its idle thread.
fn idling(number: usize) -> bool {
    arch::percpu_of(number).is_some_and(|p| p.dispatcher().idling.load(Ordering::Acquire))
}

/// Wake one idle processor among `allowed`, other than this one, so
/// that it looks for work to take.
fn wake_an_idle(allowed: u64) {
    let me = pcr::current_processor() as usize;
    if let Some(number) = sched::idle_to_wake(allowed, me, idling)
        && let Some(there) = arch::percpu_of(number)
    {
        // The request outlives the interrupt: if that processor is
        // between looking for work and halting, it looks again.
        there
            .dispatcher()
            .switch_wanted
            .store(true, Ordering::Release);
        arch::ipi_send(number);
    }
}

/// Take a thread this processor may run from another processor's queues:
/// the best that one has, if its affinity allows.
fn steal() -> Option<*mut Thread> {
    let me = pcr::current_processor() as usize;
    let processors = super::smp::online_count();
    for other in sched::steal_order(me, processors) {
        let Some(dispatcher) = arch::percpu_of(other).map(|p| p.dispatcher()) else {
            continue;
        };
        let mut ready = dispatcher.ready.lock();
        // SAFETY: queued threads are live, and while queued their
        // affinity and processor belong to the queue's lock.
        unsafe {
            let Some((link, found)) = ready.take(0) else {
                continue;
            };
            let thread = thread_of(link);
            if field::<u64>(thread, layout::AFFINITY).read() & 1 << me == 0 {
                ready.insert(link, found, true);
                continue;
            }
            field::<u32>(thread, layout::NEXT_PROCESSOR).write(me as u32);
            return Some(thread);
        }
    }
    None
}

/// The thread's wait register.
pub fn wait_register<'a>(thread: *mut Thread) -> &'a WaitRegister {
    // SAFETY: a thread's register lives as long as the thread, and
    // callers hold a thread they found through a linked wait block or
    // the current-thread slot.
    unsafe { &(*thread).wait }
}

/// A field of the thread's Windows-shaped block, for the modules that
/// keep their own facts there.
pub fn object_field<T>(thread: *mut Thread, offset: usize) -> *mut T {
    field(thread, offset)
}

/// One of the thread's four built-in wait blocks.
pub fn wait_block(thread: *mut Thread, index: usize) -> *mut KWAIT_BLOCK {
    field::<KWAIT_BLOCK>(thread, layout::WAIT_BLOCK).wrapping_add(index)
}

/// The thread's own timer, for waits with a time limit.
pub fn timer(thread: *mut Thread) -> *mut KTIMER {
    field(thread, layout::TIMER)
}

/// Record what the thread's wait returned, where Windows keeps it.
///
/// # Safety
/// `thread` is the running thread.
pub unsafe fn set_wait_status(thread: *mut Thread, status: u32) {
    // SAFETY: per the contract.
    unsafe { field::<u64>(thread, layout::WAIT_STATUS).write(u64::from(status)) };
}

/// Chain `thread`, just claimed asleep, in front of `next`.
///
/// # Safety
/// The caller claimed `thread` asleep and has not yet made it ready.
pub unsafe fn set_wake_link(thread: *mut Thread, next: *mut Thread) {
    // SAFETY: per the contract, the thread is the caller's alone.
    unsafe { (&raw mut (*thread).wake_link).write(next) };
}

/// Unchain `thread`: the thread that was chained after it.
///
/// # Safety
/// As `set_wake_link`.
pub unsafe fn take_wake_link(thread: *mut Thread) -> *mut Thread {
    // SAFETY: per the contract.
    unsafe { (&raw mut (*thread).wake_link).replace(core::ptr::null_mut()) }
}

/// Give up the processor until a waker makes this thread ready, unless
/// one has already claimed it. Called at `DISPATCH_LEVEL` by a thread
/// whose wait has begun.
pub fn sleep() {
    dispatch(Leaving::Wait);
}

/// Put `thread` at the back of a processor's queue for its priority, and
/// have that processor reconsider what it runs.
///
/// # Safety
/// `thread` is live, on no queue, and not running (or about to stop:
/// `swap_busy` set).
pub unsafe fn make_ready(thread: *mut Thread) {
    let old = irql::current();
    if old < irql::DISPATCH_LEVEL {
        arch::set_irql(irql::DISPATCH_LEVEL);
    }
    // SAFETY: per the contract; on no queue, the thread is the caller's.
    let processor = unsafe {
        let processor = sched::place(
            field::<u64>(thread, layout::AFFINITY).read(),
            field::<u32>(thread, layout::IDEAL_PROCESSOR).read() as usize,
            idling,
        );
        field::<u32>(thread, layout::NEXT_PROCESSOR).write(processor as u32);
        processor
    };
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
    // The new thread may outrank what that processor is running. Have
    // it look, at the end of an interrupt: its own DISPATCH-level one
    // here, the interprocessor one there (which also wakes it if it is
    // halted, idle).
    dispatcher.switch_wanted.store(true, Ordering::Release);
    if processor == pcr::current_processor() as usize {
        arch::self_interrupt(arch::DPC.0);
    } else {
        arch::ipi_send(processor);
    }
    arch::set_irql(old);
}

/// Whether this processor has been asked to reconsider what it runs.
pub fn switch_wanted() -> bool {
    arch::percpu()
        .dispatcher()
        .switch_wanted
        .load(Ordering::Acquire)
}

/// Reconsider what this processor runs. Called at `DISPATCH_LEVEL`, from
/// the end of an interrupt, with no lock held.
pub fn preempt() {
    arch::percpu()
        .dispatcher()
        .switch_wanted
        .store(false, Ordering::Release);
    dispatch(Leaving::Preempt);
}

/// Called from the clock tick: charge the running thread for the tick,
/// and when its quantum is spent ask for a switch.
pub fn tick() {
    let me = current();
    // SAFETY: `me` is the running thread.
    let quantum = unsafe { &(*me).quantum };
    let left = quantum.load(Ordering::Relaxed).saturating_sub(1);
    quantum.store(left, Ordering::Relaxed);
    if left == 0 {
        arch::percpu()
            .dispatcher()
            .switch_wanted
            .store(true, Ordering::Release);
    }
}

/// Pick the next thread for this processor and switch to it. Called at
/// `DISPATCH_LEVEL` with no lock held. Returns (unless `Exit`) when the
/// calling thread next runs, possibly at once.
fn dispatch(leaving: Leaving) {
    let me = current();
    let dispatcher = arch::percpu().dispatcher();
    // SAFETY: `me` is the running thread.
    let (idle_thread, my_priority) = unsafe { ((*me).idle, priority(me)) };
    if leaving == Leaving::Wait {
        // From the commit on, a waker may make this thread ready and
        // another processor may want it: `swap_busy` first. If a waker
        // has already claimed it, it does not sleep at all.
        // SAFETY: `me` is the running thread.
        unsafe {
            (*me).swap_busy.store(true, Ordering::Release);
            if !(*me).wait.commit() {
                (*me).swap_busy.store(false, Ordering::Release);
                return;
            }
        }
    }
    let next = {
        let mut ready = dispatcher.ready.lock();
        // SAFETY: `me` is the running thread.
        let quantum = unsafe { &(*me).quantum };
        let spent = quantum.load(Ordering::Relaxed) == 0;
        let floor = leaving.floor(idle_thread, spent, my_priority);
        if leaving.new_turn(spent) {
            // Whether or not anyone is waiting, a new turn begins.
            quantum.store(QUANTUM_TICKS, Ordering::Relaxed);
        }
        // SAFETY: queued threads are live.
        let taken = unsafe { ready.take(floor) };
        let busy = taken.is_some_and(|(link, _)| {
            // SAFETY: as above.
            unsafe { (*thread_of(link)).swap_busy.load(Ordering::Acquire) }
        });
        let next = match taken {
            // Still leaving its last stack on another processor: only
            // the idle thread may wait for it.
            Some((link, found)) if !idle_thread && busy => {
                // SAFETY: as above; back where it was.
                unsafe { ready.insert(link, found, true) };
                dispatcher.idle.load(Ordering::Acquire)
            }
            Some((link, _)) => thread_of(link),
            None if leaving.stops() => dispatcher.idle.load(Ordering::Acquire),
            None if idle_thread => {
                drop(ready);
                match steal() {
                    Some(thread) => {
                        // SAFETY: `me` is this processor's idle thread,
                        // which is on no queue and wanted by no one.
                        unsafe {
                            (*me).swap_busy.store(true, Ordering::Release);
                            set_state(me, layout::state::READY);
                        }
                        return switch_to(me, thread);
                    }
                    None => return,
                }
            }
            None => return,
        };
        // SAFETY: `me` is the running thread. From the moment it is on
        // a queue another processor may want it: `swap_busy` first.
        unsafe {
            (*me).swap_busy.store(true, Ordering::Release);
            match leaving {
                Leaving::Exit => set_state(me, layout::state::TERMINATED),
                Leaving::Wait => set_state(me, layout::state::WAITING),
                _ if idle_thread => set_state(me, layout::state::READY),
                _ => {
                    set_state(me, layout::state::READY);
                    let front = leaving.requeue_in_front(spent);
                    ready.insert(link_of(me), my_priority, front);
                }
            }
        }
        next
    };
    if !leaving.stops() && !idle_thread {
        // This thread is waiting now; a processor with nothing to do
        // may take it.
        // SAFETY: `me` is still on this processor; its affinity changes
        // only at creation.
        wake_an_idle(unsafe { field::<u64>(me, layout::AFFINITY).read() });
    }
    switch_to(me, next);
}

/// Leave `me`, already marked and queued as its leaving requires, for
/// `next`, which this processor took off a queue or is its idle thread.
fn switch_to(me: *mut Thread, next: *mut Thread) {
    // A DPC routine runs on the processor's DPC stack, which the next DPC
    // will use: no thread can be left there. Only a routine that lowered
    // the IRQL gets this far.
    if super::dpc::running() {
        crate::kd::bugcheck(format_args!(
            "0x000000B8 ATTEMPTED_SWITCH_FROM_DPC: a thread switch while a DPC routine runs"
        ));
    }
    let dispatcher = arch::percpu().dispatcher();
    // SAFETY: `next` is this processor's to run; it may still be leaving
    // its last stack, and then `me` is the idle thread (see `dispatch`).
    unsafe {
        dispatcher.idling.store((*next).idle, Ordering::Release);
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
            let header = previous.cast::<DISPATCHER_HEADER>();
            // Its memory is about to be reused: nothing may still point
            // into it. A wait cancels its own timer, so this holds.
            assert!(
                !super::timer::pending(timer(previous)),
                "a thread exited with its wait timer pending"
            );
            super::mutex::check_none_held(previous);
            mm::stack::free((*previous).stack);
            // It has ended: whoever waits for it may go on.
            let woken = {
                let _lock = super::object::ObjectLock::take(header);
                super::object::signal(header).store(1, Ordering::Release);
                super::object::satisfy(header)
            };
            woken.ready();
            // The reference it held on itself while it could run. Only
            // then is it counted gone: whoever waits for the count to
            // fall finds the memory already returned.
            ob::object::dereference(previous.cast());
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
        // Cleared before looking: a request that arrives while this
        // processor looks, or after, is still there when it has looked.
        dispatcher.switch_wanted.store(false, Ordering::Release);
        yield_now();
        // An interrupt between deciding to halt and halting would be
        // slept through, so decide with interrupts off.
        arch::disable_interrupts();
        if dispatcher.ready.lock().highest().is_none()
            && !dispatcher.switch_wanted.load(Ordering::Acquire)
        {
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
        create(body, 0x1234, NORMAL_PRIORITY, 1 << me)?;
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
        create(body, tag, NORMAL_PRIORITY, 1 << me)?;
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
    create(body, 1, NORMAL_PRIORITY - 1, 1 << me)?;
    create(body, 2, NORMAL_PRIORITY, 1 << me)?;
    create(body, 3, NORMAL_PRIORITY + 4, 1 << me)?;
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

/// [`KeSetPriorityThread`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-kesetprioritythread):
/// give the calling thread another priority; returns the old one. A
/// thread that lowers itself below a ready thread gives way at once.
///
/// Only the calling thread can be changed: another thread's priority
/// belongs to whichever queue it is on or is about to join, and NK has
/// no lock yet that covers a thread wherever it is. Asking for it stops
/// the system rather than doing half the job.
///
/// # Safety
/// `thread` is a thread object.
#[allow(non_snake_case)]
pub unsafe extern "C" fn KeSetPriorityThread(thread: *mut core::ffi::c_void, new: i32) -> i32 {
    let thread = thread.cast::<Thread>();
    if !(0..32).contains(&new) {
        crate::kd::bugcheck(format_args!("KeSetPriorityThread: {new} is not a priority"));
    }
    // At DISPATCH_LEVEL the thread stays on this processor and is not
    // switched away from between the comparison and the change.
    let old = irql::current();
    if old < irql::DISPATCH_LEVEL {
        arch::set_irql(irql::DISPATCH_LEVEL);
    }
    if thread != current() {
        crate::kd::bugcheck(format_args!(
            "KeSetPriorityThread: changing the priority of a thread other than the caller is not implemented"
        ));
    }
    // SAFETY: the running thread; its priority is its own while it runs.
    let before = unsafe {
        let before = priority(thread);
        field::<u8>(thread, layout::PRIORITY).write(new as u8);
        (*thread).quantum.store(QUANTUM_TICKS, Ordering::Relaxed);
        before
    };
    if (new as u8) < before {
        // Something ready may now outrank it: look, as soon as the
        // IRQL allows.
        arch::percpu()
            .dispatcher()
            .switch_wanted
            .store(true, Ordering::Release);
        arch::self_interrupt(arch::DPC.0);
    }
    arch::set_irql(old);
    i32::from(before)
}

/// A thread that changes its own priority gets the old one back, and
/// gives way at once when it steps below a ready thread.
pub fn set_priority_test() -> Result<(), &'static str> {
    fn body(tag: usize) {
        note(tag as u64);
    }
    let before = count();
    TRACE.store(0, Ordering::Relaxed);
    let me = pcr::current_processor() as usize;
    let this = current().cast::<core::ffi::c_void>();
    // SAFETY: the calling thread, here and below.
    let was = unsafe { KeSetPriorityThread(this, 16) };
    // Created below this thread, neither runs yet.
    create(body, 1, 12, 1 << me)?;
    create(body, 2, NORMAL_PRIORITY + 1, 1 << me)?;
    let waiting = TRACE.load(Ordering::Acquire);
    // SAFETY: as above.
    let (from_16, after_first, from_10, after_second) = unsafe {
        // Below the first but not the second: the first runs, now.
        let from_16 = KeSetPriorityThread(this, 10);
        let after_first = TRACE.load(Ordering::Acquire);
        // Back where it started, below the second too.
        let from_10 = KeSetPriorityThread(this, i32::from(NORMAL_PRIORITY));
        (from_16, after_first, from_10, TRACE.load(Ordering::Acquire))
    };
    if !settle(before) {
        return Err("the threads did not finish");
    }
    if (was, from_16, from_10) != (i32::from(NORMAL_PRIORITY), 16, 10) {
        return Err("setting a priority did not return the one before");
    }
    if waiting != 0 {
        return Err("a thread ran while a higher-priority thread was running");
    }
    if (after_first, after_second) != (0x1, 0x12) {
        return Err(
            "a thread that lowered its priority did not give way at once, or gave way to a lower thread",
        );
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
    create(body, 0, NORMAL_PRIORITY, 1 << target)?;
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
        create(body, seed, NORMAL_PRIORITY, 1 << me)?;
    }
    if !settle(before) || RAN.load(Ordering::Acquire) != 3 {
        return Err("the threads did not finish");
    }
    if WRONG.load(Ordering::Relaxed) != 0 {
        return Err("a register a call preserves changed across a thread switch");
    }
    Ok(150)
}

/// A thread of higher priority runs the moment it is made ready, before
/// its creator's next step; one of lower priority does not.
pub fn preempt_test() -> Result<(), &'static str> {
    fn body(tag: usize) {
        note(tag as u64);
    }
    let before = count();
    TRACE.store(0, Ordering::Relaxed);
    let me = pcr::current_processor() as usize;
    create(body, 1, NORMAL_PRIORITY - 1, 1 << me)?;
    let after_lower = TRACE.load(Ordering::Acquire);
    create(body, 2, NORMAL_PRIORITY + 1, 1 << me)?;
    let after_higher = TRACE.load(Ordering::Acquire);
    // SAFETY: the lower thread is still on this processor's queue.
    let moved = unsafe { raise_ready(NORMAL_PRIORITY - 1, NORMAL_PRIORITY) };
    if !moved || !settle(before) {
        return Err("the threads did not finish");
    }
    if after_lower != 0 {
        return Err("a thread of lower priority ran ahead of its creator");
    }
    if after_higher != 0x2 {
        return Err("a thread of higher priority did not run as soon as it was ready");
    }
    Ok(())
}

static STOP: AtomicBool = AtomicBool::new(false);
static SPINS: [AtomicU64; 3] = [const { AtomicU64::new(0) }; 3];

/// Threads of one priority that never give up the processor still share
/// it: the clock takes it from each in turn. Returns the switches made.
pub fn quantum_test() -> Result<u64, &'static str> {
    fn body(which: usize) {
        while !STOP.load(Ordering::Acquire) {
            SPINS[which].fetch_add(1, Ordering::Relaxed);
            core::hint::spin_loop();
        }
    }
    let before = count();
    let dispatcher = arch::percpu().dispatcher();
    STOP.store(false, Ordering::Release);
    for spins in &SPINS {
        spins.store(0, Ordering::Relaxed);
    }
    let me = pcr::current_processor() as usize;
    for which in 0..3 {
        create(body, which, NORMAL_PRIORITY, 1 << me)?;
    }
    let switches = dispatcher.switches.load(Ordering::Relaxed);
    // This thread spins too, as the fourth: about half a second each.
    super::time::stall(2_000_000);
    STOP.store(true, Ordering::Release);
    let switches = dispatcher.switches.load(Ordering::Relaxed) - switches;
    if !settle(before) {
        return Err("the threads did not finish");
    }
    let spins = SPINS.each_ref().map(|s| s.load(Ordering::Relaxed));
    let (least, most) = (
        spins.iter().min().unwrap_or(&0),
        spins.iter().max().unwrap_or(&0),
    );
    if *least == 0 {
        return Err("a thread that never yields starved its equals");
    }
    if *most > 10 * *least {
        return Err("equal threads' shares of the processor differ more than tenfold");
    }
    // Two seconds of two-tick turns is about 64 switches.
    if switches < 16 {
        return Err("the processor hardly changed hands");
    }
    Ok(switches)
}

/// Every register, vector ones included, survives being interrupted and
/// switched away from: threads that never call anything hold values in
/// all of them while the clock moves the processor between them.
/// Returns the checks made.
pub fn preempt_registers_test() -> Result<u64, &'static str> {
    fn body(seed: usize) {
        let until = super::time::interrupt_time() + 2_500_000;
        while super::time::interrupt_time() < until {
            if !arch::all_registers_survive(seed as u64 * 0x1_0000, 2000) {
                WRONG.fetch_add(1, Ordering::Relaxed);
            }
            SPINS[seed - 1].fetch_add(2000, Ordering::Relaxed);
        }
    }
    let before = count();
    WRONG.store(0, Ordering::Relaxed);
    for spins in &SPINS {
        spins.store(0, Ordering::Relaxed);
    }
    let me = pcr::current_processor() as usize;
    for seed in 1..=3 {
        create(body, seed, NORMAL_PRIORITY, 1 << me)?;
    }
    if !settle(before) {
        return Err("the threads did not finish");
    }
    if WRONG.load(Ordering::Relaxed) != 0 {
        return Err("a register changed under a thread that was preempted");
    }
    let checks: u64 = SPINS.iter().map(|s| s.load(Ordering::Relaxed)).sum();
    if SPINS.iter().any(|s| s.load(Ordering::Relaxed) == 0) {
        return Err("a thread made no checks");
    }
    Ok(checks)
}

/// Where the runner of `migrate_test` is.
static RUNNER_ON: AtomicU32 = AtomicU32::new(u32::MAX);

/// A thread that may run anywhere moves when it has to wait and another
/// processor is idle, and what a call preserves survives the move. A
/// runner is chased from processor to processor by threads pinned to
/// whichever one it is on. Returns the moves it made.
pub fn migrate_test() -> Result<u64, &'static str> {
    extern "C" fn switch_away() {
        yield_now();
    }
    fn runner(seed: usize) {
        let mut last = pcr::current_processor();
        while !STOP.load(Ordering::Acquire) {
            if !arch::callee_saved_survive(seed as u64, switch_away) {
                WRONG.fetch_add(1, Ordering::Relaxed);
            }
            let now = pcr::current_processor();
            if now != last {
                SPINS[0].fetch_add(1, Ordering::Relaxed);
                last = now;
            }
            RUNNER_ON.store(now, Ordering::Release);
        }
    }
    fn blocker(_: usize) {
        // Long enough for the runner to be taken elsewhere.
        super::time::stall(30_000);
    }
    const CHASES: u64 = 8;
    let before = count();
    let processors = super::smp::online_count();
    WRONG.store(0, Ordering::Relaxed);
    SPINS[0].store(0, Ordering::Relaxed);
    STOP.store(false, Ordering::Release);
    RUNNER_ON.store(u32::MAX, Ordering::Release);
    create(runner, 0x5EED, NORMAL_PRIORITY, ANYWHERE)?;
    // Keep at it until the runner has moved often enough. A chase can
    // miss: where the runner says it is may be a moment out of date.
    let deadline = super::time::interrupt_time() + 30_000_000;
    while processors >= 3
        && SPINS[0].load(Ordering::Relaxed) < CHASES
        && super::time::interrupt_time() < deadline
    {
        let on = RUNNER_ON.load(Ordering::Acquire);
        if on == u32::MAX {
            yield_now();
            continue;
        }
        // Something else to run where the runner is: when the runner
        // next yields it waits there, and an idle processor takes it.
        let moves = SPINS[0].load(Ordering::Relaxed);
        create(blocker, 0, NORMAL_PRIORITY, 1 << on)?;
        let patience = super::time::interrupt_time() + 1_000_000;
        while SPINS[0].load(Ordering::Relaxed) == moves && super::time::interrupt_time() < patience
        {
            yield_now();
        }
    }
    STOP.store(true, Ordering::Release);
    if !settle(before) {
        return Err("the threads did not finish");
    }
    if WRONG.load(Ordering::Relaxed) != 0 {
        return Err("a register a call preserves changed when a thread moved");
    }
    let moves = SPINS[0].load(Ordering::Relaxed);
    // With this thread busy on its own processor, the runner needs a
    // third to escape to.
    if processors >= 3 && moves < CHASES {
        return Err("a waiting thread was not taken by an idle processor");
    }
    Ok(moves)
}

/// A thread runs only where its affinity allows, however often it gives
/// up the processor and whoever is idle. Returns the checks made.
pub fn affinity_test() -> Result<u64, &'static str> {
    fn body(allowed: usize) {
        for _ in 0..2000 {
            if allowed & 1 << pcr::current_processor() == 0 {
                WRONG.fetch_add(1, Ordering::Relaxed);
            }
            SPINS[0].fetch_add(1, Ordering::Relaxed);
            yield_now();
        }
    }
    let before = count();
    let processors = super::smp::online_count();
    WRONG.store(0, Ordering::Relaxed);
    SPINS[0].store(0, Ordering::Relaxed);
    // Two threads per processor, each allowed only there, and two
    // allowed on the last pair only.
    let pair = 0b11u64 << processors.saturating_sub(2) & super::smp::online();
    for n in 0..processors {
        create(body, 1 << n, NORMAL_PRIORITY, 1 << n)?;
        create(body, 1 << n, NORMAL_PRIORITY, 1 << n)?;
    }
    create(body, pair as usize, NORMAL_PRIORITY, pair)?;
    create(body, pair as usize, NORMAL_PRIORITY, pair)?;
    if create(body, 0, NORMAL_PRIORITY, 1 << 63).is_ok() {
        return Err("a thread was created for a processor that does not exist");
    }
    if !settle(before) {
        return Err("the threads did not finish");
    }
    if WRONG.load(Ordering::Relaxed) != 0 {
        return Err("a thread ran on a processor outside its affinity");
    }
    Ok(SPINS[0].load(Ordering::Relaxed))
}

/// A thread is itself, on the processor it is on, wherever it runs and
/// however it got there. Some threads never give up the processor, so
/// that they are moved only by being interrupted, pushed aside and taken
/// by another processor; others sleep and wake to keep processors
/// coming free. Each keeps asking who it is, what the IRQL is, and
/// whether the processor it reaches through the per-processor register
/// is the one it is running on. Returns the checks made.
pub fn identity_test() -> Result<u64, &'static str> {
    fn check(me: *mut Thread) {
        if current() != me || irql::current() != irql::PASSIVE_LEVEL {
            WRONG.fetch_add(1, Ordering::Relaxed);
        }
        // At DISPATCH_LEVEL the thread cannot move: what the
        // per-processor register leads to must be this processor's.
        let old = irql::raise(irql::DISPATCH_LEVEL);
        let here = arch::hardware_processor();
        if old != irql::PASSIVE_LEVEL
            || platform_number(here) != Some(pcr::current_processor())
            || arch::percpu_of(pcr::current_processor() as usize)
                .is_none_or(|p| !core::ptr::eq(p, arch::percpu()))
        {
            WRONG.fetch_add(1, Ordering::Relaxed);
        }
        irql::lower(old);
    }
    /// The processor number firmware's list gives hardware id `id`.
    fn platform_number(id: u64) -> Option<u32> {
        crate::hal::platform::get()
            .cpus()
            .iter()
            .position(|cpu| cpu.hw_id == id)
            .map(|n| n as u32)
    }
    fn spinner(_: usize) {
        let me = current();
        let mut checks = 0u64;
        let until = super::time::interrupt_time() + 6_000_000;
        while super::time::interrupt_time() < until {
            for _ in 0..500 {
                check(me);
                checks += 1;
            }
        }
        SPINS[0].fetch_add(checks, Ordering::Relaxed);
    }
    fn sleeper(_: usize) {
        let me = current();
        let until = super::time::interrupt_time() + 6_000_000;
        while super::time::interrupt_time() < until {
            // SAFETY: no object is involved.
            unsafe { super::wait::wait(None, Some(-10_000)) };
            for _ in 0..2000 {
                check(me);
            }
        }
    }
    let before = count();
    let processors = super::smp::online_count();
    WRONG.store(0, Ordering::Relaxed);
    SPINS[0].store(0, Ordering::Relaxed);
    for _ in 0..processors + 1 {
        create(spinner, 0, NORMAL_PRIORITY, ANYWHERE)?;
        create(sleeper, 0, NORMAL_PRIORITY, ANYWHERE)?;
    }
    let deadline = super::time::interrupt_time() + 300_000_000;
    while count() != before {
        if super::time::interrupt_time() > deadline {
            return Err("the threads did not finish");
        }
        // SAFETY: no object is involved.
        unsafe { super::wait::wait(None, Some(-100_000)) };
    }
    if WRONG.load(Ordering::Relaxed) != 0 {
        return Err("a thread saw another's identity, a wrong IRQL, or another processor's state");
    }
    Ok(SPINS[0].load(Ordering::Relaxed))
}
