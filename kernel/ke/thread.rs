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
//!   its stack is freed, the reference it held on itself while it ran
//!   is dropped, and it is signalled (a thread is an object others can
//!   wait on), in that order as far as anyone can see: whoever learns
//!   that a thread has ended finds it buried. The block itself lives
//!   until the last reference goes.

use super::{Rank, SpinLock, irql, pcr};
use crate::arch;
use crate::mm::{self, stack::Stack};
use crate::ob;
use core::sync::atomic::{
    AtomicBool, AtomicPtr, AtomicU8, AtomicU32, AtomicU64, AtomicUsize, Ordering,
};
use nk_ke::sched::{self, Leaving};
use nk_ke::{ListEntry, QUANTUM_TICKS, ReadyQueues, WaitRegister};
use nk_ntabi::interrupt::GROUP_AFFINITY;
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
    /// Counted in [`count`]: every thread but the idle threads and the
    /// executive's worker threads.
    counted: bool,
    /// Clock ticks left before threads of this priority get a turn.
    quantum: AtomicU8,
    /// Where the thread stands with respect to waiting.
    wait: WaitRegister,
    /// The next thread in a waker's list of threads to make ready.
    wake_link: *mut Thread,
    /// The processor whose ready queue the thread is on, plus one; zero
    /// while it is on none. Written under that queue's lock.
    queued_on: AtomicU32,
    /// The priority it is queued at. That queue's lock.
    queued_at: AtomicU8,
    /// Guards the thread's APC queues (`ke::apc`).
    apc: SpinLock<()>,
    /// Stack segments the thread has been given to expand its stack
    /// (`ke::expand`): the first `segments_in_use` of them it is running
    /// on, outermost first, and where the stack pointer was when each
    /// was switched to. Only the thread itself changes these, and
    /// whoever buries it.
    segments: [Stack; MAX_SEGMENTS],
    entered_from: [u64; MAX_SEGMENTS],
    segments_in_use: u8,
    /// Segments an unwind left while it may still run on them, freed
    /// once no frame can be left there (`reap_stranded`).
    stranded: [Stack; MAX_STRANDED],
    stranded_count: u8,
}

/// The most segments unwinds can have left with frames still on them:
/// each such segment holds the stack pointer, or the place a segment in
/// use was switched to from.
const MAX_STRANDED: usize = MAX_SEGMENTS + 1;

/// The most stack segments a thread runs on at once, beyond its own
/// stack.
pub const MAX_SEGMENTS: usize = 6;

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

/// Threads that exist, idle threads and the executive's worker threads
/// not counted.
static THREADS: AtomicU32 = AtomicU32::new(0);
/// Live uncounted worker thread objects (for leak-check accounting).
static UNCOUNTED_OBJECTS: AtomicUsize = AtomicUsize::new(0);
/// Live uncounted worker thread stacks (for leak-check accounting).
static UNCOUNTED_STACKS: AtomicUsize = AtomicUsize::new(0);
/// Transitions of uncounted worker threads currently in progress (allocating
/// or freeing stack/TCB) and monotonic transition epoch so `selftest::resources`
/// never takes a torn snapshot while a dynamic worker spawns or retires.
static UNCOUNTED_IN_FLIGHT: AtomicUsize = AtomicUsize::new(0);
static UNCOUNTED_GEN: AtomicU64 = AtomicU64::new(0);

/// `(epoch, in_flight)` for uncounted worker thread lifecycle transitions.
pub fn uncounted_state() -> (u64, usize) {
    let in_flight = UNCOUNTED_IN_FLIGHT.load(Ordering::SeqCst);
    let epoch = UNCOUNTED_GEN.load(Ordering::SeqCst);
    (epoch, in_flight)
}

/// Guards an uncounted worker thread's allocation or teardown so leak checks
/// retry instead of observing intermediate pool/frame states.
struct UncountedTransition(bool);

impl UncountedTransition {
    fn begin(uncounted: bool) -> Self {
        if uncounted {
            UNCOUNTED_IN_FLIGHT.fetch_add(1, Ordering::SeqCst);
            UNCOUNTED_GEN.fetch_add(1, Ordering::SeqCst);
        }
        Self(uncounted)
    }
}

impl Drop for UncountedTransition {
    fn drop(&mut self) {
        if self.0 {
            UNCOUNTED_GEN.fetch_add(1, Ordering::SeqCst);
            UNCOUNTED_IN_FLIGHT.fetch_sub(1, Ordering::SeqCst);
        }
    }
}

/// The threads that exist, but for the idle threads and the executive's
/// worker threads, which come and go as work waits for them
/// ([`create_uncounted`]): a test waits for this to fall back to what it
/// was, once the threads it made have ended.
pub fn count() -> u32 {
    THREADS.load(Ordering::Acquire)
}

/// Pool blocks, pool bytes and stack frames currently held by live
/// uncounted worker threads (`create_uncounted`), so leak checks around
/// test groups do not mistake dynamic worker scaling for a leak.
pub fn uncounted_storage() -> (usize, usize, u64) {
    let blocks = UNCOUNTED_OBJECTS.load(Ordering::Acquire);
    let block_bytes =
        (nk_ntabi::ob::OBJECT_BODY + size_of::<Thread>()).next_multiple_of(align_of::<u16>());
    let stacks = UNCOUNTED_STACKS.load(Ordering::Acquire);
    (
        blocks,
        blocks * block_bytes,
        (stacks * mm::stack::STACK_PAGES) as u64,
    )
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

/// The thread's priority, where Windows keeps it. Another thread may
/// change it at any moment (`set_priority`), so it is only ever read
/// and written whole.
///
/// # Safety
/// `thread` is a live thread.
unsafe fn priority_of<'a>(thread: *mut Thread) -> &'a AtomicU8 {
    // SAFETY: per the contract: a byte of the thread's block.
    unsafe { AtomicU8::from_ptr(field(thread, layout::PRIORITY)) }
}

/// # Safety
/// `thread` is a live thread.
unsafe fn priority(thread: *mut Thread) -> u8 {
    // SAFETY: per the contract.
    unsafe { priority_of(thread) }.load(Ordering::SeqCst)
}

/// The processor whose ready queue the thread uses, where Windows
/// keeps it.
///
/// # Safety
/// `thread` is a live thread.
unsafe fn next_processor<'a>(thread: *mut Thread) -> &'a AtomicU32 {
    // SAFETY: per the contract: an aligned field of the thread's block.
    unsafe { AtomicU32::from_ptr(field(thread, layout::NEXT_PROCESSOR)) }
}

/// Put `thread` on `ready`, the queues of processor `processor`, at
/// its priority, which is returned.
///
/// Where it is queued is published before its priority is read, and
/// whoever changes a thread's priority writes it before looking where
/// the thread is queued (`apply_priority`): one of the two sees the
/// other, so a thread is never left queued at a priority it no longer
/// has. A change that finds the thread on no queue leaves the rest to
/// whoever queues it: the caller has that processor look at its queues
/// afterwards, or has decided what runs there on the priority returned.
///
/// # Safety
/// `ready` is that processor's, locked; `thread` is live and on no
/// queue.
unsafe fn enqueue(
    ready: &mut ReadyQueues,
    processor: usize,
    thread: *mut Thread,
    front: bool,
) -> u8 {
    // SAFETY: per the contract.
    unsafe {
        (*thread)
            .queued_on
            .store(processor as u32 + 1, Ordering::SeqCst);
        let level = priority(thread);
        (*thread).queued_at.store(level, Ordering::Relaxed);
        ready.insert(link_of(thread), level, front);
        level
    }
}

/// Take the best thread off `ready` whose priority is at least `floor`.
///
/// # Safety
/// `ready` is locked; every queued thread is live.
unsafe fn dequeue(ready: &mut ReadyQueues, floor: u8) -> Option<*mut Thread> {
    // SAFETY: per the contract.
    unsafe {
        let (link, _) = ready.take(floor)?;
        let thread = thread_of(link);
        (*thread).queued_on.store(0, Ordering::SeqCst);
        Some(thread)
    }
}

/// # Safety
/// `thread` is a live thread that the caller may change the state of.
unsafe fn set_state(thread: *mut Thread, state: u8) {
    // SAFETY: per the contract; other processors read `STATE` atomically
    // (`ke::apc`), and `Release` publishes `next_processor` before
    // `RUNNING` is visible.
    unsafe {
        AtomicU8::from_ptr(field(thread, layout::STATE)).store(state, Ordering::Release);
        AtomicU8::from_ptr(field(thread, layout::RUNNING))
            .store(u8::from(state == layout::state::RUNNING), Ordering::Relaxed);
    }
}

/// The thread running on this processor.
pub fn current() -> *mut Thread {
    pcr::current_thread().cast()
}

/// The current thread's `KTHREAD.PreviousMode` (`0` = `KernelMode`,
/// `1` = `UserMode`). Returns `KERNEL_MODE` during early boot before
/// the idle thread is installed.
pub fn previous_mode() -> i8 {
    let me = current();
    if me.is_null() {
        return nk_ntabi::io::KERNEL_MODE;
    }
    // SAFETY: `me` is the running thread; only this thread reads or
    // modifies its own `PreviousMode`.
    unsafe { field::<i8>(me, layout::PREVIOUS_MODE).read() }
}

/// Set the current thread's `KTHREAD.PreviousMode`, returning its
/// previous value.
pub fn set_previous_mode(mode: i8) -> i8 {
    let me = current();
    if me.is_null() {
        return nk_ntabi::io::KERNEL_MODE;
    }
    // SAFETY: `me` is the running thread; only this thread writes its
    // own `PreviousMode`.
    unsafe {
        let slot = field::<i8>(me, layout::PREVIOUS_MODE);
        let old = slot.read();
        slot.write(mode);
        old
    }
}

/// RAII guard that switches `KTHREAD.PreviousMode` for the current
/// scope and restores the prior value on drop.
pub struct PreviousModeGuard {
    old: i8,
}

impl PreviousModeGuard {
    /// Switch `PreviousMode` to `KERNEL_MODE` (used by `Zw*` thunks).
    pub fn kernel() -> Self {
        Self {
            old: set_previous_mode(nk_ntabi::io::KERNEL_MODE),
        }
    }

    /// Switch `PreviousMode` to `mode`.
    #[allow(dead_code)]
    pub fn enter(mode: i8) -> Self {
        Self {
            old: set_previous_mode(mode),
        }
    }
}

impl Drop for PreviousModeGuard {
    fn drop(&mut self) {
        set_previous_mode(self.old);
    }
}

/// [`ExGetPreviousMode`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-exgetpreviousmode):
/// the current thread's `KTHREAD.PreviousMode`.
#[allow(non_snake_case)]
pub extern "C" fn ExGetPreviousMode() -> i8 {
    previous_mode()
}

/// The stack the running thread is running on: its own, or the last
/// segment it was given (`ke::expand`).
pub fn current_stack() -> Stack {
    // SAFETY: the running thread, which alone changes its segments.
    unsafe { active_stack(current()) }
}

/// The stack `thread` runs on, or will when it next runs.
///
/// # Safety
/// `thread` is live, and is the running thread or not running.
unsafe fn active_stack(thread: *mut Thread) -> Stack {
    // SAFETY: per the contract.
    unsafe {
        match (*thread).segments_in_use {
            0 => (*thread).stack,
            n => (*thread).segments[usize::from(n) - 1],
        }
    }
}

/// Every stack the running thread may have frames on: its own first,
/// then the segments it runs on, outermost first, then those an unwind
/// left (`pop_segment`): an unwind out of a segment goes on walking,
/// and running, there after the thread has left it.
pub fn current_stacks() -> impl Iterator<Item = Stack> {
    let me = current();
    // SAFETY: the running thread, which alone changes its segments.
    let (own, segments, in_use, stranded, left) = unsafe {
        (
            (*me).stack,
            (*me).segments,
            usize::from((*me).segments_in_use),
            (*me).stranded,
            usize::from((*me).stranded_count),
        )
    };
    core::iter::once(own)
        .chain(segments.into_iter().take(in_use))
        .chain(stranded.into_iter().take(left))
}

/// The stack pointer, near enough: the address of a local of the caller.
#[inline(always)]
fn stack_pointer() -> u64 {
    let here = 0u8;
    core::hint::black_box(&raw const here).addr() as u64
}

/// Run the running thread on `fresh`, a stack from `mm::stack`, as one
/// more segment from now on, and say so where drivers and the overflow
/// check look. Gives `fresh` back if the thread runs on as many as it
/// may. The counts are read and changed at `DISPATCH_LEVEL`, so an APC
/// that expands the stack in between finds them whole.
pub fn push_segment(fresh: Stack) -> Result<(), Stack> {
    let me = current();
    let sp = stack_pointer();
    // SAFETY: the running thread, which alone changes its segments; at
    // DISPATCH_LEVEL nothing else runs on it meanwhile.
    let (pushed, dead) = unsafe {
        let old = irql::raise(irql::DISPATCH_LEVEL);
        let dead = reap_stranded(me, sp);
        let in_use = usize::from((*me).segments_in_use);
        let pushed = in_use < MAX_SEGMENTS;
        if pushed {
            (*me).segments[in_use] = fresh;
            (*me).entered_from[in_use] = sp;
            (*me).segments_in_use += 1;
            publish_stack(me, fresh);
        }
        irql::lower(old);
        (pushed, dead)
    };
    dead.free();
    if pushed { Ok(()) } else { Err(fresh) }
}

/// The running thread is back on the stack it ran on before its last
/// segment. Unless `unwinding`, it is running there already and the
/// segment is freed. An unwind out of a segment still runs on it: the
/// segment is kept, walkable, until no frame can be left on it
/// (`reap_stranded`).
pub fn pop_segment(unwinding: bool) {
    let me = current();
    let sp = stack_pointer();
    // SAFETY: the running thread, which alone changes its segments; at
    // DISPATCH_LEVEL nothing else runs on it meanwhile.
    let (segment, dead) = unsafe {
        let old = irql::raise(irql::DISPATCH_LEVEL);
        (*me).segments_in_use -= 1;
        let segment = (*me).segments[usize::from((*me).segments_in_use)];
        publish_stack(me, active_stack(me));
        let dead = reap_stranded(me, sp);
        if unwinding {
            // Room by the bound on segments with live frames
            // (`MAX_STRANDED`), once the dead ones are gone.
            let left = usize::from((*me).stranded_count);
            (*me).stranded[left] = segment;
            (*me).stranded_count += 1;
        }
        irql::lower(old);
        (segment, dead)
    };
    dead.free();
    if !unwinding {
        mm::stack::free(segment);
    }
}

/// Segments taken off a thread, to free once the IRQL is down.
struct Dead {
    stacks: [Stack; MAX_STRANDED],
    count: usize,
}

impl Dead {
    fn free(self) {
        for &segment in &self.stacks[..self.count] {
            mm::stack::free(segment);
        }
    }
}

/// Take off `me`'s stranded segments those no frame can be on: neither
/// the stack pointer `sp` nor the place any segment in use was switched
/// to from is on them.
///
/// # Safety
/// `me` is the running thread, at `DISPATCH_LEVEL`.
unsafe fn reap_stranded(me: *mut Thread, sp: u64) -> Dead {
    let mut dead = Dead {
        stacks: [Stack { base: 0, top: 0 }; MAX_STRANDED],
        count: 0,
    };
    // SAFETY: per the contract.
    unsafe {
        let in_use = usize::from((*me).segments_in_use);
        let entered = (*me).entered_from;
        let live = |stack: &Stack| {
            core::iter::once(sp)
                .chain(entered[..in_use].iter().copied())
                .any(|at| (stack.base..stack.top).contains(&at))
        };
        let mut kept = 0;
        for index in 0..usize::from((*me).stranded_count) {
            let stack = (*me).stranded[index];
            if live(&stack) {
                (*me).stranded[kept] = stack;
                kept += 1;
            } else {
                dead.stacks[dead.count] = stack;
                dead.count += 1;
            }
        }
        (*me).stranded_count = kept as u8;
    }
    dead
}

/// How many segments the running thread runs on.
pub fn segments_in_use() -> usize {
    // SAFETY: the running thread.
    usize::from(unsafe { (*current()).segments_in_use })
}

/// Say that the running thread `me` now runs on `stack`: in its
/// `KTHREAD`, as Windows reports a segment, and to this processor's
/// overflow check.
///
/// # Safety
/// `me` is the running thread, at `DISPATCH_LEVEL`.
unsafe fn publish_stack(me: *mut Thread, stack: Stack) {
    // SAFETY: per the contract.
    unsafe {
        field::<u64>(me, layout::INITIAL_STACK).write(stack.top);
        field::<u64>(me, layout::STACK_BASE).write(stack.top);
        field::<u64>(me, layout::STACK_LIMIT).write(stack.base);
    }
    arch::set_kernel_stack(stack.base);
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
        (&raw mut (*thread).counted).write(false);
        (&raw mut (*thread).quantum).write(AtomicU8::new(QUANTUM_TICKS));
        (&raw mut (*thread).wait).write(WaitRegister::new());
        (&raw mut (*thread).wake_link).write(core::ptr::null_mut());
        (&raw mut (*thread).queued_on).write(AtomicU32::new(0));
        (&raw mut (*thread).queued_at).write(AtomicU8::new(0));
        (&raw mut (*thread).apc).write(SpinLock::new(Rank::Apc, ()));
        (&raw mut (*thread).segments).write([Stack { base: 0, top: 0 }; MAX_SEGMENTS]);
        (&raw mut (*thread).segments_in_use).write(0);
        (&raw mut (*thread).entered_from).write([0; MAX_SEGMENTS]);
        (&raw mut (*thread).stranded).write([Stack { base: 0, top: 0 }; MAX_STRANDED]);
        (&raw mut (*thread).stranded_count).write(0);
        // Every thread NK makes is a system thread.
        field::<u32>(thread, layout::MISC_FLAGS).write(layout::MISC_FLAG_SYSTEM_THREAD);
        super::apc::init_thread(thread);
        super::wait::init_thread(thread);
        super::mutex::init_thread(thread);
        field::<u8>(thread, 0).write(layout::THREAD_OBJECT);
        field::<u64>(thread, layout::INITIAL_STACK).write(stack.top);
        field::<u64>(thread, layout::STACK_BASE).write(stack.top);
        field::<u64>(thread, layout::STACK_LIMIT).write(stack.base);
        priority_of(thread).store(thread_priority, Ordering::Relaxed);
        field::<u8>(thread, layout::BASE_PRIORITY).write(thread_priority);
        next_processor(thread).store(pcr::current_processor(), Ordering::Relaxed);
        let process = crate::ps::process::system();
        field::<usize>(thread, layout::SILO).write(nk_ntabi::silo::THREAD_NOT_ATTACHED);
        field::<*mut u8>(thread, layout::PROCESS).write(process);
        field::<u32>(thread, nk_ntabi::thread::CROSS_THREAD_FLAGS)
            .write(crate::ps::process::thread_priorities(process));
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
    let thread = new_thread(entry, argument, thread_priority, affinity, true)?;
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
    let thread = new_thread(entry, argument, thread_priority, affinity, true)?;
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

/// A new thread that will run `entry(argument)`, whole, on no queue
/// and, if `counted`, counted: not yet ready.
fn new_thread(
    entry: Entry,
    argument: usize,
    thread_priority: u8,
    affinity: u64,
    counted: bool,
) -> Result<*mut Thread, &'static str> {
    let allowed = affinity & super::smp::online();
    if allowed == 0 {
        return Err("a thread's affinity names no running processor");
    }
    // The ideal processor: the next in turn among those allowed.
    let turn = NEXT_IDEAL.fetch_add(1, Ordering::Relaxed);
    let ideal = sched::ideal_processor(allowed, turn).unwrap_or(0);
    let _transition = UncountedTransition::begin(!counted);
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
        field::<u64>(thread, layout::USER_AFFINITY).write(allowed);
        field::<u32>(thread, layout::IDEAL_PROCESSOR).write(ideal as u32);
        field::<u32>(thread, layout::USER_IDEAL_PROCESSOR).write(ideal as u32);
        field::<u64>(thread, layout::KERNEL_STACK).write(arch::new_context(stack.top, start));
        (&raw mut (*thread).counted).write(counted);
    }
    if counted {
        THREADS.fetch_add(1, Ordering::AcqRel);
    } else {
        UNCOUNTED_OBJECTS.fetch_add(1, Ordering::AcqRel);
        UNCOUNTED_STACKS.fetch_add(1, Ordering::AcqRel);
    }
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

/// Create a thread as [`create`] does, one [`count`] does not count: an
/// executive worker thread, which the work queues make when work waits
/// and end when it has long been idle (`ex::work`).
pub fn create_uncounted(
    entry: Entry,
    argument: usize,
    thread_priority: u8,
    affinity: u64,
) -> Result<*mut Thread, &'static str> {
    let thread = create_uncounted_unstarted(entry, argument, thread_priority, affinity)?;
    // SAFETY: the thread is whole and on no queue.
    unsafe { make_ready(thread) };
    Ok(thread)
}

/// As [`create_uncounted`], but not yet made ready: the caller records
/// the thread in its pool state and then calls [`begin`], so the thread
/// cannot run before its pool counts it.
pub fn create_uncounted_unstarted(
    entry: Entry,
    argument: usize,
    thread_priority: u8,
    affinity: u64,
) -> Result<*mut Thread, &'static str> {
    new_thread(entry, argument, thread_priority, affinity, false)
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
/// the best there that its affinity allows here, which need not be the
/// best there is. Each thread is looked at where it is, under its
/// queue's lock, and only the one taken leaves its queue: whoever
/// changes a thread's priority meanwhile finds it there
/// (`apply_priority`).
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
            let allowed = ready.first_where(|link| {
                field::<u64>(thread_of(link), layout::AFFINITY).read() & 1 << me != 0
            });
            let Some((link, level)) = allowed else {
                continue;
            };
            ready.remove(link, level);
            let thread = thread_of(link);
            (*thread).queued_on.store(0, Ordering::SeqCst);
            next_processor(thread).store(me as u32, Ordering::Release);
            return Some(thread);
        }
    }
    None
}

/// The thread's wait register.
///
/// # Safety
/// `thread` is a live thread, and stays live for `'a`: one found
/// through a linked wait block or the current-thread slot.
pub unsafe fn wait_register<'a>(thread: *mut Thread) -> &'a WaitRegister {
    // SAFETY: per the contract; a thread's register lives as long as
    // the thread.
    unsafe { &(*thread).wait }
}

/// The lock of the thread's APC queues.
///
/// # Safety
/// As [`wait_register`].
pub unsafe fn apc_lock<'a>(thread: *mut Thread) -> &'a SpinLock<()> {
    // SAFETY: per the contract.
    unsafe { &(*thread).apc }
}

/// The processor a running thread runs on, or a ready one is queued for.
///
/// # Safety
/// `thread` is a live thread.
pub unsafe fn processor(thread: *mut Thread) -> usize {
    // SAFETY: per the contract.
    unsafe { next_processor(thread).load(Ordering::Acquire) as usize }
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
        next_processor(thread).store(processor as u32, Ordering::Release);
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
            enqueue(&mut ready, processor, thread, false);
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
    let here = pcr::current_processor() as usize;
    // A thread that changed its affinity (`set_affinity`) may be on a
    // processor it no longer allows: whatever brought it here, it moves.
    // SAFETY: `me` is the running thread, which alone writes its
    // affinity.
    let allows = unsafe { field::<u64>(me, layout::AFFINITY).read() } & 1 << here != 0;
    let leaving = leaving.or_move(idle_thread, allows);
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
        let taken = unsafe { dequeue(&mut ready, floor) };
        let busy = taken.is_some_and(|thread| {
            // SAFETY: as above.
            unsafe { (*thread).swap_busy.load(Ordering::Acquire) }
        });
        let next = match taken {
            // Still leaving its last stack on another processor: only
            // the idle thread may wait for it.
            Some(thread) if !idle_thread && busy => {
                // SAFETY: as above; back at the front.
                unsafe { enqueue(&mut ready, here, thread, true) };
                dispatcher.idle.load(Ordering::Acquire)
            }
            Some(thread) => thread,
            None if leaving.vacates() => dispatcher.idle.load(Ordering::Acquire),
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
                        // SAFETY: `me` runs here and the other thread is ready to run here.
                        return unsafe { switch_to(me, thread) };
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
                // Queued once this processor's queue is let go.
                Leaving::Move => {}
                _ if idle_thread => set_state(me, layout::state::READY),
                _ => {
                    set_state(me, layout::state::READY);
                    let front = leaving.requeue_in_front(spent);
                    // The thread taken was chosen against the priority
                    // this one came in with. If another processor has
                    // raised it since, it found this thread on no queue
                    // and left the rest to this processor: look again
                    // once the switch is made.
                    if enqueue(&mut ready, here, me, front) > my_priority {
                        reconsider(here);
                    }
                }
            }
        }
        next
    };
    if leaving == Leaving::Move {
        // SAFETY: `me` is on no queue and about to stop: `swap_busy` is
        // set, so the processor that takes it waits for the switch.
        unsafe { make_ready(me) };
    } else if !leaving.stops() && !idle_thread {
        // This thread is waiting now; a processor with nothing to do
        // may take it.
        // SAFETY: `me` is still on this processor, and alone writes its
        // affinity.
        wake_an_idle(unsafe { field::<u64>(me, layout::AFFINITY).read() });
    }
    // SAFETY: `me` runs here and the other thread is ready to run here.
    unsafe { switch_to(me, next) };
}

/// Leave `me`, already marked and queued as its leaving requires, for
/// `next`, which this processor took off a queue or is its idle thread.
///
/// # Safety
/// `me` is the running thread and `next` a live thread ready to run
/// here.
unsafe fn switch_to(me: *mut Thread, next: *mut Thread) {
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
        arch::set_kernel_stack(active_stack(next).base);
        let old_proc = field::<*mut u8>(me, layout::APC_STATE_PROCESS).read();
        let new_proc = field::<*mut u8>(next, layout::APC_STATE_PROCESS).read();
        if old_proc != new_proc {
            let dtb = crate::ps::process::directory_table_base(new_proc);
            arch::switch_address_space(dtb);
        }
        dispatcher.previous.store(me, Ordering::Release);
        dispatcher.switches.fetch_add(1, Ordering::Relaxed);
        arch::context_switch(
            field(me, layout::KERNEL_STACK),
            field::<u64>(next, layout::KERNEL_STACK).read(),
        );
    }
    // Running again, on whatever processor took this thread.
    after_switch();
    super::apc::switched_in();
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
        if AtomicU8::from_ptr(field(previous, layout::STATE)).load(Ordering::Acquire)
            == layout::state::TERMINATED
        {
            let header = previous.cast::<DISPATCHER_HEADER>();
            // Its memory is about to be reused: nothing may still point
            // into it. A wait cancels its own timer, so this holds.
            assert!(
                !super::timer::pending(timer(previous)),
                "a thread exited with its wait timer pending"
            );
            super::mutex::check_none_held(previous);
            let counted = (*previous).counted;
            let _transition = UncountedTransition::begin(!counted);
            mm::stack::free((*previous).stack);
            if !counted {
                UNCOUNTED_STACKS.fetch_sub(1, Ordering::AcqRel);
            }
            let (segments, stranded) = ((*previous).segments, (*previous).stranded);
            let in_use = usize::from((*previous).segments_in_use);
            let left = usize::from((*previous).stranded_count);
            for &segment in segments[..in_use].iter().chain(&stranded[..left]) {
                mm::stack::free(segment);
            }
            // It has ended: whoever waits for it may go on. They are
            // to find it gone, so the reference it held on itself while
            // it could run is dropped and it is counted out before its
            // lock is let go, which is when its end can first be seen.
            // Others may then drop the last reference at any moment:
            // `deleted` waits for the lock, so the block outlives this
            // hold of it.
            let (woken, buried) = {
                let _lock = super::object::ObjectLock::take(header);
                super::object::signal(header).store(1, Ordering::Release);
                let woken = super::object::satisfy(header);
                let buried = ob::object::dereference_unless_last(previous.cast());
                if buried && counted {
                    THREADS.fetch_sub(1, Ordering::AcqRel);
                }
                (woken, buried)
            };
            woken.ready();
            if !buried {
                // Its own reference was the only one: nobody holds the
                // thread to see it end. Counted out once the memory is
                // back, for whoever waits for the count to fall.
                ob::object::dereference(previous.cast());
                if counted {
                    THREADS.fetch_sub(1, Ordering::AcqRel);
                }
            }
        } else {
            (*previous).swap_busy.store(false, Ordering::Release);
        }
    }
}

/// The object manager's call when the last reference to a thread has
/// gone. The processor that buried the thread may have dropped the
/// thread's own reference a moment ago and still hold the thread's
/// lock (`after_switch`): the block is not freed under it.
///
/// # Safety
/// `body` is a thread object nothing refers to any more.
pub unsafe extern "C" fn deleted(body: *mut core::ffi::c_void) {
    // SAFETY: per the contract: the block is live until this returns.
    unsafe {
        drop(super::object::ObjectLock::take(body.cast()));
        crate::se::impersonate::thread_deleted(body);
        let thread = body.cast::<Thread>();
        if !(*thread).counted && !(*thread).idle {
            UNCOUNTED_OBJECTS.fetch_sub(1, Ordering::AcqRel);
        }
    }
}

/// Where a new thread begins.
extern "C" fn start() -> ! {
    after_switch();
    super::apc::switched_in();
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

/// The calling thread's `MiscFlags`, which another thread may change
/// (an alert), so only ever as a whole.
///
/// # Safety
/// `me` is the running thread (live for `'a`, which ends before it
/// does).
unsafe fn misc_flags<'a>(me: *mut Thread) -> &'a AtomicU32 {
    // SAFETY: per the contract; an aligned field of the thread's block.
    unsafe { AtomicU32::from_ptr(field(me, layout::MISC_FLAGS)) }
}

/// The IRQL a thread changes its affinity at: `DISPATCH_LEVEL`, so that
/// it stays on one processor meanwhile. Returns the caller's.
fn hold_processor(what: &str) -> u8 {
    let old = irql::current();
    if old > irql::DISPATCH_LEVEL {
        crate::kd::bugcheck(format_args!(
            "0x0000000A IRQL_NOT_LESS_OR_EQUAL: {what} at IRQL {old}"
        ));
    }
    // SAFETY: the running thread exists.
    if unsafe { (*current()).idle } {
        crate::kd::bugcheck(format_args!("{what} on a processor's idle thread"));
    }
    arch::set_irql(irql::DISPATCH_LEVEL);
    old
}

/// Give the calling thread the affinity `affinity`, of running
/// processors and not empty, and `ideal` as its ideal processor, or one
/// its affinity allows if `None`; then go back to IRQL `old`. Called at
/// `DISPATCH_LEVEL`.
///
/// If the thread is on a processor the affinity does not allow, it
/// moves: before this returns if `old` is below `DISPATCH_LEVEL`,
/// otherwise as soon as its IRQL falls below that, as on Windows.
fn set_affinity(affinity: u64, ideal: Option<u32>, old: u8) {
    let me = current();
    // SAFETY: `me` is the running thread, which alone writes its
    // affinity and ideal processor; nothing reads them while it runs.
    unsafe {
        let ideal_field = field::<u32>(me, layout::IDEAL_PROCESSOR);
        let ideal = ideal
            .unwrap_or_else(|| sched::ideal_within(affinity, ideal_field.read() as usize) as u32);
        field::<u64>(me, layout::AFFINITY).write(affinity);
        ideal_field.write(ideal);
    }
    if affinity & 1 << pcr::current_processor() == 0 {
        if old < irql::DISPATCH_LEVEL {
            dispatch(Leaving::Yield);
        } else {
            // At the end of the DISPATCH-level interrupt, which arrives
            // when the IRQL allows.
            arch::percpu()
                .dispatcher()
                .switch_wanted
                .store(true, Ordering::Release);
            arch::self_interrupt(arch::DPC.0);
        }
    }
    arch::set_irql(old);
}

/// [`KeSetSystemAffinityThread`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-kesetsystemaffinitythread):
/// restrict the calling thread to the processors in group 0 named by `affinity`.
#[allow(non_snake_case)]
pub extern "C" fn KeSetSystemAffinityThread(affinity: usize) {
    let mut group_affinity = GROUP_AFFINITY {
        Mask: affinity,
        Group: 0,
        Reserved: [0; 3],
    };
    // SAFETY: local `GROUP_AFFINITY`, null `previous`.
    unsafe { KeSetSystemGroupAffinityThread(&raw mut group_affinity, core::ptr::null_mut()) };
}

/// [`KeRevertToUserAffinityThread`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-kereverttouseraffinitythread):
/// restore the calling thread's user affinity after `KeSetSystemAffinityThread`.
#[allow(non_snake_case)]
pub extern "C" fn KeRevertToUserAffinityThread() {
    let mut zero = GROUP_AFFINITY {
        Mask: 0,
        Group: 0,
        Reserved: [0; 3],
    };
    // SAFETY: local zeroed `GROUP_AFFINITY` tells `KeRevertToUserGroupAffinityThread`
    // to revert to the thread's original user affinity.
    unsafe { KeRevertToUserGroupAffinityThread(&raw mut zero) };
}

/// [`KeSetSystemGroupAffinityThread`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-kesetsystemgroupaffinitythread):
/// have the calling thread run on the processors of `affinity` only,
/// and say what system affinity it had before: none, a mask of zero,
/// if it was running with its own.
///
/// As the pinned kernel does it: the caller's mask is cut down to the
/// running processors; an affinity that names none, another group or
/// has a reserved field set changes no affinity, but the thread still
/// counts as in system affinity afterwards.
///
/// # Safety
/// `affinity` is readable and writable; `previous` is null or
/// writable.
#[allow(non_snake_case)]
pub unsafe extern "C" fn KeSetSystemGroupAffinityThread(
    affinity: *mut GROUP_AFFINITY,
    previous: *mut GROUP_AFFINITY,
) {
    // SAFETY: per the contract.
    let given = unsafe { affinity.read_unaligned() };
    let new = sched::system_affinity(
        given.Mask as u64,
        given.Group,
        given.Reserved,
        super::smp::online(),
    );
    if let Some(mask) = new {
        // SAFETY: per the contract.
        unsafe { (&raw mut (*affinity).Mask).write_unaligned(mask as usize) };
    }
    let old = hold_processor("KeSetSystemGroupAffinityThread");
    let me = current();
    // SAFETY: the running thread.
    let was_active = unsafe { misc_flags(me) }
        .fetch_or(layout::MISC_FLAG_SYSTEM_AFFINITY_ACTIVE, Ordering::AcqRel)
        & layout::MISC_FLAG_SYSTEM_AFFINITY_ACTIVE
        != 0;
    let before = GROUP_AFFINITY {
        Mask: if was_active {
            // SAFETY: the running thread's own field.
            unsafe { field::<u64>(me, layout::AFFINITY).read() as usize }
        } else {
            0
        },
        Group: 0,
        Reserved: [0; 3],
    };
    match new {
        Some(mask) => set_affinity(mask, None, old),
        None => arch::set_irql(old),
    }
    if !previous.is_null() {
        // SAFETY: per the contract.
        unsafe { previous.write_unaligned(before) };
    }
}

/// [`KeRevertToUserGroupAffinityThread`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-kereverttousergroupaffinitythread):
/// put the calling thread's affinity back to what
/// `KeSetSystemGroupAffinityThread` said it was before: its own, for a
/// mask of zero, or that system affinity (`sched::revert_affinity`).
///
/// # Safety
/// `previous` is readable and writable.
#[allow(non_snake_case)]
pub unsafe extern "C" fn KeRevertToUserGroupAffinityThread(previous: *mut GROUP_AFFINITY) {
    let me = current();
    let active =
        // SAFETY: the running thread.
        unsafe { misc_flags(me) }.load(Ordering::Acquire) & layout::MISC_FLAG_SYSTEM_AFFINITY_ACTIVE != 0;
    // SAFETY: per the contract.
    let given = unsafe { previous.read_unaligned() };
    let revert = sched::revert_affinity(
        active,
        given.Mask as u64,
        given.Group,
        given.Reserved,
        super::smp::online(),
    );
    match revert {
        sched::Revert::Nothing => {}
        sched::Revert::ToUser => {
            let old = hold_processor("KeRevertToUserGroupAffinityThread");
            // SAFETY: the running thread.
            unsafe { misc_flags(me) }
                .fetch_and(!layout::MISC_FLAG_SYSTEM_AFFINITY_ACTIVE, Ordering::AcqRel);
            // SAFETY: the running thread's own fields, written at its
            // creation.
            let (own, ideal) = unsafe {
                (
                    field::<u64>(me, layout::USER_AFFINITY).read(),
                    field::<u32>(me, layout::USER_IDEAL_PROCESSOR).read(),
                )
            };
            set_affinity(own, Some(ideal), old);
        }
        sched::Revert::To(mask) => {
            // SAFETY: per the contract: as Windows cuts the caller's
            // mask down to the running processors.
            unsafe { (&raw mut (*previous).Mask).write_unaligned(mask as usize) };
            let old = hold_processor("KeRevertToUserGroupAffinityThread");
            set_affinity(mask, None, old);
        }
    }
}

/// End the calling thread.
pub fn exit() -> ! {
    irql::expect_passive("thread exit");
    super::apc::rundown();
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

/// Wait, yielding, until only `threads` threads exist: how a test waits
/// for the threads it started to end. There is no time limit, and a test
/// does not return while a thread of its own can still run: the threads
/// use what the test would tear down. A thread that never ends is a
/// hang, which the boot harness reports with every processor's
/// registers; a limit here would only turn a slow host into a failure.
pub fn settle(threads: u32) {
    while count() != threads {
        yield_now();
        core::hint::spin_loop();
    }
}

/// [`settle`], for at most `ticks` of interrupt time (100 ns each): for
/// a test that has already failed, whose threads may never end. Says
/// whether the count came back.
pub fn settle_within(threads: u32, ticks: u64) -> bool {
    let until = super::time::interrupt_time() + ticks;
    while count() != threads {
        if super::time::interrupt_time() > until {
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
    settle(before);
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

/// A thread whose end has been seen is gone: whoever waited for it, or
/// asked and was told it had ended, finds it no longer counted, its
/// stack returned and its own reference dropped, so that its memory
/// goes with the caller's reference. Returns the threads seen off.
pub fn buried_test() -> Result<u32, &'static str> {
    fn body(_: usize) {}
    const ROUNDS: u32 = 600;
    let me = pcr::current_processor() as usize;
    let processors = super::smp::online_count();
    for round in 0..ROUNDS {
        // On another processor when there is one, so that its end and
        // this thread's look at it can happen at the same moment.
        let step = 1 + round as usize % processors.saturating_sub(1).max(1);
        let there = (me + step) % processors;
        let (threads, blocks, frames) = (count(), mm::pool::usage().blocks, mm::free_frame_count());
        let thread = create_referenced(body, 0, NORMAL_PRIORITY, 1 << there)?;
        // SAFETY: a thread this test holds a reference to, which it
        // gives up here.
        let (counted, freed) = unsafe {
            let counted = match round % 3 {
                // Asleep until it ends.
                0 => {
                    super::wait::wait(Some(thread.cast()), None);
                    count()
                }
                // Asking again and again, to catch it just ended.
                1 => {
                    while super::wait::wait(Some(thread.cast()), Some(0)) != 0 {
                        if there == me {
                            yield_now();
                        }
                        core::hint::spin_loop();
                    }
                    count()
                }
                // Looking under its lock, where its end first shows:
                // the closest anyone can come to the moment itself.
                _ => loop {
                    let seen = {
                        let _lock = super::object::ObjectLock::take(thread.cast());
                        let ended = super::object::signal(thread.cast()).load(Ordering::Acquire);
                        (ended > 0).then(count)
                    };
                    if let Some(counted) = seen {
                        break counted;
                    }
                    if there == me {
                        yield_now();
                    }
                    core::hint::spin_loop();
                },
            };
            let stack_back = mm::free_frame_count() >= frames;
            ob::object::dereference(thread.cast());
            (counted, stack_back && mm::pool::usage().blocks == blocks)
        };
        if counted != threads {
            return Err("a thread whose end was seen was still counted");
        }
        if !freed {
            return Err("a thread whose end was seen still held its stack or a reference");
        }
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
    settle(before);
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
    settle(before);
    if after_yield != 0x32 {
        return Err("a yield did not run the higher then the equal thread, and only those");
    }
    if !moved || TRACE.load(Ordering::Acquire) != 0x321 {
        return Err("the lower-priority thread did not run last");
    }
    Ok(())
}

/// Have processor `number` reconsider what it runs, at the end of an
/// interrupt: its own DISPATCH-level one here, the interprocessor one
/// there. Called at `DISPATCH_LEVEL`.
fn reconsider(number: usize) {
    let Some(there) = arch::percpu_of(number) else {
        return;
    };
    there
        .dispatcher()
        .switch_wanted
        .store(true, Ordering::Release);
    if number == pcr::current_processor() as usize {
        arch::self_interrupt(arch::DPC.0);
    } else {
        arch::ipi_send(number);
    }
}

/// Give `thread` the priority `new` in place of `old`, wherever the
/// thread is: running here or on another processor, on a ready queue,
/// waiting, or on its way between those.
///
/// The priority is written first and the queue looked for second; a
/// processor queueing the thread does the two in the other order
/// (`enqueue`). A thread found queued is moved to the back of its new
/// priority's queue under that queue's lock, and its processor looks
/// again. A thread found on no queue is running, waiting or about to
/// be queued, and whoever queues it next reads the new priority; if it
/// was lowered, the processor it runs on is asked to look for a better
/// thread. That processor is read without a lock and may be out of
/// date for a thread that is just then moving: the thread then gives
/// way at its next clock tick instead of at once.
///
/// # Safety
/// `thread` is a live thread whose lock (its header's) the caller
/// holds, at `DISPATCH_LEVEL`.
unsafe fn apply_priority(thread: *mut Thread, old: u8, new: u8) {
    // SAFETY: per the contract throughout.
    unsafe {
        priority_of(thread).store(new, Ordering::SeqCst);
        (*thread).quantum.store(QUANTUM_TICKS, Ordering::Relaxed);
        let on = (*thread).queued_on.load(Ordering::SeqCst);
        if on != 0 {
            let there = on as usize - 1;
            if let Some(dispatcher) = arch::percpu_of(there).map(|p| p.dispatcher()) {
                let mut ready = dispatcher.ready.lock();
                // Unless that processor took it off meanwhile.
                if (*thread).queued_on.load(Ordering::SeqCst) == on {
                    let level = (*thread).queued_at.load(Ordering::Relaxed);
                    if level != new {
                        ready.remove(link_of(thread), level);
                        (*thread).queued_at.store(new, Ordering::Relaxed);
                        ready.insert(link_of(thread), new, false);
                    }
                }
            }
            reconsider(there);
        } else if new < old {
            if thread == current() {
                reconsider(pcr::current_processor() as usize);
            } else {
                reconsider(next_processor(thread).load(Ordering::Relaxed) as usize);
            }
        }
    }
}

/// Give `thread` the priority `new`, as `KeSetPriorityThread` does;
/// returns the one it had. Changes of one thread's priority are made
/// one at a time, under the thread's own lock.
///
/// # Safety
/// `thread` is a live thread; `new` is below 32.
pub unsafe fn set_priority(thread: *mut Thread, new: u8) -> u8 {
    // SAFETY: per the contract; the lock is held to the end, at
    // `DISPATCH_LEVEL`.
    unsafe {
        let _lock = super::object::ObjectLock::take(thread.cast());
        let old = priority(thread);
        let base = field::<u8>(thread, layout::BASE_PRIORITY).read();
        if let Some(new) = sched::priority_to_set(base, new) {
            apply_priority(thread, old, new);
        }
        old
    }
}

/// Set `thread`'s base priority `increment` away from its process's,
/// as Windows' `KeSetBasePriorityThread` does, and move its priority
/// with it (`nk_ps::info::set_base_priority`); returns the step the
/// thread was at. Under the thread's own lock, like any change of its
/// priority.
///
/// # Safety
/// `thread` is a live thread of a process that is not real-time.
pub unsafe fn set_base_priority(thread: *mut Thread, increment: i32) -> i32 {
    // SAFETY: per the contract; the lock is held to the end, at
    // `DISPATCH_LEVEL`. A thread's process outlives it.
    unsafe {
        let _lock = super::object::ObjectLock::take(thread.cast());
        let process = field::<*mut u8>(thread, layout::PROCESS).read();
        let old = priority(thread);
        let change = nk_ps::info::set_base_priority(
            process.add(nk_ntabi::process::BASE_PRIORITY).read(),
            field::<u8>(thread, layout::BASE_PRIORITY).read(),
            old,
            field::<i8>(thread, layout::SATURATION).read(),
            increment,
        );
        field::<u8>(thread, layout::BASE_PRIORITY).write(change.base);
        field::<i8>(thread, layout::SATURATION).write(change.saturation);
        if change.priority != old {
            apply_priority(thread, old, change.priority);
        }
        change.was
    }
}

/// [`KeSetPriorityThread`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-kesetprioritythread):
/// give a thread another priority; returns the old one. A thread that
/// is lowered below a ready thread gives way, and one raised above a
/// running thread takes its processor. The thread's base priority is
/// not changed. What is asked for is adjusted as Windows adjusts it
/// (`nk_ke::sched::priority_to_set`).
///
/// # Safety
/// `thread` is a thread object.
#[allow(non_snake_case)]
pub unsafe extern "C" fn KeSetPriorityThread(thread: *mut core::ffi::c_void, new: i32) -> i32 {
    if !(0..32).contains(&new) {
        crate::kd::bugcheck(format_args!("KeSetPriorityThread: {new} is not a priority"));
    }
    // SAFETY: per the contract.
    i32::from(unsafe { set_priority(thread.cast(), new as u8) })
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
    settle(before);
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
        let here = pcr::current_processor() as usize;
        let Some(thread) = dequeue(&mut ready, from) else {
            return false;
        };
        if priority(thread) == from {
            priority_of(thread).store(to, Ordering::SeqCst);
        }
        let moved = priority(thread) == to;
        enqueue(&mut ready, here, thread, !moved);
        moved
    }
}

static OTHER: crate::test::Slot<nk_ntabi::ke::KEVENT> = crate::test::Slot::new();

/// Another thread's priority is changed wherever that thread is: while
/// it waits, while it is ready, while it runs on another processor, and
/// while it moves between all three. Returns the changes made.
pub fn set_other_priority_test() -> Result<u32, &'static str> {
    use super::wait;
    fn waits(tag: usize) {
        // SAFETY: a static, initialised event.
        unsafe { wait::wait(Some(OTHER.ptr().cast()), None) };
        note(tag as u64);
    }
    fn notes(tag: usize) {
        note(tag as u64);
    }
    fn spins(_: usize) {
        while !STOP.load(Ordering::Acquire) {
            core::hint::spin_loop();
        }
    }
    fn churns(_: usize) {
        // Ready, running and waiting by turns, on every processor.
        while !STOP.load(Ordering::Acquire) {
            yield_now();
            // SAFETY: no object is involved.
            unsafe { wait::wait(None, Some(-1_000)) };
            RAN.fetch_add(1, Ordering::Relaxed);
        }
    }
    let set = |thread: *mut Thread, new: u8| {
        // SAFETY: a thread this test holds a reference to.
        unsafe { KeSetPriorityThread(thread.cast(), i32::from(new)) }
    };
    let before = count();
    let me = pcr::current_processor() as usize;
    let mut changes = 0;
    TRACE.store(0, Ordering::Relaxed);
    // SAFETY: static storage nothing waits on.
    unsafe { wait::KeInitializeEvent(OTHER.ptr(), 0, 0) };

    // Waiting: the new priority is the one it wakes with, here above
    // this thread's, so it runs before the setting of the event
    // returns.
    let waiting = create_referenced(waits, 1, NORMAL_PRIORITY, 1 << me)?;
    // SAFETY: no object is involved.
    unsafe { wait::wait(None, Some(-100_000)) };
    let was = set(waiting, NORMAL_PRIORITY + 4);
    let not_yet = TRACE.load(Ordering::Acquire);
    // SAFETY: a static, initialised event.
    unsafe { wait::KeSetEvent(OTHER.ptr(), 0, 0) };
    let woke = TRACE.load(Ordering::Acquire);
    changes += 1;

    // Ready, below this thread: raised above it, it runs at once.
    let ready = create_referenced(notes, 2, NORMAL_PRIORITY - 1, 1 << me)?;
    let idle = TRACE.load(Ordering::Acquire);
    let was_ready = set(ready, NORMAL_PRIORITY + 1);
    let ran = TRACE.load(Ordering::Acquire);
    changes += 1;

    // Ready, raised and lowered again without ever outranking this
    // thread: it stays queued, at the priority it was left with.
    let parked = create_referenced(notes, 3, NORMAL_PRIORITY - 2, 1 << me)?;
    let steps = [
        set(parked, NORMAL_PRIORITY - 1),
        set(parked, NORMAL_PRIORITY - 3),
        set(parked, 0),
        set(parked, NORMAL_PRIORITY - 1),
    ];
    let parked_ran = TRACE.load(Ordering::Acquire);
    changes += 4;

    // Running on another processor with a lesser thread ready behind
    // it: lowered below that one, it gives way there.
    let processors = super::smp::online_count();
    let mut gave_way = true;
    STOP.store(false, Ordering::Release);
    if processors > 1 {
        let there = (me + 1) % processors;
        let spinner = create_referenced(spins, 0, NORMAL_PRIORITY + 2, 1 << there)?;
        // SAFETY: no object is involved.
        unsafe { wait::wait(None, Some(-100_000)) };
        let behind = create_referenced(notes, 4, NORMAL_PRIORITY + 1, 1 << there)?;
        // SAFETY: no object is involved.
        unsafe { wait::wait(None, Some(-200_000)) };
        let starved = TRACE.load(Ordering::Acquire) & 0xF != 4;
        let was_running = set(spinner, NORMAL_PRIORITY);
        // SAFETY: a thread this test holds a reference to.
        let ended = unsafe { wait::wait(Some(behind.cast()), Some(-20_000_000)) };
        gave_way = starved && was_running == i32::from(NORMAL_PRIORITY + 2) && ended == 0;
        STOP.store(true, Ordering::Release);
        // SAFETY: threads this test holds references to, which it gives
        // up here.
        unsafe {
            wait::wait(Some(spinner.cast()), None);
            ob::object::dereference(spinner.cast());
            ob::object::dereference(behind.cast());
        }
        changes += 1;
    }

    // Moving: threads that are ready, running and waiting by turns on
    // every processor, each set to one priority after another all the
    // while. They must all still be there to be stopped, at the
    // priority last set.
    STOP.store(false, Ordering::Release);
    RAN.store(0, Ordering::Relaxed);
    let mut movers = [core::ptr::null_mut::<Thread>(); 4];
    for mover in &mut movers {
        *mover = create_referenced(churns, 0, NORMAL_PRIORITY, ANYWHERE)?;
    }
    let until = super::time::interrupt_time() + 5_000_000;
    let mut round = 0u32;
    while super::time::interrupt_time() < until {
        for (n, &mover) in movers.iter().enumerate() {
            set(mover, NORMAL_PRIORITY - 2 + ((round + n as u32) % 5) as u8);
            changes += 1;
        }
        round += 1;
        if round % 64 == 0 {
            yield_now();
        }
    }
    let last: [i32; 4] = core::array::from_fn(|n| set(movers[n], NORMAL_PRIORITY));
    let expected: [i32; 4] = core::array::from_fn(|n| {
        i32::from(NORMAL_PRIORITY - 2 + ((round - 1 + n as u32) % 5) as u8)
    });
    let turns = RAN.load(Ordering::Relaxed);
    STOP.store(true, Ordering::Release);
    // SAFETY: threads this test holds references to, which it gives up
    // here; each wait is for that thread's end.
    unsafe {
        for thread in movers.into_iter().chain([waiting, ready, parked]) {
            wait::wait(Some(thread.cast()), None);
            ob::object::dereference(thread.cast());
        }
    }
    settle(before);
    if was != i32::from(NORMAL_PRIORITY) || not_yet != 0 || woke != 0x1 {
        return Err("a waiting thread did not wake with the priority it was given");
    }
    if idle != 0x1 || was_ready != i32::from(NORMAL_PRIORITY - 1) || ran != 0x12 {
        return Err("a ready thread raised above the running one did not run at once");
    }
    let (n, low) = (i32::from(NORMAL_PRIORITY), i32::from(NORMAL_PRIORITY - 3));
    // Asked for 0, a thread with a base priority gets 1.
    if steps != [n - 2, n - 1, low, 1] || parked_ran != 0x12 {
        return Err("a ready thread moved below the running one ran, or lost its priority");
    }
    if !gave_way {
        return Err("a thread lowered while running elsewhere did not give way there");
    }
    if last != expected || turns == 0 {
        return Err("threads on the move lost a priority that was set, or stopped moving");
    }
    Ok(changes)
}

/// A ready thread raised above the running one runs at once, whatever
/// the other processors are doing: here they are kept looking through
/// this processor's queue for a thread to take, where the one about to
/// be raised is the best there is and not theirs to have. Returns the
/// threads raised.
pub fn raise_ready_test() -> Result<u32, &'static str> {
    fn body(_: usize) {
        RAN.fetch_add(1, Ordering::Release);
    }
    const ROUNDS: u32 = 3000;
    let before = count();
    let me = pcr::current_processor() as usize;
    let processors = super::smp::online_count();
    RAN.store(0, Ordering::Release);
    let mut late = 0;
    for round in 0..ROUNDS {
        let thread = create_referenced(body, 0, NORMAL_PRIORITY - 1, 1 << me)?;
        // An idle processor that is interrupted looks for work: a
        // run of interrupts, of a length that differs from round to
        // round, keeps them looking while the priority changes.
        let old = irql::raise(irql::DISPATCH_LEVEL);
        for _ in 0..1 + round % 24 {
            for other in (0..processors).filter(|&other| other != me) {
                reconsider(other);
            }
        }
        irql::lower(old);
        // A halted processor takes longer to start looking.
        for _ in 0..round % 509 {
            core::hint::spin_loop();
        }
        let waiting = RAN.load(Ordering::Acquire);
        // SAFETY: a thread this test holds a reference to, which it
        // gives up here; the wait is for that thread's end.
        unsafe {
            KeSetPriorityThread(thread.cast(), i32::from(NORMAL_PRIORITY + 1));
            let ran = RAN.load(Ordering::Acquire);
            if (waiting, ran) != (round, round + 1) {
                late += 1;
            }
            super::wait::wait(Some(thread.cast()), None);
            ob::object::dereference(thread.cast());
        }
    }
    if count() != before {
        return Err("the threads did not finish");
    }
    if late != 0 {
        return Err("a ready thread raised above the running one did not run at once");
    }
    Ok(ROUNDS)
}

/// The round `raise_preempted_test` is in.
static ROUND: AtomicU32 = AtomicU32::new(0);
/// The round its pusher is waiting to be woken for, plus one.
static PARKED: AtomicU32 = AtomicU32::new(0);
/// The round its pusher has been woken for, plus one.
static AWAKE: AtomicU32 = AtomicU32::new(0);
/// Its runner has been raised above its pusher, and the raise is over.
static RAISED: AtomicBool = AtomicBool::new(false);

/// A thread raised while a higher thread is taking its processor from
/// it keeps the processor, or has it back at once: the processor that
/// puts it back on its queue finds the new priority there and looks
/// again. On another processor a runner spins and a pusher of higher
/// priority is woken to push it aside, round after round, while this
/// thread raises the runner above the pusher at that moment; the pusher
/// counts how long it runs while outranked. Returns the rounds.
pub fn raise_preempted_test() -> Result<u32, &'static str> {
    use super::wait;
    const ROUNDS: u32 = 3000;
    const PUSHER: u8 = NORMAL_PRIORITY + 2;
    const TOP: u8 = NORMAL_PRIORITY + 4;
    /// Looks the pusher may take while outranked: an interrupt from
    /// another processor is on its way, and arrives well within them.
    const PATIENCE: u32 = 1000;
    fn runner(_: usize) {
        while !STOP.load(Ordering::Acquire) {
            core::hint::spin_loop();
        }
    }
    fn pusher(runner: usize) {
        let runner = runner as *mut Thread;
        for round in 0.. {
            PARKED.store(round + 1, Ordering::Release);
            // SAFETY: a static, initialised event.
            unsafe { wait::wait(Some(OTHER.ptr().cast()), None) };
            if STOP.load(Ordering::Acquire) {
                return;
            }
            AWAKE.store(round + 1, Ordering::Release);
            let mut outranked = 0;
            while ROUND.load(Ordering::Acquire) == round && !STOP.load(Ordering::Acquire) {
                // SAFETY: the test holds the runner until this thread
                // has ended.
                let above = unsafe { priority(runner) } > PUSHER;
                if RAISED.load(Ordering::Acquire) && above {
                    outranked += 1;
                    if outranked == PATIENCE {
                        WRONG.fetch_add(1, Ordering::Relaxed);
                    }
                } else {
                    outranked = 0;
                }
                core::hint::spin_loop();
            }
        }
    }
    let processors = super::smp::online_count();
    if processors < 2 {
        // Nothing can raise a thread while its processor is busy
        // putting it aside.
        return Ok(0);
    }
    let before = count();
    let there = (pcr::current_processor() as usize + 1) % processors;
    STOP.store(false, Ordering::Release);
    RAISED.store(false, Ordering::Release);
    WRONG.store(0, Ordering::Relaxed);
    ROUND.store(0, Ordering::Release);
    PARKED.store(0, Ordering::Release);
    AWAKE.store(0, Ordering::Release);
    // SAFETY: static storage nothing waits on; a synchronization event.
    unsafe { wait::KeInitializeEvent(OTHER.ptr(), 1, 0) };
    let running = create_referenced(runner, 0, NORMAL_PRIORITY, 1 << there)?;
    let pushing = create_referenced(pusher, running as usize, PUSHER, 1 << there)?;
    let set = |new: u8| {
        // SAFETY: a thread this test holds a reference to.
        unsafe { KeSetPriorityThread(running.cast(), i32::from(new)) };
    };
    // Wait for the pusher to say it has got as far as `round`.
    let reached = |stage: &AtomicU32, round: u32| {
        while stage.load(Ordering::Acquire) != round + 1 {
            core::hint::spin_loop();
        }
    };
    for round in 0..ROUNDS {
        reached(&PARKED, round);
        // The pusher wakes there and the runner is put aside for it: a
        // little later each round, and over a wider span every so
        // often, the raise meets that moment.
        // SAFETY: a static, initialised event.
        unsafe { wait::KeSetEvent(OTHER.ptr(), 0, 0) };
        for _ in 0..(round % 128) << (round / 128 % 7) {
            core::hint::spin_loop();
        }
        set(TOP);
        RAISED.store(true, Ordering::Release);
        // Time for the pusher to be seen running, if it is: four
        // times what it needs, in looks like its own.
        for _ in 0..4 * PATIENCE {
            // SAFETY: a thread this test holds a reference to.
            let above = unsafe { priority(running) } > PUSHER;
            core::hint::black_box(
                above
                    && RAISED.load(Ordering::Acquire)
                    && ROUND.load(Ordering::Acquire) == round
                    && !STOP.load(Ordering::Acquire),
            );
            core::hint::spin_loop();
        }
        RAISED.store(false, Ordering::Release);
        // Below the pusher again, the runner gives way to it; the
        // pusher has then run this round, and may go back to wait.
        set(NORMAL_PRIORITY);
        reached(&AWAKE, round);
        ROUND.store(round + 1, Ordering::Release);
    }
    STOP.store(true, Ordering::Release);
    // SAFETY: a static, initialised event; threads this test holds
    // references to, which it gives up here.
    unsafe {
        wait::KeSetEvent(OTHER.ptr(), 0, 0);
        for thread in [pushing, running] {
            wait::wait(Some(thread.cast()), None);
            ob::object::dereference(thread.cast());
        }
    }
    settle(before);
    if WRONG.load(Ordering::Relaxed) != 0 {
        return Err(
            "a thread raised while it was put aside did not get its processor back at once",
        );
    }
    Ok(ROUNDS)
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
    settle(before);
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
    settle(before);
    if RAN.load(Ordering::Acquire) != 3 {
        return Err("not all three threads ran to their end");
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
    let verdict = if !moved {
        Err("the ready thread of lower priority was not on this processor's queue")
    } else if after_lower != 0 {
        Err("a thread of lower priority ran ahead of its creator")
    } else if after_higher != 0x2 {
        Err("a thread of higher priority did not run as soon as it was ready")
    } else {
        Ok(())
    };
    // A scheduler that failed the checks may never run the threads:
    // the failure is reported whether or not they end.
    if verdict.is_ok() {
        settle(before);
    } else {
        settle_within(before, 10_000_000);
    }
    verdict
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
    settle(before);
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
    settle(before);
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
    settle(before);
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
    settle(before);
    if WRONG.load(Ordering::Relaxed) != 0 {
        return Err("a thread ran on a processor outside its affinity");
    }
    Ok(SPINS[0].load(Ordering::Relaxed))
}

/// A thread that sets its system affinity is on a processor of it when
/// the call returns, for every processor, and stays there; the call
/// says what system affinity it had; at `DISPATCH_LEVEL` the move waits
/// for the IRQL to come down; reverting goes back by the same steps to
/// the thread's own affinity; an affinity of no processor changes
/// none. Returns the processors the thread was moved to.
pub fn system_affinity_test() -> Result<u32, &'static str> {
    fn group_0(mask: u64) -> GROUP_AFFINITY {
        GROUP_AFFINITY {
            Mask: mask as usize,
            Group: 0,
            Reserved: [0; 3],
        }
    }
    /// Set the calling thread's system affinity to `mask`: what the
    /// call left in the caller's mask, and the previous affinity.
    fn set(mask: u64) -> (u64, GROUP_AFFINITY) {
        let mut affinity = group_0(mask);
        let mut previous = GROUP_AFFINITY {
            Mask: 0x5A5A,
            Group: 9,
            Reserved: [9; 3],
        };
        // SAFETY: both are locals.
        unsafe { KeSetSystemGroupAffinityThread(&raw mut affinity, &raw mut previous) };
        (affinity.Mask as u64, previous)
    }
    fn revert(mut previous: GROUP_AFFINITY) {
        // SAFETY: a local.
        unsafe { KeRevertToUserGroupAffinityThread(&raw mut previous) };
    }
    let me = current();
    // SAFETY: the running thread's own fields.
    let affinity = || unsafe { field::<u64>(me, layout::AFFINITY).read() };
    let active =
        // SAFETY: the running thread.
        || unsafe { misc_flags(me) }.load(Ordering::Acquire) & layout::MISC_FLAG_SYSTEM_AFFINITY_ACTIVE != 0;
    let processors = super::smp::online_count() as u32;
    let online = super::smp::online();
    let own = affinity();
    if active() {
        return Err("the thread is in system affinity before it set one");
    }

    for target in 0..processors {
        // With a processor that does not run, which is cut from the
        // caller's mask.
        let absent = !online & 1 << 63;
        let (left, previous) = set(1 << target | absent);
        if pcr::current_processor() != target {
            return Err(
                "a thread was not on a processor of its new affinity when the call returned",
            );
        }
        if left != 1 << target || affinity() != 1 << target || !active() {
            return Err("the affinity set is not the running processors asked for");
        }
        let expected = if target == 0 { 0 } else { 1 << (target - 1) };
        if previous != group_0(expected) {
            return Err("the previous affinity is not the system affinity the thread had");
        }
        yield_now();
        if pcr::current_processor() != target {
            return Err("a thread left the processor of its system affinity");
        }
    }
    let last = processors - 1;

    // No such processors: nothing changes.
    let mut refused = group_0(1);
    refused.Group = 1;
    let mut previous = group_0(0);
    // SAFETY: both are locals.
    unsafe { KeSetSystemGroupAffinityThread(&raw mut refused, &raw mut previous) };
    let (_, none) = if online == u64::MAX {
        (0, group_0(1 << last))
    } else {
        set(!online)
    };
    if previous != group_0(1 << last)
        || none != group_0(1 << last)
        || affinity() != 1 << last
        || pcr::current_processor() != last
    {
        return Err("an affinity of no running processor of group 0 changed the thread's");
    }

    if processors > 1 {
        // At DISPATCH_LEVEL the thread stays where it is until the IRQL
        // comes down.
        let other = last - 1;
        let old = irql::raise(irql::DISPATCH_LEVEL);
        let _ = set(1 << other);
        let during = pcr::current_processor();
        irql::lower(old);
        // The move is made by an interrupt this lowering lets in.
        while pcr::current_processor() == last {
            core::hint::spin_loop();
        }
        if during != last || pcr::current_processor() != other {
            return Err("a move asked for at DISPATCH_LEVEL was not made when the IRQL came down");
        }
        // Back to the system affinity before that one.
        revert(group_0(1 << last));
        if pcr::current_processor() != last || affinity() != 1 << last || !active() {
            return Err("reverting to a system affinity did not move the thread to it");
        }
    }

    // A reserved field: nothing. Then the thread's own affinity.
    let mut bad = group_0(0);
    bad.Reserved[2] = 1;
    revert(bad);
    if affinity() != 1 << last || !active() {
        return Err("a revert with a reserved field set changed the affinity");
    }
    revert(group_0(0));
    if affinity() != own || active() || own & 1 << pcr::current_processor() == 0 {
        return Err("reverting did not put the thread back on its own affinity");
    }
    // Not in system affinity: a revert changes nothing.
    revert(group_0(online));
    if affinity() != own || active() {
        return Err("a revert changed the affinity of a thread not in system affinity");
    }
    Ok(processors)
}

/// A processor with nothing to run takes a thread it may run from
/// another's queue even when that queue's best thread is one it may
/// not. On another processor a thread spins above everything; behind it
/// wait a thread pinned there and then one this processor may run too.
/// This thread sleeps, its processor has nothing left, and the second
/// must run here, at once: nothing else would ever give it a processor.
/// Returns the processor it ran on.
pub fn steal_behind_test() -> Result<u32, &'static str> {
    use super::wait;
    fn spinner(_: usize) {
        RUNNER_ON.store(pcr::current_processor(), Ordering::Release);
        while !STOP.load(Ordering::Acquire) {
            core::hint::spin_loop();
        }
    }
    fn pinned(_: usize) {}
    fn free(_: usize) {
        RAN.store(pcr::current_processor() + 1, Ordering::Release);
    }
    let processors = super::smp::online_count();
    if processors < 2 {
        // No other processor to take from.
        return Ok(0);
    }
    let before = count();
    let me = pcr::current_processor() as usize;
    let there = (me + 1) % processors;
    STOP.store(false, Ordering::Release);
    RAN.store(0, Ordering::Release);
    RUNNER_ON.store(u32::MAX, Ordering::Release);
    create(spinner, 0, NORMAL_PRIORITY + 1, 1 << there)?;
    while RUNNER_ON.load(Ordering::Acquire) == u32::MAX {
        core::hint::spin_loop();
    }
    // Both wait behind the spinner, the pinned one first. The second
    // may run here as well, but this processor is busy with this
    // thread, so it is queued there, where it would rather be.
    let made = create(pinned, 0, NORMAL_PRIORITY, 1 << there)
        .and_then(|_| create_unstarted(free, 0, NORMAL_PRIORITY, 1 << there | 1 << me));
    let waited = made.map(|thread| {
        // SAFETY: a thread this test holds a reference to, not yet
        // started; then waited for, and let go of.
        unsafe {
            field::<u32>(thread, layout::IDEAL_PROCESSOR).write(there as u32);
            begin(thread);
            let queued_there = (*thread).queued_on.load(Ordering::SeqCst) == there as u32 + 1;
            // This processor goes idle for as long as the wait lasts.
            let status = wait::wait(Some(thread.cast()), Some(-100_000_000));
            (queued_there, status)
        }
    });
    let ran = RAN.load(Ordering::Acquire);
    STOP.store(true, Ordering::Release);
    if let Ok(thread) = made {
        // SAFETY: the reference `create_unstarted` gave; the thread
        // has run by now or runs once the spinner has gone.
        unsafe {
            wait::wait(Some(thread.cast()), None);
            ob::object::dereference(thread.cast());
        }
    }
    settle(before);
    let (queued_there, status) = waited?;
    if !queued_there {
        return Err("the thread was not queued behind the pinned one on the busy processor");
    }
    if status != wait::STATUS_SUCCESS || ran != me as u32 + 1 {
        return Err("an idle processor left a thread it may run waiting behind one it may not run");
    }
    Ok(ran - 1)
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
    // Asleep between looks: the threads are as many as two to a
    // processor, and this one would take a turn from them.
    while count() != before {
        // SAFETY: no object is involved.
        unsafe { super::wait::wait(None, Some(-100_000)) };
    }
    if WRONG.load(Ordering::Relaxed) != 0 {
        return Err("a thread saw another's identity, a wrong IRQL, or another processor's state");
    }
    Ok(SPINS[0].load(Ordering::Relaxed))
}
