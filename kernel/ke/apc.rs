//! Kernel asynchronous procedure calls.
//!
//! An APC is a routine run in the context of one particular thread. The
//! caller owns the `KAPC`; the kernel links it into the thread's
//! `KAPC_STATE` (at Windows' offsets in the thread block) while it is
//! queued, under the thread's APC lock (`thread::apc_lock`, rank 216 in
//! `doc/LOCKING.md`), and keeps no reference to it once it has run or
//! been removed.
//!
//! Windows' rules, read in its `KeInsertQueueApc`, `KiInsertQueueApc`,
//! `KiSignalThreadForApc` and `KiDeliverApc` (the decisions themselves
//! are `nk_ke::apc`, where the host tests them):
//!
//! - A special kernel APC (no normal routine) is queued after the last
//!   special one, ahead of every normal one; a normal APC at the tail.
//! - Kernel APCs run at `APC_LEVEL`: the special ones' kernel routine
//!   unless the thread is in a guarded region, a normal one's kernel
//!   routine and then, at `PASSIVE_LEVEL`, its normal routine, unless
//!   the thread is in a critical region or already delivering one.
//! - They run when the thread's IRQL falls below `APC_LEVEL`: the
//!   APC_LEVEL interrupt (`arch::APC`), which the processor holds back
//!   while the IRQL is at or above it however the IRQL came down, does
//!   it; when the thread leaves the last critical or guarded region;
//!   and when a wait entered at `PASSIVE_LEVEL` is interrupted for them,
//!   which goes on waiting afterwards.
//! - A thread that gets a processor with kernel APCs pending asks for
//!   the interrupt; it arrives once the thread's IRQL allows.
//!
//! User-mode APCs are queued, and run down when their thread ends, but
//! never delivered: there is no user mode yet (`doc/design/absent.md`).

#![allow(non_snake_case)]

use super::{irql, thread};
use crate::arch;
use core::ffi::c_void;
use core::sync::atomic::{AtomicI16, AtomicU8, AtomicU32, Ordering, fence};
use nk_ke::apc::{self as rules, Disables, Place, Signal, Step};
use nk_ntabi::io::KERNEL_MODE;
use nk_ntabi::ke::{
    APC_OBJECT, KAPC, KAPC_STATE, KERNEL_APC_IN_PROGRESS, LIST_ENTRY, PKKERNEL_ROUTINE,
    PKNORMAL_ROUTINE, PKRUNDOWN_ROUTINE, SPECIAL_APC_IN_PROGRESS, apc_environment,
};
use nk_ntabi::pcr::APC_LEVEL;
use nk_ntabi::thread::{
    APC_STATE, APC_STATE_INDEX, KERNEL_APC_DISABLE, MISC_FLAG_APC_QUEUEABLE, MISC_FLAGS,
    SAVED_APC_STATE, SPECIAL_APC_DISABLE, STATE, WAIT_IRQL, state,
};

/// Take the APC interrupt. Once, at boot; a processor started later
/// takes it from the start.
pub fn init() {
    let (vector, level) = arch::APC;
    arch::interrupt_enable(vector, level);
}

/// The thread's `KAPC_STATE`, its current one or (`index` 1) the saved
/// one.
fn apc_state(thread: *mut thread::Thread, index: u8) -> *mut KAPC_STATE {
    thread::object_field(
        thread,
        if index == 0 {
            APC_STATE
        } else {
            SAVED_APC_STATE
        },
    )
}

/// The head of the queue of APCs of processor mode `mode` in `state`.
fn queue(state: *mut KAPC_STATE, mode: i8) -> *mut LIST_ENTRY {
    // SAFETY: only the address is formed.
    unsafe {
        (&raw mut (*state).ApcListHead)
            .cast::<LIST_ENTRY>()
            .add(mode as usize & 1)
    }
}

/// The current state's queue of kernel APCs.
fn kernel_queue(thread: *mut thread::Thread) -> *mut LIST_ENTRY {
    queue(apc_state(thread, 0), KERNEL_MODE)
}

/// # Safety
/// `thread` is a live thread.
unsafe fn pending<'a>(thread: *mut thread::Thread) -> &'a AtomicU8 {
    // SAFETY: per the contract: a byte of the thread's block that other
    // processors set.
    unsafe { AtomicU8::from_ptr(&raw mut (*apc_state(thread, 0)).KernelApcPending) }
}

/// # Safety
/// `thread` is a live thread.
unsafe fn in_progress<'a>(thread: *mut thread::Thread) -> &'a AtomicU8 {
    // SAFETY: as in `pending`.
    unsafe { AtomicU8::from_ptr(&raw mut (*apc_state(thread, 0)).InProgressFlags) }
}

/// `KernelApcDisable`.
///
/// # Safety
/// `thread` is a live thread.
pub unsafe fn kernel_disable<'a>(thread: *mut thread::Thread) -> &'a AtomicI16 {
    // SAFETY: per the contract: an aligned field of the thread's block.
    unsafe { AtomicI16::from_ptr(thread::object_field(thread, KERNEL_APC_DISABLE)) }
}

/// # Safety
/// `thread` is a live thread.
unsafe fn special_disable<'a>(thread: *mut thread::Thread) -> &'a AtomicI16 {
    // SAFETY: as in `kernel_disable`.
    unsafe { AtomicI16::from_ptr(thread::object_field(thread, SPECIAL_APC_DISABLE)) }
}

/// # Safety
/// `thread` is a live thread.
unsafe fn misc_flags<'a>(thread: *mut thread::Thread) -> &'a AtomicU32 {
    // SAFETY: as in `kernel_disable`.
    unsafe { AtomicU32::from_ptr(thread::object_field(thread, MISC_FLAGS)) }
}

/// # Safety
/// `thread` is a live thread.
unsafe fn disables(thread: *mut thread::Thread) -> Disables {
    // SAFETY: per the contract.
    unsafe {
        Disables {
            kernel: kernel_disable(thread).load(Ordering::Relaxed),
            special: special_disable(thread).load(Ordering::Relaxed),
            in_progress: in_progress(thread).load(Ordering::Relaxed),
        }
    }
}

/// Whether the list at `head` is empty.
///
/// # Safety
/// `head` is a live list head.
unsafe fn empty(head: *mut LIST_ENTRY) -> bool {
    // SAFETY: per the contract; `Flink` is written atomically under the
    // thread's APC lock so lock-free checks are race-free.
    unsafe {
        core::sync::atomic::AtomicPtr::from_ptr(&raw mut (*head).Flink).load(Ordering::Acquire)
            == head
    }
}

/// Link `entry` after `at`.
///
/// # Safety
/// Both are live; `at` is on a list whose lock the caller holds.
unsafe fn link_after(at: *mut LIST_ENTRY, entry: *mut LIST_ENTRY) {
    // SAFETY: per the contract.
    unsafe {
        let next = (*at).Flink;
        entry.write(LIST_ENTRY {
            Flink: next,
            Blink: at,
        });
        (*next).Blink = entry;
        core::sync::atomic::AtomicPtr::from_ptr(&raw mut (*at).Flink)
            .store(entry, Ordering::Release);
    }
}

/// # Safety
/// `entry` is on a list whose lock the caller holds.
unsafe fn unlink(entry: *mut LIST_ENTRY) {
    // SAFETY: per the contract.
    unsafe {
        let LIST_ENTRY { Flink, Blink } = entry.read();
        core::sync::atomic::AtomicPtr::from_ptr(&raw mut (*Blink).Flink)
            .store(Flink, Ordering::Release);
        (*Flink).Blink = Blink;
    }
}

fn apc_of(entry: *mut LIST_ENTRY) -> *mut KAPC {
    entry
        .wrapping_byte_sub(core::mem::offset_of!(KAPC, ApcListEntry))
        .cast()
}

/// Start a new thread's APC states off empty, and let APCs be queued
/// to it. Once, as the thread is made.
///
/// # Safety
/// `thread` is a thread being created, which nothing else has.
pub unsafe fn init_thread(thread: *mut thread::Thread) {
    // SAFETY: per the contract.
    unsafe {
        for index in 0..2 {
            for mode in 0..2 {
                let head = queue(apc_state(thread, index), mode);
                head.write(LIST_ENTRY {
                    Flink: head,
                    Blink: head,
                });
            }
        }
        misc_flags(thread).fetch_or(MISC_FLAG_APC_QUEUEABLE, Ordering::Relaxed);
    }
}

/// `KeInitializeApc`, which no header declares and ntoskrnl exports:
/// fill in `apc` for `thread`. An APC without a normal routine is a
/// special kernel APC, whatever `mode` says.
///
/// # Safety
/// `apc` points to writable storage for a `KAPC`; `thread` is a live
/// thread.
#[allow(clippy::too_many_arguments)]
pub unsafe extern "C" fn KeInitializeApc(
    apc: *mut KAPC,
    target: *mut c_void,
    environment: u32,
    kernel: Option<PKKERNEL_ROUTINE>,
    rundown: Option<PKRUNDOWN_ROUTINE>,
    normal: Option<PKNORMAL_ROUTINE>,
    mode: i8,
    context: *mut c_void,
) {
    // SAFETY: per the contract.
    unsafe {
        let index = if environment == u32::from(apc_environment::CURRENT) {
            thread::object_field::<u8>(target.cast(), APC_STATE_INDEX).read()
        } else {
            environment as u8
        };
        (&raw mut (*apc).Type).write(APC_OBJECT);
        (&raw mut (*apc).Size).write(size_of::<KAPC>() as u8);
        (&raw mut (*apc).ApcStateIndex).write(index);
        (&raw mut (*apc).Thread).write(target);
        (&raw mut (*apc).KernelRoutine).write(kernel);
        (&raw mut (*apc).RundownRoutine).write(rundown);
        (&raw mut (*apc).NormalRoutine).write(normal);
        let special = normal.is_none();
        (&raw mut (*apc).ApcMode).write(if special { KERNEL_MODE } else { mode });
        (&raw mut (*apc).NormalContext).write(if special {
            core::ptr::null_mut()
        } else {
            context
        });
        (&raw mut (*apc).Inserted).write(0);
    }
}

/// Link `apc` into its thread's queue, as `KiInsertQueueApc` does.
///
/// # Safety
/// The thread's APC lock is held; `apc` is initialised and not queued.
unsafe fn insert(apc: *mut KAPC) {
    // SAFETY: per the contract.
    unsafe {
        let target: *mut thread::Thread = (*apc).Thread.cast();
        let current = thread::object_field::<u8>(target, APC_STATE_INDEX).read();
        // The original environment of a thread that is attached is its
        // saved state; any other is the current state.
        let index = if (*apc).ApcStateIndex == apc_environment::ORIGINAL && current != 0 {
            1
        } else {
            (*apc).ApcStateIndex = current;
            0
        };
        let head = queue(apc_state(target, index), (*apc).ApcMode);
        let entry = &raw mut (*apc).ApcListEntry;
        if (*apc).NormalRoutine.is_some() {
            link_after((*head).Blink, entry);
        } else {
            // After the last special APC, ahead of the normal ones.
            let mut at = (*head).Blink;
            while at != head && (*apc_of(at)).NormalRoutine.is_some() {
                at = (*at).Blink;
            }
            link_after(at, entry);
        }
    }
}

/// A byte of `target`'s block that other processors write.
///
/// # Safety
/// `target` is a live thread.
unsafe fn byte(target: *mut thread::Thread, offset: usize) -> u8 {
    // SAFETY: per the contract.
    unsafe { AtomicU8::from_ptr(thread::object_field(target, offset)).load(Ordering::Acquire) }
}

/// [`KeInsertQueueApc`](https://learn.microsoft.com/en-us/windows-hardware/drivers/kernel/types-of-apcs):
/// queue an initialised APC with its two system arguments, and have its
/// thread run it as soon as the rules allow. `FALSE` if it is queued
/// already or the thread takes no more APCs (it is ending). The
/// priority increment is not applied: NK gives no priority boosts.
///
/// # Safety
/// `apc` was initialised by `KeInitializeApc` for a live thread and
/// stays valid until it has run or been removed. At or below
/// `DISPATCH_LEVEL`.
pub unsafe extern "C" fn KeInsertQueueApc(
    apc: *mut KAPC,
    argument1: *mut c_void,
    argument2: *mut c_void,
    _increment: i32,
) -> u8 {
    // SAFETY: per the contract.
    unsafe {
        let target: *mut thread::Thread = (*apc).Thread.cast();
        let (signal, woken) = {
            let _lock = thread::apc_lock(target).lock();
            if misc_flags(target).load(Ordering::Relaxed) & MISC_FLAG_APC_QUEUEABLE == 0
                || (*apc).Inserted != 0
            {
                return 0;
            }
            (*apc).Inserted = 1;
            (*apc).SystemArgument1 = argument1;
            (*apc).SystemArgument2 = argument2;
            insert(apc);
            let current = thread::object_field::<u8>(target, APC_STATE_INDEX).read();
            if (*apc).ApcStateIndex != current || (*apc).ApcMode != KERNEL_MODE {
                // Saved for when the thread detaches, or a user APC.
                return 1;
            }
            let special = (*apc).NormalRoutine.is_none();
            if target == thread::current() {
                let d = disables(target);
                let signal = rules::signal(d, special, Place::Current);
                if signal != Signal::Nothing {
                    pending(target).store(1, Ordering::Relaxed);
                }
                (signal, false)
            } else {
                pending(target).store(1, Ordering::Release);
                // The queue edit and `pending` before the looks at the
                // target's wait, state and disable counts: the target
                // begins its wait before `interrupts_wait`, writes
                // `STATE = RUNNING` before `switched_in`, and raises its
                // disable count before checking the queue, each with a
                // full barrier in between, so one of the two sees the
                // other. Whether it waits is its wait register's to say,
                // not its state, which changes only as it gives up its
                // processor.
                fence(Ordering::SeqCst);
                let d = disables(target);
                let place = Place::Waiting(byte(target, WAIT_IRQL));
                let claimed = if rules::signal(d, special, place) == Signal::Unwait {
                    thread::wait_register(target).claim(super::wait::STATUS_KERNEL_APC)
                } else {
                    None
                };
                match claimed {
                    Some(found) => (Signal::Unwait, found == nk_ke::Claimed::Asleep),
                    None if byte(target, STATE) == state::RUNNING => {
                        (rules::signal(d, special, Place::Running), false)
                    }
                    None => (Signal::Pending, false),
                }
            }
        };
        match signal {
            Signal::Interrupt => arch::self_interrupt(arch::APC.0),
            Signal::InterruptOther => {
                let processor = thread::processor(target);
                if processor == super::pcr::current_processor() as usize {
                    arch::self_interrupt(arch::APC.0);
                } else {
                    arch::interrupt_processor(processor, arch::APC.0);
                }
            }
            _ if woken => thread::make_ready(target),
            _ => {}
        }
        1
    }
}

/// `KeRemoveQueueApc`: take a queued APC off its thread's queue before
/// it runs. `FALSE` if it was not queued.
///
/// # Safety
/// `apc` was initialised by `KeInitializeApc` for a live thread. At or
/// below `DISPATCH_LEVEL`.
pub unsafe extern "C" fn KeRemoveQueueApc(apc: *mut KAPC) -> u8 {
    // SAFETY: per the contract.
    unsafe {
        let target: *mut thread::Thread = (*apc).Thread.cast();
        let _lock = thread::apc_lock(target).lock();
        if (*apc).Inserted == 0 {
            return 0;
        }
        (*apc).Inserted = 0;
        let entry = &raw mut (*apc).ApcListEntry;
        unlink(entry);
        // The last kernel APC gone: none are pending.
        let mode = (*apc).ApcMode;
        let head = queue(apc_state(target, 0), mode);
        if mode == KERNEL_MODE && empty(head) {
            pending(target).store(0, Ordering::Relaxed);
        }
        1
    }
}

/// `KiDeliverApc` for kernel mode: run the running thread's kernel APCs
/// that the rules allow now, special before normal. Called at
/// `APC_LEVEL`, and returns there.
pub fn deliver() {
    let me = thread::current();
    // SAFETY: the running thread, live while it runs this. The APCs
    // queued to it stay valid until they have run.
    unsafe {
        if special_disable(me).load(Ordering::Relaxed) != 0 {
            if pending(me).load(Ordering::Acquire) != 0 {
                let _lock = thread::apc_lock(me).lock();
                pending(me).store(0, Ordering::Relaxed);
            }
            return;
        }
        let head = kernel_queue(me);
        loop {
            if empty(head) && pending(me).load(Ordering::Acquire) == 0 {
                return;
            }
            let lock = thread::apc_lock(me).lock();
            pending(me).store(0, Ordering::Relaxed);
            if empty(head) {
                return;
            }
            let entry = (*head).Flink;
            let apc = apc_of(entry);
            let kernel = (*apc).KernelRoutine;
            let mut normal = (*apc).NormalRoutine;
            let mut context = (*apc).NormalContext;
            let mut argument1 = (*apc).SystemArgument1;
            let mut argument2 = (*apc).SystemArgument2;
            let step = rules::step(disables(me), normal.is_none());
            if step == Step::Stop {
                return;
            }
            unlink(entry);
            (*apc).Inserted = 0;
            drop(lock);
            // From here the APC is the routine's: it may free it.
            let flag = if step == Step::Special {
                SPECIAL_APC_IN_PROGRESS
            } else {
                KERNEL_APC_IN_PROGRESS
            };
            in_progress(me).fetch_or(flag, Ordering::Relaxed);
            if let Some(kernel) = kernel {
                kernel(
                    apc,
                    &raw mut normal,
                    &raw mut context,
                    &raw mut argument1,
                    &raw mut argument2,
                );
            }
            if step == Step::Normal
                && let Some(normal) = normal
            {
                irql::lower(irql::PASSIVE_LEVEL);
                normal(context, argument1, argument2);
                irql::raise(APC_LEVEL);
            }
            in_progress(me).fetch_and(!flag, Ordering::Relaxed);
        }
    }
}

/// `KiCheckForKernelApcDelivery`: the thread has left the region that
/// held its kernel APCs back. At `PASSIVE_LEVEL` they run now; above,
/// when the IRQL falls.
fn check_delivery(me: *mut thread::Thread) {
    if irql::current() == irql::PASSIVE_LEVEL {
        irql::raise(APC_LEVEL);
        deliver();
        irql::lower(irql::PASSIVE_LEVEL);
    } else {
        // SAFETY: the running thread.
        unsafe { pending(me).store(1, Ordering::Relaxed) };
        arch::self_interrupt(arch::APC.0);
    }
}

/// The running thread's `KernelApcDisable` went up by `by`, as it does
/// when it leaves a critical region or releases a mutex: run what that
/// let through.
pub fn kernel_disable_raised(by: i16) {
    let me = thread::current();
    // SAFETY: the running thread.
    unsafe {
        let now = kernel_disable(me)
            .fetch_add(by, Ordering::Release)
            .wrapping_add(by);
        if by != 0 && now == 0 {
            // The disable count cleared before the queue is read: see
            // `KeInsertQueueApc`.
            fence(Ordering::SeqCst);
            if !empty(kernel_queue(me)) && special_disable(me).load(Ordering::Relaxed) == 0 {
                check_delivery(me);
            }
        }
    }
}

/// [`KeEnterGuardedRegion`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntddk/nf-ntddk-keenterguardedregion):
/// hold back every kernel APC of the running thread.
pub extern "C" fn KeEnterGuardedRegion() {
    // SAFETY: the running thread.
    unsafe { special_disable(thread::current()) }.fetch_sub(1, Ordering::Relaxed);
}

/// [`KeLeaveGuardedRegion`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntddk/nf-ntddk-keleaveguardedregion):
/// leaving the last guarded region lets the queued kernel APCs run.
pub extern "C" fn KeLeaveGuardedRegion() {
    let me = thread::current();
    // SAFETY: the running thread.
    unsafe {
        if special_disable(me).fetch_add(1, Ordering::Release) == -1 {
            // The disable count cleared before the queue is read: see
            // `KeInsertQueueApc`.
            fence(Ordering::SeqCst);
            if !empty(kernel_queue(me)) {
                check_delivery(me);
            }
        }
    }
}

/// [`KeAreAllApcsDisabled`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-keareallapcsdisabled):
/// a guarded region, interrupts off, or an IRQL of `APC_LEVEL` or above.
pub extern "C" fn KeAreAllApcsDisabled() -> u8 {
    // SAFETY: the running thread.
    let special = unsafe { special_disable(thread::current()) }.load(Ordering::Relaxed);
    u8::from(rules::all_disabled(
        special,
        arch::interrupts_enabled(),
        irql::current(),
    ))
}

/// The running thread is about to sleep in a wait entered at
/// `PASSIVE_LEVEL`, its wait already begun: whether kernel APCs are
/// pending that it must deliver first (`STATUS_KERNEL_APC`).
pub fn interrupts_wait() -> bool {
    let me = thread::current();
    // The wait begun before the flag is read: see `KeInsertQueueApc`.
    fence(Ordering::SeqCst);
    // SAFETY: the running thread.
    unsafe {
        pending(me).load(Ordering::Relaxed) != 0 && special_disable(me).load(Ordering::Relaxed) == 0
    }
}

/// The running thread has just been given a processor: if kernel APCs
/// were queued for it meanwhile, interrupt this processor at
/// `APC_LEVEL`; they run once the thread's IRQL is below that.
pub fn switched_in() {
    // `STATE = RUNNING` and `next_processor` were written before the
    // switch, and `KeInsertQueueApc` sets `pending` before reading them:
    // one of the two sees the other.
    fence(Ordering::SeqCst);
    // SAFETY: the running thread.
    if unsafe { pending(thread::current()) }.load(Ordering::Acquire) != 0 {
        arch::self_interrupt(arch::APC.0);
    }
}

/// The running thread is ending, at `PASSIVE_LEVEL`: take no more APCs,
/// run the kernel APCs still queued, and run down the user APCs (their
/// rundown routine, or the pool block freed), as Windows'
/// `KeRundownApcQueues` does. A kernel APC that still cannot run stops
/// the system, as there.
pub fn rundown() {
    let me = thread::current();
    // SAFETY: the running thread; queued APCs are valid until run down.
    unsafe {
        {
            let _lock = thread::apc_lock(me).lock();
            misc_flags(me).fetch_and(!MISC_FLAG_APC_QUEUEABLE, Ordering::Relaxed);
        }
        if !empty(kernel_queue(me)) {
            irql::raise(APC_LEVEL);
            deliver();
            irql::lower(irql::PASSIVE_LEVEL);
        }
        for index in 0..2 {
            let head = queue(apc_state(me, index), 1);
            loop {
                let apc = {
                    let _lock = thread::apc_lock(me).lock();
                    if empty(head) {
                        break;
                    }
                    let entry = (*head).Flink;
                    unlink(entry);
                    let apc = apc_of(entry);
                    (*apc).Inserted = 0;
                    apc
                };
                match (*apc).RundownRoutine {
                    Some(rundown) => rundown(apc),
                    None => crate::mm::pool::ExFreePool(apc.cast()),
                }
            }
        }
        if !empty(kernel_queue(me)) || !empty(queue(apc_state(me, 1), KERNEL_MODE)) {
            let disables = kernel_disable(me).load(Ordering::Relaxed);
            crate::kd::bugcheck(format_args!(
                "0x00000020 KERNEL_APC_PENDING_DURING_EXIT: a thread ended with kernel APCs \
                 queued (KernelApcDisable {disables})"
            ));
        }
    }
}

// ---- tests --------------------------------------------------------------

use crate::test::Slot;
use core::sync::atomic::{AtomicBool, AtomicPtr, AtomicU64};

static APCS: [Slot<KAPC>; 4] = [const { Slot::new() }; 4];
/// What the routines did, four bits an event, the latest lowest.
static TRACE: AtomicU64 = AtomicU64::new(0);
/// Routines that ran at the wrong IRQL, or on the wrong thread.
static WRONG: AtomicU32 = AtomicU32::new(0);
/// The thread the routines must run on.
static TARGET: AtomicPtr<thread::Thread> = AtomicPtr::new(core::ptr::null_mut());

fn note(event: u64) {
    let _ = TRACE.try_update(Ordering::AcqRel, Ordering::Acquire, |t| {
        Some(t << 4 | event)
    });
}

fn expect(level: u8) {
    if irql::current() != level || thread::current() != TARGET.load(Ordering::Acquire) {
        WRONG.fetch_add(1, Ordering::Relaxed);
    }
}

/// A kernel routine: notes the APC's number (its system argument 1)
/// at `APC_LEVEL`.
///
/// # Safety
/// Called by delivery, with a test APC and its arguments.
unsafe extern "C" fn kernel_note(
    apc: *mut KAPC,
    _: *mut Option<PKNORMAL_ROUTINE>,
    _: *mut *mut c_void,
    argument1: *mut *mut c_void,
    _: *mut *mut c_void,
) {
    expect(APC_LEVEL);
    // SAFETY: the arguments of a kernel routine.
    unsafe {
        if (*apc).Inserted != 0 {
            WRONG.fetch_add(1, Ordering::Relaxed);
        }
        note((*argument1).addr() as u64);
    }
}

/// A normal routine: notes its context plus 8 at `PASSIVE_LEVEL`.
///
/// # Safety
/// Called by delivery; touches nothing through its arguments.
unsafe extern "C" fn normal_note(context: *mut c_void, _: *mut c_void, _: *mut c_void) {
    expect(irql::PASSIVE_LEVEL);
    note(context.addr() as u64 + 8);
}

/// Initialise test APC `n` for `target`: special, or normal with
/// `normal_note`.
fn prepare(n: usize, target: *mut thread::Thread, special: bool) -> *mut KAPC {
    let apc = APCS[n].ptr();
    // SAFETY: static storage for a KAPC that is not queued.
    unsafe {
        KeInitializeApc(
            apc,
            target.cast(),
            u32::from(apc_environment::ORIGINAL),
            Some(kernel_note),
            None,
            (!special).then_some(normal_note as PKNORMAL_ROUTINE),
            KERNEL_MODE,
            core::ptr::without_provenance_mut(n),
        );
    }
    apc
}

/// Queue test APC `n` with its number as argument 1.
fn queue_it(apc: *mut KAPC, n: usize) -> u8 {
    // SAFETY: an initialised APC in static storage.
    unsafe {
        KeInsertQueueApc(
            apc,
            core::ptr::without_provenance_mut(n),
            core::ptr::null_mut(),
            0,
        )
    }
}

fn start(target: *mut thread::Thread) {
    TRACE.store(0, Ordering::Relaxed);
    WRONG.store(0, Ordering::Relaxed);
    TARGET.store(target, Ordering::Release);
}

fn wrong() -> Result<(), &'static str> {
    if WRONG.load(Ordering::Relaxed) != 0 {
        return Err("an APC routine ran at the wrong IRQL, on the wrong thread, or still queued");
    }
    Ok(())
}

/// Special APCs run before normal ones, whatever the order they were
/// queued in; each normal one's kernel routine runs at `APC_LEVEL` and
/// its normal routine after it at `PASSIVE_LEVEL`. Held back by a
/// guarded region, they run as it is left.
pub fn order_test() -> Result<(), &'static str> {
    let me = thread::current();
    start(me);
    KeEnterGuardedRegion();
    let queued = [
        queue_it(prepare(0, me, false), 0),
        queue_it(prepare(1, me, true), 1),
        queue_it(prepare(2, me, false), 2),
        queue_it(prepare(3, me, true), 3),
    ];
    let held = TRACE.load(Ordering::Acquire);
    let again = queue_it(APCS[1].ptr(), 1);
    KeLeaveGuardedRegion();
    if queued != [1; 4] || again != 0 {
        return Err("an APC was not queued, or one queued already was queued again");
    }
    if held != 0 {
        return Err("an APC ran inside a guarded region");
    }
    // Special 1, 3; then normal 0 (kernel 0, normal 8), 2 (2, 10).
    if TRACE.load(Ordering::Acquire) != 0x0013_082A {
        return Err("APCs did not run special first, each normal one's two routines in turn");
    }
    wrong()
}

/// A critical region holds back normal APCs but not special ones, which
/// arrive at once; leaving it runs the normal ones.
pub fn critical_test() -> Result<(), &'static str> {
    let me = thread::current();
    start(me);
    super::mutex::KeEnterCriticalRegion();
    queue_it(prepare(0, me, false), 0);
    queue_it(prepare(1, me, true), 1);
    // The interrupt that runs it may lag the request a little.
    for _ in 0..20_000 {
        if TRACE.load(Ordering::Acquire) != 0 {
            break;
        }
        core::hint::spin_loop();
    }
    let inside = TRACE.load(Ordering::Acquire);
    super::mutex::KeLeaveCriticalRegion();
    if inside != 0x1 {
        return Err("inside a critical region a special APC did not run, or a normal one did");
    }
    if TRACE.load(Ordering::Acquire) != 0x108 {
        return Err("leaving a critical region did not run the normal APC");
    }
    wrong()
}

/// An APC queued to the running thread while its IRQL is `APC_LEVEL` or
/// `DISPATCH_LEVEL` waits until the IRQL falls below `APC_LEVEL`, and
/// runs then, however it came down.
pub fn irql_test() -> Result<(), &'static str> {
    let me = thread::current();
    for level in [APC_LEVEL, irql::DISPATCH_LEVEL] {
        start(me);
        let old = irql::raise(level);
        queue_it(prepare(0, me, true), 0xA);
        let early = TRACE.load(Ordering::Acquire);
        // Lowered as WDK-built code lowers it, without a call.
        arch::set_irql(old);
        for _ in 0..20_000 {
            if TRACE.load(Ordering::Acquire) != 0 {
                break;
            }
            core::hint::spin_loop();
        }
        if early != 0 {
            return Err("an APC ran while the IRQL was at APC_LEVEL or above");
        }
        if TRACE.load(Ordering::Acquire) != 0xA {
            return Err("an APC held back by the IRQL did not run when it fell");
        }
    }
    wrong()
}

static GO: Slot<nk_ntabi::ke::KEVENT> = Slot::new();
static WAITED: AtomicU32 = AtomicU32::new(0);
static READY: AtomicBool = AtomicBool::new(false);

/// A thread in a wait that is not alertable, entered at
/// `PASSIVE_LEVEL`, runs a kernel APC queued to it, special or normal,
/// and goes on waiting: the wait ends when its object is signalled, and
/// returns what that gives.
pub fn wait_test() -> Result<u32, &'static str> {
    fn waiter(_: usize) {
        READY.store(true, Ordering::Release);
        // SAFETY: a static, initialised event.
        let status = unsafe { super::wait::wait(Some(GO.ptr().cast()), Some(-50_000_000)) };
        WAITED.store(status, Ordering::Release);
    }
    // SAFETY: static storage for an event.
    unsafe { super::wait::KeInitializeEvent(GO.ptr(), 0, 0) };
    WAITED.store(u32::MAX, Ordering::Relaxed);
    READY.store(false, Ordering::Relaxed);
    let before = thread::count();
    let target = thread::create_unstarted(waiter, 0, thread::NORMAL_PRIORITY, thread::ANYWHERE)?;
    start(target);
    // SAFETY: `target` came from `create_unstarted` and has not started.
    unsafe { thread::begin(target) };
    let asleep = || {
        // SAFETY: the thread is referenced.
        let state = unsafe { byte(target, STATE) };
        READY.load(Ordering::Acquire) && state == state::WAITING
    };
    let mut verdict = Ok(2);
    while !asleep() {
        thread::yield_now();
    }
    let settle = |events: u64| {
        while TRACE.load(Ordering::Acquire) != events {
            thread::yield_now();
        }
    };
    let q0 = queue_it(prepare(0, target, true), 1);
    settle(0x1);
    let q1 = queue_it(prepare(1, target, false), 2);
    settle(0x129);
    let ran = TRACE.load(Ordering::Acquire);
    let still = WAITED.load(Ordering::Acquire);
    // SAFETY: a static, initialised event; the thread is referenced
    // until the dereference.
    unsafe {
        super::wait::KeSetEvent(GO.ptr(), 0, 0);
        super::wait::wait(Some(target.cast()), None);
        crate::ob::object::dereference(target.cast());
    }
    thread::settle(before);
    if (q0, q1) != (1, 1) {
        verdict = Err("a kernel APC could not be queued to the waiting thread");
    } else if ran != 0x129 {
        verdict = Err("a waiting thread did not run the kernel APCs queued to it");
    } else if still != u32::MAX {
        verdict = Err("a kernel APC ended a wait that is not alertable");
    } else if WAITED.load(Ordering::Acquire) != super::wait::STATUS_SUCCESS {
        verdict = Err("the wait a kernel APC interrupted did not end with its object");
    }
    verdict.and_then(|n| wrong().map(|()| n))
}

static SPIN: AtomicBool = AtomicBool::new(false);

/// A kernel APC queued to a thread that is busy elsewhere, running or
/// ready, at `PASSIVE_LEVEL` runs on that thread. Repeated across many
/// starts so queuing races with the thread switching in on another
/// processor.
pub fn thread_test() -> Result<(), &'static str> {
    fn busy(_: usize) {
        while SPIN.load(Ordering::Acquire) {
            if TRACE.load(Ordering::Acquire) != 0 {
                break;
            }
            core::hint::spin_loop();
            thread::yield_now();
        }
    }
    const ROUNDS: usize = 16;
    for _ in 0..ROUNDS {
        SPIN.store(true, Ordering::Release);
        let before = thread::count();
        let target = thread::create_unstarted(busy, 0, thread::NORMAL_PRIORITY, thread::ANYWHERE)?;
        start(target);
        // SAFETY: `target` came from `create_unstarted` and has not started.
        unsafe { thread::begin(target) };
        let queued = queue_it(prepare(0, target, false), 5);
        while queued == 1 && TRACE.load(Ordering::Acquire) != 0x58 {
            thread::yield_now();
        }
        let ran = TRACE.load(Ordering::Acquire);
        SPIN.store(false, Ordering::Release);
        // SAFETY: the thread is referenced until the dereference.
        unsafe {
            super::wait::wait(Some(target.cast()), None);
            crate::ob::object::dereference(target.cast());
        }
        thread::settle(before);
        if queued != 1 {
            return Err("an APC could not be queued to a busy thread");
        }
        if ran != 0x58 {
            return Err("a busy thread did not run the APC queued to it");
        }
        wrong()?;
    }
    Ok(())
}

/// A queued APC taken off its queue never runs and can be taken off
/// only once; an ending thread takes no more APCs.
pub fn remove_test() -> Result<(), &'static str> {
    let me = thread::current();
    start(me);
    KeEnterGuardedRegion();
    let apc = prepare(0, me, true);
    queue_it(apc, 1);
    // SAFETY: an initialised APC in static storage.
    let (first, second) = unsafe { (KeRemoveQueueApc(apc), KeRemoveQueueApc(apc)) };
    // SAFETY: the running thread.
    let left = unsafe { pending(me).load(Ordering::Relaxed) };
    KeLeaveGuardedRegion();
    if (first, second) != (1, 0) {
        return Err("a queued APC was not removed exactly once");
    }
    if TRACE.load(Ordering::Acquire) != 0 || left != 0 {
        return Err("a removed APC ran, or left APCs pending");
    }
    wrong()
}

/// `KeAreAllApcsDisabled` is true in a guarded region, at `APC_LEVEL` or
/// above and with interrupts off, and only then; a critical region is
/// not enough.
pub fn disabled_test() -> Result<(), &'static str> {
    let free = KeAreAllApcsDisabled();
    super::mutex::KeEnterCriticalRegion();
    let critical = KeAreAllApcsDisabled();
    super::mutex::KeLeaveCriticalRegion();
    KeEnterGuardedRegion();
    let guarded = KeAreAllApcsDisabled();
    KeLeaveGuardedRegion();
    let old = irql::raise(APC_LEVEL);
    let raised = KeAreAllApcsDisabled();
    irql::lower(old);
    let saved = arch::interrupts_off();
    let off = KeAreAllApcsDisabled();
    arch::interrupts_restore(saved);
    if (free, critical, guarded, raised, off) != (0, 0, 1, 1, 1) {
        return Err("KeAreAllApcsDisabled's answers are wrong");
    }
    Ok(())
}
