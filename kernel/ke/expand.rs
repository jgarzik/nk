//! Expanding a thread's kernel stack: `KeExpandKernelStackAndCalloutEx`.
//!
//! A caller that needs more stack than may be left (a file system on
//! every create and every transfer to its disk) asks for a size and a
//! routine; the routine runs on the current stack if that has the room,
//! else on a stack segment of its own. The rules are those of Windows'
//! `KiExpandKernelStackAndCalloutSwitchStack`, read in the pinned
//! kernel:
//!
//! - A size above `MAXIMUM_EXPANSION` fails with
//!   `STATUS_INVALID_PARAMETER_3`; above `DISPATCH_LEVEL` the system
//!   stops (`IRQL_NOT_LESS_OR_EQUAL`); at `DISPATCH_LEVEL` a caller that
//!   says it may wait fails with `STATUS_INVALID_PARAMETER_4`.
//! - A size equal to the kernel stack's, or 0x6000 (which is not more
//!   than it), always gets a segment; any other gets one only if the
//!   current stack has less room left.
//!
//! A segment is a kernel stack like a thread's (`mm::stack`: the same
//! size, alignment and unmapped guard, so the overflow checks hold on
//! it), switched to by `arch::call_on_stack`, whose unwind information
//! leads a stack walk back to the stack it came from. While the routine
//! runs there the thread's `KTHREAD` stack fields, `IoGetStackLimits`,
//! the overflow check and the unwinder all see the segment
//! (`thread::push_segment`). An exception the routine lets out unwinds
//! across the switch to a handler beneath: the guarded call's undo puts
//! the thread back on its stack as the unwind passes, and the segment,
//! still under the unwind's feet, is kept and given back at the thread's
//! next return from a segment, or when it ends.
//!
//! What NK does not do as Windows does: a segment is never larger than a
//! thread's stack, so a size it cannot hold fails with
//! `STATUS_INSUFFICIENT_RESOURCES`, as does one at `DISPATCH_LEVEL` the
//! current stack cannot hold, where Windows may switch; and nesting
//! stops at `thread::MAX_SEGMENTS`.

#![allow(non_snake_case)]

use super::seh::{self, Guard};
use super::{irql, thread};
use crate::arch;
use crate::mm::stack::{self, Stack};
use core::ffi::c_void;
use nk_bootinfo::KERNEL_STACK_SIZE;
use nk_ntabi::status::{NTSTATUS, STATUS_INSUFFICIENT_RESOURCES, STATUS_SUCCESS};

/// The largest size a caller may ask for.
pub const MAXIMUM_EXPANSION: usize = 0x11800;
/// The size Windows' file systems ask for, which always gets a segment.
const FILE_SYSTEM_SIZE: usize = 0x6000;
/// Room on a segment kept for the frames that switch to it and call the
/// routine: whatever is asked for must fit beneath.
const SWITCH_FRAMES: usize = 0x200;

const STATUS_INVALID_PARAMETER_3: NTSTATUS = 0xC000_00F1_u32 as NTSTATUS;
const STATUS_INVALID_PARAMETER_4: NTSTATUS = 0xC000_00F2_u32 as NTSTATUS;

/// `PEXPAND_STACK_CALLOUT`.
pub type ExpandStackCallout = unsafe extern "C" fn(*mut c_void);

/// What the routine run on a segment is to call.
struct Callout {
    routine: ExpandStackCallout,
    parameter: *mut c_void,
}

/// The stack pointer, near enough: the address of a local of the caller.
#[inline(always)]
fn stack_pointer() -> usize {
    let here = 0u8;
    core::hint::black_box(&raw const here).addr()
}

/// [`KeExpandKernelStackAndCalloutEx`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-keexpandkernelstackandcalloutex):
/// call `routine(parameter)` with at least `size` bytes of stack.
///
/// # Safety
/// `routine` may be called with `parameter` now.
pub unsafe extern "C" fn KeExpandKernelStackAndCalloutEx(
    routine: ExpandStackCallout,
    parameter: *mut c_void,
    size: usize,
    wait: u8,
    _context: *mut c_void,
) -> NTSTATUS {
    if size > MAXIMUM_EXPANSION {
        return STATUS_INVALID_PARAMETER_3;
    }
    let level = irql::current();
    if level > irql::DISPATCH_LEVEL {
        crate::kd::bugcheck(format_args!(
            "0x0000000A IRQL_NOT_LESS_OR_EQUAL: KeExpandKernelStackAndCalloutEx at IRQL {level}"
        ));
    }
    let room = super::unwind::stack_holding(stack_pointer() as u64)
        .map_or(0, |on| stack_pointer() - on.base as usize);
    if level == irql::DISPATCH_LEVEL {
        if wait != 0 {
            return STATUS_INVALID_PARAMETER_4;
        }
        if room < size {
            return STATUS_INSUFFICIENT_RESOURCES;
        }
        // SAFETY: per the contract.
        unsafe { routine(parameter) };
        return STATUS_SUCCESS;
    }
    let forced = size == KERNEL_STACK_SIZE as usize || size == FILE_SYSTEM_SIZE;
    if !forced && room >= size {
        // SAFETY: per the contract.
        unsafe { routine(parameter) };
        return STATUS_SUCCESS;
    }
    if size > KERNEL_STACK_SIZE as usize - SWITCH_FRAMES {
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    let Some(segment) = thread::push_segment(stack::alloc) else {
        return STATUS_INSUFFICIENT_RESOURCES;
    };
    let callout = Callout { routine, parameter };
    // SAFETY: the segment is mapped, the thread's own and unused; the
    // callout outlives the call.
    unsafe { arch::call_on_stack(segment.top, on_segment, (&raw const callout).addr()) };
    thread::pop_segment(true);
    STATUS_SUCCESS
}

/// Run the callout at `callout` on the segment, guarded: an exception it
/// lets out takes the thread off the segment as the unwind passes.
extern "C" fn on_segment(callout: usize) {
    // SAFETY: the callout the caller keeps for the call.
    let callout = unsafe { &*(callout as *const Callout) };
    let guard = Guard::Undo {
        undo: unwound,
        context: core::ptr::null_mut(),
    };
    // SAFETY: per the contract of `KeExpandKernelStackAndCalloutEx`.
    unsafe {
        seh::call(
            callout.routine as usize,
            [callout.parameter.addr(), 0, 0, 0],
            &guard,
        )
    };
}

/// An unwind passes the routine's call: the thread is going back to the
/// stack it switched from.
///
/// # Safety
/// Called once by the unwind, on the segment.
unsafe fn unwound(_: *mut c_void) {
    thread::pop_segment(false);
}

// ---- tests --------------------------------------------------------------

use core::sync::atomic::{AtomicU64, AtomicUsize, Ordering};

/// Where the last test callout ran, and the stack limits it was told.
static SEEN_SP: AtomicUsize = AtomicUsize::new(0);
static SEEN_LIMITS: [AtomicUsize; 2] = [const { AtomicUsize::new(0) }; 2];
static SEEN_BASE: AtomicU64 = AtomicU64::new(0);

/// A callout that notes where it runs and what it is told about its
/// stack.
///
/// # Safety
/// Takes any parameter.
unsafe extern "C" fn note(_: *mut c_void) {
    SEEN_SP.store(stack_pointer(), Ordering::Relaxed);
    let (mut low, mut high) = (0, 0);
    // SAFETY: two locals.
    unsafe { crate::io::irpinfo::IoGetStackLimits(&raw mut low, &raw mut high) };
    SEEN_LIMITS[0].store(low, Ordering::Relaxed);
    SEEN_LIMITS[1].store(high, Ordering::Relaxed);
    let base = thread::object_field::<u64>(thread::current(), nk_ntabi::thread::STACK_BASE);
    // SAFETY: a field of the running thread's block.
    SEEN_BASE.store(unsafe { base.read() }, Ordering::Relaxed);
}

fn expand(size: usize) -> NTSTATUS {
    SEEN_SP.store(0, Ordering::Relaxed);
    // SAFETY: `note` takes any parameter.
    unsafe {
        KeExpandKernelStackAndCalloutEx(note, core::ptr::null_mut(), size, 1, core::ptr::null_mut())
    }
}

fn on(stack: Stack, address: usize) -> bool {
    (stack.base as usize..stack.top as usize).contains(&address)
}

/// A file system's 0x6000 runs on a segment, which the thread's stack
/// fields and `IoGetStackLimits` report while it does; afterwards the
/// thread is back on its own stack, the segment given back.
pub fn switch_test() -> Result<(), &'static str> {
    let own = thread::current_stack();
    let status = expand(FILE_SYSTEM_SIZE);
    let sp = SEEN_SP.load(Ordering::Relaxed);
    let (low, high) = (
        SEEN_LIMITS[0].load(Ordering::Relaxed),
        SEEN_LIMITS[1].load(Ordering::Relaxed),
    );
    if status != STATUS_SUCCESS || sp == 0 {
        return Err("the callout did not run");
    }
    if on(own, sp) {
        return Err("a 0x6000 callout ran on the thread's own stack");
    }
    if !(low..high).contains(&sp) || high - low != KERNEL_STACK_SIZE as usize {
        return Err("IoGetStackLimits did not report the segment the callout ran on");
    }
    if SEEN_BASE.load(Ordering::Relaxed) != high as u64 {
        return Err("KTHREAD.StackBase did not report the segment");
    }
    if thread::current_stack() != own || thread::segments_in_use() != 0 {
        return Err("the thread was not back on its own stack afterwards");
    }
    Ok(())
}

/// A small size with room to spare runs on the current stack; one
/// above the maximum fails without running.
pub fn inline_test() -> Result<(), &'static str> {
    let own = thread::current_stack();
    if expand(0x800) != STATUS_SUCCESS || !on(own, SEEN_SP.load(Ordering::Relaxed)) {
        return Err("a small callout did not run on the current stack");
    }
    if expand(MAXIMUM_EXPANSION + 1) != STATUS_INVALID_PARAMETER_3
        || SEEN_SP.load(Ordering::Relaxed) != 0
    {
        return Err("a size above the maximum was not refused with STATUS_INVALID_PARAMETER_3");
    }
    Ok(())
}

/// Expand to a segment and raise there, for a handler beneath the
/// switch to catch.
///
/// # Safety
/// Takes the status to raise.
pub unsafe extern "C" fn raise_on_segment(code: usize) {
    /// Raise the status `code`.
    ///
    /// # Safety
    /// Takes any status.
    unsafe extern "C" fn raise(code: *mut c_void) {
        // SAFETY: the routine takes any status.
        unsafe { arch::seh::nk_entry_ExRaiseStatus(code.addr() as i32) };
    }
    // SAFETY: `raise` takes any status.
    unsafe {
        KeExpandKernelStackAndCalloutEx(
            raise,
            core::ptr::without_provenance_mut(code),
            FILE_SYSTEM_SIZE,
            1,
            core::ptr::null_mut(),
        );
    }
}

/// After an exception raised on a segment was handled beneath the
/// switch: the thread is back on its own stack, and the next expansion
/// works and gives back the segment the unwind left behind.
pub fn after_raise_test() -> Result<(), &'static str> {
    let own = thread::current_stacks().next();
    let base = thread::object_field::<u64>(thread::current(), nk_ntabi::thread::STACK_BASE);
    // SAFETY: a field of the running thread's block.
    let base = unsafe { base.read() };
    if Some(thread::current_stack()) != own
        || thread::segments_in_use() != 0
        || own.map(|stack| stack.top) != Some(base)
    {
        return Err("an unwind out of a segment did not put the thread back on its own stack");
    }
    switch_test()
}
