//! Structured exception handling: raising, finding a handler, unwinding.
//!
//! An exception is an `EXCEPTION_RECORD` and the `CONTEXT` of the code
//! it was raised in. [`dispatch`] walks the stack from that context,
//! frame by frame (`nk_unwind`), and calls the language handler of each
//! function that names one, innermost first, until one takes the
//! exception. Taking it means unwinding: [`unwind`] walks the same
//! frames again, calls their handlers a second time so that `__finally`
//! blocks run, and continues in the frame that took it. Formats and
//! rules are Microsoft's:
//! [x64](https://learn.microsoft.com/en-us/cpp/build/exception-handling-x64),
//! [arm64](https://learn.microsoft.com/en-us/cpp/build/arm64-exception-handling).
//!
//! NK's own frames lie on those stacks too, and an unwind discards them
//! like any other: no destructor runs. So this code, and every NK frame
//! an exception can cross, holds nothing across a call into a driver
//! that would need one: no lock, no guard, no owned block. What such a
//! frame does owe is stated in the [`Guard`] it calls the driver with
//! (`doc/DESIGN.md`, "Exceptions").

#![allow(non_snake_case)]

use super::unwind::{self, WalkError};
pub use crate::arch::seh::Context;
use crate::arch::seh::{self as cpu, DispatcherContext, Handler};
use crate::arch::unwind as frames;
use crate::{kd, ldr};
use core::ffi::c_void;
use core::fmt;
use nk_ntabi::seh::{EXCEPTION_MAXIMUM_PARAMETERS, EXCEPTION_POINTERS, EXCEPTION_RECORD};
pub use nk_unwind::dispatch::EXCEPTION_NONCONTINUABLE;
use nk_unwind::dispatch::{
    EXCEPTION_COLLIDED_UNWIND, EXCEPTION_COLLIDED_UNWIND_DISPOSITION, EXCEPTION_CONTINUE_EXECUTION,
    EXCEPTION_CONTINUE_SEARCH, EXCEPTION_NESTED_CALL, EXCEPTION_NESTED_EXCEPTION,
    EXCEPTION_TARGET_UNWIND, EXCEPTION_UNWIND, FilterResult, MemoryFault, Next, STATUS_UNWIND,
    after_filter, after_search_handler, after_unwind_handler, unwind_flags,
};
use nk_unwind::scope::{self, Action, Phase};

pub const STATUS_DATATYPE_MISALIGNMENT: u32 = 0x8000_0002;
pub const STATUS_BREAKPOINT: u32 = 0x8000_0003;
pub const STATUS_ACCESS_VIOLATION: u32 = 0xC000_0005;
pub const STATUS_ILLEGAL_INSTRUCTION: u32 = 0xC000_001D;
pub const STATUS_INTEGER_DIVIDE_BY_ZERO: u32 = 0xC000_0094;

/// The first parameter of an access violation: what the access was.
pub const ACCESS_READ: u64 = 0;
pub const ACCESS_WRITE: u64 = 1;
pub const ACCESS_EXECUTE: u64 = 8;

/// How the system stops for an exception nothing handles: which of
/// Windows' bugchecks, by where the exception was raised.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Unhandled {
    /// In a system service made on behalf of user mode:
    /// `SYSTEM_SERVICE_EXCEPTION`.
    SystemService,
    /// In a system thread, a worker thread included:
    /// `SYSTEM_THREAD_EXCEPTION_NOT_HANDLED`.
    SystemThread,
    /// Anywhere else, a DPC routine for one, and whenever the stack
    /// cannot be searched: `KMODE_EXCEPTION_NOT_HANDLED`.
    KernelMode,
}

/// What a call into a driver owes if the driver's routine does not
/// return because an exception passed through it.
pub enum Guard {
    /// The call may be unwound, and NK owes nothing then.
    Nothing,
    /// The call may be unwound; `undo(context)` is then called, once,
    /// when the unwind passes.
    Undo {
        undo: unsafe fn(*mut c_void),
        context: *mut c_void,
    },
    /// No driver's frame lies beneath this call, so no handler can: an
    /// exception that reaches it is unhandled, and the system stops as
    /// Windows does for where the call is made. Nothing is ever unwound
    /// through such a call.
    Base(Unhandled),
}

/// Call `routine`, a driver's, with up to four arguments. Every call NK
/// makes into a driver goes through here: the frame between is one the
/// dispatcher knows, and `guard` says what it is to do there.
///
/// # Safety
/// `routine` is the address of a function of the Windows calling
/// convention that may be called with these arguments now.
pub unsafe fn call(routine: usize, args: [usize; 4], guard: &Guard) -> usize {
    // SAFETY: per the contract; the guard outlives the call.
    unsafe { cpu::guarded_call(routine, args, core::ptr::from_ref(guard).cast()) }
}

/// Run `service` as a system service made on behalf of user mode: an
/// exception nothing inside it handles stops the system with
/// `SYSTEM_SERVICE_EXCEPTION`, as on Windows.
pub fn system_service<R, F: FnOnce() -> R>(service: F) -> R {
    extern "C" fn run<R, F: FnOnce() -> R>(slot: *mut (Option<F>, Option<R>)) {
        // SAFETY: the slot below, which nothing else touches meanwhile.
        let slot = unsafe { &mut *slot };
        slot.1 = slot.0.take().map(|service| service());
    }
    let mut slot = (Some(service), None);
    let guard = Guard::Base(Unhandled::SystemService);
    // SAFETY: `run` takes one pointer, to the slot it is given.
    unsafe {
        call(
            run::<R, F> as *const () as usize,
            [(&raw mut slot).addr(), 0, 0, 0],
            &guard,
        )
    };
    match slot.1 {
        Some(result) => result,
        None => kd::bugcheck(format_args!("a system service did not run")),
    }
}

/// The language handler of the frame [`call`] makes.
///
/// # Safety
/// Called by the dispatcher for that frame.
pub unsafe extern "C" fn guard_handler(
    record: *mut EXCEPTION_RECORD,
    frame: u64,
    context: *mut Context,
    _dispatcher: *mut DispatcherContext,
) -> u32 {
    // SAFETY: the frame is `nk_guarded_call`'s, and its guard a `Guard`
    // of NK's own that the caller keeps until the call is over.
    let guard = unsafe { cpu::guard_of(frame).cast::<Guard>().as_ref() };
    // SAFETY: the dispatcher's record.
    let unwinding = unsafe { (*record).ExceptionFlags } & EXCEPTION_UNWIND != 0;
    match guard {
        Some(Guard::Undo { undo, context }) if unwinding => {
            // SAFETY: what the caller asked to have done in this case.
            unsafe { undo(*context) }
        }
        Some(Guard::Base(how)) if !unwinding => {
            unhandled(*how, record, context, format_args!("no handler"))
        }
        _ => {}
    }
    EXCEPTION_CONTINUE_SEARCH
}

/// The language handler of the frame the dispatcher calls a handler
/// through while it searches. A second exception, raised inside that
/// handler, meets it: the search for the second is told which frame
/// the first had reached.
///
/// # Safety
/// Called by the dispatcher for that frame.
pub unsafe extern "C" fn nested_handler(
    record: *mut EXCEPTION_RECORD,
    frame: u64,
    _context: *mut Context,
    dispatcher: *mut DispatcherContext,
) -> u32 {
    // SAFETY: the dispatcher's record; the frame is a handler-call
    // frame, which holds the dispatcher context of the search it
    // belongs to; `dispatcher` is the calling search's own.
    unsafe {
        if (*record).ExceptionFlags & EXCEPTION_UNWIND != 0 {
            return EXCEPTION_CONTINUE_SEARCH;
        }
        (*dispatcher).EstablisherFrame = (*cpu::dispatcher_of(frame)).EstablisherFrame;
    }
    EXCEPTION_NESTED_EXCEPTION
}

/// The language handler of the frame the dispatcher calls a handler
/// through while it unwinds. A walk that meets it has run into an
/// unwind in progress, and takes that unwind's frame over: it is handed
/// the dispatcher context that unwind was using.
///
/// # Safety
/// Called by the dispatcher for that frame.
pub unsafe extern "C" fn collided_handler(
    _record: *mut EXCEPTION_RECORD,
    frame: u64,
    _context: *mut Context,
    dispatcher: *mut DispatcherContext,
) -> u32 {
    // SAFETY: as in `nested_handler`. Where the new walk is to resume
    // stays its own.
    unsafe { cpu::take_over(dispatcher, cpu::dispatcher_of(frame)) };
    EXCEPTION_COLLIDED_UNWIND_DISPOSITION
}

/// A frame's language handler.
#[derive(Clone, Copy)]
struct FrameHandler {
    routine: Handler,
    /// Address of the handler's data.
    data: u64,
    search: bool,
    unwind: bool,
}

/// One frame of a walk: what its language handler is told, and the
/// context of the frame beneath.
struct Frame {
    control_pc: u64,
    image_base: u64,
    /// Address of the function's entry in its image's function table;
    /// zero for a leaf, which has none.
    function_entry: u64,
    establisher: u64,
    handler: Option<FrameHandler>,
    /// The frame beneath, as it will be when this one has returned.
    caller: Context,
    /// That frame was stopped by an interrupt at its program counter,
    /// not left by a call.
    caller_interrupted: bool,
}

/// Undo the frame `context` is in. `interrupted`: its program counter
/// is where an interrupt stopped it, not a return address.
fn frame_of(context: &Context, interrupted: bool) -> Result<Frame, WalkError> {
    let stacks = unwind::stacks();
    let mut read = |address| unwind::read_slot(&stacks, address);
    let pc = cpu::pc(context);
    let regs = cpu::regs(context);
    let mut caller = *context;
    let Some(module) = ldr::module_containing(pc) else {
        // Code in no image cannot be waiting for a call to return. An
        // interrupt can find the processor there: a call through a
        // pointer that leads nowhere faults at its target, with the
        // return address where a call leaves it, as in a leaf.
        if !interrupted {
            return Err(WalkError::NoImage { pc });
        }
        let beneath = frames::leaf(&regs, &mut read).map_err(|_| WalkError::NoImage { pc })?;
        cpu::set_regs(&mut caller, &beneath, true);
        return Ok(Frame {
            control_pc: pc,
            image_base: 0,
            function_entry: 0,
            establisher: cpu::sp(context),
            handler: None,
            caller,
            caller_interrupted: false,
        });
    };
    let offset = pc - module.base;
    let failed = |error| WalkError::Unwind {
        module,
        offset,
        error,
    };
    // SAFETY: the image's code is on the stack being walked, which is
    // this thread's own: it cannot be unloaded meanwhile.
    let image = unsafe { ldr::view(&module) };
    let step = frames::step(
        image,
        module.pdata,
        offset as u32,
        &regs,
        !interrupted,
        &mut read,
    )
    .map_err(failed)?;
    let Some(step) = step else {
        // Only interrupted code can be a leaf.
        if !interrupted {
            return Err(WalkError::NoEntry { module, offset });
        }
        let beneath = frames::leaf(&regs, &mut read).map_err(failed)?;
        cpu::set_regs(&mut caller, &beneath, true);
        return Ok(Frame {
            control_pc: pc,
            image_base: module.base,
            function_entry: 0,
            establisher: cpu::sp(context),
            handler: None,
            caller,
            caller_interrupted: false,
        });
    };
    cpu::set_regs(&mut caller, &step.regs, !step.interrupted);
    let handler = step.handler.map(|h| FrameHandler {
        // SAFETY: the address the image's unwind data gives for the
        // function's language handler, which is one by the format.
        routine: unsafe { core::mem::transmute::<u64, Handler>(module.base + u64::from(h.rva)) },
        data: module.base + u64::from(h.data_rva),
        search: h.search,
        unwind: h.unwind,
    });
    Ok(Frame {
        control_pc: pc,
        image_base: module.base,
        function_entry: module.base + u64::from(step.entry),
        establisher: step.establisher,
        handler,
        caller,
        caller_interrupted: step.interrupted,
    })
}

/// Whether `frame`, a frame's base, is a place on the stacks this
/// processor can be running on.
fn on_stack(frame: u64) -> bool {
    frame.is_multiple_of(8)
        && unwind::stacks()
            .iter()
            .flatten()
            .any(|stack| stack.base <= frame && frame <= stack.top)
}

/// The dispatcher context for the handler of `frame`.
fn dispatcher_for(
    frame: &Frame,
    handler: &FrameHandler,
    context: *mut Context,
    target: u64,
    scope_index: u32,
    interrupted: bool,
    nonvolatile: &mut cpu::Nonvolatile,
) -> DispatcherContext {
    cpu::dispatcher_context(
        frame.control_pc,
        frame.image_base,
        frame.function_entry,
        frame.establisher,
        target,
        context,
        handler.routine as usize as u64,
        handler.data,
        scope_index,
        !interrupted,
        nonvolatile,
    )
}

/// Look for a handler for the exception `record`, raised in the code
/// `context` describes. `interrupted`: the context's program counter is
/// the instruction that faulted, not a return address.
///
/// Returns only if a handler asks for the code to be continued:
/// `context` then holds the registers to continue with, which the
/// handler may have changed. A handler that takes the exception unwinds
/// to itself and this never returns; an exception nothing takes stops
/// the system.
///
/// # Safety
/// `record` and `context` are valid and nothing else uses them;
/// `context` describes a frame of the stack this is called on.
pub unsafe fn dispatch(record: *mut EXCEPTION_RECORD, context: *mut Context, interrupted: bool) {
    // SAFETY: per the contract.
    let mut current = unsafe { *context };
    let mut interrupted = interrupted;
    // SAFETY: per the contract.
    let mut flags = unsafe { (*record).ExceptionFlags } & EXCEPTION_NONCONTINUABLE;
    // The frame whose handler was running when this exception was
    // raised inside it: until the search has passed it, handlers are
    // told they are being asked a second time.
    let mut nested_frame = 0;
    loop {
        if cpu::pc(&current) == 0 && !interrupted {
            // The end of a stack: a thread's first frame, which returns
            // to address zero. Every thread is a system thread. Code
            // stopped at address zero is something else: a call through
            // a null pointer, whose caller is searched.
            unhandled(
                Unhandled::SystemThread,
                record,
                context,
                format_args!("no handler"),
            );
        }
        let mut frame = match frame_of(&current, interrupted) {
            Ok(frame) => frame,
            Err(error) => unsearchable(record, context, error),
        };
        let mut scope_index = 0;
        // Once; again for a frame taken over from an unwind this
        // search ran into.
        loop {
            if !on_stack(frame.establisher) {
                unhandled(
                    Unhandled::KernelMode,
                    record,
                    context,
                    format_args!("the frame at {:#x} is off the stack", frame.establisher),
                );
            }
            let Some(handler) = frame.handler.filter(|h| h.search) else {
                break;
            };
            let mut nonvolatile = cpu::nonvolatile(&current);
            let caller = &raw mut frame.caller;
            let mut dispatcher = dispatcher_for(
                &frame,
                &handler,
                caller,
                0,
                scope_index,
                interrupted,
                &mut nonvolatile,
            );
            // SAFETY: per the contract, and the handler is the frame's
            // own; nothing of this function's needs a destructor if the
            // handler unwinds past it.
            let disposition = unsafe {
                (*record).ExceptionFlags = flags;
                let disposition = cpu::call_handler_search(
                    record,
                    frame.establisher,
                    context,
                    &raw mut dispatcher,
                    handler.routine,
                );
                flags |= (*record).ExceptionFlags & EXCEPTION_NONCONTINUABLE;
                disposition
            };
            if nested_frame == frame.establisher {
                flags &= !EXCEPTION_NESTED_CALL;
                nested_frame = 0;
            }
            match after_search_handler(disposition, flags) {
                Next::Resume => return,
                Next::NextFrame => break,
                Next::Nested => {
                    flags |= EXCEPTION_NESTED_CALL;
                    nested_frame = nested_frame.max(dispatcher.EstablisherFrame);
                    break;
                }
                Next::Collided => {
                    // SAFETY: the dispatcher context of the unwind in
                    // progress, whose frames lie beneath this one.
                    current = unsafe { *dispatcher.ContextRecord };
                    interrupted = !cpu::unwound_to_call(&dispatcher);
                    scope_index = dispatcher.ScopeIndex;
                    frame = match frame_of(&current, interrupted) {
                        Ok(frame) => frame,
                        Err(error) => unsearchable(record, context, error),
                    };
                }
                // SAFETY: per the contract.
                Next::Raise(status) => unsafe { raise_here(status, record) },
            }
        }
        current = frame.caller;
        interrupted = frame.caller_interrupted;
    }
}

/// Unwind the stack to the frame whose base is `target_frame` and
/// continue there at `target_pc` with `value` as a call's return value:
/// what Windows' `RtlUnwindEx` does. Each frame on the way has its
/// language handler called, so that its `__finally` blocks run; NK's
/// own frames on the way are discarded. `record` is the exception being
/// handled, or null for an unwind that is not for one (`STATUS_UNWIND`).
///
/// # Safety
/// `target_frame` is a frame beneath the caller on this stack and
/// `target_pc` a place its function can be continued at; `record` is
/// null or valid. Nothing in any NK frame between needs a destructor.
pub unsafe fn unwind(
    target_frame: u64,
    target_pc: u64,
    record: *mut EXCEPTION_RECORD,
    value: u64,
) -> ! {
    let mut current = cpu::context_of(&frames::capture());
    let mut original = current;
    let mut own = new_record(STATUS_UNWIND, 0, cpu::pc(&current), &[]);
    let record = if record.is_null() {
        &raw mut own
    } else {
        record
    };
    // SAFETY: per the contract.
    let flags = unsafe { (*record).ExceptionFlags };
    let mut interrupted = false;
    loop {
        if cpu::pc(&current) == 0 && !interrupted {
            kd::bugcheck(format_args!(
                "0xC0000029 STATUS_INVALID_UNWIND_TARGET: no frame at {target_frame:#x} to unwind to"
            ));
        }
        let mut frame = match frame_of(&current, interrupted) {
            Ok(frame) => frame,
            Err(error) => kd::bugcheck(format_args!("an unwind cannot go on: {error}")),
        };
        let (mut scope_index, mut collided) = (0, 0);
        // Once; again for a frame taken over from an unwind this one
        // ran into.
        loop {
            if !on_stack(frame.establisher) {
                kd::bugcheck(format_args!(
                    "0xC0000028 STATUS_BAD_STACK: unwinding met a frame at {:#x}, off the stack",
                    frame.establisher
                ));
            }
            let Some(handler) = frame.handler.filter(|h| h.unwind) else {
                break;
            };
            let mut nonvolatile = cpu::nonvolatile(&current);
            let mut dispatcher = dispatcher_for(
                &frame,
                &handler,
                &raw mut current,
                target_pc,
                scope_index,
                interrupted,
                &mut nonvolatile,
            );
            // SAFETY: per the contract, and the handler is the frame's
            // own.
            let disposition = unsafe {
                (*record).ExceptionFlags =
                    unwind_flags(flags | collided, frame.establisher, Some(target_frame));
                cpu::call_handler_unwind(
                    record,
                    frame.establisher,
                    &raw mut original,
                    &raw mut dispatcher,
                    handler.routine,
                )
            };
            match after_unwind_handler(disposition) {
                Next::Collided => {
                    // SAFETY: the dispatcher context of the unwind in
                    // progress, whose frames lie beneath this one.
                    current = unsafe { *dispatcher.ContextRecord };
                    interrupted = !cpu::unwound_to_call(&dispatcher);
                    scope_index = dispatcher.ScopeIndex;
                    collided = EXCEPTION_COLLIDED_UNWIND;
                    frame = match frame_of(&current, interrupted) {
                        Ok(frame) => frame,
                        Err(error) => kd::bugcheck(format_args!("an unwind cannot go on: {error}")),
                    };
                }
                Next::NextFrame => break,
                _ => kd::bugcheck(format_args!(
                    "0xC0000026 STATUS_INVALID_DISPOSITION: a handler answered {disposition} to an unwind"
                )),
            }
        }
        if frame.establisher == target_frame {
            break;
        }
        current = frame.caller;
        interrupted = frame.caller_interrupted;
    }
    cpu::set_resume(&mut current, target_pc, value);
    // SAFETY: `current` is the target frame as the walk found it, and
    // per the contract it can be continued at `target_pc`.
    unsafe { cpu::restore_context(&current) }
}

/// `_local_unwind`: what compiled code calls to leave a `__try` early,
/// by `goto` or `return`. Unwinds to `target` in the frame `frame`,
/// the caller's own, which runs the `__finally` blocks of the scopes
/// being left.
///
/// # Safety
/// As [`unwind`], with no exception.
pub unsafe extern "C" fn _local_unwind(frame: u64, target: u64) -> ! {
    // SAFETY: per the contract.
    unsafe { unwind(frame, target, core::ptr::null_mut(), 0) }
}

/// The bytes of an image from `address` to the image's end, through the
/// image's view: what a handler's data is read from.
fn image_from(address: u64) -> &'static [u8] {
    let Some(module) = ldr::module_containing(address) else {
        kd::bugcheck(format_args!(
            "a language handler's data at {address:#x} is in no image"
        ));
    };
    // SAFETY: the image has a frame on the stack being dispatched, so
    // it stays loaded for as long as the caller uses the bytes.
    let image = unsafe { ldr::view(&module) };
    &image[(address - module.base) as usize..]
}

/// `EXCEPTION_FILTER`: the filter expression of a `__except`.
type Filter = unsafe extern "C" fn(*mut EXCEPTION_POINTERS, u64) -> i32;
/// `TERMINATION_HANDLER`: a `__finally` block.
type Termination = unsafe extern "C" fn(u8, u64);

/// `__C_specific_handler`: the language handler of C functions with
/// `__try`. Searching, it asks the filters of the `__except` scopes
/// around the frame's program counter, innermost first, and unwinds to
/// the block of the first that accepts. Unwinding, it runs the
/// `__finally` blocks of the scopes being left. The scope table and its
/// search are `nk_unwind::scope`.
///
/// # Safety
/// Called by the dispatcher, or by a driver's own handler passing on
/// what the dispatcher gave it.
pub unsafe extern "C" fn __C_specific_handler(
    record: *mut EXCEPTION_RECORD,
    frame: u64,
    context: *mut Context,
    dispatcher: *mut DispatcherContext,
) -> u32 {
    // SAFETY: per the contract. The dispatcher context is read once: a
    // driver's handler may have a pointer to it.
    let (given, flags, code) = unsafe {
        (
            dispatcher.read(),
            (*record).ExceptionFlags,
            (*record).ExceptionCode,
        )
    };
    let base = given.ImageBase;
    let table = image_from(given.HandlerData as u64);
    let pc = (cpu::scope_pc(&given) - base) as u32;
    let phase = if flags & EXCEPTION_UNWIND == 0 {
        Phase::Search
    } else {
        Phase::Unwind {
            target: (flags & EXCEPTION_TARGET_UNWIND != 0)
                .then(|| (cpu::target(&given) - base) as u32),
        }
    };
    let mut index = given.ScopeIndex;
    loop {
        let (found, action) = match scope::next(table, pc, phase, index) {
            Ok(Some(next)) => next,
            Ok(None) => return EXCEPTION_CONTINUE_SEARCH,
            Err(error) => kd::bugcheck(format_args!(
                "a scope table at {:p} is malformed: {error:?}",
                given.HandlerData
            )),
        };
        index = found + 1;
        let accepted = match action {
            Action::Filter {
                filter,
                jump_target,
            } => {
                let mut pointers = EXCEPTION_POINTERS {
                    ExceptionRecord: record,
                    ContextRecord: context.cast(),
                };
                // SAFETY: the scope's filter, by the table's format, and
                // the dispatcher context this handler was called with.
                let value = unsafe {
                    let filter: Filter = core::mem::transmute(base + u64::from(filter));
                    filter(&raw mut pointers, cpu::block_frame(&given, frame))
                };
                match after_filter(value) {
                    FilterResult::ContinueExecution => return EXCEPTION_CONTINUE_EXECUTION,
                    FilterResult::ContinueSearch => None,
                    FilterResult::ExecuteHandler => Some(jump_target),
                }
            }
            Action::ExecuteHandler { jump_target } => Some(jump_target),
            Action::Finally { handler } => {
                // SAFETY: per the contract; the scope's `__finally`
                // block, by the table's format. Its index is recorded
                // first: an unwind that begins inside the block takes
                // this one over and must not run the block again.
                unsafe {
                    (&raw mut (*dispatcher).ScopeIndex).write(index);
                    let finally: Termination = core::mem::transmute(base + u64::from(handler));
                    finally(1, cpu::block_frame(&given, frame));
                }
                None
            }
            Action::Stop => return EXCEPTION_CONTINUE_SEARCH,
        };
        if let Some(jump_target) = accepted {
            // The `__except` block finds the exception's code where a
            // call would have left its result.
            // SAFETY: this frame's function is on the stack beneath,
            // and the block is where its scope table says to continue.
            unsafe {
                unwind(
                    frame,
                    base + u64::from(jump_target),
                    record,
                    code as i32 as u64,
                )
            }
        }
    }
}

/// A record for the exception `code` raised at `address`.
fn new_record(code: u32, flags: u32, address: u64, parameters: &[u64]) -> EXCEPTION_RECORD {
    let mut information = [0; EXCEPTION_MAXIMUM_PARAMETERS];
    information[..parameters.len()].copy_from_slice(parameters);
    EXCEPTION_RECORD {
        ExceptionCode: code,
        ExceptionFlags: flags,
        ExceptionRecord: core::ptr::null_mut(),
        ExceptionAddress: address as *mut c_void,
        NumberParameters: parameters.len() as u32,
        ExceptionInformation: information,
    }
}

/// Raise the exception `code` in the code `context` describes: a caller
/// of the kernel, as `nk_with_caller_context` captured it. `flags` are
/// the record's; an exception that may be continued and is, is raised
/// again, as a fault repeats when its instruction is run again.
///
/// # Safety
/// `context` is valid and describes a frame of this stack; nothing in
/// any NK frame between needs a destructor.
pub unsafe fn raise(context: *mut Context, code: u32, flags: u32, parameters: &[u64]) -> ! {
    // SAFETY: per the contract.
    let address = cpu::pc(unsafe { &*context });
    loop {
        let mut record = new_record(code, flags, address, parameters);
        // SAFETY: per the contract.
        unsafe { dispatch(&raw mut record, context, false) };
    }
}

/// Deliver a processor fault as the exception `code`: the trap handler's
/// way in. `context` is the faulting code as the processor stopped it.
/// Returns if a handler asks for the code to be continued, with what it
/// made of `context`.
///
/// # Safety
/// `context` describes the code the trap interrupted, on this stack;
/// the trap handler's own frames hold nothing a destructor must give
/// back.
pub unsafe fn fault(context: *mut Context, code: u32, parameters: &[u64]) {
    // SAFETY: per the contract.
    let mut record = new_record(code, 0, cpu::pc(unsafe { &*context }), parameters);
    // SAFETY: per the contract.
    unsafe { dispatch(&raw mut record, context, true) };
}

/// Why a memory fault stops the system instead of becoming an
/// exception: the first line of its bugcheck.
pub struct FaultStop {
    verdict: MemoryFault,
    address: u64,
    access: u64,
    level: u8,
    in_kernel: bool,
}

impl fmt::Display for FaultStop {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let Self {
            address,
            access,
            level,
            ..
        } = *self;
        let low = address as u32;
        match self.verdict {
            MemoryFault::KernelAddress => {
                // Windows' second parameter: 0 read, 2 write, 0x10 execute.
                let operation = [(ACCESS_WRITE, 2), (ACCESS_EXECUTE, 0x10)]
                    .iter()
                    .find(|(kind, _)| *kind == access)
                    .map_or(0, |(_, operation)| *operation);
                write!(
                    f,
                    "0x00000050 PAGE_FAULT_IN_NONPAGED_AREA: {low:#010X} (parameter 1 \
                     {address:#018x}, parameter 2 {operation:#x})"
                )
            }
            _ => {
                let (number, name) = if self.in_kernel {
                    (0xA, "IRQL_NOT_LESS_OR_EQUAL")
                } else {
                    (0xD1, "DRIVER_IRQL_NOT_LESS_OR_EQUAL")
                };
                write!(
                    f,
                    "{number:#010X} {name}: {low:#010X} (parameter 1 {address:#018x}): memory \
                     that is not there was touched at IRQL {level} (access {access})"
                )
            }
        }
    }
}

/// The first line of a fatal trap's report: the bugcheck Windows names
/// for it, when it has one.
pub struct StopLine(pub Option<FaultStop>);

impl fmt::Display for StopLine {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.0 {
            Some(stop) => writeln!(f, "{stop}"),
            None => Ok(()),
        }
    }
}

/// Decide a memory fault on `address` by the code at `pc`: `None` if it
/// is an access violation to deliver, else why the system stops.
pub fn memory_fault(address: u64, access: u64, pc: u64) -> Option<FaultStop> {
    let level = super::irql::current();
    let verdict = nk_unwind::dispatch::memory_fault(address, level >= super::irql::DISPATCH_LEVEL);
    (verdict != MemoryFault::Exception).then(|| FaultStop {
        verdict,
        address,
        access,
        level,
        in_kernel: ldr::module_containing(pc).is_some_and(|m| m.name() == b"ntoskrnl.exe"),
    })
}

/// Raise `code`, which cannot be continued, in the function this is
/// written in: the dispatcher's own failures. `chained` is the
/// exception being dispatched when it arose.
///
/// # Safety
/// `chained` is null or a valid record.
#[inline(always)]
unsafe fn raise_here(code: u32, chained: *mut EXCEPTION_RECORD) -> ! {
    let mut context = cpu::context_of(&frames::capture());
    loop {
        let mut record = new_record(code, EXCEPTION_NONCONTINUABLE, cpu::pc(&context), &[]);
        record.ExceptionRecord = chained;
        // SAFETY: the context is this function's own frame.
        unsafe { dispatch(&raw mut record, &raw mut context, false) };
    }
}

/// Stop the system: the stack of the exception `record` cannot be
/// searched for a handler. Never a guess: a frame that cannot be undone
/// is named.
fn unsearchable(record: *mut EXCEPTION_RECORD, context: *mut Context, error: WalkError) -> ! {
    unhandled(
        Unhandled::KernelMode,
        record,
        context,
        format_args!("the stack cannot be searched: {error}"),
    )
}

/// Stop the system for an exception nothing handled, with Windows'
/// bugcheck for where it was raised. The line begins with the bugcheck's
/// code and the exception's code, which is the low half of the
/// bugcheck's first parameter; the parameter itself follows.
fn unhandled(
    how: Unhandled,
    record: *mut EXCEPTION_RECORD,
    context: *mut Context,
    why: fmt::Arguments<'_>,
) -> ! {
    // SAFETY: the dispatcher's own record and context.
    let (record, pc, sp) = unsafe { (record.read(), cpu::pc(&*context), cpu::sp(&*context)) };
    let code = record.ExceptionCode;
    let extended = i64::from(code as i32) as u64;
    // Windows widens the code with its sign for two of the three.
    let (number, name, first) = match how {
        Unhandled::SystemService => (0x3Bu32, "SYSTEM_SERVICE_EXCEPTION", u64::from(code)),
        Unhandled::SystemThread => (0x7E, "SYSTEM_THREAD_EXCEPTION_NOT_HANDLED", extended),
        Unhandled::KernelMode => (0x1E, "KMODE_EXCEPTION_NOT_HANDLED", extended),
    };
    let address = record.ExceptionAddress as u64;
    kd::bugcheck(format_args!(
        "{number:#010X} {name}: {code:#010X} (parameter 1 {first:#018x}) at {address:#018x} \
         in {}: {why}\n\
         exception flags {:#x}; {} parameters: {:#x} {:#x}\n\
         pc={pc:#018x} in {} sp={sp:#018x}",
        ldr::locate_fatal(address),
        record.ExceptionFlags,
        record.NumberParameters,
        record.ExceptionInformation[0],
        record.ExceptionInformation[1],
        ldr::locate_fatal(pc),
    ))
}

/// What `ExRaiseStatus` is entered as: raise `status` in the caller.
///
/// # Safety
/// Called through `nk_with_caller_context`.
#[unsafe(no_mangle)]
unsafe extern "C" fn nk_raise_status(status: u32, _: usize, _: usize, context: *mut Context) {
    // SAFETY: per the contract, the caller's context.
    unsafe { raise(context, status, EXCEPTION_NONCONTINUABLE, &[]) }
}

/// What `ExRaiseAccessViolation` is entered as.
///
/// # Safety
/// Called through `nk_with_caller_context`.
#[unsafe(no_mangle)]
unsafe extern "C" fn nk_raise_access_violation(
    _: usize,
    _: usize,
    _: usize,
    context: *mut Context,
) {
    // SAFETY: per the contract, the caller's context.
    unsafe {
        raise(
            context,
            STATUS_ACCESS_VIOLATION,
            EXCEPTION_NONCONTINUABLE,
            &[],
        )
    }
}

/// What `ExRaiseDatatypeMisalignment` is entered as.
///
/// # Safety
/// Called through `nk_with_caller_context`.
#[unsafe(no_mangle)]
unsafe extern "C" fn nk_raise_datatype_misalignment(
    _: usize,
    _: usize,
    _: usize,
    context: *mut Context,
) {
    // SAFETY: per the contract, the caller's context.
    unsafe {
        raise(
            context,
            STATUS_DATATYPE_MISALIGNMENT,
            EXCEPTION_NONCONTINUABLE,
            &[],
        )
    }
}

/// `MmUserProbeAddress`: the first address beyond user space.
const USER_PROBE_ADDRESS: usize = crate::mm::user::USER_PROBE_ADDRESS as usize;

/// The checks `ProbeForRead` and `ProbeForWrite` share. A range of no
/// bytes passes whatever it is. Alignment is looked at first, and a
/// misaligned address raises `STATUS_DATATYPE_MISALIGNMENT`. Returns
/// whether the range lies in user space.
///
/// # Safety
/// `context` is the caller's, from `nk_with_caller_context`.
unsafe fn probe(address: usize, length: usize, alignment: u32, context: *mut Context) -> bool {
    if length == 0 {
        return true;
    }
    if alignment > 1 && address & (alignment as usize - 1) != 0 {
        // SAFETY: per the contract.
        unsafe {
            raise(
                context,
                STATUS_DATATYPE_MISALIGNMENT,
                EXCEPTION_NONCONTINUABLE,
                &[],
            )
        }
    }
    crate::mm::user::in_range(address, length)
}

/// What [`ProbeForRead`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-probeforread)
/// is entered as. The range is not touched. One outside user space is
/// refused the way Windows 10 refuses it, which is not by raising a
/// status but by touching `MmUserProbeAddress`: a memory fault, so an
/// access violation with two parameters that may be continued.
///
/// # Safety
/// Called through `nk_with_caller_context`.
#[unsafe(no_mangle)]
unsafe extern "C" fn nk_probe_for_read(
    address: usize,
    length: usize,
    alignment: u32,
    context: *mut Context,
) {
    // SAFETY: per the contract, the caller's context.
    unsafe {
        if !probe(address, length, alignment, context) {
            raise(
                context,
                STATUS_ACCESS_VIOLATION,
                0,
                &[ACCESS_READ, USER_PROBE_ADDRESS as u64],
            );
        }
    }
}

/// What [`ProbeForWrite`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-probeforwrite)
/// is entered as. A range outside user space raises
/// `STATUS_ACCESS_VIOLATION` as `ExRaiseAccessViolation` does, without
/// parameters. One inside has a byte of each page read and written
/// back, and a fault there is the access violation of that fault.
///
/// # Safety
/// Called through `nk_with_caller_context`.
#[unsafe(no_mangle)]
unsafe extern "C" fn nk_probe_for_write(
    address: usize,
    length: usize,
    alignment: u32,
    context: *mut Context,
) {
    // SAFETY: per the contract, the caller's context.
    unsafe {
        if !probe(address, length, alignment, context) {
            raise(
                context,
                STATUS_ACCESS_VIOLATION,
                EXCEPTION_NONCONTINUABLE,
                &[],
            );
        }
        if let Err(fault) = crate::mm::user::probe_pages(address, length) {
            raise(
                context,
                STATUS_ACCESS_VIOLATION,
                0,
                &[fault.access, fault.address],
            );
        }
    }
}
