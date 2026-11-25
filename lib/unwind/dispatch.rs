//! The decisions of an exception dispatch loop, without the loop: what a
//! handler's return value means, which flags a frame's handler sees, and
//! whether a frame is one the loop may trust. The kernel walks the stack
//! and calls the handlers; these functions tell it what to do next.

/// `EXCEPTION_RECORD.ExceptionFlags`.
pub const EXCEPTION_NONCONTINUABLE: u32 = 0x01;
pub const EXCEPTION_UNWINDING: u32 = 0x02;
pub const EXCEPTION_EXIT_UNWIND: u32 = 0x04;
pub const EXCEPTION_STACK_INVALID: u32 = 0x08;
pub const EXCEPTION_NESTED_CALL: u32 = 0x10;
pub const EXCEPTION_TARGET_UNWIND: u32 = 0x20;
pub const EXCEPTION_COLLIDED_UNWIND: u32 = 0x40;
/// Any of these set: the handler is being called to unwind, not to
/// handle.
pub const EXCEPTION_UNWIND: u32 = EXCEPTION_UNWINDING
    | EXCEPTION_EXIT_UNWIND
    | EXCEPTION_TARGET_UNWIND
    | EXCEPTION_COLLIDED_UNWIND;

/// `EXCEPTION_DISPOSITION`, a language handler's return value.
pub const EXCEPTION_CONTINUE_EXECUTION: u32 = 0;
pub const EXCEPTION_CONTINUE_SEARCH: u32 = 1;
pub const EXCEPTION_NESTED_EXCEPTION: u32 = 2;
pub const EXCEPTION_COLLIDED_UNWIND_DISPOSITION: u32 = 3;

pub const STATUS_NONCONTINUABLE_EXCEPTION: u32 = 0xC000_0025;
pub const STATUS_INVALID_DISPOSITION: u32 = 0xC000_0026;
pub const STATUS_UNWIND: u32 = 0xC000_0027;
pub const STATUS_BAD_STACK: u32 = 0xC000_0028;
pub const STATUS_INVALID_UNWIND_TARGET: u32 = 0xC000_0029;

/// What the loop does after a language handler returns.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Next {
    /// Resume the interrupted code with the context record.
    Resume,
    /// Go on to the next frame.
    NextFrame,
    /// An exception was raised inside a handler of this dispatch: set
    /// [`EXCEPTION_NESTED_CALL`] until the walk passes the frame the
    /// handler named, then go on.
    Nested,
    /// The walk met a frame that is itself unwinding: take over that
    /// unwind's dispatcher context and go on from its frame.
    Collided,
    /// Raise this status as a new, non-continuable exception.
    Raise(u32),
}

/// The meaning of `disposition` while searching for a handler, for an
/// exception whose record carries `flags`.
pub fn after_search_handler(disposition: u32, flags: u32) -> Next {
    match disposition {
        EXCEPTION_CONTINUE_EXECUTION if flags & EXCEPTION_NONCONTINUABLE != 0 => {
            Next::Raise(STATUS_NONCONTINUABLE_EXCEPTION)
        }
        EXCEPTION_CONTINUE_EXECUTION => Next::Resume,
        EXCEPTION_CONTINUE_SEARCH => Next::NextFrame,
        EXCEPTION_NESTED_EXCEPTION => Next::Nested,
        EXCEPTION_COLLIDED_UNWIND_DISPOSITION => Next::Collided,
        _ => Next::Raise(STATUS_INVALID_DISPOSITION),
    }
}

/// The meaning of `disposition` while unwinding: a handler may only ask
/// to go on, or report a collision.
pub fn after_unwind_handler(disposition: u32) -> Next {
    match disposition {
        EXCEPTION_CONTINUE_SEARCH => Next::NextFrame,
        EXCEPTION_COLLIDED_UNWIND_DISPOSITION => Next::Collided,
        _ => Next::Raise(STATUS_INVALID_DISPOSITION),
    }
}

/// The meaning of a `__except` filter's value.
pub fn after_filter(value: i32) -> FilterResult {
    match value {
        ..0 => FilterResult::ContinueExecution,
        0 => FilterResult::ContinueSearch,
        _ => FilterResult::ExecuteHandler,
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FilterResult {
    /// `EXCEPTION_CONTINUE_EXECUTION`: resume the faulting code.
    ContinueExecution,
    /// `EXCEPTION_CONTINUE_SEARCH`: this `__except` declines.
    ContinueSearch,
    /// `EXCEPTION_EXECUTE_HANDLER`: unwind to the `__except` block.
    ExecuteHandler,
}

/// The flags the handler of the frame `establisher` sees during an
/// unwind to `target_frame` (`None`: an exit unwind, which has no
/// target). `flags` are the record's other flags.
pub fn unwind_flags(flags: u32, establisher: u64, target_frame: Option<u64>) -> u32 {
    let phase = match target_frame {
        None => EXCEPTION_UNWINDING | EXCEPTION_EXIT_UNWIND,
        Some(t) if t == establisher => EXCEPTION_UNWINDING | EXCEPTION_TARGET_UNWIND,
        Some(_) => EXCEPTION_UNWINDING,
    };
    (flags & !EXCEPTION_TARGET_UNWIND) | phase
}

/// Whether a frame may be used.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FrameCheck {
    Ok,
    /// Outside the stack or misaligned: stop the walk and mark the
    /// record [`EXCEPTION_STACK_INVALID`] ([`STATUS_BAD_STACK`] when
    /// unwinding).
    BadStack,
    /// The unwind walked past its target without meeting it:
    /// [`STATUS_INVALID_UNWIND_TARGET`].
    PastTarget,
}

/// Check the frame `establisher` against the stack `low..high` it must
/// lie in, and against the target of an unwind, which no frame may be
/// above. The stack grows down, so "past" is a higher address.
pub fn check_frame(establisher: u64, low: u64, high: u64, target_frame: Option<u64>) -> FrameCheck {
    if establisher < low || establisher >= high || establisher & 7 != 0 {
        FrameCheck::BadStack
    } else if target_frame.is_some_and(|t| t < establisher) {
        FrameCheck::PastTarget
    } else {
        FrameCheck::Ok
    }
}
