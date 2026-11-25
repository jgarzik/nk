//! Kernel events (`KEVENT`), as far as a kernel without threads needs
//! them: they can be initialised, set and tested, but nothing can wait.

use nk_ntabi::io::{EVENT_NOTIFICATION, KEVENT};

/// Initialise an event in place, as `KeInitializeEvent` does.
///
/// # Safety
/// `event` must point to writable memory for a `KEVENT`.
pub unsafe fn init(event: *mut KEVENT, kind: u8, signaled: bool) {
    // SAFETY: per the contract. The wait list is an empty circular list.
    unsafe {
        let head = &raw mut (*event).Header.WaitListHead;
        (*event).Header.Type = kind;
        (*event).Header.Signalling = 0;
        (*event).Header.Size = (size_of::<KEVENT>() / 4) as u8;
        (*event).Header.Reserved1 = 0;
        (*event).Header.SignalState = i32::from(signaled);
        (*head).Flink = head;
        (*head).Blink = head;
    }
}

/// A notification event, not signaled, for a caller's stack.
pub fn new_notification() -> KEVENT {
    // SAFETY: an all-zero KEVENT is a valid bit pattern (integers and
    // null pointers); `init` then gives it its real contents.
    let mut event: KEVENT = unsafe { core::mem::zeroed() };
    // SAFETY: `event` is a local, writable KEVENT. Its list head is
    // re-linked by whoever moves it; nothing waits, so it is never walked.
    unsafe { init(&raw mut event, EVENT_NOTIFICATION, false) };
    event
}

/// Signal an event, as `KeSetEvent` does when nothing is waiting.
///
/// # Safety
/// `event` must point to an initialised `KEVENT`.
pub unsafe fn set(event: *mut KEVENT) {
    // SAFETY: per the contract.
    unsafe { (&raw mut (*event).Header.SignalState).write_volatile(1) };
}

/// # Safety
/// `event` must point to an initialised `KEVENT`.
pub unsafe fn is_signaled(event: *const KEVENT) -> bool {
    // SAFETY: per the contract.
    unsafe { (&raw const (*event).Header.SignalState).read_volatile() != 0 }
}
