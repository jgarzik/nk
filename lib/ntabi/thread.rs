//! The thread object (`KTHREAD` inside `ETHREAD`).
//!
//! Drivers built with the public headers treat a thread as opaque: they
//! get its address from the processor control region and pass it back.
//! Microsoft's own drivers are built with private headers and read some
//! fields directly, so NK keeps what it maintains at Windows' offsets.
//! The x86-64 offsets are checked against the public symbols of the
//! pinned kernel build (`pdb.rs`). On arm64, where no Microsoft binary
//! is available to read them, NK uses the same numbers.
//!
//! Only the fields NK maintains are named.

/// Size of `ETHREAD`, which begins with the `KTHREAD`.
pub const ETHREAD_SIZE: usize = 0x898;
/// Size of `KTHREAD`.
pub const KTHREAD_SIZE: usize = 0x430;

/// `KTHREAD.Header.Type` of a thread: `ThreadObject`.
pub const THREAD_OBJECT: u8 = 6;

/// `InitialStack`: the top of the kernel stack.
pub const INITIAL_STACK: usize = 0x28;
/// `StackLimit`: the lowest address of the kernel stack.
pub const STACK_LIMIT: usize = 0x30;
/// `StackBase`: the top of the kernel stack.
pub const STACK_BASE: usize = 0x38;
/// `KernelStack`: the saved stack pointer of a thread that is not
/// running.
pub const KERNEL_STACK: usize = 0x58;
/// `Running`: one byte, non-zero while a processor is on this thread's
/// stack.
pub const RUNNING: usize = 0x71;
/// `Priority`: the current priority, one signed byte.
pub const PRIORITY: usize = 0xC3;
/// `WaitListEntry`: links the thread into a ready queue.
pub const WAIT_LIST_ENTRY: usize = 0xD8;
/// `State`: one byte, a `KTHREAD_STATE`.
pub const STATE: usize = 0x184;
/// `NextProcessor`: the processor whose ready queue the thread uses.
pub const NEXT_PROCESSOR: usize = 0x218;
/// `BasePriority`: one signed byte.
pub const BASE_PRIORITY: usize = 0x233;
/// `ETHREAD.StartAddress`.
pub const START_ADDRESS: usize = 0x450;

/// `KTHREAD_STATE`.
pub mod state {
    pub const INITIALIZED: u8 = 0;
    pub const READY: u8 = 1;
    pub const RUNNING: u8 = 2;
    pub const TERMINATED: u8 = 4;
}
