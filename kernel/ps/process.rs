//! The System process: the one process there is.
//!
//! Every thread belongs to it. Its block has `EPROCESS`'s size and
//! Windows' layout for the fields NK keeps; the rest is zero. It is made
//! before the first thread and never goes away, so threads point at it
//! without counting references.

use crate::ob::object;
use core::sync::atomic::{AtomicPtr, AtomicU64, Ordering};
use nk_ntabi::process as layout;

static SYSTEM: AtomicPtr<u8> = AtomicPtr::new(core::ptr::null_mut());

/// The next thread id. Process and thread ids come from one sequence
/// of multiples of four, as on Windows; the System process has the
/// first.
static NEXT_ID: AtomicU64 = AtomicU64::new(layout::SYSTEM_PROCESS_ID + 4);

/// Make the System process, created at `time` (system time).
pub fn init(time: u64) -> Result<(), &'static str> {
    let process = object::create(&object::PROCESS_TYPE, layout::EPROCESS_SIZE)
        .ok_or("no memory for the System process")?;
    // SAFETY: a fresh, zeroed object of a process's size, which the pool
    // aligns to 16 bytes; nothing else has it yet.
    unsafe {
        process.write(layout::PROCESS_OBJECT);
        process
            .add(layout::UNIQUE_PROCESS_ID)
            .cast::<u64>()
            .write(layout::SYSTEM_PROCESS_ID);
        process.add(layout::CREATE_TIME).cast::<u64>().write(time);
        process
            .add(layout::IMAGE_FILE_NAME)
            .copy_from_nonoverlapping(b"System".as_ptr(), 6);
    }
    SYSTEM.store(process, Ordering::Release);
    Ok(())
}

/// The System process object.
pub fn system() -> *mut u8 {
    SYSTEM.load(Ordering::Acquire)
}

/// An id for a new thread.
pub fn new_thread_id() -> u64 {
    NEXT_ID.fetch_add(4, Ordering::Relaxed)
}

// ---- tests --------------------------------------------------------------

/// The System process as a binary reading it would find it, and the
/// calling thread's place in it.
pub fn self_test() -> Result<(), &'static str> {
    use crate::ob::handle;
    use nk_ntabi::thread as thread_layout;
    let process = system();
    let thread = crate::ke::thread::current().cast::<u8>();
    // SAFETY: the process is live for ever and the running thread for
    // the duration; the offsets are inside their blocks and aligned.
    let (kind, id, name, owner, attached, client) = unsafe {
        (
            process.read(),
            process.add(layout::UNIQUE_PROCESS_ID).cast::<u64>().read(),
            process
                .add(layout::IMAGE_FILE_NAME)
                .cast::<[u8; 7]>()
                .read(),
            thread.add(thread_layout::PROCESS).cast::<*mut u8>().read(),
            thread
                .add(thread_layout::APC_STATE_PROCESS)
                .cast::<*mut u8>()
                .read(),
            thread.add(thread_layout::CID).cast::<[u64; 2]>().read(),
        )
    };
    if kind != layout::PROCESS_OBJECT || id != layout::SYSTEM_PROCESS_ID || &name != b"System\0" {
        return Err("the System process does not say what it is");
    }
    if owner != process || attached != process {
        return Err("the running thread does not belong to the System process");
    }
    if client[0] != layout::SYSTEM_PROCESS_ID || client[1] <= id || client[1] % 4 != 0 {
        return Err("the running thread's client id is not a System thread's");
    }
    // `NtCurrentProcess()` names it, and only as a process.
    let current = -1i64 as u64;
    match handle::reference(current, Some(&raw const object::PROCESS_TYPE)) {
        Ok(body) if body == process => {
            // SAFETY: the reference the look-up took.
            unsafe { object::dereference(body) };
        }
        Ok(_) => return Err("NtCurrentProcess names another object"),
        Err(_) => return Err("NtCurrentProcess names nothing"),
    }
    if handle::reference(current, Some(&raw const object::THREAD_TYPE)).is_ok() {
        return Err("NtCurrentProcess was accepted as a thread");
    }
    Ok(())
}
