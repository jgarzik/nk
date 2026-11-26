//! The System process: the one process there is.
//!
//! Every thread belongs to it. Its block has `EPROCESS`'s size and
//! Windows' layout for the fields NK keeps; the rest is zero. It is made
//! before the first thread and never goes away, so threads point at it
//! without counting references. It holds the SYSTEM token
//! (`se::token`), the only token there is.

#![allow(non_snake_case, non_upper_case_globals)]

use crate::ke::thread;
use crate::ob::object;
use core::ffi::c_void;
use core::sync::atomic::{AtomicPtr, AtomicU64, Ordering};
use nk_ntabi::process as layout;
use nk_ntabi::thread as thread_layout;

/// A variable a driver imports that holds a process: the import is
/// bound to its address, and the driver reads the pointer.
#[repr(transparent)]
pub struct ProcessVariable(AtomicPtr<u8>);

impl ProcessVariable {
    /// The address drivers import.
    pub const fn address(&'static self) -> *const () {
        core::ptr::from_ref(self).cast()
    }
}

/// `PsInitialSystemProcess` (`ntddk.h`):
/// the System process. Written once, before the first thread and long
/// before the first driver.
pub static PsInitialSystemProcess: ProcessVariable =
    ProcessVariable(AtomicPtr::new(core::ptr::null_mut()));

/// The next thread id. Process and thread ids come from one sequence
/// of multiples of four, as on Windows; the System process has the
/// first.
static NEXT_ID: AtomicU64 = AtomicU64::new(layout::SYSTEM_PROCESS_ID + 4);

/// Make the System process, created at `time` (system time).
pub fn init(time: u64) -> Result<(), &'static str> {
    let process = object::create(&object::PROCESS_TYPE, layout::EPROCESS_SIZE)
        .ok_or("no memory for the System process")?;
    let token = crate::se::token::create(nk_se::token::Token::system())
        .ok_or("no memory for the System process's token")?;
    // SAFETY: a fresh, zeroed object of a process's size, which the pool
    // aligns to 16 bytes; nothing else has it yet.
    unsafe {
        // An `EX_FAST_REF`. Its count bits stay zero: NK hands out no
        // references in advance, every one is taken from the object.
        process.add(layout::TOKEN).cast::<*mut u8>().write(token);
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
    PsInitialSystemProcess.0.store(process, Ordering::Release);
    Ok(())
}

/// The System process object.
pub fn system() -> *mut u8 {
    PsInitialSystemProcess.0.load(Ordering::Acquire)
}

/// The System process's primary token, with a reference for the caller
/// to drop (`object::dereference`).
pub fn reference_primary_token() -> *mut u8 {
    // SAFETY: the System process, which lives for ever.
    unsafe { PsReferencePrimaryToken(system().cast()).cast() }
}

/// [`PsGetCurrentProcess`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntddk/nf-ntddk-psgetcurrentprocess):
/// the process whose address space the calling thread is in, which is
/// what the thread says it is attached to (`ApcState.Process`). The
/// kit's headers turn the name into `IoGetCurrentProcess`; Microsoft's
/// own drivers import this one.
pub extern "C" fn PsGetCurrentProcess() -> *mut c_void {
    // SAFETY: the running thread's block; the field is pointer-aligned
    // and only the thread itself changes it.
    unsafe {
        thread::object_field::<*mut c_void>(thread::current(), thread_layout::APC_STATE_PROCESS)
            .read()
    }
}

/// [`IoGetCurrentProcess`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-iogetcurrentprocess):
/// [`PsGetCurrentProcess`] by its documented name.
pub extern "C" fn IoGetCurrentProcess() -> *mut c_void {
    PsGetCurrentProcess()
}

/// [`PsReferencePrimaryToken`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-psreferenceprimarytoken):
/// the process's primary token, with a reference the caller gives up
/// through [`PsDereferencePrimaryToken`]. The token is read out of the
/// process's fast reference (`EPROCESS.Token`), whose count bits are
/// not part of the pointer; every reference is taken on the token
/// itself.
///
/// # Safety
/// `process` is a process object.
pub unsafe extern "C" fn PsReferencePrimaryToken(process: *mut c_void) -> *mut c_void {
    // SAFETY: per the contract: a process holds its token for as long
    // as it lives, at a pointer-aligned offset; the field is written
    // once, when the process is made.
    unsafe {
        let field = process
            .cast::<u8>()
            .add(layout::TOKEN)
            .cast::<usize>()
            .read();
        let token = (field & !layout::FAST_REF_COUNT_MASK) as *mut u8;
        object::reference(token);
        token.cast()
    }
}

/// [`PsDereferencePrimaryToken`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-psdereferenceprimarytoken):
/// give up a reference [`PsReferencePrimaryToken`] took. The kit's
/// headers turn the name into `ObDereferenceObject`; Microsoft's own
/// drivers import this one.
///
/// # Safety
/// `token` came from [`PsReferencePrimaryToken`] and the caller owns
/// that reference.
pub unsafe extern "C" fn PsDereferencePrimaryToken(token: *mut c_void) {
    // SAFETY: per the contract.
    unsafe { object::dereference(token.cast()) };
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
    let process = system();
    // What a driver reads from the variable it imports, and what the
    // two names for "the current process" give it.
    // SAFETY: the variable is a pointer-sized static.
    let imported = unsafe { PsInitialSystemProcess.address().cast::<*mut u8>().read() };
    if imported != process || process.is_null() {
        return Err("PsInitialSystemProcess does not hold the System process");
    }
    if PsGetCurrentProcess() != process.cast() || IoGetCurrentProcess() != process.cast() {
        return Err("the current process is not the System process");
    }
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

/// How many references `body` has, the caller's own included.
///
/// # Safety
/// `body` is an object the caller holds a reference to.
unsafe fn references(body: *mut u8) -> i64 {
    // SAFETY: per the contract.
    unsafe {
        object::reference(body);
        object::dereference(body)
    }
}

static TOKEN_WRONG: core::sync::atomic::AtomicU32 = core::sync::atomic::AtomicU32::new(0);

/// The primary token is handed out referenced and given back, by one
/// thread and by threads on every processor at once: the same token
/// each time, a token object, with no reference lost or left. Returns
/// the references taken.
pub fn token_test() -> Result<u32, &'static str> {
    const ROUNDS: u32 = 2000;
    fn body(expected: usize) {
        for _ in 0..ROUNDS {
            // SAFETY: the System process; the reference taken is the
            // one given up.
            unsafe {
                let token = PsReferencePrimaryToken(system().cast());
                if token.addr() != expected {
                    TOKEN_WRONG.fetch_add(1, Ordering::Relaxed);
                }
                PsDereferencePrimaryToken(token);
            }
        }
    }
    let process = system();
    // SAFETY: the System process and its token live for ever; every
    // reference this takes it gives up.
    unsafe {
        let field = process.add(layout::TOKEN).cast::<usize>().read();
        let token = PsReferencePrimaryToken(process.cast()).cast::<u8>();
        if token.is_null()
            || token.addr() != field & !layout::FAST_REF_COUNT_MASK
            || !core::ptr::eq(object::type_of(token), &raw const object::TOKEN_TYPE)
        {
            return Err("the primary token is not the token object the process holds");
        }
        let held = references(token);
        let again = PsReferencePrimaryToken(process.cast()).cast::<u8>();
        if again != token || references(token) != held + 1 {
            return Err("a second reference to the primary token was not counted");
        }
        PsDereferencePrimaryToken(again.cast());
        if references(token) != held {
            return Err("a reference to the primary token was not given back");
        }
        TOKEN_WRONG.store(0, Ordering::Relaxed);
        let threads_before = thread::count();
        let processors = crate::ke::smp::online_count();
        let threads = processors.max(2);
        for n in 0..threads {
            thread::create(
                body,
                token.addr(),
                thread::NORMAL_PRIORITY,
                1 << (n % processors),
            )?;
        }
        let deadline = crate::ke::time::interrupt_time() + 100_000_000;
        while thread::count() != threads_before && crate::ke::time::interrupt_time() < deadline {
            thread::yield_now();
        }
        if thread::count() != threads_before {
            return Err("the threads did not finish");
        }
        let left = references(token);
        PsDereferencePrimaryToken(token.cast());
        if TOKEN_WRONG.load(Ordering::Relaxed) != 0 {
            return Err("a thread was handed another token");
        }
        if left != held {
            return Err("references taken on several processors were lost or left behind");
        }
        Ok(threads as u32 * ROUNDS + 2)
    }
}
