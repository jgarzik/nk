//! One-time initialisation: `RtlRunOnceExecuteOnce`. The word is the
//! driver's and its values are `nk_rtl::once`'s; here the driver's
//! initialisation routine is called, once, and the threads that arrive
//! meanwhile wait.
//!
//! A thread that finds the initialisation under way sleeps a
//! millisecond and looks again, where Windows queues it on the word.
//! The routine is for below `DISPATCH_LEVEL`.

#![allow(non_snake_case)]

use crate::ke::seh::{self, Guard};
use crate::ke::wait;
use core::ffi::c_void;
use core::sync::atomic::{AtomicUsize, Ordering};
use nk_ntabi::status::*;
use nk_rtl::once::{self, Begin};

/// The word of a driver's `RTL_RUN_ONCE`.
///
/// # Safety
/// `run_once` points to a live, aligned `RTL_RUN_ONCE`.
unsafe fn word<'a>(run_once: *mut usize) -> &'a AtomicUsize {
    // SAFETY: per the contract; other threads read and write it.
    unsafe { AtomicUsize::from_ptr(run_once) }
}

/// What is owed if the initialisation routine does not return: the
/// word is new again, so that the threads waiting are not left waiting
/// and one of them tries.
///
/// # Safety
/// `run_once` is the `RTL_RUN_ONCE` the unwound call was running.
unsafe fn abandoned(run_once: *mut c_void) {
    // SAFETY: per the contract.
    unsafe { word(run_once.cast()) }.store(once::NEW, Ordering::Release);
}

/// [`RtlRunOnceExecuteOnce`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntddk/nf-ntddk-rtlrunonceexecuteonce):
/// run `init_fn(run_once, parameter, context)` unless it has already
/// run and succeeded, and wait for it if another thread is running it.
/// `STATUS_SUCCESS` with the context it left; `STATUS_UNSUCCESSFUL` if
/// it failed, after which the next caller runs it again. A context
/// whose low two bits are not clear cannot be recorded:
/// `STATUS_INVALID_PARAMETER_2`, and the word is as if nothing had run.
///
/// # Safety
/// `run_once` points to an initialised `RTL_RUN_ONCE`; `init_fn` is an
/// `RTL_RUN_ONCE_INIT_FN`; `context` is null or writable.
pub unsafe extern "C" fn RtlRunOnceExecuteOnce(
    run_once: *mut usize,
    init_fn: *const c_void,
    parameter: *mut c_void,
    context: *mut *mut c_void,
) -> NTSTATUS {
    // SAFETY: per the contract throughout.
    unsafe {
        let word = word(run_once);
        loop {
            match once::begin(word.load(Ordering::Acquire)) {
                Begin::Done(left) => {
                    if !context.is_null() {
                        context.write_unaligned(core::ptr::with_exposed_provenance_mut(left));
                    }
                    return STATUS_SUCCESS;
                }
                Begin::Wait => {
                    wait::wait(None, Some(-10_000));
                }
                Begin::Run => {
                    if word
                        .compare_exchange(
                            once::NEW,
                            once::RUNNING,
                            Ordering::AcqRel,
                            Ordering::Acquire,
                        )
                        .is_err()
                    {
                        continue;
                    }
                    // The driver's routine, with nothing held but the
                    // word, which is given back if it does not return.
                    let succeeded = seh::call(
                        init_fn.addr(),
                        [run_once.addr(), parameter.addr(), context.addr(), 0],
                        &Guard::Undo {
                            undo: abandoned,
                            context: run_once.cast(),
                        },
                    ) as u32
                        != 0;
                    let left = if succeeded && !context.is_null() {
                        context.read_unaligned().expose_provenance()
                    } else {
                        0
                    };
                    let (after, status) = match once::done(left) {
                        _ if !succeeded => (once::NEW, STATUS_UNSUCCESSFUL),
                        Some(done) => (done, STATUS_SUCCESS),
                        None => (once::NEW, STATUS_INVALID_PARAMETER_2),
                    };
                    word.store(after, Ordering::Release);
                    return status;
                }
            }
        }
    }
}

/// How often the test's routine has run.
static RUNS: AtomicUsize = AtomicUsize::new(0);

/// An `RTL_RUN_ONCE_INIT_FN` for the test: fails if its parameter is
/// zero, and otherwise leaves the parameter as the context.
extern "C" fn initialise(_: *mut usize, parameter: *mut c_void, context: *mut *mut c_void) -> u32 {
    RUNS.fetch_add(1, Ordering::AcqRel);
    if parameter.is_null() {
        return 0;
    }
    if !context.is_null() {
        // SAFETY: the test passes a pointer to a local.
        unsafe { context.write(parameter) };
    }
    1
}

/// The routine runs until it succeeds and never again, and every caller
/// gets the context it left. Returns the times it ran.
pub fn self_test() -> Result<u32, &'static str> {
    RUNS.store(0, Ordering::Release);
    let mut storage: usize = 0;
    let once = &raw mut storage;
    let mut context = core::ptr::null_mut::<c_void>();
    let routine = initialise as *const c_void;
    let number = |n: usize| core::ptr::without_provenance_mut::<c_void>(n);
    // SAFETY: the word and the context are locals.
    unsafe {
        let run = |parameter: *mut c_void, context: *mut *mut c_void| {
            RtlRunOnceExecuteOnce(once, routine, parameter, context)
        };
        if run(number(0), &raw mut context) != STATUS_UNSUCCESSFUL || once.read() != 0 {
            return Err("a failed initialisation did not leave the word new");
        }
        // A context with a low bit set cannot be kept.
        if run(number(0x1001), &raw mut context) != STATUS_INVALID_PARAMETER_2 || once.read() != 0 {
            return Err("a context with a low bit set was recorded");
        }
        if run(number(0x1000), &raw mut context) != STATUS_SUCCESS
            || context != number(0x1000)
            || once.read() != 0x1002
        {
            return Err("a successful initialisation did not leave its context in the word");
        }
        context = core::ptr::null_mut();
        if run(number(0x2000), &raw mut context) != STATUS_SUCCESS
            || context != number(0x1000)
            || run(number(0), core::ptr::null_mut()) != STATUS_SUCCESS
        {
            return Err("an initialisation already done was not answered with its context");
        }
    }
    match RUNS.load(Ordering::Acquire) {
        3 => Ok(3),
        _ => Err("the initialisation routine ran again after it had succeeded"),
    }
}
