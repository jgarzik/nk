//! Tests of kernel stack expansion: a file system's request switches to
//! a segment, a small one does not, and an exception raised on a
//! segment is handled beneath the switch, however often.

use super::except;
use crate::ke::{expand, thread};
use crate::test::{Group, Report};
use core::ffi::c_void;
use core::sync::atomic::{AtomicU32, Ordering};
use nk_bootinfo::BootInfo;

pub static GROUP: Group = Group {
    names: &[
        "ke.expand.switch",
        "ke.expand.inline",
        "ke.expand.raise",
        "ke.expand.unwind-reuse",
        "ke.expand.raise-repeated",
    ],
    run,
    manual: false,
};

pub static GROUPS: &[&Group] = &[&GROUP];

fn run(r: &mut Report, _: &BootInfo) {
    r.check("ke.expand.switch", expand::switch_test);
    r.check("ke.expand.inline", expand::inline_test);
    r.check("ke.expand.raise", || {
        except::raises(
            expand::raise_on_segment,
            except::CODE as usize,
            except::CODE,
        )?;
        expand::after_raise_test()
    });
    r.check("ke.expand.unwind-reuse", || {
        except::raises(
            expand::raise_expanding_in_unwind,
            except::CODE as usize,
            except::CODE,
        )?;
        expand::unwind_reuse_test()
    });
    r.check("ke.expand.raise-repeated", raise_repeated);
}

/// Raises on a segment caught on the segment beneath it.
static CAUGHT: AtomicU32 = AtomicU32::new(0);

/// More times than a thread can run on segments: expand from this
/// segment, raise there, catch it here.
///
/// # Safety
/// Takes any parameter.
unsafe extern "C" fn raise_from_segment_repeatedly(_: *mut c_void) {
    for _ in 0..=thread::MAX_SEGMENTS {
        if except::raises(
            expand::raise_on_segment,
            except::CODE as usize,
            except::CODE,
        )
        .is_ok()
        {
            CAUGHT.fetch_add(1, Ordering::Relaxed);
        }
    }
}

/// A callout on a segment that again and again expands, raises on the
/// new segment and catches the exception on its own: each segment the
/// unwinds leave is given back once nothing runs on it, so the thread
/// never runs out of them.
fn raise_repeated() -> Result<(), &'static str> {
    CAUGHT.store(0, Ordering::Relaxed);
    // SAFETY: the callout takes any parameter.
    let status = unsafe {
        expand::KeExpandKernelStackAndCalloutEx(
            raise_from_segment_repeatedly,
            core::ptr::null_mut(),
            0x6000,
            1,
            core::ptr::null_mut(),
        )
    };
    if status != 0 || CAUGHT.load(Ordering::Relaxed) != thread::MAX_SEGMENTS as u32 + 1 {
        return Err("repeated raises on segments were not each caught beneath the switch");
    }
    expand::after_raise_test()
}
