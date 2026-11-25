//! Tests that are supposed to go wrong.
//!
//! A test suite that cannot fail proves nothing, so these check the
//! machinery itself: that a kernel bug stops the machine with a bugcheck
//! the harness sees, and that a failing test is reported as one. Each is
//! `manual`: it runs only in a boot that asks for it by name, and that
//! boot's scenario (`tools/scenarios.toml`) states the expected outcome.
//!
//! Before provoking a bugcheck a test prints `NK-NEG-ARMED <name>`. The
//! judge accepts a bugcheck only after that line, so a crash on the way
//! to the test is not mistaken for the one the test meant to cause.

use crate::mm;
use crate::test::{Group, Report};
use nk_bootinfo::BootInfo;

/// A Rust panic in the kernel must become a bugcheck.
pub static PANIC: Group = Group {
    names: &["neg.panic"],
    run: panic,
    manual: true,
};

fn panic(_: &mut Report, _: &BootInfo) {
    kprintln!("NK-NEG-ARMED neg.panic");
    panic!("neg.panic: deliberate panic");
}

/// A stray memory access in kernel mode must become a bugcheck.
pub static FAULT: Group = Group {
    names: &["neg.fault"],
    run: fault,
    manual: true,
};

fn fault(r: &mut Report, _: &BootInfo) {
    // Address space that is reserved but has nothing mapped in it.
    let Some(va) = mm::map::alloc_va(1) else {
        return r.fail("neg.fault", format_args!("no kernel address space"));
    };
    kprintln!("NK-NEG-ARMED neg.fault");
    // SAFETY: not safe, by design: the read must fault. The kernel
    // bugchecks in the fault handler and never returns here.
    let byte = unsafe { (va as *const u8).read_volatile() };
    r.fail(
        "neg.fault",
        format_args!("read of unmapped {va:#x} returned {byte:#x}"),
    );
}

/// A test that fails. The harness must report the boot as failed.
pub static META_FAIL: Group = Group {
    names: &["meta.fail"],
    run: meta_fail,
    manual: true,
};

fn meta_fail(r: &mut Report, _: &BootInfo) {
    r.fail("meta.fail", format_args!("deliberate failure"));
}
