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

use crate::ke::{Rank, SpinLock, dpc, irql};
use crate::mm;
use crate::test::{Group, Report, Slot};
use core::ffi::c_void;
use nk_bootinfo::BootInfo;
use nk_ntabi::ke::KDPC;

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

/// Running off the end of the kernel stack must be reported as that, not
/// as silent corruption or an unexplained fault.
pub static STACK_OVERFLOW: Group = Group {
    names: &["neg.stack-overflow"],
    run: stack_overflow,
    manual: true,
};

/// Recurse without end. Each call keeps a buffer alive across the next,
/// so the compiler cannot turn the recursion into a loop.
#[inline(never)]
#[allow(unconditional_recursion, reason = "overflowing the stack is the test")]
fn descend(depth: u64) -> u64 {
    let mut pad = [depth as u8; 256];
    core::hint::black_box(&mut pad);
    descend(depth + 1) + u64::from(pad[0])
}

fn stack_overflow(r: &mut Report, _: &BootInfo) {
    kprintln!("NK-NEG-ARMED neg.stack-overflow");
    let depth = descend(0);
    r.fail(
        "neg.stack-overflow",
        format_args!("unbounded recursion returned {depth}"),
    );
}

/// The same in a DPC routine, which runs on its processor's DPC stack,
/// not on the thread's.
pub static DPC_STACK_OVERFLOW: Group = Group {
    names: &["neg.dpc-stack-overflow"],
    run: dpc_stack_overflow,
    manual: true,
};

fn dpc_stack_overflow(r: &mut Report, _: &BootInfo) {
    /// # Safety
    /// Called as a DPC routine; it dereferences none of its arguments.
    unsafe extern "C" fn routine(_: *mut KDPC, _: *mut c_void, _: *mut c_void, _: *mut c_void) {
        descend(0);
    }
    static DPC: Slot<KDPC> = Slot::new();
    kprintln!("NK-NEG-ARMED neg.dpc-stack-overflow");
    // SAFETY: static storage for a `KDPC`, not queued.
    unsafe {
        dpc::KeInitializeDpc(DPC.ptr(), Some(routine), core::ptr::null_mut());
        dpc::KeInsertQueueDpc(DPC.ptr(), core::ptr::null_mut(), core::ptr::null_mut());
    }
    r.fail(
        "neg.dpc-stack-overflow",
        format_args!("unbounded recursion in a DPC routine returned"),
    );
}

static LOW: SpinLock<()> = SpinLock::new(Rank::Pool, ());
static HIGH: SpinLock<()> = SpinLock::new(Rank::Frames, ());

/// Taking locks against their rank order must stop the system: two
/// processors doing it in opposite orders would each wait for the other.
pub static LOCK_ORDER: Group = Group {
    names: &["neg.lock-order"],
    run: lock_order,
    manual: true,
};

fn lock_order(r: &mut Report, _: &BootInfo) {
    kprintln!("NK-NEG-ARMED neg.lock-order");
    let _high = HIGH.lock();
    let _low = LOW.lock();
    r.fail(
        "neg.lock-order",
        format_args!("locks were taken out of rank order"),
    );
}

/// Taking a lock already held must stop the system rather than wait for
/// itself forever.
pub static LOCK_TWICE: Group = Group {
    names: &["neg.lock-twice"],
    run: lock_twice,
    manual: true,
};

fn lock_twice(r: &mut Report, _: &BootInfo) {
    kprintln!("NK-NEG-ARMED neg.lock-twice");
    let _first = LOW.lock();
    let _second = LOW.lock();
    r.fail(
        "neg.lock-twice",
        format_args!("a held lock was taken again"),
    );
}

/// "Lowering" the IRQL to a higher level must stop the system.
pub static IRQL_LOWER: Group = Group {
    names: &["neg.irql-lower"],
    run: irql_lower,
    manual: true,
};

fn irql_lower(r: &mut Report, _: &BootInfo) {
    kprintln!("NK-NEG-ARMED neg.irql-lower");
    irql::lower(irql::DISPATCH_LEVEL);
    r.fail(
        "neg.irql-lower",
        format_args!("the IRQL was lowered upward"),
    );
}

/// A breakpoint executed as a driver's `DbgBreakPoint` would execute it:
/// with no debugger, the system must stop, as Windows does.
pub static BREAKPOINT: Group = Group {
    names: &["neg.breakpoint"],
    run: breakpoint,
    manual: true,
};

fn breakpoint(r: &mut Report, _: &BootInfo) {
    kprintln!("NK-NEG-ARMED neg.breakpoint");
    crate::arch::driver_breakpoint();
    // With `debug=on` a debugger is taken to be attached and to say go:
    // then getting here is right, and the scenario expects it.
    r.ok("neg.breakpoint");
}
