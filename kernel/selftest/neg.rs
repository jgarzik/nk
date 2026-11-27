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

/// A null pointer must fault: nothing of firmware's or anyone's is
/// mapped at the bottom of the address space.
pub static NULL: Group = Group {
    names: &["neg.null"],
    run: null,
    manual: true,
};

fn null(r: &mut Report, _: &BootInfo) {
    kprintln!("NK-NEG-ARMED neg.null");
    // SAFETY: not safe, by design: the read must fault. The address is
    // hidden from the compiler, which knows a null read cannot happen.
    let byte = unsafe { core::hint::black_box(core::ptr::null::<u8>()).read_volatile() };
    r.fail(
        "neg.null",
        format_args!("read of address zero returned {byte:#x}"),
    );
}

/// Ordinary memory must not be readable at its physical address: the
/// low half holds firmware's runtime regions and nothing else, where
/// firmware's own map had all of memory.
pub static LOW_MEMORY: Group = Group {
    names: &["neg.low-memory"],
    run: low_memory,
    manual: true,
};

fn low_memory(r: &mut Report, _: &BootInfo) {
    let Some(frame) = mm::alloc_frames(1) else {
        return r.fail("neg.low-memory", format_args!("no frames"));
    };
    kprintln!("NK-NEG-ARMED neg.low-memory");
    // SAFETY: not safe, by design: the read must fault.
    let byte = unsafe { (frame as *const u8).read_volatile() };
    mm::free_frames(frame, 1);
    r.fail(
        "neg.low-memory",
        format_args!("read of memory at its physical address {frame:#x} returned {byte:#x}"),
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

/// Kernel code closing a kernel handle that is protected from close
/// must stop the system, as on Windows; user mode is only refused.
pub static PROTECTED_CLOSE: Group = Group {
    names: &["neg.protected-close"],
    run: protected_close,
    manual: true,
};

fn protected_close(r: &mut Report, _: &BootInfo) {
    let why = crate::ob::handle::protected_close_test(|| {
        kprintln!("NK-NEG-ARMED neg.protected-close");
    });
    r.fail("neg.protected-close", format_args!("{why}"));
}

/// A routine NK exports as a trap must stop the system naming itself
/// when a driver calls it: a driver that reaches one is not let go on
/// with an answer NK never worked out.
pub static TRAP: Group = Group {
    names: &["neg.trap"],
    run: trap,
    manual: true,
};

/// Call `ZwCreateIoCompletion` as `msrpc.sys` would: through the
/// address its import of the name is bound to, with the routine's four
/// arguments.
fn trap(r: &mut Report, _: &BootInfo) {
    let Some(bound) = crate::export::resolve(b"ntoskrnl.exe", b"ZwCreateIoCompletion") else {
        return r.fail(
            "neg.trap",
            format_args!("ZwCreateIoCompletion is not exported"),
        );
    };
    type CreateIoCompletion = unsafe extern "C" fn(*mut *mut c_void, u32, *mut c_void, u32) -> i32;
    // SAFETY: the address of a function of the driver calling
    // convention, which is what the export table holds for a name.
    let routine = unsafe { core::mem::transmute::<usize, CreateIoCompletion>(bound as usize) };
    let mut port = core::ptr::null_mut();
    const IO_COMPLETION_ALL_ACCESS: u32 = 0x001F_0003;
    kprintln!("NK-NEG-ARMED neg.trap");
    // SAFETY: the routine's documented arguments; a trap reads none.
    let status = unsafe {
        routine(
            &raw mut port,
            IO_COMPLETION_ALL_ACCESS,
            core::ptr::null_mut(),
            0,
        )
    };
    r.fail(
        "neg.trap",
        format_args!("a trap returned {status:#x} and handle {port:p}"),
    );
}

/// This file's test groups, in the order they run.
/// A fatal hardware error reported to the HAL must stop the system as
/// Windows stops for one.
pub static HARDWARE_ERROR: Group = Group {
    names: &["neg.hardware-error"],
    run: hardware_error,
    manual: true,
};

fn hardware_error(_: &mut Report, _: &BootInfo) {
    kprintln!("NK-NEG-ARMED neg.hardware-error");
    crate::hal::fatal::stop_test()
}

/// Releasing system address space a mapping does not hold
/// (`MmUnmapIoSpace` of more pages than were mapped) must stop the
/// system as Windows' `MiReleasePtes` does: `SYSTEM_PTE_MISUSE`, 0x302.
pub static UNMAP_IO_SPACE: Group = Group {
    names: &["neg.unmap-io-space"],
    run: unmap_io_space,
    manual: true,
};

fn unmap_io_space(r: &mut Report, _: &BootInfo) {
    // A page of RAM, mapped for one page and unmapped for two: the
    // second page was never the mapping's.
    let va = crate::mm::io::MmMapIoSpaceEx(0x10_0000, 4096, 0x04);
    if va.is_null() {
        return r.fail(
            "neg.unmap-io-space",
            format_args!("the page could not be mapped"),
        );
    }
    kprintln!("NK-NEG-ARMED neg.unmap-io-space");
    crate::mm::io::MmUnmapIoSpace(va, 2 * 4096);
    r.fail(
        "neg.unmap-io-space",
        format_args!("an unmapping of pages never mapped returned"),
    );
}

pub static GROUPS: &[&Group] = &[
    &PANIC,
    &UNMAP_IO_SPACE,
    &HARDWARE_ERROR,
    &FAULT,
    &NULL,
    &LOW_MEMORY,
    &STACK_OVERFLOW,
    &DPC_STACK_OVERFLOW,
    &LOCK_ORDER,
    &LOCK_TWICE,
    &IRQL_LOWER,
    &META_FAIL,
    &BREAKPOINT,
    &PROTECTED_CLOSE,
    &TRAP,
];
