//! Tests of the kernel's own foundations: processor state, memory and
//! the description of the machine.

use crate::test::{Group, Report};
use crate::{arch, hal, ke, mm};
use nk_bootinfo::BootInfo;

pub static GROUP: Group = Group {
    names: &[
        "boot",
        "cpu.pcr",
        "cpu.breakpoint",
        "cpu.fp-preserved",
        "ke.irql-and-locks",
        "ke.interrupts",
        "ke.entropy.register-race",
        "mm.frames",
        "mm.map",
        "mm.low-half",
        "mm.user.map",
        "mm.user.refused",
        "mm.user.other-cpu",
        "mm.user.copy",
        "mm.pool",
        "mm.stack",
        "hal.cpus",
    ],
    run,
    manual: false,
};

fn run(r: &mut Report, info: &BootInfo) {
    r.check("boot", || {
        if info.is_valid() {
            Ok(())
        } else {
            Err("BootInfo magic/version mismatch")
        }
    });
    r.check("cpu.pcr", ke::pcr::self_test);
    r.check("cpu.breakpoint", ke::trap_self_test);
    r.check("cpu.fp-preserved", arch::fp_trap_test);
    r.check("ke.irql-and-locks", ke::irql::self_test);
    r.check("ke.interrupts", ke::interrupt::self_test);
    r.check("ke.entropy.register-race", ke::entropy::self_test);
    r.check("mm.frames", mm::frames_self_test);
    r.check("mm.map", mm::map::self_test);
    match mm::map::low_half_test() {
        Ok(n) => r.ok_with("mm.low-half", format_args!("{n} firmware regions")),
        Err(why) => r.fail("mm.low-half", format_args!("{why}")),
    }
    r.check("mm.user.map", mm::user::map_test);
    r.check("mm.user.refused", mm::user::refuse_test);
    match mm::user::other_cpu_test() {
        Ok(n) => r.ok_with("mm.user.other-cpu", format_args!("read on processor {n}")),
        Err(why) => r.fail("mm.user.other-cpu", format_args!("{why}")),
    }
    r.check("mm.user.copy", mm::user::copy_test);
    r.check("mm.pool", mm::pool::self_test);
    r.check("mm.stack", mm::stack::self_test);
    match hal::platform::self_test(info) {
        Ok(n) => r.ok_with("hal.cpus", format_args!("{n} processors")),
        Err(why) => r.fail("hal.cpus", format_args!("{why}")),
    }
}

/// This file's test groups, in the order they run.
pub static GROUPS: &[&Group] = &[&GROUP];
