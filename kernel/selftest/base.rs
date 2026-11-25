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
        "mm.frames",
        "mm.map",
        "mm.pool",
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
    r.check("mm.frames", mm::frames_self_test);
    r.check("mm.map", mm::map::self_test);
    r.check("mm.pool", mm::pool::self_test);
    match hal::platform::self_test(info) {
        Ok(n) => r.ok_with("hal.cpus", format_args!("{n} processors")),
        Err(why) => r.fail("hal.cpus", format_args!("{why}")),
    }
}
