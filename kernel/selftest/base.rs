//! Tests of the kernel's own foundations: processor state and memory.

use crate::test::{Group, Report};
use crate::{ke, mm};
use nk_bootinfo::BootInfo;

pub static GROUP: Group = Group {
    names: &[
        "boot",
        "cpu.pcr",
        "cpu.breakpoint",
        "mm.frames",
        "mm.map",
        "mm.pool",
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
    r.check("mm.frames", mm::frames_self_test);
    r.check("mm.map", mm::map::self_test);
    r.check("mm.pool", mm::pool::self_test);
}
