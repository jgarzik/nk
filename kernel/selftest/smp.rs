//! Tests of running on every processor.

use crate::ke::smp;
use crate::test::{Group, Report};
use nk_bootinfo::BootInfo;

pub static GROUP: Group = Group {
    names: &["smp.running"],
    run,
    manual: false,
};

fn run(r: &mut Report, _: &BootInfo) {
    match smp::self_test() {
        Ok(n) => r.ok_with("smp.running", format_args!("{n} processors, each ticking")),
        Err(why) => r.fail("smp.running", format_args!("{why}")),
    }
}
