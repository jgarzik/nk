//! `KTIMER2` through the routines drivers call, in storage of the
//! caller's.

use crate::test::{Group, Report};
use nk_bootinfo::BootInfo;

static GROUP: Group = Group {
    names: &["timer.timer2"],
    run,
    manual: false,
};

fn run(r: &mut Report, _: &BootInfo) {
    match crate::ke::timer2::self_test() {
        Ok(calls) => r.ok_with("timer.timer2", format_args!("{calls} callbacks")),
        Err(why) => r.fail("timer.timer2", format_args!("{why}")),
    }
}

/// This file's test groups, in the order they run.
pub static GROUPS: &[&Group] = &[&GROUP];
