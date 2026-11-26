//! Callback objects and one-time initialisation, through the routines
//! drivers call, with routines as a driver has them.

use crate::test::{Group, Report};
use nk_bootinfo::BootInfo;

static GROUP: Group = Group {
    names: &["ex.callback", "rtl.run-once"],
    run,
    manual: false,
};

fn run(r: &mut Report, _: &BootInfo) {
    match crate::ex::callback::self_test() {
        Ok(called) => r.ok_with("ex.callback", format_args!("{called} routines called")),
        Err(why) => r.fail("ex.callback", format_args!("{why}")),
    }
    match crate::rtl::once::self_test() {
        Ok(runs) => r.ok_with("rtl.run-once", format_args!("{runs} runs")),
        Err(why) => r.fail("rtl.run-once", format_args!("{why}")),
    }
}

/// This file's test groups, in the order they run.
pub static GROUPS: &[&Group] = &[&GROUP];
