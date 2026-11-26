//! Run-down protection, the reader/writer spin lock and the lists a
//! spin lock guards, through the routines drivers call. The words'
//! rules are tested on the host (`nk_ex::rundown`, `nk_ex::spinlock`).

use crate::ex::{rundown, spinlock};
use crate::test::{Group, Report};
use nk_bootinfo::BootInfo;

static GROUP: Group = Group {
    names: &["ex.rundown", "ex.spin-lock"],
    run,
    manual: false,
};

fn run(r: &mut Report, _: &BootInfo) {
    match rundown::self_test() {
        Ok(words) => r.ok_with("ex.rundown", format_args!("{words} cache-aware words")),
        Err(why) => r.fail("ex.rundown", format_args!("{why}")),
    }
    r.check("ex.spin-lock", spinlock::self_test);
}

/// This file's test groups, in the order they run.
pub static GROUPS: &[&Group] = &[&GROUP];
