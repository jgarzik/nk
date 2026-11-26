//! Variables drivers import: the HAL's dispatch tables and the kernel's
//! start-up state.

use crate::hal::dispatch;
use crate::kd::variables;
use crate::test::{Group, Report};
use nk_bootinfo::BootInfo;

pub static GROUP: Group = Group {
    names: &["hal.dispatch-tables", "kd.variables"],
    run,
    manual: false,
};

fn run(r: &mut Report, info: &BootInfo) {
    r.check("hal.dispatch-tables", dispatch::layout_test);
    r.check("kd.variables", || variables::variables_test(info));
}

/// This file's test groups, in the order they run.
pub static GROUPS: &[&Group] = &[&GROUP];
