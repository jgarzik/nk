//! Variables drivers import: the HAL's dispatch tables and the kernel's
//! start-up state.

use crate::hal::dispatch;
use crate::kd::variables;
use crate::test::{Group, Report};
use nk_bootinfo::BootInfo;

pub static GROUP: Group = Group {
    names: &[
        "hal.dispatch-tables",
        "hal.acpi-tables",
        "hal.system-information",
        "hal.interrupt-targets",
        "hal.description",
        "hal.pm-registers",
        "hal.queries",
        "kd.variables",
    ],
    run,
    manual: false,
};

fn run(r: &mut Report, info: &BootInfo) {
    r.check("hal.dispatch-tables", dispatch::layout_test);
    r.check("hal.acpi-tables", crate::hal::acpi::test);
    r.check("hal.system-information", crate::hal::sysinfo::test);
    r.check("hal.interrupt-targets", crate::hal::target::test);
    r.check("hal.description", crate::hal::description::test);
    r.check("hal.pm-registers", crate::hal::pm::test);
    r.check("hal.queries", crate::hal::query::test);
    r.check("kd.variables", || variables::variables_test(info));
}

/// This file's test groups, in the order they run.
pub static GROUPS: &[&Group] = &[&GROUP];
