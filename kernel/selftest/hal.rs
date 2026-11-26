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
        "hal.acpi-machine-states",
        "hal.system-information",
        "hal.interrupt-targets",
        "hal.interrupt-controller-lines",
        "hal.interrupt-arbiter",
        "hal.description",
        "hal.pm-registers",
        "hal.queries",
        "hal.firmware-variables",
        "kd.variables",
    ],
    run,
    manual: false,
};

fn run(r: &mut Report, info: &BootInfo) {
    r.check("hal.dispatch-tables", dispatch::layout_test);
    r.check("hal.acpi-tables", crate::hal::acpi::test);
    r.check(
        "hal.acpi-machine-states",
        crate::hal::acpi::machine_state_test,
    );
    r.check("hal.system-information", crate::hal::sysinfo::test);
    r.check("hal.interrupt-targets", crate::hal::target::test);
    r.check(
        "hal.interrupt-controller-lines",
        crate::hal::interrupt::version_test,
    );
    match crate::hal::interrupt::arbiter_test() {
        // Where a vector can be chosen, the line must have moved.
        Ok(moved) if moved == (crate::arch::INTERRUPT_MODEL == 1) => r.ok_with(
            "hal.interrupt-arbiter",
            format_args!("a line moved to the arbiter's vector: {moved}"),
        ),
        Ok(_) => r.fail(
            "hal.interrupt-arbiter",
            format_args!("the line was not placed as this controller places lines"),
        ),
        Err(why) => r.fail("hal.interrupt-arbiter", format_args!("{why}")),
    }
    r.check("hal.description", crate::hal::description::test);
    r.check("hal.pm-registers", crate::hal::pm::test);
    r.check("hal.queries", crate::hal::query::test);
    match crate::hal::variables::test() {
        Ok(n) => r.ok_with("hal.firmware-variables", format_args!("calls: {n}")),
        Err(why) => r.fail("hal.firmware-variables", format_args!("{why}")),
    }
    r.check("kd.variables", || variables::variables_test(info));
}

/// This file's test groups, in the order they run.
pub static GROUPS: &[&Group] = &[&GROUP];
