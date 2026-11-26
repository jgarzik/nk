//! Tests of deferred procedure calls.

use crate::ke::dpc;
use crate::test::{Group, Report};
use nk_bootinfo::BootInfo;

pub static GROUP: Group = Group {
    names: &[
        "dpc.run",
        "dpc.order",
        "dpc.remove",
        "dpc.other-cpu",
        "dpc.stack",
    ],
    run,
    manual: false,
};

fn counted(r: &mut Report, name: &str, what: &str, result: Result<u32, &'static str>) {
    match result {
        Ok(n) => r.ok_with(name, format_args!("{what} {n}")),
        Err(why) => r.fail(name, format_args!("{why}")),
    }
}

fn run(r: &mut Report, _: &BootInfo) {
    r.check("dpc.run", dpc::run_test);
    counted(r, "dpc.order", "in order:", dpc::order_test());
    counted(r, "dpc.remove", "positions removed:", dpc::remove_test());
    counted(r, "dpc.other-cpu", "on processor", dpc::other_cpu_test());
    counted(r, "dpc.stack", "also on processor", dpc::stack_test());
}

/// A DPC that runs for ever must stop the system.
pub static WATCHDOG: Group = Group {
    names: &["neg.dpc-watchdog"],
    run: watchdog,
    manual: true,
};

fn watchdog(r: &mut Report, _: &BootInfo) {
    kprintln!("NK-NEG-ARMED neg.dpc-watchdog");
    dpc::stuck_test();
    r.fail(
        "neg.dpc-watchdog",
        format_args!("a DPC that never returns returned"),
    );
}
