//! Tests of kernel APCs. No Microsoft binary on a boot path queues one
//! yet, so these are NK's own: the order of delivery, what holds it
//! back, and the wait it interrupts.

use crate::ke::apc;
use crate::test::{Group, Report};
use nk_bootinfo::BootInfo;

pub static GROUP: Group = Group {
    names: &[
        "ke.apc.order",
        "ke.apc.critical",
        "ke.apc.irql",
        "ke.apc.wait",
        "ke.apc.thread",
        "ke.apc.remove",
        "ke.apc.disabled",
    ],
    run,
    manual: false,
};

pub static GROUPS: &[&Group] = &[&GROUP];

fn run(r: &mut Report, _: &BootInfo) {
    r.check("ke.apc.order", apc::order_test);
    r.check("ke.apc.critical", apc::critical_test);
    r.check("ke.apc.irql", apc::irql_test);
    match apc::wait_test() {
        Ok(n) => r.ok_with("ke.apc.wait", format_args!("APCs run in a wait: {n}")),
        Err(why) => r.fail("ke.apc.wait", format_args!("{why}")),
    }
    r.check("ke.apc.thread", apc::thread_test);
    r.check("ke.apc.remove", apc::remove_test);
    r.check("ke.apc.disabled", apc::disabled_test);
}
