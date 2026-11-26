//! Tests of kernel timers.

use crate::ke::timer;
use crate::test::{Group, Report};
use nk_bootinfo::BootInfo;

pub static GROUP: Group = Group {
    names: &[
        "timer.never-early",
        "timer.shared-bucket",
        "timer.cancel",
        "timer.periodic",
        "timer.chain",
        "timer.other-cpu",
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
    counted(
        r,
        "timer.never-early",
        "delays tried:",
        timer::never_early_test(),
    );
    r.check("timer.shared-bucket", timer::shared_bucket_test);
    r.check("timer.cancel", timer::cancel_test);
    counted(
        r,
        "timer.periodic",
        "firings in 500 ms:",
        timer::periodic_test(),
    );
    counted(r, "timer.chain", "firings:", timer::chain_test());
    counted(
        r,
        "timer.other-cpu",
        "on processor",
        timer::other_cpu_test(),
    );
}

/// This file's test groups, in the order they run.
pub static GROUPS: &[&Group] = &[&GROUP];
