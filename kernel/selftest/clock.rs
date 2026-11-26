//! Tests of the clock: the counter, the tick, the shared data page, and
//! NK's second against the host's.

use crate::ke::time;
use crate::test::{Group, Report};
use nk_bootinfo::BootInfo;

pub static GROUP: Group = Group {
    names: &[
        "clock.monotonic",
        "clock.tick",
        "clock.shared-page",
        "clock.host-mark",
    ],
    run,
    manual: false,
};

fn counted(r: &mut Report, name: &str, what: &str, result: Result<u64, &'static str>) {
    match result {
        Ok(n) => r.ok_with(name, format_args!("{n} {what}")),
        Err(why) => r.fail(name, format_args!("{why}")),
    }
}

fn run(r: &mut Report, _: &BootInfo) {
    counted(r, "clock.monotonic", "readings", time::monotonic_test());
    counted(r, "clock.tick", "ticks in 250 ms", time::tick_test());
    counted(
        r,
        "clock.shared-page",
        "ticks since boot",
        time::shared_page_test(),
    );
    counted(
        r,
        "clock.host-mark",
        "seconds marked",
        time::host_mark_test(),
    );
}

/// This file's test groups, in the order they run.
pub static GROUPS: &[&Group] = &[&GROUP];
