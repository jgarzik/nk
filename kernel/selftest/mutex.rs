//! Tests of mutexes, fast mutexes and critical regions.

use crate::ke::mutex;
use crate::test::{Group, Report};
use core::fmt::Display;
use nk_bootinfo::BootInfo;

pub static GROUP: Group = Group {
    names: &[
        "mutex.ownership",
        "mutex.exclusion",
        "mutex.fast",
        "mutex.region",
    ],
    run,
    manual: false,
};

fn counted<N: Display>(r: &mut Report, name: &str, what: &str, result: Result<N, &'static str>) {
    match result {
        Ok(n) => r.ok_with(name, format_args!("{what} {n}")),
        Err(why) => r.fail(name, format_args!("{why}")),
    }
}

fn run(r: &mut Report, _: &BootInfo) {
    r.check("mutex.ownership", mutex::ownership_test);
    counted(
        r,
        "mutex.exclusion",
        "times taken:",
        mutex::mutex_exclusion_test(),
    );
    counted(r, "mutex.fast", "times taken:", mutex::fast_mutex_test());
    counted(r, "mutex.region", "depth:", mutex::region_test());
}

/// A thread that ends holding a mutex must stop the system.
pub static EXIT_HOLDING: Group = Group {
    names: &["neg.mutex-held-at-exit"],
    run: exit_holding,
    manual: true,
};

fn exit_holding(r: &mut Report, _: &BootInfo) {
    kprintln!("NK-NEG-ARMED neg.mutex-held-at-exit");
    let _ = mutex::exit_holding_test();
    r.fail(
        "neg.mutex-held-at-exit",
        format_args!("a thread ended holding a mutex, and nothing happened"),
    );
}

/// This file's test groups, in the order they run.
pub static GROUPS: &[&Group] = &[&GROUP, &EXIT_HOLDING];
