//! Tests of waiting: events, semaphores, time limits, delays.

use crate::ke::wait;
use crate::test::{Group, Report};
use core::fmt::Display;
use nk_bootinfo::BootInfo;

pub static GROUP: Group = Group {
    names: &[
        "wait.notification",
        "wait.synchronization",
        "wait.timeout",
        "wait.delay",
        "wait.semaphore",
        "wait.ping-pong",
        "wait.race",
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
    counted(
        r,
        "wait.notification",
        "waiters woken:",
        wait::notification_test(),
    );
    counted(
        r,
        "wait.synchronization",
        "settings:",
        wait::synchronization_test(),
    );
    counted(r, "wait.timeout", "limits tried:", wait::timeout_test());
    counted(r, "wait.delay", "delays tried:", wait::delay_test());
    counted(
        r,
        "wait.semaphore",
        "units through:",
        wait::semaphore_test(),
    );
    counted(r, "wait.ping-pong", "round trips:", wait::ping_pong_test());
    counted(r, "wait.race", "settings accounted for:", wait::race_test());
}

/// A wait that has to block at DISPATCH_LEVEL must stop the system.
pub static AT_DISPATCH: Group = Group {
    names: &["neg.wait-at-dispatch"],
    run: at_dispatch,
    manual: true,
};

fn at_dispatch(r: &mut Report, _: &BootInfo) {
    kprintln!("NK-NEG-ARMED neg.wait-at-dispatch");
    wait::blocked_at_dispatch_test();
    r.fail(
        "neg.wait-at-dispatch",
        format_args!("a wait at DISPATCH_LEVEL returned"),
    );
}

/// A wait in a DPC routine must stop the system.
pub static IN_DPC: Group = Group {
    names: &["neg.wait-in-dpc"],
    run: in_dpc,
    manual: true,
};

fn in_dpc(r: &mut Report, _: &BootInfo) {
    kprintln!("NK-NEG-ARMED neg.wait-in-dpc");
    wait::blocked_in_dpc_test();
    r.fail(
        "neg.wait-in-dpc",
        format_args!("a wait in a DPC routine returned"),
    );
}
