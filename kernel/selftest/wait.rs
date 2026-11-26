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
        "wait.any",
        "wait.all",
        "wait.many-blocking",
        "wait.all-race",
        "wait.alert",
        "wait.alert-race",
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
    r.check("wait.any", wait::any_test);
    r.check("wait.all", wait::all_test);
    counted(
        r,
        "wait.many-blocking",
        "waits:",
        wait::blocking_many_test(),
    );
    counted(
        r,
        "wait.all-race",
        "waits for both satisfied:",
        wait::all_race_test(),
    );
    counted(r, "wait.alert", "waits:", wait::alert_test());
    counted(
        r,
        "wait.alert-race",
        "alerts that took:",
        wait::alert_race_test(),
    );
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
    wait::blocked_in_dpc_test(false);
    r.fail(
        "neg.wait-in-dpc",
        format_args!("a wait in a DPC routine returned"),
    );
}

/// So must a DPC routine that lowers the IRQL and then waits: the thread
/// would be left on the processor's DPC stack.
pub static SWITCH_IN_DPC: Group = Group {
    names: &["neg.switch-in-dpc"],
    run: switch_in_dpc,
    manual: true,
};

fn switch_in_dpc(r: &mut Report, _: &BootInfo) {
    kprintln!("NK-NEG-ARMED neg.switch-in-dpc");
    wait::blocked_in_dpc_test(true);
    r.fail(
        "neg.switch-in-dpc",
        format_args!("a wait in a DPC routine that lowered the IRQL returned"),
    );
}

/// This file's test groups, in the order they run.
pub static GROUPS: &[&Group] = &[&GROUP, &AT_DISPATCH, &IN_DPC, &SWITCH_IN_DPC];
