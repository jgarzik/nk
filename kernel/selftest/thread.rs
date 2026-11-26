//! Tests of threads and the dispatcher.

use crate::ke::thread;
use crate::test::{Group, Report};
use nk_bootinfo::BootInfo;

pub static GROUP: Group = Group {
    names: &[
        "thread.lifecycle",
        "thread.buried",
        "thread.turns",
        "thread.priority",
        "thread.set-priority",
        "thread.set-priority-other",
        "thread.raise-ready",
        "thread.raise-preempted",
        "thread.other-cpu",
        "thread.registers",
        "thread.preempt",
        "thread.quantum",
        "thread.preempt-registers",
        "thread.migrate",
        "thread.affinity",
        "thread.system-affinity",
        "thread.steal-behind",
        "thread.identity",
    ],
    run,
    manual: false,
};

fn counted<N: core::fmt::Display>(
    r: &mut Report,
    name: &str,
    what: &str,
    result: Result<N, &'static str>,
) {
    match result {
        Ok(n) => r.ok_with(name, format_args!("{what} {n}")),
        Err(why) => r.fail(name, format_args!("{why}")),
    }
}

fn run(r: &mut Report, _: &BootInfo) {
    counted(
        r,
        "thread.lifecycle",
        "threads run and reaped:",
        thread::lifecycle_test(),
    );
    counted(
        r,
        "thread.buried",
        "threads seen off:",
        thread::buried_test(),
    );
    r.check("thread.turns", thread::turns_test);
    r.check("thread.priority", thread::priority_test);
    r.check("thread.set-priority", thread::set_priority_test);
    counted(
        r,
        "thread.set-priority-other",
        "changes of other threads' priorities:",
        thread::set_other_priority_test(),
    );
    counted(
        r,
        "thread.raise-ready",
        "ready threads raised:",
        thread::raise_ready_test(),
    );
    counted(
        r,
        "thread.raise-preempted",
        "threads raised while put aside:",
        thread::raise_preempted_test(),
    );
    counted(
        r,
        "thread.other-cpu",
        "on processor",
        thread::other_cpu_test(),
    );
    counted(
        r,
        "thread.registers",
        "switches checked:",
        thread::registers_test(),
    );
    r.check("thread.preempt", thread::preempt_test);
    counted(
        r,
        "thread.quantum",
        "switches in 2 s:",
        thread::quantum_test(),
    );
    counted(
        r,
        "thread.preempt-registers",
        "register checks under preemption:",
        thread::preempt_registers_test(),
    );
    counted(
        r,
        "thread.migrate",
        "moves between processors:",
        thread::migrate_test(),
    );
    counted(r, "thread.affinity", "checks:", thread::affinity_test());
    counted(
        r,
        "thread.system-affinity",
        "processors moved to:",
        thread::system_affinity_test(),
    );
    counted(
        r,
        "thread.steal-behind",
        "taken by processor",
        thread::steal_behind_test(),
    );
    counted(r, "thread.identity", "checks:", thread::identity_test());
}

/// This file's test groups, in the order they run.
pub static GROUPS: &[&Group] = &[&GROUP];
