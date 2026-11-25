//! Tests of threads and the dispatcher.

use crate::ke::thread;
use crate::test::{Group, Report};
use nk_bootinfo::BootInfo;

pub static GROUP: Group = Group {
    names: &[
        "thread.lifecycle",
        "thread.turns",
        "thread.priority",
        "thread.other-cpu",
        "thread.registers",
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
        "thread.lifecycle",
        "threads run and reaped:",
        thread::lifecycle_test(),
    );
    r.check("thread.turns", thread::turns_test);
    r.check("thread.priority", thread::priority_test);
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
}
