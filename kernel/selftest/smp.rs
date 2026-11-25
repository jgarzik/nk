//! Tests of running on every processor.

use crate::ke::{ipi, smp};
use crate::test::{Group, Report};
use core::fmt::Display;
use nk_bootinfo::BootInfo;

pub static GROUP: Group = Group {
    names: &[
        "smp.running",
        "smp.each",
        "smp.calls",
        "smp.counter",
        "smp.tlb",
    ],
    run,
    manual: false,
};

fn counted<N: Display>(r: &mut Report, name: &str, what: &str, result: Result<N, &'static str>) {
    match result {
        Ok(n) => r.ok_with(name, format_args!("{n} {what}")),
        Err(why) => r.fail(name, format_args!("{why}")),
    }
}

fn run(r: &mut Report, _: &BootInfo) {
    counted(
        r,
        "smp.running",
        "processors, each ticking",
        smp::self_test(),
    );
    counted(
        r,
        "smp.each",
        "processors, each with its own PCR",
        ipi::each_test(),
    );
    counted(
        r,
        "smp.calls",
        "calls, each delivered once",
        ipi::count_test(),
    );
    counted(r, "smp.counter", "readings in order", ipi::counter_test());
    counted(r, "smp.tlb", "processors saw the new page", ipi::tlb_test());
}

/// A processor that stops answering must stop the system.
pub static STUCK: Group = Group {
    names: &["neg.cpu-stuck"],
    run: stuck,
    manual: true,
};

fn stuck(r: &mut Report, _: &BootInfo) {
    if smp::online_count() < 2 {
        return r.fail("neg.cpu-stuck", format_args!("needs a second processor"));
    }
    kprintln!("NK-NEG-ARMED neg.cpu-stuck");
    ipi::stuck_test();
    r.fail(
        "neg.cpu-stuck",
        format_args!("a call to a stuck processor returned"),
    );
}
