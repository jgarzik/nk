//! Tests of the executive's locks, lists and timers, called the way a
//! driver calls them: through the exports, on memory of the caller's.

use crate::ex::{pushlock, slist};
use crate::test::{Group, Report};
use core::fmt::Display;
use nk_bootinfo::BootInfo;

pub static GROUP: Group = Group {
    names: &[
        "ex.pushlock.words",
        "ex.pushlock.hand-over",
        "ex.pushlock.readers",
        "ex.pushlock.contention",
        "ex.slist.swap",
        "ex.slist.order",
        "ex.slist.contention",
        "ex.pool.variants",
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
    r.check("ex.pushlock.words", pushlock::words_test);
    counted(
        r,
        "ex.pushlock.hand-over",
        "pairings:",
        pushlock::hand_over_test(),
    );
    counted(
        r,
        "ex.pushlock.readers",
        "let in together:",
        pushlock::readers_test(),
    );
    counted(
        r,
        "ex.pushlock.contention",
        "writes:",
        pushlock::contention_test(),
    );
    r.check("ex.slist.swap", slist::swap_test);
    match slist::order_test() {
        Ok(header) => r.ok_with("ex.slist.order", format_args!("header ends {header:#010x}")),
        Err(why) => r.fail("ex.slist.order", format_args!("{why}")),
    }
    counted(
        r,
        "ex.slist.contention",
        "entries taken:",
        slist::contention_test(),
    );
    counted(
        r,
        "ex.pool.variants",
        "blocks:",
        crate::mm::pool::variants_test(),
    );
}
