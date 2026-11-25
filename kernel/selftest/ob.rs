//! Tests of reference-counted objects and kernel handles.

use crate::ob::handle;
use crate::test::{Group, Report};
use nk_bootinfo::BootInfo;

pub static GROUP: Group = Group {
    names: &["ob.references", "ob.handles", "ob.thread"],
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
        "ob.references",
        "references taken and dropped:",
        handle::reference_test(),
    );
    counted(r, "ob.handles", "look-ups:", handle::handle_test());
    counted(r, "ob.thread", "waits:", handle::thread_test());
}
