//! The power manager.

use crate::test::{Group, Report};
use nk_bootinfo::BootInfo;

pub static GROUP: Group = Group {
    names: &["po.information"],
    run,
    manual: false,
};

fn run(r: &mut Report, _: &BootInfo) {
    r.check("po.information", crate::po::test);
}

/// This file's test groups, in the order they run.
pub static GROUPS: &[&Group] = &[&GROUP];
