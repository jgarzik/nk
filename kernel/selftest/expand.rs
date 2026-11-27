//! Tests of kernel stack expansion: a file system's request switches to
//! a segment, a small one does not, and an exception raised on a
//! segment is handled beneath the switch.

use super::except;
use crate::ke::expand;
use crate::test::{Group, Report};
use nk_bootinfo::BootInfo;

pub static GROUP: Group = Group {
    names: &["ke.expand.switch", "ke.expand.inline", "ke.expand.raise"],
    run,
    manual: false,
};

pub static GROUPS: &[&Group] = &[&GROUP];

fn run(r: &mut Report, _: &BootInfo) {
    r.check("ke.expand.switch", expand::switch_test);
    r.check("ke.expand.inline", expand::inline_test);
    r.check("ke.expand.raise", || {
        except::raises(
            expand::raise_on_segment,
            except::CODE as usize,
            except::CODE,
        )?;
        expand::after_raise_test()
    });
}
