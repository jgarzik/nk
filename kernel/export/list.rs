//! The export table, one list per part of the kernel that implements
//! the routines: a new export goes in the list of the module it lives
//! in, a new part of the kernel adds a list here.

use super::Export;

mod arch;
mod cm;
mod etw;
mod ex;
mod hal;
mod io;
mod ke;
mod ldr;
mod mm;
mod ob;
mod own;
mod ps;
mod rtl;
mod se;
mod trap;

/// Every list.
pub(super) static ALL: &[&[Export]] = &[
    arch::EXPORTS,
    cm::EXPORTS,
    etw::EXPORTS,
    ex::EXPORTS,
    hal::EXPORTS,
    io::EXPORTS,
    ke::EXPORTS,
    ldr::EXPORTS,
    mm::EXPORTS,
    ob::EXPORTS,
    own::EXPORTS,
    ps::EXPORTS,
    rtl::EXPORTS,
    se::EXPORTS,
    trap::EXPORTS,
];
