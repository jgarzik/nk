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
mod kd;
mod ke;
mod ldr;
mod mm;
mod ob;
mod own;
mod po;
mod ps;
mod rtl;
mod se;
mod trap;
mod trap_etw;
mod trap_ex;
mod trap_hal;
mod trap_io;
mod trap_kd;
mod trap_ke;
mod trap_mm;
mod trap_po;
mod trap_rtl;
mod trap_zw;
mod whea;

/// Every list.
pub(super) static ALL: &[&[Export]] = &[
    arch::EXPORTS,
    cm::EXPORTS,
    etw::EXPORTS,
    ex::EXPORTS,
    hal::EXPORTS,
    io::EXPORTS,
    kd::EXPORTS,
    ke::EXPORTS,
    ldr::EXPORTS,
    mm::EXPORTS,
    ob::EXPORTS,
    po::EXPORTS,
    own::EXPORTS,
    ps::EXPORTS,
    rtl::EXPORTS,
    se::EXPORTS,
    trap::EXPORTS,
    trap_etw::EXPORTS,
    trap_ex::EXPORTS,
    trap_hal::EXPORTS,
    trap_io::EXPORTS,
    trap_kd::EXPORTS,
    trap_ke::EXPORTS,
    trap_mm::EXPORTS,
    trap_po::EXPORTS,
    trap_rtl::EXPORTS,
    trap_zw::EXPORTS,
    whea::EXPORTS,
];
