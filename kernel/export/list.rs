//! The export table, one list per part of the kernel that implements
//! the routines: a new export goes in the list of the module it lives
//! in, a new part of the kernel adds a list here.

use super::Export;

mod arch;
mod cc;
mod cm;
mod etw;
mod ex;
mod fsrtl;
mod hal;
mod io;
mod kd;
mod ke;
mod ldr;
mod mm;
mod ob;
mod own;
mod pnp;
mod po;
mod ps;
mod rtl;
mod se;
mod trap;
mod trap_cc;
mod trap_crt;
mod trap_ex;
mod trap_fsrtl;
mod trap_io;
mod trap_ke;
mod trap_mm;
mod trap_ob;
mod trap_po;
mod trap_ps;
mod trap_rtl;
mod trap_se;
mod trap_zw;
mod whea;

/// Every list.
pub(super) static ALL: &[&[Export]] = &[
    arch::EXPORTS,
    cc::EXPORTS,
    cm::EXPORTS,
    etw::EXPORTS,
    ex::EXPORTS,
    fsrtl::EXPORTS,
    hal::EXPORTS,
    io::EXPORTS,
    kd::EXPORTS,
    ke::EXPORTS,
    ldr::EXPORTS,
    mm::EXPORTS,
    ob::EXPORTS,
    pnp::EXPORTS,
    po::EXPORTS,
    own::EXPORTS,
    ps::EXPORTS,
    rtl::EXPORTS,
    se::EXPORTS,
    trap::EXPORTS,
    trap_cc::EXPORTS,
    trap_crt::EXPORTS,
    trap_ex::EXPORTS,
    trap_fsrtl::EXPORTS,
    trap_io::EXPORTS,
    trap_ke::EXPORTS,
    trap_mm::EXPORTS,
    trap_po::EXPORTS,
    trap_ob::EXPORTS,
    trap_ps::EXPORTS,
    trap_rtl::EXPORTS,
    trap_se::EXPORTS,
    trap_zw::EXPORTS,
    whea::EXPORTS,
];
