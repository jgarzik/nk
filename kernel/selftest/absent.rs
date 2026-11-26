//! Services of Windows that NK does not have, where the routine's own
//! contract has an answer for "not here": the answer is that one.

use crate::ex::{license, shim};
use crate::test::{Group, Report};
use nk_bootinfo::BootInfo;
use nk_ntabi::io::UNICODE_STRING;
use nk_ntabi::status::{
    STATUS_INVALID_PARAMETER, STATUS_OBJECT_NAME_NOT_FOUND, STATUS_UNSUCCESSFUL,
};

pub static GROUP: Group = Group {
    names: &["ex.licence-values", "ex.shim-engine", "ex.secure-kernel"],
    run,
    manual: false,
};

fn licence_values() -> Result<(), &'static str> {
    let mut text: [u16; 4] = [b'N'.into(), b'k'.into(), b'-'.into(), b'X'.into()];
    let name = UNICODE_STRING {
        Length: 8,
        MaximumLength: 8,
        Buffer: text.as_mut_ptr(),
    };
    let none = core::ptr::null_mut();
    // SAFETY: a counted string over a local; nothing is written.
    let status =
        unsafe { license::ZwQueryLicenseValue(&raw const name, none, none.cast(), 0, none) };
    if status != STATUS_OBJECT_NAME_NOT_FOUND {
        return Err("a licence value NK does not hold was not reported as unknown");
    }
    // SAFETY: no string at all.
    let status =
        unsafe { license::ZwQueryLicenseValue(core::ptr::null(), none, none.cast(), 0, none) };
    if status != STATUS_INVALID_PARAMETER {
        return Err("a licence value without a name was not refused");
    }
    Ok(())
}

fn shim_engine() -> Result<(), &'static str> {
    let shim = 0u64;
    let none = core::ptr::null();
    if shim::KseRegisterShim((&raw const shim).cast(), none, 0) != STATUS_UNSUCCESSFUL
        || shim::KseRegisterShim(none, none, 0) != STATUS_INVALID_PARAMETER
    {
        return Err("registering a shim was not answered as by an engine that is not running");
    }
    Ok(())
}

fn run(r: &mut Report, _: &BootInfo) {
    r.check("ex.licence-values", licence_values);
    r.check("ex.shim-engine", shim_engine);
    r.check("ex.secure-kernel", || {
        if crate::ex::vsl::VslGetSecurePciEnabled() != 0 {
            return Err("PCI devices were reported as guarded by a secure kernel");
        }
        Ok(())
    });
}

/// This file's test groups, in the order they run.
pub static GROUPS: &[&Group] = &[&GROUP];
