//! Tests of security descriptors, access lists and the well-known SIDs,
//! through the routines drivers call.

use crate::mm::pool;
use crate::se::*;
use crate::test::{Group, Report};
use alloc::vec::Vec;
use core::ffi::c_void;
use nk_bootinfo::BootInfo;
use nk_ntabi::se::SECURITY_DESCRIPTOR;

pub static GROUP: Group = Group {
    names: &["se.well-known", "se.descriptor", "se.capture"],
    run,
    manual: false,
};

const GENERIC_ALL: u32 = 0x1000_0000;
const ACL_ROOM: usize = 64;

/// An empty access list in `room` bytes.
fn empty_acl(room: usize) -> Vec<u8> {
    let mut acl = alloc::vec![0u8; room];
    acl[0] = nk_se::ACL_REVISION;
    acl[2..4].copy_from_slice(&(room as u16).to_le_bytes());
    acl
}

/// The table drivers reach through `SeExports` holds real SIDs.
fn well_known() -> Result<(), &'static str> {
    // SAFETY: the table and what it points to are immutable statics.
    unsafe {
        let table = SeExports.table();
        let bytes = |sid: *const u8| core::slice::from_raw_parts(sid, RtlLengthSid(sid) as usize);
        if bytes((*table).SeLocalSystemSid) != [1, 1, 0, 0, 0, 0, 0, 5, 18, 0, 0, 0] {
            return Err("the system's SID is not S-1-5-18");
        }
        if bytes((*table).SeAliasAdminsSid) != [1, 2, 0, 0, 0, 0, 0, 5, 32, 0, 0, 0, 0x20, 2, 0, 0]
        {
            return Err("the administrators' SID is not S-1-5-32-544");
        }
        if bytes((*table).SeWorldSid) != [1, 1, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0] {
            return Err("everyone's SID is not S-1-1-0");
        }
        if RtlLengthSid((*table).SeNtAuthoritySid) != 8
            || RtlLengthSid((*table).SeTrustedInstallerSid) != 32
        {
            return Err("a well-known SID has the wrong length");
        }
        if (*table).SeLoadDriverPrivilege.LowPart != 10 {
            return Err("the load-driver privilege is not number 10");
        }
    }
    Ok(())
}

/// What a driver does to give its device an access list, step by step:
/// the same calls, in the same order, as the conformance driver
/// `nkc-se` makes, and the values it logs.
fn descriptor() -> Result<(), &'static str> {
    let mut log = Vec::new();
    // SAFETY: every pointer names a local that outlives the calls.
    unsafe {
        let table = SeExports.table();
        let (system, admins, world) = (
            (*table).SeLocalSystemSid,
            (*table).SeAliasAdminsSid,
            (*table).SeWorldSid,
        );
        let mut sd = core::mem::zeroed::<SECURITY_DESCRIPTOR>();
        let sd_ptr = &raw mut sd;
        let mut acl = empty_acl(ACL_ROOM);
        let mut relative = [0u8; 256];
        let (mut present, mut defaulted) = (1u8, 1u8);
        let mut got: *mut c_void = core::ptr::null_mut();

        log.extend([
            RtlLengthSid(system),
            RtlLengthSid(admins),
            RtlLengthSid(world),
        ]);
        log.push(RtlCreateSecurityDescriptor(sd_ptr, 2) as u32);
        log.push(RtlCreateSecurityDescriptor(sd_ptr, 1) as u32);
        log.push(RtlLengthSecurityDescriptor(sd_ptr.cast()));
        log.push(u32::from((&raw const (*sd_ptr).Control).read()));

        let mut sid = core::ptr::dangling_mut::<c_void>();
        log.push(
            RtlGetOwnerSecurityDescriptor(sd_ptr.cast(), &raw mut sid, &raw mut defaulted) as u32,
        );
        log.push(u32::from(!sid.is_null()));
        log.push(RtlGetDaclSecurityDescriptor(
            sd_ptr.cast(),
            &raw mut present,
            &raw mut got,
            &raw mut defaulted,
        ) as u32);
        log.push(u32::from(present));

        log.push(RtlAddAccessAllowedAce(acl.as_mut_ptr(), 7, GENERIC_ALL, system) as u32);
        log.push(RtlAddAccessAllowedAce(acl.as_mut_ptr(), 2, GENERIC_ALL, system) as u32);
        log.push(RtlAddAccessAllowedAce(acl.as_mut_ptr(), 2, GENERIC_ALL, admins) as u32);
        log.push(u32::from(u16::from_le_bytes([acl[4], acl[5]])));
        log.push(nk_se::acl_used(&acl).ok_or("the access list is damaged")? as u32);

        let mut small = empty_acl(16);
        log.push(RtlAddAccessAllowedAce(small.as_mut_ptr(), 2, GENERIC_ALL, admins) as u32);

        log.push(RtlSetDaclSecurityDescriptor(sd_ptr, 1, acl.as_mut_ptr().cast(), 0) as u32);
        log.push(RtlGetDaclSecurityDescriptor(
            sd_ptr.cast(),
            &raw mut present,
            &raw mut got,
            &raw mut defaulted,
        ) as u32);
        log.push(u32::from(present));
        log.push(u32::from(got == acl.as_mut_ptr().cast()));
        log.push(u32::from(defaulted));
        log.push(u32::from((&raw const (*sd_ptr).Control).read()));
        log.push(RtlLengthSecurityDescriptor(sd_ptr.cast()));

        let mut length = 0u32;
        log.push(
            RtlAbsoluteToSelfRelativeSD(sd_ptr.cast(), relative.as_mut_ptr(), &raw mut length)
                as u32,
        );
        log.push(length);
        length = relative.len() as u32;
        log.push(
            RtlAbsoluteToSelfRelativeSD(sd_ptr.cast(), relative.as_mut_ptr(), &raw mut length)
                as u32,
        );
        log.push(u32::from(u16::from_le_bytes([relative[2], relative[3]])));
        log.push(RtlLengthSecurityDescriptor(relative.as_ptr().cast()));
        log.push(RtlGetDaclSecurityDescriptor(
            relative.as_ptr().cast(),
            &raw mut present,
            &raw mut got,
            &raw mut defaulted,
        ) as u32);
        log.push((got as usize - relative.as_ptr() as usize) as u32);
        log.push(u32::from_le_bytes([
            relative[4],
            relative[5],
            relative[6],
            relative[7],
        ]));
        log.push(u32::from_le_bytes([
            relative[16],
            relative[17],
            relative[18],
            relative[19],
        ]));
        log.push(RtlSetDaclSecurityDescriptor(
            relative.as_mut_ptr().cast(),
            1,
            acl.as_mut_ptr().cast(),
            0,
        ) as u32);

        let mut captured: *mut c_void = core::ptr::null_mut();
        log.push(SeCaptureSecurityDescriptor(sd_ptr.cast(), 0, 0, 0, &raw mut captured) as u32);
        log.push(u32::from(captured == sd_ptr.cast()));

        // The copy holds the access list byte for byte.
        if relative[20..84] != acl[..] || relative[84] != 0 {
            return Err("the self-relative form does not hold the access list");
        }
    }
    const EXPECTED: &[u32] = &[
        12,
        16,
        12, // SID lengths
        0xC000_0058,
        0, // a descriptor is created at revision 1 only
        40,
        0, // empty: its length, its control bits
        0,
        0,
        0,
        0, // no owner, no access list
        0xC000_0059,
        0,
        0,
        2,
        52,          // two entries added
        0xC000_0099, // no room for one
        0,
        0,
        1,
        1,
        0,
        4,   // the list is set and comes back
        104, // the descriptor with its list
        0xC000_0023,
        84,
        0,
        0x8004,
        84,
        0,
        20,
        0,
        20,          // the self-relative form
        0xC000_0079, // which has no pointer to set
        0,
        1, // captured unforced: the caller's own
    ];
    if log != *EXPECTED {
        crate::kd::print(format_args!("se.descriptor observed: {log:x?}\n"));
        return Err("building a security descriptor did not give the expected values");
    }
    Ok(())
}

/// A forced capture is a self-relative copy in the pool, the caller's
/// to free.
fn capture() -> Result<(), &'static str> {
    // SAFETY: every pointer names a local that outlives the calls.
    unsafe {
        let table = SeExports.table();
        let mut sd = core::mem::zeroed::<SECURITY_DESCRIPTOR>();
        let sd_ptr = &raw mut sd;
        let mut acl = empty_acl(ACL_ROOM);
        RtlCreateSecurityDescriptor(sd_ptr, 1);
        RtlAddAccessAllowedAce(acl.as_mut_ptr(), 2, GENERIC_ALL, (*table).SeLocalSystemSid);
        RtlSetDaclSecurityDescriptor(sd_ptr, 1, acl.as_mut_ptr().cast(), 0);
        (&raw mut (*sd_ptr).Owner).write((*table).SeAliasAdminsSid.cast_mut().cast());

        let before = pool::usage().blocks;
        let mut captured: *mut c_void = core::ptr::null_mut();
        if SeCaptureSecurityDescriptor(sd_ptr.cast(), 0, 1, 1, &raw mut captured) != 0 {
            return Err("a forced capture failed");
        }
        if captured.is_null() || captured == sd_ptr.cast() || pool::usage().blocks != before + 1 {
            return Err("a forced capture did not make a copy in the pool");
        }
        // Header, the list, then the owner.
        if RtlLengthSecurityDescriptor(captured) != 20 + 64 + 16 {
            return Err("the captured copy has the wrong length");
        }
        let copy = core::slice::from_raw_parts(captured.cast::<u8>(), 100);
        let parts =
            nk_se::parse_relative(copy).ok_or("the captured copy is not a sound descriptor")?;
        if parts.dacl != Some(&acl[..])
            || parts.owner.map(<[u8]>::len) != Some(16)
            || parts.group.is_some()
        {
            return Err("the captured copy does not hold the original's parts");
        }
        pool::ExFreePoolWithTag(captured, 0);
        if pool::usage().blocks != before {
            return Err("freeing the captured copy left memory behind");
        }
        // Nothing to capture is not an error; a descriptor of another
        // revision is.
        let mut none = sd_ptr.cast::<c_void>();
        if SeCaptureSecurityDescriptor(core::ptr::null_mut(), 0, 1, 1, &raw mut none) != 0
            || !none.is_null()
        {
            return Err("capturing no descriptor did not give none");
        }
        sd_ptr.cast::<u8>().write(9);
        if SeCaptureSecurityDescriptor(sd_ptr.cast(), 0, 1, 1, &raw mut none) as u32 != 0xC000_0058
        {
            return Err("a descriptor of an unknown revision was captured");
        }
        // The group and SACL readers, on a descriptor with neither.
        sd_ptr.cast::<u8>().write(1);
        let (mut present, mut defaulted) = (1u8, 1u8);
        let mut part = core::ptr::dangling_mut::<c_void>();
        if RtlGetGroupSecurityDescriptor(sd_ptr.cast(), &raw mut part, &raw mut defaulted) != 0
            || !part.is_null()
            || defaulted != 0
            || RtlGetSaclSecurityDescriptor(
                sd_ptr.cast(),
                &raw mut present,
                &raw mut part,
                &raw mut defaulted,
            ) != 0
            || present != 0
        {
            return Err("a descriptor without group or SACL reported one");
        }
    }
    Ok(())
}

fn run(r: &mut Report, _: &BootInfo) {
    r.check("se.well-known", well_known);
    r.check("se.descriptor", descriptor);
    r.check("se.capture", capture);
}
