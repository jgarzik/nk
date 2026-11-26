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
    names: &[
        "se.well-known",
        "se.descriptor",
        "se.capture",
        "se.device",
        "se.token",
        "se.access-state",
    ],
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

/// A device is an object a handle can be opened to, and setting its
/// security through the handle gives it a descriptor of its own, which
/// lives as long as the device's memory does.
fn device() -> Result<(), &'static str> {
    use crate::io::device::{IoCreateDevice, IoDeleteDevice};
    use crate::ob::handle::{ObOpenObjectByPointer, ObReferenceObjectByHandle};
    use crate::ob::object::{ExEventObjectType, IoDeviceObjectType, ObfDereferenceObject};
    use crate::ps::ZwClose;
    use nk_ntabi::io::{DEVICE_OBJECT, DRIVER_EXTENSION, DRIVER_OBJECT};

    // Pool blocks in use, the handle table's own storage aside.
    let blocks = || pool::usage().blocks - crate::ob::handle::storage().0;
    const DACL: u32 = nk_se::DACL_SECURITY_INFORMATION;
    const OWNER: u32 = nk_se::OWNER_SECURITY_INFORMATION;
    let size = size_of::<DRIVER_OBJECT>() + size_of::<DRIVER_EXTENSION>();
    let driver = pool::alloc_zeroed(size, u32::from_le_bytes(*b"Test")).cast::<DRIVER_OBJECT>();
    if driver.is_null() {
        return Err("no memory for a driver object");
    }
    // SAFETY: the test's own driver object and locals; the device is
    // used only while this test holds it or a handle to it.
    let result = unsafe {
        (|| {
            let table = SeExports.table();
            let mut acl = empty_acl(ACL_ROOM);
            // A list that claims more entries than it holds.
            let mut damaged = empty_acl(ACL_ROOM);
            damaged[4] = 9;
            let before = blocks();
            let mut dev: *mut DEVICE_OBJECT = core::ptr::null_mut();
            if IoCreateDevice(driver, 0, core::ptr::null(), 0x22, 0, 0, &raw mut dev) != 0 {
                return Err("no device");
            }
            let mut wrong = core::ptr::dangling_mut::<c_void>();
            let status = ObOpenObjectByPointer(
                dev.cast(),
                0x200,
                core::ptr::null_mut(),
                0,
                ExEventObjectType.value(),
                0,
                &raw mut wrong,
            );
            if status as u32 != 0xC000_0024 || !wrong.is_null() {
                return Err("a device was opened as an event");
            }
            let mut handle = core::ptr::null_mut();
            if ObOpenObjectByPointer(
                dev.cast(),
                0x200,
                core::ptr::null_mut(),
                0,
                IoDeviceObjectType.value(),
                0,
                &raw mut handle,
            ) != 0
            {
                return Err("a handle to a device could not be opened");
            }
            let mut back = core::ptr::null_mut();
            if ObReferenceObjectByHandle(
                handle,
                0,
                IoDeviceObjectType.value(),
                0,
                &raw mut back,
                core::ptr::null_mut(),
            ) != 0
                || back != dev.cast()
            {
                return Err("the handle does not name the device");
            }
            ObfDereferenceObject(back);

            // A descriptor with an access list, set as the list alone.
            let mut sd = core::mem::zeroed::<SECURITY_DESCRIPTOR>();
            let sd_ptr = &raw mut sd;
            RtlCreateSecurityDescriptor(sd_ptr, 1);
            RtlAddAccessAllowedAce(acl.as_mut_ptr(), 2, GENERIC_ALL, (*table).SeLocalSystemSid);
            RtlSetDaclSecurityDescriptor(sd_ptr, 1, acl.as_mut_ptr().cast(), 0);
            (&raw mut (*sd_ptr).Owner).write((*table).SeAliasAdminsSid.cast_mut().cast());
            if !(&raw const (*dev).SecurityDescriptor).read().is_null() {
                return Err("a new device already has a descriptor");
            }
            if ZwSetSecurityObject(handle, DACL, sd_ptr.cast()) != 0 {
                return Err("setting a device's access list failed");
            }
            let first = (&raw const (*dev).SecurityDescriptor).read();
            if first.is_null() || RtlLengthSecurityDescriptor(first) != 20 + 64 {
                return Err("the device's descriptor is not the list alone");
            }
            let held = blocks();
            // Then the owner: the list stays, the old block goes.
            if ZwSetSecurityObject(handle, OWNER, sd_ptr.cast()) != 0 {
                return Err("setting a device's owner failed");
            }
            let second = (&raw const (*dev).SecurityDescriptor).read();
            let copy = core::slice::from_raw_parts(
                second.cast::<u8>(),
                RtlLengthSecurityDescriptor(second) as usize,
            );
            let parts = nk_se::parse_relative(copy).ok_or("the device's descriptor is damaged")?;
            if parts.dacl != Some(&acl[..])
                || parts.owner.map(<[u8]>::len) != Some(16)
                || copy.len() != 100
            {
                return Err("the device's descriptor lost a part");
            }
            if blocks() != held {
                return Err("replacing a descriptor did not free the old one");
            }

            // What is refused: a damaged list, a bad revision, no
            // descriptor, a handle that is none, an object without one.
            RtlSetDaclSecurityDescriptor(sd_ptr, 1, damaged.as_mut_ptr().cast(), 0);
            let bad_list = ZwSetSecurityObject(handle, DACL, sd_ptr.cast()) as u32;
            RtlSetDaclSecurityDescriptor(sd_ptr, 1, acl.as_mut_ptr().cast(), 0);
            let no_handle = ZwSetSecurityObject(0x1234 as *mut c_void, DACL, sd_ptr.cast()) as u32;
            let nothing = ZwSetSecurityObject(handle, DACL, core::ptr::null()) as u32;
            sd_ptr.cast::<u8>().write(7);
            let revision = ZwSetSecurityObject(handle, DACL, sd_ptr.cast()) as u32;
            sd_ptr.cast::<u8>().write(1);
            if (bad_list, no_handle, nothing, revision)
                != (0xC000_0077, 0xC000_0008, 0xC000_000D, 0xC000_0058)
            {
                return Err("a request that should be refused was not, or with the wrong status");
            }
            if (&raw const (*dev).SecurityDescriptor).read() != second {
                return Err("a refused request changed the descriptor");
            }
            let thread = crate::ke::thread::current();
            let mut own = core::ptr::null_mut();
            if ObOpenObjectByPointer(
                thread.cast(),
                0x200,
                core::ptr::null_mut(),
                0,
                core::ptr::null(),
                0,
                &raw mut own,
            ) != 0
            {
                return Err("a handle to a thread could not be opened");
            }
            let unsupported = ZwSetSecurityObject(own, DACL, sd_ptr.cast()) as u32;
            ZwClose(own);
            if unsupported != 0xC000_00BB {
                return Err("a thread took a security descriptor NK does not keep");
            }

            // Deleted while the handle is open, the device's memory and
            // its descriptor stay until the handle is closed.
            IoDeleteDevice(dev);
            if blocks() != held {
                return Err("a device with an open handle was freed when deleted");
            }
            if ZwClose(handle) != 0 || blocks() != before {
                return Err("closing the last handle did not free the device and its descriptor");
            }
            Ok(())
        })()
    };
    let _ = pool::free(driver.cast());
    result
}

fn run(r: &mut Report, _: &BootInfo) {
    r.check("se.well-known", well_known);
    r.check("se.descriptor", descriptor);
    r.check("se.capture", capture);
    r.check("se.device", device);
    r.check("se.token", token::token_test);
    r.check("se.access-state", token::access_state_test);
}
