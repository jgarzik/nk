//! SIDs as drivers build, compare, copy and print them. A SID is the
//! driver's memory: its two header bytes say whether it is one and how
//! long it is, so they are read first and the rest only then.

use crate::mm::pool;
use crate::rtl::string;
use core::ffi::c_void;
use nk_ntabi::io::UNICODE_STRING;
use nk_ntabi::se::PSID;
use nk_ntabi::status::*;
use nk_se::SID_MAX_SIZE;
use nk_se::sid::AppContainerSidType;

/// Pool tag of the SIDs these routines allocate.
const TAG: u32 = u32::from_le_bytes(*b"SeSi");

/// Whether `sid` points to a valid SID.
///
/// # Safety
/// `sid` is null or its first two bytes are readable.
unsafe fn valid(sid: PSID) -> bool {
    // SAFETY: per the contract.
    !sid.is_null() && unsafe { nk_se::sid::valid_header(sid.read(), sid.add(1).read()) }
}

/// A copy of the SID at `sid`, and its length; `None` if it is not a
/// valid one.
///
/// # Safety
/// `sid` is null or points to a SID.
unsafe fn copy(sid: PSID) -> Option<([u8; SID_MAX_SIZE], usize)> {
    // SAFETY: per the contract; a valid SID is at most `SID_MAX_SIZE`
    // bytes, all readable.
    unsafe {
        if !valid(sid) {
            return None;
        }
        let length = super::sid_length(sid);
        let mut bytes = [0u8; SID_MAX_SIZE];
        for (at, byte) in bytes[..length].iter_mut().enumerate() {
            *byte = sid.add(at).read();
        }
        Some((bytes, length))
    }
}

/// [`RtlValidSid`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-rtlvalidsid).
///
/// # Safety
/// `sid` is null or its first two bytes are readable.
pub unsafe extern "C" fn RtlValidSid(sid: PSID) -> u8 {
    // SAFETY: per the contract.
    u8::from(unsafe { valid(sid) })
}

/// [`RtlEqualSid`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-rtlequalsid).
///
/// # Safety
/// Both point to SIDs.
pub unsafe extern "C" fn RtlEqualSid(a: PSID, b: PSID) -> u8 {
    // SAFETY: per the contract: the comparison reads neither SID past
    // the length its own header gives it.
    let byte = |sid: PSID| move |at: usize| unsafe { sid.add(at).read() };
    u8::from(nk_se::sid::equal(byte(a), byte(b)))
}

/// [`RtlCopySid`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-rtlcopysid).
///
/// # Safety
/// `source` points to a SID; `destination` is writable for `length`
/// bytes.
pub unsafe extern "C" fn RtlCopySid(length: u32, destination: *mut u8, source: PSID) -> NTSTATUS {
    // SAFETY: per the contract.
    unsafe {
        let needed = super::sid_length(source);
        if (length as usize) < needed {
            return STATUS_BUFFER_TOO_SMALL;
        }
        // The two may overlap, as with `RtlMoveMemory`.
        core::ptr::copy(source, destination, needed);
    }
    STATUS_SUCCESS
}

/// [`RtlLengthRequiredSid`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-rtllengthrequiredsid).
pub extern "C" fn RtlLengthRequiredSid(sub_authorities: u32) -> u32 {
    (nk_se::sid_length(0) as u32).wrapping_add(sub_authorities.wrapping_mul(4))
}

/// [`RtlInitializeSid`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-rtlinitializesid):
/// the header of a SID; its sub-authorities are the caller's to fill.
///
/// # Safety
/// `sid` is writable for eight bytes; `authority` points to six.
pub unsafe extern "C" fn RtlInitializeSid(
    sid: *mut u8,
    authority: *const u8,
    sub_authorities: u8,
) -> NTSTATUS {
    if usize::from(sub_authorities) > nk_se::SID_MAX_SUB_AUTHORITIES {
        return STATUS_INVALID_PARAMETER;
    }
    // SAFETY: per the contract.
    unsafe {
        sid.write(nk_se::SID_REVISION);
        sid.add(1).write(sub_authorities);
        for at in 0..6 {
            sid.add(2 + at).write(authority.add(at).read());
        }
    }
    STATUS_SUCCESS
}

/// [`RtlSubAuthoritySid`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-rtlsubauthoritysid):
/// where sub-authority `index` of a SID is.
pub extern "C" fn RtlSubAuthoritySid(sid: PSID, index: u32) -> *mut u32 {
    sid.wrapping_add(nk_se::sid_length(index as usize))
        .cast_mut()
        .cast()
}

/// [`RtlSubAuthorityCountSid`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-rtlsubauthoritycountsid):
/// where a SID's count of sub-authorities is.
pub extern "C" fn RtlSubAuthorityCountSid(sid: PSID) -> *mut u8 {
    sid.wrapping_add(1).cast_mut()
}

/// [`RtlConvertSidToUnicodeString`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-rtlconvertsidtounicodestring):
/// a SID's text, `S-1-5-18`, terminated, in the string's buffer or in
/// one allocated for it.
///
/// # Safety
/// `sid` points to a SID; `text` is writable and, unless a buffer is to
/// be allocated, its buffer has `MaximumLength` bytes.
pub unsafe extern "C" fn RtlConvertSidToUnicodeString(
    text: *mut UNICODE_STRING,
    sid: PSID,
    allocate: u8,
) -> NTSTATUS {
    // SAFETY: per the contract.
    unsafe {
        let Some((bytes, length)) = copy(sid) else {
            return STATUS_INVALID_SID;
        };
        let sid = &bytes[..length];
        let mut subs = [0u32; nk_se::SID_MAX_SUB_AUTHORITIES];
        let count = usize::from(sid[1]);
        for (slot, sub) in subs.iter_mut().zip(nk_se::sid::sub_authorities(sid)) {
            *slot = sub;
        }
        let mut out = [0u16; nk_rtl::string::SID_TEXT_MAX];
        let Some(chars) = nk_rtl::string::sid_text(
            sid[0],
            &nk_se::sid::authority(sid),
            &subs[..count],
            &mut out,
        ) else {
            return STATUS_INVALID_SID;
        };
        if allocate != 0 {
            return string::allocated(text, &out[..chars]);
        }
        // The text and its terminator must fit.
        let (stored, needed) = nk_rtl::init_unicode_lengths(chars);
        if (&raw const (*text).MaximumLength).read_unaligned() < needed {
            return STATUS_BUFFER_OVERFLOW;
        }
        let to = (&raw const (*text).Buffer).read_unaligned();
        for (at, &unit) in out[..chars].iter().chain(&[0]).enumerate() {
            to.add(at).write_unaligned(unit);
        }
        (&raw mut (*text).Length).write_unaligned(stored);
    }
    STATUS_SUCCESS
}

/// [`RtlGetAppContainerSidType`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-rtlgetappcontainersidtype):
/// whether a SID is an app container's, and a parent's or a child's.
/// A SID that is none stores "not an app container" and fails with
/// `STATUS_NOT_APPCONTAINER`.
///
/// # Safety
/// `sid` is null or points to a SID; `kind` is writable.
pub unsafe extern "C" fn RtlGetAppContainerSidType(sid: PSID, kind: *mut u32) -> NTSTATUS {
    // SAFETY: per the contract.
    unsafe {
        let Some((bytes, length)) = copy(sid) else {
            return STATUS_INVALID_SID;
        };
        let found = nk_se::sid::app_container_sid_type(&bytes[..length]);
        kind.write_unaligned(found as u32);
        match found {
            AppContainerSidType::NotAppContainer => STATUS_NOT_APPCONTAINER,
            _ => STATUS_SUCCESS,
        }
    }
}

/// [`RtlGetAppContainerParent`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-rtlgetappcontainerparent):
/// the SID of a child app container's parent, in a pool block the
/// caller frees. A SID that is no app container's fails as
/// [`RtlGetAppContainerSidType`] does; one that is but is no child's,
/// with `STATUS_INVALID_PARAMETER`.
///
/// # Safety
/// `sid` is null or points to a SID; `parent` is writable.
pub unsafe extern "C" fn RtlGetAppContainerParent(sid: PSID, parent: *mut PSID) -> NTSTATUS {
    // SAFETY: per the contract.
    unsafe {
        let Some((bytes, length)) = copy(sid) else {
            return STATUS_INVALID_SID;
        };
        let sid = &bytes[..length];
        let Some((bytes, length)) = nk_se::sid::app_container_parent(sid) else {
            return match nk_se::sid::app_container_sid_type(sid) {
                AppContainerSidType::NotAppContainer => STATUS_NOT_APPCONTAINER,
                _ => STATUS_INVALID_PARAMETER,
            };
        };
        let block = pool::alloc(length, TAG);
        if block.is_null() {
            return STATUS_NO_MEMORY;
        }
        for (at, &byte) in bytes[..length].iter().enumerate() {
            block.add(at).write(byte);
        }
        parent.write_unaligned(block);
    }
    STATUS_SUCCESS
}

/// [`RtlCreateAcl`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-rtlcreateacl):
/// an empty ACL in `length` bytes.
///
/// # Safety
/// `acl` is writable for `length` bytes.
pub unsafe extern "C" fn RtlCreateAcl(acl: *mut c_void, length: u32, revision: u32) -> NTSTATUS {
    use nk_se::sid::NewAclError;
    match nk_se::sid::new_acl(length, revision) {
        Ok(header) => {
            for (at, &byte) in header.iter().enumerate() {
                // SAFETY: per the contract; the header fits in `length`.
                unsafe { acl.cast::<u8>().add(at).write(byte) };
            }
            STATUS_SUCCESS
        }
        Err(NewAclError::TooSmall) => STATUS_BUFFER_TOO_SMALL,
        Err(NewAclError::Invalid) => STATUS_INVALID_PARAMETER,
    }
}
