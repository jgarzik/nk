//! SIDs taken apart: validity by the header alone, equality, the parts
//! a text form is made of, a new ACL's header, and what kind of
//! app-container SID one is.
//!
//! # App containers
//!
//! A package SID is `S-1-15-2` followed by seven numbers hashed from
//! the package's name: eight sub-authorities
//! (`SECURITY_APP_PACKAGE_RID_COUNT`). A child container's SID is its
//! parent's with four more (`SECURITY_CHILD_PACKAGE_RID_COUNT`, twelve).
//! [`RtlGetAppContainerSidType`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-rtlgetappcontainersidtype)
//! tells them apart and
//! [`RtlGetAppContainerParent`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-rtlgetappcontainerparent)
//! gives a child's parent.
//!
//! Only authority 15 with a first sub-authority of 2 is an
//! app-container SID at all, and one of neither eight nor twelve
//! sub-authorities is of the invalid type. Windows 10 answers so, and
//! with these statuses (`kernel/se/sid.rs`): asked for its type, a SID
//! that is neither a parent's nor a child's has its type stored (none,
//! or invalid) and `STATUS_NOT_APPCONTAINER`; asked for its parent,
//! every SID but a child's is `STATUS_INVALID_PARAMETER`.

use crate::{ACL_HEADER, ACL_REVISION, ACL_REVISION4, SID_MAX_SIZE, SID_MAX_SUB_AUTHORITIES};
use crate::{SID_REVISION, sid_length};

/// [`RtlValidSid`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-rtlvalidsid)
/// by a SID's first two bytes, which is all that can be wrong with one:
/// they also say how long it is.
pub const fn valid_header(revision: u8, sub_authorities: u8) -> bool {
    revision == SID_REVISION && sub_authorities as usize <= SID_MAX_SUB_AUTHORITIES
}

/// [`RtlEqualSid`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-rtlequalsid).
/// Each SID is a function from an offset to the byte there. The
/// revisions and counts are compared first, so that neither is read
/// past the length its own count gives it.
pub fn equal(a: impl Fn(usize) -> u8, b: impl Fn(usize) -> u8) -> bool {
    a(0) == b(0) && a(1) == b(1) && (2..sid_length(usize::from(a(1)))).all(|at| a(at) == b(at))
}

/// The identifier authority of the valid SID `sid`, most significant
/// byte first.
pub fn authority(sid: &[u8]) -> [u8; 6] {
    [sid[2], sid[3], sid[4], sid[5], sid[6], sid[7]]
}

/// The sub-authorities of the valid SID `sid`.
pub fn sub_authorities(sid: &[u8]) -> impl Iterator<Item = u32> + '_ {
    sid[8..sid_length(usize::from(sid[1]))]
        .as_chunks::<4>()
        .0
        .iter()
        .map(|sub| u32::from_le_bytes(*sub))
}

/// Why [`new_acl`] refuses.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NewAclError {
    /// `STATUS_BUFFER_TOO_SMALL`: no room for a header.
    TooSmall,
    /// `STATUS_INVALID_PARAMETER`: a revision ACLs do not have, or a
    /// length a 16-bit size cannot hold.
    Invalid,
}

/// [`RtlCreateAcl`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-rtlcreateacl):
/// the header of an empty ACL in `length` bytes. Its size is `length`
/// brought down to a multiple of four.
pub fn new_acl(length: u32, revision: u32) -> Result<[u8; ACL_HEADER], NewAclError> {
    if (length as usize) < ACL_HEADER {
        return Err(NewAclError::TooSmall);
    }
    let size = u16::try_from(length).map_err(|_| NewAclError::Invalid)? & !3;
    if revision < u32::from(ACL_REVISION) || revision > u32::from(ACL_REVISION4) {
        return Err(NewAclError::Invalid);
    }
    let size = size.to_le_bytes();
    Ok([revision as u8, 0, size[0], size[1], 0, 0, 0, 0])
}

/// `APPCONTAINER_SID_TYPE` (`ntifs.h`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum AppContainerSidType {
    NotAppContainer = 0,
    Child = 1,
    Parent = 2,
    Invalid = 3,
}

/// `SECURITY_APP_PACKAGE_AUTHORITY`.
const APP_PACKAGE_AUTHORITY: [u8; 6] = [0, 0, 0, 0, 0, 15];
/// `SECURITY_APP_PACKAGE_BASE_RID`.
const APP_PACKAGE_BASE_RID: u32 = 2;
/// `SECURITY_APP_PACKAGE_RID_COUNT`.
const APP_PACKAGE_RID_COUNT: usize = 8;
/// `SECURITY_CHILD_PACKAGE_RID_COUNT`.
const CHILD_PACKAGE_RID_COUNT: usize = 12;

/// What kind of app-container SID the valid SID `sid` is.
pub fn app_container_sid_type(sid: &[u8]) -> AppContainerSidType {
    if authority(sid) != APP_PACKAGE_AUTHORITY
        || sub_authorities(sid).next() != Some(APP_PACKAGE_BASE_RID)
    {
        return AppContainerSidType::NotAppContainer;
    }
    match usize::from(sid[1]) {
        APP_PACKAGE_RID_COUNT => AppContainerSidType::Parent,
        CHILD_PACKAGE_RID_COUNT => AppContainerSidType::Child,
        _ => AppContainerSidType::Invalid,
    }
}

/// The parent of the child app-container SID `sid`: its first eight
/// sub-authorities under the same authority. The SID's bytes and their
/// number; `None` if `sid` is not a child's.
pub fn app_container_parent(sid: &[u8]) -> Option<([u8; SID_MAX_SIZE], usize)> {
    if app_container_sid_type(sid) != AppContainerSidType::Child {
        return None;
    }
    let length = sid_length(APP_PACKAGE_RID_COUNT);
    let mut parent = [0u8; SID_MAX_SIZE];
    parent[..length].copy_from_slice(&sid[..length]);
    parent[1] = APP_PACKAGE_RID_COUNT as u8;
    Some((parent, length))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sid;

    /// The bytes of S-1-`authority`-`subs`.
    fn bytes(authority: u8, subs: &[u32]) -> Vec<u8> {
        let (bytes, length) = sid(authority, subs);
        bytes[..length].to_vec()
    }

    /// A SID as `equal` takes it, in memory that ends where the SID
    /// does.
    fn at(sid: &[u8]) -> impl Fn(usize) -> u8 + '_ {
        |offset| sid[offset]
    }

    #[test]
    fn a_sid_is_valid_by_its_header() {
        assert!(valid_header(1, 0));
        assert!(valid_header(1, 15));
        assert!(!valid_header(1, 16));
        assert!(!valid_header(2, 2));
        assert!(!valid_header(0, 2));
    }

    #[test]
    fn equal_sids_are_the_same_bytes() {
        let admins = bytes(5, &[32, 544]);
        assert!(equal(at(&admins), at(&admins)));
        assert!(equal(at(&admins), at(&bytes(5, &[32, 544]))));
        assert!(!equal(at(&admins), at(&bytes(5, &[32, 545]))));
        assert!(!equal(at(&admins), at(&bytes(1, &[32, 544]))));
        // Another count: the shorter one is not read past its end.
        assert!(!equal(at(&admins), at(&bytes(5, &[32]))));
        assert!(!equal(at(&bytes(5, &[32])), at(&admins)));
        let mut other = admins.clone();
        other[0] = 2;
        assert!(!equal(at(&admins), at(&other)));
        assert!(equal(at(&bytes(5, &[])), at(&bytes(5, &[]))));
    }

    #[test]
    fn the_parts_of_a_sid() {
        let big = bytes(5, &[u32::MAX, 0x8000_0000, 7]);
        assert_eq!(authority(&big), [0, 0, 0, 0, 0, 5]);
        assert_eq!(
            sub_authorities(&big).collect::<Vec<_>>(),
            [u32::MAX, 0x8000_0000, 7]
        );
        assert_eq!(sub_authorities(&bytes(5, &[])).count(), 0);
        // Only as many as the count says, whatever follows.
        let mut longer = bytes(5, &[18]);
        longer.extend([9, 9, 9, 9]);
        assert_eq!(sub_authorities(&longer).collect::<Vec<_>>(), [18]);
    }

    #[test]
    fn a_new_acl_is_a_header() {
        assert_eq!(new_acl(64, 2), Ok([2, 0, 64, 0, 0, 0, 0, 0]));
        assert_eq!(new_acl(64, 4), Ok([4, 0, 64, 0, 0, 0, 0, 0]));
        assert_eq!(new_acl(8, 3), Ok([3, 0, 8, 0, 0, 0, 0, 0]));
        assert_eq!(new_acl(67, 2), Ok([2, 0, 64, 0, 0, 0, 0, 0]));
        assert_eq!(new_acl(0xFFFF, 2), Ok([2, 0, 0xFC, 0xFF, 0, 0, 0, 0]));
        assert_eq!(new_acl(64, 1), Err(NewAclError::Invalid));
        assert_eq!(new_acl(64, 5), Err(NewAclError::Invalid));
        assert_eq!(new_acl(0x1_0000, 2), Err(NewAclError::Invalid));
        assert_eq!(new_acl(4, 2), Err(NewAclError::TooSmall));
        assert_eq!(new_acl(7, 9), Err(NewAclError::TooSmall));
    }

    const PACKAGE: [u32; 12] = [2, 11, 22, 33, 44, 55, 66, 77, 1001, 1002, 1003, 1004];

    #[test]
    fn app_container_sids_are_told_apart() {
        use AppContainerSidType::*;
        for (sid, expected) in [
            (bytes(5, &[18]), NotAppContainer),
            (bytes(5, &PACKAGE[..8]), NotAppContainer),
            (bytes(15, &PACKAGE[..8]), Parent),
            (bytes(15, &PACKAGE), Child),
            // All application packages, S-1-15-2-1.
            (bytes(15, &[2, 1]), Invalid),
            (bytes(15, &PACKAGE[..9]), Invalid),
            (bytes(15, &PACKAGE[..1]), Invalid),
            // A capability, S-1-15-3-1, and the authority alone.
            (bytes(15, &[3, 1]), NotAppContainer),
            (bytes(15, &[3, 1, 2, 3, 4, 5, 6, 7]), NotAppContainer),
            (bytes(15, &[]), NotAppContainer),
        ] {
            assert_eq!(app_container_sid_type(&sid), expected, "{sid:?}");
        }
        // An authority that only ends in 15.
        let mut other = bytes(15, &PACKAGE[..8]);
        other[2] = 1;
        assert_eq!(app_container_sid_type(&other), NotAppContainer);
    }

    #[test]
    fn a_childs_parent_is_its_first_eight_sub_authorities() {
        let (parent, length) = app_container_parent(&bytes(15, &PACKAGE)).unwrap();
        assert_eq!(parent[..length], bytes(15, &PACKAGE[..8])[..]);
        assert!(parent[length..].iter().all(|&b| b == 0));
        assert_eq!(app_container_parent(&bytes(15, &PACKAGE[..8])), None);
        assert_eq!(app_container_parent(&bytes(15, &[2, 1])), None);
        assert_eq!(app_container_parent(&bytes(5, &[18])), None);
    }
}
