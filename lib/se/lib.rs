//! Security identifiers, access lists and security descriptors, as the
//! bytes Windows lays them out in. Pure: everything here works on byte
//! slices and can be tested on the host.
//!
//! - A SID is a revision, a count, a 6-byte authority, and that many
//!   32-bit sub-authorities: 8 + 4n bytes.
//! - An ACL is an 8-byte header (revision, size of the whole list in
//!   bytes, number of entries) followed by its entries, each with its
//!   own 4-byte header (type, flags, size).
//! - A security descriptor points to an owner, a group and two ACLs. An
//!   absolute one holds pointers; a self-relative one is a single block
//!   holding offsets, with the parts after a 20-byte header.

#![cfg_attr(not(test), no_std)]

extern crate alloc;

pub mod access;
pub mod acl;
pub mod assign;
pub mod descriptor;
pub mod privilege;
pub mod token;

/// The revision of every SID.
pub const SID_REVISION: u8 = 1;
/// The most sub-authorities a SID may have.
pub const SID_MAX_SUB_AUTHORITIES: usize = 15;
/// The largest a SID can be.
pub const SID_MAX_SIZE: usize = 8 + 4 * SID_MAX_SUB_AUTHORITIES;

/// The revision `RtlCreateSecurityDescriptor` accepts.
pub const SECURITY_DESCRIPTOR_REVISION: u8 = 1;
/// `ACL_REVISION`, and the highest revision an ACL may have.
pub const ACL_REVISION: u8 = 2;
pub const ACL_REVISION4: u8 = 4;
/// Size of an ACL's header.
pub const ACL_HEADER: usize = 8;
/// `ACCESS_ALLOWED_ACE_TYPE`.
pub const ACCESS_ALLOWED_ACE: u8 = 0;

/// `SECURITY_DESCRIPTOR_CONTROL` bits.
pub const SE_OWNER_DEFAULTED: u16 = 0x0001;
pub const SE_GROUP_DEFAULTED: u16 = 0x0002;
pub const SE_DACL_PRESENT: u16 = 0x0004;
pub const SE_DACL_DEFAULTED: u16 = 0x0008;
pub const SE_SACL_PRESENT: u16 = 0x0010;
pub const SE_SACL_DEFAULTED: u16 = 0x0020;
pub const SE_DACL_AUTO_INHERITED: u16 = 0x0400;
pub const SE_SACL_AUTO_INHERITED: u16 = 0x0800;
pub const SE_DACL_PROTECTED: u16 = 0x1000;
pub const SE_SACL_PROTECTED: u16 = 0x2000;
pub const SE_SELF_RELATIVE: u16 = 0x8000;

/// Size of a self-relative descriptor's header.
pub const RELATIVE_HEADER: usize = 20;
/// Size of an absolute descriptor on a 64-bit system.
pub const ABSOLUTE_SIZE: usize = 40;

/// The length of a SID with `sub_authorities` sub-authorities.
pub const fn sid_length(sub_authorities: usize) -> usize {
    8 + 4 * sub_authorities
}

/// A well-known SID, built in place: its bytes and their count.
pub const fn sid(authority: u8, sub_authorities: &[u32]) -> ([u8; SID_MAX_SIZE], usize) {
    let mut bytes = [0u8; SID_MAX_SIZE];
    bytes[0] = SID_REVISION;
    bytes[1] = sub_authorities.len() as u8;
    // The authority is six bytes, big endian; every well-known one fits
    // in the last.
    bytes[7] = authority;
    let mut i = 0;
    while i < sub_authorities.len() {
        let sub = sub_authorities[i].to_le_bytes();
        let at = 8 + 4 * i;
        bytes[at] = sub[0];
        bytes[at + 1] = sub[1];
        bytes[at + 2] = sub[2];
        bytes[at + 3] = sub[3];
        i += 1;
    }
    (bytes, sid_length(sub_authorities.len()))
}

/// The length of the SID that starts `bytes`, if it is a valid one that
/// fits.
pub fn valid_sid(bytes: &[u8]) -> Option<usize> {
    let (&revision, &count) = (bytes.first()?, bytes.get(1)?);
    let length = sid_length(usize::from(count));
    (revision == SID_REVISION
        && usize::from(count) <= SID_MAX_SUB_AUTHORITIES
        && bytes.len() >= length)
        .then_some(length)
}

fn u16_at(bytes: &[u8], at: usize) -> Option<u16> {
    Some(u16::from_le_bytes([*bytes.get(at)?, *bytes.get(at + 1)?]))
}

/// What is wrong with a request to change an ACL, as the status Windows
/// gives for it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AclError {
    /// `STATUS_INVALID_SID`
    InvalidSid,
    /// `STATUS_REVISION_MISMATCH`
    RevisionMismatch,
    /// `STATUS_INVALID_ACL`
    InvalidAcl,
    /// `STATUS_ALLOTTED_SPACE_EXCEEDED`
    NoRoom,
}

/// An ACL's size and entry count, if its header is sound and it fits in
/// `acl`.
fn acl_header(acl: &[u8]) -> Option<(usize, usize)> {
    let size = usize::from(u16_at(acl, 2)?);
    let count = usize::from(u16_at(acl, 4)?);
    (acl[0] >= ACL_REVISION && acl[0] <= ACL_REVISION4 && size >= ACL_HEADER && size <= acl.len())
        .then_some((size, count))
}

/// Where the first unused byte of an ACL is: after its last entry.
/// `None` if the entries do not fit the list's size.
pub fn acl_used(acl: &[u8]) -> Option<usize> {
    let (size, count) = acl_header(acl)?;
    let mut at = ACL_HEADER;
    for _ in 0..count {
        let entry = usize::from(u16_at(acl, at + 2)?);
        if entry < 4 || at + entry > size {
            return None;
        }
        at += entry;
    }
    Some(at)
}

/// Append an entry allowing `mask` to `sid` (`RtlAddAccessAllowedAce`).
/// `acl` is the list's storage, at least as long as its `AclSize`.
pub fn add_access_allowed(
    acl: &mut [u8],
    revision: u32,
    mask: u32,
    sid: &[u8],
) -> Result<(), AclError> {
    let sid_len = valid_sid(sid).ok_or(AclError::InvalidSid)?;
    if acl.first().is_none_or(|&r| r > ACL_REVISION4) || revision > u32::from(ACL_REVISION4) {
        return Err(AclError::RevisionMismatch);
    }
    let (size, count) = acl_header(acl).ok_or(AclError::InvalidAcl)?;
    let at = acl_used(acl).ok_or(AclError::InvalidAcl)?;
    // Type, flags, size, mask, then the SID.
    let entry = 8 + sid_len;
    if at + entry > size {
        return Err(AclError::NoRoom);
    }
    acl[at] = ACCESS_ALLOWED_ACE;
    acl[at + 1] = 0;
    acl[at + 2..at + 4].copy_from_slice(&(entry as u16).to_le_bytes());
    acl[at + 4..at + 8].copy_from_slice(&mask.to_le_bytes());
    acl[at + 8..at + entry].copy_from_slice(&sid[..sid_len]);
    acl[4..6].copy_from_slice(&(count as u16 + 1).to_le_bytes());
    // The list takes the higher of its revision and the entry's.
    acl[0] = acl[0].max(revision as u8);
    Ok(())
}

/// Round up to a multiple of four, as the parts of a descriptor are.
pub const fn aligned(length: usize) -> usize {
    (length + 3) & !3
}

/// A security descriptor's parts, whichever layout they came from. Each
/// part is its bytes, exactly as long as it says it is.
#[derive(Debug, Clone, Copy, Default)]
pub struct Parts<'a> {
    pub control: u16,
    pub owner: Option<&'a [u8]>,
    pub group: Option<&'a [u8]>,
    pub sacl: Option<&'a [u8]>,
    pub dacl: Option<&'a [u8]>,
}

impl Parts<'_> {
    /// The sum of the parts' lengths, each rounded up to four bytes.
    pub fn parts_length(&self) -> usize {
        [self.owner, self.group, self.sacl, self.dacl]
            .iter()
            .flatten()
            .map(|part| aligned(part.len()))
            .sum()
    }

    /// How long the self-relative form is.
    pub fn relative_length(&self) -> usize {
        RELATIVE_HEADER + self.parts_length()
    }

    /// Write the self-relative form into `out`
    /// (`RtlAbsoluteToSelfRelativeSD`): the header, then SACL, DACL,
    /// owner and group. `Err` with the length needed if `out` is short.
    pub fn write_relative(&self, out: &mut [u8]) -> Result<usize, usize> {
        let total = self.relative_length();
        let Some(out) = out.get_mut(..total) else {
            return Err(total);
        };
        out.fill(0);
        out[0] = SECURITY_DESCRIPTOR_REVISION;
        out[2..4].copy_from_slice(&(self.control | SE_SELF_RELATIVE).to_le_bytes());
        let mut at = RELATIVE_HEADER;
        // (the part, where in the header its offset goes)
        for (part, field) in [
            (self.sacl, 12),
            (self.dacl, 16),
            (self.owner, 4),
            (self.group, 8),
        ] {
            if let Some(part) = part {
                out[at..at + part.len()].copy_from_slice(part);
                out[field..field + 4].copy_from_slice(&(at as u32).to_le_bytes());
                at += aligned(part.len());
            }
        }
        Ok(total)
    }
}

/// `SECURITY_INFORMATION` bits: which parts of a descriptor a request
/// is about.
pub const OWNER_SECURITY_INFORMATION: u32 = 1;
pub const GROUP_SECURITY_INFORMATION: u32 = 2;
pub const DACL_SECURITY_INFORMATION: u32 = 4;
pub const SACL_SECURITY_INFORMATION: u32 = 8;

/// What is wrong with a descriptor's parts, as the status Windows gives
/// for it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Invalid {
    /// `STATUS_INVALID_SID`
    Sid,
    /// `STATUS_INVALID_ACL`
    Acl,
}

impl<'a> Parts<'a> {
    /// Whether every part is what it should be: owner and group sound
    /// SIDs, the lists sound ACLs.
    pub fn validate(&self) -> Result<(), Invalid> {
        for sid in [self.owner, self.group].into_iter().flatten() {
            if valid_sid(sid) != Some(sid.len()) {
                return Err(Invalid::Sid);
            }
        }
        for acl in [self.sacl, self.dacl].into_iter().flatten() {
            if acl_used(acl).is_none() {
                return Err(Invalid::Acl);
            }
        }
        Ok(())
    }

    /// This descriptor as its control bits say to read it: an ACL not
    /// marked present is not there, whatever the field holds.
    #[must_use]
    pub fn present(&self) -> Parts<'a> {
        let mut parts = *self;
        if parts.control & SE_DACL_PRESENT == 0 {
            parts.dacl = None;
        }
        if parts.control & SE_SACL_PRESENT == 0 {
            parts.sacl = None;
        }
        parts
    }

    /// This descriptor with the parts `information` names replaced by
    /// those of `new`, control bits included: what setting an object's
    /// security does to the descriptor it has.
    #[must_use]
    pub fn replaced(&self, new: &Parts<'a>, information: u32) -> Parts<'a> {
        self.merged(
            new,
            information,
            SE_DACL_PRESENT | SE_DACL_DEFAULTED,
            SE_SACL_PRESENT | SE_SACL_DEFAULTED,
        )
    }

    /// The parts `information` names and nothing else, each with every
    /// control bit that describes it: what querying an object's security
    /// copies out.
    #[must_use]
    pub fn selected(&self, information: u32) -> Parts<'a> {
        Parts::default().merged(
            self,
            information,
            SE_DACL_PRESENT | SE_DACL_DEFAULTED | SE_DACL_AUTO_INHERITED | SE_DACL_PROTECTED,
            SE_SACL_PRESENT | SE_SACL_DEFAULTED | SE_SACL_AUTO_INHERITED | SE_SACL_PROTECTED,
        )
    }

    /// This descriptor with the parts `information` names taken from
    /// `new`, along with their control bits: `dacl_bits` and `sacl_bits`
    /// for the lists, the "defaulted" bit for owner and group.
    fn merged(
        &self,
        new: &Parts<'a>,
        information: u32,
        dacl_bits: u16,
        sacl_bits: u16,
    ) -> Parts<'a> {
        let mut merged = *self;
        let mut take = |bit: u32, control: u16| {
            let chosen = information & bit != 0;
            if chosen {
                merged.control = merged.control & !control | new.control & control;
            }
            chosen
        };
        if take(OWNER_SECURITY_INFORMATION, SE_OWNER_DEFAULTED) {
            merged.owner = new.owner;
        }
        if take(GROUP_SECURITY_INFORMATION, SE_GROUP_DEFAULTED) {
            merged.group = new.group;
        }
        if take(DACL_SECURITY_INFORMATION, dacl_bits) {
            merged.dacl = new.dacl;
        }
        if take(SACL_SECURITY_INFORMATION, sacl_bits) {
            merged.sacl = new.sacl;
        }
        merged
    }
}

/// Read a self-relative descriptor. `None` if a part lies outside the
/// block or is not what it should be.
pub fn parse_relative(block: &[u8]) -> Option<Parts<'_>> {
    let control = u16_at(block, 2)?;
    if block.len() < RELATIVE_HEADER || control & SE_SELF_RELATIVE == 0 {
        return None;
    }
    let offset = |field: usize| {
        Some(u32::from_le_bytes(block.get(field..field + 4)?.try_into().ok()?) as usize)
    };
    let sid = |field: usize| -> Option<Option<&[u8]>> {
        match offset(field)? {
            0 => Some(None),
            at => {
                let rest = block.get(at..)?;
                Some(Some(&rest[..valid_sid(rest)?]))
            }
        }
    };
    let acl = |field: usize| -> Option<Option<&[u8]>> {
        match offset(field)? {
            0 => Some(None),
            at => {
                let rest = block.get(at..)?;
                Some(Some(&rest[..acl_header(rest)?.0]))
            }
        }
    };
    Some(Parts {
        control,
        owner: sid(4)?,
        group: sid(8)?,
        sacl: acl(12)?,
        dacl: acl(16)?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn system() -> Vec<u8> {
        let (bytes, len) = sid(5, &[18]);
        bytes[..len].to_vec()
    }

    fn admins() -> Vec<u8> {
        let (bytes, len) = sid(5, &[32, 544]);
        bytes[..len].to_vec()
    }

    fn empty_acl(room: usize) -> Vec<u8> {
        let mut acl = vec![0u8; room];
        acl[0] = ACL_REVISION;
        acl[2..4].copy_from_slice(&(room as u16).to_le_bytes());
        acl
    }

    #[test]
    fn well_known_sids() {
        // S-1-5-18, the system.
        assert_eq!(system(), [1, 1, 0, 0, 0, 0, 0, 5, 18, 0, 0, 0]);
        // S-1-5-32-544, administrators.
        assert_eq!(
            admins(),
            [1, 2, 0, 0, 0, 0, 0, 5, 32, 0, 0, 0, 0x20, 2, 0, 0]
        );
        // S-1-1-0, everyone.
        let (world, len) = sid(1, &[0]);
        assert_eq!((len, &world[..8]), (12, &[1, 1, 0, 0, 0, 0, 0, 1][..]));
        assert_eq!(sid_length(0), 8);
        assert_eq!(valid_sid(&system()), Some(12));
        assert_eq!(valid_sid(&admins()), Some(16));
    }

    #[test]
    fn what_is_not_a_sid() {
        assert_eq!(valid_sid(&[]), None);
        assert_eq!(valid_sid(&[1]), None);
        assert_eq!(valid_sid(&system()[..11]), None, "cut short");
        let mut wrong = system();
        wrong[0] = 2;
        assert_eq!(valid_sid(&wrong), None, "another revision");
        let mut many = vec![1, 16];
        many.resize(8 + 64, 0);
        assert_eq!(valid_sid(&many), None, "too many sub-authorities");
    }

    #[test]
    fn entries_are_appended_until_the_list_is_full() {
        let mut acl = empty_acl(64);
        assert_eq!(acl_used(&acl), Some(8));
        assert_eq!(
            add_access_allowed(&mut acl, 2, 0x1000_0000, &system()),
            Ok(())
        );
        assert_eq!(
            add_access_allowed(&mut acl, 2, 0x1000_0000, &admins()),
            Ok(())
        );
        // Two entries: 8 + 12 and 8 + 16 bytes after the header.
        assert_eq!(
            (u16_at(&acl, 4), acl_used(&acl)),
            (Some(2), Some(8 + 20 + 24))
        );
        // The first entry, byte for byte.
        assert_eq!(acl[8..16], [0, 0, 20, 0, 0, 0, 0, 0x10]);
        assert_eq!(acl[16..28], system()[..]);
        // 12 bytes are left: not enough for another.
        assert_eq!(
            add_access_allowed(&mut acl, 2, 1, &system()),
            Err(AclError::NoRoom)
        );
        assert_eq!(u16_at(&acl, 4), Some(2), "a refused entry changes nothing");
        // Exactly enough room is enough.
        let mut exact = empty_acl(8 + 20);
        assert_eq!(add_access_allowed(&mut exact, 2, 1, &system()), Ok(()));
        assert_eq!(
            add_access_allowed(&mut exact, 2, 1, &system()),
            Err(AclError::NoRoom)
        );
    }

    #[test]
    fn requests_that_are_refused() {
        let mut acl = empty_acl(64);
        assert_eq!(
            add_access_allowed(&mut acl, 7, 1, &system()),
            Err(AclError::RevisionMismatch)
        );
        assert_eq!(
            add_access_allowed(&mut acl, 2, 1, &system()[..5]),
            Err(AclError::InvalidSid)
        );
        let mut newer = empty_acl(64);
        newer[0] = 9;
        assert_eq!(
            add_access_allowed(&mut newer, 2, 1, &system()),
            Err(AclError::RevisionMismatch)
        );
        // A list that claims to be larger than its storage.
        let mut lying = empty_acl(64);
        lying[2..4].copy_from_slice(&200u16.to_le_bytes());
        assert_eq!(
            add_access_allowed(&mut lying, 2, 1, &system()),
            Err(AclError::InvalidAcl)
        );
        // A list whose entries run past its end.
        let mut broken = empty_acl(64);
        broken[4] = 3;
        assert_eq!(acl_used(&broken), None);
        assert_eq!(
            add_access_allowed(&mut broken, 2, 1, &system()),
            Err(AclError::InvalidAcl)
        );
        // A higher revision of entry raises the list's.
        assert_eq!(add_access_allowed(&mut acl, 4, 1, &system()), Ok(()));
        assert_eq!(acl[0], 4);
        assert_eq!(
            add_access_allowed(&mut [], 2, 1, &system()),
            Err(AclError::RevisionMismatch)
        );
    }

    #[test]
    fn a_descriptor_survives_the_self_relative_form() {
        let mut acl = empty_acl(64);
        add_access_allowed(&mut acl, 2, 0x1000_0000, &system()).unwrap();
        let (owner, group) = (admins(), system());
        let parts = Parts {
            control: SE_DACL_PRESENT,
            owner: Some(&owner),
            group: Some(&group),
            sacl: None,
            dacl: Some(&acl),
        };
        assert_eq!(parts.relative_length(), 20 + 64 + 16 + 12);
        let mut block = [0xEEu8; 200];
        // Too short: told how long.
        assert_eq!(parts.write_relative(&mut block[..50]), Err(112));
        assert_eq!(parts.write_relative(&mut []), Err(112));
        assert_eq!(parts.write_relative(&mut block), Ok(112));
        // Header: revision 1, the control bits plus "self-relative";
        // DACL right after the header, then owner, then group.
        assert_eq!(block[..4], [1, 0, 0x04, 0x80]);
        let field = |at: usize| u32::from_le_bytes(block[at..at + 4].try_into().unwrap());
        assert_eq!((field(4), field(8), field(12), field(16)), (84, 100, 0, 20));
        assert_eq!(block[112], 0xEE, "nothing past the length reported");
        let back = parse_relative(&block[..112]).unwrap();
        assert_eq!(back.control, SE_DACL_PRESENT | SE_SELF_RELATIVE);
        assert_eq!(
            (back.owner, back.group, back.sacl),
            (Some(&owner[..]), Some(&group[..]), None)
        );
        assert_eq!(back.dacl, Some(&acl[..]));
    }

    #[test]
    fn setting_security_replaces_only_the_parts_named() {
        let (mut old_acl, mut new_acl) = (empty_acl(32), empty_acl(40));
        add_access_allowed(&mut old_acl, 2, 1, &system()).unwrap();
        add_access_allowed(&mut new_acl, 2, 2, &admins()).unwrap();
        let (sys, adm) = (system(), admins());
        let old = Parts {
            control: SE_DACL_PRESENT | SE_DACL_DEFAULTED | SE_OWNER_DEFAULTED,
            owner: Some(&sys),
            group: Some(&sys),
            sacl: None,
            dacl: Some(&old_acl),
        };
        let new = Parts {
            control: SE_DACL_PRESENT | SE_GROUP_DEFAULTED | SE_SACL_PRESENT,
            owner: Some(&adm),
            group: None,
            sacl: Some(&new_acl),
            dacl: Some(&new_acl),
        };
        // Nothing named: nothing changes.
        let same = old.replaced(&new, 0);
        assert_eq!(
            (same.control, same.owner, same.dacl),
            (old.control, old.owner, old.dacl)
        );
        // The DACL alone: it and its two control bits.
        let dacl = old.replaced(&new, DACL_SECURITY_INFORMATION);
        assert_eq!(dacl.dacl, Some(&new_acl[..]));
        assert_eq!(dacl.control, SE_DACL_PRESENT | SE_OWNER_DEFAULTED);
        assert_eq!(
            (dacl.owner, dacl.group, dacl.sacl),
            (old.owner, old.group, None)
        );
        // Everything.
        let all = old.replaced(&new, 0xF);
        assert_eq!((all.owner, all.group), (Some(&adm[..]), None));
        assert_eq!(
            (all.sacl, all.dacl),
            (Some(&new_acl[..]), Some(&new_acl[..]))
        );
        assert_eq!(all.control, new.control);
        // Owner and group, one at a time.
        assert_eq!(
            old.replaced(&new, OWNER_SECURITY_INFORMATION).control,
            SE_DACL_PRESENT | SE_DACL_DEFAULTED
        );
        let group = old.replaced(&new, GROUP_SECURITY_INFORMATION);
        assert_eq!((group.group, group.owner), (None, old.owner));
        assert_eq!(group.control, old.control | SE_GROUP_DEFAULTED);
        assert_eq!(
            old.replaced(&new, SACL_SECURITY_INFORMATION).sacl,
            Some(&new_acl[..])
        );
    }

    #[test]
    fn an_acl_not_marked_present_is_not_there() {
        let acl = empty_acl(8);
        let both = Parts {
            control: SE_DACL_PRESENT | SE_SACL_PRESENT,
            sacl: Some(&acl),
            dacl: Some(&acl),
            ..Parts::default()
        };
        let kept = both.present();
        assert_eq!((kept.sacl, kept.dacl), (Some(&acl[..]), Some(&acl[..])));
        let dacl_only = Parts {
            control: SE_DACL_PRESENT,
            ..both
        }
        .present();
        assert_eq!((dacl_only.sacl, dacl_only.dacl), (None, Some(&acl[..])));
        let neither = Parts { control: 0, ..both }.present();
        assert!(neither.sacl.is_none() && neither.dacl.is_none());
    }

    #[test]
    fn parts_are_validated() {
        let (acl, sys) = (empty_acl(32), system());
        let good = Parts {
            control: SE_DACL_PRESENT,
            owner: Some(&sys),
            group: None,
            sacl: None,
            dacl: Some(&acl),
        };
        assert_eq!(good.validate(), Ok(()));
        assert_eq!(Parts::default().validate(), Ok(()));
        let mut bad_sid = system();
        bad_sid[0] = 3;
        assert_eq!(
            Parts {
                group: Some(&bad_sid),
                ..good
            }
            .validate(),
            Err(Invalid::Sid)
        );
        // A slice longer than the SID in it is not that SID.
        let long = [&system()[..], &[0, 0]].concat();
        assert_eq!(
            Parts {
                owner: Some(&long),
                ..good
            }
            .validate(),
            Err(Invalid::Sid)
        );
        let mut bad_acl = empty_acl(32);
        bad_acl[4] = 2;
        assert_eq!(
            Parts {
                sacl: Some(&bad_acl),
                ..good
            }
            .validate(),
            Err(Invalid::Acl)
        );
    }

    #[test]
    fn an_empty_descriptor_is_just_a_header() {
        let parts = Parts::default();
        let mut block = [0u8; 20];
        assert_eq!(parts.write_relative(&mut block), Ok(20));
        assert_eq!(block[..4], [1, 0, 0, 0x80]);
        let back = parse_relative(&block).unwrap();
        assert!(back.owner.is_none() && back.dacl.is_none());
        assert_eq!(aligned(0), 0);
        assert_eq!((aligned(13), aligned(16)), (16, 16));
    }

    #[test]
    fn a_damaged_self_relative_descriptor_is_refused() {
        assert!(parse_relative(&[]).is_none());
        assert!(
            parse_relative(&[1, 0, 0, 0x80]).is_none(),
            "shorter than its header"
        );
        let mut absolute = [0u8; 20];
        absolute[0] = 1;
        assert!(
            parse_relative(&absolute).is_none(),
            "not marked self-relative"
        );
        let mut block = [0u8; 40];
        Parts::default().write_relative(&mut block[..20]).unwrap();
        // An owner offset past the end; one pointing at what is no SID.
        block[4] = 200;
        assert!(parse_relative(&block).is_none());
        block[4] = 20;
        assert!(parse_relative(&block).is_none());
        // A DACL offset pointing at what is no ACL.
        block[4] = 0;
        block[16] = 24;
        assert!(parse_relative(&block).is_none());
    }
}
