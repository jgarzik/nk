//! The entries of an access list (ACEs), read one at a time.
//!
//! Every entry starts with a type, flags and its own size. The four
//! basic types (allow, deny, audit, alarm) follow that with an access
//! mask and a SID. The others (object-specific, conditional "callback",
//! mandatory label, resource attribute, scoped policy, process trust
//! label) are walked over by their size and never interpreted here.
//! Layouts: <https://learn.microsoft.com/en-us/windows/win32/secauthz/ace>

use crate::access::{GenericMapping, map_generic};
use crate::token::{CREATOR_GROUP, CREATOR_OWNER};
use crate::{ACL_HEADER, acl_used, u16_at, valid_sid};
use alloc::vec::Vec;

/// ACE types with a mask and a SID and nothing else. `ACCESS_ALLOWED_ACE`
/// is zero.
pub const ACCESS_DENIED_ACE: u8 = 1;
pub const SYSTEM_AUDIT_ACE: u8 = 2;
pub const SYSTEM_ALARM_ACE: u8 = 3;

/// ACE flags.
pub const OBJECT_INHERIT_ACE: u8 = 0x01;
pub const CONTAINER_INHERIT_ACE: u8 = 0x02;
pub const NO_PROPAGATE_INHERIT_ACE: u8 = 0x04;
pub const INHERIT_ONLY_ACE: u8 = 0x08;
pub const INHERITED_ACE: u8 = 0x10;

/// One entry of an access list.
#[derive(Debug, Clone, Copy)]
pub struct Ace<'a> {
    pub kind: u8,
    pub flags: u8,
    /// The whole entry, header included.
    pub bytes: &'a [u8],
}

impl<'a> Ace<'a> {
    /// The access mask and SID of an entry of a basic type. `None` for
    /// the other types, and for an entry too short for what it claims.
    pub fn basic(&self) -> Option<(u32, &'a [u8])> {
        if self.kind > SYSTEM_ALARM_ACE {
            return None;
        }
        let mask = u32::from_le_bytes(self.bytes.get(4..8)?.try_into().ok()?);
        let rest = self.bytes.get(8..)?;
        Some((mask, &rest[..valid_sid(rest)?]))
    }
}

/// The entries of `acl`, in the order stored. An unsound list (see
/// `acl_used`) has none.
pub fn aces(acl: &[u8]) -> impl Iterator<Item = Ace<'_>> {
    let end = acl_used(acl).unwrap_or(ACL_HEADER);
    let mut at = ACL_HEADER;
    core::iter::from_fn(move || {
        if at >= end {
            return None;
        }
        // `acl_used` saw every entry inside the list.
        let size = usize::from(u16_at(acl, at + 2)?);
        let bytes = &acl[at..at + size];
        at += size;
        Some(Ace {
            kind: bytes[0],
            flags: bytes[1],
            bytes,
        })
    })
}

/// Whether entries of this type carry object-type GUIDs: the
/// object-specific allow, deny, audit and alarm entries and their
/// conditional forms.
pub const fn object_specific(kind: u8) -> bool {
    matches!(kind, 5..=8 | 11 | 12 | 15 | 16)
}

/// `ace` with other flags.
pub fn with_flags(ace: &Ace<'_>, flags: u8) -> Vec<u8> {
    let mut bytes = ace.bytes.to_vec();
    bytes[1] = flags;
    bytes
}

/// `ace` as it takes effect on an object, with `flags`: generic rights
/// mapped, and the creator-owner and creator-group SIDs replaced by the
/// object's (`creator`: owner, group) when given. Only entries of a
/// basic type are changed.
pub fn resolved(
    ace: &Ace<'_>,
    flags: u8,
    mapping: &GenericMapping,
    creator: Option<(&[u8], &[u8])>,
) -> Vec<u8> {
    let Some((mask, sid)) = ace.basic() else {
        return with_flags(ace, flags);
    };
    let sid = match creator {
        Some((owner, _)) if sid == CREATOR_OWNER => owner,
        Some((_, group)) if sid == CREATOR_GROUP => group,
        _ => sid,
    };
    let mut bytes = Vec::with_capacity(8 + sid.len());
    bytes.extend([ace.kind, flags]);
    bytes.extend((8 + sid.len() as u16).to_le_bytes());
    bytes.extend(map_generic(mask, mapping).to_le_bytes());
    bytes.extend(sid);
    bytes
}

/// A list of `entries` and nothing more. `None` if they are more than a
/// list can hold.
pub fn build(revision: u8, entries: &[Vec<u8>]) -> Option<Vec<u8>> {
    let size = ACL_HEADER + entries.iter().map(Vec::len).sum::<usize>();
    let mut acl = Vec::with_capacity(size);
    acl.extend([revision, 0]);
    acl.extend(u16::try_from(size).ok()?.to_le_bytes());
    // Fewer entries than bytes.
    acl.extend((entries.len() as u16).to_le_bytes());
    acl.extend([0, 0]);
    for entry in entries {
        acl.extend(entry);
    }
    Some(acl)
}

/// `acl` as an object is given it when it is supplied for the object
/// or is a token's default, as the pinned kernel's `RtlpApplyAclToObject`
/// leaves a copy of it: the whole list, spare room included, with the
/// mask of every entry that takes effect there (is not inherit-only)
/// mapped and then kept within what "generic all" maps to; an audit or
/// alarm entry may also name `ACCESS_SYSTEM_SECURITY`. No SID is
/// changed: the creator-owner and creator-group SIDs are replaced only
/// in entries inherited from a parent. The entries so treated are those
/// that start with a mask: allow, deny, audit and alarm, their
/// object-specific forms, the compound entry, and the conditional
/// allow, deny, audit and alarm.
/// `None` if the list is damaged.
pub fn applied(acl: &[u8], mapping: &GenericMapping) -> Option<Vec<u8>> {
    /// `ACCESS_SYSTEM_SECURITY`.
    const SYSTEM_SECURITY: u32 = 0x0100_0000;
    /// The four generic rights.
    const GENERIC: u32 = 0xF000_0000;
    acl_used(acl)?;
    let mut copy = acl.to_vec();
    let mut at = ACL_HEADER;
    for ace in aces(acl) {
        let mask_at = at + 4;
        at += ace.bytes.len();
        let masked = matches!(ace.kind, 0..=10 | 13 | 14);
        if !masked || ace.flags & INHERIT_ONLY_ACE != 0 || ace.bytes.len() < 8 {
            continue;
        }
        let grants = matches!(ace.kind, 0 | 1 | 4 | 5 | 6 | 9 | 10);
        let within = mapping.all | if grants { 0 } else { SYSTEM_SECURITY };
        let mask = u32::from_le_bytes([
            copy[mask_at],
            copy[mask_at + 1],
            copy[mask_at + 2],
            copy[mask_at + 3],
        ]);
        let mapped = map_generic(mask, mapping) & !GENERIC & within;
        copy[mask_at..mask_at + 4].copy_from_slice(&mapped.to_le_bytes());
    }
    Some(copy)
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    /// An entry of a basic type.
    pub(crate) fn entry(kind: u8, flags: u8, mask: u32, sid: &[u8]) -> Vec<u8> {
        let mut bytes = vec![kind, flags];
        bytes.extend((8 + sid.len() as u16).to_le_bytes());
        bytes.extend(mask.to_le_bytes());
        bytes.extend(sid);
        bytes
    }

    /// A list of exactly these entries.
    pub(crate) fn list(entries: &[Vec<u8>]) -> Vec<u8> {
        build(2, entries).unwrap()
    }

    const MAPPING: GenericMapping = GenericMapping {
        read: 1,
        write: 2,
        execute: 4,
        all: 7,
    };

    #[test]
    fn a_list_is_built_from_its_entries() {
        let entries = [entry(0, 0, 1, &WORLD), entry(1, 2, 3, &WORLD)];
        let acl = build(4, &entries).unwrap();
        assert_eq!(acl[..8], [4, 0, 48, 0, 2, 0, 0, 0]);
        assert_eq!(acl[8..28], entries[0][..]);
        assert_eq!(acl[28..], entries[1][..]);
        assert_eq!(acl_used(&acl), Some(48));
        assert_eq!(build(2, &[]).unwrap(), [2, 0, 8, 0, 0, 0, 0, 0]);
        // 65 528 bytes of entries is 8 too many.
        let big = vec![0u8; 8 + 68];
        assert!(build(2, &vec![big.clone(); 862]).is_some());
        assert!(build(2, &vec![big; 863]).is_none());
    }

    #[test]
    fn an_entry_takes_effect_mapped_and_with_the_creator_named() {
        use crate::access::{GENERIC_READ, GENERIC_WRITE};
        let (owner, group) = (
            &crate::token::ADMINISTRATORS[..],
            &crate::token::LOCAL_SYSTEM[..],
        );
        let acl = list(&[
            entry(0, 3, GENERIC_READ | 0x100, &WORLD),
            entry(1, 0, GENERIC_WRITE, &CREATOR_OWNER),
            entry(0, 0, 0x10, &CREATOR_GROUP),
            vec![5, 3, 8, 0, 0, 0, 0, 0x80],
        ]);
        let seen: Vec<Ace<'_>> = aces(&acl).collect();
        let creator = Some((owner, group));
        assert_eq!(
            resolved(&seen[0], 0x10, &MAPPING, creator),
            entry(0, 0x10, 0x101, &WORLD)
        );
        assert_eq!(
            resolved(&seen[1], 0, &MAPPING, creator),
            entry(1, 0, 2, owner)
        );
        assert_eq!(
            resolved(&seen[2], 0, &MAPPING, creator),
            entry(0, 0, 0x10, group)
        );
        // No creator given: the SIDs stay.
        assert_eq!(
            resolved(&seen[1], 0, &MAPPING, None),
            entry(1, 0, 2, &CREATOR_OWNER)
        );
        // Not a basic type: only the flags change.
        assert_eq!(
            resolved(&seen[3], 9, &MAPPING, creator),
            [5, 9, 8, 0, 0, 0, 0, 0x80]
        );
        assert_eq!(with_flags(&seen[0], 0)[..4], [0, 0, 20, 0]);
        for kind in 0..=20 {
            assert_eq!(
                object_specific(kind),
                [5, 6, 7, 8, 11, 12, 15, 16].contains(&kind)
            );
        }
    }

    const WORLD: [u8; 12] = crate::token::WORLD;

    #[test]
    fn a_list_is_applied_whole_with_its_effective_masks_mapped() {
        use crate::access::{GENERIC_ALL, GENERIC_READ, GENERIC_WRITE};
        const ASS: u32 = 0x0100_0000;
        let mut acl = list(&[
            // Mapped, and kept within "generic all" (7).
            entry(0, 0, GENERIC_READ | GENERIC_WRITE | 0x100, &WORLD),
            // The creator-owner SID stays.
            entry(1, 2, GENERIC_ALL | ASS, &CREATOR_OWNER),
            // Inherit-only: untouched.
            entry(0, INHERIT_ONLY_ACE | 1, GENERIC_READ, &WORLD),
            // Audit entries, plain and conditional: may name
            // ACCESS_SYSTEM_SECURITY.
            entry(2, 0x40, GENERIC_READ | ASS | 0x100, &WORLD),
            entry(13, 0x40, ASS | 2, &WORLD),
            // Object-specific allow and conditional allow: as allow.
            entry(5, 0, GENERIC_WRITE | ASS, &WORLD),
            entry(9, 0, GENERIC_ALL | 0x200, &WORLD),
            // Conditional object-specific allow, a mandatory label and
            // a type there is not: untouched.
            entry(11, 0, GENERIC_READ, &WORLD),
            entry(0x11, 0, GENERIC_READ, &WORLD),
            entry(0x30, 0, GENERIC_READ, &WORLD),
            // Too short for a mask.
            vec![0, 0, 4, 0],
        ]);
        // Spare room, with something in it.
        acl.extend([0xAB; 8]);
        acl[2] += 8;
        let mut want = list(&[
            entry(0, 0, 3, &WORLD),
            entry(1, 2, 7, &CREATOR_OWNER),
            entry(0, INHERIT_ONLY_ACE | 1, GENERIC_READ, &WORLD),
            entry(2, 0x40, ASS | 1, &WORLD),
            entry(13, 0x40, ASS | 2, &WORLD),
            entry(5, 0, 2, &WORLD),
            entry(9, 0, 7, &WORLD),
            entry(11, 0, GENERIC_READ, &WORLD),
            entry(0x11, 0, GENERIC_READ, &WORLD),
            entry(0x30, 0, GENERIC_READ, &WORLD),
            vec![0, 0, 4, 0],
        ]);
        want.extend([0xAB; 8]);
        want[2] += 8;
        assert_eq!(applied(&acl, &MAPPING), Some(want));
        // A generic right the mapping gives back is not kept.
        let odd = GenericMapping {
            read: GENERIC_READ | 1,
            ..MAPPING
        };
        assert_eq!(
            applied(&list(&[entry(0, 0, GENERIC_READ, &WORLD)]), &odd),
            Some(list(&[entry(0, 0, 1, &WORLD)]))
        );
        // Damaged: an entry it has no room for.
        acl[4] += 1;
        assert_eq!(applied(&acl, &MAPPING), None);
    }

    #[test]
    fn entries_come_in_the_order_stored() {
        // An object-specific allow entry: mask, flags, no GUIDs, SID.
        let mut object = vec![5, 0, 24, 0, 1, 0, 0, 0, 0, 0, 0, 0];
        object.extend(WORLD);
        let acl = list(&[
            entry(ACCESS_DENIED_ACE, INHERIT_ONLY_ACE, 0x10, &WORLD),
            object.clone(),
            entry(0, 0, 0x1234_5678, &crate::token::ADMINISTRATORS),
        ]);
        let seen: Vec<Ace<'_>> = aces(&acl).collect();
        assert_eq!(seen.len(), 3);
        assert_eq!((seen[0].kind, seen[0].flags), (1, INHERIT_ONLY_ACE));
        assert_eq!(seen[0].basic(), Some((0x10, &WORLD[..])));
        assert_eq!(seen[1].bytes, &object[..]);
        assert_eq!(seen[1].basic(), None, "not a basic type");
        assert_eq!(
            seen[2].basic(),
            Some((0x1234_5678, &crate::token::ADMINISTRATORS[..]))
        );
        assert_eq!(aces(&list(&[])).count(), 0);
    }

    #[test]
    fn a_damaged_list_or_entry_yields_nothing() {
        let mut acl = list(&[entry(0, 0, 1, &WORLD)]);
        acl[4] = 2;
        assert_eq!(aces(&acl).count(), 0, "claims an entry it has no room for");
        assert_eq!(aces(&[]).count(), 0);
        // A basic entry cut off before its mask, and one before its SID.
        let short = list(&[vec![0, 0, 4, 0]]);
        assert_eq!(aces(&short).next().unwrap().basic(), None);
        let no_sid = list(&[vec![0, 0, 12, 0, 1, 0, 0, 0, 1, 1, 0, 0]]);
        assert_eq!(aces(&no_sid).next().unwrap().basic(), None);
    }
}
