//! The entries of an access list (ACEs), read one at a time.
//!
//! Every entry starts with a type, flags and its own size. The four
//! basic types (allow, deny, audit, alarm) follow that with an access
//! mask and a SID. The others (object-specific, conditional "callback",
//! mandatory label, resource attribute, scoped policy, process trust
//! label) are walked over by their size and never interpreted here.
//! Layouts: <https://learn.microsoft.com/en-us/windows/win32/secauthz/ace>

use crate::{ACL_HEADER, acl_used, u16_at, valid_sid};

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
        let size = ACL_HEADER + entries.iter().map(Vec::len).sum::<usize>();
        let mut acl = vec![2, 0];
        acl.extend((size as u16).to_le_bytes());
        acl.extend((entries.len() as u16).to_le_bytes());
        acl.extend([0, 0]);
        acl.extend(entries.concat());
        acl
    }

    const WORLD: [u8; 12] = crate::token::WORLD;

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
