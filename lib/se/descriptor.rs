//! Reading and changing the security descriptor an object has
//! (`SeQuerySecurityDescriptorInfo`, `SeSetSecurityDescriptorInfo`).
//!
//! [Query] copies the parts a `SECURITY_INFORMATION` names into a
//! self-relative descriptor in the caller's buffer and always reports
//! the length that takes; a buffer too short gets nothing. [Set]
//! replaces the parts named with those of another descriptor and yields
//! the object's new descriptor; an object without one, or with one that
//! is not self-relative, is refused.
//!
//! INFERRED, for the conformance drivers:
//! - Query: a part that is not named, or that the object lacks, is left
//!   out and its control bits are clear; a part named brings every
//!   control bit that describes it (defaulted, present, auto-inherited,
//!   protected). An object with no descriptor yields an empty one.
//! - Query: the parts are laid out owner, group, DACL, SACL: the order
//!   Windows shows for the first three, and the pinned kernel's code
//!   for the SACL.
//! - Set: a SACL named and not marked present leaves the object
//!   without one. Its "present" and "defaulted" bits follow the new
//!   list; "protected" and "auto-inherited" are left as they were.
//!
//! Set, as Windows shows a driver and the pinned kernel's code
//! (`RtlpSetSecurityObject`) decides:
//! - The descriptor that results must have an owner and a group, the
//!   new one if it is named and else the object's: without the owner
//!   `STATUS_INVALID_OWNER`, then without the group
//!   `STATUS_INVALID_PRIMARY_GROUP`. So naming either and not supplying
//!   it is refused, and so is any change to an object that lacks one.
//! - An owner or group that is set is not marked defaulted.
//! - A DACL that is named is always marked present afterwards: with the
//!   new list, or null (which allows everyone everything) when the
//!   modification has none marked present. It is not marked defaulted;
//!   it is protected if the modification says so, and auto-inherited if
//!   the modification says both that and "auto-inherit required".
//! - Generic rights in the new ACLs' effective entries are mapped;
//!   creator SIDs are not replaced. A new ACL is stored whole, as long
//!   as it says it is (`acl::applied`).
//! - Control bits that describe none of the four parts are not kept.
//!
//! Not done: Windows also maps the lists it keeps, and merges into a
//! SACL the label, attribute and policy entries that the other
//! `SECURITY_INFORMATION` bits name.
//!
//! Not here: whether the caller may set what it names. The kernel asks
//! the caller's token whether a new owner is valid
//! (`Token::valid_owner`); the access check is the object's owner's to
//! make.
//!
//! [Query]: https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-sequerysecuritydescriptorinfo
//! [Set]: https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-sesetsecuritydescriptorinfo

use crate::access::GenericMapping;
use crate::acl::applied;
use crate::{
    DACL_SECURITY_INFORMATION, GROUP_SECURITY_INFORMATION, OWNER_SECURITY_INFORMATION, Parts,
    SACL_SECURITY_INFORMATION, SE_DACL_AUTO_INHERIT_REQ, SE_DACL_AUTO_INHERITED, SE_DACL_DEFAULTED,
    SE_DACL_PRESENT, SE_DACL_PROTECTED, SE_GROUP_DEFAULTED, SE_OWNER_DEFAULTED,
    SE_SACL_AUTO_INHERITED, SE_SACL_DEFAULTED, SE_SACL_PRESENT, SE_SACL_PROTECTED, parse_relative,
};
use alloc::vec;
use alloc::vec::Vec;

/// Why an object's descriptor was not changed, as the status Windows
/// gives.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SetError {
    /// `STATUS_NO_SECURITY_ON_OBJECT`
    NoSecurityOnObject,
    /// `STATUS_BAD_DESCRIPTOR_FORMAT`
    BadDescriptorFormat,
    /// `STATUS_INVALID_OWNER`
    InvalidOwner,
    /// `STATUS_INVALID_PRIMARY_GROUP`
    InvalidPrimaryGroup,
    /// `STATUS_INVALID_ACL`
    InvalidAcl,
}

/// `SeQuerySecurityDescriptorInfo`: write the parts of `object` that
/// `information` names into `out`, self-relative. The length written,
/// or `Err` with the length needed when `out` is shorter
/// (`STATUS_BUFFER_TOO_SMALL`): either way the value for `*Length`.
pub fn query_security(
    object: Option<&Parts<'_>>,
    information: u32,
    out: &mut [u8],
) -> Result<usize, usize> {
    object
        .map(|object| object.present().selected(information))
        .unwrap_or_default()
        .write_queried(out)
}

/// `SeSetSecurityDescriptorInfo`: the descriptor `object` (a
/// self-relative block) becomes when the parts `information` names are
/// replaced by those of `modification`.
pub fn set_security(
    object: Option<&[u8]>,
    modification: &Parts<'_>,
    information: u32,
    mapping: &GenericMapping,
) -> Result<Vec<u8>, SetError> {
    let old = parse_relative(object.ok_or(SetError::NoSecurityOnObject)?)
        .ok_or(SetError::BadDescriptorFormat)?
        .present();
    let new = modification.present();
    let named = |bit: u32| information & bit != 0;
    // The part to end up with, and the control bits that come with it.
    let (owner, owner_bits) = if named(OWNER_SECURITY_INFORMATION) {
        (new.owner, 0)
    } else {
        (old.owner, old.control & SE_OWNER_DEFAULTED)
    };
    let (group, group_bits) = if named(GROUP_SECURITY_INFORMATION) {
        (new.group, 0)
    } else {
        (old.group, old.control & SE_GROUP_DEFAULTED)
    };
    if owner.is_none() {
        return Err(SetError::InvalidOwner);
    }
    if group.is_none() {
        return Err(SetError::InvalidPrimaryGroup);
    }
    // A new list as this object holds it.
    let mapped = |acl: Option<&[u8]>| {
        acl.map(|acl| applied(acl, mapping).ok_or(SetError::InvalidAcl))
            .transpose()
    };
    let new_dacl = mapped(new.dacl.filter(|_| named(DACL_SECURITY_INFORMATION)))?;
    let new_sacl = mapped(new.sacl.filter(|_| named(SACL_SECURITY_INFORMATION)))?;
    let (dacl, dacl_bits) = if named(DACL_SECURITY_INFORMATION) {
        const INHERITS: u16 = SE_DACL_AUTO_INHERIT_REQ | SE_DACL_AUTO_INHERITED;
        let inherited = if new.control & INHERITS == INHERITS {
            SE_DACL_AUTO_INHERITED
        } else {
            0
        };
        let bits = SE_DACL_PRESENT | new.control & SE_DACL_PROTECTED | inherited;
        (new_dacl.as_deref(), bits)
    } else {
        const DACL: u16 =
            SE_DACL_PRESENT | SE_DACL_DEFAULTED | SE_DACL_AUTO_INHERITED | SE_DACL_PROTECTED;
        (old.dacl, old.control & DACL)
    };
    let (sacl, sacl_bits) = {
        const LIST: u16 = SE_SACL_PRESENT | SE_SACL_DEFAULTED;
        const INHERITANCE: u16 = SE_SACL_AUTO_INHERITED | SE_SACL_PROTECTED;
        if named(SACL_SECURITY_INFORMATION) {
            let bits = new.control & LIST | old.control & INHERITANCE;
            (new_sacl.as_deref(), bits)
        } else {
            (old.sacl, old.control & (LIST | INHERITANCE))
        }
    };
    let merged = Parts {
        control: owner_bits | group_bits | dacl_bits | sacl_bits,
        owner,
        group,
        sacl,
        dacl,
    };
    let mut block = vec![0; merged.relative_length()];
    let written = merged.write_relative(&mut block);
    debug_assert_eq!(written, Ok(block.len()));
    Ok(block)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::access::GENERIC_READ;
    use crate::acl::INHERIT_ONLY_ACE;
    use crate::acl::tests::{entry, list};
    use crate::token::{ADMINISTRATORS, CREATOR_OWNER, LOCAL_SYSTEM, WORLD};
    use crate::{
        SE_DACL_AUTO_INHERITED, SE_DACL_DEFAULTED, SE_DACL_PRESENT, SE_DACL_PROTECTED,
        SE_GROUP_DEFAULTED, SE_OWNER_DEFAULTED, SE_SACL_AUTO_INHERITED, SE_SACL_DEFAULTED,
        SE_SACL_PRESENT, SE_SACL_PROTECTED, SE_SELF_RELATIVE,
    };

    const OWNER: u32 = OWNER_SECURITY_INFORMATION;
    const GROUP: u32 = GROUP_SECURITY_INFORMATION;
    const DACL: u32 = DACL_SECURITY_INFORMATION;
    const SACL: u32 = SACL_SECURITY_INFORMATION;
    const MAPPING: GenericMapping = GenericMapping {
        read: 0x0012_0089,
        write: 0x0012_0116,
        execute: 0x0012_00A0,
        all: 0x001F_01FF,
    };

    fn dacl() -> Vec<u8> {
        list(&[
            entry(0, 0, 0x001F_01FF, &LOCAL_SYSTEM),
            entry(1, 0, 2, &WORLD),
        ])
    }
    fn sacl() -> Vec<u8> {
        list(&[entry(2, 0x40, 1, &WORLD)])
    }

    /// A descriptor with every part and every control bit.
    fn full<'a>(dacl: &'a [u8], sacl: &'a [u8]) -> Parts<'a> {
        Parts {
            control: 0x3C3F,
            owner: Some(&ADMINISTRATORS),
            group: Some(&LOCAL_SYSTEM),
            sacl: Some(sacl),
            dacl: Some(dacl),
        }
    }

    fn block(parts: &Parts<'_>) -> Vec<u8> {
        let mut block = vec![0; parts.relative_length()];
        parts.write_relative(&mut block).unwrap();
        block
    }

    #[test]
    fn a_query_copies_the_parts_named() {
        let (dacl, sacl) = (dacl(), sacl());
        let object = full(&dacl, &sacl);
        // (what is asked, the control bits that come with it, its bytes)
        let parts: [(u32, u16, usize); 4] = [
            (OWNER, SE_OWNER_DEFAULTED, 16),
            (GROUP, SE_GROUP_DEFAULTED, 12),
            (
                DACL,
                SE_DACL_PRESENT | SE_DACL_DEFAULTED | SE_DACL_AUTO_INHERITED | SE_DACL_PROTECTED,
                dacl.len(),
            ),
            (
                SACL,
                SE_SACL_PRESENT | SE_SACL_DEFAULTED | SE_SACL_AUTO_INHERITED | SE_SACL_PROTECTED,
                sacl.len(),
            ),
        ];
        // Every combination of the four.
        for information in 0..16u32 {
            let asked = |bit: u32| information & bit != 0;
            let (mut control, mut length) = (SE_SELF_RELATIVE, 20);
            for (bit, bits, bytes) in parts {
                if asked(bit) {
                    control |= bits;
                    length += bytes;
                }
            }
            let mut out = [0xEEu8; 200];
            assert_eq!(
                query_security(Some(&object), information, &mut out),
                Ok(length),
                "{information:#x}"
            );
            assert_eq!(out[length], 0xEE, "nothing past the length");
            let copy = parse_relative(&out[..length]).unwrap();
            assert_eq!(copy.control, control, "{information:#x}");
            assert_eq!(copy.owner, asked(OWNER).then_some(&ADMINISTRATORS[..]));
            assert_eq!(copy.group, asked(GROUP).then_some(&LOCAL_SYSTEM[..]));
            assert_eq!(copy.dacl, asked(DACL).then_some(&dacl[..]));
            assert_eq!(copy.sacl, asked(SACL).then_some(&sacl[..]));
            // Laid out owner, group, DACL, SACL, each where the one
            // before it ends.
            let mut at = 20;
            for (index, field) in [(0, 4), (1, 8), (2, 16), (3, 12)] {
                let (bit, _, bytes) = parts[index];
                let offset = u32::from_le_bytes(out[field..field + 4].try_into().unwrap());
                if asked(bit) {
                    assert_eq!(offset as usize, at, "{information:#x}: part {bit}");
                    at += bytes;
                } else {
                    assert_eq!(offset, 0, "{information:#x}: part {bit}");
                }
            }
        }
    }

    #[test]
    fn a_query_reports_the_length_it_needs() {
        let (dacl, sacl) = (dacl(), sacl());
        let object = full(&dacl, &sacl);
        let needed = 20 + sacl.len() + dacl.len() + 16 + 12;
        let mut out = [0xEEu8; 200];
        assert_eq!(query_security(Some(&object), 0xF, &mut []), Err(needed));
        assert_eq!(
            query_security(Some(&object), 0xF, &mut out[..needed - 1]),
            Err(needed)
        );
        assert!(out.iter().all(|&byte| byte == 0xEE), "nothing was copied");
        assert_eq!(
            query_security(Some(&object), 0xF, &mut out[..needed]),
            Ok(needed)
        );
        assert_eq!(
            query_security(Some(&object), OWNER, &mut out[..20]),
            Err(36)
        );
        assert_eq!(query_security(Some(&object), 0, &mut out[..20]), Ok(20));
        assert_eq!(query_security(Some(&object), 0, &mut out[..19]), Err(20));
    }

    #[test]
    fn a_query_of_what_is_not_there() {
        let mut out = [0xEEu8; 64];
        // No descriptor at all: an empty one.
        assert_eq!(query_security(None, 0xF, &mut out), Ok(20));
        assert_eq!(
            out[..20],
            [
                1, 0, 0, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
            ]
        );
        // A null DACL is reported as present and null; a DACL that is
        // not marked present is not reported.
        let list = dacl();
        let null = Parts {
            control: SE_DACL_PRESENT,
            owner: Some(&LOCAL_SYSTEM),
            ..Parts::default()
        };
        assert_eq!(
            query_security(Some(&null), DACL | SACL | GROUP, &mut out),
            Ok(20)
        );
        assert_eq!(out[..4], [1, 0, 0x04, 0x80]);
        let unmarked = Parts {
            control: 0,
            dacl: Some(&list),
            ..null
        };
        assert_eq!(query_security(Some(&unmarked), DACL, &mut out), Ok(20));
        assert_eq!(out[..4], [1, 0, 0, 0x80]);
    }

    #[test]
    fn a_set_replaces_the_parts_named() {
        let (old_dacl, old_sacl) = (dacl(), sacl());
        let old = Parts {
            control: SE_DACL_PRESENT
                | SE_SACL_PRESENT
                | SE_DACL_PROTECTED
                | SE_DACL_AUTO_INHERITED
                | SE_OWNER_DEFAULTED
                | SE_GROUP_DEFAULTED,
            ..full(&old_dacl, &old_sacl)
        };
        let object = block(&old);
        let new_dacl = list(&[entry(0, 0, 1, &ADMINISTRATORS)]);
        let new_sacl = list(&[entry(2, 0x80, 2, &ADMINISTRATORS)]);
        let new = Parts {
            control: SE_DACL_PRESENT
                | SE_DACL_DEFAULTED
                | SE_DACL_AUTO_INHERITED
                | SE_SACL_PRESENT
                | SE_OWNER_DEFAULTED
                | SE_GROUP_DEFAULTED
                | SE_SACL_PROTECTED,
            owner: Some(&WORLD),
            group: Some(&ADMINISTRATORS),
            sacl: Some(&new_sacl),
            dacl: Some(&new_dacl),
        };
        let set = |information| set_security(Some(&object), &new, information, &MAPPING).unwrap();

        assert_eq!(set(0), object, "nothing named, nothing changed");
        let changed = set(OWNER);
        let got = parse_relative(&changed).unwrap();
        assert_eq!(got.owner, Some(&WORLD[..]));
        assert_eq!(
            (got.group, got.dacl, got.sacl),
            (old.group, old.dacl, old.sacl)
        );
        assert_eq!(
            got.control,
            SE_SELF_RELATIVE | old.control & !SE_OWNER_DEFAULTED,
            "an owner that is set is not defaulted"
        );
        let changed = set(GROUP);
        let got = parse_relative(&changed).unwrap();
        assert_eq!(
            (got.group, got.owner),
            (Some(&ADMINISTRATORS[..]), old.owner)
        );
        assert_eq!(
            got.control,
            SE_SELF_RELATIVE | old.control & !SE_GROUP_DEFAULTED,
            "nor is a group"
        );
        let changed = set(DACL);
        let got = parse_relative(&changed).unwrap();
        assert_eq!((got.dacl, got.sacl), (Some(&new_dacl[..]), old.sacl));
        assert_eq!(
            got.control,
            SE_SELF_RELATIVE
                | SE_DACL_PRESENT
                | SE_SACL_PRESENT
                | SE_OWNER_DEFAULTED
                | SE_GROUP_DEFAULTED,
            "the list is the modification's: not defaulted, protected or auto-inherited"
        );
        // Protected if the modification says so; auto-inherited if it
        // also says that it must be.
        for (bits, kept) in [
            (SE_DACL_PROTECTED, SE_DACL_PROTECTED),
            (SE_DACL_AUTO_INHERIT_REQ, 0),
            (
                SE_DACL_AUTO_INHERIT_REQ | SE_DACL_AUTO_INHERITED,
                SE_DACL_AUTO_INHERITED,
            ),
        ] {
            let marked = Parts {
                control: SE_DACL_PRESENT | bits,
                ..new
            };
            let changed = set_security(Some(&object), &marked, DACL, &MAPPING).unwrap();
            assert_eq!(
                parse_relative(&changed).unwrap().control,
                SE_SELF_RELATIVE
                    | SE_DACL_PRESENT
                    | SE_SACL_PRESENT
                    | SE_OWNER_DEFAULTED
                    | SE_GROUP_DEFAULTED
                    | kept,
                "{bits:#x}"
            );
        }
        let changed = set(SACL);
        let got = parse_relative(&changed).unwrap();
        assert_eq!((got.sacl, got.dacl), (Some(&new_sacl[..]), old.dacl));
        assert_eq!(got.control, SE_SELF_RELATIVE | old.control, "not protected");
        let changed = set(0xF);
        let got = parse_relative(&changed).unwrap();
        assert_eq!(
            (got.owner, got.group, got.sacl, got.dacl),
            (new.owner, new.group, new.sacl, new.dacl)
        );

        // What was set is what a query then reads, laid out its own way.
        let mut out = [0u8; 200];
        let length = query_security(Some(&got), 0xF, &mut out).unwrap();
        assert_eq!(length, changed.len());
        let read = parse_relative(&out[..length]).unwrap();
        assert_eq!(
            (read.control, read.owner, read.group, read.sacl, read.dacl),
            (got.control, got.owner, got.group, got.sacl, got.dacl)
        );
    }

    #[test]
    fn a_set_with_a_part_missing() {
        let (old_dacl, old_sacl) = (dacl(), sacl());
        let old = Parts {
            control: SE_DACL_PRESENT | SE_SACL_PRESENT,
            ..full(&old_dacl, &old_sacl)
        };
        let object = block(&old);
        let nothing = Parts::default();
        let set =
            |new: &Parts<'_>, information| set_security(Some(&object), new, information, &MAPPING);
        // No owner, no group: refused, the owner first.
        assert_eq!(set(&nothing, OWNER), Err(SetError::InvalidOwner));
        assert_eq!(set(&nothing, 0xF), Err(SetError::InvalidOwner));
        assert_eq!(set(&nothing, GROUP), Err(SetError::InvalidPrimaryGroup));
        let owner_only = Parts {
            owner: Some(&WORLD),
            ..nothing
        };
        assert_eq!(
            set(&owner_only, OWNER | GROUP),
            Err(SetError::InvalidPrimaryGroup)
        );
        // No DACL, one not marked present, or a null one: the object
        // has a null DACL, marked present.
        let unmarked = Parts {
            dacl: Some(&old_dacl),
            ..nothing
        };
        let null = Parts {
            control: SE_DACL_PRESENT,
            ..nothing
        };
        for new in [&nothing, &unmarked, &null] {
            let changed = set(new, DACL).unwrap();
            let got = parse_relative(&changed).unwrap();
            assert_eq!(got.dacl, None);
            assert_eq!(
                got.control,
                SE_SELF_RELATIVE | SE_DACL_PRESENT | SE_SACL_PRESENT
            );
            assert_eq!(got.sacl, old.sacl);
        }
        // No SACL: the object has none.
        let changed = set(&null, DACL | SACL).unwrap();
        let got = parse_relative(&changed).unwrap();
        assert_eq!((got.dacl, got.sacl), (None, None));
        assert_eq!(got.control, SE_SELF_RELATIVE | SE_DACL_PRESENT);
        assert_eq!(changed.len(), 20 + 16 + 12);
    }

    #[test]
    fn an_object_without_an_owner_or_a_group_cannot_be_changed() {
        let (dacl, sacl) = (dacl(), sacl());
        let whole = full(&dacl, &sacl);
        let no_owner = block(&Parts {
            owner: None,
            ..whole
        });
        let no_group = block(&Parts {
            group: None,
            ..whole
        });
        let set = |object: &[u8], information| {
            set_security(Some(object), &whole, information, &MAPPING).map(|_| ())
        };
        assert_eq!(set(&no_owner, DACL), Err(SetError::InvalidOwner));
        assert_eq!(set(&no_owner, GROUP), Err(SetError::InvalidOwner));
        assert_eq!(set(&no_owner, OWNER), Ok(()));
        assert_eq!(set(&no_group, 0), Err(SetError::InvalidPrimaryGroup));
        assert_eq!(set(&no_group, OWNER), Err(SetError::InvalidPrimaryGroup));
        assert_eq!(set(&no_group, GROUP), Ok(()));
        // Other control bits do not survive a change.
        let mut odd = block(&whole);
        odd[3] |= 0x40;
        let changed = set_security(Some(&odd), &whole, 0, &MAPPING).unwrap();
        assert_eq!(changed, block(&whole));
    }

    #[test]
    fn a_set_maps_generic_rights_in_what_it_stores() {
        let object = block(&Parts {
            owner: Some(&LOCAL_SYSTEM),
            group: Some(&LOCAL_SYSTEM),
            ..Parts::default()
        });
        let mut generic = list(&[
            entry(0, 0, GENERIC_READ, &CREATOR_OWNER),
            entry(0, INHERIT_ONLY_ACE, GENERIC_READ, &WORLD),
        ]);
        // Spare room, which is stored too.
        generic.extend([0; 8]);
        generic[2] += 8;
        let new = Parts {
            control: SE_DACL_PRESENT | SE_SACL_PRESENT | SE_SACL_DEFAULTED,
            sacl: Some(&generic),
            dacl: Some(&generic),
            ..Parts::default()
        };
        let mut stored = list(&[
            entry(0, 0, MAPPING.read, &CREATOR_OWNER),
            entry(0, INHERIT_ONLY_ACE, GENERIC_READ, &WORLD),
        ]);
        stored.extend([0; 8]);
        stored[2] += 8;
        let changed = set_security(Some(&object), &new, DACL | SACL, &MAPPING).unwrap();
        let got = parse_relative(&changed).unwrap();
        assert_eq!((got.dacl, got.sacl), (Some(&stored[..]), Some(&stored[..])));
        assert_eq!(
            got.control,
            SE_SELF_RELATIVE | SE_DACL_PRESENT | SE_SACL_PRESENT | SE_SACL_DEFAULTED
        );
        assert_eq!(got.owner, Some(&LOCAL_SYSTEM[..]));
    }

    #[test]
    fn a_set_that_is_refused() {
        let object = block(&Parts {
            owner: Some(&LOCAL_SYSTEM),
            group: Some(&LOCAL_SYSTEM),
            ..Parts::default()
        });
        let new = Parts::default();
        assert_eq!(
            set_security(None, &new, 0, &MAPPING),
            Err(SetError::NoSecurityOnObject)
        );
        // Absolute (not marked self-relative), or not a descriptor.
        let mut absolute = object.clone();
        absolute[3] = 0;
        for bad in [&absolute[..], &object[..10], &[]] {
            assert_eq!(
                set_security(Some(bad), &new, 0, &MAPPING),
                Err(SetError::BadDescriptorFormat)
            );
        }
        // A damaged list is refused when it is the one to store.
        let mut broken = dacl();
        broken[4] = 9;
        let new = Parts {
            control: SE_DACL_PRESENT | SE_SACL_PRESENT,
            sacl: Some(&broken),
            dacl: Some(&broken),
            ..Parts::default()
        };
        for information in [DACL, SACL] {
            assert_eq!(
                set_security(Some(&object), &new, information, &MAPPING),
                Err(SetError::InvalidAcl)
            );
        }
        assert_eq!(set_security(Some(&object), &new, 0, &MAPPING), Ok(object));
    }
}
