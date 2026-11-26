//! The security descriptor of a new object (`SeAssignSecurity`), from
//! its parent's, the one its creator supplied, and the creator's token.
//!
//! The rules are those of [SeAssignSecurity] and of [MS-DTYP] 2.5.3.4
//! with no auto-inherit flags, which is what `SeAssignSecurity` is:
//!
//! - Owner: the supplied one, else the token's default owner. Group:
//!   the supplied one, else the token's primary group.
//! - Each ACL, by [SeAssignSecurity]'s table: a supplied ACL that is
//!   not marked defaulted is assigned; else the entries inherited from
//!   the parent, if there are any; else the supplied defaulted ACL;
//!   else, for the DACL, the token's default DACL; else none. A supplied
//!   ACL may be null: the object then has a null ACL, marked present.
//! - What a parent's entry gives a child, by its flags, is the table of
//!   ["ACE inheritance rules"]: effective on a directory if container-
//!   inherit and on another object if object-inherit; still inheritable
//!   on a directory unless no-propagate; inherit-only on a directory
//!   when only object-inherit.
//! - An inherited entry that takes effect has its generic rights mapped
//!   and the creator-owner and creator-group SIDs replaced by the new
//!   owner and group; an inherit-only entry keeps both. A directory's
//!   entry that is effective and inheritable and would change that way
//!   becomes two: the effective one, changed, then an inherit-only one,
//!   unchanged.
//! - A supplied ACL, or the token's default, is assigned as the pinned
//!   kernel's code copies it (`acl::applied`), which Windows shows a
//!   driver: the whole list, as long as it says it is, the masks of its
//!   effective entries mapped, and no SID replaced: a creator-owner
//!   entry of a supplied list stays one.
//!
//! - A supplied owner the token may not own with is refused
//!   (`STATUS_INVALID_OWNER`, [SeAssignSecurity]) unless
//!   `SeRestorePrivilege` is enabled, and only for a creator whose
//!   previous mode is user mode: so the pinned kernel's code.
//!
//! INFERRED, for the conformance drivers:
//! - "Inherited from the parent" means at least one entry reaches this
//!   kind of child; [MS-DTYP] asks only whether the parent has an
//!   inheritable entry of any kind.
//! - `INHERITED_ACE` is not set on inherited entries, and no
//!   auto-inherited or protected control bit is set: those belong to
//!   `SeAssignSecurityEx`'s auto-inherit flags. [MS-DTYP] sets the flag
//!   always.
//! - The result's control bits are `SE_SELF_RELATIVE` and the two
//!   "present" bits; no "defaulted" bit is carried or set.
//! - Of the two entries a directory may get for one, the effective one
//!   comes first.
//! - An inherited ACL is exactly as long as its entries.
//! - Entries that are not allow, deny, audit or alarm are inherited by
//!   their flags and never changed.
//!
//! Not done: when the parent's DACL (or SACL) is marked auto-inherited
//! and the creator supplies none, Windows' `SeAssignSecurity` inherits
//! with the auto-inherit rules of `SeAssignSecurityEx`; here the rules
//! above apply all the same. Object-specific entries are not inherited (their
//! inheritance depends on object-type GUIDs); a supplied SACL is copied
//! and a parent's inherited like a DACL, with no mandatory-label rules.
//!
//! [SeAssignSecurity]: https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-seassignsecurity
//! [MS-DTYP]: https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-dtyp/98267ad6-66db-4a2c-972e-efb7d4603da1
//! ["ACE inheritance rules"]: https://learn.microsoft.com/en-us/windows/win32/secauthz/ace-inheritance-rules

use crate::access::GenericMapping;
use crate::acl::{
    Ace, CONTAINER_INHERIT_ACE, INHERIT_ONLY_ACE, INHERITED_ACE, NO_PROPAGATE_INHERIT_ACE,
    OBJECT_INHERIT_ACE, aces, applied, build, object_specific, resolved, with_flags,
};
use crate::token::{SE_SECURITY_PRIVILEGE, Token};
use crate::{
    Parts, SE_DACL_DEFAULTED, SE_DACL_PRESENT, SE_SACL_DEFAULTED, SE_SACL_PRESENT, acl_used,
};
use alloc::vec;
use alloc::vec::Vec;

/// Why a new object gets no descriptor, as the status Windows gives.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AssignError {
    /// `STATUS_INVALID_OWNER`
    InvalidOwner,
    /// `STATUS_PRIVILEGE_NOT_HELD`: a SACL was supplied without
    /// `SeSecurityPrivilege`.
    PrivilegeNotHeld,
    /// `STATUS_INVALID_ACL`: an ACL is damaged, or the result would be
    /// larger than an ACL can be.
    InvalidAcl,
}

/// A new object, as far as its security goes.
#[derive(Debug, Clone, Copy)]
pub struct Creation<'a> {
    /// The descriptor of the directory the object is created in.
    pub parent: Option<&'a Parts<'a>>,
    /// The descriptor the creator asked for.
    pub explicit: Option<&'a Parts<'a>>,
    /// The creator.
    pub token: &'a Token,
    /// Whether the object holds other objects.
    pub is_directory: bool,
    pub mapping: GenericMapping,
    /// Whether the creator is a kernel-mode caller: it may supply any
    /// owner, and a SACL without the privilege.
    pub kernel_mode: bool,
}

/// An ACL as supplied by the creator: the list (or null), and whether it
/// is marked defaulted. `None`: not supplied.
type Supplied<'a> = Option<(Option<&'a [u8]>, bool)>;

/// An ACL as assigned: the list, or a null ACL marked present. `None`:
/// the object has no such ACL.
type Assigned = Option<Option<Vec<u8>>>;

/// `SeAssignSecurity`: the new object's descriptor, self-relative.
pub fn assign_security(creation: &Creation<'_>) -> Result<Vec<u8>, AssignError> {
    let token = creation.token;
    let user_mode = !creation.kernel_mode;
    let parent = creation.parent.map(Parts::present).unwrap_or_default();
    let explicit = creation.explicit.map(Parts::present).unwrap_or_default();
    let owner = match explicit.owner {
        Some(owner) => {
            if user_mode && !token.valid_owner(owner) {
                return Err(AssignError::InvalidOwner);
            }
            owner
        }
        None => &token.owner,
    };
    let has_sacl = explicit.control & SE_SACL_PRESENT != 0;
    if has_sacl && user_mode && !token.privilege_enabled(SE_SECURITY_PRIVILEGE) {
        return Err(AssignError::PrivilegeNotHeld);
    }
    let object = Object {
        is_directory: creation.is_directory,
        mapping: &creation.mapping,
        owner,
        group: explicit.group.unwrap_or(&token.primary_group),
    };
    let supplied = |acl, present: u16, defaulted: u16| {
        (explicit.control & present != 0).then_some((acl, explicit.control & defaulted != 0))
    };
    let dacl = object.acl(
        parent.dacl,
        supplied(explicit.dacl, SE_DACL_PRESENT, SE_DACL_DEFAULTED),
        token.default_dacl.as_deref(),
    )?;
    let sacl = object.acl(
        parent.sacl,
        supplied(explicit.sacl, SE_SACL_PRESENT, SE_SACL_DEFAULTED),
        None,
    )?;
    let present = |acl: &Assigned, bit| if acl.is_some() { bit } else { 0 };
    let parts = Parts {
        control: present(&dacl, SE_DACL_PRESENT) | present(&sacl, SE_SACL_PRESENT),
        owner: Some(object.owner),
        group: Some(object.group),
        sacl: sacl.as_ref().and_then(|acl| acl.as_deref()),
        dacl: dacl.as_ref().and_then(|acl| acl.as_deref()),
    };
    let mut block = vec![0; parts.relative_length()];
    let written = parts.write_relative(&mut block);
    debug_assert_eq!(written, Ok(block.len()));
    Ok(block)
}

/// What the ACLs of a new object are computed for.
struct Object<'a> {
    is_directory: bool,
    mapping: &'a GenericMapping,
    owner: &'a [u8],
    group: &'a [u8],
}

impl Object<'_> {
    /// One ACL of the new object.
    fn acl(
        &self,
        parent: Option<&[u8]>,
        supplied: Supplied<'_>,
        default: Option<&[u8]>,
    ) -> Result<Assigned, AssignError> {
        let own = |acl: Option<&[u8]>| acl.map(|acl| self.effective(acl)).transpose();
        if let Some((acl, false)) = supplied {
            return Ok(Some(own(acl)?));
        }
        if let Some(inherited) = parent.map(|acl| self.inherited(acl)).transpose()?.flatten() {
            return Ok(Some(Some(inherited)));
        }
        match supplied {
            Some((acl, _)) => Ok(Some(own(acl)?)),
            None => Ok(own(default)?.map(Some)),
        }
    }

    /// A supplied or default ACL as it is assigned.
    fn effective(&self, acl: &[u8]) -> Result<Vec<u8>, AssignError> {
        applied(acl, self.mapping).ok_or(AssignError::InvalidAcl)
    }

    /// The ACL this object inherits from its parent's. `None` if no
    /// entry reaches it.
    fn inherited(&self, parent: &[u8]) -> Result<Option<Vec<u8>>, AssignError> {
        if acl_used(parent).is_none() {
            return Err(AssignError::InvalidAcl);
        }
        let mut entries = Vec::new();
        for ace in aces(parent) {
            self.inherit(&ace, &mut entries);
        }
        if entries.is_empty() {
            return Ok(None);
        }
        build(parent[0], &entries)
            .map(Some)
            .ok_or(AssignError::InvalidAcl)
    }

    /// What one entry of the parent gives this object: nothing, one
    /// entry or two, added to `entries`.
    fn inherit(&self, ace: &Ace<'_>, entries: &mut Vec<Vec<u8>>) {
        // Flags that are not about inheritance (an audit entry's
        // "success" and "failure") stay.
        const INHERITANCE: u8 = OBJECT_INHERIT_ACE
            | CONTAINER_INHERIT_ACE
            | NO_PROPAGATE_INHERIT_ACE
            | INHERIT_ONLY_ACE
            | INHERITED_ACE;
        if object_specific(ace.kind) {
            return;
        }
        let has = |flag: u8| ace.flags & flag != 0;
        let (container, object) = (has(CONTAINER_INHERIT_ACE), has(OBJECT_INHERIT_ACE));
        let effective = if self.is_directory { container } else { object };
        let passed_on =
            self.is_directory && !has(NO_PROPAGATE_INHERIT_ACE) && (container || object);
        let plain = ace.flags & !INHERITANCE;
        let inheritable = plain | ace.flags & (OBJECT_INHERIT_ACE | CONTAINER_INHERIT_ACE);
        if !effective {
            if passed_on {
                entries.push(with_flags(ace, inheritable | INHERIT_ONLY_ACE));
            }
            return;
        }
        let resolved = self.resolved(ace, plain);
        if !passed_on {
            entries.push(resolved);
        } else if resolved[4..] == ace.bytes[4..] {
            // Nothing to map: one entry does both jobs.
            entries.push(with_flags(ace, inheritable));
        } else {
            entries.push(resolved);
            entries.push(with_flags(ace, inheritable | INHERIT_ONLY_ACE));
        }
    }

    fn resolved(&self, ace: &Ace<'_>, flags: u8) -> Vec<u8> {
        resolved(ace, flags, self.mapping, Some((self.owner, self.group)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::access::{GENERIC_ALL, GENERIC_READ};
    use crate::acl::tests::{entry, list};
    use crate::token::{
        ADMINISTRATORS, CREATOR_GROUP, CREATOR_OWNER, LOCAL_SYSTEM, Privilege,
        SE_PRIVILEGE_ENABLED, WORLD,
    };
    use crate::{SE_SELF_RELATIVE, parse_relative};

    const MAPPING: GenericMapping = GenericMapping {
        read: 0x0012_0089,
        write: 0x0012_0116,
        execute: 0x0012_00A0,
        all: 0x001F_01FF,
    };
    const OI: u8 = OBJECT_INHERIT_ACE;
    const CI: u8 = CONTAINER_INHERIT_ACE;
    const NP: u8 = NO_PROPAGATE_INHERIT_ACE;
    const IO: u8 = INHERIT_ONLY_ACE;
    const ID: u8 = INHERITED_ACE;
    const ALLOW: u8 = 0;
    const DENY: u8 = 1;
    /// S-1-5-32-545, a SID the SYSTEM token does not have.
    const USERS: &[u8] = &[1, 2, 0, 0, 0, 0, 0, 5, 32, 0, 0, 0, 0x21, 2, 0, 0];

    /// (type, flags, mask, SID)
    type Entry = (u8, u8, u32, &'static [u8]);

    fn acl(entries: &[Entry]) -> Vec<u8> {
        let entries: Vec<Vec<u8>> = entries
            .iter()
            .map(|&(kind, flags, mask, sid)| entry(kind, flags, mask, sid))
            .collect();
        list(&entries)
    }

    /// A descriptor whose DACL is `dacl`.
    fn with_dacl(dacl: &[u8]) -> Parts<'_> {
        Parts {
            control: SE_DACL_PRESENT,
            dacl: Some(dacl),
            ..Parts::default()
        }
    }

    fn assign(
        parent: Option<&Parts<'_>>,
        explicit: Option<&Parts<'_>>,
        token: &Token,
        is_directory: bool,
        kernel_mode: bool,
    ) -> Result<Vec<u8>, AssignError> {
        assign_security(&Creation {
            parent,
            explicit,
            token,
            is_directory,
            mapping: MAPPING,
            kernel_mode,
        })
    }

    /// The DACL a child of a parent with `parent` as DACL gets, created
    /// by SYSTEM in kernel mode with nothing supplied.
    fn child_dacl(parent: &[Entry], is_directory: bool) -> Vec<u8> {
        let parent = acl(parent);
        let block = assign(
            Some(&with_dacl(&parent)),
            None,
            &Token::system(),
            is_directory,
            true,
        )
        .unwrap();
        parse_relative(&block).unwrap().dacl.unwrap().to_vec()
    }

    /// The token's default DACL as an object gets it: generic rights
    /// mapped.
    fn default_dacl() -> Vec<u8> {
        acl(&[
            (ALLOW, 0, MAPPING.all, &LOCAL_SYSTEM),
            (
                ALLOW,
                0,
                0x0002_0000 | MAPPING.read | MAPPING.execute,
                &ADMINISTRATORS,
            ),
        ])
    }

    /// What a parent's entry with these flags gives a directory and
    /// another object: the flags of each entry inherited. Empty: none,
    /// so the default DACL is assigned instead.
    struct Flags {
        parent: u8,
        directory: &'static [u8],
        leaf: &'static [u8],
    }

    const FLAGS: &[Flags] = &[
        Flags {
            parent: 0,
            directory: &[],
            leaf: &[],
        },
        Flags {
            parent: IO,
            directory: &[],
            leaf: &[],
        },
        Flags {
            parent: NP,
            directory: &[],
            leaf: &[],
        },
        Flags {
            parent: OI,
            directory: &[OI | IO],
            leaf: &[0],
        },
        Flags {
            parent: OI | NP,
            directory: &[],
            leaf: &[0],
        },
        Flags {
            parent: OI | IO,
            directory: &[OI | IO],
            leaf: &[0],
        },
        Flags {
            parent: CI,
            directory: &[CI],
            leaf: &[],
        },
        Flags {
            parent: CI | NP,
            directory: &[0],
            leaf: &[],
        },
        Flags {
            parent: CI | IO,
            directory: &[CI],
            leaf: &[],
        },
        Flags {
            parent: CI | OI,
            directory: &[CI | OI],
            leaf: &[0],
        },
        Flags {
            parent: CI | OI | NP,
            directory: &[0],
            leaf: &[0],
        },
        Flags {
            parent: CI | OI | IO,
            directory: &[CI | OI],
            leaf: &[0],
        },
        Flags {
            parent: CI | OI | ID,
            directory: &[CI | OI],
            leaf: &[0],
        },
        Flags {
            parent: CI | OI | NP | IO | ID,
            directory: &[0],
            leaf: &[0],
        },
    ];

    #[test]
    fn inheritance_by_flags() {
        for case in FLAGS {
            for (is_directory, flags) in [(true, case.directory), (false, case.leaf)] {
                let got = child_dacl(&[(DENY, case.parent, 0x3, USERS)], is_directory);
                let want = if flags.is_empty() {
                    default_dacl()
                } else {
                    let entries: Vec<Entry> = flags
                        .iter()
                        .map(|&flags| (DENY, flags, 0x3, USERS))
                        .collect();
                    acl(&entries)
                };
                assert_eq!(
                    got, want,
                    "parent flags {:#x}, directory {is_directory}",
                    case.parent
                );
            }
        }
    }

    #[test]
    fn generic_rights_are_mapped_where_an_entry_takes_effect() {
        // Effective and inheritable on a directory: two entries.
        assert_eq!(
            child_dacl(&[(ALLOW, CI, GENERIC_READ, USERS)], true),
            acl(&[
                (ALLOW, 0, MAPPING.read, USERS),
                (ALLOW, CI | IO, GENERIC_READ, USERS)
            ])
        );
        assert_eq!(
            child_dacl(&[(ALLOW, CI | OI, GENERIC_ALL | 0x0100_0000, USERS)], true),
            acl(&[
                (ALLOW, 0, MAPPING.all | 0x0100_0000, USERS),
                (ALLOW, CI | OI | IO, GENERIC_ALL | 0x0100_0000, USERS)
            ])
        );
        // Effective only: mapped.
        assert_eq!(
            child_dacl(&[(ALLOW, CI | NP, GENERIC_READ, USERS)], true),
            acl(&[(ALLOW, 0, MAPPING.read, USERS)])
        );
        assert_eq!(
            child_dacl(&[(ALLOW, OI, GENERIC_READ, USERS)], false),
            acl(&[(ALLOW, 0, MAPPING.read, USERS)])
        );
        // Inherit-only: kept generic.
        assert_eq!(
            child_dacl(&[(ALLOW, OI, GENERIC_READ, USERS)], true),
            acl(&[(ALLOW, OI | IO, GENERIC_READ, USERS)])
        );
    }

    #[test]
    fn creator_sids_become_the_new_owner_and_group() {
        // SYSTEM's default owner is Administrators, its group SYSTEM.
        assert_eq!(
            child_dacl(
                &[
                    (ALLOW, CI | OI, 1, &CREATOR_OWNER),
                    (ALLOW, CI, 2, &CREATOR_GROUP)
                ],
                true
            ),
            acl(&[
                (ALLOW, 0, 1, &ADMINISTRATORS),
                (ALLOW, CI | OI | IO, 1, &CREATOR_OWNER),
                (ALLOW, 0, 2, &LOCAL_SYSTEM),
                (ALLOW, CI | IO, 2, &CREATOR_GROUP),
            ])
        );
        assert_eq!(
            child_dacl(
                &[
                    (ALLOW, CI | OI, 1, &CREATOR_OWNER),
                    (ALLOW, OI, 2, &CREATOR_GROUP)
                ],
                false
            ),
            acl(&[(ALLOW, 0, 1, &ADMINISTRATORS), (ALLOW, 0, 2, &LOCAL_SYSTEM)])
        );
        // The supplied owner and group are the ones named.
        let parent = acl(&[
            (ALLOW, OI, 1, &CREATOR_OWNER),
            (DENY, OI, 2, &CREATOR_GROUP),
        ]);
        let explicit = Parts {
            owner: Some(USERS),
            group: Some(&WORLD),
            ..Parts::default()
        };
        let block = assign(
            Some(&with_dacl(&parent)),
            Some(&explicit),
            &Token::system(),
            false,
            true,
        )
        .unwrap();
        let made = parse_relative(&block).unwrap();
        assert_eq!((made.owner, made.group), (Some(USERS), Some(&WORLD[..])));
        assert_eq!(
            made.dacl.unwrap(),
            acl(&[(ALLOW, 0, 1, USERS), (DENY, 0, 2, &WORLD)])
        );
    }

    #[test]
    fn several_entries_keep_their_order_and_revision() {
        let mut parent = acl(&[
            (DENY, CI, 1, USERS),
            (ALLOW, 0, 2, USERS),
            (ALLOW, OI, 4, &WORLD),
            (ALLOW, CI | OI, 8, &LOCAL_SYSTEM),
        ]);
        parent[0] = 4;
        let block = assign(
            Some(&with_dacl(&parent)),
            None,
            &Token::system(),
            true,
            true,
        )
        .unwrap();
        let mut want = acl(&[
            (DENY, CI, 1, USERS),
            (ALLOW, OI | IO, 4, &WORLD),
            (ALLOW, CI | OI, 8, &LOCAL_SYSTEM),
        ]);
        want[0] = 4;
        assert_eq!(parse_relative(&block).unwrap().dacl.unwrap(), want);
    }

    #[test]
    fn with_nothing_supplied_the_token_decides() {
        let token = Token::system();
        let block = assign(None, None, &token, false, false).unwrap();
        let made = parse_relative(&block).unwrap();
        assert_eq!(made.control, SE_SELF_RELATIVE | SE_DACL_PRESENT);
        assert_eq!(made.owner, Some(&ADMINISTRATORS[..]));
        assert_eq!(made.group, Some(&LOCAL_SYSTEM[..]));
        assert_eq!(made.dacl.unwrap(), default_dacl());
        assert_eq!(made.sacl, None);
        // DACL (52), owner (16), group (12) after the header.
        assert_eq!(block.len(), 20 + 52 + 16 + 12);
        // A parent with nothing to inherit changes nothing.
        let parent = acl(&[(ALLOW, 0, 1, USERS)]);
        assert_eq!(
            assign(Some(&with_dacl(&parent)), None, &token, true, false),
            Ok(block.clone())
        );
        // Nor does a parent whose DACL is not marked present, or null.
        let inheritable = acl(&[(ALLOW, CI | OI, 1, USERS)]);
        let unmarked = Parts {
            control: 0,
            ..with_dacl(&inheritable)
        };
        assert_eq!(
            assign(Some(&unmarked), None, &token, true, false),
            Ok(block.clone())
        );
        let null = Parts {
            control: SE_DACL_PRESENT,
            ..Parts::default()
        };
        assert_eq!(assign(Some(&null), None, &token, true, false), Ok(block));
    }

    #[test]
    fn a_token_without_a_default_dacl_gives_none() {
        let mut token = Token::system();
        token.default_dacl = None;
        let block = assign(None, None, &token, false, false).unwrap();
        let made = parse_relative(&block).unwrap();
        assert_eq!((made.control, made.dacl), (SE_SELF_RELATIVE, None));
        assert_eq!(block.len(), 20 + 16 + 12);
    }

    #[test]
    fn a_supplied_dacl_wins_over_inheritance() {
        let token = Token::system();
        let parent = acl(&[(ALLOW, CI | OI, 1, USERS)]);
        let parent = with_dacl(&parent);
        let own = acl(&[
            (ALLOW, 0, GENERIC_READ, &CREATOR_OWNER),
            (ALLOW, CI | IO, GENERIC_READ, &CREATOR_OWNER),
            (DENY, ID, 2, USERS),
        ]);
        let explicit = with_dacl(&own);
        let block = assign(Some(&parent), Some(&explicit), &token, true, false).unwrap();
        let made = parse_relative(&block).unwrap();
        assert_eq!(made.control, SE_SELF_RELATIVE | SE_DACL_PRESENT);
        // Mapped where effective, the creator owner not named;
        // inherit-only left alone.
        assert_eq!(
            made.dacl.unwrap(),
            acl(&[
                (ALLOW, 0, MAPPING.read, &CREATOR_OWNER),
                (ALLOW, CI | IO, GENERIC_READ, &CREATOR_OWNER),
                (DENY, ID, 2, USERS),
            ])
        );
        // Spare room in a supplied ACL is kept.
        let mut roomy = acl(&[(ALLOW, 0, 1, USERS)]);
        roomy.extend([0; 16]);
        roomy[2] += 16;
        let block = assign(None, Some(&with_dacl(&roomy)), &token, false, false).unwrap();
        assert_eq!(parse_relative(&block).unwrap().dacl.unwrap(), roomy);
        // DACL (48), owner (16), group (12) after the header.
        assert_eq!(block.len(), 20 + 48 + 16 + 12);
    }

    #[test]
    fn a_defaulted_dacl_yields_to_inheritance() {
        let token = Token::system();
        let parent = acl(&[(ALLOW, CI | OI, 1, USERS)]);
        let parent = with_dacl(&parent);
        let own = acl(&[(DENY, 0, 2, USERS)]);
        let explicit = Parts {
            control: SE_DACL_PRESENT | SE_DACL_DEFAULTED,
            ..with_dacl(&own)
        };
        let block = assign(Some(&parent), Some(&explicit), &token, false, false).unwrap();
        let made = parse_relative(&block).unwrap();
        assert_eq!(made.dacl.unwrap(), acl(&[(ALLOW, 0, 1, USERS)]));
        assert_eq!(
            made.control,
            SE_SELF_RELATIVE | SE_DACL_PRESENT,
            "not defaulted"
        );
        // With nothing to inherit it is assigned, not the token's.
        let block = assign(None, Some(&explicit), &token, false, false).unwrap();
        assert_eq!(parse_relative(&block).unwrap().dacl.unwrap(), own);
    }

    #[test]
    fn a_supplied_null_dacl_is_a_null_dacl() {
        let token = Token::system();
        let parent = acl(&[(ALLOW, CI | OI, 1, USERS)]);
        let null = Parts {
            control: SE_DACL_PRESENT,
            ..Parts::default()
        };
        let block = assign(Some(&with_dacl(&parent)), Some(&null), &token, false, false).unwrap();
        let made = parse_relative(&block).unwrap();
        assert_eq!(
            (made.control, made.dacl),
            (SE_SELF_RELATIVE | SE_DACL_PRESENT, None)
        );
        // A DACL field without the "present" bit is not a supplied DACL.
        let own = acl(&[(DENY, 0, 2, USERS)]);
        let unmarked = Parts {
            control: 0,
            ..with_dacl(&own)
        };
        let block = assign(None, Some(&unmarked), &token, false, false).unwrap();
        assert_eq!(
            parse_relative(&block).unwrap().dacl.unwrap(),
            default_dacl()
        );
    }

    #[test]
    fn the_owner_must_be_one_the_creator_may_name() {
        fn named(owner: &[u8]) -> Parts<'_> {
            Parts {
                owner: Some(owner),
                ..Parts::default()
            }
        }
        let mut token = Token::system();
        let owner_of = |block: Vec<u8>| parse_relative(&block).unwrap().owner.unwrap().to_vec();
        // Its user, or a group with the owner bit.
        for sid in [&LOCAL_SYSTEM[..], &ADMINISTRATORS] {
            let block = assign(None, Some(&named(sid)), &token, false, false).unwrap();
            assert_eq!(owner_of(block), sid);
        }
        // Another group, or a stranger: refused in user mode only.
        for sid in [&WORLD[..], USERS] {
            assert_eq!(
                assign(None, Some(&named(sid)), &token, false, false),
                Err(AssignError::InvalidOwner)
            );
            let block = assign(None, Some(&named(sid)), &token, false, true).unwrap();
            assert_eq!(owner_of(block), sid);
        }
        // The restore privilege, enabled, allows any owner.
        for held in &mut token.privileges {
            if held.luid == crate::token::SE_RESTORE_PRIVILEGE {
                held.attributes = SE_PRIVILEGE_ENABLED;
            }
        }
        let block = assign(None, Some(&named(USERS)), &token, false, false).unwrap();
        assert_eq!(owner_of(block), USERS);
    }

    #[test]
    fn a_sacl_is_copied_when_supplied_and_inherited_like_a_dacl() {
        let mut token = Token::system();
        // An audit entry: success and failure are flags 0x40 and 0x80.
        let audit = acl(&[(2, 0xC0, GENERIC_READ, &WORLD)]);
        let explicit = Parts {
            control: SE_SACL_PRESENT,
            sacl: Some(&audit),
            ..Parts::default()
        };
        assert_eq!(
            assign(None, Some(&explicit), &token, false, false),
            Err(AssignError::PrivilegeNotHeld),
            "SYSTEM holds the privilege disabled"
        );
        let block = assign(None, Some(&explicit), &token, false, true).unwrap();
        let made = parse_relative(&block).unwrap();
        assert_eq!(
            made.control,
            SE_SELF_RELATIVE | SE_DACL_PRESENT | SE_SACL_PRESENT
        );
        assert_eq!(made.sacl.unwrap(), acl(&[(2, 0xC0, MAPPING.read, &WORLD)]));
        assert_eq!(made.dacl.unwrap(), default_dacl());
        token.privileges.push(Privilege {
            luid: SE_SECURITY_PRIVILEGE,
            attributes: SE_PRIVILEGE_ENABLED,
        });
        assert_eq!(
            assign(None, Some(&explicit), &token, false, false),
            Ok(block)
        );

        // From the parent: the audit flags stay, the inheritance flags
        // follow the rules.
        let inheritable = acl(&[(2, 0xC0 | CI | OI, 1, &WORLD)]);
        let parent = Parts {
            control: SE_SACL_PRESENT,
            sacl: Some(&inheritable),
            ..Parts::default()
        };
        let block = assign(Some(&parent), None, &token, false, false).unwrap();
        let made = parse_relative(&block).unwrap();
        assert_eq!(made.sacl.unwrap(), acl(&[(2, 0xC0, 1, &WORLD)]));
        let block = assign(Some(&parent), None, &token, true, false).unwrap();
        let made = parse_relative(&block).unwrap();
        assert_eq!(made.sacl.unwrap(), inheritable);
        // No SACL anywhere: none.
        let block = assign(None, None, &token, true, false).unwrap();
        assert_eq!(parse_relative(&block).unwrap().sacl, None);
    }

    #[test]
    fn entries_of_other_types_are_inherited_whole_or_not_at_all() {
        // An object-specific allow entry, and a mandatory label.
        let mut object = vec![5, CI | OI, 24, 0, 1, 0, 0, 0, 0, 0, 0, 0];
        object.extend(WORLD);
        let label = entry(0x11, CI | OI, GENERIC_READ, &CREATOR_OWNER);
        let parent = list(&[object, label.clone()]);
        let token = Token::system();
        let block = assign(Some(&with_dacl(&parent)), None, &token, true, true).unwrap();
        assert_eq!(
            parse_relative(&block).unwrap().dacl.unwrap(),
            list(&[label])
        );
        let block = assign(Some(&with_dacl(&parent)), None, &token, false, true).unwrap();
        assert_eq!(
            parse_relative(&block).unwrap().dacl.unwrap(),
            list(&[entry(0x11, 0, GENERIC_READ, &CREATOR_OWNER)])
        );
    }

    #[test]
    fn damaged_and_oversized_lists_are_refused() {
        let token = Token::system();
        let mut broken = acl(&[(ALLOW, CI | OI, 1, USERS)]);
        broken[4] = 9;
        let broken = with_dacl(&broken);
        assert_eq!(
            assign(Some(&broken), None, &token, true, true),
            Err(AssignError::InvalidAcl)
        );
        assert_eq!(
            assign(None, Some(&broken), &token, true, true),
            Err(AssignError::InvalidAcl)
        );
        // 2 000 entries of 20 bytes fit a list; the 4 000 a directory
        // inherits from them (24 and 20 bytes) do not.
        const CREATOR: &[u8] = &CREATOR_OWNER;
        let many = acl(&vec![(ALLOW, CI, GENERIC_READ, CREATOR); 2000]);
        assert_eq!(
            assign(Some(&with_dacl(&many)), None, &token, true, true),
            Err(AssignError::InvalidAcl)
        );
        // Inherited, with a longer SID for each creator owner: too long.
        let mut long = Token::system();
        long.owner = crate::sid(5, &[21; 15]).0.to_vec();
        let many = acl(&vec![(ALLOW, CI | NP, 1, CREATOR); 3000]);
        assert_eq!(
            assign(Some(&with_dacl(&many)), None, &long, true, true),
            Err(AssignError::InvalidAcl)
        );
    }
}
