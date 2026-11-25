//! The access check: may this token have this access to an object with
//! this security descriptor (`SeAccessCheck`).
//!
//! The algorithm is the one of [MS-DTYP] 2.5.3.2 and of ["How DACLs
//! control access to an object"], with what [SeAccessCheck] documents
//! for kernel callers. Where those pages are silent NK follows what
//! Windows is seen to do; each such choice is marked INFERRED and is
//! held to Windows by the conformance drivers.
//!
//! In order:
//!
//! 1. Generic rights in the request are mapped to the object type's own.
//! 2. A kernel-mode caller is granted what it asked, `MAXIMUM_ALLOWED`
//!    becoming the mapping's "generic all", and nothing is looked at.
//!    INFERRED: [SeAccessCheck] takes the mode and does not say what it
//!    does with it.
//! 3. An impersonation token below `SecurityImpersonation` is refused
//!    with `STATUS_BAD_IMPERSONATION_LEVEL`. INFERRED.
//! 4. A request for nothing succeeds with what was granted before, and
//!    fails if that is nothing too. INFERRED.
//! 5. `ACCESS_SYSTEM_SECURITY` is granted by `SeSecurityPrivilege` and
//!    by nothing else; without it the check fails at once ([MS-DTYP];
//!    INFERRED: with `STATUS_PRIVILEGE_NOT_HELD`). `WRITE_OWNER` is
//!    granted by `SeTakeOwnershipPrivilege` before the DACL is read
//!    ([MS-DTYP]). Neither privilege is consulted unless its right is
//!    asked for by name ([SeAccessCheck]: "does not do any privilege
//!    checks unless the caller specifically requests them").
//! 6. No DACL: everything asked is granted; `MAXIMUM_ALLOWED` gives
//!    "generic all plus any additional access the caller explicitly
//!    requests" ([SeAccessCheck]).
//! 7. The owner is granted `READ_CONTROL` and `WRITE_DAC`, unless the
//!    DACL has an effective entry for OWNER RIGHTS (S-1-3-4), which then
//!    stands for the owner in the walk ([MS-DTYP]).
//! 8. The DACL is walked in the order stored. An entry counts when it
//!    is not inherit-only and its SID is in the token (`Token::has_sid`):
//!    the first entry that counts decides each right, allow or deny.
//!    For a request by name that is [MS-DTYP]'s walk. For
//!    `MAXIMUM_ALLOWED`, [MS-DTYP] subtracts every denied right whatever
//!    the order; NK lets the order decide there too. INFERRED.
//! 9. A request by name succeeds when every right is granted; one with
//!    `MAXIMUM_ALLOWED` when also something at all is granted, now or
//!    before (INFERRED for "or before"). A refusal grants nothing.
//!
//! Not done: object-specific and conditional entries (skipped, as are
//! all types but allow and deny), restricted tokens, mandatory integrity
//! policy, AppContainer and central access policy checks, auditing.
//!
//! [MS-DTYP]: https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-dtyp/4f1bbcbb-814a-4c70-a11e-2a5b8779a6f9
//! ["How DACLs control access to an object"]: https://learn.microsoft.com/en-us/windows/win32/secauthz/how-dacls-control-access-to-an-object
//! [SeAccessCheck]: https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-seaccesscheck

use crate::acl::{ACCESS_DENIED_ACE, INHERIT_ONLY_ACE, aces};
use crate::token::{
    Luid, OWNER_RIGHTS, SE_SECURITY_PRIVILEGE, SE_TAKE_OWNERSHIP_PRIVILEGE, SECURITY_IMPERSONATION,
    Token, TokenType,
};
use crate::{ACCESS_ALLOWED_ACE, Parts, acl_used};
use alloc::vec::Vec;

/// Access rights every object type has (`ACCESS_MASK`).
pub const DELETE: u32 = 0x0001_0000;
pub const READ_CONTROL: u32 = 0x0002_0000;
pub const WRITE_DAC: u32 = 0x0004_0000;
pub const WRITE_OWNER: u32 = 0x0008_0000;
pub const SYNCHRONIZE: u32 = 0x0010_0000;
pub const ACCESS_SYSTEM_SECURITY: u32 = 0x0100_0000;
pub const MAXIMUM_ALLOWED: u32 = 0x0200_0000;
pub const GENERIC_ALL: u32 = 0x1000_0000;
pub const GENERIC_EXECUTE: u32 = 0x2000_0000;
pub const GENERIC_WRITE: u32 = 0x4000_0000;
pub const GENERIC_READ: u32 = 0x8000_0000;

/// What each generic right means for one type of object
/// (`GENERIC_MAPPING`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GenericMapping {
    pub read: u32,
    pub write: u32,
    pub execute: u32,
    pub all: u32,
}

/// `mask` with its generic rights replaced by what they stand for
/// (`RtlMapGenericMask`).
pub const fn map_generic(mask: u32, mapping: &GenericMapping) -> u32 {
    let mut mapped = mask & !(GENERIC_READ | GENERIC_WRITE | GENERIC_EXECUTE | GENERIC_ALL);
    if mask & GENERIC_READ != 0 {
        mapped |= mapping.read;
    }
    if mask & GENERIC_WRITE != 0 {
        mapped |= mapping.write;
    }
    if mask & GENERIC_EXECUTE != 0 {
        mapped |= mapping.execute;
    }
    if mask & GENERIC_ALL != 0 {
        mapped |= mapping.all;
    }
    mapped
}

/// How a check ended, as the status Windows gives for it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Status {
    /// `STATUS_SUCCESS`
    Success,
    /// `STATUS_ACCESS_DENIED`
    AccessDenied,
    /// `STATUS_PRIVILEGE_NOT_HELD`
    PrivilegeNotHeld,
    /// `STATUS_BAD_IMPERSONATION_LEVEL`
    BadImpersonationLevel,
}

/// One question for the access check.
#[derive(Debug, Clone, Copy)]
pub struct Request<'a> {
    /// The token that asks: see `subject_token`.
    pub token: &'a Token,
    /// The object's descriptor.
    pub descriptor: &'a Parts<'a>,
    /// The rights wanted, generic ones and `MAXIMUM_ALLOWED` included.
    pub desired: u32,
    /// Rights the caller already has; a success grants them as well.
    pub previously_granted: u32,
    pub mapping: GenericMapping,
    /// Whether the access mode is `KernelMode`.
    pub kernel_mode: bool,
}

/// The answer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Outcome {
    /// The rights granted; zero unless `status` is `Success`.
    pub granted: u32,
    pub status: Status,
    /// The privileges that granted a right, for the caller's
    /// `PRIVILEGE_SET`.
    pub privileges: Vec<Luid>,
}

/// The token an access check is made against: the client's while a
/// thread impersonates, else the process's (`SECURITY_SUBJECT_CONTEXT`).
pub fn subject_token<'a>(client: Option<&'a Token>, primary: &'a Token) -> &'a Token {
    client.unwrap_or(primary)
}

/// `SeAccessCheck`: see the module's description for the rules.
pub fn access_check(request: &Request<'_>) -> Outcome {
    let refused = |status| Outcome {
        granted: 0,
        status,
        privileges: Vec::new(),
    };
    let granted = |rights: u32, privileges| Outcome {
        granted: rights | request.previously_granted,
        status: Status::Success,
        privileges,
    };
    let (token, mapping) = (request.token, &request.mapping);
    let desired = map_generic(request.desired, mapping);
    let maximum = desired & MAXIMUM_ALLOWED != 0;
    let wanted = desired & !MAXIMUM_ALLOWED;
    // "Everything": what a kernel caller or an unprotected object gets.
    let everything = if maximum {
        wanted | mapping.all
    } else {
        wanted
    };
    if request.kernel_mode {
        return granted(everything, Vec::new());
    }
    if token.token_type == TokenType::Impersonation
        && token.impersonation_level < SECURITY_IMPERSONATION
    {
        return refused(Status::BadImpersonationLevel);
    }
    if desired == 0 {
        return if request.previously_granted == 0 {
            refused(Status::AccessDenied)
        } else {
            granted(0, Vec::new())
        };
    }

    // What privileges and ownership give, before any entry is read.
    let mut allowed = 0;
    let mut privileges = Vec::new();
    if wanted & ACCESS_SYSTEM_SECURITY != 0 {
        if !token.privilege_enabled(SE_SECURITY_PRIVILEGE) {
            return refused(Status::PrivilegeNotHeld);
        }
        allowed |= ACCESS_SYSTEM_SECURITY;
        privileges.push(SE_SECURITY_PRIVILEGE);
    }
    if wanted & WRITE_OWNER != 0 && token.privilege_enabled(SE_TAKE_OWNERSHIP_PRIVILEGE) {
        allowed |= WRITE_OWNER;
        privileges.push(SE_TAKE_OWNERSHIP_PRIVILEGE);
    }
    let Some(dacl) = request.descriptor.present().dacl else {
        return granted(everything, privileges);
    };
    if acl_used(dacl).is_none() {
        // NK's decision: a DACL that cannot be read protects the object.
        return refused(Status::AccessDenied);
    }
    // An entry of the DACL that takes part: (denies, mask, SID).
    let effective = || {
        aces(dacl).filter_map(|ace| {
            let (mask, sid) = ace.basic()?;
            (ace.flags & INHERIT_ONLY_ACE == 0 && ace.kind <= ACCESS_DENIED_ACE).then_some((
                ace.kind != ACCESS_ALLOWED_ACE,
                mask,
                sid,
            ))
        })
    };
    let owner = request
        .descriptor
        .owner
        .is_some_and(|owner| token.has_sid(owner, false));
    if owner && !effective().any(|(_, _, sid)| sid == OWNER_RIGHTS) {
        allowed |= READ_CONTROL | WRITE_DAC;
    }

    let mut denied = 0;
    for (denies, mask, sid) in effective() {
        let applies = if sid == OWNER_RIGHTS {
            owner
        } else {
            token.has_sid(sid, denies)
        };
        if !applies {
            continue;
        }
        // A DACL grants neither of these two.
        let mask = map_generic(mask, mapping) & !(ACCESS_SYSTEM_SECURITY | MAXIMUM_ALLOWED);
        // A right already allowed stays allowed; one denied first is
        // never allowed after.
        if denies {
            denied |= mask;
        } else {
            allowed |= mask & !denied;
        }
    }

    if wanted & !allowed != 0 {
        return refused(Status::AccessDenied);
    }
    if !maximum {
        return granted(wanted, privileges);
    }
    if allowed | request.previously_granted == 0 {
        return refused(Status::AccessDenied);
    }
    granted(allowed, privileges)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::SE_DACL_PRESENT;
    use crate::acl::tests::{entry, list};
    use crate::token::{
        Privilege, SE_GROUP_ENABLED, SE_GROUP_MANDATORY, SE_GROUP_USE_FOR_DENY_ONLY,
        SE_PRIVILEGE_ENABLED, SECURITY_IDENTIFICATION, SidAndAttributes, WORLD,
    };

    // The case table (`cases`) is plain data so that a conformance
    // driver can replay it on Windows: tokens, descriptors and requests
    // are spelled out, nothing is computed.

    /// A token, as the parts that matter here.
    struct Who {
        user: &'static [u8],
        groups: &'static [(&'static [u8], u32)],
        /// (privilege, attributes)
        privileges: &'static [(Luid, u32)],
        /// The level of an impersonation token; `None` for a primary.
        impersonation: Option<u32>,
    }

    /// (type, flags, mask, SID)
    type Entry = (u8, u8, u32, &'static [u8]);

    struct Case {
        name: &'static str,
        who: &'static Who,
        owner: Option<&'static [u8]>,
        /// `None`: the descriptor has no DACL.
        dacl: Option<&'static [Entry]>,
        desired: u32,
        previously: u32,
        kernel: bool,
        granted: u32,
        status: Status,
        privileges: &'static [Luid],
    }

    /// S-1-5-21-1-2-3-`rid`.
    const fn account(rid: u32) -> [u8; 28] {
        let (bytes, _) = crate::sid(5, &[21, 1, 2, 3, rid]);
        let mut out = [0u8; 28];
        let mut i = 0;
        while i < 28 {
            out[i] = bytes[i];
            i += 1;
        }
        out
    }
    const ALICE: &[u8] = &account(1001);
    const BOB: &[u8] = &account(1002);
    const STAFF: &[u8] = &account(2000);
    const DISABLED: &[u8] = &account(2001);
    const DENY_ONLY: &[u8] = &account(2002);
    const EVERYONE: &[u8] = &WORLD;
    const OWNER: &[u8] = &OWNER_RIGHTS;

    const ON: u32 = SE_GROUP_MANDATORY | SE_GROUP_ENABLED;
    const GROUPS: &[(&[u8], u32)] = &[
        (EVERYONE, ON),
        (STAFF, ON),
        (DISABLED, 0),
        (DENY_ONLY, SE_GROUP_USE_FOR_DENY_ONLY | SE_GROUP_ENABLED),
    ];
    /// An ordinary user with no privileges.
    const PLAIN: &Who = &Who {
        user: ALICE,
        groups: GROUPS,
        privileges: &[],
        impersonation: None,
    };
    /// The same, with the two privileges an access check may use.
    const PRIVILEGED: &Who = &Who {
        user: ALICE,
        groups: GROUPS,
        privileges: &[
            (SE_SECURITY_PRIVILEGE, SE_PRIVILEGE_ENABLED),
            (SE_TAKE_OWNERSHIP_PRIVILEGE, SE_PRIVILEGE_ENABLED),
        ],
        impersonation: None,
    };
    /// The same, holding them disabled.
    const SWITCHED_OFF: &Who = &Who {
        user: ALICE,
        groups: GROUPS,
        privileges: &[(SE_SECURITY_PRIVILEGE, 0), (SE_TAKE_OWNERSHIP_PRIVILEGE, 0)],
        impersonation: None,
    };
    const IDENTIFIED: &Who = &Who {
        user: ALICE,
        groups: GROUPS,
        privileges: &[],
        impersonation: Some(SECURITY_IDENTIFICATION),
    };
    const IMPERSONATED: &Who = &Who {
        user: ALICE,
        groups: GROUPS,
        privileges: &[],
        impersonation: Some(SECURITY_IMPERSONATION),
    };

    /// The mapping of a file.
    const MAPPING: GenericMapping = GenericMapping {
        read: 0x0012_0089,
        write: 0x0012_0116,
        execute: 0x0012_00A0,
        all: 0x001F_01FF,
    };
    const ALL: u32 = MAPPING.all;
    const ALLOW: u8 = 0;
    const DENY: u8 = 1;
    const IO: u8 = INHERIT_ONLY_ACE;
    const MAX: u32 = MAXIMUM_ALLOWED;
    const ASS: u32 = ACCESS_SYSTEM_SECURITY;
    const OK: Status = Status::Success;
    const NO: Status = Status::AccessDenied;

    /// A case with the common defaults: owned by Bob, user mode,
    /// nothing granted before, no privilege used.
    fn case(
        name: &'static str,
        dacl: Option<&'static [Entry]>,
        desired: u32,
        granted: u32,
        status: Status,
    ) -> Case {
        Case {
            name,
            who: PLAIN,
            owner: Some(BOB),
            dacl,
            desired,
            previously: 0,
            kernel: false,
            granted,
            status,
            privileges: &[],
        }
    }

    fn owned(owner: &'static [u8], mut case: Case) -> Case {
        case.owner = Some(owner);
        case
    }
    fn by(who: &'static Who, used: &'static [Luid], mut case: Case) -> Case {
        case.who = who;
        case.privileges = used;
        case
    }
    fn kernel(mut case: Case) -> Case {
        case.kernel = true;
        case
    }
    fn having(previously: u32, mut case: Case) -> Case {
        case.previously = previously;
        case
    }

    fn cases() -> Vec<Case> {
        vec![
            // Generic rights.
            case(
                "a generic right asked for is mapped",
                Some(&[(ALLOW, 0, 0x0012_0089, ALICE)]),
                GENERIC_READ,
                0x0012_0089,
                OK,
            ),
            case(
                "a generic right in an entry is mapped",
                Some(&[(ALLOW, 0, GENERIC_READ, ALICE)]),
                0x0012_0089,
                0x0012_0089,
                OK,
            ),
            case(
                "generic all needs every right",
                Some(&[(ALLOW, 0, GENERIC_READ | GENERIC_WRITE, ALICE)]),
                GENERIC_ALL,
                0,
                NO,
            ),
            case(
                "the user and an enabled group add up",
                Some(&[
                    (ALLOW, 0, 1, ALICE),
                    (ALLOW, 0, 2, STAFF),
                    (ALLOW, 0, 4, EVERYONE),
                ]),
                7,
                7,
                OK,
            ),
            case(
                "a stranger's entry gives nothing",
                Some(&[(ALLOW, 0, 1, BOB)]),
                1,
                0,
                NO,
            ),
            // MAXIMUM_ALLOWED.
            case(
                "maximum allowed collects every allowed right",
                Some(&[(ALLOW, 0, 3, ALICE), (ALLOW, 0, SYNCHRONIZE, STAFF)]),
                MAX,
                0x0010_0003,
                OK,
            ),
            case(
                "maximum allowed with a right that is granted",
                Some(&[(ALLOW, 0, 3, ALICE)]),
                MAX | 1,
                3,
                OK,
            ),
            case(
                "maximum allowed with a right that is not",
                Some(&[(ALLOW, 0, 3, ALICE)]),
                MAX | 4,
                0,
                NO,
            ),
            case(
                "maximum allowed of nothing is refused",
                Some(&[(ALLOW, 0, 3, BOB)]),
                MAX,
                0,
                NO,
            ),
            having(
                4,
                case(
                    "maximum allowed of nothing new keeps what was granted",
                    Some(&[]),
                    MAX,
                    4,
                    OK,
                ),
            ),
            case(
                "a DACL grants neither system security nor maximum allowed",
                Some(&[(ALLOW, 0, ASS | MAX | 1, ALICE)]),
                MAX,
                1,
                OK,
            ),
            // No DACL, empty DACL.
            case("no DACL grants what is asked", None, ALL, ALL, OK),
            case(
                "no DACL grants generic all for maximum allowed",
                None,
                MAX,
                ALL,
                OK,
            ),
            case(
                "no DACL: maximum allowed plus what is named",
                None,
                MAX | 0x0020_0000,
                ALL | 0x0020_0000,
                OK,
            ),
            case("an empty DACL grants nothing", Some(&[]), 1, 0, NO),
            // The owner.
            owned(
                ALICE,
                case(
                    "the owner may read and write the DACL",
                    Some(&[]),
                    READ_CONTROL | WRITE_DAC,
                    READ_CONTROL | WRITE_DAC,
                    OK,
                ),
            ),
            owned(
                ALICE,
                case(
                    "the owner gets no more than that",
                    Some(&[]),
                    READ_CONTROL | 1,
                    0,
                    NO,
                ),
            ),
            owned(
                ALICE,
                case(
                    "the owner's maximum over an empty DACL",
                    Some(&[]),
                    MAX,
                    READ_CONTROL | WRITE_DAC,
                    OK,
                ),
            ),
            owned(
                ALICE,
                case(
                    "the owner's rights join the DACL's",
                    Some(&[(ALLOW, 0, 1, EVERYONE)]),
                    WRITE_DAC | 1,
                    WRITE_DAC | 1,
                    OK,
                ),
            ),
            owned(
                ALICE,
                case(
                    "a deny entry does not take the owner's rights",
                    Some(&[(DENY, 0, READ_CONTROL | WRITE_DAC, ALICE)]),
                    READ_CONTROL,
                    READ_CONTROL,
                    OK,
                ),
            ),
            owned(
                STAFF,
                case(
                    "an enabled group may be the owner",
                    Some(&[]),
                    WRITE_DAC,
                    WRITE_DAC,
                    OK,
                ),
            ),
            owned(
                DISABLED,
                case(
                    "a disabled group is not the owner",
                    Some(&[]),
                    WRITE_DAC,
                    0,
                    NO,
                ),
            ),
            owned(
                DENY_ONLY,
                case(
                    "a deny-only group is not the owner",
                    Some(&[]),
                    WRITE_DAC,
                    0,
                    NO,
                ),
            ),
            case("someone else's object", Some(&[]), READ_CONTROL, 0, NO),
            Case {
                owner: None,
                ..case(
                    "a descriptor without an owner has none",
                    Some(&[]),
                    READ_CONTROL,
                    0,
                    NO,
                )
            },
            // OWNER RIGHTS.
            owned(
                ALICE,
                case(
                    "owner rights replace the implicit rights",
                    Some(&[(ALLOW, 0, READ_CONTROL, OWNER)]),
                    WRITE_DAC,
                    0,
                    NO,
                ),
            ),
            owned(
                ALICE,
                case(
                    "owner rights grant what they say",
                    Some(&[(ALLOW, 0, READ_CONTROL | 1, OWNER)]),
                    READ_CONTROL | 1,
                    READ_CONTROL | 1,
                    OK,
                ),
            ),
            owned(
                ALICE,
                case(
                    "owner rights may deny",
                    Some(&[(DENY, 0, WRITE_DAC, OWNER), (ALLOW, 0, ALL, ALICE)]),
                    WRITE_DAC,
                    0,
                    NO,
                ),
            ),
            case(
                "owner rights are not for others",
                Some(&[(ALLOW, 0, READ_CONTROL, OWNER)]),
                READ_CONTROL,
                0,
                NO,
            ),
            owned(
                ALICE,
                case(
                    "an inherit-only owner rights entry changes nothing",
                    Some(&[(ALLOW, IO, 1, OWNER)]),
                    WRITE_DAC,
                    WRITE_DAC,
                    OK,
                ),
            ),
            // Order: as stored.
            case(
                "allow before deny allows",
                Some(&[(ALLOW, 0, 1, ALICE), (DENY, 0, 1, ALICE)]),
                1,
                1,
                OK,
            ),
            case(
                "deny before allow denies",
                Some(&[(DENY, 0, 1, ALICE), (ALLOW, 0, 1, ALICE)]),
                1,
                0,
                NO,
            ),
            case(
                "a deny of another right does not matter",
                Some(&[(DENY, 0, 2, ALICE), (ALLOW, 0, 1, ALICE)]),
                1,
                1,
                OK,
            ),
            case(
                "one denied right refuses the request",
                Some(&[(DENY, 0, 2, EVERYONE), (ALLOW, 0, 3, ALICE)]),
                3,
                0,
                NO,
            ),
            case(
                "maximum allowed leaves out what was denied first",
                Some(&[(DENY, 0, 2, ALICE), (ALLOW, 0, 3, ALICE)]),
                MAX,
                1,
                OK,
            ),
            case(
                "maximum allowed keeps what was allowed first",
                Some(&[(ALLOW, 0, 3, ALICE), (DENY, 0, 2, ALICE)]),
                MAX,
                3,
                OK,
            ),
            // Deny-only and disabled groups, inherit-only and other entries.
            case(
                "a deny-only group is not allowed",
                Some(&[(ALLOW, 0, 1, DENY_ONLY)]),
                1,
                0,
                NO,
            ),
            case(
                "a deny-only group is denied",
                Some(&[(DENY, 0, 1, DENY_ONLY), (ALLOW, 0, 1, ALICE)]),
                1,
                0,
                NO,
            ),
            case(
                "a disabled group is not allowed",
                Some(&[(ALLOW, 0, 1, DISABLED)]),
                1,
                0,
                NO,
            ),
            case(
                "a disabled group is not denied",
                Some(&[(DENY, 0, 1, DISABLED), (ALLOW, 0, 1, ALICE)]),
                1,
                1,
                OK,
            ),
            case(
                "an inherit-only allow is skipped",
                Some(&[(ALLOW, IO, 1, ALICE)]),
                1,
                0,
                NO,
            ),
            case(
                "an inherit-only deny is skipped",
                Some(&[(DENY, IO, 1, ALICE), (ALLOW, 0, 1, ALICE)]),
                1,
                1,
                OK,
            ),
            case(
                "audit, conditional and label entries are skipped",
                Some(&[(2, 0, 1, ALICE), (9, 0, 1, ALICE), (0x11, 0, 1, ALICE)]),
                1,
                0,
                NO,
            ),
            case(
                "a conditional deny is skipped",
                Some(&[(10, 0, 1, ALICE), (ALLOW, 0, 1, ALICE)]),
                1,
                1,
                OK,
            ),
            // Kernel mode.
            kernel(case(
                "kernel mode is granted what it asks",
                Some(&[]),
                1,
                1,
                OK,
            )),
            kernel(case(
                "kernel mode: generic rights are mapped",
                Some(&[]),
                GENERIC_WRITE,
                0x0012_0116,
                OK,
            )),
            kernel(case(
                "kernel mode: maximum allowed is generic all",
                Some(&[]),
                MAX | 0x0020_0000,
                ALL | 0x0020_0000,
                OK,
            )),
            kernel(case(
                "kernel mode needs no privilege",
                Some(&[]),
                ASS,
                ASS,
                OK,
            )),
            kernel(having(
                SYNCHRONIZE,
                case(
                    "kernel mode keeps what was granted",
                    Some(&[]),
                    0,
                    SYNCHRONIZE,
                    OK,
                ),
            )),
            kernel(by(
                IDENTIFIED,
                &[],
                case(
                    "kernel mode ignores the impersonation level",
                    Some(&[]),
                    1,
                    1,
                    OK,
                ),
            )),
            // Granted before.
            having(
                SYNCHRONIZE,
                case(
                    "rights granted before are kept",
                    Some(&[(ALLOW, 0, 1, ALICE)]),
                    1,
                    SYNCHRONIZE | 1,
                    OK,
                ),
            ),
            having(
                2,
                case(
                    "rights granted before do not survive a refusal",
                    Some(&[]),
                    1,
                    0,
                    NO,
                ),
            ),
            having(
                2,
                case("asking nothing keeps what was granted", Some(&[]), 0, 2, OK),
            ),
            case(
                "asking nothing with nothing granted is refused",
                None,
                0,
                0,
                NO,
            ),
            // Privileges.
            by(
                PRIVILEGED,
                &[SE_SECURITY_PRIVILEGE],
                case(
                    "the security privilege grants system security",
                    Some(&[]),
                    ASS,
                    ASS,
                    OK,
                ),
            ),
            by(
                PRIVILEGED,
                &[SE_SECURITY_PRIVILEGE],
                case(
                    "system security beside a right from the DACL",
                    Some(&[(ALLOW, 0, 1, ALICE)]),
                    ASS | 1,
                    ASS | 1,
                    OK,
                ),
            ),
            by(
                PRIVILEGED,
                &[],
                case("a refusal uses no privilege", Some(&[]), ASS | 1, 0, NO),
            ),
            Case {
                status: Status::PrivilegeNotHeld,
                ..case(
                    "system security without the privilege",
                    Some(&[(ALLOW, 0, ASS, ALICE)]),
                    ASS,
                    0,
                    NO,
                )
            },
            Case {
                status: Status::PrivilegeNotHeld,
                ..by(
                    SWITCHED_OFF,
                    &[],
                    case(
                        "system security with the privilege disabled",
                        Some(&[]),
                        ASS,
                        0,
                        NO,
                    ),
                )
            },
            Case {
                status: Status::PrivilegeNotHeld,
                ..case(
                    "system security without the privilege, no DACL",
                    None,
                    ASS,
                    0,
                    NO,
                )
            },
            by(
                PRIVILEGED,
                &[SE_TAKE_OWNERSHIP_PRIVILEGE],
                case(
                    "the take-ownership privilege grants write owner",
                    Some(&[]),
                    WRITE_OWNER,
                    WRITE_OWNER,
                    OK,
                ),
            ),
            by(
                PRIVILEGED,
                &[SE_TAKE_OWNERSHIP_PRIVILEGE],
                case(
                    "the privilege is used before a deny entry is read",
                    Some(&[(DENY, 0, WRITE_OWNER, ALICE)]),
                    WRITE_OWNER,
                    WRITE_OWNER,
                    OK,
                ),
            ),
            by(
                PRIVILEGED,
                &[SE_TAKE_OWNERSHIP_PRIVILEGE],
                case(
                    "the privilege is used even with no DACL",
                    None,
                    WRITE_OWNER,
                    WRITE_OWNER,
                    OK,
                ),
            ),
            by(
                PRIVILEGED,
                &[SE_SECURITY_PRIVILEGE, SE_TAKE_OWNERSHIP_PRIVILEGE],
                case(
                    "both privileges at once",
                    Some(&[]),
                    ASS | WRITE_OWNER,
                    ASS | WRITE_OWNER,
                    OK,
                ),
            ),
            case(
                "write owner from the DACL uses no privilege",
                Some(&[(ALLOW, 0, WRITE_OWNER, ALICE)]),
                WRITE_OWNER,
                WRITE_OWNER,
                OK,
            ),
            by(
                SWITCHED_OFF,
                &[],
                case(
                    "write owner with the privilege disabled",
                    Some(&[]),
                    WRITE_OWNER,
                    0,
                    NO,
                ),
            ),
            by(
                PRIVILEGED,
                &[],
                case(
                    "maximum allowed consults no privilege",
                    Some(&[(ALLOW, 0, 1, ALICE)]),
                    MAX,
                    1,
                    OK,
                ),
            ),
            // Impersonation.
            Case {
                status: Status::BadImpersonationLevel,
                ..by(
                    IDENTIFIED,
                    &[],
                    case(
                        "an identification token may not ask",
                        Some(&[(ALLOW, 0, 1, ALICE)]),
                        1,
                        0,
                        NO,
                    ),
                )
            },
            by(
                IMPERSONATED,
                &[],
                case(
                    "an impersonation token may",
                    Some(&[(ALLOW, 0, 1, ALICE)]),
                    1,
                    1,
                    OK,
                ),
            ),
        ]
    }

    fn token(who: &Who) -> Token {
        let mut token = Token::system();
        token.user = SidAndAttributes {
            sid: who.user.to_vec(),
            attributes: 0,
        };
        token.groups = who
            .groups
            .iter()
            .map(|&(sid, attributes)| SidAndAttributes {
                sid: sid.to_vec(),
                attributes,
            })
            .collect();
        token.privileges = who
            .privileges
            .iter()
            .map(|&(luid, attributes)| Privilege { luid, attributes })
            .collect();
        if let Some(level) = who.impersonation {
            token.token_type = TokenType::Impersonation;
            token.impersonation_level = level;
        }
        token
    }

    fn dacl(entries: &[Entry]) -> Vec<u8> {
        let entries: Vec<Vec<u8>> = entries
            .iter()
            .map(|&(kind, flags, mask, sid)| entry(kind, flags, mask, sid))
            .collect();
        list(&entries)
    }

    #[test]
    fn the_case_table() {
        for case in cases() {
            let token = token(case.who);
            let dacl = case.dacl.map(dacl);
            let descriptor = Parts {
                control: SE_DACL_PRESENT,
                owner: case.owner,
                group: None,
                sacl: None,
                dacl: dacl.as_deref(),
            };
            let outcome = access_check(&Request {
                token: &token,
                descriptor: &descriptor,
                desired: case.desired,
                previously_granted: case.previously,
                mapping: MAPPING,
                kernel_mode: case.kernel,
            });
            assert_eq!(
                (outcome.granted, outcome.status, &outcome.privileges[..]),
                (case.granted, case.status, case.privileges),
                "{}",
                case.name
            );
        }
    }

    #[test]
    fn case_names_are_unique() {
        let cases = cases();
        let mut names: Vec<&str> = cases.iter().map(|case| case.name).collect();
        names.sort_unstable();
        names.dedup();
        assert_eq!(names.len(), cases.len());
    }

    fn ask(descriptor: &Parts<'_>, desired: u32) -> (u32, Status) {
        let token = token(PLAIN);
        let outcome = access_check(&Request {
            token: &token,
            descriptor,
            desired,
            previously_granted: 0,
            mapping: MAPPING,
            kernel_mode: false,
        });
        (outcome.granted, outcome.status)
    }

    #[test]
    fn a_dacl_that_is_not_present_is_no_dacl() {
        // The list is there, but the control bits say to ignore it.
        let empty = dacl(&[]);
        let descriptor = Parts {
            control: 0,
            owner: Some(BOB),
            dacl: Some(&empty),
            ..Parts::default()
        };
        assert_eq!(ask(&descriptor, 1), (1, OK));
        // Present and null is no DACL either.
        let null = Parts {
            control: SE_DACL_PRESENT,
            ..Parts::default()
        };
        assert_eq!(ask(&null, 1), (1, OK));
    }

    #[test]
    fn a_damaged_dacl_protects_the_object() {
        let mut broken = dacl(&[(ALLOW, 0, 1, ALICE)]);
        broken[4] = 2;
        let descriptor = Parts {
            control: SE_DACL_PRESENT,
            owner: Some(ALICE),
            dacl: Some(&broken),
            ..Parts::default()
        };
        assert_eq!(ask(&descriptor, 1), (0, NO));
        assert_eq!(ask(&descriptor, READ_CONTROL), (0, NO));
    }

    #[test]
    fn the_accounts_of_the_table_are_sids() {
        assert_eq!(&account(1001)[..], ALICE);
        for sid in [ALICE, BOB, STAFF, DISABLED, DENY_ONLY] {
            assert_eq!(crate::valid_sid(sid), Some(28));
        }
        // S-1-5-21-1-2-3-1002.
        assert_eq!(BOB[..12], [1, 5, 0, 0, 0, 0, 0, 5, 21, 0, 0, 0]);
        assert_eq!(BOB[24..], [0xEA, 3, 0, 0]);
    }

    #[test]
    fn the_subject_is_the_client_while_impersonating() {
        let (primary, client) = (Token::system(), token(IMPERSONATED));
        assert_eq!(subject_token(None, &primary), &primary);
        assert_eq!(subject_token(Some(&client), &primary), &client);
    }

    #[test]
    fn generic_rights_map_one_by_one() {
        assert_eq!(map_generic(GENERIC_READ, &MAPPING), MAPPING.read);
        assert_eq!(map_generic(GENERIC_WRITE, &MAPPING), MAPPING.write);
        assert_eq!(map_generic(GENERIC_EXECUTE, &MAPPING), MAPPING.execute);
        assert_eq!(map_generic(GENERIC_ALL, &MAPPING), MAPPING.all);
        assert_eq!(
            map_generic(GENERIC_READ | GENERIC_EXECUTE | DELETE, &MAPPING),
            MAPPING.read | MAPPING.execute | DELETE
        );
        assert_eq!(map_generic(MAX | 5, &MAPPING), MAX | 5, "nothing generic");
    }
}
