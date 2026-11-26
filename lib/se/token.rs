//! The access token as plain data: who a subject is, which groups and
//! privileges it carries, and what a new object of its making defaults
//! to. The kernel wraps one in an object; nothing here is a layout a
//! driver sees (`TOKEN` is opaque to drivers, which ask through `Se*`
//! and `Ps*` calls).
//!
//! Microsoft's description of the parts:
//! <https://learn.microsoft.com/en-us/windows/win32/secauthz/access-tokens>

use crate::{ACL_HEADER, ACL_REVISION, SID_MAX_SIZE, add_access_allowed, sid};
use alloc::vec::Vec;

/// A locally unique identifier: `LUID`, low part first, as one number.
pub type Luid = u64;

/// `SYSTEM_LUID`: the logon session of the system itself.
pub const SYSTEM_LUID: Luid = 0x3E7;

/// Group attributes (`SE_GROUP_*`).
pub const SE_GROUP_MANDATORY: u32 = 0x1;
pub const SE_GROUP_ENABLED_BY_DEFAULT: u32 = 0x2;
pub const SE_GROUP_ENABLED: u32 = 0x4;
pub const SE_GROUP_OWNER: u32 = 0x8;
pub const SE_GROUP_USE_FOR_DENY_ONLY: u32 = 0x10;
pub const SE_GROUP_INTEGRITY: u32 = 0x20;
pub const SE_GROUP_INTEGRITY_ENABLED: u32 = 0x40;
pub const SE_GROUP_LOGON_ID: u32 = 0xC000_0000;

/// Privilege attributes (`SE_PRIVILEGE_*`).
pub const SE_PRIVILEGE_ENABLED_BY_DEFAULT: u32 = 0x1;
pub const SE_PRIVILEGE_ENABLED: u32 = 0x2;
pub const SE_PRIVILEGE_USED_FOR_ACCESS: u32 = 0x8000_0000;

/// Privilege numbers (`SE_*_PRIVILEGE` in `wdm.h`).
pub const SE_CREATE_TOKEN_PRIVILEGE: Luid = 2;
pub const SE_ASSIGNPRIMARYTOKEN_PRIVILEGE: Luid = 3;
pub const SE_LOCK_MEMORY_PRIVILEGE: Luid = 4;
pub const SE_INCREASE_QUOTA_PRIVILEGE: Luid = 5;
pub const SE_TCB_PRIVILEGE: Luid = 7;
pub const SE_SECURITY_PRIVILEGE: Luid = 8;
pub const SE_TAKE_OWNERSHIP_PRIVILEGE: Luid = 9;
pub const SE_LOAD_DRIVER_PRIVILEGE: Luid = 10;
pub const SE_SYSTEM_PROFILE_PRIVILEGE: Luid = 11;
pub const SE_SYSTEMTIME_PRIVILEGE: Luid = 12;
pub const SE_PROF_SINGLE_PROCESS_PRIVILEGE: Luid = 13;
pub const SE_INC_BASE_PRIORITY_PRIVILEGE: Luid = 14;
pub const SE_CREATE_PAGEFILE_PRIVILEGE: Luid = 15;
pub const SE_CREATE_PERMANENT_PRIVILEGE: Luid = 16;
pub const SE_BACKUP_PRIVILEGE: Luid = 17;
pub const SE_RESTORE_PRIVILEGE: Luid = 18;
pub const SE_SHUTDOWN_PRIVILEGE: Luid = 19;
pub const SE_DEBUG_PRIVILEGE: Luid = 20;
pub const SE_AUDIT_PRIVILEGE: Luid = 21;
pub const SE_SYSTEM_ENVIRONMENT_PRIVILEGE: Luid = 22;
pub const SE_CHANGE_NOTIFY_PRIVILEGE: Luid = 23;
pub const SE_UNDOCK_PRIVILEGE: Luid = 25;
pub const SE_MANAGE_VOLUME_PRIVILEGE: Luid = 28;
pub const SE_IMPERSONATE_PRIVILEGE: Luid = 29;
pub const SE_CREATE_GLOBAL_PRIVILEGE: Luid = 30;
pub const SE_TRUSTED_CREDMAN_ACCESS_PRIVILEGE: Luid = 31;
pub const SE_RELABEL_PRIVILEGE: Luid = 32;
pub const SE_INC_WORKING_SET_PRIVILEGE: Luid = 33;
pub const SE_TIME_ZONE_PRIVILEGE: Luid = 34;
pub const SE_CREATE_SYMBOLIC_LINK_PRIVILEGE: Luid = 35;
pub const SE_DELEGATE_SESSION_USER_IMPERSONATE_PRIVILEGE: Luid = 36;

/// `SECURITY_IMPERSONATION_LEVEL`.
pub const SECURITY_ANONYMOUS: u32 = 0;
pub const SECURITY_IDENTIFICATION: u32 = 1;
pub const SECURITY_IMPERSONATION: u32 = 2;
pub const SECURITY_DELEGATION: u32 = 3;

/// A well-known SID of exactly `N` bytes.
const fn known<const N: usize>(authority: u8, sub_authorities: &[u32]) -> [u8; N] {
    let (bytes, length): ([u8; SID_MAX_SIZE], usize) = sid(authority, sub_authorities);
    assert!(length == N);
    let mut out = [0u8; N];
    let mut i = 0;
    while i < N {
        out[i] = bytes[i];
        i += 1;
    }
    out
}

/// Well-known SIDs
/// (<https://learn.microsoft.com/en-us/windows/win32/secauthz/well-known-sids>).
/// S-1-1-0, everyone.
pub const WORLD: [u8; 12] = known(1, &[0]);
/// S-1-3-0: stands for the owner of a new object in an inheritable entry.
pub const CREATOR_OWNER: [u8; 12] = known(3, &[0]);
/// S-1-3-1: stands for the primary group of a new object.
pub const CREATOR_GROUP: [u8; 12] = known(3, &[1]);
/// S-1-3-4: stands for the object's owner, and replaces the owner's
/// implicit rights.
pub const OWNER_RIGHTS: [u8; 12] = known(3, &[4]);
/// S-1-5-11.
pub const AUTHENTICATED_USERS: [u8; 12] = known(5, &[11]);
/// S-1-5-18.
pub const LOCAL_SYSTEM: [u8; 12] = known(5, &[18]);
/// S-1-5-32-544.
pub const ADMINISTRATORS: [u8; 16] = known(5, &[32, 544]);
/// S-1-16-16384, the system integrity level.
pub const SYSTEM_LABEL: [u8; 12] = known(16, &[0x4000]);

/// A SID with attributes: the user, or one group (`SID_AND_ATTRIBUTES`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SidAndAttributes {
    pub sid: Vec<u8>,
    pub attributes: u32,
}

/// A privilege with attributes (`LUID_AND_ATTRIBUTES`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Privilege {
    pub luid: Luid,
    pub attributes: u32,
}

/// `TOKEN_TYPE`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TokenType {
    Primary = 1,
    Impersonation = 2,
}

/// An access token.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Token {
    /// The user. Its attributes are zero, or `SE_GROUP_USE_FOR_DENY_ONLY`.
    pub user: SidAndAttributes,
    /// The groups, the integrity label among them (the one entry with
    /// `SE_GROUP_INTEGRITY`), as `TokenGroups` reports them.
    pub groups: Vec<SidAndAttributes>,
    pub privileges: Vec<Privilege>,
    /// The owner of objects this token creates: the user's SID or a
    /// group's with `SE_GROUP_OWNER`.
    pub owner: Vec<u8>,
    /// The primary group of objects this token creates.
    pub primary_group: Vec<u8>,
    /// The DACL of objects this token creates when nothing else gives
    /// them one.
    pub default_dacl: Option<Vec<u8>>,
    pub token_type: TokenType,
    /// One of `SECURITY_*`; meaningful for an impersonation token.
    pub impersonation_level: u32,
    /// Names this token; the kernel hands them out.
    pub token_id: Luid,
    /// The logon session.
    pub authentication_id: Luid,
    /// Changes whenever the token does; the kernel hands them out.
    pub modified_id: Luid,
    /// When the token expires, in 100 ns since 1601.
    pub expiration_time: i64,
    pub session_id: u32,
    /// `TOKEN_STATISTICS.DynamicCharged` and `DynamicAvailable`: the
    /// bytes set aside for the default DACL and primary group, and how
    /// many are free.
    pub dynamic_charged: u32,
    pub dynamic_available: u32,
}

impl Token {
    /// The token of Windows' System process.
    ///
    /// CONFIRMED facts are stated by the page cited; INFERRED ones are
    /// what Windows 10 shows (`!token` on process 4, `whoami /all` as
    /// SYSTEM) and are held to Windows by the conformance drivers.
    ///
    /// | Fact | Status |
    /// | --- | --- |
    /// | User S-1-5-18 | CONFIRMED: [LocalSystem account] ("the user SID is created from the SECURITY_LOCAL_SYSTEM_RID value") |
    /// | Administrators (S-1-5-32-544) among the groups | CONFIRMED: [LocalSystem account] |
    /// | Administrators' attributes: enabled, enabled by default, owner; not mandatory | INFERRED |
    /// | Everyone and Authenticated Users: mandatory, enabled, enabled by default | INFERRED |
    /// | System mandatory label S-1-16-16384 with `SE_GROUP_INTEGRITY` and `SE_GROUP_INTEGRITY_ENABLED` | INFERRED |
    /// | The order of the groups: Administrators, Everyone, Authenticated Users, label | INFERRED |
    /// | Default owner Administrators, primary group S-1-5-18 | INFERRED |
    /// | Default DACL: SYSTEM `GENERIC_ALL`, then Administrators `GENERIC_READ`, `GENERIC_EXECUTE`, `READ_CONTROL`; revision 2, no spare room | INFERRED |
    /// | The 24 privileges [LocalSystem account] lists, with the enabled state it gives each | CONFIRMED for the LocalSystem logon; INFERRED to be the same in the System process's own token |
    /// | `SeSystemProfilePrivilege`, `SeIncreaseWorkingSetPrivilege`, `SeTimeZonePrivilege`, `SeCreateSymbolicLinkPrivilege`, `SeDelegateSessionUserImpersonatePrivilege` held and enabled; `SeTrustedCredManAccessPrivilege`, `SeRelabelPrivilege` held and disabled | INFERRED |
    /// | Every enabled privilege is also enabled by default; the privileges are ordered by number | INFERRED |
    /// | Authentication id `SYSTEM_LUID` (0x3E7) | CONFIRMED: `SYSTEM_LUID` in `ntifs.h`, [well-known LUIDs] |
    /// | Session 0 | CONFIRMED: [SeQueryInformationToken] ("the console session ... is zero") |
    /// | Primary token; impersonation level stored as `SecurityAnonymous` | INFERRED |
    /// | Never expires: expiration time `i64::MAX` | INFERRED |
    /// | `DynamicCharged`, `DynamicAvailable` | unknown: zero until recorded |
    ///
    /// [LocalSystem account]: https://learn.microsoft.com/en-us/windows/win32/services/localsystem-account
    /// [well-known LUIDs]: https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-sequeryauthenticationidtoken
    /// [SeQueryInformationToken]: https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-sequeryinformationtoken
    pub fn system() -> Token {
        const ON: u32 = SE_PRIVILEGE_ENABLED | SE_PRIVILEGE_ENABLED_BY_DEFAULT;
        const PRIVILEGES: [(Luid, u32); 31] = [
            (SE_CREATE_TOKEN_PRIVILEGE, 0),
            (SE_ASSIGNPRIMARYTOKEN_PRIVILEGE, 0),
            (SE_LOCK_MEMORY_PRIVILEGE, ON),
            (SE_INCREASE_QUOTA_PRIVILEGE, 0),
            (SE_TCB_PRIVILEGE, ON),
            (SE_SECURITY_PRIVILEGE, 0),
            (SE_TAKE_OWNERSHIP_PRIVILEGE, 0),
            (SE_LOAD_DRIVER_PRIVILEGE, 0),
            (SE_SYSTEM_PROFILE_PRIVILEGE, ON),
            (SE_SYSTEMTIME_PRIVILEGE, 0),
            (SE_PROF_SINGLE_PROCESS_PRIVILEGE, ON),
            (SE_INC_BASE_PRIORITY_PRIVILEGE, ON),
            (SE_CREATE_PAGEFILE_PRIVILEGE, ON),
            (SE_CREATE_PERMANENT_PRIVILEGE, ON),
            (SE_BACKUP_PRIVILEGE, 0),
            (SE_RESTORE_PRIVILEGE, 0),
            (SE_SHUTDOWN_PRIVILEGE, 0),
            (SE_DEBUG_PRIVILEGE, ON),
            (SE_AUDIT_PRIVILEGE, ON),
            (SE_SYSTEM_ENVIRONMENT_PRIVILEGE, 0),
            (SE_CHANGE_NOTIFY_PRIVILEGE, ON),
            (SE_UNDOCK_PRIVILEGE, 0),
            (SE_MANAGE_VOLUME_PRIVILEGE, 0),
            (SE_IMPERSONATE_PRIVILEGE, ON),
            (SE_CREATE_GLOBAL_PRIVILEGE, ON),
            (SE_TRUSTED_CREDMAN_ACCESS_PRIVILEGE, 0),
            (SE_RELABEL_PRIVILEGE, 0),
            (SE_INC_WORKING_SET_PRIVILEGE, ON),
            (SE_TIME_ZONE_PRIVILEGE, ON),
            (SE_CREATE_SYMBOLIC_LINK_PRIVILEGE, ON),
            (SE_DELEGATE_SESSION_USER_IMPERSONATE_PRIVILEGE, ON),
        ];
        const EVERYWHERE: u32 = SE_GROUP_MANDATORY | SE_GROUP_ENABLED_BY_DEFAULT | SE_GROUP_ENABLED;
        let group = |sid: &[u8], attributes| SidAndAttributes {
            sid: sid.to_vec(),
            attributes,
        };
        // GENERIC_ALL; GENERIC_READ | GENERIC_EXECUTE | READ_CONTROL.
        let mut dacl = [0u8; ACL_HEADER + 20 + 24];
        dacl[0] = ACL_REVISION;
        dacl[2] = dacl.len() as u8;
        let added = add_access_allowed(&mut dacl, 2, 0x1000_0000, &LOCAL_SYSTEM)
            .and_then(|()| add_access_allowed(&mut dacl, 2, 0xA002_0000, &ADMINISTRATORS));
        debug_assert_eq!(added, Ok(()));
        Token {
            user: group(&LOCAL_SYSTEM, 0),
            groups: [
                group(
                    &ADMINISTRATORS,
                    SE_GROUP_ENABLED_BY_DEFAULT | SE_GROUP_ENABLED | SE_GROUP_OWNER,
                ),
                group(&WORLD, EVERYWHERE),
                group(&AUTHENTICATED_USERS, EVERYWHERE),
                group(
                    &SYSTEM_LABEL,
                    SE_GROUP_INTEGRITY | SE_GROUP_INTEGRITY_ENABLED,
                ),
            ]
            .into(),
            privileges: PRIVILEGES
                .iter()
                .map(|&(luid, attributes)| Privilege { luid, attributes })
                .collect(),
            owner: ADMINISTRATORS.to_vec(),
            primary_group: LOCAL_SYSTEM.to_vec(),
            default_dacl: Some(dacl.to_vec()),
            token_type: TokenType::Primary,
            impersonation_level: SECURITY_ANONYMOUS,
            token_id: 0,
            authentication_id: SYSTEM_LUID,
            modified_id: 0,
            expiration_time: i64::MAX,
            session_id: 0,
            dynamic_charged: 0,
            dynamic_available: 0,
        }
    }

    /// Whether the token holds `privilege` and it is enabled. A
    /// privilege is known by the low six bits of its number, as on
    /// Windows, which keeps a token's privileges as the bits of a
    /// 64-bit word and never looks at the rest of the LUID.
    pub fn privilege_enabled(&self, privilege: Luid) -> bool {
        let number = privilege & 63;
        self.privileges
            .iter()
            .any(|held| held.luid == number && held.attributes & SE_PRIVILEGE_ENABLED != 0)
    }

    /// Whether an access-list entry naming `sid` applies to this token.
    /// The user always counts and a group counts when enabled; a SID
    /// marked "deny only" counts for an entry that denies (`deny`) and
    /// for no other.
    pub fn has_sid(&self, sid: &[u8], deny: bool) -> bool {
        let deny_only = |attributes: u32| attributes & SE_GROUP_USE_FOR_DENY_ONLY != 0;
        if self.user.sid == sid {
            return deny || !deny_only(self.user.attributes);
        }
        self.groups.iter().any(|group| {
            group.sid == sid
                && if deny_only(group.attributes) {
                    deny
                } else {
                    group.attributes & SE_GROUP_ENABLED != 0
                }
        })
    }

    /// Whether this token may make `sid` the owner of an object: its
    /// user, or a group it holds with `SE_GROUP_OWNER`.
    pub fn may_own(&self, sid: &[u8]) -> bool {
        let deny_only = |attributes: u32| attributes & SE_GROUP_USE_FOR_DENY_ONLY != 0;
        (self.user.sid == sid && !deny_only(self.user.attributes))
            || self.groups.iter().any(|group| {
                group.sid == sid
                    && group.attributes & SE_GROUP_OWNER != 0
                    && !deny_only(group.attributes)
            })
    }

    /// The integrity level: the last number of the label's SID
    /// (0x4000 for system). Zero, "untrusted", for a token with no label.
    pub fn integrity_level(&self) -> u32 {
        self.groups
            .iter()
            .find(|group| group.attributes & SE_GROUP_INTEGRITY != 0)
            .and_then(|label| label.sid.last_chunk::<4>())
            .map_or(0, |rid| u32::from_le_bytes(*rid))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{acl_used, valid_sid};

    #[test]
    fn the_well_known_sids_are_what_they_say() {
        assert_eq!(LOCAL_SYSTEM, [1, 1, 0, 0, 0, 0, 0, 5, 18, 0, 0, 0]);
        assert_eq!(
            ADMINISTRATORS,
            [1, 2, 0, 0, 0, 0, 0, 5, 32, 0, 0, 0, 0x20, 2, 0, 0]
        );
        assert_eq!(WORLD, [1, 1, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0]);
        assert_eq!(AUTHENTICATED_USERS[7..9], [5, 11]);
        assert_eq!(CREATOR_OWNER[7..9], [3, 0]);
        assert_eq!(CREATOR_GROUP[7..9], [3, 1]);
        assert_eq!(OWNER_RIGHTS[7..9], [3, 4]);
        assert_eq!(SYSTEM_LABEL[7..], [16, 0, 0x40, 0, 0]);
        for sid in [&WORLD[..], &ADMINISTRATORS, &SYSTEM_LABEL] {
            assert_eq!(valid_sid(sid), Some(sid.len()));
        }
        // Built the same way when not a constant.
        assert_eq!(known::<16>(5, &[32, 544]), ADMINISTRATORS);
    }

    #[test]
    fn the_system_token_is_who_windows_says() {
        let token = Token::system();
        assert_eq!(
            (&token.user.sid[..], token.user.attributes),
            (&LOCAL_SYSTEM[..], 0)
        );
        let groups: Vec<(&[u8], u32)> = token
            .groups
            .iter()
            .map(|group| (&group.sid[..], group.attributes))
            .collect();
        assert_eq!(
            groups,
            [
                (&ADMINISTRATORS[..], 0xE),
                (&WORLD[..], 0x7),
                (&AUTHENTICATED_USERS[..], 0x7),
                (&SYSTEM_LABEL[..], 0x60),
            ]
        );
        assert_eq!(token.owner, ADMINISTRATORS);
        assert_eq!(token.primary_group, LOCAL_SYSTEM);
        assert_eq!(token.token_type, TokenType::Primary);
        assert_eq!(token.impersonation_level, SECURITY_ANONYMOUS);
        assert_eq!((token.authentication_id, token.session_id), (0x3E7, 0));
        assert_eq!(token.expiration_time, i64::MAX);
        assert_eq!((token.token_id, token.modified_id), (0, 0));
        assert_eq!((token.dynamic_charged, token.dynamic_available), (0, 0));
        assert_eq!(token.integrity_level(), 0x4000);
    }

    #[test]
    fn the_system_token_holds_its_privileges() {
        let token = Token::system();
        assert_eq!(token.privileges.len(), 31);
        assert!(token.privileges.is_sorted_by_key(|held| held.luid));
        // Enabled, each also by default; the rest held but off.
        let enabled: Vec<Luid> = token
            .privileges
            .iter()
            .filter(|held| held.attributes == 3)
            .map(|held| held.luid)
            .collect();
        assert_eq!(
            enabled,
            [4, 7, 11, 13, 14, 15, 16, 20, 21, 23, 29, 30, 33, 34, 35, 36]
        );
        let disabled: Vec<Luid> = token
            .privileges
            .iter()
            .filter(|held| held.attributes == 0)
            .map(|held| held.luid)
            .collect();
        assert_eq!(
            disabled,
            [2, 3, 5, 8, 9, 10, 12, 17, 18, 19, 22, 25, 28, 31, 32]
        );
        assert!(token.privilege_enabled(SE_TCB_PRIVILEGE));
        assert!(!token.privilege_enabled(SE_SECURITY_PRIVILEGE), "held, off");
        assert!(!token.privilege_enabled(6), "not held");
    }

    #[test]
    fn the_system_token_has_a_default_dacl() {
        let token = Token::system();
        let dacl = token.default_dacl.unwrap();
        assert_eq!(dacl.len(), 52);
        assert_eq!(dacl[..8], [2, 0, 52, 0, 2, 0, 0, 0]);
        assert_eq!(acl_used(&dacl), Some(52));
        assert_eq!(dacl[8..16], [0, 0, 20, 0, 0, 0, 0, 0x10]);
        assert_eq!(dacl[16..28], LOCAL_SYSTEM);
        assert_eq!(dacl[28..36], [0, 0, 24, 0, 0, 0, 0x02, 0xA0]);
        assert_eq!(dacl[36..], ADMINISTRATORS);
    }

    #[test]
    fn a_sid_counts_when_enabled_or_when_denying() {
        let mut token = Token::system();
        assert!(token.has_sid(&LOCAL_SYSTEM, false));
        assert!(token.has_sid(&ADMINISTRATORS, false));
        assert!(token.has_sid(&WORLD, true));
        assert!(!token.has_sid(&CREATOR_OWNER, false), "not in the token");
        // The label is a group that is never enabled.
        assert!(!token.has_sid(&SYSTEM_LABEL, false));
        assert!(!token.has_sid(&SYSTEM_LABEL, true));
        // Disabled: counts for nothing.
        token.groups[1].attributes = SE_GROUP_MANDATORY;
        assert!(!token.has_sid(&WORLD, false) && !token.has_sid(&WORLD, true));
        // Deny only: counts for denying, enabled or not.
        token.groups[1].attributes = SE_GROUP_USE_FOR_DENY_ONLY | SE_GROUP_ENABLED;
        assert!(!token.has_sid(&WORLD, false) && token.has_sid(&WORLD, true));
        token.groups[1].attributes = SE_GROUP_USE_FOR_DENY_ONLY;
        assert!(token.has_sid(&WORLD, true));
        token.user.attributes = SE_GROUP_USE_FOR_DENY_ONLY;
        assert!(!token.has_sid(&LOCAL_SYSTEM, false) && token.has_sid(&LOCAL_SYSTEM, true));
    }

    #[test]
    fn only_the_user_and_owner_groups_may_own() {
        let mut token = Token::system();
        assert!(token.may_own(&LOCAL_SYSTEM));
        assert!(token.may_own(&ADMINISTRATORS));
        assert!(!token.may_own(&WORLD), "a group without the owner bit");
        assert!(!token.may_own(&CREATOR_OWNER), "not in the token");
        token.groups[0].attributes |= SE_GROUP_USE_FOR_DENY_ONLY;
        token.user.attributes = SE_GROUP_USE_FOR_DENY_ONLY;
        assert!(!token.may_own(&ADMINISTRATORS) && !token.may_own(&LOCAL_SYSTEM));
    }

    #[test]
    fn a_token_without_a_label_is_untrusted() {
        let mut token = Token::system();
        token.groups.pop();
        assert_eq!(token.integrity_level(), 0);
        // A label too short to carry a level.
        token.groups.push(SidAndAttributes {
            sid: vec![1, 0],
            attributes: SE_GROUP_INTEGRITY,
        });
        assert_eq!(token.integrity_level(), 0);
    }
}
