//! Security structures a driver can see: identifiers, access lists,
//! security descriptors, and the kernel's table of well-known values.
//!
//! The bytes of SIDs, ACLs and self-relative descriptors are handled by
//! `nk_se`; here are the structures with pointers in them.

use core::ffi::c_void;
use core::mem::{offset_of, size_of};

/// [`LUID`](https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-luid):
/// a privilege's number.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct LUID {
    pub LowPart: u32,
    pub HighPart: i32,
}

/// A pointer to a SID.
pub type PSID = *const u8;

/// [`SECURITY_DESCRIPTOR`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/ns-ntifs-_security_descriptor),
/// the absolute form: its parts are pointed to.
#[repr(C)]
pub struct SECURITY_DESCRIPTOR {
    pub Revision: u8,
    pub Sbz1: u8,
    pub Control: u16,
    pub Owner: *mut c_void,
    pub Group: *mut c_void,
    pub Sacl: *mut c_void,
    pub Dacl: *mut c_void,
}

const _: () = {
    assert!(size_of::<SECURITY_DESCRIPTOR>() == nk_se::ABSOLUTE_SIZE);
    assert!(offset_of!(SECURITY_DESCRIPTOR, Control) == 2);
    assert!(offset_of!(SECURITY_DESCRIPTOR, Owner) == 8);
    assert!(offset_of!(SECURITY_DESCRIPTOR, Group) == 16);
    assert!(offset_of!(SECURITY_DESCRIPTOR, Sacl) == 24);
    assert!(offset_of!(SECURITY_DESCRIPTOR, Dacl) == 32);
};

/// [`SECURITY_SUBJECT_CONTEXT`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/ns-wdm-_security_subject_context):
/// who is asking, as `SeCaptureSubjectContext` records it. Drivers
/// keep one and read it in line.
#[repr(C)]
pub struct SECURITY_SUBJECT_CONTEXT {
    /// The thread's impersonation token; null when it has none.
    pub ClientToken: *mut c_void,
    pub ImpersonationLevel: u32,
    /// The process's primary token.
    pub PrimaryToken: *mut c_void,
    pub ProcessAuditId: *mut c_void,
}

/// `ACCESS_STATE.Flags`: the subject holds the privilege to pass
/// through directories it may not list (`ntifs.h`).
pub const TOKEN_HAS_TRAVERSE_PRIVILEGE: u32 = 0x0001;

/// [`ACCESS_STATE`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/ns-wdm-_access_state):
/// an open in progress: what was asked for, what has been granted, and
/// for whom. A create request points to one
/// (`IO_SECURITY_CONTEXT.AccessState`) and file systems read and write
/// it in line.
#[repr(C)]
pub struct ACCESS_STATE {
    pub OperationID: LUID,
    pub SecurityEvaluated: u8,
    pub GenerateAudit: u8,
    pub GenerateOnClose: u8,
    pub PrivilegesAllocated: u8,
    pub Flags: u32,
    pub RemainingDesiredAccess: u32,
    pub PreviouslyGrantedAccess: u32,
    pub OriginalDesiredAccess: u32,
    pub SubjectSecurityContext: SECURITY_SUBJECT_CONTEXT,
    pub SecurityDescriptor: *mut c_void,
    pub AuxData: *mut c_void,
    /// A union of `INITIAL_PRIVILEGE_SET` (a count, a control word and
    /// three privileges) and `PRIVILEGE_SET`.
    pub Privileges: [u32; 11],
    pub AuditPrivileges: u8,
    pub ObjectName: crate::io::UNICODE_STRING,
    pub ObjectTypeName: crate::io::UNICODE_STRING,
}

const _: () = {
    assert!(size_of::<SECURITY_SUBJECT_CONTEXT>() == 0x20);
    assert!(offset_of!(SECURITY_SUBJECT_CONTEXT, ImpersonationLevel) == 0x08);
    assert!(offset_of!(SECURITY_SUBJECT_CONTEXT, PrimaryToken) == 0x10);
    assert!(offset_of!(SECURITY_SUBJECT_CONTEXT, ProcessAuditId) == 0x18);
    assert!(size_of::<ACCESS_STATE>() == 0xA0);
    assert!(offset_of!(ACCESS_STATE, SecurityEvaluated) == 0x08);
    assert!(offset_of!(ACCESS_STATE, Flags) == 0x0C);
    assert!(offset_of!(ACCESS_STATE, RemainingDesiredAccess) == 0x10);
    assert!(offset_of!(ACCESS_STATE, PreviouslyGrantedAccess) == 0x14);
    assert!(offset_of!(ACCESS_STATE, OriginalDesiredAccess) == 0x18);
    assert!(offset_of!(ACCESS_STATE, SubjectSecurityContext) == 0x20);
    assert!(offset_of!(ACCESS_STATE, SecurityDescriptor) == 0x40);
    assert!(offset_of!(ACCESS_STATE, AuxData) == 0x48);
    assert!(offset_of!(ACCESS_STATE, Privileges) == 0x50);
    assert!(offset_of!(ACCESS_STATE, AuditPrivileges) == 0x7C);
    assert!(offset_of!(ACCESS_STATE, ObjectName) == 0x80);
    assert!(offset_of!(ACCESS_STATE, ObjectTypeName) == 0x90);
};

/// [`SECURITY_QUALITY_OF_SERVICE`](https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-security_quality_of_service):
/// how far a client lets a server act for it. Object attributes point
/// to one.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct SECURITY_QUALITY_OF_SERVICE {
    pub Length: u32,
    /// A `SECURITY_IMPERSONATION_LEVEL`.
    pub ImpersonationLevel: u32,
    /// `SECURITY_STATIC_TRACKING` (0) or `SECURITY_DYNAMIC_TRACKING`.
    pub ContextTrackingMode: u8,
    pub EffectiveOnly: u8,
}

const _: () = {
    assert!(size_of::<SECURITY_QUALITY_OF_SERVICE>() == 12);
    assert!(offset_of!(SECURITY_QUALITY_OF_SERVICE, ImpersonationLevel) == 4);
    assert!(offset_of!(SECURITY_QUALITY_OF_SERVICE, ContextTrackingMode) == 8);
    assert!(offset_of!(SECURITY_QUALITY_OF_SERVICE, EffectiveOnly) == 9);
};

/// [`LUID_AND_ATTRIBUTES`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/ns-wdm-_luid_and_attributes):
/// a privilege and its `SE_PRIVILEGE_*` bits. Twelve bytes: the header
/// packs it to four.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct LUID_AND_ATTRIBUTES {
    pub Luid: LUID,
    pub Attributes: u32,
}

/// [`PRIVILEGE_SET`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/ns-wdm-_privilege_set):
/// a count, a control word and that many privileges; one is declared.
#[repr(C)]
pub struct PRIVILEGE_SET {
    pub PrivilegeCount: u32,
    pub Control: u32,
    pub Privilege: [LUID_AND_ATTRIBUTES; 1],
}

/// How many privileges an access state holds in line
/// (`INITIAL_PRIVILEGE_COUNT`); more are kept in the pool.
pub const INITIAL_PRIVILEGE_COUNT: u32 = 3;

/// `AUX_ACCESS_DATA`: the part of an access state the documented
/// structure only points to (`ACCESS_STATE.AuxData`). Whoever makes an
/// access state supplies the room for it (`SeCreateAccessState`), so
/// its size is part of the driver ABI; the layout is the pinned
/// build's.
#[repr(C)]
pub struct AUX_ACCESS_DATA {
    /// The privileges used so far: the state's own set, or a pool block
    /// when `ACCESS_STATE.PrivilegesAllocated` says so.
    pub PrivilegesUsed: *mut PRIVILEGE_SET,
    pub GenericMapping: crate::ob::GENERIC_MAPPING,
    pub AccessesToAudit: u32,
    pub MaximumAuditMask: u32,
    pub TransactionId: [u8; 16],
    pub NewSecurityDescriptor: *mut c_void,
    pub ExistingSecurityDescriptor: *mut c_void,
    pub ParentSecurityDescriptor: *mut c_void,
    pub DeRefSecurityDescriptor: *mut c_void,
    pub SDLock: *mut c_void,
    pub AccessReasons: [u32; 32],
    pub GenerateStagingEvents: u8,
}

const _: () = {
    assert!(size_of::<LUID_AND_ATTRIBUTES>() == 12);
    assert!(offset_of!(LUID_AND_ATTRIBUTES, Attributes) == 8);
    assert!(size_of::<PRIVILEGE_SET>() == 20);
    assert!(offset_of!(PRIVILEGE_SET, Control) == 4);
    assert!(offset_of!(PRIVILEGE_SET, Privilege) == 8);
    assert!(size_of::<AUX_ACCESS_DATA>() == 0xE0);
    assert!(offset_of!(AUX_ACCESS_DATA, GenericMapping) == 0x08);
    assert!(offset_of!(AUX_ACCESS_DATA, AccessesToAudit) == 0x18);
    assert!(offset_of!(AUX_ACCESS_DATA, MaximumAuditMask) == 0x1C);
    assert!(offset_of!(AUX_ACCESS_DATA, TransactionId) == 0x20);
    assert!(offset_of!(AUX_ACCESS_DATA, NewSecurityDescriptor) == 0x30);
    assert!(offset_of!(AUX_ACCESS_DATA, ExistingSecurityDescriptor) == 0x38);
    assert!(offset_of!(AUX_ACCESS_DATA, ParentSecurityDescriptor) == 0x40);
    assert!(offset_of!(AUX_ACCESS_DATA, DeRefSecurityDescriptor) == 0x48);
    assert!(offset_of!(AUX_ACCESS_DATA, SDLock) == 0x50);
    assert!(offset_of!(AUX_ACCESS_DATA, AccessReasons) == 0x58);
    assert!(offset_of!(AUX_ACCESS_DATA, GenerateStagingEvents) == 0xD8);
};

/// `SE_EXPORTS` (`ntifs.h`): the privileges and well-known SIDs the
/// kernel publishes through `SeExports`.
#[repr(C)]
pub struct SE_EXPORTS {
    pub SeCreateTokenPrivilege: LUID,
    pub SeAssignPrimaryTokenPrivilege: LUID,
    pub SeLockMemoryPrivilege: LUID,
    pub SeIncreaseQuotaPrivilege: LUID,
    pub SeUnsolicitedInputPrivilege: LUID,
    pub SeTcbPrivilege: LUID,
    pub SeSecurityPrivilege: LUID,
    pub SeTakeOwnershipPrivilege: LUID,
    pub SeLoadDriverPrivilege: LUID,
    pub SeCreatePagefilePrivilege: LUID,
    pub SeIncreaseBasePriorityPrivilege: LUID,
    pub SeSystemProfilePrivilege: LUID,
    pub SeSystemtimePrivilege: LUID,
    pub SeProfileSingleProcessPrivilege: LUID,
    pub SeCreatePermanentPrivilege: LUID,
    pub SeBackupPrivilege: LUID,
    pub SeRestorePrivilege: LUID,
    pub SeShutdownPrivilege: LUID,
    pub SeDebugPrivilege: LUID,
    pub SeAuditPrivilege: LUID,
    pub SeSystemEnvironmentPrivilege: LUID,
    pub SeChangeNotifyPrivilege: LUID,
    pub SeRemoteShutdownPrivilege: LUID,
    pub SeNullSid: PSID,
    pub SeWorldSid: PSID,
    pub SeLocalSid: PSID,
    pub SeCreatorOwnerSid: PSID,
    pub SeCreatorGroupSid: PSID,
    pub SeNtAuthoritySid: PSID,
    pub SeDialupSid: PSID,
    pub SeNetworkSid: PSID,
    pub SeBatchSid: PSID,
    pub SeInteractiveSid: PSID,
    pub SeLocalSystemSid: PSID,
    pub SeAliasAdminsSid: PSID,
    pub SeAliasUsersSid: PSID,
    pub SeAliasGuestsSid: PSID,
    pub SeAliasPowerUsersSid: PSID,
    pub SeAliasAccountOpsSid: PSID,
    pub SeAliasSystemOpsSid: PSID,
    pub SeAliasPrintOpsSid: PSID,
    pub SeAliasBackupOpsSid: PSID,
    pub SeAuthenticatedUsersSid: PSID,
    pub SeRestrictedSid: PSID,
    pub SeAnonymousLogonSid: PSID,
    pub SeUndockPrivilege: LUID,
    pub SeSyncAgentPrivilege: LUID,
    pub SeEnableDelegationPrivilege: LUID,
    pub SeLocalServiceSid: PSID,
    pub SeNetworkServiceSid: PSID,
    pub SeManageVolumePrivilege: LUID,
    pub SeImpersonatePrivilege: LUID,
    pub SeCreateGlobalPrivilege: LUID,
    pub SeTrustedCredManAccessPrivilege: LUID,
    pub SeRelabelPrivilege: LUID,
    pub SeIncreaseWorkingSetPrivilege: LUID,
    pub SeTimeZonePrivilege: LUID,
    pub SeCreateSymbolicLinkPrivilege: LUID,
    pub SeIUserSid: PSID,
    pub SeUntrustedMandatorySid: PSID,
    pub SeLowMandatorySid: PSID,
    pub SeMediumMandatorySid: PSID,
    pub SeHighMandatorySid: PSID,
    pub SeSystemMandatorySid: PSID,
    pub SeOwnerRightsSid: PSID,
    pub SeAllAppPackagesSid: PSID,
    pub SeUserModeDriversSid: PSID,
    pub SeProcTrustWinTcbSid: PSID,
    pub SeTrustedInstallerSid: PSID,
    pub SeDelegateSessionUserImpersonatePrivilege: LUID,
}

// The offsets Microsoft's device-security library (`wdmsec.lib`, linked
// into the `cancel` fixture) reads SIDs from, by the SDDL name it gives
// each: WD, NU, IU, SY, BA, BU, BG, AU, RC, AN, LS, NS, AC, UD.
const _: () = {
    assert!(offset_of!(SE_EXPORTS, SeNullSid) == 0xB8);
    assert!(offset_of!(SE_EXPORTS, SeWorldSid) == 0xC0);
    assert!(offset_of!(SE_EXPORTS, SeNetworkSid) == 0xF0);
    assert!(offset_of!(SE_EXPORTS, SeInteractiveSid) == 0x100);
    assert!(offset_of!(SE_EXPORTS, SeLocalSystemSid) == 0x108);
    assert!(offset_of!(SE_EXPORTS, SeAliasAdminsSid) == 0x110);
    assert!(offset_of!(SE_EXPORTS, SeAliasUsersSid) == 0x118);
    assert!(offset_of!(SE_EXPORTS, SeAliasGuestsSid) == 0x120);
    assert!(offset_of!(SE_EXPORTS, SeAuthenticatedUsersSid) == 0x150);
    assert!(offset_of!(SE_EXPORTS, SeRestrictedSid) == 0x158);
    assert!(offset_of!(SE_EXPORTS, SeAnonymousLogonSid) == 0x160);
    assert!(offset_of!(SE_EXPORTS, SeLocalServiceSid) == 0x180);
    assert!(offset_of!(SE_EXPORTS, SeNetworkServiceSid) == 0x188);
    assert!(offset_of!(SE_EXPORTS, SeAllAppPackagesSid) == 0x208);
    assert!(offset_of!(SE_EXPORTS, SeUserModeDriversSid) == 0x210);
    assert!(size_of::<SE_EXPORTS>() == 0x230);
};
