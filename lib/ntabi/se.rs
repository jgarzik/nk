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
