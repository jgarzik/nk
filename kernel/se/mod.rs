//! Security: identifiers, access lists and security descriptors as
//! drivers build and take them apart.
//!
//! The byte layouts and the rules are `nk_se`, tested on the host. Here
//! are the routines drivers call, which reach the driver's memory
//! through raw pointers and hand `nk_se` copies, and the kernel's table
//! of well-known SIDs and privileges (`SeExports`).
//!
//! NK checks no access yet: there is no user mode to check. Descriptors
//! are built, converted and stored faithfully so that they are right
//! when something reads them.

#![allow(non_snake_case, non_upper_case_globals)]

use crate::mm::pool;
use alloc::vec::Vec;
use core::ffi::c_void;
use nk_ntabi::se::{LUID, PSID, SE_EXPORTS, SECURITY_DESCRIPTOR};
use nk_ntabi::status::*;
use nk_se::{AclError, Parts};

/// Pool tag of captured security descriptors.
const TAG: u32 = u32::from_le_bytes(*b"SeSc");

/// A well-known SID's bytes, aligned as a SID is.
#[repr(C, align(4))]
struct Sid([u8; nk_se::SID_MAX_SIZE]);

const fn well_known(authority: u8, sub_authorities: &[u32]) -> Sid {
    Sid(nk_se::sid(authority, sub_authorities).0)
}

const fn at(sid: &'static Sid) -> PSID {
    core::ptr::from_ref(sid).cast()
}

const fn privilege(number: u32) -> LUID {
    LUID {
        LowPart: number,
        HighPart: 0,
    }
}

// Authorities: 0 null, 1 world, 2 local, 3 creator, 5 NT, 15 app
// packages, 16 mandatory labels, 19 process trust.
static NULL: Sid = well_known(0, &[0]);
static WORLD: Sid = well_known(1, &[0]);
static LOCAL: Sid = well_known(2, &[0]);
static CREATOR_OWNER: Sid = well_known(3, &[0]);
static CREATOR_GROUP: Sid = well_known(3, &[1]);
static OWNER_RIGHTS: Sid = well_known(3, &[4]);
static NT_AUTHORITY: Sid = well_known(5, &[]);
static DIALUP: Sid = well_known(5, &[1]);
static NETWORK: Sid = well_known(5, &[2]);
static BATCH: Sid = well_known(5, &[3]);
static INTERACTIVE: Sid = well_known(5, &[4]);
static ANONYMOUS: Sid = well_known(5, &[7]);
static AUTHENTICATED: Sid = well_known(5, &[11]);
static RESTRICTED: Sid = well_known(5, &[12]);
static IUSER: Sid = well_known(5, &[17]);
static LOCAL_SYSTEM: Sid = well_known(5, &[18]);
static LOCAL_SERVICE: Sid = well_known(5, &[19]);
static NETWORK_SERVICE: Sid = well_known(5, &[20]);
static ADMINS: Sid = well_known(5, &[32, 544]);
static USERS: Sid = well_known(5, &[32, 545]);
static GUESTS: Sid = well_known(5, &[32, 546]);
static POWER_USERS: Sid = well_known(5, &[32, 547]);
static ACCOUNT_OPS: Sid = well_known(5, &[32, 548]);
static SYSTEM_OPS: Sid = well_known(5, &[32, 549]);
static PRINT_OPS: Sid = well_known(5, &[32, 550]);
static BACKUP_OPS: Sid = well_known(5, &[32, 551]);
static TRUSTED_INSTALLER: Sid = well_known(
    5,
    &[
        80,
        956_008_885,
        3_418_522_649,
        1_831_038_044,
        1_853_292_631,
        2_271_478_464,
    ],
);
static USER_MODE_DRIVERS: Sid = well_known(5, &[84, 0, 0, 0, 0, 0]);
static ALL_APP_PACKAGES: Sid = well_known(15, &[2, 1]);
static UNTRUSTED: Sid = well_known(16, &[0]);
static LOW: Sid = well_known(16, &[0x1000]);
static MEDIUM: Sid = well_known(16, &[0x2000]);
static HIGH: Sid = well_known(16, &[0x3000]);
static SYSTEM: Sid = well_known(16, &[0x4000]);
static WIN_TCB: Sid = well_known(19, &[1024, 8192]);

struct Exports(SE_EXPORTS);

// SAFETY: immutable, and every pointer in it names an immutable static.
unsafe impl Sync for Exports {}

/// The table `SeExports` points to. Privileges carry their well-known
/// numbers (`SE_*_PRIVILEGE` in `wdm.h`).
static EXPORTS: Exports = Exports(SE_EXPORTS {
    SeCreateTokenPrivilege: privilege(2),
    SeAssignPrimaryTokenPrivilege: privilege(3),
    SeLockMemoryPrivilege: privilege(4),
    SeIncreaseQuotaPrivilege: privilege(5),
    SeUnsolicitedInputPrivilege: privilege(6),
    SeTcbPrivilege: privilege(7),
    SeSecurityPrivilege: privilege(8),
    SeTakeOwnershipPrivilege: privilege(9),
    SeLoadDriverPrivilege: privilege(10),
    SeCreatePagefilePrivilege: privilege(15),
    SeIncreaseBasePriorityPrivilege: privilege(14),
    SeSystemProfilePrivilege: privilege(11),
    SeSystemtimePrivilege: privilege(12),
    SeProfileSingleProcessPrivilege: privilege(13),
    SeCreatePermanentPrivilege: privilege(16),
    SeBackupPrivilege: privilege(17),
    SeRestorePrivilege: privilege(18),
    SeShutdownPrivilege: privilege(19),
    SeDebugPrivilege: privilege(20),
    SeAuditPrivilege: privilege(21),
    SeSystemEnvironmentPrivilege: privilege(22),
    SeChangeNotifyPrivilege: privilege(23),
    SeRemoteShutdownPrivilege: privilege(24),
    SeNullSid: at(&NULL),
    SeWorldSid: at(&WORLD),
    SeLocalSid: at(&LOCAL),
    SeCreatorOwnerSid: at(&CREATOR_OWNER),
    SeCreatorGroupSid: at(&CREATOR_GROUP),
    SeNtAuthoritySid: at(&NT_AUTHORITY),
    SeDialupSid: at(&DIALUP),
    SeNetworkSid: at(&NETWORK),
    SeBatchSid: at(&BATCH),
    SeInteractiveSid: at(&INTERACTIVE),
    SeLocalSystemSid: at(&LOCAL_SYSTEM),
    SeAliasAdminsSid: at(&ADMINS),
    SeAliasUsersSid: at(&USERS),
    SeAliasGuestsSid: at(&GUESTS),
    SeAliasPowerUsersSid: at(&POWER_USERS),
    SeAliasAccountOpsSid: at(&ACCOUNT_OPS),
    SeAliasSystemOpsSid: at(&SYSTEM_OPS),
    SeAliasPrintOpsSid: at(&PRINT_OPS),
    SeAliasBackupOpsSid: at(&BACKUP_OPS),
    SeAuthenticatedUsersSid: at(&AUTHENTICATED),
    SeRestrictedSid: at(&RESTRICTED),
    SeAnonymousLogonSid: at(&ANONYMOUS),
    SeUndockPrivilege: privilege(25),
    SeSyncAgentPrivilege: privilege(26),
    SeEnableDelegationPrivilege: privilege(27),
    SeLocalServiceSid: at(&LOCAL_SERVICE),
    SeNetworkServiceSid: at(&NETWORK_SERVICE),
    SeManageVolumePrivilege: privilege(28),
    SeImpersonatePrivilege: privilege(29),
    SeCreateGlobalPrivilege: privilege(30),
    SeTrustedCredManAccessPrivilege: privilege(31),
    SeRelabelPrivilege: privilege(32),
    SeIncreaseWorkingSetPrivilege: privilege(33),
    SeTimeZonePrivilege: privilege(34),
    SeCreateSymbolicLinkPrivilege: privilege(35),
    SeIUserSid: at(&IUSER),
    SeUntrustedMandatorySid: at(&UNTRUSTED),
    SeLowMandatorySid: at(&LOW),
    SeMediumMandatorySid: at(&MEDIUM),
    SeHighMandatorySid: at(&HIGH),
    SeSystemMandatorySid: at(&SYSTEM),
    SeOwnerRightsSid: at(&OWNER_RIGHTS),
    SeAllAppPackagesSid: at(&ALL_APP_PACKAGES),
    SeUserModeDriversSid: at(&USER_MODE_DRIVERS),
    SeProcTrustWinTcbSid: at(&WIN_TCB),
    SeTrustedInstallerSid: at(&TRUSTED_INSTALLER),
    SeDelegateSessionUserImpersonatePrivilege: privilege(36),
});

/// A variable drivers import: it holds the address of the table.
#[repr(transparent)]
pub struct ExportsVariable(*const SE_EXPORTS);

// SAFETY: immutable, and the pointer names an immutable static.
unsafe impl Sync for ExportsVariable {}

/// `SeExports` (`ntifs.h`): the kernel's well-known SIDs and privileges.
pub static SeExports: ExportsVariable = ExportsVariable(&raw const EXPORTS.0);

impl ExportsVariable {
    /// The address drivers import.
    pub const fn address(&'static self) -> *const () {
        core::ptr::from_ref(self).cast()
    }

    /// The table.
    pub fn table(&self) -> *const SE_EXPORTS {
        self.0
    }
}

/// The length a SID says it has.
///
/// # Safety
/// `sid` points to a SID's first two bytes at least.
unsafe fn sid_length(sid: *const u8) -> usize {
    // SAFETY: per the contract.
    nk_se::sid_length(usize::from(unsafe { sid.add(1).read() }))
}

/// The length an ACL says it has.
///
/// # Safety
/// `acl` points to an ACL's header.
unsafe fn acl_length(acl: *const u8) -> usize {
    // SAFETY: per the contract.
    usize::from(unsafe { acl.add(2).cast::<u16>().read_unaligned() })
}

/// A copy of `len` bytes of a driver's memory, or `None` without memory
/// for it.
///
/// # Safety
/// `from` is readable for `len` bytes.
pub unsafe fn copied(from: *const u8, len: usize) -> Option<Vec<u8>> {
    let mut copy = Vec::new();
    copy.try_reserve_exact(len).ok()?;
    // SAFETY: per the contract.
    copy.extend((0..len).map(|i| unsafe { from.add(i).read() }));
    Some(copy)
}

/// A security descriptor's control bits and where its parts are (owner,
/// group, SACL, DACL; null for a part it lacks), whichever form it has.
/// An ACL counts only if the descriptor says it is present.
///
/// # Safety
/// `sd` points to a security descriptor.
unsafe fn parts_of(sd: *const u8) -> (u16, [*const u8; 4]) {
    // SAFETY: per the contract: an absolute descriptor holds four
    // pointers after its first eight bytes, a self-relative one four
    // offsets after its first four.
    unsafe {
        let control = sd.add(2).cast::<u16>().read_unaligned();
        let mut parts = if control & nk_se::SE_SELF_RELATIVE != 0 {
            [4, 8, 12, 16].map(|field| match sd.add(field).cast::<u32>().read_unaligned() {
                0 => core::ptr::null(),
                offset => sd.add(offset as usize),
            })
        } else {
            [8, 16, 24, 32].map(|field| sd.add(field).cast::<*const u8>().read_unaligned())
        };
        if control & nk_se::SE_SACL_PRESENT == 0 {
            parts[2] = core::ptr::null();
        }
        if control & nk_se::SE_DACL_PRESENT == 0 {
            parts[3] = core::ptr::null();
        }
        (control, parts)
    }
}

/// Copies of a descriptor's parts.
struct Copies {
    control: u16,
    parts: [Option<Vec<u8>>; 4],
}

impl Copies {
    /// # Safety
    /// `sd` points to a security descriptor whose parts are where it
    /// says.
    unsafe fn of(sd: *const u8) -> Option<Self> {
        // SAFETY: per the contract.
        unsafe {
            let (control, at) = parts_of(sd);
            let mut parts = [const { None }; 4];
            for (i, &part) in at.iter().enumerate() {
                if !part.is_null() {
                    let len = if i < 2 {
                        sid_length(part)
                    } else {
                        acl_length(part)
                    };
                    parts[i] = Some(copied(part, len)?);
                }
            }
            Some(Self { control, parts })
        }
    }

    fn parts(&self) -> Parts<'_> {
        let [owner, group, sacl, dacl] = self.parts.each_ref().map(Option::as_deref);
        Parts {
            control: self.control,
            owner,
            group,
            sacl,
            dacl,
        }
    }
}

/// [`RtlLengthSid`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-rtllengthsid).
///
/// # Safety
/// `sid` points to a SID.
pub unsafe extern "C" fn RtlLengthSid(sid: PSID) -> u32 {
    // SAFETY: per the contract.
    unsafe { sid_length(sid) as u32 }
}

/// [`RtlCreateSecurityDescriptor`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-rtlcreatesecuritydescriptor):
/// an empty absolute descriptor.
///
/// # Safety
/// `sd` is writable for a `SECURITY_DESCRIPTOR`.
pub unsafe extern "C" fn RtlCreateSecurityDescriptor(
    sd: *mut SECURITY_DESCRIPTOR,
    revision: u32,
) -> NTSTATUS {
    if revision != u32::from(nk_se::SECURITY_DESCRIPTOR_REVISION) {
        return STATUS_UNKNOWN_REVISION;
    }
    // SAFETY: per the contract.
    unsafe {
        sd.cast::<u8>()
            .write_bytes(0, size_of::<SECURITY_DESCRIPTOR>());
        sd.cast::<u8>().write(nk_se::SECURITY_DESCRIPTOR_REVISION);
    }
    STATUS_SUCCESS
}

/// The revision check every routine that reads a descriptor starts
/// with.
///
/// # Safety
/// `sd` points to a security descriptor.
unsafe fn known_revision(sd: *const u8) -> bool {
    // SAFETY: per the contract.
    unsafe { sd.read() == nk_se::SECURITY_DESCRIPTOR_REVISION }
}

/// [`RtlSetDaclSecurityDescriptor`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-rtlsetdaclsecuritydescriptor).
///
/// # Safety
/// `sd` points to a security descriptor the caller may write.
pub unsafe extern "C" fn RtlSetDaclSecurityDescriptor(
    sd: *mut SECURITY_DESCRIPTOR,
    present: u8,
    dacl: *mut c_void,
    defaulted: u8,
) -> NTSTATUS {
    // SAFETY: per the contract. The descriptor is the driver's: fields
    // are read and written one at a time through the raw pointer.
    unsafe {
        if !known_revision(sd.cast()) {
            return STATUS_UNKNOWN_REVISION;
        }
        let control = &raw mut (*sd).Control;
        let mut bits = control.read_unaligned();
        // Only an absolute descriptor has a pointer to set.
        if bits & nk_se::SE_SELF_RELATIVE != 0 {
            return STATUS_INVALID_SECURITY_DESCR;
        }
        if present == 0 {
            control.write_unaligned(bits & !nk_se::SE_DACL_PRESENT);
            return STATUS_SUCCESS;
        }
        (&raw mut (*sd).Dacl).write_unaligned(dacl);
        bits = (bits | nk_se::SE_DACL_PRESENT) & !nk_se::SE_DACL_DEFAULTED;
        if defaulted != 0 {
            bits |= nk_se::SE_DACL_DEFAULTED;
        }
        control.write_unaligned(bits);
    }
    STATUS_SUCCESS
}

/// The ACL `which` (2 SACL, 3 DACL) of a descriptor: whether it is
/// present, and if so where it is and whether it was defaulted.
///
/// # Safety
/// `sd` points to a security descriptor; the three results are
/// writable.
unsafe fn get_acl(
    sd: *const u8,
    which: usize,
    present_bit: u16,
    defaulted_bit: u16,
    present: *mut u8,
    acl: *mut *mut c_void,
    defaulted: *mut u8,
) -> NTSTATUS {
    // SAFETY: per the contract.
    unsafe {
        if !known_revision(sd) {
            return STATUS_UNKNOWN_REVISION;
        }
        let (control, parts) = parts_of(sd);
        let is_present = control & present_bit != 0;
        present.write(u8::from(is_present));
        // Without one, the other two results are left as they were.
        if is_present {
            acl.write_unaligned(parts[which].cast_mut().cast());
            defaulted.write(u8::from(control & defaulted_bit != 0));
        }
    }
    STATUS_SUCCESS
}

/// [`RtlGetDaclSecurityDescriptor`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-rtlgetdaclsecuritydescriptor).
///
/// # Safety
/// `sd` points to a security descriptor; the results are writable.
pub unsafe extern "C" fn RtlGetDaclSecurityDescriptor(
    sd: *const c_void,
    present: *mut u8,
    dacl: *mut *mut c_void,
    defaulted: *mut u8,
) -> NTSTATUS {
    // SAFETY: per the contract.
    unsafe {
        get_acl(
            sd.cast(),
            3,
            nk_se::SE_DACL_PRESENT,
            nk_se::SE_DACL_DEFAULTED,
            present,
            dacl,
            defaulted,
        )
    }
}

/// [`RtlGetSaclSecurityDescriptor`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-rtlgetsaclsecuritydescriptor).
///
/// # Safety
/// `sd` points to a security descriptor; the results are writable.
pub unsafe extern "C" fn RtlGetSaclSecurityDescriptor(
    sd: *const c_void,
    present: *mut u8,
    sacl: *mut *mut c_void,
    defaulted: *mut u8,
) -> NTSTATUS {
    // SAFETY: per the contract.
    unsafe {
        get_acl(
            sd.cast(),
            2,
            nk_se::SE_SACL_PRESENT,
            nk_se::SE_SACL_DEFAULTED,
            present,
            sacl,
            defaulted,
        )
    }
}

/// The SID `which` (0 owner, 1 group) of a descriptor, null if it has
/// none, and whether it was defaulted.
///
/// # Safety
/// `sd` points to a security descriptor; the results are writable.
unsafe fn get_sid(
    sd: *const u8,
    which: usize,
    defaulted_bit: u16,
    sid: *mut *mut c_void,
    defaulted: *mut u8,
) -> NTSTATUS {
    // SAFETY: per the contract.
    unsafe {
        if !known_revision(sd) {
            return STATUS_UNKNOWN_REVISION;
        }
        let (control, parts) = parts_of(sd);
        sid.write_unaligned(parts[which].cast_mut().cast());
        defaulted.write(u8::from(control & defaulted_bit != 0));
    }
    STATUS_SUCCESS
}

/// [`RtlGetOwnerSecurityDescriptor`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-rtlgetownersecuritydescriptor).
///
/// # Safety
/// `sd` points to a security descriptor; the results are writable.
pub unsafe extern "C" fn RtlGetOwnerSecurityDescriptor(
    sd: *const c_void,
    owner: *mut *mut c_void,
    defaulted: *mut u8,
) -> NTSTATUS {
    // SAFETY: per the contract.
    unsafe { get_sid(sd.cast(), 0, nk_se::SE_OWNER_DEFAULTED, owner, defaulted) }
}

/// [`RtlGetGroupSecurityDescriptor`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-rtlgetgroupsecuritydescriptor).
///
/// # Safety
/// `sd` points to a security descriptor; the results are writable.
pub unsafe extern "C" fn RtlGetGroupSecurityDescriptor(
    sd: *const c_void,
    group: *mut *mut c_void,
    defaulted: *mut u8,
) -> NTSTATUS {
    // SAFETY: per the contract.
    unsafe { get_sid(sd.cast(), 1, nk_se::SE_GROUP_DEFAULTED, group, defaulted) }
}

/// [`RtlLengthSecurityDescriptor`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-rtllengthsecuritydescriptor):
/// the descriptor's own size plus that of each part, rounded up to
/// four bytes.
///
/// # Safety
/// `sd` points to a security descriptor whose parts are where it says.
pub unsafe extern "C" fn RtlLengthSecurityDescriptor(sd: *const c_void) -> u32 {
    // SAFETY: per the contract.
    unsafe {
        let (control, parts) = parts_of(sd.cast());
        let mut length = if control & nk_se::SE_SELF_RELATIVE != 0 {
            nk_se::RELATIVE_HEADER
        } else {
            nk_se::ABSOLUTE_SIZE
        };
        for (i, &part) in parts.iter().enumerate() {
            if !part.is_null() {
                length += nk_se::aligned(if i < 2 {
                    sid_length(part)
                } else {
                    acl_length(part)
                });
            }
        }
        length as u32
    }
}

/// [`RtlAddAccessAllowedAce`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-rtladdaccessallowedace).
///
/// # Safety
/// `acl` points to an ACL with the room its `AclSize` says; `sid` to a
/// SID.
pub unsafe extern "C" fn RtlAddAccessAllowedAce(
    acl: *mut u8,
    revision: u32,
    mask: u32,
    sid: PSID,
) -> NTSTATUS {
    // SAFETY: per the contract. The list and the SID are the driver's
    // memory, so the rules run on copies and the result is written back.
    unsafe {
        let room = acl_length(acl).max(nk_se::ACL_HEADER);
        let (Some(mut list), Some(who)) = (copied(acl, room), copied(sid, sid_length(sid))) else {
            return STATUS_INSUFFICIENT_RESOURCES;
        };
        match nk_se::add_access_allowed(&mut list, revision, mask, &who) {
            Ok(()) => {
                for (i, &byte) in list.iter().enumerate() {
                    acl.add(i).write(byte);
                }
                STATUS_SUCCESS
            }
            Err(AclError::InvalidSid) => STATUS_INVALID_SID,
            Err(AclError::RevisionMismatch) => STATUS_REVISION_MISMATCH,
            Err(AclError::InvalidAcl) => STATUS_INVALID_ACL,
            Err(AclError::NoRoom) => STATUS_ALLOTTED_SPACE_EXCEEDED,
        }
    }
}

/// [`RtlAbsoluteToSelfRelativeSD`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-rtlabsolutetoselfrelativesd):
/// write the one-block form of an absolute descriptor. Too little room
/// is reported with the room needed.
///
/// # Safety
/// `absolute` points to a security descriptor; `relative` is writable
/// for `*length` bytes.
pub unsafe extern "C" fn RtlAbsoluteToSelfRelativeSD(
    absolute: *const c_void,
    relative: *mut u8,
    length: *mut u32,
) -> NTSTATUS {
    // SAFETY: per the contract.
    unsafe {
        if parts_of(absolute.cast()).0 & nk_se::SE_SELF_RELATIVE != 0 {
            return STATUS_BAD_DESCRIPTOR_FORMAT;
        }
        let Some(copies) = Copies::of(absolute.cast()) else {
            return STATUS_INSUFFICIENT_RESOURCES;
        };
        let needed = copies.parts().relative_length();
        if (length.read_unaligned() as usize) < needed {
            length.write_unaligned(needed as u32);
            return STATUS_BUFFER_TOO_SMALL;
        }
        let mut block = Vec::new();
        if block.try_reserve_exact(needed).is_err() {
            return STATUS_INSUFFICIENT_RESOURCES;
        }
        block.resize(needed, 0);
        let written = copies.parts().write_relative(&mut block);
        debug_assert_eq!(written, Ok(needed));
        for (i, &byte) in block.iter().enumerate() {
            relative.add(i).write(byte);
        }
    }
    STATUS_SUCCESS
}

impl Copies {
    /// A self-relative descriptor of `parts` in a fresh pool block.
    fn block(parts: &Parts<'_>) -> Option<*mut u8> {
        let needed = parts.relative_length();
        let block = pool::alloc(needed, TAG);
        if block.is_null() {
            return None;
        }
        // SAFETY: the block is fresh, `needed` bytes long, and the
        // kernel's own until it is returned.
        let written =
            parts.write_relative(unsafe { core::slice::from_raw_parts_mut(block, needed) });
        debug_assert_eq!(written, Ok(needed));
        Some(block)
    }
}

/// `ZwSetSecurityObject` (`ntifs.h`): replace the parts of an object's
/// security descriptor that `information` names with those of
/// `descriptor`. Devices have a descriptor (`DEVICE_OBJECT.
/// SecurityDescriptor`); for other objects NK keeps none and says so.
///
/// # Safety
/// `descriptor` points to a security descriptor whose parts are where
/// it says.
pub unsafe extern "C" fn ZwSetSecurityObject(
    handle: *mut c_void,
    information: u32,
    descriptor: *const c_void,
) -> NTSTATUS {
    use crate::ob::{handle, object};
    if descriptor.is_null() {
        return STATUS_INVALID_PARAMETER;
    }
    // SAFETY: per the contract; the object is referenced from the look-up
    // to the last line.
    unsafe {
        if !known_revision(descriptor.cast()) {
            return STATUS_UNKNOWN_REVISION;
        }
        let Some(new) = Copies::of(descriptor.cast()) else {
            return STATUS_INSUFFICIENT_RESOURCES;
        };
        match new.parts().validate() {
            Ok(()) => {}
            Err(nk_se::Invalid::Sid) => return STATUS_INVALID_SID,
            Err(nk_se::Invalid::Acl) => return STATUS_INVALID_ACL,
        }
        let body = match handle::reference(handle as u64, None) {
            Ok(body) => body,
            Err(status) => return status,
        };
        let status = if core::ptr::eq(object::type_of(body), &raw const object::DEVICE_TYPE) {
            let replaced = crate::io::device::replace_security(body.cast(), |old| {
                let old = if old.is_null() {
                    Copies {
                        control: 0,
                        parts: [const { None }; 4],
                    }
                } else {
                    Copies::of(old)?
                };
                Copies::block(&old.parts().replaced(&new.parts(), information))
            });
            match replaced {
                Some(()) => STATUS_SUCCESS,
                None => STATUS_INSUFFICIENT_RESOURCES,
            }
        } else {
            STATUS_NOT_SUPPORTED
        };
        object::dereference(body);
        status
    }
}

/// A self-relative copy of a descriptor, in a pool block the caller
/// frees. `None` without memory.
///
/// # Safety
/// `sd` points to a security descriptor whose parts are where it says.
pub unsafe fn capture(sd: *const u8) -> Option<*mut u8> {
    // SAFETY: per the contract.
    unsafe { Copies::block(&Copies::of(sd)?.parts()) }
}

/// `SeCaptureSecurityDescriptor`: give the caller a descriptor it can
/// rely on. A kernel-mode caller's own descriptor already is one,
/// unless a copy is insisted on (`force`); a copy is self-relative, in
/// the pool, and the caller's to free.
///
/// # Safety
/// `sd` is null or points to a security descriptor; `captured` is
/// writable.
pub unsafe extern "C" fn SeCaptureSecurityDescriptor(
    sd: *mut c_void,
    _requestor_mode: i8,
    _pool_type: u32,
    force: u8,
    captured: *mut *mut c_void,
) -> NTSTATUS {
    // SAFETY: per the contract. Every caller is in kernel mode: there is
    // no other yet.
    unsafe {
        if sd.is_null() || force == 0 {
            captured.write_unaligned(sd);
            return STATUS_SUCCESS;
        }
        if !known_revision(sd.cast()) {
            return STATUS_UNKNOWN_REVISION;
        }
        match capture(sd.cast()) {
            Some(copy) => {
                captured.write_unaligned(copy.cast());
                STATUS_SUCCESS
            }
            None => STATUS_INSUFFICIENT_RESOURCES,
        }
    }
}
