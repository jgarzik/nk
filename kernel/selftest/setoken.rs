//! Tests of tokens, subjects and access checks through the routines
//! drivers call: each test makes the calls a driver makes, with the
//! driver's own structures, and reads back what a driver would read.

use crate::ke::mutex::KeAreApcsDisabled;
use crate::mm::pool;
use crate::ob::object;
use crate::ps::process;
use crate::se::access::*;
use crate::se::descriptor::*;
use crate::se::impersonate::*;
use crate::se::token::*;
use crate::se::zwtoken::*;
use crate::test::{Group, Report};
use alloc::vec::Vec;
use core::ffi::c_void;
use nk_bootinfo::BootInfo;
use nk_ntabi::io::FILE_GENERIC_MAPPING;
use nk_ntabi::ob::OBJECT_ATTRIBUTES;
use nk_ntabi::se::{
    ACCESS_STATE, AUX_ACCESS_DATA, LUID_AND_ATTRIBUTES, PRIVILEGE_SET, SECURITY_DESCRIPTOR,
    SECURITY_QUALITY_OF_SERVICE, SECURITY_SUBJECT_CONTEXT, TOKEN_HAS_TRAVERSE_PRIVILEGE,
};

pub static GROUP: Group = Group {
    names: &[
        "se.subject-context",
        "se.access-state",
        "se.access-check",
        "se.access-check.privileges",
        "se.privileges",
        "se.privileges.append",
        "se.assign",
        "se.descriptor-info",
        "se.token-query",
        "se.token-handles",
        "se.impersonation",
    ],
    run,
    manual: false,
};

/// Pool tag of the tests' own blocks.
const TAG: u32 = u32::from_le_bytes(*b"SeTs");

/// `GENERIC_READ`, `DELETE`, `MAXIMUM_ALLOWED`.
const GENERIC_READ: u32 = 0x8000_0000;
const DELETE: u32 = 0x0001_0000;
const MAXIMUM_ALLOWED: u32 = 0x0200_0000;

/// A structure a driver would have on its stack, every byte `0xA5`:
/// whatever a routine does not write stays visible.
fn dirty<T>() -> T {
    let mut value = core::mem::MaybeUninit::<T>::uninit();
    // SAFETY: the bytes of `value`; the types this is used for are
    // integers and pointers, for which any bytes are a value.
    unsafe {
        value.as_mut_ptr().write_bytes(0xA5, 1);
        value.assume_init()
    }
}

/// The System process's token with a reference, and how many it has.
fn primary() -> (*mut u8, i64) {
    let token = process::reference_primary_token();
    // SAFETY: the reference just taken.
    (token, unsafe { references(token) })
}

/// A captured subject is the System process acting as itself, holds
/// its token until released, and locking it is a critical region.
fn subject_context() -> Result<(), &'static str> {
    let (token, before) = primary();
    let mut subject: SECURITY_SUBJECT_CONTEXT = dirty();
    let subject = &raw mut subject;
    // SAFETY: a local that outlives the calls; the token outlives all.
    let verdict = unsafe {
        SeCaptureSubjectContext(subject);
        let captured = subject.read();
        let held = references(token);
        let free = KeAreApcsDisabled();
        SeLockSubjectContext(subject);
        let locked = KeAreApcsDisabled();
        SeUnlockSubjectContext(subject);
        let unlocked = KeAreApcsDisabled();
        SeReleaseSubjectContext(subject);
        let released = subject.read();
        if !captured.ClientToken.is_null()
            || captured.PrimaryToken != token.cast()
            || captured.ProcessAuditId as u64 != nk_ntabi::process::SYSTEM_PROCESS_ID
        {
            Err("a captured subject is not the System process acting as itself")
        } else if captured.ImpersonationLevel != 0xA5A5_A5A5 {
            Err("a capture with no client wrote an impersonation level")
        } else if held != before + 1 || references(token) != before {
            Err("a captured subject did not hold its token exactly until released")
        } else if free != 0 || locked == 0 || unlocked != 0 {
            Err("a locked subject is not a critical region, or an unlocked one is")
        } else if !released.ClientToken.is_null() || !released.PrimaryToken.is_null() {
            Err("a released subject still names its tokens")
        } else {
            Ok(())
        }
    };
    // SAFETY: the reference `primary` took.
    unsafe { object::dereference(token) };
    verdict
}

/// What `SeCreateAccessState` leaves in the caller's two structures,
/// and what `SeDeleteAccessState` gives back.
fn access_state() -> Result<(), &'static str> {
    let (token, before) = primary();
    let (mut states, mut auxes): ([ACCESS_STATE; 3], [AUX_ACCESS_DATA; 3]) = (dirty(), dirty());
    let (states, auxes) = (states.as_mut_ptr(), auxes.as_mut_ptr());
    let aux = |i: usize| auxes.wrapping_add(i);
    let [first, second, third] = [0, 1, 2].map(|i| states.wrapping_add(i));
    // SAFETY: locals that outlive the calls; the token outlives all.
    let verdict = unsafe {
        let made = [
            SeCreateAccessState(first, aux(0), GENERIC_READ | DELETE, &FILE_GENERIC_MAPPING),
            SeCreateAccessState(second, aux(1), MAXIMUM_ALLOWED, &FILE_GENERIC_MAPPING),
            SeCreateAccessState(third, aux(2), GENERIC_READ, core::ptr::null()),
        ];
        let held = references(token);
        let verdict = (|| {
            if made != [0; 3] {
                return Err("an access state was not created");
            }
            let (a, x) = (&*first.cast_const(), &*aux(0).cast_const());
            if a.RemainingDesiredAccess != 0x13_0089
                || a.OriginalDesiredAccess != 0x13_0089
                || a.PreviouslyGrantedAccess != 0
            {
                return Err("a new access state does not hold the access asked for, mapped");
            }
            if (*second).RemainingDesiredAccess != MAXIMUM_ALLOWED
                || (*third).RemainingDesiredAccess != GENERIC_READ
            {
                return Err("access that no mapping applies to was changed");
            }
            if a.Flags != TOKEN_HAS_TRAVERSE_PRIVILEGE {
                return Err("the System token's right to traverse is not in the access state");
            }
            let subject = &a.SubjectSecurityContext;
            if subject.PrimaryToken != token.cast()
                || !subject.ClientToken.is_null()
                || subject.ProcessAuditId as u64 != 4
            {
                return Err("a new access state's subject is not the caller");
            }
            let id = |state: *const ACCESS_STATE| {
                ((*state).OperationID.LowPart, (*state).OperationID.HighPart)
            };
            if id(first) == (0, 0) || id(first) == id(second) || id(second) == id(third) {
                return Err("two access states share an operation id");
            }
            if a.AuxData != aux(0).cast()
                || x.PrivilegesUsed != (&raw mut (*first).Privileges).cast()
                || x.GenericMapping.GenericRead != FILE_GENERIC_MAPPING.GenericRead
                || x.GenericMapping.GenericAll != FILE_GENERIC_MAPPING.GenericAll
                || (*aux(2)).GenericMapping.GenericAll != 0
            {
                return Err("the auxiliary data is not the caller's room, filled in");
            }
            let quiet = a.SecurityEvaluated == 0
                && a.GenerateAudit == 0
                && a.GenerateOnClose == 0
                && a.PrivilegesAllocated == 0
                && a.AuditPrivileges == 0
                && a.SecurityDescriptor.is_null()
                && a.Privileges == [0; 11]
                && a.ObjectName.Length == 0
                && a.ObjectName.Buffer.is_null()
                && a.ObjectTypeName.Buffer.is_null()
                && x.AccessesToAudit == 0
                && x.NewSecurityDescriptor.is_null()
                && x.DeRefSecurityDescriptor.is_null()
                && x.AccessReasons == [0; 32]
                && x.GenerateStagingEvents == 0;
            if !quiet {
                return Err("a new access state holds something nobody put there");
            }
            Ok(())
        })();
        // What an open leaves in the pool for the state to free: the
        // names, and a descriptor nobody took. The group's leak check
        // says whether they were freed.
        (&raw mut (*first).ObjectName.Buffer).write(pool::alloc(32, TAG).cast());
        (&raw mut (*first).ObjectTypeName.Buffer).write(pool::alloc(32, TAG).cast());
        (&raw mut (*aux(0)).NewSecurityDescriptor).write(pool::alloc(32, TAG).cast());
        for state in [first, second, third] {
            SeDeleteAccessState(state);
        }
        if verdict.is_ok() && held != before + 3 {
            Err("an access state did not hold its token")
        } else if verdict.is_ok() && references(token) != before {
            Err("a deleted access state still holds its token")
        } else if verdict.is_ok() && !(*aux(0)).NewSecurityDescriptor.is_null() {
            Err("a deleted access state still names the descriptor it freed")
        } else {
            verdict
        }
    };
    // SAFETY: the reference `primary` took.
    unsafe { object::dereference(token) };
    verdict
}

// ---- descriptors made by hand ---------------------------------------------

/// A SID of one or two sub-authorities, laid out as the kernel's.
#[repr(C, align(4))]
struct Sid([u8; 16]);

const fn sid(authority: u8, sub_authorities: &[u32]) -> Sid {
    let (bytes, _) = nk_se::sid(authority, sub_authorities);
    let mut out = [0; 16];
    let mut i = 0;
    while i < 16 {
        out[i] = bytes[i];
        i += 1;
    }
    Sid(out)
}

static SYSTEM: Sid = sid(5, &[18]);
static ADMINS: Sid = sid(5, &[32, 544]);
static WORLD: Sid = sid(1, &[0]);
static AUTHENTICATED: Sid = sid(5, &[11]);
static ANONYMOUS: Sid = sid(5, &[7]);
static OWNER_RIGHTS: Sid = sid(3, &[4]);

impl Sid {
    fn bytes(&self) -> &[u8] {
        &self.0[..nk_se::sid_length(usize::from(self.0[1]))]
    }
}

const ALLOW: u8 = 0;
const DENY: u8 = 1;

/// One entry of an access list: type, flags, mask, SID.
type Ace = (u8, u8, u32, &'static Sid);

/// An access list of these entries, exactly as long as they are.
fn acl(aces: &[Ace]) -> Vec<u8> {
    let mut list = alloc::vec![nk_se::ACL_REVISION, 0, 0, 0, aces.len() as u8, 0, 0, 0];
    for &(kind, flags, mask, sid) in aces {
        let sid = sid.bytes();
        list.extend([kind, flags, 8 + sid.len() as u8, 0]);
        list.extend(mask.to_le_bytes());
        list.extend(sid);
    }
    list[2] = list.len() as u8;
    list
}

/// How a descriptor's access list is given.
#[derive(Clone, Copy)]
enum Dacl {
    /// None: the "present" bit is clear.
    Absent,
    /// Present, and a null pointer.
    Null,
    List(&'static [Ace]),
}

/// An absolute descriptor as a driver builds one, with the list it
/// points to.
struct Absolute {
    sd: SECURITY_DESCRIPTOR,
    _list: Vec<u8>,
}

impl Absolute {
    fn new(owner: Option<&'static Sid>, group: Option<&'static Sid>, dacl: Dacl) -> Self {
        Self::with_control(owner, group, dacl, 0)
    }

    fn with_control(
        owner: Option<&'static Sid>,
        group: Option<&'static Sid>,
        dacl: Dacl,
        control: u16,
    ) -> Self {
        let mut list = match dacl {
            Dacl::List(aces) => acl(aces),
            _ => Vec::new(),
        };
        let pointer = |sid: Option<&'static Sid>| {
            sid.map_or(core::ptr::null_mut(), |sid| {
                core::ptr::from_ref(sid).cast_mut().cast()
            })
        };
        let sd = SECURITY_DESCRIPTOR {
            Revision: nk_se::SECURITY_DESCRIPTOR_REVISION,
            Sbz1: 0,
            Control: control
                | match dacl {
                    Dacl::Absent => 0,
                    _ => nk_se::SE_DACL_PRESENT,
                },
            Owner: pointer(owner),
            Group: pointer(group),
            Sacl: core::ptr::null_mut(),
            Dacl: match dacl {
                Dacl::List(_) => list.as_mut_ptr().cast(),
                _ => core::ptr::null_mut(),
            },
        };
        Self { sd, _list: list }
    }

    fn pointer(&mut self) -> *mut c_void {
        (&raw mut self.sd).cast()
    }
}

// ---- the access check -----------------------------------------------------

const READ_CONTROL: u32 = 0x0002_0000;
const WRITE_DAC: u32 = 0x0004_0000;
const WRITE_OWNER: u32 = 0x0008_0000;
const ASS: u32 = 0x0100_0000;
const MAX: u32 = MAXIMUM_ALLOWED;
const FILE_ALL: u32 = 0x001F_01FF;
const FILE_READ: u32 = 0x0012_0089;
const GENERIC_ALL: u32 = 0x1000_0000;
const DENIED: u32 = 0xC000_0022;
const NOT_HELD: u32 = 0xC000_0061;
const BAD_LEVEL: u32 = 0xC000_00A5;
const INHERIT_ONLY: u8 = 0x08;

static ALLOW_RW: [Ace; 1] = [(ALLOW, 0, 3, &SYSTEM)];
static ALLOW_R: [Ace; 1] = [(ALLOW, 0, 1, &SYSTEM)];
static ALLOW_ALL: [Ace; 1] = [(ALLOW, 0, FILE_ALL, &SYSTEM)];
static DENY_ALL: [Ace; 1] = [(DENY, 0, FILE_ALL, &SYSTEM)];
static DENY_FIRST: [Ace; 2] = [(DENY, 0, 1, &SYSTEM), (ALLOW, 0, 3, &SYSTEM)];
static DENY_LAST: [Ace; 2] = [(ALLOW, 0, 3, &SYSTEM), (DENY, 0, 1, &SYSTEM)];
static BY_GROUPS: [Ace; 3] = [
    (ALLOW, 0, 1, &WORLD),
    (ALLOW, 0, 2, &ADMINS),
    (ALLOW, 0, 4, &AUTHENTICATED),
];
static DENY_GROUP: [Ace; 2] = [(DENY, 0, 2, &WORLD), (ALLOW, 0, 3, &SYSTEM)];
static STRANGER: [Ace; 1] = [(ALLOW, 0, FILE_ALL, &ANONYMOUS)];
static DENY_STRANGER: [Ace; 2] = [(DENY, 0, 1, &ANONYMOUS), (ALLOW, 0, 1, &SYSTEM)];
static OWNER_READS: [Ace; 1] = [(ALLOW, 0, READ_CONTROL, &OWNER_RIGHTS)];
static OWNER_ONE: [Ace; 1] = [(ALLOW, 0, 1, &OWNER_RIGHTS)];
static GENERIC_READ_ACE: [Ace; 1] = [(ALLOW, 0, GENERIC_READ, &SYSTEM)];
static GENERIC_ALL_ACE: [Ace; 1] = [(ALLOW, 0, GENERIC_ALL, &SYSTEM)];
static FILE_READ_ACE: [Ace; 1] = [(ALLOW, 0, FILE_READ, &SYSTEM)];
static INHERIT_ONLY_ACE: [Ace; 1] = [(ALLOW, INHERIT_ONLY, 1, &SYSTEM)];

/// One question: the owner, the list, what is asked, what was granted
/// before, whether for kernel mode; and the answer: status and access
/// granted (the routine returns TRUE exactly when the status is zero).
type Check = (&'static Sid, Dacl, u32, u32, bool, u32, u32);

/// The questions the conformance driver `nkc-se` asks of the System
/// process's token, in its order, with the answers of the pinned
/// kernel's code.
static CHECKS: &[Check] = &[
    // Kernel mode: nothing is looked at.
    (
        &ANONYMOUS,
        Dacl::List(&STRANGER),
        FILE_ALL,
        0,
        true,
        0,
        FILE_ALL,
    ),
    (&ANONYMOUS, Dacl::List(&STRANGER), MAX, 0, true, 0, FILE_ALL),
    (
        &ANONYMOUS,
        Dacl::List(&STRANGER),
        ASS | 1,
        0,
        true,
        0,
        ASS | 1,
    ),
    // An entry for the user.
    (&ANONYMOUS, Dacl::List(&ALLOW_RW), 1, 0, false, 0, 1),
    (&ANONYMOUS, Dacl::List(&ALLOW_RW), 7, 0, false, DENIED, 0),
    // Deny, then allow; allow, then deny: the order stored decides.
    (&ANONYMOUS, Dacl::List(&DENY_FIRST), 2, 0, false, 0, 2),
    (&ANONYMOUS, Dacl::List(&DENY_FIRST), 3, 0, false, DENIED, 0),
    (&ANONYMOUS, Dacl::List(&DENY_FIRST), MAX, 0, false, 0, 2),
    (&ANONYMOUS, Dacl::List(&DENY_LAST), 3, 0, false, 0, 3),
    (&ANONYMOUS, Dacl::List(&DENY_LAST), MAX, 0, false, 0, 3),
    // Groups.
    (&ANONYMOUS, Dacl::List(&BY_GROUPS), 7, 0, false, 0, 7),
    (&ANONYMOUS, Dacl::List(&DENY_GROUP), 2, 0, false, DENIED, 0),
    (&ANONYMOUS, Dacl::List(&DENY_GROUP), MAX, 0, false, 0, 1),
    // Entries for a SID the token does not have.
    (&ANONYMOUS, Dacl::List(&STRANGER), 1, 0, false, DENIED, 0),
    (&ANONYMOUS, Dacl::List(&STRANGER), MAX, 0, false, DENIED, 0),
    (&ANONYMOUS, Dacl::List(&DENY_STRANGER), 1, 0, false, 0, 1),
    // No access list, and one that is present and null.
    (&ANONYMOUS, Dacl::Absent, 1, 0, false, 0, 1),
    (&ANONYMOUS, Dacl::Absent, MAX, 0, false, 0, FILE_ALL),
    (
        &ANONYMOUS,
        Dacl::Absent,
        MAX | 0x1000,
        0,
        false,
        0,
        FILE_ALL | 0x1000,
    ),
    (&ANONYMOUS, Dacl::Null, 1, 0, false, 0, 1),
    (&ANONYMOUS, Dacl::Null, MAX, 0, false, 0, FILE_ALL),
    // An empty list: nothing, but for what an owner has unasked.
    (&ANONYMOUS, Dacl::List(&[]), 1, 0, false, DENIED, 0),
    (
        &ANONYMOUS,
        Dacl::List(&[]),
        READ_CONTROL,
        0,
        false,
        DENIED,
        0,
    ),
    (&ANONYMOUS, Dacl::List(&[]), MAX, 0, false, DENIED, 0),
    (
        &SYSTEM,
        Dacl::List(&[]),
        READ_CONTROL | WRITE_DAC,
        0,
        false,
        0,
        0x6_0000,
    ),
    (&SYSTEM, Dacl::List(&[]), DELETE, 0, false, DENIED, 0),
    (&SYSTEM, Dacl::List(&[]), MAX, 0, false, 0, 0x6_0000),
    (
        &ADMINS,
        Dacl::List(&[]),
        READ_CONTROL,
        0,
        false,
        0,
        READ_CONTROL,
    ),
    // An entry for OWNER RIGHTS replaces what the owner has unasked.
    (
        &SYSTEM,
        Dacl::List(&OWNER_READS),
        WRITE_DAC,
        0,
        false,
        DENIED,
        0,
    ),
    (
        &SYSTEM,
        Dacl::List(&OWNER_READS),
        READ_CONTROL,
        0,
        false,
        0,
        READ_CONTROL,
    ),
    (
        &SYSTEM,
        Dacl::List(&OWNER_READS),
        MAX,
        0,
        false,
        0,
        READ_CONTROL,
    ),
    (&ANONYMOUS, Dacl::List(&OWNER_ONE), 1, 0, false, DENIED, 0),
    (&SYSTEM, Dacl::List(&OWNER_ONE), 1, 0, false, 0, 1),
    (
        &SYSTEM,
        Dacl::List(&OWNER_ONE),
        READ_CONTROL,
        0,
        false,
        DENIED,
        0,
    ),
    (
        &SYSTEM,
        Dacl::List(&DENY_ALL),
        READ_CONTROL,
        0,
        false,
        0,
        READ_CONTROL,
    ),
    // Generic rights are nobody's to map here: not an entry's, not the
    // request's.
    (
        &ANONYMOUS,
        Dacl::List(&GENERIC_READ_ACE),
        FILE_READ,
        0,
        false,
        DENIED,
        0,
    ),
    (
        &ANONYMOUS,
        Dacl::List(&GENERIC_READ_ACE),
        FILE_READ | 2,
        0,
        false,
        DENIED,
        0,
    ),
    (
        &ANONYMOUS,
        Dacl::List(&GENERIC_ALL_ACE),
        MAX,
        0,
        false,
        0,
        GENERIC_ALL,
    ),
    (
        &ANONYMOUS,
        Dacl::List(&FILE_READ_ACE),
        GENERIC_READ,
        0,
        false,
        DENIED,
        0,
    ),
    (
        &ANONYMOUS,
        Dacl::List(&INHERIT_ONLY_ACE),
        1,
        0,
        false,
        DENIED,
        0,
    ),
    // Access granted before.
    (&ANONYMOUS, Dacl::List(&ALLOW_R), 1, 0x100, false, 0, 0x101),
    (&ANONYMOUS, Dacl::List(&ALLOW_R), 2, 0x100, false, DENIED, 0),
    (&ANONYMOUS, Dacl::List(&ALLOW_R), 0, 0, false, DENIED, 0),
    (&ANONYMOUS, Dacl::List(&ALLOW_R), 0, 0x100, false, 0, 0x100),
    (
        &ANONYMOUS,
        Dacl::List(&STRANGER),
        MAX,
        0x100,
        false,
        0,
        0x100,
    ),
    // Rights a privilege gives: the token holds both, disabled.
    (
        &ANONYMOUS,
        Dacl::List(&ALLOW_ALL),
        ASS,
        0,
        false,
        NOT_HELD,
        0,
    ),
    (
        &ANONYMOUS,
        Dacl::List(&ALLOW_ALL),
        MAX | ASS,
        0,
        false,
        NOT_HELD,
        0,
    ),
    (
        &ANONYMOUS,
        Dacl::List(&[]),
        WRITE_OWNER,
        0,
        false,
        DENIED,
        0,
    ),
    (
        &ANONYMOUS,
        Dacl::List(&ALLOW_ALL),
        WRITE_OWNER,
        0,
        false,
        0,
        WRITE_OWNER,
    ),
];

/// What one call of `SeAccessCheck` wrote and returned: the status, the
/// access granted, the return value, and the privilege set.
struct Answer {
    status: u32,
    granted: u32,
    allowed: u8,
    privileges: *mut PRIVILEGE_SET,
}

/// One access check, the way a driver makes it: results start out as
/// rubbish, so what the routine does not write shows.
///
/// # Safety
/// `subject` is a captured subject context.
unsafe fn check(
    descriptor: *mut c_void,
    subject: *mut SECURITY_SUBJECT_CONTEXT,
    desired: u32,
    previously: u32,
    kernel: bool,
) -> Answer {
    let mut privileges = core::ptr::dangling_mut::<PRIVILEGE_SET>();
    let (mut granted, mut status) = (0xAAAA_AAAAu32, 0xAAAA_AAAAu32 as i32);
    // SAFETY: per the contract; the results are locals.
    let allowed = unsafe {
        SeAccessCheck(
            descriptor,
            subject,
            1,
            desired,
            previously,
            &raw mut privileges,
            &FILE_GENERIC_MAPPING,
            i8::from(!kernel),
            &raw mut granted,
            &raw mut status,
        )
    };
    Answer {
        status: status as u32,
        granted,
        allowed,
        privileges,
    }
}

/// Every question of the table gets Windows' answer, as the System
/// process's own subject.
fn access_check() -> Result<(), &'static str> {
    let mut subject: SECURITY_SUBJECT_CONTEXT = dirty();
    let subject = &raw mut subject;
    let mut wrong = 0;
    // SAFETY: the subject is captured for as long as it is used.
    unsafe {
        SeCaptureSubjectContext(subject);
        for (i, &(owner, dacl, desired, previously, kernel, status, granted)) in
            CHECKS.iter().enumerate()
        {
            let mut descriptor = Absolute::new(Some(owner), Some(&SYSTEM), dacl);
            let answer = check(descriptor.pointer(), subject, desired, previously, kernel);
            let expected = (status, granted, u8::from(status == 0));
            if (answer.status, answer.granted, answer.allowed) != expected
                || !answer.privileges.is_null()
            {
                crate::kd::print(format_args!(
                    "se.access-check: question {i}: {:#x} {:#x} {}, not {expected:#x?}\n",
                    answer.status, answer.granted, answer.allowed
                ));
                wrong += 1;
            }
        }
        // A null descriptor: refused for user mode, not looked at for
        // kernel mode.
        let null = core::ptr::null_mut();
        let (user, kernel) = (
            check(null, subject, 1, 0, false),
            check(null, subject, 1, 0, true),
        );
        SeReleaseSubjectContext(subject);
        if (user.status, user.granted, user.allowed) != (DENIED, 0, 0)
            || (kernel.status, kernel.granted, kernel.allowed) != (0, 1, 1)
        {
            return Err("a null descriptor was not refused, or was looked at for kernel mode");
        }
    }
    if wrong != 0 {
        return Err("an access check gave another answer than Windows");
    }
    Ok(())
}

/// A subject context a test fills in itself: `client` at `level`,
/// beside the System process's token.
struct Subject {
    context: SECURITY_SUBJECT_CONTEXT,
}

impl Subject {
    /// # Safety
    /// `client` is a token object; the subject takes no reference of
    /// its own on it, so it must outlive the subject.
    unsafe fn acting_as(client: *mut u8, level: u32) -> Self {
        Self {
            context: SECURITY_SUBJECT_CONTEXT {
                ClientToken: client.cast(),
                ImpersonationLevel: level,
                PrimaryToken: process::reference_primary_token().cast(),
                ProcessAuditId: nk_ntabi::process::SYSTEM_PROCESS_ID as *mut c_void,
            },
        }
    }

    fn pointer(&mut self) -> *mut SECURITY_SUBJECT_CONTEXT {
        &raw mut self.context
    }
}

impl Drop for Subject {
    fn drop(&mut self) {
        // SAFETY: the reference `acting_as` took.
        unsafe { object::dereference(self.context.PrimaryToken.cast()) };
    }
}

/// A token like the System process's with `SeSecurityPrivilege` and
/// `SeTakeOwnershipPrivilege` enabled, as an object.
fn privileged_token() -> Result<*mut u8, &'static str> {
    use nk_se::token::{
        SE_PRIVILEGE_ENABLED, SE_SECURITY_PRIVILEGE, SE_TAKE_OWNERSHIP_PRIVILEGE, Token,
    };
    let mut token = Token::system();
    for privilege in &mut token.privileges {
        if [SE_SECURITY_PRIVILEGE, SE_TAKE_OWNERSHIP_PRIVILEGE].contains(&privilege.luid) {
            privilege.attributes |= SE_PRIVILEGE_ENABLED;
        }
    }
    create(token).ok_or("no memory for a token")
}

/// The privileges of a set: each number, with its attributes.
///
/// # Safety
/// `set` is a privilege set.
unsafe fn privileges_of(set: *const PRIVILEGE_SET) -> Vec<(u32, u32)> {
    // SAFETY: per the contract: the count says how many entries follow.
    unsafe {
        let first = (&raw const (*set).Privilege).cast::<LUID_AND_ATTRIBUTES>();
        (0..(*set).PrivilegeCount as usize)
            .map(|i| {
                let entry = first.add(i).read();
                (entry.Luid.LowPart, entry.Attributes)
            })
            .collect()
    }
}

/// A privilege that grants a right is handed out in a set the caller
/// frees; the level of a client decides whether it may ask at all.
fn access_check_privileges() -> Result<(), &'static str> {
    const USED: u32 = 0x8000_0000;
    let client = privileged_token()?;
    let mut descriptor = Absolute::new(Some(&ANONYMOUS), Some(&SYSTEM), Dacl::List(&ALLOW_R));
    let descriptor = descriptor.pointer();
    // SAFETY: the client token lives until the last line.
    let verdict = unsafe {
        let mut impersonating = Subject::acting_as(client, 2);
        let mut identifying = Subject::acting_as(client, 1);
        let both = check(
            descriptor,
            impersonating.pointer(),
            ASS | WRITE_OWNER | 1,
            0,
            false,
        );
        let one = check(descriptor, impersonating.pointer(), ASS, 0, false);
        let none = check(descriptor, impersonating.pointer(), 1, 0, false);
        let refused = check(descriptor, impersonating.pointer(), ASS | 2, 0, false);
        let level = check(descriptor, identifying.pointer(), 1, 0, false);
        let kernel = check(descriptor, identifying.pointer(), ASS, 0, true);
        let sets = [both.privileges, one.privileges].map(|set| {
            if set.is_null() {
                Vec::new()
            } else {
                let privileges = privileges_of(set);
                let control = (*set).Control;
                SeFreePrivileges(set);
                if control == 0 { privileges } else { Vec::new() }
            }
        });
        if (both.status, both.granted, both.allowed) != (0, ASS | WRITE_OWNER | 1, 1)
            || sets[0] != [(8, USED), (9, USED)]
        {
            Err("two privileges that granted rights were not handed out as used")
        } else if (one.status, one.granted) != (0, ASS) || sets[1] != [(8, USED)] {
            Err("the privilege that granted system security was not handed out")
        } else if (none.status, none.granted) != (0, 1) || !none.privileges.is_null() {
            Err("a check no privilege took part in handed out a privilege set")
        } else if (refused.status, refused.granted, refused.allowed) != (DENIED, 0, 0)
            || !refused.privileges.is_null()
        {
            Err("a refused check handed out a privilege set")
        } else if (level.status, level.granted, level.allowed) != (BAD_LEVEL, 0, 0) {
            Err("a client that only identifies was checked for access")
        } else if (kernel.status, kernel.granted) != (0, ASS) || !kernel.privileges.is_null() {
            Err("kernel mode looked at the subject")
        } else {
            Ok(())
        }
    };
    // SAFETY: the reference `privileged_token` gave.
    unsafe { object::dereference(client) };
    verdict
}

// ---- privileges -----------------------------------------------------------

/// A set of up to four privileges, as a driver declares one: the set,
/// then the entries after its first.
#[repr(C)]
struct Set {
    set: PRIVILEGE_SET,
    more: [LUID_AND_ATTRIBUTES; 3],
}

impl Set {
    fn of(control: u32, privileges: &[(u32, u32)]) -> Self {
        // SAFETY: integers, for which all-zero is a value.
        let mut set: Self = unsafe { core::mem::zeroed() };
        set.set.PrivilegeCount = privileges.len() as u32;
        set.set.Control = control;
        let first = (&raw mut set.set.Privilege).cast::<LUID_AND_ATTRIBUTES>();
        for (i, &(number, attributes)) in privileges.iter().enumerate() {
            // SAFETY: at most four entries, which the structure has.
            unsafe {
                (*first.add(i)).Luid.LowPart = number;
                (*first.add(i)).Attributes = attributes;
            }
        }
        set
    }

    fn pointer(&mut self) -> *mut PRIVILEGE_SET {
        &raw mut self.set
    }
}

const fn luid(number: u32) -> nk_ntabi::se::LUID {
    nk_ntabi::se::LUID {
        LowPart: number,
        HighPart: 0,
    }
}

/// The privilege checks, with the sets and the answers of `nkc-se`.
fn privileges() -> Result<(), &'static str> {
    const ALL: u32 = 1;
    const USED: u32 = 0x8000_0000;
    // Which privileges, by number, the System token holds enabled.
    let held = (0..64).fold(0u64, |held, number| {
        held | u64::from(SeSinglePrivilegeCheck(luid(number), 1)) << number
    });
    if held != 0x1E_60B1_E890 {
        return Err("the privileges the System token holds enabled are not Windows'");
    }
    if SeSinglePrivilegeCheck(luid(8), 0) != 1 || SeSinglePrivilegeCheck(luid(63), 0) != 1 {
        return Err("kernel mode does not hold every privilege");
    }
    let (token, before) = primary();
    let mut subject: SECURITY_SUBJECT_CONTEXT = dirty();
    let subject = &raw mut subject;
    // (control, the set, for kernel mode) and (answer, the set after).
    type Case = (u32, &'static [(u32, u32)], bool, u8, &'static [(u32, u32)]);
    let cases: [Case; 8] = [
        (ALL, &[(7, 0)], false, 1, &[(7, USED)]),
        (ALL, &[(7, 0), (2, 0)], false, 0, &[(7, USED), (2, 0)]),
        (0, &[(7, 0), (2, 0)], false, 1, &[(7, USED), (2, 0)]),
        (ALL, &[(63, 0)], false, 0, &[(63, 0)]),
        (ALL, &[(63, 0)], true, 1, &[(63, 0)]),
        (ALL, &[], false, 1, &[]),
        (0, &[], false, 0, &[]),
        (
            0,
            &[(2, USED | 1), (20, 1)],
            false,
            1,
            &[(2, 1), (20, USED | 1)],
        ),
    ];
    let mut wrong = 0;
    // SAFETY: the subject is captured for as long as it is used.
    unsafe {
        SeCaptureSubjectContext(subject);
        for (i, &(control, set, kernel, answer, after)) in cases.iter().enumerate() {
            let mut set = Set::of(control, set);
            let got = SePrivilegeCheck(set.pointer(), subject, i8::from(!kernel));
            if got != answer || privileges_of(set.pointer()) != after {
                crate::kd::print(format_args!("se.privileges: set {i}: {got}\n"));
                wrong += 1;
            }
        }
        SeReleaseSubjectContext(subject);
        // A client that only identifies holds nothing.
        let mut identifying = Subject::acting_as(token, 1);
        let mut set = Set::of(ALL, &[(7, 0)]);
        if SePrivilegeCheck(set.pointer(), identifying.pointer(), 1) != 0
            || privileges_of(set.pointer()) != [(7, 0)]
        {
            wrong += 1;
        }
    }
    // SAFETY: the reference `primary` took.
    let left = unsafe {
        let left = references(token);
        object::dereference(token);
        left
    };
    if wrong != 0 {
        return Err("a privilege check gave another answer than Windows");
    }
    if left != before {
        return Err("a privilege check kept a reference to the token");
    }
    Ok(())
}

/// Privileges an open has used stay in the access state while three
/// are enough, then move to the pool, which the state's end frees.
fn append_privileges() -> Result<(), &'static str> {
    let (mut state, mut aux): (ACCESS_STATE, AUX_ACCESS_DATA) = (dirty(), dirty());
    let (state, aux) = (&raw mut state, &raw mut aux);
    let numbers = |set: *const PRIVILEGE_SET| -> Vec<u32> {
        // SAFETY: a privilege set of the state.
        unsafe { privileges_of(set) }
            .iter()
            .map(|&(number, _)| number)
            .collect()
    };
    // SAFETY: locals that outlive the calls.
    unsafe {
        if SeCreateAccessState(state, aux, 1, &FILE_GENERIC_MAPPING) != 0 {
            return Err("no access state");
        }
        let own = (&raw mut (*state).Privileges).cast::<PRIVILEGE_SET>();
        let verdict = (|| {
            let mut one = Set::of(1, &[(7, 0)]);
            let mut two = Set::of(1, &[(23, 0), (20, 0)]);
            if SeAppendPrivileges(state, one.pointer()) != 0
                || numbers(own) != [7]
                || (*state).PrivilegesAllocated != 0
            {
                return Err("the first privilege is not in the state's own set");
            }
            if SeAppendPrivileges(state, two.pointer()) != 0
                || numbers(own) != [7, 23, 20]
                || (*state).PrivilegesAllocated != 0
                || (*aux).PrivilegesUsed != own
                || (*own).Control != 0
            {
                return Err("three privileges do not fit the state's own set");
            }
            let mut fourth = Set::of(1, &[(21, 0)]);
            if SeAppendPrivileges(state, fourth.pointer()) != 0 {
                return Err("a fourth privilege was refused");
            }
            let moved = (*aux).PrivilegesUsed;
            if moved == own || (*state).PrivilegesAllocated != 1 {
                return Err("a fourth privilege did not move the set to the pool");
            }
            if numbers(moved) != [7, 23, 20, 21] || numbers(own) != [7, 23, 20] {
                return Err("the moved set is not the old one and the new privilege");
            }
            // Once more: from the pool to the pool, the old block freed.
            if SeAppendPrivileges(state, two.pointer()) != 0
                || numbers((*aux).PrivilegesUsed) != [7, 23, 20, 21, 23, 20]
            {
                return Err("privileges were not added to a set in the pool");
            }
            Ok(())
        })();
        // Frees the set in the pool: the group's leak check says so.
        SeDeleteAccessState(state);
        verdict
    }
}

// ---- the descriptor of an object ------------------------------------------

/// A descriptor a routine handed out, taken apart: control bits, owner,
/// group, and the access list's entries (type, flags, mask, SID), or
/// `None` for no list.
type Dump = (u16, Vec<u8>, Vec<u8>, Option<Vec<(u8, u8, u32, Vec<u8>)>>);

/// # Safety
/// `descriptor` is a self-relative descriptor in a pool block.
unsafe fn dump(descriptor: *mut c_void) -> Option<Dump> {
    // SAFETY: per the contract; its length is what its parts say.
    let block = unsafe {
        let length = crate::se::RtlLengthSecurityDescriptor(descriptor) as usize;
        core::slice::from_raw_parts(descriptor.cast::<u8>(), length)
    };
    let parts = nk_se::parse_relative(block)?;
    let entries = parts.dacl.map(|dacl| {
        nk_se::acl::aces(dacl)
            .filter_map(|ace| {
                let (mask, sid) = ace.basic()?;
                Some((ace.kind, ace.flags, mask, sid.to_vec()))
            })
            .collect()
    });
    Some((
        parts.control,
        parts.owner.unwrap_or_default().to_vec(),
        parts.group.unwrap_or_default().to_vec(),
        entries,
    ))
}

static USERS: Sid = sid(5, &[32, 545]);
static CREATOR_OWNER: Sid = sid(3, &[0]);
const OI: u8 = 0x01;
const CI: u8 = 0x02;
const NP: u8 = 0x04;
const GENERIC_EXECUTE: u32 = 0x2000_0000;
const GENERIC_WRITE: u32 = 0x4000_0000;

/// A parent's list: an entry for each way of being inherited.
static PARENT: [Ace; 7] = [
    (ALLOW, OI, 1, &WORLD),
    (ALLOW, CI, 2, &ADMINS),
    (ALLOW, OI | CI | INHERIT_ONLY, GENERIC_EXECUTE, &SYSTEM),
    (ALLOW, CI | NP, 8, &AUTHENTICATED),
    (ALLOW, OI | CI, GENERIC_ALL, &CREATOR_OWNER),
    (ALLOW, 0, 0x10, &USERS),
    (DENY, OI, 0x20, &ANONYMOUS),
];
/// A list the creator supplies.
static SUPPLIED: [Ace; 2] = [
    (ALLOW, 0, GENERIC_READ, &WORLD),
    (ALLOW, 0, GENERIC_ALL, &CREATOR_OWNER),
];
static WRITE: [Ace; 1] = [(ALLOW, 0, GENERIC_WRITE, &WORLD)];
/// The list the System token gives a new object by default, mapped
/// for a file.
static FROM_TOKEN: [Ace; 2] = [
    (ALLOW, 0, FILE_ALL, &SYSTEM),
    (ALLOW, 0, 0x12_00A9, &ADMINS),
];
/// `SUPPLIED` as assigned to an object the system owns.
static FROM_SUPPLIED: [Ace; 2] = [(ALLOW, 0, FILE_READ, &WORLD), (ALLOW, 0, FILE_ALL, &SYSTEM)];
/// What an object that is not a directory inherits from `PARENT`,
/// owned by administrators.
static FROM_PARENT: [Ace; 4] = [
    (ALLOW, 0, 1, &WORLD),
    (ALLOW, 0, 0x12_00A0, &SYSTEM),
    (ALLOW, 0, FILE_ALL, &ADMINS),
    (DENY, 0, 0x20, &ANONYMOUS),
];

/// `SeAssignSecurity` as the System process's subject: the status and
/// the new descriptor, or null.
fn assign(parent: Option<&mut Absolute>, explicit: Option<&mut Absolute>) -> (i32, *mut c_void) {
    let mut subject: SECURITY_SUBJECT_CONTEXT = dirty();
    let subject = &raw mut subject;
    let mut new = core::ptr::dangling_mut::<c_void>();
    let pointer = |sd: Option<&mut Absolute>| sd.map_or(core::ptr::null_mut(), Absolute::pointer);
    // SAFETY: the descriptors and the subject outlive the call.
    let status = unsafe {
        SeCaptureSubjectContext(subject);
        let status = SeAssignSecurity(
            pointer(parent),
            pointer(explicit),
            &raw mut new,
            0,
            subject,
            &FILE_GENERIC_MAPPING,
            1,
        );
        SeReleaseSubjectContext(subject);
        status
    };
    (status, new)
}

/// The descriptor a new object gets: from the token alone, from what
/// its creator supplies, from its parent.
fn assign_security() -> Result<(), &'static str> {
    type Entries = &'static [(u8, u8, u32, &'static Sid)];
    let same = |dump: Option<Dump>, owner: &Sid, group: &Sid, entries: Option<Entries>| {
        let expected = entries.map(|entries| {
            entries
                .iter()
                .map(|&(kind, flags, mask, sid)| (kind, flags, mask, sid.bytes().to_vec()))
                .collect::<Vec<_>>()
        });
        dump.is_some_and(|(control, its_owner, its_group, its_entries)| {
            control == 0x8004
                && its_owner == owner.bytes()
                && its_group == group.bytes()
                && its_entries == expected
        })
    };
    let mut parent = Absolute::new(Some(&USERS), Some(&USERS), Dacl::List(&PARENT));
    let mut supplied = Absolute::new(Some(&SYSTEM), Some(&ADMINS), Dacl::List(&SUPPLIED));
    let mut stranger = Absolute::new(Some(&ANONYMOUS), Some(&ANONYMOUS), Dacl::Absent);
    let mut null = Absolute::new(None, None, Dacl::Null);
    let cases: [(Option<&mut Absolute>, Option<&mut Absolute>); 5] = [
        (None, None),
        (None, Some(&mut supplied)),
        (Some(&mut parent), None),
        (None, Some(&mut stranger)),
        (None, Some(&mut null)),
    ];
    // What each must come to: owner, group, entries.
    let expected: [(&Sid, &Sid, Option<Entries>); 5] = [
        // All from the token: its default owner, group and list.
        (&ADMINS, &SYSTEM, Some(&FROM_TOKEN)),
        // Supplied: generic rights mapped, the creator-owner entry now
        // the owner's.
        (&SYSTEM, &ADMINS, Some(&FROM_SUPPLIED)),
        // Inherited by an object that is not a directory.
        (&ADMINS, &SYSTEM, Some(&FROM_PARENT)),
        // An owner the token could not be, from a kernel-mode creator.
        (&ANONYMOUS, &ANONYMOUS, Some(&FROM_TOKEN)),
        // A list that is present and null.
        (&ADMINS, &SYSTEM, None),
    ];
    let mut wrong = 0;
    for (i, ((parent, explicit), (owner, group, entries))) in
        cases.into_iter().zip(expected).enumerate()
    {
        let (status, mut new) = assign(parent, explicit);
        // SAFETY: a descriptor the routine made, freed here.
        let right = status == 0
            && !new.is_null()
            && unsafe {
                let right = same(dump(new), owner, group, entries);
                let freed = SeDeassignSecurity(&raw mut new);
                right && freed == 0 && new.is_null()
            };
        if !right {
            crate::kd::print(format_args!("se.assign: case {i}: status {status:#x}\n"));
            wrong += 1;
        }
    }
    if wrong != 0 {
        return Err("a new object's descriptor is not the one Windows assigns");
    }
    Ok(())
}

/// Reading parts of an object's descriptor into a caller's buffer, and
/// changing them.
fn descriptor_info() -> Result<(), &'static str> {
    const OWNER: u32 = 1;
    const GROUP: u32 = 2;
    const DACL: u32 = 4;
    const TOO_SMALL: i32 = 0xC000_0023u32 as i32;
    const INVALID_OWNER: i32 = 0xC000_005Au32 as i32;
    const NO_SECURITY: i32 = 0xC000_00D7u32 as i32;
    let mut supplied = Absolute::new(Some(&SYSTEM), Some(&ADMINS), Dacl::List(&SUPPLIED));
    let (status, mut object) = assign(None, Some(&mut supplied));
    if status != 0 || object.is_null() {
        return Err("no descriptor to work on");
    }
    // The header a query wrote: control bits and the four offsets.
    let query = |object: &mut *mut c_void, information: u32, room: u32| {
        let mut out = [0xA5u8; 128];
        let mut length = room;
        // SAFETY: the buffer is longer than any `room` used.
        let status = unsafe {
            SeQuerySecurityDescriptorInfo(
                &raw const information,
                out.as_mut_ptr(),
                &raw mut length,
                object,
            )
        };
        let word = |at: usize| u32::from_le_bytes([out[at], out[at + 1], out[at + 2], out[at + 3]]);
        (
            status,
            length,
            word(0) >> 16,
            [word(4), word(8), word(12), word(16)],
        )
    };
    let set = |object: &mut *mut c_void, information: u32, modification: &mut Absolute| {
        let old = *object;
        // SAFETY: the object's descriptor and a local modification.
        let status = unsafe {
            SeSetSecurityDescriptorInfo(
                core::ptr::null_mut(),
                &raw const information,
                modification.pointer(),
                object,
                1,
                &FILE_GENERIC_MAPPING,
            )
        };
        let changed = *object != old;
        if changed {
            // The one the object had is the caller's to free.
            // SAFETY: a pool block from this module.
            unsafe { crate::mm::pool::ExFreePoolWithTag(old, 0) };
        }
        (status, changed)
    };
    let verdict = (|| {
        // Owner alone: 20 bytes of header and a 12-byte SID.
        if query(&mut object, OWNER, 0) != (TOO_SMALL, 32, 0xA5A5, [0xA5A5_A5A5; 4]) {
            return Err("a buffer too short was written, or not told the length needed");
        }
        if query(&mut object, OWNER, 128) != (0, 32, 0x8000, [20, 0, 0, 0]) {
            return Err("the owner alone is not what a query for the owner gives");
        }
        // The list alone: 8 bytes and two entries of 20.
        if query(&mut object, DACL, 128) != (0, 68, 0x8004, [0, 0, 0, 20]) {
            return Err("the access list alone is not what a query for it gives");
        }
        if query(&mut object, 0, 128) != (0, 20, 0x8000, [0; 4]) {
            return Err("a query for nothing does not give an empty descriptor");
        }
        let mut none = core::ptr::null_mut();
        if query(&mut none, OWNER | DACL, 128) != (0, 20, 0x8000, [0; 4]) {
            return Err("an object with no descriptor does not give an empty one");
        }
        // A new list: its generic right mapped; owner and group stay.
        let mut write = Absolute::new(None, None, Dacl::List(&WRITE));
        if set(&mut object, DACL, &mut write) != (0, true) {
            return Err("a new access list was not set");
        }
        // SAFETY: the object's descriptor.
        let now = unsafe { dump(object) }.ok_or("the new descriptor is not sound")?;
        if now.1 != SYSTEM.bytes()
            || now.2 != ADMINS.bytes()
            || now.3 != Some(alloc::vec![(ALLOW, 0, 0x12_0116, WORLD.bytes().to_vec())])
        {
            return Err("a new access list did not leave the rest, or was not mapped");
        }
        // Owners: none given, one the token may be, one it may not.
        let mut admins = Absolute::new(Some(&ADMINS), None, Dacl::Absent);
        let mut anonymous = Absolute::new(Some(&ANONYMOUS), None, Dacl::Absent);
        if set(&mut object, OWNER, &mut write) != (INVALID_OWNER, false)
            || set(&mut object, OWNER, &mut anonymous) != (INVALID_OWNER, false)
        {
            return Err("an owner that is not valid was set, or not refused as Windows does");
        }
        if set(&mut object, OWNER, &mut admins) != (0, true)
            // SAFETY: the object's descriptor.
            || unsafe { dump(object) }.is_none_or(|now| now.1 != ADMINS.bytes())
        {
            return Err("an owner the token may be was not set");
        }
        // A group named and not given: the object is left without one.
        if set(&mut object, GROUP, &mut write) != (0, true)
            // SAFETY: the object's descriptor.
            || unsafe { dump(object) }.is_none_or(|now| !now.2.is_empty())
        {
            return Err("a group named and not given did not take the group away");
        }
        if set(&mut none, DACL, &mut write) != (NO_SECURITY, false) {
            return Err("an object with no descriptor had one set");
        }
        Ok(())
    })();
    // SAFETY: the object's descriptor, freed once.
    let freed = unsafe { SeDeassignSecurity(&raw mut object) };
    verdict?;
    if freed != 0 || !object.is_null() {
        return Err("the descriptor was not given back");
    }
    Ok(())
}

// ---- what a token answers -------------------------------------------------

static SYSTEM_LABEL: Sid = sid(16, &[0x4000]);
const INVALID_INFO_CLASS: i32 = 0xC000_0003u32 as i32;
/// What a query's result variable holds before the call.
const UNTOUCHED: usize = 0xAAAA_AAAA_AAAA_AAAA;

/// One query of a token: the status, and what is where the block's
/// address goes.
///
/// # Safety
/// `token` is a token object the caller holds a reference to.
unsafe fn query(token: *mut u8, class: u32) -> (i32, usize) {
    let mut answer = UNTOUCHED as *mut c_void;
    // SAFETY: per the contract; the result is a local.
    let status = unsafe { SeQueryInformationToken(token.cast(), class, &raw mut answer) };
    (status, answer as usize)
}

/// The block a query handed out, read as 64-bit words and then freed.
/// `None` if the query failed or handed out nothing.
///
/// # Safety
/// As [`query`]; `words` is no more than the block holds.
unsafe fn block_of(token: *mut u8, class: u32, words: usize) -> Option<(usize, Vec<u64>)> {
    // SAFETY: per the contract.
    unsafe {
        let (status, block) = query(token, class);
        if status != 0 || block == UNTOUCHED || block == 0 {
            return None;
        }
        let read = (0..words)
            .map(|i| (block as *const u64).add(i).read_unaligned())
            .collect();
        Some((block, read))
    }
}

/// The SID at `address`.
///
/// # Safety
/// `address` points to a SID.
unsafe fn sid_at(address: u64) -> Vec<u8> {
    // SAFETY: per the contract.
    unsafe {
        let sid = address as *const u8;
        core::slice::from_raw_parts(sid, crate::se::RtlLengthSid(sid) as usize).to_vec()
    }
}

fn free(block: usize) {
    // SAFETY: a pool block a query handed out, freed once.
    unsafe { pool::ExFreePoolWithTag(block as *mut c_void, 0) };
}

/// The System process's token, class by class, as
/// `SeQueryInformationToken` tells it.
fn token_query() -> Result<(), &'static str> {
    let (token, before) = primary();
    // SAFETY: the token is referenced until the last line; each block
    // is read within its length and freed once.
    let verdict = unsafe {
        (|| {
            if SeTokenType(token.cast()) != 1 {
                return Err("the System token is not a primary token");
            }
            // The user: one SID_AND_ATTRIBUTES, then the SID.
            let (block, user) = block_of(token, 1, 2).ok_or("no user")?;
            let right = user[0] == block as u64 + 16
                && user[1] as u32 == 0
                && sid_at(user[0]) == SYSTEM.bytes();
            free(block);
            if !right {
                return Err("the token's user is not the system, in a block of its own");
            }
            // The groups: a count, then SID_AND_ATTRIBUTES each.
            let (block, groups) = block_of(token, 2, 9).ok_or("no groups")?;
            let expected: [(&Sid, u32); 4] = [
                (&ADMINS, 0xE),
                (&WORLD, 7),
                (&AUTHENTICATED, 7),
                (&SYSTEM_LABEL, 0x60),
            ];
            let right = groups[0] as u32 == 4
                && expected.iter().enumerate().all(|(i, &(sid, attributes))| {
                    let (pointer, its) = (groups[1 + 2 * i], groups[2 + 2 * i] as u32);
                    pointer > block as u64 && its == attributes && sid_at(pointer) == sid.bytes()
                });
            free(block);
            if !right {
                return Err("the token's groups are not the System token's");
            }
            // The privileges: a count, then 12 bytes each.
            let (block, privileges) = block_of(token, 3, 2).ok_or("no privileges")?;
            let right = privileges[0] as u32 == 31
                && (privileges[0] >> 32) as u32 == 2
                && privileges[1] == 0;
            free(block);
            if !right {
                return Err("the token's privileges do not begin as the System token's");
            }
            // Owner, primary group, default list: a pointer, then it.
            for (class, sid) in [(4, &ADMINS), (5, &SYSTEM)] {
                let (block, part) = block_of(token, class, 1).ok_or("no owner or group")?;
                let right = part[0] == block as u64 + 8 && sid_at(part[0]) == sid.bytes();
                free(block);
                if !right {
                    return Err("the token's owner or primary group is not as on Windows");
                }
            }
            let (block, list) = block_of(token, 6, 2).ok_or("no default list")?;
            // An ACL header: revision 2, 52 bytes, two entries.
            let right = list[0] == block as u64 + 8 && list[1] == 0x0002_0034_0002;
            free(block);
            if !right {
                return Err("the token's default list is not the System token's");
            }
            // The type, in a block of its own; no level for a primary.
            let (status, block) = query(token, 8);
            if status != 0 || block == UNTOUCHED {
                return Err("no type");
            }
            let kind = (block as *const u32).read();
            free(block);
            if kind != 1 || query(token, 9) != (INVALID_INFO_CLASS, UNTOUCHED) {
                return Err("the type is not primary, or a primary token told a level");
            }
            let (block, statistics) = block_of(token, 10, 7).ok_or("no statistics")?;
            free(block);
            if statistics[1] != 0x3E7
                || statistics[2] != 0x0620_7526_B64C_EB90
                || statistics[3] != 1
                || statistics[5] != 4 | 31 << 32
            {
                return Err("the statistics are not the system logon's");
            }
            // Three classes answered with a number, four bytes of it,
            // where the address would go.
            let low = |value: u32| UNTOUCHED & !0xFFFF_FFFF | value as usize;
            if query(token, 12) != (0, low(0))
                || query(token, 25) != (0, low(0x4000))
                || query(token, 29) != (0, low(0))
            {
                return Err("the session, integrity level or container answer is not a number");
            }
            if query(token, 0x7F) != (INVALID_INFO_CLASS, UNTOUCHED) {
                return Err("a class there is not was answered");
            }
            Ok(())
        })()
    };
    // SAFETY: the reference `primary` took.
    let left = unsafe {
        let left = references(token);
        object::dereference(token);
        left
    };
    verdict?;
    if left != before {
        return Err("a query kept a reference to the token");
    }
    Ok(())
}

// ---- tokens by handle -----------------------------------------------------

const TOO_SMALL: i32 = 0xC000_0023u32 as i32;
const BAD_LEVEL_STATUS: i32 = BAD_LEVEL as i32;
const OBJ_KERNEL_HANDLE: u32 = 0x200;
const TOKEN_QUERY: u32 = 0x8;
const TOKEN_DUPLICATE: u32 = 0x2;

/// `ZwQueryInformationToken` with `room` bytes of a buffer: the status,
/// the length returned (rubbish before the call), the buffer, and
/// where the buffer was.
fn ask(handle: *mut c_void, class: u32, room: u32) -> (i32, u32, [u64; 8], u64) {
    let mut buffer = [0u64; 8];
    let mut length = 0xAAAA_AAAAu32;
    // SAFETY: the buffer is 64 bytes, and no `room` is more.
    let status = unsafe {
        ZwQueryInformationToken(
            handle,
            class,
            buffer.as_mut_ptr().cast(),
            room,
            &raw mut length,
        )
    };
    (status, length, buffer, buffer.as_ptr() as u64)
}

/// A token handle's type and impersonation level (or the status that
/// refuses to tell it).
fn brief(handle: *mut c_void) -> (u32, i32) {
    let (kind, level) = (ask(handle, 8, 4), ask(handle, 9, 4));
    (
        kind.2[0] as u32,
        if level.0 == 0 {
            level.2[0] as i32
        } else {
            level.0
        },
    )
}

/// `ZwDuplicateToken` of `source` as `kind` at `level` (`None`: no
/// quality of service): the status and the new handle.
fn duplicate(source: *mut c_void, kind: u32, level: Option<u32>) -> (i32, *mut c_void) {
    let mut qos = SECURITY_QUALITY_OF_SERVICE {
        Length: 12,
        ImpersonationLevel: level.unwrap_or(0),
        ContextTrackingMode: 0,
        EffectiveOnly: 0,
    };
    let attributes = OBJECT_ATTRIBUTES {
        Length: 48,
        RootDirectory: core::ptr::null_mut(),
        ObjectName: core::ptr::null(),
        Attributes: OBJ_KERNEL_HANDLE,
        SecurityDescriptor: core::ptr::null_mut(),
        SecurityQualityOfService: match level {
            Some(_) => (&raw mut qos).cast(),
            None => core::ptr::null_mut(),
        },
    };
    let mut copy = core::ptr::null_mut();
    // SAFETY: locals that outlive the call.
    let status = unsafe {
        ZwDuplicateToken(
            source,
            TOKEN_QUERY | TOKEN_DUPLICATE,
            &raw const attributes,
            0,
            kind,
            &raw mut copy,
        )
    };
    (status, copy)
}

/// The System process's token opened, asked and copied by handle, as
/// `nkc-se` does.
fn token_handles() -> Result<(), &'static str> {
    let current_process = usize::MAX as *mut c_void;
    let mut primary = core::ptr::null_mut();
    // SAFETY: the result is a local.
    let opened = unsafe {
        ZwOpenProcessTokenEx(
            current_process,
            TOKEN_QUERY | TOKEN_DUPLICATE,
            OBJ_KERNEL_HANDLE,
            &raw mut primary,
        )
    };
    if opened != 0 {
        return Err("the process's token was not opened");
    }
    let verdict = (|| {
        // The user: no room, then room.
        if ask(primary, 1, 0).0 != TOO_SMALL || ask(primary, 1, 0).1 != 28 {
            return Err("a buffer too short was not told the length needed");
        }
        let (status, length, user, _) = ask(primary, 1, 64);
        if status != 0 || length != 28 || user[1] != 0 {
            return Err("the user was not told");
        }
        // The SID S-1-5-18 follows the pointer to it. The pointer is
        // into the buffer `ask` had; `ask` moves the buffer when it
        // returns it, so the label below is where the pointer is held
        // to the buffer's address.
        if user[0] == 0 || user[2] != 0x0500_0000_0000_0101 {
            return Err("the user's SID is not in the buffer, after the pointer to it");
        }
        if ask(primary, 8, 2).0 != TOO_SMALL || ask(primary, 8, 2).1 != 4 {
            return Err("two bytes were enough for a token's type");
        }
        if brief(primary) != (1, INVALID_INFO_CLASS) || ask(primary, 9, 4).1 != 0xAAAA_AAAA {
            return Err("the primary token is not one, or told a level, or a length for it");
        }
        let (session, container) = (ask(primary, 12, 4), ask(primary, 29, 4));
        if (session.0, session.1, session.2[0]) != (0, 4, 0)
            || (container.0, container.1, container.2[0]) != (0, 4, 0)
        {
            return Err("the session or the container answer is not four bytes of zero");
        }
        let label = ask(primary, 25, 64);
        if (label.0, label.1, label.2[1]) != (0, 28, 0x60)
            || label.2[2] != 0x1000_0000_0000_0101
            || label.2[0] != label.3 + 16
        {
            return Err("the integrity level is not a label of the system level");
        }
        let statistics = ask(primary, 10, 64);
        if (statistics.0, statistics.1, statistics.2[1], statistics.2[3]) != (0, 56, 0x3E7, 1) {
            return Err("the statistics are not the system logon's");
        }
        // A class there is not: refused before the handle is looked at.
        if ask(primary, 0x7F, 64).0 != INVALID_INFO_CLASS
            || ask(core::ptr::null_mut(), 0x7F, 64).0 != INVALID_INFO_CLASS
            || ask(core::ptr::null_mut(), 1, 64).0 == 0
        {
            return Err("a class there is not, or a handle there is not, was answered");
        }
        // Copies: an impersonation token at each level; at the source's
        // own level when none is said; a primary token again.
        let mut identifying = core::ptr::null_mut();
        for level in 0..4 {
            let (status, copy) = duplicate(primary, 2, Some(level));
            if status != 0 || brief(copy) != (2, level as i32) {
                return Err("a copy is not an impersonation token of the level asked");
            }
            if level == 1 {
                identifying = copy;
            } else {
                crate::ps::ZwClose(copy);
            }
        }
        let (unsaid, again, neither) = (
            duplicate(primary, 2, None),
            duplicate(primary, 1, None),
            duplicate(primary, 3, Some(2)),
        );
        let briefs = (brief(unsaid.1), brief(again.1));
        // What a copy that only identifies may be copied to.
        let (higher, as_primary, lower) = (
            duplicate(identifying, 2, Some(2)),
            duplicate(identifying, 1, None),
            duplicate(identifying, 2, Some(0)),
        );
        let lower_brief = brief(lower.1);
        for handle in [unsaid.1, again.1, lower.1, identifying] {
            crate::ps::ZwClose(handle);
        }
        if (unsaid.0, again.0) != (0, 0) || briefs != ((2, 0), (1, INVALID_INFO_CLASS)) {
            return Err("a copy with no level said, or a primary copy, is not as on Windows");
        }
        if neither.0 != 0xC000_000Du32 as i32 {
            return Err("a copy of a type there is not was made");
        }
        if higher.0 != BAD_LEVEL_STATUS || as_primary.0 != BAD_LEVEL_STATUS {
            return Err("a token that only identifies was copied to more than it is");
        }
        if lower.0 != 0 || lower_brief != (2, 0) {
            return Err("a token that only identifies was not copied to a lower level");
        }
        Ok(())
    })();
    if crate::ps::ZwClose(primary) != 0 {
        return Err("the token's handle was not closed");
    }
    verdict
}

// ---- impersonation --------------------------------------------------------

const NO_TOKEN: i32 = 0xC000_007Cu32 as i32;
const BAD_TOKEN_TYPE: i32 = 0xC000_00A8u32 as i32;
const LENGTH_MISMATCH: i32 = 0xC000_0004u32 as i32;
const THREAD_IMPERSONATION_TOKEN: u32 = 5;
const CURRENT_THREAD: *mut c_void = usize::MAX.wrapping_sub(1) as *mut c_void;

/// What the calling thread impersonates, as a driver asks: the token
/// (referenced and given up again), and the three facts, which are
/// `0xAA` where the routine wrote nothing.
fn wearing() -> (*mut c_void, u8, u8, u32) {
    let (mut copy_on_open, mut effective_only, mut level) = (0xAAu8, 0xAAu8, 0xAAu32);
    // SAFETY: the running thread; the results are locals.
    unsafe {
        let token = PsReferenceImpersonationToken(
            crate::ke::thread::current().cast(),
            &raw mut copy_on_open,
            &raw mut effective_only,
            &raw mut level,
        );
        PsDereferenceImpersonationToken(token);
        (token, copy_on_open, effective_only, level)
    }
}

/// `ZwSetInformationThread(ThreadImpersonationToken)` on the calling
/// thread, with `length` bytes of a handle.
fn wear(token: *mut c_void, length: u32) -> i32 {
    // SAFETY: a local that outlives the call.
    unsafe {
        crate::ps::ZwSetInformationThread(
            CURRENT_THREAD,
            THREAD_IMPERSONATION_TOKEN,
            (&raw const token).cast(),
            length,
        )
    }
}

/// The calling thread's token, opened: the status and the handle,
/// which is 1 where the routine wrote nothing.
fn open_thread_token() -> (i32, *mut c_void) {
    let mut opened = core::ptr::dangling_mut::<c_void>();
    // SAFETY: the result is a local.
    let status = unsafe {
        ZwOpenThreadTokenEx(
            CURRENT_THREAD,
            TOKEN_QUERY,
            1,
            OBJ_KERNEL_HANDLE,
            &raw mut opened,
        )
    };
    (status, opened)
}

/// The object a token handle names; the reference taken to find it is
/// given up again, the handle keeps the object.
fn token_of(handle: *mut c_void) -> *mut c_void {
    match crate::ob::handle::reference(handle as u64, None) {
        Ok(body) => {
            // SAFETY: the reference just taken.
            unsafe { object::dereference(body) };
            body.cast()
        }
        Err(_) => core::ptr::null_mut(),
    }
}

/// A thread takes on a token, is seen to wear it by every routine that
/// asks, and puts it off.
fn impersonating() -> Result<(), &'static str> {
    if wearing() != (core::ptr::null_mut(), 0xAA, 0xAA, 0xAA) {
        return Err("a new thread impersonates, or was told how");
    }
    if open_thread_token() != (NO_TOKEN, core::ptr::dangling_mut()) {
        return Err("a thread that impersonates nobody had a token to open");
    }
    let mut primary = core::ptr::null_mut();
    // SAFETY: the result is a local.
    let opened = unsafe {
        ZwOpenProcessTokenEx(
            usize::MAX as *mut c_void,
            TOKEN_QUERY | TOKEN_DUPLICATE,
            OBJ_KERNEL_HANDLE,
            &raw mut primary,
        )
    };
    let (made, worn) = duplicate(primary, 2, Some(2));
    if opened != 0 || made != 0 {
        return Err("no token to impersonate with");
    }
    let token = token_of(worn);
    let verdict = (|| {
        if wear(worn, 4) != LENGTH_MISMATCH || wear(primary, 8) != BAD_TOKEN_TYPE {
            return Err("half a handle, or a primary token, was taken on");
        }
        if !wearing().0.is_null() {
            return Err("a refused token was taken on");
        }
        if wear(worn, 8) != 0 || wearing() != (token, 0, 0, 2) {
            return Err("the thread does not wear the token it took on, at its level");
        }
        // The thread's subject now has a client beside the process.
        let mut subject: SECURITY_SUBJECT_CONTEXT = dirty();
        let subject = &raw mut subject;
        // SAFETY: a local, captured for as long as it is used.
        let (captured, regions) = unsafe {
            SeCaptureSubjectContext(subject);
            let captured = subject.read();
            SeLockSubjectContext(subject);
            let regions = crate::ke::thread::object_field::<i16>(
                crate::ke::thread::current(),
                nk_ntabi::thread::KERNEL_APC_DISABLE,
            )
            .read();
            SeUnlockSubjectContext(subject);
            SeReleaseSubjectContext(subject);
            (captured, regions)
        };
        let system = process::reference_primary_token();
        // SAFETY: the reference just taken.
        unsafe { object::dereference(system) };
        if captured.ClientToken != token
            || captured.ImpersonationLevel != 2
            || captured.PrimaryToken != system.cast()
        {
            return Err("a captured subject does not have the thread's client token");
        }
        if regions != -2 || KeAreApcsDisabled() != 0 {
            return Err("locking a subject with a client is not two critical regions");
        }
        // Opened, the thread's token is that token itself.
        let (status, opened) = open_thread_token();
        let same = token_of(opened) == token && brief(opened) == (2, 2);
        crate::ps::ZwClose(opened);
        if status != 0 || !same {
            return Err("the thread's token, opened, is not the token it wears");
        }
        // Another token in its place; then nobody, twice.
        let (made, other) = duplicate(primary, 2, Some(1));
        let replaced = made == 0 && wear(other, 8) == 0 && wearing() == (token_of(other), 0, 0, 1);
        crate::ps::ZwClose(other);
        if !replaced {
            return Err("a second token did not take the first one's place");
        }
        if wear(core::ptr::null_mut(), 8) != 0
            || !wearing().0.is_null()
            || wear(core::ptr::null_mut(), 8) != 0
        {
            return Err("the thread did not put its token off");
        }
        // Left on: the thread ends wearing it, and its end lets it go.
        if wear(worn, 8) != 0 {
            return Err("the token was not taken on again");
        }
        Ok(())
    })();
    crate::ps::ZwClose(worn);
    crate::ps::ZwClose(primary);
    verdict
}

/// Run `test` on a thread made for it and wait for the thread to end
/// and be freed: whatever it left on itself goes with it.
fn on_a_thread(test: fn() -> Result<(), &'static str>) -> Result<(), &'static str> {
    struct Job {
        test: fn() -> Result<(), &'static str>,
        verdict: Result<(), &'static str>,
    }
    fn run(job: usize) {
        let job = job as *mut Job;
        // SAFETY: the creator's local, which it keeps until this
        // thread has ended; nothing else touches it meanwhile.
        unsafe { (&raw mut (*job).verdict).write(((*job).test)()) };
    }
    let mut job = Job {
        test,
        verdict: Err("the thread did not run"),
    };
    let before = crate::ke::thread::count();
    let thread = crate::ke::thread::create_referenced(
        run,
        (&raw mut job).addr(),
        crate::ke::thread::NORMAL_PRIORITY,
        crate::ke::thread::ANYWHERE,
    )
    .map_err(|_| "no memory for a thread")?;
    // SAFETY: the thread, referenced until here; the wait is for its
    // end.
    unsafe {
        crate::ke::wait::wait(Some(thread.cast()), None);
        object::dereference(thread.cast());
    }
    // Its last reference, the one it held on itself, goes when the
    // processor it ran on has left its stack.
    while crate::ke::thread::count() != before {
        crate::ke::thread::yield_now();
    }
    job.verdict
}

/// Impersonation on a thread made for it: whatever it has taken on
/// ends with it, and the group's leak check says the token went.
fn impersonation() -> Result<(), &'static str> {
    on_a_thread(impersonating)
}

fn run(r: &mut Report, _: &BootInfo) {
    r.check("se.subject-context", subject_context);
    r.check("se.access-state", access_state);
    r.check("se.access-check", access_check);
    r.check("se.access-check.privileges", access_check_privileges);
    r.check("se.privileges", privileges);
    r.check("se.privileges.append", append_privileges);
    r.check("se.assign", assign_security);
    r.check("se.descriptor-info", descriptor_info);
    r.check("se.token-query", token_query);
    r.check("se.token-handles", token_handles);
    r.check("se.impersonation", impersonation);
}
