//! Tests of tokens, subjects and access checks through the routines
//! drivers call: each test makes the calls a driver makes, with the
//! driver's own structures, and reads back what a driver would read.

use crate::ke::mutex::KeAreApcsDisabled;
use crate::mm::pool;
use crate::ob::object;
use crate::ps::process;
use crate::se::access::*;
use crate::se::token::*;
use crate::test::{Group, Report};
use alloc::vec::Vec;
use core::ffi::c_void;
use nk_bootinfo::BootInfo;
use nk_ntabi::io::FILE_GENERIC_MAPPING;
use nk_ntabi::se::{
    ACCESS_STATE, AUX_ACCESS_DATA, LUID_AND_ATTRIBUTES, PRIVILEGE_SET, SECURITY_DESCRIPTOR,
    SECURITY_SUBJECT_CONTEXT, TOKEN_HAS_TRAVERSE_PRIVILEGE,
};

pub static GROUP: Group = Group {
    names: &[
        "se.subject-context",
        "se.access-state",
        "se.access-check",
        "se.access-check.privileges",
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

fn run(r: &mut Report, _: &BootInfo) {
    r.check("se.subject-context", subject_context);
    r.check("se.access-state", access_state);
    r.check("se.access-check", access_check);
    r.check("se.access-check.privileges", access_check_privileges);
}
