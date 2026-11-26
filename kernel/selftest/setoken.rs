//! Tests of tokens, subjects and access checks through the routines
//! drivers call: each test makes the calls a driver makes, with the
//! driver's own structures, and reads back what a driver would read.

use crate::ke::mutex::KeAreApcsDisabled;
use crate::mm::pool;
use crate::ob::object;
use crate::ps::process;
use crate::se::token::*;
use crate::test::{Group, Report};
use nk_bootinfo::BootInfo;
use nk_ntabi::io::FILE_GENERIC_MAPPING;
use nk_ntabi::se::{
    ACCESS_STATE, AUX_ACCESS_DATA, SECURITY_SUBJECT_CONTEXT, TOKEN_HAS_TRAVERSE_PRIVILEGE,
};

pub static GROUP: Group = Group {
    names: &["se.subject-context", "se.access-state"],
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

fn run(r: &mut Report, _: &BootInfo) {
    r.check("se.subject-context", subject_context);
    r.check("se.access-state", access_state);
}
