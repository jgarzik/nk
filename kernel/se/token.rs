//! Access tokens as objects, and what an open carries about its
//! requestor: the subject's security context and the access state.
//!
//! A token object's body is an `nk_se::token::Token`, NK's own layout:
//! drivers treat `TOKEN` as opaque and ask about it through routines.
//! The subject context and the access state are Windows' structures
//! (`nk_ntabi::se`): a file system is handed them and reads them in
//! line, so they are filled in through raw pointers, field by field.
//!
//! There is one token, the System process's, and no impersonation: a
//! captured subject is always that token.

use crate::ob::object;
use crate::ps::process;
use core::ffi::c_void;
use core::sync::atomic::{AtomicU64, Ordering};
use nk_ntabi::se::{ACCESS_STATE, LUID, SECURITY_SUBJECT_CONTEXT, TOKEN_HAS_TRAVERSE_PRIVILEGE};
use nk_se::token::{SE_CHANGE_NOTIFY_PRIVILEGE, Token};

/// The next locally unique identifier. Windows keeps the values below
/// 1000 for well-known ones (`SYSTEM_LUID` is 999).
static NEXT_LUID: AtomicU64 = AtomicU64::new(1000);

/// A number no other call returns until the machine stops: what names
/// a token, a change to one, or an open in progress.
pub fn allocate_luid() -> u64 {
    NEXT_LUID.fetch_add(1, Ordering::Relaxed)
}

/// A token object holding `token`, with one reference: the caller's.
/// The token is given its own id and modification id.
pub fn create(mut token: Token) -> Option<*mut u8> {
    token.token_id = allocate_luid();
    token.modified_id = allocate_luid();
    let body = object::create(&object::TOKEN_TYPE, size_of::<Token>())?;
    // SAFETY: a fresh object of a token's size, which the pool aligns
    // to 16 bytes; nothing else has it yet.
    unsafe { body.cast::<Token>().write(token) };
    Some(body)
}

/// The object manager's call when the last reference to a token has
/// gone: free what the token holds.
///
/// # Safety
/// `body` is a token object nothing refers to any more.
pub unsafe extern "C" fn deleted(body: *mut c_void) {
    // SAFETY: per the contract; `create` wrote a token there.
    unsafe { body.cast::<Token>().drop_in_place() };
}

/// The token in a token object.
///
/// # Safety
/// `body` is a token object the caller holds a reference to for as long
/// as it uses the result. No driver can write a token: its layout is
/// NK's own, and nothing but this module changes one.
pub unsafe fn of<'a>(body: *mut u8) -> &'a Token {
    // SAFETY: per the contract.
    unsafe { &*body.cast::<Token>() }
}

/// Record who the calling thread acts as, what
/// [`SeCaptureSubjectContext`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-secapturesubjectcontext)
/// does: no client token (no thread impersonates), the process's
/// primary token, referenced until [`release_subject_context`], and the
/// process's id for auditing.
///
/// # Safety
/// `context` is writable for a `SECURITY_SUBJECT_CONTEXT`.
pub unsafe fn capture_subject_context(context: *mut SECURITY_SUBJECT_CONTEXT) {
    // SAFETY: per the contract.
    unsafe {
        (&raw mut (*context).ClientToken).write(core::ptr::null_mut());
        (&raw mut (*context).ImpersonationLevel).write(nk_se::token::SECURITY_ANONYMOUS);
        (&raw mut (*context).PrimaryToken).write(process::reference_primary_token().cast());
        (&raw mut (*context).ProcessAuditId)
            .write(nk_ntabi::process::SYSTEM_PROCESS_ID as *mut c_void);
    }
}

/// Give up what [`capture_subject_context`] took: the reference on the
/// primary token.
///
/// # Safety
/// `context` was filled in by `capture_subject_context` and not
/// released since.
pub unsafe fn release_subject_context(context: *mut SECURITY_SUBJECT_CONTEXT) {
    // SAFETY: per the contract: the token is the one referenced there.
    unsafe {
        let token = (&raw const (*context).PrimaryToken).read();
        (&raw mut (*context).PrimaryToken).write(core::ptr::null_mut());
        object::dereference(token.cast());
    }
}

/// Set up the access state of an open that asks for `desired` access,
/// as `SeCreateAccessState` does: the subject captured, an operation id
/// of its own, everything asked for still to be granted (generic
/// rights as given: the type being opened maps them), and whether the
/// subject may pass through directories without a check. No security
/// descriptor, no auxiliary data, no privileges used, no names.
///
/// # Safety
/// `state` is writable for an `ACCESS_STATE`.
pub unsafe fn create_access_state(state: *mut ACCESS_STATE, desired: u32) {
    let id = allocate_luid();
    // SAFETY: per the contract; the token is referenced by the subject
    // context captured into the state.
    unsafe {
        state.write_bytes(0, 1);
        let subject = &raw mut (*state).SubjectSecurityContext;
        capture_subject_context(subject);
        let token = of((&raw const (*subject).PrimaryToken).read().cast());
        (&raw mut (*state).OperationID).write(LUID {
            LowPart: id as u32,
            HighPart: (id >> 32) as i32,
        });
        (&raw mut (*state).RemainingDesiredAccess).write(desired);
        (&raw mut (*state).OriginalDesiredAccess).write(desired);
        if token.privilege_enabled(SE_CHANGE_NOTIFY_PRIVILEGE) {
            (&raw mut (*state).Flags).write(TOKEN_HAS_TRAVERSE_PRIVILEGE);
        }
    }
}

/// End an access state from [`create_access_state`]: release its
/// subject (`SeDeleteAccessState`).
///
/// # Safety
/// `state` was set up by `create_access_state` and not deleted since.
pub unsafe fn delete_access_state(state: *mut ACCESS_STATE) {
    // SAFETY: per the contract.
    unsafe { release_subject_context(&raw mut (*state).SubjectSecurityContext) };
}

// ---- tests --------------------------------------------------------------

/// How many references an object has, the caller's own included.
///
/// # Safety
/// `body` is an object the caller holds a reference to.
unsafe fn references(body: *mut u8) -> i64 {
    // SAFETY: per the contract.
    unsafe {
        let count = object::reference(body) - 1;
        object::dereference(body);
        count
    }
}

/// The System process's token, found the way a binary finds it.
pub fn token_test() -> Result<(), &'static str> {
    use nk_ntabi::process::{FAST_REF_COUNT_MASK, TOKEN};
    // SAFETY: the System process lives for ever, and holds its token.
    unsafe {
        let field = process::system().add(TOKEN).cast::<usize>().read();
        if field == 0 || field & FAST_REF_COUNT_MASK != 0 {
            return Err("the System process's token field is not a pointer with a zero count");
        }
        let body = field as *mut u8;
        if !core::ptr::eq(object::type_of(body), &raw const object::TOKEN_TYPE) {
            return Err("the System process's token is not a token object");
        }
        let token = of(body);
        if token.user.sid != nk_se::token::LOCAL_SYSTEM || token.user.attributes != 0 {
            return Err("the System token's user is not S-1-5-18");
        }
        if token.token_type != nk_se::token::TokenType::Primary
            || token.authentication_id != nk_se::token::SYSTEM_LUID
            || token.session_id != 0
        {
            return Err("the System token is not the system logon's primary token");
        }
        if token.token_id < 1000 || token.modified_id <= token.token_id {
            return Err("the System token was not given ids of its own");
        }
        let before = references(body);
        let referenced = process::reference_primary_token();
        if referenced != body || references(body) != before + 1 {
            return Err("referencing the primary token did not reference the System token");
        }
        object::dereference(referenced);
    }
    Ok(())
}

/// A captured subject and a new access state hold what a file system
/// reads from them.
pub fn access_state_test() -> Result<(), &'static str> {
    /// `GENERIC_READ` and a specific right.
    const DESIRED: u32 = 0x8000_0001;
    // SAFETY: an all-zero state is valid (integers and null pointers).
    let mut states: [ACCESS_STATE; 2] = unsafe { core::mem::zeroed() };
    let [first, second] = [&raw mut states[0], &raw mut states[1]];
    // SAFETY: locals that outlive the calls; the token outlives all.
    unsafe {
        let token = process::reference_primary_token();
        let before = references(token);

        let subject = &raw mut (*first).SubjectSecurityContext;
        capture_subject_context(subject);
        let captured = (
            (*subject).ClientToken,
            (*subject).ImpersonationLevel,
            (*subject).PrimaryToken,
            (*subject).ProcessAuditId as u64,
        );
        let held = references(token);
        release_subject_context(subject);
        if captured != (core::ptr::null_mut(), 0, token.cast(), 4) {
            object::dereference(token);
            return Err("a captured subject is not the System process acting as itself");
        }
        if held != before + 1 || references(token) != before {
            object::dereference(token);
            return Err("a captured subject did not hold its token exactly until released");
        }

        // Dirty memory: everything not stated must come out zero.
        first
            .cast::<u8>()
            .write_bytes(0xA5, size_of::<ACCESS_STATE>());
        create_access_state(first, DESIRED);
        create_access_state(second, 0);
        let held = references(token);
        let verdict = (|| {
            let state = &*first.cast_const();
            if state.RemainingDesiredAccess != DESIRED
                || state.OriginalDesiredAccess != DESIRED
                || state.PreviouslyGrantedAccess != 0
            {
                return Err("a new access state does not hold the access asked for, as asked");
            }
            if state.Flags != TOKEN_HAS_TRAVERSE_PRIVILEGE {
                return Err("the System token's right to traverse is not in the access state");
            }
            let subject = &state.SubjectSecurityContext;
            if subject.PrimaryToken != token.cast()
                || !subject.ClientToken.is_null()
                || subject.ProcessAuditId as u64 != 4
            {
                return Err("a new access state's subject is not the caller");
            }
            let id = |state: *const ACCESS_STATE| {
                ((*state).OperationID.LowPart, (*state).OperationID.HighPart)
            };
            if id(first) == (0, 0) || id(first) == id(second) {
                return Err("two access states share an operation id");
            }
            let quiet = state.SecurityEvaluated == 0
                && state.GenerateAudit == 0
                && state.GenerateOnClose == 0
                && state.PrivilegesAllocated == 0
                && state.AuditPrivileges == 0
                && state.SecurityDescriptor.is_null()
                && state.AuxData.is_null()
                && state.Privileges == [0; 11]
                && state.ObjectName.Length == 0
                && state.ObjectName.Buffer.is_null()
                && state.ObjectTypeName.Length == 0
                && state.ObjectTypeName.Buffer.is_null();
            if !quiet {
                return Err("a new access state holds something nobody put there");
            }
            Ok(())
        })();
        delete_access_state(first);
        delete_access_state(second);
        let after = references(token);
        object::dereference(token);
        verdict?;
        if held != before + 2 || after != before {
            return Err("an access state did not hold its token exactly until deleted");
        }
    }
    Ok(())
}
