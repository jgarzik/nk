//! Access tokens as objects, and what an open carries about its
//! requestor: the subject's security context and the access state.
//!
//! A token object's body is an `nk_se::token::Token`, NK's own layout:
//! drivers treat `TOKEN` as opaque and ask about it through routines.
//! The subject context and the access state are Windows' structures
//! (`nk_ntabi::se`): a file system is handed them and reads them in
//! line, so they are filled in through raw pointers, field by field.
//!
//! A token never changes once it is made: nothing NK exports adjusts
//! one. So a token needs no lock of its own, and "locking" a subject
//! (`SeLockSubjectContext`) is what is left of Windows' routine when
//! the token lock cannot be contended: a critical region per token.

use crate::ke::mutex::{KeEnterCriticalRegion, KeLeaveCriticalRegion};
use crate::mm::pool;
use crate::ob::object;
use crate::ps::process;
use core::ffi::c_void;
use core::sync::atomic::{AtomicU64, Ordering};
use nk_ntabi::ob::GENERIC_MAPPING;
use nk_ntabi::process::UNIQUE_PROCESS_ID;
use nk_ntabi::se::{
    ACCESS_STATE, AUX_ACCESS_DATA, LUID, SECURITY_SUBJECT_CONTEXT, TOKEN_HAS_TRAVERSE_PRIVILEGE,
};
use nk_ntabi::status::*;
use nk_se::information::{Information, QueryError, token_information};
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
/// NK's own, and nothing changes one after `create`.
pub unsafe fn of<'a>(body: *mut u8) -> &'a Token {
    // SAFETY: per the contract.
    unsafe { &*body.cast::<Token>() }
}

/// The two tokens of a subject context: the client's (null when the
/// thread impersonated nobody) and the primary.
///
/// # Safety
/// `context` is readable for a `SECURITY_SUBJECT_CONTEXT`.
unsafe fn tokens(context: *const SECURITY_SUBJECT_CONTEXT) -> (*mut u8, *mut u8) {
    // SAFETY: per the contract.
    unsafe {
        (
            (&raw const (*context).ClientToken).read().cast(),
            (&raw const (*context).PrimaryToken).read().cast(),
        )
    }
}

/// The token a captured subject acts with: the client's if it has one,
/// else the primary.
///
/// # Safety
/// `context` is a captured subject context, not released: its tokens
/// are referenced for as long as the result is used.
pub unsafe fn effective<'a>(context: *const SECURITY_SUBJECT_CONTEXT) -> &'a Token {
    // SAFETY: per the contract.
    unsafe {
        let (client, primary) = tokens(context);
        of(if client.is_null() { primary } else { client })
    }
}

/// [`SeCaptureSubjectContext`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-secapturesubjectcontext):
/// record who the calling thread acts as: its process's primary token,
/// referenced until [`SeReleaseSubjectContext`], and the process's id
/// for auditing. No thread has a client token, and as on Windows
/// `ImpersonationLevel` is then left as the caller had it.
///
/// # Safety
/// `context` is writable for a `SECURITY_SUBJECT_CONTEXT`.
pub unsafe extern "C" fn SeCaptureSubjectContext(context: *mut SECURITY_SUBJECT_CONTEXT) {
    let current = process::PsGetCurrentProcess();
    // SAFETY: per the contract; the current process is a live process
    // object, whose id is at a pointer-aligned offset.
    unsafe {
        let id = current
            .cast::<u8>()
            .add(UNIQUE_PROCESS_ID)
            .cast::<*mut c_void>()
            .read();
        (&raw mut (*context).ProcessAuditId).write(id);
        (&raw mut (*context).ClientToken).write(core::ptr::null_mut());
        (&raw mut (*context).PrimaryToken).write(process::PsReferencePrimaryToken(current));
    }
}

/// [`SeReleaseSubjectContext`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-sereleasesubjectcontext):
/// give up the references a capture took, and forget the tokens.
///
/// # Safety
/// `context` was filled in by [`SeCaptureSubjectContext`] and not
/// released since.
pub unsafe extern "C" fn SeReleaseSubjectContext(context: *mut SECURITY_SUBJECT_CONTEXT) {
    // SAFETY: per the contract: the tokens are the ones referenced
    // there.
    unsafe {
        let (client, primary) = tokens(context);
        (&raw mut (*context).PrimaryToken).write(core::ptr::null_mut());
        (&raw mut (*context).ClientToken).write(core::ptr::null_mut());
        object::dereference(primary);
        if !client.is_null() {
            object::dereference(client);
        }
    }
}

/// [`SeLockSubjectContext`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-selocksubjectcontext):
/// keep the subject's tokens from changing. Windows enters a critical
/// region and takes the token's lock shared, for the primary token and
/// again for a client token. NK's tokens never change, so the critical
/// regions are all there is to it; a driver sees them
/// (`KeAreApcsDisabled`).
///
/// # Safety
/// `context` is a captured subject context.
pub unsafe extern "C" fn SeLockSubjectContext(context: *mut SECURITY_SUBJECT_CONTEXT) {
    KeEnterCriticalRegion();
    // SAFETY: per the contract.
    if !unsafe { tokens(context) }.0.is_null() {
        KeEnterCriticalRegion();
    }
}

/// [`SeUnlockSubjectContext`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-seunlocksubjectcontext):
/// undo [`SeLockSubjectContext`].
///
/// # Safety
/// `context` is a captured subject context the calling thread locked.
pub unsafe extern "C" fn SeUnlockSubjectContext(context: *mut SECURITY_SUBJECT_CONTEXT) {
    KeLeaveCriticalRegion();
    // SAFETY: per the contract.
    if !unsafe { tokens(context) }.0.is_null() {
        KeLeaveCriticalRegion();
    }
}

/// `SeCreateAccessState` (`ntifs.h` names it; Microsoft's file systems
/// call it): set up the access state of an open that asks for `desired`
/// access, in the caller's `state` and `aux`. As Windows fills them:
/// both zeroed; generic rights mapped when a mapping is given, which is
/// also kept in `aux`; everything asked for still to be granted, and
/// remembered as asked; the calling thread's subject captured; an
/// operation id of its own; the traverse flag when the subject's token
/// holds `SeChangeNotifyPrivilege` enabled; the privileges used so far
/// (none) kept in the state's own set, which `aux` points to.
///
/// # Safety
/// `state` is writable for an `ACCESS_STATE` and `aux` for an
/// `AUX_ACCESS_DATA`; `mapping` is null or points to a mapping.
pub unsafe extern "C" fn SeCreateAccessState(
    state: *mut ACCESS_STATE,
    aux: *mut AUX_ACCESS_DATA,
    desired: u32,
    mapping: *const GENERIC_MAPPING,
) -> NTSTATUS {
    let id = allocate_luid();
    // SAFETY: per the contract; the tokens are referenced by the
    // subject context captured into the state.
    unsafe {
        let mapping = (!mapping.is_null()).then(|| mapping.read_unaligned());
        let desired = match mapping {
            Some(mapping) => nk_se::access::map_generic(
                desired,
                &nk_se::access::GenericMapping {
                    read: mapping.GenericRead,
                    write: mapping.GenericWrite,
                    execute: mapping.GenericExecute,
                    all: mapping.GenericAll,
                },
            ),
            None => desired,
        };
        state.write_bytes(0, 1);
        aux.write_bytes(0, 1);
        (&raw mut (*state).AuxData).write(aux.cast());
        let subject = &raw mut (*state).SubjectSecurityContext;
        SeCaptureSubjectContext(subject);
        if effective(subject).privilege_enabled(SE_CHANGE_NOTIFY_PRIVILEGE) {
            (&raw mut (*state).Flags).write(TOKEN_HAS_TRAVERSE_PRIVILEGE);
        }
        (&raw mut (*state).RemainingDesiredAccess).write(desired);
        (&raw mut (*state).OriginalDesiredAccess).write(desired);
        (&raw mut (*aux).PrivilegesUsed).write((&raw mut (*state).Privileges).cast());
        (&raw mut (*state).OperationID).write(LUID {
            LowPart: id as u32,
            HighPart: (id >> 32) as i32,
        });
        if let Some(mapping) = mapping {
            (&raw mut (*aux).GenericMapping).write(mapping);
        }
    }
    STATUS_SUCCESS
}

/// `SeDeleteAccessState`: end an access state from
/// [`SeCreateAccessState`]. What the open collected in the pool goes
/// back to it: a privilege set that outgrew the state's own, the
/// object's name and its type's name, a new object's security
/// descriptor nobody took. Then the subject is released.
///
/// # Safety
/// `state` was set up by `SeCreateAccessState` and not deleted since;
/// what it points to is as the routines that fill it left it.
pub unsafe extern "C" fn SeDeleteAccessState(state: *mut ACCESS_STATE) {
    // SAFETY: per the contract: each pointer is null or a pool block
    // the state owns.
    unsafe {
        let aux = (&raw const (*state).AuxData)
            .read()
            .cast::<AUX_ACCESS_DATA>();
        if (&raw const (*state).PrivilegesAllocated).read() != 0 {
            pool::ExFreePoolWithTag((&raw const (*aux).PrivilegesUsed).read().cast(), 0);
        }
        for name in [
            &raw const (*state).ObjectName,
            &raw const (*state).ObjectTypeName,
        ] {
            let buffer = (&raw const (*name).Buffer).read();
            if !buffer.is_null() {
                pool::ExFreePoolWithTag(buffer.cast(), 0);
            }
        }
        if !aux.is_null() {
            let new = &raw mut (*aux).NewSecurityDescriptor;
            if !new.read().is_null() {
                pool::ExFreePoolWithTag(new.read(), 0);
                new.write(core::ptr::null_mut());
            }
        }
        SeReleaseSubjectContext(&raw mut (*state).SubjectSecurityContext);
    }
}

/// Pool tag of what a token query hands out, Windows' own (`Se  `).
const TAG_INFORMATION: u32 = u32::from_le_bytes(*b"Se  ");

/// [`SeTokenType`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-setokentype):
/// whether a token is a primary token (1) or an impersonation token
/// (2).
///
/// # Safety
/// `token` is a token object the caller holds a reference to.
pub unsafe extern "C" fn SeTokenType(token: *mut c_void) -> u32 {
    // SAFETY: per the contract.
    unsafe { of(token.cast()) }.token_type as u32
}

/// [`SeQueryInformationToken`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-sequeryinformationtoken):
/// what a token answers for `class` (`nk_se::information`). Most
/// classes come back in a pool block the caller frees with
/// `ExFreePool`, whose address `*information` receives; the session
/// id, the integrity level and "is an app container" are 32-bit values
/// written where that address would go, as on Windows. A class NK does
/// not answer, and the impersonation level of a primary token, fail
/// with `STATUS_INVALID_INFO_CLASS` and write nothing.
///
/// # Safety
/// `token` is a token object the caller holds a reference to;
/// `information` is writable for a pointer.
pub unsafe extern "C" fn SeQueryInformationToken(
    token: *mut c_void,
    class: u32,
    information: *mut *mut c_void,
) -> NTSTATUS {
    // SAFETY: per the contract.
    unsafe {
        let token = of(token.cast());
        // Once for the length, then again with the address the block
        // has: its pointers are made from it.
        let length = match token_information(token, class, 0) {
            Ok(Information::Value(value)) => {
                information.cast::<u32>().write_unaligned(value);
                return STATUS_SUCCESS;
            }
            Ok(Information::Block(block)) => block.len(),
            Err(QueryError::InvalidInfoClass) => return STATUS_INVALID_INFO_CLASS,
        };
        let block = pool::alloc(length, TAG_INFORMATION);
        if block.is_null() {
            return STATUS_INSUFFICIENT_RESOURCES;
        }
        match token_information(token, class, block as u64) {
            Ok(Information::Block(bytes)) if bytes.len() == length => {
                block.copy_from_nonoverlapping(bytes.as_ptr(), length);
                information.write_unaligned(block.cast());
                STATUS_SUCCESS
            }
            // A token does not change between the two questions.
            _ => crate::kd::bugcheck(format_args!(
                "a token answered a query differently the second time"
            )),
        }
    }
}

// ---- tests --------------------------------------------------------------

/// How many references an object has, the caller's own included.
///
/// # Safety
/// `body` is an object the caller holds a reference to.
pub unsafe fn references(body: *mut u8) -> i64 {
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
