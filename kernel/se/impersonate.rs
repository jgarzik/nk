//! Impersonation: the token a thread acts with in place of its
//! process's.
//!
//! A thread keeps it where Windows does, because Microsoft's drivers
//! are built against the thread's layout: `ETHREAD.ClientSecurity` is
//! the token's address with the impersonation level in its low two
//! bits and "effective only" in the third, and two bits of
//! `CrossThreadFlags` say that the thread impersonates and that
//! opening its token copies it (`nk_ntabi::thread`). The thread holds
//! a reference to the token for as long as it names it, and gives it
//! up when it stops impersonating or is freed.
//!
//! Any thread may ask about, or change, another's: all of it happens
//! under one lock (`IMPERSONATION`, `doc/LOCKING.md`), so the token a
//! thread names is referenced before the thread can let go of it.
//!
//! Windows asks whether a process may impersonate a given token at a
//! given level (`SeImpersonatePrivilege`, among other things) and
//! lowers the level if not. Every thread here belongs to the System
//! process, whose token holds that privilege: nothing is lowered.

use super::{token, zwtoken};
use crate::ke::thread::{self, Thread};
use crate::ke::{Rank, SpinLock};
use crate::ob::{handle, object};
use core::ffi::c_void;
use core::sync::atomic::{AtomicU32, Ordering};
use nk_ntabi::status::*;
use nk_ntabi::thread::{
    ACTIVE_IMPERSONATION_INFO, CLIENT_SECURITY, COPY_TOKEN_ON_OPEN, CROSS_THREAD_FLAGS,
};
use nk_ob::handles::Mode;
use nk_se::token::{SECURITY_ANONYMOUS, TokenType};

/// Guards every thread's `ClientSecurity` and its two flags.
static IMPERSONATION: SpinLock<()> = SpinLock::new(Rank::Impersonation, ());

/// The bits of `ClientSecurity` that are not the token's address: the
/// level, and "effective only".
const LEVEL: usize = 0x3;
const EFFECTIVE_ONLY: usize = 0x4;
const NOT_TOKEN: usize = 0x7;

/// How a thread impersonates.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Impersonation {
    /// The token object.
    pub token: *mut u8,
    /// A `SECURITY_IMPERSONATION_LEVEL`.
    pub level: u32,
    pub effective_only: bool,
    /// Whether opening the thread's token hands out a copy.
    pub copy_on_open: bool,
}

fn client_security(thread: *mut Thread) -> *mut usize {
    thread::object_field(thread, CLIENT_SECURITY)
}

/// # Safety
/// `thread` is a live thread.
unsafe fn flags<'a>(thread: *mut Thread) -> &'a AtomicU32 {
    // SAFETY: per the contract: an aligned 32-bit field of its block,
    // changed by atomic operations only.
    unsafe { AtomicU32::from_ptr(thread::object_field(thread, CROSS_THREAD_FLAGS)) }
}

/// What `thread` impersonates, if anything. The caller holds the lock.
///
/// # Safety
/// `thread` is a live thread.
unsafe fn current(thread: *mut Thread) -> Option<Impersonation> {
    // SAFETY: per the contract; the word is the lock's.
    unsafe {
        let bits = flags(thread).load(Ordering::Acquire);
        if bits & ACTIVE_IMPERSONATION_INFO == 0 {
            return None;
        }
        let word = client_security(thread).read();
        Some(Impersonation {
            token: (word & !NOT_TOKEN) as *mut u8,
            level: (word & LEVEL) as u32,
            effective_only: word & EFFECTIVE_ONLY != 0,
            copy_on_open: bits & COPY_TOKEN_ON_OPEN != 0,
        })
    }
}

/// What `thread` impersonates, with a reference to the token for the
/// caller to give up; `None` if it impersonates nobody.
///
/// # Safety
/// `thread` is a thread the caller holds a reference to, or the
/// running thread.
pub unsafe fn reference(thread: *mut Thread) -> Option<Impersonation> {
    let _lock = IMPERSONATION.lock();
    // SAFETY: per the contract. The thread's own reference keeps the
    // token alive while the lock is held.
    unsafe {
        let found = current(thread)?;
        object::reference(found.token);
        Some(found)
    }
}

/// Make `thread` impersonate as `new` says (the thread takes a
/// reference of its own on the token), or nobody. What it impersonated
/// before is let go.
///
/// # Safety
/// `thread` is a thread the caller holds a reference to, or the
/// running thread; `new.token` is a token object the caller holds a
/// reference to.
pub unsafe fn set(thread: *mut Thread, new: Option<Impersonation>) {
    // SAFETY: per the contract.
    let old = unsafe {
        if let Some(new) = new {
            object::reference(new.token);
        }
        let _lock = IMPERSONATION.lock();
        let old = current(thread);
        let bits = flags(thread);
        match new {
            Some(new) => {
                client_security(thread).write(
                    new.token.addr()
                        | new.level as usize & LEVEL
                        | if new.effective_only {
                            EFFECTIVE_ONLY
                        } else {
                            0
                        },
                );
                if new.copy_on_open {
                    bits.fetch_or(COPY_TOKEN_ON_OPEN, Ordering::AcqRel);
                } else {
                    bits.fetch_and(!COPY_TOKEN_ON_OPEN, Ordering::AcqRel);
                }
                bits.fetch_or(ACTIVE_IMPERSONATION_INFO, Ordering::AcqRel);
            }
            None => {
                bits.fetch_and(!ACTIVE_IMPERSONATION_INFO, Ordering::AcqRel);
            }
        }
        old
    };
    // Outside the lock: the last reference frees the token.
    if let Some(old) = old {
        // SAFETY: the reference the thread held.
        unsafe { object::dereference(old.token) };
    }
}

/// The object manager's call when the last reference to a thread has
/// gone: the thread lets go of the token it still impersonated.
///
/// # Safety
/// `body` is a thread object nothing refers to any more.
pub unsafe extern "C" fn thread_deleted(body: *mut c_void) {
    // SAFETY: per the contract: nothing else can reach the thread, so
    // no lock is needed to read what it names.
    unsafe {
        if let Some(left) = current(body.cast()) {
            object::dereference(left.token);
        }
    }
}

/// [`PsReferenceImpersonationToken`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-psreferenceimpersonationtoken):
/// the token `thread` impersonates, with a reference the caller gives
/// up through [`PsDereferenceImpersonationToken`], and how it
/// impersonates. Null, with nothing written, if it impersonates
/// nobody: so Windows.
///
/// # Safety
/// `thread` is a thread the caller holds a reference to, or the
/// running thread; the three results are writable.
pub unsafe extern "C" fn PsReferenceImpersonationToken(
    thread: *mut c_void,
    copy_on_open: *mut u8,
    effective_only: *mut u8,
    level: *mut u32,
) -> *mut c_void {
    // SAFETY: per the contract.
    unsafe {
        let Some(found) = reference(thread.cast()) else {
            return core::ptr::null_mut();
        };
        copy_on_open.write(u8::from(found.copy_on_open));
        effective_only.write(u8::from(found.effective_only));
        level.write_unaligned(found.level);
        found.token.cast()
    }
}

/// [`PsDereferenceImpersonationToken`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-psdereferenceimpersonationtoken):
/// give up a reference [`PsReferenceImpersonationToken`] took; null is
/// nothing to give up.
///
/// # Safety
/// `token` is null or a token the caller holds a reference to.
pub unsafe extern "C" fn PsDereferenceImpersonationToken(token: *mut c_void) {
    if !token.is_null() {
        // SAFETY: per the contract.
        unsafe { object::dereference(token.cast()) };
    }
}

/// `ThreadImpersonationToken` of `ZwSetInformationThread`: make
/// `thread` impersonate with the token a handle names, or nobody for a
/// null handle. The token must be an impersonation token
/// (`STATUS_BAD_TOKEN_TYPE`); the thread impersonates at the token's
/// own level, and opening the thread's token then opens that token
/// itself.
///
/// # Safety
/// `thread` is a thread the caller holds a reference to.
pub unsafe fn set_thread_impersonation_token(
    thread: *mut Thread,
    token_handle: *mut c_void,
) -> NTSTATUS {
    // SAFETY: per the contract; the token is referenced from the
    // look-up to the last line.
    unsafe {
        if token_handle.is_null() {
            set(thread, None);
            return STATUS_SUCCESS;
        }
        let found = handle::reference(token_handle as u64, Some(&raw const object::TOKEN_TYPE));
        let body = match found {
            Ok(body) => body,
            Err(status) => return status,
        };
        let its = token::of(body);
        let status = if its.token_type == TokenType::Impersonation {
            let new = Impersonation {
                token: body,
                level: its.impersonation_level,
                effective_only: false,
                copy_on_open: false,
            };
            set(thread, Some(new));
            STATUS_SUCCESS
        } else {
            STATUS_BAD_TOKEN_TYPE
        };
        object::dereference(body);
        status
    }
}

/// [`ZwOpenThreadTokenEx`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-zwopenthreadtokenex):
/// a handle to the token the thread a handle names impersonates.
/// `STATUS_NO_TOKEN` if it impersonates nobody, and
/// `STATUS_CANT_OPEN_ANONYMOUS` if at the anonymous level; neither
/// writes the caller's handle. A thread whose token is copied on open
/// gets a handle to a new impersonation token at the thread's level.
///
/// `OpenAsSelf` chooses whose security the access check of the open is
/// made with. An open by kernel mode is not checked, so it changes
/// nothing here.
///
/// # Safety
/// `token_handle` is writable for a handle.
pub unsafe extern "C" fn ZwOpenThreadTokenEx(
    thread_handle: *mut c_void,
    desired_access: u32,
    _open_as_self: u8,
    handle_attributes: u32,
    token_handle: *mut *mut c_void,
) -> NTSTATUS {
    let found = handle::reference_for(
        thread_handle as u64,
        Some(&raw const object::THREAD_TYPE),
        0,
        Mode::Kernel,
    );
    let thread = match found {
        Ok((thread, _)) => thread,
        Err(status) => return status,
    };
    // SAFETY: per the contract; the thread is referenced until the
    // last line, the token by `reference` until it is given up here.
    unsafe {
        let status = match reference(thread.cast()) {
            None => STATUS_NO_TOKEN,
            Some(worn) => {
                let status = if worn.level == SECURITY_ANONYMOUS {
                    STATUS_CANT_OPEN_ANONYMOUS
                } else if worn.copy_on_open {
                    let copy = token::duplicate(
                        worn.token,
                        TokenType::Impersonation,
                        worn.level,
                        worn.effective_only,
                    );
                    match copy {
                        None => STATUS_INSUFFICIENT_RESOURCES,
                        Some(copy) => {
                            let status = zwtoken::open(
                                copy,
                                desired_access,
                                handle_attributes,
                                token_handle,
                            );
                            object::dereference(copy);
                            status
                        }
                    }
                } else {
                    zwtoken::open(worn.token, desired_access, handle_attributes, token_handle)
                };
                object::dereference(worn.token);
                status
            }
        };
        object::dereference(thread);
        status
    }
}
