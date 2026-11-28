//! I/O Completion Ports (`IO_COMPLETION_TYPE`): FIFO packet queues supporting
//! `NtCreateIoCompletion`, `NtOpenIoCompletion`, `NtSetIoCompletion(Ex)`,
//! `NtQueryIoCompletion`, and `NtRemoveIoCompletion(Ex)`.

#![allow(non_snake_case)]

use crate::ke::spinlock::{Rank, SpinLock};
use crate::ke::wait;
use crate::ob::{self, handle, object};
use crate::svc::capture;
use alloc::collections::VecDeque;
use core::ffi::c_void;
use core::mem::size_of;
use nk_ntabi::io::IO_STATUS_BLOCK;
use nk_ntabi::ke::KEVENT;
use nk_ntabi::ob::OBJECT_ATTRIBUTES;
use nk_ntabi::status::*;
use nk_ob::handles::Attributes;

const OBJ_INHERIT: u32 = 0x2;
const OBJ_PERMANENT: u32 = 0x10;
const OBJ_OPENIF: u32 = 0x80;
const OBJ_KERNEL_HANDLE: u32 = 0x200;

pub const IO_COMPLETION_QUERY_STATE: u32 = 0x0001;
pub const IO_COMPLETION_MODIFY_STATE: u32 = 0x0002;

/// `FILE_IO_COMPLETION_INFORMATION` (32 bytes): one entry returned by
/// `NtRemoveIoCompletionEx` and `NtWaitForWorkViaWorkerFactory`.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct FileIoCompletionInformation {
    pub key_context: *mut c_void,
    pub apc_context: *mut c_void,
    pub io_status_block: IO_STATUS_BLOCK,
}

/// One queued completion packet.
#[derive(Clone, Copy)]
pub struct Packet {
    pub key: usize,
    pub apc_context: usize,
    pub status: NTSTATUS,
    pub information: usize,
}

/// Body of an `IO_COMPLETION_TYPE` object.
#[repr(C)]
pub struct IoCompletion {
    /// Signaled whenever `queue` is non-empty (`NotificationEvent`).
    ready: KEVENT,
    queue: SpinLock<VecDeque<Packet>>,
    concurrency: u32,
}

/// `IO_COMPLETION_TYPE`'s delete procedure.
///
/// # Safety
/// `body` is a live `IoCompletion` object with zero remaining references.
pub unsafe extern "C" fn deleted(body: *mut c_void) {
    // SAFETY: per the contract; exclusive access during deletion.
    unsafe {
        core::ptr::drop_in_place(body.cast::<IoCompletion>());
    }
}

/// Initialize a freshly allocated `IoCompletion` body.
///
/// # Safety
/// `body` points to zeroed storage of at least `size_of::<IoCompletion>()` bytes.
unsafe fn init_body(body: *mut u8, concurrency: u32) {
    let iocp = body.cast::<IoCompletion>();
    // SAFETY: per the contract.
    unsafe {
        wait::KeInitializeEvent(&raw mut (*iocp).ready, 0 /* NotificationEvent */, 0);
        (&raw mut (*iocp).queue).write(SpinLock::new(Rank::IoCompletion, VecDeque::new()));
        (&raw mut (*iocp).concurrency).write(concurrency);
    }
}

/// Post a completion packet onto `body` (safe at `<= DISPATCH_LEVEL`, e.g.
/// from `NtSetIoCompletion` or `WaitCompletionPacket` firing).
///
/// # Safety
/// `body` is a live `IO_COMPLETION_TYPE` object.
pub unsafe fn post(
    body: *mut u8,
    key: usize,
    apc_context: usize,
    status: NTSTATUS,
    information: usize,
) -> NTSTATUS {
    let iocp = body.cast::<IoCompletion>();
    // SAFETY: per the contract.
    unsafe {
        let mut q = (*iocp).queue.lock();
        if q.try_reserve(1).is_err() {
            return STATUS_INSUFFICIENT_RESOURCES;
        }
        q.push_back(Packet {
            key,
            apc_context,
            status,
            information,
        });
        drop(q);
        // Signal waiters outside `queue` lock (ObjectLock is taken outside ranked locks).
        wait::KeSetEvent(&raw mut (*iocp).ready, 0, 0);
    }
    STATUS_SUCCESS
}

/// Current queue depth of `body`.
///
/// # Safety
/// `body` is a live `IO_COMPLETION_TYPE` object.
pub unsafe fn depth(body: *mut u8) -> u32 {
    let iocp = body.cast::<IoCompletion>();
    // SAFETY: per the contract.
    unsafe { (*iocp).queue.lock().len() as u32 }
}

/// Dequeue up to `out.len()` completion packets from `body`, blocking until
/// at least one packet arrives, `timeout` expires, or an alert/user APC wakes
/// an alertable wait.
///
/// # Safety
/// `body` is a live `IO_COMPLETION_TYPE` object at `PASSIVE_LEVEL`.
pub unsafe fn remove_ex(
    body: *mut u8,
    out: &mut [FileIoCompletionInformation],
    timeout: Option<i64>,
    alertable: bool,
    mode: i8,
) -> Result<usize, NTSTATUS> {
    if out.is_empty() {
        return Err(STATUS_INVALID_PARAMETER);
    }
    let iocp = body.cast::<IoCompletion>();
    let deadline = timeout.map(|due| {
        if due == 0 {
            0i64
        } else {
            nk_ke::wait::deadline(due, crate::ke::time::system_time())
        }
    });
    loop {
        // Fast path: try popping under queue lock.
        let popped = {
            // SAFETY: per the contract.
            let mut q = unsafe { (*iocp).queue.lock() };
            let mut n = 0usize;
            while n < out.len() {
                let Some(pkt) = q.pop_front() else {
                    break;
                };
                out[n] = FileIoCompletionInformation {
                    key_context: core::ptr::with_exposed_provenance_mut(pkt.key),
                    apc_context: core::ptr::with_exposed_provenance_mut(pkt.apc_context),
                    io_status_block: IO_STATUS_BLOCK {
                        Status: pkt.status,
                        Information: pkt.information,
                    },
                };
                n += 1;
            }
            if q.is_empty() {
                drop(q);
                // SAFETY: per the contract; clear `ready` only if still empty to avoid lost wakeups.
                unsafe {
                    wait::KeClearEvent(&raw mut (*iocp).ready);
                    if !(*iocp).queue.lock().is_empty() {
                        wait::KeSetEvent(&raw mut (*iocp).ready, 0, 0);
                    }
                }
            }
            n
        };
        if popped > 0 {
            return Ok(popped);
        }
        if deadline == Some(0) {
            return Err(STATUS_TIMEOUT);
        }
        // Compute remaining timeout as absolute time (or None).
        let wait_due = deadline;
        // SAFETY: `iocp` is live and `ready` is a `KEVENT`.
        let st = unsafe {
            wait::wait_as(
                Some((&raw mut (*iocp).ready).cast()),
                wait_due,
                mode,
                alertable,
            ) as NTSTATUS
        };
        if st != STATUS_SUCCESS {
            return Err(st);
        }
    }
}

/// [`NtCreateIoCompletion`](https://learn.microsoft.com/en-us/windows/win32/devnotes/ntcreateiocompletion).
///
/// # Safety
/// Pointer parameters must satisfy `PreviousMode`.
pub unsafe extern "C" fn NtCreateIoCompletion(
    io_completion_handle: *mut *mut c_void,
    desired_access: u32,
    object_attributes: *const OBJECT_ATTRIBUTES,
    number_of_concurrent_threads: u32,
) -> NTSTATUS {
    let mode = capture::mode();
    // SAFETY: per the contract.
    let oa = match unsafe { capture::capture_object_attributes(object_attributes, mode) } {
        Ok(oa) => oa,
        Err(st) => return st,
    };
    let (root, name, attrs) = match oa {
        Some(a) => (a.root, a.name.unwrap_or_default(), a.attributes),
        None => (core::ptr::null_mut(), alloc::vec::Vec::new(), 0),
    };
    let body = if name.is_empty() {
        object::create(&object::IO_COMPLETION_TYPE, size_of::<IoCompletion>())
    } else {
        object::create_named(
            &object::IO_COMPLETION_TYPE,
            size_of::<IoCompletion>(),
            ob::leaf(&name),
        )
    };
    let Some(body) = body else {
        return STATUS_INSUFFICIENT_RESOURCES;
    };
    // SAFETY: `body` is a fresh `IoCompletion` allocation.
    unsafe { init_body(body, number_of_concurrent_threads) };
    // SAFETY: `body` starts with 1 reference.
    let held = unsafe { object::ObRef::adopt(body) };

    let (target_ref, existed) = if !name.is_empty() {
        let start = match ob::resolve_namespace_root(root, false, mode) {
            Ok(d) => d,
            Err(st) => return st,
        };
        let permanent = (attrs & OBJ_PERMANENT) != 0;
        let open_if = (attrs & OBJ_OPENIF) != 0;
        // SAFETY: `held` is a live `IO_COMPLETION_TYPE` object created with `create_named`.
        match unsafe {
            ob::insert_named(
                start.as_ref().map(object::ObRef::body),
                &name,
                held.body(),
                &object::IO_COMPLETION_TYPE,
                permanent,
                open_if,
            )
        } {
            Ok((found, existed)) => {
                // SAFETY: `insert_named` returned a referenced object; adopt it and drop `held`.
                let adopted = unsafe { object::ObRef::adopt(found) };
                drop(held);
                (adopted, existed)
            }
            Err(st) => return st,
        }
    } else {
        (held, false)
    };

    let kernel_handle = !capture::is_user(mode) || (attrs & OBJ_KERNEL_HANDLE) != 0;
    // SAFETY: `target_ref` keeps the object alive while opening the handle.
    let h = match unsafe {
        handle::open_with(
            target_ref.body(),
            desired_access,
            Attributes {
                inherit: (attrs & OBJ_INHERIT) != 0,
                protect_from_close: false,
            },
            kernel_handle,
        )
    } {
        Ok(h) => h,
        Err(st) => return st,
    };
    // SAFETY: per the contract.
    if let Err(st) = unsafe { capture::write(io_completion_handle, h as *mut c_void, mode) } {
        let _ = handle::close_for(h, capture::handle_mode(mode));
        return st;
    }
    if existed {
        STATUS_OBJECT_NAME_EXISTS
    } else {
        STATUS_SUCCESS
    }
}

/// `NtOpenIoCompletion`: open an existing named I/O completion port.
///
/// # Safety
/// Pointer parameters must satisfy `PreviousMode`.
pub unsafe extern "C" fn NtOpenIoCompletion(
    io_completion_handle: *mut *mut c_void,
    desired_access: u32,
    object_attributes: *const OBJECT_ATTRIBUTES,
) -> NTSTATUS {
    let mode = capture::mode();
    // SAFETY: per the contract.
    let Some(oa) = (match unsafe { capture::capture_object_attributes(object_attributes, mode) } {
        Ok(oa) => oa,
        Err(st) => return st,
    }) else {
        return STATUS_INVALID_PARAMETER;
    };
    let name = oa.name.unwrap_or_default();
    if name.is_empty() {
        return STATUS_OBJECT_NAME_INVALID;
    }
    // SAFETY: `parse_context` is null.
    let (found, granted) = match unsafe {
        ob::open_by_name(
            oa.root,
            &name,
            oa.attributes,
            Some(&object::IO_COMPLETION_TYPE),
            desired_access,
            mode,
            core::ptr::null_mut(),
        )
    } {
        Ok(res) => res,
        Err(st) => return st,
    };
    let kernel_handle = !capture::is_user(mode) || (oa.attributes & OBJ_KERNEL_HANDLE) != 0;
    // SAFETY: `found` keeps the object alive while opening the handle.
    let h = match unsafe {
        handle::open_with(
            found.body(),
            granted,
            Attributes {
                inherit: (oa.attributes & OBJ_INHERIT) != 0,
                protect_from_close: false,
            },
            kernel_handle,
        )
    } {
        Ok(h) => h,
        Err(st) => return st,
    };
    // SAFETY: per the contract.
    if let Err(st) = unsafe { capture::write(io_completion_handle, h as *mut c_void, mode) } {
        let _ = handle::close_for(h, capture::handle_mode(mode));
        return st;
    }
    STATUS_SUCCESS
}

/// `NtSetIoCompletion`: post a completion packet to `io_completion_handle`.
pub extern "C" fn NtSetIoCompletion(
    io_completion_handle: *mut c_void,
    key_context: *mut c_void,
    apc_context: *mut c_void,
    io_status: NTSTATUS,
    io_status_information: usize,
) -> NTSTATUS {
    let mode = capture::handle_mode(capture::mode());
    let (held, _) = match handle::reference_for(
        io_completion_handle as u64,
        Some(&raw const object::IO_COMPLETION_TYPE),
        IO_COMPLETION_MODIFY_STATE,
        mode,
    ) {
        Ok(found) => found,
        Err(st) => return st,
    };
    // SAFETY: `held` is a live `IoCompletion`.
    unsafe {
        post(
            held.body(),
            key_context.addr(),
            apc_context.addr(),
            io_status,
            io_status_information,
        )
    }
}

/// `NtSetIoCompletionEx`: post a completion packet (accepting an optional
/// reserve packet handle).
pub extern "C" fn NtSetIoCompletionEx(
    io_completion_handle: *mut c_void,
    _io_completion_packet_handle: *mut c_void,
    key_context: *mut c_void,
    apc_context: *mut c_void,
    io_status: NTSTATUS,
    io_status_information: usize,
) -> NTSTATUS {
    NtSetIoCompletion(
        io_completion_handle,
        key_context,
        apc_context,
        io_status,
        io_status_information,
    )
}

/// `NtQueryIoCompletion`: query queue depth (`IoCompletionBasicInformation` = class 0, 4 bytes).
///
/// # Safety
/// Output buffer and `return_length` must satisfy `PreviousMode`.
pub unsafe extern "C" fn NtQueryIoCompletion(
    io_completion_handle: *mut c_void,
    class: u32,
    information: *mut u8,
    length: u32,
    return_length: *mut u32,
) -> NTSTATUS {
    let mode = capture::mode();
    if class != 0 {
        return STATUS_INVALID_INFO_CLASS;
    }
    if !return_length.is_null() {
        // SAFETY: per the contract.
        if let Err(st) = unsafe { capture::write(return_length, 4u32, mode) } {
            return st;
        }
    }
    if length < 4 {
        return STATUS_INFO_LENGTH_MISMATCH;
    }
    let (held, _) = match handle::reference_for(
        io_completion_handle as u64,
        Some(&raw const object::IO_COMPLETION_TYPE),
        IO_COMPLETION_QUERY_STATE,
        capture::handle_mode(mode),
    ) {
        Ok(found) => found,
        Err(st) => return st,
    };
    // SAFETY: `held` is a live `IoCompletion`.
    let d = unsafe { depth(held.body()) };
    // SAFETY: per the contract.
    match unsafe { capture::write(information.cast::<u32>(), d, mode) } {
        Ok(()) => STATUS_SUCCESS,
        Err(st) => st,
    }
}

/// `NtRemoveIoCompletion`: dequeue one packet from `io_completion_handle`.
///
/// # Safety
/// Pointer parameters must satisfy `PreviousMode`.
pub unsafe extern "C" fn NtRemoveIoCompletion(
    io_completion_handle: *mut c_void,
    key_context: *mut *mut c_void,
    apc_context: *mut *mut c_void,
    io_status_block: *mut IO_STATUS_BLOCK,
    timeout: *const i64,
) -> NTSTATUS {
    let mode = capture::mode();
    let timeout_val = if timeout.is_null() {
        None
    } else {
        // SAFETY: per the contract.
        match unsafe { capture::read(timeout, mode) } {
            Ok(v) => Some(v),
            Err(st) => return st,
        }
    };
    let (held, _) = match handle::reference_for(
        io_completion_handle as u64,
        Some(&raw const object::IO_COMPLETION_TYPE),
        IO_COMPLETION_MODIFY_STATE,
        capture::handle_mode(mode),
    ) {
        Ok(found) => found,
        Err(st) => return st,
    };
    let mut entry = [FileIoCompletionInformation {
        key_context: core::ptr::null_mut(),
        apc_context: core::ptr::null_mut(),
        io_status_block: IO_STATUS_BLOCK {
            Status: 0,
            Information: 0,
        },
    }];
    // SAFETY: `held` is a live `IoCompletion`.
    match unsafe { remove_ex(held.body(), &mut entry, timeout_val, false, mode) } {
        Ok(_) => {
            // SAFETY: per the contract.
            unsafe {
                if let Err(st) = capture::write(key_context, entry[0].key_context, mode) {
                    return st;
                }
                if let Err(st) = capture::write(apc_context, entry[0].apc_context, mode) {
                    return st;
                }
                if let Err(st) = capture::write(io_status_block, entry[0].io_status_block, mode) {
                    return st;
                }
            }
            STATUS_SUCCESS
        }
        Err(st) => st,
    }
}

/// `NtRemoveIoCompletionEx`: batch-dequeue up to `count` packets from `io_completion_handle`.
///
/// # Safety
/// Pointer parameters must satisfy `PreviousMode`.
pub unsafe extern "C" fn NtRemoveIoCompletionEx(
    io_completion_handle: *mut c_void,
    io_completion_information: *mut FileIoCompletionInformation,
    count: u32,
    num_entries_removed: *mut u32,
    timeout: *const i64,
    alertable: u8,
) -> NTSTATUS {
    let mode = capture::mode();
    if count == 0 {
        return STATUS_INVALID_PARAMETER;
    }
    let capped = (count as usize).min(64);
    let timeout_val = if timeout.is_null() {
        None
    } else {
        // SAFETY: per the contract.
        match unsafe { capture::read(timeout, mode) } {
            Ok(v) => Some(v),
            Err(st) => return st,
        }
    };
    let (held, _) = match handle::reference_for(
        io_completion_handle as u64,
        Some(&raw const object::IO_COMPLETION_TYPE),
        IO_COMPLETION_MODIFY_STATE,
        capture::handle_mode(mode),
    ) {
        Ok(found) => found,
        Err(st) => return st,
    };
    let mut entries = alloc::vec![
        FileIoCompletionInformation {
            key_context: core::ptr::null_mut(),
            apc_context: core::ptr::null_mut(),
            io_status_block: IO_STATUS_BLOCK {
                Status: 0,
                Information: 0,
            },
        };
        capped
    ];
    // SAFETY: `held` is a live `IoCompletion`.
    match unsafe { remove_ex(held.body(), &mut entries, timeout_val, alertable != 0, mode) } {
        Ok(n) => {
            let bytes_len = n * size_of::<FileIoCompletionInformation>();
            // SAFETY: `entries` holds `n` initialized `FileIoCompletionInformation` records.
            let src =
                unsafe { core::slice::from_raw_parts(entries.as_ptr().cast::<u8>(), bytes_len) };
            // SAFETY: per the contract; `copy_to_caller` and `write` probe user pointers.
            unsafe {
                if let Err(st) =
                    capture::copy_to_caller(io_completion_information.cast::<u8>(), src, mode)
                {
                    return st;
                }
                if let Err(st) = capture::write(num_entries_removed, n as u32, mode) {
                    return st;
                }
            }
            STATUS_SUCCESS
        }
        Err(st) => st,
    }
}
