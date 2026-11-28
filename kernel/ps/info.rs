//! User-mode process & thread information queries, termination, creation,
//! resume/suspend, and native console output (`NtDisplayString`).

#![allow(non_snake_case)]

use super::{process, user};
use crate::ke::thread;
use crate::ob::{handle, object};
use crate::svc::capture;
use alloc::string::String;
use alloc::vec::Vec;
use core::ffi::c_void;
use core::mem::size_of;
use nk_ntabi::io::UNICODE_STRING;
use nk_ntabi::ob::OBJECT_ATTRIBUTES;
use nk_ntabi::process as proc_layout;
use nk_ntabi::status::*;
use nk_ntabi::thread as thread_layout;
use nk_ntabi::user::*;
use nk_ob::handles::Attributes;

const OBJ_INHERIT: u32 = 0x2;
const OBJ_KERNEL_HANDLE: u32 = 0x200;
const THREAD_CREATE_FLAGS_CREATE_SUSPENDED: u32 = 0x1;

/// `STATUS_PORT_NOT_SET` (returned by `ProcessDebugObjectHandle` when no debugger is attached).
const STATUS_PORT_NOT_SET: NTSTATUS = 0xC000_0353u32 as NTSTATUS;

/// Write `bytes` to caller buffer `(buf, len)` with optional `return_length`,
/// returning `STATUS_INFO_LENGTH_MISMATCH` if `len < bytes.len()`.
///
/// # Safety
/// Pointer parameters must satisfy `PreviousMode`.
unsafe fn write_info_out(
    buf: *mut u8,
    len: u32,
    return_length: *mut u32,
    bytes: &[u8],
    mode: i8,
) -> NTSTATUS {
    let needed = bytes.len() as u32;
    if !return_length.is_null() {
        // SAFETY: per the contract; `capture::write` probes user pointers.
        if let Err(st) = unsafe { capture::write(return_length, needed, mode) } {
            return st;
        }
    }
    if (len as usize) < bytes.len() {
        return STATUS_INFO_LENGTH_MISMATCH;
    }
    // SAFETY: per the contract; `capture::copy_to_caller` probes user pointers.
    match unsafe { capture::copy_to_caller(buf, bytes, mode) } {
        Ok(()) => STATUS_SUCCESS,
        Err(st) => st,
    }
}

/// [`NtTerminateProcess`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntddk/nf-ntddk-zwterminateprocess).
pub extern "C" fn NtTerminateProcess(
    process_handle: *mut c_void,
    exit_status: NTSTATUS,
) -> NTSTATUS {
    let raw = process_handle.addr();
    if raw == 0 {
        // `NtTerminateProcess(NULL, status)` terminates all OTHER threads in the
        // current process without terminating the calling thread (used by
        // `ntdll!RtlExitUserProcess` right before `NtTerminateProcess(-1, status)`).
        return STATUS_SUCCESS;
    }
    if raw == (-1isize) as usize {
        user::terminate_current_process(exit_status);
    }
    let mode = capture::handle_mode(capture::mode());
    let (target, _) = match handle::reference_for(
        raw as u64,
        Some(&raw const object::PROCESS_TYPE),
        PROCESS_TERMINATE,
        mode,
    ) {
        Ok(found) => found,
        Err(st) => return st,
    };
    let me_proc = process::PsGetCurrentProcess().cast::<u8>();
    if target.body() == me_proc {
        drop(target);
        user::terminate_current_process(exit_status);
    }
    // SAFETY: `target` holds a live reference to `EPROCESS`.
    unsafe { user::mark_process_terminated(target.body(), exit_status) };
    STATUS_SUCCESS
}

/// [`NtQueryInformationProcess`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntddk/nf-ntddk-zwqueryinformationprocess).
///
/// # Safety
/// Output buffer and `return_length` must satisfy `PreviousMode`.
pub unsafe extern "C" fn NtQueryInformationProcess(
    process_handle: *mut c_void,
    class: u32,
    information: *mut u8,
    length: u32,
    return_length: *mut u32,
) -> NTSTATUS {
    let mode = capture::mode();
    let (target, _) = match handle::reference_for(
        process_handle as u64,
        Some(&raw const object::PROCESS_TYPE),
        PROCESS_QUERY_LIMITED_INFORMATION,
        capture::handle_mode(mode),
    ) {
        Ok(found) => found,
        Err(st) => return st,
    };
    let proc_body = target.body();
    match class {
        PROCESS_BASIC_INFORMATION_CLASS => {
            if length != size_of::<PROCESS_BASIC_INFORMATION>() as u32 {
                if !return_length.is_null() {
                    // SAFETY: per the contract.
                    let _ = unsafe {
                        capture::write(
                            return_length,
                            size_of::<PROCESS_BASIC_INFORMATION>() as u32,
                            mode,
                        )
                    };
                }
                return STATUS_INFO_LENGTH_MISMATCH;
            }
            // SAFETY: `proc_body` is a live `EPROCESS` referenced by `target`.
            let pbi = unsafe {
                PROCESS_BASIC_INFORMATION {
                    ExitStatus: proc_body
                        .add(proc_layout::EXIT_STATUS)
                        .cast::<NTSTATUS>()
                        .read(),
                    _pad0: 0,
                    PebBaseAddress: proc_body.add(proc_layout::PEB).cast::<*mut PEB>().read(),
                    AffinityMask: crate::ke::smp::online() as usize,
                    BasePriority: i32::from(proc_body.add(proc_layout::BASE_PRIORITY).read() as i8),
                    _pad1: 0,
                    UniqueProcessId: proc_body
                        .add(proc_layout::UNIQUE_PROCESS_ID)
                        .cast::<usize>()
                        .read(),
                    InheritedFromUniqueProcessId: proc_body
                        .add(proc_layout::INHERITED_FROM_UNIQUE_PROCESS_ID)
                        .cast::<usize>()
                        .read(),
                }
            };
            // SAFETY: `pbi` is a plain `#[repr(C)]` struct.
            let bytes = unsafe {
                core::slice::from_raw_parts(
                    (&raw const pbi).cast::<u8>(),
                    size_of::<PROCESS_BASIC_INFORMATION>(),
                )
            };
            // SAFETY: per the contract.
            unsafe { write_info_out(information, length, return_length, bytes, mode) }
        }
        PROCESS_TIMES_CLASS => {
            // `KERNEL_USER_TIMES` = 4 * i64 = 32 bytes: CreateTime, ExitTime, KernelTime, UserTime.
            // SAFETY: `proc_body` is live.
            let create = unsafe { proc_body.add(proc_layout::CREATE_TIME).cast::<i64>().read() };
            let times: [i64; 4] = [create, 0, 0, 0];
            // SAFETY: `[i64; 4]` is 32 contiguous bytes.
            let bytes = unsafe { core::slice::from_raw_parts(times.as_ptr().cast::<u8>(), 32) };
            // SAFETY: per the contract.
            unsafe { write_info_out(information, length, return_length, bytes, mode) }
        }
        PROCESS_DEBUG_PORT_CLASS | PROCESS_WOW64_INFORMATION_CLASS => {
            let zero = 0u64.to_le_bytes();
            // SAFETY: per the contract.
            unsafe { write_info_out(information, length, return_length, &zero, mode) }
        }
        PROCESS_DEBUG_OBJECT_HANDLE_CLASS => STATUS_PORT_NOT_SET,
        PROCESS_DEBUG_FLAGS_CLASS => {
            // `NoDebugInherit = 1` (no debugger attached).
            let val = 1u32.to_le_bytes();
            // SAFETY: per the contract.
            unsafe { write_info_out(information, length, return_length, &val, mode) }
        }
        PROCESS_DEFAULT_HARD_ERROR_MODE_CLASS
        | PROCESS_BREAK_ON_TERMINATION_CLASS
        | PROCESS_SESSION_INFORMATION_CLASS
        | PROCESS_SUBSYSTEM_INFORMATION_CLASS => {
            let val = 0u32.to_le_bytes();
            // SAFETY: per the contract.
            unsafe { write_info_out(information, length, return_length, &val, mode) }
        }
        PROCESS_EXECUTE_FLAGS_CLASS => {
            // `MEM_EXECUTE_OPTION_DISABLE | MEM_EXECUTE_OPTION_PERMANENT` (DEP enabled).
            let val = 0x0Au32.to_le_bytes();
            // SAFETY: per the contract.
            unsafe { write_info_out(information, length, return_length, &val, mode) }
        }
        PROCESS_PRIORITY_CLASS => {
            // `PROCESS_PRIORITY_CLASS`: `[foreground: u8, priority_class: u8]` (NORMAL = 2).
            let val = [0u8, 2u8];
            // SAFETY: per the contract.
            unsafe { write_info_out(information, length, return_length, &val, mode) }
        }
        PROCESS_HANDLE_COUNT_CLASS => {
            let val = 0u32.to_le_bytes();
            // SAFETY: per the contract.
            unsafe { write_info_out(information, length, return_length, &val, mode) }
        }
        PROCESS_COOKIE_CLASS => {
            // SAFETY: `proc_body` is live.
            let cookie =
                unsafe { process::user_state(proc_body) }.map_or(0x4E4B_0001u32, |s| s.cookie);
            let val = cookie.to_le_bytes();
            // SAFETY: per the contract.
            unsafe { write_info_out(information, length, return_length, &val, mode) }
        }
        37 => {
            // `ProcessImageInformation` (37): `SECTION_IMAGE_INFORMATION` (64 bytes).
            // SAFETY: `proc_body` is live.
            let Some(info) = unsafe { process::user_state(proc_body) }.map(|s| s.image_info) else {
                return STATUS_INVALID_INFO_CLASS;
            };
            // SAFETY: `SECTION_IMAGE_INFORMATION` is a plain `#[repr(C)]` struct.
            let bytes = unsafe {
                core::slice::from_raw_parts(
                    (&raw const info).cast::<u8>(),
                    size_of::<nk_ntabi::mm::SECTION_IMAGE_INFORMATION>(),
                )
            };
            // SAFETY: per the contract.
            unsafe { write_info_out(information, length, return_length, bytes, mode) }
        }
        PROCESS_IMAGE_FILE_NAME_CLASS | PROCESS_IMAGE_FILE_NAME_WIN32_CLASS => {
            // SAFETY: `proc_body` is live.
            let path: Vec<u16> = unsafe { process::user_state(proc_body) }
                .map(|s| s.image_path.clone())
                .unwrap_or_default();
            let str_bytes = path.len() * 2;
            let total = size_of::<UNICODE_STRING>() + str_bytes + 2;
            if !return_length.is_null() {
                // SAFETY: per the contract.
                if let Err(st) = unsafe { capture::write(return_length, total as u32, mode) } {
                    return st;
                }
            }
            if (length as usize) < total {
                return STATUS_INFO_LENGTH_MISMATCH;
            }
            let buf_va = information.addr() + size_of::<UNICODE_STRING>();
            let us = UNICODE_STRING {
                Length: str_bytes as u16,
                MaximumLength: (str_bytes + 2) as u16,
                Buffer: core::ptr::with_exposed_provenance_mut(buf_va),
            };
            let mut out = Vec::with_capacity(total);
            // SAFETY: `UNICODE_STRING` is plain data.
            out.extend_from_slice(unsafe {
                core::slice::from_raw_parts(
                    (&raw const us).cast::<u8>(),
                    size_of::<UNICODE_STRING>(),
                )
            });
            for unit in path {
                out.extend_from_slice(&unit.to_le_bytes());
            }
            out.extend_from_slice(&0u16.to_le_bytes());
            // SAFETY: per the contract.
            match unsafe { capture::copy_to_caller(information, &out, mode) } {
                Ok(()) => STATUS_SUCCESS,
                Err(st) => st,
            }
        }
        PROCESS_MITIGATION_POLICY_CLASS => {
            if length < 8 {
                return STATUS_INFO_LENGTH_MISMATCH;
            }
            let zeros = alloc::vec![0u8; length as usize];
            // SAFETY: per the contract.
            unsafe { write_info_out(information, length, return_length, &zeros, mode) }
        }
        _ => STATUS_INVALID_INFO_CLASS,
    }
}

/// [`NtSetInformationProcess`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntddk/nf-ntddk-zwsetinformationprocess).
///
/// # Safety
/// `information` must satisfy `PreviousMode`.
pub unsafe extern "C" fn NtSetInformationProcess(
    process_handle: *mut c_void,
    class: u32,
    information: *const c_void,
    length: u32,
) -> NTSTATUS {
    let mode = capture::mode();
    let (_target, _) = match handle::reference_for(
        process_handle as u64,
        Some(&raw const object::PROCESS_TYPE),
        PROCESS_SET_INFORMATION,
        capture::handle_mode(mode),
    ) {
        Ok(found) => found,
        Err(st) => return st,
    };
    if information.is_null() && length != 0 {
        return STATUS_ACCESS_VIOLATION;
    }
    match class {
        PROCESS_DEFAULT_HARD_ERROR_MODE_CLASS
        | PROCESS_PRIORITY_CLASS
        | PROCESS_BREAK_ON_TERMINATION_CLASS
        | PROCESS_EXECUTE_FLAGS_CLASS
        | PROCESS_MITIGATION_POLICY_CLASS
        | 71 => STATUS_SUCCESS, // 71 = ProcessRaiseUMExceptionOnInvalidHandleClose
        _ => STATUS_NOT_IMPLEMENTED,
    }
}

/// [`NtQueryInformationThread`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntddk/nf-ntddk-zwqueryinformationthread).
///
/// # Safety
/// Output buffer and `return_length` must satisfy `PreviousMode`.
pub unsafe extern "C" fn NtQueryInformationThread(
    thread_handle: *mut c_void,
    class: u32,
    information: *mut u8,
    length: u32,
    return_length: *mut u32,
) -> NTSTATUS {
    let mode = capture::mode();
    let (target, _) = match handle::reference_for(
        thread_handle as u64,
        Some(&raw const object::THREAD_TYPE),
        THREAD_QUERY_LIMITED_INFORMATION,
        capture::handle_mode(mode),
    ) {
        Ok(found) => found,
        Err(st) => return st,
    };
    let th = target.body().cast::<thread::Thread>();
    match class {
        THREAD_BASIC_INFORMATION_CLASS => {
            // SAFETY: `th` is a live `ETHREAD` referenced by `target`.
            let tbi = unsafe {
                let state = thread::object_field::<u8>(th, thread_layout::STATE).read();
                let cid = thread::object_field::<[u64; 2]>(th, thread_layout::CID).read();
                THREAD_BASIC_INFORMATION {
                    ExitStatus: if state == thread_layout::state::TERMINATED {
                        STATUS_SUCCESS
                    } else {
                        STATUS_PENDING
                    },
                    _pad0: 0,
                    TebBaseAddress: thread::object_field::<*mut TEB>(th, thread_layout::TEB).read(),
                    ClientId: CLIENT_ID {
                        UniqueProcess: core::ptr::with_exposed_provenance_mut(cid[0] as usize),
                        UniqueThread: core::ptr::with_exposed_provenance_mut(cid[1] as usize),
                    },
                    AffinityMask: thread::object_field::<u64>(th, thread_layout::AFFINITY).read()
                        as usize,
                    Priority: i32::from(
                        thread::object_field::<u8>(th, thread_layout::PRIORITY).read() as i8,
                    ),
                    BasePriority: i32::from(
                        thread::object_field::<u8>(th, thread_layout::BASE_PRIORITY).read() as i8,
                    ),
                }
            };
            // SAFETY: plain `#[repr(C)]` struct.
            let bytes = unsafe {
                core::slice::from_raw_parts(
                    (&raw const tbi).cast::<u8>(),
                    size_of::<THREAD_BASIC_INFORMATION>(),
                )
            };
            // SAFETY: per the contract.
            unsafe { write_info_out(information, length, return_length, bytes, mode) }
        }
        THREAD_TIMES_CLASS => {
            let zeros = [0u8; 32];
            // SAFETY: per the contract.
            unsafe { write_info_out(information, length, return_length, &zeros, mode) }
        }
        THREAD_QUERY_SET_WIN32_START_ADDRESS_CLASS => {
            // SAFETY: `th` is live.
            let addr =
                unsafe { thread::object_field::<u64>(th, thread_layout::START_ADDRESS).read() };
            let val = addr.to_le_bytes();
            // SAFETY: per the contract.
            unsafe { write_info_out(information, length, return_length, &val, mode) }
        }
        THREAD_IS_IO_PENDING_CLASS => {
            let val = 0u32.to_le_bytes();
            // SAFETY: per the contract.
            unsafe { write_info_out(information, length, return_length, &val, mode) }
        }
        THREAD_HIDE_FROM_DEBUGGER_CLASS => {
            let val = [0u8; 1];
            // SAFETY: per the contract.
            unsafe { write_info_out(information, length, return_length, &val, mode) }
        }
        _ => STATUS_INVALID_INFO_CLASS,
    }
}

/// `NtCreateThreadEx`: create a user-mode thread in `process_handle`.
///
/// # Safety
/// Pointer parameters must satisfy `PreviousMode`.
#[allow(clippy::too_many_arguments)]
pub unsafe extern "C" fn NtCreateThreadEx(
    thread_handle: *mut *mut c_void,
    desired_access: u32,
    object_attributes: *const OBJECT_ATTRIBUTES,
    process_handle: *mut c_void,
    start_routine: *mut c_void,
    argument: *mut c_void,
    create_flags: u32,
    _zero_bits: usize,
    stack_size: usize,
    maximum_stack_size: usize,
    _attribute_list: *mut c_void,
) -> NTSTATUS {
    let mode = capture::mode();
    // SAFETY: per the contract.
    let oa = match unsafe { capture::capture_object_attributes(object_attributes, mode) } {
        Ok(oa) => oa,
        Err(st) => return st,
    };
    let (target_proc, _) = match handle::reference_for(
        process_handle as u64,
        Some(&raw const object::PROCESS_TYPE),
        PROCESS_CREATE_THREAD,
        capture::handle_mode(mode),
    ) {
        Ok(found) => found,
        Err(st) => return st,
    };
    let suspended = (create_flags & THREAD_CREATE_FLAGS_CREATE_SUSPENDED) != 0;
    // SAFETY: `target_proc` holds a live `EPROCESS`.
    let th_ref = match unsafe {
        user::create_thread(
            target_proc.body(),
            start_routine.addr() as u64,
            argument.addr() as u64,
            maximum_stack_size as u64,
            stack_size as u64,
            false,
            suspended,
        )
    } {
        Ok(t) => t,
        Err(st) => return st,
    };
    let attrs = oa.map_or(0, |a| a.attributes);
    let kernel_handle = !capture::is_user(mode) || (attrs & OBJ_KERNEL_HANDLE) != 0;
    // SAFETY: `th_ref` keeps the thread alive while opening the handle.
    let h = match unsafe {
        handle::open_with(
            th_ref.body(),
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
    if let Err(st) = unsafe { capture::write(thread_handle, h as *mut c_void, mode) } {
        let _ = handle::close_for(h, capture::handle_mode(mode));
        return st;
    }
    STATUS_SUCCESS
}

/// `NtResumeThread`: resume a suspended thread and optionally return its previous suspend count.
///
/// # Safety
/// `previous_suspend_count` is null or satisfies `PreviousMode`.
pub unsafe extern "C" fn NtResumeThread(
    thread_handle: *mut c_void,
    previous_suspend_count: *mut u32,
) -> NTSTATUS {
    let mode = capture::mode();
    let (target, _) = match handle::reference_for(
        thread_handle as u64,
        Some(&raw const object::THREAD_TYPE),
        THREAD_SUSPEND_RESUME,
        capture::handle_mode(mode),
    ) {
        Ok(found) => found,
        Err(st) => return st,
    };
    // SAFETY: `target` holds a live `ETHREAD`.
    let prev = unsafe { thread::resume_thread(target.body().cast()) };
    if !previous_suspend_count.is_null() {
        // SAFETY: per the contract.
        if let Err(st) = unsafe { capture::write(previous_suspend_count, prev, mode) } {
            return st;
        }
    }
    STATUS_SUCCESS
}

/// `NtSuspendThread`: stub returning `STATUS_NOT_IMPLEMENTED` for active threads.
///
/// # Safety
/// `previous_suspend_count` is null or satisfies `PreviousMode`.
pub unsafe extern "C" fn NtSuspendThread(
    _thread_handle: *mut c_void,
    _previous_suspend_count: *mut u32,
) -> NTSTATUS {
    STATUS_NOT_IMPLEMENTED
}

/// `NtDisplayString`: print a native user-mode UTF-16 message to the serial console.
///
/// # Safety
/// `string` must satisfy `PreviousMode`.
pub unsafe extern "C" fn NtDisplayString(string: *const UNICODE_STRING) -> NTSTATUS {
    let mode = capture::mode();
    // SAFETY: per the contract; `capture_unicode_string` probes user pointers.
    let wide = match unsafe { capture::capture_unicode_string(string, mode) } {
        Ok(w) => w,
        Err(st) => return st,
    };
    let text: String = char::decode_utf16(wide.iter().copied())
        .map(|r| r.unwrap_or('?'))
        .filter(|&c| c != '\r')
        .collect();
    if !text.is_empty() {
        crate::kd::print(format_args!("{text}"));
    }
    STATUS_SUCCESS
}

/// `NtQueryDefaultLocale`: return en-US (`0x0409`).
///
/// # Safety
/// `default_locale_id` must satisfy `PreviousMode`.
pub unsafe extern "C" fn NtQueryDefaultLocale(
    _user_profile: u8,
    default_locale_id: *mut u32,
) -> NTSTATUS {
    let mode = capture::mode();
    // SAFETY: per the contract.
    match unsafe { capture::write(default_locale_id, 0x0409u32, mode) } {
        Ok(()) => STATUS_SUCCESS,
        Err(st) => st,
    }
}

/// `NtQueryDefaultUILanguage`: return en-US (`0x0409`).
///
/// # Safety
/// `language_id` must satisfy `PreviousMode`.
pub unsafe extern "C" fn NtQueryDefaultUILanguage(language_id: *mut u16) -> NTSTATUS {
    let mode = capture::mode();
    // SAFETY: per the contract.
    match unsafe { capture::write(language_id, 0x0409u16, mode) } {
        Ok(()) => STATUS_SUCCESS,
        Err(st) => st,
    }
}

/// `NtQueryInstallUILanguage`: return en-US (`0x0409`).
///
/// # Safety
/// `language_id` must satisfy `PreviousMode`.
pub unsafe extern "C" fn NtQueryInstallUILanguage(language_id: *mut u16) -> NTSTATUS {
    let mode = capture::mode();
    // SAFETY: per the contract.
    match unsafe { capture::write(language_id, 0x0409u16, mode) } {
        Ok(()) => STATUS_SUCCESS,
        Err(st) => st,
    }
}

/// `NtGetMUIRegistryInfo`: MUI language-pack registry info (none installed on NK,
/// causing `ntdll!LdrFindResource_U` to use each binary's built-in resources).
///
/// # Safety
/// `data_size` is null or satisfies `PreviousMode`.
pub unsafe extern "C" fn NtGetMUIRegistryInfo(
    _flags: u32,
    data_size: *mut u32,
    _data: *mut c_void,
) -> NTSTATUS {
    let mode = capture::mode();
    if !data_size.is_null() {
        // SAFETY: per the contract.
        let _ = unsafe { capture::write(data_size, 0u32, mode) };
    }
    STATUS_OBJECT_NAME_NOT_FOUND
}

/// `NtIsUILanguageComitted`: report UI language committed.
pub extern "C" fn NtIsUILanguageComitted() -> NTSTATUS {
    STATUS_SUCCESS
}

/// `NtInitializeNlsFiles`: NLS `locale.nls` mapping (absent on NK; `ntdll` falls
/// back to built-in en-US resources when `STATUS_OBJECT_NAME_NOT_FOUND` is returned).
///
/// # Safety
/// Pointer parameters must satisfy `PreviousMode`.
pub unsafe extern "C" fn NtInitializeNlsFiles(
    _base_address: *mut *mut c_void,
    default_locale_id: *mut u32,
    _default_casing_table_size: *mut i64,
) -> NTSTATUS {
    let mode = capture::mode();
    if !default_locale_id.is_null() {
        // SAFETY: per the contract.
        let _ = unsafe { capture::write(default_locale_id, 0x0409u32, mode) };
    }
    STATUS_OBJECT_NAME_NOT_FOUND
}

/// `NtGetNlsSectionPtr`: query a named NLS section (not mapped on NK).
pub extern "C" fn NtGetNlsSectionPtr(
    _nls_type: u32,
    _code_page: u32,
    _context_data: *mut c_void,
    _section_pointer: *mut *mut c_void,
    _section_size: *mut u32,
) -> NTSTATUS {
    STATUS_OBJECT_NAME_NOT_FOUND
}

/// `NtFlushInstructionCache`: no-op on x86-64 (coherent icache).
pub extern "C" fn NtFlushInstructionCache(
    _process_handle: *mut c_void,
    _base_address: *const c_void,
    _length: usize,
) -> NTSTATUS {
    STATUS_SUCCESS
}

/// `NtTraceControl`: user-mode ETW logger registration/control stub returning
/// success with 0 bytes output (used by `ntdll!EtwEventRegister`).
///
/// # Safety
/// `return_length` is null or satisfies `PreviousMode`.
pub unsafe extern "C" fn NtTraceControl(
    _operation: u32,
    _in_buf: *const c_void,
    _in_len: u32,
    _out_buf: *mut c_void,
    _out_len: u32,
    return_length: *mut u32,
) -> NTSTATUS {
    let mode = capture::mode();
    if !return_length.is_null() {
        // SAFETY: per the contract.
        let _ = unsafe { capture::write(return_length, 0u32, mode) };
    }
    STATUS_SUCCESS
}

/// `NtApphelpCacheControl`: shim cache query (no shims cached on NK).
pub extern "C" fn NtApphelpCacheControl(_command: u32, _data: *mut c_void) -> NTSTATUS {
    STATUS_NOT_FOUND
}

/// `NtTraceEvent`: emit a user-mode ETW event (no active user trace sessions on NK).
pub extern "C" fn NtTraceEvent(
    _trace_handle: *mut c_void,
    _flags: u32,
    _field_size: u32,
    _fields: *const c_void,
) -> NTSTATUS {
    STATUS_SUCCESS
}

/// `NtSerializeBoot`: synchronize native boot-time tools (`autochk.exe`).
pub extern "C" fn NtSerializeBoot() -> NTSTATUS {
    STATUS_SUCCESS
}

/// `NtAllocateLocallyUniqueId`: allocate a fresh monotonic `LUID`.
///
/// # Safety
/// `luid` must satisfy `PreviousMode`.
pub unsafe extern "C" fn NtAllocateLocallyUniqueId(luid: *mut u64) -> NTSTATUS {
    static NEXT_LUID: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0x1000);
    let mode = capture::mode();
    let id = NEXT_LUID.fetch_add(1, core::sync::atomic::Ordering::Relaxed);
    // SAFETY: per the contract.
    match unsafe { capture::write(luid, id, mode) } {
        Ok(()) => STATUS_SUCCESS,
        Err(st) => st,
    }
}

/// `NtUpdateWnfStateData`: update a WNF state name (no user subscribers on NK).
#[allow(clippy::too_many_arguments)]
pub extern "C" fn NtUpdateWnfStateData(
    _state_name: *const u64,
    _buffer: *const c_void,
    _length: u32,
    _type_id: *const c_void,
    _explicit_scope: *const c_void,
    _matching_change_stamp: u32,
    _check_stamp: u32,
) -> NTSTATUS {
    STATUS_SUCCESS
}

/// `NtDrawText`: draw native boot-time text (routed to serial console via `NtDisplayString`).
///
/// # Safety
/// `text` must satisfy `PreviousMode`.
pub unsafe extern "C" fn NtDrawText(text: *const UNICODE_STRING) -> NTSTATUS {
    // SAFETY: per the contract.
    unsafe { NtDisplayString(text) }
}

/// `NtSetThreadExecutionState`: record display/system stay-awake state.
///
/// # Safety
/// `previous_flags` must satisfy `PreviousMode`.
pub unsafe extern "C" fn NtSetThreadExecutionState(
    new_flags: u32,
    previous_flags: *mut u32,
) -> NTSTATUS {
    static EXEC_STATE: core::sync::atomic::AtomicU32 =
        core::sync::atomic::AtomicU32::new(0x8000_0000);
    let mode = capture::mode();
    let prev = EXEC_STATE.swap(new_flags, core::sync::atomic::Ordering::AcqRel);
    if !previous_flags.is_null() {
        // SAFETY: per the contract.
        if let Err(st) = unsafe { capture::write(previous_flags, prev, mode) } {
            return st;
        }
    }
    STATUS_SUCCESS
}

/// `NtShutdownSystem`: flush dirty cache pages on shutdown/reboot request.
pub extern "C" fn NtShutdownSystem(_action: u32) -> NTSTATUS {
    crate::cc::lazy::shutdown_flush();
    STATUS_SUCCESS
}

/// `NtRaiseHardError`: native-subsystem hard-error notification (no CSRSS
/// hard-error port exists, so returns `ResponseNotHandled = 6`).
///
/// # Safety
/// `parameters` and `response` must satisfy `PreviousMode`.
#[allow(clippy::too_many_arguments)]
pub unsafe extern "C" fn NtRaiseHardError(
    error_status: NTSTATUS,
    number_of_parameters: u32,
    _unicode_string_parameter_mask: u32,
    parameters: *const usize,
    _valid_response_options: u32,
    response: *mut u32,
) -> NTSTATUS {
    const RESPONSE_NOT_HANDLED: u32 = 6;
    let mode = capture::mode();
    let p0 = if number_of_parameters >= 1 && !parameters.is_null() {
        // SAFETY: per the contract; probed via `capture::read`.
        unsafe { capture::read(parameters, mode).unwrap_or(0) }
    } else {
        0
    };
    kprintln!(
        "ps: NtRaiseHardError status={:#010x} nparams={} p0={:#x}",
        error_status as u32,
        number_of_parameters,
        p0
    );
    if !response.is_null() {
        // SAFETY: per the contract.
        if let Err(st) = unsafe { capture::write(response, RESPONSE_NOT_HANDLED, mode) } {
            return st;
        }
    }
    STATUS_SUCCESS
}
