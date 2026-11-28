//! Directory objects by handle: `ZwCreateDirectoryObject`,
//! `ZwMakeTemporaryObject`. The directories themselves are the
//! namespace's (`ob`).

#![allow(non_snake_case)]

use super::handle::{self, OBJ_KERNEL_HANDLE};
use super::object::{self, ObRef};
use core::ffi::c_void;
use nk_ntabi::ob::OBJECT_ATTRIBUTES;
use nk_ntabi::status::*;
use nk_ob::handles::Attributes;

/// Object attributes (`wdm.h`).
const OBJ_INHERIT: u32 = 0x2;
const OBJ_PERMANENT: u32 = 0x10;
const OBJ_EXCLUSIVE: u32 = 0x20;
const OBJ_OPENIF: u32 = 0x80;
const OBJ_OPENLINK: u32 = 0x100;

/// Whether the object `body` is of the type `ty`.
///
/// # Safety
/// The caller holds a reference to `body`.
#[allow(dead_code)]
pub(super) unsafe fn is(body: *mut u8, ty: &'static object::ObjectType) -> bool {
    // SAFETY: per the contract.
    core::ptr::eq(unsafe { object::type_of(body) }, ty)
}

/// [`ZwCreateDirectoryObject`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-zwcreatedirectoryobject):
/// make a directory object and give a handle to it, granted the access
/// asked for. With a name in the attributes the directory is an entry
/// of the namespace, at that path from the root or from the
/// attributes' root directory; without, it is reached by its handle
/// alone. `OBJ_PERMANENT` makes it permanent: a temporary directory
/// loses its name when its last handle closes. A name that is taken is
/// `STATUS_OBJECT_NAME_COLLISION`; with `OBJ_OPENIF`, and a directory
/// having the name, that directory is opened and the status is
/// `STATUS_OBJECT_NAME_EXISTS`.
///
/// The handle is written when the attributes were acceptable: null if
/// the directory could then not be made or named, as the pinned
/// kernel's `ObpCreateDirectoryObject` leaves it.
///
/// `OBJ_OPENLINK` is invalid for a directory, as on Windows. The gap
/// the ledger's "partial" stands for: `OBJ_EXCLUSIVE` is refused with
/// `STATUS_NOT_IMPLEMENTED`. A security descriptor in the attributes
/// is not looked at: nothing checks access to an object.
///
/// # Safety
/// `directory_handle` is writable; `object_attributes` is null or
/// points to an `OBJECT_ATTRIBUTES` whose name is null or a counted
/// string.
pub unsafe extern "C" fn NtCreateDirectoryObject(
    directory_handle: *mut *mut c_void,
    desired_access: u32,
    object_attributes: *const OBJECT_ATTRIBUTES,
) -> NTSTATUS {
    let mode = crate::svc::capture::mode();
    // SAFETY: per the contract; fault-protected for `UserMode`.
    let oa =
        match unsafe { crate::svc::capture::capture_object_attributes(object_attributes, mode) } {
            Ok(oa) => oa,
            Err(status) => return status,
        };
    let (root, name, attributes) = match oa {
        Some(oa) => {
            if oa.attributes & OBJ_OPENLINK != 0 {
                return STATUS_INVALID_PARAMETER;
            }
            if oa.attributes & OBJ_EXCLUSIVE != 0 {
                return STATUS_NOT_IMPLEMENTED;
            }
            (oa.root, oa.name.unwrap_or_default(), oa.attributes)
        }
        None => (core::ptr::null_mut(), alloc::vec::Vec::new(), 0),
    };
    let start = match super::resolve_namespace_root(root, name.is_empty(), mode) {
        Ok(start) => start,
        Err(status) => {
            // SAFETY: per the contract; fault-protected for `UserMode`.
            let _ = unsafe {
                crate::svc::capture::write(directory_handle, core::ptr::null_mut(), mode)
            };
            return status;
        }
    };
    let made = super::create_directory(
        start.as_ref().map(ObRef::body),
        &name,
        attributes & OBJ_PERMANENT != 0,
        attributes & OBJ_OPENIF != 0,
    );
    drop(start);
    // SAFETY: per the contract for the handle; `body` is the reference
    // the directory came with, given up once the handle holds it.
    unsafe {
        let (body, existed) = match made {
            Ok(made) => made,
            Err(status) => {
                let _ = crate::svc::capture::write(directory_handle, core::ptr::null_mut(), mode);
                return status;
            }
        };
        let opened = handle::open_with(
            body,
            desired_access,
            Attributes {
                inherit: attributes & OBJ_INHERIT != 0,
                protect_from_close: false,
            },
            attributes & OBJ_KERNEL_HANDLE != 0,
        );
        if opened.is_err() && !existed {
            // No handle was ever open: a temporary directory's name
            // goes, as when its last handle closes.
            super::directory_handle_closed(core::ptr::null_mut(), body.cast(), 1, 1);
        }
        object::dereference(body);
        match opened {
            Ok(opened) => {
                if let Err(status) =
                    crate::svc::capture::write(directory_handle, opened as *mut c_void, mode)
                {
                    let _ = handle::close_for(opened, crate::svc::capture::handle_mode(mode));
                    return status;
                }
                if existed {
                    STATUS_OBJECT_NAME_EXISTS
                } else {
                    STATUS_SUCCESS
                }
            }
            Err(status) => {
                let _ = crate::svc::capture::write(directory_handle, core::ptr::null_mut(), mode);
                status
            }
        }
    }
}

/// [`ZwMakeTemporaryObject`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-zwmaketemporaryobject):
/// the object the handle names is no longer permanent, so its name
/// goes when its last handle closes. Kernel mode's handle is asked
/// for no access.
///
/// Directories and named events are the objects NK makes permanent by
/// handle. An object without a name has no permanence to lose. A named
/// object of another type has its name from the kernel code that made
/// it, which takes it away again; making one temporary by handle stops
/// the system by name: the ledger's "partial".
pub extern "C" fn NtMakeTemporaryObject(handle: *mut c_void) -> NTSTATUS {
    let held = match handle::reference(handle as u64, None) {
        Ok(held) => held,
        Err(status) => return status,
    };
    let body = held.body();
    // SAFETY: the reference just taken, given up at the end.
    unsafe {
        let ty = object::type_of(body);
        if core::ptr::eq(ty, &raw const object::DIRECTORY_TYPE)
            || core::ptr::eq(ty, &raw const object::EVENT_TYPE)
        {
            super::make_temporary(body);
        } else if object::has_name(body) {
            let name: alloc::string::String = char::decode_utf16(ty.name().iter().copied())
                .map(|c| c.unwrap_or('?'))
                .collect();
            crate::kd::bugcheck(format_args!(
                "ZwMakeTemporaryObject: making a named object of type {name} temporary is not \
                 implemented"
            ));
        }
    }
    STATUS_SUCCESS
}

/// [`NtOpenDirectoryObject`](https://learn.microsoft.com/en-us/windows/win32/devnotes/ntopendirectoryobject).
///
/// # Safety
/// Pointer parameters must satisfy `PreviousMode`.
pub unsafe extern "C" fn NtOpenDirectoryObject(
    directory_handle: *mut *mut c_void,
    desired_access: u32,
    object_attributes: *const OBJECT_ATTRIBUTES,
) -> NTSTATUS {
    let mode = crate::svc::capture::mode();
    // SAFETY: per the contract.
    let Some(oa) =
        (match unsafe { crate::svc::capture::capture_object_attributes(object_attributes, mode) } {
            Ok(oa) => oa,
            Err(st) => return st,
        })
    else {
        return STATUS_INVALID_PARAMETER;
    };
    let name = oa.name.unwrap_or_default();
    if name.is_empty() {
        return STATUS_OBJECT_NAME_INVALID;
    }
    // SAFETY: `parse_context` is null for directory opens.
    let (found, granted) = match unsafe {
        super::open_by_name(
            oa.root,
            &name,
            oa.attributes,
            Some(&object::DIRECTORY_TYPE),
            desired_access,
            mode,
            core::ptr::null_mut(),
        )
    } {
        Ok(res) => res,
        Err(st) => return st,
    };
    let kernel_handle =
        !crate::svc::capture::is_user(mode) || (oa.attributes & OBJ_KERNEL_HANDLE) != 0;
    // SAFETY: `found` keeps the directory alive while opening the handle.
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
    if let Err(st) = unsafe { crate::svc::capture::write(directory_handle, h as *mut c_void, mode) }
    {
        let _ = handle::close_for(h, crate::svc::capture::handle_mode(mode));
        return st;
    }
    STATUS_SUCCESS
}

/// [`NtOpenSymbolicLinkObject`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-zwopensymboliclinkobject).
///
/// # Safety
/// Pointer parameters must satisfy `PreviousMode`.
pub unsafe extern "C" fn NtOpenSymbolicLinkObject(
    link_handle: *mut *mut c_void,
    desired_access: u32,
    object_attributes: *const OBJECT_ATTRIBUTES,
) -> NTSTATUS {
    let mode = crate::svc::capture::mode();
    // SAFETY: per the contract.
    let Some(oa) =
        (match unsafe { crate::svc::capture::capture_object_attributes(object_attributes, mode) } {
            Ok(oa) => oa,
            Err(st) => return st,
        })
    else {
        return STATUS_INVALID_PARAMETER;
    };
    let name = oa.name.unwrap_or_default();
    if name.is_empty() {
        return STATUS_OBJECT_NAME_INVALID;
    }
    // Opening a symbolic link itself always stops at the final link (`OBJ_OPENLINK`).
    // SAFETY: `parse_context` is null for symbolic link opens.
    let (found, granted) = match unsafe {
        super::open_by_name(
            oa.root,
            &name,
            oa.attributes | OBJ_OPENLINK,
            Some(&object::SYMBOLIC_LINK_TYPE),
            desired_access,
            mode,
            core::ptr::null_mut(),
        )
    } {
        Ok(res) => res,
        Err(st) => return st,
    };
    let kernel_handle =
        !crate::svc::capture::is_user(mode) || (oa.attributes & OBJ_KERNEL_HANDLE) != 0;
    // SAFETY: `found` keeps the symbolic link alive while opening the handle.
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
    if let Err(st) = unsafe { crate::svc::capture::write(link_handle, h as *mut c_void, mode) } {
        let _ = handle::close_for(h, crate::svc::capture::handle_mode(mode));
        return st;
    }
    STATUS_SUCCESS
}

/// [`NtQuerySymbolicLinkObject`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-zwquerysymboliclinkobject).
///
/// # Safety
/// Pointer parameters must satisfy `PreviousMode`.
pub unsafe extern "C" fn NtQuerySymbolicLinkObject(
    link_handle: *mut c_void,
    link_target: *mut UNICODE_STRING,
    returned_length: *mut u32,
) -> NTSTATUS {
    const SYMBOLIC_LINK_QUERY: u32 = 0x1;
    let mode = crate::svc::capture::mode();
    let (held, _) = match handle::reference_for(
        link_handle as u64,
        Some(&raw const object::SYMBOLIC_LINK_TYPE),
        SYMBOLIC_LINK_QUERY,
        crate::svc::capture::handle_mode(mode),
    ) {
        Ok(found) => found,
        Err(st) => return st,
    };
    // SAFETY: per the contract.
    let mut out_us = match unsafe { crate::svc::capture::read(link_target, mode) } {
        Ok(u) => u,
        Err(st) => return st,
    };
    // SAFETY: `held` is a live `OBJECT_SYMBOLIC_LINK`.
    let target = unsafe {
        let sl = held.body().cast::<nk_ntabi::ob::OBJECT_SYMBOLIC_LINK>();
        crate::rtl::copy_unicode(&raw const (*sl).LinkTarget)
    };
    let bytes_len = target.len() * 2;
    let needed = (bytes_len + 2) as u32;
    if !returned_length.is_null() {
        // SAFETY: per the contract.
        if let Err(st) = unsafe { crate::svc::capture::write(returned_length, needed, mode) } {
            return st;
        }
    }
    if usize::from(out_us.MaximumLength) < bytes_len {
        return STATUS_BUFFER_TOO_SMALL;
    }
    if bytes_len > 0 {
        // SAFETY: `target` is valid UTF-16 code units.
        let src = unsafe { core::slice::from_raw_parts(target.as_ptr().cast::<u8>(), bytes_len) };
        // SAFETY: `copy_to_caller` probes user pointers.
        let cp =
            unsafe { crate::svc::capture::copy_to_caller(out_us.Buffer.cast::<u8>(), src, mode) };
        if let Err(st) = cp {
            return st;
        }
    }
    if usize::from(out_us.MaximumLength) >= bytes_len + 2 {
        // SAFETY: room for trailing NUL.
        let _ = unsafe {
            crate::svc::capture::copy_to_caller(
                out_us.Buffer.cast::<u8>().add(bytes_len),
                &[0u8; 2],
                mode,
            )
        };
    }
    out_us.Length = bytes_len as u16;
    // SAFETY: per the contract.
    match unsafe { crate::svc::capture::write(link_target, out_us, mode) } {
        Ok(()) => STATUS_SUCCESS,
        Err(st) => st,
    }
}

/// `OBJECT_DIRECTORY_INFORMATION` (`ntifs.h`, 32 bytes on 64-bit Windows).
#[repr(C)]
#[derive(Clone, Copy)]
struct ObjectDirectoryInformation {
    name: nk_ntabi::io::UNICODE_STRING,
    type_name: nk_ntabi::io::UNICODE_STRING,
}

/// [`NtQueryDirectoryObject`](https://learn.microsoft.com/en-us/windows/win32/devnotes/ntquerydirectoryobject).
///
/// # Safety
/// Pointer parameters must satisfy `PreviousMode`.
pub unsafe extern "C" fn NtQueryDirectoryObject(
    directory_handle: *mut c_void,
    buffer: *mut u8,
    length: u32,
    return_single_entry: u8,
    restart_scan: u8,
    context: *mut u32,
    return_length: *mut u32,
) -> NTSTATUS {
    const DIRECTORY_QUERY: u32 = 0x0001;
    let mode = crate::svc::capture::mode();
    let (held, _) = match handle::reference_for(
        directory_handle as u64,
        Some(&raw const object::DIRECTORY_TYPE),
        DIRECTORY_QUERY,
        crate::svc::capture::handle_mode(mode),
    ) {
        Ok(found) => found,
        Err(st) => return st,
    };
    let start_idx = if restart_scan != 0 {
        0usize
    } else {
        // SAFETY: per the contract.
        match unsafe { crate::svc::capture::read(context, mode) } {
            Ok(c) => c as usize,
            Err(st) => return st,
        }
    };
    let entries = match super::list_directory(held.body()) {
        Ok(e) => e,
        Err(st) => return st,
    };
    if start_idx >= entries.len() {
        if !return_length.is_null() {
            // SAFETY: per the contract.
            let _ = unsafe { crate::svc::capture::write(return_length, 0u32, mode) };
        }
        return STATUS_NO_MORE_ENTRIES;
    }

    let rec_size = size_of::<ObjectDirectoryInformation>();
    let avail = length as usize;
    let mut chosen = 0usize;
    let mut str_bytes = 0usize;
    for entry in entries.iter().skip(start_idx) {
        let entry_str = (entry.name.len() + 1) * 2 + (entry.type_name.len() + 1) * 2;
        let next_total = (chosen + 2) * rec_size + str_bytes + entry_str;
        if next_total > avail {
            break;
        }
        chosen += 1;
        str_bytes += entry_str;
        if return_single_entry != 0 {
            break;
        }
    }
    if chosen == 0 {
        let entry = &entries[start_idx];
        let needed =
            (2 * rec_size + (entry.name.len() + 1) * 2 + (entry.type_name.len() + 1) * 2) as u32;
        if !return_length.is_null() {
            // SAFETY: per the contract.
            let _ = unsafe { crate::svc::capture::write(return_length, needed, mode) };
        }
        return STATUS_BUFFER_TOO_SMALL;
    }

    let total = (chosen + 1) * rec_size + str_bytes;
    let mut out = alloc::vec![0u8; total];
    let mut str_off = (chosen + 1) * rec_size;
    let base_va = buffer.addr();
    for (i, entry) in entries.iter().skip(start_idx).take(chosen).enumerate() {
        let name = &entry.name;
        let ty = &entry.type_name;
        let name_bytes = name.len() * 2;
        let ty_bytes = ty.len() * 2;
        let name_va = base_va + str_off;
        for (j, &u) in name.iter().enumerate() {
            out[str_off + j * 2..str_off + j * 2 + 2].copy_from_slice(&u.to_le_bytes());
        }
        str_off += name_bytes + 2;
        let ty_va = base_va + str_off;
        for (j, &u) in ty.iter().enumerate() {
            out[str_off + j * 2..str_off + j * 2 + 2].copy_from_slice(&u.to_le_bytes());
        }
        str_off += ty_bytes + 2;
        let rec = ObjectDirectoryInformation {
            name: nk_ntabi::io::UNICODE_STRING {
                Length: name_bytes as u16,
                MaximumLength: (name_bytes + 2) as u16,
                Buffer: core::ptr::with_exposed_provenance_mut(name_va),
            },
            type_name: nk_ntabi::io::UNICODE_STRING {
                Length: ty_bytes as u16,
                MaximumLength: (ty_bytes + 2) as u16,
                Buffer: core::ptr::with_exposed_provenance_mut(ty_va),
            },
        };
        // SAFETY: `ObjectDirectoryInformation` is plain `#[repr(C)]` data.
        let rec_bytes =
            unsafe { core::slice::from_raw_parts((&raw const rec).cast::<u8>(), rec_size) };
        out[i * rec_size..(i + 1) * rec_size].copy_from_slice(rec_bytes);
    }
    // Note: slot `chosen` is already zeroed as the null terminator entry.
    // SAFETY: per the contract; `copy_to_caller` probes user pointers.
    if let Err(st) = unsafe { crate::svc::capture::copy_to_caller(buffer, &out, mode) } {
        return st;
    }
    let next_ctx = (start_idx + chosen) as u32;
    // SAFETY: per the contract.
    if let Err(st) = unsafe { crate::svc::capture::write(context, next_ctx, mode) } {
        return st;
    }
    if !return_length.is_null() {
        // SAFETY: per the contract.
        if let Err(st) = unsafe { crate::svc::capture::write(return_length, total as u32, mode) } {
            return st;
        }
    }
    if start_idx + chosen < entries.len() {
        STATUS_MORE_ENTRIES
    } else {
        STATUS_SUCCESS
    }
}

/// [`NtCreateSymbolicLinkObject`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-zwcreatesymboliclinkobject).
///
/// # Safety
/// Pointer parameters must satisfy `PreviousMode`.
pub unsafe extern "C" fn NtCreateSymbolicLinkObject(
    link_handle: *mut *mut c_void,
    desired_access: u32,
    object_attributes: *const OBJECT_ATTRIBUTES,
    link_target: *const nk_ntabi::io::UNICODE_STRING,
) -> NTSTATUS {
    let mode = crate::svc::capture::mode();
    // SAFETY: per the contract.
    let Some(oa) =
        (match unsafe { crate::svc::capture::capture_object_attributes(object_attributes, mode) } {
            Ok(oa) => oa,
            Err(st) => return st,
        })
    else {
        return STATUS_INVALID_PARAMETER;
    };
    // SAFETY: per the contract.
    let target = match unsafe { crate::svc::capture::capture_unicode_string(link_target, mode) } {
        Ok(t) => t,
        Err(st) => return st,
    };
    let name = oa.name.unwrap_or_default();
    if name.is_empty() || target.is_empty() {
        return STATUS_OBJECT_NAME_INVALID;
    }
    let start = match super::resolve_namespace_root(oa.root, false, mode) {
        Ok(s) => s,
        Err(st) => return st,
    };
    let body = match super::create_link(
        start.as_ref().map(ObRef::body),
        &name,
        &target,
        oa.attributes & OBJ_PERMANENT != 0,
    ) {
        Ok(b) => b,
        Err(st) => return st,
    };
    drop(start);
    let kernel_handle =
        !crate::svc::capture::is_user(mode) || (oa.attributes & OBJ_KERNEL_HANDLE) != 0;
    // SAFETY: `body` carries the caller reference from `create_link`.
    unsafe {
        let opened = handle::open_with(
            body,
            desired_access,
            Attributes {
                inherit: oa.attributes & OBJ_INHERIT != 0,
                protect_from_close: false,
            },
            kernel_handle,
        );
        object::dereference(body);
        match opened {
            Ok(h) => {
                if let Err(st) = crate::svc::capture::write(link_handle, h as *mut c_void, mode) {
                    let _ = handle::close_for(h, crate::svc::capture::handle_mode(mode));
                    return st;
                }
                STATUS_SUCCESS
            }
            Err(st) => st,
        }
    }
}

/// [`NtDuplicateObject`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-zwduplicateobject).
///
/// # Safety
/// `target_handle` is null or satisfies `PreviousMode`.
pub unsafe extern "C" fn NtDuplicateObject(
    source_process_handle: *mut c_void,
    source_handle: *mut c_void,
    target_process_handle: *mut c_void,
    target_handle: *mut *mut c_void,
    desired_access: u32,
    handle_attributes: u32,
    options: u32,
) -> NTSTATUS {
    const PROCESS_DUP_HANDLE: u32 = 0x0040;
    const DUPLICATE_CLOSE_SOURCE: u32 = 0x1;
    const DUPLICATE_SAME_ACCESS: u32 = 0x2;
    const DUPLICATE_SAME_ATTRIBUTES: u32 = 0x4;
    let mode = crate::svc::capture::mode();
    let hmode = crate::svc::capture::handle_mode(mode);

    let (src_proc, _) = match handle::reference_for(
        source_process_handle as u64,
        Some(&raw const object::PROCESS_TYPE),
        PROCESS_DUP_HANDLE,
        hmode,
    ) {
        Ok(found) => found,
        Err(st) => return st,
    };
    // SAFETY: `src_proc` is a live `EPROCESS`.
    let (obj, info) = match unsafe {
        handle::reference_in(src_proc.body(), source_handle as u64, None, 0, hmode)
    } {
        Ok(found) => found,
        Err(st) => return st,
    };

    let close_source = (options & DUPLICATE_CLOSE_SOURCE) != 0;
    if target_process_handle.is_null() {
        if close_source {
            let _ = handle::close_for(source_handle as u64, hmode);
        }
        return STATUS_SUCCESS;
    }

    let (dst_proc, _) = match handle::reference_for(
        target_process_handle as u64,
        Some(&raw const object::PROCESS_TYPE),
        PROCESS_DUP_HANDLE,
        hmode,
    ) {
        Ok(found) => found,
        Err(st) => return st,
    };
    let access = if (options & DUPLICATE_SAME_ACCESS) != 0 {
        info.granted
    } else {
        desired_access
    };
    let attrs = if (options & DUPLICATE_SAME_ATTRIBUTES) != 0 {
        info.attributes
    } else {
        Attributes {
            inherit: (handle_attributes & OBJ_INHERIT) != 0,
            protect_from_close: false,
        }
    };
    let kernel_handle =
        !crate::svc::capture::is_user(mode) || (handle_attributes & OBJ_KERNEL_HANDLE) != 0;
    // SAFETY: `dst_proc` and `obj` are live references.
    let new_h =
        match unsafe { handle::open_in(dst_proc.body(), obj.body(), access, attrs, kernel_handle) }
        {
            Ok(h) => h,
            Err(st) => return st,
        };
    if close_source {
        let _ = handle::close_for(source_handle as u64, hmode);
    }
    if !target_handle.is_null() {
        // SAFETY: per the contract.
        let wr = unsafe { crate::svc::capture::write(target_handle, new_h as *mut c_void, mode) };
        if let Err(st) = wr {
            return st;
        }
    }
    STATUS_SUCCESS
}

/// [`NtQueryObject`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-ntqueryobject).
///
/// # Safety
/// Output buffer and `return_length` must satisfy `PreviousMode`.
pub unsafe extern "C" fn NtQueryObject(
    object_handle: *mut c_void,
    class: u32,
    information: *mut u8,
    length: u32,
    return_length: *mut u32,
) -> NTSTATUS {
    const OBJECT_BASIC_INFORMATION: u32 = 0;
    const OBJECT_NAME_INFORMATION: u32 = 1;
    const OBJECT_TYPE_INFORMATION: u32 = 2;
    let mode = crate::svc::capture::mode();
    let (held, info) = match handle::reference_for(
        object_handle as u64,
        None,
        0,
        crate::svc::capture::handle_mode(mode),
    ) {
        Ok(found) => found,
        Err(st) => return st,
    };
    match class {
        OBJECT_BASIC_INFORMATION => {
            // `PUBLIC_OBJECT_BASIC_INFORMATION`: 56 bytes.
            let mut buf = [0u8; 56];
            buf[4..8].copy_from_slice(&info.granted.to_le_bytes());
            buf[8..12].copy_from_slice(&1u32.to_le_bytes()); // HandleCount
            buf[12..16].copy_from_slice(&1u32.to_le_bytes()); // PointerCount
            if !return_length.is_null() {
                // SAFETY: per the contract.
                if let Err(st) = unsafe { crate::svc::capture::write(return_length, 56u32, mode) } {
                    return st;
                }
            }
            if length < 56 {
                return STATUS_INFO_LENGTH_MISMATCH;
            }
            // SAFETY: per the contract.
            match unsafe { crate::svc::capture::copy_to_caller(information, &buf, mode) } {
                Ok(()) => STATUS_SUCCESS,
                Err(st) => st,
            }
        }
        OBJECT_NAME_INFORMATION => {
            // Return empty `UNICODE_STRING` when unnamed (16 bytes).
            let needed = size_of::<UNICODE_STRING>() as u32 + 2;
            if !return_length.is_null() {
                // SAFETY: per the contract.
                if let Err(st) = unsafe { crate::svc::capture::write(return_length, needed, mode) }
                {
                    return st;
                }
            }
            if length < needed {
                return STATUS_INFO_LENGTH_MISMATCH;
            }
            let buf_va = information.addr() + size_of::<UNICODE_STRING>();
            let us = UNICODE_STRING {
                Length: 0,
                MaximumLength: 2,
                Buffer: core::ptr::with_exposed_provenance_mut(buf_va),
            };
            let mut out = alloc::vec![0u8; needed as usize];
            // SAFETY: `UNICODE_STRING` is plain data.
            out[..size_of::<UNICODE_STRING>()].copy_from_slice(unsafe {
                core::slice::from_raw_parts(
                    (&raw const us).cast::<u8>(),
                    size_of::<UNICODE_STRING>(),
                )
            });
            // SAFETY: per the contract.
            match unsafe { crate::svc::capture::copy_to_caller(information, &out, mode) } {
                Ok(()) => STATUS_SUCCESS,
                Err(st) => st,
            }
        }
        OBJECT_TYPE_INFORMATION => {
            // `PUBLIC_OBJECT_TYPE_INFORMATION`: 104 bytes header (`UNICODE_STRING` + 22 u32s) + UTF-16 name + NUL.
            // SAFETY: `held` is a live object.
            let name = unsafe { object::type_of(held.body()).name() };
            let name_bytes = name.len() * 2;
            let hdr_size = 104usize;
            let total = hdr_size + name_bytes + 2;
            if !return_length.is_null() {
                // SAFETY: per the contract.
                let wr = unsafe { crate::svc::capture::write(return_length, total as u32, mode) };
                if let Err(st) = wr {
                    return st;
                }
            }
            if (length as usize) < total {
                return STATUS_INFO_LENGTH_MISMATCH;
            }
            let mut out = alloc::vec![0u8; total];
            let us = UNICODE_STRING {
                Length: name_bytes as u16,
                MaximumLength: (name_bytes + 2) as u16,
                Buffer: core::ptr::with_exposed_provenance_mut(information.addr() + hdr_size),
            };
            // SAFETY: `UNICODE_STRING` is plain data.
            out[..size_of::<UNICODE_STRING>()].copy_from_slice(unsafe {
                core::slice::from_raw_parts(
                    (&raw const us).cast::<u8>(),
                    size_of::<UNICODE_STRING>(),
                )
            });
            for (i, &unit) in name.iter().enumerate() {
                out[hdr_size + i * 2..hdr_size + i * 2 + 2].copy_from_slice(&unit.to_le_bytes());
            }
            // SAFETY: per the contract.
            match unsafe { crate::svc::capture::copy_to_caller(information, &out, mode) } {
                Ok(()) => STATUS_SUCCESS,
                Err(st) => st,
            }
        }
        _ => STATUS_INVALID_INFO_CLASS,
    }
}

// ---- tests --------------------------------------------------------------

use nk_ntabi::io::UNICODE_STRING;

/// `ZwCreateDirectoryObject` for `name` (none if empty), relative to
/// `root`, with `flags`: the status and the handle written.
fn create(name: &str, root: u64, flags: u32) -> (NTSTATUS, u64) {
    let mut text: alloc::vec::Vec<u16> = name.encode_utf16().collect();
    let string = UNICODE_STRING {
        Length: (text.len() * 2) as u16,
        MaximumLength: (text.len() * 2) as u16,
        Buffer: text.as_mut_ptr(),
    };
    let attributes = OBJECT_ATTRIBUTES {
        Length: size_of::<OBJECT_ATTRIBUTES>() as u32,
        RootDirectory: root as *mut c_void,
        ObjectName: if name.is_empty() {
            core::ptr::null()
        } else {
            &raw const string
        },
        Attributes: flags,
        SecurityDescriptor: core::ptr::null_mut(),
        SecurityQualityOfService: core::ptr::null_mut(),
    };
    let mut handle = 0x5A5A as *mut c_void;
    // SAFETY: locals that outlive the call.
    let status =
        unsafe { ZwCreateDirectoryObject(&raw mut handle, 0xF000F, &raw const attributes) };
    (status, handle as u64)
}

/// Whether `path` leads to something.
fn there(path: &str) -> Result<(), NTSTATUS> {
    let path: alloc::vec::Vec<u16> = path.encode_utf16().collect();
    super::lookup(None, &path)?;
    Ok(())
}

/// Directories made and unmade by handle, as `disk.sys` makes
/// `\Device\HarddiskN`: permanent and temporary names, what is in a
/// directory, and what is refused. Returns the directories asked for.
pub fn directory_test() -> Result<u32, &'static str> {
    use crate::mm::pool;
    const KERNEL: u32 = 0x240;
    const PERMANENT: u32 = KERNEL | OBJ_PERMANENT;
    const DISK: &str = "\\Device\\NkHarddisk7";
    let before = (super::count(), pool::usage().blocks, handle::count());
    let close = |handle: u64| handle::close(handle);

    // A temporary directory: its name goes with its last handle.
    let (status, temporary) = create("\\Device\\NkTemporary", 0, KERNEL);
    if status != STATUS_SUCCESS || there("\\Device\\NkTemporary").is_err() {
        return Err("a directory was not made by name");
    }
    close(temporary);
    if there("\\Device\\NkTemporary") != Err(STATUS_OBJECT_NAME_NOT_FOUND) {
        return Err("a temporary directory kept its name after its last handle closed");
    }

    // A permanent one, as disk.sys asks: it outlives its handle.
    let (status, disk) = create(DISK, 0, PERMANENT);
    if status != STATUS_SUCCESS || nk_ntabi::ob::handle_index(disk, false).is_some() {
        return Err("a permanent directory was not made, or its handle is no kernel handle");
    }
    close(disk);
    if there(DISK).is_err() {
        return Err("a permanent directory lost its name with its handle");
    }
    let verdict = (|| {
        // The name is taken; OBJ_OPENIF opens what has it.
        let taken = [
            create(DISK, 0, PERMANENT),
            create("\\DEVICE\\nkharddisk7", 0, KERNEL),
        ];
        if taken != [(STATUS_OBJECT_NAME_COLLISION, 0); 2] {
            return Err("a directory's name was given out again, or a handle written");
        }
        let (status, disk) = create(DISK, 0, KERNEL | OBJ_OPENIF);
        if status != STATUS_OBJECT_NAME_EXISTS {
            return Err("OBJ_OPENIF did not open the directory that has the name");
        }
        // Below it, by path and relative to its handle; a device-like
        // object in it, as `\Device\HarddiskN\DR0` is.
        let (status, part) = create("Partitions", disk, KERNEL);
        let wide: alloc::vec::Vec<u16> = "\\Device\\NkHarddisk7\\DR0".encode_utf16().collect();
        let Some(event) = object::create_named(
            &object::EVENT_TYPE,
            size_of::<nk_ntabi::ke::KEVENT>(),
            super::leaf(&wide),
        ) else {
            close(disk);
            close(part);
            return Err("no memory");
        };
        // SAFETY: a named object this test holds until it has taken
        // the name away again.
        let inserted = unsafe { super::insert(&wide, event) };
        let found = (
            there("\\Device\\NkHarddisk7\\Partitions"),
            there("\\Device\\NkHarddisk7\\DR0"),
        );
        // SAFETY: the event's header says where it is.
        let in_disk = unsafe { (*object::name_info(event)).Directory.cast::<u8>() };
        // The handle keeps the directory once the reference goes.
        let disk_body =
            handle::reference(disk, None).map_or(core::ptr::null_mut(), |held| held.body());
        // SAFETY: the running thread, an object nothing is below.
        let thread = unsafe { handle::open(crate::ke::thread::current().cast(), 0) }.unwrap_or(0);
        let refused = [
            create("\\Device\\NkHarddisk7\\DR0\\x", 0, KERNEL).0,
            create("\\Device\\NkHarddisk7\\DR0", 0, KERNEL | OBJ_OPENIF).0,
            create("\\NkNoDirectory\\x", 0, KERNEL).0,
            create("x", thread, KERNEL).0,
            create(DISK, 0, KERNEL | OBJ_OPENLINK).0,
            create(DISK, 0, KERNEL | OBJ_EXCLUSIVE).0,
            create(DISK, 0, 0x8000).0,
            create("NkRelative", 0, KERNEL).0,
        ];
        close(thread);
        close(part);
        // Made temporary with a handle open: the name stays until the
        // handle closes, and then goes though the directory is not
        // empty. What is in it is still in it, and it is still there.
        let temporary = ZwMakeTemporaryObject(disk as *mut c_void);
        let still = there(DISK);
        close(disk);
        let gone = (there(DISK), there("\\Device\\NkHarddisk7\\DR0"));
        // SAFETY: as above.
        let (after, name_left) = unsafe {
            let info = object::name_info(event);
            ((*info).Directory.cast::<u8>(), (*info).Name.Length)
        };
        // The name is free again while the old directory lives on.
        let (again_status, again) = create(DISK, 0, KERNEL);
        close(again);
        // SAFETY: the event made above: its name, then its reference.
        unsafe {
            super::remove(event);
            object::dereference(event);
        }
        if status != STATUS_SUCCESS || inserted != STATUS_SUCCESS || found != (Ok(()), Ok(())) {
            return Err("a directory made at run time does not hold directories and objects");
        }
        if in_disk.is_null() || in_disk != disk_body {
            return Err("an object in a directory made at run time does not say so");
        }
        if refused
            != [
                STATUS_OBJECT_TYPE_MISMATCH,
                STATUS_OBJECT_TYPE_MISMATCH,
                STATUS_OBJECT_PATH_NOT_FOUND,
                STATUS_INVALID_HANDLE,
                STATUS_INVALID_PARAMETER,
                STATUS_NOT_IMPLEMENTED,
                STATUS_INVALID_PARAMETER,
                STATUS_OBJECT_PATH_SYNTAX_BAD,
            ]
        {
            return Err("a directory that cannot be made was not refused with its own status");
        }
        if temporary != STATUS_SUCCESS || still.is_err() {
            return Err("a directory made temporary lost its name while a handle was open");
        }
        if gone
            != (
                Err(STATUS_OBJECT_NAME_NOT_FOUND),
                Err(STATUS_OBJECT_PATH_NOT_FOUND),
            )
        {
            return Err("a directory made temporary kept its name after its last handle closed");
        }
        if after != in_disk || name_left == 0 {
            return Err("an object left its directory when the directory lost its name");
        }
        if again_status != STATUS_SUCCESS {
            return Err("the name of a directory that lost it could not be used again");
        }
        Ok(())
    })();
    if verdict.is_err() {
        // Whatever is left of the permanent directory.
        let (status, disk) = create(DISK, 0, KERNEL | OBJ_OPENIF);
        if nt_success(status) {
            ZwMakeTemporaryObject(disk as *mut c_void);
            close(disk);
        }
    }
    verdict?;

    // Without a name: reached by handle alone, and gone with it.
    let (status, unnamed) = create("", 0, PERMANENT);
    let (below_status, below) = create("Below", unnamed, KERNEL);
    let (again_status, again) = create("below", unnamed, KERNEL | OBJ_OPENIF);
    let made_temporary = ZwMakeTemporaryObject(unnamed as *mut c_void);
    let no_handle = ZwMakeTemporaryObject(0x7FFC as *mut c_void);
    for handle in [again, below, unnamed] {
        close(handle);
    }
    if status != STATUS_SUCCESS
        || below_status != STATUS_SUCCESS
        || again_status != STATUS_OBJECT_NAME_EXISTS
    {
        return Err("a directory without a name does not hold a directory");
    }
    if made_temporary != STATUS_SUCCESS || no_handle != STATUS_INVALID_HANDLE {
        return Err("ZwMakeTemporaryObject did not answer for an unnamed directory or no handle");
    }
    let mut handle = core::ptr::null_mut();
    // SAFETY: no attributes at all, and a local for the handle.
    let status = unsafe { ZwCreateDirectoryObject(&raw mut handle, 0xF000F, core::ptr::null()) };
    close(handle as u64);
    if status != STATUS_SUCCESS {
        return Err("a directory was not made without object attributes");
    }
    if (super::count(), pool::usage().blocks, handle::count()) != before {
        return Err("directories, memory or handles were left behind");
    }
    Ok(17)
}

pub use crate::svc::zw::{ZwCreateDirectoryObject, ZwMakeTemporaryObject};
