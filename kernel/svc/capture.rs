//! Uniform argument capture and write-back for NT system services.
//!
//! Rules:
//! - When `PreviousMode == UserMode`, every caller pointer is probed against
//!   `MmUserProbeAddress` (`nk_mm::probe`) and copied through `mm::user::copy`
//!   (fault-protected). A fault returns `STATUS_ACCESS_VIOLATION`; misalignment
//!   returns `STATUS_DATATYPE_MISALIGNMENT`.
//! - When `PreviousMode == KernelMode`, caller pointers are trusted directly,
//!   matching Windows' `PreviousMode` contract.
//! - NK never creates a Rust reference (`&T` / `&mut T`) into user memory and
//!   never touches user memory while holding a spin lock.

use crate::ke::thread;
use crate::mm::user::{self, USER_PROBE_ADDRESS};
use alloc::vec::Vec;
use core::ffi::c_void;
use core::mem::{MaybeUninit, align_of, size_of};
use nk_mm::probe::{self, ProbeError};
use nk_ntabi::io::{KERNEL_MODE, UNICODE_STRING};
use nk_ntabi::ob::OBJECT_ATTRIBUTES;
use nk_ntabi::se::SECURITY_QUALITY_OF_SERVICE;
use nk_ntabi::status::*;
use nk_ob::handles::Mode;

/// `OBJ_KERNEL_HANDLE` (`wdm.h`): stripped when captured from user mode.
const OBJ_KERNEL_HANDLE: u32 = 0x200;
/// `OBJ_VALID_ATTRIBUTES` (`wdm.h`).
const OBJ_VALID_ATTRIBUTES: u32 = 0x1FF2;

/// Maximum captured byte buffer size for single-shot capture helpers (64 MiB).
const MAX_CAPTURE_BYTES: usize = 64 * 1024 * 1024;

/// Current thread's `PreviousMode` (`KERNEL_MODE` or `USER_MODE`).
#[inline]
pub fn mode() -> i8 {
    thread::previous_mode()
}

/// Whether `mode` represents a user-mode caller.
#[inline]
pub fn is_user(mode: i8) -> bool {
    mode != KERNEL_MODE
}

/// Convert `KPROCESSOR_MODE` into `nk_ob::handles::Mode`.
#[inline]
pub fn handle_mode(mode: i8) -> Mode {
    if is_user(mode) {
        Mode::User
    } else {
        Mode::Kernel
    }
}

fn map_probe(err: ProbeError) -> NTSTATUS {
    match err {
        ProbeError::AccessViolation => STATUS_ACCESS_VIOLATION,
        ProbeError::DatatypeMisalignment => STATUS_DATATYPE_MISALIGNMENT,
        ProbeError::InvalidParameter => STATUS_INVALID_PARAMETER,
    }
}

/// Probe `[addr, addr + len)` for reading by `mode`.
pub fn probe_read(addr: usize, len: usize, align: usize, mode: i8) -> Result<(), NTSTATUS> {
    if !is_user(mode) {
        return Ok(());
    }
    probe::check_range(addr as u64, len as u64, align as u64, USER_PROBE_ADDRESS)
        .map_err(map_probe)?;
    if !user::in_range(addr, len) {
        return Err(STATUS_ACCESS_VIOLATION);
    }
    Ok(())
}

/// Probe `[addr, addr + len)` for writing by `mode`, touching each page on
/// `UserMode` as Windows' `ProbeForWrite` does.
#[allow(dead_code)]
pub fn probe_write(addr: usize, len: usize, align: usize, mode: i8) -> Result<(), NTSTATUS> {
    probe_read(addr, len, align, mode)?;
    if is_user(mode) && len > 0 {
        user::probe_pages(addr, len).map_err(|_| STATUS_ACCESS_VIOLATION)?;
    }
    Ok(())
}

/// Read a `Copy` value from `ptr` using fault-protected copy for `UserMode`.
///
/// # Safety
/// For `KernelMode`, `ptr` must be valid for reading `size_of::<T>()` bytes.
pub unsafe fn read<T: Copy>(ptr: *const T, mode: i8) -> Result<T, NTSTATUS> {
    if !is_user(mode) {
        // SAFETY: kernel-mode caller contract.
        return Ok(unsafe { ptr.read_unaligned() });
    }
    probe_read(ptr.addr(), size_of::<T>(), 1, mode)?;
    let mut slot = MaybeUninit::<T>::uninit();
    // SAFETY: `slot` is kernel stack memory; `ptr` is probed in user range.
    unsafe {
        user::copy(
            slot.as_mut_ptr().cast::<u8>(),
            ptr.cast::<u8>(),
            size_of::<T>(),
        )
    }
    .map_err(|_| STATUS_ACCESS_VIOLATION)?;
    // SAFETY: `user::copy` initialized all `size_of::<T>()` bytes.
    Ok(unsafe { slot.assume_init() })
}

/// Read an aligned `Copy` value from `ptr` (`align_of::<T>()` checked for `UserMode`).
///
/// # Safety
/// For `KernelMode`, `ptr` must be valid for reading `size_of::<T>()` bytes.
#[allow(dead_code)]
pub unsafe fn read_aligned<T: Copy>(ptr: *const T, mode: i8) -> Result<T, NTSTATUS> {
    if is_user(mode) {
        probe_read(ptr.addr(), size_of::<T>(), align_of::<T>(), mode)?;
    }
    // SAFETY: caller contract (kernel) or probed above (user).
    unsafe { read(ptr, mode) }
}

/// Write a `Copy` value to `ptr` using fault-protected copy for `UserMode`.
///
/// # Safety
/// For `KernelMode`, `ptr` must be valid for writing `size_of::<T>()` bytes.
pub unsafe fn write<T: Copy>(ptr: *mut T, value: T, mode: i8) -> Result<(), NTSTATUS> {
    if !is_user(mode) {
        // SAFETY: kernel-mode caller contract.
        unsafe { ptr.write_unaligned(value) };
        return Ok(());
    }
    probe_read(ptr.addr(), size_of::<T>(), 1, mode)?;
    // SAFETY: `&raw const value` is kernel stack memory; `ptr` is in user range.
    unsafe {
        user::copy(
            ptr.cast::<u8>(),
            core::ptr::from_ref(&value).cast::<u8>(),
            size_of::<T>(),
        )
    }
    .map_err(|_| STATUS_ACCESS_VIOLATION)
}

/// Write an aligned `Copy` value to `ptr` (`align_of::<T>()` checked for `UserMode`).
///
/// # Safety
/// For `KernelMode`, `ptr` must be valid for writing `size_of::<T>()` bytes.
#[allow(dead_code)]
pub unsafe fn write_aligned<T: Copy>(ptr: *mut T, value: T, mode: i8) -> Result<(), NTSTATUS> {
    if is_user(mode) {
        probe_read(ptr.addr(), size_of::<T>(), align_of::<T>(), mode)?;
    }
    // SAFETY: caller contract (kernel) or probed above (user).
    unsafe { write(ptr, value, mode) }
}

/// Copy `dst.len()` bytes from caller memory `src` into kernel slice `dst`.
///
/// # Safety
/// For `KernelMode`, `src` must be readable for `dst.len()` bytes.
pub unsafe fn copy_from_caller(dst: &mut [u8], src: *const u8, mode: i8) -> Result<(), NTSTATUS> {
    if dst.is_empty() {
        return Ok(());
    }
    if !is_user(mode) {
        // SAFETY: kernel-mode caller contract.
        unsafe { core::ptr::copy_nonoverlapping(src, dst.as_mut_ptr(), dst.len()) };
        return Ok(());
    }
    probe_read(src.addr(), dst.len(), 1, mode)?;
    // SAFETY: `dst` is kernel memory; `src` is probed in user range.
    unsafe { user::copy(dst.as_mut_ptr(), src, dst.len()) }.map_err(|_| STATUS_ACCESS_VIOLATION)
}

/// Copy `src` from kernel memory into caller memory `dst`.
///
/// # Safety
/// For `KernelMode`, `dst` must be writable for `src.len()` bytes.
pub unsafe fn copy_to_caller(dst: *mut u8, src: &[u8], mode: i8) -> Result<(), NTSTATUS> {
    if src.is_empty() {
        return Ok(());
    }
    if !is_user(mode) {
        // SAFETY: kernel-mode caller contract.
        unsafe { core::ptr::copy_nonoverlapping(src.as_ptr(), dst, src.len()) };
        return Ok(());
    }
    probe_read(dst.addr(), src.len(), 1, mode)?;
    // SAFETY: `src` is kernel memory; `dst` is probed in user range.
    unsafe { user::copy(dst, src.as_ptr(), src.len()) }.map_err(|_| STATUS_ACCESS_VIOLATION)
}

/// Copy `len` bytes from caller pointer `ptr` into a freshly allocated `Vec<u8>`.
///
/// # Safety
/// For `KernelMode`, `ptr` must be readable for `len` bytes (when `len > 0`).
pub unsafe fn capture_bytes(ptr: *const u8, len: usize, mode: i8) -> Result<Vec<u8>, NTSTATUS> {
    if len == 0 {
        return Ok(Vec::new());
    }
    if len > MAX_CAPTURE_BYTES {
        return Err(STATUS_INSUFFICIENT_RESOURCES);
    }
    if is_user(mode) {
        probe_read(ptr.addr(), len, 1, mode)?;
    } else if ptr.is_null() {
        return Err(STATUS_ACCESS_VIOLATION);
    }
    let mut out = Vec::new();
    if out.try_reserve_exact(len).is_err() {
        return Err(STATUS_INSUFFICIENT_RESOURCES);
    }
    out.resize(len, 0);
    // SAFETY: `out` has `len` bytes; caller contract or probed above.
    unsafe { copy_from_caller(&mut out, ptr, mode) }?;
    Ok(out)
}

/// Capture a caller `UNICODE_STRING` into kernel memory.
///
/// A null `ptr` returns an empty `Vec<u16>`. For `UserMode`, validates
/// alignment and bounds of both the `UNICODE_STRING` header and its UTF-16
/// buffer.
///
/// # Safety
/// For `KernelMode`, `ptr` is null or points to a valid `UNICODE_STRING`.
pub unsafe fn capture_unicode_string(
    ptr: *const UNICODE_STRING,
    mode: i8,
) -> Result<Vec<u16>, NTSTATUS> {
    if ptr.is_null() {
        return Ok(Vec::new());
    }
    if !is_user(mode) {
        // SAFETY: kernel-mode caller contract.
        return Ok(unsafe { crate::rtl::copy_unicode(ptr) });
    }
    // SAFETY: `read` probes and fault-copies from user memory.
    let header = unsafe { read(ptr, mode) }?;
    let units = probe::check_unicode_string(
        header.Length,
        header.MaximumLength,
        header.Buffer.addr() as u64,
        USER_PROBE_ADDRESS,
    )
    .map_err(map_probe)?;
    if units == 0 {
        return Ok(Vec::new());
    }
    let byte_len = units * 2;
    if !user::in_range(header.Buffer.addr(), byte_len) {
        return Err(STATUS_ACCESS_VIOLATION);
    }
    let mut out = Vec::new();
    if out.try_reserve_exact(units).is_err() {
        return Err(STATUS_INSUFFICIENT_RESOURCES);
    }
    out.resize(units, 0);
    // SAFETY: `out` holds `byte_len` writable bytes; `header.Buffer` is probed.
    unsafe {
        user::copy(
            out.as_mut_ptr().cast::<u8>(),
            header.Buffer.cast::<u8>(),
            byte_len,
        )
    }
    .map_err(|_| STATUS_ACCESS_VIOLATION)?;
    Ok(out)
}

/// Kernel copy of a caller's `OBJECT_ATTRIBUTES`.
pub struct CapturedObjectAttributes {
    pub root: *mut c_void,
    pub name: Option<Vec<u16>>,
    pub attributes: u32,
    #[allow(dead_code)]
    pub security_descriptor: *mut c_void,
    pub qos: Option<SECURITY_QUALITY_OF_SERVICE>,
}

/// Capture an optional `OBJECT_ATTRIBUTES` into kernel memory.
///
/// Validates `Length == size_of::<OBJECT_ATTRIBUTES>()` and
/// `OBJ_VALID_ATTRIBUTES`. For `UserMode`, strips `OBJ_KERNEL_HANDLE` as
/// Windows' `ObpCaptureObjectAttributes` does.
///
/// # Safety
/// For `KernelMode`, `ptr` is null or points to a valid `OBJECT_ATTRIBUTES`.
pub unsafe fn capture_object_attributes(
    ptr: *const OBJECT_ATTRIBUTES,
    mode: i8,
) -> Result<Option<CapturedObjectAttributes>, NTSTATUS> {
    if ptr.is_null() {
        return Ok(None);
    }
    // SAFETY: kernel-mode contract or fault-protected user read.
    let raw = unsafe { read(ptr, mode) }?;
    if raw.Length as usize != size_of::<OBJECT_ATTRIBUTES>() {
        return Err(STATUS_INVALID_PARAMETER);
    }
    let mut attributes = raw.Attributes;
    if is_user(mode) {
        attributes &= !OBJ_KERNEL_HANDLE;
    }
    if attributes & !OBJ_VALID_ATTRIBUTES != 0 {
        return Err(STATUS_INVALID_PARAMETER);
    }
    let name = if raw.ObjectName.is_null() {
        None
    } else {
        // SAFETY: kernel contract or fault-protected user capture.
        Some(unsafe { capture_unicode_string(raw.ObjectName, mode) }?)
    };
    let qos = if raw.SecurityQualityOfService.is_null() {
        None
    } else {
        // SAFETY: kernel contract or fault-protected user read.
        Some(unsafe {
            read(
                raw.SecurityQualityOfService
                    .cast::<SECURITY_QUALITY_OF_SERVICE>(),
                mode,
            )
        }?)
    };
    Ok(Some(CapturedObjectAttributes {
        root: raw.RootDirectory,
        name,
        attributes,
        security_descriptor: raw.SecurityDescriptor,
        qos,
    }))
}

/// Exercise `capture` with a mapped user page, invalid/kernel pointers,
/// misalignment, `UNICODE_STRING`, and `OBJECT_ATTRIBUTES`.
pub fn self_test() -> Result<(), &'static str> {
    use nk_ntabi::io::USER_MODE;
    let va = user::USER_PROBE_ADDRESS - 2 * crate::mm::PAGE_SIZE as u64;
    user::map_pages(va, 1).map_err(|_| "capture test: cannot map user page")?;
    let result = (|| {
        let base = core::ptr::with_exposed_provenance_mut::<u8>(va as usize);
        // 1. Kernel pointer rejected for UserMode.
        let klocal = 0x1234_5678u32;
        // SAFETY: intentionally testing kernel-address rejection in UserMode.
        if unsafe { read(&raw const klocal, USER_MODE) } != Err(STATUS_ACCESS_VIOLATION) {
            return Err("capture::read accepted a kernel pointer from UserMode");
        }
        // 2. Misaligned aligned-read rejected with STATUS_DATATYPE_MISALIGNMENT.
        // SAFETY: testing alignment rejection in UserMode.
        let unaligned = unsafe { base.add(1).cast::<u32>() };
        // SAFETY: probed in UserMode.
        if unsafe { read_aligned(unaligned, USER_MODE) } != Err(STATUS_DATATYPE_MISALIGNMENT) {
            return Err("capture::read_aligned did not return STATUS_DATATYPE_MISALIGNMENT");
        }
        // 3. Unmapped user page rejected with STATUS_ACCESS_VIOLATION.
        let unmapped =
            core::ptr::with_exposed_provenance::<u32>(va as usize + crate::mm::PAGE_SIZE);
        // SAFETY: probed in UserMode.
        if unsafe { read(unmapped, USER_MODE) } != Err(STATUS_ACCESS_VIOLATION) {
            return Err("capture::read on unmapped page did not return STATUS_ACCESS_VIOLATION");
        }
        // 4. Write + read round trip on mapped user page.
        let word = base.cast::<u64>();
        // SAFETY: mapped user page.
        unsafe { write_aligned(word, 0xDEAD_BEEF_CAFE_BABEu64, USER_MODE) }
            .map_err(|_| "capture::write_aligned failed on mapped user page")?;
        // SAFETY: mapped user page.
        let got = unsafe { read_aligned(word, USER_MODE) }
            .map_err(|_| "capture::read_aligned failed on mapped user page")?;
        if got != 0xDEAD_BEEF_CAFE_BABE {
            return Err("capture write/read round trip mismatch");
        }
        // 5. OBJECT_ATTRIBUTES + UNICODE_STRING capture strips OBJ_KERNEL_HANDLE.
        let chars: [u16; 2] = [u16::from(b'O'), u16::from(b'K')];
        // SAFETY: mapped user page.
        let str_buf = unsafe { base.add(0x100).cast::<u16>() };
        // SAFETY: mapped user page.
        unsafe { copy_to_caller(str_buf.cast(), &[b'O', 0, b'K', 0], USER_MODE) }
            .map_err(|_| "copy_to_caller failed for string")?;
        // SAFETY: mapped user page.
        let us_ptr = unsafe { base.add(0x120).cast::<UNICODE_STRING>() };
        // SAFETY: mapped user page.
        unsafe {
            write(
                us_ptr,
                UNICODE_STRING {
                    Length: 4,
                    MaximumLength: 4,
                    Buffer: str_buf,
                },
                USER_MODE,
            )
        }
        .map_err(|_| "write UNICODE_STRING failed")?;
        // SAFETY: mapped user page.
        let oa_ptr = unsafe { base.add(0x140).cast::<OBJECT_ATTRIBUTES>() };
        // SAFETY: mapped user page.
        unsafe {
            write(
                oa_ptr,
                OBJECT_ATTRIBUTES {
                    Length: size_of::<OBJECT_ATTRIBUTES>() as u32,
                    RootDirectory: core::ptr::null_mut(),
                    ObjectName: us_ptr.cast_const(),
                    Attributes: 0x40 | OBJ_KERNEL_HANDLE,
                    SecurityDescriptor: core::ptr::null_mut(),
                    SecurityQualityOfService: core::ptr::null_mut(),
                },
                USER_MODE,
            )
        }
        .map_err(|_| "write OBJECT_ATTRIBUTES failed")?;
        // SAFETY: mapped user page.
        let oa = unsafe { capture_object_attributes(oa_ptr, USER_MODE) }
            .map_err(|_| "capture_object_attributes failed")?
            .ok_or("capture_object_attributes returned None")?;
        if oa.attributes != 0x40 || oa.name.as_deref() != Some(&chars[..]) {
            return Err("capture_object_attributes did not strip OBJ_KERNEL_HANDLE or copy name");
        }
        Ok(())
    })();
    user::unmap_pages(va, 1);
    result
}
