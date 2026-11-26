//! The length encodings of memory and port resource descriptors. The
//! rules are `nk_rtl::resource`; here a driver's descriptor is read and
//! written field by field.

#![allow(non_snake_case)]

use nk_ntabi::resource::{CM_PARTIAL_RESOURCE_DESCRIPTOR, IO_RESOURCE_DESCRIPTOR};
use nk_ntabi::status::*;
use nk_rtl::resource::{self, EncodeError};

/// Store `value` through `to` unless it is null.
///
/// # Safety
/// `to` is null or writable.
unsafe fn store<T>(to: *mut T, value: T) {
    if !to.is_null() {
        // SAFETY: per the contract.
        unsafe { to.write_unaligned(value) };
    }
}

/// [`RtlCmDecodeMemIoResource`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-rtlcmdecodememioresource):
/// the length in bytes of a port or memory resource, and where it
/// starts.
///
/// # Safety
/// `descriptor` is readable and `start` is null or writable.
pub unsafe extern "C" fn RtlCmDecodeMemIoResource(
    descriptor: *const CM_PARTIAL_RESOURCE_DESCRIPTOR,
    start: *mut u64,
) -> u64 {
    // SAFETY: per the contract.
    unsafe {
        let generic = &raw const (*descriptor).u.Generic;
        store(start, (&raw const (*generic).Start).read_unaligned() as u64);
        resource::cm_decode(
            (&raw const (*descriptor).Type).read(),
            (&raw const (*descriptor).Flags).read_unaligned(),
            (&raw const (*generic).Length).read_unaligned(),
        )
    }
}

/// [`RtlCmEncodeMemIoResource`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-rtlcmencodememioresource):
/// make `descriptor` a port or memory resource of `length` bytes at
/// `start`. A length no encoding holds is `STATUS_UNSUCCESSFUL`, with
/// the start stored and the large-memory flags cleared, as on Windows.
///
/// # Safety
/// `descriptor` is writable.
pub unsafe extern "C" fn RtlCmEncodeMemIoResource(
    descriptor: *mut CM_PARTIAL_RESOURCE_DESCRIPTOR,
    resource_type: u8,
    length: u64,
    start: u64,
) -> NTSTATUS {
    // SAFETY: per the contract.
    unsafe {
        let flags = &raw mut (*descriptor).Flags;
        let generic = &raw mut (*descriptor).u.Generic;
        let encoded = resource::encode(resource_type, flags.read_unaligned(), length, 0);
        if encoded != Err(EncodeError::InvalidParameter) {
            (&raw mut (*generic).Start).write_unaligned(start as i64);
        }
        match encoded {
            Ok(encoded) => {
                (&raw mut (*descriptor).Type).write(encoded.resource_type);
                flags.write_unaligned(encoded.flags);
                (&raw mut (*generic).Length).write_unaligned(encoded.length);
                STATUS_SUCCESS
            }
            Err(EncodeError::Unsuccessful { flags: cleared }) => {
                flags.write_unaligned(cleared);
                STATUS_UNSUCCESSFUL
            }
            Err(EncodeError::InvalidParameter) => STATUS_INVALID_PARAMETER,
        }
    }
}

/// [`RtlIoDecodeMemIoResource`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-rtliodecodememioresource):
/// the length in bytes of a port or memory requirement, its alignment
/// and the range it may come from.
///
/// # Safety
/// `descriptor` is readable and each of the others is null or writable.
pub unsafe extern "C" fn RtlIoDecodeMemIoResource(
    descriptor: *const IO_RESOURCE_DESCRIPTOR,
    alignment: *mut u64,
    minimum: *mut u64,
    maximum: *mut u64,
) -> u64 {
    // SAFETY: per the contract.
    unsafe {
        let generic = &raw const (*descriptor).u.Generic;
        let (length, aligned) = resource::io_decode(
            (&raw const (*descriptor).Type).read(),
            (&raw const (*descriptor).Flags).read_unaligned(),
            (&raw const (*generic).Length).read_unaligned(),
            (&raw const (*generic).Alignment).read_unaligned(),
        );
        store(alignment, aligned);
        store(
            minimum,
            (&raw const (*generic).MinimumAddress).read_unaligned() as u64,
        );
        store(
            maximum,
            (&raw const (*generic).MaximumAddress).read_unaligned() as u64,
        );
        length
    }
}

/// [`RtlIoEncodeMemIoResource`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-rtlioencodememioresource):
/// make `descriptor` a port or memory requirement. What no encoding
/// holds is `STATUS_UNSUCCESSFUL`, with the range stored and the
/// large-memory flags cleared, as on Windows.
///
/// # Safety
/// `descriptor` is writable.
pub unsafe extern "C" fn RtlIoEncodeMemIoResource(
    descriptor: *mut IO_RESOURCE_DESCRIPTOR,
    resource_type: u8,
    length: u64,
    alignment: u64,
    minimum: u64,
    maximum: u64,
) -> NTSTATUS {
    // SAFETY: per the contract.
    unsafe {
        let flags = &raw mut (*descriptor).Flags;
        let generic = &raw mut (*descriptor).u.Generic;
        let encoded = resource::encode(resource_type, flags.read_unaligned(), length, alignment);
        if encoded != Err(EncodeError::InvalidParameter) {
            (&raw mut (*generic).MinimumAddress).write_unaligned(minimum as i64);
            (&raw mut (*generic).MaximumAddress).write_unaligned(maximum as i64);
        }
        match encoded {
            Ok(encoded) => {
                (&raw mut (*descriptor).Type).write(encoded.resource_type);
                flags.write_unaligned(encoded.flags);
                (&raw mut (*generic).Length).write_unaligned(encoded.length);
                (&raw mut (*generic).Alignment).write_unaligned(encoded.alignment);
                STATUS_SUCCESS
            }
            Err(EncodeError::Unsuccessful { flags: cleared }) => {
                flags.write_unaligned(cleared);
                STATUS_UNSUCCESSFUL
            }
            Err(EncodeError::InvalidParameter) => STATUS_INVALID_PARAMETER,
        }
    }
}

/// [`RtlFindClosestEncodableLength`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-rtlfindclosestencodablelength).
///
/// # Safety
/// `target` is writable.
pub unsafe extern "C" fn RtlFindClosestEncodableLength(source: u64, target: *mut u64) -> NTSTATUS {
    let (length, found) = resource::closest_encodable(source);
    // SAFETY: per the contract.
    unsafe { target.write_unaligned(length) };
    if found {
        STATUS_SUCCESS
    } else {
        STATUS_UNSUCCESSFUL
    }
}
