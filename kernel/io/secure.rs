//! `IoCreateDeviceSecure`: a device made with the security an SDDL
//! string describes, which Microsoft's device-security library
//! (`wdmsec.lib`) asks the kernel for by name before falling back on a
//! copy of its own.

#![allow(non_snake_case)]

use core::ffi::c_void;
use nk_ntabi::io::*;
use nk_ntabi::status::*;
use nk_se::sddl::{self, SddlError};

/// The parts of a descriptor `ObSetSecurityObjectByPointer` is told to
/// set.
const OWNER_SECURITY_INFORMATION: u32 = 0x1;
const GROUP_SECURITY_INFORMATION: u32 = 0x2;
const DACL_SECURITY_INFORMATION: u32 = 0x4;

/// [`IoCreateDeviceSecure`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdmsec/nf-wdmsec-wdmlibiocreatedevicesecure):
/// `IoCreateDevice`, then the descriptor `sddl` describes set on the new
/// device: those of its parts the string gives, as the pinned kernel's
/// `IopDevObjApplyPostCreationSettings` sets them. No string is
/// `STATUS_INVALID_PARAMETER`; one that is not SDDL is
/// `STATUS_INVALID_PARAMETER` and makes no device; SDDL NK does not
/// understand (`nk_se::sddl`) stops the system naming it.
///
/// With a class GUID, Windows first reads the class's settings
/// (`Control\Class\{guid}\Properties`), which may override the type,
/// characteristics, exclusivity and descriptor. A class with no such
/// key overrides nothing; one that has the key stops the system, as NK
/// does not apply them.
///
/// # Safety
/// As `IoCreateDevice`; `sddl` and `class` are null or valid.
pub unsafe extern "C" fn IoCreateDeviceSecure(
    driver: *mut DRIVER_OBJECT,
    extension_size: u32,
    name: *const UNICODE_STRING,
    device_type: u32,
    characteristics: u32,
    exclusive: u8,
    sddl_string: *const UNICODE_STRING,
    class: *const nk_ntabi::rtl::GUID,
    device_out: *mut *mut DEVICE_OBJECT,
) -> NTSTATUS {
    // SAFETY: per the contract.
    unsafe { device_out.write(core::ptr::null_mut()) };
    if sddl_string.is_null() {
        return STATUS_INVALID_PARAMETER;
    }
    if !class.is_null() {
        // SAFETY: per the contract.
        let guid = unsafe { class.read_unaligned() };
        let text = nk_rtl::string::guid_text(guid.Data1, guid.Data2, guid.Data3, &guid.Data4);
        let key = alloc::format!(
            "Machine\\System\\CurrentControlSet\\Control\\Class\\{}\\Properties",
            alloc::string::String::from_utf16_lossy(&text)
        );
        if crate::cm::exists(&key) {
            crate::kd::bugcheck(format_args!(
                "IoCreateDeviceSecure: NK does not apply the settings of device class {key}"
            ));
        }
    }
    // SAFETY: per the contract.
    let wide = unsafe { crate::rtl::copy_unicode(sddl_string) };
    let Ok(text) = alloc::string::String::from_utf16(&wide) else {
        return STATUS_INVALID_PARAMETER;
    };
    let descriptor = match sddl::parse(&text) {
        Ok(descriptor) => descriptor,
        Err(SddlError::Invalid) => return STATUS_INVALID_PARAMETER,
        Err(SddlError::Unsupported(part)) => crate::kd::bugcheck(format_args!(
            "IoCreateDeviceSecure: NK does not understand `{part}` in the SDDL string {text}"
        )),
    };
    let mut device = core::ptr::null_mut();
    // SAFETY: per the contract.
    let status = unsafe {
        super::device::IoCreateDevice(
            driver,
            extension_size,
            name,
            device_type,
            characteristics,
            exclusive,
            &raw mut device,
        )
    };
    if status < 0 {
        return status;
    }
    let parts = nk_se::parse_relative(&descriptor);
    let information = parts.map_or(0, |p| {
        (if p.owner.is_some() {
            OWNER_SECURITY_INFORMATION
        } else {
            0
        }) | (if p.group.is_some() {
            GROUP_SECURITY_INFORMATION
        } else {
            0
        }) | (if p.dacl.is_some() {
            DACL_SECURITY_INFORMATION
        } else {
            0
        })
    });
    // SAFETY: the device just made, referenced by its creation; the
    // descriptor is self-relative and whole.
    let status = unsafe {
        crate::se::ObSetSecurityObjectByPointer(
            device.cast(),
            information,
            descriptor.as_ptr().cast::<c_void>(),
        )
    };
    if status < 0 {
        // SAFETY: the device made above, which nothing else knows of.
        unsafe { super::device::IoDeleteDevice(device) };
        return status;
    }
    // SAFETY: per the contract.
    unsafe { device_out.write(device) };
    STATUS_SUCCESS
}
