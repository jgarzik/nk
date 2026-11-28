//! A volume's GUID name, as the mount point manager knows it:
//! `IoVolumeDeviceToGuidPath` and `IoVolumeDeviceToGuid`, done as the
//! pinned kernel does them. The volume device is asked its name
//! (`IOCTL_MOUNTDEV_QUERY_DEVICE_NAME`), the mount point manager the
//! mount points of that name (`IOCTL_MOUNTMGR_QUERY_POINTS`), and the
//! first link of the form `\??\Volume...` is the answer. Without the
//! mount point manager the open of `\Device\MountPointManager` fails,
//! and so do they, with the output untouched, as on Windows.

#![allow(non_snake_case)]

use super::{build, irp};
use crate::mm::pool;
use crate::ob::object;
use crate::{ke, rtl};
use alloc::vec::Vec;
use core::ffi::c_void;
use nk_ntabi::io::*;
use nk_ntabi::status::*;

const IOCTL_MOUNTDEV_QUERY_DEVICE_NAME: u32 = 0x004D_0008;
const IOCTL_MOUNTMGR_QUERY_POINTS: u32 = 0x006D_0008;
const STATUS_NOT_FOUND: NTSTATUS = 0xC000_0225_u32 as NTSTATUS;
const STATUS_BUFFER_OVERFLOW: NTSTATUS = 0x8000_0005_u32 as NTSTATUS;
const TAG: u32 = u32::from_le_bytes(*b"IoVg");
/// `MOUNTMGR_MOUNT_POINT`: three offset-and-length pairs.
const MOUNT_POINT: usize = 0x18;

/// Send `code` to `device` and wait: the status and the bytes returned.
///
/// # Safety
/// `device` is live; the buffers are writable for their lengths.
unsafe fn control(
    device: *mut DEVICE_OBJECT,
    code: u32,
    input: &mut [u8],
    output: &mut [u8],
) -> (NTSTATUS, usize) {
    // SAFETY: per the contract; event and status block outlive the wait.
    unsafe {
        let mut event = core::mem::zeroed::<KEVENT>();
        ke::wait::KeInitializeEvent(&raw mut event, 0, 0);
        let mut iosb = IO_STATUS_BLOCK {
            Status: 0,
            Information: 0,
        };
        let request = build::IoBuildDeviceIoControlRequest(
            code,
            device,
            input.as_mut_ptr().cast(),
            input.len() as u32,
            output.as_mut_ptr().cast(),
            output.len() as u32,
            0,
            &raw mut event,
            &raw mut iosb,
        );
        if request.is_null() {
            return (STATUS_INSUFFICIENT_RESOURCES, 0);
        }
        let mut status = irp::IofCallDriver(device, request);
        if status == STATUS_PENDING {
            ke::wait::wait(Some((&raw mut event).cast()), None);
            status = iosb.Status;
        }
        (status, iosb.Information)
    }
}

/// The `\??\Volume...` link the mount point manager has for the device
/// named `name`.
fn guid_path_of(name: &[u16]) -> Result<Vec<u16>, NTSTATUS> {
    let mut manager: Vec<u16> = "\\Device\\MountPointManager".encode_utf16().collect();
    let manager = UNICODE_STRING {
        Length: (manager.len() * 2) as u16,
        MaximumLength: (manager.len() * 2) as u16,
        Buffer: manager.as_mut_ptr(),
    };
    let (mut file, mut device) = (core::ptr::null_mut(), core::ptr::null_mut());
    // SAFETY: the name and the two outputs are locals.
    let status = unsafe {
        super::file::IoGetDeviceObjectPointer(
            &raw const manager,
            0x80,
            &raw mut file,
            &raw mut device,
        )
    };
    if !nt_success(status) {
        return Err(status);
    }
    let mut input = alloc::vec![0u8; MOUNT_POINT + name.len() * 2];
    input[16..20].copy_from_slice(&(MOUNT_POINT as u32).to_le_bytes());
    input[20..22].copy_from_slice(&((name.len() * 2) as u16).to_le_bytes());
    for (i, c) in name.iter().enumerate() {
        input[MOUNT_POINT + 2 * i..MOUNT_POINT + 2 * i + 2].copy_from_slice(&c.to_le_bytes());
    }
    let mut output = alloc::vec![0u8; 8 + MOUNT_POINT];
    // SAFETY: the manager's device, held by the file object.
    let mut answer =
        unsafe { control(device, IOCTL_MOUNTMGR_QUERY_POINTS, &mut input, &mut output) };
    if answer.0 == STATUS_BUFFER_OVERFLOW {
        let size = u32::from_le_bytes(output[..4].try_into().unwrap_or_default()) as usize;
        output = alloc::vec![0u8; size.max(8)];
        // SAFETY: as above.
        answer = unsafe { control(device, IOCTL_MOUNTMGR_QUERY_POINTS, &mut input, &mut output) };
    }
    // SAFETY: the reference IoGetDeviceObjectPointer gave.
    unsafe { object::dereference(file.cast()) };
    if !nt_success(answer.0) {
        return Err(answer.0);
    }
    let word = |at: usize| {
        u32::from_le_bytes(
            output
                .get(at..at + 4)
                .and_then(|b| b.try_into().ok())
                .unwrap_or_default(),
        ) as usize
    };
    let prefix: Vec<u16> = "\\??\\Volume".encode_utf16().collect();
    for point in 0..word(4) {
        let base = 8 + point * MOUNT_POINT;
        let (offset, length) = (word(base), word(base + 4) & 0xFFFF);
        let Some(bytes) = output.get(offset..offset + length) else {
            continue;
        };
        let link: Vec<u16> = bytes
            .as_chunks::<2>()
            .0
            .iter()
            .map(|&b| u16::from_le_bytes(b))
            .collect();
        let upper = |c: u16| {
            if (u16::from(b'a')..=u16::from(b'z')).contains(&c) {
                c - 32
            } else {
                c
            }
        };
        if link.len() >= prefix.len()
            && link
                .iter()
                .zip(&prefix)
                .all(|(&a, &b)| upper(a) == upper(b))
        {
            return Ok(link);
        }
    }
    Err(STATUS_NOT_FOUND)
}

/// [`IoVolumeDeviceToGuidPath`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-iovolumedevicetoguidpath):
/// the volume's `\??\Volume{...}` name, in pool the caller frees.
///
/// # Safety
/// `volume` is a live device; `path` is writable. At `PASSIVE_LEVEL`.
pub unsafe extern "C" fn IoVolumeDeviceToGuidPath(
    volume: *mut DEVICE_OBJECT,
    path: *mut UNICODE_STRING,
) -> NTSTATUS {
    // SAFETY: per the contract.
    unsafe {
        if !matches!((*volume).DeviceType, 0x02 | 0x07 | 0x1F | 0x24) {
            return STATUS_INVALID_PARAMETER;
        }
        let mut output = [0u8; 0x200];
        let (status, _) = control(
            volume,
            IOCTL_MOUNTDEV_QUERY_DEVICE_NAME,
            &mut [],
            &mut output,
        );
        if !nt_success(status) {
            return status;
        }
        let length = usize::from(u16::from_le_bytes([output[0], output[1]]).min(0x1FE));
        let name: Vec<u16> = output[2..2 + length]
            .as_chunks::<2>()
            .0
            .iter()
            .map(|&b| u16::from_le_bytes(b))
            .collect();
        let link = match guid_path_of(&name) {
            Ok(link) => link,
            Err(status) => return status,
        };
        let buffer = pool::alloc(link.len() * 2, TAG).cast::<u16>();
        if buffer.is_null() {
            return STATUS_INSUFFICIENT_RESOURCES;
        }
        core::ptr::copy_nonoverlapping(link.as_ptr(), buffer, link.len());
        path.write(UNICODE_STRING {
            Length: (link.len() * 2) as u16,
            MaximumLength: (link.len() * 2) as u16,
            Buffer: buffer,
        });
        STATUS_SUCCESS
    }
}

/// [`IoVolumeDeviceToGuid`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-iovolumedevicetoguid):
/// the GUID in the volume's GUID name.
///
/// # Safety
/// `volume` is a live device; `guid` is writable. At `PASSIVE_LEVEL`.
pub unsafe extern "C" fn IoVolumeDeviceToGuid(
    volume: *mut DEVICE_OBJECT,
    guid: *mut c_void,
) -> NTSTATUS {
    // SAFETY: per the contract.
    unsafe {
        let mut path = core::mem::zeroed::<UNICODE_STRING>();
        let status = IoVolumeDeviceToGuidPath(volume, &raw mut path);
        if !nt_success(status) {
            return status;
        }
        // The braces and what is between them, after `\??\Volume`.
        let skip = 10usize.min(usize::from(path.Length) / 2);
        let braced = UNICODE_STRING {
            Length: path.Length - (skip * 2) as u16,
            MaximumLength: path.Length - (skip * 2) as u16,
            Buffer: path.Buffer.add(skip),
        };
        let status = rtl::counted::RtlGUIDFromString(&raw const braced, guid.cast());
        let _ = pool::free(path.Buffer.cast());
        status
    }
}
