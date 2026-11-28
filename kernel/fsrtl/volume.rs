//! A file system's report of an event on its volume
//! ([`FsRtlNotifyVolumeEvent`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-fsrtlnotifyvolumeevent)),
//! as the pinned kernel makes it: a target-device change of the volume's
//! physical device object, reported with the event's GUID to whoever
//! registered for the volume (the mount manager, among others). A mount
//! is reported from a worker; a dismount, a lock and an unlock before
//! the routine returns. The status is that of finding the device: the
//! report's own is not passed on, as on Windows.

#![allow(non_snake_case)]

use crate::kd;
use crate::ob::object;
use crate::pnp::notify;
use nk_ntabi::io::{DEVICE_OBJECT, FILE_OBJECT};
use nk_ntabi::pnp::{TARGET_DEVICE_CUSTOM_HEADER, TARGET_DEVICE_CUSTOM_NOTIFICATION};
use nk_ntabi::status::NTSTATUS;

/// `FSRTL_VOLUME_*`, the events a file system reports.
const DISMOUNT: u32 = 1;
const LOCK: u32 = 3;
const UNLOCK: u32 = 5;
const MOUNT: u32 = 6;

/// The events' GUIDs, as `GUID_IO_VOLUME_*` in the pinned kernel.
const GUID_IO_VOLUME_DISMOUNT: [u8; 16] = guid(
    0xd16a55e8,
    0x1059,
    0x11d2,
    [0x8f, 0xfd, 0x00, 0xa0, 0xc9, 0xa0, 0x6d, 0x32],
);
const GUID_IO_VOLUME_LOCK: [u8; 16] = guid(
    0x50708874,
    0xc9af,
    0x11d1,
    [0x8f, 0xef, 0x00, 0xa0, 0xc9, 0xa0, 0x6d, 0x32],
);
const GUID_IO_VOLUME_UNLOCK: [u8; 16] = guid(
    0x9a8c3d68,
    0xd0cb,
    0x11d1,
    [0x8f, 0xef, 0x00, 0xa0, 0xc9, 0xa0, 0x6d, 0x32],
);
const GUID_IO_VOLUME_MOUNT: [u8; 16] = guid(
    0xb5804878,
    0x1a96,
    0x11d2,
    [0x8f, 0xfd, 0x00, 0xa0, 0xc9, 0xa0, 0x6d, 0x32],
);

/// A GUID's bytes as they lie in memory.
const fn guid(a: u32, b: u16, c: u16, d: [u8; 8]) -> [u8; 16] {
    let (a, b, c) = (a.to_le_bytes(), b.to_le_bytes(), c.to_le_bytes());
    [
        a[0], a[1], a[2], a[3], b[0], b[1], c[0], c[1], d[0], d[1], d[2], d[3], d[4], d[5], d[6],
        d[7],
    ]
}

/// `FsRtlNotifyVolumeEvent`. The events other than these four, which no
/// binary NK runs was seen to report, were not read from the pinned
/// kernel: reporting one stops the system by name.
///
/// # Safety
/// `file` is an open file object on the volume; called at
/// `PASSIVE_LEVEL`.
pub unsafe extern "C" fn FsRtlNotifyVolumeEvent(file: *mut FILE_OBJECT, event: u32) -> NTSTATUS {
    let (guid, now) = match event {
        MOUNT => (GUID_IO_VOLUME_MOUNT, false),
        DISMOUNT => (GUID_IO_VOLUME_DISMOUNT, true),
        LOCK => (GUID_IO_VOLUME_LOCK, true),
        UNLOCK => (GUID_IO_VOLUME_UNLOCK, true),
        _ => kd::bugcheck(format_args!(
            "FsRtlNotifyVolumeEvent: NK does not implement volume event {event}"
        )),
    };
    // SAFETY: per the contract.
    let device = match unsafe { notify::related_target(file) } {
        Ok(device) => device as *mut DEVICE_OBJECT,
        Err(status) => return status,
    };
    let notification = TARGET_DEVICE_CUSTOM_NOTIFICATION {
        Version: 1,
        Size: TARGET_DEVICE_CUSTOM_HEADER as u16,
        Event: guid,
        FileObject: core::ptr::null_mut(),
        NameBufferOffset: -1,
        CustomDataBuffer: [0],
    };
    // SAFETY: the device is referenced, the structure the routine's own.
    unsafe {
        if now {
            notify::report_target_change(device, &raw const notification);
        } else {
            notify::IoReportTargetDeviceChangeAsynchronous(device, &raw const notification, 0, 0);
        }
        object::dereference(device.cast());
    }
    nk_ntabi::status::STATUS_SUCCESS
}

/// [`FsRtlDismountComplete`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-fsrtldismountcomplete):
/// notify filter manager that a volume dismount completed (no `FltMgr` on NK).
pub extern "C" fn FsRtlDismountComplete(
    _device_object: *mut DEVICE_OBJECT,
    _status: NTSTATUS,
) -> NTSTATUS {
    nk_ntabi::status::STATUS_SUCCESS
}
