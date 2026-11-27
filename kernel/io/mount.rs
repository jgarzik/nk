//! Mounting: what the I/O manager does when a device a file system can
//! be mounted on (one with a volume parameter block, `VPB`) is opened.
//!
//! Unless the open is a direct device open ([`direct_open`]), the
//! block must be mounted first ([`mounted`]): a file system claims the
//! device, its volume device is put in the block, and the open's
//! requests go to that volume device (`file::related_device`). NK has
//! one file system to mount, the kernel's own RAW (`io::raw`), and
//! mounts it as Windows does when no other claims the device: for an
//! open of the device itself, or of any name on a device whose block
//! allows a raw mount (`VPB_RAW_MOUNT`). Otherwise the open fails with
//! `STATUS_UNRECOGNIZED_VOLUME`. A mount clears the device's
//! `DO_VERIFY_VOLUME`. A volume stays mounted until its device is
//! deleted and nothing is open on it ([`device_deleted`]).

use super::raw;
use crate::ke::{Rank, SpinLock};
use nk_ntabi::io::*;
use nk_ntabi::status::*;

/// The lock Windows keeps for every block (`IopVpbSpinLock`): each
/// block's `Flags`, `DeviceObject` and `ReferenceCount` change under it.
static VPB_LOCK: SpinLock<()> = SpinLock::new(Rank::Vpb, ());

/// The access that needs no file system: `SYNCHRONIZE`,
/// `FILE_READ_ATTRIBUTES`, `READ_CONTROL`, `ACCESS_SYSTEM_SECURITY`,
/// `WRITE_OWNER` and `WRITE_DAC`.
const DIRECT_ACCESS: u32 =
    0x0010_0000 | 0x80 | 0x0002_0000 | 0x0100_0000 | 0x0008_0000 | 0x0004_0000;

/// Whether an open is a direct device open, which mounts nothing: the
/// device itself (no name after it, no related file) for nothing but
/// [`DIRECT_ACCESS`].
pub fn direct_open(itself: bool, access: u32) -> bool {
    itself && access & !DIRECT_ACCESS == 0
}

/// The block of `device`, mounted, with a reference for an open that
/// is not a direct device open. `itself`: the open names the device
/// itself, which allows a raw mount.
///
/// # Safety
/// `device` is a live device with a volume parameter block. Called at
/// `PASSIVE_LEVEL`.
pub unsafe fn mounted(device: *mut DEVICE_OBJECT, itself: bool) -> Result<*mut VPB, NTSTATUS> {
    // SAFETY: per the contract; the block is the device's for its life,
    // and its fields change under the lock.
    unsafe {
        let vpb = (*device).Vpb.cast::<VPB>();
        let raw_allowed = {
            let _lock = VPB_LOCK.lock();
            if (*vpb).Flags & VPB_MOUNTED != 0 {
                (*vpb).ReferenceCount += 1;
                return Ok(vpb);
            }
            itself || (*vpb).Flags & VPB_RAW_MOUNT != 0
        };
        if !raw_allowed {
            return Err(STATUS_UNRECOGNIZED_VOLUME);
        }
        // Made with no lock held; published only if no other mount came
        // first, else given up.
        let volume = raw::mount(device, vpb)?;
        let lost = {
            let _lock = VPB_LOCK.lock();
            let lost = (*vpb).Flags & VPB_MOUNTED != 0;
            if !lost {
                (*vpb).DeviceObject = volume;
                (*vpb).Flags |= VPB_MOUNTED;
                (*volume).Vpb = vpb.cast();
                (*device).Flags &= !DO_VERIFY_VOLUME;
            }
            (*vpb).ReferenceCount += 1;
            lost
        };
        if lost {
            raw::discard(volume);
        }
        Ok(vpb)
    }
}

/// Give up an open's reference to `vpb`; the last one of a device being
/// deleted dismounts it.
///
/// # Safety
/// The caller holds a reference from [`mounted`]. Called at
/// `PASSIVE_LEVEL`.
pub unsafe fn release(vpb: *mut VPB) {
    // SAFETY: per the contract.
    let volume = unsafe {
        let _lock = VPB_LOCK.lock();
        (*vpb).ReferenceCount -= 1;
        take_if_free(vpb)
    };
    dismount(volume);
}

/// `device`, which has a block, is being deleted (`IoDeleteDevice`,
/// before it marks the device): its volume is dismounted now if nothing
/// is open on it, else when the last open goes.
///
/// # Safety
/// `device` is a live device with a volume parameter block. Called at
/// `PASSIVE_LEVEL`, with no lock held.
pub unsafe fn device_deleted(device: *mut DEVICE_OBJECT) {
    // SAFETY: per the contract.
    let volume = unsafe {
        let vpb = (*device).Vpb.cast::<VPB>();
        let _lock = VPB_LOCK.lock();
        (*vpb).Flags |= VPB_REMOVE_PENDING;
        take_if_free(vpb)
    };
    dismount(volume);
}

/// The volume device of `vpb`, taken out of it, if its device is being
/// deleted, a volume is mounted and nothing is open on it. The caller
/// holds the lock.
///
/// # Safety
/// `vpb` is a live block.
unsafe fn take_if_free(vpb: *mut VPB) -> *mut DEVICE_OBJECT {
    // SAFETY: per the contract; the lock is held.
    unsafe {
        let flags = (*vpb).Flags;
        if flags & VPB_REMOVE_PENDING == 0 || flags & VPB_MOUNTED == 0 || (*vpb).ReferenceCount != 0
        {
            return core::ptr::null_mut();
        }
        let volume = (*vpb).DeviceObject;
        (*vpb).DeviceObject = core::ptr::null_mut();
        (*vpb).Flags &= !VPB_MOUNTED;
        volume
    }
}

/// Delete a volume device taken out of its block, if there is one.
fn dismount(volume: *mut DEVICE_OBJECT) {
    if !volume.is_null() {
        // SAFETY: out of its block, so nothing new reaches it; RAW's.
        unsafe { raw::discard(volume) };
    }
}
