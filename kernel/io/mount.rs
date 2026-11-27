//! Mounting: what the I/O manager does when a device a file system can
//! be mounted on (one with a volume parameter block, `VPB`) is opened.
//!
//! Unless the open is a direct device open ([`direct_open`]), the
//! block must be mounted first ([`mounted`]), as Windows'
//! `IopCheckVpbMounted` does: a locked volume refuses the open
//! (`STATUS_ACCESS_DENIED`); an unmounted one is offered to the
//! registered file systems (`io::fs`), the open's requests then going to
//! the volume device the one that took it put in the block
//! (`file::related_device`). The block is then initialised as
//! `IopMountInitializeVpb` does it ([`mounted_by`]). A RAW volume stays
//! mounted until its device is deleted and nothing is open on it
//! ([`device_deleted`]); another file system's volume is that file
//! system's to dismount.

#![allow(non_snake_case)]

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
/// `device` is a live device with a volume parameter block, counted.
/// Called at `PASSIVE_LEVEL`.
pub unsafe fn mounted(device: *mut DEVICE_OBJECT, itself: bool) -> Result<*mut VPB, NTSTATUS> {
    // SAFETY: per the contract; the block is the device's for its life,
    // and its fields change under the lock.
    unsafe {
        let vpb = (*device).Vpb.cast::<VPB>();
        loop {
            {
                let _lock = VPB_LOCK.lock();
                let flags = (*vpb).Flags;
                if flags & VPB_MOUNTED != 0 {
                    if flags & VPB_LOCKED != 0 {
                        return Err(STATUS_ACCESS_DENIED);
                    }
                    (*vpb).ReferenceCount += 1;
                    return Ok(vpb);
                }
            }
            let status = super::fs::mount_volume(device, itself);
            if !nt_success(status) {
                return Err(status);
            }
        }
    }
}

/// `VPB.Flags` of `vpb`, read under the lock.
///
/// # Safety
/// `vpb` is a live block.
pub unsafe fn flags(vpb: *mut VPB) -> u16 {
    let _lock = VPB_LOCK.lock();
    // SAFETY: per the contract.
    unsafe { (*vpb).Flags }
}

/// A file system took the volume on `real`, whose stack's top is
/// `target`, and filled in the block: mark it mounted (raw-mountable
/// still if it was, and open to direct writes if `last`, RAW, took it),
/// size the volume device's stack for the device beneath it, point its
/// extension at the block and count the mount, as Windows'
/// `IopMountInitializeVpb` does.
///
/// # Safety
/// `real` and `target` are live; the file system has put its volume
/// device in the block.
pub unsafe fn mounted_by(
    real: *mut DEVICE_OBJECT,
    target: *mut DEVICE_OBJECT,
    raw: bool,
    last: bool,
) {
    // SAFETY: per the contract.
    let volume = unsafe {
        let vpb = (*real).Vpb.cast::<VPB>();
        let _lock = VPB_LOCK.lock();
        let mut flags = VPB_MOUNTED;
        if raw {
            flags |= VPB_RAW_MOUNT;
        }
        if last {
            flags |= VPB_DIRECT_WRITES_ALLOWED;
        }
        (*vpb).Flags = flags;
        let volume = (*vpb).DeviceObject;
        (*volume).StackSize = (*target).StackSize + 1;
        (*(*volume).DeviceObjectExtension).Vpb = vpb.cast();
        (*vpb).ReferenceCount += 1;
        volume
    };
    super::fs::trace(format_args!("{real:p} mounted, volume device {volume:p}"));
}

/// [`IoAcquireVpbSpinLock`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-ioacquirevpbspinlock):
/// take the lock every block's mount state is under.
///
/// # Safety
/// `irql` is writable.
pub unsafe extern "C" fn IoAcquireVpbSpinLock(irql: *mut u8) {
    let old = VPB_LOCK.acquire_split();
    // SAFETY: per the contract.
    unsafe { irql.write(old) };
}

/// [`IoReleaseVpbSpinLock`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-ioreleasevpbspinlock).
///
/// # Safety
/// The caller holds the lock from `IoAcquireVpbSpinLock`, which gave
/// `irql`.
pub unsafe extern "C" fn IoReleaseVpbSpinLock(irql: u8) {
    // SAFETY: per the contract.
    unsafe { VPB_LOCK.release_split(irql) };
}

/// Count one more reference to `vpb`: a stream file object's
/// (`IoCreateStreamFileObject`).
///
/// # Safety
/// `vpb` is a live block.
pub unsafe fn reference(vpb: *mut VPB) {
    let _lock = VPB_LOCK.lock();
    // SAFETY: per the contract.
    unsafe { (*vpb).ReferenceCount += 1 };
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
/// deleted and RAW's volume is mounted with nothing open on it: its one
/// reference left is the mount's own ([`mounted_by`]). Another file
/// system's volume is that file system's to dismount. The caller holds
/// the lock.
///
/// # Safety
/// `vpb` is a live block.
unsafe fn take_if_free(vpb: *mut VPB) -> *mut DEVICE_OBJECT {
    // SAFETY: per the contract; the lock is held.
    unsafe {
        let flags = (*vpb).Flags;
        if flags & VPB_REMOVE_PENDING == 0
            || flags & VPB_MOUNTED == 0
            || (*vpb).ReferenceCount != 1
            || !raw::owns((*vpb).DeviceObject)
        {
            return core::ptr::null_mut();
        }
        let volume = (*vpb).DeviceObject;
        (*vpb).DeviceObject = core::ptr::null_mut();
        (*vpb).Flags &= !VPB_MOUNTED;
        (*vpb).ReferenceCount = 0;
        volume
    }
}

/// Delete a RAW volume device taken out of its block, if there is one.
fn dismount(volume: *mut DEVICE_OBJECT) {
    if !volume.is_null() {
        // SAFETY: RAW's, out of its block, so nothing new reaches it.
        unsafe { raw::discard(volume) };
    }
}
