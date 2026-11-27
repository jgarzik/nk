//! RAW: the file system the kernel mounts on a disk, volume, CD-ROM or
//! tape that no other file system claims, as Windows' kernel does
//! (`\FileSystem\RAW`). It has no files: it lets the device itself be
//! opened and passes reads, writes, control requests and flushes to
//! the device beneath, which is how a disk or a volume is read raw
//! (`\Device\Harddisk0\DR0`, `\Device\HarddiskVolume1`).
//!
//! A mount ([`mount`]) is a volume device of RAW's whose extension says
//! which block it serves and which device its requests go to (the top
//! of the real device's stack, held from then on). The I/O manager's
//! mount path is `io::mount`.

#![allow(non_snake_case)]

use super::{device, driver, irp};
use crate::ob::object;
use core::ffi::c_void;
use core::sync::atomic::{AtomicPtr, Ordering};
use nk_ntabi::io::*;
use nk_ntabi::status::*;

/// RAW's driver object.
static DRIVER: AtomicPtr<DRIVER_OBJECT> = AtomicPtr::new(core::ptr::null_mut());

/// What a RAW volume device keeps: the block it is mounted for and the
/// device its requests go to.
#[repr(C)]
struct Vcb {
    vpb: *mut VPB,
    target: *mut DEVICE_OBJECT,
}

/// `FILE_DIRECTORY_FILE` among a create's options; `FO_NO_INTERMEDIATE_BUFFERING`
/// among a file's flags, which RAW sets on every open as Windows' does.
const FILE_DIRECTORY_FILE: u32 = 0x1;
const FO_NO_INTERMEDIATE_BUFFERING: u32 = 0x8;

/// `FILE_DEVICE_CD_ROM_FILE_SYSTEM` and `FILE_DEVICE_TAPE_FILE_SYSTEM`.
const FILE_DEVICE_CD_ROM_FILE_SYSTEM: u32 = 0x03;
const FILE_DEVICE_TAPE_FILE_SYSTEM: u32 = 0x20;

/// Make RAW's driver object. Once, at boot.
pub fn init() -> Result<(), &'static str> {
    let made = driver::builtin_in("\\FileSystem\\", "RAW", |object| {
        // SAFETY: the driver object being set up.
        unsafe {
            let table = &raw mut (*object).MajorFunction;
            let set = |major: u8, routine: DRIVER_DISPATCH| {
                (*table)[usize::from(major)] = Some(routine);
            };
            set(IRP_MJ_CREATE, create);
            set(IRP_MJ_CLEANUP, cleanup);
            set(IRP_MJ_CLOSE, cleanup);
            for major in [
                IRP_MJ_READ,
                IRP_MJ_WRITE,
                IRP_MJ_DEVICE_CONTROL,
                IRP_MJ_FLUSH_BUFFERS,
            ] {
                set(major, pass_down);
            }
            for major in [
                IRP_MJ_QUERY_INFORMATION,
                IRP_MJ_SET_INFORMATION,
                IRP_MJ_QUERY_VOLUME_INFORMATION,
                IRP_MJ_FILE_SYSTEM_CONTROL,
            ] {
                set(major, absent);
            }
        }
    })
    .map_err(|_| "RAW's driver object could not be made")?;
    DRIVER.store(made, Ordering::Release);
    Ok(())
}

/// Mount RAW on `real`, whose block is `vpb`: a new volume device of
/// RAW's, not yet published in the block (the caller does that, or
/// gives the device up with [`discard`] if another mount came first).
///
/// # Safety
/// `real` is a live device with the block `vpb`. Called at
/// `PASSIVE_LEVEL`.
pub unsafe fn mount(
    real: *mut DEVICE_OBJECT,
    vpb: *mut VPB,
) -> Result<*mut DEVICE_OBJECT, NTSTATUS> {
    // SAFETY: per the contract; the reference on the top of the real
    // device's stack is the mount's, given up only with the device.
    unsafe {
        let device_type = match (*real).DeviceType {
            0x02 => FILE_DEVICE_CD_ROM_FILE_SYSTEM,
            0x1F => FILE_DEVICE_TAPE_FILE_SYSTEM,
            _ => FILE_DEVICE_DISK_FILE_SYSTEM,
        };
        let mut volume = core::ptr::null_mut();
        let status = device::IoCreateDevice(
            DRIVER.load(Ordering::Acquire),
            size_of::<Vcb>() as u32,
            core::ptr::null(),
            device_type,
            0,
            0,
            &raw mut volume,
        );
        if !nt_success(status) {
            return Err(status);
        }
        let target = device::IoGetAttachedDeviceReference(real);
        (*volume).StackSize = (*target).StackSize + 1;
        (*volume).AlignmentRequirement = (*target).AlignmentRequirement;
        (*volume).SectorSize = (*target).SectorSize;
        // Requests are built for RAW's device and passed on as they are:
        // they carry the buffer the way the device beneath asks for.
        let method = (*target).Flags & (DO_DIRECT_IO | DO_BUFFERED_IO);
        (*volume).Flags = ((*volume).Flags | method) & !DO_DEVICE_INITIALIZING;
        (*volume)
            .DeviceExtension
            .cast::<Vcb>()
            .write(Vcb { vpb, target });
        Ok(volume)
    }
}

/// Give up a volume device [`mount`] made: one never published, or one
/// taken out of its block with nothing open on it.
///
/// # Safety
/// `volume` came from [`mount`] and nothing else reaches it.
pub unsafe fn discard(volume: *mut DEVICE_OBJECT) {
    // SAFETY: per the contract.
    unsafe {
        object::dereference((*vcb(volume)).target.cast());
        device::IoDeleteDevice(volume);
    }
}

/// The extension of RAW's volume device `volume`.
fn vcb(volume: *mut DEVICE_OBJECT) -> *mut Vcb {
    // SAFETY: RAW's devices have a `Vcb` as their extension.
    unsafe { (*volume).DeviceExtension.cast() }
}

/// Complete `request` with `status` and `information`.
///
/// # Safety
/// `request` is the caller's to complete.
unsafe fn complete(request: *mut IRP, status: NTSTATUS, information: usize) -> NTSTATUS {
    // SAFETY: per the contract.
    unsafe {
        (*request).IoStatus.Status = status;
        (*request).IoStatus.Information = information;
        irp::IofCompleteRequest(request, 0);
    }
    status
}

/// `IRP_MJ_CREATE`: the volume itself may be opened, and nothing in it.
/// A file name, a related file, a disposition other than "open", or a
/// directory is `STATUS_INVALID_PARAMETER`, as Windows' RAW answers.
///
/// # Safety
/// `volume` is RAW's volume device and `request` a request sent to it.
unsafe extern "C" fn create(volume: *mut DEVICE_OBJECT, request: *mut IRP) -> NTSTATUS {
    // SAFETY: a create the I/O manager sent RAW's volume device: its
    // location names the file object, which is the I/O manager's.
    unsafe {
        let location = (*request).CurrentStackLocation;
        let file = (*location).FileObject;
        let options = (*location).Parameters[1] as u32;
        let refused = (*file).FileName.Length != 0
            || !(*file).RelatedFileObject.is_null()
            || options >> 24 != FILE_OPEN
            || options & FILE_DIRECTORY_FILE != 0;
        if refused {
            return complete(request, STATUS_INVALID_PARAMETER, 0);
        }
        let vcb = vcb(volume);
        (*file).Vpb = (*vcb).vpb.cast();
        (*file).FsContext = vcb.cast::<c_void>();
        (*file).Flags |= FO_NO_INTERMEDIATE_BUFFERING;
        complete(request, STATUS_SUCCESS, FILE_OPENED)
    }
}

/// `IRP_MJ_CLEANUP` and `IRP_MJ_CLOSE`: RAW keeps nothing per open,
/// and nothing is undone. The volume stays mounted.
///
/// # Safety
/// `volume` is RAW's volume device and `request` a request sent to it.
unsafe extern "C" fn cleanup(_volume: *mut DEVICE_OBJECT, request: *mut IRP) -> NTSTATUS {
    // SAFETY: the request is RAW's to complete.
    unsafe { complete(request, STATUS_SUCCESS, 0) }
}

/// Reads, writes, control requests and flushes go to the device beneath
/// as they are.
///
/// # Safety
/// `volume` is RAW's volume device and `request` a request sent to it.
unsafe extern "C" fn pass_down(volume: *mut DEVICE_OBJECT, request: *mut IRP) -> NTSTATUS {
    // SAFETY: the request has a location below RAW's (the device's
    // stack size is the target's plus one); the target is held.
    unsafe {
        let current = (*request).CurrentStackLocation;
        let next = irp::next_location(request);
        (*next).MajorFunction = (*current).MajorFunction;
        (*next).MinorFunction = (*current).MinorFunction;
        (*next).Flags = (*current).Flags;
        (*next).Control = 0;
        (*next).Parameters = (*current).Parameters;
        (*next).FileObject = (*current).FileObject;
        (*next).CompletionRoutine = None;
        (*next).Context = core::ptr::null_mut();
        irp::IofCallDriver((*vcb(volume)).target, request)
    }
}

/// What Windows' RAW answers and NK's does not yet: the file's and the
/// volume's information and file-system control requests. Stops the
/// system naming the request.
///
/// # Safety
/// `volume` is RAW's volume device and `request` a request sent to it.
unsafe extern "C" fn absent(_volume: *mut DEVICE_OBJECT, request: *mut IRP) -> NTSTATUS {
    // SAFETY: a request sent to RAW's device.
    let major = unsafe { (*(*request).CurrentStackLocation).MajorFunction };
    crate::kd::bugcheck(format_args!(
        "RAW: NK does not implement request {major:#x} on a raw volume"
    ))
}
