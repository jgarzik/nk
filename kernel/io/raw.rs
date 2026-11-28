//! RAW: the file system the kernel mounts on a disk, volume, CD-ROM or
//! tape that no other file system claims, as Windows' kernel does
//! (`\FileSystem\RAW`). It has no files: it lets the device itself be
//! opened and passes reads, writes, control requests and flushes to
//! the device beneath, which is how a disk or a volume is read raw
//! (`\Device\Harddisk0\DR0`, `\Device\HarddiskVolume1`).
//!
//! RAW registers a control device on the disk, CD-ROM and tape queues
//! at boot (`\Device\RawDisk`, `\Device\RawCdRom`, `\Device\RawTape`),
//! before any other file system, so it stays last on each (`io::fs`).
//! It takes every volume it is asked to mount, as Windows' RAW does
//! (`RawMountVolume`); the I/O manager decides when it is asked. A
//! mount ([`mount`]) is a volume device of RAW's whose extension says
//! which block it serves and which device its requests go to (the top
//! of the real device's stack, held from then on).

#![allow(non_snake_case)]

use super::{device, driver, irp, share};
use crate::ex::pushlock::PushLock;
use crate::ob::object;
use core::ffi::c_void;
use core::sync::atomic::{AtomicPtr, Ordering};
use nk_ntabi::io::*;
use nk_ntabi::status::*;

/// RAW's driver object.
static DRIVER: AtomicPtr<DRIVER_OBJECT> = AtomicPtr::new(core::ptr::null_mut());
/// RAW's control devices: disk, CD-ROM, tape.
static CONTROL: [AtomicPtr<DEVICE_OBJECT>; 3] =
    [const { AtomicPtr::new(core::ptr::null_mut()) }; 3];

/// What a RAW volume device keeps: the block it is mounted for, the device
/// its requests go to, share-access counts, open count, and volume lock state.
#[repr(C)]
struct Vcb {
    vpb: *mut VPB,
    target: *mut DEVICE_OBJECT,
    state: PushLock<VcbState>,
}

struct VcbState {
    share: SHARE_ACCESS,
    open_count: u32,
    locked_by: *mut FILE_OBJECT,
}

// SAFETY: `VcbState` is only accessed under `Vcb::state`.
unsafe impl Send for VcbState {}

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
            set(IRP_MJ_CLOSE, close);
            for major in [
                IRP_MJ_READ,
                IRP_MJ_WRITE,
                IRP_MJ_DEVICE_CONTROL,
                IRP_MJ_FLUSH_BUFFERS,
            ] {
                set(major, pass_down);
            }
            set(IRP_MJ_QUERY_INFORMATION, query_information);
            set(IRP_MJ_SET_INFORMATION, set_information);
            set(IRP_MJ_QUERY_VOLUME_INFORMATION, query_volume_information);
            set(IRP_MJ_FILE_SYSTEM_CONTROL, file_system_control);
            set(IRP_MJ_PNP, pnp);
            set(IRP_MJ_SHUTDOWN, shutdown);
        }
    })
    .map_err(|_| "RAW's driver object could not be made")?;
    DRIVER.store(made, Ordering::Release);
    for (slot, (name, device_type)) in CONTROL.iter().zip([
        ("\\Device\\RawDisk", FILE_DEVICE_DISK_FILE_SYSTEM),
        ("\\Device\\RawCdRom", FILE_DEVICE_CD_ROM_FILE_SYSTEM),
        ("\\Device\\RawTape", FILE_DEVICE_TAPE_FILE_SYSTEM),
    ]) {
        let mut wide: alloc::vec::Vec<u16> = name.encode_utf16().collect();
        let name = UNICODE_STRING {
            Length: (wide.len() * 2) as u16,
            MaximumLength: (wide.len() * 2) as u16,
            Buffer: wide.as_mut_ptr(),
        };
        let mut control = core::ptr::null_mut();
        // SAFETY: RAW's driver object; the name is copied by the call.
        unsafe {
            if !nt_success(device::IoCreateDevice(
                made,
                0,
                &raw const name,
                device_type,
                0,
                0,
                &raw mut control,
            )) {
                return Err("a RAW control device could not be made");
            }
            slot.store(control, Ordering::Release);
            super::fs::IoRegisterFileSystem(control);
        }
    }
    Ok(())
}

/// Whether `volume` is a device of RAW's.
///
/// # Safety
/// `volume` is a live device.
pub unsafe fn owns(volume: *mut DEVICE_OBJECT) -> bool {
    // SAFETY: per the contract.
    unsafe { (*volume).DriverObject == DRIVER.load(Ordering::Acquire) }
}

/// `IRP_MJ_FILE_SYSTEM_CONTROL`. To a control device: `IRP_MN_MOUNT_VOLUME`,
/// which RAW always takes (its volume device in the block, the serial
/// number all ones and no label, as `RawInitializeVcb` leaves them).
/// Anything else is what NK's RAW does not answer yet.
///
/// # Safety
/// `device` is RAW's and `request` a request sent to it.
unsafe extern "C" fn file_system_control(
    device: *mut DEVICE_OBJECT,
    request: *mut IRP,
) -> NTSTATUS {
    // SAFETY: the request's location is valid per the dispatch contract.
    unsafe {
        let location = (*request).CurrentStackLocation;
        let control = CONTROL.iter().any(|c| c.load(Ordering::Acquire) == device);
        if control {
            if (*location).MinorFunction != IRP_MN_MOUNT_VOLUME {
                return complete(request, STATUS_INVALID_DEVICE_REQUEST, 0);
            }
            let vpb = (*location).Parameters[0] as usize as *mut VPB;
            let target = (*location).Parameters[1] as usize as *mut DEVICE_OBJECT;
            let status = match mount(target, vpb) {
                Ok(volume) => {
                    (*vpb).DeviceObject = volume;
                    (*vpb).SerialNumber = u32::MAX;
                    (*vpb).VolumeLabelLength = 0;
                    STATUS_SUCCESS
                }
                Err(status) => status,
            };
            return complete(request, status, 0);
        }
        if (*location).MinorFunction != IRP_MN_USER_FS_REQUEST {
            return complete(request, STATUS_INVALID_DEVICE_REQUEST, 0);
        }
        let code = (*location).Parameters[2] as u32;
        let file = (*location).FileObject;
        let vcb = vcb(device);
        let status = match code {
            FSCTL_LOCK_VOLUME => {
                let mut state = (*vcb).state.lock();
                if state.locked_by.is_null() && state.open_count == 1 {
                    state.locked_by = file;
                    let vpb = (*vcb).vpb;
                    if !vpb.is_null() {
                        (*vpb).Flags |= VPB_LOCKED;
                    }
                    STATUS_SUCCESS
                } else {
                    STATUS_ACCESS_DENIED
                }
            }
            FSCTL_UNLOCK_VOLUME => {
                let mut state = (*vcb).state.lock();
                if state.locked_by == file {
                    state.locked_by = core::ptr::null_mut();
                    let vpb = (*vcb).vpb;
                    if !vpb.is_null() {
                        (*vpb).Flags &= !VPB_LOCKED;
                    }
                    STATUS_SUCCESS
                } else {
                    STATUS_ACCESS_DENIED
                }
            }
            FSCTL_DISMOUNT_VOLUME => {
                let mut state = (*vcb).state.lock();
                if !state.locked_by.is_null() && state.locked_by != file {
                    STATUS_ACCESS_DENIED
                } else {
                    state.locked_by = core::ptr::null_mut();
                    let vpb = (*vcb).vpb;
                    if !vpb.is_null() {
                        (*vpb).Flags &= !VPB_LOCKED;
                    }
                    STATUS_SUCCESS
                }
            }
            FSCTL_IS_VOLUME_MOUNTED | FSCTL_ALLOW_EXTENDED_DASD_IO => STATUS_SUCCESS,
            _ => STATUS_INVALID_DEVICE_REQUEST,
        };
        complete(request, status, 0)
    }
}

/// Mount RAW on `real`, whose block is `vpb`: a new volume device of
/// RAW's, not yet in the block.
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
        (*volume).DeviceExtension.cast::<Vcb>().write(Vcb {
            vpb,
            target,
            state: PushLock::new(VcbState {
                share: SHARE_ACCESS {
                    OpenCount: 0,
                    Readers: 0,
                    Writers: 0,
                    Deleters: 0,
                    SharedRead: 0,
                    SharedWrite: 0,
                    SharedDelete: 0,
                },
                open_count: 0,
                locked_by: core::ptr::null_mut(),
            }),
        });
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
        let sec = (*location).Parameters[0] as usize as *const IO_SECURITY_CONTEXT;
        let desired = if sec.is_null() {
            0
        } else {
            (*sec).DesiredAccess
        };
        let share_mode = u32::from(((*location).Parameters[2] >> 16) as u16);
        let vcb = vcb(volume);
        let mut state = (*vcb).state.lock();
        if !state.locked_by.is_null() {
            drop(state);
            return complete(request, STATUS_ACCESS_DENIED, 0);
        }
        if state.open_count > 0 {
            let st = share::IoCheckShareAccess(desired, share_mode, file, &raw mut state.share, 1);
            if !nt_success(st) {
                drop(state);
                return complete(request, st, 0);
            }
        } else {
            share::IoSetShareAccess(desired, share_mode, file, &raw mut state.share);
        }
        state.open_count += 1;
        drop(state);
        (*file).Vpb = (*vcb).vpb.cast();
        (*file).FsContext = vcb.cast::<c_void>();
        (*file).Flags |= FO_NO_INTERMEDIATE_BUFFERING;
        complete(request, STATUS_SUCCESS, FILE_OPENED)
    }
}

/// `IRP_MJ_CLEANUP`: release share-access counts and any volume lock held by
/// this file object.
///
/// # Safety
/// `volume` is RAW's volume device and `request` a request sent to it.
unsafe extern "C" fn cleanup(volume: *mut DEVICE_OBJECT, request: *mut IRP) -> NTSTATUS {
    // SAFETY: the request is RAW's to complete.
    unsafe {
        let file = (*(*request).CurrentStackLocation).FileObject;
        let vcb = vcb(volume);
        let mut state = (*vcb).state.lock();
        if state.open_count > 0 {
            share::IoRemoveShareAccess(file, &raw mut state.share);
            state.open_count -= 1;
        }
        if state.locked_by == file {
            state.locked_by = core::ptr::null_mut();
            let vpb = (*vcb).vpb;
            if !vpb.is_null() {
                (*vpb).Flags &= !VPB_LOCKED;
            }
        }
        drop(state);
        complete(request, STATUS_SUCCESS, 0)
    }
}

/// `IRP_MJ_CLOSE`: RAW keeps nothing per close; the volume stays mounted.
///
/// # Safety
/// `volume` is RAW's volume device and `request` a request sent to it.
unsafe extern "C" fn close(_volume: *mut DEVICE_OBJECT, request: *mut IRP) -> NTSTATUS {
    // SAFETY: the request is RAW's to complete.
    unsafe { complete(request, STATUS_SUCCESS, 0) }
}

/// `IRP_MJ_QUERY_VOLUME_INFORMATION` on a RAW volume: answers
/// `FileFsVolumeInformation`, `FileFsDeviceInformation`,
/// `FileFsAttributeInformation`, `FileFsSizeInformation`, and
/// `FileFsFullSizeInformation`.
///
/// # Safety
/// `volume` is RAW's volume device and `request` a request sent to it.
unsafe extern "C" fn query_volume_information(
    volume: *mut DEVICE_OBJECT,
    request: *mut IRP,
) -> NTSTATUS {
    // SAFETY: per the IRP dispatch contract.
    unsafe {
        let location = (*request).CurrentStackLocation;
        let length = (*location).Parameters[0] as usize;
        let class = (*location).Parameters[1] as u32;
        let out = (*request).SystemBuffer.cast::<u8>();
        if out.is_null() {
            return complete(request, STATUS_INVALID_PARAMETER, 0);
        }
        let vcb = vcb(volume);
        match class {
            FILE_FS_VOLUME_INFORMATION => {
                // `FILE_FS_VOLUME_INFORMATION`: CreationTime(8), Serial(4), LabelLen(4), SupportsObjects(1), pad(1) = 18 B.
                const NEED: usize = 18;
                if length < NEED {
                    return complete(request, STATUS_BUFFER_OVERFLOW, 0);
                }
                out.write_bytes(0, NEED);
                let serial = if (*vcb).vpb.is_null() {
                    u32::MAX
                } else {
                    (*(*vcb).vpb).SerialNumber
                };
                out.add(8).cast::<u32>().write_unaligned(serial);
                complete(request, STATUS_SUCCESS, NEED)
            }
            FILE_FS_DEVICE_INFORMATION => {
                // `FILE_FS_DEVICE_INFORMATION`: DeviceType(4), Characteristics(4) = 8 B.
                const NEED: usize = 8;
                if length < NEED {
                    return complete(request, STATUS_BUFFER_OVERFLOW, 0);
                }
                let target = (*vcb).target;
                out.cast::<u32>().write_unaligned((*target).DeviceType);
                out.add(4)
                    .cast::<u32>()
                    .write_unaligned((*target).Characteristics);
                complete(request, STATUS_SUCCESS, NEED)
            }
            FILE_FS_ATTRIBUTE_INFORMATION => {
                // `FILE_FS_ATTRIBUTE_INFORMATION`: Attributes(4), MaxCompLen(4), NameLen(4), "RAW"(6) = 18 B.
                const NEED: usize = 18;
                if length < 12 {
                    return complete(request, STATUS_BUFFER_TOO_SMALL, 0);
                }
                out.write_bytes(0, length.min(NEED));
                out.add(4).cast::<u32>().write_unaligned(255);
                out.add(8).cast::<u32>().write_unaligned(6);
                let raw_name: [u16; 3] = [u16::from(b'R'), u16::from(b'A'), u16::from(b'W')];
                let avail = (length - 12).min(6);
                out.add(12)
                    .copy_from_nonoverlapping(raw_name.as_ptr().cast::<u8>(), avail);
                if length < NEED {
                    complete(request, STATUS_BUFFER_OVERFLOW, 12 + avail)
                } else {
                    complete(request, STATUS_SUCCESS, NEED)
                }
            }
            FILE_FS_SIZE_INFORMATION | FILE_FS_FULL_SIZE_INFORMATION => {
                let need = if class == FILE_FS_SIZE_INFORMATION {
                    24
                } else {
                    32
                };
                if length < need {
                    return complete(request, STATUS_BUFFER_OVERFLOW, 0);
                }
                let bps = u32::from((*(*vcb).target).SectorSize).max(512);
                out.write_bytes(0, need);
                if class == FILE_FS_SIZE_INFORMATION {
                    out.add(16).cast::<u32>().write_unaligned(1);
                    out.add(20).cast::<u32>().write_unaligned(bps);
                } else {
                    out.add(24).cast::<u32>().write_unaligned(1);
                    out.add(28).cast::<u32>().write_unaligned(bps);
                }
                complete(request, STATUS_SUCCESS, need)
            }
            _ => complete(request, STATUS_INVALID_INFO_CLASS, 0),
        }
    }
}

/// `IRP_MJ_QUERY_INFORMATION` on a RAW volume: answers
/// `FilePositionInformation` (14) and `FileStandardInformation` (5).
///
/// # Safety
/// `volume` is RAW's volume device and `request` a request sent to it.
unsafe extern "C" fn query_information(_volume: *mut DEVICE_OBJECT, request: *mut IRP) -> NTSTATUS {
    const FILE_STANDARD_INFORMATION: u32 = 5;
    const FILE_POSITION_INFORMATION: u32 = 14;
    // SAFETY: per the IRP dispatch contract.
    unsafe {
        let location = (*request).CurrentStackLocation;
        let length = (*location).Parameters[0] as usize;
        let class = (*location).Parameters[1] as u32;
        let out = (*request).SystemBuffer.cast::<u8>();
        if out.is_null() {
            return complete(request, STATUS_INVALID_PARAMETER, 0);
        }
        match class {
            FILE_POSITION_INFORMATION => {
                if length < 8 {
                    return complete(request, STATUS_INFO_LENGTH_MISMATCH, 0);
                }
                let pos = (*(*location).FileObject).CurrentByteOffset;
                out.cast::<i64>().write_unaligned(pos);
                complete(request, STATUS_SUCCESS, 8)
            }
            FILE_STANDARD_INFORMATION => {
                if length < 24 {
                    return complete(request, STATUS_INFO_LENGTH_MISMATCH, 0);
                }
                out.write_bytes(0, 24);
                out.add(16).cast::<u32>().write_unaligned(1);
                complete(request, STATUS_SUCCESS, 24)
            }
            _ => complete(request, STATUS_INVALID_PARAMETER, 0),
        }
    }
}

/// `IRP_MJ_SET_INFORMATION` on a RAW volume: supports
/// `FilePositionInformation` (14).
///
/// # Safety
/// `volume` is RAW's volume device and `request` a request sent to it.
unsafe extern "C" fn set_information(_volume: *mut DEVICE_OBJECT, request: *mut IRP) -> NTSTATUS {
    const FILE_POSITION_INFORMATION: u32 = 14;
    // SAFETY: per the IRP dispatch contract.
    unsafe {
        let location = (*request).CurrentStackLocation;
        let length = (*location).Parameters[0] as usize;
        let class = (*location).Parameters[1] as u32;
        let input = (*request).SystemBuffer.cast::<u8>();
        if class == FILE_POSITION_INFORMATION && !input.is_null() && length >= 8 {
            let pos = input.cast::<i64>().read_unaligned();
            (*(*location).FileObject).CurrentByteOffset = pos;
            return complete(request, STATUS_SUCCESS, 0);
        }
        complete(request, STATUS_INVALID_PARAMETER, 0)
    }
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

/// `IRP_MJ_SHUTDOWN`, sent to RAW's first control device the file
/// systems' shutdown reaches: as Windows' `RawShutdown`, all three leave
/// their queues and are deleted.
///
/// # Safety
/// `_device` is RAW's and `request` a request sent to it.
unsafe extern "C" fn shutdown(_device: *mut DEVICE_OBJECT, request: *mut IRP) -> NTSTATUS {
    // SAFETY: RAW's own control devices, made at boot.
    unsafe {
        for control in &CONTROL {
            let control = control.swap(core::ptr::null_mut(), Ordering::AcqRel);
            if !control.is_null() {
                super::fs::IoUnregisterFileSystem(control);
                device::IoDeleteDevice(control);
            }
        }
        complete(request, STATUS_SUCCESS, 0)
    }
}

/// `IRP_MJ_PNP`, as Windows' `RawDispatch` answers it: a query to
/// remove the device is refused (`STATUS_DEVICE_BUSY`), the volume being
/// mounted; anything else, the target-device relation among them, goes
/// to the device beneath.
///
/// # Safety
/// `volume` is RAW's volume device and `request` a request sent to it.
unsafe extern "C" fn pnp(volume: *mut DEVICE_OBJECT, request: *mut IRP) -> NTSTATUS {
    /// `IRP_MN_QUERY_REMOVE_DEVICE` and `STATUS_DEVICE_BUSY`.
    const IRP_MN_QUERY_REMOVE_DEVICE: u8 = 0x01;
    const STATUS_DEVICE_BUSY: NTSTATUS = 0x8000_0011_u32 as NTSTATUS;
    // SAFETY: a request sent to RAW's volume device.
    unsafe {
        if (*(*request).CurrentStackLocation).MinorFunction == IRP_MN_QUERY_REMOVE_DEVICE {
            return complete(request, STATUS_DEVICE_BUSY, 0);
        }
        pass_down(volume, request)
    }
}
