//! File systems: their registration, the mount request, and the small
//! routines file systems call on the I/O manager.
//!
//! A file system registers its control devices (`IoRegisterFileSystem`)
//! on one of four queues by device type: disk, CD-ROM, tape, network.
//! A new one goes at the head, a low-priority one just ahead of the
//! last, which on the disk, CD-ROM and tape queues is RAW (`io::raw`,
//! registered at boot). Opening a device with a volume parameter block
//! that nothing is mounted on (`io::mount`) walks the queue for the
//! device's type with `IRP_MN_MOUNT_VOLUME` until one file system takes
//! the volume, as Windows' `IopMountVolume` does: the rules of the walk
//! are `nk_io::mount`, read in the pinned kernel, the mounts of one
//! device are serialised by its `DeviceLock`, and the queue is not held
//! while a file system is asked: one that registers or goes meanwhile
//! sends the walk back to the head.

#![allow(non_snake_case)]

use super::{device, irp};
use crate::ke::{self, Rank, SpinLock};
use crate::ob::object;
use alloc::vec::Vec;
use core::ffi::c_void;
use nk_io::mount::{self as rules, Next, Offer, Queue};
use nk_ntabi::io::*;
use nk_ntabi::status::*;
use nk_ntabi::thread::{DEVICE_TO_VERIFY, MISC_FLAG_SYSTEM_THREAD, MISC_FLAGS, TOP_LEVEL_IRP};

/// The registered file systems' control devices, each queue in the
/// order its file systems are asked; how many registrations there have
/// been, which tells a mount walk the queues changed under it; and
/// whether the system has shut its file systems down.
struct Database {
    queues: [Vec<usize>; 4],
    changes: u32,
    shut_down: bool,
}

/// Windows keeps this under `IopDatabaseResource`. NK holds its lock
/// only to look at or change the queues, never across a request.
static DATABASE: SpinLock<Database> = SpinLock::new(
    Rank::FileSystems,
    Database {
        queues: [Vec::new(), Vec::new(), Vec::new(), Vec::new()],
        changes: 0,
        shut_down: false,
    },
);

fn index(queue: Queue) -> usize {
    match queue {
        Queue::Disk => 0,
        Queue::CdRom => 1,
        Queue::Tape => 2,
        Queue::Network => 3,
    }
}

/// [`IoRegisterFileSystem`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-ioregisterfilesystem):
/// put a file system's control device on the queue for its type. The
/// device is counted while it is registered, and stops initialising.
///
/// # Safety
/// `device` is a live control device of a file system driver.
pub unsafe extern "C" fn IoRegisterFileSystem(device: *mut DEVICE_OBJECT) {
    ke::irql::expect_passive("IoRegisterFileSystem");
    // SAFETY: per the contract.
    unsafe {
        let queue = rules::registration_queue((*device).DeviceType);
        if matches!(queue, Some(Queue::Disk | Queue::CdRom | Queue::Tape)) {
            (*(*device).DriverObject).Flags |= DRVO_BASE_FILESYSTEM_DRIVER;
        }
        let low = (*device).Flags & DO_LOW_PRIORITY_FILESYSTEM != 0;
        (*device).Flags &= !DO_DEVICE_INITIALIZING;
        {
            let mut database = DATABASE.lock();
            if let Some(queue) = queue {
                let list = &mut database.queues[index(queue)];
                let at = if low { list.len().saturating_sub(1) } else { 0 };
                // Count the control device before publishing it on the
                // queue so concurrent mount walks or unregistrations
                // always see a referenced device (rank 12 -> rank 25).
                device::reference(device);
                list.insert(at, device.addr());
            }
            database.changes = database.changes.wrapping_add(1);
        }
    }
    trace(format_args!("registered {device:p}"));
}

/// [`IoUnregisterFileSystem`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-iounregisterfilesystem):
/// take a control device off its queue, and give up its count.
///
/// # Safety
/// `device` was registered with `IoRegisterFileSystem`.
pub unsafe extern "C" fn IoUnregisterFileSystem(device: *mut DEVICE_OBJECT) {
    ke::irql::expect_passive("IoUnregisterFileSystem");
    let removed = {
        let mut database = DATABASE.lock();
        let mut removed = false;
        for list in &mut database.queues {
            if let Some(at) = list.iter().position(|&d| d == device.addr()) {
                list.remove(at);
                removed = true;
            }
        }
        database.changes = database.changes.wrapping_add(1);
        removed
    };
    if removed {
        // SAFETY: the count `IoRegisterFileSystem` took.
        unsafe { device::dereference(device) };
    }
    trace(format_args!("unregistered {device:p}"));
}

/// Report a step of the mount path under `trace=mount`.
pub fn trace(what: core::fmt::Arguments<'_>) {
    if crate::kd::trace_mount() {
        kprintln!("mount: {what}");
    }
}

/// From now on no volume mounts (`STATUS_TOO_LATE`): the file systems
/// are being shut down.
pub fn stop_mounting() {
    DATABASE.lock().shut_down = true;
}

/// The first control device on the disk, CD-ROM and tape queues that is
/// not in `sent`, counted: the next base file system to send its
/// shutdown request. The queues are looked at afresh each time, as
/// Windows walks them, since a file system unregisters as it shuts down.
pub fn next_base(sent: &[*mut DEVICE_OBJECT]) -> Option<*mut DEVICE_OBJECT> {
    let database = DATABASE.lock();
    let device = database.queues[..3]
        .iter()
        .flatten()
        .map(|&d| core::ptr::with_exposed_provenance_mut::<DEVICE_OBJECT>(d))
        .find(|d| !sent.contains(d))?;
    // SAFETY: a registered device is counted, so live; the lock keeps it
    // registered while it is counted again.
    unsafe { device::reference(device) };
    Some(device)
}

/// Mount a volume on `real`, a device with a volume parameter block,
/// as Windows' `IopMountVolume` does. `allow_raw`: the open names the
/// device itself. `STATUS_SUCCESS` also when another mount got there
/// first.
///
/// # Safety
/// `real` is a live device with a volume parameter block, counted by
/// the caller. At `PASSIVE_LEVEL`.
pub unsafe fn mount_volume(real: *mut DEVICE_OBJECT, allow_raw: bool) -> NTSTATUS {
    if DATABASE.lock().shut_down {
        return STATUS_TOO_LATE;
    }
    super::super::ke::mutex::KeEnterCriticalRegion();
    // SAFETY: per the contract; the device lock is a synchronization
    // event in the device, which outlives the wait.
    let status = unsafe {
        ke::wait::wait(Some((&raw mut (*real).DeviceLock).cast()), None);
        let status = mount_locked(real, allow_raw);
        ke::wait::KeSetEvent(&raw mut (*real).DeviceLock, 0, 0);
        status
    };
    super::super::ke::mutex::KeLeaveCriticalRegion();
    status
}

/// `IopMountVolume` with the device's lock held.
///
/// # Safety
/// As [`mount_volume`].
unsafe fn mount_locked(real: *mut DEVICE_OBJECT, allow_raw: bool) -> NTSTATUS {
    // SAFETY: per the contract.
    unsafe {
        let vpb = (*real).Vpb.cast::<VPB>();
        let flags = super::mount::flags(vpb);
        if flags & VPB_MOUNTED != 0 {
            return STATUS_SUCCESS;
        }
        if flags & VPB_REMOVE_PENDING != 0 {
            return STATUS_NO_SUCH_DEVICE;
        }
        (*real).Flags &= !DO_VERIFY_VOLUME;
        let target = device::top(real);
        object::reference(target.cast());
        let queue = index(rules::mount_queue((*real).DeviceType));
        let raw_block = flags & VPB_RAW_MOUNT != 0;
        let mut status = STATUS_UNSUCCESSFUL;
        let mut at = 0;
        enum Pick {
            Stop,
            Skip,
            Ask(*mut DEVICE_OBJECT, usize, u32),
        }
        loop {
            let pick = {
                let database = DATABASE.lock();
                let list = &database.queues[queue];
                match list.get(at) {
                    None => Pick::Stop,
                    Some(&addr) => {
                        let len = list.len();
                        match rules::offer(at, len, allow_raw, raw_block) {
                            Offer::Stop => Pick::Stop,
                            Offer::Skip => Pick::Skip,
                            Offer::Ask => {
                                let cdo =
                                    core::ptr::with_exposed_provenance_mut::<DEVICE_OBJECT>(addr);
                                // Take the device reference while `DATABASE`
                                // still holds the registration entry, so an
                                // unregister + delete on another CPU cannot
                                // free `cdo` before we count it (rank 12 -> 25).
                                if device::reference_unless_deleted(cdo) {
                                    Pick::Ask(cdo, len, database.changes)
                                } else {
                                    Pick::Skip
                                }
                            }
                        }
                    }
                }
            };
            let (cdo, len, changes) = match pick {
                Pick::Stop => break,
                Pick::Skip => {
                    at += 1;
                    continue;
                }
                Pick::Ask(cdo, len, changes) => (cdo, len, changes),
            };
            let last = at + 1 == len;
            let (answer, information) = ask(cdo, target, vpb, allow_raw);
            device::dereference(cdo);
            status = answer;
            trace(format_args!(
                "{real:p}: file system {cdo:p} answered {:#x}",
                answer as u32
            ));
            let changed = DATABASE.lock().changes != changes;
            match rules::next(answer as u32, information, changed, allow_raw, last) {
                Next::Mounted => {
                    super::mount::mounted_by(real, target, raw_block, last);
                    break;
                }
                Next::Next => at += 1,
                Next::Restart => at = 0,
                Next::Raw => at = len - 1,
                Next::Stop => break,
            }
        }
        object::dereference(target.cast());
        status
    }
}

/// Send the file system whose control device is `cdo` the request to
/// mount `vpb`'s volume, whose device stack's top is `target`, and wait
/// for its answer. Returns the status, and the information the file
/// system returned with it if it pended the request (Windows reads it
/// only then).
///
/// # Safety
/// `cdo` is counted; `target` and `vpb` are live.
unsafe fn ask(
    cdo: *mut DEVICE_OBJECT,
    target: *mut DEVICE_OBJECT,
    vpb: *mut VPB,
    allow_raw: bool,
) -> (NTSTATUS, usize) {
    // SAFETY: per the contract; the event and the status block live on
    // this stack until the request has completed, which is waited for.
    unsafe {
        let top = device::top(cdo);
        let mut depth = 1u8;
        let mut walk = cdo;
        while !(*walk).AttachedDevice.is_null() {
            walk = (*walk).AttachedDevice;
            depth += 1;
        }
        let mut event = core::mem::zeroed::<KEVENT>();
        ke::wait::KeInitializeEvent(&raw mut event, 0, 0);
        let mut iosb = IO_STATUS_BLOCK {
            Status: 0,
            Information: 0,
        };
        let request = irp::alloc((*target).StackSize.saturating_add(depth as i8));
        if request.is_null() {
            return (STATUS_INSUFFICIENT_RESOURCES, 0);
        }
        (*request).Flags = IRP_MOUNT_COMPLETION | IRP_SYNCHRONOUS_PAGING_IO;
        (*request).RequestorMode = KERNEL_MODE;
        (*request).UserEvent = &raw mut event;
        (*request).UserIosb = &raw mut iosb;
        (*request).Thread = ke::thread::current().cast();
        let location = irp::next_location(request);
        (*location).MajorFunction = IRP_MJ_FILE_SYSTEM_CONTROL;
        (*location).MinorFunction = IRP_MN_MOUNT_VOLUME;
        (*location).Flags = if allow_raw { SL_ALLOW_RAW_MOUNT } else { 0 };
        (*location).Parameters = [vpb.addr() as u64, target.addr() as u64, 0, 0];
        object::reference(top.cast());
        let mut status = irp::IofCallDriver(top, request);
        let mut information = 0;
        if status == STATUS_PENDING {
            ke::wait::wait(Some((&raw mut event).cast()), None);
            status = iosb.Status;
            information = iosb.Information;
        }
        object::dereference(top.cast());
        (status, information)
    }
}

/// [`IoGetTopLevelIrp`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-iogettoplevelirp):
/// the running thread's `ETHREAD.TopLevelIrp`.
pub extern "C" fn IoGetTopLevelIrp() -> *mut IRP {
    let slot = ke::thread::object_field::<*mut IRP>(ke::thread::current(), TOP_LEVEL_IRP);
    // SAFETY: a field of the running thread's block.
    unsafe { slot.read() }
}

/// [`IoSetTopLevelIrp`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-iosettoplevelirp).
///
/// # Safety
/// Any value: the slot is the file system's to interpret.
pub unsafe extern "C" fn IoSetTopLevelIrp(value: *mut IRP) {
    let slot = ke::thread::object_field::<*mut IRP>(ke::thread::current(), TOP_LEVEL_IRP);
    // SAFETY: a field of the running thread's block.
    unsafe { slot.write(value) };
}

/// [`IoGetDeviceToVerify`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-iogetdevicetoverify):
/// the device `IoSetDeviceToVerify` or `IoSetHardErrorOrVerifyDevice`
/// left on `thread`.
///
/// # Safety
/// `thread` is a live thread.
pub unsafe extern "C" fn IoGetDeviceToVerify(thread: *mut c_void) -> *mut DEVICE_OBJECT {
    let slot = ke::thread::object_field::<*mut DEVICE_OBJECT>(thread.cast(), DEVICE_TO_VERIFY);
    // SAFETY: per the contract.
    unsafe { slot.read() }
}

/// [`IoSetDeviceToVerify`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-iosetdevicetoverify).
///
/// # Safety
/// `thread` is a live thread.
pub unsafe extern "C" fn IoSetDeviceToVerify(thread: *mut c_void, device: *mut DEVICE_OBJECT) {
    let slot = ke::thread::object_field::<*mut DEVICE_OBJECT>(thread.cast(), DEVICE_TO_VERIFY);
    // SAFETY: per the contract.
    unsafe { slot.write(device) };
}

/// [`IoIsSystemThread`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-iosystemthread):
/// `KTHREAD.SystemThread`.
///
/// # Safety
/// `thread` is a live thread.
pub unsafe extern "C" fn IoIsSystemThread(thread: *mut c_void) -> u8 {
    let flags = ke::thread::object_field::<u32>(thread.cast(), MISC_FLAGS);
    // SAFETY: per the contract.
    u8::from(unsafe { flags.read() } & MISC_FLAG_SYSTEM_THREAD != 0)
}

/// [`IoIsOperationSynchronous`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-iooperationsynchronous):
/// as the pinned kernel decides it: a file opened for synchronous I/O
/// or a synchronous call, unless the request is asynchronous paging
/// I/O; or synchronous paging I/O.
///
/// # Safety
/// `request` is a live IRP whose current location has a file object.
pub unsafe extern "C" fn IoIsOperationSynchronous(request: *mut IRP) -> u8 {
    // SAFETY: per the contract.
    unsafe {
        let flags = (*request).Flags;
        let file = (*(*request).CurrentStackLocation).FileObject;
        let synchronous =
            (*file).Flags & FO_SYNCHRONOUS_IO != 0 || flags & IRP_SYNCHRONOUS_API != 0;
        let paging = flags & (IRP_PAGING_IO | IRP_SYNCHRONOUS_PAGING_IO);
        u8::from(
            (synchronous || paging == IRP_PAGING_IO | IRP_SYNCHRONOUS_PAGING_IO)
                && paging != IRP_PAGING_IO,
        )
    }
}

/// [`IoGetRelatedDeviceObject`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-iogetrelateddeviceobject).
///
/// # Safety
/// `file` is a live file object.
pub unsafe extern "C" fn IoGetRelatedDeviceObject(file: *mut FILE_OBJECT) -> *mut DEVICE_OBJECT {
    // SAFETY: per the contract.
    unsafe { super::file::related_device(file) }
}
