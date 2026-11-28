//! nkfs's mount half: a file system that registers with the I/O
//! manager and is mounted on first open, for the mount path's tests
//! (`test=io.mount.*`), before Microsoft's FAT driver runs.
//!
//! A test disk, `\Device\NkTestVol` (a disk device, so it has a volume
//! parameter block), reads as [`pattern`]. Two control devices of one
//! test file system driver register on the disk queue: the first, low
//! priority, takes the volume; the second, registered after it at the
//! head, refuses it (`STATUS_UNRECOGNIZED_VOLUME`), so a first open is
//! seen to ask the head, then the low-priority one, and never RAW. The
//! volume device it mounts makes a stream file object as a real file
//! system does, runs every create on a 0x6000 stack expansion as
//! fastfat does, and splits each read into two associated requests to
//! the disk.
//!
//! Test scaffolding for the file-system phase: it goes when Microsoft's
//! FAT driver runs over NK's cache manager.

use super::except;
use crate::io::file::{self, OpenRequest};
use crate::io::{device, fs, irp};
use crate::ke::{self, expand};
use crate::mm::pool;
use crate::ob::object;
use crate::test::{Group, Report};
use core::ffi::c_void;
use core::sync::atomic::{AtomicBool, AtomicPtr, AtomicU32, AtomicU64, AtomicUsize, Ordering};
use nk_bootinfo::BootInfo;
use nk_ntabi::io::*;
use nk_ntabi::status::*;

pub static GROUP: Group = Group {
    names: &[
        "io.mount.queue",
        "io.mount.block",
        "io.mount.stream",
        "io.mount.expanded",
        "io.mount.again",
        "io.mount.associated",
        "io.mount.expand-raise",
        "io.mount.close",
        "io.mount.unregister-race",
    ],
    run,
    manual: false,
};

pub static GROUPS: &[&Group] = &[&GROUP];

const TAG: u32 = u32::from_le_bytes(*b"NkFm");
const DISK: &str = "\\Device\\NkTestVol";
const FILE: &str = "\\Device\\NkTestVol\\a";
/// `FILE_DEVICE_DISK`: a device type the I/O manager gives a volume
/// parameter block.
const FILE_DEVICE_DISK: u32 = 0x07;

/// What byte `offset` of the test disk holds.
pub fn pattern(offset: u64) -> u8 {
    (offset as u8) ^ ((offset >> 9) as u8) ^ 0xA5
}

static DISK_DEVICE: AtomicPtr<DEVICE_OBJECT> = AtomicPtr::new(core::ptr::null_mut());
/// The control device that takes the volume, and the one that refuses.
static TAKER: AtomicPtr<DEVICE_OBJECT> = AtomicPtr::new(core::ptr::null_mut());
static REFUSER: AtomicPtr<DEVICE_OBJECT> = AtomicPtr::new(core::ptr::null_mut());
static VOLUME: AtomicPtr<DEVICE_OBJECT> = AtomicPtr::new(core::ptr::null_mut());
static STREAM: AtomicPtr<FILE_OBJECT> = AtomicPtr::new(core::ptr::null_mut());
/// Which control devices were asked to mount, in order, two bits each:
/// 1 the refuser, 2 the taker.
static ASKED: AtomicU32 = AtomicU32::new(0);
/// Cleanup and close requests for the stream file, and for opened files.
static STREAM_CLEANUPS: AtomicU32 = AtomicU32::new(0);
static STREAM_CLOSES: AtomicU32 = AtomicU32::new(0);
static FILE_CLOSES: AtomicU32 = AtomicU32::new(0);
/// The bounds of the stack the last create's callout ran on.
static CREATE_STACK: AtomicU64 = AtomicU64::new(0);
static CREATES: AtomicU32 = AtomicU32::new(0);
/// Associated reads the disk served.
static DISK_READS: AtomicUsize = AtomicUsize::new(0);

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

/// The test disk's dispatch routine: a read fills the buffer with the
/// pattern.
///
/// # Safety
/// Called by the I/O manager with a request for the disk.
unsafe extern "C" fn disk_dispatch(_: *mut DEVICE_OBJECT, request: *mut IRP) -> NTSTATUS {
    // SAFETY: a request built for a device that does neither buffered
    // nor direct I/O, from the kernel: the buffer is the requestor's.
    unsafe {
        let location = (*request).CurrentStackLocation;
        if (*location).MajorFunction != IRP_MJ_READ {
            return complete(request, STATUS_INVALID_DEVICE_REQUEST, 0);
        }
        let length = (*location).Parameters[0] as u32 as usize;
        let offset = (*location).Parameters[2];
        let buffer = (*request).UserBuffer.cast::<u8>();
        for i in 0..length {
            buffer.add(i).write(pattern(offset + i as u64));
        }
        DISK_READS.fetch_add(1, Ordering::Relaxed);
        complete(request, STATUS_SUCCESS, length)
    }
}

/// The file system's dispatch routine, for its control devices and its
/// volume device.
///
/// # Safety
/// Called by the I/O manager.
unsafe extern "C" fn fs_dispatch(device: *mut DEVICE_OBJECT, request: *mut IRP) -> NTSTATUS {
    // SAFETY: requests the I/O manager sent this file system.
    unsafe {
        let location = (*request).CurrentStackLocation;
        let file = (*location).FileObject;
        let stream = !file.is_null() && (*file).Flags & FO_STREAM_FILE != 0;
        match (*location).MajorFunction {
            IRP_MJ_FILE_SYSTEM_CONTROL if (*location).MinorFunction == IRP_MN_MOUNT_VOLUME => {
                mount(device, request)
            }
            IRP_MJ_CREATE => create(request),
            IRP_MJ_CLEANUP => {
                if stream {
                    STREAM_CLEANUPS.fetch_add(1, Ordering::Relaxed);
                }
                complete(request, STATUS_SUCCESS, 0)
            }
            IRP_MJ_CLOSE => {
                let count = if stream { &STREAM_CLOSES } else { &FILE_CLOSES };
                count.fetch_add(1, Ordering::Relaxed);
                complete(request, STATUS_SUCCESS, 0)
            }
            IRP_MJ_READ => read(request),
            _ => complete(request, STATUS_INVALID_DEVICE_REQUEST, 0),
        }
    }
}

/// `IRP_MN_MOUNT_VOLUME` to control device `cdo`: the refuser refuses;
/// the taker takes the test disk alone, making its volume device and a
/// stream file object on it.
///
/// # Safety
/// `request` is the I/O manager's mount request.
unsafe fn mount(cdo: *mut DEVICE_OBJECT, request: *mut IRP) -> NTSTATUS {
    // SAFETY: the mount request's parameters: the block and the top of
    // the disk's stack.
    unsafe {
        let location = (*request).CurrentStackLocation;
        let vpb = (*location).Parameters[0] as usize as *mut VPB;
        let refuser = cdo == REFUSER.load(Ordering::Acquire);
        let _ = ASKED.try_update(Ordering::AcqRel, Ordering::Acquire, |a| {
            Some(a << 2 | if refuser { 1 } else { 2 })
        });
        if refuser || (*vpb).RealDevice != DISK_DEVICE.load(Ordering::Acquire) {
            return complete(request, STATUS_UNRECOGNIZED_VOLUME, 0);
        }
        let mut volume = core::ptr::null_mut();
        let status = device::IoCreateDevice(
            (*cdo).DriverObject,
            0,
            core::ptr::null(),
            FILE_DEVICE_DISK_FILE_SYSTEM,
            0,
            0,
            &raw mut volume,
        );
        if !nt_success(status) {
            return complete(request, status, 0);
        }
        (*volume).Flags &= !DO_DEVICE_INITIALIZING;
        (*vpb).DeviceObject = volume;
        (*vpb).SerialNumber = 0x4E4B_0001;
        VOLUME.store(volume, Ordering::Release);
        let stream = file::IoCreateStreamFileObject(core::ptr::null_mut(), (*vpb).RealDevice);
        STREAM.store(stream, Ordering::Release);
        complete(request, STATUS_SUCCESS, 0)
    }
}

/// Note the stack a create's callout runs on, by its lowest address.
///
/// # Safety
/// Takes any parameter.
unsafe extern "C" fn create_callout(_: *mut c_void) {
    let (mut low, mut high) = (0usize, 0usize);
    // SAFETY: two locals.
    unsafe { crate::io::irpinfo::IoGetStackLimits(&raw mut low, &raw mut high) };
    CREATE_STACK.store(low as u64, Ordering::Relaxed);
}

/// `IRP_MJ_CREATE` on the volume device: on a 0x6000 expansion, as
/// fastfat runs its creates.
///
/// # Safety
/// `request` is a create sent to the volume device.
unsafe fn create(request: *mut IRP) -> NTSTATUS {
    CREATES.fetch_add(1, Ordering::Relaxed);
    // SAFETY: the callout takes any parameter.
    let expanded = unsafe {
        expand::KeExpandKernelStackAndCalloutEx(
            create_callout,
            core::ptr::null_mut(),
            0x6000,
            1,
            core::ptr::null_mut(),
        )
    };
    // SAFETY: the request is ours to complete.
    unsafe { complete(request, expanded, FILE_OPENED) }
}

/// `IRP_MJ_READ` on the volume device: two associated reads to the
/// disk, one per half; the master completes when both have.
///
/// # Safety
/// `request` is a read sent to the volume device.
unsafe fn read(request: *mut IRP) -> NTSTATUS {
    // SAFETY: a kernel requestor's read on a device of neither buffered
    // nor direct I/O: the buffer is the requestor's, live until the
    // master completes.
    unsafe {
        let location = (*request).CurrentStackLocation;
        let length = (*location).Parameters[0] as u32 as usize;
        let offset = (*location).Parameters[2];
        let disk = DISK_DEVICE.load(Ordering::Acquire);
        let half = length / 2;
        let parts = [(0, half), (half, length - half)];
        let mut associated = [core::ptr::null_mut(); 2];
        for (slot, _) in associated.iter_mut().zip(parts) {
            *slot = irp::IoMakeAssociatedIrp(request, (*disk).StackSize);
        }
        if associated.iter().any(|a| a.is_null()) {
            for a in associated.into_iter().filter(|a| !a.is_null()) {
                irp::free(a);
            }
            return complete(request, STATUS_INSUFFICIENT_RESOURCES, 0);
        }
        // The master's status is the file system's to set; the count is
        // its to start.
        (*request).IoStatus.Status = STATUS_SUCCESS;
        (*request).IoStatus.Information = length;
        (&raw mut (*request).SystemBuffer).cast::<i32>().write(2);
        (*location).Control |= SL_PENDING_RETURNED;
        for (a, (start, len)) in associated.into_iter().zip(parts) {
            (*a).UserBuffer = (*request).UserBuffer.cast::<u8>().add(start).cast();
            let next = irp::next_location(a);
            (*next).MajorFunction = IRP_MJ_READ;
            (*next).Parameters = [len as u64, 0, offset + start as u64, 0];
            irp::IofCallDriver(disk, a);
        }
        STATUS_PENDING
    }
}

/// A driver object in pool, for a test driver, with `dispatch` for
/// every major function.
fn driver(dispatch: DRIVER_DISPATCH) -> Option<*mut DRIVER_OBJECT> {
    let size = size_of::<DRIVER_OBJECT>() + size_of::<DRIVER_EXTENSION>();
    let driver = pool::alloc_zeroed(size, TAG).cast::<DRIVER_OBJECT>();
    if driver.is_null() {
        return None;
    }
    // SAFETY: a fresh block of a driver object's size.
    unsafe {
        (*driver).Type = IO_TYPE_DRIVER;
        (*driver).Size = size_of::<DRIVER_OBJECT>() as i16;
        (*driver).DriverExtension = driver.add(1).cast();
        (*driver).MajorFunction = [Some(dispatch); IRP_MJ_MAXIMUM_FUNCTION + 1];
    }
    Some(driver)
}

/// A device of `driver`'s, named `name` if given.
fn create_device(
    driver: *mut DRIVER_OBJECT,
    name: Option<&str>,
    device_type: u32,
) -> Option<*mut DEVICE_OBJECT> {
    let mut wide: alloc::vec::Vec<u16> = name.unwrap_or("").encode_utf16().collect();
    let unicode = UNICODE_STRING {
        Length: (wide.len() * 2) as u16,
        MaximumLength: (wide.len() * 2) as u16,
        Buffer: wide.as_mut_ptr(),
    };
    let mut device_object = core::ptr::null_mut();
    // SAFETY: the test's driver object; the name is copied.
    unsafe {
        let name = if name.is_some() {
            &raw const unicode
        } else {
            core::ptr::null()
        };
        if !nt_success(device::IoCreateDevice(
            driver,
            0,
            name,
            device_type,
            0,
            0,
            &raw mut device_object,
        )) {
            return None;
        }
        (*device_object).Flags &= !DO_DEVICE_INITIALIZING;
    }
    Some(device_object)
}

fn open(name: &str) -> Result<u64, NTSTATUS> {
    file::open(&OpenRequest::new(name)).map(|(handle, _)| handle)
}

fn check(r: &mut Report, name: &str, ok: bool, why: &str) {
    if ok {
        r.ok(name);
    } else {
        r.fail(name, format_args!("{why}"));
    }
}

fn run(r: &mut Report, _: &BootInfo) {
    let (Some(disk_driver), Some(fs_driver)) = (driver(disk_dispatch), driver(fs_dispatch)) else {
        r.skip_rest(format_args!("no memory for the test drivers"));
        return;
    };
    let disk = create_device(disk_driver, Some(DISK), FILE_DEVICE_DISK);
    let taker = create_device(fs_driver, None, FILE_DEVICE_DISK_FILE_SYSTEM);
    let refuser = create_device(fs_driver, None, FILE_DEVICE_DISK_FILE_SYSTEM);
    let (Some(disk), Some(taker), Some(refuser)) = (disk, taker, refuser) else {
        r.skip_rest(format_args!("the test devices could not be made"));
        return;
    };
    DISK_DEVICE.store(disk, Ordering::Release);
    TAKER.store(taker, Ordering::Release);
    REFUSER.store(refuser, Ordering::Release);
    for count in [
        &ASKED,
        &STREAM_CLEANUPS,
        &STREAM_CLOSES,
        &FILE_CLOSES,
        &CREATES,
    ] {
        count.store(0, Ordering::Relaxed);
    }
    // SAFETY: the test's control devices.
    unsafe {
        (*taker).Flags |= DO_LOW_PRIORITY_FILESYSTEM;
        fs::IoRegisterFileSystem(taker);
        fs::IoRegisterFileSystem(refuser);
    }

    // The first open of a name on the disk mounts it.
    let first = open(FILE);
    check(
        r,
        "io.mount.queue",
        first.is_ok() && ASKED.load(Ordering::Acquire) == 0b0110,
        "a first open did not ask the head of the queue, then the low-priority file system, and stop there",
    );
    // SAFETY: the disk is live; its block is read under the lock.
    let (flags, mounted, references) = unsafe {
        let vpb = (*disk).Vpb.cast::<VPB>();
        (
            crate::io::mount::flags(vpb),
            (*vpb).DeviceObject,
            (*vpb).ReferenceCount,
        )
    };
    let volume = VOLUME.load(Ordering::Acquire);
    // The mount's own reference, the stream file object's, the open's.
    check(
        r,
        "io.mount.block",
        flags == VPB_MOUNTED && mounted == volume && !volume.is_null() && references == 3
            // SAFETY: the volume device, live while mounted.
            && unsafe { (*volume).StackSize } == unsafe { (*disk).StackSize } + 1,
        "the block was not marked mounted on the file system's volume device, counted and sized as Windows does",
    );
    check(
        r,
        "io.mount.stream",
        STREAM_CLEANUPS.load(Ordering::Acquire) == 1 && STREAM_CLOSES.load(Ordering::Acquire) == 0,
        "a stream file object's handle did not send its cleanup at once, or sent a close",
    );
    let segment = CREATE_STACK.load(Ordering::Acquire);
    let own = ke::thread::current_stacks().next().map_or(0, |s| s.base);
    check(
        r,
        "io.mount.expanded",
        CREATES.load(Ordering::Acquire) == 1 && segment != 0 && segment != own,
        "the create did not reach the volume device, or its 0x6000 callout ran on the thread's stack",
    );
    let second = open(FILE);
    check(
        r,
        "io.mount.again",
        second.is_ok()
            && ASKED.load(Ordering::Acquire) == 0b0110
            && CREATES.load(Ordering::Acquire) == 2,
        "a second open mounted again, or did not reach the volume device",
    );
    let mut buffer = [0u8; 1024];
    let read = first
        .map_err(|_| ())
        .and_then(|h| file::read_at(h, 0x200, &mut buffer).map_err(|_| ()));
    let right = buffer
        .iter()
        .enumerate()
        .all(|(i, &b)| b == pattern(0x200 + i as u64));
    check(
        r,
        "io.mount.associated",
        read.is_ok_and(|res| res.status == STATUS_SUCCESS && res.information == 1024)
            && right
            && DISK_READS.load(Ordering::Acquire) == 2,
        "a read split into two associated requests did not complete its master with their data",
    );
    r.check("io.mount.expand-raise", || {
        except::raises(
            expand::raise_on_segment,
            except::CODE as usize,
            except::CODE,
        )?;
        expand::after_raise_test()
    });

    // Closing everything: each open's close, then the stream file
    // object's when its last reference goes.
    for handle in [first, second].into_iter().flatten() {
        file::close(handle);
    }
    let stream = STREAM.swap(core::ptr::null_mut(), Ordering::AcqRel);
    if !stream.is_null() {
        // SAFETY: the reference IoCreateStreamFileObject gave.
        unsafe { object::dereference(stream.cast()) };
    }
    // SAFETY: the block, read under the lock.
    let left = unsafe { (*(*disk).Vpb.cast::<VPB>()).ReferenceCount };
    check(
        r,
        "io.mount.close",
        FILE_CLOSES.load(Ordering::Acquire) == 2
            && STREAM_CLOSES.load(Ordering::Acquire) == 1
            && left == 1,
        "the opens' and the stream file object's closes did not come, or left the block counted",
    );
    // SAFETY: the test's devices and drivers, nothing open on them.
    unsafe {
        fs::IoUnregisterFileSystem(refuser);
        fs::IoUnregisterFileSystem(taker);
        if !volume.is_null() {
            device::IoDeleteDevice(volume);
        }
        device::IoDeleteDevice(refuser);
        device::IoDeleteDevice(taker);
        device::IoDeleteDevice(disk);
    }
    VOLUME.store(core::ptr::null_mut(), Ordering::Release);
    r.check("io.mount.unregister-race", || {
        unregister_race_test(disk_driver)
    });
    let _ = pool::free(fs_driver.cast());
    let _ = pool::free(disk_driver.cast());
}

const RACE_MAGIC: u64 = 0x4E4B_4653_5241_4345;
static RACE_STOP: AtomicBool = AtomicBool::new(false);
static RACE_BAD: AtomicBool = AtomicBool::new(false);
static RACE_MOUNTS: AtomicU32 = AtomicU32::new(0);
static RACE_ASKED: AtomicU32 = AtomicU32::new(0);

/// # Safety
/// Called by the I/O manager for a temporary control device during
/// `unregister_race_test`.
unsafe extern "C" fn race_fs_dispatch(cdo: *mut DEVICE_OBJECT, request: *mut IRP) -> NTSTATUS {
    // SAFETY: `cdo` is live while this mount request runs; its extension
    // holds `RACE_MAGIC` for the life of the device.
    unsafe {
        let ext = (*cdo).DeviceExtension.cast::<u64>();
        if ext.is_null() || ext.read() != RACE_MAGIC {
            RACE_BAD.store(true, Ordering::Release);
        }
        RACE_ASKED.fetch_add(1, Ordering::Relaxed);
        complete(request, STATUS_UNRECOGNIZED_VOLUME, 0)
    }
}

/// Race `IoUnregisterFileSystem` + `IoDeleteDevice` on temporary control
/// devices against concurrent `mount_volume` walks on another CPU.
fn unregister_race_test(disk_driver: *mut DRIVER_OBJECT) -> Result<(), &'static str> {
    fn mounter(arg: usize) {
        let disk = arg as *mut DEVICE_OBJECT;
        while !RACE_STOP.load(Ordering::Acquire) {
            // SAFETY: `disk` is live until this thread exits.
            let _ = unsafe { fs::mount_volume(disk, false) };
            RACE_MOUNTS.fetch_add(1, Ordering::Relaxed);
            ke::thread::yield_now();
        }
    }

    let Some(race_driver) = driver(race_fs_dispatch) else {
        return Err("no memory for the unregister-race driver");
    };
    let Some(disk) = create_device(disk_driver, None, FILE_DEVICE_DISK) else {
        let _ = pool::free(race_driver.cast());
        return Err("no memory for the unregister-race disk");
    };
    RACE_STOP.store(false, Ordering::Release);
    RACE_BAD.store(false, Ordering::Release);
    RACE_MOUNTS.store(0, Ordering::Relaxed);
    RACE_ASKED.store(0, Ordering::Relaxed);

    let before = ke::thread::count();
    let worker = ke::thread::create_referenced(
        mounter,
        disk.addr(),
        ke::thread::NORMAL_PRIORITY,
        ke::thread::ANYWHERE,
    )?;

    let mut failed = None;
    for _ in 0..64 {
        let mut cdo = core::ptr::null_mut();
        // SAFETY: live driver object and output local.
        let status = unsafe {
            device::IoCreateDevice(
                race_driver,
                size_of::<u64>() as u32,
                core::ptr::null(),
                FILE_DEVICE_DISK_FILE_SYSTEM,
                0,
                0,
                &raw mut cdo,
            )
        };
        if !nt_success(status) || cdo.is_null() {
            failed = Some("could not create temporary control device");
            break;
        }
        // SAFETY: fresh device with 8-byte extension.
        unsafe {
            (*cdo).DeviceExtension.cast::<u64>().write(RACE_MAGIC);
            fs::IoRegisterFileSystem(cdo);
        }
        ke::thread::yield_now();
        // SAFETY: registered above, deleted once unregistered.
        unsafe {
            fs::IoUnregisterFileSystem(cdo);
            device::IoDeleteDevice(cdo);
        }
    }

    RACE_STOP.store(true, Ordering::Release);
    // SAFETY: referenced thread object.
    unsafe {
        ke::wait::wait(Some(worker.cast()), None);
        object::dereference(worker.cast());
        device::IoDeleteDevice(disk);
        let _ = pool::free(race_driver.cast());
    }
    ke::thread::settle(before);

    if let Some(why) = failed {
        return Err(why);
    }
    if RACE_BAD.load(Ordering::Acquire) {
        return Err("mount request observed a corrupted or freed control device");
    }
    if RACE_MOUNTS.load(Ordering::Relaxed) == 0 {
        return Err("mounter thread did not run any mount walks");
    }
    Ok(())
}
