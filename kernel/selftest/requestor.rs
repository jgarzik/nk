//! Tests of what the I/O manager does for a requestor before a driver
//! sees the request and after the driver is done with it: the access a
//! user-mode request needs of its handle, and the memory it may name as
//! its buffers.
//!
//! The driver is here, in Rust, as in `pend`: what is under test is the
//! I/O manager's side.

use crate::io::file::{self, IoError, OpenRequest};
use crate::io::{device, irp};
use crate::mm::{self, pool, user};
use crate::test::{Group, Report};
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU32, Ordering};
use nk_bootinfo::BootInfo;
use nk_ntabi::io::*;
use nk_ntabi::status::*;

pub static GROUP: Group = Group {
    names: &["io.user.access", "io.user.firmware-buffer"],
    run,
    manual: false,
};

const DEVICE: &str = "\\Device\\NkRequestor";
const PIPE: &str = "\\Device\\NkRequestor\\pipe";
const SYNCHRONIZE: u32 = 0x0010_0000;

/// Requests the driver was sent, creates, cleanups and closes aside.
static SERVED: AtomicU32 = AtomicU32::new(0);

/// Complete `irp` with success and nothing returned.
///
/// # Safety
/// Called from a dispatch routine with its IRP.
unsafe fn succeed(irp: *mut IRP) -> NTSTATUS {
    // SAFETY: per the contract.
    unsafe {
        (*irp).IoStatus.Status = STATUS_SUCCESS;
        (*irp).IoStatus.Information = 0;
        irp::IofCompleteRequest(irp, 0);
    }
    STATUS_SUCCESS
}

/// A file opened by a name below the device is a named pipe, marked as
/// a pipe's file system marks it.
///
/// # Safety
/// Called as a dispatch routine for a create, cleanup or close request.
unsafe extern "C" fn open_or_close(_: *mut DEVICE_OBJECT, irp: *mut IRP) -> NTSTATUS {
    // SAFETY: a live IRP being dispatched, and its file object.
    unsafe {
        let location = (*irp).CurrentStackLocation;
        let file = (*location).FileObject;
        if (*location).MajorFunction == IRP_MJ_CREATE && (*file).FileName.Length != 0 {
            (*file).Flags |= FO_NAMED_PIPE;
        }
        succeed(irp)
    }
}

/// # Safety
/// Called as a dispatch routine for a read, write or control request.
unsafe extern "C" fn serve(_: *mut DEVICE_OBJECT, irp: *mut IRP) -> NTSTATUS {
    SERVED.fetch_add(1, Ordering::AcqRel);
    // SAFETY: a live IRP being dispatched.
    unsafe { succeed(irp) }
}

/// Make the driver and its device, run `test`, and take both down.
fn with_driver(test: impl FnOnce() -> Result<u32, &'static str>) -> Result<u32, &'static str> {
    let size = size_of::<DRIVER_OBJECT>() + size_of::<DRIVER_EXTENSION>();
    let driver = pool::alloc_zeroed(size, u32::from_le_bytes(*b"Test")).cast::<DRIVER_OBJECT>();
    if driver.is_null() {
        return Err("no memory for a driver object");
    }
    let mut name: Vec<u16> = DEVICE.encode_utf16().collect();
    let name = UNICODE_STRING {
        Length: (name.len() * 2) as u16,
        MaximumLength: (name.len() * 2) as u16,
        Buffer: name.as_mut_ptr(),
    };
    let mut device_object = core::ptr::null_mut();
    // SAFETY: the test's own driver object, set up as `driver::load`
    // sets one up.
    let result = unsafe {
        (*driver).MajorFunction = [Some(irp::invalid_device_request); IRP_MJ_MAXIMUM_FUNCTION + 1];
        for major in [IRP_MJ_CREATE, IRP_MJ_CLEANUP, IRP_MJ_CLOSE] {
            (*driver).MajorFunction[usize::from(major)] = Some(open_or_close);
        }
        for major in [
            IRP_MJ_READ,
            IRP_MJ_WRITE,
            IRP_MJ_DEVICE_CONTROL,
            IRP_MJ_FILE_SYSTEM_CONTROL,
        ] {
            (*driver).MajorFunction[usize::from(major)] = Some(serve);
        }
        if device::IoCreateDevice(
            driver,
            0,
            &raw const name,
            0x22,
            0,
            0,
            &raw mut device_object,
        ) != 0
        {
            let _ = pool::free(driver.cast());
            return Err("could not create the test device");
        }
        (*device_object).Flags &= !DO_DEVICE_INITIALIZING;
        let result = test();
        let open = (*device_object).ReferenceCount;
        device::IoDeleteDevice(device_object);
        result.and_then(|n| match open {
            0 => Ok(n),
            _ => Err("a file closed for good still holds its device"),
        })
    };
    let _ = pool::free(driver.cast());
    result
}

/// Open the device, or the pipe below it, for exactly `access`.
fn open_for(access: u32, pipe: bool) -> Result<u64, &'static str> {
    let request = OpenRequest {
        desired_access: access,
        ..OpenRequest::new(if pipe { PIPE } else { DEVICE })
    };
    file::open(&request)
        .map(|(handle, _)| handle)
        .map_err(|_| "the device did not open")
}

/// A request made for user mode reaches the driver only through a
/// handle that was granted the access the request needs: to read, to
/// write or append, and for a control request what its code says.
/// Kernel mode's requests are not held to it. Returns the requests
/// made.
fn access() -> Result<u32, &'static str> {
    const READ: u32 = 1;
    const WRITE: u32 = 2;
    const APPEND: u32 = 4;
    let control = |access| ctl_code(0x22, 0x800, METHOD_NEITHER, access);
    // The handles, by what they were opened for and whether to a pipe,
    // and which of the requests below each may make.
    let handles = [
        (READ, false, [true, false, true, true, false, false]),
        (WRITE, false, [false, true, true, false, true, false]),
        (APPEND, false, [false, true, true, false, false, false]),
        (READ | WRITE, false, [true, true, true, true, true, true]),
        (0, false, [false, false, true, false, false, false]),
        // A pipe has no appending.
        (APPEND, true, [false, false, true, false, false, false]),
        (WRITE, true, [false, true, true, false, true, false]),
    ];
    let mut made = 0;
    for (granted, pipe, allowed) in handles {
        let handle = open_for(granted | SYNCHRONIZE, pipe)?;
        let none = file::Buffer::NONE;
        let requests = [
            file::user_transfer(handle, IRP_MJ_READ, none),
            file::user_transfer(handle, IRP_MJ_WRITE, none),
            file::user_control(handle, IRP_MJ_DEVICE_CONTROL, control(0), none, none),
            file::user_control(handle, IRP_MJ_DEVICE_CONTROL, control(1), none, none),
            file::user_control(handle, IRP_MJ_FILE_SYSTEM_CONTROL, control(2), none, none),
            file::user_control(handle, IRP_MJ_DEVICE_CONTROL, control(3), none, none),
        ];
        let before = SERVED.load(Ordering::Acquire);
        // Kernel mode asks for nothing of its handle.
        let kernel = [
            file::read(handle, &mut []),
            file::write(handle, &[]),
            file::device_control(handle, control(3), &[], &mut []),
        ];
        let served = SERVED.load(Ordering::Acquire) - before;
        file::close(handle);
        for (got, allowed) in requests.iter().zip(allowed) {
            made += 1;
            match (got, allowed) {
                (Ok(r), true) if r.status == STATUS_SUCCESS => {}
                (Err(IoError::Handle(STATUS_ACCESS_DENIED)), false) => {}
                (Ok(_), false) => {
                    return Err(
                        "a user-mode request went through a handle not granted the access it needs",
                    );
                }
                _ => return Err("a user-mode request the handle allows was refused"),
            }
        }
        if served != 3
            || kernel
                .iter()
                .any(|r| r.map(|r| r.status) != Ok(STATUS_SUCCESS))
        {
            return Err("a kernel-mode request was held to its handle's access");
        }
        made += 3;
    }
    // Every handle's three kernel requests, and the user requests
    // allowed: the driver saw no other.
    let allowed: u32 = handles
        .iter()
        .map(|(_, _, allowed)| allowed.iter().filter(|a| **a).count() as u32)
        .sum();
    if SERVED.swap(0, Ordering::AcqRel) != allowed + 3 * handles.len() as u32 {
        return Err("the driver was sent a request the I/O manager refused");
    }
    Ok(made)
}

/// The low half of the address space holds firmware's runtime memory
/// besides the user range, mapped and writable. It is not user mode's
/// to name: a request whose buffer touches it is refused with the
/// access violation of a buffer that is not there, by every probe, and
/// no driver sees it. Returns the requests made.
fn firmware_buffer() -> Result<u32, &'static str> {
    let region = mm::firmware_regions()
        .map(|(region, _)| region)
        .find(|r| r.phys > user::LOWEST_USER_ADDRESS && r.end() <= user::USER_PROBE_ADDRESS)
        .ok_or("firmware has no runtime region in the user range")?;
    let firmware = file::Buffer {
        address: region.phys as usize,
        len: 16,
    };
    let handle = open_for(0x1F_01FF, false)?;
    let none = file::Buffer::NONE;
    let control = |method| ctl_code(0x22, 0x801, method, 0);
    let device = IRP_MJ_DEVICE_CONTROL;
    let requests = [
        file::user_transfer(handle, IRP_MJ_READ, firmware),
        file::user_transfer(handle, IRP_MJ_WRITE, firmware),
        file::user_control(handle, device, control(METHOD_BUFFERED), firmware, none),
        file::user_control(handle, device, control(METHOD_BUFFERED), none, firmware),
        file::user_control(handle, device, control(METHOD_IN_DIRECT), none, firmware),
        file::user_control(handle, device, control(METHOD_OUT_DIRECT), none, firmware),
    ];
    file::close(handle);
    let served = SERVED.swap(0, Ordering::AcqRel);
    if requests
        .iter()
        .any(|r| r.map(|r| r.status) != Ok(STATUS_ACCESS_VIOLATION))
    {
        return Err("a user-mode request was let name firmware's memory as its buffer");
    }
    if served != 0 {
        return Err("the driver was sent a request whose buffer is firmware's memory");
    }
    // The last byte of a range is firmware's, or the first.
    if user::in_range(region.phys as usize - 1, 2) || user::in_range(region.end() as usize - 1, 2) {
        return Err("a range that runs into or out of firmware's memory passed as user memory");
    }
    if user::frame_of(region.phys).is_some() {
        return Err("a page of firmware's memory was found as a user page");
    }
    Ok(requests.len() as u32)
}

fn run(r: &mut Report, _: &BootInfo) {
    let mut counted = |name, result: Result<u32, &'static str>| match result {
        Ok(n) => r.ok_with(name, format_args!("requests: {n}")),
        Err(why) => r.fail(name, format_args!("{why}")),
    };
    counted("io.user.access", with_driver(access));
    counted("io.user.firmware-buffer", with_driver(firmware_buffer));
}
