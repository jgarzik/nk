//! Tests of what the I/O manager does for a requestor before a driver
//! sees the request and after the driver is done with it: the access a
//! user-mode request needs of its handle, the memory it may name as
//! its buffers, what becomes of results that cannot be copied to it,
//! and an open whose create request the driver pends.
//!
//! The driver is here, in Rust, as in `pend`: what is under test is the
//! I/O manager's side.

use super::USER_OUTPUT;
use crate::io::file::{self, IoError, IoResult, OpenRequest};
use crate::io::{device, irp};
use crate::ke::{dpc, thread, time, timer};
use crate::mm::{self, pool, user};
use crate::test::{Group, Report, Slot};
use alloc::vec::Vec;
use core::ffi::c_void;
use core::sync::atomic::{AtomicPtr, AtomicU32, Ordering};
use nk_bootinfo::BootInfo;
use nk_ntabi::io::*;
use nk_ntabi::ke::{KDPC, KTIMER};
use nk_ntabi::status::*;

pub static GROUP: Group = Group {
    names: &[
        "io.user.access",
        "io.user.firmware-buffer",
        "io.user.copy-out-fault",
        "io.open.pended",
        "io.open.user-root",
        "io.open.closed-at-once",
    ],
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

/// What the last character of a file's name asks of its create
/// request: pended, and completed 20 ms later by a timer's DPC, with
/// success or as refused; or left uncompleted, the dispatch routine
/// returning success all the same.
const LATER: u16 = b'+' as u16;
const LATER_REFUSED: u16 = b'-' as u16;
const NEVER: u16 = b'!' as u16;
/// What a pended create that succeeds reports for the open.
const OPENED_LATER: usize = 0x5A;

/// The create request the driver holds, its timer and the timer's DPC.
static HELD: AtomicPtr<IRP> = AtomicPtr::new(core::ptr::null_mut());
static TIMER: Slot<KTIMER> = Slot::new();
static DPC: Slot<KDPC> = Slot::new();
/// The access the held create asked for, as its security context and
/// access state said when the request was completed.
static ASKED_AT_COMPLETION: [AtomicU32; 2] = [AtomicU32::new(0), AtomicU32::new(0)];
/// Create, cleanup and close requests the driver was sent.
static CREATES: AtomicU32 = AtomicU32::new(0);
static CLEANUPS: AtomicU32 = AtomicU32::new(0);
static CLOSES: AtomicU32 = AtomicU32::new(0);

/// Complete the held create request.
///
/// # Safety
/// Called as a DPC routine; it dereferences none of its arguments.
unsafe extern "C" fn complete_held(_: *mut KDPC, _: *mut c_void, _: *mut c_void, _: *mut c_void) {
    let irp = HELD.swap(core::ptr::null_mut(), Ordering::AcqRel);
    if irp.is_null() {
        return;
    }
    // SAFETY: the driver's own pended create request: what it points to
    // is the I/O manager's and stays until the request is completed.
    unsafe {
        let location = (*irp).CurrentStackLocation;
        let context = (*location).Parameters[0] as *const IO_SECURITY_CONTEXT;
        ASKED_AT_COMPLETION[0].store((*context).DesiredAccess, Ordering::Release);
        ASKED_AT_COMPLETION[1].store(
            (*(*context).AccessState).OriginalDesiredAccess,
            Ordering::Release,
        );
        let name = (*(*location).FileObject).FileName;
        let last = name.Buffer.add(usize::from(name.Length) / 2 - 1).read();
        let (status, information) = if last == LATER {
            (STATUS_SUCCESS, OPENED_LATER)
        } else {
            (STATUS_ACCESS_DENIED, 0)
        };
        (*irp).IoStatus.Status = status;
        (*irp).IoStatus.Information = information;
        irp::IofCompleteRequest(irp, 0);
    }
}

/// A file opened by a name below the device is a named pipe, marked as
/// a pipe's file system marks it.
///
/// # Safety
/// Called as a dispatch routine for a create, cleanup or close request.
unsafe extern "C" fn open_or_close(_: *mut DEVICE_OBJECT, irp: *mut IRP) -> NTSTATUS {
    // SAFETY: a live IRP being dispatched, and its file object; the
    // statics are the driver's.
    unsafe {
        let location = (*irp).CurrentStackLocation;
        let file = (*location).FileObject;
        match (*location).MajorFunction {
            IRP_MJ_CREATE => drop(CREATES.fetch_add(1, Ordering::AcqRel)),
            IRP_MJ_CLEANUP => drop(CLEANUPS.fetch_add(1, Ordering::AcqRel)),
            IRP_MJ_CLOSE => drop(CLOSES.fetch_add(1, Ordering::AcqRel)),
            _ => {}
        }
        let name = (*file).FileName;
        if (*location).MajorFunction == IRP_MJ_CREATE && name.Length != 0 {
            (*file).Flags |= FO_NAMED_PIPE;
            let last = name.Buffer.add(usize::from(name.Length) / 2 - 1).read();
            if last == NEVER {
                return STATUS_SUCCESS;
            }
            if last == LATER || last == LATER_REFUSED {
                // `IoMarkIrpPending`.
                (*location).Control |= SL_PENDING_RETURNED;
                HELD.store(irp, Ordering::Release);
                timer::KeSetTimer(TIMER.ptr(), -20 * 10_000, DPC.ptr());
                return STATUS_PENDING;
            }
        }
        succeed(irp)
    }
}

/// Buffered control requests during which the requestor's output
/// buffer, the page at `USER_OUTPUT`, goes away: answered in full, at
/// once, or marked pending first.
const GONE: u32 = ctl_code(0x22, 0x810, METHOD_BUFFERED, 0);
const GONE_PENDED: u32 = ctl_code(0x22, 0x811, METHOD_BUFFERED, 0);

/// # Safety
/// Called as a dispatch routine for a read, write or control request.
unsafe extern "C" fn serve(_: *mut DEVICE_OBJECT, irp: *mut IRP) -> NTSTATUS {
    SERVED.fetch_add(1, Ordering::AcqRel);
    // SAFETY: a live IRP being dispatched; a buffered request's system
    // buffer is as long as the output asked for.
    unsafe {
        let location = (*irp).CurrentStackLocation;
        let code = match (*location).MajorFunction {
            IRP_MJ_DEVICE_CONTROL => (*location).Parameters[2] as u32,
            _ => 0,
        };
        if code != GONE && code != GONE_PENDED {
            return succeed(irp);
        }
        // What another thread of the requestor's process may do while
        // its request is served.
        user::unmap_pages(USER_OUTPUT, 1);
        let wanted = (*location).Parameters[0] as usize;
        (*irp).SystemBuffer.cast::<u8>().write_bytes(0x5A, wanted);
        (*irp).IoStatus.Status = STATUS_SUCCESS;
        (*irp).IoStatus.Information = wanted;
        if code == GONE_PENDED {
            // `IoMarkIrpPending`.
            (*location).Control |= SL_PENDING_RETURNED;
            irp::IofCompleteRequest(irp, 0);
            return STATUS_PENDING;
        }
        irp::IofCompleteRequest(irp, 0);
        STATUS_SUCCESS
    }
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
        dpc::KeInitializeDpc(DPC.ptr(), Some(complete_held), core::ptr::null_mut());
        timer::KeInitializeTimer(TIMER.ptr());
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
        requestor_mode: USER_MODE,
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
                (Ok(r), false) if r.status == STATUS_ACCESS_DENIED => {}
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

/// A user-mode requestor's buffer is probed when the request is made
/// and may be gone when the results are copied to it. The fault is the
/// request's final status, as on Windows, where the exception of the
/// copy becomes `IoStatus.Status`: what the system service returns for
/// a request the driver pended. For one the driver completed before
/// its dispatch routine returned, the service returns the routine's
/// own status. Either way the driver kept its contract. Returns the
/// requests made.
fn copy_out_fault() -> Result<u32, &'static str> {
    let handle = open_for(0x1F_01FF, false)?;
    let output = file::Buffer {
        address: USER_OUTPUT as usize,
        len: 8,
    };
    let mut results = [Err(IoError::NoMemory); 2];
    for (result, code) in results.iter_mut().zip([GONE, GONE_PENDED]) {
        if user::map_pages(USER_OUTPUT, 1).is_err() {
            file::close(handle);
            return Err("cannot map a user page");
        }
        *result = file::user_control(
            handle,
            IRP_MJ_DEVICE_CONTROL,
            code,
            file::Buffer::NONE,
            output,
        );
        if user::frame_of(USER_OUTPUT).is_some() {
            user::unmap_pages(USER_OUTPUT, 1);
            file::close(handle);
            return Err("the driver was not sent the request, or left the buffer mapped");
        }
    }
    file::close(handle);
    SERVED.store(0, Ordering::Release);
    if matches!(results[0], Err(IoError::StatusMismatch { .. })) {
        return Err("results that could not be copied out were blamed on the driver's statuses");
    }
    let came_back = |status| {
        Ok(IoResult {
            status,
            information: 8,
        })
    };
    if results[0] != came_back(STATUS_SUCCESS) {
        return Err("a request completed at once did not return its dispatch routine's status");
    }
    if results[1] != came_back(STATUS_ACCESS_VIOLATION) {
        return Err("a pended request whose results could not be copied did not end as the fault");
    }
    Ok(2)
}

/// A driver may pend a create request and complete it later. The open
/// waits, as `IoCreateFile` does: what the request points to (the
/// security context, the access state) is there until then, and the
/// open ends as the request was completed. Returns the opens made.
fn pended_open() -> Result<u32, &'static str> {
    const READ: u32 = 0x0012_0089;
    let open = |name| {
        ASKED_AT_COMPLETION[0].store(0, Ordering::Release);
        ASKED_AT_COMPLETION[1].store(0, Ordering::Release);
        let request = OpenRequest {
            desired_access: READ,
            ..OpenRequest::new(name)
        };
        let before = time::interrupt_time();
        let opened = file::open(&request);
        let asked = [
            ASKED_AT_COMPLETION[0].load(Ordering::Acquire),
            ASKED_AT_COMPLETION[1].load(Ordering::Acquire),
        ];
        // The timer's 20 ms is the least the open can have waited.
        (opened, time::interrupt_time() - before >= 200_000, asked)
    };
    CLEANUPS.store(0, Ordering::Release);
    CLOSES.store(0, Ordering::Release);
    let (opened, waited, asked) = open("\\Device\\NkRequestor\\pended+");
    let Ok((handle, information)) = opened else {
        return Err("a create the driver pended and then completed did not open the file");
    };
    let closed = file::close(handle);
    if information != OPENED_LATER || !waited {
        return Err("the open did not wait for the pended create and return what it reported");
    }
    if asked != [READ; 2] {
        return Err("a pended create's security context was not there when it was completed");
    }
    let requests = |cleanups, closes| {
        CLEANUPS.load(Ordering::Acquire) == cleanups && CLOSES.load(Ordering::Acquire) == closes
    };
    if closed != STATUS_SUCCESS || !requests(1, 1) {
        return Err("a file opened by a pended create was not cleaned up and closed, once");
    }
    let (opened, waited, asked) = open("\\Device\\NkRequestor\\pended-");
    if opened != Err(STATUS_ACCESS_DENIED) || !waited || asked != [READ; 2] {
        return Err("a create pended and then refused did not fail the open with its status");
    }
    if !requests(1, 1) {
        return Err("the driver heard more of a file whose pended create it refused");
    }
    Ok(2)
}

/// An open names its root by handle, and the handle is the requestor's:
/// Windows references it on behalf of the open's mode and asks no
/// access of it (`ObpLookupObjectName`). So a kernel handle is no root
/// for an open made for user mode, and no driver hears of that open;
/// the same entry by the name user mode has for it is one. Returns the
/// opens made.
fn user_root() -> Result<u32, &'static str> {
    // Granted nothing: no access is asked of a root.
    let request = OpenRequest {
        desired_access: 0,
        ..OpenRequest::new(DEVICE)
    };
    let kernel = file::open(&request)
        .map(|(handle, _)| handle)
        .map_err(|_| "the device did not open")?;
    let relative = |root, mode| {
        CREATES.store(0, Ordering::Release);
        let request = OpenRequest {
            root: Some(root),
            requestor_mode: mode,
            ..OpenRequest::new("below")
        };
        let opened = file::open(&request).map(|(handle, _)| file::close(handle));
        (opened, CREATES.load(Ordering::Acquire))
    };
    let own = kernel & !nk_ntabi::ob::KERNEL_HANDLE;
    let opens = [
        relative(kernel, USER_MODE),
        relative(own, USER_MODE),
        relative(kernel, KERNEL_MODE),
        relative(own, KERNEL_MODE),
    ];
    file::close(kernel);
    if opens[0].0.is_ok() {
        return Err("an open for user mode was resolved from a kernel handle as its root");
    }
    if opens[0] != (Err(STATUS_INVALID_HANDLE), 0) {
        return Err("an open for user mode from a kernel handle was not an invalid handle");
    }
    if opens[1..]
        .iter()
        .any(|open| *open != (Ok(STATUS_SUCCESS), 1))
    {
        return Err("an open relative to a handle its requestor may use was refused");
    }
    Ok(opens.len() as u32)
}

/// The handle the opens of [`closed_at_once`] are given, for the thread
/// that closes it under them; whether that thread is to go on; and how
/// often it got there first.
static GUESSED: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);
static GUESSING: AtomicU32 = AtomicU32::new(0);
static GUESSED_RIGHT: AtomicU32 = AtomicU32::new(0);

/// Close the handle the next open will be given, again and again.
fn close_guessed(_: usize) {
    let alone = crate::ke::smp::online_count() == 1;
    while GUESSING.load(Ordering::Acquire) == 1 {
        if file::close(GUESSED.load(Ordering::Acquire)) == STATUS_SUCCESS {
            GUESSED_RIGHT.fetch_add(1, Ordering::AcqRel);
        }
        if alone {
            thread::yield_now();
        }
    }
}

/// A handle's number can be guessed, so a handle can be closed by
/// another thread the instant it exists, while the open that made it
/// is still returning. Whoever closes it, the driver is sent one
/// cleanup and one close for each file it opened. Returns the opens
/// made.
fn closed_at_once() -> Result<u32, &'static str> {
    const ROUNDS: u32 = 2000;
    let wait = |ready: &dyn Fn() -> bool| {
        let deadline = time::interrupt_time() + 100_000_000;
        while !ready() && time::interrupt_time() < deadline {
            thread::yield_now();
        }
        ready()
    };
    let sent = || {
        (
            CLEANUPS.load(Ordering::Acquire),
            CLOSES.load(Ordering::Acquire),
        )
    };
    CLEANUPS.store(0, Ordering::Release);
    CLOSES.store(0, Ordering::Release);
    // Every open is given the lowest free number: the same each time.
    let (handle, _) =
        file::open(&OpenRequest::new(DEVICE)).map_err(|_| "the device did not open")?;
    file::close(handle);
    if sent() != (1, 1) {
        return Err("a file opened and closed was not cleaned up and closed once");
    }
    GUESSED.store(handle, Ordering::Release);
    GUESSED_RIGHT.store(0, Ordering::Release);
    GUESSING.store(1, Ordering::Release);
    let threads = thread::count();
    thread::create(close_guessed, 0, thread::NORMAL_PRIORITY, thread::ANYWHERE)?;
    let mut verdict = Ok(ROUNDS);
    for round in 1..=ROUNDS {
        match file::open(&OpenRequest::new(DEVICE)) {
            // Closed here, unless the other thread was first.
            Ok((handle, _)) => drop(file::close(handle)),
            Err(_) => {
                verdict = Err("the device did not open");
                break;
            }
        }
        // The close request is the last a file's driver hears of it.
        if !wait(&|| sent().1 == round + 1) {
            verdict = Err("a file whose handle was closed was never closed for its driver");
            break;
        }
        if sent().0 != round + 1 {
            verdict = Err("a file whose handle was closed under its open was cleaned up twice");
            break;
        }
    }
    GUESSING.store(0, Ordering::Release);
    thread::settle(threads);
    kprintln!(
        "io: handles closed by the thread that guessed them: {}",
        GUESSED_RIGHT.load(Ordering::Acquire)
    );
    verdict
}

/// A dispatch routine that returns success for a create request it has
/// not completed breaks the driver's contract, and the driver may still
/// hold the IRP, which points at the opener's stack. The system stops,
/// naming the routine.
pub static CREATE_NOT_COMPLETED: Group = Group {
    names: &["neg.create-not-completed"],
    run: create_not_completed,
    manual: true,
};

fn create_not_completed(r: &mut Report, _: &BootInfo) {
    kprintln!("NK-NEG-ARMED neg.create-not-completed");
    let opened = with_driver(|| {
        Ok(
            file::open(&OpenRequest::new("\\Device\\NkRequestor\\abandoned!"))
                .map_or_else(|s| s as u32, |_| 0),
        )
    });
    r.fail(
        "neg.create-not-completed",
        format_args!(
            "a driver returned success for a create it had not completed, and the open came back: {opened:x?}"
        ),
    );
}

fn run(r: &mut Report, _: &BootInfo) {
    let mut counted = |name, result: Result<u32, &'static str>| match result {
        Ok(n) => r.ok_with(name, format_args!("requests: {n}")),
        Err(why) => r.fail(name, format_args!("{why}")),
    };
    counted("io.user.access", with_driver(access));
    counted("io.user.firmware-buffer", with_driver(firmware_buffer));
    counted("io.user.copy-out-fault", with_driver(copy_out_fault));
    counted("io.open.pended", with_driver(pended_open));
    counted("io.open.user-root", with_driver(user_root));
    counted("io.open.closed-at-once", with_driver(closed_at_once));
}

/// This file's test groups, in the order they run.
pub static GROUPS: &[&Group] = &[&GROUP, &CREATE_NOT_COMPLETED];
