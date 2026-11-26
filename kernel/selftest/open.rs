//! Tests of opening and closing: what a driver is handed when a name
//! below its device is opened, and when it hears that the file is done
//! with.
//!
//! The driver is here, in Rust, written the way a WDM driver in C is,
//! because what is under test is the I/O manager's side: it records
//! each create request as it finds it and counts the cleanup and close
//! requests. Microsoft's `npfs.sys` and `msfs.sys` are the drivers
//! these requests are shaped for; nothing here loads them.

use crate::io::file::{self, IoError, IoResult, Kind, OpenRequest};
use crate::io::{device, irp};
use crate::ke::{irql, thread, time, wait};
use crate::mm::pool;
use crate::ob::{self, handle, object};
use crate::test::{Group, Report, Slot};
use alloc::string::String;
use alloc::vec::Vec;
use core::ffi::c_void;
use core::sync::atomic::{AtomicPtr, AtomicU32, AtomicUsize, Ordering};
use nk_bootinfo::BootInfo;
use nk_ntabi::io::*;
use nk_ntabi::status::*;

pub static GROUP: Group = Group {
    names: &[
        "io.open.remainder",
        "io.open.relative",
        "io.open.relative-lifetime",
        "io.open.create-request",
        "io.open.named-pipe",
        "io.open.mailslot",
        "io.fs-control",
        "io.close.cleanup-then-close",
        "io.close.deferred",
    ],
    run,
    manual: false,
};

const DEVICE: &str = "\\Device\\NkOpen";
const LINK: &str = "\\??\\NkOpen";
const STATUS_ACCESS_DENIED: NTSTATUS = 0xC000_0022u32 as NTSTATUS;
/// What the driver reports as the result of a create: a marker for a
/// file, `FILE_CREATED` for a pipe or a mailslot.
const OPENED: usize = 0x5A;
const CREATED: usize = 2;
/// What the name of a file the driver refuses to open ends with.
const REFUSED: &str = "refuse";

/// A create request as the driver found it.
#[derive(Clone, Copy)]
struct Seen {
    major: u8,
    minor: u8,
    file: *mut FILE_OBJECT,
    related: *mut FILE_OBJECT,
    /// What the related file object says it is (`Type`), read while
    /// the create is being processed; zero without one.
    related_type: i16,
    device: *mut DEVICE_OBJECT,
    /// `FileObject->FileName`: its characters (as many as fit), its
    /// length and room in bytes, and whether it has a buffer.
    name: [u16; 40],
    name_bytes: u16,
    name_room: u16,
    name_buffer: bool,
    file_flags: u32,
    parameters: [u64; 4],
    irp_flags: u32,
    requestor_mode: i8,
    /// The `IO_SECURITY_CONTEXT`: desired access, full create options,
    /// and whether it has a quality of service.
    desired: u32,
    full_options: u32,
    qos: bool,
    /// The `ACCESS_STATE`: original, remaining and granted access, its
    /// flags, and the subject's primary token.
    original: u32,
    remaining: u32,
    granted: u32,
    state_flags: u32,
    token: *mut c_void,
    /// The named pipe's parameters, for a pipe.
    pipe: Option<NAMED_PIPE_CREATE_PARAMETERS>,
    /// The mailslot's parameters, for a mailslot.
    mailslot: Option<MAILSLOT_CREATE_PARAMETERS>,
}

/// The last create request. Requests are made by the test's own thread,
/// one at a time, and the driver runs in that thread.
static SEEN: Slot<Seen> = Slot::new();
static CREATES: AtomicU32 = AtomicU32::new(0);
/// Cleanup and close requests seen, the file object of the last of
/// each, and when each last came in the sequence of both.
static CLEANUPS: AtomicU32 = AtomicU32::new(0);
static CLOSES: AtomicU32 = AtomicU32::new(0);
static CLEANED: AtomicPtr<FILE_OBJECT> = AtomicPtr::new(core::ptr::null_mut());
static CLOSED: AtomicPtr<FILE_OBJECT> = AtomicPtr::new(core::ptr::null_mut());
static STEP: AtomicU32 = AtomicU32::new(0);
static CLEANUP_AT: AtomicU32 = AtomicU32::new(0);
static CLOSE_AT: AtomicU32 = AtomicU32::new(0);
/// The IRQL the last close request arrived at, and the thread it
/// arrived in.
static CLOSE_IRQL: AtomicU32 = AtomicU32::new(0);
static CLOSE_THREAD: AtomicUsize = AtomicUsize::new(0);
/// The last control request: its major and minor function and its
/// parameters.
static CONTROL: Slot<(u8, u8, [u64; 4])> = Slot::new();

/// # Safety
/// Called as a dispatch routine for a create request.
unsafe extern "C" fn create(device: *mut DEVICE_OBJECT, irp: *mut IRP) -> NTSTATUS {
    // SAFETY: a live create IRP being dispatched: its stack location,
    // file object, security context and access state are the I/O
    // manager's and stay until the request completes.
    unsafe {
        let location = (*irp).CurrentStackLocation;
        let file = (*location).FileObject;
        let context = (*location).Parameters[0] as *const IO_SECURITY_CONTEXT;
        let state = (*context).AccessState;
        let name = (*file).FileName;
        let mut text = [0u16; 40];
        let characters = (usize::from(name.Length) / 2).min(text.len());
        for (i, slot) in text.iter_mut().enumerate().take(characters) {
            *slot = name.Buffer.add(i).read();
        }
        let major = (*location).MajorFunction;
        let related = (*file).RelatedFileObject;
        let related_type = if related.is_null() {
            0
        } else {
            (*related).Type
        };
        let pipe = (major == IRP_MJ_CREATE_NAMED_PIPE)
            .then(|| ((*location).Parameters[3] as *const NAMED_PIPE_CREATE_PARAMETERS).read());
        let mailslot = (major == IRP_MJ_CREATE_MAILSLOT)
            .then(|| ((*location).Parameters[3] as *const MAILSLOT_CREATE_PARAMETERS).read());
        SEEN.ptr().write(Seen {
            major,
            minor: (*location).MinorFunction,
            file,
            related,
            related_type,
            device,
            name: text,
            name_bytes: name.Length,
            name_room: name.MaximumLength,
            name_buffer: !name.Buffer.is_null(),
            file_flags: (*file).Flags,
            parameters: (*location).Parameters,
            irp_flags: (*irp).Flags,
            requestor_mode: (*irp).RequestorMode,
            desired: (*context).DesiredAccess,
            full_options: (*context).FullCreateOptions,
            qos: !(*context).SecurityQos.is_null(),
            original: (*state).OriginalDesiredAccess,
            remaining: (*state).RemainingDesiredAccess,
            granted: (*state).PreviouslyGrantedAccess,
            state_flags: (*state).Flags,
            token: (*state).SubjectSecurityContext.PrimaryToken,
            pipe,
            mailslot,
        });
        CREATES.fetch_add(1, Ordering::AcqRel);
        let refused: Vec<u16> = REFUSED.encode_utf16().collect();
        let status = if text[..characters].ends_with(&refused) {
            STATUS_ACCESS_DENIED
        } else {
            STATUS_SUCCESS
        };
        (*irp).IoStatus.Status = status;
        (*irp).IoStatus.Information = match status {
            STATUS_SUCCESS if major == IRP_MJ_CREATE => OPENED,
            STATUS_SUCCESS => CREATED,
            _ => 0,
        };
        irp::IofCompleteRequest(irp, 0);
        status
    }
}

/// # Safety
/// Called as a dispatch routine for a cleanup or a close request.
unsafe extern "C" fn cleanup_or_close(_: *mut DEVICE_OBJECT, irp: *mut IRP) -> NTSTATUS {
    // SAFETY: a live IRP being dispatched.
    unsafe {
        let location = (*irp).CurrentStackLocation;
        let file = (*location).FileObject;
        let step = STEP.fetch_add(1, Ordering::AcqRel) + 1;
        if (*location).MajorFunction == IRP_MJ_CLEANUP {
            CLEANUPS.fetch_add(1, Ordering::AcqRel);
            CLEANED.store(file, Ordering::Release);
            CLEANUP_AT.store(step, Ordering::Release);
        } else {
            CLOSE_IRQL.store(u32::from(irql::current()), Ordering::Release);
            CLOSE_THREAD.store(thread::current().addr(), Ordering::Release);
            CLOSES.fetch_add(1, Ordering::AcqRel);
            CLOSED.store(file, Ordering::Release);
            CLOSE_AT.store(step, Ordering::Release);
        }
        (*irp).IoStatus.Status = STATUS_SUCCESS;
        (*irp).IoStatus.Information = 0;
        irp::IofCompleteRequest(irp, 0);
    }
    STATUS_SUCCESS
}

/// A buffered control request: the input comes back reversed.
///
/// # Safety
/// Called as a dispatch routine for a control request.
unsafe extern "C" fn control(_: *mut DEVICE_OBJECT, irp: *mut IRP) -> NTSTATUS {
    // SAFETY: a live IRP being dispatched; a buffered request's system
    // buffer holds the larger of input and output.
    unsafe {
        let location = (*irp).CurrentStackLocation;
        let parameters = (*location).Parameters;
        CONTROL.ptr().write((
            (*location).MajorFunction,
            (*location).MinorFunction,
            parameters,
        ));
        let n = (parameters[0] as usize).min(parameters[1] as usize);
        let buffer = (*irp).SystemBuffer.cast::<u8>();
        if n != 0 {
            core::slice::from_raw_parts_mut(buffer, n).reverse();
        }
        (*irp).IoStatus.Status = STATUS_SUCCESS;
        (*irp).IoStatus.Information = n;
        irp::IofCompleteRequest(irp, 0);
    }
    STATUS_SUCCESS
}

/// Make the driver, its device and a symbolic link to it, run `test`
/// with the device, and take everything down again.
fn with_driver(
    test: impl FnOnce(*mut DEVICE_OBJECT) -> Result<u32, &'static str>,
) -> Result<u32, &'static str> {
    let size = size_of::<DRIVER_OBJECT>() + size_of::<DRIVER_EXTENSION>();
    let driver = pool::alloc_zeroed(size, u32::from_le_bytes(*b"Test")).cast::<DRIVER_OBJECT>();
    if driver.is_null() {
        return Err("no memory for a driver object");
    }
    let wide = |text: &str| text.encode_utf16().collect::<Vec<u16>>();
    let mut name = wide(DEVICE);
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
        for major in [
            IRP_MJ_CREATE,
            IRP_MJ_CREATE_NAMED_PIPE,
            IRP_MJ_CREATE_MAILSLOT,
        ] {
            (*driver).MajorFunction[usize::from(major)] = Some(create);
        }
        for major in [IRP_MJ_CLEANUP, IRP_MJ_CLOSE] {
            (*driver).MajorFunction[usize::from(major)] = Some(cleanup_or_close);
        }
        for major in [IRP_MJ_DEVICE_CONTROL, IRP_MJ_FILE_SYSTEM_CONTROL] {
            (*driver).MajorFunction[usize::from(major)] = Some(control);
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
        let result = if ob::insert_link(&wide(LINK), &wide(DEVICE)) == STATUS_SUCCESS {
            let result = test(device_object);
            ob::remove_link(&wide(LINK));
            result
        } else {
            Err("could not make a symbolic link to the test device")
        };
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

/// The last create request the driver saw.
fn last() -> Seen {
    // SAFETY: written by the driver in this thread, before the request
    // that carried it returned.
    unsafe { SEEN.ptr().read() }
}

/// The name of the file object in the last create request.
fn seen_name() -> String {
    let seen = last();
    String::from_utf16_lossy(&seen.name[..usize::from(seen.name_bytes) / 2])
}

fn open(name: &str) -> Result<u64, NTSTATUS> {
    super::open(name)
}

fn open_from(name: &str, root: u64) -> Result<u64, NTSTATUS> {
    let request = OpenRequest {
        root: Some(root),
        ..OpenRequest::new(name)
    };
    file::open(&request).map(|(handle, _)| handle)
}

/// A path that goes on below a device reaches the device's driver as
/// the name of the file object, backslash first, whatever led to the
/// device. Returns the opens made.
fn remainder(device: *mut DEVICE_OBJECT) -> Result<u32, &'static str> {
    let leads = [
        ("\\Device\\NkOpen", ""),
        ("\\Device\\NkOpen\\", "\\"),
        ("\\Device\\NkOpen\\dir\\leaf.txt", "\\dir\\leaf.txt"),
        ("\\device\\NKOPEN\\Mixed Case", "\\Mixed Case"),
        ("\\??\\NkOpen", ""),
        ("\\??\\NkOpen\\via\\link", "\\via\\link"),
        ("\\DosDevices\\nkopen\\X", "\\X"),
        ("\\GLOBAL??\\NkOpen\\\\odd\\", "\\\\odd\\"),
    ];
    for (path, rest) in leads {
        let creates = CREATES.load(Ordering::Acquire);
        let handle = open(path).map_err(|_| "a path to the device, or below it, did not open")?;
        let seen = last();
        let closed = file::close(handle);
        if CREATES.load(Ordering::Acquire) != creates + 1 || seen.major != IRP_MJ_CREATE {
            return Err("an open did not send the driver one create request");
        }
        if seen_name() != rest {
            return Err("the driver was not handed the rest of the path as the file's name");
        }
        // No name, no buffer; a name has room for a terminator.
        let shaped = if rest.is_empty() {
            !seen.name_buffer && seen.name_room == 0
        } else {
            seen.name_buffer && seen.name_room == seen.name_bytes + 2
        };
        if !shaped {
            return Err("the file's name is not a counted string of the I/O manager's");
        }
        if seen.device != device || !seen.related.is_null() {
            return Err("an absolute open named the wrong device, or a related file");
        }
        if closed != STATUS_SUCCESS {
            return Err("closing the handle failed");
        }
    }
    let creates = CREATES.load(Ordering::Acquire);
    let nowhere = [
        ("\\Device\\NkNone", STATUS_OBJECT_NAME_NOT_FOUND),
        ("\\Device\\NkNone\\x", STATUS_OBJECT_PATH_NOT_FOUND),
        ("\\Device", STATUS_OBJECT_TYPE_MISMATCH),
        ("\\", STATUS_OBJECT_TYPE_MISMATCH),
        ("Device\\NkOpen", STATUS_OBJECT_PATH_SYNTAX_BAD),
    ];
    for (path, expected) in nowhere {
        if open(path) != Err(expected) {
            return Err("a path that leads to no device did not fail with its own status");
        }
    }
    if CREATES.load(Ordering::Acquire) != creates {
        return Err("the driver was asked to open what is not below its device");
    }
    Ok((leads.len() + nowhere.len()) as u32)
}

/// A name relative to an open file goes to that file's device with the
/// file as the related file object; a name relative to a directory is
/// looked up from there. Returns the opens made.
fn relative(device: *mut DEVICE_OBJECT) -> Result<u32, &'static str> {
    let root = open("\\Device\\NkOpen\\dir").map_err(|_| "the root did not open")?;
    let root_file = last().file;
    let verdict = (|| {
        let creates = CREATES.load(Ordering::Acquire);
        let leaf = open_from("leaf\\name", root).map_err(|_| "a relative open failed")?;
        let seen = last();
        file::close(leaf);
        if seen.related != root_file || seen.file == root_file || seen.device != device {
            return Err("a relative open did not name the root's file object and device");
        }
        if seen_name() != "leaf\\name" {
            return Err("a relative open's name is not the name as given");
        }
        // No name at all: the root's device, the root as the related
        // file, and nothing for the driver to parse.
        let again = open_from("", root).map_err(|_| "an empty relative name did not open")?;
        let seen = last();
        file::close(again);
        if seen.related != root_file || seen.name_bytes != 0 || seen.name_buffer {
            return Err("an empty name relative to a file did not reach the driver as one");
        }
        if CREATES.load(Ordering::Acquire) != creates + 2 {
            return Err("relative opens did not send one create request each");
        }
        if open_from("\\Device\\NkOpen", root) != Err(STATUS_OBJECT_PATH_SYNTAX_BAD)
            || CREATES.load(Ordering::Acquire) != creates + 2
        {
            return Err("an absolute name was accepted relative to a file");
        }
        Ok(())
    })();
    file::close(root);
    verdict?;

    // A directory as the root.
    let path: Vec<u16> = "\\Device".encode_utf16().collect();
    let (directory, _) = ob::lookup(None, &path).map_err(|_| "no \\Device")?;
    // SAFETY: the look-up's reference, handed to the handle and then
    // given up; a thread is an object too.
    let (directory, thread) = unsafe {
        let handles = (
            handle::open(directory, 0).unwrap_or(0),
            handle::open(crate::ke::thread::current().cast(), 0).unwrap_or(0),
        );
        object::dereference(directory);
        handles
    };
    let verdict = (|| {
        let below = open_from("NkOpen\\below", directory)
            .map_err(|_| "an open relative to a directory failed")?;
        let seen = last();
        file::close(below);
        if seen_name() != "\\below" || !seen.related.is_null() || seen.device != device {
            return Err("an open relative to a directory did not reach the device as any other");
        }
        let refused = [
            (
                open_from("\\Device\\NkOpen", directory),
                STATUS_OBJECT_PATH_SYNTAX_BAD,
            ),
            (open_from("NkNone", directory), STATUS_OBJECT_NAME_NOT_FOUND),
            (open_from("", directory), STATUS_OBJECT_TYPE_MISMATCH),
            (open_from("x", thread), STATUS_INVALID_HANDLE),
            (open_from("x", directory + 4096), STATUS_INVALID_HANDLE),
        ];
        if refused.iter().any(|(got, expected)| *got != Err(*expected)) {
            return Err("a relative open that cannot be was not refused with its own status");
        }
        Ok(())
    })();
    handle::close(directory);
    handle::close(thread);
    verdict?;
    Ok(10)
}

/// The related file object is the driver's to read while it processes
/// the create, and no longer
/// ([`FILE_OBJECT`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/ns-wdm-_file_object):
/// "only valid during the processing of the IRP_MJ_CREATE requests"):
/// the root may be closed for good the moment the open returns, and the
/// new file object must not go on pointing at it. Returns the opens
/// made.
fn relative_lifetime(_: *mut DEVICE_OBJECT) -> Result<u32, &'static str> {
    let closes = CLOSES.load(Ordering::Acquire);
    let root = open("\\Device\\NkOpen\\dir").map_err(|_| "the root did not open")?;
    let root_file = last().file;
    let Ok(leaf) = open_from("leaf", root) else {
        file::close(root);
        return Err("a relative open failed");
    };
    let seen = last();
    // The root goes at once: its last handle and its last reference.
    let gone = file::close(root) == STATUS_SUCCESS
        && CLOSES.load(Ordering::Acquire) == closes + 1
        && CLOSED.load(Ordering::Acquire) == root_file;
    // SAFETY: the relative file is open: its object is there to read.
    let kept = unsafe { (*seen.file).RelatedFileObject };
    let mut output = [0u8; 4];
    let code = ctl_code(0x22, 0x800, METHOD_BUFFERED, 0);
    let served = file::device_control(leaf, code, b"ab", &mut output);
    let closed = file::close(leaf);
    if seen.related != root_file || seen.related_type != IO_TYPE_FILE {
        return Err("the driver did not find a live related file object during the create");
    }
    if !gone {
        return Err("the root was not closed for good while a file opened relative to it lived");
    }
    if !kept.is_null() {
        return Err("a file object goes on pointing at a related file object that has gone");
    }
    if served.map(|r| (r.status, r.information)) != Ok((STATUS_SUCCESS, 2))
        || closed != STATUS_SUCCESS
        || CLOSES.load(Ordering::Acquire) != closes + 2
    {
        return Err("a file opened relative to a root that has gone did not work and close");
    }

    // A create the driver refuses: the root is there for the driver to
    // read all the same, and is the only file closed afterwards.
    let root = open("\\Device\\NkOpen\\dir").map_err(|_| "the root did not open")?;
    let root_file = last().file;
    let refused = open_from("refuse", root);
    let seen = last();
    let closed = file::close(root);
    if refused != Err(STATUS_ACCESS_DENIED) {
        return Err("a refused relative create did not fail with the driver's status");
    }
    if seen.related != root_file || seen.related_type != IO_TYPE_FILE {
        return Err("the driver did not find a live related file object in a create it refused");
    }
    if closed != STATUS_SUCCESS
        || CLOSES.load(Ordering::Acquire) != closes + 3
        || CLOSED.load(Ordering::Acquire) != root_file
    {
        return Err("after a refused relative create the root did not close, alone");
    }
    Ok(4)
}

/// What a create request carries: the options, the share access, the
/// security context and access state, the requestor's mode; and what
/// the open gives back.
fn create_request(_: *mut DEVICE_OBJECT) -> Result<u32, &'static str> {
    // GENERIC_READ | SYNCHRONIZE | DELETE: one generic right, two
    // specific ones.
    const ASKED: u32 = 0x8011_0000;
    // FILE_GENERIC_READ and the two.
    const MAPPED: u32 = 0x0012_0089 | 0x0011_0000;
    let request = OpenRequest {
        desired_access: ASKED,
        share_access: 3,
        create_options: FILE_SYNCHRONOUS_IO_NONALERT | FILE_NON_DIRECTORY_FILE,
        // FILE_OPEN_IF
        disposition: 3,
        ..OpenRequest::new("\\Device\\NkOpen\\file")
    };
    let (handle, information) = file::open(&request).map_err(|_| "the open failed")?;
    let seen = last();
    // SAFETY: the file is open: its object is there to be read.
    let flags_after = unsafe { (*seen.file).Flags };
    file::close(handle);
    if information != OPENED {
        return Err("the open did not return what the driver reported for the create");
    }
    if seen.major != IRP_MJ_CREATE || seen.minor != 0 {
        return Err("a file was not opened with IRP_MJ_CREATE");
    }
    let context = seen.parameters[0];
    if context == 0 || seen.parameters[1..] != [0x0300_0060, 3 << 16, 0] {
        return Err("the create parameters are not the options, share access and no EA");
    }
    if (seen.desired, seen.full_options, seen.qos) != (MAPPED, 0x60, false) {
        return Err("the security context does not hold the mapped access and the options");
    }
    if (seen.original, seen.remaining, seen.granted) != (MAPPED, MAPPED, 0) {
        return Err("the access state does not hold the access asked for, nothing granted yet");
    }
    let token = crate::ps::process::reference_primary_token();
    // SAFETY: the reference just taken.
    unsafe { object::dereference(token) };
    if seen.token != token.cast() || seen.state_flags != nk_ntabi::se::TOKEN_HAS_TRAVERSE_PRIVILEGE
    {
        return Err("the access state's subject is not the System process");
    }
    if seen.requestor_mode != KERNEL_MODE
        || seen.irp_flags != IRP_CREATE_OPERATION | IRP_SYNCHRONOUS_API | IRP_DEFER_IO_COMPLETION
    {
        return Err("the create IRP does not say who asks, or that it is a create");
    }
    if seen.file_flags != FO_SYNCHRONOUS_IO || flags_after != FO_SYNCHRONOUS_IO | FO_HANDLE_CREATED
    {
        return Err("the file object's flags do not follow the options and the handle");
    }

    // On behalf of user mode, and without the synchronous options.
    let request = OpenRequest {
        create_options: FILE_NON_DIRECTORY_FILE,
        requestor_mode: USER_MODE,
        ..OpenRequest::new("\\Device\\NkOpen\\file")
    };
    let (handle, _) = file::open(&request).map_err(|_| "the open failed")?;
    let seen = last();
    file::close(handle);
    if seen.requestor_mode != USER_MODE || seen.file_flags != 0 {
        return Err("the requestor's mode or the options did not reach the driver");
    }
    if (seen.desired, seen.parameters[1], seen.parameters[2]) != (0x0012_019F, 0x0100_0040, 0) {
        return Err("the default access, disposition and share access did not reach the driver");
    }

    // A create the driver refuses: its status is the open's, and the
    // driver hears no more of the file.
    let before = (
        CLEANUPS.load(Ordering::Acquire),
        CLOSES.load(Ordering::Acquire),
    );
    if open("\\Device\\NkOpen\\refuse") != Err(STATUS_ACCESS_DENIED) {
        return Err("a refused create did not fail the open with the driver's status");
    }
    let after = (
        CLEANUPS.load(Ordering::Acquire),
        CLOSES.load(Ordering::Acquire),
    );
    if after != before {
        return Err("a file that was never opened was cleaned up or closed");
    }
    Ok(3)
}

/// A named pipe is created with its own request, which carries the
/// pipe's parameters.
fn named_pipe(_: *mut DEVICE_OBJECT) -> Result<u32, &'static str> {
    let parameters = NAMED_PIPE_CREATE_PARAMETERS {
        NamedPipeType: 1,
        ReadMode: 1,
        CompletionMode: 0,
        MaximumInstances: 7,
        InboundQuota: 4096,
        OutboundQuota: 8192,
        DefaultTimeout: -500_000,
        TimeoutSpecified: 1,
    };
    let request = OpenRequest {
        share_access: 3,
        create_options: FILE_SYNCHRONOUS_IO_NONALERT,
        // FILE_CREATE
        disposition: 2,
        kind: Kind::NamedPipe(parameters),
        ..OpenRequest::new("\\Device\\NkOpen\\pipe-name")
    };
    let (handle, information) = file::open(&request).map_err(|_| "the pipe was not created")?;
    let seen = last();
    file::close(handle);
    if seen.major != IRP_MJ_CREATE_NAMED_PIPE || seen_name() != "\\pipe-name" {
        return Err("a pipe was not created with IRP_MJ_CREATE_NAMED_PIPE and its name");
    }
    if information != CREATED {
        return Err("creating a pipe did not return what the driver reported");
    }
    if seen.parameters[1..3] != [0x0200_0020, 3 << 16] || seen.parameters[3] == 0 {
        return Err("the pipe's create parameters are not the options and share access");
    }
    let Some(got) = seen.pipe else {
        return Err("the driver found no pipe parameters");
    };
    let fields = |p: &NAMED_PIPE_CREATE_PARAMETERS| {
        (
            (p.NamedPipeType, p.ReadMode, p.CompletionMode),
            (p.MaximumInstances, p.InboundQuota, p.OutboundQuota),
            (p.DefaultTimeout, p.TimeoutSpecified),
        )
    };
    if fields(&got) != fields(&parameters) {
        return Err("the pipe's parameters did not reach the driver as given");
    }
    if (seen.desired, seen.remaining) != (0x0012_019F, 0x0012_019F) {
        return Err("a pipe's create request does not carry the access asked for");
    }
    Ok(1)
}

/// A mailslot is created with its own request, which carries the
/// mailslot's parameters.
fn mailslot(_: *mut DEVICE_OBJECT) -> Result<u32, &'static str> {
    let parameters = MAILSLOT_CREATE_PARAMETERS {
        MailslotQuota: 4096,
        MaximumMessageSize: 400,
        ReadTimeout: -2_500_000,
        TimeoutSpecified: 1,
    };
    // As `NtCreateMailslotFile` asks: shared for reading and writing,
    // and only if the name is free (`FILE_CREATE`).
    let request = OpenRequest {
        // GENERIC_READ | SYNCHRONIZE
        desired_access: 0x8010_0000,
        share_access: 3,
        create_options: FILE_SYNCHRONOUS_IO_NONALERT,
        disposition: 2,
        kind: Kind::Mailslot(parameters),
        ..OpenRequest::new("\\Device\\NkOpen\\slot-name")
    };
    let (handle, information) = file::open(&request).map_err(|_| "the mailslot was not created")?;
    let seen = last();
    file::close(handle);
    if seen.major != IRP_MJ_CREATE_MAILSLOT || seen_name() != "\\slot-name" {
        return Err("a mailslot was not created with IRP_MJ_CREATE_MAILSLOT and its name");
    }
    if information != CREATED {
        return Err("creating a mailslot did not return what the driver reported");
    }
    if seen.parameters[1..3] != [0x0200_0020, 3 << 16] || seen.parameters[3] == 0 {
        return Err("the mailslot's create parameters are not the options and share access");
    }
    let Some(got) = seen.mailslot else {
        return Err("the driver found no mailslot parameters");
    };
    let fields = |p: &MAILSLOT_CREATE_PARAMETERS| {
        (
            (p.MailslotQuota, p.MaximumMessageSize),
            (p.ReadTimeout, p.TimeoutSpecified),
        )
    };
    if fields(&got) != fields(&parameters) {
        return Err("the mailslot's parameters did not reach the driver as given");
    }
    if (seen.desired, seen.remaining) != (0x0012_0089, 0x0012_0089) {
        return Err("a mailslot's create request does not carry the access asked for");
    }
    // An option that means nothing for a mailslot is refused before the
    // name is looked at: no driver hears of it.
    let before = CREATES.load(Ordering::Acquire);
    let refused = file::open(&OpenRequest {
        create_options: FILE_SYNCHRONOUS_IO_NONALERT | FILE_NON_DIRECTORY_FILE,
        ..request
    });
    if refused != Err(STATUS_INVALID_PARAMETER) || CREATES.load(Ordering::Acquire) != before {
        return Err("a mailslot was created with an option that is not a mailslot's");
    }
    Ok(1)
}

/// Either kind of control request, as the requestor sends it.
type Control = fn(u64, u32, &[u8], &mut [u8]) -> Result<IoResult, IoError>;

/// A file-system control request reaches the driver as its own kind of
/// request, with its buffers; a handle that names no file reaches no
/// driver.
fn fs_control(_: *mut DEVICE_OBJECT) -> Result<u32, &'static str> {
    // `FSCTL_PIPE_PEEK`'s shape: a file-system device type, buffered.
    let code = ctl_code(0x11, 0x803, METHOD_BUFFERED, 0);
    let opened = open(DEVICE).map_err(|_| "the device did not open")?;
    // SAFETY: a thread is an object; the handle is closed below.
    let thread = unsafe { handle::open(crate::ke::thread::current().cast(), 0) }.unwrap_or(0);
    let verdict = (|| {
        let kinds: [(u8, Control); 2] = [
            (IRP_MJ_FILE_SYSTEM_CONTROL, file::fs_control),
            (IRP_MJ_DEVICE_CONTROL, file::device_control),
        ];
        for (major, send) in kinds {
            let mut output = [0xEEu8; 8];
            let result =
                send(opened, code, b"abc", &mut output).map_err(|_| "a control request failed")?;
            // SAFETY: written by the driver in this thread.
            let (seen_major, seen_minor, parameters) = unsafe { CONTROL.ptr().read() };
            if (seen_major, seen_minor) != (major, 0) || parameters != [8, 3, u64::from(code), 0] {
                return Err("a control request did not reach the driver as its own kind");
            }
            if (result.status, result.information) != (STATUS_SUCCESS, 3)
                || output != *b"cba\xEE\xEE\xEE\xEE\xEE"
            {
                return Err("a control request's output did not come back");
            }
        }
        let mut output = [0u8; 8];
        let refused = [
            (
                file::fs_control(thread, code, b"abc", &mut output),
                STATUS_OBJECT_TYPE_MISMATCH,
            ),
            (
                file::fs_control(opened + 4096, code, b"abc", &mut output),
                STATUS_INVALID_HANDLE,
            ),
            (file::read(thread, &mut output), STATUS_OBJECT_TYPE_MISMATCH),
            (file::write(0, b"abc"), STATUS_INVALID_HANDLE),
        ];
        if refused
            .iter()
            .any(|(got, expected)| *got != Err(IoError::Handle(*expected)))
        {
            return Err("a request through a handle that names no file was not refused");
        }
        Ok(())
    })();
    handle::close(thread);
    file::close(opened);
    verdict?;
    Ok(2)
}

/// The driver hears cleanup when the last handle closes and close when
/// the last reference goes, once each and in that order. Returns the
/// files closed for good.
fn cleanup_then_close(device: *mut DEVICE_OBJECT) -> Result<u32, &'static str> {
    let counts = || {
        (
            CLEANUPS.load(Ordering::Acquire),
            CLOSES.load(Ordering::Acquire),
        )
    };
    let (cleanups, closes) = counts();

    // One handle, no other reference: both at once, cleanup first.
    let only = open("\\Device\\NkOpen\\one").map_err(|_| "the open failed")?;
    let file = last().file;
    // SAFETY: a device this test's driver made; a read of one field.
    if unsafe { (*device).ReferenceCount } != 1 {
        return Err("an open file does not hold its device");
    }
    if file::close(only) != STATUS_SUCCESS || counts() != (cleanups + 1, closes + 1) {
        return Err("closing the only handle did not send one cleanup and one close");
    }
    let in_order = CLEANUP_AT.load(Ordering::Acquire) < CLOSE_AT.load(Ordering::Acquire);
    let same_file =
        CLEANED.load(Ordering::Acquire) == file && CLOSED.load(Ordering::Acquire) == file;
    if !in_order || !same_file {
        return Err("cleanup did not come before close, or not for the file");
    }
    if file::close(only) != STATUS_INVALID_HANDLE || counts() != (cleanups + 1, closes + 1) {
        return Err("a closed handle was closed again");
    }

    // Two handles and a reference that outlives both.
    let first = open("\\Device\\NkOpen\\two").map_err(|_| "the open failed")?;
    let file = last().file;
    let mut second = core::ptr::null_mut();
    // SAFETY: the file is open, so its object is live; the outputs are
    // locals.
    let status = unsafe {
        handle::ObOpenObjectByPointer(
            file.cast(),
            0x200,
            core::ptr::null_mut(),
            0,
            &raw const object::FILE_TYPE,
            KERNEL_MODE,
            &raw mut second,
        )
    };
    if status != STATUS_SUCCESS {
        file::close(first);
        return Err("a second handle to an open file could not be made");
    }
    let second = second as u64;
    if file::close(first) != STATUS_SUCCESS || counts() != (cleanups + 1, closes + 1) {
        file::close(second);
        return Err("the driver heard of a handle closing while another was open");
    }
    // The file still works through the handle that is left.
    let mut output = [0u8; 4];
    let code = ctl_code(0x22, 0x800, METHOD_BUFFERED, 0);
    let through = file::device_control(second, code, b"ab", &mut output);
    let Ok(held) = handle::reference(second, Some(&raw const object::FILE_TYPE)) else {
        file::close(second);
        return Err("an open file's handle did not give its object");
    };
    let closed = file::close(second);
    let after_handles = counts();
    // SAFETY: the reference taken above keeps the object.
    let flags = unsafe { (*file).Flags };
    let cleanup_at = CLEANUP_AT.load(Ordering::Acquire);
    // SAFETY: the reference taken above, given up: the last one.
    unsafe { object::dereference(held) };
    if after_handles.0 != cleanups + 2 {
        return Err("the last handle's closing did not send the driver a cleanup");
    }
    if after_handles.1 != closes + 1 {
        return Err("a close was sent while a reference to the file remained");
    }
    if through.map(|r| (r.status, r.information)) != Ok((STATUS_SUCCESS, 2)) {
        return Err("a file with one handle closed did not serve the other");
    }
    if closed != STATUS_SUCCESS || flags & FO_CLEANUP_COMPLETE == 0 {
        return Err("the last handle's closing was not recorded on the file object");
    }
    if counts() != (cleanups + 2, closes + 2)
        || CLOSE_AT.load(Ordering::Acquire) <= cleanup_at
        || CLOSED.load(Ordering::Acquire) != file
    {
        return Err("the last reference going did not send one close, after the cleanup");
    }
    Ok(2)
}

/// A file whose last reference goes at `DISPATCH_LEVEL` is closed
/// later, by a worker thread at `PASSIVE_LEVEL`, and then freed.
/// Returns the files closed that way.
fn deferred_close(device: *mut DEVICE_OBJECT) -> Result<u32, &'static str> {
    let closes = CLOSES.load(Ordering::Acquire);
    let blocks = pool::usage().blocks;
    let only = open("\\Device\\NkOpen\\late").map_err(|_| "the open failed")?;
    let file = last().file;
    let Ok(held) = handle::reference(only, Some(&raw const object::FILE_TYPE)) else {
        file::close(only);
        return Err("an open file's handle did not give its object");
    };
    let closed = file::close(only);
    let old = irql::raise(irql::DISPATCH_LEVEL);
    // SAFETY: the reference taken above, given up: the last one.
    unsafe { object::dereference(held) };
    irql::lower(old);
    if closed != STATUS_SUCCESS {
        return Err("the handle of a file with a reference left did not close");
    }
    // A worker thread on another processor may have sent the close by
    // now; where and by whom it was sent is what the driver recorded.
    // The close arrives, and after it the file object and the file's
    // hold on its device go.
    let deadline = time::interrupt_time() + 50_000_000;
    // SAFETY: a device this test's driver made; a read of one field.
    let pending = || unsafe { (*device).ReferenceCount } != 0 || pool::usage().blocks != blocks;
    while pending() && time::interrupt_time() < deadline {
        // SAFETY: no object is involved.
        unsafe { wait::wait(None, Some(-10_000)) };
    }
    if CLOSES.load(Ordering::Acquire) != closes + 1 || CLOSED.load(Ordering::Acquire) != file {
        return Err("the close request of a file let go at DISPATCH_LEVEL never arrived");
    }
    if CLOSE_IRQL.load(Ordering::Acquire) != u32::from(irql::PASSIVE_LEVEL)
        || CLOSE_THREAD.load(Ordering::Acquire) == thread::current().addr()
    {
        return Err("the deferred close did not arrive in a worker thread at PASSIVE_LEVEL");
    }
    if pending() {
        return Err("a file closed by a worker thread was not freed");
    }
    Ok(1)
}

fn counted(r: &mut Report, name: &str, what: &str, result: Result<u32, &'static str>) {
    match result {
        Ok(n) => r.ok_with(name, format_args!("{what} {n}")),
        Err(why) => r.fail(name, format_args!("{why}")),
    }
}

fn run(r: &mut Report, _: &BootInfo) {
    counted(r, "io.open.remainder", "opens:", with_driver(remainder));
    counted(r, "io.open.relative", "opens:", with_driver(relative));
    counted(
        r,
        "io.open.relative-lifetime",
        "opens:",
        with_driver(relative_lifetime),
    );
    counted(
        r,
        "io.open.create-request",
        "opens:",
        with_driver(create_request),
    );
    counted(r, "io.open.named-pipe", "pipes:", with_driver(named_pipe));
    counted(r, "io.open.mailslot", "mailslots:", with_driver(mailslot));
    counted(r, "io.fs-control", "kinds:", with_driver(fs_control));
    counted(
        r,
        "io.close.cleanup-then-close",
        "files:",
        with_driver(cleanup_then_close),
    );
    counted(
        r,
        "io.close.deferred",
        "files:",
        with_driver(deferred_close),
    );
}
