//! The requestor side of I/O: open a name, read, write, send control
//! codes, close. This is what the system services `NtCreateFile`,
//! `NtCreateNamedPipeFile`, `NtReadFile`, `NtDeviceIoControlFile`,
//! `NtFsControlFile` and `NtClose` do on Windows; the kernel's
//! self-tests are the only caller so far.
//!
//! An open resolves its name in the object namespace. The look-up stops
//! at a device; what is left of the path is the device's to parse, so
//! it goes to the driver in a create request as the new file object's
//! name. The file object is an object-manager object and the open
//! returns a handle to it. The handle's closing, when it is the last,
//! sends the driver a cleanup request; the last reference's going
//! sends the close request and lets go of the device.
//!
//! Each request is a real IRP sent to the driver's dispatch routine.
//! Buffers are passed the way the device or control code asks for:
//! buffered, direct, or neither. A request the driver pends is waited
//! for; it may also be started, cancelled, and waited for later
//! ([`Pending`]).
//!
//! The requestor owns the IRP: completion hands back the results and
//! signals, and the requestor frees the IRP once it has seen that. So a
//! request can be cancelled at any time before its requestor lets go,
//! completed or not.

use super::{TAG_FILE_NAME, TAG_IO_BUFFER, device, irp, mdl};
use crate::ke::seh::Guard;
use crate::mm::{pool, user};
use crate::ob::{handle, object};
use crate::{ke, ob, se};
use alloc::boxed::Box;
use alloc::vec::Vec;
use core::ffi::c_void;
use nk_ntabi::io::*;
use nk_ntabi::se::ACCESS_STATE;
use nk_ntabi::status::*;
use nk_ob::handles::Mode;

/// What a request came back with.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IoResult {
    pub status: NTSTATUS,
    pub information: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IoError {
    NoMemory,
    /// The handle does not name an open file, or (for user mode) was
    /// not granted the access the request needs: the status says which.
    Handle(NTSTATUS),
    /// The driver returned something other than `STATUS_PENDING` without
    /// having completed the request, which the driver contract forbids.
    NotCompleted {
        dispatch_status: NTSTATUS,
    },
    /// The dispatch routine returned a different status than it completed
    /// the request with, which the driver contract forbids.
    StatusMismatch {
        dispatch_status: NTSTATUS,
        completed: NTSTATUS,
    },
    /// The device asks for a buffer method not implemented yet.
    UnsupportedMethod,
    /// The I/O manager cannot use a buffer of the request: no driver
    /// saw it, and it fails with this status.
    Refused(NTSTATUS),
}

/// `LOCK_OPERATION` values for `MmProbeAndLockPages`.
const IO_READ_ACCESS: u32 = 0;
const IO_WRITE_ACCESS: u32 = 1;

/// What is opened.
#[derive(Clone, Copy)]
pub enum Kind {
    /// A file or device (`NtCreateFile`): `IRP_MJ_CREATE`.
    File,
    /// An instance of a named pipe (`NtCreateNamedPipeFile`):
    /// `IRP_MJ_CREATE_NAMED_PIPE`, with these parameters.
    NamedPipe(NAMED_PIPE_CREATE_PARAMETERS),
}

/// An open, as the system services take it.
pub struct OpenRequest<'a> {
    /// A path in the object namespace; relative to `root` if there is
    /// one.
    pub name: &'a str,
    /// A handle to a directory object or to an open file
    /// (`OBJECT_ATTRIBUTES.RootDirectory`).
    pub root: Option<u64>,
    pub desired_access: u32,
    pub share_access: u32,
    pub create_options: u32,
    pub disposition: u32,
    pub kind: Kind,
    /// `KERNEL_MODE` or `USER_MODE`: on whose behalf the request is
    /// made (`Irp->RequestorMode`).
    pub requestor_mode: i8,
}

impl<'a> OpenRequest<'a> {
    /// Open what `name` leads to, as the oracle's runner does on
    /// Windows for a plain `open` step: for reading and writing,
    /// synchronously, shared with nobody, and only if it exists.
    pub const fn new(name: &'a str) -> Self {
        Self {
            name,
            root: None,
            // GENERIC_READ | GENERIC_WRITE | SYNCHRONIZE
            desired_access: 0xC010_0000,
            share_access: 0,
            create_options: FILE_SYNCHRONOUS_IO_NONALERT | FILE_NON_DIRECTORY_FILE,
            disposition: FILE_OPEN,
            kind: Kind::File,
            requestor_mode: KERNEL_MODE,
        }
    }
}

/// What the requestor keeps while its request is on its way: where the
/// results go, and what is signalled when they are there.
struct Waiting {
    iosb: IO_STATUS_BLOCK,
    done: KEVENT,
}

/// A request that has been sent. It may be complete already.
pub struct Pending {
    irp: *mut IRP,
    waiting: Box<Waiting>,
    dispatch_status: NTSTATUS,
    /// The file object, if the request holds a reference to it: one
    /// made through a handle does, until it has been waited for.
    held: *mut FILE_OBJECT,
}

impl Pending {
    /// Ask the driver to give the request up
    /// ([`irp::IoCancelIrp`]). `false` if the driver had no cancel
    /// routine set: the request is past cancelling, or was never
    /// cancellable.
    pub fn cancel(&self) -> bool {
        // SAFETY: the requestor owns the IRP until `wait` frees it.
        unsafe { irp::IoCancelIrp(self.irp) != 0 }
    }

    /// Wait for the request to complete, and return what it came back
    /// with: the status its system service returns on Windows, and the
    /// status block's count. The status is the dispatch routine's for
    /// a request completed before the routine returned, and the final
    /// status of one the driver pended. They differ when the results
    /// could not be copied to a user-mode requestor: the fault is the
    /// final status, and no fault of the driver's.
    pub fn wait(mut self) -> Result<IoResult, IoError> {
        let done = &raw mut self.waiting.done;
        let completed;
        // SAFETY: the event lives in `self.waiting` until this returns;
        // the IRP is the requestor's to free once it has completed, and
        // the file object's reference the request's to give up then.
        unsafe {
            if self.dispatch_status != STATUS_PENDING && ke::wait::KeReadStateEvent(done) == 0 {
                // The driver neither completed the request nor said it
                // would later. It may still hold the IRP, which points
                // at this request's results and its file: leave all be.
                let dispatch_status = self.dispatch_status;
                core::mem::forget(self);
                return Err(IoError::NotCompleted { dispatch_status });
            }
            ke::wait::wait(Some(done.cast()), None);
            // What the driver completed the request with, which final
            // completion leaves in the IRP.
            completed = (*self.irp).IoStatus.Status;
            irp::free(self.irp);
            if !self.held.is_null() {
                object::dereference(self.held.cast());
            }
        }
        if self.dispatch_status == STATUS_PENDING {
            return Ok(IoResult {
                status: self.waiting.iosb.Status,
                information: self.waiting.iosb.Information,
            });
        }
        if self.dispatch_status != completed {
            return Err(IoError::StatusMismatch {
                dispatch_status: self.dispatch_status,
                completed,
            });
        }
        Ok(IoResult {
            status: self.dispatch_status,
            information: self.waiting.iosb.Information,
        })
    }
}

/// What [`start`] owes if the dispatch routine is unwound: the critical
/// region it called the routine in.
///
/// # Safety
/// The thread is in that critical region.
unsafe fn leave_critical_region(_: *mut c_void) {
    ke::mutex::KeLeaveCriticalRegion();
}

/// Fill in the common requestor fields and send the IRP on behalf of
/// `mode`.
///
/// If an exception unwinds the dispatch routine, the request is still
/// its driver's: the IRP, and the block of results and event the IRP
/// points to, are left where they are.
///
/// # Safety
/// `irp` must be a fresh IRP whose next stack location is set up for
/// `file`'s device. Whatever buffers it names stay valid until the
/// returned request has been waited for.
unsafe fn start(file: *mut FILE_OBJECT, irp: *mut IRP, mode: i8) -> Pending {
    // SAFETY: an all-zero event is a valid value (integers and null
    // pointers); it is initialised properly just below.
    let done: KEVENT = unsafe { core::mem::zeroed() };
    let mut waiting = Box::new(Waiting {
        iosb: IO_STATUS_BLOCK {
            Status: STATUS_PENDING,
            Information: 0,
        },
        done,
    });
    // SAFETY: per the contract; the boxed results and event stay where
    // they are until `Pending::wait` has seen the request complete.
    unsafe {
        ke::wait::KeInitializeEvent(&raw mut waiting.done, 0, 0);
        (*irp).UserIosb = &raw mut waiting.iosb;
        (*irp).UserEvent = &raw mut waiting.done;
        (*irp).RequestorMode = mode;
        (*irp).Thread = ke::pcr::current_thread().cast();
        (*irp).OriginalFileObject = file;
        (*irp::next_location(irp)).FileObject = file;
        // Windows calls the driver for a synchronous request with kernel
        // APCs off, in a critical region; a driver can ask, and
        // nkc-mutex does (oracle/nkc-mutex.txt).
        let device_object = (*file).DeviceObject;
        let guard = Guard::Undo {
            undo: leave_critical_region,
            context: core::ptr::null_mut(),
        };
        let dispatch_status =
            ke::mutex::in_critical_region(|| irp::call_driver(device_object, irp, &guard));
        Pending {
            irp,
            waiting,
            dispatch_status,
            held: core::ptr::null_mut(),
        }
    }
}

/// Send the IRP on the kernel's own behalf and wait for it to complete.
///
/// # Safety
/// As [`start`].
unsafe fn submit(file: *mut FILE_OBJECT, irp: *mut IRP) -> Result<IoResult, IoError> {
    // SAFETY: per the contract.
    unsafe { start(file, irp, KERNEL_MODE) }.wait()
}

/// A new IRP for `file`'s device with its next location's function set.
///
/// # Safety
/// `file` must be a live file object.
unsafe fn request(
    file: *mut FILE_OBJECT,
    major: u8,
    parameters: [u64; 4],
) -> Result<*mut IRP, IoError> {
    // SAFETY: per the contract.
    unsafe {
        let irp = irp::alloc((*(*file).DeviceObject).StackSize);
        if irp.is_null() {
            return Err(IoError::NoMemory);
        }
        let location = irp::next_location(irp);
        (*location).MajorFunction = major;
        (*location).Parameters = parameters;
        Ok(irp)
    }
}

/// The device an open is for, the part of the name the device's driver
/// is to parse, and for a name relative to an open file, that file.
/// The device and the file are referenced (pointer references).
struct Target {
    device: *mut DEVICE_OBJECT,
    remainder: Vec<u16>,
    related: *mut FILE_OBJECT,
}

impl Drop for Target {
    fn drop(&mut self) {
        // SAFETY: the references `resolve` took.
        unsafe {
            object::dereference(self.device.cast());
            if !self.related.is_null() {
                object::dereference(self.related.cast());
            }
        }
    }
}

/// Find what `name` leads to, from the namespace's root or from what
/// the handle `root` names: a directory, where the look-up starts, or
/// an open file, whose device parses the whole name. The look-up ends
/// at a device; whatever else it ends at is no file.
fn resolve(root: Option<u64>, name: &[u16]) -> Result<Target, NTSTATUS> {
    let is = |body: *mut u8, ty: &'static object::ObjectType| {
        // SAFETY: called with objects this function holds a reference to.
        core::ptr::eq(unsafe { object::type_of(body) }, ty)
    };
    let found = match root {
        None => ob::lookup(None, name),
        Some(root) => {
            let root = handle::reference(root, None)?;
            if is(root, &object::FILE_TYPE) {
                // Relative to an open file: the name as given is the
                // driver's to read, and is not absolute.
                if name.first() == Some(&u16::from(b'\\')) {
                    // SAFETY: the reference taken above.
                    unsafe { object::dereference(root) };
                    return Err(STATUS_OBJECT_PATH_SYNTAX_BAD);
                }
                let related = root.cast::<FILE_OBJECT>();
                // SAFETY: an open file holds a reference on its device,
                // so the device's memory is there to be referenced.
                let device = unsafe {
                    let device = (*related).DeviceObject;
                    object::reference(device.cast());
                    device
                };
                return Ok(Target {
                    device,
                    remainder: name.to_vec(),
                    related,
                });
            }
            let found = if is(root, &object::DIRECTORY_TYPE) {
                ob::lookup(Some(root), name)
            } else if is(root, &object::KEY_TYPE) {
                // A key parses a name into a key, never a file.
                Err(STATUS_OBJECT_TYPE_MISMATCH)
            } else {
                // Nothing parses a name below such an object.
                Err(STATUS_INVALID_HANDLE)
            };
            // SAFETY: the reference taken above.
            unsafe { object::dereference(root) };
            found
        }
    };
    let (body, remainder) = found?;
    if !is(body, &object::DEVICE_TYPE) {
        // SAFETY: the look-up's reference.
        unsafe { object::dereference(body) };
        return Err(STATUS_OBJECT_TYPE_MISMATCH);
    }
    Ok(Target {
        device: body.cast(),
        remainder,
        related: core::ptr::null_mut(),
    })
}

/// Give a new file object its name: a counted string in a pool block
/// of the I/O manager's, with room for a terminator. An empty name
/// needs no block. `false` without memory.
///
/// # Safety
/// `file` is a fresh file object nothing else has.
unsafe fn set_name(file: *mut FILE_OBJECT, name: &[u16]) -> bool {
    let Ok(bytes) = u16::try_from(name.len() * 2) else {
        return false;
    };
    if bytes == 0 {
        return true;
    }
    let Some(room) = bytes.checked_add(2) else {
        return false;
    };
    let buffer = pool::alloc_zeroed(usize::from(room), TAG_FILE_NAME).cast::<u16>();
    if buffer.is_null() {
        return false;
    }
    // SAFETY: per the contract; the block has room for the name.
    unsafe {
        buffer.copy_from_nonoverlapping(name.as_ptr(), name.len());
        (*file).FileName = UNICODE_STRING {
            Length: bytes,
            MaximumLength: room,
            Buffer: buffer,
        };
    }
    true
}

/// Open a name: find the device it leads to, make a file object, and
/// send the device's driver the create request. Returns a handle to the
/// file object and what the driver reported as the result of the create
/// (`IoStatus.Information`: `FILE_OPENED`, `FILE_CREATED`, ...), or the
/// status the open failed with.
pub fn open(request: &OpenRequest<'_>) -> Result<(u64, usize), NTSTATUS> {
    let name: Vec<u16> = request.name.encode_utf16().collect();
    let target = resolve(request.root, &name)?;
    let device = target.device;
    // Finding the device and counting the open are two steps, and the
    // device may be deleted between them: its memory is held (by the
    // look-up's pointer reference) until the device's own count has
    // been taken, or the open has been refused.
    // SAFETY: `target` keeps the device's memory. A device still being
    // set up is not opened.
    let live = unsafe {
        let counted = device::reference_unless_deleted(device);
        let ready = counted && (*device).Flags & DO_DEVICE_INITIALIZING == 0;
        if counted && !ready {
            device::dereference(device);
        }
        ready
    };
    if !live {
        return Err(STATUS_NO_SUCH_DEVICE);
    }
    let Some(body) = object::create(&object::FILE_TYPE, size_of::<FILE_OBJECT>()) else {
        // SAFETY: the count taken above.
        unsafe { device::dereference(device) };
        return Err(STATUS_INSUFFICIENT_RESOURCES);
    };
    let file = body.cast::<FILE_OBJECT>();
    // What the driver is handed by pointer lives here until the create
    // has completed: the access state, the security context that points
    // to it, and a named pipe's parameters. They are the driver's to
    // read and write meanwhile, so they are reached through raw
    // pointers only.
    let desired = object::FILE_TYPE.map_generic(request.desired_access);
    // SAFETY: an all-zero access state is a valid value (integers and
    // null pointers).
    let mut state: ACCESS_STATE = unsafe { core::mem::zeroed() };
    let state = &raw mut state;
    let mut context = IO_SECURITY_CONTEXT {
        SecurityQos: core::ptr::null_mut(),
        AccessState: state,
        DesiredAccess: desired,
        FullCreateOptions: request.create_options,
    };
    let context = &raw mut context as u64;
    let options = create_options(request.disposition, request.create_options);
    let share = request.share_access as u16;
    let mut pipe = match request.kind {
        Kind::NamedPipe(parameters) => Some(parameters),
        Kind::File => None,
    };
    let (major, parameters) = match &mut pipe {
        Some(pipe) => (
            IRP_MJ_CREATE_NAMED_PIPE,
            create_pipe_parameters(context, options, share, core::ptr::from_mut(pipe) as u64),
        ),
        None => (
            IRP_MJ_CREATE,
            create_parameters(context, options, 0, share, 0),
        ),
    };
    // SAFETY: `device` is counted, so it is live; `file` is a fresh
    // zeroed object of the right size; the locals above outlive the
    // request, which is waited for here.
    let result = unsafe {
        (*file).Type = IO_TYPE_FILE;
        (*file).Size = size_of::<FILE_OBJECT>() as i16;
        (*file).DeviceObject = device;
        (*file).RelatedFileObject = target.related;
        if request.create_options & (FILE_SYNCHRONOUS_IO_ALERT | FILE_SYNCHRONOUS_IO_NONALERT) != 0
        {
            (*file).Flags = FO_SYNCHRONOUS_IO;
        }
        ke::wait::KeInitializeEvent(&raw mut (*file).Lock, 1, 0);
        ke::wait::KeInitializeEvent(&raw mut (*file).Event, 0, 0);
        (*file).IrpList.Flink = &raw mut (*file).IrpList;
        (*file).IrpList.Blink = &raw mut (*file).IrpList;
        // The access state as Windows hands it to a file system: the
        // generic rights mapped to the file rights they stand for.
        se::token::create_access_state(state, desired);
        let named = set_name(file, &target.remainder);
        let result = if named {
            self::request(file, major, parameters).and_then(|irp| {
                (*irp).Flags = IRP_CREATE_OPERATION | IRP_SYNCHRONOUS_API | IRP_DEFER_IO_COMPLETION;
                start(file, irp, request.requestor_mode).wait()
            })
        } else {
            Err(IoError::NoMemory)
        };
        // What the open has been granted: for kernel mode, with no
        // check made, all that was asked for and whatever the driver
        // granted on its own.
        let granted = (&raw const (*state).PreviouslyGrantedAccess).read()
            | (&raw const (*state).RemainingDesiredAccess).read();
        se::token::delete_access_state(state);
        // The related file object is the driver's to read only while
        // the create is processed. `target` holds it until this
        // function returns, which is after the request has completed,
        // pended or not; the pointer does not outlive that reference.
        (*file).RelatedFileObject = core::ptr::null_mut();
        result.map(|r| (r, granted))
    };
    let status = match result {
        Ok((r, granted)) if nt_success(r.status) => {
            // SAFETY: `file` is the open file; the handle takes its own
            // reference and the creating one is given up. Without a
            // handle that ends the file: its type sends the driver the
            // cleanup and the close.
            unsafe {
                let handle = handle::open(body, granted);
                if handle.is_ok() {
                    (*file).Flags |= FO_HANDLE_CREATED;
                }
                object::dereference(body);
                return handle.map(|handle| (handle, r.information));
            }
        }
        Ok((r, _)) => r.status,
        Err(IoError::NoMemory) => STATUS_INSUFFICIENT_RESOURCES,
        Err(_) => STATUS_UNSUCCESSFUL,
    };
    // SAFETY: the create failed, so the driver has nothing open: the
    // file object goes without a cleanup or a close request, which is
    // what a file object with no device means.
    unsafe {
        (*file).DeviceObject = core::ptr::null_mut();
        device::dereference(device);
        object::dereference(body);
    }
    Err(status)
}

/// Close a handle from [`open`]: what `NtClose` returns. The file
/// object's type sends the driver its cleanup and close requests when
/// the last handle and the last reference go.
pub fn close(handle: u64) -> NTSTATUS {
    handle::close(handle)
}

/// Tell the driver the last handle to `file` has closed.
///
/// # Safety
/// `file` is a live file object with a device.
unsafe fn cleanup(file: *mut FILE_OBJECT) {
    // SAFETY: per the contract. A driver may legitimately not handle
    // cleanup, so its result is nobody's concern.
    unsafe {
        let _ = request(file, IRP_MJ_CLEANUP, [0; 4]).and_then(|irp| {
            (*irp).Flags = IRP_CLOSE_OPERATION | IRP_SYNCHRONOUS_API;
            submit(file, irp)
        });
        (*file).Flags |= FO_CLEANUP_COMPLETE;
    }
}

/// The file type's close procedure: a handle to a file object has been
/// closed. When it was the last one in the system, the driver is sent
/// `IRP_MJ_CLEANUP`: no handle will make another request, though
/// requests under way and references may remain.
///
/// # Safety
/// `object` is a file object the caller holds a reference to.
pub unsafe extern "C" fn handle_closed(
    _process: *mut c_void,
    object: *mut c_void,
    _process_handle_count: usize,
    system_handle_count: usize,
) {
    if system_handle_count != 1 {
        return;
    }
    // SAFETY: per the contract: a handle was open, so the create
    // succeeded and the file has its device.
    unsafe {
        cleanup(object.cast());
    }
}

/// The file type's delete procedure: the last reference to a file
/// object has gone. The driver is sent `IRP_MJ_CLOSE` (after a cleanup
/// request, if the file never had a handle to be closed), the device
/// loses the file's reference and the name its block. A file object
/// whose create failed has no device, and the driver hears nothing.
///
/// A driver is called at `PASSIVE_LEVEL`: when the last reference to
/// a file goes above it, the object manager leaves this to a worker
/// thread (`ob::object`), as Windows does.
///
/// # Safety
/// `object` is a file object nothing refers to any more.
pub unsafe extern "C" fn deleted(object: *mut c_void) {
    let file = object.cast::<FILE_OBJECT>();
    // SAFETY: per the contract; the name's block is the I/O manager's
    // own, or one a file system put in its place from the pool.
    unsafe {
        let device = (*file).DeviceObject;
        if !device.is_null() {
            ke::irql::expect_passive("closing a file object");
            if (*file).Flags & FO_HANDLE_CREATED == 0 {
                cleanup(file);
            }
            let _ = request(file, IRP_MJ_CLOSE, [0; 4]).and_then(|irp| {
                (*irp).Flags = IRP_CLOSE_OPERATION | IRP_SYNCHRONOUS_API;
                submit(file, irp)
            });
            device::dereference(device);
        }
        let name = (*file).FileName.Buffer;
        if !name.is_null() {
            let _ = pool::free(name.cast());
        }
        (*file).Type = 0;
    }
}

/// [`IoGetDeviceObjectPointer`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-iogetdeviceobjectpointer):
/// open the named device for kernel mode and hand the caller the file
/// object, with a reference, and the device the file's requests go to.
/// The handle of the open is closed again, so the device's driver is
/// sent a create and a cleanup now, and a close when the caller gives
/// the file object's reference up.
///
/// # Safety
/// `name` is a counted string and the two last arguments are writable.
#[allow(non_snake_case)]
pub unsafe extern "C" fn IoGetDeviceObjectPointer(
    name: *const UNICODE_STRING,
    desired_access: u32,
    file_object: *mut *mut FILE_OBJECT,
    device_object: *mut *mut DEVICE_OBJECT,
) -> NTSTATUS {
    // SAFETY: per the contract.
    let name = alloc::string::String::from_utf16_lossy(&unsafe { crate::rtl::copy_unicode(name) });
    let request = OpenRequest {
        name: &name,
        root: None,
        desired_access,
        share_access: 0,
        create_options: FILE_NON_DIRECTORY_FILE,
        disposition: FILE_OPEN,
        kind: Kind::File,
        requestor_mode: KERNEL_MODE,
    };
    let handle = match open(&request) {
        Ok((handle, _)) => handle,
        Err(status) => return status,
    };
    let Ok(file) = file_of(handle) else {
        crate::kd::bugcheck(format_args!(
            "IoGetDeviceObjectPointer: a handle just opened names no file"
        ))
    };
    close(handle);
    // SAFETY: per the contract; the reference just taken keeps the file
    // object, whose device is set for as long as it is open.
    unsafe {
        file_object.write(file);
        device_object.write((*file).DeviceObject);
    }
    STATUS_SUCCESS
}

/// The open file `handle` names, with a reference for a request to
/// hold.
fn file_of(handle: u64) -> Result<*mut FILE_OBJECT, IoError> {
    file_for(handle, KERNEL_MODE, Needs::All(0))
}

/// What a request made for user mode needs its handle to have been
/// granted, as the system service that makes the request on Windows
/// asks. Kernel mode's handle is asked for nothing.
#[derive(Clone, Copy)]
enum Needs {
    /// Every right of the mask: `FILE_READ_DATA` to read, and for a
    /// control request what its code says (`ctl_access`).
    All(u32),
    /// To write (`may_write`).
    Write,
}

/// The open file `handle` names, with a reference, for a request made
/// on behalf of `mode` that needs `needs` of the handle. User mode's
/// handle without it is refused: `STATUS_ACCESS_DENIED`.
fn file_for(handle: u64, mode: i8, needs: Needs) -> Result<*mut FILE_OBJECT, IoError> {
    let (mode, all) = match (mode, needs) {
        (KERNEL_MODE, _) => (Mode::Kernel, 0),
        (_, Needs::All(mask)) => (Mode::User, mask),
        (_, Needs::Write) => (Mode::User, 0),
    };
    let (body, information) =
        handle::reference_for(handle, Some(&raw const object::FILE_TYPE), all, mode)
            .map_err(IoError::Handle)?;
    let file = body.cast::<FILE_OBJECT>();
    // SAFETY: an open file, referenced just above.
    unsafe {
        if mode == Mode::User
            && matches!(needs, Needs::Write)
            && !may_write(information.granted, (*file).Flags)
        {
            object::dereference(body);
            return Err(IoError::Handle(STATUS_ACCESS_DENIED));
        }
    }
    Ok(file)
}

/// A requestor's buffer, as a system service is given it: an address
/// and a length. Kernel mode's is trusted. User mode's is whatever the
/// requestor chose to say, and is used only through checks and
/// `mm::user::copy`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Buffer {
    pub address: usize,
    pub len: usize,
}

impl Buffer {
    /// No buffer: a null pointer and no length.
    pub const NONE: Self = Self { address: 0, len: 0 };

    /// The kernel's own memory. An empty slice is no buffer.
    fn of(bytes: &[u8]) -> Self {
        if bytes.is_empty() {
            Self::NONE
        } else {
            Self {
                address: bytes.as_ptr().addr(),
                len: bytes.len(),
            }
        }
    }

    fn ptr(self) -> *mut u8 {
        core::ptr::with_exposed_provenance_mut(self.address)
    }

    /// What Windows makes of a user-mode requestor's buffer that the
    /// I/O manager copies: a null pointer is no buffer, whatever length
    /// came with it.
    fn if_present(self) -> Self {
        if self.address == 0 { Self::NONE } else { self }
    }
}

/// Refuse a user-mode request whose buffer the I/O manager cannot use:
/// the status of the exception Windows' own probe raises and catches.
const REFUSED: IoError = IoError::Refused(STATUS_ACCESS_VIOLATION);

/// Probe a user-mode requestor's buffer for reading: it lies in the
/// user range. Nothing is touched (`ProbeForRead`).
fn probe_read(buffer: Buffer) -> Result<(), IoError> {
    if user::in_range(buffer.address, buffer.len) {
        Ok(())
    } else {
        Err(REFUSED)
    }
}

/// Probe a user-mode requestor's buffer for writing: it lies in the
/// user range and every page of it can be written (`ProbeForWrite`).
fn probe_write(buffer: Buffer) -> Result<(), IoError> {
    probe_read(buffer)?;
    user::probe_pages(buffer.address, buffer.len).map_err(|_| REFUSED)
}

/// Copy a requestor's bytes into a system buffer: plainly from kernel
/// memory, through the copy that may fail from user memory.
///
/// # Safety
/// `system` has room for the buffer; a kernel-mode buffer is valid.
unsafe fn copy_in(system: *mut u8, buffer: Buffer, mode: i8) -> Result<(), IoError> {
    // SAFETY: per the contract; a user buffer has been probed.
    unsafe {
        if mode == KERNEL_MODE {
            core::ptr::copy_nonoverlapping(buffer.ptr(), system, buffer.len);
            Ok(())
        } else {
            user::copy(system, buffer.ptr(), buffer.len).map_err(|_| REFUSED)
        }
    }
}

/// Free a request that was not sent: its IRP, its system buffer and
/// its MDLs.
///
/// # Safety
/// `irp` is a fresh IRP no driver has seen.
unsafe fn discard(irp: *mut IRP) {
    // SAFETY: per the contract.
    unsafe {
        let system = (*irp).SystemBuffer;
        if !system.is_null() {
            let _ = pool::free(system.cast());
        }
        mdl::release_chain(irp);
        irp::free(irp);
    }
}

/// Build a request for the open file `handle` names and send it on
/// behalf of `mode`, which if it is user mode needs `needs` of the
/// handle. The request holds the file object until it has been waited
/// for. A request `build` gives up on is freed.
///
/// # Safety
/// `build` sets up the fresh IRP it is given for the file's device;
/// whatever buffers it names stay valid until the returned request has
/// been waited for.
unsafe fn send(
    handle: u64,
    major: u8,
    parameters: impl FnOnce(*mut FILE_OBJECT) -> [u64; 4],
    mode: i8,
    needs: Needs,
    build: impl FnOnce(*mut FILE_OBJECT, *mut IRP) -> Result<(), IoError>,
) -> Result<Pending, IoError> {
    let file = file_for(handle, mode, needs)?;
    // SAFETY: `file` is an open file, referenced.
    let built = unsafe { request(file, major, parameters(file)) }.and_then(|irp| {
        build(file, irp).map(|()| irp).inspect_err(|_| {
            // SAFETY: the request was not sent.
            unsafe { discard(irp) }
        })
    });
    match built {
        Ok(irp) => {
            // SAFETY: per the contract.
            let mut pending = unsafe { start(file, irp, mode) };
            pending.held = file;
            Ok(pending)
        }
        Err(error) => {
            // SAFETY: the reference `file_of` took.
            unsafe { object::dereference(file.cast()) };
            Err(error)
        }
    }
}

/// What a request the I/O manager refused before any driver saw it
/// comes back as: its status, as a system service returns it.
fn refused(result: Result<IoResult, IoError>) -> Result<IoResult, IoError> {
    match result {
        Err(IoError::Refused(status)) => Ok(IoResult {
            status,
            information: 0,
        }),
        other => other,
    }
}

/// Read or write. `buffer` is filled by a read and sent by a write.
///
/// # Safety
/// A kernel-mode `buffer` must be valid for its length (writable for a
/// read) until the returned request has been waited for.
unsafe fn transfer(handle: u64, major: u8, buffer: Buffer, mode: i8) -> Result<Pending, IoError> {
    let len = buffer.len;
    // SAFETY: `file` is an open file, referenced.
    let parameters =
        |file: *mut FILE_OBJECT| unsafe { rw_parameters(len as u32, (*file).CurrentByteOffset) };
    // SAFETY: per the contract; `irp` is fresh.
    let build = |file: *mut FILE_OBJECT, irp: *mut IRP| unsafe {
        if mode != KERNEL_MODE {
            if major == IRP_MJ_READ {
                probe_write(buffer)?;
            } else {
                probe_read(buffer)?;
            }
        }
        let flags = (*(*file).DeviceObject).Flags;
        if flags & DO_BUFFERED_IO != 0 {
            if len != 0 {
                let system = pool::alloc(len, TAG_IO_BUFFER);
                if system.is_null() {
                    return Err(IoError::NoMemory);
                }
                (*irp).SystemBuffer = system.cast();
                (*irp).Flags = IRP_BUFFERED_IO | IRP_DEALLOCATE_BUFFER;
                if major == IRP_MJ_READ {
                    (*irp).Flags |= IRP_INPUT_OPERATION;
                    (*irp).UserBuffer = buffer.ptr().cast();
                    irp::requestor_room(irp).write(len);
                } else {
                    copy_in(system, buffer, mode)?;
                }
            }
        } else if flags & DO_DIRECT_IO != 0 {
            return Err(IoError::UnsupportedMethod);
        } else {
            // Neither: the driver gets the caller's buffer as it is.
            (*irp).UserBuffer = buffer.ptr().cast();
        }
        Ok(())
    };
    let needs = if major == IRP_MJ_READ {
        Needs::All(FILE_READ_DATA)
    } else {
        Needs::Write
    };
    // SAFETY: per the contract.
    unsafe { send(handle, major, parameters, mode, needs, build) }
}

/// Read up to `buffer.len()` bytes.
pub fn read(handle: u64, buffer: &mut [u8]) -> Result<IoResult, IoError> {
    // SAFETY: the buffer is borrowed until the request has been waited
    // for, here.
    unsafe { read_start(handle, buffer) }?.wait()
}

/// Send a read without waiting for it.
///
/// # Safety
/// `buffer` must stay valid and unused until the returned request has
/// been waited for.
pub unsafe fn read_start(handle: u64, buffer: &mut [u8]) -> Result<Pending, IoError> {
    // SAFETY: `buffer` is a valid writable slice; the rest per the
    // contract.
    unsafe { transfer(handle, IRP_MJ_READ, Buffer::of(buffer), KERNEL_MODE) }
}

/// Write `buffer`.
pub fn write(handle: u64, buffer: &[u8]) -> Result<IoResult, IoError> {
    // SAFETY: a write only reads the buffer, which is borrowed until
    // the request has been waited for, here.
    unsafe { transfer(handle, IRP_MJ_WRITE, Buffer::of(buffer), KERNEL_MODE) }?.wait()
}

/// Read or write (`major`) on behalf of user mode, as `NtReadFile` and
/// `NtWriteFile` do: `buffer` is wherever the requestor says. One the
/// I/O manager cannot use fails the request with the access violation.
/// The handle must have been granted the access to read, or to write or
/// append.
pub fn user_transfer(handle: u64, major: u8, buffer: Buffer) -> Result<IoResult, IoError> {
    // SAFETY: a user-mode buffer is only used through checks.
    let pending = unsafe { transfer(handle, major, buffer, USER_MODE) };
    refused(pending.and_then(Pending::wait))
}

/// Send a device control request (`IRP_MJ_DEVICE_CONTROL`) and wait for
/// it. The control code's low two bits say how the buffers travel.
pub fn device_control(
    handle: u64,
    code: u32,
    input: &[u8],
    output: &mut [u8],
) -> Result<IoResult, IoError> {
    // SAFETY: the slices are borrowed until the request has been waited
    // for, here.
    unsafe { device_control_start(handle, code, input, output) }?.wait()
}

/// Send a device control request without waiting for it.
///
/// # Safety
/// `output` must stay valid and unused until the returned request has
/// been waited for.
pub unsafe fn device_control_start(
    handle: u64,
    code: u32,
    input: &[u8],
    output: &mut [u8],
) -> Result<Pending, IoError> {
    let (input, output) = (Buffer::of(input), Buffer::of(output));
    // SAFETY: per the contract; the slices are valid for their lengths.
    unsafe {
        control(
            handle,
            IRP_MJ_DEVICE_CONTROL,
            code,
            input,
            output,
            KERNEL_MODE,
        )
    }
}

/// Send a file-system control request (`IRP_MJ_FILE_SYSTEM_CONTROL`,
/// what `NtFsControlFile` sends) and wait for it. Buffers travel as for
/// a device control request.
pub fn fs_control(
    handle: u64,
    code: u32,
    input: &[u8],
    output: &mut [u8],
) -> Result<IoResult, IoError> {
    let (input, output) = (Buffer::of(input), Buffer::of(output));
    // SAFETY: the slices are borrowed until the request has been waited
    // for, here.
    unsafe {
        control(
            handle,
            IRP_MJ_FILE_SYSTEM_CONTROL,
            code,
            input,
            output,
            KERNEL_MODE,
        )
    }?
    .wait()
}

/// Send a control request (`major`: device or file-system control) on
/// behalf of user mode, as `NtDeviceIoControlFile` and
/// `NtFsControlFile` do, and wait for it. The buffers are wherever the
/// requestor says. For the buffered and direct methods the I/O manager
/// probes and copies them, and one it cannot use fails the request with
/// the access violation; for `METHOD_NEITHER` the driver is handed the
/// addresses as they are. The handle must have been granted the access
/// the control code names.
pub fn user_control(
    handle: u64,
    major: u8,
    code: u32,
    input: Buffer,
    output: Buffer,
) -> Result<IoResult, IoError> {
    // SAFETY: user-mode buffers are only used through checks.
    let pending = unsafe { control(handle, major, code, input, output, USER_MODE) };
    refused(pending.and_then(Pending::wait))
}

/// Send a control request of either kind. Their parameters have one
/// layout, and the minor function of a file-system control request
/// from a requestor is zero (`IRP_MN_USER_FS_REQUEST`).
///
/// # Safety
/// Kernel-mode buffers must be valid, and `output` unused, until the
/// returned request has been waited for.
unsafe fn control(
    handle: u64,
    major: u8,
    code: u32,
    input: Buffer,
    output: Buffer,
    mode: i8,
) -> Result<Pending, IoError> {
    let method = code & 3;
    let user = mode != KERNEL_MODE;
    // A user-mode buffer the I/O manager itself copies, in or out, has
    // no length if it is null: the input of the buffered and direct
    // methods, the output of the buffered one. A direct method's second
    // buffer keeps its length, and a null one fails its probe.
    let (input, output) = match method {
        METHOD_BUFFERED if user => (input.if_present(), output.if_present()),
        METHOD_IN_DIRECT | METHOD_OUT_DIRECT if user => (input.if_present(), output),
        _ => (input, output),
    };
    let parameters = |_| {
        let type3 = if method == METHOD_NEITHER {
            input.address as u64
        } else {
            0
        };
        ioctl_parameters(output.len as u32, input.len as u32, code, type3)
    };
    // SAFETY: per the contract; `irp` is fresh.
    let build = |_, irp: *mut IRP| unsafe {
        // The buffered part of a request: a system buffer of `len`
        // bytes holding the input.
        let buffered = |len: usize| -> Result<(), IoError> {
            if len == 0 {
                return Ok(());
            }
            let system = pool::alloc(len, TAG_IO_BUFFER);
            if system.is_null() {
                return Err(IoError::NoMemory);
            }
            (*irp).SystemBuffer = system.cast();
            (*irp).Flags = IRP_BUFFERED_IO | IRP_DEALLOCATE_BUFFER;
            copy_in(system, input, mode)
        };
        match method {
            METHOD_BUFFERED => {
                // One system buffer serves both directions: input is
                // copied in, and the driver's output is copied back out
                // of it on completion.
                if user {
                    probe_read(input)?;
                    probe_write(output)?;
                }
                buffered(input.len.max(output.len))?;
                if output.len != 0 {
                    (*irp).Flags |= IRP_INPUT_OPERATION;
                    (*irp).UserBuffer = output.ptr().cast();
                    irp::requestor_room(irp).write(output.len);
                }
            }
            METHOD_IN_DIRECT | METHOD_OUT_DIRECT => {
                // The "input" buffer is buffered; the "output" buffer is
                // described by an MDL and its pages locked. For
                // METHOD_IN_DIRECT the driver reads from it, for
                // METHOD_OUT_DIRECT it writes to it.
                let operation = if method == METHOD_IN_DIRECT {
                    IO_READ_ACCESS
                } else {
                    IO_WRITE_ACCESS
                };
                if user {
                    probe_read(input)?;
                    if operation == IO_READ_ACCESS {
                        probe_read(output)?;
                    } else {
                        probe_write(output)?;
                    }
                }
                buffered(input.len)?;
                if output.len != 0 {
                    let described =
                        mdl::IoAllocateMdl(output.ptr().cast(), output.len as u32, 0, 0, irp);
                    if described.is_null() {
                        return Err(IoError::NoMemory);
                    }
                    mdl::probe_and_lock(described, mode, operation).map_err(IoError::Refused)?;
                }
            }
            _ => {
                // METHOD_NEITHER hands the driver the requestor's
                // addresses as they are; whether they can be used is
                // the driver's to find out.
                (*irp).UserBuffer = output.ptr().cast();
            }
        }
        Ok(())
    };
    let needs = Needs::All(ctl_access(code));
    // SAFETY: per the contract.
    unsafe { send(handle, major, parameters, mode, needs, build) }
}
