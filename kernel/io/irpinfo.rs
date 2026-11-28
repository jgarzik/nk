//! What a driver asks about a request and its requestor: the I/O
//! priority, the requestor's process, the stack it runs on; and what
//! it notes on the requestor's thread.

#![allow(non_snake_case)]

use super::irp;
use core::ffi::c_void;
use nk_ntabi::io::*;
use nk_ntabi::process::UNIQUE_PROCESS_ID;
use nk_ntabi::status::*;
use nk_ntabi::thread::{DEVICE_TO_VERIFY, IO_BOOST_COUNT};

/// [`IoGetIoPriorityHint`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-iogetiopriorityhint):
/// the request's I/O priority, read out of the IRP's flags as the
/// pinned kernel reads it (`nk_ntabi::io::io_priority_hint`). The
/// requests NK builds carry the normal hint; an IRP with none is
/// normal too. No thread of NK's has its I/O priority boosted, and
/// the count Windows keeps of that in the thread is read all the
/// same.
///
/// # Safety
/// `irp` is a live IRP whose thread, if it names one, is a live
/// thread.
pub unsafe extern "C" fn IoGetIoPriorityHint(irp: *mut IRP) -> u32 {
    // SAFETY: per the contract; the thread's field is read through its
    // pointer.
    unsafe {
        let thread = (&raw const (*irp).Thread).read().cast::<u8>();
        let boosted = !thread.is_null() && thread.add(IO_BOOST_COUNT).cast::<u32>().read() != 0;
        io_priority_hint((&raw const (*irp).Flags).read(), boosted)
    }
}

/// [`IoGetPagingIoPriority`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-iogetpagingiopriority):
/// the priority of a paging request, read out of the IRP's flags as
/// the pinned kernel reads it; invalid for a request that is not
/// paging I/O, which is every request while NK pages nothing.
///
/// # Safety
/// `irp` is a live IRP.
pub unsafe extern "C" fn IoGetPagingIoPriority(irp: *mut IRP) -> u32 {
    // SAFETY: per the contract.
    paging_io_priority(unsafe { (&raw const (*irp).Flags).read() })
}

/// [`IoRetrievePriorityInfo`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-ioretrievepriorityinfo):
/// the priorities a file system should give a request, as the pinned
/// kernel decides them: the I/O priority from the request's flags if it
/// carries one, else from the thread (normal at least for a thread whose
/// priority was boosted), the thread's base priority and its page
/// priority; with no thread, normal I/O priority and the other two -1.
/// A process in background mode caps both at low.
///
/// Partial: a file object's own priority (in its extension) and a
/// thread in a scheduling group were not read, and NK makes neither;
/// meeting one stops the system by name.
///
/// # Safety
/// `irp` and `file` are null or live; `thread` is null or a thread
/// object; `info` is a writable `IO_PRIORITY_INFO`.
pub unsafe extern "C" fn IoRetrievePriorityInfo(
    irp: *mut IRP,
    file: *mut FILE_OBJECT,
    thread: *mut c_void,
    info: *mut u32,
) -> NTSTATUS {
    use nk_ntabi::process::{BACKGROUND, FLAGS};
    use nk_ntabi::thread::{
        BASE_PRIORITY, CROSS_THREAD_FLAGS, PRIORITY, PROCESS, SCHEDULING_GROUP,
        THREAD_IO_PRIORITY_SHIFT, THREAD_PAGE_PRIORITY_SHIFT,
    };
    /// `IRP_IO_PRIORITY_MASK` in an IRP's flags.
    const IRP_PRIORITY: u32 = 0xE_0000;
    const NORMAL: u32 = 2;
    // SAFETY: per the contract; the thread and its process are read
    // field by field, the info written field by field.
    unsafe {
        info.add(3).write_unaligned(NORMAL);
        let thread = thread.cast::<u8>();
        let background = || {
            let process = thread.add(PROCESS).cast::<*const u8>().read();
            process.add(FLAGS).cast::<u32>().read() & BACKGROUND != 0
        };
        let flags = || thread.add(CROSS_THREAD_FLAGS).cast::<u32>().read();
        let io = if !irp.is_null() && (&raw const (*irp).Flags).read() & IRP_PRIORITY != 0 {
            IoGetIoPriorityHint(irp)
        } else if !file.is_null() && !(&raw const (*file).FileObjectExtension).read().is_null() {
            crate::kd::bugcheck(format_args!(
                "IoRetrievePriorityInfo: NK does not implement a file object's own priority"
            ));
        } else if thread.is_null() {
            NORMAL
        } else {
            let mut io = if background() {
                0
            } else {
                flags() >> THREAD_IO_PRIORITY_SHIFT & 7
            };
            if io < NORMAL
                && thread == crate::ps::KeGetCurrentThread().cast()
                && thread.add(IO_BOOST_COUNT).cast::<u32>().read() != 0
            {
                io = NORMAL;
            }
            io
        };
        if thread.is_null() {
            info.add(1).write_unaligned(u32::MAX);
            info.add(2).write_unaligned(u32::MAX);
            return STATUS_SUCCESS;
        }
        info.add(3).write_unaligned(io);
        if thread.add(PRIORITY).cast::<i8>().read() < 16
            && !thread
                .add(SCHEDULING_GROUP)
                .cast::<*const u8>()
                .read()
                .is_null()
        {
            crate::kd::bugcheck(format_args!(
                "IoRetrievePriorityInfo: NK does not implement threads in scheduling groups"
            ));
        }
        info.add(1)
            .write_unaligned(i32::from(thread.add(BASE_PRIORITY).cast::<i8>().read()) as u32);
        let mut page = flags() >> THREAD_PAGE_PRIORITY_SHIFT & 7;
        if background() {
            page = page.min(NORMAL);
        }
        info.add(2).write_unaligned(page);
    }
    STATUS_SUCCESS
}

/// [`IoGetRequestorProcessId`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-iogetrequestorprocessid):
/// the id of the process [`irp::IoGetRequestorProcess`] names; zero
/// for a request no thread made.
///
/// # Safety
/// As [`irp::IoGetRequestorProcess`].
pub unsafe extern "C" fn IoGetRequestorProcessId(irp: *mut IRP) -> u32 {
    // SAFETY: per the contract; the id is written once, when the
    // process is made.
    unsafe {
        let process = irp::IoGetRequestorProcess(irp).cast::<u8>();
        if process.is_null() {
            return 0;
        }
        process.add(UNIQUE_PROCESS_ID).cast::<usize>().read() as u32
    }
}

/// [`IoGetInitiatorProcess`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntddk/nf-ntddk-iogetinitiatorprocess):
/// the process that initiated creating `file_object`, if different from
/// the current process. NK attaches no separate initiator-process context
/// to file objects, so this returns null (as Windows does when none was
/// recorded).
///
/// # Safety
/// `file_object` is null or a live `FILE_OBJECT`.
pub unsafe extern "C" fn IoGetInitiatorProcess(_file_object: *mut FILE_OBJECT) -> *mut c_void {
    core::ptr::null_mut()
}

/// [`IoIs32bitProcess`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-iois32bitprocess):
/// whether the request comes from a 32-bit process, whose structures
/// a driver must then read as 32-bit ones. Windows answers by the
/// requestor's process (the caller's, with no IRP) having a WOW64
/// side. NK runs no 32-bit code and no process has one: no.
pub extern "C" fn IoIs32bitProcess(_irp: *mut IRP) -> u8 {
    0
}

/// [`IoGetStackLimits`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-iogetstacklimits):
/// the bounds of the stack the caller is running on: its thread's, or
/// the processor's DPC stack. Both are zero if the caller is on
/// neither, as the pinned kernel writes them when it cannot tell.
///
/// # Safety
/// Both pointers are writable.
pub unsafe extern "C" fn IoGetStackLimits(low_limit: *mut usize, high_limit: *mut usize) {
    let here = 0u8;
    let (low, high) = crate::ke::unwind::stack_holding((&raw const here).addr() as u64)
        .map_or((0, 0), |stack| (stack.base as usize, stack.top as usize));
    // SAFETY: per the contract.
    unsafe {
        low_limit.write_unaligned(low);
        high_limit.write_unaligned(high);
    }
}

/// [`IoSetHardErrorOrVerifyDevice`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-iosetharderrororverifydevice):
/// note, on the thread that made the request, the device a file
/// system is to verify or that a hard error is about. A request no
/// thread made notes nothing, as on Windows. The note is kept where
/// Windows keeps it (`ETHREAD.DeviceToVerify`); nothing of NK's reads
/// it yet, there being no file system to ask
/// (`IoGetDeviceToVerify`) and no hard-error pop-ups.
///
/// # Safety
/// `irp` is a live IRP whose thread, if it names one, is a live
/// thread.
pub unsafe extern "C" fn IoSetHardErrorOrVerifyDevice(irp: *mut IRP, device: *mut DEVICE_OBJECT) {
    // SAFETY: per the contract; the thread's field is written through
    // its pointer.
    unsafe {
        let thread = (&raw const (*irp).Thread).read().cast::<u8>();
        if !thread.is_null() {
            thread
                .add(DEVICE_TO_VERIFY)
                .cast::<*mut DEVICE_OBJECT>()
                .write(device);
        }
    }
}

/// [`IoValidateDeviceIoControlAccess`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-iovalidatedeviceiocontrolaccess):
/// verify that the requestor of an I/O or file-system control IRP has
/// the read/write access bits `required_access` asks for (`FILE_READ_ACCESS`
/// = 1, `FILE_WRITE_ACCESS` = 2). Kernel-mode requests always succeed;
/// user-mode requests are checked against `FileObject->ReadAccess` and
/// `WriteAccess`.
///
/// # Safety
/// `irp` is a live IRP with a valid current stack location and file object.
pub unsafe extern "C" fn IoValidateDeviceIoControlAccess(
    irp: *mut IRP,
    required_access: u32,
) -> NTSTATUS {
    const FILE_READ_ACCESS: u32 = 1;
    const FILE_WRITE_ACCESS: u32 = 2;
    if irp.is_null() || required_access & !(FILE_READ_ACCESS | FILE_WRITE_ACCESS) != 0 {
        return STATUS_INVALID_PARAMETER;
    }
    // SAFETY: per the contract.
    unsafe {
        let location = (&raw const (*irp).CurrentStackLocation).read();
        if location.is_null() {
            return STATUS_INVALID_PARAMETER;
        }
        let major = (&raw const (*location).MajorFunction).read();
        if !matches!(
            major,
            IRP_MJ_DEVICE_CONTROL | IRP_MJ_INTERNAL_DEVICE_CONTROL | IRP_MJ_FILE_SYSTEM_CONTROL
        ) {
            return STATUS_INVALID_PARAMETER;
        }
        if (&raw const (*irp).RequestorMode).read() == KERNEL_MODE || required_access == 0 {
            return STATUS_SUCCESS;
        }
        let file = (&raw const (*location).FileObject).read();
        if file.is_null() {
            return STATUS_INVALID_PARAMETER;
        }
        if required_access & FILE_READ_ACCESS != 0 && (&raw const (*file).ReadAccess).read() == 0 {
            return STATUS_ACCESS_DENIED;
        }
        if required_access & FILE_WRITE_ACCESS != 0 && (&raw const (*file).WriteAccess).read() == 0
        {
            return STATUS_ACCESS_DENIED;
        }
        STATUS_SUCCESS
    }
}

/// [`IoRecordIoAttribution`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-iorecordioattribution):
/// charge disk I/O to the process an attribution handle stands for.
/// The information must be version 1 (`STATUS_REVISION_MISMATCH`), as
/// Windows checks first. NK attributes no I/O and gives out no
/// handle ([`super::irpext::IoGetIoAttributionHandle`] finds none), so
/// whatever is passed names nothing: `STATUS_INVALID_HANDLE`, Windows'
/// answer for a handle it does not know.
///
/// # Safety
/// `information` points to an `IO_ATTRIBUTION_INFORMATION`.
pub unsafe extern "C" fn IoRecordIoAttribution(
    _handle: *mut c_void,
    information: *const u32,
) -> NTSTATUS {
    // SAFETY: per the contract: the structure begins with its version.
    if unsafe { information.read_unaligned() } != 1 {
        return STATUS_REVISION_MISMATCH;
    }
    STATUS_INVALID_HANDLE
}

// ---- tests --------------------------------------------------------------

/// What drivers ask about a request, of IRPs the test makes: the
/// priority in the flags, the requestor's process id, the stack, the
/// device to verify. Returns the answers checked.
pub fn test() -> Result<u32, &'static str> {
    use crate::ke::thread;
    let request = irp::alloc(1);
    if request.is_null() {
        return Err("no memory for an IRP");
    }
    let me = thread::current().cast::<u8>();
    let mut device = 0u64;
    let device = (&raw mut device).cast::<DEVICE_OBJECT>();
    // SAFETY: the test's own IRP, freed at the end, and the running
    // thread.
    let verdict = unsafe {
        (|| {
            let noted = || me.add(DEVICE_TO_VERIFY).cast::<*mut DEVICE_OBJECT>().read();
            // An IRP no thread made.
            if IoGetIoPriorityHint(request) != IO_PRIORITY_NORMAL
                || IoGetPagingIoPriority(request) != IO_PAGING_PRIORITY_INVALID
                || IoGetRequestorProcessId(request) != 0
                || IoIs32bitProcess(request) != 0
                || IoIs32bitProcess(core::ptr::null_mut()) != 0
            {
                return Err("an IRP no thread made was not answered for as one");
            }
            let before = noted();
            IoSetHardErrorOrVerifyDevice(request, device);
            if noted() != before {
                return Err("a device to verify was noted on a thread for an IRP of no thread");
            }
            // The running thread's request, with a low priority hint.
            (*request).Thread = me.cast();
            (*request).Flags = 2 << 17;
            let system = crate::ps::process::PsGetProcessId(crate::ps::process::system().cast());
            if IoGetIoPriorityHint(request) != IO_PRIORITY_LOW
                || IoGetRequestorProcessId(request) as usize != system.addr()
                || system.addr() == 0
            {
                return Err("a thread's request does not say its priority and its process");
            }
            (*request).Flags = IRP_PAGING_IO | 5 << 17;
            if IoGetPagingIoPriority(request) != IO_PAGING_PRIORITY_HIGH
                || IoGetIoPriorityHint(request) != 4
            {
                return Err("a paging request does not say its priority");
            }
            IoSetHardErrorOrVerifyDevice(request, device);
            let after = noted();
            IoSetHardErrorOrVerifyDevice(request, before);
            if after != device || noted() != before {
                return Err("the device to verify was not noted on the request's thread");
            }
            // The stack this runs on holds a local, and is the thread's.
            let (mut low, mut high) = (1usize, 1usize);
            IoGetStackLimits(&raw mut low, &raw mut high);
            let here = (&raw const low).addr();
            let stack = thread::current_stack();
            if !(low <= here && here < high) || (low as u64, high as u64) != (stack.base, stack.top)
            {
                return Err("the stack limits are not those of the stack the caller is on");
            }
            // Attribution: nothing is attributed, so no handle is one.
            let (version_one, version_two) = (1u32, 2u32);
            let mut handle = core::ptr::null_mut();
            if IoRecordIoAttribution(handle, &raw const version_two) != STATUS_REVISION_MISMATCH
                || IoRecordIoAttribution(handle, &raw const version_one) != STATUS_INVALID_HANDLE
                || super::irpext::IoGetIoAttributionHandle(request, &raw mut handle)
                    != STATUS_NOT_FOUND
            {
                return Err("I/O attribution was not answered as on a system that has none");
            }
            // IoValidateDeviceIoControlAccess: checks major function, mode and file access.
            let mut fake_file = core::mem::zeroed::<FILE_OBJECT>();
            let fake_file_ptr = &raw mut fake_file;
            let loc = irp::next_location(request);
            (*request).CurrentStackLocation = loc;
            (*loc).MajorFunction = IRP_MJ_READ;
            (*loc).FileObject = fake_file_ptr;
            if IoValidateDeviceIoControlAccess(request, 1) != STATUS_INVALID_PARAMETER {
                return Err("IoValidateDeviceIoControlAccess accepted a non-control IRP");
            }
            (*loc).MajorFunction = IRP_MJ_DEVICE_CONTROL;
            (*request).RequestorMode = KERNEL_MODE;
            if IoValidateDeviceIoControlAccess(request, 3) != STATUS_SUCCESS {
                return Err("IoValidateDeviceIoControlAccess refused a kernel-mode request");
            }
            (*request).RequestorMode = USER_MODE;
            if IoValidateDeviceIoControlAccess(request, 1) != STATUS_ACCESS_DENIED
                || IoValidateDeviceIoControlAccess(request, 2) != STATUS_ACCESS_DENIED
                || IoValidateDeviceIoControlAccess(request, 4) != STATUS_INVALID_PARAMETER
            {
                return Err("IoValidateDeviceIoControlAccess missed a denied or invalid access");
            }
            (&raw mut (*fake_file_ptr).ReadAccess).write(1);
            if IoValidateDeviceIoControlAccess(request, 1) != STATUS_SUCCESS
                || IoValidateDeviceIoControlAccess(request, 2) != STATUS_ACCESS_DENIED
            {
                return Err("IoValidateDeviceIoControlAccess mischecked ReadAccess");
            }
            (&raw mut (*fake_file_ptr).WriteAccess).write(1);
            if IoValidateDeviceIoControlAccess(request, 3) != STATUS_SUCCESS {
                return Err("IoValidateDeviceIoControlAccess mischecked Read+WriteAccess");
            }
            Ok(22)
        })()
    };
    // SAFETY: the test's IRP, which no driver holds.
    unsafe {
        (*request).Thread = core::ptr::null_mut();
        irp::IoFreeIrp(request);
    }
    verdict
}
