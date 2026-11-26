//! Tests of what Microsoft's file-system drivers `npfs.sys` and
//! `msfs.sys` ask of the kernel that no conformance driver asks yet.
//! Each calls the exports as those binaries do, with what their code
//! passes (read from the binaries), and the driver, where one is
//! needed, is here in Rust.

use crate::io::file::{self, OpenRequest};
use crate::io::{device, irp};
use crate::mm::pool;
use crate::ob::object;
use crate::ps::process;
use crate::test::{Group, Report};
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU32, AtomicUsize, Ordering};
use nk_bootinfo::BootInfo;
use nk_ntabi::io::*;
use nk_ntabi::status::*;
use nk_ntabi::thread as thread_layout;

const TAG: u32 = u32::from_le_bytes(*b"Test");

pub static REQUESTOR: Group = Group {
    names: &["io.requestor-process", "io.file-generic-mapping"],
    run: requestor,
    manual: false,
};

fn requestor(r: &mut Report, _: &BootInfo) {
    match requestor_process() {
        Ok(cases) => r.ok_with("io.requestor-process", format_args!("{cases} cases")),
        Err(why) => r.fail("io.requestor-process", format_args!("{why}")),
    }
    r.check("io.file-generic-mapping", file_generic_mapping);
}

const DEVICE: &str = "\\Device\\NkFsd";
const SYNCHRONIZE: u32 = 0x0010_0000;
const GENERIC_READ: u32 = 0x8000_0000;

/// What the driver's create routine was told: the requestor's process,
/// and the access the open asks for.
static CREATE_REQUESTOR: AtomicUsize = AtomicUsize::new(0);
static CREATE_ACCESS: AtomicU32 = AtomicU32::new(0);

/// The driver's create, cleanup and close routine. On a create it asks
/// who the requestor is, as `npfs.sys` does in its create routines
/// before it looks at anything else of the request.
///
/// # Safety
/// Called as a dispatch routine.
unsafe extern "C" fn dispatch(_: *mut DEVICE_OBJECT, irp: *mut IRP) -> NTSTATUS {
    // SAFETY: a live IRP being dispatched.
    unsafe {
        let location = (*irp).CurrentStackLocation;
        if (*location).MajorFunction == IRP_MJ_CREATE {
            CREATE_REQUESTOR.store(irp::IoGetRequestorProcess(irp).addr(), Ordering::Release);
            let context = (*location).Parameters[0] as *const IO_SECURITY_CONTEXT;
            CREATE_ACCESS.store((*context).DesiredAccess, Ordering::Release);
        }
        (*irp).IoStatus.Status = STATUS_SUCCESS;
        (*irp).IoStatus.Information = 0;
        irp::IofCompleteRequest(irp, 0);
    }
    STATUS_SUCCESS
}

/// Make the driver and its device, run `test`, and take both down.
fn with_driver<T>(test: impl FnOnce() -> Result<T, &'static str>) -> Result<T, &'static str> {
    let size = size_of::<DRIVER_OBJECT>() + size_of::<DRIVER_EXTENSION>();
    let driver = pool::alloc_zeroed(size, TAG).cast::<DRIVER_OBJECT>();
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
            (*driver).MajorFunction[usize::from(major)] = Some(dispatch);
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
        device::IoDeleteDevice(device_object);
        result
    };
    let _ = pool::free(driver.cast());
    result
}

/// `IoGetRequestorProcess`, asked as `npfs.sys` and `msfs.sys` ask it:
/// from a create routine, of the IRP the I/O manager sent, to learn
/// which process is opening the pipe or mailslot. That process is the
/// System process, the only one. Then of IRPs made as a driver makes
/// its own (`IoAllocateIrp`), with each thing the routine reads set as
/// Windows could set it; a block of memory stands for the thread, so
/// that each field read is told apart. Returns the cases checked.
fn requestor_process() -> Result<u32, &'static str> {
    let system = process::system().addr();
    if system == 0 || process::IoGetCurrentProcess().addr() != system {
        return Err("the current process is not the System process");
    }
    CREATE_REQUESTOR.store(0, Ordering::Release);
    with_driver(|| {
        let (handle, _) =
            file::open(&OpenRequest::new(DEVICE)).map_err(|_| "the test device did not open")?;
        file::close(handle);
        Ok(())
    })?;
    if CREATE_REQUESTOR.load(Ordering::Acquire) != system {
        return Err("a create request's requestor is not the System process");
    }
    let mut cases = 1;

    // A thread whose own process and attached process differ.
    const OWN: usize = 0x4E4B_1000;
    const ATTACHED: usize = 0x4E4B_2000;
    let thread = pool::alloc_zeroed(thread_layout::ETHREAD_SIZE, TAG);
    let request = irp::IoAllocateIrp(1, 0);
    if thread.is_null() || request.is_null() {
        if !thread.is_null() {
            let _ = pool::free(thread);
        }
        if !request.is_null() {
            // SAFETY: the IRP just allocated.
            unsafe { irp::IoFreeIrp(request) };
        }
        return Err("no memory for an IRP and a thread block");
    }
    // SAFETY: the test's own IRP and its own block of a thread's size;
    // the routine reads only the two fields written here.
    let answers = unsafe {
        thread
            .add(thread_layout::PROCESS)
            .cast::<usize>()
            .write(OWN);
        thread
            .add(thread_layout::APC_STATE_PROCESS)
            .cast::<usize>()
            .write(ATTACHED);
        let ask = move || irp::IoGetRequestorProcess(request).addr();
        // As allocated: no thread made the request.
        let no_thread = ask();
        (*request).Thread = thread.cast();
        let original = ask();
        (*request).ApcEnvironment = ATTACHED_APC_ENVIRONMENT;
        let attached = ask();
        (*request).ApcEnvironment = 2;
        let neither = ask();
        // The process is in the IRP itself, with flags below it, and
        // the thread is not asked.
        (*request).Flags |= IRP_ISSUING_PROCESS_IN_OVERLAY;
        (*request).Overlay[0] = 0x4E4B_3000 | 5;
        let issuing = ask();
        (*request).Thread = core::ptr::null_mut();
        let issuing_no_thread = ask();
        // The calling thread, as the I/O manager names it in a request.
        (*request).Flags &= !IRP_ISSUING_PROCESS_IN_OVERLAY;
        (*request).Overlay[0] = 0;
        (*request).ApcEnvironment = ORIGINAL_APC_ENVIRONMENT;
        (*request).Thread = crate::ke::thread::current().cast();
        let mine = ask();
        irp::IoFreeIrp(request);
        [
            no_thread,
            original,
            attached,
            neither,
            issuing,
            issuing_no_thread,
            mine,
        ]
    };
    let _ = pool::free(thread);
    let expected = [
        (0, "an IRP with no thread has a requestor"),
        (OWN, "the requestor is not the thread's own process"),
        (
            ATTACHED,
            "a request made while attached does not answer the attached process",
        ),
        (0, "an APC environment that is neither answers a process"),
        (
            0x4E4B_3000,
            "an IRP that holds its issuing process does not answer it, less its flag bits",
        ),
        (
            0x4E4B_3000,
            "an IRP that holds its issuing process needs a thread",
        ),
        (
            system,
            "the calling thread's requests are not the System process's",
        ),
    ];
    for (answer, (wanted, why)) in answers.into_iter().zip(expected) {
        if answer != wanted {
            return Err(why);
        }
        cases += 1;
    }
    Ok(cases)
}

/// `IoGetFileObjectGenericMapping`, as `npfs.sys` and `msfs.sys` use
/// it: called with no arguments wherever a pipe or mailslot is created
/// or its security changed, and the pointer passed on to the access
/// check (`SeAssignSecurity`, `SeAccessCheck`), which reads the four
/// masks through it. The masks are the pinned kernel's, the pointer is
/// the same every time, and it is the mapping an open's desired access
/// is mapped with before the driver sees it.
fn file_generic_mapping() -> Result<(), &'static str> {
    let mapping = object::IoGetFileObjectGenericMapping();
    if mapping.is_null() || mapping != object::IoGetFileObjectGenericMapping() {
        return Err("the mapping is not one place");
    }
    // SAFETY: the file type's mapping, which is never written.
    let masks = unsafe {
        [
            (*mapping).GenericRead,
            (*mapping).GenericWrite,
            (*mapping).GenericExecute,
            (*mapping).GenericAll,
        ]
    };
    // What the pinned kernel's export points at: `FILE_GENERIC_READ`,
    // `FILE_GENERIC_WRITE`, `FILE_GENERIC_EXECUTE`, `FILE_ALL_ACCESS`.
    if masks != [0x0012_0089, 0x0012_0116, 0x0012_00A0, 0x001F_01FF] {
        return Err("the masks are not Windows' for a file");
    }
    CREATE_ACCESS.store(0, Ordering::Release);
    with_driver(|| {
        let request = OpenRequest {
            desired_access: GENERIC_READ | SYNCHRONIZE,
            ..OpenRequest::new(DEVICE)
        };
        let (handle, _) = file::open(&request).map_err(|_| "the test device did not open")?;
        file::close(handle);
        Ok(())
    })?;
    if CREATE_ACCESS.load(Ordering::Acquire) != masks[0] | SYNCHRONIZE {
        return Err("an open for GENERIC_READ did not reach the driver as the mapping's read mask");
    }
    Ok(())
}
