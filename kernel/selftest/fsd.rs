//! Tests of what Microsoft's file-system drivers `npfs.sys` and
//! `msfs.sys` ask of the kernel that no conformance driver asks yet.
//! Each calls the exports as those binaries do, with what their code
//! passes (read from the binaries), and the driver, where one is
//! needed, is here in Rust.

use crate::ex::pushlock;
use crate::io::file::{self, OpenRequest};
use crate::io::{device, fsrtl, irp};
use crate::mm::pool;
use crate::ob::object;
use crate::ps::process;
use crate::test::{Group, Report};
use alloc::vec::Vec;
use core::ffi::c_void;
use core::sync::atomic::{AtomicU32, AtomicUsize, Ordering};
use nk_bootinfo::BootInfo;
use nk_ntabi::fsrtl::*;
use nk_ntabi::io::*;
use nk_ntabi::ke::FAST_MUTEX;
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

pub static STREAM_CONTEXTS: Group = Group {
    names: &["fsrtl.teardown-stream-contexts"],
    run: |r, _| match stream_contexts() {
        Ok(freed) => r.ok_with(STREAM_CONTEXTS.names[0], format_args!("{freed} contexts")),
        Err(why) => r.fail(STREAM_CONTEXTS.names[0], format_args!("{why}")),
    },
    manual: false,
};

/// What a filter attaches to a stream: the context header Windows
/// defines, then the filter's own.
#[repr(C)]
struct StreamContext {
    header: FSRTL_PER_STREAM_CONTEXT,
    /// The stream it is attached to.
    stream: *mut FSRTL_ADVANCED_FCB_HEADER,
    id: u32,
}

/// Contexts freed, and their ids in the order they were freed, four
/// bits each.
static FREED: AtomicU32 = AtomicU32::new(0);
static ORDER: AtomicU32 = AtomicU32::new(0);
/// What a free callback found wrong, a bit each.
static WRONG: AtomicU32 = AtomicU32::new(0);
const STILL_LINKED: u32 = 1;
const LOCK_HELD: u32 = 2;
const IN_CRITICAL_REGION: u32 = 4;
const NO_MEMORY: u32 = 8;
/// `KeAreApcsDisabled` for the test's thread outside the routine.
static APCS_DISABLED: AtomicU32 = AtomicU32::new(0);
/// The id of a context for the next free callback to attach to the
/// stream it is called for, or zero.
static ATTACH_LATE: AtomicU32 = AtomicU32::new(0);

/// Whether a header's contexts are guarded by its push lock.
///
/// # Safety
/// `stream` is an initialised header.
unsafe fn has_push_lock(stream: *mut FSRTL_ADVANCED_FCB_HEADER) -> bool {
    // SAFETY: per the contract.
    unsafe { fcb_header_version((*stream).Common.ReservedAndVersion) >= FSRTL_FCB_HEADER_V1 }
}

/// Attach a context to a stream as `FsRtlInsertPerStreamContext` does:
/// at the head of the header's list. The caller holds the header's
/// lock, or nobody else can reach the header.
///
/// # Safety
/// `stream` is an initialised advanced header.
unsafe fn attach(stream: *mut FSRTL_ADVANCED_FCB_HEADER, id: u32) -> Result<(), &'static str> {
    let context = pool::alloc_zeroed(size_of::<StreamContext>(), TAG).cast::<StreamContext>();
    if context.is_null() {
        return Err("no memory for a stream context");
    }
    // SAFETY: a fresh block of a context's size; the header per the
    // contract.
    unsafe {
        (*context).header.OwnerId = (&raw const FREED).cast_mut().cast::<c_void>();
        (*context).header.InstanceId = stream.cast();
        (*context).header.FreeCallback = Some(free_context);
        (*context).stream = stream;
        (*context).id = id;
        let head = &raw mut (*stream).FilterContexts;
        let entry = &raw mut (*context).header.Links;
        let first = (*head).Flink;
        (*entry).Flink = first;
        (*entry).Blink = head;
        (*first).Blink = entry;
        (*head).Flink = entry;
    }
    Ok(())
}

/// A filter's `FreeCallback`. It checks what Microsoft documents and
/// the pinned kernel does for it: the context is off the stream's list
/// already, and the header's lock is free for it to take, outside any
/// critical region of the kernel's making. Then it frees the context,
/// which is what the callback is for.
///
/// # Safety
/// Called by `FsRtlTeardownPerStreamContexts` with a context made by
/// `attach`.
unsafe extern "C" fn free_context(context: *mut FSRTL_PER_STREAM_CONTEXT) {
    let context = context.cast::<StreamContext>();
    // SAFETY: per the contract: the context is this routine's now, and
    // its stream's header is live until the teardown returns.
    unsafe {
        let stream = (*context).stream;
        let head = &raw mut (*stream).FilterContexts;
        let late = ATTACH_LATE.swap(0, Ordering::AcqRel);
        let mut wrong = 0;
        // With the lock held: what the list holds, and one more.
        let inspect = move || {
            let mut found = 0;
            let mut entry = (*head).Flink;
            while entry != head {
                if entry == &raw mut (*context).header.Links {
                    found |= STILL_LINKED;
                }
                entry = (*entry).Flink;
            }
            // A filter may attach to the stream while it is torn down.
            if late != 0 && attach(stream, late).is_err() {
                found |= NO_MEMORY;
            }
            found
        };
        if has_push_lock(stream) {
            if u32::from(crate::ke::mutex::KeAreApcsDisabled())
                != APCS_DISABLED.load(Ordering::Acquire)
            {
                wrong |= IN_CRITICAL_REGION;
            }
            crate::ke::mutex::KeEnterCriticalRegion();
            if pushlock::ExTryAcquirePushLockExclusiveEx(&raw mut (*stream).PushLock, 0) == 0 {
                wrong |= LOCK_HELD;
            } else {
                wrong |= inspect();
                pushlock::ExReleasePushLockEx(&raw mut (*stream).PushLock, 0);
            }
            crate::ke::mutex::KeLeaveCriticalRegion();
        } else if crate::ke::mutex::ExTryToAcquireFastMutex((*stream).FastMutex) == 0 {
            wrong |= LOCK_HELD;
        } else {
            wrong |= inspect();
            crate::ke::mutex::ExReleaseFastMutex((*stream).FastMutex);
        }
        WRONG.fetch_or(wrong, Ordering::AcqRel);
        // One thread tears a stream down: nothing else updates these.
        ORDER.store(
            ORDER.load(Ordering::Acquire) << 4 | (*context).id,
            Ordering::Release,
        );
        FREED.fetch_add(1, Ordering::AcqRel);
        let _ = pool::free(context.cast());
    }
}

/// A stream's control block as `npfs.sys` and `msfs.sys` make one: a
/// zeroed pool block with the header at its front, set up by the code
/// `FsRtlSetupAdvancedHeader` compiles to in both (advanced, supporting
/// filter contexts, version 3, an empty list, a zero push lock), and a
/// fast mutex of its own from the pool, initialised in line.
struct Stream {
    header: *mut FSRTL_ADVANCED_FCB_HEADER,
}

impl Stream {
    fn new(version: u8) -> Result<Self, &'static str> {
        // What npfs.sys allocates for a control block.
        const FCB_SIZE: usize = 0x188;
        let header = pool::alloc_zeroed(FCB_SIZE, TAG).cast::<FSRTL_ADVANCED_FCB_HEADER>();
        let fast_mutex = pool::alloc_zeroed(size_of::<FAST_MUTEX>(), TAG).cast::<FAST_MUTEX>();
        if header.is_null() || fast_mutex.is_null() {
            for block in [header.cast::<u8>(), fast_mutex.cast()] {
                if !block.is_null() {
                    let _ = pool::free(block);
                }
            }
            return Err("no memory for a stream's control block");
        }
        // SAFETY: two fresh, zeroed blocks of the sizes written to.
        unsafe {
            (*header).Common.Flags |= FSRTL_FLAG_ADVANCED_HEADER;
            (*header).Common.Flags2 |= FSRTL_FLAG2_SUPPORTS_FILTER_CONTEXTS;
            (*header).Common.ReservedAndVersion =
                with_fcb_header_version((*header).Common.ReservedAndVersion, version);
            let head = &raw mut (*header).FilterContexts;
            (*head).Flink = head;
            (*head).Blink = head;
            (*fast_mutex).Count = 1;
            crate::ke::wait::KeInitializeEvent(&raw mut (*fast_mutex).Event, 1, 0);
            (*header).FastMutex = fast_mutex;
        }
        Ok(Self { header })
    }

    /// Attach contexts with these ids, in this order, under the
    /// header's lock.
    fn attach(&self, ids: &[u32]) -> Result<(), &'static str> {
        // SAFETY: the stream's own header and locks.
        unsafe {
            let pushed = has_push_lock(self.header);
            if pushed {
                crate::ke::mutex::KeEnterCriticalRegion();
                pushlock::ExAcquirePushLockExclusiveEx(&raw mut (*self.header).PushLock, 0);
            } else {
                crate::ke::mutex::ExAcquireFastMutex((*self.header).FastMutex);
            }
            let result = ids.iter().try_for_each(|&id| attach(self.header, id));
            if pushed {
                pushlock::ExReleasePushLockEx(&raw mut (*self.header).PushLock, 0);
                crate::ke::mutex::KeLeaveCriticalRegion();
            } else {
                crate::ke::mutex::ExReleaseFastMutex((*self.header).FastMutex);
            }
            result
        }
    }

    /// Tear the stream's contexts down, as the file system does just
    /// before it frees the control block. Returns how many were freed
    /// and in which order.
    fn teardown(&self) -> (u32, u32) {
        FREED.store(0, Ordering::Release);
        ORDER.store(0, Ordering::Release);
        // SAFETY: the stream's header, which nothing else uses.
        unsafe { fsrtl::FsRtlTeardownPerStreamContexts(self.header) };
        (FREED.load(Ordering::Acquire), ORDER.load(Ordering::Acquire))
    }

    /// Whether no context is attached and neither lock is held.
    fn at_rest(&self) -> bool {
        // SAFETY: the stream's own header and mutex.
        unsafe {
            let head = &raw mut (*self.header).FilterContexts;
            (*head).Flink == head
                && (*head).Blink == head
                && (*self.header).PushLock == 0
                && (*(*self.header).FastMutex).Count == 1
        }
    }
}

impl Drop for Stream {
    /// Free the mutex, then the block, as both drivers do after the
    /// teardown.
    fn drop(&mut self) {
        // SAFETY: the stream's own blocks, used by nothing else now.
        unsafe {
            let _ = pool::free((*self.header).FastMutex.cast());
            let _ = pool::free(self.header.cast());
        }
    }
}

/// `FsRtlTeardownPerStreamContexts`, called as `npfs.sys` and
/// `msfs.sys` call it: with the control block they are about to free,
/// whose header they set up in line, whatever is attached to it and
/// without looking first. The contexts are attached here the way the
/// filter manager's side of the kernel attaches them, since no filter
/// runs on NK. Checked: a stream with nothing attached is left exactly
/// as it was; every context is unlinked and its `FreeCallback` called
/// once, the newest first, with the lock free and the region left; a
/// context attached by a callback is torn down too; a version 0 header
/// goes by its fast mutex; a header whose flags deny it has contexts is
/// not read. Returns how many contexts the callbacks freed.
fn stream_contexts() -> Result<u32, &'static str> {
    WRONG.store(0, Ordering::Release);
    ATTACH_LATE.store(0, Ordering::Release);
    let apcs_disabled = u32::from(crate::ke::mutex::KeAreApcsDisabled());
    APCS_DISABLED.store(apcs_disabled, Ordering::Release);
    let mut total = 0;

    let stream = Stream::new(FSRTL_FCB_HEADER_V3)?;
    if stream.teardown() != (0, 0) || !stream.at_rest() {
        return Err("tearing down a stream with no contexts did something");
    }
    stream.attach(&[1, 2, 3])?;
    // The first callback, for context 3, attaches context 4.
    ATTACH_LATE.store(4, Ordering::Release);
    let (freed, order) = stream.teardown();
    total += freed;
    if freed != 4 {
        return Err("not every context's FreeCallback was called once");
    }
    if order != 0x3421 {
        return Err("the contexts were not freed newest first, one attached meanwhile next");
    }
    if !stream.at_rest() {
        return Err("the list or its lock is not as an empty stream's afterwards");
    }

    // A header that says it has no contexts is not read, whatever its
    // list holds; with the flags back, the context is torn down.
    stream.attach(&[5])?;
    for (flags, flags2) in [
        (FSRTL_FLAG_ADVANCED_HEADER, 0),
        (0, FSRTL_FLAG2_SUPPORTS_FILTER_CONTEXTS),
    ] {
        // SAFETY: the stream's own header.
        unsafe {
            (*stream.header).Common.Flags = flags;
            (*stream.header).Common.Flags2 = flags2;
        }
        if stream.teardown() != (0, 0) {
            return Err("a header that denies having contexts had them torn down");
        }
    }
    // SAFETY: the stream's own header.
    unsafe {
        (*stream.header).Common.Flags = FSRTL_FLAG_ADVANCED_HEADER;
        (*stream.header).Common.Flags2 = FSRTL_FLAG2_SUPPORTS_FILTER_CONTEXTS;
    }
    let (freed, order) = stream.teardown();
    total += freed;
    if (freed, order) != (1, 5) || !stream.at_rest() {
        return Err("the context of a header that says it has contexts was not torn down");
    }
    drop(stream);

    // An old header: no push lock, the file system's fast mutex guards
    // the list.
    let old = Stream::new(FSRTL_FCB_HEADER_V0)?;
    old.attach(&[6, 7])?;
    let (freed, order) = old.teardown();
    total += freed;
    if (freed, order) != (2, 0x76) || !old.at_rest() {
        return Err("a version 0 header's contexts were not torn down under its fast mutex");
    }
    drop(old);

    let wrong = WRONG.load(Ordering::Acquire);
    if wrong & STILL_LINKED != 0 {
        return Err("a FreeCallback found its context still on the list");
    }
    if wrong & LOCK_HELD != 0 {
        return Err("a FreeCallback could not take the header's lock");
    }
    if wrong & IN_CRITICAL_REGION != 0 {
        return Err("a FreeCallback ran inside the routine's critical region");
    }
    if wrong & NO_MEMORY != 0 {
        return Err("no memory for a context attached during the teardown");
    }
    if u32::from(crate::ke::mutex::KeAreApcsDisabled()) != apcs_disabled {
        return Err("the routine did not leave the critical region it entered");
    }
    Ok(total)
}

pub static DRIVER_PAGING: Group = Group {
    names: &["mm.driver-paging"],
    run: |r, _| r.check(DRIVER_PAGING.names[0], driver_paging),
    manual: false,
};

/// Stands for the routine in its own image whose address `msfs.sys`
/// passes to both paging routines.
#[inline(never)]
extern "C" fn paged_routine(value: u32) -> u32 {
    core::hint::black_box(value).rotate_left(7) ^ 0x4E4B
}

/// `MmPageEntireDriver` and `MmResetDriverPaging`, called as `msfs.sys`
/// calls them: with the address of a routine of its own image; the
/// first at initialisation and whenever its last file closes, the
/// second when its count of open files goes from none to one, after
/// which it runs code that may not fault. The image here is the
/// kernel's own, which is in the table of images like a driver's.
/// Checked: the first names the image's base; after the second the
/// image's code is as it was and can be read and run at
/// `DISPATCH_LEVEL`, where a page that had to be brought in would stop
/// the system; the pair can be repeated, as files open and close; and
/// an address in no image is taken by both, the first answering null,
/// with the table of images unchanged.
fn driver_paging() -> Result<(), &'static str> {
    use crate::ke::{irql, kspin};
    use crate::ldr;
    let routine = paged_routine as *const () as *mut c_void;
    let image = ldr::module_containing(routine as u64).ok_or("the routine is in no image")?;
    let images = ldr::modules().map(|list| list.len());
    // What the routine's code is, and what it computes, read at
    // `DISPATCH_LEVEL`.
    let at_dispatch = || {
        let old = kspin::KfRaiseIrql(irql::DISPATCH_LEVEL);
        // SAFETY: sixteen bytes of this image's code, and the start of
        // its headers.
        let facts = unsafe {
            (
                routine.cast::<[u8; 16]>().read_volatile(),
                (image.base as *const u16).read_volatile(),
                paged_routine(0x1234_5678),
            )
        };
        kspin::KeLowerIrql(old);
        facts
    };
    let before = at_dispatch();
    for _ in 0..3 {
        // SAFETY: both take any address.
        let base = unsafe { ldr::MmPageEntireDriver(routine) };
        if base as u64 != image.base {
            return Err("MmPageEntireDriver did not answer the image's base");
        }
        // SAFETY: as above.
        unsafe { ldr::MmResetDriverPaging(routine) };
        if at_dispatch() != before {
            return Err("after MmResetDriverPaging the image's code is not what it was");
        }
    }
    // Not in any image: memory from the pool, and no address at all.
    let block = pool::alloc(64, TAG);
    if block.is_null() {
        return Err("no memory");
    }
    for nowhere in [block.cast::<c_void>(), core::ptr::null_mut()] {
        // SAFETY: both take any address.
        unsafe {
            if !ldr::MmPageEntireDriver(nowhere).is_null() {
                let _ = pool::free(block);
                return Err("an address in no image has an image's base");
            }
            ldr::MmResetDriverPaging(nowhere);
        }
    }
    let _ = pool::free(block);
    if ldr::modules().map(|list| list.len()) != images || at_dispatch() != before {
        return Err("the paging routines changed the images");
    }
    Ok(())
}

/// A stream whose list of contexts does not link back must stop the
/// system, as the pinned kernel's check of the links does (a fast
/// fail), before anything is unlinked through it.
pub static BROKEN_LIST: Group = Group {
    names: &["neg.stream-context-list"],
    run: broken_list,
    manual: true,
};

fn broken_list(r: &mut Report, _: &BootInfo) {
    let name = BROKEN_LIST.names[0];
    let stream = match Stream::new(FSRTL_FCB_HEADER_V3) {
        Ok(stream) => stream,
        Err(why) => return r.fail(name, format_args!("{why}")),
    };
    if let Err(why) = stream.attach(&[1, 2]) {
        return r.fail(name, format_args!("{why}"));
    }
    // SAFETY: the stream's own list: the second context no longer
    // points back at the first.
    unsafe {
        let first = (*stream.header).FilterContexts.Flink;
        (*(*first).Flink).Blink = &raw mut (*stream.header).FilterContexts;
    }
    kprintln!("NK-NEG-ARMED {name}");
    let (freed, _) = stream.teardown();
    r.fail(
        name,
        format_args!("a broken list was torn down: {freed} contexts freed"),
    );
}
