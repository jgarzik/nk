//! nkfs: a file system for the memory manager's tests, and nothing
//! else. One device, `\Device\NkFs`; opening it opens its one file, 3
//! MiB held in pool, with an `FSRTL_ADVANCED_FCB_HEADER` and section
//! object pointers as a real file system's file has. Its read and write
//! routines serve paging and non-cached requests from the pool buffer
//! through the request's MDL, record each paging request (major
//! function, flags, offset, length, top-level IRP, and whether the
//! thread's paging I/O was the cache manager's), and fail a read at an
//! offset a test names with a device data error.
//!
//! Test scaffolding for the file-system phase: it goes when Microsoft's
//! FAT driver runs over NK's cache manager.

use crate::io::file::{self, OpenRequest};
use crate::io::{device, irp, mdl};
use crate::mm::pool;
use crate::ob::{handle, object};
use core::cell::UnsafeCell;
use core::ffi::c_void;
use core::mem::MaybeUninit;
use core::sync::atomic::{AtomicI32, AtomicPtr, AtomicU32, AtomicU64, AtomicUsize, Ordering};
use nk_ntabi::ex::ERESOURCE;
use nk_ntabi::fsrtl::FSRTL_ADVANCED_FCB_HEADER;
use nk_ntabi::io::*;
use nk_ntabi::ke::KEVENT;
use nk_ntabi::status::*;
use nk_ntabi::thread::CACHE_MANAGER_ACTIVE;

const TAG: u32 = u32::from_le_bytes(*b"NkFs");
const DEVICE: &str = "\\Device\\NkFs";
/// The file's size.
pub const FILE_BYTES: usize = 3 << 20;
/// `ETHREAD.TopLevelIrp`.
const TOP_LEVEL_IRP: usize = 0x4C0;

/// What a file system keeps per file: the header the memory and cache
/// managers read, and the section object pointers.
#[repr(C)]
pub struct Fcb {
    pub header: FSRTL_ADVANCED_FCB_HEADER,
    pub sop: SECTION_OBJECT_POINTERS,
    /// The header's main and paging resources.
    pub resource: ERESOURCE,
    pub paging_io_resource: ERESOURCE,
}

/// What byte `offset` of the file holds before anything is written.
pub fn pattern(offset: usize) -> u8 {
    ((offset >> 12) as u8) ^ (offset as u8) ^ 0x5A
}

/// One paging request as the file system saw it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Record {
    pub major: u8,
    pub flags: u32,
    pub offset: u64,
    pub length: u32,
    pub top_level: usize,
    pub cache_manager_active: bool,
}

const LOG_ROOM: usize = 64;
static LOG: [[AtomicU64; 4]; LOG_ROOM] = [const { [const { AtomicU64::new(0) }; 4] }; LOG_ROOM];
static LOGGED: AtomicUsize = AtomicUsize::new(0);
/// A read at this offset plus one fails; 0 for none.
static FAIL_AT: AtomicU64 = AtomicU64::new(0);
/// Optional write-pause hook for deterministic in-flight flush tests:
/// when `PAUSE_WRITE_AT == offset + 1`, the paging write signals
/// `PAUSE_EVENTS.paused` and waits on `PAUSE_EVENTS.release` (blocking
/// cleanly so priority-13 workers never starve priority-8 test threads
/// on 1-CPU boots), then completes with `WRITE_STATUS`.
struct PauseEvents {
    paused: UnsafeCell<MaybeUninit<KEVENT>>,
    release: UnsafeCell<MaybeUninit<KEVENT>>,
}

// SAFETY: initialised by `arm_write_pause` before any worker can match
// `PAUSE_WRITE_AT`, then accessed only through kernel event routines.
unsafe impl Sync for PauseEvents {}

static PAUSE_EVENTS: PauseEvents = PauseEvents {
    paused: UnsafeCell::new(MaybeUninit::uninit()),
    release: UnsafeCell::new(MaybeUninit::uninit()),
};
static PAUSE_WRITE_AT: AtomicU64 = AtomicU64::new(0);
static WRITE_STATUS: AtomicI32 = AtomicI32::new(STATUS_SUCCESS);
/// Persistent write-failure injection for error-handling tests: fails
/// every paging write while non-zero.
static FAIL_WRITE_STATUS: AtomicI32 = AtomicI32::new(STATUS_SUCCESS);
static DATA: AtomicPtr<u8> = AtomicPtr::new(core::ptr::null_mut());
static FCB: AtomicPtr<Fcb> = AtomicPtr::new(core::ptr::null_mut());
/// At the last paging write: bit 0, the writing thread held the main
/// resource exclusive; bit 1, the paging resource shared.
static HELD_AT_WRITE: AtomicU32 = AtomicU32::new(0);

/// What the writing thread held at the last paging write, as
/// (main resource exclusive, paging resource shared).
pub fn held_at_write() -> (bool, bool) {
    let held = HELD_AT_WRITE.swap(0, Ordering::AcqRel);
    (held & 1 != 0, held & 2 != 0)
}

/// The paging requests recorded since the last call, oldest first.
pub fn take_log() -> alloc::vec::Vec<Record> {
    let n = LOGGED.swap(0, Ordering::AcqRel).min(LOG_ROOM);
    (0..n)
        .map(|i| {
            let [w0, w1, w2, w3] = LOG[i].each_ref().map(|w| w.load(Ordering::Acquire));
            Record {
                major: w0 as u8,
                cache_manager_active: (w0 >> 8) as u8 == 1,
                flags: (w0 >> 32) as u32,
                offset: w1,
                length: w2 as u32,
                top_level: w3 as usize,
            }
        })
        .collect()
}

/// Have the read that starts at `offset` fail (`None`: none).
pub fn fail_read_at(offset: Option<u64>) {
    FAIL_AT.store(offset.map_or(0, |o| o + 1), Ordering::Release);
}

/// Arm a one-shot pause on the next paging write starting at `offset`.
pub fn arm_write_pause(offset: u64) {
    // SAFETY: static notification events initialised before arming
    // `PAUSE_WRITE_AT`.
    unsafe {
        crate::ke::wait::KeInitializeEvent(PAUSE_EVENTS.paused.get().cast(), 0, 0);
        crate::ke::wait::KeInitializeEvent(PAUSE_EVENTS.release.get().cast(), 0, 0);
    }
    WRITE_STATUS.store(STATUS_SUCCESS, Ordering::Release);
    PAUSE_WRITE_AT.store(offset + 1, Ordering::Release);
}

/// Wait until the armed paging write has entered `nkfs::transfer`.
pub fn wait_write_paused() {
    // SAFETY: initialised by `arm_write_pause`.
    unsafe {
        crate::ke::wait::wait(Some(PAUSE_EVENTS.paused.get().cast()), None);
    }
}

/// Release the paused paging write with `status`.
pub fn release_write_pause(status: NTSTATUS) {
    PAUSE_WRITE_AT.store(0, Ordering::Release);
    WRITE_STATUS.store(status, Ordering::Release);
    // SAFETY: initialised by `arm_write_pause`.
    unsafe {
        crate::ke::wait::KeSetEvent(PAUSE_EVENTS.release.get().cast(), 0, 0);
    }
}

/// Fail every subsequent paging write with `status` (`STATUS_SUCCESS`
/// clears injection).
pub fn fail_writes_with(status: NTSTATUS) {
    FAIL_WRITE_STATUS.store(status, Ordering::Release);
}

/// The file's bytes as nkfs holds them.
pub fn data() -> &'static [u8] {
    // SAFETY: the buffer lives while the volume does, which outlives
    // every test that asks.
    unsafe { core::slice::from_raw_parts(DATA.load(Ordering::Acquire), FILE_BYTES) }
}

/// Extra per-file FCB for multi-map cache tests (`cc.shutdown-drain`,
/// `cc.wait-lazy-barrier`), sharing `\Device\NkFs` with its own small
/// backing buffer and per-file paging write fault injection.
#[repr(C)]
pub struct ExtraFcb {
    pub fcb: Fcb,
    pub data: *mut u8,
    pub len: usize,
    /// Number of matching paging writes to fail (`u32::MAX` = persistent).
    pub fail_count: AtomicU32,
    pub fail_status: AtomicI32,
    /// Fail paging writes whose `offset >= fail_from_offset`.
    pub fail_from_offset: AtomicU64,
    /// Total paging write attempts reaching `transfer` for this file.
    pub write_attempts: AtomicU32,
    /// Paging write attempts at `offset >= fail_from_offset`.
    pub failed_range_attempts: AtomicU32,
    /// Successful paging writes completed for this file.
    pub write_successes: AtomicU32,
}

/// While non-null during `IRP_MJ_CREATE`, attach this `ExtraFcb` instead
/// of the default single `FCB`.
static EXTRA_CREATE_FCB: AtomicPtr<ExtraFcb> = AtomicPtr::new(core::ptr::null_mut());

/// Owned handle, file object, `ExtraFcb` and backing buffer for one
/// independent cached file on `\Device\NkFs`.
pub struct ExtraFile {
    fcb: *mut ExtraFcb,
    handle: u64,
    pub file: *mut FILE_OBJECT,
}

impl ExtraFile {
    pub fn sop(&self) -> *mut SECTION_OBJECT_POINTERS {
        // SAFETY: `self.fcb` is live for the lifetime of `ExtraFile`.
        unsafe { &raw mut (*self.fcb).fcb.sop }
    }

    pub fn data(&self) -> &[u8] {
        // SAFETY: `data` is live for `len` bytes until `Drop`.
        unsafe { core::slice::from_raw_parts((*self.fcb).data, (*self.fcb).len) }
    }

    /// Configure paging write failure injection on this file.
    /// `count == u32::MAX` fails persistently; `count == 0` disables.
    pub fn set_write_fail(&self, count: u32, status: NTSTATUS, from_offset: u64) {
        // SAFETY: `self.fcb` is live.
        unsafe {
            (*self.fcb)
                .fail_from_offset
                .store(from_offset, Ordering::Release);
            (*self.fcb).fail_status.store(status, Ordering::Release);
            (*self.fcb).fail_count.store(count, Ordering::Release);
        }
    }

    pub fn write_attempts(&self) -> u32 {
        // SAFETY: `self.fcb` is live.
        unsafe { (*self.fcb).write_attempts.load(Ordering::Acquire) }
    }

    pub fn failed_range_attempts(&self) -> u32 {
        // SAFETY: `self.fcb` is live.
        unsafe { (*self.fcb).failed_range_attempts.load(Ordering::Acquire) }
    }

    pub fn write_successes(&self) -> u32 {
        // SAFETY: `self.fcb` is live.
        unsafe { (*self.fcb).write_successes.load(Ordering::Acquire) }
    }
}

impl Drop for ExtraFile {
    fn drop(&mut self) {
        if !self.file.is_null() {
            // SAFETY: the reference `open_extra_file` took.
            unsafe { object::dereference(self.file.cast()) };
        }
        if self.handle != 0 {
            file::close(self.handle);
        }
        if !self.fcb.is_null() {
            // SAFETY: `self.fcb` and its data buffer belong exclusively to
            // this `ExtraFile` once closed and uninitialized.
            unsafe {
                crate::ex::resource::ExDeleteResourceLite(&raw mut (*self.fcb).fcb.resource);
                crate::ex::resource::ExDeleteResourceLite(
                    &raw mut (*self.fcb).fcb.paging_io_resource,
                );
                let data = (*self.fcb).data;
                if !data.is_null() {
                    let _ = pool::free(data);
                }
            }
            let _ = pool::free(self.fcb.cast());
        }
    }
}

/// The dispatch routine.
///
/// # Safety
/// Called as a dispatch routine.
unsafe extern "C" fn dispatch(_: *mut DEVICE_OBJECT, irp: *mut IRP) -> NTSTATUS {
    // SAFETY: a live IRP being dispatched to this driver.
    unsafe {
        let location = (*irp).CurrentStackLocation;
        let file = (*location).FileObject;
        let (status, information) = match (*location).MajorFunction {
            IRP_MJ_CREATE => {
                let extra = EXTRA_CREATE_FCB.swap(core::ptr::null_mut(), Ordering::AcqRel);
                if !extra.is_null() {
                    let fcb = &raw mut (*extra).fcb;
                    (*file).FsContext = fcb.cast();
                    (*file).SectionObjectPointer = (&raw mut (*fcb).sop).cast();
                } else {
                    let fcb = FCB.load(Ordering::Acquire);
                    (*file).FsContext = fcb.cast();
                    (*file).SectionObjectPointer = (&raw mut (*fcb).sop).cast();
                }
                (STATUS_SUCCESS, FILE_OPENED)
            }
            IRP_MJ_READ | IRP_MJ_WRITE => transfer(irp, location),
            _ => (STATUS_SUCCESS, 0),
        };
        (*irp).IoStatus.Status = status;
        (*irp).IoStatus.Information = information;
        irp::IofCompleteRequest(irp, 0);
        status
    }
}

/// `FILE_OPENED`.
const FILE_OPENED: usize = 1;

/// A read or write, served from the buffer through the request's MDL.
///
/// # Safety
/// A live read or write request and its current location.
unsafe fn transfer(irp: *mut IRP, location: *mut IO_STACK_LOCATION) -> (NTSTATUS, usize) {
    // SAFETY: per the contract.
    unsafe {
        let major = (*location).MajorFunction;
        let length = (*location).Parameters[0] as u32;
        let offset = (*location).Parameters[2];
        let flags = (*irp).Flags;
        let file_obj = (*location).FileObject;
        let main_fcb = FCB.load(Ordering::Acquire);
        if !file_obj.is_null() && (*file_obj).FsContext != main_fcb.cast() {
            return transfer_extra(
                irp,
                major,
                length,
                offset,
                flags,
                (*file_obj).FsContext.cast(),
            );
        }
        if flags & IRP_PAGING_IO != 0 {
            let thread = crate::ke::pcr::current_thread();
            let active = thread.add(CACHE_MANAGER_ACTIVE).read();
            let top = thread.add(TOP_LEVEL_IRP).cast::<usize>().read();
            let at = LOGGED.fetch_add(1, Ordering::AcqRel);
            if at < LOG_ROOM {
                let words = [
                    u64::from(major) | u64::from(active) << 8 | u64::from(flags) << 32,
                    offset,
                    u64::from(length),
                    top as u64,
                ];
                for (slot, word) in LOG[at].iter().zip(words) {
                    slot.store(word, Ordering::Release);
                }
            }
        }
        if major == IRP_MJ_WRITE && flags & IRP_PAGING_IO != 0 {
            let fcb = FCB.load(Ordering::Acquire);
            let held = u32::from(
                crate::ex::resource::ExIsResourceAcquiredExclusiveLite(&raw mut (*fcb).resource)
                    != 0,
            ) | u32::from(
                crate::ex::resource::ExIsResourceAcquiredSharedLite(
                    &raw mut (*fcb).paging_io_resource,
                ) != 0,
            ) << 1;
            HELD_AT_WRITE.store(held, Ordering::Release);
        }
        if major == IRP_MJ_READ && FAIL_AT.load(Ordering::Acquire) == offset + 1 {
            return (STATUS_DEVICE_DATA_ERROR, 0);
        }
        if major == IRP_MJ_WRITE && flags & IRP_PAGING_IO != 0 {
            if PAUSE_WRITE_AT.load(Ordering::Acquire) == offset + 1 {
                crate::ke::wait::KeSetEvent(PAUSE_EVENTS.paused.get().cast(), 0, 0);
                crate::ke::wait::wait(Some(PAUSE_EVENTS.release.get().cast()), None);
                let st = WRITE_STATUS.load(Ordering::Acquire);
                if nt_error(st) {
                    return (st, 0);
                }
            }
            let injected = FAIL_WRITE_STATUS.load(Ordering::Acquire);
            if nt_error(injected) {
                return (injected, 0);
            }
        }
        if flags & IRP_NOCACHE == 0 || offset as usize >= FILE_BYTES {
            return (STATUS_INVALID_DEVICE_REQUEST, 0);
        }
        let count = (length as usize).min(FILE_BYTES - offset as usize);
        let system = mdl::MmMapLockedPagesSpecifyCache(
            (*irp).MdlAddress,
            KERNEL_MODE,
            1,
            core::ptr::null_mut(),
            0,
            16,
        );
        if system.is_null() {
            return (STATUS_INSUFFICIENT_RESOURCES, 0);
        }
        let file = DATA.load(Ordering::Acquire).add(offset as usize);
        if major == IRP_MJ_READ {
            core::ptr::copy_nonoverlapping(file, system.cast::<u8>(), count);
        } else {
            core::ptr::copy_nonoverlapping(system.cast::<u8>(), file, count);
        }
        (STATUS_SUCCESS, count)
    }
}

/// Serve a read or write on an [`ExtraFile`].
///
/// # Safety
/// Live IRP and live `ExtraFcb`.
unsafe fn transfer_extra(
    irp: *mut IRP,
    major: u8,
    length: u32,
    offset: u64,
    flags: u32,
    extra: *mut ExtraFcb,
) -> (NTSTATUS, usize) {
    // SAFETY: per the contract.
    unsafe {
        if major == IRP_MJ_WRITE && flags & IRP_PAGING_IO != 0 {
            (*extra).write_attempts.fetch_add(1, Ordering::AcqRel);
            let fail_from = (*extra).fail_from_offset.load(Ordering::Acquire);
            if offset >= fail_from {
                let fail_st = (*extra).fail_status.load(Ordering::Acquire);
                let mut prev = (*extra).fail_count.load(Ordering::Acquire);
                let mut should_fail = false;
                while prev > 0 {
                    if prev == u32::MAX {
                        should_fail = true;
                        break;
                    }
                    match (*extra).fail_count.compare_exchange_weak(
                        prev,
                        prev - 1,
                        Ordering::AcqRel,
                        Ordering::Acquire,
                    ) {
                        Ok(_) => {
                            should_fail = true;
                            break;
                        }
                        Err(actual) => prev = actual,
                    }
                }
                if should_fail && nt_error(fail_st) {
                    (*extra)
                        .failed_range_attempts
                        .fetch_add(1, Ordering::AcqRel);
                    return (fail_st, 0);
                }
            }
        }
        let len = (*extra).len;
        if flags & IRP_NOCACHE == 0 || offset as usize >= len {
            return (STATUS_INVALID_DEVICE_REQUEST, 0);
        }
        let count = (length as usize).min(len - offset as usize);
        let system = mdl::MmMapLockedPagesSpecifyCache(
            (*irp).MdlAddress,
            KERNEL_MODE,
            1,
            core::ptr::null_mut(),
            0,
            16,
        );
        if system.is_null() {
            return (STATUS_INSUFFICIENT_RESOURCES, 0);
        }
        let buf = (*extra).data.add(offset as usize);
        if major == IRP_MJ_READ {
            core::ptr::copy_nonoverlapping(buf, system.cast::<u8>(), count);
        } else {
            core::ptr::copy_nonoverlapping(system.cast::<u8>(), buf, count);
            if flags & IRP_PAGING_IO != 0 {
                (*extra).write_successes.fetch_add(1, Ordering::AcqRel);
            }
        }
        (STATUS_SUCCESS, count)
    }
}

/// The volume: its driver, device and file, while a test runs.
pub struct Volume {
    driver: *mut DRIVER_OBJECT,
    device: *mut DEVICE_OBJECT,
    handle: u64,
    pub file: *mut FILE_OBJECT,
}

impl Volume {
    /// Make the driver, the device and the file (contents
    /// [`pattern`]), and open it.
    pub fn new() -> Result<Self, &'static str> {
        let data = pool::alloc(FILE_BYTES, TAG);
        let fcb = pool::alloc_zeroed(size_of::<Fcb>(), TAG).cast::<Fcb>();
        let size = size_of::<DRIVER_OBJECT>() + size_of::<DRIVER_EXTENSION>();
        let driver = pool::alloc_zeroed(size, TAG).cast::<DRIVER_OBJECT>();
        if data.is_null() || fcb.is_null() || driver.is_null() {
            for block in [data, fcb.cast(), driver.cast()]
                .into_iter()
                .filter(|b| !b.is_null())
            {
                let _ = pool::free(block);
            }
            return Err("no memory for nkfs");
        }
        // SAFETY: the blocks just allocated, ours alone.
        unsafe {
            for i in 0..FILE_BYTES {
                data.add(i).write(pattern(i));
            }
            let header = &raw mut (*fcb).header.Common;
            (*header).NodeByteSize = size_of::<Fcb>() as i16;
            (*header).AllocationSize = FILE_BYTES as i64;
            (*header).FileSize = FILE_BYTES as i64;
            (*header).ValidDataLength = FILE_BYTES as i64;
            crate::ex::resource::ExInitializeResourceLite(&raw mut (*fcb).resource);
            crate::ex::resource::ExInitializeResourceLite(&raw mut (*fcb).paging_io_resource);
            (*header).Resource = &raw mut (*fcb).resource;
            (*header).PagingIoResource = &raw mut (*fcb).paging_io_resource;
        }
        DATA.store(data, Ordering::Release);
        FCB.store(fcb, Ordering::Release);
        let mut name: alloc::vec::Vec<u16> = DEVICE.encode_utf16().collect();
        let name = UNICODE_STRING {
            Length: (name.len() * 2) as u16,
            MaximumLength: (name.len() * 2) as u16,
            Buffer: name.as_mut_ptr(),
        };
        let mut device_object = core::ptr::null_mut();
        // SAFETY: the test's own driver object, set up as `driver::load`
        // sets one up.
        unsafe {
            (*driver).DriverExtension = driver.add(1).cast();
            (*(*driver).DriverExtension).DriverObject = driver;
            (*driver).MajorFunction =
                [Some(irp::invalid_device_request); IRP_MJ_MAXIMUM_FUNCTION + 1];
            for major in [
                IRP_MJ_CREATE,
                IRP_MJ_CLEANUP,
                IRP_MJ_CLOSE,
                IRP_MJ_READ,
                IRP_MJ_WRITE,
            ] {
                (*driver).MajorFunction[usize::from(major)] = Some(dispatch);
            }
            if device::IoCreateDevice(
                driver,
                0,
                &raw const name,
                0x8,
                0,
                0,
                &raw mut device_object,
            ) != 0
            {
                let _ = pool::free(driver.cast());
                return Err("could not create the nkfs device");
            }
            (*device_object).Flags &= !DO_DEVICE_INITIALIZING;
        }
        let mut volume = Self {
            driver,
            device: device_object,
            handle: 0,
            file: core::ptr::null_mut(),
        };
        volume.handle = file::open(&OpenRequest::new(DEVICE))
            .map_err(|_| "the nkfs file did not open")?
            .0;
        let mut object: *mut c_void = core::ptr::null_mut();
        // SAFETY: a kernel handle just opened; the reference taken is
        // the volume's until it is dropped.
        let status = unsafe {
            handle::ObReferenceObjectByHandle(
                volume.handle as *mut c_void,
                0,
                core::ptr::null(),
                KERNEL_MODE,
                &raw mut object,
                core::ptr::null_mut(),
            )
        };
        if status != STATUS_SUCCESS {
            return Err("the nkfs file's handle names no object");
        }
        volume.file = object.cast();
        take_log();
        fail_read_at(None);
        Ok(volume)
    }

    /// Open the file again: another file object for the same file, its
    /// handle and a reference, for the caller to give up with
    /// [`close_another`].
    pub fn open_another(&self) -> Result<(u64, *mut FILE_OBJECT), &'static str> {
        let handle = file::open(&OpenRequest::new(DEVICE))
            .map_err(|_| "the nkfs file did not open again")?
            .0;
        let mut object: *mut c_void = core::ptr::null_mut();
        // SAFETY: a kernel handle just opened.
        let status = unsafe {
            handle::ObReferenceObjectByHandle(
                handle as *mut c_void,
                0,
                core::ptr::null(),
                KERNEL_MODE,
                &raw mut object,
                core::ptr::null_mut(),
            )
        };
        if status != STATUS_SUCCESS {
            file::close(handle);
            return Err("the nkfs file's second handle names no object");
        }
        Ok((handle, object.cast()))
    }

    /// Open a separate independent file backed by its own `ExtraFcb` and
    /// `size`-byte pool buffer.
    pub fn open_extra_file(&self, size: usize) -> Result<ExtraFile, &'static str> {
        let data = pool::alloc_zeroed(size, TAG);
        let extra = pool::alloc_zeroed(size_of::<ExtraFcb>(), TAG).cast::<ExtraFcb>();
        if data.is_null() || extra.is_null() {
            if !data.is_null() {
                let _ = pool::free(data);
            }
            if !extra.is_null() {
                let _ = pool::free(extra.cast());
            }
            return Err("no memory for nkfs extra file");
        }
        // SAFETY: freshly allocated blocks owned exclusively here.
        unsafe {
            let header = &raw mut (*extra).fcb.header.Common;
            (*header).NodeByteSize = size_of::<Fcb>() as i16;
            (*header).AllocationSize = size as i64;
            (*header).FileSize = size as i64;
            (*header).ValidDataLength = size as i64;
            crate::ex::resource::ExInitializeResourceLite(&raw mut (*extra).fcb.resource);
            crate::ex::resource::ExInitializeResourceLite(&raw mut (*extra).fcb.paging_io_resource);
            (*header).Resource = &raw mut (*extra).fcb.resource;
            (*header).PagingIoResource = &raw mut (*extra).fcb.paging_io_resource;
            (*extra).data = data;
            (*extra).len = size;
        }
        EXTRA_CREATE_FCB.store(extra, Ordering::Release);
        let open_res = file::open(&OpenRequest::new(DEVICE));
        let leftover = EXTRA_CREATE_FCB.swap(core::ptr::null_mut(), Ordering::AcqRel);
        let Ok((handle, _)) = open_res else {
            if !leftover.is_null() {
                // SAFETY: never attached to any file object.
                unsafe {
                    crate::ex::resource::ExDeleteResourceLite(&raw mut (*extra).fcb.resource);
                    crate::ex::resource::ExDeleteResourceLite(
                        &raw mut (*extra).fcb.paging_io_resource,
                    );
                }
                let _ = pool::free(data);
                let _ = pool::free(extra.cast());
            }
            return Err("extra nkfs file did not open");
        };
        let mut object: *mut c_void = core::ptr::null_mut();
        // SAFETY: kernel handle just opened.
        let status = unsafe {
            handle::ObReferenceObjectByHandle(
                handle as *mut c_void,
                0,
                core::ptr::null(),
                KERNEL_MODE,
                &raw mut object,
                core::ptr::null_mut(),
            )
        };
        if status != STATUS_SUCCESS {
            file::close(handle);
            // SAFETY: handle closed; nothing else references `extra`.
            unsafe {
                crate::ex::resource::ExDeleteResourceLite(&raw mut (*extra).fcb.resource);
                crate::ex::resource::ExDeleteResourceLite(&raw mut (*extra).fcb.paging_io_resource);
            }
            let _ = pool::free(data);
            let _ = pool::free(extra.cast());
            return Err("extra nkfs handle names no object");
        }
        Ok(ExtraFile {
            fcb: extra,
            handle,
            file: object.cast(),
        })
    }

    /// The file's FCB.
    pub fn fcb(&self) -> *mut Fcb {
        FCB.load(Ordering::Acquire)
    }

    /// Give the driver a fast-I/O dispatch table.
    pub fn set_fast_io(&self, table: *mut FAST_IO_DISPATCH) {
        // SAFETY: the test's own driver object.
        unsafe { (*self.driver).FastIoDispatch = table.cast() };
    }

    /// The file's section object pointers.
    pub fn sop(&self) -> *mut SECTION_OBJECT_POINTERS {
        // SAFETY: the file is open; nkfs set the pointer at create.
        unsafe { (*self.file).SectionObjectPointer.cast() }
    }
}

/// Give up what [`Volume::open_another`] gave.
pub fn close_another(handle: u64, file: *mut FILE_OBJECT) {
    // SAFETY: the reference `open_another` took.
    unsafe { object::dereference(file.cast()) };
    file::close(handle);
}

impl Drop for Volume {
    fn drop(&mut self) {
        if !self.file.is_null() {
            // SAFETY: the reference `new` took.
            unsafe { object::dereference(self.file.cast()) };
        }
        if self.handle != 0 {
            file::close(self.handle);
        }
        // SAFETY: the device and driver `new` made; no file is open on
        // the device any more (a section's reference to the file was
        // dropped by the test, which checks it).
        unsafe { device::IoDeleteDevice(self.device) };
        let fcb = FCB.load(Ordering::Acquire);
        // SAFETY: the FCB's resources, initialised by `new`, held by
        // nobody now.
        unsafe {
            crate::ex::resource::ExDeleteResourceLite(&raw mut (*fcb).resource);
            crate::ex::resource::ExDeleteResourceLite(&raw mut (*fcb).paging_io_resource);
        }
        for block in [
            self.driver.cast(),
            FCB.swap(core::ptr::null_mut(), Ordering::AcqRel).cast(),
            DATA.swap(core::ptr::null_mut(), Ordering::AcqRel),
        ] {
            let _ = pool::free(block);
        }
    }
}

// ---- Synthetic large-file device (\Device\NkFsLarge) for low-memory proofs ----

/// Device path for the 80 MiB synthetic tag-verified backing file used by `user.lowmem`.
#[allow(dead_code)]
pub const LARGE_DEVICE: &str = "\\Device\\NkFsLarge";
/// Logical size of `\Device\NkFsLarge` (80 MiB = 20,480 pages), backed by only
/// 80 KiB of per-page tags so a 96 MiB QEMU VM can map views strictly larger than RAM.
#[allow(dead_code)]
pub const LARGE_PAGES: usize = 20 * 1024;
#[allow(dead_code)]
pub const LARGE_BYTES: usize = LARGE_PAGES * crate::mm::PAGE_SIZE;

#[allow(dead_code)]
struct LargeState {
    fcb: Fcb,
    tags: alloc::vec::Vec<AtomicU32>,
    paging_reads: AtomicU64,
    paging_writes: AtomicU64,
    pages_written: AtomicU64,
    corruptions: AtomicU64,
}

#[allow(dead_code)]
static LARGE_STATE: AtomicPtr<LargeState> = AtomicPtr::new(core::ptr::null_mut());

/// Deterministic 64-bit word expected at `word_idx` (`0..512`) of `page_idx` when
/// its tag is `tag`.
#[allow(dead_code)]
#[inline]
pub const fn large_word(page_idx: usize, word_idx: usize, tag: u32) -> u64 {
    ((tag as u64) << 32) | ((page_idx as u64) << 12) | (word_idx as u64)
}

/// Dispatch routine for `\Device\NkFsLarge`.
///
/// # Safety
/// Called by the I/O manager with a live IRP.
#[allow(dead_code)]
unsafe extern "C" fn large_dispatch(_: *mut DEVICE_OBJECT, irp: *mut IRP) -> NTSTATUS {
    // SAFETY: live IRP dispatched to this driver.
    unsafe {
        let location = (*irp).CurrentStackLocation;
        let file = (*location).FileObject;
        let state = LARGE_STATE.load(Ordering::Acquire);
        let (status, information) = if state.is_null() {
            (STATUS_DEVICE_NOT_READY, 0)
        } else {
            match (*location).MajorFunction {
                IRP_MJ_CREATE => {
                    let fcb = &raw mut (*state).fcb;
                    (*file).FsContext = fcb.cast();
                    (*file).SectionObjectPointer = (&raw mut (*fcb).sop).cast();
                    (STATUS_SUCCESS, FILE_OPENED)
                }
                IRP_MJ_QUERY_INFORMATION => {
                    let len = (*location).Parameters[0] as usize;
                    let class = (*location).Parameters[1] as u32;
                    let sys = (*irp).SystemBuffer.cast::<u8>();
                    if class == 5 && !sys.is_null() && len >= 24 {
                        // `FILE_STANDARD_INFORMATION`: AllocationSize, EndOfFile, Links=1, ...
                        core::ptr::write_bytes(sys, 0, 24);
                        sys.cast::<i64>().write_unaligned(LARGE_BYTES as i64);
                        sys.add(8).cast::<i64>().write_unaligned(LARGE_BYTES as i64);
                        sys.add(16).cast::<u32>().write_unaligned(1);
                        (STATUS_SUCCESS, 24)
                    } else {
                        (STATUS_INVALID_INFO_CLASS, 0)
                    }
                }
                IRP_MJ_READ | IRP_MJ_WRITE => {
                    let major = (*location).MajorFunction;
                    let length = (*location).Parameters[0] as usize;
                    let offset = (*location).Parameters[2] as usize;
                    let flags = (*irp).Flags;
                    if (flags & IRP_NOCACHE) == 0
                        || offset >= LARGE_BYTES
                        || !offset.is_multiple_of(crate::mm::PAGE_SIZE)
                    {
                        (STATUS_INVALID_DEVICE_REQUEST, 0)
                    } else {
                        let count = length.min(LARGE_BYTES - offset);
                        let system = mdl::MmMapLockedPagesSpecifyCache(
                            (*irp).MdlAddress,
                            KERNEL_MODE,
                            1,
                            core::ptr::null_mut(),
                            0,
                            16,
                        );
                        if system.is_null() {
                            (STATUS_INSUFFICIENT_RESOURCES, 0)
                        } else {
                            let st = &*state;
                            let npages = count / crate::mm::PAGE_SIZE;
                            let first_page = offset / crate::mm::PAGE_SIZE;
                            if major == IRP_MJ_READ {
                                st.paging_reads.fetch_add(1, Ordering::Relaxed);
                                for p in 0..npages {
                                    let page_idx = first_page + p;
                                    let tag = st.tags[page_idx].load(Ordering::Acquire);
                                    let words = system
                                        .cast::<u8>()
                                        .add(p * crate::mm::PAGE_SIZE)
                                        .cast::<u64>();
                                    for w in 0..512 {
                                        words.add(w).write(large_word(page_idx, w, tag));
                                    }
                                }
                            } else {
                                st.paging_writes.fetch_add(1, Ordering::Relaxed);
                                st.pages_written.fetch_add(npages as u64, Ordering::Relaxed);
                                for p in 0..npages {
                                    let page_idx = first_page + p;
                                    let words = system
                                        .cast::<u8>()
                                        .add(p * crate::mm::PAGE_SIZE)
                                        .cast::<u64>();
                                    let w0 = words.read();
                                    let tag = (w0 >> 32) as u32;
                                    let mut ok = true;
                                    for w in 0..512 {
                                        if words.add(w).read() != large_word(page_idx, w, tag) {
                                            ok = false;
                                            break;
                                        }
                                    }
                                    if ok {
                                        st.tags[page_idx].store(tag, Ordering::Release);
                                    } else {
                                        st.corruptions.fetch_add(1, Ordering::Relaxed);
                                    }
                                }
                            }
                            (STATUS_SUCCESS, count)
                        }
                    }
                }
                _ => (STATUS_SUCCESS, 0),
            }
        };
        (*irp).IoStatus.Status = status;
        (*irp).IoStatus.Information = information;
        irp::IofCompleteRequest(irp, 0);
        status
    }
}

/// Owned `\Device\NkFsLarge` synthetic 80 MiB volume for `user.lowmem`.
#[allow(dead_code)]
pub struct LargeVolume {
    driver: *mut DRIVER_OBJECT,
    device: *mut DEVICE_OBJECT,
    state: *mut LargeState,
}

#[allow(dead_code)]
impl LargeVolume {
    /// Mount `\Device\NkFsLarge` (64 MiB logical file, 64 KiB tag store).
    pub fn mount() -> Result<Self, &'static str> {
        let drv_size = size_of::<DRIVER_OBJECT>() + size_of::<DRIVER_EXTENSION>();
        let driver = pool::alloc_zeroed(drv_size, TAG).cast::<DRIVER_OBJECT>();
        if driver.is_null() {
            return Err("no memory for nkfs large driver");
        }
        // SAFETY: fresh zeroed driver object + extension.
        unsafe {
            (*driver).DriverExtension = driver.add(1).cast();
            (*(*driver).DriverExtension).DriverObject = driver;
            (*driver).MajorFunction.fill(Some(large_dispatch));
        }
        let mut tags = alloc::vec::Vec::with_capacity(LARGE_PAGES);
        for _ in 0..LARGE_PAGES {
            tags.push(AtomicU32::new(0));
        }
        // SAFETY: `Fcb` is all-zero valid before resource init.
        let fcb: Fcb = unsafe { core::mem::zeroed() };
        let mut state = alloc::boxed::Box::new(LargeState {
            fcb,
            tags,
            paging_reads: AtomicU64::new(0),
            paging_writes: AtomicU64::new(0),
            pages_written: AtomicU64::new(0),
            corruptions: AtomicU64::new(0),
        });
        // SAFETY: initializing FCB resources in-place inside pinned Box allocation.
        unsafe {
            let header = &raw mut state.fcb.header.Common;
            (*header).NodeByteSize = size_of::<Fcb>() as i16;
            (*header).AllocationSize = LARGE_BYTES as i64;
            (*header).FileSize = LARGE_BYTES as i64;
            (*header).ValidDataLength = LARGE_BYTES as i64;
            crate::ex::resource::ExInitializeResourceLite(&raw mut state.fcb.resource);
            crate::ex::resource::ExInitializeResourceLite(&raw mut state.fcb.paging_io_resource);
            (*header).Resource = &raw mut state.fcb.resource;
            (*header).PagingIoResource = &raw mut state.fcb.paging_io_resource;
        }
        let state_ptr = alloc::boxed::Box::into_raw(state);
        LARGE_STATE.store(state_ptr, Ordering::Release);

        let name: alloc::vec::Vec<u16> = LARGE_DEVICE.encode_utf16().collect();
        let mut name_us = UNICODE_STRING {
            Length: (name.len() * 2) as u16,
            MaximumLength: (name.len() * 2) as u16,
            Buffer: name.as_ptr().cast_mut(),
        };
        let mut dev: *mut DEVICE_OBJECT = core::ptr::null_mut();
        // SAFETY: valid driver object and counted name.
        let st =
            unsafe { device::IoCreateDevice(driver, 0, &raw mut name_us, 8, 0, 0, &raw mut dev) };
        if st != STATUS_SUCCESS || dev.is_null() {
            LARGE_STATE.store(core::ptr::null_mut(), Ordering::Release);
            // SAFETY: reclaiming `state_ptr` on failure.
            unsafe {
                crate::ex::resource::ExDeleteResourceLite(&raw mut (*state_ptr).fcb.resource);
                crate::ex::resource::ExDeleteResourceLite(
                    &raw mut (*state_ptr).fcb.paging_io_resource,
                );
                drop(alloc::boxed::Box::from_raw(state_ptr));
            }
            let _ = pool::free(driver.cast());
            return Err("IoCreateDevice(\\Device\\NkFsLarge) failed");
        }
        // SAFETY: device created above.
        unsafe { (*dev).Flags &= !DO_DEVICE_INITIALIZING };
        Ok(Self {
            driver,
            device: dev,
            state: state_ptr,
        })
    }

    /// Section object pointers for `\Device\NkFsLarge`.
    pub fn sop(&self) -> *mut SECTION_OBJECT_POINTERS {
        // SAFETY: `self.state` is live until `Drop`.
        unsafe { &raw mut (*self.state).fcb.sop }
    }

    /// Return `(paging_reads, paging_writes, pages_written, corruptions)`.
    pub fn stats(&self) -> (u64, u64, u64, u64) {
        // SAFETY: `self.state` is live until `Drop`.
        unsafe {
            let st = &*self.state;
            (
                st.paging_reads.load(Ordering::Acquire),
                st.paging_writes.load(Ordering::Acquire),
                st.pages_written.load(Ordering::Acquire),
                st.corruptions.load(Ordering::Acquire),
            )
        }
    }
}

impl Drop for LargeVolume {
    fn drop(&mut self) {
        LARGE_STATE.store(core::ptr::null_mut(), Ordering::Release);
        // SAFETY: device created by `mount`.
        unsafe { device::IoDeleteDevice(self.device) };
        // SAFETY: `self.state` belongs exclusively to this `LargeVolume`.
        unsafe {
            crate::ex::resource::ExDeleteResourceLite(&raw mut (*self.state).fcb.resource);
            crate::ex::resource::ExDeleteResourceLite(
                &raw mut (*self.state).fcb.paging_io_resource,
            );
            drop(alloc::boxed::Box::from_raw(self.state));
        }
        let _ = pool::free(self.driver.cast());
    }
}
