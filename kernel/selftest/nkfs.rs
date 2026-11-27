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
use core::ffi::c_void;
use core::sync::atomic::{AtomicPtr, AtomicU32, AtomicU64, AtomicUsize, Ordering};
use nk_ntabi::ex::ERESOURCE;
use nk_ntabi::fsrtl::FSRTL_ADVANCED_FCB_HEADER;
use nk_ntabi::io::*;
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

/// The file's bytes as nkfs holds them.
pub fn data() -> &'static [u8] {
    // SAFETY: the buffer lives while the volume does, which outlives
    // every test that asks.
    unsafe { core::slice::from_raw_parts(DATA.load(Ordering::Acquire), FILE_BYTES) }
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
                let fcb = FCB.load(Ordering::Acquire);
                (*file).FsContext = fcb.cast();
                (*file).SectionObjectPointer = (&raw mut (*fcb).sop).cast();
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
