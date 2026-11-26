//! NK's own test disk: a driver here, in Rust, with a driver object and
//! a dispatch routine, whose one device is a disk kept in pool memory.
//! It is sent requests through the same entry points a real driver's
//! device is, and answers them as Microsoft's `disk.sys` on
//! `classpnp.sys` answers for a disk (`nk_disk::model` has the rules):
//!
//! - the device does direct I/O (`DO_DIRECT_IO`): a read or a write
//!   comes with an MDL over the requestor's buffer, which the dispatch
//!   routine maps;
//! - every request the disk takes is pended and completed from a DPC,
//!   as a disk completes from its interrupt; a request that is the
//!   requestor's mistake is completed in the dispatch routine;
//! - the disk does one transfer at a time, in the order they came.
//!
//! Before any request the disk holds the data disk's original pattern
//! (`doc/TESTING.md`, "The data disk").
//!
//! The disk can be told to go wrong in one of the ways a disk or its
//! driver stack can ([`Fault`]): the proof of disk I/O has to notice
//! each.

use super::stack;
use crate::io::{device, irp, mdl};
use crate::ke::{dpc, irql, kspin};
use crate::mm::pool;
use core::ffi::c_void;
use core::sync::atomic::{AtomicU32, AtomicU64, AtomicUsize, Ordering};
use nk_disk::model::{self, Identity};
use nk_disk::pattern::{self, Mismatch, SECTOR};
use nk_ntabi::disk::{BUS_TYPE_RAM, FILE_DEVICE_DISK};
use nk_ntabi::io::*;
use nk_ntabi::ke::{KDPC, KSPIN_LOCK};
use nk_ntabi::status::*;

pub const NAME: &str = "\\Device\\NkTestDisk";

/// The disk's size: 8 MiB, which has the write range and one whole
/// cylinder of the geometry a disk is given.
pub const SIZE: usize = 8 << 20;

/// What the disk says of itself: a disk in memory, on an adapter that
/// takes a megabyte at a time from a buffer aligned to four bytes.
pub const IDENTITY: Identity<'static> = Identity {
    vendor: "NK",
    product: "TEST DISK",
    revision: "1",
    serial: "NK0001",
    bus_type: BUS_TYPE_RAM,
    device_number: 0x4E4B,
    maximum_transfer_length: 1 << 20,
    maximum_physical_pages: 257,
    alignment_mask: 3,
};

const TAG: u32 = u32::from_le_bytes(*b"NkTD");

/// A way for the disk to go wrong, at the sector [`Fault::at`] names.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum Fault {
    None = 0,
    /// A write that has the sector succeeds without storing it.
    LostWrite,
    /// A write that has the sector stores it in the next sector too.
    StrayWrite,
    /// A read that has the sector gets the next sector's bytes for it.
    WrongSector,
    /// A transfer that has the sector reports one sector less than it
    /// moved.
    ShortCount,
}

static FAULT: AtomicU32 = AtomicU32::new(0);
static FAULT_SECTOR: AtomicU64 = AtomicU64::new(0);

impl Fault {
    /// Have the disk go wrong this way at `sector` from now on.
    pub fn at(self, sector: u64) {
        FAULT_SECTOR.store(sector, Ordering::Release);
        FAULT.store(self as u32, Ordering::Release);
    }

    /// Whether the disk is to go wrong this way in a transfer of the
    /// sectors `[first, end)`; if so, at which sector.
    fn strikes(self, first: u64, end: u64) -> Option<u64> {
        let sector = FAULT_SECTOR.load(Ordering::Acquire);
        (FAULT.load(Ordering::Acquire) == self as u32 && (first..end).contains(&sector))
            .then_some(sector)
    }
}

/// What the driver saw of the last read or write sent to it, for the
/// test of the requestor: how its buffer arrived.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Seen {
    pub major: u8,
    pub offset: i64,
    pub length: u32,
    /// The MDL's `ByteCount` and `ByteOffset`, if the request had an
    /// MDL: the length of the requestor's buffer and where in its
    /// first page it starts.
    pub mdl: Option<(u32, u32)>,
    /// The MDL's pages were locked.
    pub locked: bool,
    /// The request had a system buffer or a user buffer address.
    pub other_buffers: bool,
    pub irql: u8,
}

static SEEN_MAJOR: AtomicU32 = AtomicU32::new(0);
static SEEN_OFFSET: AtomicU64 = AtomicU64::new(0);
static SEEN_LENGTH: AtomicU32 = AtomicU32::new(0);
/// Bit 32: there was an MDL; bit 33: locked; bit 34: other buffers;
/// the low half the MDL's byte count.
static SEEN_MDL: AtomicU64 = AtomicU64::new(0);
static SEEN_MDL_OFFSET: AtomicU32 = AtomicU32::new(0);
static SEEN_IRQL: AtomicU32 = AtomicU32::new(0);
/// Requests of each kind the driver was sent: transfers, flushes,
/// control requests.
static TRANSFERS: AtomicUsize = AtomicUsize::new(0);
static FLUSHES: AtomicUsize = AtomicUsize::new(0);
static CONTROLS: AtomicUsize = AtomicUsize::new(0);

/// The last read or write the driver was sent.
pub fn seen() -> Seen {
    let mdl = SEEN_MDL.load(Ordering::Acquire);
    Seen {
        major: SEEN_MAJOR.load(Ordering::Acquire) as u8,
        offset: SEEN_OFFSET.load(Ordering::Acquire) as i64,
        length: SEEN_LENGTH.load(Ordering::Acquire),
        mdl: (mdl & 1 << 32 != 0).then_some((mdl as u32, SEEN_MDL_OFFSET.load(Ordering::Acquire))),
        locked: mdl & 1 << 33 != 0,
        other_buffers: mdl & 1 << 34 != 0,
        irql: SEEN_IRQL.load(Ordering::Acquire) as u8,
    }
}

/// How many transfers, flushes and control requests the driver has
/// been sent.
pub fn requests() -> (usize, usize, usize) {
    (
        TRANSFERS.load(Ordering::Acquire),
        FLUSHES.load(Ordering::Acquire),
        CONTROLS.load(Ordering::Acquire),
    )
}

/// The device's extension: the driver's own, in the device object's
/// block, reached through pointers only.
#[repr(C)]
struct Extension {
    /// Guards the queue and the disk's bytes.
    lock: KSPIN_LOCK,
    /// The requests pended, oldest first, linked by their `ListEntry`
    /// (`Tail.Overlay.ListEntry`).
    queue: LIST_ENTRY,
    /// Completes what is queued.
    dpc: KDPC,
    /// The disk's bytes: `SIZE` of them, from the pool.
    store: *mut u8,
}

/// # Safety
/// `device` is the test disk's device object.
unsafe fn extension(device: *mut DEVICE_OBJECT) -> *mut Extension {
    // SAFETY: per the contract: `IoCreateDevice` made room for it.
    unsafe { (*device).DeviceExtension.cast() }
}

/// # Safety
/// `request` is a request the driver holds and has not completed.
unsafe fn complete(request: *mut IRP, status: NTSTATUS, information: usize) {
    // SAFETY: per the contract.
    unsafe {
        (*request).IoStatus.Status = status;
        (*request).IoStatus.Information = information;
        irp::IofCompleteRequest(request, 0);
    }
}

/// The read or write in a stack location: its byte offset and length.
///
/// # Safety
/// `location` is the driver's location of a read or a write.
unsafe fn transfer_of(location: *mut IO_STACK_LOCATION) -> (i64, u32) {
    // SAFETY: per the contract. `Parameters.Read`: Length, Key,
    // ByteOffset.
    let parameters = unsafe { (*location).Parameters };
    (parameters[2] as i64, parameters[0] as u32)
}

/// Mark the request pending, queue it and have the DPC complete it.
///
/// # Safety
/// `request` is a request being dispatched to `device`, the test disk,
/// with the status and the count it is to complete with (if nothing
/// goes wrong on the way) in its status block.
unsafe fn pend(device: *mut DEVICE_OBJECT, request: *mut IRP) -> NTSTATUS {
    // SAFETY: per the contract; the queue is the lock's.
    unsafe {
        let own = extension(device);
        // `IoMarkIrpPending`.
        (*(*request).CurrentStackLocation).Control |= SL_PENDING_RETURNED;
        let lock = &raw mut (*own).lock;
        let old = kspin::KeAcquireSpinLockRaiseToDpc(lock);
        // `InsertTailList`.
        let head = &raw mut (*own).queue;
        let entry = &raw mut (*request).ListEntry;
        let last = (*head).Blink;
        (*entry).Flink = head;
        (*entry).Blink = last;
        (*last).Flink = entry;
        (*head).Blink = entry;
        kspin::KeReleaseSpinLock(lock, old);
        dpc::KeInsertQueueDpc(
            &raw mut (*own).dpc,
            core::ptr::null_mut(),
            core::ptr::null_mut(),
        );
    }
    STATUS_PENDING
}

/// Do the transfer of a queued read or write between the requestor's
/// buffer, mapped at `buffer`, and the disk's bytes; returns the count
/// to report.
///
/// # Safety
/// The caller holds the disk's lock; `store` is the disk's bytes;
/// `buffer` is valid for `bytes.len()` bytes, writable for a read.
unsafe fn move_bytes(
    store: *mut u8,
    buffer: *mut u8,
    bytes: core::ops::Range<usize>,
    read: bool,
) -> usize {
    let (first, end) = ((bytes.start / SECTOR) as u64, (bytes.end / SECTOR) as u64);
    let len = bytes.len();
    // Where in the buffer, and in the disk, a sector of the transfer is.
    let in_buffer = |sector: u64| (sector - first) as usize * SECTOR;
    let on_disk = |sector: u64| sector as usize * SECTOR;
    // The sector after `sector`, if the disk has one.
    let next = |sector: u64| (on_disk(sector + 1) < SIZE).then_some(sector + 1);
    // SAFETY: per the contract: every range below is inside the buffer
    // or inside the disk, and the two do not overlap.
    unsafe {
        if read {
            core::ptr::copy_nonoverlapping(store.add(bytes.start), buffer, len);
            if let Some(sector) = Fault::WrongSector.strikes(first, end)
                && let Some(next) = next(sector)
            {
                core::ptr::copy_nonoverlapping(
                    store.add(on_disk(next)),
                    buffer.add(in_buffer(sector)),
                    SECTOR,
                );
            }
        } else {
            let lost = Fault::LostWrite.strikes(first, end);
            for sector in first..end {
                if lost != Some(sector) {
                    core::ptr::copy_nonoverlapping(
                        buffer.add(in_buffer(sector)),
                        store.add(on_disk(sector)),
                        SECTOR,
                    );
                }
            }
            if let Some(sector) = Fault::StrayWrite.strikes(first, end)
                && let Some(next) = next(sector)
            {
                core::ptr::copy_nonoverlapping(
                    buffer.add(in_buffer(sector)),
                    store.add(on_disk(next)),
                    SECTOR,
                );
            }
        }
    }
    if Fault::ShortCount.strikes(first, end).is_some() {
        len - SECTOR
    } else {
        len
    }
}

/// The driver's DPC: the disk is done with what was queued. Each
/// request in turn is taken off the queue, a transfer is carried out,
/// and the request is completed.
///
/// # Safety
/// Called as a DPC routine whose context is the test disk's device.
unsafe extern "C" fn finished(_: *mut KDPC, context: *mut c_void, _: *mut c_void, _: *mut c_void) {
    let device = context.cast::<DEVICE_OBJECT>();
    // SAFETY: the device outlives its DPC (`TestDisk::drop`); a queued
    // request is the driver's until it completes it.
    unsafe {
        let own = extension(device);
        let lock = &raw mut (*own).lock;
        let head = &raw mut (*own).queue;
        loop {
            kspin::KeAcquireSpinLockAtDpcLevel(lock);
            let entry = (*head).Flink;
            if entry == head {
                kspin::KeReleaseSpinLockFromDpcLevel(lock);
                return;
            }
            // `RemoveHeadList`.
            let after = (*entry).Flink;
            (*head).Flink = after;
            (*after).Blink = head;
            let request = entry
                .byte_sub(core::mem::offset_of!(IRP, ListEntry))
                .cast::<IRP>();
            let location = (*request).CurrentStackLocation;
            let major = (*location).MajorFunction;
            let mut information = (*request).IoStatus.Information;
            if major == IRP_MJ_READ || major == IRP_MJ_WRITE {
                let (offset, length) = transfer_of(location);
                // The dispatch routine queued only what transfers
                // bytes, with its buffer mapped.
                if let Ok(Some(bytes)) = model::transfer(offset, length, SIZE as u64) {
                    let buffer = (*(*request).MdlAddress).MappedSystemVa.cast::<u8>();
                    information = move_bytes((*own).store, buffer, bytes, major == IRP_MJ_READ);
                }
            }
            kspin::KeReleaseSpinLockFromDpcLevel(lock);
            complete(request, (*request).IoStatus.Status, information);
        }
    }
}

/// The driver's dispatch routine.
///
/// # Safety
/// Called as a dispatch routine of the test disk's device.
unsafe extern "C" fn dispatch(device: *mut DEVICE_OBJECT, request: *mut IRP) -> NTSTATUS {
    // SAFETY: a live IRP being dispatched to the driver's device.
    unsafe {
        let location = (*request).CurrentStackLocation;
        let major = (*location).MajorFunction;
        match major {
            IRP_MJ_CREATE | IRP_MJ_CLEANUP | IRP_MJ_CLOSE => {
                complete(request, STATUS_SUCCESS, 0);
                STATUS_SUCCESS
            }
            IRP_MJ_READ | IRP_MJ_WRITE => {
                let (offset, length) = transfer_of(location);
                let described = (*request).MdlAddress;
                TRANSFERS.fetch_add(1, Ordering::AcqRel);
                SEEN_MAJOR.store(u32::from(major), Ordering::Release);
                SEEN_OFFSET.store(offset as u64, Ordering::Release);
                SEEN_LENGTH.store(length, Ordering::Release);
                SEEN_IRQL.store(u32::from(irql::current()), Ordering::Release);
                let mut mdl_seen = 0;
                if !described.is_null() {
                    mdl_seen = 1 << 32 | u64::from((*described).ByteCount);
                    if (*described).MdlFlags & MDL_PAGES_LOCKED != 0 {
                        mdl_seen |= 1 << 33;
                    }
                    SEEN_MDL_OFFSET.store((*described).ByteOffset, Ordering::Release);
                }
                if !(*request).SystemBuffer.is_null() || !(*request).UserBuffer.is_null() {
                    mdl_seen |= 1 << 34;
                }
                SEEN_MDL.store(mdl_seen, Ordering::Release);
                match model::transfer(offset, length, SIZE as u64) {
                    // The requestor's mistake: the class driver's own
                    // answer, given at once.
                    Err(STATUS_INVALID_PARAMETER) => {
                        complete(request, STATUS_INVALID_PARAMETER, 0);
                        STATUS_INVALID_PARAMETER
                    }
                    // The drive's answer, when it gets to the request.
                    Err(status) => {
                        (*request).IoStatus.Status = status;
                        (*request).IoStatus.Information = 0;
                        pend(device, request)
                    }
                    // No bytes: the class driver sends the drive
                    // nothing.
                    Ok(None) => {
                        complete(request, STATUS_SUCCESS, 0);
                        STATUS_SUCCESS
                    }
                    Ok(Some(_)) => {
                        // `MmGetSystemAddressForMdlSafe`: the DPC finds
                        // the address in the MDL.
                        let mapped = if described.is_null() {
                            core::ptr::null_mut()
                        } else {
                            mdl::MmMapLockedPagesSpecifyCache(
                                described,
                                KERNEL_MODE,
                                0,
                                core::ptr::null_mut(),
                                0,
                                0,
                            )
                        };
                        if mapped.is_null() {
                            complete(request, STATUS_INSUFFICIENT_RESOURCES, 0);
                            return STATUS_INSUFFICIENT_RESOURCES;
                        }
                        (*request).IoStatus.Status = STATUS_SUCCESS;
                        pend(device, request)
                    }
                }
            }
            IRP_MJ_FLUSH_BUFFERS => {
                // Nothing is held back: the disk's cache is the disk.
                FLUSHES.fetch_add(1, Ordering::AcqRel);
                (*request).IoStatus.Status = STATUS_SUCCESS;
                (*request).IoStatus.Information = 0;
                pend(device, request)
            }
            IRP_MJ_DEVICE_CONTROL => {
                CONTROLS.fetch_add(1, Ordering::AcqRel);
                // `Parameters.DeviceIoControl`: OutputBufferLength,
                // InputBufferLength, IoControlCode. Every code the disk
                // knows is buffered: one system buffer, input in,
                // answer out.
                let parameters = (*location).Parameters;
                let (room, given, code) = (
                    parameters[0] as u32 as usize,
                    parameters[1] as u32 as usize,
                    parameters[2] as u32,
                );
                let system = (*request).SystemBuffer.cast::<u8>();
                let mut input = alloc::vec![0u8; if system.is_null() { 0 } else { given }];
                core::ptr::copy_nonoverlapping(system, input.as_mut_ptr(), input.len());
                match model::control(code, &input, room, SIZE as u64, &IDENTITY) {
                    Ok(answer) => {
                        core::ptr::copy_nonoverlapping(answer.as_ptr(), system, answer.len());
                        (*request).IoStatus.Status = STATUS_SUCCESS;
                        (*request).IoStatus.Information = answer.len();
                        pend(device, request)
                    }
                    Err(status) => {
                        complete(request, status, 0);
                        status
                    }
                }
            }
            _ => irp::invalid_device_request(device, request),
        }
    }
}

/// The test disk: its driver and its device, there while this lives.
pub struct TestDisk {
    driver: *mut DRIVER_OBJECT,
    device: *mut DEVICE_OBJECT,
    store: *mut u8,
}

impl TestDisk {
    /// Make the driver and the disk, every sector holding the original
    /// pattern, with nothing wrong with it.
    pub fn new() -> Result<Self, &'static str> {
        let store = pool::alloc(SIZE, TAG);
        if store.is_null() {
            return Err("no memory for the test disk");
        }
        // SAFETY: a fresh block of `SIZE` bytes nothing else has yet;
        // every byte of it is written.
        unsafe {
            store.write_bytes(0, SIZE);
            pattern::fill(
                core::slice::from_raw_parts_mut(store, SIZE),
                0,
                pattern::ORIGINAL,
            );
        }
        let free_store = || {
            let _ = pool::free(store);
        };
        let driver = stack::make_driver(dispatch).inspect_err(|_| free_store())?;
        let mut wide: alloc::vec::Vec<u16> = NAME.encode_utf16().collect();
        let name = UNICODE_STRING {
            Length: (wide.len() * 2) as u16,
            MaximumLength: (wide.len() * 2) as u16,
            Buffer: wide.as_mut_ptr(),
        };
        let mut made = core::ptr::null_mut();
        // SAFETY: a driver object of the test's and a counted string;
        // the new device's extension is the driver's to set up before
        // the device takes requests.
        unsafe {
            if device::IoCreateDevice(
                driver,
                size_of::<Extension>() as u32,
                &raw const name,
                FILE_DEVICE_DISK,
                0,
                0,
                &raw mut made,
            ) != STATUS_SUCCESS
            {
                stack::free_driver(driver);
                free_store();
                return Err("could not create the test disk's device");
            }
            let own = extension(made);
            kspin::KeInitializeSpinLock(&raw mut (*own).lock);
            let head = &raw mut (*own).queue;
            (*head).Flink = head;
            (*head).Blink = head;
            dpc::KeInitializeDpc(&raw mut (*own).dpc, Some(finished), made.cast());
            (*own).store = store;
            (*made).Flags |= DO_DIRECT_IO;
            (*made).Flags &= !DO_DEVICE_INITIALIZING;
        }
        Fault::None.at(0);
        Ok(Self {
            driver,
            device: made,
            store,
        })
    }

    /// Hold the disk's bytes to the data disk's pattern as the harness
    /// holds the image after a boot: every sector of the write range
    /// the written pattern if `written`, every other its original one.
    /// Returns the sectors compared, or the first word that differs.
    pub fn image(&self, written: bool) -> Result<u64, Mismatch> {
        // SAFETY: the disk's bytes are the lock's: nothing writes them
        // while they are read here.
        unsafe {
            let lock = &raw mut (*extension(self.device)).lock;
            let old = kspin::KeAcquireSpinLockRaiseToDpc(lock);
            let bytes = core::slice::from_raw_parts(self.store, SIZE);
            let held = pattern::check_disk(bytes, 0, written);
            kspin::KeReleaseSpinLock(lock, old);
            held.map(|()| (SIZE / SECTOR) as u64)
        }
    }
}

impl Drop for TestDisk {
    fn drop(&mut self) {
        Fault::None.at(0);
        // Whatever DPC of the disk's was queued has run before the
        // device and the disk's bytes go.
        dpc::flush();
        // SAFETY: the driver's device, which no request is in any more,
        // then the driver object and the disk's bytes.
        unsafe {
            device::IoDeleteDevice(self.device);
            stack::free_driver(self.driver);
        }
        let _ = pool::free(self.store);
    }
}
