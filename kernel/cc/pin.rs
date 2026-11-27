//! Mapping and pinning: `CcMapData` hands a file system a view of a
//! range and a handle that is the view's VACB plus one; `CcPinRead`,
//! `CcPinMappedData` and `CcPreparePinWrite` a buffer control block
//! (BCB) that keeps the range's view while it is pinned and records
//! whether the range is dirty. `CcUnpinData` tells the handles apart as
//! Windows does (`nk_cc::bcblist::handle_kind`).
//!
//! On a stream whose modified writing is disabled (the file system's
//! metadata), a pin takes the BCB's resource, shared or with
//! `PIN_EXCLUSIVE` exclusive, and an unpin gives it back, so the lazy
//! writer, which takes it exclusive, never writes a range while it is
//! being changed; on other streams the resource is not used, as in
//! `CcPinFileData`.
//!
//! A dirty BCB's pages are not marked modified in the memory manager
//! until the range is written (`MmSetAddressRangeModified`, then a flush):
//! Windows' order. A BCB nobody pins goes away when it is clean; a dirty
//! one stays on the list for the lazy writer.
//!
//! Partial: a map or pin of a range that crosses a view (256 KiB)
//! boundary stops the system by name; Windows reads past the view for
//! a map, and gives an OBCB for a pin, which no file system of the set
//! needs.

use super::vacb::{self, View};
use super::{DIRTY, MASTER, Scm, TAG_BCB, alloc_in_pool, cache_manager_bugcheck, cached, flag};
use super::{free_in_pool, or_raise};
use crate::arch::seh::{Context, fourth_argument, stack_argument};
use crate::ex::resource;
use crate::mm::cache::{self, Resident};
use crate::mm::{PAGE_SIZE, flush};
use core::cell::{Cell, UnsafeCell};
use core::ffi::c_void;
use core::sync::atomic::{AtomicBool, Ordering};
use nk_cc::bcblist::{self, BCB_NODE, Entry, Handle};
use nk_ntabi::cc::*;
use nk_ntabi::ex::ERESOURCE;
use nk_ntabi::io::{FILE_OBJECT, IO_STATUS_BLOCK};
use nk_ntabi::status::*;
use nk_ntabi::thread::DISABLE_PAGE_FAULT_CLUSTERING;

/// No VACB.
const NO_VACB: usize = usize::MAX;

/// A buffer control block. `node_type` comes first, as the handle tests
/// read it there.
#[repr(C)]
pub struct Bcb {
    node_type: u16,
    /// Under [`DIRTY`].
    dirty: AtomicBool,
    pub byte_length: u32,
    pub file_offset: u64,
    pub beyond_last_byte: u64,
    pub oldest_lsn: Cell<i64>,
    pub newest_lsn: Cell<i64>,
    // Under the map's BCB mutex.
    pin_count: Cell<u32>,
    vacb: Cell<usize>,
    base_address: Cell<usize>,
    pub scm: *const Scm,
    resource: UnsafeCell<ERESOURCE>,
}

impl Bcb {
    fn resource(&self) -> *mut ERESOURCE {
        self.resource.get()
    }

    pub fn is_dirty(&self) -> bool {
        self.dirty.load(Ordering::Acquire)
    }

    fn entry(&self) -> Entry {
        Entry {
            offset: self.file_offset,
            beyond: self.beyond_last_byte,
            dirty: self.is_dirty(),
        }
    }

    /// Pages the BCB's range touches.
    fn pages(&self) -> u64 {
        let page = PAGE_SIZE as u64;
        self.beyond_last_byte.div_ceil(page) - self.file_offset / page
    }

    /// Its address while pinned: where its first byte is mapped.
    pub fn base(&self) -> usize {
        self.base_address.get()
    }
}

/// Whether pins of `scm` take their BCB's resource: its stream is one
/// whose modified writing is disabled.
fn uses_resource(scm: &Scm) -> bool {
    scm.flags.get() & flag::MODIFIED_WRITE_DISABLED != 0
}

/// Stop the system if `[offset, offset + len)` leaves the view that
/// holds `offset`.
fn within_view(v: &View, offset: u64, len: u32, routine: &str) {
    if len > v.left {
        cache_manager_bugcheck(format_args!(
            "{routine} of {len:#x} bytes at {offset:#x} crosses a view's end, which NK does not \
             implement"
        ));
    }
}

/// `ETHREAD.DisablePageFaultClustering` set to `on` around `f`.
fn with_clustering_off<R>(on: bool, f: impl FnOnce() -> R) -> R {
    let thread = crate::ke::pcr::current_thread();
    // SAFETY: the current thread's own byte.
    let was = unsafe { thread.add(DISABLE_PAGE_FAULT_CLUSTERING).read() };
    if on {
        // SAFETY: as above.
        unsafe { thread.add(DISABLE_PAGE_FAULT_CLUSTERING).write(1) };
    }
    let r = f();
    // SAFETY: as above.
    unsafe { thread.add(DISABLE_PAGE_FAULT_CLUSTERING).write(was) };
    r
}

/// The arguments a file system gives a map or pin: the file offset.
///
/// # Safety
/// `offset` is readable.
unsafe fn read_offset(offset: *const i64) -> u64 {
    // SAFETY: per the contract.
    unsafe { offset.read_unaligned() as u64 }
}

/// What `CcMapData` is entered as: the fourth argument is the flags,
/// the fifth where the handle goes, the sixth where the buffer does.
///
/// # Safety
/// Called by a file system as `CcMapData` on a cached file, with
/// `context` from `nk_with_caller_context`.
#[unsafe(no_mangle)]
unsafe extern "C" fn nk_cc_map_data(
    file: *mut FILE_OBJECT,
    offset: *const i64,
    length: u32,
    context: *mut Context,
) -> u8 {
    // SAFETY: per the contract.
    unsafe {
        let flags = fourth_argument(&*context) as u32;
        let bcb_out = stack_argument(&*context, 4) as *mut usize;
        let buffer_out = stack_argument(&*context, 5) as *mut usize;
        let scm = cached(file, "CcMapData");
        let r = map_data(scm, read_offset(offset), length, flags, bcb_out, buffer_out);
        u8::from(or_raise(context, r))
    }
}

/// `CcMapData`.
///
/// # Safety
/// `bcb_out` and `buffer_out` are writable.
unsafe fn map_data(
    scm: &Scm,
    offset: u64,
    length: u32,
    flags: u32,
    bcb_out: *mut usize,
    buffer_out: *mut usize,
) -> Result<bool, NTSTATUS> {
    let wait = flags & MAP_WAIT != 0;
    if !wait {
        // SAFETY: per the contract (CcPinFileData clears it first).
        unsafe { buffer_out.write(0) };
    }
    let v = vacb::get_va(scm, offset)?;
    within_view(&v, offset, length, "CcMapData");
    let resident = if wait && flags & MAP_NO_READ != 0 {
        Ok(true)
    } else {
        let mode = if wait {
            Resident::FaultIn
        } else {
            Resident::NoIo
        };
        with_clustering_off(flags & MAP_DISABLE_PAGEFAULT_CLUSTERING != 0, || {
            cache::make_resident(v.va, length as usize, mode)
        })
    };
    match resident {
        Ok(true) => {
            let handle = vacb::with(|p| p.handle(v.vacb));
            // SAFETY: per the contract.
            unsafe {
                bcb_out.write(handle);
                buffer_out.write(v.va);
            }
            Ok(true)
        }
        Ok(false) => {
            vacb::free_va(v.vacb);
            Ok(false)
        }
        Err(status) => {
            vacb::free_va(v.vacb);
            Err(status)
        }
    }
}

/// How a pin uses its range.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Use {
    /// It reads, and takes no resource.
    ReadOnly,
    /// It may change the range: the resource is taken where the stream
    /// uses it.
    ReadWrite,
    /// It overwrites the range: pages wholly inside are not read.
    WriteOnly,
}

/// `CcPinFileData`: pin `[offset, offset + length)` of `scm`. `None`
/// when, without waiting, the BCB's resource or the pages are not to be
/// had, or with `PIN_IF_BCB` no BCB covers the range; nothing is held
/// then.
fn pin_file_data(
    scm: &Scm,
    offset: u64,
    length: u32,
    flags: u32,
    how: Use,
    routine: &str,
) -> Result<Option<(*mut Bcb, usize)>, NTSTATUS> {
    let wait = flags & PIN_WAIT != 0;
    let end = offset + u64::from(length);
    if end > scm.section_size.get() {
        cache_manager_bugcheck(format_args!(
            "{routine} of {length:#x} bytes at {offset:#x} is beyond the section ({:#x})",
            scm.section_size.get()
        ));
    }
    let v = vacb::get_va(scm, offset)?;
    within_view(&v, offset, length, routine);
    let takes_resource = how != Use::ReadOnly && uses_resource(scm);
    // A new BCB of a pinned metadata stream covers whole pages, within
    // the view.
    let whole_pages = how == Use::ReadWrite
        && scm.flags.get() & (flag::PIN_ACCESS | flag::MODIFIED_WRITE_DISABLED)
            == flag::PIN_ACCESS | flag::MODIFIED_WRITE_DISABLED;
    let (bcb_offset, bcb_end) = if whole_pages {
        let page = PAGE_SIZE as u64;
        let view_end = offset + u64::from(v.left);
        let view_start = offset - (v.va % cache::VIEW_BYTES) as u64;
        (
            (offset & !(page - 1)).max(view_start),
            end.next_multiple_of(page).min(view_end),
        )
    } else {
        (offset, end)
    };
    let fresh = alloc_in_pool(
        Bcb {
            node_type: BCB_NODE,
            dirty: AtomicBool::new(false),
            byte_length: (bcb_end - bcb_offset) as u32,
            file_offset: bcb_offset,
            beyond_last_byte: bcb_end,
            oldest_lsn: Cell::new(0),
            newest_lsn: Cell::new(0),
            pin_count: Cell::new(0),
            vacb: Cell::new(NO_VACB),
            base_address: Cell::new(0),
            scm,
            // SAFETY: initialised below, before the BCB is seen.
            resource: UnsafeCell::new(unsafe { core::mem::zeroed() }),
        },
        TAG_BCB,
    );
    if fresh.is_null() {
        vacb::free_va(v.vacb);
        return Err(STATUS_INSUFFICIENT_RESOURCES);
    }
    // SAFETY: the fresh BCB, ours alone; its resource does not move.
    unsafe { resource::ExInitializeResourceLite((*fresh).resource()) };
    let (bcb, used_fresh, extra_view) = scm.with_bcbs(|bcbs, _| {
        // SAFETY: BCBs on the list are live under the mutex.
        let entries: alloc::vec::Vec<Entry> =
            bcbs.iter().map(|&b| unsafe { (*b).entry() }).collect();
        let (bcb, used_fresh) = match bcblist::find(&entries, offset, end) {
            Ok(i) => (bcbs[i], false),
            Err(_) if flags & PIN_IF_BCB != 0 => return (core::ptr::null_mut(), false, true),
            Err(_) => {
                let at = entries.partition_point(|e| e.offset <= bcb_offset);
                if bcbs.try_reserve(1).is_err() {
                    return (core::ptr::null_mut(), false, true);
                }
                bcbs.insert(at, fresh);
                (fresh, true)
            }
        };
        // SAFETY: as above.
        let b = unsafe { &*bcb };
        b.pin_count.set(b.pin_count.get() + 1);
        let extra = if b.vacb.get() == NO_VACB {
            b.vacb.set(v.vacb);
            b.base_address.set(v.va - (offset - b.file_offset) as usize);
            false
        } else {
            true
        };
        (bcb, used_fresh, extra)
    });
    if !used_fresh {
        // SAFETY: never seen by anyone else.
        unsafe {
            resource::ExDeleteResourceLite((*fresh).resource());
            free_in_pool(fresh);
        }
    }
    if extra_view {
        vacb::free_va(v.vacb);
    }
    if bcb.is_null() {
        return if flags & PIN_IF_BCB != 0 {
            Ok(None)
        } else {
            Err(STATUS_INSUFFICIENT_RESOURCES)
        };
    }
    // SAFETY: pinned, so live.
    let b = unsafe { &*bcb };
    if takes_resource {
        // SAFETY: the BCB's resource, initialised.
        let got = unsafe {
            if flags & PIN_EXCLUSIVE != 0 {
                resource::ExAcquireResourceExclusiveLite(b.resource(), u8::from(wait))
            } else {
                resource::ExAcquireSharedStarveExclusive(b.resource(), u8::from(wait))
            }
        };
        if got == 0 {
            unpin(b, false);
            return Ok(None);
        }
    }
    let buffer = b.base() + (offset - b.file_offset) as usize;
    if flags & PIN_NO_READ == 0 {
        let mode = match how {
            Use::WriteOnly => Resident::WillOverwrite,
            _ if wait => Resident::FaultIn,
            _ => Resident::NoIo,
        };
        match cache::make_resident(buffer, length as usize, mode) {
            Ok(true) => {}
            Ok(false) => {
                unpin(b, takes_resource);
                return Ok(None);
            }
            Err(status) => {
                unpin(b, takes_resource);
                return Err(status);
            }
        }
    }
    super::trace(format_args!(
        "{routine} {:p} {offset:#x}+{length:#x}: bcb {bcb:p}",
        core::ptr::from_ref(scm)
    ));
    Ok(Some((bcb, buffer)))
}

/// `CcUnpinFileData`: one pin fewer, the resource given back if the pin
/// took it. A BCB nobody pins gives its view back, and goes if clean.
fn unpin(b: &Bcb, release_resource: bool) {
    if release_resource {
        // SAFETY: the pin took it on this thread.
        unsafe { resource::ExReleaseResourceLite(b.resource()) };
    }
    // SAFETY: a BCB names its live map.
    let scm = unsafe { &*b.scm };
    let (view, free) = scm.with_bcbs(|bcbs, _| {
        let count = b.pin_count.get();
        if count == 0 {
            cache_manager_bugcheck(format_args!(
                "a BCB nobody pins is unpinned ({:p})",
                core::ptr::from_ref(b)
            ));
        }
        b.pin_count.set(count - 1);
        if count > 1 {
            return (NO_VACB, false);
        }
        let view = b.vacb.replace(NO_VACB);
        b.base_address.set(0);
        let free = !b.is_dirty();
        if free {
            bcbs.retain(|&x| !core::ptr::eq(x, b));
        }
        (view, free)
    });
    if view != NO_VACB {
        vacb::free_va(view);
    }
    if free {
        let bcb = core::ptr::from_ref(b).cast_mut();
        // SAFETY: off the list and pinned by nobody: nothing names it.
        unsafe {
            resource::ExDeleteResourceLite((*bcb).resource());
            free_in_pool(bcb);
        }
    }
}

/// The kind of a handle a file system gives back.
fn kind(handle: usize) -> Handle {
    bcblist::handle_kind(handle, |address| {
        // SAFETY: a handle with bit 0 clear points at a node type.
        unsafe { (address as *const u16).read() }
    })
}

/// The BCB a handle is, or stop: `routine` was given something else.
fn bcb_of(handle: usize, routine: &str) -> &'static Bcb {
    match kind(handle) {
        // SAFETY: a BCB handle points at a live BCB.
        Handle::Bcb => unsafe { &*(handle as *const Bcb) },
        other => cache_manager_bugcheck(format_args!(
            "{routine} was given {handle:#x}, which is not a BCB ({other:?})"
        )),
    }
}

/// What `CcPinRead` is entered as: the fourth argument is the flags,
/// the fifth where the BCB goes, the sixth where the buffer does.
///
/// # Safety
/// As [`nk_cc_map_data`], for `CcPinRead`.
#[unsafe(no_mangle)]
unsafe extern "C" fn nk_cc_pin_read(
    file: *mut FILE_OBJECT,
    offset: *const i64,
    length: u32,
    context: *mut Context,
) -> u8 {
    // SAFETY: per the contract.
    unsafe {
        let flags = fourth_argument(&*context) as u32;
        let bcb_out = stack_argument(&*context, 4) as *mut usize;
        let buffer_out = stack_argument(&*context, 5) as *mut usize;
        let scm = cached(file, "CcPinRead");
        let how = if uses_resource(scm) {
            Use::ReadWrite
        } else {
            Use::ReadOnly
        };
        let r = pin_file_data(scm, read_offset(offset), length, flags, how, "CcPinRead");
        match or_raise(context, r) {
            Some((bcb, buffer)) => {
                bcb_out.write(bcb.addr());
                buffer_out.write(buffer);
                1
            }
            None => 0,
        }
    }
}

/// What `CcPinMappedData` is entered as: the fourth argument is the
/// flags, the fifth the handle `CcMapData` gave, replaced by a BCB.
///
/// # Safety
/// As [`nk_cc_map_data`], for `CcPinMappedData`.
#[unsafe(no_mangle)]
unsafe extern "C" fn nk_cc_pin_mapped_data(
    file: *mut FILE_OBJECT,
    offset: *const i64,
    length: u32,
    context: *mut Context,
) -> u8 {
    // SAFETY: per the contract.
    unsafe {
        let flags = fourth_argument(&*context) as u32;
        let bcb_io = stack_argument(&*context, 4) as *mut usize;
        let scm = cached(file, "CcPinMappedData");
        let Handle::Mapped(address) = kind(bcb_io.read()) else {
            cache_manager_bugcheck(format_args!(
                "CcPinMappedData was given {:#x}, which is not a mapping",
                bcb_io.read()
            ));
        };
        let how = if uses_resource(scm) {
            Use::ReadWrite
        } else {
            Use::ReadOnly
        };
        let r = pin_file_data(
            scm,
            read_offset(offset),
            length,
            flags,
            how,
            "CcPinMappedData",
        );
        match or_raise(context, r) {
            Some((bcb, _)) => {
                if let Some(i) = vacb::with(|p| p.vacb_of_handle(address)) {
                    vacb::free_va(i);
                }
                bcb_io.write(bcb.addr());
                1
            }
            None => 0,
        }
    }
}

/// What `CcPreparePinWrite` is entered as: the fourth argument is
/// `Zero`, the fifth the flags, the sixth where the BCB goes, the
/// seventh where the buffer does.
///
/// # Safety
/// As [`nk_cc_map_data`], for `CcPreparePinWrite`.
#[unsafe(no_mangle)]
unsafe extern "C" fn nk_cc_prepare_pin_write(
    file: *mut FILE_OBJECT,
    offset: *const i64,
    length: u32,
    context: *mut Context,
) -> u8 {
    // SAFETY: per the contract.
    unsafe {
        let zero = fourth_argument(&*context) as u8 != 0;
        let flags = stack_argument(&*context, 4) as u32;
        let bcb_out = stack_argument(&*context, 5) as *mut usize;
        let buffer_out = stack_argument(&*context, 6) as *mut usize;
        let scm = cached(file, "CcPreparePinWrite");
        if flags & PIN_CALLER_TRACKS_DIRTY_DATA != 0 {
            cache_manager_bugcheck(format_args!(
                "CcPreparePinWrite with PIN_CALLER_TRACKS_DIRTY_DATA, which NK does not implement"
            ));
        }
        let r = pin_file_data(
            scm,
            read_offset(offset),
            length,
            flags,
            Use::WriteOnly,
            "CcPreparePinWrite",
        );
        match or_raise(context, r) {
            Some((bcb, buffer)) => {
                if zero {
                    core::ptr::write_bytes(buffer as *mut u8, 0, length as usize);
                }
                set_dirty(&*bcb, core::ptr::null());
                bcb_out.write(bcb.addr());
                buffer_out.write(buffer);
                1
            }
            None => 0,
        }
    }
}

/// Mark `b` dirty and charge its pages, `lsn` (if given) its newest log
/// sequence number.
fn set_dirty(b: &Bcb, lsn: *const i64) {
    // SAFETY: a BCB names its live map.
    let scm = unsafe { &*b.scm };
    let _m = MASTER.lock();
    let mut d = DIRTY.lock();
    // SAFETY: the caller's number, if any.
    if let Some(&lsn) = unsafe { lsn.as_ref() } {
        if b.oldest_lsn.get() == 0 {
            b.oldest_lsn.set(lsn);
        }
        b.newest_lsn.set(lsn);
    }
    if !b.dirty.swap(true, Ordering::AcqRel) {
        let pages = b.pages();
        scm.dirty_pages.set(scm.dirty_pages.get() + pages);
        d.pages += pages;
        drop(d);
        super::lazy::schedule_scan();
    }
}

/// Mark `b` clean and take its pages off the counts.
pub fn set_clean(b: &Bcb) {
    // SAFETY: a BCB names its live map.
    let scm = unsafe { &*b.scm };
    let mut d = DIRTY.lock();
    if b.dirty.swap(false, Ordering::AcqRel) {
        let pages = b.pages();
        scm.dirty_pages.set(scm.dirty_pages.get() - pages);
        d.pages -= pages;
    }
}

/// [`CcSetDirtyPinnedData`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-ccsetdirtypinneddata):
/// the pinned range is dirty. Nothing reaches the memory manager until
/// the range is written.
///
/// # Safety
/// `bcb` is a handle from a pin; `lsn` null or readable.
pub unsafe extern "C" fn CcSetDirtyPinnedData(bcb: *mut c_void, lsn: *const i64) {
    set_dirty(bcb_of(bcb.addr(), "CcSetDirtyPinnedData"), lsn);
}

/// [`CcUnpinData`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-ccunpindata):
/// give back a mapping or a pin.
///
/// # Safety
/// `bcb` is a handle from `CcMapData` or a pin, not given back yet.
pub unsafe extern "C" fn CcUnpinData(bcb: *mut c_void) {
    match kind(bcb.addr()) {
        Handle::Mapped(address) => match vacb::with(|p| p.vacb_of_handle(address)) {
            Some(i) => vacb::free_va(i),
            None => cache_manager_bugcheck(format_args!(
                "CcUnpinData was given {bcb:p}, which is no mapping"
            )),
        },
        Handle::Bcb => {
            let b = bcb_of(bcb.addr(), "CcUnpinData");
            // SAFETY: a BCB names its live map.
            unpin(b, uses_resource(unsafe { &*b.scm }));
        }
        other => cache_manager_bugcheck(format_args!(
            "CcUnpinData was given {bcb:p}, which is no handle the cache manager gave ({other:?})"
        )),
    }
}

/// [`CcRepinBcb`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-ccrepinbcb):
/// one more pin, kept past `CcUnpinData` until `CcUnpinRepinnedBcb`;
/// the resource is not touched.
///
/// # Safety
/// `bcb` is a pinned BCB.
pub unsafe extern "C" fn CcRepinBcb(bcb: *mut c_void) {
    let b = bcb_of(bcb.addr(), "CcRepinBcb (0x2072)");
    // SAFETY: a BCB names its live map.
    let scm = unsafe { &*b.scm };
    scm.with_bcbs(|_, _| b.pin_count.set(b.pin_count.get() + 1));
}

/// [`CcUnpinRepinnedBcb`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-ccunpinrepinnedbcb):
/// give back a repin; with `write_through`, write the range first if it
/// is dirty, synchronously. Never raises: a write's failure is in
/// `iosb`, and one the memory manager does not call fatal leaves the
/// range dirty.
///
/// # Safety
/// `bcb` is a repinned BCB; `iosb` writable.
pub unsafe extern "C" fn CcUnpinRepinnedBcb(
    bcb: *mut c_void,
    write_through: u8,
    iosb: *mut IO_STATUS_BLOCK,
) {
    let b = bcb_of(bcb.addr(), "CcUnpinRepinnedBcb");
    // SAFETY: per the contract.
    unsafe { (&raw mut (*iosb).Status).write(STATUS_SUCCESS) };
    if write_through == 0 {
        unpin(b, false);
        return;
    }
    // SAFETY: a BCB names its live map.
    let scm = unsafe { &*b.scm };
    let resource = uses_resource(scm);
    if resource {
        // SAFETY: the BCB's resource.
        unsafe { resource::ExAcquireResourceExclusiveLite(b.resource(), 1) };
    }
    if b.is_dirty() {
        cache::set_range_modified(b.base(), b.byte_length as usize);
        set_clean(b);
        let result = flush::flush_section(
            scm.sop,
            Some((b.file_offset, b.byte_length)),
            Some(crate::fsrtl::acquire::CC_FLUSH),
        );
        // SAFETY: per the contract.
        unsafe { (&raw mut (*iosb).Status).write(result.Status) };
        if nt_error(result.Status)
            && !nk_mm::section::is_write_error_fatal(true, false, result.Status)
        {
            set_dirty(b, core::ptr::null());
        }
    }
    unpin(b, resource);
    super::throttle::post_deferred();
}

/// [`CcGetFileObjectFromBcb`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-ccgetfileobjectfrombcb):
/// the file object the cache manager holds for the BCB's file (the first
/// that cached it, not necessarily the caller's).
///
/// # Safety
/// `bcb` is a pinned BCB.
pub unsafe extern "C" fn CcGetFileObjectFromBcb(bcb: *mut c_void) -> *mut FILE_OBJECT {
    let b = bcb_of(bcb.addr(), "CcGetFileObjectFromBcb");
    // SAFETY: a BCB names its live map.
    unsafe { (*b.scm).file_object.get() }
}

/// Free every BCB of a map being deleted. None may be pinned or dirty.
pub fn delete_bcbs(scm: &Scm) {
    let bcbs = scm.with_bcbs(|bcbs, _| core::mem::take(bcbs));
    for bcb in bcbs {
        // SAFETY: the deletion owns the list's BCBs.
        unsafe {
            if (*bcb).pin_count.get() != 0 || (*bcb).is_dirty() {
                cache_manager_bugcheck(format_args!(
                    "a map is deleted with BCB {bcb:p} pinned or dirty"
                ));
            }
            resource::ExDeleteResourceLite((*bcb).resource());
            free_in_pool(bcb);
        }
    }
}

/// A run of dirty BCBs taken for writing: its range and its BCBs, each
/// held by one more pin (and its resource, where the stream uses it)
/// until [`finish_run`].
pub struct DirtyRun {
    pub offset: u64,
    pub length: u32,
    bcbs: alloc::vec::Vec<*mut Bcb>,
    resource: bool,
}

/// `CcAcquireByteRangeForWrite` for pins: the next dirty run of `scm`
/// at or after `from` and before `end`, of at most `most` bytes. Its
/// BCBs' resources are taken exclusive, waiting for their pinners; the
/// BCBs are clean from now on, their pages handed to the memory manager
/// as modified.
pub fn take_dirty_run(scm: &Scm, from: u64, end: u64, most: u64) -> Option<DirtyRun> {
    let resource = uses_resource(scm);
    let run = scm.with_bcbs(|bcbs, _| {
        // SAFETY: BCBs on the list are live under the mutex.
        let entries: alloc::vec::Vec<Entry> =
            bcbs.iter().map(|&b| unsafe { (*b).entry() }).collect();
        let (start, stop, members) = bcblist::dirty_run(&entries, from, most)?;
        if start >= end {
            return None;
        }
        let taken: alloc::vec::Vec<*mut Bcb> = members.iter().map(|&i| bcbs[i]).collect();
        for &b in &taken {
            // SAFETY: as above.
            let b = unsafe { &*b };
            b.pin_count.set(b.pin_count.get() + 1);
        }
        Some(DirtyRun {
            offset: start,
            length: (stop - start) as u32,
            bcbs: taken,
            resource,
        })
    })?;
    for &b in &run.bcbs {
        // SAFETY: held by the run's pin.
        let b = unsafe { &*b };
        if resource {
            // SAFETY: the BCB's resource.
            unsafe { resource::ExAcquireResourceExclusiveLite(b.resource(), 1) };
        }
        if b.vacb.get() != NO_VACB {
            cache::set_range_modified(b.base(), b.byte_length as usize);
        }
        set_clean(b);
    }
    Some(run)
}

/// `CcReleaseByteRangeFromWrite` for pins: the run's write is over;
/// after a failure that is not fatal its BCBs are dirty again.
pub fn finish_run(run: DirtyRun, redirty: bool) {
    for b in run.bcbs {
        // SAFETY: held by the run's pin.
        let b = unsafe { &*b };
        if redirty {
            set_dirty(b, core::ptr::null());
        }
        unpin(b, run.resource);
    }
}

/// Forget the dirt of the BCBs of `scm` that reach `from` or beyond (a
/// file cut or purged there): they are clean, and those nobody pins go.
pub fn discard_from(scm: &Scm, from: u64) {
    let gone = scm.with_bcbs(|bcbs, _| {
        let mut gone = alloc::vec::Vec::new();
        bcbs.retain(|&b| {
            // SAFETY: BCBs on the list are live under the mutex.
            let bcb = unsafe { &*b };
            if bcb.beyond_last_byte <= from {
                return true;
            }
            set_clean(bcb);
            if bcb.pin_count.get() != 0 {
                return true;
            }
            gone.push(b);
            false
        });
        gone
    });
    for b in gone {
        // SAFETY: off the list and pinned by nobody.
        unsafe {
            resource::ExDeleteResourceLite((*b).resource());
            free_in_pool(b);
        }
    }
}
