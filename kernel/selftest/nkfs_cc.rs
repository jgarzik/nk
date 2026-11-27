//! The cache manager over nkfs, called as a file system calls it: cache
//! maps made and deleted, maps and pins, what each reads and writes.

use super::except;
use super::nkfs::{self, Record, Volume};
use crate::arch::seh as entry;
use crate::cc;
use crate::mm::flush;
use crate::test::{Group, Report};
use alloc::vec::Vec;
use core::ffi::c_void;
use core::sync::atomic::{AtomicUsize, Ordering};
use nk_bootinfo::BootInfo;
use nk_ntabi::cc::*;
use nk_ntabi::io::{
    FAST_IO_DISPATCH, FILE_OBJECT, IO_STATUS_BLOCK, IRP_MJ_READ, IRP_MJ_WRITE, MDL,
    SECTION_OBJECT_POINTERS,
};
use nk_ntabi::status::*;

pub static GROUPS: &[&Group] = &[&CC];

static CC: Group = Group {
    names: &[
        "cc.map",
        "cc.map-nowait",
        "cc.map-error",
        "cc.pin",
        "cc.pin-write-through",
        "cc.flush-acquire",
        "cc.prepare-pin-write",
        "cc.uninitialize",
        "cc.initialize-extend-fails",
        "cc.copy-read",
        "cc.copy-write",
        "cc.copy-write-beyond-valid",
        "cc.mdl",
        "cc.zero",
        "cc.purge",
        "cc.sizes",
        "cc.attributes",
        "cc.lazy-write",
        "cc.defer-write",
        "cc.lazy-close",
    ],
    run: cc_tests,
    manual: false,
};

type Verdicts = Vec<(&'static str, Result<(), &'static str>)>;

fn cc_tests(r: &mut Report, _: &BootInfo) {
    let mut verdicts = Verdicts::new();
    let outcome = run(&mut verdicts);
    for (name, verdict) in &verdicts {
        match verdict {
            Ok(()) => r.ok(name),
            Err(why) => r.fail(name, format_args!("{why}")),
        }
    }
    for name in CC
        .names
        .iter()
        .filter(|n| !verdicts.iter().any(|(v, _)| v == *n))
    {
        r.fail(
            name,
            format_args!("not reached: {}", outcome.err().unwrap_or("?")),
        );
    }
}

static SIZES: CC_FILE_SIZES = CC_FILE_SIZES {
    AllocationSize: nkfs::FILE_BYTES as i64,
    FileSize: nkfs::FILE_BYTES as i64,
    ValidDataLength: nkfs::FILE_BYTES as i64,
};

/// The callbacks the tests' file system gives: nothing to take.
///
/// # Safety
/// Takes any context.
unsafe extern "C" fn acquire(_: *mut c_void, _: u8) -> u8 {
    1
}

/// # Safety
/// Takes any context.
unsafe extern "C" fn release(_: *mut c_void) {}

/// Calls of `AcquireForLazyWrite`.
static LAZY_ACQUIRED: AtomicUsize = AtomicUsize::new(0);

/// `AcquireForLazyWrite`: nothing to take; counted.
///
/// # Safety
/// Takes any context.
unsafe extern "C" fn acquire_lazy(_: *mut c_void, _: u8) -> u8 {
    LAZY_ACQUIRED.fetch_add(1, Ordering::Relaxed);
    1
}

/// Calls of the deferred write's post routine.
static POSTED: AtomicUsize = AtomicUsize::new(0);

/// A deferred write's post routine.
///
/// # Safety
/// Takes any contexts.
unsafe extern "C" fn posted(context: *mut c_void, _: *mut c_void) {
    POSTED.fetch_add(context.addr(), Ordering::Relaxed);
}

static CALLBACKS: CACHE_MANAGER_CALLBACKS = CACHE_MANAGER_CALLBACKS {
    AcquireForLazyWrite: Some(acquire_lazy),
    ReleaseFromLazyWrite: Some(release),
    AcquireForReadAhead: Some(acquire),
    ReleaseFromReadAhead: Some(release),
};

/// `CcInitializeCacheMap` on `file`.
fn initialize(file: *mut FILE_OBJECT, pin_access: bool) {
    // SAFETY: a file object of nkfs's, with its pointers and header.
    unsafe {
        entry::nk_entry_CcInitializeCacheMap(
            file.cast(),
            (&raw const SIZES).cast(),
            u8::from(pin_access),
            (&raw const CALLBACKS).cast(),
            core::ptr::null_mut(),
        )
    }
}

/// `CcMapData`: the result, the handle and the buffer.
fn map(file: *mut FILE_OBJECT, offset: i64, length: u32, flags: u32) -> (u8, usize, usize) {
    let (mut bcb, mut buffer) = (0x5A5A_usize, 0x5A5A_usize);
    // SAFETY: a cached file of nkfs's; the outputs are on this stack.
    let ok = unsafe {
        entry::nk_entry_CcMapData(
            file.cast(),
            &raw const offset,
            length,
            flags,
            (&raw mut bcb).cast(),
            (&raw mut buffer).cast(),
        )
    };
    (ok, bcb, buffer)
}

/// `CcPinRead`: the result, the handle and the buffer.
fn pin(file: *mut FILE_OBJECT, offset: i64, length: u32, flags: u32) -> (u8, usize, usize) {
    let (mut bcb, mut buffer) = (0usize, 0usize);
    // SAFETY: as in `map`.
    let ok = unsafe {
        entry::nk_entry_CcPinRead(
            file.cast(),
            &raw const offset,
            length,
            flags,
            (&raw mut bcb).cast(),
            (&raw mut buffer).cast(),
        )
    };
    (ok, bcb, buffer)
}

fn unpin(handle: usize) {
    // SAFETY: a handle a map or pin gave.
    unsafe { cc::pin::CcUnpinData(handle as *mut c_void) };
}

/// Whether the bytes at `va` hold the file's original bytes at `offset`.
fn holds_pattern(va: usize, offset: usize, len: usize) -> bool {
    // SAFETY: a mapped or pinned range the caller holds.
    (0..len)
        .all(|i| unsafe { ((va + i) as *const u8).read_volatile() } == nkfs::pattern(offset + i))
}

fn reads(log: &[Record]) -> impl Iterator<Item = &Record> {
    log.iter().filter(|r| r.major == IRP_MJ_READ)
}

/// Sizes no section can be extended to: the memory manager has no
/// directory that large.
static HUGE: CC_FILE_SIZES = CC_FILE_SIZES {
    AllocationSize: 1 << 46,
    FileSize: nkfs::FILE_BYTES as i64,
    ValidDataLength: nkfs::FILE_BYTES as i64,
};

/// A body for `except::raises`: cache the file object at `file` again
/// with sizes its section cannot be extended to.
extern "C" fn initialize_huge(file: usize) {
    // SAFETY: a cached nkfs file object.
    unsafe {
        entry::nk_entry_CcInitializeCacheMap(
            file as *mut c_void,
            (&raw const HUGE).cast(),
            1,
            (&raw const CALLBACKS).cast(),
            core::ptr::null_mut(),
        )
    }
}

/// Calls of the fast-I/O flush routines: acquisitions in the low four
/// bits, releases in the next four.
static ACQUIRED: AtomicUsize = AtomicUsize::new(0);

/// `AcquireForCcFlush`.
///
/// # Safety
/// Takes any arguments.
unsafe extern "C" fn acquire_for_flush(_: *mut FILE_OBJECT, _: *mut c_void) -> NTSTATUS {
    ACQUIRED.fetch_add(1, Ordering::Relaxed);
    STATUS_SUCCESS
}

/// `ReleaseForCcFlush`.
///
/// # Safety
/// Takes any arguments.
unsafe extern "C" fn release_for_flush(_: *mut FILE_OBJECT, _: *mut c_void) -> NTSTATUS {
    ACQUIRED.fetch_add(0x10, Ordering::Relaxed);
    STATUS_SUCCESS
}

/// The tests' fast-I/O table: only the flush routines.
static FAST_IO: crate::test::Slot<FAST_IO_DISPATCH> = crate::test::Slot::new();

/// The file the raise test maps, for its body.
static RAISING_FILE: AtomicUsize = AtomicUsize::new(0);

/// A body for `except::raises`: map the page at `offset` and wait.
extern "C" fn map_raising(offset: usize) {
    let file = RAISING_FILE.load(Ordering::Relaxed) as *mut FILE_OBJECT;
    let (_, handle, _) = map(file, offset as i64, 0x200, MAP_WAIT);
    unpin(handle);
}

fn run(verdicts: &mut Verdicts) -> Result<(), &'static str> {
    let volume = Volume::new()?;
    let file = volume.file;
    let sop = volume.sop();
    initialize(file, true);
    // SAFETY: nkfs's file object and pointers.
    let (scm, pcm, data) = unsafe {
        (
            (*sop).SharedCacheMap,
            (*file).PrivateCacheMap,
            (*sop).DataSectionObject,
        )
    };
    let mapped = (|| {
        if scm.is_null() || pcm.is_null() || data.is_null() {
            return Err("caching the file did not set its shared and private maps and section");
        }
        let (ok, handle, buffer) = map(file, 0x1000, 0x200, MAP_WAIT);
        if ok != 1 || handle & 1 == 0 {
            return Err("CcMapData did not return TRUE with a view's handle (bit 0 set)");
        }
        if !holds_pattern(buffer, 0x1000, 0x200) {
            unpin(handle);
            return Err("a mapped range does not hold the file's bytes");
        }
        let log = nkfs::take_log();
        unpin(handle);
        match reads(&log).next() {
            Some(r) if r.offset == 0x1000 => Ok(()),
            _ => Err("mapping a range did not read its page from the file"),
        }
    })();
    verdicts.push(("cc.map", mapped));

    let nowait = (|| {
        let (ok, handle, buffer) = map(file, 0x42000, 0x100, 0);
        if ok != 0 || handle != 0x5A5A || buffer != 0 {
            if ok != 0 {
                unpin(handle);
            }
            return Err(
                "CcMapData without waiting on a page not in memory did not return FALSE, \
                        leaving the handle and clearing the buffer",
            );
        }
        if reads(&nkfs::take_log()).next().is_some() {
            return Err("CcMapData without waiting read the file");
        }
        Ok(())
    })();
    verdicts.push(("cc.map-nowait", nowait));

    nkfs::fail_read_at(Some(0x80000));
    RAISING_FILE.store(file.addr(), Ordering::Relaxed);
    let raised = except::raises(map_raising, 0x80000, STATUS_DEVICE_DATA_ERROR as u32);
    nkfs::fail_read_at(None);
    nkfs::take_log();
    verdicts.push(("cc.map-error", raised));

    let pinned = (|| {
        let (ok, bcb, buffer) = pin(file, 0x3010, 0x100, PIN_WAIT);
        if ok != 1 || bcb & 1 != 0 {
            return Err("CcPinRead did not return TRUE with a BCB");
        }
        // SAFETY: a BCB handle points at its node type.
        let node = unsafe { (bcb as *const u16).read() };
        let (again_ok, again, _) = pin(file, 0x3080, 0x10, PIN_WAIT);
        let same = again_ok == 1 && again == bcb;
        if again_ok == 1 {
            unpin(again);
        }
        // SAFETY: a pinned BCB.
        let owner = unsafe { cc::pin::CcGetFileObjectFromBcb(bcb as *mut c_void) };
        let good = holds_pattern(buffer, 0x3010, 0x100);
        unpin(bcb);
        nkfs::take_log();
        if node != 0x2FD {
            Err("a BCB's node type is not 0x2FD")
        } else if !same {
            Err("a pin inside a pinned range did not get the same BCB")
        } else if owner != file {
            Err("CcGetFileObjectFromBcb did not give the file object that cached the file")
        } else if !good {
            Err("a pinned range does not hold the file's bytes")
        } else {
            Ok(())
        }
    })();
    verdicts.push(("cc.pin", pinned));

    // A repinned dirty BCB written through: the range's page is written
    // with paging I/O, and the BCB is clean.
    let through = (|| {
        let (ok, bcb, buffer) = pin(file, 0x6000, 0x20, PIN_WAIT | PIN_EXCLUSIVE);
        if ok != 1 {
            return Err("CcPinRead failed");
        }
        // SAFETY: the pinned range.
        unsafe { core::ptr::write_bytes(buffer as *mut u8, 0xC5, 0x20) };
        // SAFETY: a pinned BCB.
        unsafe {
            cc::pin::CcSetDirtyPinnedData(bcb as *mut c_void, core::ptr::null());
            cc::pin::CcRepinBcb(bcb as *mut c_void);
        }
        unpin(bcb);
        // SAFETY: nkfs's map, live while cached.
        let dirty = unsafe { (*cc::scm_of(file)).dirty_pages.get() };
        nkfs::take_log();
        let mut iosb = IO_STATUS_BLOCK {
            Status: STATUS_PENDING,
            Information: 0,
        };
        // SAFETY: the repinned BCB; a status block on this stack.
        unsafe { cc::pin::CcUnpinRepinnedBcb(bcb as *mut c_void, 1, &raw mut iosb) };
        let log = nkfs::take_log();
        let held = nkfs::held_at_write();
        // SAFETY: as above.
        let after = unsafe { (*cc::scm_of(file)).dirty_pages.get() };
        let written = log
            .iter()
            .any(|r| r.major == IRP_MJ_WRITE && r.offset == 0x6000 && r.cache_manager_active);
        if dirty != 1 {
            Err("a dirty pinned page is not one dirty page of the map")
        } else if iosb.Status != STATUS_SUCCESS {
            Err("CcUnpinRepinnedBcb's write-through failed")
        } else if !written || nkfs::data()[0x6000..0x6020] != [0xC5; 0x20] {
            Err("CcUnpinRepinnedBcb did not write the range through to the file")
        } else if after != 0 {
            Err("a range written through is still dirty")
        } else if held != (true, true) {
            Err(
                "with no fast-I/O routine, the write did not hold the main resource exclusive \
                 and the paging resource shared",
            )
        } else {
            Ok(())
        }
    })();
    verdicts.push(("cc.pin-write-through", through));

    // With the file system's own routines, those take the file for the
    // flush, and the header's resources are left alone.
    let fast = (|| {
        let table = FAST_IO.ptr();
        // SAFETY: the test's own table, nobody else's until set.
        unsafe {
            core::ptr::write_bytes(table, 0, 1);
            (*table).SizeOfFastIoDispatch = size_of::<FAST_IO_DISPATCH>() as u32;
            // AcquireForCcFlush and ReleaseForCcFlush, at 0xD0 and 0xD8.
            (*table).Routines[25] = acquire_for_flush as *mut c_void;
            (*table).Routines[26] = release_for_flush as *mut c_void;
        }
        volume.set_fast_io(table);
        ACQUIRED.store(0, Ordering::Relaxed);
        let (ok, bcb, _) = pin(file, 0x7000, 0x20, PIN_WAIT);
        if ok != 1 {
            return Err("CcPinRead failed");
        }
        // SAFETY: a pinned BCB.
        unsafe {
            cc::pin::CcSetDirtyPinnedData(bcb as *mut c_void, core::ptr::null());
            cc::pin::CcRepinBcb(bcb as *mut c_void);
        }
        unpin(bcb);
        let mut iosb = IO_STATUS_BLOCK {
            Status: STATUS_PENDING,
            Information: 0,
        };
        // SAFETY: the repinned BCB; a status block on this stack.
        unsafe { cc::pin::CcUnpinRepinnedBcb(bcb as *mut c_void, 1, &raw mut iosb) };
        volume.set_fast_io(core::ptr::null_mut());
        nkfs::take_log();
        let held = nkfs::held_at_write();
        match ACQUIRED.load(Ordering::Relaxed) {
            0x11 if held == (false, false) && iosb.Status == STATUS_SUCCESS => Ok(()),
            0x11 => Err("with the file system's routines, the header's resources were taken too"),
            _ => Err("AcquireForCcFlush and ReleaseForCcFlush were not each called once"),
        }
    })();
    verdicts.push(("cc.flush-acquire", fast));

    // A page overwritten whole is not read, starts zeroed and is dirty.
    let prepared = (|| {
        let offset = 0x60000i64;
        let (mut bcb, mut buffer) = (0usize, 0usize);
        // SAFETY: a cached nkfs file; outputs on this stack.
        let ok = unsafe {
            entry::nk_entry_CcPreparePinWrite(
                file.cast(),
                &raw const offset,
                0x1000,
                1,
                PIN_WAIT,
                (&raw mut bcb).cast(),
                (&raw mut buffer).cast(),
            )
        };
        if ok != 1 {
            return Err("CcPreparePinWrite failed");
        }
        let read = reads(&nkfs::take_log()).next().is_some();
        // SAFETY: the pinned page.
        let zeroed = (0..0x1000).all(|i| unsafe { ((buffer + i) as *const u8).read() } == 0);
        // SAFETY: nkfs's map.
        let dirty = unsafe { (*cc::scm_of(file)).dirty_pages.get() };
        // SAFETY: a pinned BCB; write it out to leave the map clean.
        unsafe { cc::pin::CcRepinBcb(bcb as *mut c_void) };
        unpin(bcb);
        let mut iosb = IO_STATUS_BLOCK {
            Status: STATUS_PENDING,
            Information: 0,
        };
        // SAFETY: as above.
        unsafe { cc::pin::CcUnpinRepinnedBcb(bcb as *mut c_void, 1, &raw mut iosb) };
        nkfs::take_log();
        if read {
            Err("CcPreparePinWrite of a whole page read it")
        } else if !zeroed {
            Err("CcPreparePinWrite with Zero did not zero the range")
        } else if dirty != 1 {
            Err("CcPreparePinWrite did not leave the range dirty")
        } else if nkfs::data()[0x60000..0x61000].iter().any(|&b| b != 0) {
            Err("the zeroed page did not reach the file")
        } else {
            Ok(())
        }
    })();
    verdicts.push(("cc.prepare-pin-write", prepared));

    // Two file objects cache the file: the first one's uninitialize keeps
    // the map, the second deletes it and signals both events, once.
    // A cache map that cannot be extended for a second caller raises,
    // and gives back every block the call took.
    let before = crate::mm::pool::usage();
    let raised = except::raises(
        initialize_huge,
        file.addr(),
        STATUS_INSUFFICIENT_RESOURCES as u32,
    );
    let after = crate::mm::pool::usage();
    verdicts.push((
        "cc.initialize-extend-fails",
        raised.and(if after.blocks == before.blocks {
            Ok(())
        } else {
            Err("a failed CcInitializeCacheMap kept pool blocks")
        }),
    ));

    let uninit = (|| {
        let (handle, second) = volume.open_another()?;
        initialize(second, true);
        // SAFETY: zeroed events are initialised before use.
        let mut events: [CACHE_UNINITIALIZE_EVENT; 2] = unsafe { core::mem::zeroed() };
        for e in &mut events {
            // SAFETY: the event on this stack.
            unsafe { crate::ke::wait::KeInitializeEvent(&raw mut e.Event, 0, 0) };
        }
        let state = |e: &mut CACHE_UNINITIALIZE_EVENT| {
            // SAFETY: the event on this stack.
            unsafe { crate::ke::wait::KeReadStateEvent(&raw mut e.Event) }
        };
        // SAFETY: cached file objects; events on this stack, signalled
        // before it ends (the map is deleted below).
        let first =
            unsafe { cc::map::CcUninitializeCacheMap(file, core::ptr::null(), &raw mut events[0]) };
        let kept = state(&mut events[0]) == 0;
        // SAFETY: as above.
        let last = unsafe {
            cc::map::CcUninitializeCacheMap(second, core::ptr::null(), &raw mut events[1])
        };
        let both = state(&mut events[0]) != 0 && state(&mut events[1]) != 0;
        // SAFETY: nkfs's pointers.
        let (scm, pcm) = unsafe { ((*sop).SharedCacheMap, (*second).PrivateCacheMap) };
        nkfs::close_another(handle, second);
        if first != 0 || !kept {
            Err("uninitializing one of two file objects deleted the map or signalled its event")
        } else if last != 1 || !both {
            Err("uninitializing the last file object did not delete the map and signal both events")
        } else if !scm.is_null() || !pcm.is_null() {
            Err("SharedCacheMap or PrivateCacheMap is set after the map was deleted")
        } else {
            Ok(())
        }
    })();
    verdicts.push(("cc.uninitialize", uninit));
    copies(&volume, verdicts)?;
    // The file's pages go before the volume does.
    flush::purge_section(sop, None, true);
    drop(volume);
    Ok(())
}

/// `CcCopyReadEx`: the result and the status block.
fn copy_read(
    file: *mut FILE_OBJECT,
    offset: i64,
    buffer: &mut [u8],
    wait: bool,
) -> (u8, IO_STATUS_BLOCK) {
    let mut iosb = IO_STATUS_BLOCK {
        Status: STATUS_PENDING,
        Information: 0,
    };
    // SAFETY: a cached nkfs file; the buffer and block on the caller's
    // stack.
    let ok = unsafe {
        entry::nk_entry_CcCopyReadEx(
            file.cast(),
            &raw const offset,
            buffer.len() as u32,
            u8::from(wait),
            buffer.as_mut_ptr().cast(),
            (&raw mut iosb).cast(),
            core::ptr::null_mut(),
        )
    };
    (ok, iosb)
}

/// `CcCopyWrite`, waiting.
fn copy_write(file: *mut FILE_OBJECT, offset: i64, bytes: &[u8]) -> u8 {
    // SAFETY: as in `copy_read`.
    unsafe {
        entry::nk_entry_CcCopyWrite(
            file.cast(),
            &raw const offset,
            bytes.len() as u32,
            1,
            bytes.as_ptr().cast(),
        )
    }
}

/// `CcFlushCache` of the whole file.
fn flush_all(sop: *mut SECTION_OBJECT_POINTERS) -> IO_STATUS_BLOCK {
    let mut iosb = IO_STATUS_BLOCK {
        Status: STATUS_PENDING,
        Information: 0,
    };
    // SAFETY: nkfs's pointers; a block on this stack.
    unsafe { cc::flush::CcFlushCache(sop, core::ptr::null(), 0, &raw mut iosb) };
    iosb
}

fn dirty_pages(file: *mut FILE_OBJECT) -> u64 {
    // SAFETY: nkfs's cached file's map.
    unsafe { (*cc::scm_of(file)).dirty_pages.get() }
}

/// The copy, flush, size and MDL interfaces on a file cached for copying.
fn copies(volume: &Volume, verdicts: &mut Verdicts) -> Result<(), &'static str> {
    let file = volume.file;
    let sop = volume.sop();
    initialize(file, false);
    nkfs::take_log();

    let read = (|| {
        let mut buffer = [0u8; 0x3000];
        let (ok, iosb) = copy_read(file, 0x20100, &mut buffer, true);
        if ok != 1 || iosb.Status != STATUS_SUCCESS || iosb.Information != 0x3000 {
            return Err("CcCopyReadEx did not return TRUE with the length read");
        }
        if (0..buffer.len()).any(|i| buffer[i] != nkfs::pattern(0x20100 + i)) {
            return Err("CcCopyReadEx did not copy the file's bytes");
        }
        let mut other = [0u8; 0x10];
        let (ok, iosb) = copy_read(file, 0x2A0000, &mut other, false);
        if ok != 0 || iosb.Status != STATUS_PENDING {
            return Err(
                "CcCopyReadEx without waiting on a page not in memory did not return \
                        FALSE, leaving the status block",
            );
        }
        Ok(())
    })();
    nkfs::take_log();
    verdicts.push(("cc.copy-read", read));

    // A write into part of a valid page reads it; the flush writes it and
    // leaves the file clean; the volume has no dirty data after.
    let write = (|| {
        if copy_write(file, 0x30080, &[0xA7; 0x100]) != 1 {
            return Err("CcCopyWrite failed");
        }
        let read = reads(&nkfs::take_log()).any(|r| r.offset == 0x30000);
        let dirty = dirty_pages(file);
        // SAFETY: nkfs's file has no volume parameter block.
        let any = unsafe { cc::flush::CcIsThereDirtyData(core::ptr::null_mut()) };
        let iosb = flush_all(sop);
        let log = nkfs::take_log();
        // SAFETY: as above.
        let after = unsafe { cc::flush::CcIsThereDirtyData(core::ptr::null_mut()) };
        let written = log
            .iter()
            .any(|r| r.major == IRP_MJ_WRITE && r.offset == 0x30000);
        if !read {
            Err("a write into part of a valid page did not read it")
        } else if dirty != 1 || any != 1 {
            Err("a copied write did not leave one dirty page")
        } else if iosb.Status != STATUS_SUCCESS || !written {
            Err("CcFlushCache did not write the dirty page")
        } else if nkfs::data()[0x30080..0x30180] != [0xA7; 0x100]
            || nkfs::data()[0x3007F] != nkfs::pattern(0x3007F)
        {
            Err("the file does not hold the write after the flush")
        } else if dirty_pages(file) != 0 || after != 0 {
            Err("the file is still dirty after the flush")
        } else {
            Ok(())
        }
    })();
    verdicts.push(("cc.copy-write", write));

    // Beyond the valid data length nothing is read and the rest of the
    // page is zero.
    let beyond = {
        let fcb = volume.fcb();
        // SAFETY: nkfs's FCB header, the test's.
        unsafe { (*fcb).header.Common.ValidDataLength = 0x50000 };
        let ok = copy_write(file, 0x50800, &[0x3C; 0x10]);
        let read = reads(&nkfs::take_log()).next().is_some();
        flush_all(sop);
        nkfs::take_log();
        // SAFETY: as above.
        unsafe { (*fcb).header.Common.ValidDataLength = nkfs::FILE_BYTES as i64 };
        let data = nkfs::data();
        if ok != 1 {
            Err("CcCopyWrite failed")
        } else if read {
            Err("a write beyond the valid data length read the file")
        } else if data[0x50000..0x50800].iter().any(|&b| b != 0) || data[0x50800] != 0x3C {
            Err("the page beyond the valid data length is not zero around the write")
        } else {
            Ok(())
        }
    };
    verdicts.push(("cc.copy-write-beyond-valid", beyond));

    let mdl = (|| {
        let offset = 0x10000i64;
        let mut chain: *mut MDL = core::ptr::null_mut();
        let mut iosb = IO_STATUS_BLOCK {
            Status: STATUS_PENDING,
            Information: 0,
        };
        // SAFETY: a cached nkfs file; outputs on this stack.
        unsafe {
            entry::nk_entry_CcMdlRead(
                file.cast(),
                &raw const offset,
                0x2000,
                (&raw mut chain).cast(),
                (&raw mut iosb).cast(),
            )
        };
        if chain.is_null() || iosb.Information != 0x2000 {
            return Err("CcMdlRead gave no MDL or not the length");
        }
        // SAFETY: the locked MDL CcMdlRead gave.
        let va = unsafe {
            crate::io::mdl::MmMapLockedPagesSpecifyCache(chain, 0, 1, core::ptr::null_mut(), 0, 16)
        };
        let good = !va.is_null() && holds_pattern(va.addr(), 0x10000, 0x2000);
        // SAFETY: as above.
        unsafe {
            if !va.is_null() {
                crate::io::mdl::MmUnmapLockedPages(va, chain);
            }
            cc::mdl::CcMdlReadComplete(file, chain);
        }
        if !good {
            return Err("an MDL read's pages do not hold the file's bytes");
        }
        nkfs::take_log();
        let offset = 0x70000i64;
        let mut chain: *mut MDL = core::ptr::null_mut();
        // SAFETY: as above.
        unsafe {
            entry::nk_entry_CcPrepareMdlWrite(
                file.cast(),
                &raw const offset,
                0x1000,
                (&raw mut chain).cast(),
                (&raw mut iosb).cast(),
            )
        };
        let read = reads(&nkfs::take_log()).next().is_some();
        // SAFETY: nkfs's map.
        let open = unsafe { (*cc::scm_of(file)).open_count.get() };
        // SAFETY: the locked MDL; written through a system mapping.
        unsafe {
            let va = crate::io::mdl::MmMapLockedPagesSpecifyCache(
                chain,
                0,
                1,
                core::ptr::null_mut(),
                0,
                16,
            );
            if !va.is_null() {
                core::ptr::write_bytes(va.cast::<u8>(), 0x6E, 0x1000);
                crate::io::mdl::MmUnmapLockedPages(va, chain);
            }
            entry::nk_entry_CcMdlWriteComplete(file.cast(), &raw const offset, chain.cast());
        }
        let dirty = dirty_pages(file);
        flush_all(sop);
        nkfs::take_log();
        // SAFETY: as above.
        let after = unsafe { (*cc::scm_of(file)).open_count.get() };
        if read {
            Err("CcPrepareMdlWrite of a whole page read it")
        } else if open != 2 || after != 1 {
            Err("a prepared MDL write did not hold the map open until completed")
        } else if dirty != 1 || nkfs::data()[0x70000..0x71000] != [0x6E; 0x1000] {
            Err("a completed MDL write was not dirty and then written")
        } else {
            Ok(())
        }
    })();
    verdicts.push(("cc.mdl", mdl));

    let zero = {
        let (start, end) = (0x90000i64, 0x91000i64);
        // SAFETY: a cached nkfs file; offsets on this stack.
        let ok =
            unsafe { entry::nk_entry_CcZeroData(file.cast(), &raw const start, &raw const end, 1) };
        let read = reads(&nkfs::take_log()).next().is_some();
        let dirty = dirty_pages(file);
        flush_all(sop);
        nkfs::take_log();
        if ok != 1 || read || dirty != 1 {
            Err("CcZeroData of a whole page read it or did not leave it dirty")
        } else if nkfs::data()[0x90000..0x91000].iter().any(|&b| b != 0) {
            Err("the zeroed page did not reach the file")
        } else {
            Ok(())
        }
    };
    verdicts.push(("cc.zero", zero));

    // A purge fails while a view in the range is in use, then discards the
    // dirty data with the pages.
    let purge = {
        let (ok, handle, _) = map(file, 0xA0000, 0x10, MAP_WAIT);
        copy_write(file, 0xA1000, &[1; 0x10]);
        // SAFETY: nkfs's pointers.
        let busy = unsafe { cc::size::CcPurgeCacheSection(sop, core::ptr::null(), 0, 0) };
        if ok == 1 {
            unpin(handle);
        }
        // SAFETY: as above.
        let purged = unsafe { cc::size::CcPurgeCacheSection(sop, core::ptr::null(), 0, 0) };
        nkfs::take_log();
        let dirty = dirty_pages(file);
        let gone = matches!(flush::page_of_file(sop, 0xA1000), flush::FilePage::Absent);
        if busy != 0 {
            Err("a purge succeeded with a view in use")
        } else if purged != 1 || !gone {
            Err("a purge with no view in use did not discard the pages")
        } else if dirty != 0 {
            Err("a purge left dirty data")
        } else {
            Ok(())
        }
    };
    verdicts.push(("cc.purge", purge));

    // Shrinking the file takes back what lies beyond; growing the
    // allocation extends the section to a whole mebibyte.
    let sizes = {
        copy_write(file, 0x2F0000, &[2; 0x10]);
        let small = CC_FILE_SIZES {
            AllocationSize: nkfs::FILE_BYTES as i64,
            FileSize: 0x200000,
            ValidDataLength: 0x200000,
        };
        // SAFETY: a cached nkfs file; sizes on this stack.
        unsafe { entry::nk_entry_CcSetFileSizes(file.cast(), (&raw const small).cast()) };
        let dirty = dirty_pages(file);
        let big = CC_FILE_SIZES {
            AllocationSize: (4 << 20) + 1,
            FileSize: 0x200000,
            ValidDataLength: 0x200000,
        };
        // SAFETY: as above.
        let status = unsafe { cc::size::CcSetFileSizesEx(file, &raw const big) };
        // SAFETY: nkfs's map.
        let (section, size) = unsafe {
            let scm = &*cc::scm_of(file);
            (scm.section_size.get(), scm.file_size.get())
        };
        if dirty != 0 {
            Err("shrinking the file left dirty data beyond its end")
        } else if status != STATUS_SUCCESS || section != 5 << 20 || size != 0x200000 {
            Err("growing the allocation did not extend the section to a whole mebibyte")
        } else {
            Ok(())
        }
    };
    verdicts.push(("cc.sizes", sizes));

    let attributes = {
        // SAFETY: a cached nkfs file.
        unsafe { cc::size::CcSetAdditionalCacheAttributes(file, 1, 1) };
        // SAFETY: nkfs's map.
        let flags = unsafe { (*cc::scm_of(file)).flags.get() };
        // SAFETY: as above.
        unsafe { cc::size::CcSetAdditionalCacheAttributes(file, 0, 0) };
        // SAFETY: as above.
        let after = unsafe { (*cc::scm_of(file)).flags.get() };
        if flags & 0x203 != 0x203 || after & 0x3 != 0 || after & 0x200 == 0 {
            Err("disabling write-behind did not also disable modified writing, kept after")
        } else {
            Ok(())
        }
    };
    verdicts.push(("cc.attributes", attributes));

    // Dirty data is written by the lazy writer within the first delay
    // and a second, through the file system's callbacks.
    let lazy = {
        LAZY_ACQUIRED.store(0, Ordering::Relaxed);
        let ok = copy_write(file, 0xB0010, &[0x99; 0x20]);
        let interval: i64 = -45_000_000;
        // SAFETY: a due time on this stack.
        unsafe { crate::ke::wait::KeDelayExecutionThread(0, 0, &raw const interval) };
        let log = nkfs::take_log();
        let written = log
            .iter()
            .any(|r| r.major == IRP_MJ_WRITE && r.offset == 0xB0000 && r.cache_manager_active);
        if ok != 1 {
            Err("CcCopyWrite failed")
        } else if !written || nkfs::data()[0xB0010..0xB0030] != [0x99; 0x20] {
            Err("the lazy writer did not write the dirty page within 4.5 s")
        } else if LAZY_ACQUIRED.load(Ordering::Relaxed) == 0 {
            Err("the lazy writer did not take the file through AcquireForLazyWrite")
        } else if dirty_pages(file) != 0 {
            Err("the file is dirty after the lazy writer wrote it")
        } else {
            Ok(())
        }
    };
    verdicts.push(("cc.lazy-write", lazy));

    let deferred = {
        POSTED.store(0, Ordering::Relaxed);
        // SAFETY: a cached file; the post routine takes any contexts.
        let can = unsafe { cc::throttle::CcCanIWrite(file, 0x1000, 0, 0) };
        // SAFETY: as above.
        unsafe {
            cc::throttle::CcDeferWrite(
                file,
                posted as *const () as usize,
                7 as *mut c_void,
                core::ptr::null_mut(),
                0x1000,
                0,
            )
        };
        if can != 1 {
            Err("CcCanIWrite refused a small write with the cache clean")
        } else if POSTED.load(Ordering::Relaxed) != 7 {
            Err("CcDeferWrite did not call the post routine at once with the cache clean")
        } else {
            Ok(())
        }
    };
    verdicts.push(("cc.defer-write", deferred));

    // A file cached for copying and closed without a truncate size is
    // left to the lazy writer, which deletes its map and signals the
    // event.
    let close = {
        // SAFETY: a zeroed event, initialised before use.
        let mut event: CACHE_UNINITIALIZE_EVENT = unsafe { core::mem::zeroed() };
        // SAFETY: the event on this stack.
        unsafe { crate::ke::wait::KeInitializeEvent(&raw mut event.Event, 0, 0) };
        // SAFETY: a cached nkfs file; the event lives until signalled
        // (waited for below).
        let kept =
            unsafe { cc::map::CcUninitializeCacheMap(file, core::ptr::null(), &raw mut event) };
        // SAFETY: as above.
        let early = unsafe { crate::ke::wait::KeReadStateEvent(&raw mut event.Event) };
        let waited = cc::lazy::CcWaitForCurrentLazyWriterActivity();
        // SAFETY: as above.
        let late = unsafe { crate::ke::wait::KeReadStateEvent(&raw mut event.Event) };
        // SAFETY: nkfs's pointers.
        let scm = unsafe { (*sop).SharedCacheMap };
        if late == 0 {
            // The map holds the event: wait for it rather than leave it
            // on this stack.
            // SAFETY: as above.
            unsafe { crate::ke::wait::wait(Some((&raw mut event.Event).cast()), None) };
        }
        if kept != 0 || early != 0 {
            Err("closing a file cached for copying deleted its map at once")
        } else if waited != STATUS_SUCCESS || late == 0 || !scm.is_null() {
            Err("the lazy writer did not delete the closed map and signal its event")
        } else {
            Ok(())
        }
    };
    verdicts.push(("cc.lazy-close", close));
    Ok(())
}
