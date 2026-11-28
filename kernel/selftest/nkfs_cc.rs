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
        "cc.fast-read",
        "cc.fast-write",
        "cc.fast-mdl",
        "cc.lazy-write",
        "cc.defer-write",
        "cc.lazy-close",
        "cc.wait-twice",
        "cc.vacb-evict-race",
        "cc.lifecycle-race",
        "cc.pin-attribute-race",
        "cc.flush-inflight",
        "cc.copy-write-nowait-mixed",
        "cc.shutdown-drain",
        "cc.wait-lazy-barrier",
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
        let flags = unsafe { (*cc::scm_of(file)).flags() };
        // SAFETY: as above.
        unsafe { cc::size::CcSetAdditionalCacheAttributes(file, 0, 0) };
        // SAFETY: as above.
        let after = unsafe { (*cc::scm_of(file)).flags() };
        if flags & 0x203 != 0x203 || after & 0x3 != 0 || after & 0x200 == 0 {
            Err("disabling write-behind did not also disable modified writing, kept after")
        } else {
            Ok(())
        }
    };
    verdicts.push(("cc.attributes", attributes));
    fast_paths(volume, verdicts);

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

    // Exercise concurrent VACB eviction (recycling and `unmap_views`) against
    // waiting and no-wait lookups on another CPU while `file` is still cached.
    let evict_race = {
        // SAFETY: `file` is cached right now.
        let scm = unsafe { cc::cached(file, "cc.vacb-evict-race") };
        cc::vacb::evict_race_test(scm)
    };
    verdicts.push(("cc.vacb-evict-race", evict_race));

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
    verdicts.push(("cc.wait-twice", wait_twice()));
    verdicts.push(("cc.lifecycle-race", lifecycle_race(file, sop)));
    verdicts.push(("cc.pin-attribute-race", pin_attribute_race(file, sop)));
    verdicts.push(("cc.flush-inflight", flush_inflight_test(file, sop)));
    verdicts.push((
        "cc.copy-write-nowait-mixed",
        copy_write_nowait_mixed_test(file, sop),
    ));
    verdicts.push(("cc.shutdown-drain", shutdown_drain_test(volume)));
    verdicts.push(("cc.wait-lazy-barrier", wait_lazy_barrier_test(volume)));
    Ok(())
}

static FAULT_WRITE_FILE: core::sync::atomic::AtomicPtr<FILE_OBJECT> =
    core::sync::atomic::AtomicPtr::new(core::ptr::null_mut());
static FAULT_WRITE_BUF: AtomicUsize = AtomicUsize::new(0);

extern "C" fn copy_write_faulting_source(offset: usize) {
    let file = FAULT_WRITE_FILE.load(Ordering::Acquire);
    let buf = FAULT_WRITE_BUF.load(Ordering::Acquire) as *const u8;
    let off = offset as i64;
    // SAFETY: cached file and caller buffer whose second page is unmapped.
    unsafe {
        let _ = entry::nk_entry_CcCopyWriteEx(
            file.cast(),
            &raw const off,
            0x1100,
            1,
            buf.cast(),
            core::ptr::null_mut(),
        );
    }
}

/// A failed no-wait `CcCopyWriteEx` spanning a full page followed by a cold
/// partial page below VDL must neither modify the first page nor leave
/// untracked dirt; a faulting source buffer mid-write must leave any already
/// modified page accounted for in the dirty bitmap.
#[inline(never)]
fn copy_write_nowait_mixed_test(
    file: *mut FILE_OBJECT,
    sop: *mut SECTION_OBJECT_POINTERS,
) -> Result<(), &'static str> {
    initialize(file, false);
    // Ensure [0x80000, 0x82000) is clean and purged, then fault in only page
    // 0x80000 and purge 0x81000 so 0x80000 is resident while 0x81000 is cold.
    let base = 0x80000i64;
    let cold = 0x81000i64;
    // SAFETY: live `sop` and stack offsets.
    unsafe {
        cc::size::CcPurgeCacheSection(sop, &raw const base, 0x2000, 0);
    }
    let mut probe = [0u8; 0x10];
    let mut iosb = IO_STATUS_BLOCK {
        Status: STATUS_PENDING,
        Information: 0,
    };
    // SAFETY: cached file and stack buffers.
    let read_ok = unsafe {
        entry::nk_entry_CcCopyReadEx(
            file.cast(),
            &raw const base,
            probe.len() as u32,
            1,
            probe.as_mut_ptr().cast(),
            (&raw mut iosb).cast(),
            core::ptr::null_mut(),
        )
    };
    // SAFETY: live `sop` and stack offset.
    let purged_cold = unsafe { cc::size::CcPurgeCacheSection(sop, &raw const cold, 0x1000, 0) };
    if read_ok != 1 || purged_cold != 1 {
        let zero = 0i64;
        // SAFETY: cached file.
        unsafe { cc::map::CcUninitializeCacheMap(file, &raw const zero, core::ptr::null_mut()) };
        cc::lazy::CcWaitForCurrentLazyWriterActivity();
        return Err("could not prepare mixed resident/cold pages");
    }

    // 1. No-wait write of 0x1100 bytes (full page 0x80000 + partial cold page
    //    0x81000 < VDL) must fail cleanly without modifying 0x80000 or dirtying.
    let src = alloc::vec![0xE5_u8; 0x1100];
    // SAFETY: cached file and live source buffer.
    let wrote = unsafe {
        entry::nk_entry_CcCopyWriteEx(
            file.cast(),
            &raw const base,
            src.len() as u32,
            0,
            src.as_ptr().cast(),
            core::ptr::null_mut(),
        )
    };
    let dirty_after_nowait = dirty_pages(file);
    let mut check_buf = [0u8; 0x20];
    // SAFETY: cached file and stack buffer.
    let _ = unsafe {
        entry::nk_entry_CcCopyReadEx(
            file.cast(),
            &raw const base,
            check_buf.len() as u32,
            1,
            check_buf.as_mut_ptr().cast(),
            (&raw mut iosb).cast(),
            core::ptr::null_mut(),
        )
    };
    let unmodified = check_buf
        .iter()
        .enumerate()
        .all(|(i, &b)| b == nkfs::pattern(0x80000 + i));

    // 2. Source-buffer fault on page 2 after overwriting page 1 must leave
    //    page 1 tracked dirty so a whole-file flush writes it to disk.
    let user_va = 0x4000_1000_0000_u64;
    let mut verdict = if wrote != 0 {
        Err("no-wait CcCopyWriteEx succeeded across a cold partial page below VDL")
    } else if dirty_after_nowait != 0 {
        Err("failed no-wait CcCopyWriteEx left dirty pages marked")
    } else if !unmodified {
        Err("failed no-wait CcCopyWriteEx modified the first page before failing")
    } else {
        Ok(())
    };
    if verdict.is_ok() {
        if crate::mm::user::map_pages(user_va, 1).is_err() {
            verdict = Err("could not map user page for source-fault write test");
        } else {
            // SAFETY: freshly mapped writable user page.
            unsafe { core::ptr::write_bytes(user_va as *mut u8, 0x7C, 0x1000) };
            FAULT_WRITE_FILE.store(file, Ordering::Release);
            FAULT_WRITE_BUF.store(user_va as usize, Ordering::Release);
            let raised = except::raises(
                copy_write_faulting_source,
                base as usize,
                cc::STATUS_INVALID_USER_BUFFER as u32,
            );
            crate::mm::user::unmap_pages(user_va, 1);
            let dirty_after_fault = dirty_pages(file);
            flush_all(sop);
            if let Err(why) = raised {
                verdict = Err(why);
            } else if dirty_after_fault == 0 {
                verdict =
                    Err("faulting CcCopyWriteEx left modified page untracked in dirty bitmap");
            } else if nkfs::data()[0x80000..0x80020] != [0x7C; 0x20] {
                verdict = Err("whole-file flush did not write page modified before source fault");
            }
        }
    }

    nkfs::take_log();
    let zero = 0i64;
    // SAFETY: cached file.
    unsafe { cc::map::CcUninitializeCacheMap(file, &raw const zero, core::ptr::null_mut()) };
    cc::lazy::CcWaitForCurrentLazyWriterActivity();
    verdict
}

/// Synchronous whole-file and ranged `CcFlushCache` (as well as direct
/// `mm::flush::flush_section`) must wait for an in-flight write-behind or
/// concurrent paging write rather than returning early, and must surface an
/// error when that write fails.
#[inline(never)]
fn flush_inflight_test(
    file: *mut FILE_OBJECT,
    sop: *mut SECTION_OBJECT_POINTERS,
) -> Result<(), &'static str> {
    use crate::ke::thread;
    use core::sync::atomic::{AtomicBool, AtomicI32};

    struct FlushTask {
        sop: *mut SECTION_OBJECT_POINTERS,
        offset: Option<i64>,
        length: u32,
        direct_mm: bool,
        done: AtomicBool,
        status: AtomicI32,
    }

    fn run_flush(arg: usize) {
        // SAFETY: `arg` points to `FlushTask` on the test's stack until exit.
        let t = unsafe { &*(arg as *const FlushTask) };
        let status = if t.direct_mm {
            let range = t.offset.map(|o| (o as u64, t.length));
            flush::flush_section(t.sop, range, None).Status
        } else {
            let mut iosb = IO_STATUS_BLOCK {
                Status: STATUS_PENDING,
                Information: 0,
            };
            let off_val = t.offset.unwrap_or(0);
            let off_ptr = if t.offset.is_some() {
                &raw const off_val
            } else {
                core::ptr::null()
            };
            // SAFETY: live `sop`, stack `off_val` and `iosb`.
            unsafe { cc::flush::CcFlushCache(t.sop, off_ptr, t.length, &raw mut iosb) };
            iosb.Status
        };
        t.status.store(status, Ordering::Release);
        t.done.store(true, Ordering::Release);
    }

    initialize(file, false);
    // Helper: dirty one page at `offset`, trigger a background flush that
    // pauses inside `nkfs`, launch a synchronous flush task, verify it stays
    // blocked while the write is paused, release the write with `write_st`,
    // and return the synchronous flush's status.
    let run_case = |offset: i64,
                    sync_range: Option<(i64, u32)>,
                    direct_mm: bool,
                    write_st: NTSTATUS|
     -> Result<NTSTATUS, &'static str> {
        let marker = [0x6B_u8; 0x20];
        // SAFETY: cached file and stack buffer.
        let wrote = unsafe {
            entry::nk_entry_CcCopyWriteEx(
                file.cast(),
                &raw const offset,
                marker.len() as u32,
                1,
                marker.as_ptr().cast(),
                core::ptr::null_mut(),
            )
        };
        if wrote != 1 {
            return Err("CcCopyWriteEx failed in flush_inflight_test");
        }
        nkfs::arm_write_pause(offset as u64);
        let bg = FlushTask {
            sop,
            offset: None,
            length: 0,
            direct_mm: false,
            done: AtomicBool::new(false),
            status: AtomicI32::new(STATUS_PENDING),
        };
        let sync = FlushTask {
            sop,
            offset: sync_range.map(|(o, _)| o),
            length: sync_range.map_or(0, |(_, l)| l),
            direct_mm,
            done: AtomicBool::new(false),
            status: AtomicI32::new(STATUS_PENDING),
        };
        let before = thread::count();
        let t_bg = thread::create_referenced(
            run_flush,
            core::ptr::from_ref(&bg).addr(),
            thread::NORMAL_PRIORITY,
            thread::ANYWHERE,
        )?;
        // Wait until the background flush is paused inside nkfs's paging write
        // (run already removed from MBCB and `WRITE_IN_PROGRESS` set in MM).
        nkfs::wait_write_paused();

        let t_sync = thread::create_referenced(
            run_flush,
            core::ptr::from_ref(&sync).addr(),
            thread::NORMAL_PRIORITY,
            thread::ANYWHERE,
        )?;
        for _ in 0..32 {
            thread::yield_now();
        }
        let finished_early = sync.done.load(Ordering::Acquire);
        nkfs::release_write_pause(write_st);

        for t in [t_bg, t_sync] {
            // SAFETY: referenced thread objects.
            unsafe {
                crate::ke::wait::wait(Some(t.cast()), None);
                crate::ob::object::dereference(t.cast());
            }
        }
        thread::settle(before);
        if finished_early {
            return Err("synchronous flush returned before in-flight paging write completed");
        }
        Ok(sync.status.load(Ordering::Acquire))
    };

    let mut verdict = Ok(());
    // 1. Whole-file CcFlushCache waits for in-flight write (success).
    match run_case(0x70000, None, false, STATUS_SUCCESS) {
        Ok(st) if st == STATUS_SUCCESS => {}
        Ok(_) => verdict = Err("whole-file CcFlushCache failed after successful in-flight write"),
        Err(why) => verdict = Err(why),
    }
    // 2. Ranged CcFlushCache waits for in-flight write (success).
    if verdict.is_ok() {
        match run_case(0x71000, Some((0x71000, 0x1000)), false, STATUS_SUCCESS) {
            Ok(st) if st == STATUS_SUCCESS => {}
            Ok(_) => verdict = Err("ranged CcFlushCache failed after successful in-flight write"),
            Err(why) => verdict = Err(why),
        }
    }
    // 3. Direct MmFlushSection waits on WRITE_IN_PROGRESS even after MODIFIED
    //    was cleared by the first writer.
    if verdict.is_ok() {
        match run_case(0x72000, Some((0x72000, 0x1000)), true, STATUS_SUCCESS) {
            Ok(st) if st == STATUS_SUCCESS => {}
            Ok(_) => verdict = Err("direct MmFlushSection failed after successful in-flight write"),
            Err(why) => verdict = Err(why),
        }
    }
    // 4. Whole-file CcFlushCache surfaces error when the in-flight write fails.
    if verdict.is_ok() {
        nkfs::fail_writes_with(STATUS_DEVICE_DATA_ERROR);
        let res = run_case(0x73000, None, false, STATUS_DEVICE_DATA_ERROR);
        nkfs::fail_writes_with(STATUS_SUCCESS);
        match res {
            Ok(st) if nt_error(st) => {}
            Ok(_) => {
                verdict =
                    Err("synchronous CcFlushCache reported success after failed in-flight write");
            }
            Err(why) => verdict = Err(why),
        }
    }

    flush_all(sop);
    nkfs::take_log();
    let zero = 0i64;
    // SAFETY: cached file.
    unsafe { cc::map::CcUninitializeCacheMap(file, &raw const zero, core::ptr::null_mut()) };
    cc::lazy::CcWaitForCurrentLazyWriterActivity();
    verdict
}

/// Setting `MODIFIED_WRITE_DISABLED` via `CcSetAdditionalCacheAttributes`
/// while a BCB is pinned must not cause `CcUnpinData` to release a resource
/// that the pin never acquired; subsequent pins after unpinning pick up the
/// new policy cleanly.
fn pin_attribute_race(
    file: *mut FILE_OBJECT,
    sop: *mut SECTION_OBJECT_POINTERS,
) -> Result<(), &'static str> {
    initialize(file, false);
    // Pin while MODIFIED_WRITE_DISABLED is clear (no resource acquired).
    let (ok1, bcb1, buf1) = pin(file, 0x10000, 0x1000, PIN_WAIT);
    if ok1 != 1 || bcb1 == 0 || buf1 == 0 {
        let zero = 0i64;
        // SAFETY: cached file.
        unsafe { cc::map::CcUninitializeCacheMap(file, &raw const zero, core::ptr::null_mut()) };
        return Err("initial pin before attribute change failed");
    }
    // Turn MODIFIED_WRITE_DISABLED on while `bcb1` is still pinned.
    // SAFETY: cached file object.
    unsafe { cc::size::CcSetAdditionalCacheAttributes(file, 0, 1) };
    // Unpinning must NOT attempt to release an unowned resource.
    unpin(bcb1);

    // Pin again now that pin_count reached 0: this pin acquires the resource
    // and must release it cleanly on unpin.
    let (ok2, bcb2, buf2) = pin(file, 0x10000, 0x1000, PIN_WAIT);
    if ok2 != 1 || bcb2 == 0 || buf2 == 0 {
        let zero = 0i64;
        // SAFETY: cached file.
        unsafe { cc::map::CcUninitializeCacheMap(file, &raw const zero, core::ptr::null_mut()) };
        return Err("second pin after attribute change failed");
    }
    // SAFETY: pinned BCB handle.
    unsafe { cc::pin::CcSetDirtyPinnedData(bcb2 as *mut c_void, core::ptr::null()) };
    unpin(bcb2);
    flush_all(sop);
    nkfs::take_log();
    let zero = 0i64;
    // SAFETY: cached file.
    unsafe { cc::map::CcUninitializeCacheMap(file, &raw const zero, core::ptr::null_mut()) };
    cc::lazy::CcWaitForCurrentLazyWriterActivity();
    Ok(())
}

/// Exercise `CcPurgeCacheSection` and `CcFlushCache` racing with cache-map
/// creation, failed creation (`abandon`), immediate deletion, and map
/// replacement from multiple CPUs, plus dirty-data preservation across
/// uninitialization.
fn lifecycle_race(
    file: *mut FILE_OBJECT,
    sop: *mut SECTION_OBJECT_POINTERS,
) -> Result<(), &'static str> {
    use crate::ke::thread;
    use core::sync::atomic::{AtomicBool, AtomicU32};

    struct Shared {
        sop: *mut SECTION_OBJECT_POINTERS,
        stop: AtomicBool,
        purges: AtomicU32,
        flushes: AtomicU32,
        bad: AtomicBool,
    }

    fn purger(arg: usize) {
        // SAFETY: `arg` points to `Shared` on the test's stack until exit.
        let s = unsafe { &*(arg as *const Shared) };
        while !s.stop.load(Ordering::Acquire) {
            // SAFETY: `sop` belongs to the live nkfs volume for the whole test.
            unsafe {
                let _ = cc::size::CcPurgeCacheSection(s.sop, core::ptr::null(), 0, 0);
            }
            s.purges.fetch_add(1, Ordering::Relaxed);
            thread::yield_now();
        }
    }

    fn flusher(arg: usize) {
        // SAFETY: as above.
        let s = unsafe { &*(arg as *const Shared) };
        let mut iosb = IO_STATUS_BLOCK {
            Status: STATUS_PENDING,
            Information: 0,
        };
        while !s.stop.load(Ordering::Acquire) {
            // SAFETY: as above.
            unsafe {
                cc::flush::CcFlushCache(s.sop, core::ptr::null(), 0, &raw mut iosb);
            }
            if nt_error(iosb.Status) {
                s.bad.store(true, Ordering::Release);
            }
            s.flushes.fetch_add(1, Ordering::Relaxed);
            thread::yield_now();
        }
    }

    let shared = Shared {
        sop,
        stop: AtomicBool::new(false),
        purges: AtomicU32::new(0),
        flushes: AtomicU32::new(0),
        bad: AtomicBool::new(false),
    };
    let ptr = core::ptr::from_ref(&shared).addr();
    let before = thread::count();
    let t_purge =
        thread::create_referenced(purger, ptr, thread::NORMAL_PRIORITY, thread::ANYWHERE)?;
    let t_flush =
        thread::create_referenced(flusher, ptr, thread::NORMAL_PRIORITY, thread::ANYWHERE)?;

    let mut failed = None;
    let zero = 0i64;
    for round in 0..32 {
        if round % 4 == 0 {
            // Failed creation (`abandon`) while waiters contend on `sop`.
            if let Err(why) = except::raises(
                initialize_huge,
                file.addr(),
                STATUS_INSUFFICIENT_RESOURCES as u32,
            ) {
                failed = Some(why);
                break;
            }
        }
        initialize(file, true);
        thread::yield_now();
        // SAFETY: `file` is cached; `zero` lives on this stack.
        unsafe {
            cc::map::CcUninitializeCacheMap(file, &raw const zero, core::ptr::null_mut());
        }
        cc::lazy::CcWaitForCurrentLazyWriterActivity();
    }

    shared.stop.store(true, Ordering::Release);
    for t in [t_purge, t_flush] {
        // SAFETY: referenced thread objects.
        unsafe {
            crate::ke::wait::wait(Some(t.cast()), None);
            crate::ob::object::dereference(t.cast());
        }
    }
    thread::settle(before);
    cc::lazy::CcWaitForCurrentLazyWriterActivity();

    if let Some(why) = failed {
        return Err(why);
    }
    if shared.bad.load(Ordering::Acquire) {
        return Err("concurrent CcFlushCache failed during lifecycle transitions");
    }
    if shared.purges.load(Ordering::Relaxed) == 0 || shared.flushes.load(Ordering::Relaxed) == 0 {
        return Err("concurrent purger/flusher threads did not execute");
    }

    // Dirty-data preservation: write dirty data, uninitialize without truncate
    // (leaving deletion to lazy close), flush concurrently, and verify the
    // bytes reach disk and the map is cleanly deleted afterwards.
    initialize(file, false);
    let offset = 0x60000i64;
    let marker = [0xAB_u8; 0x20];
    // SAFETY: cached file and stack buffer.
    let wrote = unsafe {
        entry::nk_entry_CcCopyWriteEx(
            file.cast(),
            &raw const offset,
            marker.len() as u32,
            1,
            marker.as_ptr().cast(),
            core::ptr::null_mut(),
        )
    };
    let mut iosb = IO_STATUS_BLOCK {
        Status: STATUS_PENDING,
        Information: 0,
    };
    // SAFETY: cached file, live `sop`, stack `iosb`.
    unsafe {
        cc::map::CcUninitializeCacheMap(file, core::ptr::null(), core::ptr::null_mut());
        cc::flush::CcFlushCache(sop, core::ptr::null(), 0, &raw mut iosb);
    }
    cc::lazy::CcWaitForCurrentLazyWriterActivity();
    nkfs::take_log();
    // SAFETY: live `sop`.
    let leftover = unsafe { !(*sop).SharedCacheMap.is_null() };
    if wrote != 1 || nt_error(iosb.Status) {
        return Err("dirty write or flush failed during uninitialize");
    }
    if nkfs::data()[0x60000..0x60020] != marker {
        return Err("dirty data was lost across CcUninitializeCacheMap + CcFlushCache");
    }
    if leftover {
        return Err("shared cache map remained attached after lazy close");
    }
    Ok(())
}

/// A thread's call of `CcWaitForCurrentLazyWriterActivity`.
fn wait_on_a_thread(_: usize) {
    cc::lazy::CcWaitForCurrentLazyWriterActivity();
}

/// Two threads waiting for the lazy writer at once both return.
fn wait_twice() -> Result<(), &'static str> {
    let before = crate::ke::thread::count();
    let thread = crate::ke::thread::create_referenced(
        wait_on_a_thread,
        0,
        crate::ke::thread::NORMAL_PRIORITY,
        crate::ke::thread::ANYWHERE,
    )
    .map_err(|_| "no memory for a thread")?;
    cc::lazy::CcWaitForCurrentLazyWriterActivity();
    let timeout: i64 = -50_000_000;
    // SAFETY: the thread, referenced until here; the wait is for its end.
    let ended = unsafe { crate::ke::wait::wait(Some(thread.cast()), Some(timeout)) };
    if ended != STATUS_SUCCESS as u32 {
        return Err("a second waiter for the lazy writer did not return within 5 s");
    }
    // SAFETY: as above.
    unsafe { crate::ob::object::dereference(thread.cast()) };
    while crate::ke::thread::count() != before {
        crate::ke::thread::yield_now();
    }
    Ok(())
}

/// The fast-I/O paths of FsRtl over the cache, the file's fast I/O
/// possible.
fn fast_paths(volume: &Volume, verdicts: &mut Verdicts) {
    use crate::fsrtl::fastio;
    use nk_ntabi::cc::{FO_FILE_FAST_IO_READ, FO_FILE_MODIFIED};
    let file = volume.file;
    let sop = volume.sop();
    let fcb = volume.fcb();
    // SAFETY: nkfs's header, the test's.
    unsafe { (*fcb).header.Common.IsFastIoPossible = 1 };
    let mut iosb = IO_STATUS_BLOCK {
        Status: STATUS_PENDING,
        Information: 0,
    };
    let read = {
        let mut buffer = [0u8; 0x100];
        let offset = 0x40000i64;
        // SAFETY: a cached nkfs file; buffer and block on this stack.
        let ok = unsafe {
            fastio::FsRtlCopyRead(
                file,
                &raw const offset,
                0x100,
                1,
                0,
                buffer.as_mut_ptr().cast(),
                (&raw mut iosb).cast(),
                core::ptr::null_mut(),
            )
        };
        // SAFETY: nkfs's file object.
        let (flags, position) = unsafe { ((*file).Flags, (*file).CurrentByteOffset) };
        let good = (0..0x100).all(|i| buffer[i] == nkfs::pattern(0x40000 + i));
        let end = nkfs::FILE_BYTES as i64;
        let mut eof = IO_STATUS_BLOCK {
            Status: STATUS_PENDING,
            Information: 0,
        };
        // SAFETY: as above.
        let at_end = unsafe {
            fastio::FsRtlCopyRead(
                file,
                &raw const end,
                0x10,
                1,
                0,
                buffer.as_mut_ptr().cast(),
                &raw mut eof,
                core::ptr::null_mut(),
            )
        };
        // SAFETY: as above.
        unsafe { (*fcb).header.Common.IsFastIoPossible = 0 };
        // SAFETY: as above.
        let refused = unsafe {
            fastio::FsRtlCopyRead(
                file,
                &raw const offset,
                0x10,
                1,
                0,
                buffer.as_mut_ptr().cast(),
                &raw mut eof,
                core::ptr::null_mut(),
            )
        };
        // SAFETY: as above.
        unsafe { (*fcb).header.Common.IsFastIoPossible = 1 };
        nkfs::take_log();
        if ok != 1 || iosb.Information != 0x100 || !good {
            Err("FsRtlCopyRead did not read through the cache")
        } else if flags & FO_FILE_FAST_IO_READ == 0 || position != 0x40100 {
            Err("FsRtlCopyRead did not mark the file object and move its position")
        } else if at_end != 1 || eof.Status != STATUS_END_OF_FILE {
            Err("FsRtlCopyRead at the end of the file did not return TRUE with STATUS_END_OF_FILE")
        } else if refused != 0 {
            Err("FsRtlCopyRead read with fast I/O not possible")
        } else {
            Ok(())
        }
    };
    verdicts.push(("cc.fast-read", read));

    let write = {
        let offset = 0x41000i64;
        let bytes = [0x5D_u8; 0x10];
        // SAFETY: as above.
        let ok = unsafe {
            fastio::FsRtlCopyWrite(
                file,
                &raw const offset,
                0x10,
                1,
                0,
                bytes.as_ptr().cast_mut().cast(),
                (&raw mut iosb).cast(),
                core::ptr::null_mut(),
            )
        };
        // SAFETY: as above.
        let flags = unsafe { (*file).Flags };
        let beyond = nkfs::FILE_BYTES as i64 - 8;
        // SAFETY: as above.
        let past = unsafe {
            fastio::FsRtlCopyWrite(
                file,
                &raw const beyond,
                0x10,
                1,
                0,
                bytes.as_ptr().cast_mut().cast(),
                (&raw mut iosb).cast(),
                core::ptr::null_mut(),
            )
        };
        flush_all(sop);
        nkfs::take_log();
        if ok != 1 || flags & FO_FILE_MODIFIED == 0 {
            Err("FsRtlCopyWrite did not write through the cache and mark the file modified")
        } else if nkfs::data()[0x41000..0x41010] != bytes {
            Err("the file does not hold FsRtlCopyWrite's bytes after a flush")
        } else if past != 0 {
            Err("FsRtlCopyWrite wrote past the allocation size")
        } else {
            Ok(())
        }
    };
    verdicts.push(("cc.fast-write", write));

    let mdl = {
        let offset = 0x42000i64;
        let mut chain: *mut MDL = core::ptr::null_mut();
        // SAFETY: as above; the chain on this stack.
        let read = unsafe {
            fastio::FsRtlMdlReadDev(
                file,
                &raw const offset,
                0x1000,
                0,
                &raw mut chain,
                (&raw mut iosb).cast(),
                core::ptr::null_mut(),
            )
        };
        let got = !chain.is_null();
        // SAFETY: the chain the read gave.
        unsafe { fastio::FsRtlMdlReadCompleteDev(file, chain, core::ptr::null_mut()) };
        let mut chain: *mut MDL = core::ptr::null_mut();
        let offset = 0x43000i64;
        // SAFETY: as above.
        let prepared = unsafe {
            fastio::FsRtlPrepareMdlWriteDev(
                file,
                &raw const offset,
                0x1000,
                0,
                &raw mut chain,
                (&raw mut iosb).cast(),
                core::ptr::null_mut(),
            )
        };
        // SAFETY: the prepared chain, completed once.
        let completed = !chain.is_null()
            && unsafe {
                entry::nk_entry_FsRtlMdlWriteCompleteDev(
                    file.cast(),
                    &raw const offset,
                    chain.cast(),
                    core::ptr::null_mut(),
                )
            } == 1;
        let dirty = dirty_pages(file);
        flush_all(sop);
        nkfs::take_log();
        if read != 1 || !got {
            Err("FsRtlMdlReadDev gave no MDL")
        } else if prepared != 1 || !completed || dirty != 1 {
            Err("FsRtlPrepareMdlWriteDev and FsRtlMdlWriteCompleteDev did not leave the page dirty")
        } else {
            Ok(())
        }
    };
    verdicts.push(("cc.fast-mdl", mdl));
    // SAFETY: nkfs's header.
    unsafe { (*fcb).header.Common.IsFastIoPossible = 0 };
}

/// Initialize caching on an [`nkfs::ExtraFile`] with its exact size.
fn init_extra(extra: &nkfs::ExtraFile, size: i64) {
    let sizes = CC_FILE_SIZES {
        AllocationSize: size,
        FileSize: size,
        ValidDataLength: size,
    };
    // SAFETY: live extra file object with valid FCB header and SOP.
    unsafe {
        entry::nk_entry_CcInitializeCacheMap(
            extra.file.cast(),
            (&raw const sizes).cast(),
            0,
            (&raw const CALLBACKS).cast(),
            core::ptr::null_mut(),
        );
    }
}

/// Dirty one page at `offset` on `file` with byte pattern `fill`.
#[inline(never)]
fn dirty_extra_page(file: *mut FILE_OBJECT, offset: i64, fill: u8) -> bool {
    let page = alloc::vec![fill; 0x1000];
    // SAFETY: cached file and live buffer.
    unsafe {
        entry::nk_entry_CcCopyWriteEx(
            file.cast(),
            &raw const offset,
            page.len() as u32,
            1,
            page.as_ptr().cast(),
            core::ptr::null_mut(),
        ) == 1
    }
}

/// Cleanly flush, uninitialize and wait for teardown of a slice of
/// [`nkfs::ExtraFile`]s before they are dropped.
#[inline(never)]
fn teardown_extras(files: &[nkfs::ExtraFile]) -> Result<(), &'static str> {
    let zero = 0i64;
    for f in files {
        f.set_write_fail(0, STATUS_SUCCESS, 0);
        flush_all(f.sop());
        // SAFETY: live extra file.
        unsafe {
            cc::map::CcUninitializeCacheMap(f.file, &raw const zero, core::ptr::null_mut());
        }
    }
    let _ = cc::lazy::drain_dirty_for_shutdown();
    for f in files {
        // SAFETY: live extra file SOP.
        if unsafe { !(*f.sop()).SharedCacheMap.is_null() } {
            return Err("extra file shared cache map did not tear down cleanly");
        }
    }
    Ok(())
}

/// Shutdown multi-batch drain (>64 maps without timer sleep), transient
/// error recovery, bounded retries on persistent retryable errors with
/// dirty-bit preservation and fair traversal, immediate termination on
/// permanent/fatal errors, and partial-write progress resetting retries.
#[inline(never)]
fn shutdown_drain_test(volume: &Volume) -> Result<(), &'static str> {
    // 1. >64 dirty maps (70 maps) must all drain across >=2 immediate batches.
    {
        let mut files = Vec::with_capacity(70);
        for _ in 0..70 {
            files.push(volume.open_extra_file(0x4000)?);
        }
        for (i, f) in files.iter().enumerate() {
            init_extra(f, 0x4000);
            if !dirty_extra_page(f.file, 0, (i as u8).wrapping_add(1)) {
                let _ = teardown_extras(&files);
                return Err("CcCopyWriteEx failed while dirtying 70 maps");
            }
        }
        let summary = cc::lazy::drain_dirty_for_shutdown();
        let all_on_disk = files.iter().enumerate().all(|(i, f)| {
            let expected = (i as u8).wrapping_add(1);
            dirty_pages(f.file) == 0 && f.data()[..0x100].iter().all(|&b| b == expected)
        });
        teardown_extras(&files)?;
        if summary.batches < 2 {
            return Err("70 dirty maps did not span at least two SCAN_ROOM batches");
        }
        if summary.maps_flushed < 70
            || summary.failed_maps != 0
            || summary.remaining_dirty_pages != 0
        {
            return Err("shutdown drain summary did not report all 70 maps flushed cleanly");
        }
        if !all_on_disk {
            return Err("not all 70 dirty maps reached disk on shutdown drain");
        }
    }

    // 2. Transient retryable error (2 failures, 3rd attempt succeeds).
    {
        let f = volume.open_extra_file(0x4000)?;
        init_extra(&f, 0x4000);
        f.set_write_fail(2, STATUS_INSUFFICIENT_RESOURCES, 0);
        if !dirty_extra_page(f.file, 0, 0xA5) {
            let _ = teardown_extras(&[f]);
            return Err("could not dirty transient-error test file");
        }
        let summary = cc::lazy::drain_dirty_for_shutdown();
        let attempts = f.write_attempts();
        let successes = f.write_successes();
        let dirty = dirty_pages(f.file);
        let ok_bytes = f.data()[..0x100].iter().all(|&b| b == 0xA5);
        teardown_extras(&[f])?;
        if summary.failed_maps != 0 || summary.remaining_dirty_pages != 0 {
            return Err("transient-error file did not recover during shutdown drain");
        }
        if attempts != 3 || successes != 1 || dirty != 0 || !ok_bytes {
            return Err("transient-error recovery did not flush on the 3rd attempt");
        }
    }

    // 3. Persistent retryable error (64 failing maps ahead of 2 healthy maps):
    //    must flush healthy maps (fair traversal), bound retries to 3 per
    //    failing map, and preserve dirty bits on every failing map.
    {
        let mut healthy = Vec::with_capacity(2);
        for _ in 0..2 {
            healthy.push(volume.open_extra_file(0x4000)?);
        }
        let mut failing = Vec::with_capacity(64);
        for _ in 0..64 {
            failing.push(volume.open_extra_file(0x4000)?);
        }
        // Initialize healthy maps first, then failing maps so the 64 failing
        // maps sit at the head of `MASTER`'s list ahead of the healthy maps.
        for (i, f) in healthy.iter().enumerate() {
            init_extra(f, 0x4000);
            if !dirty_extra_page(f.file, 0, 0xC0 + i as u8) {
                let _ = teardown_extras(&healthy);
                let _ = teardown_extras(&failing);
                return Err("could not dirty healthy map");
            }
        }
        for (i, f) in failing.iter().enumerate() {
            init_extra(f, 0x4000);
            f.set_write_fail(u32::MAX, STATUS_INSUFFICIENT_RESOURCES, 0);
            if !dirty_extra_page(f.file, 0, 0x40 + (i as u8 & 0x3F)) {
                let _ = teardown_extras(&healthy);
                let _ = teardown_extras(&failing);
                return Err("could not dirty failing map");
            }
        }
        let summary = cc::lazy::drain_dirty_for_shutdown();
        let healthy_flushed = healthy.iter().enumerate().all(|(i, f)| {
            dirty_pages(f.file) == 0 && f.data()[..0x100].iter().all(|&b| b == 0xC0 + i as u8)
        });
        let failing_bounded_and_dirty = failing
            .iter()
            .all(|f| f.write_attempts() == 3 && dirty_pages(f.file) == 1);
        // Prove preserved dirty bits still flush once the failure clears.
        failing[0].set_write_fail(0, STATUS_SUCCESS, 0);
        flush_all(failing[0].sop());
        let recovered_after_clear = dirty_pages(failing[0].file) == 0
            && failing[0].data()[..0x100].iter().all(|&b| b == 0x40);
        teardown_extras(&failing)?;
        teardown_extras(&healthy)?;
        if !healthy_flushed {
            return Err("64 failing maps at head starved healthy maps behind them");
        }
        if !failing_bounded_and_dirty {
            return Err("failing maps were not bounded to 3 attempts with dirty bits preserved");
        }
        if summary.failed_maps != 64 || summary.remaining_dirty_pages != 64 {
            return Err("shutdown summary misreported persistent failing maps");
        }
        if !recovered_after_clear {
            return Err("preserved dirty bit did not flush after failure cleared");
        }
    }

    // 4. Permanent/fatal write error must terminate on attempt 1 without retries.
    {
        let f = volume.open_extra_file(0x4000)?;
        init_extra(&f, 0x4000);
        f.set_write_fail(u32::MAX, STATUS_MEDIA_WRITE_PROTECTED, 0);
        if !dirty_extra_page(f.file, 0, 0xEE) {
            let _ = teardown_extras(&[f]);
            return Err("could not dirty fatal-error file");
        }
        let summary = cc::lazy::drain_dirty_for_shutdown();
        let attempts = f.write_attempts();
        teardown_extras(&[f])?;
        if attempts != 1 || summary.failed_maps != 1 {
            return Err("fatal write error was retried unnecessarily or not counted");
        }
    }

    // 5. Partial-write progress resets the no-progress retry counter: page 0
    //    succeeds in batch 1 while page 2 persistently fails, so page 2 gets
    //    1 attempt in the progress batch plus 3 subsequent no-progress attempts.
    {
        let f = volume.open_extra_file(0x4000)?;
        init_extra(&f, 0x4000);
        f.set_write_fail(u32::MAX, STATUS_INSUFFICIENT_RESOURCES, 0x2000);
        if !dirty_extra_page(f.file, 0x0, 0x31) || !dirty_extra_page(f.file, 0x2000, 0x32) {
            let _ = teardown_extras(&[f]);
            return Err("could not dirty partial-progress file");
        }
        let summary = cc::lazy::drain_dirty_for_shutdown();
        let page0_ok = f.data()[..0x100].iter().all(|&b| b == 0x31);
        let page2_attempts = f.failed_range_attempts();
        let dirty = dirty_pages(f.file);
        teardown_extras(&[f])?;
        if !page0_ok {
            return Err("partial-write progress did not persist the healthy page");
        }
        if page2_attempts != 4 {
            return Err("partial-write progress did not reset the 3-attempt retry counter");
        }
        if dirty != 1 || summary.failed_maps != 1 || summary.remaining_dirty_pages != 1 {
            return Err("partial-write terminal failure did not preserve remaining dirty page");
        }
    }

    Ok(())
}

/// `CcWaitForCurrentLazyWriterActivity` must act as a completion barrier
/// for currently queued lazy-writer activity rather than looping until
/// newly dirtied data from unrelated writers is drained.
#[inline(never)]
fn wait_lazy_barrier_test(volume: &Volume) -> Result<(), &'static str> {
    use crate::ke::thread;
    use core::sync::atomic::AtomicBool;

    let file = volume.file;
    initialize(file, false);
    let extra = volume.open_extra_file(0x4000)?;
    init_extra(&extra, 0x4000);

    let offset = 0x90000i64;
    let marker = alloc::vec![0x9B_u8; 0x1000];
    // SAFETY: cached file and live buffer.
    let wrote = unsafe {
        entry::nk_entry_CcCopyWriteEx(
            file.cast(),
            &raw const offset,
            marker.len() as u32,
            1,
            marker.as_ptr().cast(),
            core::ptr::null_mut(),
        )
    };
    if wrote != 1 {
        let _ = teardown_extras(&[extra]);
        return Err("could not dirty main file for lazy barrier test");
    }

    static BARRIER_DONE: AtomicBool = AtomicBool::new(false);
    BARRIER_DONE.store(false, Ordering::Release);
    fn run_barrier(_: usize) {
        cc::lazy::CcWaitForCurrentLazyWriterActivity();
        BARRIER_DONE.store(true, Ordering::Release);
    }

    nkfs::arm_write_pause(offset as u64);
    let before = thread::count();
    let t = thread::create_referenced(run_barrier, 0, thread::NORMAL_PRIORITY, thread::ANYWHERE)
        .map_err(|_| "no memory for lazy barrier thread")?;
    nkfs::wait_write_paused();

    // Dirty an unrelated file AFTER the barrier's scan has already run.
    let dirtied_late = dirty_extra_page(extra.file, 0, 0x5E);
    nkfs::release_write_pause(STATUS_SUCCESS);

    let timeout: i64 = -50_000_000;
    // SAFETY: referenced thread, waited on before dereference.
    let waited = unsafe { crate::ke::wait::wait(Some(t.cast()), Some(timeout)) };
    // SAFETY: as above.
    unsafe { crate::ob::object::dereference(t.cast()) };
    while thread::count() != before {
        thread::yield_now();
    }

    let late_still_dirty = dirty_pages(extra.file) == 1;
    let main_on_disk = nkfs::data()[0x90000..0x90100].iter().all(|&b| b == 0x9B);
    let teardown_res = teardown_extras(&[extra]);
    let zero = 0i64;
    // SAFETY: cached file.
    unsafe { cc::map::CcUninitializeCacheMap(file, &raw const zero, core::ptr::null_mut()) };
    cc::lazy::CcWaitForCurrentLazyWriterActivity();
    nkfs::take_log();
    teardown_res?;

    if waited != STATUS_SUCCESS as u32 || !BARRIER_DONE.load(Ordering::Acquire) {
        return Err("CcWaitForCurrentLazyWriterActivity did not return promptly");
    }
    if !dirtied_late || !main_on_disk {
        return Err("queued lazy write did not reach disk before barrier returned");
    }
    if !late_still_dirty {
        return Err("CcWaitForCurrentLazyWriterActivity waited for data dirtied after its scan");
    }
    Ok(())
}
