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
use nk_ntabi::io::{FILE_OBJECT, IO_STATUS_BLOCK, IRP_MJ_READ, IRP_MJ_WRITE};
use nk_ntabi::status::*;

pub static GROUPS: &[&Group] = &[&CC];

static CC: Group = Group {
    names: &[
        "cc.map",
        "cc.map-nowait",
        "cc.map-error",
        "cc.pin",
        "cc.pin-write-through",
        "cc.prepare-pin-write",
        "cc.uninitialize",
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

static CALLBACKS: CACHE_MANAGER_CALLBACKS = CACHE_MANAGER_CALLBACKS {
    AcquireForLazyWrite: Some(acquire),
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
        } else {
            Ok(())
        }
    })();
    verdicts.push(("cc.pin-write-through", through));

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
    // The file's pages go before the volume does.
    flush::purge_section(sop, None, true);
    drop(volume);
    Ok(())
}
