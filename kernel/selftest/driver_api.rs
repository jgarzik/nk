//! Tests of routines drivers call that have no home in a larger test:
//! remove locks, the version report, looking a routine up by name, and
//! pool with quota.

use crate::io::remlock::*;
use crate::ke::{thread, time, wait};
use crate::mm::pool;
use crate::test::{Group, Report, Slot};
use core::sync::atomic::{AtomicU32, Ordering};
use nk_bootinfo::BootInfo;
use nk_ntabi::io::{IO_REMOVE_LOCK, OSVERSIONINFO_SIZE, RTL_OSVERSIONINFOEXW, UNICODE_STRING};
use nk_ntabi::status::STATUS_SUCCESS;

pub static GROUP: Group = Group {
    names: &[
        "io.remove-lock",
        "rtl.version",
        "mm.routine-address",
        "ex.pool-quota",
    ],
    run,
    manual: false,
};

static LOCK: Slot<IO_REMOVE_LOCK> = Slot::new();
static STAGE: AtomicU32 = AtomicU32::new(0);

fn acquire() -> i32 {
    // SAFETY: a static, initialised remove lock.
    unsafe {
        IoAcquireRemoveLockEx(
            LOCK.ptr(),
            core::ptr::null_mut(),
            core::ptr::null(),
            0,
            0x20,
        )
    }
}

fn release() {
    // SAFETY: a static remove lock the caller acquired.
    unsafe { IoReleaseRemoveLockEx(LOCK.ptr(), core::ptr::null_mut(), 0x20) };
}

/// Requests are counted in and out; removal waits for the ones still in
/// and turns away any that come after.
fn remove_lock() -> Result<(), &'static str> {
    fn holder(_: usize) {
        // Holds a count across the remover's wait, then lets go.
        STAGE.store(1, Ordering::Release);
        // SAFETY: no object is involved.
        unsafe { wait::wait(None, Some(-500_000)) };
        STAGE.store(2, Ordering::Release);
        release();
    }
    let before = thread::count();
    // SAFETY: static storage for a remove lock nothing uses.
    unsafe { IoInitializeRemoveLockEx(LOCK.ptr(), 0, 0, 0, 0x20) };
    if acquire() != STATUS_SUCCESS || acquire() != STATUS_SUCCESS {
        return Err("a remove lock refused a request before any removal");
    }
    release();
    // One count is this thread's; a second is handed to another thread.
    if acquire() != STATUS_SUCCESS {
        return Err("a remove lock refused a request before any removal");
    }
    STAGE.store(0, Ordering::Release);
    thread::create(holder, 0, thread::NORMAL_PRIORITY, thread::ANYWHERE)?;
    while STAGE.load(Ordering::Acquire) == 0 {
        thread::yield_now();
    }
    let started = time::interrupt_time();
    // SAFETY: a static remove lock this thread acquired.
    unsafe { IoReleaseRemoveLockAndWaitEx(LOCK.ptr(), core::ptr::null_mut(), 0x20) };
    if STAGE.load(Ordering::Acquire) != 2 || time::interrupt_time() - started < 300_000 {
        return Err("removal did not wait for the request still in progress");
    }
    if acquire() != STATUS_DELETE_PENDING {
        return Err("a request was let in after removal");
    }
    // Nothing else in progress: removal returns at once.
    // SAFETY: as above.
    unsafe {
        IoInitializeRemoveLockEx(LOCK.ptr(), 0, 0, 0, 0x20);
        acquire();
        IoReleaseRemoveLockAndWaitEx(LOCK.ptr(), core::ptr::null_mut(), 0x20);
    }
    let deadline = time::interrupt_time() + 20_000_000;
    while thread::count() != before && time::interrupt_time() < deadline {
        thread::yield_now();
    }
    Ok(())
}

/// The version reported is the reference machine's, in whichever of the
/// two structure sizes the caller declares, and no byte beyond it.
fn version() -> Result<(), &'static str> {
    for size in [
        OSVERSIONINFO_SIZE as usize,
        size_of::<RTL_OSVERSIONINFOEXW>(),
    ] {
        let mut raw = [0xEEu8; size_of::<RTL_OSVERSIONINFOEXW>()];
        let info = raw.as_mut_ptr().cast::<RTL_OSVERSIONINFOEXW>();
        // SAFETY: a local buffer of the larger structure's size.
        let (status, version) = unsafe {
            (&raw mut (*info).dwOSVersionInfoSize).write_unaligned(size as u32);
            let status = crate::rtl::RtlGetVersion(info);
            (
                status,
                [
                    (&raw const (*info).dwMajorVersion).read_unaligned(),
                    (&raw const (*info).dwMinorVersion).read_unaligned(),
                    (&raw const (*info).dwBuildNumber).read_unaligned(),
                    (&raw const (*info).dwPlatformId).read_unaligned(),
                ],
            )
        };
        if status != STATUS_SUCCESS || version != [10, 0, 19045, 2] {
            return Err("the version reported is not Windows 10.0.19045");
        }
        let untouched = raw[size..].iter().all(|&b| b == 0xEE);
        let extended = size == raw.len();
        if !untouched || (extended && raw[OSVERSIONINFO_SIZE as usize + 6] != 1) {
            return Err(
                "the version report wrote past the size given, or left the product type out",
            );
        }
    }
    Ok(())
}

/// A routine the kernel exports is found by name, at the address a
/// driver importing it is given; an unknown name gives null.
fn routine_address() -> Result<(), &'static str> {
    let find = |name: &str| {
        let mut wide: alloc::vec::Vec<u16> = name.encode_utf16().collect();
        let counted = UNICODE_STRING {
            Length: (wide.len() * 2) as u16,
            MaximumLength: (wide.len() * 2) as u16,
            Buffer: wide.as_mut_ptr(),
        };
        // SAFETY: a valid counted string.
        unsafe { crate::export::MmGetSystemRoutineAddress(&raw const counted) as u64 }
    };
    for name in [
        "KeSetEvent",
        "IofCompleteRequest",
        "KeStallExecutionProcessor",
    ] {
        let imported = crate::export::resolve(b"ntoskrnl.exe", name.as_bytes());
        if imported.is_none() || imported != Some(find(name)) {
            return Err("an exported routine was not found by name at its address");
        }
    }
    if find("NoSuchRoutineInAnyKernel") != 0 || find("kesetevent") != 0 || find("") != 0 {
        return Err("a name that is not an export was found");
    }
    Ok(())
}

/// Pool with quota is pool: allocated, usable, freed.
fn pool_quota() -> Result<(), &'static str> {
    let before = pool::usage().blocks;
    let block = pool::ExAllocatePoolWithQuotaTag(8, 100, u32::from_le_bytes(*b"Test")).cast::<u8>();
    if block.is_null() || pool::usage().blocks != before + 1 {
        return Err("a quota allocation did not allocate one block");
    }
    // SAFETY: a fresh block of 100 bytes, freed once.
    unsafe {
        block.write_bytes(0xA5, 100);
        pool::ExFreePoolWithTag(block.cast(), 0);
    }
    if pool::usage().blocks != before {
        return Err("a quota allocation was not freed");
    }
    Ok(())
}

fn run(r: &mut Report, _: &BootInfo) {
    r.check("io.remove-lock", remove_lock);
    r.check("rtl.version", version);
    r.check("mm.routine-address", routine_address);
    r.check("ex.pool-quota", pool_quota);
}
