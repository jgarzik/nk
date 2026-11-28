//! The user range of the System process: pages at addresses below
//! `MmUserProbeAddress`, in the low half of the address space.
//!
//! There is one address space, so the range is every thread's. Pages
//! are fresh zeroed frames, readable and writable by the kernel, not
//! executable, and not marked user-accessible: nothing runs in user
//! mode, and a kernel-only page is one the kernel can touch whether or
//! not the processor forbids it user pages (x86-64 SMAP, arm64 PAN;
//! NK enables neither).
//!
//! The low half also holds firmware's runtime regions at their physical
//! addresses, mapped and writable. They are not part of the user range:
//! a range that touches one is refused, to be mapped and by every probe
//! of a requestor's buffer. So is the lowest 64 KiB to be mapped, as on
//! Windows: a null pointer with a small offset faults.

use super::{PAGE_SIZE, alloc_frames, free_frames, map};
use nk_mm::pt::{MapError, Prot};

/// Windows' `MmUserProbeAddress`: the first address beyond the user
/// range. The same value on both architectures; either's low half is
/// larger.
pub const USER_PROBE_ADDRESS: u64 = 0x7FFF_FFFF_0000;
/// The lowest address of the user range.
pub const LOWEST_USER_ADDRESS: u64 = 0x1_0000;

/// A variable drivers import: one word, which they read through the
/// address their import is bound to and cannot write.
#[repr(transparent)]
pub struct Variable(u64);

impl Variable {
    /// The address drivers import.
    pub const fn address(&'static self) -> *const () {
        (&raw const self.0).cast()
    }
}

/// `MmUserProbeAddress`: the first address beyond the user range, which
/// a driver's in-line probes compare with.
#[allow(non_upper_case_globals)]
pub static MmUserProbeAddress: Variable = Variable(USER_PROBE_ADDRESS);

/// `MmHighestUserAddress`: the last byte of the user range, as Windows
/// x64 has it: the 64 KiB below `MmUserProbeAddress` are never part of
/// the range.
#[allow(non_upper_case_globals)]
pub static MmHighestUserAddress: Variable = Variable(USER_PROBE_ADDRESS - 0x1_0001);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UserError {
    /// Not whole pages inside the user range.
    BadRange,
    /// The range touches memory firmware's runtime services use.
    Firmware,
    /// A page of the range is already mapped.
    AlreadyMapped,
    NoMemory,
}

/// The end of the `pages` pages at `va`, if they are whole pages inside
/// the user range.
fn range_end(va: u64, pages: usize) -> Option<u64> {
    let len = u64::try_from(pages).ok()?.checked_mul(PAGE_SIZE as u64)?;
    let end = va.checked_add(len)?;
    let ok = pages != 0
        && va.is_multiple_of(PAGE_SIZE as u64)
        && va >= LOWEST_USER_ADDRESS
        && end <= USER_PROBE_ADDRESS;
    ok.then_some(end)
}

/// Whether any of the `len` bytes at `address`, a range that does not
/// wrap, are memory firmware's runtime services use.
fn firmware(address: u64, len: u64) -> bool {
    super::firmware_regions().any(|(region, _)| region.overlaps(address, len))
}

/// Whether the `pages` pages at `va` may hold user pages.
fn check(va: u64, pages: usize) -> Result<(), UserError> {
    let end = range_end(va, pages).ok_or(UserError::BadRange)?;
    if firmware(va, end - va) {
        return Err(UserError::Firmware);
    }
    Ok(())
}

/// Map `pages` zeroed pages at `va`. On failure nothing is left mapped.
pub fn map_pages(va: u64, pages: usize) -> Result<(), UserError> {
    check(va, pages)?;
    for page in 0..pages {
        let at = va + (page * PAGE_SIZE) as u64;
        let mapped = alloc_frames(1)
            .ok_or(UserError::NoMemory)
            .and_then(|frame| {
                map::map(at, frame, 1, Prot::RW).map_err(|e| {
                    free_frames(frame, 1);
                    match e {
                        MapError::AlreadyMapped => UserError::AlreadyMapped,
                        _ => UserError::NoMemory,
                    }
                })
            });
        if let Err(e) = mapped {
            release(va, page);
            return Err(e);
        }
    }
    Ok(())
}

/// Unmap the `pages` pages at `va` that `map_pages` mapped and free
/// their frames. Every processor drops the translations before the
/// frames can be used again. A range `map_pages` would have refused is a
/// kernel bug: what is mapped there is not this module's to free.
pub fn unmap_pages(va: u64, pages: usize) {
    assert!(
        check(va, pages).is_ok(),
        "unmap of {pages} pages at {va:#x}: not a user range"
    );
    release(va, pages);
}

fn release(va: u64, pages: usize) {
    for page in 0..pages {
        let at = va + (page * PAGE_SIZE) as u64;
        if let Some(frame) = frame_of(at) {
            // SAFETY: the region is being given up; nothing uses it.
            unsafe { map::unmap(at, 1) };
            free_frames(frame, 1);
        }
    }
}

/// The frame behind the page that holds `va`, an address in the user
/// range, if one is mapped there. A page of firmware's is not a user
/// page.
pub fn frame_of(va: u64) -> Option<u64> {
    let page = va & !(PAGE_SIZE as u64 - 1);
    if !(LOWEST_USER_ADDRESS..USER_PROBE_ADDRESS).contains(&va) || firmware(page, PAGE_SIZE as u64)
    {
        return None;
    }
    map::translate(va).map(|pa| pa & !(PAGE_SIZE as u64 - 1))
}

/// Whether the `len` bytes at `address` lie in the user range: what
/// Windows' `ProbeForRead` asks, and that none of them is firmware's,
/// which Windows has no need to ask. An empty range always does.
pub fn in_range(address: usize, len: usize) -> bool {
    if len == 0 {
        return true;
    }
    let user = address
        .checked_add(len)
        .is_some_and(|end| end as u64 <= USER_PROBE_ADDRESS);
    user && !firmware(address as u64, len as u64)
}

/// Read and write back one byte of every page of the `len` bytes at
/// `address`, a range in the user half: what Windows' `ProbeForWrite`
/// does after its range check. `Err` is the first fault.
pub fn probe_pages(address: usize, len: usize) -> Result<(), Fault> {
    if len == 0 {
        return Ok(());
    }
    let end = address + len;
    let mut at = address;
    while at < end {
        let byte = core::ptr::with_exposed_provenance_mut::<u8>(at);
        // SAFETY: a byte of the requestor's range, copied onto itself;
        // a fault is the result.
        unsafe { copy(byte, byte, 1) }?;
        at = (at & !(PAGE_SIZE - 1)) + PAGE_SIZE;
    }
    Ok(())
}

/// Where a copy met memory that is not there, and what it was doing:
/// `ke::seh::ACCESS_READ` or `ACCESS_WRITE`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Fault {
    pub address: u64,
    pub access: u64,
}

/// Copy `len` bytes from `from` to `to`, where either may be a
/// requestor's memory: unmapped, or not writable. Every access NK makes
/// to such memory is this one. A fault is the `Err`, not an exception;
/// bytes before it may have been copied.
///
/// # Safety
/// Whatever of the two ranges is mapped may be read and written by the
/// caller: the ranges are checked to be the requestor's, or are the
/// kernel's own.
pub unsafe fn copy(to: *mut u8, from: *const u8, len: usize) -> Result<(), Fault> {
    // SAFETY: per the contract.
    unsafe { crate::arch::seh::fault_copy(to, from, len) }
        .map_err(|(address, access)| Fault { address, access })
}

// ---- tests --------------------------------------------------------------

use crate::ke::{ipi, smp};
use core::sync::atomic::{AtomicU64, Ordering};

/// Where the tests map: the bottom and the top of the range.
const LOW: u64 = LOWEST_USER_ADDRESS;
const HIGH: u64 = USER_PROBE_ADDRESS - 2 * PAGE_SIZE as u64;

/// Pages map at both ends of the range, start zeroed, hold what is
/// written through them, and are the frames the tables name; unmapped,
/// the tables name nothing and the frames are back.
pub fn map_test() -> Result<(), &'static str> {
    // Page tables for the two places stay; make them before counting.
    for va in [LOW, HIGH] {
        map_pages(va, 2).map_err(|_| "cannot map user pages")?;
        unmap_pages(va, 2);
    }
    let before = super::free_frame_count();
    for va in [LOW, HIGH] {
        map_pages(va, 2).map_err(|_| "cannot map user pages")?;
        let second = va + PAGE_SIZE as u64;
        let (Some(a), Some(b)) = (frame_of(va + 0x123), frame_of(second)) else {
            return Err("the tables do not name a mapped user page");
        };
        // SAFETY: both pages were just mapped read-write and are this
        // test's own; the direct map aliases their frames.
        unsafe {
            let p = va as *mut u64;
            if p.read_volatile() != 0 || (second as *const u64).read_volatile() != 0 {
                return Err("a fresh user page is not zeroed");
            }
            p.write_volatile(0x1122_3344_5566_7788);
            (second as *mut u64).write_volatile(0x99AA_BBCC_DDEE_FF00);
            if p.read_volatile() != 0x1122_3344_5566_7788
                || super::phys_to_virt(a).cast::<u64>().read_volatile() != 0x1122_3344_5566_7788
                || super::phys_to_virt(b).cast::<u64>().read_volatile() != 0x99AA_BBCC_DDEE_FF00
            {
                return Err("a user page does not hold what was written to it");
            }
        }
        if super::free_frame_count() != before - 2 {
            return Err("two user pages did not take two frames");
        }
        unmap_pages(va, 2);
        if frame_of(va).is_some() || frame_of(second).is_some() {
            return Err("a user page is still mapped after unmap");
        }
        if super::free_frame_count() != before {
            return Err("unmapping user pages did not return their frames");
        }
    }
    Ok(())
}

/// Ranges outside the user range, ranges that touch firmware's memory
/// and pages already mapped are refused, and a refusal maps nothing.
pub fn refuse_test() -> Result<(), &'static str> {
    let page = PAGE_SIZE as u64;
    let bad = [
        (0, 1),
        (LOWEST_USER_ADDRESS - page, 2),
        (LOW + 1, 1),
        (LOW, 0),
        (USER_PROBE_ADDRESS - page, 2),
        (USER_PROBE_ADDRESS, 1),
        (0xFFFF_F880_0000_0000, 1),
        (LOW, usize::MAX),
    ];
    for (va, pages) in bad {
        if map_pages(va, pages) != Err(UserError::BadRange) {
            return Err("a range outside the user range was not refused");
        }
    }
    if frame_of(USER_PROBE_ADDRESS - page).is_some() {
        return Err("a refused range was left partly mapped");
    }

    // A firmware region inside the user range, and the page before it.
    let region = super::firmware_regions()
        .map(|(region, _)| region)
        .find(|r| r.phys > LOWEST_USER_ADDRESS && r.end() <= USER_PROBE_ADDRESS)
        .ok_or("firmware has no runtime region in the user range")?;
    for (va, pages) in [
        (region.phys, 1),
        (region.phys - page, 2),
        (region.end() - page, 2),
    ] {
        if map_pages(va, pages) != Err(UserError::Firmware) {
            return Err("a range over firmware's memory was not refused");
        }
    }
    if map::translate(region.phys) != Some(region.phys) {
        return Err("firmware's memory is no longer mapped at its own address");
    }

    // A page already mapped: refused, and the mapping before it undone.
    let before = super::free_frame_count();
    map_pages(HIGH + page, 1).map_err(|_| "cannot map a user page")?;
    let first = frame_of(HIGH + page);
    let again = map_pages(HIGH, 2);
    let kept = frame_of(HIGH + page) == first && frame_of(HIGH).is_none();
    unmap_pages(HIGH + page, 1);
    if again != Err(UserError::AlreadyMapped) {
        return Err("mapping a mapped user page was not refused");
    }
    if !kept {
        return Err("a refused mapping changed what was mapped");
    }
    if super::free_frame_count() != before {
        return Err("a refused mapping leaked frames");
    }
    Ok(())
}

/// What the other processor read, and where it read it.
static READ: AtomicU64 = AtomicU64::new(0);

fn read_there(va: usize) {
    // SAFETY: the caller mapped the page and waits for this routine.
    READ.store(
        unsafe { (va as *const u64).read_volatile() },
        Ordering::Release,
    );
}

/// A user page is every processor's: another one reads what this one
/// wrote. Returns the processor that read.
pub fn other_cpu_test() -> Result<usize, &'static str> {
    const VALUE: u64 = 0x0123_4567_89AB_CDEF;
    map_pages(HIGH, 1).map_err(|_| "cannot map a user page")?;
    // SAFETY: the page was just mapped read-write and is this test's.
    unsafe { (HIGH as *mut u64).write_volatile(VALUE) };
    let target = smp::online_count() - 1;
    READ.store(0, Ordering::Release);
    ipi::call_on(target, read_there, HIGH as usize);
    unmap_pages(HIGH, 1);
    if READ.load(Ordering::Acquire) != VALUE {
        return Err("another processor did not read what was written to a user page");
    }
    Ok(target)
}

/// A copy to or from memory that is not there fails, saying where and
/// how, without disturbing the system; between mapped pages it copies.
pub fn copy_test() -> Result<(), &'static str> {
    use crate::ke::seh::{ACCESS_READ, ACCESS_WRITE};
    let page = PAGE_SIZE as u64;
    map_pages(HIGH, 1).map_err(|_| "cannot map a user page")?;
    let mapped = HIGH as *mut u8;
    let source = [0x5Au8; 32];
    let mut sink = [0u8; 32];
    // SAFETY: the page was just mapped and is this test's; the buffers
    // are local; the unmapped page is the point.
    let results = unsafe {
        [
            copy(mapped, source.as_ptr(), 32),
            copy(sink.as_mut_ptr(), mapped.add(16), 16),
            // The last sixteen bytes of the page, then into the void.
            copy(sink.as_mut_ptr(), mapped.add(PAGE_SIZE - 16), 32),
            copy(mapped.add(PAGE_SIZE - 8), source.as_ptr(), 16),
            copy(sink.as_mut_ptr(), core::ptr::null(), 1),
        ]
    };
    // SAFETY: still mapped.
    let landed = unsafe { mapped.add(PAGE_SIZE - 8).cast::<u64>().read_volatile() };
    unmap_pages(HIGH, 1);
    let fault = |address, access| Err(Fault { address, access });
    if results[0].is_err() || results[1].is_err() {
        return Err("a copy between mapped pages failed");
    }
    if results[2] != fault(HIGH + page, ACCESS_READ) {
        return Err("a read that ran off a mapped page did not fail at the next page, as a read");
    }
    if results[3] != fault(HIGH + page, ACCESS_WRITE) {
        return Err("a write that ran off a mapped page did not fail at the next page, as a write");
    }
    if landed != 0x5A5A_5A5A_5A5A_5A5A {
        return Err("the bytes before a fault were not copied");
    }
    if results[4] != fault(0, ACCESS_READ) {
        return Err("a read of address zero did not fail there");
    }
    Ok(())
}
