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
//! addresses; a range that touches one is refused. So is the lowest
//! 64 KiB, as on Windows: a null pointer with a small offset faults.

use super::{PAGE_SIZE, alloc_frames, free_frames, map};
use nk_mm::pt::{MapError, Prot};

/// Windows' `MmUserProbeAddress`: the first address beyond the user
/// range. The same value on both architectures; either's low half is
/// larger.
pub const USER_PROBE_ADDRESS: u64 = 0x7FFF_FFFF_0000;
/// The lowest address of the user range.
pub const LOWEST_USER_ADDRESS: u64 = 0x1_0000;

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

/// Whether the `pages` pages at `va` may hold user pages.
fn check(va: u64, pages: usize) -> Result<(), UserError> {
    let end = range_end(va, pages).ok_or(UserError::BadRange)?;
    if super::firmware_regions().any(|(region, _)| region.overlaps(va, end - va)) {
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
            map::unmap(at, 1);
            free_frames(frame, 1);
        }
    }
}

/// The frame behind the page that holds `va`, an address in the user
/// range, if one is mapped there.
pub fn frame_of(va: u64) -> Option<u64> {
    if !(LOWEST_USER_ADDRESS..USER_PROBE_ADDRESS).contains(&va) {
        return None;
    }
    map::translate(va).map(|pa| pa & !(PAGE_SIZE as u64 - 1))
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
    if frame_of(region.phys) != Some(region.phys) {
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
