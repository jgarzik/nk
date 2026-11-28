//! The page-frame-number database (`nk_mm::pfn`) and the frame bitmap
//! beside it, behind one lock.
//!
//! The bitmap hands out frames, contiguous runs included; the database
//! records what each frame is. A frame the kernel takes (pool, stacks,
//! page tables, driver images) is active and owned by no section; a page
//! of a file is owned by its prototype PTE and lives on the lists when
//! nothing maps it. When the bitmap has no frame left, the oldest
//! standby page is taken from its file.
//!
//! The database is allocated once, at boot, from the bitmap: one entry
//! per frame up to the highest usable one.

use super::{PAGE_SIZE, phys_to_virt};
use crate::ke::spinlock::Guard as LockGuard;
use crate::ke::{Rank, SpinLock};
use nk_mm::frames::{FrameBitmap, Within};
use nk_mm::pfn::{Location, Pfn, PfnDb};

/// The allocator and the database.
pub struct Frames {
    pub bitmap: FrameBitmap<'static>,
    pub db: PfnDb<'static>,
}

/// Guards every PFN entry, the page lists, the frame bitmap, and what
/// lib/mm and doc/LOCKING.md say rank 60 guards.
pub static PFN: SpinLock<Option<Frames>> = SpinLock::new(Rank::Pfn, None);

/// The lock held: the allocator and the database.
pub type Guard = LockGuard<'static, Option<Frames>>;

/// Take the PFN lock. Stops the system if called before [`init`].
pub fn lock() -> Guard {
    PFN.lock()
}

/// What the lock guards, once [`init`] has run.
pub fn frames(guard: &mut Guard) -> &mut Frames {
    match guard.as_mut() {
        Some(frames) => frames,
        None => crate::kd::bugcheck(format_args!("the PFN database is used before it exists")),
    }
}

/// Build the database over the `nframes` frames `bitmap` tracks, in
/// frames taken from `bitmap`, and put both behind the lock.
pub fn init(mut bitmap: FrameBitmap<'static>, nframes: u64) -> Result<(), &'static str> {
    let pages = (nframes as usize * size_of::<Pfn>()).div_ceil(PAGE_SIZE);
    let first = bitmap
        .alloc(pages as u64)
        .ok_or("no room for the page-frame-number database")?;
    let base = phys_to_virt(first * PAGE_SIZE as u64).cast::<Pfn>();
    for pfn in 0..nframes {
        let entry = if bitmap.is_free(pfn) {
            Pfn::FREE
        } else {
            Pfn::IN_USE
        };
        // SAFETY: the run just allocated holds `nframes` entries, is in
        // the direct map, and nothing else will ever be given it.
        unsafe { base.add(pfn as usize).write(entry) };
    }
    // SAFETY: every entry was written above; the storage is this
    // database's for good.
    let entries = unsafe { core::slice::from_raw_parts_mut(base, nframes as usize) };
    *PFN.lock() = Some(Frames {
        bitmap,
        db: PfnDb::new(entries),
    });
    Ok(())
}

/// Take `count` frames where `within` allows, recording them as the
/// kernel's. When none are free, standby pages are taken from their
/// files ([`super::section::reclaim`]), oldest first, until the run can
/// be had or standby is empty. Returns the first frame number. Not
/// zeroed.
pub fn take(guard: &mut Guard, count: u64, within: Option<&Within>) -> Option<u64> {
    loop {
        let f = frames(guard);
        let run = match within {
            Some(within) => f.bitmap.alloc_within(count, within),
            None => f.bitmap.alloc(count),
        };
        if let Some(first) = run {
            for pfn in first..first + count {
                f.db.kernel_allocate(pfn);
            }
            return Some(first);
        }
        if !super::section::reclaim(guard) {
            return None;
        }
    }
}

/// Give back to the allocator a page of a section that the database
/// has released (`PfnDb::release`).
pub fn give_back_released(guard: &mut Guard, pfn: u64) {
    let freed = frames(guard).bitmap.dealloc(pfn, 1);
    assert!(freed, "a released frame {pfn:#x} was not allocated");
}

/// Total immediately reclaimable frames (`Free + Standby`).
pub fn free_plus_standby() -> u64 {
    let mut guard = lock();
    let f = frames(&mut guard);
    f.bitmap.free_frames() + f.db.count(Location::Standby)
}

/// Number of unmapped dirty frames waiting on `Location::Modified`.
pub fn modified_count() -> u64 {
    let mut guard = lock();
    frames(&mut guard).db.count(Location::Modified)
}

/// How many frames are free, and on standby, modified and
/// modified-no-write.
pub fn counts() -> [u64; 4] {
    let mut guard = lock();
    let f = frames(&mut guard);
    [
        f.bitmap.free_frames(),
        f.db.count(Location::Standby),
        f.db.count(Location::Modified),
        f.db.count(Location::ModifiedNoWrite),
    ]
}

/// Give back frames [`take`] handed out. A double free is a kernel bug.
pub fn give_back(guard: &mut Guard, first: u64, count: u64) {
    let f = frames(guard);
    let ok = f.bitmap.dealloc(first, count)
        && (first..first + count).all(|pfn| f.db.kernel_free(pfn).is_ok());
    assert!(
        ok,
        "free of frames not allocated: frame {first:#x} x{count}"
    );
}

/// The state of the frame at physical address `pa`: where it is, and
/// its reference and share counts.
pub fn state(pa: u64) -> (Location, u16, u32) {
    let mut guard = lock();
    let e = *frames(&mut guard).db.get(pa / PAGE_SIZE as u64);
    (e.location(), e.ref_count, e.share_count)
}

/// Check the database's invariants (`PfnDb::check`).
pub fn check() -> Result<(), &'static str> {
    let mut guard = lock();
    frames(&mut guard).db.check().map_err(|e| e.0)
}
