//! Per-process working-set trimmer (`MiWorkingSetManager`): ages user-mode
//! hardware `Accessed` bits on mapped data-file views and demotes cold (or
//! under memory pressure, active) PTEs back to `UserSwPte::Prototype`, moving
//! clean unmapped frames to `Location::Standby` and dirty frames to
//! `Location::Modified` (waking the mapped-page writer).

use super::PAGE_SIZE;
use super::pfn;
use super::space::AddressSpace;
use super::view::{self, UserSection};
use super::writer;
use crate::arch;
use crate::ps::{cid, process};
use core::cell::UnsafeCell;
use core::mem::MaybeUninit;
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use nk_mm::pt::Arch;
use nk_mm::pte::UserSwPte;
use nk_mm::vad::VadKind;
use nk_ntabi::ke::KEVENT;

/// Low-water threshold (`free + standby` frames) that triggers active trimming.
pub const LOW_WATER_FRAMES: u64 = 512; // 2 MiB
/// High-water threshold (`free + standby` frames) for background aging.
const HIGH_WATER_FRAMES: u64 = 1024; // 4 MiB
/// Priority 16 (`LOW_REALTIME_PRIORITY`), matching Windows' balance set manager.
const TRIMMER_PRIORITY: u8 = 16;

/// If `pte` has the hardware Accessed bit set (x86-64 bit 5), return the PTE
/// with Accessed cleared for two-hand clock aging; returns `None` otherwise
/// (arm64 AF is required to avoid Access Flag faults).
#[cfg(target_arch = "x86_64")]
#[inline]
fn age_pte(pte: u64) -> Option<u64> {
    const X64_ACCESSED: u64 = 1 << 5;
    ((pte & X64_ACCESSED) != 0).then_some(pte & !X64_ACCESSED)
}

#[cfg(not(target_arch = "x86_64"))]
#[inline]
fn age_pte(_pte: u64) -> Option<u64> {
    None
}

struct TrimEvent(UnsafeCell<MaybeUninit<KEVENT>>);

// SAFETY: initialized once in `init()` before starting the trimmer thread.
unsafe impl Sync for TrimEvent {}

static TRIM_EVENT: TrimEvent = TrimEvent(UnsafeCell::new(MaybeUninit::uninit()));
static STARTED: AtomicBool = AtomicBool::new(false);
static TRIMMED_PAGES: AtomicU64 = AtomicU64::new(0);

/// Start the working-set trimmer system thread. Called once during boot.
pub fn init() -> Result<(), &'static str> {
    if STARTED.swap(true, Ordering::AcqRel) {
        return Ok(());
    }
    // SAFETY: static event initialized once before the thread runs.
    unsafe {
        crate::ke::wait::KeInitializeEvent(TRIM_EVENT.0.get().cast(), 1, 0);
    }
    crate::ke::thread::create(
        trimmer_thread,
        0,
        TRIMMER_PRIORITY,
        crate::ke::thread::ANYWHERE,
    )
    .map(|_| ())
}

/// Total user mapped pages demoted back to `Prototype` by the trimmer.
#[allow(dead_code)]
pub fn trimmed_pages() -> u64 {
    TRIMMED_PAGES.load(Ordering::Acquire)
}

/// Trim up to `target_pages` resident data-file PTEs across `space`.
/// When `force_hot` is `false`, pages with the hardware `Accessed` bit set have
/// their `Accessed` bit cleared instead of being evicted on the first pass.
fn trim_space(space: &AddressSpace, target_pages: usize, force_hot: bool) -> (usize, bool) {
    let arch_pt = arch::pt_arch();
    let inner = space.lock();
    let mut trimmed = 0usize;
    let mut dirtied_any = false;
    let mut flush_lo = u64::MAX;
    let mut flush_hi = 0u64;

    for vad in inner.vads.iter() {
        if trimmed >= target_pages {
            break;
        }
        let VadKind::Mapped {
            section: sec_addr,
            offset,
            is_image: false,
            share_write,
        } = vad.kind
        else {
            continue;
        };
        let sec_body = core::ptr::with_exposed_provenance_mut::<u8>(sec_addr);
        // SAFETY: `vad` holds a live reference to `sec_body` under `space.lock()`.
        let user_sec = unsafe { super::section::user_section(sec_body) };
        if !matches!(user_sec, Some(UserSection::DataFile(_))) {
            continue;
        }
        // SAFETY: `sec_body` is a live data-file section.
        let ca = unsafe { super::section::section_ca(sec_body) };
        if ca.is_null() {
            continue;
        }

        let mut va = vad.start;
        while va < vad.end && trimmed < target_pages {
            let pte = space.read_pte(va);
            if pte != 0 && arch_pt.present(pte) {
                if !force_hot && let Some(aged) = age_pte(pte) {
                    // Two-hand clock aging: clear Accessed bit on first pass.
                    let _ = space.write_pte(va, aged);
                    flush_lo = flush_lo.min(va);
                    flush_hi = flush_hi.max(va + PAGE_SIZE as u64);
                } else {
                    let pa = arch_pt.addr(pte);
                    let dirty = share_write && arch_pt.dirty(pte);
                    // Only demote shared prototype frames (leave private CoW frames resident).
                    if view::is_shared_frame(*vad, va, pa) {
                        let proto = UserSwPte::Prototype { proto_va: 0 }.encode();
                        if space.write_pte(va, proto).is_ok() {
                            flush_lo = flush_lo.min(va);
                            flush_hi = flush_hi.max(va + PAGE_SIZE as u64);
                            let moved_dirty =
                                view::trim_data_page(ca, offset + (va - vad.start), pa, dirty);
                            dirtied_any |= moved_dirty;
                            trimmed += 1;
                        }
                    }
                }
            }
            va += PAGE_SIZE as u64;
        }
    }
    drop(inner);

    if flush_hi > flush_lo {
        let pages = ((flush_hi - flush_lo) / PAGE_SIZE as u64) as usize;
        arch::flush_tlb_range(flush_lo, pages);
    }
    if trimmed > 0 {
        TRIMMED_PAGES.fetch_add(trimmed as u64, Ordering::Relaxed);
    }
    (trimmed, dirtied_any)
}

/// Sweep all live user processes, trimming up to `target_pages` mapped data-file pages.
pub fn trim_pass(target_pages: usize, force_hot: bool) -> usize {
    let procs = cid::snapshot_user_processes();
    let mut total_trimmed = 0usize;
    let mut any_dirty = false;
    for proc_ref in procs {
        if total_trimmed >= target_pages {
            break;
        }
        // SAFETY: `proc_ref` keeps `EPROCESS` alive.
        let Some(space) = (unsafe { process::address_space(proc_ref.body()) }) else {
            continue;
        };
        let (t, d) = trim_space(space, target_pages - total_trimmed, force_hot);
        total_trimmed += t;
        any_dirty |= d;
    }
    if any_dirty || pfn::modified_count() >= 64 {
        writer::kick();
    }
    total_trimmed
}

/// Called at `PASSIVE_LEVEL` (with no locks held) before faulting in a new page
/// when `free + standby` drops below `min_free`: trims mapped views, wakes the
/// mapped-page writer, and waits briefly for cleaned pages to land on `Standby`.
pub fn ensure_free_frames(min_free: u64) {
    if pfn::free_plus_standby() >= min_free {
        return;
    }
    for attempt in 0..16 {
        let trimmed = trim_pass(512, attempt > 0);
        if pfn::free_plus_standby() >= min_free {
            return;
        }
        if pfn::modified_count() > 0 {
            writer::kick();
            writer::wait_progress(-2_000_000); // up to 200 ms
        } else if trimmed == 0 {
            break;
        }
    }
}

fn trimmer_thread(_arg: usize) {
    loop {
        let avail = pfn::free_plus_standby();
        if avail < LOW_WATER_FRAMES {
            let _ = trim_pass(512, true);
        } else if avail < HIGH_WATER_FRAMES {
            let _ = trim_pass(128, false);
        }
        if pfn::modified_count() >= 64 {
            writer::kick();
        }
        // SAFETY: initialized in `init()`.
        unsafe {
            crate::ke::wait::wait(Some(TRIM_EVENT.0.get().cast()), Some(-5_000_000));
        }
    }
}
