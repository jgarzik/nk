//! Purging a file's pages: what the cache manager and file systems ask
//! of a data section beyond mapping it.

use super::PAGE_SIZE;
use super::pfn::{self, Guard};
use super::section::{self, ControlArea};
use crate::arch;
use core::sync::atomic::Ordering;
use nk_mm::pfn::{Location, flag};
use nk_mm::pt::Arch;
use nk_mm::pte::{self, Proto};
use nk_mm::section::{self as rule, SUBSECTION_PAGES};
use nk_ntabi::io::SECTION_OBJECT_POINTERS;

/// The pages `range` (offset and length; `None`: all) covers of a
/// section of `size` bytes, as `(subsection, first page, end page)`
/// runs.
fn runs(range: Option<(u64, u32)>, size: u64) -> impl Iterator<Item = (usize, usize, usize)> {
    let (start, end) = match range {
        Some((offset, 0)) => (offset, size),
        Some((offset, len)) => (offset, (offset + u64::from(len)).min(size)),
        None => (0, size),
    };
    let first = start / PAGE_SIZE as u64;
    let last = end.div_ceil(PAGE_SIZE as u64);
    let per = SUBSECTION_PAGES as u64;
    (first / per..last.div_ceil(per)).map(move |i| {
        let lo = first.max(i * per) - i * per;
        let hi = last.min((i + 1) * per) - i * per;
        (i as usize, lo as usize, hi as usize)
    })
}

/// `MmPurgeSection`: discard the pages `range` covers of the file's data
/// section, modified ones too, so that the next access reads the file.
/// False, changing nothing, when Windows' rule refuses
/// (`MiCanFileBeTruncatedInternal` with the purge's checks: being made
/// or deleted, pages locked, and with `require_no_views` any view
/// mapped), or when a page in the range is under I/O. A page a
/// system-cache view maps is taken out of the view first. True if the
/// file has no data section.
pub fn purge_section(
    sop: *mut SECTION_OBJECT_POINTERS,
    range: Option<(u64, u32)>,
    require_no_views: bool,
) -> bool {
    let purged = {
        let mut g = pfn::lock();
        match section::control_area(&g, sop) {
            None => true,
            Some(ca) => {
                let offset = range.map_or(0, |(offset, _)| offset);
                rule::can_truncate(&ca.counts(), Some(offset), true, !require_no_views)
                    && purge(&mut g, ca, range)
            }
        }
    };
    section::reap();
    section::trace(format_args!("purge {sop:p} {range:x?}: {purged}"));
    purged
}

/// Discard the pages of `ca` in `range`, once none is busy.
fn purge(g: &mut Guard, ca: &ControlArea, range: Option<(u64, u32)>) -> bool {
    let size = ca.size.get();
    // Refuse before anything changes: a page under I/O or locked.
    for (i, lo, hi) in runs(range, size) {
        let ss = ca.subsection(g, i);
        // SAFETY: a subsection in the directory is live under the lock.
        let Some(ss) = (unsafe { ss.as_ref() }) else {
            continue;
        };
        for proto in &ss.protos[lo..hi] {
            let (Proto::Valid(frame) | Proto::Transition(frame)) =
                Proto::decode(proto.load(Ordering::Relaxed))
            else {
                continue;
            };
            let e = pfn::frames(g).db.get(frame);
            if e.has(flag::READ_IN_PROGRESS | flag::WRITE_IN_PROGRESS)
                || e.ref_count > u16::from(e.share_count != 0)
            {
                return false;
            }
        }
    }
    let a = arch::pt_arch();
    let no_write = ca.no_write();
    for (i, lo, hi) in runs(range, size) {
        let ss = ca.subsection(g, i);
        // SAFETY: as above.
        let Some(ss) = (unsafe { ss.as_ref() }) else {
            continue;
        };
        let view = ss.view_va.get();
        for (j, proto) in ss.protos.iter().enumerate().take(hi).skip(lo) {
            let frame = match Proto::decode(proto.load(Ordering::Relaxed)) {
                Proto::Valid(frame) => {
                    // Mapped by its view only: out of the view first.
                    let va = view + (j * PAGE_SIZE) as u64;
                    let entry = super::cache::entry_of(va);
                    let old = entry.swap(
                        pte::prototype_pointer(core::ptr::from_ref(proto).addr() as u64),
                        Ordering::AcqRel,
                    );
                    arch::flush_tlb_page(va);
                    let db = &mut pfn::frames(g).db;
                    if a.present(old) && a.dirty(old) {
                        db.get_mut(frame).flags |= flag::MODIFIED;
                    }
                    if let Err(e) = db.unshare(frame, no_write, false) {
                        crate::kd::bugcheck(format_args!("mm: purging a mapped page: {}", e.0));
                    }
                    frame
                }
                Proto::Transition(frame) => frame,
                _ => continue,
            };
            debug_assert!(matches!(
                pfn::frames(g).db.get(frame).location(),
                Location::Standby | Location::Modified | Location::ModifiedNoWrite
            ));
            match pfn::frames(g).db.release(frame) {
                Ok((_, original)) => proto.store(original, Ordering::Relaxed),
                Err(e) => crate::kd::bugcheck(format_args!("mm: purging a page: {}", e.0)),
            }
            pfn::give_back_released(g, frame);
            section::page_left(g, ss);
        }
    }
    ca.flags.set(ca.flags.get() | rule::flag::WAS_PURGED);
    true
}
