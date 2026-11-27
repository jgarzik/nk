//! The memory manager's data sections, system-cache views and paging
//! I/O, driven as the cache manager drives them, over nkfs.

use super::nkfs::{self, Record, Volume};
use crate::mm::cache::{self, CacheSlot, Resident};
use crate::mm::{PAGE_SIZE, flush, pfn, section};
use crate::test::{Group, Report};
use alloc::vec::Vec;
use nk_bootinfo::BootInfo;
use nk_ntabi::io::{IRP_MJ_READ, IRP_MJ_WRITE, IRP_PRIORITY_HINT_NORMAL, SECTION_OBJECT_POINTERS};
use nk_ntabi::status::*;

pub static GROUPS: &[&Group] = &[&SECTION];

static SECTION: Group = Group {
    names: &[
        "mm.section",
        "mm.section-view",
        "mm.section-read",
        "mm.section-overwrite",
        "mm.section-inpage-error",
        "mm.section-flush",
        "mm.section-truncate",
        "mm.section-purge",
    ],
    run: section_tests,
    manual: false,
};

const VIEW: usize = cache::VIEW_BYTES;
/// What a paging read's flags are: `IRP_NOCACHE | IRP_PAGING_IO |
/// IRP_SYNCHRONOUS_PAGING_IO` and a normal priority.
const PAGING_READ: u32 = 0x43 | IRP_PRIORITY_HINT_NORMAL;

fn section_tests(r: &mut Report, _: &BootInfo) {
    let mut verdicts: Vec<(&str, Result<(), &'static str>)> = Vec::new();
    let outcome = run(&mut verdicts);
    for (name, verdict) in &verdicts {
        match verdict {
            Ok(()) => r.ok(name),
            Err(why) => r.fail(name, format_args!("{why}")),
        }
    }
    for name in SECTION
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

/// The slots the tests map views in, reserved once.
fn slots() -> Result<[CacheSlot; 2], &'static str> {
    static SLOTS: spin_once::Once = spin_once::Once::new();
    let first = SLOTS.get_or_init(|| cache::reserve_cache_slots(2).map(|s| s[0].0).unwrap_or(0));
    if first == 0 {
        return Err("no system-cache slots");
    }
    Ok([CacheSlot(first), CacheSlot(first + VIEW)])
}

/// A once-set word, for the slots.
mod spin_once {
    use core::sync::atomic::{AtomicUsize, Ordering};
    pub struct Once(AtomicUsize);
    impl Once {
        pub const fn new() -> Self {
            Self(AtomicUsize::new(0))
        }
        /// The tests run on one thread: no race to settle.
        pub fn get_or_init(&self, f: impl FnOnce() -> usize) -> usize {
            match self.0.load(Ordering::Acquire) {
                0 => {
                    let v = f();
                    self.0.store(v, Ordering::Release);
                    v
                }
                v => v,
            }
        }
    }
}

fn data_section(sop: *mut SECTION_OBJECT_POINTERS) -> *mut core::ffi::c_void {
    // SAFETY: nkfs's file's block, live while the volume is.
    unsafe { (*sop).DataSectionObject }
}

/// Whether the `len` bytes of the view at `va` hold the file's bytes at
/// `offset` as nkfs made them.
fn holds_pattern(va: usize, offset: usize, len: usize) -> bool {
    // SAFETY: the caller made the range valid in a view it holds.
    (0..len)
        .all(|i| unsafe { ((va + i) as *const u8).read_volatile() } == nkfs::pattern(offset + i))
}

fn one_read(log: &[Record], offset: u64, pages: u32) -> Result<(), &'static str> {
    match log {
        [read]
            if read.major == IRP_MJ_READ
                && read.flags == PAGING_READ
                && read.offset == offset
                && read.length == pages * PAGE_SIZE as u32 =>
        {
            Ok(())
        }
        [read] if read.flags != PAGING_READ => {
            Err("a paging read's flags are not 0x43 with a normal priority")
        }
        [_] => Err("a paging read's offset or length is wrong"),
        _ => Err("not exactly one paging read"),
    }
}

fn run(verdicts: &mut Vec<(&'static str, Result<(), &'static str>)>) -> Result<(), &'static str> {
    let [slot, slot2] = slots()?;
    let lists_before = pfn::counts()[1..].to_vec();
    let volume = Volume::new()?;
    let sop = volume.sop();

    // A cache manager's section: rounded to 1 MiB, named by the file.
    let s =
        section::create_cache_manager_section(volume.file, 3 << 20).map_err(|_| "no section")?;
    let again = section::create_cache_manager_section(volume.file, 1 << 20)
        .map_err(|_| "no second section")?;
    let ca = data_section(sop);
    verdicts.push((
        "mm.section",
        if ca.is_null() {
            Err("DataSectionObject is null with a section")
        } else if s.size() != 3 << 20 || again.size() != 1 << 20 {
            Err("a section's size is not what it was made with")
        } else {
            Ok(())
        },
    ));
    if section::extend_section(&again, 4 << 20) != Ok(4 << 20) || s.size() != 3 << 20 {
        return Err("extending a section did not grow it alone");
    }
    if !section::disable_modified_write(sop) {
        return Err("a file with a data section could not have modified writing disabled");
    }
    drop(again);
    if data_section(sop) != ca {
        return Err("dropping one of two sections changed the data section");
    }

    // A view maps without reading.
    cache::map_cache_view(&s, slot, 0, VIEW as u32).map_err(|_| "the view did not map")?;
    let v = slot.0;
    verdicts.push((
        "mm.section-view",
        if !nkfs::take_log().is_empty() {
            Err("mapping a view read the file")
        } else if cache::hard_fault_bytes(v, VIEW) != VIEW {
            Err("a fresh view's pages are not all in the file only")
        } else {
            Ok(())
        },
    ));

    // Asking for a byte reads its page and fifteen after it, in one
    // paging read of Windows' shape; then what is in memory needs no
    // read, and the last page of the view is read alone.
    let read = (|| {
        if cache::make_resident(v + 0x1234, 1, Resident::FaultIn) != Ok(true) {
            return Err("a page did not become resident");
        }
        one_read(&nkfs::take_log(), 0x1000, 16)?;
        if !holds_pattern(v + 0x1000, 0x1000, PAGE_SIZE) {
            return Err("the view does not hold the file's bytes");
        }
        // The rest of the cluster is in memory, though not in the view.
        if cache::make_resident(v + 0x2000, 15 * PAGE_SIZE, Resident::NoIo) != Ok(true) {
            return Err("pages read with a fault are not found in memory");
        }
        if !holds_pattern(v + 0x2000, 0x2000, 15 * PAGE_SIZE) {
            return Err("pages read with a fault do not hold the file's bytes");
        }
        if cache::make_resident(v + 0x20000, 1, Resident::NoIo) != Ok(false) {
            return Err("a page in the file only was found in memory");
        }
        // Read-ahead: into memory, not into the view.
        let ahead =
            cache::prefetch_for_cc(&s, 0x20000, 0x2000, 0).map_err(|_| "read-ahead failed")?;
        if cache::wait_prefetch(ahead) != STATUS_SUCCESS {
            return Err("read-ahead's status is not success");
        }
        one_read(&nkfs::take_log(), 0x20000, 16)?;
        if cache::make_resident(v + 0x20000, 0x10000, Resident::NoIo) != Ok(true)
            || !holds_pattern(v + 0x20000, 0x20000, 0x10000)
        {
            return Err("pages read ahead are not found in memory");
        }
        if cache::hard_fault_bytes(v, VIEW) != VIEW - 32 * PAGE_SIZE {
            return Err("the pages read are still counted as in the file only");
        }
        if cache::make_resident(v + VIEW - 1, 1, Resident::FaultIn) != Ok(true) {
            return Err("the last page did not become resident");
        }
        one_read(&nkfs::take_log(), (VIEW - PAGE_SIZE) as u64, 1)?;
        if !holds_pattern(v + VIEW - PAGE_SIZE, VIEW - PAGE_SIZE, PAGE_SIZE) {
            return Err("the last page does not hold the file's bytes");
        }
        Ok(())
    })();
    verdicts.push(("mm.section-read", read));

    // A page the cache manager overwrites is not read: in the file only,
    // it starts zeroed.
    let overwrite = (|| {
        let src = [0xC3u8; 0x20];
        // SAFETY: a kernel buffer of that length.
        unsafe { cache::copy_to_cached_page(v + 0x30000, src.as_ptr(), 0x10, 0x20) }
            .map_err(|_| "copying to a cached page failed")?;
        if !nkfs::take_log().is_empty() {
            return Err("a page copied to was read");
        }
        // SAFETY: the page was just made valid in the view.
        let page = unsafe { core::slice::from_raw_parts((v + 0x30000) as *const u8, PAGE_SIZE) };
        if page[..0x10].iter().any(|&b| b != 0)
            || page[0x10..0x30] != src
            || page[0x30..].iter().any(|&b| b != 0)
        {
            return Err("a page copied to is not zero around what was copied");
        }
        cache::set_range_modified(v + 0x30000, PAGE_SIZE);
        if cache::make_resident(v + 0x31000, PAGE_SIZE, Resident::WillOverwrite) != Ok(true)
            || !nkfs::take_log().is_empty()
        {
            return Err("a page to be overwritten was read");
        }
        Ok(())
    })();
    verdicts.push(("mm.section-overwrite", overwrite));
    let [_, standby, _, no_write] = pfn::counts();
    cache::unmap_cache_view(&s, slot, false);
    let [_, standby_after, _, no_write_after] = pfn::counts();
    // Mapped: pages 1 to 16, 32 to 47, 49 and 63 clean, 48 dirty, of a
    // section only the cache manager writes.
    if no_write_after != no_write + 1 || standby_after != standby + 34 {
        return Err(
            "unmapping the view did not put its pages on standby and the dirty one on modified-no-write",
        );
    }

    // A read that fails is the fault's error, and leaves the page in the
    // file only.
    nkfs::fail_read_at(Some(VIEW as u64));
    cache::map_cache_view(&s, slot2, VIEW as u64, VIEW as u32)
        .map_err(|_| "the second view did not map")?;
    let failed = cache::make_resident(slot2.0, 1, Resident::FaultIn);
    nkfs::fail_read_at(None);
    let reads = nkfs::take_log().len();
    // No IRP for the read: the fault fails, and waits for nothing.
    crate::io::paging::fail_next_allocation();
    let no_irp = cache::make_resident(slot2.0, 1, Resident::FaultIn);
    verdicts.push((
        "mm.section-inpage-error",
        if failed != Err(STATUS_DEVICE_DATA_ERROR) {
            Err("a failed read is not the fault's status")
        } else if reads != 1 {
            Err("a failed read was not one paging read")
        } else if no_irp != Err(STATUS_INSUFFICIENT_RESOURCES) || !nkfs::take_log().is_empty() {
            Err("a read with no IRP is not the fault's failure for want of resources")
        } else if cache::hard_fault_bytes(slot2.0, VIEW) != VIEW {
            Err("a page whose read failed is not in the file only")
        } else {
            Ok(())
        },
    ));

    // A flush writes exactly the modified pages, each run with the
    // paging flags and the cache manager's mark on the thread.
    cache::map_cache_view(&s, slot, 0, VIEW as u32).map_err(|_| "the view did not map again")?;
    let flushed = (|| {
        if cache::make_resident(v + 0x2000, 1, Resident::NoIo) != Ok(true) {
            return Err("a page on standby is not found again");
        }
        // SAFETY: the page was just made valid in the view.
        unsafe { ((v + 0x2008) as *mut u64).write_volatile(0x1122_3344_5566_7788) };
        let result = flush::flush_section(sop, Some((0, VIEW as u32)), None);
        let log = nkfs::take_log();
        let write = |r: &Record, offset| {
            r.major == IRP_MJ_WRITE
                && r.flags == PAGING_READ
                && r.cache_manager_active
                && r.offset == offset
                && r.length == PAGE_SIZE as u32
        };
        if result.Status != STATUS_SUCCESS || result.Information != 2 * PAGE_SIZE {
            return Err("a flush did not write two pages");
        }
        if log.len() != 2 || !write(&log[0], 0x2000) || !write(&log[1], 0x30000) {
            return Err(
                "a flush's writes are not the modified pages, with paging flags and the cache manager's mark",
            );
        }
        let data = nkfs::data();
        if data[0x2008..0x2010] != 0x1122_3344_5566_7788u64.to_le_bytes()
            || data[0x30010..0x30030] != [0xC3; 0x20]
            || data[0x30000] != 0
        {
            return Err("the file does not hold what was flushed");
        }
        match flush::page_of_file(sop, 0x2000) {
            flush::FilePage::Resident {
                modified: false,
                references: 1,
                ..
            } => {}
            _ => return Err("a flushed page is not clean and mapped"),
        }
        if flush::available_pages() == 0 {
            return Err("no page is available");
        }
        let again = flush::flush_section(sop, None, None);
        if again.Information != 0 || !nkfs::take_log().is_empty() {
            return Err("a second flush wrote clean pages");
        }
        Ok(())
    })();
    verdicts.push(("mm.section-flush", flushed));
    cache::unmap_cache_view(&s, slot, false);
    let size = 0x1000i64;
    // SAFETY: the file's section object pointers and a size on this stack.
    let truncatable = unsafe { flush::MmCanFileBeTruncated(sop, &raw const size) } != 0;
    verdicts.push((
        "mm.section-truncate",
        if !truncatable || !flush::can_file_be_truncated(sop, None) {
            Err("a file only the cache maps cannot be truncated")
        } else if !flush::only_system_cache_views(sop) {
            Err("the system cache's views are not all the file has")
        } else {
            Ok(())
        },
    ));

    // A purge that requires no views is refused while one is mapped,
    // and once it is unmapped discards every page, the dirty one too.
    let refused = flush::purge_section(sop, None, true);
    cache::unmap_cache_view(&s, slot2, false);
    let purged = flush::purge_section(sop, None, true);
    drop(s);
    let leftover = !data_section(sop).is_null();
    drop(volume);
    let lists_after = pfn::counts()[1..].to_vec();
    verdicts.push((
        "mm.section-purge",
        if refused {
            Err("a purge requiring no views was allowed with a view mapped")
        } else if !purged {
            Err("a purge with no view mapped was refused")
        } else if leftover {
            Err("the data section outlived its sections, views and pages")
        } else if lists_after != lists_before {
            Err("pages of the file are still on the standby or modified lists")
        } else {
            Ok(())
        },
    ));
    Ok(())
}
