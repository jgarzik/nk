//! The cache manager: files' data kept in memory for file systems, read
//! and written through views of the files' sections (`doc/design/cc.md`).
//!
//! Per file, a shared cache map ([`Scm`]) hangs from
//! `SectionObjectPointer->SharedCacheMap`; per file object that caches
//! the file, a private cache map ([`Pcm`]) from
//! `FileObject->PrivateCacheMap`. Both are NK's own structures, with
//! Windows' field names: no file system reads them. Each view of a file
//! is a VACB of the pool in [`vacb`], mapped through the memory
//! manager's system cache; each pinned range a BCB ([`pin`]).
//!
//! Locks, in rank order (`doc/LOCKING.md`): [`MASTER`] (41) guards the
//! shared cache maps' counts, flags, sizes and list, and the private
//! maps' links; [`vacb::VACBS`] (42) the views; [`DIRTY`] (43) the dirty
//! counts and dirty marks. A shared cache map's BCB list and dirty
//! bitmap are under its own guarded mutex, a sleeping lock taken outside
//! every ranked one. No ranked lock is held across a call to the memory
//! manager, the pool or a file system.
//!
//! A routine documented to raise is entered through
//! `nk_with_caller_context`; its body returns `Err(status)` with
//! nothing held, and the entry raises it in the caller.

#![allow(non_snake_case)]

pub mod copy;
pub mod flush;
pub mod map;
pub mod mdl;
pub mod pin;
pub mod size;
pub mod vacb;

use crate::arch::seh::Context;
use crate::ke::seh::{EXCEPTION_NONCONTINUABLE, raise};
use crate::ke::spinlock::{Rank, SpinLock};
use crate::mm::pool;
use crate::mm::section::SectionRef;
use core::cell::{Cell, UnsafeCell};
use core::sync::atomic::{AtomicBool, Ordering};
use nk_cc::mbcb::Mbcb;
use nk_cc::vacbidx::VacbIndex;
use nk_ntabi::cc::CACHE_UNINITIALIZE_EVENT;
use nk_ntabi::io::{FILE_OBJECT, SECTION_OBJECT_POINTERS};
use nk_ntabi::ke::FAST_MUTEX;
use nk_ntabi::status::*;

/// Windows' pool tags: shared cache map, private cache map, BCB.
const TAG_SCM: u32 = u32::from_le_bytes(*b"CcSc");
const TAG_PCM: u32 = u32::from_le_bytes(*b"CcPc");
const TAG_BCB: u32 = u32::from_le_bytes(*b"CcBc");

/// `STATUS_UNEXPECTED_MM_CREATE_ERR`, `_MAP_ERROR`, `_EXTEND_ERR`.
pub const STATUS_UNEXPECTED_MM_CREATE_ERR: NTSTATUS = 0xC000_00EA_u32 as NTSTATUS;
pub const STATUS_UNEXPECTED_MM_MAP_ERROR: NTSTATUS = 0xC000_00EB_u32 as NTSTATUS;
pub const STATUS_UNEXPECTED_MM_EXTEND_ERR: NTSTATUS = 0xC000_00EC_u32 as NTSTATUS;

/// A shared cache map's `Flags`, Windows' values.
pub mod flag {
    pub const DISABLE_READ_AHEAD: u32 = 0x1;
    pub const DISABLE_WRITE_BEHIND: u32 = 0x2;
    pub const PIN_ACCESS: u32 = 0x4;
    pub const TRUNCATE_REQUIRED: u32 = 0x10;
    pub const WRITE_QUEUED: u32 = 0x20;
    pub const BEING_CREATED: u32 = 0x100;
    pub const MODIFIED_WRITE_DISABLED: u32 = 0x200;
    /// NK's: the map is being deleted; whoever finds it waits for that.
    pub const BEING_DELETED: u32 = 0x8000_0000;
}

/// A private cache map: one per file object caching a file.
pub struct Pcm {
    pub file_object: Cell<*mut FILE_OBJECT>,
    pub scm: Cell<*mut Scm>,
    /// The next on the shared cache map's list, under [`MASTER`].
    next: Cell<*mut Pcm>,
    /// The last two reads, under [`MASTER`].
    pub history: Cell<nk_cc::readahead::History>,
    /// The read-ahead granularity minus one.
    pub read_ahead_mask: Cell<u32>,
}

/// A shared cache map: one per cached file.
pub struct Scm {
    // Under MASTER.
    pub open_count: Cell<u32>,
    /// References the cache manager's own work holds: a flush, a
    /// creation or deletion in progress. The map is not deleted while
    /// one is held.
    pub refs: Cell<u32>,
    pub flags: Cell<u32>,
    pub file_size: Cell<i64>,
    pub valid_data_length: Cell<i64>,
    pub valid_data_goal: Cell<i64>,
    pub section_size: Cell<u64>,
    next: Cell<*mut Scm>,
    prev: Cell<*mut Scm>,
    privates: Cell<*mut Pcm>,
    uninit_events: Cell<*mut CACHE_UNINITIALIZE_EVENT>,
    // Set while the map is being created, then fixed until it is
    // deleted.
    pub sop: *mut SECTION_OBJECT_POINTERS,
    /// The file object the cache manager holds a reference on: the
    /// first that cached the file.
    pub file_object: Cell<*mut FILE_OBJECT>,
    section: UnsafeCell<Option<SectionRef>>,
    /// Under `vacb::VACBS`.
    index: UnsafeCell<Option<VacbIndex>>,
    /// Under [`DIRTY`].
    pub dirty_pages: Cell<u64>,
    /// Guards `bcbs` and `mbcb`.
    bcb_lock: UnsafeCell<FAST_MUTEX>,
    bcbs: UnsafeCell<alloc::vec::Vec<*mut pin::Bcb>>,
    mbcb: UnsafeCell<Mbcb>,
    /// The first file object's private map lives here.
    pcm: Pcm,
    pcm_used: Cell<bool>,
}

/// What [`MASTER`] guards beyond the maps' own fields: the list of every
/// shared cache map.
pub struct Master {
    head: *mut Scm,
}

// SAFETY: the list's maps are reached only under the lock.
unsafe impl Send for Master {}

/// The shared cache maps, their counts, flags, sizes and list.
pub static MASTER: SpinLock<Master> = SpinLock::new(
    Rank::CcMaster,
    Master {
        head: core::ptr::null_mut(),
    },
);

/// What [`DIRTY`] guards: the dirty pages in the cache.
pub struct Dirty {
    pub pages: u64,
}

/// Dirty-page counts and the BCBs' dirty marks.
pub static DIRTY: SpinLock<Dirty> = SpinLock::new(Rank::CcDirty, Dirty { pages: 0 });

static STARTED: AtomicBool = AtomicBool::new(false);

/// How many views the cache manager maps at once: NK's choice, 64 MiB
/// of the system cache.
const VIEWS: usize = 256;

/// Start the cache manager (`CcInitializeCacheManager`): reserve its
/// views. Once, before any file system starts.
pub fn init() -> Result<(), &'static str> {
    vacb::init(VIEWS)?;
    STARTED.store(true, Ordering::Release);
    Ok(())
}

/// A line of `trace=cc`.
pub fn trace(what: core::fmt::Arguments<'_>) {
    if crate::kd::trace_cc() {
        kprintln!("NK-CC {what}");
    }
}

/// Stop the system for a broken rule of the cache manager's
/// (`CACHE_MANAGER`, 0x34), as Windows' internal checks do.
pub fn cache_manager_bugcheck(why: core::fmt::Arguments<'_>) -> ! {
    crate::kd::bugcheck(format_args!("0x00000034 CACHE_MANAGER: {why}"))
}

/// Raise `status` in the caller `context` describes.
///
/// # Safety
/// `context` is the one `nk_with_caller_context` made for the routine
/// being run; the caller holds nothing and owes nothing.
pub unsafe fn raise_status(context: *mut Context, status: NTSTATUS) -> ! {
    // SAFETY: per the contract.
    unsafe { raise(context, status as u32, EXCEPTION_NONCONTINUABLE, &[]) }
}

/// The result of a body, or a raise in the caller.
///
/// # Safety
/// As [`raise_status`].
pub unsafe fn or_raise<T>(context: *mut Context, r: Result<T, NTSTATUS>) -> T {
    match r {
        Ok(v) => v,
        // SAFETY: per the contract.
        Err(status) => unsafe { raise_status(context, status) },
    }
}

/// `STATUS_INVALID_USER_BUFFER`, what a fault on a caller's buffer
/// becomes; `STATUS_UNEXPECTED_IO_ERROR`, what a status a file system
/// would not expect does.
pub const STATUS_INVALID_USER_BUFFER: NTSTATUS = 0xC000_00E8_u32 as NTSTATUS;
pub const STATUS_UNEXPECTED_IO_ERROR: NTSTATUS = 0xC000_00E9_u32 as NTSTATUS;

/// An I/O status as the cache manager raises it: itself if a file
/// system expects it, else `STATUS_UNEXPECTED_IO_ERROR`.
pub fn io_status(status: NTSTATUS) -> NTSTATUS {
    nk_fsrtl::status::normalize(status as u32, STATUS_UNEXPECTED_IO_ERROR as u32) as NTSTATUS
}

/// The private cache map of `file`, if it caches its file.
///
/// # Safety
/// `file` is a live file object.
pub unsafe fn pcm_of(file: *mut FILE_OBJECT) -> Option<&'static Pcm> {
    // SAFETY: per the contract; the field is the cache manager's.
    unsafe { (*file).PrivateCacheMap.cast::<Pcm>().as_ref() }
}

/// Take a reference on `scm` for the cache manager's own work.
pub fn reference(scm: &Scm) {
    let _m = MASTER.lock();
    scm.refs.set(scm.refs.get() + 1);
}

/// Give back a [`reference`].
pub fn dereference(scm: &Scm) {
    let _m = MASTER.lock();
    scm.refs.set(scm.refs.get() - 1);
}

/// Wait about 10 ms (`Cc10Milliseconds`), as the cache manager waits for
/// a map being made or deleted elsewhere.
pub fn short_delay() {
    let interval: i64 = -100_000;
    // SAFETY: a due time on this stack.
    unsafe { crate::ke::wait::KeDelayExecutionThread(0, 0, &raw const interval) };
}

impl Scm {
    /// The file's section.
    pub fn section(&self) -> &SectionRef {
        // SAFETY: set before the map is found by anyone but its creator,
        // cleared only by its deletion, which nothing else runs beside.
        unsafe { (*self.section.get()).as_ref() }.expect("a shared cache map with no section")
    }

    /// Run `f` on the BCB list and dirty bitmap, with the map's mutex
    /// held. At or below `APC_LEVEL`.
    pub fn with_bcbs<R>(
        &self,
        f: impl FnOnce(&mut alloc::vec::Vec<*mut pin::Bcb>, &mut Mbcb) -> R,
    ) -> R {
        // SAFETY: the mutex guards both; the references end with `f`.
        unsafe {
            crate::ke::mutex::KeAcquireGuardedMutex(self.bcb_lock.get());
            let r = f(&mut *self.bcbs.get(), &mut *self.mbcb.get());
            crate::ke::mutex::KeReleaseGuardedMutex(self.bcb_lock.get());
            r
        }
    }

    /// The first private map on the list, or null. Under [`MASTER`].
    pub fn first_private(&self) -> *mut Pcm {
        self.privates.get()
    }

    /// The file object's FCB header's `Flags2` and whether it is a
    /// stream file object (`FsContext2` null).
    fn file_kind(file: *mut FILE_OBJECT) -> (u8, bool) {
        // SAFETY: the file system's file object and its header, live
        // while the file system calls the cache manager on it.
        unsafe {
            let header = (*file)
                .FsContext
                .cast::<nk_ntabi::fsrtl::FSRTL_COMMON_FCB_HEADER>();
            let flags2 = if header.is_null() {
                0
            } else {
                (&raw const (*header).Flags2).read()
            };
            (flags2, (*file).FsContext2.is_null())
        }
    }
}

/// The shared cache map of `file`'s stream, or null.
///
/// # Safety
/// `file` is a live file object whose file system set its section
/// object pointers.
pub unsafe fn scm_of(file: *mut FILE_OBJECT) -> *mut Scm {
    // SAFETY: per the contract; the pointer is the cache manager's.
    unsafe {
        let sop = (*file)
            .SectionObjectPointer
            .cast::<SECTION_OBJECT_POINTERS>();
        if sop.is_null() {
            return core::ptr::null_mut();
        }
        (&raw const (*sop).SharedCacheMap).read().cast()
    }
}

/// The shared cache map of a file a file system calls the cache manager
/// on: one it cached.
///
/// # Safety
/// As [`scm_of`]; the file system keeps the file cached while it calls.
pub unsafe fn cached(file: *mut FILE_OBJECT, routine: &str) -> &'static Scm {
    // SAFETY: per the contract.
    match unsafe { scm_of(file).as_ref() } {
        Some(scm) => scm,
        None => cache_manager_bugcheck(format_args!(
            "{routine} on file object {file:p}, which is not cached"
        )),
    }
}

/// Make a block of pool for `value`, or null.
fn alloc_in_pool<T>(value: T, tag: u32) -> *mut T {
    let block = pool::alloc(size_of::<T>(), tag).cast::<T>();
    if !block.is_null() {
        // SAFETY: a fresh block of the right size, ours alone.
        unsafe { block.write(value) };
    }
    block
}

/// Drop and free a block [`alloc_in_pool`] made.
///
/// # Safety
/// `block` came from [`alloc_in_pool`] and nothing refers to it.
unsafe fn free_in_pool<T>(block: *mut T) {
    // SAFETY: per the contract.
    unsafe { core::ptr::drop_in_place(block) };
    if let Err(e) = pool::free(block.cast()) {
        crate::kd::bugcheck(format_args!("cc: freeing {block:p}: {e:?}"));
    }
}
