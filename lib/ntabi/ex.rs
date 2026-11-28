//! Executive structures drivers see: work items, push locks, sequenced
//! lists, lookaside lists and resources.

use crate::ke::{KSPIN_LOCK, LIST_ENTRY};
use core::ffi::c_void;

/// `EX_PUSH_LOCK`: one word the driver owns, zero when the lock is
/// free. Its bits are `nk_ex::pushlock`'s.
pub type EX_PUSH_LOCK = usize;

/// `EX_RUNDOWN_REF`: one word the driver owns, zero when new. Its bits
/// are `nk_ex::rundown`'s.
pub type EX_RUNDOWN_REF = usize;

/// `EX_SPIN_LOCK`: a `LONG` the driver owns, zero when free. Its bits
/// are `nk_ex::spinlock`'s.
pub type EX_SPIN_LOCK = i32;

/// `EX_RUNDOWN_REF_CACHE_AWARE`: run-down protection with a word a
/// processor. Drivers hold it by pointer; the layout is the kernel's
/// own (its public symbols give it), which a driver that sets the
/// memory aside itself depends on only through
/// `ExSizeOfRundownProtectionCacheAware`.
#[repr(C)]
pub struct EX_RUNDOWN_REF_CACHE_AWARE {
    /// The first processor's word.
    pub RunRefs: *mut EX_RUNDOWN_REF,
    /// The block the words are in, when the kernel allocated them.
    pub PoolToFree: *mut c_void,
    /// Bytes from one processor's word to the next.
    pub RunRefSize: u32,
    /// How many words.
    pub Number: u32,
}

/// `SLIST_ENTRY`: an entry of a sequenced list; 16-byte aligned, which
/// is what leaves the header four bits to spare.
#[repr(C, align(16))]
pub struct SLIST_ENTRY {
    pub Next: *mut SLIST_ENTRY,
}

/// `SLIST_HEADER`: the head of a sequenced list, as its two quadwords.
/// The fields inside them (`HeaderX64`, and `HeaderArm64`, which has the
/// same ones at the same bits) are `nk_ex::slist`'s.
#[repr(C, align(16))]
pub struct SLIST_HEADER {
    pub Alignment: u64,
    pub Region: u64,
}

/// `GUID`, which `UUID` is another name for.
#[repr(C)]
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct GUID {
    pub Data1: u32,
    pub Data2: u16,
    pub Data3: u16,
    pub Data4: [u8; 8],
}

/// `EXT_DELETE_CALLBACK`: what a driver may ask `ExDeleteTimer` to call
/// once the timer is gone.
pub type EXT_DELETE_CALLBACK = unsafe extern "C" fn(*mut c_void);

/// `EXT_DELETE_PARAMETERS`: the optional last argument of
/// `ExDeleteTimer`, set up by the header's
/// `ExInitializeDeleteTimerParameters`.
#[repr(C)]
pub struct EXT_DELETE_PARAMETERS {
    pub Version: u32,
    pub Reserved: u32,
    pub DeleteCallback: Option<EXT_DELETE_CALLBACK>,
    pub DeleteContext: *mut c_void,
}

/// `ALLOCATE_FUNCTION`: a lookaside list's routine for a block it does
/// not have: pool type, size, tag.
pub type ALLOCATE_FUNCTION = unsafe extern "C" fn(u32, usize, u32) -> *mut c_void;

/// `FREE_FUNCTION`: a lookaside list's routine for a block it will not
/// keep.
pub type FREE_FUNCTION = unsafe extern "C" fn(*mut c_void);

/// `GENERAL_LOOKASIDE`: a lookaside list. The driver's in-line code
/// pops and pushes `ListHead`, counts in the four counters and calls
/// `Allocate` and `Free` itself; the kernel fills the structure in and
/// empties it.
#[repr(C, align(64))]
pub struct GENERAL_LOOKASIDE {
    pub ListHead: SLIST_HEADER,
    pub Depth: u16,
    pub MaximumDepth: u16,
    pub TotalAllocates: u32,
    pub AllocateMisses: u32,
    pub TotalFrees: u32,
    pub FreeMisses: u32,
    pub Type: u32,
    pub Tag: u32,
    pub Size: u32,
    pub Allocate: Option<ALLOCATE_FUNCTION>,
    pub Free: Option<FREE_FUNCTION>,
    pub ListEntry: LIST_ENTRY,
    pub LastTotalAllocates: u32,
    pub LastAllocateMisses: u32,
    pub Future: [u32; 2],
}

/// `PAGED_LOOKASIDE_LIST`.
#[repr(C)]
pub struct PAGED_LOOKASIDE_LIST {
    pub L: GENERAL_LOOKASIDE,
}

/// `NPAGED_LOOKASIDE_LIST`.
#[repr(C)]
pub struct NPAGED_LOOKASIDE_LIST {
    pub L: GENERAL_LOOKASIDE,
}

/// `LOOKASIDE_LIST_EX`: the same block, whose routines take the list
/// too (`AllocateEx(PoolType, NumberOfBytes, Tag, Lookaside)`,
/// `FreeEx(Buffer, Lookaside)`) in the slots of `Allocate` and `Free`.
pub type LOOKASIDE_LIST_EX = GENERAL_LOOKASIDE;

/// `OWNER_ENTRY`: one owner of a resource. `Bits` is three flag bits
/// and, from bit 3, `OwnerCount`; in the first entry of an owner table
/// the same word is `TableSize`, the number of entries.
#[repr(C)]
pub struct OWNER_ENTRY {
    pub OwnerThread: usize,
    pub Bits: u32,
}

/// `ERESOURCE`: an executive resource, in the driver's memory.
#[repr(C)]
pub struct ERESOURCE {
    pub SystemResourcesList: LIST_ENTRY,
    pub OwnerTable: *mut OWNER_ENTRY,
    pub ActiveCount: i16,
    pub Flag: u16,
    pub SharedWaiters: *mut c_void,
    pub ExclusiveWaiters: *mut c_void,
    pub OwnerEntry: OWNER_ENTRY,
    pub ActiveEntries: u32,
    pub ContentionCount: u32,
    pub NumberOfSharedWaiters: u32,
    pub NumberOfExclusiveWaiters: u32,
    pub Reserved2: *mut c_void,
    pub Address: *mut c_void,
    pub SpinLock: KSPIN_LOCK,
}

/// `WORKER_THREAD_ROUTINE`.
pub type WORKER_THREAD_ROUTINE = unsafe extern "C" fn(*mut c_void);

/// `WORK_QUEUE_ITEM`: a work item the driver owns. `ExInitializeWorkItem`
/// is in-line code in the driver: it sets the routine and parameter and
/// nulls `List.Flink`, which is null exactly while the item is on no
/// queue.
#[repr(C)]
pub struct WORK_QUEUE_ITEM {
    pub List: LIST_ENTRY,
    pub WorkerRoutine: Option<WORKER_THREAD_ROUTINE>,
    pub Parameter: *mut c_void,
}

/// `IO_WORKITEM`: a work item the I/O manager allocates. Opaque to
/// drivers but for its size (`IoSizeofWorkItem`); laid out as on
/// Windows.
#[repr(C)]
pub struct IO_WORKITEM {
    pub WorkItem: WORK_QUEUE_ITEM,
    pub Routine: *mut c_void,
    pub IoObject: *mut c_void,
    pub Context: *mut c_void,
    pub WorkOnBehalfThread: *mut c_void,
    pub Type: u32,
    pub ActivityId: [u8; 16],
}

/// `WORK_QUEUE_TYPE`, as Windows 10 numbers it.
pub const CRITICAL_WORK_QUEUE: u32 = 0;
pub const DELAYED_WORK_QUEUE: u32 = 1;
pub const HYPER_CRITICAL_WORK_QUEUE: u32 = 2;
pub const NORMAL_WORK_QUEUE: u32 = 3;
pub const BACKGROUND_WORK_QUEUE: u32 = 4;
pub const REAL_TIME_WORK_QUEUE: u32 = 5;
pub const SUPER_CRITICAL_WORK_QUEUE: u32 = 6;

/// The queues NK keeps: critical, delayed and hypercritical, numbered
/// as their `WORK_QUEUE_TYPE`.
pub const WORK_QUEUES: usize = 3;

/// The queue that serves a `WORK_QUEUE_TYPE`: critical, delayed and
/// hypercritical their own; normal and background the delayed one; real
/// time the hypercritical; supercritical the critical. `None` for a
/// value Windows does not define.
pub const fn work_queue(queue_type: u32) -> Option<usize> {
    Some(match queue_type {
        CRITICAL_WORK_QUEUE | DELAYED_WORK_QUEUE | HYPER_CRITICAL_WORK_QUEUE => queue_type as usize,
        NORMAL_WORK_QUEUE | BACKGROUND_WORK_QUEUE => DELAYED_WORK_QUEUE as usize,
        REAL_TIME_WORK_QUEUE => HYPER_CRITICAL_WORK_QUEUE as usize,
        SUPER_CRITICAL_WORK_QUEUE => CRITICAL_WORK_QUEUE as usize,
        _ => return None,
    })
}

const _: () = {
    use core::mem::{offset_of, size_of};
    assert!(size_of::<WORK_QUEUE_ITEM>() == 0x20);
    assert!(offset_of!(WORK_QUEUE_ITEM, WorkerRoutine) == 0x10);
    assert!(size_of::<IO_WORKITEM>() == 0x58);
    assert!(offset_of!(IO_WORKITEM, Routine) == 0x20);
    assert!(offset_of!(IO_WORKITEM, Context) == 0x30);
    assert!(offset_of!(IO_WORKITEM, ActivityId) == 0x44);

    assert!(size_of::<GUID>() == 0x10);
    assert!(offset_of!(GUID, Data2) == 0x04);
    assert!(offset_of!(GUID, Data3) == 0x06);
    assert!(offset_of!(GUID, Data4) == 0x08);
    assert!(size_of::<EXT_DELETE_PARAMETERS>() == 0x18);
    assert!(offset_of!(EXT_DELETE_PARAMETERS, DeleteCallback) == 0x08);
    assert!(offset_of!(EXT_DELETE_PARAMETERS, DeleteContext) == 0x10);

    assert!(size_of::<EX_PUSH_LOCK>() == 8);
    assert!(size_of::<EX_RUNDOWN_REF>() == 8);
    assert!(size_of::<EX_SPIN_LOCK>() == 4);
    assert!(size_of::<EX_RUNDOWN_REF_CACHE_AWARE>() == 0x18);
    assert!(offset_of!(EX_RUNDOWN_REF_CACHE_AWARE, PoolToFree) == 0x08);
    assert!(offset_of!(EX_RUNDOWN_REF_CACHE_AWARE, RunRefSize) == 0x10);
    assert!(offset_of!(EX_RUNDOWN_REF_CACHE_AWARE, Number) == 0x14);
    assert!(size_of::<SLIST_ENTRY>() == 0x10);
    assert!(size_of::<SLIST_HEADER>() == 0x10);
    assert!(align_of::<SLIST_HEADER>() == 0x10);
    assert!(offset_of!(SLIST_HEADER, Region) == 0x08);

    assert!(size_of::<GENERAL_LOOKASIDE>() == 0x80);
    assert!(offset_of!(GENERAL_LOOKASIDE, Depth) == 0x10);
    assert!(offset_of!(GENERAL_LOOKASIDE, MaximumDepth) == 0x12);
    assert!(offset_of!(GENERAL_LOOKASIDE, TotalAllocates) == 0x14);
    assert!(offset_of!(GENERAL_LOOKASIDE, AllocateMisses) == 0x18);
    assert!(offset_of!(GENERAL_LOOKASIDE, TotalFrees) == 0x1C);
    assert!(offset_of!(GENERAL_LOOKASIDE, FreeMisses) == 0x20);
    assert!(offset_of!(GENERAL_LOOKASIDE, Type) == 0x24);
    assert!(offset_of!(GENERAL_LOOKASIDE, Tag) == 0x28);
    assert!(offset_of!(GENERAL_LOOKASIDE, Size) == 0x2C);
    assert!(offset_of!(GENERAL_LOOKASIDE, Allocate) == 0x30);
    assert!(offset_of!(GENERAL_LOOKASIDE, Free) == 0x38);
    assert!(offset_of!(GENERAL_LOOKASIDE, ListEntry) == 0x40);
    assert!(offset_of!(GENERAL_LOOKASIDE, LastTotalAllocates) == 0x50);
    assert!(offset_of!(GENERAL_LOOKASIDE, Future) == 0x58);
    assert!(size_of::<PAGED_LOOKASIDE_LIST>() == 0x80);
    assert!(size_of::<NPAGED_LOOKASIDE_LIST>() == 0x80);

    assert!(size_of::<OWNER_ENTRY>() == 0x10);
    assert!(offset_of!(OWNER_ENTRY, Bits) == 0x08);
    assert!(size_of::<ERESOURCE>() == 0x68);
    assert!(offset_of!(ERESOURCE, OwnerTable) == 0x10);
    assert!(offset_of!(ERESOURCE, ActiveCount) == 0x18);
    assert!(offset_of!(ERESOURCE, Flag) == 0x1A);
    assert!(offset_of!(ERESOURCE, SharedWaiters) == 0x20);
    assert!(offset_of!(ERESOURCE, ExclusiveWaiters) == 0x28);
    assert!(offset_of!(ERESOURCE, OwnerEntry) == 0x30);
    assert!(offset_of!(ERESOURCE, ActiveEntries) == 0x40);
    assert!(offset_of!(ERESOURCE, ContentionCount) == 0x44);
    assert!(offset_of!(ERESOURCE, NumberOfSharedWaiters) == 0x48);
    assert!(offset_of!(ERESOURCE, NumberOfExclusiveWaiters) == 0x4C);
    assert!(offset_of!(ERESOURCE, Address) == 0x58);
    assert!(offset_of!(ERESOURCE, SpinLock) == 0x60);
};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn each_kind_of_work_queue_is_served_by_one_nk_keeps() {
        // The three NK keeps serve themselves.
        assert_eq!(work_queue(CRITICAL_WORK_QUEUE), Some(0));
        assert_eq!(work_queue(DELAYED_WORK_QUEUE), Some(1));
        assert_eq!(work_queue(HYPER_CRITICAL_WORK_QUEUE), Some(2));
        // The four it does not go to the nearest.
        assert_eq!(work_queue(NORMAL_WORK_QUEUE), Some(1));
        assert_eq!(work_queue(BACKGROUND_WORK_QUEUE), Some(1));
        assert_eq!(work_queue(REAL_TIME_WORK_QUEUE), Some(2));
        assert_eq!(work_queue(SUPER_CRITICAL_WORK_QUEUE), Some(0));
        // Every answer is a queue that exists.
        for queue_type in 0..=SUPER_CRITICAL_WORK_QUEUE {
            assert!(work_queue(queue_type).is_some_and(|q| q < WORK_QUEUES));
        }
    }

    #[test]
    fn a_work_queue_type_windows_does_not_define_has_no_queue() {
        // `MaximumWorkQueue` and beyond.
        assert_eq!(work_queue(7), None);
        assert_eq!(work_queue(8), None);
        assert_eq!(work_queue(0x100), None);
        assert_eq!(work_queue(u32::MAX), None);
    }
}
