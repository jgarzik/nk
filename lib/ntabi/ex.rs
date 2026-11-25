//! Executive structures drivers see: work items.

use crate::ke::LIST_ENTRY;
use core::ffi::c_void;

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

const _: () = {
    use core::mem::{offset_of, size_of};
    assert!(size_of::<WORK_QUEUE_ITEM>() == 0x20);
    assert!(offset_of!(WORK_QUEUE_ITEM, WorkerRoutine) == 0x10);
    assert!(size_of::<IO_WORKITEM>() == 0x58);
    assert!(offset_of!(IO_WORKITEM, Routine) == 0x20);
    assert!(offset_of!(IO_WORKITEM, Context) == 0x30);
    assert!(offset_of!(IO_WORKITEM, ActivityId) == 0x44);
};
