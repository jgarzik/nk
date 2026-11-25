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
