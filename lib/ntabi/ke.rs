//! Kernel-core types drivers see: IRQL and spin locks.

use core::ffi::c_void;

/// `KIRQL`: an interrupt request level, one byte.
pub type KIRQL = u8;

/// `KSPIN_LOCK`: one pointer-sized word owned by the driver, zero when
/// the lock is free.
pub type KSPIN_LOCK = usize;

/// `KSPIN_LOCK_QUEUE`: a waiter's place in a queued spin lock.
#[repr(C)]
pub struct KSPIN_LOCK_QUEUE {
    pub Next: *mut c_void,
    pub Lock: *mut KSPIN_LOCK,
}

/// `KLOCK_QUEUE_HANDLE`: what a driver keeps, usually on its stack, while
/// it holds a queued spin lock.
#[repr(C)]
pub struct KLOCK_QUEUE_HANDLE {
    pub LockQueue: KSPIN_LOCK_QUEUE,
    pub OldIrql: KIRQL,
}

const _: () = {
    use core::mem::{offset_of, size_of};
    assert!(size_of::<KSPIN_LOCK>() == 8);
    assert!(size_of::<KSPIN_LOCK_QUEUE>() == 0x10);
    assert!(offset_of!(KSPIN_LOCK_QUEUE, Lock) == 0x08);
    assert!(size_of::<KLOCK_QUEUE_HANDLE>() == 0x18);
    assert!(offset_of!(KLOCK_QUEUE_HANDLE, OldIrql) == 0x10);
};

/// `SINGLE_LIST_ENTRY`.
#[repr(C)]
pub struct SINGLE_LIST_ENTRY {
    pub Next: *mut SINGLE_LIST_ENTRY,
}

/// `KDEFERRED_ROUTINE`: what a DPC runs.
pub type KDEFERRED_ROUTINE = unsafe extern "C" fn(*mut KDPC, *mut c_void, *mut c_void, *mut c_void);

/// The `Type` of a `KDPC`: `DpcObject`.
pub const DPC_OBJECT: u8 = 0x13;
/// The `Importance` `KeInitializeDpc` gives: `MediumImportance`.
pub const MEDIUM_IMPORTANCE: u8 = 1;

/// `KDPC`: a deferred procedure call. The driver allocates it; the kernel
/// queues it through `DpcListEntry`, and `DpcData` is non-null exactly
/// while it is queued.
#[repr(C)]
pub struct KDPC {
    pub Type: u8,
    pub Importance: u8,
    pub Number: u16,
    pub DpcListEntry: SINGLE_LIST_ENTRY,
    pub ProcessorHistory: usize,
    pub DeferredRoutine: Option<KDEFERRED_ROUTINE>,
    pub DeferredContext: *mut c_void,
    pub SystemArgument1: *mut c_void,
    pub SystemArgument2: *mut c_void,
    pub DpcData: *mut c_void,
}

const _: () = {
    use core::mem::{offset_of, size_of};
    assert!(size_of::<KDPC>() == 0x40);
    assert!(offset_of!(KDPC, DpcListEntry) == 0x08);
    assert!(offset_of!(KDPC, DeferredRoutine) == 0x18);
    assert!(offset_of!(KDPC, SystemArgument1) == 0x28);
    assert!(offset_of!(KDPC, DpcData) == 0x38);
};

/// [`KAPC_STATE`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-kestackattachprocess):
/// a thread's APC state, and the room a driver gives
/// `KeStackAttachProcess` to save one in. The driver owns it.
#[repr(C)]
pub struct KAPC_STATE {
    pub ApcListHead: [LIST_ENTRY; 2],
    /// The process the saved state belongs to. `KeStackAttachProcess`
    /// leaves [`KAPC_STATE_NOT_ATTACHED`] here when the thread was in
    /// the process already and nothing was saved.
    pub Process: *mut core::ffi::c_void,
    pub InProgressFlags: u8,
    pub KernelApcPending: u8,
    pub UserApcPendingAll: u8,
}

/// What `KAPC_STATE.Process` holds after an attach that did nothing.
pub const KAPC_STATE_NOT_ATTACHED: usize = 1;

const _: () = {
    use core::mem::{offset_of, size_of};
    assert!(size_of::<KAPC_STATE>() == 0x30);
    assert!(offset_of!(KAPC_STATE, Process) == 0x20);
    assert!(offset_of!(KAPC_STATE, InProgressFlags) == 0x28);
    assert!(offset_of!(KAPC_STATE, KernelApcPending) == 0x29);
    assert!(offset_of!(KAPC_STATE, UserApcPendingAll) == 0x2A);
};

/// `LIST_ENTRY`.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct LIST_ENTRY {
    pub Flink: *mut LIST_ENTRY,
    pub Blink: *mut LIST_ENTRY,
}

/// `DISPATCHER_HEADER`: the start of every object a thread can wait on.
/// The first four bytes mean different things for different objects; the
/// names here are the timer's.
#[repr(C)]
pub struct DISPATCHER_HEADER {
    /// The object's type; bit 7 is the object's lock.
    pub Type: u8,
    pub TimerControlFlags: u8,
    pub Hand: u8,
    /// Bit 6: the timer is in a timer table.
    pub TimerMiscFlags: u8,
    pub SignalState: i32,
    pub WaitListHead: LIST_ENTRY,
}

/// Bit 7 of `DISPATCHER_HEADER.Type`: the object's lock.
pub const OBJECT_LOCK: u8 = 0x80;
/// `DISPATCHER_HEADER.Type` of a timer made by `KeInitializeTimer`:
/// `TimerNotificationObject`.
pub const TIMER_NOTIFICATION_OBJECT: u8 = 8;
/// `TimerMiscFlags`: `Inserted`.
pub const TIMER_INSERTED: u8 = 1 << 6;

/// `KTIMER`.
#[repr(C)]
pub struct KTIMER {
    pub Header: DISPATCHER_HEADER,
    /// When it is due, in interrupt time.
    pub DueTime: u64,
    pub TimerListEntry: LIST_ENTRY,
    pub Dpc: *mut KDPC,
    /// The processor whose table it is in.
    pub Processor: u16,
    pub TimerType: u16,
    /// Milliseconds between firings; 0 for a one-shot timer.
    pub Period: u32,
}

/// [`PROCESSOR_NUMBER`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/miniport/ns-miniport-_processor_number):
/// a processor by its group and its number in the group.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct PROCESSOR_NUMBER {
    pub Group: u16,
    pub Number: u8,
    pub Reserved: u8,
}

const _: () = {
    assert!(core::mem::size_of::<PROCESSOR_NUMBER>() == 4);
    assert!(core::mem::offset_of!(PROCESSOR_NUMBER, Number) == 2);
    assert!(core::mem::offset_of!(PROCESSOR_NUMBER, Reserved) == 3);
};

/// `DISPATCHER_HEADER.Type`... of a `KDPC` made by
/// `KeInitializeThreadedDpc`: `ThreadedDpcObject`.
pub const THREADED_DPC_OBJECT: u8 = 0x1A;
/// `KDPC_IMPORTANCE`: `HighImportance`, the largest value there is.
pub const HIGH_IMPORTANCE: u8 = 2;

/// `KTIMER2` (`wdm.h`): the storage a driver sets aside for a timer of
/// the `KeInitializeTimer2` family. The fields are Windows' and no
/// driver reads them; how NK uses the bytes is `ke::timer2`'s.
#[repr(C)]
pub struct KTIMER2 {
    pub Header: DISPATCHER_HEADER,
    /// A union with a `LIST_ENTRY`.
    pub RbNodes: [[usize; 3]; 2],
    pub DueTime: [i64; 2],
    pub Period: i64,
    pub Callback: *mut c_void,
    pub CallbackContext: *mut c_void,
    pub DisableCallback: *mut c_void,
    pub DisableContext: *mut c_void,
    pub AbsoluteSystemTime: u8,
    pub TypeFlags: u8,
    pub CollectionIndex: [u8; 2],
}

const _: () = {
    use core::mem::{offset_of, size_of};
    assert!(size_of::<KTIMER2>() == 0x88);
    assert!(offset_of!(KTIMER2, RbNodes) == 0x18);
    assert!(offset_of!(KTIMER2, DueTime) == 0x48);
    assert!(offset_of!(KTIMER2, Period) == 0x58);
    assert!(offset_of!(KTIMER2, Callback) == 0x60);
    assert!(offset_of!(KTIMER2, CallbackContext) == 0x68);
    assert!(offset_of!(KTIMER2, DisableCallback) == 0x70);
    assert!(offset_of!(KTIMER2, DisableContext) == 0x78);
    assert!(offset_of!(KTIMER2, AbsoluteSystemTime) == 0x80);
    assert!(offset_of!(KTIMER2, TypeFlags) == 0x81);
    assert!(offset_of!(KTIMER2, CollectionIndex) == 0x82);
    assert!(size_of::<LIST_ENTRY>() == 0x10);
    assert!(size_of::<DISPATCHER_HEADER>() == 0x18);
    assert!(offset_of!(DISPATCHER_HEADER, SignalState) == 0x04);
    assert!(offset_of!(DISPATCHER_HEADER, WaitListHead) == 0x08);
    assert!(size_of::<KTIMER>() == 0x40);
    assert!(offset_of!(KTIMER, DueTime) == 0x18);
    assert!(offset_of!(KTIMER, TimerListEntry) == 0x20);
    assert!(offset_of!(KTIMER, Dpc) == 0x30);
    assert!(offset_of!(KTIMER, Period) == 0x3C);
};

/// `DISPATCHER_HEADER.Type` values NK knows (`KOBJECTS`).
pub const EVENT_NOTIFICATION_OBJECT: u8 = 0;
pub const EVENT_SYNCHRONIZATION_OBJECT: u8 = 1;
pub const SEMAPHORE_OBJECT: u8 = 5;
pub const TIMER_SYNCHRONIZATION_OBJECT: u8 = 9;
/// `TimerMiscFlags`: `Expired`.
pub const TIMER_EXPIRED: u8 = 1 << 7;

/// `KEVENT`.
#[repr(C)]
pub struct KEVENT {
    pub Header: DISPATCHER_HEADER,
}

/// `KSEMAPHORE`.
#[repr(C)]
pub struct KSEMAPHORE {
    pub Header: DISPATCHER_HEADER,
    pub Limit: i32,
}

/// `KWAIT_BLOCK`: one thread's wait on one object, linked into the
/// object's wait list. Four of them are built into every thread, where
/// the two spare fields are used for other things; NK writes the rest
/// field by field.
#[repr(C)]
pub struct KWAIT_BLOCK {
    pub WaitListEntry: LIST_ENTRY,
    pub WaitType: u8,
    pub BlockState: u8,
    pub WaitKey: u16,
    pub SpareLong: i32,
    pub Thread: *mut c_void,
    pub Object: *mut c_void,
    pub SparePtr: *mut c_void,
}

/// `KWAIT_BLOCK.BlockState`: linked into its object's wait list.
pub const WAIT_BLOCK_ACTIVE: u8 = 4;
/// `KWAIT_BLOCK.BlockState`: not linked.
pub const WAIT_BLOCK_INACTIVE: u8 = 5;

const _: () = {
    use core::mem::{offset_of, size_of};
    assert!(size_of::<KEVENT>() == 0x18);
    assert!(size_of::<KSEMAPHORE>() == 0x20);
    assert!(offset_of!(KSEMAPHORE, Limit) == 0x18);
    assert!(size_of::<KWAIT_BLOCK>() == 0x30);
    assert!(offset_of!(KWAIT_BLOCK, BlockState) == 0x11);
    assert!(offset_of!(KWAIT_BLOCK, Thread) == 0x18);
    assert!(offset_of!(KWAIT_BLOCK, Object) == 0x20);
};

/// `DISPATCHER_HEADER.Type` of a mutex: `MutantObject`.
pub const MUTANT_OBJECT: u8 = 2;

/// `KMUTANT` (`KMUTEX`). Its signal state is 1 when free, 0 when held
/// once, and one lower for each further time its owner has taken it.
#[repr(C)]
pub struct KMUTANT {
    pub Header: DISPATCHER_HEADER,
    /// Links the mutex into its owner's list of mutexes held.
    pub MutantListEntry: LIST_ENTRY,
    pub OwnerThread: *mut c_void,
    pub MutantFlags: u8,
    /// 1 for a mutex from `KeInitializeMutex`: kernel APCs stay off
    /// while it is held.
    pub ApcDisable: u8,
}

/// `FAST_MUTEX`. A driver initialises it in line: `Count` 1, no owner,
/// and a synchronization event. `Count` is 1 when free, 0 when held, and
/// one lower for each thread waiting.
#[repr(C)]
pub struct FAST_MUTEX {
    pub Count: i32,
    pub Owner: *mut c_void,
    pub Contention: u32,
    pub Event: KEVENT,
    pub OldIrql: u32,
}

const _: () = {
    use core::mem::{offset_of, size_of};
    assert!(size_of::<KMUTANT>() == 0x38);
    assert!(offset_of!(KMUTANT, OwnerThread) == 0x28);
    assert!(offset_of!(KMUTANT, ApcDisable) == 0x31);
    assert!(size_of::<FAST_MUTEX>() == 0x38);
    assert!(offset_of!(FAST_MUTEX, Event) == 0x18);
    assert!(offset_of!(FAST_MUTEX, OldIrql) == 0x30);
};

/// `KUSER_SHARED_DATA`: a page at a fixed kernel address that code built
/// with the WDK reads the time from directly. Only the fields NK
/// maintains are named.
pub const SHARED_DATA: u64 = 0xFFFF_F780_0000_0000;
/// `TickCountMultiplier`, 32 bits.
pub const SHARED_TICK_MULTIPLIER: usize = 0x004;
/// `InterruptTime`: 100 ns units since boot.
pub const SHARED_INTERRUPT_TIME: usize = 0x008;
/// `SystemTime`: 100 ns units since 1601, UTC.
pub const SHARED_SYSTEM_TIME: usize = 0x014;
/// `TickCount`: clock ticks since boot.
pub const SHARED_TICK_COUNT: usize = 0x320;

/// `KBUGCHECK_CALLBACK_REASON`: why a bugcheck callback is called. Only
/// the values NK acts on are named.
pub const KB_CALLBACK_RESERVED1: u32 = 1;
pub const KB_CALLBACK_TRIAGE_DUMP_DATA: u32 = 7;

/// `KBUGCHECK_BUFFER_DUMP_STATE`: a callback record's `State`.
pub const BUFFER_EMPTY: u8 = 0;
pub const BUFFER_INSERTED: u8 = 1;
pub const BUFFER_FINISHED: u8 = 3;
pub const BUFFER_INCOMPLETE: u8 = 4;

/// `KBUGCHECK_REASON_CALLBACK_ROUTINE`: reason, record, data, length.
pub type KBUGCHECK_REASON_CALLBACK_ROUTINE =
    unsafe extern "C" fn(u32, *mut KBUGCHECK_REASON_CALLBACK_RECORD, *mut c_void, u32);

/// [`KBUGCHECK_REASON_CALLBACK_RECORD`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-keregisterbugcheckreasoncallback):
/// the driver's memory, which `KeInitializeCallbackRecord` (in-line
/// code) marks empty and the kernel links into its list.
#[repr(C)]
pub struct KBUGCHECK_REASON_CALLBACK_RECORD {
    pub Entry: LIST_ENTRY,
    pub CallbackRoutine: Option<KBUGCHECK_REASON_CALLBACK_ROUTINE>,
    pub Component: *mut u8,
    pub Checksum: usize,
    pub Reason: u32,
    pub State: u8,
}

/// `KBUGCHECK_TRIAGE_DUMP_DATA`: what a `KbCallbackTriageDumpData`
/// callback is shown, and where it leaves its array of memory ranges.
#[repr(C)]
pub struct KBUGCHECK_TRIAGE_DUMP_DATA {
    pub DataArray: *mut c_void,
    pub Flags: u32,
    pub MaxVirtMemSize: u32,
    pub BugCheckCode: u32,
    pub BugCheckParameter1: usize,
    pub BugCheckParameter2: usize,
    pub BugCheckParameter3: usize,
    pub BugCheckParameter4: usize,
}

const _: () = {
    use core::mem::{offset_of, size_of};
    assert!(size_of::<KBUGCHECK_REASON_CALLBACK_RECORD>() == 0x30);
    assert!(offset_of!(KBUGCHECK_REASON_CALLBACK_RECORD, CallbackRoutine) == 0x10);
    assert!(offset_of!(KBUGCHECK_REASON_CALLBACK_RECORD, Component) == 0x18);
    assert!(offset_of!(KBUGCHECK_REASON_CALLBACK_RECORD, Checksum) == 0x20);
    assert!(offset_of!(KBUGCHECK_REASON_CALLBACK_RECORD, Reason) == 0x28);
    assert!(offset_of!(KBUGCHECK_REASON_CALLBACK_RECORD, State) == 0x2C);
    assert!(size_of::<KBUGCHECK_TRIAGE_DUMP_DATA>() == 0x38);
    assert!(offset_of!(KBUGCHECK_TRIAGE_DUMP_DATA, MaxVirtMemSize) == 0x0C);
    assert!(offset_of!(KBUGCHECK_TRIAGE_DUMP_DATA, BugCheckCode) == 0x10);
    assert!(offset_of!(KBUGCHECK_TRIAGE_DUMP_DATA, BugCheckParameter1) == 0x18);
};
