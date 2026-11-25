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

/// `LIST_ENTRY`.
#[repr(C)]
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

const _: () = {
    use core::mem::{offset_of, size_of};
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
