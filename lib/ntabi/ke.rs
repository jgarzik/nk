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
