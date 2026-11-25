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
