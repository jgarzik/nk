//! Kernel core: synchronisation and processor state.

pub mod spinlock;

pub use spinlock::SpinLock;
