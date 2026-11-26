//! The executive's primitives as logic over memory a driver owns, with
//! no threads and no hardware behind them, so the host can test them.
//!
//! Each primitive is a set of transitions: given the old state, the new
//! state and what the caller must do next (the lock is taken, wait, wake
//! these waiters). The kernel binds them to the driver's memory, makes
//! each transition atomic, and supplies the blocking and waking with its
//! own wait machinery.
//!
//! [`pushlock`] is `EX_PUSH_LOCK`, one word. [`resource`] is `ERESOURCE`
//! and its owner table. [`slist`] is `SLIST_HEADER`.
//! [`lookaside`] is what initialising a lookaside list writes.
//! [`uuid`] makes the time-based UUIDs of `ExUuidCreate`.
//! [`sysinfo`] is the length rules of `ZwQuerySystemInformation` and the
//! list of loaded modules it and `RtlQueryModuleInformation` report.
//!
//! [`timer`] reads the arguments of the `ExAllocateTimer` family: an
//! executive timer is a kernel timer with a callback, and the rules for
//! due times are `nk_ke::wait`'s.

#![cfg_attr(not(test), no_std)]

pub mod lookaside;
pub mod pushlock;
pub mod resource;
pub mod slist;
pub mod sysinfo;
pub mod timer;
pub mod uuid;

#[cfg(test)]
mod model;
