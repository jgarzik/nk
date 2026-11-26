//! The process structure's rules as pure functions, so the host can
//! test them: what the kernel decides from numbers alone, before it
//! touches a thread or a process.
//!
//! [`info`] is the thread information classes of
//! `ZwSetInformationThread` and what a base priority does to a thread.

#![cfg_attr(not(test), no_std)]

pub mod info;
