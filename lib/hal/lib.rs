//! What the hardware layer works out before it touches a register: how
//! an IRQL, a processor or a period is encoded for an interrupt
//! controller or a timer.
//!
//! Both architectures are built on every host, so the arm64 arithmetic
//! is tested where the kernel is developed. The registers themselves are
//! `kernel/arch`'s.

#![cfg_attr(not(test), no_std)]

pub mod arm;
pub mod x86;
