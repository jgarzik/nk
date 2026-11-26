//! A disk as its requestor sees it, as pure functions the host can
//! test:
//!
//! - [`pattern`]: what the data disk of a boot scenario holds, sector
//!   by sector, before and after the kernel's test has written it. The
//!   mirror of `tools/datadisk.py`; `doc/TESTING.md` states the numbers.
//! - [`answer`]: what a disk answers its control codes with, read out
//!   of the bytes Microsoft's `disk.sys` and `classpnp.sys` put in a
//!   requestor's buffer, and held to what Microsoft documents of them.
//! - [`model`]: the same answers made, and the rule for which transfers
//!   a disk takes, for NK's own test disk.

#![cfg_attr(not(test), no_std)]

extern crate alloc;

pub mod answer;
pub mod model;
pub mod pattern;
