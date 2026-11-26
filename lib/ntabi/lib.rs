//! Everything a Windows driver can see of the kernel's data: structure
//! layouts, status codes, constants.
//!
//! These are the Windows 10 (NT 10.0.19041 line) definitions for x86-64
//! and arm64, taken from Microsoft's public WDK headers and documentation.
//! Each structure carries size and offset checks. Structures here are
//! exactly as large as Windows makes them: the kernel keeps its own
//! bookkeeping elsewhere, never in extra trailing fields.
//!
//! Drivers write to these objects at will, so the kernel reaches them
//! through raw pointers, never through Rust references.
//!
//! Names keep their Windows spelling so they can be searched for in
//! Microsoft's documentation.

#![cfg_attr(not(test), no_std)]
#![allow(non_snake_case, non_camel_case_types, clippy::upper_case_acronyms)]

pub mod ex;
pub mod io;
pub mod ke;
pub mod ob;
pub mod pcr;
pub mod process;
pub mod se;
pub mod seh;
pub mod silo;
pub mod status;
pub mod thread;

#[cfg(test)]
mod pdb;
#[cfg(test)]
mod probe;
