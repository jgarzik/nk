//! Everything a Windows driver can see of the kernel's data: structure
//! layouts, status codes, constants.
//!
//! These are the Windows 10 (NT 10.0.19041 line) definitions for x86-64
//! and arm64, taken from Microsoft's public WDK headers and documentation.
//! Each structure carries compile-time size and offset checks. Structures
//! here are exactly as large as Windows makes them: the kernel keeps its
//! own bookkeeping elsewhere, never in extra trailing fields.
//!
//! Drivers write to these objects at will, so the kernel reaches them
//! through raw pointers, never through Rust references.

#![cfg_attr(not(test), no_std)]

pub mod pcr;
