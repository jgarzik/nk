//! The file-system runtime library's rules with no driver memory behind
//! them, so the host can test them. The kernel's `FsRtl*` exports copy a
//! driver's structure in, apply these, and write the result back.
//!
//! [`mcb`] is the mapping control block: which run of a file's virtual
//! blocks lies at which logical blocks of its volume. [`status`] is
//! which statuses a file system lets through. [`tunnel`] is the
//! tunnel cache of names of files just renamed or deleted.

#![cfg_attr(not(test), no_std)]

extern crate alloc;

pub mod mcb;
pub mod status;
pub mod tunnel;
