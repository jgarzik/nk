//! Architecture layer. Generic code calls the names re-exported here; no
//! `cfg(target_arch)` appears outside this directory.

#[cfg(target_arch = "x86_64")]
#[path = "x86_64/mod.rs"]
mod imp;

#[cfg(target_arch = "aarch64")]
#[path = "aarch64/mod.rs"]
mod imp;

pub use imp::*;
