//! Memory-management logic that needs no hardware: page-table
//! construction, frame, pool and address-space allocator arithmetic, the
//! page-frame-number database, and what Windows' page protections ask of
//! a mapping.
//!
//! Memory is reached through traits, so the same code runs in the loader,
//! in the kernel and in host unit tests against fake memory. No `unsafe`.

#![cfg_attr(not(test), no_std)]

pub mod frames;
pub mod heap;
pub mod pfn;
pub mod pooltab;
pub mod probe;
pub mod protect;
pub mod pt;
pub mod pte;
pub mod section;
pub mod space;

pub const PAGE_SIZE: u64 = 4096;
