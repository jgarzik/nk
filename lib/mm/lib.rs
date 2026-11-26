//! Memory-management logic that needs no hardware: page-table
//! construction, and frame, pool and address-space allocator arithmetic.
//!
//! Memory is reached through traits, so the same code runs in the loader,
//! in the kernel and in host unit tests against fake memory. No `unsafe`.

#![cfg_attr(not(test), no_std)]

pub mod frames;
pub mod heap;
pub mod pt;
pub mod space;

pub const PAGE_SIZE: u64 = 4096;
