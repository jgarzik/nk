//! The object manager's tables, with no objects behind them: the
//! namespace that maps names to objects and symbolic links, and the
//! slots of a handle table.
//!
//! Both hold whatever the kernel puts in them (a pointer, in practice)
//! and never look inside it; the kernel wraps them in a lock and does
//! the reference counting.
//!
//! [`tree`] is the namespace: directories, and a path walk that follows
//! symbolic links and stops at the object whose type parses the rest.
//! [`handles`] is handle slots with granted access and attributes.
//! [`header`] is how an object's header names its type.
//! [`descriptors`] is the store of security descriptors: one counted
//! copy of each.
//!
//! [`descriptors`] uses `unsafe`: it links and counts blocks the kernel
//! allocated, reached by raw pointer. Nothing else in the crate does.

#![cfg_attr(not(test), no_std)]

extern crate alloc;

pub mod descriptors;
pub mod handles;
pub mod header;
pub mod tree;

/// How many symbolic links a lookup follows before giving up.
pub const MAX_LINK_DEPTH: usize = 8;
