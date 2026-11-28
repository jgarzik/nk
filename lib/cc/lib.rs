//! The cache manager's rules with no file or memory behind them, so the
//! host can test them. The kernel's `Cc*` exports keep their state in
//! these structures, under their own locks, and act on what they decide.
//!
//! - [`vacbidx`]: which view of a file's section each 256 KiB of the
//!   file is mapped in, in Windows' three size classes.
//! - [`mbcb`]: the dirty pages of a file written by copy or MDL, as page
//!   bitmaps, and the runs the lazy writer and flushes take from them.
//! - [`bcblist`]: a file's pinned ranges (buffer control blocks), the
//!   one that covers a range, the dirty runs among them, and the three
//!   kinds of handle a file system is given.
//! - [`readahead`]: the access pattern of a file object's last reads and
//!   the read-ahead it calls for.
//! - [`pages`]: the dirty-page thresholds and how many pages a lazy
//!   writer's pass writes.
//! - [`uninit`]: whether `CcUninitializeCacheMap` deletes a file's cache
//!   map at once or leaves it to the lazy writer.

#![cfg_attr(not(test), no_std)]

extern crate alloc;

pub mod bcblist;
pub mod drain;
pub mod mbcb;
pub mod pages;
pub mod readahead;
pub mod uninit;
pub mod vacbidx;

/// Bytes in a page.
pub const PAGE_SIZE: u64 = 4096;
/// Bytes in a view (`VACB_MAPPING_GRANULARITY`).
pub const VIEW_BYTES: u64 = 256 * 1024;
/// Bytes a cache manager's section grows by, and what a file opened for
/// writing has its first section rounded up to.
pub const SECTION_GRANULARITY: u64 = 1 << 20;

/// The size of the section `CcInitializeCacheMapEx` makes for a file of
/// allocation size `allocation`, opened with write access or not: an
/// allocation of 0 counts as 1, then it is rounded up to 1 MiB when the
/// file object has write access and to one view (256 KiB) when it has
/// not, as the pinned kernel rounds it.
pub fn first_section_size(allocation: u64, write_access: bool) -> u64 {
    let size = allocation.max(1);
    if write_access {
        size.next_multiple_of(SECTION_GRANULARITY)
    } else {
        size.next_multiple_of(VIEW_BYTES)
    }
}

/// The size `CcSetFileSizesEx` extends a section to for a new
/// allocation size: rounded up to 1 MiB.
pub fn extended_section_size(allocation: u64) -> u64 {
    allocation.next_multiple_of(SECTION_GRANULARITY)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_first_section_is_rounded_by_the_access() {
        assert_eq!(first_section_size(0, false), VIEW_BYTES);
        assert_eq!(first_section_size(0, true), 1 << 20);
        assert_eq!(first_section_size(VIEW_BYTES + 1, false), 2 * VIEW_BYTES);
        assert_eq!(first_section_size(VIEW_BYTES + 1, true), 1 << 20);
        assert_eq!(first_section_size((1 << 20) + 1, true), 2 << 20);
    }

    #[test]
    fn an_extension_is_whole_mebibytes() {
        assert_eq!(extended_section_size(1), 1 << 20);
        assert_eq!(extended_section_size(1 << 20), 1 << 20);
        assert_eq!(extended_section_size((1 << 20) + 1), 2 << 20);
    }
}
