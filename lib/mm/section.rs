//! The decisions about a file's data section that need no memory: where
//! a file offset's page lives, whether the file can be truncated or its
//! pages purged, and how a failed write is treated. Each is the pinned
//! Windows kernel's rule, read from its code.

use crate::PAGE_SIZE;

/// Bytes of a file one subsection covers: one system-cache view.
pub const SUBSECTION_BYTES: u64 = 256 * 1024;
/// Pages one subsection covers.
pub const SUBSECTION_PAGES: usize = (SUBSECTION_BYTES / PAGE_SIZE) as usize;

/// Which subsection holds the page at file offset `offset`, and which
/// of its pages it is.
pub fn locate(offset: u64) -> (usize, usize) {
    (
        (offset / SUBSECTION_BYTES) as usize,
        (offset % SUBSECTION_BYTES / PAGE_SIZE) as usize,
    )
}

/// How many subsections a section of `size` bytes has.
pub fn subsections(size: u64) -> usize {
    size.div_ceil(SUBSECTION_BYTES) as usize
}

/// `_MMSECTION_FLAGS` bits of a control area NK keeps.
pub mod flag {
    pub const BEING_DELETED: u32 = 1 << 0;
    pub const BEING_CREATED: u32 = 1 << 1;
    pub const BEING_PURGED: u32 = 1 << 2;
    pub const NO_MODIFIED_WRITING: u32 = 1 << 3;
    pub const FILE: u32 = 1 << 7;
    pub const WAS_PURGED: u32 = 1 << 15;
}

/// The counts of a data control area the truncate and purge rules
/// read.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Counts {
    pub flags: u32,
    pub locked_pages: u64,
    pub user_references: u64,
    pub mapped_views: u64,
    /// The section's size: where its last subsection ends.
    pub size: u64,
}

/// `MiCanFileBeTruncatedInternal` once the image section is dealt with
/// and a data section exists: whether a file whose data section has
/// `counts` may be cut to `new_size` (`None`: to no size the caller
/// names). With `purge`, as `MmPurgeSection` asks: mapped views refuse
/// too, unless `ignore_views`.
pub fn can_truncate(
    counts: &Counts,
    new_size: Option<u64>,
    purge: bool,
    ignore_views: bool,
) -> bool {
    if counts.flags & (flag::BEING_DELETED | flag::BEING_CREATED) != 0 {
        return false;
    }
    if counts.locked_pages > 1 && counts.flags & flag::NO_MODIFIED_WRITING == 0 {
        return false;
    }
    if purge && !ignore_views && counts.mapped_views != 0 {
        return false;
    }
    if counts.user_references == 0 {
        return true;
    }
    match new_size {
        None => false,
        Some(size) => size >= counts.size.next_multiple_of(PAGE_SIZE),
    }
}

/// `MiIsRetryIoStatus`: whether a flush write that failed with `status`
/// over `bytes` bytes is tried again: for want of memory; or, over more
/// than a page, for a failure that is not the whole device's (a bad
/// sector), page by page to find the page that fails.
pub fn is_retry_status(status: i32, bytes: u64) -> bool {
    const STATUS_NO_MEMORY: u32 = 0xC000_0017;
    const STATUS_INSUFFICIENT_RESOURCES: u32 = 0xC000_009A;
    const STATUS_WORKING_SET_QUOTA: u32 = 0xC000_00A1;
    match status as u32 {
        STATUS_NO_MEMORY | STATUS_INSUFFICIENT_RESOURCES | STATUS_WORKING_SET_QUOTA => true,
        _ => bytes > PAGE_SIZE && !is_total_device_failure(status),
    }
}

/// `FsRtlIsTotalDeviceFailure`: an error that is not one of a bad
/// sector's (CRC, device data error, and 0xC0000470).
pub fn is_total_device_failure(status: i32) -> bool {
    status < 0 && !matches!(status as u32, 0xC000_003F | 0xC000_009C | 0xC000_0470)
}

/// `MmIsWriteErrorFatal(CacheManager, Remote, Status)`: whether data
/// that failed to be written with `status` is given up rather than kept
/// dirty. `cache_manager`: the cache manager asks; `remote`: the file
/// is on a remote device (`FILE_REMOTE_DEVICE`).
pub fn is_write_error_fatal(cache_manager: bool, remote: bool, status: i32) -> bool {
    const STATUS_FILE_LOCK_CONFLICT: u32 = 0xC000_0054;
    if status as u32 != STATUS_FILE_LOCK_CONFLICT && cache_manager && remote {
        return true;
    }
    match status as u32 {
        // Invalid, corrupt, dismounted, no such device.
        0xC000_0098 | 0xC000_0102 | 0xC000_026E | 0xC000_000E => true,
        // Device not connected.
        0xC000_009D if !cache_manager || !remote => true,
        // Media write protected.
        0xC000_00A2 if cache_manager => true,
        _ => !is_total_device_failure(status),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn offsets_find_their_subsection() {
        assert_eq!(locate(0), (0, 0));
        assert_eq!(locate(0x3_FFFF), (0, 63));
        assert_eq!(locate(0x4_0000), (1, 0));
        assert_eq!(locate(0x30_1234), (12, 1));
        assert_eq!(subsections(0), 0);
        assert_eq!(subsections(1), 1);
        assert_eq!(subsections(0x10_0000), 4);
        assert_eq!(subsections(0x10_0001), 5);
    }

    #[test]
    fn the_truncate_rule_is_windows() {
        let cache_only = Counts {
            locked_pages: 1,
            size: 0x10_0000,
            ..Counts::default()
        };
        assert!(can_truncate(&cache_only, Some(0), false, false));
        assert!(can_truncate(&cache_only, None, false, false));
        let creating = Counts {
            flags: flag::BEING_CREATED,
            ..cache_only
        };
        assert!(!can_truncate(&creating, Some(0), false, false));
        let locked = Counts {
            locked_pages: 2,
            ..cache_only
        };
        assert!(!can_truncate(&locked, Some(0), false, false));
        let no_write = Counts {
            flags: flag::NO_MODIFIED_WRITING,
            ..locked
        };
        assert!(can_truncate(&no_write, Some(0), false, false));
        let mapped = Counts {
            user_references: 1,
            mapped_views: 1,
            size: 0x2345,
            ..cache_only
        };
        assert!(!can_truncate(&mapped, None, false, false));
        assert!(!can_truncate(&mapped, Some(0x2fff), false, false));
        assert!(can_truncate(&mapped, Some(0x3000), false, false));
        assert!(!can_truncate(&mapped, Some(0x3000), true, false));
        assert!(can_truncate(&mapped, Some(0x3000), true, true));
        let viewed = Counts {
            mapped_views: 1,
            ..cache_only
        };
        assert!(!can_truncate(&viewed, None, true, false));
        assert!(can_truncate(&viewed, None, false, false));
    }

    #[test]
    fn write_errors_are_sorted_as_windows_sorts_them() {
        let s = |v: u32| v as i32;
        assert!(is_retry_status(s(0xC000_009A), 0x1000));
        assert!(!is_retry_status(s(0xC000_0185), 0x1000));
        // A bad sector in a write of several pages: again, page by page.
        assert!(is_retry_status(s(0xC000_009C), 0x2000));
        assert!(!is_retry_status(s(0xC000_009C), 0x1000));
        assert!(!is_retry_status(s(0xC000_0185), 0x2000));
        assert!(is_total_device_failure(s(0xC000_0185)));
        assert!(!is_total_device_failure(s(0xC000_003F)));
        assert!(!is_total_device_failure(0));
        // A bad sector is fatal; a device that failed whole is not.
        assert!(is_write_error_fatal(false, false, s(0xC000_009C)));
        assert!(!is_write_error_fatal(false, false, s(0xC000_0185)));
        assert!(is_write_error_fatal(false, false, s(0xC000_026E)));
        assert!(is_write_error_fatal(true, true, s(0xC000_0185)));
        assert!(!is_write_error_fatal(true, true, s(0xC000_0054)));
        assert!(is_write_error_fatal(true, false, s(0xC000_00A2)));
        assert!(!is_write_error_fatal(false, false, s(0xC000_00A2)));
        assert!(is_write_error_fatal(false, true, s(0xC000_009D)));
    }
}
