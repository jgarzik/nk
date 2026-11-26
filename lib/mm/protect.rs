//! What a Windows page protection or caching type asks of a mapping.
//!
//! [Memory protection constants](https://learn.microsoft.com/en-us/windows/win32/memory/memory-protection-constants),
//! [`MEMORY_CACHING_TYPE`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/ne-wdm-_memory_caching_type).

pub const PAGE_NOACCESS: u32 = 0x01;
pub const PAGE_READONLY: u32 = 0x02;
pub const PAGE_READWRITE: u32 = 0x04;
pub const PAGE_EXECUTE: u32 = 0x10;
pub const PAGE_EXECUTE_READ: u32 = 0x20;
pub const PAGE_EXECUTE_READWRITE: u32 = 0x40;
pub const PAGE_NOCACHE: u32 = 0x200;
pub const PAGE_WRITECOMBINE: u32 = 0x400;

/// `MEMORY_CACHING_TYPE`.
pub const MM_NON_CACHED: u32 = 0;
pub const MM_CACHED: u32 = 1;
pub const MM_WRITE_COMBINED: u32 = 2;
pub const MM_HARDWARE_COHERENT_CACHED: u32 = 3;
pub const MM_NON_CACHED_UNORDERED: u32 = 4;
pub const MM_USWC_CACHED: u32 = 5;

/// What a system mapping is asked to allow.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Protection {
    /// Any access at all: `PAGE_NOACCESS` asks for none.
    pub access: bool,
    pub write: bool,
    pub exec: bool,
    /// Not through the processor's caches: `PAGE_NOCACHE`, or
    /// `PAGE_WRITECOMBINE`, which NK maps the same way. Write combining
    /// only makes a run of writes cheaper; what is read and written is
    /// the same.
    pub uncached: bool,
}

/// What `protect`, a system mapping's protection, asks for. `None` for a
/// value that is not one access with at most one of the caching
/// modifiers: copy-on-write, guard pages and unknown bits have no
/// meaning for a system mapping.
pub const fn protection(protect: u32) -> Option<Protection> {
    let (access, write, exec) = match protect & !(PAGE_NOCACHE | PAGE_WRITECOMBINE) {
        PAGE_NOACCESS => (false, false, false),
        PAGE_READONLY => (true, false, false),
        PAGE_READWRITE => (true, true, false),
        PAGE_EXECUTE | PAGE_EXECUTE_READ => (true, false, true),
        PAGE_EXECUTE_READWRITE => (true, true, true),
        _ => return None,
    };
    let modifiers = protect & (PAGE_NOCACHE | PAGE_WRITECOMBINE);
    if modifiers == PAGE_NOCACHE | PAGE_WRITECOMBINE {
        return None;
    }
    Some(Protection {
        access,
        write,
        exec,
        uncached: modifiers != 0,
    })
}

/// Whether a `MEMORY_CACHING_TYPE` asks for a mapping that bypasses the
/// caches; `None` for a value that is not one.
pub const fn uncached(cache_type: u32) -> Option<bool> {
    match cache_type {
        MM_NON_CACHED | MM_WRITE_COMBINED | MM_NON_CACHED_UNORDERED => Some(true),
        MM_CACHED | MM_HARDWARE_COHERENT_CACHED | MM_USWC_CACHED => Some(false),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn p(access: bool, write: bool, exec: bool, uncached: bool) -> Option<Protection> {
        Some(Protection {
            access,
            write,
            exec,
            uncached,
        })
    }

    #[test]
    fn a_protection_is_one_access_and_at_most_one_caching_modifier() {
        assert_eq!(protection(PAGE_READWRITE), p(true, true, false, false));
        assert_eq!(
            protection(PAGE_READWRITE | PAGE_NOCACHE),
            p(true, true, false, true)
        );
        assert_eq!(
            protection(PAGE_READWRITE | PAGE_WRITECOMBINE),
            p(true, true, false, true)
        );
        assert_eq!(protection(PAGE_READONLY), p(true, false, false, false));
        assert_eq!(
            protection(PAGE_READONLY | PAGE_NOCACHE),
            p(true, false, false, true)
        );
        assert_eq!(protection(PAGE_EXECUTE), p(true, false, true, false));
        assert_eq!(protection(PAGE_EXECUTE_READ), p(true, false, true, false));
        assert_eq!(
            protection(PAGE_EXECUTE_READWRITE),
            p(true, true, true, false)
        );
        assert_eq!(protection(PAGE_NOACCESS), p(false, false, false, false));
    }

    #[test]
    fn a_protection_that_means_nothing_for_a_system_mapping_is_refused() {
        // None; two accesses; both modifiers; copy on write; a guard
        // page; a bit nobody defines.
        for bad in [
            0,
            PAGE_READONLY | PAGE_READWRITE,
            PAGE_READWRITE | PAGE_NOCACHE | PAGE_WRITECOMBINE,
            0x08,
            0x80,
            PAGE_READWRITE | 0x100,
            PAGE_READWRITE | 0x8000_0000,
            PAGE_NOCACHE,
        ] {
            assert_eq!(protection(bad), None, "{bad:#x}");
        }
    }

    #[test]
    fn a_caching_type_is_cached_or_not() {
        assert_eq!(uncached(MM_NON_CACHED), Some(true));
        assert_eq!(uncached(MM_CACHED), Some(false));
        assert_eq!(uncached(MM_WRITE_COMBINED), Some(true));
        assert_eq!(uncached(MM_HARDWARE_COHERENT_CACHED), Some(false));
        assert_eq!(uncached(MM_NON_CACHED_UNORDERED), Some(true));
        assert_eq!(uncached(MM_USWC_CACHED), Some(false));
        assert_eq!(uncached(6), None);
        assert_eq!(uncached(u32::MAX), None);
    }
}
