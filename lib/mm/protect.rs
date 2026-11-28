//! What a Windows page protection or caching type asks of a mapping.
//!
//! [Memory protection constants](https://learn.microsoft.com/en-us/windows/win32/memory/memory-protection-constants),
//! [`MEMORY_CACHING_TYPE`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/ne-wdm-_memory_caching_type).

pub const PAGE_NOACCESS: u32 = 0x01;
pub const PAGE_READONLY: u32 = 0x02;
pub const PAGE_READWRITE: u32 = 0x04;
pub const PAGE_WRITECOPY: u32 = 0x08;
pub const PAGE_EXECUTE: u32 = 0x10;
pub const PAGE_EXECUTE_READ: u32 = 0x20;
pub const PAGE_EXECUTE_READWRITE: u32 = 0x40;
pub const PAGE_EXECUTE_WRITECOPY: u32 = 0x80;
pub const PAGE_GUARD: u32 = 0x100;
pub const PAGE_NOCACHE: u32 = 0x200;
pub const PAGE_WRITECOMBINE: u32 = 0x400;

/// Virtual memory allocation/state/type flags (`winnt.h`).
pub const MEM_COMMIT: u32 = 0x0000_1000;
pub const MEM_RESERVE: u32 = 0x0000_2000;
pub const MEM_DECOMMIT: u32 = 0x0000_4000;
pub const MEM_RELEASE: u32 = 0x0000_8000;
pub const MEM_FREE: u32 = 0x0001_0000;
pub const MEM_PRIVATE: u32 = 0x0002_0000;
pub const MEM_MAPPED: u32 = 0x0004_0000;
pub const MEM_RESET: u32 = 0x0008_0000;
pub const MEM_TOP_DOWN: u32 = 0x0010_0000;
pub const MEM_WRITE_WATCH: u32 = 0x0020_0000;
pub const MEM_LARGE_PAGES: u32 = 0x2000_0000;
pub const MEM_IMAGE: u32 = 0x0100_0000;

/// Compact 5-bit internal protection code stored in software PTEs (bits 5..9).
/// `0` means uncommitted/empty; `1..=8` are committed base protections;
/// bit 4 (`0x10`) adds `PAGE_GUARD`.
pub const MM_PROT_EMPTY: u8 = 0;
pub const MM_PROT_READONLY: u8 = 1;
pub const MM_PROT_EXECUTE: u8 = 2;
pub const MM_PROT_EXECUTE_READ: u8 = 3;
pub const MM_PROT_READWRITE: u8 = 4;
pub const MM_PROT_WRITECOPY: u8 = 5;
pub const MM_PROT_EXECUTE_READWRITE: u8 = 6;
pub const MM_PROT_EXECUTE_WRITECOPY: u8 = 7;
pub const MM_PROT_NOACCESS: u8 = 8;
pub const MM_PROT_GUARD: u8 = 0x10;

/// Convert a Win32 user-mode `PAGE_*` protection into NK's 5-bit internal code.
/// Rejects invalid combinations (`PAGE_NOACCESS | PAGE_GUARD`, both `NOCACHE`
/// and `WRITECOMBINE`, unknown bits, or zero).
pub const fn win32_to_mm(win32: u32) -> Option<u8> {
    let base = win32 & !(PAGE_GUARD | PAGE_NOCACHE | PAGE_WRITECOMBINE);
    let modifiers = win32 & (PAGE_NOCACHE | PAGE_WRITECOMBINE);
    if modifiers == PAGE_NOCACHE | PAGE_WRITECOMBINE {
        return None;
    }
    let guard = win32 & PAGE_GUARD != 0;
    let code = match base {
        PAGE_NOACCESS => {
            if guard || modifiers != 0 {
                return None;
            }
            MM_PROT_NOACCESS
        }
        PAGE_READONLY => MM_PROT_READONLY,
        PAGE_READWRITE => MM_PROT_READWRITE,
        PAGE_WRITECOPY => MM_PROT_WRITECOPY,
        PAGE_EXECUTE => MM_PROT_EXECUTE,
        PAGE_EXECUTE_READ => MM_PROT_EXECUTE_READ,
        PAGE_EXECUTE_READWRITE => MM_PROT_EXECUTE_READWRITE,
        PAGE_EXECUTE_WRITECOPY => MM_PROT_EXECUTE_WRITECOPY,
        _ => return None,
    };
    Some(if guard { code | MM_PROT_GUARD } else { code })
}

/// Convert NK's 5-bit internal protection code back to Win32 `PAGE_*`.
pub const fn mm_to_win32(mm: u8) -> u32 {
    let guard = if mm & MM_PROT_GUARD != 0 {
        PAGE_GUARD
    } else {
        0
    };
    let base = match mm & !MM_PROT_GUARD {
        MM_PROT_READONLY => PAGE_READONLY,
        MM_PROT_EXECUTE => PAGE_EXECUTE,
        MM_PROT_EXECUTE_READ => PAGE_EXECUTE_READ,
        MM_PROT_READWRITE => PAGE_READWRITE,
        MM_PROT_WRITECOPY => PAGE_WRITECOPY,
        MM_PROT_EXECUTE_READWRITE => PAGE_EXECUTE_READWRITE,
        MM_PROT_EXECUTE_WRITECOPY => PAGE_EXECUTE_WRITECOPY,
        MM_PROT_NOACCESS => PAGE_NOACCESS,
        _ => 0,
    };
    base | guard
}

/// True if `mm` is a copy-on-write protection (`WRITECOPY` or `EXECUTE_WRITECOPY`).
pub const fn mm_is_cow(mm: u8) -> bool {
    matches!(
        mm & !MM_PROT_GUARD,
        MM_PROT_WRITECOPY | MM_PROT_EXECUTE_WRITECOPY
    )
}

/// True if `mm` has `PAGE_GUARD` set.
pub const fn mm_is_guard(mm: u8) -> bool {
    mm & MM_PROT_GUARD != 0
}

/// Promote a copy-on-write protection to its writable private equivalent.
pub const fn mm_break_cow(mm: u8) -> u8 {
    match mm & !MM_PROT_GUARD {
        MM_PROT_WRITECOPY => MM_PROT_READWRITE,
        MM_PROT_EXECUTE_WRITECOPY => MM_PROT_EXECUTE_READWRITE,
        other => other,
    }
}

/// Hardware user-page [`crate::pt::Prot`] for a non-guard, accessible 5-bit
/// protection code, plus whether the valid PTE should carry the copy-on-write
/// software bit (mapped read-only in hardware so the first write faults).
/// Returns `None` for `EMPTY`, `NOACCESS`, or `GUARD`.
pub const fn mm_to_user_hw(mm: u8) -> Option<(crate::pt::Prot, bool)> {
    use crate::pt::Prot;
    if mm == MM_PROT_EMPTY || mm & MM_PROT_GUARD != 0 {
        return None;
    }
    match mm {
        MM_PROT_READONLY => Some((Prot::USER_RO, false)),
        MM_PROT_EXECUTE | MM_PROT_EXECUTE_READ => Some((Prot::USER_RX, false)),
        MM_PROT_READWRITE => Some((Prot::USER_RW, false)),
        MM_PROT_WRITECOPY => Some((Prot::USER_RO, true)),
        MM_PROT_EXECUTE_READWRITE => Some((Prot::USER_RWX, false)),
        MM_PROT_EXECUTE_WRITECOPY => Some((Prot::USER_RX, true)),
        _ => None,
    }
}

/// Recover NK's 5-bit internal protection code from a valid user hardware PTE's
/// `(writable, executable, cow)` attributes.
pub const fn user_hw_to_mm(writable: bool, executable: bool, cow: bool) -> u8 {
    match (writable, executable, cow) {
        (false, false, false) => MM_PROT_READONLY,
        (false, false, true) => MM_PROT_WRITECOPY,
        (true, false, _) => MM_PROT_READWRITE,
        (false, true, false) => MM_PROT_EXECUTE_READ,
        (false, true, true) => MM_PROT_EXECUTE_WRITECOPY,
        (true, true, _) => MM_PROT_EXECUTE_READWRITE,
    }
}

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
