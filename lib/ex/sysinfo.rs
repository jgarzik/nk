//! The length rules of `ZwQuerySystemInformation` and
//! `RtlQueryModuleInformation`, and the path a loaded module is
//! reported under.
//!
//! The rules are those of the pinned kernel's code, class by class:
//! what length a class accepts, what it reports as the length needed,
//! and how much of a list that does not fit is still written.

/// Bytes of one module in the list of class 11
/// (`RTL_PROCESS_MODULE_INFORMATION`), and of the count before them.
pub const MODULE_ENTRY: u32 = 0x128;
pub const MODULES_HEADER: u32 = 8;
/// Bytes of a module's path, its terminator included.
pub const PATH_LENGTH: usize = 256;

/// How a class with a structure of fixed size treats the caller's
/// length.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Fixed {
    /// The length must be the structure's size exactly.
    Exactly(u32),
    /// The length must be at least the structure's size.
    AtLeast(u32),
}

/// What a query of such a class does.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FixedAnswer {
    /// Whether the structure is written; else the status is
    /// `STATUS_INFO_LENGTH_MISMATCH`.
    pub fits: bool,
    /// What is reported as the length, written or not.
    pub length: u32,
}

impl Fixed {
    pub fn answer(self, given: u32) -> FixedAnswer {
        let (fits, length) = match self {
            Fixed::Exactly(size) => (given == size, size),
            Fixed::AtLeast(size) => (given >= size, size),
        };
        FixedAnswer { fits, length }
    }
}

/// What a query for the list of `count` modules does with a buffer of
/// `given` bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ModuleList {
    /// How many entries are written: those that fit whole, from the
    /// first.
    pub entries: u32,
    /// Whether the count, which is always of all the modules, is
    /// written: the buffer holds at least the header.
    pub count: bool,
    /// The length reported: what the whole list needs.
    pub needed: u32,
    /// Whether everything fit; else `STATUS_INFO_LENGTH_MISMATCH`.
    pub complete: bool,
}

pub fn module_list(count: u32, given: u32) -> ModuleList {
    let needed = MODULES_HEADER + MODULE_ENTRY * count;
    let entries = (given.saturating_sub(MODULES_HEADER) / MODULE_ENTRY).min(count);
    ModuleList {
        entries,
        count: given >= MODULES_HEADER,
        needed,
        complete: given >= MODULES_HEADER && entries == count,
    }
}

/// The two sizes `RtlQueryModuleInformation` reports a module in:
/// its base alone, or base, size and path.
pub const AUX_BASIC: u32 = 8;
pub const AUX_EXTENDED: u32 = 0x110;

/// What `RtlQueryModuleInformation` answers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuxAnswer {
    /// A size per module that is neither of the two:
    /// `STATUS_INVALID_PARAMETER_2`. The length is left alone.
    BadSize,
    /// A buffer that is not aligned for a pointer:
    /// `STATUS_INVALID_PARAMETER_3`. The length is left alone.
    Misaligned,
    /// No buffer: success, and the length is set to what is needed.
    Needed(u32),
    /// A buffer too small: `STATUS_BUFFER_TOO_SMALL`, and the length is
    /// set to what is needed.
    TooSmall(u32),
    /// Every module is written; the length is set to the bytes written.
    Written(u32),
}

/// Decide a call for `count` modules: `buffer` is the buffer's address,
/// zero for none, and `given` the length the caller states.
pub fn aux_modules(count: u32, size_per_module: u32, buffer: usize, given: u32) -> AuxAnswer {
    if size_per_module != AUX_BASIC && size_per_module != AUX_EXTENDED {
        return AuxAnswer::BadSize;
    }
    if buffer % 8 != 0 {
        return AuxAnswer::Misaligned;
    }
    let needed = count * size_per_module;
    if buffer == 0 {
        AuxAnswer::Needed(needed)
    } else if given < needed {
        AuxAnswer::TooSmall(needed)
    } else {
        AuxAnswer::Written(needed)
    }
}

/// Where a loaded image is said to have come from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Origin {
    /// The kernel and what goes by its side: `\SystemRoot\system32`.
    System,
    /// A driver: `\SystemRoot\System32\drivers`, which NK's boot files
    /// stand for.
    Driver,
}

/// The path a module is reported under, as bytes with a terminator, and
/// where the file name begins in it. A path too long for the field is
/// cut to fit, as Windows cuts it.
pub fn module_path(origin: Origin, file_name: &[u8]) -> ([u8; PATH_LENGTH], u16) {
    let directory: &[u8] = match origin {
        Origin::System => b"\\SystemRoot\\system32\\",
        Origin::Driver => b"\\SystemRoot\\System32\\drivers\\",
    };
    let mut path = [0u8; PATH_LENGTH];
    let bytes = directory.iter().chain(file_name).take(PATH_LENGTH - 1);
    for (slot, &byte) in path.iter_mut().zip(bytes) {
        *slot = byte;
    }
    (path, file_name_offset(&path))
}

/// Where the file name begins in a terminated path: after its last
/// backslash, or at its start if it has none.
pub fn file_name_offset(path: &[u8]) -> u16 {
    let length = path.iter().position(|&b| b == 0).unwrap_or(path.len());
    path[..length]
        .iter()
        .rposition(|&b| b == b'\\')
        .map_or(0, |at| at as u16 + 1)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_class_of_exact_size_takes_that_length_only() {
        let class = Fixed::Exactly(0x40);
        assert_eq!(
            class.answer(0x40),
            FixedAnswer {
                fits: true,
                length: 0x40
            }
        );
        for given in [0, 8, 0x3F, 0x41, 0x1000] {
            let answer = class.answer(given);
            assert!(!answer.fits, "{given:#x}");
            // The length needed is reported all the same.
            assert_eq!(answer.length, 0x40);
        }
    }

    #[test]
    fn a_class_of_minimum_size_takes_larger_buffers() {
        let class = Fixed::AtLeast(2);
        assert!(!class.answer(0).fits);
        assert!(!class.answer(1).fits);
        for given in [2, 3, 0x100] {
            assert_eq!(
                class.answer(given),
                FixedAnswer {
                    fits: true,
                    length: 2
                }
            );
        }
    }

    #[test]
    fn no_buffer_reports_what_the_module_list_needs() {
        let list = module_list(3, 0);
        assert_eq!(
            list,
            ModuleList {
                entries: 0,
                count: false,
                needed: 8 + 3 * 0x128,
                complete: false
            }
        );
    }

    #[test]
    fn a_short_buffer_gets_the_whole_count_and_the_entries_that_fit() {
        // The header alone: the count, no entries.
        let list = module_list(3, 8);
        assert_eq!((list.entries, list.count, list.complete), (0, true, false));
        // One byte short of the second entry.
        let list = module_list(3, 8 + 2 * 0x128 - 1);
        assert_eq!((list.entries, list.count, list.complete), (1, true, false));
        // Less than the header.
        let list = module_list(3, 7);
        assert_eq!((list.entries, list.count, list.complete), (0, false, false));
        assert_eq!(list.needed, 8 + 3 * 0x128);
    }

    #[test]
    fn a_buffer_that_holds_the_list_is_complete() {
        for given in [8 + 3 * 0x128, 8 + 3 * 0x128 + 1, 0x10000] {
            let list = module_list(3, given);
            assert_eq!((list.entries, list.count, list.complete), (3, true, true));
            assert_eq!(list.needed, 8 + 3 * 0x128);
        }
        // No modules: the header is the list.
        assert!(module_list(0, 8).complete);
        assert!(!module_list(0, 4).complete);
    }

    #[test]
    fn module_information_comes_in_two_sizes_only() {
        for size in [0, 4, 12, 0x10, 0x108, 0x128] {
            assert_eq!(aux_modules(3, size, 0, 0), AuxAnswer::BadSize, "{size:#x}");
        }
        // The size is looked at before the buffer.
        assert_eq!(aux_modules(3, 12, 0x1001, 0), AuxAnswer::BadSize);
        assert_eq!(aux_modules(3, 8, 0x1001, 64), AuxAnswer::Misaligned);
        assert_eq!(aux_modules(3, 0x110, 0x1004, 0x1000), AuxAnswer::Misaligned);
    }

    #[test]
    fn module_information_reports_the_length_it_needs_or_wrote() {
        assert_eq!(aux_modules(3, 0x110, 0, 0), AuxAnswer::Needed(0x330));
        // With no buffer the stated length does not matter.
        assert_eq!(aux_modules(3, 0x110, 0, 0x10000), AuxAnswer::Needed(0x330));
        assert_eq!(
            aux_modules(3, 0x110, 0x1000, 0x110),
            AuxAnswer::TooSmall(0x330)
        );
        assert_eq!(
            aux_modules(3, 0x110, 0x1000, 0x32F),
            AuxAnswer::TooSmall(0x330)
        );
        assert_eq!(
            aux_modules(3, 0x110, 0x1000, 0x330),
            AuxAnswer::Written(0x330)
        );
        assert_eq!(
            aux_modules(3, 0x110, 0x1000, 0x10000),
            AuxAnswer::Written(0x330)
        );
        assert_eq!(aux_modules(3, 8, 0x1000, 24), AuxAnswer::Written(24));
    }

    fn text(path: &[u8; PATH_LENGTH]) -> &str {
        let length = path.iter().position(|&b| b == 0).unwrap();
        core::str::from_utf8(&path[..length]).unwrap()
    }

    #[test]
    fn the_kernel_and_drivers_are_reported_where_windows_keeps_them() {
        let (path, at) = module_path(Origin::System, b"ntoskrnl.exe");
        assert_eq!(text(&path), "\\SystemRoot\\system32\\ntoskrnl.exe");
        assert_eq!(&text(&path)[usize::from(at)..], "ntoskrnl.exe");
        let (path, at) = module_path(Origin::Driver, b"sioctl.sys");
        assert_eq!(text(&path), "\\SystemRoot\\System32\\drivers\\sioctl.sys");
        assert_eq!(&text(&path)[usize::from(at)..], "sioctl.sys");
    }

    #[test]
    fn a_path_too_long_is_cut_and_still_ends() {
        let name = [b'n'; 300];
        let (path, at) = module_path(Origin::Driver, &name);
        assert_eq!(path[PATH_LENGTH - 1], 0);
        assert_eq!(text(&path).len(), PATH_LENGTH - 1);
        assert_eq!(usize::from(at), "\\SystemRoot\\System32\\drivers\\".len());
    }

    #[test]
    fn a_path_without_a_backslash_is_all_file_name() {
        assert_eq!(file_name_offset(b"plain.sys\0"), 0);
        assert_eq!(file_name_offset(b"a\\b\\c.sys\0"), 4);
        // What follows the terminator is not looked at.
        assert_eq!(file_name_offset(b"a.sys\0\\junk"), 0);
        assert_eq!(file_name_offset(b""), 0);
    }
}
