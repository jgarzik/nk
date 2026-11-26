//! The length rules of the routines that fill a counted string:
//! [`RtlInitString`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-rtlinitstring),
//! [`RtlAppendUnicodeStringToString`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-rtlappendunicodestringtostring),
//! [`RtlCopyUnicodeString`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-rtlcopyunicodestring)
//! and
//! [`RtlDuplicateUnicodeString`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-rtlduplicateunicodestring).
//! Lengths are in bytes. The kernel moves the characters.
//!
//! Where Microsoft's pages stop, the rules are read from the kernel NK
//! follows (10.0.19041): what `RtlInitString` makes of a string too
//! long to count, when a terminator is written after an append or a
//! copy (when two bytes are free for it), and which flags and strings
//! `RtlDuplicateUnicodeString` refuses.

/// How far `RtlInitString` need scan for a terminator: a string this
/// long or longer gets the same lengths.
pub const INIT_STRING_SCAN: usize = 0xFFFF;

/// `(Length, MaximumLength)` that `RtlInitString` and
/// `RtlInitAnsiString` store for a source of `chars` bytes before its
/// NUL. A string of 0xFFFF bytes or more is given as 0xFFFE.
pub fn init_string_lengths(chars: usize) -> (u16, u16) {
    let length = if chars >= INIT_STRING_SCAN {
        0xFFFE
    } else {
        chars as u16
    };
    (length, length + 1)
}

/// `RtlAppendUnicodeStringToString`: the destination's new `Length`,
/// and whether a terminator is written after the text, when `source`
/// bytes are appended to `length` bytes in a buffer of `maximum`.
/// `None`, when they do not fit, is `STATUS_BUFFER_TOO_SMALL`. An empty
/// source changes nothing: not even a terminator is written.
pub fn append(length: u16, maximum: u16, source: u16) -> Option<(u16, bool)> {
    if source == 0 {
        return Some((length, false));
    }
    let total = u32::from(length) + u32::from(source);
    (total <= u32::from(maximum)).then(|| (total as u16, total + 1 < u32::from(maximum)))
}

/// `RtlCopyUnicodeString`: the `Length` stored, which is how many bytes
/// are copied, and whether a terminator is written after them, for a
/// source of `source` bytes and a buffer of `maximum`.
pub fn copy(source: u16, maximum: u16) -> (u16, bool) {
    let length = source.min(maximum);
    (length, u32::from(length) + 2 <= u32::from(maximum))
}

/// `RTL_DUPLICATE_UNICODE_STRING_NULL_TERMINATE`.
pub const DUPLICATE_NULL_TERMINATE: u32 = 1;
/// `RTL_DUPLICATE_UNICODE_STRING_ALLOCATE_NULL_STRING`.
pub const DUPLICATE_ALLOCATE_NULL_STRING: u32 = 2;

/// Why `RtlDuplicateUnicodeString` refuses.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DuplicateError {
    /// `STATUS_INVALID_PARAMETER`.
    InvalidParameter,
    /// `STATUS_NAME_TOO_LONG`.
    NameTooLong,
}

/// A counted string's header, as `RtlDuplicateUnicodeString` judges it.
#[derive(Debug, Clone, Copy)]
pub struct Header {
    pub length: u16,
    pub maximum: u16,
    pub buffer_is_null: bool,
}

/// `RtlDuplicateUnicodeString`: the `(Length, MaximumLength)` of the
/// copy of `source` (`None` for a null pointer, which duplicates as an
/// empty string). A `MaximumLength` of zero means no buffer is
/// allocated and the copy's buffer is null; otherwise that many bytes
/// are allocated, and a terminator follows the text if the flags ask
/// for one.
pub fn duplicate(flags: u32, source: Option<Header>) -> Result<(u16, u16), DuplicateError> {
    let terminate = flags & DUPLICATE_NULL_TERMINATE != 0;
    let allocate_empty = flags & DUPLICATE_ALLOCATE_NULL_STRING != 0;
    // An empty string is only worth allocating for its terminator.
    if flags & !(DUPLICATE_NULL_TERMINATE | DUPLICATE_ALLOCATE_NULL_STRING) != 0
        || (allocate_empty && !terminate)
    {
        return Err(DuplicateError::InvalidParameter);
    }
    let length = match source {
        None => 0,
        Some(header) => {
            let malformed = header.length % 2 != 0
                || header.maximum % 2 != 0
                || header.length > header.maximum
                || (header.buffer_is_null && (header.length != 0 || header.maximum != 0));
            if malformed {
                return Err(DuplicateError::InvalidParameter);
            }
            header.length
        }
    };
    if terminate && length == 0xFFFE {
        return Err(DuplicateError::NameTooLong);
    }
    if length == 0 && !allocate_empty {
        return Ok((0, 0));
    }
    Ok((length, if terminate { length + 2 } else { length }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn init_string_counts_up_to_the_field() {
        assert_eq!(init_string_lengths(0), (0, 1));
        assert_eq!(init_string_lengths(5), (5, 6));
        assert_eq!(init_string_lengths(0xFFFE), (0xFFFE, 0xFFFF));
        assert_eq!(init_string_lengths(0xFFFF), (0xFFFE, 0xFFFF));
        assert_eq!(init_string_lengths(0x1_0000), (0xFFFE, 0xFFFF));
        assert_eq!(init_string_lengths(usize::MAX), (0xFFFE, 0xFFFF));
    }

    #[test]
    fn an_append_fits_or_fails_whole() {
        assert_eq!(append(4, 20, 6), Some((10, true)));
        // A terminator needs two free bytes.
        assert_eq!(append(4, 12, 6), Some((10, true)));
        assert_eq!(append(4, 11, 6), Some((10, false)));
        assert_eq!(append(4, 10, 6), Some((10, false)));
        assert_eq!(append(4, 9, 6), None);
        assert_eq!(append(0, 0, 2), None);
        assert_eq!(append(0xFFFE, 0xFFFE, 2), None);
        assert_eq!(append(0x8000, 0xFFFF, 0x7FFE), Some((0xFFFE, false)));
        // Nothing to append: nothing is checked or written.
        assert_eq!(append(4, 20, 0), Some((4, false)));
        assert_eq!(append(30, 20, 0), Some((30, false)));
    }

    #[test]
    fn a_copy_takes_what_fits() {
        assert_eq!(copy(6, 20), (6, true));
        assert_eq!(copy(6, 8), (6, true));
        assert_eq!(copy(6, 7), (6, false));
        assert_eq!(copy(6, 6), (6, false));
        assert_eq!(copy(6, 4), (4, false));
        assert_eq!(copy(6, 0), (0, false));
        assert_eq!(copy(0, 0), (0, false));
        assert_eq!(copy(0, 2), (0, true));
        assert_eq!(copy(0xFFFE, 0xFFFF), (0xFFFE, false));
    }

    fn header(length: u16, maximum: u16) -> Option<Header> {
        Some(Header {
            length,
            maximum,
            buffer_is_null: false,
        })
    }

    #[test]
    fn a_duplicate_is_as_long_as_its_source() {
        assert_eq!(duplicate(0, header(6, 10)), Ok((6, 6)));
        assert_eq!(duplicate(1, header(6, 10)), Ok((6, 8)));
        assert_eq!(duplicate(3, header(6, 10)), Ok((6, 8)));
        assert_eq!(duplicate(0, header(0xFFFE, 0xFFFE)), Ok((0xFFFE, 0xFFFE)));
        assert_eq!(duplicate(1, header(0xFFFC, 0xFFFE)), Ok((0xFFFC, 0xFFFE)));
        assert_eq!(
            duplicate(1, header(0xFFFE, 0xFFFE)),
            Err(DuplicateError::NameTooLong)
        );
    }

    #[test]
    fn an_empty_duplicate_has_a_buffer_only_if_asked() {
        let empty = Some(Header {
            length: 0,
            maximum: 0,
            buffer_is_null: true,
        });
        for source in [None, empty, header(0, 10)] {
            assert_eq!(duplicate(0, source), Ok((0, 0)));
            assert_eq!(duplicate(1, source), Ok((0, 0)));
            assert_eq!(duplicate(3, source), Ok((0, 2)));
        }
    }

    #[test]
    fn bad_flags_and_malformed_strings_are_refused() {
        let invalid = Err(DuplicateError::InvalidParameter);
        for flags in [2, 4, 5, 7, 8, 0x8000_0000, u32::MAX] {
            assert_eq!(duplicate(flags, header(6, 10)), invalid, "{flags:#x}");
        }
        for (length, maximum) in [(5, 10), (6, 9), (12, 10)] {
            assert_eq!(duplicate(0, header(length, maximum)), invalid);
        }
        for (length, maximum) in [(2, 2), (0, 2)] {
            let source = Some(Header {
                length,
                maximum,
                buffer_is_null: true,
            });
            assert_eq!(duplicate(0, source), invalid);
        }
        // The flags are judged before the string.
        assert_eq!(duplicate(2, header(5, 10)), invalid);
    }
}
