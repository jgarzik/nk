//! Provider traits: the blob a provider hands `EtwSetInformation` to
//! name itself
//! ([provider traits](https://learn.microsoft.com/en-us/windows/win32/etw/provider-traits)).
//!
//! The blob is its own size in two bytes, the provider's name with a
//! terminator, then any number of chunks, each beginning with its own
//! size in two bytes.

/// The lengths `EtwSetInformation` takes a traits blob at; any other is
/// refused before the blob is looked at.
pub const SHORTEST: usize = 3;
pub const LONGEST: usize = 0x7FFF;

/// Whether `blob` is well formed, by the checks of the pinned kernel:
/// its first two bytes are its length, its name ends inside it, and the
/// chunks after the name end exactly where it does.
///
/// One rule is NK's own: a chunk whose size is less than the two bytes
/// that state it is refused, since a walk can make no progress there.
pub fn well_formed(blob: &[u8]) -> bool {
    let length = blob.len();
    if length < SHORTEST || usize::from(u16::from_le_bytes([blob[0], blob[1]])) != length {
        return false;
    }
    let Some(name) = blob[2..].iter().position(|&b| b == 0) else {
        return false;
    };
    let mut at = 2 + name + 1;
    while at < length {
        if at + 2 > length {
            return false;
        }
        let size = usize::from(u16::from_le_bytes([blob[at], blob[at + 1]]));
        if size < 2 {
            return false;
        }
        at += size;
    }
    at == length
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_size_and_a_terminated_name_are_traits() {
        assert!(well_formed(&[9, 0, b'N', b'k', b'c', b'E', b't', b'w', 0]));
        // The shortest there are: an empty name.
        assert!(well_formed(&[3, 0, 0]));
    }

    #[test]
    fn the_size_must_be_the_length() {
        assert!(!well_formed(&[8, 0, b'N', b'k', b'c', b'E', b't', b'w', 0]));
        assert!(!well_formed(&[
            10, 0, b'N', b'k', b'c', b'E', b't', b'w', 0
        ]));
        assert!(!well_formed(&[9, 1, b'N', b'k', b'c', b'E', b't', b'w', 0]));
    }

    #[test]
    fn blobs_too_short_to_hold_a_name_are_refused() {
        assert!(!well_formed(&[]));
        assert!(!well_formed(&[2, 0]));
    }

    #[test]
    fn the_name_must_end_inside_the_blob() {
        assert!(!well_formed(&[5, 0, b'a', b'b', b'c']));
    }

    #[test]
    fn chunks_after_the_name_must_end_where_the_blob_does() {
        // One chunk of three bytes: its size and a type.
        assert!(well_formed(&[7, 0, b'a', 0, 3, 0, 1]));
        // Two chunks.
        assert!(well_formed(&[11, 0, b'a', 0, 3, 0, 1, 4, 0, 2, 9]));
        // A chunk that runs past the end.
        assert!(!well_formed(&[7, 0, b'a', 0, 4, 0, 1]));
        // One byte left over: no room for a chunk's size.
        assert!(!well_formed(&[5, 0, b'a', 0, 7]));
        // A chunk that says it is shorter than its own size field.
        assert!(!well_formed(&[6, 0, b'a', 0, 0, 0]));
        assert!(!well_formed(&[6, 0, b'a', 0, 1, 0]));
    }
}
