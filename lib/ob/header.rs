//! What an object's header says, in the form Windows stores it.

/// The first index a type has; Windows keeps 0 and 1 for itself.
pub const FIRST_TYPE_INDEX: u8 = 2;

/// The byte Windows 10 keeps in `OBJECT_HEADER.TypeIndex` for an object
/// of the type numbered `index`: the index combined with a cookie chosen
/// at boot and with the second byte of the header's own address, so the
/// byte alone does not name the type. The same operation turns the
/// stored byte back into the index.
pub const fn type_index(index: u8, cookie: u8, header: u64) -> u8 {
    index ^ cookie ^ (header >> 8) as u8
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_stored_byte_gives_the_index_back() {
        for index in [FIRST_TYPE_INDEX, 3, 7, 0x40, 0xFF] {
            for cookie in [0, 1, 0x5A, 0xFF] {
                for header in [0, 0x100, 0xFFFF_8000_1234_5670, u64::MAX] {
                    let stored = type_index(index, cookie, header);
                    assert_eq!(type_index(stored, cookie, header), index);
                }
            }
        }
    }

    #[test]
    fn the_stored_byte_depends_on_cookie_and_address() {
        let header = 0xFFFF_8000_0000_1200;
        assert_eq!(type_index(5, 0, 0), 5, "nothing to hide it with");
        assert_ne!(type_index(5, 0x21, header), type_index(5, 0x22, header));
        // Only the second byte of the address takes part.
        assert_ne!(
            type_index(5, 0x21, header),
            type_index(5, 0x21, header + 0x100)
        );
        assert_eq!(
            type_index(5, 0x21, header),
            type_index(5, 0x21, header + 0xF0)
        );
        assert_eq!(
            type_index(5, 0x21, header),
            type_index(5, 0x21, header + 0x1_0000)
        );
    }
}
