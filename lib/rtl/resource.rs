//! How a memory or port resource's length is written in a resource
//! descriptor: the rules of
//! [`RtlCmEncodeMemIoResource`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-rtlcmencodememioresource),
//! [`RtlCmDecodeMemIoResource`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-rtlcmdecodememioresource),
//! [`RtlIoEncodeMemIoResource`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-rtlioencodememioresource),
//! [`RtlIoDecodeMemIoResource`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-rtliodecodememioresource)
//! and
//! [`RtlFindClosestEncodableLength`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-rtlfindclosestencodablelength).
//!
//! A descriptor has 32 bits for a length. A memory range of 4 GB or
//! more is a *large* memory resource: its type says so, and one of
//! three flags says whether the 32 bits count units of 2^8, 2^16 or
//! 2^32 bytes.
//!
//! The rules here are read from the kernel NK follows (10.0.19041)
//! where Microsoft's pages stop: which statuses refuse what, that a
//! failed encoding has already cleared the descriptor's large-memory
//! flags, that decoding goes by the flags alone when the type is
//! neither port nor memory, and that an alignment that is not a whole
//! number of units is doubled until it is.

/// `CmResourceTypePort`.
pub const TYPE_PORT: u8 = 1;
/// `CmResourceTypeMemory`.
pub const TYPE_MEMORY: u8 = 3;
/// `CmResourceTypeMemoryLarge`.
pub const TYPE_MEMORY_LARGE: u8 = 7;

/// `CM_RESOURCE_MEMORY_LARGE_40`: the length counts units of 2^8 bytes.
pub const LARGE_40: u16 = 0x200;
/// `CM_RESOURCE_MEMORY_LARGE_48`: units of 2^16 bytes.
pub const LARGE_48: u16 = 0x400;
/// `CM_RESOURCE_MEMORY_LARGE_64`: units of 2^32 bytes.
pub const LARGE_64: u16 = 0x800;
/// `CM_RESOURCE_MEMORY_LARGE`: the three flags.
pub const LARGE: u16 = LARGE_40 | LARGE_48 | LARGE_64;

/// The three encodings: the flag, and the bits its unit shifts by.
const ENCODINGS: [(u16, u32); 3] = [(LARGE_40, 8), (LARGE_48, 16), (LARGE_64, 32)];

/// The largest length an encoding with units of `2^shift` bytes holds.
const fn limit(shift: u32) -> u64 {
    (u32::MAX as u64) << shift
}

/// How far a descriptor's 32-bit fields are shifted: not at all for a
/// port or a plain memory resource; otherwise by the first large-memory
/// flag set. `None` if there is none, which decodes as zero.
fn shift(resource_type: u8, flags: u16) -> Option<u32> {
    if matches!(resource_type, TYPE_PORT | TYPE_MEMORY) {
        return Some(0);
    }
    ENCODINGS
        .into_iter()
        .find(|&(flag, _)| flags & flag != 0)
        .map(|(_, shift)| shift)
}

/// `RtlCmDecodeMemIoResource`: the length in bytes that a descriptor of
/// this type and these flags, with `length` in its 32 bits, describes.
pub fn cm_decode(resource_type: u8, flags: u16, length: u32) -> u64 {
    shift(resource_type, flags).map_or(0, |shift| u64::from(length) << shift)
}

/// `RtlIoDecodeMemIoResource`: the length and the alignment in bytes of
/// a requirement descriptor.
pub fn io_decode(resource_type: u8, flags: u16, length: u32, alignment: u32) -> (u64, u64) {
    shift(resource_type, flags).map_or((0, 0), |shift| {
        (u64::from(length) << shift, u64::from(alignment) << shift)
    })
}

/// Why an encoding fails.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EncodeError {
    /// `STATUS_INVALID_PARAMETER`: the type is not one of the three, or
    /// a port's range does not fit 32 bits. The descriptor is untouched.
    InvalidParameter,
    /// `STATUS_UNSUCCESSFUL`: no encoding holds the length. The
    /// descriptor's addresses have been stored and its flags are these,
    /// the large-memory ones cleared.
    Unsuccessful { flags: u16 },
}

/// What an encoding stores in a descriptor, beside its addresses.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Encoded {
    pub resource_type: u8,
    pub flags: u16,
    pub length: u32,
    /// Of a requirement descriptor; zero for a resource descriptor.
    pub alignment: u32,
}

/// `RtlIoEncodeMemIoResource`: the type, flags, length and alignment to
/// store for a range of `length` bytes aligned to `alignment`, in a
/// descriptor whose flags are `flags`. `RtlCmEncodeMemIoResource` is
/// this with an alignment of zero.
pub fn encode(
    resource_type: u8,
    flags: u16,
    length: u64,
    alignment: u64,
) -> Result<Encoded, EncodeError> {
    let small = length <= limit(0) && alignment <= limit(0);
    match resource_type {
        TYPE_PORT if small => {
            return Ok(Encoded {
                resource_type: TYPE_PORT,
                flags,
                length: length as u32,
                alignment: alignment as u32,
            });
        }
        TYPE_MEMORY | TYPE_MEMORY_LARGE => {}
        _ => return Err(EncodeError::InvalidParameter),
    }
    let flags = flags & !LARGE;
    if small {
        return Ok(Encoded {
            resource_type: TYPE_MEMORY,
            flags,
            length: length as u32,
            alignment: alignment as u32,
        });
    }
    let failed = Err(EncodeError::Unsuccessful { flags });
    // The smallest unit that reaches the length.
    let Some((flag, shift)) = ENCODINGS
        .into_iter()
        .find(|&(_, shift)| length <= limit(shift))
    else {
        return failed;
    };
    let unit = 1u64 << shift;
    if length % unit != 0 || alignment > limit(shift) {
        return failed;
    }
    // An alignment between units is doubled until it is on one: a
    // stricter alignment satisfies the one asked for.
    let mut alignment = alignment;
    while alignment % unit != 0 {
        let Some(doubled) = alignment.checked_mul(2) else {
            return failed;
        };
        alignment = doubled;
    }
    let Ok(alignment) = u32::try_from(alignment >> shift) else {
        return failed;
    };
    Ok(Encoded {
        resource_type: TYPE_MEMORY_LARGE,
        flags: flags | flag,
        length: (length >> shift) as u32,
        alignment,
    })
}

/// `RtlFindClosestEncodableLength`: the smallest length at or above
/// `length` that a descriptor can hold, and whether there is one (if
/// not, the status is `STATUS_UNSUCCESSFUL` and zero is stored).
pub fn closest_encodable(length: u64) -> (u64, bool) {
    if length <= limit(0) {
        return (length, true);
    }
    let mut length = length;
    for (_, shift) in ENCODINGS {
        if length > limit(shift) {
            continue;
        }
        let unit = 1u64 << shift;
        if length % unit == 0 {
            return (length, true);
        }
        // Rounded up to the unit; if that is past what this unit
        // reaches, the next unit takes it from there.
        length = (length & !(unit - 1)) + unit;
        if length <= limit(shift) || shift == 32 {
            return (length, true);
        }
    }
    (0, false)
}

#[cfg(test)]
mod tests {
    use super::*;

    const GB: u64 = 1 << 30;

    #[test]
    fn a_plain_descriptor_decodes_as_its_length() {
        assert_eq!(cm_decode(TYPE_PORT, 0, 0x100), 0x100);
        assert_eq!(cm_decode(TYPE_MEMORY, 0, u32::MAX), u64::from(u32::MAX));
        // The large flags mean nothing on a port or plain memory.
        assert_eq!(cm_decode(TYPE_MEMORY, LARGE_40, 0x100), 0x100);
        assert_eq!(cm_decode(TYPE_PORT, LARGE_64, 0x100), 0x100);
        assert_eq!(io_decode(TYPE_MEMORY, LARGE, 0x1000, 0x10), (0x1000, 0x10));
    }

    #[test]
    fn a_large_descriptor_decodes_by_its_flag() {
        assert_eq!(cm_decode(TYPE_MEMORY_LARGE, LARGE_40, 0x100_0000), 4 * GB);
        assert_eq!(cm_decode(TYPE_MEMORY_LARGE, LARGE_48, 0x1_0000), 4 * GB);
        assert_eq!(cm_decode(TYPE_MEMORY_LARGE, LARGE_64, 3), 12 * GB);
        assert_eq!(
            cm_decode(TYPE_MEMORY_LARGE, LARGE_64, u32::MAX),
            0xFFFF_FFFF_0000_0000
        );
        // The first flag set decides; none set is nothing.
        assert_eq!(cm_decode(TYPE_MEMORY_LARGE, LARGE_40 | LARGE_64, 1), 0x100);
        assert_eq!(
            cm_decode(TYPE_MEMORY_LARGE, LARGE_48 | LARGE_64, 1),
            0x1_0000
        );
        assert_eq!(cm_decode(TYPE_MEMORY_LARGE, 0, 5), 0);
        assert_eq!(cm_decode(TYPE_MEMORY_LARGE, 0x100, 5), 0);
        // Any other type goes by the flags too.
        assert_eq!(cm_decode(2, LARGE_40, 1), 0x100);
        assert_eq!(cm_decode(0, 0, 1), 0);
        assert_eq!(
            io_decode(TYPE_MEMORY_LARGE, LARGE_48, 0x1_0000, 2),
            (4 * GB, 0x2_0000)
        );
        assert_eq!(io_decode(TYPE_MEMORY_LARGE, 0, 7, 7), (0, 0));
    }

    fn ok(
        resource_type: u8,
        flags: u16,
        length: u32,
        alignment: u32,
    ) -> Result<Encoded, EncodeError> {
        Ok(Encoded {
            resource_type,
            flags,
            length,
            alignment,
        })
    }

    #[test]
    fn a_length_under_4_gb_is_stored_as_it_is() {
        assert_eq!(
            encode(TYPE_PORT, 0x11, 0x100, 1),
            ok(TYPE_PORT, 0x11, 0x100, 1)
        );
        assert_eq!(
            encode(TYPE_MEMORY, 0, 0x1000, 0x1000),
            ok(TYPE_MEMORY, 0, 0x1000, 0x1000)
        );
        // A large type with a small length becomes plain memory, and
        // stale large flags go.
        assert_eq!(
            encode(TYPE_MEMORY_LARGE, LARGE_48 | 1, 0xFFFF_FFFF, 0),
            ok(TYPE_MEMORY, 1, u32::MAX, 0)
        );
        // A port keeps its flags as they are.
        assert_eq!(
            encode(TYPE_PORT, LARGE_40, 8, 0),
            ok(TYPE_PORT, LARGE_40, 8, 0)
        );
        assert_eq!(encode(TYPE_MEMORY, 0, 0, 0), ok(TYPE_MEMORY, 0, 0, 0));
    }

    #[test]
    fn a_large_length_takes_the_smallest_unit_that_reaches_it() {
        assert_eq!(
            encode(TYPE_MEMORY, 0x4, 4 * GB, 0),
            ok(TYPE_MEMORY_LARGE, LARGE_40 | 4, 0x100_0000, 0)
        );
        assert_eq!(
            encode(TYPE_MEMORY_LARGE, LARGE_64, 0xFF_FFFF_FF00, 0x100),
            ok(TYPE_MEMORY_LARGE, LARGE_40, u32::MAX, 1)
        );
        assert_eq!(
            encode(TYPE_MEMORY, 0, 0x100_0000_0000, 0x1_0000),
            ok(TYPE_MEMORY_LARGE, LARGE_48, 0x100_0000, 1)
        );
        assert_eq!(
            encode(TYPE_MEMORY, 0, 0xFFFF_FFFF_0000, 0),
            ok(TYPE_MEMORY_LARGE, LARGE_48, u32::MAX, 0)
        );
        assert_eq!(
            encode(TYPE_MEMORY, 0, 0x1_0000_0000_0000, 1 << 32),
            ok(TYPE_MEMORY_LARGE, LARGE_64, 0x1_0000, 1)
        );
        assert_eq!(
            encode(TYPE_MEMORY, 0, 0xFFFF_FFFF_0000_0000, 0),
            ok(TYPE_MEMORY_LARGE, LARGE_64, u32::MAX, 0)
        );
        // A small length with a large alignment is a large resource.
        assert_eq!(
            encode(TYPE_MEMORY, 0, 0x1000, 4 * GB),
            ok(TYPE_MEMORY_LARGE, LARGE_40, 0x10, 0x100_0000)
        );
    }

    #[test]
    fn an_alignment_between_units_is_doubled_onto_one() {
        assert_eq!(
            encode(TYPE_MEMORY, 0, 4 * GB, 0x80),
            ok(TYPE_MEMORY_LARGE, LARGE_40, 0x100_0000, 1)
        );
        assert_eq!(
            encode(TYPE_MEMORY, 0, 4 * GB, 1),
            ok(TYPE_MEMORY_LARGE, LARGE_40, 0x100_0000, 1)
        );
        assert_eq!(
            encode(TYPE_MEMORY, 0, 4 * GB, 0x300),
            ok(TYPE_MEMORY_LARGE, LARGE_40, 0x100_0000, 3)
        );
        assert_eq!(
            encode(TYPE_MEMORY, 0, 4 * GB, 0x180),
            ok(TYPE_MEMORY_LARGE, LARGE_40, 0x100_0000, 3)
        );
        assert_eq!(
            encode(TYPE_MEMORY, 0, 0x100_0000_0000, 0x1000),
            ok(TYPE_MEMORY_LARGE, LARGE_48, 0x100_0000, 1)
        );
        // Doubled past what the unit's 32 bits hold.
        assert_eq!(
            encode(TYPE_MEMORY, 7, 4 * GB, 0xFF_FFFF_FE80),
            Err(EncodeError::Unsuccessful { flags: 7 })
        );
    }

    #[test]
    fn what_no_encoding_holds_is_refused() {
        let unsuccessful = |flags| Err(EncodeError::Unsuccessful { flags });
        // Not a whole number of the unit its size calls for.
        assert_eq!(encode(TYPE_MEMORY, 0, 4 * GB + 1, 0), unsuccessful(0));
        assert_eq!(encode(TYPE_MEMORY, 0, 4 * GB + 0x80, 0), unsuccessful(0));
        assert_eq!(
            encode(TYPE_MEMORY, LARGE | 3, 0x100_0000_0100, 0),
            unsuccessful(3)
        );
        assert_eq!(
            encode(TYPE_MEMORY, 0, 0x1_0000_0001_0000, 0),
            unsuccessful(0)
        );
        // Past the largest unit's reach.
        assert_eq!(
            encode(TYPE_MEMORY, 0, 0xFFFF_FFFF_0000_0001, 0),
            unsuccessful(0)
        );
        assert_eq!(encode(TYPE_MEMORY, 0, u64::MAX, 0), unsuccessful(0));
        // An alignment past the unit's reach.
        assert_eq!(
            encode(TYPE_MEMORY, 0, 4 * GB, 0x100_0000_0000),
            unsuccessful(0)
        );
        // A port has no large form; other types have none at all.
        let invalid = Err(EncodeError::InvalidParameter);
        assert_eq!(encode(TYPE_PORT, 0, 4 * GB, 0), invalid);
        assert_eq!(encode(TYPE_PORT, 0, 8, 4 * GB), invalid);
        for resource_type in [0, 2, 4, 5, 6, 8, 0x81, 0xFF] {
            assert_eq!(encode(resource_type, 0, 8, 0), invalid, "{resource_type}");
        }
    }

    #[test]
    fn what_is_encoded_decodes_to_the_same_length() {
        for length in [
            0,
            1,
            0xFFFF_FFFF,
            4 * GB,
            4 * GB + 0x100,
            0xFF_FFFF_FF00,
            0x100_0000_0000,
            0xFFFF_FFFF_0000,
            0x1_0000_0000_0000,
            0xFFFF_FFFF_0000_0000,
        ] {
            let encoded = encode(TYPE_MEMORY, 0, length, 0).unwrap();
            assert_eq!(
                cm_decode(encoded.resource_type, encoded.flags, encoded.length),
                length,
                "{length:#x}"
            );
        }
    }

    #[test]
    fn the_closest_encodable_length_rounds_up_to_a_unit() {
        for (length, expected) in [
            (0, 0),
            (1, 1),
            (0xFFFF_FFFF, 0xFFFF_FFFF),
            (4 * GB, 4 * GB),
            (4 * GB + 1, 4 * GB + 0x100),
            (4 * GB + 0xFF, 4 * GB + 0x100),
            (4 * GB + 0x100, 4 * GB + 0x100),
            (0xFF_FFFF_FF00, 0xFF_FFFF_FF00),
            // Rounded past the first unit's reach, the second takes it.
            (0xFF_FFFF_FE01, 0xFF_FFFF_FF00),
            (0xFF_FFFF_FF01, 0x100_0000_0000),
            (0x100_0000_0001, 0x100_0001_0000),
            (0xFFFF_FFFF_0000, 0xFFFF_FFFF_0000),
            (0xFFFF_FFFF_0001, 0x1_0000_0000_0000),
            (0x1_0000_0000_0001, 0x1_0001_0000_0000),
            (0xFFFF_FFFF_0000_0000, 0xFFFF_FFFF_0000_0000),
        ] {
            assert_eq!(closest_encodable(length), (expected, true), "{length:#x}");
            // What it answers encodes, and nothing smaller would do.
            let encoded = encode(TYPE_MEMORY, 0, expected, 0).unwrap();
            assert_eq!(
                cm_decode(encoded.resource_type, encoded.flags, encoded.length),
                expected
            );
        }
        assert_eq!(closest_encodable(0xFFFF_FFFF_0000_0001), (0, false));
        assert_eq!(closest_encodable(u64::MAX), (0, false));
    }
}
