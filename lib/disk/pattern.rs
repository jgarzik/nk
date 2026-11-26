//! The data disk's content. Seen as 64-bit little-endian words, word
//! `k` of the disk (the 8 bytes at byte offset `8 * k`) holds
//! `seed ^ k`: no two sectors are alike, and a transfer that lands in
//! the wrong place, even inside a sector, shows.

/// Bytes in a sector.
pub const SECTOR: usize = 512;
/// Words in a sector.
const WORDS: u64 = (SECTOR / 8) as u64;

/// The seed of every sector before the boot: "NKOR" in the high half.
pub const ORIGINAL: u64 = 0x4E4B_4F52_0000_0000;
/// The seed a kernel test writes with: "NKWR".
pub const WRITTEN: u64 = 0x4E4B_5752_0000_0000;
/// The sectors a kernel test may write, `[WRITE_FIRST, WRITE_END)`:
/// 128 KiB, 1 MiB into the disk.
pub const WRITE_FIRST: u64 = 2048;
pub const WRITE_END: u64 = 2304;

/// The seed sector `sector` has; `written` says whether the kernel's
/// test has written the write range.
pub const fn seed_of(sector: u64, written: bool) -> u64 {
    if written && WRITE_FIRST <= sector && sector < WRITE_END {
        WRITTEN
    } else {
        ORIGINAL
    }
}

/// Where a buffer differs from the pattern.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Mismatch {
    /// The sector of the disk the word belongs to.
    pub sector: u64,
    /// Which word of the disk it is.
    pub word: u64,
    /// What the buffer holds there.
    pub found: u64,
}

/// A buffer of the pattern is whole sectors.
fn whole_sectors(buffer: &[u8]) {
    assert!(
        buffer.len() % SECTOR == 0,
        "a buffer of the disk's pattern is whole sectors"
    );
}

/// Fill `buffer` with what the sectors starting at sector `first` hold
/// under `seed`, as many sectors as the buffer has.
pub fn fill(buffer: &mut [u8], first: u64, seed: u64) {
    whole_sectors(buffer);
    for (word, bytes) in (first * WORDS..).zip(buffer.as_chunks_mut::<8>().0) {
        *bytes = (seed ^ word).to_le_bytes();
    }
}

/// Whether `buffer` holds what the sectors starting at sector `first`
/// hold under `seed`; if not, the first word that differs.
pub fn check(buffer: &[u8], first: u64, seed: u64) -> Result<(), Mismatch> {
    whole_sectors(buffer);
    for (word, bytes) in (first * WORDS..).zip(buffer.as_chunks::<8>().0) {
        let found = u64::from_le_bytes(*bytes);
        if found != seed ^ word {
            return Err(Mismatch {
                sector: word / WORDS,
                word,
                found,
            });
        }
    }
    Ok(())
}

/// Whether `buffer`, the sectors starting at sector `first`, is what
/// the disk holds there: each sector under its own seed ([`seed_of`]).
pub fn check_disk(buffer: &[u8], first: u64, written: bool) -> Result<(), Mismatch> {
    whole_sectors(buffer);
    for (sector, bytes) in (first..).zip(buffer.as_chunks::<SECTOR>().0) {
        check(bytes, sector, seed_of(sector, written))?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The bytes `tools/datadisk.py` makes: `sectors(first, count, seed)`
    /// packs `seed ^ k` as little-endian 64-bit words.
    #[test]
    fn the_bytes_are_the_harness_s() {
        let mut two = [0u8; 2 * SECTOR];
        fill(&mut two, 0, ORIGINAL);
        assert_eq!(two[..8], [0, 0, 0, 0, 0x52, 0x4F, 0x4B, 0x4E]);
        assert_eq!(two[8..16], [1, 0, 0, 0, 0x52, 0x4F, 0x4B, 0x4E]);
        // Sector 1 starts at word 64.
        assert_eq!(
            two[SECTOR..SECTOR + 8],
            [64, 0, 0, 0, 0x52, 0x4F, 0x4B, 0x4E]
        );
        // The first written sector starts at word 2048 * 64 = 0x20000.
        let mut one = [0u8; SECTOR];
        fill(&mut one, WRITE_FIRST, WRITTEN);
        assert_eq!(one[..8], [0, 0, 2, 0, 0x52, 0x57, 0x4B, 0x4E]);
        assert_eq!(one[SECTOR - 8..], [63, 0, 2, 0, 0x52, 0x57, 0x4B, 0x4E]);
    }

    #[test]
    fn a_filled_buffer_checks() {
        let mut buffer = [0u8; 3 * SECTOR];
        fill(&mut buffer, 7, ORIGINAL);
        assert_eq!(check(&buffer, 7, ORIGINAL), Ok(()));
        assert_eq!(check(&[], 7, ORIGINAL), Ok(()));
    }

    #[test]
    fn a_wrong_place_seed_or_byte_shows() {
        let mut buffer = [0u8; 2 * SECTOR];
        fill(&mut buffer, 7, ORIGINAL);
        // The right sectors at the wrong address.
        assert_eq!(
            check(&buffer, 8, ORIGINAL),
            Err(Mismatch {
                sector: 8,
                word: 8 * 64,
                found: ORIGINAL ^ (7 * 64),
            })
        );
        // The other seed.
        assert_eq!(check(&buffer, 7, WRITTEN).unwrap_err().word, 7 * 64);
        // One byte, in the second sector.
        buffer[SECTOR + 17] ^= 1;
        assert_eq!(
            check(&buffer, 7, ORIGINAL),
            Err(Mismatch {
                sector: 8,
                word: 8 * 64 + 2,
                found: (ORIGINAL ^ (8 * 64 + 2)) ^ 0x100,
            })
        );
        // A transfer shifted by a word inside a sector.
        fill(&mut buffer, 7, ORIGINAL);
        buffer.copy_within(8.., 0);
        assert_eq!(check(&buffer, 7, ORIGINAL).unwrap_err().word, 7 * 64);
    }

    #[test]
    fn the_write_range_has_the_written_seed_once_written() {
        assert_eq!(seed_of(WRITE_FIRST - 1, true), ORIGINAL);
        assert_eq!(seed_of(WRITE_FIRST, true), WRITTEN);
        assert_eq!(seed_of(WRITE_END - 1, true), WRITTEN);
        assert_eq!(seed_of(WRITE_END, true), ORIGINAL);
        assert_eq!(seed_of(WRITE_FIRST, false), ORIGINAL);
        assert_eq!((WRITE_END - WRITE_FIRST) as usize * SECTOR, 128 << 10);
    }

    #[test]
    fn a_stretch_of_the_disk_checks_sector_by_sector() {
        let first = WRITE_FIRST - 2;
        let mut buffer = [0u8; 4 * SECTOR];
        fill(&mut buffer, first, ORIGINAL);
        assert_eq!(check_disk(&buffer, first, false), Ok(()));
        // Once written, the two sectors inside the range are stale.
        assert_eq!(
            check_disk(&buffer, first, true).unwrap_err().sector,
            WRITE_FIRST
        );
        fill(&mut buffer[2 * SECTOR..], WRITE_FIRST, WRITTEN);
        assert_eq!(check_disk(&buffer, first, true), Ok(()));
        assert_eq!(
            check_disk(&buffer, first, false).unwrap_err().sector,
            WRITE_FIRST
        );
    }

    #[test]
    #[should_panic(expected = "whole sectors")]
    fn a_buffer_is_whole_sectors() {
        fill(&mut [0u8; 100], 0, ORIGINAL);
    }
}
