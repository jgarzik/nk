//! Which ANSI characters are legal in file names: the table behind
//! `FsRtlLegalAnsiCharacterArray`, which `ntifs.h` reads through
//! [`FsRtlIsAnsiCharacterLegalFat`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-fsrtlisansicharacterlegalfat),
//! [`FsRtlIsAnsiCharacterLegalHpfs`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-fsrtlisansicharacterlegalhpfs),
//! [`FsRtlIsAnsiCharacterLegalNtfs`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-fsrtlisansicharacterlegalntfs),
//! [`FsRtlIsAnsiCharacterLegalNtfsStream`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-fsrtlisansicharacterlegalntfsstream)
//! and
//! [`FsRtlIsAnsiCharacterWild`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-fsrtlisansicharacterwild).
//!
//! The header's macros index the table with a character below 0x80 and
//! test the flags below; a character from 0x80 up never reaches it.
//!
//! # INFERRED
//!
//! Microsoft publishes the flags and the macros, not the table. It is
//! built here from the naming rules of each file system, to be checked
//! against the table of a running Windows:
//!
//! - no control character, and none of `" * / < > ? \ |`, is legal in
//!   a FAT, HPFS or NTFS name; HPFS also excludes `:`, and FAT `:` and
//!   `+ , ; = [ ]`;
//! - the wildcards are `*` and `?` and the three DOS ones, `"`, `<`
//!   and `>`;
//! - the OLE flag, which with the NTFS one says what a stream's name
//!   may hold, is set for every character but NUL and `! / : \`.

/// `FSRTL_FAT_LEGAL`.
pub const FAT_LEGAL: u8 = 0x01;
/// `FSRTL_HPFS_LEGAL`.
pub const HPFS_LEGAL: u8 = 0x02;
/// `FSRTL_NTFS_LEGAL`.
pub const NTFS_LEGAL: u8 = 0x04;
/// `FSRTL_WILD_CHARACTER`.
pub const WILD_CHARACTER: u8 = 0x08;
/// `FSRTL_OLE_LEGAL`.
pub const OLE_LEGAL: u8 = 0x10;

const fn among(c: u8, set: &[u8]) -> bool {
    let mut i = 0;
    while i < set.len() {
        if set[i] == c {
            return true;
        }
        i += 1;
    }
    false
}

const fn flags(c: u8) -> u8 {
    let mut flags = 0;
    if c >= 0x20 && !among(c, b"\"*/<>?\\|") {
        flags |= NTFS_LEGAL;
        if c != b':' {
            flags |= HPFS_LEGAL;
            if !among(c, b"+,;=[]") {
                flags |= FAT_LEGAL;
            }
        }
    }
    if among(c, b"\"*<>?") {
        flags |= WILD_CHARACTER;
    }
    if c != 0 && !among(c, b"!/:\\") {
        flags |= OLE_LEGAL;
    }
    flags
}

const fn table() -> [u8; 128] {
    let mut table = [0u8; 128];
    let mut c = 0;
    while c < 128 {
        table[c] = flags(c as u8);
        c += 1;
    }
    table
}

/// The flags of the characters 0x00 to 0x7F.
pub const LEGAL_ANSI_CHARACTERS: [u8; 128] = table();

#[cfg(test)]
mod tests {
    use super::*;

    const ALL: u8 = FAT_LEGAL | HPFS_LEGAL | NTFS_LEGAL | OLE_LEGAL;

    fn of(c: u8) -> u8 {
        LEGAL_ANSI_CHARACTERS[usize::from(c)]
    }

    #[test]
    fn the_table_is_the_rules_for_each_character() {
        assert_eq!(table(), LEGAL_ANSI_CHARACTERS);
        for c in 0..128 {
            assert_eq!(flags(c), of(c), "{c:#x}");
        }
    }

    #[test]
    fn letters_and_digits_are_legal_everywhere() {
        for c in (b'a'..=b'z').chain(b'A'..=b'Z').chain(b'0'..=b'9') {
            assert_eq!(of(c), ALL, "{}", c as char);
        }
        for &c in b" #$%&'()-@^_`{}~\x7F" {
            assert_eq!(of(c), ALL, "{}", c as char);
        }
    }

    #[test]
    fn the_exceptions() {
        assert_eq!(of(0), 0);
        for c in 1..0x20 {
            assert_eq!(of(c), OLE_LEGAL, "{c:#x}");
        }
        for &c in b"\"*<>?" {
            assert_eq!(of(c), WILD_CHARACTER | OLE_LEGAL, "{}", c as char);
        }
        for &c in b"+,;=[]" {
            assert_eq!(of(c), ALL & !FAT_LEGAL, "{}", c as char);
        }
        assert_eq!(of(b':'), NTFS_LEGAL);
        assert_eq!(of(b'/'), 0);
        assert_eq!(of(b'\\'), 0);
        assert_eq!(of(b'|'), OLE_LEGAL);
        assert_eq!(of(b'!'), ALL & !OLE_LEGAL);
        assert_eq!(of(b'.'), ALL);
    }

    /// The header's `FsRtlTestAnsiCharacter`: any of the flags, or the
    /// wildcard flag if wildcards are let through.
    fn test(c: u8, wild_ok: bool, flags: u8) -> bool {
        of(c) & (flags | if wild_ok { WILD_CHARACTER } else { 0 }) != 0
    }

    #[test]
    fn the_headers_macros_give_each_file_systems_rules() {
        // A FAT name: no `+`, no wildcard unless asked.
        assert!(test(b'a', false, FAT_LEGAL));
        assert!(!test(b'+', false, FAT_LEGAL));
        assert!(test(b'+', false, HPFS_LEGAL));
        assert!(!test(b'*', false, FAT_LEGAL));
        assert!(test(b'*', true, FAT_LEGAL));
        assert!(!test(b'\\', true, FAT_LEGAL | HPFS_LEGAL | NTFS_LEGAL));
        // A stream's name may hold what a file's may not, a colon
        // aside.
        let stream = NTFS_LEGAL | OLE_LEGAL;
        assert!(test(b'|', false, stream));
        assert!(test(1, false, stream));
        assert!(test(b'*', false, stream));
        assert!(test(b':', false, stream));
        assert!(!test(b'/', false, stream));
        assert!(!test(0, true, stream));
        // Exactly five wildcards.
        let wild = (0..128).filter(|&c| test(c, false, WILD_CHARACTER));
        assert_eq!(wild.collect::<Vec<u8>>(), b"\"*<>?");
    }
}
