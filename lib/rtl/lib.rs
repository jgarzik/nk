//! Runtime-library logic with no hardware behind it: UTF-16
//! counted-string arithmetic and object-name handling here; in the
//! modules, formatted output, upper-casing and comparison, the prefix
//! table, the AVL table's balancing, wildcard matching, text forms and length rules, code pages,
//! the characters legal in file names, bitmaps, the C string
//! functions, and the filter of debug messages.
//! Nothing here allocates: what a routine works on is the caller's.
//!
//! The kernel's `Rtl*` exports and its object namespace are thin wrappers
//! over these functions, so the behaviour is tested on the build host.

#![cfg_attr(not(test), no_std)]

pub mod avl;
pub mod bitmap;
pub mod codepage;
pub mod convert;
pub mod counted;
pub mod crt;
pub mod dbgfilter;
pub mod doserror;
pub mod fatname;
pub mod format;
pub mod gen83;
pub mod legal;
pub mod once;
pub mod prefix;
pub mod range;
pub mod resource;
pub mod splay;
pub mod string;
pub mod upcase;
pub mod wildcard;

pub use upcase::upcase_char;

/// Windows' tables, as the conformance driver `nkc-rtl` returned them
/// on Windows 10 (`oracle/nkc-rtl-tables.txt`): the tables here are
/// held to them unit by unit.
#[cfg(test)]
mod recorded {
    const TRANSCRIPT: &str = include_str!("../../oracle/nkc-rtl-tables.txt");

    /// What the device-control requests with these function numbers
    /// returned, one after another.
    fn bytes(functions: core::ops::Range<u32>) -> Vec<u8> {
        let mut all = Vec::new();
        for line in TRANSCRIPT.lines() {
            // `ioctl d <code> - <room>: <status> <length> <bytes>`
            let mut fields = line.split(' ');
            if fields.next() != Some("ioctl") {
                continue;
            }
            let code = u32::from_str_radix(fields.nth(1).unwrap(), 16).unwrap();
            // `CTL_CODE`: the function number is bits 2 to 13.
            if functions.contains(&(code >> 2 & 0xFFF)) {
                let hex = fields.next_back().unwrap();
                all.extend(
                    (0..hex.len())
                        .step_by(2)
                        .map(|at| u8::from_str_radix(&hex[at..at + 2], 16).unwrap()),
                );
            }
        }
        all
    }

    fn units(bytes: &[u8]) -> Vec<u16> {
        let (pairs, _) = bytes.as_chunks::<2>();
        pairs.iter().map(|&pair| u16::from_le_bytes(pair)).collect()
    }

    /// `RtlUpcaseUnicodeChar` of each of the 65536 units.
    pub fn upcase() -> Vec<u16> {
        units(&bytes(0xA00..0xA10))
    }

    /// The unit `RtlMultiByteToUnicodeN` makes of each of the 256
    /// bytes.
    pub fn to_unicode() -> Vec<u16> {
        units(&bytes(0xA10..0xA11))
    }

    /// The byte `RtlUnicodeToMultiByteN` makes of each of the 65536
    /// units.
    pub fn to_ansi() -> Vec<u8> {
        bytes(0xA20..0xA30)
    }
}

/// A counted string, where it lies: the prefix table and the wildcard
/// matcher read a driver's names through this, a unit at a time.
pub trait Text {
    /// Its length in units.
    fn length(&self) -> usize;
    /// The unit at `at`, which is below `length`.
    fn unit(&self, at: usize) -> u16;
}

impl Text for [u16] {
    fn length(&self) -> usize {
        self.len()
    }
    fn unit(&self, at: usize) -> u16 {
        self[at]
    }
}

/// A byte string, a single-byte page's: each byte is a unit.
impl Text for [u8] {
    fn length(&self) -> usize {
        self.len()
    }
    fn unit(&self, at: usize) -> u16 {
        u16::from(self[at])
    }
}

/// Largest `Length`, in bytes, `RtlInitUnicodeString` will report: the
/// 16-bit field must also leave room for the terminator in
/// `MaximumLength`.
pub const MAX_INIT_LENGTH: usize = 0xFFFC;

/// `(Length, MaximumLength)` that `RtlInitUnicodeString` stores for a
/// source string of `chars` UTF-16 units before its NUL. A longer string
/// is truncated, as on Windows.
pub fn init_unicode_lengths(chars: usize) -> (u16, u16) {
    let len = chars.saturating_mul(2).min(MAX_INIT_LENGTH);
    (len as u16, (len + 2) as u16)
}

/// Compare two names the way the object manager and the registry do:
/// without regard to case, by the full upper-case table
/// ([`upcase_char`]).
pub fn names_equal(a: &[u16], b: &[u16]) -> bool {
    upcase::equal_unicode_string(a, b, true)
}

/// The file an image path names: what follows its last backslash, up to
/// the terminator if the path carries one (`\\SystemRoot\\System32\\
/// drivers\\null.sys` names `null.sys`).
pub fn image_file(path: &[u16]) -> &[u16] {
    let end = path.iter().position(|&c| c == 0).unwrap_or(path.len());
    let path = &path[..end];
    let start = path
        .iter()
        .rposition(|&c| c == u16::from(b'\\'))
        .map_or(0, |i| i + 1);
    &path[start..]
}

/// An absolute object name: starts with a backslash and names something.
pub fn is_valid_object_name(name: &[u16]) -> bool {
    name.len() > 1 && name[0] == u16::from(b'\\') && !name.contains(&0)
}

/// Whether `text` matches `pattern`, where `*` in the pattern stands for
/// any run of characters (including none) and everything else is literal.
pub fn glob_match(pattern: &str, text: &str) -> bool {
    let (p, t) = (pattern.as_bytes(), text.as_bytes());
    // `star`: where the last `*` was, and how much text it has taken.
    let (mut pi, mut ti, mut star) = (0, 0, None);
    while ti < t.len() {
        if pi < p.len() && p[pi] == b'*' {
            star = Some((pi, ti));
            pi += 1;
        } else if pi < p.len() && p[pi] == t[ti] {
            pi += 1;
            ti += 1;
        } else if let Some((sp, st)) = star {
            // Let the last `*` take one more character and retry.
            star = Some((sp, st + 1));
            pi = sp + 1;
            ti = st + 1;
        } else {
            return false;
        }
    }
    p[pi..].iter().all(|&c| c == b'*')
}

#[cfg(test)]
mod tests {
    use super::*;

    fn w(s: &str) -> Vec<u16> {
        s.encode_utf16().collect()
    }

    #[test]
    fn image_file_is_the_last_component() {
        assert_eq!(
            image_file(&w("\\SystemRoot\\System32\\drivers\\null.sys\0")),
            &w("null.sys")[..]
        );
        assert_eq!(image_file(&w("null.sys")), &w("null.sys")[..]);
        assert_eq!(image_file(&w("System32\\drivers\\")), &w("")[..]);
        assert_eq!(image_file(&w("a\\b\0\\c")), &w("b")[..]);
        assert_eq!(image_file(&[]), &w("")[..]);
    }

    #[test]
    fn init_lengths() {
        assert_eq!(init_unicode_lengths(0), (0, 2));
        assert_eq!(init_unicode_lengths(12), (24, 26));
        assert_eq!(init_unicode_lengths(0x7FFE), (0xFFFC, 0xFFFE));
        assert_eq!(
            init_unicode_lengths(0x8000),
            (0xFFFC, 0xFFFE),
            "truncated, not wrapped"
        );
        assert_eq!(init_unicode_lengths(usize::MAX), (0xFFFC, 0xFFFE));
    }

    #[test]
    fn case_folding() {
        assert!(names_equal(&w("\\Device\\Null"), &w("\\DEVICE\\null")));
        assert!(!names_equal(&w("\\Device\\Null"), &w("\\Device\\Nul")));
        assert!(!names_equal(&w("\\Device\\Null"), &w("\\Device\\Nulls")));
        assert!(names_equal(&w("caf\u{e9}"), &w("CAF\u{c9}")), "Latin-1");
        assert!(
            names_equal(&w("\u{3b1}\u{3b2}\u{3b3}"), &w("\u{391}\u{392}\u{393}")),
            "beyond Latin-1"
        );
        assert!(!names_equal(&w("\u{f7}"), &w("\u{d7}")), "no letters");
    }

    #[test]
    fn name_validity() {
        assert!(is_valid_object_name(&w("\\Device\\Null")));
        assert!(!is_valid_object_name(&w("Device\\Null")), "relative");
        assert!(!is_valid_object_name(&w("\\")));
        assert!(!is_valid_object_name(&w("")));
        assert!(
            !is_valid_object_name(&[0x5C, 0x41, 0, 0x42]),
            "embedded NUL"
        );
    }

    #[test]
    fn globs() {
        for (pattern, text, expected) in [
            ("", "", true),
            ("", "a", false),
            ("*", "", true),
            ("*", "anything.at.all", true),
            ("null.read", "null.read", true),
            ("null.read", "null.reads", false),
            ("null.*", "null.read", true),
            ("null.*", "null.", true),
            ("null.*", "nullx", false),
            ("*.load", "sioctl.load", true),
            ("*.load", "sioctl.loader", false),
            ("s*t*l.*", "sioctl.open", true),
            ("a*b*c", "abcbc", true),
            ("a*b*c", "abcb", false),
            ("**", "x", true),
            ("neg.panic", "neg.panic", true),
        ] {
            assert_eq!(
                glob_match(pattern, text),
                expected,
                "{pattern:?} vs {text:?}"
            );
        }
    }
}
