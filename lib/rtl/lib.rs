//! Runtime-library logic with no hardware or allocator behind it: UTF-16
//! counted-string arithmetic and object-name handling.
//!
//! The kernel's `Rtl*` exports and its object namespace are thin wrappers
//! over these functions, so the behaviour is tested on the build host.

#![cfg_attr(not(test), no_std)]

pub mod format;
pub mod upcase;

pub use upcase::upcase_char;

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

/// Uppercase one UTF-16 unit for case-insensitive name comparison.
///
/// Covers ASCII and Latin-1. Windows uses a full upcase table; names
/// outside these ranges compare case-sensitively here, which can only
/// make NK stricter, never match two names Windows keeps apart.
/// [`upcase_char`] is the full table.
pub fn upcase(c: u16) -> u16 {
    match c {
        0x61..=0x7A => c - 0x20,
        0xE0..=0xFE if c != 0xF7 => c - 0x20,
        _ => c,
    }
}

/// Compare two names the way the object manager does: case-insensitively.
pub fn names_equal(a: &[u16], b: &[u16]) -> bool {
    a.len() == b.len() && a.iter().zip(b).all(|(&x, &y)| upcase(x) == upcase(y))
}

fn strip_prefix_ignore_case<'a>(name: &'a [u16], prefix: &str) -> Option<&'a [u16]> {
    let n = prefix.len();
    let head = name.get(..n)?;
    head.iter()
        .zip(prefix.bytes())
        .all(|(&c, p)| upcase(c) == upcase(u16::from(p)))
        .then(|| &name[n..])
}

/// The directories that hold MS-DOS device names. `\DosDevices` and
/// `\GLOBAL??` are aliases of `\??`.
const DOS_DEVICE_DIRS: [&str; 3] = ["\\??\\", "\\DosDevices\\", "\\GLOBAL??\\"];

/// If `name` is in a DOS-devices directory, the part after the directory.
/// `\DosDevices\Foo`, `\??\Foo` and `\GLOBAL??\Foo` all yield `Foo`, so the
/// three spellings name one object.
pub fn dos_device_name(name: &[u16]) -> Option<&[u16]> {
    DOS_DEVICE_DIRS
        .iter()
        .find_map(|dir| strip_prefix_ignore_case(name, dir))
}

/// True if two object names refer to the same object: equal ignoring case,
/// with the DOS-devices directory aliases folded together.
pub fn same_object_name(a: &[u16], b: &[u16]) -> bool {
    match (dos_device_name(a), dos_device_name(b)) {
        (Some(x), Some(y)) => names_equal(x, y),
        (None, None) => names_equal(a, b),
        _ => false,
    }
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
        assert_eq!(upcase(0xE9), 0xC9, "e-acute");
        assert_eq!(upcase(0xF7), 0xF7, "division sign has no upper case");
        assert_eq!(upcase(u16::from(b'[')), u16::from(b'['));
    }

    #[test]
    fn dos_device_aliases() {
        assert_eq!(
            dos_device_name(&w("\\DosDevices\\IoctlTest")),
            Some(&w("IoctlTest")[..])
        );
        assert_eq!(
            dos_device_name(&w("\\??\\IoctlTest")),
            Some(&w("IoctlTest")[..])
        );
        assert_eq!(dos_device_name(&w("\\global??\\X")), Some(&w("X")[..]));
        assert_eq!(dos_device_name(&w("\\Device\\IoctlTest")), None);
        assert_eq!(
            dos_device_name(&w("\\DosDevices")),
            None,
            "the directory itself"
        );
        assert!(same_object_name(
            &w("\\DosDevices\\IoctlTest"),
            &w("\\??\\IOCTLTEST")
        ));
        assert!(!same_object_name(&w("\\DosDevices\\A"), &w("\\Device\\A")));
        assert!(same_object_name(&w("\\Device\\A"), &w("\\device\\a")));
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
