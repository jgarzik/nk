//! File-name matching against a wildcard expression: the logic of
//! [`FsRtlIsNameInExpression`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-_fsrtl_advanced_fcb_header-fsrtlisnameinexpression).
//!
//! The wildcards, as that page and
//! [MS-FSCC 2.1.4.4](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-fscc/dc92d939-ec45-40c8-96e5-4c4091e4ab43)
//! state them:
//!
//! | In the expression | Matches |
//! | --- | --- |
//! | `*` | zero or more characters |
//! | `?` | one character |
//! | `<` (`DOS_STAR`) | zero or more characters, but never the name's last period |
//! | `>` (`DOS_QM`) | one character; at a period or at the end of the name, nothing |
//! | `"` (`DOS_DOT`) | a period; at the end of the name, nothing |
//!
//! Anything else matches itself. If only one of the two strings is
//! empty there is no match, so `*` does not match the empty name; two
//! empty strings match.
//!
//! # INFERRED
//!
//! The table above is the documentation's wording made exact. Where the
//! wording leaves a choice, this is NK's reading, to be checked against
//! Windows:
//!
//! - `>` never consumes a period: at one it only steps aside;
//! - `"` in the middle of a name matches a period and nothing else;
//! - `<` consumes any character after the last period, and every
//!   character of a name without one;
//! - without regard to case only the name is upper-cased, by the
//!   system's table or the caller's; an expression with a lower-case
//!   letter then matches nothing that letter stands against;
//! - the name's last period is found before its units are upper-cased.

use crate::Text;

const STAR: u16 = b'*' as u16;
const QUESTION: u16 = b'?' as u16;
const DOS_STAR: u16 = b'<' as u16;
const DOS_QM: u16 = b'>' as u16;
const DOS_DOT: u16 = b'"' as u16;
const PERIOD: u16 = b'.' as u16;

/// Units in the longest expression: the longest counted string.
pub const MAX_EXPRESSION: usize = 0x7FFF;

/// One bit for each place in an expression, its end included.
struct Reached([u64; MAX_EXPRESSION / 64 + 1]);

impl Reached {
    fn get(&self, at: usize) -> bool {
        self.0[at / 64] >> (at % 64) & 1 != 0
    }
    fn set(&mut self, at: usize, reached: bool) {
        let bit = 1 << (at % 64);
        if reached {
            self.0[at / 64] |= bit;
        } else {
            self.0[at / 64] &= !bit;
        }
    }
}

/// Whether `name` matches `expression`. Each unit of the name is
/// compared as `fold` gives it: the identity for a match that regards
/// case, an upper-case table for one that does not, and then the
/// expression must be in upper case already.
///
/// The expression is run as a state machine over the name, one state
/// per expression character: time is bounded by the product of the two
/// lengths, whatever the pattern, and memory by four kilobytes of the
/// caller's stack. Nothing is allocated, so the match cannot fail,
/// where Windows raises `STATUS_NO_MEMORY`. None if the expression is
/// longer than a counted string can be.
pub fn is_name_in_expression(
    expression: &(impl Text + ?Sized),
    name: &(impl Text + ?Sized),
    fold: impl Fn(u16) -> u16,
) -> Option<bool> {
    let (end, length) = (expression.length(), name.length());
    if end > MAX_EXPRESSION {
        return None;
    }
    if end == 0 || length == 0 {
        return Some(end == 0 && length == 0);
    }
    let last_period = (0..length).rev().find(|&at| name.unit(at) == PERIOD);
    // `reached.get(i)`: the first `i` expression characters can match
    // the name read so far.
    let mut reached = Reached([0; MAX_EXPRESSION / 64 + 1]);
    reached.set(0, true);
    for at in 0..=length {
        let c = (at < length).then(|| fold(name.unit(at)));
        // What an expression character may match without consuming.
        for i in 0..end {
            let nothing = match expression.unit(i) {
                STAR | DOS_STAR => true,
                DOS_QM => c.is_none() || c == Some(PERIOD),
                DOS_DOT => c.is_none(),
                _ => false,
            };
            if reached.get(i) && nothing {
                reached.set(i + 1, true);
            }
        }
        let Some(c) = c else { break };
        // Consume `c`. Downwards, so that each state is read before it
        // is written.
        for i in (0..=end).rev() {
            let stays = i < end
                && reached.get(i)
                && match expression.unit(i) {
                    STAR => true,
                    DOS_STAR => Some(at) != last_period,
                    _ => false,
                };
            let steps = i > 0
                && reached.get(i - 1)
                && match expression.unit(i - 1) {
                    STAR | DOS_STAR => false,
                    QUESTION => true,
                    DOS_QM => c != PERIOD,
                    DOS_DOT => c == PERIOD,
                    literal => literal == c,
                };
            reached.set(i, stays || steps);
        }
    }
    Some(reached.get(end))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::upcase::upcase_char;

    fn w(s: &str) -> Vec<u16> {
        s.encode_utf16().collect()
    }

    fn fold(ignore_case: bool) -> fn(u16) -> u16 {
        if ignore_case { upcase_char } else { |c| c }
    }

    fn matches(expression: &str, name: &str, ignore_case: bool) -> bool {
        is_name_in_expression(
            w(expression).as_slice(),
            w(name).as_slice(),
            fold(ignore_case),
        )
        .unwrap()
    }

    #[test]
    fn expressions() {
        for (expression, name, expected) in [
            // Empty strings.
            ("", "", true),
            ("*", "", false),
            ("", "a", false),
            ("<", "", false),
            // Literals.
            ("abc", "abc", true),
            ("abc", "abd", false),
            ("abc", "ab", false),
            ("ab", "abc", false),
            // `*`.
            ("*", "anything.at.all", true),
            ("*.txt", "a.txt", true),
            ("*.txt", ".txt", true),
            ("*.txt", "a.txt.bak", false),
            ("a*c", "ac", true),
            ("a*c", "abbbc", true),
            ("a*c", "abbbd", false),
            ("a**c", "abc", true),
            ("*a*b*", "xxaxxbxx", true),
            ("*a*b*", "xxbxxaxx", false),
            // A trailing `.*` needs the period.
            ("foo.*", "foo", false),
            ("foo.*", "foo.", true),
            ("foo.*", "foo.c", true),
            // `?`.
            ("?", "a", true),
            ("?", ".", true),
            ("?", "ab", false),
            ("a?c", "abc", true),
            ("a?c", "ac", false),
            ("a?", "a", false),
            // `<`: stops before the last period.
            ("<", "abc", true),
            ("<", "a.b", false),
            ("<.b", "a.b", true),
            ("<.c", "a.b.c", true),
            ("<.b.c", "a.b.c", true),
            ("<.b", "a.b.c", false),
            ("<\"", "foo", true),
            ("<\"", "foo.txt", false),
            ("<\"*", "foo.txt", true),
            ("<.", "a.", true),
            ("a<", "a.", false),
            // After the last period it is a `*` again.
            (".<", ".abc", true),
            ("<.<", "a.b", true),
            // `>`: one character, or nothing at a period or the end.
            (">", "a", true),
            (">", ".", false),
            (">>>", "ab", true),
            (">>>", "abcd", false),
            ("a>.txt", "a.txt", true),
            ("a>.txt", "ab.txt", true),
            ("a>.txt", "abc.txt", false),
            ("a>>>.>>>", "ab.c", true),
            ("a>b", "ab", false),
            ("a>b", "a.b", false),
            // `"`: a period, or nothing at the end.
            ("a\"", "a", true),
            ("a\"", "a.", true),
            ("a\"b", "a.b", true),
            ("a\"b", "ab", false),
            ("a\"b", "axb", false),
            ("a\"\"", "a", true),
            ("*\"*", "foo", true),
            ("*\"*", "foo.c", true),
        ] {
            assert_eq!(
                matches(expression, name, false),
                expected,
                "{expression:?} against {name:?}"
            );
        }
    }

    #[test]
    fn case() {
        // The name is upper-cased; the expression is taken as it is.
        assert!(matches("FOO.*", "foo.txt", true));
        assert!(matches("FOO.TXT", "Foo.Txt", true));
        assert!(!matches("FOO.TXT", "Foo.Txt", false));
        assert!(!matches("foo.txt", "foo.txt", true), "not upper case");
        assert!(matches("foo.txt", "foo.txt", false));
        // By the system table, not ASCII alone.
        assert!(matches("\u{C9}T\u{C9}*", "\u{E9}t\u{E9}.txt", true));
        assert!(matches("\u{391}?", "\u{3B1}\u{3B2}", true));
        assert!(!matches("\u{391}", "\u{3B1}", false));
    }

    /// The same rules by trying every way to match: exponential.
    fn slow(expression: &[u16], name: &[u16], at: usize) -> bool {
        let Some((&e, rest)) = expression.split_first() else {
            return at == name.len();
        };
        let c = name.get(at).copied();
        let last_period = name.iter().rposition(|&c| c == PERIOD);
        match e {
            STAR => slow(rest, name, at) || (c.is_some() && slow(expression, name, at + 1)),
            DOS_STAR => {
                slow(rest, name, at)
                    || (c.is_some() && Some(at) != last_period && slow(expression, name, at + 1))
            }
            DOS_QM if c.is_none() || c == Some(PERIOD) => slow(rest, name, at),
            DOS_DOT if c.is_none() => slow(rest, name, at),
            DOS_DOT => c == Some(PERIOD) && slow(rest, name, at + 1),
            QUESTION | DOS_QM => c.is_some() && slow(rest, name, at + 1),
            literal => c == Some(literal) && slow(rest, name, at + 1),
        }
    }

    /// Every string over `alphabet` of up to `longest` characters.
    fn strings(alphabet: &[u16], longest: usize) -> Vec<Vec<u16>> {
        let mut all = vec![Vec::new()];
        let mut from = 0;
        for _ in 0..longest {
            let to = all.len();
            for i in from..to {
                for &c in alphabet {
                    let mut longer = all[i].clone();
                    longer.push(c);
                    all.push(longer);
                }
            }
            from = to;
        }
        all
    }

    #[test]
    fn every_small_expression_agrees_with_the_exponential_matcher() {
        let expressions = strings(&w("a.*?<>\""), 5);
        let names = strings(&w("ab."), 4);
        let mut matched = 0;
        for expression in &expressions {
            for name in &names {
                let expected = if expression.is_empty() || name.is_empty() {
                    expression.is_empty() && name.is_empty()
                } else {
                    slow(expression, name, 0)
                };
                let got =
                    is_name_in_expression(expression.as_slice(), name.as_slice(), fold(false))
                        .unwrap();
                assert_eq!(got, expected, "{expression:?} against {name:?}");
                matched += usize::from(got);
            }
        }
        assert!(matched > 100_000, "{matched}");
        assert!(matched < expressions.len() * names.len() / 2, "{matched}");
    }

    #[test]
    fn a_pattern_that_defeats_backtracking_is_decided() {
        // `*a*a*a...b` against a run of `a`: no match, and a matcher
        // that tries every split of the name never finishes. Here the
        // work is the product of the lengths, 18 million steps.
        let name = vec![u16::from(b'a'); 3000];
        for wildcard in ["*a", "<a", ">*", "\"*a"] {
            let mut expression: Vec<u16> = w(wildcard).repeat(3000 / wildcard.len());
            expression.push(u16::from(b'b'));
            assert_eq!(
                is_name_in_expression(expression.as_slice(), name.as_slice(), fold(true)),
                Some(false),
                "{wildcard}"
            );
        }
        // And one that does match, the long way round.
        let expression = w("*a").repeat(3000);
        assert_eq!(
            is_name_in_expression(expression.as_slice(), name.as_slice(), fold(false)),
            Some(true)
        );
    }

    /// Every line of the conformance driver `nkc-rtl`'s table: the
    /// expression, the name, whether case is disregarded, and what its
    /// source predicts of Windows.
    #[test]
    fn the_conformance_drivers_expressions() {
        for (expression, name, ignore_case, expected) in [
            ("*", "anything", false, true),
            ("*", "", false, false),
            ("", "", false, true),
            ("", "a", false, false),
            ("abc", "abc", false, true),
            ("abc", "ABC", false, false),
            ("ABC", "abc", true, true),
            ("abc", "ABC", true, false),
            ("abc", "abcd", false, false),
            ("abcd", "abc", false, false),
            ("*abc", "xxabc", false, true),
            ("*abc", "xxabd", false, false),
            ("*abc", "abc", false, true),
            ("*abcd", "bcd", false, false),
            ("*ABC", "xxabc", true, true),
            ("*.txt", "file.txt", false, true),
            ("*.txt", "file.txt.bak", false, false),
            ("*.TXT", "file.txt", true, true),
            ("*.TXT", "file.txt", false, false),
            ("a*", "a", false, true),
            ("a*", "abc", false, true),
            ("a*", "ba", false, false),
            ("a*c", "ac", false, true),
            ("a*c", "abcbc", false, true),
            ("a*c", "abcb", false, false),
            ("*a*", "xax", false, true),
            ("*a*", "xxx", false, false),
            ("**", "x", false, true),
            ("a*b*c", "aXbYc", false, true),
            ("a*b*c", "acb", false, false),
            ("*a*a*a", "aaa", false, true),
            ("*a*a*a*a", "aaa", false, false),
            ("*.", "file.", false, true),
            ("*.", "file", false, false),
            ("*.*", "file", false, false),
            ("*.*", "file.txt", false, true),
            ("*.*", ".", false, true),
            ("a?c", "abc", false, true),
            ("a?c", "ac", false, false),
            ("a?c", "abbc", false, false),
            ("a?c", "a.c", false, true),
            ("???", "ab", false, false),
            ("???", "abc", false, true),
            ("?", "", false, false),
            ("a?", "a", false, false),
            ("?*", "a", false, true),
            ("<", "abc", false, true),
            ("<", "a.b", false, false),
            ("<.txt", "file.txt", false, true),
            ("<.txt", "a.b.txt", false, true),
            ("<.txt", "file.txt.bak", false, false),
            ("<.b", "a.b.c", false, false),
            ("a<", "a.b", false, false),
            ("a<c", "a.c", false, false),
            ("a<c", "abc", false, true),
            ("<\"*", "file", false, true),
            ("<\"*", "file.txt", false, true),
            ("<\"*", "a.b.c", false, true),
            ("<\"", "file.", false, true),
            ("a>", "a", false, true),
            ("a>", "ab", false, true),
            ("a>", "abc", false, false),
            ("a>>", "a", false, true),
            ("a>c", "ac", false, false),
            ("a>c", "abc", false, true),
            ("a>.c", "a.c", false, true),
            (">>>.txt", "ab.txt", false, true),
            (">>>.txt", "abcd.txt", false, false),
            (">", ".", false, false),
            (">>>>>>>>\">>>", "abc.de", false, true),
            (">>>>>>>>\">>>", "abc", false, true),
            (">>>>>>>>\">>>", "abcdefghi.x", false, false),
            (">>>>>>>>\">>>", "abc.defg", false, false),
            ("a\"b", "a.b", false, true),
            ("a\"b", "axb", false, false),
            ("a\"b", "ab", false, false),
            ("a\"", "a", false, true),
            ("a\"", "a.", false, true),
            ("a\"", "ab", false, false),
            ("\"", ".", false, true),
            ("file\"*", "file", false, true),
            ("file\"*", "file.c", false, true),
            ("file\"*", "filex", false, false),
            ("A?C*", "abcdef", true, true),
            ("A?C*", "abcdef", false, false),
            ("<.TXT", "File.Txt", true, true),
            ("\u{C9}*", "\u{E9}x", true, true),
            ("\u{C9}*", "\u{E9}x", false, false),
            ("\u{391}?", "\u{3B1}\u{3B2}", true, true),
        ] {
            assert_eq!(
                matches(expression, name, ignore_case),
                expected,
                "{expression:?} against {name:?}, case disregarded: {ignore_case}"
            );
        }
    }

    #[test]
    fn the_name_is_compared_through_the_callers_table() {
        let through = |expression: &str, name: &str, fold: fn(u16) -> u16| {
            is_name_in_expression(w(expression).as_slice(), w(name).as_slice(), fold)
        };
        // A table that makes every character `X`.
        assert_eq!(through("X?X", "abc", |_| 0x58), Some(true));
        assert_eq!(through("abc", "abc", |_| 0x58), Some(false));
        // The name's last period is where it was before the table.
        // `<` cannot take the second unit, though it reads as `X`.
        assert_eq!(through("<X", "a.b", |_| 0x58), Some(false));
        assert_eq!(through("<XX", "a.b", |_| 0x58), Some(true));
        assert_eq!(through("<X", "abc", |_| 0x58), Some(true));
    }

    #[test]
    fn the_longest_expression_is_matched_and_a_longer_one_refused() {
        let star = vec![STAR; MAX_EXPRESSION];
        let name = w("a");
        assert_eq!(
            is_name_in_expression(star.as_slice(), name.as_slice(), fold(false)),
            Some(true)
        );
        let mut literal = vec![STAR; MAX_EXPRESSION - 1];
        literal.push(0x62);
        assert_eq!(
            is_name_in_expression(literal.as_slice(), name.as_slice(), fold(false)),
            Some(false)
        );
        let longer = vec![STAR; MAX_EXPRESSION + 1];
        assert_eq!(
            is_name_in_expression(longer.as_slice(), name.as_slice(), fold(false)),
            None
        );
    }
}
