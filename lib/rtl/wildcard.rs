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
//! - with `ignore_case` only the name is upper-cased, by the system
//!   table; an expression with a lower-case letter then matches nothing
//!   that letter stands against.

use crate::upcase::upcase_char;
use alloc::collections::TryReserveError;
use alloc::vec::Vec;

const STAR: u16 = b'*' as u16;
const QUESTION: u16 = b'?' as u16;
const DOS_STAR: u16 = b'<' as u16;
const DOS_QM: u16 = b'>' as u16;
const DOS_DOT: u16 = b'"' as u16;
const PERIOD: u16 = b'.' as u16;

/// Whether `name` matches `expression`. With `ignore_case` the name is
/// compared in upper case and the expression must already be.
///
/// The expression is run as a state machine over the name, one state
/// per expression character: time is bounded by the product of the two
/// lengths and memory by the expression's, whatever the pattern. The
/// error is the allocator refusing that memory, for which Windows
/// raises `STATUS_NO_MEMORY`.
pub fn is_name_in_expression(
    expression: &[u16],
    name: &[u16],
    ignore_case: bool,
) -> Result<bool, TryReserveError> {
    if expression.is_empty() || name.is_empty() {
        return Ok(expression.is_empty() && name.is_empty());
    }
    let last_period = name.iter().rposition(|&c| c == PERIOD);
    let end = expression.len();
    // `reached[i]`: the first `i` expression characters can match the
    // name read so far.
    let mut reached = Vec::new();
    reached.try_reserve_exact(end + 1)?;
    reached.resize(end + 1, false);
    reached[0] = true;
    for at in 0..=name.len() {
        let c = name
            .get(at)
            .map(|&c| if ignore_case { upcase_char(c) } else { c });
        // What an expression character may match without consuming.
        for i in 0..end {
            let nothing = match expression[i] {
                STAR | DOS_STAR => true,
                DOS_QM => c.is_none() || c == Some(PERIOD),
                DOS_DOT => c.is_none(),
                _ => false,
            };
            if reached[i] && nothing {
                reached[i + 1] = true;
            }
        }
        let Some(c) = c else { break };
        // Consume `c`. Downwards, so that each state is read before it
        // is written.
        for i in (0..=end).rev() {
            let stays = i < end
                && reached[i]
                && match expression[i] {
                    STAR => true,
                    DOS_STAR => Some(at) != last_period,
                    _ => false,
                };
            let steps = i > 0
                && reached[i - 1]
                && match expression[i - 1] {
                    STAR | DOS_STAR => false,
                    QUESTION => true,
                    DOS_QM => c != PERIOD,
                    DOS_DOT => c == PERIOD,
                    literal => literal == c,
                };
            reached[i] = stays || steps;
        }
    }
    Ok(reached[end])
}

#[cfg(test)]
mod tests {
    use super::*;

    fn w(s: &str) -> Vec<u16> {
        s.encode_utf16().collect()
    }

    fn matches(expression: &str, name: &str, ignore_case: bool) -> bool {
        is_name_in_expression(&w(expression), &w(name), ignore_case).unwrap()
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
                let got = is_name_in_expression(expression, name, false).unwrap();
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
                is_name_in_expression(&expression, &name, true),
                Ok(false),
                "{wildcard}"
            );
        }
        // And one that does match, the long way round.
        let expression = w("*a").repeat(3000);
        assert_eq!(is_name_in_expression(&expression, &name, false), Ok(true));
    }
}
