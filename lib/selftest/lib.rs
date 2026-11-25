//! The bookkeeping behind the kernel's boot self-tests: which groups a
//! `test=` pattern selects, and whether a group reported exactly the
//! verdicts it declared. The kernel's runner (`kernel/test.rs`) prints
//! and counts; the decisions are here, where the host can test them.

#![cfg_attr(not(test), no_std)]

use nk_rtl::glob_match;

/// Most verdicts one group may declare.
pub const MAX_VERDICTS: usize = 64;

/// Whether a group runs. With no pattern, every group that is not
/// `manual` does. With one, a group runs if one of its names matches it
/// (`*` matches any run of characters); a `manual` group, one that ends
/// the boot on purpose, only if a name of its own is given exactly.
pub fn selected(names: &[&str], manual: bool, pattern: Option<&str>) -> bool {
    match pattern {
        None => !manual,
        Some(p) if manual => names.contains(&p),
        Some(p) => names.iter().any(|n| glob_match(p, n)),
    }
}

/// Why a verdict was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClaimError {
    /// The group did not declare a verdict of that name.
    Undeclared,
    /// The verdict was already reported.
    Twice,
}

/// Which of a group's declared verdicts have been reported.
#[derive(Debug)]
pub struct Claims<'a> {
    names: &'a [&'a str],
    /// Bit `i` is set once `names[i]` has a verdict.
    seen: u64,
}

impl<'a> Claims<'a> {
    /// `None` if the group declares more verdicts than can be tracked.
    pub fn new(names: &'a [&'a str]) -> Option<Self> {
        (names.len() <= MAX_VERDICTS).then_some(Self { names, seen: 0 })
    }

    /// Record the verdict for `name`.
    pub fn claim(&mut self, name: &str) -> Result<(), ClaimError> {
        let i = self
            .names
            .iter()
            .position(|n| *n == name)
            .ok_or(ClaimError::Undeclared)?;
        if self.seen & (1 << i) != 0 {
            return Err(ClaimError::Twice);
        }
        self.seen |= 1 << i;
        Ok(())
    }

    /// The declared verdicts not reported yet, in declaration order.
    pub fn missing(&self) -> impl Iterator<Item = &'a str> + use<'a> {
        let seen = self.seen;
        self.names
            .iter()
            .enumerate()
            .filter(move |(i, _)| seen & (1 << i) == 0)
            .map(|(_, name)| *name)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const NULL: &[&str] = &["null.load", "null.read", "io.open.missing-name"];
    const NEG: &[&str] = &["neg.panic"];

    #[test]
    fn without_a_pattern_everything_but_manual_groups_runs() {
        assert!(selected(NULL, false, None));
        assert!(!selected(NEG, true, None));
    }

    #[test]
    fn a_pattern_selects_groups_by_any_of_their_names() {
        for (pattern, wanted) in [
            ("null.read", true),
            ("null.*", true),
            ("*", true),
            ("io.*", true),
            ("*.missing-name", true),
            ("sioctl.*", false),
            ("null", false),
            ("", false),
        ] {
            assert_eq!(selected(NULL, false, Some(pattern)), wanted, "{pattern:?}");
        }
    }

    #[test]
    fn manual_groups_need_their_exact_name() {
        assert!(selected(NEG, true, Some("neg.panic")));
        for pattern in ["*", "neg.*", "neg.pani", "neg.panic2", ""] {
            assert!(!selected(NEG, true, Some(pattern)), "{pattern:?}");
        }
    }

    #[test]
    fn each_declared_verdict_is_claimed_once() {
        let mut claims = Claims::new(NULL).unwrap();
        assert_eq!(claims.missing().collect::<Vec<_>>(), NULL);
        assert_eq!(claims.claim("null.read"), Ok(()));
        assert_eq!(claims.claim("null.read"), Err(ClaimError::Twice));
        assert_eq!(claims.claim("null.write"), Err(ClaimError::Undeclared));
        assert_eq!(
            claims.missing().collect::<Vec<_>>(),
            ["null.load", "io.open.missing-name"]
        );
        assert_eq!(claims.claim("io.open.missing-name"), Ok(()));
        assert_eq!(claims.claim("null.load"), Ok(()));
        assert_eq!(claims.missing().count(), 0);
        assert_eq!(claims.claim("null.load"), Err(ClaimError::Twice));
    }

    #[test]
    fn the_limit_on_verdicts() {
        let many = ["x"; MAX_VERDICTS + 1];
        assert!(Claims::new(&many[..MAX_VERDICTS]).is_some());
        assert!(Claims::new(&many).is_none());
        // The last trackable verdict really is tracked.
        let names: Vec<String> = (0..MAX_VERDICTS).map(|i| format!("t{i}")).collect();
        let names: Vec<&str> = names.iter().map(String::as_str).collect();
        let mut claims = Claims::new(&names).unwrap();
        assert_eq!(claims.claim("t63"), Ok(()));
        assert_eq!(claims.claim("t63"), Err(ClaimError::Twice));
        assert_eq!(claims.missing().count(), MAX_VERDICTS - 1);
    }
}
