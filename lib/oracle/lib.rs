//! Oracle scripts and transcripts.
//!
//! A script is a list of requests to make of a driver. It is replayed on
//! real Windows and on NK; each prints a transcript, and the two must be
//! the same text. `oracle/README.md` defines both formats. This crate is
//! NK's reading of a script and NK's spelling of a transcript line; the
//! Windows side is `oracle/runner.ps1`.

#![cfg_attr(not(test), no_std)]

use core::fmt;

/// What every output buffer holds before a request, so that bytes nobody
/// wrote are visible in the transcript.
pub const FILL: u8 = 0xEE;

/// One step of a script. Byte strings stay as the hex text of the script.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Step<'a> {
    /// The script is for a system with a kernel debugger attached that
    /// says "go" at every breakpoint. The step reports whether one is.
    Debugger,
    /// Load a test driver from a file.
    Load {
        service: &'a str,
        file: &'a str,
    },
    /// A driver that ships in Windows: there it is already running.
    Use {
        service: &'a str,
    },
    Unload {
        service: &'a str,
    },
    Open {
        handle: &'a str,
        path: &'a str,
    },
    Close {
        handle: &'a str,
    },
    Ioctl {
        handle: &'a str,
        code: u32,
        input: Hex<'a>,
        output_len: usize,
    },
    Read {
        handle: &'a str,
        len: usize,
    },
    Write {
        handle: &'a str,
        data: Hex<'a>,
    },
}

/// Bytes written as hex digits, or `-` for none.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Hex<'a>(&'a str);

impl<'a> Hex<'a> {
    fn parse(text: &'a str) -> Result<Self, &'static str> {
        if text == "-" {
            return Ok(Hex(""));
        }
        if text.len() % 2 != 0 || !text.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Err("bytes must be an even number of hex digits, or -");
        }
        Ok(Hex(text))
    }

    /// Number of bytes.
    pub fn len(&self) -> usize {
        self.0.len() / 2
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    pub fn bytes(&self) -> impl Iterator<Item = u8> + 'a {
        let digit = |b: u8| match b {
            b'0'..=b'9' => b - b'0',
            b'a'..=b'f' => b - b'a' + 10,
            _ => b - b'A' + 10,
        };
        self.0
            .as_bytes()
            .as_chunks::<2>()
            .0
            .iter()
            .map(move |pair| digit(pair[0]) << 4 | digit(pair[1]))
    }
}

/// Parse one line of a script. `Ok(None)` for a blank line or a comment.
pub fn parse_line(line: &str) -> Result<Option<Step<'_>>, &'static str> {
    let line = line.trim();
    if line.is_empty() || line.starts_with('#') {
        return Ok(None);
    }
    let mut words = line.split_ascii_whitespace();
    let mut next = || words.next().ok_or("a field is missing");
    let number = |text: &str| {
        text.parse::<usize>()
            .map_err(|_| "a length is not a number")
    };
    let step = match next()? {
        "debugger" => Step::Debugger,
        "load" => Step::Load {
            service: next()?,
            file: next()?,
        },
        "use" => Step::Use { service: next()? },
        "unload" => Step::Unload { service: next()? },
        "open" => Step::Open {
            handle: next()?,
            path: next()?,
        },
        "close" => Step::Close { handle: next()? },
        "ioctl" => Step::Ioctl {
            handle: next()?,
            code: u32::from_str_radix(next()?, 16).map_err(|_| "a control code is not hex")?,
            input: Hex::parse(next()?)?,
            output_len: number(next()?)?,
        },
        "read" => Step::Read {
            handle: next()?,
            len: number(next()?)?,
        },
        "write" => Step::Write {
            handle: next()?,
            data: Hex::parse(next()?)?,
        },
        _ => return Err("unknown step"),
    };
    if words.next().is_some() {
        return Err("too many fields");
    }
    Ok(Some(step))
}

/// A script's steps, in order, stopping at the first line that does not
/// parse.
pub fn steps(script: &str) -> impl Iterator<Item = Result<Step<'_>, &'static str>> {
    script
        .lines()
        .filter_map(|line| parse_line(line).transpose())
}

/// The step as a transcript repeats it: its fields, single-spaced.
impl fmt::Display for Step<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {
            Step::Debugger => write!(f, "debugger"),
            Step::Load { service, .. } => write!(f, "load {service}"),
            Step::Use { service } => write!(f, "use {service}"),
            Step::Unload { service } => write!(f, "unload {service}"),
            Step::Open { handle, path } => write!(f, "open {handle} {path}"),
            Step::Close { handle } => write!(f, "close {handle}"),
            Step::Ioctl {
                handle,
                code,
                input,
                output_len,
            } => write!(f, "ioctl {handle} {code:08x} {input} {output_len}"),
            Step::Read { handle, len } => write!(f, "read {handle} {len}"),
            Step::Write { handle, data } => write!(f, "write {handle} {data}"),
        }
    }
}

impl fmt::Display for Hex<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(if self.0.is_empty() { "-" } else { self.0 })
    }
}

/// A status and byte count as a transcript shows them: the count only
/// when the status is not an error, because Windows reports none for a
/// failed request.
pub struct Outcome {
    pub status: u32,
    pub information: usize,
}

impl fmt::Display for Outcome {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:08x} ", self.status)?;
        if self.status >= 0xC000_0000 {
            f.write_str("-")
        } else {
            write!(f, "{}", self.information)
        }
    }
}

/// A buffer as a transcript shows it: lower-case hex, or `-` if empty.
pub struct Dump<'a>(pub &'a [u8]);

impl fmt::Display for Dump<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.0.is_empty() {
            return f.write_str("-");
        }
        self.0.iter().try_for_each(|b| write!(f, "{b:02x}"))
    }
}

/// How NK's transcript departed from the one Windows produced.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mismatch<'a> {
    /// Line `number` (from 1) differs; `windows` is what Windows printed.
    Differs { number: usize, windows: &'a str },
    /// NK printed a line where the Windows transcript had already ended.
    WindowsEnded,
    /// The script finished but the Windows transcript has more: `next`,
    /// or nothing at all where its closing `end` should be.
    WindowsContinues { next: Option<&'a str> },
}

/// How Windows stopped at a step: the bugcheck code and its first
/// parameter, 32 bits of each.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Stop {
    pub code: u32,
    pub parameter: u32,
}

/// Compares NK's transcript with the recorded one, a line at a time.
pub struct Checker<'a> {
    /// What is left of the recorded transcript.
    rest: &'a str,
    matched: usize,
}

impl<'a> Checker<'a> {
    pub fn new(windows: &'a str) -> Self {
        Self {
            rest: windows,
            matched: 0,
        }
    }

    /// The next recorded line, skipping the header and blank lines.
    fn next(&mut self) -> Option<&'a str> {
        while !self.rest.is_empty() {
            let (line, rest) = self.rest.split_once('\n').unwrap_or((self.rest, ""));
            self.rest = rest;
            let line = line.trim();
            if !line.is_empty() && !line.starts_with('#') {
                return Some(line);
            }
        }
        None
    }

    /// Whether Windows stopped (bugchecked) at the step about to be
    /// run, which a transcript line names `step`: if so, the bugcheck
    /// code and its first parameter. Such a line is the transcript's
    /// last; nothing is consumed.
    pub fn stops_at(&self, step: &str) -> Option<Stop> {
        let mut ahead = Checker {
            rest: self.rest,
            matched: self.matched,
        };
        let line = ahead.next()?;
        let outcome = line.strip_prefix(step)?.strip_prefix(": stopped ")?;
        let (code, parameter) = outcome.split_once(' ')?;
        Some(Stop {
            code: u32::from_str_radix(code, 16).ok()?,
            parameter: u32::from_str_radix(parameter, 16).ok()?,
        })
    }

    /// NK printed `line` for the next step: is it what Windows printed?
    pub fn line(&mut self, line: &str) -> Result<(), Mismatch<'a>> {
        match self.next() {
            // `end` closes the transcript; no step prints it.
            Some("end") | None => Err(Mismatch::WindowsEnded),
            Some(windows) if windows == line => {
                self.matched += 1;
                Ok(())
            }
            Some(windows) => Err(Mismatch::Differs {
                number: self.matched + 1,
                windows,
            }),
        }
    }

    /// The script is over: the recorded transcript must be too. Returns
    /// how many lines matched.
    pub fn finish(mut self) -> Result<usize, Mismatch<'a>> {
        match self.next() {
            Some("end") => Ok(self.matched),
            next => Err(Mismatch::WindowsContinues { next }),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn one(line: &str) -> Step<'_> {
        parse_line(line).expect("parses").expect("a step")
    }

    #[test]
    fn every_step_parses_and_echoes() {
        for (line, echo) in [
            ("debugger", "debugger"),
            ("load sioctl sioctl.sys", "load sioctl"),
            ("use null", "use null"),
            ("unload sioctl", "unload sioctl"),
            (
                "open dos \\DosDevices\\IoctlTest",
                "open dos \\DosDevices\\IoctlTest",
            ),
            ("close dos", "close dos"),
            (
                "ioctl dos 9c402408 68656c 100",
                "ioctl dos 9c402408 68656c 100",
            ),
            ("ioctl n 00150800 - 0", "ioctl n 00150800 - 0"),
            ("read n 64", "read n 64"),
            ("write n -", "write n -"),
            ("  write   n \t 78  ", "write n 78"),
        ] {
            assert_eq!(format!("{}", one(line)), echo, "{line:?}");
        }
    }

    #[test]
    fn fields() {
        let Step::Ioctl {
            handle,
            code,
            input,
            output_len,
        } = one("ioctl dos 9C402408 00ff7A 16")
        else {
            panic!("not an ioctl");
        };
        assert_eq!((handle, code, output_len), ("dos", 0x9C40_2408, 16));
        assert_eq!(input.bytes().collect::<Vec<u8>>(), [0x00, 0xFF, 0x7A]);
        assert_eq!((input.len(), input.is_empty()), (3, false));
        let Step::Write { data, .. } = one("write n -") else {
            panic!("not a write");
        };
        assert!(data.is_empty() && data.bytes().next().is_none());
    }

    #[test]
    fn blank_lines_and_comments_are_not_steps() {
        for line in ["", "   ", "# a comment", "  # indented"] {
            assert_eq!(parse_line(line), Ok(None), "{line:?}");
        }
        let script = "# header\n\nuse null\n  # note\nclose n\n";
        let all: Vec<_> = steps(script).collect();
        assert_eq!(
            all,
            [
                Ok(Step::Use { service: "null" }),
                Ok(Step::Close { handle: "n" })
            ]
        );
    }

    #[test]
    fn bad_lines_are_errors() {
        for line in [
            "frobnicate x",
            "open dos",
            "ioctl dos 9c402408 6865",
            "ioctl dos zz 68 4",
            "ioctl dos 9c402408 686 4",
            "ioctl dos 9c402408 6g 4",
            "read n many",
            "close n extra",
            "write n",
        ] {
            assert!(parse_line(line).is_err(), "{line:?} should not parse");
        }
    }

    #[test]
    fn results_are_spelled_as_windows_spells_them() {
        let show = |status, information| {
            format!(
                "{}",
                Outcome {
                    status,
                    information
                }
            )
        };
        assert_eq!(show(0, 38), "00000000 38");
        assert_eq!(show(0x8000_0005, 4), "80000005 4", "a warning has a count");
        assert_eq!(show(0xC000_0010, 0), "c0000010 -", "an error has none");
        assert_eq!(show(0xC000_0000, 7), "c0000000 -");
        assert_eq!(format!("{}", Dump(&[0x54, 0xEE, 0x00])), "54ee00");
        assert_eq!(format!("{}", Dump(&[])), "-");
    }

    const RECORDED: &str = "# Recorded on Windows\n# script sha256 abc\nuse null: ok\n\nread n 4: c0000011 - eeeeeeee\nend\n";

    #[test]
    fn a_matching_transcript_passes() {
        let mut c = Checker::new(RECORDED);
        assert_eq!(c.line("use null: ok"), Ok(()));
        assert_eq!(c.line("read n 4: c0000011 - eeeeeeee"), Ok(()));
        assert_eq!(c.finish(), Ok(2));
    }

    #[test]
    fn the_first_differing_line_is_named() {
        let mut c = Checker::new(RECORDED);
        c.line("use null: ok").unwrap();
        assert_eq!(
            c.line("read n 4: c0000011 - 00000000"),
            Err(Mismatch::Differs {
                number: 2,
                windows: "read n 4: c0000011 - eeeeeeee"
            })
        );
        let mut c = Checker::new(RECORDED);
        assert!(matches!(
            c.line("use null: failed"),
            Err(Mismatch::Differs { number: 1, .. })
        ));
    }

    #[test]
    fn a_transcript_of_the_wrong_length_fails() {
        // NK does more than Windows did.
        let mut c = Checker::new(RECORDED);
        c.line("use null: ok").unwrap();
        c.line("read n 4: c0000011 - eeeeeeee").unwrap();
        assert_eq!(c.line("close n: 00000000"), Err(Mismatch::WindowsEnded));
        // NK does less.
        let mut c = Checker::new(RECORDED);
        c.line("use null: ok").unwrap();
        assert_eq!(
            c.finish(),
            Err(Mismatch::WindowsContinues {
                next: Some("read n 4: c0000011 - eeeeeeee")
            })
        );
        // A recorded transcript cut short of its `end`.
        let mut c = Checker::new("use null: ok\n");
        c.line("use null: ok").unwrap();
        assert_eq!(c.finish(), Err(Mismatch::WindowsContinues { next: None }));
        assert_eq!(
            Checker::new("").line("use null: ok"),
            Err(Mismatch::WindowsEnded)
        );
        // A step can never match the closing marker.
        assert_eq!(
            Checker::new("end\n").line("end"),
            Err(Mismatch::WindowsEnded)
        );
    }

    #[test]
    fn a_transcript_may_end_with_windows_stopping() {
        let windows =
            "# header\nopen d \\Device\\X: 00000000\nload event: stopped 0000007e 80000003\n";
        let mut checker = Checker::new(windows);
        assert_eq!(
            checker.stops_at("open d \\Device\\X"),
            None,
            "that step completed"
        );
        assert_eq!(
            checker.stops_at("load event"),
            None,
            "not the next step yet"
        );
        checker.line("open d \\Device\\X: 00000000").unwrap();
        assert_eq!(
            checker.stops_at("load event"),
            Some(Stop {
                code: 0x7E,
                parameter: 0x8000_0003
            })
        );
        // Looking does not consume: asking twice gives the same answer.
        assert!(checker.stops_at("load event").is_some());
        assert_eq!(checker.stops_at("load other"), None, "another step");
        assert_eq!(checker.stops_at("load"), None, "a step is matched whole");
        // A transcript that stops has no `end`: finishing it is an error.
        assert!(matches!(
            checker.finish(),
            Err(Mismatch::WindowsContinues { next: Some(_) })
        ));
        // Malformed codes are not a stop.
        for bad in [
            "load event: stopped",
            "load event: stopped zz 1",
            "load event: stopped 7e",
        ] {
            assert_eq!(Checker::new(bad).stops_at("load event"), None, "{bad}");
        }
    }
}
