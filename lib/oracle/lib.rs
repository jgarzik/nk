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
    /// Put a file where an importer loaded afterwards finds the library
    /// it imports from; it is taken away again when the script ends.
    Install {
        file: &'a str,
    },
    /// A driver that is part of the system: started if it is stopped,
    /// and then stopped again when the script ends.
    Use {
        service: &'a str,
    },
    Unload {
        service: &'a str,
    },
    Open {
        handle: &'a str,
        path: &'a str,
        args: OpenArgs<'a>,
    },
    /// Create an instance of a named pipe: its server end.
    Pipe {
        handle: &'a str,
        path: &'a str,
        args: PipeArgs<'a>,
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
    /// Device control where a buffer may be an address of the script's
    /// choosing instead of memory the replayer provides.
    IoctlAt {
        handle: &'a str,
        code: u32,
        input: Input<'a>,
        output: Output<'a>,
    },
    Fsctl {
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

/// `GENERIC_READ | GENERIC_WRITE | SYNCHRONIZE`.
const READ_WRITE: u32 = 0xC010_0000;
/// `FILE_SYNCHRONOUS_IO_NONALERT`.
const SYNCHRONOUS: u32 = 0x20;
/// `FILE_NON_DIRECTORY_FILE`.
const NON_DIRECTORY: u32 = 0x40;

/// The `key=value` fields of `text`, each handed to `set`.
fn options<'a>(
    text: &'a str,
    mut set: impl FnMut(&'a str, &'a str) -> Result<(), &'static str>,
) -> Result<(), &'static str> {
    text.split_ascii_whitespace().try_for_each(|word| {
        let (key, value) = word.split_once('=').ok_or("an option is not key=value")?;
        set(key, value)
    })
}

fn hex32(text: &str) -> Result<u32, &'static str> {
    u32::from_str_radix(text, 16).map_err(|_| "an option's value is not hex")
}

fn decimal32(text: &str) -> Result<u32, &'static str> {
    text.parse()
        .map_err(|_| "an option's value is not a number")
}

/// Writes `text`'s fields, each after one space.
fn spaced(f: &mut fmt::Formatter<'_>, text: &str) -> fmt::Result {
    text.split_ascii_whitespace()
        .try_for_each(|word| write!(f, " {word}"))
}

/// How an `open` step opens: what its options say, over the defaults.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OpenArgs<'a> {
    /// The options as the script wrote them.
    text: &'a str,
    /// The handle the path is relative to, if it is.
    pub root: Option<&'a str>,
    pub access: u32,
    pub share: u32,
    pub options: u32,
}

impl<'a> OpenArgs<'a> {
    fn parse(text: &'a str) -> Result<Self, &'static str> {
        let mut args = Self {
            text,
            root: None,
            access: READ_WRITE,
            share: 0,
            options: SYNCHRONOUS | NON_DIRECTORY,
        };
        options(text, |key, value| {
            match key {
                "root" => args.root = Some(value),
                "access" => args.access = hex32(value)?,
                "share" => args.share = hex32(value)?,
                "options" => args.options = hex32(value)?,
                _ => return Err("unknown option"),
            }
            Ok(())
        })?;
        Ok(args)
    }
}

/// What a `pipe` step asks of `NtCreateNamedPipeFile`: what its options
/// say, over the defaults.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PipeArgs<'a> {
    /// The options as the script wrote them.
    text: &'a str,
    pub access: u32,
    pub share: u32,
    pub disposition: u32,
    pub options: u32,
    /// `NamedPipeType`: 0 a byte stream, 1 messages.
    pub kind: u32,
    /// `ReadMode`: 0 bytes, 1 messages.
    pub read: u32,
    /// `CompletionMode`: 0 a request waits, 1 it does not.
    pub completion: u32,
    pub instances: u32,
    pub inquota: u32,
    pub outquota: u32,
    /// The default timeout, in milliseconds.
    pub timeout: u32,
}

impl<'a> PipeArgs<'a> {
    fn parse(text: &'a str) -> Result<Self, &'static str> {
        let mut args = Self {
            text,
            access: READ_WRITE,
            // FILE_SHARE_READ | FILE_SHARE_WRITE: both directions.
            share: 3,
            // FILE_OPEN_IF
            disposition: 3,
            options: SYNCHRONOUS,
            kind: 0,
            read: 0,
            completion: 0,
            instances: 1,
            inquota: 4096,
            outquota: 4096,
            timeout: 50,
        };
        options(text, |key, value| {
            match key {
                "access" => args.access = hex32(value)?,
                "share" => args.share = hex32(value)?,
                "disposition" => args.disposition = decimal32(value)?,
                "options" => args.options = hex32(value)?,
                "type" => args.kind = decimal32(value)?,
                "read" => args.read = decimal32(value)?,
                "completion" => args.completion = decimal32(value)?,
                "instances" => args.instances = decimal32(value)?,
                "inquota" => args.inquota = decimal32(value)?,
                "outquota" => args.outquota = decimal32(value)?,
                "timeout" => args.timeout = decimal32(value)?,
                _ => return Err("unknown option"),
            }
            Ok(())
        })?;
        Ok(args)
    }
}

/// A buffer at an address the script chose: `@<address>:<length>`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct At<'a> {
    /// As the script wrote it.
    text: &'a str,
    pub address: u64,
    pub len: usize,
}

impl<'a> At<'a> {
    /// `None` if `text` does not begin with `@`.
    fn parse(text: &'a str) -> Option<Result<Self, &'static str>> {
        let fields = text.strip_prefix('@')?;
        let parse = || {
            let (address, len) = fields.split_once(':')?;
            Some(At {
                text,
                address: u64::from_str_radix(address, 16).ok()?,
                len: len.parse().ok()?,
            })
        };
        Some(parse().ok_or("a buffer at an address is @<hex address>:<length>"))
    }
}

/// The input buffer of an `ioctlat` step.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Input<'a> {
    /// Memory the replayer provides, holding these bytes.
    Bytes(Hex<'a>),
    At(At<'a>),
}

/// The output buffer of an `ioctlat` step.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Output<'a> {
    /// Memory the replayer provides, of this length.
    Len(usize),
    At(At<'a>),
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
    // What follows the field `word` on the line.
    let after = |word: &str| &line[word.as_ptr() as usize - line.as_ptr() as usize + word.len()..];
    let code = |text: &str| u32::from_str_radix(text, 16).map_err(|_| "a control code is not hex");
    let step = match next()? {
        "debugger" => Step::Debugger,
        "load" => Step::Load {
            service: next()?,
            file: next()?,
        },
        "install" => Step::Install { file: next()? },
        "use" => Step::Use { service: next()? },
        "unload" => Step::Unload { service: next()? },
        // These two end with any number of options.
        "open" => {
            let (handle, path) = (next()?, next()?);
            let args = OpenArgs::parse(after(path))?;
            return Ok(Some(Step::Open { handle, path, args }));
        }
        "pipe" => {
            let (handle, path) = (next()?, next()?);
            let args = PipeArgs::parse(after(path))?;
            return Ok(Some(Step::Pipe { handle, path, args }));
        }
        "close" => Step::Close { handle: next()? },
        "ioctl" => Step::Ioctl {
            handle: next()?,
            code: code(next()?)?,
            input: Hex::parse(next()?)?,
            output_len: number(next()?)?,
        },
        "ioctlat" => Step::IoctlAt {
            handle: next()?,
            code: code(next()?)?,
            input: {
                let text = next()?;
                match At::parse(text) {
                    Some(at) => Input::At(at?),
                    None => Input::Bytes(Hex::parse(text)?),
                }
            },
            output: {
                let text = next()?;
                match At::parse(text) {
                    Some(at) => Output::At(at?),
                    None => Output::Len(number(text)?),
                }
            },
        },
        "fsctl" => Step::Fsctl {
            handle: next()?,
            code: code(next()?)?,
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
            Step::Install { file } => write!(f, "install {file}"),
            Step::Use { service } => write!(f, "use {service}"),
            Step::Unload { service } => write!(f, "unload {service}"),
            Step::Open { handle, path, args } => {
                write!(f, "open {handle} {path}")?;
                spaced(f, args.text)
            }
            Step::Pipe { handle, path, args } => {
                write!(f, "pipe {handle} {path}")?;
                spaced(f, args.text)
            }
            Step::Close { handle } => write!(f, "close {handle}"),
            Step::Ioctl {
                handle,
                code,
                input,
                output_len,
            } => write!(f, "ioctl {handle} {code:08x} {input} {output_len}"),
            Step::IoctlAt {
                handle,
                code,
                input,
                output,
            } => {
                write!(f, "ioctlat {handle} {code:08x} ")?;
                match input {
                    Input::Bytes(bytes) => write!(f, "{bytes} "),
                    Input::At(at) => write!(f, "{} ", at.text),
                }?;
                match output {
                    Output::Len(len) => write!(f, "{len}"),
                    Output::At(at) => f.write_str(at.text),
                }
            }
            Step::Fsctl {
                handle,
                code,
                input,
                output_len,
            } => write!(f, "fsctl {handle} {code:08x} {input} {output_len}"),
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
            ("install nkc-lib.sys", "install nkc-lib.sys"),
            (
                "open root \\Device\\NamedPipe\\  options=20   access=80100000",
                "open root \\Device\\NamedPipe\\ options=20 access=80100000",
            ),
            ("open c nk-test root=root", "open c nk-test root=root"),
            (
                "pipe s \\Device\\NamedPipe\\nk-test",
                "pipe s \\Device\\NamedPipe\\nk-test",
            ),
            (
                "pipe s \\Device\\NamedPipe\\nk-test type=1  read=1",
                "pipe s \\Device\\NamedPipe\\nk-test type=1 read=1",
            ),
            (
                "ioctlat dos 9c40240f @0:16 38",
                "ioctlat dos 9c40240f @0:16 38",
            ),
            (
                "ioctlat dos 9c40240f 6869 @ffff800000000000:38",
                "ioctlat dos 9c40240f 6869 @ffff800000000000:38",
            ),
            ("ioctlat dos 9c40240f - 0", "ioctlat dos 9c40240f - 0"),
            ("fsctl s 00110008 - 0", "fsctl s 00110008 - 0"),
            ("fsctl s 0011400c 6869 16", "fsctl s 0011400c 6869 16"),
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
    fn an_open_without_options_has_the_defaults() {
        let Step::Open { handle, path, args } = one("open n \\Device\\Null ") else {
            panic!("not an open");
        };
        assert_eq!((handle, path), ("n", "\\Device\\Null"));
        assert_eq!(
            (args.root, args.access, args.share, args.options),
            (None, 0xC010_0000, 0, 0x60)
        );
        // The handle and the path may be the same text.
        let Step::Open { args, .. } = one("open a a root=a access=80 share=3 options=21") else {
            panic!("not an open");
        };
        assert_eq!(
            (args.root, args.access, args.share, args.options),
            (Some("a"), 0x80, 3, 0x21)
        );
    }

    #[test]
    fn pipe_options_override_the_defaults() {
        let Step::Pipe { handle, path, args } = one("pipe s \\Device\\NamedPipe\\x") else {
            panic!("not a pipe");
        };
        assert_eq!((handle, path), ("s", "\\Device\\NamedPipe\\x"));
        assert_eq!(
            (args.access, args.share, args.disposition, args.options),
            (0xC010_0000, 3, 3, 0x20)
        );
        assert_eq!((args.kind, args.read, args.completion), (0, 0, 0));
        assert_eq!(
            (args.instances, args.inquota, args.outquota, args.timeout),
            (1, 4096, 4096, 50)
        );
        let Step::Pipe { args, .. } = one(
            "pipe s p access=80100000 share=1 disposition=2 options=0 type=1 read=1 \
             completion=1 instances=4294967295 inquota=0 outquota=512 timeout=1000",
        ) else {
            panic!("not a pipe");
        };
        assert_eq!(
            (args.access, args.share, args.disposition, args.options),
            (0x8010_0000, 1, 2, 0)
        );
        assert_eq!((args.kind, args.read, args.completion), (1, 1, 1));
        assert_eq!(
            (args.instances, args.inquota, args.outquota, args.timeout),
            (u32::MAX, 0, 512, 1000)
        );
    }

    #[test]
    fn a_buffer_is_the_replayers_or_at_an_address() {
        let Step::IoctlAt { input, output, .. } =
            one("ioctlat d 9c40240f @FFFF800000000000:16 @10000:38")
        else {
            panic!("not an ioctlat");
        };
        let (Input::At(input), Output::At(output)) = (input, output) else {
            panic!("not addresses");
        };
        assert_eq!((input.address, input.len), (0xFFFF_8000_0000_0000, 16));
        assert_eq!((output.address, output.len), (0x1_0000, 38));
        let Step::IoctlAt { input, output, .. } = one("ioctlat d 9c40240f 6869 38") else {
            panic!("not an ioctlat");
        };
        let Input::Bytes(bytes) = input else {
            panic!("not bytes");
        };
        assert_eq!(bytes.bytes().collect::<Vec<u8>>(), b"hi");
        assert_eq!(output, Output::Len(38));
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
            "install",
            "install a.sys b.sys",
            "open n",
            "open n \\Device\\Null extra",
            "open n \\Device\\Null colour=1",
            "open n \\Device\\Null access=xyz",
            "open n \\Device\\Null share=",
            "open n \\Device\\Null options=100000000",
            "pipe s",
            "pipe s p extra",
            "pipe s p root=r",
            "pipe s p access=g",
            "pipe s p share=g",
            "pipe s p options=g",
            "pipe s p disposition=x",
            "pipe s p type=byte",
            "pipe s p read=-1",
            "pipe s p completion=",
            "pipe s p instances=many",
            "pipe s p inquota=1k",
            "pipe s p outquota=1k",
            "pipe s p timeout=soon",
            "ioctlat d 9c40240f @0:16",
            "ioctlat d zz @0:16 @0:16",
            "ioctlat d 9c40240f @0 16",
            "ioctlat d 9c40240f @zz:16 16",
            "ioctlat d 9c40240f @0:x 16",
            "ioctlat d 9c40240f 6 16",
            "ioctlat d 9c40240f 68 @0",
            "ioctlat d 9c40240f 68 many",
            "ioctlat d 9c40240f 68 16 extra",
            "fsctl s 00110008 -",
            "fsctl s zz - 0",
            "fsctl s 00110008 6 0",
            "fsctl s 00110008 - x",
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
