//! Formatted output, as the C runtime in the Windows kernel does it:
//! the engine behind `DbgPrint`, `_snwprintf` and their kin.
//!
//! A format is `%[flags][width][.precision][size]type`. The engine is
//! given the format's characters, a source of arguments, and a sink for
//! the characters produced; it reads nothing itself, so strings an
//! argument points to are fetched through the argument source.
//!
//! Supported, because drivers use them:
//!
//! - flags `-` `+` space `#` `0`; width and precision as digits or `*`;
//! - sizes `h` `hh` `l` `ll` `w` `I` `I32` `I64`;
//! - `d` `i` `u` `x` `X` `o` (32 bits unless the size says 64 or, with
//!   `h`, 16), `p` (a
//!   pointer: sixteen upper-case hex digits);
//! - `c` `C`, `s` `S` (a string of the format's own width, or of the
//!   other; `hs`/`ws`/`ls` say which outright), `Z` (`ANSI_STRING`),
//!   `wZ` (`UNICODE_STRING`); `%%`.
//!
//! Floating point is not: the kernel's own does not format it either.

/// Where a format's arguments come from, and how what they point to is
/// read.
pub trait Arguments {
    /// The next argument, as the 64 bits it was passed in.
    fn next(&mut self) -> u64;
    /// The characters of the NUL-terminated narrow string at `address`,
    /// at most `limit` of them.
    fn narrow(&mut self, address: u64, limit: usize, out: &mut dyn FnMut(u16));
    /// The same for a wide string.
    fn wide(&mut self, address: u64, limit: usize, out: &mut dyn FnMut(u16));
    /// The buffer address and length in characters of the counted
    /// string (`ANSI_STRING`, or `UNICODE_STRING` if `wide`) at
    /// `address`.
    fn counted(&mut self, address: u64, wide: bool) -> (u64, usize);
}

/// Where produced characters go.
type Sink<'a> = &'a mut dyn FnMut(u16);

#[derive(Default, Clone, Copy)]
struct Spec {
    left: bool,
    plus: bool,
    space: bool,
    alternate: bool,
    zero: bool,
    width: usize,
    precision: Option<usize>,
    /// 64-bit integer; or a wide (`Some(true)`) or narrow string.
    long: bool,
    wide: Option<bool>,
}

/// Pad `body` (given as a way to emit it, and its length) to the width.
fn padded(spec: &Spec, len: usize, out: &mut dyn FnMut(u16), body: &mut dyn FnMut(Sink<'_>)) {
    let pad = spec.width.saturating_sub(len);
    if !spec.left {
        (0..pad).for_each(|_| out(u16::from(b' ')));
    }
    body(out);
    if spec.left {
        (0..pad).for_each(|_| out(u16::from(b' ')));
    }
}

/// A number: sign or prefix, zeros up to the precision (or the width,
/// with the `0` flag), then the digits.
fn number(
    spec: &Spec,
    value: u64,
    negative: bool,
    radix: u64,
    upper: bool,
    out: &mut dyn FnMut(u16),
) {
    let mut digits = [0u8; 22];
    let mut n = 0;
    let mut rest = value;
    while rest != 0 {
        let d = (rest % radix) as u8;
        digits[n] = match d {
            0..=9 => b'0' + d,
            _ if upper => b'A' + d - 10,
            _ => b'a' + d - 10,
        };
        n += 1;
        rest /= radix;
    }
    // Zero prints as "0" unless the precision is zero.
    if n == 0 && spec.precision != Some(0) {
        digits[0] = b'0';
        n = 1;
    }
    let mut prefix = [0u8; 2];
    let mut p = 0;
    if negative {
        prefix[0] = b'-';
        p = 1;
    } else if radix == 10 && spec.plus {
        prefix[0] = b'+';
        p = 1;
    } else if radix == 10 && spec.space {
        prefix[0] = b' ';
        p = 1;
    } else if spec.alternate && radix == 16 && value != 0 {
        prefix = [b'0', if upper { b'X' } else { b'x' }];
        p = 2;
    } else if spec.alternate && radix == 8 && value != 0 {
        prefix[0] = b'0';
        p = 1;
    }
    let zeros = match spec.precision {
        Some(precision) => precision.saturating_sub(n),
        None if spec.zero && !spec.left => spec.width.saturating_sub(n + p),
        None => 0,
    };
    padded(spec, p + zeros + n, out, &mut |out| {
        prefix[..p].iter().for_each(|&c| out(u16::from(c)));
        (0..zeros).for_each(|_| out(u16::from(b'0')));
        digits[..n].iter().rev().for_each(|&c| out(u16::from(c)));
    });
}

/// A string argument: counted first, so that it can be padded.
fn string(
    spec: &Spec,
    args: &mut dyn Arguments,
    address: u64,
    wide: bool,
    limit: usize,
    out: &mut dyn FnMut(u16),
) {
    if address == 0 {
        let null = b"(null)";
        let shown = spec.precision.map_or(null.len(), |p| p.min(null.len()));
        return padded(spec, shown, out, &mut |out| {
            null[..shown].iter().for_each(|&c| out(u16::from(c)));
        });
    }
    let limit = spec.precision.map_or(limit, |p| p.min(limit));
    let mut len = 0;
    if wide {
        args.wide(address, limit, &mut |_| len += 1);
    } else {
        args.narrow(address, limit, &mut |_| len += 1);
    }
    padded(spec, len, out, &mut |out| {
        if wide {
            args.wide(address, limit, out);
        } else {
            args.narrow(address, limit, out);
        }
    });
}

/// A width or precision at `pending`: digits, or `*` for "the next
/// argument". None if there is neither.
fn count(
    pending: &mut Option<u16>,
    format: &mut dyn Iterator<Item = u16>,
    args: &mut dyn Arguments,
) -> Option<i64> {
    if *pending == Some(u16::from(b'*')) {
        *pending = format.next();
        return Some(i64::from(args.next() as i32));
    }
    let mut value = None;
    while let Some(d) = pending
        .and_then(|c| u8::try_from(c).ok())
        .filter(u8::is_ascii_digit)
    {
        value = Some(value.unwrap_or(0i64).saturating_mul(10) + i64::from(d - b'0'));
        *pending = format.next();
    }
    value
}

/// Write `format`, with its arguments substituted, to `out`.
/// `wide_format` says whether the format itself is a wide string, which
/// decides what a bare `%s` and `%c` mean.
pub fn format(
    format: &mut dyn Iterator<Item = u16>,
    wide_format: bool,
    args: &mut dyn Arguments,
    out: &mut dyn FnMut(u16),
) {
    let is = |c: Option<u16>, ch: u8| c == Some(u16::from(ch));
    let mut pending = format.next();
    while let Some(c) = pending {
        pending = format.next();
        if c != u16::from(b'%') {
            out(c);
            continue;
        }
        let mut spec = Spec::default();
        // Flags.
        loop {
            match pending.and_then(|c| u8::try_from(c).ok()) {
                Some(b'-') => spec.left = true,
                Some(b'+') => spec.plus = true,
                Some(b' ') => spec.space = true,
                Some(b'#') => spec.alternate = true,
                Some(b'0') => spec.zero = true,
                _ => break,
            }
            pending = format.next();
        }
        // Width and precision: digits, or `*` for "the next argument".
        if let Some(width) = count(&mut pending, format, args) {
            // A negative width from `*` means left-justify.
            spec.left |= width < 0;
            spec.width = width.unsigned_abs() as usize;
        }
        if is(pending, b'.') {
            pending = format.next();
            // A negative precision from `*` means none was given.
            spec.precision = usize::try_from(count(&mut pending, format, args).unwrap_or(0)).ok();
        }
        // Size.
        loop {
            match pending.and_then(|c| u8::try_from(c).ok()) {
                Some(b'h') => spec.wide = Some(false),
                Some(b'w') => spec.wide = Some(true),
                Some(b'l') => {
                    // `l` widens a string; `ll` a number.
                    if spec.wide == Some(true) {
                        spec.long = true;
                    }
                    spec.wide = Some(true);
                }
                Some(b'I') => {
                    // `I` alone is pointer-sized; `I32`/`I64` say.
                    spec.long = true;
                    pending = format.next();
                    if is(pending, b'6') || is(pending, b'3') {
                        spec.long = is(pending, b'6');
                        // The second digit, then on.
                        let _ = format.next();
                        pending = format.next();
                    }
                    continue;
                }
                _ => break,
            }
            pending = format.next();
        }
        let Some(kind) = pending.and_then(|c| u8::try_from(c).ok()) else {
            // A format that ends inside a specification: nothing more.
            return;
        };
        pending = format.next();
        match kind {
            b'%' => out(u16::from(b'%')),
            b'd' | b'i' => {
                let raw = args.next();
                // `h` marks a short, as it marks a narrow string.
                let value = if spec.long {
                    raw as i64
                } else if spec.wide == Some(false) {
                    i64::from(raw as i16)
                } else {
                    i64::from(raw as i32)
                };
                number(&spec, value.unsigned_abs(), value < 0, 10, false, out);
            }
            b'u' | b'x' | b'X' | b'o' => {
                let raw = args.next();
                let value = if spec.long {
                    raw
                } else if spec.wide == Some(false) {
                    u64::from(raw as u16)
                } else {
                    u64::from(raw as u32)
                };
                let radix = match kind {
                    b'u' => 10,
                    b'o' => 8,
                    _ => 16,
                };
                number(&spec, value, false, radix, kind == b'X', out);
            }
            b'p' => {
                let pointer = Spec {
                    precision: Some(16),
                    ..spec
                };
                number(&pointer, args.next(), false, 16, true, out);
            }
            b'c' | b'C' => {
                let c = args.next();
                // A narrow character is one byte; a wide one, sixteen bits.
                let wide = spec.wide.unwrap_or((kind == b'c') == wide_format);
                let c = if wide { c as u16 } else { u16::from(c as u8) };
                padded(&spec, 1, out, &mut |out| out(c));
            }
            b's' | b'S' => {
                let wide = spec.wide.unwrap_or((kind == b's') == wide_format);
                let address = args.next();
                string(&spec, args, address, wide, usize::MAX, out);
            }
            b'Z' => {
                let wide = spec.wide == Some(true);
                let address = args.next();
                if address == 0 {
                    string(&spec, args, 0, wide, 0, out);
                } else {
                    let (buffer, len) = args.counted(address, wide);
                    string(&spec, args, buffer, wide, len, out);
                }
            }
            // Not a type this engine knows: Windows prints the
            // character itself.
            other => out(u16::from(other)),
        }
    }
}

/// What `_snwprintf` and `_snprintf` return for `produced` characters
/// and a buffer of `count`: the number written when they fit (with a
/// terminator only if there is room for one), -1 when they do not.
pub const fn snprintf_result(produced: usize, count: usize) -> i32 {
    if produced > count {
        -1
    } else {
        produced as i32
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Arguments from a list; "addresses" are indices into string tables.
    struct Test<'a> {
        values: core::iter::Copied<core::slice::Iter<'a, u64>>,
        narrow: &'a [&'a str],
        wide: &'a [&'a str],
    }

    impl Arguments for Test<'_> {
        fn next(&mut self) -> u64 {
            self.values
                .next()
                .expect("the format asks for an argument that was not passed")
        }
        fn narrow(&mut self, address: u64, limit: usize, out: &mut dyn FnMut(u16)) {
            self.narrow[address as usize - 1]
                .bytes()
                .take(limit)
                .for_each(|b| out(u16::from(b)));
        }
        fn wide(&mut self, address: u64, limit: usize, out: &mut dyn FnMut(u16)) {
            self.wide[address as usize - 1]
                .encode_utf16()
                .take(limit)
                .for_each(out);
        }
        fn counted(&mut self, address: u64, wide: bool) -> (u64, usize) {
            let table = if wide { self.wide } else { self.narrow };
            // Counted strings: the same tables, but only the first 3.
            (address, table[address as usize - 1].len().min(3))
        }
    }

    const NARROW: &[&str] = &["hello", "a much longer narrow string"];
    const WIDE: &[&str] = &["wide", "CancelSamp"];

    fn run(wide_format: bool, fmt: &str, values: &[u64]) -> String {
        let mut args = Test {
            values: values.iter().copied(),
            narrow: NARROW,
            wide: WIDE,
        };
        let mut out = Vec::new();
        format(&mut fmt.encode_utf16(), wide_format, &mut args, &mut |c| {
            out.push(c)
        });
        assert!(
            args.values.next().is_none(),
            "{fmt}: an argument was not used"
        );
        String::from_utf16(&out).unwrap()
    }

    fn narrow(fmt: &str, values: &[u64]) -> String {
        run(false, fmt, values)
    }

    #[test]
    fn plain_text_and_percent() {
        assert_eq!(narrow("", &[]), "");
        assert_eq!(narrow("no specifications", &[]), "no specifications");
        assert_eq!(narrow("100%% sure", &[]), "100% sure");
        assert_eq!(narrow("ends in %", &[]), "ends in ");
    }

    #[test]
    fn integers() {
        assert_eq!(narrow("%d %i", &[42, (-7i64) as u64]), "42 -7");
        // 32 bits unless told otherwise: the upper half is not looked at.
        assert_eq!(narrow("%d", &[0xFFFF_FFFF_0000_0005]), "5");
        assert_eq!(narrow("%d", &[0xFFFF_FFFF]), "-1");
        assert_eq!(narrow("%u", &[0xFFFF_FFFF]), "4294967295");
        assert_eq!(narrow("%x %X %o", &[0xBEEF, 0xBEEF, 8]), "beef BEEF 10");
        assert_eq!(narrow("%lu %lx", &[7, 0xAB]), "7 ab");
        assert_eq!(
            narrow("%I64d %I64u", &[(-5i64) as u64, u64::MAX]),
            "-5 18446744073709551615"
        );
        assert_eq!(
            narrow("%llx %Ix %I32x", &[1 << 40, 1 << 40, 1 << 40]),
            "10000000000 10000000000 0"
        );
        assert_eq!(narrow("%d", &[0]), "0");
        assert_eq!(narrow("[%.0d]", &[0]), "[]");
    }

    #[test]
    fn a_short_integer_is_sixteen_bits_of_its_argument() {
        // A short is promoted to an int on the way in; `h` takes it
        // back to the sixteen bits that were passed.
        assert_eq!(
            narrow("%hx %hu %ho", &[0xFFFF_FFFF, 0xFFFF_FFFF, 0x1_0008]),
            "ffff 65535 10"
        );
        assert_eq!(narrow("%hd %hi", &[0xFFFF_FFFF, 0x1_8000]), "-1 -32768");
        assert_eq!(narrow("%hd", &[0x1_0005]), "5");
        // It still marks a string or character as narrow.
        assert_eq!(run(true, "%hs%hc", &[1, 0x1241]), "helloA");
    }

    #[test]
    fn width_flags_and_precision() {
        assert_eq!(
            narrow("[%5d][%-5d][%05d]", &[42, 42, 42]),
            "[   42][42   ][00042]"
        );
        assert_eq!(
            narrow("[%+d][% d][%+d]", &[5, 5, (-5i64) as u64]),
            "[+5][ 5][-5]"
        );
        assert_eq!(narrow("[%05d]", &[(-42i64) as u64]), "[-0042]");
        assert_eq!(narrow("[%.3d][%8.3d]", &[7, 7]), "[007][     007]");
        assert_eq!(
            narrow("[%#x][%#X][%#o][%#x]", &[255, 255, 8, 0]),
            "[0xff][0XFF][010][0]"
        );
        assert_eq!(narrow("[%#06x]", &[255]), "[0x00ff]");
        assert_eq!(
            narrow("[%*d][%-*d][%.*d]", &[4, 7, 4, 7, 3, 7]),
            "[   7][7   ][007]"
        );
        // A negative width from an argument left-justifies.
        assert_eq!(narrow("[%*d]", &[(-4i64) as u64, 7]), "[7   ]");
        // Left-justified ignores the zero flag.
        assert_eq!(narrow("[%-05d]", &[42]), "[42   ]");
    }

    #[test]
    fn pointers_are_sixteen_upper_case_digits() {
        assert_eq!(
            narrow("DeviceObject %p\n", &[0xFFFF_F880_0013_8040]),
            "DeviceObject FFFFF88000138040\n"
        );
        assert_eq!(narrow("%p", &[0]), "0000000000000000");
    }

    #[test]
    fn the_guid_format_of_the_device_security_library() {
        let guid = "{%08X-%04X-%04X-%02X%02X-%02X%02X%02X%02X%02X%02X}";
        let parts = [
            0x4D36_E96C,
            0xE325,
            0x11CE,
            0xBF,
            0xC1,
            0x08,
            0x00,
            0x2B,
            0xE1,
            0x03,
            0x18,
        ];
        assert_eq!(
            run(true, guid, &parts),
            "{4D36E96C-E325-11CE-BFC1-08002BE10318}"
        );
    }

    #[test]
    fn strings_follow_the_formats_width_unless_told() {
        // In a narrow format %s is narrow and %S wide...
        assert_eq!(
            narrow("%s/%S/%ws/%ls/%hs", &[1, 1, 2, 2, 1]),
            "hello/wide/CancelSamp/CancelSamp/hello"
        );
        // ...and in a wide one the other way round.
        assert_eq!(
            run(true, "%s/%S/%hs/%ws", &[1, 1, 1, 2]),
            "wide/hello/hello/CancelSamp"
        );
        assert_eq!(
            narrow("[%8s][%-8s][%.2s][%6.2s]", &[1, 1, 1, 1]),
            "[   hello][hello   ][he][    he]"
        );
        assert_eq!(
            narrow("[%s][%.3s][%8s]", &[0, 0, 0]),
            "[(null)][(nu][  (null)]"
        );
    }

    #[test]
    fn counted_strings() {
        // The test tables give a counted string a length of 3.
        assert_eq!(narrow("%Z|%wZ|%5wZ|", &[1, 2, 2]), "hel|Can|  Can|");
        assert_eq!(narrow("%wZ", &[0]), "(null)");
    }

    #[test]
    fn characters() {
        assert_eq!(
            narrow("%c%c%C", &[u64::from(b'o'), u64::from(b'k'), 0x263A]),
            "ok\u{263A}"
        );
        // A narrow character is one byte of the argument.
        assert_eq!(narrow("%c", &[0x1234_5641]), "A");
        assert_eq!(
            run(true, "%c%wc%hc", &[0x263A, 0x263A, 0x1241]),
            "\u{263A}\u{263A}A"
        );
        assert_eq!(narrow("[%3c][%-3c]", &[65, 65]), "[  A][A  ]");
    }

    #[test]
    fn what_is_not_a_specification_is_printed() {
        assert_eq!(narrow("%y %q", &[]), "y q");
    }

    #[test]
    fn the_bounded_forms_report_what_fits() {
        assert_eq!(snprintf_result(5, 10), 5);
        assert_eq!(
            snprintf_result(10, 10),
            10,
            "fits exactly, with no room for a terminator"
        );
        assert_eq!(snprintf_result(11, 10), -1);
        assert_eq!(snprintf_result(0, 0), 0);
    }
}
