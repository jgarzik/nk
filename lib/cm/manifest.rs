//! Registry content as text: the manifest format of nk-fixtures'
//! `hive/system.hive.txt`, whose header comment defines it.
//!
//! [`parse`] turns the text into a list of [`Op`]: make a key, set a
//! value of the key made last. [`apply`] carries the list out on a
//! tree. What the format's reference reader (nk-fixtures'
//! `scripts/hive.py`) refuses is refused here, so that a file read
//! here can be handed to it: a key or a value named twice, a class on
//! a key whose subkeys came first. Two things differ. A text that
//! names no key is accepted, and is no operations; and a control
//! character anywhere in a line is refused, a carriage return
//! included.

use crate::{Error, Hive, KeyId, components, same};
use alloc::vec::Vec;
use core::fmt;

/// One step of building what a manifest describes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Op {
    /// Make the key `path`, and the keys above it, where they are not
    /// there; give it `class`, UTF-16 without a terminator, if there
    /// is one. `path` is relative: components separated by `\`.
    Key {
        path: Vec<u16>,
        class: Option<Vec<u8>>,
    },
    /// Give the key of the nearest `Key` before this a value, in place
    /// of one of the same name.
    Value {
        name: Vec<u16>,
        kind: u32,
        data: Vec<u8>,
    },
}

/// Why a manifest was refused, and at which line, counted from 1.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ManifestError {
    pub line: u32,
    pub what: &'static str,
}

impl fmt::Display for ManifestError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "line {}: {}", self.line, self.what)
    }
}

/// The longest name of a key, and of a value, in characters: Windows'
/// limits.
const MAX_KEY_NAME: usize = 255;
const MAX_VALUE_NAME: usize = 16383;
/// The most keys one `keys` line makes, and the most bytes `counter:`
/// data has: the reference reader's limits.
const MAX_KEYS: u64 = 10000;
const MAX_COUNTER: u64 = 1 << 20;

const NO_MEMORY: &str = "no memory";
const BACKSLASH: u16 = b'\\' as u16;

/// How a type's data are written, when not as raw data.
#[derive(Clone, Copy)]
enum Form {
    /// Only as raw data.
    Raw,
    /// One string, stored with its terminator.
    String,
    /// Strings, each stored with its terminator, and one terminator
    /// more.
    Strings,
    /// One number in so many bytes, the most significant first or last.
    Number { bytes: usize, big_endian: bool },
}

/// The types: name, `REG_*` number, form.
const TYPES: &[(&str, u32, Form)] = &[
    ("none", 0, Form::Raw),
    ("sz", 1, Form::String),
    ("expand_sz", 2, Form::String),
    ("binary", 3, Form::Raw),
    (
        "dword",
        4,
        Form::Number {
            bytes: 4,
            big_endian: false,
        },
    ),
    (
        "dword_be",
        5,
        Form::Number {
            bytes: 4,
            big_endian: true,
        },
    ),
    ("multi_sz", 7, Form::Strings),
    ("resource_list", 8, Form::Raw),
    ("full_resource_descriptor", 9, Form::Raw),
    ("resource_requirements_list", 10, Form::Raw),
    (
        "qword",
        11,
        Form::Number {
            bytes: 8,
            big_endian: false,
        },
    ),
];

type Field = Vec<u16>;

fn push<T>(list: &mut Vec<T>, item: T) -> Result<(), &'static str> {
    list.try_reserve(1).map_err(|_| NO_MEMORY)?;
    list.push(item);
    Ok(())
}

fn append<T>(
    list: &mut Vec<T>,
    items: impl ExactSizeIterator<Item = T>,
) -> Result<(), &'static str> {
    list.try_reserve(items.len()).map_err(|_| NO_MEMORY)?;
    list.extend(items);
    Ok(())
}

/// `field` is the ASCII word `word`.
fn is(field: &[u16], word: &str) -> bool {
    field.iter().copied().eq(word.bytes().map(u16::from))
}

/// What follows `prefix` in `field`, if it starts with it.
fn after<'a>(field: &'a [u16], prefix: &str) -> Option<&'a [u16]> {
    let (start, rest) = field.split_at_checked(prefix.len())?;
    is(start, prefix).then_some(rest)
}

/// The value of a hexadecimal digit.
fn hex_digit(unit: u16) -> Option<u8> {
    char::from_u32(u32::from(unit))?
        .to_digit(16)
        .map(|digit| digit as u8)
}

/// A number: decimal, or hexadecimal after `0x`.
fn number(field: &[u16]) -> Option<u64> {
    let (digits, radix) = match after(field, "0x").or_else(|| after(field, "0X")) {
        Some(digits) => (digits, 16),
        None => (field, 10),
    };
    // 010 is not ten, and nobody's eight either.
    if digits.is_empty() || (radix == 10 && digits.len() > 1 && digits[0] == u16::from(b'0')) {
        return None;
    }
    digits.iter().try_fold(0u64, |sum, &unit| {
        let digit = char::from_u32(u32::from(unit))?.to_digit(radix)?;
        sum.checked_mul(u64::from(radix))?
            .checked_add(u64::from(digit))
    })
}

/// The quoted string whose opening quote is before `line[at]`: a JSON
/// string. Returns it and where the text after its closing quote
/// starts.
fn quoted(line: &[u8], mut at: usize) -> Result<(Field, usize), &'static str> {
    const UNTERMINATED: &str = "a quoted string does not end";
    let mut text = Vec::new();
    loop {
        let byte = *line.get(at).ok_or(UNTERMINATED)?;
        at += 1;
        let unit = match byte {
            b'"' => break,
            b'\\' => {
                let escape = *line.get(at).ok_or(UNTERMINATED)?;
                at += 1;
                match escape {
                    b'"' | b'\\' | b'/' => u16::from(escape),
                    b'b' => 8,
                    b'f' => 12,
                    b'n' => 10,
                    b'r' => 13,
                    b't' => 9,
                    b'u' => {
                        let digits = line.get(at..at + 4).ok_or("\\u takes four hex digits")?;
                        at += 4;
                        digits.iter().try_fold(0u16, |sum, &digit| {
                            let digit =
                                hex_digit(u16::from(digit)).ok_or("\\u takes four hex digits")?;
                            Ok::<u16, &'static str>(sum << 4 | u16::from(digit))
                        })?
                    }
                    _ => return Err("an unknown escape in a quoted string"),
                }
            }
            _ => u16::from(byte),
        };
        push(&mut text, unit)?;
    }
    if char::decode_utf16(text.iter().copied()).any(|unit| unit.is_err()) {
        return Err("a string holds half of a surrogate pair");
    }
    Ok((text, at))
}

/// The fields of a line: bare words, and strings in quotes.
fn fields(line: &[u8]) -> Result<Vec<Field>, &'static str> {
    let mut out = Vec::new();
    let mut at = 0;
    while let Some(&byte) = line.get(at) {
        if byte == b' ' {
            at += 1;
        } else if byte == b'"' {
            let (text, end) = quoted(line, at + 1)?;
            if line.get(end).is_some_and(|&next| next != b' ') {
                return Err("a quoted string must be followed by a space");
            }
            push(&mut out, text)?;
            at = end;
        } else {
            let len = line[at..]
                .iter()
                .position(|&byte| byte == b' ')
                .unwrap_or(line.len() - at);
            let word = &line[at..at + len];
            if word.contains(&b'"') {
                return Err("a quote inside a bare word");
            }
            let mut text = Vec::new();
            append(&mut text, word.iter().map(|&byte| u16::from(byte)))?;
            push(&mut out, text)?;
            at += len;
        }
    }
    Ok(out)
}

/// Raw data, if `field` is `hex:<digits>` or `counter:<n>`.
fn raw(field: &[u16]) -> Result<Option<Vec<u8>>, &'static str> {
    let mut data = Vec::new();
    if let Some(digits) = after(field, "hex:") {
        const BAD: &str = "hex: takes pairs of hex digits";
        let (pairs, odd) = digits.as_chunks::<2>();
        if !odd.is_empty() {
            return Err(BAD);
        }
        data.try_reserve_exact(pairs.len()).map_err(|_| NO_MEMORY)?;
        for [high, low] in pairs {
            let (high, low) = hex_digit(*high).zip(hex_digit(*low)).ok_or(BAD)?;
            data.push(high << 4 | low);
        }
    } else if let Some(length) = after(field, "counter:") {
        let length = number(length)
            .filter(|&length| length <= MAX_COUNTER)
            .ok_or("counter: takes a length of at most 1 MiB")? as usize;
        data.try_reserve_exact(length).map_err(|_| NO_MEMORY)?;
        data.extend((0u32..).flat_map(u32::to_le_bytes).take(length));
    } else {
        return Ok(None);
    }
    Ok(Some(data))
}

/// `strings` as UTF-16, each with its terminator, and `more`
/// terminators after the last.
fn utf16(strings: &[Field], more: usize) -> Result<Vec<u8>, &'static str> {
    let units = strings.iter().map(|s| s.len() + 1).sum::<usize>() + more;
    let mut data = Vec::new();
    data.try_reserve_exact(units * 2).map_err(|_| NO_MEMORY)?;
    for string in strings {
        data.extend(
            string
                .iter()
                .chain(&[0])
                .flat_map(|unit| unit.to_le_bytes()),
        );
    }
    data.resize(units * 2, 0);
    Ok(data)
}

/// The data of a value of the form `form`, as `fields` write them.
fn data(form: Form, fields: &[Field]) -> Result<Vec<u8>, &'static str> {
    if let [only] = fields
        && let Some(raw) = raw(only)?
    {
        return Ok(raw);
    }
    match form {
        Form::Raw => Err("this type takes hex:<digits> or counter:<length>"),
        Form::String => match fields {
            [_] => utf16(fields, 0),
            _ => Err("this type takes one string"),
        },
        Form::Strings => {
            if fields.iter().any(|string| string.is_empty()) {
                return Err("an empty string would end a multi_sz early");
            }
            utf16(fields, 1)
        }
        Form::Number { bytes, big_endian } => {
            const BAD: &str = "this type takes one number that fits it";
            let [field] = fields else { return Err(BAD) };
            let number = number(field).ok_or(BAD)?;
            if bytes < 8 && number >> (bytes * 8) != 0 {
                return Err(BAD);
            }
            let mut data = Vec::new();
            data.try_reserve_exact(bytes).map_err(|_| NO_MEMORY)?;
            data.extend_from_slice(&number.to_le_bytes()[..bytes]);
            if big_endian {
                data.reverse();
            }
            Ok(data)
        }
    }
}

/// Refuse a path that is not names separated by single backslashes.
fn check_path(path: &[u16]) -> Result<(), &'static str> {
    for name in path.split(|&unit| unit == BACKSLASH) {
        if name.is_empty() {
            return Err("a key path has an empty component");
        }
        if name.len() > MAX_KEY_NAME {
            return Err("a key name is longer than 255 characters");
        }
    }
    Ok(())
}

/// `key` lies below the key `above`.
fn below(key: &[u16], above: &[u16]) -> bool {
    key.split_at_checked(above.len())
        .is_some_and(|(start, rest)| rest.first() == Some(&BACKSLASH) && same(start, above))
}

/// The keys `ops` make, by path.
fn paths(ops: &[Op]) -> impl Iterator<Item = &[u16]> {
    ops.iter().filter_map(|op| match op {
        Op::Key { path, .. } => Some(&path[..]),
        Op::Value { .. } => None,
    })
}

/// What one line adds to `ops`. `current` says whether a value may
/// follow: the line before it that was no value was a `key` line.
fn line(text: &[u8], ops: &mut Vec<Op>, current: &mut bool) -> Result<(), &'static str> {
    if !text.is_ascii() {
        return Err("not ASCII: write other characters as \\uXXXX in quotes");
    }
    if text.iter().any(u8::is_ascii_control) {
        return Err("a control character");
    }
    let Some(first) = text.iter().position(|&byte| byte != b' ') else {
        return Ok(());
    };
    if text[first] == b'#' {
        return Ok(());
    }
    let mut fields = fields(text)?;
    let (what, args) = fields.split_first_mut().ok_or("an empty line kind")?;
    if is(what, "key") {
        const EXPECTED: &str = "expected: key <path> [class <string>]";
        let (path, class) = match args {
            [path] => (path, None),
            [path, word, class] if is(word, "class") => (path, Some(class)),
            _ => return Err(EXPECTED),
        };
        check_path(path)?;
        if paths(ops).any(|old| same(old, path)) {
            return Err("the key is already there");
        }
        let class = match class {
            Some(class) => {
                if paths(ops).any(|old| below(old, path)) {
                    return Err("a key with a class must come before the keys under it");
                }
                let mut bytes = Vec::new();
                bytes
                    .try_reserve_exact(class.len() * 2)
                    .map_err(|_| NO_MEMORY)?;
                bytes.extend(class.iter().flat_map(|unit| unit.to_le_bytes()));
                Some(bytes)
            }
            None => None,
        };
        let path = core::mem::take(path);
        push(ops, Op::Key { path, class })?;
        *current = true;
    } else if is(what, "keys") {
        const EXPECTED: &str = "expected: keys <path-prefix> <count, 1 to 10000>";
        let [prefix, count] = args else {
            return Err(EXPECTED);
        };
        let count = number(count)
            .filter(|count| (1..=MAX_KEYS).contains(count))
            .ok_or(EXPECTED)?;
        let before = ops.len();
        for index in 0..count {
            let mut path = Vec::new();
            path.try_reserve_exact(prefix.len() + 4)
                .map_err(|_| NO_MEMORY)?;
            path.extend_from_slice(prefix);
            path.extend(
                [1000, 100, 10, 1]
                    .iter()
                    .map(|place| u16::from(b'0') + (index / place % 10) as u16),
            );
            check_path(&path)?;
            // The keys of this line differ from one another as they
            // are numbered.
            if paths(&ops[..before]).any(|old| same(old, &path)) {
                return Err("the key is already there");
            }
            push(ops, Op::Key { path, class: None })?;
        }
        *current = false;
    } else if is(what, "value") {
        if !*current {
            return Err("a value needs a key line before it");
        }
        let [name, kind, written @ ..] = args else {
            return Err("expected: value <name> <type> <data...>");
        };
        let &(_, kind, form) = TYPES
            .iter()
            .find(|(word, ..)| is(kind, word))
            .ok_or("unknown type")?;
        if name.len() > MAX_VALUE_NAME {
            return Err("value name too long");
        }
        // The values of the key so far: what follows the last `key`.
        let twice = ops.iter().rev().map_while(|op| match op {
            Op::Value { name, .. } => Some(name),
            Op::Key { .. } => None,
        });
        if twice.into_iter().any(|old| same(old, name)) {
            return Err("the value is already there");
        }
        let data = data(form, written)?;
        let name = core::mem::take(name);
        push(ops, Op::Value { name, kind, data })?;
    } else {
        return Err("unknown line kind");
    }
    Ok(())
}

/// The operations the manifest `text` describes, in its order. The
/// first operation, if there is any, is an [`Op::Key`].
pub fn parse(text: &[u8]) -> Result<Vec<Op>, ManifestError> {
    let mut ops = Vec::new();
    let mut current = false;
    for (number, text) in text.split(|&byte| byte == b'\n').enumerate() {
        line(text, &mut ops, &mut current).map_err(|what| ManifestError {
            line: number as u32 + 1,
            what,
        })?;
    }
    Ok(ops)
}

/// Carry out `ops` on `hive`, paths starting from `under`: lay a
/// manifest over what is there.
///
/// Keys that exist stay, with their subkeys and values; a value takes
/// the place of one of the same name, and a class the place of the
/// key's class. Names are compared as the registry compares them,
/// without regard to case; a key that is there keeps its spelling. A
/// symbolic link is a key like any other, as it is in a hive file: it
/// is not followed. Every key made or changed, and every key a key is
/// made under, has `time` as its last write time.
///
/// A value before any key is a value of `under`. On an error the
/// operations carried out so far remain.
pub fn apply(hive: &mut Hive, under: KeyId, ops: &[Op], time: u64) -> Result<(), Error> {
    let mut current = under;
    for op in ops {
        match op {
            Op::Key { path, class } => {
                current = under;
                for name in components(path) {
                    let above = hive.live(current)?;
                    current = match hive.child(above, name) {
                        Some(child) => KeyId(child),
                        None => {
                            let new = KeyId(hive.add_child(above, name)?);
                            hive.set_last_write(new, time)?;
                            hive.set_last_write(KeyId(above), time)?;
                            new
                        }
                    };
                }
                if let Some(class) = class {
                    hive.set_class(current, class)?;
                    hive.set_last_write(current, time)?;
                }
            }
            Op::Value { name, kind, data } => {
                hive.set_value(current, name, *kind, data)?;
                hive.set_last_write(current, time)?;
            }
        }
    }
    Ok(())
}
