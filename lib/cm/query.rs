//! The query table of
//! [`RtlQueryRegistryValues`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-rtlqueryregistryvalues)
//! and `RtlQueryRegistryValuesEx`, worked through without touching the
//! caller's memory.
//!
//! A [`Query`] reads the registry through a [`Reader`] and says what is
//! to be done for the table, one [`Action`] at a time: call an entry's
//! routine with a value, store a value where the entry points, delete a
//! value. The kernel does each, which it alone can (the routine is a
//! driver's, the pointers are into a driver's memory), and asks for the
//! next. It has opened the key the call names and copied the table out
//! of the caller's memory.
//!
//! Between two actions everything the query holds is in the [`Query`]:
//! a routine that never returns, because it raised an exception, leaves
//! nothing behind that dropping the `Query` does not free.

use alloc::vec::Vec;

/// `RTL_QUERY_REGISTRY_SUBKEY`: the name is a subkey, which the
/// entries that follow are about.
pub const SUBKEY: u32 = 0x01;
/// `RTL_QUERY_REGISTRY_TOPKEY`: back to the key the call names.
pub const TOPKEY: u32 = 0x02;
/// `RTL_QUERY_REGISTRY_REQUIRED`: the value must be there.
pub const REQUIRED: u32 = 0x04;
/// `RTL_QUERY_REGISTRY_NOVALUE`: an entry without a name wants one call
/// with no value, not a call for every value.
pub const NOVALUE: u32 = 0x08;
/// `RTL_QUERY_REGISTRY_NOEXPAND`: strings are delivered as stored.
pub const NOEXPAND: u32 = 0x10;
/// `RTL_QUERY_REGISTRY_DIRECT`: the value is stored where the entry
/// points; there is no routine.
pub const DIRECT: u32 = 0x20;
/// `RTL_QUERY_REGISTRY_DELETE`: the value is deleted once delivered.
pub const DELETE: u32 = 0x40;
/// `RTL_QUERY_REGISTRY_TYPECHECK`: a value stored directly must have
/// the type in the top byte of the entry's default type.
pub const TYPECHECK: u32 = 0x100;
/// `RTL_QUERY_REGISTRY_TYPECHECK_SHIFT`.
pub const TYPECHECK_SHIFT: u32 = 24;
/// The status a [`Query`] does not take for a failure when delivering
/// a value answers it: a routine's own, or the kernel's for a place too
/// small to store in.
pub const STATUS_BUFFER_TOO_SMALL: i32 = 0xC000_0023_u32 as i32;

const REG_NONE: u32 = 0;
const REG_SZ: u32 = 1;
const REG_EXPAND_SZ: u32 = 2;
const REG_MULTI_SZ: u32 = 7;

/// One `RTL_QUERY_REGISTRY_TABLE` entry, copied from the caller.
#[derive(Debug, Clone, Copy)]
pub struct Entry<'a> {
    /// Whether it has a `QueryRoutine`.
    pub routine: bool,
    pub flags: u32,
    /// `Name`, if it is not null, without its terminator.
    pub name: Option<&'a [u16]>,
    pub default_type: u32,
    /// The `DefaultLength` bytes at `DefaultData`; where the length is
    /// zero and the type a string's, the string with its terminators.
    pub default_data: &'a [u8],
}

/// The caller's table, as the kernel copied it: whatever keeps the
/// copy hands out its entries by number.
pub trait Table {
    /// Entry `index`; `None` past the last the caller's memory held.
    fn entry(&self, index: usize) -> Option<Entry<'_>>;
}

impl Table for [Entry<'_>] {
    fn entry(&self, index: usize) -> Option<Entry<'_>> {
        self.get(index).copied()
    }
}

/// What the kernel is to do for a table entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Action<'a> {
    /// Call the routine of entry `entry`. `name` is `None` for the call
    /// that carries no value.
    Call {
        entry: usize,
        name: Option<&'a [u16]>,
        kind: u32,
        data: &'a [u8],
    },
    /// Store a string in the `UNICODE_STRING` that is `slot` such
    /// structures past where entry `entry` points: the characters of
    /// `text` ([`string_to_store`]) and a terminator, in the buffer the
    /// structure names or, if it names none, in a new one.
    StoreString {
        entry: usize,
        slot: usize,
        text: &'a [u8],
    },
    /// Copy up to four bytes of data to where entry `entry` points.
    StoreSmall { entry: usize, data: &'a [u8] },
    /// Store longer data in the buffer entry `entry` points to, which
    /// starts with its own size ([`buffer_data_offset`]).
    StoreBuffer {
        entry: usize,
        kind: u32,
        data: &'a [u8],
    },
    /// Delete value `name` of the top key or of its subkey `subkey`.
    Delete {
        subkey: Option<&'a [u16]>,
        name: &'a [u16],
    },
}

/// Why a query stopped.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QueryError {
    /// An entry's flags and members do not go together, or a
    /// `REG_EXPAND_SZ` was to be expanded (`STATUS_INVALID_PARAMETER`).
    InvalidParameter,
    /// A subkey or a required value is not there
    /// (`STATUS_OBJECT_NAME_NOT_FOUND`).
    NotFound,
    /// A value stored directly has another type than the entry expects
    /// (`STATUS_OBJECT_TYPE_MISMATCH`).
    TypeMismatch,
    /// No memory for a value's name (`STATUS_INSUFFICIENT_RESOURCES`).
    NoMemory,
    /// Reading the registry, or doing an action, failed with this
    /// status.
    Failed(i32),
}

/// A value: its type and data.
pub type Value = (u32, Vec<u8>);

/// The registry as a [`Query`] reads it. Keys are named from the key
/// the call is about, the top key: `None` is that key, `Some` its
/// subkey of that path.
pub trait Reader {
    /// Whether the top key has the subkey `subkey`.
    fn has_key(&mut self, subkey: &[u16]) -> Result<bool, i32>;
    /// A value by name; `None` if the key has none of that name.
    fn value(&mut self, subkey: Option<&[u16]>, name: &[u16]) -> Result<Option<Value>, i32>;
    /// A value by index, with its name; `None` past the last.
    fn value_at(
        &mut self,
        subkey: Option<&[u16]>,
        index: usize,
    ) -> Result<Option<(Vec<u16>, Value)>, i32>;
}

/// Where the data of an [`Action::StoreBuffer`] go in the caller's
/// buffer, whose first 32 bits are `declared`: its size, negated if
/// only the data are wanted. Otherwise the data follow their length
/// and type, 32 bits each. `None` if the buffer is too small
/// (`STATUS_BUFFER_TOO_SMALL`): nothing is stored.
pub fn buffer_data_offset(declared: i32, len: usize) -> Option<usize> {
    let header = if declared < 0 { 0 } else { 8 };
    (declared.unsigned_abs() as usize >= header + len).then_some(header)
}

/// The characters of an [`Action::StoreString`]'s text: whole 16-bit
/// units, without the terminator the text ends with if it ends with
/// one (a string a driver stored may not). Their length is the
/// `UNICODE_STRING`'s `Length`; its buffer holds them and a terminator.
pub fn string_to_store(text: &[u8]) -> &[u8] {
    let whole = &text[..text.len() & !1];
    whole.strip_suffix(&[0, 0]).unwrap_or(whole)
}

/// The length of the string a `REG_MULTI_SZ` starts with, terminator
/// included; `None` at the empty string that ends the list, and at the
/// end of the data.
fn string_len(rest: &[u8]) -> Option<usize> {
    let (units, _) = rest.as_chunks::<2>();
    let end = units
        .iter()
        .position(|&unit| unit == [0, 0])
        .map_or(rest.len(), |at| 2 * at + 2);
    (end != 0 && rest[..end] != [0, 0]).then_some(end)
}

/// How far the entry in hand has got.
#[derive(Clone, Copy)]
enum Stage {
    /// It has not been looked at.
    Entry,
    /// It wants every value of its key, and the next is to be read.
    Next,
    /// The value in hand goes out in one piece, which it has not yet.
    Whole,
    /// The value in hand is several strings: those before byte `at`
    /// are out, `slot` of them.
    Strings { at: usize, slot: usize },
    /// The value in hand is out.
    Delivered,
    /// The value in hand is out and, if `deleted`, gone from its key.
    Settled { deleted: bool },
    /// The entry is done.
    Done,
}

/// What [`Query::advance`] found to do; [`Query::action`] spells it
/// out.
#[derive(Clone, Copy)]
enum Step {
    /// Bytes `from..to` of the data in hand, for `slot`.
    Piece { from: usize, to: usize, slot: usize },
    /// The call that carries no value.
    Bare,
    /// Delete the value in hand.
    Delete,
}

/// A query table being worked through: where it has got to, and the
/// value in hand.
pub struct Query {
    /// The entry in hand.
    entry: usize,
    stage: Stage,
    /// The entry whose name is the subkey the entries are about.
    subkey: Option<usize>,
    /// For an entry that wants every value: the index of the value in
    /// hand.
    index: Option<usize>,
    /// Whether such an entry has had a value yet.
    any: bool,
    /// The value in hand: its name, the type it is delivered as, its
    /// data (unless the entry's default is delivered in its place), and
    /// whether the key has it.
    name: Vec<u16>,
    kind: u32,
    data: Vec<u8>,
    default: bool,
    found: bool,
    /// The action before this one delivered a value: called a routine
    /// or stored where an entry points.
    delivered: bool,
}

impl Default for Query {
    fn default() -> Self {
        Self::new()
    }
}

impl Query {
    /// A query at the start of its table.
    pub const fn new() -> Self {
        Self {
            entry: 0,
            stage: Stage::Entry,
            subkey: None,
            index: None,
            any: false,
            name: Vec::new(),
            kind: REG_NONE,
            data: Vec::new(),
            default: false,
            found: false,
            delivered: false,
        }
    }

    /// The next thing to do for `table`, the caller's; `None` when
    /// there is nothing more. The table ends at the first entry with
    /// neither routine nor name, or where the copy does. `done` says
    /// how the action before went: the status it failed with, or `Ok`
    /// (as before the first).
    ///
    /// Nothing is expanded. A `REG_MULTI_SZ` goes out one string at a
    /// time unless the entry says [`NOEXPAND`], and then whole, a
    /// value of the registry followed by one more terminator, which
    /// its length counts; a `REG_EXPAND_SZ`
    /// without that flag ends the query (`InvalidParameter`), value or
    /// default: the kernel of Windows 10 answers so, even given an
    /// environment that has the variable.
    ///
    /// The query stops at the first entry that fails; a value that was
    /// not delivered for want of room ([`STATUS_BUFFER_TOO_SMALL`]) is
    /// no failure, as on Windows: the table goes on. An entry with
    /// [`DIRECT`] is checked against [`TYPECHECK`] only if it sets
    /// that flag: whether a caller must set it is the kernel's rule.
    pub fn next<'a, T: Table + ?Sized, R: Reader>(
        &'a mut self,
        table: &'a T,
        reader: &mut R,
        done: Result<(), i32>,
    ) -> Result<Option<Action<'a>>, QueryError> {
        match done {
            // Windows ignores this one status from a routine, and
            // from its own storing.
            Err(STATUS_BUFFER_TOO_SMALL) if self.delivered => {}
            Err(status) => return Err(QueryError::Failed(status)),
            Ok(()) => {}
        }
        let Some(step) = self.advance(table, reader)? else {
            return Ok(None);
        };
        Ok(self.action(table, step))
    }

    /// The name of the subkey the entries are about.
    fn subkey_name<'a, T: Table + ?Sized>(&self, table: &'a T) -> Option<&'a [u16]> {
        table.entry(self.subkey?)?.name
    }

    /// Move on to the next thing to do.
    fn advance<T: Table + ?Sized, R: Reader>(
        &mut self,
        table: &T,
        reader: &mut R,
    ) -> Result<Option<Step>, QueryError> {
        self.delivered = false;
        loop {
            let Some(entry) = table.entry(self.entry) else {
                return Ok(None);
            };
            let flags = entry.flags;
            match self.stage {
                Stage::Entry => {
                    if !entry.routine && entry.name.is_none() {
                        return Ok(None);
                    }
                    // Stored directly: a value by name, and no routine.
                    if flags & DIRECT != 0
                        && (flags & SUBKEY != 0 || entry.routine || entry.name.is_none())
                    {
                        return Err(QueryError::InvalidParameter);
                    }
                    if flags & (SUBKEY | TOPKEY) != 0 {
                        self.subkey = None;
                    }
                    if flags & SUBKEY != 0 {
                        let name = entry.name.ok_or(QueryError::InvalidParameter)?;
                        if !reader.has_key(name).map_err(QueryError::Failed)? {
                            return Err(QueryError::NotFound);
                        }
                        self.subkey = Some(self.entry);
                    }
                    self.index = None;
                    match entry.name {
                        // A subkey's routine is called for each of its
                        // values.
                        Some(_) if flags & SUBKEY != 0 && !entry.routine => {
                            self.stage = Stage::Done;
                        }
                        Some(name) if flags & SUBKEY == 0 => {
                            let found = reader
                                .value(self.subkey_name(table), name)
                                .map_err(QueryError::Failed)?;
                            self.take(&entry, name, found)?;
                        }
                        None if flags & NOVALUE != 0 => {
                            self.stage = Stage::Done;
                            self.delivered = true;
                            return Ok(Some(Step::Bare));
                        }
                        _ => {
                            self.index = Some(0);
                            self.any = false;
                            self.stage = Stage::Next;
                        }
                    }
                }
                Stage::Next => {
                    let next = reader
                        .value_at(self.subkey_name(table), self.index.unwrap_or(0))
                        .map_err(QueryError::Failed)?;
                    match next {
                        Some((name, value)) => {
                            self.any = true;
                            self.take(&entry, &name, Some(value))?;
                        }
                        None if !self.any && flags & REQUIRED != 0 => {
                            return Err(QueryError::NotFound);
                        }
                        None => self.stage = Stage::Done,
                    }
                }
                Stage::Whole => {
                    self.stage = Stage::Delivered;
                    let to = self.data(&entry).len();
                    if let Some(step) = self.piece(&entry, 0, to, 0) {
                        return Ok(Some(step));
                    }
                }
                // One string at a time; stored directly, each in the
                // next `UNICODE_STRING`.
                Stage::Strings { at, slot } => match string_len(&self.data(&entry)[at..]) {
                    Some(len) => {
                        let to = at + len;
                        self.stage = Stage::Strings {
                            at: to,
                            slot: slot + 1,
                        };
                        if let Some(step) = self.piece(&entry, at, to, slot) {
                            return Ok(Some(step));
                        }
                    }
                    None => self.stage = Stage::Delivered,
                },
                Stage::Delivered => {
                    let deleted = self.found && flags & DELETE != 0;
                    self.stage = Stage::Settled { deleted };
                    if deleted {
                        return Ok(Some(Step::Delete));
                    }
                }
                Stage::Settled { deleted } => match self.index {
                    // A deleted value leaves its place to the next.
                    Some(index) => {
                        self.index = Some(index + usize::from(!deleted));
                        self.stage = Stage::Next;
                    }
                    None => self.stage = Stage::Done,
                },
                Stage::Done => {
                    self.entry += 1;
                    self.stage = Stage::Entry;
                }
            }
        }
    }

    /// Take in hand the value `found` under `name`, or the entry's
    /// default if there is none, and decide how it goes out.
    fn take(
        &mut self,
        entry: &Entry<'_>,
        name: &[u16],
        found: Option<Value>,
    ) -> Result<(), QueryError> {
        let flags = entry.flags;
        let default_type = entry.default_type & 0xFF;
        self.found = found.is_some();
        self.name.clear();
        self.name
            .try_reserve(name.len())
            .map_err(|_| QueryError::NoMemory)?;
        self.name.extend_from_slice(name);
        // A value that is empty and of the default's type counts as
        // missing.
        let kind = match found {
            Some((kind, data)) if !(data.is_empty() && kind == default_type) => {
                let expected = entry.default_type >> TYPECHECK_SHIFT;
                if flags & DIRECT != 0 && flags & TYPECHECK != 0 && kind != expected {
                    return Err(QueryError::TypeMismatch);
                }
                self.data = data;
                self.default = false;
                kind
            }
            _ if flags & REQUIRED != 0 => return Err(QueryError::NotFound),
            _ if default_type == REG_NONE => {
                self.stage = Stage::Delivered;
                return Ok(());
            }
            _ => {
                self.default = true;
                default_type
            }
        };
        self.kind = kind;
        self.stage = Stage::Whole;
        if flags & NOEXPAND != 0 {
            // Windows delivers a list of strings from the registry
            // with one terminator more than it is stored with, and
            // counts it.
            if kind == REG_MULTI_SZ && !self.default {
                self.data.try_reserve(2).map_err(|_| QueryError::NoMemory)?;
                self.data.extend([0, 0]);
            }
            return Ok(());
        }
        if kind == REG_EXPAND_SZ {
            return Err(QueryError::InvalidParameter);
        }
        if kind == REG_MULTI_SZ {
            self.kind = REG_SZ;
            self.stage = Stage::Strings { at: 0, slot: 0 };
        }
        Ok(())
    }

    /// The data in hand.
    fn data<'a>(&'a self, entry: &Entry<'a>) -> &'a [u8] {
        if self.default {
            entry.default_data
        } else {
            &self.data
        }
    }

    /// Bytes `from..to` of the data in hand as a step, if the entry
    /// wants them at all: it may have neither a routine nor a place to
    /// store.
    fn piece(&mut self, entry: &Entry<'_>, from: usize, to: usize, slot: usize) -> Option<Step> {
        self.delivered = entry.flags & DIRECT != 0 || entry.routine;
        self.delivered.then_some(Step::Piece { from, to, slot })
    }

    /// `step` as the action the kernel is to do.
    fn action<'a, T: Table + ?Sized>(&'a self, table: &'a T, step: Step) -> Option<Action<'a>> {
        let index = self.entry;
        let entry = table.entry(index)?;
        Some(match step {
            Step::Piece { from, to, slot } => {
                let data = &self.data(&entry)[from..to];
                let kind = self.kind;
                if entry.flags & DIRECT == 0 {
                    Action::Call {
                        entry: index,
                        name: Some(&self.name),
                        kind,
                        data,
                    }
                } else if matches!(kind, REG_SZ | REG_EXPAND_SZ | REG_MULTI_SZ) {
                    Action::StoreString {
                        entry: index,
                        slot,
                        text: data,
                    }
                } else if data.len() <= 4 {
                    Action::StoreSmall { entry: index, data }
                } else {
                    Action::StoreBuffer {
                        entry: index,
                        kind,
                        data,
                    }
                }
            }
            Step::Bare => Action::Call {
                entry: index,
                name: None,
                kind: REG_NONE,
                data: &[],
            },
            Step::Delete => Action::Delete {
                subkey: self.subkey_name(table),
                name: &self.name,
            },
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::writer::{w, wide};

    const REG_BINARY: u32 = 3;
    const REG_DWORD: u32 = 4;
    const STATUS_UNSUCCESSFUL: i32 = 0xC000_0001_u32 as i32;

    /// A value as a test gives it, and as the registry keeps it: name,
    /// type, data.
    type Given<'a> = (&'a str, u32, &'a [u8]);
    type Stored = (String, u32, Vec<u8>);

    /// A registry of a top key and its subkeys, which writes down what
    /// it is told to do.
    #[derive(Default)]
    struct Fake {
        /// The top key under the name ""; then subkeys.
        keys: Vec<(String, Vec<Stored>)>,
        done: Vec<String>,
        /// The status to answer the action of that number with.
        fail: Option<(usize, i32)>,
        /// The status every read fails with.
        broken: Option<i32>,
    }

    fn text(units: &[u16]) -> String {
        String::from_utf16(units).unwrap()
    }

    /// Strings read as text, with `|` for each terminator.
    fn show(kind: u32, data: &[u8]) -> String {
        if !matches!(kind, REG_SZ | REG_EXPAND_SZ | REG_MULTI_SZ) {
            return format!("{data:?}");
        }
        let units: Vec<u16> = data
            .as_chunks::<2>()
            .0
            .iter()
            .map(|&unit| u16::from_le_bytes(unit))
            .collect();
        format!("'{}'", text(&units).replace('\0', "|"))
    }

    impl Fake {
        fn new(keys: &[(&str, &[Given<'_>])]) -> Self {
            let keys = keys.iter().map(|(key, values)| {
                let values = values
                    .iter()
                    .map(|(n, k, d)| (n.to_string(), *k, d.to_vec()));
                (key.to_string(), values.collect())
            });
            Self {
                keys: keys.collect(),
                ..Self::default()
            }
        }

        fn key(&mut self, subkey: Option<&[u16]>) -> &mut Vec<Stored> {
            let name = subkey.map(text).unwrap_or_default();
            let key = self.keys.iter_mut().find(|(key, _)| *key == name);
            &mut key.expect("the query reads only keys it has seen").1
        }

        fn readable(&self) -> Result<(), i32> {
            self.broken.map_or(Ok(()), Err)
        }
    }

    impl Reader for Fake {
        fn has_key(&mut self, subkey: &[u16]) -> Result<bool, i32> {
            self.readable()?;
            Ok(self.keys.iter().any(|(key, _)| *key == text(subkey)))
        }

        fn value(&mut self, subkey: Option<&[u16]>, name: &[u16]) -> Result<Option<Value>, i32> {
            self.readable()?;
            let found = self.key(subkey).iter().find(|value| value.0 == text(name));
            Ok(found.map(|(_, kind, data)| (*kind, data.clone())))
        }

        fn value_at(
            &mut self,
            subkey: Option<&[u16]>,
            index: usize,
        ) -> Result<Option<(Vec<u16>, Value)>, i32> {
            self.readable()?;
            let found = self.key(subkey).get(index);
            Ok(found.map(|(name, kind, data)| (w(name), (*kind, data.clone()))))
        }
    }

    impl Fake {
        /// Do `action` as the kernel would, by writing it down; the
        /// status it is told to fail with.
        fn act(&mut self, action: Action<'_>) -> Result<(), i32> {
            let line = match action {
                Action::Call {
                    entry,
                    name,
                    kind,
                    data,
                } => format!(
                    "call {entry} {} {kind} {}",
                    name.map_or("-".to_string(), text),
                    show(kind, data)
                ),
                Action::StoreString { entry, slot, text } => {
                    format!("string {entry}+{slot} {}", show(REG_SZ, text))
                }
                Action::StoreSmall { entry, data } => format!("small {entry} {data:?}"),
                Action::StoreBuffer { entry, kind, data } => {
                    format!("buffer {entry} {kind} {data:?}")
                }
                Action::Delete { subkey, name } => {
                    let name = text(name);
                    self.key(subkey).retain(|value| value.0 != name);
                    format!("delete {}\\{name}", subkey.map(text).unwrap_or_default())
                }
            };
            self.done.push(line);
            match self.fail {
                Some((at, status)) if at == self.done.len() => Err(status),
                _ => Ok(()),
            }
        }
    }

    /// A table entry in short: has a routine, flags, name.
    fn entry<'a>(routine: bool, flags: u32, name: Option<&'a [u16]>) -> Entry<'a> {
        Entry {
            routine,
            flags,
            name,
            default_type: REG_NONE,
            default_data: &[],
        }
    }

    /// Run a table against a registry; what was done, and how it ended.
    /// Work through `table` as the kernel does: ask for an action, do
    /// it, say how it went.
    fn query(table: &[Entry<'_>], fake: &mut Fake) -> Result<(), QueryError> {
        let mut query = Query::default();
        let mut done = Ok(());
        while let Some(action) = query.next(table, fake, done)? {
            done = fake.act(action);
        }
        Ok(())
    }

    fn run(fake: &mut Fake, table: &[Entry<'_>]) -> (Vec<String>, Result<(), QueryError>) {
        let result = query(table, fake);
        (std::mem::take(&mut fake.done), result)
    }

    fn top(values: &[Given<'_>]) -> Fake {
        Fake::new(&[("", values)])
    }

    #[test]
    fn a_named_value_goes_to_the_routine() {
        let (n, t, missing) = (w("Number"), w("Text"), w("Missing"));
        let hello = wide("hello\0");
        let mut fake = top(&[
            ("Number", REG_DWORD, &[7, 0, 0, 0]),
            ("Text", REG_SZ, &hello),
        ]);
        let table = [
            entry(true, 0, Some(&n)),
            entry(true, 0, Some(&missing)),
            entry(true, 0, Some(&t)),
            // The end of the table: what follows is not looked at.
            entry(false, 0, None),
            entry(true, REQUIRED, Some(&missing)),
        ];
        let (done, result) = run(&mut fake, &table);
        assert_eq!(result, Ok(()));
        assert_eq!(
            done,
            ["call 0 Number 4 [7, 0, 0, 0]", "call 2 Text 1 'hello|'"]
        );
        // A table may also simply end.
        let (done, result) = run(&mut fake, &table[..1]);
        assert_eq!((done.len(), result), (1, Ok(())));
        // A name without a routine or a place to store asks for
        // nothing, but is still checked.
        let (done, result) = run(&mut fake, &[entry(false, REQUIRED, Some(&n))]);
        assert_eq!((done.len(), result), (0, Ok(())));
        let (_, result) = run(&mut fake, &[entry(false, REQUIRED, Some(&missing))]);
        assert_eq!(result, Err(QueryError::NotFound));
    }

    #[test]
    fn a_missing_value_is_an_error_if_required_and_else_the_default() {
        let name = w("Missing");
        let mut fake = top(&[("Empty", REG_DWORD, &[]), ("None", REG_NONE, &[])]);
        let with_default = Entry {
            default_type: REG_DWORD,
            default_data: &[9, 0, 0, 0],
            ..entry(true, 0, Some(&name))
        };
        let (done, result) = run(&mut fake, &[with_default]);
        assert_eq!(result, Ok(()));
        assert_eq!(done, ["call 0 Missing 4 [9, 0, 0, 0]"]);
        // Required: the default does not stand in.
        let required = Entry {
            flags: REQUIRED,
            ..with_default
        };
        let after = entry(true, NOVALUE, None);
        let (done, result) = run(&mut fake, &[required, after]);
        assert_eq!((done.len(), result), (0, Err(QueryError::NotFound)));
        // An empty value of the default's type counts as missing: the
        // default is used, or the entry fails if the value is required.
        let empty = w("Empty");
        let for_empty = Entry {
            name: Some(&empty),
            ..with_default
        };
        let (done, _) = run(&mut fake, &[for_empty]);
        assert_eq!(done, ["call 0 Empty 4 [9, 0, 0, 0]"]);
        let (_, result) = run(
            &mut fake,
            &[Entry {
                flags: REQUIRED,
                ..for_empty
            }],
        );
        assert_eq!(result, Err(QueryError::NotFound));
        // Empty and of another type, it is a value.
        let other = Entry {
            default_type: REG_BINARY,
            ..for_empty
        };
        let (done, _) = run(&mut fake, &[other]);
        assert_eq!(done, ["call 0 Empty 4 []"]);
        // No default type: nothing is delivered, and that is no error.
        let none = w("None");
        let table = [entry(true, 0, Some(&name)), entry(true, 0, Some(&none))];
        let (done, result) = run(&mut fake, &table);
        assert_eq!((done.len(), result), (0, Ok(())));
        // Only the low byte of the default type is the type.
        let checked = Entry {
            default_type: REG_DWORD << TYPECHECK_SHIFT | REG_BINARY,
            default_data: &[1, 2],
            ..entry(true, 0, Some(&name))
        };
        let (done, _) = run(&mut fake, &[checked]);
        assert_eq!(done, ["call 0 Missing 3 [1, 2]"]);
    }

    #[test]
    fn several_strings_come_one_at_a_time_unless_asked_for_whole() {
        let name = w("List");
        let list = wide("one\0two\0\0three\0");
        let mut fake = top(&[
            ("List", REG_MULTI_SZ, &list),
            ("Open", REG_MULTI_SZ, &wide("a\0b")),
            ("Bare", REG_MULTI_SZ, &[0, 0]),
        ]);
        // Up to the empty string that ends the list.
        let (done, result) = run(&mut fake, &[entry(true, 0, Some(&name))]);
        assert_eq!(result, Ok(()));
        assert_eq!(done, ["call 0 List 1 'one|'", "call 0 List 1 'two|'"]);
        let (done, _) = run(&mut fake, &[entry(true, NOEXPAND, Some(&name))]);
        // Whole, it is followed by a terminator the registry does
        // not hold; a default is the caller's and goes as it is.
        assert_eq!(done, ["call 0 List 7 'one|two||three||'"]);
        let (absent, ended) = (w("Missing"), wide("d1\0\0"));
        let whole_default = Entry {
            flags: NOEXPAND,
            default_type: REG_MULTI_SZ,
            default_data: &ended,
            ..entry(true, 0, Some(&absent))
        };
        let (done, _) = run(&mut fake, &[whole_default]);
        assert_eq!(done, ["call 0 Missing 7 'd1||'"]);
        // A list that is not ended properly is read to its last byte.
        let open = w("Open");
        let (done, _) = run(&mut fake, &[entry(true, 0, Some(&open))]);
        assert_eq!(done, ["call 0 Open 1 'a|'", "call 0 Open 1 'b'"]);
        // An odd byte at the end goes with the last string.
        assert_eq!(string_len(&[b'x', 0, 0, 0, b'y']), Some(4));
        assert_eq!(string_len(b"y"), Some(1));
        assert_eq!(string_len(&[]), None);
        // An empty list is no strings at all.
        let bare = w("Bare");
        let (done, result) = run(&mut fake, &[entry(true, 0, Some(&bare))]);
        assert_eq!((done.len(), result), (0, Ok(())));
        // A default is split like a value; a routine's failure stops
        // the strings.
        let missing = w("Missing");
        let default = Entry {
            default_type: REG_MULTI_SZ,
            default_data: &wide("d1\0d2\0\0"),
            ..entry(true, 0, Some(&missing))
        };
        let (done, _) = run(&mut fake, &[default]);
        assert_eq!(done, ["call 0 Missing 1 'd1|'", "call 0 Missing 1 'd2|'"]);
        fake.fail = Some((1, STATUS_UNSUCCESSFUL));
        let (done, result) = run(&mut fake, &[default]);
        assert_eq!(done.len(), 1);
        assert_eq!(result, Err(QueryError::Failed(STATUS_UNSUCCESSFUL)));
    }

    #[test]
    fn an_expandable_string_is_delivered_only_as_stored() {
        let name = w("Path");
        let value = wide("%SystemRoot%\\x\0");
        let mut fake = top(&[("Path", REG_EXPAND_SZ, &value), ("N", REG_DWORD, &[1])]);
        // Asked for as stored, it keeps its type and its text.
        let (done, result) = run(&mut fake, &[entry(true, NOEXPAND, Some(&name))]);
        assert_eq!(result, Ok(()));
        assert_eq!(done, ["call 0 Path 2 '%SystemRoot%\\x|'"]);
        let (done, _) = run(&mut fake, &[entry(false, DIRECT | NOEXPAND, Some(&name))]);
        assert_eq!(done, ["string 0+0 '%SystemRoot%\\x|'"]);
        // To be expanded, it ends the query: by name, to a routine or
        // stored directly, and among every value of the key.
        let after = entry(true, NOVALUE, None);
        for wanting in [
            entry(true, 0, Some(&name)),
            entry(false, DIRECT, Some(&name)),
            entry(false, 0, Some(&name)),
        ] {
            let (done, result) = run(&mut fake, &[wanting, after]);
            assert_eq!((done.len(), result), (0, Err(QueryError::InvalidParameter)));
        }
        let (done, result) = run(&mut fake, &[entry(true, 0, None), after]);
        assert_eq!((done.len(), result), (0, Err(QueryError::InvalidParameter)));
        fake.keys[0].1.reverse();
        let (done, result) = run(&mut fake, &[entry(true, 0, None), after]);
        assert_eq!(result, Err(QueryError::InvalidParameter));
        assert_eq!(done, ["call 0 N 4 [1]"]);
        // So does a default of that type.
        let missing = w("Missing");
        let default = Entry {
            default_type: REG_EXPAND_SZ,
            default_data: &value,
            ..entry(true, 0, Some(&missing))
        };
        let (done, result) = run(&mut fake, &[default]);
        assert_eq!((done.len(), result), (0, Err(QueryError::InvalidParameter)));
        let as_stored = Entry {
            flags: NOEXPAND,
            ..default
        };
        let (done, _) = run(&mut fake, &[as_stored]);
        assert_eq!(done, ["call 0 Missing 2 '%SystemRoot%\\x|'"]);
    }

    #[test]
    fn an_entry_without_a_name_gets_every_value_or_one_bare_call() {
        let mut fake = top(&[("A", REG_DWORD, &[1]), ("B", REG_BINARY, &[2, 2])]);
        let (done, result) = run(&mut fake, &[entry(true, 0, None)]);
        assert_eq!(result, Ok(()));
        assert_eq!(done, ["call 0 A 4 [1]", "call 0 B 3 [2, 2]"]);
        let (done, result) = run(&mut fake, &[entry(true, NOVALUE, None)]);
        assert_eq!(result, Ok(()));
        assert_eq!(done, ["call 0 - 0 []"]);
        // A key without values: skipped, unless a value is required.
        let mut empty = top(&[]);
        let table = [entry(true, 0, None), entry(true, NOVALUE, None)];
        let (done, result) = run(&mut empty, &table);
        assert_eq!((done.len(), result), (1, Ok(())));
        let (done, result) = run(&mut empty, &[entry(true, REQUIRED, None), table[1]]);
        assert_eq!((done.len(), result), (0, Err(QueryError::NotFound)));
        // The bare call can fail the query too.
        fake.fail = Some((1, STATUS_UNSUCCESSFUL));
        let (_, result) = run(&mut fake, &[entry(true, NOVALUE, None)]);
        assert_eq!(result, Err(QueryError::Failed(STATUS_UNSUCCESSFUL)));
    }

    #[test]
    fn a_subkey_entry_moves_the_entries_after_it() {
        let (sub, other, v, gone) = (w("Sub"), w("Other\\Deep"), w("V"), w("Gone"));
        let keys: &[(&str, &[Given<'_>])] = &[
            ("", &[("V", REG_DWORD, &[0])]),
            ("Sub", &[("V", REG_DWORD, &[1]), ("W", REG_DWORD, &[2])]),
            ("Other\\Deep", &[("V", REG_DWORD, &[3])]),
        ];
        let mut fake = Fake::new(keys);
        let table = [
            entry(true, 0, Some(&v)),
            entry(false, SUBKEY, Some(&sub)),
            entry(true, 0, Some(&v)),
            // Another subkey is named from the top again.
            entry(false, SUBKEY, Some(&other)),
            entry(true, 0, Some(&v)),
            entry(true, TOPKEY, Some(&v)),
            // With a routine, a subkey entry delivers all its values.
            entry(true, SUBKEY, Some(&sub)),
            entry(true, TOPKEY | NOVALUE, None),
            entry(true, 0, Some(&v)),
        ];
        let (done, result) = run(&mut fake, &table);
        assert_eq!(result, Ok(()));
        assert_eq!(
            done,
            [
                "call 0 V 4 [0]",
                "call 2 V 4 [1]",
                "call 4 V 4 [3]",
                "call 5 V 4 [0]",
                "call 6 V 4 [1]",
                "call 6 W 4 [2]",
                "call 7 - 0 []",
                "call 8 V 4 [0]"
            ]
        );
        // A subkey that is not there ends the query.
        let table = [
            entry(false, SUBKEY, Some(&gone)),
            entry(true, NOVALUE, None),
        ];
        let (done, result) = run(&mut fake, &table);
        assert_eq!((done.len(), result), (0, Err(QueryError::NotFound)));
        // A subkey entry needs a name.
        let (_, result) = run(&mut fake, &[entry(true, SUBKEY, None)]);
        assert_eq!(result, Err(QueryError::InvalidParameter));
        // A subkey with a routine and no values, required.
        let mut bare = Fake::new(&[("", &[]), ("Sub", &[])]);
        let (_, result) = run(&mut bare, &[entry(true, SUBKEY | REQUIRED, Some(&sub))]);
        assert_eq!(result, Err(QueryError::NotFound));
    }

    #[test]
    fn a_value_is_stored_directly_by_its_type_and_size() {
        let hello = wide("hello\0");
        let list = wide("a\0b\0\0");
        let mut fake = top(&[
            ("Text", REG_SZ, &hello),
            ("List", REG_MULTI_SZ, &list),
            ("Number", REG_DWORD, &[1, 2, 3, 4]),
            ("Byte", REG_BINARY, &[9]),
            ("Blob", REG_BINARY, &[1, 2, 3, 4, 5]),
        ]);
        let names = ["Text", "List", "Number", "Byte", "Blob"].map(w);
        let table: Vec<Entry<'_>> = names
            .iter()
            .map(|name| entry(false, DIRECT, Some(name)))
            .collect();
        let (done, result) = run(&mut fake, &table);
        assert_eq!(result, Ok(()));
        assert_eq!(
            done,
            [
                "string 0+0 'hello|'",
                // Each string in the next structure...
                "string 1+0 'a|'",
                "string 1+1 'b|'",
                "small 2 [1, 2, 3, 4]",
                "small 3 [9]",
                "buffer 4 3 [1, 2, 3, 4, 5]"
            ]
        );
        // ...or the whole list in one.
        let (done, _) = run(
            &mut fake,
            &[entry(false, DIRECT | NOEXPAND, Some(&names[1]))],
        );
        assert_eq!(done, ["string 0+0 'a|b|||'"]);
        // A default is stored like a value.
        let missing = w("Missing");
        let default = Entry {
            default_type: REG_DWORD,
            default_data: &[5, 0, 0, 0],
            ..entry(false, DIRECT, Some(&missing))
        };
        let (done, _) = run(&mut fake, &[default]);
        assert_eq!(done, ["small 0 [5, 0, 0, 0]"]);
        // A failure to store ends the query; a place too small to
        // store in does not, and the entries after it are reached.
        fake.fail = Some((1, STATUS_UNSUCCESSFUL));
        let (done, result) = run(&mut fake, &table);
        assert_eq!(done.len(), 1);
        assert_eq!(result, Err(QueryError::Failed(STATUS_UNSUCCESSFUL)));
        for at in [1, 3, 4, 6] {
            fake.fail = Some((at, STATUS_BUFFER_TOO_SMALL));
            let (done, result) = run(&mut fake, &table);
            assert_eq!((done.len(), result), (6, Ok(())), "action {at}");
        }
        fake.fail = None;
        // Direct storing takes a name, no routine and no subkey.
        for wrong in [
            entry(true, DIRECT, Some(&names[0])),
            entry(true, DIRECT, None),
            entry(false, DIRECT | SUBKEY, Some(&names[0])),
        ] {
            let (done, result) = run(&mut fake, &[wrong]);
            assert_eq!((done.len(), result), (0, Err(QueryError::InvalidParameter)));
        }
    }

    #[test]
    fn a_checked_type_must_match_the_stored_value() {
        let (number, missing) = (w("Number"), w("Missing"));
        let mut fake = top(&[("Number", REG_DWORD, &[1, 0, 0, 0])]);
        let expecting = |kind: u32, flags: u32| Entry {
            default_type: kind << TYPECHECK_SHIFT,
            ..entry(false, DIRECT | flags, Some(&number))
        };
        let (done, result) = run(&mut fake, &[expecting(REG_DWORD, TYPECHECK)]);
        assert_eq!((done.len(), result), (1, Ok(())));
        let (done, result) = run(&mut fake, &[expecting(REG_SZ, TYPECHECK)]);
        assert_eq!((done.len(), result), (0, Err(QueryError::TypeMismatch)));
        // Not asked to check, the top byte means nothing.
        let (done, result) = run(&mut fake, &[expecting(REG_SZ, 0)]);
        assert_eq!((done.len(), result), (1, Ok(())));
        // A default is the caller's own and is not checked.
        let default = Entry {
            name: Some(&missing),
            default_type: REG_SZ << TYPECHECK_SHIFT | REG_DWORD,
            default_data: &[3, 0, 0, 0],
            ..expecting(REG_SZ, TYPECHECK)
        };
        let (done, result) = run(&mut fake, &[default]);
        assert_eq!(result, Ok(()));
        assert_eq!(done, ["small 0 [3, 0, 0, 0]"]);
    }

    #[test]
    fn a_delivered_value_is_deleted_if_asked() {
        let (a, missing, sub) = (w("A"), w("Missing"), w("Sub"));
        let values: &[Given<'_>] = &[
            ("A", REG_DWORD, &[1]),
            ("B", REG_DWORD, &[2]),
            ("C", REG_DWORD, &[3]),
        ];
        let mut fake = Fake::new(&[("", values), ("Sub", values)]);
        let table = [
            entry(true, DELETE, Some(&a)),
            // Nothing found, nothing deleted.
            entry(true, DELETE, Some(&missing)),
            entry(false, SUBKEY, Some(&sub)),
            entry(false, DIRECT | DELETE, Some(&a)),
        ];
        let (done, result) = run(&mut fake, &table);
        assert_eq!(result, Ok(()));
        assert_eq!(
            done,
            [
                "call 0 A 4 [1]",
                "delete \\A",
                "small 3 [1]",
                "delete Sub\\A"
            ]
        );
        // Every value of a key, each deleted after its call.
        let (done, result) = run(&mut fake, &[entry(true, DELETE, None)]);
        assert_eq!(result, Ok(()));
        assert_eq!(
            done,
            [
                "call 0 B 4 [2]",
                "delete \\B",
                "call 0 C 4 [3]",
                "delete \\C"
            ]
        );
        assert!(fake.keys[0].1.is_empty());
        // A routine that fails keeps its value; a deletion that fails
        // ends the query.
        fake.fail = Some((1, STATUS_UNSUCCESSFUL));
        let table = [entry(false, SUBKEY, Some(&sub)), entry(true, DELETE, None)];
        let (done, result) = run(&mut fake, &table);
        assert_eq!(done, ["call 1 B 4 [2]"]);
        assert_eq!(result, Err(QueryError::Failed(STATUS_UNSUCCESSFUL)));
        fake.fail = Some((2, STATUS_BUFFER_TOO_SMALL));
        let (done, result) = run(&mut fake, &table);
        assert_eq!(done.len(), 2);
        assert_eq!(result, Err(QueryError::Failed(STATUS_BUFFER_TOO_SMALL)));
    }

    #[test]
    fn a_routine_that_fails_ends_the_query_but_for_one_status() {
        let (a, b) = (w("A"), w("B"));
        let mut fake = top(&[("A", REG_DWORD, &[1]), ("B", REG_DWORD, &[2])]);
        let table = [entry(true, 0, Some(&a)), entry(true, 0, Some(&b))];
        fake.fail = Some((1, STATUS_UNSUCCESSFUL));
        let (done, result) = run(&mut fake, &table);
        assert_eq!(done.len(), 1);
        assert_eq!(result, Err(QueryError::Failed(STATUS_UNSUCCESSFUL)));
        // "Buffer too small" from a routine is not taken for a failure.
        fake.fail = Some((1, STATUS_BUFFER_TOO_SMALL));
        let (done, result) = run(&mut fake, &table);
        assert_eq!((done.len(), result), (2, Ok(())));
        // A registry that cannot be read fails every kind of entry.
        fake.fail = None;
        fake.broken = Some(STATUS_UNSUCCESSFUL);
        for one in [
            table[0],
            entry(true, 0, None),
            entry(false, SUBKEY, Some(&a)),
        ] {
            let (done, result) = run(&mut fake, &[one]);
            assert_eq!(done.len(), 0);
            assert_eq!(result, Err(QueryError::Failed(STATUS_UNSUCCESSFUL)));
        }
    }

    #[test]
    fn a_stored_string_is_its_characters_without_the_terminator() {
        assert_eq!(string_to_store(&wide("nk\0")), wide("nk"));
        // Several strings stored as one keep all terminators but the
        // last: of a list from the registry, the one that was added.
        assert_eq!(string_to_store(&wide("a\0bc\0\0")), wide("a\0bc\0"));
        assert_eq!(string_to_store(&wide("a\0bc\0\0\0")), wide("a\0bc\0\0"));
        // A string a driver stored without a terminator, or with half
        // a character at its end, loses no character.
        assert_eq!(string_to_store(&wide("nk")), wide("nk"));
        assert_eq!(string_to_store(&[b'n', 0, b'k']), [b'n', 0]);
        assert_eq!(string_to_store(&[0, 0, 0]), []);
        assert_eq!(string_to_store(&[]), []);
    }

    #[test]
    fn a_table_cut_short_by_its_copy_ends_there() {
        // The kernel's copy of a table may end before any entry says
        // so; a subkey entry is found again by its number.
        let (sub, v) = (w("Sub"), w("V"));
        let keys: &[(&str, &[Given<'_>])] = &[("", &[]), ("Sub", &[("V", REG_DWORD, &[1])])];
        let mut fake = Fake::new(keys);
        let table = [
            entry(false, SUBKEY, Some(&sub)),
            entry(true, DELETE, Some(&v)),
        ];
        let (done, result) = run(&mut fake, &table);
        assert_eq!(result, Ok(()));
        assert_eq!(done, ["call 1 V 4 [1]", "delete Sub\\V"]);
        // A status left over from before the first action is a failure
        // like any other: nothing was delivered yet.
        let mut query = Query::new();
        assert_eq!(
            query.next(&table[..], &mut fake, Err(STATUS_BUFFER_TOO_SMALL)),
            Err(QueryError::Failed(STATUS_BUFFER_TOO_SMALL))
        );
    }

    #[test]
    fn a_sized_buffer_says_whether_it_wants_a_header() {
        // Negative: the data alone, if the size holds them.
        assert_eq!(buffer_data_offset(-16, 16), Some(0));
        assert_eq!(buffer_data_offset(-16, 17), None);
        assert_eq!(buffer_data_offset(i32::MIN, 5), Some(0));
        // Positive: length and type first.
        assert_eq!(buffer_data_offset(24, 16), Some(8));
        assert_eq!(buffer_data_offset(23, 16), None);
        assert_eq!(buffer_data_offset(0, 5), None);
    }
}
