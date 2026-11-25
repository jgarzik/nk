//! The registry: a tree of named keys, each holding named values.
//!
//! Pure and in memory. Names of keys and values are compared without
//! regard to case, as Windows compares them. A key is known by a
//! [`KeyId`]; the root is what Windows calls `\Registry`. A key's
//! subkeys are kept, and enumerated, in the order of their upper-cased
//! names; its values in the order they were first set.
//!
//! [`regf`] reads a hive file in place.
//!
//! Every allocation asks for exactly what it needs, so that
//! [`Hive::storage`] can say how much pool the tree holds.

#![cfg_attr(not(test), no_std)]

extern crate alloc;

use alloc::vec::Vec;
use core::cmp::Ordering;

mod info;
pub mod regf;
#[cfg(test)]
mod regf_tests;
#[cfg(test)]
mod writer;

pub use info::{
    KEY_BASIC_HEADER, KEY_FULL_HEADER, KEY_NAME_HEADER, KEY_NODE_HEADER, KeyInfo, NO_CLASS,
    VALUE_BASIC_HEADER, key_basic_information, key_full_information, key_name_information,
    key_node_information, value_basic_information,
};

/// A key in a hive.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KeyId(usize);

impl KeyId {
    /// The number to keep in a key object.
    pub const fn index(self) -> usize {
        self.0
    }

    /// The key a number from [`KeyId::index`] stands for.
    pub const fn from_index(index: usize) -> Self {
        Self(index)
    }
}

/// Why a request failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    /// No such key (`STATUS_OBJECT_NAME_NOT_FOUND`).
    NotFound,
    /// No memory for the change; nothing was changed.
    NoMemory,
    /// The key has been deleted (`STATUS_KEY_DELETED`).
    Deleted,
    /// The key has subkeys and so cannot be deleted
    /// (`STATUS_CANNOT_DELETE`).
    HasSubkeys,
}

struct Value {
    name: Vec<u16>,
    kind: u32,
    data: Vec<u8>,
}

struct Key {
    name: Vec<u16>,
    parent: usize,
    /// Its subkeys, in the order of their upper-cased names.
    children: Vec<usize>,
    values: Vec<Value>,
    /// The class it was given: bytes, UTF-16 by convention.
    class: Vec<u8>,
    /// Its security descriptor, self-relative; empty if it has none.
    security: Vec<u8>,
    /// When it was last written, as a `FILETIME`.
    last_write: u64,
    /// It is a symbolic link to another key.
    link: bool,
    /// How many handles are open to it.
    open: u32,
    /// Deleted: gone from its parent, empty, and refusing every
    /// request. Its place in the table is reused once no handle is
    /// open to it.
    deleted: bool,
}

/// A registry.
pub struct Hive {
    /// Key 0 is the root, once there is one.
    keys: Vec<Key>,
}

/// The name of the root, as paths spell it.
const ROOT: &[u16] = &[0x52, 0x45, 0x47, 0x49, 0x53, 0x54, 0x52, 0x59];

fn same(a: &[u16], b: &[u16]) -> bool {
    a.len() == b.len()
        && a.iter()
            .zip(b)
            .all(|(&x, &y)| nk_rtl::upcase(x) == nk_rtl::upcase(y))
}

/// The order Windows keeps and enumerates subkeys in: by upper-cased
/// name, a name before any longer one it starts.
fn order(a: &[u16], b: &[u16]) -> Ordering {
    let upper = |&c: &u16| nk_rtl::upcase(c);
    a.iter().map(upper).cmp(b.iter().map(upper))
}

/// The parts of a path between backslashes.
fn components(path: &[u16]) -> impl Iterator<Item = &[u16]> {
    path.split(|&c| c == u16::from(b'\\'))
        .filter(|part| !part.is_empty())
}

/// A copy of `items` in a vector of exactly their size.
fn exact<T: Copy>(items: &[T]) -> Result<Vec<T>, Error> {
    let mut copy = Vec::new();
    copy.try_reserve_exact(items.len())
        .map_err(|_| Error::NoMemory)?;
    copy.extend_from_slice(items);
    Ok(copy)
}

/// What an absolute path names below the root: `\Registry\Machine\X`
/// gives `Machine\X`. `None` if the path does not start at the root.
pub fn below_root(path: &[u16]) -> Option<&[u16]> {
    let rest = path.strip_prefix(&[u16::from(b'\\')])?;
    let end = rest
        .iter()
        .position(|&c| c == u16::from(b'\\'))
        .unwrap_or(rest.len());
    same(&rest[..end], ROOT).then(|| &rest[end..])
}

impl Default for Hive {
    fn default() -> Self {
        Self::new()
    }
}

impl Hive {
    /// An empty registry, without even a root.
    pub const fn new() -> Self {
        Self { keys: Vec::new() }
    }

    /// The root key, made on first use.
    pub fn root(&mut self) -> Result<KeyId, Error> {
        if self.keys.is_empty() {
            self.add(ROOT, 0)?;
        }
        Ok(KeyId(0))
    }

    fn add(&mut self, name: &[u16], parent: usize) -> Result<usize, Error> {
        let key = Key {
            name: exact(name)?,
            parent,
            children: Vec::new(),
            values: Vec::new(),
            class: Vec::new(),
            security: Vec::new(),
            last_write: 0,
            link: false,
            open: 0,
            deleted: false,
        };
        // The place of a deleted key nobody has open any more, or a
        // new one.
        match self
            .keys
            .iter()
            .position(|old| old.deleted && old.open == 0)
        {
            Some(vacant) => {
                self.keys[vacant] = key;
                Ok(vacant)
            }
            None => {
                self.keys
                    .try_reserve_exact(1)
                    .map_err(|_| Error::NoMemory)?;
                self.keys.push(key);
                Ok(self.keys.len() - 1)
            }
        }
    }

    fn live(&self, key: KeyId) -> Result<usize, Error> {
        if self.keys[key.0].deleted {
            Err(Error::Deleted)
        } else {
            Ok(key.0)
        }
    }

    /// A handle has been opened to `key`.
    pub fn opened(&mut self, key: KeyId) {
        self.keys[key.0].open += 1;
    }

    /// A handle to `key` has been closed.
    pub fn closed(&mut self, key: KeyId) {
        self.keys[key.0].open -= 1;
    }

    /// Delete `key`: it leaves its parent and loses its values at once,
    /// and every later request through a handle still open to it is
    /// refused. A key with subkeys is not deleted; nor is the root.
    pub fn delete(&mut self, key: KeyId) -> Result<(), Error> {
        let index = self.live(key)?;
        if !self.keys[index].children.is_empty() || index == 0 {
            return Err(Error::HasSubkeys);
        }
        let parent = self.keys[index].parent;
        self.keys[parent].children.retain(|&child| child != index);
        self.keys[parent].children.shrink_to_fit();
        let gone = &mut self.keys[index];
        gone.deleted = true;
        gone.name = Vec::new();
        gone.values = Vec::new();
        gone.class = Vec::new();
        gone.security = Vec::new();
        Ok(())
    }

    fn child(&self, key: usize, name: &[u16]) -> Option<usize> {
        self.keys[key]
            .children
            .iter()
            .copied()
            .find(|&child| same(&self.keys[child].name, name))
    }

    /// The key `path` names, starting from `start`. An empty path names
    /// `start` itself.
    pub fn open(&self, start: KeyId, path: &[u16]) -> Result<KeyId, Error> {
        components(path)
            .try_fold(self.live(start)?, |key, name| self.child(key, name))
            .map(KeyId)
            .ok_or(Error::NotFound)
    }

    /// Open the key `path` names, creating it if it is not there. Only
    /// the last part of the path is created: the keys above it must
    /// exist. Says whether the key is new.
    pub fn create(&mut self, start: KeyId, path: &[u16]) -> Result<(KeyId, bool), Error> {
        let mut key = self.live(start)?;
        let mut parts = components(path).peekable();
        while let Some(name) = parts.next() {
            key = match self.child(key, name) {
                Some(child) => child,
                None if parts.peek().is_some() => return Err(Error::NotFound),
                None => {
                    // Room in the parent first, so that a failure
                    // leaves no key behind that nothing leads to.
                    self.keys[key]
                        .children
                        .try_reserve_exact(1)
                        .map_err(|_| Error::NoMemory)?;
                    let new = self.add(name, key)?;
                    let at = self.keys[key]
                        .children
                        .partition_point(|&child| order(&self.keys[child].name, name).is_lt());
                    self.keys[key].children.insert(at, new);
                    return Ok((KeyId(new), true));
                }
            };
        }
        Ok((KeyId(key), false))
    }

    /// Give `key` a value, replacing one of the same name.
    pub fn set_value(
        &mut self,
        key: KeyId,
        name: &[u16],
        kind: u32,
        data: &[u8],
    ) -> Result<(), Error> {
        let index = self.live(key)?;
        let data = exact(data)?;
        let values = &mut self.keys[index].values;
        if let Some(value) = values.iter_mut().find(|value| same(&value.name, name)) {
            value.kind = kind;
            value.data = data;
            return Ok(());
        }
        let name = exact(name)?;
        values.try_reserve_exact(1).map_err(|_| Error::NoMemory)?;
        values.push(Value { name, kind, data });
        Ok(())
    }

    /// A value of `key`: its name as it was set, its type and data.
    /// `NotFound` if it has no such value.
    pub fn value(&self, key: KeyId, name: &[u16]) -> Result<(&[u16], u32, &[u8]), Error> {
        self.keys[self.live(key)?]
            .values
            .iter()
            .find(|value| same(&value.name, name))
            .map(|value| (&value.name[..], value.kind, &value.data[..]))
            .ok_or(Error::NotFound)
    }

    /// The memory the tree holds, as `(allocations, bytes)`.
    pub fn storage(&self) -> (usize, usize) {
        let mut total = (0, 0);
        let mut count = |capacity: usize, each: usize| {
            total.0 += usize::from(capacity != 0);
            total.1 += capacity * each;
        };
        count(self.keys.capacity(), size_of::<Key>());
        for key in &self.keys {
            count(key.name.capacity(), 2);
            count(key.children.capacity(), size_of::<usize>());
            count(key.values.capacity(), size_of::<Value>());
            count(key.class.capacity(), 1);
            count(key.security.capacity(), 1);
            for value in &key.values {
                count(value.name.capacity(), 2);
                count(value.data.capacity(), 1);
            }
        }
        total
    }
}

/// Size of a `KEY_VALUE_PARTIAL_INFORMATION` before its data: title
/// index, type, data length.
pub const PARTIAL_HEADER: usize = 12;

/// How much of a value fitted the caller's buffer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Fit {
    /// All of it (`STATUS_SUCCESS`).
    All,
    /// The header and as much data as there was room for
    /// (`STATUS_BUFFER_OVERFLOW`).
    Part,
    /// Not even the header: nothing was written
    /// (`STATUS_BUFFER_TOO_SMALL`).
    Nothing,
}

/// Write a value as a `KEY_VALUE_PARTIAL_INFORMATION` into `out`.
/// Returns how much fitted, and the length that holds all of it.
pub fn partial_information(kind: u32, data: &[u8], out: &mut [u8]) -> (Fit, usize) {
    let needed = PARTIAL_HEADER + data.len();
    if out.len() < PARTIAL_HEADER {
        return (Fit::Nothing, needed);
    }
    out[..4].fill(0);
    out[4..8].copy_from_slice(&kind.to_le_bytes());
    out[8..12].copy_from_slice(&(data.len() as u32).to_le_bytes());
    let room = (out.len() - PARTIAL_HEADER).min(data.len());
    out[PARTIAL_HEADER..PARTIAL_HEADER + room].copy_from_slice(&data[..room]);
    (
        if room == data.len() {
            Fit::All
        } else {
            Fit::Part
        },
        needed,
    )
}

/// Size of a `KEY_VALUE_FULL_INFORMATION` before the name: title
/// index, type, data offset, data length, name length.
pub const FULL_HEADER: usize = 20;

/// The `DataOffset` of a value that has no data.
pub const NO_DATA: u32 = u32::MAX;

/// Write a value as a `KEY_VALUE_FULL_INFORMATION` into `out`: the
/// header, the name, then the data at the next multiple of eight bytes
/// (so Windows 10 x64 places it; `oracle/nkc-reg.txt`). A value with no
/// data ends with its name and gives [`NO_DATA`] as the offset.
/// Returns how much fitted, and the length that holds all of it.
pub fn full_information(name: &[u16], kind: u32, data: &[u8], out: &mut [u8]) -> (Fit, usize) {
    let name_bytes = name.len() * 2;
    let (data_offset, needed) = if data.is_empty() {
        (NO_DATA, FULL_HEADER + name_bytes)
    } else {
        let offset = (FULL_HEADER + name_bytes + 7) & !7;
        (offset as u32, offset + data.len())
    };
    if out.len() < FULL_HEADER {
        return (Fit::Nothing, needed);
    }
    let header = [0, kind, data_offset, data.len() as u32, name_bytes as u32];
    for (i, field) in header.iter().enumerate() {
        out[4 * i..4 * i + 4].copy_from_slice(&field.to_le_bytes());
    }
    let name = name.iter().flat_map(|unit| unit.to_le_bytes());
    out[FULL_HEADER..]
        .iter_mut()
        .zip(name)
        .for_each(|(to, from)| *to = from);
    if let Some(room) = out.get_mut(data_offset as usize..) {
        room.iter_mut().zip(data).for_each(|(to, &from)| *to = from);
    }
    (
        if out.len() >= needed {
            Fit::All
        } else {
            Fit::Part
        },
        needed,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn w(text: &str) -> Vec<u16> {
        text.encode_utf16().collect()
    }

    /// A hive with `\Registry\Machine\System`.
    fn hive() -> (Hive, KeyId) {
        let mut hive = Hive::new();
        let root = hive.root().unwrap();
        hive.create(root, &w("Machine")).unwrap();
        let (system, new) = hive.create(root, &w("Machine\\System")).unwrap();
        assert!(new);
        (hive, system)
    }

    #[test]
    fn absolute_paths_start_at_the_root() {
        assert_eq!(
            below_root(&w("\\Registry\\Machine\\X")),
            Some(&w("\\Machine\\X")[..])
        );
        assert_eq!(below_root(&w("\\REGISTRY")), Some(&[][..]));
        assert_eq!(below_root(&w("\\registry\\")), Some(&w("\\")[..]));
        assert_eq!(below_root(&w("\\Device\\Null")), None);
        assert_eq!(below_root(&w("\\RegistryX\\Machine")), None);
        assert_eq!(below_root(&w("Registry\\Machine")), None);
        assert_eq!(below_root(&[]), None);
    }

    #[test]
    fn keys_are_found_whatever_the_letter_case() {
        let (mut hive, system) = hive();
        let root = hive.root().unwrap();
        assert_eq!(hive.open(root, &w("MACHINE\\system")), Ok(system));
        assert_eq!(
            hive.open(root, &w("\\Machine\\System\\")),
            Ok(system),
            "stray backslashes"
        );
        assert_eq!(
            hive.open(system, &[]),
            Ok(system),
            "an empty path is the key itself"
        );
        assert_eq!(
            hive.open(root, &w("Machine\\Software")),
            Err(Error::NotFound)
        );
        assert_eq!(hive.open(root, &w("Machine\\Syste")), Err(Error::NotFound));
        assert_eq!(hive.open(system, &w("System")), Err(Error::NotFound));
        assert_eq!(Hive::default().root(), Ok(KeyId::from_index(0)));
        assert_eq!(system.index(), 2);
    }

    #[test]
    fn creating_makes_only_the_last_part() {
        let (mut hive, system) = hive();
        // Its parent is missing: refused, and nothing is made.
        assert_eq!(hive.create(system, &w("A\\B")), Err(Error::NotFound));
        assert_eq!(hive.open(system, &w("A")), Err(Error::NotFound));
        let (a, new) = hive.create(system, &w("A")).unwrap();
        assert!(new);
        let (b, new) = hive.create(system, &w("a\\B")).unwrap();
        assert!(new);
        // Created again, a key is opened.
        assert_eq!(hive.create(system, &w("A\\b")), Ok((b, false)));
        assert_eq!(hive.create(a, &[]), Ok((a, false)));
        assert_eq!(hive.open(system, &w("A\\B")), Ok(b));
        // Two keys of one name under different parents are different.
        let (other, _) = hive.create(b, &w("A")).unwrap();
        assert_ne!(other, a);
    }

    #[test]
    fn values_are_set_replaced_and_read() {
        let (mut hive, system) = hive();
        assert_eq!(hive.value(system, &w("Number")), Err(Error::NotFound));
        hive.set_value(system, &w("Number"), 4, &[0x78, 0x56, 0x34, 0x12])
            .unwrap();
        hive.set_value(system, &w("Text"), 1, &[b'n', 0, 0, 0])
            .unwrap();
        let number = w("Number");
        assert_eq!(
            hive.value(system, &w("NUMBER")),
            Ok((&number[..], 4, &[0x78, 0x56, 0x34, 0x12][..]))
        );
        assert_eq!(
            hive.value(system, &w("text")).map(|v| (v.1, v.2)),
            Ok((1, &[b'n', 0, 0, 0][..]))
        );
        // Set again under another spelling: replaced, type and all; the
        // name stays as it was first set.
        hive.set_value(system, &w("number"), 3, &[9]).unwrap();
        assert_eq!(
            hive.value(system, &w("NUMBER")),
            Ok((&number[..], 3, &[9][..]))
        );
        hive.set_value(system, &w("Empty"), 3, &[]).unwrap();
        assert_eq!(
            hive.value(system, &w("Empty")).map(|v| (v.1, v.2.len())),
            Ok((3, 0))
        );
        // Values belong to their key.
        let root = hive.root().unwrap();
        assert_eq!(hive.value(root, &w("Number")), Err(Error::NotFound));
    }

    #[test]
    fn a_deleted_key_is_gone_at_once_and_its_place_reused_when_closed() {
        let (mut hive, system) = hive();
        let (key, _) = hive.create(system, &w("Gone")).unwrap();
        let (sub, _) = hive.create(key, &w("Sub")).unwrap();
        hive.set_value(key, &w("V"), 4, &[1, 2, 3, 4]).unwrap();
        hive.opened(key);
        // Not while it has a subkey; nor the root, ever.
        assert_eq!(hive.delete(key), Err(Error::HasSubkeys));
        assert_eq!(hive.delete(sub), Ok(()));
        let before = hive.storage();
        assert_eq!(hive.delete(key), Ok(()));
        let root = hive.root().unwrap();
        assert_eq!(hive.delete(root), Err(Error::HasSubkeys));
        // Gone by name, and its memory with it...
        assert_eq!(hive.open(system, &w("Gone")), Err(Error::NotFound));
        assert!(hive.storage().1 < before.1);
        // ...and through the handle still open, everything is refused.
        assert_eq!(hive.delete(key), Err(Error::Deleted));
        assert_eq!(hive.open(key, &[]), Err(Error::Deleted));
        assert_eq!(hive.create(key, &w("New")), Err(Error::Deleted));
        assert_eq!(hive.set_value(key, &w("V"), 4, &[]), Err(Error::Deleted));
        assert_eq!(hive.value(key, &w("V")), Err(Error::Deleted));
        // A new key takes the place of the subkey, which nobody had
        // open, not of the key that is still open.
        let (again, new) = hive.create(system, &w("Gone")).unwrap();
        assert!(new);
        assert_eq!(again, sub);
        assert_eq!(hive.value(again, &w("V")), Err(Error::NotFound));
        // Closed, the deleted key's place is free too.
        hive.closed(key);
        let (next, _) = hive.create(system, &w("Next")).unwrap();
        assert_eq!(next, key);
        assert_eq!(hive.open(system, &w("next")), Ok(next));
    }

    #[test]
    fn storage_counts_what_the_tree_holds() {
        let mut hive = Hive::new();
        assert_eq!(hive.storage(), (0, 0));
        let root = hive.root().unwrap();
        // The key table and the root's name.
        let (blocks, bytes) = hive.storage();
        assert_eq!((blocks, bytes), (2, size_of::<Key>() + 16));
        let (key, _) = hive.create(root, &w("K")).unwrap();
        let with_key = hive.storage();
        // A second table entry, the root's child list, the name.
        assert_eq!(with_key.0, 4);
        assert_eq!(with_key.1, 2 * size_of::<Key>() + 16 + 8 + 2);
        hive.set_value(key, &w("V"), 4, &[1, 2, 3, 4]).unwrap();
        let with_value = hive.storage();
        assert_eq!(with_value.0, with_key.0 + 3);
        assert_eq!(with_value.1, with_key.1 + size_of::<Value>() + 2 + 4);
        // Replacing a value with one of the same size changes nothing.
        hive.set_value(key, &w("v"), 4, &[5, 6, 7, 8]).unwrap();
        assert_eq!(hive.storage(), with_value);
    }

    #[test]
    fn the_full_form_carries_the_name_and_says_where_the_data_is() {
        let data = [1, 2, 3, 4, 5, 6];
        // "Text": 8 bytes of name end at 28; the data starts at 32, as
        // Windows places it.
        let mut out = [0xEEu8; 48];
        assert_eq!(
            full_information(&w("Text"), 1, &data, &mut out),
            (Fit::All, 38)
        );
        assert_eq!(
            out[..20],
            [0, 0, 0, 0, 1, 0, 0, 0, 32, 0, 0, 0, 6, 0, 0, 0, 8, 0, 0, 0]
        );
        assert_eq!(out[20..28], [b'T', 0, b'e', 0, b'x', 0, b't', 0]);
        assert_eq!(out[28..32], [0xEE; 4], "the gap is left alone");
        assert_eq!(out[32..38], data);
        assert_eq!(out[38], 0xEE);
        // A name of three letters ends at 26: the data is at 32 again.
        assert_eq!(
            full_information(&w("Odd"), 3, &data[..3], &mut out),
            (Fit::All, 35)
        );
        assert_eq!(out[8], 32);
        // Exactly enough; one short; the header and part of the name;
        // the header alone.
        let mut exact = [0xEEu8; 38];
        assert_eq!(
            full_information(&w("Text"), 1, &data, &mut exact).0,
            Fit::All
        );
        let mut short = [0xEEu8; 37];
        assert_eq!(
            full_information(&w("Text"), 1, &data, &mut short),
            (Fit::Part, 38)
        );
        assert_eq!(short[32..37], data[..5]);
        let mut name_cut = [0xEEu8; 23];
        assert_eq!(
            full_information(&w("Text"), 1, &data, &mut name_cut),
            (Fit::Part, 38)
        );
        assert_eq!(name_cut[16..], [8, 0, 0, 0, b'T', 0, b'e']);
        let mut header = [0xEEu8; 20];
        assert_eq!(
            full_information(&w("Text"), 1, &data, &mut header),
            (Fit::Part, 38)
        );
        assert_eq!(header[8], 32);
        // Not even the header: untouched.
        let mut nothing = [0xEEu8; 19];
        assert_eq!(
            full_information(&w("Text"), 1, &data, &mut nothing),
            (Fit::Nothing, 38)
        );
        assert_eq!(nothing, [0xEE; 19]);
        // No data: the value ends with its name, and says so.
        assert_eq!(
            full_information(&w("Empty"), 3, &[], &mut out),
            (Fit::All, 30)
        );
        assert_eq!(out[8..16], [0xFF, 0xFF, 0xFF, 0xFF, 0, 0, 0, 0]);
    }

    #[test]
    fn a_value_is_reported_as_far_as_the_buffer_reaches() {
        let data = [b'n', 0, b'k', 0, 0, 0];
        let mut out = [0xEEu8; 24];
        assert_eq!(partial_information(1, &data, &mut out), (Fit::All, 18));
        assert_eq!(out[..12], [0, 0, 0, 0, 1, 0, 0, 0, 6, 0, 0, 0]);
        assert_eq!(out[12..18], data);
        assert_eq!(out[18], 0xEE, "nothing past the value");
        // Exactly enough.
        let mut exact = [0xEEu8; 18];
        assert_eq!(partial_information(1, &data, &mut exact).0, Fit::All);
        // The header and some of the data.
        let mut part = [0xEEu8; 14];
        assert_eq!(partial_information(1, &data, &mut part), (Fit::Part, 18));
        assert_eq!(part, [0, 0, 0, 0, 1, 0, 0, 0, 6, 0, 0, 0, b'n', 0]);
        let mut header = [0xEEu8; 12];
        assert_eq!(partial_information(1, &data, &mut header), (Fit::Part, 18));
        assert_eq!(header[8], 6);
        // Not even the header: untouched.
        let mut short = [0xEEu8; 11];
        assert_eq!(
            partial_information(1, &data, &mut short),
            (Fit::Nothing, 18)
        );
        assert_eq!(short, [0xEE; 11]);
        assert_eq!(partial_information(1, &data, &mut []), (Fit::Nothing, 18));
        // A value without data fits its header.
        assert_eq!(partial_information(3, &[], &mut header), (Fit::All, 12));
    }
}
