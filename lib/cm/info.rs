//! What a key says about itself: its subkeys and values by index, its
//! attributes, and the information structures of `ZwQueryKey`,
//! `ZwEnumerateKey` and `ZwEnumerateValueKey`.
//!
//! The structures are Microsoft's
//! ([`KEY_INFORMATION_CLASS`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/ne-wdm-_key_information_class),
//! [`KEY_VALUE_INFORMATION_CLASS`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/ne-wdm-_key_value_information_class)).
//! Each formatter answers as the value formatters in the crate root do:
//! how much fitted ([`Fit`]) and the length that holds everything.

use crate::{Error, Fit, Hive, KeyId, Longest, exact, same};
use alloc::vec::Vec;

/// What the key information structures are made from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KeyInfo<'a> {
    pub name: &'a [u16],
    /// The class: bytes, UTF-16 by convention; empty if there is none.
    pub class: &'a [u8],
    /// When the key was last written, as a `FILETIME`.
    pub last_write: u64,
    pub subkeys: u32,
    /// The longest subkey name, in bytes: the longest there has been
    /// since the key last had no subkeys, as Windows counts.
    pub max_name_len: u32,
    /// The longest subkey class, in bytes, counted the same way.
    pub max_class_len: u32,
    pub values: u32,
    /// The longest value name, in bytes: the longest there has been
    /// since the key last had no values.
    pub max_value_name_len: u32,
    /// The longest value data, in bytes, counted the same way.
    pub max_value_data_len: u32,
}

impl Hive {
    /// Subkey `index` of `key`, counting in the order of the subkeys'
    /// upper-cased names, as Windows does. `None` past the last
    /// (`STATUS_NO_MORE_ENTRIES`).
    pub fn subkey(&self, key: KeyId, index: usize) -> Result<Option<KeyId>, Error> {
        let key = &self.keys[self.live(key)?];
        Ok(key.children.get(index).copied().map(KeyId))
    }

    /// Value `index` of `key`, counting in the order the values were
    /// first set: its name, type and data. `None` past the last
    /// (`STATUS_NO_MORE_ENTRIES`).
    #[allow(clippy::type_complexity)]
    pub fn value_at(
        &self,
        key: KeyId,
        index: usize,
    ) -> Result<Option<(&[u16], u32, &[u8])>, Error> {
        let key = &self.keys[self.live(key)?];
        Ok(key
            .values
            .get(index)
            .map(|value| (&value.name[..], value.kind, &value.data[..])))
    }

    /// Take a value away from `key`. `NotFound` if it has no such value.
    pub fn delete_value(&mut self, key: KeyId, name: &[u16]) -> Result<(), Error> {
        let index = self.live(key)?;
        let values = &mut self.keys[index].values;
        let at = values
            .iter()
            .position(|value| same(&value.name, name))
            .ok_or(Error::NotFound)?;
        values.remove(at);
        values.shrink_to_fit();
        if values.is_empty() {
            let longest = &mut self.keys[index].longest;
            longest.value_name = 0;
            longest.value_data = 0;
        }
        Ok(())
    }

    /// What `key` holds, for the key information structures.
    pub fn info(&self, key: KeyId) -> Result<KeyInfo<'_>, Error> {
        let key = &self.keys[self.live(key)?];
        Ok(KeyInfo {
            name: &key.name,
            class: &key.class,
            last_write: key.last_write,
            subkeys: key.children.len() as u32,
            max_name_len: key.longest.name,
            max_class_len: key.longest.class,
            values: key.values.len() as u32,
            max_value_name_len: key.longest.value_name,
            max_value_data_len: key.longest.value_data,
        })
    }

    /// Have `key` remember lengths at least as long as `longest`: what
    /// a hive file says the key has held.
    pub fn raise_longest(&mut self, key: KeyId, longest: Longest) -> Result<(), Error> {
        let index = self.live(key)?;
        self.keys[index].longest.raise(longest);
        Ok(())
    }

    /// The full name of `key`, from the root: `\REGISTRY\...`, each
    /// part spelled as it was created.
    pub fn path(&self, key: KeyId) -> Result<Vec<u16>, Error> {
        let key = self.live(key)?;
        // The keys from `key` up to the root. A key that has subkeys is
        // never deleted, so every one of them is live.
        let chain = || {
            let mut next = Some(key);
            core::iter::from_fn(move || {
                let at = next?;
                next = (at != 0).then(|| self.keys[at].parent);
                Some(&self.keys[at].name[..])
            })
        };
        let len = chain().map(|name| 1 + name.len()).sum();
        let mut path = Vec::new();
        path.try_reserve_exact(len).map_err(|_| Error::NoMemory)?;
        path.resize(len, u16::from(b'\\'));
        let mut end = len;
        for name in chain() {
            path[end - name.len()..end].copy_from_slice(name);
            end -= name.len() + 1;
        }
        Ok(path)
    }

    /// The security descriptor of `key`, self-relative; empty if it was
    /// given none.
    pub fn security(&self, key: KeyId) -> Result<&[u8], Error> {
        Ok(&self.keys[self.live(key)?].security)
    }

    /// Whether `key` is a symbolic link to another key.
    pub fn is_link(&self, key: KeyId) -> Result<bool, Error> {
        Ok(self.keys[self.live(key)?].link)
    }

    /// Give `key` a class.
    pub fn set_class(&mut self, key: KeyId, class: &[u8]) -> Result<(), Error> {
        let index = self.live(key)?;
        self.keys[index].class = exact(class)?;
        // The root is no key's subkey.
        if index != 0 {
            let parent = self.keys[index].parent;
            self.keys[parent].longest.raise(Longest {
                class: class.len() as u32,
                ..Longest::default()
            });
        }
        Ok(())
    }

    /// Give `key` a self-relative security descriptor.
    pub fn set_security(&mut self, key: KeyId, descriptor: &[u8]) -> Result<(), Error> {
        let index = self.live(key)?;
        self.keys[index].security = exact(descriptor)?;
        Ok(())
    }

    /// The key `key` is a subkey of; the root, for the root.
    pub fn parent(&self, key: KeyId) -> Result<KeyId, Error> {
        Ok(KeyId(self.keys[self.live(key)?].parent))
    }

    /// Say when `key` was last written, as a `FILETIME`.
    pub fn set_last_write(&mut self, key: KeyId, time: u64) -> Result<(), Error> {
        let index = self.live(key)?;
        self.keys[index].last_write = time;
        Ok(())
    }

    /// Say whether `key` is a symbolic link to another key.
    pub fn set_link(&mut self, key: KeyId, link: bool) -> Result<(), Error> {
        let index = self.live(key)?;
        self.keys[index].link = link;
        Ok(())
    }

    /// Make `key` a symbolic link to the key `target` names, a full
    /// path from the root (`\Registry\...`): what creating a key with
    /// `REG_OPTION_CREATE_LINK` and setting its `SymbolicLinkValue`
    /// does on Windows. The target need not exist.
    pub fn link_to(&mut self, key: KeyId, target: &[u16]) -> Result<(), Error> {
        let mut bytes = Vec::new();
        bytes
            .try_reserve_exact(target.len() * 2)
            .map_err(|_| Error::NoMemory)?;
        bytes.extend(target.iter().flat_map(|unit| unit.to_le_bytes()));
        self.set_value(key, crate::LINK_VALUE, crate::REG_LINK, &bytes)?;
        self.set_link(key, true)
    }
}

/// Size of a `KEY_BASIC_INFORMATION` before the name: last write time,
/// title index, name length.
pub const KEY_BASIC_HEADER: usize = 16;
/// Size of a `KEY_NODE_INFORMATION` before the name: last write time,
/// title index, class offset, class length, name length.
pub const KEY_NODE_HEADER: usize = 24;
/// Size of a `KEY_FULL_INFORMATION` before the class: last write time,
/// title index, class offset, class length, then six counts.
pub const KEY_FULL_HEADER: usize = 44;
/// Size of a `KEY_NAME_INFORMATION` before the name: its length.
pub const KEY_NAME_HEADER: usize = 4;
/// Size of a `KEY_CACHED_INFORMATION` as C counts it: last write time,
/// title index, five counts and the name's length, 36 bytes, then the
/// first character of a name it never holds and padding to the
/// structure's alignment of eight.
pub const KEY_CACHED_SIZE: usize = 40;
/// How much of a `KEY_CACHED_INFORMATION` is written: its fields.
const KEY_CACHED_FIELDS: usize = 36;
/// Size of a `KEY_VALUE_BASIC_INFORMATION` before the name: title
/// index, type, name length.
pub const VALUE_BASIC_HEADER: usize = 12;
/// The `ClassOffset` of a key that has no class.
pub const NO_CLASS: u32 = u32::MAX;

/// Write the fixed part of a structure, as 32-bit fields. `false`, and
/// nothing written, if `out` has no room for all of it.
fn fixed(out: &mut [u8], fields: &[u32]) -> bool {
    let Some(room) = out.get_mut(..4 * fields.len()) else {
        return false;
    };
    let (words, _) = room.as_chunks_mut::<4>();
    for (word, field) in words.iter_mut().zip(fields) {
        *word = field.to_le_bytes();
    }
    true
}

/// Write `bytes` at `at`, as far as `out` reaches.
fn put(out: &mut [u8], at: usize, bytes: impl Iterator<Item = u8>) {
    if let Some(room) = out.get_mut(at..) {
        room.iter_mut().zip(bytes).for_each(|(to, from)| *to = from);
    }
}

fn wide(name: &[u16]) -> impl Iterator<Item = u8> + '_ {
    name.iter().flat_map(|unit| unit.to_le_bytes())
}

/// The answer of a formatter that has written its fixed part.
fn fit(out: &[u8], needed: usize) -> (Fit, usize) {
    let fit = if out.len() >= needed {
        Fit::All
    } else {
        Fit::Part
    };
    (fit, needed)
}

/// The two halves of a `FILETIME`, low first.
fn time(filetime: u64) -> [u32; 2] {
    [filetime as u32, (filetime >> 32) as u32]
}

/// Write a key as a `KEY_BASIC_INFORMATION` into `out`: when it was
/// last written and its name. Returns how much fitted, and the length
/// that holds all of it.
pub fn key_basic_information(key: &KeyInfo<'_>, out: &mut [u8]) -> (Fit, usize) {
    let name = key.name.len() * 2;
    let needed = KEY_BASIC_HEADER + name;
    let [low, high] = time(key.last_write);
    if !fixed(out, &[low, high, 0, name as u32]) {
        return (Fit::Nothing, needed);
    }
    put(out, KEY_BASIC_HEADER, wide(key.name));
    fit(out, needed)
}

/// Write a key as a `KEY_NODE_INFORMATION` into `out`: the header, the
/// name, then the class at the next multiple of four bytes. A key
/// without a class ends with its name and gives [`NO_CLASS`] as the
/// offset. Returns how much fitted, and the length that holds all of
/// it.
pub fn key_node_information(key: &KeyInfo<'_>, out: &mut [u8]) -> (Fit, usize) {
    let name = key.name.len() * 2;
    let (class_offset, needed) = if key.class.is_empty() {
        (NO_CLASS, KEY_NODE_HEADER + name)
    } else {
        let offset = (KEY_NODE_HEADER + name + 3) & !3;
        (offset as u32, offset + key.class.len())
    };
    let [low, high] = time(key.last_write);
    let class = key.class.len() as u32;
    if !fixed(out, &[low, high, 0, class_offset, class, name as u32]) {
        return (Fit::Nothing, needed);
    }
    put(out, KEY_NODE_HEADER, wide(key.name));
    put(out, class_offset as usize, key.class.iter().copied());
    fit(out, needed)
}

/// Write a key as a `KEY_FULL_INFORMATION` into `out`: the header with
/// the counts of subkeys and values and their longest names, classes
/// and data, then the class. A key without a class gives [`NO_CLASS`]
/// as the offset. Returns how much fitted, and the length that holds
/// all of it.
pub fn key_full_information(key: &KeyInfo<'_>, out: &mut [u8]) -> (Fit, usize) {
    let needed = KEY_FULL_HEADER + key.class.len();
    let class_offset = if key.class.is_empty() {
        NO_CLASS
    } else {
        KEY_FULL_HEADER as u32
    };
    let [low, high] = time(key.last_write);
    let header = [
        low,
        high,
        0,
        class_offset,
        key.class.len() as u32,
        key.subkeys,
        key.max_name_len,
        key.max_class_len,
        key.values,
        key.max_value_name_len,
        key.max_value_data_len,
    ];
    if !fixed(out, &header) {
        return (Fit::Nothing, needed);
    }
    put(out, KEY_FULL_HEADER, key.class.iter().copied());
    fit(out, needed)
}

/// Write a key's full name ([`Hive::path`]) as a
/// `KEY_NAME_INFORMATION` into `out`. Returns how much fitted, and the
/// length that holds all of it.
pub fn key_name_information(path: &[u16], out: &mut [u8]) -> (Fit, usize) {
    let needed = KEY_NAME_HEADER + path.len() * 2;
    if !fixed(out, &[path.len() as u32 * 2]) {
        return (Fit::Nothing, needed);
    }
    put(out, KEY_NAME_HEADER, wide(path));
    fit(out, needed)
}

/// Write a key as a `KEY_CACHED_INFORMATION` into `out`: the counts of
/// the full form and the length of the key's name, without name or
/// class. It is all there or not at all: Windows wants room for the
/// whole structure ([`KEY_CACHED_SIZE`]) and writes its fields, leaving
/// the four bytes after them alone.
pub fn key_cached_information(key: &KeyInfo<'_>, out: &mut [u8]) -> (Fit, usize) {
    let [low, high] = time(key.last_write);
    let fields = [
        low,
        high,
        0,
        key.subkeys,
        key.max_name_len,
        key.values,
        key.max_value_name_len,
        key.max_value_data_len,
        key.name.len() as u32 * 2,
    ];
    const { assert!(size_of::<[u32; 9]>() == KEY_CACHED_FIELDS) };
    if out.len() >= KEY_CACHED_SIZE && fixed(out, &fields) {
        (Fit::All, KEY_CACHED_SIZE)
    } else {
        (Fit::Nothing, KEY_CACHED_SIZE)
    }
}

/// Write a structure that is `fields` and nothing more, 32 bits each,
/// into `out`: all of it or nothing.
pub fn fixed_information(fields: &[u32], out: &mut [u8]) -> (Fit, usize) {
    let needed = 4 * fields.len();
    if fixed(out, fields) {
        (Fit::All, needed)
    } else {
        (Fit::Nothing, needed)
    }
}

/// Write a structure that is one 32-bit word of bit fields into `out`:
/// the bits of `mask` become those of `flags`; the others, which the
/// structure reserves, keep what `out` held, as Windows leaves them.
pub fn flag_information(flags: u32, mask: u32, out: &mut [u8]) -> (Fit, usize) {
    let Some(word) = out.first_chunk_mut::<4>() else {
        return (Fit::Nothing, 4);
    };
    *word = (u32::from_le_bytes(*word) & !mask | flags & mask).to_le_bytes();
    (Fit::All, 4)
}

/// Write a value as a `KEY_VALUE_BASIC_INFORMATION` into `out`: its
/// type and name. Returns how much fitted, and the length that holds
/// all of it.
pub fn value_basic_information(name: &[u16], kind: u32, out: &mut [u8]) -> (Fit, usize) {
    let needed = VALUE_BASIC_HEADER + name.len() * 2;
    if !fixed(out, &[0, kind, name.len() as u32 * 2]) {
        return (Fit::Nothing, needed);
    }
    put(out, VALUE_BASIC_HEADER, wide(name));
    fit(out, needed)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::writer::w;

    /// A hive with `\Registry\K`.
    fn hive() -> (Hive, KeyId) {
        let mut hive = Hive::new();
        let root = hive.root().unwrap();
        let (key, _) = hive.create(root, &w("K")).unwrap();
        (hive, key)
    }

    fn names(hive: &Hive, key: KeyId) -> Vec<String> {
        (0..)
            .map_while(|index| hive.subkey(key, index).unwrap())
            .map(|subkey| String::from_utf16(hive.info(subkey).unwrap().name).unwrap())
            .collect()
    }

    #[test]
    fn subkeys_are_counted_in_the_order_of_their_upper_cased_names() {
        let (mut hive, key) = hive();
        assert_eq!(hive.subkey(key, 0), Ok(None));
        for name in ["b", "A", "c10", "C2", "ab", "Z", "é", "a"] {
            hive.create(key, &w(name)).unwrap();
        }
        // Letter case does not count; a name comes before a longer one
        // that starts with it; digits compare as characters.
        assert_eq!(
            names(&hive, key),
            ["A", "ab", "b", "c10", "C2", "Z", "é"],
            "created again, `a` is `A`"
        );
        assert_eq!(hive.subkey(key, 7), Ok(None));
        assert_eq!(hive.subkey(key, usize::MAX), Ok(None));
        // Every one is still found by name, and the order survives a
        // deletion and a creation.
        let b = hive.open(key, &w("B")).unwrap();
        assert_eq!(hive.subkey(key, 2), Ok(Some(b)));
        hive.delete(b).unwrap();
        hive.create(key, &w("aa")).unwrap();
        assert_eq!(names(&hive, key), ["A", "aa", "ab", "c10", "C2", "Z", "é"]);
        // A deleted key has no subkeys to count.
        let (gone, _) = hive.create(key, &w("gone")).unwrap();
        hive.opened(gone);
        hive.delete(gone).unwrap();
        assert_eq!(hive.subkey(gone, 0), Err(Error::Deleted));
        assert_eq!(hive.value_at(gone, 0), Err(Error::Deleted));
        assert_eq!(hive.info(gone).map(|_| ()), Err(Error::Deleted));
        assert_eq!(hive.path(gone), Err(Error::Deleted));
        assert_eq!(hive.delete_value(gone, &[]), Err(Error::Deleted));
    }

    #[test]
    fn values_are_counted_in_the_order_they_were_set_and_can_be_deleted() {
        let (mut hive, key) = hive();
        assert_eq!(hive.value_at(key, 0), Ok(None));
        let empty = hive.storage();
        for (name, data) in [("z", &[1u8][..]), ("A", &[2, 2]), ("m", &[3, 3, 3])] {
            hive.set_value(key, &w(name), 3, data).unwrap();
        }
        // Set again, a value keeps its place.
        hive.set_value(key, &w("Z"), 4, &[9]).unwrap();
        let list = |hive: &Hive| -> Vec<(String, u32, Vec<u8>)> {
            (0..)
                .map_while(|index| hive.value_at(key, index).unwrap())
                .map(|(name, kind, data)| (String::from_utf16(name).unwrap(), kind, data.to_vec()))
                .collect()
        };
        assert_eq!(
            list(&hive),
            [
                ("z".to_string(), 4, vec![9]),
                ("A".to_string(), 3, vec![2, 2]),
                ("m".to_string(), 3, vec![3, 3, 3])
            ]
        );
        // Deleted under any spelling; the others keep their order.
        assert_eq!(hive.delete_value(key, &w("a")), Ok(()));
        assert_eq!(hive.delete_value(key, &w("a")), Err(Error::NotFound));
        assert_eq!(hive.value(key, &w("A")), Err(Error::NotFound));
        assert_eq!(
            list(&hive).iter().map(|v| &v.0[..]).collect::<Vec<_>>(),
            ["z", "m"]
        );
        assert_eq!(hive.value_at(key, 2), Ok(None));
        // With the last value goes the last of their memory.
        hive.delete_value(key, &w("M")).unwrap();
        hive.delete_value(key, &w("Z")).unwrap();
        assert_eq!(hive.storage(), empty);
    }

    #[test]
    fn a_key_carries_class_time_security_and_the_link_flag() {
        let (mut hive, key) = hive();
        let bare = hive.storage();
        let info = hive.info(key).unwrap();
        assert_eq!(
            info,
            KeyInfo {
                name: &w("K"),
                class: &[],
                last_write: 0,
                subkeys: 0,
                max_name_len: 0,
                max_class_len: 0,
                values: 0,
                max_value_name_len: 0,
                max_value_data_len: 0,
            }
        );
        assert_eq!(hive.security(key), Ok(&[][..]));
        assert_eq!(hive.is_link(key), Ok(false));
        hive.set_class(key, &[1, 2, 3, 4]).unwrap();
        hive.set_security(key, &[5; 20]).unwrap();
        hive.set_last_write(key, 0x0123_4567_89AB_CDEF).unwrap();
        hive.set_link(key, true).unwrap();
        assert_eq!(hive.security(key), Ok(&[5; 20][..]));
        assert_eq!(hive.is_link(key), Ok(true));
        // Two blocks more, of 4 and 20 bytes.
        assert_eq!(hive.storage(), (bare.0 + 2, bare.1 + 24));
        // The counts and the longest of each kind, in bytes.
        let (long, _) = hive.create(key, &w("Longer")).unwrap();
        hive.create(key, &w("S")).unwrap();
        hive.set_class(long, &[0; 6]).unwrap();
        hive.set_value(key, &w("Name"), 1, &[0; 10]).unwrap();
        hive.set_value(key, &w("N"), 1, &[0; 30]).unwrap();
        hive.set_value(key, &[], 1, &[]).unwrap();
        let info = hive.info(key).unwrap();
        assert_eq!(
            info,
            KeyInfo {
                name: &w("K"),
                class: &[1, 2, 3, 4],
                last_write: 0x0123_4567_89AB_CDEF,
                subkeys: 2,
                max_name_len: 12,
                max_class_len: 6,
                values: 3,
                max_value_name_len: 8,
                max_value_data_len: 30,
            }
        );
        // A deleted key refuses all of it, and holds none of it.
        hive.opened(long);
        let before = hive.storage();
        hive.delete(long).unwrap();
        assert_eq!(
            hive.storage().1,
            before.1 - 12 - 6 - 8,
            "name, class, place in the parent"
        );
        assert_eq!(hive.set_class(long, &[1]), Err(Error::Deleted));
        assert_eq!(hive.set_security(long, &[1]), Err(Error::Deleted));
        assert_eq!(hive.set_last_write(long, 1), Err(Error::Deleted));
        assert_eq!(hive.parent(long), Err(Error::Deleted));
        assert_eq!(hive.set_link(long, true), Err(Error::Deleted));
        assert_eq!(hive.security(long), Err(Error::Deleted));
        assert_eq!(hive.is_link(long), Err(Error::Deleted));
    }

    #[test]
    fn the_longest_lengths_are_kept_until_nothing_is_left() {
        let (mut hive, key) = hive();
        let longest = |hive: &Hive| {
            let info = hive.info(key).unwrap();
            [
                info.max_name_len,
                info.max_class_len,
                info.max_value_name_len,
                info.max_value_data_len,
            ]
        };
        hive.set_value(key, &w("Longest"), 3, &[0; 9]).unwrap();
        hive.set_value(key, &w("V"), 3, &[0; 20]).unwrap();
        let (long, _) = hive.create(key, &w("LongName")).unwrap();
        let (short, _) = hive.create(key, &w("S")).unwrap();
        hive.set_class(long, &[0; 6]).unwrap();
        hive.set_class(short, &[0; 2]).unwrap();
        assert_eq!(longest(&hive), [16, 6, 14, 20]);
        // The longest of each goes; the numbers stay, as on Windows.
        hive.delete_value(key, &w("Longest")).unwrap();
        hive.set_value(key, &w("V"), 3, &[0; 3]).unwrap();
        hive.delete(long).unwrap();
        assert_eq!(longest(&hive), [16, 6, 14, 20]);
        // With the last value, and the last subkey, they start again.
        hive.delete_value(key, &w("V")).unwrap();
        assert_eq!(longest(&hive), [16, 6, 0, 0]);
        hive.delete(short).unwrap();
        assert_eq!(longest(&hive), [0; 4]);
        hive.set_value(key, &w("ab"), 3, &[1]).unwrap();
        hive.create(key, &w("abc")).unwrap();
        assert_eq!(longest(&hive), [6, 0, 4, 1]);
        // What a hive file says a key held raises them, never lowers.
        let said = Longest {
            name: 2,
            class: 8,
            value_name: 40,
            value_data: 0,
        };
        hive.raise_longest(key, said).unwrap();
        assert_eq!(longest(&hive), [6, 8, 40, 1]);
        // The root's class is no subkey's.
        let root = hive.root().unwrap();
        hive.set_class(root, &[0; 4]).unwrap();
        assert_eq!(hive.info(root).unwrap().max_class_len, 0);
        let (gone, _) = hive.create(key, &w("gone")).unwrap();
        hive.opened(gone);
        hive.delete(gone).unwrap();
        assert_eq!(hive.raise_longest(gone, said), Err(Error::Deleted));
    }

    #[test]
    fn a_path_starts_at_the_root() {
        let (mut hive, key) = hive();
        let root = hive.root().unwrap();
        assert_eq!(hive.path(root), Ok(w("\\REGISTRY")));
        assert_eq!((hive.parent(key), hive.parent(root)), (Ok(root), Ok(root)));
        assert_eq!(hive.path(key), Ok(w("\\REGISTRY\\K")));
        let (sub, _) = hive.create(key, &w("Sub Key")).unwrap();
        let path = hive.path(sub).unwrap();
        assert_eq!(path, w("\\REGISTRY\\K\\Sub Key"));
        assert_eq!(path.capacity(), path.len());
    }

    /// Run a formatter at every length up to more than enough, and
    /// return what it writes when all fits. Below `header` bytes
    /// nothing is written; from there on, as much as there is room for.
    fn at_every_length(header: usize, format: impl Fn(&mut [u8]) -> (Fit, usize)) -> Vec<u8> {
        let needed = format(&mut []).1;
        let mut all = vec![0xEE; needed];
        assert_eq!(format(&mut all), (Fit::All, needed), "exactly enough");
        let mut roomy = vec![0xEE; needed + 5];
        assert_eq!(format(&mut roomy), (Fit::All, needed));
        assert_eq!(roomy[..needed], all[..]);
        assert_eq!(roomy[needed..], [0xEE; 5], "nothing past the end");
        for len in header..needed {
            let mut part = vec![0xEE; len];
            assert_eq!(format(&mut part), (Fit::Part, needed), "{len} bytes");
            assert_eq!(part[..], all[..len], "{len} bytes");
        }
        for len in 0..header {
            let mut nothing = vec![0xEE; len];
            assert_eq!(format(&mut nothing), (Fit::Nothing, needed), "{len} bytes");
            assert_eq!(nothing, vec![0xEE; len], "{len} bytes");
        }
        all
    }

    const KEY: KeyInfo<'static> = KeyInfo {
        name: &[0x4B, 0x65, 0x79],
        class: &[b'C', 0, b'l', 0],
        last_write: 0x0102_0304_0506_0708,
        subkeys: 2,
        max_name_len: 10,
        max_class_len: 6,
        values: 3,
        max_value_name_len: 8,
        max_value_data_len: 100,
    };
    const TIME: [u8; 8] = [8, 7, 6, 5, 4, 3, 2, 1];
    const NAME: [u8; 6] = [b'K', 0, b'e', 0, b'y', 0];

    #[test]
    fn basic_information_is_the_time_and_the_name() {
        let all = at_every_length(KEY_BASIC_HEADER, |out| key_basic_information(&KEY, out));
        assert_eq!(all.len(), 22);
        assert_eq!(all[..8], TIME);
        assert_eq!(all[8..16], [0, 0, 0, 0, 6, 0, 0, 0]);
        assert_eq!(all[16..], NAME);
        // A key without a name is its header.
        let root = KeyInfo { name: &[], ..KEY };
        let all = at_every_length(KEY_BASIC_HEADER, |out| key_basic_information(&root, out));
        assert_eq!(all[8..], [0; 8]);
    }

    #[test]
    fn node_information_puts_the_class_after_the_name() {
        let all = at_every_length(KEY_NODE_HEADER, |out| key_node_information(&KEY, out));
        // The name ends at 30; the class starts at 32.
        assert_eq!(all.len(), 36);
        assert_eq!(all[..8], TIME);
        assert_eq!(
            all[8..24],
            [0, 0, 0, 0, 32, 0, 0, 0, 4, 0, 0, 0, 6, 0, 0, 0]
        );
        assert_eq!(all[24..30], NAME);
        assert_eq!(all[30..32], [0xEE; 2], "the gap is left alone");
        assert_eq!(all[32..], [b'C', 0, b'l', 0]);
        // A name that ends on a multiple of four is followed at once.
        let even = KeyInfo {
            name: &[0x4B, 0x65],
            ..KEY
        };
        let all = at_every_length(KEY_NODE_HEADER, |out| key_node_information(&even, out));
        assert_eq!((all.len(), all[12]), (32, 28));
        // No class: the key ends with its name, and says so.
        let plain = KeyInfo { class: &[], ..KEY };
        let all = at_every_length(KEY_NODE_HEADER, |out| key_node_information(&plain, out));
        assert_eq!(all.len(), 30);
        assert_eq!(all[12..20], [0xFF, 0xFF, 0xFF, 0xFF, 0, 0, 0, 0]);
    }

    #[test]
    fn full_information_counts_subkeys_and_values() {
        let all = at_every_length(KEY_FULL_HEADER, |out| key_full_information(&KEY, out));
        assert_eq!(all.len(), 48);
        assert_eq!(all[..8], TIME);
        let fields: Vec<u32> = all[8..44]
            .chunks(4)
            .map(|field| u32::from_le_bytes(field.try_into().unwrap()))
            .collect();
        assert_eq!(fields, [0, 44, 4, 2, 10, 6, 3, 8, 100]);
        assert_eq!(all[44..], [b'C', 0, b'l', 0]);
        let plain = KeyInfo { class: &[], ..KEY };
        let all = at_every_length(KEY_FULL_HEADER, |out| key_full_information(&plain, out));
        assert_eq!(all.len(), 44);
        assert_eq!(all[12..20], [0xFF, 0xFF, 0xFF, 0xFF, 0, 0, 0, 0]);
    }

    #[test]
    fn cached_information_is_the_counts_and_no_name() {
        let all = at_every_length(KEY_CACHED_SIZE, |out| key_cached_information(&KEY, out));
        // The structure's size, of which the last four bytes are left
        // alone.
        assert_eq!(all.len(), 40);
        assert_eq!(all[36..], [0xEE; 4]);
        assert_eq!(all[..8], TIME);
        let fields: Vec<u32> = all[8..36]
            .chunks(4)
            .map(|field| u32::from_le_bytes(field.try_into().unwrap()))
            .collect();
        // Title index, subkeys, longest name, values, longest value
        // name and data, the length of the key's own name.
        assert_eq!(fields, [0, 2, 10, 3, 8, 100, 6]);
        // A structure of fixed size is there whole or not at all.
        let all = at_every_length(12, |out| fixed_information(&[1, 2, 0x0403_0201], out));
        assert_eq!(all, [1, 0, 0, 0, 2, 0, 0, 0, 1, 2, 3, 4]);
    }

    #[test]
    fn a_word_of_flags_keeps_its_reserved_bits() {
        let format = |out: &mut [u8]| flag_information(0b0101, 0b1111, out);
        for len in 0..4 {
            let mut short = vec![0xEE; len];
            assert_eq!(format(&mut short), (Fit::Nothing, 4));
            assert_eq!(short, vec![0xEE; len]);
        }
        // The four flags are written, set or clear; the rest stays.
        let mut out = [0xEE; 6];
        assert_eq!(format(&mut out), (Fit::All, 4));
        assert_eq!(out, [0xE5, 0xEE, 0xEE, 0xEE, 0xEE, 0xEE]);
        // A flag outside the mask is not written.
        let mut out = [0; 4];
        assert_eq!(flag_information(0b11, 0b01, &mut out), (Fit::All, 4));
        assert_eq!(out, [1, 0, 0, 0]);
    }

    #[test]
    fn name_information_is_the_full_name() {
        let path = w("\\REGISTRY\\K");
        let all = at_every_length(KEY_NAME_HEADER, |out| key_name_information(&path, out));
        assert_eq!(all.len(), 26);
        assert_eq!(all[..4], [22, 0, 0, 0]);
        assert_eq!(all[4..8], [b'\\', 0, b'R', 0]);
        assert_eq!(all[22..], [b'\\', 0, b'K', 0]);
    }

    #[test]
    fn value_basic_information_is_the_type_and_the_name() {
        let name = w("Val");
        let all = at_every_length(VALUE_BASIC_HEADER, |out| {
            value_basic_information(&name, 4, out)
        });
        assert_eq!(all.len(), 18);
        assert_eq!(all[..12], [0, 0, 0, 0, 4, 0, 0, 0, 6, 0, 0, 0]);
        assert_eq!(all[12..], [b'V', 0, b'a', 0, b'l', 0]);
        // The value without a name is its header.
        let all = at_every_length(VALUE_BASIC_HEADER, |out| {
            value_basic_information(&[], 1, out)
        });
        assert_eq!(all, [0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0]);
    }
}
