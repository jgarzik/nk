//! The object manager's tables, with no objects behind them: the
//! namespace that maps names to objects and symbolic links, and the
//! slots of a handle table.
//!
//! Both hold whatever the kernel puts in them (a pointer, in practice)
//! and never look inside it; the kernel wraps them in a lock and does
//! the reference counting.
//!
//! [`tree`] is the namespace with directories: a path walk that follows
//! symbolic links and stops at the object whose type parses the rest.
//! [`handles`] is handle slots with granted access and attributes.

#![cfg_attr(not(test), no_std)]

extern crate alloc;

pub mod handles;
pub mod header;
pub mod tree;

use alloc::vec::Vec;

/// How many symbolic links a lookup follows before giving up.
pub const MAX_LINK_DEPTH: usize = 8;

/// What a name leads to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Target<T> {
    /// An object.
    Object(T),
    /// Another name.
    SymbolicLink(Vec<u16>),
}

/// Why a name could not be added or removed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NameError {
    /// Not an absolute name (`STATUS_OBJECT_NAME_INVALID`).
    Invalid,
    /// The name is taken (`STATUS_OBJECT_NAME_COLLISION`).
    Collision,
    /// No memory for the entry; nothing was changed.
    NoMemory,
    /// No such symbolic link (`STATUS_OBJECT_NAME_NOT_FOUND`).
    NotFound,
}

#[derive(Debug)]
struct Entry<T> {
    name: Vec<u16>,
    target: Target<T>,
}

/// The object namespace, reduced to a flat list of full names.
///
/// Names are compared case-insensitively and `\DosDevices`, `\??` and
/// `\GLOBAL??` are one directory (`nk_rtl::same_object_name`). A name
/// must match an entry exactly: there is no directory tree and no
/// parsing of a path remainder. An empty namespace holds no memory.
#[derive(Debug)]
pub struct Namespace<T> {
    entries: Vec<Entry<T>>,
}

impl<T: Copy + PartialEq> Namespace<T> {
    pub const fn new() -> Self {
        Self {
            entries: Vec::new(),
        }
    }

    /// Number of names.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Add a name. Fails if the name is malformed or already taken.
    pub fn insert(&mut self, name: &[u16], target: Target<T>) -> Result<(), NameError> {
        if !nk_rtl::is_valid_object_name(name) {
            return Err(NameError::Invalid);
        }
        if self
            .entries
            .iter()
            .any(|e| nk_rtl::same_object_name(&e.name, name))
        {
            return Err(NameError::Collision);
        }
        let mut copy = Vec::new();
        if copy.try_reserve_exact(name.len()).is_err() || self.entries.try_reserve(1).is_err() {
            return Err(NameError::NoMemory);
        }
        copy.extend_from_slice(name);
        self.entries.push(Entry { name: copy, target });
        Ok(())
    }

    /// Remove the symbolic link called `name`. An object's name is not
    /// removed this way.
    pub fn remove_link(&mut self, name: &[u16]) -> Result<(), NameError> {
        let found = self.entries.iter().position(|e| {
            matches!(e.target, Target::SymbolicLink(_)) && nk_rtl::same_object_name(&e.name, name)
        });
        let index = found.ok_or(NameError::NotFound)?;
        self.entries.swap_remove(index);
        self.entries.shrink_to_fit();
        Ok(())
    }

    /// Remove every name of `object`. Links that led to those names
    /// stay, and lead nowhere.
    pub fn remove_object(&mut self, object: T) {
        self.entries
            .retain(|e| !matches!(e.target, Target::Object(o) if o == object));
        self.entries.shrink_to_fit();
    }

    /// The object `name` refers to, following at most
    /// [`MAX_LINK_DEPTH`] names: a link to a link to an object is found,
    /// a ring of links is not.
    pub fn lookup(&self, name: &[u16]) -> Option<T> {
        let mut name = name;
        for _ in 0..MAX_LINK_DEPTH {
            match &self
                .entries
                .iter()
                .find(|e| nk_rtl::same_object_name(&e.name, name))?
                .target
            {
                Target::Object(object) => return Some(*object),
                Target::SymbolicLink(to) => name = to,
            }
        }
        None
    }
}

/// The slots of a handle table: each open handle has one, and a handle
/// is its slot's index. The lowest free slot is used first, so indices
/// stay small and a closed handle's number is given out again.
#[derive(Debug)]
pub struct Slots<T> {
    slots: Vec<Option<T>>,
}

impl<T> Slots<T> {
    pub const fn new() -> Self {
        Self { slots: Vec::new() }
    }

    /// Put `item` in the lowest free slot and return its index.
    pub fn insert(&mut self, item: T) -> usize {
        let index = match self.slots.iter().position(Option::is_none) {
            Some(free) => free,
            None => {
                self.slots.push(None);
                self.slots.len() - 1
            }
        };
        self.slots[index] = Some(item);
        index
    }

    /// What slot `index` holds, if it is in use.
    pub fn get(&self, index: usize) -> Option<&T> {
        self.slots.get(index)?.as_ref()
    }

    /// Empty slot `index` and return what it held, if it was in use.
    pub fn take(&mut self, index: usize) -> Option<T> {
        self.slots.get_mut(index)?.take()
    }

    /// Slots in use.
    pub fn count(&self) -> usize {
        self.slots.iter().flatten().count()
    }

    /// The memory the table itself occupies, in bytes. It grows with the
    /// most slots ever in use at once and is kept.
    pub fn storage(&self) -> usize {
        self.slots.capacity() * size_of::<Option<T>>()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn w(s: &str) -> Vec<u16> {
        s.encode_utf16().collect()
    }

    fn link(to: &str) -> Target<u32> {
        Target::SymbolicLink(w(to))
    }

    fn with(entries: &[(&str, Target<u32>)]) -> Namespace<u32> {
        let mut ns = Namespace::new();
        for (name, target) in entries {
            assert_eq!(ns.insert(&w(name), target.clone()), Ok(()), "{name}");
        }
        ns
    }

    #[test]
    fn a_name_leads_to_its_object() {
        let ns = with(&[
            ("\\Device\\Null", Target::Object(1)),
            ("\\Device\\Beep", Target::Object(2)),
        ]);
        assert_eq!(ns.lookup(&w("\\Device\\Null")), Some(1));
        assert_eq!(ns.lookup(&w("\\Device\\Beep")), Some(2));
        assert_eq!(ns.len(), 2);
        assert!(!ns.is_empty());
    }

    #[test]
    fn names_are_found_whatever_their_case() {
        let ns = with(&[("\\Device\\Null", Target::Object(1))]);
        assert_eq!(ns.lookup(&w("\\DEVICE\\null")), Some(1));
        assert_eq!(ns.lookup(&w("\\device\\NULL")), Some(1));
    }

    #[test]
    fn a_name_must_match_exactly() {
        let ns = with(&[("\\Device\\Null", Target::Object(1))]);
        assert_eq!(ns.lookup(&w("\\Device\\Nul")), None);
        assert_eq!(ns.lookup(&w("\\Device\\Null2")), None);
        // No directory tree: a path below a device is not the device.
        assert_eq!(ns.lookup(&w("\\Device\\Null\\file")), None);
        assert_eq!(ns.lookup(&w("\\Device")), None);
        assert_eq!(ns.lookup(&w("")), None);
        assert_eq!(Namespace::<u32>::new().lookup(&w("\\Device\\Null")), None);
    }

    #[test]
    fn a_symbolic_link_leads_to_what_its_target_names() {
        let ns = with(&[
            ("\\Device\\Null", Target::Object(1)),
            ("\\DosDevices\\NUL", link("\\Device\\Null")),
        ]);
        assert_eq!(ns.lookup(&w("\\DosDevices\\NUL")), Some(1));
        // The three spellings of the DOS-devices directory are one.
        assert_eq!(ns.lookup(&w("\\??\\NUL")), Some(1));
        assert_eq!(ns.lookup(&w("\\GLOBAL??\\nul")), Some(1));
        // A link made before its target exists works once it does.
        let mut ns = with(&[("\\??\\Later", link("\\Device\\Later"))]);
        assert_eq!(ns.lookup(&w("\\??\\Later")), None);
        ns.insert(&w("\\Device\\Later"), Target::Object(9)).unwrap();
        assert_eq!(ns.lookup(&w("\\??\\Later")), Some(9));
    }

    /// `\L0` -> `\L1` -> ... -> `\L<links>`, which is object 7.
    fn chain(links: usize) -> Namespace<u32> {
        let mut ns = Namespace::new();
        for i in 0..links {
            let to = format!("\\L{}", i + 1);
            ns.insert(&w(&format!("\\L{i}")), link(&to)).unwrap();
        }
        ns.insert(&w(&format!("\\L{links}")), Target::Object(7))
            .unwrap();
        ns
    }

    #[test]
    fn links_are_followed_up_to_the_limit_and_no_further() {
        assert_eq!(chain(0).lookup(&w("\\L0")), Some(7));
        assert_eq!(chain(1).lookup(&w("\\L0")), Some(7));
        // Eight names in all: seven links and the object.
        assert_eq!(chain(MAX_LINK_DEPTH - 1).lookup(&w("\\L0")), Some(7));
        // One link more is one too many, though the object is there.
        let long = chain(MAX_LINK_DEPTH);
        assert_eq!(long.lookup(&w("\\L0")), None);
        assert_eq!(long.lookup(&w("\\L1")), Some(7));
    }

    #[test]
    fn a_ring_of_links_leads_nowhere() {
        let ns = with(&[
            ("\\A", link("\\B")),
            ("\\B", link("\\A")),
            ("\\Self", link("\\Self")),
        ]);
        assert_eq!(ns.lookup(&w("\\A")), None);
        assert_eq!(ns.lookup(&w("\\B")), None);
        assert_eq!(ns.lookup(&w("\\Self")), None);
    }

    #[test]
    fn a_link_to_nothing_leads_nowhere() {
        let ns = with(&[("\\??\\Gone", link("\\Device\\Gone"))]);
        assert_eq!(ns.lookup(&w("\\??\\Gone")), None);
    }

    #[test]
    fn a_malformed_name_is_refused() {
        let mut ns = Namespace::new();
        for bad in ["", "\\", "Device\\Null", "\\Device\0Null"] {
            assert_eq!(
                ns.insert(&w(bad), Target::Object(1)),
                Err(NameError::Invalid),
                "{bad:?}"
            );
        }
        assert!(ns.is_empty());
    }

    #[test]
    fn a_name_is_taken_once() {
        let mut ns = with(&[
            ("\\Device\\Null", Target::Object(1)),
            ("\\??\\NUL", link("\\Device\\Null")),
        ]);
        let taken = Err(NameError::Collision);
        assert_eq!(ns.insert(&w("\\Device\\Null"), Target::Object(2)), taken);
        // By another case, by a link, or by an alias of the directory.
        assert_eq!(ns.insert(&w("\\DEVICE\\NULL"), Target::Object(2)), taken);
        assert_eq!(ns.insert(&w("\\Device\\Null"), link("\\X")), taken);
        assert_eq!(ns.insert(&w("\\DosDevices\\nul"), link("\\X")), taken);
        assert_eq!(ns.insert(&w("\\GLOBAL??\\NUL"), Target::Object(2)), taken);
        // Nothing changed.
        assert_eq!(ns.len(), 2);
        assert_eq!(ns.lookup(&w("\\Device\\Null")), Some(1));
        assert_eq!(ns.lookup(&w("\\??\\NUL")), Some(1));
    }

    #[test]
    fn removing_a_link_leaves_the_object_and_other_links() {
        let mut ns = with(&[
            ("\\Device\\Null", Target::Object(1)),
            ("\\??\\NUL", link("\\Device\\Null")),
            ("\\??\\NUL2", link("\\Device\\Null")),
        ]);
        // By any spelling.
        assert_eq!(ns.remove_link(&w("\\dosdevices\\nul")), Ok(()));
        assert_eq!(ns.lookup(&w("\\??\\NUL")), None);
        assert_eq!(ns.lookup(&w("\\??\\NUL2")), Some(1));
        assert_eq!(ns.lookup(&w("\\Device\\Null")), Some(1));
        assert_eq!(ns.len(), 2);
        // Gone: a second removal finds nothing.
        assert_eq!(ns.remove_link(&w("\\??\\NUL")), Err(NameError::NotFound));
        // The name is free again.
        assert_eq!(ns.insert(&w("\\??\\NUL"), Target::Object(5)), Ok(()));
    }

    #[test]
    fn an_object_s_name_is_not_removed_as_a_link() {
        let mut ns = with(&[("\\Device\\Null", Target::Object(1))]);
        assert_eq!(
            ns.remove_link(&w("\\Device\\Null")),
            Err(NameError::NotFound)
        );
        assert_eq!(ns.lookup(&w("\\Device\\Null")), Some(1));
    }

    #[test]
    fn removing_an_object_removes_all_its_names_and_only_those() {
        let mut ns = with(&[
            ("\\Device\\A", Target::Object(1)),
            ("\\Device\\B", Target::Object(2)),
            ("\\Device\\A2", Target::Object(1)),
            ("\\??\\A", link("\\Device\\A")),
        ]);
        ns.remove_object(1);
        assert_eq!(ns.lookup(&w("\\Device\\A")), None);
        assert_eq!(ns.lookup(&w("\\Device\\A2")), None);
        assert_eq!(ns.lookup(&w("\\Device\\B")), Some(2));
        // The link stays, leading nowhere, until it is deleted.
        assert_eq!(ns.len(), 2);
        assert_eq!(ns.lookup(&w("\\??\\A")), None);
        assert_eq!(ns.remove_link(&w("\\??\\A")), Ok(()));
        // An object with no name: nothing happens.
        ns.remove_object(42);
        assert_eq!(ns.len(), 1);
    }

    #[test]
    fn an_emptied_namespace_holds_no_memory() {
        let mut ns = with(&[
            ("\\Device\\A", Target::Object(1)),
            ("\\??\\A", link("\\Device\\A")),
        ]);
        assert!(ns.entries.capacity() >= 2);
        ns.remove_object(1);
        ns.remove_link(&w("\\??\\A")).unwrap();
        assert!(ns.is_empty());
        assert_eq!(ns.entries.capacity(), 0);
    }

    #[test]
    fn handle_slots_are_filled_lowest_first() {
        let mut slots = Slots::new();
        assert_eq!(slots.count(), 0);
        assert_eq!(slots.storage(), 0);
        assert_eq!(slots.insert('a'), 0);
        assert_eq!(slots.insert('b'), 1);
        assert_eq!(slots.insert('c'), 2);
        assert_eq!(slots.count(), 3);
        assert_eq!(slots.get(1), Some(&'b'));
        // A freed slot in the middle is the next one used.
        assert_eq!(slots.take(1), Some('b'));
        assert_eq!(slots.take(0), Some('a'));
        assert_eq!(slots.count(), 1);
        assert_eq!(slots.insert('d'), 0);
        assert_eq!(slots.insert('e'), 1);
        assert_eq!(slots.insert('f'), 3);
        assert_eq!(slots.get(0), Some(&'d'));
        assert_eq!(slots.get(2), Some(&'c'));
    }

    #[test]
    fn a_closed_or_unknown_slot_holds_nothing() {
        let mut slots = Slots::new();
        assert_eq!(slots.get(0), None);
        assert_eq!(slots.take(0), None);
        let index = slots.insert(5u8);
        assert_eq!(slots.get(index + 1), None);
        assert_eq!(slots.take(usize::MAX), None);
        assert_eq!(slots.take(index), Some(5));
        // Closed: it is gone, and closing it again does nothing.
        assert_eq!(slots.get(index), None);
        assert_eq!(slots.take(index), None);
        assert_eq!(slots.count(), 0);
    }

    #[test]
    fn the_table_keeps_the_room_of_its_fullest_moment() {
        let mut slots = Slots::new();
        for n in 0..10u64 {
            slots.insert(n);
        }
        let storage = slots.storage();
        assert!(storage >= 10 * size_of::<Option<u64>>());
        for n in 0..10 {
            slots.take(n);
        }
        assert_eq!(slots.count(), 0);
        assert_eq!(slots.storage(), storage);
        // And fills up again without growing.
        for n in 0..10u64 {
            slots.insert(n);
        }
        assert_eq!(slots.storage(), storage);
    }
}
