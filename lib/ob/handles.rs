//! The slots of a handle table that remembers what each handle may do:
//! the access granted when it was opened, and its attributes.
//!
//! A handle is its slot's index, the lowest free slot is used first
//! (so indices stay small and a closed handle's number is given out
//! again), and the table never looks inside what it holds. The kernel turns generic rights and `MAXIMUM_ALLOWED`
//! into the type's specific rights before a mask gets here.

use alloc::vec::Vec;

/// On whose behalf a handle is used (`KPROCESSOR_MODE`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    Kernel,
    User,
}

/// What a handle is, besides its access.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Attributes {
    /// Child processes get a copy (`OBJ_INHERIT`).
    pub inherit: bool,
    /// The handle cannot be closed (`OBJ_PROTECT_CLOSE`).
    pub protect_from_close: bool,
}

/// Why a handle could not be used.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HandleError {
    /// No such handle (`STATUS_INVALID_HANDLE`).
    Invalid,
    /// The handle was not granted the access asked for
    /// (`STATUS_ACCESS_DENIED`).
    Denied,
    /// The handle is protected from close
    /// (`STATUS_HANDLE_NOT_CLOSABLE`).
    Protected,
    /// No memory for the slot; nothing was changed
    /// (`STATUS_INSUFFICIENT_RESOURCES`).
    NoMemory,
}

/// An open handle: what `OBJECT_HANDLE_INFORMATION` reports, and the
/// object.
#[derive(Debug, PartialEq, Eq)]
pub struct Handle<'a, T> {
    pub object: &'a T,
    pub granted: u32,
    pub attributes: Attributes,
}

#[derive(Debug)]
struct Slot<T> {
    object: T,
    granted: u32,
    attributes: Attributes,
}

/// A handle table's slots, each with its granted access and attributes.
#[derive(Debug)]
pub struct Handles<T> {
    slots: Vec<Option<Slot<T>>>,
}

impl<T> Handles<T> {
    pub const fn new() -> Self {
        Self { slots: Vec::new() }
    }

    /// Open a handle to `object` in the lowest free slot and return its
    /// index.
    pub fn insert(
        &mut self,
        object: T,
        granted: u32,
        attributes: Attributes,
    ) -> Result<usize, HandleError> {
        let index = match self.slots.iter().position(Option::is_none) {
            Some(free) => free,
            None => {
                self.slots
                    .try_reserve(1)
                    .map_err(|_| HandleError::NoMemory)?;
                self.slots.push(None);
                self.slots.len() - 1
            }
        };
        self.slots[index] = Some(Slot {
            object,
            granted,
            attributes,
        });
        Ok(index)
    }

    /// Handle `index`, if it is open.
    pub fn get(&self, index: usize) -> Option<Handle<'_, T>> {
        let slot = self.slots.get(index)?.as_ref()?;
        Some(Handle {
            object: &slot.object,
            granted: slot.granted,
            attributes: slot.attributes,
        })
    }

    /// The object handle `index` names, for a caller that wants
    /// `desired` access to it. User mode gets it only if the handle was
    /// granted every right asked for; kernel mode is not checked
    /// ([`ObReferenceObjectByHandle`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-obreferenceobjectbyhandle)).
    pub fn reference(&self, index: usize, desired: u32, mode: Mode) -> Result<&T, HandleError> {
        let handle = self.get(index).ok_or(HandleError::Invalid)?;
        if mode == Mode::User && desired & !handle.granted != 0 {
            return Err(HandleError::Denied);
        }
        Ok(handle.object)
    }

    /// Close handle `index` and return what it named. A handle
    /// protected from close stays open, whoever asks: what follows (a
    /// status for user mode, a bug check for a kernel handle) is the
    /// kernel's to decide.
    pub fn close(&mut self, index: usize) -> Result<T, HandleError> {
        let slot = self.slots.get_mut(index).ok_or(HandleError::Invalid)?;
        match slot {
            None => Err(HandleError::Invalid),
            Some(open) if open.attributes.protect_from_close => Err(HandleError::Protected),
            Some(_) => slot.take().map(|s| s.object).ok_or(HandleError::Invalid),
        }
    }

    /// Open handles.
    pub fn count(&self) -> usize {
        self.slots.iter().flatten().count()
    }

    /// Iterate over every open `(index, Handle)` in slot order.
    pub fn iter(&self) -> impl Iterator<Item = (usize, Handle<'_, T>)> {
        self.slots.iter().enumerate().filter_map(|(i, slot)| {
            let slot = slot.as_ref()?;
            Some((
                i,
                Handle {
                    object: &slot.object,
                    granted: slot.granted,
                    attributes: slot.attributes,
                },
            ))
        })
    }

    /// Take every open entry out of the table, ignoring `protect_from_close`,
    /// for process handle-table teardown.
    pub fn drain_all(&mut self) -> Vec<T> {
        let mut out = Vec::new();
        for slot in &mut self.slots {
            if let Some(open) = slot.take() {
                out.push(open.object);
            }
        }
        out
    }

    /// The memory the table itself occupies, in bytes. It grows with the
    /// most handles ever open at once and is kept.
    pub fn storage(&self) -> usize {
        self.slots.capacity() * size_of::<Option<Slot<T>>>()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const PLAIN: Attributes = Attributes {
        inherit: false,
        protect_from_close: false,
    };
    const INHERIT: Attributes = Attributes {
        inherit: true,
        protect_from_close: false,
    };
    const PROTECTED: Attributes = Attributes {
        inherit: false,
        protect_from_close: true,
    };

    const READ: u32 = 0x1;
    const WRITE: u32 = 0x2;
    const SYNCHRONIZE: u32 = 0x0010_0000;

    #[test]
    fn handle_slots_are_filled_lowest_first() {
        let mut handles = Handles::new();
        assert_eq!(handles.count(), 0);
        assert_eq!(handles.storage(), 0);
        assert_eq!(handles.insert('a', READ, PLAIN), Ok(0));
        assert_eq!(handles.insert('b', WRITE, INHERIT), Ok(1));
        assert_eq!(handles.insert('c', READ | WRITE, PLAIN), Ok(2));
        assert_eq!(handles.count(), 3);
        // A freed slot in the middle is the next one used.
        assert_eq!(handles.close(1), Ok('b'));
        assert_eq!(handles.close(0), Ok('a'));
        assert_eq!(handles.count(), 1);
        assert_eq!(handles.insert('d', 0, PLAIN), Ok(0));
        assert_eq!(handles.insert('e', 0, PLAIN), Ok(1));
        assert_eq!(handles.insert('f', 0, PLAIN), Ok(3));
        assert_eq!(handles.get(0).map(|h| *h.object), Some('d'));
        assert_eq!(handles.get(2).map(|h| *h.object), Some('c'));
        assert_eq!(handles.count(), 4);
    }

    #[test]
    fn a_handle_keeps_its_access_and_attributes() {
        let mut handles = Handles::new();
        let index = handles.insert(7u8, READ | SYNCHRONIZE, INHERIT).unwrap();
        let expected = Handle {
            object: &7,
            granted: READ | SYNCHRONIZE,
            attributes: INHERIT,
        };
        assert_eq!(handles.get(index), Some(expected));
        // A slot used again starts afresh.
        assert_eq!(handles.close(index), Ok(7));
        assert_eq!(handles.insert(8, WRITE, PLAIN), Ok(index));
        let expected = Handle {
            object: &8,
            granted: WRITE,
            attributes: PLAIN,
        };
        assert_eq!(handles.get(index), Some(expected));
        assert_eq!(Attributes::default(), PLAIN);
    }

    #[test]
    fn a_closed_or_unknown_handle_names_nothing() {
        let mut handles = Handles::new();
        assert_eq!(handles.get(0), None);
        assert_eq!(handles.close(0), Err(HandleError::Invalid));
        let index = handles.insert(5u8, READ, PLAIN).unwrap();
        assert_eq!(handles.get(index + 1), None);
        assert_eq!(handles.close(usize::MAX), Err(HandleError::Invalid));
        for mode in [Mode::Kernel, Mode::User] {
            let unknown = handles.reference(index + 1, 0, mode);
            assert_eq!(unknown, Err(HandleError::Invalid));
        }
        assert_eq!(handles.close(index), Ok(5));
        // Closed: it is gone, and closing it again fails.
        assert_eq!(handles.get(index), None);
        assert_eq!(handles.close(index), Err(HandleError::Invalid));
        let closed = handles.reference(index, 0, Mode::Kernel);
        assert_eq!(closed, Err(HandleError::Invalid));
        assert_eq!(handles.count(), 0);
    }

    #[test]
    fn user_mode_gets_only_the_access_the_handle_was_granted() {
        let mut handles = Handles::new();
        let index = handles.insert('o', READ | SYNCHRONIZE, PLAIN).unwrap();
        let none = handles.insert('n', 0, PLAIN).unwrap();
        let cases = [
            (index, 0, Ok(&'o')),
            (index, READ, Ok(&'o')),
            (index, SYNCHRONIZE, Ok(&'o')),
            (index, READ | SYNCHRONIZE, Ok(&'o')),
            (index, WRITE, Err(HandleError::Denied)),
            // One right too many spoils the rest.
            (index, READ | WRITE, Err(HandleError::Denied)),
            (index, u32::MAX, Err(HandleError::Denied)),
            (none, 0, Ok(&'n')),
            (none, READ, Err(HandleError::Denied)),
        ];
        for (handle, desired, expected) in cases {
            let user = handles.reference(handle, desired, Mode::User);
            assert_eq!(user, expected, "{handle} {desired:#x}");
            // Kernel mode is not held to the mask.
            let kernel = handles.reference(handle, desired, Mode::Kernel);
            assert_eq!(kernel.ok(), handles.get(handle).map(|h| h.object));
        }
    }

    #[test]
    fn a_protected_handle_is_not_closed() {
        let mut handles = Handles::new();
        let index = handles.insert('p', READ, PROTECTED).unwrap();
        assert_eq!(handles.close(index), Err(HandleError::Protected));
        assert_eq!(handles.count(), 1);
        assert_eq!(handles.reference(index, READ, Mode::User), Ok(&'p'));
        let other = handles.insert('q', READ, INHERIT).unwrap();
        assert_eq!(handles.close(other), Ok('q'));
    }

    #[test]
    fn the_table_keeps_the_room_of_its_fullest_moment() {
        let mut handles = Handles::new();
        for n in 0..10u64 {
            handles.insert(n, 0, PLAIN).unwrap();
        }
        let storage = handles.storage();
        assert!(storage >= 10 * size_of::<u64>());
        for n in 0..10 {
            handles.close(n).unwrap();
        }
        assert_eq!(handles.count(), 0);
        assert_eq!(handles.storage(), storage);
        // And fills up again without growing.
        for n in 0..10u64 {
            handles.insert(n, 0, PLAIN).unwrap();
        }
        assert_eq!(handles.storage(), storage);
    }

    #[test]
    fn iter_and_drain_all_cover_every_open_slot() {
        let mut handles = Handles::new();
        let a = handles.insert('a', READ, INHERIT).unwrap();
        let b = handles.insert('b', WRITE, PROTECTED).unwrap();
        let c = handles.insert('c', READ | WRITE, PLAIN).unwrap();
        assert_eq!(handles.close(c), Ok('c'));
        let listed: Vec<(usize, char, bool)> = handles
            .iter()
            .map(|(i, h)| (i, *h.object, h.attributes.inherit))
            .collect();
        assert_eq!(listed, alloc::vec![(a, 'a', true), (b, 'b', false)]);
        let drained = handles.drain_all();
        assert_eq!(drained, alloc::vec!['a', 'b']);
        assert_eq!(handles.count(), 0);
    }
}
