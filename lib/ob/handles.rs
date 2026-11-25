//! The slots of a handle table that remembers what each handle may do:
//! the access granted when it was opened, and its attributes.
//!
//! As with [`Slots`](crate::Slots), a handle is its slot's index, the
//! lowest free slot is used first, and the table never looks inside
//! what it holds. The kernel turns generic rights and `MAXIMUM_ALLOWED`
//! into the type's specific rights before a mask gets here.

use alloc::vec::Vec;

/// `DUPLICATE_CLOSE_SOURCE`: close the source handle.
pub const DUPLICATE_CLOSE_SOURCE: u32 = 0x1;
/// `DUPLICATE_SAME_ACCESS`: the new handle gets the source's access.
pub const DUPLICATE_SAME_ACCESS: u32 = 0x2;
/// `DUPLICATE_SAME_ATTRIBUTES`: the new handle gets the source's
/// attributes.
pub const DUPLICATE_SAME_ATTRIBUTES: u32 = 0x4;

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

    /// The memory the table itself occupies, in bytes. It grows with the
    /// most handles ever open at once and is kept.
    pub fn storage(&self) -> usize {
        self.slots.capacity() * size_of::<Option<Slot<T>>>()
    }
}

/// What duplicating a handle produces.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Duplicate {
    /// The new handle's access.
    pub granted: u32,
    /// The part of it the source handle did not have. The kernel must
    /// check these rights against the object before granting them to a
    /// user-mode caller.
    pub added: u32,
    /// The new handle's attributes.
    pub attributes: Attributes,
    /// Close the source handle, whether or not the new one is made.
    pub close_source: bool,
}

/// What
/// [`ZwDuplicateObject`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-zwduplicateobject)
/// makes of a source handle with `source_granted` access and
/// `source_attributes`, asked for `desired` access and `attributes`
/// under `options` (`DUPLICATE_*`; other bits are not looked at).
/// `DUPLICATE_SAME_ACCESS` overrides `desired`, and
/// `DUPLICATE_SAME_ATTRIBUTES` overrides `attributes`.
pub fn duplicate(
    source_granted: u32,
    source_attributes: Attributes,
    desired: u32,
    attributes: Attributes,
    options: u32,
) -> Duplicate {
    let granted = if options & DUPLICATE_SAME_ACCESS != 0 {
        source_granted
    } else {
        desired
    };
    let attributes = if options & DUPLICATE_SAME_ATTRIBUTES != 0 {
        source_attributes
    } else {
        attributes
    };
    Duplicate {
        granted,
        added: granted & !source_granted,
        attributes,
        close_source: options & DUPLICATE_CLOSE_SOURCE != 0,
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
    fn a_duplicate_takes_its_access_and_attributes_as_asked() {
        const SAME: u32 = DUPLICATE_SAME_ACCESS;
        const ATTRIBUTES: u32 = DUPLICATE_SAME_ATTRIBUTES;
        const CLOSE: u32 = DUPLICATE_CLOSE_SOURCE;
        let source = READ | SYNCHRONIZE;
        // (source attributes, desired, attributes, options) ->
        // (granted, added, attributes, close source)
        let cases = [
            // The source's access, whatever was asked for.
            ((INHERIT, 0, PLAIN, SAME), (source, 0, PLAIN, false)),
            ((INHERIT, WRITE, PLAIN, SAME), (source, 0, PLAIN, false)),
            // An explicit mask: fewer rights, none, the same, or more.
            ((PLAIN, READ, PLAIN, 0), (READ, 0, PLAIN, false)),
            ((PLAIN, 0, PLAIN, 0), (0, 0, PLAIN, false)),
            ((PLAIN, source, PLAIN, 0), (source, 0, PLAIN, false)),
            (
                (PLAIN, READ | WRITE, PLAIN, 0),
                (READ | WRITE, WRITE, PLAIN, false),
            ),
            ((PLAIN, WRITE, PLAIN, 0), (WRITE, WRITE, PLAIN, false)),
            // Attributes: as given, or the source's.
            ((PLAIN, READ, INHERIT, 0), (READ, 0, INHERIT, false)),
            ((INHERIT, READ, PROTECTED, 0), (READ, 0, PROTECTED, false)),
            (
                (INHERIT, READ, PROTECTED, ATTRIBUTES),
                (READ, 0, INHERIT, false),
            ),
            (
                (PROTECTED, READ, PLAIN, ATTRIBUTES),
                (READ, 0, PROTECTED, false),
            ),
            // Closing the source changes nothing else.
            ((PLAIN, READ, PLAIN, CLOSE), (READ, 0, PLAIN, true)),
            (
                (PLAIN, WRITE, INHERIT, CLOSE | SAME),
                (source, 0, INHERIT, true),
            ),
            (
                (INHERIT, WRITE, PLAIN, CLOSE | SAME | ATTRIBUTES),
                (source, 0, INHERIT, true),
            ),
            // Bits that are no option do nothing.
            ((PLAIN, WRITE, PLAIN, 0xFFF8), (WRITE, WRITE, PLAIN, false)),
        ];
        for (given, expected) in cases {
            let (source_attributes, desired, attributes, options) = given;
            let got = duplicate(source, source_attributes, desired, attributes, options);
            let (granted, added, attributes, close_source) = expected;
            let expected = Duplicate {
                granted,
                added,
                attributes,
                close_source,
            };
            assert_eq!(got, expected, "{given:?}");
        }
    }
}
