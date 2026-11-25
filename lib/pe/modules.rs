//! The table of loaded images: which image an address is in, and where
//! that image keeps its function table.

use crate::DataDir;

/// The longest image name kept, in bytes.
pub const NAME_MAX: usize = 47;

/// One loaded image.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Module {
    name: [u8; NAME_MAX],
    name_len: u8,
    pub base: u64,
    pub size: u64,
    /// The image's exception directory (`.pdata`), empty if it has none.
    pub pdata: DataDir,
}

impl Module {
    /// `None` if the name is longer than [`NAME_MAX`] or the image is
    /// empty or wraps the address space.
    pub fn new(name: &[u8], base: u64, size: u64, pdata: DataDir) -> Option<Self> {
        if name.len() > NAME_MAX || size == 0 || base.checked_add(size).is_none() {
            return None;
        }
        let mut copy = [0; NAME_MAX];
        copy[..name.len()].copy_from_slice(name);
        Some(Self {
            name: copy,
            name_len: name.len() as u8,
            base,
            size,
            pdata,
        })
    }

    /// The image's file name.
    pub fn name(&self) -> &[u8] {
        &self.name[..usize::from(self.name_len)]
    }

    pub fn contains(&self, address: u64) -> bool {
        (self.base..self.base + self.size).contains(&address)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InsertError {
    /// Every slot is taken.
    Full,
    /// The image's addresses are partly another image's.
    Overlaps,
}

/// Up to `N` loaded images. It holds no memory beyond itself, so it can
/// be searched and changed at any IRQL.
#[derive(Debug)]
pub struct Modules<const N: usize> {
    slots: [Option<Module>; N],
}

impl<const N: usize> Modules<N> {
    pub const fn new() -> Self {
        Self { slots: [None; N] }
    }

    pub fn insert(&mut self, module: Module) -> Result<(), InsertError> {
        let end = module.base + module.size;
        if self
            .slots
            .iter()
            .flatten()
            .any(|m| module.base < m.base + m.size && m.base < end)
        {
            return Err(InsertError::Overlaps);
        }
        let slot = self
            .slots
            .iter_mut()
            .find(|s| s.is_none())
            .ok_or(InsertError::Full)?;
        *slot = Some(module);
        Ok(())
    }

    /// Take out the image loaded at `base`.
    pub fn remove(&mut self, base: u64) -> Option<Module> {
        self.slots
            .iter_mut()
            .find(|s| s.is_some_and(|m| m.base == base))?
            .take()
    }

    /// The image `address` is in.
    pub fn containing(&self, address: u64) -> Option<Module> {
        self.slots
            .iter()
            .flatten()
            .copied()
            .find(|m| m.contains(address))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn module(name: &str, base: u64, size: u64) -> Module {
        Module::new(name.as_bytes(), base, size, DataDir::default()).unwrap()
    }

    #[test]
    fn a_module_keeps_its_name_and_range() {
        let pdata = DataDir {
            rva: 0x3000,
            size: 0x24,
        };
        let m = Module::new(b"sioctl.sys", 0x1000, 0x2000, pdata).unwrap();
        assert_eq!(m.name(), b"sioctl.sys");
        assert_eq!(m.pdata, pdata);
        assert!(!m.contains(0xFFF));
        assert!(m.contains(0x1000));
        assert!(m.contains(0x2FFF));
        assert!(!m.contains(0x3000));
    }

    #[test]
    fn a_module_that_cannot_be_described_is_refused() {
        let dir = DataDir::default();
        assert!(Module::new(&[b'a'; NAME_MAX], 0x1000, 1, dir).is_some());
        assert!(Module::new(&[b'a'; NAME_MAX + 1], 0x1000, 1, dir).is_none());
        assert!(Module::new(b"empty", 0x1000, 0, dir).is_none());
        assert!(Module::new(b"wraps", u64::MAX, 2, dir).is_none());
        assert!(Module::new(b"last", u64::MAX, 1, dir).is_none());
    }

    #[test]
    fn an_address_finds_its_image() {
        let mut table = Modules::<4>::new();
        table.insert(module("a.sys", 0x1000, 0x1000)).unwrap();
        table.insert(module("b.sys", 0x2000, 0x1000)).unwrap();
        assert_eq!(table.containing(0x1FFF).unwrap().name(), b"a.sys");
        assert_eq!(table.containing(0x2000).unwrap().name(), b"b.sys");
        assert_eq!(table.containing(0x3000), None);
        assert_eq!(table.containing(0xFFF), None);
    }

    #[test]
    fn overlapping_images_are_refused() {
        let mut table = Modules::<4>::new();
        table.insert(module("a.sys", 0x2000, 0x2000)).unwrap();
        for (base, size) in [
            (0x2000, 0x2000),
            (0x1000, 0x1001),
            (0x3FFF, 0x10),
            (0x2800, 0x100),
            (0x1000, 0x8000),
        ] {
            assert_eq!(
                table.insert(module("b.sys", base, size)),
                Err(InsertError::Overlaps),
                "{base:#x}+{size:#x}"
            );
        }
        // Touching is not overlapping.
        table.insert(module("below.sys", 0x1000, 0x1000)).unwrap();
        table.insert(module("above.sys", 0x4000, 0x1000)).unwrap();
    }

    #[test]
    fn a_full_table_refuses_and_a_removed_slot_is_reused() {
        let mut table = Modules::<2>::new();
        table.insert(module("a.sys", 0x1000, 0x1000)).unwrap();
        table.insert(module("b.sys", 0x2000, 0x1000)).unwrap();
        assert_eq!(
            table.insert(module("c.sys", 0x3000, 0x1000)),
            Err(InsertError::Full)
        );
        // Only a base address names an image to remove.
        assert_eq!(table.remove(0x1800), None);
        assert_eq!(table.remove(0x1000).unwrap().name(), b"a.sys");
        assert_eq!(table.remove(0x1000), None);
        assert_eq!(table.containing(0x1000), None);
        table.insert(module("c.sys", 0x3000, 0x1000)).unwrap();
        assert_eq!(table.containing(0x3000).unwrap().name(), b"c.sys");
        assert_eq!(table.containing(0x2000).unwrap().name(), b"b.sys");
    }
}
