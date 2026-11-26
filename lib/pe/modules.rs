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
    /// Where the kernel reads the image's bytes: an address at which all
    /// `size` bytes are mapped and none can be written.
    pub view: u64,
    /// The image's export directory, empty if it exports nothing.
    pub exports: DataDir,
    /// Loaded because another image imports from it (an export driver),
    /// not started as a driver.
    pub library: bool,
    /// How many loaded images import from it: what keeps a library
    /// loaded.
    pub references: u32,
    /// Its place in the order images were loaded in, given when it is
    /// entered in a table.
    order: u64,
}

impl Module {
    /// `None` if the name is longer than [`NAME_MAX`] or the image is
    /// empty or wraps the address space.
    pub fn new(name: &[u8], base: u64, size: u64, pdata: DataDir, view: u64) -> Option<Self> {
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
            view,
            exports: DataDir::default(),
            library: false,
            references: 0,
            order: 0,
        })
    }

    /// The image's file name without its extension: what a forwarded
    /// export names a module by (`NTOSKRNL.Name`).
    pub fn stem(&self) -> &[u8] {
        let name = self.name();
        match name.iter().rposition(|&b| b == b'.') {
            Some(dot) => &name[..dot],
            None => name,
        }
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
    /// How many images were ever entered.
    entered: u64,
}

impl<const N: usize> Modules<N> {
    pub const fn new() -> Self {
        Self {
            slots: [None; N],
            entered: 0,
        }
    }

    pub fn insert(&mut self, mut module: Module) -> Result<(), InsertError> {
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
        self.entered += 1;
        module.order = self.entered;
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

    /// The image whose file name is `name`, whatever the letter case.
    pub fn named(&self, name: &[u8]) -> Option<Module> {
        self.slots
            .iter()
            .flatten()
            .copied()
            .find(|m| m.name().eq_ignore_ascii_case(name))
    }

    /// The image whose file name without its extension is `stem`,
    /// whatever the letter case.
    pub fn with_stem(&self, stem: &[u8]) -> Option<Module> {
        self.slots
            .iter()
            .flatten()
            .copied()
            .find(|m| m.stem().eq_ignore_ascii_case(stem))
    }

    /// Count one more importer of the image loaded at `base`, or one
    /// fewer (`by` is 1 or -1). Returns how many it has now; `None` if
    /// no image is loaded there or the count would leave its range.
    pub fn count_importer(&mut self, base: u64, by: i32) -> Option<u32> {
        let module = self.slots.iter_mut().flatten().find(|m| m.base == base)?;
        module.references = module.references.checked_add_signed(by)?;
        Some(module.references)
    }

    /// Hand the images to `take`, oldest load first, for as long as it
    /// takes them (it says so by returning `true`), and return how many
    /// there are. Nothing is allocated here.
    pub fn in_load_order(&self, mut take: impl FnMut(Module) -> bool) -> usize {
        let mut count = 0;
        let mut after = 0;
        let mut taking = true;
        // Each pass finds the oldest image not yet handed over.
        while let Some(next) = self
            .slots
            .iter()
            .flatten()
            .filter(|m| m.order > after)
            .min_by_key(|m| m.order)
        {
            taking = taking && take(*next);
            after = next.order;
            count += 1;
        }
        count
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
        Module::new(name.as_bytes(), base, size, DataDir::default(), 0).unwrap()
    }

    #[test]
    fn a_module_keeps_its_name_and_range() {
        let pdata = DataDir {
            rva: 0x3000,
            size: 0x24,
        };
        let m = Module::new(b"sioctl.sys", 0x1000, 0x2000, pdata, 0x9000).unwrap();
        assert_eq!(m.name(), b"sioctl.sys");
        assert_eq!(m.pdata, pdata);
        assert_eq!(m.view, 0x9000);
        assert!(!m.contains(0xFFF));
        assert!(m.contains(0x1000));
        assert!(m.contains(0x2FFF));
        assert!(!m.contains(0x3000));
    }

    #[test]
    fn a_module_that_cannot_be_described_is_refused() {
        let dir = DataDir::default();
        assert!(Module::new(&[b'a'; NAME_MAX], 0x1000, 1, dir, 0).is_some());
        assert!(Module::new(&[b'a'; NAME_MAX + 1], 0x1000, 1, dir, 0).is_none());
        assert!(Module::new(b"empty", 0x1000, 0, dir, 0).is_none());
        assert!(Module::new(b"wraps", u64::MAX, 2, dir, 0).is_none());
        assert!(Module::new(b"last", u64::MAX, 1, dir, 0).is_none());
    }

    #[test]
    fn images_are_listed_in_the_order_they_were_loaded() {
        let mut table = Modules::<4>::new();
        table.insert(module("kernel", 0x9000, 0x1000)).unwrap();
        table.insert(module("a.sys", 0x1000, 0x1000)).unwrap();
        table.insert(module("b.sys", 0x2000, 0x1000)).unwrap();
        // An unloaded image's slot goes to the next one loaded, which is
        // still the newest.
        table.remove(0x1000).unwrap();
        table.insert(module("c.sys", 0x5000, 0x1000)).unwrap();
        let mut out = Vec::new();
        let all = |out: &mut Vec<Module>, room: usize, table: &Modules<4>| {
            out.clear();
            table.in_load_order(|module| {
                let fits = out.len() < room;
                if fits {
                    out.push(module);
                }
                fits
            })
        };
        assert_eq!(all(&mut out, 4, &table), 3);
        let names: Vec<&[u8]> = out.iter().map(|m| m.name()).collect();
        assert_eq!(names, [&b"kernel"[..], b"b.sys", b"c.sys"]);
        // With too little room the count is still all of them, and
        // nothing is offered once one was declined.
        assert_eq!(all(&mut out, 1, &table), 3);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].name(), b"kernel");
        let mut offered = 0;
        let count = table.in_load_order(|_| {
            offered += 1;
            false
        });
        assert_eq!((count, offered), (3, 1));
        assert_eq!(all(&mut out, 4, &Modules::<4>::new()), 0);
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
    fn an_image_is_found_by_its_file_name_and_by_its_stem() {
        let mut table = Modules::<4>::new();
        table
            .insert(module("ntoskrnl.exe", 0x1000, 0x1000))
            .unwrap();
        table.insert(module("nkc-lib.sys", 0x2000, 0x1000)).unwrap();
        table.insert(module("a.b.sys", 0x3000, 0x1000)).unwrap();
        table.insert(module("bare", 0x4000, 0x1000)).unwrap();
        assert_eq!(table.named(b"NKC-LIB.SYS").unwrap().base, 0x2000);
        assert_eq!(table.named(b"nkc-lib"), None);
        assert_eq!(table.named(b"nkc-lib.sy"), None);
        assert_eq!(table.with_stem(b"NTOSKRNL").unwrap().base, 0x1000);
        assert_eq!(table.with_stem(b"nkc-lib").unwrap().base, 0x2000);
        // Only the last dot ends the stem.
        assert_eq!(table.with_stem(b"a.b").unwrap().base, 0x3000);
        assert_eq!(table.with_stem(b"a"), None);
        assert_eq!(table.with_stem(b"bare").unwrap().base, 0x4000);
        assert_eq!(table.with_stem(b"nkc-lib.sys"), None);
    }

    #[test]
    fn importers_are_counted_per_image() {
        let mut table = Modules::<4>::new();
        let mut library = module("nkc-lib.sys", 0x2000, 0x1000);
        library.library = true;
        library.exports = DataDir {
            rva: 0x800,
            size: 0x60,
        };
        table.insert(library).unwrap();
        table.insert(module("user.sys", 0x4000, 0x1000)).unwrap();
        assert_eq!(table.count_importer(0x2000, 1), Some(1));
        assert_eq!(table.count_importer(0x2000, 1), Some(2));
        assert_eq!(table.count_importer(0x2000, -1), Some(1));
        let found = table.named(b"nkc-lib.sys").unwrap();
        assert_eq!((found.references, found.library), (1, true));
        assert_eq!(found.exports.rva, 0x800);
        assert_eq!(table.named(b"user.sys").unwrap().references, 0);
        assert_eq!(table.count_importer(0x2000, -1), Some(0));
        // Never below none; only a base address names an image.
        assert_eq!(table.count_importer(0x2000, -1), None);
        assert_eq!(table.count_importer(0x2800, 1), None);
        assert_eq!(table.containing(0x2000).unwrap().references, 0);
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
