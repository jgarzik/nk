//! The export directory: what an image offers other images, by name and
//! by ordinal.
//!
//! As everywhere in this crate the image is one laid out in memory, the
//! input is untrusted, and a malformed table is an `Err`.

use crate::{DataDir, PeError, cstr_at, u16_at, u32_at};

/// Size of `IMAGE_EXPORT_DIRECTORY`.
const DIRECTORY_SIZE: u32 = 40;

/// What an export leads to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Export<'a> {
    /// Code or data at this RVA of the exporting image.
    Rva(u32),
    /// Another image's export, named `MODULE.Name` or `MODULE.#ordinal`.
    Forward(&'a [u8]),
}

/// An image's export directory.
#[derive(Debug, Clone, Copy)]
pub struct Exports<'a> {
    image: &'a [u8],
    dir: DataDir,
    /// The ordinal of the first entry of the address table.
    base: u32,
    functions: u32,
    names: u32,
    address_table: u32,
    name_table: u32,
    ordinal_table: u32,
}

impl<'a> Exports<'a> {
    /// The exports of `image`, whose export directory is `dir`. `None`
    /// if it has none.
    pub fn parse(image: &'a [u8], dir: DataDir) -> Result<Option<Self>, PeError> {
        if dir.rva == 0 || dir.size == 0 {
            return Ok(None);
        }
        let at = dir.rva as usize;
        if dir.size < DIRECTORY_SIZE
            || (dir.rva as usize)
                .checked_add(dir.size as usize)
                .is_none_or(|end| end > image.len())
        {
            return Err(PeError::OutOfBounds);
        }
        let exports = Self {
            image,
            dir,
            base: u32_at(image, at + 16)?,
            functions: u32_at(image, at + 20)?,
            names: u32_at(image, at + 24)?,
            address_table: u32_at(image, at + 28)?,
            name_table: u32_at(image, at + 32)?,
            ordinal_table: u32_at(image, at + 36)?,
        };
        // Each table lies in the image, whole.
        for (table, entries, size) in [
            (exports.address_table, exports.functions, 4u64),
            (exports.name_table, exports.names, 4),
            (exports.ordinal_table, exports.names, 2),
        ] {
            let end = u64::from(table) + u64::from(entries) * size;
            if entries != 0 && (table == 0 || end > image.len() as u64) {
                return Err(PeError::OutOfBounds);
            }
        }
        Ok(Some(exports))
    }

    /// How many names the image exports.
    pub fn names(&self) -> u32 {
        self.names
    }

    /// The ordinals the address table covers, gaps included.
    pub fn ordinals(&self) -> core::ops::Range<u32> {
        self.base..self.base.saturating_add(self.functions)
    }

    /// The `index`th name, in the table's order (sorted, in a well-made
    /// image), and the ordinal it stands for.
    pub fn name(&self, index: u32) -> Result<(&'a [u8], u32), PeError> {
        if index >= self.names {
            return Err(PeError::OutOfBounds);
        }
        let i = index as usize;
        let name = cstr_at(
            self.image,
            u32_at(self.image, self.name_table as usize + 4 * i)?,
        )?;
        let slot = u16_at(self.image, self.ordinal_table as usize + 2 * i)?;
        Ok((name, self.base.wrapping_add(u32::from(slot))))
    }

    /// The export called `name`. The name table is searched as Windows
    /// searches it, by halving, so a table that is not sorted hides
    /// some of its names.
    pub fn by_name(&self, name: &[u8]) -> Result<Option<Export<'a>>, PeError> {
        let (mut low, mut high) = (0, self.names);
        while low < high {
            let middle = low + (high - low) / 2;
            let (candidate, ordinal) = self.name(middle)?;
            match candidate.cmp(name) {
                core::cmp::Ordering::Equal => return self.by_ordinal(ordinal),
                core::cmp::Ordering::Less => low = middle + 1,
                core::cmp::Ordering::Greater => high = middle,
            }
        }
        Ok(None)
    }

    /// The export numbered `ordinal`.
    pub fn by_ordinal(&self, ordinal: u32) -> Result<Option<Export<'a>>, PeError> {
        let slot = ordinal.wrapping_sub(self.base);
        if slot >= self.functions {
            return Ok(None);
        }
        let rva = u32_at(self.image, self.address_table as usize + 4 * slot as usize)?;
        if rva == 0 {
            // A gap in the ordinals.
            return Ok(None);
        }
        // An address inside the export directory itself is not code:
        // it is the name of another image's export.
        if (self.dir.rva..self.dir.rva + self.dir.size).contains(&rva) {
            return Ok(Some(Export::Forward(cstr_at(self.image, rva)?)));
        }
        Ok(Some(Export::Rva(rva)))
    }
}

/// The two halves of a forwarder, `MODULE.Name`: the module, without an
/// extension, and what it is asked for. `None` if it has no dot or an
/// empty half.
pub fn forward_target(forward: &[u8]) -> Option<(&[u8], &[u8])> {
    // The module may hold dots of its own; the symbol cannot.
    let dot = forward.iter().rposition(|&b| b == b'.')?;
    let (module, symbol) = (&forward[..dot], &forward[dot + 1..]);
    (!module.is_empty() && !symbol.is_empty()).then_some((module, symbol))
}

#[cfg(test)]
mod tests {
    use super::*;

    const DIR: u32 = 0x100;
    const BASE: u32 = 5;

    /// An image whose export directory, at `DIR`, has the address table
    /// `addresses` (from ordinal `BASE`) and `named`: names with the
    /// address-table slot each stands for, in the given order.
    fn image(
        addresses: &[u32],
        named: &[(&str, u16)],
        forwards: &[(usize, &str)],
    ) -> (Vec<u8>, DataDir) {
        let mut image = vec![0u8; 0x1000];
        let put = |image: &mut Vec<u8>, at: usize, v: u32| {
            image[at..at + 4].copy_from_slice(&v.to_le_bytes())
        };
        let address_table = DIR + DIRECTORY_SIZE;
        let name_table = address_table + 4 * addresses.len() as u32;
        let ordinal_table = name_table + 4 * named.len() as u32;
        let mut strings = ordinal_table + 2 * named.len() as u32;
        let dir = DIR as usize;
        put(&mut image, dir + 16, BASE);
        put(&mut image, dir + 20, addresses.len() as u32);
        put(&mut image, dir + 24, named.len() as u32);
        put(&mut image, dir + 28, address_table);
        put(&mut image, dir + 32, name_table);
        put(&mut image, dir + 36, ordinal_table);
        let mut addresses = addresses.to_vec();
        let mut string = |image: &mut Vec<u8>, s: &str| {
            let at = strings;
            image[at as usize..at as usize + s.len()].copy_from_slice(s.as_bytes());
            strings += s.len() as u32 + 1;
            at
        };
        for (slot, target) in forwards {
            addresses[*slot] = string(&mut image, target);
        }
        for (i, address) in addresses.iter().enumerate() {
            put(&mut image, address_table as usize + 4 * i, *address);
        }
        for (i, (name, slot)) in named.iter().enumerate() {
            let at = string(&mut image, name);
            put(&mut image, name_table as usize + 4 * i, at);
            image[ordinal_table as usize + 2 * i..][..2].copy_from_slice(&slot.to_le_bytes());
        }
        let size = strings - DIR;
        (image, DataDir { rva: DIR, size })
    }

    fn sample() -> (Vec<u8>, DataDir) {
        // Slots: 0 Alpha, 1 a gap, 2 by ordinal only, 3 Gamma (a
        // forwarder), 4 Beta.
        image(
            &[0x2000, 0, 0x2020, 0, 0x2040],
            &[("Alpha", 0), ("Beta", 4), ("Gamma", 3)],
            &[(3, "OTHER.Target")],
        )
    }

    #[test]
    fn an_image_without_the_directory_exports_nothing() {
        let image = [0u8; 64];
        assert!(
            Exports::parse(&image, DataDir::default())
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn names_lead_to_addresses() {
        let (image, dir) = sample();
        let e = Exports::parse(&image, dir).unwrap().unwrap();
        assert_eq!(e.names(), 3);
        assert_eq!(e.by_name(b"Alpha"), Ok(Some(Export::Rva(0x2000))));
        assert_eq!(e.by_name(b"Beta"), Ok(Some(Export::Rva(0x2040))));
        assert_eq!(
            e.by_name(b"Gamma"),
            Ok(Some(Export::Forward(b"OTHER.Target")))
        );
        for absent in ["", "Alph", "Alphaa", "Delta", "alpha", "Zeta"] {
            assert_eq!(e.by_name(absent.as_bytes()), Ok(None), "{absent}");
        }
        assert_eq!(e.name(1), Ok((&b"Beta"[..], BASE + 4)));
        assert_eq!(e.name(3), Err(PeError::OutOfBounds));
    }

    #[test]
    fn ordinals_count_from_the_base() {
        let (image, dir) = sample();
        let e = Exports::parse(&image, dir).unwrap().unwrap();
        assert_eq!(e.by_ordinal(BASE), Ok(Some(Export::Rva(0x2000))));
        assert_eq!(e.by_ordinal(BASE + 1), Ok(None), "a gap");
        assert_eq!(e.by_ordinal(BASE + 2), Ok(Some(Export::Rva(0x2020))));
        assert_eq!(
            e.by_ordinal(BASE + 3),
            Ok(Some(Export::Forward(b"OTHER.Target")))
        );
        assert_eq!(e.by_ordinal(BASE + 5), Ok(None), "past the table");
        assert_eq!(e.by_ordinal(BASE - 1), Ok(None), "below the base");
        assert_eq!(e.by_ordinal(0), Ok(None));
        assert_eq!(e.by_ordinal(u32::MAX), Ok(None));
        assert_eq!(e.ordinals(), BASE..BASE + 5);
    }

    #[test]
    fn an_unsorted_name_table_hides_names_as_on_windows() {
        let (image, dir) = image(
            &[0x2000, 0x2010, 0x2020],
            &[("C", 0), ("B", 1), ("A", 2)],
            &[],
        );
        let e = Exports::parse(&image, dir).unwrap().unwrap();
        assert_eq!(e.by_name(b"B"), Ok(Some(Export::Rva(0x2010))));
        assert_eq!(e.by_name(b"A"), Ok(None));
        assert_eq!(e.by_name(b"C"), Ok(None));
    }

    #[test]
    fn tables_outside_the_image_are_refused() {
        let (good, dir) = sample();
        let truncated = DataDir {
            rva: dir.rva,
            size: DIRECTORY_SIZE - 1,
        };
        assert_eq!(
            Exports::parse(&good, truncated).err(),
            Some(PeError::OutOfBounds)
        );
        let beyond = DataDir {
            rva: good.len() as u32 - 8,
            size: 64,
        };
        assert_eq!(
            Exports::parse(&good, beyond).err(),
            Some(PeError::OutOfBounds)
        );
        // Each table's address in turn points past the end, or nowhere.
        for field in [28, 32, 36] {
            for bad in [0u32, good.len() as u32 - 2, u32::MAX] {
                let mut image = good.clone();
                image[DIR as usize + field..][..4].copy_from_slice(&bad.to_le_bytes());
                assert_eq!(
                    Exports::parse(&image, dir).err(),
                    Some(PeError::OutOfBounds),
                    "field {field} = {bad:#x}"
                );
            }
        }
        // A count too large for the image.
        let mut image = good.clone();
        image[DIR as usize + 20..][..4].copy_from_slice(&u32::MAX.to_le_bytes());
        assert_eq!(
            Exports::parse(&image, dir).err(),
            Some(PeError::OutOfBounds)
        );
    }

    #[test]
    fn a_name_or_forwarder_that_runs_off_the_image_is_an_error() {
        let (mut image, dir) = sample();
        let name_table = Exports::parse(&image, dir).unwrap().unwrap().name_table as usize;
        // The first name's address: past the end.
        image[name_table..][..4].copy_from_slice(&0xFFFF_0000u32.to_le_bytes());
        let e = Exports::parse(&image, dir).unwrap().unwrap();
        assert_eq!(e.name(0), Err(PeError::OutOfBounds));
        assert_eq!(
            e.by_name(b"Beta"),
            Ok(Some(Export::Rva(0x2040))),
            "not on the way"
        );
        assert_eq!(e.by_name(b"Alpha"), Err(PeError::OutOfBounds));
        // A forwarder with no terminator before the image ends.
        let mut unterminated = vec![0xAAu8; 0x200];
        unterminated[..0x1C0].copy_from_slice(&image[..0x1C0]);
        let dir = DataDir {
            rva: DIR,
            size: 0x100,
        };
        let slot3 = DIR as usize + DIRECTORY_SIZE as usize + 12;
        unterminated[slot3..][..4].copy_from_slice(&0x1F8u32.to_le_bytes());
        let e = Exports::parse(&unterminated, dir).unwrap().unwrap();
        assert_eq!(e.by_ordinal(BASE + 3), Err(PeError::OutOfBounds));
    }

    #[test]
    fn a_forwarder_names_a_module_and_a_symbol() {
        assert_eq!(
            forward_target(b"NTOSKRNL.RtlZeroMemory"),
            Some((&b"NTOSKRNL"[..], &b"RtlZeroMemory"[..]))
        );
        assert_eq!(forward_target(b"HAL.#12"), Some((&b"HAL"[..], &b"#12"[..])));
        assert_eq!(
            forward_target(b"api-ms-win.core-l1-1-0.Name"),
            Some((&b"api-ms-win.core-l1-1-0"[..], &b"Name"[..]))
        );
        for bad in ["", "NoDot", ".Name", "MODULE."] {
            assert_eq!(forward_target(bad.as_bytes()), None, "{bad}");
        }
    }
}
