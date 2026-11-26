//! Four-level page tables with 4 KiB pages.
//!
//! x86-64 and arm64 (4 KiB granule, 48-bit addresses) share the same tree
//! shape: four levels of 512 entries. Only the entry encoding differs, and
//! that is the [`Arch`] trait. Both encodings live here so the host tests
//! cover both.
//!
//! Levels are numbered from the leaf: level 0 maps 4 KiB pages, level 1
//! 2 MiB, level 2 1 GiB, level 3 is the root table.

use crate::PAGE_SIZE;

/// What a mapping allows. Kernel-only mappings; there is no user mode yet.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Prot {
    pub write: bool,
    pub exec: bool,
    /// Device registers rather than RAM (arm64: device memory attributes).
    pub device: bool,
}

impl Prot {
    pub const RO: Self = Self {
        write: false,
        exec: false,
        device: false,
    };
    pub const RW: Self = Self {
        write: true,
        exec: false,
        device: false,
    };
    pub const RX: Self = Self {
        write: false,
        exec: true,
        device: false,
    };
    pub const RWX: Self = Self {
        write: true,
        exec: true,
        device: false,
    };
    pub const DEVICE: Self = Self {
        write: true,
        exec: false,
        device: true,
    };
}

/// Page-table entry encoding for one architecture.
pub trait Arch {
    /// Entry pointing at a next-level table at physical address `pa`.
    fn table(&self, pa: u64) -> u64;
    /// Entry mapping `pa` at `level` (0 = 4 KiB, 1 = 2 MiB, 2 = 1 GiB).
    fn leaf(&self, pa: u64, level: u8, prot: Prot) -> u64;
    fn present(&self, entry: u64) -> bool;
    /// True if a present entry at `level` maps memory rather than a table.
    fn is_leaf(&self, entry: u64, level: u8) -> bool;
    /// True if a leaf entry lets the kernel write what it maps.
    fn writable(&self, entry: u64) -> bool;
    /// Physical address held in a present entry.
    fn addr(&self, entry: u64) -> u64 {
        entry & 0x0000_FFFF_FFFF_F000
    }
}

pub struct X86_64;

impl Arch for X86_64 {
    fn table(&self, pa: u64) -> u64 {
        pa | 0b11 // present, writable; leaf entries carry the real protection
    }

    fn leaf(&self, pa: u64, level: u8, prot: Prot) -> u64 {
        const PRESENT: u64 = 1;
        const WRITE: u64 = 1 << 1;
        const HUGE: u64 = 1 << 7;
        const GLOBAL: u64 = 1 << 8;
        const NX: u64 = 1 << 63;
        let mut e = pa | PRESENT | GLOBAL;
        if prot.write {
            e |= WRITE;
        }
        if level > 0 {
            e |= HUGE;
        }
        if !prot.exec {
            e |= NX;
        }
        e
    }

    fn present(&self, entry: u64) -> bool {
        entry & 1 != 0
    }

    fn is_leaf(&self, entry: u64, level: u8) -> bool {
        level == 0 || entry & (1 << 7) != 0
    }

    fn writable(&self, entry: u64) -> bool {
        entry & (1 << 1) != 0
    }
}

/// arm64 stage-1 EL1 encoding. The memory-attribute indices depend on what
/// `MAIR_EL1` holds, which the loader inherits from firmware.
pub struct Aarch64 {
    pub mair_normal: u8,
    pub mair_device: u8,
}

/// What `MAIR_EL1`, as firmware left it, lacks.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MairError {
    /// No attribute for write-back cacheable normal memory.
    NoNormal,
    /// No attribute for device memory.
    NoDevice,
}

/// `MAIR` attribute encodings.
const ATTR_NORMAL_WB: u8 = 0xFF;
const ATTR_DEVICE_NGNRNE: u8 = 0x00;
const ATTR_DEVICE_NGNRE: u8 = 0x04;

impl Aarch64 {
    /// Find the attribute indices to use in a `MAIR_EL1` value that is
    /// someone else's to define: its eight bytes are attributes 0 to 7.
    /// Normal memory is write-back cacheable; device memory is the
    /// strictest kind the register offers (nGnRnE, else nGnRE).
    pub fn from_mair(mair: u64) -> Result<Self, MairError> {
        let find = |attr: u8| mair.to_le_bytes().iter().position(|&a| a == attr);
        let normal = find(ATTR_NORMAL_WB).ok_or(MairError::NoNormal)?;
        let device = find(ATTR_DEVICE_NGNRNE)
            .or_else(|| find(ATTR_DEVICE_NGNRE))
            .ok_or(MairError::NoDevice)?;
        Ok(Self {
            mair_normal: normal as u8,
            mair_device: device as u8,
        })
    }
}

impl Arch for Aarch64 {
    fn table(&self, pa: u64) -> u64 {
        pa | 0b11
    }

    fn leaf(&self, pa: u64, level: u8, prot: Prot) -> u64 {
        const VALID: u64 = 1;
        const PAGE: u64 = 1 << 1; // at level 0; clear means "block" above it
        const AP_RO: u64 = 1 << 7;
        const SH_INNER: u64 = 3 << 8;
        const AF: u64 = 1 << 10;
        const PXN: u64 = 1 << 53;
        const UXN: u64 = 1 << 54;
        let index = if prot.device {
            self.mair_device
        } else {
            self.mair_normal
        };
        let mut e = pa | VALID | AF | UXN | (u64::from(index) << 2);
        if level == 0 {
            e |= PAGE;
        }
        if !prot.device {
            e |= SH_INNER;
        }
        if !prot.write {
            e |= AP_RO;
        }
        if !prot.exec {
            e |= PXN;
        }
        e
    }

    fn present(&self, entry: u64) -> bool {
        entry & 1 != 0
    }

    fn is_leaf(&self, entry: u64, level: u8) -> bool {
        level == 0 || entry & 0b10 == 0
    }

    fn writable(&self, entry: u64) -> bool {
        // AP[2]: read-only.
        entry & (1 << 7) == 0
    }
}

/// Storage for page tables: allocates them and reads/writes their entries
/// by physical address.
pub trait TableMem {
    /// A new, zeroed table. Returns its physical address.
    fn alloc_table(&mut self) -> Option<u64>;
    fn read(&self, table: u64, index: usize) -> u64;
    fn write(&mut self, table: u64, index: usize, entry: u64);
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MapError {
    /// No memory for an intermediate table.
    NoMemory,
    /// The address is already mapped (possibly by a larger page).
    AlreadyMapped,
    /// Address or length not aligned to the page size used.
    Unaligned,
}

fn index(va: u64, level: u8) -> usize {
    ((va >> (12 + 9 * u32::from(level))) & 0x1FF) as usize
}

pub fn level_size(level: u8) -> u64 {
    PAGE_SIZE << (9 * u32::from(level))
}

/// Map one page of `level_size(level)` bytes at `va` to `pa`.
pub fn map(
    mem: &mut impl TableMem,
    arch: &impl Arch,
    root: u64,
    va: u64,
    pa: u64,
    level: u8,
    prot: Prot,
) -> Result<(), MapError> {
    let size = level_size(level);
    if level > 2 || !va.is_multiple_of(size) || !pa.is_multiple_of(size) {
        return Err(MapError::Unaligned);
    }
    let mut table = root;
    for l in (level + 1..=3).rev() {
        let e = mem.read(table, index(va, l));
        table = if !arch.present(e) {
            let next = mem.alloc_table().ok_or(MapError::NoMemory)?;
            mem.write(table, index(va, l), arch.table(next));
            next
        } else if arch.is_leaf(e, l) {
            return Err(MapError::AlreadyMapped);
        } else {
            arch.addr(e)
        };
    }
    if arch.present(mem.read(table, index(va, level))) {
        return Err(MapError::AlreadyMapped);
    }
    mem.write(table, index(va, level), arch.leaf(pa, level, prot));
    Ok(())
}

/// Map `len` bytes at `va` to `pa`, using pages up to `max_level` in size
/// wherever alignment allows.
#[allow(
    clippy::too_many_arguments,
    reason = "a mapping is this many independent facts"
)]
pub fn map_range(
    mem: &mut impl TableMem,
    arch: &impl Arch,
    root: u64,
    mut va: u64,
    mut pa: u64,
    len: u64,
    max_level: u8,
    prot: Prot,
) -> Result<(), MapError> {
    if !(va | pa | len).is_multiple_of(PAGE_SIZE) {
        return Err(MapError::Unaligned);
    }
    let end = va + len;
    while va < end {
        let level = (0..=max_level.min(2))
            .rev()
            .find(|&l| (va | pa).is_multiple_of(level_size(l)) && end - va >= level_size(l))
            .unwrap_or(0);
        map(mem, arch, root, va, pa, level, prot)?;
        va += level_size(level);
        pa += level_size(level);
    }
    Ok(())
}

/// The physical address `va` maps to, if any.
pub fn translate(mem: &impl TableMem, arch: &impl Arch, root: u64, va: u64) -> Option<u64> {
    lookup(mem, arch, root, va).map(|(pa, _)| pa)
}

/// The physical address `va` maps to, if any, and whether the mapping
/// may be written: the leaf entry's protection, which is where `map`
/// puts it.
pub fn lookup(mem: &impl TableMem, arch: &impl Arch, root: u64, va: u64) -> Option<(u64, bool)> {
    let mut table = root;
    for l in (0..=3u8).rev() {
        let e = mem.read(table, index(va, l));
        if !arch.present(e) {
            return None;
        }
        if l < 3 && arch.is_leaf(e, l) {
            let pa = arch.addr(e) & !(level_size(l) - 1) | va & (level_size(l) - 1);
            return Some((pa, arch.writable(e)));
        }
        table = arch.addr(e);
    }
    None
}

/// Remove the 4 KiB mapping at `va`. Returns the physical page it mapped.
/// Intermediate tables are kept. The caller flushes the TLB.
pub fn unmap(mem: &mut impl TableMem, arch: &impl Arch, root: u64, va: u64) -> Option<u64> {
    let mut table = root;
    for l in (1..=3u8).rev() {
        let e = mem.read(table, index(va, l));
        if !arch.present(e) || arch.is_leaf(e, l) {
            return None;
        }
        table = arch.addr(e);
    }
    let e = mem.read(table, index(va, 0));
    if !arch.present(e) {
        return None;
    }
    mem.write(table, index(va, 0), 0);
    Some(arch.addr(e))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    /// Tables kept in a map keyed by fake physical address.
    #[derive(Default)]
    struct Mem {
        tables: HashMap<u64, [u64; 512]>,
        limit: Option<usize>,
    }

    impl Mem {
        fn root(&mut self) -> u64 {
            self.alloc_table().unwrap()
        }
    }

    impl TableMem for Mem {
        fn alloc_table(&mut self) -> Option<u64> {
            if self.limit.is_some_and(|l| self.tables.len() >= l) {
                return None;
            }
            let pa = 0x10_0000 + 0x1000 * self.tables.len() as u64;
            self.tables.insert(pa, [0; 512]);
            Some(pa)
        }
        fn read(&self, table: u64, index: usize) -> u64 {
            self.tables[&table][index]
        }
        fn write(&mut self, table: u64, index: usize, entry: u64) {
            self.tables.get_mut(&table).unwrap()[index] = entry;
        }
    }

    const ARM: Aarch64 = Aarch64 {
        mair_normal: 3,
        mair_device: 0,
    };
    const KVA: u64 = 0xFFFF_F800_0000_0000;

    #[test]
    fn a_lookup_says_whether_the_mapping_may_be_written() {
        fn check(arch: &impl Arch) {
            let mut m = Mem::default();
            let root = m.root();
            for (i, prot) in [Prot::RO, Prot::RW, Prot::RX, Prot::RWX, Prot::DEVICE]
                .into_iter()
                .enumerate()
            {
                let small = KVA + 0x1000 * i as u64;
                let large = KVA + 0x4000_0000 + 0x20_0000 * i as u64;
                map(&mut m, arch, root, small, 0x20_5000, 0, prot).unwrap();
                map(&mut m, arch, root, large, 0x4000_0000, 1, prot).unwrap();
                assert_eq!(
                    lookup(&m, arch, root, small + 0x123),
                    Some((0x20_5123, prot.write))
                );
                assert_eq!(
                    lookup(&m, arch, root, large + 0x12_3456),
                    Some((0x4012_3456, prot.write))
                );
            }
            assert_eq!(lookup(&m, arch, root, KVA + 0x8000), None);
        }
        check(&X86_64);
        check(&ARM);
    }

    #[test]
    fn map_translate_unmap_4k() {
        let mut m = Mem::default();
        let root = m.root();
        map(&mut m, &X86_64, root, KVA + 0x3000, 0x20_5000, 0, Prot::RW).unwrap();
        assert_eq!(m.tables.len(), 4, "root plus three intermediate tables");
        assert_eq!(translate(&m, &X86_64, root, KVA + 0x3123), Some(0x20_5123));
        assert_eq!(translate(&m, &X86_64, root, KVA + 0x4000), None);
        assert_eq!(unmap(&mut m, &X86_64, root, KVA + 0x3000), Some(0x20_5000));
        assert_eq!(translate(&m, &X86_64, root, KVA + 0x3000), None);
        assert_eq!(unmap(&mut m, &X86_64, root, KVA + 0x3000), None);
    }

    #[test]
    fn double_map_is_refused() {
        let mut m = Mem::default();
        let root = m.root();
        map(&mut m, &ARM, root, 0x4000_0000, 0x4000_0000, 1, Prot::RW).unwrap();
        assert_eq!(
            map(&mut m, &ARM, root, 0x4000_0000, 0, 1, Prot::RW),
            Err(MapError::AlreadyMapped)
        );
        // A 4 KiB page inside an existing 2 MiB block.
        assert_eq!(
            map(&mut m, &ARM, root, 0x4000_1000, 0, 0, Prot::RW),
            Err(MapError::AlreadyMapped)
        );
    }

    #[test]
    fn unaligned_and_oom() {
        let mut m = Mem::default();
        let root = m.root();
        assert_eq!(
            map(&mut m, &X86_64, root, 0x1234, 0, 0, Prot::RW),
            Err(MapError::Unaligned)
        );
        assert_eq!(
            map(&mut m, &X86_64, root, 0x20_0000, 0x1000, 1, Prot::RW),
            Err(MapError::Unaligned)
        );
        assert_eq!(
            map_range(&mut m, &X86_64, root, 0, 0, 0x1001, 2, Prot::RW),
            Err(MapError::Unaligned)
        );
        m.limit = Some(2);
        assert_eq!(
            map(&mut m, &X86_64, root, 0, 0, 0, Prot::RW),
            Err(MapError::NoMemory)
        );
    }

    #[test]
    fn range_uses_large_pages_where_aligned() {
        let mut m = Mem::default();
        let root = m.root();
        // 4 KiB head, 2 MiB middle, 4 KiB tail.
        let (va, len) = (0x1FF000, 0x1000 + 0x20_0000 + 0x2000);
        map_range(&mut m, &X86_64, root, va, va, len, 1, Prot::RW).unwrap();
        for off in [0, 0x1000, 0x10_0000, 0x20_1000, 0x20_2000] {
            assert_eq!(
                translate(&m, &X86_64, root, va + off + 5),
                Some(va + off + 5)
            );
        }
        assert_eq!(translate(&m, &X86_64, root, va + len), None);
        // root, one L2, one L1, two L0 tables (head and tail); the middle is a block.
        assert_eq!(m.tables.len(), 5);
        // 1 GiB pages when allowed.
        let mut g = Mem::default();
        let root = g.root();
        map_range(&mut g, &X86_64, root, 0, 0, 2 << 30, 2, Prot::RW).unwrap();
        assert_eq!(g.tables.len(), 2);
        assert_eq!(translate(&g, &X86_64, root, 0x7FFF_FFFF), Some(0x7FFF_FFFF));
    }

    #[test]
    fn x86_entry_bits() {
        let a = X86_64;
        assert_eq!(a.leaf(0x5000, 0, Prot::RW), 0x5000 | 0x103 | 1 << 63);
        assert_eq!(a.leaf(0x5000, 0, Prot::RX), 0x5000 | 0x101);
        assert_eq!(a.leaf(0x20_0000, 1, Prot::RO), 0x20_0000 | 0x181 | 1 << 63);
        assert_eq!(a.table(0x7000), 0x7003);
        assert!(a.is_leaf(a.leaf(0x20_0000, 1, Prot::RW), 1) && !a.is_leaf(a.table(0x7000), 1));
        assert_eq!(a.addr(a.leaf(0x1_2345_6000, 0, Prot::RO)), 0x1_2345_6000);
    }

    fn indices(mair: u64) -> Result<(u8, u8), MairError> {
        Aarch64::from_mair(mair).map(|a| (a.mair_normal, a.mair_device))
    }

    #[test]
    fn mair_indices_are_found_wherever_firmware_put_them() {
        // EDK2's value: device, non-cacheable, write-through, write-back.
        assert_eq!(indices(0xFFBB_4400), Ok((3, 0)));
        // The other way round, and in the top bytes.
        assert_eq!(indices(0xBB44_00FF), Ok((0, 1)));
        assert_eq!(indices(0xFF00_4444_4444_4444), Ok((7, 6)));
        // Listed twice: the lower index.
        assert_eq!(indices(0x00FF_00FF_4444_4444), Ok((4, 5)));
    }

    #[test]
    fn the_strictest_device_attribute_is_preferred() {
        // nGnRE at index 0, nGnRnE at index 2: the latter, though later.
        assert_eq!(indices(0x4444_4444_FF00_4404), Ok((3, 2)));
        // Only nGnRE on offer.
        assert_eq!(indices(0x4444_4444_44FF_4404), Ok((2, 0)));
    }

    #[test]
    fn a_mair_without_what_nk_needs_is_refused() {
        // Device memory but only non-cacheable normal memory.
        assert_eq!(indices(0x4444_4444_4444_4400), Err(MairError::NoNormal));
        // Normal memory but no device attribute NK knows.
        assert_eq!(indices(0xFFFF_FFFF_FFFF_FFFF), Err(MairError::NoDevice));
        assert_eq!(indices(0x4444_4444_4444_08FF), Err(MairError::NoDevice));
        // A register never written: all device, no normal memory.
        assert_eq!(indices(0), Err(MairError::NoNormal));
    }

    #[test]
    fn entries_carry_the_indices_found_in_mair() {
        let a = Aarch64::from_mair(0xFFBB_4400).unwrap();
        // Attribute index is bits 2-4 of a leaf entry.
        assert_eq!(a.leaf(0x1000, 0, Prot::RW) >> 2 & 7, 3);
        assert_eq!(a.leaf(0x1000, 0, Prot::DEVICE) >> 2 & 7, 0);
    }

    #[test]
    fn arm64_entry_bits() {
        let a = ARM;
        // Page, normal memory (index 3), inner shareable, AF, UXN; RW so no AP_RO; NX so PXN.
        assert_eq!(
            a.leaf(0x5000, 0, Prot::RW),
            0x5000 | 0b11 | 3 << 2 | 3 << 8 | 1 << 10 | 3 << 53
        );
        // Executable kernel text: read-only, PXN clear, UXN still set.
        assert_eq!(
            a.leaf(0x5000, 0, Prot::RX),
            0x5000 | 0b11 | 3 << 2 | 1 << 7 | 3 << 8 | 1 << 10 | 1 << 54
        );
        // 2 MiB device block: index 0, not shareable, bit 1 clear.
        assert_eq!(
            a.leaf(0x20_0000, 1, Prot::DEVICE),
            0x20_0000 | 1 | 1 << 10 | 3 << 53
        );
        assert!(a.is_leaf(a.leaf(0x20_0000, 1, Prot::RW), 1) && !a.is_leaf(a.table(0x7000), 1));
        assert_eq!(a.addr(a.leaf(0x1_2345_6000, 0, Prot::RX)), 0x1_2345_6000);
    }
}
