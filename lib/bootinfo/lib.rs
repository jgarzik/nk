//! The block `nkload` hands to the kernel.
//!
//! This is NK's private contract between its own loader and kernel. No
//! driver sees it, so it deliberately does not imitate the Windows loader
//! parameter block. Both sides are built from the same source; `MAGIC` and
//! `VERSION` catch a stale loader paired with a new kernel.
//!
//! All addresses in the block are physical. The kernel reaches them through
//! the direct map at [`BootInfo::hhdm_base`].

#![cfg_attr(not(test), no_std)]

pub mod entropy;
pub mod sha512;

pub const MAGIC: u64 = u64::from_le_bytes(*b"NKBOOT\0\0");
pub const VERSION: u32 = 8;

/// Where the loader maps things. Fixed, so the kernel can be linked and
/// debugged against known addresses.
pub const HHDM_BASE: u64 = 0xFFFF_8000_0000_0000;
pub const KERNEL_BASE: u64 = 0xFFFF_F800_0000_0000;

/// How many boot files the loader can hand over. The table is part of
/// [`BootInfo`], which the loader allocates by its size: an entry costs
/// its 48 bytes and nothing else.
pub const MAX_MODULES: usize = 128;
/// Room for a boot file's name. A longer name is cut short, and the
/// kernel then finds no file of the full name.
pub const MODULE_NAME_LEN: usize = 32;
/// The name of the module that is the SYSTEM registry hive.
pub const HIVE_MODULE: &str = "SYSTEM";
/// The name of the module that is the registry overlay: keys and
/// values as text, to lay over the hive.
pub const OVERLAY_MODULE: &str = "OVERLAY";
/// Room for the kernel command line, including its NUL padding.
pub const CMDLINE_LEN: usize = 256;

/// Size of every kernel stack, the boot stack included.
///
/// A stack's top is a multiple of twice this size, so an address on the
/// stack has bit `KERNEL_STACK_SHIFT` set and the `KERNEL_STACK_SIZE`
/// bytes below the stack have it clear. That lets exception entry tell
/// that the stack has overflowed from the stack pointer alone, before it
/// stores anything (arm64, which takes exceptions on the current stack).
pub const KERNEL_STACK_SIZE: u64 = 1 << KERNEL_STACK_SHIFT;
pub const KERNEL_STACK_SHIFT: u32 = 15;

/// The highest stack top inside `len` bytes at `start`: a multiple of
/// twice the stack size with a whole stack below it. `None` if the range
/// has room for none; three stack sizes always do.
pub const fn stack_top_in(start: u64, len: u64) -> Option<u64> {
    let top = (start + len) & !(2 * KERNEL_STACK_SIZE - 1);
    if top >= start + KERNEL_STACK_SIZE && len >= KERNEL_STACK_SIZE {
        Some(top)
    } else {
        None
    }
}

/// Whether `address` lies in the unmapped stretch below the kernel stack
/// whose lowest address is `base`: where an overflowing stack lands.
/// A `base` of 0 means "no stack recorded" and matches nothing.
pub const fn below_stack(base: u64, address: u64) -> bool {
    base >= KERNEL_STACK_SIZE && address < base && address >= base - KERNEL_STACK_SIZE
}

/// A calendar date and time (UTC, Gregorian) as Windows counts time:
/// 100 ns units since 1601-01-01. `None` for a date that does not exist
/// or lies before 1601.
pub const fn windows_time(
    year: u32,
    month: u32,
    day: u32,
    hour: u32,
    minute: u32,
    second: u32,
) -> Option<u64> {
    const DAYS: [u32; 12] = [31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];
    let leap = year % 4 == 0 && (year % 100 != 0 || year % 400 == 0);
    if year < 1601 || month < 1 || month > 12 || hour > 23 || minute > 59 || second > 59 {
        return None;
    }
    let in_month = DAYS[month as usize - 1] + (leap && month == 2) as u32;
    if day < 1 || day > in_month {
        return None;
    }
    // Days in the whole years since 1601, then in this year's whole months.
    let y = (year - 1601) as u64;
    let mut days = y * 365 + y / 4 - y / 100 + y / 400;
    let mut m = 0;
    while m < month as usize - 1 {
        days += (DAYS[m] + (leap && m == 1) as u32) as u64;
        m += 1;
    }
    days += (day - 1) as u64;
    let seconds = days * 86_400 + (hour * 3600 + minute * 60 + second) as u64;
    Some(seconds * 10_000_000)
}

/// `EFI_MEMORY_TYPE` values the kernel cares about.
pub const EFI_LOADER_CODE: u32 = 1;
pub const EFI_RUNTIME_CODE: u32 = 5;
pub const EFI_CONVENTIONAL: u32 = 7;
pub const EFI_MMIO: u32 = 11;
pub const EFI_MMIO_PORT: u32 = 12;
/// `EFI_MEMORY_RUNTIME`: firmware needs this region after boot services.
pub const EFI_ATTR_RUNTIME: u64 = 1 << 63;

/// A file the loader read for the kernel (a driver image).
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct Module {
    pub phys: u64,
    pub size: u64,
    /// File name, NUL padded.
    pub name: [u8; MODULE_NAME_LEN],
}

impl Module {
    pub const EMPTY: Self = Self {
        phys: 0,
        size: 0,
        name: [0; MODULE_NAME_LEN],
    };

    /// The file name without its NUL padding.
    pub fn name(&self) -> &[u8] {
        let len = self
            .name
            .iter()
            .position(|&b| b == 0)
            .unwrap_or(MODULE_NAME_LEN);
        &self.name[..len]
    }

    /// Store `name`, truncated to fit.
    pub fn set_name(&mut self, name: &[u8]) {
        let len = name.len().min(MODULE_NAME_LEN);
        self.name = [0; MODULE_NAME_LEN];
        self.name[..len].copy_from_slice(&name[..len]);
    }
}

/// The diagnostic serial port.
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Serial {
    pub kind: u32,
    _pad: u32,
    /// I/O port number or physical MMIO address, by `kind`.
    pub base: u64,
}

impl Serial {
    pub const NONE: u32 = 0;
    /// 16550 on x86 I/O ports.
    pub const PORT_16550: u32 = 1;
    /// ARM PL011, memory mapped.
    pub const MMIO_PL011: u32 = 2;

    pub const fn new(kind: u32, base: u64) -> Self {
        Self {
            kind,
            _pad: 0,
            base,
        }
    }

    /// The port an ACPI SPCR table describes, if it is a kind NK has a
    /// driver for: a PL011 in memory (interface type 3) or a 16550 on
    /// I/O ports (types 0 and 1). `mmio` says the address is a memory
    /// address.
    pub const fn from_spcr(mmio: bool, interface: u8, address: u64) -> Option<Self> {
        match (mmio, interface) {
            (true, 3) => Some(Self::new(Self::MMIO_PL011, address)),
            (false, 0 | 1) => Some(Self::new(Self::PORT_16550, address)),
            _ => None,
        }
    }
}

/// Identifies the Windows system partition (the volume containing
/// `\Windows\System32\ntdll.dll`), discovered by `nkload` from UEFI
/// `SimpleFileSystem` + `DevicePath` Hard Drive nodes.
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SystemPartition {
    /// `SIG_NONE` (0), `SIG_MBR` (1), or `SIG_GPT` (2).
    pub sig_type: u8,
    pub _pad: [u8; 3],
    /// 1-based partition number from the UEFI Hard Drive device path.
    pub number: u32,
    /// Starting LBA of the partition.
    pub start_lba: u64,
    /// GPT partition GUID (when `sig_type == SIG_GPT`) or 4-byte MBR disk
    /// signature in `sig[0..4]` (when `sig_type == SIG_MBR`).
    pub sig: [u8; 16],
}

impl SystemPartition {
    pub const SIG_NONE: u8 = 0;
    pub const SIG_MBR: u8 = 1;
    pub const SIG_GPT: u8 = 2;

    pub const NONE: Self = Self {
        sig_type: Self::SIG_NONE,
        _pad: [0; 3],
        number: 0,
        start_lba: 0,
        sig: [0; 16],
    };

    pub const fn is_present(&self) -> bool {
        self.sig_type != Self::SIG_NONE
    }
}

/// Walk a serialized UEFI `EFI_DEVICE_PATH_PROTOCOL` byte stream and extract
/// the first Media Hard Drive node (`type = 4`, `subtype = 1`, `len >= 42`).
pub fn parse_hd_device_path(path: &[u8]) -> Option<SystemPartition> {
    let mut at = 0usize;
    while at + 4 <= path.len() {
        let kind = path[at];
        let sub = path[at + 1];
        let len = u16::from_le_bytes([path[at + 2], path[at + 3]]) as usize;
        if len < 4 || at + len > path.len() {
            return None;
        }
        // End of Hardware Device Path (Entire Device Path).
        if kind == 0x7F && sub == 0xFF {
            return None;
        }
        if kind == 4 && sub == 1 && len >= 42 {
            let number = u32::from_le_bytes(path[at + 4..at + 8].try_into().ok()?);
            let start_lba = u64::from_le_bytes(path[at + 8..at + 16].try_into().ok()?);
            let mut sig = [0u8; 16];
            sig.copy_from_slice(&path[at + 24..at + 40]);
            let sig_type = path[at + 41];
            if matches!(
                sig_type,
                SystemPartition::SIG_MBR | SystemPartition::SIG_GPT
            ) {
                return Some(SystemPartition {
                    sig_type,
                    _pad: [0; 3],
                    number,
                    start_lba,
                    sig,
                });
            }
        }
        at += len;
    }
    None
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct BootInfo {
    pub magic: u64,
    pub version: u32,
    pub nmodules: u32,
    pub hhdm_base: u64,
    /// The kernel image: where it sits in RAM and how many bytes.
    pub kernel_phys: u64,
    pub kernel_size: u64,
    /// The UEFI memory map as left by `ExitBootServices`: `mmap_len` bytes
    /// of descriptors, each `mmap_desc_size` bytes.
    pub mmap_phys: u64,
    pub mmap_len: u64,
    pub mmap_desc_size: u64,
    /// ACPI RSDP, or 0.
    pub rsdp: u64,
    /// `EFI_RUNTIME_SERVICES` table. Its code is identity mapped.
    pub efi_runtime: u64,
    pub serial: Serial,
    /// arm64 only: indices into `MAIR_EL1` for normal and device memory.
    pub mair_normal: u8,
    pub mair_device: u8,
    _pad: [u8; 6],
    /// Wall-clock time when the loader ran, as Windows counts it: 100 ns
    /// units since 1601-01-01 UTC. 0 if firmware could not say.
    pub boot_time: u64,
    /// The entropy the loader gathered, as Windows' loader hands it to
    /// its kernel: a `BOOT_ENTROPY_LDR_RESULT` (`nk-ntabi`) in pages of
    /// its own, which the kernel wipes once it has given the entropy
    /// out (`doc/BOOT.md`, Boot entropy).
    pub entropy: u64,
    /// The Windows system partition (`\Windows\System32\ntdll.dll`), if
    /// present on any UEFI filesystem at boot.
    pub system_partition: SystemPartition,
    /// The kernel command line: `key=value` words separated by spaces,
    /// NUL padded. Empty when the boot volume has no command-line file.
    pub cmdline: [u8; CMDLINE_LEN],
    /// The files the loader read for the kernel: every boot driver, by
    /// its file name, and the registry hive and the registry overlay,
    /// where there is one, as [`HIVE_MODULE`] and [`OVERLAY_MODULE`].
    pub modules: [Module; MAX_MODULES],
}

impl BootInfo {
    pub const fn new() -> Self {
        Self {
            magic: MAGIC,
            version: VERSION,
            nmodules: 0,
            hhdm_base: HHDM_BASE,
            kernel_phys: 0,
            kernel_size: 0,
            mmap_phys: 0,
            mmap_len: 0,
            mmap_desc_size: 0,
            rsdp: 0,
            efi_runtime: 0,
            serial: Serial::new(Serial::NONE, 0),
            mair_normal: 0,
            mair_device: 0,
            _pad: [0; 6],
            boot_time: 0,
            entropy: 0,
            system_partition: SystemPartition::NONE,
            cmdline: [0; CMDLINE_LEN],
            modules: [Module::EMPTY; MAX_MODULES],
        }
    }

    /// Store the command line read from the boot volume. Line ends and
    /// other control characters become spaces. `Err` if it does not fit
    /// or is not ASCII: a truncated option would silently change a test.
    pub fn set_cmdline(&mut self, text: &[u8]) -> Result<(), &'static str> {
        if text.len() >= CMDLINE_LEN {
            return Err("kernel command line is too long");
        }
        if !text.is_ascii() {
            return Err("kernel command line is not ASCII");
        }
        self.cmdline = [0; CMDLINE_LEN];
        for (dst, &src) in self.cmdline.iter_mut().zip(text) {
            *dst = if src < b' ' { b' ' } else { src };
        }
        Ok(())
    }

    /// The command line without its padding.
    pub fn cmdline(&self) -> &str {
        let len = self
            .cmdline
            .iter()
            .position(|&b| b == 0)
            .unwrap_or(CMDLINE_LEN);
        core::str::from_utf8(&self.cmdline[..len]).unwrap_or("")
    }

    /// The value of the command-line word `key=value`, if present. The
    /// last occurrence wins.
    pub fn option(&self, key: &str) -> Option<&str> {
        self.cmdline()
            .split(' ')
            .filter_map(|word| word.split_once('='))
            .filter(|(k, _)| *k == key)
            .map(|(_, v)| v)
            .next_back()
    }

    pub fn is_valid(&self) -> bool {
        self.magic == MAGIC && self.version == VERSION
    }

    pub fn modules(&self) -> &[Module] {
        &self.modules[..(self.nmodules as usize).min(MAX_MODULES)]
    }
}

/// One region of the UEFI memory map.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MemRegion {
    pub kind: u32,
    pub phys: u64,
    pub pages: u64,
    pub attr: u64,
}

impl MemRegion {
    pub fn end(&self) -> u64 {
        self.phys + self.pages * 4096
    }

    /// RAM of any kind, as opposed to device registers.
    pub fn is_ram(&self) -> bool {
        !matches!(self.kind, EFI_MMIO | EFI_MMIO_PORT)
    }

    /// Whether the `len` bytes at `addr` all lie in this region.
    pub fn contains(&self, addr: u64, len: u64) -> bool {
        addr.checked_add(len)
            .is_some_and(|end| self.phys <= addr && end <= self.end())
    }

    /// Whether any of the `len` bytes at `start` lie in this region.
    pub fn overlaps(&self, start: u64, len: u64) -> bool {
        self.phys < start + len && self.end() > start
    }

    /// What firmware still needs this region for once the kernel runs,
    /// if anything: the loader keeps such memory mapped where it is.
    pub fn firmware_use(&self) -> Option<FirmwareUse> {
        match self.kind {
            EFI_LOADER_CODE => Some(FirmwareUse::LoaderCode),
            EFI_RUNTIME_CODE => Some(FirmwareUse::RuntimeCode),
            _ if self.attr & EFI_ATTR_RUNTIME != 0 => Some(FirmwareUse::RuntimeData),
            _ => None,
        }
    }
}

/// Why a region stays mapped at its physical address.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FirmwareUse {
    /// The loader's own code, running until it jumps to the kernel.
    LoaderCode,
    /// Code of UEFI runtime services.
    RuntimeCode,
    /// Anything else runtime services use: their data, device registers.
    RuntimeData,
}

/// Where RAM ends: the highest address of any region that is not device
/// registers. Zero for a map with no RAM.
pub fn ram_top(map: &[u8], desc_size: usize) -> u64 {
    regions(map, desc_size)
        .filter(|r| r.is_ram())
        .map(|r| r.end())
        .max()
        .unwrap_or(0)
}

/// Whether any of the `len` bytes at `start` are RAM.
pub fn has_ram(map: &[u8], desc_size: usize, start: u64, len: u64) -> bool {
    regions(map, desc_size).any(|r| r.is_ram() && r.overlaps(start, len))
}

/// Whether the `len` bytes at `addr` lie within one region of the map,
/// of any kind: memory firmware has described, as opposed to an address
/// it never mentioned.
pub fn described(map: &[u8], desc_size: usize, addr: u64, len: u64) -> bool {
    regions(map, desc_size).any(|r| r.contains(addr, len))
}

/// Offsets in `EFI_FILE_INFO`, which a directory read returns.
const FILE_INFO_ATTRIBUTE: usize = 72;
const FILE_INFO_NAME: usize = 80;
/// `EFI_FILE_DIRECTORY`.
const FILE_DIRECTORY: u64 = 0x10;

/// Read one directory entry (`EFI_FILE_INFO`): copies its name into
/// `name` as ASCII, a `?` for each character that is not, cut short if
/// `name` is, and returns the name's length and whether the entry is a
/// directory. `None` if `info` is too short to be an entry.
pub fn directory_entry(info: &[u8], name: &mut [u8]) -> Option<(usize, bool)> {
    let attr = info.get(FILE_INFO_ATTRIBUTE..FILE_INFO_NAME)?;
    let attr = u64::from_le_bytes(attr.try_into().ok()?);
    let mut len = 0;
    for c in info[FILE_INFO_NAME..]
        .as_chunks::<2>()
        .0
        .iter()
        .map(|c| u16::from_le_bytes(*c))
    {
        if c == 0 || len == name.len() {
            break;
        }
        name[len] = if c < 0x80 { c as u8 } else { b'?' };
        len += 1;
    }
    Some((len, attr & FILE_DIRECTORY != 0))
}

/// Iterate a raw UEFI memory map. Firmware chooses the descriptor size, so
/// it is not `size_of` anything: step by `desc_size`.
pub fn regions(map: &[u8], desc_size: usize) -> impl Iterator<Item = MemRegion> + '_ {
    let step = desc_size.max(40);
    map.chunks_exact(step).map(|d| {
        let q = |o: usize| u64::from_le_bytes(d[o..o + 8].try_into().unwrap_or([0; 8]));
        MemRegion {
            kind: q(0) as u32,
            phys: q(8),
            pages: q(24),
            attr: q(32),
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn desc(kind: u32, phys: u64, pages: u64, attr: u64, size: usize) -> Vec<u8> {
        let mut d = vec![0xEE; size];
        d[..8].copy_from_slice(&u64::from(kind).to_le_bytes());
        d[8..16].copy_from_slice(&phys.to_le_bytes());
        d[24..32].copy_from_slice(&pages.to_le_bytes());
        d[32..40].copy_from_slice(&attr.to_le_bytes());
        d
    }

    #[test]
    fn regions_step_by_firmware_descriptor_size() {
        // OVMF uses 48-byte descriptors although the struct is 40 bytes.
        let mut map = desc(EFI_CONVENTIONAL, 0x10_0000, 256, 0xF, 48);
        map.extend(desc(EFI_MMIO, 0xFEC0_0000, 1, EFI_ATTR_RUNTIME, 48));
        let r: Vec<MemRegion> = regions(&map, 48).collect();
        assert_eq!(r.len(), 2);
        assert_eq!(
            (r[0].kind, r[0].phys, r[0].end()),
            (EFI_CONVENTIONAL, 0x10_0000, 0x20_0000)
        );
        assert!(r[0].is_ram() && !r[1].is_ram());
        assert_eq!(r[1].attr, EFI_ATTR_RUNTIME);
    }

    const MMIO_ATTR: u64 = EFI_ATTR_RUNTIME | 1;

    /// A machine: low RAM, a hole, more RAM, flash for runtime services,
    /// and RAM above 4 GiB.
    fn machine() -> Vec<u8> {
        let mut map = desc(EFI_CONVENTIONAL, 0, 0xA0, 0xF, 48);
        map.extend(desc(EFI_LOADER_CODE, 0x10_0000, 0x100, 0xF, 48));
        map.extend(desc(EFI_CONVENTIONAL, 0x20_0000, 0x7FE00, 0xF, 48));
        map.extend(desc(EFI_RUNTIME_CODE, 0x8000_0000, 0x10, MMIO_ATTR, 48));
        map.extend(desc(6, 0x8001_0000, 0x10, MMIO_ATTR, 48));
        map.extend(desc(EFI_MMIO, 0xFFC0_0000, 0x400, MMIO_ATTR, 48));
        map.extend(desc(EFI_CONVENTIONAL, 0x1_0000_0000, 0x4_0000, 0xF, 48));
        map
    }

    #[test]
    fn ram_ends_at_the_top_of_the_highest_ram_region() {
        assert_eq!(ram_top(&machine(), 48), 0x1_4000_0000);
        // Device registers above RAM do not count.
        let mut map = desc(EFI_CONVENTIONAL, 0x10_0000, 0x100, 0xF, 48);
        map.extend(desc(EFI_MMIO, 0xFEC0_0000, 1, MMIO_ATTR, 48));
        map.extend(desc(EFI_MMIO_PORT, 0xFFFF_0000, 1, MMIO_ATTR, 48));
        assert_eq!(ram_top(&map, 48), 0x20_0000);
        // The order of the map does not matter.
        let mut map = desc(EFI_CONVENTIONAL, 0x4000_0000, 0x100, 0xF, 48);
        map.extend(desc(EFI_CONVENTIONAL, 0x10_0000, 0x100, 0xF, 48));
        assert_eq!(ram_top(&map, 48), 0x4010_0000);
        assert_eq!(ram_top(&[], 48), 0);
        assert_eq!(ram_top(&desc(EFI_MMIO, 0x1000, 1, 0, 48), 48), 0);
    }

    #[test]
    fn a_block_has_ram_if_any_ram_region_reaches_into_it() {
        const BLOCK: u64 = 2 << 20;
        let map = machine();
        // Wholly RAM, and RAM only at its start (0 to 0xA0000).
        assert!(has_ram(&map, 48, 0x40_0000, BLOCK));
        assert!(has_ram(&map, 48, 0, BLOCK));
        // The hole between 2 GiB + 128 KiB and the flash.
        assert!(!has_ram(&map, 48, 0x9000_0000, BLOCK));
        // Device registers are not RAM.
        assert!(!has_ram(&map, 48, 0xFFC0_0000, BLOCK));
        assert!(!has_ram(&map, 48, 0xFFE0_0000, BLOCK));
        // Runtime services' memory is.
        assert!(has_ram(&map, 48, 0x8000_0000, BLOCK));
        // A region that ends exactly where the block begins, or begins
        // exactly where it ends, is not in it.
        let map = desc(EFI_CONVENTIONAL, 0x20_0000, 0x200, 0xF, 48);
        assert!(!has_ram(&map, 48, 0x40_0000, BLOCK));
        assert!(!has_ram(&map, 48, 0, BLOCK));
        assert!(has_ram(&map, 48, 0x20_0000, BLOCK));
        // One page of RAM at either end of a block is enough.
        let mut map = desc(EFI_CONVENTIONAL, 0x3F_F000, 1, 0xF, 48);
        map.extend(desc(EFI_CONVENTIONAL, 0x60_0000, 1, 0xF, 48));
        assert!(has_ram(&map, 48, 0x20_0000, BLOCK));
        assert!(has_ram(&map, 48, 0x60_0000, BLOCK));
        assert!(!has_ram(&map, 48, 0x40_0000, BLOCK));
    }

    #[test]
    fn memory_is_described_if_one_region_holds_all_of_it() {
        let map = machine();
        assert!(described(&map, 48, 0x20_0000, 0x1000));
        assert!(described(&map, 48, 0, 0xA_0000));
        // Device registers are described too.
        assert!(described(&map, 48, 0xFFC0_0000, 4));
        // The last byte of a region, and one past it.
        assert!(described(&map, 48, 0xA_0000 - 1, 1));
        assert!(!described(&map, 48, 0xA_0000 - 1, 2));
        assert!(!described(&map, 48, 0xA_0000, 1));
        // Never mentioned.
        assert!(!described(&map, 48, 0x9000_0000, 1));
        // Spanning two regions that touch: no one region holds it.
        assert!(!described(&map, 48, 0x1F_F000, 0x2000));
        // A length that wraps the address space is not inside anything.
        assert!(!described(&map, 48, 0x20_0000, u64::MAX));
        assert!(!described(&[], 48, 0, 0));
    }

    #[test]
    fn a_region_contains_and_overlaps_by_its_bounds() {
        let r = MemRegion {
            kind: EFI_CONVENTIONAL,
            phys: 0x8000,
            pages: 1,
            attr: 0,
        };
        assert!(r.contains(0x8000, 0x1000));
        assert!(r.contains(0x8FFF, 1));
        assert!(r.contains(0x9000, 0), "nothing, at the very end");
        assert!(!r.contains(0x7FFF, 2));
        assert!(!r.contains(0x8001, 0x1000));
        assert!(!r.contains(u64::MAX, 2));
        assert!(r.overlaps(0x7000, 0x1001));
        assert!(!r.overlaps(0x7000, 0x1000));
        assert!(r.overlaps(0x8FFF, 0x4000));
        assert!(!r.overlaps(0x9000, 0x4000));
    }

    #[test]
    fn firmware_keeps_its_runtime_memory_and_the_loader_its_code() {
        let region = |kind, attr| MemRegion {
            kind,
            phys: 0,
            pages: 1,
            attr,
        };
        assert_eq!(
            region(EFI_LOADER_CODE, 0xF).firmware_use(),
            Some(FirmwareUse::LoaderCode)
        );
        assert_eq!(
            region(EFI_RUNTIME_CODE, MMIO_ATTR).firmware_use(),
            Some(FirmwareUse::RuntimeCode)
        );
        // Runtime code is code whatever its attributes say.
        assert_eq!(
            region(EFI_RUNTIME_CODE, 0).firmware_use(),
            Some(FirmwareUse::RuntimeCode)
        );
        // Runtime data, and device registers runtime services use.
        assert_eq!(
            region(6, MMIO_ATTR).firmware_use(),
            Some(FirmwareUse::RuntimeData)
        );
        assert_eq!(
            region(EFI_MMIO, MMIO_ATTR).firmware_use(),
            Some(FirmwareUse::RuntimeData)
        );
        // Everything else is the kernel's to map as it likes.
        assert_eq!(region(EFI_CONVENTIONAL, 0xF).firmware_use(), None);
        assert_eq!(region(EFI_MMIO, 1).firmware_use(), None);
        assert_eq!(region(2, 0xF).firmware_use(), None);
    }

    #[test]
    fn the_serial_port_is_what_the_spcr_describes_if_nk_can_drive_it() {
        assert_eq!(
            Serial::from_spcr(true, 3, 0x0900_0000),
            Some(Serial::new(Serial::MMIO_PL011, 0x0900_0000))
        );
        for interface in [0, 1] {
            assert_eq!(
                Serial::from_spcr(false, interface, 0x3F8),
                Some(Serial::new(Serial::PORT_16550, 0x3F8))
            );
        }
        // A 16550 in memory and a PL011 on I/O ports have no driver.
        assert_eq!(Serial::from_spcr(true, 0, 0x1000), None);
        assert_eq!(Serial::from_spcr(true, 1, 0x1000), None);
        assert_eq!(Serial::from_spcr(false, 3, 0x3F8), None);
        // Nor do the other interface types.
        assert_eq!(Serial::from_spcr(true, 2, 0x1000), None);
        assert_eq!(Serial::from_spcr(false, 2, 0x3F8), None);
        assert_eq!(Serial::from_spcr(true, 0x12, 0x1000), None);
    }

    /// An `EFI_FILE_INFO` for a file or directory called `name`.
    fn file_info(name: &str, attribute: u64) -> Vec<u8> {
        let mut info = vec![0u8; 80];
        info[72..80].copy_from_slice(&attribute.to_le_bytes());
        for c in name.encode_utf16() {
            info.extend_from_slice(&c.to_le_bytes());
        }
        info.extend_from_slice(&[0, 0]);
        info
    }

    #[test]
    fn a_directory_entry_gives_its_name_and_kind() {
        let mut name = [0u8; 32];
        let entry = directory_entry(&file_info("null.sys", 0x20), &mut name);
        assert_eq!(entry, Some((8, false)));
        assert_eq!(&name[..8], b"null.sys");
        let entry = directory_entry(&file_info("drivers", 0x10), &mut name);
        assert_eq!(entry, Some((7, true)));
        assert_eq!(&name[..7], b"drivers");
        // Other attribute bits do not make a directory, nor hide one.
        assert_eq!(
            directory_entry(&file_info("x", 0x27), &mut name),
            Some((1, false))
        );
        assert_eq!(
            directory_entry(&file_info("x", 0x37), &mut name),
            Some((1, true))
        );
    }

    #[test]
    fn a_directory_entry_s_name_is_made_ascii_and_cut_to_fit() {
        let mut name = [0u8; 32];
        let entry = directory_entry(&file_info("caf\u{e9}\u{4e2d}.sys", 0), &mut name);
        assert_eq!(entry, Some((9, false)));
        assert_eq!(&name[..9], b"caf??.sys");
        // A name longer than the room for it is cut, not overrun.
        let mut short = [0xAAu8; 4];
        let entry = directory_entry(&file_info("sioctl.sys", 0), &mut short);
        assert_eq!(entry, Some((4, false)));
        assert_eq!(&short, b"sioc");
        // No room at all, and no name at all.
        assert_eq!(
            directory_entry(&file_info("sioctl.sys", 0x10), &mut []),
            Some((0, true))
        );
        assert_eq!(
            directory_entry(&file_info("", 0), &mut name),
            Some((0, false))
        );
    }

    #[test]
    fn a_directory_entry_reads_only_what_it_was_given() {
        let mut name = [0u8; 8];
        // Too short to hold the attribute.
        assert_eq!(directory_entry(&[0u8; 79], &mut name), None);
        assert_eq!(directory_entry(&[], &mut name), None);
        // A name that runs to the end of the buffer with no terminator,
        // and an odd byte left over.
        let mut info = file_info("ab", 0);
        info.truncate(84);
        assert_eq!(directory_entry(&info, &mut name), Some((2, false)));
        info.push(b'c');
        assert_eq!(directory_entry(&info, &mut name), Some((2, false)));
        assert_eq!(&name[..2], b"ab");
        // Exactly the fixed part: an empty name.
        assert_eq!(directory_entry(&[0u8; 80], &mut name), Some((0, false)));
    }

    #[test]
    fn regions_ignore_trailing_partial_descriptor() {
        let mut map = desc(EFI_CONVENTIONAL, 0, 1, 0, 48);
        map.extend([0u8; 20]);
        assert_eq!(regions(&map, 48).count(), 1);
        assert_eq!(
            regions(&map, 0).count(),
            1,
            "a bogus size must not divide by zero"
        );
    }

    #[test]
    fn module_names() {
        let mut m = Module::EMPTY;
        m.set_name(b"null.sys");
        assert_eq!(m.name(), b"null.sys");
        m.set_name(&[b'x'; 40]);
        assert_eq!(m.name().len(), MODULE_NAME_LEN);
    }

    #[test]
    fn the_modules_are_the_ones_the_loader_counted() {
        let mut info = BootInfo::new();
        assert!(info.modules().is_empty());
        for (i, name) in [&b"null.sys"[..], b"sioctl.sys"].into_iter().enumerate() {
            info.modules[i].set_name(name);
            info.modules[i].size = 100 + i as u64;
            info.nmodules += 1;
        }
        let listed: Vec<_> = info.modules().iter().map(|m| (m.name(), m.size)).collect();
        assert_eq!(listed, [(&b"null.sys"[..], 100), (b"sioctl.sys", 101)]);
        // A count the table cannot hold is not believed: reading a
        // damaged structure stays inside it.
        info.nmodules = MAX_MODULES as u32;
        assert_eq!(info.modules().len(), MAX_MODULES);
        info.nmodules = MAX_MODULES as u32 + 1;
        assert_eq!(info.modules().len(), MAX_MODULES);
        info.nmodules = u32::MAX;
        assert_eq!(info.modules().len(), MAX_MODULES);
    }

    #[test]
    fn layout_is_stable() {
        // Both loader and kernel are built from this source, but a silent
        // layout change should still be a deliberate VERSION bump.
        assert_eq!(size_of::<Module>(), 48);
        assert_eq!(size_of::<SystemPartition>(), 32);
        assert_eq!(
            size_of::<BootInfo>(),
            120 + size_of::<SystemPartition>() + CMDLINE_LEN + 48 * MAX_MODULES
        );
        assert!(BootInfo::new().is_valid());
    }

    #[test]
    fn hd_device_path_parses_gpt_and_mbr() {
        // Leading PCI node (6 bytes), then Media Hard Drive GPT node (42 bytes), then End (4 bytes).
        let mut dp = vec![1u8, 1, 6, 0, 0x00, 0x1F];
        let mut hd = [0u8; 42];
        hd[0] = 4; // Media
        hd[1] = 1; // Hard Drive
        hd[2..4].copy_from_slice(&42u16.to_le_bytes());
        hd[4..8].copy_from_slice(&2u32.to_le_bytes()); // partition #2
        hd[8..16].copy_from_slice(&2048u64.to_le_bytes());
        let guid = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16];
        hd[24..40].copy_from_slice(&guid);
        hd[40] = 2; // GPT
        hd[41] = SystemPartition::SIG_GPT;
        dp.extend_from_slice(&hd);
        dp.extend_from_slice(&[0x7F, 0xFF, 4, 0]);
        assert_eq!(
            parse_hd_device_path(&dp),
            Some(SystemPartition {
                sig_type: SystemPartition::SIG_GPT,
                _pad: [0; 3],
                number: 2,
                start_lba: 2048,
                sig: guid,
            })
        );
        // MBR node.
        hd[40] = 1;
        hd[41] = SystemPartition::SIG_MBR;
        hd[24..40].fill(0);
        hd[24..28].copy_from_slice(&0x4E4B_0001u32.to_le_bytes());
        let mut mbr = Vec::new();
        mbr.extend_from_slice(&hd);
        mbr.extend_from_slice(&[0x7F, 0xFF, 4, 0]);
        let parsed = parse_hd_device_path(&mbr).expect("MBR node");
        assert_eq!(parsed.sig_type, SystemPartition::SIG_MBR);
        assert_eq!(&parsed.sig[..4], &0x4E4B_0001u32.to_le_bytes());
        // No HD node -> None.
        assert_eq!(parse_hd_device_path(&[0x7F, 0xFF, 4, 0]), None);
    }

    #[test]
    fn stack_tops() {
        const S: u64 = KERNEL_STACK_SIZE;
        // Three stack sizes hold a stack wherever they start.
        for start in [
            0x10_0000,
            0x10_1000,
            0x10_7000,
            0x10_8000,
            0x10_F000,
            0x7FFF_F000,
        ] {
            let top = stack_top_in(start, 3 * S).expect("room for a stack");
            assert_eq!(top % (2 * S), 0);
            assert!(top - S >= start && top <= start + 3 * S);
            // On the stack the bit is set; in the size below it, clear.
            for sp in [top - 8, top - S] {
                assert_ne!(sp >> KERNEL_STACK_SHIFT & 1, 0, "{sp:#x}");
            }
            for sp in [top - S - 8, top - 2 * S] {
                assert_eq!(sp >> KERNEL_STACK_SHIFT & 1, 0, "{sp:#x}");
            }
        }
        assert_eq!(
            stack_top_in(2 * S, S),
            None,
            "an aligned top with no stack below"
        );
        assert_eq!(stack_top_in(S, S), Some(2 * S));
        assert_eq!(stack_top_in(S + 0x1000, S), None);
        assert_eq!(stack_top_in(0x1000, 0x1000), None);
    }

    #[test]
    fn the_gap_below_a_stack() {
        const S: u64 = KERNEL_STACK_SIZE;
        let base = 0xFFFF_F880_0000_8000;
        assert!(below_stack(base, base - 8));
        assert!(below_stack(base, base - S));
        assert!(!below_stack(base, base), "the stack itself");
        assert!(!below_stack(base, base + 64));
        assert!(!below_stack(base, base - S - 8), "below the gap");
        assert!(!below_stack(0, 0x1000), "no stack recorded");
        assert!(!below_stack(0, u64::MAX));
        assert!(!below_stack(S / 2, 0), "a base too low to have a gap");
    }

    #[test]
    fn windows_times() {
        assert_eq!(windows_time(1601, 1, 1, 0, 0, 0), Some(0));
        assert_eq!(windows_time(1601, 1, 2, 0, 0, 1), Some(864_010_000_000));
        // The Unix epoch, a constant every Windows programmer knows.
        assert_eq!(
            windows_time(1970, 1, 1, 0, 0, 0),
            Some(116_444_736_000_000_000)
        );
        // 2020-01-01, the bound the clock conformance driver checks against.
        assert_eq!(
            windows_time(2020, 1, 1, 0, 0, 0),
            Some(132_223_104_000_000_000)
        );
        // Leap days: 2000 had one, 1900 did not, 2024 did.
        assert_eq!(
            windows_time(2000, 3, 1, 0, 0, 0).unwrap()
                - windows_time(2000, 2, 28, 0, 0, 0).unwrap(),
            2 * 864_000_000_000
        );
        assert!(windows_time(1900, 2, 29, 0, 0, 0).is_none());
        assert!(windows_time(2024, 2, 29, 23, 59, 59).is_some());
        assert!(windows_time(2023, 2, 29, 0, 0, 0).is_none());
        for bad in [
            (1600, 12, 31, 0, 0, 0),
            (2026, 0, 1, 0, 0, 0),
            (2026, 13, 1, 0, 0, 0),
            (2026, 4, 31, 0, 0, 0),
            (2026, 1, 0, 0, 0, 0),
            (2026, 1, 1, 24, 0, 0),
            (2026, 1, 1, 0, 60, 0),
            (2026, 1, 1, 0, 0, 60),
        ] {
            assert!(
                windows_time(bad.0, bad.1, bad.2, bad.3, bad.4, bad.5).is_none(),
                "{bad:?}"
            );
        }
    }

    #[test]
    fn cmdline_options() {
        let mut info = BootInfo::new();
        assert_eq!(info.cmdline(), "");
        assert_eq!(info.option("test"), None);
        info.set_cmdline(b"test=neg.panic  cpus=4\r\n").unwrap();
        assert_eq!(info.option("test"), Some("neg.panic"));
        assert_eq!(info.option("cpus"), Some("4"));
        assert_eq!(info.option("cpu"), None, "a key is matched whole");
        assert_eq!(info.option("neg.panic"), None, "values are not keys");
        info.set_cmdline(b"test=a test=b").unwrap();
        assert_eq!(info.option("test"), Some("b"), "the last word wins");
        info.set_cmdline(b"test=").unwrap();
        assert_eq!(info.option("test"), Some(""));
    }

    #[test]
    fn cmdline_rejects_what_it_cannot_hold() {
        let mut info = BootInfo::new();
        assert!(info.set_cmdline(&[b'a'; CMDLINE_LEN]).is_err());
        assert!(info.set_cmdline(&[b'a'; CMDLINE_LEN - 1]).is_ok());
        assert_eq!(info.cmdline().len(), CMDLINE_LEN - 1);
        assert!(info.set_cmdline("test=\u{e9}".as_bytes()).is_err());
    }
}
