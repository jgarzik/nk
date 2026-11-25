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

pub const MAGIC: u64 = u64::from_le_bytes(*b"NKBOOT\0\0");
pub const VERSION: u32 = 2;

/// Where the loader maps things. Fixed, so the kernel can be linked and
/// debugged against known addresses.
pub const HHDM_BASE: u64 = 0xFFFF_8000_0000_0000;
pub const KERNEL_BASE: u64 = 0xFFFF_F800_0000_0000;

pub const MAX_MODULES: usize = 16;
pub const MODULE_NAME_LEN: usize = 32;
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
    /// The kernel command line: `key=value` words separated by spaces,
    /// NUL padded. Empty when the boot volume has no command-line file.
    pub cmdline: [u8; CMDLINE_LEN],
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
    fn layout_is_stable() {
        // Both loader and kernel are built from this source, but a silent
        // layout change should still be a deliberate VERSION bump.
        assert_eq!(size_of::<Module>(), 48);
        assert_eq!(size_of::<BootInfo>(), 104 + CMDLINE_LEN + 48 * MAX_MODULES);
        assert!(BootInfo::new().is_valid());
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
