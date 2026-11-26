//! Find ACPI tables and read the few fields NK needs from them.
//!
//! Firmware tables are untrusted input: lengths are checked and a
//! malformed table reads as absent. Physical memory is reached through
//! [`PhysMem`], so the loader (identity map), the kernel (direct map) and
//! host tests (a byte vector) share this code.

#![cfg_attr(not(test), no_std)]

/// Read access to physical memory.
pub trait PhysMem {
    /// `len` bytes at physical address `addr`, or `None` if unreachable.
    fn bytes(&self, addr: u64, len: usize) -> Option<&[u8]>;
}

const SDT_HEADER: usize = 36;
/// Sanity bound on a table length read from firmware.
const MAX_TABLE: usize = 1 << 20;

fn u32_at(b: &[u8], off: usize) -> Option<u32> {
    Some(u32::from_le_bytes(b.get(off..off + 4)?.try_into().ok()?))
}

fn u64_at(b: &[u8], off: usize) -> Option<u64> {
    Some(u64::from_le_bytes(b.get(off..off + 8)?.try_into().ok()?))
}

/// The whole table at `addr`, header included.
fn table(mem: &impl PhysMem, addr: u64) -> Option<&[u8]> {
    let len = u32_at(mem.bytes(addr, SDT_HEADER)?, 4)? as usize;
    if !(SDT_HEADER..=MAX_TABLE).contains(&len) {
        return None;
    }
    mem.bytes(addr, len)
}

/// The root table the RSDP at `rsdp` names, and the width of its
/// entries: the XSDT when there is one, else the RSDT.
fn root(mem: &impl PhysMem, rsdp: u64) -> Option<(&[u8], usize)> {
    let r = mem.bytes(rsdp, 36)?;
    if &r[..8] != b"RSD PTR " {
        return None;
    }
    let xsdt = if r[15] >= 2 { u64_at(r, 24)? } else { 0 };
    let (root, width) = if xsdt != 0 {
        (xsdt, 8)
    } else {
        (u64::from(u32_at(r, 16)?), 4)
    };
    Some((table(mem, root)?, width))
}

/// The tables the root table lists, in its order.
fn listed(mem: &impl PhysMem, rsdp: u64) -> impl Iterator<Item = &[u8]> {
    root(mem, rsdp).into_iter().flat_map(move |(root, width)| {
        root[SDT_HEADER..].chunks_exact(width).filter_map(move |e| {
            let addr = if width == 8 {
                u64_at(e, 0)?
            } else {
                u64::from(u32_at(e, 0)?)
            };
            table(mem, addr)
        })
    })
}

/// Find the table with signature `sig` (for example `b"SPCR"`), starting
/// from the RSDP. Uses the XSDT when present, else the RSDT.
pub fn find_table<'a>(mem: &'a impl PhysMem, rsdp: u64, sig: &[u8; 4]) -> Option<&'a [u8]> {
    listed(mem, rsdp).find(|t| &t[..4] == sig)
}

/// Offsets in the FADT: the DSDT's 32-bit address, the table's
/// revision, and the DSDT's 64-bit address, which revision 3 added.
const FADT_DSDT: usize = 40;
const SDT_REVISION: usize = 8;
const FADT_X_DSDT: usize = 140;

/// The table an operating system's ACPI driver asks its HAL for by
/// signature, as Windows' HAL answers:
///
/// - `RSDT` or `XSDT`: the root table, whichever of the two the firmware
///   has (the XSDT when there is one), under either name;
/// - `DSDT`: the table the FADT points to, which no root table lists:
///   by its 64-bit address from revision 3 of the FADT when that is not
///   zero, else by the 32-bit one;
/// - any other: the first listed table of that signature whose OEM id
///   and OEM table id are the ones given, where they are given.
pub fn lookup<'a>(
    mem: &'a impl PhysMem,
    rsdp: u64,
    sig: &[u8; 4],
    oem_id: Option<&[u8; 6]>,
    oem_table_id: Option<&[u8; 8]>,
) -> Option<&'a [u8]> {
    match sig {
        b"RSDT" | b"XSDT" => root(mem, rsdp).map(|(root, _)| root),
        b"DSDT" => {
            let fadt = find_table(mem, rsdp, b"FACP")?;
            let wide = if fadt[SDT_REVISION] >= 3 {
                u64_at(fadt, FADT_X_DSDT).unwrap_or(0)
            } else {
                0
            };
            let at = if wide != 0 {
                wide
            } else {
                u64::from(u32_at(fadt, FADT_DSDT)?)
            };
            table(mem, at).filter(|t| &t[..4] == b"DSDT")
        }
        _ => listed(mem, rsdp).find(|t| {
            &t[..4] == sig
                && oem_id.is_none_or(|id| &t[10..16] == id)
                && oem_table_id.is_none_or(|id| &t[16..24] == id)
        }),
    }
}

/// The console UART described by an SPCR table.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Spcr {
    /// SPCR interface type: 0 and 1 are 16550-compatible, 3 is ARM PL011.
    pub interface: u8,
    /// True if `address` is a memory address, false for an I/O port.
    pub mmio: bool,
    pub address: u64,
}

pub fn spcr(table: &[u8]) -> Option<Spcr> {
    let address = u64_at(table, 44)?;
    Some(Spcr {
        interface: *table.get(36)?,
        mmio: *table.get(40)? == 0,
        address,
    })
}

/// The interrupt of the console UART an SPCR table describes, as a
/// global system interrupt: on ARM, the GIC interrupt id. `None` if the
/// table names no such interrupt.
pub fn spcr_interrupt(table: &[u8]) -> Option<u32> {
    /// Interrupt type bits that say the GSI field is meaningful: I/O
    /// APIC, I/O SAPIC, ARM GIC.
    const HAS_GSI: u8 = 0b1110;
    (*table.get(52)? & HAS_GSI != 0).then(|| u32_at(table, 54))?
}

/// The physical address of the registers of the high precision event
/// timer an HPET table describes, if they are in memory.
pub fn hpet(table: &[u8]) -> Option<u64> {
    let in_memory = *table.get(40)? == 0;
    u64_at(table, 44).filter(|&address| in_memory && address != 0)
}

/// One entry of the MADT that NK acts on. Processor entries of both
/// encodings (8-bit APIC id and x2APIC) read as [`MadtEntry::LocalApic`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MadtEntry {
    /// An x86 processor, by its local APIC id.
    LocalApic {
        uid: u32,
        id: u32,
        /// Usable now.
        enabled: bool,
        /// Not enabled, but the system may bring it online later.
        online_capable: bool,
    },
    IoApic {
        id: u8,
        address: u32,
        gsi_base: u32,
    },
    /// 64-bit replacement for the header's local APIC address.
    LocalApicAddress(u64),
    /// An ARM processor: its GIC CPU interface.
    Gicc {
        uid: u32,
        mpidr: u64,
        enabled: bool,
        /// This processor's redistributor, when the table lists
        /// redistributors per processor rather than as regions; else 0.
        gicr_base: u64,
    },
    /// The GIC distributor. `version` 0 means "ask the hardware".
    Gicd {
        address: u64,
        version: u8,
    },
    /// A region holding the redistributors of several processors.
    Gicr {
        address: u64,
        length: u32,
    },
    /// An entry type NK does not use yet.
    Other(u8),
}

/// The Multiple APIC Description Table: processors and interrupt
/// controllers.
#[derive(Debug, Clone, Copy)]
pub struct Madt<'a> {
    /// Local APIC address from the header (x86; 32-bit).
    pub local_apic: u32,
    entries: &'a [u8],
}

const MADT_ENTRIES: usize = 44;

/// Parse a MADT. `None` if any entry is malformed: a table that cannot be
/// read to its end is not trusted for its beginning either.
pub fn madt(table: &[u8]) -> Option<Madt<'_>> {
    let madt = Madt {
        local_apic: u32_at(table, 36)?,
        entries: table.get(MADT_ENTRIES..)?,
    };
    let mut rest = madt.entries;
    while !rest.is_empty() {
        let len = usize::from(*rest.get(1)?);
        if len < 2 || len > rest.len() || entry(&rest[..len]).is_none() {
            return None;
        }
        rest = &rest[len..];
    }
    Some(madt)
}

/// Decode one entry; `None` if it is too short for its type.
fn entry(e: &[u8]) -> Option<MadtEntry> {
    Some(match e[0] {
        0 => {
            let flags = u32_at(e, 4)?;
            MadtEntry::LocalApic {
                uid: u32::from(e[2]),
                id: u32::from(e[3]),
                enabled: flags & 1 != 0,
                online_capable: flags & 2 != 0,
            }
        }
        1 => MadtEntry::IoApic {
            id: e[2],
            address: u32_at(e, 4)?,
            gsi_base: u32_at(e, 8)?,
        },
        5 => MadtEntry::LocalApicAddress(u64_at(e, 4)?),
        9 => {
            let flags = u32_at(e, 8)?;
            MadtEntry::LocalApic {
                uid: u32_at(e, 12)?,
                id: u32_at(e, 4)?,
                enabled: flags & 1 != 0,
                online_capable: flags & 2 != 0,
            }
        }
        0xB => MadtEntry::Gicc {
            uid: u32_at(e, 8)?,
            mpidr: u64_at(e, 68)?,
            enabled: u32_at(e, 12)? & 1 != 0,
            gicr_base: u64_at(e, 60)?,
        },
        0xC => MadtEntry::Gicd {
            address: u64_at(e, 8)?,
            version: *e.get(20)?,
        },
        0xE => MadtEntry::Gicr {
            address: u64_at(e, 4)?,
            length: u32_at(e, 12)?,
        },
        other => MadtEntry::Other(other),
    })
}

impl<'a> Madt<'a> {
    pub fn entries(&self) -> impl Iterator<Item = MadtEntry> + 'a {
        let mut rest = self.entries;
        core::iter::from_fn(move || {
            // `madt` checked every length, so this neither panics nor
            // stops early.
            let len = usize::from(*rest.get(1)?);
            let (this, next) = rest.split_at_checked(len)?;
            rest = next;
            entry(this)
        })
    }
}

/// The ACPI power-management timer: a free-running counter at a fixed,
/// known rate, which makes it a reference to calibrate other clocks by.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PmTimer {
    /// I/O port of the 32-bit counter register.
    pub port: u16,
    /// Whether all 32 bits count; otherwise only the low 24 do.
    pub wide: bool,
}

/// The power-management timer's rate, in ticks per second.
pub const PM_TIMER_HZ: u64 = 3_579_545;

/// The power-management timer described by a FADT (`FACP`) table, if it
/// has one on I/O ports.
pub fn pm_timer(fadt: &[u8]) -> Option<PmTimer> {
    let port = u32_at(fadt, 76)?;
    let length = *fadt.get(91)?;
    let flags = u32_at(fadt, 112)?;
    if port == 0 || port > 0xFFFF || length != 4 {
        return None;
    }
    Some(PmTimer {
        port: port as u16,
        wide: flags & 1 << 8 != 0,
    })
}

/// Ticks of the power-management timer from reading `earlier` to reading
/// `later`, allowing for the counter wrapping once.
pub fn pm_timer_delta(timer: PmTimer, earlier: u32, later: u32) -> u32 {
    let mask = if timer.wide { u32::MAX } else { 0x00FF_FFFF };
    later.wrapping_sub(earlier) & mask
}

/// How an ARM machine's firmware is called for power control (PSCI).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Psci {
    /// By a secure monitor call.
    Smc,
    /// By a hypervisor call.
    Hvc,
}

/// Whether, and how, PSCI is offered: the ARM boot flags of a FADT.
pub fn psci(fadt: &[u8]) -> Option<Psci> {
    let flags = u16::from_le_bytes([*fadt.get(129)?, *fadt.get(130)?]);
    match flags & 3 {
        0b01 => Some(Psci::Smc),
        0b11 => Some(Psci::Hvc),
        _ => None,
    }
}

/// The interrupt of the ARM virtual timer, from a GTDT table.
pub fn virtual_timer_interrupt(gtdt: &[u8]) -> Option<u32> {
    u32_at(gtdt, 64).filter(|&id| id != 0)
}

/// A processor as firmware names it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Cpu {
    /// Local APIC id (x86-64) or MPIDR affinity (arm64).
    pub hw_id: u64,
    /// ACPI processor UID.
    pub uid: u32,
}

/// Why a processor list from firmware cannot be used.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CensusError {
    /// The processor running this code is not in the list.
    NoBootProcessor,
    /// The boot processor is listed more than once.
    BootProcessorTwice,
    /// Another processor is listed more than once.
    ProcessorTwice,
}

/// Number the processors: the boot processor (hardware id `boot`) is 0,
/// as on Windows, and the rest follow in the order firmware lists them.
/// Fills `out` and returns how many it holds, and whether firmware listed
/// more than fit.
pub fn census(
    boot: u64,
    listed: impl Iterator<Item = Cpu>,
    out: &mut [Cpu],
) -> Result<(usize, bool), CensusError> {
    // Slot 0 is kept for the boot processor wherever the list has it.
    let (mut n, mut boot_seen, mut more) = (1, false, false);
    for cpu in listed {
        if cpu.hw_id == boot {
            if boot_seen {
                return Err(CensusError::BootProcessorTwice);
            }
            if let Some(first) = out.first_mut() {
                *first = cpu;
            }
            boot_seen = true;
        } else if out
            .get(1..n)
            .is_some_and(|rest| rest.iter().any(|c| c.hw_id == cpu.hw_id))
        {
            return Err(CensusError::ProcessorTwice);
        } else if n < out.len() {
            out[n] = cpu;
            n += 1;
        } else {
            more = true;
        }
    }
    if !boot_seen || out.is_empty() {
        return Err(CensusError::NoBootProcessor);
    }
    Ok((n, more))
}

/// One entry of the MCFG table: the memory-mapped configuration space
/// (ECAM) of the buses `start_bus..=end_bus` of one PCI segment group.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Ecam {
    /// Physical address of the configuration space of bus 0 of the
    /// segment, whether or not bus 0 is in the range.
    pub base: u64,
    pub segment: u16,
    pub start_bus: u8,
    pub end_bus: u8,
}

/// Bytes of configuration space per function, per device and per bus.
pub const ECAM_FUNCTION: u64 = 0x1000;
const ECAM_DEVICE: u64 = 8 * ECAM_FUNCTION;
/// Bytes of configuration space per bus.
pub const ECAM_BUS: u64 = 32 * ECAM_DEVICE;

impl Ecam {
    /// Whether this entry holds the configuration space of `bus` of
    /// `segment`.
    pub const fn covers(&self, segment: u16, bus: u8) -> bool {
        self.segment == segment && self.start_bus <= bus && bus <= self.end_bus
    }

    /// Physical address of the first bus the entry covers, and the bytes
    /// its buses take.
    pub const fn span(&self) -> (u64, u64) {
        (
            self.base + self.start_bus as u64 * ECAM_BUS,
            (self.end_bus as u64 - self.start_bus as u64 + 1) * ECAM_BUS,
        )
    }

    /// Where, from the address [`span`](Self::span) starts at, the
    /// configuration space of a function begins. `None` for a bus the
    /// entry does not cover or a device or function number out of range.
    pub const fn function_offset(&self, bus: u8, device: u8, function: u8) -> Option<u64> {
        if !self.covers(self.segment, bus) || device >= 32 || function >= 8 {
            return None;
        }
        Some(
            (bus - self.start_bus) as u64 * ECAM_BUS
                + device as u64 * ECAM_DEVICE
                + function as u64 * ECAM_FUNCTION,
        )
    }
}

const MCFG_ENTRIES: usize = 44;
const MCFG_ENTRY: usize = 16;

/// The entries of an MCFG table
/// ([PCI Firmware Specification](https://pcisig.com/specifications), "MCFG
/// Table Description"). An entry whose bus range runs backwards, or whose
/// buses would lie past the end of the address space, is left out; a
/// table too short for its header has none.
pub fn mcfg(table: &[u8]) -> impl Iterator<Item = Ecam> + '_ {
    table
        .get(MCFG_ENTRIES..)
        .unwrap_or(&[])
        .as_chunks::<MCFG_ENTRY>()
        .0
        .iter()
        .filter_map(|e| {
            let entry = Ecam {
                base: u64_at(e, 0)?,
                segment: u16::from_le_bytes([e[8], e[9]]),
                start_bus: e[10],
                end_bus: e[11],
            };
            let fits = entry.start_bus <= entry.end_bus
                && entry
                    .base
                    .checked_add((u64::from(entry.end_bus) + 1) * ECAM_BUS)
                    .is_some();
            fits.then_some(entry)
        })
}

/// How a MADT interrupt source override, or a GSI's own default, says a
/// line signals.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Signal {
    /// As the bus the source is on defines it.
    BusDefault,
    /// Active high (polarity) or edge triggered (trigger mode).
    HighOrEdge,
    /// Active low (polarity) or level triggered (trigger mode).
    LowOrLevel,
}

fn signal(bits: u16) -> Option<Signal> {
    match bits & 3 {
        0 => Some(Signal::BusDefault),
        1 => Some(Signal::HighOrEdge),
        3 => Some(Signal::LowOrLevel),
        _ => None,
    }
}

/// A MADT interrupt source override: ISA interrupt `source` arrives as
/// global system interrupt `gsi`, signalling as stated.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SourceOverride {
    pub source: u8,
    pub gsi: u32,
    pub polarity: Signal,
    pub trigger: Signal,
}

impl<'a> Madt<'a> {
    /// The interrupt source overrides (entry type 2) of the table. One
    /// with a reserved polarity or trigger value is left out.
    pub fn source_overrides(&self) -> impl Iterator<Item = SourceOverride> + 'a {
        let mut rest = self.entries;
        core::iter::from_fn(move || {
            loop {
                let len = usize::from(*rest.get(1)?);
                let (this, next) = rest.split_at_checked(len.max(2))?;
                rest = next;
                if this[0] == 2 && this.len() >= 10 {
                    let flags = u16::from_le_bytes([this[8], this[9]]);
                    if let (Some(gsi), Some(polarity), Some(trigger)) =
                        (u32_at(this, 4), signal(flags), signal(flags >> 2))
                    {
                        return Some(SourceOverride {
                            source: this[3],
                            gsi,
                            polarity,
                            trigger,
                        });
                    }
                }
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Physical memory starting at address 0x1000.
    struct Fake(Vec<u8>);

    impl PhysMem for Fake {
        fn bytes(&self, addr: u64, len: usize) -> Option<&[u8]> {
            let off = usize::try_from(addr.checked_sub(0x1000)?).ok()?;
            self.0.get(off..off.checked_add(len)?)
        }
    }

    fn sdt(sig: &[u8; 4], body: &[u8]) -> Vec<u8> {
        let mut t = vec![0u8; SDT_HEADER];
        t[..4].copy_from_slice(sig);
        t[4..8].copy_from_slice(&((SDT_HEADER + body.len()) as u32).to_le_bytes());
        t.extend_from_slice(body);
        t
    }

    fn spcr_body(interface: u8, space: u8, addr: u64) -> Vec<u8> {
        let mut b = vec![0u8; 44];
        b[0] = interface;
        b[4] = space;
        b[8..16].copy_from_slice(&addr.to_le_bytes());
        b
    }

    /// RSDP at 0x1000, root table at 0x1100, tables from 0x1200 every 0x100.
    fn firmware(xsdt: bool, tables: &[Vec<u8>]) -> Fake {
        let mut m = vec![0u8; 0x1000];
        m[..8].copy_from_slice(b"RSD PTR ");
        let width = if xsdt { 8 } else { 4 };
        let mut entries = Vec::new();
        for (i, t) in tables.iter().enumerate() {
            let addr = 0x1200 + 0x100 * i as u64;
            m[(addr - 0x1000) as usize..][..t.len()].copy_from_slice(t);
            entries.extend_from_slice(&addr.to_le_bytes()[..width]);
        }
        let root = sdt(if xsdt { b"XSDT" } else { b"RSDT" }, &entries);
        m[0x100..][..root.len()].copy_from_slice(&root);
        if xsdt {
            m[15] = 2;
            m[24..32].copy_from_slice(&0x1100u64.to_le_bytes());
        } else {
            m[16..20].copy_from_slice(&0x1100u32.to_le_bytes());
        }
        Fake(m)
    }

    #[test]
    fn finds_spcr_via_xsdt_and_rsdt() {
        for xsdt in [true, false] {
            let fw = firmware(
                xsdt,
                &[
                    sdt(b"FACP", &[0; 8]),
                    sdt(b"SPCR", &spcr_body(3, 0, 0x0900_0000)),
                ],
            );
            let t = find_table(&fw, 0x1000, b"SPCR").expect("SPCR");
            assert_eq!(
                spcr(t),
                Some(Spcr {
                    interface: 3,
                    mmio: true,
                    address: 0x0900_0000
                })
            );
            assert!(find_table(&fw, 0x1000, b"MCFG").is_none());
        }
    }

    #[test]
    fn a_table_is_looked_up_as_the_hal_answers_the_acpi_driver() {
        for xsdt in [true, false] {
            let oem = |id: &[u8; 6], table: &[u8; 8]| {
                let mut t = sdt(b"SSDT", &[0; 4]);
                t[10..16].copy_from_slice(id);
                t[16..24].copy_from_slice(table);
                t
            };
            // A revision 1 FADT has only the 32-bit address of the DSDT.
            let mut body = vec![0u8; 112];
            body[FADT_DSDT - SDT_HEADER..][..4].copy_from_slice(&0x1800u32.to_le_bytes());
            let mut fadt = sdt(b"FACP", &body);
            fadt[SDT_REVISION] = 1;
            let mut fw = firmware(
                xsdt,
                &[
                    fadt,
                    oem(b"NKNKNK", b"FIRST   "),
                    oem(b"NKNKNK", b"SECOND  "),
                ],
            );
            let dsdt = sdt(b"DSDT", &[7; 12]);
            fw.0[0x800..][..dsdt.len()].copy_from_slice(&dsdt);

            let find = |sig, id, table| lookup(&fw, 0x1000, sig, id, table);
            let name: &[u8] = if xsdt { b"XSDT" } else { b"RSDT" };
            assert_eq!(&find(b"RSDT", None, None).unwrap()[..4], name);
            assert_eq!(&find(b"XSDT", None, None).unwrap()[..4], name);
            assert_eq!(find(b"DSDT", None, None).unwrap(), &dsdt[..]);
            assert_eq!(&find(b"SSDT", None, None).unwrap()[16..24], b"FIRST   ");
            assert_eq!(
                &find(b"SSDT", Some(b"NKNKNK"), Some(b"SECOND  ")).unwrap()[16..24],
                b"SECOND  "
            );
            assert!(find(b"SSDT", Some(b"OTHER "), None).is_none());
            assert!(find(b"SSDT", None, Some(b"THIRD   ")).is_none());
            assert!(find(b"MCFG", None, None).is_none());
        }
    }

    /// From revision 3 the FADT's 64-bit address of the DSDT is used,
    /// unless it is zero.
    #[test]
    fn the_dsdt_is_found_by_the_fadt_s_wide_address_when_it_has_one() {
        let dsdt = sdt(b"DSDT", &[9; 4]);
        for (wide, narrow, found) in [
            (0x1900u64, 0x1800u32, true),
            (0, 0x1900, true),
            (0, 0, false),
        ] {
            let mut body = vec![0u8; 240];
            body[FADT_DSDT - SDT_HEADER..][..4].copy_from_slice(&narrow.to_le_bytes());
            body[FADT_X_DSDT - SDT_HEADER..][..8].copy_from_slice(&wide.to_le_bytes());
            let mut fadt = sdt(b"FACP", &body);
            fadt[SDT_REVISION] = 5;
            let mut fw = firmware(true, &[fadt]);
            fw.0[0x900..][..dsdt.len()].copy_from_slice(&dsdt);
            assert_eq!(lookup(&fw, 0x1000, b"DSDT", None, None).is_some(), found);
        }
    }

    #[test]
    fn the_console_s_interrupt_comes_from_the_spcr() {
        let table = |kind: u8, gsi: u32| {
            let mut body = spcr_body(3, 0, 0x0900_0000);
            body[52 - SDT_HEADER] = kind;
            body[54 - SDT_HEADER..58 - SDT_HEADER].copy_from_slice(&gsi.to_le_bytes());
            sdt(b"SPCR", &body)
        };
        // QEMU's arm64 `virt`: the GIC, interrupt 33.
        assert_eq!(spcr_interrupt(&table(8, 33)), Some(33));
        assert_eq!(spcr_interrupt(&table(2, 4)), Some(4));
        // A PC-AT interrupt alone names no GSI; nor does no interrupt.
        assert_eq!(spcr_interrupt(&table(1, 4)), None);
        assert_eq!(spcr_interrupt(&table(0, 33)), None);
        assert_eq!(spcr_interrupt(&table(8, 33)[..57]), None, "truncated");
        assert_eq!(spcr_interrupt(&[0; 40]), None);
    }

    #[test]
    fn the_event_timer_s_registers_come_from_the_hpet_table() {
        let table = |space: u8, address: u64| {
            let mut body = vec![0u8; 20];
            body[4] = space;
            body[8..16].copy_from_slice(&address.to_le_bytes());
            sdt(b"HPET", &body)
        };
        assert_eq!(hpet(&table(0, 0xFED0_0000)), Some(0xFED0_0000));
        assert_eq!(hpet(&table(1, 0xFED0_0000)), None, "I/O ports");
        assert_eq!(hpet(&table(0, 0)), None);
        assert_eq!(hpet(&table(0, 0xFED0_0000)[..50]), None, "truncated");
    }

    #[test]
    fn io_port_uart() {
        let s = spcr(&sdt(b"SPCR", &spcr_body(0, 1, 0x3F8))).unwrap();
        assert_eq!((s.mmio, s.address), (false, 0x3F8));
    }

    #[test]
    fn malformed_firmware_reads_as_absent() {
        let mut fw = firmware(true, &[sdt(b"SPCR", &spcr_body(3, 0, 0x0900_0000))]);
        assert!(
            find_table(&fw, 0x2000_0000, b"SPCR").is_none(),
            "unmapped RSDP"
        );
        assert!(find_table(&fw, 0x1100, b"SPCR").is_none(), "not an RSDP");
        // A table length that runs off the end of memory.
        fw.0[0x204..0x208].copy_from_slice(&0x000F_0000u32.to_le_bytes());
        assert!(find_table(&fw, 0x1000, b"SPCR").is_none());
        assert!(spcr(&[0; 40]).is_none(), "truncated SPCR");
    }

    #[test]
    fn a_table_whose_length_is_out_of_bounds_reads_as_absent() {
        // The SPCR is the first table: at 0x1200, its length at 0x1204.
        let length =
            |fw: &mut Fake, len: u32| fw.0[0x204..0x208].copy_from_slice(&len.to_le_bytes());
        let mut fw = firmware(true, &[sdt(b"SPCR", &spcr_body(3, 0, 0x0900_0000))]);
        // Enough memory that a long table is refused for its length, not
        // for running off the end.
        fw.0.resize(0x30_0000, 0);
        assert!(find_table(&fw, 0x1000, b"SPCR").is_some());
        // Shorter than its own header.
        for short in [0, 1, SDT_HEADER as u32 - 1] {
            length(&mut fw, short);
            assert!(find_table(&fw, 0x1000, b"SPCR").is_none(), "{short}");
        }
        // The header alone is a table, if an empty one.
        length(&mut fw, SDT_HEADER as u32);
        assert_eq!(find_table(&fw, 0x1000, b"SPCR").map(<[u8]>::len), Some(36));
        // Up to the bound, and not a byte past it.
        length(&mut fw, MAX_TABLE as u32);
        assert_eq!(
            find_table(&fw, 0x1000, b"SPCR").map(<[u8]>::len),
            Some(MAX_TABLE)
        );
        for long in [MAX_TABLE as u32 + 1, u32::MAX] {
            length(&mut fw, long);
            assert!(find_table(&fw, 0x1000, b"SPCR").is_none(), "{long:#x}");
        }
        // A root table with a bad length hides every table.
        length(&mut fw, 80);
        assert!(find_table(&fw, 0x1000, b"SPCR").is_some());
        fw.0[0x104..0x108].copy_from_slice(&35u32.to_le_bytes());
        assert!(find_table(&fw, 0x1000, b"SPCR").is_none());
    }

    fn madt_table(local_apic: u32, entries: &[Vec<u8>]) -> Vec<u8> {
        let mut body = local_apic.to_le_bytes().to_vec();
        body.extend_from_slice(&1u32.to_le_bytes());
        for e in entries {
            body.extend_from_slice(e);
        }
        sdt(b"APIC", &body)
    }

    fn lapic(uid: u8, id: u8, flags: u32) -> Vec<u8> {
        let mut e = vec![0, 8, uid, id];
        e.extend_from_slice(&flags.to_le_bytes());
        e
    }

    fn x2apic(id: u32, flags: u32, uid: u32) -> Vec<u8> {
        let mut e = vec![9, 16, 0, 0];
        for v in [id, flags, uid] {
            e.extend_from_slice(&v.to_le_bytes());
        }
        e
    }

    fn gicc(uid: u32, flags: u32, gicr: u64, mpidr: u64) -> Vec<u8> {
        let mut e = vec![0u8; 80];
        (e[0], e[1]) = (0xB, 80);
        e[8..12].copy_from_slice(&uid.to_le_bytes());
        e[12..16].copy_from_slice(&flags.to_le_bytes());
        e[60..68].copy_from_slice(&gicr.to_le_bytes());
        e[68..76].copy_from_slice(&mpidr.to_le_bytes());
        e
    }

    #[test]
    fn madt_x86() {
        let mut ioapic = vec![1, 12, 7, 0];
        ioapic.extend_from_slice(&0xFEC0_0000u32.to_le_bytes());
        ioapic.extend_from_slice(&24u32.to_le_bytes());
        let mut addr = vec![5, 12, 0, 0];
        addr.extend_from_slice(&0x1_FEE0_0000u64.to_le_bytes());
        let t = madt_table(
            0xFEE0_0000,
            &[
                lapic(0, 0, 1),
                lapic(1, 1, 1),
                lapic(2, 2, 0),
                lapic(3, 3, 2),
                ioapic,
                vec![2, 10, 0, 0, 2, 0, 0, 0, 0, 0], // interrupt source override
                x2apic(0x1_0000, 1, 9),
                addr,
            ],
        );
        let m = madt(&t).expect("MADT");
        assert_eq!(m.local_apic, 0xFEE0_0000);
        let e: Vec<MadtEntry> = m.entries().collect();
        let cpu = |uid, id, enabled, online_capable| MadtEntry::LocalApic {
            uid,
            id,
            enabled,
            online_capable,
        };
        assert_eq!(
            e,
            [
                cpu(0, 0, true, false),
                cpu(1, 1, true, false),
                cpu(2, 2, false, false),
                cpu(3, 3, false, true),
                MadtEntry::IoApic {
                    id: 7,
                    address: 0xFEC0_0000,
                    gsi_base: 24
                },
                MadtEntry::Other(2),
                cpu(9, 0x1_0000, true, false),
                MadtEntry::LocalApicAddress(0x1_FEE0_0000),
            ]
        );
    }

    #[test]
    fn madt_arm() {
        let mut gicd = vec![0u8; 24];
        (gicd[0], gicd[1], gicd[20]) = (0xC, 24, 3);
        gicd[8..16].copy_from_slice(&0x0800_0000u64.to_le_bytes());
        let mut gicr = vec![0xE, 16, 0, 0];
        gicr.extend_from_slice(&0x080A_0000u64.to_le_bytes());
        gicr.extend_from_slice(&0x00F6_0000u32.to_le_bytes());
        let t = madt_table(0, &[gicc(0, 1, 0, 0), gicc(1, 1, 0, 0x101), gicd, gicr]);
        let e: Vec<MadtEntry> = madt(&t).expect("MADT").entries().collect();
        assert_eq!(
            e,
            [
                MadtEntry::Gicc {
                    uid: 0,
                    mpidr: 0,
                    enabled: true,
                    gicr_base: 0
                },
                MadtEntry::Gicc {
                    uid: 1,
                    mpidr: 0x101,
                    enabled: true,
                    gicr_base: 0
                },
                MadtEntry::Gicd {
                    address: 0x0800_0000,
                    version: 3
                },
                MadtEntry::Gicr {
                    address: 0x080A_0000,
                    length: 0x00F6_0000
                },
            ]
        );
    }

    #[test]
    fn malformed_madt_reads_as_absent() {
        let good = madt_table(0xFEE0_0000, &[lapic(0, 0, 1), lapic(1, 1, 1)]);
        assert!(madt(&good).is_some());
        assert!(madt(&good[..40]).is_none(), "no room for the header");
        // An entry whose length runs past the table.
        let mut t = good.clone();
        t[MADT_ENTRIES + 8 + 1] = 9;
        assert!(madt(&t).is_none());
        // A zero-length entry would never advance.
        let mut t = good.clone();
        t[MADT_ENTRIES + 1] = 0;
        assert!(madt(&t).is_none());
        // An entry shorter than its type needs.
        let t = madt_table(
            0,
            &[vec![
                0xB, 20, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            ]],
        );
        assert!(madt(&t).is_none());
        // A table that ends in the middle of an entry header.
        let mut t = good;
        t.push(0);
        assert!(madt(&t).is_none());
    }

    fn cpus(ids: &[u64]) -> impl Iterator<Item = Cpu> + '_ {
        ids.iter().map(|&hw_id| Cpu {
            hw_id,
            uid: hw_id as u32 + 100,
        })
    }

    fn ids(out: &[Cpu], n: usize) -> Vec<u64> {
        out[..n].iter().map(|c| c.hw_id).collect()
    }

    #[test]
    fn census_puts_the_boot_processor_first() {
        let mut out = [Cpu { hw_id: 0, uid: 0 }; 8];
        let (n, more) = census(2, cpus(&[0, 1, 2, 3]), &mut out).unwrap();
        assert_eq!((ids(&out, n), more), (vec![2, 0, 1, 3], false));
        assert_eq!(out[0].uid, 102, "the entry itself, not just its id");
        // Already first, and alone.
        let (n, _) = census(0, cpus(&[0, 1]), &mut out).unwrap();
        assert_eq!(ids(&out, n), [0, 1]);
        let (n, _) = census(7, cpus(&[7]), &mut out).unwrap();
        assert_eq!(ids(&out, n), [7]);
    }

    #[test]
    fn census_rejects_lists_it_cannot_trust() {
        let mut out = [Cpu { hw_id: 0, uid: 0 }; 8];
        assert_eq!(
            census(9, cpus(&[0, 1]), &mut out),
            Err(CensusError::NoBootProcessor)
        );
        assert_eq!(
            census(0, cpus(&[]), &mut out),
            Err(CensusError::NoBootProcessor)
        );
        assert_eq!(
            census(1, cpus(&[0, 1, 1]), &mut out),
            Err(CensusError::BootProcessorTwice)
        );
        assert_eq!(
            census(0, cpus(&[0, 1, 2, 1]), &mut out),
            Err(CensusError::ProcessorTwice)
        );
        assert_eq!(
            census(0, cpus(&[0, 1]), &mut []),
            Err(CensusError::NoBootProcessor)
        );
    }

    #[test]
    fn census_keeps_what_fits_and_says_when_there_was_more() {
        let mut out = [Cpu { hw_id: 0, uid: 0 }; 3];
        let (n, more) = census(4, cpus(&[0, 1, 2, 3, 4]), &mut out).unwrap();
        assert_eq!((ids(&out, n), more), (vec![4, 0, 1], true));
        let (n, more) = census(0, cpus(&[0, 1, 2]), &mut out).unwrap();
        assert_eq!((n, more), (3, false));
        // A duplicate among the ones that did not fit is not noticed, and
        // does not matter: they are not used.
        assert!(census(0, cpus(&[0, 1, 2, 3, 3]), &mut out).is_ok());
    }

    fn fadt_table(port: u32, length: u8, flags: u32) -> Vec<u8> {
        let mut body = vec![0u8; 116 - SDT_HEADER];
        body[76 - SDT_HEADER..80 - SDT_HEADER].copy_from_slice(&port.to_le_bytes());
        body[91 - SDT_HEADER] = length;
        body[112 - SDT_HEADER..116 - SDT_HEADER].copy_from_slice(&flags.to_le_bytes());
        sdt(b"FACP", &body)
    }

    #[test]
    fn pm_timer_from_the_fadt() {
        let at = |wide| Some(PmTimer { port: 0x608, wide });
        assert_eq!(pm_timer(&fadt_table(0x608, 4, 1 << 8)), at(true));
        assert_eq!(pm_timer(&fadt_table(0x608, 4, 0)), at(false));
        assert_eq!(pm_timer(&fadt_table(0, 4, 0)), None, "no timer");
        assert_eq!(
            pm_timer(&fadt_table(0x608, 0, 0)),
            None,
            "no register length"
        );
        assert_eq!(
            pm_timer(&fadt_table(0x1_0000, 4, 0)),
            None,
            "not an I/O port"
        );
        assert_eq!(pm_timer(&fadt_table(0x608, 4, 0)[..100]), None, "truncated");
    }

    #[test]
    fn psci_from_the_fadt() {
        let with = |flags: u16| {
            let mut body = vec![0u8; 140 - SDT_HEADER];
            body[129 - SDT_HEADER..131 - SDT_HEADER].copy_from_slice(&flags.to_le_bytes());
            sdt(b"FACP", &body)
        };
        assert_eq!(psci(&with(0b01)), Some(Psci::Smc));
        assert_eq!(psci(&with(0b11)), Some(Psci::Hvc));
        assert_eq!(psci(&with(0b00)), None, "not offered");
        assert_eq!(psci(&with(0b10)), None, "a conduit without PSCI");
        assert_eq!(psci(&with(0b11)[..130]), None, "truncated");
        assert_eq!(
            psci(&fadt_table(0x608, 4, 0)),
            None,
            "an x86 FADT is shorter"
        );
    }

    #[test]
    fn pm_timer_deltas_survive_a_wrap() {
        let narrow = PmTimer {
            port: 0x608,
            wide: false,
        };
        let wide = PmTimer {
            port: 0x608,
            wide: true,
        };
        assert_eq!(pm_timer_delta(narrow, 100, 350), 250);
        assert_eq!(pm_timer_delta(narrow, 0x00FF_FFF0, 0x10), 0x20);
        assert_eq!(pm_timer_delta(wide, 0xFFFF_FFF0, 0x10), 0x20);
        assert_eq!(pm_timer_delta(wide, 0x00FF_FFF0, 0x0100_0010), 0x20);
    }

    #[test]
    fn virtual_timer_from_the_gtdt() {
        let mut body = vec![0u8; 80 - SDT_HEADER];
        body[64 - SDT_HEADER..68 - SDT_HEADER].copy_from_slice(&27u32.to_le_bytes());
        let table = sdt(b"GTDT", &body);
        assert_eq!(virtual_timer_interrupt(&table), Some(27));
        assert_eq!(virtual_timer_interrupt(&table[..66]), None, "truncated");
        assert_eq!(
            virtual_timer_interrupt(&sdt(b"GTDT", &[0; 44])),
            None,
            "no interrupt"
        );
    }

    fn mcfg_entry(base: u64, segment: u16, start: u8, end: u8) -> Vec<u8> {
        let mut e = base.to_le_bytes().to_vec();
        e.extend_from_slice(&segment.to_le_bytes());
        e.extend_from_slice(&[start, end, 0, 0, 0, 0]);
        e
    }

    fn mcfg_table(entries: &[Vec<u8>]) -> Vec<u8> {
        let mut body = vec![0u8; 8];
        for e in entries {
            body.extend_from_slice(e);
        }
        sdt(b"MCFG", &body)
    }

    #[test]
    fn mcfg_entries_come_from_the_table() {
        // q35's table, and a second segment whose buses start at 0x40.
        let t = mcfg_table(&[
            mcfg_entry(0xB000_0000, 0, 0, 0xFF),
            mcfg_entry(0x40_1000_0000, 1, 0x40, 0x7F),
        ]);
        let e: Vec<Ecam> = mcfg(&t).collect();
        assert_eq!(
            e,
            [
                Ecam {
                    base: 0xB000_0000,
                    segment: 0,
                    start_bus: 0,
                    end_bus: 0xFF
                },
                Ecam {
                    base: 0x40_1000_0000,
                    segment: 1,
                    start_bus: 0x40,
                    end_bus: 0x7F
                },
            ]
        );
        assert_eq!(e[0].span(), (0xB000_0000, 0x1000_0000));
        // The base is bus 0's even when bus 0 is not covered.
        assert_eq!(e[1].span(), (0x40_1400_0000, 0x400_0000));
        assert!(e[0].covers(0, 0) && e[0].covers(0, 0xFF) && !e[0].covers(1, 0));
        assert!(e[1].covers(1, 0x40) && e[1].covers(1, 0x7F));
        assert!(!e[1].covers(1, 0x3F) && !e[1].covers(1, 0x80));
    }

    #[test]
    fn a_function_s_configuration_space_is_found_by_bus_device_and_function() {
        let q35 = Ecam {
            base: 0xB000_0000,
            segment: 0,
            start_bus: 0,
            end_bus: 0xFF,
        };
        assert_eq!(q35.function_offset(0, 0, 0), Some(0));
        // 00:1f.2, the AHCI controller of an ICH9.
        assert_eq!(q35.function_offset(0, 0x1F, 2), Some(0xF_A000));
        assert_eq!(q35.function_offset(1, 0, 0), Some(0x10_0000));
        assert_eq!(q35.function_offset(0xFF, 31, 7), Some(0xFFF_F000));
        assert_eq!(q35.function_offset(0, 32, 0), None);
        assert_eq!(q35.function_offset(0, 0, 8), None);
        let part = Ecam {
            start_bus: 0x40,
            end_bus: 0x7F,
            ..q35
        };
        assert_eq!(part.function_offset(0x40, 0, 0), Some(0));
        assert_eq!(part.function_offset(0x41, 1, 1), Some(0x10_9000));
        assert_eq!(part.function_offset(0x3F, 0, 0), None);
        assert_eq!(part.function_offset(0x80, 0, 0), None);
    }

    #[test]
    fn a_malformed_mcfg_entry_is_left_out() {
        // Bus range backwards; buses past the end of the address space.
        let t = mcfg_table(&[
            mcfg_entry(0xB000_0000, 0, 9, 8),
            mcfg_entry(u64::MAX - 0xFFF, 0, 0, 0xFF),
            mcfg_entry(0xC000_0000, 2, 3, 3),
        ]);
        let e: Vec<Ecam> = mcfg(&t).collect();
        assert_eq!(e.len(), 1);
        assert_eq!((e[0].segment, e[0].start_bus), (2, 3));
        // A truncated last entry is not an entry; nor is a short table.
        assert_eq!(mcfg(&t[..t.len() - 1]).count(), 0);
        assert_eq!(mcfg(&t[..40]).count(), 0);
        assert_eq!(mcfg(&mcfg_table(&[])).count(), 0);
    }

    #[test]
    fn interrupt_source_overrides_come_from_the_madt() {
        let iso = |source: u8, gsi: u32, flags: u16| {
            let mut e = vec![2, 10, 0, source];
            e.extend_from_slice(&gsi.to_le_bytes());
            e.extend_from_slice(&flags.to_le_bytes());
            e
        };
        // QEMU's: the timer on GSI 2, and the PCI lines level, active high.
        let t = madt_table(
            0xFEE0_0000,
            &[
                lapic(0, 0, 1),
                iso(0, 2, 0),
                iso(5, 5, 0b1101),
                iso(9, 9, 0b1111),
                iso(10, 10, 0b0101),
                iso(11, 11, 0b0010), // reserved polarity value
                x2apic(1, 1, 1),
            ],
        );
        let o: Vec<SourceOverride> = madt(&t).unwrap().source_overrides().collect();
        let over = |source, gsi, polarity, trigger| SourceOverride {
            source,
            gsi,
            polarity,
            trigger,
        };
        assert_eq!(
            o,
            [
                over(0, 2, Signal::BusDefault, Signal::BusDefault),
                over(5, 5, Signal::HighOrEdge, Signal::LowOrLevel),
                over(9, 9, Signal::LowOrLevel, Signal::LowOrLevel),
                over(10, 10, Signal::HighOrEdge, Signal::HighOrEdge),
            ]
        );
    }
}
