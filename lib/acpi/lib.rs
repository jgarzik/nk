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

/// Find the table with signature `sig` (for example `b"SPCR"`), starting
/// from the RSDP. Uses the XSDT when present, else the RSDT.
pub fn find_table<'a>(mem: &'a impl PhysMem, rsdp: u64, sig: &[u8; 4]) -> Option<&'a [u8]> {
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
    let root = table(mem, root)?;
    root[SDT_HEADER..].chunks_exact(width).find_map(|e| {
        let addr = if width == 8 {
            u64_at(e, 0)?
        } else {
            u64::from(u32_at(e, 0)?)
        };
        table(mem, addr).filter(|t| &t[..4] == sig)
    })
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
}
