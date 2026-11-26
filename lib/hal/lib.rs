//! What the hardware layer works out before it touches a register:
//! which interrupt controllers and processors firmware's MADT describes,
//! and how an IRQL, a processor or a period is encoded for an interrupt
//! controller or a timer; how PCI configuration space is addressed.
//!
//! Both architectures are built on every host, so the arm64 arithmetic
//! is tested where the kernel is developed. The registers themselves are
//! `kernel/arch`'s.

#![cfg_attr(not(test), no_std)]

pub mod arm;
pub mod pci;
pub mod x86;

/// MADT tables for the tests, built entry by entry.
#[cfg(test)]
mod table {
    /// A MADT with this local APIC address in its header.
    pub fn madt(local_apic: u32, entries: &[Vec<u8>]) -> Vec<u8> {
        let mut t = vec![0u8; 36];
        t.extend_from_slice(&local_apic.to_le_bytes());
        t.extend_from_slice(&1u32.to_le_bytes());
        for e in entries {
            t.extend_from_slice(e);
        }
        t
    }

    pub fn local_apic(uid: u8, id: u8, flags: u32) -> Vec<u8> {
        let mut e = vec![0, 8, uid, id];
        e.extend_from_slice(&flags.to_le_bytes());
        e
    }

    pub fn x2apic(id: u32, flags: u32, uid: u32) -> Vec<u8> {
        let mut e = vec![9, 16, 0, 0];
        for v in [id, flags, uid] {
            e.extend_from_slice(&v.to_le_bytes());
        }
        e
    }

    pub fn io_apic(id: u8, address: u32, gsi_base: u32) -> Vec<u8> {
        let mut e = vec![1, 12, id, 0];
        e.extend_from_slice(&address.to_le_bytes());
        e.extend_from_slice(&gsi_base.to_le_bytes());
        e
    }

    pub fn local_apic_address(address: u64) -> Vec<u8> {
        let mut e = vec![5, 12, 0, 0];
        e.extend_from_slice(&address.to_le_bytes());
        e
    }

    pub fn gicc(uid: u32, flags: u32, gicr: u64, mpidr: u64) -> Vec<u8> {
        let mut e = vec![0u8; 80];
        (e[0], e[1]) = (0xB, 80);
        e[8..12].copy_from_slice(&uid.to_le_bytes());
        e[12..16].copy_from_slice(&flags.to_le_bytes());
        e[60..68].copy_from_slice(&gicr.to_le_bytes());
        e[68..76].copy_from_slice(&mpidr.to_le_bytes());
        e
    }

    pub fn gicd(address: u64, version: u8) -> Vec<u8> {
        let mut e = vec![0u8; 24];
        (e[0], e[1], e[20]) = (0xC, 24, version);
        e[8..16].copy_from_slice(&address.to_le_bytes());
        e
    }

    pub fn gicr(address: u64, length: u32) -> Vec<u8> {
        let mut e = vec![0xE, 16, 0, 0];
        e.extend_from_slice(&address.to_le_bytes());
        e.extend_from_slice(&length.to_le_bytes());
        e
    }
}
