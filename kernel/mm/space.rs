//! Per-process user address space (`AddressSpace`): owns the root page table
//! and low-half intermediate page-table hierarchy for a non-System process.
//!
//! On x86-64, slots `256..512` of the PML4 are copied once from `SYSTEM_CR3`
//! (whose high-half PDPTs were pre-allocated in `arch::low_half_init`), so all
//! kernel mappings are shared automatically without PML4 synchronization.
//! Slots `0..256` belong exclusively to this process and are freed on
//! [`AddressSpace::destroy`] / `Drop`.
//!
//! On arm64, `TTBR1_EL1` holds the kernel half independently, so the root
//! table (`TTBR0_EL1`) belongs wholly to this process and all `0..512` slots
//! are freed on teardown.

use super::{alloc_frames, free_frames, phys_to_virt};
use crate::arch;
use crate::ex::pushlock::PushLock;
use core::sync::atomic::{AtomicU64, Ordering};
use nk_mm::pt::{self, Arch, MapError, Prot, TableMem};

/// Page-table memory backed by individual frames that belong to one process
/// and will be freed when its [`AddressSpace`] is destroyed (unlike
/// `mm::map::Tables`, which accounts permanent kernel tables in `TABLE_FRAMES`).
struct UserTables;

impl TableMem for UserTables {
    fn alloc_table(&mut self) -> Option<u64> {
        alloc_frames(1)
    }

    fn read(&self, table: u64, index: usize) -> u64 {
        // SAFETY: `table` is a live page-table frame reachable through the
        // direct map; `index` is below 512.
        unsafe { AtomicU64::from_ptr(phys_to_virt(table).cast::<u64>().add(index)) }
            .load(Ordering::Relaxed)
    }

    fn write(&mut self, table: u64, index: usize, entry: u64) {
        // SAFETY: as in `read`.
        unsafe { AtomicU64::from_ptr(phys_to_virt(table).cast::<u64>().add(index)) }
            .store(entry, Ordering::Relaxed);
    }
}

/// Number of top-level entries owned by a user address space (`0..256` on
/// x86-64 because `256..512` are shared kernel PDPTs; all `0..512` in arm64's
/// `TTBR0_EL1`).
#[cfg(target_arch = "x86_64")]
const USER_ROOT_SLOTS: usize = 256;
#[cfg(target_arch = "aarch64")]
const USER_ROOT_SLOTS: usize = 512;

/// One non-System process's page-table hierarchy.
pub struct AddressSpace {
    /// Physical address of the root page table (CR3 / TTBR0_EL1), or 0 once
    /// destroyed. Immutable while live so context switch and attach can read
    /// it lock-free at `DISPATCH_LEVEL`.
    root: u64,
    /// Serialises page-table edits within this address space at `PASSIVE_LEVEL`
    /// / `APC_LEVEL` (in a critical region).
    lock: PushLock<()>,
}

impl AddressSpace {
    /// Allocate a fresh user address space with an empty low half and shared
    /// kernel half.
    pub fn new() -> Option<Self> {
        let root = alloc_frames(1)?;
        arch::copy_kernel_half(root);
        Some(Self {
            root,
            lock: PushLock::new(()),
        })
    }

    /// Physical address of this address space's root page table.
    pub fn root(&self) -> u64 {
        self.root
    }

    /// Map one 4 KiB page at low-half virtual address `va` to physical frame
    /// `pa` with protection `prot`.
    pub fn map_page(&self, va: u64, pa: u64, prot: Prot) -> Result<(), MapError> {
        assert!(
            va >> 63 == 0,
            "AddressSpace::map_page on kernel address {va:#x}"
        );
        let _guard = self.lock.lock();
        let arch_pt = arch::pt_arch();
        pt::map(&mut UserTables, &arch_pt, self.root, va, pa, 0, prot)?;
        arch::mapping_sync();
        Ok(())
    }

    /// Unmap the 4 KiB page at low-half virtual address `va`, returning its
    /// physical frame if mapped, and flush the TLB across processors.
    pub fn unmap_page(&self, va: u64) -> Option<u64> {
        assert!(
            va >> 63 == 0,
            "AddressSpace::unmap_page on kernel address {va:#x}"
        );
        let _guard = self.lock.lock();
        let arch_pt = arch::pt_arch();
        let pa = pt::unmap(&mut UserTables, &arch_pt, self.root, va)?;
        arch::flush_tlb_page(va);
        Some(pa)
    }

    /// Translate `va` in this address space.
    pub fn translate(&self, va: u64) -> Option<u64> {
        let _guard = self.lock.read();
        let arch_pt = arch::pt_arch();
        pt::translate(&UserTables, &arch_pt, self.root, va)
    }

    /// Free all user intermediate page-table frames and the root table.
    /// The caller must already have unmapped/freed any data frames and ensured
    /// no processor is executing in this address space.
    pub fn destroy(&mut self) {
        let root = self.root;
        if root == 0 {
            return;
        }
        assert_ne!(
            root,
            arch::kernel_address_space(),
            "cannot destroy the System address space"
        );
        assert_ne!(
            root,
            arch::current_address_space(),
            "cannot destroy the currently active address space"
        );
        self.root = 0;
        let arch_pt = arch::pt_arch();
        free_subtables(&arch_pt, root, 3, USER_ROOT_SLOTS);
        free_frames(root, 1);
    }
}

impl Drop for AddressSpace {
    fn drop(&mut self) {
        self.destroy();
    }
}

/// Recursively free all non-leaf child page tables under `table` (at `level`,
/// inspecting slots `0..slots`). Leaf data frames are NOT freed here.
fn free_subtables(arch_pt: &impl Arch, table: u64, level: u8, slots: usize) {
    if level == 0 {
        return;
    }
    let tables = UserTables;
    for slot in 0..slots {
        let entry = tables.read(table, slot);
        if !arch_pt.present(entry) || arch_pt.is_leaf(entry, level) {
            continue;
        }
        let child = arch_pt.addr(entry);
        free_subtables(arch_pt, child, level - 1, 512);
        free_frames(child, 1);
    }
}
