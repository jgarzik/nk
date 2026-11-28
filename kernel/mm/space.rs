//! Per-process user address space (`AddressSpace`): owns the root page table,
//! low-half intermediate page-table hierarchy, and Virtual Address Descriptor
//! (`VadTree`) for a non-System process.
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

use super::{PAGE_SIZE, alloc_frames, free_frames, phys_to_virt};
use crate::arch;
use crate::ex::pushlock::{PushLock, ReadGuard, WriteGuard};
use core::sync::atomic::{AtomicU64, Ordering};
use nk_mm::pt::{self, Arch, MapError, Prot, TableMem};
use nk_mm::pte::UserSwPte;
use nk_mm::vad::{VadKind, VadTree};

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

/// Mutable virtual-memory state protected by [`AddressSpace::lock`].
pub struct AddressSpaceInner {
    pub vads: VadTree,
    pub committed_pages: u64,
    pub peak_commit: u64,
}

impl AddressSpaceInner {
    pub fn charge_commit(&mut self, pages: u64) {
        self.committed_pages = self.committed_pages.saturating_add(pages);
        if self.committed_pages > self.peak_commit {
            self.peak_commit = self.committed_pages;
        }
    }

    pub fn uncharge_commit(&mut self, pages: u64) {
        self.committed_pages = self.committed_pages.saturating_sub(pages);
    }
}

/// One non-System process's page-table hierarchy and VAD tree.
pub struct AddressSpace {
    /// Physical address of the root page table (CR3 / TTBR0_EL1), or 0 once
    /// destroyed. Immutable while live so context switch and attach can read
    /// it lock-free at `DISPATCH_LEVEL`.
    root: u64,
    /// Serialises VAD and page-table edits within this address space at
    /// `PASSIVE_LEVEL` / `APC_LEVEL` (in a critical region).
    lock: PushLock<AddressSpaceInner>,
}

/// Construct a valid user-mode 4 KiB hardware PTE, optionally setting the
/// architecture's OS-available copy-on-write bit.
pub fn valid_user_pte(pa: u64, prot: Prot, cow: bool) -> u64 {
    let arch_pt = arch::pt_arch();
    let mut entry = arch_pt.leaf(pa, 0, prot);
    if cow {
        entry |= arch_pt.cow_bit();
    }
    entry
}

/// Walk the 4-level page table rooted at `root` and return the raw 64-bit leaf
/// PTE for `va`, or `0` if any intermediate table is absent.
fn read_leaf_raw(root: u64, va: u64) -> u64 {
    let arch_pt = arch::pt_arch();
    let tables = UserTables;
    let mut table = root;
    for level in (1..=3).rev() {
        let idx = ((va >> (12 + 9 * level)) & 0x1FF) as usize;
        let entry = tables.read(table, idx);
        if !arch_pt.present(entry) || arch_pt.is_leaf(entry, level) {
            return 0;
        }
        table = arch_pt.addr(entry);
    }
    let idx = ((va >> 12) & 0x1FF) as usize;
    tables.read(table, idx)
}

/// Walk the 4-level page table rooted at `root`, allocating missing user
/// intermediate tables (with `U/S = 1`), and write raw `entry` at leaf `va`.
fn write_leaf_raw(root: u64, va: u64, entry: u64) -> Result<(), MapError> {
    let arch_pt = arch::pt_arch();
    let mut tables = UserTables;
    let mut table = root;
    for level in (1..=3).rev() {
        let idx = ((va >> (12 + 9 * level)) & 0x1FF) as usize;
        let cur = tables.read(table, idx);
        if !arch_pt.present(cur) {
            let child = tables.alloc_table().ok_or(MapError::NoMemory)?;
            tables.write(table, idx, arch_pt.table_for(child, true));
            table = child;
        } else if arch_pt.is_leaf(cur, level) {
            return Err(MapError::AlreadyMapped);
        } else {
            let user_bit = arch_pt.user_table_bit();
            if user_bit != 0 && (cur & user_bit) == 0 {
                tables.write(table, idx, cur | user_bit);
            }
            table = arch_pt.addr(cur);
        }
    }
    let idx = ((va >> 12) & 0x1FF) as usize;
    tables.write(table, idx, entry);
    Ok(())
}

/// If intermediate tables exist for `va`, read and zero its leaf PTE and
/// return the previous raw entry; otherwise return `0` without allocating.
fn clear_leaf_raw(root: u64, va: u64) -> u64 {
    let arch_pt = arch::pt_arch();
    let mut tables = UserTables;
    let mut table = root;
    for level in (1..=3).rev() {
        let idx = ((va >> (12 + 9 * level)) & 0x1FF) as usize;
        let entry = tables.read(table, idx);
        if !arch_pt.present(entry) || arch_pt.is_leaf(entry, level) {
            return 0;
        }
        table = arch_pt.addr(entry);
    }
    let idx = ((va >> 12) & 0x1FF) as usize;
    let old = tables.read(table, idx);
    if old != 0 {
        tables.write(table, idx, 0);
    }
    old
}

impl AddressSpace {
    /// Allocate a fresh user address space with an empty low half, the shared
    /// kernel half, and a read-only user mapping of `KUSER_SHARED_DATA` at
    /// `0x7FFE_0000`.
    pub fn new() -> Option<Self> {
        let root = alloc_frames(1)?;
        arch::copy_kernel_half(root);
        let space = Self {
            root,
            lock: PushLock::new(AddressSpaceInner {
                vads: VadTree::new(),
                committed_pages: 0,
                peak_commit: 0,
            }),
        };
        let kusd_frame = crate::ke::time::shared_data_frame();
        if kusd_frame != 0
            && space
                .map_page(nk_ntabi::ke::USER_SHARED_DATA, kusd_frame, Prot::USER_RO)
                .is_err()
        {
            // Drop frees intermediate tables and `root` cleanly.
            return None;
        }
        Some(space)
    }

    /// Physical address of this address space's root page table.
    pub fn root(&self) -> u64 {
        self.root
    }

    /// Acquire the address-space lock exclusively for VAD + PTE updates.
    pub fn lock(&self) -> WriteGuard<'_, AddressSpaceInner> {
        self.lock.lock()
    }

    /// Acquire the address-space lock shared for read-only queries.
    pub fn read(&self) -> ReadGuard<'_, AddressSpaceInner> {
        self.lock.read()
    }

    /// Read the raw leaf PTE for low-half `va` while holding the address-space lock.
    pub fn read_pte(&self, va: u64) -> u64 {
        debug_assert!(va >> 63 == 0);
        read_leaf_raw(self.root, va)
    }

    /// Write raw leaf PTE `entry` for low-half `va` while holding the lock.
    pub fn write_pte(&self, va: u64, entry: u64) -> Result<(), MapError> {
        debug_assert!(va >> 63 == 0);
        write_leaf_raw(self.root, va, entry)
    }

    /// Zero the leaf PTE for low-half `va` (without allocating tables) and return
    /// its previous raw value while holding the lock.
    pub fn clear_pte(&self, va: u64) -> u64 {
        debug_assert!(va >> 63 == 0);
        clear_leaf_raw(self.root, va)
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

    /// Free all private committed frames tracked by VADs, all user intermediate
    /// page-table frames, and the root table. No processor may be executing in
    /// this address space.
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
        let arch_pt = arch::pt_arch();
        let vads = {
            let mut inner = self.lock.lock();
            inner.committed_pages = 0;
            inner.vads.drain_all()
        };
        for vad in vads {
            match vad.kind {
                VadKind::Private => {
                    let mut va = vad.start;
                    while va < vad.end {
                        let old = clear_leaf_raw(root, va);
                        if old != 0 {
                            if arch_pt.present(old) {
                                free_frames(arch_pt.addr(old), 1);
                            } else if let UserSwPte::Transition { pfn, .. } = UserSwPte::decode(old)
                            {
                                free_frames(pfn * PAGE_SIZE as u64, 1);
                            }
                        }
                        va += PAGE_SIZE as u64;
                    }
                }
                VadKind::Mapped { .. } => {
                    super::view::unmap_vad(self, vad);
                }
            }
        }
        self.root = 0;
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
