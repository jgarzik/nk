//! User-mode virtual memory manager: `NtAllocateVirtualMemory(Ex)`,
//! `NtFreeVirtualMemory`, `NtProtectVirtualMemory`, `NtQueryVirtualMemory`,
//! `NtSetInformationVirtualMemory`, `NtReadVirtualMemory`,
//! `NtWriteVirtualMemory`, and user-mode page-fault resolution (demand-zero,
//! copy-on-write, one-shot `PAGE_GUARD`, and automatic user stack growth).

#![allow(non_snake_case)]

use super::space::{AddressSpace, AddressSpaceInner, valid_user_pte};
use super::{PAGE_SIZE, alloc_frames, free_frames, phys_to_virt};
use crate::arch;
use crate::ke::thread;
use crate::ob::{handle, object};
use crate::ps::process;
use crate::svc::capture;
use core::ffi::c_void;
use nk_mm::protect::{
    self, MEM_COMMIT, MEM_DECOMMIT, MEM_FREE, MEM_LARGE_PAGES, MEM_RELEASE, MEM_RESERVE, MEM_RESET,
    MEM_TOP_DOWN, MEM_WRITE_WATCH, MM_PROT_EMPTY, MM_PROT_EXECUTE, MM_PROT_EXECUTE_READ,
    MM_PROT_EXECUTE_READWRITE, MM_PROT_EXECUTE_WRITECOPY, MM_PROT_GUARD, MM_PROT_NOACCESS,
    MM_PROT_READONLY, MM_PROT_READWRITE, MM_PROT_WRITECOPY, PAGE_NOACCESS, PAGE_READWRITE,
    mm_break_cow, mm_is_cow, mm_is_guard, mm_to_user_hw, mm_to_win32, user_hw_to_mm, win32_to_mm,
};
use nk_mm::pt::Arch;
use nk_mm::pte::{Access, UserSwPte};
use nk_mm::vad::{
    ALLOC_GRANULARITY, KUSD_WINDOW_END, KUSD_WINDOW_START, MIN_USER_VA, USER_PROBE_VA, Vad, VadKind,
};
use nk_ntabi::mm::{
    MEM_ADDRESS_REQUIREMENTS, MEM_EXTENDED_PARAMETER, MEM_EXTENDED_PARAMETER_ADDRESS_REQUIREMENTS,
    MEMORY_BASIC_INFORMATION, MEMORY_BASIC_INFORMATION_CLASS,
    MEMORY_MAPPED_FILENAME_INFORMATION_CLASS, MEMORY_RANGE_ENTRY, MEMORY_REGION_INFORMATION,
    MEMORY_REGION_INFORMATION_CLASS, VM_CFG_CALL_TARGET_INFORMATION, VM_PREFETCH_INFORMATION,
};
use nk_ntabi::status::*;
use nk_ntabi::thread as thread_layout;

const PAGE_MASK: u64 = PAGE_SIZE as u64 - 1;
const GRAN_MASK: u64 = ALLOC_GRANULARITY - 1;

/// Process access rights required by VM services.
const PROCESS_VM_OPERATION: u32 = 0x0008;
const PROCESS_VM_READ: u32 = 0x0010;
const PROCESS_VM_WRITE: u32 = 0x0020;
const PROCESS_QUERY_INFORMATION: u32 = 0x0400;

/// Offsets into user-mode `TEB` (`_NT_TIB` + `DeallocationStack`), verified in `ntdll.x64.pdb`.
const TEB_STACK_BASE: u64 = 0x0008;
const TEB_STACK_LIMIT: u64 = 0x0010;
const TEB_DEALLOCATION_STACK: u64 = 0x1478;

/// Outcome of resolving a page fault on a user-mode virtual address.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UserFault {
    /// Page is now valid and satisfies the faulting access; resume execution.
    Resolved,
    /// Non-stack `PAGE_GUARD` was cleared; raise `STATUS_GUARD_PAGE_VIOLATION`.
    GuardViolation,
    /// Stack guard hit the bottom of the stack VAD; raise `STATUS_STACK_OVERFLOW`.
    StackOverflow,
    /// Invalid or forbidden access; raise `STATUS_ACCESS_VIOLATION`.
    AccessViolation,
    /// Backing I/O or memory allocation failed; raise `STATUS_IN_PAGE_ERROR`.
    InPageError(NTSTATUS),
    /// Current process has no user `AddressSpace` (System process).
    NotUser,
}

/// Target process referenced by a VM system call (`NtCurrentProcess` or an
/// opened `Process` handle).
struct TargetProcess {
    proc: *mut u8,
    _owned: Option<object::ObRef>,
}

impl TargetProcess {
    fn resolve(
        process_handle: *mut c_void,
        desired_access: u32,
        mode: i8,
    ) -> Result<Self, NTSTATUS> {
        if process_handle.addr() == (-1isize) as usize {
            let proc = process::PsGetCurrentProcess().cast::<u8>();
            return Ok(Self { proc, _owned: None });
        }
        let (ob, _) = handle::reference_for(
            process_handle.addr() as u64,
            Some(&raw const object::PROCESS_TYPE),
            desired_access,
            capture::handle_mode(mode),
        )?;
        let proc = ob.body();
        Ok(Self {
            proc,
            _owned: Some(ob),
        })
    }

    fn space(&self) -> Result<&AddressSpace, NTSTATUS> {
        // SAFETY: `self.proc` is either the current process or kept alive by `self.owned`.
        unsafe { process::address_space(self.proc) }.ok_or(STATUS_INVALID_HANDLE)
    }

    fn is_current(&self) -> bool {
        self.proc == process::PsGetCurrentProcess().cast::<u8>()
    }
}

fn page_down(va: u64) -> u64 {
    va & !PAGE_MASK
}

fn page_up(size: u64) -> Option<u64> {
    size.checked_add(PAGE_MASK).map(|v| v & !PAGE_MASK)
}

fn gran_down(va: u64) -> u64 {
    va & !GRAN_MASK
}

/// Convert a `ZeroBits` parameter into an upper exclusive VA ceiling.
fn zero_bits_ceiling(zero_bits: usize) -> Result<u64, NTSTATUS> {
    if zero_bits == 0 {
        return Ok(USER_PROBE_VA);
    }
    let bits = zero_bits as u64;
    if bits <= 21 {
        // Count of required leading zero bits in a 32-bit-ish or 64-bit mask:
        // Windows defines `ZeroBits <= 21` as number of high-order zero bits
        // in the lower 32 bits (i.e. max address `< 1 << (32 - bits)`).
        let shift = 32 - bits;
        let limit = 1u64 << shift;
        Ok(limit.min(USER_PROBE_VA))
    } else {
        // Windows 64-bit extension: `ZeroBits > 21` is a bitmask of the highest
        // allowed address (like `0x7FFF_FFFF` for 2 GiB).
        let limit = bits.saturating_add(1).min(USER_PROBE_VA);
        if limit <= MIN_USER_VA {
            return Err(STATUS_INVALID_PARAMETER_3);
        }
        Ok(limit)
    }
}

/// Extract `(state, win32_protect)` of one page inside a known VAD from its raw PTE.
fn pte_state_and_protect(raw: u64) -> (u32, u32) {
    let arch_pt = arch::pt_arch();
    if raw == 0 {
        return (MEM_RESERVE, 0);
    }
    if arch_pt.present(raw) {
        let mm = user_hw_to_mm(
            arch_pt.writable(raw),
            arch_pt.executable(raw),
            (raw & arch_pt.cow_bit()) != 0,
        );
        return (MEM_COMMIT, mm_to_win32(mm));
    }
    match UserSwPte::decode(raw) {
        UserSwPte::Zero => (MEM_RESERVE, 0),
        UserSwPte::DemandZero { mm_prot } | UserSwPte::Transition { mm_prot, .. } => {
            (MEM_COMMIT, mm_to_win32(mm_prot))
        }
        UserSwPte::Prototype { .. } => (MEM_COMMIT, PAGE_READWRITE),
    }
}

/// True if `access` is permitted by non-guard `mm_prot`.
fn access_allowed(mm_prot: u8, access: Access) -> bool {
    match mm_prot {
        MM_PROT_READONLY => access == Access::Read,
        MM_PROT_READWRITE => matches!(access, Access::Read | Access::Write),
        MM_PROT_WRITECOPY => matches!(access, Access::Read | Access::Write),
        MM_PROT_EXECUTE | MM_PROT_EXECUTE_READ => {
            matches!(access, Access::Read | Access::Execute)
        }
        MM_PROT_EXECUTE_READWRITE | MM_PROT_EXECUTE_WRITECOPY => true,
        _ => false,
    }
}

/// Update one committed page's PTE to `new_mm_prot`. Returns `Err(STATUS_NOT_COMMITTED)`
/// if the page is uncommitted (`0`), or `Err(STATUS_INSUFFICIENT_RESOURCES)` if page
/// tables cannot be allocated. Also returns `(old_win32_prot, needs_tlb_flush)`.
fn protect_one_page(
    space: &AddressSpace,
    va: u64,
    new_mm_prot: u8,
) -> Result<(u32, bool), NTSTATUS> {
    let arch_pt = arch::pt_arch();
    let old = space.read_pte(va);
    if old == 0 {
        return Err(STATUS_NOT_COMMITTED);
    }
    if arch_pt.present(old) {
        let old_mm = user_hw_to_mm(
            arch_pt.writable(old),
            arch_pt.executable(old),
            (old & arch_pt.cow_bit()) != 0,
        );
        let pa = arch_pt.addr(old);
        let new_entry = if let Some((hw_prot, cow)) = mm_to_user_hw(new_mm_prot) {
            valid_user_pte(pa, hw_prot, cow)
        } else {
            // `PAGE_NOACCESS` or `PAGE_GUARD` on a resident frame: preserve the
            // physical frame in a Transition software PTE!
            UserSwPte::Transition {
                pfn: pa / PAGE_SIZE as u64,
                mm_prot: new_mm_prot,
            }
            .encode()
        };
        space
            .write_pte(va, new_entry)
            .map_err(|_| STATUS_INSUFFICIENT_RESOURCES)?;
        Ok((mm_to_win32(old_mm), true))
    } else {
        match UserSwPte::decode(old) {
            UserSwPte::Zero => Err(STATUS_NOT_COMMITTED),
            UserSwPte::DemandZero { mm_prot } => {
                let new_entry = UserSwPte::DemandZero {
                    mm_prot: new_mm_prot,
                }
                .encode();
                space
                    .write_pte(va, new_entry)
                    .map_err(|_| STATUS_INSUFFICIENT_RESOURCES)?;
                Ok((mm_to_win32(mm_prot), false))
            }
            UserSwPte::Transition { pfn, mm_prot } => {
                let pa = pfn * PAGE_SIZE as u64;
                let new_entry = if let Some((hw_prot, cow)) = mm_to_user_hw(new_mm_prot) {
                    valid_user_pte(pa, hw_prot, cow)
                } else {
                    UserSwPte::Transition {
                        pfn,
                        mm_prot: new_mm_prot,
                    }
                    .encode()
                };
                space
                    .write_pte(va, new_entry)
                    .map_err(|_| STATUS_INSUFFICIENT_RESOURCES)?;
                Ok((mm_to_win32(mm_prot), false))
            }
            UserSwPte::Prototype { .. } => {
                // Stage 2B extends this for mapped sections.
                Ok((PAGE_READWRITE, false))
            }
        }
    }
}

/// Core virtual memory allocator shared by `NtAllocateVirtualMemory` and
/// `NtAllocateVirtualMemoryEx`.
#[allow(clippy::too_many_arguments)]
fn allocate_vm(
    target: &TargetProcess,
    req_base: u64,
    req_size: u64,
    alloc_type: u32,
    protect: u32,
    min_va: u64,
    max_va: u64,
    alignment: u64,
) -> Result<(u64, u64), NTSTATUS> {
    let valid_flags =
        MEM_COMMIT | MEM_RESERVE | MEM_RESET | MEM_TOP_DOWN | MEM_WRITE_WATCH | MEM_LARGE_PAGES;
    if (alloc_type & !valid_flags) != 0 {
        return Err(STATUS_INVALID_PARAMETER_5);
    }
    let do_reserve = (alloc_type & MEM_RESERVE) != 0;
    let do_commit = (alloc_type & MEM_COMMIT) != 0;
    let do_reset = (alloc_type & MEM_RESET) != 0;
    if !do_reserve && !do_commit && !do_reset {
        return Err(STATUS_INVALID_PARAMETER_5);
    }
    if do_reset && (do_reserve || do_commit) {
        return Err(STATUS_INVALID_PARAMETER_5);
    }
    if req_size == 0 {
        return Err(STATUS_INVALID_PARAMETER_4);
    }
    let Some(mm_prot) = win32_to_mm(protect) else {
        return Err(STATUS_INVALID_PAGE_PROTECTION);
    };
    let space = target.space()?;
    let align = if alignment == 0 {
        ALLOC_GRANULARITY
    } else if !alignment.is_power_of_two() || alignment < ALLOC_GRANULARITY {
        return Err(STATUS_INVALID_PARAMETER);
    } else {
        alignment
    };

    let mut inner = space.lock();

    if do_reset {
        if req_base == 0 {
            return Err(STATUS_INVALID_PARAMETER_2);
        }
        let start = page_down(req_base);
        let end = page_up(
            req_base
                .checked_add(req_size)
                .ok_or(STATUS_INVALID_PARAMETER_4)?,
        )
        .ok_or(STATUS_INVALID_PARAMETER_4)?;
        let Some(vad) = inner.vads.find_containing(start) else {
            return Err(STATUS_MEMORY_NOT_ALLOCATED);
        };
        if end > vad.end {
            return Err(STATUS_MEMORY_NOT_ALLOCATED);
        }
        return Ok((start, end - start));
    }

    // Commit-only on an already-reserved VAD (when `req_base != 0` and `!do_reserve`).
    if do_commit && !do_reserve && req_base != 0 {
        let start = page_down(req_base);
        let end = page_up(
            req_base
                .checked_add(req_size)
                .ok_or(STATUS_INVALID_PARAMETER_4)?,
        )
        .ok_or(STATUS_INVALID_PARAMETER_4)?;
        if start < MIN_USER_VA || end > USER_PROBE_VA || start >= end {
            return Err(STATUS_CONFLICTING_ADDRESSES);
        }
        let Some(vad) = inner.vads.find_containing(start) else {
            return Err(STATUS_CONFLICTING_ADDRESSES);
        };
        if end > vad.end {
            return Err(STATUS_CONFLICTING_ADDRESSES);
        }
        let mut newly_committed = 0u64;
        let mut flushed = false;
        let mut va = start;
        while va < end {
            let raw = space.read_pte(va);
            if raw == 0 {
                let dz = UserSwPte::DemandZero { mm_prot }.encode();
                if space.write_pte(va, dz).is_err() {
                    // Roll back pages we just marked demand-zero.
                    let mut undo = start;
                    while undo < va {
                        let _ = space.clear_pte(undo);
                        undo += PAGE_SIZE as u64;
                    }
                    return Err(STATUS_INSUFFICIENT_RESOURCES);
                }
                newly_committed += 1;
            } else {
                // Already committed: Windows updates its protection to `protect`.
                let (_, need_flush) = protect_one_page(space, va, mm_prot)?;
                flushed |= need_flush;
            }
            va += PAGE_SIZE as u64;
        }
        if let Some(vad_mut) = inner.vads.find_containing_mut(start) {
            vad_mut.committed_pages += newly_committed;
        }
        inner.charge_commit(newly_committed);
        if flushed {
            arch::flush_tlb_range(start, ((end - start) / PAGE_SIZE as u64) as usize);
        }
        return Ok((start, end - start));
    }

    // Reserve a brand-new VAD (with optional immediate commit).
    // Note: Windows treats `MEM_COMMIT` with `BaseAddress == 0` as `MEM_RESERVE | MEM_COMMIT`.
    let (start, size) = if req_base == 0 {
        let size = page_up(req_size).ok_or(STATUS_INVALID_PARAMETER_4)?;
        let top_down = (alloc_type & MEM_TOP_DOWN) != 0;
        let Some(base) = inner.vads.find_gap(size, align, top_down, min_va, max_va) else {
            return Err(STATUS_NO_MEMORY);
        };
        (base, size)
    } else {
        let start = gran_down(req_base);
        let raw_end = req_base
            .checked_add(req_size)
            .ok_or(STATUS_INVALID_PARAMETER_4)?;
        let end = page_up(raw_end).ok_or(STATUS_INVALID_PARAMETER_4)?;
        if start < MIN_USER_VA || end > USER_PROBE_VA || start >= end {
            return Err(STATUS_CONFLICTING_ADDRESSES);
        }
        if inner.vads.overlaps(start, end) {
            return Err(STATUS_CONFLICTING_ADDRESSES);
        }
        (start, end - start)
    };
    let end = start + size;
    let pages = size / PAGE_SIZE as u64;

    if do_commit {
        let dz = UserSwPte::DemandZero { mm_prot }.encode();
        let mut va = start;
        while va < end {
            if space.write_pte(va, dz).is_err() {
                let mut undo = start;
                while undo < va {
                    let _ = space.clear_pte(undo);
                    undo += PAGE_SIZE as u64;
                }
                return Err(STATUS_INSUFFICIENT_RESOURCES);
            }
            va += PAGE_SIZE as u64;
        }
    }

    let vad = Vad {
        start,
        end,
        protect,
        kind: VadKind::Private,
        committed_pages: if do_commit { pages } else { 0 },
    };
    inner
        .vads
        .insert(vad)
        .map_err(|_| STATUS_CONFLICTING_ADDRESSES)?;
    if do_commit {
        inner.charge_commit(pages);
    }
    Ok((start, size))
}

/// [`NtAllocateVirtualMemory`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-ntallocatevirtualmemory).
///
/// # Safety
/// `base_address` and `region_size` must be valid pointers per `PreviousMode`.
pub unsafe extern "C" fn NtAllocateVirtualMemory(
    process_handle: *mut c_void,
    base_address: *mut *mut c_void,
    zero_bits: usize,
    region_size: *mut usize,
    allocation_type: u32,
    protect: u32,
) -> NTSTATUS {
    let mode = capture::mode();
    // SAFETY: per the contract; `capture::read` probes and fault-protects user pointers.
    let req_base = match unsafe { capture::read(base_address, mode) } {
        Ok(p) => p.addr() as u64,
        Err(st) => return st,
    };
    // SAFETY: as above.
    let req_size = match unsafe { capture::read(region_size, mode) } {
        Ok(s) => s as u64,
        Err(st) => return st,
    };
    let max_va = match zero_bits_ceiling(zero_bits) {
        Ok(v) => v,
        Err(st) => return st,
    };
    let target = match TargetProcess::resolve(process_handle, PROCESS_VM_OPERATION, mode) {
        Ok(t) => t,
        Err(st) => return st,
    };
    let (out_base, out_size) = match allocate_vm(
        &target,
        req_base,
        req_size,
        allocation_type,
        protect,
        MIN_USER_VA,
        max_va,
        ALLOC_GRANULARITY,
    ) {
        Ok(res) => res,
        Err(st) => return st,
    };
    // SAFETY: per the contract; `capture::write` probes and fault-protects user pointers.
    if let Err(st) = unsafe {
        capture::write(
            base_address,
            core::ptr::with_exposed_provenance_mut(out_base as usize),
            mode,
        )
    } {
        return st;
    }
    // SAFETY: as above.
    if let Err(st) = unsafe { capture::write(region_size, out_size as usize, mode) } {
        return st;
    }
    STATUS_SUCCESS
}

/// [`NtAllocateVirtualMemoryEx`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-ntallocatevirtualmemoryex).
///
/// # Safety
/// Pointer parameters must satisfy the NT service contract for `PreviousMode`.
pub unsafe extern "C" fn NtAllocateVirtualMemoryEx(
    process_handle: *mut c_void,
    base_address: *mut *mut c_void,
    region_size: *mut usize,
    allocation_type: u32,
    page_protection: u32,
    extended_parameters: *mut MEM_EXTENDED_PARAMETER,
    extended_parameter_count: u32,
) -> NTSTATUS {
    let mode = capture::mode();
    // SAFETY: per the contract; `capture::read` probes and fault-protects user pointers.
    let req_base = match unsafe { capture::read(base_address, mode) } {
        Ok(p) => p.addr() as u64,
        Err(st) => return st,
    };
    // SAFETY: as above.
    let req_size = match unsafe { capture::read(region_size, mode) } {
        Ok(s) => s as u64,
        Err(st) => return st,
    };

    let mut min_va = MIN_USER_VA;
    let mut max_va = USER_PROBE_VA;
    let mut align = ALLOC_GRANULARITY;

    if extended_parameter_count > 0 {
        if extended_parameters.is_null() || extended_parameter_count > 16 {
            return STATUS_INVALID_PARAMETER_6;
        }
        for i in 0..extended_parameter_count as usize {
            // SAFETY: `i < extended_parameter_count`; `capture::read` fault-protects user pointers.
            let param = match unsafe { capture::read(extended_parameters.add(i), mode) } {
                Ok(p) => p,
                Err(st) => return st,
            };
            let kind = param.Type & 0xFF;
            if kind == MEM_EXTENDED_PARAMETER_ADDRESS_REQUIREMENTS {
                let req_ptr = core::ptr::with_exposed_provenance::<MEM_ADDRESS_REQUIREMENTS>(
                    param.Value as usize,
                );
                // SAFETY: `capture::read` probes and fault-protects user pointers.
                let req = match unsafe { capture::read(req_ptr, mode) } {
                    Ok(r) => r,
                    Err(st) => return st,
                };
                if req.LowestStartingAddress != 0 {
                    min_va = req.LowestStartingAddress.max(MIN_USER_VA);
                }
                if req.HighestEndingAddress != 0 {
                    let hi = req
                        .HighestEndingAddress
                        .saturating_add(1)
                        .min(USER_PROBE_VA);
                    max_va = hi;
                }
                if req.Alignment != 0 {
                    align = req.Alignment;
                }
            }
        }
    }

    let target = match TargetProcess::resolve(process_handle, PROCESS_VM_OPERATION, mode) {
        Ok(t) => t,
        Err(st) => return st,
    };
    let (out_base, out_size) = match allocate_vm(
        &target,
        req_base,
        req_size,
        allocation_type,
        page_protection,
        min_va,
        max_va,
        align,
    ) {
        Ok(res) => res,
        Err(st) => return st,
    };
    // SAFETY: per the contract; `capture::write` probes and fault-protects user pointers.
    if let Err(st) = unsafe {
        capture::write(
            base_address,
            core::ptr::with_exposed_provenance_mut(out_base as usize),
            mode,
        )
    } {
        return st;
    }
    // SAFETY: as above.
    if let Err(st) = unsafe { capture::write(region_size, out_size as usize, mode) } {
        return st;
    }
    STATUS_SUCCESS
}

/// Free resident frames and zero PTEs across `[start, end)` of a private VAD.
/// Returns `(decommitted_pages, flushed_any_valid)`.
fn decommit_private_range(space: &AddressSpace, start: u64, end: u64) -> (u64, bool) {
    let arch_pt = arch::pt_arch();
    let mut decommitted = 0u64;
    let mut had_valid = false;
    let mut va = start;
    while va < end {
        let old = space.clear_pte(va);
        if old != 0 {
            decommitted += 1;
            if arch_pt.present(old) {
                had_valid = true;
                free_frames(arch_pt.addr(old), 1);
            } else if let UserSwPte::Transition { pfn, .. } = UserSwPte::decode(old) {
                free_frames(pfn * PAGE_SIZE as u64, 1);
            }
        }
        va += PAGE_SIZE as u64;
    }
    (decommitted, had_valid)
}

/// [`NtFreeVirtualMemory`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-ntfreevirtualmemory).
///
/// # Safety
/// `base_address` and `region_size` must satisfy `PreviousMode`.
pub unsafe extern "C" fn NtFreeVirtualMemory(
    process_handle: *mut c_void,
    base_address: *mut *mut c_void,
    region_size: *mut usize,
    free_type: u32,
) -> NTSTATUS {
    let mode = capture::mode();
    // SAFETY: per the contract; `capture::read` probes and fault-protects user pointers.
    let req_base = match unsafe { capture::read(base_address, mode) } {
        Ok(p) => p.addr() as u64,
        Err(st) => return st,
    };
    // SAFETY: as above.
    let req_size = match unsafe { capture::read(region_size, mode) } {
        Ok(s) => s as u64,
        Err(st) => return st,
    };
    if free_type != MEM_DECOMMIT && free_type != MEM_RELEASE {
        return STATUS_INVALID_PARAMETER_4;
    }
    let target = match TargetProcess::resolve(process_handle, PROCESS_VM_OPERATION, mode) {
        Ok(t) => t,
        Err(st) => return st,
    };
    let space = match target.space() {
        Ok(s) => s,
        Err(st) => return st,
    };

    let start = page_down(req_base);
    let mut inner = space.lock();
    let Some(vad) = inner.vads.find_containing(start).copied() else {
        return STATUS_MEMORY_NOT_ALLOCATED;
    };
    if !matches!(vad.kind, VadKind::Private) {
        return STATUS_UNABLE_TO_FREE_VM;
    }

    let (out_base, out_size) = if free_type == MEM_RELEASE {
        if req_size == 0 {
            if start != vad.start {
                return STATUS_FREE_VM_NOT_AT_BASE;
            }
        } else {
            let Some(end) = page_up(req_base.saturating_add(req_size)) else {
                return STATUS_INVALID_PARAMETER_3;
            };
            if start != vad.start || end != vad.end {
                return STATUS_UNABLE_TO_FREE_VM;
            }
        }
        let (decommitted, had_valid) = decommit_private_range(space, vad.start, vad.end);
        inner.vads.remove(vad.start);
        inner.uncharge_commit(decommitted);
        if had_valid {
            arch::flush_tlb_range(vad.start, vad.pages() as usize);
        }
        (vad.start, vad.len())
    } else {
        // MEM_DECOMMIT: `req_size == 0` decommits from `start` through `vad.end`.
        let end = if req_size == 0 {
            vad.end
        } else {
            let Some(e) = page_up(req_base.saturating_add(req_size)) else {
                return STATUS_INVALID_PARAMETER_3;
            };
            if e > vad.end {
                return STATUS_UNABLE_TO_FREE_VM;
            }
            e
        };
        let (decommitted, had_valid) = decommit_private_range(space, start, end);
        if let Some(vad_mut) = inner.vads.find_containing_mut(start) {
            vad_mut.committed_pages = vad_mut.committed_pages.saturating_sub(decommitted);
        }
        inner.uncharge_commit(decommitted);
        if had_valid {
            arch::flush_tlb_range(start, ((end - start) / PAGE_SIZE as u64) as usize);
        }
        (start, end - start)
    };
    drop(inner);

    // SAFETY: per the contract; `capture::write` probes and fault-protects user pointers.
    if let Err(st) = unsafe {
        capture::write(
            base_address,
            core::ptr::with_exposed_provenance_mut(out_base as usize),
            mode,
        )
    } {
        return st;
    }
    // SAFETY: as above.
    if let Err(st) = unsafe { capture::write(region_size, out_size as usize, mode) } {
        return st;
    }
    STATUS_SUCCESS
}

/// [`NtProtectVirtualMemory`](https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualprotectex).
///
/// # Safety
/// Pointer parameters must satisfy `PreviousMode`.
pub unsafe extern "C" fn NtProtectVirtualMemory(
    process_handle: *mut c_void,
    base_address: *mut *mut c_void,
    region_size: *mut usize,
    new_protect: u32,
    old_protect: *mut u32,
) -> NTSTATUS {
    let mode = capture::mode();
    // SAFETY: per the contract; `capture::read` probes and fault-protects user pointers.
    let req_base = match unsafe { capture::read(base_address, mode) } {
        Ok(p) => p.addr() as u64,
        Err(st) => return st,
    };
    // SAFETY: as above.
    let req_size = match unsafe { capture::read(region_size, mode) } {
        Ok(s) => s as u64,
        Err(st) => return st,
    };
    if req_size == 0 {
        return STATUS_INVALID_PARAMETER_3;
    }
    let Some(new_mm) = win32_to_mm(new_protect) else {
        return STATUS_INVALID_PAGE_PROTECTION;
    };
    let start = page_down(req_base);
    let Some(raw_end) = req_base.checked_add(req_size) else {
        return STATUS_INVALID_PARAMETER_3;
    };
    let Some(end) = page_up(raw_end) else {
        return STATUS_INVALID_PARAMETER_3;
    };
    let target = match TargetProcess::resolve(process_handle, PROCESS_VM_OPERATION, mode) {
        Ok(t) => t,
        Err(st) => return st,
    };
    let space = match target.space() {
        Ok(s) => s,
        Err(st) => return st,
    };

    let inner = space.lock();
    let Some(vad) = inner.vads.find_containing(start) else {
        return STATUS_CONFLICTING_ADDRESSES;
    };
    if end > vad.end {
        return STATUS_CONFLICTING_ADDRESSES;
    }
    // Verify every page in the range is committed before mutating any PTE.
    let mut check = start;
    while check < end {
        if space.read_pte(check) == 0 {
            return STATUS_NOT_COMMITTED;
        }
        check += PAGE_SIZE as u64;
    }

    let mut first_old = 0u32;
    let mut flushed = false;
    let mut va = start;
    while va < end {
        let (old_w32, need_flush) = match protect_one_page(space, va, new_mm) {
            Ok(v) => v,
            Err(st) => return st,
        };
        if va == start {
            first_old = old_w32;
        }
        flushed |= need_flush;
        va += PAGE_SIZE as u64;
    }
    drop(inner);

    if flushed {
        arch::flush_tlb_range(start, ((end - start) / PAGE_SIZE as u64) as usize);
    }

    // SAFETY: per the contract; `capture::write` probes and fault-protects user pointers.
    if let Err(st) = unsafe {
        capture::write(
            base_address,
            core::ptr::with_exposed_provenance_mut(start as usize),
            mode,
        )
    } {
        return st;
    }
    // SAFETY: as above.
    if let Err(st) = unsafe { capture::write(region_size, (end - start) as usize, mode) } {
        return st;
    }
    // SAFETY: as above.
    if let Err(st) = unsafe { capture::write(old_protect, first_old, mode) } {
        return st;
    }
    STATUS_SUCCESS
}

/// [`NtQueryVirtualMemory`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-ntqueryvirtualmemory).
///
/// # Safety
/// Output buffer and `return_length` must satisfy `PreviousMode`.
pub unsafe extern "C" fn NtQueryVirtualMemory(
    process_handle: *mut c_void,
    base_address: *const c_void,
    memory_information_class: u32,
    memory_information: *mut c_void,
    memory_information_length: usize,
    return_length: *mut usize,
) -> NTSTATUS {
    let mode = capture::mode();
    let va = page_down(base_address.addr() as u64);
    if va >= USER_PROBE_VA {
        return STATUS_INVALID_PARAMETER_2;
    }
    let target = match TargetProcess::resolve(process_handle, PROCESS_QUERY_INFORMATION, mode) {
        Ok(t) => t,
        Err(st) => return st,
    };
    let space = match target.space() {
        Ok(s) => s,
        Err(st) => return st,
    };

    match memory_information_class {
        MEMORY_BASIC_INFORMATION_CLASS => {
            let needed = size_of::<MEMORY_BASIC_INFORMATION>();
            if memory_information_length < needed {
                if !return_length.is_null() {
                    // SAFETY: per the contract; `capture::write` probes user pointers.
                    let _ = unsafe { capture::write(return_length, needed, mode) };
                }
                return STATUS_INFO_LENGTH_MISMATCH;
            }
            let inner = space.read();
            let info = if (KUSD_WINDOW_START..KUSD_WINDOW_END).contains(&va) {
                MEMORY_BASIC_INFORMATION {
                    BaseAddress: va,
                    AllocationBase: KUSD_WINDOW_START,
                    AllocationProtect: protect::PAGE_READONLY,
                    PartitionId: 0,
                    _pad0: 0,
                    RegionSize: KUSD_WINDOW_END - va,
                    State: MEM_COMMIT,
                    Protect: protect::PAGE_READONLY,
                    Type: protect::MEM_PRIVATE,
                    _pad1: 0,
                }
            } else if let Some(vad) = inner.vads.find_containing(va) {
                let (state, prot) = pte_state_and_protect(space.read_pte(va));
                let mut end = va + PAGE_SIZE as u64;
                while end < vad.end {
                    let (s2, p2) = pte_state_and_protect(space.read_pte(end));
                    if s2 != state || p2 != prot {
                        break;
                    }
                    end += PAGE_SIZE as u64;
                }
                MEMORY_BASIC_INFORMATION {
                    BaseAddress: va,
                    AllocationBase: vad.start,
                    AllocationProtect: vad.protect,
                    PartitionId: 0,
                    _pad0: 0,
                    RegionSize: end - va,
                    State: state,
                    Protect: prot,
                    Type: vad.kind.mem_type(),
                    _pad1: 0,
                }
            } else {
                // Free region up to the next VAD, KUSD window, or USER_PROBE_VA.
                let mut end = inner
                    .vads
                    .find_next(va)
                    .map_or(USER_PROBE_VA, |next| next.start);
                if va < KUSD_WINDOW_START && KUSD_WINDOW_START < end {
                    end = KUSD_WINDOW_START;
                }
                MEMORY_BASIC_INFORMATION {
                    BaseAddress: va,
                    AllocationBase: 0,
                    AllocationProtect: 0,
                    PartitionId: 0,
                    _pad0: 0,
                    RegionSize: end - va,
                    State: MEM_FREE,
                    Protect: PAGE_NOACCESS,
                    Type: 0,
                    _pad1: 0,
                }
            };
            drop(inner);
            // SAFETY: per the contract; `capture::write` probes user pointers.
            if let Err(st) = unsafe {
                capture::write(
                    memory_information.cast::<MEMORY_BASIC_INFORMATION>(),
                    info,
                    mode,
                )
            } {
                return st;
            }
            if !return_length.is_null() {
                // SAFETY: as above.
                if let Err(st) = unsafe { capture::write(return_length, needed, mode) } {
                    return st;
                }
            }
            STATUS_SUCCESS
        }
        MEMORY_REGION_INFORMATION_CLASS => {
            let needed = size_of::<MEMORY_REGION_INFORMATION>();
            if memory_information_length < needed {
                if !return_length.is_null() {
                    // SAFETY: per the contract; `capture::write` probes user pointers.
                    let _ = unsafe { capture::write(return_length, needed, mode) };
                }
                return STATUS_INFO_LENGTH_MISMATCH;
            }
            let inner = space.read();
            let Some(vad) = inner.vads.find_containing(va) else {
                return STATUS_INVALID_ADDRESS;
            };
            let info = MEMORY_REGION_INFORMATION {
                AllocationBase: vad.start,
                AllocationProtect: vad.protect,
                RegionType: if matches!(vad.kind, VadKind::Private) {
                    1 // Private
                } else {
                    2 // MappedDataFile
                },
                RegionSize: vad.len(),
                CommitSize: vad.committed_pages * PAGE_SIZE as u64,
                PartitionId: 0,
                NodePreference: 0,
            };
            drop(inner);
            // SAFETY: per the contract; `capture::write` probes user pointers.
            if let Err(st) = unsafe {
                capture::write(
                    memory_information.cast::<MEMORY_REGION_INFORMATION>(),
                    info,
                    mode,
                )
            } {
                return st;
            }
            if !return_length.is_null() {
                // SAFETY: as above.
                if let Err(st) = unsafe { capture::write(return_length, needed, mode) } {
                    return st;
                }
            }
            STATUS_SUCCESS
        }
        MEMORY_MAPPED_FILENAME_INFORMATION_CLASS => STATUS_INVALID_ADDRESS,
        _ => STATUS_INVALID_INFO_CLASS,
    }
}

/// [`NtSetInformationVirtualMemory`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-ntsetinformationvirtualmemory).
///
/// # Safety
/// Pointer parameters must satisfy `PreviousMode`.
pub unsafe extern "C" fn NtSetInformationVirtualMemory(
    process_handle: *mut c_void,
    vm_information_class: u32,
    number_of_entries: usize,
    virtual_addresses: *const MEMORY_RANGE_ENTRY,
    _vm_information: *const c_void,
    _vm_information_length: usize,
) -> NTSTATUS {
    let mode = capture::mode();
    let _target = match TargetProcess::resolve(process_handle, PROCESS_VM_OPERATION, mode) {
        Ok(t) => t,
        Err(st) => return st,
    };
    if number_of_entries > 0 && !virtual_addresses.is_null() {
        // SAFETY: per the contract; `capture::read` fault-protects user pointers.
        if let Err(st) = unsafe { capture::read(virtual_addresses, mode) } {
            return st;
        }
    }
    match vm_information_class {
        VM_PREFETCH_INFORMATION | VM_CFG_CALL_TARGET_INFORMATION => STATUS_SUCCESS,
        _ => STATUS_INVALID_INFO_CLASS,
    }
}

/// [`NtReadVirtualMemory`](https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-readprocessmemory).
///
/// # Safety
/// `buffer` and `bytes_read` must satisfy `PreviousMode`.
pub unsafe extern "C" fn NtReadVirtualMemory(
    process_handle: *mut c_void,
    base_address: *const c_void,
    buffer: *mut c_void,
    number_of_bytes_to_read: usize,
    number_of_bytes_read: *mut usize,
) -> NTSTATUS {
    let mode = capture::mode();
    let target = match TargetProcess::resolve(process_handle, PROCESS_VM_READ, mode) {
        Ok(t) => t,
        Err(st) => return st,
    };
    let src_va = base_address.addr() as u64;
    if src_va
        .checked_add(number_of_bytes_to_read as u64)
        .is_none_or(|end| end > USER_PROBE_VA)
    {
        return STATUS_ACCESS_VIOLATION;
    }
    if capture::is_user(mode) && !crate::mm::user::in_range(buffer.addr(), number_of_bytes_to_read)
    {
        return STATUS_ACCESS_VIOLATION;
    }

    let mut copied = 0usize;
    let mut status = STATUS_SUCCESS;
    let mut rem = number_of_bytes_to_read;
    let mut cur_src = src_va;
    let mut cur_dst = buffer.cast::<u8>();

    let space = match target.space() {
        Ok(s) => s,
        Err(st) => return st,
    };

    while rem > 0 {
        let off = (cur_src & PAGE_MASK) as usize;
        let chunk = rem.min(PAGE_SIZE - off);
        let Ok(pa) = fault_and_translate(space, cur_src, false, target.is_current()) else {
            status = STATUS_PARTIAL_COPY;
            break;
        };
        let src_ptr = phys_to_virt(pa).cast_const();
        // SAFETY: `src_ptr` is a valid direct-map pointer for `chunk` bytes within
        // one page; `cur_dst` is fault-protected for user mode.
        if unsafe { crate::mm::user::copy(cur_dst, src_ptr, chunk) }.is_err() {
            status = STATUS_ACCESS_VIOLATION;
            break;
        }
        copied += chunk;
        cur_src += chunk as u64;
        cur_dst = cur_dst.wrapping_add(chunk);
        rem -= chunk;
    }

    if !number_of_bytes_read.is_null() {
        // SAFETY: per the contract; `capture::write` probes user pointers.
        let _ = unsafe { capture::write(number_of_bytes_read, copied, mode) };
    }
    status
}

/// [`NtWriteVirtualMemory`](https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-writeprocessmemory).
///
/// # Safety
/// `buffer` and `bytes_written` must satisfy `PreviousMode`.
pub unsafe extern "C" fn NtWriteVirtualMemory(
    process_handle: *mut c_void,
    base_address: *mut c_void,
    buffer: *const c_void,
    number_of_bytes_to_write: usize,
    number_of_bytes_written: *mut usize,
) -> NTSTATUS {
    let mode = capture::mode();
    let target = match TargetProcess::resolve(process_handle, PROCESS_VM_WRITE, mode) {
        Ok(t) => t,
        Err(st) => return st,
    };
    let dst_va = base_address.addr() as u64;
    if dst_va
        .checked_add(number_of_bytes_to_write as u64)
        .is_none_or(|end| end > USER_PROBE_VA)
    {
        return STATUS_ACCESS_VIOLATION;
    }
    if capture::is_user(mode) && !crate::mm::user::in_range(buffer.addr(), number_of_bytes_to_write)
    {
        return STATUS_ACCESS_VIOLATION;
    }

    let mut copied = 0usize;
    let mut status = STATUS_SUCCESS;
    let mut rem = number_of_bytes_to_write;
    let mut cur_dst = dst_va;
    let mut cur_src = buffer.cast::<u8>();

    let space = match target.space() {
        Ok(s) => s,
        Err(st) => return st,
    };

    while rem > 0 {
        let off = (cur_dst & PAGE_MASK) as usize;
        let chunk = rem.min(PAGE_SIZE - off);
        let Ok(pa) = fault_and_translate(space, cur_dst, true, target.is_current()) else {
            status = STATUS_PARTIAL_COPY;
            break;
        };
        let dst_ptr = phys_to_virt(pa);
        // SAFETY: `dst_ptr` is a valid direct-map writable pointer for `chunk`
        // bytes within one page; `cur_src` is fault-protected for user mode.
        if unsafe { crate::mm::user::copy(dst_ptr, cur_src, chunk) }.is_err() {
            status = STATUS_ACCESS_VIOLATION;
            break;
        }
        copied += chunk;
        cur_dst += chunk as u64;
        cur_src = cur_src.wrapping_add(chunk);
        rem -= chunk;
    }

    if !number_of_bytes_written.is_null() {
        // SAFETY: per the contract; `capture::write` probes user pointers.
        let _ = unsafe { capture::write(number_of_bytes_written, copied, mode) };
    }
    status
}

/// Resolve any demand-zero/CoW fault on `va` inside `space` and return the
/// byte-exact physical address `pa + (va & 0xFFF)`.
fn fault_and_translate(
    space: &AddressSpace,
    va: u64,
    write: bool,
    is_current: bool,
) -> Result<u64, NTSTATUS> {
    let access = if write { Access::Write } else { Access::Read };
    match resolve_in_space(space, va, access, is_current) {
        UserFault::Resolved => {
            let page_pa = space.translate(va).ok_or(STATUS_ACCESS_VIOLATION)?;
            Ok(page_pa)
        }
        UserFault::InPageError(st) => Err(st),
        _ => Err(STATUS_ACCESS_VIOLATION),
    }
}

/// Resolve a user page for `MmProbeAndLockPages` (faulting in demand-zero / CoW
/// pages if needed) and return its physical page address.
pub fn probe_and_lock_user_page(va: u64, write: bool) -> Result<u64, NTSTATUS> {
    let proc = process::PsGetCurrentProcess().cast::<u8>();
    // SAFETY: current process is always live.
    let Some(space) = (unsafe { process::address_space(proc) }) else {
        return Err(STATUS_ACCESS_VIOLATION);
    };
    let page = page_down(va);
    fault_and_translate(space, page, write, true)
}

/// Attempt Windows-style automatic user stack growth after a `PAGE_GUARD`
/// fault at `page` inside `vad`. Returns `Some(UserFault::Resolved)` if stack
/// grew transparently, `Some(UserFault::StackOverflow)` if the stack hit its
/// bottom limit, or `None` if `page` is not inside the current thread's stack.
fn try_grow_user_stack(
    page: u64,
    vad: Vad,
    space: &AddressSpace,
    inner: &mut AddressSpaceInner,
) -> Option<UserFault> {
    let me = thread::current();
    if me.is_null() {
        return None;
    }
    // SAFETY: `me` is the running thread.
    let teb = unsafe { thread::object_field::<u64>(me, thread_layout::TEB).read() };
    if teb == 0 || teb >= USER_PROBE_VA {
        return None;
    }
    // Read TEB.StackBase, TEB.StackLimit, TEB.DeallocationStack directly from
    // the address space (via `translate` + `phys_to_virt` so we don't recurse
    // into page faults while holding `space.lock()`!).
    let read_u64 = |offset: u64| -> Option<u64> {
        let addr = teb.checked_add(offset)?;
        let pte = space.read_pte(page_down(addr));
        let arch_pt = arch::pt_arch();
        if !arch_pt.present(pte) {
            return None;
        }
        let pa = arch_pt.addr(pte) + (addr & PAGE_MASK);
        // SAFETY: `pa` is a valid resident page of the current process's TEB.
        Some(unsafe { phys_to_virt(pa).cast::<u64>().read_unaligned() })
    };
    let write_u64 = |offset: u64, val: u64| {
        if let Some(addr) = teb.checked_add(offset) {
            let pte = space.read_pte(page_down(addr));
            let arch_pt = arch::pt_arch();
            if arch_pt.present(pte) && arch_pt.writable(pte) {
                let pa = arch_pt.addr(pte) + (addr & PAGE_MASK);
                // SAFETY: `pa` is a valid writable resident page of the TEB.
                unsafe { phys_to_virt(pa).cast::<u64>().write_unaligned(val) };
            }
        }
    };

    let stack_base = read_u64(TEB_STACK_BASE)?;
    let stack_limit = read_u64(TEB_STACK_LIMIT)?;
    let dealloc = read_u64(TEB_DEALLOCATION_STACK)?;
    if dealloc == 0 || page < dealloc || page >= stack_base {
        return None;
    }
    if page < stack_limit {
        write_u64(TEB_STACK_LIMIT, page);
    }
    // Leave at least one page above `dealloc` so the final page triggers
    // `STATUS_STACK_OVERFLOW` before running off the bottom of the stack VAD.
    let next_guard = page.checked_sub(PAGE_SIZE as u64)?;
    if next_guard >= dealloc + PAGE_SIZE as u64 && vad.contains(next_guard) {
        if space.read_pte(next_guard) == 0 {
            let dz = UserSwPte::DemandZero {
                mm_prot: MM_PROT_READWRITE | MM_PROT_GUARD,
            }
            .encode();
            if space.write_pte(next_guard, dz).is_ok() {
                if let Some(v) = inner.vads.find_containing_mut(next_guard) {
                    v.committed_pages += 1;
                }
                inner.charge_commit(1);
            }
        }
        Some(UserFault::Resolved)
    } else {
        Some(UserFault::StackOverflow)
    }
}

/// Core fault handler for a user-mode virtual address inside `space`.
fn resolve_in_space(
    space: &AddressSpace,
    va: u64,
    access: Access,
    allow_stack_growth: bool,
) -> UserFault {
    if !(MIN_USER_VA..USER_PROBE_VA).contains(&va) {
        return UserFault::AccessViolation;
    }
    if (KUSD_WINDOW_START..KUSD_WINDOW_END).contains(&va) {
        // KUSER_SHARED_DATA is permanently mapped read-only; reads succeed without
        // faulting, writes/executes are always access violations.
        return if access == Access::Read {
            UserFault::Resolved
        } else {
            UserFault::AccessViolation
        };
    }

    let page = page_down(va);
    let arch_pt = arch::pt_arch();
    let mut inner = space.lock();
    let Some(vad) = inner.vads.find_containing(page).copied() else {
        return UserFault::AccessViolation;
    };

    let raw = space.read_pte(page);
    if arch_pt.present(raw) {
        let writable = arch_pt.writable(raw);
        let executable = arch_pt.executable(raw);
        let already_ok = match access {
            Access::Read => true,
            Access::Write => writable,
            Access::Execute => executable,
        };
        if already_ok {
            return UserFault::Resolved;
        }
        // Copy-on-Write break on write fault to a COW-marked valid page.
        if access == Access::Write && (raw & arch_pt.cow_bit()) != 0 {
            let old_pa = arch_pt.addr(raw);
            let Some(new_pa) = alloc_frames(1) else {
                return UserFault::InPageError(STATUS_INSUFFICIENT_RESOURCES);
            };
            // SAFETY: both `old_pa` and `new_pa` are valid 4 KiB frames in the direct map.
            unsafe {
                core::ptr::copy_nonoverlapping(
                    phys_to_virt(old_pa),
                    phys_to_virt(new_pa),
                    PAGE_SIZE,
                );
            }
            let old_mm = user_hw_to_mm(false, executable, true);
            let new_mm = mm_break_cow(old_mm);
            let Some((hw_prot, _)) = mm_to_user_hw(new_mm) else {
                free_frames(new_pa, 1);
                return UserFault::AccessViolation;
            };
            let new_pte = valid_user_pte(new_pa, hw_prot, false);
            if space.write_pte(page, new_pte).is_err() {
                free_frames(new_pa, 1);
                return UserFault::InPageError(STATUS_INSUFFICIENT_RESOURCES);
            }
            arch::flush_tlb_page(page);
            // For a private VAD, this page was the sole owner of `old_pa`.
            if matches!(vad.kind, VadKind::Private) {
                free_frames(old_pa, 1);
            }
            return UserFault::Resolved;
        }
        return UserFault::AccessViolation;
    }

    match UserSwPte::decode(raw) {
        UserSwPte::Zero => UserFault::AccessViolation,
        UserSwPte::DemandZero { mm_prot } => {
            if mm_prot == MM_PROT_EMPTY || mm_prot == MM_PROT_NOACCESS {
                return UserFault::AccessViolation;
            }
            if mm_is_guard(mm_prot) {
                let base_prot = mm_prot & !MM_PROT_GUARD;
                let Some(pa) = alloc_frames(1) else {
                    return UserFault::InPageError(STATUS_INSUFFICIENT_RESOURCES);
                };
                let eff_prot = if access == Access::Write && mm_is_cow(base_prot) {
                    mm_break_cow(base_prot)
                } else {
                    base_prot
                };
                let new_entry = if let Some((hw_prot, cow)) = mm_to_user_hw(eff_prot) {
                    valid_user_pte(pa, hw_prot, cow)
                } else {
                    UserSwPte::Transition {
                        pfn: pa / PAGE_SIZE as u64,
                        mm_prot: eff_prot,
                    }
                    .encode()
                };
                if space.write_pte(page, new_entry).is_err() {
                    free_frames(pa, 1);
                    return UserFault::InPageError(STATUS_INSUFFICIENT_RESOURCES);
                }
                arch::mapping_sync();
                if allow_stack_growth
                    && let Some(outcome) = try_grow_user_stack(page, vad, space, &mut inner)
                {
                    return outcome;
                }
                return UserFault::GuardViolation;
            }
            if !access_allowed(mm_prot, access) {
                return UserFault::AccessViolation;
            }
            let Some(pa) = alloc_frames(1) else {
                return UserFault::InPageError(STATUS_INSUFFICIENT_RESOURCES);
            };
            // Writing a demand-zero WRITECOPY page breaks CoW immediately.
            let eff_prot = if access == Access::Write && mm_is_cow(mm_prot) {
                mm_break_cow(mm_prot)
            } else {
                mm_prot
            };
            let Some((hw_prot, cow)) = mm_to_user_hw(eff_prot) else {
                free_frames(pa, 1);
                return UserFault::AccessViolation;
            };
            let new_pte = valid_user_pte(pa, hw_prot, cow);
            if space.write_pte(page, new_pte).is_err() {
                free_frames(pa, 1);
                return UserFault::InPageError(STATUS_INSUFFICIENT_RESOURCES);
            }
            arch::mapping_sync();
            UserFault::Resolved
        }
        UserSwPte::Transition { pfn, mm_prot } => {
            if !mm_is_guard(mm_prot) {
                return UserFault::AccessViolation;
            }
            let base_prot = mm_prot & !MM_PROT_GUARD;
            let pa = pfn * PAGE_SIZE as u64;
            let eff_prot = if access == Access::Write && mm_is_cow(base_prot) {
                mm_break_cow(base_prot)
            } else {
                base_prot
            };
            let new_entry = if let Some((hw_prot, cow)) = mm_to_user_hw(eff_prot) {
                valid_user_pte(pa, hw_prot, cow)
            } else {
                UserSwPte::Transition {
                    pfn,
                    mm_prot: eff_prot,
                }
                .encode()
            };
            if space.write_pte(page, new_entry).is_err() {
                return UserFault::InPageError(STATUS_INSUFFICIENT_RESOURCES);
            }
            arch::flush_tlb_page(page);
            if allow_stack_growth
                && let Some(outcome) = try_grow_user_stack(page, vad, space, &mut inner)
            {
                return outcome;
            }
            UserFault::GuardViolation
        }
        UserSwPte::Prototype { .. } => {
            // Section view faults are wired in Stage 2B.
            UserFault::AccessViolation
        }
    }
}

/// Entry point from `mm::fault::page_fault` for any low-half virtual address.
pub fn handle_fault(va: u64, access: Access, user_mode: bool) -> UserFault {
    let proc = process::PsGetCurrentProcess().cast::<u8>();
    if proc.is_null() {
        return UserFault::NotUser;
    }
    // SAFETY: current process is live for the duration of the fault.
    let Some(space) = (unsafe { process::address_space(proc) }) else {
        return UserFault::NotUser;
    };
    resolve_in_space(space, va, access, user_mode)
}
