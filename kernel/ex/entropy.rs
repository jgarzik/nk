//! Boot entropy: the block of entropy the loader gathered
//! (`BOOT_ENTROPY_LDR_RESULT`, `doc/BOOT.md`), given out once, as
//! Windows gives it out.
//!
//! The pinned kernel's `ExQueryBootEntropyInformation` runs
//! `ExpInitBootEntropyInformation` once (`RtlRunOnceExecuteOnce`): it
//! copies the head of the loader's block (the source records and the
//! seed for `cng.sys`) into the caller's buffer and then wipes that head
//! in the loader's block. Every later call finds the run done and fails
//! with `STATUS_UNSUCCESSFUL`. The first caller is `cng.sys`, through
//! `ZwQuerySystemInformation(SystemBootEntropyInformation)`; once the
//! boot and system drivers have started, Windows calls it itself with no
//! buffer, which only wipes, so that nothing started later can have the
//! seed ([`wipe`]).

use core::sync::atomic::{AtomicPtr, Ordering};
use nk_bootinfo::BootInfo;
use nk_ntabi::status::*;
use nk_ntabi::sysinfo::{BOOT_ENTROPY_LDR_RESULT, SYSTEM_BOOT_ENTROPY_INFORMATION_SIZE};

/// The loader's block in the direct map, until its head has been given
/// out or wiped; then null.
static BLOCK: AtomicPtr<BOOT_ENTROPY_LDR_RESULT> = AtomicPtr::new(core::ptr::null_mut());

/// Take the loader's block. A loader that gathered nothing hands none,
/// and every query then fails as a second one does.
pub fn init(info: &BootInfo) {
    if info.entropy != 0 {
        let block = crate::mm::phys_to_virt(info.entropy).cast::<BOOT_ENTROPY_LDR_RESULT>();
        BLOCK.store(block, Ordering::Release);
    }
}

/// `ExQueryBootEntropyInformation`: the first call copies the head of
/// the loader's block into `buffer` (when there is one) and wipes it;
/// any other call is `STATUS_UNSUCCESSFUL`.
///
/// # Safety
/// `buffer` is null or writable for
/// [`SYSTEM_BOOT_ENTROPY_INFORMATION_SIZE`] bytes.
pub unsafe fn query(buffer: *mut u8) -> NTSTATUS {
    let block = BLOCK.swap(core::ptr::null_mut(), Ordering::AcqRel);
    if block.is_null() {
        return STATUS_UNSUCCESSFUL;
    }
    let head = block.cast::<u8>();
    // SAFETY: the loader's block lies in pages it allocated for it, which
    // the kernel keeps and nothing else reaches; the swap made this the
    // only call that ever touches it. `buffer` per the contract.
    unsafe {
        if !buffer.is_null() {
            buffer.copy_from_nonoverlapping(head, SYSTEM_BOOT_ENTROPY_INFORMATION_SIZE);
        }
        // Volatile, so the wipe is not dropped as a dead store.
        for i in 0..SYSTEM_BOOT_ENTROPY_INFORMATION_SIZE {
            head.add(i).write_volatile(0);
        }
    }
    STATUS_SUCCESS
}

/// Wipe the head of the loader's block if no one has asked for it:
/// what Windows does once its boot and system drivers have started.
pub fn wipe() {
    // SAFETY: no buffer.
    unsafe { query(core::ptr::null_mut()) };
}
