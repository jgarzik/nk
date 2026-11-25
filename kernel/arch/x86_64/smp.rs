//! Starting the other processors on x86-64.
//!
//! A processor that is not running is woken with an INIT and then a
//! start-up interrupt naming a page below 1 MiB, where it begins in real
//! mode. The trampoline below is copied to that page. It climbs to
//! protected mode, then to long mode on the kernel's own page tables, and
//! calls into the kernel on the stack it was given.

use super::{apic, cpu, trap};
use crate::hal::platform;
use crate::ke::{smp, time};
use crate::mm;
use core::arch::global_asm;
use nk_bootinfo::{BootInfo, EFI_CONVENTIONAL, regions};
use nk_mm::pt::Prot;

/// Where the trampoline runs: a page of ordinary low memory. The address
/// is assembled into the trampoline.
const TRAMPOLINE: u64 = 0x8000;
/// `EfiBootServicesCode` and `EfiBootServicesData`: free once the kernel
/// runs.
const EFI_BOOT_SERVICES: [u32; 2] = [3, 4];

global_asm!(
    r#"
    .section .rdata
    .balign 16
    .globl nk_ap_trampoline
nk_ap_trampoline:
    .code16
    cli
    cld
    xorw %ax, %ax
    movw %ax, %ds
    lgdtl (0x8000 + 9f - nk_ap_trampoline)
    movl %cr0, %eax
    orl $1, %eax
    movl %eax, %cr0
    ljmpl $0x08, $(0x8000 + 2f - nk_ap_trampoline)
    .code32
2:
    movw $0x10, %ax
    movw %ax, %ds
    movw %ax, %es
    movw %ax, %ss
    // PAE, then the kernel's page tables, then long mode with NX, then
    // paging with write protection.
    movl %cr4, %eax
    orl $0x20, %eax
    movl %eax, %cr4
    movl (0x8000 + nk_ap_cr3 - nk_ap_trampoline), %eax
    movl %eax, %cr3
    movl $0xC0000080, %ecx
    rdmsr
    orl $0x900, %eax
    wrmsr
    movl %cr0, %eax
    orl $0x80010000, %eax
    movl %eax, %cr0
    ljmpl $0x18, $(0x8000 + 3f - nk_ap_trampoline)
    .code64
3:
    movq (0x8000 + nk_ap_stack - nk_ap_trampoline), %rsp
    movq (0x8000 + nk_ap_argument - nk_ap_trampoline), %rcx
    movq (0x8000 + nk_ap_entry - nk_ap_trampoline), %rax
    xorl %ebp, %ebp
    subq $32, %rsp
    callq *%rax
    ud2
    .balign 8
// Flat 32-bit code and data, and 64-bit code: just enough to get out.
8:
    .quad 0
    .quad 0x00CF9A000000FFFF
    .quad 0x00CF92000000FFFF
    .quad 0x00209A0000000000
9:
    .word 31
    .long 0x8000 + 8b - nk_ap_trampoline
    .balign 8
    .globl nk_ap_cr3
nk_ap_cr3:
    .quad 0
    .globl nk_ap_stack
nk_ap_stack:
    .quad 0
    .globl nk_ap_entry
nk_ap_entry:
    .quad 0
    .globl nk_ap_argument
nk_ap_argument:
    .quad 0
    .globl nk_ap_trampoline_end
nk_ap_trampoline_end:
    .text
"#,
    options(att_syntax)
);

unsafe extern "C" {
    static nk_ap_trampoline: u8;
    static nk_ap_trampoline_end: u8;
    static nk_ap_cr3: u8;
    static nk_ap_stack: u8;
    static nk_ap_entry: u8;
    static nk_ap_argument: u8;
}

/// Whether the trampoline's page is memory nothing else is using.
fn trampoline_page_free(info: &BootInfo) -> bool {
    // SAFETY: the loader left the memory map in reserved memory that the
    // direct map covers.
    let map = unsafe {
        core::slice::from_raw_parts(mm::phys_to_virt(info.mmap_phys), info.mmap_len as usize)
    };
    regions(map, info.mmap_desc_size as usize).any(|r| {
        (r.kind == EFI_CONVENTIONAL || EFI_BOOT_SERVICES.contains(&r.kind))
            && r.contains(TRAMPOLINE, 4096)
    })
}

/// Put the trampoline in place. Done once, before the first start.
pub fn prepare(info: &BootInfo) -> Result<(), &'static str> {
    if !trampoline_page_free(info) {
        return Err("the page for the start-up trampoline is not free memory");
    }
    // The processor loads the page-table root while still in 32-bit mode.
    if super::pt_root() > u64::from(u32::MAX) {
        return Err("the kernel's page tables lie above 4 GiB; cannot start processors");
    }
    // The trampoline turns paging on while running at its physical
    // address, so that address must be mapped to itself.
    mm::map::map(TRAMPOLINE, TRAMPOLINE, 1, Prot::RWX)
        .map_err(|_| "cannot map the start-up trampoline")?;
    // SAFETY: the page is free low memory in the direct map, and the
    // blob between the two symbols is smaller than a page.
    unsafe {
        let start = &raw const nk_ap_trampoline;
        let len = (&raw const nk_ap_trampoline_end).offset_from(start) as usize;
        assert!(len <= 4096);
        core::ptr::copy_nonoverlapping(start, mm::phys_to_virt(TRAMPOLINE), len);
    }
    Ok(())
}

/// Every processor is running: the trampoline's low mapping goes.
pub fn finish() {
    mm::map::unmap(TRAMPOLINE, 1);
}

/// Store `value` in the copy of the trampoline's data word `field`.
///
/// # Safety
/// `field` is one of the trampoline's data symbols.
unsafe fn patch(field: *const u8, value: u64) {
    // SAFETY: the symbol lies inside the blob copied to the trampoline
    // page, at the same offset there.
    unsafe {
        let offset = field.offset_from(&raw const nk_ap_trampoline) as usize;
        mm::phys_to_virt(TRAMPOLINE + offset as u64)
            .cast::<u64>()
            .write_unaligned(value);
    }
}

/// Wake processor `number` (local APIC id `apic_id`) to run on the stack
/// ending at `stack_top`. Returns at once; the processor reports in by
/// itself.
pub fn start(number: usize, apic_id: u64, stack_top: u64) {
    // SAFETY: the four symbols are the trampoline's data words.
    unsafe {
        patch(&raw const nk_ap_cr3, super::pt_root());
        patch(&raw const nk_ap_stack, stack_top);
        patch(
            &raw const nk_ap_entry,
            entry as extern "C" fn(u64) -> ! as usize as u64,
        );
        patch(&raw const nk_ap_argument, number as u64);
    }
    // The sequence Intel specifies: INIT, a pause, then the start-up
    // interrupt, twice in case the first is missed.
    apic::send_init(apic_id as u32);
    time::stall(10_000);
    for _ in 0..2 {
        apic::send_startup(apic_id as u32, (TRAMPOLINE >> 12) as u32);
        time::stall(200);
    }
}

/// Where a started processor enters the kernel, in long mode on its own
/// stack with interrupts off.
extern "C" fn entry(number: u64) -> ! {
    cpu::init(number as u32);
    trap::load();
    apic::init_cpu();
    smp::ap_main(number as usize)
}

/// Local APIC id of each processor NK may start.
pub fn hardware_id(number: usize) -> u64 {
    platform::get().cpus()[number].hw_id
}
