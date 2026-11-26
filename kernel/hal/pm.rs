//! ACPI's fixed hardware for `acpi.sys`: the HAL's ACPI table has
//! routines that say whether a register block exists and read and
//! write it, and one that gives the driver the FACS. Windows' HAL sets
//! the blocks up from the FADT once (`nk_acpi::pm_registers` has its
//! rules); `acpi.sys` names a block by its number there.

#![allow(non_snake_case)]

use super::dispatch::{HalAcpiDispatchTable, acpi_slot};
use super::platform;
use crate::arch;
use core::ffi::c_void;
use core::sync::atomic::{AtomicU32, AtomicUsize, Ordering};
use nk_acpi::{PM_REGISTERS, RegisterSpace};
use nk_ntabi::status::{NTSTATUS, STATUS_BUFFER_TOO_SMALL, STATUS_NOT_SUPPORTED, STATUS_SUCCESS};

/// How a block is reached.
const ABSENT: u32 = 0;
const PORT: u32 = 1;
const MEMORY: u32 = 2;

/// One register block: how it is reached, where (a port, or the address
/// its memory is mapped at), and the size of an access.
struct Block {
    kind: AtomicU32,
    base: AtomicUsize,
    access: AtomicU32,
}

static BLOCKS: [Block; PM_REGISTERS] = [const {
    Block {
        kind: AtomicU32::new(ABSENT),
        base: AtomicUsize::new(0),
        access: AtomicU32::new(0),
    }
}; PM_REGISTERS];

/// Set the blocks up from the firmware's FADT and put the routines in
/// their slots. Once, after the machine's description is known and
/// before any driver runs.
pub fn init() {
    if let Some(fadt) = platform::acpi_table(b"FACP", None, None) {
        for (block, register) in BLOCKS.iter().zip(nk_acpi::pm_registers(fadt)) {
            let Some(register) = register else { continue };
            let (kind, base) = match register.space {
                RegisterSpace::Port(port) => (PORT, usize::from(port)),
                RegisterSpace::Memory(at) => {
                    let protection = nk_mm::protect::Protection {
                        access: true,
                        write: true,
                        exec: false,
                        uncached: true,
                    };
                    // Mapped for good: the block is the machine's.
                    match crate::mm::io::map_physical(at, 8, protection) {
                        Some(mapped) => (MEMORY, mapped.addr()),
                        None => continue,
                    }
                }
            };
            block.base.store(base, Ordering::Relaxed);
            block.access.store(register.access, Ordering::Relaxed);
            block.kind.store(kind, Ordering::Release);
        }
    }
    let table = &HalAcpiDispatchTable;
    table.provide(
        acpi_slot("HalAcpiPmRegisterAvailable"),
        HalAcpiPmRegisterAvailable as *const (),
    );
    table.provide(
        acpi_slot("HalAcpiPmRegisterRead"),
        HalAcpiPmRegisterRead as *const (),
    );
    table.provide(
        acpi_slot("HalAcpiPmRegisterWrite"),
        HalAcpiPmRegisterWrite as *const (),
    );
    table.provide(
        acpi_slot("HalAcpiGetFacsMapping"),
        HalAcpiGetFacsMapping as *const (),
    );
}

/// The block numbered `register`, if the machine has it.
fn block(register: i32) -> Option<&'static Block> {
    let block = BLOCKS.get(usize::try_from(register).ok()?)?;
    (block.kind.load(Ordering::Acquire) != ABSENT).then_some(block)
}

/// `HalAcpiPmRegisterAvailable`: success if the machine has the block,
/// `STATUS_NOT_SUPPORTED` if not.
pub extern "C" fn HalAcpiPmRegisterAvailable(register: i32) -> NTSTATUS {
    if block(register).is_some() {
        STATUS_SUCCESS
    } else {
        STATUS_NOT_SUPPORTED
    }
}

/// One access of the block's size, `offset` bytes into it.
///
/// # Safety
/// The block is the machine's ACPI hardware, and the caller the ACPI
/// driver, whose registers these are.
unsafe fn access(block: &Block, offset: u32, write: Option<u32>) -> u32 {
    let size = block.access.load(Ordering::Relaxed);
    let base = block.base.load(Ordering::Relaxed) + offset as usize;
    // SAFETY: per the contract; a mapped block is device memory mapped
    // in `init`, read and written with volatile accesses of its size.
    unsafe {
        if block.kind.load(Ordering::Relaxed) == PORT {
            match write {
                Some(value) => {
                    arch::port_write(base as u16, size, value);
                    0
                }
                None => arch::port_read(base as u16, size).unwrap_or(0),
            }
        } else {
            let at = base as *mut u8;
            match (size, write) {
                (1, Some(value)) => at.write_volatile(value as u8),
                (2, Some(value)) => at.cast::<u16>().write_volatile(value as u16),
                (_, Some(value)) => at.cast::<u32>().write_volatile(value),
                (1, None) => return u32::from(at.read_volatile()),
                (2, None) => return u32::from(at.cast::<u16>().read_volatile()),
                (_, None) => return at.cast::<u32>().read_volatile(),
            }
            0
        }
    }
}

/// `HalAcpiPmRegisterRead`: read one access of the block `register`,
/// `offset` bytes into it, into `buffer`, and say in `returned` how
/// many bytes that is. A buffer shorter than the block's access size is
/// `STATUS_BUFFER_TOO_SMALL`. Windows' routine reads through a block it
/// does not have; NK answers `STATUS_NOT_SUPPORTED`.
///
/// # Safety
/// `buffer` points to `length` writable bytes; `returned` is null or
/// points to a writable `ULONG`.
pub unsafe extern "C" fn HalAcpiPmRegisterRead(
    register: i32,
    offset: u32,
    buffer: *mut u8,
    length: u32,
    returned: *mut u32,
) -> NTSTATUS {
    let Some(block) = block(register) else {
        return STATUS_NOT_SUPPORTED;
    };
    let size = block.access.load(Ordering::Relaxed);
    if size > length {
        return STATUS_BUFFER_TOO_SMALL;
    }
    // SAFETY: the caller's buffer, of at least the access size.
    unsafe {
        let value = access(block, offset, None).to_le_bytes();
        core::ptr::copy_nonoverlapping(value.as_ptr(), buffer, size as usize);
        if !returned.is_null() {
            returned.write_unaligned(size);
        }
    }
    STATUS_SUCCESS
}

/// `HalAcpiPmRegisterWrite`: as [`HalAcpiPmRegisterRead`], writing.
///
/// # Safety
/// `buffer` points to `length` readable bytes; `returned` is null or
/// points to a writable `ULONG`.
pub unsafe extern "C" fn HalAcpiPmRegisterWrite(
    register: i32,
    offset: u32,
    buffer: *const u8,
    length: u32,
    returned: *mut u32,
) -> NTSTATUS {
    let Some(block) = block(register) else {
        return STATUS_NOT_SUPPORTED;
    };
    let size = block.access.load(Ordering::Relaxed);
    if size > length {
        return STATUS_BUFFER_TOO_SMALL;
    }
    let mut value = [0u8; 4];
    // SAFETY: the caller's buffer, of at least the access size.
    unsafe {
        core::ptr::copy_nonoverlapping(buffer, value.as_mut_ptr(), size as usize);
        access(block, offset, Some(u32::from_le_bytes(value)));
        if !returned.is_null() {
            returned.write_unaligned(size);
        }
    }
    STATUS_SUCCESS
}

/// `HalAcpiGetFacsMapping`: the firmware's FACS, which the ACPI driver
/// reads and writes (the waking vector, the global lock), found through
/// the FADT's 32-bit field as Windows' HAL finds it; null if the
/// firmware has none. The address is the table itself in the kernel's
/// map of physical memory.
pub extern "C" fn HalAcpiGetFacsMapping() -> *mut c_void {
    platform::acpi_table(b"FACP", None, None)
        .and_then(nk_acpi::facs_address)
        .and_then(|at| platform::firmware_memory(at, 64))
        .filter(|facs| &facs[..4] == b"FACS")
        .map_or(core::ptr::null_mut(), |facs| {
            facs.as_ptr().cast_mut().cast()
        })
}

/// For the self-tests: what the machine has, read as `acpi.sys` reads
/// it, through the slots.
pub fn test() -> Result<(), &'static str> {
    const TIMER: i32 = 2;
    let fadt = platform::acpi_table(b"FACP", None, None).ok_or("no FADT")?;
    let described = nk_acpi::pm_registers(fadt);
    for (number, register) in described.iter().enumerate() {
        let available = HalAcpiPmRegisterAvailable(number as i32) == STATUS_SUCCESS;
        if available != register.is_some() {
            return Err("a block's availability is not what the FADT says");
        }
    }
    if HalAcpiPmRegisterAvailable(PM_REGISTERS as i32) != STATUS_NOT_SUPPORTED
        || HalAcpiPmRegisterAvailable(-1) != STATUS_NOT_SUPPORTED
    {
        return Err("a block no HAL has was reported available");
    }
    let table = HalAcpiDispatchTable.address();
    // SAFETY: the slots at Windows' offsets hold the routines above.
    let slot = |offset: usize| unsafe { table.cast::<u8>().add(offset).cast::<usize>().read() };
    if slot(0x78) != HalAcpiPmRegisterAvailable as *const () as usize
        || slot(0x80) != HalAcpiPmRegisterRead as *const () as usize
        || slot(0x88) != HalAcpiPmRegisterWrite as *const () as usize
        || slot(0x68) != HalAcpiGetFacsMapping as *const () as usize
    {
        return Err("a routine is not in Windows' slot for it");
    }
    if described[TIMER as usize].is_some() {
        // The power-management timer counts: two reads differ or the
        // second is the later one, and it is read four bytes at a time.
        let (mut first, mut second, mut size) = ([0u8; 4], [0u8; 4], 0u32);
        // SAFETY: locals of the lengths given.
        let read = unsafe {
            HalAcpiPmRegisterRead(TIMER, 0, first.as_mut_ptr(), 4, &raw mut size) == STATUS_SUCCESS
                && size == 4
                && HalAcpiPmRegisterRead(TIMER, 0, second.as_mut_ptr(), 2, core::ptr::null_mut())
                    == STATUS_BUFFER_TOO_SMALL
        };
        if !read {
            return Err("the timer was not read four bytes at a time");
        }
        let mut later = 0;
        for _ in 0..1_000_000 {
            // SAFETY: as above.
            unsafe { HalAcpiPmRegisterRead(TIMER, 0, second.as_mut_ptr(), 4, &raw mut size) };
            later = u32::from_le_bytes(second);
            if later != u32::from_le_bytes(first) {
                break;
            }
        }
        if later == u32::from_le_bytes(first) {
            return Err("the power-management timer does not count");
        }
    }
    let facs = HalAcpiGetFacsMapping();
    let expected = nk_acpi::facs_address(fadt).is_some();
    // SAFETY: a mapping given starts with the table's signature.
    let signed = !facs.is_null() && unsafe { facs.cast::<[u8; 4]>().read() } == *b"FACS";
    if signed != expected {
        return Err("the FACS was not given where the firmware has one");
    }
    Ok(())
}
