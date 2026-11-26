//! What the HAL does for `acpi.sys`: the two exchange tables of routines
//! and the firmware's tables are found through it.
//!
//! `acpi.sys` calls `HalDispatchTable.HalInitPowerManagement` from its
//! `DriverEntry`, handing over a table of its own routines and getting
//! the HAL's ACPI table back (`dispatch::HalAcpiDispatchTable`). It
//! then asks that table's `HalAcpiGetTable` for each firmware table it
//! reads, the root table first.

#![allow(non_snake_case)]

use super::dispatch::{HalAcpiDispatchTable, HalDispatchTable, acpi_slot, public_slot};
use super::platform;
use core::ffi::c_void;
use core::sync::atomic::{AtomicPtr, Ordering};
use nk_ntabi::status::{NTSTATUS, STATUS_INVALID_PARAMETER, STATUS_SUCCESS};

/// The table of its routines the ACPI driver gave the HAL, or null
/// before it has.
static DRIVER_TABLE: AtomicPtr<c_void> = AtomicPtr::new(core::ptr::null_mut());

/// `HalDispatchTable.HalInitPowerManagement`: take the ACPI driver's
/// table of routines and give it the HAL's.
///
/// # Safety
/// `hal_table` points to a writable pointer.
pub unsafe extern "C" fn HalInitPowerManagement(
    driver_table: *mut c_void,
    hal_table: *mut *const c_void,
) -> NTSTATUS {
    if driver_table.is_null() || hal_table.is_null() {
        return STATUS_INVALID_PARAMETER;
    }
    DRIVER_TABLE.store(driver_table, Ordering::Release);
    // SAFETY: the caller's.
    unsafe { hal_table.write_unaligned(HalAcpiDispatchTable.address().cast()) };
    STATUS_SUCCESS
}

/// The HAL's ACPI table, `HalAcpiGetTable`: the firmware's table of the
/// signature `signature`, or null. `RSDT` and `XSDT` both name the root
/// table the firmware has, and `DSDT` the table the FADT points to; for
/// any other, `oem_id` (six bytes) and `oem_table_id` (eight), where
/// not null, pick among tables of one signature.
///
/// The address is the firmware's table itself in the kernel's map of
/// physical memory, where Windows gives a copy it keeps: firmware
/// memory is never reused, so the table stays.
///
/// # Safety
/// `oem_id` is null or points to six bytes, `oem_table_id` to eight.
pub unsafe extern "C" fn HalAcpiGetTable(
    signature: u32,
    oem_id: *const [u8; 6],
    oem_table_id: *const [u8; 8],
) -> *mut c_void {
    // SAFETY: the caller's, read once.
    let (oem_id, oem_table_id) = unsafe {
        (
            (!oem_id.is_null()).then(|| oem_id.read_unaligned()),
            (!oem_table_id.is_null()).then(|| oem_table_id.read_unaligned()),
        )
    };
    platform::acpi_table(
        &signature.to_le_bytes(),
        oem_id.as_ref(),
        oem_table_id.as_ref(),
    )
    .map_or(core::ptr::null_mut(), |table| {
        table.as_ptr().cast_mut().cast()
    })
}

/// Put the routines of this file in their slots.
pub fn init() {
    HalDispatchTable.provide(
        public_slot("HalInitPowerManagement"),
        HalInitPowerManagement as *const (),
    );
    HalAcpiDispatchTable.provide(acpi_slot("HalAcpiGetTable"), HalAcpiGetTable as *const ());
}

/// For the self-tests: the exchange and the table lookups, made as
/// `acpi.sys` makes them, through the slots.
pub fn test() -> Result<(), &'static str> {
    type Exchange = unsafe extern "C" fn(*mut c_void, *mut *const c_void) -> NTSTATUS;
    type GetTable = unsafe extern "C" fn(u32, *const [u8; 6], *const [u8; 8]) -> *mut c_void;
    let before = DRIVER_TABLE.load(Ordering::Acquire);
    let mut drivers = [0u64; 2];
    let mut hal: *const c_void = core::ptr::null();
    // SAFETY: the slot holds `HalInitPowerManagement`, of this type.
    let exchange: Exchange = unsafe {
        core::mem::transmute(HalDispatchTable.routine(public_slot("HalInitPowerManagement")))
    };
    // SAFETY: locals for both tables.
    let status = unsafe { exchange(drivers.as_mut_ptr().cast(), &raw mut hal) };
    let taken = DRIVER_TABLE.swap(before, Ordering::AcqRel);
    if status != STATUS_SUCCESS
        || hal != HalAcpiDispatchTable.address().cast()
        || taken != drivers.as_mut_ptr().cast()
    {
        return Err("the tables were not exchanged");
    }
    // SAFETY: the HAL's table starts with its signature and version.
    if unsafe { hal.cast::<u64>().read() } != nk_ntabi::hal::HAL_ACPI_DISPATCH_HEADER {
        return Err("the HAL's table does not start with Windows' signature and version");
    }
    // SAFETY: no table to take or no place for the HAL's.
    let refused = unsafe {
        exchange(core::ptr::null_mut(), &raw mut hal) != STATUS_INVALID_PARAMETER
            || exchange(drivers.as_mut_ptr().cast(), core::ptr::null_mut())
                != STATUS_INVALID_PARAMETER
    };
    if refused {
        return Err("an exchange without a table was not refused");
    }
    // SAFETY: the slot at Windows' offset holds `HalAcpiGetTable`.
    let get: GetTable =
        unsafe { core::mem::transmute(hal.cast::<u8>().add(0x58).cast::<*const ()>().read()) };
    let none = (core::ptr::null(), core::ptr::null());
    let signature = |name: &[u8; 4]| {
        // SAFETY: no ids; a table found starts with its signature.
        unsafe {
            let table = get(u32::from_le_bytes(*name), none.0, none.1);
            (!table.is_null()).then(|| table.cast::<[u8; 4]>().read())
        }
    };
    let root = signature(b"RSDT");
    if !matches!(root, Some([b'X' | b'R', b'S', b'D', b'T'])) || signature(b"XSDT") != root {
        return Err("the root table was not found under both of its names");
    }
    if signature(b"FACP") != Some(*b"FACP") || signature(b"APIC") != Some(*b"APIC") {
        return Err("a table the root table lists was not found");
    }
    if signature(b"DSDT") != Some(*b"DSDT") {
        return Err("the DSDT was not found through the FADT");
    }
    if signature(b"NKNK").is_some() {
        return Err("a table the firmware does not have was found");
    }
    // SAFETY: ids no table has.
    let other = unsafe { get(u32::from_le_bytes(*b"FACP"), b"NoSuch", none.1) };
    if !other.is_null() {
        return Err("a table was found whatever OEM id was asked for");
    }
    Ok(())
}
