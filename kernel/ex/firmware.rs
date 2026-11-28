//! `ZwSetSystemInformation`: the classes drivers NK runs set, the
//! registration of a firmware table provider and of an entropy routine.

#![allow(non_snake_case)]

use crate::ke::spinlock::{Rank, SpinLock};
use crate::ob::object;
use core::ffi::c_void;
use nk_ex::firmware::{Changed, Provider, Providers};
use nk_ntabi::status::*;
use nk_ntabi::sysinfo::{
    SYSTEM_ENTROPY_INTERRUPT_TIMING_INFORMATION_CLASS, SYSTEM_ENTROPY_TIMING_INFORMATION,
    SYSTEM_FIRMWARE_TABLE_HANDLER, SYSTEM_REGISTER_FIRMWARE_TABLE_INFORMATION_HANDLER_CLASS,
};

/// The firmware table providers drivers have registered.
static PROVIDERS: SpinLock<Providers> = SpinLock::new(Rank::FirmwareTables, Providers::new());

/// `ZwSetSystemInformation` (exported, not documented for drivers):
/// set system information of one class.
///
/// `SystemRegisterFirmwareTableInformationHandler` is implemented, as
/// the pinned kernel's `ExpRegisterFirmwareTableInformationHandler`:
/// `acpi.sys` registers the routine that serves the `'ACPI'` tables,
/// and takes it back when it unloads. The provider and a reference to
/// its driver object are kept (`nk_ex::firmware`). Nothing on NK asks a
/// provider for a table yet: `ZwQuerySystemInformation` does not answer
/// the class that would.
///
/// `SystemEntropyInterruptTimingInformation` (0x83), from `cng.sys`,
/// registers its routine for the times of interrupts
/// (`ke::entropy::register`); a length other than the request's is
/// `STATUS_INFO_LENGTH_MISMATCH`, as the pinned kernel answers.
///
/// Any other class stops the system naming it.
///
/// # Safety
/// `information` is null or readable for `length` bytes; for the
/// class above it names a routine and a live driver object.
pub unsafe extern "C" fn NtSetSystemInformation(
    class: u32,
    information: *mut c_void,
    length: u32,
) -> NTSTATUS {
    if class == SYSTEM_ENTROPY_INTERRUPT_TIMING_INFORMATION_CLASS {
        if information.is_null()
            || length as usize != size_of::<SYSTEM_ENTROPY_TIMING_INFORMATION>()
        {
            return STATUS_INFO_LENGTH_MISMATCH;
        }
        // SAFETY: per the contract: the caller's buffer, of the length.
        let request = unsafe {
            information
                .cast::<SYSTEM_ENTROPY_TIMING_INFORMATION>()
                .read_unaligned()
        };
        // SAFETY: per the contract, the driver's routines.
        return unsafe {
            crate::ke::entropy::register(
                request.EntropyRoutine.addr(),
                request.InitializationRoutine.addr(),
                request.InitializationContext.addr(),
            )
        };
    }
    if class != SYSTEM_REGISTER_FIRMWARE_TABLE_INFORMATION_HANDLER_CLASS {
        crate::kd::bugcheck(format_args!(
            "ZwSetSystemInformation: NK does not implement information class {class}"
        ));
    }
    if information.is_null() || (length as usize) < size_of::<SYSTEM_FIRMWARE_TABLE_HANDLER>() {
        return STATUS_INFO_LENGTH_MISMATCH;
    }
    // SAFETY: per the contract: the caller's buffer, long enough.
    let request = unsafe {
        information
            .cast::<SYSTEM_FIRMWARE_TABLE_HANDLER>()
            .read_unaligned()
    };
    let provider = Provider {
        signature: request.ProviderSignature,
        handler: request.FirmwareTableHandler.addr(),
        driver: request.DriverObject.addr(),
    };
    let changed = {
        let mut providers = PROVIDERS.lock();
        let changed = providers.change(provider, request.Register != 0);
        if changed == Ok(Changed::Registered) {
            // Under the lock: the provider is never listed without
            // its reference.
            // SAFETY: per the contract, a live driver object.
            unsafe { object::reference(request.DriverObject.cast()) };
        }
        changed
    };
    match changed {
        Ok(Changed::Registered) => STATUS_SUCCESS,
        Ok(Changed::Unregistered) => {
            // SAFETY: the reference taken when it was registered.
            unsafe { object::dereference(request.DriverObject.cast()) };
            STATUS_SUCCESS
        }
        Err(status) => status,
    }
}

/// For the self-tests: the routine and the driver object registered
/// for `signature`.
pub fn test_provider(signature: u32) -> Option<(usize, usize)> {
    PROVIDERS
        .lock()
        .find(signature)
        .map(|provider| (provider.handler, provider.driver))
}

/// Query a registered firmware table provider (`SystemFirmwareTableInformation`,
/// class `0x4C`), as `ExpGetSystemFirmwareTableInformation`.
///
/// # Safety
/// `buffer` is readable and writable for `length` bytes.
pub unsafe fn query_table(buffer: *mut u8, length: u32) -> (NTSTATUS, Option<u32>) {
    use nk_ntabi::sysinfo::SYSTEM_FIRMWARE_TABLE_INFORMATION_HEADER as HEADER;
    if buffer.is_null() || (length as usize) < HEADER {
        return (STATUS_INFO_LENGTH_MISMATCH, None);
    }
    // SAFETY: per the contract; `length >= HEADER` (16 bytes).
    let signature = unsafe {
        let payload = length - HEADER as u32;
        buffer.add(0xC).cast::<u32>().write_unaligned(payload);
        buffer.cast::<u32>().read_unaligned()
    };
    let found = {
        let providers = PROVIDERS.lock();
        providers.find(signature).map(|provider| {
            // Pin the provider's driver object while we invoke its callback
            // outside the lock.
            // SAFETY: registered providers hold a live driver object reference.
            unsafe { object::reference(provider.driver as *mut u8) };
            (provider.handler, provider.driver)
        })
    };
    let Some((handler, driver)) = found else {
        return (STATUS_NOT_IMPLEMENTED, None);
    };
    // SAFETY: `handler` is a registered `PFNFTH` (`NTSTATUS (*)(PSYSTEM_FIRMWARE_TABLE_INFORMATION)`).
    let status = unsafe {
        crate::ke::seh::call(
            handler,
            [buffer.addr(), 0, 0, 0],
            &crate::ke::seh::Guard::Nothing,
        ) as u32 as NTSTATUS
    };
    // SAFETY: releases the reference taken above.
    unsafe { object::dereference(driver as *mut u8) };
    // SAFETY: `buffer` is still valid for `HEADER` bytes.
    let written = unsafe { buffer.add(0xC).cast::<u32>().read_unaligned() };
    (status, Some(written.saturating_add(HEADER as u32)))
}

pub use crate::svc::zw::ZwSetSystemInformation;
