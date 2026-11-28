//! Virtual secure mode: services of the secure kernel. NK runs without
//! one, and answers as Windows does when virtual secure mode is off.

#![allow(non_snake_case)]

/// `VslGetSecurePciEnabled` (undocumented): whether the secure kernel
/// guards PCI devices. Without virtual secure mode Windows' routine
/// answers false before asking anything.
pub extern "C" fn VslGetSecurePciEnabled() -> u8 {
    0
}

/// `VslGetSecurePciDeviceAlternateFunctionNumberForVtl0Dma`
/// (undocumented): the function number the secure kernel lets a PCI
/// device do DMA under. With no secure kernel connected Windows'
/// routine answers 0xFF, none.
pub extern "C" fn VslGetSecurePciDeviceAlternateFunctionNumberForVtl0Dma(
    _segment: u32,
    _bus: u8,
    _device: u8,
    _function: u8,
) -> u8 {
    0xFF
}

/// `VslQuerySecureDevice` (undocumented): what the secure kernel knows
/// of a device. Windows' routine clears the 16 bytes of the answer and
/// asks the secure kernel, which with none connected fails with
/// `STATUS_DEVICE_NOT_CONNECTED`.
///
/// # Safety
/// `answer` points to 16 writable bytes.
pub unsafe extern "C" fn VslQuerySecureDevice(
    _device: *const core::ffi::c_void,
    answer: *mut [u8; 16],
) -> nk_ntabi::status::NTSTATUS {
    // SAFETY: per the contract.
    unsafe { answer.write_unaligned([0; 16]) };
    nk_ntabi::status::STATUS_DEVICE_NOT_CONNECTED
}

/// `VslExchangeEntropy` (undocumented): trade 64 bytes of entropy with
/// the secure kernel. With no secure kernel connected Windows' routine
/// fails with `STATUS_DEVICE_NOT_CONNECTED` and leaves the buffer as it
/// was.
pub extern "C" fn VslExchangeEntropy(_entropy: *mut [u8; 64]) -> nk_ntabi::status::NTSTATUS {
    nk_ntabi::status::STATUS_DEVICE_NOT_CONNECTED
}

/// `VslCreateSecureSection` (undocumented): create a VTL1-protected memory
/// section. With virtual secure mode disabled, writes null and fails with
/// `STATUS_DEVICE_NOT_CONNECTED`.
///
/// # Safety
/// `section_handle` is null or writable.
pub unsafe extern "C" fn VslCreateSecureSection(
    section_handle: *mut *mut core::ffi::c_void,
    _size: u64,
    _attributes: u32,
    _flags: u32,
) -> nk_ntabi::status::NTSTATUS {
    if !section_handle.is_null() {
        // SAFETY: checked non-null; per the contract.
        unsafe { section_handle.write_unaligned(core::ptr::null_mut()) };
    }
    nk_ntabi::status::STATUS_DEVICE_NOT_CONNECTED
}

/// `VslDeleteSecureSection` (undocumented): delete a VTL1 secure section.
/// With virtual secure mode disabled, returns `STATUS_DEVICE_NOT_CONNECTED`.
pub extern "C" fn VslDeleteSecureSection(
    _section_handle: *mut core::ffi::c_void,
) -> nk_ntabi::status::NTSTATUS {
    nk_ntabi::status::STATUS_DEVICE_NOT_CONNECTED
}

/// `SkIsSecureKernel` (undocumented): whether the caller runs in the
/// secure kernel. In the normal kernel Windows' routine answers
/// `STATUS_NOT_IMPLEMENTED`, so a driver built for both knows it is
/// not.
pub extern "C" fn SkIsSecureKernel() -> nk_ntabi::status::NTSTATUS {
    nk_ntabi::status::STATUS_NOT_IMPLEMENTED
}

/// The secure kernel's own services (`SkAllocatePool`, `SkFreePool`,
/// `SkInitializePushLock`, `SkAcquirePushLockExclusive`,
/// `SkReleasePushLockExclusive`, `SkQuerySecureKernelInformation`): in
/// the normal kernel every one of them is the same routine, which stops
/// the system with bugcheck 0x123 and no parameters. A driver calls them
/// only after `SkIsSecureKernel` said it runs there.
pub extern "C" fn secure_kernel_only() -> ! {
    crate::ke::bugcheck::KeBugCheckEx(0x123, 0, 0, 0, 0)
}
