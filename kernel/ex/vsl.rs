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
