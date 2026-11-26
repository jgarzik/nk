//! Parts of Windows NK runs without, each answered as the pinned
//! kernel's own routine answers while that part is off: the driver
//! verifier, the headless terminal, a hypervisor's interface.

#![allow(non_snake_case)]

use core::ffi::c_void;
use nk_ex::headless::{self, Verdict};
use nk_ntabi::status::{NTSTATUS, STATUS_SUCCESS};

/// `VfIsVerificationEnabled` (undocumented): whether the driver
/// verifier checks objects of kind `kind`. The verifier is not
/// running, and Windows' routine then answers false before it looks
/// at either argument.
pub extern "C" fn VfIsVerificationEnabled(_kind: u32, _object: *const c_void) -> u32 {
    0
}

/// `VfFailDeviceNode` (undocumented): the driver verifier's report of
/// a device that broke a rule. It asks `VfIsVerificationEnabled`
/// first, and with the verifier not running reports nothing.
pub extern "C" fn VfFailDeviceNode(
    _device: *const c_void,
    _bugcheck_major: u32,
    _bugcheck_minor: u32,
) {
}

/// `VfFailSystemBIOS` (undocumented): the driver verifier's report of
/// firmware that broke a rule. With the verifier not running Windows'
/// routine returns at once.
pub extern "C" fn VfFailSystemBIOS(_bugcheck_major: u32, _bugcheck_minor: u32) {}

/// `HeadlessDispatch` (undocumented; `HEADLESS_CMD` in the WDK's
/// `ntddk.h` of old): one command to the headless terminal. NK has
/// none, and answers as Windows does while headless operation is not
/// set up (`nk_ex::headless`): the terminal cannot be enabled, a
/// question is answered with zeros, and output has nowhere to go and
/// succeeds.
///
/// # Safety
/// `output_size` is null or points to the length of the buffer at
/// `output`, which is null or writable for that length.
pub unsafe extern "C" fn HeadlessDispatch(
    command: u32,
    _input: *const c_void,
    _input_size: usize,
    output: *mut c_void,
    output_size: *mut usize,
) -> NTSTATUS {
    match headless::dispatch(command, !output.is_null() && !output_size.is_null()) {
        Verdict::Status(status) => status,
        Verdict::Zeroed => {
            // SAFETY: per the contract: both are there, and the buffer
            // is as long as the caller says.
            unsafe {
                output
                    .cast::<u8>()
                    .write_bytes(0, output_size.read_unaligned())
            };
            STATUS_SUCCESS
        }
    }
}

/// `HviIsAnyHypervisorPresent` (undocumented): whether the processor
/// says it runs under a hypervisor (`arch::platform`).
pub extern "C" fn HviIsAnyHypervisorPresent() -> u8 {
    u8::from(crate::arch::platform::hypervisor_present())
}

/// `HviGetHypervisorFeatures` (undocumented): the feature words of a
/// hypervisor that offers Microsoft's interface, zeros under any other
/// and under none.
///
/// # Safety
/// `features` points to room for four `u32`.
pub unsafe extern "C" fn HviGetHypervisorFeatures(features: *mut [u32; 4]) {
    // SAFETY: per the contract.
    unsafe { features.write_unaligned(crate::arch::platform::hypervisor_features()) };
}
