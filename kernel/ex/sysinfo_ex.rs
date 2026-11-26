//! `NtQuerySystemInformationEx`: the questions about the system that
//! come with an input. Answered: the NUMA node and the processor group
//! of `SystemLogicalProcessorAndGroupInformation`, and whether
//! interrupts are steered (`nk_ex::sysinfo_ex`). Any other class, and
//! the parts of these two NK does not have, stop the system naming
//! what was asked.

#![allow(non_snake_case)]

use crate::ke::smp;
use core::ffi::c_void;
use nk_ex::sysinfo_ex::{self as rules, Answer, Relationship};
use nk_ntabi::status::{NTSTATUS, STATUS_SUCCESS};
use nk_ntabi::sysinfo::{
    GROUP_RELATIONSHIP_ENTRY, NUMA_NODE_RELATIONSHIP_ENTRY,
    SYSTEM_INTERRUPT_STEERING_INFORMATION_CLASS, SYSTEM_INTERRUPT_STEERING_INFORMATION_INPUT,
    SYSTEM_LOGICAL_PROCESSOR_AND_GROUP_INFORMATION_CLASS,
};

/// [`NtQuerySystemInformationEx`](https://learn.microsoft.com/en-us/windows/win32/api/winternl/nf-winternl-ntquerysysteminformation)
/// (undocumented in this form), which drivers import under this name
/// and as `ZwQuerySystemInformationEx`: for a caller in kernel mode
/// the two do the same.
///
/// | Class | Answer |
/// | --- | --- |
/// | 107, `SystemLogicalProcessorAndGroupInformation` | for the relationship in the input: the NUMA node (1) or the group (4), one entry: NK has one of each, holding every running processor. A buffer too short for the entry is `STATUS_INFO_LENGTH_MISMATCH` with the length needed, which is how a caller asks for it |
/// | 180, `SystemInterruptSteeringInformation` | whether the interrupts of the controller are steered between processors: no |
///
/// No input, or one of no length, is `STATUS_INVALID_PARAMETER`
/// whatever the class.
///
/// # Safety
/// `input` is readable for `input_length` bytes and `output` writable
/// for `output_length`; `return_length` is null or writable.
pub unsafe extern "C" fn NtQuerySystemInformationEx(
    class: u32,
    input: *const c_void,
    input_length: u32,
    output: *mut c_void,
    output_length: u32,
    return_length: *mut u32,
) -> NTSTATUS {
    if let Err(status) = rules::has_input(input.is_null(), input_length) {
        return status;
    }
    let report = |length: u32| {
        if !return_length.is_null() {
            // SAFETY: per the contract.
            unsafe { return_length.write_unaligned(length) };
        }
    };
    let failed = |status: NTSTATUS, length: Option<u32>| {
        if let Some(length) = length {
            report(length);
        }
        status
    };
    match class {
        SYSTEM_LOGICAL_PROCESSOR_AND_GROUP_INFORMATION_CLASS => {
            // SAFETY: per the contract, where the input is long enough.
            let relationship =
                (input_length >= 4).then(|| unsafe { input.cast::<u32>().read_unaligned() });
            match rules::relationship(relationship, input_length, smp::online(), output_length) {
                Answer::Status(status, length) => failed(status, length),
                Answer::Written(entry) => {
                    // SAFETY: per the contract: the rules found the
                    // buffer long enough for the entry.
                    unsafe {
                        match entry {
                            Relationship::NumaNode(e) => {
                                output
                                    .cast::<NUMA_NODE_RELATIONSHIP_ENTRY>()
                                    .write_unaligned(e);
                            }
                            Relationship::Group(e) => {
                                output.cast::<GROUP_RELATIONSHIP_ENTRY>().write_unaligned(e);
                            }
                        }
                    }
                    report(entry.length());
                    STATUS_SUCCESS
                }
                Answer::NotImplemented => crate::kd::bugcheck(format_args!(
                    "NtQuerySystemInformationEx: NK does not implement processor relationship {}",
                    relationship.unwrap_or(0)
                )),
            }
        }
        SYSTEM_INTERRUPT_STEERING_INFORMATION_CLASS => {
            let whole =
                input_length as usize >= size_of::<SYSTEM_INTERRUPT_STEERING_INFORMATION_INPUT>();
            // SAFETY: per the contract, where the input is long enough;
            // a copy, since the driver may write it.
            let question = whole.then(|| unsafe {
                input
                    .cast::<SYSTEM_INTERRUPT_STEERING_INFORMATION_INPUT>()
                    .read_unaligned()
            });
            match rules::interrupt_steering(question.as_ref(), input_length, output_length) {
                Answer::Status(status, length) => failed(status, length),
                Answer::Written(steered) => {
                    // SAFETY: per the contract: four bytes at least.
                    unsafe { output.cast::<u32>().write_unaligned(steered) };
                    report(4);
                    STATUS_SUCCESS
                }
                Answer::NotImplemented => crate::kd::bugcheck(format_args!(
                    "NtQuerySystemInformationEx: NK does not implement the steering mode of one interrupt (GSIV {:#x})",
                    question.map_or(0, |q| q.Gsiv)
                )),
            }
        }
        _ => crate::kd::bugcheck(format_args!(
            "NtQuerySystemInformationEx: NK does not implement information class {class}"
        )),
    }
}
