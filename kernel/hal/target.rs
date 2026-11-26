//! `HalGetInterruptTargetInformation`: how the machine's interrupt
//! controllers address processors, which a bus driver needs before it
//! composes message-signalled interrupts. Undocumented; the layout and
//! the answers are the pinned kernel's.

#![allow(non_snake_case)]

use super::platform;
use crate::arch::InterruptVectors;
use crate::ke::smp;
use nk_ntabi::status::{NTSTATUS, STATUS_INVALID_PARAMETER, STATUS_NOT_FOUND, STATUS_SUCCESS};

/// What the routine fills in: 24 bytes.
#[repr(C)]
pub struct INTERRUPT_TARGET_INFORMATION {
    /// The kind of target asked about, as given.
    pub TargetType: u32,
    /// For one processor: its `PROCESSOR_NUMBER`, the group in the low
    /// half and the number within the group in the third byte.
    pub ProcessorNumber: u32,
    /// Bit 0: message-signalled interrupts can be delivered.
    pub Flags: u32,
    /// For one processor in a logical mode: its target in that mode.
    pub Target: [u32; 2],
    /// How interrupts name their destination.
    pub Format: u32,
}

const _: () = assert!(size_of::<INTERRUPT_TARGET_INFORMATION>() == 0x18);

/// `TargetType`: one processor, named by `target`.
const ONE_PROCESSOR: u32 = 0;
/// `TargetType`: the machine as a whole.
const ANY: u32 = 2;
/// `Flags`: messages are supported.
const MESSAGES_SUPPORTED: u32 = 1;
/// `Format`: a destination is a processor's own identifier (physical
/// mode), which is how NK programs its controllers on both
/// architectures. Windows' other formats are its logical modes.
const PHYSICAL: u32 = 1;

/// The routine drivers import. For the machine as a whole it says
/// whether messages can be delivered and that destinations are
/// physical. Asked about one processor, named by the identifier its
/// interrupt controller knows it by (`target`: its local APIC's on
/// x86-64; `acpi.sys` asks for each processor the firmware lists), it
/// says the same and gives the processor's number, or
/// `STATUS_NOT_FOUND` if no running processor has the identifier. Any
/// other kind of target is `STATUS_INVALID_PARAMETER`. All as the
/// pinned kernel does on a machine in physical mode.
///
/// # Safety
/// `information` points to 24 writable bytes.
pub unsafe extern "C" fn HalGetInterruptTargetInformation(
    target_type: u32,
    target: u32,
    information: *mut INTERRUPT_TARGET_INFORMATION,
) -> NTSTATUS {
    if target_type != ANY && target_type != ONE_PROCESSOR {
        return STATUS_INVALID_PARAMETER;
    }
    let mut answer = INTERRUPT_TARGET_INFORMATION {
        TargetType: target_type,
        ProcessorNumber: 0,
        Flags: if InterruptVectors::MESSAGES {
            MESSAGES_SUPPORTED
        } else {
            0
        },
        Target: [0; 2],
        Format: PHYSICAL,
    };
    let mut status = STATUS_SUCCESS;
    if target_type == ONE_PROCESSOR {
        let index = platform::get()
            .cpus()
            .iter()
            .position(|cpu| cpu.hw_id == u64::from(target))
            .filter(|&index| smp::is_online(index));
        match index {
            // NK's processors are all in group 0.
            Some(index) => answer.ProcessorNumber = (index as u32) << 16,
            None => status = STATUS_NOT_FOUND,
        }
    }
    // SAFETY: the caller's. Windows fills in what it knows before it
    // looks for the processor.
    unsafe { information.write_unaligned(answer) };
    status
}

/// For the self-tests.
pub fn test() -> Result<(), &'static str> {
    let mut information = INTERRUPT_TARGET_INFORMATION {
        TargetType: 9,
        ProcessorNumber: 9,
        Flags: 9,
        Target: [9; 2],
        Format: 9,
    };
    // SAFETY: a local of the routine's structure.
    let status = unsafe { HalGetInterruptTargetInformation(ANY, 0, &raw mut information) };
    if status != STATUS_SUCCESS
        || information.TargetType != ANY
        || information.ProcessorNumber != 0
        || information.Target != [0; 2]
        || information.Format != PHYSICAL
        || (information.Flags == MESSAGES_SUPPORTED) != InterruptVectors::MESSAGES
    {
        return Err("the machine's interrupt targets were not described");
    }
    // SAFETY: as above.
    if unsafe { HalGetInterruptTargetInformation(1, 0, &raw mut information) }
        != STATUS_INVALID_PARAMETER
    {
        return Err("a kind of target Windows refuses was not refused");
    }
    // Each running processor is found by its controller's identifier,
    // as `acpi.sys` asks; an identifier no processor has is not.
    let mut none = 0u64;
    for (index, cpu) in platform::get().cpus().iter().enumerate() {
        none = none.max(cpu.hw_id + 1);
        let Ok(id) = u32::try_from(cpu.hw_id) else {
            continue;
        };
        // SAFETY: as above.
        let status =
            unsafe { HalGetInterruptTargetInformation(ONE_PROCESSOR, id, &raw mut information) };
        let expected = if smp::is_online(index) {
            STATUS_SUCCESS
        } else {
            STATUS_NOT_FOUND
        };
        if status != expected
            || information.TargetType != ONE_PROCESSOR
            || information.Format != PHYSICAL
            || information.Target != [0; 2]
            || (status == STATUS_SUCCESS && information.ProcessorNumber != (index as u32) << 16)
        {
            return Err("a processor was not found by its controller's identifier");
        }
    }
    if let Ok(none) = u32::try_from(none) {
        // SAFETY: as above.
        if unsafe { HalGetInterruptTargetInformation(ONE_PROCESSOR, none, &raw mut information) }
            != STATUS_NOT_FOUND
        {
            return Err("a processor was found for an identifier none has");
        }
    }
    Ok(())
}
