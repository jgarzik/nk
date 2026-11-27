//! Stopping the system: how a stop a driver asks for is reported, and
//! the rules of the callback records drivers leave for that moment.
//!
//! Codes and their names are Microsoft's
//! ([bug check code reference](https://learn.microsoft.com/en-us/windows-hardware/drivers/debugger/bug-check-code-reference2)).

use core::fmt;

/// The name of a bugcheck code, for the codes NK itself stops with and
/// the ones drivers most often do. `None` for any other: the number is
/// the report.
pub fn name(code: u32) -> Option<&'static str> {
    Some(match code {
        0x09 => "IRQL_NOT_GREATER_OR_EQUAL",
        0x0A => "IRQL_NOT_LESS_OR_EQUAL",
        0x0C => "MAXIMUM_WAIT_OBJECTS_EXCEEDED",
        0x0F => "SPIN_LOCK_ALREADY_OWNED",
        0x10 => "SPIN_LOCK_NOT_OWNED",
        0x18 => "REFERENCE_BY_POINTER",
        0x19 => "BAD_POOL_HEADER",
        0x1E => "KMODE_EXCEPTION_NOT_HANDLED",
        0x3B => "SYSTEM_SERVICE_EXCEPTION",
        0x44 => "MULTIPLE_IRP_COMPLETE_REQUESTS",
        0x48 => "CANCEL_STATE_IN_COMPLETED_IRP",
        0x50 => "PAGE_FAULT_IN_NONPAGED_AREA",
        0x7E => "SYSTEM_THREAD_EXCEPTION_NOT_HANDLED",
        0x7F => "UNEXPECTED_KERNEL_MODE_TRAP",
        0x80 => "NMI_HARDWARE_FAILURE",
        0x8E => "KERNEL_MODE_EXCEPTION_NOT_HANDLED",
        0x93 => "INVALID_KERNEL_HANDLE",
        0xB8 => "ATTEMPTED_SWITCH_FROM_DPC",
        0xC2 => "BAD_POOL_CALLER",
        0xC4 => "DRIVER_VERIFIER_DETECTED_VIOLATION",
        0xD1 => "DRIVER_IRQL_NOT_LESS_OR_EQUAL",
        0xDA => "SYSTEM_PTE_MISUSE",
        0xE1 => "WORKER_THREAD_RETURNED_AT_BAD_IRQL",
        0xE2 => "MANUALLY_INITIATED_CRASH",
        0xE4 => "WORKER_INVALID",
        0x11D => "EVENT_TRACING_FATAL_ERROR",
        0x122 => "WHEA_INTERNAL_ERROR",
        0x124 => "WHEA_UNCORRECTABLE_ERROR",
        0x133 => "DPC_WATCHDOG_VIOLATION",
        0x139 => "KERNEL_SECURITY_CHECK_FAILURE",
        0x189 => "BAD_OBJECT_HEADER",
        _ => return None,
    })
}

/// A stop asked for with `KeBugCheckEx`: prints as the rest of the
/// `BUGCHECK:` line, code first, as every stop with a Windows code does.
pub struct Stop {
    pub code: u32,
    pub parameters: [usize; 4],
}

impl fmt::Display for Stop {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:#010X}", self.code)?;
        if let Some(name) = name(self.code) {
            write!(f, " {name}")?;
        }
        f.write_str(": KeBugCheckEx (")?;
        for (index, parameter) in self.parameters.iter().enumerate() {
            let comma = if index == 0 { "" } else { ", " };
            write!(f, "{comma}parameter {} {parameter:#018x}", index + 1)?;
        }
        f.write_str(")")
    }
}

/// What Windows stores in a reason-callback record's `Checksum` when it
/// is registered, and looks for before it calls the routine: the sum of
/// the routine's address, the reason (as a signed number) and the
/// component name's address.
pub fn checksum(routine: usize, reason: u32, component: usize) -> usize {
    routine
        .wrapping_add(reason as i32 as isize as usize)
        .wrapping_add(component)
}

/// Whether a record can lie at `address`: pointers to records are
/// aligned as pointers are. A list that leads anywhere else is broken.
pub fn plausible(address: usize) -> bool {
    address != 0 && address % align_of::<usize>() == 0
}

/// The fields of a callback record, as read at the moment of a stop.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Record {
    /// The record before it in the list, by its own back link.
    pub blink: usize,
    pub routine: usize,
    pub component: usize,
    pub checksum: usize,
    pub reason: u32,
    pub state: u8,
}

/// What a walk of the list does at one record.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Walk {
    /// The list is broken here: go no further.
    End,
    /// Not a record to call for this reason, or no longer what was
    /// registered: pass over it.
    Skip,
    /// Call its routine.
    Call,
}

/// `State` of a record that is registered and has not been called.
const INSERTED: u8 = 1;

/// Decide one record of the list, reached from the entry at
/// `previous`, in a walk that calls the routines registered for
/// `wanted`. The order of the checks is Windows'.
pub fn examine(record: &Record, previous: usize, wanted: u32) -> Walk {
    if record.blink != previous {
        return Walk::End;
    }
    let intact = record.state == INSERTED
        && record.checksum == checksum(record.routine, record.reason, record.component)
        && record.reason == wanted
        && record.routine != 0;
    if intact { Walk::Call } else { Walk::Skip }
}

/// Where a newly registered record goes: the triage-data callbacks run
/// in the order they registered, every other reason's newest first.
pub fn at_tail(reason: u32) -> bool {
    reason == 7
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_named_stop_prints_code_name_and_four_parameters() {
        let stop = Stop {
            code: 0xE2,
            parameters: [1, 0x22, 0xFFFF_F880_0000_1000, 0],
        };
        assert_eq!(
            stop.to_string(),
            "0x000000E2 MANUALLY_INITIATED_CRASH: KeBugCheckEx (parameter 1 \
             0x0000000000000001, parameter 2 0x0000000000000022, parameter 3 \
             0xfffff88000001000, parameter 4 0x0000000000000000)"
        );
    }

    #[test]
    fn a_code_without_a_name_prints_as_its_number() {
        let stop = Stop {
            code: 0xDEAD_BEEF,
            parameters: [0; 4],
        };
        assert!(stop.to_string().starts_with("0xDEADBEEF: KeBugCheckEx ("));
        assert_eq!(name(0xDEAD_BEEF), None);
    }

    /// Every code that has a name, with Microsoft's name for it (the
    /// bug check code reference).
    const NAMED: [(u32, &str); 31] = [
        (0x09, "IRQL_NOT_GREATER_OR_EQUAL"),
        (0x0A, "IRQL_NOT_LESS_OR_EQUAL"),
        (0x0C, "MAXIMUM_WAIT_OBJECTS_EXCEEDED"),
        (0x0F, "SPIN_LOCK_ALREADY_OWNED"),
        (0x10, "SPIN_LOCK_NOT_OWNED"),
        (0x18, "REFERENCE_BY_POINTER"),
        (0x19, "BAD_POOL_HEADER"),
        (0x1E, "KMODE_EXCEPTION_NOT_HANDLED"),
        (0x3B, "SYSTEM_SERVICE_EXCEPTION"),
        (0x44, "MULTIPLE_IRP_COMPLETE_REQUESTS"),
        (0x48, "CANCEL_STATE_IN_COMPLETED_IRP"),
        (0x50, "PAGE_FAULT_IN_NONPAGED_AREA"),
        (0x7E, "SYSTEM_THREAD_EXCEPTION_NOT_HANDLED"),
        (0x7F, "UNEXPECTED_KERNEL_MODE_TRAP"),
        (0x80, "NMI_HARDWARE_FAILURE"),
        (0x8E, "KERNEL_MODE_EXCEPTION_NOT_HANDLED"),
        (0x93, "INVALID_KERNEL_HANDLE"),
        (0xB8, "ATTEMPTED_SWITCH_FROM_DPC"),
        (0xC2, "BAD_POOL_CALLER"),
        (0xC4, "DRIVER_VERIFIER_DETECTED_VIOLATION"),
        (0xD1, "DRIVER_IRQL_NOT_LESS_OR_EQUAL"),
        (0xDA, "SYSTEM_PTE_MISUSE"),
        (0xE1, "WORKER_THREAD_RETURNED_AT_BAD_IRQL"),
        (0xE2, "MANUALLY_INITIATED_CRASH"),
        (0xE4, "WORKER_INVALID"),
        (0x11D, "EVENT_TRACING_FATAL_ERROR"),
        (0x122, "WHEA_INTERNAL_ERROR"),
        (0x124, "WHEA_UNCORRECTABLE_ERROR"),
        (0x133, "DPC_WATCHDOG_VIOLATION"),
        (0x139, "KERNEL_SECURITY_CHECK_FAILURE"),
        (0x189, "BAD_OBJECT_HEADER"),
    ];

    #[test]
    fn each_named_code_has_microsofts_name_and_no_other_code_has_one() {
        for (code, wanted) in NAMED {
            assert_eq!(name(code), Some(wanted), "{code:#x}");
        }
        // Everything Windows numbers so far is below this.
        for code in 0..0x1000 {
            let listed = NAMED.iter().any(|&(named, _)| named == code);
            assert_eq!(name(code).is_some(), listed, "{code:#x}");
        }
        // The codes drivers make up for themselves, and the ones with
        // the high bits Windows adds to a code while it reports it.
        for code in [0x1000_007E, 0x4000_0080, 0xC000_0005, u32::MAX] {
            assert_eq!(name(code), None, "{code:#x}");
        }
    }

    #[test]
    fn every_named_stop_reads_code_then_name_then_the_parameters() {
        for (code, wanted) in NAMED {
            let stop = Stop {
                code,
                parameters: [code as usize, 2, 3, 4],
            };
            assert_eq!(
                stop.to_string(),
                format!(
                    "{code:#010X} {wanted}: KeBugCheckEx (parameter 1 {code:#018x}, \
                     parameter 2 0x0000000000000002, parameter 3 0x0000000000000003, \
                     parameter 4 0x0000000000000004)"
                )
            );
        }
    }

    #[test]
    fn no_two_codes_share_a_name() {
        for (index, (_, first)) in NAMED.iter().enumerate() {
            for (_, second) in &NAMED[index + 1..] {
                assert_ne!(first, second);
            }
        }
    }

    #[test]
    fn the_checksum_is_the_sum_and_wraps() {
        assert_eq!(checksum(0x1000, 2, 0x30), 0x1032);
        assert_eq!(checksum(usize::MAX, 2, 0), 1);
        // The reason counts as a signed number.
        assert_eq!(checksum(0x1000, u32::MAX, 0), 0xFFF);
    }

    fn registered(reason: u32) -> Record {
        Record {
            blink: 0x5000,
            routine: 0x1000,
            component: 0x2000,
            checksum: checksum(0x1000, reason, 0x2000),
            reason,
            state: INSERTED,
        }
    }

    #[test]
    fn a_registered_record_is_called_for_its_reason_only() {
        assert_eq!(examine(&registered(7), 0x5000, 7), Walk::Call);
        assert_eq!(examine(&registered(2), 0x5000, 7), Walk::Skip);
        assert_eq!(examine(&registered(7), 0x5000, 1), Walk::Skip);
    }

    #[test]
    fn a_record_changed_since_it_was_registered_is_passed_over() {
        let good = registered(1);
        for state in [0, 2, 3, 4] {
            assert_eq!(examine(&Record { state, ..good }, 0x5000, 1), Walk::Skip);
        }
        let other_routine = Record {
            routine: 0x1008,
            ..good
        };
        assert_eq!(examine(&other_routine, 0x5000, 1), Walk::Skip);
        let other_component = Record {
            component: 0,
            ..good
        };
        assert_eq!(examine(&other_component, 0x5000, 1), Walk::Skip);
        // No routine, with a checksum to match.
        let none = Record {
            routine: 0,
            checksum: checksum(0, 1, 0x2000),
            ..good
        };
        assert_eq!(examine(&none, 0x5000, 1), Walk::Skip);
    }

    #[test]
    fn a_back_link_that_does_not_lead_back_ends_the_walk() {
        assert_eq!(examine(&registered(1), 0x5008, 1), Walk::End);
    }

    #[test]
    fn records_are_where_pointers_can_be() {
        assert!(plausible(0x1000));
        assert!(!plausible(0));
        assert!(!plausible(0x1004));
    }

    #[test]
    fn only_triage_callbacks_queue_at_the_tail() {
        assert!(at_tail(7));
        for reason in [0, 1, 2, 3, 4, 5, 6, 8, 0x3FF] {
            assert!(!at_tail(reason));
        }
    }
}
