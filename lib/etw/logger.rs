//! Trace sessions ("loggers"), of which there are none: what
//! `WmiQueryTraceInformation` answers then.
//!
//! A provider learns of a session through the handle in the request
//! that enables it: the session's number in the low 16 bits, the level
//! in the third byte, the enable flags in the upper half. Some classes
//! only take such a handle apart, and answer whether the session exists
//! or not; the rest ask about a session and find none. The checks and
//! their order are the pinned kernel's.

use nk_ntabi::status::*;

/// How many sessions Windows has room for by default; a session's
/// number is below it.
pub const MAX_LOGGERS: u64 = 0x40;

/// `TRACE_INFORMATION_CLASS`.
pub const TRACE_ID: u32 = 0;
pub const TRACE_HANDLE: u32 = 1;
pub const TRACE_ENABLE_FLAGS: u32 = 2;
pub const TRACE_ENABLE_LEVEL: u32 = 3;
pub const GLOBAL_LOGGER_HANDLE: u32 = 4;
pub const ALL_LOGGER_HANDLES: u32 = 6;
pub const TRACE_HANDLE_BY_NAME: u32 = 7;
pub const LOGGER_EVENTS_LOST: u32 = 8;
pub const TRACE_SESSION_SETTINGS: u32 = 9;
pub const LOGGER_EVENTS_LOGGED: u32 = 10;
pub const DISK_IO_NOTIFY_ROUTINES: u32 = 11;
pub const ALL_NOTIFY_ROUTINES: u32 = 12;
pub const FLT_IO_NOTIFY_ROUTINES: u32 = 13;
pub const WDF_NOTIFY_ROUTINES: u32 = 15;

/// What a class reads through the caller's `Buffer` pointer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Input {
    /// Nothing: the pointer is not looked at.
    Nothing,
    /// Only whether there is one.
    Presence,
    /// A session's number: the 32 bits it points to.
    LoggerId,
    /// A `WNODE_HEADER`'s `HistoricalContext`: the 64 bits at offset 8.
    HistoricalContext,
    /// A counted string naming a session.
    Name,
}

pub fn input(class: u32) -> Input {
    match class {
        TRACE_ID | TRACE_ENABLE_FLAGS | TRACE_ENABLE_LEVEL => Input::HistoricalContext,
        TRACE_HANDLE => Input::LoggerId,
        TRACE_HANDLE_BY_NAME => Input::Name,
        LOGGER_EVENTS_LOST | TRACE_SESSION_SETTINGS | LOGGER_EVENTS_LOGGED => Input::Presence,
        _ => Input::Nothing,
    }
}

/// What is written to the caller's `TraceInformation`, if it gave one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Output {
    Nothing,
    U32(u32),
    U64(u64),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Answer {
    pub status: NTSTATUS,
    /// What is written to the caller's `RequiredLength`, if it gave
    /// one: zero unless the class got far enough to say.
    pub required: u32,
    pub output: Output,
}

/// What the caller handed in.
#[derive(Debug, Clone, Copy)]
pub struct Query {
    pub class: u32,
    /// `TraceInformationLength`.
    pub length: u32,
    /// Whether `TraceInformation` is a pointer.
    pub has_information: bool,
    /// Whether `RequiredLength` is a pointer.
    pub has_required: bool,
    /// What the class reads through `Buffer` ([`input`]); `None` for no
    /// buffer. For [`Input::Name`], non-zero if the string has
    /// characters.
    pub buffer: Option<u64>,
}

fn fail(status: NTSTATUS, required: u32) -> Answer {
    Answer {
        status,
        required,
        output: Output::Nothing,
    }
}

/// Whether `context` can be a session's handle at all: a provider that
/// was never enabled holds zero, and Windows refuses all ones in the
/// low half too.
fn is_handle(context: u64) -> bool {
    context != 0 && context != 0xFFFF_FFFF
}

/// Answer a query on a system where no session exists.
pub fn query(q: &Query) -> Answer {
    let done = |required: u32, output: Output| Answer {
        status: STATUS_SUCCESS,
        required,
        output,
    };
    let Query { length, buffer, .. } = *q;
    match q.class {
        TRACE_ID => match buffer {
            _ if length != 4 => fail(STATUS_INFO_LENGTH_MISMATCH, 0),
            None => fail(STATUS_INVALID_PARAMETER_MIX, 0),
            Some(context) if !is_handle(context) || context & 0xFFFF >= MAX_LOGGERS => {
                fail(STATUS_INVALID_HANDLE, 0)
            }
            Some(context) => done(4, Output::U32(u32::from(context as u16))),
        },
        TRACE_HANDLE => match buffer {
            _ if length != 8 => fail(STATUS_INFO_LENGTH_MISMATCH, 0),
            None => fail(STATUS_INVALID_PARAMETER_MIX, 0),
            Some(id) if id >= MAX_LOGGERS => fail(STATUS_INVALID_HANDLE, 0),
            // Session zero, the kernel's own, goes by 0xFFFF.
            Some(0) => done(8, Output::U64(0xFFFF)),
            Some(id) => done(8, Output::U64(id)),
        },
        TRACE_ENABLE_FLAGS | TRACE_ENABLE_LEVEL => match buffer {
            _ if length < 4 => fail(STATUS_INFO_LENGTH_MISMATCH, 0),
            None => fail(STATUS_INVALID_PARAMETER_MIX, 0),
            Some(context) if !is_handle(context) => fail(STATUS_INVALID_HANDLE, 0),
            Some(context) if q.class == TRACE_ENABLE_FLAGS => {
                done(4, Output::U32((context >> 32) as u32))
            }
            Some(context) => done(4, Output::U32((context >> 16) as u32 & 0xFF)),
        },
        GLOBAL_LOGGER_HANDLE => {
            if length != 8 {
                fail(STATUS_INFO_LENGTH_MISMATCH, 0)
            } else {
                fail(STATUS_NOT_FOUND, 0)
            }
        }
        // The handles of every session: none, in no bytes.
        ALL_LOGGER_HANDLES => {
            if length < 8 || !q.has_information {
                fail(STATUS_INFO_LENGTH_MISMATCH, 0)
            } else {
                done(0, Output::Nothing)
            }
        }
        TRACE_HANDLE_BY_NAME => match buffer {
            _ if length != 8 => fail(STATUS_INFO_LENGTH_MISMATCH, 0),
            None | Some(0) => fail(STATUS_INVALID_PARAMETER, 0),
            Some(_) => fail(STATUS_WMI_INSTANCE_NOT_FOUND, 0),
        },
        LOGGER_EVENTS_LOST | LOGGER_EVENTS_LOGGED => {
            let size = if q.class == LOGGER_EVENTS_LOST { 4 } else { 8 };
            match buffer {
                _ if length != size => fail(STATUS_INFO_LENGTH_MISMATCH, 0),
                None => fail(STATUS_INVALID_PARAMETER_MIX, 0),
                Some(_) => fail(STATUS_NOT_FOUND, 0),
            }
        }
        TRACE_SESSION_SETTINGS => {
            if buffer.is_none() {
                fail(STATUS_INVALID_PARAMETER_5, 0)
            } else if !q.has_required {
                fail(STATUS_INVALID_PARAMETER_4, 0)
            } else if length < 0x20 {
                fail(STATUS_INFO_LENGTH_MISMATCH, 0x20)
            } else if !q.has_information {
                fail(STATUS_INVALID_PARAMETER_2, 0x20)
            } else {
                fail(STATUS_WMI_INSTANCE_NOT_FOUND, 0x20)
            }
        }
        // The tables of routines the kernel calls on disk, file-system
        // and framework events as it traces them. Tracing has not
        // started, which is Windows' answer before it has.
        DISK_IO_NOTIFY_ROUTINES | FLT_IO_NOTIFY_ROUTINES | WDF_NOTIFY_ROUTINES => {
            fail(STATUS_DEVICE_NOT_READY, 8)
        }
        ALL_NOTIFY_ROUTINES => fail(STATUS_DEVICE_NOT_READY, 0x78),
        _ => fail(STATUS_INVALID_INFO_CLASS, 0),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ask(class: u32, length: u32, buffer: Option<u64>) -> Answer {
        query(&Query {
            class,
            length,
            has_information: true,
            has_required: true,
            buffer,
        })
    }

    /// The handle nkc-etw takes apart: flags 5, level 3, session 2.
    const HANDLE: u64 = 0x0000_0005_0003_0002;

    #[test]
    fn a_handle_is_taken_apart_whether_or_not_its_session_exists() {
        assert_eq!(
            ask(TRACE_ENABLE_LEVEL, 4, Some(HANDLE)),
            Answer {
                status: STATUS_SUCCESS,
                required: 4,
                output: Output::U32(3)
            }
        );
        assert_eq!(
            ask(TRACE_ENABLE_FLAGS, 4, Some(HANDLE)).output,
            Output::U32(5)
        );
        assert_eq!(ask(TRACE_ID, 4, Some(HANDLE)).output, Output::U32(2));
        // The level is one byte of the handle.
        assert_eq!(
            ask(TRACE_ENABLE_LEVEL, 4, Some(0x0000_0005_0703_0002)).output,
            Output::U32(3)
        );
        // Flags and level take a longer buffer; the id does not.
        assert_eq!(ask(TRACE_ENABLE_LEVEL, 8, Some(HANDLE)).status, 0);
        assert_eq!(
            ask(TRACE_ID, 8, Some(HANDLE)).status,
            STATUS_INFO_LENGTH_MISMATCH
        );
    }

    #[test]
    fn the_checks_come_in_windows_order() {
        // Length, then the buffer, then the handle.
        assert_eq!(
            ask(TRACE_ENABLE_LEVEL, 2, None),
            fail(STATUS_INFO_LENGTH_MISMATCH, 0)
        );
        assert_eq!(
            ask(TRACE_ENABLE_LEVEL, 4, None),
            fail(STATUS_INVALID_PARAMETER_MIX, 0)
        );
        for none in [0, 0xFFFF_FFFF] {
            for class in [TRACE_ID, TRACE_ENABLE_FLAGS, TRACE_ENABLE_LEVEL] {
                assert_eq!(ask(class, 4, Some(none)), fail(STATUS_INVALID_HANDLE, 0));
            }
        }
    }

    #[test]
    fn a_session_number_beyond_the_last_is_no_handle() {
        assert_eq!(ask(TRACE_ID, 4, Some(0x3F)).output, Output::U32(0x3F));
        assert_eq!(ask(TRACE_ID, 4, Some(0x40)).status, STATUS_INVALID_HANDLE);
        assert_eq!(
            ask(TRACE_ID, 4, Some(0x5_0003_FFFF)).status,
            STATUS_INVALID_HANDLE
        );
        // Flags and level do not look at the number.
        assert_eq!(ask(TRACE_ENABLE_LEVEL, 4, Some(0x5_0003_FFFF)).status, 0);
    }

    #[test]
    fn a_session_number_becomes_a_handle() {
        assert_eq!(ask(TRACE_HANDLE, 8, Some(5)).output, Output::U64(5));
        assert_eq!(ask(TRACE_HANDLE, 8, Some(0)).output, Output::U64(0xFFFF));
        assert_eq!(ask(TRACE_HANDLE, 8, Some(5)).required, 8);
        assert_eq!(
            ask(TRACE_HANDLE, 8, Some(0x40)).status,
            STATUS_INVALID_HANDLE
        );
        assert_eq!(
            ask(TRACE_HANDLE, 4, Some(5)).status,
            STATUS_INFO_LENGTH_MISMATCH
        );
        assert_eq!(
            ask(TRACE_HANDLE, 8, None).status,
            STATUS_INVALID_PARAMETER_MIX
        );
    }

    #[test]
    fn questions_about_a_session_find_none() {
        assert_eq!(
            ask(GLOBAL_LOGGER_HANDLE, 8, None),
            fail(STATUS_NOT_FOUND, 0)
        );
        assert_eq!(
            ask(GLOBAL_LOGGER_HANDLE, 4, None).status,
            STATUS_INFO_LENGTH_MISMATCH
        );
        assert_eq!(
            ask(LOGGER_EVENTS_LOST, 4, Some(1)),
            fail(STATUS_NOT_FOUND, 0)
        );
        assert_eq!(
            ask(LOGGER_EVENTS_LOST, 8, Some(1)).status,
            STATUS_INFO_LENGTH_MISMATCH
        );
        assert_eq!(
            ask(LOGGER_EVENTS_LOGGED, 8, Some(1)),
            fail(STATUS_NOT_FOUND, 0)
        );
        assert_eq!(
            ask(LOGGER_EVENTS_LOGGED, 8, None).status,
            STATUS_INVALID_PARAMETER_MIX
        );
        assert_eq!(
            ask(TRACE_HANDLE_BY_NAME, 8, Some(1)).status,
            STATUS_WMI_INSTANCE_NOT_FOUND
        );
        for no_name in [None, Some(0)] {
            assert_eq!(
                ask(TRACE_HANDLE_BY_NAME, 8, no_name).status,
                STATUS_INVALID_PARAMETER
            );
        }
        assert_eq!(
            ask(TRACE_HANDLE_BY_NAME, 4, Some(1)).status,
            STATUS_INFO_LENGTH_MISMATCH
        );
    }

    #[test]
    fn the_list_of_all_sessions_is_empty() {
        assert_eq!(
            ask(ALL_LOGGER_HANDLES, 8, None),
            Answer {
                status: STATUS_SUCCESS,
                required: 0,
                output: Output::Nothing
            }
        );
        assert_eq!(
            ask(ALL_LOGGER_HANDLES, 4, None).status,
            STATUS_INFO_LENGTH_MISMATCH
        );
        let no_room = query(&Query {
            class: ALL_LOGGER_HANDLES,
            length: 64,
            has_information: false,
            has_required: true,
            buffer: None,
        });
        assert_eq!(no_room.status, STATUS_INFO_LENGTH_MISMATCH);
    }

    #[test]
    fn session_settings_check_their_pointers_one_by_one() {
        let settings = |length, has_information, has_required, buffer| {
            query(&Query {
                class: TRACE_SESSION_SETTINGS,
                length,
                has_information,
                has_required,
                buffer,
            })
        };
        assert_eq!(
            settings(0x20, true, true, None),
            fail(STATUS_INVALID_PARAMETER_5, 0)
        );
        assert_eq!(
            settings(0x20, true, false, Some(1)),
            fail(STATUS_INVALID_PARAMETER_4, 0)
        );
        assert_eq!(
            settings(0x1F, true, true, Some(1)),
            fail(STATUS_INFO_LENGTH_MISMATCH, 0x20)
        );
        assert_eq!(
            settings(0x20, false, true, Some(1)),
            fail(STATUS_INVALID_PARAMETER_2, 0x20)
        );
        assert_eq!(
            settings(0x20, true, true, Some(1)),
            fail(STATUS_WMI_INSTANCE_NOT_FOUND, 0x20)
        );
    }

    #[test]
    fn notify_routine_tables_are_not_ready_and_say_their_size() {
        for class in [
            DISK_IO_NOTIFY_ROUTINES,
            FLT_IO_NOTIFY_ROUTINES,
            WDF_NOTIFY_ROUTINES,
        ] {
            assert_eq!(ask(class, 8, None), fail(STATUS_DEVICE_NOT_READY, 8));
        }
        assert_eq!(
            ask(ALL_NOTIFY_ROUTINES, 0x78, None),
            fail(STATUS_DEVICE_NOT_READY, 0x78)
        );
    }

    #[test]
    fn other_classes_are_none() {
        for class in [5, 14, 16, 0x7F, u32::MAX] {
            assert_eq!(
                ask(class, 4, Some(HANDLE)),
                fail(STATUS_INVALID_INFO_CLASS, 0)
            );
            assert_eq!(input(class), Input::Nothing);
        }
    }

    #[test]
    fn each_class_reads_its_own_kind_of_buffer() {
        assert_eq!(input(TRACE_ID), Input::HistoricalContext);
        assert_eq!(input(TRACE_ENABLE_LEVEL), Input::HistoricalContext);
        assert_eq!(input(TRACE_HANDLE), Input::LoggerId);
        assert_eq!(input(TRACE_HANDLE_BY_NAME), Input::Name);
        assert_eq!(input(LOGGER_EVENTS_LOST), Input::Presence);
        assert_eq!(input(GLOBAL_LOGGER_HANDLE), Input::Nothing);
        assert_eq!(input(ALL_LOGGER_HANDLES), Input::Nothing);
    }
}
