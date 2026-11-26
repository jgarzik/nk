//! The headless terminal (Emergency Management Services) when there is
//! none: what the pinned kernel's `HeadlessDispatch` answers each
//! command with while headless operation is not set up.

use nk_ntabi::status::{NTSTATUS, STATUS_INVALID_PARAMETER, STATUS_SUCCESS, STATUS_UNSUCCESSFUL};

/// `HEADLESS_CMD` `HeadlessCmdEnableTerminal`.
const ENABLE_TERMINAL: u32 = 1;
/// `HEADLESS_CMD` `HeadlessCmdPutData`.
const PUT_DATA: u32 = 0x15;
/// The commands that answer with data: query information, get line,
/// terminal poll, get byte, query GUID (2, 11, 12, 13, 16).
const ANSWERING: u32 = 0x13804;

/// What a command comes to.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Verdict {
    /// Return this status and touch nothing.
    Status(NTSTATUS),
    /// Fill the output buffer, to the length the caller gave, with
    /// zeros and return `STATUS_SUCCESS`.
    Zeroed,
}

/// The answer to `command` with no terminal. `output` is whether the
/// caller gave both an output buffer and its length.
///
/// The terminal cannot be enabled and takes no data; a command that
/// answers with data answers zeros; every other command (writing
/// text, setting colours, logging) has nothing to do and succeeds, as
/// on Windows.
pub fn dispatch(command: u32, output: bool) -> Verdict {
    if command == ENABLE_TERMINAL || command == PUT_DATA {
        Verdict::Status(STATUS_UNSUCCESSFUL)
    } else if command <= 16 && ANSWERING & (1 << command) != 0 {
        if output {
            Verdict::Zeroed
        } else {
            Verdict::Status(STATUS_INVALID_PARAMETER)
        }
    } else {
        Verdict::Status(STATUS_SUCCESS)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn no_terminal_to_enable_or_feed() {
        for output in [false, true] {
            assert_eq!(dispatch(1, output), Verdict::Status(STATUS_UNSUCCESSFUL));
            assert_eq!(dispatch(0x15, output), Verdict::Status(STATUS_UNSUCCESSFUL));
        }
    }

    #[test]
    fn questions_are_answered_with_zeros() {
        for command in [2, 11, 12, 13, 16] {
            assert_eq!(dispatch(command, true), Verdict::Zeroed);
            assert_eq!(
                dispatch(command, false),
                Verdict::Status(STATUS_INVALID_PARAMETER)
            );
        }
    }

    #[test]
    fn everything_else_has_nothing_to_do() {
        for command in [0, 3, 4, 10, 14, 15, 17, 0x14, 0x16, 1000] {
            assert_eq!(dispatch(command, false), Verdict::Status(STATUS_SUCCESS));
            assert_eq!(dispatch(command, true), Verdict::Status(STATUS_SUCCESS));
        }
    }
}
