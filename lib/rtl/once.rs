//! One-time initialisation (`RTL_RUN_ONCE`): the word behind
//! [`RtlRunOnceExecuteOnce`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntddk/nf-ntddk-rtlrunonceexecuteonce).
//!
//! The word is zero until the initialisation is first asked for. Its
//! low two bits are its state, as Windows names them; once it is done
//! the rest is the context the initialisation left, which is why a
//! context's low two bits must be clear.
//!
//! While one thread runs the initialisation the word is [`RUNNING`].
//! Windows chains the threads waiting for it through the rest of the
//! word; NK's wait in the kernel's own way and leave the rest zero.

/// The state bits of the word.
pub const STATE: usize = 3;
/// Nothing has been asked for: the whole word is zero.
pub const NEW: usize = 0;
/// A thread is running the initialisation.
pub const RUNNING: usize = 1;
/// Done: the rest of the word is the context.
pub const DONE: usize = 2;

/// What a thread that wants the initialisation done finds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Begin {
    /// Done already, with this context.
    Done(usize),
    /// Nobody has begun: store [`RUNNING`], if the word is still
    /// [`NEW`], and run it.
    Run,
    /// Another thread is running it: wait, and look again.
    Wait,
}

/// What the word says to a thread that wants the initialisation done.
pub fn begin(word: usize) -> Begin {
    match word & STATE {
        DONE => Begin::Done(word & !STATE),
        _ if word == NEW => Begin::Run,
        _ => Begin::Wait,
    }
}

/// The word of an initialisation that succeeded and left `context`;
/// `None` if the context's low two bits are not clear, which the
/// routine cannot record.
pub fn done(context: usize) -> Option<usize> {
    (context & STATE == 0).then_some(context | DONE)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_word_goes_from_new_to_running_to_done() {
        assert_eq!(begin(NEW), Begin::Run);
        assert_eq!(begin(RUNNING), Begin::Wait);
        assert_eq!(begin(done(0).unwrap()), Begin::Done(0));
        assert_eq!(begin(done(0x1000).unwrap()), Begin::Done(0x1000));
        assert_eq!(
            begin(done(0xFFFF_8000_0000_1234 & !3).unwrap()),
            Begin::Done(0xFFFF_8000_0000_1234 & !3)
        );
        // Windows' other state in progress is waited out too.
        assert_eq!(begin(3), Begin::Wait);
        assert_eq!(begin(0x1001), Begin::Wait);
    }

    #[test]
    fn a_context_needs_its_low_two_bits_clear() {
        assert_eq!(done(0), Some(DONE));
        assert_eq!(done(8), Some(10));
        assert_eq!(done(1), None);
        assert_eq!(done(2), None);
        assert_eq!(done(0x1003), None);
    }
}
