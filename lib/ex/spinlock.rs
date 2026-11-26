//! The [reader/writer spin lock](https://learn.microsoft.com/en-us/windows-hardware/drivers/kernel/reader-writer-spin-locks)
//! (`EX_SPIN_LOCK`): a `LONG` of the driver's memory.
//!
//! The word, read from the kernel NK follows (10.0.19041): bit 31 is the
//! writer's, set from the moment one claims the lock; the low thirty
//! bits count the readers inside. A writer that has claimed the lock
//! waits for the readers to leave, and new readers wait for the writer.
//! Bit 30 is a note that somebody is spinning for the lock; a reader
//! clears it as it leaves, and a writer's release clears the word.

/// Bit 31: a writer holds the lock, or has claimed it and waits for the
/// readers inside to leave.
pub const EXCLUSIVE: u32 = 0x8000_0000;
/// Bit 30: somebody is spinning for the lock.
pub const CONTENDED: u32 = 0x4000_0000;

/// `ExAcquireSpinLockShared`: the word with one more reader, or `None`
/// while a writer has the lock or has claimed it.
pub fn enter_shared(word: u32) -> Option<u32> {
    (word & EXCLUSIVE == 0).then(|| word + 1)
}

/// Whether a writer that has set [`EXCLUSIVE`] now has the lock to
/// itself: the readers have left.
pub fn exclusive_alone(word: u32) -> bool {
    word & !CONTENDED == EXCLUSIVE
}

/// The word with the note that somebody is spinning; `None` if it says
/// so already.
pub fn note_contended(word: u32) -> Option<u32> {
    (word & CONTENDED == 0).then_some(word | CONTENDED)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn readers_share_and_wait_for_a_writer() {
        assert_eq!(enter_shared(0), Some(1));
        assert_eq!(enter_shared(1), Some(2));
        assert_eq!(enter_shared(CONTENDED | 2), Some(CONTENDED | 3));
        assert_eq!(enter_shared(EXCLUSIVE), None);
        assert_eq!(enter_shared(EXCLUSIVE | 1), None);
        assert_eq!(enter_shared(EXCLUSIVE | CONTENDED), None);
    }

    #[test]
    fn a_writer_waits_for_the_readers_inside() {
        assert!(exclusive_alone(EXCLUSIVE));
        assert!(exclusive_alone(EXCLUSIVE | CONTENDED));
        assert!(!exclusive_alone(EXCLUSIVE | 1));
        assert!(!exclusive_alone(EXCLUSIVE | CONTENDED | 3));
        assert!(!exclusive_alone(0));
        assert!(!exclusive_alone(2));
    }

    #[test]
    fn spinning_is_noted_once() {
        assert_eq!(
            note_contended(EXCLUSIVE | 1),
            Some(EXCLUSIVE | CONTENDED | 1)
        );
        assert_eq!(note_contended(EXCLUSIVE | CONTENDED | 1), None);
    }
}
