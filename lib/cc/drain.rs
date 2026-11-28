//! Shutdown dirty-cache drain policy: bounded retries without progress,
//! immediate termination on permanent/fatal write errors, and summary
//! accounting independent of each map's dirty state.

/// Total attempts without forward progress before a map's shutdown drain
/// is declared a terminal failure.
pub const MAX_NO_PROGRESS_ATTEMPTS: u8 = 3;

/// Per-map shutdown drain tracking, kept independently of the map's
/// dirty bitmap and BCBs so unsuccessful writeback never clears dirty
/// bits.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct MapDrainState {
    generation: u32,
    no_progress: u8,
    terminal: bool,
    last_status: i32,
}

/// The result of one write-behind attempt on a map during a shutdown
/// drain.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Attempt {
    /// A flush ran on the map.
    Write {
        dirty_before: u64,
        dirty_after: u64,
        status: i32,
        fatal: bool,
    },
    /// `AcquireForLazyWrite` returned FALSE before a flush could run.
    AcquireFailed { dirty: u64, status: i32 },
}

/// How the drain state advances after an [`Attempt`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Outcome {
    /// No shutdown drain is active (`generation == 0`).
    Inactive,
    /// The map now has zero dirty pages.
    Clean,
    /// Some dirty pages remain, but the attempt reduced them.
    Progress,
    /// No forward progress was made, but retries remain.
    Retry { attempts: u8 },
    /// The map is terminally failed for this shutdown drain generation
    /// (either a permanent/fatal error or `MAX_NO_PROGRESS_ATTEMPTS`
    /// attempts without progress).
    Terminal {
        status: i32,
        attempts: u8,
        remaining_dirty: u64,
    },
}

/// Final summary of a shutdown dirty-cache drain.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct DrainSummary {
    /// Number of `SCAN_ROOM`-bounded scan batches dispatched.
    pub batches: u32,
    /// Number of maps whose dirty data drained cleanly.
    pub maps_flushed: u32,
    /// Total dirty pages successfully written across all batches.
    pub pages_written: u64,
    /// Number of maps that ended in terminal failure.
    pub failed_maps: u32,
    /// Dirty pages still remaining on terminal maps at drain completion.
    pub remaining_dirty_pages: u64,
}

impl MapDrainState {
    pub const fn new() -> Self {
        Self {
            generation: 0,
            no_progress: 0,
            terminal: false,
            last_status: 0,
        }
    }

    /// Whether this map has already reached terminal failure in
    /// `generation`.
    pub fn is_terminal(&self, generation: u32) -> bool {
        generation != 0 && self.generation == generation && self.terminal
    }

    /// The last error status observed during the active drain.
    pub fn last_status(&self) -> i32 {
        self.last_status
    }

    /// Consecutive no-progress attempts recorded in the active drain.
    pub fn no_progress(&self) -> u8 {
        self.no_progress
    }

    /// Advance this map's state for `generation` given `attempt`.
    pub fn record(&mut self, generation: u32, attempt: Attempt) -> Outcome {
        if generation == 0 {
            return Outcome::Inactive;
        }
        if self.generation != generation {
            self.generation = generation;
            self.no_progress = 0;
            self.terminal = false;
            self.last_status = 0;
        }
        match attempt {
            Attempt::AcquireFailed { dirty, status } => {
                if dirty == 0 {
                    self.no_progress = 0;
                    return Outcome::Clean;
                }
                self.no_progress = self.no_progress.saturating_add(1);
                self.last_status = status;
                if self.no_progress >= MAX_NO_PROGRESS_ATTEMPTS {
                    self.terminal = true;
                    Outcome::Terminal {
                        status,
                        attempts: self.no_progress,
                        remaining_dirty: dirty,
                    }
                } else {
                    Outcome::Retry {
                        attempts: self.no_progress,
                    }
                }
            }
            Attempt::Write {
                dirty_before,
                dirty_after,
                status,
                fatal,
            } => {
                if fatal {
                    self.no_progress = self.no_progress.saturating_add(1);
                    self.terminal = true;
                    self.last_status = status;
                    return Outcome::Terminal {
                        status,
                        attempts: self.no_progress,
                        remaining_dirty: dirty_after,
                    };
                }
                if dirty_after == 0 {
                    self.no_progress = 0;
                    return Outcome::Clean;
                }
                if dirty_after < dirty_before {
                    self.no_progress = 0;
                    if status < 0 {
                        self.last_status = status;
                    }
                    return Outcome::Progress;
                }
                self.no_progress = self.no_progress.saturating_add(1);
                self.last_status = status;
                if self.no_progress >= MAX_NO_PROGRESS_ATTEMPTS {
                    self.terminal = true;
                    Outcome::Terminal {
                        status,
                        attempts: self.no_progress,
                        remaining_dirty: dirty_after,
                    }
                } else {
                    Outcome::Retry {
                        attempts: self.no_progress,
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const RETRYABLE: i32 = 0xC000_009A_u32 as i32; // STATUS_INSUFFICIENT_RESOURCES
    const FATAL: i32 = 0xC000_00A2_u32 as i32; // STATUS_MEDIA_WRITE_PROTECTED
    const LOCK_BUSY: i32 = 0xC000_0054_u32 as i32; // STATUS_FILE_LOCK_CONFLICT

    #[test]
    fn inactive_generation_does_not_mutate_state() {
        let mut s = MapDrainState::new();
        assert_eq!(
            s.record(
                0,
                Attempt::Write {
                    dirty_before: 4,
                    dirty_after: 4,
                    status: RETRYABLE,
                    fatal: false,
                }
            ),
            Outcome::Inactive
        );
        assert!(!s.is_terminal(0));
        assert!(!s.is_terminal(1));
        assert_eq!(s.no_progress(), 0);
        assert_eq!(s.last_status(), 0);
    }

    #[test]
    fn transient_retryable_errors_recover_within_bound() {
        let mut s = MapDrainState::new();
        for expected in 1..=2 {
            assert_eq!(
                s.record(
                    1,
                    Attempt::Write {
                        dirty_before: 2,
                        dirty_after: 2,
                        status: RETRYABLE,
                        fatal: false,
                    }
                ),
                Outcome::Retry { attempts: expected }
            );
            assert!(!s.is_terminal(1));
            assert_eq!(s.no_progress(), expected);
            assert_eq!(s.last_status(), RETRYABLE);
        }
        assert_eq!(
            s.record(
                1,
                Attempt::Write {
                    dirty_before: 2,
                    dirty_after: 0,
                    status: 0,
                    fatal: false,
                }
            ),
            Outcome::Clean
        );
        assert!(!s.is_terminal(1));
        assert_eq!(s.no_progress(), 0);
    }

    #[test]
    fn persistent_retryable_error_terminates_after_three_attempts() {
        let mut s = MapDrainState::new();
        assert_eq!(
            s.record(
                1,
                Attempt::Write {
                    dirty_before: 3,
                    dirty_after: 3,
                    status: RETRYABLE,
                    fatal: false,
                }
            ),
            Outcome::Retry { attempts: 1 }
        );
        assert_eq!(
            s.record(
                1,
                Attempt::Write {
                    dirty_before: 3,
                    dirty_after: 3,
                    status: RETRYABLE,
                    fatal: false,
                }
            ),
            Outcome::Retry { attempts: 2 }
        );
        assert_eq!(
            s.record(
                1,
                Attempt::Write {
                    dirty_before: 3,
                    dirty_after: 3,
                    status: RETRYABLE,
                    fatal: false,
                }
            ),
            Outcome::Terminal {
                status: RETRYABLE,
                attempts: 3,
                remaining_dirty: 3,
            }
        );
        assert!(s.is_terminal(1));
        // A new drain generation resets prior terminal status.
        assert!(!s.is_terminal(2));
        assert_eq!(
            s.record(
                2,
                Attempt::Write {
                    dirty_before: 3,
                    dirty_after: 0,
                    status: 0,
                    fatal: false,
                }
            ),
            Outcome::Clean
        );
        assert!(!s.is_terminal(2));
    }

    #[test]
    fn partial_write_progress_resets_no_progress_counter() {
        let mut s = MapDrainState::new();
        assert_eq!(
            s.record(
                1,
                Attempt::Write {
                    dirty_before: 4,
                    dirty_after: 4,
                    status: RETRYABLE,
                    fatal: false,
                }
            ),
            Outcome::Retry { attempts: 1 }
        );
        assert_eq!(
            s.record(
                1,
                Attempt::Write {
                    dirty_before: 4,
                    dirty_after: 4,
                    status: RETRYABLE,
                    fatal: false,
                }
            ),
            Outcome::Retry { attempts: 2 }
        );
        // Partial progress reduces dirty pages from 4 to 2 -> resets counter.
        assert_eq!(
            s.record(
                1,
                Attempt::Write {
                    dirty_before: 4,
                    dirty_after: 2,
                    status: RETRYABLE,
                    fatal: false,
                }
            ),
            Outcome::Progress
        );
        assert_eq!(s.no_progress(), 0);
        assert!(!s.is_terminal(1));
        // Three subsequent no-progress attempts are now allowed before terminal.
        assert_eq!(
            s.record(
                1,
                Attempt::Write {
                    dirty_before: 2,
                    dirty_after: 2,
                    status: RETRYABLE,
                    fatal: false,
                }
            ),
            Outcome::Retry { attempts: 1 }
        );
        assert_eq!(
            s.record(
                1,
                Attempt::Write {
                    dirty_before: 2,
                    dirty_after: 2,
                    status: RETRYABLE,
                    fatal: false,
                }
            ),
            Outcome::Retry { attempts: 2 }
        );
        assert_eq!(
            s.record(
                1,
                Attempt::Write {
                    dirty_before: 2,
                    dirty_after: 2,
                    status: RETRYABLE,
                    fatal: false,
                }
            ),
            Outcome::Terminal {
                status: RETRYABLE,
                attempts: 3,
                remaining_dirty: 2,
            }
        );
        assert!(s.is_terminal(1));
    }

    #[test]
    fn fatal_error_terminates_immediately_without_retries() {
        let mut s = MapDrainState::new();
        assert_eq!(
            s.record(
                1,
                Attempt::Write {
                    dirty_before: 5,
                    dirty_after: 0,
                    status: FATAL,
                    fatal: true,
                }
            ),
            Outcome::Terminal {
                status: FATAL,
                attempts: 1,
                remaining_dirty: 0,
            }
        );
        assert!(s.is_terminal(1));
        assert_eq!(s.last_status(), FATAL);
    }

    #[test]
    fn acquire_failures_bound_retries_and_clean_when_zero() {
        let mut s = MapDrainState::new();
        assert_eq!(
            s.record(
                1,
                Attempt::AcquireFailed {
                    dirty: 0,
                    status: LOCK_BUSY,
                }
            ),
            Outcome::Clean
        );
        assert_eq!(
            s.record(
                1,
                Attempt::AcquireFailed {
                    dirty: 2,
                    status: LOCK_BUSY,
                }
            ),
            Outcome::Retry { attempts: 1 }
        );
        assert_eq!(
            s.record(
                1,
                Attempt::AcquireFailed {
                    dirty: 2,
                    status: LOCK_BUSY,
                }
            ),
            Outcome::Retry { attempts: 2 }
        );
        assert_eq!(
            s.record(
                1,
                Attempt::AcquireFailed {
                    dirty: 2,
                    status: LOCK_BUSY,
                }
            ),
            Outcome::Terminal {
                status: LOCK_BUSY,
                attempts: 3,
                remaining_dirty: 2,
            }
        );
        assert!(s.is_terminal(1));
    }
}
