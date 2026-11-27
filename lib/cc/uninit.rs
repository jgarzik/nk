//! `CcUninitializeCacheMap`'s decision, read from the pinned kernel:
//! once a file object's private cache map is gone, is the file's shared
//! cache map deleted now, or left for the lazy writer to flush and
//! delete (lazy close)? And when is the caller's event signalled?

/// What the decision looks at, after the private cache map is unlinked
/// and the open count dropped.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct State {
    /// Private cache maps left.
    pub open_count: u32,
    pub dirty_pages: u64,
    /// A write-behind is queued for the file.
    pub write_queued: bool,
    /// The file was cached with `PinAccess`.
    pub pin_access: bool,
    /// The caller passed a truncate size.
    pub truncate: bool,
}

/// What becomes of the shared cache map.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Outcome {
    /// Deleted in this call: the routine returns TRUE and signals the
    /// event at once.
    DeleteNow,
    /// Left on the dirty list for the lazy writer, which deletes it if
    /// it is still unused once flushed; the event waits for that.
    Lazy,
    /// Still open through other file objects: nothing more happens,
    /// and the event waits for the deletion.
    Open,
}

/// The decision: deleted now only when no file object has it open, it
/// holds no dirty data, no write-behind is queued, and it was cached for
/// pinning or is being truncated.
pub fn decide(s: &State) -> Outcome {
    if s.open_count != 0 {
        Outcome::Open
    } else if s.dirty_pages == 0 && !s.write_queued && (s.pin_access || s.truncate) {
        Outcome::DeleteNow
    } else {
        Outcome::Lazy
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const CLOSED_PINNED: State = State {
        open_count: 0,
        dirty_pages: 0,
        write_queued: false,
        pin_access: true,
        truncate: false,
    };

    #[test]
    fn the_table() {
        assert_eq!(decide(&CLOSED_PINNED), Outcome::DeleteNow);
        assert_eq!(
            decide(&State {
                open_count: 1,
                ..CLOSED_PINNED
            }),
            Outcome::Open
        );
        assert_eq!(
            decide(&State {
                dirty_pages: 1,
                ..CLOSED_PINNED
            }),
            Outcome::Lazy
        );
        assert_eq!(
            decide(&State {
                write_queued: true,
                ..CLOSED_PINNED
            }),
            Outcome::Lazy
        );
        let copy = State {
            pin_access: false,
            ..CLOSED_PINNED
        };
        assert_eq!(
            decide(&copy),
            Outcome::Lazy,
            "a file cached for copying closes lazily"
        );
        assert_eq!(
            decide(&State {
                truncate: true,
                ..copy
            }),
            Outcome::DeleteNow
        );
        assert_eq!(
            decide(&State {
                truncate: true,
                dirty_pages: 3,
                ..copy
            }),
            Outcome::Lazy
        );
    }
}
