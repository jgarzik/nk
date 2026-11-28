//! The rules of kernel APCs, as Windows' `KiSignalThreadForApc` and
//! `KiDeliverApc` apply them: what queueing an APC does to its thread,
//! and which queued APC may run next. The kernel (`kernel/ke/apc.rs`)
//! reads the thread's counters, asks, and acts.

/// The counters of a thread that decide whether its kernel APCs run.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Disables {
    /// `KernelApcDisable`: negative inside a critical region.
    pub kernel: i16,
    /// `SpecialApcDisable`: negative inside a guarded region.
    pub special: i16,
    /// `ApcState.InProgressFlags`: a kernel APC is being delivered.
    pub in_progress: u8,
}

/// Where the thread an APC was queued to stands.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Place {
    /// It is the thread queueing the APC.
    Current,
    /// It runs on another processor.
    Running,
    /// It waits, having entered the wait at this IRQL.
    Waiting(u8),
    /// Ready, being created, or anything else: it looks at its APCs when
    /// it next gets a processor.
    Elsewhere,
}

/// What queueing a kernel APC does to its thread.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Signal {
    /// Nothing: the APC waits in the queue until a region is left.
    Nothing,
    /// Mark kernel APCs pending; the thread finds them when it next runs.
    Pending,
    /// Mark them pending and interrupt this processor at `APC_LEVEL`:
    /// they run when its IRQL falls below that.
    Interrupt,
    /// Mark them pending and interrupt the thread's processor.
    InterruptOther,
    /// Mark them pending and end the thread's wait with
    /// `STATUS_KERNEL_APC`: it delivers them and waits again.
    Unwait,
}

/// What queueing a kernel APC (`special`: one without a normal routine)
/// does to a thread with counters `d` standing at `place`.
pub fn signal(d: Disables, special: bool, place: Place) -> Signal {
    match place {
        Place::Current => {
            if (d.kernel == 0 && d.special == 0) || (special && d.special == 0) {
                Signal::Interrupt
            } else {
                Signal::Nothing
            }
        }
        Place::Running => Signal::InterruptOther,
        Place::Waiting(0)
            if d.special == 0 && (special || (d.kernel == 0 && d.in_progress == 0)) =>
        {
            Signal::Unwait
        }
        Place::Waiting(_) | Place::Elsewhere => Signal::Pending,
    }
}

/// What delivery does with the APC at the head of the kernel queue.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Step {
    /// Run its kernel routine (a special APC), and look again.
    Special,
    /// Run its kernel routine and then its normal routine, and look again.
    Normal,
    /// Leave it, and the rest of the queue, for later.
    Stop,
}

/// What delivery does with the head of the kernel queue: special APCs
/// are queued ahead of normal ones and run unless a guarded region
/// forbids; a normal one waits while another kernel APC is in progress
/// or the thread is in a critical region.
pub fn step(d: Disables, head_is_special: bool) -> Step {
    if d.special != 0 {
        Step::Stop
    } else if head_is_special {
        Step::Special
    } else if d.in_progress != 0 || d.kernel != 0 {
        Step::Stop
    } else {
        Step::Normal
    }
}

/// `KeAreAllApcsDisabled`: no APC of any kind can run now.
pub fn all_disabled(special_disable: i16, interrupts_enabled: bool, irql: u8) -> bool {
    special_disable != 0 || !interrupts_enabled || irql >= 1
}

#[cfg(test)]
mod tests {
    use super::*;

    const FREE: Disables = Disables {
        kernel: 0,
        special: 0,
        in_progress: 0,
    };
    const CRITICAL: Disables = Disables { kernel: -1, ..FREE };
    const GUARDED: Disables = Disables {
        special: -1,
        ..FREE
    };
    const BUSY: Disables = Disables {
        in_progress: 1,
        ..FREE
    };

    #[test]
    fn queued_to_the_current_thread() {
        assert_eq!(signal(FREE, false, Place::Current), Signal::Interrupt);
        assert_eq!(signal(FREE, true, Place::Current), Signal::Interrupt);
        // A critical region holds back normal APCs, not special ones.
        assert_eq!(signal(CRITICAL, false, Place::Current), Signal::Nothing);
        assert_eq!(signal(CRITICAL, true, Place::Current), Signal::Interrupt);
        // A guarded region holds back both.
        assert_eq!(signal(GUARDED, true, Place::Current), Signal::Nothing);
        assert_eq!(signal(GUARDED, false, Place::Current), Signal::Nothing);
    }

    #[test]
    fn queued_to_another_thread() {
        assert_eq!(
            signal(GUARDED, false, Place::Running),
            Signal::InterruptOther
        );
        assert_eq!(signal(FREE, false, Place::Elsewhere), Signal::Pending);
        assert_eq!(signal(FREE, false, Place::Waiting(0)), Signal::Unwait);
        assert_eq!(signal(FREE, true, Place::Waiting(0)), Signal::Unwait);
        // A wait entered at APC_LEVEL is not interrupted.
        assert_eq!(signal(FREE, true, Place::Waiting(1)), Signal::Pending);
        assert_eq!(signal(CRITICAL, true, Place::Waiting(0)), Signal::Unwait);
        assert_eq!(signal(CRITICAL, false, Place::Waiting(0)), Signal::Pending);
        assert_eq!(signal(BUSY, false, Place::Waiting(0)), Signal::Pending);
        assert_eq!(signal(BUSY, true, Place::Waiting(0)), Signal::Unwait);
        assert_eq!(signal(GUARDED, true, Place::Waiting(0)), Signal::Pending);
    }

    #[test]
    fn delivery_order() {
        assert_eq!(step(FREE, true), Step::Special);
        assert_eq!(step(FREE, false), Step::Normal);
        assert_eq!(step(CRITICAL, true), Step::Special);
        assert_eq!(step(CRITICAL, false), Step::Stop);
        assert_eq!(step(BUSY, true), Step::Special);
        assert_eq!(step(BUSY, false), Step::Stop);
        assert_eq!(step(GUARDED, true), Step::Stop);
        assert_eq!(step(GUARDED, false), Step::Stop);
    }

    #[test]
    fn all_apcs_disabled() {
        assert!(!all_disabled(0, true, 0));
        assert!(all_disabled(-1, true, 0));
        assert!(all_disabled(0, false, 0));
        assert!(all_disabled(0, true, 1));
        assert!(all_disabled(0, true, 2));
    }
}
