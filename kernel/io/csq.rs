//! Cancel-safe queues: `IoCsqInitialize`, `IoCsqInsertIrp`,
//! `IoCsqRemoveNextIrp`.
//!
//! A driver that holds requests must let each be cancelled, and the
//! race between cancelling one and taking it off the queue is easy to
//! get wrong. Here the driver supplies only a queue and a lock, as
//! callbacks; the I/O manager sets and clears the cancel routine around
//! them. See [Cancel-Safe IRP Queues](https://learn.microsoft.com/en-us/windows-hardware/drivers/kernel/cancel-safe-irp-queues).
//!
//! While a request is queued, its fourth driver-context pointer names
//! the queue, or the caller's `IO_CSQ_IRP_CONTEXT` if it gave one; the
//! two are told apart by their first field.

#![allow(non_snake_case)]

use super::irp::IoReleaseCancelSpinLock;
use crate::ke::seh::{self, Guard};
use core::ffi::c_void;
use core::sync::atomic::{AtomicPtr, Ordering};
use nk_ntabi::io::*;
use nk_ntabi::status::*;

/// The request's cancel routine slot, to be changed in one step
/// (`IoSetCancelRoutine`).
///
/// # Safety
/// `irp` is a live IRP.
unsafe fn cancel_routine<'a>(irp: *mut IRP) -> &'a AtomicPtr<c_void> {
    // SAFETY: per the contract.
    unsafe { AtomicPtr::from_ptr(&raw mut (*irp).CancelRoutine) }
}

/// Forget that `irp` is queued: clear its context pointer and, if the
/// caller gave a context block, that block's pointer to the request.
///
/// # Safety
/// `irp` is a live IRP that a queue's insert marked.
unsafe fn unmark(irp: *mut IRP) {
    // SAFETY: per the contract: the pointer names a queue or a context
    // block, both of which start with their type.
    unsafe {
        let slot = &raw mut (*irp).DriverContext[3];
        let marked = slot.read();
        if !marked.is_null() && marked.cast::<u32>().read() == IO_TYPE_CSQ_IRP_CONTEXT {
            (&raw mut (*marked.cast::<IO_CSQ_IRP_CONTEXT>()).Irp).write(core::ptr::null_mut());
        }
        slot.write(core::ptr::null_mut());
    }
}

/// [`IoCsqInitialize`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-iocsqinitialize).
///
/// # Safety
/// `csq` is writable for an `IO_CSQ`.
pub unsafe extern "C" fn IoCsqInitialize(
    csq: *mut IO_CSQ,
    insert: CSQ_INSERT,
    remove: CSQ_REMOVE,
    peek: CSQ_PEEK,
    acquire: CSQ_ACQUIRE,
    release: CSQ_RELEASE,
    complete: CSQ_COMPLETE,
) -> NTSTATUS {
    // SAFETY: per the contract.
    unsafe {
        csq.write_unaligned(IO_CSQ {
            Type: IO_TYPE_CSQ,
            CsqInsertIrp: Some(insert),
            CsqRemoveIrp: Some(remove),
            CsqPeekNextIrp: Some(peek),
            CsqAcquireLock: Some(acquire),
            CsqReleaseLock: Some(release),
            CsqCompleteCanceledIrp: Some(complete),
            ReservePointer: core::ptr::null_mut(),
        });
    }
    STATUS_SUCCESS
}

/// The queue's callbacks, read out of the driver's structure.
struct Callbacks {
    insert: CSQ_INSERT,
    remove: CSQ_REMOVE,
    peek: CSQ_PEEK,
    acquire: CSQ_ACQUIRE,
    release: CSQ_RELEASE,
    complete: CSQ_COMPLETE,
}

/// Each calls the driver's callback. The I/O manager holds nothing of
/// its own across one (the queue's lock is the driver's, taken and
/// released by its callbacks), so an unwind through it owes nothing.
impl Callbacks {
    /// # Safety
    /// `routine` is one of the queue's callbacks and `args` are what it
    /// takes.
    unsafe fn call(routine: usize, args: [usize; 4]) -> usize {
        // SAFETY: per the contract.
        unsafe { seh::call(routine, args, &Guard::Nothing) }
    }

    /// # Safety
    /// As the driver's `CsqInsertIrp`.
    unsafe fn insert(&self, csq: *mut IO_CSQ, irp: *mut IRP) {
        // SAFETY: per the contract.
        unsafe { Self::call(self.insert as usize, [csq.addr(), irp.addr(), 0, 0]) };
    }

    /// # Safety
    /// As the driver's `CsqRemoveIrp`.
    unsafe fn remove(&self, csq: *mut IO_CSQ, irp: *mut IRP) {
        // SAFETY: per the contract.
        unsafe { Self::call(self.remove as usize, [csq.addr(), irp.addr(), 0, 0]) };
    }

    /// # Safety
    /// As the driver's `CsqPeekNextIrp`.
    unsafe fn peek(&self, csq: *mut IO_CSQ, irp: *mut IRP, context: *mut c_void) -> *mut IRP {
        // SAFETY: per the contract.
        let next = unsafe {
            Self::call(
                self.peek as usize,
                [csq.addr(), irp.addr(), context.addr(), 0],
            )
        };
        next as *mut IRP
    }

    /// # Safety
    /// As the driver's `CsqAcquireLock`.
    unsafe fn acquire(&self, csq: *mut IO_CSQ, irql: *mut u8) {
        // SAFETY: per the contract.
        unsafe { Self::call(self.acquire as usize, [csq.addr(), irql.addr(), 0, 0]) };
    }

    /// # Safety
    /// As the driver's `CsqReleaseLock`.
    unsafe fn release(&self, csq: *mut IO_CSQ, irql: u8) {
        // SAFETY: per the contract.
        unsafe { Self::call(self.release as usize, [csq.addr(), usize::from(irql), 0, 0]) };
    }

    /// # Safety
    /// As the driver's `CsqCompleteCanceledIrp`.
    unsafe fn complete(&self, csq: *mut IO_CSQ, irp: *mut IRP) {
        // SAFETY: per the contract.
        unsafe { Self::call(self.complete as usize, [csq.addr(), irp.addr(), 0, 0]) };
    }
}

/// # Safety
/// `csq` is a queue set up by `IoCsqInitialize`.
unsafe fn callbacks(csq: *mut IO_CSQ) -> Callbacks {
    // SAFETY: per the contract.
    let queue = unsafe { csq.read_unaligned() };
    let (Some(insert), Some(remove), Some(peek), Some(acquire), Some(release), Some(complete)) = (
        queue.CsqInsertIrp,
        queue.CsqRemoveIrp,
        queue.CsqPeekNextIrp,
        queue.CsqAcquireLock,
        queue.CsqReleaseLock,
        queue.CsqCompleteCanceledIrp,
    ) else {
        crate::kd::bugcheck(format_args!(
            "IoCsq: {csq:p} is not an initialized cancel-safe queue"
        ));
    };
    Callbacks {
        insert,
        remove,
        peek,
        acquire,
        release,
        complete,
    }
}

/// The cancel routine of every queued request. Entered with the cancel
/// spin lock held.
///
/// # Safety
/// Called by `IoCancelIrp`, for a request `IoCsqInsertIrp` queued.
unsafe extern "C" fn cancelled(_device: *mut DEVICE_OBJECT, irp: *mut IRP) {
    // SAFETY: called by `IoCancelIrp` for a request `IoCsqInsertIrp`
    // queued: its context pointer names the queue, or a context block
    // that does. The queue's lock is what excludes the insert and the
    // removal; the cancel lock is not needed and is let go first.
    unsafe {
        IoReleaseCancelSpinLock((*irp).CancelIrql);
        let marked = (*irp).DriverContext[3];
        let csq = if marked.cast::<u32>().read() == IO_TYPE_CSQ_IRP_CONTEXT {
            (*marked.cast::<IO_CSQ_IRP_CONTEXT>()).Csq
        } else {
            marked.cast::<IO_CSQ>()
        };
        let queue = callbacks(csq);
        let mut irql = 0;
        queue.acquire(csq, &raw mut irql);
        queue.remove(csq, irp);
        unmark(irp);
        queue.release(csq, irql);
        queue.complete(csq, irp);
    }
}

/// [`IoCsqInsertIrp`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-iocsqinsertirp):
/// queue a request, mark it pending and make it cancellable. A request
/// already cancelled is taken straight off again and completed as
/// cancelled.
///
/// # Safety
/// `csq` is an initialized queue; `irp` a request being dispatched to
/// the caller; `context` null or writable for an `IO_CSQ_IRP_CONTEXT`.
pub unsafe extern "C" fn IoCsqInsertIrp(
    csq: *mut IO_CSQ,
    irp: *mut IRP,
    context: *mut IO_CSQ_IRP_CONTEXT,
) {
    // SAFETY: per the contract.
    unsafe {
        let queue = callbacks(csq);
        if context.is_null() {
            (*irp).DriverContext[3] = csq.cast();
        } else {
            context.write_unaligned(IO_CSQ_IRP_CONTEXT {
                Type: IO_TYPE_CSQ_IRP_CONTEXT,
                Irp: irp,
                Csq: csq,
            });
            (*irp).DriverContext[3] = context.cast();
        }
        let mut irql = 0;
        queue.acquire(csq, &raw mut irql);
        queue.insert(csq, irp);
        // `IoMarkIrpPending`.
        (*(*irp).CurrentStackLocation).Control |= SL_PENDING_RETURNED;
        // Install the routine, then look at the cancel flag; the
        // canceller sets the flag, then looks for the routine. Each
        // must see the other's write if it came first, so both sides
        // use sequentially consistent operations: with anything weaker
        // each can miss the other, and a cancelled request stays
        // queued for good.
        cancel_routine(irp).swap(cancelled as *mut c_void, Ordering::SeqCst);
        // Cancelled before the routine was in place? Then nobody will
        // call it: if it can still be taken back out, the request is
        // this call's to complete. If it cannot, the canceller has it
        // and waits for the queue's lock.
        if super::irp::cancel_flag(irp).load(Ordering::SeqCst) != 0
            && !cancel_routine(irp)
                .swap(core::ptr::null_mut(), Ordering::SeqCst)
                .is_null()
        {
            queue.remove(csq, irp);
            unmark(irp);
            queue.release(csq, irql);
            queue.complete(csq, irp);
        } else {
            queue.release(csq, irql);
        }
    }
}

/// [`IoCsqRemoveNextIrp`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-iocsqremovenextirp):
/// take the first request off the queue that matches `peek_context`
/// and is not being cancelled; null if there is none.
///
/// # Safety
/// `csq` is an initialized queue.
pub unsafe extern "C" fn IoCsqRemoveNextIrp(
    csq: *mut IO_CSQ,
    peek_context: *mut c_void,
) -> *mut IRP {
    // SAFETY: per the contract; requests the queue's peek returns are
    // live while the queue's lock is held.
    unsafe {
        let queue = callbacks(csq);
        let mut irql = 0;
        queue.acquire(csq, &raw mut irql);
        let mut irp = core::ptr::null_mut();
        loop {
            irp = queue.peek(csq, irp, peek_context);
            if irp.is_null() {
                break;
            }
            // Its cancel routine already taken: it is being cancelled,
            // and belongs to the canceller.
            if cancel_routine(irp)
                .swap(core::ptr::null_mut(), Ordering::AcqRel)
                .is_null()
            {
                continue;
            }
            queue.remove(csq, irp);
            unmark(irp);
            break;
        }
        queue.release(csq, irql);
        irp
    }
}

/// The WDM version this kernel implements: that of Windows 10.
const WDM_VERSION: (u8, u8) = (6, 0);

/// [`IoIsWdmVersionAvailable`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-ioiswdmversionavailable):
/// whether the kernel offers at least the given WDM version.
pub extern "C" fn IoIsWdmVersionAvailable(major: u8, minor: u8) -> u8 {
    u8::from((major, minor) <= WDM_VERSION)
}
