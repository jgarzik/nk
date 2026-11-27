//! Tests of requests a driver makes of another driver: built for it by
//! the I/O manager (`IoBuildSynchronousFsdRequest`,
//! `IoBuildDeviceIoControlRequest`), or its own IRP, sent and waited
//! for (`IoSynchronousCallDriver`), used again (`IoReuseIrp`) or laid
//! out in its own memory (`IoInitializeIrp`); and of what goes with
//! them: cancelling a built request, a split request's master status,
//! a partial MDL, a reference by pointer.
//!
//! The requests go through the three-driver stack of `stack`, sent by
//! the test as a driver above it would send them.

use super::stack::{self, ECHO, HOLD, PDO, PEND, PENDED_OFFSET, Stack};
use crate::io::{build, device, irp, mdl};
use crate::ke::{irql, wait};
use crate::mm::pool;
use crate::ob::object::{self, ObRef};
use crate::test::{Group, Report};
use core::ffi::c_void;
use core::sync::atomic::Ordering;
use nk_bootinfo::BootInfo;
use nk_ntabi::io::*;
use nk_ntabi::status::*;

pub static GROUP: Group = Group {
    names: &[
        "io.request.synchronous-fsd",
        "io.request.device-control",
        "io.request.synchronous-call",
        "io.request.cancel-built",
        "io.request.master-status",
        "io.request.power",
        "io.mdl.partial",
        "ob.reference-by-pointer",
    ],
    run,
    manual: false,
};

pub static GROUPS: &[&Group] = &[&GROUP];

const TAG: u32 = u32::from_le_bytes(*b"Test");

/// Where a built request's results go, and what is set when they are
/// there: the sender's, on its stack, as a driver has them.
struct Sender {
    event: KEVENT,
    status_block: IO_STATUS_BLOCK,
}

impl Sender {
    fn new() -> Self {
        Self {
            // SAFETY: an all-zero event is a valid value; `arm`
            // initialises it before each use.
            event: unsafe { core::mem::zeroed() },
            status_block: IO_STATUS_BLOCK {
                Status: STATUS_PENDING,
                Information: 0,
            },
        }
    }

    /// Ready for a request: `KeInitializeEvent(NotificationEvent, FALSE)`.
    fn arm(&mut self) -> (*mut KEVENT, *mut IO_STATUS_BLOCK) {
        self.status_block = IO_STATUS_BLOCK {
            Status: STATUS_PENDING,
            Information: usize::MAX,
        };
        // SAFETY: the sender's own event, which nothing waits on.
        unsafe { wait::KeInitializeEvent(&raw mut self.event, 0, 0) };
        (&raw mut self.event, &raw mut self.status_block)
    }

    /// Send a built request to `top` and wait for it, as the callers of
    /// the `IoBuild` routines do: `IoCallDriver`, and a wait on the
    /// event if the request is pending. Returns its status and count,
    /// and whether it was pended.
    ///
    /// # Safety
    /// `request` was built for `top`'s stack with this sender's event
    /// and status block, which `arm` handed out.
    unsafe fn send(
        &mut self,
        top: *mut DEVICE_OBJECT,
        request: *mut IRP,
    ) -> Result<(NTSTATUS, usize, bool), &'static str> {
        // SAFETY: per the contract.
        unsafe {
            let status = irp::IofCallDriver(top, request);
            let pended = status == STATUS_PENDING;
            if pended {
                wait::wait(Some((&raw mut self.event).cast()), None);
            } else if wait::KeReadStateEvent(&raw mut self.event) == 0 {
                return Err("a built request completed without its event being set");
            }
            let block = (&raw const self.status_block).read_volatile();
            if !pended && block.Status != status {
                return Err("the status block does not hold the status the request completed with");
            }
            Ok((block.Status, block.Information, pended))
        }
    }
}

/// How the devices of the stack ask for a transfer's buffer.
fn set_transfer_method(stack: &Stack, flags: u32) {
    for device in stack.devices {
        // SAFETY: live devices of the test's, with no request under
        // way.
        unsafe {
            (*device).Flags = (*device).Flags & !(DO_BUFFERED_IO | DO_DIRECT_IO) | flags;
        }
    }
}

/// The top of the stack, with the reference a driver holds while it
/// sends requests there.
struct Top(ObRef);

impl Top {
    fn of(stack: &Stack) -> Self {
        // SAFETY: a live device of the test's; the reference is the
        // caller's.
        Self(unsafe {
            ObRef::adopt(device::IoGetAttachedDeviceReference(stack.devices[PDO as usize]).cast())
        })
    }

    fn device(&self) -> *mut DEVICE_OBJECT {
        self.0.cast()
    }
}

/// `IoBuildSynchronousFsdRequest`: a read and a write, completed at
/// once and pended, reach the bottom of the stack with their length,
/// offset and data the way the device asks for them (buffered, direct,
/// neither) and come back through the caller's status block, buffer
/// and event; a request with no transfer carries no buffer. The I/O
/// manager frees each. Returns the requests sent.
fn synchronous_fsd() -> Result<u32, &'static str> {
    const LEN: usize = 96;
    let stack = Stack::build()?;
    let top = Top::of(&stack);
    let mut sender = Sender::new();
    let mut sent = 0;
    let blocks = pool::usage().blocks;
    for (method, irp_flags) in [
        (
            DO_BUFFERED_IO,
            IRP_BUFFERED_IO | IRP_DEALLOCATE_BUFFER | IRP_INPUT_OPERATION,
        ),
        (DO_DIRECT_IO, 0),
        (0, 0),
    ] {
        set_transfer_method(&stack, method);
        for offset in [0x40i64, PENDED_OFFSET] {
            let mut data = alloc::vec![0u8; LEN];
            let (event, block) = sender.arm();
            // SAFETY: the buffer, the offset, the event and the status
            // block outlive the request, which is waited for here.
            unsafe {
                let request = build::IoBuildSynchronousFsdRequest(
                    u32::from(IRP_MJ_READ),
                    top.device(),
                    data.as_mut_ptr().cast(),
                    LEN as u32,
                    &raw const offset,
                    event,
                    block,
                );
                if request.is_null() {
                    return Err("a read request could not be built");
                }
                if (*request).StackCount != 3
                    || (*request).Flags != irp_flags | IRP_PRIORITY_HINT_NORMAL
                    || (*request).Thread.is_null()
                    || ((*request).MdlAddress.is_null() != (method != DO_DIRECT_IO))
                    || ((*request).UserBuffer.is_null() == (method != DO_DIRECT_IO))
                {
                    return Err("a built read is not set up as the device asks");
                }
                let (status, count, pended) = sender.send(top.device(), request)?;
                if pended != (offset == PENDED_OFFSET) {
                    return Err("the bus driver did not pend the read it was to pend");
                }
                if status != STATUS_SUCCESS || count != LEN {
                    return Err("a built read did not come back with its status and count");
                }
                if data
                    .iter()
                    .enumerate()
                    .any(|(i, byte)| *byte != stack::read_pattern(offset, i))
                {
                    return Err("a built read did not bring back what was read");
                }
                // The same bytes, written.
                let (event, block) = sender.arm();
                let request = build::IoBuildSynchronousFsdRequest(
                    u32::from(IRP_MJ_WRITE),
                    top.device(),
                    data.as_mut_ptr().cast(),
                    LEN as u32,
                    &raw const offset,
                    event,
                    block,
                );
                if request.is_null() {
                    return Err("a write request could not be built");
                }
                if method == DO_BUFFERED_IO
                    && (*request).Flags
                        != IRP_BUFFERED_IO | IRP_DEALLOCATE_BUFFER | IRP_PRIORITY_HINT_NORMAL
                {
                    return Err("a built buffered write is flagged as returning data");
                }
                let (status, count, _) = sender.send(top.device(), request)?;
                let sum: u32 = data.iter().map(|b| u32::from(*b)).sum();
                if status != STATUS_SUCCESS
                    || count != LEN
                    || stack::WRITTEN.load(Ordering::Acquire) != sum
                    || stack::WRITTEN_AT.load(Ordering::Acquire) != offset as usize
                {
                    return Err("a built write did not reach the bottom with its data and offset");
                }
            }
            sent += 2;
        }
    }
    // A request with no transfer: a buffer named with it is not used.
    let mut unused = [0u8; 8];
    let (event, block) = sender.arm();
    // SAFETY: as above.
    unsafe {
        let request = build::IoBuildSynchronousFsdRequest(
            u32::from(IRP_MJ_PNP),
            top.device(),
            unused.as_mut_ptr().cast(),
            8,
            core::ptr::null(),
            event,
            block,
        );
        if request.is_null() {
            return Err("a request with no transfer could not be built");
        }
        let location = irp::next_location(request);
        if (*location).MajorFunction != IRP_MJ_PNP
            || (*location).Parameters != [0; 4]
            || !(*request).SystemBuffer.is_null()
            || !(*request).MdlAddress.is_null()
            || !(*request).UserBuffer.is_null()
            || (*request).Flags != IRP_PRIORITY_HINT_NORMAL
        {
            return Err("a request with no transfer was given a buffer or parameters");
        }
        // As whoever sends a Plug and Play request sets it; the bus
        // driver does not know this one and completes it as it came.
        (*request).IoStatus.Status = STATUS_NOT_SUPPORTED;
        let (status, count, _) = sender.send(top.device(), request)?;
        if status != STATUS_NOT_SUPPORTED || count != 0 {
            return Err("a request with no transfer did not come back");
        }
    }
    if pool::usage().blocks != blocks {
        return Err("the I/O manager did not free the requests it built");
    }
    Ok(sent + 1)
}

/// `IoBuildDeviceIoControlRequest`: a control request, internal or not,
/// by each buffer method, completed at once and pended, reaches the
/// bottom with the right major function and comes back with its
/// output where the caller asked for it. Returns the requests sent.
fn device_control() -> Result<u32, &'static str> {
    let stack = Stack::build()?;
    let top = Top::of(&stack);
    let mut sender = Sender::new();
    let mut sent = 0;
    let blocks = pool::usage().blocks;
    for method in [METHOD_BUFFERED, METHOD_OUT_DIRECT, METHOD_NEITHER] {
        for internal in [0u8, 1] {
            for function in [ECHO, PEND] {
                let mut input = *b"abcdefgh";
                let mut output = alloc::vec![0u8; 8];
                let (event, block) = sender.arm();
                stack::clear_log();
                // SAFETY: the buffers, the event and the status block
                // outlive the request, which is waited for here.
                unsafe {
                    let request = build::IoBuildDeviceIoControlRequest(
                        ctl_code(0x22, function, method, 0),
                        top.device(),
                        input.as_mut_ptr().cast(),
                        8,
                        output.as_mut_ptr().cast(),
                        8,
                        internal,
                        event,
                        block,
                    );
                    if request.is_null() {
                        return Err("a control request could not be built");
                    }
                    let (status, count, pended) = sender.send(top.device(), request)?;
                    if pended != (function == PEND) {
                        return Err("the bus driver did not pend the request it was to pend");
                    }
                    if status != STATUS_SUCCESS || count != 8 || &output[..] != b"hgfedcba" {
                        return Err("a built control request did not come back whole");
                    }
                }
                let major = if internal != 0 {
                    IRP_MJ_INTERNAL_DEVICE_CONTROL
                } else {
                    IRP_MJ_DEVICE_CONTROL
                };
                if stack::arrived_at_the_bottom() != Some(major) {
                    return Err("a built control request arrived with the wrong major function");
                }
                sent += 1;
            }
        }
    }
    // No buffers at all: nothing is allocated for them.
    let (event, block) = sender.arm();
    // SAFETY: as above.
    unsafe {
        let request = build::IoBuildDeviceIoControlRequest(
            ctl_code(0x22, ECHO, METHOD_BUFFERED, 0),
            top.device(),
            core::ptr::null_mut(),
            0,
            core::ptr::null_mut(),
            0,
            0,
            event,
            block,
        );
        if request.is_null() {
            return Err("a control request with no buffers could not be built");
        }
        if !(*request).SystemBuffer.is_null() || (*request).Flags != IRP_PRIORITY_HINT_NORMAL {
            return Err("a control request with no buffers was given one");
        }
        let (status, count, _) = sender.send(top.device(), request)?;
        if status != STATUS_SUCCESS || count != 0 {
            return Err("a control request with no buffers did not come back");
        }
    }
    if pool::usage().blocks != blocks {
        return Err("the I/O manager did not free the requests it built");
    }
    Ok(sent + 1)
}

/// Set up the next location of a driver's own IRP for a buffered
/// control request of `function` whose data is `buffer`.
///
/// # Safety
/// `request` is the test's own IRP, not sent; `buffer` outlives its
/// way down and back.
unsafe fn own_control(request: *mut IRP, function: u32, buffer: &mut [u8; 4]) {
    // SAFETY: per the contract.
    unsafe {
        *buffer = *b"wxyz";
        (*request).SystemBuffer = buffer.as_mut_ptr().cast();
        let location = irp::next_location(request);
        (*location).MajorFunction = IRP_MJ_DEVICE_CONTROL;
        (*location).Parameters =
            ioctl_parameters(4, 4, ctl_code(0x22, function, METHOD_BUFFERED, 0), 0);
    }
}

/// Whether a driver's own IRP came back from `IoSynchronousCallDriver`
/// as it should: with the bus driver's results, uncompleted, back at
/// the sender's place above the first location.
///
/// # Safety
/// `request` is the test's own IRP, which no driver holds.
unsafe fn came_back(request: *mut IRP, buffer: &[u8; 4]) -> bool {
    // SAFETY: per the contract.
    unsafe {
        (*request).Type == IO_TYPE_IRP
            && (*request).IoStatus.Status == STATUS_SUCCESS
            && (*request).IoStatus.Information == 4
            && buffer == b"zyxw"
            && (*request).CurrentLocation == (*request).StackCount + 1
    }
}

/// `IoSynchronousCallDriver` sends a driver's own IRP and returns when
/// the drivers below are done with it, pended or not, leaving it the
/// driver's; `IoReuseIrp` makes it ready to send again; `IoInitializeIrp`
/// makes one in the driver's own memory. Returns the requests sent.
fn synchronous_call() -> Result<u32, &'static str> {
    let stack = Stack::build()?;
    let top = Top::of(&stack);
    let mut buffer = [0u8; 4];
    let mut sent = 0;
    // SAFETY: the test's own IRPs, sent to a stack of the test's and
    // freed when they have come back.
    unsafe {
        let request = irp::IoAllocateIrp((*top.device()).StackSize, 0);
        if request.is_null() {
            return Err("no memory for an IRP");
        }
        let result = (|| {
            for function in [PEND, ECHO, PEND] {
                own_control(request, function, &mut buffer);
                let status = build::IoSynchronousCallDriver(top.device(), request);
                if status != STATUS_SUCCESS || !came_back(request, &buffer) {
                    return Err("an IRP sent synchronously did not come back to its sender");
                }
                sent += 1;
                // Used again: as new, but for the status given.
                (*request).Cancel = 1;
                irp::IoReuseIrp(request, STATUS_NOT_SUPPORTED);
                if (*request).IoStatus.Status != STATUS_NOT_SUPPORTED
                    || (*request).IoStatus.Information != 0
                    || (*request).Cancel != 0
                    || (*request).PendingReturned != 0
                    || !(*request).SystemBuffer.is_null()
                    || (*request).StackCount != 3
                    || (*request).CurrentLocation != 4
                    || (*request).CurrentStackLocation
                        != request.add(1).cast::<IO_STACK_LOCATION>().add(3)
                    || (*irp::next_location(request)).CompletionRoutine.is_some()
                {
                    return Err("IoReuseIrp did not leave the IRP as new");
                }
            }
            Ok(())
        })();
        irp::IoFreeIrp(request);
        result?;

        // An IRP in the driver's own memory, which held something else.
        let (_, size) = irp_size(3);
        let own = pool::alloc(size, TAG).cast::<IRP>();
        if own.is_null() {
            return Err("no memory for an IRP of the driver's own");
        }
        core::ptr::write_bytes(own.cast::<u8>(), 0xA5, size);
        irp::IoInitializeIrp(own, size as u16, 3);
        let laid_out = (*own).Type == IO_TYPE_IRP
            && usize::from((*own).Size) == size
            && (*own).StackCount == 3
            && (*own).CurrentLocation == 4
            && (*own).AllocationFlags == 0
            && (*own).ThreadListEntry.Flink == &raw mut (*own).ThreadListEntry
            && (*own).CurrentStackLocation == own.add(1).cast::<IO_STACK_LOCATION>().add(3)
            && core::slice::from_raw_parts(own.add(1).cast::<u8>(), size - size_of::<IRP>())
                .iter()
                .all(|byte| *byte == 0);
        let result = if laid_out {
            own_control(own, PEND, &mut buffer);
            let status = build::IoSynchronousCallDriver(top.device(), own);
            if status == STATUS_SUCCESS && came_back(own, &buffer) {
                Ok(sent + 1)
            } else {
                Err("an IRP in the driver's own memory did not come back to its sender")
            }
        } else {
            Err("IoInitializeIrp did not lay the IRP out")
        };
        let _ = pool::free(own.cast());
        result
    }
}

/// A built request the bottom of the stack holds is cancelled with
/// `IoCancelIrp`: its driver's cancel routine is entered with the
/// cancel spin lock held, and the request completes as cancelled, to
/// the caller's status block and event. Returns the facts checked.
fn cancel_built() -> Result<u32, &'static str> {
    let stack = Stack::build()?;
    let top = Top::of(&stack);
    let mut sender = Sender::new();
    let mut data = *b"hold";
    let blocks = pool::usage().blocks;
    // The cancel spin lock, as a driver takes it around its own queue.
    let mut old = 0xFF;
    // SAFETY: room for the IRQL; released at once.
    let held_at = unsafe {
        irp::IoAcquireCancelSpinLock(&raw mut old);
        let held_at = irql::current();
        irp::IoReleaseCancelSpinLock(old);
        held_at
    };
    if old != irql::PASSIVE_LEVEL
        || held_at != irql::DISPATCH_LEVEL
        || irql::current() != irql::PASSIVE_LEVEL
    {
        return Err("the cancel spin lock did not raise the IRQL and give it back");
    }
    let (event, block) = sender.arm();
    // SAFETY: the buffer, the event and the status block outlive the
    // request, which is waited for here; it is cancelled while the bus
    // driver holds it.
    unsafe {
        let request = build::IoBuildDeviceIoControlRequest(
            ctl_code(0x22, HOLD, METHOD_BUFFERED, 0),
            top.device(),
            data.as_mut_ptr().cast(),
            4,
            data.as_mut_ptr().cast(),
            4,
            0,
            event,
            block,
        );
        if request.is_null() {
            return Err("a control request could not be built");
        }
        if irp::IofCallDriver(top.device(), request) != STATUS_PENDING {
            return Err("the bus driver did not hold the request");
        }
        if wait::KeReadStateEvent(event) != 0 {
            return Err("a held request's event is set");
        }
        if irp::IoCancelIrp(request) == 0 {
            return Err("IoCancelIrp found no cancel routine on a held request");
        }
        wait::wait(Some(event.cast()), None);
        let result = block.read_volatile();
        if result.Status != STATUS_CANCELLED || result.Information != 0 {
            return Err("a cancelled request did not complete as cancelled");
        }
    }
    if &data != b"hold" {
        return Err("a cancelled request's buffer was written");
    }
    if pool::usage().blocks != blocks {
        return Err("the I/O manager did not free the cancelled request");
    }
    Ok(6)
}

/// `IoSetMasterIrpStatus` folds the parts' statuses into the master
/// request's. Returns the steps checked.
fn master_status() -> Result<u32, &'static str> {
    let master = irp::IoAllocateIrp(1, 0);
    if master.is_null() {
        return Err("no memory for an IRP");
    }
    let steps = [
        (STATUS_SUCCESS, STATUS_SUCCESS),
        (STATUS_BUFFER_OVERFLOW, STATUS_BUFFER_OVERFLOW),
        (STATUS_SUCCESS, STATUS_BUFFER_OVERFLOW),
        (STATUS_END_OF_FILE, STATUS_END_OF_FILE),
        (STATUS_ACCESS_DENIED, STATUS_END_OF_FILE),
        (STATUS_VERIFY_REQUIRED, STATUS_VERIFY_REQUIRED),
        (STATUS_END_OF_FILE, STATUS_VERIFY_REQUIRED),
    ];
    // SAFETY: the test's own IRP.
    unsafe {
        let wrong = steps.iter().any(|(part, then)| {
            build::IoSetMasterIrpStatus(master, *part);
            (*master).IoStatus.Status != *then
        });
        irp::IoFreeIrp(master);
        if wrong {
            return Err("a part's status was not folded into the master's as Windows folds it");
        }
    }
    Ok(steps.len() as u32)
}

/// A completion routine that keeps the request for its sender.
///
/// # Safety
/// Called as a completion routine.
unsafe extern "C" fn keep(_: *mut DEVICE_OBJECT, _: *mut IRP, _: *mut c_void) -> NTSTATUS {
    STATUS_MORE_PROCESSING_REQUIRED
}

/// `PoCallDriver` sends a power request down the stack as
/// `IoCallDriver` sends any other, with its parameters where the
/// header puts them; `PoStartNextPowerIrp` changes nothing. Returns
/// the facts checked.
fn power() -> Result<u32, &'static str> {
    use nk_ntabi::pnp::*;
    let stack = Stack::build()?;
    let top = Top::of(&stack);
    let parameters = power_parameters(
        0,
        POWER_STATE_TYPE_DEVICE,
        POWER_DEVICE_D0,
        POWER_ACTION_NONE,
    );
    // SAFETY: the test's own IRP, sent to a stack of the test's and
    // kept by its completion routine.
    unsafe {
        let request = irp::IoAllocateIrp((*top.device()).StackSize, 0);
        if request.is_null() {
            return Err("no memory for an IRP");
        }
        (*request).IoStatus.Status = STATUS_NOT_SUPPORTED;
        let location = irp::next_location(request);
        (*location).MajorFunction = IRP_MJ_POWER;
        (*location).MinorFunction = IRP_MN_SET_POWER;
        (*location).Parameters = parameters;
        (*location).CompletionRoutine = Some(keep);
        (*location).Control = SL_INVOKE_ON_SUCCESS | SL_INVOKE_ON_ERROR | SL_INVOKE_ON_CANCEL;
        stack::clear_log();
        let status = irp::PoCallDriver(top.device(), request);
        let before = core::slice::from_raw_parts(request.cast::<u8>(), size_of::<IRP>()).to_vec();
        irp::PoStartNextPowerIrp(request);
        let after = core::slice::from_raw_parts(request.cast::<u8>(), size_of::<IRP>());
        let unchanged = before == after;
        let completed = (*request).IoStatus.Status;
        irp::IoFreeIrp(request);
        if status != STATUS_SUCCESS || completed != STATUS_SUCCESS {
            return Err("a power request did not go down the stack and come back");
        }
        if !unchanged {
            return Err("PoStartNextPowerIrp changed the request");
        }
    }
    if stack::arrived_at_the_bottom() != Some(IRP_MJ_POWER)
        || stack::arrived_with() != (IRP_MN_SET_POWER, parameters)
    {
        return Err("a power request did not arrive with its minor function and parameters");
    }
    Ok(5)
}

/// `IoBuildPartialMdl`: a part of a locked buffer, mapped on its own,
/// is the same memory; a part of a mapped buffer shares its mapping.
/// Returns the facts checked.
fn partial_mdl_test() -> Result<u32, &'static str> {
    const LEN: usize = 0x2800;
    let block = pool::alloc(LEN + 0x200, TAG);
    if block.is_null() {
        return Err("no memory for a buffer");
    }
    // SAFETY: the block, described by MDLs of the test's that are all
    // freed before it.
    let result = unsafe {
        let va = block.add(0x123);
        core::ptr::write_bytes(va, 0, LEN);
        let source = mdl::IoAllocateMdl(va.cast(), LEN as u32, 0, 0, core::ptr::null_mut());
        let part = mdl::IoAllocateMdl(va.cast(), LEN as u32, 0, 0, core::ptr::null_mut());
        let result = (|| {
            if source.is_null() || part.is_null() {
                return Err("no memory for an MDL");
            }
            mdl::probe_and_lock(source, KERNEL_MODE, IO_WRITE_ACCESS)
                .map_err(|_| "a pool buffer could not be locked")?;
            // A part in the middle, mapped on its own.
            let at = va.add(0x1010);
            mdl::IoBuildPartialMdl(source, part, at.cast(), 0x900);
            let flags = (*part).MdlFlags;
            if flags & MDL_PARTIAL == 0
                || flags & (MDL_PAGES_LOCKED | MDL_MAPPED_TO_SYSTEM_VA) != 0
                || (*part).ByteCount != 0x900
                || (*part).ByteOffset as usize != at.addr() & 0xFFF
                || (*part).StartVa.addr() != at.addr() & !0xFFF
            {
                return Err("a partial MDL does not describe the part asked for");
            }
            let view = stack::mapped(part);
            if view.is_null() || view == at {
                return Err("a partial MDL was not given a mapping of its own");
            }
            if (*part).MdlFlags & MDL_PARTIAL_HAS_BEEN_MAPPED == 0 {
                return Err("a mapped partial MDL is not marked as mapped");
            }
            for i in 0..0x900 {
                view.add(i).write(i as u8 ^ 0x5A);
            }
            if (0..0x900).any(|i| at.add(i).read() != i as u8 ^ 0x5A)
                || at.sub(1).read() != 0
                || at.add(0x900).read() != 0
            {
                return Err("a partial MDL's mapping is not the part of the buffer it names");
            }
            // `MmPrepareMdlForReuse`, as classpnp does it between two
            // pieces of a transfer: the part's own mapping is taken
            // down, and the MDL is as it was before it was mapped; it
            // then describes another part, mapped again.
            mdl::MmUnmapLockedPages(view.cast(), part);
            if (*part).MdlFlags & (MDL_MAPPED_TO_SYSTEM_VA | MDL_PARTIAL_HAS_BEEN_MAPPED) != 0
                || !(*part).MappedSystemVa.is_null()
            {
                return Err("an unmapped partial MDL still says it has a mapping of its own");
            }
            mdl::IoBuildPartialMdl(source, part, va.add(0x400).cast(), 0x1000);
            let second = stack::mapped(part);
            if second.is_null() || second.read() != va.add(0x400).read() {
                return Err("a partial MDL could not be used for a second part");
            }
            va.add(0x400).write(0x33);
            if second.read() != 0x33 {
                return Err("a reused partial MDL does not map the part it names");
            }
            mdl::MmUnmapLockedPages(second.cast(), part);
            // `IoFreeMdl` prepares the MDL for reuse too: freed mapped
            // or unmapped, and made again, it has no mapping left.
            mdl::IoFreeMdl(part);
            let part = mdl::IoAllocateMdl(va.cast(), LEN as u32, 0, 0, core::ptr::null_mut());
            if part.is_null() {
                return Err("no memory for an MDL");
            }
            mdl::IoBuildPartialMdl(source, part, at.cast(), 0x900);
            if stack::mapped(part).is_null() {
                return Err("a partial MDL was not mapped");
            }
            mdl::IoFreeMdl(part);
            let part = mdl::IoAllocateMdl(va.cast(), LEN as u32, 0, 0, core::ptr::null_mut());
            if part.is_null() {
                return Err("no memory for an MDL");
            }
            // A part of a mapped buffer, to its end: it shares the
            // source's mapping.
            let whole = stack::mapped(source);
            mdl::IoBuildPartialMdl(source, part, va.add(0x2000).cast(), 0);
            let shares = (*part).MdlFlags & MDL_MAPPED_TO_SYSTEM_VA != 0
                && (*part).MdlFlags & MDL_PARTIAL_HAS_BEEN_MAPPED == 0
                && (*part).MappedSystemVa.cast::<u8>() == whole.add(0x2000)
                && stack::mapped(part) == whole.add(0x2000)
                && (*part).ByteCount as usize == LEN - 0x2000;
            va.add(0x2001).write(0x77);
            let same = whole.add(0x2001).read() == 0x77;
            mdl::IoFreeMdl(part);
            if !shares || !same {
                return Err("a part of a mapped buffer does not share its mapping");
            }
            // An empty part, at the end of a buffer that ends on a page
            // boundary: it maps no page, and taking that mapping down
            // gives back what mapping it took.
            let end = (va.addr() + 0x1000) & !0xFFF;
            let short = mdl::IoAllocateMdl(
                va.cast(),
                (end - va.addr()) as u32,
                0,
                0,
                core::ptr::null_mut(),
            );
            let part = mdl::IoAllocateMdl(va.cast(), LEN as u32, 0, 0, core::ptr::null_mut());
            if short.is_null() || part.is_null() {
                return Err("no memory for an MDL");
            }
            let empty = (|| {
                mdl::probe_and_lock(short, KERNEL_MODE, IO_WRITE_ACCESS)
                    .map_err(|_| "a pool buffer could not be locked")?;
                mdl::IoBuildPartialMdl(
                    short,
                    part,
                    core::ptr::with_exposed_provenance_mut::<c_void>(end),
                    0,
                );
                if (*part).ByteCount != 0 || (*part).ByteOffset != 0 {
                    return Err("a part at a buffer's end is not empty");
                }
                let view = stack::mapped(part);
                if view.is_null() {
                    return Err("an empty partial MDL was not mapped");
                }
                mdl::MmUnmapLockedPages(view.cast(), part);
                Ok(())
            })();
            mdl::IoFreeMdl(part);
            if (*short).MdlFlags & MDL_PAGES_LOCKED != 0 {
                mdl::MmUnlockPages(short);
            }
            mdl::IoFreeMdl(short);
            empty?;
            Ok(10)
        })();
        if !source.is_null() {
            if (*source).MdlFlags & MDL_PAGES_LOCKED != 0 {
                mdl::MmUnlockPages(source);
            }
            mdl::IoFreeMdl(source);
        }
        result
    };
    let _ = pool::free(block);
    result
}

/// `ObReferenceObjectByPointer` takes a reference if the object is of
/// the type named; with no type named, for kernel mode only. Returns
/// the cases checked.
fn reference_by_pointer() -> Result<u32, &'static str> {
    let stack = Stack::build()?;
    let object = stack.devices[PDO as usize].cast::<c_void>();
    let device_type = object::IoDeviceObjectType.value();
    let file_type = object::IoFileObjectType.value();
    if !core::ptr::eq(file_type, &raw const object::FILE_TYPE) {
        return Err("IoFileObjectType does not name the file type");
    }
    let cases = [
        (device_type, KERNEL_MODE, STATUS_SUCCESS),
        (device_type, USER_MODE, STATUS_SUCCESS),
        (file_type, KERNEL_MODE, STATUS_OBJECT_TYPE_MISMATCH),
        (file_type, USER_MODE, STATUS_OBJECT_TYPE_MISMATCH),
        (core::ptr::null(), KERNEL_MODE, STATUS_SUCCESS),
        (core::ptr::null(), USER_MODE, STATUS_OBJECT_TYPE_MISMATCH),
    ];
    for (wanted, mode, expected) in cases {
        // SAFETY: a live device of the test's; a reference taken is
        // given back.
        unsafe {
            let before = object::reference(object.cast());
            let status = object::ObReferenceObjectByPointer(object, 0, wanted, mode);
            let after = object::dereference(object.cast());
            let taken = after - (before - 1);
            if status == STATUS_SUCCESS {
                object::dereference(object.cast());
            }
            if status != expected || taken != i64::from(status == STATUS_SUCCESS) {
                return Err("a reference by pointer was not taken, or refused, as on Windows");
            }
        }
    }
    Ok(cases.len() as u32)
}

fn run(report: &mut Report, _: &BootInfo) {
    let mut numbered = |name: &str, result: Result<u32, &'static str>| match result {
        Ok(n) => report.ok_with(name, format_args!("{n} checked")),
        Err(why) => report.fail(name, format_args!("{why}")),
    };
    numbered("io.request.synchronous-fsd", synchronous_fsd());
    numbered("io.request.device-control", device_control());
    numbered("io.request.synchronous-call", synchronous_call());
    numbered("io.request.cancel-built", cancel_built());
    numbered("io.request.master-status", master_status());
    numbered("io.request.power", power());
    numbered("io.mdl.partial", partial_mdl_test());
    numbered("ob.reference-by-pointer", reference_by_pointer());
}
