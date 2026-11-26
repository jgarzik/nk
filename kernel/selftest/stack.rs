//! Tests of device stacks: a bus driver's device, a function driver's
//! attached on top of it and a filter's on top of that, as Microsoft's
//! bus, port and class drivers build them.
//!
//! The three drivers are here, in Rust, written the way WDM drivers in
//! C are (the in-line macros spelled out) and calling the exports a
//! real driver calls, because what is under test is the I/O manager's
//! side: the bookkeeping of a stack, where a request opened by name
//! goes, and how it travels down and completes back up.

use crate::ex::work;
use crate::io::file::{self, IoResult};
use crate::io::{device, irp};
use crate::ke::dpc;
use crate::ob::object;
use crate::test::{Group, Report, Slot};
use alloc::vec::Vec;
use core::ffi::c_void;
use core::sync::atomic::{AtomicPtr, AtomicU32, AtomicUsize, Ordering};
use nk_bootinfo::BootInfo;
use nk_ntabi::ex::WORK_QUEUE_ITEM;
use nk_ntabi::io::*;
use nk_ntabi::ke::KDPC;
use nk_ntabi::status::*;

pub static GROUP: Group = Group {
    names: &[
        "io.stack.attach",
        "io.stack.open-goes-to-the-top",
        "io.stack.pended-below",
        "io.stack.detach-then-delete",
        "io.stack.delete-then-detach",
        "io.stack.fast-io-detach",
    ],
    run,
    manual: false,
};

pub static GROUPS: &[&Group] = &[&GROUP];

/// The bus driver's device, which has the name.
pub(super) const PDO_NAME: &str = "\\Device\\NkStackPdo";

/// The levels of the stack, bottom first.
pub(super) const PDO: u32 = 0;
pub(super) const FDO: u32 = 1;
pub(super) const FILTER: u32 = 2;

/// What a control code asks of the stack: its function number.
/// Completed by the bus driver at once: the input comes back reversed.
const ECHO: u32 = 0x900;
/// Pended by the bus driver and completed from a DPC.
const PEND: u32 = 0x901;
/// As `PEND`, and the function driver takes the request back in its
/// completion routine and completes it again from a work item.
const PEND_AND_HOLD: u32 = 0x902;

const fn code(function: u32) -> u32 {
    ctl_code(0x22, function, METHOD_BUFFERED, 0)
}

/// What a device of the stack keeps in its extension.
#[repr(C)]
pub(super) struct Layer {
    /// The device this one is attached to; null in the bus driver's.
    pub lower: *mut DEVICE_OBJECT,
    pub level: u32,
}

/// What happened, in order: `EVENT << 16 | level << 8 | major`.
const ARRIVED: u32 = 1;
const COMPLETED: u32 = 2;
const RECOMPLETED: u32 = 3;
static LOG: [AtomicU32; 32] = [const { AtomicU32::new(0) }; 32];
static LOGGED: AtomicUsize = AtomicUsize::new(0);
/// Whether everything a completion routine was handed was as it should
/// be: its own device, the status the request completed with.
static WRONG: AtomicU32 = AtomicU32::new(0);
/// How many stack locations the last request had when it reached the
/// bus driver.
static STACK_COUNT: AtomicU32 = AtomicU32::new(0);

const fn event(kind: u32, level: u32, major: u8) -> u32 {
    kind << 16 | level << 8 | major as u32
}

fn log(kind: u32, level: u32, major: u8) {
    let at = LOGGED.fetch_add(1, Ordering::AcqRel);
    if let Some(slot) = LOG.get(at) {
        slot.store(event(kind, level, major), Ordering::Release);
    }
}

/// Forget what happened.
pub(super) fn clear_log() {
    LOGGED.store(0, Ordering::Release);
    WRONG.store(0, Ordering::Release);
}

/// What happened since the log was cleared.
fn logged() -> Vec<u32> {
    let count = LOGGED.load(Ordering::Acquire).min(LOG.len());
    LOG[..count]
        .iter()
        .map(|slot| slot.load(Ordering::Acquire))
        .collect()
}

/// The request the bus driver holds, its DPC, and the request the
/// function driver took back, with its work item.
static HELD: AtomicPtr<IRP> = AtomicPtr::new(core::ptr::null_mut());
static DPC: Slot<KDPC> = Slot::new();
static TAKEN: AtomicPtr<IRP> = AtomicPtr::new(core::ptr::null_mut());
static WORK: Slot<WORK_QUEUE_ITEM> = Slot::new();

/// # Safety
/// `device` is a device of the test's.
pub(super) unsafe fn layer(device: *mut DEVICE_OBJECT) -> *mut Layer {
    // SAFETY: per the contract: `make_device` gave it the extension.
    unsafe { (*device).DeviceExtension.cast() }
}

/// The bus driver completes a request it holds.
///
/// # Safety
/// Called as a DPC routine; it dereferences none of its arguments.
unsafe extern "C" fn complete_held(_: *mut KDPC, _: *mut c_void, _: *mut c_void, _: *mut c_void) {
    let irp = HELD.swap(core::ptr::null_mut(), Ordering::AcqRel);
    if !irp.is_null() {
        // SAFETY: the bus driver pended `irp` and has not completed it.
        unsafe { finish(irp) };
    }
}

/// Complete a buffered control request: the input comes back reversed.
///
/// # Safety
/// `irp` is a control request the caller owns, at its own location.
unsafe fn finish(irp: *mut IRP) {
    // SAFETY: per the contract; a buffered request's system buffer
    // holds the larger of input and output.
    unsafe {
        let parameters = (*(*irp).CurrentStackLocation).Parameters;
        let n = (parameters[0] as usize).min(parameters[1] as usize);
        if n != 0 {
            core::slice::from_raw_parts_mut((*irp).SystemBuffer.cast::<u8>(), n).reverse();
        }
        (*irp).IoStatus.Status = STATUS_SUCCESS;
        (*irp).IoStatus.Information = n;
        irp::IofCompleteRequest(irp, 0);
    }
}

/// The bus driver's dispatch routine, for every request.
///
/// # Safety
/// Called as a dispatch routine.
unsafe extern "C" fn bus_dispatch(device: *mut DEVICE_OBJECT, irp: *mut IRP) -> NTSTATUS {
    // SAFETY: a live IRP being dispatched to a device of the test's.
    unsafe {
        let location = (*irp).CurrentStackLocation;
        let major = (*location).MajorFunction;
        log(ARRIVED, (*layer(device)).level, major);
        STACK_COUNT.store((*irp).StackCount as u32, Ordering::Release);
        if (*location).DeviceObject != device {
            WRONG.fetch_add(1, Ordering::AcqRel);
        }
        if major != IRP_MJ_DEVICE_CONTROL {
            (*irp).IoStatus.Status = STATUS_SUCCESS;
            (*irp).IoStatus.Information = 0;
            irp::IofCompleteRequest(irp, 0);
            return STATUS_SUCCESS;
        }
        if (*location).Parameters[2] as u32 == code(ECHO) {
            finish(irp);
            return STATUS_SUCCESS;
        }
        // `IoMarkIrpPending`.
        (*location).Control |= SL_PENDING_RETURNED;
        HELD.store(irp, Ordering::Release);
        dpc::KeInsertQueueDpc(DPC.ptr(), core::ptr::null_mut(), core::ptr::null_mut());
        STATUS_PENDING
    }
}

/// The function driver completes again the request its completion
/// routine took back.
///
/// # Safety
/// Called as a work routine.
unsafe extern "C" fn recomplete(_: *mut c_void) {
    let irp = TAKEN.swap(core::ptr::null_mut(), Ordering::AcqRel);
    if !irp.is_null() {
        log(RECOMPLETED, FDO, IRP_MJ_DEVICE_CONTROL);
        // SAFETY: the function driver's completion routine took `irp`
        // back, so it is the function driver's to complete.
        unsafe { irp::IofCompleteRequest(irp, 0) };
    }
}

/// The completion routine the function driver and the filter set as
/// they pass a request down. `context` is the driver's own `Layer`.
///
/// # Safety
/// Called as a completion routine.
unsafe extern "C" fn passed_back(
    device: *mut DEVICE_OBJECT,
    irp: *mut IRP,
    context: *mut c_void,
) -> NTSTATUS {
    // SAFETY: a live IRP completing through a location of the test's.
    unsafe {
        let own = context.cast::<Layer>();
        let level = (*own).level;
        // The routine is told its own device, and finds the IRP back at
        // its own location.
        if device.is_null()
            || layer(device) != own
            || (*(*irp).CurrentStackLocation).DeviceObject != device
        {
            WRONG.fetch_add(1, Ordering::AcqRel);
        }
        let location = (*irp).CurrentStackLocation;
        let major = (*location).MajorFunction;
        log(COMPLETED, level, major);
        let held = major == IRP_MJ_DEVICE_CONTROL
            && (*location).Parameters[2] as u32 == code(PEND_AND_HOLD);
        if level == FDO && held {
            // The dispatch routine marked the request pending and
            // returned so.
            TAKEN.store(irp, Ordering::Release);
            (&raw mut (*WORK.ptr()).List.Flink).write(core::ptr::null_mut());
            (&raw mut (*WORK.ptr()).WorkerRoutine).write(Some(recomplete));
            (&raw mut (*WORK.ptr()).Parameter).write(core::ptr::null_mut());
            work::ExQueueWorkItem(WORK.ptr(), 1);
            return STATUS_MORE_PROCESSING_REQUIRED;
        }
        if (*irp).PendingReturned != 0 {
            // `IoMarkIrpPending`.
            (*location).Control |= SL_PENDING_RETURNED;
        }
    }
    STATUS_SUCCESS
}

/// The dispatch routine of the function driver and of the filter, for
/// every request: pass it down, with a completion routine.
///
/// # Safety
/// Called as a dispatch routine.
unsafe extern "C" fn pass_down(device: *mut DEVICE_OBJECT, irp: *mut IRP) -> NTSTATUS {
    // SAFETY: a live IRP being dispatched to a device of the test's,
    // with a location left for the device below.
    unsafe {
        let own = layer(device);
        let location = (*irp).CurrentStackLocation;
        let major = (*location).MajorFunction;
        log(ARRIVED, (*own).level, major);
        if (*location).DeviceObject != device {
            WRONG.fetch_add(1, Ordering::AcqRel);
        }
        // `IoCopyCurrentIrpStackLocationToNext`: all but the completion
        // routine and its context, and no control flags.
        let next = irp::next_location(irp);
        core::ptr::copy_nonoverlapping(
            location.cast::<u8>(),
            next.cast::<u8>(),
            core::mem::offset_of!(IO_STACK_LOCATION, CompletionRoutine),
        );
        // `IoSetCompletionRoutine(Irp, PassedBack, Layer, TRUE, TRUE, TRUE)`.
        (*next).CompletionRoutine = Some(passed_back);
        (*next).Context = own.cast();
        (*next).Control = SL_INVOKE_ON_SUCCESS | SL_INVOKE_ON_ERROR | SL_INVOKE_ON_CANCEL;
        let held = major == IRP_MJ_DEVICE_CONTROL
            && (*location).Parameters[2] as u32 == code(PEND_AND_HOLD);
        if (*own).level == FDO && held {
            // Its completion routine will take the request back: the
            // request is pending whatever the driver below returns.
            (*location).Control |= SL_PENDING_RETURNED;
            irp::IofCallDriver((*own).lower, irp);
            return STATUS_PENDING;
        }
        irp::IofCallDriver((*own).lower, irp)
    }
}

/// A driver object of the test's: an object of the driver type, with
/// its extension behind it, every request going to `dispatch`.
pub(super) fn make_driver(dispatch: DRIVER_DISPATCH) -> Result<*mut DRIVER_OBJECT, &'static str> {
    let size = size_of::<DRIVER_OBJECT>() + size_of::<DRIVER_EXTENSION>();
    let body = object::create(&object::DRIVER_TYPE, size).ok_or("no memory for a driver object")?;
    let driver = body.cast::<DRIVER_OBJECT>();
    // SAFETY: a fresh zeroed object of that size, set up as
    // `driver::load` sets one up.
    unsafe {
        let extension = driver.add(1).cast::<DRIVER_EXTENSION>();
        (*extension).DriverObject = driver;
        (*driver).Type = IO_TYPE_DRIVER;
        (*driver).Size = size_of::<DRIVER_OBJECT>() as i16;
        (*driver).DriverExtension = extension;
        (*driver).MajorFunction = [Some(dispatch); IRP_MJ_MAXIMUM_FUNCTION + 1];
    }
    Ok(driver)
}

/// Give a driver object of the test's up.
///
/// # Safety
/// `driver` came from [`make_driver`] and has no devices left.
pub(super) unsafe fn free_driver(driver: *mut DRIVER_OBJECT) {
    // SAFETY: per the contract: the reference it was made with.
    unsafe { object::dereference(driver.cast()) };
}

/// A device of `driver`'s at `level`, called `name` if it has one, and
/// ready for requests.
pub(super) fn make_device(
    driver: *mut DRIVER_OBJECT,
    level: u32,
    name: Option<&str>,
) -> Result<*mut DEVICE_OBJECT, &'static str> {
    let mut wide: Vec<u16> = name.unwrap_or("").encode_utf16().collect();
    let counted = UNICODE_STRING {
        Length: (wide.len() * 2) as u16,
        MaximumLength: (wide.len() * 2) as u16,
        Buffer: wide.as_mut_ptr(),
    };
    let name = if name.is_some() {
        &raw const counted
    } else {
        core::ptr::null()
    };
    let mut made = core::ptr::null_mut();
    // SAFETY: a driver object of the test's; the name is a counted
    // string or null.
    unsafe {
        if device::IoCreateDevice(
            driver,
            size_of::<Layer>() as u32,
            name,
            0x22,
            0,
            0,
            &raw mut made,
        ) != STATUS_SUCCESS
        {
            return Err("could not create a device of the stack");
        }
        (*layer(made)).level = level;
        (*made).Flags |= DO_BUFFERED_IO;
        (*made).Flags &= !DO_DEVICE_INITIALIZING;
    }
    Ok(made)
}

/// The three drivers and their devices, attached.
pub(super) struct Stack {
    pub drivers: [*mut DRIVER_OBJECT; 3],
    pub devices: [*mut DEVICE_OBJECT; 3],
}

impl Stack {
    /// Three drivers and a device of each, not yet attached.
    fn unattached() -> Result<Self, &'static str> {
        let mut stack = Stack {
            drivers: [core::ptr::null_mut(); 3],
            devices: [core::ptr::null_mut(); 3],
        };
        // On a failure half way, `Drop` takes down what was made.
        for level in [PDO, FDO, FILTER] {
            let dispatch: DRIVER_DISPATCH = if level == PDO {
                bus_dispatch
            } else {
                pass_down
            };
            let at = level as usize;
            stack.drivers[at] = make_driver(dispatch)?;
            stack.devices[at] =
                make_device(stack.drivers[at], level, (level == PDO).then_some(PDO_NAME))?;
        }
        Ok(stack)
    }

    /// The stack, built: the function driver's device attached to the
    /// bus driver's, the filter's to the top of that.
    pub(super) fn build() -> Result<Self, &'static str> {
        let stack = Self::unattached()?;
        // SAFETY: devices of the test's; each driver keeps what it was
        // attached to, as a driver's `AddDevice` does.
        unsafe {
            dpc::KeInitializeDpc(DPC.ptr(), Some(complete_held), core::ptr::null_mut());
            let [pdo, fdo, filter] = stack.devices;
            (*layer(fdo)).lower = device::IoAttachDeviceToDeviceStack(fdo, pdo);
            // A filter names the device at the bottom and lands on top.
            (*layer(filter)).lower = device::IoAttachDeviceToDeviceStack(filter, pdo);
            if (*layer(fdo)).lower != pdo || (*layer(filter)).lower != fdo {
                return Err("attaching did not return the device attached to");
            }
        }
        Ok(stack)
    }

    fn pdo(&self) -> *mut DEVICE_OBJECT {
        self.devices[PDO as usize]
    }

    fn filter(&self) -> *mut DEVICE_OBJECT {
        self.devices[FILTER as usize]
    }

    /// Detach and delete the device at `level`, as its driver does when
    /// the device is removed, and forget it.
    fn remove(&mut self, level: u32) {
        let at = level as usize;
        let device = core::mem::replace(&mut self.devices[at], core::ptr::null_mut());
        if device.is_null() {
            return;
        }
        // SAFETY: a device of the test's, attached to `lower` if it has
        // one.
        unsafe {
            let lower = (*layer(device)).lower;
            if !lower.is_null() {
                device::IoDetachDevice(lower);
            }
            device::IoDeleteDevice(device);
        }
    }
}

impl Drop for Stack {
    fn drop(&mut self) {
        // Top first, as a stack is taken down.
        for level in [FILTER, FDO, PDO] {
            self.remove(level);
        }
        for driver in self.drivers {
            if !driver.is_null() {
                // SAFETY: its devices are gone.
                unsafe { free_driver(driver) };
            }
        }
    }
}

/// The device a device's extension says it is attached to.
///
/// # Safety
/// `device` is a live device object.
unsafe fn attached_to(device: *mut DEVICE_OBJECT) -> *mut DEVICE_OBJECT {
    // SAFETY: per the contract.
    unsafe { (*(*device).DeviceObjectExtension).AttachedTo }
}

/// Attaching keeps the books Windows keeps: each device's
/// `AttachedDevice` and `StackSize`, its extension's `AttachedTo`, what
/// the device attached to passes on, and who is at the top and at the
/// bottom. A device still initialising is not attached to. Returns the
/// facts checked.
fn attach() -> Result<u32, &'static str> {
    let stack = Stack::build()?;
    let [pdo, fdo, filter] = stack.devices;
    // SAFETY: live devices of the test's.
    unsafe {
        if (*pdo).AttachedDevice != fdo
            || (*fdo).AttachedDevice != filter
            || !(*filter).AttachedDevice.is_null()
        {
            return Err("AttachedDevice does not lead up the stack");
        }
        if !attached_to(pdo).is_null() || attached_to(fdo) != pdo || attached_to(filter) != fdo {
            return Err("the extensions' AttachedTo does not lead down the stack");
        }
        if ((*pdo).StackSize, (*fdo).StackSize, (*filter).StackSize) != (1, 2, 3) {
            return Err("StackSize is not one more than the device attached to");
        }
        let extension = (*filter).DeviceObjectExtension;
        if (*extension).Type != IO_TYPE_DEVICE_OBJECT_EXTENSION
            || (*extension).DeviceObject != filter
        {
            return Err("the device object extension does not name its device");
        }
        // The top, and the bottom, each with a reference for the caller.
        for from in stack.devices {
            let count = object::reference(filter.cast());
            let top = device::IoGetAttachedDeviceReference(from);
            if top != filter || object::dereference(top.cast()) != count {
                return Err("IoGetAttachedDeviceReference did not reference the top");
            }
            object::dereference(filter.cast());
            let count = object::reference(pdo.cast());
            let base = device::IoGetDeviceAttachmentBaseRef(from);
            if base != pdo || object::dereference(base.cast()) != count {
                return Err("IoGetDeviceAttachmentBaseRef did not reference the bottom");
            }
            object::dereference(pdo.cast());
        }
    }
    // What the device attached to requires of transfers, the device
    // attached requires too; and a device still initialising is not
    // attached to.
    let driver = make_driver(pass_down)?;
    let result = (|| {
        let lower = make_device(driver, PDO, None)?;
        let upper = make_device(driver, FDO, None);
        // SAFETY: devices of the test's.
        unsafe {
            let result = upper.and_then(|upper| {
                (*lower).AlignmentRequirement = 0x1FF;
                (*lower).SectorSize = 4096;
                (*lower).Flags |= DO_DEVICE_INITIALIZING;
                let refused = device::IoAttachDeviceToDeviceStack(upper, lower);
                (*lower).Flags &= !DO_DEVICE_INITIALIZING;
                let attached = device::IoAttachDeviceToDeviceStack(upper, lower);
                let passed_on = ((*upper).AlignmentRequirement, (*upper).SectorSize);
                if attached == lower {
                    device::IoDetachDevice(lower);
                }
                device::IoDeleteDevice(upper);
                if !refused.is_null() {
                    Err("a device still initialising was attached to")
                } else if attached != lower {
                    Err("a device could not be attached once its target was ready")
                } else if passed_on != (0x1FF, 4096) {
                    Err("the alignment and sector size were not passed up")
                } else {
                    Ok(13)
                }
            });
            device::IoDeleteDevice(lower);
            result
        }
    })();
    // SAFETY: its devices are gone.
    unsafe { free_driver(driver) };
    result
}

/// Send a control request through the handle and wait for it.
fn control(opened: u64, how: u32) -> Result<(IoResult, [u8; 4]), &'static str> {
    let mut output = [0u8; 4];
    let result = file::device_control(opened, code(how), b"abcd", &mut output)
        .map_err(|_| "the request was not carried out")?;
    Ok((result, output))
}

/// Opening the bus driver's device by name sends the create to the top
/// of the stack, in an IRP with a location for every device; so with
/// every later request on the file, and with the device
/// `IoGetDeviceObjectPointer` hands out. Returns the events checked.
fn open_goes_to_the_top() -> Result<u32, &'static str> {
    let stack = Stack::build()?;
    clear_log();
    let opened = super::open(PDO_NAME).map_err(|_| "the stack's device could not be opened")?;
    let through = |major: u8| {
        alloc::vec![
            event(ARRIVED, FILTER, major),
            event(ARRIVED, FDO, major),
            event(ARRIVED, PDO, major),
            event(COMPLETED, FDO, major),
            event(COMPLETED, FILTER, major),
        ]
    };
    let mut checked = 0;
    let mut expect = |what: Vec<u32>, why: &'static str| {
        let seen = logged();
        clear_log_keeping_wrong();
        checked += seen.len() as u32;
        if seen == what { Ok(()) } else { Err(why) }
    };
    let result = (|| {
        expect(
            through(IRP_MJ_CREATE),
            "the create did not go down from the top and complete back up",
        )?;
        if STACK_COUNT.load(Ordering::Acquire) != 3 {
            return Err("the create's IRP did not have a location for each device");
        }
        // SAFETY: the file is open: its object names its device.
        unsafe {
            let file = crate::ob::handle::reference_for(
                opened,
                Some(&raw const object::FILE_TYPE),
                0,
                nk_ob::handles::Mode::Kernel,
            )
            .map_err(|_| "the handle names no file")?
            .0
            .cast::<FILE_OBJECT>();
            let named = (*file).DeviceObject;
            object::dereference(file.cast());
            if named != stack.pdo() || (*stack.pdo()).ReferenceCount != 1 {
                return Err("the file is not counted on the device that was named");
            }
        }
        let (result, output) = control(opened, ECHO)?;
        if result.status != STATUS_SUCCESS || result.information != 4 || &output != b"dcba" {
            return Err("a control request through the stack did not come back whole");
        }
        expect(
            through(IRP_MJ_DEVICE_CONTROL),
            "a control request did not go down from the top and complete back up",
        )
    })();
    let closed = file::close(opened);
    let result = result.and_then(|()| {
        if closed != STATUS_SUCCESS {
            return Err("closing the stack's device failed");
        }
        let mut both = through(IRP_MJ_CLEANUP);
        both.extend(through(IRP_MJ_CLOSE));
        expect(
            both,
            "the cleanup and the close did not go through the stack",
        )
    });
    let result = result.and_then(|()| {
        // A driver that finds the device by name is handed the top.
        let mut name: Vec<u16> = PDO_NAME.encode_utf16().collect();
        let name = UNICODE_STRING {
            Length: (name.len() * 2) as u16,
            MaximumLength: (name.len() * 2) as u16,
            Buffer: name.as_mut_ptr(),
        };
        let mut file = core::ptr::null_mut();
        let mut found = core::ptr::null_mut();
        // SAFETY: a counted string and room for the two pointers.
        unsafe {
            if file::IoGetDeviceObjectPointer(&raw const name, 0, &raw mut file, &raw mut found)
                != STATUS_SUCCESS
            {
                return Err("IoGetDeviceObjectPointer could not open the stack");
            }
            let named = (*file).DeviceObject;
            object::dereference(file.cast());
            if found != stack.filter() || named != stack.pdo() {
                return Err("IoGetDeviceObjectPointer did not hand out the top of the stack");
            }
        }
        Ok(())
    });
    if WRONG.load(Ordering::Acquire) != 0 {
        return Err("a routine of the stack was handed the wrong device");
    }
    result.map(|()| checked + 2)
}

/// Forget what happened, but not that something was wrong.
fn clear_log_keeping_wrong() {
    LOGGED.store(0, Ordering::Release);
}

/// A request the bottom of the stack pends and completes from a DPC
/// completes back up through each completion routine; one whose
/// routine answers `STATUS_MORE_PROCESSING_REQUIRED` stops there, and
/// goes on up when that driver completes it again. Returns the events
/// checked.
fn pended_below() -> Result<u32, &'static str> {
    let stack = Stack::build()?;
    let opened = super::open(PDO_NAME).map_err(|_| "the stack's device could not be opened")?;
    let major = IRP_MJ_DEVICE_CONTROL;
    let down = [
        event(ARRIVED, FILTER, major),
        event(ARRIVED, FDO, major),
        event(ARRIVED, PDO, major),
        event(COMPLETED, FDO, major),
    ];
    let result = (|| {
        let mut checked = 0;
        for (how, then) in [
            (PEND, &[event(COMPLETED, FILTER, major)][..]),
            (
                PEND_AND_HOLD,
                &[
                    event(RECOMPLETED, FDO, major),
                    event(COMPLETED, FILTER, major),
                ][..],
            ),
        ] {
            for _ in 0..10 {
                clear_log();
                let (result, output) = control(opened, how)?;
                if result.status != STATUS_SUCCESS || result.information != 4 || &output != b"dcba"
                {
                    return Err("a request pended below did not come back whole");
                }
                let seen = logged();
                if seen[..] != [&down[..], then].concat()[..] {
                    return Err("a request pended below did not complete up the stack in order");
                }
                if WRONG.load(Ordering::Acquire) != 0 {
                    return Err("a completion routine was handed the wrong device");
                }
                checked += seen.len() as u32;
            }
        }
        Ok(checked)
    })();
    let closed = file::close(opened);
    drop(stack);
    match closed {
        STATUS_SUCCESS => result,
        _ => result.and(Err("closing the stack's device failed")),
    }
}

/// Whether a device whose memory the caller holds is still a device:
/// freeing one clears its type.
///
/// # Safety
/// The caller holds a pointer reference on `device`.
unsafe fn is_device(device: *mut DEVICE_OBJECT) -> bool {
    // SAFETY: per the contract.
    unsafe { (&raw const (*device).Type).read_volatile() == IO_TYPE_DEVICE }
}

/// A stack taken down as drivers take it down, top first, each device
/// detached and then deleted: every device goes when it is deleted,
/// and what is left stays as it was. Returns the facts checked.
fn detach_then_delete() -> Result<u32, &'static str> {
    let mut stack = Stack::build()?;
    let [pdo, fdo, filter] = stack.devices;
    // SAFETY: the test holds a pointer reference on each device, so
    // its memory is there to look at after it has been freed.
    unsafe {
        for device in [pdo, fdo, filter] {
            object::reference(device.cast());
        }
        let result = (|| {
            stack.remove(FILTER);
            if is_device(filter) {
                return Err("a detached, deleted device is still a device");
            }
            if !(*fdo).AttachedDevice.is_null() || (*fdo).StackSize != 2 {
                return Err("detaching did not leave the device below as the top");
            }
            if device::IoGetAttachedDeviceReference(pdo) != fdo {
                return Err("the top of the stack is not the device left on top");
            }
            object::dereference(fdo.cast());
            stack.remove(FDO);
            if is_device(fdo) || !(*pdo).AttachedDevice.is_null() || !is_device(pdo) {
                return Err("removing the function driver's device did not leave the bus's");
            }
            stack.remove(PDO);
            if is_device(pdo) {
                return Err("the last device of the stack was not freed");
            }
            Ok(7)
        })();
        for device in [pdo, fdo, filter] {
            object::dereference(device.cast());
        }
        result
    }
}

/// A device deleted while another is still attached to it stays until
/// that one has detached and its last reference has gone: the deletion
/// is pending, the name is gone, and nothing new can attach to it.
/// Returns the facts checked.
fn delete_then_detach() -> Result<u32, &'static str> {
    let mut stack = Stack::build()?;
    stack.remove(FILTER);
    let [pdo, fdo, _] = stack.devices;
    // SAFETY: as in `detach_then_delete`.
    unsafe {
        object::reference(pdo.cast());
        let result = (|| {
            // The bus driver deletes its device under the function
            // driver's.
            stack.devices[PDO as usize] = core::ptr::null_mut();
            device::IoDeleteDevice(pdo);
            if !is_device(pdo) {
                return Err("a device was freed with another still attached to it");
            }
            if (*(*pdo).DeviceObjectExtension).ExtensionFlags & DOE_DELETE_PENDING == 0 {
                return Err("the deletion is not marked pending in the extension");
            }
            if (*pdo).AttachedDevice != fdo || attached_to(fdo) != pdo {
                return Err("deleting the device below broke the attachment");
            }
            if super::open(PDO_NAME) != Err(STATUS_OBJECT_NAME_NOT_FOUND) {
                return Err("a deleted device can still be opened by name");
            }
            // The function driver lets go. A work item on its way still
            // counts on the device, so it stays, at the top of a stack of
            // its own, and nothing can be attached to it.
            device::reference(pdo);
            device::IoDetachDevice(pdo);
            (*layer(fdo)).lower = core::ptr::null_mut();
            if !attached_to(fdo).is_null() {
                return Err("detaching left the extension's AttachedTo set");
            }
            if !is_device(pdo) {
                return Err("a deleted device was freed while still referenced");
            }
            let other = make_device(stack.drivers[FILTER as usize], FILTER, None)?;
            let attached = device::IoAttachDeviceToDeviceStack(other, pdo);
            if !attached.is_null() {
                device::IoDetachDevice(attached);
            }
            device::IoDeleteDevice(other);
            if !attached.is_null() {
                return Err("a device was attached to one that is being deleted");
            }
            // The last reference goes, and the device with it.
            device::dereference(pdo);
            if is_device(pdo) {
                return Err("the deleted device was not freed when nothing held it any more");
            }
            Ok(8)
        })();
        object::dereference(pdo.cast());
        result
    }
}

/// How often the filter's `FastIoDetachDevice` was called, and with the
/// right devices.
static FAST_DETACHED: AtomicU32 = AtomicU32::new(0);
static FAST_DETACH_SOURCE: AtomicPtr<DEVICE_OBJECT> = AtomicPtr::new(core::ptr::null_mut());

/// The filter's `FastIoDetachDevice`: the device it is attached to is
/// being deleted, so it detaches and deletes its own.
///
/// # Safety
/// Called as a `FastIoDetachDevice` routine.
unsafe extern "C" fn fast_io_detach(source: *mut DEVICE_OBJECT, target: *mut DEVICE_OBJECT) {
    FAST_DETACHED.fetch_add(1, Ordering::AcqRel);
    FAST_DETACH_SOURCE.store(source, Ordering::Release);
    // SAFETY: `source` is the filter's device, attached to `target`.
    unsafe {
        device::IoDetachDevice(target);
        device::IoDeleteDevice(source);
    }
}

/// A driver with a `FastIoDetachDevice` routine is told when the device
/// its own is attached to is deleted, and both go if it detaches and
/// deletes its own there. Returns the facts checked.
fn fast_io_detach_test() -> Result<u32, &'static str> {
    let mut stack = Stack::build()?;
    stack.remove(FILTER);
    let [pdo, fdo, _] = stack.devices;
    // SAFETY: a zeroed dispatch table is one with no routines.
    let mut table: FAST_IO_DISPATCH = unsafe { core::mem::zeroed() };
    table.SizeOfFastIoDispatch = size_of::<FAST_IO_DISPATCH>() as u32;
    table.Routines[FAST_IO_DETACH_DEVICE] = fast_io_detach as *mut c_void;
    FAST_DETACHED.store(0, Ordering::Release);
    // SAFETY: as in `detach_then_delete`; the table outlives the
    // function driver's device.
    unsafe {
        (*stack.drivers[FDO as usize]).FastIoDispatch = (&raw mut table).cast();
        object::reference(pdo.cast());
        object::reference(fdo.cast());
        stack.devices = [core::ptr::null_mut(); 3];
        device::IoDeleteDevice(pdo);
        let gone = !is_device(pdo) && !is_device(fdo);
        object::dereference(pdo.cast());
        object::dereference(fdo.cast());
        (*stack.drivers[FDO as usize]).FastIoDispatch = core::ptr::null_mut();
        if FAST_DETACHED.load(Ordering::Acquire) != 1
            || FAST_DETACH_SOURCE.load(Ordering::Acquire) != fdo
        {
            return Err("the attached driver was not told, once, with its own device");
        }
        if !gone {
            return Err("the devices were not freed when the attached driver let go");
        }
    }
    Ok(4)
}

fn run(report: &mut Report, _: &BootInfo) {
    let mut numbered = |name: &str, result: Result<u32, &'static str>| match result {
        Ok(n) => report.ok_with(name, format_args!("{n} checked")),
        Err(why) => report.fail(name, format_args!("{why}")),
    };
    numbered("io.stack.attach", attach());
    numbered("io.stack.open-goes-to-the-top", open_goes_to_the_top());
    numbered("io.stack.pended-below", pended_below());
    numbered("io.stack.detach-then-delete", detach_then_delete());
    numbered("io.stack.delete-then-detach", delete_then_detach());
    numbered("io.stack.fast-io-detach", fast_io_detach_test());
}
