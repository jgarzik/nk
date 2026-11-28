//! Plug and Play notifications: a driver registers a callback for a
//! category of events (`IoRegisterPlugPlayNotification`) and is called
//! when one happens.
//!
//! The events NK produces are the arrival and the removal of a device
//! interface (`super::interface`), and the custom events drivers report
//! for a device (`IoReportTargetDeviceChangeAsynchronous`), which go to
//! the registrations for that device's changes. A registration for a
//! hardware profile change is kept and never called, nor is one for a
//! device for its removal: NK has one hardware profile and removes no
//! device on request.
//!
//! A callback is called at `PASSIVE_LEVEL` with no lock held: for an
//! interface arrival or removal, on an executive worker thread (as Windows
//! dispatches PnP interface notifications asynchronously, while
//! `PNPNOTIFY_DEVICE_INTERFACE_INCLUDE_EXISTING_INTERFACES` still notifies
//! synchronously before `IoRegisterPlugPlayNotification` returns); for a
//! custom event, on a worker thread. While it runs, the registration counts
//! as in use, and taking it back waits for that to end.

#![allow(non_snake_case)]

use crate::ke::seh::{self, Guard};
use crate::ke::{Rank, SpinLock};
use crate::mm::pool;
use crate::ob::object;
use alloc::string::String;
use alloc::vec::Vec;
use core::ffi::c_void;
use core::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use nk_ntabi::io::{DRIVER_OBJECT, UNICODE_STRING};
use nk_ntabi::pnp::*;
use nk_ntabi::status::*;

/// Monotonic identifier for registrations and unregister claims so queued
/// worker deliveries never match a replacement registration that reused an
/// address (ABA).
static NEXT_ID: AtomicU64 = AtomicU64::new(1);

/// One registration. Its address is the opaque handle handed to the driver;
/// queued notifications match by its monotonic [`id`](Self::id) and category.
struct Registration {
    id: u64,
    category: u32,
    /// For interface changes: the class.
    class: [u8; 16],
    /// For a device's changes: the device (the physical device object
    /// of the file's stack, which the registration holds a reference
    /// to) and the file the driver named.
    target: usize,
    file: usize,
    driver: usize,
    callback: usize,
    context: usize,
    /// Callbacks in progress, and the thread of the last one to begin.
    calls: u32,
    caller: usize,
    /// Taken back: no further callback begins.
    gone: bool,
    /// Claim token of the unregister call that owns finalization (0 = active).
    unregistered_by: u64,
    /// Set when the callback itself unregistered this entry, transferring
    /// removal and reference release to [`call`] on callback return.
    self_unregistered: bool,
}

#[expect(
    clippy::vec_box,
    reason = "a registration's address is the handle a driver holds"
)]
static REGISTRATIONS: SpinLock<Vec<alloc::boxed::Box<Registration>>> =
    SpinLock::new(Rank::DeviceTree, Vec::new());

/// Release the object references held by a removed registration, outside
/// `REGISTRATIONS`.
///
/// # Safety
/// `driver` and (when nonzero) `target` are the registration's own references.
unsafe fn release_refs(driver: usize, target: usize) {
    // SAFETY: per the contract.
    unsafe {
        if target != 0 {
            object::dereference(target as *mut u8);
        }
        object::dereference(driver as *mut u8);
    }
}

/// Call `callback(structure, context)` for the registration `id` of `category`,
/// if it is still registered.
fn call(id: u64, category: u32, structure: *mut c_void) {
    let target = {
        let mut registrations = REGISTRATIONS.lock();
        registrations
            .iter_mut()
            .find(|r| r.id == id && r.category == category && !r.gone)
            .map(|r| {
                r.calls += 1;
                r.caller = crate::ke::pcr::current_thread() as usize;
                (r.callback, r.context)
            })
    };
    let Some((callback, context)) = target else {
        return;
    };
    // SAFETY: a driver's notification callback, registered for this
    // category, called at `PASSIVE_LEVEL` with the structure of that
    // category and the driver's context. Nothing is owed if it is
    // unwound but the count of calls, which is left raised: the
    // registration then cannot be taken back, as an entry Windows'
    // callback never returned from cannot.
    unsafe { seh::call(callback, [structure.addr(), context, 0, 0], &Guard::Nothing) };
    let finalized = {
        let mut registrations = REGISTRATIONS.lock();
        if let Some(at) = registrations.iter().position(|r| r.id == id) {
            registrations[at].calls -= 1;
            // Only remove here when the callback itself unregistered this
            // entry; an external unregister waits for `calls == 0` and owns
            // removal and reference release.
            (registrations[at].self_unregistered && registrations[at].calls == 0).then(|| {
                let removed = registrations.swap_remove(at);
                registrations.shrink_to_fit();
                (removed.driver, removed.target)
            })
        } else {
            None
        }
    };
    if let Some((driver, target)) = finalized {
        // SAFETY: the registration's references, released outside the lock.
        unsafe { release_refs(driver, target) };
    }
}

/// Tell `ids` that the interface `link` of `class` arrived or went.
fn tell(ids: &[u64], class: &[u8; 16], link: &str, arrived: bool) {
    if ids.is_empty() {
        return;
    }
    crate::ke::irql::expect_passive("a Plug and Play notification");
    // The structure and the name are the callbacks' to read during the
    // call: in the pool, reached by pointer only.
    let mut name: Vec<u16> = link.encode_utf16().chain([0]).collect();
    let bytes = size_of::<DEVICE_INTERFACE_CHANGE_NOTIFICATION>() + size_of::<UNICODE_STRING>();
    let block = pool::alloc_zeroed(bytes, super::TAG);
    if block.is_null() {
        return;
    }
    let structure = block.cast::<DEVICE_INTERFACE_CHANGE_NOTIFICATION>();
    // SAFETY: a fresh zeroed block with room for the structure and the
    // counted string behind it; `name` outlives the calls.
    unsafe {
        let string = structure.add(1).cast::<UNICODE_STRING>();
        string.write(UNICODE_STRING {
            Length: ((name.len() - 1) * 2) as u16,
            MaximumLength: (name.len() * 2) as u16,
            Buffer: name.as_mut_ptr(),
        });
        structure.write(DEVICE_INTERFACE_CHANGE_NOTIFICATION {
            Version: 1,
            Size: size_of::<DEVICE_INTERFACE_CHANGE_NOTIFICATION>() as u16,
            Event: if arrived {
                GUID_DEVICE_INTERFACE_ARRIVAL
            } else {
                GUID_DEVICE_INTERFACE_REMOVAL
            },
            InterfaceClassGuid: *class,
            SymbolicLinkName: string,
        });
    }
    for &id in ids {
        call(id, EVENT_CATEGORY_DEVICE_INTERFACE_CHANGE, structure.cast());
    }
    let _ = pool::free(block);
}

/// Number of interface-change work items queued or executing.
static PENDING_INTERFACE: AtomicUsize = AtomicUsize::new(0);

/// Work item payload for asynchronous interface arrival/removal delivery.
struct InterfaceWork {
    item: nk_ntabi::ex::WORK_QUEUE_ITEM,
    ids: Vec<u64>,
    class: [u8; 16],
    link: String,
    arrived: bool,
}

/// Worker routine delivering an interface arrival/removal notification.
///
/// # Safety
/// `parameter` is a boxed [`InterfaceWork`] created by [`interface_changed`].
unsafe extern "C" fn deliver_interface(parameter: *mut c_void) {
    // SAFETY: created with `Box::into_raw` in `interface_changed`.
    let work = unsafe { alloc::boxed::Box::from_raw(parameter.cast::<InterfaceWork>()) };
    tell(&work.ids, &work.class, &work.link, work.arrived);
    drop(work);
    PENDING_INTERFACE.fetch_sub(1, Ordering::Release);
}

/// Wait until all queued interface-change notifications have been delivered.
/// Called at `PASSIVE_LEVEL` with no PnP lock held.
pub fn wait_idle() {
    while PENDING_INTERFACE.load(Ordering::Acquire) != 0 {
        crate::ke::thread::yield_now();
    }
}

/// Notify every `EVENT_CATEGORY_TARGET_DEVICE_CHANGE` registration targeting
/// `pdo` that the device has been removed (`GUID_TARGET_DEVICE_REMOVE_COMPLETE`).
/// Delivered on an executive worker thread so callers holding the PnP engine
/// mutex do not deadlock with callbacks that unregister or close handles.
pub fn device_removed(pdo: usize) {
    let targets: Vec<(u64, usize)> = REGISTRATIONS
        .lock()
        .iter()
        .filter(|r| r.category == EVENT_CATEGORY_TARGET_DEVICE_CHANGE && r.target == pdo && !r.gone)
        .map(|r| (r.id, r.file))
        .collect();
    if targets.is_empty() {
        return;
    }
    struct RemovalWork {
        item: nk_ntabi::ex::WORK_QUEUE_ITEM,
        targets: Vec<(u64, usize)>,
    }
    /// # Safety
    /// `parameter` is a boxed `RemovalWork` queued by `device_removed`.
    unsafe extern "C" fn deliver_removal(parameter: *mut c_void) {
        // SAFETY: created with `Box::into_raw` below.
        let work = unsafe { alloc::boxed::Box::from_raw(parameter.cast::<RemovalWork>()) };
        let block = pool::alloc_zeroed(size_of::<TARGET_DEVICE_REMOVAL_NOTIFICATION>(), super::TAG);
        if !block.is_null() {
            let notif = block.cast::<TARGET_DEVICE_REMOVAL_NOTIFICATION>();
            for &(id, file) in &work.targets {
                // SAFETY: freshly allocated notification block.
                unsafe {
                    notif.write(TARGET_DEVICE_REMOVAL_NOTIFICATION {
                        Version: 1,
                        Size: size_of::<TARGET_DEVICE_REMOVAL_NOTIFICATION>() as u16,
                        Event: GUID_TARGET_DEVICE_REMOVE_COMPLETE,
                        FileObject: file as *mut _,
                    });
                }
                call(id, EVENT_CATEGORY_TARGET_DEVICE_CHANGE, notif.cast());
            }
            let _ = pool::free(block);
        }
        drop(work);
        PENDING_INTERFACE.fetch_sub(1, Ordering::Release);
    }
    let work = alloc::boxed::Box::into_raw(alloc::boxed::Box::new(RemovalWork {
        // SAFETY: plain C struct initialised immediately below.
        item: unsafe { core::mem::zeroed() },
        targets,
    }));
    PENDING_INTERFACE.fetch_add(1, Ordering::AcqRel);
    // SAFETY: `work` stays allocated until `deliver_removal` frees it.
    unsafe {
        (*work).item.WorkerRoutine = Some(deliver_removal);
        (*work).item.Parameter = work.cast();
        crate::ex::work::ExQueueWorkItem(&raw mut (*work).item, nk_ntabi::ex::DELAYED_WORK_QUEUE);
    }
}

/// The interface `link` of `class` was enabled or disabled: queue delivery to
/// every registration for the class on an executive worker thread, avoiding
/// lock inversions when callers hold device or PnP locks while toggling
/// interfaces.
pub fn interface_changed(class: &[u8; 16], link: &str, arrived: bool) {
    let ids: Vec<u64> = REGISTRATIONS
        .lock()
        .iter()
        .filter(|r| {
            r.category == EVENT_CATEGORY_DEVICE_INTERFACE_CHANGE && r.class == *class && !r.gone
        })
        .map(|r| r.id)
        .collect();
    if ids.is_empty() {
        return;
    }
    let work = alloc::boxed::Box::into_raw(alloc::boxed::Box::new(InterfaceWork {
        // SAFETY: `WORK_QUEUE_ITEM` is a plain C struct initialized immediately below.
        item: unsafe { core::mem::zeroed() },
        ids,
        class: *class,
        link: String::from(link),
        arrived,
    }));
    PENDING_INTERFACE.fetch_add(1, Ordering::AcqRel);
    // SAFETY: `work` stays allocated until `deliver_interface` frees it.
    unsafe {
        (*work).item.WorkerRoutine = Some(deliver_interface);
        (*work).item.Parameter = work.cast();
        crate::ex::work::ExQueueWorkItem(&raw mut (*work).item, nk_ntabi::ex::DELAYED_WORK_QUEUE);
    }
}

/// [`IoRegisterPlugPlayNotification`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-ioregisterplugplaynotification):
/// have `callback` called with `context` for events of `category`. The
/// registration holds a reference to `driver` until it is taken back.
///
/// For interface changes, `data` is the class's GUID, and with
/// `PNPNOTIFY_DEVICE_INTERFACE_INCLUDE_EXISTING_INTERFACES` the
/// callback is called, before this returns, for each interface of the
/// class that is enabled now. Registrations of the other two
/// categories are kept and never called (see the top of this file).
///
/// # Safety
/// `driver` is a live driver object; `callback` is a notification
/// callback of that driver; for interface changes `data` points to a
/// GUID; `handle` is writable.
pub unsafe extern "C" fn IoRegisterPlugPlayNotification(
    category: u32,
    flags: u32,
    data: *const c_void,
    driver: *mut DRIVER_OBJECT,
    callback: usize,
    context: usize,
    handle: *mut *mut c_void,
) -> NTSTATUS {
    crate::ke::irql::expect_passive("IoRegisterPlugPlayNotification");
    let class = match category {
        EVENT_CATEGORY_DEVICE_INTERFACE_CHANGE => {
            if data.is_null() {
                return STATUS_INVALID_PARAMETER;
            }
            // SAFETY: per the contract.
            unsafe { data.cast::<[u8; 16]>().read_unaligned() }
        }
        EVENT_CATEGORY_HARDWARE_PROFILE_CHANGE | EVENT_CATEGORY_TARGET_DEVICE_CHANGE => [0; 16],
        _ => return STATUS_INVALID_DEVICE_REQUEST,
    };
    if driver.is_null() || callback == 0 || handle.is_null() {
        return STATUS_INVALID_PARAMETER;
    }
    // A device's changes are those of the device the file's stack says
    // it is (`TargetDeviceRelation`), as Windows asks.
    let (target, file) = if category == EVENT_CATEGORY_TARGET_DEVICE_CHANGE {
        // SAFETY: per the contract, `data` is an open file object.
        match unsafe { related_target(data.cast_mut().cast()) } {
            Ok(target) => (target, data as usize),
            Err(status) => return status,
        }
    } else {
        (0, 0)
    };
    let id = NEXT_ID.fetch_add(1, Ordering::Relaxed);
    let registration = alloc::boxed::Box::new(Registration {
        id,
        category,
        class,
        target,
        file,
        driver: driver as usize,
        callback,
        context,
        calls: 0,
        caller: 0,
        gone: false,
        unregistered_by: 0,
        self_unregistered: false,
    });
    let own = core::ptr::from_ref::<Registration>(&registration) as usize;
    {
        let mut registrations = REGISTRATIONS.lock();
        if registrations.try_reserve_exact(1).is_err() {
            drop(registrations);
            if target != 0 {
                // SAFETY: `related_target` returned a referenced PDO.
                unsafe { object::dereference(target as *mut u8) };
            }
            return STATUS_INSUFFICIENT_RESOURCES;
        }
        registrations.push(registration);
    }
    // SAFETY: per the contract: the registration's reference, and the
    // caller's place for the handle.
    unsafe {
        object::reference(driver.cast());
        handle.write_unaligned(own as *mut c_void);
    }
    if category == EVENT_CATEGORY_DEVICE_INTERFACE_CHANGE
        && flags & PNPNOTIFY_DEVICE_INTERFACE_INCLUDE_EXISTING_INTERFACES != 0
    {
        for link in super::interface::enabled_of(&class) {
            tell(&[id], &class, &link, true);
        }
    }
    STATUS_SUCCESS
}

/// [`IoUnregisterPlugPlayNotificationEx`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-iounregisterplugplaynotificationex):
/// take a registration back. No callback begins after this is called;
/// one in progress on another thread is waited for. Called from inside
/// the registration's own callback, it does not wait for itself.
///
/// # Safety
/// `handle` came from `IoRegisterPlugPlayNotification` and has not
/// been taken back.
pub unsafe extern "C" fn IoUnregisterPlugPlayNotificationEx(handle: *mut c_void) -> NTSTATUS {
    let own = handle as usize;
    let me = crate::ke::pcr::current_thread() as usize;
    let claim = NEXT_ID.fetch_add(1, Ordering::Relaxed);
    let refs = loop {
        {
            let mut registrations = REGISTRATIONS.lock();
            let Some(at) = registrations
                .iter()
                .position(|r| core::ptr::from_ref::<Registration>(r) as usize == own)
            else {
                return STATUS_INVALID_PARAMETER;
            };
            let found = &mut registrations[at];
            if found.unregistered_by == 0 {
                found.gone = true;
                found.unregistered_by = claim;
            } else if found.unregistered_by != claim {
                // Another unregister call (or self-unregister) already claimed this handle.
                return STATUS_INVALID_PARAMETER;
            }
            if found.calls == 0 {
                let removed = registrations.swap_remove(at);
                registrations.shrink_to_fit();
                break Some((removed.driver, removed.target));
            }
            if found.calls == 1 && found.caller == me {
                // Self-unregister from inside the callback: defer removal and
                // reference release to `call` when the callback returns so the
                // driver and target objects stay pinned while it runs.
                found.self_unregistered = true;
                break None;
            }
        }
        // A callback is running on another thread: let it finish.
        crate::ke::thread::yield_now();
    };
    if let Some((driver, target)) = refs {
        // SAFETY: the registration's references, released outside the lock.
        unsafe { release_refs(driver, target) };
    }
    STATUS_SUCCESS
}

/// [`IoUnregisterPlugPlayNotification`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-iounregisterplugplaynotification):
/// as `IoUnregisterPlugPlayNotificationEx`.
///
/// # Safety
/// As `IoUnregisterPlugPlayNotificationEx`.
pub unsafe extern "C" fn IoUnregisterPlugPlayNotification(handle: *mut c_void) -> NTSTATUS {
    // SAFETY: per the contract.
    unsafe { IoUnregisterPlugPlayNotificationEx(handle) }
}

/// A custom event on its way to a worker: the work item, the device,
/// the reporter's callback and its context, then the event's copy.
#[repr(C)]
struct Report {
    item: nk_ntabi::ex::WORK_QUEUE_ITEM,
    device: usize,
    callback: usize,
    context: usize,
}

/// The physical device object a file system's volume answers for, with
/// a reference: the target-device relation of the top of the stack a
/// request on `file` goes to, the file system's volume device on a
/// mounted volume, as Windows' `IoGetRelatedTargetDevice` asks it.
///
/// # Safety
/// `file` is an open file object. Called at `PASSIVE_LEVEL`.
pub unsafe fn related_target(file: *mut nk_ntabi::io::FILE_OBJECT) -> Result<usize, NTSTATUS> {
    // SAFETY: per the contract.
    let reported = unsafe {
        super::query::relations(
            crate::io::file::related_device(file),
            TARGET_DEVICE_RELATION,
        )
    }?
    .ok_or(STATUS_NOT_SUPPORTED)?;
    let (first, rest) = reported.split_first().ok_or(STATUS_NOT_SUPPORTED)?;
    for extra in rest {
        // SAFETY: each device the driver reported comes referenced.
        unsafe { object::dereference(*extra as *mut u8) };
    }
    Ok(*first)
}

/// A report of `notification` for `device`, copied into a block for
/// [`deliver`]; `Err` with Windows' status for an event a driver may not
/// report, a structure too short, or no memory.
///
/// # Safety
/// `device` is a physical device object; `notification` is readable for
/// its `Size`.
unsafe fn report(
    device: *mut nk_ntabi::io::DEVICE_OBJECT,
    notification: *const TARGET_DEVICE_CUSTOM_NOTIFICATION,
    callback: usize,
    context: usize,
) -> Result<*mut u8, NTSTATUS> {
    // SAFETY: per the contract; the header is read field by field.
    let (event, size, name) = unsafe {
        (
            (&raw const (*notification).Event).read_unaligned(),
            usize::from((&raw const (*notification).Size).read_unaligned()),
            (&raw const (*notification).NameBufferOffset).read_unaligned(),
        )
    };
    let predefined = [
        GUID_TARGET_DEVICE_QUERY_REMOVE,
        GUID_TARGET_DEVICE_REMOVE_CANCELLED,
        GUID_TARGET_DEVICE_REMOVE_COMPLETE,
    ];
    let data = size.wrapping_sub(TARGET_DEVICE_CUSTOM_HEADER);
    if predefined.contains(&event)
        || size < TARGET_DEVICE_CUSTOM_HEADER
        || (name != -1 && name as isize > data as isize)
    {
        return Err(STATUS_INVALID_DEVICE_REQUEST);
    }
    let block = pool::alloc(size_of::<Report>() + size, super::TAG);
    if block.is_null() {
        return Err(STATUS_INSUFFICIENT_RESOURCES);
    }
    // SAFETY: a fresh block with room for the report and the copy; the
    // device is referenced until the report is delivered.
    unsafe {
        object::reference(device.cast());
        let record = block.cast::<Report>();
        record.write(Report {
            item: core::mem::zeroed(),
            device: device as usize,
            callback,
            context,
        });
        core::ptr::copy_nonoverlapping(
            notification.cast::<u8>(),
            block.add(size_of::<Report>()),
            size,
        );
        (*record).item.WorkerRoutine = Some(deliver);
        (*record).item.Parameter = block.cast();
    }
    Ok(block)
}

/// [`IoReportTargetDeviceChangeAsynchronous`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-ioreporttargetdevicechangeasynchronous):
/// tell the registrations for `device`'s changes of the custom event
/// `notification`, from a worker thread, each with its own file object
/// in the structure; then call `callback` with `context`, if given. The
/// event is copied, and `STATUS_PENDING` answered at once. One of the
/// predefined removal events, or a structure too short for its header
/// or its name, is `STATUS_INVALID_DEVICE_REQUEST`, as Windows answers.
///
/// # Safety
/// `device` is a physical device object; `notification` is readable for
/// its `Size`; `callback` is null or a routine of the caller's.
pub unsafe extern "C" fn IoReportTargetDeviceChangeAsynchronous(
    device: *mut nk_ntabi::io::DEVICE_OBJECT,
    notification: *const TARGET_DEVICE_CUSTOM_NOTIFICATION,
    callback: usize,
    context: usize,
) -> NTSTATUS {
    // SAFETY: per the contract.
    match unsafe { report(device, notification, callback, context) } {
        Ok(block) => {
            // SAFETY: the block `report` made, its work item set up.
            unsafe {
                let record = block.cast::<Report>();
                crate::ex::work::ExQueueWorkItem(
                    &raw mut (*record).item,
                    nk_ntabi::ex::DELAYED_WORK_QUEUE,
                );
            }
            STATUS_PENDING
        }
        Err(status) => status,
    }
}

/// What Windows' `IoReportTargetDeviceChange` does for a custom event:
/// tell the registrations for `device` before returning, in the
/// caller's thread.
///
/// # Safety
/// As [`IoReportTargetDeviceChangeAsynchronous`], at `PASSIVE_LEVEL`.
pub unsafe fn report_target_change(
    device: *mut nk_ntabi::io::DEVICE_OBJECT,
    notification: *const TARGET_DEVICE_CUSTOM_NOTIFICATION,
) -> NTSTATUS {
    // SAFETY: per the contract.
    match unsafe { report(device, notification, 0, 0) } {
        Ok(block) => {
            // SAFETY: the block `report` made; `deliver` frees it.
            unsafe { deliver(block.cast()) };
            STATUS_SUCCESS
        }
        Err(status) => status,
    }
}

/// The worker's part of [`IoReportTargetDeviceChangeAsynchronous`].
///
/// # Safety
/// `parameter` is the report's block.
unsafe extern "C" fn deliver(parameter: *mut c_void) {
    let block = parameter.cast::<u8>();
    // SAFETY: per the contract; the copy is the kernel's, handed to each
    // callback in turn.
    unsafe {
        let report = block.cast::<Report>();
        let device = (*report).device;
        let copy = block
            .add(size_of::<Report>())
            .cast::<TARGET_DEVICE_CUSTOM_NOTIFICATION>();
        let targets: Vec<(u64, usize)> = REGISTRATIONS
            .lock()
            .iter()
            .filter(|r| {
                r.category == EVENT_CATEGORY_TARGET_DEVICE_CHANGE && r.target == device && !r.gone
            })
            .map(|r| (r.id, r.file))
            .collect();
        for (id, file) in targets {
            (&raw mut (*copy).FileObject).write_unaligned(file as *mut _);
            call(id, EVENT_CATEGORY_TARGET_DEVICE_CHANGE, copy.cast());
        }
        let (callback, context) = ((*report).callback, (*report).context);
        if callback != 0 {
            // SAFETY: the reporter's routine, called at `PASSIVE_LEVEL`
            // with its context. Nothing is owed if it is unwound.
            seh::call(callback, [context, 0, 0, 0], &Guard::Nothing);
        }
        object::dereference(device as *mut u8);
        let _ = pool::free(block);
    }
}
