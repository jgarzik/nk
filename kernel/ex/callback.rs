//! [Callback objects](https://learn.microsoft.com/en-us/windows-hardware/drivers/kernel/callback-objects):
//! a named place where drivers register routines and whoever owns the
//! condition calls them all (`ExCreateCallback`, `ExRegisterCallback`,
//! `ExUnregisterCallback`, `ExNotifyCallback`).
//!
//! A callback object is an object-manager object of type `Callback`,
//! and the ones with names live in `\Callback`. Its body is NK's own: a
//! list of registrations. A registration is a pool block that holds a
//! reference to its object; its address is the handle
//! `ExRegisterCallback` returns.
//!
//! One lock, [`LOCK`], covers every object's list and every
//! registration (`doc/LOCKING.md`). A notification holds it only
//! between routines: a routine is called with the lock dropped, at the
//! caller's IRQL, its registration marked busy so that unregistering
//! waits for it. Unregistering from inside the routine being called
//! therefore never returns, as on Windows.
//!
//! # The system's callback objects
//!
//! Windows makes `\Callback\SetSystemTime`, `\Callback\PowerState` and
//! `\Callback\ProcessorAdd` at start, and drivers open them without
//! asking for them to be created. NK makes them too. It never notifies
//! them: its time is not set, it has no power transitions, and no
//! processor is added after start.
//!
//! # What is not Windows'
//!
//! Creating a named object relative to a directory handle is refused
//! with `STATUS_NOT_IMPLEMENTED`; opening one that way works. A named
//! object made without `OBJ_PERMANENT` has no name, which is what is
//! left of its name on Windows once `ExCreateCallback` has closed the
//! handle it made the object with.

#![allow(non_snake_case)]

use crate::ke::seh::{self, Guard};
use crate::ke::{Rank, SpinLock, wait};
use crate::mm::pool;
use crate::ob::{self, object};
use core::ffi::c_void;
use core::mem::MaybeUninit;
use nk_ntabi::ke::{KEVENT, LIST_ENTRY};
use nk_ntabi::ob::OBJECT_ATTRIBUTES;
use nk_ntabi::status::*;

/// Pool tag of registrations.
const TAG: u32 = u32::from_le_bytes(*b"CBRe");

/// `OBJ_PERMANENT`.
const OBJ_PERMANENT: u32 = 0x10;

/// The body of a callback object.
#[repr(C)]
struct Callback {
    /// The registrations, oldest first.
    registrations: LIST_ENTRY,
    /// Whether more than one routine may be registered.
    allow_multiple: bool,
}

/// One registered routine.
#[repr(C)]
struct Registration {
    /// First: a registration is found from its place in the list.
    links: LIST_ENTRY,
    /// The object, which the registration holds a reference to.
    callback: *mut Callback,
    function: usize,
    context: usize,
    /// Notifications in the middle of calling the routine.
    busy: u32,
    /// The event of the thread unregistering this, once it waits for
    /// `busy` to be nothing; from then on no notification calls the
    /// routine.
    leaving: *mut KEVENT,
}

/// Every callback object's list of registrations, and every
/// registration's `busy` and `leaving`.
static LOCK: SpinLock<()> = SpinLock::new(Rank::Callbacks, ());

/// The names of the callback objects Windows makes at start.
const SYSTEM: [&str; 3] = [
    "\\Callback\\SetSystemTime",
    "\\Callback\\PowerState",
    "\\Callback\\ProcessorAdd",
];

fn wide(text: &str) -> alloc::vec::Vec<u16> {
    text.encode_utf16().collect()
}

/// A new callback object, with one reference: unnamed, or to be given
/// the name `leaf` in a directory.
fn create(leaf: Option<&[u16]>, allow_multiple: bool) -> Option<*mut u8> {
    let size = size_of::<Callback>();
    let body = match leaf {
        Some(leaf) => object::create_named(&object::CALLBACK_TYPE, size, leaf),
        None => object::create(&object::CALLBACK_TYPE, size),
    }?;
    let callback = body.cast::<Callback>();
    // SAFETY: fresh storage of a callback's size, which nothing else
    // has yet.
    unsafe {
        let head = &raw mut (*callback).registrations;
        head.write(LIST_ENTRY {
            Flink: head,
            Blink: head,
        });
        (&raw mut (*callback).allow_multiple).write(allow_multiple);
    }
    Some(body)
}

/// Make a callback object that has the name `path` for good. The
/// namespace keeps the reference the object was made with.
fn create_permanent(path: &[u16], allow_multiple: bool) -> Result<*mut u8, NTSTATUS> {
    let body = create(Some(ob::leaf(path)), allow_multiple).ok_or(STATUS_INSUFFICIENT_RESOURCES)?;
    // SAFETY: made above with the path's last component as its name;
    // its reference is never given up.
    match unsafe { ob::insert(path, body) } {
        STATUS_SUCCESS => Ok(body),
        status => {
            // SAFETY: the creating reference; the object has no name.
            unsafe { object::dereference(body) };
            Err(status)
        }
    }
}

/// Make the callback objects Windows has from the start.
pub fn init() -> Result<(), &'static str> {
    for name in SYSTEM {
        create_permanent(&wide(name), true)
            .map_err(|_| "cannot make the system's callback objects")?;
    }
    Ok(())
}

/// [`ExCreateCallback`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-excreatecallback):
/// open the callback object the attributes name, or make one if there
/// is none and `create` says to. The caller gets a reference, to drop
/// with `ObDereferenceObject`.
///
/// Partial: see the top of the file.
///
/// # Safety
/// `callback_object` is writable and `object_attributes` points to
/// initialised `OBJECT_ATTRIBUTES`.
pub unsafe extern "C" fn ExCreateCallback(
    callback_object: *mut *mut c_void,
    object_attributes: *const OBJECT_ATTRIBUTES,
    create: u8,
    allow_multiple_callbacks: u8,
) -> NTSTATUS {
    // SAFETY: per the contract; the driver's memory, read field by
    // field.
    let (root, name, attributes) = unsafe {
        (
            (&raw const (*object_attributes).RootDirectory).read_unaligned(),
            (&raw const (*object_attributes).ObjectName).read_unaligned(),
            (&raw const (*object_attributes).Attributes).read_unaligned(),
        )
    };
    // SAFETY: per the contract, a counted string or null.
    let path = (!name.is_null()).then(|| unsafe { crate::rtl::copy_unicode(name) });
    // An object of that name, if there is one.
    let mut status = STATUS_UNSUCCESSFUL;
    if let Some(path) = &path {
        let start = (!root.is_null()).then_some(root.cast::<u8>());
        match ob::lookup(start, path) {
            Ok((body, rest)) => {
                // SAFETY: `lookup` returned the object referenced.
                let is_callback = unsafe {
                    core::ptr::eq(
                        object::type_of(body.body()),
                        &raw const object::CALLBACK_TYPE,
                    )
                };
                if rest.is_empty() && is_callback {
                    // SAFETY: per the contract; the reference is the
                    // driver's.
                    unsafe { callback_object.write_unaligned(body.into_raw().cast()) };
                    return STATUS_SUCCESS;
                }
                status = if rest.is_empty() {
                    STATUS_OBJECT_TYPE_MISMATCH
                } else {
                    STATUS_OBJECT_PATH_NOT_FOUND
                };
            }
            Err(why) => status = why,
        }
    }
    if create == 0 {
        return status;
    }
    let allow_multiple = allow_multiple_callbacks != 0;
    let made = match &path {
        Some(_) if !root.is_null() => Err(STATUS_NOT_IMPLEMENTED),
        Some(path) if attributes & OBJ_PERMANENT != 0 => {
            create_permanent(path, allow_multiple).inspect(|&body| {
                // SAFETY: the namespace holds the object; this is the
                // caller's reference.
                unsafe { object::reference(body) };
            })
        }
        _ => self::create(None, allow_multiple).ok_or(STATUS_INSUFFICIENT_RESOURCES),
    };
    match made {
        Ok(body) => {
            // SAFETY: per the contract.
            unsafe { callback_object.write_unaligned(body.cast()) };
            STATUS_SUCCESS
        }
        Err(status) => status,
    }
}

/// [`ExRegisterCallback`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-exregistercallback):
/// have `callback_function(context, argument1, argument2)` called at
/// every notification of the object. Returns what to unregister with;
/// null if there is no memory, or the object takes one routine and has
/// one.
///
/// # Safety
/// `callback_object` is a callback object the caller holds a reference
/// to; the routine may be called so until it is unregistered.
pub unsafe extern "C" fn ExRegisterCallback(
    callback_object: *mut c_void,
    callback_function: *const c_void,
    callback_context: *mut c_void,
) -> *mut c_void {
    let callback = callback_object.cast::<Callback>();
    let registration = pool::alloc(size_of::<Registration>(), TAG).cast::<Registration>();
    if registration.is_null() {
        return core::ptr::null_mut();
    }
    // SAFETY: per the contract; the block is fresh, and the list is
    // changed under its lock.
    let registered = unsafe {
        object::reference(callback.cast());
        let head = &raw mut (*callback).registrations;
        let _lock = LOCK.lock();
        let last = (&raw const (*head).Blink).read();
        if last != head && !(&raw const (*callback).allow_multiple).read() {
            false
        } else {
            registration.write(Registration {
                links: LIST_ENTRY {
                    Flink: head,
                    Blink: last,
                },
                callback,
                function: callback_function.addr(),
                context: callback_context.addr(),
                busy: 0,
                leaving: core::ptr::null_mut(),
            });
            (&raw mut (*last).Flink).write(registration.cast());
            (&raw mut (*head).Blink).write(registration.cast());
            true
        }
    };
    if registered {
        return registration.cast();
    }
    // SAFETY: the reference and the block taken above.
    unsafe {
        object::dereference(callback.cast());
        pool::ExFreePoolWithTag(registration.cast(), TAG);
    }
    core::ptr::null_mut()
}

/// [`ExUnregisterCallback`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-exunregistercallback):
/// stop the routine being called, waiting for any call of it that is
/// under way. For below `DISPATCH_LEVEL`, and not for the routine
/// itself.
///
/// # Safety
/// `callback_registration` came from `ExRegisterCallback` and is
/// unregistered once.
pub unsafe extern "C" fn ExUnregisterCallback(callback_registration: *mut c_void) {
    let registration = callback_registration.cast::<Registration>();
    let mut storage = MaybeUninit::<KEVENT>::uninit();
    let event = storage.as_mut_ptr();
    // SAFETY: per the contract; the registration is live until this
    // frees it, and its fields are read and written under the lock.
    unsafe {
        loop {
            {
                let _lock = LOCK.lock();
                if (&raw const (*registration).busy).read() == 0 {
                    let LIST_ENTRY { Flink, Blink } = (&raw const (*registration).links).read();
                    (&raw mut (*Blink).Flink).write(Flink);
                    (&raw mut (*Flink).Blink).write(Blink);
                    break;
                }
                // The frame stays until the last call under way sets
                // the event.
                wait::KeInitializeEvent(event, 1, 0);
                (&raw mut (*registration).leaving).write(event);
            }
            wait::wait(Some(event.cast()), None);
        }
        object::dereference((&raw const (*registration).callback).read().cast());
        pool::ExFreePoolWithTag(registration.cast(), TAG);
    }
}

/// One call of a registration's routine is over: under the lock, count
/// it off, and answer the event to set if a thread unregistering waits
/// for that.
///
/// # Safety
/// `registration` is live and counted busy by the caller, which holds
/// the lock.
unsafe fn called(registration: *mut Registration) -> *mut KEVENT {
    // SAFETY: per the contract.
    unsafe {
        let busy = (&raw const (*registration).busy).read() - 1;
        (&raw mut (*registration).busy).write(busy);
        if busy == 0 {
            (&raw const (*registration).leaving).read()
        } else {
            core::ptr::null_mut()
        }
    }
}

/// What a notification owes if a routine does not return: its
/// registration is no longer busy.
///
/// # Safety
/// `registration` is a registration the unwound call had counted busy.
unsafe fn abandoned(registration: *mut c_void) {
    // SAFETY: per the contract.
    unsafe {
        let waiter = {
            let _lock = LOCK.lock();
            called(registration.cast())
        };
        if !waiter.is_null() {
            wait::KeSetEvent(waiter, 0, 0);
        }
    }
}

/// [`ExNotifyCallback`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-exnotifycallback):
/// call every routine registered with the object, oldest first, each
/// with its own context and these two arguments, at the caller's IRQL.
///
/// # Safety
/// `callback_object` is null or a callback object the caller holds a
/// reference to.
pub unsafe extern "C" fn ExNotifyCallback(
    callback_object: *mut c_void,
    argument1: *mut c_void,
    argument2: *mut c_void,
) {
    if callback_object.is_null() {
        return;
    }
    let callback = callback_object.cast::<Callback>();
    // An event owed to a thread unregistering, set at the next moment
    // the lock is not held.
    let mut owed = core::ptr::null_mut::<KEVENT>();
    // SAFETY: per the contract. A registration counted busy stays in
    // the list, so the walk goes on from it once its routine returns.
    unsafe {
        let head = &raw mut (*callback).registrations;
        let mut lock = LOCK.lock();
        let mut at = (&raw const (*head).Flink).read();
        while at != head {
            let registration = at.cast::<Registration>();
            if (&raw const (*registration).leaving).read().is_null() {
                (&raw mut (*registration).busy).write((&raw const (*registration).busy).read() + 1);
                let function = (&raw const (*registration).function).read();
                let context = (&raw const (*registration).context).read();
                drop(lock);
                if !owed.is_null() {
                    wait::KeSetEvent(owed, 0, 0);
                }
                // The driver's routine, with no lock held. If it does
                // not return, the registration is counted off all the
                // same.
                seh::call(
                    function,
                    [context, argument1.addr(), argument2.addr(), 0],
                    &Guard::Undo {
                        undo: abandoned,
                        context: registration.cast(),
                    },
                );
                lock = LOCK.lock();
                owed = called(registration);
            }
            at = (&raw const (*at).Flink).read();
        }
        drop(lock);
        if !owed.is_null() {
            wait::KeSetEvent(owed, 0, 0);
        }
    }
}

/// A routine for the test: add its context and arguments up.
extern "C" fn tally(context: *mut c_void, argument1: *mut c_void, argument2: *mut c_void) {
    TALLY.fetch_add(
        context.addr() + argument1.addr() * 16 + argument2.addr() * 256,
        core::sync::atomic::Ordering::AcqRel,
    );
}

static TALLY: core::sync::atomic::AtomicUsize = core::sync::atomic::AtomicUsize::new(0);

/// Routines registered with an object are called with their contexts
/// and the notification's arguments until unregistered; an object for
/// one routine takes one; and the system's objects are found by name.
/// Returns the routines called.
pub fn self_test() -> Result<u32, &'static str> {
    use core::sync::atomic::Ordering;
    use nk_ntabi::io::UNICODE_STRING;
    let none = core::ptr::null_mut::<c_void>();
    let number = |n: usize| core::ptr::without_provenance_mut::<c_void>(n);
    let attributes = |name: *const UNICODE_STRING| OBJECT_ATTRIBUTES {
        Length: size_of::<OBJECT_ATTRIBUTES>() as u32,
        RootDirectory: none,
        ObjectName: name,
        Attributes: 0x40,
        SecurityDescriptor: none,
        SecurityQualityOfService: none,
    };
    let counted = |text: &mut [u16]| UNICODE_STRING {
        Length: (text.len() * 2) as u16,
        MaximumLength: (text.len() * 2) as u16,
        Buffer: text.as_mut_ptr(),
    };
    TALLY.store(0, Ordering::Release);
    // `ExCreateCallback` with attributes that name `name`, or nothing.
    let open = |out: *mut *mut c_void, name: *const UNICODE_STRING, create: u8, many: u8| {
        let attributes = attributes(name);
        // SAFETY: `out` is a local of the test's, and the attributes are
        // initialised.
        unsafe { ExCreateCallback(out, &raw const attributes, create, many) }
    };
    // SAFETY: every pointer is to a local; each object opened is
    // dereferenced, and each routine registered is unregistered.
    unsafe {
        // The system's object, by name, without creating.
        let mut name = wide("\\Callback\\PowerState");
        let name = counted(&mut name);
        let mut system = none;
        if open(&raw mut system, &raw const name, 0, 1) != STATUS_SUCCESS || system.is_null() {
            return Err("\\Callback\\PowerState was not found by name");
        }
        let mut again = none;
        let found = open(&raw mut again, &raw const name, 1, 1);
        if found == STATUS_SUCCESS {
            object::dereference(again.cast());
        }
        object::dereference(system.cast());
        if found != STATUS_SUCCESS || again != system {
            return Err("opening a callback object that exists made another");
        }
        let mut absent = wide("\\Callback\\NkNoSuchCallback");
        let absent = counted(&mut absent);
        let mut nothing = none;
        if open(&raw mut nothing, &raw const absent, 0, 1) != STATUS_OBJECT_NAME_NOT_FOUND
            || open(&raw mut nothing, core::ptr::null(), 0, 1) != STATUS_UNSUCCESSFUL
        {
            return Err("a callback object that is not there was opened");
        }

        // An object of the test's own, for many routines.
        let mut many = none;
        if open(&raw mut many, core::ptr::null(), 1, 1) != STATUS_SUCCESS {
            return Err("ExCreateCallback did not make an unnamed object");
        }
        let routine = tally as *const c_void;
        let first = ExRegisterCallback(many, routine, number(1));
        let second = ExRegisterCallback(many, routine, number(2));
        let result = (|| {
            if first.is_null() || second.is_null() {
                return Err("two routines could not be registered");
            }
            ExNotifyCallback(many, number(3), number(4));
            // Both contexts, and the arguments twice.
            if TALLY.swap(0, Ordering::AcqRel) != 3 + 2 * (3 * 16 + 4 * 256) {
                return Err("a notification did not call both routines with their arguments");
            }
            Ok(())
        })();
        if !first.is_null() {
            ExUnregisterCallback(first);
        }
        ExNotifyCallback(many, number(1), none);
        let one = TALLY.swap(0, Ordering::AcqRel);
        if !second.is_null() {
            ExUnregisterCallback(second);
        }
        ExNotifyCallback(many, number(1), none);
        ExNotifyCallback(none, none, none);
        let nobody = TALLY.swap(0, Ordering::AcqRel);
        object::dereference(many.cast());
        result?;
        if one != 2 + 16 || nobody != 0 {
            return Err("an unregistered routine was called, or a registered one was not");
        }

        // An object for one routine takes one.
        let mut single = none;
        if open(&raw mut single, core::ptr::null(), 1, 0) != STATUS_SUCCESS {
            return Err("ExCreateCallback did not make an object for one routine");
        }
        let only = ExRegisterCallback(single, routine, number(1));
        let refused = ExRegisterCallback(single, routine, number(2));
        if !refused.is_null() {
            ExUnregisterCallback(refused);
        }
        if !only.is_null() {
            ExUnregisterCallback(only);
        }
        object::dereference(single.cast());
        if only.is_null() || !refused.is_null() {
            return Err("an object for one routine did not take exactly one");
        }
    }
    Ok(3)
}
