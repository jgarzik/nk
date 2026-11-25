//! Objects with a header: a reference count, a handle count and a type.
//!
//! What the object manager allocates has an `OBJECT_HEADER` in front of
//! it, laid out as on Windows. A pointer to an object is a pointer to
//! its body; the header is found by stepping back. An object lives until
//! its last reference is dropped: handles hold references, and so does
//! anything that was given a pointer by `ObReferenceObjectByHandle`.
//!
//! A type is an `OBJECT_TYPE` laid out as on Windows. A driver names a
//! type by the value of a variable it imports (`*ExEventObjectType`),
//! the type's address. An object's header names its type the way
//! Windows 10 does: by the type's index, hidden behind a cookie chosen
//! at boot and a byte of the header's own address.

#![allow(non_snake_case, non_upper_case_globals)]

use crate::mm::pool;
use core::ffi::c_void;
use core::sync::atomic::{AtomicI64, AtomicU8, Ordering};
use nk_ntabi::io::UNICODE_STRING;
use nk_ntabi::ke::LIST_ENTRY;
use nk_ntabi::ob::{
    GENERIC_MAPPING, OB_DELETE_METHOD, OBJECT_BODY, OBJECT_HEADER, OBJECT_TYPE,
    OBJECT_TYPE_INITIALIZER,
};
use nk_ob::header::{FIRST_TYPE_INDEX, type_index};

/// Pool tag of object-manager allocations.
const TAG: u32 = u32::from_le_bytes(*b"ObNK");

/// A kind of object.
#[repr(transparent)]
pub struct ObjectType(OBJECT_TYPE);

// SAFETY: a type is never written after it is built, and its pointers
// name statics.
unsafe impl Sync for ObjectType {}

/// A type's name, as UTF-16.
const fn wide<const N: usize>(name: &[u8; N]) -> [u16; N] {
    let mut out = [0; N];
    let mut i = 0;
    while i < N {
        out[i] = name[i] as u16;
        i += 1;
    }
    out
}

impl ObjectType {
    /// The type numbered `index`, called `name`. `delete` is called
    /// with the body when the last reference has gone, before the
    /// object's memory is freed: it gives up what the object owns.
    const fn new(index: u8, name: &'static [u16], delete: Option<OB_DELETE_METHOD>) -> Self {
        const EMPTY: LIST_ENTRY = LIST_ENTRY {
            Flink: core::ptr::null_mut(),
            Blink: core::ptr::null_mut(),
        };
        Self(OBJECT_TYPE {
            TypeList: EMPTY,
            Name: UNICODE_STRING {
                Length: (name.len() * 2) as u16,
                MaximumLength: (name.len() * 2) as u16,
                Buffer: name.as_ptr().cast_mut(),
            },
            DefaultObject: core::ptr::null_mut(),
            Index: index,
            TotalNumberOfObjects: 0,
            TotalNumberOfHandles: 0,
            HighWaterNumberOfObjects: 0,
            HighWaterNumberOfHandles: 0,
            TypeInfo: OBJECT_TYPE_INITIALIZER {
                Length: size_of::<OBJECT_TYPE_INITIALIZER>() as u16,
                ObjectTypeFlags: 0,
                ObjectTypeCode: 0,
                InvalidAttributes: 0,
                GenericMapping: GENERIC_MAPPING {
                    GenericRead: 0,
                    GenericWrite: 0,
                    GenericExecute: 0,
                    GenericAll: 0,
                },
                ValidAccessMask: 0,
                RetainAccess: 0,
                PoolType: 0,
                DefaultPagedPoolCharge: 0,
                DefaultNonPagedPoolCharge: 0,
                DumpProcedure: core::ptr::null_mut(),
                OpenProcedure: core::ptr::null_mut(),
                CloseProcedure: core::ptr::null_mut(),
                DeleteProcedure: delete,
                ParseProcedure: core::ptr::null_mut(),
                SecurityProcedure: core::ptr::null_mut(),
                QueryNameProcedure: core::ptr::null_mut(),
                OkayToCloseProcedure: core::ptr::null_mut(),
                WaitObjectFlagMask: 0,
                WaitObjectFlagOffset: 0,
                WaitObjectPointerOffset: 0,
            },
            TypeLock: 0,
            Key: 0,
            CallbackList: EMPTY,
        })
    }

    /// The type's name.
    pub fn name(&self) -> &'static [u16] {
        // SAFETY: `new` made the counted string from a static slice.
        unsafe {
            core::slice::from_raw_parts(self.0.Name.Buffer, usize::from(self.0.Name.Length) / 2)
        }
    }
}

static EVENT_NAME: [u16; 5] = wide(b"Event");
static THREAD_NAME: [u16; 6] = wide(b"Thread");
static DEVICE_NAME: [u16; 6] = wide(b"Device");
static KEY_NAME: [u16; 3] = wide(b"Key");
static PROCESS_NAME: [u16; 7] = wide(b"Process");
static TOKEN_NAME: [u16; 5] = wide(b"Token");

/// Events (`KEVENT`).
pub static EVENT_TYPE: ObjectType = ObjectType::new(FIRST_TYPE_INDEX, &EVENT_NAME, None);
/// Threads (`ETHREAD`).
pub static THREAD_TYPE: ObjectType = ObjectType::new(FIRST_TYPE_INDEX + 1, &THREAD_NAME, None);
/// Devices (`DEVICE_OBJECT`).
pub static DEVICE_TYPE: ObjectType = ObjectType::new(
    FIRST_TYPE_INDEX + 2,
    &DEVICE_NAME,
    Some(crate::io::device::deleted),
);
/// Registry keys: an open key's object names the key (`cm`).
pub static KEY_TYPE: ObjectType =
    ObjectType::new(FIRST_TYPE_INDEX + 3, &KEY_NAME, Some(crate::cm::closed));

/// Processes (`EPROCESS`).
pub static PROCESS_TYPE: ObjectType = ObjectType::new(FIRST_TYPE_INDEX + 4, &PROCESS_NAME, None);

/// Access tokens: the body is NK's own (`se::token`).
pub static TOKEN_TYPE: ObjectType = ObjectType::new(
    FIRST_TYPE_INDEX + 5,
    &TOKEN_NAME,
    Some(crate::se::token::deleted),
);

/// Every type, by index from `FIRST_TYPE_INDEX`.
static TYPES: [&ObjectType; 6] = [
    &EVENT_TYPE,
    &THREAD_TYPE,
    &DEVICE_TYPE,
    &KEY_TYPE,
    &PROCESS_TYPE,
    &TOKEN_TYPE,
];

/// What hides type indices in object headers. Chosen once, before the
/// first object is made.
static COOKIE: AtomicU8 = AtomicU8::new(0);

/// Choose the cookie from `seed`. Called once, before any object exists.
pub fn init(seed: u64) {
    COOKIE.store((seed ^ seed >> 8 ^ seed >> 16) as u8, Ordering::Relaxed);
}

/// A variable a driver imports to name a type: it holds the type's
/// address.
#[repr(transparent)]
pub struct TypeVariable(*const ObjectType);

// SAFETY: immutable, and the pointer names a static.
unsafe impl Sync for TypeVariable {}

/// [`ExEventObjectType`](https://learn.microsoft.com/en-us/windows-hardware/drivers/kernel/object-reference-tracing-with-tags):
/// what a driver passes to `ObReferenceObjectByHandle` to insist on an
/// event.
pub static ExEventObjectType: TypeVariable = TypeVariable(&raw const EVENT_TYPE);

/// [`PsThreadType`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-obreferenceobjectbyhandle):
/// what a driver passes to insist on a thread.
pub static PsThreadType: TypeVariable = TypeVariable(&raw const THREAD_TYPE);

/// `IoDeviceObjectType` (`wdm.h`): what a driver passes to insist on a
/// device.
pub static IoDeviceObjectType: TypeVariable = TypeVariable(&raw const DEVICE_TYPE);

impl TypeVariable {
    /// The address drivers import.
    pub const fn address(&'static self) -> *const () {
        core::ptr::from_ref(self).cast()
    }

    /// The value drivers read from it.
    pub fn value(&self) -> *const ObjectType {
        self.0
    }
}

fn header(body: *mut u8) -> *mut OBJECT_HEADER {
    body.wrapping_sub(OBJECT_BODY).cast()
}

/// # Safety
/// `body` is a live object from [`create`].
unsafe fn pointer_count<'a>(body: *mut u8) -> &'a AtomicI64 {
    // SAFETY: per the contract.
    unsafe { AtomicI64::from_ptr(&raw mut (*header(body)).PointerCount) }
}

/// # Safety
/// `body` is a live object from [`create`].
pub unsafe fn handle_count<'a>(body: *mut u8) -> &'a AtomicI64 {
    // SAFETY: per the contract.
    unsafe { AtomicI64::from_ptr(&raw mut (*header(body)).HandleCount) }
}

/// Allocate a zeroed object of `size` bytes and type `ty`, with one
/// reference: the caller's.
pub fn create(ty: &'static ObjectType, size: usize) -> Option<*mut u8> {
    let block = pool::alloc_zeroed(OBJECT_BODY + size, TAG);
    if block.is_null() {
        return None;
    }
    // SAFETY: a fresh, zeroed block large enough for the header, which
    // the pool aligns to 16 bytes.
    unsafe {
        let header = block.cast::<OBJECT_HEADER>();
        (&raw mut (*header).PointerCount).write(1);
        (&raw mut (*header).TypeIndex).write(type_index(
            ty.0.Index,
            COOKIE.load(Ordering::Relaxed),
            header as u64,
        ));
    }
    Some(block.wrapping_add(OBJECT_BODY))
}

/// The type of an object.
///
/// # Safety
/// `body` is a live object from [`create`].
pub unsafe fn type_of(body: *mut u8) -> &'static ObjectType {
    let header = header(body);
    // SAFETY: per the contract; the byte was written by `create`.
    let stored = unsafe { (&raw const (*header).TypeIndex).read() };
    let index = type_index(stored, COOKIE.load(Ordering::Relaxed), header as u64);
    match TYPES.get(usize::from(index.wrapping_sub(FIRST_TYPE_INDEX))) {
        Some(ty) => ty,
        None => crate::kd::bugcheck(format_args!(
            "0x00000189 BAD_OBJECT_HEADER: an object's header names no type"
        )),
    }
}

/// Take a reference. Returns the new count.
///
/// # Safety
/// `body` is a live object from [`create`] to which the caller already
/// holds a reference, or which it found under a lock that keeps it
/// alive.
pub unsafe fn reference(body: *mut u8) -> i64 {
    // SAFETY: per the contract.
    unsafe { pointer_count(body) }.fetch_add(1, Ordering::AcqRel) + 1
}

/// Drop a reference; the last one frees the object. Returns the new
/// count.
///
/// # Safety
/// `body` is a live object from [`create`] and the caller owns one of
/// its references, which it gives up.
pub unsafe fn dereference(body: *mut u8) -> i64 {
    // SAFETY: per the contract.
    let left = unsafe { pointer_count(body) }.fetch_sub(1, Ordering::AcqRel) - 1;
    if left == 0 {
        // SAFETY: nothing refers to the object any more; its type's
        // procedure is given the body it was created with.
        unsafe {
            if let Some(delete) = type_of(body).0.TypeInfo.DeleteProcedure {
                delete(body.cast());
            }
        }
        let freed = pool::free(header(body).cast());
        debug_assert!(freed.is_ok());
    } else if left < 0 {
        crate::kd::bugcheck(format_args!(
            "0x00000018 REFERENCE_BY_POINTER: an object was dereferenced more often than referenced"
        ));
    }
    left
}

/// [`ObfDereferenceObject`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-obfdereferenceobject):
/// what `ObDereferenceObject` compiles to.
///
/// # Safety
/// `object` is an object the caller holds a reference to.
pub unsafe extern "C" fn ObfDereferenceObject(object: *mut c_void) -> isize {
    // SAFETY: per the contract.
    unsafe { dereference(object.cast()) as isize }
}

// ---- tests --------------------------------------------------------------

/// A type as a driver holding its address sees it, and an object's
/// header as Windows 10 writes it.
pub fn type_test() -> Result<(), &'static str> {
    for (variable, name, index) in [
        (&ExEventObjectType, "Event", EVENT_TYPE.0.Index),
        (&PsThreadType, "Thread", THREAD_TYPE.0.Index),
        (&IoDeviceObjectType, "Device", DEVICE_TYPE.0.Index),
    ] {
        // SAFETY: the variable holds the address of a static type.
        let ty = unsafe { &*variable.value() };
        if !ty.name().iter().copied().eq(name.encode_utf16()) {
            return Err("a type does not have Windows' name for it");
        }
        if usize::from(ty.0.TypeInfo.Length) != size_of::<OBJECT_TYPE_INITIALIZER>() {
            return Err("a type's initializer does not state its size");
        }
        if ty.0.Index != index || index < FIRST_TYPE_INDEX {
            return Err("a type has the wrong index");
        }
    }
    // Objects big enough to get pages of their own, so their headers'
    // addresses differ in the byte that takes part.
    let mut bodies = [core::ptr::null_mut::<u8>(); 4];
    let mut verdict = Ok(());
    for (pages, body) in bodies.iter_mut().enumerate() {
        match create(&EVENT_TYPE, (pages + 1) * crate::mm::PAGE_SIZE) {
            Some(new) => *body = new,
            None => verdict = Err("no memory"),
        }
    }
    let cookie = COOKIE.load(Ordering::Relaxed);
    let stored = bodies.map(|body| {
        if body.is_null() {
            return None;
        }
        // SAFETY: a live object made above.
        let byte = unsafe { (&raw const (*header(body)).TypeIndex).read() };
        Some((byte, (header(body) as u64 >> 8) as u8))
    });
    for (body, stored) in bodies.iter().zip(stored) {
        let Some((byte, _)) = stored else { continue };
        let expected = type_index(EVENT_TYPE.0.Index, cookie, header(*body) as u64);
        // SAFETY: a live object made above.
        if byte != expected || !core::ptr::eq(unsafe { type_of(*body) }, &raw const EVENT_TYPE) {
            verdict = verdict.and(Err("a header does not lead back to the object's type"));
        }
    }
    let differ = |pick: fn((u8, u8)) -> u8| {
        let mut seen = stored.iter().flatten().map(|s| pick(*s));
        seen.next().is_some_and(|first| seen.any(|b| b != first))
    };
    if verdict.is_ok() && !differ(|(_, address)| address) {
        verdict = Err("the test's objects all share the address byte");
    }
    if verdict.is_ok() && !differ(|(byte, _)| byte) {
        verdict = Err("the type index is stored as it is, not hidden by the header's address");
    }
    for body in bodies {
        if !body.is_null() {
            // SAFETY: the creating reference of an object made above.
            unsafe { dereference(body) };
        }
    }
    verdict
}
