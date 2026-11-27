//! Objects with a header: a reference count, a handle count and a type.
//!
//! What the object manager allocates has an `OBJECT_HEADER` in front of
//! it, laid out as on Windows. A pointer to an object is a pointer to
//! its body; the header is found by stepping back. An object lives until
//! its last reference is dropped: handles hold references, and so does
//! anything that was given a pointer by `ObReferenceObjectByHandle`.
//!
//! An object made to be named has an `OBJECT_HEADER_NAME_INFO` in front
//! of its header, which the header's `InfoMask` says, as on Windows.
//! One pool block holds the name information, the header, the body and
//! the characters of the name, in that order.
//!
//! A type is an `OBJECT_TYPE` laid out as on Windows. A driver names a
//! type by the value of a variable it imports (`*ExEventObjectType`),
//! the type's address. An object's header names its type the way
//! Windows 10 does: by the type's index, hidden behind a cookie chosen
//! at boot and a byte of the header's own address.

#![allow(non_snake_case, non_upper_case_globals)]

use crate::ke::irql;
use crate::mm::pool;
use core::cell::UnsafeCell;
use core::ffi::c_void;
use core::sync::atomic::{AtomicI64, AtomicPtr, AtomicU8, Ordering};
use nk_ntabi::ex::{CRITICAL_WORK_QUEUE, WORK_QUEUE_ITEM};
use nk_ntabi::io::UNICODE_STRING;
use nk_ntabi::ke::LIST_ENTRY;
use nk_ntabi::ob::{
    GENERIC_MAPPING, OB_CLOSE_METHOD, OB_DELETE_METHOD, OB_INFOMASK_NAME, OBJECT_BODY,
    OBJECT_HEADER, OBJECT_HEADER_NAME_INFO, OBJECT_TYPE, OBJECT_TYPE_INITIALIZER,
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
                CloseProcedure: None,
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

    /// The same type, whose `close` is called whenever a handle to one
    /// of its objects is closed.
    const fn closing(mut self, close: OB_CLOSE_METHOD) -> Self {
        self.0.TypeInfo.CloseProcedure = Some(close);
        self
    }

    /// The same type, for which the generic rights mean what `mapping`
    /// says. A type without one has no meaning for them: a handle asked
    /// for generic rights alone is granted nothing.
    const fn rights(mut self, mapping: GENERIC_MAPPING) -> Self {
        self.0.TypeInfo.ValidAccessMask = mapping.GenericAll;
        self.0.TypeInfo.GenericMapping = mapping;
        self
    }

    /// Where the type keeps what the generic rights stand for.
    pub const fn generic_mapping(&'static self) -> *const GENERIC_MAPPING {
        &raw const self.0.TypeInfo.GenericMapping
    }

    /// What the type does when a handle to one of its objects closes.
    pub fn close_procedure(&self) -> Option<OB_CLOSE_METHOD> {
        self.0.TypeInfo.CloseProcedure
    }

    /// `access` with its generic rights replaced by the rights they
    /// stand for in this type.
    pub fn map_generic(&self, access: u32) -> u32 {
        let mapping = &self.0.TypeInfo.GenericMapping;
        nk_se::access::map_generic(
            access,
            &nk_se::access::GenericMapping {
                read: mapping.GenericRead,
                write: mapping.GenericWrite,
                execute: mapping.GenericExecute,
                all: mapping.GenericAll,
            },
        )
    }

    /// How many bytes of NK's own an object of this type carries at
    /// the very front of its block, before any header: a silo context
    /// has a record there (`ps::silo`). A multiple of the pool's
    /// alignment, so the header after it stays aligned.
    fn own_front(&self) -> usize {
        let has_record = core::ptr::eq(self, &raw const SILO_CONTEXT_PAGED_TYPE)
            || core::ptr::eq(self, &raw const SILO_CONTEXT_NONPAGED_TYPE);
        if has_record {
            crate::ps::silo::CONTEXT_RECORD
        } else {
            0
        }
    }

    /// Whether the type's delete procedure must run at `PASSIVE_LEVEL`:
    /// a file's sends its driver the close request.
    fn deletes_at_passive(&self) -> bool {
        core::ptr::eq(self, &raw const FILE_TYPE)
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
static DIRECTORY_NAME: [u16; 9] = wide(b"Directory");
static SYMBOLIC_LINK_NAME: [u16; 12] = wide(b"SymbolicLink");
static DRIVER_NAME: [u16; 6] = wide(b"Driver");
static FILE_NAME: [u16; 4] = wide(b"File");
static JOB_NAME: [u16; 3] = wide(b"Job");
static CALLBACK_NAME: [u16; 8] = wide(b"Callback");
static SILO_CONTEXT_PAGED_NAME: [u16; 18] = wide(b"PsSiloContextPaged");
static SILO_CONTEXT_NONPAGED_NAME: [u16; 21] = wide(b"PsSiloContextNonPaged");

/// Events (`KEVENT`).
pub static EVENT_TYPE: ObjectType = ObjectType::new(FIRST_TYPE_INDEX, &EVENT_NAME, None);
/// Threads (`ETHREAD`).
pub static THREAD_TYPE: ObjectType = ObjectType::new(
    FIRST_TYPE_INDEX + 1,
    &THREAD_NAME,
    Some(crate::ke::thread::deleted),
);
/// Devices (`DEVICE_OBJECT`).
pub static DEVICE_TYPE: ObjectType = ObjectType::new(
    FIRST_TYPE_INDEX + 2,
    &DEVICE_NAME,
    Some(crate::io::device::deleted),
);
/// Registry keys: an open key's object names the key (`cm`).
pub static KEY_TYPE: ObjectType =
    ObjectType::new(FIRST_TYPE_INDEX + 3, &KEY_NAME, Some(crate::cm::closed)).rights(
        // `KEY_READ`, `KEY_WRITE`, `KEY_EXECUTE`, `KEY_ALL_ACCESS`.
        GENERIC_MAPPING {
            GenericRead: 0x0002_0019,
            GenericWrite: 0x0002_0006,
            GenericExecute: 0x0002_0019,
            GenericAll: 0x000F_003F,
        },
    );

/// Processes (`EPROCESS`).
pub static PROCESS_TYPE: ObjectType = ObjectType::new(FIRST_TYPE_INDEX + 4, &PROCESS_NAME, None);

/// Access tokens: the body is NK's own (`se::token`).
pub static TOKEN_TYPE: ObjectType = ObjectType::new(
    FIRST_TYPE_INDEX + 5,
    &TOKEN_NAME,
    Some(crate::se::token::deleted),
);

/// Directories of the namespace (`OBJECT_DIRECTORY`): what is in one
/// is the namespace's to know (`ob`), which hears of a handle closing
/// (a temporary directory then loses its name) and of the last
/// reference going. The generic rights are the pinned kernel's
/// `ObpDirectoryMapping`.
pub static DIRECTORY_TYPE: ObjectType = ObjectType::new(
    FIRST_TYPE_INDEX + 6,
    &DIRECTORY_NAME,
    Some(super::directory_deleted),
)
.closing(super::directory_handle_closed)
.rights(GENERIC_MAPPING {
    GenericRead: 0x0002_0003,
    GenericWrite: 0x0002_000C,
    GenericExecute: 0x0002_0003,
    GenericAll: 0x000F_000F,
});
/// Symbolic links (`OBJECT_SYMBOLIC_LINK`).
pub static SYMBOLIC_LINK_TYPE: ObjectType =
    ObjectType::new(FIRST_TYPE_INDEX + 7, &SYMBOLIC_LINK_NAME, None);
/// Drivers (`DRIVER_OBJECT`).
pub static DRIVER_TYPE: ObjectType = ObjectType::new(
    FIRST_TYPE_INDEX + 8,
    &DRIVER_NAME,
    Some(crate::io::driver::deleted),
);

/// Open files (`FILE_OBJECT`): the last handle closing sends the
/// driver a cleanup request, the last reference going a close request
/// (`io::file`).
pub static FILE_TYPE: ObjectType = ObjectType::new(
    FIRST_TYPE_INDEX + 9,
    &FILE_NAME,
    Some(crate::io::file::deleted),
)
.closing(crate::io::file::handle_closed)
.rights(nk_ntabi::io::FILE_GENERIC_MAPPING);

/// [`IoGetFileObjectGenericMapping`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-iogetfileobjectgenericmapping):
/// what the generic rights stand for in a file. The answer points into
/// the file type itself, at the mapping an open's desired access is
/// mapped with, so a file system that checks access against it and the
/// I/O manager cannot disagree. It is never written.
#[allow(non_snake_case)]
pub extern "C" fn IoGetFileObjectGenericMapping() -> *const GENERIC_MAPPING {
    FILE_TYPE.generic_mapping()
}

/// Silo contexts (`ps::silo`): what a driver keeps per silo. Windows
/// has one type for contexts made from paged pool and one for the
/// rest; a context's routine is called when its last reference goes.
pub static SILO_CONTEXT_PAGED_TYPE: ObjectType = ObjectType::new(
    FIRST_TYPE_INDEX + 10,
    &SILO_CONTEXT_PAGED_NAME,
    Some(crate::ps::silo::context_deleted),
);
pub static SILO_CONTEXT_NONPAGED_TYPE: ObjectType = ObjectType::new(
    FIRST_TYPE_INDEX + 11,
    &SILO_CONTEXT_NONPAGED_NAME,
    Some(crate::ps::silo::context_deleted),
);

/// Jobs (`EJOB`). The type is there for drivers to name: no job is
/// ever made, so no object has it and no handle names one.
pub static JOB_TYPE: ObjectType = ObjectType::new(FIRST_TYPE_INDEX + 12, &JOB_NAME, None);

/// Callback objects (`ex::callback`): a list of the routines drivers
/// registered. A registration holds a reference, so an object that is
/// deleted has none left.
pub static CALLBACK_TYPE: ObjectType = ObjectType::new(FIRST_TYPE_INDEX + 13, &CALLBACK_NAME, None);

/// Every type, by index from `FIRST_TYPE_INDEX`.
static TYPES: [&ObjectType; 14] = [
    &EVENT_TYPE,
    &THREAD_TYPE,
    &DEVICE_TYPE,
    &KEY_TYPE,
    &PROCESS_TYPE,
    &TOKEN_TYPE,
    &DIRECTORY_TYPE,
    &SYMBOLIC_LINK_TYPE,
    &DRIVER_TYPE,
    &FILE_TYPE,
    &SILO_CONTEXT_PAGED_TYPE,
    &SILO_CONTEXT_NONPAGED_TYPE,
    &JOB_TYPE,
    &CALLBACK_TYPE,
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

/// [`IoFileObjectType`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-obreferenceobjectbyhandle):
/// what a driver passes to insist on an open file.
pub static IoFileObjectType: TypeVariable = TypeVariable(&raw const FILE_TYPE);

/// [`PsJobType`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntddk/nf-ntddk-psgetjobsilo):
/// what a driver passes to insist on a job. A file system asks for the
/// job behind a handle a requestor gave it, to find the job's silo;
/// with no jobs, every such handle names something else and is refused
/// as the wrong type.
pub static PsJobType: TypeVariable = TypeVariable(&raw const JOB_TYPE);

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

pub(super) fn header(body: *mut u8) -> *mut OBJECT_HEADER {
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

/// The name information in front of an object's header, or null for an
/// object made without.
///
/// # Safety
/// `body` is a live object from [`create`] or [`create_named`].
pub unsafe fn name_info(body: *mut u8) -> *mut OBJECT_HEADER_NAME_INFO {
    let header = header(body);
    // SAFETY: per the contract; the mask was written when the object
    // was made and never changes.
    if unsafe { (&raw const (*header).InfoMask).read() } & OB_INFOMASK_NAME == 0 {
        return core::ptr::null_mut();
    }
    header.cast::<OBJECT_HEADER_NAME_INFO>().wrapping_sub(1)
}

/// Whether an object has a name in the namespace now.
///
/// # Safety
/// `body` is a live object from [`create`] or [`create_named`].
pub unsafe fn has_name(body: *mut u8) -> bool {
    // SAFETY: per the contract.
    unsafe {
        let info = name_info(body);
        !info.is_null() && !(&raw const (*info).Directory).read().is_null()
    }
}

/// Where the pool block of an object begins: at what its type keeps in
/// front (`ObjectType::own_front`), then its name information if it
/// has any, then its header.
///
/// # Safety
/// As [`name_info`].
unsafe fn block(body: *mut u8) -> *mut u8 {
    // SAFETY: per the contract.
    unsafe {
        let info = name_info(body);
        let headers: *mut u8 = if info.is_null() {
            header(body).cast()
        } else {
            info.cast()
        };
        headers.sub(type_of(body).own_front())
    }
}

/// The record an object's type keeps at the front of the object's
/// block (`ObjectType::own_front`).
///
/// # Safety
/// `body` is a live object of a type that keeps one.
pub unsafe fn own_record(body: *mut u8) -> *mut u8 {
    // SAFETY: per the contract.
    unsafe { block(body) }
}

/// Allocate a zeroed object of `size` bytes and type `ty`, with one
/// reference: the caller's.
pub fn create(ty: &'static ObjectType, size: usize) -> Option<*mut u8> {
    allocate(ty, size, None)
}

/// As [`create`], for an object that will be given a name in the
/// namespace (`ob::insert`): `name` is the name it will have in its
/// directory, the last component of its path. The object carries
/// Windows' name information; it is in no directory yet.
pub fn create_named(ty: &'static ObjectType, size: usize, name: &[u16]) -> Option<*mut u8> {
    allocate(ty, size, Some(name))
}

fn allocate(ty: &'static ObjectType, size: usize, name: Option<&[u16]>) -> Option<*mut u8> {
    let own = ty.own_front();
    let named = name.is_some();
    let front = own
        + if named {
            size_of::<OBJECT_HEADER_NAME_INFO>()
        } else {
            0
        };
    let name = name.unwrap_or(&[]);
    // A counted string's length is 16 bits.
    let name_bytes = u16::try_from(name.len() * 2).ok()?;
    // The name's characters follow the body.
    let characters = (front + OBJECT_BODY + size).next_multiple_of(align_of::<u16>());
    let block = pool::alloc_zeroed(characters + usize::from(name_bytes), TAG);
    if block.is_null() {
        return None;
    }
    // SAFETY: a fresh, zeroed block large enough for the type's own
    // record, the name information, the header and the name, which the
    // pool aligns to 16 bytes; the sizes of what precedes the header
    // keep it so aligned.
    unsafe {
        let header = block.add(front).cast::<OBJECT_HEADER>();
        (&raw mut (*header).PointerCount).write(1);
        (&raw mut (*header).TypeIndex).write(type_index(
            ty.0.Index,
            COOKIE.load(Ordering::Relaxed),
            header as u64,
        ));
        if named {
            let info = block.add(own).cast::<OBJECT_HEADER_NAME_INFO>();
            let buffer = block.add(characters).cast::<u16>();
            buffer.copy_from_nonoverlapping(name.as_ptr(), name.len());
            (&raw mut (*info).Name).write(UNICODE_STRING {
                Length: name_bytes,
                MaximumLength: name_bytes,
                Buffer: buffer,
            });
            (&raw mut (*info).ReferenceCount).write(1);
            (&raw mut (*header).InfoMask).write(OB_INFOMASK_NAME);
        }
        Some(block.add(front + OBJECT_BODY))
    }
}

/// Record that a named object is now in `directory` (a directory
/// object), which it holds a reference to for as long as it is there,
/// as on Windows: a directory outlives its name while it has entries.
/// The namespace calls this under its lock.
///
/// # Safety
/// `body` is a live object from [`create_named`]; `directory` is a
/// live directory object.
pub unsafe fn entered(body: *mut u8, directory: *mut u8) {
    // SAFETY: per the contract: the object has name information.
    unsafe {
        reference(directory);
        (&raw mut (*name_info(body)).Directory).write(directory.cast());
    }
}

/// Record that a named object has lost its name: it is in no
/// directory and its name is empty, as Windows leaves it. The
/// namespace calls this under its lock. Returns the directory the
/// object was in, whose reference the caller gives up once that lock
/// is released.
///
/// # Safety
/// `body` is a live object from [`create_named`] that is in a
/// directory.
#[must_use]
pub unsafe fn left(body: *mut u8) -> *mut u8 {
    // SAFETY: per the contract: the object has name information.
    unsafe {
        let info = name_info(body);
        let directory = (&raw const (*info).Directory).read().cast::<u8>();
        (&raw mut (*info).Directory).write(core::ptr::null_mut());
        (&raw mut (*info).Name).write(UNICODE_STRING {
            Length: 0,
            MaximumLength: 0,
            Buffer: core::ptr::null_mut(),
        });
        directory
    }
}

/// Whether an object is permanent (`OBJ_PERMANENT`): whether its name
/// stays when its last handle closes. Read and written under the
/// namespace's lock.
///
/// # Safety
/// `body` is a live object from [`create`].
pub unsafe fn permanent(body: *mut u8) -> bool {
    // SAFETY: per the contract.
    unsafe {
        (&raw const (*header(body)).Flags).read() & nk_ntabi::ob::OB_FLAG_PERMANENT_OBJECT != 0
    }
}

/// Make an object permanent, or temporary.
///
/// # Safety
/// As [`permanent`].
pub unsafe fn set_permanent(body: *mut u8, permanent: bool) {
    // SAFETY: per the contract.
    unsafe {
        let flags = &raw mut (*header(body)).Flags;
        let old = flags.read();
        flags.write(if permanent {
            old | nk_ntabi::ob::OB_FLAG_PERMANENT_OBJECT
        } else {
            old & !nk_ntabi::ob::OB_FLAG_PERMANENT_OBJECT
        });
    }
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

/// Delete an object: its type's procedure releases what it owns, then
/// its memory goes.
///
/// # Safety
/// `body` is an object from [`create`] that nothing refers to any more.
unsafe fn delete(body: *mut u8) {
    // SAFETY: per the contract; the type's procedure is given the body
    // the object was created with.
    unsafe {
        if let Some(delete) = type_of(body).0.TypeInfo.DeleteProcedure {
            delete(body.cast());
        }
        super::security::object_freed(body);
    }
    // SAFETY: still the object's memory; its block is found before it
    // is given back.
    let freed = pool::free(unsafe { block(body) });
    debug_assert!(freed.is_ok());
}

/// The objects waiting to be deleted by a worker thread, newest first,
/// linked through their headers as Windows links them: `NextToFree`
/// shares its place with the handle count, which no longer counts
/// anything.
static DEFERRED: AtomicPtr<u8> = AtomicPtr::new(core::ptr::null_mut());

/// The work item that deletes them: queued by whoever makes the list
/// non-empty. A worker takes an item off its queue before running it,
/// and the routine takes the whole list, so the next object deferred
/// finds the list empty and the item free to be queued again.
struct DeferredWork(UnsafeCell<WORK_QUEUE_ITEM>);

// SAFETY: reached only through `ExQueueWorkItem`, which locks.
unsafe impl Sync for DeferredWork {}

static DEFERRED_WORK: DeferredWork = DeferredWork(UnsafeCell::new(WORK_QUEUE_ITEM {
    List: LIST_ENTRY {
        Flink: core::ptr::null_mut(),
        Blink: core::ptr::null_mut(),
    },
    WorkerRoutine: Some(delete_deferred),
    Parameter: core::ptr::null_mut(),
}));

/// Where an object waiting to be deleted names the next one.
fn next_to_free(body: *mut u8) -> *mut *mut u8 {
    // `NextToFree` is a union with `HandleCount`.
    header(body)
        .wrapping_byte_add(core::mem::offset_of!(OBJECT_HEADER, HandleCount))
        .cast()
}

/// Leave an object's deletion to a worker thread, which runs at
/// `PASSIVE_LEVEL`. Windows does this for an object whose last
/// reference goes where its delete procedure cannot run.
///
/// # Safety
/// `body` is an object from [`create`] that nothing refers to any more;
/// the IRQL is at most `DISPATCH_LEVEL`.
unsafe fn defer(body: *mut u8) {
    let mut head = DEFERRED.load(Ordering::Acquire);
    loop {
        // SAFETY: per the contract: the header is this function's alone
        // until the object is on the list.
        unsafe { next_to_free(body).write(head) };
        match DEFERRED.compare_exchange_weak(head, body, Ordering::AcqRel, Ordering::Acquire) {
            Ok(_) => break,
            Err(now) => head = now,
        }
    }
    if head.is_null() {
        // SAFETY: the item is on no queue: see `DeferredWork`.
        unsafe { crate::ex::work::ExQueueWorkItem(DEFERRED_WORK.0.get(), CRITICAL_WORK_QUEUE) };
    }
}

/// The work routine: delete every object left for a worker thread.
///
/// # Safety
/// Called as a work routine.
unsafe extern "C" fn delete_deferred(_: *mut c_void) {
    let mut body = DEFERRED.swap(core::ptr::null_mut(), Ordering::AcqRel);
    while !body.is_null() {
        // SAFETY: `defer` put the object there, unreferenced, and wrote
        // the link, which is read before the object is freed.
        unsafe {
            let next = next_to_free(body).read();
            delete(body);
            body = next;
        }
    }
}

/// Drop a reference; the last one frees the object. Returns the new
/// count.
///
/// An object whose delete procedure calls a driver (an open file) is
/// deleted at `PASSIVE_LEVEL`: if its last reference goes above that,
/// a worker thread deletes it later.
///
/// # Safety
/// `body` is a live object from [`create`] and the caller owns one of
/// its references, which it gives up.
pub unsafe fn dereference(body: *mut u8) -> i64 {
    // SAFETY: per the contract.
    let left = unsafe { pointer_count(body) }.fetch_sub(1, Ordering::AcqRel) - 1;
    if left == 0 {
        // SAFETY: nothing refers to the object any more.
        unsafe {
            if type_of(body).deletes_at_passive() && irql::current() != irql::PASSIVE_LEVEL {
                defer(body);
            } else {
                delete(body);
            }
        }
    } else if left < 0 {
        crate::kd::bugcheck(format_args!(
            "0x00000018 REFERENCE_BY_POINTER: an object was dereferenced more often than referenced"
        ));
    }
    left
}

/// One pointer reference to an object, owned: given up when this is
/// dropped, however the holder leaves, unless [`ObRef::into_raw`] hands
/// it on first (to a handle, a driver, a table that keeps it).
pub struct ObRef(*mut u8);

impl ObRef {
    /// Take ownership of a reference the caller holds.
    ///
    /// # Safety
    /// `body` is a live object from [`create`] and the caller owns one
    /// of its references, which this now owns.
    pub unsafe fn adopt(body: *mut u8) -> Self {
        Self(body)
    }

    /// Take a new reference to `body`.
    ///
    /// # Safety
    /// As [`reference`].
    pub unsafe fn new(body: *mut u8) -> Self {
        // SAFETY: per the contract.
        unsafe { reference(body) };
        Self(body)
    }

    /// The object's body.
    pub fn body(&self) -> *mut u8 {
        self.0
    }

    /// The object's body, as the structure it is.
    pub fn cast<T>(&self) -> *mut T {
        self.0.cast()
    }

    /// Hand the reference on: it is the caller's to give up.
    pub fn into_raw(self) -> *mut u8 {
        core::mem::ManuallyDrop::new(self).0
    }
}

impl Drop for ObRef {
    fn drop(&mut self) {
        // SAFETY: the reference this owns.
        unsafe { dereference(self.0) };
    }
}

/// Drop a reference unless it is the last one; says whether it was
/// dropped. For an owner that must give its reference up while it
/// still holds a lock inside the object.
///
/// # Safety
/// As [`dereference`], except that the caller still owns the reference
/// when the answer is `false`.
pub unsafe fn dereference_unless_last(body: *mut u8) -> bool {
    // SAFETY: per the contract.
    unsafe { pointer_count(body) }
        .try_update(Ordering::AcqRel, Ordering::Acquire, |count| {
            (count > 1).then(|| count - 1)
        })
        .is_ok()
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

/// The count a driver's reference left: an object whose last reference
/// has gone is being deleted, and a pointer to it is no reference.
/// Windows stops there too
/// ([`REFERENCE_BY_POINTER`](https://learn.microsoft.com/en-us/windows-hardware/drivers/debugger/bug-check-0x18--reference-by-pointer)).
fn referenced(count: i64) -> isize {
    if count <= 1 {
        crate::kd::bugcheck(format_args!(
            "0x00000018 REFERENCE_BY_POINTER: a reference was taken to an object that had none"
        ));
    }
    count as isize
}

/// [`ObfReferenceObject`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-obfreferenceobject):
/// what `ObReferenceObject` compiles to. Returns the count it made.
///
/// # Safety
/// `object` is an object the caller holds a reference to.
pub unsafe extern "C" fn ObfReferenceObject(object: *mut c_void) -> isize {
    // SAFETY: per the contract.
    referenced(unsafe { reference(object.cast()) })
}

/// [`ObReferenceObjectByPointer`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-obreferenceobjectbypointer):
/// take a reference to an object the caller already has a pointer to,
/// if it is of the type named. As the pinned kernel decides it: an
/// object of another type is `STATUS_OBJECT_TYPE_MISMATCH` for either
/// mode; no type named is accepted for kernel mode only. The desired
/// access is not looked at, as on Windows.
///
/// # Safety
/// `object` is an object the caller holds a reference to; `object_type`
/// is null or what an exported type variable holds.
pub unsafe extern "C" fn ObReferenceObjectByPointer(
    object: *mut c_void,
    _desired_access: u32,
    object_type: *const ObjectType,
    access_mode: i8,
) -> nk_ntabi::status::NTSTATUS {
    // SAFETY: per the contract.
    unsafe {
        let acceptable = if object_type.is_null() {
            access_mode == nk_ntabi::io::KERNEL_MODE
        } else {
            core::ptr::eq(type_of(object.cast()), object_type)
        };
        if !acceptable {
            return nk_ntabi::status::STATUS_OBJECT_TYPE_MISMATCH;
        }
        referenced(reference(object.cast()));
    }
    nk_ntabi::status::STATUS_SUCCESS
}

/// [`ObfReferenceObjectWithTag`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-obfreferenceobjectwithtag).
/// The tag names the reference for
/// [object reference tracing](https://learn.microsoft.com/en-us/windows-hardware/drivers/kernel/object-reference-tracing-with-tags),
/// which NK does not do, as Windows does not unless it is turned on:
/// the count is the one count.
///
/// # Safety
/// As [`ObfReferenceObject`].
pub unsafe extern "C" fn ObfReferenceObjectWithTag(object: *mut c_void, _tag: u32) -> isize {
    // SAFETY: per the contract.
    referenced(unsafe { reference(object.cast()) })
}

/// [`ObfDereferenceObjectWithTag`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-obfdereferenceobjectwithtag):
/// as [`ObfDereferenceObject`]; the tag, as in
/// [`ObfReferenceObjectWithTag`], changes nothing.
///
/// # Safety
/// `object` is an object the caller holds a reference to.
pub unsafe extern "C" fn ObfDereferenceObjectWithTag(object: *mut c_void, _tag: u32) -> isize {
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
        (&PsJobType, "Job", JOB_TYPE.0.Index),
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
    // Every type is known by its index, and no two share one.
    for (at, ty) in TYPES.iter().enumerate() {
        if usize::from(ty.0.Index) != usize::from(FIRST_TYPE_INDEX) + at {
            return Err("a type is not listed under its index");
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
