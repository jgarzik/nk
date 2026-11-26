//! IRP extensions: what the I/O manager keeps about a request beside
//! the IRP, and the routines that read and write it. An activity id
//! (`IoSetActivityIdIrp`), four bytes of a driver's own
//! (`IoSetGenericIrpExtension`), and kinds that only Windows' own
//! components make: a file system's tracked offset, a disk I/O
//! attribution handle, an adapter's crypto parameters.
//!
//! The rules are the pinned kernel's (`IopAllocateIrpExtension`,
//! `IopFreeIrpExtension`). The extension is a block of the pool the
//! IRP points to (`IrpExtension`), marked in the IRP's allocation
//! flags and freed with the IRP. A generic extension alone needs no
//! block: its bytes are kept in the pointer's own place, another flag
//! saying so, until a second kind makes a block necessary. NK makes
//! the first two kinds; the others are never there, and the routines
//! that ask for them say so.
//!
//! An IRP is its driver's memory: every field is read and written
//! through raw pointers. Nothing here is locked, as nothing is on
//! Windows: an IRP has one owner at a time.

#![allow(non_snake_case)]

use crate::ke::thread;
use crate::mm::pool;
use core::ffi::c_void;
use nk_ntabi::etw::GUID;
use nk_ntabi::io::*;
use nk_ntabi::status::*;
use nk_ntabi::thread::ACTIVITY_ID;

/// The pool tag of an extension block, Windows' own.
const TAG: u32 = u32::from_le_bytes(*b"IrpX");

/// Whether the IRP's generic extension is kept in `IrpExtension`
/// itself.
///
/// # Safety
/// `irp` is a live IRP.
unsafe fn inline(irp: *mut IRP) -> bool {
    // SAFETY: per the contract.
    unsafe { (&raw const (*irp).AllocationFlags).read() & IRP_ALLOCATION_GENERIC_INLINE != 0 }
}

/// The IRP's extension block, or null.
///
/// # Safety
/// `irp` is a live IRP.
unsafe fn block(irp: *mut IRP) -> *mut IOP_IRP_EXTENSION {
    // SAFETY: per the contract.
    unsafe {
        if inline(irp) {
            core::ptr::null_mut()
        } else {
            (&raw const (*irp).IrpExtension).read().cast()
        }
    }
}

/// Whether the IRP has an extension of `kind`
/// (`IopIrpHasExtensionType`).
///
/// # Safety
/// `irp` is a live IRP.
unsafe fn has(irp: *mut IRP, kind: u32) -> bool {
    // SAFETY: per the contract; the block, if there is one, is the
    // IRP's.
    unsafe {
        if inline(irp) {
            return kind == IRP_EXTENSION_GENERIC;
        }
        let block = block(irp);
        !block.is_null() && (&raw const (*block).TypesAllocated).read() & (1 << kind) != 0
    }
}

/// Where an extension of some kind is.
enum Place {
    /// In the IRP's block.
    Block(*mut IOP_IRP_EXTENSION),
    /// A generic extension, in the `IrpExtension` field itself.
    Field,
}

/// Give the IRP an extension of `kind` (`IopAllocateIrpExtension`):
/// mark it in the block the IRP has; or keep a generic extension in
/// the field; or make the block, moving into it the generic extension
/// the field held. `None` without memory.
///
/// # Safety
/// `irp` is a live IRP the caller owns.
unsafe fn allocate(irp: *mut IRP, kind: u32) -> Option<Place> {
    // SAFETY: per the contract; a new block is fresh, zeroed memory of
    // an extension's size.
    unsafe {
        let existing = block(irp);
        if !existing.is_null() {
            let types = &raw mut (*existing).TypesAllocated;
            types.write(types.read() | 1 << kind);
            return Some(Place::Block(existing));
        }
        let flags = &raw mut (*irp).AllocationFlags;
        if kind == IRP_EXTENSION_GENERIC {
            flags.write(flags.read() | IRP_ALLOCATION_GENERIC_INLINE);
            return Some(Place::Field);
        }
        let new =
            pool::alloc_zeroed(size_of::<IOP_IRP_EXTENSION>(), TAG).cast::<IOP_IRP_EXTENSION>();
        if new.is_null() {
            return None;
        }
        (&raw mut (*new).ExtensionFlags).write(1);
        let mut types = 1u16 << kind;
        if inline(irp) {
            // The generic extension moves from the field to the block.
            let field = (&raw const (*irp).IrpExtension).cast::<[u8; IRP_GENERIC_EXTENSION_SIZE]>();
            (&raw mut (*new).GenericExtension).write(field.read());
            types |= 1 << IRP_EXTENSION_GENERIC;
        }
        (&raw mut (*new).TypesAllocated).write(types);
        (&raw mut (*irp).IrpExtension).write(new.cast());
        flags.write((flags.read() & !IRP_ALLOCATION_GENERIC_INLINE) | IRP_ALLOCATION_EXTENSION);
        Some(Place::Block(new))
    }
}

/// Take extensions away from the IRP (`IopFreeIrpExtension`): the one
/// of `kind`, or all of them. A generic extension kept in the field
/// goes whatever is asked. The block is freed when it holds nothing
/// more, if `free_block`.
///
/// # Safety
/// `irp` is a live IRP the caller owns.
unsafe fn release(irp: *mut IRP, kind: Option<u32>, free_block: bool) {
    // SAFETY: per the contract.
    unsafe {
        let flags = &raw mut (*irp).AllocationFlags;
        if inline(irp) {
            flags.write(flags.read() & !IRP_ALLOCATION_GENERIC_INLINE);
            (&raw mut (*irp).IrpExtension).write(core::ptr::null_mut());
            return;
        }
        let block = block(irp);
        if block.is_null() {
            return;
        }
        let types = &raw mut (*block).TypesAllocated;
        let (left, tracked) = match kind {
            None => (0, types.read() & 1 << IRP_EXTENSION_FS_TRACK_OFFSET != 0),
            Some(kind) => (
                types.read() & !(1 << kind),
                kind == IRP_EXTENSION_FS_TRACK_OFFSET,
            ),
        };
        if tracked {
            (&raw mut (*block).Parameters[0]).write(0);
        }
        types.write(left);
        if left == 0 && free_block && flags.read() & IRP_ALLOCATION_EXTENSION != 0 {
            let _ = pool::free(block.cast());
            flags.write(flags.read() & !IRP_ALLOCATION_EXTENSION);
            (&raw mut (*irp).IrpExtension).write(core::ptr::null_mut());
        }
    }
}

/// An IRP is being freed: its extensions go with it.
///
/// # Safety
/// `irp` is a live IRP that no driver holds.
pub unsafe fn freed(irp: *mut IRP) {
    // SAFETY: per the contract.
    unsafe { release(irp, None, true) };
}

/// What `IoReuseIrp` carries over the IRP's clearing: the block, and
/// the activity id if the IRP had one.
pub struct Kept {
    block: *mut IOP_IRP_EXTENSION,
    activity: Option<GUID>,
}

/// Before an IRP is reused: its extensions end, a generic one kept in
/// the field included, but the block stays the IRP's, and so does the
/// activity id, as the pinned kernel's `IoReuseIrp` has it.
///
/// # Safety
/// `irp` is a live IRP the caller owns.
pub unsafe fn before_reuse(irp: *mut IRP) -> Kept {
    // SAFETY: per the contract.
    unsafe {
        let block = block(irp);
        if block.is_null() {
            return Kept {
                block,
                activity: None,
            };
        }
        let activity =
            has(irp, IRP_EXTENSION_ACTIVITY_ID).then(|| (&raw const (*block).ActivityId).read());
        (&raw mut (*block).TypesAllocated).write(0);
        Kept { block, activity }
    }
}

/// After the IRP has been cleared for reuse, with the allocation flag
/// of its block kept: the block is the IRP's again.
///
/// # Safety
/// `irp` is the IRP `kept` came from, cleared since.
pub unsafe fn after_reuse(irp: *mut IRP, kept: Kept) {
    if kept.block.is_null() {
        return;
    }
    // SAFETY: per the contract; the block was the IRP's and was not
    // freed.
    unsafe {
        (&raw mut (*irp).IrpExtension).write(kept.block.cast());
        if let Some(id) = kept.activity {
            (&raw mut (*kept.block).TypesAllocated).write(1 << IRP_EXTENSION_ACTIVITY_ID);
            (&raw mut (*kept.block).ActivityId).write(id);
        }
    }
}

/// Where the running thread keeps the activity id it works under: a
/// pointer in its `ETHREAD`.
fn thread_activity() -> *mut *const GUID {
    thread::current()
        .cast::<u8>()
        .wrapping_add(ACTIVITY_ID)
        .cast()
}

/// [`IoGetActivityIdIrp`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-iogetactivityidirp):
/// the activity id the IRP was given; `STATUS_NOT_FOUND` if it has
/// none. NK's I/O manager gives none of its own: Windows gives one to
/// each request while I/O tracing is on, which it never is here
/// ([`IoIsActivityTracingEnabled`]).
///
/// # Safety
/// `irp` is a live IRP; `guid` is writable.
pub unsafe extern "C" fn IoGetActivityIdIrp(irp: *mut IRP, guid: *mut GUID) -> NTSTATUS {
    // SAFETY: per the contract.
    unsafe {
        if !has(irp, IRP_EXTENSION_ACTIVITY_ID) {
            return STATUS_NOT_FOUND;
        }
        guid.write_unaligned((&raw const (*block(irp)).ActivityId).read());
    }
    STATUS_SUCCESS
}

/// [`IoSetActivityIdIrp`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-iosetactivityidirp):
/// give the IRP an activity id. With no id given, Windows takes the
/// calling thread's own (`EtwActivityIdControl`), for the thread the
/// request is of only (`STATUS_NOT_SUPPORTED` for another); NK's
/// threads have no id of their own, so that fails as it does on
/// Windows for a system thread, and the IRP is left without one.
///
/// # Safety
/// `irp` is a live IRP the caller owns; `guid` is null or readable.
pub unsafe extern "C" fn IoSetActivityIdIrp(irp: *mut IRP, guid: *const GUID) -> NTSTATUS {
    // SAFETY: per the contract.
    unsafe {
        let Some(Place::Block(block)) = allocate(irp, IRP_EXTENSION_ACTIVITY_ID) else {
            return STATUS_INSUFFICIENT_RESOURCES;
        };
        let id = &raw mut (*block).ActivityId;
        if !guid.is_null() {
            id.write(guid.read_unaligned());
            return STATUS_SUCCESS;
        }
        let status = if (&raw const (*irp).Thread).read() == thread::current().cast() {
            crate::etw::EtwActivityIdControl(nk_etw::activity::GET_ID, id)
        } else {
            STATUS_NOT_SUPPORTED
        };
        if !nt_success(status) {
            release(irp, Some(IRP_EXTENSION_ACTIVITY_ID), true);
        }
        status
    }
}

/// [`IoGetActivityIdThread`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-iogetactivityidthread):
/// the activity id the running thread works under, or null.
pub extern "C" fn IoGetActivityIdThread() -> *const GUID {
    // SAFETY: the running thread's own field.
    unsafe { thread_activity().read() }
}

/// [`IoClearActivityIdThread`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-ioclearactivityidthread):
/// the running thread works under `original_id` again, which is what
/// `IoPropagateActivityIdToThread` handed back.
pub extern "C" fn IoClearActivityIdThread(original_id: *const GUID) {
    // SAFETY: the running thread's own field.
    unsafe { thread_activity().write(original_id) };
}

/// [`IoPropagateActivityIdToThread`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-iopropagateactivityidtothread):
/// the running thread works under the IRP's activity id, copied to
/// `propagated_id`, which the thread then points to; what it pointed
/// to before is handed back for `IoClearActivityIdThread`.
/// `STATUS_NOT_FOUND` if the IRP has no activity id.
///
/// # Safety
/// `irp` is a live IRP; `propagated_id` is writable and stays so until
/// the thread's id is cleared; `original_id` is writable.
pub unsafe extern "C" fn IoPropagateActivityIdToThread(
    irp: *mut IRP,
    propagated_id: *mut GUID,
    original_id: *mut *const GUID,
) -> NTSTATUS {
    // SAFETY: per the contract.
    unsafe {
        if !has(irp, IRP_EXTENSION_ACTIVITY_ID) {
            return STATUS_NOT_FOUND;
        }
        IoGetActivityIdIrp(irp, propagated_id);
        let slot = thread_activity();
        let before = slot.read();
        slot.write(propagated_id);
        original_id.write_unaligned(before);
    }
    STATUS_SUCCESS
}

/// [`IoIsActivityTracingEnabled`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-ioisactivitytracingenabled):
/// no. Windows says yes while a trace session listens to the I/O
/// manager's own provider; NK has no session.
pub extern "C" fn IoIsActivityTracingEnabled() -> u8 {
    0
}

/// [`IoGetGenericIrpExtension`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-iogetgenericirpextension):
/// the first `size` bytes of the IRP's generic extension, which holds
/// four (`STATUS_INVALID_PARAMETER` for more); `STATUS_NOT_FOUND` if
/// the IRP has none.
///
/// # Safety
/// `irp` is a live IRP; `data` is writable for `size` bytes.
pub unsafe extern "C" fn IoGetGenericIrpExtension(
    irp: *mut IRP,
    data: *mut u8,
    size: u16,
) -> NTSTATUS {
    if usize::from(size) > IRP_GENERIC_EXTENSION_SIZE {
        return STATUS_INVALID_PARAMETER;
    }
    // SAFETY: per the contract.
    unsafe {
        if !has(irp, IRP_EXTENSION_GENERIC) {
            return STATUS_NOT_FOUND;
        }
        let from = if inline(irp) {
            (&raw const (*irp).IrpExtension).cast::<u8>()
        } else {
            (&raw const (*block(irp)).GenericExtension).cast::<u8>()
        };
        core::ptr::copy(from, data, usize::from(size));
    }
    STATUS_SUCCESS
}

/// [`IoSetGenericIrpExtension`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-iosetgenericirpextension):
/// write the first `size` bytes of the IRP's generic extension, of at
/// most four (`STATUS_INVALID_PARAMETER`). Unless `overwrite`, an IRP
/// that has one already keeps it (`STATUS_ALREADY_COMMITTED`).
///
/// # Safety
/// `irp` is a live IRP the caller owns; `data` is readable for `size`
/// bytes.
pub unsafe extern "C" fn IoSetGenericIrpExtension(
    irp: *mut IRP,
    data: *const u8,
    size: u16,
    overwrite: u8,
) -> NTSTATUS {
    if usize::from(size) > IRP_GENERIC_EXTENSION_SIZE {
        return STATUS_INVALID_PARAMETER;
    }
    // SAFETY: per the contract.
    unsafe {
        if overwrite == 0 && has(irp, IRP_EXTENSION_GENERIC) {
            return STATUS_ALREADY_COMMITTED;
        }
        let to = match allocate(irp, IRP_EXTENSION_GENERIC) {
            Some(Place::Field) => (&raw mut (*irp).IrpExtension).cast::<u8>(),
            Some(Place::Block(block)) => (&raw mut (*block).GenericExtension).cast::<u8>(),
            None => return STATUS_INSUFFICIENT_RESOURCES,
        };
        core::ptr::copy(data, to, usize::from(size));
    }
    STATUS_SUCCESS
}

/// The system stops: an IRP has an extension of a kind only Windows'
/// own components make, which NK has none of, and a driver asks for
/// it to be copied.
fn foreign_kind(what: &str) -> ! {
    crate::kd::bugcheck(format_args!(
        "IoPropagateIrpExtension: the source IRP has {what}, which NK never makes and does not \
         copy"
    ))
}

/// [`IoPropagateIrpExtensionEx`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-iopropagateirpextensionex):
/// copy to `target` the extensions of `source` that `flags` name: the
/// activity id, the generic extension, the driver flags. A source
/// with no extension is done at once. `STATUS_INSUFFICIENT_RESOURCES`
/// without memory for the target's block.
///
/// A tracked offset, a disk I/O attribution handle and crypto
/// parameters are put in an IRP by components NK does not have. Asked
/// to copy one that is there, which cannot be, the system stops by
/// name: the ledger's "partial".
///
/// # Safety
/// Both are live IRPs; the caller owns `target`.
pub unsafe extern "C" fn IoPropagateIrpExtensionEx(
    source: *mut IRP,
    target: *mut IRP,
    _tracked_offset: i64,
    flags: u32,
) -> NTSTATUS {
    // SAFETY: per the contract.
    unsafe {
        if inline(source) {
            if flags & IRP_PROPAGATE_GENERIC != 0 {
                let mut bytes = [0u8; IRP_GENERIC_EXTENSION_SIZE];
                IoGetGenericIrpExtension(source, bytes.as_mut_ptr(), bytes.len() as u16);
                return IoSetGenericIrpExtension(target, bytes.as_ptr(), bytes.len() as u16, 1);
            }
            return STATUS_SUCCESS;
        }
        let from = block(source);
        if from.is_null() {
            return STATUS_SUCCESS;
        }
        if flags & IRP_PROPAGATE_ACTIVITY_ID != 0 && has(source, IRP_EXTENSION_ACTIVITY_ID) {
            let id = (&raw const (*from).ActivityId).read();
            let status = IoSetActivityIdIrp(target, &raw const id);
            if !nt_success(status) {
                return status;
            }
        }
        if flags & IRP_PROPAGATE_GENERIC != 0 && has(source, IRP_EXTENSION_GENERIC) {
            let bytes = (&raw const (*from).GenericExtension).read();
            let status = IoSetGenericIrpExtension(target, bytes.as_ptr(), bytes.len() as u16, 1);
            if !nt_success(status) {
                return status;
            }
        }
        for (flag, kind, what) in [
            (
                IRP_PROPAGATE_FS_TRACK_OFFSET,
                IRP_EXTENSION_FS_TRACK_OFFSET,
                "a file system's tracked offset",
            ),
            (
                IRP_PROPAGATE_DISK_IO_ATTRIBUTION,
                IRP_EXTENSION_DISK_IO_ATTRIBUTION,
                "a disk I/O attribution handle",
            ),
            (
                IRP_PROPAGATE_ADAPTER_CRYPTO,
                IRP_EXTENSION_ADAPTER_CRYPTO,
                "an adapter's crypto parameters",
            ),
        ] {
            if flags & flag != 0 && has(source, kind) {
                foreign_kind(what);
            }
        }
        if flags & IRP_PROPAGATE_DRIVER_FLAGS != 0 && has(source, IRP_EXTENSION_DRIVER_FLAGS) {
            let Some(Place::Block(to)) = allocate(target, IRP_EXTENSION_DRIVER_FLAGS) else {
                return STATUS_INSUFFICIENT_RESOURCES;
            };
            (&raw mut (*to).DriverFlags).write((&raw const (*from).DriverFlags).read());
        }
    }
    STATUS_SUCCESS
}

/// [`IoPropagateIrpExtension`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-iopropagateirpextension):
/// [`IoPropagateIrpExtensionEx`] with no offset.
///
/// # Safety
/// As [`IoPropagateIrpExtensionEx`].
pub unsafe extern "C" fn IoPropagateIrpExtension(
    source: *mut IRP,
    target: *mut IRP,
    flags: u32,
) -> NTSTATUS {
    // SAFETY: per the contract.
    unsafe { IoPropagateIrpExtensionEx(source, target, 0, flags) }
}

/// [`IoGetIoAttributionHandle`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-iogetioattributionhandle):
/// the handle under which the request's disk I/O is attributed to a
/// process, if the IRP carries one. NK attributes no I/O, so no IRP
/// does: `STATUS_NOT_FOUND`, Windows' answer for such an IRP.
///
/// # Safety
/// `irp` is a live IRP; `handle` is writable.
pub unsafe extern "C" fn IoGetIoAttributionHandle(
    irp: *mut IRP,
    handle: *mut *mut c_void,
) -> NTSTATUS {
    // SAFETY: per the contract.
    unsafe {
        if !has(irp, IRP_EXTENSION_DISK_IO_ATTRIBUTION) {
            return STATUS_NOT_FOUND;
        }
        handle.write_unaligned((&raw const (*block(irp)).DiskIoAttributionHandle).read());
    }
    STATUS_SUCCESS
}

/// [`IoGetAdapterCryptoEngineExtension`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-iogetadaptercryptoengineextension):
/// the crypto parameters a file system put in the IRP for the
/// adapter's engine. No component of NK puts any:
/// `STATUS_NOT_FOUND`, Windows' answer for such an IRP.
///
/// # Safety
/// `irp` is a live IRP; `parameters` is writable.
pub unsafe extern "C" fn IoGetAdapterCryptoEngineExtension(
    irp: *mut IRP,
    parameters: *mut *mut c_void,
) -> NTSTATUS {
    // SAFETY: per the contract.
    unsafe {
        if !has(irp, IRP_EXTENSION_ADAPTER_CRYPTO) {
            return STATUS_NOT_FOUND;
        }
        parameters.write_unaligned((&raw mut (*block(irp)).Parameters).cast());
    }
    STATUS_SUCCESS
}

// ---- tests --------------------------------------------------------------

/// A GUID whose every part is `n`.
fn id(n: u8) -> GUID {
    GUID {
        Data1: u32::from(n) * 0x0101_0101,
        Data2: u16::from(n) * 0x0101,
        Data3: u16::from(n) * 0x0101,
        Data4: [n; 8],
    }
}

/// The activity id of `irp`, or the status of asking.
fn activity_of(irp: *mut IRP) -> Result<[u8; 16], NTSTATUS> {
    let mut got = id(0xEE);
    // SAFETY: the test's own IRP and a local.
    match unsafe { IoGetActivityIdIrp(irp, &raw mut got) } {
        // SAFETY: a GUID is sixteen plain bytes.
        STATUS_SUCCESS => Ok(unsafe { core::mem::transmute::<GUID, [u8; 16]>(got) }),
        status => Err(status),
    }
}

fn bytes(guid: GUID) -> [u8; 16] {
    // SAFETY: a GUID is sixteen plain bytes.
    unsafe { core::mem::transmute::<GUID, [u8; 16]>(guid) }
}

/// The generic extension of `irp`, or the status of asking.
fn generic_of(irp: *mut IRP) -> Result<[u8; 4], NTSTATUS> {
    let mut got = [0xEE; 4];
    // SAFETY: the test's own IRP and a local.
    match unsafe { IoGetGenericIrpExtension(irp, got.as_mut_ptr(), 4) } {
        STATUS_SUCCESS => Ok(got),
        status => Err(status),
    }
}

/// Extensions of an IRP: the generic one in the pointer's place and
/// then in a block, the activity id, what is copied to another IRP,
/// what survives a reuse, and that the block goes with the IRP.
/// Returns the facts checked.
pub fn extension_test() -> Result<u32, &'static str> {
    use super::irp;
    let before = pool::usage().blocks;
    let (first, second) = (irp::alloc(1), irp::alloc(2));
    if first.is_null() || second.is_null() {
        return Err("no memory for two IRPs");
    }
    // SAFETY: two IRPs of the test's own, freed at the end.
    let verdict = unsafe {
        (|| {
            let set = |irp, data: [u8; 4], size: u16, overwrite: bool| {
                IoSetGenericIrpExtension(irp, data.as_ptr(), size, u8::from(overwrite))
            };
            let handle = |irp| {
                let mut none = core::ptr::null_mut();
                (
                    IoGetIoAttributionHandle(irp, &raw mut none),
                    IoGetAdapterCryptoEngineExtension(irp, &raw mut none),
                )
            };
            // A new IRP has nothing.
            if activity_of(first) != Err(STATUS_NOT_FOUND)
                || generic_of(first) != Err(STATUS_NOT_FOUND)
                || handle(first) != (STATUS_NOT_FOUND, STATUS_NOT_FOUND)
                || IoPropagateIrpExtension(first, second, 0x3F) != STATUS_SUCCESS
                || !(*second).IrpExtension.is_null()
            {
                return Err("an IRP without an extension was found to have one");
            }
            // A generic extension alone lives in the pointer's place.
            if set(first, [1, 2, 3, 4], 5, true) != STATUS_INVALID_PARAMETER
                || set(first, [1, 2, 3, 4], 4, false) != STATUS_SUCCESS
                || (*first).AllocationFlags != IRP_ALLOCATION_GENERIC_INLINE
                || (*first).IrpExtension.addr() != 0x0403_0201
                || pool::usage().blocks != before + 2
            {
                return Err("a generic extension alone was not kept in the IRP itself");
            }
            if set(first, [9, 9, 9, 9], 4, false) != STATUS_ALREADY_COMMITTED
                || set(first, [5, 6, 0, 0], 2, true) != STATUS_SUCCESS
                || generic_of(first) != Ok([5, 6, 3, 4])
                || activity_of(first) != Err(STATUS_NOT_FOUND)
                || handle(first) != (STATUS_NOT_FOUND, STATUS_NOT_FOUND)
            {
                return Err("a generic extension was not kept, overwritten or read back");
            }
            // An activity id needs the block; the generic bytes move.
            let given = id(0x11);
            if IoSetActivityIdIrp(first, &raw const given) != STATUS_SUCCESS
                || (*first).AllocationFlags != IRP_ALLOCATION_EXTENSION
                || pool::usage().blocks != before + 3
                || activity_of(first) != Ok(bytes(id(0x11)))
                || generic_of(first) != Ok([5, 6, 3, 4])
            {
                return Err("an activity id did not move the IRP's extensions into a block");
            }
            let block = (*first).IrpExtension.cast::<IOP_IRP_EXTENSION>();
            if ((*block).ExtensionFlags, (*block).TypesAllocated) != (1, 0b101) {
                return Err("the extension block does not say what it holds");
            }
            // No id given: the thread's own, which no thread of NK has.
            if IoSetActivityIdIrp(second, core::ptr::null()) != STATUS_NOT_SUPPORTED
                || !(*second).IrpExtension.is_null()
                || (*second).AllocationFlags != 0
                || pool::usage().blocks != before + 3
            {
                return Err("an IRP was given an activity id from a thread that has none");
            }
            // Copied: what the flags name, and no more.
            if IoPropagateIrpExtension(first, second, IRP_PROPAGATE_GENERIC) != STATUS_SUCCESS
                || generic_of(second) != Ok([5, 6, 3, 4])
                || activity_of(second) != Err(STATUS_NOT_FOUND)
                || (*second).AllocationFlags != IRP_ALLOCATION_GENERIC_INLINE
            {
                return Err("the generic extension alone was not copied to another IRP");
            }
            if IoPropagateIrpExtensionEx(first, second, 0x1000, 0x3E) != STATUS_SUCCESS
                || activity_of(second) != Ok(bytes(id(0x11)))
                || generic_of(second) != Ok([5, 6, 3, 4])
            {
                return Err("the activity id was not copied to another IRP");
            }
            // From an IRP whose generic extension is in the field.
            release(second, None, true);
            if set(second, [7, 7, 7, 7], 4, true) != STATUS_SUCCESS
                || set(first, [0, 0, 0, 0], 4, true) != STATUS_SUCCESS
                || IoPropagateIrpExtension(second, first, IRP_PROPAGATE_ACTIVITY_ID)
                    != STATUS_SUCCESS
                || generic_of(first) != Ok([0, 0, 0, 0])
                || IoPropagateIrpExtension(second, first, 0x3F) != STATUS_SUCCESS
                || generic_of(first) != Ok([7, 7, 7, 7])
            {
                return Err("a generic extension kept in an IRP was not copied as asked");
            }
            // Reused: the block and the activity id stay, the rest goes.
            irp::IoReuseIrp(first, STATUS_SUCCESS);
            irp::IoReuseIrp(second, STATUS_SUCCESS);
            if (*first).IrpExtension.cast() != block
                || (*first).AllocationFlags != IRP_ALLOCATION_EXTENSION
                || activity_of(first) != Ok(bytes(id(0x11)))
                || generic_of(first) != Err(STATUS_NOT_FOUND)
                || (*second).AllocationFlags != 0
                || !(*second).IrpExtension.is_null()
                || generic_of(second) != Err(STATUS_NOT_FOUND)
            {
                return Err("a reused IRP did not keep its block and activity id alone");
            }
            Ok(27)
        })()
    };
    // SAFETY: the test's IRPs, which no driver holds.
    unsafe {
        irp::IoFreeIrp(first);
        irp::IoFreeIrp(second);
    }
    let facts = verdict?;
    if pool::usage().blocks != before {
        return Err("an IRP's extension block was not freed with the IRP");
    }
    Ok(facts)
}

/// The activity id a thread works under: taken from an IRP and given
/// back.
pub fn thread_activity_test() -> Result<(), &'static str> {
    use super::irp;
    if IoIsActivityTracingEnabled() != 0 {
        return Err("I/O tracing was reported as on");
    }
    let request = irp::alloc(1);
    if request.is_null() {
        return Err("no memory for an IRP");
    }
    let at_first = IoGetActivityIdThread();
    let mut propagated = id(0);
    let mut original = core::ptr::without_provenance::<GUID>(0x5A5A);
    // SAFETY: the test's own IRP, freed at the end; locals that
    // outlive the thread's use of them.
    let verdict = unsafe {
        (|| {
            if IoPropagateActivityIdToThread(request, &raw mut propagated, &raw mut original)
                != STATUS_NOT_FOUND
                || original.addr() != 0x5A5A
                || IoGetActivityIdThread() != at_first
            {
                return Err("an IRP without an activity id gave a thread one");
            }
            let given = id(0x22);
            if IoSetActivityIdIrp(request, &raw const given) != STATUS_SUCCESS
                || IoPropagateActivityIdToThread(request, &raw mut propagated, &raw mut original)
                    != STATUS_SUCCESS
                || bytes((&raw const propagated).read()) != bytes(id(0x22))
                || IoGetActivityIdThread() != &raw const propagated
                || original != at_first
            {
                return Err("a thread was not given the IRP's activity id");
            }
            IoClearActivityIdThread(original);
            if IoGetActivityIdThread() != at_first {
                return Err("a thread's activity id was not given back");
            }
            Ok(())
        })()
    };
    IoClearActivityIdThread(at_first);
    // SAFETY: the test's IRP, which no driver holds.
    unsafe { irp::IoFreeIrp(request) };
    verdict
}
