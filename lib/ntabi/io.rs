//! I/O manager structures: driver, device and file objects, IRPs, MDLs.
//!
//! Layouts are the 64-bit Windows 10 ones from the WDK's `wdm.h`; x86-64
//! and arm64 share them, since every field is a fixed-width integer or a
//! pointer. The `layout` test module pins every offset NK or a fixture
//! driver touches.
//!
//! Fields NK never reads are still present and named, so a driver that
//! does read them finds the right bytes (zero) at the right place.

use crate::status::{NTSTATUS, nt_success};
use core::ffi::c_void;

pub type PVOID = *mut c_void;

pub use crate::ke::{DISPATCHER_HEADER, KEVENT, LIST_ENTRY};

/// `UNICODE_STRING`: a counted UTF-16 string. Lengths are in bytes.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct UNICODE_STRING {
    pub Length: u16,
    pub MaximumLength: u16,
    pub Buffer: *mut u16,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct IO_STATUS_BLOCK {
    /// `Status`, overlaid on a pointer-sized slot.
    pub Status: NTSTATUS,
    pub Information: usize,
}

/// `IO_CSQ.Type` and `IO_CSQ_IRP_CONTEXT.Type`.
pub const IO_TYPE_CSQ_IRP_CONTEXT: u32 = 1;
pub const IO_TYPE_CSQ: u32 = 2;

/// A cancel-safe queue's callbacks, which the driver supplies.
pub type CSQ_INSERT = unsafe extern "C" fn(*mut IO_CSQ, *mut IRP);
pub type CSQ_REMOVE = unsafe extern "C" fn(*mut IO_CSQ, *mut IRP);
pub type CSQ_PEEK = unsafe extern "C" fn(*mut IO_CSQ, *mut IRP, PVOID) -> *mut IRP;
pub type CSQ_ACQUIRE = unsafe extern "C" fn(*mut IO_CSQ, *mut u8);
pub type CSQ_RELEASE = unsafe extern "C" fn(*mut IO_CSQ, u8);
pub type CSQ_COMPLETE = unsafe extern "C" fn(*mut IO_CSQ, *mut IRP);

/// [`IO_CSQ`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/ns-wdm-_io_csq):
/// a cancel-safe queue's dispatch table, kept by the driver.
#[repr(C)]
pub struct IO_CSQ {
    pub Type: u32,
    pub CsqInsertIrp: Option<CSQ_INSERT>,
    pub CsqRemoveIrp: Option<CSQ_REMOVE>,
    pub CsqPeekNextIrp: Option<CSQ_PEEK>,
    pub CsqAcquireLock: Option<CSQ_ACQUIRE>,
    pub CsqReleaseLock: Option<CSQ_RELEASE>,
    pub CsqCompleteCanceledIrp: Option<CSQ_COMPLETE>,
    pub ReservePointer: PVOID,
}

/// `IO_CSQ_IRP_CONTEXT`: lets a driver name one queued request later.
#[repr(C)]
pub struct IO_CSQ_IRP_CONTEXT {
    pub Type: u32,
    pub Irp: *mut IRP,
    pub Csq: *mut IO_CSQ,
}

const _: () = {
    use core::mem::{offset_of, size_of};
    assert!(size_of::<IO_CSQ>() == 0x40);
    assert!(offset_of!(IO_CSQ, CsqInsertIrp) == 0x08);
    assert!(offset_of!(IO_CSQ, CsqCompleteCanceledIrp) == 0x30);
    assert!(offset_of!(IO_CSQ, ReservePointer) == 0x38);
    assert!(size_of::<IO_CSQ_IRP_CONTEXT>() == 0x18);
    assert!(offset_of!(IO_CSQ_IRP_CONTEXT, Irp) == 0x08);
    assert!(offset_of!(IO_CSQ_IRP_CONTEXT, Csq) == 0x10);
};

/// `IO_REMOVE_LOCK` as free builds of drivers see it: the common block
/// only. The fields a checked build adds follow it and are not NK's.
#[repr(C)]
pub struct IO_REMOVE_LOCK {
    pub Removed: u8,
    pub Reserved: [u8; 3],
    pub IoCount: i32,
    pub RemoveEvent: KEVENT,
}

/// `RTL_OSVERSIONINFOEXW`; its first 276 bytes are `RTL_OSVERSIONINFOW`.
#[repr(C)]
pub struct RTL_OSVERSIONINFOEXW {
    pub dwOSVersionInfoSize: u32,
    pub dwMajorVersion: u32,
    pub dwMinorVersion: u32,
    pub dwBuildNumber: u32,
    pub dwPlatformId: u32,
    pub szCSDVersion: [u16; 128],
    pub wServicePackMajor: u16,
    pub wServicePackMinor: u16,
    pub wSuiteMask: u16,
    pub wProductType: u8,
    pub wReserved: u8,
}

/// Size of `RTL_OSVERSIONINFOW`: the structure without its last five
/// fields.
pub const OSVERSIONINFO_SIZE: u32 = 276;

#[repr(C)]
pub struct KDEVICE_QUEUE {
    pub Type: i16,
    pub Size: i16,
    pub DeviceListHead: LIST_ENTRY,
    pub Lock: usize,
    pub Busy: u64,
}

#[repr(C)]
pub struct KDPC {
    pub TargetInfoAsUlong: u32,
    pub DpcListEntry: PVOID,
    pub ProcessorHistory: usize,
    pub DeferredRoutine: PVOID,
    pub DeferredContext: PVOID,
    pub SystemArgument1: PVOID,
    pub SystemArgument2: PVOID,
    pub DpcData: PVOID,
}

pub type DRIVER_DISPATCH = unsafe extern "C" fn(*mut DEVICE_OBJECT, *mut IRP) -> NTSTATUS;
pub type DRIVER_INITIALIZE =
    unsafe extern "C" fn(*mut DRIVER_OBJECT, *mut UNICODE_STRING) -> NTSTATUS;
pub type DRIVER_UNLOAD = unsafe extern "C" fn(*mut DRIVER_OBJECT);
/// `DRIVER_CANCEL`: entered holding the cancel spin lock, which it
/// releases at `Irp->CancelIrql`.
pub type DRIVER_CANCEL = unsafe extern "C" fn(*mut DEVICE_OBJECT, *mut IRP);
pub type IO_COMPLETION_ROUTINE =
    unsafe extern "C" fn(*mut DEVICE_OBJECT, *mut IRP, PVOID) -> NTSTATUS;

pub const IRP_MJ_CREATE: u8 = 0x00;
pub const IRP_MJ_CLOSE: u8 = 0x02;
pub const IRP_MJ_READ: u8 = 0x03;
pub const IRP_MJ_WRITE: u8 = 0x04;
pub const IRP_MJ_DEVICE_CONTROL: u8 = 0x0E;
pub const IRP_MJ_CLEANUP: u8 = 0x12;
pub const IRP_MJ_MAXIMUM_FUNCTION: usize = 0x1B;

pub const IO_TYPE_DEVICE: i16 = 3;
pub const IO_TYPE_DRIVER: i16 = 4;
pub const IO_TYPE_FILE: i16 = 5;
pub const IO_TYPE_IRP: i16 = 6;

#[repr(C)]
pub struct DRIVER_EXTENSION {
    pub DriverObject: *mut DRIVER_OBJECT,
    pub AddDevice: PVOID,
    pub Count: u32,
    pub ServiceKeyName: UNICODE_STRING,
}

#[repr(C)]
pub struct DRIVER_OBJECT {
    pub Type: i16,
    pub Size: i16,
    /// Head of the driver's device list, linked through `NextDevice`.
    pub DeviceObject: *mut DEVICE_OBJECT,
    pub Flags: u32,
    pub DriverStart: PVOID,
    pub DriverSize: u32,
    pub DriverSection: PVOID,
    pub DriverExtension: *mut DRIVER_EXTENSION,
    pub DriverName: UNICODE_STRING,
    pub HardwareDatabase: *mut UNICODE_STRING,
    pub FastIoDispatch: PVOID,
    pub DriverInit: Option<DRIVER_INITIALIZE>,
    pub DriverStartIo: PVOID,
    pub DriverUnload: Option<DRIVER_UNLOAD>,
    pub MajorFunction: [Option<DRIVER_DISPATCH>; IRP_MJ_MAXIMUM_FUNCTION + 1],
}

/// `DEVICE_OBJECT.Flags`
pub const DO_BUFFERED_IO: u32 = 0x0000_0004;
pub const DO_EXCLUSIVE: u32 = 0x0000_0008;
pub const DO_DIRECT_IO: u32 = 0x0000_0010;
pub const DO_DEVICE_HAS_NAME: u32 = 0x0000_0040;
pub const DO_DEVICE_INITIALIZING: u32 = 0x0000_0080;

/// `DEVICE_OBJECT.Queue`: a device-queue wait block, 0x48 bytes.
#[repr(C)]
pub struct WAIT_CONTEXT_BLOCK {
    pub WaitQueueEntry: [u64; 3],
    pub DeviceRoutine: PVOID,
    pub DeviceContext: PVOID,
    pub NumberOfMapRegisters: u32,
    pub DeviceObject: PVOID,
    pub CurrentIrp: PVOID,
    pub BufferChainingDpc: PVOID,
}

/// Windows declares `DEVICE_OBJECT` with 16-byte alignment, which rounds
/// its size up to 0x150. The device extension follows it.
#[repr(C, align(16))]
pub struct DEVICE_OBJECT {
    pub Type: i16,
    pub Size: u16,
    pub ReferenceCount: i32,
    pub DriverObject: *mut DRIVER_OBJECT,
    pub NextDevice: *mut DEVICE_OBJECT,
    pub AttachedDevice: *mut DEVICE_OBJECT,
    pub CurrentIrp: *mut IRP,
    pub Timer: PVOID,
    pub Flags: u32,
    pub Characteristics: u32,
    pub Vpb: PVOID,
    pub DeviceExtension: PVOID,
    pub DeviceType: u32,
    pub StackSize: i8,
    pub Queue: WAIT_CONTEXT_BLOCK,
    pub AlignmentRequirement: u32,
    pub DeviceQueue: KDEVICE_QUEUE,
    pub Dpc: KDPC,
    pub ActiveThreadCount: u32,
    pub SecurityDescriptor: PVOID,
    pub DeviceLock: KEVENT,
    pub SectorSize: u16,
    pub Spare1: u16,
    pub DeviceObjectExtension: PVOID,
    pub Reserved: PVOID,
}

/// `FILE_OBJECT.Flags`
pub const FO_SYNCHRONOUS_IO: u32 = 0x0000_0002;

#[repr(C)]
pub struct FILE_OBJECT {
    pub Type: i16,
    pub Size: i16,
    pub DeviceObject: *mut DEVICE_OBJECT,
    pub Vpb: PVOID,
    pub FsContext: PVOID,
    pub FsContext2: PVOID,
    pub SectionObjectPointer: PVOID,
    pub PrivateCacheMap: PVOID,
    pub FinalStatus: NTSTATUS,
    pub RelatedFileObject: *mut FILE_OBJECT,
    pub LockOperation: u8,
    pub DeletePending: u8,
    pub ReadAccess: u8,
    pub WriteAccess: u8,
    pub DeleteAccess: u8,
    pub SharedRead: u8,
    pub SharedWrite: u8,
    pub SharedDelete: u8,
    pub Flags: u32,
    pub FileName: UNICODE_STRING,
    pub CurrentByteOffset: i64,
    pub Waiters: u32,
    pub Busy: u32,
    pub LastLock: PVOID,
    pub Lock: KEVENT,
    pub Event: KEVENT,
    pub CompletionContext: PVOID,
    pub IrpListLock: usize,
    pub IrpList: LIST_ENTRY,
    pub FileObjectExtension: PVOID,
}

/// `IRP.Flags`
pub const IRP_BUFFERED_IO: u32 = 0x0000_0010;
pub const IRP_DEALLOCATE_BUFFER: u32 = 0x0000_0020;
pub const IRP_INPUT_OPERATION: u32 = 0x0000_0040;

/// `KPROCESSOR_MODE`
pub const KERNEL_MODE: i8 = 0;
pub const USER_MODE: i8 = 1;

#[repr(C)]
pub struct IRP {
    pub Type: i16,
    pub Size: u16,
    pub MdlAddress: *mut MDL,
    pub Flags: u32,
    /// `AssociatedIrp`: a union; drivers of buffered I/O read `SystemBuffer`.
    pub SystemBuffer: PVOID,
    pub ThreadListEntry: LIST_ENTRY,
    pub IoStatus: IO_STATUS_BLOCK,
    pub RequestorMode: i8,
    pub PendingReturned: u8,
    pub StackCount: i8,
    pub CurrentLocation: i8,
    pub Cancel: u8,
    pub CancelIrql: u8,
    pub ApcEnvironment: i8,
    pub AllocationFlags: u8,
    pub UserIosb: *mut IO_STATUS_BLOCK,
    pub UserEvent: *mut KEVENT,
    /// `Overlay`: APC routine and context, or an allocation size.
    pub Overlay: [u64; 2],
    pub CancelRoutine: PVOID,
    pub UserBuffer: PVOID,
    /// `Tail.Overlay.DriverContext`: four pointers for the driver's use.
    pub DriverContext: [PVOID; 4],
    pub Thread: PVOID,
    pub AuxiliaryBuffer: PVOID,
    pub ListEntry: LIST_ENTRY,
    /// `Tail.Overlay.CurrentStackLocation`
    pub CurrentStackLocation: *mut IO_STACK_LOCATION,
    pub OriginalFileObject: *mut FILE_OBJECT,
    pub IrpExtension: PVOID,
}

/// `IO_STACK_LOCATION.Control`
pub const SL_PENDING_RETURNED: u8 = 0x01;
pub const SL_INVOKE_ON_CANCEL: u8 = 0x20;
pub const SL_INVOKE_ON_SUCCESS: u8 = 0x40;
pub const SL_INVOKE_ON_ERROR: u8 = 0x80;

/// One driver's view of a request. `Parameters` is a union of per-request
/// structs; it is kept as four raw 8-byte slots and decoded by the
/// accessors below, because on 64-bit Windows every member of those
/// structs is pointer aligned.
#[repr(C)]
pub struct IO_STACK_LOCATION {
    pub MajorFunction: u8,
    pub MinorFunction: u8,
    pub Flags: u8,
    pub Control: u8,
    pub Parameters: [u64; 4],
    pub DeviceObject: *mut DEVICE_OBJECT,
    pub FileObject: *mut FILE_OBJECT,
    pub CompletionRoutine: Option<IO_COMPLETION_ROUTINE>,
    pub Context: PVOID,
}

/// How many stack locations an IRP for a device stack `stack_size` deep
/// has, and the size of the IRP with them, as `IoSizeOfIrp` gives it. A
/// request always has at least one location.
pub const fn irp_size(stack_size: i8) -> (usize, usize) {
    let locations = if stack_size < 1 {
        1
    } else {
        stack_size as usize
    };
    (
        locations,
        size_of::<IRP>() + locations * size_of::<IO_STACK_LOCATION>(),
    )
}

/// Whether a stack location's completion routine is to be called, given
/// the location's `Control` byte, the status the request completed with
/// and whether it was cancelled: on success, on failure or on
/// cancellation, as the driver that set the routine asked
/// (`IoSetCompletionRoutine`).
pub const fn completion_routine_wanted(control: u8, status: NTSTATUS, cancelled: bool) -> bool {
    (nt_success(status) && control & SL_INVOKE_ON_SUCCESS != 0)
        || (!nt_success(status) && control & SL_INVOKE_ON_ERROR != 0)
        || (cancelled && control & SL_INVOKE_ON_CANCEL != 0)
}

/// `Parameters.Read` / `Parameters.Write`: Length, Key, ByteOffset.
pub const fn rw_parameters(length: u32, byte_offset: i64) -> [u64; 4] {
    [length as u64, 0, byte_offset as u64, 0]
}

/// `Parameters.DeviceIoControl`: OutputBufferLength, InputBufferLength,
/// IoControlCode, Type3InputBuffer.
pub const fn ioctl_parameters(out_len: u32, in_len: u32, code: u32, type3_input: u64) -> [u64; 4] {
    [out_len as u64, in_len as u64, code as u64, type3_input]
}

/// Buffer-passing method of an I/O control code: its low two bits.
pub const METHOD_BUFFERED: u32 = 0;
pub const METHOD_IN_DIRECT: u32 = 1;
pub const METHOD_OUT_DIRECT: u32 = 2;
pub const METHOD_NEITHER: u32 = 3;

/// The `CTL_CODE` macro.
pub const fn ctl_code(device_type: u32, function: u32, method: u32, access: u32) -> u32 {
    device_type << 16 | access << 14 | function << 2 | method
}

/// `MDL.MdlFlags`
pub const MDL_MAPPED_TO_SYSTEM_VA: i16 = 0x0001;
pub const MDL_PAGES_LOCKED: i16 = 0x0002;
pub const MDL_SOURCE_IS_NONPAGED_POOL: i16 = 0x0004;
pub const MDL_ALLOCATED_FIXED_SIZE: i16 = 0x0008;

/// Memory descriptor list header. An array of page frame numbers (one
/// `u64` per page spanned) follows it in the same allocation.
#[repr(C)]
pub struct MDL {
    pub Next: *mut MDL,
    pub Size: i16,
    pub MdlFlags: i16,
    pub AllocationProcessorNumber: u16,
    pub Reserved: u16,
    pub Process: PVOID,
    pub MappedSystemVa: PVOID,
    pub StartVa: PVOID,
    pub ByteCount: u32,
    pub ByteOffset: u32,
}

/// Pages spanned by `len` bytes starting at `va`: the
/// `ADDRESS_AND_SIZE_TO_SPAN_PAGES` macro.
pub const fn span_pages(va: usize, len: usize) -> usize {
    ((va & 0xFFF) + len + 0xFFF) >> 12
}

/// Bytes `IoAllocateMdl` needs for a buffer: header plus one PFN per page.
pub const fn mdl_size(va: usize, len: usize) -> usize {
    size_of::<MDL>() + span_pages(va, len) * 8
}

/// The layouts drivers were compiled against, from the Windows 10 x64
/// public symbols; arm64 is identical. Checked when this crate is built,
/// for every target, so a definition that drifts cannot reach a driver.
/// `probe.rs` compares the same definitions with tables the WDK produced.
const _: () = {
    use core::mem::{align_of, offset_of, size_of};
    assert!(size_of::<UNICODE_STRING>() == 0x10);
    assert!(size_of::<LIST_ENTRY>() == 0x10);
    assert!(size_of::<IO_STATUS_BLOCK>() == 0x10);
    assert!(size_of::<DISPATCHER_HEADER>() == 0x18);
    assert!(size_of::<KEVENT>() == 0x18);
    assert!(size_of::<KDEVICE_QUEUE>() == 0x28);
    assert!(size_of::<KDPC>() == 0x40);
    assert!(size_of::<WAIT_CONTEXT_BLOCK>() == 0x48);
    assert!(size_of::<DRIVER_EXTENSION>() == 0x28);
    assert!(size_of::<DRIVER_OBJECT>() == 0x150);
    assert!(size_of::<DEVICE_OBJECT>() == 0x150);
    assert!(align_of::<DEVICE_OBJECT>() == 16);
    assert!(size_of::<FILE_OBJECT>() == 0xD8);
    assert!(size_of::<IRP>() == 0xD0);
    assert!(size_of::<IO_STACK_LOCATION>() == 0x48);
    assert!(size_of::<MDL>() == 0x30);
    assert!(offset_of!(DRIVER_OBJECT, DeviceObject) == 0x08);
    assert!(offset_of!(DRIVER_OBJECT, DriverStart) == 0x18);
    assert!(offset_of!(DRIVER_OBJECT, DriverExtension) == 0x30);
    assert!(offset_of!(DRIVER_OBJECT, DriverName) == 0x38);
    assert!(offset_of!(DRIVER_OBJECT, FastIoDispatch) == 0x50);
    assert!(offset_of!(DRIVER_OBJECT, DriverInit) == 0x58);
    assert!(offset_of!(DRIVER_OBJECT, DriverUnload) == 0x68);
    assert!(offset_of!(DRIVER_OBJECT, MajorFunction) == 0x70);
    assert!(offset_of!(DEVICE_OBJECT, ReferenceCount) == 0x04);
    assert!(offset_of!(DEVICE_OBJECT, DriverObject) == 0x08);
    assert!(offset_of!(DEVICE_OBJECT, NextDevice) == 0x10);
    assert!(offset_of!(DEVICE_OBJECT, AttachedDevice) == 0x18);
    assert!(offset_of!(DEVICE_OBJECT, Flags) == 0x30);
    assert!(offset_of!(DEVICE_OBJECT, Characteristics) == 0x34);
    assert!(offset_of!(DEVICE_OBJECT, DeviceExtension) == 0x40);
    assert!(offset_of!(DEVICE_OBJECT, DeviceType) == 0x48);
    assert!(offset_of!(DEVICE_OBJECT, StackSize) == 0x4C);
    assert!(offset_of!(DEVICE_OBJECT, Queue) == 0x50);
    assert!(offset_of!(DEVICE_OBJECT, AlignmentRequirement) == 0x98);
    assert!(offset_of!(DEVICE_OBJECT, DeviceQueue) == 0xA0);
    assert!(offset_of!(DEVICE_OBJECT, Dpc) == 0xC8);
    assert!(offset_of!(DEVICE_OBJECT, ActiveThreadCount) == 0x108);
    assert!(offset_of!(DEVICE_OBJECT, SecurityDescriptor) == 0x110);
    assert!(offset_of!(DEVICE_OBJECT, DeviceLock) == 0x118);
    assert!(offset_of!(DEVICE_OBJECT, SectorSize) == 0x130);
    assert!(offset_of!(DEVICE_OBJECT, DeviceObjectExtension) == 0x138);
    assert!(offset_of!(DEVICE_OBJECT, Reserved) == 0x140);
    assert!(offset_of!(FILE_OBJECT, DeviceObject) == 0x08);
    assert!(offset_of!(FILE_OBJECT, FsContext) == 0x18);
    assert!(offset_of!(FILE_OBJECT, PrivateCacheMap) == 0x30);
    assert!(offset_of!(FILE_OBJECT, FinalStatus) == 0x38);
    assert!(offset_of!(FILE_OBJECT, RelatedFileObject) == 0x40);
    assert!(offset_of!(FILE_OBJECT, Flags) == 0x50);
    assert!(offset_of!(FILE_OBJECT, FileName) == 0x58);
    assert!(offset_of!(FILE_OBJECT, CurrentByteOffset) == 0x68);
    assert!(offset_of!(FILE_OBJECT, Lock) == 0x80);
    assert!(offset_of!(FILE_OBJECT, Event) == 0x98);
    assert!(offset_of!(FILE_OBJECT, CompletionContext) == 0xB0);
    assert!(offset_of!(FILE_OBJECT, IrpList) == 0xC0);
    assert!(offset_of!(FILE_OBJECT, FileObjectExtension) == 0xD0);
    assert!(offset_of!(IRP, MdlAddress) == 0x08);
    assert!(offset_of!(IRP, Flags) == 0x10);
    assert!(offset_of!(IRP, SystemBuffer) == 0x18);
    assert!(offset_of!(IRP, IoStatus) == 0x30);
    assert!(offset_of!(IRP, RequestorMode) == 0x40);
    assert!(offset_of!(IRP, PendingReturned) == 0x41);
    assert!(offset_of!(IRP, StackCount) == 0x42);
    assert!(offset_of!(IRP, CurrentLocation) == 0x43);
    assert!(offset_of!(IRP, Cancel) == 0x44);
    assert!(offset_of!(IRP, UserIosb) == 0x48);
    assert!(offset_of!(IRP, UserEvent) == 0x50);
    assert!(offset_of!(IRP, CancelRoutine) == 0x68);
    assert!(offset_of!(IRP, UserBuffer) == 0x70);
    assert!(offset_of!(IRP, DriverContext) == 0x78);
    assert!(offset_of!(IRP, Thread) == 0x98);
    assert!(offset_of!(IRP, ListEntry) == 0xA8);
    assert!(offset_of!(IRP, CurrentStackLocation) == 0xB8);
    assert!(offset_of!(IRP, OriginalFileObject) == 0xC0);
    assert!(offset_of!(IO_STACK_LOCATION, Control) == 0x03);
    assert!(offset_of!(IO_STACK_LOCATION, Parameters) == 0x08);
    assert!(offset_of!(IO_STACK_LOCATION, DeviceObject) == 0x28);
    assert!(offset_of!(IO_STACK_LOCATION, FileObject) == 0x30);
    assert!(offset_of!(IO_STACK_LOCATION, CompletionRoutine) == 0x38);
    assert!(offset_of!(IO_STACK_LOCATION, Context) == 0x40);
    assert!(offset_of!(MDL, MdlFlags) == 0x0A);
    assert!(offset_of!(MDL, MappedSystemVa) == 0x18);
    assert!(offset_of!(MDL, StartVa) == 0x20);
    assert!(offset_of!(MDL, ByteCount) == 0x28);
    assert!(offset_of!(MDL, ByteOffset) == 0x2C);
    assert!(offset_of!(IO_STATUS_BLOCK, Information) == 0x08);
    assert!(offset_of!(DISPATCHER_HEADER, SignalState) == 0x04);
    assert!(offset_of!(DISPATCHER_HEADER, WaitListHead) == 0x08);
};

const _: () = {
    use core::mem::{offset_of, size_of};
    assert!(size_of::<IO_REMOVE_LOCK>() == 0x20);
    assert!(offset_of!(IO_REMOVE_LOCK, IoCount) == 0x04);
    assert!(offset_of!(IO_REMOVE_LOCK, RemoveEvent) == 0x08);
    assert!(size_of::<RTL_OSVERSIONINFOEXW>() == 284);
    assert!(offset_of!(RTL_OSVERSIONINFOEXW, wServicePackMajor) == OSVERSIONINFO_SIZE as usize);
};

#[cfg(test)]
mod layout {
    use super::*;
    /// `Parameters` offsets as drivers compile them (cross-checked against
    /// the disassembly of Microsoft's null.sys, which reads Write.Length at
    /// +0x08 and QueryFile.FileInformationClass at +0x10 of the location).
    #[test]
    fn parameters() {
        assert_eq!(rw_parameters(0x1234, 0x55), [0x1234, 0, 0x55, 0]);
        assert_eq!(ioctl_parameters(1, 2, 3, 4), [1, 2, 3, 4]);
        // The four codes of Microsoft's SIOCTL sample (device type 40000).
        assert_eq!(ctl_code(40000, 0x900, METHOD_IN_DIRECT, 0), 0x9C40_2401);
        assert_eq!(ctl_code(40000, 0x901, METHOD_OUT_DIRECT, 0), 0x9C40_2406);
        assert_eq!(ctl_code(40000, 0x902, METHOD_BUFFERED, 0), 0x9C40_2408);
        assert_eq!(ctl_code(40000, 0x903, METHOD_NEITHER, 0), 0x9C40_240F);
    }

    #[test]
    fn an_irp_has_at_least_one_stack_location() {
        // 0xD0 for the IRP and 0x48 for each location, on 64-bit Windows.
        assert_eq!(irp_size(1), (1, 0xD0 + 0x48));
        assert_eq!(irp_size(2), (2, 0xD0 + 2 * 0x48));
        assert_eq!(irp_size(0), (1, 0xD0 + 0x48));
        assert_eq!(irp_size(-1), (1, 0xD0 + 0x48));
        assert_eq!(irp_size(i8::MIN), (1, 0xD0 + 0x48));
        // The deepest stack still fits the IRP's 16-bit `Size`.
        let (locations, size) = irp_size(i8::MAX);
        assert_eq!(locations, 127);
        assert!(size <= usize::from(u16::MAX));
    }

    #[test]
    fn a_completion_routine_is_called_for_the_outcomes_it_asked_for() {
        use crate::status::*;
        let wanted = completion_routine_wanted;
        // Asked for nothing: never called.
        for status in [STATUS_SUCCESS, STATUS_END_OF_FILE] {
            assert!(!wanted(0, status, false));
            assert!(!wanted(0, status, true));
            assert!(!wanted(SL_PENDING_RETURNED, status, true));
        }
        // On success only.
        assert!(wanted(SL_INVOKE_ON_SUCCESS, STATUS_SUCCESS, false));
        assert!(!wanted(SL_INVOKE_ON_SUCCESS, STATUS_END_OF_FILE, false));
        // On error only.
        assert!(wanted(SL_INVOKE_ON_ERROR, STATUS_END_OF_FILE, false));
        assert!(!wanted(SL_INVOKE_ON_ERROR, STATUS_SUCCESS, false));
        // On cancellation only: whatever the status, if cancelled.
        assert!(wanted(SL_INVOKE_ON_CANCEL, STATUS_SUCCESS, true));
        assert!(wanted(SL_INVOKE_ON_CANCEL, STATUS_END_OF_FILE, true));
        assert!(!wanted(SL_INVOKE_ON_CANCEL, STATUS_SUCCESS, false));
        assert!(!wanted(SL_INVOKE_ON_CANCEL, STATUS_END_OF_FILE, false));
        // All three, as `IoSetCompletionRoutine(.., TRUE, TRUE, TRUE)`.
        let all = SL_INVOKE_ON_SUCCESS | SL_INVOKE_ON_ERROR | SL_INVOKE_ON_CANCEL;
        for status in [STATUS_SUCCESS, STATUS_END_OF_FILE, STATUS_BUFFER_OVERFLOW] {
            assert!(wanted(all, status, false));
            assert!(wanted(all, status, true));
        }
    }

    #[test]
    fn a_warning_counts_as_a_failure_and_information_as_a_success() {
        use crate::status::*;
        let wanted = completion_routine_wanted;
        // `NT_SUCCESS` draws the line: a warning is not a success.
        assert!(wanted(SL_INVOKE_ON_ERROR, STATUS_BUFFER_OVERFLOW, false));
        assert!(!wanted(SL_INVOKE_ON_SUCCESS, STATUS_BUFFER_OVERFLOW, false));
        let informational = STATUS_IMAGE_MACHINE_TYPE_MISMATCH;
        assert!(wanted(SL_INVOKE_ON_SUCCESS, informational, false));
        assert!(!wanted(SL_INVOKE_ON_ERROR, informational, false));
        // The pending-returned bit shares the byte and changes nothing.
        let noisy = SL_INVOKE_ON_ERROR | SL_PENDING_RETURNED;
        assert!(wanted(noisy, STATUS_END_OF_FILE, false));
        assert!(!wanted(noisy, STATUS_SUCCESS, false));
    }

    #[test]
    fn mdl_page_math() {
        assert_eq!(span_pages(0x1000, 0), 0);
        assert_eq!(span_pages(0x1000, 1), 1);
        assert_eq!(span_pages(0x1000, 0x1000), 1);
        assert_eq!(
            span_pages(0x1FFF, 2),
            2,
            "two bytes straddling a page boundary"
        );
        assert_eq!(span_pages(0x1800, 0x1000), 2);
        assert_eq!(span_pages(0x1001, 0x2FFF), 3);
        assert_eq!(mdl_size(0x1FFF, 2), 0x30 + 16);
    }
}
