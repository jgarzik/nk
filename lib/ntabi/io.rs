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
/// A queue set up by `IoCsqInitializeEx`, whose insert routine returns
/// a status.
pub const IO_TYPE_CSQ_EX: u32 = 3;

/// A cancel-safe queue's callbacks, which the driver supplies.
pub type CSQ_INSERT = unsafe extern "C" fn(*mut IO_CSQ, *mut IRP);
pub type CSQ_INSERT_EX = unsafe extern "C" fn(*mut IO_CSQ, *mut IRP, PVOID) -> NTSTATUS;
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
    /// A [`CSQ_INSERT`], or a [`CSQ_INSERT_EX`] when `Type` is
    /// [`IO_TYPE_CSQ_EX`].
    pub CsqInsertIrp: PVOID,
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

/// `KDEVICE_QUEUE_ENTRY`: how a request waits in a device queue. In an
/// IRP it is `Tail.Overlay.DeviceQueueEntry`, which shares its place
/// with the driver context ([`IRP_DEVICE_QUEUE_ENTRY`]).
#[repr(C)]
pub struct KDEVICE_QUEUE_ENTRY {
    pub DeviceListEntry: LIST_ENTRY,
    pub SortKey: u32,
    pub Inserted: u8,
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
pub const IRP_MJ_CREATE_NAMED_PIPE: u8 = 0x01;
pub const IRP_MJ_CLOSE: u8 = 0x02;
pub const IRP_MJ_READ: u8 = 0x03;
pub const IRP_MJ_WRITE: u8 = 0x04;
pub const IRP_MJ_QUERY_INFORMATION: u8 = 0x05;
pub const IRP_MJ_SET_INFORMATION: u8 = 0x06;
pub const IRP_MJ_FLUSH_BUFFERS: u8 = 0x09;
pub const IRP_MJ_QUERY_VOLUME_INFORMATION: u8 = 0x0A;
pub const IRP_MJ_FILE_SYSTEM_CONTROL: u8 = 0x0D;
pub const IRP_MJ_DEVICE_CONTROL: u8 = 0x0E;
pub const IRP_MJ_INTERNAL_DEVICE_CONTROL: u8 = 0x0F;
pub const IRP_MJ_SHUTDOWN: u8 = 0x10;
pub const IRP_MJ_CLEANUP: u8 = 0x12;
pub const IRP_MJ_CREATE_MAILSLOT: u8 = 0x13;
pub const IRP_MJ_POWER: u8 = 0x16;
pub const IRP_MJ_SYSTEM_CONTROL: u8 = 0x17;
pub const IRP_MJ_PNP: u8 = 0x1B;
/// Minor functions of `IRP_MJ_SYSTEM_CONTROL`: WMI asks a driver for
/// its registration, the older way and the newer.
pub const IRP_MN_REGINFO: u8 = 0x08;
pub const IRP_MN_REGINFO_EX: u8 = 0x0B;
pub const IRP_MJ_MAXIMUM_FUNCTION: usize = 0x1B;

pub const IO_TYPE_DEVICE: i16 = 3;
/// `VPB.Type` (`IO_TYPE_VPB`).
pub const IO_TYPE_VPB: i16 = 0x0A;

/// The device types whose devices the I/O manager gives a volume
/// parameter block: what a file system can be mounted on
/// (`FILE_DEVICE_CD_ROM`, `FILE_DEVICE_DISK`, `FILE_DEVICE_TAPE`,
/// `FILE_DEVICE_VIRTUAL_DISK`), as `IoCreateDevice` of the pinned
/// kernel tests them.
pub const fn device_type_has_vpb(device_type: u32) -> bool {
    matches!(device_type, 0x02 | 0x07 | 0x1F | 0x24)
}

/// `VPB.Flags`: a file system is mounted on the device; the device
/// accepts the raw file system even when a file in it is opened.
pub const VPB_MOUNTED: u16 = 0x0001;
pub const VPB_RAW_MOUNT: u16 = 0x0010;
/// `VPB_REMOVE_PENDING`: the device is being deleted; the volume is
/// dismounted once nothing is open on it.
pub const VPB_REMOVE_PENDING: u16 = 0x0008;
/// `VPB_LOCKED`: the volume is locked; opens of it are refused.
pub const VPB_LOCKED: u16 = 0x0002;
/// `VPB_DIRECT_WRITES_ALLOWED`: set by the I/O manager when the last
/// file system on the queue, RAW, mounted the volume.
pub const VPB_DIRECT_WRITES_ALLOWED: u16 = 0x0020;

/// `IRP_MN_MOUNT_VOLUME` and `IRP_MN_VERIFY_VOLUME`, minor functions
/// of `IRP_MJ_FILE_SYSTEM_CONTROL`.
pub const IRP_MN_USER_FS_REQUEST: u8 = 0x00;
pub const IRP_MN_MOUNT_VOLUME: u8 = 0x01;
/// `SL_ALLOW_RAW_MOUNT`: a mount request's location flag, the open
/// that caused it allowing RAW.
pub const SL_ALLOW_RAW_MOUNT: u8 = 0x01;
/// `IRP_MOUNT_COMPLETION | IRP_SYNCHRONOUS_PAGING_IO`: the flags of
/// the mount request the I/O manager sends.
pub const IRP_MOUNT_COMPLETION: u32 = 0x0000_0002;
/// `IRP_ASSOCIATED_IRP`: the request is one of a master's associated
/// requests (`IoMakeAssociatedIrp`); `AssociatedIrp.MasterIrp` names it.
pub const IRP_ASSOCIATED_IRP: u32 = 0x0000_0008;
/// `DO_LOW_PRIORITY_FILESYSTEM`: a file system that registers behind
/// the others, just ahead of RAW.
pub const DO_LOW_PRIORITY_FILESYSTEM: u32 = 0x0001_0000;
/// `DRVO_BASE_FILESYSTEM_DRIVER`: the driver registered a disk, CD-ROM
/// or tape file system; it is sent the file systems' shutdown request.
pub const DRVO_BASE_FILESYSTEM_DRIVER: u32 = 0x80;
/// `FO_STREAM_FILE` and `FO_DIRECT_DEVICE_OPEN`.
pub const FO_STREAM_FILE: u32 = 0x0000_0100;
pub const FO_DIRECT_DEVICE_OPEN: u32 = 0x0000_0800;

/// `DO_VERIFY_VOLUME`: the volume must be verified before its file
/// system uses it again; mounting clears it.
pub const DO_VERIFY_VOLUME: u32 = 0x0000_0002;

/// `FILE_DEVICE_DISK_FILE_SYSTEM`: the type of a disk file system's
/// devices.
pub const FILE_DEVICE_DISK_FILE_SYSTEM: u32 = 0x08;

/// [`VPB`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/ns-wdm-_vpb):
/// the volume parameter block of a device a file system can be mounted
/// on. `disk.sys` sets `VPB_RAW_MOUNT` in the block of the device it
/// creates.
#[repr(C)]
pub struct VPB {
    pub Type: i16,
    pub Size: i16,
    pub Flags: u16,
    pub VolumeLabelLength: u16,
    /// The file system's volume device, once one is mounted.
    pub DeviceObject: *mut DEVICE_OBJECT,
    /// The device the block belongs to.
    pub RealDevice: *mut DEVICE_OBJECT,
    pub SerialNumber: u32,
    pub ReferenceCount: u32,
    pub VolumeLabel: [u16; 32],
}

const _: () = {
    assert!(size_of::<VPB>() == 0x60);
    assert!(core::mem::offset_of!(VPB, Flags) == 0x04);
    assert!(core::mem::offset_of!(VPB, DeviceObject) == 0x08);
    assert!(core::mem::offset_of!(VPB, RealDevice) == 0x10);
    assert!(core::mem::offset_of!(VPB, SerialNumber) == 0x18);
    assert!(core::mem::offset_of!(VPB, ReferenceCount) == 0x1C);
    assert!(core::mem::offset_of!(VPB, VolumeLabel) == 0x20);
};

pub const IO_TYPE_DRIVER: i16 = 4;
pub const IO_TYPE_FILE: i16 = 5;
pub const IO_TYPE_IRP: i16 = 6;

/// `DRIVER_OBJECT.DriverExtension`. The WDK declares it as far as
/// `ServiceKeyName`; the rest is the I/O manager's own, laid out as the
/// pinned kernel's.
#[repr(C)]
pub struct DRIVER_EXTENSION {
    pub DriverObject: *mut DRIVER_OBJECT,
    pub AddDevice: PVOID,
    pub Count: u32,
    pub ServiceKeyName: UNICODE_STRING,
    /// The extensions the driver allocated for its driver object
    /// (`IoAllocateDriverObjectExtension`), newest first.
    pub ClientDriverExtension: *mut IO_CLIENT_EXTENSION,
    pub FsFilterCallbacks: PVOID,
    pub KseCallbacks: PVOID,
    pub DvCallbacks: PVOID,
    pub VerifierContext: PVOID,
}

/// What precedes each extension a driver allocates for its driver
/// object: the next one, and the address the driver knows it by.
#[repr(C)]
pub struct IO_CLIENT_EXTENSION {
    pub NextExtension: *mut IO_CLIENT_EXTENSION,
    pub ClientIdentificationAddress: PVOID,
}

/// `ERROR_LOG_ENTRY.Type` (`IO_TYPE_ERROR_LOG`).
pub const IO_TYPE_ERROR_LOG: i16 = 0x0B;

/// [`IO_ERROR_LOG_PACKET`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/ns-wdm-_io_error_log_packet):
/// what a driver fills in to report an error. Dump data and insertion
/// strings follow it, within the size the driver asked for.
#[repr(C)]
pub struct IO_ERROR_LOG_PACKET {
    pub MajorFunctionCode: u8,
    pub RetryCount: u8,
    pub DumpDataSize: u16,
    pub NumberOfStrings: u16,
    pub StringOffset: u16,
    pub EventCategory: u16,
    pub ErrorCode: NTSTATUS,
    pub UniqueErrorValue: u32,
    pub FinalStatus: NTSTATUS,
    pub SequenceNumber: u32,
    pub IoControlCode: u32,
    pub DeviceOffset: i64,
    pub DumpData: [u32; 1],
}

/// What the I/O manager keeps in front of an error-log packet: the
/// pinned kernel's `ERROR_LOG_ENTRY`, which no header and no symbol
/// file declares, as `IoAllocateErrorLogEntry` and
/// `IoWriteErrorLogEntry` of that kernel fill it in.
#[repr(C)]
pub struct ERROR_LOG_ENTRY {
    pub Type: i16,
    pub Size: i16,
    pub ListEntry: LIST_ENTRY,
    pub DeviceObject: *mut DEVICE_OBJECT,
    pub DriverObject: *mut DRIVER_OBJECT,
    pub TimeStamp: i64,
}

/// `ERROR_LOG_MAXIMUM_SIZE` (`wdm.h`): the largest packet, strings and
/// dump data included.
pub const ERROR_LOG_MAXIMUM_SIZE: u8 = 240;

/// How many bytes of error-log packets may be outstanding before the
/// pinned kernel allocates no more.
pub const ERROR_LOG_OUTSTANDING_LIMIT: u32 = 0x6_4000;

/// The bytes `IoAllocateErrorLogEntry` allocates for a packet of
/// `entry_size` bytes: the header, then the packet rounded up to eight
/// bytes. `None` for a size smaller than the packet's fixed part or
/// larger than `ERROR_LOG_MAXIMUM_SIZE`, which Windows refuses.
pub const fn error_log_allocation(entry_size: u8) -> Option<usize> {
    let size = entry_size as usize;
    if size < size_of::<IO_ERROR_LOG_PACKET>() || entry_size > ERROR_LOG_MAXIMUM_SIZE {
        return None;
    }
    Some(size_of::<ERROR_LOG_ENTRY>() + ((size + 7) & !7))
}

/// The largest extension `IoAllocateDriverObjectExtension` of the
/// pinned kernel allocates: its header must still fit a 32-bit size.
pub const MAXIMUM_DRIVER_OBJECT_EXTENSION: u32 = 0xFFFF_FFEF;

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
/// Passed up a stack: a device attached to one that has it gets it.
pub const DO_DEVICE_IRP_REQUIRES_EXTENSION: u32 = 0x0800_0000;

/// The deepest stack another device can still be attached to: the
/// pinned kernel refuses to attach to a device whose `StackSize` has
/// reached this.
pub const MAXIMUM_ATTACH_STACK_SIZE: i8 = 0x7D;

/// How many routines a `FAST_IO_DISPATCH` holds.
pub const FAST_IO_ROUTINES: usize = 27;
/// Which of them is `FastIoDetachDevice`.
pub const FAST_IO_DETACH_DEVICE: usize = 12;

/// [`FAST_IO_DISPATCH`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/ns-wdm-_fast_io_dispatch):
/// what `DRIVER_OBJECT.FastIoDispatch` points to. The driver says how
/// much of it there is; a routine past that size is not there.
#[repr(C)]
pub struct FAST_IO_DISPATCH {
    pub SizeOfFastIoDispatch: u32,
    pub Routines: [PVOID; FAST_IO_ROUTINES],
}

/// `FastIoDetachDevice`: the device `target`, which `source` is
/// attached to, is being deleted.
pub type FAST_IO_DETACH_DEVICE_ROUTINE =
    unsafe extern "C" fn(source: *mut DEVICE_OBJECT, target: *mut DEVICE_OBJECT);

/// Where in a driver's `FAST_IO_DISPATCH` the routine numbered `index`
/// is, if a table of `size` bytes (`SizeOfFastIoDispatch`) reaches it:
/// the pinned kernel calls `FastIoDetachDevice` only from a table
/// larger than the routine's offset.
pub const fn fast_io_routine_offset(size: u32, index: usize) -> Option<usize> {
    let offset = core::mem::offset_of!(FAST_IO_DISPATCH, Routines) + index * size_of::<PVOID>();
    if index < FAST_IO_ROUTINES && size as usize > offset {
        Some(offset)
    } else {
        None
    }
}

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
    pub DeviceObjectExtension: *mut DEVOBJ_EXTENSION,
    pub Reserved: PVOID,
}

/// `DEVOBJ_EXTENSION.Type` (`IO_TYPE_DEVICE_OBJECT_EXTENSION`).
pub const IO_TYPE_DEVICE_OBJECT_EXTENSION: i16 = 0x0D;

/// `DEVOBJ_EXTENSION.ExtensionFlags`: what is pending for the device.
/// The names are those of the WDK's debugger extensions; the values are
/// the ones the pinned kernel tests.
pub const DOE_UNLOAD_PENDING: u32 = 0x01;
pub const DOE_DELETE_PENDING: u32 = 0x02;
pub const DOE_REMOVE_PENDING: u32 = 0x04;
pub const DOE_REMOVE_PROCESSED: u32 = 0x08;
pub const DOE_START_PENDING: u32 = 0x10;

/// `DEVOBJ_EXTENSION.StartIoFlags`, as the pinned kernel uses them: a
/// call of `IoStartNextPacket` that found another at work left word
/// that the next request is to be started, and that the driver's
/// requests are cancellable; the driver chose deferred start, and
/// requests that are not cancellable once started
/// (`IoSetStartIoAttributes`).
pub const DOE_SIO_NO_KEY: u32 = 0x20;
pub const DOE_SIO_CANCELABLE: u32 = 0x80;
pub const DOE_SIO_DEFERRED: u32 = 0x100;
pub const DOE_SIO_NO_CANCEL: u32 = 0x200;

/// What `DEVICE_OBJECT.DeviceObjectExtension` points to: the I/O
/// manager's own record of a device, which the WDK declares only the
/// head of. Microsoft's drivers read it in line (the device node, the
/// device attached to), so it is laid out as the pinned kernel's.
#[repr(C)]
pub struct DEVOBJ_EXTENSION {
    pub Type: i16,
    pub Size: u16,
    pub DeviceObject: *mut DEVICE_OBJECT,
    pub PowerFlags: u32,
    pub Dope: PVOID,
    pub ExtensionFlags: u32,
    pub DeviceNode: PVOID,
    /// The device this one is attached to, the next lower of its stack.
    pub AttachedTo: *mut DEVICE_OBJECT,
    pub StartIoCount: i32,
    pub StartIoKey: i32,
    pub StartIoFlags: u32,
    pub Vpb: PVOID,
    pub DependencyNode: PVOID,
    pub InterruptContext: PVOID,
    pub InterruptCount: i32,
    pub VerifierContext: PVOID,
}

/// `FILE_OBJECT.Flags`
pub const FO_SYNCHRONOUS_IO: u32 = 0x0000_0002;
/// The last handle has been closed and the cleanup request completed.
pub const FO_CLEANUP_COMPLETE: u32 = 0x0000_4000;
/// A handle has been made for the file object.
pub const FO_HANDLE_CREATED: u32 = 0x0004_0000;

/// Create options (`NtCreateFile`'s `CreateOptions`): requests on the
/// file are synchronous, alertable or not.
pub const FILE_SYNCHRONOUS_IO_ALERT: u32 = 0x0000_0010;
pub const FILE_SYNCHRONOUS_IO_NONALERT: u32 = 0x0000_0020;
pub const FILE_NON_DIRECTORY_FILE: u32 = 0x0000_0040;
/// Create disposition: open what exists, fail otherwise.
pub const FILE_OPEN: u32 = 1;
/// What a create reports in `IoStatus.Information`: the file existed
/// and was opened.
pub const FILE_OPENED: usize = 1;

/// What the generic rights mean for a file
/// ([`IoGetFileObjectGenericMapping`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-iogetfileobjectgenericmapping)):
/// `FILE_GENERIC_READ`, `FILE_GENERIC_WRITE`, `FILE_GENERIC_EXECUTE`,
/// `FILE_ALL_ACCESS`.
pub const FILE_GENERIC_MAPPING: crate::ob::GENERIC_MAPPING = crate::ob::GENERIC_MAPPING {
    GenericRead: 0x0012_0089,
    GenericWrite: 0x0012_0116,
    GenericExecute: 0x0012_00A0,
    GenericAll: 0x001F_01FF,
};

/// [`IO_SECURITY_CONTEXT`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/ns-wdm-_io_security_context):
/// what `Parameters.Create.SecurityContext` points to.
#[repr(C)]
pub struct IO_SECURITY_CONTEXT {
    pub SecurityQos: PVOID,
    pub AccessState: *mut crate::se::ACCESS_STATE,
    /// The access asked for, generic rights mapped to the file rights.
    pub DesiredAccess: u32,
    pub FullCreateOptions: u32,
}

/// [`NAMED_PIPE_CREATE_PARAMETERS`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/ns-wdm-_named_pipe_create_parameters):
/// what `Parameters.CreatePipe.Parameters` points to.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct NAMED_PIPE_CREATE_PARAMETERS {
    pub NamedPipeType: u32,
    pub ReadMode: u32,
    pub CompletionMode: u32,
    pub MaximumInstances: u32,
    pub InboundQuota: u32,
    pub OutboundQuota: u32,
    pub DefaultTimeout: i64,
    pub TimeoutSpecified: u8,
}

/// [`MAILSLOT_CREATE_PARAMETERS`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/ns-wdm-_mailslot_create_parameters):
/// what `Parameters.CreateMailslot.Parameters` points to.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct MAILSLOT_CREATE_PARAMETERS {
    pub MailslotQuota: u32,
    pub MaximumMessageSize: u32,
    pub ReadTimeout: i64,
    pub TimeoutSpecified: u8,
}

/// [`SECTION_OBJECT_POINTERS`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/ns-wdm-_section_object_pointers):
/// what a file system keeps per stream for the memory and cache
/// managers (`FILE_OBJECT.SectionObjectPointer` points at it). The
/// memory manager owns `DataSectionObject` and `ImageSectionObject`,
/// the cache manager `SharedCacheMap`; file systems compare them with
/// null.
#[repr(C)]
pub struct SECTION_OBJECT_POINTERS {
    pub DataSectionObject: PVOID,
    pub SharedCacheMap: PVOID,
    pub ImageSectionObject: PVOID,
}

const _: () = {
    use core::mem::{offset_of, size_of};
    assert!(size_of::<SECTION_OBJECT_POINTERS>() == 0x18);
    assert!(offset_of!(SECTION_OBJECT_POINTERS, SharedCacheMap) == 0x08);
    assert!(offset_of!(SECTION_OBJECT_POINTERS, ImageSectionObject) == 0x10);
    assert!(offset_of!(FILE_OBJECT, SectionObjectPointer) == 0x28);
};

/// [`SHARE_ACCESS`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-iocheckshareaccess):
/// a file system's counts of a file's opens, by what they asked for and
/// what they share.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct SHARE_ACCESS {
    pub OpenCount: u32,
    pub Readers: u32,
    pub Writers: u32,
    pub Deleters: u32,
    pub SharedRead: u32,
    pub SharedWrite: u32,
    pub SharedDelete: u32,
}

const _: () = {
    use core::mem::{offset_of, size_of};
    assert!(size_of::<SHARE_ACCESS>() == 0x1C);
    assert!(offset_of!(SHARE_ACCESS, SharedDelete) == 0x18);
};

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
pub const IRP_SYNCHRONOUS_API: u32 = 0x0000_0004;
pub const IRP_BUFFERED_IO: u32 = 0x0000_0010;
pub const IRP_DEALLOCATE_BUFFER: u32 = 0x0000_0020;
pub const IRP_INPUT_OPERATION: u32 = 0x0000_0040;
pub const IRP_CREATE_OPERATION: u32 = 0x0000_0080;
pub const IRP_CLOSE_OPERATION: u32 = 0x0000_0400;
pub const IRP_DEFER_IO_COMPLETION: u32 = 0x0000_0800;
/// The bit `IoGetRequestorProcess` of the pinned kernel tests first:
/// set, the first word of `Overlay` holds the process the request was
/// issued for (`IssuingProcess`), with flags in its low three bits. The
/// I/O manager sets it for a request a user-mode driver's host makes;
/// NK never does.
pub const IRP_ISSUING_PROCESS_IN_OVERLAY: u32 = 0x0000_2000;

/// The bits of `IRP.Flags` that carry the I/O priority hint of a
/// request the I/O manager builds for a driver, and what the pinned
/// kernel puts there for a thread of normal I/O priority
/// (`IoPriorityNormal`, 2, plus one). Every thread of NK's is one.
pub const IRP_PRIORITY_HINT_MASK: u32 = 0x000E_0000;
pub const IRP_PRIORITY_HINT_NORMAL: u32 = 0x0006_0000;

/// `IRP_NOCACHE`: the request goes past the cache, to the device.
pub const IRP_NOCACHE: u32 = 0x0000_0001;
/// `IRP_PAGING_IO`: the request is the memory manager's, for a page.
pub const IRP_PAGING_IO: u32 = 0x0000_0002;
/// `IRP_SYNCHRONOUS_PAGING_IO`: the memory manager waits for the paging
/// request on its own event; completion signals it and frees the IRP,
/// leaving the MDL and its pages to the memory manager.
pub const IRP_SYNCHRONOUS_PAGING_IO: u32 = 0x0000_0040;
/// `IRP.AllocationFlags`: a synchronous paging read into an MDL marked
/// `MDL_IO_PAGE_READ`, as `IoPageReadEx` of the pinned kernel marks it.
pub const IRP_ALLOCATION_PAGE_READ: u8 = 0x20;

/// `IO_PRIORITY_HINT`.
pub const IO_PRIORITY_VERY_LOW: u32 = 0;
pub const IO_PRIORITY_LOW: u32 = 1;
pub const IO_PRIORITY_NORMAL: u32 = 2;
/// `IO_PAGING_PRIORITY`.
pub const IO_PAGING_PRIORITY_INVALID: u32 = 0;
pub const IO_PAGING_PRIORITY_NORMAL: u32 = 1;
pub const IO_PAGING_PRIORITY_HIGH: u32 = 2;

/// [`IoGetIoPriorityHint`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-iogetiopriorityhint)
/// as the pinned kernel works it out of `IRP.Flags`: the hint is the
/// three bits of [`IRP_PRIORITY_HINT_MASK`], less one; a request with
/// none is of normal priority; and a hint below normal counts as
/// normal while the thread that made the request has its I/O priority
/// boosted (`thread_boosted`: there is a thread, and its
/// `IoBoostCount` is not zero).
pub const fn io_priority_hint(irp_flags: u32, thread_boosted: bool) -> u32 {
    let stored = (irp_flags & IRP_PRIORITY_HINT_MASK) >> 17;
    if stored == 0 {
        return IO_PRIORITY_NORMAL;
    }
    let hint = stored - 1;
    if hint < IO_PRIORITY_NORMAL && thread_boosted {
        return IO_PRIORITY_NORMAL;
    }
    hint
}

/// [`IoGetPagingIoPriority`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-iogetpagingiopriority)
/// as the pinned kernel works it out of `IRP.Flags`: invalid for a
/// request that is not paging I/O; else high for the stored hint 5,
/// and normal for every other, none included.
pub const fn paging_io_priority(irp_flags: u32) -> u32 {
    if irp_flags & IRP_PAGING_IO == 0 {
        return IO_PAGING_PRIORITY_INVALID;
    }
    if (irp_flags & IRP_PRIORITY_HINT_MASK) >> 17 == 5 {
        IO_PAGING_PRIORITY_HIGH
    } else {
        IO_PAGING_PRIORITY_NORMAL
    }
}

/// `IRP.AllocationFlags`: the IRP has an extension from the pool
/// (`IrpExtension` points to an [`IOP_IRP_EXTENSION`]), and: its
/// generic extension is kept in the `IrpExtension` field itself,
/// which is then no pointer.
pub const IRP_ALLOCATION_EXTENSION: u8 = 0x40;
pub const IRP_ALLOCATION_GENERIC_INLINE: u8 = 0x80;

/// `IOP_IRP_EXTENSION`: what `IRP.IrpExtension` points to. Private to
/// Windows; its layout is the pinned kernel's.
#[repr(C)]
pub struct IOP_IRP_EXTENSION {
    /// Bit 0: the block is from the pool.
    pub ExtensionFlags: u16,
    /// One bit for each kind of extension the block holds
    /// (`IRP_EXTENSION_*`).
    pub TypesAllocated: u16,
    pub GenericExtension: [u8; 4],
    pub VerifierContext: PVOID,
    pub DiskIoAttributionHandle: PVOID,
    pub ActivityId: crate::etw::GUID,
    /// A union: a timestamp, a zeroing offset, a file system's tracked
    /// offset (a pointer and an offset), or an adapter's crypto
    /// parameters.
    pub Parameters: [u64; 2],
    pub DriverFlags: u64,
}

/// The kinds of IRP extension, as bits of `TypesAllocated` are
/// numbered.
pub const IRP_EXTENSION_ACTIVITY_ID: u32 = 0;
pub const IRP_EXTENSION_GENERIC: u32 = 2;
pub const IRP_EXTENSION_FS_ZEROING_OFFSET: u32 = 4;
pub const IRP_EXTENSION_FS_TRACK_OFFSET: u32 = 5;
pub const IRP_EXTENSION_DISK_IO_ATTRIBUTION: u32 = 6;
pub const IRP_EXTENSION_ADAPTER_CRYPTO: u32 = 7;
pub const IRP_EXTENSION_DRIVER_FLAGS: u32 = 8;
/// The most bytes a generic extension holds
/// (`IoSizeofGenericIrpExtension`).
pub const IRP_GENERIC_EXTENSION_SIZE: usize = 4;

/// `IoPropagateIrpExtension`'s flags: which kinds to copy.
pub const IRP_PROPAGATE_GENERIC: u32 = 0x1;
pub const IRP_PROPAGATE_ACTIVITY_ID: u32 = 0x2;
pub const IRP_PROPAGATE_FS_TRACK_OFFSET: u32 = 0x4;
pub const IRP_PROPAGATE_DISK_IO_ATTRIBUTION: u32 = 0x8;
pub const IRP_PROPAGATE_ADAPTER_CRYPTO: u32 = 0x10;
pub const IRP_PROPAGATE_DRIVER_FLAGS: u32 = 0x20;

const _: () = {
    use core::mem::{offset_of, size_of};
    assert!(size_of::<IOP_IRP_EXTENSION>() == 0x40);
    assert!(offset_of!(IOP_IRP_EXTENSION, TypesAllocated) == 2);
    assert!(offset_of!(IOP_IRP_EXTENSION, GenericExtension) == 4);
    assert!(offset_of!(IOP_IRP_EXTENSION, DiskIoAttributionHandle) == 0x10);
    assert!(offset_of!(IOP_IRP_EXTENSION, ActivityId) == 0x18);
    assert!(offset_of!(IOP_IRP_EXTENSION, Parameters) == 0x28);
    assert!(offset_of!(IOP_IRP_EXTENSION, DriverFlags) == 0x38);
    assert!(offset_of!(IRP, AllocationFlags) == 0x47);
    assert!(offset_of!(IRP, IrpExtension) == 0xC8);
};

/// Whether `IoBuildSynchronousFsdRequest` of the pinned kernel builds a
/// request of this major function with no buffer and no transfer
/// parameters: a flush, a shutdown, a power or a Plug and Play request.
/// Every other major function gets the buffer the caller named, passed
/// the way the device asks for, and the length and offset of a read.
pub const fn fsd_request_has_no_buffer(major: u32) -> bool {
    major == IRP_MJ_FLUSH_BUFFERS as u32
        || major == IRP_MJ_SHUTDOWN as u32
        || major == IRP_MJ_POWER as u32
        || major == IRP_MJ_PNP as u32
}

/// What
/// [`IoSetMasterIrpStatus`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntddk/nf-ntddk-iosetmasterirpstatus)
/// makes of a master request's status `current` when a part of it
/// completes with `status`: the status to store, or `None` to leave the
/// master's. As the pinned kernel decides it: "verify required" always
/// wins and is never replaced; "read from the other copy" is replaced
/// by anything and replaces nothing; otherwise the more severe of the
/// two (the top two bits) wins, and the first of equals stays.
pub const fn master_irp_status(current: NTSTATUS, status: NTSTATUS) -> Option<NTSTATUS> {
    use crate::status::{STATUS_FT_READ_FROM_COPY, STATUS_VERIFY_REQUIRED};
    if status == STATUS_VERIFY_REQUIRED {
        return Some(status);
    }
    if current == STATUS_VERIFY_REQUIRED {
        return None;
    }
    if current == STATUS_FT_READ_FROM_COPY {
        return Some(status);
    }
    if status == STATUS_FT_READ_FROM_COPY {
        return None;
    }
    if status as u32 >> 30 > current as u32 >> 30 {
        Some(status)
    } else {
        None
    }
}

/// `IRP.ApcEnvironment`: the thread was in its own process when the
/// request was made (`OriginalApcEnvironment`).
pub const ORIGINAL_APC_ENVIRONMENT: i8 = 0;
/// `IRP.ApcEnvironment`: the thread was attached to another process
/// (`AttachedApcEnvironment`).
pub const ATTACHED_APC_ENVIRONMENT: i8 = 1;

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
    /// `Overlay`: APC routine and context, or an allocation size. The
    /// first word is `IssuingProcess` instead in a request marked
    /// [`IRP_ISSUING_PROCESS_IN_OVERLAY`].
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

/// Where in an IRP its device queue entry is
/// (`Tail.Overlay.DeviceQueueEntry`): it overlays the driver context.
pub const IRP_DEVICE_QUEUE_ENTRY: usize = core::mem::offset_of!(IRP, DriverContext);

/// `IO_STACK_LOCATION.Flags` of a create request: the opener's access
/// is to be checked though the request is kernel mode's, and the name
/// is to be compared case-sensitively.
pub const SL_FORCE_ACCESS_CHECK: u8 = 0x01;
pub const SL_CASE_SENSITIVE: u8 = 0x80;
/// `IO_STACK_LOCATION.Flags` of a device or file-system control request:
/// whether the handle was granted read or write access (`wdm.h`).
pub const SL_READ_ACCESS_GRANTED: u8 = 0x01;
pub const SL_WRITE_ACCESS_GRANTED: u8 = 0x04;
/// `IO_STACK_LOCATION.Control`
pub const SL_PENDING_RETURNED: u8 = 0x01;
pub const SL_INVOKE_ON_CANCEL: u8 = 0x20;
pub const SL_INVOKE_ON_SUCCESS: u8 = 0x40;
pub const SL_INVOKE_ON_ERROR: u8 = 0x80;

/// [`KEYBOARD_INPUT_DATA`](https://learn.microsoft.com/en-us/windows/win32/api/ntddkbd/ns-ntddkbd-keyboard_input_data)
/// (`ntddkbd.h`): one keyboard scan-code event returned by `kbdclass.sys`.
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct KEYBOARD_INPUT_DATA {
    pub UnitId: u16,
    pub MakeCode: u16,
    pub Flags: u16,
    pub Reserved: u16,
    pub ExtraInformation: u32,
}

const _: () = {
    assert!(core::mem::size_of::<KEYBOARD_INPUT_DATA>() == 12);
    assert!(core::mem::offset_of!(KEYBOARD_INPUT_DATA, UnitId) == 0);
    assert!(core::mem::offset_of!(KEYBOARD_INPUT_DATA, MakeCode) == 2);
    assert!(core::mem::offset_of!(KEYBOARD_INPUT_DATA, Flags) == 4);
    assert!(core::mem::offset_of!(KEYBOARD_INPUT_DATA, Reserved) == 6);
    assert!(core::mem::offset_of!(KEYBOARD_INPUT_DATA, ExtraInformation) == 8);
};

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

/// `Parameters.Create.Options`: the create disposition in the high
/// eight bits, the create options in the low twenty-four.
pub const fn create_options(disposition: u32, options: u32) -> u32 {
    disposition << 24 | options & 0x00FF_FFFF
}

/// `Parameters.Create`: SecurityContext, Options, FileAttributes and
/// ShareAccess (16 bits each, sharing a slot), EaLength.
pub const fn create_parameters(
    security_context: u64,
    options: u32,
    file_attributes: u16,
    share_access: u16,
    ea_length: u32,
) -> [u64; 4] {
    [
        security_context,
        options as u64,
        file_attributes as u64 | (share_access as u64) << 16,
        ea_length as u64,
    ]
}

/// `Parameters.CreatePipe` and `Parameters.CreateMailslot`, which are
/// laid out alike: as `Parameters.Create`, with a reserved word where
/// the file attributes are and, where the EA length is, a pointer to
/// the `NAMED_PIPE_CREATE_PARAMETERS` or `MAILSLOT_CREATE_PARAMETERS`.
pub const fn create_pipe_parameters(
    security_context: u64,
    options: u32,
    share_access: u16,
    parameters: u64,
) -> [u64; 4] {
    [
        security_context,
        options as u64,
        (share_access as u64) << 16,
        parameters,
    ]
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

/// File access rights a request needs of the handle it is made through.
pub const FILE_READ_DATA: u32 = 0x1;
pub const FILE_WRITE_DATA: u32 = 0x2;
/// For a named pipe the same bit is `FILE_CREATE_PIPE_INSTANCE`.
pub const FILE_APPEND_DATA: u32 = 0x4;
/// `FILE_OBJECT.Flags`: the file is a named pipe (its file system sets
/// it).
pub const FO_NAMED_PIPE: u32 = 0x0000_0080;

/// The access a control code says its requestor's handle must have:
/// bits 14 and 15 of the code, `FILE_READ_ACCESS` and
/// `FILE_WRITE_ACCESS`, which are `FILE_READ_DATA` and
/// `FILE_WRITE_DATA`. `FILE_ANY_ACCESS` is none.
pub const fn ctl_access(code: u32) -> u32 {
    (code >> 14) & 3
}

/// Whether user mode may write through a handle granted `granted` to a
/// file object with `file_flags`: the handle may write data, or append
/// it, as `NtWriteFile` asks. A named pipe has no appending: the bit
/// means something else there.
pub const fn may_write(granted: u32, file_flags: u32) -> bool {
    let append = if file_flags & FO_NAMED_PIPE == 0 {
        FILE_APPEND_DATA
    } else {
        0
    };
    granted & (FILE_WRITE_DATA | append) != 0
}

/// `LOCK_OPERATION`: what the caller of `MmProbeAndLockPages` means to
/// do with the pages.
pub const IO_READ_ACCESS: u32 = 0;
pub const IO_WRITE_ACCESS: u32 = 1;
pub const IO_MODIFY_ACCESS: u32 = 2;

/// `MDL.MdlFlags`
pub const MDL_MAPPED_TO_SYSTEM_VA: i16 = 0x0001;
pub const MDL_PAGES_LOCKED: i16 = 0x0002;
pub const MDL_SOURCE_IS_NONPAGED_POOL: i16 = 0x0004;
pub const MDL_ALLOCATED_FIXED_SIZE: i16 = 0x0008;
/// The MDL describes part of another's buffer (`IoBuildPartialMdl`).
pub const MDL_PARTIAL: i16 = 0x0010;
/// A partial MDL that has a system mapping of its own, to be taken
/// down when the MDL is freed or reused.
pub const MDL_PARTIAL_HAS_BEEN_MAPPED: i16 = 0x0020;
pub const MDL_IO_PAGE_READ: i16 = 0x0040;
pub const MDL_ALLOCATED_MUST_SUCCEED: i16 = 0x4000;

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

/// What a partial MDL describes
/// ([`IoBuildPartialMdl`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-iobuildpartialmdl)).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PartialMdl {
    /// The first page of the source MDL's page array that the part
    /// uses, and how many it uses.
    pub first_page: usize,
    pub pages: usize,
    /// The part's `ByteOffset` and `ByteCount`.
    pub byte_offset: u32,
    pub byte_count: u32,
    /// How far into the source's buffer the part starts.
    pub skipped: usize,
}

/// The part of a source MDL's buffer that starts at `va` and is
/// `length` bytes long, or reaches the end of the source's buffer if
/// `length` is zero. The source's buffer starts at `source_va`
/// (`StartVa` plus `ByteOffset`) and is `source_count` bytes long.
/// `None` if the part does not lie within the source's buffer.
pub const fn partial_mdl(
    source_va: usize,
    source_count: u32,
    va: usize,
    length: u32,
) -> Option<PartialMdl> {
    if va < source_va {
        return None;
    }
    let skipped = va - source_va;
    if skipped > source_count as usize {
        return None;
    }
    let left = source_count as usize - skipped;
    let byte_count = if length == 0 { left } else { length as usize };
    if byte_count > left {
        return None;
    }
    Some(PartialMdl {
        first_page: (va >> 12) - (source_va >> 12),
        pages: span_pages(va, byte_count),
        byte_offset: (va & 0xFFF) as u32,
        byte_count: byte_count as u32,
        skipped,
    })
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
    assert!(offset_of!(KDEVICE_QUEUE, DeviceListHead) == 0x08);
    assert!(offset_of!(KDEVICE_QUEUE, Lock) == 0x18);
    assert!(offset_of!(KDEVICE_QUEUE, Busy) == 0x20);
    assert!(size_of::<KDEVICE_QUEUE_ENTRY>() == 0x18);
    assert!(offset_of!(KDEVICE_QUEUE_ENTRY, SortKey) == 0x10);
    assert!(offset_of!(KDEVICE_QUEUE_ENTRY, Inserted) == 0x14);
    assert!(IRP_DEVICE_QUEUE_ENTRY == 0x78);
    assert!(size_of::<KDEVICE_QUEUE_ENTRY>() <= 4 * size_of::<PVOID>());
    assert!(offset_of!(DRIVER_OBJECT, DriverStartIo) == 0x60);
    assert!(offset_of!(DEVICE_OBJECT, CurrentIrp) == 0x20);
    assert!(size_of::<KDPC>() == 0x40);
    assert!(size_of::<WAIT_CONTEXT_BLOCK>() == 0x48);
    assert!(size_of::<DRIVER_EXTENSION>() == 0x50);
    assert!(offset_of!(DRIVER_EXTENSION, ServiceKeyName) == 0x18);
    assert!(offset_of!(DRIVER_EXTENSION, ClientDriverExtension) == 0x28);
    assert!(offset_of!(DRIVER_EXTENSION, VerifierContext) == 0x48);
    assert!(size_of::<IO_CLIENT_EXTENSION>() == 0x10);
    assert!(size_of::<IO_ERROR_LOG_PACKET>() == 0x30);
    assert!(offset_of!(IO_ERROR_LOG_PACKET, DumpDataSize) == 0x02);
    assert!(offset_of!(IO_ERROR_LOG_PACKET, StringOffset) == 0x06);
    assert!(offset_of!(IO_ERROR_LOG_PACKET, EventCategory) == 0x08);
    assert!(offset_of!(IO_ERROR_LOG_PACKET, ErrorCode) == 0x0C);
    assert!(offset_of!(IO_ERROR_LOG_PACKET, UniqueErrorValue) == 0x10);
    assert!(offset_of!(IO_ERROR_LOG_PACKET, FinalStatus) == 0x14);
    assert!(offset_of!(IO_ERROR_LOG_PACKET, SequenceNumber) == 0x18);
    assert!(offset_of!(IO_ERROR_LOG_PACKET, IoControlCode) == 0x1C);
    assert!(offset_of!(IO_ERROR_LOG_PACKET, DeviceOffset) == 0x20);
    assert!(offset_of!(IO_ERROR_LOG_PACKET, DumpData) == 0x28);
    assert!(size_of::<ERROR_LOG_ENTRY>() == 0x30);
    assert!(offset_of!(ERROR_LOG_ENTRY, ListEntry) == 0x08);
    assert!(offset_of!(ERROR_LOG_ENTRY, DeviceObject) == 0x18);
    assert!(offset_of!(ERROR_LOG_ENTRY, DriverObject) == 0x20);
    assert!(offset_of!(ERROR_LOG_ENTRY, TimeStamp) == 0x28);
    assert!(offset_of!(IO_CLIENT_EXTENSION, ClientIdentificationAddress) == 0x08);
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
    assert!(size_of::<FAST_IO_DISPATCH>() == 0xE0);
    assert!(offset_of!(FAST_IO_DISPATCH, Routines) == 0x08);
    assert!(offset_of!(DEVICE_OBJECT, Spare1) == 0x132);
    assert!(size_of::<DEVOBJ_EXTENSION>() == 0x70);
    assert!(offset_of!(DEVOBJ_EXTENSION, Size) == 0x02);
    assert!(offset_of!(DEVOBJ_EXTENSION, DeviceObject) == 0x08);
    assert!(offset_of!(DEVOBJ_EXTENSION, PowerFlags) == 0x10);
    assert!(offset_of!(DEVOBJ_EXTENSION, Dope) == 0x18);
    assert!(offset_of!(DEVOBJ_EXTENSION, ExtensionFlags) == 0x20);
    assert!(offset_of!(DEVOBJ_EXTENSION, DeviceNode) == 0x28);
    assert!(offset_of!(DEVOBJ_EXTENSION, AttachedTo) == 0x30);
    assert!(offset_of!(DEVOBJ_EXTENSION, StartIoCount) == 0x38);
    assert!(offset_of!(DEVOBJ_EXTENSION, StartIoKey) == 0x3C);
    assert!(offset_of!(DEVOBJ_EXTENSION, StartIoFlags) == 0x40);
    assert!(offset_of!(DEVOBJ_EXTENSION, Vpb) == 0x48);
    assert!(offset_of!(DEVOBJ_EXTENSION, DependencyNode) == 0x50);
    assert!(offset_of!(DEVOBJ_EXTENSION, InterruptContext) == 0x58);
    assert!(offset_of!(DEVOBJ_EXTENSION, InterruptCount) == 0x60);
    assert!(offset_of!(DEVOBJ_EXTENSION, VerifierContext) == 0x68);
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
    assert!(offset_of!(IRP, ApcEnvironment) == 0x46);
    assert!(offset_of!(IRP, UserIosb) == 0x48);
    assert!(offset_of!(IRP, Overlay) == 0x58);
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
    assert!(size_of::<IO_SECURITY_CONTEXT>() == 0x18);
    assert!(offset_of!(IO_SECURITY_CONTEXT, AccessState) == 0x08);
    assert!(offset_of!(IO_SECURITY_CONTEXT, DesiredAccess) == 0x10);
    assert!(offset_of!(IO_SECURITY_CONTEXT, FullCreateOptions) == 0x14);
    assert!(size_of::<NAMED_PIPE_CREATE_PARAMETERS>() == 0x28);
    assert!(offset_of!(NAMED_PIPE_CREATE_PARAMETERS, MaximumInstances) == 0x0C);
    assert!(offset_of!(NAMED_PIPE_CREATE_PARAMETERS, OutboundQuota) == 0x14);
    assert!(offset_of!(NAMED_PIPE_CREATE_PARAMETERS, DefaultTimeout) == 0x18);
    assert!(offset_of!(NAMED_PIPE_CREATE_PARAMETERS, TimeoutSpecified) == 0x20);
    assert!(size_of::<MAILSLOT_CREATE_PARAMETERS>() == 0x18);
    assert!(offset_of!(MAILSLOT_CREATE_PARAMETERS, MaximumMessageSize) == 0x04);
    assert!(offset_of!(MAILSLOT_CREATE_PARAMETERS, ReadTimeout) == 0x08);
    assert!(offset_of!(MAILSLOT_CREATE_PARAMETERS, TimeoutSpecified) == 0x10);
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
        // `FILE_OPEN_IF` with two options; an option bit above the low
        // twenty-four does not reach the disposition.
        assert_eq!(create_options(3, 0x60), 0x0300_0060);
        assert_eq!(create_options(1, 0xFF00_0021), 0x0100_0021);
        // `FileAttributes` at +0x10 of the parameters and `ShareAccess`
        // at +0x12, as `wdm.h` lays the structure out.
        assert_eq!(
            create_parameters(0x1000, 0x0100_0060, 0x80, 3, 0x20),
            [0x1000, 0x0100_0060, 0x0003_0080, 0x20]
        );
        assert_eq!(
            create_pipe_parameters(0x1000, 0x0300_0020, 3, 0x2000),
            [0x1000, 0x0300_0020, 0x0003_0000, 0x2000]
        );
        // The four codes of Microsoft's SIOCTL sample (device type 40000).
        assert_eq!(ctl_code(40000, 0x900, METHOD_IN_DIRECT, 0), 0x9C40_2401);
        assert_eq!(ctl_code(40000, 0x901, METHOD_OUT_DIRECT, 0), 0x9C40_2406);
        assert_eq!(ctl_code(40000, 0x902, METHOD_BUFFERED, 0), 0x9C40_2408);
        assert_eq!(ctl_code(40000, 0x903, METHOD_NEITHER, 0), 0x9C40_240F);
    }

    #[test]
    fn a_control_code_names_the_access_its_handle_needs() {
        assert_eq!(ctl_access(ctl_code(40000, 0x900, METHOD_BUFFERED, 0)), 0);
        assert_eq!(
            ctl_access(ctl_code(0xFFFF, 0xFFF, METHOD_NEITHER, 1)),
            FILE_READ_DATA
        );
        assert_eq!(
            ctl_access(ctl_code(0x22, 0, METHOD_BUFFERED, 2)),
            FILE_WRITE_DATA
        );
        assert_eq!(ctl_access(ctl_code(0x22, 0x801, METHOD_IN_DIRECT, 3)), 3);
        // FSCTL_PIPE_PEEK and FSCTL_PIPE_TRANSCEIVE, from the SDK.
        assert_eq!(ctl_access(0x0011_400C), FILE_READ_DATA);
        assert_eq!(ctl_access(0x0011_C017), 3);
    }

    #[test]
    fn writing_needs_write_or_append_and_a_pipe_has_no_append() {
        assert!(may_write(FILE_WRITE_DATA, 0));
        assert!(may_write(FILE_APPEND_DATA, 0));
        assert!(may_write(FILE_WRITE_DATA | FILE_READ_DATA, FO_NAMED_PIPE));
        assert!(!may_write(FILE_APPEND_DATA, FO_NAMED_PIPE));
        assert!(!may_write(FILE_READ_DATA | 0x0010_0000, 0));
        assert!(!may_write(0, FO_SYNCHRONOUS_IO));
    }

    #[test]
    fn a_fast_io_routine_is_there_only_in_a_table_that_reaches_it() {
        // `FastIoDetachDevice` is at 0x68, and the kernel asks for a
        // table larger than that.
        assert_eq!(
            fast_io_routine_offset(0xE0, FAST_IO_DETACH_DEVICE),
            Some(0x68)
        );
        assert_eq!(
            fast_io_routine_offset(0x69, FAST_IO_DETACH_DEVICE),
            Some(0x68)
        );
        assert_eq!(fast_io_routine_offset(0x68, FAST_IO_DETACH_DEVICE), None);
        assert_eq!(fast_io_routine_offset(0, FAST_IO_DETACH_DEVICE), None);
        assert_eq!(fast_io_routine_offset(0xE0, 0), Some(0x08));
        assert_eq!(
            fast_io_routine_offset(0xE0, FAST_IO_ROUTINES - 1),
            Some(0xD8)
        );
        assert_eq!(fast_io_routine_offset(u32::MAX, FAST_IO_ROUTINES), None);
    }

    #[test]
    fn an_error_log_packet_is_held_to_windows_sizes() {
        // The fixed part alone, and nothing smaller.
        assert_eq!(error_log_allocation(0x30), Some(0x60));
        assert_eq!(error_log_allocation(0x2F), None);
        assert_eq!(error_log_allocation(0), None);
        // Rounded up to eight bytes behind the header.
        assert_eq!(error_log_allocation(0x31), Some(0x30 + 0x38));
        assert_eq!(error_log_allocation(0x38), Some(0x30 + 0x38));
        // The largest, and nothing larger.
        assert_eq!(
            error_log_allocation(ERROR_LOG_MAXIMUM_SIZE),
            Some(0x30 + 0xF0)
        );
        assert_eq!(error_log_allocation(ERROR_LOG_MAXIMUM_SIZE + 1), None);
        assert_eq!(error_log_allocation(u8::MAX), None);
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
    fn a_master_request_keeps_its_most_telling_status() {
        use crate::status::*;
        let set = master_irp_status;
        // The more severe status wins; the first of equals stays.
        assert_eq!(
            set(STATUS_SUCCESS, STATUS_END_OF_FILE),
            Some(STATUS_END_OF_FILE)
        );
        assert_eq!(set(STATUS_END_OF_FILE, STATUS_SUCCESS), None);
        assert_eq!(set(STATUS_END_OF_FILE, STATUS_ACCESS_DENIED), None);
        assert_eq!(set(STATUS_SUCCESS, STATUS_SUCCESS), None);
        assert_eq!(
            set(STATUS_SUCCESS, STATUS_BUFFER_OVERFLOW),
            Some(STATUS_BUFFER_OVERFLOW)
        );
        assert_eq!(
            set(STATUS_BUFFER_OVERFLOW, STATUS_END_OF_FILE),
            Some(STATUS_END_OF_FILE)
        );
        assert_eq!(set(STATUS_END_OF_FILE, STATUS_BUFFER_OVERFLOW), None);
        // An informational status outranks a plain success.
        assert_eq!(
            set(STATUS_SUCCESS, STATUS_OBJECT_NAME_EXISTS),
            Some(STATUS_OBJECT_NAME_EXISTS)
        );
        // "Verify required" always wins, over an error too, and stays.
        assert_eq!(
            set(STATUS_END_OF_FILE, STATUS_VERIFY_REQUIRED),
            Some(STATUS_VERIFY_REQUIRED)
        );
        assert_eq!(
            set(STATUS_VERIFY_REQUIRED, STATUS_VERIFY_REQUIRED),
            Some(STATUS_VERIFY_REQUIRED)
        );
        assert_eq!(set(STATUS_VERIFY_REQUIRED, STATUS_END_OF_FILE), None);
        assert_eq!(set(STATUS_VERIFY_REQUIRED, STATUS_FT_READ_FROM_COPY), None);
        // "Read from the other copy" gives way to anything, a success
        // included, and replaces nothing.
        assert_eq!(
            set(STATUS_FT_READ_FROM_COPY, STATUS_SUCCESS),
            Some(STATUS_SUCCESS)
        );
        assert_eq!(
            set(STATUS_FT_READ_FROM_COPY, STATUS_FT_READ_FROM_COPY),
            Some(STATUS_FT_READ_FROM_COPY)
        );
        assert_eq!(set(STATUS_SUCCESS, STATUS_FT_READ_FROM_COPY), None);
        assert_eq!(set(STATUS_END_OF_FILE, STATUS_FT_READ_FROM_COPY), None);
    }

    #[test]
    fn requests_without_a_transfer_get_no_buffer() {
        for major in [
            IRP_MJ_FLUSH_BUFFERS,
            IRP_MJ_SHUTDOWN,
            IRP_MJ_POWER,
            IRP_MJ_PNP,
        ] {
            assert!(fsd_request_has_no_buffer(u32::from(major)));
        }
        for major in [
            IRP_MJ_READ,
            IRP_MJ_WRITE,
            IRP_MJ_CREATE,
            IRP_MJ_DEVICE_CONTROL,
            IRP_MJ_INTERNAL_DEVICE_CONTROL,
            IRP_MJ_SYSTEM_CONTROL,
        ] {
            assert!(!fsd_request_has_no_buffer(u32::from(major)));
        }
        assert!(!fsd_request_has_no_buffer(0x109));
        assert_eq!(IRP_PRIORITY_HINT_NORMAL & !IRP_PRIORITY_HINT_MASK, 0);
        assert_eq!(IRP_PRIORITY_HINT_NORMAL >> 17, 3);
    }

    #[test]
    fn the_priority_hint_is_read_out_of_the_flags() {
        let stored = |hint: u32| hint << 17;
        // No hint, and the hint NK's built requests carry: normal.
        assert_eq!(io_priority_hint(0, false), IO_PRIORITY_NORMAL);
        assert_eq!(io_priority_hint(0, true), IO_PRIORITY_NORMAL);
        assert_eq!(
            io_priority_hint(IRP_PRIORITY_HINT_NORMAL, false),
            IO_PRIORITY_NORMAL
        );
        // Stored one more than it is.
        assert_eq!(io_priority_hint(stored(1), false), IO_PRIORITY_VERY_LOW);
        assert_eq!(io_priority_hint(stored(2), false), IO_PRIORITY_LOW);
        assert_eq!(io_priority_hint(stored(4), false), 3);
        assert_eq!(io_priority_hint(stored(5), false), 4);
        assert_eq!(io_priority_hint(stored(7), false), 6);
        // A boosted thread's low requests count as normal; others stay.
        assert_eq!(io_priority_hint(stored(1), true), IO_PRIORITY_NORMAL);
        assert_eq!(io_priority_hint(stored(2), true), IO_PRIORITY_NORMAL);
        assert_eq!(io_priority_hint(stored(5), true), 4);
        // Other flags are not the hint.
        assert_eq!(
            io_priority_hint(stored(2) | 0xFFF1_FFFF, false),
            IO_PRIORITY_LOW
        );
    }

    #[test]
    fn the_paging_priority_is_of_paging_requests_only() {
        let stored = |hint: u32| hint << 17;
        assert_eq!(paging_io_priority(0), IO_PAGING_PRIORITY_INVALID);
        assert_eq!(paging_io_priority(stored(5)), IO_PAGING_PRIORITY_INVALID);
        assert_eq!(paging_io_priority(IRP_PAGING_IO), IO_PAGING_PRIORITY_NORMAL);
        assert_eq!(
            paging_io_priority(IRP_PAGING_IO | stored(5)),
            IO_PAGING_PRIORITY_HIGH
        );
        for hint in [1, 2, 3, 4, 6, 7] {
            assert_eq!(
                paging_io_priority(IRP_PAGING_IO | stored(hint)),
                IO_PAGING_PRIORITY_NORMAL
            );
        }
    }

    #[test]
    fn a_partial_mdl_describes_part_of_the_source_buffer() {
        // The source: three pages' worth starting 0x800 into a page.
        let (source, count) = (0x10_0800, 0x3000);
        // The whole of it.
        assert_eq!(
            partial_mdl(source, count, source, 0),
            Some(PartialMdl {
                first_page: 0,
                pages: 4,
                byte_offset: 0x800,
                byte_count: 0x3000,
                skipped: 0,
            })
        );
        // A part inside the second page.
        assert_eq!(
            partial_mdl(source, count, 0x10_1010, 0x20),
            Some(PartialMdl {
                first_page: 1,
                pages: 1,
                byte_offset: 0x10,
                byte_count: 0x20,
                skipped: 0x810,
            })
        );
        // From the middle to the end: a length of zero.
        assert_eq!(
            partial_mdl(source, count, 0x10_2FFF, 0),
            Some(PartialMdl {
                first_page: 2,
                pages: 2,
                byte_offset: 0xFFF,
                byte_count: 0x801,
                skipped: 0x27FF,
            })
        );
        // Up to the last byte, and no further.
        assert!(partial_mdl(source, count, 0x10_3000, 0x800).is_some());
        assert_eq!(partial_mdl(source, count, 0x10_3000, 0x801), None);
        assert_eq!(partial_mdl(source, count, source, 0x3001), None);
        // Not before the buffer, nor past its end.
        assert_eq!(partial_mdl(source, count, 0x10_07FF, 1), None);
        assert_eq!(partial_mdl(source, count, 0x10_3801, 0), None);
        // At the very end, nothing is left to describe; the page the
        // end lies in is still spanned, as the WDK's macro spans it.
        assert_eq!(
            partial_mdl(source, count, 0x10_3800, 0),
            Some(PartialMdl {
                first_page: 3,
                pages: 1,
                byte_offset: 0x800,
                byte_count: 0,
                skipped: 0x3000,
            })
        );
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
