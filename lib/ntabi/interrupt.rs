//! Device interrupts as drivers see them: the interrupt object and what
//! is passed to connect and disconnect one.
//!
//! [`IoConnectInterruptEx`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-ioconnectinterruptex),
//! [`IO_CONNECT_INTERRUPT_PARAMETERS`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/ns-wdm-_io_connect_interrupt_parameters).
//! `KINTERRUPT` is private to the kernel, and its layout is the pinned
//! build's: Microsoft's own drivers read its lock and IRQL fields.

use crate::io::{DEVICE_OBJECT, PVOID};
use crate::ke::{KIRQL, KSPIN_LOCK, LIST_ENTRY};

/// `KSERVICE_ROUTINE`: an interrupt service routine. Returns nonzero
/// (a `BOOLEAN`) if the interrupt was its device's.
pub type KSERVICE_ROUTINE = unsafe extern "C" fn(*mut KINTERRUPT, PVOID) -> u8;
/// `KMESSAGE_SERVICE_ROUTINE`: the same for a message-signalled
/// interrupt; the third argument is the message's number.
pub type KMESSAGE_SERVICE_ROUTINE = unsafe extern "C" fn(*mut KINTERRUPT, PVOID, u32) -> u8;
/// `KSYNCHRONIZE_ROUTINE`: run by `KeSynchronizeExecution`.
pub type KSYNCHRONIZE_ROUTINE = unsafe extern "C" fn(PVOID) -> u8;

/// The `Type` of a `KINTERRUPT`: `InterruptObject`.
pub const INTERRUPT_OBJECT: i16 = 22;

/// `KINTERRUPT`: one connection of a service routine to an interrupt.
#[repr(C)]
pub struct KINTERRUPT {
    pub Type: i16,
    pub Size: i16,
    /// The interrupt objects connected to one vector.
    pub InterruptListEntry: LIST_ENTRY,
    pub ServiceRoutine: Option<KSERVICE_ROUTINE>,
    pub MessageServiceRoutine: Option<KMESSAGE_SERVICE_ROUTINE>,
    pub MessageIndex: u32,
    pub ServiceContext: PVOID,
    /// The lock the service routine runs under, unless the driver gave
    /// its own.
    pub SpinLock: KSPIN_LOCK,
    pub TickCount: u32,
    /// The lock in use: `SpinLock` above, or the driver's.
    pub ActualLock: *mut KSPIN_LOCK,
    pub DispatchAddress: PVOID,
    pub Vector: u32,
    pub Irql: KIRQL,
    pub SynchronizeIrql: KIRQL,
    pub FloatingSave: u8,
    pub Connected: u8,
    /// The processor the interrupt is sent to.
    pub Number: u32,
    pub ShareVector: u8,
    pub EmulateActiveBoth: u8,
    pub ActiveCount: u16,
    pub InternalState: i32,
    /// `KINTERRUPT_MODE`.
    pub Mode: u32,
    /// `KINTERRUPT_POLARITY`.
    pub Polarity: u32,
    pub ServiceCount: u32,
    pub DispatchCount: u32,
    pub PassiveEvent: PVOID,
    pub TrapFrame: PVOID,
    pub DisconnectData: PVOID,
    pub ServiceThread: PVOID,
    pub ConnectionData: PVOID,
    pub IntTrackEntry: PVOID,
    /// `ISRDPCSTATS`, which NK does not keep.
    pub IsrDpcStats: [u64; 12],
    pub RedirectObject: PVOID,
    pub PhysicalDeviceObject: *mut DEVICE_OBJECT,
}

/// `IO_CONNECT_INTERRUPT_PARAMETERS.Version` and
/// `IO_DISCONNECT_INTERRUPT_PARAMETERS.Version`.
pub const CONNECT_FULLY_SPECIFIED: u32 = 1;
pub const CONNECT_LINE_BASED: u32 = 2;
pub const CONNECT_MESSAGE_BASED: u32 = 3;
pub const CONNECT_FULLY_SPECIFIED_GROUP: u32 = 4;
pub const CONNECT_MESSAGE_BASED_PASSIVE: u32 = 5;

/// `IO_CONNECT_INTERRUPT_FULLY_SPECIFIED_PARAMETERS`.
#[repr(C)]
pub struct IO_CONNECT_INTERRUPT_FULLY_SPECIFIED_PARAMETERS {
    pub PhysicalDeviceObject: *mut DEVICE_OBJECT,
    pub InterruptObject: *mut *mut KINTERRUPT,
    pub ServiceRoutine: Option<KSERVICE_ROUTINE>,
    pub ServiceContext: PVOID,
    pub SpinLock: *mut KSPIN_LOCK,
    pub SynchronizeIrql: KIRQL,
    pub FloatingSave: u8,
    pub ShareVector: u8,
    pub Vector: u32,
    pub Irql: KIRQL,
    /// `KINTERRUPT_MODE`.
    pub InterruptMode: u32,
    pub ProcessorEnableMask: usize,
    /// Read only for `CONNECT_FULLY_SPECIFIED_GROUP`.
    pub Group: u16,
}

/// `IO_CONNECT_INTERRUPT_LINE_BASED_PARAMETERS`.
#[repr(C)]
pub struct IO_CONNECT_INTERRUPT_LINE_BASED_PARAMETERS {
    pub PhysicalDeviceObject: *mut DEVICE_OBJECT,
    pub InterruptObject: *mut *mut KINTERRUPT,
    pub ServiceRoutine: Option<KSERVICE_ROUTINE>,
    pub ServiceContext: PVOID,
    pub SpinLock: *mut KSPIN_LOCK,
    pub SynchronizeIrql: KIRQL,
    pub FloatingSave: u8,
}

/// `IO_CONNECT_INTERRUPT_MESSAGE_BASED_PARAMETERS`. `ConnectionContext`
/// points to where the result goes: an `IO_INTERRUPT_MESSAGE_INFO`
/// pointer, or, if the device has no message interrupts and the
/// connection fell back to its line, a `KINTERRUPT` pointer.
#[repr(C)]
pub struct IO_CONNECT_INTERRUPT_MESSAGE_BASED_PARAMETERS {
    pub PhysicalDeviceObject: *mut DEVICE_OBJECT,
    pub ConnectionContext: *mut PVOID,
    pub MessageServiceRoutine: Option<KMESSAGE_SERVICE_ROUTINE>,
    pub ServiceContext: PVOID,
    pub SpinLock: *mut KSPIN_LOCK,
    pub SynchronizeIrql: KIRQL,
    pub FloatingSave: u8,
    pub FallBackServiceRoutine: Option<KSERVICE_ROUTINE>,
}

/// `IO_CONNECT_INTERRUPT_PARAMETERS`: a version, then the member of the
/// union the version selects. NK reads the union through the member's
/// own type at [`IO_CONNECT_INTERRUPT_PARAMETERS::UNION`].
#[repr(C)]
pub struct IO_CONNECT_INTERRUPT_PARAMETERS {
    pub Version: u32,
    pub FullySpecified: IO_CONNECT_INTERRUPT_FULLY_SPECIFIED_PARAMETERS,
}

impl IO_CONNECT_INTERRUPT_PARAMETERS {
    /// Offset of the union.
    pub const UNION: usize = 8;
}

/// `IO_DISCONNECT_INTERRUPT_PARAMETERS`. `ConnectionContext` is the
/// `KINTERRUPT` or `IO_INTERRUPT_MESSAGE_INFO` the connection returned.
#[repr(C)]
pub struct IO_DISCONNECT_INTERRUPT_PARAMETERS {
    pub Version: u32,
    pub ConnectionContext: PVOID,
}

/// `IO_REPORT_INTERRUPT_ACTIVE_STATE_PARAMETERS`: the same shape.
pub type IO_REPORT_INTERRUPT_ACTIVE_STATE_PARAMETERS = IO_DISCONNECT_INTERRUPT_PARAMETERS;

/// `IO_INTERRUPT_MESSAGE_INFO_ENTRY`: one message of a device.
#[repr(C)]
pub struct IO_INTERRUPT_MESSAGE_INFO_ENTRY {
    /// Where the device writes to send the message.
    pub MessageAddress: i64,
    pub TargetProcessorSet: usize,
    pub InterruptObject: *mut KINTERRUPT,
    /// What the device writes.
    pub MessageData: u32,
    pub Vector: u32,
    pub Irql: KIRQL,
    pub Mode: u32,
    pub Polarity: u32,
}

/// `IO_INTERRUPT_MESSAGE_INFO`: `MessageCount` entries follow the
/// header in the same block.
#[repr(C)]
pub struct IO_INTERRUPT_MESSAGE_INFO {
    /// The IRQL every message's service routine is synchronised at.
    pub UnifiedIrql: KIRQL,
    pub MessageCount: u32,
    pub MessageInfo: [IO_INTERRUPT_MESSAGE_INFO_ENTRY; 1],
}

/// `GROUP_AFFINITY`: a set of processors of one group.
#[repr(C)]
pub struct GROUP_AFFINITY {
    pub Mask: usize,
    pub Group: u16,
    pub Reserved: [u16; 3],
}

const _: () = {
    use core::mem::{offset_of, size_of};
    assert!(size_of::<KINTERRUPT>() == 0x120);
    assert!(offset_of!(KINTERRUPT, InterruptListEntry) == 0x08);
    assert!(offset_of!(KINTERRUPT, ServiceRoutine) == 0x18);
    assert!(offset_of!(KINTERRUPT, MessageServiceRoutine) == 0x20);
    assert!(offset_of!(KINTERRUPT, MessageIndex) == 0x28);
    assert!(offset_of!(KINTERRUPT, ServiceContext) == 0x30);
    assert!(offset_of!(KINTERRUPT, SpinLock) == 0x38);
    assert!(offset_of!(KINTERRUPT, TickCount) == 0x40);
    assert!(offset_of!(KINTERRUPT, ActualLock) == 0x48);
    assert!(offset_of!(KINTERRUPT, DispatchAddress) == 0x50);
    assert!(offset_of!(KINTERRUPT, Vector) == 0x58);
    assert!(offset_of!(KINTERRUPT, Irql) == 0x5C);
    assert!(offset_of!(KINTERRUPT, SynchronizeIrql) == 0x5D);
    assert!(offset_of!(KINTERRUPT, FloatingSave) == 0x5E);
    assert!(offset_of!(KINTERRUPT, Connected) == 0x5F);
    assert!(offset_of!(KINTERRUPT, Number) == 0x60);
    assert!(offset_of!(KINTERRUPT, ShareVector) == 0x64);
    assert!(offset_of!(KINTERRUPT, ActiveCount) == 0x66);
    assert!(offset_of!(KINTERRUPT, InternalState) == 0x68);
    assert!(offset_of!(KINTERRUPT, Mode) == 0x6C);
    assert!(offset_of!(KINTERRUPT, Polarity) == 0x70);
    assert!(offset_of!(KINTERRUPT, ServiceCount) == 0x74);
    assert!(offset_of!(KINTERRUPT, DispatchCount) == 0x78);
    assert!(offset_of!(KINTERRUPT, PassiveEvent) == 0x80);
    assert!(offset_of!(KINTERRUPT, IsrDpcStats) == 0xB0);
    assert!(offset_of!(KINTERRUPT, RedirectObject) == 0x110);
    assert!(offset_of!(KINTERRUPT, PhysicalDeviceObject) == 0x118);

    assert!(size_of::<IO_CONNECT_INTERRUPT_PARAMETERS>() == 0x50);
    assert!(
        offset_of!(IO_CONNECT_INTERRUPT_PARAMETERS, FullySpecified)
            == IO_CONNECT_INTERRUPT_PARAMETERS::UNION
    );
    assert!(size_of::<IO_CONNECT_INTERRUPT_FULLY_SPECIFIED_PARAMETERS>() == 0x48);
    assert!(offset_of!(IO_CONNECT_INTERRUPT_FULLY_SPECIFIED_PARAMETERS, SpinLock) == 0x20);
    assert!(
        offset_of!(
            IO_CONNECT_INTERRUPT_FULLY_SPECIFIED_PARAMETERS,
            SynchronizeIrql
        ) == 0x28
    );
    assert!(
        offset_of!(
            IO_CONNECT_INTERRUPT_FULLY_SPECIFIED_PARAMETERS,
            FloatingSave
        ) == 0x29
    );
    assert!(offset_of!(IO_CONNECT_INTERRUPT_FULLY_SPECIFIED_PARAMETERS, ShareVector) == 0x2A);
    assert!(offset_of!(IO_CONNECT_INTERRUPT_FULLY_SPECIFIED_PARAMETERS, Vector) == 0x2C);
    assert!(offset_of!(IO_CONNECT_INTERRUPT_FULLY_SPECIFIED_PARAMETERS, Irql) == 0x30);
    assert!(
        offset_of!(
            IO_CONNECT_INTERRUPT_FULLY_SPECIFIED_PARAMETERS,
            InterruptMode
        ) == 0x34
    );
    assert!(
        offset_of!(
            IO_CONNECT_INTERRUPT_FULLY_SPECIFIED_PARAMETERS,
            ProcessorEnableMask
        ) == 0x38
    );
    assert!(offset_of!(IO_CONNECT_INTERRUPT_FULLY_SPECIFIED_PARAMETERS, Group) == 0x40);
    assert!(size_of::<IO_CONNECT_INTERRUPT_LINE_BASED_PARAMETERS>() == 0x30);
    assert!(offset_of!(IO_CONNECT_INTERRUPT_LINE_BASED_PARAMETERS, FloatingSave) == 0x29);
    assert!(size_of::<IO_CONNECT_INTERRUPT_MESSAGE_BASED_PARAMETERS>() == 0x38);
    assert!(
        offset_of!(
            IO_CONNECT_INTERRUPT_MESSAGE_BASED_PARAMETERS,
            FallBackServiceRoutine
        ) == 0x30
    );
    assert!(size_of::<IO_DISCONNECT_INTERRUPT_PARAMETERS>() == 0x10);
    assert!(offset_of!(IO_DISCONNECT_INTERRUPT_PARAMETERS, ConnectionContext) == 0x08);

    assert!(size_of::<IO_INTERRUPT_MESSAGE_INFO_ENTRY>() == 0x30);
    assert!(offset_of!(IO_INTERRUPT_MESSAGE_INFO_ENTRY, TargetProcessorSet) == 0x08);
    assert!(offset_of!(IO_INTERRUPT_MESSAGE_INFO_ENTRY, InterruptObject) == 0x10);
    assert!(offset_of!(IO_INTERRUPT_MESSAGE_INFO_ENTRY, MessageData) == 0x18);
    assert!(offset_of!(IO_INTERRUPT_MESSAGE_INFO_ENTRY, Vector) == 0x1C);
    assert!(offset_of!(IO_INTERRUPT_MESSAGE_INFO_ENTRY, Irql) == 0x20);
    assert!(offset_of!(IO_INTERRUPT_MESSAGE_INFO_ENTRY, Mode) == 0x24);
    assert!(offset_of!(IO_INTERRUPT_MESSAGE_INFO_ENTRY, Polarity) == 0x28);
    assert!(size_of::<IO_INTERRUPT_MESSAGE_INFO>() == 0x38);
    assert!(offset_of!(IO_INTERRUPT_MESSAGE_INFO, MessageCount) == 0x04);
    assert!(offset_of!(IO_INTERRUPT_MESSAGE_INFO, MessageInfo) == 0x08);

    assert!(size_of::<GROUP_AFFINITY>() == 0x10);
    assert!(offset_of!(GROUP_AFFINITY, Group) == 0x08);
};
