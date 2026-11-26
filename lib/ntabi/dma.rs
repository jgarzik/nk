//! DMA as drivers see it: the adapter object's visible head, the table
//! of operations a driver calls through, and what goes in and out of
//! them.
//!
//! [`DEVICE_DESCRIPTION`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/ns-wdm-_device_description),
//! [`DMA_OPERATIONS`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/ns-wdm-_dma_operations).
//! The table is the pinned build's, which is longer than the one the
//! documentation lists.

use crate::io::PVOID;

/// `DEVICE_DESCRIPTION.Version`.
pub const DEVICE_DESCRIPTION_VERSION: u32 = 0;
pub const DEVICE_DESCRIPTION_VERSION1: u32 = 1;
pub const DEVICE_DESCRIPTION_VERSION2: u32 = 2;
pub const DEVICE_DESCRIPTION_VERSION3: u32 = 3;

/// `DEVICE_DESCRIPTION`: how a device does DMA. The last four fields
/// are read only for version 3.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct DEVICE_DESCRIPTION {
    pub Version: u32,
    /// A bus master: it drives the transfer itself.
    pub Master: u8,
    pub ScatterGather: u8,
    pub DemandMode: u8,
    pub AutoInitialize: u8,
    pub Dma32BitAddresses: u8,
    pub IgnoreCount: u8,
    pub Reserved1: u8,
    pub Dma64BitAddresses: u8,
    pub BusNumber: u32,
    pub DmaChannel: u32,
    /// `INTERFACE_TYPE`.
    pub InterfaceType: u32,
    pub DmaWidth: u32,
    pub DmaSpeed: u32,
    pub MaximumLength: u32,
    pub DmaPort: u32,
    /// How many address bits the device drives; 0 for "as the two flags
    /// above say".
    pub DmaAddressWidth: u32,
    pub DmaControllerInstance: u32,
    pub DmaRequestLine: u32,
    pub DeviceAddress: i64,
}

/// `DMA_ADAPTER`: what `IoGetDmaAdapter` returns a pointer to.
#[repr(C)]
pub struct DMA_ADAPTER {
    pub Version: u16,
    pub Size: u16,
    pub DmaOperations: *const DMA_OPERATIONS,
}

/// `DMA_OPERATIONS`: the routines of an adapter, each a function
/// address.
#[repr(C)]
pub struct DMA_OPERATIONS {
    pub Size: u32,
    pub PutDmaAdapter: *const (),
    pub AllocateCommonBuffer: *const (),
    pub FreeCommonBuffer: *const (),
    pub AllocateAdapterChannel: *const (),
    pub FlushAdapterBuffers: *const (),
    pub FreeAdapterChannel: *const (),
    pub FreeMapRegisters: *const (),
    pub MapTransfer: *const (),
    pub GetDmaAlignment: *const (),
    pub ReadDmaCounter: *const (),
    pub GetScatterGatherList: *const (),
    pub PutScatterGatherList: *const (),
    pub CalculateScatterGatherList: *const (),
    pub BuildScatterGatherList: *const (),
    pub BuildMdlFromScatterGatherList: *const (),
    pub GetDmaAdapterInfo: *const (),
    pub GetDmaTransferInfo: *const (),
    pub InitializeDmaTransferContext: *const (),
    pub AllocateCommonBufferEx: *const (),
    pub AllocateAdapterChannelEx: *const (),
    pub ConfigureAdapterChannel: *const (),
    pub CancelAdapterChannel: *const (),
    pub MapTransferEx: *const (),
    pub GetScatterGatherListEx: *const (),
    pub BuildScatterGatherListEx: *const (),
    pub FlushAdapterBuffersEx: *const (),
    pub FreeAdapterObject: *const (),
    pub CancelMappedTransfer: *const (),
    pub AllocateDomainCommonBuffer: *const (),
    pub FlushDmaBuffer: *const (),
    pub JoinDmaDomain: *const (),
    pub LeaveDmaDomain: *const (),
    pub GetDmaDomain: *const (),
    pub AllocateCommonBufferWithBounds: *const (),
    pub AllocateCommonBufferVector: *const (),
    pub GetCommonBufferFromVectorByIndex: *const (),
    pub FreeCommonBufferFromVector: *const (),
    pub FreeCommonBufferVector: *const (),
}

/// `SCATTER_GATHER_ELEMENT`: one run of bus addresses.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct SCATTER_GATHER_ELEMENT {
    pub Address: i64,
    pub Length: u32,
    pub Reserved: usize,
}

/// `SCATTER_GATHER_LIST`: `NumberOfElements` elements follow the header.
/// `Reserved` is the kernel's.
#[repr(C)]
pub struct SCATTER_GATHER_LIST {
    pub NumberOfElements: u32,
    pub Reserved: usize,
    pub Elements: [SCATTER_GATHER_ELEMENT; 0],
}

/// `IO_ALLOCATION_ACTION`: what an adapter-channel execution routine
/// returns.
pub const KEEP_OBJECT: u32 = 1;
pub const DEALLOCATE_OBJECT: u32 = 2;
pub const DEALLOCATE_OBJECT_KEEP_REGISTERS: u32 = 3;

/// `DRIVER_CONTROL`: `(DeviceObject, Irp, MapRegisterBase, Context)`,
/// returning an `IO_ALLOCATION_ACTION`.
pub type DRIVER_CONTROL = unsafe extern "C" fn(PVOID, PVOID, PVOID, PVOID) -> u32;
/// `DRIVER_LIST_CONTROL`: `(DeviceObject, Irp, ScatterGather, Context)`.
pub type DRIVER_LIST_CONTROL = unsafe extern "C" fn(PVOID, PVOID, *mut SCATTER_GATHER_LIST, PVOID);

/// `DMA_ADAPTER_INFO_VERSION1`.
pub const DMA_ADAPTER_INFO_VERSION1: u32 = 1;
/// `DMA_ADAPTER_INFO_V1.Flags`: execution routines are called before the
/// requesting routine returns; the transfer routines may be bypassed,
/// because bus addresses are physical addresses the device can reach.
pub const ADAPTER_INFO_SYNCHRONOUS_CALLBACK: u32 = 1;
pub const ADAPTER_INFO_API_BYPASS: u32 = 2;

/// `DMA_ADAPTER_INFO`, whose union has the one member.
#[repr(C)]
pub struct DMA_ADAPTER_INFO {
    pub Version: u32,
    pub ReadDmaCounterAvailable: u8,
    pub ScatterGatherLimit: u32,
    pub DmaAddressWidth: u32,
    pub Flags: u32,
    pub MinimumTransferUnit: u32,
}

/// `DMA_TRANSFER_INFO_VERSION1` and `2`.
pub const DMA_TRANSFER_INFO_VERSION1: u32 = 1;
pub const DMA_TRANSFER_INFO_VERSION2: u32 = 2;

/// `DMA_TRANSFER_INFO`, as its largest member, `V2`: version 1 lacks
/// `LogicalPageCount`.
#[repr(C)]
pub struct DMA_TRANSFER_INFO {
    pub Version: u32,
    pub MapRegisterCount: u32,
    pub ScatterGatherElementCount: u32,
    pub ScatterGatherListSize: u32,
    pub LogicalPageCount: u32,
}

const _: () = {
    use core::mem::{offset_of, size_of};
    assert!(size_of::<DEVICE_DESCRIPTION>() == 0x40);
    assert!(offset_of!(DEVICE_DESCRIPTION, Master) == 0x04);
    assert!(offset_of!(DEVICE_DESCRIPTION, Dma32BitAddresses) == 0x08);
    assert!(offset_of!(DEVICE_DESCRIPTION, Dma64BitAddresses) == 0x0B);
    assert!(offset_of!(DEVICE_DESCRIPTION, InterfaceType) == 0x14);
    assert!(offset_of!(DEVICE_DESCRIPTION, MaximumLength) == 0x20);
    assert!(offset_of!(DEVICE_DESCRIPTION, DmaAddressWidth) == 0x28);
    assert!(offset_of!(DEVICE_DESCRIPTION, DeviceAddress) == 0x38);
    assert!(size_of::<DMA_ADAPTER>() == 0x10);
    assert!(offset_of!(DMA_ADAPTER, DmaOperations) == 0x08);
    assert!(size_of::<DMA_OPERATIONS>() == 0x138);
    assert!(offset_of!(DMA_OPERATIONS, PutDmaAdapter) == 0x08);
    assert!(offset_of!(DMA_OPERATIONS, GetScatterGatherList) == 0x58);
    assert!(offset_of!(DMA_OPERATIONS, GetDmaAdapterInfo) == 0x80);
    assert!(offset_of!(DMA_OPERATIONS, AllocateCommonBufferEx) == 0x98);
    assert!(offset_of!(DMA_OPERATIONS, FlushDmaBuffer) == 0xF0);
    assert!(offset_of!(DMA_OPERATIONS, AllocateCommonBufferWithBounds) == 0x110);
    assert!(offset_of!(DMA_OPERATIONS, FreeCommonBufferVector) == 0x130);
    assert!(size_of::<SCATTER_GATHER_ELEMENT>() == 0x18);
    assert!(offset_of!(SCATTER_GATHER_ELEMENT, Length) == 0x08);
    assert!(size_of::<SCATTER_GATHER_LIST>() == 0x10);
    assert!(offset_of!(SCATTER_GATHER_LIST, Elements) == 0x10);
    assert!(size_of::<DMA_ADAPTER_INFO>() == 0x18);
    assert!(offset_of!(DMA_ADAPTER_INFO, ScatterGatherLimit) == 0x08);
    assert!(offset_of!(DMA_ADAPTER_INFO, MinimumTransferUnit) == 0x14);
    assert!(size_of::<DMA_TRANSFER_INFO>() == 0x14);
    assert!(offset_of!(DMA_TRANSFER_INFO, LogicalPageCount) == 0x10);
};
