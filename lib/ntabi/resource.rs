//! Hardware resource descriptors, as far as the kernel reads and writes
//! them itself: the fields every kind of resource has, and the generic
//! view of the union that the memory and port encodings use.

use core::mem::{offset_of, size_of};

/// The view of a resource descriptor's union that fits a port and every
/// size of memory range: where it starts and its encoded length.
#[repr(C, packed(4))]
#[derive(Clone, Copy)]
pub struct CM_PARTIAL_RESOURCE_GENERIC {
    pub Start: i64,
    pub Length: u32,
}

/// The interrupt view of the union, its largest.
#[repr(C, packed(4))]
#[derive(Clone, Copy)]
pub struct CM_PARTIAL_RESOURCE_INTERRUPT {
    pub Level: u32,
    pub Vector: u32,
    pub Affinity: usize,
}

/// The union of a [`CM_PARTIAL_RESOURCE_DESCRIPTOR`]: the views NK
/// names. `wdm.h` has one per resource type.
#[repr(C, packed(4))]
#[derive(Clone, Copy)]
pub union CM_PARTIAL_RESOURCE_UNION {
    pub Generic: CM_PARTIAL_RESOURCE_GENERIC,
    pub Interrupt: CM_PARTIAL_RESOURCE_INTERRUPT,
}

/// [`CM_PARTIAL_RESOURCE_DESCRIPTOR`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/ns-wdm-_cm_partial_resource_descriptor):
/// one resource a device has been assigned. Packed to four bytes, as
/// `wdm.h` declares it.
#[repr(C, packed(4))]
#[derive(Clone, Copy)]
pub struct CM_PARTIAL_RESOURCE_DESCRIPTOR {
    pub Type: u8,
    pub ShareDisposition: u8,
    pub Flags: u16,
    pub u: CM_PARTIAL_RESOURCE_UNION,
}

/// The view of a requirement descriptor's union that fits a port and
/// every size of memory range.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct IO_RESOURCE_GENERIC {
    pub Length: u32,
    pub Alignment: u32,
    pub MinimumAddress: i64,
    pub MaximumAddress: i64,
}

/// The union of an [`IO_RESOURCE_DESCRIPTOR`]: the view NK names, which
/// is as large as any.
#[repr(C)]
#[derive(Clone, Copy)]
pub union IO_RESOURCE_UNION {
    pub Generic: IO_RESOURCE_GENERIC,
}

/// [`IO_RESOURCE_DESCRIPTOR`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/ns-wdm-_io_resource_descriptor):
/// one resource a device can use, and the range it may come from.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct IO_RESOURCE_DESCRIPTOR {
    pub Option: u8,
    pub Type: u8,
    pub ShareDisposition: u8,
    pub Spare1: u8,
    pub Flags: u16,
    pub Spare2: u16,
    pub u: IO_RESOURCE_UNION,
}

const _: () = {
    assert!(size_of::<CM_PARTIAL_RESOURCE_DESCRIPTOR>() == 0x14);
    assert!(offset_of!(CM_PARTIAL_RESOURCE_DESCRIPTOR, ShareDisposition) == 1);
    assert!(offset_of!(CM_PARTIAL_RESOURCE_DESCRIPTOR, Flags) == 2);
    assert!(offset_of!(CM_PARTIAL_RESOURCE_DESCRIPTOR, u) == 4);
    assert!(size_of::<CM_PARTIAL_RESOURCE_UNION>() == 0x10);
    assert!(offset_of!(CM_PARTIAL_RESOURCE_GENERIC, Length) == 8);
    assert!(offset_of!(CM_PARTIAL_RESOURCE_INTERRUPT, Affinity) == 8);
    assert!(size_of::<IO_RESOURCE_DESCRIPTOR>() == 0x20);
    assert!(offset_of!(IO_RESOURCE_DESCRIPTOR, Type) == 1);
    assert!(offset_of!(IO_RESOURCE_DESCRIPTOR, ShareDisposition) == 2);
    assert!(offset_of!(IO_RESOURCE_DESCRIPTOR, Flags) == 4);
    assert!(offset_of!(IO_RESOURCE_DESCRIPTOR, u) == 8);
    assert!(offset_of!(IO_RESOURCE_GENERIC, Alignment) == 4);
    assert!(offset_of!(IO_RESOURCE_GENERIC, MinimumAddress) == 8);
    assert!(offset_of!(IO_RESOURCE_GENERIC, MaximumAddress) == 0x10);
};
