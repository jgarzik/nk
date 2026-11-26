//! Resource descriptors through the routines drivers call. The rules
//! themselves are tested on the host (`nk_rtl::resource`).

use crate::rtl::resource::*;
use crate::test::{Group, Report};
use nk_bootinfo::BootInfo;
use nk_ntabi::resource::{CM_PARTIAL_RESOURCE_DESCRIPTOR, IO_RESOURCE_DESCRIPTOR};
use nk_ntabi::status::*;

static GROUP: Group = Group {
    names: &["rtl.resource"],
    run,
    manual: false,
};

const GB: u64 = 1 << 30;
const MEMORY: u8 = 3;
const MEMORY_LARGE: u8 = 7;
const LARGE_40: u16 = 0x200;
const LARGE_48: u16 = 0x400;

fn resource() -> Result<(), &'static str> {
    // SAFETY: the descriptors are locals, zeroed, which is a valid value
    // of each; the other pointers are to locals.
    unsafe {
        let mut assigned = core::mem::zeroed::<CM_PARTIAL_RESOURCE_DESCRIPTOR>();
        let cm = &raw mut assigned;
        let mut start = 0u64;
        if RtlCmEncodeMemIoResource(cm, MEMORY, 0x1000, 0xFEC0_0000) != STATUS_SUCCESS
            || (assigned.Type, { assigned.Flags }, {
                assigned.u.Generic.Length
            }) != (MEMORY, 0, 0x1000)
            || RtlCmDecodeMemIoResource(cm, &raw mut start) != 0x1000
            || start != 0xFEC0_0000
        {
            return Err("a memory resource under 4 GB did not encode and decode as itself");
        }
        if RtlCmEncodeMemIoResource(cm, MEMORY, 8 * GB, 0x1_0000_0000) != STATUS_SUCCESS
            || (assigned.Type, { assigned.Flags }, {
                assigned.u.Generic.Length
            }) != (MEMORY_LARGE, LARGE_40, 0x200_0000)
            || RtlCmDecodeMemIoResource(cm, core::ptr::null_mut()) != 8 * GB
        {
            return Err("a memory resource of 8 GB is not a large one in units of 256 bytes");
        }
        if RtlCmEncodeMemIoResource(cm, MEMORY, 8 * GB + 1, 7) != STATUS_UNSUCCESSFUL
            || { assigned.Flags } != 0
            || { assigned.u.Generic.Start } != 7
            || RtlCmEncodeMemIoResource(cm, 2, 16, 0) != STATUS_INVALID_PARAMETER
            || RtlCmEncodeMemIoResource(cm, 1, 8 * GB, 0) != STATUS_INVALID_PARAMETER
        {
            return Err("RtlCmEncodeMemIoResource took a length or a type it cannot encode");
        }

        let mut wanted = core::mem::zeroed::<IO_RESOURCE_DESCRIPTOR>();
        let io = &raw mut wanted;
        let (mut alignment, mut minimum, mut maximum) = (0u64, 0u64, 0u64);
        let status =
            RtlIoEncodeMemIoResource(io, MEMORY, 0x100_0000_0000, 0x1000, 4 * GB, u64::MAX);
        if status != STATUS_SUCCESS
            || (wanted.Type, wanted.Flags) != (MEMORY_LARGE, LARGE_48)
            || (wanted.u.Generic.Length, wanted.u.Generic.Alignment) != (0x100_0000, 1)
        {
            return Err("a memory requirement of 1 TB is not a large one in units of 64 KB");
        }
        let length =
            RtlIoDecodeMemIoResource(io, &raw mut alignment, &raw mut minimum, &raw mut maximum);
        if (length, alignment, minimum, maximum) != (0x100_0000_0000, 0x1_0000, 4 * GB, u64::MAX) {
            return Err("RtlIoDecodeMemIoResource did not give back what was encoded");
        }
        if RtlIoEncodeMemIoResource(io, 1, 8, 4 * GB, 0, 0) != STATUS_INVALID_PARAMETER {
            return Err("RtlIoEncodeMemIoResource took a port with a 4 GB alignment");
        }

        let mut closest = 1u64;
        if RtlFindClosestEncodableLength(4 * GB + 1, &raw mut closest) != STATUS_SUCCESS
            || closest != 4 * GB + 0x100
            || RtlFindClosestEncodableLength(u64::MAX, &raw mut closest) != STATUS_UNSUCCESSFUL
            || closest != 0
        {
            return Err("RtlFindClosestEncodableLength did not round up to a unit");
        }
    }
    Ok(())
}

fn run(r: &mut Report, _: &BootInfo) {
    r.check("rtl.resource", resource);
}

/// This file's test groups, in the order they run.
pub static GROUPS: &[&Group] = &[&GROUP];
