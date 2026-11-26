//! `HalBugCheckSystem`: stop the system over a fatal hardware error.
//! The platform-specific hardware error driver (`pshed.dll`) and its
//! plug-ins call it with the error's source and record. Undocumented;
//! what it looks for in the record and how it stops are the pinned
//! kernel's (`nk_whea::fatal_stop`).

#![allow(non_snake_case)]

use crate::ke::bugcheck::KeBugCheckEx;
use nk_ntabi::whea::{
    NMI_SECTION_GUID, WHEA_ERROR_RECORD_HEADER, WHEA_ERROR_RECORD_SECTION_DESCRIPTOR,
    WHEA_ERROR_SOURCE_DESCRIPTOR, WHEA_NMI_ERROR_SECTION_FLAGS, WHEA_XPF_MCA_SECTION_STATUS,
    XPF_MCA_SECTION_GUID,
};
use nk_whea::FatalSection;

/// The routine drivers import. It does not return.
///
/// # Safety
/// `source` is an error source's descriptor and `record` a whole error
/// record: its header, the section descriptors the header counts, and
/// the sections they place.
pub unsafe extern "C" fn HalBugCheckSystem(
    source: *const WHEA_ERROR_SOURCE_DESCRIPTOR,
    record: *const WHEA_ERROR_RECORD_HEADER,
) -> ! {
    // SAFETY: per the contract; the caller's memory, read field by
    // field through raw pointers.
    let (kind, count) = unsafe {
        (
            (&raw const (*source).Type).read_unaligned(),
            (&raw const (*record).SectionCount).read_unaligned(),
        )
    };
    let sections = (0..usize::from(count)).map(|n| {
        // SAFETY: as above: descriptor `n` follows the header, and
        // says where in the record its section is.
        unsafe {
            let descriptor = record
                .byte_add(
                    size_of::<WHEA_ERROR_RECORD_HEADER>()
                        + n * size_of::<WHEA_ERROR_RECORD_SECTION_DESCRIPTOR>(),
                )
                .cast::<WHEA_ERROR_RECORD_SECTION_DESCRIPTOR>();
            let offset = (&raw const (*descriptor).SectionOffset).read_unaligned();
            let section = record.cast::<u8>().byte_add(offset as usize);
            let kind = (&raw const (*descriptor).SectionType).read_unaligned();
            if kind == NMI_SECTION_GUID {
                FatalSection::Nmi {
                    hypervisor: section.add(WHEA_NMI_ERROR_SECTION_FLAGS).read() & 1 != 0,
                }
            } else if kind == XPF_MCA_SECTION_GUID {
                FatalSection::MachineCheck {
                    status: section
                        .add(WHEA_XPF_MCA_SECTION_STATUS)
                        .cast::<u64>()
                        .read_unaligned(),
                }
            } else {
                FatalSection::Other
            }
        }
    });
    let (code, parameters) = nk_whea::fatal_stop(kind, record.addr(), sections);
    KeBugCheckEx(
        code,
        parameters[0],
        parameters[1],
        parameters[2],
        parameters[3],
    )
}

/// Stop the system as a driver does for a machine check: a record of
/// two sections, the second a machine check's. For the test that the
/// stop is Windows'.
pub fn stop_test() -> ! {
    const HEADER: usize = size_of::<WHEA_ERROR_RECORD_HEADER>();
    const DESCRIPTOR: usize = size_of::<WHEA_ERROR_RECORD_SECTION_DESCRIPTOR>();
    /// The machine-check section's place in the record, after a section
    /// of eight bytes of another kind.
    const CHECK: usize = HEADER + 2 * DESCRIPTOR + 8;
    let mut record = [0u8; CHECK + WHEA_XPF_MCA_SECTION_STATUS + 8];
    let base = (&raw mut record).cast::<u8>();
    // SAFETY: every write is within the local record; the source is a
    // zeroed local, which is a valid descriptor to read a type from.
    unsafe {
        let header = base.cast::<WHEA_ERROR_RECORD_HEADER>();
        (&raw mut (*header).SectionCount).write_unaligned(2);
        let descriptor = |n: usize| {
            base.add(HEADER + n * DESCRIPTOR)
                .cast::<WHEA_ERROR_RECORD_SECTION_DESCRIPTOR>()
        };
        (&raw mut (*descriptor(0)).SectionOffset).write_unaligned((CHECK - 8) as u32);
        (&raw mut (*descriptor(1)).SectionOffset).write_unaligned(CHECK as u32);
        (&raw mut (*descriptor(1)).SectionType).write_unaligned(XPF_MCA_SECTION_GUID);
        base.add(CHECK + WHEA_XPF_MCA_SECTION_STATUS)
            .cast::<u64>()
            .write_unaligned(0xDEAD_BEEF_1234_5678);
        let mut source = core::mem::zeroed::<WHEA_ERROR_SOURCE_DESCRIPTOR>();
        source.Type = nk_ntabi::whea::WHEA_ERR_SRC_TYPE_PCIE;
        HalBugCheckSystem(&raw const source, base.cast())
    }
}
