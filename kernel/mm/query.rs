//! What the memory manager says about the machine's size.

/// `MM_SYSTEMSIZE`'s `MmLargeSystem`.
const LARGE_SYSTEM: u32 = 2;

/// [`MmQuerySystemSize`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-mmquerysystemsize):
/// whether the machine is small, medium or large. The pinned kernel
/// answers large whatever its memory.
#[allow(non_snake_case)]
pub extern "C" fn MmQuerySystemSize() -> u32 {
    LARGE_SYSTEM
}
