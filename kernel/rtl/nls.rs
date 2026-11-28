//! The OEM code page's variables, which file systems import to decide
//! how to treat bytes of a short name (`ntifs.h`: `NLS_MB_OEM_CODE_PAGE_TAG`,
//! `NLS_OEM_LEAD_BYTE_INFO`, read by `FsRtlIsLeadDbcsCharacter`).
//!
//! NK's OEM page is 437, Windows' for the English (United States)
//! system locale: one byte per character, so no byte leads a
//! double-byte character.

#![allow(non_upper_case_globals)]

/// `NlsMbOemCodePageTag`: a `BOOLEAN`, true when the OEM page has
/// double-byte characters. 437 has none.
#[repr(transparent)]
pub struct Tag(u8);

impl Tag {
    /// The address drivers import.
    pub const fn address(&'static self) -> *const () {
        (&raw const self.0).cast()
    }
}

/// The tag: 437 has no double-byte characters.
pub static NlsMbOemCodePageTag: Tag = Tag(0);

/// For each byte, whether it leads a double-byte character: none do.
static LEAD_BYTES: [u16; 256] = [0; 256];

/// `NlsOemLeadByteInfo`: a pointer to the page's lead-byte table.
#[repr(transparent)]
pub struct LeadByteInfo(*const u16);

// SAFETY: immutable, and the pointer names a static.
unsafe impl Sync for LeadByteInfo {}

impl LeadByteInfo {
    /// The address drivers import.
    pub const fn address(&'static self) -> *const () {
        (&raw const self.0).cast()
    }
}

/// The table no byte of which leads.
pub static NlsOemLeadByteInfo: LeadByteInfo = LeadByteInfo(LEAD_BYTES.as_ptr());
