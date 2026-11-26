//! The errata manager, as far as a driver's own structures go: what a
//! provider hands `EmProviderRegister`.

use crate::ex::GUID;
use core::ffi::c_void;

/// `EM_ENTRY_REGISTRATION`: one kind of entry a provider supplies.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct EM_ENTRY_REGISTRATION {
    pub EntryGuid: *const GUID,
    pub LazyEntryCallback: *mut c_void,
    pub LazyCallbackContext: *mut c_void,
}

/// `EM_CALLBACK_REGISTRATION`: one callback a provider implements.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct EM_CALLBACK_REGISTRATION {
    pub CallbackGuid: *const GUID,
    pub CallbackFunction: *mut c_void,
    pub Context: *mut c_void,
}

const _: () = {
    use core::mem::{offset_of, size_of};
    assert!(size_of::<EM_ENTRY_REGISTRATION>() == 0x18);
    assert!(offset_of!(EM_ENTRY_REGISTRATION, LazyEntryCallback) == 0x08);
    assert!(size_of::<EM_CALLBACK_REGISTRATION>() == 0x18);
    assert!(offset_of!(EM_CALLBACK_REGISTRATION, CallbackFunction) == 0x08);
    assert!(offset_of!(EM_CALLBACK_REGISTRATION, Context) == 0x10);
};
