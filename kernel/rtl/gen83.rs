//! [`RtlGenerate8dot3Name`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-rtlgenerate8dot3name):
//! the next short name for a long one, by the rules of `nk_rtl::gen83`.

#![allow(non_snake_case)]

use super::string::Wide;
use alloc::vec::Vec;
use nk_ntabi::io::UNICODE_STRING;
use nk_ntabi::rtl::GENERATE_NAME_CONTEXT;
use nk_ntabi::status::*;
use nk_rtl::gen83;

/// `RtlGenerate8dot3Name`: the context, which the caller zeroed before
/// its first call for this long name, carries the base, the extension
/// and the last number. The short name goes in the caller's buffer,
/// which has room for twelve characters; its `Length` is set.
///
/// # Safety
/// `name` points to a counted string; `context` is writable; `short` is a
/// counted string whose buffer holds twelve characters.
pub unsafe extern "C" fn RtlGenerate8dot3Name(
    name: *const UNICODE_STRING,
    allow_extended: u8,
    context: *mut GENERATE_NAME_CONTEXT,
    short: *mut UNICODE_STRING,
) -> NTSTATUS {
    // SAFETY: per the contract; the context and the strings are the
    // caller's, read and written whole.
    unsafe {
        let long: Vec<u16> = Wide::of(name).units().collect();
        let mut ctx = context.read_unaligned();
        let mut out = [0u16; gen83::MAX_SHORT];
        let made = gen83::generate(
            &long,
            allow_extended != 0,
            crate::fsrtl::safe_extensions(),
            &mut ctx,
            &mut out,
        );
        context.write_unaligned(ctx);
        let (Ok(length) | Err(length)) = made;
        let buffer = (&raw const (*short).Buffer).read_unaligned();
        for (at, &c) in out[..length].iter().enumerate() {
            buffer.add(at).write_unaligned(c);
        }
        (&raw mut (*short).Length).write_unaligned((length * 2) as u16);
        match made {
            Ok(_) => STATUS_SUCCESS,
            Err(_) => STATUS_FILE_SYSTEM_LIMITATION,
        }
    }
}
