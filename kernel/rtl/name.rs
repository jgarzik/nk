//! File names, as the file-system runtime library judges them: the
//! wildcard match and the table of characters legal in a name. They
//! are `FsRtl` routines; their rules are `nk_rtl::wildcard` and
//! `nk_rtl::legal`.

#![allow(non_snake_case, non_upper_case_globals)]

use super::string::Wide;
use nk_ntabi::io::UNICODE_STRING;

/// [`FsRtlIsNameInExpression`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-_fsrtl_advanced_fcb_header-fsrtlisnameinexpression):
/// whether `name` matches the wildcard expression. Without regard to
/// case the name is compared in upper case, by the caller's table of
/// 65536 capitals if it gives one, else by the system's, and the
/// expression must be in upper case already.
///
/// Both strings are read in place and nothing is allocated, so the
/// routine never raises.
///
/// # Safety
/// `expression` and `name` point to counted strings; `upcase_table` is
/// null or points to 65536 units.
pub unsafe extern "C" fn FsRtlIsNameInExpression(
    expression: *const UNICODE_STRING,
    name: *const UNICODE_STRING,
    ignore_case: u8,
    upcase_table: *const u16,
) -> u8 {
    // SAFETY: per the contract.
    let (expression, name) = unsafe { (Wide::of(expression), Wide::of(name)) };
    let fold = |c: u16| {
        if ignore_case == 0 {
            c
        } else if upcase_table.is_null() {
            nk_rtl::upcase_char(c)
        } else {
            // SAFETY: per the contract: the table has a unit for every
            // value of `c`.
            unsafe { upcase_table.add(usize::from(c)).read_unaligned() }
        }
    };
    // A counted string is never longer than the longest expression.
    u8::from(nk_rtl::wildcard::is_name_in_expression(&expression, &name, fold) == Some(true))
}

/// The table itself, where drivers can read and nothing can write.
static LEGAL: [u8; 128] = nk_rtl::legal::LEGAL_ANSI_CHARACTERS;

/// A variable drivers import: it holds the address of the table.
#[repr(transparent)]
pub struct LegalVariable(*const u8);

// SAFETY: immutable, and the pointer names an immutable static.
unsafe impl Sync for LegalVariable {}

/// `FsRtlLegalAnsiCharacterArray` (`ntifs.h`): for each character below
/// 0x80, the file systems in whose names it is legal and whether it is
/// a wildcard.
pub static FsRtlLegalAnsiCharacterArray: LegalVariable = LegalVariable(LEGAL.as_ptr());

impl LegalVariable {
    /// The address drivers import.
    pub const fn address(&'static self) -> *const () {
        core::ptr::from_ref(self).cast()
    }
}
