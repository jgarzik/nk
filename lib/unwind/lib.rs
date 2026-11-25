//! Windows structured-exception unwinding, as data: find a function's
//! unwind record in `.pdata`, undo its prolog over a register set, and
//! search a `__C_specific_handler` scope table.
//!
//! Nothing here runs code or touches a real stack. Inputs are a mapped
//! image as a byte slice, RVAs, a register set, and a callback that reads
//! one 64-bit stack slot; the kernel supplies the callback and the loop
//! that walks frames. Both architectures' decoders build on every host.
//!
//! Input is untrusted: every offset is bounds-checked and malformed unwind
//! data is an `Err`, never a panic. No allocation and no `unsafe`.
//!
//! Formats:
//! <https://learn.microsoft.com/en-us/cpp/build/exception-handling-x64>,
//! <https://learn.microsoft.com/en-us/cpp/build/arm64-exception-handling>.

#![cfg_attr(not(test), no_std)]

pub mod arm64;
pub mod x64;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UnwindError {
    /// An RVA or a table runs outside the image.
    OutOfBounds,
    /// Unwind data that breaks its format: a code that overruns its array,
    /// an unknown version, sizes that contradict each other.
    BadUnwindInfo,
    /// A well-formed unwind code this crate does not implement; carries
    /// the opcode (x64) or the first code byte (arm64).
    Unsupported(u8),
    /// Chained unwind records or `.pdata` indirections nest too deeply to
    /// be anything but a loop.
    ChainTooDeep,
    /// The stack-read callback refused an address the unwind needs.
    BadStack,
    /// A scope table whose record count runs past its bytes.
    BadScopeTable,
}

/// Where a program counter sits in its function. Language handlers are
/// only meaningful in the body: a prolog or epilog has no complete frame.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Place {
    Prolog,
    Body,
    Epilog,
}

/// Longest chain of unwind records followed before giving up.
const MAX_CHAIN: usize = 32;

fn bytes_at(d: &[u8], off: usize, len: usize) -> Result<&[u8], UnwindError> {
    let end = off.checked_add(len).ok_or(UnwindError::OutOfBounds)?;
    d.get(off..end).ok_or(UnwindError::OutOfBounds)
}

fn u8_at(d: &[u8], off: usize) -> Result<u8, UnwindError> {
    d.get(off).copied().ok_or(UnwindError::OutOfBounds)
}

fn u16_at(d: &[u8], off: usize) -> Result<u16, UnwindError> {
    bytes_at(d, off, 2).map(|b| u16::from_le_bytes([b[0], b[1]]))
}

fn u32_at(d: &[u8], off: usize) -> Result<u32, UnwindError> {
    bytes_at(d, off, 4).map(|b| u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
}

/// Read one stack slot through the caller's callback.
fn slot(read: &mut impl FnMut(u64) -> Option<u64>, addr: u64) -> Result<u64, UnwindError> {
    read(addr).ok_or(UnwindError::BadStack)
}

/// Index of the last `.pdata` entry whose first word (the function's
/// start RVA) is at or below `rva`. Entries are `entry_size` bytes and
/// sorted by start, as the PE format requires.
fn last_at_or_below(
    image: &[u8],
    dir_rva: u32,
    dir_size: u32,
    entry_size: usize,
    rva: u32,
) -> Result<Option<usize>, UnwindError> {
    let table = bytes_at(image, dir_rva as usize, dir_size as usize)?;
    let (mut lo, mut hi) = (0, table.len() / entry_size);
    while lo < hi {
        let mid = lo + (hi - lo) / 2;
        if u32_at(table, mid * entry_size)? <= rva {
            lo = mid + 1;
        } else {
            hi = mid;
        }
    }
    Ok(lo.checked_sub(1))
}

#[cfg(test)]
mod arm64_tests;
#[cfg(test)]
mod x64_tests;
