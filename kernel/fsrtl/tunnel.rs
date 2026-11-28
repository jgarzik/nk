//! Tunnel caches in a file system's volume control block: the exports
//! over `nk_fsrtl::tunnel`.
//!
//! The `TUNNEL` is the file system's memory: its fast mutex serialises
//! the routines, its `NumEntries` counts the entries, and `Cache` points
//! to NK's record of them, a pool block made with the first entry and
//! freed by `FsRtlDeleteTunnelCache`. Without memory an entry is not
//! remembered, as on Windows. The timer queue the structure
//! declares is left empty: NK keeps the entries' order in its record.
//! The limits are read from the registry at boot (`fsrtl::init`).

#![allow(non_snake_case)]

use super::limits;
use crate::ke::mutex::{ExAcquireFastMutex, ExReleaseFastMutex, KeInitializeGuardedMutex};
use crate::ke::time;
use crate::mm::pool;
use crate::rtl::counted::RtlCopyUnicodeString;
use crate::rtl::string::Wide;
use alloc::vec::Vec;
use core::mem::size_of;
use nk_fsrtl::tunnel::{Entry, Tunnel};
use nk_ntabi::fsrtl::TUNNEL;
use nk_ntabi::io::UNICODE_STRING;

/// The pool tag of a long name handed back in a fresh buffer.
const TAG_NAME: u32 = u32::from_le_bytes(*b"Tun4");

/// The pool tag of a cache's record.
const TAG_RECORD: u32 = u32::from_le_bytes(*b"TunL");

/// Run `f` on the cache's record with its mutex held, keeping
/// `NumEntries` in step; `None` if there was no memory for a record.
///
/// # Safety
/// `cache` is an initialised tunnel cache; the caller is at or below
/// `APC_LEVEL`.
unsafe fn locked<R>(cache: *mut TUNNEL, f: impl FnOnce(&mut Tunnel) -> R) -> Option<R> {
    // SAFETY: per the contract; `Cache` is null or the pool block this
    // module made for this cache, a `Tunnel`, used only under its mutex.
    unsafe {
        ExAcquireFastMutex(&raw mut (*cache).Mutex);
        let slot = &raw mut (*cache).Cache;
        if slot.read_unaligned().is_null() {
            let record = pool::alloc(size_of::<Tunnel>(), TAG_RECORD).cast::<Tunnel>();
            if !record.is_null() {
                record.write(Tunnel::default());
                slot.write_unaligned(record.cast());
            }
        }
        let record = slot.read_unaligned().cast::<Tunnel>();
        let r = (!record.is_null()).then(|| {
            let tunnel = &mut *record;
            let r = f(tunnel);
            (&raw mut (*cache).NumEntries).write_unaligned(tunnel.len() as u16);
            r
        });
        ExReleaseFastMutex(&raw mut (*cache).Mutex);
        r
    }
}

/// `items` in a vector, or `None` without memory for it.
fn copied<T>(items: impl ExactSizeIterator<Item = T>) -> Option<Vec<T>> {
    let mut v = Vec::new();
    v.try_reserve_exact(items.len()).ok()?;
    v.extend(items);
    Some(v)
}

fn now() -> i64 {
    time::system_time() as i64
}

/// [`FsRtlInitializeTunnelCache`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-fsrtlinitializetunnelcache):
/// an empty cache.
///
/// # Safety
/// `cache` is the file system's writable `TUNNEL`.
pub unsafe extern "C" fn FsRtlInitializeTunnelCache(cache: *mut TUNNEL) {
    // SAFETY: per the contract.
    unsafe {
        KeInitializeGuardedMutex(&raw mut (*cache).Mutex);
        (&raw mut (*cache).Cache).write_unaligned(core::ptr::null_mut());
        let queue = &raw mut (*cache).TimerQueue;
        (&raw mut (*queue).Flink).write_unaligned(queue);
        (&raw mut (*queue).Blink).write_unaligned(queue);
        (&raw mut (*cache).NumEntries).write_unaligned(0);
    }
}

/// [`FsRtlDeleteTunnelCache`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-fsrtldeletetunnelcache):
/// forget every entry and free the record. Nothing is done with
/// tunnelling off, as on Windows.
///
/// # Safety
/// `cache` is an initialised tunnel cache nothing else uses.
pub unsafe extern "C" fn FsRtlDeleteTunnelCache(cache: *mut TUNNEL) {
    if limits().off() {
        return;
    }
    // SAFETY: per the contract; the record is this module's box.
    unsafe {
        let slot = &raw mut (*cache).Cache;
        let record = slot.read_unaligned();
        if !record.is_null() {
            core::ptr::drop_in_place(record.cast::<Tunnel>());
            let _ = pool::free(record.cast());
        }
        slot.write_unaligned(core::ptr::null_mut());
        (&raw mut (*cache).NumEntries).write_unaligned(0);
    }
}

/// [`FsRtlAddToTunnelCache`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-fsrtladdtotunnelcache):
/// remember a file's names and data under its directory's key.
///
/// # Safety
/// `cache` is an initialised tunnel cache; the names are counted
/// strings; `data` is readable for `data_length` bytes.
pub unsafe extern "C" fn FsRtlAddToTunnelCache(
    cache: *mut TUNNEL,
    directory: u64,
    short: *const UNICODE_STRING,
    long: *const UNICODE_STRING,
    key_by_short: u8,
    data_length: u32,
    data: *const u8,
) {
    let limits = limits();
    if limits.off() {
        return;
    }
    // SAFETY: per the contract.
    unsafe {
        let (Some(short), Some(long), Some(data)) = (
            copied(Wide::of(short).units()),
            copied(Wide::of(long).units()),
            copied(
                core::slice::from_raw_parts(data, data_length as usize)
                    .iter()
                    .copied(),
            ),
        ) else {
            return;
        };
        let entry = Entry {
            directory,
            by_short: key_by_short != 0,
            short,
            long,
            data,
            time: 0,
        };
        locked(cache, |t| t.add(entry, now(), limits));
    }
}

/// [`FsRtlFindInTunnelCache`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-fsrtlfindintunnelcache):
/// the names and data remembered under `name` in a directory. The short
/// name is copied as far as the caller's buffer holds; a long name the
/// caller's buffer cannot hold gets a pool buffer, which the caller
/// frees. False if nothing is remembered, or if there was no memory for
/// that buffer (where Windows would write through a null pointer).
///
/// # Safety
/// `cache` is an initialised tunnel cache; `name` is a counted string;
/// the outputs are writable counted strings and a data buffer large
/// enough for what the file system stored.
pub unsafe extern "C" fn FsRtlFindInTunnelCache(
    cache: *mut TUNNEL,
    directory: u64,
    name: *const UNICODE_STRING,
    short: *mut UNICODE_STRING,
    long: *mut UNICODE_STRING,
    data_length: *mut u32,
    data: *mut u8,
) -> u8 {
    let limits = limits();
    if limits.off() {
        return 0;
    }
    // SAFETY: per the contract.
    unsafe {
        let Some(key) = copied(Wide::of(name).units()) else {
            return 0;
        };
        let Some(Some(found)) = locked(cache, |t| t.find(directory, &key, now(), limits).cloned())
        else {
            return 0;
        };
        let counted = |units: &[u16]| UNICODE_STRING {
            Length: (units.len() * 2) as u16,
            MaximumLength: (units.len() * 2) as u16,
            Buffer: units.as_ptr().cast_mut(),
        };
        RtlCopyUnicodeString(short, &counted(&found.short));
        let bytes = found.long.len() * 2;
        if usize::from((&raw const (*long).MaximumLength).read_unaligned()) >= bytes {
            RtlCopyUnicodeString(long, &counted(&found.long));
        } else {
            let buffer = pool::alloc(bytes, TAG_NAME).cast::<u16>();
            if buffer.is_null() {
                return 0;
            }
            core::ptr::copy_nonoverlapping(found.long.as_ptr(), buffer, found.long.len());
            long.write_unaligned(UNICODE_STRING {
                Length: bytes as u16,
                MaximumLength: bytes as u16,
                Buffer: buffer,
            });
        }
        core::ptr::copy_nonoverlapping(found.data.as_ptr(), data, found.data.len());
        data_length.write_unaligned(found.data.len() as u32);
        1
    }
}

/// [`FsRtlDeleteKeyFromTunnelCache`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-fsrtldeletekeyfromtunnelcache):
/// forget every entry of a directory.
///
/// # Safety
/// `cache` is an initialised tunnel cache.
pub unsafe extern "C" fn FsRtlDeleteKeyFromTunnelCache(cache: *mut TUNNEL, directory: u64) {
    let limits = limits();
    if limits.off() {
        return;
    }
    // SAFETY: per the contract.
    unsafe { locked(cache, |t| t.delete_key(directory, limits)) };
}
