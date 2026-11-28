//! Tests of routines drivers call that have no home in a larger test:
//! remove locks, the version report, looking a routine up by name, and
//! pool with quota.

use crate::io::remlock::*;
use crate::ke::{thread, time, wait};
use crate::mm::pool;
use crate::test::{Group, Report, Slot};
use core::sync::atomic::{AtomicU32, Ordering};
use nk_bootinfo::BootInfo;
use nk_ntabi::io::{IO_REMOVE_LOCK, OSVERSIONINFO_SIZE, RTL_OSVERSIONINFOEXW, UNICODE_STRING};
use nk_ntabi::status::STATUS_SUCCESS;

pub static GROUP: Group = Group {
    names: &[
        "io.remove-lock",
        "rtl.version",
        "mm.routine-address",
        "ex.pool-quota",
        "rtl.printf",
        "rtl.strings",
    ],
    run,
    manual: false,
};

static LOCK: Slot<IO_REMOVE_LOCK> = Slot::new();
static STAGE: AtomicU32 = AtomicU32::new(0);

fn acquire() -> i32 {
    // SAFETY: a static, initialised remove lock.
    unsafe {
        IoAcquireRemoveLockEx(
            LOCK.ptr(),
            core::ptr::null_mut(),
            core::ptr::null(),
            0,
            0x20,
        )
    }
}

fn release() {
    // SAFETY: a static remove lock the caller acquired.
    unsafe { IoReleaseRemoveLockEx(LOCK.ptr(), core::ptr::null_mut(), 0x20) };
}

/// Requests are counted in and out; removal waits for the ones still in
/// and turns away any that come after.
fn remove_lock() -> Result<(), &'static str> {
    fn holder(_: usize) {
        // Holds a count across the remover's wait, then lets go.
        STAGE.store(1, Ordering::Release);
        // SAFETY: no object is involved.
        unsafe { wait::wait(None, Some(-500_000)) };
        STAGE.store(2, Ordering::Release);
        release();
    }
    let before = thread::count();
    // SAFETY: static storage for a remove lock nothing uses.
    unsafe { IoInitializeRemoveLockEx(LOCK.ptr(), 0, 0, 0, 0x20) };
    if acquire() != STATUS_SUCCESS || acquire() != STATUS_SUCCESS {
        return Err("a remove lock refused a request before any removal");
    }
    release();
    // One count is this thread's; a second is handed to another thread.
    if acquire() != STATUS_SUCCESS {
        return Err("a remove lock refused a request before any removal");
    }
    STAGE.store(0, Ordering::Release);
    thread::create(holder, 0, thread::NORMAL_PRIORITY, thread::ANYWHERE)?;
    while STAGE.load(Ordering::Acquire) == 0 {
        thread::yield_now();
    }
    let started = time::interrupt_time();
    // SAFETY: a static remove lock this thread acquired.
    unsafe { IoReleaseRemoveLockAndWaitEx(LOCK.ptr(), core::ptr::null_mut(), 0x20) };
    if STAGE.load(Ordering::Acquire) != 2 || time::interrupt_time() - started < 300_000 {
        return Err("removal did not wait for the request still in progress");
    }
    if acquire() != STATUS_DELETE_PENDING {
        return Err("a request was let in after removal");
    }
    // Nothing else in progress: removal returns at once.
    // SAFETY: as above.
    unsafe {
        IoInitializeRemoveLockEx(LOCK.ptr(), 0, 0, 0, 0x20);
        acquire();
        IoReleaseRemoveLockAndWaitEx(LOCK.ptr(), core::ptr::null_mut(), 0x20);
    }
    thread::settle(before);
    Ok(())
}

/// The version reported is the reference machine's, in whichever of the
/// two structure sizes the caller declares, and no byte beyond it.
fn version() -> Result<(), &'static str> {
    for size in [
        OSVERSIONINFO_SIZE as usize,
        size_of::<RTL_OSVERSIONINFOEXW>(),
    ] {
        let mut raw = [0xEEu8; size_of::<RTL_OSVERSIONINFOEXW>()];
        let info = raw.as_mut_ptr().cast::<RTL_OSVERSIONINFOEXW>();
        // SAFETY: a local buffer of the larger structure's size.
        let (status, version) = unsafe {
            (&raw mut (*info).dwOSVersionInfoSize).write_unaligned(size as u32);
            let status = crate::rtl::RtlGetVersion(info);
            (
                status,
                [
                    (&raw const (*info).dwMajorVersion).read_unaligned(),
                    (&raw const (*info).dwMinorVersion).read_unaligned(),
                    (&raw const (*info).dwBuildNumber).read_unaligned(),
                    (&raw const (*info).dwPlatformId).read_unaligned(),
                ],
            )
        };
        if status != STATUS_SUCCESS || version != [10, 0, 19045, 2] {
            return Err("the version reported is not Windows 10.0.19045");
        }
        let untouched = raw[size..].iter().all(|&b| b == 0xEE);
        let extended = size == raw.len();
        if !untouched || (extended && raw[OSVERSIONINFO_SIZE as usize + 6] != 1) {
            return Err(
                "the version report wrote past the size given, or left the product type out",
            );
        }
    }
    if crate::rtl::RtlIsStateSeparationEnabled() != 0 {
        return Err("RtlIsStateSeparationEnabled must be false on NK");
    }
    // SAFETY: null pointers are allowed for optional query filters.
    let bad_desc = unsafe {
        crate::hal::description::IoQueryDeviceDescription(
            core::ptr::null(),
            core::ptr::null(),
            core::ptr::null(),
            core::ptr::null(),
            core::ptr::null(),
            core::ptr::null(),
            core::ptr::null(),
            core::ptr::null_mut(),
        )
    };
    if bad_desc != nk_ntabi::status::STATUS_INVALID_PARAMETER {
        return Err("IoQueryDeviceDescription accepted null callout");
    }
    // SAFETY: non-null dummy callout pointer is never invoked when no legacy
    // description matches.
    let missing_desc = unsafe {
        crate::hal::description::IoQueryDeviceDescription(
            core::ptr::null(),
            core::ptr::null(),
            core::ptr::null(),
            core::ptr::null(),
            core::ptr::null(),
            core::ptr::null(),
            core::ptr::dangling(),
            core::ptr::null_mut(),
        )
    };
    if missing_desc != nk_ntabi::status::STATUS_OBJECT_NAME_NOT_FOUND {
        return Err("IoQueryDeviceDescription did not return STATUS_OBJECT_NAME_NOT_FOUND");
    }
    // SAFETY: null is compared against loaded image ranges and yields null;
    // lock-by-handle and unlock accept the returned handle.
    unsafe {
        if !crate::ldr::MmLockPagableDataSection(core::ptr::null_mut()).is_null() {
            return Err("MmLockPagableDataSection returned non-null for null address");
        }
        crate::ldr::MmLockPagableSectionByHandle(core::ptr::null_mut());
        crate::ldr::MmUnlockPagableImageSection(core::ptr::null_mut());
    }
    Ok(())
}

/// A routine the kernel exports is found by name, at the address a
/// driver importing it is given; an unknown name gives null.
fn routine_address() -> Result<(), &'static str> {
    let find = |name: &str| {
        let mut wide: alloc::vec::Vec<u16> = name.encode_utf16().collect();
        let counted = UNICODE_STRING {
            Length: (wide.len() * 2) as u16,
            MaximumLength: (wide.len() * 2) as u16,
            Buffer: wide.as_mut_ptr(),
        };
        // SAFETY: a valid counted string.
        unsafe { crate::export::MmGetSystemRoutineAddress(&raw const counted) as u64 }
    };
    for name in [
        "KeSetEvent",
        "IofCompleteRequest",
        "KeStallExecutionProcessor",
    ] {
        let imported = crate::export::resolve(b"ntoskrnl.exe", name.as_bytes());
        if imported.is_none() || imported != Some(find(name)) {
            return Err("an exported routine was not found by name at its address");
        }
    }
    if find("NoSuchRoutineInAnyKernel") != 0 || find("kesetevent") != 0 || find("") != 0 {
        return Err("a name that is not an export was found");
    }
    Ok(())
}

/// Pool with quota is pool: allocated, usable, freed.
fn pool_quota() -> Result<(), &'static str> {
    let before = pool::usage().blocks;
    let block = pool::ExAllocatePoolWithQuotaTag(8, 100, u32::from_le_bytes(*b"Test")).cast::<u8>();
    if block.is_null() || pool::usage().blocks != before + 1 {
        return Err("a quota allocation did not allocate one block");
    }
    // SAFETY: a fresh block of 100 bytes, freed once.
    unsafe {
        block.write_bytes(0xA5, 100);
        pool::ExFreePoolWithTag(block.cast(), 0);
    }
    if pool::usage().blocks != before {
        return Err("a quota allocation was not freed");
    }
    Ok(())
}

/// A wide, NUL-terminated copy of `text`.
fn wide(text: &str) -> alloc::vec::Vec<u16> {
    text.encode_utf16().chain([0]).collect()
}

/// Formatted output through the entry points drivers call, with enough
/// arguments that some travel in registers and some on the stack.
fn printf() -> Result<(), &'static str> {
    use crate::rtl::print::{nk_variadic__snwprintf, nk_variadic_DbgPrint};
    let guid = wide("{%08X-%04X-%04X-%02X%02X-%02X%02X%02X%02X%02X%02X}");
    let expected = wide("{4D36E96C-E325-11CE-BFC1-08002BE10318}");
    let mut buffer = [0xEEEEu16; 48];
    // SAFETY: a local buffer of 48 characters and a format with eleven
    // integer arguments, passed as C passes them.
    let written = unsafe {
        nk_variadic__snwprintf(
            buffer.as_mut_ptr(),
            buffer.len(),
            guid.as_ptr(),
            0x4D36_E96Cu32,
            0xE325u32,
            0x11CEu32,
            0xBFu32,
            0xC1u32,
            0x08u32,
            0x00u32,
            0x2Bu32,
            0xE1u32,
            0x03u32,
            0x18u32,
        )
    };
    if written != 38 || buffer[..39] != expected[..] || buffer[39] != 0xEEEE {
        return Err("a GUID was not formatted as the C runtime formats it");
    }
    // Strings, a pointer, and a 64-bit number after them.
    let format = wide("%s|%S|%p|%I64u");
    let (text, narrow) = (wide("wide"), b"narrow\0");
    let mut buffer = [0u16; 64];
    // SAFETY: as above; the strings are NUL-terminated locals.
    let written = unsafe {
        nk_variadic__snwprintf(
            buffer.as_mut_ptr(),
            buffer.len(),
            format.as_ptr(),
            text.as_ptr(),
            narrow.as_ptr(),
            0xFFFF_F880_0013_8040u64,
            u64::MAX,
        )
    };
    let expected = wide("wide|narrow|FFFFF88000138040|18446744073709551615");
    if written != expected.len() as i32 - 1 || buffer[..expected.len()] != expected[..] {
        return Err("strings, a pointer and a 64-bit number were not formatted right");
    }
    // The bounded forms: an exact fit has no terminator; too long is -1
    // with the buffer full.
    let format = wide("%d");
    let mut small = [0xEEEEu16; 4];
    // SAFETY: as above, with the count the buffer really has room for.
    let (fits, exact, over) = unsafe {
        (
            nk_variadic__snwprintf(small.as_mut_ptr(), 4, format.as_ptr(), 123u32),
            nk_variadic__snwprintf(small.as_mut_ptr(), 3, format.as_ptr(), 456u32),
            nk_variadic__snwprintf(small.as_mut_ptr(), 2, format.as_ptr(), 789u32),
        )
    };
    // After the three calls: "78" from the last, "6" left from the
    // second, and the first call's terminator.
    if (fits, exact, over) != (3, 3, -1) || small != [0x37, 0x38, 0x36, 0] {
        return Err("a bounded format did not report or write what fits");
    }
    // SAFETY: a NUL-terminated format and the one argument it names.
    let status = unsafe {
        nk_variadic_DbgPrint(
            c"DeviceObject %p\n".as_ptr().cast(),
            0xFFFF_F880_0013_8040u64,
        )
    };
    if status != 0 {
        return Err("DbgPrint did not return success");
    }
    Ok(())
}

/// The C-runtime string routines, and freeing a counted string.
fn strings() -> Result<(), &'static str> {
    use crate::rtl::print::{_wcsnicmp, RtlFreeUnicodeString, wcschr};
    let text = wide("Class\\{GUID}");
    // SAFETY: NUL-terminated locals throughout.
    unsafe {
        let brace = wcschr(text.as_ptr(), u16::from(b'{'));
        if brace != text.as_ptr().add(6).cast_mut()
            || !wcschr(text.as_ptr(), u16::from(b'#')).is_null()
            || wcschr(text.as_ptr(), 0) != text.as_ptr().add(12).cast_mut()
        {
            return Err("wcschr did not find a character, or found one that is not there");
        }
        let (a, b, c) = (wide("Security"), wide("SECURITY!"), wide("Secure"));
        if _wcsnicmp(a.as_ptr(), b.as_ptr(), 8) != 0
            || _wcsnicmp(a.as_ptr(), b.as_ptr(), 9) >= 0
            || _wcsnicmp(a.as_ptr(), c.as_ptr(), 100) <= 0
            || _wcsnicmp(a.as_ptr(), c.as_ptr(), 5) != 0
            || _wcsnicmp(a.as_ptr(), b.as_ptr(), 0) != 0
        {
            return Err("_wcsnicmp compared wrongly");
        }
        let before = pool::usage().blocks;
        let buffer = pool::ExAllocatePoolWithTag(0, 32, u32::from_le_bytes(*b"Test"));
        let mut counted = UNICODE_STRING {
            Length: 8,
            MaximumLength: 32,
            Buffer: buffer.cast(),
        };
        RtlFreeUnicodeString(&raw mut counted);
        if !counted.Buffer.is_null() || counted.Length != 0 || pool::usage().blocks != before {
            return Err("RtlFreeUnicodeString did not free and empty the string");
        }
        // An empty string is left alone.
        RtlFreeUnicodeString(&raw mut counted);
    }
    Ok(())
}

fn run(r: &mut Report, _: &BootInfo) {
    r.check("io.remove-lock", remove_lock);
    r.check("rtl.version", version);
    r.check("mm.routine-address", routine_address);
    r.check("ex.pool-quota", pool_quota);
    r.check("rtl.printf", printf);
    r.check("rtl.strings", strings);
}

/// This file's test groups, in the order they run.
pub static GROUPS: &[&Group] = &[&GROUP];
