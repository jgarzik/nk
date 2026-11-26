//! Questions a driver asks about the system it runs on: the classes of
//! `ZwQuerySystemInformation` that the binaries NK runs ask for, the
//! list of loaded modules, the version, whether the verifier watches a
//! driver, and whether a live dump can be taken.
//!
//! The length rules are `nk_ex::sysinfo`. Buffers are the driver's
//! memory: written field by field through raw pointers, and nothing is
//! written that Windows does not write.

#![allow(non_snake_case)]

use crate::ke::{irql, smp, time};
use crate::mm::user::{LOWEST_USER_ADDRESS, USER_PROBE_ADDRESS};
use crate::{kd, ldr, mm, rtl};
use alloc::vec::Vec;
use core::ffi::c_void;
use nk_ex::sysinfo::{self as rules, AuxAnswer, Fixed, Origin};
use nk_ntabi::io::{DRIVER_OBJECT, UNICODE_STRING};
use nk_ntabi::status::*;
use nk_ntabi::sysinfo::*;

/// One loaded image as the two module lists report it.
struct Listed {
    base: u64,
    size: u32,
    /// How many hold it loaded: its importers for a library, else one.
    load_count: u16,
    path: [u8; MODULE_PATH_LENGTH],
    file_name: u16,
}

/// The images in memory as Windows lists them: the kernel, then
/// `hal.dll`, then the drivers in the order they were loaded.
///
/// NK has no separate HAL image: `hal.dll` is a second name of the
/// kernel's (its imports bind to the kernel's exports), so it is listed
/// with the kernel's range. An address in that range is the kernel's to
/// whoever takes the first module that contains it.
///
/// `None` without memory for the list: the query fails
/// (`STATUS_INSUFFICIENT_RESOURCES`), having written nothing.
fn listed() -> Option<Vec<Listed>> {
    let modules = ldr::modules()?;
    let mut list = Vec::new();
    list.try_reserve_exact(modules.len() + 1).ok()?;
    for (index, module) in modules.iter().enumerate() {
        // The kernel's own image is the first entered.
        let names: &[(Origin, &[u8])] = if index == 0 {
            &[
                (Origin::System, module.name()),
                (Origin::System, b"hal.dll"),
            ]
        } else {
            &[(Origin::Driver, module.name())]
        };
        for &(origin, name) in names {
            let (path, file_name) = rules::module_path(origin, name);
            list.push(Listed {
                base: module.base,
                size: module.size as u32,
                load_count: if module.library {
                    module.references.min(u32::from(u16::MAX)) as u16
                } else {
                    1
                },
                path,
                file_name,
            });
        }
    }
    Some(list)
}

/// Write a module's path as Windows does: its characters and the
/// terminator, no byte beyond.
///
/// # Safety
/// `to` is writable for `MODULE_PATH_LENGTH` bytes.
unsafe fn write_path(to: *mut u8, path: &[u8; MODULE_PATH_LENGTH]) {
    let length = path.iter().position(|&b| b == 0).unwrap_or(path.len() - 1);
    // SAFETY: per the contract; the terminator is within the field.
    unsafe { core::ptr::copy_nonoverlapping(path.as_ptr(), to, length + 1) };
}

/// Class 11: the count of loaded modules and as many entries as fit.
/// `Section` and `MappedBase` of an entry are not written, as on
/// Windows. `Flags` is zero: NK keeps no loader flags. `None` without
/// memory to list them.
///
/// # Safety
/// `buffer` is writable for `length` bytes.
unsafe fn modules(buffer: *mut u8, length: u32) -> Option<(NTSTATUS, u32)> {
    let list = listed()?;
    let plan = rules::module_list(list.len() as u32, length);
    // SAFETY: per the contract and the plan: the count if the header
    // fits, and whole entries that fit.
    unsafe {
        if plan.count {
            buffer.cast::<u32>().write_unaligned(list.len() as u32);
        }
        for (index, module) in list.iter().take(plan.entries as usize).enumerate() {
            let entry = buffer
                .add(RTL_PROCESS_MODULES_HEADER)
                .cast::<RTL_PROCESS_MODULE_INFORMATION>()
                .add(index);
            (&raw mut (*entry).ImageBase).write_unaligned(module.base as *mut c_void);
            (&raw mut (*entry).ImageSize).write_unaligned(module.size);
            (&raw mut (*entry).Flags).write_unaligned(0);
            (&raw mut (*entry).LoadOrderIndex).write_unaligned(index as u16);
            (&raw mut (*entry).InitOrderIndex).write_unaligned(0);
            (&raw mut (*entry).LoadCount).write_unaligned(module.load_count);
            (&raw mut (*entry).OffsetToFileName).write_unaligned(module.file_name);
            write_path((&raw mut (*entry).FullPathName).cast(), &module.path);
        }
    }
    let status = if plan.complete {
        STATUS_SUCCESS
    } else {
        STATUS_INFO_LENGTH_MISMATCH
    };
    Some((status, plan.needed))
}

/// Class 0, written field by field: the bytes between and after the
/// fields stay the caller's.
///
/// # Safety
/// `to` is writable for the structure's size.
unsafe fn basic(to: *mut SYSTEM_BASIC_INFORMATION) {
    let (pages, lowest, highest) = mm::physical_memory();
    let processors = smp::online_count();
    let clamp = |value: u64| value.min(u64::from(u32::MAX)) as u32;
    // SAFETY: per the contract.
    unsafe {
        (&raw mut (*to).Reserved).write_unaligned(0);
        (&raw mut (*to).TimerResolution).write_unaligned(time::KeQueryTimeIncrement());
        (&raw mut (*to).PageSize).write_unaligned(mm::PAGE_SIZE as u32);
        (&raw mut (*to).NumberOfPhysicalPages).write_unaligned(clamp(pages));
        (&raw mut (*to).LowestPhysicalPageNumber).write_unaligned(clamp(lowest));
        (&raw mut (*to).HighestPhysicalPageNumber).write_unaligned(clamp(highest));
        // Windows reserves address space in units of 64 KiB.
        (&raw mut (*to).AllocationGranularity).write_unaligned(0x1_0000);
        (&raw mut (*to).MinimumUserModeAddress).write_unaligned(LOWEST_USER_ADDRESS as usize);
        // The last address below the 64 KiB no-access region that ends
        // the user range.
        (&raw mut (*to).MaximumUserModeAddress).write_unaligned(USER_PROBE_ADDRESS as usize - 1);
        // One group of at most 64 processors, numbered from zero.
        (&raw mut (*to).ActiveProcessorsAffinityMask)
            .write_unaligned(usize::MAX >> (usize::BITS as usize - processors));
        (&raw mut (*to).NumberOfProcessors).write_unaligned(processors as i8);
    }
}

/// [`NtQuerySystemInformation`](https://learn.microsoft.com/en-us/windows/win32/api/winternl/nf-winternl-ntquerysysteminformation),
/// which drivers import under this name and as
/// `ZwQuerySystemInformation`: for a caller in kernel mode the two do
/// the same.
///
/// Answered: `SystemBasicInformation` (0), `SystemModuleInformation`
/// (11), `SystemKernelDebuggerInformation` (35) and
/// `SystemIsolatedUserModeInformation` (165), which says there is no
/// secure kernel. Any other class is `STATUS_INVALID_INFO_CLASS`, and
/// leaves `return_length` alone, as Windows does for a class it does
/// not know. Without memory to list the modules, class 11 is
/// `STATUS_INSUFFICIENT_RESOURCES`, and nothing is written.
///
/// # Safety
/// `buffer` is writable for `length` bytes, and `return_length` is null
/// or writable.
pub unsafe extern "C" fn NtQuerySystemInformation(
    class: u32,
    buffer: *mut c_void,
    length: u32,
    return_length: *mut u32,
) -> NTSTATUS {
    let buffer = buffer.cast::<u8>();
    let fixed = |rule: Fixed, write: &dyn Fn()| {
        let answer = rule.answer(length);
        if answer.fits {
            write();
            (STATUS_SUCCESS, answer.length)
        } else {
            (STATUS_INFO_LENGTH_MISMATCH, answer.length)
        }
    };
    let (status, reported) = match class {
        SYSTEM_BASIC_INFORMATION_CLASS => fixed(
            Fixed::Exactly(size_of::<SYSTEM_BASIC_INFORMATION>() as u32),
            // SAFETY: per the contract, and the length is the structure's.
            &|| unsafe { basic(buffer.cast()) },
        ),
        SYSTEM_KERNEL_DEBUGGER_INFORMATION_CLASS => fixed(
            Fixed::AtLeast(size_of::<SYSTEM_KERNEL_DEBUGGER_INFORMATION>() as u32),
            &|| {
                // Enabled and present go together: NK's debugger is
                // either there and answering (`debug=on`) or not there.
                let attached = kd::debugger_attached();
                // SAFETY: per the contract; the length is two at least.
                unsafe {
                    buffer.write(u8::from(attached));
                    buffer.add(1).write(u8::from(!attached));
                }
            },
        ),
        SYSTEM_ISOLATED_USER_MODE_INFORMATION_CLASS => fixed(
            Fixed::Exactly(SYSTEM_ISOLATED_USER_MODE_INFORMATION_SIZE as u32),
            &|| {
                // No secure kernel, no hypervisor-enforced code
                // integrity: every bit clear.
                // SAFETY: per the contract; the length is the block's.
                unsafe {
                    buffer.write_bytes(0, SYSTEM_ISOLATED_USER_MODE_INFORMATION_SIZE);
                }
            },
        ),
        // SAFETY: per the contract.
        SYSTEM_MODULE_INFORMATION_CLASS => match unsafe { modules(buffer, length) } {
            Some(answer) => answer,
            None => return STATUS_INSUFFICIENT_RESOURCES,
        },
        _ => return STATUS_INVALID_INFO_CLASS,
    };
    if !return_length.is_null() {
        // SAFETY: per the contract.
        unsafe { return_length.write_unaligned(reported) };
    }
    status
}

/// `RtlQueryModuleInformation`, which the WDK's auxiliary library
/// (`AuxKlibQueryModuleInformation`) calls: the loaded modules, each as
/// its base alone (`size_per_module` 8) or as `AUX_MODULE_EXTENDED_INFO`
/// (0x110). With no buffer, the length needed. Without memory to list
/// them, `STATUS_INSUFFICIENT_RESOURCES`, and nothing is written.
///
/// # Safety
/// `information_length` is readable and writable; `buffer` is null or
/// writable for the length stated there.
pub unsafe extern "C" fn RtlQueryModuleInformation(
    information_length: *mut u32,
    size_per_module: u32,
    buffer: *mut c_void,
) -> NTSTATUS {
    let Some(list) = listed() else {
        return STATUS_INSUFFICIENT_RESOURCES;
    };
    // The length is read only once a buffer makes it matter, as on
    // Windows.
    let given = if buffer.is_null() {
        0
    } else {
        // SAFETY: per the contract.
        unsafe { information_length.read_unaligned() }
    };
    let answer = rules::aux_modules(list.len() as u32, size_per_module, buffer.addr(), given);
    let (status, length) = match answer {
        AuxAnswer::BadSize => return STATUS_INVALID_PARAMETER_2,
        AuxAnswer::Misaligned => return STATUS_INVALID_PARAMETER_3,
        AuxAnswer::Needed(length) => (STATUS_SUCCESS, length),
        AuxAnswer::TooSmall(length) => (STATUS_BUFFER_TOO_SMALL, length),
        AuxAnswer::Written(length) => {
            for (index, module) in list.iter().enumerate() {
                // SAFETY: per the contract and the answer: the buffer
                // holds every module at this size, and is aligned.
                unsafe {
                    let entry = buffer
                        .cast::<u8>()
                        .add(index * size_per_module as usize)
                        .cast::<AUX_MODULE_EXTENDED_INFO>();
                    (&raw mut (*entry).ImageBase).write(module.base as *mut c_void);
                    if size_per_module == rules::AUX_EXTENDED {
                        (&raw mut (*entry).ImageSize).write(module.size);
                        (&raw mut (*entry).FileNameOffset).write(module.file_name);
                        (&raw mut (*entry).FullPathName).write(module.path);
                    }
                }
            }
            (STATUS_SUCCESS, length)
        }
    };
    // SAFETY: per the contract.
    unsafe { information_length.write_unaligned(length) };
    status
}

/// [`PsGetVersion`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-psgetversion):
/// the version `RtlGetVersion` reports, each part only if asked for,
/// and an empty service-pack string. `FALSE`: not a checked build.
///
/// # Safety
/// Each pointer is null or writable.
pub unsafe extern "C" fn PsGetVersion(
    major: *mut u32,
    minor: *mut u32,
    build: *mut u32,
    csd_version: *mut UNICODE_STRING,
) -> u8 {
    let (major_version, minor_version, build_number) = rtl::VERSION;
    // SAFETY: per the contract.
    unsafe {
        if !major.is_null() {
            major.write_unaligned(major_version);
        }
        if !minor.is_null() {
            minor.write_unaligned(minor_version);
        }
        if !build.is_null() {
            build.write_unaligned(build_number & 0xFFFF);
        }
        if !csd_version.is_null() {
            csd_version.write_unaligned(UNICODE_STRING {
                Length: 0,
                MaximumLength: 0,
                Buffer: core::ptr::null_mut(),
            });
        }
    }
    0
}

/// [`MmIsDriverVerifying`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-mmisdriververifying):
/// zero. NK has no driver verifier, so no driver is being verified.
pub extern "C" fn MmIsDriverVerifying(_driver: *mut DRIVER_OBJECT) -> u32 {
    0
}

/// [`MmIsVerifierEnabled`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-mmisverifierenabled):
/// `STATUS_NOT_SUPPORTED`, with no flags: NK has no driver verifier.
/// That is Windows' answer with its verifier off.
///
/// # Safety
/// `verifier_flags` is null or writable.
pub unsafe extern "C" fn MmIsVerifierEnabled(verifier_flags: *mut u32) -> NTSTATUS {
    if !verifier_flags.is_null() {
        // SAFETY: per the contract.
        unsafe { verifier_flags.write_unaligned(0) };
    }
    STATUS_NOT_SUPPORTED
}

/// [`MmAddVerifierThunks`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-mmaddverifierthunks):
/// `STATUS_NOT_SUPPORTED`, Windows' answer with its verifier off: the
/// thunks are not looked at.
pub extern "C" fn MmAddVerifierThunks(_thunk_buffer: *mut c_void, _size: u32) -> NTSTATUS {
    STATUS_NOT_SUPPORTED
}

/// `ExIsSoftBoot` (exported, not documented): whether the system was
/// started by a soft restart, with the firmware skipped. NK is always
/// started by firmware.
pub extern "C" fn ExIsSoftBoot() -> u8 {
    0
}

/// [`MmIsAddressValid`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-mmisaddressvalid):
/// whether reading the address would not fault: whether it is mapped,
/// as the processor reads its page tables. Callable at any IRQL.
pub extern "C" fn MmIsAddressValid(virtual_address: *const c_void) -> u8 {
    let address = virtual_address.addr() as u64;
    // An address is 48 bits, sign-extended, on both architectures: one
    // that is not names nothing, whatever a walk of the tables with its
    // low bits would find.
    let canonical = ((address as i64) << 16) >> 16 == address as i64;
    u8::from(canonical && crate::mm::map::physical(address).is_some())
}

/// The answers of a system with no driver verifier, started by
/// firmware; and which addresses are valid.
pub fn answers_test() -> Result<(), &'static str> {
    let mut flags = 7u32;
    // SAFETY: a local.
    let status = unsafe { MmIsVerifierEnabled(&raw mut flags) };
    // SAFETY: null is allowed.
    let none = unsafe { MmIsVerifierEnabled(core::ptr::null_mut()) };
    if (status, flags, none) != (STATUS_NOT_SUPPORTED, 0, STATUS_NOT_SUPPORTED)
        || MmAddVerifierThunks(core::ptr::null_mut(), 0) != STATUS_NOT_SUPPORTED
    {
        return Err("the driver verifier is not reported as off");
    }
    if ExIsSoftBoot() != 0 {
        return Err("ExIsSoftBoot says the firmware was skipped");
    }
    let here = (&raw const flags).cast::<c_void>();
    let code = answers_test as *const c_void;
    if MmIsAddressValid(here) != 1 || MmIsAddressValid(code) != 1 {
        return Err("MmIsAddressValid says the stack or the kernel's code is not mapped");
    }
    // Address zero, and the hole between the halves of the address
    // space, are never mapped.
    let hole = core::ptr::without_provenance::<c_void>(0x0000_8000_0000_0000);
    if MmIsAddressValid(core::ptr::null()) != 0 || MmIsAddressValid(hole) != 0 {
        return Err("MmIsAddressValid says an address nothing maps is valid");
    }
    Ok(())
}

/// `DbgkWerCaptureLiveKernelDump`: write a dump of the running system
/// for error reporting. NK cannot: it answers as Windows does before
/// its live-dump support has started, `STATUS_DEVICE_NOT_READY`, after
/// the one check Windows makes before that, of the IRQL
/// (`STATUS_INVALID_LEVEL` above `PASSIVE_LEVEL`). A caller logs the
/// status and goes on without a dump.
///
/// The arguments are the component's name, a bugcheck code and its four
/// parameters, two pointers and flags.
#[allow(clippy::too_many_arguments)]
pub extern "C" fn DbgkWerCaptureLiveKernelDump(
    _component: *const u16,
    _code: u32,
    _p1: usize,
    _p2: usize,
    _p3: usize,
    _p4: usize,
    _first: *mut c_void,
    _second: *mut c_void,
    _flags: u32,
) -> NTSTATUS {
    if irql::current() != irql::PASSIVE_LEVEL {
        return STATUS_INVALID_LEVEL;
    }
    STATUS_DEVICE_NOT_READY
}
