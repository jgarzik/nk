//! System DLL (`\SystemRoot\System32\ntdll.dll`), `\Device\BootDevice` /
//! `\SystemRoot` symlink resolution, and shared read-only NLS / API-Set v6
//! sections mapped into every user-mode process.

#![allow(dead_code)]

use crate::ex::pushlock::PushLock;
use crate::io::file::{self, OpenRequest};
use crate::mm::{self, PAGE_SIZE};
use crate::ob::{self, object::ObRef};
use alloc::format;
use alloc::vec;
use alloc::vec::Vec;
use nk_bootinfo::{BootInfo, SystemPartition};
use nk_mm::protect::PAGE_READONLY;
use nk_mm::vad::USER_PROBE_VA;
use nk_ntabi::disk::{
    IOCTL_DISK_GET_PARTITION_INFO_EX, PARTITION_INFORMATION_EX, PARTITION_STYLE_GPT,
    PARTITION_STYLE_MBR,
};
use nk_ntabi::ke::KAPC_STATE;
use nk_ntabi::status::*;
use nk_ntabi::user::PS_SYSTEM_DLL_INIT_BLOCK;
use nk_pe::exports::{Export, Exports};
use nk_pe::{DIR_EXPORT, Pe};

/// Resolved export RVAs inside `ntdll.dll`.
#[derive(Clone, Copy)]
pub struct NtdllExports {
    pub preferred_base: u64,
    pub image_size: u64,
    pub ldr_initialize_thunk: u32,
    pub ki_user_apc_dispatcher: u32,
    pub ki_user_exception_dispatcher: u32,
    pub ki_user_callback_dispatcher: u32,
    pub rtl_user_thread_start: u32,
    pub ldr_system_dll_init_block: u32,
}

/// Per-process mapped addresses of `ntdll.dll`, NLS tables, and API-Set v6 map.
#[derive(Clone, Copy)]
pub struct MappedSysDll {
    pub ntdll_base: u64,
    pub ntdll_size: u64,
    pub ldr_initialize_thunk: u64,
    pub ki_user_apc_dispatcher: u64,
    pub ki_user_exception_dispatcher: u64,
    pub ki_user_callback_dispatcher: u64,
    pub rtl_user_thread_start: u64,
    pub ansi_cp_va: u64,
    pub oem_cp_va: u64,
    pub unicode_case_va: u64,
    pub apiset_va: u64,
}

struct CachedSysDll {
    ntdll_section: ObRef,
    exports: NtdllExports,
    nls_section: ObRef,
    oem_cp_off: u64,
    unicode_case_off: u64,
    apiset_section: ObRef,
}

// SAFETY: `ObRef` points to kernel section objects safe to share across threads.
unsafe impl Send for CachedSysDll {}
// SAFETY: as above; `SYSDLL` is guarded by a `PushLock`.
unsafe impl Sync for CachedSysDll {}

static SYSDLL: PushLock<Option<CachedSysDll>> = PushLock::new(None);

fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().collect()
}

fn guid_bytes(g: &nk_ntabi::ex::GUID) -> [u8; 16] {
    let mut out = [0u8; 16];
    out[..4].copy_from_slice(&g.Data1.to_le_bytes());
    out[4..6].copy_from_slice(&g.Data2.to_le_bytes());
    out[6..8].copy_from_slice(&g.Data3.to_le_bytes());
    out[8..16].copy_from_slice(&g.Data4);
    out
}

/// Check whether `vol_name` (e.g. `\Device\HarddiskVolume1`) matches `part`.
fn volume_matches(vol_name: &str, part: &SystemPartition) -> bool {
    let req = OpenRequest {
        share_access: 0x3,
        ..OpenRequest::new(vol_name)
    };
    let Ok((handle, _)) = file::open(&req) else {
        return false;
    };
    let mut buf = [0u8; size_of::<PARTITION_INFORMATION_EX>()];
    let res = file::device_control(handle, IOCTL_DISK_GET_PARTITION_INFO_EX, &[], &mut buf);
    file::close(handle);
    let Ok(r) = res else {
        return false;
    };
    if r.status != STATUS_SUCCESS || r.information < size_of::<PARTITION_INFORMATION_EX>() {
        return false;
    }
    // SAFETY: `buf` is at least `size_of::<PARTITION_INFORMATION_EX>()` bytes.
    let info = unsafe {
        buf.as_ptr()
            .cast::<PARTITION_INFORMATION_EX>()
            .read_unaligned()
    };
    match (part.sig_type, info.PartitionStyle) {
        (SystemPartition::SIG_GPT, PARTITION_STYLE_GPT) => {
            // SAFETY: `PartitionStyle == PARTITION_STYLE_GPT` selects the `Gpt` variant.
            let gpt = unsafe { info.Info.Gpt };
            guid_bytes(&gpt.PartitionId) == part.sig
        }
        (SystemPartition::SIG_MBR, PARTITION_STYLE_MBR) => {
            info.StartingOffset == (part.start_lba as i64) * 512
        }
        _ => false,
    }
}

/// Read an entire file from the NT namespace (e.g. `\SystemRoot\System32\ntdll.dll`).
pub fn read_file_bytes(path: &str) -> Result<Vec<u8>, NTSTATUS> {
    const GENERIC_READ_SYNC: u32 = 0x8010_0000;
    const SHARE_READ_WRITE: u32 = 0x3;
    let req = OpenRequest {
        desired_access: GENERIC_READ_SYNC,
        share_access: SHARE_READ_WRITE,
        ..OpenRequest::new(path)
    };
    let (handle, _) = file::open(&req)?;
    let mut std_info = [0u8; 24];
    let q = file::query_information(handle, 5, &mut std_info);
    if let Err(e) = q {
        file::close(handle);
        return Err(match e {
            file::IoError::NoMemory => STATUS_INSUFFICIENT_RESOURCES,
            file::IoError::Handle(s) | file::IoError::Refused(s) => s,
            file::IoError::NotCompleted { dispatch_status: s }
            | file::IoError::StatusMismatch {
                dispatch_status: s, ..
            } => s,
        });
    }
    let eof = i64::from_le_bytes(std_info[8..16].try_into().unwrap_or([0; 8]));
    if eof <= 0 || eof > 64 * 1024 * 1024 {
        file::close(handle);
        return Err(STATUS_INVALID_IMAGE_FORMAT);
    }
    let total = eof as usize;
    let mut buf = vec![0u8; total];
    let mut off = 0usize;
    while off < total {
        let chunk = (total - off).min(64 * 1024);
        match file::read_at(handle, off as i64, &mut buf[off..off + chunk]) {
            Ok(r) if r.information > 0 => off += r.information,
            Ok(_) => break,
            Err(e) => {
                file::close(handle);
                return Err(match e {
                    file::IoError::NoMemory => STATUS_INSUFFICIENT_RESOURCES,
                    file::IoError::Handle(s) | file::IoError::Refused(s) => s,
                    file::IoError::NotCompleted { dispatch_status: s }
                    | file::IoError::StatusMismatch {
                        dispatch_status: s, ..
                    } => s,
                });
            }
        }
    }
    file::close(handle);
    buf.truncate(off);
    Ok(buf)
}

/// Ensure `\Device\BootDevice` and `\SystemRoot` symbolic links point to the
/// Windows system partition containing `\Windows\System32\ntdll.dll`.
pub fn ensure_system_root(info: &BootInfo) -> Result<(), NTSTATUS> {
    let sysroot = wide("\\SystemRoot");
    if ob::lookup(None, &sysroot).is_ok() {
        return Ok(());
    }

    // Wait up to 10 seconds for `\Device\HarddiskVolume1` to be published by `volmgr.sys`.
    let vol1 = wide("\\Device\\HarddiskVolume1");
    let mut appeared = false;
    for _ in 0..100 {
        if ob::lookup(None, &vol1).is_ok_and(|(_, rest)| rest.is_empty()) {
            appeared = true;
            break;
        }
        // SAFETY: delay wait with no dispatcher object.
        unsafe { crate::ke::wait::wait(None, Some(-1_000_000)) };
    }
    if !appeared {
        return Err(STATUS_OBJECT_NAME_NOT_FOUND);
    }

    // Pick the volume matching `BootInfo::system_partition`, falling back to
    // the first volume that contains `\Windows\System32\ntdll.dll`.
    let mut chosen: Option<alloc::string::String> = None;
    for n in 1..=8u32 {
        let name = format!("\\Device\\HarddiskVolume{n}");
        let w = wide(&name);
        if !ob::lookup(None, &w).is_ok_and(|(_, rest)| rest.is_empty()) {
            continue;
        }
        if info.system_partition.is_present() && volume_matches(&name, &info.system_partition) {
            chosen = Some(name);
            break;
        }
        if chosen.is_none() {
            let probe = format!("{name}\\Windows\\System32\\ntdll.dll");
            let req = OpenRequest {
                desired_access: 0x8010_0000,
                share_access: 0x3,
                ..OpenRequest::new(&probe)
            };
            if let Ok((h, _)) = file::open(&req) {
                file::close(h);
                chosen = Some(name);
            }
        }
    }

    let Some(target) = chosen else {
        return Err(STATUS_OBJECT_NAME_NOT_FOUND);
    };

    let boot_dev = wide("\\Device\\BootDevice");
    let _ = ob::insert_link(&boot_dev, &wide(&target));
    let st = ob::insert_link(&sysroot, &wide("\\Device\\BootDevice\\Windows"));
    if st != STATUS_SUCCESS && st != STATUS_OBJECT_NAME_COLLISION {
        return Err(st);
    }
    kprintln!(
        "ps: \\Device\\BootDevice -> {target}, \\SystemRoot -> \\Device\\BootDevice\\Windows"
    );
    Ok(())
}

/// Lay out a PE32+ file into a temporary virtual image buffer and resolve the
/// required `ntdll.dll` exports.
fn parse_ntdll_exports(bytes: &[u8]) -> Result<NtdllExports, NTSTATUS> {
    let pe = Pe::parse(bytes).map_err(|_| STATUS_INVALID_IMAGE_FORMAT)?;
    let h = pe.headers();
    let img_sz = (h.size_of_image as usize).next_multiple_of(PAGE_SIZE);
    let mut image = vec![0u8; img_sz];
    let hdr_len = (h.size_of_headers as usize).min(bytes.len()).min(img_sz);
    image[..hdr_len].copy_from_slice(&bytes[..hdr_len]);
    for s in pe.sections() {
        let rva = s.rva as usize;
        let raw_off = s.raw_off as usize;
        let copy_len = (s.raw_size as usize).min(s.mem_size() as usize);
        if rva + copy_len <= image.len() && raw_off + copy_len <= bytes.len() {
            image[rva..rva + copy_len].copy_from_slice(&bytes[raw_off..raw_off + copy_len]);
        }
    }
    let Some(exports) =
        Exports::parse(&image, h.dir(DIR_EXPORT)).map_err(|_| STATUS_INVALID_IMAGE_FORMAT)?
    else {
        return Err(STATUS_INVALID_IMAGE_FORMAT);
    };
    let resolve = |sym: &[u8]| -> Result<u32, NTSTATUS> {
        match exports
            .by_name(sym)
            .map_err(|_| STATUS_INVALID_IMAGE_FORMAT)?
        {
            Some(Export::Rva(rva)) => Ok(rva),
            _ => Err(STATUS_PROCEDURE_NOT_FOUND),
        }
    };
    Ok(NtdllExports {
        preferred_base: h.image_base,
        image_size: img_sz as u64,
        ldr_initialize_thunk: resolve(b"LdrInitializeThunk")?,
        ki_user_apc_dispatcher: resolve(b"KiUserApcDispatcher")?,
        ki_user_exception_dispatcher: resolve(b"KiUserExceptionDispatcher")?,
        ki_user_callback_dispatcher: resolve(b"KiUserCallbackDispatcher")?,
        rtl_user_thread_start: resolve(b"RtlUserThreadStart")?,
        ldr_system_dll_init_block: resolve(b"LdrSystemDllInitBlock")?,
    })
}

/// Ensure `ntdll.dll`, NLS, and API-Set v6 sections are loaded and cached.
pub fn ensure_loaded() -> Result<(), NTSTATUS> {
    if SYSDLL.read().is_some() {
        return Ok(());
    }
    let ntdll_bytes = read_file_bytes("\\SystemRoot\\System32\\ntdll.dll")?;
    let exports = parse_ntdll_exports(&ntdll_bytes)?;
    let ntdll_name = wide("\\Windows\\System32\\ntdll.dll");
    let ntdll_section = mm::view::create_image_section_from_bytes(&ntdll_name, &ntdll_bytes)?;

    // Build combined page-aligned NLS blob: C_1252, C_437, l_intl.
    let c1252 = nk_nls::c_1252();
    let c437 = nk_nls::c_437();
    let lintl = nk_nls::l_intl();
    let oem_cp_off = c1252.len().next_multiple_of(PAGE_SIZE);
    let unicode_case_off = (oem_cp_off + c437.len()).next_multiple_of(PAGE_SIZE);
    let total_nls = (unicode_case_off + lintl.len()).next_multiple_of(PAGE_SIZE);
    let mut nls_blob = vec![0u8; total_nls];
    nls_blob[..c1252.len()].copy_from_slice(&c1252);
    nls_blob[oem_cp_off..oem_cp_off + c437.len()].copy_from_slice(&c437);
    nls_blob[unicode_case_off..unicode_case_off + lintl.len()].copy_from_slice(&lintl);
    let nls_section = mm::view::create_pagefile_section_from_bytes(&nls_blob, PAGE_READONLY)?;

    let apiset_blob = nk_apiset::default_map();
    let apiset_section = mm::view::create_pagefile_section_from_bytes(&apiset_blob, PAGE_READONLY)?;

    let mut guard = SYSDLL.lock();
    if guard.is_none() {
        *guard = Some(CachedSysDll {
            ntdll_section,
            exports,
            nls_section,
            oem_cp_off: oem_cp_off as u64,
            unicode_case_off: unicode_case_off as u64,
            apiset_section,
        });
    }
    Ok(())
}

/// Map `ntdll.dll`, the read-only NLS tables, and the API-Set v6 schema into
/// `process`, and patch `ntdll!LdrSystemDllInitBlock` in `process`'s address space.
///
/// # Safety
/// `process` is a live non-System `EPROCESS` with an initialized `AddressSpace`.
pub unsafe fn map_into_process(process: *mut u8) -> Result<MappedSysDll, NTSTATUS> {
    ensure_loaded()?;
    // SAFETY: per the contract.
    let space =
        unsafe { super::process::address_space(process) }.ok_or(STATUS_INVALID_PARAMETER)?;

    let (ntdll_base, ntdll_size, exports, nls_base, oem_off, case_off, apiset_base) = {
        let guard = SYSDLL.read();
        let cached = guard.as_ref().ok_or(STATUS_UNSUCCESSFUL)?;
        // SAFETY: `cached.*_section` are live `SECTION_TYPE` objects held by `guard`.
        let (ntdll_base, ntdll_size, _) = unsafe {
            mm::view::map_view_in_space(
                cached.ntdll_section.body(),
                space,
                0,
                0,
                0,
                0,
                nk_mm::protect::PAGE_EXECUTE_WRITECOPY,
                USER_PROBE_VA,
            )
        }?;
        // SAFETY: as above.
        let (nls_base, _, _) = unsafe {
            mm::view::map_view_in_space(
                cached.nls_section.body(),
                space,
                0,
                0,
                0,
                0,
                PAGE_READONLY,
                USER_PROBE_VA,
            )
        }?;
        // SAFETY: as above.
        let (apiset_base, _, _) = unsafe {
            mm::view::map_view_in_space(
                cached.apiset_section.body(),
                space,
                0,
                0,
                0,
                0,
                PAGE_READONLY,
                USER_PROBE_VA,
            )
        }?;
        (
            ntdll_base,
            ntdll_size,
            cached.exports,
            nls_base,
            cached.oem_cp_off,
            cached.unicode_case_off,
            apiset_base,
        )
    };

    // Patch `ntdll!LdrSystemDllInitBlock` in the target process (triggers CoW on `.mrdata`).
    let rng = (crate::arch::counter() ^ 0xA5A5_5A5A_1234_5678) as u32 | 1;
    let init_block = PS_SYSTEM_DLL_INIT_BLOCK {
        Size: size_of::<PS_SYSTEM_DLL_INIT_BLOCK>() as u32,
        _pad0: 0,
        SystemDllWowRelocation: 0,
        SystemDllNativeRelocation: ntdll_base.wrapping_sub(exports.preferred_base),
        Wow64SharedInformation: [0; 16],
        RngData: rng,
        Flags: 0,
        MitigationOptionsMap: [0; 3],
        CfgBitMap: 0,
        CfgBitMapSize: 0,
        Wow64CfgBitMap: 0,
        Wow64CfgBitMapSize: 0,
        MitigationAuditOptionsMap: [0; 3],
    };
    let init_block_va = ntdll_base + u64::from(exports.ldr_system_dll_init_block);
    let mut apc_state = core::mem::MaybeUninit::<KAPC_STATE>::zeroed();
    // SAFETY: `process` is a live `EPROCESS`; `init_block_va` lies inside `ntdll.dll`'s `.mrdata`
    // (mapped WRITECOPY), and `mm::user::copy` fault-protects the write.
    let patch_res = unsafe {
        super::process::KeStackAttachProcess(process.cast(), apc_state.as_mut_ptr());
        let r = mm::user::copy(
            core::ptr::with_exposed_provenance_mut(init_block_va as usize),
            (&raw const init_block).cast::<u8>(),
            size_of::<PS_SYSTEM_DLL_INIT_BLOCK>(),
        );
        super::process::KeUnstackDetachProcess(apc_state.as_mut_ptr());
        r
    };
    if patch_res.is_err() {
        return Err(STATUS_ACCESS_VIOLATION);
    }

    Ok(MappedSysDll {
        ntdll_base,
        ntdll_size,
        ldr_initialize_thunk: ntdll_base + u64::from(exports.ldr_initialize_thunk),
        ki_user_apc_dispatcher: ntdll_base + u64::from(exports.ki_user_apc_dispatcher),
        ki_user_exception_dispatcher: ntdll_base + u64::from(exports.ki_user_exception_dispatcher),
        ki_user_callback_dispatcher: ntdll_base + u64::from(exports.ki_user_callback_dispatcher),
        rtl_user_thread_start: ntdll_base + u64::from(exports.rtl_user_thread_start),
        ansi_cp_va: nls_base,
        oem_cp_va: nls_base + oem_off,
        unicode_case_va: nls_base + case_off,
        apiset_va: apiset_base,
    })
}
