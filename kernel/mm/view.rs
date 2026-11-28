//! User-mode section objects and views: pagefile sections, file-backed data
//! sections (coherent with the cache manager via `ControlArea`), and PE32+
//! image sections (`SEC_IMAGE`) with deterministic base mapping and on-demand
//! relocation (`STATUS_IMAGE_NOT_AT_BASE`).

#![allow(non_snake_case)]

use super::fault::{self, Mode};
use super::pfn;
use super::section::{self, ControlArea, SectionRef};
use super::space::{AddressSpace, valid_user_pte};
use super::vm::{UserFault, resolve_target_process};
use super::{PAGE_SIZE, alloc_frames, free_frames, phys_to_virt};
use crate::arch;
use crate::ex::pushlock::PushLock;
use crate::io::file;
use crate::ob::{self, handle, object};
use crate::svc::capture;
use alloc::sync::Arc;
use alloc::vec;
use alloc::vec::Vec;
use core::ffi::c_void;
use core::sync::atomic::{AtomicU64, Ordering};
use nk_mm::protect::{
    MEM_LARGE_PAGES, MEM_TOP_DOWN, MM_PROT_EXECUTE_READ, MM_PROT_EXECUTE_WRITECOPY,
    MM_PROT_NOACCESS, MM_PROT_READONLY, MM_PROT_READWRITE, MM_PROT_WRITECOPY, PAGE_EXECUTE,
    PAGE_EXECUTE_READ, PAGE_EXECUTE_READWRITE, PAGE_EXECUTE_WRITECOPY, PAGE_NOACCESS,
    PAGE_READONLY, PAGE_READWRITE, PAGE_WRITECOPY, mm_break_cow, mm_is_cow, mm_to_user_hw,
    mm_to_win32, win32_to_mm,
};
use nk_mm::pt::Arch;
use nk_mm::pte::{Access, Proto, UserSwPte};
use nk_mm::reloc::apply_page_relocs;
use nk_mm::section::SUBSECTION_PAGES;
use nk_mm::vad::{ALLOC_GRANULARITY, MIN_USER_VA, USER_PROBE_VA, Vad, VadKind};
use nk_ntabi::io::{FILE_OBJECT, IO_STATUS_BLOCK};
use nk_ntabi::mm::{
    SEC_COMMIT, SEC_FILE, SEC_IMAGE, SEC_IMAGE_NO_EXECUTE, SEC_NOCACHE, SEC_PROTECTED_IMAGE,
    SEC_RESERVE, SECTION_BASIC_INFORMATION, SECTION_BASIC_INFORMATION_CLASS, SECTION_EXTEND_SIZE,
    SECTION_IMAGE_INFORMATION, SECTION_IMAGE_INFORMATION_CLASS, SECTION_MAP_EXECUTE,
    SECTION_MAP_READ, SECTION_MAP_WRITE, SECTION_QUERY, VIEW_SHARE, VIEW_UNMAP,
};
use nk_ntabi::ob::OBJECT_ATTRIBUTES;
use nk_ntabi::status::*;
use nk_ob::handles::Attributes;
use nk_pe::{DIR_BASERELOC, MACHINE_NATIVE, Pe, SCN_MEM_EXECUTE, SCN_MEM_READ, SCN_MEM_WRITE};

const PAGE_MASK: u64 = PAGE_SIZE as u64 - 1;
const PROCESS_VM_OPERATION: u32 = 0x0008;
const OBJ_INHERIT: u32 = 0x2;
const OBJ_PERMANENT: u32 = 0x10;
const OBJ_OPENIF: u32 = 0x80;
const SUBSECTION_BYTES: u64 = (SUBSECTION_PAGES * PAGE_SIZE) as u64;

/// Backing storage for an anonymous pagefile-backed section.
pub(super) struct PagefileBacking {
    /// Physical frame address per 4 KiB page (`0` = not yet allocated).
    frames: PushLock<Vec<u64>>,
    max_size: AtomicU64,
    protect: u32,
    alloc_attrs: u32,
}

impl Drop for PagefileBacking {
    fn drop(&mut self) {
        let mut frames = self.frames.lock();
        for pa in frames.iter_mut() {
            if *pa != 0 {
                free_frames(*pa, 1);
                *pa = 0;
            }
        }
    }
}

/// Backing metadata for a file-backed data section (the actual `ControlArea`
/// lives in `Section.ca`, shared with `Cc`).
pub(super) struct DataFileBacking {
    /// Keeps the cache-manager `SectionRef` (and thus `ControlArea`) alive.
    _section_ref: SectionRef,
    file_name: Vec<u16>,
    protect: u32,
    alloc_attrs: u32,
}

/// How one 4 KiB page of a `SEC_IMAGE` PE image is populated from `file_data`.
#[derive(Clone, Copy)]
struct ImagePageDesc {
    /// Source offset in `ImageBacking::file_data` (valid when `copy_len > 0`).
    file_off: u32,
    /// Number of bytes to copy from `file_off` (rest of the 4 KiB page is zero).
    copy_len: u16,
    /// Internal 5-bit `MM_PROT_*` protection for this page.
    mm_prot: u8,
}

/// Backing storage for a `SEC_IMAGE` PE32+ section.
pub(super) struct ImageBacking {
    info: SECTION_IMAGE_INFORMATION,
    preferred_base: u64,
    image_size: u64,
    alloc_attrs: u32,
    file_name: Vec<u16>,
    /// Raw PE file bytes (used for on-demand page fill and cross-page relocs).
    file_data: Vec<u8>,
    /// `.reloc` directory bytes (copied out of laid-out image range or raw section).
    relocs: Vec<u8>,
    /// Per-page descriptors (`image_size / PAGE_SIZE` entries).
    pages: Vec<ImagePageDesc>,
    /// Shared prototype frames for views mapped at `preferred_base` (`0` = not yet paged in).
    proto_frames: PushLock<Vec<u64>>,
}

impl ImageBacking {
    /// Fill `dst` (4096 bytes) with the un-relocated contents of image page `idx`.
    fn fill_page(&self, idx: usize, dst: &mut [u8; PAGE_SIZE]) {
        dst.fill(0);
        if let Some(desc) = self.pages.get(idx)
            && desc.copy_len > 0
        {
            let start = desc.file_off as usize;
            let len = usize::from(desc.copy_len);
            if let Some(src) = self.file_data.get(start..start + len) {
                dst[..len].copy_from_slice(src);
            }
        }
    }

    /// Read un-relocated image bytes at arbitrary `rva` (used for cross-page relocs).
    fn read_unrelocated(&self, rva: u32, out: &mut [u8]) -> bool {
        read_unrelocated_raw(&self.pages, &self.file_data, rva, out)
    }
}

/// Read un-relocated image bytes at arbitrary `rva` from raw page descriptors and file bytes.
fn read_unrelocated_raw(
    pages: &[ImagePageDesc],
    file_data: &[u8],
    rva: u32,
    out: &mut [u8],
) -> bool {
    let mut rem = out.len();
    let mut cur_rva = rva as usize;
    let mut dst_off = 0usize;
    while rem > 0 {
        let pg = cur_rva / PAGE_SIZE;
        let off = cur_rva % PAGE_SIZE;
        let chunk = rem.min(PAGE_SIZE - off);
        let Some(desc) = pages.get(pg) else {
            return false;
        };
        let copy_len = usize::from(desc.copy_len);
        for i in 0..chunk {
            let p_off = off + i;
            out[dst_off + i] = if p_off < copy_len {
                file_data
                    .get(desc.file_off as usize + p_off)
                    .copied()
                    .unwrap_or(0)
            } else {
                0
            };
        }
        rem -= chunk;
        cur_rva += chunk;
        dst_off += chunk;
    }
    true
}

impl Drop for ImageBacking {
    fn drop(&mut self) {
        let mut frames = self.proto_frames.lock();
        for pa in frames.iter_mut() {
            if *pa != 0 {
                free_frames(*pa, 1);
                *pa = 0;
            }
        }
    }
}

/// Extended section payload stored on `SECTION_TYPE` objects created for user mode.
pub(super) enum UserSection {
    Pagefile(Arc<PagefileBacking>),
    DataFile(DataFileBacking),
    Image(Arc<ImageBacking>),
}

impl UserSection {
    fn alloc_attrs(&self) -> u32 {
        match self {
            Self::Pagefile(p) => p.alloc_attrs,
            Self::DataFile(d) => d.alloc_attrs,
            Self::Image(i) => i.alloc_attrs,
        }
    }

    fn section_protect(&self) -> u32 {
        match self {
            Self::Pagefile(p) => p.protect,
            Self::DataFile(d) => d.protect,
            Self::Image(_) => PAGE_EXECUTE_WRITECOPY,
        }
    }

    fn is_image(&self) -> bool {
        matches!(self, Self::Image(_))
    }

    fn filename(&self) -> Option<&[u16]> {
        match self {
            Self::Pagefile(_) => None,
            Self::DataFile(d) if !d.file_name.is_empty() => Some(&d.file_name),
            Self::Image(i) if !i.file_name.is_empty() => Some(&i.file_name),
            _ => None,
        }
    }
}

/// Translate PE section characteristics (`SCN_MEM_*`) into NK's 5-bit `MM_PROT_*`.
/// Writable image sections start as copy-on-write (`WRITECOPY` / `EXECUTE_WRITECOPY`).
fn pe_chars_to_mm_prot(chars: u32, no_exec: bool) -> u8 {
    let w = (chars & SCN_MEM_WRITE) != 0;
    let x = !no_exec && (chars & SCN_MEM_EXECUTE) != 0;
    let r = (chars & SCN_MEM_READ) != 0;
    match (w, x, r) {
        (true, true, _) => MM_PROT_EXECUTE_WRITECOPY,
        (true, false, _) => MM_PROT_WRITECOPY,
        (false, true, _) => MM_PROT_EXECUTE_READ,
        (false, false, true) => MM_PROT_READONLY,
        (false, false, false) => MM_PROT_NOACCESS,
    }
}

/// Parse PE32+ image bytes into an [`ImageBacking`].
fn parse_image_backing(
    name: &[u16],
    file_data: Vec<u8>,
    alloc_attrs: u32,
) -> Result<Arc<ImageBacking>, NTSTATUS> {
    let pe = Pe::parse(&file_data).map_err(|_| STATUS_INVALID_IMAGE_FORMAT)?;
    pe.check_machine(MACHINE_NATIVE)
        .map_err(|_| STATUS_IMAGE_MACHINE_TYPE_MISMATCH)?;
    let h = pe.headers();
    let image_size = u64::from(h.size_of_image).next_multiple_of(PAGE_SIZE as u64);
    let npages = (image_size / PAGE_SIZE as u64) as usize;
    if npages == 0 || npages > 0x4_0000 {
        return Err(STATUS_INVALID_IMAGE_FORMAT);
    }
    let no_exec = (alloc_attrs & SEC_NOCACHE) != 0;

    let mut pages = vec![
        ImagePageDesc {
            file_off: 0,
            copy_len: 0,
            mm_prot: MM_PROT_NOACCESS,
        };
        npages
    ];

    // Headers occupy `[0, size_of_headers)` as read-only.
    let hdr_bytes = (h.size_of_headers as usize).min(file_data.len());
    let hdr_pages = hdr_bytes.div_ceil(PAGE_SIZE).min(npages);
    for (p, desc) in pages.iter_mut().enumerate().take(hdr_pages) {
        let off = p * PAGE_SIZE;
        let len = (hdr_bytes - off).min(PAGE_SIZE);
        desc.file_off = off as u32;
        desc.copy_len = len as u16;
        desc.mm_prot = MM_PROT_READONLY;
    }

    // Each PE section maps `[s.rva, s.rva + s.mem_size())`.
    for s in pe.sections() {
        let rva = s.rva as usize;
        let mem_sz = s.mem_size() as usize;
        let raw_sz = (s.raw_size as usize).min(mem_sz);
        let prot = pe_chars_to_mm_prot(s.characteristics, no_exec);
        let first_pg = rva / PAGE_SIZE;
        let end_pg = (rva + mem_sz).div_ceil(PAGE_SIZE).min(npages);
        for (pg, slot) in pages.iter_mut().enumerate().take(end_pg).skip(first_pg) {
            let pg_rva = pg * PAGE_SIZE;
            let rel = pg_rva.saturating_sub(rva);
            let copy_len = if rel < raw_sz {
                (raw_sz - rel).min(PAGE_SIZE)
            } else {
                0
            };
            let file_off = if copy_len > 0 {
                s.raw_off.saturating_add(rel as u32)
            } else {
                0
            };
            *slot = ImagePageDesc {
                file_off,
                copy_len: copy_len as u16,
                mm_prot: prot,
            };
        }
    }

    // Copy out `.reloc` directory bytes if present.
    let reloc_dir = h.dir(DIR_BASERELOC);
    let mut relocs = Vec::new();
    if reloc_dir.rva != 0 && reloc_dir.size != 0 {
        let mut buf = vec![0u8; reloc_dir.size as usize];
        if read_unrelocated_raw(&pages, &file_data, reloc_dir.rva, &mut buf) {
            relocs = buf;
        }
    }

    let info = build_image_info(&h, file_data.len() as u32);
    Ok(Arc::new(ImageBacking {
        info,
        preferred_base: h.image_base,
        image_size,
        alloc_attrs,
        file_name: name.to_vec(),
        file_data,
        relocs,
        pages,
        proto_frames: PushLock::new(vec![0u64; npages]),
    }))
}

fn build_image_info(h: &nk_pe::Headers, file_size: u32) -> SECTION_IMAGE_INFORMATION {
    SECTION_IMAGE_INFORMATION {
        TransferAddress: h.image_base.wrapping_add(u64::from(h.entry_rva)),
        ZeroBits: 0,
        _pad0: 0,
        MaximumStackSize: if h.size_of_stack_reserve != 0 {
            h.size_of_stack_reserve
        } else {
            0x10_0000
        },
        CommittedStackSize: if h.size_of_stack_commit != 0 {
            h.size_of_stack_commit
        } else {
            0x1_0000
        },
        SubSystemType: u32::from(h.subsystem),
        SubSystemMinorVersion: h.minor_subsystem_version,
        SubSystemMajorVersion: h.major_subsystem_version,
        MajorOperatingSystemVersion: h.major_os_version,
        MinorOperatingSystemVersion: h.minor_os_version,
        ImageCharacteristics: h.characteristics,
        DllCharacteristics: h.dll_characteristics,
        Machine: h.machine,
        ImageContainsCode: 1,
        ImageFlags: 0,
        LoaderFlags: h.loader_flags,
        ImageFileSize: file_size,
        CheckSum: h.checksum,
    }
}

/// Create a pagefile-backed `SECTION_TYPE` object for kernel helpers (NLS, API-set, etc.).
#[allow(dead_code)]
pub fn create_pagefile_section(
    max_size: u64,
    protect: u32,
    committed: bool,
) -> Result<object::ObRef, NTSTATUS> {
    create_pagefile_section_named(max_size, protect, committed, None)
}

/// Create a committed pagefile-backed `SECTION_TYPE` object pre-populated with
/// `bytes` (zero-padded to a page boundary). Used for shared read-only NLS and
/// API-set sections mapped into every user process.
#[allow(dead_code)]
pub fn create_pagefile_section_from_bytes(
    bytes: &[u8],
    protect: u32,
) -> Result<object::ObRef, NTSTATUS> {
    if bytes.is_empty() {
        return Err(STATUS_INVALID_PARAMETER);
    }
    if win32_to_mm(protect).is_none() {
        return Err(STATUS_INVALID_PAGE_PROTECTION);
    }
    let size = (bytes.len() as u64).next_multiple_of(PAGE_SIZE as u64);
    let npages = (size / PAGE_SIZE as u64) as usize;
    let mut frames = vec![0u64; npages];
    for (idx, slot) in frames.iter_mut().enumerate() {
        let Some(pa) = alloc_frames(1) else {
            for &pa in &frames[..idx] {
                if pa != 0 {
                    free_frames(pa, 1);
                }
            }
            return Err(STATUS_NO_MEMORY);
        };
        let off = idx * PAGE_SIZE;
        let len = bytes.len().saturating_sub(off).min(PAGE_SIZE);
        // SAFETY: `pa` is a freshly allocated physical frame accessible via the direct map.
        unsafe {
            let dst = phys_to_virt(pa);
            core::ptr::write_bytes(dst, 0, PAGE_SIZE);
            if len > 0 {
                core::ptr::copy_nonoverlapping(bytes.as_ptr().add(off), dst, len);
            }
        }
        *slot = pa;
    }
    let backing = Arc::new(PagefileBacking {
        frames: PushLock::new(frames),
        max_size: AtomicU64::new(size),
        protect,
        alloc_attrs: SEC_COMMIT,
    });
    // SAFETY: `ca` is null (pagefile section).
    unsafe {
        section::create_user_section(
            size,
            core::ptr::null_mut(),
            UserSection::Pagefile(backing),
            None,
        )
    }
}

fn create_pagefile_section_named(
    max_size: u64,
    protect: u32,
    committed: bool,
    leaf_name: Option<&[u16]>,
) -> Result<object::ObRef, NTSTATUS> {
    if max_size == 0 {
        return Err(STATUS_INVALID_PARAMETER);
    }
    if win32_to_mm(protect).is_none() {
        return Err(STATUS_INVALID_PAGE_PROTECTION);
    }
    let size = max_size.next_multiple_of(PAGE_SIZE as u64);
    let npages = (size / PAGE_SIZE as u64) as usize;
    let alloc_attrs = if committed { SEC_COMMIT } else { SEC_RESERVE };
    let backing = Arc::new(PagefileBacking {
        frames: PushLock::new(vec![0u64; npages]),
        max_size: AtomicU64::new(size),
        protect,
        alloc_attrs,
    });
    // SAFETY: `ca` is null (pagefile section).
    unsafe {
        section::create_user_section(
            size,
            core::ptr::null_mut(),
            UserSection::Pagefile(backing),
            leaf_name,
        )
    }
}

/// Create a `SEC_IMAGE` section directly from in-memory PE32+ bytes (e.g. boot
/// modules like `ntdll.dll` or self-test fixtures).
#[allow(dead_code)]
pub fn create_image_section_from_bytes(
    name: &[u16],
    bytes: &[u8],
) -> Result<object::ObRef, NTSTATUS> {
    let backing = parse_image_backing(name, bytes.to_vec(), SEC_IMAGE)?;
    let size = backing.image_size;
    // SAFETY: `ca` is null (image section owns its own `ImageBacking`).
    unsafe {
        section::create_user_section(
            size,
            core::ptr::null_mut(),
            UserSection::Image(backing),
            None,
        )
    }
}

/// Return the `SECTION_IMAGE_INFORMATION` of a `SEC_IMAGE` section object.
///
/// # Safety
/// `section_body` points to a live `SECTION_TYPE` object.
#[allow(dead_code)]
pub unsafe fn image_info(section_body: *const u8) -> Option<SECTION_IMAGE_INFORMATION> {
    // SAFETY: per the contract.
    match unsafe { section::user_section(section_body)? } {
        UserSection::Image(img) => Some(img.info),
        _ => None,
    }
}

/// Read the UTF-16 `FileName` stored inside a `FILE_OBJECT`, if any.
///
/// # Safety
/// `file` is a live `FILE_OBJECT`.
unsafe fn read_file_name(file: *const FILE_OBJECT) -> Vec<u16> {
    // SAFETY: per the contract.
    unsafe {
        let us = (*file).FileName;
        if us.Buffer.is_null() || us.Length == 0 {
            return Vec::new();
        }
        let count = usize::from(us.Length) / 2;
        core::slice::from_raw_parts(us.Buffer, count).to_vec()
    }
}

fn io_err_status(e: file::IoError) -> NTSTATUS {
    match e {
        file::IoError::NoMemory => STATUS_INSUFFICIENT_RESOURCES,
        file::IoError::Handle(s) | file::IoError::Refused(s) => s,
        file::IoError::NotCompleted { dispatch_status } => dispatch_status,
        file::IoError::StatusMismatch {
            dispatch_status, ..
        } => dispatch_status,
    }
}

/// Read the entire contents of an open file handle (`FileHandle`) via `io::file`.
fn read_entire_file(file_handle: u64) -> Result<Vec<u8>, NTSTATUS> {
    // FileStandardInformation (class 5): 24 bytes; EndOfFile is i64 at offset 8.
    let mut std_info = [0u8; 24];
    file::query_information(file_handle, 5, &mut std_info).map_err(io_err_status)?;
    let eof = i64::from_le_bytes(std_info[8..16].try_into().unwrap_or([0; 8]));
    if eof <= 0 || eof > 64 * 1024 * 1024 {
        return Err(STATUS_INVALID_IMAGE_FORMAT);
    }
    let total = eof as usize;
    let mut buf = vec![0u8; total];
    let mut off = 0usize;
    while off < total {
        let chunk = (total - off).min(64 * 1024);
        let res = file::read_at(file_handle, off as i64, &mut buf[off..off + chunk])
            .map_err(io_err_status)?;
        if res.information == 0 {
            break;
        }
        off += res.information;
    }
    buf.truncate(off);
    Ok(buf)
}

/// Read a file's `EndOfFile` size via `FileStandardInformation`.
fn query_file_size(file_handle: u64) -> Result<u64, NTSTATUS> {
    let mut std_info = [0u8; 24];
    file::query_information(file_handle, 5, &mut std_info).map_err(io_err_status)?;
    let eof = i64::from_le_bytes(std_info[8..16].try_into().unwrap_or([0; 8]));
    Ok(eof.max(0) as u64)
}

/// Adjust `ControlArea` view counts and subsection view counts when a user
/// data-file view is mapped (`delta = +1`) or unmapped (`delta = -1`).
fn adjust_data_view_counts(
    ca: *mut ControlArea,
    offset: u64,
    len: u64,
    writable: bool,
    mapping: bool,
) {
    if ca.is_null() || len == 0 {
        return;
    }
    let first_ss = (offset / SUBSECTION_BYTES) as usize;
    let last_ss = ((offset + len - 1) / SUBSECTION_BYTES) as usize;
    if mapping {
        for idx in first_ss..=last_ss {
            let mut spare = section::spare_subsection();
            {
                let g = pfn::lock();
                // SAFETY: `ca` is kept alive by the section object's `SectionRef`.
                let ca_ref = unsafe { &*ca };
                if let Some(ss) = section::subsection_or(&g, ca_ref, idx, &mut spare) {
                    // SAFETY: `ss` is valid under the PFN lock.
                    let ss_ref = unsafe { &*ss };
                    ss_ref.views.set(ss_ref.views.get() + 1);
                }
            }
            section::drop_spare(spare);
        }
        let _g = pfn::lock();
        // SAFETY: `ca` is alive via the section object.
        let ca_ref = unsafe { &*ca };
        ca_ref.mapped_views.set(ca_ref.mapped_views.get() + 1);
        ca_ref.user_refs.set(ca_ref.user_refs.get() + 1);
        if writable {
            ca_ref
                .writable_user_refs
                .set(ca_ref.writable_user_refs.get() + 1);
        }
    } else {
        {
            let g = pfn::lock();
            // SAFETY: `ca` is kept alive by the view's reference to the section.
            let ca_ref = unsafe { &*ca };
            for idx in first_ss..=last_ss {
                let ss = ca_ref.subsection(&g, idx);
                if !ss.is_null() {
                    // SAFETY: valid under PFN lock.
                    let ss_ref = unsafe { &*ss };
                    ss_ref.views.set(ss_ref.views.get().saturating_sub(1));
                    section::unused_subsection(&g, ss_ref);
                }
            }
            ca_ref
                .mapped_views
                .set(ca_ref.mapped_views.get().saturating_sub(1));
            ca_ref
                .user_refs
                .set(ca_ref.user_refs.get().saturating_sub(1));
            if writable {
                ca_ref
                    .writable_user_refs
                    .set(ca_ref.writable_user_refs.get().saturating_sub(1));
            }
            section::check(&g, ca_ref);
        }
        section::reap();
    }
}

/// Check whether `view_protect` is allowed by `section_protect`.
fn view_protect_compatible(section_protect: u32, view_protect: u32) -> bool {
    let sec_exec = matches!(
        section_protect & 0xFF,
        PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY
    );
    let sec_write = matches!(
        section_protect & 0xFF,
        PAGE_READWRITE | PAGE_EXECUTE_READWRITE
    );
    match view_protect & 0xFF {
        PAGE_NOACCESS | PAGE_READONLY | PAGE_WRITECOPY => true,
        PAGE_READWRITE => sec_write,
        PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_WRITECOPY => sec_exec,
        PAGE_EXECUTE_READWRITE => sec_exec && sec_write,
        _ => false,
    }
}

/// Map `section_body` into `space`, creating a `VadKind::Mapped` VAD and
/// populating `UserSwPte::Prototype` entries. Returns `(base, view_size, status)`
/// where `status` is `STATUS_IMAGE_NOT_AT_BASE` when a `SEC_IMAGE` view was
/// relocated away from its preferred `ImageBase`, else `STATUS_SUCCESS`.
///
/// # Safety
/// `section_body` is a live `SECTION_TYPE` object.
#[allow(clippy::too_many_arguments)]
pub unsafe fn map_view_in_space(
    section_body: *mut u8,
    space: &AddressSpace,
    req_base: u64,
    section_offset: u64,
    req_view_size: u64,
    alloc_type: u32,
    win32_protect: u32,
    max_va: u64,
) -> Result<(u64, u64, NTSTATUS), NTSTATUS> {
    // SAFETY: per the contract.
    let Some(user_sec) = (unsafe { section::user_section(section_body) }) else {
        return Err(STATUS_INVALID_HANDLE);
    };
    // SAFETY: per the contract.
    let sec_size = unsafe { section::section_size(section_body) };
    let is_image = user_sec.is_image();

    if !is_image {
        if win32_to_mm(win32_protect).is_none() {
            return Err(STATUS_INVALID_PAGE_PROTECTION);
        }
        if !view_protect_compatible(user_sec.section_protect(), win32_protect) {
            return Err(STATUS_SECTION_PROTECTION);
        }
        if !section_offset.is_multiple_of(ALLOC_GRANULARITY) {
            return Err(STATUS_MAPPED_ALIGNMENT);
        }
    } else if section_offset != 0 {
        return Err(STATUS_INVALID_PARAMETER_6);
    }

    if section_offset >= sec_size {
        return Err(STATUS_INVALID_VIEW_SIZE);
    }
    let max_view = sec_size - section_offset;
    let view_size = if req_view_size == 0 {
        max_view.next_multiple_of(PAGE_SIZE as u64)
    } else {
        let rounded = req_view_size.next_multiple_of(PAGE_SIZE as u64);
        if rounded > max_view.next_multiple_of(PAGE_SIZE as u64) {
            return Err(STATUS_INVALID_VIEW_SIZE);
        }
        rounded
    };

    let share_write = !is_image
        && matches!(
            win32_protect & 0xFF,
            PAGE_READWRITE | PAGE_EXECUTE_READWRITE
        );

    let mut inner = space.lock();
    let (base, status) = if is_image {
        let UserSection::Image(img) = user_sec else {
            unreachable!();
        };
        if req_base != 0 {
            let aligned = req_base & !(ALLOC_GRANULARITY - 1);
            if aligned < MIN_USER_VA
                || aligned
                    .checked_add(view_size)
                    .is_none_or(|e| e > USER_PROBE_VA)
                || inner.vads.overlaps(aligned, aligned + view_size)
            {
                return Err(STATUS_CONFLICTING_ADDRESSES);
            }
            let st = if aligned == img.preferred_base {
                STATUS_SUCCESS
            } else {
                STATUS_IMAGE_NOT_AT_BASE
            };
            (aligned, st)
        } else if img.preferred_base >= MIN_USER_VA
            && img
                .preferred_base
                .checked_add(view_size)
                .is_some_and(|e| e <= max_va && !inner.vads.overlaps(img.preferred_base, e))
        {
            // Deterministic base: prefer the PE image's own `ImageBase` when free!
            (img.preferred_base, STATUS_SUCCESS)
        } else {
            let top_down = (alloc_type & MEM_TOP_DOWN) != 0;
            let Some(found) =
                inner
                    .vads
                    .find_gap(view_size, ALLOC_GRANULARITY, top_down, MIN_USER_VA, max_va)
            else {
                return Err(STATUS_NO_MEMORY);
            };
            (found, STATUS_IMAGE_NOT_AT_BASE)
        }
    } else if req_base != 0 {
        let aligned = req_base & !(ALLOC_GRANULARITY - 1);
        if aligned < MIN_USER_VA
            || aligned
                .checked_add(view_size)
                .is_none_or(|e| e > USER_PROBE_VA)
            || inner.vads.overlaps(aligned, aligned + view_size)
        {
            return Err(STATUS_CONFLICTING_ADDRESSES);
        }
        (aligned, STATUS_SUCCESS)
    } else {
        let top_down = (alloc_type & MEM_TOP_DOWN) != 0;
        let Some(found) =
            inner
                .vads
                .find_gap(view_size, ALLOC_GRANULARITY, top_down, MIN_USER_VA, max_va)
        else {
            return Err(STATUS_NO_MEMORY);
        };
        (found, STATUS_SUCCESS)
    };

    let end = base + view_size;
    // Populate prototype software PTEs across the view.
    let proto_raw = UserSwPte::Prototype { proto_va: 0 }.encode();
    let mut va = base;
    while va < end {
        if space.write_pte(va, proto_raw).is_err() {
            let mut undo = base;
            while undo < va {
                let _ = space.clear_pte(undo);
                undo += PAGE_SIZE as u64;
            }
            return Err(STATUS_INSUFFICIENT_RESOURCES);
        }
        va += PAGE_SIZE as u64;
    }

    // Take an object reference on the section owned by this VAD (released in `unmap_vad`).
    // SAFETY: `section_body` is a live `SECTION_TYPE` object.
    unsafe { object::reference(section_body) };

    let vad = Vad {
        start: base,
        end,
        protect: if is_image {
            PAGE_EXECUTE_WRITECOPY
        } else {
            win32_protect
        },
        kind: VadKind::Mapped {
            section: section_body.addr(),
            offset: section_offset,
            is_image,
            share_write,
        },
        committed_pages: view_size / PAGE_SIZE as u64,
    };
    if inner.vads.insert(vad).is_err() {
        let mut undo = base;
        while undo < end {
            let _ = space.clear_pte(undo);
            undo += PAGE_SIZE as u64;
        }
        // SAFETY: dropping the reference we just took.
        unsafe { object::dereference(section_body) };
        return Err(STATUS_CONFLICTING_ADDRESSES);
    }
    drop(inner);

    // SAFETY: `section_body` is kept alive by the VAD's reference.
    let ca = unsafe { section::section_ca(section_body) };
    if !ca.is_null() {
        adjust_data_view_counts(ca, section_offset, view_size, share_write, true);
    }

    Ok((base, view_size, status))
}

/// Tear down a `VadKind::Mapped` VAD: unmap all pages, propagate dirty bits &
/// release PFN share counts for data-file views, free private CoW / relocated
/// frames, adjust `ControlArea` view counts, and drop the VAD's `Section` ref.
///
/// Caller has ALREADY removed `vad` from `space`'s `VadTree` (or is inside
/// `AddressSpace::destroy()`).
pub fn unmap_vad(space: &AddressSpace, vad: Vad) {
    let VadKind::Mapped {
        section: sec_addr,
        offset,
        is_image: _,
        share_write,
    } = vad.kind
    else {
        return;
    };
    let section_body = core::ptr::with_exposed_provenance_mut::<u8>(sec_addr);
    // SAFETY: the VAD held a reference to `section_body` until the end of this function.
    let user_sec = unsafe { section::user_section(section_body) };
    // SAFETY: as above.
    let ca = unsafe { section::section_ca(section_body) };
    let arch_pt = arch::pt_arch();
    let mut had_valid = false;

    match user_sec {
        Some(UserSection::Pagefile(pf)) => {
            let frames = pf.frames.lock();
            let mut va = vad.start;
            while va < vad.end {
                let old = space.clear_pte(va);
                if old != 0 && arch_pt.present(old) {
                    had_valid = true;
                    let pa = arch_pt.addr(old);
                    let idx = ((offset + (va - vad.start)) / PAGE_SIZE as u64) as usize;
                    let shared_pa = frames.get(idx).copied().unwrap_or(0);
                    if pa != shared_pa {
                        // Private CoW copy owned solely by this view.
                        free_frames(pa, 1);
                    }
                } else if old != 0
                    && !arch_pt.present(old)
                    && let UserSwPte::Transition { pfn, .. } = UserSwPte::decode(old)
                {
                    let pa = pfn * PAGE_SIZE as u64;
                    let idx = ((offset + (va - vad.start)) / PAGE_SIZE as u64) as usize;
                    let shared_pa = frames.get(idx).copied().unwrap_or(0);
                    if pa != shared_pa {
                        free_frames(pa, 1);
                    }
                }
                va += PAGE_SIZE as u64;
            }
        }
        Some(UserSection::Image(img)) => {
            let is_relocated = vad.start != img.preferred_base;
            let protos = img.proto_frames.lock();
            let mut va = vad.start;
            while va < vad.end {
                let old = space.clear_pte(va);
                if old != 0 && arch_pt.present(old) {
                    had_valid = true;
                    let pa = arch_pt.addr(old);
                    let idx = ((va - vad.start) / PAGE_SIZE as u64) as usize;
                    let shared_pa = if is_relocated {
                        0
                    } else {
                        protos.get(idx).copied().unwrap_or(0)
                    };
                    if pa != shared_pa {
                        // Relocated page or CoW private copy.
                        free_frames(pa, 1);
                    }
                } else if old != 0
                    && !arch_pt.present(old)
                    && let UserSwPte::Transition { pfn, .. } = UserSwPte::decode(old)
                {
                    let pa = pfn * PAGE_SIZE as u64;
                    let idx = ((va - vad.start) / PAGE_SIZE as u64) as usize;
                    let shared_pa = if is_relocated {
                        0
                    } else {
                        protos.get(idx).copied().unwrap_or(0)
                    };
                    if pa != shared_pa {
                        free_frames(pa, 1);
                    }
                }
                va += PAGE_SIZE as u64;
            }
        }
        Some(UserSection::DataFile(_)) => {
            let mut va = vad.start;
            while va < vad.end {
                let old = space.clear_pte(va);
                if old != 0 && arch_pt.present(old) {
                    had_valid = true;
                    let pa = arch_pt.addr(old);
                    let dirty = share_write && arch_pt.dirty(old);
                    release_data_page(ca, offset + (va - vad.start), pa, dirty);
                } else if old != 0
                    && !arch_pt.present(old)
                    && let UserSwPte::Transition { pfn, .. } = UserSwPte::decode(old)
                {
                    release_data_page(ca, offset + (va - vad.start), pfn * PAGE_SIZE as u64, false);
                }
                va += PAGE_SIZE as u64;
            }
        }
        None => {}
    }

    if had_valid && space.root() != 0 {
        arch::flush_tlb_range(vad.start, vad.pages() as usize);
    }

    if !ca.is_null() {
        adjust_data_view_counts(ca, offset, vad.len(), share_write, false);
    }

    // Drop the VAD's reference on the section object.
    // SAFETY: balanced against `object::reference(section_body)` in `map_view_in_space`.
    unsafe { object::dereference(section_body) };
}

/// Release a frame referenced by a data-file view: if it matches the section's
/// prototype frame, drop its PFN share count (and propagate `dirty`); otherwise
/// it was a private CoW copy so free it directly.
fn release_data_page(ca: *mut ControlArea, file_offset: u64, pa: u64, dirty: bool) {
    if ca.is_null() {
        free_frames(pa, 1);
        return;
    }
    let frame = pa / PAGE_SIZE as u64;
    let ss_idx = (file_offset / SUBSECTION_BYTES) as usize;
    let pg_idx = ((file_offset % SUBSECTION_BYTES) / PAGE_SIZE as u64) as usize;
    let is_shared = {
        let mut g = pfn::lock();
        // SAFETY: `ca` is alive via the VAD's section reference.
        let ca_ref = unsafe { &*ca };
        let ss = ca_ref.subsection(&g, ss_idx);
        let shared = if !ss.is_null() {
            // SAFETY: valid under PFN lock.
            let proto = unsafe { (*ss).protos[pg_idx].load(Ordering::Relaxed) };
            matches!(Proto::decode(proto), Proto::Valid(f) if f == frame)
        } else {
            false
        };
        if shared {
            let no_write = ca_ref.no_write();
            if let Err(e) = pfn::frames(&mut g).db.dereference(frame, no_write, dirty) {
                crate::kd::bugcheck(format_args!("mm: unmapping user data-file page: {}", e.0));
            }
        }
        shared
    };
    if !is_shared {
        free_frames(pa, 1);
    }
}

/// Called from `mm::vm` when a CoW write replaces `old_pa` inside a mapped VAD.
pub fn cow_released_frame(vad: Vad, page: u64, old_pa: u64) {
    let VadKind::Mapped {
        section: sec_addr,
        offset,
        ..
    } = vad.kind
    else {
        return;
    };
    let section_body = core::ptr::with_exposed_provenance_mut::<u8>(sec_addr);
    // SAFETY: `vad` holds a live reference to `section_body`.
    let ca = unsafe { section::section_ca(section_body) };
    if !ca.is_null() {
        release_data_page(ca, offset + (page - vad.start), old_pa, false);
    }
    // For Pagefile and Image sections, `old_pa` is either the shared prototype
    // frame (still owned by the section) or a relocated image page (if relocated,
    // free `old_pa`!).
    // SAFETY: `vad` holds a live reference to `section_body`.
    if let Some(UserSection::Image(img)) = (unsafe { section::user_section(section_body) })
        && vad.start != img.preferred_base
    {
        free_frames(old_pa, 1);
    }
}

/// Return the Win32 protection of a not-yet-faulted `UserSwPte::Prototype` page
/// inside a mapped VAD (for `NtQueryVirtualMemory`).
pub fn prototype_page_protect(vad: Vad, page: u64) -> u32 {
    let VadKind::Mapped {
        section: sec_addr, ..
    } = vad.kind
    else {
        return vad.protect;
    };
    let section_body = core::ptr::with_exposed_provenance::<u8>(sec_addr);
    // SAFETY: `vad` keeps `section_body` alive.
    match unsafe { section::user_section(section_body) } {
        Some(UserSection::Image(img)) => {
            let idx = ((page - vad.start) / PAGE_SIZE as u64) as usize;
            img.pages
                .get(idx)
                .map_or(PAGE_NOACCESS, |d| mm_to_win32(d.mm_prot))
        }
        _ => vad.protect,
    }
}

/// Return the UTF-16 mapped filename for a `VadKind::Mapped` VAD (for
/// `NtQueryVirtualMemory(MemoryMappedFilenameInformation)`).
pub fn mapped_filename(vad: Vad) -> Option<Vec<u16>> {
    let VadKind::Mapped {
        section: sec_addr, ..
    } = vad.kind
    else {
        return None;
    };
    let section_body = core::ptr::with_exposed_provenance::<u8>(sec_addr);
    // SAFETY: `vad` keeps `section_body` alive while caller holds `space.read()`.
    unsafe { section::user_section(section_body) }
        .and_then(|u| u.filename())
        .map(|s| s.to_vec())
}

/// Check if `access` is permitted by `mm_prot`.
fn access_ok(mm_prot: u8, access: Access) -> bool {
    match mm_prot {
        MM_PROT_READONLY => access == Access::Read,
        MM_PROT_READWRITE | MM_PROT_WRITECOPY => matches!(access, Access::Read | Access::Write),
        MM_PROT_EXECUTE_READ => matches!(access, Access::Read | Access::Execute),
        MM_PROT_EXECUTE_WRITECOPY | nk_mm::protect::MM_PROT_EXECUTE_READWRITE => true,
        _ => false,
    }
}

/// Resolve a page fault on a `UserSwPte::Prototype` entry inside a mapped VAD.
/// Called WITHOUT holding `space.lock()` so data-file paging I/O can block
/// freely at `PASSIVE_LEVEL`, then re-acquires `space.lock()` to install the PTE.
pub fn fault_mapped_page(space: &AddressSpace, vad: Vad, page: u64, access: Access) -> UserFault {
    let VadKind::Mapped {
        section: sec_addr,
        offset,
        is_image: _,
        share_write: _,
    } = vad.kind
    else {
        return UserFault::AccessViolation;
    };
    let section_body = core::ptr::with_exposed_provenance_mut::<u8>(sec_addr);
    // Take a temporary reference so `section_body` stays live even if another
    // thread unmaps the VAD concurrently while we do I/O.
    // SAFETY: caller verified `vad` was in `space` under `space.lock()`.
    let _hold = unsafe { object::ObRef::new(section_body) };
    // SAFETY: `_hold` keeps `section_body` alive.
    let Some(user_sec) = (unsafe { section::user_section(section_body) }) else {
        return UserFault::AccessViolation;
    };

    match user_sec {
        UserSection::Pagefile(pf) => {
            let Some(mm_prot) = win32_to_mm(vad.protect) else {
                return UserFault::AccessViolation;
            };
            if !access_ok(mm_prot, access) {
                return UserFault::AccessViolation;
            }
            let idx = ((offset + (page - vad.start)) / PAGE_SIZE as u64) as usize;
            let shared_pa = {
                let mut frames = pf.frames.lock();
                let Some(slot) = frames.get_mut(idx) else {
                    return UserFault::AccessViolation;
                };
                if *slot == 0 {
                    let Some(pa) = alloc_frames(1) else {
                        return UserFault::InPageError(STATUS_INSUFFICIENT_RESOURCES);
                    };
                    *slot = pa;
                }
                *slot
            };
            let (install_pa, eff_prot) = if access == Access::Write && mm_is_cow(mm_prot) {
                let Some(priv_pa) = alloc_frames(1) else {
                    return UserFault::InPageError(STATUS_INSUFFICIENT_RESOURCES);
                };
                // SAFETY: both frames are valid 4 KiB pages in the direct map.
                unsafe {
                    core::ptr::copy_nonoverlapping(
                        phys_to_virt(shared_pa),
                        phys_to_virt(priv_pa),
                        PAGE_SIZE,
                    );
                }
                (priv_pa, mm_break_cow(mm_prot))
            } else {
                (shared_pa, mm_prot)
            };
            let Some((hw_prot, cow)) = mm_to_user_hw(eff_prot) else {
                if install_pa != shared_pa {
                    free_frames(install_pa, 1);
                }
                return UserFault::AccessViolation;
            };
            let _guard = space.lock();
            if arch::pt_arch().present(space.read_pte(page)) {
                if install_pa != shared_pa {
                    free_frames(install_pa, 1);
                }
                return UserFault::Resolved;
            }
            if space
                .write_pte(page, valid_user_pte(install_pa, hw_prot, cow))
                .is_err()
            {
                if install_pa != shared_pa {
                    free_frames(install_pa, 1);
                }
                return UserFault::InPageError(STATUS_INSUFFICIENT_RESOURCES);
            }
            arch::mapping_sync();
            UserFault::Resolved
        }
        UserSection::Image(img) => {
            let idx = ((page - vad.start) / PAGE_SIZE as u64) as usize;
            let Some(&desc) = img.pages.get(idx) else {
                return UserFault::AccessViolation;
            };
            let mm_prot = desc.mm_prot;
            if !access_ok(mm_prot, access) {
                return UserFault::AccessViolation;
            }
            let delta = vad.start.wrapping_sub(img.preferred_base);
            let is_relocated = delta != 0;

            let (install_pa, owned_priv, eff_prot) = if is_relocated {
                let Some(pa) = alloc_frames(1) else {
                    return UserFault::InPageError(STATUS_INSUFFICIENT_RESOURCES);
                };
                // SAFETY: `pa` is our fresh 4 KiB frame in the direct map.
                let page_buf = unsafe { &mut *phys_to_virt(pa).cast::<[u8; PAGE_SIZE]>() };
                img.fill_page(idx, page_buf);
                let page_rva = (idx * PAGE_SIZE) as u32;
                if apply_page_relocs(&img.relocs, page_rva, delta, page_buf, |rva, dst| {
                    img.read_unrelocated(rva, dst)
                })
                .is_err()
                {
                    free_frames(pa, 1);
                    return UserFault::InPageError(STATUS_INVALID_IMAGE_FORMAT);
                }
                let eff = if access == Access::Write && mm_is_cow(mm_prot) {
                    mm_break_cow(mm_prot)
                } else {
                    mm_prot
                };
                (pa, true, eff)
            } else {
                // Preferred base: share prototype frames across processes!
                let proto_pa = {
                    let mut protos = img.proto_frames.lock();
                    let Some(slot) = protos.get_mut(idx) else {
                        return UserFault::AccessViolation;
                    };
                    if *slot == 0 {
                        let Some(pa) = alloc_frames(1) else {
                            return UserFault::InPageError(STATUS_INSUFFICIENT_RESOURCES);
                        };
                        // SAFETY: fresh frame in the direct map.
                        let page_buf = unsafe { &mut *phys_to_virt(pa).cast::<[u8; PAGE_SIZE]>() };
                        img.fill_page(idx, page_buf);
                        *slot = pa;
                    }
                    *slot
                };
                if access == Access::Write && mm_is_cow(mm_prot) {
                    let Some(priv_pa) = alloc_frames(1) else {
                        return UserFault::InPageError(STATUS_INSUFFICIENT_RESOURCES);
                    };
                    // SAFETY: both frames are valid 4 KiB pages in the direct map.
                    unsafe {
                        core::ptr::copy_nonoverlapping(
                            phys_to_virt(proto_pa),
                            phys_to_virt(priv_pa),
                            PAGE_SIZE,
                        );
                    }
                    (priv_pa, true, mm_break_cow(mm_prot))
                } else {
                    (proto_pa, false, mm_prot)
                }
            };

            let Some((hw_prot, cow)) = mm_to_user_hw(eff_prot) else {
                if owned_priv {
                    free_frames(install_pa, 1);
                }
                return UserFault::AccessViolation;
            };
            let _guard = space.lock();
            if arch::pt_arch().present(space.read_pte(page)) {
                if owned_priv {
                    free_frames(install_pa, 1);
                }
                return UserFault::Resolved;
            }
            if space
                .write_pte(page, valid_user_pte(install_pa, hw_prot, cow))
                .is_err()
            {
                if owned_priv {
                    free_frames(install_pa, 1);
                }
                return UserFault::InPageError(STATUS_INSUFFICIENT_RESOURCES);
            }
            arch::mapping_sync();
            UserFault::Resolved
        }
        UserSection::DataFile(_) => {
            let Some(mm_prot) = win32_to_mm(vad.protect) else {
                return UserFault::AccessViolation;
            };
            if !access_ok(mm_prot, access) {
                return UserFault::AccessViolation;
            }
            // SAFETY: `_hold` keeps `section_body` (and its `ControlArea`) alive.
            let ca = unsafe { section::section_ca(section_body) };
            if ca.is_null() {
                return UserFault::AccessViolation;
            }
            let file_offset = offset + (page - vad.start);
            let ss_idx = (file_offset / SUBSECTION_BYTES) as usize;
            let pg_idx = ((file_offset % SUBSECTION_BYTES) / PAGE_SIZE as u64) as usize;

            let ss = {
                let mut spare = section::spare_subsection();
                let found = {
                    let g = pfn::lock();
                    // SAFETY: `ca` is live via `_hold`.
                    section::subsection_or(&g, unsafe { &*ca }, ss_idx, &mut spare)
                };
                section::drop_spare(spare);
                let Some(ss) = found else {
                    return UserFault::InPageError(STATUS_INSUFFICIENT_RESOURCES);
                };
                ss
            };

            // Bring the file page into memory via the shared PFN / `mm::fault::resolve` path!
            if let Err(st) = fault::resolve(ss, pg_idx, None, Mode::FaultIn) {
                return UserFault::InPageError(st);
            }

            // Pin a share count on the resident prototype frame under the PFN lock.
            let frame_opt = {
                let mut g = pfn::lock();
                // SAFETY: `ss` is kept alive by the view's subsection ref.
                let proto = unsafe { &(*ss).protos[pg_idx] };
                match Proto::decode(proto.load(Ordering::Relaxed)) {
                    Proto::Valid(frame) | Proto::Transition(frame) => {
                        match pfn::frames(&mut g).db.share(frame) {
                            Ok(_) => {
                                proto.store(Proto::Valid(frame).encode(), Ordering::Relaxed);
                                Some(frame)
                            }
                            Err(_) => None,
                        }
                    }
                    _ => None,
                }
            };
            let Some(frame) = frame_opt else {
                return UserFault::InPageError(STATUS_IN_PAGE_ERROR);
            };
            let shared_pa = frame * PAGE_SIZE as u64;

            let (install_pa, eff_prot, used_shared) =
                if access == Access::Write && mm_is_cow(mm_prot) {
                    let Some(priv_pa) = alloc_frames(1) else {
                        release_data_page(ca, file_offset, shared_pa, false);
                        return UserFault::InPageError(STATUS_INSUFFICIENT_RESOURCES);
                    };
                    // SAFETY: both frames are valid 4 KiB pages in the direct map.
                    unsafe {
                        core::ptr::copy_nonoverlapping(
                            phys_to_virt(shared_pa),
                            phys_to_virt(priv_pa),
                            PAGE_SIZE,
                        );
                    }
                    release_data_page(ca, file_offset, shared_pa, false);
                    (priv_pa, mm_break_cow(mm_prot), false)
                } else {
                    (shared_pa, mm_prot, true)
                };

            let Some((hw_prot, cow)) = mm_to_user_hw(eff_prot) else {
                if used_shared {
                    release_data_page(ca, file_offset, shared_pa, false);
                } else {
                    free_frames(install_pa, 1);
                }
                return UserFault::AccessViolation;
            };

            let _guard = space.lock();
            if arch::pt_arch().present(space.read_pte(page)) {
                if used_shared {
                    release_data_page(ca, file_offset, shared_pa, false);
                } else {
                    free_frames(install_pa, 1);
                }
                return UserFault::Resolved;
            }
            if space
                .write_pte(page, valid_user_pte(install_pa, hw_prot, cow))
                .is_err()
            {
                if used_shared {
                    release_data_page(ca, file_offset, shared_pa, false);
                } else {
                    free_frames(install_pa, 1);
                }
                return UserFault::InPageError(STATUS_INSUFFICIENT_RESOURCES);
            }
            arch::mapping_sync();
            UserFault::Resolved
        }
    }
}

/// [`NtCreateSection`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-zwcreatesection).
///
/// # Safety
/// Pointer parameters must satisfy `PreviousMode`.
pub unsafe extern "C" fn NtCreateSection(
    section_handle: *mut *mut c_void,
    desired_access: u32,
    object_attributes: *const OBJECT_ATTRIBUTES,
    maximum_size: *const i64,
    section_page_protection: u32,
    allocation_attributes: u32,
    file_handle: *mut c_void,
) -> NTSTATUS {
    let mode = capture::mode();
    let max_size_opt = if maximum_size.is_null() {
        None
    } else {
        // SAFETY: per the contract; `capture::read` probes user pointers.
        match unsafe { capture::read(maximum_size, mode) } {
            Ok(v) if v < 0 => return STATUS_INVALID_PARAMETER_4,
            Ok(v) => Some(v as u64),
            Err(st) => return st,
        }
    };
    // SAFETY: per the contract; `capture_object_attributes` probes user pointers.
    let oa = match unsafe { capture::capture_object_attributes(object_attributes, mode) } {
        Ok(oa) => oa,
        Err(st) => return st,
    };

    let valid_alloc = SEC_COMMIT
        | SEC_RESERVE
        | SEC_IMAGE
        | SEC_NOCACHE
        | SEC_FILE
        | SEC_PROTECTED_IMAGE
        | MEM_LARGE_PAGES;
    if (allocation_attributes & !valid_alloc) != 0 {
        return STATUS_INVALID_PARAMETER_6;
    }
    let is_image = (allocation_attributes & SEC_IMAGE) != 0
        || (allocation_attributes & SEC_IMAGE_NO_EXECUTE) == SEC_IMAGE_NO_EXECUTE;

    let (root, name, attrs) = match oa {
        Some(oa) => (oa.root, oa.name.unwrap_or_default(), oa.attributes),
        None => (core::ptr::null_mut(), Vec::new(), 0),
    };

    // Resolve optional namespace root directory before allocating the section.
    let ns_root = if !name.is_empty() {
        match ob::resolve_namespace_root(root, false, mode) {
            Ok(r) => r,
            Err(st) => return st,
        }
    } else {
        None
    };

    let leaf_name = (!name.is_empty()).then(|| ob::leaf(&name));
    let sec_ref: object::ObRef = if file_handle.is_null() {
        if is_image {
            return STATUS_INVALID_FILE_FOR_SECTION;
        }
        let Some(sz) = max_size_opt.filter(|&s| s > 0) else {
            return STATUS_INVALID_PARAMETER_4;
        };
        let committed = (allocation_attributes & SEC_RESERVE) == 0;
        match create_pagefile_section_named(sz, section_page_protection, committed, leaf_name) {
            Ok(r) => r,
            Err(st) => return st,
        }
    } else {
        let fh = file_handle.addr() as u64;
        let (file_ob, _) = match handle::reference_for(
            fh,
            Some(&raw const object::FILE_TYPE),
            0,
            capture::handle_mode(mode),
        ) {
            Ok(v) => v,
            Err(st) => return st,
        };
        let file_obj = file_ob.body().cast::<FILE_OBJECT>();
        // SAFETY: `file_ob` keeps `file_obj` alive.
        let fname = unsafe { read_file_name(file_obj) };
        if is_image {
            let bytes = match read_entire_file(fh) {
                Ok(b) => b,
                Err(st) => return st,
            };
            let backing = match parse_image_backing(&fname, bytes, allocation_attributes) {
                Ok(b) => b,
                Err(st) => return st,
            };
            let size = backing.image_size;
            // SAFETY: image section has no data `ControlArea`.
            match unsafe {
                section::create_user_section(
                    size,
                    core::ptr::null_mut(),
                    UserSection::Image(backing),
                    leaf_name,
                )
            } {
                Ok(r) => r,
                Err(st) => return st,
            }
        } else {
            if win32_to_mm(section_page_protection).is_none() {
                return STATUS_INVALID_PAGE_PROTECTION;
            }
            let file_size = match query_file_size(fh) {
                Ok(sz) => sz,
                Err(st) => return st,
            };
            let req_size = max_size_opt.unwrap_or(0);
            let eff_size = if req_size > 0 { req_size } else { file_size };
            if eff_size == 0 {
                return STATUS_MAPPED_FILE_SIZE_ZERO;
            }
            let cm_sec = match section::create_cache_manager_section(file_obj, eff_size) {
                Ok(s) => s,
                Err(st) => return st,
            };
            let ca = cm_sec.ca();
            // Bump `ca.section_refs` for our user `Section` object (in addition
            // to `cm_sec`, which lives inside `DataFileBacking`).
            {
                let _g = pfn::lock();
                // SAFETY: `cm_sec` keeps `ca` alive.
                let ca_ref = unsafe { &*ca };
                ca_ref.section_refs.set(ca_ref.section_refs.get() + 1);
            }
            let backing = DataFileBacking {
                _section_ref: cm_sec,
                file_name: fname,
                protect: section_page_protection,
                alloc_attrs: allocation_attributes | SEC_FILE,
            };
            // SAFETY: `ca.section_refs` was incremented above for this object.
            match unsafe {
                section::create_user_section(
                    eff_size.next_multiple_of(PAGE_SIZE as u64),
                    ca,
                    UserSection::DataFile(backing),
                    leaf_name,
                )
            } {
                Ok(r) => r,
                Err(st) => return st,
            }
        }
    };

    // Enter into OB namespace if named.
    let (final_ob, existed) = if !name.is_empty() {
        let dir = ns_root.as_ref().map(object::ObRef::body);
        // SAFETY: `sec_ref` is a live `SECTION_TYPE` object created with `leaf_name`.
        match unsafe {
            ob::insert_named(
                dir,
                &name,
                sec_ref.body(),
                &object::SECTION_TYPE,
                attrs & OBJ_PERMANENT != 0,
                attrs & OBJ_OPENIF != 0,
            )
        } {
            Ok((existing, true)) => {
                // SAFETY: `existing` has a new reference returned by `insert_named`.
                (unsafe { object::ObRef::adopt(existing) }, true)
            }
            Ok((_, false)) => (sec_ref, false),
            Err(st) => return st,
        }
    } else {
        (sec_ref, false)
    };
    drop(ns_root);

    let kernel_handle = !capture::is_user(mode);
    // SAFETY: `final_ob` keeps the section alive while opening the handle.
    let opened = unsafe {
        handle::open_with(
            final_ob.body(),
            desired_access,
            Attributes {
                inherit: attrs & OBJ_INHERIT != 0,
                protect_from_close: false,
            },
            kernel_handle,
        )
    };
    let h = match opened {
        Ok(h) => h,
        Err(st) => return st,
    };
    // SAFETY: per the contract; `capture::write` probes user pointers.
    if let Err(st) = unsafe { capture::write(section_handle, h as *mut c_void, mode) } {
        let _ = handle::close_for(h, capture::handle_mode(mode));
        return st;
    }
    if existed {
        STATUS_OBJECT_NAME_EXISTS
    } else {
        STATUS_SUCCESS
    }
}

/// [`NtOpenSection`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-zwopensection).
///
/// # Safety
/// Pointer parameters must satisfy `PreviousMode`.
pub unsafe extern "C" fn NtOpenSection(
    section_handle: *mut *mut c_void,
    desired_access: u32,
    object_attributes: *const OBJECT_ATTRIBUTES,
) -> NTSTATUS {
    let mode = capture::mode();
    // SAFETY: per the contract; `capture_object_attributes` probes user pointers.
    let Some(oa) = (match unsafe { capture::capture_object_attributes(object_attributes, mode) } {
        Ok(oa) => oa,
        Err(st) => return st,
    }) else {
        return STATUS_INVALID_PARAMETER;
    };
    let name = oa.name.unwrap_or_default();
    if name.is_empty() {
        return STATUS_OBJECT_NAME_INVALID;
    }
    // SAFETY: `parse_context` is null for section opens.
    let (found, granted) = match unsafe {
        ob::open_by_name(
            oa.root,
            &name,
            oa.attributes,
            Some(&object::SECTION_TYPE),
            desired_access,
            mode,
            core::ptr::null_mut(),
        )
    } {
        Ok(res) => res,
        Err(st) => return st,
    };
    let kernel_handle = !capture::is_user(mode);
    // SAFETY: `found` keeps the section alive while opening the handle.
    let h = match unsafe {
        handle::open_with(
            found.body(),
            granted,
            Attributes {
                inherit: oa.attributes & OBJ_INHERIT != 0,
                protect_from_close: false,
            },
            kernel_handle,
        )
    } {
        Ok(h) => h,
        Err(st) => return st,
    };
    // SAFETY: per the contract; `capture::write` probes user pointers.
    if let Err(st) = unsafe { capture::write(section_handle, h as *mut c_void, mode) } {
        let _ = handle::close_for(h, capture::handle_mode(mode));
        return st;
    }
    STATUS_SUCCESS
}

/// [`NtQuerySection`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-ntquerysection).
///
/// # Safety
/// Output buffer and `return_length` must satisfy `PreviousMode`.
pub unsafe extern "C" fn NtQuerySection(
    section_handle: *mut c_void,
    section_information_class: u32,
    section_information: *mut c_void,
    section_information_length: usize,
    return_length: *mut usize,
) -> NTSTATUS {
    let mode = capture::mode();
    let (sec_ob, _) = match handle::reference_for(
        section_handle.addr() as u64,
        Some(&raw const object::SECTION_TYPE),
        SECTION_QUERY,
        capture::handle_mode(mode),
    ) {
        Ok(v) => v,
        Err(st) => return st,
    };
    let body = sec_ob.body();
    // SAFETY: `sec_ob` keeps `body` alive.
    let Some(user_sec) = (unsafe { section::user_section(body) }) else {
        return STATUS_INVALID_HANDLE;
    };

    match section_information_class {
        SECTION_BASIC_INFORMATION_CLASS => {
            let needed = size_of::<SECTION_BASIC_INFORMATION>();
            if section_information_length < needed {
                if !return_length.is_null() {
                    // SAFETY: per the contract; `capture::write` probes user pointers.
                    let _ = unsafe { capture::write(return_length, needed, mode) };
                }
                return STATUS_INFO_LENGTH_MISMATCH;
            }
            // SAFETY: `sec_ob` keeps `body` alive.
            let size = unsafe { section::section_size(body) };
            let info = SECTION_BASIC_INFORMATION {
                BaseAddress: match user_sec {
                    UserSection::Image(img) => img.preferred_base,
                    _ => 0,
                },
                AllocationAttributes: user_sec.alloc_attrs(),
                _pad0: 0,
                MaximumSize: size as i64,
            };
            // SAFETY: per the contract; `capture::write` probes user pointers.
            if let Err(st) = unsafe {
                capture::write(
                    section_information.cast::<SECTION_BASIC_INFORMATION>(),
                    info,
                    mode,
                )
            } {
                return st;
            }
            if !return_length.is_null() {
                // SAFETY: as above.
                if let Err(st) = unsafe { capture::write(return_length, needed, mode) } {
                    return st;
                }
            }
            STATUS_SUCCESS
        }
        SECTION_IMAGE_INFORMATION_CLASS => {
            let UserSection::Image(img) = user_sec else {
                return STATUS_SECTION_NOT_IMAGE;
            };
            let needed = size_of::<SECTION_IMAGE_INFORMATION>();
            if section_information_length < needed {
                if !return_length.is_null() {
                    // SAFETY: per the contract; `capture::write` probes user pointers.
                    let _ = unsafe { capture::write(return_length, needed, mode) };
                }
                return STATUS_INFO_LENGTH_MISMATCH;
            }
            // SAFETY: per the contract; `capture::write` probes user pointers.
            if let Err(st) = unsafe {
                capture::write(
                    section_information.cast::<SECTION_IMAGE_INFORMATION>(),
                    img.info,
                    mode,
                )
            } {
                return st;
            }
            if !return_length.is_null() {
                // SAFETY: as above.
                if let Err(st) = unsafe { capture::write(return_length, needed, mode) } {
                    return st;
                }
            }
            STATUS_SUCCESS
        }
        _ => STATUS_INVALID_INFO_CLASS,
    }
}

/// [`NtMapViewOfSection`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-zwmapviewofsection).
///
/// # Safety
/// Pointer parameters must satisfy `PreviousMode`.
#[allow(clippy::too_many_arguments)]
pub unsafe extern "C" fn NtMapViewOfSection(
    section_handle: *mut c_void,
    process_handle: *mut c_void,
    base_address: *mut *mut c_void,
    zero_bits: usize,
    _commit_size: usize,
    section_offset: *mut i64,
    view_size: *mut usize,
    inherit_disposition: u32,
    allocation_type: u32,
    win32_protect: u32,
) -> NTSTATUS {
    let mode = capture::mode();
    if inherit_disposition != VIEW_SHARE && inherit_disposition != VIEW_UNMAP {
        return STATUS_INVALID_PARAMETER_8;
    }
    // SAFETY: per the contract; `capture::read` probes user pointers.
    let req_base = match unsafe { capture::read(base_address, mode) } {
        Ok(p) => p.addr() as u64,
        Err(st) => return st,
    };
    // SAFETY: as above.
    let req_view_size = match unsafe { capture::read(view_size, mode) } {
        Ok(s) => s as u64,
        Err(st) => return st,
    };
    let req_offset = if section_offset.is_null() {
        0u64
    } else {
        // SAFETY: as above.
        match unsafe { capture::read(section_offset, mode) } {
            Ok(v) if v < 0 => return STATUS_INVALID_PARAMETER_6,
            Ok(v) => v as u64,
            Err(st) => return st,
        }
    };
    let max_va = match super::vm::zero_bits_ceiling(zero_bits) {
        Ok(v) => v,
        Err(st) => return st,
    };

    let req_access = match win32_protect & 0xFF {
        PAGE_READWRITE => SECTION_MAP_READ | SECTION_MAP_WRITE,
        PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_WRITECOPY => {
            SECTION_MAP_READ | SECTION_MAP_EXECUTE
        }
        PAGE_EXECUTE_READWRITE => SECTION_MAP_READ | SECTION_MAP_WRITE | SECTION_MAP_EXECUTE,
        _ => SECTION_MAP_READ,
    };
    let (sec_ob, _) = match handle::reference_for(
        section_handle.addr() as u64,
        Some(&raw const object::SECTION_TYPE),
        req_access,
        capture::handle_mode(mode),
    ) {
        Ok(v) => v,
        Err(st) => return st,
    };
    let target = match resolve_target_process(process_handle, PROCESS_VM_OPERATION, mode) {
        Ok(t) => t,
        Err(st) => return st,
    };
    let space = match target.space() {
        Ok(s) => s,
        Err(st) => return st,
    };

    // SAFETY: `sec_ob` keeps the section alive.
    let (out_base, out_size, status) = match unsafe {
        map_view_in_space(
            sec_ob.body(),
            space,
            req_base,
            req_offset,
            req_view_size,
            allocation_type,
            win32_protect,
            max_va,
        )
    } {
        Ok(v) => v,
        Err(st) => return st,
    };

    // SAFETY: per the contract; `capture::write` probes user pointers.
    if let Err(st) = unsafe {
        capture::write(
            base_address,
            core::ptr::with_exposed_provenance_mut(out_base as usize),
            mode,
        )
    } {
        return st;
    }
    // SAFETY: as above.
    if let Err(st) = unsafe { capture::write(view_size, out_size as usize, mode) } {
        return st;
    }
    if !section_offset.is_null() {
        // SAFETY: as above.
        let _ = unsafe { capture::write(section_offset, req_offset as i64, mode) };
    }
    status
}

/// [`NtUnmapViewOfSection`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-zwunmapviewofsection).
pub extern "C" fn NtUnmapViewOfSection(
    process_handle: *mut c_void,
    base_address: *mut c_void,
) -> NTSTATUS {
    NtUnmapViewOfSectionEx(process_handle, base_address, 0)
}

/// [`NtUnmapViewOfSectionEx`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-zwunmapviewofsection).
pub extern "C" fn NtUnmapViewOfSectionEx(
    process_handle: *mut c_void,
    base_address: *mut c_void,
    _flags: u32,
) -> NTSTATUS {
    let mode = capture::mode();
    let va = (base_address.addr() as u64) & !PAGE_MASK;
    let target = match resolve_target_process(process_handle, PROCESS_VM_OPERATION, mode) {
        Ok(t) => t,
        Err(st) => return st,
    };
    let space = match target.space() {
        Ok(s) => s,
        Err(st) => return st,
    };
    let vad = {
        let mut inner = space.lock();
        let Some(found) = inner.vads.find_containing(va).copied() else {
            return STATUS_NOT_MAPPED_VIEW;
        };
        if !matches!(found.kind, VadKind::Mapped { .. }) {
            return STATUS_NOT_MAPPED_VIEW;
        }
        inner.vads.remove(found.start);
        found
    };
    unmap_vad(space, vad);
    STATUS_SUCCESS
}

/// [`NtFlushVirtualMemory`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-zwflushvirtualmemory):
/// propagate hardware dirty bits from user PTEs into the PFN database and flush
/// mapped file ranges through `mm::flush`.
///
/// # Safety
/// Pointer parameters must satisfy `PreviousMode`.
pub unsafe extern "C" fn NtFlushVirtualMemory(
    process_handle: *mut c_void,
    base_address: *mut *mut c_void,
    region_size: *mut usize,
    io_status: *mut IO_STATUS_BLOCK,
) -> NTSTATUS {
    let mode = capture::mode();
    // SAFETY: per the contract; `capture::read` probes user pointers.
    let req_base = match unsafe { capture::read(base_address, mode) } {
        Ok(p) => p.addr() as u64,
        Err(st) => return st,
    };
    // SAFETY: as above.
    let req_size = match unsafe { capture::read(region_size, mode) } {
        Ok(s) => s as u64,
        Err(st) => return st,
    };
    let target = match resolve_target_process(process_handle, PROCESS_VM_OPERATION, mode) {
        Ok(t) => t,
        Err(st) => return st,
    };
    let space = match target.space() {
        Ok(s) => s,
        Err(st) => return st,
    };
    let start = req_base & !PAGE_MASK;
    let (flush_start, flush_len, ca_and_off) = {
        let inner = space.lock();
        let Some(vad) = inner.vads.find_containing(start).copied() else {
            return STATUS_NOT_MAPPED_VIEW;
        };
        let end = if req_size == 0 {
            vad.end
        } else {
            (req_base.saturating_add(req_size))
                .next_multiple_of(PAGE_SIZE as u64)
                .min(vad.end)
        };
        let ca_info = if let VadKind::Mapped {
            section: sec_addr,
            offset,
            share_write: true,
            ..
        } = vad.kind
        {
            let sec_body = core::ptr::with_exposed_provenance_mut::<u8>(sec_addr);
            // SAFETY: `vad` keeps `sec_body` alive under `space.lock()`.
            let ca = unsafe { section::section_ca(sec_body) };
            (!ca.is_null()).then(|| {
                // Transfer hardware dirty bits to PFN database and clear hardware dirty bit.
                let arch_pt = arch::pt_arch();
                let mut va = start;
                while va < end {
                    let pte = space.read_pte(va);
                    if arch_pt.present(pte) && arch_pt.dirty(pte) {
                        let frame = arch_pt.addr(pte) / PAGE_SIZE as u64;
                        let _ = space.write_pte(va, arch_pt.clean(pte));
                        let mut g = pfn::lock();
                        pfn::frames(&mut g).db.get_mut(frame).flags |= nk_mm::pfn::flag::MODIFIED;
                    }
                    va += PAGE_SIZE as u64;
                }
                arch::flush_tlb_range(start, ((end - start) / PAGE_SIZE as u64) as usize);
                // SAFETY: `ca` is live while `sec_body` is referenced.
                let sop = unsafe { (*ca).sop };
                (sop, offset + (start - vad.start))
            })
        } else {
            None
        };
        (start, end - start, ca_info)
    };

    let iosb = if let Some((sop, file_off)) = ca_and_off {
        super::flush::flush_section(sop, Some((file_off, flush_len as u32)), None)
    } else {
        IO_STATUS_BLOCK {
            Status: STATUS_SUCCESS,
            Information: flush_len as usize,
        }
    };

    // SAFETY: per the contract; `capture::write` probes user pointers.
    let _ = unsafe {
        capture::write(
            base_address,
            core::ptr::with_exposed_provenance_mut(flush_start as usize),
            mode,
        )
    };
    // SAFETY: as above.
    let _ = unsafe { capture::write(region_size, flush_len as usize, mode) };
    if !io_status.is_null() {
        // SAFETY: as above.
        let _ = unsafe { capture::write(io_status, iosb, mode) };
    }
    iosb.Status
}

/// [`NtExtendSection`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-ntextendsection).
///
/// # Safety
/// `new_section_size` must satisfy `PreviousMode`.
pub unsafe extern "C" fn NtExtendSection(
    section_handle: *mut c_void,
    new_section_size: *mut i64,
) -> NTSTATUS {
    let mode = capture::mode();
    // SAFETY: per the contract; `capture::read` probes user pointers.
    let req = match unsafe { capture::read(new_section_size, mode) } {
        Ok(v) if v < 0 => return STATUS_INVALID_PARAMETER_2,
        Ok(v) => v as u64,
        Err(st) => return st,
    };
    let (sec_ob, _) = match handle::reference_for(
        section_handle.addr() as u64,
        Some(&raw const object::SECTION_TYPE),
        SECTION_EXTEND_SIZE,
        capture::handle_mode(mode),
    ) {
        Ok(v) => v,
        Err(st) => return st,
    };
    let body = sec_ob.body();
    // SAFETY: `sec_ob` keeps `body` alive.
    let Some(user_sec) = (unsafe { section::user_section(body) }) else {
        return STATUS_INVALID_HANDLE;
    };
    let final_size = match user_sec {
        UserSection::Pagefile(pf) => {
            let new_aligned = req.next_multiple_of(PAGE_SIZE as u64);
            let mut frames = pf.frames.lock();
            let cur = pf.max_size.load(Ordering::Acquire);
            if new_aligned > cur {
                frames.resize((new_aligned / PAGE_SIZE as u64) as usize, 0);
                pf.max_size.store(new_aligned, Ordering::Release);
                // SAFETY: `sec_ob` keeps `body` alive.
                unsafe { section::grow_section_size(body, new_aligned) }
            } else {
                cur
            }
        }
        UserSection::DataFile(df) => {
            let grown = match section::extend_section(&df._section_ref, req) {
                Ok(sz) => sz,
                Err(st) => return st,
            };
            // SAFETY: `sec_ob` keeps `body` alive.
            unsafe { section::grow_section_size(body, grown) }
        }
        UserSection::Image(_) => return STATUS_SECTION_NOT_EXTENDED,
    };
    // SAFETY: per the contract; `capture::write` probes user pointers.
    if let Err(st) = unsafe { capture::write(new_section_size, final_size as i64, mode) } {
        return st;
    }
    STATUS_SUCCESS
}
