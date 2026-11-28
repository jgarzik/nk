//! User-mode process and thread creation: PEB (`MmCreatePeb`), TEB
//! (`MmCreateTeb`), user stack reservation/commit/guard, initial `CONTEXT`
//! handoff to `ntdll!LdrInitializeThunk`, and first-process bootstrap.

#![allow(dead_code)]

use super::sysdll::{self, MappedSysDll};
use crate::arch;
use crate::ke::thread;
use crate::mm::{self, PAGE_SIZE};
use crate::ob::object::{self, ObRef};
use alloc::boxed::Box;
use alloc::vec::Vec;
use core::ffi::c_void;
use core::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use nk_bootinfo::BootInfo;
use nk_mm::protect::{MEM_COMMIT, MEM_RESERVE, PAGE_EXECUTE_WRITECOPY, PAGE_GUARD, PAGE_READWRITE};
use nk_mm::vad::{ALLOC_GRANULARITY, USER_PROBE_VA};
use nk_ntabi::io::UNICODE_STRING;
use nk_ntabi::ke::KAPC_STATE;
use nk_ntabi::mm::SECTION_IMAGE_INFORMATION;
use nk_ntabi::process as proc_layout;
use nk_ntabi::seh::x64::{CONTEXT, CONTEXT_CONTROL, CONTEXT_FULL, CONTEXT_SEGMENTS};
use nk_ntabi::status::*;
use nk_ntabi::thread as thread_layout;
use nk_ntabi::user::{
    CLIENT_ID, PEB, PS_CREATE_NOTIFY_INFO, RTL_USER_PROC_PARAMS_NORMALIZED,
    RTL_USER_PROCESS_PARAMETERS, TEB, TEB_SAME_INITIAL_THREAD,
};

/// Minimum user stack reserve (256 KiB) and commit (16 KiB).
const MIN_STACK_RESERVE: u64 = 256 * 1024;
const MIN_STACK_COMMIT: u64 = 16 * 1024;

/// NK's per-process user-mode state stored inside [`super::process::Process`].
pub struct UserProcessState {
    pub sysdll: MappedSysDll,
    pub peb_va: u64,
    pub image_base: u64,
    pub entry_va: u64,
    pub image_info: SECTION_IMAGE_INFORMATION,
    pub image_path: Vec<u16>,
    pub cmd_line: Vec<u16>,
    pub active_threads: AtomicU32,
    pub terminated: AtomicBool,
    pub cookie: u32,
}

fn wide_nul(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(core::iter::once(0)).collect()
}

fn leaf_ascii_name(path: &str) -> [u8; proc_layout::IMAGE_FILE_NAME_LEN] {
    let leaf = path.rsplit('\\').next().unwrap_or(path);
    let mut out = [0u8; proc_layout::IMAGE_FILE_NAME_LEN];
    let n = leaf.len().min(proc_layout::IMAGE_FILE_NAME_LEN - 1);
    out[..n].copy_from_slice(&leaf.as_bytes()[..n]);
    out
}

/// Allocate user virtual memory inside the currently attached process via
/// `ZwAllocateVirtualMemory`.
fn alloc_in_attached(size: usize, protect: u32) -> Result<u64, NTSTATUS> {
    let mut base: *mut c_void = core::ptr::null_mut();
    let mut region = size;
    // SAFETY: kernel-mode `ZwAllocateVirtualMemory` targeting current attached process.
    let st = unsafe {
        crate::svc::zw::ZwAllocateVirtualMemory(
            (-1isize) as *mut c_void,
            &raw mut base,
            0,
            &raw mut region,
            MEM_RESERVE | MEM_COMMIT,
            protect,
        )
    };
    if st != STATUS_SUCCESS {
        return Err(st);
    }
    Ok(base.addr() as u64)
}

/// Write a `UNICODE_STRING` buffer into user memory at `cursor`, advancing `cursor`.
///
/// # Safety
/// The target user process is attached and `[cursor, cursor + units.len() * 2]` is writable.
unsafe fn write_user_unicode(cursor: &mut u64, units: &[u16]) -> Result<UNICODE_STRING, NTSTATUS> {
    let byte_len = units.len().saturating_sub(1) * 2;
    let total_bytes = units.len() * 2;
    let addr = *cursor;
    // SAFETY: per the contract; `mm::user::copy` fault-protects the write.
    unsafe {
        mm::user::copy(
            core::ptr::with_exposed_provenance_mut(addr as usize),
            units.as_ptr().cast::<u8>(),
            total_bytes,
        )
    }
    .map_err(|_| STATUS_ACCESS_VIOLATION)?;
    *cursor = (addr + total_bytes as u64).next_multiple_of(8);
    Ok(UNICODE_STRING {
        Length: byte_len as u16,
        MaximumLength: total_bytes as u16,
        Buffer: core::ptr::with_exposed_provenance_mut(addr as usize),
    })
}

/// Allocate and initialize `PEB` + `RTL_USER_PROCESS_PARAMETERS` in the
/// currently attached user process (`MmCreatePeb`).
///
/// # Safety
/// Caller is attached to `process` (`KeStackAttachProcess`).
unsafe fn create_peb_in_attached(
    image_base: u64,
    image_info: &SECTION_IMAGE_INFORMATION,
    sysdll: &MappedSysDll,
    image_path: &str,
    cmd_line: &str,
) -> Result<u64, NTSTATUS> {
    // Allocate PEB (1 page) + ProcessParameters + strings + environment (2 pages).
    let peb_va = alloc_in_attached(PAGE_SIZE, PAGE_READWRITE)?;
    let params_va = alloc_in_attached(4 * PAGE_SIZE, PAGE_READWRITE)?;

    let img_w = wide_nul(image_path);
    let cmd_w = wide_nul(cmd_line);
    let cur_dir_w = wide_nul("C:\\");
    let dll_path_w = wide_nul("C:\\Windows\\System32");
    let win_title_w = wide_nul(image_path);
    let env_w: Vec<u16> = "SystemRoot=C:\\Windows\0Path=C:\\Windows\\System32\0\0"
        .encode_utf16()
        .collect();

    let mut cursor =
        params_va + (size_of::<RTL_USER_PROCESS_PARAMETERS>() as u64).next_multiple_of(16);
    // SAFETY: attached to target process; `params_va` has 4 RW pages.
    let (img_us, cmd_us, cur_us, dll_us, title_us, env_va, env_bytes) = unsafe {
        let img_us = write_user_unicode(&mut cursor, &img_w)?;
        let cmd_us = write_user_unicode(&mut cursor, &cmd_w)?;
        let cur_us = write_user_unicode(&mut cursor, &cur_dir_w)?;
        let dll_us = write_user_unicode(&mut cursor, &dll_path_w)?;
        let title_us = write_user_unicode(&mut cursor, &win_title_w)?;
        let env_va = cursor;
        let env_bytes = env_w.len() * 2;
        mm::user::copy(
            core::ptr::with_exposed_provenance_mut(env_va as usize),
            env_w.as_ptr().cast::<u8>(),
            env_bytes,
        )
        .map_err(|_| STATUS_ACCESS_VIOLATION)?;
        cursor = (env_va + env_bytes as u64).next_multiple_of(8);
        (img_us, cmd_us, cur_us, dll_us, title_us, env_va, env_bytes)
    };
    let params_len = (cursor - params_va) as u32;

    // SAFETY: `RTL_USER_PROCESS_PARAMETERS` is all-zero valid.
    let mut params: RTL_USER_PROCESS_PARAMETERS = unsafe { core::mem::zeroed() };
    params.MaximumLength = (4 * PAGE_SIZE) as u32;
    params.Length = params_len;
    params.Flags = RTL_USER_PROC_PARAMS_NORMALIZED;
    params.CurrentDirectory.DosPath = cur_us;
    params.DllPath = dll_us;
    params.ImagePathName = img_us;
    params.CommandLine = cmd_us;
    params.WindowTitle = title_us;
    params.Environment = core::ptr::with_exposed_provenance_mut(env_va as usize);
    params.EnvironmentSize = env_bytes;

    // SAFETY: `params_va` is writable user memory in the attached process.
    unsafe {
        mm::user::copy(
            core::ptr::with_exposed_provenance_mut(params_va as usize),
            (&raw const params).cast::<u8>(),
            size_of::<RTL_USER_PROCESS_PARAMETERS>(),
        )
    }
    .map_err(|_| STATUS_ACCESS_VIOLATION)?;

    // SAFETY: `PEB` is all-zero valid.
    let mut peb: PEB = unsafe { core::mem::zeroed() };
    peb.Mutant = (-1isize) as *mut c_void;
    peb.ImageBaseAddress = core::ptr::with_exposed_provenance_mut(image_base as usize);
    peb.ProcessParameters = core::ptr::with_exposed_provenance_mut(params_va as usize);
    peb.ApiSetMap = core::ptr::with_exposed_provenance_mut(sysdll.apiset_va as usize);
    peb.AnsiCodePageData = core::ptr::with_exposed_provenance_mut(sysdll.ansi_cp_va as usize);
    peb.OemCodePageData = core::ptr::with_exposed_provenance_mut(sysdll.oem_cp_va as usize);
    peb.UnicodeCaseTableData =
        core::ptr::with_exposed_provenance_mut(sysdll.unicode_case_va as usize);
    peb.NumberOfProcessors = crate::ke::smp::online_count() as u32;
    peb.CriticalSectionTimeout = -25_920_000_000_000; // 30 days relative
    peb.HeapSegmentReserve = 0x10_0000;
    peb.HeapSegmentCommit = 0x2000;
    peb.HeapDeCommitTotalFreeThreshold = 0x1_0000;
    peb.HeapDeCommitFreeBlockThreshold = 0x1000;
    peb.OSMajorVersion = 10;
    peb.OSMinorVersion = 0;
    peb.OSBuildNumber = 19045;
    peb.OSPlatformId = 2; // VER_PLATFORM_WIN32_NT
    peb.ImageSubsystem = image_info.SubSystemType;
    peb.ImageSubsystemMajorVersion = u32::from(image_info.SubSystemMajorVersion);
    peb.ImageSubsystemMinorVersion = u32::from(image_info.SubSystemMinorVersion);
    peb.ActiveProcessAffinityMask = crate::ke::smp::online() as usize;
    peb.SessionId = 0;
    peb.MinimumStackCommit = 0;

    // SAFETY: `peb_va` is writable user memory in the attached process.
    unsafe {
        mm::user::copy(
            core::ptr::with_exposed_provenance_mut(peb_va as usize),
            (&raw const peb).cast::<u8>(),
            size_of::<PEB>(),
        )
    }
    .map_err(|_| STATUS_ACCESS_VIOLATION)?;

    Ok(peb_va)
}

/// Create a user-mode process backed by the PE32+ image at `image_path`
/// (e.g. `\SystemRoot\System32\nkt.exe`).
///
/// # Safety
/// `parent` is a live `EPROCESS`.
pub unsafe fn create_process(
    image_path: &str,
    cmd_line: &str,
    parent: *mut u8,
    inherit_handles: bool,
) -> Result<ObRef, NTSTATUS> {
    sysdll::ensure_loaded()?;
    let exe_bytes = sysdll::read_file_bytes(image_path)?;
    let entry_rva = nk_pe::Pe::parse(&exe_bytes)
        .map_err(|_| STATUS_INVALID_IMAGE_FORMAT)?
        .headers()
        .entry_rva;
    let image_path_w: Vec<u16> = image_path.encode_utf16().collect();
    let exe_sec = mm::view::create_image_section_from_bytes(&image_path_w, &exe_bytes)?;
    // SAFETY: `exe_sec` is a live `SEC_IMAGE` section.
    let image_info =
        unsafe { mm::view::image_info(exe_sec.body()) }.ok_or(STATUS_INVALID_IMAGE_FORMAT)?;

    let short_name = leaf_ascii_name(image_path);
    let short_len = short_name
        .iter()
        .position(|&b| b == 0)
        .unwrap_or(short_name.len());
    // SAFETY: `parent` is a live `EPROCESS` per the contract.
    let proc_ref = unsafe {
        super::process::create_minimal(&short_name[..short_len], parent, inherit_handles)
    }?;
    let proc_body = proc_ref.body();

    // SAFETY: `proc_body` is a live non-System `EPROCESS`.
    let space = unsafe { super::process::address_space(proc_body) }.ok_or(STATUS_UNSUCCESSFUL)?;
    // SAFETY: `exe_sec` is a live `SEC_IMAGE` section.
    let (image_base, _, _) = unsafe {
        mm::view::map_view_in_space(
            exe_sec.body(),
            space,
            0,
            0,
            0,
            0,
            PAGE_EXECUTE_WRITECOPY,
            USER_PROBE_VA,
        )
    }?;

    // Map `ntdll.dll`, NLS, API-Set and patch `LdrSystemDllInitBlock`.
    // SAFETY: `proc_body` is a live non-System `EPROCESS`.
    let mapped_sysdll = unsafe { sysdll::map_into_process(proc_body) }?;

    // Allocate & populate PEB + RTL_USER_PROCESS_PARAMETERS inside `proc_body`.
    let mut apc_state = core::mem::MaybeUninit::<KAPC_STATE>::zeroed();
    // SAFETY: `proc_body` is live; attach, create PEB, detach.
    let peb_va = unsafe {
        super::process::KeStackAttachProcess(proc_body.cast(), apc_state.as_mut_ptr());
        let res = create_peb_in_attached(
            image_base,
            &image_info,
            &mapped_sysdll,
            image_path,
            cmd_line,
        );
        super::process::KeUnstackDetachProcess(apc_state.as_mut_ptr());
        res
    }?;

    // Record `EPROCESS` user fields and `UserProcessState`.
    let cookie = ((arch::counter() ^ 0x55AA_33CC_7788_9911) as u32) | 1;
    let cmd_w: Vec<u16> = cmd_line.encode_utf16().collect();
    let state = Box::new(UserProcessState {
        sysdll: mapped_sysdll,
        peb_va,
        image_base,
        entry_va: image_base.wrapping_add(u64::from(entry_rva)),
        image_info,
        image_path: image_path_w,
        cmd_line: cmd_w,
        active_threads: AtomicU32::new(0),
        terminated: AtomicBool::new(false),
        cookie,
    });
    // Transfer the `exe_sec` reference into `EPROCESS.SectionObject` (dropped in `process::deleted`).
    let sec_ptr = exe_sec.body();
    core::mem::forget(exe_sec);
    // SAFETY: `proc_body` is newly created and exclusively owned here.
    unsafe {
        proc_body.add(proc_layout::PEB).cast::<u64>().write(peb_va);
        proc_body
            .add(proc_layout::SECTION_BASE_ADDRESS)
            .cast::<u64>()
            .write(image_base);
        proc_body
            .add(proc_layout::SECTION_OBJECT)
            .cast::<*mut u8>()
            .write(sec_ptr);
        super::process::set_user_state(proc_body, state);
    }

    // Dispatch process-creation notify routines (`cng.sys`, etc.).
    // SAFETY: `proc_body` and `parent` are live processes.
    let (pid, parent_pid) = unsafe {
        (
            super::process::PsGetProcessId(proc_body.cast()).addr() as u64,
            super::process::PsGetProcessId(parent.cast()).addr() as u64,
        )
    };
    let mut img_us = UNICODE_STRING {
        Length: (image_path.len() * 2) as u16,
        MaximumLength: (image_path.len() * 2) as u16,
        // SAFETY: `state` lives inside `proc_ref` for the duration of this call.
        Buffer: unsafe {
            super::process::user_state(proc_body)
                .map_or(core::ptr::null_mut(), |s| s.image_path.as_ptr().cast_mut())
        },
    };
    let mut cmd_us = UNICODE_STRING {
        Length: (cmd_line.len() * 2) as u16,
        MaximumLength: (cmd_line.len() * 2) as u16,
        // SAFETY: as above.
        Buffer: unsafe {
            super::process::user_state(proc_body)
                .map_or(core::ptr::null_mut(), |s| s.cmd_line.as_ptr().cast_mut())
        },
    };
    let mut notify_info = PS_CREATE_NOTIFY_INFO {
        Size: size_of::<PS_CREATE_NOTIFY_INFO>(),
        Flags: 0,
        _pad0: 0,
        ParentProcessId: core::ptr::with_exposed_provenance_mut(parent_pid as usize),
        CreatingThreadId: CLIENT_ID {
            UniqueProcess: super::process::PsGetCurrentProcessId(),
            UniqueThread: super::process::PsGetCurrentThreadId(),
        },
        FileObject: core::ptr::null_mut(),
        ImageFileName: &raw mut img_us,
        CommandLine: &raw mut cmd_us,
        CreationStatus: STATUS_SUCCESS,
        _pad1: 0,
    };
    // SAFETY: `proc_body` and `notify_info` are valid for the call.
    let notify_st = unsafe {
        super::notify::dispatch_process(proc_body.cast(), parent_pid, pid, Some(&mut notify_info))
    };
    if !nt_success(notify_st) {
        return Err(notify_st);
    }

    Ok(proc_ref)
}

/// Startup parameters handed to a new user thread's kernel trampoline.
struct UserThreadStart {
    teb_va: u64,
    ldr_init_rip: u64,
    init_rsp: u64,
    ctx_va: u64,
    ntdll_base: u64,
}

fn user_thread_trampoline(arg: usize) {
    // SAFETY: boxed by `create_thread` and leaked exclusively to this thread.
    let start = *unsafe { Box::from_raw(arg as *mut UserThreadStart) };
    arch::set_user_gs_base(start.teb_va);
    // SAFETY: thread belongs to the target user process whose `ntdll.dll`,
    // `PEB`, `TEB`, stack, and initial `CONTEXT` are mapped.
    unsafe {
        arch::enter_user_mode(
            start.ldr_init_rip,
            start.init_rsp,
            start.ctx_va,
            start.ntdll_base,
        )
    }
}

/// Create a user-mode thread in `process` whose initial `CONTEXT` begins at
/// `ntdll!RtlUserThreadStart(start_address, start_param)`, entered through
/// `ntdll!LdrInitializeThunk(ctx_va, ntdll_base)`.
///
/// # Safety
/// `process` is a live user `EPROCESS` created by [`create_process`].
#[allow(clippy::too_many_arguments)]
pub unsafe fn create_thread(
    process: *mut u8,
    start_address: u64,
    start_param: u64,
    stack_reserve: u64,
    stack_commit: u64,
    initial_thread: bool,
    suspended: bool,
) -> Result<ObRef, NTSTATUS> {
    // SAFETY: per the contract.
    let state = unsafe { super::process::user_state(process) }.ok_or(STATUS_INVALID_PARAMETER)?;
    if state.terminated.load(Ordering::Acquire) {
        return Err(STATUS_PROCESS_IS_TERMINATING);
    }
    let sysdll = state.sysdll;
    let peb_va = state.peb_va;
    let reserve = stack_reserve
        .max(MIN_STACK_RESERVE)
        .next_multiple_of(ALLOC_GRANULARITY);
    let commit = stack_commit
        .max(MIN_STACK_COMMIT)
        .min(reserve - 2 * PAGE_SIZE as u64)
        .next_multiple_of(PAGE_SIZE as u64);

    // Create the kernel thread first (unstarted) so we know its TID for `TEB.ClientId`.
    let start_box = Box::into_raw(Box::new(UserThreadStart {
        teb_va: 0,
        ldr_init_rip: sysdll.ldr_initialize_thunk,
        init_rsp: 0,
        ctx_va: 0,
        ntdll_base: sysdll.ntdll_base,
    }));
    let Ok(th) = thread::create_unstarted(
        user_thread_trampoline,
        start_box.addr(),
        thread::NORMAL_PRIORITY,
        thread::ANYWHERE,
    ) else {
        // SAFETY: thread creation failed, so `start_box` is still ours.
        drop(unsafe { Box::from_raw(start_box) });
        return Err(STATUS_INSUFFICIENT_RESOURCES);
    };
    // SAFETY: `th` is unstarted and `process` is live.
    let (pid, tid) = unsafe {
        thread::assign_process(th, process);
        let cid = thread::object_field::<[u64; 2]>(th, thread_layout::CID).read();
        (cid[0], cid[1])
    };

    // Attach to `process` to allocate user stack + guard + TEB + initial CONTEXT.
    let mut apc_state = core::mem::MaybeUninit::<KAPC_STATE>::zeroed();
    // SAFETY: `process` is live.
    let setup: Result<(u64, u64, u64), NTSTATUS> = unsafe {
        super::process::KeStackAttachProcess(process.cast(), apc_state.as_mut_ptr());
        let r = (|| -> Result<(u64, u64, u64), NTSTATUS> {
            // 1. Reserve full stack region.
            let mut stack_base_ptr: *mut c_void = core::ptr::null_mut();
            let mut res_sz = reserve as usize;
            let st = crate::svc::zw::ZwAllocateVirtualMemory(
                (-1isize) as *mut c_void,
                &raw mut stack_base_ptr,
                0,
                &raw mut res_sz,
                MEM_RESERVE,
                PAGE_READWRITE,
            );
            if st != STATUS_SUCCESS {
                return Err(st);
            }
            let stack_reserve_lo = stack_base_ptr.addr() as u64;
            let stack_top = stack_reserve_lo + res_sz as u64;
            let commit_lo = stack_top - commit;
            let guard_va = commit_lo - PAGE_SIZE as u64;

            // 2. Commit top `commit` bytes RW.
            let mut commit_ptr =
                core::ptr::with_exposed_provenance_mut::<c_void>(commit_lo as usize);
            let mut commit_sz = commit as usize;
            let st = crate::svc::zw::ZwAllocateVirtualMemory(
                (-1isize) as *mut c_void,
                &raw mut commit_ptr,
                0,
                &raw mut commit_sz,
                MEM_COMMIT,
                PAGE_READWRITE,
            );
            if st != STATUS_SUCCESS {
                return Err(st);
            }

            // 3. Commit 1 guard page directly below `commit_lo`.
            let mut guard_ptr = core::ptr::with_exposed_provenance_mut::<c_void>(guard_va as usize);
            let mut guard_sz = PAGE_SIZE;
            let st = crate::svc::zw::ZwAllocateVirtualMemory(
                (-1isize) as *mut c_void,
                &raw mut guard_ptr,
                0,
                &raw mut guard_sz,
                MEM_COMMIT,
                PAGE_READWRITE | PAGE_GUARD,
            );
            if st != STATUS_SUCCESS {
                return Err(st);
            }

            // 4. Allocate 2-page TEB (6200 bytes -> 8 KiB).
            let teb_va = alloc_in_attached(2 * PAGE_SIZE, PAGE_READWRITE)?;
            let mut teb: TEB = core::mem::zeroed();
            teb.NtTib.ExceptionList = core::ptr::null_mut();
            teb.NtTib.StackBase = core::ptr::with_exposed_provenance_mut(stack_top as usize);
            teb.NtTib.StackLimit = core::ptr::with_exposed_provenance_mut(commit_lo as usize);
            teb.NtTib.SelfPtr = core::ptr::with_exposed_provenance_mut(teb_va as usize);
            let cid = CLIENT_ID {
                UniqueProcess: core::ptr::with_exposed_provenance_mut(pid as usize),
                UniqueThread: core::ptr::with_exposed_provenance_mut(tid as usize),
            };
            teb.ClientId = cid;
            teb.RealClientId = cid;
            teb.ProcessEnvironmentBlock = core::ptr::with_exposed_provenance_mut(peb_va as usize);
            teb.CurrentLocale = 0x0409; // en-US
            let act_va = teb_va + core::mem::offset_of!(TEB, ActivationStack) as u64;
            teb.ActivationContextStackPointer =
                core::ptr::with_exposed_provenance_mut(act_va as usize);
            let static_buf_va = teb_va + core::mem::offset_of!(TEB, StaticUnicodeBuffer) as u64;
            teb.StaticUnicodeString = UNICODE_STRING {
                Length: 0,
                MaximumLength: 522,
                Buffer: core::ptr::with_exposed_provenance_mut(static_buf_va as usize),
            };
            teb.DeallocationStack =
                core::ptr::with_exposed_provenance_mut(stack_reserve_lo as usize);
            if initial_thread {
                teb.SameTebFlags = TEB_SAME_INITIAL_THREAD;
            }
            mm::user::copy(
                core::ptr::with_exposed_provenance_mut(teb_va as usize),
                (&raw const teb).cast::<u8>(),
                size_of::<TEB>(),
            )
            .map_err(|_| STATUS_ACCESS_VIOLATION)?;

            // 5. Place initial `CONTEXT` on the user stack for `LdrInitializeThunk`
            //    to resume via `NtContinue(ctx_va, TRUE)` -> `RtlUserThreadStart(start, param)`.
            let ctx_va = (stack_top - 0x40 - size_of::<CONTEXT>() as u64) & !0xFu64;
            let target_rsp = stack_top - 0x28; // 16n + 8 at function entry
            let mut ctx: CONTEXT = core::mem::zeroed();
            ctx.ContextFlags = CONTEXT_FULL | CONTEXT_CONTROL | CONTEXT_SEGMENTS;
            ctx.MxCsr = 0x1F80;
            ctx.SegCs = 0x33;
            ctx.SegDs = 0x2B;
            ctx.SegEs = 0x2B;
            ctx.SegFs = 0;
            ctx.SegGs = 0x2B;
            ctx.SegSs = 0x2B;
            ctx.EFlags = 0x202;
            ctx.Rip = sysdll.rtl_user_thread_start;
            ctx.Rsp = target_rsp;
            ctx.Rcx = start_address;
            ctx.Rdx = start_param;
            ctx.FltSave.ControlWord = 0x027F;
            ctx.FltSave.MxCsr = 0x1F80;
            ctx.FltSave.MxCsr_Mask = 0xFFFF;
            mm::user::copy(
                core::ptr::with_exposed_provenance_mut(ctx_va as usize),
                (&raw const ctx).cast::<u8>(),
                size_of::<CONTEXT>(),
            )
            .map_err(|_| STATUS_ACCESS_VIOLATION)?;

            // Stack pointer when entering `LdrInitializeThunk(ctx_va, ntdll_base)`:
            // 32 bytes shadow space + 8-byte fake return address slot below `ctx_va`.
            let init_rsp = ((ctx_va - 0x30) & !0xFu64) + 8;
            Ok((teb_va, ctx_va, init_rsp))
        })();
        super::process::KeUnstackDetachProcess(apc_state.as_mut_ptr());
        r
    };

    let (teb_va, ctx_va, init_rsp) = match setup {
        Ok(v) => v,
        Err(st) => {
            // SAFETY: `th` was never started; discard it and free `start_box`.
            unsafe {
                thread::discard(th);
                object::dereference(th.cast());
                drop(Box::from_raw(start_box));
            }
            return Err(st);
        }
    };

    // SAFETY: `th` is still unstarted; fill in `start_box`, `KTHREAD.Teb`, and start address.
    unsafe {
        (*start_box).teb_va = teb_va;
        (*start_box).ctx_va = ctx_va;
        (*start_box).init_rsp = init_rsp;
        thread::set_teb(th, teb_va);
        thread::object_field::<u64>(th, thread_layout::START_ADDRESS).write(start_address);
    }

    // Increment active thread count on `EPROCESS`.
    state.active_threads.fetch_add(1, Ordering::AcqRel);
    // SAFETY: `process` is live.
    unsafe {
        let slot = process.add(proc_layout::ACTIVE_THREADS).cast::<AtomicU32>();
        (*slot).fetch_add(1, Ordering::AcqRel);
    }

    super::notify::dispatch_thread(pid, tid, true);

    // SAFETY: `th` has one caller reference from `create_unstarted`; wrap in `ObRef`.
    let th_ref = unsafe { ObRef::adopt(th.cast()) };
    if !suspended {
        // SAFETY: `th` is fully initialized and unstarted.
        unsafe { thread::begin(th) };
    }
    Ok(th_ref)
}

/// Called when a user-mode thread is terminating: decrements its owning
/// process's active thread count, dispatches thread-exit notify, and signals
/// the `EPROCESS` dispatcher object if it was the last thread.
pub fn notify_thread_exit(exit_status: NTSTATUS) {
    let me = thread::current();
    // SAFETY: `me` is the running thread.
    let (proc_ptr, pid, tid) = unsafe {
        let p = super::process::PsGetThreadProcess(me.cast()).cast::<u8>();
        let cid = thread::object_field::<[u64; 2]>(me, thread_layout::CID).read();
        (p, cid[0], cid[1])
    };
    if proc_ptr.is_null() || proc_ptr == super::process::system() {
        return;
    }
    super::notify::dispatch_thread(pid, tid, false);
    // SAFETY: `proc_ptr` is kept alive by `me`'s process reference.
    let Some(state) = (unsafe { super::process::user_state(proc_ptr) }) else {
        return;
    };
    let prev = state.active_threads.fetch_sub(1, Ordering::AcqRel);
    // SAFETY: `proc_ptr` is live.
    unsafe {
        let slot = proc_ptr
            .add(proc_layout::ACTIVE_THREADS)
            .cast::<AtomicU32>();
        (*slot).fetch_sub(1, Ordering::AcqRel);
    }
    if prev == 1 {
        // Last thread of the process exited: record exit status if still pending and signal process.
        // SAFETY: `proc_ptr` is live.
        unsafe {
            let st_ptr = proc_ptr.add(proc_layout::EXIT_STATUS).cast::<AtomicU32>();
            let _ = (*st_ptr).compare_exchange(
                STATUS_PENDING as u32,
                exit_status as u32,
                Ordering::AcqRel,
                Ordering::Acquire,
            );
            state.terminated.store(true, Ordering::Release);
            let parent_pid = proc_ptr
                .add(proc_layout::INHERITED_FROM_UNIQUE_PROCESS_ID)
                .cast::<u64>()
                .read();
            super::notify::dispatch_process(proc_ptr.cast(), parent_pid, pid, None);
            let header = proc_ptr.cast::<nk_ntabi::ke::DISPATCHER_HEADER>();
            let woken = {
                let _lock = crate::ke::object::ObjectLock::take(header);
                crate::ke::object::signal(header).store(1, Ordering::Release);
                crate::ke::object::satisfy(header)
            };
            woken.ready();
        }
    }
}

/// Bootstrap the first user-mode process (`image_path`, `cmd_line`) after
/// resolving `\Device\BootDevice` and `\SystemRoot` from `info`.
/// Returns `(process_ref, initial_thread_ref)`.
pub fn start_first(
    info: &BootInfo,
    image_path: &str,
    cmd_line: &str,
) -> Result<(ObRef, ObRef), NTSTATUS> {
    sysdll::ensure_system_root(info)?;
    // SAFETY: `system()` is always live.
    let proc_ref =
        unsafe { create_process(image_path, cmd_line, super::process::system(), false) }?;
    // SAFETY: `proc_ref` is a live user process created above.
    let (entry, peb_va, stack_reserve, stack_commit) = unsafe {
        let s = super::process::user_state(proc_ref.body()).ok_or(STATUS_UNSUCCESSFUL)?;
        (
            s.entry_va,
            s.peb_va,
            s.image_info.MaximumStackSize,
            s.image_info.CommittedStackSize,
        )
    };
    // SAFETY: `proc_ref` is live.
    let th_ref = unsafe {
        create_thread(
            proc_ref.body(),
            entry,
            peb_va,
            stack_reserve,
            stack_commit,
            true,
            false,
        )
    }?;
    Ok((proc_ref, th_ref))
}
