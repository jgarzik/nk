//! `nkt.exe`: NK's in-tree `/subsystem:native` user-mode test binary.
//!
//! Built with `x86_64-unknown-uefi` + `/subsystem:native` and `raw-dylib`
//! imports from `ntdll.dll`. Runs unmodified on both NK and reference
//! Windows 10 (via `RtlCreateUserProcess`), writing deterministic `NKT ...`
//! lines to the NT file path passed as its first argument (and echoing them
//! via `NtDisplayString`).

#![no_std]
#![no_main]

use core::ffi::c_void;
use core::fmt::{self, Write as _};
use core::panic::PanicInfo;

type NtStatus = i32;
type Handle = *mut c_void;

const CURRENT_PROCESS: Handle = -1isize as Handle;

const STATUS_SUCCESS: NtStatus = 0;
const STATUS_TIMEOUT: NtStatus = 0x0000_0102;
const STATUS_INVALID_HANDLE: NtStatus = 0xC000_0008u32 as NtStatus;

const MEM_COMMIT: u32 = 0x0000_1000;
const MEM_RESERVE: u32 = 0x0000_2000;
const MEM_RELEASE: u32 = 0x0000_8000;

const PAGE_READONLY: u32 = 0x02;
const PAGE_READWRITE: u32 = 0x04;
const PAGE_GUARD: u32 = 0x100;

const OBJ_CASE_INSENSITIVE: u32 = 0x40;
const FILE_OVERWRITE_IF: u32 = 5;
const FILE_SYNCHRONOUS_IO_NONALERT: u32 = 0x20;
const FILE_NON_DIRECTORY_FILE: u32 = 0x40;
const FILE_GENERIC_WRITE: u32 = 0x4010_0000;
const FILE_SHARE_READ: u32 = 1;
const FILE_ATTRIBUTE_NORMAL: u32 = 0x80;

const NOTIFICATION_EVENT: u32 = 0;
const EVENT_ALL_ACCESS: u32 = 0x001F_0003;

#[repr(C)]
#[derive(Clone, Copy)]
struct UnicodeString {
    length: u16,
    maximum_length: u16,
    buffer: *const u16,
}

#[repr(C)]
struct ObjectAttributes {
    length: u32,
    root_directory: Handle,
    object_name: *const UnicodeString,
    attributes: u32,
    security_descriptor: *mut c_void,
    security_qos: *mut c_void,
}

#[repr(C)]
#[derive(Default)]
struct IoStatusBlock {
    status: usize,
    information: usize,
}

#[repr(C)]
#[derive(Default)]
struct MemoryBasicInformation {
    base_address: *mut c_void,
    allocation_base: *mut c_void,
    allocation_protect: u32,
    _pad0: u32,
    region_size: usize,
    state: u32,
    protect: u32,
    mem_type: u32,
    _pad1: u32,
}

#[repr(C)]
#[derive(Default)]
struct ProcessBasicInformation {
    exit_status: NtStatus,
    _pad0: u32,
    peb_base_address: *mut c_void,
    affinity_mask: usize,
    base_priority: i32,
    _pad1: u32,
    unique_process_id: usize,
    inherited_from_unique_process_id: usize,
}

#[link(name = "ntdll", kind = "raw-dylib")]
unsafe extern "system" {
    fn NtAllocateVirtualMemory(
        process: Handle,
        base_address: *mut *mut c_void,
        zero_bits: usize,
        region_size: *mut usize,
        allocation_type: u32,
        protect: u32,
    ) -> NtStatus;
    fn NtFreeVirtualMemory(
        process: Handle,
        base_address: *mut *mut c_void,
        region_size: *mut usize,
        free_type: u32,
    ) -> NtStatus;
    fn NtProtectVirtualMemory(
        process: Handle,
        base_address: *mut *mut c_void,
        region_size: *mut usize,
        new_protect: u32,
        old_protect: *mut u32,
    ) -> NtStatus;
    fn NtQueryVirtualMemory(
        process: Handle,
        base_address: *const c_void,
        info_class: u32,
        buffer: *mut c_void,
        length: usize,
        return_length: *mut usize,
    ) -> NtStatus;
    fn NtCreateEvent(
        handle: *mut Handle,
        desired_access: u32,
        object_attributes: *const ObjectAttributes,
        event_type: u32,
        initial_state: u8,
    ) -> NtStatus;
    fn NtSetEvent(handle: Handle, previous_state: *mut i32) -> NtStatus;
    fn NtResetEvent(handle: Handle, previous_state: *mut i32) -> NtStatus;
    fn NtWaitForSingleObject(handle: Handle, alertable: u8, timeout: *const i64) -> NtStatus;
    fn NtClose(handle: Handle) -> NtStatus;
    fn NtCreateFile(
        handle: *mut Handle,
        desired_access: u32,
        object_attributes: *const ObjectAttributes,
        io_status: *mut IoStatusBlock,
        allocation_size: *const i64,
        file_attributes: u32,
        share_access: u32,
        create_disposition: u32,
        create_options: u32,
        ea_buffer: *const c_void,
        ea_length: u32,
    ) -> NtStatus;
    fn NtWriteFile(
        file_handle: Handle,
        event: Handle,
        apc_routine: *const c_void,
        apc_context: *mut c_void,
        io_status: *mut IoStatusBlock,
        buffer: *const u8,
        length: u32,
        byte_offset: *const i64,
        key: *const u32,
    ) -> NtStatus;
    fn NtQueryInformationProcess(
        process: Handle,
        info_class: u32,
        buffer: *mut c_void,
        length: u32,
        return_length: *mut u32,
    ) -> NtStatus;
    fn NtDisplayString(string: *const UnicodeString) -> NtStatus;
    fn NtTerminateProcess(process: Handle, exit_status: NtStatus) -> NtStatus;
    fn RtlAllocateHeap(heap: *mut c_void, flags: u32, size: usize) -> *mut c_void;
    fn RtlFreeHeap(heap: *mut c_void, flags: u32, base: *mut c_void) -> u8;
}

/// Fixed-capacity ASCII transcript buffer written both to the optional output
/// file and to `NtDisplayString`.
struct Log {
    buf: [u8; 4096],
    len: usize,
}

impl Log {
    const fn new() -> Self {
        Self {
            buf: [0; 4096],
            len: 0,
        }
    }

    fn as_bytes(&self) -> &[u8] {
        &self.buf[..self.len]
    }
}

impl fmt::Write for Log {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        let bytes = s.as_bytes();
        let avail = self.buf.len().saturating_sub(self.len);
        let n = bytes.len().min(avail);
        self.buf[self.len..self.len + n].copy_from_slice(&bytes[..n]);
        self.len += n;
        Ok(())
    }
}

fn display_ascii(bytes: &[u8]) {
    let mut wide = [0u16; 256];
    let mut i = 0usize;
    while i < bytes.len() {
        let chunk = (bytes.len() - i).min(wide.len());
        for (dst, &src) in wide[..chunk].iter_mut().zip(&bytes[i..i + chunk]) {
            *dst = u16::from(src);
        }
        let us = UnicodeString {
            length: (chunk * 2) as u16,
            maximum_length: (chunk * 2) as u16,
            buffer: wide.as_ptr(),
        };
        // SAFETY: `us` points to `chunk` live UTF-16 code units.
        let _ = unsafe { NtDisplayString(&raw const us) };
        i += chunk;
    }
}

/// Extract the second whitespace-separated token from `PEB.ProcessParameters.CommandLine`
/// as an NT path for the output transcript file, if present.
///
/// # Safety
/// `peb` is the process's live `PEB`.
unsafe fn output_path_from_peb(peb: *mut c_void, out: &mut [u16; 256]) -> usize {
    if peb.is_null() {
        return 0;
    }
    // SAFETY: `_PEB.ProcessParameters` is at offset 0x20; `_RTL_USER_PROCESS_PARAMETERS.CommandLine`
    // is at offset 0x70 on x64 Windows 10.
    let cmdline = unsafe {
        let params = peb.cast::<u8>().add(0x20).cast::<*const u8>().read();
        if params.is_null() {
            return 0;
        }
        params.add(0x70).cast::<UnicodeString>().read()
    };
    if cmdline.buffer.is_null() || cmdline.length < 2 {
        return 0;
    }
    let units = (cmdline.length / 2) as usize;
    // SAFETY: `cmdline.buffer` holds `units` UTF-16 code units in process parameters.
    let slice = unsafe { core::slice::from_raw_parts(cmdline.buffer, units) };
    // Skip leading spaces, skip argv[0], skip spaces, take argv[1].
    let mut i = 0usize;
    while i < slice.len() && slice[i] == u16::from(b' ') {
        i += 1;
    }
    let quoted = i < slice.len() && slice[i] == u16::from(b'"');
    if quoted {
        i += 1;
        while i < slice.len() && slice[i] != u16::from(b'"') {
            i += 1;
        }
        if i < slice.len() {
            i += 1;
        }
    } else {
        while i < slice.len() && slice[i] != u16::from(b' ') {
            i += 1;
        }
    }
    while i < slice.len() && slice[i] == u16::from(b' ') {
        i += 1;
    }
    let start = i;
    while i < slice.len() && slice[i] != u16::from(b' ') && slice[i] != 0 {
        i += 1;
    }
    let len = (i - start).min(out.len());
    out[..len].copy_from_slice(&slice[start..start + len]);
    len
}

fn write_transcript_file(path: &[u16], data: &[u8]) {
    if path.is_empty() {
        return;
    }
    let name = UnicodeString {
        length: (path.len() * 2) as u16,
        maximum_length: (path.len() * 2) as u16,
        buffer: path.as_ptr(),
    };
    let oa = ObjectAttributes {
        length: size_of::<ObjectAttributes>() as u32,
        root_directory: core::ptr::null_mut(),
        object_name: &raw const name,
        attributes: OBJ_CASE_INSENSITIVE,
        security_descriptor: core::ptr::null_mut(),
        security_qos: core::ptr::null_mut(),
    };
    let mut iosb = IoStatusBlock::default();
    let mut handle: Handle = core::ptr::null_mut();
    // SAFETY: all pointers reference live stack objects.
    let status = unsafe {
        NtCreateFile(
            &raw mut handle,
            FILE_GENERIC_WRITE,
            &raw const oa,
            &raw mut iosb,
            core::ptr::null(),
            FILE_ATTRIBUTE_NORMAL,
            FILE_SHARE_READ,
            FILE_OVERWRITE_IF,
            FILE_SYNCHRONOUS_IO_NONALERT | FILE_NON_DIRECTORY_FILE,
            core::ptr::null(),
            0,
        )
    };
    if status == STATUS_SUCCESS {
        let mut write_iosb = IoStatusBlock::default();
        // SAFETY: `handle` is open and `data` is live for the synchronous write.
        unsafe {
            let _ = NtWriteFile(
                handle,
                core::ptr::null_mut(),
                core::ptr::null(),
                core::ptr::null_mut(),
                &raw mut write_iosb,
                data.as_ptr(),
                data.len() as u32,
                core::ptr::null(),
                core::ptr::null(),
            );
            let _ = NtClose(handle);
        }
    }
}

fn run_vm_tests(log: &mut Log) {
    let mut base: *mut c_void = core::ptr::null_mut();
    let mut size: usize = 0x1_0000;
    // SAFETY: kernel-backed virtual allocation in current process.
    let st_alloc = unsafe {
        NtAllocateVirtualMemory(
            CURRENT_PROCESS,
            &raw mut base,
            0,
            &raw mut size,
            MEM_RESERVE | MEM_COMMIT,
            PAGE_READWRITE,
        )
    };
    let mut pattern_ok = false;
    let mut mbi = MemoryBasicInformation::default();
    let mut st_query = -1;
    let mut st_prot = -1;
    let mut old_prot = 0u32;
    let mut st_free = -1;
    if st_alloc == STATUS_SUCCESS && !base.is_null() {
        // SAFETY: `base` was just committed read-write for `size` bytes.
        unsafe {
            let p = base.cast::<u64>();
            p.write_volatile(0x1122_3344_5566_7788);
            p.add(512).write_volatile(0xAABB_CCDD_EEFF_0011);
            pattern_ok = p.read_volatile() == 0x1122_3344_5566_7788
                && p.add(512).read_volatile() == 0xAABB_CCDD_EEFF_0011;
            let mut ret_len = 0usize;
            st_query = NtQueryVirtualMemory(
                CURRENT_PROCESS,
                base,
                0, // MemoryBasicInformation
                (&raw mut mbi).cast(),
                size_of::<MemoryBasicInformation>(),
                &raw mut ret_len,
            );
            let mut prot_base = base;
            let mut prot_size = 0x1000usize;
            st_prot = NtProtectVirtualMemory(
                CURRENT_PROCESS,
                &raw mut prot_base,
                &raw mut prot_size,
                PAGE_READONLY,
                &raw mut old_prot,
            );
            let mut free_base = base;
            let mut free_size = 0usize;
            st_free = NtFreeVirtualMemory(
                CURRENT_PROCESS,
                &raw mut free_base,
                &raw mut free_size,
                MEM_RELEASE,
            );
        }
    }
    let _ = writeln!(
        log,
        "NKT vm.rw: alloc={:#010x} rw={} query={:#010x} state={:#x} prot={:#x} chg={:#010x} old={:#x} free={:#010x}",
        st_alloc as u32,
        u8::from(pattern_ok),
        st_query as u32,
        mbi.state,
        mbi.protect,
        st_prot as u32,
        old_prot,
        st_free as u32,
    );

    // Guard page allocation + query.
    let mut gbase: *mut c_void = core::ptr::null_mut();
    let mut gsize: usize = 0x2000;
    // SAFETY: stack out-pointers.
    let st_g = unsafe {
        NtAllocateVirtualMemory(
            CURRENT_PROCESS,
            &raw mut gbase,
            0,
            &raw mut gsize,
            MEM_RESERVE | MEM_COMMIT,
            PAGE_READWRITE | PAGE_GUARD,
        )
    };
    let mut gmbi = MemoryBasicInformation::default();
    let mut st_gq = -1;
    if st_g == STATUS_SUCCESS {
        let mut ret_len = 0usize;
        // SAFETY: `gbase` is live.
        unsafe {
            st_gq = NtQueryVirtualMemory(
                CURRENT_PROCESS,
                gbase,
                0,
                (&raw mut gmbi).cast(),
                size_of::<MemoryBasicInformation>(),
                &raw mut ret_len,
            );
            let mut fb = gbase;
            let mut fs = 0usize;
            let _ = NtFreeVirtualMemory(CURRENT_PROCESS, &raw mut fb, &raw mut fs, MEM_RELEASE);
        }
    }
    let _ = writeln!(
        log,
        "NKT vm.guard: alloc={:#010x} query={:#010x} prot={:#x}",
        st_g as u32, st_gq as u32, gmbi.protect,
    );
}

fn run_event_and_handle_tests(log: &mut Log) {
    let mut ev: Handle = core::ptr::null_mut();
    let zero_timeout: i64 = 0;
    // SAFETY: standard NT object creation and wait calls.
    let (st_c, st_w0, st_s, prev_s, st_w1, st_r, prev_r, st_w2, st_cl) = unsafe {
        let st_c = NtCreateEvent(
            &raw mut ev,
            EVENT_ALL_ACCESS,
            core::ptr::null(),
            NOTIFICATION_EVENT,
            0,
        );
        let st_w0 = NtWaitForSingleObject(ev, 0, &raw const zero_timeout);
        let mut prev_s = -1i32;
        let st_s = NtSetEvent(ev, &raw mut prev_s);
        let st_w1 = NtWaitForSingleObject(ev, 0, &raw const zero_timeout);
        let mut prev_r = -1i32;
        let st_r = NtResetEvent(ev, &raw mut prev_r);
        let st_w2 = NtWaitForSingleObject(ev, 0, &raw const zero_timeout);
        let st_cl = NtClose(ev);
        (st_c, st_w0, st_s, prev_s, st_w1, st_r, prev_r, st_w2, st_cl)
    };
    let _ = writeln!(
        log,
        "NKT event.sync: create={:#010x} w0={} set={:#010x}/{} w1={:#010x} rst={:#010x}/{} w2={} close={:#010x}",
        st_c as u32,
        u8::from(st_w0 == STATUS_TIMEOUT),
        st_s as u32,
        prev_s,
        st_w1 as u32,
        st_r as u32,
        prev_r,
        u8::from(st_w2 == STATUS_TIMEOUT),
        st_cl as u32,
    );

    // SAFETY: deliberately invalid handle value.
    let st_bad = unsafe { NtClose(core::ptr::with_exposed_provenance_mut(0x7FFC)) };
    let _ = writeln!(
        log,
        "NKT handle.bad: close={:#010x} match={}",
        st_bad as u32,
        u8::from(st_bad == STATUS_INVALID_HANDLE),
    );
}

fn run_process_and_heap_tests(log: &mut Log, peb: *mut c_void) {
    let mut pbi = ProcessBasicInformation::default();
    let mut ret_len = 0u32;
    // SAFETY: querying current process basic information into stack struct.
    let st = unsafe {
        NtQueryInformationProcess(
            CURRENT_PROCESS,
            0, // ProcessBasicInformation
            (&raw mut pbi).cast(),
            size_of::<ProcessBasicInformation>() as u32,
            &raw mut ret_len,
        )
    };
    let _ = writeln!(
        log,
        "NKT proc.basic: status={:#010x} peb_eq={} pid_nz={} len={}",
        st as u32,
        u8::from(pbi.peb_base_address == peb && !peb.is_null()),
        u8::from(pbi.unique_process_id != 0),
        ret_len,
    );

    // Exercise ntdll's process heap (`PEB.ProcessHeap` at offset 0x30).
    let mut heap_ok = false;
    if !peb.is_null() {
        // SAFETY: `PEB.ProcessHeap` at offset 0x30 is initialised by ntdll before entry.
        unsafe {
            let heap = peb.cast::<u8>().add(0x30).cast::<*mut c_void>().read();
            if !heap.is_null() {
                let block = RtlAllocateHeap(heap, 0, 128);
                if !block.is_null() {
                    block.cast::<u64>().write_volatile(0xCAFE_BABE_DEAD_BEEF);
                    heap_ok = block.cast::<u64>().read_volatile() == 0xCAFE_BABE_DEAD_BEEF;
                    let _ = RtlFreeHeap(heap, 0, block);
                }
            }
        }
    }
    let _ = writeln!(log, "NKT heap.alloc: ok={}", u8::from(heap_ok));
}

/// Native process entry point invoked by `ntdll!LdrInitializeThunk`.
///
/// # Safety
/// Called by Windows / NK with `peb` pointing to the process's live `PEB`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn NtProcessStartup(peb: *mut c_void) -> ! {
    let mut log = Log::new();
    let _ = writeln!(log, "NKT start");
    run_vm_tests(&mut log);
    run_event_and_handle_tests(&mut log);
    run_process_and_heap_tests(&mut log, peb);
    let _ = writeln!(log, "NKT done");

    display_ascii(log.as_bytes());

    let mut path_buf = [0u16; 256];
    // SAFETY: `peb` is our process's PEB.
    let path_len = unsafe { output_path_from_peb(peb, &mut path_buf) };
    if path_len > 0 {
        write_transcript_file(&path_buf[..path_len], log.as_bytes());
    }

    // SAFETY: terminates this process cleanly.
    unsafe {
        let _ = NtTerminateProcess(CURRENT_PROCESS, STATUS_SUCCESS);
    }
    loop {
        core::hint::spin_loop();
    }
}

#[panic_handler]
fn panic(_: &PanicInfo<'_>) -> ! {
    // SAFETY: exit with an unmistakable error status on panic.
    unsafe {
        let _ = NtTerminateProcess(CURRENT_PROCESS, 0xC000_0001u32 as NtStatus);
    }
    loop {
        core::hint::spin_loop();
    }
}
