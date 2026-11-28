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
use core::sync::atomic::{AtomicU32, Ordering};

type NtStatus = i32;
type Handle = *mut c_void;

const CURRENT_PROCESS: Handle = -1isize as Handle;
const CURRENT_THREAD: Handle = -2isize as Handle;

const STATUS_SUCCESS: NtStatus = 0;
const STATUS_TIMEOUT: NtStatus = 0x0000_0102;
const STATUS_GUARD_PAGE_VIOLATION: u32 = 0x8000_0001;
const STATUS_ACCESS_VIOLATION: u32 = 0xC000_0005;
const STATUS_INVALID_HANDLE: NtStatus = 0xC000_0008u32 as NtStatus;
const STATUS_MUTANT_NOT_OWNED: NtStatus = 0xC000_0046u32 as NtStatus;
const STATUS_SEMAPHORE_LIMIT_EXCEEDED: NtStatus = 0xC000_0047u32 as NtStatus;

const MEM_COMMIT: u32 = 0x0000_1000;
const MEM_RESERVE: u32 = 0x0000_2000;
const MEM_RELEASE: u32 = 0x0000_8000;

const PAGE_READONLY: u32 = 0x02;
const PAGE_READWRITE: u32 = 0x04;
const PAGE_WRITECOPY: u32 = 0x08;
const PAGE_GUARD: u32 = 0x100;

const SEC_COMMIT: u32 = 0x0800_0000;
const SECTION_ALL_ACCESS: u32 = 0x000F_001F;
const VIEW_UNMAP: u32 = 2;

const OBJ_CASE_INSENSITIVE: u32 = 0x40;
const FILE_OVERWRITE_IF: u32 = 5;
const FILE_SYNCHRONOUS_IO_NONALERT: u32 = 0x20;
const FILE_NON_DIRECTORY_FILE: u32 = 0x40;
const FILE_GENERIC_WRITE: u32 = 0x4010_0000;
const FILE_SHARE_READ: u32 = 1;
const FILE_ATTRIBUTE_NORMAL: u32 = 0x80;

const NOTIFICATION_EVENT: u32 = 0;
const EVENT_ALL_ACCESS: u32 = 0x001F_0003;
const MUTANT_ALL_ACCESS: u32 = 0x001F_0001;
const SEMAPHORE_ALL_ACCESS: u32 = 0x001F_0003;
const IO_COMPLETION_ALL_ACCESS: u32 = 0x001F_0003;
const TIMER_ALL_ACCESS: u32 = 0x001F_0003;
const THREAD_ALL_ACCESS: u32 = 0x001F_FFFF;
const DIRECTORY_QUERY_TRAVERSE: u32 = 0x0003;
const SYMBOLIC_LINK_QUERY: u32 = 0x0001;

const EXCEPTION_CONTINUE_EXECUTION: i32 = -1;
const EXCEPTION_CONTINUE_SEARCH: i32 = 0;

#[repr(C)]
#[derive(Clone, Copy)]
struct UnicodeString {
    length: u16,
    maximum_length: u16,
    buffer: *mut u16,
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

#[repr(C)]
#[derive(Clone, Copy, Default)]
struct FileIoCompletionInformation {
    key_context: usize,
    apc_context: usize,
    status: usize,
    information: usize,
}

#[repr(C)]
struct ExceptionRecord {
    exception_code: u32,
    exception_flags: u32,
    exception_record: *mut ExceptionRecord,
    exception_address: *mut c_void,
    number_parameters: u32,
    _pad0: u32,
    exception_information: [usize; 15],
}

#[repr(C)]
struct ExceptionPointers {
    exception_record: *mut ExceptionRecord,
    context_record: *mut c_void,
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
    fn NtCreateSection(
        section_handle: *mut Handle,
        desired_access: u32,
        object_attributes: *const ObjectAttributes,
        maximum_size: *const i64,
        section_page_protection: u32,
        allocation_attributes: u32,
        file_handle: Handle,
    ) -> NtStatus;
    fn NtMapViewOfSection(
        section_handle: Handle,
        process_handle: Handle,
        base_address: *mut *mut c_void,
        zero_bits: usize,
        commit_size: usize,
        section_offset: *mut i64,
        view_size: *mut usize,
        inherit_disposition: u32,
        allocation_type: u32,
        win32_protect: u32,
    ) -> NtStatus;
    fn NtUnmapViewOfSection(process_handle: Handle, base_address: *mut c_void) -> NtStatus;
    fn NtCreateEvent(
        handle: *mut Handle,
        desired_access: u32,
        object_attributes: *const ObjectAttributes,
        event_type: u32,
        initial_state: u8,
    ) -> NtStatus;
    fn NtSetEvent(handle: Handle, previous_state: *mut i32) -> NtStatus;
    fn NtResetEvent(handle: Handle, previous_state: *mut i32) -> NtStatus;
    fn NtCreateMutant(
        handle: *mut Handle,
        desired_access: u32,
        object_attributes: *const ObjectAttributes,
        initial_owner: u8,
    ) -> NtStatus;
    fn NtReleaseMutant(handle: Handle, previous_count: *mut i32) -> NtStatus;
    fn NtCreateSemaphore(
        handle: *mut Handle,
        desired_access: u32,
        object_attributes: *const ObjectAttributes,
        initial_count: i32,
        maximum_count: i32,
    ) -> NtStatus;
    fn NtReleaseSemaphore(handle: Handle, release_count: i32, previous_count: *mut i32)
    -> NtStatus;
    fn NtWaitForSingleObject(handle: Handle, alertable: u8, timeout: *const i64) -> NtStatus;
    fn NtWaitForMultipleObjects(
        count: u32,
        handles: *const Handle,
        wait_type: u32,
        alertable: u8,
        timeout: *const i64,
    ) -> NtStatus;
    fn NtCreateIoCompletion(
        handle: *mut Handle,
        desired_access: u32,
        object_attributes: *const ObjectAttributes,
        concurrent_threads: u32,
    ) -> NtStatus;
    fn NtSetIoCompletion(
        handle: Handle,
        key_context: usize,
        apc_context: usize,
        io_status: NtStatus,
        io_info: usize,
    ) -> NtStatus;
    fn NtRemoveIoCompletionEx(
        handle: Handle,
        entries: *mut FileIoCompletionInformation,
        count: u32,
        removed: *mut u32,
        timeout: *const i64,
        alertable: u8,
    ) -> NtStatus;
    fn NtCreateWaitCompletionPacket(
        handle: *mut Handle,
        desired_access: u32,
        object_attributes: *const ObjectAttributes,
    ) -> NtStatus;
    fn NtAssociateWaitCompletionPacket(
        wcp: Handle,
        iocp: Handle,
        target: Handle,
        key_context: usize,
        apc_context: usize,
        io_status: NtStatus,
        io_info: usize,
        already_signaled: *mut u8,
    ) -> NtStatus;
    fn NtCreateTimer2(
        handle: *mut Handle,
        reserved1: *mut c_void,
        object_attributes: *const ObjectAttributes,
        attributes: u32,
        desired_access: u32,
    ) -> NtStatus;
    fn NtSetTimer2(
        handle: Handle,
        due_time: *const i64,
        period: *const i64,
        parameters: *const c_void,
    ) -> NtStatus;
    fn NtCreateThreadEx(
        thread_handle: *mut Handle,
        desired_access: u32,
        object_attributes: *const ObjectAttributes,
        process_handle: Handle,
        start_routine: *mut c_void,
        argument: *mut c_void,
        create_flags: u32,
        zero_bits: usize,
        stack_size: usize,
        max_stack_size: usize,
        attribute_list: *mut c_void,
    ) -> NtStatus;
    fn NtResumeThread(thread_handle: Handle, previous_suspend_count: *mut u32) -> NtStatus;
    fn NtQueueApcThread(
        thread_handle: Handle,
        apc_routine: unsafe extern "system" fn(*mut c_void, *mut c_void, *mut c_void),
        arg1: *mut c_void,
        arg2: *mut c_void,
        arg3: *mut c_void,
    ) -> NtStatus;
    fn NtTestAlert() -> NtStatus;
    fn NtOpenDirectoryObject(
        handle: *mut Handle,
        desired_access: u32,
        object_attributes: *const ObjectAttributes,
    ) -> NtStatus;
    fn NtOpenSymbolicLinkObject(
        handle: *mut Handle,
        desired_access: u32,
        object_attributes: *const ObjectAttributes,
    ) -> NtStatus;
    fn NtQuerySymbolicLinkObject(
        handle: Handle,
        target: *mut UnicodeString,
        returned_length: *mut u32,
    ) -> NtStatus;
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
    fn NtTerminateThread(thread: Handle, exit_status: NtStatus) -> NtStatus;
    fn NtTerminateProcess(process: Handle, exit_status: NtStatus) -> NtStatus;
    fn RtlAllocateHeap(heap: *mut c_void, flags: u32, size: usize) -> *mut c_void;
    fn RtlFreeHeap(heap: *mut c_void, flags: u32, base: *mut c_void) -> u8;
    fn RtlAddVectoredExceptionHandler(
        first: u32,
        handler: unsafe extern "system" fn(*mut ExceptionPointers) -> i32,
    ) -> *mut c_void;
    fn RtlRemoveVectoredExceptionHandler(handle: *mut c_void) -> u32;
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
            buffer: wide.as_mut_ptr(),
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
        buffer: path.as_ptr().cast_mut(),
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

fn run_section_tests(log: &mut Log) {
    let mut sec: Handle = core::ptr::null_mut();
    let max_size: i64 = 0x2000;
    // SAFETY: stack locals.
    let st_c = unsafe {
        NtCreateSection(
            &raw mut sec,
            SECTION_ALL_ACCESS,
            core::ptr::null(),
            &raw const max_size,
            PAGE_READWRITE,
            SEC_COMMIT,
            core::ptr::null_mut(),
        )
    };
    let mut shared_ok = false;
    let mut cow_ok = false;
    if st_c == STATUS_SUCCESS {
        let mut v1: *mut c_void = core::ptr::null_mut();
        let mut v2: *mut c_void = core::ptr::null_mut();
        let mut v3: *mut c_void = core::ptr::null_mut();
        let (mut s1, mut s2, mut s3) = (0usize, 0usize, 0usize);
        // SAFETY: mapping 3 views of `sec`, testing shared write + CoW isolation, then unmapping.
        unsafe {
            let r1 = NtMapViewOfSection(
                sec,
                CURRENT_PROCESS,
                &raw mut v1,
                0,
                0,
                core::ptr::null_mut(),
                &raw mut s1,
                VIEW_UNMAP,
                0,
                PAGE_READWRITE,
            );
            let r2 = NtMapViewOfSection(
                sec,
                CURRENT_PROCESS,
                &raw mut v2,
                0,
                0,
                core::ptr::null_mut(),
                &raw mut s2,
                VIEW_UNMAP,
                0,
                PAGE_READWRITE,
            );
            let r3 = NtMapViewOfSection(
                sec,
                CURRENT_PROCESS,
                &raw mut v3,
                0,
                0,
                core::ptr::null_mut(),
                &raw mut s3,
                VIEW_UNMAP,
                0,
                PAGE_WRITECOPY,
            );
            if r1 == STATUS_SUCCESS && r2 == STATUS_SUCCESS && r3 == STATUS_SUCCESS {
                v1.cast::<u64>().write_volatile(0x1234_5678_9ABC_DEF0);
                shared_ok = v2.cast::<u64>().read_volatile() == 0x1234_5678_9ABC_DEF0
                    && v3.cast::<u64>().read_volatile() == 0x1234_5678_9ABC_DEF0;
                v3.cast::<u64>().write_volatile(0xDEAD_BEEF_CAFE_BABE);
                cow_ok = v3.cast::<u64>().read_volatile() == 0xDEAD_BEEF_CAFE_BABE
                    && v1.cast::<u64>().read_volatile() == 0x1234_5678_9ABC_DEF0;
            }
            if !v3.is_null() {
                let _ = NtUnmapViewOfSection(CURRENT_PROCESS, v3);
            }
            if !v2.is_null() {
                let _ = NtUnmapViewOfSection(CURRENT_PROCESS, v2);
            }
            if !v1.is_null() {
                let _ = NtUnmapViewOfSection(CURRENT_PROCESS, v1);
            }
            let _ = NtClose(sec);
        }
    }
    let _ = writeln!(
        log,
        "NKT section.cow: create={:#010x} shared={} cow={}",
        st_c as u32,
        u8::from(shared_ok),
        u8::from(cow_ok),
    );
}

fn run_event_and_sync_tests(log: &mut Log) {
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

    // Mutant, semaphore, and NtWaitForMultipleObjects (WaitAny & WaitAll).
    let mut mut_h: Handle = core::ptr::null_mut();
    let mut sem_h: Handle = core::ptr::null_mut();
    let mut e1: Handle = core::ptr::null_mut();
    let mut e2: Handle = core::ptr::null_mut();
    // SAFETY: stack locals and kernel sync objects.
    let (mut_ok, sem_ok, multi_ok) = unsafe {
        let mut mut_ok = false;
        if NtCreateMutant(&raw mut mut_h, MUTANT_ALL_ACCESS, core::ptr::null(), 1) == STATUS_SUCCESS
        {
            let w = NtWaitForSingleObject(mut_h, 0, &raw const zero_timeout);
            let (mut p1, mut p2) = (-99i32, -99i32);
            let r1 = NtReleaseMutant(mut_h, &raw mut p1);
            let r2 = NtReleaseMutant(mut_h, &raw mut p2);
            let r3 = NtReleaseMutant(mut_h, core::ptr::null_mut());
            mut_ok = w == STATUS_SUCCESS
                && r1 == STATUS_SUCCESS
                && p1 == -1
                && r2 == STATUS_SUCCESS
                && p2 == 0
                && r3 == STATUS_MUTANT_NOT_OWNED;
            let _ = NtClose(mut_h);
        }

        let mut sem_ok = false;
        if NtCreateSemaphore(
            &raw mut sem_h,
            SEMAPHORE_ALL_ACCESS,
            core::ptr::null(),
            1,
            2,
        ) == STATUS_SUCCESS
        {
            let w0 = NtWaitForSingleObject(sem_h, 0, &raw const zero_timeout);
            let w1 = NtWaitForSingleObject(sem_h, 0, &raw const zero_timeout);
            let mut prev = -1i32;
            let r_ok = NtReleaseSemaphore(sem_h, 1, &raw mut prev);
            let r_over = NtReleaseSemaphore(sem_h, 2, core::ptr::null_mut());
            sem_ok = w0 == STATUS_SUCCESS
                && w1 == STATUS_TIMEOUT
                && r_ok == STATUS_SUCCESS
                && prev == 0
                && r_over == STATUS_SEMAPHORE_LIMIT_EXCEEDED;
            let _ = NtClose(sem_h);
        }

        let mut multi_ok = false;
        if NtCreateEvent(
            &raw mut e1,
            EVENT_ALL_ACCESS,
            core::ptr::null(),
            NOTIFICATION_EVENT,
            0,
        ) == STATUS_SUCCESS
            && NtCreateEvent(
                &raw mut e2,
                EVENT_ALL_ACCESS,
                core::ptr::null(),
                NOTIFICATION_EVENT,
                1,
            ) == STATUS_SUCCESS
        {
            let arr = [e1, e2];
            let any = NtWaitForMultipleObjects(2, arr.as_ptr(), 1, 0, &raw const zero_timeout);
            let all0 = NtWaitForMultipleObjects(2, arr.as_ptr(), 0, 0, &raw const zero_timeout);
            let _ = NtSetEvent(e1, core::ptr::null_mut());
            let all1 = NtWaitForMultipleObjects(2, arr.as_ptr(), 0, 0, &raw const zero_timeout);
            multi_ok = any == 1 && all0 == STATUS_TIMEOUT && all1 == STATUS_SUCCESS;
            let _ = NtClose(e1);
            let _ = NtClose(e2);
        }
        (mut_ok, sem_ok, multi_ok)
    };
    let _ = writeln!(
        log,
        "NKT sync.multi: mutant={} sem={} wait_multi={}",
        u8::from(mut_ok),
        u8::from(sem_ok),
        u8::from(multi_ok),
    );
}

fn run_tp_tests(log: &mut Log) {
    let mut iocp: Handle = core::ptr::null_mut();
    let mut wcp: Handle = core::ptr::null_mut();
    let mut ev: Handle = core::ptr::null_mut();
    let mut timer: Handle = core::ptr::null_mut();
    // SAFETY: stack locals and NT threadpool primitives.
    let (iocp_ok, wcp_ok, timer_ok) = unsafe {
        let mut iocp_ok = false;
        let mut wcp_ok = false;
        if NtCreateIoCompletion(
            &raw mut iocp,
            IO_COMPLETION_ALL_ACCESS,
            core::ptr::null(),
            1,
        ) == STATUS_SUCCESS
        {
            let st_set = NtSetIoCompletion(iocp, 0x1111, 0x2222, 0, 0x3333);
            let mut pkt = [FileIoCompletionInformation::default(); 2];
            let mut rem = 0u32;
            let zero: i64 = 0;
            let st_rem =
                NtRemoveIoCompletionEx(iocp, pkt.as_mut_ptr(), 2, &raw mut rem, &raw const zero, 0);
            iocp_ok = st_set == STATUS_SUCCESS
                && st_rem == STATUS_SUCCESS
                && rem == 1
                && pkt[0].key_context == 0x1111
                && pkt[0].apc_context == 0x2222
                && pkt[0].information == 0x3333;

            if NtCreateWaitCompletionPacket(&raw mut wcp, 1, core::ptr::null()) == STATUS_SUCCESS
                && NtCreateEvent(
                    &raw mut ev,
                    EVENT_ALL_ACCESS,
                    core::ptr::null(),
                    NOTIFICATION_EVENT,
                    0,
                ) == STATUS_SUCCESS
            {
                let mut already = 0xFFu8;
                let st_assoc = NtAssociateWaitCompletionPacket(
                    wcp,
                    iocp,
                    ev,
                    0x4444,
                    0x5555,
                    0,
                    0x6666,
                    &raw mut already,
                );
                let _ = NtSetEvent(ev, core::ptr::null_mut());
                let mut rem2 = 0u32;
                let wait_1s: i64 = -10_000_000;
                let st_rem2 = NtRemoveIoCompletionEx(
                    iocp,
                    pkt.as_mut_ptr(),
                    2,
                    &raw mut rem2,
                    &raw const wait_1s,
                    0,
                );
                wcp_ok = st_assoc == STATUS_SUCCESS
                    && already == 0
                    && st_rem2 == STATUS_SUCCESS
                    && rem2 == 1
                    && pkt[0].key_context == 0x4444
                    && pkt[0].apc_context == 0x5555
                    && pkt[0].information == 0x6666;
                let _ = NtClose(ev);
                let _ = NtClose(wcp);
            }
            let _ = NtClose(iocp);
        }

        let mut timer_ok = false;
        if NtCreateTimer2(
            &raw mut timer,
            core::ptr::null_mut(),
            core::ptr::null(),
            0,
            TIMER_ALL_ACCESS,
        ) == STATUS_SUCCESS
        {
            let due: i64 = -100_000; // 10 ms relative
            let period: i64 = 0;
            let st_set = NtSetTimer2(timer, &raw const due, &raw const period, core::ptr::null());
            let timeout_2s: i64 = -20_000_000;
            let st_wait = NtWaitForSingleObject(timer, 0, &raw const timeout_2s);
            timer_ok = st_set == STATUS_SUCCESS && st_wait == STATUS_SUCCESS;
            let _ = NtClose(timer);
        }
        (iocp_ok, wcp_ok, timer_ok)
    };
    let _ = writeln!(
        log,
        "NKT tp.iocp: iocp={} wcp={} timer2={}",
        u8::from(iocp_ok),
        u8::from(wcp_ok),
        u8::from(timer_ok),
    );
}

static WORKER_SUM: AtomicU32 = AtomicU32::new(0);
static APC_COUNT: AtomicU32 = AtomicU32::new(0);

/// Worker thread entry point for `NtCreateThreadEx`.
///
/// # Safety
/// Invoked by `ntdll!RtlUserThreadStart` with the integer argument passed to `NtCreateThreadEx`.
unsafe extern "system" fn child_thread_entry(arg: *mut c_void) -> u32 {
    WORKER_SUM.fetch_add(arg.addr() as u32, Ordering::AcqRel);
    // SAFETY: cleanly terminate this worker thread.
    unsafe {
        let _ = NtTerminateThread(CURRENT_THREAD, STATUS_SUCCESS);
    }
    0
}

/// User APC callback invoked via `ntdll!KiUserApcDispatcher`.
///
/// # Safety
/// Invoked with the three opaque context pointers supplied to `NtQueueApcThread`.
unsafe extern "system" fn user_apc_callback(
    arg1: *mut c_void,
    arg2: *mut c_void,
    arg3: *mut c_void,
) {
    let sum = (arg1.addr() + arg2.addr() + arg3.addr()) as u32;
    APC_COUNT.fetch_add(sum, Ordering::AcqRel);
}

fn run_thread_and_apc_tests(log: &mut Log) {
    WORKER_SUM.store(0, Ordering::Release);
    APC_COUNT.store(0, Ordering::Release);

    let mut th: Handle = core::ptr::null_mut();
    // SAFETY: creating a suspended user thread, resuming it, joining it, and delivering a user APC.
    let (thread_ok, apc_ok) = unsafe {
        let st_ct = NtCreateThreadEx(
            &raw mut th,
            THREAD_ALL_ACCESS,
            core::ptr::null(),
            CURRENT_PROCESS,
            child_thread_entry as *const () as *mut c_void,
            core::ptr::with_exposed_provenance_mut(42),
            1, // THREAD_CREATE_FLAGS_CREATE_SUSPENDED
            0,
            0,
            0,
            core::ptr::null_mut(),
        );
        let mut thread_ok = false;
        if st_ct == STATUS_SUCCESS {
            let mut prev_susp = 0u32;
            let st_res = NtResumeThread(th, &raw mut prev_susp);
            let timeout_5s: i64 = -50_000_000;
            let st_join = NtWaitForSingleObject(th, 0, &raw const timeout_5s);
            thread_ok = st_res == STATUS_SUCCESS
                && prev_susp == 1
                && st_join == STATUS_SUCCESS
                && WORKER_SUM.load(Ordering::Acquire) == 42;
            let _ = NtClose(th);
        }

        let st_q = NtQueueApcThread(
            CURRENT_THREAD,
            user_apc_callback,
            core::ptr::with_exposed_provenance_mut(10),
            core::ptr::with_exposed_provenance_mut(20),
            core::ptr::with_exposed_provenance_mut(30),
        );
        let _ = NtTestAlert();
        let apc_ok = st_q == STATUS_SUCCESS && APC_COUNT.load(Ordering::Acquire) == 60;
        (thread_ok, apc_ok)
    };
    let _ = writeln!(
        log,
        "NKT thread.apc: thread={} apc={}",
        u8::from(thread_ok),
        u8::from(apc_ok),
    );
}

static VEH_GUARD_SEEN: AtomicU32 = AtomicU32::new(0);
static VEH_AV_SEEN: AtomicU32 = AtomicU32::new(0);
static VEH_AV_PAGE: core::sync::atomic::AtomicUsize = core::sync::atomic::AtomicUsize::new(0);

/// Vectored exception handler invoked by `ntdll!RtlDispatchException`.
///
/// # Safety
/// `info` is null or points to a valid `EXCEPTION_POINTERS` structure on the user stack.
unsafe extern "system" fn nkt_veh_handler(info: *mut ExceptionPointers) -> i32 {
    if info.is_null() {
        return EXCEPTION_CONTINUE_SEARCH;
    }
    // SAFETY: `info` and `info.exception_record` are supplied by `ntdll!RtlDispatchException`.
    let rec = unsafe { &*(*info).exception_record };
    if rec.exception_code == STATUS_GUARD_PAGE_VIOLATION {
        VEH_GUARD_SEEN.fetch_add(1, Ordering::AcqRel);
        return EXCEPTION_CONTINUE_EXECUTION;
    }
    if rec.exception_code == STATUS_ACCESS_VIOLATION {
        let target = VEH_AV_PAGE.load(Ordering::Acquire);
        if target != 0 && rec.number_parameters >= 2 && rec.exception_information[1] == target {
            let mut base = core::ptr::with_exposed_provenance_mut::<c_void>(target);
            let mut sz = 0x1000usize;
            let mut old = 0u32;
            // SAFETY: upgrading the faulting RO test page to RW so execution resumes cleanly.
            let st = unsafe {
                NtProtectVirtualMemory(
                    CURRENT_PROCESS,
                    &raw mut base,
                    &raw mut sz,
                    PAGE_READWRITE,
                    &raw mut old,
                )
            };
            if st == STATUS_SUCCESS {
                VEH_AV_SEEN.fetch_add(1, Ordering::AcqRel);
                return EXCEPTION_CONTINUE_EXECUTION;
            }
        }
    }
    EXCEPTION_CONTINUE_SEARCH
}

fn run_veh_tests(log: &mut Log) {
    VEH_GUARD_SEEN.store(0, Ordering::Release);
    VEH_AV_SEEN.store(0, Ordering::Release);
    VEH_AV_PAGE.store(0, Ordering::Release);

    // SAFETY: registering a VEH, deliberately triggering one-shot GUARD + RO-write AV, and cleaning up.
    let (guard_ok, av_ok) = unsafe {
        let veh = RtlAddVectoredExceptionHandler(1, nkt_veh_handler);
        let mut guard_ok = false;
        let mut av_ok = false;
        if !veh.is_null() {
            // 1. One-shot PAGE_GUARD exception caught and resumed.
            let mut gb: *mut c_void = core::ptr::null_mut();
            let mut gs: usize = 0x1000;
            if NtAllocateVirtualMemory(
                CURRENT_PROCESS,
                &raw mut gb,
                0,
                &raw mut gs,
                MEM_RESERVE | MEM_COMMIT,
                PAGE_READWRITE | PAGE_GUARD,
            ) == STATUS_SUCCESS
            {
                let p = gb.cast::<u64>();
                p.write_volatile(0x1357_2468);
                let v = p.read_volatile();
                guard_ok = v == 0x1357_2468 && VEH_GUARD_SEEN.load(Ordering::Acquire) == 1;
                let mut fb = gb;
                let mut fs = 0usize;
                let _ = NtFreeVirtualMemory(CURRENT_PROCESS, &raw mut fb, &raw mut fs, MEM_RELEASE);
            }

            // 2. Write AV on PAGE_READONLY caught, upgraded to PAGE_READWRITE, and resumed.
            let mut ab: *mut c_void = core::ptr::null_mut();
            let mut asz: usize = 0x1000;
            if NtAllocateVirtualMemory(
                CURRENT_PROCESS,
                &raw mut ab,
                0,
                &raw mut asz,
                MEM_RESERVE | MEM_COMMIT,
                PAGE_READONLY,
            ) == STATUS_SUCCESS
            {
                VEH_AV_PAGE.store(ab.addr(), Ordering::Release);
                let p = ab.cast::<u64>();
                p.write_volatile(0x9988_7766_5544_3322);
                let v = p.read_volatile();
                av_ok = v == 0x9988_7766_5544_3322 && VEH_AV_SEEN.load(Ordering::Acquire) == 1;
                VEH_AV_PAGE.store(0, Ordering::Release);
                let mut fb = ab;
                let mut fs = 0usize;
                let _ = NtFreeVirtualMemory(CURRENT_PROCESS, &raw mut fb, &raw mut fs, MEM_RELEASE);
            }

            let _ = RtlRemoveVectoredExceptionHandler(veh);
        }
        (guard_ok, av_ok)
    };
    let _ = writeln!(
        log,
        "NKT seh.veh: guard={} av={}",
        u8::from(guard_ok),
        u8::from(av_ok),
    );
}

fn run_ob_dir_tests(log: &mut Log) {
    let mut known_name: [u16; 10] = [
        u16::from(b'\\'),
        u16::from(b'K'),
        u16::from(b'n'),
        u16::from(b'o'),
        u16::from(b'w'),
        u16::from(b'n'),
        u16::from(b'D'),
        u16::from(b'l'),
        u16::from(b'l'),
        u16::from(b's'),
    ];
    let dir_us = UnicodeString {
        length: (known_name.len() * 2) as u16,
        maximum_length: (known_name.len() * 2) as u16,
        buffer: known_name.as_mut_ptr(),
    };
    let dir_oa = ObjectAttributes {
        length: size_of::<ObjectAttributes>() as u32,
        root_directory: core::ptr::null_mut(),
        object_name: &raw const dir_us,
        attributes: OBJ_CASE_INSENSITIVE,
        security_descriptor: core::ptr::null_mut(),
        security_qos: core::ptr::null_mut(),
    };
    let mut link_name: [u16; 12] = [
        u16::from(b'K'),
        u16::from(b'n'),
        u16::from(b'o'),
        u16::from(b'w'),
        u16::from(b'n'),
        u16::from(b'D'),
        u16::from(b'l'),
        u16::from(b'l'),
        u16::from(b'P'),
        u16::from(b'a'),
        u16::from(b't'),
        u16::from(b'h'),
    ];
    let mut dir_h: Handle = core::ptr::null_mut();
    // SAFETY: stack locals and NT namespace queries.
    let (st_dir, link_ok) = unsafe {
        let st_dir =
            NtOpenDirectoryObject(&raw mut dir_h, DIRECTORY_QUERY_TRAVERSE, &raw const dir_oa);
        let mut link_ok = false;
        if st_dir == STATUS_SUCCESS {
            let link_us = UnicodeString {
                length: (link_name.len() * 2) as u16,
                maximum_length: (link_name.len() * 2) as u16,
                buffer: link_name.as_mut_ptr(),
            };
            let link_oa = ObjectAttributes {
                length: size_of::<ObjectAttributes>() as u32,
                root_directory: dir_h,
                object_name: &raw const link_us,
                attributes: OBJ_CASE_INSENSITIVE,
                security_descriptor: core::ptr::null_mut(),
                security_qos: core::ptr::null_mut(),
            };
            let mut link_h: Handle = core::ptr::null_mut();
            if NtOpenSymbolicLinkObject(&raw mut link_h, SYMBOLIC_LINK_QUERY, &raw const link_oa)
                == STATUS_SUCCESS
            {
                let mut target_buf = [0u16; 128];
                let mut target_us = UnicodeString {
                    length: 0,
                    maximum_length: (target_buf.len() * 2) as u16,
                    buffer: target_buf.as_mut_ptr(),
                };
                let mut ret_len = 0u32;
                let st_q = NtQuerySymbolicLinkObject(link_h, &raw mut target_us, &raw mut ret_len);
                link_ok = st_q == STATUS_SUCCESS && target_us.length > 0;
                let _ = NtClose(link_h);
            }
            let _ = NtClose(dir_h);
        }
        (st_dir, link_ok)
    };
    let _ = writeln!(
        log,
        "NKT ob.dir: open={:#010x} link={}",
        st_dir as u32,
        u8::from(link_ok),
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
    run_section_tests(&mut log);
    run_event_and_sync_tests(&mut log);
    run_tp_tests(&mut log);
    run_thread_and_apc_tests(&mut log);
    run_veh_tests(&mut log);
    run_ob_dir_tests(&mut log);
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
