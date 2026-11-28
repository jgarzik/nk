//! Ring 3 transition, `SYSCALL`/`SYSRETQ`, `KUSER_SHARED_DATA` read-only user
//! alias, user GS (`TEB`), and Ring 3 privilege-isolation self-tests.

use crate::test::{Group, Report};
use nk_bootinfo::BootInfo;

pub static GROUP: Group = Group {
    names: &["user.stub", "user.vm", "user.section"],
    run,
    manual: false,
};

pub static NKT: Group = Group {
    names: &["user.nkt"],
    run: run_nkt,
    manual: true,
};

pub static AUTOCHK_CLEAN: Group = Group {
    names: &["user.autochk.clean"],
    run: run_autochk_clean,
    manual: true,
};

pub static AUTOCHK_DIRTY: Group = Group {
    names: &["user.autochk.dirty"],
    run: run_autochk_dirty,
    manual: true,
};

pub static SVC_TRAP: Group = Group {
    names: &["user.svc_trap"],
    run: run_svc_trap,
    manual: true,
};

pub static GROUPS: &[&Group] = &[&GROUP, &NKT, &AUTOCHK_CLEAN, &AUTOCHK_DIRTY, &SVC_TRAP];

#[cfg(not(target_arch = "x86_64"))]
fn run(r: &mut Report, _info: &BootInfo) {
    r.skip("user.stub", format_args!("x86-64 only"));
    r.skip("user.vm", format_args!("x86-64 only"));
    r.skip("user.section", format_args!("x86-64 only"));
}

#[cfg(not(target_arch = "x86_64"))]
fn run_nkt(r: &mut Report, _info: &BootInfo) {
    r.skip("user.nkt", format_args!("x86-64 only"));
}

#[cfg(not(target_arch = "x86_64"))]
fn run_autochk_clean(r: &mut Report, _info: &BootInfo) {
    r.skip("user.autochk.clean", format_args!("x86-64 only"));
}

#[cfg(not(target_arch = "x86_64"))]
fn run_autochk_dirty(r: &mut Report, _info: &BootInfo) {
    r.skip("user.autochk.dirty", format_args!("x86-64 only"));
}

#[cfg(not(target_arch = "x86_64"))]
fn run_svc_trap(r: &mut Report, _info: &BootInfo) {
    r.skip("user.svc_trap", format_args!("x86-64 only"));
}

#[cfg(target_arch = "x86_64")]
mod x64 {
    use crate::arch;
    use crate::ke::{thread, wait};
    use crate::mm;
    use crate::ob::object;
    use crate::ps::process;
    use core::arch::global_asm;
    use nk_mm::pt::Prot;
    use nk_ntabi::ke::XSTATE_MASK_AVX;
    use nk_ntabi::status::{
        STATUS_ACCESS_VIOLATION, STATUS_INVALID_HANDLE, STATUS_PRIVILEGED_INSTRUCTION,
        STATUS_SUCCESS,
    };

    const CODE_VA: u64 = 0x0040_0000;
    const DATA_VA: u64 = 0x0041_0000;
    const STACK_RSP: u64 = DATA_VA + 0xF00;
    const TEB_VA: u64 = DATA_VA + 0x100;

    // Assemble Ring 3 user-mode test stubs in `.rdata` (copied into a `USER_RX`
    // page in the test process's isolated `AddressSpace`).
    global_asm!(
        r#"
    .section .rdata
    .balign 16
    .globl nk_user_stub_main
nk_user_stub_main:
    // rcx = DATA_VA (0x0041_0000)
    mov r12, rcx
    // Load distinct sentinel values into every non-volatile GPR so we can
    // verify `syscall`/`sysretq` preserves all of them.
    mov rbx, 0x1111222233334444
    mov rbp, 0x2222333344445555
    mov r13, 0x3333444455556666
    mov r14, 0x4444555566667777
    mov r15, 0x5555666677778888

    // 1. Read KUSER_SHARED_DATA read-only alias at 0x7FFE_0000.
    mov r11d, 0x7FFE0000
    mov eax, dword ptr [r11 + 0x26C]     // NtMajorVersion
    mov dword ptr [r12 + 0x00], eax
    mov eax, dword ptr [r11 + 0x260]     // NtBuildNumber
    mov dword ptr [r12 + 0x04], eax
    mov eax, dword ptr [r11 + 0x330]     // Cookie
    mov dword ptr [r12 + 0x08], eax

    // 2. Read user TEB self-pointer via gs:[0x30].
    mov rax, gs:[0x30]
    mov qword ptr [r12 + 0x10], rax

    // 3. Syscall #1: NtClose(0x1234) -> STATUS_INVALID_HANDLE (0 stack args).
    mov r10d, 0x1234
    mov eax, 15                          // nr::NtClose
    syscall
    mov dword ptr [r12 + 0x18], eax

    // 4. Syscall #2: NtCreateEvent(&handle, 0x1F0003, NULL, 0, 1) (1 stack arg!).
    sub rsp, 0x40
    mov qword ptr [rsp + 0x28], 1        // InitialState = TRUE (stack arg 0)
    lea r10, [r12 + 0x20]                // EventHandle
    mov edx, 0x1F0003                    // EVENT_ALL_ACCESS
    xor r8d, r8d                         // ObjectAttributes = NULL
    xor r9d, r9d                         // NotificationEvent = 0
    mov eax, 72                          // nr::NtCreateEvent
    syscall
    add rsp, 0x40
    mov dword ptr [r12 + 0x1C], eax

    // 5. Syscall #3: NtClose(handle) -> STATUS_SUCCESS.
    mov r10, qword ptr [r12 + 0x20]
    mov eax, 15                          // nr::NtClose
    syscall
    mov dword ptr [r12 + 0x24], eax

    // 6. Syscall #4: NtQuerySystemInformation(0, DATA+0x200, 64, DATA+0x2C).
    xor r10d, r10d                       // SystemBasicInformation
    lea rdx, [r12 + 0x200]
    mov r8d, 64
    lea r9, [r12 + 0x2C]
    mov eax, 54                          // nr::NtQuerySystemInformation
    syscall
    mov dword ptr [r12 + 0x28], eax

    // 7. If AVX is advertised in KUSER_SHARED_DATA.XState.EnabledFeatures,
    //    execute 256-bit `vmovdqu` round-trip in Ring 3.
    mov r11d, 0x7FFE0000
    mov rax, qword ptr [r11 + 0x3D8]
    test al, 4
    jz 2f
    vmovdqu ymm0, ymmword ptr [r12 + 0x80]
    vmovdqu ymmword ptr [r12 + 0xA0], ymm0
    vzeroupper
2:

    // 8. Verify every non-volatile GPR survived all syscalls.
    mov rax, 0x1111222233334444
    cmp rbx, rax
    jne 3f
    mov rax, 0x2222333344445555
    cmp rbp, rax
    jne 3f
    mov rax, 0x3333444455556666
    cmp r13, rax
    jne 3f
    mov rax, 0x4444555566667777
    cmp r14, rax
    jne 3f
    mov rax, 0x5555666677778888
    cmp r15, rax
    jne 3f
    mov dword ptr [r12 + 0x30], 1
3:

    // 9. Syscall #5: NtTerminateThread(0, 0) -> cleanly exits this thread.
    xor r10d, r10d
    xor edx, edx
    mov eax, 83                          // nr::NtTerminateThread
    syscall
    ud2
    .globl nk_user_stub_main_end
nk_user_stub_main_end:

    .balign 16
    .globl nk_user_stub_write_kusd
nk_user_stub_write_kusd:
    mov eax, 0x7FFE0000
    mov dword ptr [rax], 1
    ud2
    .globl nk_user_stub_write_kusd_end
nk_user_stub_write_kusd_end:

    .balign 16
    .globl nk_user_stub_read_kernel
nk_user_stub_read_kernel:
    mov rax, 0xFFFFF78000000000
    mov eax, dword ptr [rax]
    ud2
    .globl nk_user_stub_read_kernel_end
nk_user_stub_read_kernel_end:

    .balign 16
    .globl nk_user_stub_cli
nk_user_stub_cli:
    cli
    ud2
    .globl nk_user_stub_cli_end
nk_user_stub_cli_end:
    .text
"#
    );

    unsafe extern "C" {
        static nk_user_stub_main: u8;
        static nk_user_stub_main_end: u8;
        static nk_user_stub_write_kusd: u8;
        static nk_user_stub_write_kusd_end: u8;
        static nk_user_stub_read_kernel: u8;
        static nk_user_stub_read_kernel_end: u8;
        static nk_user_stub_cli: u8;
        static nk_user_stub_cli_end: u8;
    }

    fn run_user_snippet(
        proc: *mut u8,
        code_pa: u64,
        start: *const u8,
        end: *const u8,
        teb: u64,
    ) -> Result<(), &'static str> {
        // SAFETY: `start..end` is a valid `.rdata` stub smaller than one page;
        // `code_pa` is our owned physical code frame mapped at `CODE_VA`.
        unsafe {
            let len = end.offset_from(start) as usize;
            assert!(len <= mm::PAGE_SIZE);
            let dst = mm::phys_to_virt(code_pa);
            core::ptr::write_bytes(dst, 0xCC, mm::PAGE_SIZE);
            core::ptr::copy_nonoverlapping(start, dst, len);
        }

        fn enter_trampoline(arg: usize) {
            let _ = arg;
            // SAFETY: thread belongs to `proc`, which has `CODE_VA` mapped `USER_RX`
            // and `DATA_VA` mapped `USER_RW`.
            unsafe { arch::user::enter_user_mode(CODE_VA, STACK_RSP, DATA_VA, 0) }
        }

        let t = thread::create_unstarted(
            enter_trampoline,
            0,
            thread::NORMAL_PRIORITY,
            thread::ANYWHERE,
        )?;
        // SAFETY: `t` is unstarted and `proc` is a live process.
        unsafe {
            thread::assign_process(t, proc);
            thread::set_teb(t, teb);
            thread::begin(t);
            wait::KeWaitForSingleObject(t.cast(), 0, 0, 0, core::ptr::null());
            object::dereference(t.cast());
        }
        Ok(())
    }

    pub fn run() -> Result<(), &'static str> {
        // SAFETY: `process::system()` is live for the lifetime of the kernel.
        let proc_ref = unsafe { process::create_minimal(b"stub.exe", process::system(), false) }
            .map_err(|_| "failed to create stub user process")?;
        let proc = proc_ref.body();
        // SAFETY: `proc_ref` keeps `proc` alive for the entire test.
        let Some(space) = (unsafe { process::address_space(proc) }) else {
            return Err("stub user process has no AddressSpace");
        };
        let Some(code_pa) = mm::alloc_frames(1) else {
            return Err("out of memory for user stub code page");
        };
        let Some(data_pa) = mm::alloc_frames(1) else {
            mm::free_frames(code_pa, 1);
            return Err("out of memory for user stub data/stack page");
        };
        if space.map_page(CODE_VA, code_pa, Prot::USER_RX).is_err()
            || space.map_page(DATA_VA, data_pa, Prot::USER_RW).is_err()
        {
            let _ = space.unmap_page(CODE_VA);
            let _ = space.unmap_page(DATA_VA);
            mm::free_frames(code_pa, 1);
            mm::free_frames(data_pa, 1);
            return Err("failed to map user stub pages");
        }

        let avx_pattern: [u64; 4] = [
            0x0123_4567_89AB_CDEF,
            0xFEDC_BA98_7654_3210,
            0xCAFE_BABE_1234_5678,
            0xDEAD_BEEF_90AB_CDEF,
        ];
        // Populate fake TEB self pointer at TEB + 0x30 and AVX input at DATA + 0x80.
        // SAFETY: `data_pa` is our owned zeroed page reachable via the direct map.
        unsafe {
            let base = mm::phys_to_virt(data_pa);
            base.add(0x130).cast::<u64>().write(TEB_VA);
            base.add(0x80).cast::<[u64; 4]>().write(avx_pattern);
        }

        let res = (|| -> Result<(), &'static str> {
            run_user_snippet(
                proc,
                code_pa,
                &raw const nk_user_stub_main,
                &raw const nk_user_stub_main_end,
                TEB_VA,
            )?;

            // Inspect results written by Ring 3 code through the direct map.
            // SAFETY: the user thread has exited; `data_pa` is exclusively ours.
            let (
                major,
                build,
                cookie,
                teb_seen,
                close_bad,
                create_ev,
                handle,
                close_ok,
                qsi,
                qsi_len,
                nonvol,
                avx_out,
            ) = unsafe {
                let b = mm::phys_to_virt(data_pa);
                (
                    b.add(0x00).cast::<u32>().read(),
                    b.add(0x04).cast::<u32>().read(),
                    b.add(0x08).cast::<u32>().read(),
                    b.add(0x10).cast::<u64>().read(),
                    b.add(0x18).cast::<i32>().read(),
                    b.add(0x1C).cast::<i32>().read(),
                    b.add(0x20).cast::<u64>().read(),
                    b.add(0x24).cast::<i32>().read(),
                    b.add(0x28).cast::<i32>().read(),
                    b.add(0x2C).cast::<u32>().read(),
                    b.add(0x30).cast::<u32>().read(),
                    b.add(0xA0).cast::<[u64; 4]>().read(),
                )
            };
            if major != 10 || build != 19045 || cookie == 0 {
                return Err("Ring 3 KUSER_SHARED_DATA read mismatch");
            }
            if teb_seen != TEB_VA {
                return Err("Ring 3 gs:[0x30] TEB base mismatch");
            }
            if close_bad != STATUS_INVALID_HANDLE {
                return Err("Ring 3 NtClose(bad) did not return STATUS_INVALID_HANDLE");
            }
            if create_ev != STATUS_SUCCESS || handle == 0 {
                return Err("Ring 3 NtCreateEvent (stack arg) failed");
            }
            if close_ok != STATUS_SUCCESS {
                return Err("Ring 3 NtClose(event) failed");
            }
            if qsi != STATUS_SUCCESS || qsi_len == 0 {
                return Err("Ring 3 NtQuerySystemInformation failed");
            }
            if nonvol != 1 {
                return Err("non-volatile GPRs were clobbered across SYSCALL/SYSRETQ");
            }
            if (arch::xstate_enabled_mask() & XSTATE_MASK_AVX) != 0 && avx_out != avx_pattern {
                return Err("Ring 3 AVX vmovdqu round-trip mismatch");
            }

            // Isolation check 1: write to read-only KUSER_SHARED_DATA -> #PF AV.
            arch::user::set_exception_observer(true);
            run_user_snippet(
                proc,
                code_pa,
                &raw const nk_user_stub_write_kusd,
                &raw const nk_user_stub_write_kusd_end,
                0,
            )?;
            arch::user::set_exception_observer(false);
            let (code, _, info0, info1) = arch::user::observed_exception();
            if code != STATUS_ACCESS_VIOLATION as u32
                || info0 != crate::ke::seh::ACCESS_WRITE
                || info1 != nk_ntabi::ke::USER_SHARED_DATA
            {
                return Err("Ring 3 write to KUSER_SHARED_DATA did not raise write AV");
            }

            // Isolation check 2: read kernel address -> #PF AV.
            arch::user::set_exception_observer(true);
            run_user_snippet(
                proc,
                code_pa,
                &raw const nk_user_stub_read_kernel,
                &raw const nk_user_stub_read_kernel_end,
                0,
            )?;
            arch::user::set_exception_observer(false);
            let (code, _, info0, info1) = arch::user::observed_exception();
            if code != STATUS_ACCESS_VIOLATION as u32
                || info0 != crate::ke::seh::ACCESS_READ
                || info1 != nk_ntabi::ke::SHARED_DATA
            {
                return Err("Ring 3 read of kernel memory did not raise read AV");
            }

            // Isolation check 3: privileged `cli` in Ring 3 -> #GP STATUS_PRIVILEGED_INSTRUCTION.
            arch::user::set_exception_observer(true);
            run_user_snippet(
                proc,
                code_pa,
                &raw const nk_user_stub_cli,
                &raw const nk_user_stub_cli_end,
                0,
            )?;
            arch::user::set_exception_observer(false);
            let (code, _, _, _) = arch::user::observed_exception();
            if code != STATUS_PRIVILEGED_INSTRUCTION as u32 {
                return Err("Ring 3 `cli` did not raise STATUS_PRIVILEGED_INSTRUCTION");
            }
            Ok(())
        })();

        // Unmap and free user data/code frames before dropping `proc_ref` so
        // `AddressSpace::destroy` frees all page tables with zero frame leaks.
        let _ = space.unmap_page(CODE_VA);
        let _ = space.unmap_page(DATA_VA);
        mm::free_frames(code_pa, 1);
        mm::free_frames(data_pa, 1);
        drop(proc_ref);

        res
    }

    pub fn run_vm() -> Result<(), &'static str> {
        use crate::io::mdl::{IoAllocateMdl, IoFreeMdl, MmUnlockPages, probe_and_lock};
        use crate::svc::zw;
        use core::ffi::c_void;
        use nk_mm::protect::*;
        use nk_ntabi::io::{IO_WRITE_ACCESS, USER_MODE};
        use nk_ntabi::ke::KAPC_STATE;
        use nk_ntabi::mm::{
            MEM_ADDRESS_REQUIREMENTS, MEM_EXTENDED_PARAMETER,
            MEM_EXTENDED_PARAMETER_ADDRESS_REQUIREMENTS, MEMORY_BASIC_INFORMATION,
            MEMORY_BASIC_INFORMATION_CLASS,
        };
        use nk_ntabi::status::STATUS_GUARD_PAGE_VIOLATION;

        // SAFETY: `process::system()` is live forever.
        let proc_ref = unsafe { process::create_minimal(b"vmtest.exe", process::system(), false) }
            .map_err(|_| "failed to create vmtest process")?;
        let proc = proc_ref.body();
        // SAFETY: `proc_ref` keeps `proc` alive for the entire test.
        let Some(space) = (unsafe { process::address_space(proc) }) else {
            return Err("vmtest process has no AddressSpace");
        };

        // SAFETY: attaching to our live `proc` and detaching before returning.
        unsafe {
            let mut apc_state = core::mem::zeroed::<KAPC_STATE>();
            process::KeStackAttachProcess(proc.cast(), &raw mut apc_state);

            let res = (|| -> Result<(), &'static str> {
                let cur = (-1isize) as *mut c_void;
                // 1. Reserve 4 pages (16 KiB).
                let mut base: *mut c_void = core::ptr::null_mut();
                let mut size: usize = 4 * mm::PAGE_SIZE;
                let st = zw::ZwAllocateVirtualMemory(
                    cur,
                    &raw mut base,
                    0,
                    &raw mut size,
                    MEM_RESERVE,
                    PAGE_READWRITE,
                );
                if st != STATUS_SUCCESS || base.is_null() || size != 4 * mm::PAGE_SIZE {
                    return Err("ZwAllocateVirtualMemory(MEM_RESERVE) failed");
                }
                // Verify query reports MEM_RESERVE.
                let mut mbi = MEMORY_BASIC_INFORMATION::default();
                let mut ret_len = 0usize;
                let st = zw::ZwQueryVirtualMemory(
                    cur,
                    base,
                    MEMORY_BASIC_INFORMATION_CLASS,
                    (&raw mut mbi).cast(),
                    size_of::<MEMORY_BASIC_INFORMATION>(),
                    &raw mut ret_len,
                );
                if st != STATUS_SUCCESS
                    || mbi.State != MEM_RESERVE
                    || mbi.RegionSize != (4 * mm::PAGE_SIZE) as u64
                    || mbi.Type != MEM_PRIVATE
                {
                    return Err("ZwQueryVirtualMemory(MEM_RESERVE) mismatch");
                }

                // 2. Commit middle 2 pages (pages 1..3) as PAGE_READWRITE.
                let mut cbase = base.wrapping_byte_add(mm::PAGE_SIZE);
                let mut csize = 2 * mm::PAGE_SIZE;
                let st = zw::ZwAllocateVirtualMemory(
                    cur,
                    &raw mut cbase,
                    0,
                    &raw mut csize,
                    MEM_COMMIT,
                    PAGE_READWRITE,
                );
                if st != STATUS_SUCCESS || csize != 2 * mm::PAGE_SIZE {
                    return Err("ZwAllocateVirtualMemory(MEM_COMMIT) failed");
                }

                // Query page 0 -> RESERVE 1 page; page 1 -> COMMIT 2 pages RW.
                let st = zw::ZwQueryVirtualMemory(
                    cur,
                    cbase,
                    MEMORY_BASIC_INFORMATION_CLASS,
                    (&raw mut mbi).cast(),
                    size_of::<MEMORY_BASIC_INFORMATION>(),
                    &raw mut ret_len,
                );
                if st != STATUS_SUCCESS
                    || mbi.State != MEM_COMMIT
                    || mbi.Protect != PAGE_READWRITE
                    || mbi.RegionSize != (2 * mm::PAGE_SIZE) as u64
                {
                    return Err("ZwQueryVirtualMemory(MEM_COMMIT) mismatch");
                }

                // 3. Demand-zero fault via copy: read must yield 0, write persists.
                let mut read_val = 0xDEAD_BEEFu64;
                if mm::user::copy(
                    (&raw mut read_val).cast(),
                    cbase.cast::<u8>(),
                    size_of::<u64>(),
                )
                .is_err()
                    || read_val != 0
                {
                    return Err("demand-zero read fault did not yield zero");
                }
                let magic = 0x1122_3344_5566_7788u64;
                if mm::user::copy(
                    cbase.cast::<u8>(),
                    (&raw const magic).cast(),
                    size_of::<u64>(),
                )
                .is_err()
                {
                    return Err("demand-zero write failed");
                }
                let pa_before = space
                    .translate(cbase.addr() as u64)
                    .ok_or("committed page has no physical translation after fault")?;

                // 4. Protect to PAGE_WRITECOPY -> writing must CoW to a NEW frame!
                let mut pbase = cbase;
                let mut psize = mm::PAGE_SIZE;
                let mut old_prot = 0u32;
                let st = zw::ZwProtectVirtualMemory(
                    cur,
                    &raw mut pbase,
                    &raw mut psize,
                    PAGE_WRITECOPY,
                    &raw mut old_prot,
                );
                if st != STATUS_SUCCESS || old_prot != PAGE_READWRITE {
                    return Err("ZwProtectVirtualMemory(PAGE_WRITECOPY) failed");
                }
                let magic2 = 0xAABB_CCDD_EEFF_0011u64;
                if mm::user::copy(
                    cbase.cast::<u8>(),
                    (&raw const magic2).cast(),
                    size_of::<u64>(),
                )
                .is_err()
                {
                    return Err("CoW write fault failed");
                }
                let pa_after = space
                    .translate(cbase.addr() as u64)
                    .ok_or("CoW page missing translation")?;
                if pa_after == pa_before {
                    return Err("CoW write did not allocate a fresh frame");
                }
                // Protection must have promoted to PAGE_READWRITE.
                let st = zw::ZwQueryVirtualMemory(
                    cur,
                    cbase,
                    MEMORY_BASIC_INFORMATION_CLASS,
                    (&raw mut mbi).cast(),
                    size_of::<MEMORY_BASIC_INFORMATION>(),
                    &raw mut ret_len,
                );
                if st != STATUS_SUCCESS || mbi.Protect != PAGE_READWRITE {
                    return Err("CoW write did not promote protection to PAGE_READWRITE");
                }

                // 5. PAGE_NOACCESS preserves frame in Transition PTE and rejects read.
                let st = zw::ZwProtectVirtualMemory(
                    cur,
                    &raw mut pbase,
                    &raw mut psize,
                    PAGE_NOACCESS,
                    &raw mut old_prot,
                );
                if st != STATUS_SUCCESS || old_prot != PAGE_READWRITE {
                    return Err("ZwProtectVirtualMemory(PAGE_NOACCESS) failed");
                }
                if mm::user::copy(
                    (&raw mut read_val).cast(),
                    cbase.cast::<u8>(),
                    size_of::<u64>(),
                )
                .is_ok()
                {
                    return Err("PAGE_NOACCESS read did not fault");
                }
                let st = zw::ZwProtectVirtualMemory(
                    cur,
                    &raw mut pbase,
                    &raw mut psize,
                    PAGE_READWRITE,
                    &raw mut old_prot,
                );
                if st != STATUS_SUCCESS || old_prot != PAGE_NOACCESS {
                    return Err("ZwProtectVirtualMemory(restore RW) failed");
                }
                if mm::user::copy(
                    (&raw mut read_val).cast(),
                    cbase.cast::<u8>(),
                    size_of::<u64>(),
                )
                .is_err()
                    || read_val != magic2
                {
                    return Err("PAGE_NOACCESS transition did not preserve frame contents");
                }

                // 6. One-shot PAGE_GUARD raises STATUS_GUARD_PAGE_VIOLATION once, then clears!
                let st = zw::ZwProtectVirtualMemory(
                    cur,
                    &raw mut pbase,
                    &raw mut psize,
                    PAGE_READWRITE | PAGE_GUARD,
                    &raw mut old_prot,
                );
                if st != STATUS_SUCCESS || old_prot != PAGE_READWRITE {
                    return Err("ZwProtectVirtualMemory(PAGE_GUARD) failed");
                }
                // First fault via `handle_fault` returns GuardViolation and clears PAGE_GUARD.
                let first =
                    mm::vm::handle_fault(cbase.addr() as u64, nk_mm::pte::Access::Read, true);
                if first != mm::vm::UserFault::GuardViolation {
                    return Err("PAGE_GUARD first touch did not return GuardViolation");
                }
                let _ = STATUS_GUARD_PAGE_VIOLATION;
                // Second access succeeds and preserves `magic2`.
                if mm::user::copy(
                    (&raw mut read_val).cast(),
                    cbase.cast::<u8>(),
                    size_of::<u64>(),
                )
                .is_err()
                    || read_val != magic2
                {
                    return Err("PAGE_GUARD did not clear after first touch");
                }

                // 7. MmProbeAndLockPages on an untouched demand-zero committed page (page 2).
                let page2 = cbase.wrapping_byte_add(mm::PAGE_SIZE);
                let mdl = IoAllocateMdl(page2, mm::PAGE_SIZE as u32, 0, 0, core::ptr::null_mut());
                if mdl.is_null() {
                    return Err("IoAllocateMdl failed");
                }
                let lock_res = probe_and_lock(mdl, USER_MODE, IO_WRITE_ACCESS);
                if lock_res.is_ok() {
                    MmUnlockPages(mdl);
                }
                IoFreeMdl(mdl);
                if lock_res.is_err() {
                    return Err("MmProbeAndLockPages failed on demand-zero user page");
                }

                // 8. NtAllocateVirtualMemoryEx with AddressRequirements + NtRead/WriteVirtualMemory.
                let mut req = MEM_ADDRESS_REQUIREMENTS {
                    LowestStartingAddress: 0x1000_0000,
                    HighestEndingAddress: 0x1FFF_FFFF,
                    Alignment: 0x10_0000,
                };
                let mut ext = MEM_EXTENDED_PARAMETER {
                    Type: MEM_EXTENDED_PARAMETER_ADDRESS_REQUIREMENTS,
                    Value: (&raw mut req).addr() as u64,
                };
                let mut ebase: *mut c_void = core::ptr::null_mut();
                let mut esize: usize = mm::PAGE_SIZE;
                let st = zw::ZwAllocateVirtualMemoryEx(
                    cur,
                    &raw mut ebase,
                    &raw mut esize,
                    MEM_RESERVE | MEM_COMMIT | MEM_TOP_DOWN,
                    PAGE_READWRITE,
                    &raw mut ext,
                    1,
                );
                if st != STATUS_SUCCESS
                    || ebase.addr() < 0x1000_0000
                    || ebase.addr() >= 0x2000_0000
                    || !ebase.addr().is_multiple_of(0x10_0000)
                {
                    return Err("ZwAllocateVirtualMemoryEx AddressRequirements mismatch");
                }
                let wbuf = 0xFEED_FACE_CAFE_BABEu64;
                let mut wdone = 0usize;
                let st = zw::ZwWriteVirtualMemory(
                    cur,
                    ebase,
                    (&raw const wbuf).cast(),
                    size_of::<u64>(),
                    &raw mut wdone,
                );
                let mut rbuf = 0u64;
                let mut rdone = 0usize;
                let st2 = zw::ZwReadVirtualMemory(
                    cur,
                    ebase,
                    (&raw mut rbuf).cast(),
                    size_of::<u64>(),
                    &raw mut rdone,
                );
                if st != STATUS_SUCCESS
                    || st2 != STATUS_SUCCESS
                    || wdone != 8
                    || rdone != 8
                    || rbuf != wbuf
                {
                    return Err("ZwRead/WriteVirtualMemory round-trip failed");
                }

                // 9. Decommit page 1 and release both VADs cleanly.
                let mut dbase = cbase;
                let mut dsize = mm::PAGE_SIZE;
                if zw::ZwFreeVirtualMemory(cur, &raw mut dbase, &raw mut dsize, MEM_DECOMMIT)
                    != STATUS_SUCCESS
                {
                    return Err("ZwFreeVirtualMemory(MEM_DECOMMIT) failed");
                }
                let mut fsize = 0usize;
                if zw::ZwFreeVirtualMemory(cur, &raw mut base, &raw mut fsize, MEM_RELEASE)
                    != STATUS_SUCCESS
                {
                    return Err("ZwFreeVirtualMemory(MEM_RELEASE) failed");
                }
                fsize = 0;
                if zw::ZwFreeVirtualMemory(cur, &raw mut ebase, &raw mut fsize, MEM_RELEASE)
                    != STATUS_SUCCESS
                {
                    return Err("ZwFreeVirtualMemory(MEM_RELEASE ex) failed");
                }
                Ok(())
            })();

            process::KeUnstackDetachProcess(&raw mut apc_state);
            drop(proc_ref);
            res
        }
    }

    /// Build a minimal valid PE32+ image in memory (3 pages: headers, `.text`,
    /// `.data`, and `.reloc` with one `DIR64` relocation at RVA `0x2000`) to test
    /// `SEC_IMAGE` preferred-base mapping, relocation (`STATUS_IMAGE_NOT_AT_BASE`),
    /// and `.data` CoW isolation.
    fn synthetic_pe_image(preferred_base: u64) -> alloc::vec::Vec<u8> {
        let mut img = alloc::vec![0u8; 0x2000];
        let put16 = |b: &mut [u8], o: usize, v: u16| b[o..o + 2].copy_from_slice(&v.to_le_bytes());
        let put32 = |b: &mut [u8], o: usize, v: u32| b[o..o + 4].copy_from_slice(&v.to_le_bytes());
        let put64 = |b: &mut [u8], o: usize, v: u64| b[o..o + 8].copy_from_slice(&v.to_le_bytes());

        // DOS header
        img[0] = b'M';
        img[1] = b'Z';
        put32(&mut img, 0x3C, 0x80);
        // PE signature + COFF header at 0x80
        img[0x80..0x84].copy_from_slice(b"PE\0\0");
        put16(&mut img, 0x84, nk_pe::MACHINE_NATIVE);
        put16(&mut img, 0x86, 3); // 3 sections: .text, .data, .reloc
        put16(&mut img, 0x94, 0xF0); // SizeOfOptionalHeader
        put16(&mut img, 0x96, 0x0022); // EXECUTABLE_IMAGE | LARGE_ADDRESS_AWARE

        // OptionalHeader64 at 0x98
        let opt = 0x98;
        put16(&mut img, opt, 0x20B); // PE32+
        put32(&mut img, opt + 16, 0x1000); // AddressOfEntryPoint
        put64(&mut img, opt + 24, preferred_base);
        put32(&mut img, opt + 32, 0x1000); // SectionAlignment
        put32(&mut img, opt + 36, 0x200); // FileAlignment
        put16(&mut img, opt + 40, 10); // MajorOSVersion
        put16(&mut img, opt + 48, 10); // MajorSubsystemVersion
        put32(&mut img, opt + 56, 0x4000); // SizeOfImage (4 pages)
        put32(&mut img, opt + 60, 0x400); // SizeOfHeaders
        put16(&mut img, opt + 68, 1); // IMAGE_SUBSYSTEM_NATIVE
        put64(&mut img, opt + 72, 0x4_0000); // StackReserve
        put64(&mut img, opt + 80, 0x1_0000); // StackCommit
        put32(&mut img, opt + 108, 16); // NumberOfRvaAndSizes
        // DIR_BASERELOC (index 5) at RVA 0x3000, size 12
        put32(&mut img, opt + 112 + 5 * 8, 0x3000);
        put32(&mut img, opt + 116 + 5 * 8, 12);

        // Section table at 0x98 + 0xF0 = 0x188
        let mut write_sec = |idx: usize, name: &[u8; 8], rva: u32, raw_off: u32, chars: u32| {
            let s = 0x188 + idx * 40;
            img[s..s + 8].copy_from_slice(name);
            put32(&mut img, s + 8, 0x1000); // VirtualSize
            put32(&mut img, s + 12, rva);
            put32(&mut img, s + 16, 0x200); // SizeOfRawData
            put32(&mut img, s + 20, raw_off);
            put32(&mut img, s + 36, chars);
        };
        write_sec(
            0,
            b".text\0\0\0",
            0x1000,
            0x400,
            nk_pe::SCN_MEM_READ | nk_pe::SCN_MEM_EXECUTE,
        );
        write_sec(
            1,
            b".data\0\0\0",
            0x2000,
            0x600,
            nk_pe::SCN_MEM_READ | nk_pe::SCN_MEM_WRITE,
        );
        write_sec(2, b".reloc\0\0", 0x3000, 0x800, nk_pe::SCN_MEM_READ);

        // .text byte at 0x400: `ret` (0xC3)
        img[0x400] = 0xC3;
        // .data pointer at 0x600 (RVA 0x2000): preferred_base + 0x1000
        put64(&mut img, 0x600, preferred_base + 0x1000);
        // .reloc block at 0x800: page RVA 0x2000, size 12, entry DIR64@0x000 + padding 0
        put32(&mut img, 0x800, 0x2000);
        put32(&mut img, 0x804, 12);
        put16(&mut img, 0x808, 10 << 12);
        put16(&mut img, 0x80A, 0);
        img
    }

    pub fn run_section() -> Result<(), &'static str> {
        use crate::svc::zw;
        use core::ffi::c_void;
        use nk_mm::protect::*;
        use nk_ntabi::io::UNICODE_STRING;
        use nk_ntabi::ke::KAPC_STATE;
        use nk_ntabi::mm::{
            SEC_COMMIT, SECTION_ALL_ACCESS, SECTION_BASIC_INFORMATION,
            SECTION_BASIC_INFORMATION_CLASS, SECTION_IMAGE_INFORMATION,
            SECTION_IMAGE_INFORMATION_CLASS, VIEW_UNMAP,
        };
        use nk_ntabi::ob::OBJECT_ATTRIBUTES;
        use nk_ntabi::status::STATUS_IMAGE_NOT_AT_BASE;

        // SAFETY: `process::system()` is live forever.
        let proc_ref = unsafe { process::create_minimal(b"sectest.exe", process::system(), false) }
            .map_err(|_| "failed to create sectest process")?;
        let proc = proc_ref.body();
        // SAFETY: `proc_ref` keeps `proc` alive for the test.
        let Some(space) = (unsafe { process::address_space(proc) }) else {
            return Err("sectest process has no AddressSpace");
        };

        // SAFETY: attach to `proc` and detach before dropping `proc_ref`.
        unsafe {
            let mut apc_state = core::mem::zeroed::<KAPC_STATE>();
            process::KeStackAttachProcess(proc.cast(), &raw mut apc_state);

            let res = (|| -> Result<(), &'static str> {
                let cur = (-1isize) as *mut c_void;

                // 1. Named pagefile section: create, open by name, map 2 shared views + 1 CoW view.
                let mut name_w: alloc::vec::Vec<u16> =
                    "\\BaseNamedObjects\\NkSecTest".encode_utf16().collect();
                let mut us = UNICODE_STRING {
                    Length: (name_w.len() * 2) as u16,
                    MaximumLength: (name_w.len() * 2) as u16,
                    Buffer: name_w.as_mut_ptr(),
                };
                let oa = OBJECT_ATTRIBUTES {
                    Length: size_of::<OBJECT_ATTRIBUTES>() as u32,
                    RootDirectory: core::ptr::null_mut(),
                    ObjectName: &raw mut us,
                    Attributes: 0x40, // OBJ_CASE_INSENSITIVE
                    SecurityDescriptor: core::ptr::null_mut(),
                    SecurityQualityOfService: core::ptr::null_mut(),
                };
                let max_sz: i64 = (2 * mm::PAGE_SIZE) as i64;
                let mut sec_h: *mut c_void = core::ptr::null_mut();
                let st = zw::ZwCreateSection(
                    &raw mut sec_h,
                    SECTION_ALL_ACCESS,
                    &raw const oa,
                    &raw const max_sz,
                    PAGE_READWRITE,
                    SEC_COMMIT,
                    core::ptr::null_mut(),
                );
                if st != STATUS_SUCCESS || sec_h.is_null() {
                    return Err("ZwCreateSection(pagefile) failed");
                }

                // Open the same named section via ZwOpenSection.
                let mut sec_h2: *mut c_void = core::ptr::null_mut();
                let st = zw::ZwOpenSection(&raw mut sec_h2, SECTION_ALL_ACCESS, &raw const oa);
                if st != STATUS_SUCCESS || sec_h2.is_null() {
                    let _ = zw::ZwClose(sec_h);
                    return Err("ZwOpenSection failed");
                }

                // Query SectionBasicInformation.
                let mut sbi = SECTION_BASIC_INFORMATION::default();
                let mut ret_len = 0usize;
                let st = zw::ZwQuerySection(
                    sec_h,
                    SECTION_BASIC_INFORMATION_CLASS,
                    (&raw mut sbi).cast(),
                    size_of::<SECTION_BASIC_INFORMATION>(),
                    &raw mut ret_len,
                );
                if st != STATUS_SUCCESS || sbi.MaximumSize != max_sz {
                    let _ = zw::ZwClose(sec_h2);
                    let _ = zw::ZwClose(sec_h);
                    return Err("ZwQuerySection(Basic) mismatch");
                }

                // Map view A and view B (both RW shared) + view C (WRITECOPY).
                let mut va_a: *mut c_void = core::ptr::null_mut();
                let mut sz_a: usize = 0;
                let mut va_b: *mut c_void = core::ptr::null_mut();
                let mut sz_b: usize = 0;
                let mut va_c: *mut c_void = core::ptr::null_mut();
                let mut sz_c: usize = 0;
                let st_a = zw::ZwMapViewOfSection(
                    sec_h,
                    cur,
                    &raw mut va_a,
                    0,
                    0,
                    core::ptr::null_mut(),
                    &raw mut sz_a,
                    VIEW_UNMAP,
                    0,
                    PAGE_READWRITE,
                );
                let st_b = zw::ZwMapViewOfSection(
                    sec_h2,
                    cur,
                    &raw mut va_b,
                    0,
                    0,
                    core::ptr::null_mut(),
                    &raw mut sz_b,
                    VIEW_UNMAP,
                    0,
                    PAGE_READWRITE,
                );
                let st_c = zw::ZwMapViewOfSection(
                    sec_h,
                    cur,
                    &raw mut va_c,
                    0,
                    0,
                    core::ptr::null_mut(),
                    &raw mut sz_c,
                    VIEW_UNMAP,
                    0,
                    PAGE_WRITECOPY,
                );
                if st_a != STATUS_SUCCESS
                    || st_b != STATUS_SUCCESS
                    || st_c != STATUS_SUCCESS
                    || va_a == va_b
                {
                    let _ = zw::ZwClose(sec_h2);
                    let _ = zw::ZwClose(sec_h);
                    return Err("ZwMapViewOfSection(pagefile) failed");
                }

                // Write through view A -> must appear in view B AND view C (before CoW).
                let val1 = 0x1122_3344_5566_7788u64;
                let mut seen_b = 0u64;
                let mut seen_c = 0u64;
                if mm::user::copy(va_a.cast(), (&raw const val1).cast(), 8).is_err()
                    || mm::user::copy((&raw mut seen_b).cast(), va_b.cast(), 8).is_err()
                    || mm::user::copy((&raw mut seen_c).cast(), va_c.cast(), 8).is_err()
                    || seen_b != val1
                    || seen_c != val1
                {
                    return Err("shared pagefile views did not observe shared write");
                }

                // Write through view C (WRITECOPY) -> view A/B stay `val1`, view C gets `val2`!
                let val2 = 0xDEAD_BEEF_CAFE_BABEu64;
                let mut seen_a_after = 0u64;
                let mut seen_c_after = 0u64;
                if mm::user::copy(va_c.cast(), (&raw const val2).cast(), 8).is_err()
                    || mm::user::copy((&raw mut seen_a_after).cast(), va_a.cast(), 8).is_err()
                    || mm::user::copy((&raw mut seen_c_after).cast(), va_c.cast(), 8).is_err()
                    || seen_a_after != val1
                    || seen_c_after != val2
                {
                    return Err("WRITECOPY section view broke shared isolation");
                }

                // Extend section and unmap all 3 views.
                let mut new_sz: i64 = (4 * mm::PAGE_SIZE) as i64;
                if zw::ZwExtendSection(sec_h, &raw mut new_sz) != STATUS_SUCCESS
                    || new_sz != (4 * mm::PAGE_SIZE) as i64
                {
                    return Err("ZwExtendSection failed");
                }
                if zw::ZwUnmapViewOfSection(cur, va_a) != STATUS_SUCCESS
                    || zw::ZwUnmapViewOfSection(cur, va_b) != STATUS_SUCCESS
                    || zw::ZwUnmapViewOfSection(cur, va_c) != STATUS_SUCCESS
                {
                    return Err("ZwUnmapViewOfSection failed");
                }
                let _ = zw::ZwClose(sec_h2);
                let _ = zw::ZwClose(sec_h);

                // 2. PE Image section: preferred base (`STATUS_SUCCESS`) + relocated (`STATUS_IMAGE_NOT_AT_BASE`).
                let pref: u64 = 0x0000_0001_4000_0000;
                let pe_bytes = synthetic_pe_image(pref);
                let img_name: alloc::vec::Vec<u16> =
                    "\\Device\\Test\\synth.exe".encode_utf16().collect();
                let img_sec = mm::view::create_image_section_from_bytes(&img_name, &pe_bytes)
                    .map_err(|_| "create_image_section_from_bytes failed")?;
                let img_info = mm::view::image_info(img_sec.body())
                    .ok_or("missing SECTION_IMAGE_INFORMATION")?;
                if img_info.TransferAddress != pref + 0x1000
                    || img_info.SubSystemType != 1
                    || img_info.MaximumStackSize != 0x4_0000
                {
                    return Err("SECTION_IMAGE_INFORMATION mismatch");
                }
                let _ = SECTION_IMAGE_INFORMATION_CLASS;
                let _ = size_of::<SECTION_IMAGE_INFORMATION>();

                // First mapping lands at preferred base (`STATUS_SUCCESS`).
                let (base1, sz1, st1) = mm::view::map_view_in_space(
                    img_sec.body(),
                    space,
                    0,
                    0,
                    0,
                    0,
                    PAGE_EXECUTE_READ,
                    nk_mm::vad::USER_PROBE_VA,
                )
                .map_err(|_| "map image view #1 failed")?;
                if st1 != STATUS_SUCCESS || base1 != pref || sz1 != 0x4000 {
                    return Err("image view #1 did not land at preferred base");
                }
                // Second mapping cannot take `pref` -> relocated with `STATUS_IMAGE_NOT_AT_BASE`!
                let (base2, sz2, st2) = mm::view::map_view_in_space(
                    img_sec.body(),
                    space,
                    0,
                    0,
                    0,
                    0,
                    PAGE_EXECUTE_READ,
                    nk_mm::vad::USER_PROBE_VA,
                )
                .map_err(|_| "map image view #2 failed")?;
                if st2 != STATUS_IMAGE_NOT_AT_BASE || base2 == pref || sz2 != 0x4000 {
                    return Err("image view #2 did not relocate with STATUS_IMAGE_NOT_AT_BASE");
                }

                // Read relocated pointer at RVA 0x2000 in both views!
                let mut ptr1 = 0u64;
                let mut ptr2 = 0u64;
                if mm::user::copy((&raw mut ptr1).cast(), (base1 + 0x2000) as *const u8, 8).is_err()
                    || mm::user::copy((&raw mut ptr2).cast(), (base2 + 0x2000) as *const u8, 8)
                        .is_err()
                {
                    return Err("reading .data of image views failed");
                }
                if ptr1 != base1 + 0x1000 || ptr2 != base2 + 0x1000 {
                    return Err("image base relocation fixup mismatch");
                }

                // Write to `.data` in view #1 (WRITECOPY) -> view #2 remains untouched.
                let new_val = 0x55AA_55AA_1234_5678u64;
                let mut check2 = 0u64;
                if mm::user::copy((base1 + 0x2000) as *mut u8, (&raw const new_val).cast(), 8)
                    .is_err()
                    || mm::user::copy((&raw mut check2).cast(), (base2 + 0x2000) as *const u8, 8)
                        .is_err()
                    || check2 != base2 + 0x1000
                {
                    return Err("image .data WRITECOPY leaked across views");
                }

                // Leave view #1 and view #2 mapped on purpose so `AddressSpace::destroy()`
                // proves full teardown with zero frame/pool/object leaks!
                drop(img_sec);
                Ok(())
            })();

            process::KeUnstackDetachProcess(&raw mut apc_state);
            drop(proc_ref);
            res
        }
    }
}

#[cfg(target_arch = "x86_64")]
fn run(r: &mut Report, _info: &BootInfo) {
    match x64::run() {
        Ok(()) => r.ok_with(
            "user.stub",
            format_args!(
                "Ring 3 iretq, KUSD RO, TEB gs, SYSCALL/SYSRETQ (0..5 args), AVX, isolation"
            ),
        ),
        Err(why) => r.fail("user.stub", format_args!("{why}")),
    }
    match x64::run_vm() {
        Ok(()) => r.ok_with(
            "user.vm",
            format_args!(
                "VAD reserve/commit/decommit/release, demand-zero, CoW, NOACCESS, PAGE_GUARD, MDL lock"
            ),
        ),
        Err(why) => r.fail("user.vm", format_args!("{why}")),
    }
    match x64::run_section() {
        Ok(()) => r.ok_with(
            "user.section",
            format_args!(
                "named pagefile shared/CoW views, extend, SEC_IMAGE preferred+relocated, teardown"
            ),
        ),
        Err(why) => r.fail("user.section", format_args!("{why}")),
    }
}

#[cfg(target_arch = "x86_64")]
fn run_nkt(r: &mut Report, info: &BootInfo) {
    use crate::ke::wait;
    use nk_ntabi::process as proc_layout;
    use nk_ntabi::status::NTSTATUS;

    const EXPECTED: &[u8] = include_str!("../../oracle/user/nkt.txt").as_bytes();
    const OUT_PATH: &str = "\\Device\\BootDevice\\nkt.txt";

    // First user process permanently caches `ntdll.dll`/NLS/API-Set sections,
    // mounts the FAT32 system volume, and registers `\Device\BootDevice` + `\SystemRoot`.
    crate::test::keeps_what_it_started();
    let (proc_ref, _th_ref) = match crate::ps::user::start_first(
        info,
        "\\SystemRoot\\System32\\nkt.exe",
        "\\SystemRoot\\System32\\nkt.exe \\Device\\BootDevice\\nkt.txt",
    ) {
        Ok(pair) => pair,
        Err(st) => {
            r.fail("user.nkt", format_args!("start_first failed: {st:#010x}"));
            return;
        }
    };
    // Wait up to 30 seconds for `nkt.exe` to complete.
    // SAFETY: `proc_ref` holds a live `EPROCESS` dispatcher object.
    let wait_st = unsafe { wait::wait(Some(proc_ref.body().cast()), Some(-300_000_000)) };
    if wait_st != 0 {
        r.fail(
            "user.nkt",
            format_args!("timed out waiting for nkt.exe (wait={wait_st:#x})"),
        );
        return;
    }
    // SAFETY: `proc_ref` is live and terminated.
    let exit_status = unsafe {
        proc_ref
            .body()
            .add(proc_layout::EXIT_STATUS)
            .cast::<NTSTATUS>()
            .read()
    };
    // Ensure any partial line from `autochk.exe`'s `NtDisplayString` is
    // terminated before emitting the structured `NK-TEST` verdict line.
    kprintln!("");
    if exit_status != 0 {
        r.fail(
            "user.nkt",
            format_args!("nkt.exe exited with status {exit_status:#010x}"),
        );
        return;
    }
    let got = match crate::ps::sysdll::read_file_bytes(OUT_PATH) {
        Ok(bytes) => bytes,
        Err(st) => {
            r.fail(
                "user.nkt",
                format_args!("reading {OUT_PATH} failed: {st:#010x}"),
            );
            return;
        }
    };
    if got != EXPECTED {
        r.fail(
            "user.nkt",
            format_args!(
                "transcript mismatch vs oracle/user/nkt.txt (got {}B, expected {}B)",
                got.len(),
                EXPECTED.len()
            ),
        );
        return;
    }
    r.ok_with(
        "user.nkt",
        format_args!(
            "ntdll.dll + nkt.exe exited 0 and matched oracle/user/nkt.txt ({} bytes)",
            got.len()
        ),
    );
}

#[cfg(target_arch = "x86_64")]
fn run_autochk_common(r: &mut Report, info: &BootInfo, name: &str, expect_second_vol: bool) {
    use crate::ke::wait;
    use nk_ntabi::process as proc_layout;
    use nk_ntabi::status::NTSTATUS;

    crate::test::keeps_what_it_started();

    if expect_second_vol {
        // Wait up to 10 seconds for `\Device\HarddiskVolume2` to be published.
        let vol2: alloc::vec::Vec<u16> = "\\Device\\HarddiskVolume2".encode_utf16().collect();
        for _ in 0..100 {
            if crate::ob::lookup(None, &vol2).is_ok_and(|(_, rest)| rest.is_empty()) {
                break;
            }
            // SAFETY: delay wait with no dispatcher object.
            unsafe { wait::wait(None, Some(-1_000_000)) };
        }
    }

    let (proc_ref, _th_ref) = match crate::ps::user::start_first(
        info,
        "\\SystemRoot\\System32\\autochk.exe",
        "autochk.exe *",
    ) {
        Ok(pair) => pair,
        Err(st) => {
            r.fail(name, format_args!("start_first failed: {st:#010x}"));
            return;
        }
    };
    // Wait up to 60 seconds for `autochk.exe` to complete.
    // SAFETY: `proc_ref` holds a live `EPROCESS` dispatcher object.
    let wait_st = unsafe { wait::wait(Some(proc_ref.body().cast()), Some(-600_000_000)) };
    if wait_st != 0 {
        r.fail(
            name,
            format_args!("timed out waiting for autochk.exe (wait={wait_st:#x})"),
        );
        return;
    }
    // SAFETY: `proc_ref` is live and terminated.
    let exit_status = unsafe {
        proc_ref
            .body()
            .add(proc_layout::EXIT_STATUS)
            .cast::<NTSTATUS>()
            .read()
    };
    // Ensure any partial line from `autochk.exe`'s `NtDisplayString` is
    // terminated before emitting the structured `NK-TEST` verdict line.
    kprintln!("");
    if exit_status != 0 {
        r.fail(
            name,
            format_args!("autochk.exe exited with status {exit_status:#010x}"),
        );
        return;
    }
    r.ok_with(
        name,
        format_args!("unmodified Microsoft autochk.exe exited 0"),
    );
}

#[cfg(target_arch = "x86_64")]
fn run_autochk_clean(r: &mut Report, info: &BootInfo) {
    run_autochk_common(r, info, "user.autochk.clean", false);
}

#[cfg(target_arch = "x86_64")]
fn run_autochk_dirty(r: &mut Report, info: &BootInfo) {
    run_autochk_common(r, info, "user.autochk.dirty", true);
}

#[cfg(target_arch = "x86_64")]
fn run_svc_trap(r: &mut Report, _info: &BootInfo) {
    use crate::arch;
    use crate::ke::{thread, wait};
    use crate::mm;
    use crate::ob::object;
    use crate::ps::process;
    use nk_mm::pt::Prot;

    // Assemble a minimal Ring 3 stub that executes `syscall` with SSDT slot
    // #0x91 (`NtAddAtom`, unimplemented) to verify named bugcheck enforcement.
    const CODE_VA: u64 = 0x0040_0000;
    const STACK_VA: u64 = 0x0041_0000;
    #[rustfmt::skip]
    const STUB: [u8; 9] = [
        0xB8, 0x47, 0x00, 0x00, 0x00, // mov eax, 0x47 (NtAddAtom)
        0x0F, 0x05,                   // syscall
        0x0F, 0x0B,                   // ud2
    ];

    // SAFETY: `process::system()` is live forever.
    let Ok(proc_ref) =
        (unsafe { process::create_minimal(b"svctrap.exe", process::system(), false) })
    else {
        r.fail("user.svc_trap", format_args!("create_minimal failed"));
        return;
    };
    let proc = proc_ref.body();
    // SAFETY: `proc_ref` keeps `proc` alive.
    let Some(space) = (unsafe { process::address_space(proc) }) else {
        r.fail("user.svc_trap", format_args!("no AddressSpace"));
        return;
    };
    let (Some(code_pa), Some(stack_pa)) = (mm::alloc_frames(1), mm::alloc_frames(1)) else {
        r.fail("user.svc_trap", format_args!("out of memory"));
        return;
    };
    if space.map_page(CODE_VA, code_pa, Prot::USER_RX).is_err()
        || space.map_page(STACK_VA, stack_pa, Prot::USER_RW).is_err()
    {
        r.fail("user.svc_trap", format_args!("map_page failed"));
        return;
    }
    // SAFETY: `code_pa` is our freshly allocated frame.
    unsafe {
        let dst = mm::phys_to_virt(code_pa);
        core::ptr::copy_nonoverlapping(STUB.as_ptr(), dst, STUB.len());
    }
    fn enter(_: usize) {
        // SAFETY: `CODE_VA` is mapped `USER_RX`, `STACK_VA + 0xF00` is writable.
        unsafe { arch::user::enter_user_mode(CODE_VA, STACK_VA + 0xF00, 0, 0) }
    }
    let Ok(t) = thread::create_unstarted(enter, 0, thread::NORMAL_PRIORITY, thread::ANYWHERE)
    else {
        r.fail("user.svc_trap", format_args!("create_unstarted failed"));
        return;
    };
    // SAFETY: `t` is unstarted and `proc` is live.
    unsafe {
        thread::assign_process(t, proc);
        kprintln!("NK-NEG-ARMED user.svc_trap");
        thread::begin(t);
        wait::KeWaitForSingleObject(t.cast(), 0, 0, 0, core::ptr::null());
        object::dereference(t.cast());
    }
    r.fail(
        "user.svc_trap",
        format_args!("unimplemented syscall did not bugcheck"),
    );
}
