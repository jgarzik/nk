//! Ring 3 transition, `SYSCALL`/`SYSRETQ`, `KUSER_SHARED_DATA` read-only user
//! alias, user GS (`TEB`), and Ring 3 privilege-isolation self-tests.

use crate::test::{Group, Report};
use nk_bootinfo::BootInfo;

pub static GROUP: Group = Group {
    names: &["user.stub", "user.vm"],
    run,
    manual: false,
};

pub static GROUPS: &[&Group] = &[&GROUP];

#[cfg(not(target_arch = "x86_64"))]
fn run(r: &mut Report, _info: &BootInfo) {
    r.skip("user.stub", format_args!("x86-64 only"));
    r.skip("user.vm", format_args!("x86-64 only"));
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
            unsafe { arch::user::enter_user_mode(CODE_VA, STACK_RSP, DATA_VA) }
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
}
