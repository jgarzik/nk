//! NT system service table (SSDT), `Zw*` thunks, and dispatch.
//!
//! One table of 471 entries (`services.tsv`, generated into `OUT_DIR/svc_table.rs`
//! by `kernel/build.rs` and checked against `ntdll.dll` by `tools/svctable.py`)
//! defines every NT system-call slot for Windows 10 19045.2006 x86-64.
//!
//! Each implemented service lives as `NtXxx` in its owning subsystem and is
//! registered once below. From that single registration NK derives:
//! - the SSDT dispatch trampoline (`dispatch`) with a compile-time check that
//!   the Rust parameter count matches Windows' `KiArgumentTable` stack-arg count;
//! - the `ZwXxx` kernel-mode thunk (`svc::zw::ZwXxx`) that switches
//!   `KTHREAD.PreviousMode` to `KernelMode`, invokes `NtXxx`, and restores
//!   `PreviousMode` on return;
//! - the service's status for the ledger (`State::Implemented` / `Partial`).
//!
//! An absent service number within `0..SERVICE_COUNT` stops the system naming
//! the service (`BUGCHECK: NtXxx: NK does not implement this service`); an index
//! past `SERVICE_COUNT` returns `STATUS_INVALID_SYSTEM_SERVICE`.

#![allow(non_snake_case)]

use crate::export::State;
use crate::kd;
use crate::ke::thread::PreviousModeGuard;
use core::ffi::c_void;
use nk_ntabi::io::{IO_STATUS_BLOCK, UNICODE_STRING};
use nk_ntabi::ob::OBJECT_ATTRIBUTES;
use nk_ntabi::status::{NTSTATUS, STATUS_INVALID_SYSTEM_SERVICE};

include!(concat!(env!("OUT_DIR"), "/svc_table.rs"));

/// Maximum total arguments of any Windows 10 19045.2006 NT system service
/// (4 register arguments + up to 13 stack arguments).
pub const MAX_SYSCALL_ARGS: usize = 17;

/// Converts a raw 64-bit system-call argument slot into a typed parameter.
trait FromSyscallArg: Copy {
    fn from_arg(raw: usize) -> Self;
}

impl FromSyscallArg for usize {
    #[inline(always)]
    fn from_arg(raw: usize) -> Self {
        raw
    }
}

impl FromSyscallArg for isize {
    #[inline(always)]
    fn from_arg(raw: usize) -> Self {
        raw as isize
    }
}

impl FromSyscallArg for u64 {
    #[inline(always)]
    fn from_arg(raw: usize) -> Self {
        raw as u64
    }
}

impl FromSyscallArg for i64 {
    #[inline(always)]
    fn from_arg(raw: usize) -> Self {
        raw as i64
    }
}

impl FromSyscallArg for u32 {
    #[inline(always)]
    fn from_arg(raw: usize) -> Self {
        raw as u32
    }
}

impl FromSyscallArg for i32 {
    #[inline(always)]
    fn from_arg(raw: usize) -> Self {
        raw as i32
    }
}

impl FromSyscallArg for u16 {
    #[inline(always)]
    fn from_arg(raw: usize) -> Self {
        raw as u16
    }
}

impl FromSyscallArg for i16 {
    #[inline(always)]
    fn from_arg(raw: usize) -> Self {
        raw as i16
    }
}

impl FromSyscallArg for u8 {
    #[inline(always)]
    fn from_arg(raw: usize) -> Self {
        raw as u8
    }
}

impl FromSyscallArg for i8 {
    #[inline(always)]
    fn from_arg(raw: usize) -> Self {
        raw as i8
    }
}

impl<T> FromSyscallArg for *const T {
    #[inline(always)]
    fn from_arg(raw: usize) -> Self {
        core::ptr::with_exposed_provenance(raw)
    }
}

impl<T> FromSyscallArg for *mut T {
    #[inline(always)]
    fn from_arg(raw: usize) -> Self {
        core::ptr::with_exposed_provenance_mut(raw)
    }
}

/// A registered system-service dispatch entry.
#[derive(Clone, Copy)]
pub struct ServiceSlot {
    pub trampoline: unsafe fn(&[usize; MAX_SYSCALL_ARGS]) -> NTSTATUS,
    #[allow(dead_code)]
    pub state: State,
}

/// Compile-time helper verifying that `argc` matches `SERVICE_META[number].stack_args`.
const fn check_arity(number: u16, argc: usize) {
    let expected = SERVICE_META[number as usize].stack_args as usize;
    let actual = argc.saturating_sub(4);
    assert!(
        actual == expected,
        "service parameter count does not match services.tsv stack_args"
    );
}

/// Build the dense `SERVICE_COUNT` dispatch table at compile time, rejecting
/// duplicate registrations.
const fn build_table(entries: &[(u16, ServiceSlot)]) -> [Option<ServiceSlot>; SERVICE_COUNT] {
    let mut table: [Option<ServiceSlot>; SERVICE_COUNT] = [None; SERVICE_COUNT];
    let mut i = 0;
    while i < entries.len() {
        let (num, slot) = entries[i];
        assert!(
            (num as usize) < SERVICE_COUNT,
            "service number out of range"
        );
        assert!(table[num as usize].is_none(), "duplicate service number");
        table[num as usize] = Some(slot);
        i += 1;
    }
    table
}

/// Count tokens in a comma-separated list of `ident: ty`.
macro_rules! count_args {
    () => { 0usize };
    ($head:ident : $hty:ty $(, $tail:ident : $tty:ty)*) => {
        1usize + count_args!($($tail : $tty),*)
    };
}

/// Invoke a safe or unsafe `Nt*` handler with sequentially indexed raw args.
macro_rules! call_from_args {
    (@step safe, $func:path, $args:ident, $idx:expr, ($($acc:expr,)*)) => {
        $func($($acc),*)
    };
    (@step unsafe, $func:path, $args:ident, $idx:expr, ($($acc:expr,)*)) => {
        // SAFETY: caller guarantees `args` matches the NT service contract.
        unsafe { $func($($acc),*) }
    };
    (@step $safety:ident, $func:path, $args:ident, $idx:expr, ($($acc:expr,)*), $name:ident : $ty:ty $(, $rest_n:ident : $rest_t:ty)*) => {
        call_from_args!(
            @step $safety,
            $func,
            $args,
            $idx + 1usize,
            ($($acc,)* <$ty as FromSyscallArg>::from_arg($args[$idx]),)
            $(, $rest_n : $rest_t)*
        )
    };
}

/// Generate a `Zw*` thunk for a safe or unsafe `Nt*` implementation.
macro_rules! define_zw_fn {
    (safe, $zw:ident, $impl_path:path, ($($arg:ident : $ty:ty),* $(,)?)) => {
        #[doc = concat!("Kernel-mode `", stringify!($zw), "` thunk: sets `PreviousMode` to `KernelMode`, calls the `Nt*` implementation, and restores `PreviousMode`.")]
        #[allow(clippy::too_many_arguments)]
        pub extern "C" fn $zw($($arg: $ty),*) -> NTSTATUS {
            let _mode = PreviousModeGuard::kernel();
            $impl_path($($arg),*)
        }
    };
    (unsafe, $zw:ident, $impl_path:path, ($($arg:ident : $ty:ty),* $(,)?)) => {
        #[doc = concat!("Kernel-mode `", stringify!($zw), "` thunk: sets `PreviousMode` to `KernelMode`, calls the `Nt*` implementation, and restores `PreviousMode`.\n\n# Safety\nPer the NT system-service contract for `", stringify!($zw), "`.")]
        #[allow(clippy::too_many_arguments)]
        pub unsafe extern "C" fn $zw($($arg: $ty),*) -> NTSTATUS {
            let _mode = PreviousModeGuard::kernel();
            // SAFETY: caller satisfies the NT service contract; `PreviousMode` is `KernelMode`.
            unsafe { $impl_path($($arg),*) }
        }
    };
}

/// Define all implemented system services from a single authoritative list.
macro_rules! register_services {
    (
        $(
            $safety:ident $state:ident, $nt:ident => $impl_path:path, $zw:ident($($arg:ident : $ty:ty),* $(,)?);
        )*
    ) => {
        /// Generated `Zw*` thunks: each sets `KTHREAD.PreviousMode` to
        /// `KernelMode`, delegates to the `Nt*` implementation, and restores
        /// the caller's `PreviousMode`.
        pub mod zw {
            use super::*;
            $(
                define_zw_fn!($safety, $zw, $impl_path, ($($arg : $ty),*));
            )*
        }

        mod trampolines {
            use super::*;
            $(
                /// # Safety
                /// Caller guarantees `args` satisfies the NT service contract.
                pub(super) unsafe fn $nt(args: &[usize; MAX_SYSCALL_ARGS]) -> NTSTATUS {
                    const { check_arity(nr::$nt, count_args!($($arg : $ty),*)) };
                    call_from_args!(@step $safety, $impl_path, args, 0usize, () $(, $arg : $ty)*)
                }
            )*
        }

        static HANDLERS: [Option<ServiceSlot>; SERVICE_COUNT] = build_table(&[
            $(
                (
                    nr::$nt,
                    ServiceSlot {
                        trampoline: trampolines::$nt,
                        state: State::$state,
                    },
                ),
            )*
        ]);
    };
}

register_services! {
    // Registry (`kernel/cm`)
    unsafe Implemented, NtCreateKey => crate::cm::NtCreateKey, ZwCreateKey(
        key_handle: *mut *mut c_void,
        desired_access: u32,
        attributes: *const OBJECT_ATTRIBUTES,
        title_index: u32,
        class: *const UNICODE_STRING,
        create_options: u32,
        disposition: *mut u32,
    );
    safe Implemented, NtDeleteKey => crate::cm::NtDeleteKey, ZwDeleteKey(
        key_handle: *mut c_void,
    );
    unsafe Implemented, NtDeleteValueKey => crate::cm::NtDeleteValueKey, ZwDeleteValueKey(
        key_handle: *mut c_void,
        value_name: *const UNICODE_STRING,
    );
    unsafe Partial, NtNotifyChangeKey => crate::cm::notify::NtNotifyChangeKey, ZwNotifyChangeKey(
        key_handle: *mut c_void,
        event: *mut c_void,
        work_item: *mut c_void,
        queue: *mut c_void,
        status_block: *mut IO_STATUS_BLOCK,
        filter: u32,
        watch_tree: u8,
        buffer: *mut c_void,
        buffer_size: u32,
        asynchronous: u8,
    );
    unsafe Implemented, NtEnumerateKey => crate::cm::NtEnumerateKey, ZwEnumerateKey(
        key_handle: *mut c_void,
        index: u32,
        class: u32,
        information: *mut u8,
        length: u32,
        result_length: *mut u32,
    );
    unsafe Implemented, NtEnumerateValueKey => crate::cm::NtEnumerateValueKey, ZwEnumerateValueKey(
        key_handle: *mut c_void,
        index: u32,
        class: u32,
        information: *mut u8,
        length: u32,
        result_length: *mut u32,
    );
    unsafe Implemented, NtOpenKey => crate::cm::NtOpenKey, ZwOpenKey(
        key_handle: *mut *mut c_void,
        desired_access: u32,
        attributes: *const OBJECT_ATTRIBUTES,
    );
    unsafe Implemented, NtQueryKey => crate::cm::NtQueryKey, ZwQueryKey(
        key_handle: *mut c_void,
        class: u32,
        information: *mut u8,
        length: u32,
        result_length: *mut u32,
    );
    unsafe Implemented, NtQueryValueKey => crate::cm::NtQueryValueKey, ZwQueryValueKey(
        key_handle: *mut c_void,
        value_name: *const UNICODE_STRING,
        class: u32,
        information: *mut u8,
        length: u32,
        result_length: *mut u32,
    );
    unsafe Implemented, NtSetValueKey => crate::cm::NtSetValueKey, ZwSetValueKey(
        key_handle: *mut c_void,
        value_name: *const UNICODE_STRING,
        title_index: u32,
        kind: u32,
        data: *const u8,
        data_size: u32,
    );

    // Executive (`kernel/ex`)
    unsafe Partial, NtQueryWnfStateData => crate::ex::wnf::NtQueryWnfStateData, ZwQueryWnfStateData(
        state_name: *const u64,
        type_id: *const c_void,
        explicit_scope: *const c_void,
        change_stamp: *mut u32,
        buffer: *mut c_void,
        buffer_size: *mut u32,
    );
    unsafe Partial, NtQueryWnfStateNameInformation => crate::ex::wnf::NtQueryWnfStateNameInformation, ZwQueryWnfStateNameInformation(
        state_name: *const u64,
        name_info_class: u32,
        explicit_scope: *const c_void,
        info_buffer: *mut c_void,
        info_buffer_size: u32,
    );
    unsafe Implemented, NtQueryLicenseValue => crate::ex::license::NtQueryLicenseValue, ZwQueryLicenseValue(
        name: *const UNICODE_STRING,
        kind: *mut u32,
        data: *mut c_void,
        data_size: u32,
        result_size: *mut u32,
    );
    unsafe Partial, NtSetSystemInformation => crate::ex::firmware::NtSetSystemInformation, ZwSetSystemInformation(
        class: u32,
        information: *mut c_void,
        length: u32,
    );
    unsafe Partial, NtQuerySystemInformation => crate::ex::sysinfo::NtQuerySystemInformation, ZwQuerySystemInformation(
        class: u32,
        buffer: *mut c_void,
        length: u32,
        return_length: *mut u32,
    );
    unsafe Partial, NtQuerySystemInformationEx => crate::ex::sysinfo_ex::NtQuerySystemInformationEx, ZwQuerySystemInformationEx(
        class: u32,
        input: *const c_void,
        input_length: u32,
        output: *mut c_void,
        output_length: u32,
        return_length: *mut u32,
    );

    // I/O (`kernel/io`)
    unsafe Partial, NtCreateFile => crate::io::zwfile::NtCreateFile, ZwCreateFile(
        file_handle: *mut *mut c_void,
        desired_access: u32,
        object_attributes: *const OBJECT_ATTRIBUTES,
        io_status_block: *mut IO_STATUS_BLOCK,
        allocation_size: *const i64,
        file_attributes: u32,
        share_access: u32,
        create_disposition: u32,
        create_options: u32,
        ea_buffer: *const c_void,
        ea_length: u32,
    );
    unsafe Partial, NtOpenFile => crate::io::zwfile::NtOpenFile, ZwOpenFile(
        file_handle: *mut *mut c_void,
        desired_access: u32,
        object_attributes: *const OBJECT_ATTRIBUTES,
        io_status_block: *mut IO_STATUS_BLOCK,
        share_access: u32,
        open_options: u32,
    );
    unsafe Partial, NtLoadDriver => crate::io::service::NtLoadDriver, ZwLoadDriver(
        driver_service_name: *const UNICODE_STRING,
    );
    unsafe Partial, NtUnloadDriver => crate::io::service::NtUnloadDriver, ZwUnloadDriver(
        driver_service_name: *const UNICODE_STRING,
    );

    // Object manager (`kernel/ob`)
    unsafe Partial, NtCreateEvent => crate::ob::event::NtCreateEvent, ZwCreateEvent(
        event_handle: *mut *mut c_void,
        desired_access: u32,
        object_attributes: *const OBJECT_ATTRIBUTES,
        event_type: u32,
        initial_state: u8,
    );
    unsafe Implemented, NtOpenEvent => crate::ob::event::NtOpenEvent, ZwOpenEvent(
        event_handle: *mut *mut c_void,
        desired_access: u32,
        object_attributes: *const OBJECT_ATTRIBUTES,
    );
    unsafe Partial, NtWaitForSingleObject => crate::ob::event::NtWaitForSingleObject, ZwWaitForSingleObject(
        handle: *mut c_void,
        alertable: u8,
        timeout: *const i64,
    );
    unsafe Partial, NtCreateDirectoryObject => crate::ob::directory::NtCreateDirectoryObject, ZwCreateDirectoryObject(
        directory_handle: *mut *mut c_void,
        desired_access: u32,
        object_attributes: *const OBJECT_ATTRIBUTES,
    );
    safe Partial, NtMakeTemporaryObject => crate::ob::directory::NtMakeTemporaryObject, ZwMakeTemporaryObject(
        handle: *mut c_void,
    );

    // Power (`kernel/po`)
    safe Partial, NtInitiatePowerAction => crate::po::action::NtInitiatePowerAction, ZwInitiatePowerAction(
        action: i32,
        lightest_state: i32,
        flags: u32,
        asynchronous: u8,
    );
    unsafe Partial, NtPowerInformation => crate::po::NtPowerInformation, ZwPowerInformation(
        level: i32,
        input: *mut c_void,
        input_length: u32,
        output: *mut c_void,
        output_length: u32,
    );

    // Process & thread (`kernel/ps`)
    safe Implemented, NtAlertThread => crate::ps::NtAlertThread, ZwAlertThread(
        thread_handle: *mut c_void,
    );
    safe Implemented, NtClose => crate::ps::NtClose, ZwClose(
        handle: *mut c_void,
    );
    unsafe Partial, NtSetInformationThread => crate::ps::NtSetInformationThread, ZwSetInformationThread(
        thread_handle: *mut c_void,
        class: u32,
        information: *const c_void,
        length: u32,
    );

    // Security (`kernel/se`)
    unsafe Implemented, NtDuplicateToken => crate::se::zwtoken::NtDuplicateToken, ZwDuplicateToken(
        existing_handle: *mut c_void,
        desired_access: u32,
        object_attributes: *const OBJECT_ATTRIBUTES,
        effective_only: u8,
        token_type: u32,
        new_handle: *mut *mut c_void,
    );
    safe Implemented, NtImpersonateAnonymousToken => crate::se::impersonate::NtImpersonateAnonymousToken, ZwImpersonateAnonymousToken(
        thread_handle: *mut c_void,
    );
    unsafe Implemented, NtOpenProcessTokenEx => crate::se::zwtoken::NtOpenProcessTokenEx, ZwOpenProcessTokenEx(
        process_handle: *mut c_void,
        desired_access: u32,
        handle_attributes: u32,
        token_handle: *mut *mut c_void,
    );
    unsafe Implemented, NtOpenThreadTokenEx => crate::se::impersonate::NtOpenThreadTokenEx, ZwOpenThreadTokenEx(
        thread_handle: *mut c_void,
        desired_access: u32,
        open_as_self: u8,
        handle_attributes: u32,
        token_handle: *mut *mut c_void,
    );
    unsafe Implemented, NtQueryInformationToken => crate::se::zwtoken::NtQueryInformationToken, ZwQueryInformationToken(
        token_handle: *mut c_void,
        class: u32,
        buffer: *mut u8,
        length: u32,
        return_length: *mut u32,
    );
    unsafe Implemented, NtSetSecurityObject => crate::se::NtSetSecurityObject, ZwSetSecurityObject(
        handle: *mut c_void,
        information: u32,
        descriptor: *const c_void,
    );
}

/// Metadata for NT service `index` (`0..SERVICE_COUNT`), if in range.
#[allow(dead_code)]
pub fn meta(index: u32) -> Option<&'static ServiceMeta> {
    SERVICE_META.get(index as usize)
}

/// Dispatch NT service `index` with raw 64-bit argument slots.
///
/// - `index >= SERVICE_COUNT` returns `STATUS_INVALID_SYSTEM_SERVICE`.
/// - An unimplemented service within range bugchecks naming the service.
///
/// # Safety
/// `args` must satisfy the contract of the invoked service for the current
/// thread's `PreviousMode`.
#[allow(dead_code)]
pub unsafe fn dispatch(index: u32, args: &[usize; MAX_SYSCALL_ARGS]) -> NTSTATUS {
    let Some(entry) = SERVICE_META.get(index as usize) else {
        return STATUS_INVALID_SYSTEM_SERVICE;
    };
    let Some(slot) = HANDLERS[index as usize] else {
        kd::bugcheck(format_args!(
            "{}: NK does not implement this service (#{:#x}, args {:#x}, {:#x}, {:#x}, {:#x})",
            entry.name, index, args[0], args[1], args[2], args[3]
        ))
    };
    // SAFETY: per caller contract.
    unsafe { (slot.trampoline)(args) }
}

/// Exercise `ExGetPreviousMode`, `PreviousModeGuard`, `Zw*` thunk mode
/// switching, and out-of-range SSDT dispatch.
pub fn self_test() -> Result<(), &'static str> {
    use crate::ke::thread::{ExGetPreviousMode, PreviousModeGuard};
    use nk_ntabi::io::{KERNEL_MODE, USER_MODE};
    use nk_ntabi::status::STATUS_INVALID_HANDLE;

    if ExGetPreviousMode() != KERNEL_MODE {
        return Err("kernel thread PreviousMode did not start as KernelMode");
    }
    {
        let _u = PreviousModeGuard::enter(USER_MODE);
        if ExGetPreviousMode() != USER_MODE {
            return Err("PreviousModeGuard::enter(UserMode) did not switch mode");
        }
        // Calling a Zw* thunk from UserMode must enter Nt* with KernelMode and
        // restore UserMode on return.
        let status = zw::ZwClose(core::ptr::with_exposed_provenance_mut(0x7FFC));
        if status != STATUS_INVALID_HANDLE {
            return Err("ZwClose on an invalid handle did not return STATUS_INVALID_HANDLE");
        }
        if ExGetPreviousMode() != USER_MODE {
            return Err("ZwClose did not restore PreviousMode on return");
        }
    }
    if ExGetPreviousMode() != KERNEL_MODE {
        return Err("PreviousModeGuard drop did not restore KernelMode");
    }
    let zeros = [0usize; MAX_SYSCALL_ARGS];
    // SAFETY: out-of-range index returns STATUS_INVALID_SYSTEM_SERVICE without
    // invoking any service handler.
    let oob = unsafe { dispatch(SERVICE_COUNT as u32, &zeros) };
    if oob != STATUS_INVALID_SYSTEM_SERVICE {
        return Err("out-of-range service index did not return STATUS_INVALID_SYSTEM_SERVICE");
    }
    Ok(())
}
