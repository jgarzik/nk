//! Parts of Windows NK runs without, the debug message filter and the
//! stack probe, through the routines drivers import.

use crate::ex::{absent, vsl};
use crate::rtl::print;
use crate::test::{Group, Report};
use core::sync::atomic::{AtomicU32, Ordering};
use nk_bootinfo::BootInfo;
use nk_ntabi::status::{
    STATUS_DEBUGGER_INACTIVE, STATUS_DEVICE_NOT_CONNECTED, STATUS_INVALID_PARAMETER,
    STATUS_NOT_FOUND, STATUS_SUCCESS, STATUS_UNSUCCESSFUL,
};

pub static GROUP: Group = Group {
    names: &[
        "ex.verifier-off",
        "ex.headless-off",
        "ex.secure-devices",
        "ex.hypervisor",
        "io.no-paging-file",
        "rtl.debug-filter",
        "cpu.stack-probe",
        "kd.no-debugger",
        "ex.sysinfo.with-input",
    ],
    run,
    manual: false,
};

fn verifier_off() -> Result<(), &'static str> {
    let object = 0u64;
    if absent::VfIsVerificationEnabled(1, (&raw const object).cast()) != 0 {
        return Err("the driver verifier was reported as running");
    }
    // Reports to a verifier that is not running go nowhere.
    absent::VfFailDeviceNode((&raw const object).cast(), 0xC4, 1);
    absent::VfFailSystemBIOS(0xC4, 1);
    Ok(())
}

fn headless_off() -> Result<(), &'static str> {
    let none = core::ptr::null();
    let mut answer = [0xFFu8; 8];
    let mut size = 6usize;
    // SAFETY: a buffer and its length in locals, or neither.
    unsafe {
        if absent::HeadlessDispatch(1, none, 0, core::ptr::null_mut(), core::ptr::null_mut())
            != STATUS_UNSUCCESSFUL
            || absent::HeadlessDispatch(0x15, none, 0, core::ptr::null_mut(), core::ptr::null_mut())
                != STATUS_UNSUCCESSFUL
        {
            return Err("a terminal that is not there was enabled or took data");
        }
        // A question: zeros, for the length given and no further.
        if absent::HeadlessDispatch(2, none, 0, answer.as_mut_ptr().cast(), &raw mut size)
            != STATUS_SUCCESS
            || answer != [0, 0, 0, 0, 0, 0, 0xFF, 0xFF]
        {
            return Err("a question was not answered with zeros");
        }
        if absent::HeadlessDispatch(2, none, 0, core::ptr::null_mut(), &raw mut size)
            != STATUS_INVALID_PARAMETER
        {
            return Err("a question with nowhere to answer was not refused");
        }
        // Output: nowhere to go, and no failure.
        if absent::HeadlessDispatch(
            3,
            c"text".as_ptr().cast(),
            5,
            core::ptr::null_mut(),
            core::ptr::null_mut(),
        ) != STATUS_SUCCESS
        {
            return Err("output to no terminal failed");
        }
    }
    Ok(())
}

fn secure_devices() -> Result<(), &'static str> {
    if vsl::VslGetSecurePciDeviceAlternateFunctionNumberForVtl0Dma(0, 0, 0x1F, 2) != 0xFF {
        return Err("a secure kernel that is not there named a function number");
    }
    let device = [0u8; 12];
    let mut answer = [0xFFu8; 16];
    // SAFETY: locals of the sizes the routine reads and writes.
    let status = unsafe { vsl::VslQuerySecureDevice(device.as_ptr().cast(), &raw mut answer) };
    if status != STATUS_DEVICE_NOT_CONNECTED || answer != [0; 16] {
        return Err("a device was known to a secure kernel that is not there");
    }
    Ok(())
}

fn hypervisor() -> Result<(), &'static str> {
    let mut features = [0xFFFF_FFFFu32; 4];
    // SAFETY: a local of four words.
    unsafe { absent::HviGetHypervisorFeatures(&raw mut features) };
    if features != crate::arch::platform::hypervisor_features() {
        return Err("the hypervisor's features are not what the processor reports");
    }
    // Features only come from a hypervisor that is there.
    if absent::HviIsAnyHypervisorPresent() == 0 && features != [0; 4] {
        return Err("features were reported with no hypervisor");
    }
    Ok(())
}

fn no_paging_file() -> Result<(), &'static str> {
    let file = 0u64;
    if crate::io::fsrtl::FsRtlIsSystemPagingFile((&raw const file).cast()) != 0 {
        return Err("a file was taken for a paging file");
    }
    Ok(())
}

/// `DPFLTR_IHVDRIVER_ID`, and the levels.
const COMPONENT: u32 = 77;
const ERROR: u32 = 0;
const INFO: u32 = 3;

fn debug_filter() -> Result<(), &'static str> {
    if !print::debug_filter_passes(COMPONENT, ERROR) || print::debug_filter_passes(COMPONENT, INFO)
    {
        return Err("at boot the filter does not pass errors alone");
    }
    if print::DbgSetDebugFilterState(COMPONENT, INFO, 1) != STATUS_SUCCESS
        || !print::debug_filter_passes(COMPONENT, INFO)
        || print::debug_filter_passes(COMPONENT + 1, INFO)
    {
        return Err("a level turned on for a component does not pass for it alone");
    }
    let arguments = [7u64];
    // SAFETY: formats that name one integer, which is passed.
    unsafe {
        print::nk_variadic_DbgPrintEx(
            COMPONENT,
            INFO,
            c"filtered message %d\n".as_ptr().cast(),
            7u32,
        );
        print::vDbgPrintExWithPrefix(
            c"prefix: ".as_ptr().cast(),
            COMPONENT,
            INFO,
            c"message %d\n".as_ptr().cast(),
            arguments.as_ptr(),
        );
    }
    if print::DbgSetDebugFilterState(COMPONENT, INFO, 0) != STATUS_SUCCESS
        || print::debug_filter_passes(COMPONENT, INFO)
    {
        return Err("a level turned off still passes");
    }
    // The mask of every component.
    print::DbgSetDebugFilterState(u32::MAX, INFO, 1);
    let all = print::debug_filter_passes(COMPONENT + 1, INFO);
    print::DbgSetDebugFilterState(u32::MAX, INFO, 0);
    if !all || print::debug_filter_passes(COMPONENT + 1, INFO) {
        return Err("the mask of every component was not turned on and off");
    }
    // No debugger takes a command: nothing happens.
    print::DbgCommandString(c"name".as_ptr().cast(), c"command".as_ptr().cast());
    Ok(())
}

extern "C" fn power_handler() {
    POWER_HANDLER_CALLS.fetch_add(1, Ordering::Relaxed);
}

static POWER_HANDLER_CALLS: AtomicU32 = AtomicU32::new(0);

fn no_debugger() -> Result<(), &'static str> {
    use crate::kd::debugger;
    use crate::ke::irql;
    // The debugger's lock is a real one.
    let before = irql::current();
    let mut old = 0xFFu8;
    // SAFETY: a local for the IRQL; released with what was given.
    unsafe {
        debugger::KdAcquireDebuggerLock(&raw mut old);
        let held_at = irql::current();
        debugger::KdReleaseDebuggerLock(old);
        if old != before || held_at != irql::DISPATCH_LEVEL || irql::current() != before {
            return Err("the debugger's lock was not held at DISPATCH_LEVEL and given back");
        }
    }
    if debugger::KdDisableDebugger() != STATUS_DEBUGGER_INACTIVE
        || debugger::KdEnableDebugger() != STATUS_DEBUGGER_INACTIVE
    {
        return Err("a debugger that is not there was turned off or on");
    }
    // A power handler registers; with no debugger nothing calls it.
    let mut handle = core::ptr::null_mut();
    // SAFETY: a local for the handle.
    let status = unsafe {
        debugger::KdRegisterPowerHandler(
            power_handler as *mut core::ffi::c_void,
            core::ptr::null_mut(),
            &raw mut handle,
        )
    };
    if status != STATUS_SUCCESS || handle.is_null() {
        return Err("a power handler was not registered");
    }
    if debugger::KdPowerTransitionEx(5, 0) != STATUS_SUCCESS
        || POWER_HANDLER_CALLS.load(Ordering::Relaxed) != 0
    {
        return Err("a power transition did not succeed without calling handlers");
    }
    if debugger::KdDeregisterPowerHandler(handle) != STATUS_SUCCESS
        || debugger::KdDeregisterPowerHandler(handle) != STATUS_NOT_FOUND
    {
        return Err("a power handler was not deregistered once");
    }
    Ok(())
}

fn sysinfo_with_input() -> Result<(), &'static str> {
    use crate::ex::sysinfo_ex::NtQuerySystemInformationEx as query;
    use nk_ntabi::interrupt::GROUP_AFFINITY;
    use nk_ntabi::status::STATUS_INFO_LENGTH_MISMATCH;
    use nk_ntabi::sysinfo::{
        GROUP_RELATIONSHIP_ENTRY, NUMA_NODE_RELATIONSHIP_ENTRY,
        SYSTEM_INTERRUPT_STEERING_INFORMATION_INPUT,
    };
    let online = crate::ke::smp::online();
    let mut length = 0u32;
    let numa = 1u32;
    let group = 4u32;
    let mut entry = [0u8; 0x50];
    // SAFETY: inputs, outputs and lengths in locals, of the sizes
    // given.
    unsafe {
        // As pci.sys asks: the length first, then the entry.
        if query(
            107,
            (&raw const numa).cast(),
            4,
            core::ptr::null_mut(),
            0,
            &raw mut length,
        ) != STATUS_INFO_LENGTH_MISMATCH
            || length != 0x30
        {
            return Err("the length of the NUMA node's entry was not reported");
        }
        if query(
            107,
            (&raw const numa).cast(),
            4,
            entry.as_mut_ptr().cast(),
            0x30,
            &raw mut length,
        ) != STATUS_SUCCESS
        {
            return Err("the NUMA node was not reported");
        }
        let node = entry
            .as_ptr()
            .cast::<NUMA_NODE_RELATIONSHIP_ENTRY>()
            .read_unaligned();
        if (node.Relationship, node.Size, node.NodeNumber) != (1, 0x30, 0)
            || node.GroupMask.Mask as u64 != online
            || node.GroupMask.Group != 0
        {
            return Err("the NUMA node is not the one node of every running processor");
        }
        if query(
            107,
            (&raw const group).cast(),
            4,
            entry.as_mut_ptr().cast(),
            0x50,
            &raw mut length,
        ) != STATUS_SUCCESS
            || length != 0x50
        {
            return Err("the processor group was not reported");
        }
        let groups = entry
            .as_ptr()
            .cast::<GROUP_RELATIONSHIP_ENTRY>()
            .read_unaligned();
        if (groups.ActiveGroupCount, groups.MaximumGroupCount) != (1, 1)
            || u32::from(groups.ActiveProcessorCount) != online.count_ones()
            || groups.ActiveProcessorMask as u64 != online
        {
            return Err("the group is not the one group of every running processor");
        }
        if query(
            107,
            core::ptr::null(),
            4,
            entry.as_mut_ptr().cast(),
            0x50,
            &raw mut length,
        ) != STATUS_INVALID_PARAMETER
            || query(
                107,
                (&raw const numa).cast(),
                0,
                entry.as_mut_ptr().cast(),
                0x50,
                &raw mut length,
            ) != STATUS_INVALID_PARAMETER
        {
            return Err("a question without its input was not refused");
        }
        // Interrupt steering, as pci.sys asks about it.
        let question = SYSTEM_INTERRUPT_STEERING_INFORMATION_INPUT {
            Gsiv: u32::MAX,
            ControllerInterrupt: 1,
            EdgeInterrupt: 0,
            IsPrimaryInterrupt: 0,
            TargetAffinity: GROUP_AFFINITY {
                Mask: 0,
                Group: 0,
                Reserved: [0; 3],
            },
        };
        let mut steered = 0xFFFF_FFFFu32;
        if query(
            180,
            (&raw const question).cast(),
            0x18,
            (&raw mut steered).cast(),
            4,
            core::ptr::null_mut(),
        ) != STATUS_SUCCESS
            || steered != 0
        {
            return Err("interrupts were not reported as not steered");
        }
        if query(
            180,
            (&raw const question).cast(),
            0x10,
            (&raw mut steered).cast(),
            4,
            &raw mut length,
        ) != STATUS_INFO_LENGTH_MISMATCH
        {
            return Err("a steering question of the wrong length was not refused");
        }
    }
    Ok(())
}

fn run(r: &mut Report, _: &BootInfo) {
    r.check("ex.verifier-off", verifier_off);
    r.check("ex.headless-off", headless_off);
    r.check("ex.secure-devices", secure_devices);
    r.check("ex.hypervisor", hypervisor);
    r.check("io.no-paging-file", no_paging_file);
    r.check("rtl.debug-filter", debug_filter);
    r.check("cpu.stack-probe", crate::arch::chkstk_test);
    r.check("kd.no-debugger", no_debugger);
    r.check("ex.sysinfo.with-input", sysinfo_with_input);
}

/// This file's test groups, in the order they run.
pub static GROUPS: &[&Group] = &[&GROUP];
