//! The HAL as a bus driver: `\Driver\ACPI_HAL`.
//!
//! As on Windows, the HAL reports a device of its own to the Plug and
//! Play manager (`ROOT\ACPI_HAL\0000`), attaches a device to it, and
//! reports one child on that device's bus: `ACPI_HAL\PNP0C08\0`, the
//! device the ACPI driver is the function driver of. Everything else
//! in the machine is found below that one.
//!
//! What the two devices answer is what the pinned kernel's HAL answers
//! (`HalpDispatchPnp` and the routines it calls); what Windows' HAL
//! answers and NK's does not is listed at `pdo_pnp`.

use crate::arch;
use crate::io::{device, driver, irp};
use crate::mm::pool;
use crate::pnp::root::{complete, complete_unchanged, pool_string, relations_of};
use core::sync::atomic::{AtomicPtr, Ordering};
use nk_ntabi::io::*;
use nk_ntabi::pnp::*;
use nk_ntabi::status::*;
use nk_pnp::resources::{IoDescriptor, IoList, Partial, Requirements, ResourceList};

/// The service name of the HAL's driver, as Windows names it.
const SERVICE: &str = "ACPI_HAL";
/// `FILE_DEVICE_BUS_EXTENDER`.
const FILE_DEVICE_BUS_EXTENDER: u32 = 0x2A;
/// `PNPBus`, and "no bus number".
const PNP_BUS: u32 = 15;
const NO_BUS: u32 = u32::MAX;
/// `CmResourceShareDeviceExclusive`.
const DEVICE_EXCLUSIVE: u8 = 1;

/// What the child answers for its device and hardware identifiers, and
/// for its instance.
const CHILD_IDS: &str = "ACPI_HAL\\PNP0C08\0*PNP0C08\0";
const CHILD_INSTANCE: &str = "0";

/// Which of the HAL's devices a device object is.
#[repr(u32)]
#[derive(Clone, Copy, PartialEq, Eq)]
enum Kind {
    /// The HAL's device on top of the reported physical device.
    Function = 1,
    /// The child: the ACPI driver's physical device.
    Child = 2,
}

/// The extension of the HAL's devices.
#[repr(C)]
struct Extension {
    kind: Kind,
    /// For the function device: what it is attached to.
    lower: *mut DEVICE_OBJECT,
}

/// The physical device the HAL reported, and its child.
static REPORTED: AtomicPtr<DEVICE_OBJECT> = AtomicPtr::new(core::ptr::null_mut());
static CHILD: AtomicPtr<DEVICE_OBJECT> = AtomicPtr::new(core::ptr::null_mut());

/// Whether `pdo` is the device the HAL reported: its child's interrupt
/// resources are vectors as they stand, not lines to translate.
pub fn is_hal_device(pdo: usize) -> bool {
    pdo != 0 && pdo == REPORTED.load(Ordering::Acquire) as usize
}

/// The requirements of the ACPI driver's device: one exclusive
/// interrupt per number the architecture's HAL offers.
fn child_requirements() -> Option<Requirements> {
    let runs = arch::acpi_device_interrupts();
    if runs.is_empty() {
        return None;
    }
    let descriptors = runs
        .iter()
        .flat_map(|(first, count)| *first..*first + *count)
        .map(|number| IoDescriptor::interrupt(0, DEVICE_EXCLUSIVE, 0, number, number))
        .collect();
    Some(Requirements {
        interface: PNP_BUS,
        bus: NO_BUS,
        slot: 0,
        lists: alloc::vec![IoList {
            version: 1,
            revision: 1,
            descriptors,
        }],
    })
}

/// Its boot configuration: the same interrupts, each at the IRQL its
/// number has as a vector (`HalpQueryResources`), for any processor.
fn child_resources() -> Option<ResourceList> {
    let requirements = child_requirements()?;
    let partials = requirements.lists[0]
        .descriptors
        .iter()
        .filter_map(|descriptor| descriptor.wanted())
        .map(|wanted| {
            let vector = wanted.minimum as u32;
            // What the reference Windows recorded (`LogConf\BootConfig`):
            // a number above the vectors has the lowest device IRQL.
            let level = if vector <= 0xFF {
                (vector >> 4) as u16
            } else {
                3
            };
            Partial::interrupt(DEVICE_EXCLUSIVE, 0, level, 0, vector, u64::MAX)
        })
        .collect();
    Some(ResourceList::of(PNP_BUS, NO_BUS, partials))
}

/// `bytes` in a pool block the receiver frees; zero without memory.
fn pool_bytes(bytes: &[u8]) -> usize {
    let block = pool::alloc(bytes.len(), crate::pnp::TAG);
    if !block.is_null() {
        // SAFETY: a fresh block of that length.
        unsafe { block.copy_from_nonoverlapping(bytes.as_ptr(), bytes.len()) };
    }
    block as usize
}

/// Complete `request` with what `answer` allocated, or for want of
/// memory.
///
/// # Safety
/// `request` is an IRP its caller owns.
unsafe fn complete_with(request: *mut IRP, answer: usize) -> NTSTATUS {
    // SAFETY: per the contract.
    unsafe {
        match answer {
            0 => complete(request, STATUS_INSUFFICIENT_RESOURCES, 0),
            answer => complete(request, STATUS_SUCCESS, answer),
        }
    }
}

/// The child's answers. Windows' HAL also hands out three interfaces
/// from here (`GUID_BUS_INTERFACE_STANDARD`, the ACPI CMOS interface,
/// the DMA cache-coherency interface): NK's hands out none, and a
/// query for one comes back as it was sent.
///
/// # Safety
/// `request` is a Plug and Play IRP at the HAL's location.
unsafe fn pdo_pnp(request: *mut IRP) -> NTSTATUS {
    // SAFETY: per the contract.
    unsafe {
        let location = (*request).CurrentStackLocation;
        let parameters = (*location).Parameters;
        let wide = |text: &str| {
            text.encode_utf16()
                .chain([0])
                .collect::<alloc::vec::Vec<u16>>()
        };
        match (*location).MinorFunction {
            IRP_MN_QUERY_ID => match parameters[0] as u32 {
                // One string serves both: the device identifier is the
                // first of the hardware identifiers.
                BUS_QUERY_DEVICE_ID | BUS_QUERY_HARDWARE_IDS => {
                    complete_with(request, pool_string(&wide(CHILD_IDS)))
                }
                BUS_QUERY_INSTANCE_ID => complete_with(request, pool_string(&wide(CHILD_INSTANCE))),
                _ => complete_unchanged(request),
            },
            IRP_MN_QUERY_CAPABILITIES => {
                let capabilities = parameters[0] as *mut DEVICE_CAPABILITIES;
                if (&raw const (*capabilities).Version).read_unaligned() != 1 {
                    return complete_unchanged(request);
                }
                // Unique and silently installed; not lockable,
                // ejectable, removable, a dock, or usable raw. D0 while
                // the system works, D3 when it hibernates or shuts down.
                const CLEARED: u32 = DEVICE_CAPABILITY_LOCK_SUPPORTED
                    | DEVICE_CAPABILITY_EJECT_SUPPORTED
                    | DEVICE_CAPABILITY_REMOVABLE
                    | DEVICE_CAPABILITY_DOCK_DEVICE
                    | DEVICE_CAPABILITY_RAW_DEVICE_OK;
                let flags = &raw mut (*capabilities).Flags;
                flags.write_unaligned(
                    (flags.read_unaligned() & !CLEARED)
                        | DEVICE_CAPABILITY_UNIQUE_ID
                        | DEVICE_CAPABILITY_SILENT_INSTALL,
                );
                (&raw mut (*capabilities).Address).write_unaligned(u32::MAX);
                (&raw mut (*capabilities).UINumber).write_unaligned(u32::MAX);
                let states = (&raw mut (*capabilities).DeviceState).cast::<u32>();
                states
                    .add(POWER_SYSTEM_WORKING as usize)
                    .write_unaligned(POWER_DEVICE_D0);
                for state in [POWER_SYSTEM_HIBERNATE, POWER_SYSTEM_SHUTDOWN] {
                    states.add(state as usize).write_unaligned(POWER_DEVICE_D3);
                }
                (&raw mut (*capabilities).D1Latency).write_unaligned(0);
                (&raw mut (*capabilities).D2Latency).write_unaligned(0);
                (&raw mut (*capabilities).D3Latency).write_unaligned(0);
                complete(request, STATUS_SUCCESS, 0)
            }
            IRP_MN_QUERY_RESOURCE_REQUIREMENTS => match child_requirements() {
                Some(list) => complete_with(request, pool_bytes(&list.to_bytes())),
                None => complete_unchanged(request),
            },
            IRP_MN_QUERY_RESOURCES => match child_resources() {
                Some(list) => complete_with(request, pool_bytes(&list.to_bytes())),
                None => complete_unchanged(request),
            },
            IRP_MN_QUERY_DEVICE_RELATIONS => match parameters[0] as u32 {
                TARGET_DEVICE_RELATION => {
                    let own = CHILD.load(Ordering::Acquire) as usize;
                    complete_with(request, relations_of(&[own]))
                }
                _ => complete_unchanged(request),
            },
            IRP_MN_START_DEVICE
            | IRP_MN_QUERY_PNP_DEVICE_STATE
            | IRP_MN_DEVICE_USAGE_NOTIFICATION => {
                let information = (*request).IoStatus.Information;
                complete(request, STATUS_SUCCESS, information)
            }
            _ => complete_unchanged(request),
        }
    }
}

/// The HAL's dispatch routine for Plug and Play requests.
///
/// # Safety
/// Called as a dispatch routine.
unsafe extern "C" fn dispatch_pnp(device: *mut DEVICE_OBJECT, request: *mut IRP) -> NTSTATUS {
    // SAFETY: a live request at the HAL's location, for one of its
    // devices, whose extension `make` set up.
    unsafe {
        let extension = (*device).DeviceExtension.cast::<Extension>();
        if (*extension).kind == Kind::Child {
            return pdo_pnp(request);
        }
        let location = (*request).CurrentStackLocation;
        let parameters = (*location).Parameters;
        match ((*location).MinorFunction, parameters[0] as u32) {
            (IRP_MN_QUERY_DEVICE_RELATIONS, BUS_RELATIONS) => {
                let child = CHILD.load(Ordering::Acquire) as usize;
                match relations_of(&[child]) {
                    0 => return complete(request, STATUS_INSUFFICIENT_RESOURCES, 0),
                    list => {
                        (*request).IoStatus.Status = STATUS_SUCCESS;
                        (*request).IoStatus.Information = list;
                    }
                }
            }
            (IRP_MN_QUERY_ID, BUS_QUERY_HARDWARE_IDS) => {
                if let Some(id) = arch::hal_hardware_id() {
                    let list: alloc::vec::Vec<u16> = id.encode_utf16().chain([0, 0]).collect();
                    match pool_string(&list) {
                        0 => return complete(request, STATUS_INSUFFICIENT_RESOURCES, 0),
                        text => {
                            (*request).IoStatus.Status = STATUS_SUCCESS;
                            (*request).IoStatus.Information = text;
                        }
                    }
                }
            }
            _ => {}
        }
        pass_down(extension, request)
    }
}

/// Pass `request` to the device the HAL's function device is attached
/// to, without a location of its own (`IoSkipCurrentIrpStackLocation`).
///
/// # Safety
/// `extension` is the function device's; `request` is at its location.
unsafe fn pass_down(extension: *mut Extension, request: *mut IRP) -> NTSTATUS {
    // SAFETY: per the contract.
    unsafe {
        (*request).CurrentLocation += 1;
        (*request).CurrentStackLocation = (*request).CurrentStackLocation.add(1);
        irp::IofCallDriver((*extension).lower, request)
    }
}

/// The HAL's dispatch routine for power requests: the child has no
/// power state of its own, and the function device passes them on.
///
/// # Safety
/// Called as a dispatch routine.
unsafe extern "C" fn dispatch_power(device: *mut DEVICE_OBJECT, request: *mut IRP) -> NTSTATUS {
    irp::PoStartNextPowerIrp(request);
    // SAFETY: as in `dispatch_pnp`.
    unsafe {
        let extension = (*device).DeviceExtension.cast::<Extension>();
        if (*extension).kind == Kind::Child {
            complete_unchanged(request)
        } else {
            pass_down(extension, request)
        }
    }
}

/// A device of the HAL's.
fn make(
    driver: *mut DRIVER_OBJECT,
    kind: Kind,
    characteristics: u32,
) -> Result<*mut DEVICE_OBJECT, &'static str> {
    let mut made = core::ptr::null_mut();
    // SAFETY: the HAL's driver object; no name of the HAL's choosing;
    // `made` is writable.
    let status = unsafe {
        device::IoCreateDevice(
            driver,
            size_of::<Extension>() as u32,
            core::ptr::null(),
            FILE_DEVICE_BUS_EXTENDER,
            characteristics,
            0,
            &raw mut made,
        )
    };
    if !nt_success(status) {
        return Err("a device of the HAL's could not be made");
    }
    // SAFETY: the device just made and its extension, which nothing
    // else knows yet.
    unsafe {
        (*made)
            .DeviceExtension
            .cast::<Extension>()
            .write(Extension {
                kind,
                lower: core::ptr::null_mut(),
            });
    }
    Ok(made)
}

/// Make the HAL's driver, report its device, attach to it, and make
/// the child. After the Plug and Play manager's root exists, before
/// any driver starts.
pub fn init() -> Result<(), &'static str> {
    let driver = driver::builtin(SERVICE, |object| {
        // SAFETY: the driver object being set up.
        unsafe {
            (*object).MajorFunction[usize::from(IRP_MJ_PNP)] = Some(dispatch_pnp);
            (*object).MajorFunction[usize::from(IRP_MJ_POWER)] = Some(dispatch_power);
        }
    })
    .map_err(|_| "the HAL's driver object could not be made")?;
    let reported = crate::pnp::report_detected_device(SERVICE, Some("Internal"))
        .map_err(|_| "the HAL's device could not be reported")?;
    let function = make(driver, Kind::Function, 0)?;
    let child = make(
        driver,
        Kind::Child,
        crate::pnp::root::FILE_AUTOGENERATED_DEVICE_NAME,
    )?;
    // SAFETY: devices just made; the function device is attached while
    // it is still initialising, as a driver's `AddDevice` does it, and
    // both are opened for requests after.
    unsafe {
        let lower = device::IoAttachDeviceToDeviceStack(function, reported);
        if lower.is_null() {
            return Err("the HAL's device could not be attached");
        }
        (*(*function).DeviceExtension.cast::<Extension>()).lower = lower;
        (*function).Flags &= !DO_DEVICE_INITIALIZING;
        (*child).Flags &= !DO_DEVICE_INITIALIZING;
    }
    REPORTED.store(reported, Ordering::Release);
    CHILD.store(child, Ordering::Release);
    Ok(())
}
