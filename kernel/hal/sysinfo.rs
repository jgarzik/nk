//! `HalDispatchTable.HalQuerySystemInformation`: what drivers ask the
//! HAL about the machine, by information class
//! ([`HAL_QUERY_INFORMATION_CLASS`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntddk/ne-ntddk-_hal_query_information_class)).
//!
//! The classes Microsoft's drivers reach are answered as the pinned
//! kernel's HAL answers them on a machine like NK's; any other class
//! stops the system naming it.

#![allow(non_snake_case)]

use super::dispatch::{HalDispatchTable, public_slot};
use core::ffi::c_void;
use core::sync::atomic::{AtomicU64, Ordering};
use nk_ntabi::status::{
    NTSTATUS, STATUS_INFO_LENGTH_MISMATCH, STATUS_SUCCESS, STATUS_UNSUCCESSFUL,
};

/// `HalQueryDebuggerInformation`: the devices the kernel debugger uses.
const DEBUGGER_INFORMATION: u32 = 33;

/// `HalQueryAMLIIllegalIOPortAddresses`: the I/O ports the ACPI
/// driver's interpreter must keep firmware's AML code away from.
const AML_ILLEGAL_PORTS: u32 = 16;

/// `HAL_AMLI_BAD_IO_ADDRESS_LIST`: one run of ports. The list ends with
/// an entry of zeros.
#[repr(C)]
struct BadIoAddress {
    begin: u32,
    size: u32,
    os_version_trigger: u32,
    /// Padding, written as zero: the list is copied to a driver.
    reserved: u32,
    /// The routine that carries an access out for the AML, or null:
    /// the access is refused.
    handler: usize,
}

const _: () = assert!(size_of::<BadIoAddress>() == 0x18);

/// The configuration address AML last wrote to port 0xCF8, and above
/// bit 32 whether it has written one.
static AML_PCI_ADDRESS: AtomicU64 = AtomicU64::new(0);

/// The handler of the PCI configuration ports in the list: AML's
/// accesses to 0xCF8 to 0xCFF are not made on the ports, which belong
/// to the HAL, but carried out by it. A write of the address port is
/// remembered; an access of the data ports reads or writes the
/// configuration register the remembered address names, through the
/// HAL's own access. Anything else fails, as in Windows' routine.
///
/// # Safety
/// `data` points to four bytes, readable and writable.
pub unsafe extern "C" fn aml_pci_ports(read: u8, port: u32, size: u32, data: *mut u32) -> NTSTATUS {
    const ADDRESS: u32 = 0xCF8;
    const DATA: u32 = 0xCFC;
    if port == ADDRESS {
        // SAFETY: the caller's.
        let address = unsafe { data.read_unaligned() };
        AML_PCI_ADDRESS.store(1 << 32 | u64::from(address), Ordering::Release);
        return STATUS_SUCCESS;
    }
    let latched = AML_PCI_ADDRESS.load(Ordering::Acquire);
    if !(DATA..DATA + 4).contains(&port) || latched >> 32 == 0 || size == 0 || size > 4 {
        return STATUS_UNSUCCESSFUL;
    }
    let address = latched as u32;
    let function = super::pci::Function {
        segment: 0,
        bus: (address >> 16) as u8,
        device: (address >> 11 & 0x1F) as u8,
        function: (address >> 8 & 7) as u8,
    };
    let offset = (address & 0xFC) + (port - DATA);
    let mut bytes = [0u8; 4];
    let part = &mut bytes[..size as usize];
    // SAFETY: the caller's four bytes.
    unsafe {
        if read != 0 {
            super::pci::read(function, offset, part);
            data.write_unaligned(u32::from_le_bytes(bytes));
        } else {
            part.copy_from_slice(&data.read_unaligned().to_le_bytes()[..size as usize]);
            super::pci::write(function, offset, part);
        }
    }
    STATUS_SUCCESS
}

/// The routine in the slot.
///
/// # Safety
/// `buffer` points to `size` writable bytes; `returned` is null or
/// points to a writable `ULONG`.
pub unsafe extern "C" fn HalQuerySystemInformation(
    class: u32,
    size: u32,
    buffer: *mut c_void,
    returned: *mut u32,
) -> NTSTATUS {
    let give = |length: u32| {
        if !returned.is_null() {
            // SAFETY: the caller's.
            unsafe { returned.write_unaligned(length) };
        }
    };
    give(0);
    match class {
        // Windows' HAL says the answer is four bytes long, and fails
        // when its list of debugging devices is empty. NK's always is:
        // it speaks no Windows debugger protocol.
        DEBUGGER_INFORMATION => {
            give(4);
            STATUS_UNSUCCESSFUL
        }
        // The architecture's list and the terminating entry of zeros.
        // Too small a buffer is told the size, as on Windows.
        AML_ILLEGAL_PORTS => {
            let ports = crate::arch::AML_FORBIDDEN_PORTS;
            let needed = ((ports.len() + 1) * size_of::<BadIoAddress>()) as u32;
            if size < needed {
                give(needed);
                return STATUS_INFO_LENGTH_MISMATCH;
            }
            let list = buffer.cast::<BadIoAddress>();
            for (n, &(begin, count, trigger, carried_out)) in ports.iter().enumerate() {
                let entry = BadIoAddress {
                    begin,
                    size: count,
                    os_version_trigger: trigger,
                    reserved: 0,
                    handler: if carried_out {
                        aml_pci_ports as *const () as usize
                    } else {
                        0
                    },
                };
                // SAFETY: the caller's buffer, of `needed` bytes.
                unsafe { list.add(n).write_unaligned(entry) };
            }
            let end = BadIoAddress {
                begin: 0,
                size: 0,
                os_version_trigger: 0,
                reserved: 0,
                handler: 0,
            };
            // SAFETY: as above; the last entry.
            unsafe { list.add(ports.len()).write_unaligned(end) };
            give(needed);
            STATUS_SUCCESS
        }
        _ => crate::kd::bugcheck(format_args!(
            "HalQuerySystemInformation: NK does not implement information class {class} \
             (buffer of {size:#x} bytes)"
        )),
    }
}

/// Put the routine in its slot.
pub fn init() {
    HalDispatchTable.provide(
        public_slot("HalQuerySystemInformation"),
        HalQuerySystemInformation as *const (),
    );
}

/// For the self-tests.
pub fn test() -> Result<(), &'static str> {
    let mut returned = 77u32;
    // SAFETY: no buffer, of no length; a local for the length.
    let status = unsafe {
        HalQuerySystemInformation(
            DEBUGGER_INFORMATION,
            0,
            core::ptr::null_mut(),
            &raw mut returned,
        )
    };
    if status != STATUS_UNSUCCESSFUL || returned != 4 {
        return Err("debugging devices were not reported as none, four bytes long");
    }
    // The forbidden ports: the size first, then the list, which ends
    // with an entry of zeros.
    let mut needed = 0u32;
    // SAFETY: no buffer, of no length.
    let status = unsafe {
        HalQuerySystemInformation(AML_ILLEGAL_PORTS, 0, core::ptr::null_mut(), &raw mut needed)
    };
    let ports = crate::arch::AML_FORBIDDEN_PORTS;
    if status != STATUS_INFO_LENGTH_MISMATCH || needed as usize != (ports.len() + 1) * 0x18 {
        return Err("the size of the list of forbidden ports was not told");
    }
    let mut list = [0xFFu8; 0x18 * 24];
    // SAFETY: a local larger than the list.
    let status = unsafe {
        HalQuerySystemInformation(
            AML_ILLEGAL_PORTS,
            list.len() as u32,
            list.as_mut_ptr().cast(),
            &raw mut returned,
        )
    };
    let last = &list[ports.len() * 0x18..][..0x18];
    if status != STATUS_SUCCESS || returned != needed || last.iter().any(|&b| b != 0) {
        return Err("the list of forbidden ports was not given, ended by zeros");
    }
    if let Some(n) = ports.iter().position(|port| port.3) {
        let entry = &list[n * 0x18..][..0x18];
        let handler = usize::from_le_bytes(entry[16..24].try_into().unwrap_or([0; 8]));
        if handler != aml_pci_ports as *const () as usize || entry[..4] != 0xCF8u32.to_le_bytes() {
            return Err("the configuration ports are not carried out by the HAL");
        }
        // Through the handler, the host bridge's vendor is read as the
        // HAL's own access reads it.
        let mut word = 0x8000_0000u32;
        let mut own = [0u8; 2];
        let bridge = super::pci::Function {
            segment: 0,
            bus: 0,
            device: 0,
            function: 0,
        };
        super::pci::read(bridge, 0, &mut own);
        // SAFETY: a local word for the address and for the data.
        let read = unsafe {
            aml_pci_ports(0, 0xCF8, 4, &raw mut word) == STATUS_SUCCESS
                && aml_pci_ports(1, 0xCFC, 2, &raw mut word) == STATUS_SUCCESS
        };
        if !read || word as u16 != u16::from_le_bytes(own) {
            return Err("an access the HAL carries out did not read the register");
        }
        // SAFETY: a port the handler does not serve.
        if unsafe { aml_pci_ports(1, 0xCF9, 1, &raw mut word) } != STATUS_UNSUCCESSFUL {
            return Err("an access to a port between the two was not refused");
        }
    }
    if HalDispatchTable.routine(public_slot("HalQuerySystemInformation"))
        != HalQuerySystemInformation as *mut ()
    {
        return Err("the routine is not in its slot");
    }
    Ok(())
}
