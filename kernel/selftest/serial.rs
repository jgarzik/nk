//! Microsoft's inbox `serial.sys` (with `serenum.sys` upper filter) on a
//! secondary ISA 16550 UART (COM2, 0x2F8), while NK's diagnostic console
//! retains COM1 (0x3F8) via `KdComPortInUse`.

use crate::io::file::{self, OpenRequest};
use crate::io::service;
use crate::ldr;
use crate::pnp::interface;
use crate::pnp::node::{self, State};
use crate::pnp::registry;
use crate::test::{Group, Report};
use nk_bootinfo::BootInfo;
use nk_ntabi::status::*;
use nk_pnp::resources::{ResourceList, TYPE_PORT};

pub static GROUP: Group = Group {
    names: &["serial.load", "serial.io"],
    run,
    manual: true,
};

pub static GROUPS: &[&Group] = &[&GROUP];

const PORTS_CLASS: &str = "{4d36e978-e325-11ce-bfc1-08002be10318}";

/// `GUID_DEVINTERFACE_COMPORT` = `{86E0D1E0-8089-11D0-9CE4-08003E301F73}`.
const GUID_DEVINTERFACE_COMPORT: [u8; 16] = [
    0xE0, 0xD1, 0xE0, 0x86, 0x89, 0x80, 0xD0, 0x11, 0x9C, 0xE4, 0x08, 0x00, 0x3E, 0x30, 0x1F, 0x73,
];

/// `ntddser.h` buffered control codes (`FILE_DEVICE_SERIAL_PORT = 0x1B`).
const IOCTL_SERIAL_SET_BAUD_RATE: u32 = 0x001B_0004;
const IOCTL_SERIAL_SET_LINE_CONTROL: u32 = 0x001B_000C;
const IOCTL_SERIAL_SET_TIMEOUTS: u32 = 0x001B_001C;
const IOCTL_SERIAL_PURGE: u32 = 0x001B_004C;
const IOCTL_SERIAL_GET_BAUD_RATE: u32 = 0x001B_0050;
const SERIAL_PURGE_RXCLEAR: u32 = 0x0000_0008;

/// Must match `tools/boot_test.py` (`SERIAL2_EXPECT` / `SERIAL2_REPLY`).
const TX_PAYLOAD: &[u8] = b"NK-SER-TX:HELLO-HOST\n";
const RX_EXPECT: &[u8] = b"NK-SER-RX:HELLO-GUEST\n";

fn com_ports() -> alloc::vec::Vec<node::Node> {
    node::all()
        .into_iter()
        .filter_map(node::get)
        .filter(|n| {
            n.instance
                .to_ascii_uppercase()
                .starts_with("ACPI\\PNP0501\\")
        })
        .collect()
}

fn port_base(n: &node::Node) -> Option<u64> {
    let (raw, _) = ResourceList::parse(&n.raw)?;
    raw.partials()
        .find(|p| p.kind == TYPE_PORT)
        .and_then(|p| p.as_range())
        .map(|(start, _)| start)
}

/// Verify COM2 (`0x2F8`) started through ACPI/PnP under `Serial` + `serenum`,
/// while COM1 (`0x3F8`) stayed untouched by `serial.sys`.
pub(super) fn verify_load() -> Result<(), &'static str> {
    if !service::running("Serial") || !service::running("serenum") {
        return Err("Serial or serenum service is not running");
    }
    if ldr::module_named("serial.sys").is_none() || ldr::module_named("serenum.sys").is_none() {
        return Err("serial.sys or serenum.sys is not loaded");
    }
    let ports = com_ports();
    let com2 = ports
        .iter()
        .find(|n| n.state == State::Started && port_base(n) == Some(0x2F8))
        .ok_or("no started ACPI\\PNP0501 device at COM2 (0x2F8)")?;
    // COM1 (0x3F8) must not be owned by a started serial.sys instance.
    if ports
        .iter()
        .any(|n| n.state == State::Started && port_base(n) == Some(0x3F8))
    {
        return Err("COM1 (0x3F8) was claimed despite KdComPortInUse");
    }
    let key = registry::enum_key(&com2.instance);
    if registry::string(&key, "Service").as_deref() != Some("Serial")
        || registry::string(&key, "ClassGUID").as_deref() != Some(PORTS_CLASS)
    {
        return Err("COM2 does not have Serial / Ports class");
    }
    // SAFETY: live device node in the tree.
    let stack =
        unsafe { crate::pnp::engine::stack_drivers(com2.pdo as *mut nk_ntabi::io::DEVICE_OBJECT) };
    kprintln!("serial: COM2 {} stack={stack:?}", com2.instance);
    if !stack
        .iter()
        .any(|d| d.eq_ignore_ascii_case("\\Driver\\Serial"))
        || !stack
            .iter()
            .any(|d| d.eq_ignore_ascii_case("\\Driver\\serenum"))
    {
        return Err("COM2 stack does not contain Serial and serenum");
    }
    Ok(())
}

/// Open COM2's published COMPORT interface, configure 115200 8N1 + timeouts,
/// write `TX_PAYLOAD` to the host peer, and read back `RX_EXPECT`.
pub(super) fn bidirectional_io() -> Result<(), &'static str> {
    let links = interface::enabled_of(&GUID_DEVINTERFACE_COMPORT);
    let link = links
        .iter()
        .find(|l| l.to_ascii_uppercase().contains("PNP0501"))
        .or_else(|| links.first())
        .ok_or("no enabled GUID_DEVINTERFACE_COMPORT interface")?;
    kprintln!("serial: opening {link}");
    let request = OpenRequest {
        desired_access: 0xC010_0000, // GENERIC_READ | GENERIC_WRITE | SYNCHRONIZE
        share_access: 0,
        ..OpenRequest::new(link)
    };
    let (handle, _) = file::open(&request).map_err(|status| {
        kprintln!("serial: open failed: {status:#x}");
        "could not open COM2 interface"
    })?;
    let outcome = (|| {
        // Configure 115200 baud, 8N1, and read/write timeouts.
        let baud = 115_200u32.to_le_bytes();
        let mut empty = [];
        let r = file::device_control(handle, IOCTL_SERIAL_SET_BAUD_RATE, &baud, &mut empty)
            .map_err(|_| "SET_BAUD_RATE refused")?;
        if r.status != STATUS_SUCCESS {
            kprintln!("serial: SET_BAUD_RATE status={:#x}", r.status);
            return Err("SET_BAUD_RATE failed");
        }
        let mut got_baud = [0u8; 4];
        let r = file::device_control(handle, IOCTL_SERIAL_GET_BAUD_RATE, &[], &mut got_baud)
            .map_err(|_| "GET_BAUD_RATE refused")?;
        if r.status != STATUS_SUCCESS || u32::from_le_bytes(got_baud) != 115_200 {
            return Err("GET_BAUD_RATE did not return 115200");
        }
        let line_ctrl = [0u8, 0u8, 8u8]; // 1 stop bit, no parity, 8 data bits
        let r = file::device_control(
            handle,
            IOCTL_SERIAL_SET_LINE_CONTROL,
            &line_ctrl,
            &mut empty,
        )
        .map_err(|_| "SET_LINE_CONTROL refused")?;
        if r.status != STATUS_SUCCESS {
            return Err("SET_LINE_CONTROL failed");
        }
        // ReadIntervalTimeout=500ms, ReadTotalTimeoutConstant=5000ms, WriteTotalTimeoutConstant=5000ms
        let mut timeouts = [0u8; 20];
        timeouts[0..4].copy_from_slice(&500u32.to_le_bytes());
        timeouts[8..12].copy_from_slice(&5000u32.to_le_bytes());
        timeouts[16..20].copy_from_slice(&5000u32.to_le_bytes());
        let r = file::device_control(handle, IOCTL_SERIAL_SET_TIMEOUTS, &timeouts, &mut empty)
            .map_err(|_| "SET_TIMEOUTS refused")?;
        if r.status != STATUS_SUCCESS {
            return Err("SET_TIMEOUTS failed");
        }
        let purge = SERIAL_PURGE_RXCLEAR.to_le_bytes();
        let _ = file::device_control(handle, IOCTL_SERIAL_PURGE, &purge, &mut empty);
        let w = file::write(handle, TX_PAYLOAD).map_err(|_| "serial write refused")?;
        if w.status != STATUS_SUCCESS || w.information != TX_PAYLOAD.len() {
            kprintln!("serial: write status={:#x} len={}", w.status, w.information);
            return Err("serial write failed");
        }
        let mut received = alloc::vec::Vec::new();
        let mut chunk = [0u8; 64];
        for _ in 0..8 {
            if received.len() >= RX_EXPECT.len() {
                break;
            }
            let r = file::read(handle, &mut chunk).map_err(|_| "serial read refused")?;
            if r.status != STATUS_SUCCESS && r.status != STATUS_TIMEOUT {
                kprintln!("serial: read status={:#x}", r.status);
                return Err("serial read failed");
            }
            received.extend_from_slice(&chunk[..r.information]);
        }
        if received != RX_EXPECT {
            kprintln!("serial: received {received:?}, expected {RX_EXPECT:?}");
            return Err("serial received payload did not match host peer");
        }
        Ok(())
    })();
    file::close(handle);
    outcome
}

fn run(r: &mut Report, _: &BootInfo) {
    crate::test::keeps_what_it_started();
    if ldr::boot_file("serial.sys").is_none() || ldr::boot_file("serenum.sys").is_none() {
        r.skip_rest(format_args!("serial.sys or serenum.sys not provided"));
        return;
    }
    r.check("serial.load", verify_load);
    r.check("serial.io", bidirectional_io);
}
