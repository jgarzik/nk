//! Microsoft's WDK KMDF Echo (AutoSync) sample driver (`echo.x64.sys`)
//! running on Microsoft's inbox KMDF runtime (`wdfldr.sys`, `wdf01000.sys`,
//! `sleepstudyhelper.sys`) through standard root PnP enumeration
//! (`ROOT\ECHO\0000`).

use crate::io::{file, service};
use crate::ldr;
use crate::pnp::interface;
use crate::pnp::node::{self, State};
use crate::pnp::registry;
use crate::test::{Group, Report};
use nk_bootinfo::BootInfo;
use nk_ntabi::status::STATUS_SUCCESS;
use nk_pnp::ids;

pub static GROUP: Group = Group {
    names: &["echo.load", "echo.io"],
    run,
    manual: true,
};

pub static GROUPS: &[&Group] = &[&GROUP];

/// `GUID_DEVINTERFACE_ECHO` from `Windows-driver-samples/general/echo/kmdf/driver/AutoSync/public.h`:
/// `{CDC35B6E-0BE4-4936-BF5F-5537380A7C1A}`.
const ECHO_INTERFACE: &str = "{cdc35b6e-0be4-4936-bf5f-5537380a7c1a}";

const IMAGES: [&str; 4] = [
    "wdfldr.sys",
    "wdf01000.sys",
    "sleepstudyhelper.sys",
    "kmdf-echo.sys",
];

fn load() -> Result<(), &'static str> {
    if !service::running("Wdf01000") {
        return Err("Wdf01000 service is not running");
    }
    if !service::running("Echo") {
        return Err("Echo service is not running");
    }
    let pdo = node::by_instance("ROOT\\ECHO\\0000").ok_or("ROOT\\ECHO\\0000 was not enumerated")?;
    let found = node::get(pdo).ok_or("ROOT\\ECHO\\0000 has no node")?;
    if found.state != State::Started {
        kprintln!(
            "echo: ROOT\\ECHO\\0000 state={:?} problem={}",
            found.state,
            found.problem
        );
        return Err("ROOT\\ECHO\\0000 did not start");
    }
    let key = registry::enum_key(&found.instance);
    if registry::string(&key, "Service").as_deref() != Some("Echo") {
        return Err("ROOT\\ECHO\\0000 is not bound to service Echo");
    }
    Ok(())
}

/// Write and read back two distinct payloads on the KMDF Echo device interface.
fn io() -> Result<(), &'static str> {
    let class = ids::guid_from_text(ECHO_INTERFACE).ok_or("invalid echo interface GUID")?;
    let links = interface::enabled_of(&class);
    let link = links
        .first()
        .ok_or("GUID_DEVINTERFACE_ECHO was not enabled by echo.sys")?;
    kprintln!("echo: opening device interface {link}");
    let handle = super::open(link).map_err(|_| "failed to open KMDF Echo interface")?;
    let check = || {
        for payload in [
            &b"NK-PHASE5-KMDF-ECHO-PAYLOAD-1"[..],
            &b"SECOND-DISTINCT-ECHO-BUFFER-2026!"[..],
        ] {
            let written = file::write(handle, payload).map_err(|_| "write to echo failed")?;
            if written.status != STATUS_SUCCESS || written.information != payload.len() {
                kprintln!(
                    "echo: write status={:#010x} info={}",
                    written.status as u32,
                    written.information
                );
                return Err("echo write returned unexpected status or byte count");
            }
            let mut buf = [0xEEu8; 64];
            let read = file::read(handle, &mut buf[..payload.len()])
                .map_err(|_| "read from echo failed")?;
            if read.status != STATUS_SUCCESS
                || read.information != payload.len()
                || &buf[..read.information] != payload
            {
                kprintln!(
                    "echo: read status={:#010x} info={} data={:?}",
                    read.status as u32,
                    read.information,
                    &buf[..read.information.min(buf.len())]
                );
                return Err("echo read did not match written payload");
            }
        }
        Ok(())
    };
    let result = check();
    file::close(handle);
    result
}

fn run(r: &mut Report, _: &BootInfo) {
    crate::test::keeps_what_it_started();
    if let Some(absent) = IMAGES.iter().find(|file| ldr::boot_file(file).is_none()) {
        r.skip_rest(format_args!("module {absent} not provided"));
        return;
    }
    r.check("echo.load", load);
    r.check("echo.io", io);
}
