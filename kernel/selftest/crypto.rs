//! Microsoft's kernel cryptography and security drivers as boot
//! drivers, as Windows starts them: `cng.sys` (which stops the system
//! with `0x121` if any part of its start fails, so its start is whole or
//! the boot is over) and then `ksecdd.sys`, which opens `\Device\CNG`.
//! The proof is that both ran and their devices are there.

use crate::io::service;
use crate::ldr;
use crate::test::{Group, Report};
use nk_bootinfo::BootInfo;

pub static GROUP: Group = Group {
    names: &["crypto.boot"],
    run,
    manual: true,
};

pub static GROUPS: &[&Group] = &[&GROUP];

fn exists(name: &str) -> bool {
    let wide: alloc::vec::Vec<u16> = name.encode_utf16().collect();
    crate::ob::lookup(None, &wide).is_ok_and(|(_, rest)| rest.is_empty())
}

fn run(r: &mut Report, _: &BootInfo) {
    if ldr::boot_file("cng.sys").is_none() || ldr::boot_file("ksecdd.sys").is_none() {
        r.skip_rest(format_args!("cng.sys or ksecdd.sys not provided"));
        return;
    }
    let running = service::running("CNG") && service::running("KSecDD");
    let devices = exists("\\Device\\CNG") && exists("\\Device\\KsecDD");
    if running && devices {
        r.ok_with(
            "crypto.boot",
            format_args!("CNG and KSecDD running, \\Device\\CNG and \\Device\\KsecDD there"),
        );
    } else {
        r.fail(
            "crypto.boot",
            format_args!("running {running}, devices {devices}"),
        );
    }
}
