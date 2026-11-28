//! Integrated Phase 5 q35 scenario: verifies NVMe GPT FAT32 read + writeback
//! (`stornvme.sys` + `fastfat.sys`), COM2 bidirectional serial (`msisadrv.sys` +
//! `serial.sys` + `serenum.sys`, leaving COM1 for NK logs), and empty-boot xHCI
//! USB 3.0 + HID keyboard hotplug (`usbxhci`..`kbdclass`) all running together
//! in one boot, followed by clean shutdown and offline `fatdisk.py` verification.

use crate::ldr;
use crate::test::{Group, Report};
use nk_bootinfo::BootInfo;

pub static GROUP: Group = Group {
    names: &["phase5.nvme", "phase5.serial", "phase5.usb"],
    run,
    manual: true,
};

pub static GROUPS: &[&Group] = &[&GROUP];

const IMAGES: [&str; 18] = [
    "acpi.sys",
    "pci.sys",
    "storport.sys",
    "stornvme.sys",
    "disk.sys",
    "fastfat.sys",
    "wdfldr.sys",
    "wdf01000.sys",
    "msisadrv.sys",
    "serial.sys",
    "serenum.sys",
    "usbxhci.sys",
    "ucx01000.sys",
    "usbhub3.sys",
    "hidusb.sys",
    "hidclass.sys",
    "kbdhid.sys",
    "kbdclass.sys",
];

fn nvme_fat() -> Result<(), &'static str> {
    super::nvme::verify_ancestry()?;
    super::nvme::fat_read_and_write()
}

fn serial_com2() -> Result<(), &'static str> {
    super::serial::verify_load()?;
    super::serial::bidirectional_io()
}

fn usb_kbd_hotplug() -> Result<(), &'static str> {
    super::usb_kbd::verify_empty_xhci()?;
    super::usb_kbd::hotplug_lifecycle()
}

fn run(r: &mut Report, _: &BootInfo) {
    crate::test::keeps_what_it_started();
    if let Some(absent) = IMAGES.iter().find(|file| ldr::boot_file(file).is_none()) {
        r.skip_rest(format_args!("module {absent} not provided"));
        return;
    }
    r.check("phase5.nvme", nvme_fat);
    r.check("phase5.serial", serial_com2);
    r.check("phase5.usb", usb_kbd_hotplug);
}
