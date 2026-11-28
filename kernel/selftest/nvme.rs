//! Microsoft's inbox NVMe stack (`stornvme.sys` on `storport.sys`) on QEMU's
//! PCIe NVMe controller, proving device ancestry through ACPI/PCI, GPT volume
//! discovery (`partmgr`/`volmgr`/`mountmgr`), and FAT32 read + writeback
//! (`fastfat.sys`) verified offline by the host.

use crate::io::service;
use crate::ldr;
use crate::pnp::node::{self, State};
use crate::pnp::registry;
use crate::test::{Group, Report};
use nk_bootinfo::BootInfo;

pub static GROUP: Group = Group {
    names: &["nvme.load", "nvme.enumerate", "nvme.fat"],
    run,
    manual: true,
};

pub static GROUPS: &[&Group] = &[&GROUP];

const SCSI_ADAPTER: &str = "{4d36e97b-e325-11ce-bfc1-08002be10318}";
const DISK_DRIVE: &str = "{4d36e967-e325-11ce-bfc1-08002be10318}";

const IMAGES: [&str; 6] = [
    "acpi.sys",
    "pci.sys",
    "storport.sys",
    "stornvme.sys",
    "disk.sys",
    "fastfat.sys",
];

fn load() -> Result<(), &'static str> {
    if !service::running("stornvme") {
        return Err("stornvme service is not running");
    }
    if ldr::module_named("stornvme.sys").is_none() {
        return Err("stornvme.sys is not loaded");
    }
    Ok(())
}

/// Confirm that the QEMU NVMe PCI function (`1b36:0010`) started under
/// `ACPI\PNP0A08\0` with `stornvme`, and that a started disk node
/// (`SCSI\Disk&Ven_NVMe...`) is its direct child.
pub(super) fn verify_ancestry() -> Result<(), &'static str> {
    let all: alloc::vec::Vec<_> = node::all().into_iter().filter_map(node::get).collect();
    let nvme = all
        .iter()
        .find(|n| {
            n.instance
                .to_ascii_uppercase()
                .starts_with("PCI\\VEN_1B36&DEV_0010")
        })
        .ok_or("no PCI NVMe controller (1b36:0010) was enumerated")?;
    if nvme.state != State::Started {
        kprintln!(
            "nvme: controller {} state={:?} problem={}",
            nvme.instance,
            nvme.state,
            nvme.problem
        );
        return Err("the NVMe controller did not start");
    }
    let parent = node::get(nvme.parent).map(|p| p.instance);
    if parent.as_deref() != Some("ACPI\\PNP0A08\\0") {
        kprintln!("nvme: unexpected parent {parent:?}");
        return Err("the NVMe controller is not under the PCI root bus");
    }
    let key = registry::enum_key(&nvme.instance);
    if registry::string(&key, "Service").as_deref() != Some("stornvme")
        || registry::string(&key, "ClassGUID").as_deref() != Some(SCSI_ADAPTER)
    {
        return Err("the NVMe controller does not have stornvme / SCSIAdapter");
    }

    let disk = all
        .iter()
        .find(|n| n.parent == nvme.pdo && n.instance.to_ascii_uppercase().starts_with("SCSI\\DISK"))
        .ok_or("no disk child was enumerated below the NVMe controller")?;
    if disk.state != State::Started {
        kprintln!(
            "nvme: disk {} state={:?} problem={}",
            disk.instance,
            disk.state,
            disk.problem
        );
        return Err("the NVMe disk did not start");
    }
    let dkey = registry::enum_key(&disk.instance);
    if registry::string(&dkey, "Service").as_deref() != Some("disk")
        || registry::string(&dkey, "ClassGUID").as_deref() != Some(DISK_DRIVE)
    {
        return Err("the NVMe disk does not have disk / DiskDrive");
    }
    kprintln!(
        "nvme: verified ancestry {} -> {}",
        nvme.instance,
        disk.instance
    );
    Ok(())
}

/// Read the host's known FAT32 files from C:, then perform the bounded write,
/// overwrite, truncate, flush, rename and delete verified offline by fatdisk.py.
pub(super) fn fat_read_and_write() -> Result<(), &'static str> {
    super::fat::read()?;
    super::fat::write()
}

fn run(r: &mut Report, _: &BootInfo) {
    crate::test::keeps_what_it_started();
    if let Some(absent) = IMAGES.iter().find(|file| ldr::boot_file(file).is_none()) {
        r.skip_rest(format_args!("module {absent} not provided"));
        return;
    }
    r.check("nvme.load", load);
    r.check("nvme.enumerate", verify_ancestry);
    r.check("nvme.fat", fat_read_and_write);
}
