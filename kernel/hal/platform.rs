//! What the machine is made of, read from ACPI once at boot: the
//! processors and where the interrupt controllers are.
//!
//! The MADT lists every processor firmware knows. NK numbers the boot
//! processor 0, as Windows does, and the rest in table order.

use crate::arch::platform::{self as arch_platform, Controllers};
use crate::mm;
use alloc::boxed::Box;
use core::sync::atomic::{AtomicPtr, Ordering};
use nk_acpi::{CensusError, PhysMem};
use nk_bootinfo::{BootInfo, described};

/// One processor group, as on Windows: at most 64 logical processors.
pub const MAX_CPUS: usize = 64;

/// How many stretches of memory-mapped PCI configuration space are kept.
pub const MAX_ECAM: usize = 16;

pub use nk_acpi::Cpu;

pub struct Platform {
    cpus: [Cpu; MAX_CPUS],
    ncpus: usize,
    pub controllers: Controllers,
    /// What else firmware says that this architecture needs.
    pub firmware: arch_platform::Firmware,
    /// Memory-mapped PCI configuration space, from the ACPI MCFG.
    ecam: [Option<nk_acpi::Ecam>; MAX_ECAM],
}

impl Platform {
    /// Usable processors; index 0 is the boot processor.
    pub fn cpus(&self) -> &[Cpu] {
        &self.cpus[..self.ncpus]
    }

    /// The stretches of memory-mapped PCI configuration space.
    pub fn ecam(&self) -> impl Iterator<Item = (usize, nk_acpi::Ecam)> + '_ {
        self.ecam
            .iter()
            .enumerate()
            .filter_map(|(i, e)| Some((i, (*e)?)))
    }
}

static PLATFORM: AtomicPtr<Platform> = AtomicPtr::new(core::ptr::null_mut());

/// The loader's hand-off block, which says where the firmware's tables
/// are and which memory is firmware's.
static BOOT: AtomicPtr<BootInfo> = AtomicPtr::new(core::ptr::null_mut());

/// The firmware's ACPI table of the signature `signature`, as a HAL
/// answers an ACPI driver's request for it (`nk_acpi::lookup`). The
/// table is the firmware's own memory, which nothing reuses.
pub fn acpi_table(
    signature: &[u8; 4],
    oem_id: Option<&[u8; 6]>,
    oem_table_id: Option<&[u8; 8]>,
) -> Option<&'static [u8]> {
    // SAFETY: null, or the hand-off block `init` was given, which lives
    // for ever and is never written.
    let info: &'static BootInfo = unsafe { BOOT.load(Ordering::Acquire).as_ref() }?;
    let memory = DirectMap(info);
    let table = nk_acpi::lookup(&memory, info.rsdp, signature, oem_id, oem_table_id)?;
    // SAFETY: `DirectMap` hands out firmware memory in the direct map,
    // mapped and unchanged for the life of the kernel; the slice's
    // lifetime was tied to the local `DirectMap` only.
    Some(unsafe { core::slice::from_raw_parts(table.as_ptr(), table.len()) })
}

/// The platform description. Panics before [`init`].
pub fn get() -> &'static Platform {
    let p = PLATFORM.load(Ordering::Acquire);
    assert!(!p.is_null(), "platform description used before hal init");
    // SAFETY: `init` stored a leaked, fully initialised `Platform` that is
    // never written again.
    unsafe { &*p }
}

/// Firmware tables through the direct map. Only addresses inside a region
/// of the firmware memory map are mapped, so only those are readable.
struct DirectMap<'a>(&'a BootInfo);

impl PhysMem for DirectMap<'_> {
    fn bytes(&self, addr: u64, len: usize) -> Option<&[u8]> {
        // SAFETY: the loader left the memory map in reserved memory that
        // the direct map covers.
        let map = unsafe {
            core::slice::from_raw_parts(
                mm::phys_to_virt(self.0.mmap_phys),
                self.0.mmap_len as usize,
            )
        };
        described(map, self.0.mmap_desc_size as usize, addr, len as u64).then(|| {
            // SAFETY: the range lies in one mapped firmware region, and
            // firmware does not change its tables after boot services.
            unsafe { core::slice::from_raw_parts(mm::phys_to_virt(addr), len) }
        })
    }
}

/// Read the MADT and record the processors and interrupt controllers.
pub fn init(info: &'static BootInfo) -> Result<(), &'static str> {
    BOOT.store(core::ptr::from_ref(info).cast_mut(), Ordering::Release);
    let mem = DirectMap(info);
    let table = nk_acpi::find_table(&mem, info.rsdp, b"APIC").ok_or("no ACPI MADT")?;
    let madt = nk_acpi::madt(table).ok_or("the ACPI MADT is malformed")?;

    let mut cpus = [Cpu { hw_id: 0, uid: 0 }; MAX_CPUS];
    let listed = madt.entries().filter_map(|e| arch_platform::usable_cpu(&e));
    let (n, more) = nk_acpi::census(arch_platform::current_cpu_id(), listed, &mut cpus).map_err(
        |e| match e {
            CensusError::NoBootProcessor => "the MADT does not list the boot processor",
            CensusError::BootProcessorTwice => "the MADT lists the boot processor twice",
            CensusError::ProcessorTwice => "the MADT lists a processor twice",
        },
    )?;
    if more {
        kprintln!("hal: more than {MAX_CPUS} processors; the rest stay off");
    }
    let mut ecam = [None; MAX_ECAM];
    if let Some(table) = nk_acpi::find_table(&mem, info.rsdp, b"MCFG") {
        for (slot, entry) in ecam.iter_mut().zip(nk_acpi::mcfg(table)) {
            *slot = Some(entry);
        }
    }
    let platform = Box::leak(Box::new(Platform {
        cpus,
        ncpus: n,
        controllers: Controllers::from_madt(&madt),
        firmware: arch_platform::firmware(|signature| {
            nk_acpi::find_table(&mem, info.rsdp, signature)
        }),
        ecam,
    }));
    kprintln!("hal: {n} processors; {}", platform.controllers);
    PLATFORM.store(platform, Ordering::Release);
    Ok(())
}

/// The census agrees with the processor running this code and, when the
/// command line states how many processors the machine has (`cpus=<n>`,
/// set by the test harness to what it asked QEMU for), with that.
pub fn self_test(info: &BootInfo) -> Result<usize, &'static str> {
    let cpus = get().cpus();
    if cpus.first().map(|c| c.hw_id) != Some(arch_platform::current_cpu_id()) {
        return Err("processor 0 is not the boot processor");
    }
    if (1..cpus.len()).any(|i| cpus[..i].iter().any(|c| c.hw_id == cpus[i].hw_id)) {
        return Err("two processors share a hardware id");
    }
    match info.option("cpus").map(str::parse::<usize>) {
        Some(Ok(expected)) if expected == cpus.len() => Ok(cpus.len()),
        Some(Ok(_)) => Err("processor count differs from cpus= on the command line"),
        Some(Err(_)) => Err("cpus= on the command line is not a number"),
        None => Ok(cpus.len()),
    }
}
