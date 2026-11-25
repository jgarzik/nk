//! What the machine is made of, read from ACPI once at boot: the
//! processors and where the interrupt controllers are.
//!
//! The MADT lists every processor firmware knows. NK numbers the boot
//! processor 0, as Windows does, and the rest in table order.

use crate::arch::platform::{self as arch_platform, Controllers};
use crate::mm;
use alloc::boxed::Box;
use core::sync::atomic::{AtomicPtr, Ordering};
use nk_acpi::PhysMem;
use nk_bootinfo::{BootInfo, regions};

/// One processor group, as on Windows: at most 64 logical processors.
pub const MAX_CPUS: usize = 64;

/// A processor as firmware names it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Cpu {
    /// Local APIC id (x86-64) or MPIDR affinity (arm64).
    pub hw_id: u64,
    /// ACPI processor UID.
    pub uid: u32,
}

pub struct Platform {
    cpus: [Cpu; MAX_CPUS],
    ncpus: usize,
    pub controllers: Controllers,
}

impl Platform {
    /// Usable processors; index 0 is the boot processor.
    pub fn cpus(&self) -> &[Cpu] {
        &self.cpus[..self.ncpus]
    }
}

static PLATFORM: AtomicPtr<Platform> = AtomicPtr::new(core::ptr::null_mut());

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
        let end = addr.checked_add(len as u64)?;
        // SAFETY: the loader left the memory map in reserved memory that
        // the direct map covers.
        let map = unsafe {
            core::slice::from_raw_parts(
                mm::phys_to_virt(self.0.mmap_phys),
                self.0.mmap_len as usize,
            )
        };
        regions(map, self.0.mmap_desc_size as usize)
            .any(|r| r.phys <= addr && end <= r.end())
            .then(|| {
                // SAFETY: the range lies in one mapped firmware region, and
                // firmware does not change its tables after boot services.
                unsafe { core::slice::from_raw_parts(mm::phys_to_virt(addr), len) }
            })
    }
}

/// Read the MADT and record the processors and interrupt controllers.
pub fn init(info: &BootInfo) -> Result<(), &'static str> {
    let mem = DirectMap(info);
    let table = nk_acpi::find_table(&mem, info.rsdp, b"APIC").ok_or("no ACPI MADT")?;
    let madt = nk_acpi::madt(table).ok_or("the ACPI MADT is malformed")?;

    let boot = arch_platform::boot_cpu_id();
    let mut cpus = [Cpu { hw_id: 0, uid: 0 }; MAX_CPUS];
    // Slot 0 is kept for the boot processor wherever the table lists it.
    let (mut n, mut boot_seen) = (1, false);
    for cpu in madt.entries().filter_map(|e| arch_platform::usable_cpu(&e)) {
        if cpu.hw_id == boot {
            if boot_seen {
                return Err("the MADT lists the boot processor twice");
            }
            (cpus[0], boot_seen) = (cpu, true);
        } else if cpus[1..n].iter().any(|c| c.hw_id == cpu.hw_id) {
            return Err("the MADT lists a processor twice");
        } else if n < MAX_CPUS {
            cpus[n] = cpu;
            n += 1;
        } else {
            kprintln!("hal: more than {MAX_CPUS} processors; the rest stay off");
            break;
        }
    }
    if !boot_seen {
        return Err("the MADT does not list the boot processor");
    }
    let platform = Box::leak(Box::new(Platform {
        cpus,
        ncpus: n,
        controllers: Controllers::from_madt(&madt),
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
    if cpus.first().map(|c| c.hw_id) != Some(arch_platform::boot_cpu_id()) {
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
