//! nkload: NK's UEFI loader.
//!
//! Stands where Windows has `bootmgfw.efi` and `winload.efi`: firmware
//! starts it from the EFI system partition, it reads the kernel and the
//! boot drivers from `\NK`, maps the kernel, leaves boot services and
//! jumps. What it hands over is described in `nk-bootinfo`.

#![no_std]
#![no_main]

#[cfg_attr(target_arch = "x86_64", path = "arch/x86_64.rs")]
#[cfg_attr(target_arch = "aarch64", path = "arch/aarch64.rs")]
mod arch;
mod efi;
mod entropy;

use nk_bootinfo::{
    BootInfo, FirmwareUse, HHDM_BASE, HIVE_MODULE, KERNEL_BASE, KERNEL_STACK_SIZE, MAX_MODULES,
    MODULE_NAME_LEN, Module, OVERLAY_MODULE, Serial, has_ram, ram_top, regions, stack_top_in,
    windows_time,
};
use nk_mm::pt::{self, Prot, TableMem};
use nk_pe::Pe;

#[global_allocator]
static POOL: efi::Pool = efi::Pool;

const KERNEL_PATH: &str = "\\NK\\nkkrnl.exe";
const DRIVER_DIR: &str = "\\NK\\drivers";
/// Optional: the SYSTEM registry hive, handed over as one more module.
const HIVE_PATH: &str = "\\NK\\SYSTEM";
const OVERLAY_PATH: &str = "\\NK\\OVERLAY";
/// Optional: one line of `key=value` words for the kernel.
const CMDLINE_PATH: &str = "\\NK\\cmdline.txt";
/// Room for one kernel stack at the alignment the kernel requires.
const STACK_PAGES: usize = 3 * (KERNEL_STACK_SIZE as usize) / 4096;
/// Room for the final memory map; firmware maps are a few KiB.
const MMAP_PAGES: usize = 16;
const BLOCK_2M: u64 = 2 << 20;

/// Page tables in firmware-allocated pages, reached by physical address
/// (firmware identity-maps RAM).
struct Tables;

impl TableMem for Tables {
    fn alloc_table(&mut self) -> Option<u64> {
        efi::alloc_pages(1)
    }

    fn read(&self, table: u64, index: usize) -> u64 {
        // SAFETY: `table` came from `alloc_table`: a live, identity-mapped
        // page of 512 entries; `index` is below 512.
        unsafe { (table as *const u64).add(index).read() }
    }

    fn write(&mut self, table: u64, index: usize, entry: u64) {
        // SAFETY: as in `read`; nothing else references table pages.
        unsafe { (table as *mut u64).add(index).write(entry) }
    }
}

struct Identity;

impl nk_acpi::PhysMem for Identity {
    fn bytes(&self, addr: u64, len: usize) -> Option<&[u8]> {
        if addr == 0 {
            return None;
        }
        // SAFETY: firmware identity-maps the ACPI tables it advertises, and
        // nk-acpi bounds every length it asks for.
        Some(unsafe { core::slice::from_raw_parts(addr as *const u8, len) })
    }
}

/// Protection for the image page at `rva`, from the section that holds it.
fn page_prot(pe: &Pe<'_>, rva: u32) -> Option<Prot> {
    let flags = pe.page_flags(rva)?;
    Some(Prot {
        write: flags & nk_pe::SCN_MEM_WRITE != 0,
        exec: flags & nk_pe::SCN_MEM_EXECUTE != 0,
        device: false,
    })
}

/// Hand the kernel the contents of a file as the boot module `name`.
fn add_module(info: &mut BootInfo, name: &str, data: &[u8]) -> Result<(), &'static str> {
    if info.nmodules as usize == MAX_MODULES {
        return Err("too many boot files");
    }
    let mut module = Module::EMPTY;
    module.phys = data.as_ptr() as u64;
    module.size = data.len() as u64;
    module.set_name(name.as_bytes());
    info.modules[info.nmodules as usize] = module;
    info.nmodules += 1;
    println!("nkload: module {name} ({} bytes)", data.len());
    Ok(())
}

/// Read every file in the driver directory as a boot module, and the
/// registry hive and the registry overlay where there is one. Neither
/// is looked into here: the kernel checks them.
fn load_modules(root: &efi::File, info: &mut BootInfo) -> Result<(), &'static str> {
    for (path, module, unread) in [
        (HIVE_PATH, HIVE_MODULE, "cannot read \\NK\\SYSTEM"),
        (OVERLAY_PATH, OVERLAY_MODULE, "cannot read \\NK\\OVERLAY"),
    ] {
        if let Some(file) = root.open(path) {
            add_module(info, module, file.read_all().ok_or(unread)?)?;
        }
    }
    let Some(dir) = root.open(DRIVER_DIR) else {
        return Ok(()); // no drivers is a valid configuration
    };
    let mut name = [0u8; MODULE_NAME_LEN];
    while let Some((len, is_dir)) = dir.next_entry(&mut name) {
        if is_dir {
            continue;
        }
        let name = core::str::from_utf8(&name[..len]).map_err(|_| "driver name is not ASCII")?;
        let data = dir
            .open(name)
            .and_then(|f| f.read_all())
            .ok_or("cannot read a boot driver")?;
        add_module(info, name, data)?;
    }
    Ok(())
}

/// Build the kernel's page tables: direct map, kernel image, and on
/// architectures that need it a minimal identity map.
fn build_tables(
    arch: &arch::PtArch,
    pe: &Pe<'_>,
    image_phys: u64,
    map: &[u8],
    desc_size: usize,
) -> Result<u64, &'static str> {
    let mut t = Tables;
    let root = t.alloc_table().ok_or("out of memory for page tables")?;
    let top = arch::map_top(ram_top(map, desc_size)).next_multiple_of(BLOCK_2M);
    let fail = |_| "cannot build page tables";

    // The direct map, in 2 MiB blocks: RAM where the memory map has RAM,
    // device memory elsewhere (UART, interrupt controller).
    for block in (0..top).step_by(BLOCK_2M as usize) {
        let ram = has_ram(map, desc_size, block, BLOCK_2M);
        let prot = if ram { Prot::RW } else { Prot::DEVICE };
        pt::map(&mut t, arch, root, HHDM_BASE + block, block, 1, prot).map_err(fail)?;
    }

    // The identity map holds only what must run or be reached at its
    // physical address: firmware runtime regions (for ResetSystem and
    // friends) and this loader's own code, which is still executing when
    // the tables are switched. Everything else in the low half, including
    // page zero, stays unmapped.
    if arch::NEEDS_IDENTITY_MAP {
        for r in regions(map, desc_size) {
            let prot = match r.firmware_use() {
                Some(FirmwareUse::LoaderCode) => Prot::RX,
                // Runtime driver images mix code and writable data.
                Some(FirmwareUse::RuntimeCode) => Prot::RWX,
                Some(FirmwareUse::RuntimeData) => Prot::RW,
                None => continue,
            };
            pt::map_range(&mut t, arch, root, r.phys, r.phys, r.pages * 4096, 0, prot)
                .map_err(fail)?;
        }
    }

    if pe.headers().section_alignment < 4096 {
        return Err("kernel sections are not page aligned");
    }
    for rva in (0..pe.headers().size_of_image).step_by(4096) {
        if let Some(prot) = page_prot(pe, rva) {
            let (va, pa) = (KERNEL_BASE + u64::from(rva), image_phys + u64::from(rva));
            pt::map(&mut t, arch, root, va, pa, 0, prot).map_err(fail)?;
        }
    }
    Ok(root)
}

fn serial() -> Serial {
    let spcr = nk_acpi::find_table(&Identity, efi::rsdp(), b"SPCR").and_then(nk_acpi::spcr);
    spcr.and_then(|s| Serial::from_spcr(s.mmio, s.interface, s.address))
        .unwrap_or(arch::DEFAULT_SERIAL)
}

fn load(image: efi::Handle) -> Result<core::convert::Infallible, &'static str> {
    // Where the loader's time begins, for the time source.
    let started = arch::cycles();
    let root_dir = efi::File::boot_volume(image).ok_or("cannot open the boot volume")?;
    let file = root_dir
        .open(KERNEL_PATH)
        .and_then(|f| f.read_all())
        .ok_or("cannot read \\NK\\nkkrnl.exe")?;
    let pe = Pe::parse(file).map_err(|_| "kernel is not a PE32+ image")?;
    pe.check_machine(arch::MACHINE)
        .map_err(|_| "kernel is built for another machine")?;
    let h = pe.headers();

    let size = h.size_of_image as usize;
    let image_phys = efi::alloc_pages(size.div_ceil(4096)).ok_or("out of memory for the kernel")?;
    let mapped = efi::page_slice(image_phys, size);
    pe.map_into(mapped)
        .map_err(|_| "cannot map the kernel image")?;
    nk_pe::relocate(mapped, &h, KERNEL_BASE).map_err(|_| "cannot relocate the kernel")?;
    println!("nkload: kernel {size:#x} bytes at {image_phys:#x} -> {KERNEL_BASE:#x}");

    let info_phys =
        efi::alloc_pages(size_of::<BootInfo>().div_ceil(4096)).ok_or("out of memory")?;
    let stack = efi::alloc_pages(STACK_PAGES).ok_or("out of memory")?;
    let mmap = efi::page_slice(
        efi::alloc_pages(MMAP_PAGES).ok_or("out of memory")?,
        MMAP_PAGES * 4096,
    );

    let mut info = BootInfo::new();
    info.kernel_phys = image_phys;
    info.kernel_size = size as u64;
    info.rsdp = efi::rsdp();
    info.boot_time = efi::time()
        .and_then(|[y, mo, d, h, mi, s]| windows_time(y, mo, d, h, mi, s))
        .unwrap_or(0);
    info.efi_runtime = efi::runtime() as u64;
    info.serial = serial();
    load_modules(&root_dir, &mut info)?;
    let hive = info
        .modules()
        .iter()
        .find(|m| m.name() == HIVE_MODULE.as_bytes())
        .map(|m| efi::page_slice(m.phys, m.size as usize) as &[u8]);
    let oem0 = nk_acpi::find_table(&Identity, info.rsdp, b"OEM0");
    info.entropy = entropy::gather(hive, oem0, started)?;
    if let Some(file) = root_dir.open(CMDLINE_PATH) {
        let text = file.read_all().ok_or("cannot read \\NK\\cmdline.txt")?;
        info.set_cmdline(text.trim_ascii())?;
        println!("nkload: command line: {}", info.cmdline());
    }
    drop(root_dir);

    let pt_arch = arch::pt_arch(&mut info)?;
    let (len, desc_size, _) = efi::memory_map(mmap).ok_or("cannot read the memory map")?;
    let root = build_tables(&pt_arch, &pe, image_phys, &mmap[..len], desc_size)?;
    println!("nkload: starting kernel");

    // Nothing may allocate or print from here: either would change the
    // memory map and invalidate the key. One retry, as the UEFI
    // specification allows for a map that changed during the first call.
    let mut left = None;
    for _ in 0..2 {
        let (len, desc_size, key) = efi::memory_map(mmap).ok_or("cannot read the memory map")?;
        if efi::exit_boot_services(image, key) {
            left = Some((len, desc_size));
            break;
        }
    }
    let (len, desc_size) = left.ok_or("ExitBootServices failed")?;
    info.mmap_phys = mmap.as_ptr() as u64;
    info.mmap_len = len as u64;
    info.mmap_desc_size = desc_size as u64;
    // SAFETY: `info_phys` is a fresh allocation large enough for BootInfo.
    unsafe { (info_phys as *mut BootInfo).write(info) };

    let entry = KERNEL_BASE + u64::from(h.entry_rva);
    let stack_top = HHDM_BASE
        + stack_top_in(stack, (STACK_PAGES * 4096) as u64).ok_or("no room for the boot stack")?;
    // SAFETY: boot services are gone; `root` maps the kernel image, the
    // direct map holding the stack and BootInfo, and (where the
    // architecture needs it) the identity range this code runs from.
    unsafe { arch::enter(root, entry, stack_top, HHDM_BASE + info_phys) }
}

#[unsafe(no_mangle)]
extern "efiapi" fn efi_main(image: efi::Handle, st: *mut efi::SystemTable) -> efi::Status {
    // SAFETY: firmware passes its system table to the image entry point.
    unsafe { efi::init(st) };
    println!(
        "nkload: NK loader {} ({})",
        env!("CARGO_PKG_VERSION"),
        arch::NAME
    );
    let Err(why) = load(image);
    // The boot test reads this line; then power off rather than hang.
    println!("NK-TEST boot:FAIL nkload: {why}");
    efi::shutdown()
}

#[panic_handler]
fn panic(info: &core::panic::PanicInfo<'_>) -> ! {
    println!("NK-TEST boot:FAIL nkload PANIC: {info}");
    efi::shutdown()
}
