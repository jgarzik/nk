//! The driver image loader: PE file in, relocated and bound image mapped
//! with per-section protections out.
//!
//! The PE work is `lib/pe`, the same code nkload maps the kernel with.
//! This module supplies memory and the import resolver.

#![allow(non_snake_case)]

use crate::ke::{Rank, SpinLock};
use crate::mm::{self, PAGE_SIZE, map};
use crate::{arch, export};
use alloc::string::String;
use core::ffi::c_void;
use core::sync::atomic::{AtomicPtr, AtomicU64, Ordering};
use nk_bootinfo::BootInfo;
use nk_mm::pt::Prot;
use nk_pe::modules::{Module, Modules};
use nk_pe::{Pe, PeError, Symbol};

/// The loader's hand-off block, for the files it read from the boot
/// volume.
static BOOT: AtomicPtr<BootInfo> = AtomicPtr::new(core::ptr::null_mut());

/// The name Windows' own module list gives the kernel image.
const KERNEL_NAME: &[u8] = b"ntoskrnl.exe";

/// A frame of zeros, mapped wherever an image's view has nothing to
/// show. Never written.
static ZERO_FRAME: AtomicU64 = AtomicU64::new(0);

/// Map the view of an image of `pages` pages laid out in the frames at
/// `phys`: a second mapping of the whole image, read-only, through which
/// the kernel reads its function table and code.
///
/// A page of a section the image cannot write shows that page. Every
/// other page (writable data, a gap between sections) shows zeros. So
/// no byte of the view changes or faults, and a slice over all of it is
/// sound whatever the image's own code is doing. `flags` gives the
/// section characteristics of the page at an RVA.
fn map_view(phys: u64, pages: usize, flags: impl Fn(u32) -> Option<u32>) -> Option<u64> {
    let view = map::alloc_va(pages)?;
    for page in 0..pages {
        let rva = (page * PAGE_SIZE) as u32;
        let constant = flags(rva).is_some_and(|f| f & nk_pe::SCN_MEM_WRITE == 0);
        let frame = if constant {
            phys + u64::from(rva)
        } else {
            ZERO_FRAME.load(Ordering::Relaxed)
        };
        if map::map(view + u64::from(rva), frame, 1, Prot::RO).is_err() {
            unmap_view(view, pages);
            return None;
        }
    }
    Some(view)
}

fn unmap_view(view: u64, pages: usize) {
    map::unmap(view, pages);
    map::free_va(view, pages);
}

/// The bytes of a loaded image, through its view.
///
/// # Safety
/// The image stays loaded for as long as the slice is used. That holds
/// while code of the image is on a live stack, which is when its
/// function table is wanted.
pub unsafe fn view<'a>(module: &Module) -> &'a [u8] {
    // SAFETY: `map_view` mapped `size` bytes there, which nothing can
    // write; per the contract they are still mapped.
    unsafe { core::slice::from_raw_parts(module.view as *const u8, module.size as usize) }
}

/// Remember where the boot files are, and enter the kernel's own image
/// in the table of loaded images.
pub fn init(info: &'static BootInfo) -> Result<(), &'static str> {
    BOOT.store(core::ptr::from_ref(info).cast_mut(), Ordering::Release);
    let zero = mm::alloc_frames(1).ok_or("no memory for the frame of zeros")?;
    ZERO_FRAME.store(zero, Ordering::Relaxed);
    // SAFETY: the loader laid the kernel image out in `kernel_size`
    // bytes at `kernel_phys`, whose first page holds its headers.
    let first = unsafe {
        core::slice::from_raw_parts(
            mm::phys_to_virt(info.kernel_phys),
            (info.kernel_size as usize).min(PAGE_SIZE),
        )
    };
    let headers = nk_pe::image_headers(first).map_err(|_| "the kernel image has no headers")?;
    let pages = (info.kernel_size as usize).div_ceil(PAGE_SIZE);
    let view = map_view(info.kernel_phys, pages, |rva| {
        nk_pe::image_page_flags(first, rva)
    })
    .ok_or("no memory for the view of the kernel image")?;
    let kernel = Module::new(
        KERNEL_NAME,
        nk_bootinfo::KERNEL_BASE,
        info.kernel_size,
        headers.dir(nk_pe::DIR_EXCEPTION),
        view,
    )
    .ok_or("the kernel image cannot be described")?;
    MODULES
        .lock()
        .insert(kernel)
        .map_err(|_| "the kernel image could not be entered")
}

/// The contents of the boot file called `name` (`sioctl.sys`), if the
/// loader read one of that name from `\NK\drivers`. This is NK's
/// `System32\drivers` until there is a file system to read.
pub fn boot_file(name: &str) -> Option<&'static [u8]> {
    // SAFETY: null, or the hand-off block `init` was given, which lives
    // for ever and is never written.
    let info = unsafe { BOOT.load(Ordering::Acquire).as_ref() }?;
    let m = info
        .modules()
        .iter()
        .find(|m| m.name().eq_ignore_ascii_case(name.as_bytes()))?;
    // SAFETY: the loader read the file into reserved memory that stays
    // mapped and unmodified for the life of the kernel.
    Some(unsafe { core::slice::from_raw_parts(mm::phys_to_virt(m.phys), m.size as usize) })
}

/// `IMAGE_SUBSYSTEM_NATIVE`: what a kernel driver is linked as.
const SUBSYSTEM_NATIVE: u16 = 1;

/// A driver image in memory, as its loader holds it.
#[derive(Clone, Copy)]
pub struct Image {
    pub base: u64,
    pub size: usize,
    pub entry: u64,
    phys: u64,
    pages: usize,
}

#[derive(Debug)]
#[expect(dead_code, reason = "fields are read through Debug in test reports")]
pub enum LoadError {
    /// Not a loadable PE32+ image for this machine.
    Pe(PeError),
    /// Not linked as a native (kernel-mode) image.
    NotNative(u16),
    /// Sections are not page aligned, so cannot be protected separately.
    Unaligned,
    NoMemory,
    /// Its name is too long to keep, or too many images are loaded.
    TooMany,
    /// The kernel has no export for an import of the driver.
    Unresolved {
        module: String,
        symbol: String,
    },
}

/// How many images can be loaded at once.
const MAX_MODULES: usize = 256;

/// The images in memory, the kernel's own first: which image an address
/// is in, and where that image's function table is. Held at
/// `HIGH_LEVEL` and holding no memory, so any context may search it.
static MODULES: SpinLock<Modules<MAX_MODULES>> = SpinLock::new(Rank::Modules, Modules::new());

fn lossy(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).into_owned()
}

/// A stack-protector cookie for one image. The entropy is only the CPU's
/// cycle counter; a real random source is future work.
fn security_cookie() -> u64 {
    nk_pe::security_cookie(arch::counter())
}

/// Load a driver image from the bytes of its file, called `name`.
pub fn load(name: &str, file: &[u8]) -> Result<Image, LoadError> {
    let pe = Pe::parse(file).map_err(LoadError::Pe)?;
    pe.check_machine(nk_pe::MACHINE_NATIVE)
        .map_err(LoadError::Pe)?;
    let h = pe.headers();
    if h.subsystem != SUBSYSTEM_NATIVE {
        return Err(LoadError::NotNative(h.subsystem));
    }
    if h.section_alignment < PAGE_SIZE as u32 {
        return Err(LoadError::Unaligned);
    }
    let size = h.size_of_image as usize;
    let pages = size.div_ceil(PAGE_SIZE);
    let phys = mm::alloc_frames(pages).ok_or(LoadError::NoMemory)?;
    let Some(base) = map::alloc_va(pages) else {
        mm::free_frames(phys, pages);
        return Err(LoadError::NoMemory);
    };
    let image = Image {
        base,
        size,
        entry: base + u64::from(h.entry_rva),
        phys,
        pages,
    };

    // Build the image through the direct map, which is always writable;
    // the driver's own view gets each section's real protection.
    // SAFETY: the frames were just allocated for this image and nothing
    // else references them until they are mapped below.
    let mem = unsafe { core::slice::from_raw_parts_mut(mm::phys_to_virt(phys), pages * PAGE_SIZE) };
    let built = (|| {
        pe.map_into(mem).map_err(LoadError::Pe)?;
        nk_pe::relocate(mem, &h, base).map_err(LoadError::Pe)?;
        let resolver = |module: &[u8], sym: Symbol<'_>| match sym {
            Symbol::Name(name) => export::resolve(module, name),
            Symbol::Ordinal(_) => None,
        };
        nk_pe::bind_imports(mem, &h, resolver).map_err(|e| match e {
            PeError::Unresolved {
                dll_rva,
                name_rva,
                ordinal,
            } => LoadError::Unresolved {
                module: nk_pe::cstr_at(mem, dll_rva).map(lossy).unwrap_or_default(),
                symbol: match nk_pe::cstr_at(mem, name_rva) {
                    Ok(name) if name_rva != 0 => lossy(name),
                    _ => alloc::format!("#{ordinal}"),
                },
            },
            other => LoadError::Pe(other),
        })?;
        if let Some(rva) = nk_pe::security_cookie_rva(mem, &h, base) {
            mem[rva as usize..rva as usize + 8].copy_from_slice(&security_cookie().to_le_bytes());
        }
        for rva in (0..h.size_of_image).step_by(PAGE_SIZE) {
            if let Some(flags) = pe.page_flags(rva) {
                let prot = Prot {
                    write: flags & nk_pe::SCN_MEM_WRITE != 0,
                    exec: flags & nk_pe::SCN_MEM_EXECUTE != 0,
                    device: false,
                };
                map::map(base + u64::from(rva), phys + u64::from(rva), 1, prot)
                    .map_err(|_| LoadError::NoMemory)?;
            }
        }
        Ok(())
    })();
    if let Err(e) = built {
        release(&image);
        return Err(e);
    }
    arch::sync_icache(mem.as_ptr(), mem.len());
    let Some(view) = map_view(phys, pages, |rva| pe.page_flags(rva)) else {
        release(&image);
        return Err(LoadError::NoMemory);
    };
    let entered = Module::new(
        name.as_bytes(),
        base,
        size as u64,
        h.dir(nk_pe::DIR_EXCEPTION),
        view,
    )
    .is_some_and(|module| MODULES.lock().insert(module).is_ok());
    if !entered {
        unmap_view(view, pages);
        release(&image);
        return Err(LoadError::TooMany);
    }
    Ok(image)
}

fn release(image: &Image) {
    map::unmap(image.base, image.pages);
    map::free_va(image.base, image.pages);
    mm::free_frames(image.phys, image.pages);
}

/// Unmap an image and free its memory. No code in it may run again.
pub fn unload(image: &Image) {
    let module = MODULES.lock().remove(image.base);
    // The image's addresses go back first, so that the next image of
    // this size is given them again and its view the view's.
    release(image);
    if let Some(module) = module {
        unmap_view(module.view, image.pages);
    }
}

/// The image `address` is in: the kernel's own or a loaded driver's.
pub fn module_containing(address: u64) -> Option<Module> {
    MODULES.lock().containing(address)
}

/// Where `address` is, for the report of a fatal error: prints as
/// `sioctl.sys+0x1234`, or as `no image`. Takes the table whoever holds
/// it, so only the path that stops the system may ask.
pub fn locate_fatal(address: u64) -> Located {
    Located(
        MODULES
            .force_lock()
            .containing(address)
            .map(|module| (module, address - module.base)),
    )
}

/// An address as an image and an offset into it.
pub struct Located(Option<(Module, u64)>);

impl core::fmt::Display for Located {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match &self.0 {
            Some((module, offset)) => {
                let name = core::str::from_utf8(module.name()).unwrap_or("?");
                write!(f, "{name}+{offset:#x}")
            }
            None => f.write_str("no image"),
        }
    }
}

/// `MmPageEntireDriver`: make a driver's whole image pageable and return
/// its base address, or null if the address is in no driver.
///
/// NK never pages kernel memory out, so only the lookup has an effect.
/// That is within the contract: pageable memory may always stay resident.
///
/// # Safety
/// Callable with any pointer value; it is only compared.
pub unsafe extern "C" fn MmPageEntireDriver(address_within_section: *mut c_void) -> *mut c_void {
    module_containing(address_within_section as u64)
        .map_or(core::ptr::null_mut(), |module| module.base as *mut c_void)
}
