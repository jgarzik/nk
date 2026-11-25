//! The driver image loader: PE file in, relocated and bound image mapped
//! with per-section protections out.
//!
//! The PE work is `lib/pe`, the same code nkload maps the kernel with.
//! This module supplies memory and the import resolver.

#![allow(non_snake_case)]

use crate::ke::SpinLock;
use crate::mm::{self, PAGE_SIZE, map};
use crate::{arch, export};
use alloc::string::String;
use alloc::vec::Vec;
use core::ffi::c_void;
use nk_mm::pt::Prot;
use nk_pe::{Pe, PeError, Symbol};

/// `IMAGE_SUBSYSTEM_NATIVE`: what a kernel driver is linked as.
const SUBSYSTEM_NATIVE: u16 = 1;
/// The value MSVC leaves in `__security_cookie` for the loader to replace.
const DEFAULT_COOKIE: u64 = 0x2B99_2DDF_A232;

/// A driver image in memory.
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
    /// The kernel has no export for an import of the driver.
    Unresolved {
        module: String,
        symbol: String,
    },
}

/// Images currently loaded, for address-to-image lookups.
static LOADED: SpinLock<Vec<Image>> = SpinLock::new(Vec::new());

fn lossy(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).into_owned()
}

/// A stack-protector cookie for one image: unpredictable-ish, never zero,
/// never the default, and with the top 16 bits clear, which the x64 check
/// routine requires. The entropy is only the CPU's cycle counter; a real
/// random source is future work.
fn security_cookie() -> u64 {
    let mut x = arch::cycle_counter() ^ 0x9E37_79B9_7F4A_7C15;
    x ^= x >> 30;
    x = x.wrapping_mul(0xBF58_476D_1CE4_E5B9);
    x ^= x >> 27;
    let cookie = x & 0x0000_FFFF_FFFF_FFFF;
    if cookie == 0 || cookie == DEFAULT_COOKIE {
        0x0000_1F2E_3D4C_5B6A
    } else {
        cookie
    }
}

/// Load a driver image from the bytes of its file.
pub fn load(file: &[u8]) -> Result<Image, LoadError> {
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
    LOADED.lock().push(image);
    Ok(image)
}

fn release(image: &Image) {
    map::unmap(image.base, image.pages);
    map::free_va(image.base, image.pages);
    mm::free_frames(image.phys, image.pages);
}

/// Unmap an image and free its memory. No code in it may run again.
pub fn unload(image: &Image) {
    {
        let mut loaded = LOADED.lock();
        loaded.retain(|i| i.base != image.base);
        // An empty table holds no memory, so leak checks see none.
        loaded.shrink_to_fit();
    }
    release(image);
}

/// The loaded image that contains `addr`.
pub fn image_containing(addr: u64) -> Option<Image> {
    LOADED
        .lock()
        .iter()
        .copied()
        .find(|i| (i.base..i.base + i.size as u64).contains(&addr))
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
    image_containing(address_within_section as u64)
        .map_or(core::ptr::null_mut(), |i| i.base as *mut c_void)
}
