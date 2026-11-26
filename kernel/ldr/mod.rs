//! The driver image loader: PE file in, relocated and bound image mapped
//! with per-section protections out.
//!
//! The PE work is `lib/pe`, the same code nkload maps the kernel with.
//! This module supplies memory and the import resolver.
//!
//! An import from `ntoskrnl.exe` or `hal.dll` is bound to the kernel's
//! export table. An import from any other module is bound to that
//! module's export directory: the module is an export driver, a library,
//! loaded when the first image that imports from it is loaded and
//! unloaded when the last one goes
//! ([Creating Export Drivers](https://learn.microsoft.com/en-us/windows-hardware/drivers/kernel/creating-export-drivers)).
//! Loading and unloading are one at a time, under a mutex a thread can
//! sleep on: a load calls a library's `DllInitialize`, and loads another
//! image from inside itself.

#![allow(non_snake_case)]

use crate::ke::seh::{self, Guard, Unhandled};
use crate::ke::{Rank, SpinLock, mutex, wait};
use crate::mm::{self, PAGE_SIZE, map};
use crate::{arch, export};
use alloc::string::String;
use alloc::vec::Vec;
use core::cell::UnsafeCell;
use core::ffi::c_void;
use core::mem::MaybeUninit;
use core::sync::atomic::{AtomicPtr, AtomicU64, Ordering};
use nk_bootinfo::BootInfo;
use nk_mm::pt::Prot;
use nk_ntabi::io::UNICODE_STRING;
use nk_ntabi::ke::KMUTANT;
use nk_ntabi::status::*;
use nk_pe::exports::{Export, Exports, forward_target};
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
    // SAFETY: static storage for a mutex nothing has yet.
    unsafe { mutex::KeInitializeMutex(LOADER.mutex.get().cast(), 0) };
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
pub struct Image {
    pub base: u64,
    pub size: usize,
    pub entry: u64,
    phys: u64,
    pages: usize,
    /// The libraries it imports from, by base address: it counts as one
    /// importer of each until it is unloaded.
    libraries: Vec<u64>,
}

/// A library: an image loaded because another imports from it.
struct Library {
    image: Image,
    /// Its `DllUnload`, if it exports one.
    unload: Option<u64>,
}

/// What serialises loading and unloading, and the libraries, which
/// belong to whoever holds it.
struct Loader {
    mutex: UnsafeCell<MaybeUninit<KMUTANT>>,
    libraries: UnsafeCell<Vec<Library>>,
}

// SAFETY: the mutex is reached through the kernel's mutex routines,
// which lock for themselves; the list only by the thread that holds the
// mutex (`with_libraries`).
unsafe impl Sync for Loader {}

static LOADER: Loader = Loader {
    mutex: UnsafeCell::new(MaybeUninit::uninit()),
    libraries: UnsafeCell::new(Vec::new()),
};

/// Run `f` as the one load or unload in progress. The mutex is taken
/// again by the same thread without waiting: a library is loaded from
/// inside the load of the image that imports from it.
fn serialised<R>(f: impl FnOnce() -> R) -> R {
    let mutex = LOADER.mutex.get();
    // SAFETY: the loader's mutex, initialised by `init`; released by the
    // thread that took it.
    unsafe {
        wait::wait(Some(mutex.cast()), None);
        let result = f();
        mutex::KeReleaseMutex(mutex.cast(), 0);
        result
    }
}

/// Run `f` on the list of libraries. For the thread that holds the
/// loader's mutex (`serialised`); `f` neither loads nor unloads, so no
/// two calls are ever in progress at once.
fn with_libraries<R>(f: impl FnOnce(&mut Vec<Library>) -> R) -> R {
    // SAFETY: per the contract above, this is the only reference.
    f(unsafe { &mut *LOADER.libraries.get() })
}

/// How deep libraries may import from libraries. Images that import
/// from each other in a circle are refused at this depth.
const MAX_NESTING: usize = 8;

/// How many forwarders in a row lead from an import to an address.
const MAX_FORWARDS: usize = 8;

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
    /// The module the image imports from has no such export: the
    /// kernel's table, or a library's export directory.
    Unresolved {
        module: String,
        symbol: String,
    },
    /// An image of this file name is loaded already.
    AlreadyLoaded,
    /// The image imports from a library that is not among the boot
    /// files.
    NoLibrary {
        module: String,
    },
    /// The library's `DllInitialize` refused.
    LibraryFailed {
        module: String,
        status: NTSTATUS,
    },
    /// The image imports from one that runs as a driver. Not handled.
    NotALibrary {
        module: String,
    },
    /// Libraries import from libraries deeper than [`MAX_NESTING`], or
    /// in a circle.
    TooDeep {
        module: String,
    },
}

impl LoadError {
    /// What Windows' `ZwLoadDriver` reports for it. Observed on the
    /// reference Windows (`doc/DESIGN.md`, Exports): a library that
    /// lacks a name its importer asks for, and a library that is
    /// nowhere. The rest follow the status codes' own meanings.
    pub fn status(&self) -> NTSTATUS {
        match self {
            Self::Pe(_) | Self::NotNative(_) | Self::Unaligned => STATUS_INVALID_IMAGE_FORMAT,
            Self::NoMemory | Self::TooMany | Self::TooDeep { .. } => STATUS_INSUFFICIENT_RESOURCES,
            Self::Unresolved { symbol, .. } if symbol.starts_with('#') => {
                STATUS_DRIVER_ORDINAL_NOT_FOUND
            }
            Self::Unresolved { .. } => STATUS_DRIVER_ENTRYPOINT_NOT_FOUND,
            Self::AlreadyLoaded => STATUS_IMAGE_ALREADY_LOADED,
            Self::NoLibrary { .. } => STATUS_OBJECT_NAME_NOT_FOUND,
            Self::LibraryFailed { status, .. } => *status,
            Self::NotALibrary { .. } => STATUS_NOT_SUPPORTED,
        }
    }
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

/// The address of the export `symbol` of the loaded image `module`,
/// following forwarders: to the kernel (`NTOSKRNL.Name`), or to another
/// library, of which the importer then holds a reference too (`held`).
/// A forwarder does not load its target. `None` if there is no such
/// export or the chain leads nowhere.
fn export_address(
    module: &Module,
    symbol: Symbol<'_>,
    held: &mut Vec<u64>,
    hops: usize,
) -> Option<u64> {
    // SAFETY: the image is loaded, and stays loaded while the loader's
    // mutex is held, which it is by every caller.
    let image = unsafe { view(module) };
    let exports = Exports::parse(image, module.exports).ok()??;
    let export = match symbol {
        Symbol::Name(name) => exports.by_name(name),
        Symbol::Ordinal(ordinal) => exports.by_ordinal(u32::from(ordinal)),
    };
    match export.ok()?? {
        Export::Rva(rva) => Some(module.base + u64::from(rva)),
        Export::Forward(forward) => {
            if hops == MAX_FORWARDS {
                return None;
            }
            let (stem, target) = forward_target(forward)?;
            let symbol = match target.strip_prefix(b"#") {
                Some(digits) => Symbol::Ordinal(core::str::from_utf8(digits).ok()?.parse().ok()?),
                None => Symbol::Name(target),
            };
            if [&b"ntoskrnl"[..], b"hal"]
                .iter()
                .any(|kernel| kernel.eq_ignore_ascii_case(stem))
            {
                return match symbol {
                    Symbol::Name(name) => export::resolve(KERNEL_NAME, name),
                    Symbol::Ordinal(_) => None,
                };
            }
            let next = MODULES.lock().with_stem(stem).filter(|m| m.library)?;
            hold(next.base, held).ok()?;
            export_address(&next, symbol, held, hops + 1)
        }
    }
}

/// Count the image being loaded as an importer of the library at
/// `base`, once however many of its imports lead there.
fn hold(base: u64, held: &mut Vec<u64>) -> Result<(), LoadError> {
    if held.contains(&base) {
        return Ok(());
    }
    held.try_reserve_exact(1).map_err(|_| LoadError::NoMemory)?;
    MODULES.lock().count_importer(base, 1);
    held.push(base);
    Ok(())
}

/// The library called `name`, with the image being loaded counted as
/// one of its importers: the loaded one, or else the boot file of that
/// name, loaded and initialised now.
fn library(name: &[u8], depth: usize, held: &mut Vec<u64>) -> Result<Module, LoadError> {
    let found = MODULES.lock().named(name);
    let module = match found {
        Some(module) if module.library => module,
        Some(_) => {
            return Err(LoadError::NotALibrary {
                module: lossy(name),
            });
        }
        None if depth == MAX_NESTING => {
            return Err(LoadError::TooDeep {
                module: lossy(name),
            });
        }
        None => {
            let file = core::str::from_utf8(name)
                .ok()
                .and_then(|name| Some((name, boot_file(name)?)));
            let Some((name, file)) = file else {
                return Err(LoadError::NoLibrary {
                    module: lossy(name),
                });
            };
            load_library(name, file, depth + 1).inspect_err(|error| refused(name, error))?
        }
    };
    hold(module.base, held)?;
    Ok(module)
}

/// The address of `name` among the exports of the library `module`
/// itself: a routine the loader calls.
fn own_export(module: &Module, name: &[u8]) -> Option<u64> {
    // SAFETY: as in `export_address`.
    let image = unsafe { view(module) };
    match Exports::parse(image, module.exports).ok()??.by_name(name) {
        Ok(Some(Export::Rva(rva))) => Some(module.base + u64::from(rva)),
        _ => None,
    }
}

/// Load the library in `file`, called `name`: as any image is loaded,
/// and then its `DllInitialize` is called, at `PASSIVE_LEVEL`, with the
/// path of the key a service of its name would have (the key need not
/// exist: the library is given the name, as on Windows). Its entry
/// point is not called. A library whose `DllInitialize` fails is
/// unloaded again.
fn load_library(name: &str, file: &[u8], depth: usize) -> Result<Module, LoadError> {
    let image = load_image(name, file, true, depth)?;
    let Some(module) = MODULES.lock().named(name.as_bytes()) else {
        unreachable!("an image just loaded is in the table of images");
    };
    if let Some(initialize) = own_export(&module, b"DllInitialize") {
        let mut path: Vec<u16> = "\\Registry\\Machine\\System\\CurrentControlSet\\Services\\"
            .encode_utf16()
            .chain(String::from_utf8_lossy(module.stem()).encode_utf16())
            .chain([0])
            .collect();
        let bytes = (path.len() - 1) * 2;
        let mut registry = UNICODE_STRING {
            Length: bytes as u16,
            MaximumLength: (bytes + 2) as u16,
            Buffer: path.as_mut_ptr(),
        };
        // SAFETY: the export of that name of an image just mapped,
        // relocated and bound, which has the signature every library's
        // `DllInitialize` has; the string outlives the call. The load
        // mutex is held, so nothing may be unwound through the call:
        // an exception the library lets out is unhandled, in the system
        // thread that loads images.
        let status = unsafe {
            seh::call(
                initialize as usize,
                [(&raw mut registry).addr(), 0, 0, 0],
                &Guard::Base(Unhandled::SystemThread),
            ) as u32 as NTSTATUS
        };
        if !nt_success(status) {
            unload_image(&image);
            return Err(LoadError::LibraryFailed {
                module: name.into(),
                status,
            });
        }
    }
    let unload = own_export(&module, b"DllUnload");
    with_libraries(|libraries| {
        libraries.reserve_exact(1);
        libraries.push(Library { image, unload });
    });
    Ok(module)
}

/// Say in the log why an image was not loaded, with Windows' status.
fn refused(name: &str, error: &LoadError) {
    kprintln!(
        "ldr: {name} not loaded, status {:#010x}: {error:?}",
        error.status()
    );
}

/// Load a driver image from the bytes of its file, called `name`. A
/// refusal is logged, naming the module and symbol where an import is
/// the reason.
pub fn load(name: &str, file: &[u8]) -> Result<Image, LoadError> {
    serialised(|| load_image(name, file, false, 0)).inspect_err(|error| refused(name, error))
}

/// Load an image, as a driver or as a `library`, `depth` libraries deep
/// in the imports of the image whose load began it. For the holder of
/// the loader's mutex.
fn load_image(name: &str, file: &[u8], library: bool, depth: usize) -> Result<Image, LoadError> {
    if MODULES.lock().named(name.as_bytes()).is_some() {
        return Err(LoadError::AlreadyLoaded);
    }
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
    let mut image = Image {
        base,
        size,
        entry: base + u64::from(h.entry_rva),
        phys,
        pages,
        libraries: Vec::new(),
    };

    // Build the image through the direct map, which is always writable;
    // the driver's own view gets each section's real protection.
    // SAFETY: the frames were just allocated for this image and nothing
    // else references them until they are mapped below.
    let mem = unsafe { core::slice::from_raw_parts_mut(mm::phys_to_virt(phys), pages * PAGE_SIZE) };
    let held = &mut image.libraries;
    let built = (|| {
        pe.map_into(mem).map_err(LoadError::Pe)?;
        nk_pe::relocate(mem, &h, base).map_err(LoadError::Pe)?;
        // Why a module could not be imported from at all; an import the
        // module simply lacks is named from the image's own tables.
        let mut unusable = None;
        let resolver = |module: &[u8], sym: Symbol<'_>| {
            if export::is_kernel(module) {
                return match sym {
                    Symbol::Name(name) => export::resolve(module, name),
                    Symbol::Ordinal(_) => None,
                };
            }
            match self::library(module, depth, held) {
                Ok(library) => export_address(&library, sym, held, 0),
                Err(error) => {
                    unusable.get_or_insert(error);
                    None
                }
            }
        };
        let bound = nk_pe::bind_imports(mem, &h, resolver);
        bound.map_err(|e| match (e, unusable) {
            (PeError::Unresolved { .. }, Some(unusable)) => unusable,
            (
                PeError::Unresolved {
                    dll_rva,
                    name_rva,
                    ordinal,
                },
                None,
            ) => LoadError::Unresolved {
                module: nk_pe::cstr_at(mem, dll_rva).map(lossy).unwrap_or_default(),
                symbol: match nk_pe::cstr_at(mem, name_rva) {
                    Ok(name) if name_rva != 0 => lossy(name),
                    _ => alloc::format!("#{ordinal}"),
                },
            },
            (other, _) => LoadError::Pe(other),
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
    .is_some_and(|mut module| {
        module.exports = h.dir(nk_pe::DIR_EXPORT);
        module.library = library;
        MODULES.lock().insert(module).is_ok()
    });
    if !entered {
        unmap_view(view, pages);
        release(&image);
        return Err(LoadError::TooMany);
    }
    Ok(image)
}

/// Give back an image's memory and addresses, and its place among the
/// importers of the libraries it had bound to.
fn release(image: &Image) {
    map::unmap(image.base, image.pages);
    map::free_va(image.base, image.pages);
    mm::free_frames(image.phys, image.pages);
    for &library in &image.libraries {
        drop_importer(library);
    }
}

/// Unmap an image and free its memory. No code in it may run again.
/// The libraries it imported from lose an importer; one that has none
/// left is unloaded after it.
pub fn unload(image: &Image) {
    serialised(|| unload_image(image));
}

/// As [`unload`], for the holder of the loader's mutex.
fn unload_image(image: &Image) {
    let module = MODULES.lock().remove(image.base);
    // The image's addresses go back first, so that the next image of
    // this size is given them again and its view the view's.
    release(image);
    if let Some(module) = module {
        unmap_view(module.view, image.pages);
    }
}

/// The library at `base` has one importer fewer. With none left its
/// `DllUnload` is called, at `PASSIVE_LEVEL`, and it is unloaded. As
/// [Microsoft documents](https://learn.microsoft.com/en-us/windows-hardware/drivers/kernel/creating-export-drivers),
/// a library that exports no `DllUnload` stays loaded; so does one
/// whose `DllUnload` fails.
fn drop_importer(base: u64) {
    if MODULES.lock().count_importer(base, -1) != Some(0) {
        return;
    }
    let found = with_libraries(|libraries| {
        let at = libraries.iter().position(|l| l.image.base == base)?;
        Some((at, libraries[at].unload?))
    });
    let Some((at, routine)) = found else {
        return;
    };
    // SAFETY: the export called `DllUnload` of a loaded library, which
    // has the signature every library's `DllUnload` has. As for
    // `DllInitialize`, the load mutex is held and the call is a base.
    let status = unsafe {
        seh::call(
            routine as usize,
            [0; 4],
            &Guard::Base(Unhandled::SystemThread),
        ) as u32 as NTSTATUS
    };
    if !nt_success(status) {
        kprintln!("ldr: a library's DllUnload failed, status {status:#010x}: it stays loaded");
        return;
    }
    let library = with_libraries(|libraries| {
        let library = libraries.remove(at);
        // An empty list holds no memory, so leak checks see none.
        libraries.shrink_to_fit();
        library
    });
    unload_image(&library.image);
}

/// The loaded image whose file name is `name`.
pub fn module_named(name: &str) -> Option<Module> {
    MODULES.lock().named(name.as_bytes())
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

// ---- tests --------------------------------------------------------------

/// A place among a library's importers, held by a test as a second
/// importer would hold it: taken with the library loaded if it was not,
/// given up when dropped.
pub struct TestImporter(Vec<u64>);

impl TestImporter {
    /// Import from the library called `name`, as an image whose import
    /// table names it would.
    pub fn of(name: &str) -> Result<Self, LoadError> {
        serialised(|| {
            let mut held = Vec::new();
            library(name.as_bytes(), 0, &mut held).map(|_| Self(held))
        })
    }
}

impl Drop for TestImporter {
    fn drop(&mut self) {
        serialised(|| {
            for &library in &self.0 {
                drop_importer(library);
            }
        });
    }
}

/// What an import of `symbol` from an image is bound to, for a test's
/// own image: one that exists only as `image`, the bytes of its export
/// directory `exports`, standing in the table of images as the library
/// `name` at `base` for as long as this takes.
///
/// # Safety
/// `base` is the start of `image.len()` bytes of address space that are
/// nothing else's.
pub unsafe fn bind_for_test(
    name: &str,
    base: u64,
    image: &[u8],
    exports: nk_pe::DataDir,
    symbols: &[Symbol<'_>],
) -> Option<Vec<Option<u64>>> {
    let mut module = Module::new(
        name.as_bytes(),
        base,
        image.len() as u64,
        nk_pe::DataDir::default(),
        image.as_ptr() as u64,
    )?;
    module.exports = exports;
    module.library = true;
    serialised(|| {
        MODULES.lock().insert(module).ok()?;
        let mut held = Vec::new();
        let bound = symbols
            .iter()
            .map(|&symbol| export_address(&module, symbol, &mut held, 0))
            .collect();
        MODULES.lock().remove(base);
        Some(bound)
    })
}
