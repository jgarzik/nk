//! The slice of UEFI that nkload uses: just enough tables and protocols to
//! print, read files, allocate memory and leave boot services.
//!
//! Layouts follow the UEFI specification. Table members nkload never calls
//! are kept as opaque `usize` padding so the offsets of the ones it does
//! call stay right.

use core::ffi::c_void;
use core::fmt;
use core::sync::atomic::{AtomicPtr, Ordering};

pub type Handle = *mut c_void;
pub type Status = usize;

pub const SUCCESS: Status = 0;

/// `EfiLoaderData`: memory the kernel must treat as in use.
const LOADER_DATA: u32 = 2;
const ALLOCATE_ANY_PAGES: u32 = 0;
const FILE_MODE_READ: u64 = 1;
pub const FILE_DIRECTORY: u64 = 0x10;
/// `EfiResetShutdown`
pub const RESET_SHUTDOWN: u32 = 2;

#[repr(C)]
pub struct Guid(u32, u16, u16, [u8; 8]);

const LOADED_IMAGE: Guid = Guid(
    0x5B1B31A1,
    0x9562,
    0x11D2,
    [0x8E, 0x3F, 0x00, 0xA0, 0xC9, 0x69, 0x72, 0x3B],
);
const SIMPLE_FILE_SYSTEM: Guid = Guid(
    0x964E5B22,
    0x6459,
    0x11D2,
    [0x8E, 0x39, 0x00, 0xA0, 0xC9, 0x69, 0x72, 0x3B],
);
const FILE_INFO: Guid = Guid(
    0x09576E92,
    0x6D3F,
    0x11D2,
    [0x8E, 0x39, 0x00, 0xA0, 0xC9, 0x69, 0x72, 0x3B],
);
const ACPI_20_TABLE: Guid = Guid(
    0x8868E871,
    0xE4F1,
    0x11D3,
    [0xBC, 0x22, 0x00, 0x80, 0xC7, 0x3C, 0x88, 0x81],
);

#[repr(C)]
struct TableHeader {
    signature: u64,
    revision: u32,
    size: u32,
    crc: u32,
    reserved: u32,
}

#[repr(C)]
pub struct SystemTable {
    hdr: TableHeader,
    firmware_vendor: *const u16,
    firmware_revision: u32,
    console_in_handle: Handle,
    console_in: *mut c_void,
    console_out_handle: Handle,
    console_out: *mut TextOutput,
    stderr_handle: Handle,
    stderr: *mut c_void,
    pub runtime: *mut RuntimeServices,
    boot: *mut BootServices,
    nconfig: usize,
    config: *const ConfigTable,
}

#[repr(C)]
struct ConfigTable {
    guid: Guid,
    table: *const c_void,
}

#[repr(C)]
struct TextOutput {
    reset: usize,
    output_string: unsafe extern "efiapi" fn(*mut TextOutput, *const u16) -> Status,
}

#[repr(C)]
struct BootServices {
    hdr: TableHeader,
    tpl: [usize; 2],
    allocate_pages: unsafe extern "efiapi" fn(u32, u32, usize, *mut u64) -> Status,
    free_pages: usize,
    get_memory_map:
        unsafe extern "efiapi" fn(*mut usize, *mut u8, *mut usize, *mut usize, *mut u32) -> Status,
    pool: [usize; 2],
    events: [usize; 6],
    protocol_install: [usize; 3],
    handle_protocol: unsafe extern "efiapi" fn(Handle, *const Guid, *mut *mut c_void) -> Status,
    protocol_misc: [usize; 5],
    image: [usize; 4],
    exit_boot_services: unsafe extern "efiapi" fn(Handle, usize) -> Status,
}

#[repr(C)]
pub struct RuntimeServices {
    hdr: TableHeader,
    time_and_variables: [usize; 10],
    pub reset_system: unsafe extern "efiapi" fn(u32, Status, usize, *const c_void) -> !,
}

#[repr(C)]
struct LoadedImage {
    revision: u32,
    parent: Handle,
    system_table: *mut SystemTable,
    device: Handle,
}

#[repr(C)]
struct FileSystem {
    revision: u64,
    open_volume: unsafe extern "efiapi" fn(*mut FileSystem, *mut *mut FileProto) -> Status,
}

#[repr(C)]
struct FileProto {
    revision: u64,
    open: unsafe extern "efiapi" fn(
        *mut FileProto,
        *mut *mut FileProto,
        *const u16,
        u64,
        u64,
    ) -> Status,
    close: unsafe extern "efiapi" fn(*mut FileProto) -> Status,
    delete: usize,
    read: unsafe extern "efiapi" fn(*mut FileProto, *mut usize, *mut u8) -> Status,
    write: usize,
    get_position: usize,
    set_position: usize,
    get_info: unsafe extern "efiapi" fn(*mut FileProto, *const Guid, *mut usize, *mut u8) -> Status,
}

/// Offsets in `EFI_FILE_INFO`.
const INFO_FILE_SIZE: usize = 8;
const INFO_ATTRIBUTE: usize = 72;
const INFO_NAME: usize = 80;

static SYSTEM_TABLE: AtomicPtr<SystemTable> = AtomicPtr::new(core::ptr::null_mut());

/// Record the system table firmware passed to the entry point.
///
/// # Safety
/// `st` must be the valid `EFI_SYSTEM_TABLE` pointer for this image, and
/// boot services must still be active.
pub unsafe fn init(st: *mut SystemTable) {
    SYSTEM_TABLE.store(st, Ordering::Relaxed);
}

fn st() -> &'static SystemTable {
    // SAFETY: `init` stored the firmware's system table, which stays valid
    // and unmoved for the life of the image.
    unsafe { &*SYSTEM_TABLE.load(Ordering::Relaxed) }
}

fn bs() -> &'static BootServices {
    // SAFETY: the system table's boot services pointer is valid until
    // ExitBootServices, after which nkload calls nothing here.
    unsafe { &*st().boot }
}

/// The firmware's runtime services table (stays valid after boot services).
pub fn runtime() -> *mut RuntimeServices {
    st().runtime
}

/// Power the machine off. Works before and after `ExitBootServices`.
pub fn shutdown() -> ! {
    // SAFETY: the runtime table is valid for the life of the system, and
    // ResetSystem takes no pointers with EfiResetShutdown.
    unsafe { ((*runtime()).reset_system)(RESET_SHUTDOWN, SUCCESS, 0, core::ptr::null()) }
}

/// Encode `s` as NUL-terminated UCS-2 for firmware calls.
fn ucs2<const N: usize>(s: &str) -> [u16; N] {
    let mut out = [0u16; N];
    for (o, c) in out[..N - 1].iter_mut().zip(s.encode_utf16()) {
        *o = c;
    }
    out
}

pub struct Console;

impl fmt::Write for Console {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        let out = st().console_out;
        if out.is_null() {
            return Ok(());
        }
        let mut buf = [0u16; 65];
        let mut n = 0;
        let flush = |buf: &mut [u16; 65], n: &mut usize| {
            buf[*n] = 0;
            // SAFETY: `out` is the firmware's text protocol and `buf` is a
            // NUL-terminated string that outlives the call.
            unsafe { ((*out).output_string)(out, buf.as_ptr()) };
            *n = 0;
        };
        for c in s.chars() {
            // Firmware consoles want CR LF.
            let units: &[u16] = if c == '\n' { &[13, 10] } else { &[c as u16] };
            if n + units.len() > 64 {
                flush(&mut buf, &mut n);
            }
            buf[n..n + units.len()].copy_from_slice(units);
            n += units.len();
        }
        flush(&mut buf, &mut n);
        Ok(())
    }
}

#[macro_export]
macro_rules! println {
    ($($arg:tt)*) => {{
        use core::fmt::Write as _;
        let _ = writeln!($crate::efi::Console, $($arg)*);
    }};
}

/// Allocate `pages` zeroed 4 KiB pages. Returns the physical address.
pub fn alloc_pages(pages: usize) -> Option<u64> {
    let mut addr = 0u64;
    // SAFETY: AllocatePages writes one address through the out pointer.
    let s = unsafe { (bs().allocate_pages)(ALLOCATE_ANY_PAGES, LOADER_DATA, pages, &raw mut addr) };
    if s != SUCCESS {
        return None;
    }
    // SAFETY: firmware just gave us `pages` pages at `addr`, identity mapped.
    unsafe { core::ptr::write_bytes(addr as *mut u8, 0, pages * 4096) };
    Some(addr)
}

/// A byte slice over memory from `alloc_pages`, which is never freed.
pub fn page_slice(addr: u64, len: usize) -> &'static mut [u8] {
    // SAFETY: callers pass an address and length from `alloc_pages`; each
    // allocation is turned into a slice once, so there is no aliasing.
    unsafe { core::slice::from_raw_parts_mut(addr as *mut u8, len) }
}

/// The ACPI RSDP from the configuration table, or 0.
pub fn rsdp() -> u64 {
    // SAFETY: firmware guarantees `nconfig` entries at `config`.
    let tables = unsafe { core::slice::from_raw_parts(st().config, st().nconfig) };
    let same = |a: &Guid, b: &Guid| (a.0, a.1, a.2, a.3) == (b.0, b.1, b.2, b.3);
    tables
        .iter()
        .find(|t| same(&t.guid, &ACPI_20_TABLE))
        .map_or(0, |t| t.table as u64)
}

/// Read the current memory map into `buf`. Returns (bytes, descriptor size, map key).
pub fn memory_map(buf: &mut [u8]) -> Option<(usize, usize, usize)> {
    let (mut size, mut key, mut desc, mut ver) = (buf.len(), 0, 0, 0);
    // SAFETY: the out pointers are valid and `size` bounds the buffer.
    let s = unsafe {
        (bs().get_memory_map)(
            &raw mut size,
            buf.as_mut_ptr(),
            &raw mut key,
            &raw mut desc,
            &raw mut ver,
        )
    };
    (s == SUCCESS).then_some((size, desc, key))
}

/// Leave boot services. After `true`, only runtime services may be called.
pub fn exit_boot_services(image: Handle, key: usize) -> bool {
    // SAFETY: `image` is this image's handle and `key` names a memory map.
    unsafe { (bs().exit_boot_services)(image, key) == SUCCESS }
}

/// An open file or directory on the boot volume.
pub struct File(*mut FileProto);

impl File {
    /// The root directory of the volume nkload was started from.
    pub fn boot_volume(image: Handle) -> Option<File> {
        let mut li: *mut c_void = core::ptr::null_mut();
        let mut fs: *mut c_void = core::ptr::null_mut();
        let mut root: *mut FileProto = core::ptr::null_mut();
        // SAFETY: each call writes one interface pointer on success; the
        // interfaces are firmware objects valid during boot services.
        unsafe {
            if (bs().handle_protocol)(image, &LOADED_IMAGE, &raw mut li) != SUCCESS {
                return None;
            }
            let device = (*li.cast::<LoadedImage>()).device;
            if (bs().handle_protocol)(device, &SIMPLE_FILE_SYSTEM, &raw mut fs) != SUCCESS {
                return None;
            }
            let fs = fs.cast::<FileSystem>();
            if ((*fs).open_volume)(fs, &raw mut root) != SUCCESS {
                return None;
            }
        }
        Some(File(root))
    }

    /// Open `path` (backslash separated) relative to this directory.
    pub fn open(&self, path: &str) -> Option<File> {
        let name: [u16; 128] = ucs2(path);
        let mut out: *mut FileProto = core::ptr::null_mut();
        // SAFETY: `self.0` is an open file protocol; `name` is NUL terminated.
        let s = unsafe { ((*self.0).open)(self.0, &raw mut out, name.as_ptr(), FILE_MODE_READ, 0) };
        // Lazily: a `File` built around the null pointer of a failed open
        // would be closed when dropped.
        (s == SUCCESS).then(|| File(out))
    }

    /// Size in bytes.
    pub fn size(&self) -> Option<usize> {
        let mut info = [0u64; 64];
        let mut len = size_of_val(&info);
        // SAFETY: `info` is an aligned buffer of `len` bytes.
        let s = unsafe {
            ((*self.0).get_info)(self.0, &FILE_INFO, &raw mut len, info.as_mut_ptr().cast())
        };
        (s == SUCCESS).then_some(info[INFO_FILE_SIZE / 8] as usize)
    }

    /// Read up to `buf.len()` bytes. Returns the count read.
    pub fn read(&self, buf: &mut [u8]) -> Option<usize> {
        let mut len = buf.len();
        // SAFETY: `buf` is valid for `len` bytes.
        let s = unsafe { ((*self.0).read)(self.0, &raw mut len, buf.as_mut_ptr()) };
        (s == SUCCESS).then_some(len)
    }

    /// Read the whole file into freshly allocated pages.
    pub fn read_all(&self) -> Option<&'static mut [u8]> {
        let size = self.size()?;
        let buf = page_slice(alloc_pages(size.div_ceil(4096).max(1))?, size);
        (self.read(buf)? == size).then_some(buf)
    }

    /// Next entry of a directory: `(name, is_directory)`. The name is ASCII
    /// in `name`; returns its length, or `None` at the end.
    pub fn next_entry(&self, name: &mut [u8]) -> Option<(usize, bool)> {
        let mut info = [0u64; 64];
        // SAFETY: `info` is plain data; viewing it as bytes is always valid.
        let bytes = unsafe { core::slice::from_raw_parts_mut(info.as_mut_ptr().cast::<u8>(), 512) };
        if self.read(bytes)? == 0 {
            return None;
        }
        let attr = u64::from_le_bytes(bytes[INFO_ATTRIBUTE..INFO_ATTRIBUTE + 8].try_into().ok()?);
        let mut len = 0;
        for c in bytes[INFO_NAME..]
            .as_chunks::<2>()
            .0
            .iter()
            .map(|c| u16::from_le_bytes([c[0], c[1]]))
        {
            if c == 0 || len == name.len() {
                break;
            }
            name[len] = if c < 0x80 { c as u8 } else { b'?' };
            len += 1;
        }
        Some((len, attr & FILE_DIRECTORY != 0))
    }
}

impl Drop for File {
    fn drop(&mut self) {
        // SAFETY: `self.0` is an open file protocol, closed exactly once.
        unsafe { ((*self.0).close)(self.0) };
    }
}
