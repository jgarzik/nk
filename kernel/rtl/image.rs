//! What a driver asks about loaded images: a message of an image's
//! message table (`RtlFindMessage`), and the image an address is in
//! (`RtlPcToFileName`). The images are the loader's (`ldr`); the
//! resource directory and the message table are read by `nk_pe`.

#![allow(non_snake_case)]

use crate::ldr;
use core::ffi::c_void;
use nk_ntabi::io::UNICODE_STRING;
use nk_ntabi::status::*;
use nk_pe::resources::{self, LANG_EN_US, ResourceError};

/// The machine's UI language, the language Windows was installed in
/// and the system's default locale, which the pinned kernel keeps in
/// `PsMachineUILanguageId`, `PsInstallUILanguageId` and
/// `PsDefaultSystemLocaleId`: NK is a US English system.
const SYSTEM_LANGUAGE: u16 = LANG_EN_US;

/// [`RtlFindMessage`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-rtlfindmessage):
/// the entry of message `message_id` in the message table of the
/// image loaded at `dll_handle`: the resource of type
/// `message_table_id` (`RT_MESSAGETABLE`), name 1, in the language
/// asked for or one Windows falls back to (`nk_pe::resources`). The
/// entry is in the image, and is the caller's to read while the image
/// is loaded.
///
/// What is missing has Windows' status: the image has no resources,
/// or `dll_handle` is no loaded image's base
/// (`STATUS_RESOURCE_DATA_NOT_FOUND`), no such type, no table of that
/// type, not in a language tried, no such message
/// (`STATUS_MESSAGE_NOT_FOUND`). A resource directory that leads
/// outside its image has no resource data.
///
/// The gaps the ledger's "partial" stands for: a language falls back
/// to its primary language, not to the parent Windows' locale data
/// names for the few languages that have another; and there are no
/// language files beside an image (MUI), so only the image itself is
/// searched.
///
/// # Safety
/// `message_entry` is writable; the image at `dll_handle` stays loaded
/// for the call.
pub unsafe extern "C" fn RtlFindMessage(
    dll_handle: *mut c_void,
    message_table_id: u32,
    message_language_id: u32,
    message_id: u32,
    message_entry: *mut *mut c_void,
) -> NTSTATUS {
    let base = dll_handle as u64;
    let Some(module) = ldr::module_containing(base).filter(|module| module.base == base) else {
        return STATUS_RESOURCE_DATA_NOT_FOUND;
    };
    // SAFETY: per the contract, the image stays loaded.
    let image = unsafe { ldr::view(&module) };
    let Ok(headers) = nk_pe::image_headers(image) else {
        return STATUS_RESOURCE_DATA_NOT_FOUND;
    };
    let languages = resources::languages(
        message_language_id as u16,
        SYSTEM_LANGUAGE,
        SYSTEM_LANGUAGE,
        SYSTEM_LANGUAGE,
    );
    let found = resources::find(
        image,
        headers.dir(resources::DIR_RESOURCE),
        message_table_id,
        1,
        &languages,
    );
    let data = match found {
        Ok(data) => data,
        Err(ResourceError::NoResources | ResourceError::Malformed) => {
            return STATUS_RESOURCE_DATA_NOT_FOUND;
        }
        Err(ResourceError::Type) => return STATUS_RESOURCE_TYPE_NOT_FOUND,
        Err(ResourceError::Name) => return STATUS_RESOURCE_NAME_NOT_FOUND,
        Err(ResourceError::Language) => return STATUS_RESOURCE_LANG_NOT_FOUND,
    };
    let (start, end) = (data.rva as usize, data.rva as usize + data.size as usize);
    let Some(table) = image.get(start..end) else {
        return STATUS_RESOURCE_DATA_NOT_FOUND;
    };
    let Some(entry) = resources::find_message(table, message_id) else {
        return STATUS_MESSAGE_NOT_FOUND;
    };
    // SAFETY: per the contract. The entry is given by its address in
    // the image as the driver sees it, not in the kernel's view.
    unsafe { message_entry.write_unaligned((base + start as u64 + entry as u64) as *mut c_void) };
    STATUS_SUCCESS
}

/// `RtlPcToFileName`: the file name of the loaded image the address
/// `pc_value` is in (`ntoskrnl.exe`, `disk.sys`), copied into
/// `file_name` as `RtlCopyUnicodeString` copies: as much as the
/// buffer holds. `STATUS_NOT_FOUND` for an address in no image. The
/// pinned kernel's routine walks its list of loaded modules and does
/// the same.
///
/// # Safety
/// `file_name` is a counted string whose buffer has `MaximumLength`
/// bytes.
pub unsafe extern "C" fn RtlPcToFileName(
    pc_value: *const c_void,
    file_name: *mut UNICODE_STRING,
) -> NTSTATUS {
    let Some(module) = ldr::module_containing(pc_value as u64) else {
        return STATUS_NOT_FOUND;
    };
    // Image names are ASCII, and no longer than this.
    let mut wide = [0u16; nk_pe::modules::NAME_MAX];
    let name = module.name();
    for (to, from) in wide.iter_mut().zip(name) {
        *to = u16::from(*from);
    }
    let source = UNICODE_STRING {
        Length: (name.len() * 2) as u16,
        MaximumLength: (name.len() * 2) as u16,
        Buffer: wide.as_mut_ptr(),
    };
    // SAFETY: per the contract for the destination; the source is the
    // local above.
    unsafe { super::counted::RtlCopyUnicodeString(file_name, &raw const source) };
    STATUS_SUCCESS
}

// ---- tests --------------------------------------------------------------

/// A PE32+ image of two pages laid out in memory: headers that name a
/// resource directory at the second page, holding a message table
/// (type 11, name 1) in languages 0x0407 and 0x0409, each with
/// messages 0x100 and 0x101. Returns it with the offsets, in the
/// image, of the 0x0409 table's two entries and the 0x0407 table's
/// first.
fn message_image() -> (alloc::vec::Vec<u8>, [usize; 3]) {
    use alloc::vec::Vec;
    const RSRC: usize = 0x1000;
    let mut image = alloc::vec![0u8; 0x2000];
    let mut put = |at: usize, bytes: &[u8]| image[at..at + bytes.len()].copy_from_slice(bytes);
    put(0, b"MZ");
    put(0x3C, &0x80u32.to_le_bytes());
    put(0x80, b"PE\0\0");
    let opt = 0x80 + 4 + 20;
    put(opt, &0x20Bu16.to_le_bytes());
    put(opt + 60, &0x400u32.to_le_bytes());
    put(opt + 108, &16u32.to_le_bytes());
    put(opt + 112 + 8 * 2, &(RSRC as u32).to_le_bytes());
    put(opt + 116 + 8 * 2, &0x1000u32.to_le_bytes());
    // A directory of entries named by number.
    let directory = |entries: &[(u32, u32)]| -> Vec<u8> {
        let mut out = alloc::vec![0u8; 14];
        out.extend((entries.len() as u16).to_le_bytes());
        for (id, leads) in entries {
            out.extend(id.to_le_bytes());
            out.extend(leads.to_le_bytes());
        }
        out
    };
    const SUB: u32 = 0x8000_0000;
    put(RSRC, &directory(&[(11, SUB | 0x20)]));
    put(RSRC + 0x20, &directory(&[(1, SUB | 0x40)]));
    put(RSRC + 0x40, &directory(&[(0x0407, 0x60), (0x0409, 0x70)]));
    // One table: a block for 0x100..=0x101, two entries.
    let table = |first: &[u8], second: &[u8]| -> Vec<u8> {
        let mut out = 1u32.to_le_bytes().to_vec();
        out.extend(0x100u32.to_le_bytes());
        out.extend(0x101u32.to_le_bytes());
        out.extend(16u32.to_le_bytes());
        for text in [first, second] {
            out.extend(((4 + text.len()) as u16).to_le_bytes());
            out.extend(0u16.to_le_bytes());
            out.extend(text);
        }
        out
    };
    let (german, english) = (
        table(b"Eins\0\0\0\0", b"Zwei\0\0\0\0"),
        table(b"One\0", b"Two\0"),
    );
    let (german_at, english_at) = (RSRC + 0x100, RSRC + 0x200);
    for (entry, at, bytes) in [(0x60, german_at, &german), (0x70, english_at, &english)] {
        put(RSRC + entry, &(at as u32).to_le_bytes());
        put(RSRC + entry + 4, &(bytes.len() as u32).to_le_bytes());
        put(at, bytes);
    }
    (image, [english_at + 16, english_at + 24, german_at + 16])
}

/// `RtlFindMessage` on an image of the test's own, entered in the
/// table of loaded images as a driver's is; and on what is no image.
/// Returns the messages asked for.
pub fn find_message_test() -> Result<u32, &'static str> {
    use crate::mm::map;
    let (image, [one, two, eins]) = message_image();
    let pages = image.len().div_ceil(crate::mm::PAGE_SIZE);
    let base = map::alloc_va(pages).ok_or("no address space")?;
    let find = |handle: u64, ty: u32, language: u32, id: u32| {
        let mut entry = 0x5A5A as *mut c_void;
        // SAFETY: a local for the entry; the test's image is entered
        // for as long as the closure below runs.
        let status =
            unsafe { RtlFindMessage(handle as *mut c_void, ty, language, id, &raw mut entry) };
        (status, entry as u64)
    };
    let at = |offset: usize| (STATUS_SUCCESS, base + offset as u64);
    let untouched = |status: NTSTATUS| (status, 0x5A5A);
    let before = find(base, 11, 0, 0x100);
    // SAFETY: address space reserved above for nothing else.
    let asked = unsafe {
        ldr::with_image_for_test("nkt-messages.sys", base, &image, || {
            [
                // No language asked for: the system's, not the first.
                (find(base, 11, 0, 0x100), at(one)),
                (find(base, 11, 0, 0x101), at(two)),
                (find(base, 11, 0x0409, 0x101), at(two)),
                (find(base, 11, 0x0407, 0x100), at(eins)),
                // A language asked for falls back to its primary
                // language alone, which this table is not in.
                (
                    find(base, 11, 0x0C07, 0x100),
                    untouched(STATUS_RESOURCE_LANG_NOT_FOUND),
                ),
                (
                    find(base, 11, 0x040C, 0x100),
                    untouched(STATUS_RESOURCE_LANG_NOT_FOUND),
                ),
                (
                    find(base, 11, 0, 0x102),
                    untouched(STATUS_MESSAGE_NOT_FOUND),
                ),
                (find(base, 11, 0, 0xFF), untouched(STATUS_MESSAGE_NOT_FOUND)),
                (
                    find(base, 16, 0, 0x100),
                    untouched(STATUS_RESOURCE_TYPE_NOT_FOUND),
                ),
                // Not an image's base.
                (
                    find(base + 0x10, 11, 0, 0x100),
                    untouched(STATUS_RESOURCE_DATA_NOT_FOUND),
                ),
            ]
        })
    };
    map::free_va(base, pages);
    let asked = asked.ok_or("the test's image could not be entered")?;
    if before != untouched(STATUS_RESOURCE_DATA_NOT_FOUND) {
        return Err("a message was found at an address where no image is loaded");
    }
    if asked.iter().any(|(got, expected)| got != expected) {
        return Err("a message was not found where its table has it, or not refused as it is");
    }
    // The kernel's own image has no resources.
    if find(nk_bootinfo::KERNEL_BASE, 11, 0, 1) != untouched(STATUS_RESOURCE_DATA_NOT_FOUND) {
        return Err("the kernel's image, which has no resources, had a message");
    }
    Ok(asked.len() as u32 + 2)
}

/// `RtlPcToFileName`: the kernel's own code is in `ntoskrnl.exe`; a
/// short buffer takes what it holds; no image, no name.
pub fn pc_to_file_name_test() -> Result<(), &'static str> {
    let name_of = |pc: u64, room: usize| {
        let mut buffer = [0xFFFFu16; 16];
        let mut name = UNICODE_STRING {
            Length: 0x7777,
            MaximumLength: (room * 2) as u16,
            Buffer: buffer.as_mut_ptr(),
        };
        // SAFETY: a counted string over a local of sixteen units, of
        // which it claims `room`.
        let status = unsafe { RtlPcToFileName(pc as *const c_void, &raw mut name) };
        (status, name.Length, buffer)
    };
    let here = pc_to_file_name_test as *const () as u64;
    let (status, length, buffer) = name_of(here, 16);
    let expected: alloc::vec::Vec<u16> = "ntoskrnl.exe".encode_utf16().collect();
    if status != STATUS_SUCCESS
        || length != 24
        || buffer[..12] != expected[..]
        || buffer[12] != 0
        || buffer[13] != 0xFFFF
    {
        return Err("the kernel's own code is not in ntoskrnl.exe, terminated");
    }
    let (status, length, buffer) = name_of(here, 4);
    if status != STATUS_SUCCESS
        || length != 8
        || buffer[..4] != expected[..4]
        || buffer[4] != 0xFFFF
    {
        return Err("a short buffer was not given as much of the name as it holds");
    }
    let (status, length, buffer) = name_of(0x1000, 16);
    if status != STATUS_NOT_FOUND || length != 0x7777 || buffer[0] != 0xFFFF {
        return Err("an address in no image was given a file name");
    }
    Ok(())
}
