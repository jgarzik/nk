//! Tests of the registry, through the routines drivers call.

use crate::cm::{
    ZwCreateKey, ZwDeleteKey, ZwEnumerateKey, ZwEnumerateValueKey, ZwOpenKey, ZwQueryValueKey,
    ZwSetValueKey,
};
use crate::ps::ZwClose;
use crate::test::{Group, Report};
use alloc::vec::Vec;
use core::ffi::c_void;
use nk_bootinfo::BootInfo;
use nk_ntabi::io::UNICODE_STRING;
use nk_ntabi::ob::OBJECT_ATTRIBUTES;

pub static GROUP: Group = Group {
    names: &[
        "cm.keys",
        "cm.values",
        "cm.delete",
        "cm.enumerate.keys",
        "cm.enumerate.values",
        "cm.namespace",
        "cm.control-set",
        "cm.hive.values",
        "cm.hive.names",
        "cm.hive.refused",
    ],
    run,
    manual: false,
};

const SERVICES: &str = "\\Registry\\Machine\\System\\CurrentControlSet\\Services";
const NOT_FOUND: u32 = 0xC000_0034;

/// A counted string over `text`, which must outlive it.
fn counted(text: &[u16]) -> UNICODE_STRING {
    UNICODE_STRING {
        Length: (text.len() * 2) as u16,
        MaximumLength: (text.len() * 2) as u16,
        Buffer: text.as_ptr().cast_mut(),
    }
}

/// Open (or create) the key `path`, relative to `root` if that is not
/// null: the status, the handle, and for a creation what it reports.
fn key(path: &str, root: *mut c_void, create: bool) -> (u32, *mut c_void, u32) {
    let text: Vec<u16> = path.encode_utf16().collect();
    let name = counted(&text);
    let attributes = OBJECT_ATTRIBUTES {
        Length: size_of::<OBJECT_ATTRIBUTES>() as u32,
        RootDirectory: root,
        ObjectName: &raw const name,
        Attributes: 0x240,
        SecurityDescriptor: core::ptr::null_mut(),
        SecurityQualityOfService: core::ptr::null_mut(),
    };
    let mut handle = core::ptr::null_mut();
    let mut disposition = 0;
    // SAFETY: locals that outlive the call.
    let status = unsafe {
        if create {
            ZwCreateKey(
                &raw mut handle,
                0xF003F,
                &raw const attributes,
                0,
                core::ptr::null(),
                0,
                &raw mut disposition,
            )
        } else {
            ZwOpenKey(&raw mut handle, 0xF003F, &raw const attributes)
        }
    };
    (status as u32, handle, disposition)
}

fn keys() -> Result<(), &'static str> {
    let null = core::ptr::null_mut();
    let path = alloc::format!("{SERVICES}\\NkTest");
    if key(&path, null, false).0 != NOT_FOUND {
        return Err("a key that was never made was opened");
    }
    // The keys above the last must exist.
    if key(&alloc::format!("{SERVICES}\\Missing\\NkTest"), null, true).0 != NOT_FOUND {
        return Err("a key was created under a key that is not there");
    }
    let (status, made, disposition) = key(&path, null, true);
    if (status, disposition) != (0, 1) || made.is_null() {
        return Err("creating a key did not report a new key");
    }
    let (status, again, disposition) = key(&path, null, true);
    if (status, disposition) != (0, 2) {
        return Err("creating a key that exists did not report an existing key");
    }
    let (status, other_case, _) = key(
        "\\REGISTRY\\machine\\SYSTEM\\currentcontrolset\\services\\nktest",
        null,
        false,
    );
    if status != 0 {
        return Err("a key was not found under another letter case");
    }
    // Relative to an open key.
    let (status, services, _) = key(SERVICES, null, false);
    let (relative, by_root, _) = key("NkTest", services, false);
    let (sub, child, disposition) = key("Sub", made, true);
    if (status, relative, sub, disposition) != (0, 0, 0, 1) {
        return Err("a key was not opened or created relative to an open key");
    }
    let (status, by_path, _) = key(&alloc::format!("{path}\\Sub"), null, false);
    if status != 0 {
        return Err("a key created relative to an open key is not where it should be");
    }
    // What is refused.
    let refused = [
        key("\\NkTest", services, false).0, // relative, yet from the top
        key("Registry\\Machine", null, false).0, // no root and not from the top
        key("\\Device", null, false).0,     // elsewhere in the namespace
        key("NkTest", 0x1234 as *mut c_void, false).0,
    ];
    if refused != [0xC000_003B, 0xC000_003B, 0xC000_0024, 0xC000_0008] {
        crate::kd::print(format_args!("cm.keys refused: {refused:x?}\n"));
        return Err("a name that should be refused was not, or with the wrong status");
    }
    for handle in [made, again, other_case, services, by_root, child, by_path] {
        if ZwClose(handle) != 0 {
            return Err("a key handle could not be closed");
        }
    }
    if key("X", made, false).0 != 0xC000_0008 {
        return Err("a closed key handle still names a key");
    }
    Ok(())
}

/// Query `name` into `room` bytes: status, reported length, the bytes.
fn query(handle: *mut c_void, name: &str, class: u32, room: usize) -> (u32, u32, [u8; 32]) {
    let text: Vec<u16> = name.encode_utf16().collect();
    let name = counted(&text);
    let mut out = [0xEEu8; 32];
    let mut length = 0xEEEE_EEEE;
    // SAFETY: locals that outlive the call; `room` is at most 32.
    let status = unsafe {
        ZwQueryValueKey(
            handle,
            &raw const name,
            class,
            out.as_mut_ptr(),
            room as u32,
            &raw mut length,
        )
    };
    (status as u32, length, out)
}

fn set(handle: *mut c_void, name: &str, kind: u32, data: &[u8]) -> u32 {
    let text: Vec<u16> = name.encode_utf16().collect();
    let name = counted(&text);
    // SAFETY: locals that outlive the call.
    (unsafe {
        ZwSetValueKey(
            handle,
            &raw const name,
            0,
            kind,
            data.as_ptr(),
            data.len() as u32,
        )
    }) as u32
}

fn values() -> Result<(), &'static str> {
    let (status, handle, _) = key(
        &alloc::format!("{SERVICES}\\NkValues"),
        core::ptr::null_mut(),
        true,
    );
    if status != 0 {
        return Err("no key to keep values in");
    }
    let result = (|| {
        // No such value: the length is left as it was.
        if query(handle, "Number", 2, 28).0 != NOT_FOUND
            || query(handle, "Number", 2, 28).1 != 0xEEEE_EEEE
        {
            return Err("a value that was never set was found");
        }
        let text = [b'n', 0, b'k', 0, 0, 0];
        if set(handle, "Number", 4, &0x1234_5678u32.to_le_bytes()) != 0
            || set(handle, "Text", 1, &text) != 0
        {
            return Err("a value could not be set");
        }
        // Title index, type, data length, data; under another letter case.
        let (status, length, out) = query(handle, "NUMBER", 2, 28);
        if (status, length) != (0, 16)
            || out[..17]
                != [
                    0, 0, 0, 0, 4, 0, 0, 0, 4, 0, 0, 0, 0x78, 0x56, 0x34, 0x12, 0xEE,
                ]
        {
            return Err("a number did not come back as it was set");
        }
        let (status, length, out) = query(handle, "Text", 2, 28);
        if (status, length) != (0, 18)
            || out[4] != 1
            || out[8] != 6
            || out[12..18] != text
            || out[18] != 0xEE
        {
            return Err("a string did not come back as it was set");
        }
        // Room for the header but not the data; then for neither.
        let (status, length, out) = query(handle, "Text", 2, 12);
        if (status, length) != (0x8000_0005, 18) || out[8] != 6 || out[12] != 0xEE {
            return Err("a buffer with room for the header alone was not told of the overflow");
        }
        let (status, length, out) = query(handle, "Text", 2, 0);
        if (status, length) != (0xC000_0023, 18) || out[0] != 0xEE {
            return Err("a buffer too small for the header was written to, or not told the length");
        }
        // Set again, a value is replaced.
        if set(handle, "number", 4, &0x1234_5679u32.to_le_bytes()) != 0
            || query(handle, "Number", 2, 28).2[12] != 0x79
        {
            return Err("setting a value again did not replace it");
        }
        // The other forms of query are not there; a handle to something
        // else is not a key.
        // The full form: the name as it was set, and where the data is
        // (at the next multiple of eight bytes, as on Windows). Six
        // bytes short of the whole, it holds what fitted and says so.
        let (status, length, out) = query(handle, "TEXT", 1, 32);
        if (status, length) != (0x8000_0005, 38)
            || out[4..20] != [1, 0, 0, 0, 32, 0, 0, 0, 6, 0, 0, 0, 8, 0, 0, 0]
            || out[20..28] != [b'T', 0, b'e', 0, b'x', 0, b't', 0]
            || out[28..32] != [0; 4]
        {
            return Err("the full form of a value is not its name, type and data");
        }
        // Asked with no room, it says how much is needed.
        let sizing = (
            query(handle, "Text", 1, 0).0,
            query(handle, "Text", 1, 0).1,
            query(handle, "Text", 1, 20).0,
        );
        if sizing != (0xC000_0023, 38, 0x8000_0005) {
            return Err("the full form did not say how much room it needs");
        }
        if query(handle, "Number", 0, 28).0 != 0xC000_0002 {
            return Err("an unimplemented form of query did not say so");
        }
        let mut thread = core::ptr::null_mut();
        // SAFETY: the running thread is an object; the handle is closed
        // below.
        unsafe {
            crate::ob::handle::ObOpenObjectByPointer(
                crate::ke::thread::current().cast(),
                0x200,
                core::ptr::null_mut(),
                0,
                core::ptr::null(),
                0,
                &raw mut thread,
            );
        }
        let mismatched = (
            query(thread, "Number", 2, 28).0,
            set(thread, "Number", 4, &[0; 4]),
        );
        ZwClose(thread);
        if mismatched != (0xC000_0024, 0xC000_0024) {
            return Err("a thread handle was taken for a key");
        }
        Ok(())
    })();
    ZwClose(handle);
    result
}

/// A deleted key is gone by name at once; handles still open to it are
/// good only for closing; a key with subkeys is not deleted.
fn delete() -> Result<(), &'static str> {
    let null = core::ptr::null_mut();
    let path = alloc::format!("{SERVICES}\\NkDelete");
    let (_, parent, _) = key(&path, null, true);
    let (_, child, _) = key("Child", parent, true);
    let (_, second, _) = key(&path, null, false);
    let result = (|| {
        if set(parent, "V", 4, &[1, 2, 3, 4]) != 0 {
            return Err("a value could not be set");
        }
        if ZwDeleteKey(parent) as u32 != 0xC000_0121 {
            return Err("a key with a subkey was deleted");
        }
        if ZwDeleteKey(child) != 0 || ZwDeleteKey(parent) != 0 {
            return Err("an empty key could not be deleted");
        }
        if key(&path, null, false).0 != NOT_FOUND {
            return Err("a deleted key can still be opened by name");
        }
        // Through either handle still open to it: refused.
        let refused = [
            ZwDeleteKey(second) as u32,
            set(second, "V", 4, &[0; 4]),
            query(parent, "V", 2, 28).0,
            key("Child", second, true).0,
        ];
        if refused != [0xC000_017C; 4] {
            return Err("a deleted key still answers through an open handle");
        }
        if ZwDeleteKey(0x1234 as *mut c_void) as u32 != 0xC000_0008 {
            return Err("deleting through no handle did not say so");
        }
        Ok(())
    })();
    for handle in [parent, child, second] {
        ZwClose(handle);
    }
    result?;
    // The name is free again, and the new key is empty.
    let (status, again, disposition) = key(&path, null, true);
    let empty = query(again, "V", 2, 28).0 == NOT_FOUND;
    let deleted = ZwDeleteKey(again);
    ZwClose(again);
    if (status, disposition, deleted) != (0, 1, 0) || !empty {
        return Err("a deleted key's name could not be used again for a new, empty key");
    }
    Ok(())
}

/// Create or open the key `name` under `parent` (from the top if that
/// is null), with a class if one is given: the status and the handle.
fn child(parent: *mut c_void, name: &str, class: Option<&str>) -> (u32, *mut c_void) {
    let text: Vec<u16> = name.encode_utf16().collect();
    let name = counted(&text);
    let class: Option<Vec<u16>> = class.map(|class| class.encode_utf16().collect());
    let class = class.as_deref().map(counted);
    let attributes = OBJECT_ATTRIBUTES {
        Length: size_of::<OBJECT_ATTRIBUTES>() as u32,
        RootDirectory: parent,
        ObjectName: &raw const name,
        Attributes: 0x240,
        SecurityDescriptor: core::ptr::null_mut(),
        SecurityQualityOfService: core::ptr::null_mut(),
    };
    let mut handle = core::ptr::null_mut();
    // SAFETY: locals that outlive the call.
    let status = unsafe {
        ZwCreateKey(
            &raw mut handle,
            0xF003F,
            &raw const attributes,
            0,
            class
                .as_ref()
                .map_or(core::ptr::null(), core::ptr::from_ref),
            0,
            core::ptr::null_mut(),
        )
    };
    (status as u32, handle)
}

/// The key the enumeration and query tests work on, made as the
/// conformance driver `nkc-reg` makes its own, so that the numbers
/// here are the ones its source predicts:
///
/// ```text
/// NkcTest, class "Cls"
///   values, in the order set: Number (REG_DWORD 0x12345678), Text
///     (REG_SZ "nk"), Odd (REG_BINARY, 3 bytes), the unnamed value
///     (REG_SZ "d"), Multi (REG_MULTI_SZ "a", "bc")
///   subkeys, in the order created: Beta (class "BC"; one value, Val,
///     REG_BINARY of 5 bytes; one subkey, Sub), alpha, Gamma9
/// ```
fn build() -> Result<*mut c_void, &'static str> {
    let (status, key) = child(
        core::ptr::null_mut(),
        &alloc::format!("{SERVICES}\\NkcTest"),
        Some("Cls"),
    );
    if status != 0 {
        return Err("the key to describe could not be made");
    }
    let number = 0x1234_5678u32.to_le_bytes();
    let (beta, sub) = {
        let (made, beta) = child(key, "Beta", Some("BC"));
        let (deeper, sub) = child(beta, "Sub", None);
        ZwClose(sub);
        (beta, made | deeper)
    };
    let made = [
        set(key, "Number", 4, &number),
        set(key, "Text", 1, &utf16("nk\0")),
        set(key, "Odd", 3, &number[..3]),
        set(key, "", 1, &utf16("d\0")),
        set(key, "Multi", 7, &utf16("a\0bc\0\0")),
        sub,
        set(beta, "Val", 3, &[1, 2, 3, 4, 5]),
        ZwClose(beta) as u32,
    ];
    for name in ["alpha", "Gamma9"] {
        let (status, handle) = child(key, name, None);
        ZwClose(handle);
        if status != 0 {
            return Err("a subkey to describe could not be made");
        }
    }
    if made != [0; 8] {
        return Err("the values and subkeys to describe could not be made");
    }
    Ok(key)
}

/// Delete the subkey `name` of `parent`, which has no subkeys.
fn remove(parent: *mut c_void, name: &str) -> bool {
    let (status, handle) = child(parent, name, None);
    let deleted = ZwDeleteKey(handle);
    ZwClose(handle);
    (status, deleted) == (0, 0)
}

/// Run `test` on the key [`build`] makes, and delete the key.
fn with_key(
    test: impl FnOnce(*mut c_void) -> Result<(), &'static str>,
) -> Result<(), &'static str> {
    let key = build()?;
    let result = test(key);
    let (_, beta) = child(key, "Beta", None);
    let mut gone = remove(beta, "Sub");
    ZwClose(beta);
    for name in ["Beta", "alpha", "Gamma9"] {
        gone &= remove(key, name);
    }
    gone &= ZwDeleteKey(key) == 0;
    ZwClose(key);
    result?;
    if !gone {
        return Err("the key that was described could not be deleted again");
    }
    Ok(())
}

/// How many bytes an answer may have.
const ROOM: usize = 192;
/// What nothing wrote: the buffer's bytes and the length reported.
const UNTOUCHED: u8 = 0xEE;
const NO_LENGTH: u32 = 0xEEEE_EEEE;
const TOO_SMALL: u32 = 0xC000_0023;
const OVERFLOW: u32 = 0x8000_0005;
const NO_MORE: u32 = 0x8000_001A;
const INVALID_PARAMETER: u32 = 0xC000_000D;

/// What a query answered into a buffer of [`UNTOUCHED`] bytes: its
/// status, the length it reported, the buffer.
struct Answer {
    status: u32,
    length: u32,
    bytes: [u8; ROOM],
}

/// Make the query `ask`, giving it a buffer, how many bytes of it to
/// use, and where to report the length.
fn answer(room: usize, ask: impl FnOnce(*mut u8, u32, *mut u32) -> i32) -> Answer {
    let mut bytes = [UNTOUCHED; ROOM];
    let mut length = NO_LENGTH;
    let status = ask(bytes.as_mut_ptr(), room.min(ROOM) as u32, &raw mut length) as u32;
    Answer {
        status,
        length,
        bytes,
    }
}

impl Answer {
    /// Whether the query failed with `status` and touched nothing.
    fn refused(&self, status: u32) -> bool {
        (self.status, self.length) == (status, NO_LENGTH) && self.bytes == [UNTOUCHED; ROOM]
    }

    /// Whether, with `room` bytes to use, the query answered as it must
    /// for a structure that is `whole` when all of it fits and whose
    /// fixed part is `fixed` bytes: the status for how much fitted, the
    /// whole length reported, as much of the structure as there was
    /// room for unless not even the fixed part fitted, and not a byte
    /// more. `whole` has [`UNTOUCHED`] where the structure leaves bytes
    /// alone. The first `skip` bytes are a time, which is not compared.
    fn is(&self, room: usize, whole: &[u8], fixed: usize, skip: usize) -> bool {
        let (status, written) = match room {
            _ if room < fixed => (TOO_SMALL, 0),
            _ if room < whole.len() => (OVERFLOW, room),
            _ => (0, whole.len()),
        };
        (self.status, self.length) == (status, whole.len() as u32)
            && (written <= skip || self.bytes[skip..written] == whole[skip..written])
            && self.bytes[written..].iter().all(|&byte| byte == UNTOUCHED)
    }
}

/// Whether the query `ask(room)` answers as it must ([`Answer::is`])
/// with room for none of the structure, for a byte less than its fixed
/// part, for the fixed part alone, for a byte less than all of it, for
/// all, and for more.
fn at_every_room(whole: &[u8], fixed: usize, skip: usize, ask: impl Fn(usize) -> Answer) -> bool {
    let all = whole.len();
    [0, fixed - 1, fixed, all - 1, all, all + 8]
        .into_iter()
        .all(|room| ask(room).is(room, whole, fixed, skip))
}

/// 32-bit fields as bytes.
fn fields(fields: &[u32]) -> Vec<u8> {
    fields
        .iter()
        .flat_map(|field| field.to_le_bytes())
        .collect()
}

/// The parts of a structure, one after another.
fn joined(parts: &[&[u8]]) -> Vec<u8> {
    parts.concat()
}

/// Sizes of the fixed parts of the key and value structures.
const KEY_BASIC: usize = 16;
const KEY_NODE: usize = 24;
const KEY_FULL: usize = 44;
const VALUE_BASIC: usize = 12;
const VALUE_FULL: usize = 20;
const VALUE_PARTIAL: usize = 12;
const VALUE_PARTIAL_ALIGN64: usize = 8;
/// A last write time, where a structure starts with one.
const TIME: [u8; 8] = [0; 8];

fn enumerate_key(key: *mut c_void, index: u32, class: u32, room: usize) -> Answer {
    // SAFETY: the buffer is `ROOM` bytes and the room no more.
    answer(room, |out, room, length| unsafe {
        ZwEnumerateKey(key, index, class, out, room, length)
    })
}

/// Subkeys come by index in the order of their names, letter case
/// disregarded, in the basic, node and full forms, each with Windows'
/// status and length for a buffer of any size.
fn enumerate_keys(key: *mut c_void) -> Result<(), &'static str> {
    // Created as Beta, alpha, Gamma9.
    for (index, name) in ["alpha", "Beta", "Gamma9"].into_iter().enumerate() {
        let name = utf16(name);
        let whole = joined(&[&TIME, &fields(&[0, name.len() as u32]), &name]);
        let ask = |room| enumerate_key(key, index as u32, 0, room);
        if !at_every_room(&whole, KEY_BASIC, 8, ask) {
            return Err("a subkey's basic form is not its name, in the order of the names");
        }
    }
    // The class follows the name; a key without one says so.
    let beta = joined(&[&TIME, &fields(&[0, 32, 4, 8]), &utf16("BetaBC")]);
    let alpha = joined(&[&TIME, &fields(&[0, u32::MAX, 0, 10]), &utf16("alpha")]);
    if !at_every_room(&beta, KEY_NODE, 8, |room| enumerate_key(key, 1, 1, room))
        || !at_every_room(&alpha, KEY_NODE, 8, |room| enumerate_key(key, 0, 1, room))
    {
        return Err("a subkey's node form is not its name and class");
    }
    // Beta: one subkey (Sub), one value (Val, of five bytes).
    let beta = joined(&[&TIME, &fields(&[0, 44, 4, 1, 6, 0, 1, 6, 5]), &utf16("BC")]);
    let gamma = joined(&[&TIME, &fields(&[0, u32::MAX, 0, 0, 0, 0, 0, 0, 0])]);
    if !at_every_room(&beta, KEY_FULL, 8, |room| enumerate_key(key, 1, 2, room))
        || !at_every_room(&gamma, KEY_FULL, 8, |room| enumerate_key(key, 2, 2, room))
    {
        return Err("a subkey's full form does not count what it holds");
    }
    // Past the last: whatever the room. The forms that describe only
    // an open key: not a subkey, whether or not there is one.
    for (index, class, room, status) in [
        (3, 0, ROOM, NO_MORE),
        (3, 0, 0, NO_MORE),
        (u32::MAX, 2, ROOM, NO_MORE),
        (0, 3, ROOM, INVALID_PARAMETER),
        (0, 4, ROOM, INVALID_PARAMETER),
        (3, 9, ROOM, INVALID_PARAMETER),
    ] {
        if !enumerate_key(key, index, class, room).refused(status) {
            return Err(
                "a subkey that is not there, or a form that is not a subkey's, was answered",
            );
        }
    }
    // Not a key's handle; a key that has been deleted.
    let (_, gone) = child(key, "Gone", None);
    let refused = [
        enumerate_key(0x1234 as *mut c_void, 0, 0, ROOM).refused(0xC000_0008),
        ZwDeleteKey(gone) == 0,
        enumerate_key(gone, 0, 0, ROOM).refused(0xC000_017C),
        ZwClose(gone) == 0,
    ];
    if refused != [true; 4] {
        return Err("subkeys were enumerated through no handle, or of a deleted key");
    }
    Ok(())
}

fn enumerate_value(key: *mut c_void, index: u32, class: u32, room: usize) -> Answer {
    // SAFETY: the buffer is `ROOM` bytes and the room no more.
    answer(room, |out, room, length| unsafe {
        ZwEnumerateValueKey(key, index, class, out, room, length)
    })
}

/// The values of [`build`]'s key in each form, as (index, class, fixed
/// part, the whole structure): what `ZwEnumerateValueKey` answers by
/// index and `ZwQueryValueKey` by name.
fn value_forms() -> Vec<(u32, u32, usize, Vec<u8>)> {
    let gap = |bytes: usize| alloc::vec![UNTOUCHED; bytes];
    let number = 0x1234_5678u32.to_le_bytes();
    let basic = |index, kind, name: &str| {
        let name = utf16(name);
        let whole = joined(&[&fields(&[0, kind, name.len() as u32]), &name]);
        (index, 0, VALUE_BASIC, whole)
    };
    alloc::vec![
        // In the order they were first set.
        basic(0, 4, "Number"),
        basic(1, 1, "Text"),
        basic(2, 3, "Odd"),
        basic(3, 1, ""),
        basic(4, 7, "Multi"),
        // The data of the full forms start at a multiple of eight; the
        // bytes between name and data are left alone.
        (
            0,
            1,
            VALUE_FULL,
            joined(&[&fields(&[0, 4, 32, 4, 12]), &utf16("Number"), &number]),
        ),
        (
            1,
            1,
            VALUE_FULL,
            joined(&[
                &fields(&[0, 1, 32, 6, 8]),
                &utf16("Text"),
                &gap(4),
                &utf16("nk\0"),
            ]),
        ),
        (
            3,
            1,
            VALUE_FULL,
            joined(&[&fields(&[0, 1, 24, 4, 0]), &gap(4), &utf16("d\0")]),
        ),
        (
            2,
            2,
            VALUE_PARTIAL,
            joined(&[&fields(&[0, 3, 3]), &number[..3]]),
        ),
        (
            4,
            2,
            VALUE_PARTIAL,
            joined(&[&fields(&[0, 7, 12]), &utf16("a\0bc\0\0")]),
        ),
        (
            2,
            3,
            VALUE_FULL,
            joined(&[
                &fields(&[0, 3, 32, 3, 6]),
                &utf16("Odd"),
                &gap(6),
                &number[..3],
            ]),
        ),
        // No title index in this one.
        (
            1,
            4,
            VALUE_PARTIAL_ALIGN64,
            joined(&[&fields(&[1, 6]), &utf16("nk\0")]),
        ),
        (
            0,
            4,
            VALUE_PARTIAL_ALIGN64,
            joined(&[&fields(&[4, 4]), &number]),
        ),
    ]
}

/// Values come by index in the order they were first set, in every
/// form, each with Windows' status and length for a buffer of any size.
fn enumerate_values(key: *mut c_void) -> Result<(), &'static str> {
    for (index, class, fixed, whole) in value_forms() {
        let ask = |room| enumerate_value(key, index, class, room);
        if !at_every_room(&whole, fixed, 0, ask) {
            crate::kd::print(format_args!(
                "cm.enumerate.values: value {index}, class {class}\n"
            ));
            return Err("a value was not described as Windows describes it");
        }
    }
    // Past the last: whatever the room. The form of a layered key's
    // value, and a form there is none of.
    for (index, class, room, status) in [
        (5, 0, ROOM, NO_MORE),
        (5, 1, 0, NO_MORE),
        (u32::MAX, 2, ROOM, NO_MORE),
        (0, 5, ROOM, INVALID_PARAMETER),
        (0, 6, ROOM, INVALID_PARAMETER),
        (5, 6, ROOM, INVALID_PARAMETER),
    ] {
        if !enumerate_value(key, index, class, room).refused(status) {
            return Err("a value that is not there, or a form there is none of, was answered");
        }
    }
    let (_, gone) = child(key, "Gone", None);
    let refused = [
        enumerate_value(0x1234 as *mut c_void, 0, 0, ROOM).refused(0xC000_0008),
        ZwDeleteKey(gone) == 0,
        enumerate_value(gone, 0, 0, ROOM).refused(0xC000_017C),
        ZwClose(gone) == 0,
    ];
    if refused != [true; 4] {
        return Err("values were enumerated through no handle, or of a deleted key");
    }
    Ok(())
}

/// A registry name is a path in the object namespace: it is looked up
/// there, through symbolic links and from a directory if one is given,
/// and must lead to the registry's root key, which walks the rest.
fn namespace() -> Result<(), &'static str> {
    use crate::io::file::{self, OpenRequest};
    use crate::ob::{self, handle, object};
    let wide = |text: &str| text.encode_utf16().collect::<Vec<u16>>();
    let null = core::ptr::null_mut();
    // The root key is an object called `\Registry`; a path below it
    // stops there with the rest left over.
    let (root, rest) = ob::lookup(None, &wide("\\REGISTRY\\Machine\\System"))
        .map_err(|_| "\\Registry is not in the namespace")?;
    // SAFETY: the look-up's reference, given up after the type is read.
    let is_key = unsafe {
        let is_key = core::ptr::eq(object::type_of(root), &raw const object::KEY_TYPE);
        object::dereference(root);
        is_key
    };
    if !is_key || rest != wide("\\Machine\\System") {
        return Err("\\Registry is not a key object that is handed the rest of the path");
    }
    // A handle to the namespace's root directory, to start from.
    let (directory, _) = ob::lookup(None, &wide("\\")).map_err(|_| "no root directory")?;
    // SAFETY: the look-up's reference, handed to the handle.
    let directory = unsafe {
        let opened = handle::open(directory, 0).unwrap_or(0);
        object::dereference(directory);
        opened as *mut c_void
    };
    let made = ob::insert_link(&wide("\\??\\NkRegistry"), &wide("\\Registry\\Machine"));
    let result = (|| {
        if made != 0 {
            return Err("a symbolic link to a key could not be made");
        }
        let (direct, system, _) = key("\\Registry\\Machine\\System", null, false);
        let (linked, by_link, _) = key("\\DosDevices\\nkregistry\\SYSTEM", null, false);
        let (below, by_directory, _) = key("Registry\\Machine\\System", directory, false);
        // A key made by one path is found by the others.
        let (created, new, disposition) = key("\\??\\NkRegistry\\System\\NkNamespace", null, true);
        let (found, same, _) = key("NkNamespace", system, false);
        let deleted = ZwDeleteKey(new);
        for handle in [system, by_link, by_directory, new, same] {
            ZwClose(handle);
        }
        if (direct, linked, below) != (0, 0, 0) {
            return Err("a key was not opened through the namespace by every path to it");
        }
        if (created, disposition, found, deleted) != (0, 1, 0, 0) {
            return Err("a key made through a symbolic link is not where the link leads");
        }
        let refused = [
            (key("\\Registry\\Machine\\NkNone", null, false).0, NOT_FOUND),
            (key("\\NkNoDirectory\\Machine", null, false).0, 0xC000_003A),
            (key("\\??\\NkNoLink\\System", null, false).0, 0xC000_003A),
            (key("\\Device", null, false).0, 0xC000_0024),
            (key("\\", null, false).0, 0xC000_0024),
            (key("Device", directory, false).0, 0xC000_0024),
            (key("\\Registry", directory, false).0, 0xC000_003B),
        ];
        if refused.iter().any(|(status, expected)| status != expected) {
            return Err("a name that leads to no key was not refused with its own status");
        }
        // A key is no file, by its name or as the root of one.
        let (machine, opened, _) = key("\\Registry\\Machine", null, false);
        let by_name = file::open(&OpenRequest::new("\\Registry\\Machine"));
        let relative = file::open(&OpenRequest {
            root: Some(opened as u64),
            ..OpenRequest::new("System")
        });
        ZwClose(opened);
        let mismatch = Err(0xC000_0024u32 as i32);
        if machine != 0 || by_name != mismatch || relative != mismatch {
            return Err("a key was opened as a file");
        }
        Ok(())
    })();
    ob::remove_link(&wide("\\??\\NkRegistry"));
    ZwClose(directory);
    result
}

const SYSTEM: &str = "\\Registry\\Machine\\System";
const NK_TEST: &str = "\\Registry\\Machine\\System\\CurrentControlSet\\Control\\NkTest";

/// The type and data of the value `name` of the key `path`, whatever
/// its size; the status if the key or the value is not there.
fn value_of(path: &str, name: &str) -> Result<(u32, Vec<u8>), u32> {
    let (status, handle, _) = key(path, core::ptr::null_mut(), false);
    if status != 0 {
        return Err(status);
    }
    let text: Vec<u16> = name.encode_utf16().collect();
    let name = counted(&text);
    let mut needed = 0u32;
    // SAFETY: locals that outlive the calls; the buffer is as long as
    // the call is told.
    let read = unsafe {
        ZwQueryValueKey(
            handle,
            &raw const name,
            2,
            core::ptr::null_mut(),
            0,
            &raw mut needed,
        );
        let mut out = alloc::vec![0u8; needed as usize];
        let status = ZwQueryValueKey(
            handle,
            &raw const name,
            2,
            out.as_mut_ptr(),
            needed,
            &raw mut needed,
        );
        (status as u32, out)
    };
    ZwClose(handle);
    match read {
        (0, out) if out.len() >= 12 => Ok((
            u32::from_le_bytes([out[4], out[5], out[6], out[7]]),
            out[12..].to_vec(),
        )),
        (0, _) => Err(0xC000_0001),
        (status, _) => Err(status),
    }
}

fn utf16(text: &str) -> Vec<u8> {
    text.encode_utf16().flat_map(u16::to_le_bytes).collect()
}

/// `CurrentControlSet` is the control set `Select` names, by a
/// symbolic link: what is made through one name is there through the
/// other. The keys every system has are there, hive or no hive.
fn control_set() -> Result<(), &'static str> {
    let null = core::ptr::null_mut();
    let Ok((4, current)) = value_of(&alloc::format!("{SYSTEM}\\Select"), "Current") else {
        return Err("Select\\Current is not a number");
    };
    let control = alloc::format!("{SYSTEM}\\ControlSet{:03}", current[0]);
    for path in [
        "\\Registry\\Machine\\Hardware",
        "\\Registry\\User",
        &alloc::format!("{SYSTEM}\\CurrentControlSet"),
        &alloc::format!("{SYSTEM}\\CurrentControlSet\\Control\\Class"),
        &alloc::format!("{control}\\Services"),
    ] {
        let (status, handle, _) = key(path, null, false);
        ZwClose(handle);
        if status != 0 {
            return Err("a key every system has is not there");
        }
    }
    // Made through the link, found in the control set; and back.
    let (made, by_link, disposition) = key(&alloc::format!("{SERVICES}\\NkLink"), null, true);
    let (found, by_set, _) = key(&alloc::format!("{control}\\Services\\NkLink"), null, false);
    let written = set(by_set, "Through", 4, &7u32.to_le_bytes());
    let read = query(by_link, "Through", 2, 28);
    let deleted = ZwDeleteKey(by_set);
    let gone = key(&alloc::format!("{SERVICES}\\NkLink"), null, false).0;
    for handle in [by_link, by_set] {
        ZwClose(handle);
    }
    if (made, disposition, found) != (0, 1, 0) {
        return Err("a key made through CurrentControlSet is not in the control set");
    }
    if written != 0 || (read.0, read.2[12]) != (0, 7) {
        return Err("a value set in the control set is not there through CurrentControlSet");
    }
    if deleted != 0 || gone != NOT_FOUND {
        return Err("a key deleted in the control set is still there through CurrentControlSet");
    }
    Ok(())
}

/// What only the hive holds is in the registry, read as drivers read
/// it, through `CurrentControlSet`: values of every size, keys nested
/// deep and in great number.
fn hive_values() -> Result<(), &'static str> {
    let counter = |n: usize| -> Vec<u8> { (0u32..).flat_map(u32::to_le_bytes).take(n).collect() };
    let expected: [(&str, &str, u32, Vec<u8>); 9] = [
        ("Types", "Dword", 4, 0x1234_5678u32.to_le_bytes().to_vec()),
        ("Types", "Multi", 7, utf16("one\0two\0three and four\0\0")),
        ("Types", "None", 0, Vec::new()),
        ("Sizes", "Size4", 3, alloc::vec![0xA1, 0xA2, 0xA3, 0xA4]),
        (
            "Sizes",
            "Size5",
            3,
            alloc::vec![0xA1, 0xA2, 0xA3, 0xA4, 0xA5],
        ),
        ("Sizes", "Size16345", 3, counter(16345)),
        ("Sizes", "Size40000", 3, counter(40000)),
        ("", "", 1, utf16("the unnamed value\0")),
        ("Deep\\1\\2\\3\\4\\5\\6\\7\\8", "Bottom", 1, utf16("here\0")),
    ];
    for (below, name, kind, data) in expected {
        if value_of(&alloc::format!("{NK_TEST}\\{below}"), name) != Ok((kind, data)) {
            crate::kd::print(format_args!("cm.hive.values: {below} {name}\n"));
            return Err("a value of the hive is not in the registry as the hive has it");
        }
    }
    let services = value_of(&alloc::format!("{SERVICES}\\Npfs"), "Group");
    if services != Ok((1, utf16("File System\0"))) {
        return Err("a service key of the hive is not under CurrentControlSet\\Services");
    }
    let last = key(
        &alloc::format!("{NK_TEST}\\Many\\Key1199"),
        core::ptr::null_mut(),
        false,
    );
    let past = key(
        &alloc::format!("{NK_TEST}\\Many\\Key1200"),
        core::ptr::null_mut(),
        false,
    );
    ZwClose(last.1);
    if (last.0, past.0) != (0, NOT_FOUND) {
        return Err("the hive's many subkeys of one key are not all there, or too many");
    }
    Ok(())
}

/// Names outside ASCII are found, in whatever letter case: Latin-1,
/// Greek, and characters that have no case.
fn hive_names() -> Result<(), &'static str> {
    let names = alloc::format!("{NK_TEST}\\Names");
    for (name, number) in [
        ("CAF\u{c9}", 3u32),
        ("caf\u{e9}", 3),
        ("\u{391}\u{392}\u{393}", 4),
        ("\u{3b1}\u{3b2}\u{3b3}", 4),
        ("\u{65e5}\u{672c}\u{8a9e}", 5),
    ] {
        if value_of(&names, name) != Ok((4, number.to_le_bytes().to_vec())) {
            return Err("a value with a name outside ASCII was not found");
        }
        let (status, handle, _) = key(
            &alloc::format!("{names}\\{name}"),
            core::ptr::null_mut(),
            false,
        );
        ZwClose(handle);
        if status != 0 {
            return Err("a key with a name outside ASCII was not found");
        }
    }
    if value_of(&names, "\u{1f600}") != Ok((4, 6u32.to_le_bytes().to_vec())) {
        return Err("a value named by a surrogate pair was not found");
    }
    Ok(())
}

fn run(r: &mut Report, _: &BootInfo) {
    r.check("cm.keys", keys);
    r.check("cm.values", values);
    r.check("cm.delete", delete);
    r.check("cm.enumerate.keys", || with_key(enumerate_keys));
    r.check("cm.enumerate.values", || with_key(enumerate_values));
    r.check("cm.namespace", namespace);
    r.check("cm.control-set", control_set);
    let Some(hive) = crate::ldr::boot_file(nk_bootinfo::HIVE_MODULE) else {
        return r.skip_rest(format_args!("no SYSTEM hive provided"));
    };
    r.check("cm.hive.values", hive_values);
    r.check("cm.hive.names", hive_names);
    r.check("cm.hive.refused", || crate::cm::refused_test(hive));
}
