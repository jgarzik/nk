//! Tests of the registry, through the routines drivers call.

use super::{except, resources};
use crate::cm::{
    RtlQueryRegistryValues, RtlQueryRegistryValuesEx, ZwCreateKey, ZwDeleteKey, ZwDeleteValueKey,
    ZwEnumerateKey, ZwEnumerateValueKey, ZwOpenKey, ZwQueryKey, ZwQueryValueKey, ZwSetValueKey,
};
use crate::ps::ZwClose;
use crate::test::{Group, Report};
use alloc::vec::Vec;
use core::ffi::c_void;
use core::sync::atomic::{AtomicU32, AtomicUsize, Ordering};
use nk_bootinfo::BootInfo;
use nk_ntabi::cm::RTL_QUERY_REGISTRY_TABLE;
use nk_ntabi::io::UNICODE_STRING;
use nk_ntabi::ob::OBJECT_ATTRIBUTES;

pub static GROUP: Group = Group {
    names: &[
        "cm.keys",
        "cm.values",
        "cm.delete",
        "cm.delete.value",
        "cm.enumerate.keys",
        "cm.enumerate.values",
        "cm.query.key",
        "cm.query.value",
        "cm.table.direct",
        "cm.table.routine",
        "cm.table.roots",
        "cm.table.raise",
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
        // The full form: the name as it was set, and where the data is
        // (at the next multiple of eight bytes, as on Windows), the
        // bytes between left alone. Six bytes short of the whole, it
        // holds what fitted and says so.
        let (status, length, out) = query(handle, "TEXT", 1, 32);
        if (status, length) != (0x8000_0005, 38)
            || out[4..20] != [1, 0, 0, 0, 32, 0, 0, 0, 6, 0, 0, 0, 8, 0, 0, 0]
            || out[20..28] != [b'T', 0, b'e', 0, b'x', 0, b't', 0]
            || out[28..32] != [0xEE; 4]
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
        // A form there is none of; a handle to something else is not a
        // key.
        if query(handle, "Number", 6, 28).0 != 0xC000_000D {
            return Err("a form of query there is none of did not say so");
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

fn delete_named(key: *mut c_void, name: &str) -> u32 {
    let text: Vec<u16> = name.encode_utf16().collect();
    let name = counted(&text);
    // SAFETY: a local that outlives the call.
    (unsafe { ZwDeleteValueKey(key, &raw const name) }) as u32
}

/// A deleted value is gone under any spelling of its name, the values
/// after it move up, and set again it is the last. The longest name
/// and data the key reports stay what they were until its last value
/// goes, as on Windows.
fn delete_value(key: *mut c_void) -> Result<(), &'static str> {
    let basic = |index, kind, name: &str| {
        let name = utf16(name);
        let whole = joined(&[&fields(&[0, kind, name.len() as u32]), &name]);
        enumerate_value(key, index, 0, ROOM).is(ROOM, &whole, VALUE_BASIC, 0)
    };
    // Values, the longest name, the longest data, the key's own name.
    let counts = |values, name, data| {
        let whole = joined(&[&TIME, &fields(&[0, 3, 12, values, name, data, 14])]);
        query_key_info(key, 4, ROOM).is(ROOM, &whole, 36, 8)
    };
    let deleted = [
        delete_named(key, "NUMBER"),
        delete_named(key, "NUMBER"),
        delete_named(key, "Absent"),
    ];
    if deleted != [0, NOT_FOUND, NOT_FOUND] {
        return Err("a value was not deleted once, by a name in other letter case");
    }
    if query_value_info(key, "Number", 0, ROOM).status != NOT_FOUND || !basic(0, 1, "Text") {
        return Err("a deleted value is still there, or the next did not take its place");
    }
    // Number had the longest name, and is gone: the number stays.
    if !counts(4, 12, 12) {
        return Err("the key does not count four values, with the longest name it has held");
    }
    let number = 0x1234_5678u32.to_le_bytes();
    if (delete_named(key, "Odd"), set(key, "Odd", 3, &number[..3])) != (0, 0)
        || !basic(3, 3, "Odd")
        || !basic(1, 1, "")
    {
        return Err("a value deleted and set again is not the key's last");
    }
    // The unnamed value is deleted by the empty name; with the last
    // value gone the key counts from nothing again.
    let emptied = ["", "Text", "multi", "odd"].map(|name| delete_named(key, name));
    if emptied != [0; 4] || !enumerate_value(key, 0, 0, ROOM).refused(NO_MORE) || !counts(0, 0, 0) {
        return Err("a key whose values were all deleted still has, or counts, some");
    }
    if set(key, "ab", 3, &number) != 0 || !counts(1, 4, 4) {
        return Err("a key that lost all its values does not count its next from nothing");
    }
    let (_, gone) = child(key, "Gone", None);
    let refused = [
        delete_named(0x1234 as *mut c_void, "ab"),
        ZwDeleteKey(gone) as u32,
        delete_named(gone, "ab"),
        ZwClose(gone) as u32,
        delete_named(key, "ab"),
    ];
    if refused != [0xC000_0008, 0, 0xC000_017C, 0, 0] {
        return Err("a value was deleted through no handle, or from a deleted key");
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

fn query_key_info(key: *mut c_void, class: u32, room: usize) -> Answer {
    // SAFETY: the buffer is `ROOM` bytes and the room no more.
    answer(room, |out, room, length| unsafe {
        ZwQueryKey(key, class, out, room, length)
    })
}

/// A key's full name as `KEY_NAME_INFORMATION` has it.
fn name_form(path: &str) -> Vec<u8> {
    let path = utf16(path);
    joined(&[&fields(&[path.len() as u32]), &path])
}

/// An open key is described in every form, each with Windows' status
/// and length for a buffer of any size.
fn query_key(key: *mut c_void) -> Result<(), &'static str> {
    let gap = [UNTOUCHED; 2];
    let name = utf16("NkcTest");
    // (class, fixed part, bytes of time at the start, the structure)
    let forms: [(u32, usize, usize, Vec<u8>); 10] = [
        (0, KEY_BASIC, 8, joined(&[&TIME, &fields(&[0, 14]), &name])),
        // The class starts at the next multiple of four after the name.
        (
            1,
            KEY_NODE,
            8,
            joined(&[&TIME, &fields(&[0, 40, 6, 14]), &name, &gap, &utf16("Cls")]),
        ),
        // Three subkeys, the longest name Gamma9, the longest class BC;
        // five values, the longest name Number, the longest data Multi's.
        (
            2,
            KEY_FULL,
            8,
            joined(&[
                &TIME,
                &fields(&[0, 44, 6, 3, 12, 4, 5, 12, 12]),
                &utf16("Cls"),
            ]),
        ),
        // The link CurrentControlSet is followed; each part is spelled
        // as it was created.
        (
            3,
            4,
            0,
            name_form("\\REGISTRY\\MACHINE\\SYSTEM\\ControlSet001\\Services\\NkcTest"),
        ),
        // The counts again, and the length of the name without the name.
        (
            4,
            36,
            8,
            joined(&[&TIME, &fields(&[0, 3, 12, 5, 12, 12, 14])]),
        ),
        // Flags, virtualization, handle tags: none. Trusted. No layer.
        (5, 12, 0, fields(&[0, 0, 0])),
        (6, 4, 0, fields(&[0])),
        (7, 4, 0, fields(&[0])),
        (8, 4, 0, fields(&[1])),
        (9, 4, 0, fields(&[0])),
    ];
    for (class, fixed, skip, whole) in forms {
        if !at_every_room(&whole, fixed, skip, |room| query_key_info(key, class, room)) {
            crate::kd::print(format_args!("cm.query.key: class {class}\n"));
            return Err("an open key was not described as Windows describes it");
        }
    }
    if !query_key_info(key, 10, ROOM).refused(INVALID_PARAMETER) {
        return Err("a form there is none of was answered");
    }
    // The registry's own root, and a key of the hive or the skeleton
    // opened in other letter case than it was made in.
    let (_, root, _) = self::key("\\Registry", core::ptr::null_mut(), false);
    let (_, system, _) = self::key("\\registry\\machine\\system", core::ptr::null_mut(), false);
    let named = [
        query_key_info(root, 3, ROOM).is(ROOM, &name_form("\\REGISTRY"), 4, 0),
        query_key_info(system, 3, ROOM).is(ROOM, &name_form("\\REGISTRY\\MACHINE\\SYSTEM"), 4, 0),
        ZwClose(root) == 0,
        ZwClose(system) == 0,
    ];
    if named != [true; 4] {
        return Err("a key Windows has from the start is not named as Windows names it");
    }
    let (_, gone) = child(key, "Gone", None);
    let refused = [
        query_key_info(0x1234 as *mut c_void, 0, ROOM).refused(0xC000_0008),
        ZwDeleteKey(gone) == 0,
        query_key_info(gone, 3, ROOM).refused(0xC000_017C),
        query_key_info(gone, 8, ROOM).refused(0xC000_017C),
        ZwClose(gone) == 0,
    ];
    if refused != [true; 5] {
        return Err("a key was described through no handle, or after it was deleted");
    }
    Ok(())
}

fn query_value_info(key: *mut c_void, name: &str, class: u32, room: usize) -> Answer {
    let text: Vec<u16> = name.encode_utf16().collect();
    let name = counted(&text);
    // SAFETY: the buffer is `ROOM` bytes and the room no more; the name
    // outlives the call.
    answer(room, |out, room, length| unsafe {
        ZwQueryValueKey(key, &raw const name, class, out, room, length)
    })
}

/// A value is described by name in every form it is described in by
/// index: found whatever the letter case of the name asked for, and
/// named as it was set.
fn query_value(key: *mut c_void) -> Result<(), &'static str> {
    let names = ["NUMBER", "text", "ODD", "", "mULTI"];
    for (index, class, fixed, whole) in value_forms() {
        let name = names[index as usize];
        let ask = |room| query_value_info(key, name, class, room);
        if !at_every_room(&whole, fixed, 0, ask) {
            crate::kd::print(format_args!("cm.query.value: {name}, class {class}\n"));
            return Err("a value was not described by name as Windows describes it");
        }
    }
    // The form of a layered key's value and a form there is none of,
    // whether or not the value is there; a value that is not.
    for (name, class, status) in [
        ("Text", 5, INVALID_PARAMETER),
        ("Text", 6, INVALID_PARAMETER),
        ("Absent", 6, INVALID_PARAMETER),
        ("Absent", 0, NOT_FOUND),
        ("Absent", 4, NOT_FOUND),
    ] {
        if !query_value_info(key, name, class, ROOM).refused(status) {
            return Err("a value that is not there, or a form there is none of, was answered");
        }
    }
    Ok(())
}

// ---- query tables -------------------------------------------------------

/// `RTL_QUERY_REGISTRY_*` flags.
const SUBKEY: u32 = 0x01;
const TOPKEY: u32 = 0x02;
const REQUIRED: u32 = 0x04;
const NOVALUE: u32 = 0x08;
const NOEXPAND: u32 = 0x10;
const DIRECT: u32 = 0x20;
const DELETE: u32 = 0x40;
const TYPECHECK: u32 = 0x100;
/// Value types.
const REG_SZ: u32 = 1;
const REG_EXPAND_SZ: u32 = 2;
const REG_BINARY: u32 = 3;
const REG_DWORD: u32 = 4;
const REG_MULTI_SZ: u32 = 7;
const REG_QWORD: u32 = 11;
const TYPE_MISMATCH: u32 = 0xC000_0024;
const UNSUCCESSFUL: u32 = 0xC000_0001;

/// The two exports, which answer alike.
const EXPORTS: [Export; 2] = [RtlQueryRegistryValues, RtlQueryRegistryValuesEx];
type Export = unsafe extern "C" fn(
    u32,
    *const u16,
    *const RTL_QUERY_REGISTRY_TABLE,
    *mut c_void,
    *const u16,
) -> i32;

/// The full name of the key [`build`] makes, and that key from
/// `Services`.
const TABLE_KEY: &str = "\\Registry\\Machine\\System\\CurrentControlSet\\Services\\NkcTest";
const TABLE_KEY_FROM_ROOT: &str = "Machine\\System\\CurrentControlSet\\Services\\NkcTest";

/// `text` with a terminator.
fn z(text: &str) -> Vec<u16> {
    text.encode_utf16().chain([0]).collect()
}

/// The entry that ends a table.
const END: RTL_QUERY_REGISTRY_TABLE = RTL_QUERY_REGISTRY_TABLE {
    QueryRoutine: None,
    Flags: 0,
    Name: core::ptr::null_mut(),
    EntryContext: core::ptr::null_mut(),
    DefaultType: 0,
    DefaultData: core::ptr::null_mut(),
    DefaultLength: 0,
};

/// An entry that stores the value `name` where `target` points, which
/// must have the type `expect`; it has no default.
fn direct<T>(flags: u32, name: &[u16], target: *mut T, expect: u32) -> RTL_QUERY_REGISTRY_TABLE {
    RTL_QUERY_REGISTRY_TABLE {
        Flags: DIRECT | TYPECHECK | flags,
        Name: name.as_ptr().cast_mut(),
        EntryContext: target.cast(),
        DefaultType: expect << 24,
        ..END
    }
}

/// An entry that calls [`routine`] for the value `name` (every value,
/// if there is none), with `tag` as the entry's context.
fn calling(flags: u32, name: Option<&[u16]>, tag: usize) -> RTL_QUERY_REGISTRY_TABLE {
    RTL_QUERY_REGISTRY_TABLE {
        QueryRoutine: Some(routine),
        Flags: flags,
        Name: name.map_or(core::ptr::null_mut(), |name| name.as_ptr().cast_mut()),
        EntryContext: core::ptr::without_provenance_mut(tag),
        ..END
    }
}

/// Run `entries`, ended as a table must be, on the key `path` names
/// from `relative_to`, with the environment the tests expand from.
fn run_table(
    export: Export,
    relative_to: u32,
    path: *const u16,
    entries: &[RTL_QUERY_REGISTRY_TABLE],
    context: *mut c_void,
) -> u32 {
    let environment = z("NKVAR=value\0");
    let mut table: Vec<RTL_QUERY_REGISTRY_TABLE> = Vec::new();
    table.extend_from_slice(entries);
    table.push(END);
    // SAFETY: a table that ends, of entries the tests make to point at
    // their own variables; a path or handle as the caller says.
    (unsafe {
        export(
            relative_to,
            path,
            table.as_ptr(),
            context,
            environment.as_ptr(),
        )
    }) as u32
}

/// Run `entries` on the tests' key, by its full name.
fn on_key(export: Export, entries: &[RTL_QUERY_REGISTRY_TABLE]) -> u32 {
    run_table(
        export,
        0,
        z(TABLE_KEY).as_ptr(),
        entries,
        core::ptr::null_mut(),
    )
}

const NO_STRING: UNICODE_STRING = UNICODE_STRING {
    Length: 0,
    MaximumLength: 0,
    Buffer: core::ptr::null_mut(),
};

/// What a query stored in `string`: its length, its room, its text and
/// the unit after it; `None` if it has no buffer. A buffer the query
/// made is freed, as its caller must.
fn stored(string: &mut UNICODE_STRING, allocated: bool) -> Option<(u16, u16, Vec<u16>)> {
    if string.Buffer.is_null() {
        return None;
    }
    let units = usize::from(string.Length) / 2 + 1;
    // SAFETY: the buffer holds the string and its terminator.
    let text = (0..units)
        .map(|i| unsafe { string.Buffer.add(i).read() })
        .collect();
    if allocated {
        // SAFETY: the query's own block, which nothing else names.
        unsafe { crate::mm::pool::ExFreePoolWithTag(string.Buffer.cast(), 0) };
    }
    let found = (string.Length, string.MaximumLength, text);
    *string = NO_STRING;
    Some(found)
}

/// What [`stored`] finds for `text` in a buffer the query made.
fn string_of(text: &str) -> Option<(u16, u16, Vec<u16>)> {
    let units = z(text);
    Some((
        (units.len() * 2 - 2) as u16,
        (units.len() * 2) as u16,
        units,
    ))
}

/// Run `queries` on the tests' key, given more values to read: a
/// number of four bytes and one of eight, and a string with variables
/// in it. The queries must leave nothing behind: no memory of their
/// own, and none of the caller's strings unfreed.
fn with_more_values(
    key: *mut c_void,
    export: Export,
    queries: fn(*mut c_void, Export) -> Result<(), &'static str>,
) -> Result<(), &'static str> {
    let qword = 0x1122_3344_5566_7788u64.to_le_bytes();
    let set = [
        set(key, "Number", REG_DWORD, &qword[..4]),
        set(key, "Qword", REG_QWORD, &qword),
        set(key, "Expand", REG_EXPAND_SZ, &utf16("%NKVAR%\\x%NOPE%\0")),
    ];
    if set != [0; 3] {
        return Err("the values to query could not be set");
    }
    let before = resources();
    queries(key, export)?;
    if resources() != before {
        return Err("query tables left something behind");
    }
    Ok(())
}

/// A value is stored where its entry points, by its type and size, as
/// Microsoft documents and as nkc-reg's source predicts: small data in
/// place, longer data in a buffer that says its size, a string in a
/// counted string.
fn table_direct(key: *mut c_void, export: Export) -> Result<(), &'static str> {
    let names = [
        "Number",
        "Odd",
        "Qword",
        "Text",
        "Expand",
        "Multi",
        "Absent",
        "Beta",
        "Val",
        "Temp",
        "NoSuchKey",
    ]
    .map(z);
    let [
        number_name,
        odd,
        qword,
        text,
        expand,
        multi,
        absent,
        beta,
        val,
        temp,
        no_key,
    ] = &names;
    let mut number = 0xEEEE_EEEEu32;
    let target = &raw mut number;
    let one = |entry: RTL_QUERY_REGISTRY_TABLE| {
        // SAFETY: a local of the test's, which the entry points to.
        unsafe { target.write(0xEEEE_EEEE) };
        let status = on_key(export, &[entry]);
        // SAFETY: as above.
        (status, unsafe { target.read() })
    };
    // Four bytes, and three: the fourth is left alone.
    let small = [
        one(direct(0, number_name, target, REG_DWORD)),
        one(direct(0, odd, target, REG_BINARY)),
        // A value of another type than the entry expects.
        one(direct(0, text, target, REG_DWORD)),
        // A value that is not there: required; not required; with a
        // default, which is not type-checked.
        one(direct(REQUIRED, absent, target, REG_DWORD)),
        one(direct(0, absent, target, REG_DWORD)),
        one(RTL_QUERY_REGISTRY_TABLE {
            DefaultType: REG_DWORD << 24 | REG_DWORD,
            DefaultData: (&raw const DEFAULT_NUMBER).cast_mut().cast(),
            DefaultLength: 4,
            ..direct(0, absent, target, REG_DWORD)
        }),
        // Storing directly and naming a subkey do not go together.
        one(direct(SUBKEY, beta, target, REG_DWORD)),
        // Without the type check, as drivers older than it ask.
        one(RTL_QUERY_REGISTRY_TABLE {
            Flags: DIRECT,
            DefaultType: 0,
            ..direct(0, number_name, target, REG_DWORD)
        }),
    ];
    if small
        != [
            (0, 0x5566_7788),
            (0, 0xEE34_5678),
            (TYPE_MISMATCH, 0xEEEE_EEEE),
            (NOT_FOUND, 0xEEEE_EEEE),
            (0, 0xEEEE_EEEE),
            (0, DEFAULT_NUMBER),
            (INVALID_PARAMETER, 0xEEEE_EEEE),
            (0, 0x5566_7788),
        ]
    {
        crate::kd::print(format_args!("cm.table.direct: {small:x?}\n"));
        return Err("a value of up to four bytes was not stored, or refused, as on Windows");
    }

    // More than four bytes: a buffer whose first word is its size. A
    // positive size wants length and type before the data, a negative
    // one the data alone; one too small for either is refused.
    let mut buffer = [0xEEEE_EEEEu32; 6];
    let sized = [24, -24, 12].map(|size: i32| {
        buffer = [0xEEEE_EEEE; 6];
        buffer[0] = size as u32;
        let entry = direct(0, qword, buffer.as_mut_ptr(), REG_QWORD);
        (on_key(export, &[entry]), buffer)
    });
    const E: u32 = 0xEEEE_EEEE;
    if sized
        != [
            (0, [8, REG_QWORD, 0x5566_7788, 0x1122_3344, E, E]),
            (0, [0x5566_7788, 0x1122_3344, E, E, E, E]),
            (TOO_SMALL, [12, E, E, E, E, E]),
        ]
    {
        return Err("a value of more than four bytes was not stored in a sized buffer");
    }

    // A string: in a new buffer with room for the terminator; in the
    // caller's, if it has that room.
    let mut string = NO_STRING;
    let into = &raw mut string;
    let mut small_buffer = [0xEEEEu16; 4];
    let made = on_key(export, &[direct(0, text, into, REG_SZ)]);
    if (made, stored(&mut string, true)) != (0, string_of("nk")) {
        return Err("a string was not stored in a buffer made for it");
    }
    let mut own = |room: u16| {
        small_buffer = [0xEEEE; 4];
        string = UNICODE_STRING {
            Length: 0,
            MaximumLength: room,
            Buffer: small_buffer.as_mut_ptr(),
        };
        let status = on_key(export, &[direct(0, text, into, REG_SZ)]);
        (status, string.Length, string.MaximumLength, small_buffer)
    };
    let fits = own(6);
    let short = own(4);
    string = NO_STRING;
    if fits != (0, 4, 6, [0x6E, 0x6B, 0, 0xEEEE]) || short != (TOO_SMALL, 0, 4, [0xEEEE; 4]) {
        return Err("a string was not stored in the caller's buffer only if it has room");
    }

    // Expanded from the environment, unless asked for as stored; a
    // variable the environment has not stays as written. Several
    // strings as one, or each in the next counted string. A default
    // string whose length is left to be measured.
    let mut strings = [NO_STRING; 3];
    let mut one_string = |entry: RTL_QUERY_REGISTRY_TABLE| {
        let status = on_key(export, &[entry]);
        (status, stored(&mut string, true))
    };
    let expanded = [
        one_string(direct(0, expand, into, REG_EXPAND_SZ)),
        one_string(direct(NOEXPAND, expand, into, REG_EXPAND_SZ)),
        one_string(direct(NOEXPAND, multi, into, REG_MULTI_SZ)),
        one_string(RTL_QUERY_REGISTRY_TABLE {
            DefaultType: REG_SZ << 24 | REG_SZ,
            DefaultData: DEFAULT_TEXT.as_ptr().cast_mut().cast(),
            ..direct(0, absent, into, REG_SZ)
        }),
        one_string(RTL_QUERY_REGISTRY_TABLE {
            Flags: DIRECT,
            DefaultType: 0,
            ..direct(0, text, into, REG_SZ)
        }),
    ];
    if expanded
        != [
            (0, string_of("value\\x%NOPE%")),
            (0, string_of("%NKVAR%\\x%NOPE%")),
            (0, string_of("a\0bc\0")),
            (0, string_of("dflt")),
            (0, string_of("nk")),
        ]
    {
        return Err("a string was not expanded, or kept as stored, as asked");
    }
    let several = on_key(
        export,
        &[direct(0, multi, strings.as_mut_ptr(), REG_MULTI_SZ)],
    );
    let each = strings.each_mut().map(|string| stored(string, true));
    if (several, each) != (0, [string_of("a"), string_of("bc"), None]) {
        return Err("several strings were not stored each in the next counted string");
    }

    // A subkey entry moves the entries after it to the subkey; one
    // that says so, back to the key the call named.
    buffer = [E; 6];
    buffer[0] = 24;
    let below = [
        RTL_QUERY_REGISTRY_TABLE {
            Flags: SUBKEY,
            Name: beta.as_ptr().cast_mut(),
            ..END
        },
        direct(0, val, buffer.as_mut_ptr(), REG_BINARY),
        direct(TOPKEY, number_name, target, REG_DWORD),
    ];
    // SAFETY: the local the last entry points to.
    unsafe { target.write(E) };
    let found = on_key(export, &below);
    // SAFETY: as above.
    let top = unsafe { target.read() };
    let missing = on_key(
        export,
        &[
            RTL_QUERY_REGISTRY_TABLE {
                Flags: SUBKEY,
                Name: no_key.as_ptr().cast_mut(),
                ..END
            },
            direct(0, val, buffer.as_mut_ptr(), REG_BINARY),
        ],
    );
    if (found, buffer, top, missing)
        != (
            0,
            [5, REG_BINARY, 0x0403_0201, 0xEEEE_EE05, E, E],
            0x5566_7788,
            NOT_FOUND,
        )
    {
        return Err("a subkey entry did not move the entries after it, there and back");
    }

    // Stored, then deleted.
    if set(key, "Temp", REG_DWORD, &7u32.to_le_bytes()) != 0
        || one(direct(DELETE, temp, target, REG_DWORD)) != (0, 7)
        || delete_named(key, "Temp") != NOT_FOUND
    {
        return Err("a value was not stored and then deleted");
    }
    Ok(())
}

static DEFAULT_NUMBER: u32 = 0xDEFA_0017;
/// "dflt" and its terminator.
static DEFAULT_TEXT: [u16; 5] = [0x64, 0x66, 0x6C, 0x74, 0];

/// What a routine is told to answer, in its entry's context, as in
/// nkc-reg.
const ANSWER_OK: usize = 0x100;
const ANSWER_FAIL: usize = 0x200;
const ANSWER_SMALL: usize = 0x300;

/// One call of [`routine`]: the value's type and length, its name's
/// first character (0xFFFF: no name), its data's first four bytes
/// (fewer: filled with 0xFF; all ones: no data), the entry's context.
type Call = [u32; 5];

/// A query routine: writes down what it was called with, in the list
/// the query's context points to, and answers what its entry's context
/// says.
///
/// # Safety
/// Called by a query whose context is a `Vec<Call>`.
unsafe extern "C" fn routine(
    name: *mut u16,
    kind: u32,
    data: *mut c_void,
    length: u32,
    context: *mut c_void,
    entry_context: *mut c_void,
) -> i32 {
    // SAFETY: per the contract; the name and data are what a query
    // lends its routine.
    let (calls, first, bytes) = unsafe {
        let first = if name.is_null() {
            0xFFFF
        } else {
            u32::from(name.read())
        };
        let bytes = if data.is_null() || length == 0 {
            u32::MAX
        } else {
            let mut bytes = [0xFF; 4];
            for (i, byte) in bytes.iter_mut().enumerate().take(length as usize) {
                *byte = data.cast::<u8>().add(i).read();
            }
            u32::from_le_bytes(bytes)
        };
        (&mut *context.cast::<Vec<Call>>(), first, bytes)
    };
    let answer = entry_context.addr();
    calls.push([kind, length, first, bytes, answer as u32]);
    (match answer & 0xF00 {
        ANSWER_FAIL => UNSUCCESSFUL,
        ANSWER_SMALL => TOO_SMALL,
        _ => 0,
    }) as i32
}

/// Run `entries` on the tests' key: the status, and the calls made.
fn calls_of(export: Export, entries: &[RTL_QUERY_REGISTRY_TABLE]) -> (u32, Vec<Call>) {
    let mut calls: Vec<Call> = Vec::new();
    let status = run_table(
        export,
        0,
        z(TABLE_KEY).as_ptr(),
        entries,
        (&raw mut calls).cast(),
    );
    (status, calls)
}

/// The first two characters of `text`, as a routine's data begin.
fn starts(text: &str) -> u32 {
    let mut units = text.encode_utf16().chain([0, 0]);
    let (low, high) = (units.next().unwrap_or(0), units.next().unwrap_or(0));
    u32::from(low) | u32::from(high) << 16
}

/// An entry's routine is called with each value the entry asks for:
/// one string of several at a time, an expandable string expanded, a
/// default for a value that is not there, every value of a key. Its
/// failure ends the query, but for the one status Windows ignores.
fn table_routine(key: *mut c_void, export: Export) -> Result<(), &'static str> {
    let names = ["Number", "Text", "Multi", "Expand", "Absent", "Beta"].map(z);
    let [number, text, multi, expand, absent, beta] = &names;
    let ok = |tag: usize| ANSWER_OK | tag;
    let c = |letter: char| letter as u32;
    let named: [(RTL_QUERY_REGISTRY_TABLE, u32, &[Call]); 9] = [
        (
            calling(0, Some(number), ok(1)),
            0,
            &[[REG_DWORD, 4, c('N'), 0x5566_7788, 0x101]],
        ),
        // A string's length counts its terminator.
        (
            calling(0, Some(text), ok(2)),
            0,
            &[[REG_SZ, 6, c('T'), starts("nk"), 0x102]],
        ),
        // Each string of several, as a string; or all of them as they
        // are stored.
        (
            calling(0, Some(multi), ok(3)),
            0,
            &[
                [REG_SZ, 4, c('M'), starts("a"), 0x103],
                [REG_SZ, 6, c('M'), starts("bc"), 0x103],
            ],
        ),
        (
            calling(NOEXPAND, Some(multi), ok(4)),
            0,
            &[[REG_MULTI_SZ, 12, c('M'), starts("a"), 0x104]],
        ),
        // Expanded, a plain string; or as stored.
        (
            calling(0, Some(expand), ok(5)),
            0,
            &[[REG_SZ, 28, c('E'), starts("va"), 0x105]],
        ),
        (
            calling(NOEXPAND, Some(expand), ok(6)),
            0,
            &[[REG_EXPAND_SZ, 32, c('E'), starts("%N"), 0x106]],
        ),
        // Not there: no call; an error if required; the default, its
        // length measured.
        (calling(0, Some(absent), ok(7)), 0, &[]),
        (calling(REQUIRED, Some(absent), ok(8)), NOT_FOUND, &[]),
        (
            RTL_QUERY_REGISTRY_TABLE {
                DefaultType: REG_SZ,
                DefaultData: DEFAULT_TEXT.as_ptr().cast_mut().cast(),
                ..calling(0, Some(absent), ok(9))
            },
            0,
            &[[REG_SZ, 10, c('A'), starts("df"), 0x109]],
        ),
    ];
    for (entry, status, calls) in named {
        if calls_of(export, &[entry]) != (status, calls.to_vec()) {
            crate::kd::print(format_args!(
                "cm.table.routine: {:x?}\n",
                calls_of(export, &[entry])
            ));
            return Err("a routine was not called with the value its entry names");
        }
    }
    // A failure ends the query: the entry after it is not reached.
    // "Buffer too small" is not taken for one.
    let after = calling(0, Some(text), ok(0x11));
    let failed = calls_of(export, &[calling(0, Some(number), ANSWER_FAIL | 1), after]);
    let small = calls_of(export, &[calling(0, Some(number), ANSWER_SMALL | 1), after]);
    if (failed.0, failed.1.len(), small.0, small.1.len()) != (UNSUCCESSFUL, 1, 0, 2) {
        return Err("a routine's failure did not end the query, or the wrong status did");
    }
    // No name: every value of the key in the key's order, each under
    // its own name; or, if the entry says so, one call with no value.
    let every: [Call; 8] = [
        [REG_DWORD, 4, c('N'), 0x5566_7788, 0x121],
        [REG_SZ, 6, c('T'), starts("nk"), 0x121],
        [REG_BINARY, 3, c('O'), 0xFF34_5678, 0x121],
        [REG_SZ, 4, 0, starts("d"), 0x121],
        [REG_SZ, 4, c('M'), starts("a"), 0x121],
        [REG_SZ, 6, c('M'), starts("bc"), 0x121],
        [REG_QWORD, 8, c('Q'), 0x5566_7788, 0x121],
        [REG_SZ, 28, c('E'), starts("va"), 0x121],
    ];
    if calls_of(export, &[calling(0, None, ok(0x21))]) != (0, every.to_vec())
        || calls_of(export, &[calling(NOVALUE, None, ok(0x22))])
            != (0, alloc::vec![[0, 0, 0xFFFF, u32::MAX, 0x122]])
    {
        return Err("an entry without a name did not get every value, or the one bare call");
    }
    // A subkey entry with a routine: every value of the subkey. A
    // routine and a place to store do not go together.
    let mut unused = 0u32;
    let both = RTL_QUERY_REGISTRY_TABLE {
        EntryContext: (&raw mut unused).cast(),
        ..calling(DIRECT, Some(number), ok(0x24))
    };
    if calls_of(export, &[calling(SUBKEY, Some(beta), ok(0x23))])
        != (0, alloc::vec![[REG_BINARY, 5, c('V'), 0x0403_0201, 0x123]])
        || calls_of(export, &[both]) != (INVALID_PARAMETER, Vec::new())
    {
        return Err("a subkey's routine did not get the subkey's values");
    }
    // With the delete flag each value goes once its routine has had it.
    let (status, calls) = calls_of(export, &[calling(DELETE, None, ok(0x25))]);
    if (status, calls.len()) != (0, 8) || !enumerate_value(key, 0, 0, ROOM).refused(NO_MORE) {
        return Err("values were not deleted once their routine had been called");
    }
    Ok(())
}

/// Keys one below another, from the key `from` names: made if they are
/// not there. Returns the handles of the ones made, outermost first,
/// or `None` if one could not be.
fn chain(from: &str, parts: &[&str]) -> Option<Vec<*mut c_void>> {
    let mut made = Vec::new();
    let mut path = alloc::string::String::from(from);
    for part in parts {
        path.push('\\');
        path.push_str(part);
        let (status, handle, disposition) = key(&path, core::ptr::null_mut(), true);
        if status != 0 {
            unchain(made);
            return None;
        }
        if disposition == 1 {
            made.push(handle);
        } else {
            ZwClose(handle);
        }
    }
    Some(made)
}

/// Delete the keys [`chain`] made, innermost first.
fn unchain(made: Vec<*mut c_void>) -> bool {
    made.into_iter().rev().fold(true, |gone, handle| {
        let deleted = ZwDeleteKey(handle);
        ZwClose(handle);
        gone && deleted == 0
    })
}

/// The path of a query starts where `RelativeTo` says: at one of the
/// keys Windows names by number, at the top, or at a key handle.
fn table_roots(key: *mut c_void, export: Export) -> Result<(), &'static str> {
    const MACHINE: &str = "\\Registry\\Machine";
    let mut number = 0xEEEE_EEEEu32;
    let target = &raw mut number;
    let name = z("Number");
    let entry = direct(REQUIRED, &name, target, REG_DWORD);
    let from = |relative_to: u32, path: *const u16| {
        // SAFETY: a local of the test's, which the entry points to.
        unsafe { target.write(0xEEEE_EEEE) };
        let status = run_table(export, relative_to, path, &[entry], core::ptr::null_mut());
        // SAFETY: as above.
        (status, unsafe { target.read() })
    };
    const NONE: (u32, u32) = (NOT_FOUND, 0xEEEE_EEEE);
    const FOUND: (u32, u32) = (0, 0x1234_5678);
    let missing = z(&alloc::format!("{TABLE_KEY}\\NoSuchKey"));
    let roots = [
        from(1, z("NkcTest").as_ptr()),
        from(0x4000_0000, key.cast()),
        from(0xC000_0000, key.cast()),
        from(0, z(TABLE_KEY).as_ptr()),
        // A key that is not there, optional or not.
        from(0, missing.as_ptr()),
        from(0x8000_0000, missing.as_ptr()),
        from(1, z("nk-no-such-service").as_ptr()),
        // A root there is none of; a handle that is no key's.
        from(99, z("NkcTest").as_ptr()),
        from(0x4000_0000, core::ptr::without_provenance(0x1234)),
    ];
    if roots
        != [
            FOUND,
            FOUND,
            FOUND,
            FOUND,
            NONE,
            NONE,
            NONE,
            (INVALID_PARAMETER, 0xEEEE_EEEE),
            (0xC000_0008, 0xEEEE_EEEE),
        ]
    {
        crate::kd::print(format_args!("cm.table.roots: {roots:x?}\n"));
        return Err("a path was not taken from the top, from Services or from a handle");
    }
    // The other roots: each is a key the test makes for the purpose,
    // with what lies above it where the registry has not got that.
    let control = alloc::format!("{MACHINE}\\System\\CurrentControlSet\\Control");
    let places: [(u32, &str, &[&str]); 4] = [
        (2, &control, &["NkRoot"]),
        (
            3,
            MACHINE,
            &[
                "Software",
                "Microsoft",
                "Windows NT",
                "CurrentVersion",
                "NkRoot",
            ],
        ),
        (4, MACHINE, &["Hardware", "DeviceMap", "NkRoot"]),
        (5, "\\Registry\\User", &[".Default", "NkRoot"]),
    ];
    for (relative_to, above, parts) in places {
        let before = from(relative_to, z("NkRoot").as_ptr());
        let made = chain(above, parts).ok_or("a key to query from could not be made")?;
        let written = made
            .last()
            .map(|&handle| set(handle, "Number", REG_DWORD, &relative_to.to_le_bytes()));
        let found = from(relative_to, z("NkRoot").as_ptr());
        if !unchain(made) || written != Some(0) {
            return Err("a key to query from could not be written, or deleted again");
        }
        if (before, found) != (NONE, (0, relative_to)) {
            crate::kd::print(format_args!(
                "cm.table.roots: root {relative_to}: {before:x?} {found:x?}\n"
            ));
            return Err("a root Windows names by number is not the key Windows means");
        }
    }
    Ok(())
}

/// How often [`raising`] has been called, and what [`query_and_raise`]
/// got back from the query.
static RAISE_CALLS: AtomicU32 = AtomicU32::new(0);
static RAISE_RETURNED: AtomicU32 = AtomicU32::new(0);
/// The export [`query_and_raise`] calls.
static RAISE_EXPORT: AtomicUsize = AtomicUsize::new(0);

/// ASCII `text` as a terminated string of `N` units.
const fn terminated<const N: usize>(text: &str) -> [u16; N] {
    let mut units = [0; N];
    let mut i = 0;
    while i < text.len() {
        units[i] = text.as_bytes()[i] as u16;
        i += 1;
    }
    units
}

/// What [`query_and_raise`] names: it is a driver's function, unwound
/// with the query, and keeps nothing that only a destructor frees.
static RAISE_KEY: [u16; TABLE_KEY.len() + 1] = terminated(TABLE_KEY);
static RAISE_ENVIRONMENT: [u16; 13] = terminated("NKVAR=value");
static BETA: [u16; 5] = terminated("Beta");
static MULTI: [u16; 6] = terminated("Multi");
static ABSENT: [u16; 7] = terminated("Absent");

/// A query routine that raises an exception the second time it is
/// called: with the query in the middle of a value of several strings.
///
/// # Safety
/// Callable as a query routine with any arguments.
unsafe extern "C" fn raising(
    _: *mut u16,
    _: u32,
    _: *mut c_void,
    _: u32,
    _: *mut c_void,
    _: *mut c_void,
) -> i32 {
    if RAISE_CALLS.fetch_add(1, Ordering::Relaxed) == 1 {
        except::raise(except::CODE as usize);
    }
    0
}

/// A body for a `__try`: a driver's function that runs a query table
/// whose routine raises. Much of what a query can hold is held when it
/// does: an environment, a value in hand, a string lent out, entries
/// with names and a default still to come.
extern "C" fn query_and_raise(_: usize) {
    let table = [
        RTL_QUERY_REGISTRY_TABLE {
            Flags: SUBKEY,
            Name: BETA.as_ptr().cast_mut(),
            ..END
        },
        RTL_QUERY_REGISTRY_TABLE {
            QueryRoutine: Some(raising),
            Flags: TOPKEY,
            Name: MULTI.as_ptr().cast_mut(),
            ..END
        },
        RTL_QUERY_REGISTRY_TABLE {
            QueryRoutine: Some(raising),
            Name: ABSENT.as_ptr().cast_mut(),
            DefaultType: REG_SZ,
            DefaultData: DEFAULT_TEXT.as_ptr().cast_mut().cast(),
            ..END
        },
        END,
    ];
    // SAFETY: the address of one of the two exports, stored by the
    // test; a table that ends, and strings that do.
    let status = unsafe {
        let export: Export = core::mem::transmute(RAISE_EXPORT.load(Ordering::Relaxed));
        export(
            0,
            RAISE_KEY.as_ptr(),
            table.as_ptr(),
            core::ptr::null_mut(),
            RAISE_ENVIRONMENT.as_ptr(),
        )
    };
    RAISE_RETURNED.store(status as u32 | 1 << 31, Ordering::Relaxed);
}

/// A routine that raises an exception is unwound through the query to
/// the handler of the driver function that made it, and the query
/// leaves nothing behind: no memory, no lock, and the key no longer
/// counted as open.
fn table_raise(_: *mut c_void, export: Export) -> Result<(), &'static str> {
    // A query that returns holds nothing afterwards: the measure. The
    // test's own handle is the one open of the key.
    let quiet = [calling(0, None, ANSWER_OK)];
    let _ = calls_of(export, &quiet);
    let before = (resources(), crate::cm::open_count(TABLE_KEY_FROM_ROOT));
    RAISE_CALLS.store(0, Ordering::Relaxed);
    RAISE_RETURNED.store(0, Ordering::Relaxed);
    RAISE_EXPORT.store(export as usize, Ordering::Relaxed);
    except::arm([except::ACCEPT, except::DECLINE]);
    except::caught(query_and_raise, 0)?;
    let ran = (
        RAISE_CALLS.load(Ordering::Relaxed),
        RAISE_RETURNED.load(Ordering::Relaxed),
    );
    if ran != (2, 0) {
        return Err("the routine did not raise in its second call, or the query returned");
    }
    let after = (resources(), crate::cm::open_count(TABLE_KEY_FROM_ROOT));
    if after.0 != before.0 {
        crate::kd::print(format_args!(
            "cm.table.raise: {:?}\n  then {:?}\n",
            before.0, after.0
        ));
        return Err("a query whose routine raised left memory or a raised IRQL behind");
    }
    if (before.1, after.1) != (Some(1), Some(1)) {
        return Err("a query whose routine raised left its key counted as open");
    }
    // The registry is not left locked, and answers as before.
    let again = calls_of(export, &quiet);
    if (again.0, again.1.len()) != (0, 6) {
        return Err("the registry does not answer after a query was unwound");
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
    // Windows spells this group `File system` in its drivers' keys and
    // `File System` in the list of groups; the hive may do either.
    let services = value_of(&alloc::format!("{SERVICES}\\Npfs"), "Group");
    if !matches!(&services, Ok((1, group)) if group.eq_ignore_ascii_case(&utf16("File System\0"))) {
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
    r.check("cm.delete.value", || with_key(delete_value));
    r.check("cm.enumerate.keys", || with_key(enumerate_keys));
    r.check("cm.enumerate.values", || with_key(enumerate_values));
    r.check("cm.query.key", || with_key(query_key));
    r.check("cm.query.value", || with_key(query_value));
    let both = |test: fn(*mut c_void, Export) -> Result<(), &'static str>| {
        EXPORTS
            .into_iter()
            .try_for_each(|export| with_key(|key| test(key, export)))
    };
    r.check("cm.table.direct", || {
        both(|key, export| with_more_values(key, export, table_direct))
    });
    r.check("cm.table.routine", || {
        both(|key, export| with_more_values(key, export, table_routine))
    });
    r.check("cm.table.roots", || both(table_roots));
    r.check("cm.table.raise", || both(table_raise));
    r.check("cm.namespace", namespace);
    r.check("cm.control-set", control_set);
    let Some(hive) = crate::ldr::boot_file(nk_bootinfo::HIVE_MODULE) else {
        return r.skip_rest(format_args!("no SYSTEM hive provided"));
    };
    r.check("cm.hive.values", hive_values);
    r.check("cm.hive.names", hive_names);
    r.check("cm.hive.refused", || crate::cm::refused_test(hive));
}
