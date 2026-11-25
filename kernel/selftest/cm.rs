//! Tests of the registry, through the routines drivers call.

use crate::cm::{ZwCreateKey, ZwOpenKey, ZwQueryValueKey, ZwSetValueKey};
use crate::ps::ZwClose;
use crate::test::{Group, Report};
use alloc::vec::Vec;
use core::ffi::c_void;
use nk_bootinfo::BootInfo;
use nk_ntabi::io::UNICODE_STRING;
use nk_ntabi::ob::OBJECT_ATTRIBUTES;

pub static GROUP: Group = Group {
    names: &["cm.keys", "cm.values"],
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
        key("\\Device\\Null", null, false).0, // elsewhere in the namespace
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
        // The full form: the name as it was set, and where the data is.
        // Two bytes short of the whole, it holds what fitted and says
        // so.
        let (status, length, out) = query(handle, "TEXT", 1, 32);
        if (status, length) != (0x8000_0005, 34)
            || out[4..20] != [1, 0, 0, 0, 28, 0, 0, 0, 6, 0, 0, 0, 8, 0, 0, 0]
            || out[20..28] != [b'T', 0, b'e', 0, b'x', 0, b't', 0]
            || out[28..32] != text[..4]
        {
            return Err("the full form of a value is not its name, type and data");
        }
        // Asked with no room, it says how much is needed.
        let sizing = (
            query(handle, "Text", 1, 0).0,
            query(handle, "Text", 1, 0).1,
            query(handle, "Text", 1, 20).0,
        );
        if sizing != (0xC000_0023, 34, 0x8000_0005) {
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

fn run(r: &mut Report, _: &BootInfo) {
    r.check("cm.keys", keys);
    r.check("cm.values", values);
}
