//! Directory objects by handle: `ZwCreateDirectoryObject`,
//! `ZwMakeTemporaryObject`. The directories themselves are the
//! namespace's (`ob`).

#![allow(non_snake_case)]

use super::handle::{self, OBJ_KERNEL_HANDLE};
use super::object::{self, ObRef};
use core::ffi::c_void;
use nk_ntabi::ob::OBJECT_ATTRIBUTES;
use nk_ntabi::status::*;
use nk_ob::handles::Attributes;

/// Object attributes (`wdm.h`).
const OBJ_INHERIT: u32 = 0x2;
const OBJ_PERMANENT: u32 = 0x10;
const OBJ_EXCLUSIVE: u32 = 0x20;
const OBJ_OPENIF: u32 = 0x80;
const OBJ_OPENLINK: u32 = 0x100;
const OBJ_VALID_ATTRIBUTES: u32 = 0x1FF2;

/// Whether the object `body` is of the type `ty`.
///
/// # Safety
/// The caller holds a reference to `body`.
unsafe fn is(body: *mut u8, ty: &'static object::ObjectType) -> bool {
    // SAFETY: per the contract.
    core::ptr::eq(unsafe { object::type_of(body) }, ty)
}

/// [`ZwCreateDirectoryObject`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-zwcreatedirectoryobject):
/// make a directory object and give a handle to it, granted the access
/// asked for. With a name in the attributes the directory is an entry
/// of the namespace, at that path from the root or from the
/// attributes' root directory; without, it is reached by its handle
/// alone. `OBJ_PERMANENT` makes it permanent: a temporary directory
/// loses its name when its last handle closes. A name that is taken is
/// `STATUS_OBJECT_NAME_COLLISION`; with `OBJ_OPENIF`, and a directory
/// having the name, that directory is opened and the status is
/// `STATUS_OBJECT_NAME_EXISTS`.
///
/// The handle is written when the attributes were acceptable: null if
/// the directory could then not be made or named, as the pinned
/// kernel's `ObpCreateDirectoryObject` leaves it.
///
/// `OBJ_OPENLINK` is invalid for a directory, as on Windows. The gap
/// the ledger's "partial" stands for: `OBJ_EXCLUSIVE` is refused with
/// `STATUS_NOT_IMPLEMENTED`. A security descriptor in the attributes
/// is not looked at: nothing checks access to an object.
///
/// # Safety
/// `directory_handle` is writable; `object_attributes` is null or
/// points to an `OBJECT_ATTRIBUTES` whose name is null or a counted
/// string.
pub unsafe extern "C" fn ZwCreateDirectoryObject(
    directory_handle: *mut *mut c_void,
    desired_access: u32,
    object_attributes: *const OBJECT_ATTRIBUTES,
) -> NTSTATUS {
    let (mut root, mut name, mut attributes) = (core::ptr::null_mut(), alloc::vec::Vec::new(), 0);
    if !object_attributes.is_null() {
        // SAFETY: per the contract; the driver's memory, read field by
        // field through its pointer.
        let length = unsafe {
            root = (&raw const (*object_attributes).RootDirectory).read_unaligned();
            name = crate::rtl::copy_unicode(
                (&raw const (*object_attributes).ObjectName).read_unaligned(),
            );
            attributes = (&raw const (*object_attributes).Attributes).read_unaligned();
            (&raw const (*object_attributes).Length).read_unaligned()
        };
        if length as usize != size_of::<OBJECT_ATTRIBUTES>()
            || attributes & !OBJ_VALID_ATTRIBUTES != 0
            || attributes & OBJ_OPENLINK != 0
        {
            return STATUS_INVALID_PARAMETER;
        }
        if attributes & OBJ_EXCLUSIVE != 0 {
            return STATUS_NOT_IMPLEMENTED;
        }
    }
    // The root directory is held while the name is looked up from it.
    // A name is relative to a directory; an object of a type that
    // parses names itself (a device, a file, a key) parses none into
    // a directory, and nothing is below any other object.
    let start = if root.is_null() || name.is_empty() {
        None
    } else {
        match handle::reference(root as u64, None) {
            Ok(start) => Some(start),
            Err(status) => return status,
        }
    };
    let made = match start.as_ref().map(ObRef::body) {
        // SAFETY: the reference just taken.
        Some(start) if !unsafe { is(start, &object::DIRECTORY_TYPE) } => {
            let parses = [&object::DEVICE_TYPE, &object::FILE_TYPE, &object::KEY_TYPE]
                .into_iter()
                // SAFETY: the same reference.
                .any(|ty| unsafe { is(start, ty) });
            Err(if parses {
                STATUS_OBJECT_TYPE_MISMATCH
            } else {
                STATUS_INVALID_HANDLE
            })
        }
        start => super::create_directory(
            start,
            &name,
            attributes & OBJ_PERMANENT != 0,
            attributes & OBJ_OPENIF != 0,
        ),
    };
    drop(start);
    // SAFETY: per the contract for the handle; `body` is the reference
    // the directory came with, given up once the handle holds it.
    unsafe {
        let (body, existed) = match made {
            Ok(made) => made,
            Err(status) => {
                directory_handle.write_unaligned(core::ptr::null_mut());
                return status;
            }
        };
        let opened = handle::open_with(
            body,
            desired_access,
            Attributes {
                inherit: attributes & OBJ_INHERIT != 0,
                protect_from_close: false,
            },
            attributes & OBJ_KERNEL_HANDLE != 0,
        );
        if opened.is_err() && !existed {
            // No handle was ever open: a temporary directory's name
            // goes, as when its last handle closes.
            super::directory_handle_closed(core::ptr::null_mut(), body.cast(), 1, 1);
        }
        object::dereference(body);
        match opened {
            Ok(opened) => {
                directory_handle.write_unaligned(opened as *mut c_void);
                if existed {
                    STATUS_OBJECT_NAME_EXISTS
                } else {
                    STATUS_SUCCESS
                }
            }
            Err(status) => {
                directory_handle.write_unaligned(core::ptr::null_mut());
                status
            }
        }
    }
}

/// [`ZwMakeTemporaryObject`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-zwmaketemporaryobject):
/// the object the handle names is no longer permanent, so its name
/// goes when its last handle closes. Kernel mode's handle is asked
/// for no access.
///
/// Directories are the objects NK makes permanent by handle. An
/// object without a name has no permanence to lose. A named object of
/// another type has its name from the kernel code that made it, which
/// takes it away again; making one temporary by handle stops the
/// system by name: the ledger's "partial".
pub extern "C" fn ZwMakeTemporaryObject(handle: *mut c_void) -> NTSTATUS {
    let held = match handle::reference(handle as u64, None) {
        Ok(held) => held,
        Err(status) => return status,
    };
    let body = held.body();
    // SAFETY: the reference just taken, given up at the end.
    unsafe {
        let ty = object::type_of(body);
        if core::ptr::eq(ty, &raw const object::DIRECTORY_TYPE) {
            super::make_temporary(body);
        } else if object::has_name(body) {
            let name: alloc::string::String = char::decode_utf16(ty.name().iter().copied())
                .map(|c| c.unwrap_or('?'))
                .collect();
            crate::kd::bugcheck(format_args!(
                "ZwMakeTemporaryObject: making a named object of type {name} temporary is not \
                 implemented"
            ));
        }
    }
    STATUS_SUCCESS
}

// ---- tests --------------------------------------------------------------

use nk_ntabi::io::UNICODE_STRING;

/// `ZwCreateDirectoryObject` for `name` (none if empty), relative to
/// `root`, with `flags`: the status and the handle written.
fn create(name: &str, root: u64, flags: u32) -> (NTSTATUS, u64) {
    let mut text: alloc::vec::Vec<u16> = name.encode_utf16().collect();
    let string = UNICODE_STRING {
        Length: (text.len() * 2) as u16,
        MaximumLength: (text.len() * 2) as u16,
        Buffer: text.as_mut_ptr(),
    };
    let attributes = OBJECT_ATTRIBUTES {
        Length: size_of::<OBJECT_ATTRIBUTES>() as u32,
        RootDirectory: root as *mut c_void,
        ObjectName: if name.is_empty() {
            core::ptr::null()
        } else {
            &raw const string
        },
        Attributes: flags,
        SecurityDescriptor: core::ptr::null_mut(),
        SecurityQualityOfService: core::ptr::null_mut(),
    };
    let mut handle = 0x5A5A as *mut c_void;
    // SAFETY: locals that outlive the call.
    let status =
        unsafe { ZwCreateDirectoryObject(&raw mut handle, 0xF000F, &raw const attributes) };
    (status, handle as u64)
}

/// Whether `path` leads to something.
fn there(path: &str) -> Result<(), NTSTATUS> {
    let path: alloc::vec::Vec<u16> = path.encode_utf16().collect();
    let (body, _) = super::lookup(None, &path)?;
    // SAFETY: the look-up's reference.
    unsafe { object::dereference(body) };
    Ok(())
}

/// Directories made and unmade by handle, as `disk.sys` makes
/// `\Device\HarddiskN`: permanent and temporary names, what is in a
/// directory, and what is refused. Returns the directories asked for.
pub fn directory_test() -> Result<u32, &'static str> {
    use crate::mm::pool;
    const KERNEL: u32 = 0x240;
    const PERMANENT: u32 = KERNEL | OBJ_PERMANENT;
    const DISK: &str = "\\Device\\NkHarddisk7";
    let before = (super::count(), pool::usage().blocks, handle::count());
    let close = |handle: u64| handle::close(handle);

    // A temporary directory: its name goes with its last handle.
    let (status, temporary) = create("\\Device\\NkTemporary", 0, KERNEL);
    if status != STATUS_SUCCESS || there("\\Device\\NkTemporary").is_err() {
        return Err("a directory was not made by name");
    }
    close(temporary);
    if there("\\Device\\NkTemporary") != Err(STATUS_OBJECT_NAME_NOT_FOUND) {
        return Err("a temporary directory kept its name after its last handle closed");
    }

    // A permanent one, as disk.sys asks: it outlives its handle.
    let (status, disk) = create(DISK, 0, PERMANENT);
    if status != STATUS_SUCCESS || nk_ntabi::ob::handle_index(disk, false).is_some() {
        return Err("a permanent directory was not made, or its handle is no kernel handle");
    }
    close(disk);
    if there(DISK).is_err() {
        return Err("a permanent directory lost its name with its handle");
    }
    let verdict = (|| {
        // The name is taken; OBJ_OPENIF opens what has it.
        let taken = [
            create(DISK, 0, PERMANENT),
            create("\\DEVICE\\nkharddisk7", 0, KERNEL),
        ];
        if taken != [(STATUS_OBJECT_NAME_COLLISION, 0); 2] {
            return Err("a directory's name was given out again, or a handle written");
        }
        let (status, disk) = create(DISK, 0, KERNEL | OBJ_OPENIF);
        if status != STATUS_OBJECT_NAME_EXISTS {
            return Err("OBJ_OPENIF did not open the directory that has the name");
        }
        // Below it, by path and relative to its handle; a device-like
        // object in it, as `\Device\HarddiskN\DR0` is.
        let (status, part) = create("Partitions", disk, KERNEL);
        let wide: alloc::vec::Vec<u16> = "\\Device\\NkHarddisk7\\DR0".encode_utf16().collect();
        let Some(event) = object::create_named(
            &object::EVENT_TYPE,
            size_of::<nk_ntabi::ke::KEVENT>(),
            super::leaf(&wide),
        ) else {
            close(disk);
            close(part);
            return Err("no memory");
        };
        // SAFETY: a named object this test holds until it has taken
        // the name away again.
        let inserted = unsafe { super::insert(&wide, event) };
        let found = (
            there("\\Device\\NkHarddisk7\\Partitions"),
            there("\\Device\\NkHarddisk7\\DR0"),
        );
        // SAFETY: the event's header says where it is.
        let in_disk = unsafe { (*object::name_info(event)).Directory.cast::<u8>() };
        // The handle keeps the directory once the reference goes.
        let disk_body =
            handle::reference(disk, None).map_or(core::ptr::null_mut(), |held| held.body());
        // SAFETY: the running thread, an object nothing is below.
        let thread = unsafe { handle::open(crate::ke::thread::current().cast(), 0) }.unwrap_or(0);
        let refused = [
            create("\\Device\\NkHarddisk7\\DR0\\x", 0, KERNEL).0,
            create("\\Device\\NkHarddisk7\\DR0", 0, KERNEL | OBJ_OPENIF).0,
            create("\\NkNoDirectory\\x", 0, KERNEL).0,
            create("x", thread, KERNEL).0,
            create(DISK, 0, KERNEL | OBJ_OPENLINK).0,
            create(DISK, 0, KERNEL | OBJ_EXCLUSIVE).0,
            create(DISK, 0, 0x8000).0,
            create("NkRelative", 0, KERNEL).0,
        ];
        close(thread);
        close(part);
        // Made temporary with a handle open: the name stays until the
        // handle closes, and then goes though the directory is not
        // empty. What is in it is still in it, and it is still there.
        let temporary = ZwMakeTemporaryObject(disk as *mut c_void);
        let still = there(DISK);
        close(disk);
        let gone = (there(DISK), there("\\Device\\NkHarddisk7\\DR0"));
        // SAFETY: as above.
        let (after, name_left) = unsafe {
            let info = object::name_info(event);
            ((*info).Directory.cast::<u8>(), (*info).Name.Length)
        };
        // The name is free again while the old directory lives on.
        let (again_status, again) = create(DISK, 0, KERNEL);
        close(again);
        // SAFETY: the event made above: its name, then its reference.
        unsafe {
            super::remove(event);
            object::dereference(event);
        }
        if status != STATUS_SUCCESS || inserted != STATUS_SUCCESS || found != (Ok(()), Ok(())) {
            return Err("a directory made at run time does not hold directories and objects");
        }
        if in_disk.is_null() || in_disk != disk_body {
            return Err("an object in a directory made at run time does not say so");
        }
        if refused
            != [
                STATUS_OBJECT_TYPE_MISMATCH,
                STATUS_OBJECT_TYPE_MISMATCH,
                STATUS_OBJECT_PATH_NOT_FOUND,
                STATUS_INVALID_HANDLE,
                STATUS_INVALID_PARAMETER,
                STATUS_NOT_IMPLEMENTED,
                STATUS_INVALID_PARAMETER,
                STATUS_OBJECT_PATH_SYNTAX_BAD,
            ]
        {
            return Err("a directory that cannot be made was not refused with its own status");
        }
        if temporary != STATUS_SUCCESS || still.is_err() {
            return Err("a directory made temporary lost its name while a handle was open");
        }
        if gone
            != (
                Err(STATUS_OBJECT_NAME_NOT_FOUND),
                Err(STATUS_OBJECT_PATH_NOT_FOUND),
            )
        {
            return Err("a directory made temporary kept its name after its last handle closed");
        }
        if after != in_disk || name_left == 0 {
            return Err("an object left its directory when the directory lost its name");
        }
        if again_status != STATUS_SUCCESS {
            return Err("the name of a directory that lost it could not be used again");
        }
        Ok(())
    })();
    if verdict.is_err() {
        // Whatever is left of the permanent directory.
        let (status, disk) = create(DISK, 0, KERNEL | OBJ_OPENIF);
        if nt_success(status) {
            ZwMakeTemporaryObject(disk as *mut c_void);
            close(disk);
        }
    }
    verdict?;

    // Without a name: reached by handle alone, and gone with it.
    let (status, unnamed) = create("", 0, PERMANENT);
    let (below_status, below) = create("Below", unnamed, KERNEL);
    let (again_status, again) = create("below", unnamed, KERNEL | OBJ_OPENIF);
    let made_temporary = ZwMakeTemporaryObject(unnamed as *mut c_void);
    let no_handle = ZwMakeTemporaryObject(0x7FFC as *mut c_void);
    for handle in [again, below, unnamed] {
        close(handle);
    }
    if status != STATUS_SUCCESS
        || below_status != STATUS_SUCCESS
        || again_status != STATUS_OBJECT_NAME_EXISTS
    {
        return Err("a directory without a name does not hold a directory");
    }
    if made_temporary != STATUS_SUCCESS || no_handle != STATUS_INVALID_HANDLE {
        return Err("ZwMakeTemporaryObject did not answer for an unnamed directory or no handle");
    }
    let mut handle = core::ptr::null_mut();
    // SAFETY: no attributes at all, and a local for the handle.
    let status = unsafe { ZwCreateDirectoryObject(&raw mut handle, 0xF000F, core::ptr::null()) };
    close(handle as u64);
    if status != STATUS_SUCCESS {
        return Err("a directory was not made without object attributes");
    }
    if (super::count(), pool::usage().blocks, handle::count()) != before {
        return Err("directories, memory or handles were left behind");
    }
    Ok(17)
}
