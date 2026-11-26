//! What the kernel exports to drivers.
//!
//! One table drives three things: the import binder resolves names against
//! it, the boot log prints it, and the compatibility ledger is generated
//! from that log. An import with no entry here rejects the driver.
//!
//! An entry's `State` is an honest claim about the function behind it; see
//! `ledger/README.md`. Exports exist because a real driver in the fixture
//! corpus imports them, not to fill out the Windows export list.

mod trap;

use crate::rtl;

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum State {
    /// Does what the Windows routine does, for what the kernel supports.
    Implemented,
    /// Works for the subset the proof drivers use; gaps are documented at
    /// the function.
    Partial,
    /// Present so the driver loads; bugchecks by name if ever called
    /// (`trap`).
    Traps,
}

impl State {
    fn name(self) -> &'static str {
        match self {
            State::Implemented => "implemented",
            State::Partial => "partial",
            State::Traps => "traps",
        }
    }
}

pub struct Export {
    module: &'static str,
    name: &'static str,
    addr: *const (),
    state: State,
}

// SAFETY: an `Export` is immutable and its pointer names a function.
unsafe impl Sync for Export {}

const NT: &str = "ntoskrnl.exe";

macro_rules! export {
    ($state:ident, $path:path) => {
        Export {
            module: NT,
            name: {
                // The symbol is the last path segment.
                let full = stringify!($path).as_bytes();
                let mut start = full.len();
                while start > 0 && full[start - 1] != b':' {
                    start -= 1;
                }
                // SAFETY: `full` is ASCII and `start` is a char boundary.
                unsafe { core::str::from_utf8_unchecked(full.split_at(start).1) }
            },
            addr: $path as *const (),
            state: State::$state,
        }
    };
}

/// A variable, not a function: the import is bound to its address.
macro_rules! export_variable {
    ($state:ident, $name:literal, $variable:path) => {
        Export {
            module: NT,
            name: $name,
            addr: $variable.address(),
            state: State::$state,
        }
    };
}

/// A function entered through an assembly stub, exported under the
/// name drivers import, which is not the stub's.
macro_rules! export_entry {
    ($state:ident, $name:literal, $entry:path) => {
        Export {
            module: NT,
            name: $name,
            addr: $entry as *const (),
            state: State::$state,
        }
    };
}

/// A list of routines NK exports and does not implement: defines each
/// (see `trap`: it takes whatever the driver passed, looks at none of
/// it, and stops the system naming itself) and the list's `EXPORTS`.
macro_rules! trap_list {
    ($($name:ident),* $(,)?) => {
        $(
            #[doc = concat!("`", stringify!($name), "`: not implemented; stops the system.")]
            pub extern "C" fn $name(a: usize, b: usize, c: usize, d: usize) -> ! {
                crate::kd::bugcheck(format_args!(
                    concat!(
                        stringify!($name),
                        ": NK does not implement this routine (called with {:#x}, {:#x}, {:#x}, {:#x})"
                    ),
                    a, b, c, d
                ))
            }
        )*

        pub(in crate::export) static EXPORTS: &[Export] = &[
            $(
                Export {
                    module: NT,
                    name: stringify!($name),
                    addr: $name as *const (),
                    state: State::Traps,
                },
            )*
        ];
    };
}

mod list;

/// Every export, list after list.
fn all() -> impl Iterator<Item = &'static Export> {
    list::ALL.iter().flat_map(|exports| exports.iter())
}

/// The address a driver's import of `module!name` binds to.
///
/// `hal.dll` is another name for the kernel here. In the Windows build NK
/// follows, every export of `hal.dll` forwards to `ntoskrnl.exe`, and
/// which of the two a driver names for a routine differs by architecture.
pub fn resolve(module: &[u8], name: &[u8]) -> Option<u64> {
    if !is_kernel(module) {
        return None;
    }
    all()
        .find(|e| e.name.as_bytes() == name)
        .map(|e| e.addr as u64)
}

/// The routines Microsoft's kernel exports by number alone that a
/// binary NK loads imports, with the names its public symbols give
/// them. `acpi.sys` imports number 4.
const BY_ORDINAL: &[(u16, &str)] = &[(4, "ExAllocateTimerInternal2")];

/// The address a driver's import of `module!#ordinal` binds to: that
/// of the export NK has under the routine's name.
pub fn resolve_ordinal(module: &[u8], ordinal: u16) -> Option<u64> {
    let (_, name) = BY_ORDINAL.iter().find(|(number, _)| *number == ordinal)?;
    resolve(module, name.as_bytes())
}

/// Whether `module` names an extension API set
/// (`ext-ms-win-ntos-ksr-l1-1-3.dll`): a set of routines that a given
/// Windows may have no module for. Windows finds the host of a set in
/// its API-set schema; where there is none it leaves each import of the
/// set bound to the routine the importing image carries for that case,
/// which the linker put in the import's slot. NK hosts no extension
/// set, so that is what its loader does with every one.
pub fn is_extension_api_set(module: &[u8]) -> bool {
    module
        .get(..7)
        .is_some_and(|start| start.eq_ignore_ascii_case(b"ext-ms-"))
}

/// Whether `module` is a name the kernel's own exports go by: an
/// import from any other module is from a driver that exports.
pub fn is_kernel(module: &[u8]) -> bool {
    [NT, "hal.dll"]
        .iter()
        .any(|name| name.as_bytes().eq_ignore_ascii_case(module))
}

/// [`MmGetSystemRoutineAddress`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-mmgetsystemroutineaddress):
/// the address of a routine the kernel or the HAL exports, by name, or
/// null if there is none of that name. It is how a driver asks whether a
/// routine exists before relying on it.
///
/// A name that is not found is printed, `NK-LOOKUP <name> absent`: the
/// driver takes another path without it and no import table shows the
/// name, so the ledger lists these from the boot log.
///
/// # Safety
/// `name` points to a valid counted string.
#[allow(non_snake_case)]
pub unsafe extern "C" fn MmGetSystemRoutineAddress(
    name: *const nk_ntabi::io::UNICODE_STRING,
) -> *mut core::ffi::c_void {
    // SAFETY: per the contract.
    let wide = unsafe { rtl::copy_unicode(name) };
    // Export names are ASCII; a name that is not cannot match one.
    let mut ascii = [0u8; 128];
    let found = if wide.len() > ascii.len() || wide.iter().any(|&unit| unit > 0x7F) {
        None
    } else {
        for (byte, &unit) in ascii.iter_mut().zip(&wide) {
            *byte = unit as u8;
        }
        resolve(NT.as_bytes(), &ascii[..wide.len()])
    };
    match found {
        Some(addr) => addr as *mut core::ffi::c_void,
        None => {
            // One word, whatever the driver passed.
            let name: alloc::string::String = char::decode_utf16(wide.iter().copied())
                .map(|c| c.ok().filter(|c| c.is_ascii_graphic()).unwrap_or('?'))
                .collect();
            kprintln!("NK-LOOKUP {name} absent");
            ABSENT.fetch_add(1, core::sync::atomic::Ordering::Relaxed);
            core::ptr::null_mut()
        }
    }
}

/// Names asked for by `MmGetSystemRoutineAddress` and not found.
static ABSENT: core::sync::atomic::AtomicUsize = core::sync::atomic::AtomicUsize::new(0);

/// How many look-ups by name have found nothing, so far.
pub fn absent_lookups() -> usize {
    ABSENT.load(core::sync::atomic::Ordering::Relaxed)
}

/// Print the table for the ledger: `NK-EXPORT <module> <name> <state>`.
pub fn print_all() {
    for e in all() {
        kprintln!("NK-EXPORT {} {} {}", e.module, e.name, e.state.name());
    }
}
