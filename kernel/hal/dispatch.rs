//! The HAL's dispatch tables, `HalDispatchTable` and
//! `HalPrivateDispatchTable`: exported variables through which
//! Microsoft's bus drivers call the HAL, and into which they store
//! routines of their own for the HAL and each other to call. The slots
//! are listed in `nk_ntabi::hal`.
//!
//! A slot NK has no routine for holds a trap that stops the system
//! naming the table and the slot, as an unimplemented export does
//! (`export::trap`): never null, which a driver would take for "this
//! HAL has no such service" or jump through.
//!
//! The tables are memory drivers write, so NK reads a slot as an atomic
//! and holds no reference into them.

#![allow(non_snake_case, non_upper_case_globals)]

use core::sync::atomic::{AtomicPtr, AtomicU64, Ordering};
use nk_ntabi::hal::{
    FIRST_SLOT, HAL_DISPATCH_SLOTS, HAL_DISPATCH_VERSION, HAL_PRIVATE_DISPATCH_SLOTS,
    HAL_PRIVATE_DISPATCH_VERSION, slot_offset,
};

/// A version number, padded to a pointer, and then `N` routines.
#[repr(C)]
pub struct Table<const N: usize> {
    version: AtomicU64,
    slots: [AtomicPtr<()>; N],
}

impl<const N: usize> Table<N> {
    /// The address drivers import.
    pub const fn address(&'static self) -> *const () {
        core::ptr::from_ref(self).cast()
    }

    /// The routine in the slot at `offset` now: NK's, or the one a
    /// driver stored.
    pub fn routine(&self, offset: usize) -> *mut () {
        self.slots[(offset - FIRST_SLOT) / 8].load(Ordering::Acquire)
    }

    /// Put NK's routine in the slot at `offset`.
    pub fn provide(&self, offset: usize, routine: *const ()) {
        self.slots[(offset - FIRST_SLOT) / 8].store(routine.cast_mut(), Ordering::Release);
    }

    /// The version drivers read.
    pub fn version(&self) -> u32 {
        self.version.load(Ordering::Relaxed) as u32
    }
}

/// The offset of the slot `name` of `HalDispatchTable`.
pub const fn public_slot(name: &str) -> usize {
    match slot_offset(HAL_DISPATCH_SLOTS, name) {
        Some(offset) => offset,
        None => panic!("no such slot in HalDispatchTable"),
    }
}

/// The offset of the slot `name` of `HalPrivateDispatchTable`.
pub const fn private_slot(name: &str) -> usize {
    match slot_offset(HAL_PRIVATE_DISPATCH_SLOTS, name) {
        Some(offset) => offset,
        None => panic!("no such slot in HalPrivateDispatchTable"),
    }
}

/// Define a table whose every slot holds a trap naming it.
macro_rules! table {
    ($table:ident, $traps:ident, $slots:expr, $version:expr; $($slot:ident),* $(,)?) => {
        mod $traps {
            $(
                pub extern "C" fn $slot() -> ! {
                    crate::kd::bugcheck(format_args!(concat!(
                        stringify!($table),
                        ".",
                        stringify!($slot),
                        ": NK does not implement this routine"
                    )))
                }
            )*
        }

        #[doc = concat!("`", stringify!($table), "`, as drivers import it.")]
        pub static $table: Table<{ $slots.len() }> = Table {
            version: AtomicU64::new($version as u64),
            slots: [$(AtomicPtr::new($traps::$slot as *mut ())),*],
        };
    };
}

macro_rules! public {
    ($($slot:ident),* $(,)?) => {
        table!(HalDispatchTable, public_traps, HAL_DISPATCH_SLOTS, HAL_DISPATCH_VERSION; $($slot),*);
    };
}

macro_rules! private {
    ($($slot:ident),* $(,)?) => {
        table!(
            HalPrivateDispatchTable,
            private_traps,
            HAL_PRIVATE_DISPATCH_SLOTS,
            HAL_PRIVATE_DISPATCH_VERSION;
            $($slot),*
        );
    };
}

nk_ntabi::hal_dispatch_slots!(public);
nk_ntabi::hal_private_dispatch_slots!(private);

/// For the self-tests: the tables are what the imports bind to, laid
/// out as Windows', every slot holding a routine.
pub fn layout_test() -> Result<(), &'static str> {
    let import = |name: &[u8]| crate::export::resolve(b"ntoskrnl.exe", name);
    if import(b"HalDispatchTable") != Some(HalDispatchTable.address() as u64)
        || import(b"HalPrivateDispatchTable") != Some(HalPrivateDispatchTable.address() as u64)
        || crate::export::resolve(b"HAL.dll", b"HalDispatchTable") != import(b"HalDispatchTable")
    {
        return Err("an import of a dispatch table is not bound to the table");
    }
    if HalDispatchTable.version() != 4 || HalPrivateDispatchTable.version() != 0x33 {
        return Err("a dispatch table does not start with Windows' version");
    }
    if size_of_val(&HalDispatchTable) != 0xb8 || size_of_val(&HalPrivateDispatchTable) != 1200 {
        return Err("a dispatch table is not the size of Windows'");
    }
    // SAFETY: a table is a version and then pointers, all initialised;
    // read as a driver reads it, by offset from the imported address.
    let slot = |table: *const (), offset: usize| unsafe {
        table.cast::<u8>().add(offset).cast::<*mut ()>().read()
    };
    let power = public_slot("HalInitPowerManagement");
    let assign = private_slot("HalPciAssignSlotResources");
    if power != 0x68
        || assign != 0x40
        || slot(HalDispatchTable.address(), power) != HalDispatchTable.routine(power)
        || slot(HalPrivateDispatchTable.address(), assign)
            != HalPrivateDispatchTable.routine(assign)
    {
        return Err("a slot is not where Windows has it");
    }
    let empty = (FIRST_SLOT..0xb8)
        .step_by(8)
        .any(|offset| HalDispatchTable.routine(offset).is_null())
        || (FIRST_SLOT..1200)
            .step_by(8)
            .any(|offset| HalPrivateDispatchTable.routine(offset).is_null());
    if empty {
        return Err("a slot holds no routine");
    }
    // A routine NK provides is what a driver then reads from the slot.
    let spare = public_slot("Spare1");
    let trap = HalDispatchTable.routine(spare);
    HalDispatchTable.provide(spare, layout_test as *const ());
    let provided = slot(HalDispatchTable.address(), spare);
    HalDispatchTable.provide(spare, trap);
    if provided != layout_test as *mut () {
        return Err("a routine NK provided is not what the slot holds");
    }
    Ok(())
}
