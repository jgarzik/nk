//! The errata manager, through the routines drivers import.

use crate::ex::em;
use crate::ob::object;
use crate::test::{Group, Report};
use core::ffi::c_void;
use nk_bootinfo::BootInfo;
use nk_ntabi::em::{EM_CALLBACK_REGISTRATION, EM_ENTRY_REGISTRATION};
use nk_ntabi::ex::GUID;
use nk_ntabi::status::{STATUS_INVALID_PARAMETER, STATUS_OBJECT_NAME_COLLISION, STATUS_SUCCESS};

pub static GROUP: Group = Group {
    names: &["em.providers", "em.no-rules"],
    run,
    manual: false,
};

static ENTRY: GUID = GUID {
    Data1: 0x4E4B_0001,
    Data2: 2,
    Data3: 3,
    Data4: [4; 8],
};

static CALLBACK: GUID = GUID {
    Data1: 0x4E4B_0002,
    Data2: 2,
    Data3: 3,
    Data4: [4; 8],
};

extern "C" fn callback() -> u32 {
    0
}

extern "C" fn other_callback() -> u32 {
    1
}

fn providers() -> Result<(), &'static str> {
    // Any object stands for the driver: it is only referenced.
    let driver: *mut c_void = crate::ke::pcr::current_thread().cast();
    let no_entries = core::ptr::null();
    let no_callbacks = core::ptr::null();
    let entries = [EM_ENTRY_REGISTRATION {
        EntryGuid: &raw const ENTRY,
        LazyEntryCallback: core::ptr::null_mut(),
        LazyCallbackContext: core::ptr::null_mut(),
    }];
    let callbacks = [EM_CALLBACK_REGISTRATION {
        CallbackGuid: &raw const CALLBACK,
        CallbackFunction: callback as *mut c_void,
        Context: core::ptr::null_mut(),
    }];
    let others = [EM_CALLBACK_REGISTRATION {
        CallbackFunction: other_callback as *mut c_void,
        ..callbacks[0]
    }];
    let nameless = [EM_ENTRY_REGISTRATION {
        EntryGuid: core::ptr::null(),
        ..entries[0]
    }];
    let mut handle: *mut c_void = core::ptr::null_mut();
    let mut second: *mut c_void = core::ptr::null_mut();
    let out = &raw mut handle;

    // SAFETY: arrays of one, locals for the handles, a live object.
    unsafe {
        if em::EmProviderRegister(core::ptr::null_mut(), no_entries, 0, no_callbacks, 0, out)
            != STATUS_INVALID_PARAMETER
            || em::EmProviderRegister(driver, no_entries, 1, no_callbacks, 0, out)
                != STATUS_INVALID_PARAMETER
            || em::EmProviderRegister(driver, no_entries, 0, no_callbacks, 1, out)
                != STATUS_INVALID_PARAMETER
            || em::EmProviderRegister(
                driver,
                no_entries,
                0,
                no_callbacks,
                0,
                core::ptr::null_mut(),
            ) != STATUS_INVALID_PARAMETER
            || em::EmProviderRegister(driver, nameless.as_ptr(), 1, no_callbacks, 0, out)
                != STATUS_INVALID_PARAMETER
            || !handle.is_null()
        {
            return Err("a registration without its arguments was not refused");
        }

        // A provider registers, as pci.sys and acpi.sys do, and holds
        // its driver object.
        let before = object::ObfReferenceObject(driver);
        if em::EmProviderRegister(driver, entries.as_ptr(), 1, callbacks.as_ptr(), 1, out)
            != STATUS_SUCCESS
            || handle.is_null()
        {
            return Err("a provider did not register");
        }
        if em::registered(&CALLBACK, &ENTRY) != (Some(callback as *const () as usize), 1) {
            return Err("the database does not hold what the provider registered");
        }
        // Another routine for the same callback collides.
        if em::EmProviderRegister(driver, no_entries, 0, others.as_ptr(), 1, &raw mut second)
            != STATUS_OBJECT_NAME_COLLISION
            || !second.is_null()
        {
            return Err("a second routine for a callback was not refused");
        }
        let held = object::ObfReferenceObject(driver);
        em::EmProviderDeregister(handle);
        em::EmProviderDeregister(core::ptr::null_mut());
        object::ObfDereferenceObject(driver);
        let after = object::ObfDereferenceObject(driver);
        if held != before + 2 || after != before - 1 {
            return Err("the provider's driver object was not referenced and released");
        }
        if em::registered(&CALLBACK, &ENTRY) != (None, 0) {
            return Err("a deregistered provider is still in the database");
        }
    }
    Ok(())
}

fn no_rules() -> Result<(), &'static str> {
    let mut state = 7u32;
    let input = [0usize; 2];
    // SAFETY: a GUID, and locals for the state and the entries.
    unsafe {
        // pci.sys does not load unless each rule it asks about is
        // answered: defined, and not applying.
        if em::EmClientQueryRuleState(&raw const ENTRY, &raw mut state) != STATUS_SUCCESS
            || state != 0
        {
            return Err("a rule was not reported as defined and not applying");
        }
        state = 7;
        if em::EmClientRuleEvaluate(&raw const ENTRY, input.as_ptr().cast(), 1, &raw mut state)
            != STATUS_SUCCESS
            || state != 0
        {
            return Err("an evaluated rule was not reported as not applying");
        }
        state = 7;
        if em::EmClientQueryRuleState(core::ptr::null(), &raw mut state) != STATUS_INVALID_PARAMETER
            || em::EmClientRuleEvaluate(&raw const ENTRY, input.as_ptr().cast(), 0, &raw mut state)
                != STATUS_INVALID_PARAMETER
            || em::EmClientQueryRuleState(&raw const ENTRY, core::ptr::null_mut())
                != STATUS_INVALID_PARAMETER
            || state != 7
        {
            return Err("a question without its arguments was not refused");
        }
    }
    Ok(())
}

fn run(r: &mut Report, _: &BootInfo) {
    r.check("em.providers", providers);
    r.check("em.no-rules", no_rules);
}

/// This file's test groups, in the order they run.
pub static GROUPS: &[&Group] = &[&GROUP];
