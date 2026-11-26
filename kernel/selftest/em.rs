//! The errata manager, through the routines drivers import.

use crate::ex::em;
use crate::ob::object;
use crate::test::{Group, Report};
use core::ffi::c_void;
use nk_bootinfo::BootInfo;
use nk_ntabi::em::{EM_CALLBACK_REGISTRATION, EM_ENTRY_REGISTRATION};
use nk_ntabi::ex::GUID;
use nk_ntabi::status::{STATUS_INVALID_PARAMETER, STATUS_NOT_FOUND, STATUS_SUCCESS};

pub static GROUP: Group = Group {
    names: &["em.empty-database"],
    run,
    manual: false,
};

static SOME: GUID = GUID {
    Data1: 0x4E4B_0001,
    Data2: 2,
    Data3: 3,
    Data4: [4; 8],
};

extern "C" fn callback() -> u32 {
    0
}

fn empty_database() -> Result<(), &'static str> {
    // Any object stands for the driver: it is only referenced.
    let driver: *mut c_void = crate::ke::pcr::current_thread().cast();
    let none = core::ptr::null();
    let no_callbacks = core::ptr::null();
    let entries = [EM_ENTRY_REGISTRATION {
        EntryGuid: &raw const SOME,
        LazyEntryCallback: core::ptr::null_mut(),
        LazyCallbackContext: core::ptr::null_mut(),
    }];
    let callbacks = [EM_CALLBACK_REGISTRATION {
        CallbackGuid: &raw const SOME,
        CallbackFunction: callback as *mut c_void,
        Context: core::ptr::null_mut(),
    }];
    let mut handle: *mut c_void = core::ptr::null_mut();

    // SAFETY: arrays of one, a local for the handle, a live object.
    unsafe {
        // acpi.sys registers entries and callbacks: none is known.
        if em::EmProviderRegister(
            driver,
            entries.as_ptr(),
            1,
            callbacks.as_ptr(),
            1,
            &raw mut handle,
        ) != STATUS_NOT_FOUND
            || em::EmProviderRegister(driver, none, 0, callbacks.as_ptr(), 1, &raw mut handle)
                != STATUS_NOT_FOUND
            || !handle.is_null()
        {
            return Err("an entry type or callback was found in an empty database");
        }
        if em::EmProviderRegister(
            core::ptr::null_mut(),
            none,
            0,
            no_callbacks,
            0,
            &raw mut handle,
        ) != STATUS_INVALID_PARAMETER
            || em::EmProviderRegister(driver, none, 1, no_callbacks, 0, &raw mut handle)
                != STATUS_INVALID_PARAMETER
            || em::EmProviderRegister(driver, none, 0, no_callbacks, 0, core::ptr::null_mut())
                != STATUS_INVALID_PARAMETER
        {
            return Err("a registration without its arguments was not refused");
        }
        // A provider of nothing registers, and holds its driver object.
        let before = object::ObfReferenceObject(driver);
        if em::EmProviderRegister(driver, none, 0, no_callbacks, 0, &raw mut handle)
            != STATUS_SUCCESS
            || handle.is_null()
        {
            return Err("a provider of nothing did not register");
        }
        let held = object::ObfReferenceObject(driver);
        em::EmProviderDeregister(handle);
        em::EmProviderDeregister(core::ptr::null_mut());
        object::ObfDereferenceObject(driver);
        let after = object::ObfDereferenceObject(driver);
        if held != before + 2 || after != before - 1 {
            return Err("the provider's driver object was not referenced and released");
        }

        // A client's rule: unknown, and not found.
        let mut state = 7u32;
        if em::EmClientQueryRuleState(&raw const SOME, &raw mut state) != STATUS_NOT_FOUND
            || state != 1
        {
            return Err("a rule's state was not unknown and its rule not found");
        }
        state = 7;
        let input = [0usize; 2];
        if em::EmClientRuleEvaluate(&raw const SOME, input.as_ptr().cast(), 1, &raw mut state)
            != STATUS_NOT_FOUND
            || state != 1
        {
            return Err("an evaluated rule was not unknown and not found");
        }
        state = 7;
        if em::EmClientQueryRuleState(core::ptr::null(), &raw mut state) != STATUS_INVALID_PARAMETER
            || em::EmClientRuleEvaluate(&raw const SOME, input.as_ptr().cast(), 0, &raw mut state)
                != STATUS_INVALID_PARAMETER
            || state != 7
        {
            return Err("a question without its arguments was not refused");
        }
    }
    Ok(())
}

fn run(r: &mut Report, _: &BootInfo) {
    r.check("em.empty-database", empty_database);
}

/// This file's test groups, in the order they run.
pub static GROUPS: &[&Group] = &[&GROUP];
