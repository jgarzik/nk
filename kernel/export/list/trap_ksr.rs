//! Memory kept across a soft restart (the API set
//! `ext-ms-win-ntos-ksr`), which `acpi.sys` and `pci.sys` import and NK
//! does not implement: each stops the system, naming itself, if called.

#![allow(non_snake_case)]

use super::super::{Export, NT, State};

trap_list!(
    KsrClaimPersistedMemory,
    KsrEnumeratePersistedMemory,
    KsrFreePersistedMemory,
    KsrFreePersistedMemoryBlock,
    KsrGetFirmwareInformation,
    KsrMdlToMemoryRuns,
    KsrPersistMemory,
    KsrPersistMetadata,
    KsrQueryMetadata,
);
