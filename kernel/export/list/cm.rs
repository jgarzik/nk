//! Exports implemented in `kernel/cm`.

use super::super::{Export, NT, State};
use crate::cm;

pub(in crate::export) static EXPORTS: &[Export] = &[
    export!(Implemented, cm::RtlQueryRegistryValues),
    export!(Implemented, cm::RtlQueryRegistryValuesEx),
    export!(Implemented, cm::ZwCreateKey),
    export!(Implemented, cm::ZwDeleteKey),
    export!(Implemented, cm::ZwDeleteValueKey),
    export!(Partial, cm::notify::ZwNotifyChangeKey),
    export!(Implemented, cm::ZwEnumerateKey),
    export!(Implemented, cm::ZwEnumerateValueKey),
    export!(Implemented, cm::ZwOpenKey),
    export!(Implemented, cm::ZwQueryKey),
    export!(Implemented, cm::ZwQueryValueKey),
    export!(Implemented, cm::ZwSetValueKey),
    export!(Implemented, cm::RtlCheckRegistryKey),
    export!(Implemented, cm::RtlCreateRegistryKey),
    export!(Implemented, cm::RtlDeleteRegistryValue),
    export!(Implemented, cm::RtlWriteRegistryValue),
];
