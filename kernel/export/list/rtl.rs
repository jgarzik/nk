//! Exports implemented in `kernel/rtl`.

use super::super::{Export, NT, State};
use crate::rtl;

pub(in crate::export) static EXPORTS: &[Export] = &[
    export!(Implemented, rtl::RtlGetVersion),
    export!(Implemented, rtl::RtlInitUnicodeString),
    export_entry!(Implemented, "DbgPrint", rtl::print::nk_variadic_DbgPrint),
    export!(Implemented, rtl::name::FsRtlIsNameInExpression),
    export_variable!(
        Implemented,
        "FsRtlLegalAnsiCharacterArray",
        rtl::name::FsRtlLegalAnsiCharacterArray
    ),
    export!(Implemented, rtl::string::RtlCompareMemory),
    export!(Implemented, rtl::prefix::RtlFindUnicodePrefix),
    export!(Implemented, rtl::string::RtlFreeAnsiString),
    export!(Implemented, rtl::print::RtlFreeUnicodeString),
    export!(Implemented, rtl::prefix::RtlInitializeUnicodePrefix),
    export!(Implemented, rtl::prefix::RtlInsertUnicodePrefix),
    export!(Implemented, rtl::string::RtlMultiByteToUnicodeN),
    export!(Implemented, rtl::string::RtlPrefixUnicodeString),
    export!(Implemented, rtl::prefix::RtlRemoveUnicodePrefix),
    export!(Implemented, rtl::string::RtlStringFromGUID),
    export!(Implemented, rtl::string::RtlUnicodeStringToAnsiString),
    export!(Implemented, rtl::string::RtlUnicodeToMultiByteN),
    export!(Implemented, rtl::string::RtlUpcaseUnicodeChar),
    export!(Implemented, rtl::string::RtlUpcaseUnicodeString),
    export_entry!(
        Implemented,
        "_snwprintf",
        rtl::print::nk_variadic__snwprintf
    ),
    export!(Implemented, rtl::crt::_stricmp),
    export!(Implemented, rtl::print::_vsnwprintf),
    export!(Implemented, rtl::crt::_wcsicmp),
    export!(Implemented, rtl::print::_wcsnicmp),
    export!(Implemented, rtl::crt::strncmp),
    export!(Implemented, rtl::crt::strrchr),
    export!(Implemented, rtl::print::wcschr),
    export!(Implemented, rtl::crt::wcsstr),
    export!(Implemented, rtl::feature::RtlNotifyFeatureUsage),
    export!(Implemented, rtl::feature::RtlQueryFeatureConfiguration),
    export!(
        Implemented,
        rtl::feature::RtlQueryFeatureConfigurationChangeStamp
    ),
    export!(
        Implemented,
        rtl::feature::RtlRegisterFeatureConfigurationChangeNotification
    ),
    export!(
        Implemented,
        rtl::feature::RtlUnregisterFeatureConfigurationChangeNotification
    ),
];
