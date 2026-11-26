//! Routines NK exports and does not implement: each stops the system,
//! naming itself, if a driver ever calls it.
//!
//! A trap exists so that a driver which imports the routine loads; it
//! is right only for a routine the driver does not reach on the paths
//! NK runs it down. It is never a success: nothing returns from one.
//! Which routines trap, and why, is in `doc/DESIGN.md`, "What is
//! absent".

#![allow(non_snake_case)]

/// Define, for each name, the routine a driver's import of that name is
/// bound to: it takes whatever the driver passed, looks at none of it,
/// and stops the system with
/// `BUGCHECK: <name>: NK does not implement this routine`.
///
/// The routine declares no parameters. Both calling conventions NK
/// serves leave the arguments to the caller to pass and to clean up,
/// so a routine that reads none is callable with any.
macro_rules! traps {
    ($($name:ident),* $(,)?) => {
        $(
            #[doc = concat!("`", stringify!($name), "`: not implemented; stops the system.")]
            pub extern "C" fn $name() -> ! {
                crate::kd::bugcheck(format_args!(concat!(
                    stringify!($name),
                    ": NK does not implement this routine"
                )))
            }
        )*
    };
}

// Advanced local procedure calls: `msrpc.sys` is the transport of RPC
// over ALPC ports, and NK has no ALPC.
traps!(
    ZwAlpcCancelMessage,
    ZwAlpcConnectPort,
    ZwAlpcConnectPortEx,
    ZwAlpcCreatePortSection,
    ZwAlpcCreateResourceReserve,
    ZwAlpcCreateSectionView,
    ZwAlpcCreateSecurityContext,
    ZwAlpcDeletePortSection,
    ZwAlpcDeleteSectionView,
    ZwAlpcDeleteSecurityContext,
    ZwAlpcDisconnectPort,
    ZwAlpcQueryInformation,
    ZwAlpcQueryInformationMessage,
    ZwAlpcSendWaitReceivePort,
    ZwAlpcSetInformation,
);

// I/O completion ports, which `msrpc.sys` waits on for its ALPC
// messages.
traps!(
    IoSetIoCompletionEx,
    ZwCreateIoCompletion,
    ZwRemoveIoCompletionEx,
);
