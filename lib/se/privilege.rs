//! Privilege checks: does a subject hold these privileges, enabled.
//!
//! [SePrivilegeCheck] and [SeSinglePrivilegeCheck] state the rules: only
//! enabled privileges count, all of the set or any one of it as the
//! set's control says, and a kernel-mode caller holds everything. The
//! particulars are the pinned Windows kernel's, read from its code:
//!
//! - for a kernel-mode caller the answer is yes and the set is left as
//!   it was;
//! - a subject that impersonates below `SecurityImpersonation` holds
//!   nothing, and the set is left as it was;
//! - otherwise every privilege of the set has
//!   `SE_PRIVILEGE_USED_FOR_ACCESS` cleared, then set if the token has
//!   it enabled; the other attribute bits are kept;
//! - "all" of an empty set is held, "any" of it is not.
//!
//! [SePrivilegeCheck]: https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-seprivilegecheck
//! [SeSinglePrivilegeCheck]: https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntddk/nf-ntddk-sesingleprivilegecheck

use crate::token::{Luid, Privilege, SE_PRIVILEGE_USED_FOR_ACCESS, SECURITY_IMPERSONATION, Token};

/// `PRIVILEGE_SET.Control`: every privilege of the set is needed. Zero:
/// any one will do.
pub const PRIVILEGE_SET_ALL_NECESSARY: u32 = 1;

/// `SePrivilegeCheck`: whether the subject has the privileges of
/// `required` enabled, all or any as `control` says. `token` is the
/// subject's (`access::subject_token`) and `impersonation_level` the
/// level at which it impersonates, if it does.
pub fn privilege_check(
    token: &Token,
    impersonation_level: Option<u32>,
    control: u32,
    required: &mut [Privilege],
    kernel_mode: bool,
) -> bool {
    if kernel_mode {
        return true;
    }
    if impersonation_level.is_some_and(|level| level < SECURITY_IMPERSONATION) {
        return false;
    }
    let mut held = 0;
    for privilege in required.iter_mut() {
        privilege.attributes &= !SE_PRIVILEGE_USED_FOR_ACCESS;
        if token.privilege_enabled(privilege.luid) {
            privilege.attributes |= SE_PRIVILEGE_USED_FOR_ACCESS;
            held += 1;
        }
    }
    if control & PRIVILEGE_SET_ALL_NECESSARY != 0 {
        held == required.len()
    } else {
        held > 0
    }
}

/// `SeSinglePrivilegeCheck`: whether the subject has `privilege`
/// enabled: a check of a set of that one, all necessary.
pub fn single_privilege_check(
    token: &Token,
    impersonation_level: Option<u32>,
    privilege: Luid,
    kernel_mode: bool,
) -> bool {
    let mut set = [Privilege {
        luid: privilege,
        attributes: 0,
    }];
    privilege_check(
        token,
        impersonation_level,
        PRIVILEGE_SET_ALL_NECESSARY,
        &mut set,
        kernel_mode,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::token::{
        SE_CHANGE_NOTIFY_PRIVILEGE, SE_DEBUG_PRIVILEGE, SE_SECURITY_PRIVILEGE, SE_TCB_PRIVILEGE,
        SECURITY_IDENTIFICATION,
    };
    use alloc::vec::Vec;

    const ALL: u32 = PRIVILEGE_SET_ALL_NECESSARY;
    const ANY: u32 = 0;
    const USED: u32 = SE_PRIVILEGE_USED_FOR_ACCESS;
    /// Not in the SYSTEM token at all (`SeUnsolicitedInputPrivilege`).
    const ABSENT: Luid = 6;
    /// In it, disabled.
    const OFF: Luid = SE_SECURITY_PRIVILEGE;
    const ON: Luid = SE_TCB_PRIVILEGE;
    const ON_TOO: Luid = SE_DEBUG_PRIVILEGE;

    struct Case {
        name: &'static str,
        control: u32,
        kernel: bool,
        /// (privilege, attributes before, attributes after)
        set: &'static [(Luid, u32, u32)],
        answer: bool,
    }

    /// Against the SYSTEM token.
    const CASES: &[Case] = &[
        Case {
            name: "all: every one enabled",
            control: ALL,
            kernel: false,
            set: &[(ON, 0, USED), (ON_TOO, 0, USED)],
            answer: true,
        },
        Case {
            name: "all: one disabled",
            control: ALL,
            kernel: false,
            set: &[(ON, 0, USED), (OFF, 0, 0)],
            answer: false,
        },
        Case {
            name: "all: one not held",
            control: ALL,
            kernel: false,
            set: &[(ABSENT, 0, 0), (ON, 0, USED)],
            answer: false,
        },
        Case {
            name: "any: one enabled is enough",
            control: ANY,
            kernel: false,
            set: &[(OFF, 0, 0), (ON, 0, USED), (ABSENT, 0, 0)],
            answer: true,
        },
        Case {
            name: "any: none enabled",
            control: ANY,
            kernel: false,
            set: &[(OFF, 0, 0), (ABSENT, 0, 0)],
            answer: false,
        },
        Case {
            name: "the other attribute bits are kept",
            control: ALL,
            kernel: false,
            set: &[(ON, 3, USED | 3), (OFF, 3, 3)],
            answer: false,
        },
        Case {
            name: "a mark left from before is cleared",
            control: ANY,
            kernel: false,
            set: &[(OFF, USED | 1, 1), (ON, USED, USED)],
            answer: true,
        },
        Case {
            name: "all of nothing",
            control: ALL,
            kernel: false,
            set: &[],
            answer: true,
        },
        Case {
            name: "any of nothing",
            control: ANY,
            kernel: false,
            set: &[],
            answer: false,
        },
        Case {
            name: "kernel mode holds everything and marks nothing",
            control: ALL,
            kernel: true,
            set: &[(OFF, 0, 0), (ABSENT, USED, USED)],
            answer: true,
        },
        Case {
            name: "kernel mode: any",
            control: ANY,
            kernel: true,
            set: &[(ABSENT, 0, 0)],
            answer: true,
        },
        Case {
            name: "kernel mode: any of nothing",
            control: ANY,
            kernel: true,
            set: &[],
            answer: true,
        },
    ];

    fn set_of(case: &Case) -> Vec<Privilege> {
        case.set
            .iter()
            .map(|&(luid, attributes, _)| Privilege { luid, attributes })
            .collect()
    }

    #[test]
    fn the_case_table() {
        let token = Token::system();
        for case in CASES {
            let mut set = set_of(case);
            let answer = privilege_check(&token, None, case.control, &mut set, case.kernel);
            assert_eq!(answer, case.answer, "{}", case.name);
            for (after, &(luid, _, attributes)) in set.iter().zip(case.set) {
                assert_eq!(*after, Privilege { luid, attributes }, "{}", case.name);
            }
        }
    }

    #[test]
    fn a_client_must_be_impersonated_to_hold_anything() {
        let token = Token::system();
        let case = &CASES[0];
        // At the impersonation level: as if the token were its own.
        let mut set = set_of(case);
        assert!(privilege_check(
            &token,
            Some(SECURITY_IMPERSONATION),
            ALL,
            &mut set,
            false
        ));
        // Below it: nothing held, nothing touched.
        let mut set = set_of(case);
        set[0].attributes = USED | 1;
        let before = set.clone();
        let level = Some(SECURITY_IDENTIFICATION);
        assert!(!privilege_check(&token, level, ALL, &mut set, false));
        assert!(!privilege_check(&token, level, ANY, &mut set, false));
        assert_eq!(set, before);
        // Kernel mode does not ask who.
        assert!(privilege_check(&token, level, ALL, &mut set, true));
        assert!(!single_privilege_check(&token, level, ON, false));
    }

    #[test]
    fn one_privilege() {
        let token = Token::system();
        assert!(single_privilege_check(&token, None, ON, false));
        assert!(single_privilege_check(
            &token,
            None,
            SE_CHANGE_NOTIFY_PRIVILEGE,
            false
        ));
        assert!(!single_privilege_check(&token, None, OFF, false));
        assert!(!single_privilege_check(&token, None, ABSENT, false));
        assert!(single_privilege_check(&token, None, OFF, true));
        assert!(single_privilege_check(&token, None, ABSENT, true));
    }

    #[test]
    fn a_privilege_is_known_by_the_low_six_bits_of_its_number() {
        let token = Token::system();
        // The high part of the LUID is not looked at, and the low part
        // counts modulo 64: Windows keeps a token's privileges as the
        // bits of a 64-bit word.
        assert!(single_privilege_check(&token, None, ON | 5 << 32, false));
        assert!(single_privilege_check(&token, None, ON + 64, false));
        assert!(!single_privilege_check(&token, None, OFF + 64, false));
    }
}
