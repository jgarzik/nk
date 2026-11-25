//! Privilege checks: does a token hold these privileges, enabled.
//!
//! [SePrivilegeCheck] and [SeSinglePrivilegeCheck] state the rules: only
//! enabled privileges count, all of the set or any one of it as the
//! set's control says, and a kernel-mode caller holds everything.
//!
//! INFERRED, for the conformance drivers: a privilege found enabled has
//! `SE_PRIVILEGE_USED_FOR_ACCESS` added to its attributes, the other
//! bits kept; one not found is left as it was; "any" of an empty set is
//! refused.
//!
//! [SePrivilegeCheck]: https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-seprivilegecheck
//! [SeSinglePrivilegeCheck]: https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-sesingleprivilegecheck

use crate::token::{Luid, Privilege, SE_PRIVILEGE_USED_FOR_ACCESS, Token};

/// `PRIVILEGE_SET.Control`: every privilege of the set is needed. Zero:
/// any one will do.
pub const PRIVILEGE_SET_ALL_NECESSARY: u32 = 1;

/// `SePrivilegeCheck`: whether `token` has the privileges of `required`
/// enabled, all or any as `control` says. Each one it has is marked
/// `SE_PRIVILEGE_USED_FOR_ACCESS`; in kernel mode all are, and the
/// answer is yes.
pub fn privilege_check(
    token: &Token,
    control: u32,
    required: &mut [Privilege],
    kernel_mode: bool,
) -> bool {
    let mut held = 0;
    for privilege in required.iter_mut() {
        if kernel_mode || token.privilege_enabled(privilege.luid) {
            privilege.attributes |= SE_PRIVILEGE_USED_FOR_ACCESS;
            held += 1;
        }
    }
    if kernel_mode || control & PRIVILEGE_SET_ALL_NECESSARY != 0 {
        held == required.len()
    } else {
        held > 0
    }
}

/// `SeSinglePrivilegeCheck`: whether `token` has `privilege` enabled. A
/// kernel-mode caller always does.
pub fn single_privilege_check(token: &Token, privilege: Luid, kernel_mode: bool) -> bool {
    kernel_mode || token.privilege_enabled(privilege)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::token::{
        SE_CHANGE_NOTIFY_PRIVILEGE, SE_DEBUG_PRIVILEGE, SE_SECURITY_PRIVILEGE, SE_TCB_PRIVILEGE,
    };

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
            name: "kernel mode holds everything",
            control: ALL,
            kernel: true,
            set: &[(OFF, 0, USED), (ABSENT, 0, USED)],
            answer: true,
        },
        Case {
            name: "kernel mode: any",
            control: ANY,
            kernel: true,
            set: &[(ABSENT, 0, USED)],
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

    #[test]
    fn the_case_table() {
        let token = Token::system();
        for case in CASES {
            let mut set: Vec<Privilege> = case
                .set
                .iter()
                .map(|&(luid, attributes, _)| Privilege { luid, attributes })
                .collect();
            let answer = privilege_check(&token, case.control, &mut set, case.kernel);
            assert_eq!(answer, case.answer, "{}", case.name);
            for (after, &(luid, _, attributes)) in set.iter().zip(case.set) {
                assert_eq!(*after, Privilege { luid, attributes }, "{}", case.name);
            }
        }
    }

    #[test]
    fn one_privilege() {
        let token = Token::system();
        assert!(single_privilege_check(&token, ON, false));
        assert!(single_privilege_check(
            &token,
            SE_CHANGE_NOTIFY_PRIVILEGE,
            false
        ));
        assert!(!single_privilege_check(&token, OFF, false));
        assert!(!single_privilege_check(&token, ABSENT, false));
        assert!(single_privilege_check(&token, OFF, true));
        assert!(single_privilege_check(&token, ABSENT, true));
    }
}
