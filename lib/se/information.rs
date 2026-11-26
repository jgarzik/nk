//! What a token answers when asked about itself
//! (`SeQueryInformationToken`), as the bytes the caller receives.
//!
//! [SeQueryInformationToken] hands most classes back in a pool block it
//! allocates, and two (`TokenSessionId`, `TokenIntegrityLevel`) as "a
//! DWORD value (not a pointer to it)" stored where the block's address
//! would go. `token_information` returns which, with the bytes.
//!
//! A block that holds pointers (to a SID or an ACL later in the same
//! block) needs the address it will live at. The caller asks twice:
//! once with any `base` to learn the length, then, the block allocated,
//! with its address; it copies the second answer in.
//!
//! The layouts are the structures of `ntifs.h` for a 64-bit system
//! ([TOKEN_INFORMATION_CLASS] links each one): a count or pointers
//! first, the SIDs or the ACL packed after them in order.
//!
//! Which classes are values, that `TokenIsAppContainer` is one of them,
//! that a block is exactly as long as its parts, and that
//! `TokenImpersonationLevel` of a primary token fails with
//! `STATUS_INVALID_INFO_CLASS` are the pinned kernel's, read from its
//! code.
//!
//! INFERRED, for the conformance drivers: the variable parts follow the
//! fixed part in the order of the array; a token without a default
//! DACL answers a null pointer; `TokenGroups` includes the integrity
//! label.
//!
//! Not done: every other class (`TokenSource`, restricted SIDs, linked
//! tokens, claims, capabilities, ...).
//!
//! [SeQueryInformationToken]: https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-sequeryinformationtoken
//! [TOKEN_INFORMATION_CLASS]: https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/ne-ntifs-_token_information_class

use crate::token::{Token, TokenType};
use alloc::vec::Vec;

/// `TOKEN_INFORMATION_CLASS` values answered here.
pub const TOKEN_USER: u32 = 1;
pub const TOKEN_GROUPS: u32 = 2;
pub const TOKEN_PRIVILEGES: u32 = 3;
pub const TOKEN_OWNER: u32 = 4;
pub const TOKEN_PRIMARY_GROUP: u32 = 5;
pub const TOKEN_DEFAULT_DACL: u32 = 6;
pub const TOKEN_TYPE: u32 = 8;
pub const TOKEN_IMPERSONATION_LEVEL: u32 = 9;
pub const TOKEN_STATISTICS: u32 = 10;
pub const TOKEN_SESSION_ID: u32 = 12;
pub const TOKEN_INTEGRITY_LEVEL: u32 = 25;
pub const TOKEN_IS_APP_CONTAINER: u32 = 29;

/// An answer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Information {
    /// A number, stored in the caller's variable itself.
    Value(u32),
    /// The contents of a pool block, whose address the caller's
    /// variable receives.
    Block(Vec<u8>),
}

/// Why there is no answer, as the status Windows gives.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QueryError {
    /// `STATUS_INVALID_INFO_CLASS`
    InvalidInfoClass,
}

/// `SeQueryInformationToken`: what `token` answers for `class`. `base`
/// is the address a block will have; pointers in it are made from it.
pub fn token_information(token: &Token, class: u32, base: u64) -> Result<Information, QueryError> {
    let block = match class {
        // TOKEN_USER: one SID_AND_ATTRIBUTES.
        TOKEN_USER => sids(base, &[], &[(&token.user.sid, token.user.attributes)]),
        // TOKEN_GROUPS: the count, padding, then the array.
        TOKEN_GROUPS => {
            let groups: Vec<(&[u8], u32)> = token
                .groups
                .iter()
                .map(|group| (&group.sid[..], group.attributes))
                .collect();
            let count = (groups.len() as u64).to_le_bytes();
            sids(base, &count, &groups)
        }
        // TOKEN_PRIVILEGES: the count, then LUID_AND_ATTRIBUTES of 12
        // bytes each.
        TOKEN_PRIVILEGES => {
            let mut block = (token.privileges.len() as u32).to_le_bytes().to_vec();
            for privilege in &token.privileges {
                block.extend(privilege.luid.to_le_bytes());
                block.extend(privilege.attributes.to_le_bytes());
            }
            block
        }
        // TOKEN_OWNER, TOKEN_PRIMARY_GROUP, TOKEN_DEFAULT_DACL: one
        // pointer, then what it points to.
        TOKEN_OWNER => pointed(base, Some(&token.owner)),
        TOKEN_PRIMARY_GROUP => pointed(base, Some(&token.primary_group)),
        TOKEN_DEFAULT_DACL => pointed(base, token.default_dacl.as_deref()),
        TOKEN_TYPE => (token.token_type as u32).to_le_bytes().to_vec(),
        TOKEN_IMPERSONATION_LEVEL if token.token_type == TokenType::Impersonation => {
            token.impersonation_level.to_le_bytes().to_vec()
        }
        TOKEN_STATISTICS => {
            let mut block = Vec::with_capacity(56);
            block.extend(token.token_id.to_le_bytes());
            block.extend(token.authentication_id.to_le_bytes());
            block.extend(token.expiration_time.to_le_bytes());
            block.extend((token.token_type as u32).to_le_bytes());
            block.extend(token.impersonation_level.to_le_bytes());
            block.extend(token.dynamic_charged.to_le_bytes());
            block.extend(token.dynamic_available.to_le_bytes());
            block.extend((token.groups.len() as u32).to_le_bytes());
            block.extend((token.privileges.len() as u32).to_le_bytes());
            block.extend(token.modified_id.to_le_bytes());
            block
        }
        TOKEN_SESSION_ID => return Ok(Information::Value(token.session_id)),
        TOKEN_INTEGRITY_LEVEL => return Ok(Information::Value(token.integrity_level())),
        TOKEN_IS_APP_CONTAINER => return Ok(Information::Value(0)),
        _ => return Err(QueryError::InvalidInfoClass),
    };
    Ok(Information::Block(block))
}

/// `header`, an array of `SID_AND_ATTRIBUTES` (a pointer, the
/// attributes, padding: 16 bytes), then the SIDs the pointers name.
fn sids(base: u64, header: &[u8], entries: &[(&[u8], u32)]) -> Vec<u8> {
    let mut block = header.to_vec();
    let mut at = base + (header.len() + 16 * entries.len()) as u64;
    for (sid, attributes) in entries {
        block.extend(at.to_le_bytes());
        block.extend(u64::from(*attributes).to_le_bytes());
        at += sid.len() as u64;
    }
    for (sid, _) in entries {
        block.extend(*sid);
    }
    block
}

/// A pointer and, right after it, the SID or ACL it points to; a null
/// pointer alone for `None`.
fn pointed(base: u64, part: Option<&[u8]>) -> Vec<u8> {
    let mut block = part.map_or(0, |_| base + 8).to_le_bytes().to_vec();
    block.extend(part.unwrap_or_default());
    block
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::token::{
        ADMINISTRATORS, AUTHENTICATED_USERS, LOCAL_SYSTEM, SECURITY_IDENTIFICATION, SYSTEM_LABEL,
        WORLD,
    };

    const BASE: u64 = 0xFFFF_8000_1234_5000;

    fn block(token: &Token, class: u32) -> Vec<u8> {
        match token_information(token, class, BASE) {
            Ok(Information::Block(block)) => block,
            other => panic!("class {class}: {other:?}"),
        }
    }
    fn u32_at(block: &[u8], at: usize) -> u32 {
        u32::from_le_bytes(block[at..at + 4].try_into().unwrap())
    }
    fn u64_at(block: &[u8], at: usize) -> u64 {
        u64::from_le_bytes(block[at..at + 8].try_into().unwrap())
    }

    #[test]
    fn the_user() {
        let mut token = Token::system();
        let user = block(&token, TOKEN_USER);
        assert_eq!(user.len(), 16 + 12);
        assert_eq!(u64_at(&user, 0), BASE + 16, "Sid");
        assert_eq!(u64_at(&user, 8), 0, "Attributes, padding");
        assert_eq!(user[16..], LOCAL_SYSTEM);
        token.user.attributes = 0x10;
        assert_eq!(u32_at(&block(&token, TOKEN_USER), 8), 0x10);
    }

    #[test]
    fn the_groups() {
        let groups = block(&Token::system(), TOKEN_GROUPS);
        // Count and padding, four entries, the four SIDs.
        assert_eq!(groups.len(), 8 + 4 * 16 + 16 + 12 + 12 + 12);
        assert_eq!(u64_at(&groups, 0), 4, "GroupCount, padding");
        let expected: [(&[u8], u32); 4] = [
            (&ADMINISTRATORS, 0xE),
            (&WORLD, 0x7),
            (&AUTHENTICATED_USERS, 0x7),
            (&SYSTEM_LABEL, 0x60),
        ];
        let mut at = 8 + 4 * 16;
        for (i, (sid, attributes)) in expected.into_iter().enumerate() {
            let entry = 8 + 16 * i;
            assert_eq!(u64_at(&groups, entry), BASE + at as u64, "Groups[{i}].Sid");
            assert_eq!(u64_at(&groups, entry + 8), u64::from(attributes));
            assert_eq!(&groups[at..at + sid.len()], sid, "the SID it points to");
            at += sid.len();
        }
        assert_eq!(at, groups.len());
        // No groups: the count alone.
        let mut alone = Token::system();
        alone.groups.clear();
        assert_eq!(block(&alone, TOKEN_GROUPS), [0; 8]);
    }

    #[test]
    fn the_privileges() {
        let token = Token::system();
        let privileges = block(&token, TOKEN_PRIVILEGES);
        assert_eq!(privileges.len(), 4 + 12 * 31);
        assert_eq!(u32_at(&privileges, 0), 31, "PrivilegeCount");
        for (i, held) in token.privileges.iter().enumerate() {
            let entry = 4 + 12 * i;
            assert_eq!(u32_at(&privileges, entry), held.luid as u32, "Luid.LowPart");
            assert_eq!(u32_at(&privileges, entry + 4), 0, "Luid.HighPart");
            assert_eq!(u32_at(&privileges, entry + 8), held.attributes);
        }
        // The first two, byte for byte: create-token off, and the third,
        // lock-memory, on.
        assert_eq!(privileges[4..16], [2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
        assert_eq!(privileges[28..40], [4, 0, 0, 0, 0, 0, 0, 0, 3, 0, 0, 0]);
    }

    #[test]
    fn the_owner_the_primary_group_and_the_default_dacl() {
        let mut token = Token::system();
        let owner = block(&token, TOKEN_OWNER);
        assert_eq!((owner.len(), u64_at(&owner, 0)), (8 + 16, BASE + 8));
        assert_eq!(owner[8..], ADMINISTRATORS);
        let group = block(&token, TOKEN_PRIMARY_GROUP);
        assert_eq!((group.len(), u64_at(&group, 0)), (8 + 12, BASE + 8));
        assert_eq!(group[8..], LOCAL_SYSTEM);
        let dacl = block(&token, TOKEN_DEFAULT_DACL);
        assert_eq!((dacl.len(), u64_at(&dacl, 0)), (8 + 52, BASE + 8));
        assert_eq!(dacl[8..], token.default_dacl.clone().unwrap()[..]);
        token.default_dacl = None;
        assert_eq!(block(&token, TOKEN_DEFAULT_DACL), [0; 8]);
    }

    #[test]
    fn the_type_and_the_impersonation_level() {
        let mut token = Token::system();
        assert_eq!(block(&token, TOKEN_TYPE), [1, 0, 0, 0]);
        assert_eq!(
            token_information(&token, TOKEN_IMPERSONATION_LEVEL, BASE),
            Err(QueryError::InvalidInfoClass),
            "a primary token has none"
        );
        token.token_type = TokenType::Impersonation;
        token.impersonation_level = SECURITY_IDENTIFICATION;
        assert_eq!(block(&token, TOKEN_TYPE), [2, 0, 0, 0]);
        assert_eq!(block(&token, TOKEN_IMPERSONATION_LEVEL), [1, 0, 0, 0]);
    }

    #[test]
    fn the_statistics() {
        let mut token = Token::system();
        token.token_id = 0x1_0000_03EA;
        token.modified_id = 0x3EB;
        token.dynamic_charged = 0x1000;
        token.dynamic_available = 0x0F00;
        let statistics = block(&token, TOKEN_STATISTICS);
        assert_eq!(statistics.len(), 56);
        assert_eq!(u32_at(&statistics, 0), 0x3EA, "TokenId.LowPart");
        assert_eq!(u32_at(&statistics, 4), 1, "TokenId.HighPart");
        assert_eq!(u64_at(&statistics, 8), 0x3E7, "AuthenticationId");
        assert_eq!(
            u64_at(&statistics, 16),
            crate::token::SYSTEM_TOKEN_EXPIRATION as u64,
            "ExpirationTime"
        );
        assert_eq!(u32_at(&statistics, 24), 1, "TokenType");
        assert_eq!(u32_at(&statistics, 28), 0, "ImpersonationLevel");
        assert_eq!(u32_at(&statistics, 32), 0x1000, "DynamicCharged");
        assert_eq!(u32_at(&statistics, 36), 0x0F00, "DynamicAvailable");
        assert_eq!(u32_at(&statistics, 40), 4, "GroupCount");
        assert_eq!(u32_at(&statistics, 44), 31, "PrivilegeCount");
        assert_eq!(u64_at(&statistics, 48), 0x3EB, "ModifiedId");
    }

    #[test]
    fn the_values() {
        let mut token = Token::system();
        token.session_id = 3;
        let value = |class| token_information(&token, class, BASE);
        assert_eq!(value(TOKEN_SESSION_ID), Ok(Information::Value(3)));
        assert_eq!(value(TOKEN_INTEGRITY_LEVEL), Ok(Information::Value(0x4000)));
        assert_eq!(value(TOKEN_IS_APP_CONTAINER), Ok(Information::Value(0)));
    }

    #[test]
    fn the_classes_not_answered() {
        let token = Token::system();
        // TokenSource, TokenRestrictedSids, TokenUserClaimAttributes and
        // numbers that are no class.
        for class in [0, 7, 11, 13, 24, 26, 28, 30, 33, 34, 1000] {
            assert_eq!(
                token_information(&token, class, BASE),
                Err(QueryError::InvalidInfoClass),
                "class {class}"
            );
        }
    }

    #[test]
    fn the_base_moves_only_the_pointers() {
        let token = Token::system();
        for class in [TOKEN_USER, TOKEN_GROUPS, TOKEN_OWNER, TOKEN_DEFAULT_DACL] {
            let (low, high) = (
                token_information(&token, class, 0).unwrap(),
                token_information(&token, class, BASE).unwrap(),
            );
            let (Information::Block(low), Information::Block(high)) = (low, high) else {
                panic!("class {class} is a block");
            };
            assert_eq!(low.len(), high.len());
            assert_ne!(low, high);
        }
        assert_eq!(
            token_information(&token, TOKEN_STATISTICS, 0),
            token_information(&token, TOKEN_STATISTICS, BASE)
        );
    }
}
