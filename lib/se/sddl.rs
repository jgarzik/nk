//! Security descriptors written as
//! [SDDL](https://learn.microsoft.com/en-us/windows/win32/secauthz/security-descriptor-string-format)
//! strings, as `IoCreateDeviceSecure` takes them: an owner (`O:`), a
//! group (`G:`) and a DACL (`D:`, with its flags), each ACE
//! `(type;flags;rights;;;sid)`.
//!
//! What is understood: ACE types allow (`A`) and deny (`D`); the ACE
//! flags `OI`, `CI`, `NP`, `IO`, `ID`; the DACL flags `P`, `AI`, `AR`;
//! rights as the generic, standard, file and key names or a hexadecimal
//! number; SIDs as `S-1-...` or by the names Microsoft's device-security
//! library knows (`WD NU IU SY BA BU BG AU RC AN LS NS AC UD`). Anything
//! else valid SDDL may say is [`SddlError::Unsupported`], naming it: the
//! kernel stops the system then rather than guess. A string that is not
//! SDDL is [`SddlError::Invalid`].

use crate::acl::{ACCESS_DENIED_ACE, CONTAINER_INHERIT_ACE, INHERIT_ONLY_ACE, INHERITED_ACE};
use crate::acl::{NO_PROPAGATE_INHERIT_ACE, OBJECT_INHERIT_ACE};
use crate::{
    Parts, SE_DACL_AUTO_INHERIT_REQ, SE_DACL_AUTO_INHERITED, SE_DACL_PRESENT, SE_DACL_PROTECTED,
    SE_SELF_RELATIVE,
};
use alloc::vec::Vec;

/// Why a string gave no descriptor.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SddlError<'a> {
    /// Not SDDL.
    Invalid,
    /// SDDL this parser does not understand: the part it stopped at.
    Unsupported(&'a str),
}

/// `ACCESS_ALLOWED_ACE_TYPE`.
const ACCESS_ALLOWED_ACE: u8 = 0;
/// `ACL_REVISION`.
const ACL_REVISION: u8 = 2;

/// The SIDs known by name: `(name, authority, sub-authorities)`.
const ALIASES: [(&str, u8, &[u32]); 14] = [
    ("WD", 1, &[0]),
    ("NU", 5, &[2]),
    ("IU", 5, &[4]),
    ("SY", 5, &[18]),
    ("BA", 5, &[32, 544]),
    ("BU", 5, &[32, 545]),
    ("BG", 5, &[32, 546]),
    ("AU", 5, &[11]),
    ("RC", 5, &[12]),
    ("AN", 5, &[7]),
    ("LS", 5, &[19]),
    ("NS", 5, &[20]),
    ("AC", 15, &[2, 1]),
    ("UD", 5, &[84, 0, 0, 0, 0, 0]),
];

/// The rights known by name.
const RIGHTS: [(&str, u32); 19] = [
    ("GA", 0x1000_0000),
    ("GX", 0x2000_0000),
    ("GW", 0x4000_0000),
    ("GR", 0x8000_0000),
    ("SD", 0x0001_0000),
    ("RC", 0x0002_0000),
    ("WD", 0x0004_0000),
    ("WO", 0x0008_0000),
    ("FA", 0x001F_01FF),
    ("FR", 0x0012_0089),
    ("FW", 0x0012_0116),
    ("FX", 0x0012_00A0),
    ("KA", 0x000F_003F),
    ("KR", 0x0002_0019),
    ("KW", 0x0002_0006),
    ("KX", 0x0002_0019),
    ("CC", 0x0000_0001),
    ("DC", 0x0000_0002),
    ("LC", 0x0000_0004),
];

/// A SID's bytes.
fn sid(authority: u8, subs: &[u32]) -> Vec<u8> {
    let mut out = Vec::with_capacity(8 + 4 * subs.len());
    out.extend([1, subs.len() as u8, 0, 0, 0, 0, 0, authority]);
    for sub in subs {
        out.extend(sub.to_le_bytes());
    }
    out
}

/// The SID `text` names.
fn parse_sid(text: &str) -> Result<Vec<u8>, SddlError<'_>> {
    if let Some(rest) = text.strip_prefix("S-1-") {
        let mut parts = rest.split('-');
        let authority: u64 = parts
            .next()
            .and_then(|a| a.parse().ok())
            .ok_or(SddlError::Invalid)?;
        let subs: Vec<u32> = parts
            .map(|p| p.parse().map_err(|_| SddlError::Invalid))
            .collect::<Result<_, _>>()?;
        if subs.is_empty() || subs.len() > 15 || authority > 0xFFFF_FFFF_FFFF {
            return Err(SddlError::Invalid);
        }
        let mut out = sid(0, &subs);
        out[2..8].copy_from_slice(&authority.to_be_bytes()[2..]);
        return Ok(out);
    }
    ALIASES
        .iter()
        .find(|(name, ..)| *name == text)
        .map(|&(_, authority, subs)| sid(authority, subs))
        .ok_or(SddlError::Unsupported(text))
}

/// The rights `text` names.
fn parse_rights(text: &str) -> Result<u32, SddlError<'_>> {
    if let Some(hex) = text.strip_prefix("0x").or_else(|| text.strip_prefix("0X")) {
        return u32::from_str_radix(hex, 16).map_err(|_| SddlError::Invalid);
    }
    if text.len() % 2 != 0 {
        return Err(SddlError::Invalid);
    }
    let mut mask = 0;
    for at in (0..text.len()).step_by(2) {
        let name = text.get(at..at + 2).ok_or(SddlError::Invalid)?;
        mask |= RIGHTS
            .iter()
            .find(|(n, _)| *n == name)
            .map(|&(_, m)| m)
            .ok_or(SddlError::Unsupported(name))?;
    }
    Ok(mask)
}

/// The ACE flags `text` names.
fn parse_ace_flags(text: &str) -> Result<u8, SddlError<'_>> {
    if text.len() % 2 != 0 {
        return Err(SddlError::Invalid);
    }
    let mut flags = 0;
    for at in (0..text.len()).step_by(2) {
        flags |= match text.get(at..at + 2).ok_or(SddlError::Invalid)? {
            "OI" => OBJECT_INHERIT_ACE,
            "CI" => CONTAINER_INHERIT_ACE,
            "NP" => NO_PROPAGATE_INHERIT_ACE,
            "IO" => INHERIT_ONLY_ACE,
            "ID" => INHERITED_ACE,
            other => return Err(SddlError::Unsupported(other)),
        };
    }
    Ok(flags)
}

/// One ACE, the text between its parentheses.
fn parse_ace(text: &str) -> Result<Vec<u8>, SddlError<'_>> {
    let fields: Vec<&str> = text.split(';').collect();
    let [kind, flags, rights, object, inherited, account] = fields[..] else {
        return Err(SddlError::Invalid);
    };
    if !object.is_empty() {
        return Err(SddlError::Unsupported(object));
    }
    if !inherited.is_empty() {
        return Err(SddlError::Unsupported(inherited));
    }
    let kind = match kind {
        "A" => ACCESS_ALLOWED_ACE,
        "D" => ACCESS_DENIED_ACE,
        other => return Err(SddlError::Unsupported(other)),
    };
    let flags = parse_ace_flags(flags)?;
    let mask = parse_rights(rights)?;
    let sid = parse_sid(account)?;
    let mut ace = Vec::with_capacity(8 + sid.len());
    ace.extend([kind, flags]);
    ace.extend(((8 + sid.len()) as u16).to_le_bytes());
    ace.extend(mask.to_le_bytes());
    ace.extend(sid);
    Ok(ace)
}

/// A DACL: its flags and its ACEs, the text after `D:`.
fn parse_dacl(text: &str) -> Result<(u16, Vec<u8>), SddlError<'_>> {
    let open = text.find('(').unwrap_or(text.len());
    let (flags_text, mut aces_text) = text.split_at(open);
    let mut control = SE_DACL_PRESENT;
    let mut flags = flags_text;
    while !flags.is_empty() {
        let (bit, len) = if flags.starts_with("AI") {
            (SE_DACL_AUTO_INHERITED, 2)
        } else if flags.starts_with("AR") {
            (SE_DACL_AUTO_INHERIT_REQ, 2)
        } else if flags.starts_with('P') {
            (SE_DACL_PROTECTED, 1)
        } else {
            return Err(SddlError::Unsupported(flags));
        };
        control |= bit;
        flags = &flags[len..];
    }
    let mut aces = Vec::new();
    while !aces_text.is_empty() {
        let body = aces_text.strip_prefix('(').ok_or(SddlError::Invalid)?;
        let close = body.find(')').ok_or(SddlError::Invalid)?;
        aces.push(parse_ace(&body[..close])?);
        aces_text = &body[close + 1..];
    }
    let acl = crate::acl::build(ACL_REVISION, &aces).ok_or(SddlError::Invalid)?;
    Ok((control, acl))
}

/// The self-relative security descriptor `text` describes.
pub fn parse(text: &str) -> Result<Vec<u8>, SddlError<'_>> {
    let mut owner = None;
    let mut group = None;
    let mut dacl = None;
    let mut control = SE_SELF_RELATIVE;
    let mut rest = text;
    while !rest.is_empty() {
        let (tag, body) = rest.split_at_checked(2).ok_or(SddlError::Invalid)?;
        // A part runs to the next part's tag.
        let end = ["O:", "G:", "D:", "S:"]
            .iter()
            .filter_map(|t| body.find(t))
            .min()
            .unwrap_or(body.len());
        let (part, next) = body.split_at(end);
        match tag {
            "O:" if owner.is_none() => owner = Some(parse_sid(part)?),
            "G:" if group.is_none() => group = Some(parse_sid(part)?),
            "D:" if dacl.is_none() => {
                let (bits, acl) = parse_dacl(part)?;
                control |= bits;
                dacl = Some(acl);
            }
            "S:" => return Err(SddlError::Unsupported(tag)),
            _ => return Err(SddlError::Invalid),
        }
        rest = next;
    }
    let parts = Parts {
        control,
        owner: owner.as_deref(),
        group: group.as_deref(),
        sacl: None,
        dacl: dacl.as_deref(),
    };
    let mut out = alloc::vec![0; parts.relative_length()];
    parts
        .write_relative(&mut out)
        .map_err(|_| SddlError::Invalid)?;
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parse_relative;

    #[test]
    fn pcw_device_descriptor() {
        // pcw.sys's device: protected DACL, four allow entries, the last
        // for a capability SID given in full.
        let text = "D:P(A;;GA;;;SY)(A;;GRGWGX;;;BA)(A;;GR;;;WD)\
                    (A;;GRGW;;;S-1-15-3-1024-1221526253-3924910130-1751405008-69508222-1499930412-38408379-3528704847-309525946)";
        let sd = parse(text).unwrap();
        let parts = parse_relative(&sd).unwrap();
        assert_eq!(
            parts.control,
            SE_SELF_RELATIVE | SE_DACL_PRESENT | SE_DACL_PROTECTED
        );
        assert!(parts.owner.is_none() && parts.group.is_none());
        let aces: Vec<_> = crate::acl::aces(parts.dacl.unwrap()).collect();
        assert_eq!(aces.len(), 4);
        let (mask, sid) = aces[0].basic().unwrap();
        assert_eq!((aces[0].kind, mask), (0, 0x1000_0000));
        assert_eq!(sid, [1, 1, 0, 0, 0, 0, 0, 5, 18, 0, 0, 0]);
        assert_eq!(aces[1].basic().unwrap().0, 0xE000_0000);
        let (_, sid) = aces[3].basic().unwrap();
        assert_eq!(sid[..8], [1, 10, 0, 0, 0, 0, 0, 15]);
        assert_eq!(sid[8..12], 3u32.to_le_bytes());
        assert_eq!(sid[sid.len() - 4..], 309525946u32.to_le_bytes());
    }

    #[test]
    fn owner_group_and_flags() {
        let sd = parse("O:BAG:SYD:AI(D;CIOI;0x1f;;;BU)").unwrap();
        let parts = parse_relative(&sd).unwrap();
        assert_eq!(parts.owner.unwrap()[8..], [32, 0, 0, 0, 0x20, 2, 0, 0]);
        assert_eq!(parts.group.unwrap()[8..], [18, 0, 0, 0]);
        let ace = crate::acl::aces(parts.dacl.unwrap()).next().unwrap();
        assert_eq!((ace.kind, ace.flags), (1, 3));
        assert_eq!(ace.basic().unwrap().0, 0x1F);
        assert_eq!(
            parts.control & SE_DACL_AUTO_INHERITED,
            SE_DACL_AUTO_INHERITED
        );
        // An empty DACL is present and denies everything.
        let parts_empty = parse("D:").unwrap();
        let parts_empty = parse_relative(&parts_empty).unwrap();
        assert_eq!(crate::acl::aces(parts_empty.dacl.unwrap()).count(), 0);
    }

    #[test]
    fn what_is_not_understood_is_named() {
        assert_eq!(parse("D:(A;;GA;;;PU)"), Err(SddlError::Unsupported("PU")));
        assert_eq!(parse("D:(OA;;GA;;;SY)"), Err(SddlError::Unsupported("OA")));
        assert_eq!(parse("S:(AU;;GA;;;SY)"), Err(SddlError::Unsupported("S:")));
        assert_eq!(parse("D:(A;;GA;;SY)"), Err(SddlError::Invalid));
        assert_eq!(parse("X:"), Err(SddlError::Invalid));
        assert_eq!(parse("D:(A;;GA;;;S-1-x)"), Err(SddlError::Invalid));
    }
}
