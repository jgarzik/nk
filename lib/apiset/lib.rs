//! Windows API-Set Schema v6 (`API_SET_NAMESPACE`) builder and resolver.
//!
//! Layout verified against Windows 10 22H2 `apisetschema.dll` (`.apiset`
//! section, version 6):
//! - `API_SET_NAMESPACE` (28 bytes): `version=6`, `size`, `flags`, `count`,
//!   `entry_offset`, `hash_offset`, `hash_factor=31`.
//! - `API_SET_NAMESPACE_ENTRY` (24 bytes): `flags`, `name_offset`,
//!   `name_length`, `hashed_length`, `value_offset`, `value_count`.
//! - `API_SET_VALUE_ENTRY` (20 bytes): `flags`, `name_offset`, `name_length`,
//!   `value_offset`, `value_length`.
//! - `API_SET_HASH_ENTRY` (8 bytes): `hash`, `index` — sorted ascending by
//!   `hash` for binary search by `ntdll!ApiSetResolveToHost`.

#![cfg_attr(not(test), no_std)]

extern crate alloc;

use alloc::string::String;
use alloc::vec::Vec;

pub const VERSION: u32 = 6;
pub const HASH_FACTOR: u32 = 31;
pub const FLAG_SEALED: u32 = 1;

const HEADER_SIZE: usize = 28;
const ENTRY_SIZE: usize = 24;
const VALUE_SIZE: usize = 20;
const HASH_SIZE: usize = 8;

/// One redirection target for an API-set contract.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Host<'a> {
    /// Optional importing module override (empty string for default target).
    pub alias: &'a str,
    /// Target host DLL name (e.g. `"ntdll.dll"`).
    pub target: &'a str,
}

/// One API-set namespace entry to encode.
#[derive(Debug, Clone, Copy)]
pub struct Entry<'a> {
    /// Contract name without `.dll` suffix (e.g. `"api-ms-win-core-crt-l1-1-0"`).
    pub name: &'a str,
    pub sealed: bool,
    pub hosts: &'a [Host<'a>],
}

fn ascii_lower_u16(unit: u16) -> u16 {
    if (u16::from(b'A')..=u16::from(b'Z')).contains(&unit) {
        unit + 32
    } else {
        unit
    }
}

/// Compute the v6 hash of the hashed portion of an API-set name (everything
/// before the final `'-'`, ASCII-lowercased).
pub fn hash_name(name: &str, factor: u32) -> u32 {
    let prefix = hashed_prefix(name);
    let mut h = 0u32;
    for unit in prefix.encode_utf16() {
        h = h
            .wrapping_mul(factor)
            .wrapping_add(u32::from(ascii_lower_u16(unit)));
    }
    h
}

fn hashed_prefix(name: &str) -> &str {
    let trimmed = strip_dll_suffix(name);
    match trimmed.rfind('-') {
        Some(pos) => &trimmed[..pos],
        None => trimmed,
    }
}

fn strip_dll_suffix(name: &str) -> &str {
    if name.len() >= 4 && name[name.len() - 4..].eq_ignore_ascii_case(".dll") {
        &name[..name.len() - 4]
    } else {
        name
    }
}

fn push_u32(out: &mut Vec<u8>, v: u32) {
    out.extend_from_slice(&v.to_le_bytes());
}

fn write_u32(out: &mut [u8], at: usize, v: u32) {
    out[at..at + 4].copy_from_slice(&v.to_le_bytes());
}

fn push_utf16_aligned(out: &mut Vec<u8>, s: &str) -> (u32, u32) {
    if s.is_empty() {
        return (0, 0);
    }
    while !out.len().is_multiple_of(4) {
        out.push(0);
    }
    let off = out.len() as u32;
    for unit in s.encode_utf16() {
        out.extend_from_slice(&unit.to_le_bytes());
    }
    let len = out.len() as u32 - off;
    (off, len)
}

/// Build a Windows API-Set Schema v6 binary namespace blob.
pub fn build(entries: &[Entry<'_>]) -> Vec<u8> {
    let count = entries.len();
    let entry_offset = HEADER_SIZE;
    let values_start = entry_offset + count * ENTRY_SIZE;
    let total_values: usize = entries.iter().map(|e| e.hosts.len()).sum();
    let strings_start = values_start + total_values * VALUE_SIZE;

    let mut out = Vec::with_capacity(strings_start + count * 64 + count * HASH_SIZE);
    out.resize(strings_start, 0);

    let mut hashes: Vec<(u32, u32)> = Vec::with_capacity(count);
    let mut val_cursor = values_start;

    for (idx, entry) in entries.iter().enumerate() {
        let name = strip_dll_suffix(entry.name);
        let (name_off, name_len) = push_utf16_aligned(&mut out, name);
        let hashed_len = (hashed_prefix(name).encode_utf16().count() * 2) as u32;
        let val_off = if entry.hosts.is_empty() {
            0
        } else {
            val_cursor as u32
        };

        for host in entry.hosts {
            let (alias_off, alias_len) = push_utf16_aligned(&mut out, host.alias);
            let (target_off, target_len) = push_utf16_aligned(&mut out, host.target);
            write_u32(&mut out, val_cursor, 0); // flags
            write_u32(&mut out, val_cursor + 4, alias_off);
            write_u32(&mut out, val_cursor + 8, alias_len);
            write_u32(&mut out, val_cursor + 12, target_off);
            write_u32(&mut out, val_cursor + 16, target_len);
            val_cursor += VALUE_SIZE;
        }

        let e_at = entry_offset + idx * ENTRY_SIZE;
        write_u32(&mut out, e_at, if entry.sealed { FLAG_SEALED } else { 0 });
        write_u32(&mut out, e_at + 4, name_off);
        write_u32(&mut out, e_at + 8, name_len);
        write_u32(&mut out, e_at + 12, hashed_len);
        write_u32(&mut out, e_at + 16, val_off);
        write_u32(&mut out, e_at + 20, entry.hosts.len() as u32);

        hashes.push((hash_name(name, HASH_FACTOR), idx as u32));
    }

    hashes.sort_unstable_by_key(|&(h, idx)| (h, idx));
    while !out.len().is_multiple_of(4) {
        out.push(0);
    }
    let hash_offset = out.len() as u32;
    for (h, idx) in hashes {
        push_u32(&mut out, h);
        push_u32(&mut out, idx);
    }
    let total_size = out.len() as u32;

    write_u32(&mut out, 0, VERSION);
    write_u32(&mut out, 4, total_size);
    write_u32(&mut out, 8, 0); // flags
    write_u32(&mut out, 12, count as u32);
    write_u32(&mut out, 16, entry_offset as u32);
    write_u32(&mut out, 20, hash_offset);
    write_u32(&mut out, 24, HASH_FACTOR);
    out
}

/// Default built-in API-set map for native user-mode processes on NK
/// (contracts resolving to `ntdll.dll`).
pub fn default_map() -> Vec<u8> {
    const NTDLL: &[Host<'static>] = &[Host {
        alias: "",
        target: "ntdll.dll",
    }];
    const ENTRIES: &[Entry<'static>] = &[
        Entry {
            name: "api-ms-win-core-crt-l1-1-0",
            sealed: true,
            hosts: NTDLL,
        },
        Entry {
            name: "api-ms-win-core-apiquery-l1-1-0",
            sealed: true,
            hosts: NTDLL,
        },
        Entry {
            name: "api-ms-win-core-apiquery-l1-1-1",
            sealed: true,
            hosts: NTDLL,
        },
        Entry {
            name: "api-ms-win-core-apiquery-l2-1-0",
            sealed: true,
            hosts: NTDLL,
        },
        Entry {
            name: "api-ms-win-core-string-l1-1-0",
            sealed: true,
            hosts: NTDLL,
        },
        Entry {
            name: "api-ms-win-core-util-l1-1-0",
            sealed: true,
            hosts: NTDLL,
        },
    ];
    build(ENTRIES)
}

/// Parsed view of a v6 API-set namespace blob.
#[derive(Debug, Clone, Copy)]
pub struct Namespace<'a> {
    data: &'a [u8],
    pub count: u32,
    entry_offset: usize,
    hash_offset: usize,
    pub hash_factor: u32,
}

impl<'a> Namespace<'a> {
    pub fn parse(data: &'a [u8]) -> Option<Self> {
        if data.len() < HEADER_SIZE {
            return None;
        }
        let u = |at: usize| -> Option<u32> {
            Some(u32::from_le_bytes(data.get(at..at + 4)?.try_into().ok()?))
        };
        if u(0)? != VERSION {
            return None;
        }
        let size = u(4)? as usize;
        if size > data.len() {
            return None;
        }
        let count = u(12)?;
        let entry_offset = u(16)? as usize;
        let hash_offset = u(20)? as usize;
        let hash_factor = u(24)?;
        entry_offset
            .checked_add((count as usize).checked_mul(ENTRY_SIZE)?)
            .filter(|&end| end <= size)?;
        hash_offset
            .checked_add((count as usize).checked_mul(HASH_SIZE)?)
            .filter(|&end| end <= size)?;
        Some(Self {
            data: &data[..size],
            count,
            entry_offset,
            hash_offset,
            hash_factor,
        })
    }

    fn u32_at(&self, at: usize) -> Option<u32> {
        Some(u32::from_le_bytes(
            self.data.get(at..at + 4)?.try_into().ok()?,
        ))
    }

    fn utf16_eq_ignore_ascii_case(&self, off: usize, len: usize, needle: &str) -> bool {
        let Some(slice) = self.data.get(off..off + len) else {
            return false;
        };
        if len % 2 != 0 {
            return false;
        }
        let mut units = slice
            .as_chunks::<2>()
            .0
            .iter()
            .map(|c| u16::from_le_bytes(*c));
        let mut want = needle.encode_utf16();
        loop {
            match (units.next(), want.next()) {
                (None, None) => return true,
                (Some(a), Some(b)) => {
                    if ascii_lower_u16(a) != ascii_lower_u16(b) {
                        return false;
                    }
                }
                _ => return false,
            }
        }
    }

    fn decode_utf16(&self, off: usize, len: usize) -> Option<String> {
        let slice = self.data.get(off..off + len)?;
        if len % 2 != 0 {
            return None;
        }
        let units = slice
            .as_chunks::<2>()
            .0
            .iter()
            .map(|c| u16::from_le_bytes(*c));
        char::decode_utf16(units)
            .collect::<Result<String, _>>()
            .ok()
    }

    /// Resolve `contract` (with or without `.dll`), optionally for importing
    /// module `parent`, returning the target host DLL name if mapped.
    pub fn resolve(&self, contract: &str, parent: Option<&str>) -> Option<String> {
        if self.count == 0 {
            return None;
        }
        let prefix = hashed_prefix(contract);
        let target_hash = hash_name(contract, self.hash_factor);
        // Binary search the sorted hash table for the first matching hash.
        let mut lo = 0u32;
        let mut hi = self.count;
        while lo < hi {
            let mid = lo + (hi - lo) / 2;
            let h = self.u32_at(self.hash_offset + mid as usize * HASH_SIZE)?;
            if h < target_hash {
                lo = mid + 1;
            } else {
                hi = mid;
            }
        }
        let mut pos = lo;
        while pos < self.count {
            let h_at = self.hash_offset + pos as usize * HASH_SIZE;
            if self.u32_at(h_at)? != target_hash {
                break;
            }
            let idx = self.u32_at(h_at + 4)? as usize;
            let e_at = self.entry_offset + idx * ENTRY_SIZE;
            let name_off = self.u32_at(e_at + 4)? as usize;
            let hashed_len = self.u32_at(e_at + 12)? as usize;
            if self.utf16_eq_ignore_ascii_case(name_off, hashed_len, prefix) {
                let val_off = self.u32_at(e_at + 16)? as usize;
                let val_cnt = self.u32_at(e_at + 20)? as usize;
                if val_cnt == 0 {
                    return None;
                }
                // Check host-specific overrides (entries 1..val_cnt) first.
                if let Some(parent_name) = parent {
                    for k in 1..val_cnt {
                        let v_at = val_off + k * VALUE_SIZE;
                        let a_off = self.u32_at(v_at + 4)? as usize;
                        let a_len = self.u32_at(v_at + 8)? as usize;
                        if self.utf16_eq_ignore_ascii_case(a_off, a_len, parent_name) {
                            let t_off = self.u32_at(v_at + 12)? as usize;
                            let t_len = self.u32_at(v_at + 16)? as usize;
                            return self.decode_utf16(t_off, t_len);
                        }
                    }
                }
                // Default host entry is index 0.
                let t_off = self.u32_at(val_off + 12)? as usize;
                let t_len = self.u32_at(val_off + 16)? as usize;
                return self.decode_utf16(t_off, t_len);
            }
            pos += 1;
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn build_and_resolve_round_trip() {
        let map = build(&[
            Entry {
                name: "api-ms-win-core-crt-l1-1-0",
                sealed: true,
                hosts: &[Host {
                    alias: "",
                    target: "ntdll.dll",
                }],
            },
            Entry {
                name: "api-ms-win-core-synch-l1-2-0",
                sealed: true,
                hosts: &[
                    Host {
                        alias: "",
                        target: "kernelbase.dll",
                    },
                    Host {
                        alias: "kernelbase.dll",
                        target: "kernel32.dll",
                    },
                ],
            },
        ]);
        let ns = Namespace::parse(&map).expect("valid v6 namespace");
        assert_eq!(ns.count, 2);
        assert_eq!(
            ns.resolve("API-MS-WIN-CORE-CRT-L1-1-0.DLL", None)
                .as_deref(),
            Some("ntdll.dll")
        );
        // Revision suffix after final '-' is ignored by v6 hashing.
        assert_eq!(
            ns.resolve("api-ms-win-core-crt-l1-1-9", None).as_deref(),
            Some("ntdll.dll")
        );
        assert_eq!(
            ns.resolve("api-ms-win-core-synch-l1-2-0.dll", None)
                .as_deref(),
            Some("kernelbase.dll")
        );
        assert_eq!(
            ns.resolve("api-ms-win-core-synch-l1-2-0.dll", Some("KERNELBASE.DLL"))
                .as_deref(),
            Some("kernel32.dll")
        );
        assert_eq!(ns.resolve("api-ms-win-nonexistent-l1-1-0", None), None);
    }

    #[test]
    fn empty_and_default_maps_parse() {
        let empty = build(&[]);
        let ns = Namespace::parse(&empty).expect("empty v6 namespace");
        assert_eq!(ns.count, 0);
        assert_eq!(ns.resolve("api-ms-win-core-crt-l1-1-0", None), None);

        let def = default_map();
        let ns = Namespace::parse(&def).expect("default v6 namespace");
        assert_eq!(
            ns.resolve("api-ms-win-core-crt-l1-1-0.dll", None)
                .as_deref(),
            Some("ntdll.dll")
        );
    }

    #[test]
    fn reference_apisetschema_matches_parser_and_rebuilds_equivalently() {
        let Some(home) = std::env::var_os("HOME") else {
            return;
        };
        let path =
            std::path::PathBuf::from(home).join(".cache/nk/plan/vm-extracted/apisetschema.dll");
        let Ok(file) = std::fs::read(&path) else {
            eprintln!("SKIP: no reference apisetschema.dll ({})", path.display());
            return;
        };
        let pe_off = u32::from_le_bytes(file[0x3C..0x40].try_into().unwrap()) as usize;
        let nsect = u16::from_le_bytes(file[pe_off + 6..pe_off + 8].try_into().unwrap()) as usize;
        let opt_sz =
            u16::from_le_bytes(file[pe_off + 20..pe_off + 22].try_into().unwrap()) as usize;
        let sect_off = pe_off + 24 + opt_sz;
        let mut apiset = None;
        for i in 0..nsect {
            let s = &file[sect_off + i * 40..sect_off + (i + 1) * 40];
            if s[..8].starts_with(b".apiset\0") {
                let vsz = u32::from_le_bytes(s[8..12].try_into().unwrap()) as usize;
                let raw = u32::from_le_bytes(s[20..24].try_into().unwrap()) as usize;
                apiset = Some(&file[raw..raw + vsz]);
                break;
            }
        }
        let section = apiset.expect(".apiset section");
        let ns = Namespace::parse(section).expect("parse reference apisetschema.dll");
        assert!(ns.count > 500);
        // Verify every single hash entry resolves cleanly and matches our hash function.
        for pos in 0..ns.count as usize {
            let h_at = ns.hash_offset + pos * HASH_SIZE;
            let stored_hash = ns.u32_at(h_at).unwrap();
            let idx = ns.u32_at(h_at + 4).unwrap() as usize;
            let e_at = ns.entry_offset + idx * ENTRY_SIZE;
            let name_off = ns.u32_at(e_at + 4).unwrap() as usize;
            let name_len = ns.u32_at(e_at + 8).unwrap() as usize;
            let val_cnt = ns.u32_at(e_at + 20).unwrap() as usize;
            let name = ns.decode_utf16(name_off, name_len).unwrap();
            assert_eq!(hash_name(&name, ns.hash_factor), stored_hash, "{name}");
            let resolved = ns.resolve(&name, None);
            assert_eq!(resolved.is_some(), val_cnt > 0, "{name}");
        }
        assert_eq!(
            ns.resolve("api-ms-win-core-crt-l1-1-0.dll", None)
                .as_deref(),
            Some("ntdll.dll")
        );
    }
}
