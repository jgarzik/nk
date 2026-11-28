//! Per-page PE32+ base relocation applicator with cross-page fixup support.
//!
//! When a `SEC_IMAGE` view cannot be mapped at its preferred `ImageBase`,
//! relocations touching each demand-paged 4 KiB page are applied on page-in
//! without materialising the whole image upfront. Fixups that straddle a 4 KiB
//! page boundary (e.g. a 64-bit `IMAGE_REL_BASED_DIR64` at page offset
//! `0xFF9..=0xFFF`) read the original un-relocated 8 bytes via a caller-supplied
//! reader and patch the slice lying inside the target page.

use crate::PAGE_SIZE;

const REL_ABSOLUTE: u16 = 0;
const REL_HIGHLOW: u16 = 3;
const REL_DIR64: u16 = 10;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RelocError {
    MalformedBlock,
    UnsupportedType(u16),
    ReadFailed,
}

fn u16_le(buf: &[u8], off: usize) -> Option<u16> {
    let s = buf.get(off..off.checked_add(2)?)?;
    Some(u16::from_le_bytes([s[0], s[1]]))
}

fn u32_le(buf: &[u8], off: usize) -> Option<u32> {
    let s = buf.get(off..off.checked_add(4)?)?;
    Some(u32::from_le_bytes([s[0], s[1], s[2], s[3]]))
}

/// Apply all PE base relocations from `.reloc` directory `relocs` that touch
/// the 4 KiB image page starting at `page_rva` (must be page-aligned), using
/// relocation offset `delta = actual_base.wrapping_sub(preferred_base)`.
///
/// `read_orig(rva, dst)` fills `dst` (4 or 8 bytes) with the original
/// un-relocated image bytes at `rva` whenever a fixup straddles a 4 KiB page
/// boundary.
pub fn apply_page_relocs<F>(
    relocs: &[u8],
    page_rva: u32,
    delta: u64,
    page: &mut [u8; PAGE_SIZE as usize],
    mut read_orig: F,
) -> Result<(), RelocError>
where
    F: FnMut(u32, &mut [u8]) -> bool,
{
    if delta == 0 || relocs.is_empty() {
        return Ok(());
    }
    let page_start = u64::from(page_rva);
    let page_end = page_start + PAGE_SIZE;
    let prev_page_rva = page_rva.checked_sub(PAGE_SIZE as u32);

    let mut off = 0usize;
    while off + 8 <= relocs.len() {
        let block_rva = u32_le(relocs, off).ok_or(RelocError::MalformedBlock)?;
        let block_size = u32_le(relocs, off + 4).ok_or(RelocError::MalformedBlock)? as usize;
        if block_size == 0 {
            break;
        }
        if block_size < 8 || off + block_size > relocs.len() {
            return Err(RelocError::MalformedBlock);
        }

        // Only blocks for `page_rva` or the immediately preceding page can
        // touch bytes inside `[page_start, page_end)`.
        if block_rva == page_rva || Some(block_rva) == prev_page_rva {
            let mut pos = off + 8;
            while pos + 2 <= off + block_size {
                let entry = u16_le(relocs, pos).ok_or(RelocError::MalformedBlock)?;
                pos += 2;
                let kind = entry >> 12;
                let elem_off = u64::from(entry & 0x0FFF);
                let fix_rva = u64::from(block_rva) + elem_off;
                let width: u64 = match kind {
                    REL_ABSOLUTE => continue,
                    REL_HIGHLOW => 4,
                    REL_DIR64 => 8,
                    other => return Err(RelocError::UnsupportedType(other)),
                };
                let fix_end = fix_rva + width;
                if fix_end <= page_start || fix_rva >= page_end {
                    continue;
                }
                if fix_rva >= page_start && fix_end <= page_end {
                    // Entirely inside this page: fast in-place update.
                    let i = (fix_rva - page_start) as usize;
                    match kind {
                        REL_DIR64 => {
                            let val =
                                u64::from_le_bytes(page[i..i + 8].try_into().unwrap_or([0; 8]));
                            page[i..i + 8].copy_from_slice(&val.wrapping_add(delta).to_le_bytes());
                        }
                        REL_HIGHLOW => {
                            let val =
                                u32::from_le_bytes(page[i..i + 4].try_into().unwrap_or([0; 4]));
                            page[i..i + 4]
                                .copy_from_slice(&val.wrapping_add(delta as u32).to_le_bytes());
                        }
                        _ => unreachable!(),
                    }
                } else {
                    // Cross-page fixup: read the full original value and write
                    // the subslice overlapping `[page_start, page_end)`.
                    let mut raw = [0u8; 8];
                    let w = width as usize;
                    if !read_orig(fix_rva as u32, &mut raw[..w]) {
                        return Err(RelocError::ReadFailed);
                    }
                    let mut patched = [0u8; 8];
                    match kind {
                        REL_DIR64 => {
                            let val = u64::from_le_bytes(raw);
                            patched.copy_from_slice(&val.wrapping_add(delta).to_le_bytes());
                        }
                        REL_HIGHLOW => {
                            let val = u32::from_le_bytes([raw[0], raw[1], raw[2], raw[3]]);
                            patched[..4]
                                .copy_from_slice(&val.wrapping_add(delta as u32).to_le_bytes());
                        }
                        _ => unreachable!(),
                    }
                    let ov_start = fix_rva.max(page_start);
                    let ov_end = fix_end.min(page_end);
                    let src_off = (ov_start - fix_rva) as usize;
                    let dst_off = (ov_start - page_start) as usize;
                    let len = (ov_end - ov_start) as usize;
                    page[dst_off..dst_off + len].copy_from_slice(&patched[src_off..src_off + len]);
                }
            }
        }
        off += block_size;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn push_block(out: &mut alloc::vec::Vec<u8>, page_rva: u32, entries: &[u16]) {
        let size = (8 + entries.len() * 2) as u32;
        out.extend_from_slice(&page_rva.to_le_bytes());
        out.extend_from_slice(&size.to_le_bytes());
        for &e in entries {
            out.extend_from_slice(&e.to_le_bytes());
        }
    }

    #[test]
    fn in_page_and_cross_page_dir64_relocations() {
        let mut image = alloc::vec![0u8; 8192];
        // Normal DIR64 at 0x0010.
        image[0x0010..0x0018].copy_from_slice(&0x0000_0001_4000_1234u64.to_le_bytes());
        // Cross-page DIR64 straddling 0x0FFC..0x1004 (4 bytes on page 0, 4 bytes on page 1).
        let cross_orig: u64 = 0x0000_0001_4000_FFFF;
        image[0x0FFC..0x1004].copy_from_slice(&cross_orig.to_le_bytes());
        // Cross-page DIR64 straddling 0x0FF9..0x1001? Test a second image or test 0x0FFC + 0x1020.
        image[0x1020..0x1024].copy_from_slice(&0x1000_0050u32.to_le_bytes());

        let mut relocs = alloc::vec::Vec::new();
        push_block(
            &mut relocs,
            0x0000,
            &[(REL_DIR64 << 12) | 0x010, (REL_DIR64 << 12) | 0xFFC, 0],
        );
        push_block(&mut relocs, 0x1000, &[(REL_HIGHLOW << 12) | 0x020, 0]);

        let delta: u64 = 0x0000_0000_0001_0000; // carries across low 32->high 32 on 0x4000_FFFF? Try 0xFFFF_0001!
        let delta2: u64 = 0x0000_0002_FFFF_0002; // forces carry into upper 32 bits!
        let _ = delta;

        let mut p0: [u8; 4096] = image[0..4096].try_into().unwrap();
        let mut p1: [u8; 4096] = image[4096..8192].try_into().unwrap();

        let reader = |rva: u32, dst: &mut [u8]| -> bool {
            let s = rva as usize;
            if s + dst.len() > image.len() {
                return false;
            }
            dst.copy_from_slice(&image[s..s + dst.len()]);
            true
        };

        apply_page_relocs(&relocs, 0x0000, delta2, &mut p0, reader).unwrap();
        apply_page_relocs(&relocs, 0x1000, delta2, &mut p1, reader).unwrap();

        let got_in = u64::from_le_bytes(p0[0x10..0x18].try_into().unwrap());
        assert_eq!(got_in, 0x0000_0001_4000_1234u64.wrapping_add(delta2));

        let mut joined = [0u8; 8];
        joined[0..4].copy_from_slice(&p0[0xFFC..0x1000]);
        joined[4..8].copy_from_slice(&p1[0x000..0x004]);
        assert_eq!(u64::from_le_bytes(joined), cross_orig.wrapping_add(delta2));

        let got_hl = u32::from_le_bytes(p1[0x20..0x24].try_into().unwrap());
        assert_eq!(got_hl, 0x1000_0050u32.wrapping_add(delta2 as u32));
    }
}
