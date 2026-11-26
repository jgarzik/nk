//! Activity ids: the GUIDs that tie the events of one piece of work
//! together (`EtwActivityIdControl`).
//!
//! Windows keeps a thread's current activity id in its TEB, which a
//! system thread does not have, and makes a new id from a counter and
//! eight bytes that do not change. The decisions are the pinned
//! kernel's.

use nk_ntabi::etw::GUID;
use nk_ntabi::status::{NTSTATUS, STATUS_NOT_SUPPORTED};

/// `EVENT_ACTIVITY_CTRL_CREATE_ID`: make a new id, touching no
/// thread's.
pub const CREATE_ID: u32 = 3;

/// A new activity id: the low eight bytes are `base`, which is the
/// same for every id of this boot, the high eight `count`, which no
/// two ids share.
pub fn create(base: u64, count: u64) -> GUID {
    let low = base.to_le_bytes();
    GUID {
        Data1: u32::from_le_bytes([low[0], low[1], low[2], low[3]]),
        Data2: u16::from_le_bytes([low[4], low[5]]),
        Data3: u16::from_le_bytes([low[6], low[7]]),
        Data4: count.to_le_bytes(),
    }
}

/// What a control code other than [`CREATE_ID`] comes to on a thread
/// with no TEB, which is every thread NK has: the codes that read or
/// set the thread's id have no thread's id to work on. Windows checks
/// for the TEB before it looks at the code, so an unknown code is
/// answered the same.
pub fn without_teb(_code: u32) -> NTSTATUS {
    STATUS_NOT_SUPPORTED
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_id_is_the_base_and_a_count() {
        let id = create(0x0807_0605_0403_0201, 0x1112_1314_1516_1718);
        assert_eq!(id.Data1, 0x0403_0201);
        assert_eq!(id.Data2, 0x0605);
        assert_eq!(id.Data3, 0x0807);
        assert_eq!(id.Data4, [0x18, 0x17, 0x16, 0x15, 0x14, 0x13, 0x12, 0x11]);
        assert_ne!(create(1, 1), create(1, 2));
    }

    #[test]
    fn a_thread_without_a_teb_has_no_id() {
        for code in [0, 1, 2, 4, 5, 99] {
            assert_eq!(without_teb(code), STATUS_NOT_SUPPORTED);
        }
    }
}
