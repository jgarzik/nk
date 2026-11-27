//! Mounting a volume as Windows' `IopMountVolume` does, read in the
//! pinned kernel: which registered file system is asked, in which
//! order, and what each answer means for the walk.

/// The queues file systems register on (`IoRegisterFileSystem`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Queue {
    Disk,
    CdRom,
    Tape,
    Network,
}

/// The queue a control device of type `device_type` registers on:
/// `FILE_DEVICE_DISK_FILE_SYSTEM`, `FILE_DEVICE_CD_ROM_FILE_SYSTEM`,
/// `FILE_DEVICE_TAPE_FILE_SYSTEM`, `FILE_DEVICE_NETWORK_FILE_SYSTEM`.
/// Any other registers on none.
pub fn registration_queue(device_type: u32) -> Option<Queue> {
    match device_type {
        0x08 => Some(Queue::Disk),
        0x03 => Some(Queue::CdRom),
        0x20 => Some(Queue::Tape),
        0x14 => Some(Queue::Network),
        _ => None,
    }
}

/// The queue whose file systems are asked to mount a volume on a device
/// of type `device_type`: a disk or virtual disk the disk queue, a
/// CD-ROM the CD-ROM queue, anything else the tape queue.
pub fn mount_queue(device_type: u32) -> Queue {
    match device_type {
        0x07 | 0x24 => Queue::Disk,
        0x02 => Queue::CdRom,
        _ => Queue::Tape,
    }
}

/// What the walk does with the file system at `index` of a queue of
/// `len`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Offer {
    /// Send it the mount request.
    Ask,
    /// Pass it over for the next.
    Skip,
    /// End the walk: nothing after it is asked.
    Stop,
}

/// Whether the file system at `index` of `len` is asked to mount. The
/// last on a queue is RAW. It is asked only when the open allows a raw
/// mount or it is the only one; a block marked `VPB_RAW_MOUNT`
/// (`raw_block`) is offered to it alone.
pub fn offer(index: usize, len: usize, allow_raw: bool, raw_block: bool) -> Offer {
    let last = index + 1 == len;
    if !allow_raw && last && index != 0 {
        Offer::Stop
    } else if raw_block && !last {
        Offer::Skip
    } else {
        Offer::Ask
    }
}

pub const STATUS_UNRECOGNIZED_VOLUME: u32 = 0xC000_014F;
pub const STATUS_FS_DRIVER_REQUIRED: u32 = 0xC000_019C;

/// What the walk does after a file system's answer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Next {
    /// It mounted the volume.
    Mounted,
    /// Ask the next one.
    Next,
    /// File systems registered or went meanwhile: from the head again.
    Restart,
    /// Ask the last, RAW, next.
    Raw,
    /// End the walk with this answer.
    Stop,
}

/// The walk's next step after a file system answered `status` with
/// `information` (`IoStatus.Information`). `changed`: a file system
/// registered or unregistered during the request. `last`: it was the
/// last on its queue.
pub fn next(status: u32, information: usize, changed: bool, allow_raw: bool, last: bool) -> Next {
    if status as i32 >= 0 {
        return Next::Mounted;
    }
    // Media and readiness answers end the walk when the file system
    // says so.
    let stops_if_told = matches!(
        status,
        0xC000_00A2..=0xC000_00A3 | 0xC000_0012..=0xC000_0014 | 0x8000_0016 | 0xC000_00B5
    );
    if stops_if_told && information == 1 {
        return Next::Stop;
    }
    if changed {
        return Next::Restart;
    }
    match status {
        STATUS_UNRECOGNIZED_VOLUME | STATUS_FS_DRIVER_REQUIRED => Next::Next,
        _ if nk_fsrtl::status::is_total_device_failure(status) => {
            if allow_raw && !last {
                Next::Raw
            } else {
                Next::Stop
            }
        }
        _ => Next::Next,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn queues() {
        assert_eq!(registration_queue(0x08), Some(Queue::Disk));
        assert_eq!(registration_queue(0x03), Some(Queue::CdRom));
        assert_eq!(registration_queue(0x20), Some(Queue::Tape));
        assert_eq!(registration_queue(0x14), Some(Queue::Network));
        assert_eq!(registration_queue(0x07), None);
        assert_eq!(mount_queue(0x07), Queue::Disk);
        assert_eq!(mount_queue(0x24), Queue::Disk);
        assert_eq!(mount_queue(0x02), Queue::CdRom);
        assert_eq!(mount_queue(0x1F), Queue::Tape);
    }

    #[test]
    fn who_is_asked() {
        // RAW alone is asked, raw mount or not.
        assert_eq!(offer(0, 1, false, false), Offer::Ask);
        // With others, RAW only when a raw mount is allowed.
        assert_eq!(offer(0, 2, false, false), Offer::Ask);
        assert_eq!(offer(1, 2, false, false), Offer::Stop);
        assert_eq!(offer(1, 2, true, false), Offer::Ask);
        // A block marked for raw mounts goes to RAW alone.
        assert_eq!(offer(0, 2, true, true), Offer::Skip);
        assert_eq!(offer(1, 2, true, true), Offer::Ask);
    }

    #[test]
    fn answers() {
        assert_eq!(next(0, 0, false, false, false), Next::Mounted);
        assert_eq!(
            next(STATUS_UNRECOGNIZED_VOLUME, 0, false, false, false),
            Next::Next
        );
        assert_eq!(
            next(STATUS_UNRECOGNIZED_VOLUME, 0, true, false, false),
            Next::Restart
        );
        // No media is a total failure, unless the file system says
        // stop, which it ends the walk with in any case.
        assert_eq!(next(0xC000_0013, 0, false, true, false), Next::Raw);
        assert_eq!(next(0xC000_0013, 1, false, true, false), Next::Stop);
        // A total failure goes to RAW if a raw mount is allowed.
        assert_eq!(next(0xC000_0185, 0, false, true, false), Next::Raw);
        assert_eq!(next(0xC000_0185, 0, false, false, false), Next::Stop);
        assert_eq!(next(0xC000_0185, 0, false, true, true), Next::Stop);
        // A CRC error is not one.
        assert_eq!(next(0xC000_003F, 0, false, true, false), Next::Next);
    }
}
